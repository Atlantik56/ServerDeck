import copy
import json
import pathlib
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from service_restart import ServiceRestarts
from test_service_restart_remote import runtime


class FakeControl:
    def __init__(self, root):
        self.root = root; self.lock = threading.RLock(); self.busy = set(); self.jobs = {}; self.plans = {}
        self.clients_cache = {}; self.software_cache = {}; self.ssh = Mock()
        self.host = {'id': 'one', 'name': 'One', 'host': '192.0.2.1', 'port': 22, 'user': 'root', 'key': 'private-key-handle', 'services': ['x-ui.service']}

    def server(self, sid):
        if sid != self.host['id']: raise ValueError('Unknown server')
        return self.host

    def save_jobs(self):
        (self.root / 'jobs.json').write_text(json.dumps(self.jobs))


class RestartCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.control = FakeControl(pathlib.Path(self.temp.name)); self.manager = ServiceRestarts(self.control)
        self.before = runtime()

    def planned(self):
        self.control.ssh.return_value = self.before
        public = self.manager.plan(self.control.host, 'x-ui.service')
        return public, self.control.plans[public['id']]

    def job(self):
        public, plan = self.planned()
        with patch('service_restart.threading.Thread'):
            value = self.manager.execute(plan, self.control.host['host'])
        return self.control.jobs[value['id']], plan

    def test_targets_and_plan_only_read_no_job_or_execution(self):
        self.control.ssh.return_value = {'targets': [], 'checkedAt': time.time()}
        self.manager.targets(self.control.host)
        self.assertEqual(self.control.ssh.call_args.args[1]['op'], 'service-restart-targets')
        public, plan = self.planned()
        self.assertEqual(self.control.ssh.call_args.args[1]['op'], 'service-restart-info')
        self.assertFalse(self.control.jobs); self.assertFalse(self.control.busy)
        self.assertNotIn('binding', public); self.assertNotIn('before', public)
        self.assertFalse(public['summary']['backupRequired'])
        self.assertEqual(plan['binding'], ['192.0.2.1', 22, 'root', 'private-key-handle'])

    def test_blocked_unregistered_inactive_and_busy_targets_fail_closed(self):
        for unit in ('ssh.service', 'fail2ban.service', 'unregistered.service', 'x-ui.service;reboot'):
            with self.assertRaises(ValueError): self.manager.plan(self.control.host, unit)
        self.control.busy.add('one')
        with self.assertRaises(ValueError): self.manager.plan(self.control.host, 'x-ui.service')
        self.control.ssh.assert_not_called()

    def test_confirmation_expiry_and_changed_registry_prevent_dispatch(self):
        _, plan = self.planned()
        with self.assertRaises(ValueError): self.manager.execute(plan, 'wrong')
        self.control.host['services'].append('nginx.service')
        with self.assertRaises(ValueError): self.manager.execute(plan, '192.0.2.1')
        self.control.host['services'].pop(); plan['expiresAt'] = 0
        with self.assertRaises(ValueError): self.manager.execute(plan, '192.0.2.1')
        self.assertFalse(self.control.jobs)

    def test_double_confirm_and_other_host_job_are_serialized(self):
        job, plan = self.job()
        with self.assertRaises(ValueError): self.manager.execute(plan, '192.0.2.1')
        with self.assertRaises(ValueError): self.manager.targets(self.control.host)
        self.assertIn('one', self.control.busy)
        self.assertEqual(len(json.loads((self.control.root / 'jobs.json').read_text())), 1)

    def test_persistence_failure_rolls_back_reservation_before_any_thread(self):
        _, plan = self.planned()
        with patch.object(self.control, 'save_jobs', side_effect=OSError('disk full')), patch('service_restart.threading.Thread') as thread:
            with self.assertRaises(OSError): self.manager.execute(plan, '192.0.2.1')
        thread.assert_not_called(); self.assertFalse(plan['used']); self.assertFalse(self.control.busy); self.assertFalse(self.control.jobs)

    def test_remote_revision_drift_never_schedules_restart(self):
        job, plan = self.job(); self.control.ssh.reset_mock()
        self.control.ssh.return_value = dict(self.before, bootId='different')
        self.manager.submit(job['id'], plan)
        self.assertEqual(job['state'], 'failed'); self.assertNotIn('one', self.control.busy)
        self.assertEqual(self.control.ssh.call_count, 1)

    def test_lost_ack_only_observes_durable_status_and_does_not_resubmit(self):
        job, plan = self.job(); self.control.ssh.reset_mock()
        self.control.ssh.side_effect = [self.before, TimeoutError(), {'state': 'succeeded', 'restartConfirmed': True, 'workerActive': False}]
        self.manager.submit(job['id'], plan)
        self.assertEqual(job['state'], 'succeeded'); self.assertNotIn('one', self.control.busy)
        self.assertEqual([call.args[1]['op'] for call in self.control.ssh.call_args_list], ['service-restart-info', 'service-restart-schedule', 'service-restart-status'])

    def test_ambiguous_outcome_remains_busy_and_has_no_automatic_retry(self):
        job, _ = self.job(); job['deadline'] = time.time() - 1
        self.control.ssh.return_value = {'state': 'unknown', 'workerActive': False}
        self.manager.monitor(job['id'])
        self.assertEqual(job['state'], 'needs_review'); self.assertIn('one', self.control.busy)

    def test_manual_recheck_only_resumes_status_after_controller_restart(self):
        job, _ = self.job(); job.update(state='needs_review', remoteSubmitted=True)
        restored = ServiceRestarts(self.control); self.control.ssh.reset_mock()
        self.control.ssh.return_value = {'state': 'succeeded', 'workerActive': False}
        restored.monitor(job['id'])
        self.assertEqual(self.control.ssh.call_args.args[1]['op'], 'service-restart-status')
        self.assertEqual(job['state'], 'succeeded')

    def test_acknowledge_cannot_release_running_worker_or_unknown_recent_command(self):
        job, _ = self.job(); job['createdAt'] -= 60
        self.control.ssh.return_value = {'state': 'running', 'workerActive': True}
        with self.assertRaises(ValueError): self.manager.acknowledge(job)
        self.control.ssh.return_value = {'state': 'unknown', 'workerActive': False}
        with self.assertRaises(ValueError): self.manager.acknowledge(job)

    def test_discovered_docker_target_is_canonicalized_and_bound_to_original_info(self):
        full = 'b' * 64; before = copy.deepcopy(self.before)
        before['target'].update(unit='docker:' + full, identity=full, name='amnezia-awg', kind='docker')
        self.control.ssh.return_value = before
        public = self.manager.plan(self.control.host, 'docker:' + full[:12])
        plan = self.control.plans[public['id']]
        self.assertEqual(public['unit'], 'docker:' + full)
        self.assertEqual(plan['request']['unit'], 'docker:' + full)
        self.assertEqual(plan['services'], ['x-ui.service'])


if __name__ == '__main__': unittest.main()
