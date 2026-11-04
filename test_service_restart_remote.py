import copy
import json
import pathlib
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from service_restart_remote import RemoteServiceRestart, restart_digest, restart_preservation, validate_restart_target, restart_awg_digest, restart_guard_digest


def runtime():
    unit = {'Id': 'x-ui.service', 'Names': 'x-ui.service', 'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running', 'MainPID': '10',
            'ActiveEnterTimestampMonotonic': '10', 'ExecMainStartTimestampMonotonic': '10', 'InvocationID': 'old', 'FragmentPath': '/unit/x-ui.service'}
    ssh = dict(unit, Id='ssh.service', Names='ssh.service sshd.service', MainPID='20', InvocationID='ssh')
    return {'bootId': 'boot', 'system': 'running', 'aptBusy': [], 'services': {'x-ui.service': unit, 'ssh.service': ssh},
            'containers': {}, 'awg': {'awg1': {'ifindex': 4, 'configHash': 'configuration'}},
            'configHashes': {'/protected': 'hash'}, 'safety': {'forwarding': {'ipv4': '1'}, 'sshGuard': {'present': True, 'structureHash': 'guard'}},
            'target': {'unit': 'x-ui.service', 'name': 'x-ui.service', 'kind': 'service', 'identity': 'x-ui.service',
                       'active': True, 'pid': '10', 'startedAt': '10', 'invocation': 'old'}}


def restarted(before):
    after = copy.deepcopy(before)
    after['target'].update(pid='11', startedAt='11', invocation='new')
    after['services']['x-ui.service'].update(MainPID='11', ActiveEnterTimestampMonotonic='11', ExecMainStartTimestampMonotonic='11', InvocationID='new')
    return after


class RemoteRestartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name); self.remote = RemoteServiceRestart(self.root / 'state')
        self.before = runtime(); self.jid = 'a' * 32
        self.req = {'job': self.jid, 'unit': 'x-ui.service', 'services': ['x-ui.service'], 'expiresAt': time.time() + 300,
                    'revision': restart_digest(self.before)}

    def scheduled(self):
        with patch.object(self.remote, 'info', return_value=self.before), patch.object(self.remote, '_run', return_value=Mock(returncode=0)):
            self.remote.schedule(self.req, 'fixed adapter source')
        return json.loads(self.remote._paths(self.jid)[2].read_text())

    def test_deny_core_and_unknown_targets_and_shell_option_inputs(self):
        for unit in ['ssh.service', 'sshd@root.service', 'docker.service', 'containerd.service', 'nftables.service', 'fail2ban.service',
                     'server-deck.service', 'server-deck-auth.service', 'server-deck-ssh-guard.service', 'systemd-networkd.service',
                     '-bad.service', 'x-ui.service;reboot', '../../x-ui.service']:
            with self.assertRaises(ValueError): validate_restart_target(unit, [unit] if not unit.startswith('-') else ['x-ui.service'])
        with self.assertRaises(ValueError): validate_restart_target('nginx.service', ['x-ui.service'])
        self.assertEqual(validate_restart_target('awg-quick@awg1.service', ['awg-quick@awg1.service']), 'service')
        self.assertEqual(validate_restart_target('caddy.service', ['caddy.service']), 'service')

    def test_durable_schedule_deduplicates_and_never_executes_restart_directly(self):
        with patch.object(self.remote, 'info', return_value=self.before), patch.object(self.remote, '_run', return_value=Mock(returncode=0)) as run:
            self.assertTrue(self.remote.schedule(self.req, 'fixed adapter source')['accepted'])
            self.assertTrue(self.remote.schedule(self.req, 'fixed adapter source')['reused'])
        self.assertEqual(run.call_count, 1)
        args = run.call_args.args[0]
        self.assertEqual(args[0], 'systemd-run'); self.assertIn('--service-restart-worker', args)
        self.assertNotIn('restart', args); self.assertNotIn('reboot', args)
        folder, status, request, source = self.remote._paths(self.jid)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in (status, request, source)))

    def test_schedule_late_ack_cannot_overwrite_worker_dispatch_marker(self):
        _, record, _, _ = self.remote._paths(self.jid)
        def acknowledge(*args, **kwargs):
            state = json.loads(record.read_text()); state.update(state='running', dispatchStarted=True)
            self.remote._write(record, state); return Mock(returncode=0)
        with patch.object(self.remote, 'info', return_value=self.before), patch.object(self.remote, '_run', side_effect=acknowledge):
            self.remote.schedule(self.req, 'source')
        self.assertTrue(json.loads(record.read_text())['dispatchStarted'])
        self.assertEqual(json.loads(record.read_text())['state'], 'running')

    def test_preflight_state_drift_and_apt_busy_never_schedule(self):
        with patch.object(self.remote, 'info', return_value=dict(self.before, bootId='different')), patch.object(self.remote, '_run') as run:
            with self.assertRaisesRegex(ValueError, 'Состояние изменилось'): self.remote.schedule(self.req, 'source')
            run.assert_not_called()
        with patch.object(self.remote, '_collect', return_value=dict(self.before, aptBusy=['dpkg'])):
            with self.assertRaisesRegex(ValueError, 'APT/dpkg'): self.remote.info(self.req)

    def test_worker_marks_before_dispatch_then_restarts_only_once(self):
        req = self.scheduled(); _, record, _, _ = self.remote._paths(self.jid)
        def restart(target):
            self.assertTrue(json.loads(record.read_text())['dispatchStarted'])
            self.assertEqual(target['unit'], 'x-ui.service'); return True
        with patch.object(self.remote, 'info', return_value=self.before), patch.object(self.remote, 'observe', return_value=restarted(self.before)), patch.object(self.remote, '_restart', side_effect=restart) as call:
            self.remote.worker(req); self.remote.worker(req)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(json.loads(record.read_text())['state'], 'succeeded')

    def test_changed_preflight_or_expired_plan_fails_before_any_command(self):
        req = self.scheduled()
        with patch.object(self.remote, 'info', return_value=dict(self.before, bootId='new')), patch.object(self.remote, '_restart') as restart:
            self.remote.worker(req); restart.assert_not_called()
        self.assertEqual(json.loads(self.remote._paths(self.jid)[1].read_text())['state'], 'failed')

    def test_other_service_awg_or_config_changes_require_review_without_rollback(self):
        for kind in ['ssh', 'awg', 'config']:
            with self.subTest(kind=kind):
                self.jid = {'ssh': 'b', 'awg': 'c', 'config': 'd'}[kind] * 32; self.req['job'] = self.jid
                req = self.scheduled(); after = restarted(self.before)
                if kind == 'ssh': after['services']['ssh.service']['MainPID'] = '999'
                elif kind == 'awg': after['awg']['awg1']['configHash'] = 'changed'
                else: after['configHashes']['/protected'] = 'changed'
                with patch.object(self.remote, 'info', return_value=self.before), patch.object(self.remote, 'observe', return_value=after), patch.object(self.remote, '_restart', return_value=True) as restart:
                    self.remote.worker(req)
                state = json.loads(self.remote._paths(self.jid)[1].read_text())
                self.assertEqual(state['state'], 'needs_review'); self.assertTrue(state['violations']); self.assertEqual(restart.call_count, 1)

    def test_unknown_restart_outcome_times_out_without_retry(self):
        req = self.scheduled(); _, record, _, _ = self.remote._paths(self.jid)
        state = json.loads(record.read_text()); state['deadline'] = time.time() - 1; self.remote._write(record, state)
        with patch.object(self.remote, 'info', return_value=self.before), patch.object(self.remote, 'observe', return_value=self.before), patch.object(self.remote, '_restart', side_effect=TimeoutError()) as restart:
            self.remote.worker(req)
        self.assertEqual(restart.call_count, 1)
        self.assertEqual(json.loads(record.read_text())['state'], 'needs_review')

    def test_restart_argv_has_no_shell_and_only_selected_target(self):
        with patch.object(self.remote, '_run', return_value=Mock(returncode=0)) as run:
            self.remote._restart(self.before['target'])
        self.assertEqual(run.call_args.args[0], ['systemctl', 'restart', '--', 'x-ui.service'])

    def test_catalog_only_known_active_apps_and_managed_container_full_identity(self):
        full = 'b' * 64; unknown = 'c' * 64; value = copy.deepcopy(self.before)
        value['services']['ssh.service'] = value['services']['x-ui.service']
        value['containers'] = {full: {'id': full, 'name': 'amnezia-awg', 'active': True},
                               unknown: {'id': unknown, 'name': 'unrelated-database', 'active': True}}
        with patch.object(self.remote, '_collect', return_value=value):
            targets = self.remote.catalog({'services': ['x-ui.service', 'ssh.service']})['targets']
        self.assertEqual({t['unit'] for t in targets}, {'x-ui.service', 'docker:' + full})

    def test_full_docker_identity_and_config_binding_is_not_runtime_pid_only(self):
        before = runtime(); after = restarted(before)
        after['target']['identity'] = 'another.service'
        self.assertFalse(restart_preservation(before, after)[0])
        old = restart_digest(before); before['configHashes']['new'] = 'newhash'
        self.assertNotEqual(restart_digest(before), old)

    def test_canonical_alias_and_fragment_cannot_hide_a_protected_service(self):
        for state in [dict(self.before['services']['x-ui.service'], Id='ssh.service'),
                      dict(self.before['services']['x-ui.service'], Names='innocent.service sshd.service'),
                      dict(self.before['services']['x-ui.service'], FragmentPath='/usr/lib/systemd/system/server-deck.service')]:
            with self.assertRaises(ValueError): self.remote._safe_service_target('innocent.service', state)

    def test_awg_hash_ignores_peer_order_and_roaming_but_binds_peer_keys(self):
        a = '[Interface]\nPrivateKey=private\nListenPort=10\n[Peer]\nPublicKey=A\nPresharedKey=secretA\nEndpoint=1.1.1.1:10\nAllowedIPs=10.0.0.1/32,10.0.0.2/32\n[Peer]\nPublicKey=B\nPresharedKey=secretB\n'
        b = '[Interface]\nListenPort=10\nPrivateKey=private\n[Peer]\nPresharedKey=secretB\nPublicKey=B\n[Peer]\nAllowedIPs=10.0.0.2/32,10.0.0.1/32\nEndpoint=2.2.2.2:20\nPresharedKey=secretA\nPublicKey=A\n'
        self.assertEqual(restart_awg_digest(a), restart_awg_digest(b))
        self.assertNotEqual(restart_awg_digest(a), restart_awg_digest(b.replace('secretA', 'changed')))

    def test_worker_waits_for_scheduling_lock_then_rechecks_before_one_dispatch(self):
        req = self.scheduled()
        with patch('service_restart_remote.fcntl.flock', side_effect=[BlockingIOError(), BlockingIOError(), None]) as flock, patch('service_restart_remote.time.sleep'), patch.object(self.remote, 'info', return_value=self.before), patch.object(self.remote, 'observe', return_value=restarted(self.before)), patch.object(self.remote, '_restart', return_value=True) as restart:
            self.remote.worker(req)
        self.assertEqual(flock.call_count, 3); self.assertEqual(restart.call_count, 1)
        self.assertEqual(json.loads(self.remote._paths(self.jid)[1].read_text())['state'], 'succeeded')

    def test_guard_digest_ignores_dynamic_bans_handles_and_counters_only(self):
        first = {'nftables': [{'metainfo': {'version': 'one'}}, {'set': {'name': 'blocked4', 'handle': 1, 'elem': ['1.1.1.1'], 'type': 'ipv4_addr'}}, {'rule': {'handle': 2, 'expr': [{'counter': {'packets': 3, 'bytes': 40}}, {'drop': None}]}}]}
        second = copy.deepcopy(first); second['nftables'][0]['metainfo']['version'] = 'two'
        second['nftables'][1]['set'].update(handle=99, elem=['8.8.8.8'])
        second['nftables'][2]['rule']['expr'][0]['counter'] = {'packets': 500, 'bytes': 6000}
        self.assertEqual(restart_guard_digest(first), restart_guard_digest(second))
        second['nftables'][2]['rule']['expr'][-1] = {'accept': None}
        self.assertNotEqual(restart_guard_digest(first), restart_guard_digest(second))

    def test_missing_live_guard_or_forwarding_change_is_never_success(self):
        after = restarted(self.before); after['safety']['sshGuard']['present'] = False
        self.assertTrue(restart_preservation(self.before, after)[1])
        after = restarted(self.before); after['safety']['forwarding']['ipv4'] = '0'
        self.assertTrue(restart_preservation(self.before, after)[1])

    def test_inactive_service_or_unmanaged_stopped_docker_is_not_started(self):
        inactive = dict(self.before['services']['x-ui.service'], ActiveState='inactive')
        with patch.object(self.remote, '_platform'), patch.object(self.remote, '_service', return_value=inactive), patch.object(self.remote, '_containers', return_value={}):
            with self.assertRaisesRegex(ValueError, 'остановлена'): self.remote._collect({'unit': 'x-ui.service', 'services': ['x-ui.service']})
        full = 'b' * 64
        for name, active in [('unrelated-database', True), ('amnezia-awg', False)]:
            container = {'id': full, 'name': name, 'image': 'sha256:fixed', 'active': active, 'pid': '5', 'startedAt': 'old', 'health': ''}
            with patch.object(self.remote, '_platform'), patch.object(self.remote, '_service', return_value=self.before['services']['x-ui.service']), patch.object(self.remote, '_containers', return_value={full: container}), patch.object(self.remote, '_container', return_value=container):
                with self.assertRaises(ValueError): self.remote._collect({'unit': 'docker:' + full, 'services': []})

    def test_inside_awg_container_snapshot_uses_fixed_read_only_commands_and_only_hashes(self):
        identity = 'b' * 64
        config = '[Interface]\nPrivateKey=do-not-return\nListenPort=123\n[Peer]\nPublicKey=peer\nAllowedIPs=10.0.0.2/32\n'
        with patch.object(self.remote, '_run', side_effect=[Mock(stdout='awg0'), Mock(stdout=config)]) as run:
            value = self.remote._container_awg({'id': identity})
        self.assertEqual(run.call_args_list[0].args[0], ['docker', 'exec', '--', identity, 'awg', 'show', 'interfaces'])
        self.assertEqual(run.call_args_list[1].args[0], ['docker', 'exec', '--', identity, 'awg', 'showconf', 'awg0'])
        self.assertNotIn('do-not-return', json.dumps(value))
        self.assertEqual(value, {'awg0': restart_awg_digest(config)})
        with patch.object(self.remote, '_run', return_value=Mock(stdout='')):
            with self.assertRaises(ValueError): self.remote._container_awg({'id': identity})

    def test_selected_awg_container_can_change_pid_but_never_keys_or_peers(self):
        identity = 'b' * 64; before = runtime()
        before['target'] = {'unit': 'docker:' + identity, 'kind': 'docker', 'identity': identity, 'name': 'amnezia-awg',
                            'image': 'sha256:fixed', 'active': True, 'pid': '10', 'startedAt': 'old', 'invocation': '', 'awg': {'awg0': 'fixedconfig'}}
        before['containers'][identity] = dict(before['target'])
        after = copy.deepcopy(before); after['target'].update(pid='11', startedAt='new'); after['containers'][identity].update(pid='11', startedAt='new')
        confirmed, violations = restart_preservation(before, after)
        self.assertTrue(confirmed); self.assertEqual(violations, [])
        after['target']['awg']['awg0'] = 'newkeys'
        self.assertTrue(restart_preservation(before, after)[1])


if __name__ == '__main__': unittest.main()
