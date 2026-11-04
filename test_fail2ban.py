import copy
import json
import pathlib
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import fail2ban_remote as remote
from fail2ban import Fail2banManager


def settings(**kw):
    return dict(maxretry=5, findtime=600, bantime=3600, ignoreip=[], **kw)


def info():
    return dict(installed=True, privileged=True, editable=True, jail='sshd', jails=['recidive', 'sshd'],
                revision='a' * 64, controllerIp='192.0.2.1', sshPorts=[22], effective=settings(),
                protectedIgnoreip=['127.0.0.0/8', '192.0.2.1', '::1'], checkedAt=time.time())


class ValidationTests(unittest.TestCase):
    def test_valid_settings_and_canonical_cidr(self):
        result = remote.validate_settings(dict(maxretry=5, findtime=600, bantime=3600,
                                               ignoreip=['198.51.100.23/24', '2001:db8::1', '198.51.100.0/24']))
        self.assertEqual(result['ignoreip'], ['198.51.100.0/24', '2001:db8::1'])

    def test_injection_broad_networks_and_hostnames_rejected(self):
        for value in ['example.com', '192.0.2.1\n[DEFAULT]', '0.0.0.0/0', '::/0', '10.0.0.0/7', 'fe80::1%eth0']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                remote.validate_settings(dict(maxretry=5, findtime=600, bantime=3600, ignoreip=[value]))

    def test_all_bounds_and_types(self):
        for key, value in [('maxretry', 2), ('maxretry', 101), ('maxretry', True), ('maxretry', '5'),
                           ('findtime', 59), ('findtime', 86401), ('bantime', -1), ('bantime', 2592001)]:
            data = settings(); data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): remote.validate_settings(data)

    def test_unknown_keys_rejected(self):
        with self.assertRaises(ValueError): remote.validate_settings(dict(settings(), command='restart'))

    def test_existing_ignoreip_parser(self):
        self.assertEqual(remote.ignored_addresses('These IP addresses/networks are ignored:\n|- 127.0.0.1/8\n`- ::1'),
                         ['127.0.0.0/8', '::1'])

    def test_existing_unknown_ignoreip_blocks_edit(self):
        with self.assertRaises(ValueError): remote.ignored_addresses('These IP addresses/networks are ignored:\n`- administrator.example')

    def test_dropin_preserves_protected_values_and_no_actions(self):
        content, ignored = remote.dropin(settings(), ['127.0.0.0/8', '192.0.2.1', '::1'])
        self.assertIn('192.0.2.1', ignored)
        self.assertEqual([line for line in content.splitlines() if '=' in line],
                         ['maxretry = 5', 'findtime = 600', 'bantime = 3600', 'ignoreip = 127.0.0.0/8 192.0.2.1 ::1'])
        for bad in ('action =', 'enabled =', 'port =', 'filter =', 'backend ='): self.assertNotIn(bad, content)

    def test_source_address_requires_actual_ssh_connection(self):
        with patch.dict(remote.os.environ, {}, clear=True), self.assertRaises(ValueError): remote.source_address()
        with patch.dict(remote.os.environ, {'SSH_CONNECTION': '192.0.2.1 12345 198.51.100.5 22'}):
            self.assertEqual(remote.source_address(), '192.0.2.1')


class FakeControl:
    def __init__(self):
        self.lock = threading.RLock(); self.busy = set(); self.keydir = pathlib.Path('/tmp')
        self.target = dict(id='node', host='192.0.2.55', name='Example', port=22, user='root', key='example', services=[])
    def server(self, sid):
        if sid != self.target['id']: raise ValueError('Сервер не найден')
        return copy.deepcopy(self.target)
    def servers(self): return [self.server('node')]


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.c = FakeControl(); self.calls = []
        def transport(server, request):
            self.calls.append(copy.deepcopy(request))
            if request['op'] == 'inspect': return info()
            if request['op'] == 'apply': return {'state': 'succeeded', 'job': request['job']}
            return {'state': 'unknown', 'mutationBusy': False}
        self.transport = transport
        self.manager = Fail2banManager(self.c, pathlib.Path(self.tmp.name), transport=transport)

    def plan(self): return self.manager.plan(dict(settings(), server='node'))

    def test_plan_does_not_write_remote_and_protects_controller(self):
        plan = self.plan()
        self.assertEqual([x['op'] for x in self.calls], ['inspect'])
        self.assertIn('192.0.2.1', plan['effectiveIgnoreip'])
        self.assertNotIn('binding', plan)

    def test_wrong_confirmation_sends_no_mutation(self):
        plan = self.plan()
        with self.assertRaises(ValueError): self.manager.apply({'plan': plan['id'], 'confirmation': 'no'})
        self.assertEqual(len(self.calls), 1)

    def test_expired_plan_sends_no_mutation(self):
        plan = self.plan(); self.manager.plans[plan['id']]['expiresAt'] = time.time() - 1
        with self.assertRaises(ValueError): self.manager.apply({'plan': plan['id'], 'confirmation': plan['host']})
        self.assertEqual(len(self.calls), 1)

    def test_registry_binding_change_blocks_apply(self):
        plan = self.plan(); self.c.target['key'] = 'different'
        with self.assertRaises(ValueError): self.manager.apply({'plan': plan['id'], 'confirmation': plan['host']})

    def test_apply_single_use_and_shared_lock(self):
        plan = self.plan()
        result = self.manager.apply({'plan': plan['id'], 'confirmation': plan['host']})
        self.assertEqual(result['state'], 'succeeded'); self.assertEqual(self.c.busy, set())
        self.assertEqual(self.calls[-1]['revision'], 'a' * 64)
        with self.assertRaises(ValueError): self.manager.apply({'plan': plan['id'], 'confirmation': plan['host']})
        self.assertEqual(sum(x['op'] == 'apply' for x in self.calls), 1)

    def test_existing_shared_mutation_blocks_plan(self):
        self.c.busy.add('node')
        with self.assertRaises(ValueError): self.plan()
        self.assertEqual(self.calls, [])

    def test_service_busy_guard_blocks_plan(self):
        self.manager.busy_fn = lambda sid: True
        with self.assertRaises(ValueError): self.plan()

    def test_missing_package_blocks_plan(self):
        self.manager.transport = lambda s, r: {'installed': False, 'editable': False, 'message': 'Не установлен'}
        with self.assertRaisesRegex(ValueError, 'Не установлен'): self.plan()

    def test_uncertain_transport_holds_lock_and_never_replays(self):
        plan = self.plan()
        def transport(s, r): raise TimeoutError()
        self.manager.transport = transport
        result = self.manager.apply({'plan': plan['id'], 'confirmation': plan['host']})
        self.assertEqual(result['state'], 'needs_review'); self.assertIn('node', self.c.busy)
        again = Fail2banManager(self.c, pathlib.Path(self.tmp.name), transport=self.transport)
        self.assertIn('node', self.c.busy)
        self.assertEqual(again.inspect('node')['pendingJobs'][0]['job'], result['job'])

    def test_review_waits_for_plan_and_checks_remote_lock(self):
        plan = self.plan(); self.manager.transport = lambda s, r: (_ for _ in ()).throw(TimeoutError())
        result = self.manager.apply({'plan': plan['id'], 'confirmation': plan['host']})
        self.manager.transport = self.transport
        with self.assertRaises(ValueError): self.manager.review({'job': result['job'], 'confirmation': plan['host']})
        path = self.manager.root / (result['job'] + '.json'); value = json.loads(path.read_text()); value['expiresAt'] = 0
        path.write_text(json.dumps(value))
        self.manager.transport = lambda s, r: {'state': 'applying', 'mutationBusy': True} if r['op'] == 'status' else info()
        with self.assertRaises(ValueError): self.manager.review({'job': result['job'], 'confirmation': plan['host']})
        self.manager.transport = self.transport
        self.assertEqual(self.manager.review({'job': result['job'], 'confirmation': plan['host']})['state'], 'reviewed')
        self.assertEqual(self.c.busy, set())

    def test_old_terminal_review_cannot_unlock_new_unrelated_job(self):
        plan = self.plan(); result = self.manager.apply({'plan': plan['id'], 'confirmation': plan['host']})
        self.c.busy.add('node')
        path = self.manager.root / (result['job'] + '.json'); value = json.loads(path.read_text()); value['expiresAt'] = 0
        path.write_text(json.dumps(value)); self.calls.clear()
        with self.assertRaises(ValueError): self.manager.review({'job': result['job'], 'confirmation': plan['host']})
        self.assertEqual(self.calls, []); self.assertIn('node', self.c.busy)

    def test_review_is_serialized_and_rechecks_other_control_jobs(self):
        plan = self.plan(); self.manager.transport = lambda s, r: (_ for _ in ()).throw(TimeoutError())
        result = self.manager.apply({'plan': plan['id'], 'confirmation': plan['host']})
        path = self.manager.root / (result['job'] + '.json'); value = json.loads(path.read_text()); value['expiresAt'] = 0
        path.write_text(json.dumps(value)); data = {'job': result['job'], 'confirmation': plan['host']}
        def transport(s, r):
            if r['op'] == 'status':
                with self.assertRaisesRegex(ValueError, 'уже выполняется'): self.manager.review(data)
                self.c.jobs = {'other': {'server': 'node', 'state': 'submitting'}}
                return {'state': 'unknown', 'mutationBusy': False}
            return info()
        self.manager.transport = transport
        with self.assertRaisesRegex(ValueError, 'Другая задача'): self.manager.review(data)
        self.assertIn('node', self.c.busy); self.assertEqual(self.manager.reviewing, set())


class RemoteApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        base = pathlib.Path(self.tmp.name)
        self.config = base / 'etc'; self.config.mkdir(); (self.config / 'jail.d').mkdir()
        self.managed = self.config / 'jail.d/zzzz-server-deck.local'
        self.state = base / 'state'
        for name, value in [('CONFIG', self.config), ('MANAGED', self.managed), ('STATE', self.state)]:
            p = patch.object(remote, name, value); p.start(); self.addCleanup(p.stop)
        self.before = info(); self.after = info(); self.after['effective']['ignoreip'] = self.before['protectedIgnoreip']
        self.commands = []
        self.req = dict(op='apply', job='b' * 32, revision='a' * 64, settings=settings(), expiresAt=time.time() + 300)

    def command(self, args, timeout=15): self.commands.append(args); return 'OK'

    def test_success_managed_file_only_and_jail_reload(self):
        other = self.config / 'jail.local'; other.write_text('[recidive]\nenabled=true\n')
        with patch.object(remote, 'inspect', side_effect=[self.before, self.after]), patch.object(remote, 'command', self.command):
            result = remote.apply(self.req)
        self.assertEqual(result['state'], 'succeeded')
        self.assertEqual(other.read_text(), '[recidive]\nenabled=true\n')
        self.assertEqual(self.commands, [['fail2ban-client', '-t'], ['fail2ban-client', 'reload', 'sshd']])
        self.assertNotIn('--restart', sum(self.commands, [])); self.assertNotIn('--unban', sum(self.commands, []))
        self.assertTrue((pathlib.Path(result['backup']) / 'before.json').exists())

    def test_revision_change_no_write(self):
        self.req['revision'] = 'c' * 64
        with patch.object(remote, 'inspect', return_value=self.before), self.assertRaises(ValueError): remote.apply(self.req)
        self.assertFalse(self.managed.exists())

    def test_existing_dropin_backed_up_and_rollback_on_config_error(self):
        original = b'[sshd]\nmaxretry = 7\n'; self.managed.write_bytes(original)
        count = [0]
        def command(args, timeout=15):
            count[0] += 1
            if count[0] == 1: raise RuntimeError('test fails')
            return self.command(args)
        with patch.object(remote, 'inspect', side_effect=[self.before, self.before]), patch.object(remote, 'command', command):
            result = remote.apply(self.req)
        self.assertEqual(result['state'], 'failed'); self.assertTrue(result['rolledBack'])
        self.assertEqual(self.managed.read_bytes(), original)
        self.assertEqual((pathlib.Path(result['backup']) / 'managed.local').read_bytes(), original)

    def test_new_dropin_removed_on_reload_failure(self):
        count = [0]
        def command(args, timeout=15):
            count[0] += 1
            if count[0] == 2: raise RuntimeError('reload fails')
            return self.command(args)
        with patch.object(remote, 'inspect', side_effect=[self.before, self.before]), patch.object(remote, 'command', command):
            result = remote.apply(self.req)
        self.assertTrue(result['rolledBack']); self.assertFalse(self.managed.exists())

    def test_unconfirmed_effective_values_roll_back(self):
        unexpected = copy.deepcopy(self.after); unexpected['effective']['maxretry'] = 9
        with patch.object(remote, 'inspect', side_effect=[self.before, unexpected, self.before]), patch.object(remote, 'command', self.command):
            result = remote.apply(self.req)
        self.assertTrue(result['rolledBack']); self.assertFalse(self.managed.exists())

    def test_failed_rollback_requires_review(self):
        with patch.object(remote, 'inspect', return_value=self.before), patch.object(remote, 'command', side_effect=RuntimeError()):
            result = remote.apply(self.req)
        self.assertEqual(result['state'], 'needs_review'); self.assertFalse(result['rolledBack'])

    def test_remote_duplicate_does_not_reload(self):
        with patch.object(remote, 'inspect', side_effect=[self.before, self.after]), patch.object(remote, 'command', self.command):
            result = remote.apply(self.req)
            again = remote.apply(self.req)
        self.assertEqual(again['state'], result['state']); self.assertEqual(len(self.commands), 2)

    def test_symlink_managed_file_rejected(self):
        target = self.config / 'target'; target.write_text('do not change'); self.managed.symlink_to(target)
        with patch.object(remote, 'inspect', return_value=self.before), self.assertRaises(ValueError): remote.apply(self.req)
        self.assertEqual(target.read_text(), 'do not change')

    def test_remote_mutation_lock_blocks_apply(self):
        self.state.mkdir(); lock = open(self.state / 'mutation.lock', 'a'); self.addCleanup(lock.close)
        remote.fcntl.flock(lock, remote.fcntl.LOCK_EX | remote.fcntl.LOCK_NB)
        with self.assertRaises(ValueError): remote.apply(self.req)

    def test_expiry_rejects_before_writes(self):
        self.req['expiresAt'] = time.time() - 1
        with self.assertRaises(ValueError): remote.apply(self.req)
        self.assertFalse(self.state.exists())

    def test_status_does_not_apply(self):
        self.state.mkdir()
        (self.state / ('fail2ban-' + self.req['job'] + '.json')).write_text(json.dumps({'state': 'succeeded'}))
        result = remote.dispatch({'op': 'status', 'job': self.req['job']})
        self.assertEqual(result, {'state': 'succeeded', 'mutationBusy': False})


if __name__ == '__main__': unittest.main()
