import copy
import json
import pathlib
import tempfile
import unittest
from unittest.mock import Mock
from outage_diagnostics import OutageDiagnostics, _chebur_summary

class Provider:
    def __init__(self, available=True):
        self.value = {'available': available, 'busy': False, 'servers': {}}
        self.calls = []
    def snapshot(self): return copy.deepcopy(self.value)
    def start(self, server, targets=None, interface=None):
        self.calls.append((copy.deepcopy(server), targets, interface))
        self.value['busy'] = True
        self.value['servers'][server['id']] = {'host': server['host'], 'status': 'running', 'startedAt': 1000}
    def finish(self, sid='a', **result):
        self.value['busy'] = False
        self.value['servers'][sid].update(status='done', finishedAt=1002, **result)

class OutageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / 'outage.json'; self.now = 1000
        self.registry = [{'id': 'a', 'name': 'A', 'host': '198.51.100.9', 'port': 22, 'key': 'not-for-provider', 'user': 'private-user'}]
        self.native, self.chebur = Provider(), Provider()
        self.manager = OutageDiagnostics(self.path, lambda: self.registry, lambda: self.native, lambda: self.chebur, clock=lambda: self.now)
    def fail(self, **values): return self.manager.observe(self.registry[0], dict(ok=False, **values))
    def success(self): return self.manager.observe(self.registry[0], {'ok': True})
    def row(self): return self.manager.snapshot()['servers']['a']
    def test_first_failure_enqueues_without_network_in_monitor(self):
        self.assertTrue(self.fail()); self.assertEqual(self.row()['status'], 'queued')
        self.assertEqual(self.native.calls, []); self.assertEqual(self.chebur.calls, [])
        self.manager.tick()
        self.assertEqual(len(self.native.calls), 1); self.assertEqual(len(self.chebur.calls), 1)
        for provider in (self.native, self.chebur):
            self.assertNotIn('key', provider.calls[0][0]); self.assertNotIn('user', provider.calls[0][0])
    def test_repeated_failures_and_cached_get_do_not_relaunch(self):
        self.fail(); self.manager.tick()
        for _ in range(10):
            self.now += 10; self.assertFalse(self.fail()); self.manager.snapshot(); self.manager.tick()
        self.assertEqual(len(self.chebur.calls), 1)
    def test_healthy_servers_are_not_probed(self):
        self.success(); self.manager.tick()
        self.assertEqual(self.manager.snapshot()['servers'], {}); self.assertFalse(self.chebur.calls)
    def test_restart_does_not_replay_uncertain_check(self):
        self.fail(); self.manager.tick()
        restarted = OutageDiagnostics(self.path, lambda: self.registry, lambda: self.native, lambda: self.chebur, clock=lambda: self.now)
        restarted.observe(self.registry[0], {'ok': False}); restarted.tick()
        self.assertEqual(restarted.snapshot()['servers']['a']['status'], 'interrupted'); self.assertEqual(len(self.chebur.calls), 1)
    def test_success_cancels_not_started_work(self):
        self.fail(); self.success(); self.manager.tick()
        self.assertEqual(self.row()['status'], 'cancelled'); self.assertFalse(self.chebur.calls)
    def test_recovery_is_preserved_without_declaring_provider_passed(self):
        self.fail(); self.manager.tick(); self.now += 2; self.success()
        self.assertTrue(self.row()['sshReachable']); self.assertEqual(self.row()['cheburcheck']['status'], 'running')
    def test_flap_cooldown_and_subsequent_new_outage(self):
        self.fail(); self.success(); self.now += 50; self.assertFalse(self.fail())
        self.success(); self.now += 301; self.assertTrue(self.fail()); self.assertEqual(self.row()['triggeredAt'], self.now)
    def test_persistent_second_outage_is_queued_after_flap_cooldown_once(self):
        self.fail(); self.success(); self.now += 50; self.assertFalse(self.fail())
        self.now += 251; self.assertTrue(self.fail()); self.manager.tick()
        self.assertEqual(len(self.chebur.calls), 1)
        for _ in range(5):
            self.now += 60; self.assertFalse(self.fail()); self.manager.tick()
        self.assertEqual(len(self.chebur.calls), 1)
    def test_later_manual_provider_result_is_not_attributed_to_outage(self):
        self.fail(); self.manager.tick()
        self.chebur.value['servers']['a'].update(status='done', startedAt=1010, probes=[{'verdicts': ['ok']}])
        self.manager.tick(); self.assertEqual(self.row()['cheburcheck']['status'], 'running')
    def test_changed_registry_host_hides_and_replaces_old_result(self):
        self.fail(); self.registry[0]['host'] = '198.51.100.10'
        self.assertEqual(self.manager.snapshot()['servers'], {}); self.assertTrue(self.fail()); self.assertEqual(self.row()['host'], '198.51.100.10')
    def test_port_change_rebinds_identity(self):
        self.fail(); self.registry[0]['port'] = 2222
        self.assertFalse(self.manager.snapshot()['servers']); self.assertTrue(self.fail())
    def test_removed_server_never_runs(self):
        self.fail(); self.registry.clear(); self.manager.tick()
        self.assertFalse(self.chebur.calls); self.assertFalse(self.manager.snapshot()['servers'])
    def test_native_point_unavailable_is_not_rf_success(self):
        self.native.value['available'] = False; self.fail(); self.manager.tick()
        self.assertEqual(self.row()['native']['status'], 'unavailable'); self.assertFalse(self.row()['native']['ruPointVerified'])
        self.assertFalse(self.native.calls); self.assertEqual(len(self.chebur.calls), 1)
    def test_foreign_native_point_is_never_rf_measurement(self):
        self.fail(); self.manager.tick(); self.native.finish(point={'country': 'NL'}, verdict='reachable'); self.chebur.finish(probes=[], check={'blocked': False})
        self.manager.tick()
        self.assertEqual(self.row()['native']['verdict'], 'point_not_ru'); self.assertFalse(self.row()['native']['ruPointVerified']); self.assertEqual(self.row()['cheburcheck']['verdict'], 'unconfirmed')
    def test_mixed_chebur_probes_are_algorithmic_indication(self):
        result = _chebur_summary({'status': 'done', 'probes': [{'verdicts': ['tspu_block']}, {'verdicts': ['ok']}], 'check': {'blocked': True}})
        self.assertEqual(result['verdict'], 'mixed'); self.assertEqual(result['probeCount'], 2); self.assertTrue(result['databaseMatch'])
    def test_no_database_match_does_not_mean_reachable(self):
        self.assertEqual(_chebur_summary({'status': 'done', 'check': {'blocked': False}})['verdict'], 'unconfirmed')
    def test_partial_ok_probes_do_not_mean_passed(self):
        self.assertEqual(_chebur_summary({'status': 'partial', 'probes': [{'verdicts': ['ok']}]})['verdict'], 'unconfirmed')
    def test_stale_previous_result_cannot_complete_new_outage(self):
        self.fail(); self.manager.tick(); self.chebur.value['servers']['a'].update(status='done', startedAt=900, probes=[{'verdicts': ['ok']}]); self.manager.tick()
        self.assertEqual(self.row()['cheburcheck']['status'], 'running')
    def test_dns_case_normalization_preserves_target_binding(self):
        self.registry[0]['host'] = 'VPS.Example.COM'; self.fail(); self.manager.tick()
        self.chebur.finish(host='vps.example.com', probes=[{'verdicts': ['ok']}]); self.manager.tick()
        self.assertEqual(self.row()['cheburcheck']['status'], 'done')
    def test_mismatched_provider_target_cannot_complete(self):
        self.fail(); self.manager.tick(); self.chebur.finish(host='198.51.100.10', probes=[{'verdicts': ['ok']}]); self.manager.tick()
        self.assertEqual(self.row()['cheburcheck']['status'], 'running')
    def test_auth_and_hostkey_failures_explicit_and_no_secret_retained(self):
        for error, reason in [('Permission denied /secret/key', 'authentication'), ('Host key verification failed /secret/key', 'host_key')]:
            self.registry[0]['port'] += 1; self.fail(error=error, tcpOk=True)
            self.assertEqual(self.row()['reason'], reason); self.assertNotIn('/secret', json.dumps(self.row()))
        self.registry[0]['port'] += 1; self.fail(error='remote failed', tcpOk=True); self.assertEqual(self.row()['reason'], 'ssh_or_remote_error')
    def test_busy_provider_waits_without_launch_and_deadline_bounds(self):
        self.chebur.value['busy'] = True; self.fail(); self.manager.tick(); self.assertFalse(self.chebur.calls)
        self.now += 901; self.manager.tick()
        self.assertEqual(self.row()['status'], 'partial'); self.assertEqual(self.row()['cheburcheck']['verdict'], 'deadline_exceeded'); self.assertFalse(self.chebur.calls)
    def test_two_outages_serialize_with_existing_provider_busy_flag(self):
        second = dict(self.registry[0], id='b', host='198.51.100.10'); self.registry.append(second)
        self.fail(); self.manager.observe(second, {'ok': False}); self.manager.tick(); self.assertEqual(len(self.chebur.calls), 1)
        self.chebur.finish(probes=[]); self.native.finish(point={'country': 'RU'}, verdict='unconfirmed'); self.manager.tick(); self.assertEqual(len(self.chebur.calls), 2)
    def test_provider_exception_is_sanitized(self):
        self.chebur.snapshot = Mock(side_effect=RuntimeError('private-url-token')); self.fail(); self.manager.tick()
        self.assertEqual(self.row()['cheburcheck']['verdict'], 'provider_unavailable'); self.assertNotIn('private-url-token', json.dumps(self.row()))
    def test_state_and_provider_facts_are_persisted_private(self):
        self.fail(); self.manager.tick()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600); self.assertNotIn('not-for-provider', self.path.read_text())
    def test_no_telegram_transport_dependency(self):
        import outage_diagnostics
        self.assertFalse(hasattr(outage_diagnostics, 'AlertManager'))
if __name__ == '__main__': unittest.main()
