"""Critical-only policy: positive evidence, one app incident and no retries spam."""
import copy
import unittest

from alerts import AlertError, DeliveryError, critical_category, is_critical_rule
from test_alerts import Fixture


class CriticalFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.servers[0]['services'] = ['mtproxyl.service', 'awg-quick@awg0.service', 'x-ui.service']

    @staticmethod
    def services(mt='active', awg='active', helper='active'):
        return [{'unit': unit, 'state': state, 'collectionOk': True} for unit, state in
                [('mtproxyl.service', mt), ('awg-quick@awg0.service', awg), ('x-ui.service', helper)]]

    @staticmethod
    def containers(mt='active', awg=None, probe=None):
        values = [{'name': 'mtproxyl', 'state': mt, 'description': mt}]
        if awg is not None:
            values.append({'name': 'amnezia-awg2', 'state': awg, 'description': awg,
                           'awg': {'collectionOk': True, 'interfaces': ['awg0']} if probe is None else probe})
        return values

    def sample(self, **changes):
        values = {'services': self.services(), 'containers': self.containers(),
                  'awg': [{'interface': 'awg0', 'peers': 0, 'online': 0, 'rxErrorsDelta': 0}],
                  'collectionOk': {'services': True, 'containers': True, 'awg': True}}
        values.update(changes)
        return super().sample(**values)

    def critical(self):
        self.connect()
        self.manager.configure({'criticalOnly': True})

    def notifications(self, kind=None):
        return [h for h in self.manager.status()['history'] if h['kind'] in ('alarm', 'recovery', 'reminder') and
                h['status'] == 'sent' and (kind is None or h['kind'] == kind)]


class CriticalClassificationTests(unittest.TestCase):
    def test_only_explicit_data_plane_targets_are_critical(self):
        allowed = ['ssh', 'app:awg', 'app:mtproxyl', 'awg:awg0:missing',
                   'service:awg-quick@awg0.service', 'service:amneziawg.service',
                   'service:amnezia-awg2.service', 'service:mtproxyl.service',
                   'service:mtproxyl-telemt.service', 'service:mtproxy.service',
                   'service:telemt@main.service', 'service:mtproxyl@one.service',
                   'container:mtproxyl', 'container:mtproxyl-telemt', 'container:telemt',
                   'container:amnezia-awg2', 'container:amnezia-awg-1', 'container:amnezia-awg-v2',
                   'awg-container:amnezia-awg2:missing']
        excluded = [None, '', 'unknown', 'resource:cpu', 'reboot-required', 'awg:awg0:rx',
                    'service:x-ui.service', 'service:mtproxyl-panel.service',
                    'service:mtproxyl-zapret2.service', 'service:mtproxyl-pq-nginx.service',
                    'service:nginx.service', 'service:caddy.service', 'service:fail2ban.service',
                    'service:amnezia-awg-update.service', 'service:telemt-log.timer',
                    'container:mtproxyl-panel', 'container:mtproxyl-logs',
                    'container:amnezia-xray', 'container:database']
        for key in allowed:
            with self.subTest(key=key):
                self.assertTrue(is_critical_rule(key))
        for key in excluded:
            with self.subTest(key=key):
                self.assertFalse(is_critical_rule(key))
        self.assertEqual(critical_category('container:amnezia-awg2'), 'app:awg')
        self.assertEqual(critical_category('service:telemt.service'), 'app:mtproxyl')


class CriticalPolicyTests(CriticalFixture):
    def test_preset_is_backward_compatible_and_enforces_only_critical_channels(self):
        self.assertFalse(self.manager.status()['config']['criticalOnly'])
        self.connect()
        with self.assertRaises(AlertError):
            self.manager.configure({'criticalOnly': 1})
        self.manager.configure({'criticalOnly': True, 'resources': True, 'security': True,
                                'awgRx': True, 'reboot': True, 'remindersMinutes': 15,
                                'outageConsecutive': 1, 'recoveryConsecutive': 1})
        config = self.manager.status()['config']
        for name in ('resources', 'security', 'awgRx', 'reboot'):
            self.assertFalse(config[name])
        self.assertTrue(config['awg'])
        self.assertTrue(config['services'])
        self.assertEqual((config['outageConsecutive'], config['recoveryConsecutive'], config['remindersMinutes']), (2, 2, 0))

    def test_resources_helpers_reboot_rx_security_and_peer_idle_stay_quiet(self):
        self.critical()
        for _ in range(5):
            self.step(cpu=99, disk={'used': 99, 'total': 100}, services=self.services(helper='failed'),
                      rebootRequired=True, awg=[{'interface': 'awg0', 'peers': 5, 'online': 0,
                                                 'latestHandshake': 0, 'rxErrorsDelta': 999}])
        self.assertFalse(self.notifications())
        self.assertIsNone(self.manager._queue('security', 'Security', 'Security'))
        self.assertIsNone(self.manager._queue('security_digest', 'Digest', 'Digest'))
        self.assertTrue(all(is_critical_rule(rule['rule']) for rule in self.manager.state['rules'].values()))

    def test_two_fresh_ssh_failures_and_two_recoveries_produce_one_pair_without_reminders(self):
        self.critical()
        self.step(ok=False)
        self.assertFalse(self.notifications())
        for _ in range(3):
            self.now += 10
            self.manager.tick()  # same failure measurement cannot confirm
        self.assertFalse(self.notifications())
        self.step(ok=False)
        self.assertEqual(len(self.notifications('alarm')), 1)
        for _ in range(5):
            self.step(ok=False)
        self.manager = self.reopen()
        self.step(ok=False)
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.step(ok=True)
        self.assertFalse(self.notifications('recovery'))
        self.step(ok=True)
        self.assertEqual(len(self.notifications('recovery')), 1)
        self.step(ok=True)
        self.assertEqual(len(self.notifications()), 2)

    def test_missing_stale_and_invalid_ssh_data_neither_alert_nor_recover(self):
        self.critical()
        self.now += 600
        self.report['servers']['one'] = {'latest': None}
        self.manager.tick()
        self.assertFalse(self.notifications())
        self.assertNotIn('one|unknown', self.manager.state['rules'])
        self.step(ok=False)
        self.step(ok=False)
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.now += 600
        self.manager.tick()
        self.step(ok=None)
        self.step(ok=None)
        self.assertFalse(self.notifications('recovery'))
        self.assertTrue(self.manager.state['rules']['one|ssh']['active'])

    def test_service_and_container_failures_coalesce_into_one_mtproxyl_incident(self):
        self.critical()
        for _ in range(2):
            self.step(services=self.services(mt='failed'), containers=self.containers(mt='inactive'))
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.assertIn('MTProxyL недоступен', self.telegram.sent[-1]['text'])
        self.assertIn('mtproxyl.service', self.telegram.sent[-1]['text'])
        for _ in range(3):
            self.step(services=self.services(mt='failed'), containers=self.containers(mt='active'))
        self.assertEqual(len(self.notifications()), 1)  # one healthy component cannot mask a failed one
        self.step()
        self.assertFalse(self.notifications('recovery'))
        self.step()
        self.assertEqual(len(self.notifications('recovery')), 1)

    def test_awg_container_service_and_interface_failures_coalesce_without_peer_checks(self):
        self.critical()
        self.step(containers=self.containers(awg='active'))
        for _ in range(2):
            self.step(services=self.services(awg='inactive'), containers=self.containers(awg='inactive'), awg=[])
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.assertIn('AWG недоступен', self.telegram.sent[-1]['text'])
        self.step(containers=self.containers(awg='active'))
        self.assertFalse(self.notifications('recovery'))
        self.step(containers=self.containers(awg='active'))
        self.assertEqual(len(self.notifications('recovery')), 1)

    def test_running_container_without_inside_awg_is_failure_even_without_interface_baseline(self):
        self.connect()
        self.manager.state['expectedAwg'] = {}
        self.manager.state['expectedServices'] = {}
        self.manager.configure({'criticalOnly': True})
        values = dict(services=[], awg=[], containers=self.containers(awg='active', probe={'collectionOk': True, 'interfaces': []}))
        self.step(**values)
        self.step(**values)
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.assertIn('интерфейс AWG', self.telegram.sent[-1]['text'])

    def test_unsupported_host_awg_tool_does_not_prove_expected_host_interface_missing(self):
        self.critical()
        self.assertTrue(self.manager.state['expectedAwg']['one']['awg0'])
        for _ in range(3):
            self.step(awgSupported=False, awg=[])
        self.assertFalse(self.notifications())
        self.assertEqual(self.manager.state['rules']['one|app:awg']['bad'], 0)
        self.step(awgSupported=True, awg=[])
        self.step(awgSupported=True, awg=[])
        self.assertEqual(len(self.notifications('alarm')), 1)

    def test_unknown_inventory_and_namespace_probes_never_recover_an_active_incident(self):
        self.critical()
        self.step(containers=self.containers(awg='active'))
        for _ in range(2):
            self.step(services=self.services(awg='failed'), containers=self.containers(awg='inactive'), awg=[])
        self.assertEqual(len(self.notifications('alarm')), 1)
        for _ in range(3):
            self.step(services=self.services(), containers=self.containers(awg='active', probe={'collectionOk': False, 'interfaces': []}),
                      collectionOk={'services': True, 'containers': True, 'awg': False})
        self.assertFalse(self.notifications('recovery'))
        self.assertTrue(self.manager.state['rules']['one|app:awg']['active'])
        self.step(containers=self.containers(awg='active'))
        self.assertFalse(self.notifications('recovery'))
        self.step(containers=self.containers(awg='active'))
        self.assertEqual(len(self.notifications('recovery')), 1)

    def test_missing_collector_success_metadata_and_unit_flags_cannot_recover(self):
        self.critical()
        self.step(services=self.services(mt='failed'))
        self.step(services=self.services(mt='failed'))
        self.assertEqual(len(self.notifications('alarm')), 1)
        for _ in range(2):
            self.step(collectionOk={})
        self.assertFalse(self.notifications('recovery'))
        rows = self.services()
        for row in rows:
            del row['collectionOk']
        for _ in range(2):
            self.step(services=rows)
        self.assertFalse(self.notifications('recovery'))
        self.step()
        self.assertFalse(self.notifications('recovery'))
        self.step()
        self.assertEqual(len(self.notifications('recovery')), 1)

    def test_complete_missing_container_is_down_but_failed_docker_collection_is_unknown(self):
        self.critical()
        for _ in range(3):
            self.step(containers=[], collectionOk={'services': True, 'containers': False, 'awg': False})
        self.assertFalse(self.notifications())
        self.step(containers=[])
        self.step(containers=[])
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.step(containers=None)
        self.step(containers=None)
        self.assertFalse(self.notifications('recovery'))

    def test_first_seen_failed_service_remains_required_when_it_disappears(self):
        self.critical()
        self.manager.state['expectedServices']['one'].pop('mtproxyl.service', None)
        self.step(services=self.services(mt='failed'))
        self.step(services=self.services(mt='failed'))
        self.assertEqual(len(self.notifications('alarm')), 1)
        rows = [row for row in self.services() if row['unit'] != 'mtproxyl.service']
        self.step(services=rows)
        self.step(services=rows)
        self.assertFalse(self.notifications('recovery'))
        self.assertTrue(self.manager.state['expectedServices']['one']['mtproxyl.service'])
        self.step()
        self.step()
        self.assertEqual(len(self.notifications('recovery')), 1)

    def test_first_seen_unhealthy_container_remains_required_when_it_disappears(self):
        self.critical()
        self.manager.state['expectedContainers']['one'].pop('mtproxyl', None)
        values = self.containers(mt='inactive')
        values[0]['description'] = 'Exited (unhealthy)'
        self.step(containers=values)
        self.step(containers=values)
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.step(containers=[])
        self.step(containers=[])
        self.assertFalse(self.notifications('recovery'))
        self.assertTrue(self.manager.state['expectedContainers']['one']['mtproxyl'])
        self.step()
        self.step()
        self.assertEqual(len(self.notifications('recovery')), 1)

    def test_policy_change_preserves_notified_legacy_incident_and_recovery_baseline(self):
        self.connect()
        self.step(services=self.services(mt='failed'))
        self.step(services=self.services(mt='failed'))
        self.assertEqual(len(self.notifications('alarm')), 1)
        old = copy.deepcopy(self.manager.state['rules']['one|service:mtproxyl.service'])
        expected = copy.deepcopy(self.manager.state['expectedAwg'])
        self.manager.configure({'criticalOnly': True})
        app = self.manager.state['rules']['one|app:mtproxyl']
        self.assertEqual((app['active'], app['notified'], app['since']), (old['active'], old['notified'], old['since']))
        self.assertEqual(self.manager.state['expectedAwg'], expected)
        self.step(services=self.services(mt='failed'))
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.step()
        self.step()
        self.assertEqual(len(self.notifications('recovery')), 1)

    def test_queued_app_notice_is_held_during_host_loss_and_ssh_is_prioritized(self):
        self.critical()
        self.telegram.failure = DeliveryError(429, 60)
        self.step(services=self.services(mt='failed'))
        self.step(services=self.services(mt='failed'))
        self.assertTrue(self.manager.state['queue'])
        self.telegram.failure = None
        self.step(ok=False)
        self.assertFalse(self.notifications())
        self.step(ok=False)
        self.assertEqual(len(self.notifications()), 1)
        self.assertIn('SSH', self.telegram.sent[-1]['text'])
        self.step(services=self.services(mt='failed'))
        self.step(services=self.services(mt='failed'))
        self.assertEqual(len(self.notifications('recovery')), 1)
        self.now += 2
        self.manager.tick()
        self.assertEqual(len(self.notifications('alarm')), 2)
        self.assertIn('MTProxyL', self.telegram.sent[-1]['text'])

    def test_ambiguous_critical_delivery_is_not_retried_across_restart(self):
        self.critical()
        attempts = sum(method == 'sendMessage' for method, _ in self.telegram.calls)
        self.telegram.failure = DeliveryError(0)
        self.step(ok=False)
        self.step(ok=False)
        self.assertFalse(self.manager.state['queue'])
        self.assertEqual(self.manager.status()['history'][0]['status'], 'uncertain')
        self.manager = self.reopen()
        self.telegram.failure = None
        for _ in range(3):
            self.step(ok=False)
        self.assertEqual(sum(method == 'sendMessage' for method, _ in self.telegram.calls), attempts + 1)
        self.step()
        self.assertFalse(self.notifications('recovery'))
        self.step()
        self.assertEqual(len(self.notifications('recovery')), 1)
        self.manager = self.reopen()
        self.step()
        self.assertEqual(len(self.notifications('recovery')), 1)
        self.assertFalse(self.manager.state['rules']['one|ssh'].get('deliveryUncertain', False))

    def test_ambiguous_critical_app_attempt_survives_migration_and_only_recovers_once(self):
        self.critical()
        self.telegram.failure = DeliveryError(500)
        self.step(services=self.services(mt='failed'))
        self.step(services=self.services(mt='failed'))
        self.assertTrue(self.manager.state['rules']['one|app:mtproxyl']['deliveryUncertain'])
        self.manager = self.reopen()
        self.manager.configure({'criticalOnly': True})
        self.telegram.failure = None
        self.step()
        self.step()
        self.assertEqual(len(self.notifications('recovery')), 1)
        for _ in range(3):
            self.step()
        self.assertEqual(len(self.notifications()), 1)

    def test_known_429_retries_but_stale_expired_critical_notice_is_not_sent(self):
        self.critical()
        self.telegram.failure = DeliveryError(429, 60)
        self.step(ok=False)
        self.step(ok=False)
        self.assertEqual(self.manager.state['queue'][0]['expiresAt'], self.now + 900)
        self.now += 1000
        self.report['servers']['one'] = {'latest': None}
        self.telegram.failure = None
        self.manager = self.reopen()
        self.manager.tick()
        self.assertFalse(self.telegram.sent)
        self.assertFalse(self.manager.state['queue'])

    def test_master_off_holds_pending_automatic_critical_delivery_but_allows_explicit_test(self):
        self.critical()
        self.telegram.failure = DeliveryError(429, 60)
        self.step(ok=False)
        self.step(ok=False)
        self.assertTrue(self.manager.state['queue'])
        self.manager.configure({'enabled': False})
        self.telegram.failure = None
        self.now += 60
        self.sample(ok=False)
        self.manager.tick()
        self.assertFalse(self.telegram.sent)
        self.assertTrue(self.manager.state['queue'])
        self.assertTrue(self.manager.state['rules']['one|ssh']['active'])
        self.manager.test()
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertIn('Проверка доставки', self.telegram.sent[0]['text'])
        self.manager.configure({'enabled': True})
        self.step(ok=False)
        self.assertEqual(len(self.notifications('alarm')), 1)

    def test_leaving_critical_mode_continues_existing_app_incident_without_component_duplicates(self):
        self.critical()
        for _ in range(2):
            self.step(services=self.services(mt='failed'), containers=self.containers(mt='inactive'))
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.manager.configure({'criticalOnly': False})
        for _ in range(3):
            self.step(services=self.services(mt='failed'), containers=self.containers(mt='inactive'))
        self.assertEqual(len(self.notifications('alarm')), 1)
        self.assertNotIn('one|service:mtproxyl.service', self.manager.state['rules'])
        self.assertNotIn('one|container:mtproxyl', self.manager.state['rules'])
        self.step()
        self.assertFalse(self.notifications('recovery'))
        self.step()
        self.assertEqual(len(self.notifications('recovery')), 1)
        self.step()
        self.assertNotIn('one|app:mtproxyl', self.manager.state['rules'])
        self.assertEqual(len(self.notifications()), 2)

    def test_leaving_critical_mode_retires_recovered_unsent_aggregate_without_orphan_recovery(self):
        self.critical()
        self.telegram.failure = DeliveryError(429, 60)
        self.step(services=self.services(mt='failed'))
        self.step(services=self.services(mt='failed'))
        self.manager.configure({'criticalOnly': False})
        self.now += 60
        self.telegram.failure = None
        self.step()
        self.step()
        self.assertNotIn('one|app:mtproxyl', self.manager.state['rules'])
        self.assertIn('one|service:mtproxyl.service', self.manager.state['rules'])
        self.assertFalse(self.notifications())
        self.assertFalse(self.manager.state['queue'])
        self.step(services=self.services(mt='failed'))
        self.step(services=self.services(mt='failed'))
        self.assertEqual(len(self.notifications('alarm')), 1)


if __name__ == '__main__':
    unittest.main()
