import copy
import json
import pathlib
import tempfile
import threading
import unittest
from unittest.mock import patch

from alerts import AlertError, AlertManager, DeliveryError, TelegramClient


class FakeTelegram:
    def __init__(self):
        self.calls = []
        self.updates = []
        self.sent = []
        self.webhook = ''
        self.failure = None

    def __call__(self, method, data):
        self.calls.append((method, copy.deepcopy(data)))
        if method == 'getMe':
            return {'username': 'test_deck_bot', 'id': 123456}
        if method == 'getWebhookInfo':
            return {'url': self.webhook}
        if method == 'getUpdates':
            return copy.deepcopy(self.updates)
        if method == 'sendMessage':
            if self.failure:
                raise self.failure
            self.sent.append(copy.deepcopy(data))
            return {'message_id': len(self.sent)}
        raise AssertionError(method)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.token_path = self.root / 'token'
        self.token = '123456789:' + 'a' * 35
        self.token_path.write_text(self.token)
        self.now = 1000000.0
        self.servers = [{'id': 'one', 'name': 'Первый VPS', 'host': '192.0.2.1',
                         'services': ['x-ui.service', 'optional.service']}]
        self.telegram = FakeTelegram()
        self.report = {'servers': {}}
        self.manager = self.reopen()

    def reopen(self):
        return AlertManager(self.root, lambda: self.servers, lambda: self.report,
                            self.token_path, transport=self.telegram, clock=lambda: self.now)

    def tearDown(self):
        self.temp.cleanup()

    def sample(self, **changes):
        row = {'ts': self.now, 'ok': True, 'cpu': 10, 'memory': {'used': 20, 'total': 100},
               'disk': {'used': 30, 'total': 100}, 'alerts': [], 'failed': [], 'awg': [],
               'services': [{'unit': 'x-ui.service', 'state': 'active'},
                            {'unit': 'optional.service', 'state': 'inactive'}], 'containers': []}
        row.update(changes)
        self.report['servers']['one'] = {'latest': row, 'stale': False}
        return row

    def step(self, seconds=60, **changes):
        self.now += seconds
        self.sample(**changes)
        self.manager.tick()

    def connect(self, group=False):
        status = self.manager.start_pairing()
        code = status['pairing']['code']
        self.telegram.updates = [{'update_id': 4, 'message': {'date': self.now,
                                  'text': '/deck_' + code if group else '/start deck_' + code,
                                  'chat': {'id': -10 if group else 42,
                                           'type': 'group' if group else 'private',
                                           'title': 'Моя группа' if group else '', 'first_name': 'Owner'}}}]
        self.sample()
        self.manager.tick()
        self.telegram.updates = []
        self.assertEqual(len(self.telegram.sent), 1)
        self.telegram.sent.clear()
        self.now += 2


class PairingTests(Fixture):
    def test_group_command_is_short_and_accepts_bot_mention(self):
        status = self.manager.start_pairing()
        code = status['pairing']['code']
        self.assertEqual(status['pairing']['command'], '/deck ' + code)
        self.telegram.updates = [{'update_id': 4, 'message': {'date': self.now,
                                  'text': '/deck@test_deck_bot ' + code,
                                  'chat': {'id': -10, 'type': 'supergroup', 'title': 'Group'}}}]
        self.sample()
        self.manager.tick()
        self.assertEqual(self.manager.status()['chat']['id'], '-10')
        self.assertEqual(self.manager.status()['chat']['type'], 'supergroup')
        self.assertIsNone(self.manager.status()['pairing'])

    def test_private_binding_requires_exact_fresh_code_and_hides_token(self):
        status = self.manager.start_pairing()
        pairing = status['pairing']
        self.assertIn('https://t.me/test_deck_bot?start=deck_', pairing['startUrl'])
        self.assertEqual(pairing['expiresAt'] - self.now, 1800)
        self.telegram.updates = [{'update_id': 1, 'message': {'date': self.now, 'text': '/start wrong',
                                  'chat': {'id': 99, 'type': 'private'}}}]
        self.manager.tick()
        self.assertIsNone(self.manager.status()['chat'])
        self.telegram.updates.append({'update_id': 2, 'message': {'date': self.now - 100, 'text': '/start deck_' + pairing['code'],
                                    'chat': {'id': 99, 'type': 'private'}}})
        self.manager.tick()
        self.assertIsNone(self.manager.status()['chat'])
        self.telegram.updates.append({'update_id': 3, 'message': {'date': self.now, 'text': '/start deck_' + pairing['code'],
                                    'chat': {'id': 42, 'type': 'private', 'first_name': 'Owner'}}})
        self.manager.tick()
        status = self.manager.status()
        self.assertEqual(status['chat']['id'], '42')
        self.assertTrue(status['enabled'])
        self.assertIsNone(status['pairing'])
        self.assertNotIn(self.token, json.dumps(status))
        self.assertNotIn(self.token, self.manager.path.read_text())
        self.assertEqual(self.manager.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.reopen().status()['enabled'])

    def test_group_expiry_cancel_and_webhook_do_not_hijack_existing_integration(self):
        self.connect(group=True)
        self.assertEqual(self.manager.status()['chat']['id'], '-10')
        self.telegram.webhook = 'https://existing.example/secret'
        status = self.manager.start_pairing()
        self.assertTrue(status['pairing']['blocked'])
        before = len(self.telegram.calls)
        self.manager.tick()
        self.assertNotIn('getUpdates', [m for m, _ in self.telegram.calls[before:]])
        self.assertFalse(any(m in ('deleteWebhook', 'setWebhook') for m, _ in self.telegram.calls))
        self.assertNotIn('existing.example', json.dumps(status))
        self.manager.cancel_pairing()
        self.assertIsNone(self.manager.status()['pairing'])
        self.telegram.webhook = ''
        self.manager.start_pairing()
        self.now += 1801
        self.assertIsNone(self.manager.status()['pairing'])

    def test_configuration_policy_and_test_delivery_when_monitoring_paused(self):
        for config in [{'enabled': True}, {'cpuThreshold': 101}, {'resourceConsecutive': 0},
                       {'services': 'yes'}, {'unknown': True}, {'remindersMinutes': 5}]:
            with self.assertRaises(AlertError):
                self.manager.configure(config)
        self.connect()
        self.manager.configure({'enabled': False, 'cpuThreshold': 90})
        self.manager.test()
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertIn('Проверка доставки', self.telegram.sent[0]['text'])
        with self.assertRaises(AlertError):
            self.manager.test()


class AlertTests(Fixture):
    def test_unknown_or_ssh_failure_breaks_pending_consecutive_resource_checks(self):
        self.connect()
        for interruption in ('ssh', 'stale', 'gap'):
            with self.subTest(interruption=interruption):
                self.manager = self.reopen()
                self.manager.configure({'enabled': False})
                self.manager.configure({'enabled': True})
                self.telegram.sent.clear()
                self.step(cpu=95)
                self.step(cpu=95)
                if interruption == 'ssh':
                    self.step(ok=False)
                elif interruption == 'stale':
                    self.now += 181
                    self.manager.tick()
                    self.telegram.sent.clear()
                else:
                    self.now += 181
                self.step(cpu=95)
                self.assertFalse(any('Высокая загрузка' in x['text'] for x in self.telegram.sent))
                self.step(cpu=95)
                self.assertFalse(any('Высокая загрузка' in x['text'] for x in self.telegram.sent))
                self.step(cpu=95)
                self.assertTrue(any('Высокая загрузка' in x['text'] for x in self.telegram.sent))

    def test_healthy_baseline_is_quiet_and_outage_recovery_are_deduplicated(self):
        self.connect()
        for _ in range(3):
            self.step()
        self.assertFalse(self.telegram.sent)
        self.step(ok=False)
        self.assertFalse(self.telegram.sent)
        for _ in range(5):
            self.manager.tick()  # same timestamp must not add confirmations
        self.assertFalse(self.telegram.sent)
        self.step(ok=False)
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertIn('Нет доступа', self.telegram.sent[0]['text'])
        self.manager = self.reopen()
        self.step(ok=False)
        self.assertEqual(len(self.telegram.sent), 1)
        self.step()
        self.assertEqual(len(self.telegram.sent), 1)
        self.step()
        self.assertEqual(len(self.telegram.sent), 2)
        self.assertIn('Восстановление', self.telegram.sent[-1]['text'])

    def test_sustained_resources_and_missing_value_are_not_false_recovery(self):
        self.connect()
        self.step(cpu=95)
        self.step(cpu=95)
        self.assertFalse(self.telegram.sent)
        self.step(cpu=95)
        self.assertEqual(len(self.telegram.sent), 1)
        self.step(cpu=None)
        self.step(cpu=None)
        self.assertEqual(len(self.telegram.sent), 1)
        self.step(cpu=10)
        self.step(cpu=10)
        self.assertEqual(len(self.telegram.sent), 2)

    def test_optional_stopped_service_quiet_but_previously_active_service_and_container_alert(self):
        self.connect()
        self.step(containers=[{'name': 'telemt', 'state': 'active', 'description': 'Up 1 hour'}])
        for _ in range(2):
            self.step(services=[{'unit': 'x-ui.service', 'state': 'inactive'},
                                {'unit': 'optional.service', 'state': 'inactive'}],
                      containers=[{'name': 'telemt', 'state': 'inactive', 'description': 'Exited'}])
        self.now += 2
        self.manager.tick()  # drain second incident, not a duplicate sample
        texts = [x['text'] for x in self.telegram.sent]
        self.assertEqual(len(texts), 2)
        self.assertFalse(any('optional.service' in x for x in texts))
        self.assertTrue(any('x-ui.service' in x for x in texts))
        self.assertTrue(any('telemt' in x for x in texts))

    def test_stale_and_future_data_are_unknown_not_healthy(self):
        self.connect()
        self.now += 181
        self.manager.tick()
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertIn('Нет свежих измерений', self.telegram.sent[0]['text'])
        self.now += 60
        self.report['servers']['one']['latest']['ts'] = self.now + 1000
        self.manager.tick()
        self.assertEqual(len(self.telegram.sent), 1)
        self.step()
        self.assertEqual(len(self.telegram.sent), 1)
        self.step()
        self.assertEqual(len(self.telegram.sent), 2)
        self.assertIn('Восстановление', self.telegram.sent[-1]['text'])

    def test_temporarily_unreadable_history_uses_last_seen_timestamp_for_stale_grace(self):
        self.connect()
        self.step()
        self.step()
        self.step()
        self.now += 60
        self.report = {'servers': {}}
        self.manager.tick()
        self.assertFalse(self.telegram.sent)
        self.now += 121
        self.manager.tick()
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertIn('Нет свежих измерений', self.telegram.sent[-1]['text'])

    def test_awg_no_online_peers_is_not_a_fault_but_missing_interface_and_sustained_rx_are(self):
        self.connect()
        self.manager.configure({'awgRx': True})
        interface = {'interface': 'awg1', 'online': 0, 'peers': 2, 'rxErrorsDelta': 0}
        self.step(awg=[interface])
        self.step(awg=[interface])
        self.assertFalse(self.telegram.sent)
        for _ in range(3):
            self.step(awg=[dict(interface, rxErrorsDelta=3)])
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertIn('Диагностика AWG', self.telegram.sent[-1]['text'])
        self.step(awg=[])
        self.step(awg=[])
        self.assertEqual(len(self.telegram.sent), 2)
        self.assertIn('не обнаружен', self.telegram.sent[-1]['text'])

    def test_awg_rx_flapping_is_diagnostic_only_by_default_and_missing_stays_protected(self):
        self.connect()
        interface = {'interface': 'awg1', 'online': 0, 'peers': 2, 'rxErrorsDelta': 0}
        for delta in [2, 31, 4, 0, 0] * 4:
            self.step(awg=[dict(interface, rxErrorsDelta=delta)])
        self.assertFalse(self.manager.status()['config']['awgRx'])
        self.assertFalse(self.telegram.sent)
        self.assertFalse(any(key.endswith(':rx') for key in self.manager.state['rules']))
        self.step(awg=[])
        self.step(awg=[])
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertIn('Интерфейс AWG не обнаружен', self.telegram.sent[0]['text'])

    def test_optional_awg_rx_has_hourly_cooldown_across_clear_retrigger_and_restart(self):
        self.connect()
        self.manager.configure({'awgRx': True})
        interface = {'interface': 'awg1', 'rxErrorsDelta': 31}
        for _ in range(3):
            self.step(awg=[interface])
        first = self.now
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertTrue(self.telegram.sent[0]['text'].startswith('ℹ️'))
        for _ in range(2):
            self.step(awg=[dict(interface, rxErrorsDelta=0)])
        self.assertEqual(len(self.telegram.sent), 1, 'RX diagnostics must never send a recovery notification')
        for _ in range(3):
            self.step(awg=[interface])
        self.manager = self.reopen()
        for delta in [0, 0, 2, 31, 2, 0, 0]:
            self.step(awg=[dict(interface, rxErrorsDelta=delta)])
        self.assertEqual(len(self.telegram.sent), 1)
        self.now = first + 3420
        for _ in range(3):
            self.step(awg=[interface])
        self.assertEqual(len(self.telegram.sent), 2)
        self.assertFalse(any('Восстановление' in item['text'] for item in self.telegram.sent))

    def test_legacy_awg_rx_migration_preserves_other_incidents_queue_history_and_baselines(self):
        self.connect()
        server = self.servers[0]
        self.manager._advance(server, 'ssh', True, self.now, 'SSH outage', 'Keep', 1, self.now)
        self.manager._advance(server, 'awg:awg1:rx', True, self.now, 'Old RX', 'Retire', 1, self.now)
        self.manager.state['expectedAwg'] = {'one': {'awg1': True}}
        legacy = copy.deepcopy(self.manager.state)
        legacy.pop('awgRxPolicy')
        legacy.pop('awgRxLastNotice')
        legacy['config'].pop('awgRx')
        expected_rules = {key: copy.deepcopy(value) for key, value in legacy['rules'].items() if not key.endswith(':rx')}
        expected_queue = [q for q in legacy['queue'] if q['rule']['id'] == 'one|ssh']
        self.manager.path.write_text(json.dumps(legacy))
        self.manager = self.reopen()
        self.assertFalse(self.manager.storage_error)
        self.assertEqual(self.manager.state['awgRxPolicy'], 1)
        self.assertFalse(self.manager.status()['config']['awgRx'])
        self.assertEqual(self.manager.state['rules'], expected_rules)
        self.assertEqual(self.manager.state['queue'], expected_queue)
        self.assertEqual(self.manager.state['history'], legacy['history'])
        self.assertEqual(self.manager.state['expectedServices'], legacy['expectedServices'])
        self.assertEqual(self.manager.state['expectedAwg'], legacy['expectedAwg'])
        self.assertFalse(self.telegram.sent)
        self.manager = self.reopen()
        self.assertEqual(self.manager.state['queue'], expected_queue, 'Migration must be idempotent')

    def test_only_awg_rx_toggle_resets_only_rx_and_preserves_notice_cooldown(self):
        self.connect()
        server = self.servers[0]
        self.manager._advance(server, 'ssh', True, self.now, 'SSH outage', 'Keep', 1, self.now)
        expected_rules = copy.deepcopy(self.manager.state['rules'])
        expected_queue = copy.deepcopy(self.manager.state['queue'])
        expected_baseline = copy.deepcopy(self.manager.state['expectedServices'])
        self.manager.configure({'awgRx': True})
        self.manager._advance(server, 'awg:awg1:rx', True, self.now, 'RX diagnostic', 'Test', 1, self.now, diagnostic=True)
        self.manager.configure({'awgRx': False})
        self.assertEqual(self.manager.state['rules'], expected_rules)
        self.assertEqual(self.manager.state['queue'], expected_queue)
        self.assertEqual(self.manager.state['expectedServices'], expected_baseline)
        self.assertEqual(self.manager.state['awgRxLastNotice']['one|awg:awg1:rx'], self.now)

    def test_new_server_is_covered_automatically_and_removed_server_is_pruned(self):
        self.connect()
        self.servers.append({'id': 'two', 'name': 'Second', 'host': '192.0.2.2'})
        for _ in range(2):
            self.now += 60
            self.sample()
            self.report['servers']['two'] = {'latest': {'ts': self.now, 'ok': False}}
            self.manager.tick()
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertIn('192.0.2.2', self.telegram.sent[0]['text'])
        self.servers.pop()
        self.manager.tick()
        self.assertFalse(any(r['server'] == 'two' for r in self.manager.status()['active']))


class DeliveryTests(Fixture):
    def test_only_one_sender_reserves_messages_during_concurrent_test_and_tick(self):
        self.connect()
        self.manager._queue('test', 'First', 'First')
        self.manager._queue('test', 'Second', 'Second')
        started = threading.Event()
        release = threading.Event()
        calls = []

        def blocking_transport(method, data):
            self.assertEqual(method, 'sendMessage')
            calls.append(data)
            started.set()
            release.wait(3)
            return {'message_id': len(calls)}

        self.manager.transport = blocking_transport
        worker = threading.Thread(target=self.manager._flush)
        worker.start()
        self.assertTrue(started.wait(1))
        try:
            self.manager._flush()
            self.assertEqual(len(calls), 1)
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.manager._flush()
        self.assertEqual(len(calls), 1)
        self.now += 1
        self.manager._flush()
        self.assertEqual(len(calls), 2)

    def test_429_backoff_is_persistent_and_does_not_flood(self):
        self.connect()
        self.telegram.failure = DeliveryError(429, 40)
        self.manager.test()
        self.assertEqual(self.manager.status()['queueLength'], 1)
        attempts = sum(m == 'sendMessage' for m, _ in self.telegram.calls)
        self.manager.tick()
        self.assertEqual(sum(m == 'sendMessage' for m, _ in self.telegram.calls), attempts)
        self.manager = self.reopen()
        self.now += 39
        self.manager.tick()
        self.assertEqual(sum(m == 'sendMessage' for m, _ in self.telegram.calls), attempts)
        self.telegram.failure = None
        self.now += 1
        self.manager.tick()
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertEqual(self.manager.status()['queueLength'], 0)

    def test_no_recovery_for_an_alarm_that_was_never_delivered(self):
        self.connect()
        self.telegram.failure = DeliveryError(403)
        self.step(ok=False)
        self.step(ok=False)
        self.assertEqual(self.manager.status()['history'][0]['status'], 'failed')
        self.telegram.failure = None
        self.step()
        self.step()
        self.assertFalse(self.telegram.sent)

    def test_interrupted_delivery_is_not_automatically_replayed_after_restart(self):
        self.connect()
        self.manager._queue('test', 'Example', 'Test')
        self.manager.state['queue'][0]['phase'] = 'sending'
        self.manager._save()
        self.manager = self.reopen()
        self.manager.tick()
        self.assertFalse(self.telegram.sent)
        self.assertEqual(self.manager.status()['history'][0]['status'], 'uncertain')

    def test_raw_transport_errors_and_corrupt_storage_do_not_leak_secrets(self):
        self.connect()
        self.telegram.failure = RuntimeError('https://api.telegram.org/bot' + self.token + '/sendMessage')
        self.manager.test()
        self.assertNotIn(self.token, json.dumps(self.manager.status()))
        self.manager.path.write_text('{"version":1,"rules":[]}' )
        reopened = self.reopen()
        self.assertFalse(reopened.status()['enabled'])
        self.assertIn('повреждён', reopened.status()['lastError'])
        before = reopened.path.read_text()
        reopened.tick()
        self.assertEqual(reopened.path.read_text(), before)

    def test_corrupt_nested_shapes_disable_alerts_without_breaking_status(self):
        self.connect()
        original = json.loads(self.manager.path.read_text())
        for key, wrong in [('queue', ['bad']), ('rules', {'a': 'bad'}),
                           ('pairing', {'code': 1}), ('chat', {'id': []}),
                           ('history', [1]), ('lastSampleAt', {'one': 'not-time'})]:
            with self.subTest(key=key):
                content = dict(original, **{key: wrong})
                self.manager.path.write_text(json.dumps(content))
                reopened = self.reopen()
                self.assertFalse(reopened.status()['enabled'])
                self.assertIn('повреждён', reopened.status()['lastError'])
                reopened.tick()
                self.assertEqual(json.loads(reopened.path.read_text()), content)


class TransportTests(unittest.TestCase):
    def test_http_errors_do_not_expose_token_url_or_telegram_description(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'token'
            token = '123456789:' + 'b' * 35
            path.write_text(token)
            client = TelegramClient(path)
            from urllib.error import URLError
            with patch('alerts.urllib.request.urlopen', side_effect=URLError('bot' + token)):
                with self.assertRaises(DeliveryError) as error:
                    client.call('getMe')
            self.assertNotIn(token, str(error.exception))


if __name__ == '__main__':
    unittest.main()
