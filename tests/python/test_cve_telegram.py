import copy
import json
import threading
from unittest.mock import patch

from alerts import AlertError, AlertManager, DeliveryError, RELEASE_CVE, RELEASE_SOURCE, RELEASE_PAGE
from test_critical_alerts import CriticalFixture


class ReleaseTests(CriticalFixture):
    def setUp(self):
        self.provider = None
        self.events = []
        self.provider_calls = 0
        super().setUp()
        for number in range(2, 7):
            self.servers.append({'id': 'host' + str(number), 'name': 'VPS ' + str(number), 'host': '192.0.2.' + str(number)})

    def reopen(self):
        return AlertManager(self.root, lambda: self.servers, lambda: self.report, self.token_path,
                            transport=self.telegram, clock=lambda: self.now, security_release_fn=self.provider)

    def event(self, **changes):
        value = {'cve': RELEASE_CVE, 'sourcePackage': 'linux', 'releaseCodename': 'noble',
                 'fixedVersion': '6.8.0-149.149', 'vendorStatus': 'released', 'checkedAt': self.now,
                 'sourceUrl': RELEASE_SOURCE, 'servers': [{'id': s['id'], 'name': s['name'], 'host': s['host'],
                    'kernel': '6.8.0-147-generic', 'installedVersion': '6.8.0-147.147', 'state': 'published'} for s in self.servers]}
        value.update(changes)
        return value

    def releases(self):
        return [item for item in self.manager.state['queue'] if item['kind'] == 'security_release']

    def history(self):
        return [item for item in self.manager.status()['history'] if item['kind'] == 'security_release']

    def callback(self):
        self.provider_calls += 1
        if isinstance(self.events, Exception):
            raise self.events
        return copy.deepcopy(self.events)

    def use_provider(self):
        self.provider = self.callback
        self.manager.security_release_fn = self.provider

    def test_only_verified_released_fixed_cve_fresh_active_rows_can_reserve(self):
        self.critical()
        invalid = [self.event(vendorStatus='pending'), self.event(cve='CVE-2026-1'),
                   self.event(sourceUrl='https://example.org/CVE.json'), self.event(checkedAt=self.now - 10801),
                   self.event(checkedAt=self.now + 61), self.event(fixedVersion='$(id)'), self.event(servers=[])]
        for state in ('fixed', 'unknown', 'awaiting_release', 'available'):
            value = self.event()
            value['servers'][0]['state'] = state
            invalid.append(value)
        value = self.event()
        value['servers'][0]['host'] = '192.0.2.99'
        invalid.append(value)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(AlertError):
                self.manager.notify_security_release(value)
        self.assertFalse(self.manager.state['securityReleaseEvents'])
        self.assertFalse(self.releases())
        self.assertFalse(self.telegram.sent)

    def test_one_group_enqueues_without_direct_send_and_preserves_exact_critical_settings(self):
        self.critical()
        config = copy.deepcopy(self.manager.status()['config'])
        rules = copy.deepcopy(self.manager.state['rules'])
        result = self.manager.notify_security_release(self.event())
        self.assertTrue(result['accepted'])
        self.assertFalse(result['duplicate'])
        self.assertFalse(self.telegram.sent)
        self.assertEqual(self.manager.status()['config'], config)
        self.assertEqual(self.manager.state['rules'], rules)
        self.assertEqual(len(self.releases()), 1)
        self.manager._flush()
        self.assertEqual(len(self.telegram.sent), 1)
        message = self.telegram.sent[0]['text']
        self.assertIn('6.8.0-149.149', message)
        self.assertIn('APT', message)
        self.assertIn(RELEASE_PAGE, message)
        self.assertLessEqual(len(message.encode('utf-16-le')) // 2, 4096)
        for server in self.servers:
            self.assertIn(server['host'], message)
        self.assertEqual(self.manager.state['securityReleaseEvents'][result['eventId']]['status'], 'sent')

    def test_host_list_state_panel_ack_settings_and_restart_never_change_event_identity(self):
        self.critical()
        original = self.event()
        first = self.manager.notify_security_release(original)
        self.manager.configure({'cpuThreshold': 90, 'securityPacketThreshold': 2000})
        changed = self.event(servers=original['servers'][:1])
        changed['servers'][0]['state'] = 'reboot_required'
        changed['acknowledged'] = True  # panel ACK is a separate channel
        duplicate = self.manager.notify_security_release(changed)
        self.assertEqual(first['eventId'], duplicate['eventId'])
        self.assertEqual(len(self.releases()), 1)
        self.manager._flush()
        self.manager = self.reopen()
        duplicate = self.manager.notify_security_release(original)
        self.assertTrue(duplicate['duplicate'])
        self.assertFalse(duplicate['queued'])
        self.manager._flush()
        self.assertEqual(len(self.history()), 1)
        self.assertEqual(self.manager.path.stat().st_mode & 0o777, 0o600)

    def test_master_off_unpaired_and_group_chat_do_not_reserve(self):
        value = self.event()
        self.assertFalse(self.manager.notify_security_release(value)['accepted'])
        self.assertFalse(self.manager.state['securityReleaseEvents'])
        self.critical()
        self.manager.configure({'enabled': False})
        self.assertFalse(self.manager.notify_security_release(value)['accepted'])
        self.manager.configure({'enabled': True})
        for kind in ('group', 'supergroup'):
            self.manager.state['chat'].update(type=kind, id='-10')
            self.assertFalse(self.manager.notify_security_release(value)['accepted'])
        self.assertFalse(self.manager.state['securityReleaseEvents'])

    def test_rebinding_private_recipient_cancels_pending_without_replay(self):
        self.critical()
        first = self.manager.notify_security_release(self.event())
        code = self.manager.start_pairing()['pairing']['code']
        self.telegram.updates = [{'update_id': 20, 'message': {'date': self.now, 'text': '/start deck_' + code,
                                     'chat': {'id': 99, 'type': 'private', 'first_name': 'New owner'}}}]
        self.manager.tick()
        self.assertEqual(self.manager.state['securityReleaseEvents'][first['eventId']]['status'], 'cancelled')
        self.assertFalse(self.releases())
        self.assertTrue(self.manager.notify_security_release(self.event())['duplicate'])
        self.assertFalse(self.history())

    def test_recipient_guard_cancels_direct_private_to_group_change(self):
        self.critical()
        first = self.manager.notify_security_release(self.event())
        self.manager.state['chat'].update(type='group', id='-10')
        self.manager._flush()
        self.assertFalse(self.telegram.sent)
        self.assertEqual(self.manager.state['securityReleaseEvents'][first['eventId']]['status'], 'cancelled')

    def test_pending_repair_holds_old_recipient_until_cancelled_or_rebound(self):
        self.critical()
        self.manager.notify_security_release(self.event())
        self.manager.start_pairing()
        self.manager._flush()
        self.assertFalse(self.telegram.sent)
        self.assertEqual(len(self.releases()), 1)
        self.manager.cancel_pairing()
        self.manager._flush()
        self.assertEqual(len(self.history()), 1)
        self.assertEqual(self.history()[0]['status'], 'sent')

    def test_429_known_rejection_retries_same_durable_item_once(self):
        self.critical()
        self.manager.notify_security_release(self.event())
        identifier = self.releases()[0]['id']
        self.telegram.failure = DeliveryError(429, 60)
        self.manager._flush()
        self.assertEqual(self.releases()[0]['id'], identifier)
        self.manager = self.reopen()
        self.now += 60
        self.telegram.failure = None
        self.manager._flush()
        self.assertEqual(len(self.history()), 1)
        self.assertEqual(self.history()[0]['status'], 'sent')
        self.assertFalse(self.releases())

    def test_ambiguous_delivery_and_crash_sending_are_terminal_without_retry(self):
        self.critical()
        for index, code in enumerate((0, 500)):
            value = self.event(fixedVersion='6.8.0-' + str(149 + index) + '.149')
            result = self.manager.notify_security_release(value)
            self.telegram.failure = DeliveryError(code)
            self.manager._flush()
            self.assertEqual(self.manager.state['securityReleaseEvents'][result['eventId']]['status'], 'uncertain')
            self.assertFalse(self.releases())
        value = self.event(fixedVersion='6.8.0-151.151')
        result = self.manager.notify_security_release(value)
        self.releases()[0]['phase'] = 'sending'
        self.manager._save()
        self.manager = self.reopen()
        self.assertEqual(self.manager.state['securityReleaseEvents'][result['eventId']]['status'], 'uncertain')
        self.telegram.failure = None
        self.manager.notify_security_release(value)
        self.manager._flush()
        self.assertFalse(self.telegram.sent)
        self.assertEqual([h['status'] for h in self.history()], ['uncertain', 'uncertain', 'uncertain'])

    def test_403_and_expiration_are_terminal_and_expired_keys_never_reopen(self):
        self.critical()
        first = self.manager.notify_security_release(self.event())
        self.telegram.failure = DeliveryError(403)
        self.manager._flush()
        self.assertEqual(self.manager.state['securityReleaseEvents'][first['eventId']]['status'], 'failed')
        self.telegram.failure = None
        other = self.event(fixedVersion='6.8.0-150.150')
        second = self.manager.notify_security_release(other)
        self.manager.state['nextSendAt'] = self.now + 10000
        self.now += 3601
        self.manager._flush()
        self.assertEqual(self.manager.state['securityReleaseEvents'][second['eventId']]['status'], 'expired')
        other['checkedAt'] = self.now
        self.assertTrue(self.manager.notify_security_release(other)['duplicate'])
        self.assertFalse(self.releases())

    def test_callback_poll_is_outside_lock_single_cadence_and_no_cache_error_delivery(self):
        self.critical()
        self.use_provider()
        self.events = [self.event()]
        callback = self.callback
        acquired = threading.Event()

        def checked_callback():
            def probe_lock():
                with self.manager.lock:
                    acquired.set()
            worker = threading.Thread(target=probe_lock, daemon=True)
            worker.start()
            self.assertTrue(acquired.wait(1), 'release callback held manager lock')
            worker.join(1)
            return callback()

        self.manager.security_release_fn = checked_callback
        self.telegram.failure = DeliveryError(429, 60)
        self.manager.tick()
        self.assertEqual(self.provider_calls, 1)
        self.now += 10
        self.manager.tick()
        self.assertEqual(self.provider_calls, 1)
        self.events = RuntimeError('sensitive cache exception')
        self.now += 20
        self.manager.tick()
        self.assertEqual(self.provider_calls, 2)
        self.telegram.failure = None
        self.now += 30
        self.manager.tick()
        self.assertFalse(self.telegram.sent)
        self.assertTrue(self.releases())
        self.events = [self.event()]
        self.now += 30
        self.manager.tick()
        self.assertEqual(len(self.history()), 1)
        self.assertEqual(self.history()[0]['status'], 'sent')

    def test_empty_or_malformed_callback_holds_previously_queued_notice_until_expiration(self):
        self.critical()
        self.use_provider()
        self.events = [self.event()]
        self.telegram.failure = DeliveryError(429, 60)
        self.manager.tick()
        self.events = []
        self.telegram.failure = None
        self.now += 60
        self.manager.tick()
        self.assertFalse(self.telegram.sent)
        self.events = [self.event(), {'cve': 'bad'}]
        self.now += 30
        self.manager.tick()
        self.assertFalse(self.telegram.sent)
        self.now += 3600
        self.manager.tick()
        self.assertFalse(self.releases())
        self.assertEqual(next(iter(self.manager.state['securityReleaseEvents'].values()))['status'], 'expired')

    def test_critical_health_outage_has_priority_over_earlier_release(self):
        self.critical()
        self.manager.notify_security_release(self.event())
        self.manager.state['nextSendAt'] = self.now + 120
        self.step(services=self.services(awg='failed'), awg=[])
        self.step(services=self.services(awg='failed'), awg=[])
        self.assertEqual(len(self.telegram.sent), 1)
        self.assertIn('AWG недоступен', self.telegram.sent[0]['text'])
        self.assertEqual(len(self.releases()), 1)

    def test_reservation_write_failure_rolls_back_and_old_storage_loads_backwards(self):
        self.critical()
        with patch.object(self.manager, '_save', side_effect=OSError('disk full')):
            with self.assertRaises(AlertError):
                self.manager.notify_security_release(self.event())
        self.assertFalse(self.manager.state['securityReleaseEvents'])
        self.assertFalse(self.releases())
        value = json.loads(self.manager.path.read_text())
        value.pop('securityReleaseEvents')
        self.manager.path.write_text(json.dumps(value))
        self.manager = self.reopen()
        self.assertFalse(self.manager.storage_error)
        self.assertFalse(self.manager.state['securityReleaseEvents'])

    def test_ledger_capacity_does_not_evict_old_keys_to_resend(self):
        self.critical()
        self.manager.notify_security_release(self.event())
        record = copy.deepcopy(next(iter(self.manager.state['securityReleaseEvents'].values())))
        self.manager.state['securityReleaseEvents'] = {format(n, '064x'): dict(record, status='sent') for n in range(512)}
        self.manager.state['queue'] = []
        result = self.manager.notify_security_release(self.event(fixedVersion='6.8.0-999.999'))
        self.assertFalse(result['accepted'])
        self.assertEqual(len(self.manager.state['securityReleaseEvents']), 512)
