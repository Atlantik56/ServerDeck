import copy
import json
import unittest

from alerts import AlertError, AlertManager, DeliveryError
from test_alerts import Fixture, FakeTelegram


class SecurityFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.security_report = self.summary()

    def reopen(self):
        return AlertManager(self.root, lambda: self.servers, lambda: self.report,
                            self.token_path, transport=self.telegram, clock=lambda: self.now,
                            security_fn=lambda: self.security_report)

    def summary(self, count=0, bans=0, packets=None, event=None, ok=True):
        return {'generatedAt': self.now,
                'servers': [{'id': s['id'], 'name': s['name'], 'host': s['host'],
                             'checkedAt': self.now, 'ok': ok, 'failedPassword10m': count,
                             'blockedPacketsPerMinute': packets} for s in self.servers],
                'totals': {'newSharedBans10m': bans}, 'newestEventAt': event}

    def step_security(self, seconds=60, count=0, bans=0, packets=None, event=None, ok=True):
        self.now += seconds
        row = self.sample()
        for server in self.servers:
            self.report['servers'][server['id']] = {'latest': copy.deepcopy(row)}
        self.security_report = self.summary(count, bans, packets, event, ok)
        self.manager.tick()

    def notices(self):
        return [h for h in self.manager.status()['history'] if h['kind'] in ('security', 'security_digest') and h['status'] == 'sent']


class SecurityAlertTests(SecurityFixture):
    def test_unrelated_host_refresh_does_not_confirm_an_unchanged_high_sample(self):
        self.servers.append({'id': 'two', 'name': 'Second', 'host': '192.0.2.2'})
        self.security_report = self.summary()
        baseline = self.now
        self.connect()
        self.now = baseline + 60
        self.sample()
        self.security_report = self.summary()
        self.security_report['servers'][0]['failedPassword10m'] = 40
        self.security_report['servers'][1]['checkedAt'] = baseline
        self.manager.tick()
        self.assertEqual(self.manager.status()['security']['bad'], 1)
        self.now = baseline + 90
        self.sample()
        self.security_report['generatedAt'] = self.now
        self.security_report['servers'][1]['checkedAt'] = self.now
        self.manager.tick()
        self.assertFalse(self.notices())
        self.assertEqual(self.manager.status()['security']['bad'], 1)
        self.now = baseline + 120
        self.sample()
        self.security_report['generatedAt'] = self.now
        self.security_report['servers'][0]['checkedAt'] = self.now
        self.manager.tick()
        self.assertEqual(len(self.notices()), 1)

    def test_new_relevant_sample_is_seen_even_if_cluster_max_timestamp_is_unchanged(self):
        self.servers.append({'id': 'two', 'name': 'Second', 'host': '192.0.2.2'})
        self.security_report = self.summary()
        baseline = self.now
        self.connect()
        self.now = baseline + 80
        self.sample()
        self.security_report = self.summary()
        self.security_report['servers'][0].update(checkedAt=baseline + 60, failedPassword10m=40)
        self.manager.tick()
        self.assertFalse(self.notices())
        self.now = baseline + 90
        self.sample()
        self.security_report['generatedAt'] = self.now
        self.security_report['servers'][0]['checkedAt'] = baseline + 70
        self.manager.tick()
        self.assertEqual(len(self.notices()), 1)

    def test_separate_hosts_cannot_lend_each_other_single_high_confirmations(self):
        self.servers.append({'id': 'two', 'name': 'Second', 'host': '192.0.2.2'})
        self.security_report = self.summary()
        self.connect()
        self.now += 60
        self.sample()
        self.security_report = self.summary()
        self.security_report['servers'][0]['failedPassword10m'] = 40
        self.manager.tick()
        self.assertFalse(self.notices())
        self.assertEqual(self.manager.status()['security']['bad'], 1)
        self.now += 60
        self.sample()
        self.security_report = self.summary()
        self.security_report['servers'][1]['failedPassword10m'] = 40
        self.manager.tick()
        self.assertFalse(self.notices())
        self.assertEqual(self.manager.status()['security']['bad'], 1)

    def test_existing_high_counters_are_a_quiet_startup_baseline(self):
        self.security_report = self.summary(count=50, bans=50, event=self.now - 20)
        previous_event = self.security_report['newestEventAt']
        self.connect()
        for _ in range(3):
            self.step_security(count=50, bans=50, event=previous_event)
        self.assertFalse(self.notices())
        event = self.now + 60
        self.step_security(count=55, bans=51, event=event)
        self.assertFalse(self.notices())
        self.step_security(count=55, bans=51, event=event)
        self.assertEqual(len(self.notices()), 1)

    def test_one_global_notice_confirms_distinct_collector_samples_not_api_reads(self):
        self.servers.extend([{'id': 'two', 'name': 'Second', 'host': '192.0.2.2'},
                             {'id': 'three', 'name': 'Third', 'host': '192.0.2.3'}])
        self.security_report = self.summary()
        self.connect()
        event = self.now + 60
        self.step_security(count=40, event=event)
        self.assertFalse(self.notices())
        for _ in range(3):
            self.now += 10
            self.sample()
            self.security_report['generatedAt'] = self.now  # same underlying collector checkedAt
            self.manager.tick()
        self.assertFalse(self.notices())
        self.step_security(count=40, event=event)
        self.assertEqual(len(self.notices()), 1)
        self.assertIn('Second', self.telegram.sent[-1]['text'])
        self.assertIn('Third', self.telegram.sent[-1]['text'])
        self.assertNotIn('recovery', [h['kind'] for h in self.manager.status()['history']])

    def test_global_cooldown_survives_restart_and_new_activity(self):
        self.connect()
        self.step_security(count=40, event=self.now + 60)
        self.step_security(count=41, event=self.now + 60)
        self.assertEqual(len(self.notices()), 1)
        reserved = self.manager.status()['security']['lastNoticeAt']
        self.manager = self.reopen()
        self.step_security(count=60, bans=30, event=self.now + 60)
        self.step_security(count=61, bans=31, event=self.now + 60)
        self.assertEqual(len(self.notices()), 1)
        self.assertEqual(self.manager.status()['security']['lastNoticeAt'], reserved)
        self.step_security(seconds=3600, count=90, event=self.now + 3600)
        self.assertEqual(len(self.notices()), 1)
        self.step_security(count=91, event=self.now + 60)
        self.assertEqual(len(self.notices()), 2)

    def test_stale_or_missing_feed_cannot_confirm_or_clear_security_activity(self):
        self.connect()
        event = self.now + 60
        self.step_security(count=40, event=event)
        self.now += 181
        self.sample()
        self.manager.tick()
        self.assertFalse(self.notices())
        self.assertIn('Нет свежего', self.manager.status()['security']['lastError'])
        self.step_security(count=40, event=event)
        self.assertFalse(self.notices())
        self.step_security(count=41, event=self.now + 60)
        self.step_security(count=42, event=self.now + 60)
        self.assertEqual(len(self.notices()), 1)
        last_notice = self.manager.status()['security']['lastNoticeAt']
        self.step_security(seconds=3600, ok=False)
        self.assertEqual(len(self.notices()), 1)
        self.assertEqual(self.manager.status()['security']['lastNoticeAt'], last_notice)
        self.assertFalse(any(h['kind'] == 'recovery' for h in self.manager.status()['history']))

    def test_valid_packet_rate_can_alert_without_any_failed_password(self):
        self.connect()
        self.step_security(packets=1500)
        self.assertFalse(self.notices())
        self.step_security(packets=1500)
        self.assertEqual(len(self.notices()), 1)
        text = self.telegram.sent[-1]['text']
        self.assertIn('1500/мин', text)
        self.assertIn('0 неверных паролей', text)
        self.assertNotIn('DDoS', text)
        self.step_security(packets=None)
        self.step_security(packets=None)
        self.assertEqual(len(self.notices()), 1)

    def test_new_shared_bans_are_a_global_window_not_one_notice_per_ip(self):
        self.connect()
        self.step_security(bans=25)
        self.step_security(bans=26)
        self.assertEqual(len(self.notices()), 1)
        self.assertIn('Новых общих блокировок за 10 мин: 26', self.telegram.sent[-1]['text'])
        self.assertNotIn('IP:', self.telegram.sent[-1]['text'])

    def test_quiet_digest_only_follows_observed_activity_and_labels_peak_windows(self):
        self.connect()
        self.step_security(seconds=6 * 3600)
        self.assertFalse(self.notices())
        self.step_security(count=5, event=self.now + 60)
        self.assertEqual(len(self.notices()), 1)
        self.assertEqual(self.notices()[0]['kind'], 'security_digest')
        self.assertIn('Пиковые наблюдавшиеся окна', self.telegram.sent[-1]['text'])
        self.assertIn('за 10 мин', self.telegram.sent[-1]['text'])
        previous_event = self.security_report['newestEventAt']
        self.step_security(seconds=6 * 3600, count=0, event=previous_event)
        self.assertEqual(len(self.notices()), 1)

    def test_security_config_never_resets_health_or_awg_and_preserves_quiet_period(self):
        self.connect()
        for _ in range(3):
            self.step(cpu=95)
        before = copy.deepcopy(self.manager.state['rules'])
        self.manager.state['securityState']['lastNoticeAt'] = self.now
        self.manager.configure({'securityCooldownMinutes': 120, 'securityPacketThreshold': 2000})
        self.assertEqual(self.manager.state['rules'], before)
        self.assertEqual(self.manager.status()['security']['lastNoticeAt'], self.now)
        self.manager.configure({'security': False})
        self.manager.configure({'security': True})
        self.assertEqual(self.manager.state['rules'], before)
        self.assertEqual(self.manager.status()['security']['lastNoticeAt'], self.now)

    def test_security_settings_are_bounded_and_network_failure_is_not_sensitive(self):
        self.connect()
        for config in [{'securityCooldownMinutes': 59}, {'securityConsecutive': 1},
                       {'securityFailedThreshold': 9}, {'securityBanThreshold': 100001},
                       {'securityPacketThreshold': 99}, {'securityDigestHours': 5},
                       {'securityDigestHours': 169}, {'security': 1}]:
            with self.subTest(config=config), self.assertRaises(AlertError):
                self.manager.configure(config)
        self.manager.security_fn = lambda: (_ for _ in ()).throw(RuntimeError('sensitive ' + self.token))
        self.now += 60
        self.sample()
        self.manager.tick()
        self.assertNotIn(self.token, json.dumps(self.manager.status()))
        self.assertFalse(self.notices())

    def test_failed_delivery_does_not_create_another_logical_notice_during_cooldown(self):
        self.connect()
        self.telegram.failure = DeliveryError(429, 60)
        self.step_security(count=40, event=self.now + 60)
        self.step_security(count=41, event=self.now + 60)
        self.assertEqual(sum(q['kind'] == 'security' for q in self.manager.state['queue']), 1)
        reserved = self.manager.status()['security']['lastNoticeAt']
        self.manager = self.reopen()
        for _ in range(3):
            self.step_security(count=100, event=self.now + 60)
        self.assertEqual(sum(q['kind'] == 'security' for q in self.manager.state['queue']), 1)
        self.assertEqual(self.manager.status()['security']['lastNoticeAt'], reserved)

    def test_expired_notice_is_not_delivered_after_restart_with_missing_feed(self):
        self.connect()
        self.telegram.failure = DeliveryError(429, 60)
        self.step_security(count=40, event=self.now + 60)
        self.step_security(count=41, event=self.now + 60)
        pending = next(q for q in self.manager.state['queue'] if q['kind'] == 'security')
        self.assertEqual(pending['expiresAt'], self.now + 900)
        reserved = self.manager.status()['security']['lastNoticeAt']
        self.now += 7200
        self.sample()
        self.security_report = None
        self.telegram.failure = None
        self.manager = self.reopen()
        self.manager.tick()
        self.assertFalse(self.telegram.sent)
        self.assertFalse(self.manager.state['queue'])
        self.assertFalse(json.loads(self.manager.path.read_text())['queue'])
        self.assertEqual(self.manager.status()['security']['lastNoticeAt'], reserved)
        self.step_security(count=60, event=self.now + 60)
        self.assertFalse(self.notices())
        self.step_security(count=61, event=self.now + 60)
        self.assertEqual(len(self.notices()), 1)
        self.assertEqual(self.notices()[0]['time'], self.now)

    def assert_ambiguous_security_delivery_is_not_retried(self, code):
        self.connect()
        attempts_before = sum(method == 'sendMessage' for method, _ in self.telegram.calls)
        self.telegram.failure = DeliveryError(code)
        self.step_security(count=40)
        self.step_security(count=41)
        self.assertFalse(self.manager.state['queue'])
        history = [h for h in self.manager.status()['history'] if h['kind'] == 'security']
        self.assertEqual([h['status'] for h in history], ['uncertain'])
        reserved = self.manager.status()['security']['lastNoticeAt']
        self.manager = self.reopen()
        for _ in range(3):
            self.step_security(count=100)
            self.manager._flush()
        self.assertEqual(sum(method == 'sendMessage' for method, _ in self.telegram.calls), attempts_before + 1)
        self.assertEqual(self.manager.status()['security']['lastNoticeAt'], reserved)
        self.assertIn('автоматического повтора нет', self.manager.status()['lastError'])

    def test_security_network_timeout_is_uncertain_and_never_automatically_retried(self):
        self.assert_ambiguous_security_delivery_is_not_retried(0)

    def test_security_server_error_is_uncertain_and_never_automatically_retried(self):
        self.assert_ambiguous_security_delivery_is_not_retried(500)

    def test_health_network_failure_keeps_existing_retry_policy(self):
        self.connect()
        self.telegram.failure = DeliveryError(0)
        self.manager._queue('alarm', 'Health alert', 'Health', 'one')
        self.manager._flush()
        self.assertEqual(len(self.manager.state['queue']), 1)
        self.assertEqual(self.manager.state['queue'][0]['phase'], 'pending')
        self.assertEqual(self.manager.state['queue'][0]['due'], self.now + 15)
        self.telegram.failure = None
        self.now += 15
        self.manager._flush()
        self.assertFalse(self.manager.state['queue'])
        self.assertEqual(self.telegram.sent[-1]['text'], 'Health alert')


class FakeMenu:
    def __init__(self):
        self.calls = []

    def handle(self, text=None, callback_data=None):
        self.calls.append((text, callback_data))
        return {'text': 'Сводка серверов', 'reply_markup': {'inline_keyboard': [[{'text': 'Меню', 'callback_data': 'deck:menu'}]]}}


class MenuTelegram(FakeTelegram):
    def __init__(self):
        super().__init__()
        self.edits = []
        self.answers = []
        self.edit_failure = None

    def __call__(self, method, data):
        if method in ('answerCallbackQuery', 'editMessageText', 'setMyCommands', 'setChatMenuButton'):
            self.calls.append((method, copy.deepcopy(data)))
            if method == 'answerCallbackQuery':
                self.answers.append(copy.deepcopy(data))
            elif method == 'editMessageText':
                if self.edit_failure:
                    raise self.edit_failure
                self.edits.append(copy.deepcopy(data))
            return True
        return super().__call__(method, data)


class MenuIntegrationTests(Fixture):
    def setUp(self):
        self.menu = FakeMenu()
        super().setUp()
        self.telegram = MenuTelegram()
        self.manager = self.reopen()

    def reopen(self):
        return AlertManager(self.root, lambda: self.servers, lambda: self.report,
                            self.token_path, transport=self.telegram, clock=lambda: self.now,
                            bot_menu=self.menu)

    def message(self, identifier, text='/menu', chat=42, sender=42, date=None):
        return {'update_id': identifier, 'message': {'message_id': identifier + 100,
                'date': self.now if date is None else date, 'text': text,
                'chat': {'id': chat, 'type': 'private'}, 'from': {'id': sender, 'is_bot': False}}}

    def callback(self, identifier, data='deck:status', chat=42, sender=42, author=123456):
        return {'update_id': identifier, 'callback_query': {'id': 'callback-' + str(identifier),
                'data': data, 'from': {'id': sender, 'is_bot': False},
                'message': {'message_id': 900, 'date': self.now - 100000,
                            'chat': {'id': chat, 'type': 'private'},
                            'from': {'id': author, 'is_bot': True}}}}

    def poll(self, updates, seconds=2):
        self.now += seconds
        self.sample()
        self.telegram.updates = updates
        self.manager.tick()

    def test_paired_menu_uses_single_consumer_and_durable_update_deduplication(self):
        self.connect()
        before = sum(method == 'getUpdates' for method, _ in self.telegram.calls)
        self.poll([self.message(10, '/start')])
        self.assertEqual(sum(method == 'getUpdates' for method, _ in self.telegram.calls), before + 1)
        self.assertEqual(len(self.telegram.sent), 1)
        poll = next(data for method, data in reversed(self.telegram.calls) if method == 'getUpdates')
        self.assertEqual(set(poll['allowed_updates']), {'message', 'callback_query'})
        self.assertEqual(poll['timeout'], 1)
        self.manager = self.reopen()
        self.poll([self.message(10, '/start')])
        self.assertEqual(len(self.telegram.sent), 1)

    def test_strangers_and_spoofed_private_senders_never_reach_renderer_or_get_replies(self):
        self.connect()
        self.poll([self.message(10, chat=99, sender=99), self.message(11, sender=99),
                   self.callback(12, chat=99, sender=99), self.callback(13, sender=99),
                   self.callback(14, author=999)])
        self.assertFalse(self.menu.calls)
        self.assertFalse(self.telegram.sent)
        self.assertFalse(self.telegram.answers)
        self.assertFalse(self.telegram.edits)
        self.assertEqual(self.manager.state['offset'], 15)

    def test_group_alert_recipient_does_not_grant_members_protected_menu_access(self):
        self.connect(group=True)
        self.assertFalse(self.manager.status()['menu']['enabled'])
        with self.assertRaises(AlertError):
            self.manager.publish_menu()
        updates = [self.message(10, chat=-10, sender=42), self.callback(11, chat=-10, sender=42)]
        updates[0]['message']['chat']['type'] = 'group'
        updates[1]['callback_query']['message']['chat']['type'] = 'group'
        for update in updates:
            self.manager._handle_menu_update(update)
        self.assertFalse(self.menu.calls)
        self.assertFalse(self.telegram.sent)
        self.assertFalse(self.telegram.answers)

    def test_poll_conflict_during_concurrent_new_pairing_keeps_pairing_intact(self):
        self.connect()
        original = self.manager.transport

        def concurrent_pairing(method, data):
            if method == 'getUpdates':
                self.manager.start_pairing()
                raise DeliveryError(409)
            return original(method, data)

        self.manager.transport = concurrent_pairing
        self.manager._poll_pairing()
        self.assertIsNotNone(self.manager.status()['pairing'])
        self.assertFalse(self.manager.status()['pairing'].get('blocked', False))
        self.assertIn('другом получателе', self.manager.status()['menu']['lastError'])

    def test_old_commands_are_ignored_but_old_message_buttons_still_work(self):
        self.connect()
        self.poll([self.message(10, date=self.now - 600), self.message(11, text='ordinary text'),
                   self.message(12, text='/reboot'), self.callback(13)])
        self.assertEqual(len(self.menu.calls), 1)
        self.assertEqual(len(self.telegram.edits), 1)
        self.assertEqual(self.telegram.edits[0]['message_id'], 900)
        self.assertEqual(len(self.telegram.answers), 1)
        self.assertFalse(self.telegram.sent)

    def test_interaction_rate_cap_does_not_replace_queued_health_alerts(self):
        self.connect()
        identifier = self.manager._queue('alarm', 'Health alert', 'Health', 'one')
        self.poll([self.message(10), self.message(11, '/status'), self.message(12, '/servers'),
                   self.message(13, '/services'), self.message(14, '/security')])
        self.assertEqual(len(self.menu.calls), 3)
        self.assertLessEqual(sum(q['kind'] == 'menu' for q in self.manager.state['queue']), 1)
        self.assertTrue(any(q['id'] == identifier for q in self.manager.state['queue']))
        self.poll([])
        self.poll([])
        self.assertTrue(any(message['text'] == 'Health alert' for message in self.telegram.sent))

    def test_callback_edit_failure_does_not_fall_back_to_spamming_new_messages(self):
        self.connect()
        self.telegram.edit_failure = DeliveryError(400)
        self.poll([self.callback(10)])
        self.assertEqual(len(self.telegram.answers), 1)
        self.assertFalse(self.telegram.sent)
        self.assertFalse(self.manager.state['queue'])
        attempts = sum(method == 'editMessageText' for method, _ in self.telegram.calls)
        self.poll([])
        self.assertEqual(sum(method == 'editMessageText' for method, _ in self.telegram.calls), attempts)

    def test_publish_commands_is_explicit_private_scoped_and_idempotent_without_messages(self):
        self.connect()
        self.poll([])
        self.assertFalse(any(method in ('setMyCommands', 'setChatMenuButton') for method, _ in self.telegram.calls))
        self.assertFalse(self.telegram.sent)
        self.manager.publish_menu()
        calls = [(method, data) for method, data in self.telegram.calls if method in ('setMyCommands', 'setChatMenuButton')]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1]['scope'], {'type': 'chat', 'chat_id': 42})
        self.assertEqual(calls[1][1], {'chat_id': 42, 'menu_button': {'type': 'commands'}})
        self.assertEqual([c['command'] for c in calls[0][1]['commands']], ['menu', 'status', 'servers', 'services', 'security'])
        self.assertTrue(self.manager.status()['botMenuEnabled'])
        self.manager.publish_menu()
        self.assertEqual(sum(method in ('setMyCommands', 'setChatMenuButton') for method, _ in self.telegram.calls), 2)
        self.assertFalse(self.telegram.sent)

    def test_menu_requests_do_not_consume_security_cooldown(self):
        self.connect()
        sent_at = self.manager.status()['lastSentAt']
        history = copy.deepcopy(self.manager.status()['history'])
        self.manager.state['securityState']['lastNoticeAt'] = self.now - 100
        self.poll([self.message(10, '/security')])
        self.assertEqual(self.manager.state['securityState']['lastNoticeAt'], self.now - 102)
        self.assertEqual(self.manager.status()['history'], history)
        self.assertEqual(self.manager.status()['lastSentAt'], sent_at)


if __name__ == '__main__':
    unittest.main()
