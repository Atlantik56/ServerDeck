"""Authorization and replay gates around the optional Telegram action handler."""
import copy
import json
import threading
import unittest

from alerts import AlertError, AlertManager
from test_alerts import Fixture
from test_security_alerts import FakeMenu, MenuTelegram


class FakeActions:
    def __init__(self):
        self.calls = []
        self.invalidations = 0
        self.failure = None
        self.on_handle = None

    def invalidate_pending(self):
        self.invalidations += 1

    def handle(self, text=None, callback_data=None, *, chat_id, user_id, message_id=None):
        self.calls.append({'text': text, 'callback_data': callback_data, 'chat_id': chat_id,
                           'user_id': user_id, 'message_id': message_id})
        if self.on_handle:
            self.on_handle()
        if self.failure:
            raise self.failure
        return {'text': 'План управления', 'reply_markup': {'inline_keyboard': []},
                'disable_web_page_preview': True}


class ActionTransportTests(Fixture):
    def setUp(self):
        self.actions = FakeActions()
        self.menu = FakeMenu()
        super().setUp()
        self.telegram = MenuTelegram()
        self.manager = self.reopen()

    def reopen(self):
        return AlertManager(self.root, lambda: self.servers, lambda: self.report,
                            self.token_path, transport=self.telegram, clock=lambda: self.now,
                            bot_menu=self.menu, bot_actions=self.actions)

    def message(self, identifier, text='ПЕРЕЗАПУСТИТЬ 123456', chat=42, sender=42, date=None):
        return {'update_id': identifier, 'message': {'message_id': identifier + 100,
                'date': self.now if date is None else date, 'text': text,
                'chat': {'id': chat, 'type': 'private'}, 'from': {'id': sender, 'is_bot': False}}}

    def callback(self, identifier, data='deck:manage:servers', chat=42, sender=42, author=123456):
        return {'update_id': identifier, 'callback_query': {'id': 'action-' + str(identifier),
                'data': data, 'from': {'id': sender, 'is_bot': False},
                'message': {'message_id': 900, 'date': self.now - 100000,
                            'chat': {'id': chat, 'type': 'private'},
                            'from': {'id': author, 'is_bot': True}}}}

    def poll(self, updates, seconds=2):
        self.now += seconds
        self.sample()
        self.telegram.updates = updates
        self.manager.tick()

    def test_control_callbacks_reach_only_action_handler_with_verified_identity(self):
        self.connect()
        self.poll([self.callback(10), self.callback(11, 'deck:act:plan:opaque')])
        self.assertEqual([call['callback_data'] for call in self.actions.calls],
                         ['deck:manage:servers', 'deck:act:plan:opaque'])
        self.assertTrue(all(call['chat_id'] == '42' and call['user_id'] == '42' and
                            call['message_id'] == 900 and call['text'] is None for call in self.actions.calls))
        self.assertFalse(self.menu.calls)
        self.assertTrue(self.telegram.answers)
        self.assertTrue(self.telegram.edits)
        self.assertFalse(self.telegram.sent)

    def test_exact_fresh_typed_confirmation_reaches_action_handler(self):
        self.connect()
        self.poll([self.message(10)])
        self.assertEqual(self.actions.calls, [{'text': 'ПЕРЕЗАПУСТИТЬ 123456', 'callback_data': None,
                                               'chat_id': '42', 'user_id': '42', 'message_id': 110}])
        self.assertFalse(self.menu.calls)
        self.assertEqual(self.telegram.sent[-1]['text'], 'План управления')

    def test_unknown_chats_forged_senders_bot_senders_and_authors_never_reach_actions(self):
        self.connect()
        bot_sender = self.callback(15)
        bot_sender['callback_query']['from']['is_bot'] = True
        self.poll([self.callback(10, chat=99, sender=99), self.callback(11, sender=99),
                   self.callback(12, author=999), self.message(13, chat=99, sender=99),
                   self.message(14, sender=99), bot_sender])
        self.assertFalse(self.actions.calls)
        self.assertFalse(self.telegram.sent)
        self.assertFalse(self.telegram.edits)
        self.assertFalse(self.telegram.answers)
        self.assertEqual(self.manager.state['offset'], 16)

    def test_group_recipient_does_not_allow_actions_from_any_member(self):
        self.connect(group=True)
        group_message = self.message(10, chat=-10)
        group_callback = self.callback(11, chat=-10)
        group_message['message']['chat']['type'] = 'group'
        group_callback['callback_query']['message']['chat']['type'] = 'group'
        self.manager._handle_menu_update(group_message)
        self.manager._handle_menu_update(group_callback)
        self.assertFalse(self.actions.calls)
        self.assertFalse(self.telegram.sent)
        self.assertFalse(self.telegram.answers)

    def test_stale_or_future_confirmation_is_ignored_but_old_bot_buttons_are_allowed(self):
        self.connect()
        self.poll([self.message(10, date=self.now - 600), self.message(11, date=self.now + 60),
                   self.callback(12)])
        self.assertEqual(len(self.actions.calls), 1)
        self.assertEqual(self.actions.calls[0]['callback_data'], 'deck:manage:servers')
        self.assertIsNone(self.actions.calls[0]['text'])

    def test_typed_confirmation_requires_exact_ascii_format(self):
        self.connect()
        variants = ['перезапустить 123456', 'ПЕРЕЗАПУСТИТЬ  123456', ' ПЕРЕЗАПУСТИТЬ 123456',
                    'ПЕРЕЗАПУСТИТЬ 123456\n', 'ПЕРЕЗАПУСТИТЬ １２３４５６', 'ПЕРЕЗАПУСТИТЬ 12345',
                    'ПЕРЕЗАПУСТИТЬ 1234567', 'ПЕРЕЗАПУСТИТЬ 123456 extra']
        self.poll([self.message(i + 10, text=text) for i, text in enumerate(variants)])
        self.assertFalse(self.actions.calls)
        self.assertFalse(self.telegram.sent)

    def test_action_handler_requires_valid_message_identifier(self):
        self.connect()
        updates = [self.message(10), self.message(11), self.callback(12)]
        del updates[0]['message']['message_id']
        updates[1]['message']['message_id'] = True
        updates[2]['callback_query']['message']['message_id'] = -1
        self.poll(updates)
        self.assertFalse(self.actions.calls)
        self.assertFalse(self.telegram.sent)
        self.assertFalse(self.telegram.answers)

    def test_shared_rate_limit_is_applied_before_action_dispatch(self):
        self.connect()
        self.poll([self.message(10, text='/status'), self.callback(11), self.callback(12),
                   self.callback(13), self.message(14)])
        self.assertEqual(len(self.menu.calls), 1)
        self.assertEqual(len(self.actions.calls), 2)
        self.assertTrue(any(answer.get('text') == 'Подождите несколько секунд.' for answer in self.telegram.answers))

    def test_update_offset_is_persisted_before_action_and_prevents_restart_replay(self):
        self.connect()
        observed = []
        self.actions.on_handle = lambda: observed.append(json.loads(self.manager.path.read_text())['offset'])
        self.poll([self.message(10)])
        self.assertEqual(observed, [11])
        self.manager = self.reopen()
        self.poll([self.message(10)])
        self.assertEqual(len(self.actions.calls), 1)
        self.assertEqual(self.manager.state['offset'], 11)

    def test_other_namespaces_and_commands_still_use_pure_menu(self):
        self.connect()
        self.poll([self.message(10, text='/services'), self.callback(11, 'deck:status'),
                   self.callback(12, 'deck:manage')])
        self.assertFalse(self.actions.calls)
        self.assertEqual(len(self.menu.calls), 3)

    def test_oversize_control_callback_is_not_routed_as_an_action(self):
        self.connect()
        self.poll([self.callback(10, 'deck:act:' + 'x' * 64)])
        self.assertFalse(self.actions.calls)
        self.assertEqual(self.menu.calls, [(None, 'invalid')])

    def test_action_exception_is_sanitized_without_retrying_the_update(self):
        self.connect()
        self.actions.failure = RuntimeError('secret-value-that-must-not-escape')
        self.poll([self.message(10)])
        self.assertEqual(len(self.actions.calls), 1)
        self.assertIn('Не удалось обработать запрос', self.telegram.sent[-1]['text'])
        self.assertNotIn('secret-value', json.dumps(self.telegram.sent) + json.dumps(self.manager.status()))
        self.poll([self.message(10)])
        self.assertEqual(len(self.actions.calls), 1)

    def test_pairing_resets_pending_actions_and_blocks_actions_until_cancelled(self):
        self.connect()
        invalidations = self.actions.invalidations
        self.manager.start_pairing()
        self.assertEqual(self.actions.invalidations, invalidations + 1)
        self.poll([self.message(10)])
        self.assertFalse(self.actions.calls)
        self.manager.cancel_pairing()
        self.assertEqual(self.actions.invalidations, invalidations + 2)
        self.poll([self.message(11)])
        self.assertEqual(len(self.actions.calls), 1)

    def test_confirmation_invalidation_failure_keeps_existing_pairing_state(self):
        self.connect()
        previous = copy.deepcopy(self.manager.state['chat'])
        self.actions.invalidate_pending = lambda: (_ for _ in ()).throw(RuntimeError('sensitive failure'))
        with self.assertRaises(AlertError) as error:
            self.manager.start_pairing()
        self.assertNotIn('sensitive', str(error.exception))
        self.assertEqual(self.manager.state['chat'], previous)
        self.assertIsNone(self.manager.state['pairing'])

    def test_pending_pairing_dispatch_can_be_cancelled_concurrently_without_lock_inversion(self):
        self.connect()
        self.manager.start_pairing()
        original = self.manager._handle_menu_update
        completed = threading.Event()
        workers = []

        def dispatch(update):
            def cancel():
                self.manager.cancel_pairing()
                completed.set()

            worker = threading.Thread(target=cancel, daemon=True)
            workers.append(worker)
            worker.start()
            self.assertTrue(completed.wait(2), 'Pairing cancellation blocked behind menu dispatch state lock')
            original(update)

        self.manager._handle_menu_update = dispatch
        try:
            self.poll([self.callback(10)])
        finally:
            for worker in workers:
                worker.join(2)
        self.assertTrue(completed.is_set())
        self.assertIsNone(self.manager.state['pairing'])

    def test_revoked_pairing_code_cannot_bind_after_the_update_was_read(self):
        self.connect()
        previous = copy.deepcopy(self.manager.state['chat'])
        status = self.manager.start_pairing()
        code = status['pairing']['code']
        original_lock = self.manager.action_lock

        class CancelBeforeBind:
            def __enter__(inner):
                self.manager.action_lock = original_lock
                self.manager.cancel_pairing()
                original_lock.acquire()

            def __exit__(inner, *args):
                original_lock.release()

        self.manager.action_lock = CancelBeforeBind()
        update = self.message(10, text='/start deck_' + code, chat=99, sender=99)
        self.poll([update])
        self.assertEqual(self.manager.state['chat'], previous)
        self.assertIsNone(self.manager.state['pairing'])


if __name__ == '__main__':
    unittest.main()
