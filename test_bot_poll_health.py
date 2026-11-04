"""An empty successful Telegram poll must retire old transport errors."""
from unittest.mock import patch
from alerts import DeliveryError
from test_alerts import Fixture
from test_security_alerts import FakeMenu


class PollHealthTests(Fixture):
    def setUp(self):
        super().setUp()
        self.connect()
        self.manager.bot_menu = FakeMenu()
        self.old_poll = self.now - 30
        self.manager.state['menuState'].update(lastError='old poll error',
                                               nextPollAt=self.now - 1,
                                               lastPollAt=self.old_poll)
        self.manager._save()

    def test_empty_success_clears_error_and_backoff_durably(self):
        self.telegram.updates = []
        self.manager._poll_pairing()
        menu = self.manager.state['menuState']
        self.assertEqual(menu['lastError'], '')
        self.assertEqual(menu['nextPollAt'], 0)
        self.assertEqual(menu['lastPollAt'], self.now)
        self.assertEqual(self.reopen().state['menuState'], menu)
        self.assertFalse(self.telegram.sent)

    def test_malformed_response_does_not_claim_success(self):
        with patch.object(self.manager, 'transport', return_value={'invalid': 'response'}):
            self.manager._poll_pairing()
        self.assertEqual(self.manager.state['menuState']['lastError'], 'old poll error')
        self.assertEqual(self.manager.state['menuState']['lastPollAt'], self.old_poll)

    def test_transport_failure_retains_real_error_and_backoff(self):
        with patch.object(self.manager, 'transport', side_effect=DeliveryError(500)):
            self.manager._poll_pairing()
        self.assertTrue(self.manager.state['menuState']['lastError'])
        self.assertGreater(self.manager.state['menuState']['nextPollAt'], self.now)
        self.assertEqual(self.manager.state['menuState']['lastPollAt'], self.old_poll)
