"""Real HTTP route checks; the update watcher and all external actions are mocked."""
import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch

import public_access
import server


class SecurityUpdateRoutes(unittest.TestCase):
    NOTICE = 'a' * 64
    UNAVAILABLE = 'Проверка обновлений безопасности временно недоступна'

    def setUp(self):
        self.watch = Mock(spec=['snapshot', 'request_check', 'acknowledge'])
        self.watch.snapshot.return_value = {'running': False, 'notices': [], 'checkedAt': 123}
        self.watch.request_check.return_value = {'accepted': True, 'running': True}
        self.watch.acknowledge.return_value = {'acknowledged': self.NOTICE}
        self.telegram_config = {'enabled': True, 'criticalOnly': True, 'security': False,
                                'services': True, 'chatId': 'private-test-chat'}
        self.alerts = Mock()
        self.alerts.status.return_value = {'config': copy.deepcopy(self.telegram_config)}

        self.patch(public_access, 'ORIGIN', 'https://deck.example')
        self.patch(public_access, 'HOST', 'deck.example')
        self.patch(public_access, 'GATEWAY', 'gateway')
        self.factory = self.patch(server, 'security_updates_watch', Mock(return_value=self.watch), create=True)
        self.alerts_factory = self.patch(server, 'alerts_manager', Mock(return_value=self.alerts))
        self.ssh = self.patch(server, 'ssh', Mock(side_effect=AssertionError('A route must not call SSH')))
        self.control = self.patch(server, 'control', Mock(side_effect=AssertionError('A route must not mutate control jobs')))
        self.registry = self.patch(server, 'servers', Mock(return_value=[]))
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_httpd)

    def patch(self, target, name, value, **kwargs):
        patcher = patch.object(target, name, value, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def close_httpd(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def request(self, path='/api/security-updates', method='GET', data=None, extra=None):
        headers = {'Host': 'deck.example', 'Origin': 'https://deck.example',
                   'X-Deck-Gateway': 'gateway', 'X-Deck-Token': server.TOKEN,
                   'Content-Type': 'application/json'}
        for key, value in (extra or {}).items():
            if value is None:
                headers.pop(key, None)
            else:
                headers[key] = value
        connection = http.client.HTTPConnection('127.0.0.1', self.httpd.server_port, timeout=5)
        try:
            connection.request(method, path, json.dumps(data) if method == 'POST' else None, headers)
            response = connection.getresponse()
            body = json.loads(response.read())
            return response.status, body, dict(response.getheaders())
        finally:
            connection.close()

    def assert_no_external_effects(self):
        self.ssh.assert_not_called()
        self.control.assert_not_called()
        self.alerts_factory.assert_not_called()
        self.alerts.configure.assert_not_called()
        self.alerts.test.assert_not_called()
        self.alerts.start_pairing.assert_not_called()
        self.alerts.publish_menu.assert_not_called()
        self.assertEqual(self.alerts.status.return_value['config'], self.telegram_config)

    def test_get_requires_host_gateway_and_session_token(self):
        for extra in ({'Host': 'other.example'}, {'X-Deck-Gateway': None},
                      {'X-Deck-Gateway': 'wrong'}, {'X-Deck-Token': None},
                      {'X-Deck-Token': 'wrong'}):
            with self.subTest(headers=extra):
                self.assertEqual(self.request(extra=extra)[0], 403)
        self.factory.assert_not_called()
        self.watch.snapshot.assert_not_called()
        self.assert_no_external_effects()

    def test_get_reads_cached_snapshot_without_starting_a_check(self):
        for _ in range(2):
            code, body, headers = self.request()
            self.assertEqual(code, 200)
            self.assertEqual(body, self.watch.snapshot.return_value)
            self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(self.watch.snapshot.call_count, 2)
        self.watch.request_check.assert_not_called()
        self.watch.acknowledge.assert_not_called()
        self.registry.assert_not_called()
        self.assert_no_external_effects()

    def test_post_requires_host_gateway_token_and_same_origin(self):
        for path, data in (('/api/security-updates/check', {}),
                           ('/api/security-updates/ack', {'notice': self.NOTICE})):
            for extra in ({'Host': 'other.example'}, {'X-Deck-Gateway': None},
                          {'X-Deck-Token': None}, {'X-Deck-Token': 'wrong'},
                          {'Origin': None}, {'Origin': 'https://other.example'},
                          {'Origin': 'http://deck.example'}):
                with self.subTest(path=path, headers=extra):
                    self.assertEqual(self.request(path, 'POST', data, extra)[0], 403)
        self.factory.assert_not_called()
        self.watch.request_check.assert_not_called()
        self.watch.acknowledge.assert_not_called()
        self.assert_no_external_effects()

    def test_check_returns_202_and_starts_only_the_watch_check(self):
        code, body, headers = self.request('/api/security-updates/check', 'POST', {})
        self.assertEqual(code, 202)
        self.assertEqual(body, self.watch.request_check.return_value)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.watch.request_check.assert_called_once_with()
        self.watch.snapshot.assert_not_called()
        self.watch.acknowledge.assert_not_called()
        self.assert_no_external_effects()

    def test_check_rejects_fields_for_configuration_or_execution(self):
        for body in ({'force': True}, {'action': 'reboot'}, {'criticalOnly': False},
                     {'security': True}, {'notice': self.NOTICE}, {'servers': []}):
            with self.subTest(body=body):
                self.assertEqual(self.request('/api/security-updates/check', 'POST', body)[0], 400)
        self.watch.request_check.assert_not_called()
        self.assert_no_external_effects()

    def test_write_requires_a_json_object_before_any_manager_call(self):
        for path in ('/api/security-updates/check', '/api/security-updates/ack'):
            for body in (None, [], ['notice'], 'notice', True, 123):
                with self.subTest(path=path, body=body):
                    self.assertEqual(self.request(path, 'POST', body)[0], 400)
        self.factory.assert_not_called()
        self.watch.request_check.assert_not_called()
        self.watch.acknowledge.assert_not_called()
        self.assert_no_external_effects()

    def test_acknowledgement_passes_only_the_exact_notice(self):
        code, body, _ = self.request('/api/security-updates/ack', 'POST', {'notice': self.NOTICE})
        self.assertEqual(code, 200)
        self.assertEqual(body, self.watch.acknowledge.return_value)
        self.watch.acknowledge.assert_called_once_with(self.NOTICE)
        self.watch.request_check.assert_not_called()
        self.assert_no_external_effects()

    def test_acknowledgement_rejects_missing_notice_extra_fields_and_nonstring(self):
        for body in ({}, {'notice': self.NOTICE, 'criticalOnly': False},
                     {'notice': self.NOTICE, 'security': True}, {'notice': None},
                     {'notice': 123}, {'notice': ['a']}, {'notice': {'id': self.NOTICE}}):
            with self.subTest(body=body):
                self.assertEqual(self.request('/api/security-updates/ack', 'POST', body)[0], 400)
        self.watch.acknowledge.assert_not_called()
        self.assert_no_external_effects()

    def test_watch_validation_error_is_a_public_400(self):
        self.watch.acknowledge.side_effect = ValueError('Неверное уведомление')
        code, body, _ = self.request('/api/security-updates/ack', 'POST', {'notice': 'bad-id'})
        self.assertEqual(code, 400)
        self.assertEqual(body, {'error': 'Неверное уведомление'})
        self.watch.acknowledge.assert_called_once_with('bad-id')
        self.assert_no_external_effects()

    def test_unexpected_write_errors_are_sanitized_503(self):
        secret = 'private-token-and-internal-path'
        for method, path, data in (('request_check', '/api/security-updates/check', {}),
                                   ('acknowledge', '/api/security-updates/ack', {'notice': self.NOTICE})):
            with self.subTest(path=path):
                getattr(self.watch, method).side_effect = RuntimeError(secret)
                code, body, _ = self.request(path, 'POST', data)
                self.assertEqual(code, 503)
                self.assertEqual(body, {'error': self.UNAVAILABLE})
                self.assertNotIn(secret, json.dumps(body))
        self.assert_no_external_effects()

    def test_failed_snapshot_is_not_a_healthy_empty_response_or_a_leak(self):
        for error in (ValueError('private-database-path'), RuntimeError('private-token')):
            with self.subTest(error=type(error).__name__):
                self.watch.snapshot.side_effect = error
                code, body, _ = self.request()
                self.assertEqual(code, 503)
                self.assertEqual(body, {'error': self.UNAVAILABLE})
                self.assertNotIn(str(error), json.dumps(body))
        self.watch.request_check.assert_not_called()
        self.assert_no_external_effects()

    def test_unknown_paths_and_wrong_methods_cannot_start_work(self):
        for method, path, data in (('GET', '/api/security-updates/unknown', None),
                                   ('GET', '/api/security-updates/check', None),
                                   ('GET', '/api/security-updates/ack', None),
                                   ('POST', '/api/security-updates/unknown', {}),
                                   ('POST', '/api/security-updates', {})):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(path, method, data)[0], 404)
        self.watch.snapshot.assert_not_called()
        self.watch.request_check.assert_not_called()
        self.watch.acknowledge.assert_not_called()
        self.assert_no_external_effects()


if __name__ == '__main__':
    unittest.main()
