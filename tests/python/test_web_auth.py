import http.client
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import web_auth as auth

HASH = '$2b$12$' + 'A' * 53
OTHER_HASH = '$2b$12$' + 'B' * 53
PASSWORD = 'only-a-test-password'
GATEWAY = 'test-gateway-' + 'x' * 48
ORIGIN = 'https://deck.example'


class VerifierTests(unittest.TestCase):
    def test_subprocess_is_bounded_and_secrets_only_use_stdin(self):
        for output, expected in [(b'true', True), (b'false', False)]:
            process = subprocess.CompletedProcess([], 0, output)
            with patch('web_auth.subprocess.run', return_value=process) as run:
                self.assertEqual(auth.verify_password(PASSWORD, HASH), expected)
            args = run.call_args.args[0]
            self.assertNotIn(PASSWORD, str(args))
            self.assertNotIn(HASH, str(args))
            self.assertEqual(args[1:3], ['-I', '-c'])
            options = run.call_args.kwargs
            self.assertEqual(json.loads(options['input']), {'password': PASSWORD, 'hash': HASH})
            self.assertEqual(options['timeout'], 8)
            self.assertEqual(options['stderr'], subprocess.DEVNULL)

    def test_verifier_timeout_or_bad_output_is_generic_and_not_retried(self):
        for process in [subprocess.CompletedProcess([], 1, PASSWORD.encode()),
                        subprocess.CompletedProcess([], 0, b'unexpected')]:
            with patch('web_auth.subprocess.run', return_value=process) as run:
                with self.assertRaises(auth.AuthError) as error:
                    auth.verify_password(PASSWORD, HASH)
                self.assertNotIn(PASSWORD, str(error.exception))
                self.assertEqual(run.call_count, 1)
        with patch('web_auth.subprocess.run', side_effect=subprocess.TimeoutExpired(['python'], 8, stderr=PASSWORD.encode())) as run:
            with self.assertRaises(auth.AuthError) as error:
                auth.verify_password(PASSWORD, HASH)
            self.assertNotIn(PASSWORD, str(error.exception))
            self.assertEqual(run.call_count, 1)


class AuthFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.accounts = self.root / 'accounts'
        self.accounts.write_text('admin ' + HASH + '\n')
        self.now = 1000000.0
        self.verifier = Mock(side_effect=lambda password, hashed: password == PASSWORD and hashed == HASH)
        self.store = auth.AuthStore(self.accounts, self.root / 'state', clock=lambda: self.now, verifier=self.verifier)

    def tearDown(self):
        self.temp.cleanup()


class StoreTests(AuthFixture):
    def test_state_contains_only_token_digest_and_hash_fingerprint(self):
        token, session = self.store.authenticate('admin', PASSWORD)
        self.assertEqual(session['username'], 'admin')
        self.assertEqual(self.store.validate(token)['username'], 'admin')
        text = self.store.path.read_text()
        self.assertNotIn(token, text)
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn(HASH, text)
        self.assertIn(auth.token_digest(token), text)
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        loaded = auth.AuthStore(self.accounts, self.root / 'state', clock=lambda: self.now, verifier=self.verifier)
        self.assertEqual(loaded.validate(token)['username'], 'admin')

    def test_unknown_user_always_verifies_bcrypt_but_never_gets_session(self):
        for username, password in [('unknown', PASSWORD), ('admin', 'wrong'), ('../admin', PASSWORD)]:
            self.assertIsNone(self.store.authenticate(username, password))
        self.assertEqual(self.verifier.call_count, 3)
        self.assertFalse(self.store.sessions)

    def test_slow_verification_keeps_checks_available_and_rechecks_changed_hash(self):
        token, _ = self.store.create('admin')
        verifying = threading.Event()
        release = threading.Event()
        checked = threading.Event()
        results = []
        checks = []

        def slow_verify(password, hashed):
            verifying.set()
            release.wait(5)
            return True

        self.store.verifier = slow_verify
        worker = threading.Thread(target=lambda: results.append(self.store.authenticate('admin', PASSWORD)))
        worker.start()
        self.assertTrue(verifying.wait(2))

        def session_check():
            checks.append(self.store.validate(token))
            checked.set()

        check_worker = threading.Thread(target=session_check)
        check_worker.start()
        try:
            self.assertTrue(checked.wait(2), 'Slow bcrypt blocked an existing session check')
            self.assertEqual(checks[0]['username'], 'admin')
            self.accounts.write_text('admin ' + OTHER_HASH + '\n')
        finally:
            release.set()
            worker.join(3)
            check_worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results, [None], 'Password changed during verification must reject the old password')

    def test_password_change_and_account_removal_invalidate_sessions(self):
        token, _ = self.store.create('admin')
        self.accounts.write_text('admin ' + OTHER_HASH + '\n')
        self.assertIsNone(self.store.validate(token))
        self.assertNotIn(auth.token_digest(token), self.store.sessions)
        token, _ = self.store.create('admin')
        self.accounts.write_text('other ' + HASH + '\n')
        self.assertIsNone(self.store.validate(token))

    def test_absolute_expiry_idle_expiry_and_rotation(self):
        first, _ = self.store.create('admin')
        self.now += auth.DEFAULT_TTL
        self.assertIsNone(self.store.validate(first))
        remembered, _ = self.store.create('admin', remember=True)
        self.now += auth.IDLE_TTL
        self.assertIsNone(self.store.validate(remembered))
        first, _ = self.store.authenticate('admin', PASSWORD)
        second, _ = self.store.authenticate('admin', PASSWORD, previous=first)
        self.assertNotEqual(first, second)
        self.assertIsNone(self.store.validate(first))
        self.assertEqual(self.store.validate(second)['username'], 'admin')
        self.store.revoke(second)
        self.assertIsNone(self.store.validate(second))

    def test_recent_use_extends_idle_time_but_never_absolute_lifetime(self):
        token, original = self.store.create('admin', remember=True)
        self.now += 6 * 86400
        self.assertEqual(self.store.validate(token)['expires'], original['expires'])
        self.now += 6 * 86400
        self.assertEqual(self.store.validate(token)['expires'], original['expires'])
        self.now = original['expires']
        self.assertIsNone(self.store.validate(token))

    def test_remembered_session_survives_auth_restart_and_default_session_lifetime(self):
        token, original = self.store.create('admin', remember=True)
        self.now += auth.DEFAULT_TTL + 60
        restarted = auth.AuthStore(self.accounts, self.root / 'state', clock=lambda: self.now, verifier=self.verifier)
        session = restarted.validate(token)
        self.assertEqual(session['username'], 'admin')
        self.assertEqual(session['expires'], original['created'] + auth.REMEMBER_TTL)
        self.now += auth.IDLE_TTL
        self.assertIsNone(restarted.validate(token))

    def test_short_trusted_seed_and_bounded_sessions(self):
        token, value = self.store.create('admin', ttl=600)
        self.assertEqual(value['expires'] - value['created'], 600)
        for lifetime in (0, -1, auth.DEFAULT_TTL + 1, float('inf')):
            with self.assertRaises(ValueError):
                self.store.create('admin', ttl=lifetime)
        with self.assertRaises(auth.AuthError):
            self.store.create('missing')
        self.now += 600
        self.assertIsNone(self.store.validate(token))

    def test_malformed_account_or_session_storage_fails_closed(self):
        token, _ = self.store.create('admin')
        for text in ['', 'admin junk\n', 'admin ' + HASH + '\nadmin ' + HASH + '\n']:
            self.accounts.write_text(text)
            with self.assertRaises(auth.AuthError):
                self.store.validate(token)
        self.accounts.write_text('admin ' + HASH + '\n')
        for content in ['not json', '{}', '{"version":1,"sessions":{"bad":{}}}']:
            self.store.path.write_text(content)
            with self.assertRaises(auth.AuthError):
                auth.AuthStore(self.accounts, self.root / 'state')


class EndpointTests(AuthFixture):
    def setUp(self):
        super().setUp()
        self.server = auth.AuthServer(('127.0.0.1', 0), self.store, ORIGIN, GATEWAY)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def request(self, method='GET', path='/check', data=None, headers=None):
        base = {'X-Deck-Auth': GATEWAY, 'X-Deck-Client-IP': '192.0.2.1',
                'Origin': ORIGIN, 'Content-Type': 'application/json', 'X-Deck-Request': '1'}
        base.update(headers or {})
        body = json.dumps(data) if data is not None else None
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        connection.request(method, path, body, base)
        response = connection.getresponse()
        result = (response.status, dict(response.getheaders()), response.read())
        connection.close()
        return result

    def login(self, **overrides):
        values = {'username': 'admin', 'password': PASSWORD, 'remember': False}
        values.update(overrides)
        return self.request('POST', '/auth/login', values)

    def test_no_gateway_and_spoofed_user_headers_cannot_authorize(self):
        self.assertEqual(self.request(headers={'X-Deck-Auth': ''})[0], 403)
        self.assertEqual(self.request(headers={'X-Deck-Auth': 'bad'})[0], 403)
        status, headers, _ = self.request(headers={'X-Deck-User': 'admin', 'X-Forwarded-Uri': '/api/state'})
        self.assertEqual(status, 401)
        self.assertNotIn('X-Deck-User', headers)
        self.assertNotIn('WWW-Authenticate', headers)
        status, headers, _ = self.request(headers={'X-Forwarded-Uri': '//evil.example/'})
        self.assertEqual((status, headers.get('Location')), (303, '/login/'))

    def test_forward_auth_query_strings_preserve_access_and_identity(self):
        status, headers, _ = self.login()
        self.assertEqual(status, 200)
        cookie = headers['Set-Cookie'].split(';', 1)[0]
        for query in ('hours=1', 'hours=24', 'hours=168', 'force=1', 'id=backup-test', 'x=%2Fapi%2Fstate'):
            original = '/api/health?' + query
            forwarded = {'X-Forwarded-Uri':original, 'X-Forwarded-Method':'GET'}
            status, headers, _ = self.request(path='/check?'+query, headers=forwarded)
            self.assertEqual(status, 401)
            self.assertNotIn('X-Deck-User', headers)
            status, headers, _ = self.request(path='/check?'+query, headers=dict(forwarded, Cookie=cookie))
            self.assertEqual(status, 204)
            self.assertEqual(headers['X-Deck-User'], 'admin')
        self.assertEqual(self.request(path='/auth/session?fresh=1', headers={'Cookie':cookie})[0], 200)
        self.assertEqual(self.request(path='/check/extra?hours=24', headers={'Cookie':cookie})[0], 404)

    def test_login_cookie_check_and_logout(self):
        status, headers, body = self.login()
        self.assertEqual(status, 200)
        cookie = headers['Set-Cookie']
        for flag in ('__Host-deck_session=', 'Path=/', 'Secure', 'HttpOnly', 'SameSite=Strict'):
            self.assertIn(flag, cookie)
        self.assertNotIn('Domain=', cookie)
        self.assertNotIn('Max-Age=', cookie)
        self.assertNotIn(PASSWORD.encode(), body)
        self.assertEqual(json.loads(body), {'ok': True, 'username': 'admin'})
        request_cookie = cookie.split(';', 1)[0]
        status, response_headers, _ = self.request(headers={'Cookie': request_cookie})
        self.assertEqual(status, 204)
        self.assertEqual(response_headers.get('X-Deck-User'), 'admin')
        self.assertEqual(self.request(path='/auth/session', headers={'Cookie': request_cookie})[0], 200)
        status, response_headers, _ = self.request('POST', '/auth/logout', {}, {'Cookie': request_cookie})
        self.assertEqual(status, 200)
        self.assertIn('Max-Age=0', response_headers['Set-Cookie'])
        self.assertEqual(self.request(path='/auth/session', headers={'Cookie': request_cookie})[0], 401)

    def test_remember_cookie_and_malformed_or_duplicate_cookies(self):
        status, headers, _ = self.login(remember=True)
        self.assertEqual(status, 200)
        self.assertIn('Max-Age=' + str(auth.REMEMBER_TTL), headers['Set-Cookie'])
        good = headers['Set-Cookie'].split(';', 1)[0]
        for cookie in ['__Host-deck_session=invalid', good + '; ' + good, good + '; __Host-deck_session=other']:
            self.assertEqual(self.request(path='/auth/session', headers={'Cookie': cookie})[0], 401)

    def test_missing_strict_cookie_does_not_erase_a_remembered_browser_session(self):
        status, headers, _ = self.login(remember=True)
        self.assertEqual(status, 200)
        cookie = headers['Set-Cookie'].split(';', 1)[0]
        for path, forwarded, expected in [('/check', '/', 303), ('/check', '/api/state', 401), ('/auth/session', '/', 401)]:
            status, headers, _ = self.request(path=path, headers={'X-Forwarded-Uri': forwarded})
            self.assertEqual(status, expected)
            self.assertNotIn('Set-Cookie', headers)
        # The same construction used at daemon startup reads persistent state.
        self.server.store = auth.AuthStore(self.accounts, self.root / 'state', clock=lambda: self.now, verifier=self.verifier)
        self.assertEqual(self.request(path='/auth/session', headers={'Cookie': cookie})[0], 200)

    def test_late_check_for_rotated_token_cannot_clear_new_login_cookie(self):
        status, headers, _ = self.login(remember=True)
        old_cookie = headers['Set-Cookie'].split(';', 1)[0]
        status, headers, _ = self.request('POST', '/auth/login',
            {'username': 'admin', 'password': PASSWORD, 'remember': True}, {'Cookie': old_cookie})
        self.assertEqual(status, 200)
        new_cookie = headers['Set-Cookie'].split(';', 1)[0]
        self.assertNotEqual(new_cookie, old_cookie)
        status, headers, _ = self.request(path='/auth/session', headers={'Cookie': old_cookie})
        self.assertEqual(status, 401)
        self.assertNotIn('Set-Cookie', headers)
        self.assertEqual(self.request(path='/auth/session', headers={'Cookie': new_cookie})[0], 200)

    def test_login_errors_do_not_enumerate_accounts_or_return_secrets(self):
        first = self.login(username='missing')[2]
        second = self.login(password='wrong')[2]
        self.assertEqual(first, second)
        for secret in (PASSWORD, HASH, GATEWAY):
            self.assertNotIn(secret.encode(), first)
        self.assertNotIn('WWW-Authenticate', self.login(password='wrong')[1])

    def test_cross_origin_form_content_type_and_custom_header(self):
        data = {'username': 'admin', 'password': PASSWORD}
        for headers in [{'Origin': 'https://evil.example'}, {'Origin': ''}, {'X-Deck-Request': ''}, {'Content-Type': 'text/plain'}]:
            self.assertEqual(self.request('POST', '/auth/login', data, headers)[0], 403)
            self.assertEqual(self.request('POST', '/auth/logout', {}, headers)[0], 403)
        self.verifier.assert_not_called()
        self.assertEqual(self.login(remember='true')[0], 400)
        self.assertEqual(self.login(password='x' * 9000)[0], 400)
        self.assertEqual(self.login(password='bad\x00password')[0], 400)

    def test_rate_limit_and_concurrency_limit(self):
        for _ in range(8):
            self.assertEqual(self.login(password='wrong')[0], 401)
        status, headers, _ = self.login(password='wrong')
        self.assertEqual(status, 429)
        self.assertEqual(headers.get('Retry-After'), '300')
        self.assertEqual(self.verifier.call_count, 8)
        self.server.limiter = auth.LoginLimiter()
        self.server.login_slots.acquire()
        self.server.login_slots.acquire()
        try:
            self.assertEqual(self.login()[0], 429)
        finally:
            self.server.login_slots.release()
            self.server.login_slots.release()

    def slow_login(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        connection.putrequest('POST', '/auth/login')
        for name, value in {'X-Deck-Auth': GATEWAY, 'X-Deck-Client-IP': '192.0.2.1',
                            'Origin': ORIGIN, 'X-Deck-Request': '1',
                            'Content-Type': 'application/json', 'Content-Length': '1000'}.items():
            connection.putheader(name, value)
        connection.endheaders()  # Deliberately withhold the body.
        return connection

    def test_slow_login_bodies_are_limited_before_read_and_do_not_block_check_or_logout(self):
        token, _ = self.store.create('admin')
        cookie = auth.COOKIE + '=' + token
        slow = [self.slow_login(), self.slow_login()]
        try:
            deadline = time.monotonic() + 2
            while self.server.login_slots._value != 0 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(self.server.login_slots._value, 0)
            rejected = self.slow_login()
            try:
                response = rejected.getresponse()
                self.assertEqual(response.status, 429)
                response.read()
            finally:
                rejected.close()
            self.assertEqual(self.request(headers={'Cookie': cookie})[0], 204)
            self.assertEqual(self.request('POST', '/auth/logout', {}, {'Cookie': cookie})[0], 200)
            self.verifier.assert_not_called()
        finally:
            for connection in slow:
                connection.close()

    def test_absolute_deadline_closes_incomplete_headers(self):
        self.server.request_deadline = .2
        connection = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
        try:
            connection.sendall(b'GET /check HTTP/1.1\r\nHost: localhost\r\n')
            self.assertEqual(connection.recv(1024), b'')
        finally:
            connection.close()

    def test_bounded_request_pool_rejects_excess_connections_and_recovers(self):
        self.server.request_slots = threading.BoundedSemaphore(1)
        self.server.request_slots.acquire()
        try:
            self.assertEqual(self.request()[0], 503)
        finally:
            self.server.request_slots.release()
        self.assertEqual(self.request()[0], 303)


class LimiterTests(unittest.TestCase):
    def test_global_limit_and_expiration_are_bounded(self):
        now = [1000]
        limiter = auth.LoginLimiter(clock=lambda: now[0])
        for n in range(60):
            self.assertTrue(limiter.allow(str(n)))
        self.assertFalse(limiter.allow('new-client'))
        self.assertLessEqual(len(limiter.by_ip), 60)
        now[0] += 301
        self.assertTrue(limiter.allow('new-client'))
        self.assertEqual(len(limiter.by_ip), 1)


if __name__ == '__main__':
    unittest.main()
