"""Loopback cookie authentication for Caddy; passwords and bearer tokens are never logged.

The Caddy account file remains the only password store. Session files contain
token digests and password-hash fingerprints, never raw cookies or passwords.
"""
import fcntl
import hashlib
import hmac
import http.cookies
import ipaddress
import json
import math
import os
import pathlib
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

COOKIE = '__Host-deck_session'
USER = re.compile(r'[A-Za-z0-9_.@-]{1,64}')
BCRYPT = re.compile(r'\$2[aby]\$(?:0[4-9]|1[0-6])\$[A-Za-z0-9./]{53}')
DIGEST = re.compile(r'[a-f0-9]{64}')
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}')
DEFAULT_TTL = 12 * 3600
REMEMBER_TTL = 30 * 86400
IDLE_TTL = 7 * 86400
MAX_SESSIONS = 256
HASH_CODE = """import crypt,json,sys
data=json.load(sys.stdin)
if crypt.METHOD_BLOWFISH not in crypt.methods: sys.exit(1)
result=crypt.crypt(data['password'],crypt.mksalt(crypt.METHOD_BLOWFISH,rounds=4096))
sys.stdout.write(result or '')
"""
VERIFY_CODE = """import crypt,hmac,json,sys
data=json.load(sys.stdin)
result=crypt.crypt(data['password'],data['hash'])
sys.stdout.write('true' if result and hmac.compare_digest(result,data['hash']) else 'false')
"""


class AuthError(Exception):
    pass


def verify_password(password, hashed):
    # Python 3.12's crypt extension holds the GIL. A bounded child process
    # keeps existing session checks responsive during expensive bcrypt work.
    try:
        result = subprocess.run(
            [sys.executable, '-I', '-c', VERIFY_CODE],
            input=json.dumps({'password': password, 'hash': hashed}).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
        answer = result.stdout.strip()
        if result.returncode != 0 or answer not in (b'true', b'false'):
            raise AuthError('Password verification unavailable')
        return answer == b'true'
    except (OSError, subprocess.TimeoutExpired):
        raise AuthError('Password verification unavailable') from None


def hash_password(password):
    try:
        result = subprocess.run([sys.executable, '-I', '-c', HASH_CODE],
            input=json.dumps({'password': password}).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=8)
        hashed = result.stdout.decode('ascii').strip()
        if result.returncode != 0 or not BCRYPT.fullmatch(hashed):
            raise AuthError('Password hashing unavailable')
        return hashed
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise AuthError('Password hashing unavailable') from None


class SetupError(AuthError):
    def __init__(self, message, status=400):
        self.status = status
        super().__init__(message)


def valid_origin(origin):
    try:
        parsed = urlsplit(origin)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or
                parsed.path or parsed.query or parsed.fragment or not re.fullmatch(r'[a-z0-9.:-]+', parsed.netloc)):
            return False
        if parsed.netloc.endswith(':'):
            return False
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return False
        host = parsed.hostname
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host):
                return False
        return True
    except (TypeError, ValueError):
        return False


def token_digest(token):
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def fingerprint(hashed):
    return hashlib.sha256(hashed.encode('ascii')).hexdigest()


def read_accounts(path, allow_empty=False):
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise AuthError('Account configuration unavailable')
    accounts = {}
    for line in raw.decode('utf-8').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = line.split()
        if (len(parts) != 2 or not USER.fullmatch(parts[0]) or
                not BCRYPT.fullmatch(parts[1]) or parts[0] in accounts):
            raise AuthError('Account configuration unavailable')
        accounts[parts[0]] = parts[1]
    if (not accounts and not allow_empty) or len(accounts) > 128:
        raise AuthError('Account configuration unavailable')
    return accounts


class AuthStore:
    def __init__(self, accounts_path, state_dir, clock=time.time, verifier=None, hasher=None):
        self.accounts_path = pathlib.Path(accounts_path)
        self.state_dir = pathlib.Path(state_dir)
        self.clock = clock
        self.verifier = verifier or verify_password
        self.hasher = hasher or hash_password
        self.setup_lock = threading.Lock()
        self.lock = threading.RLock()
        self.sessions = {}
        if self.state_dir.is_symlink():
            raise AuthError('Session storage unavailable')
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.state_dir / 'sessions.json'
        accounts = read_accounts(self.accounts_path, allow_empty=True)
        if not accounts:
            self._bootstrap()  # Empty accounts are valid only for a provisioned first run.

        if self.path.exists():
            if self.path.is_symlink() or self.path.stat().st_size > 256 * 1024:
                raise AuthError('Session storage unavailable')
            self._load()

    def _bootstrap(self):
        path = self.state_dir / 'bootstrap.json'
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2048:
                raise ValueError()
            state = json.loads(path.read_text())
            if (set(state) != {'version', 'tokenHash', 'expiresAt', 'consumed'} or
                    type(state['version']) is not int or state['version'] != 1 or not isinstance(state['tokenHash'], str) or
                    not DIGEST.fullmatch(state['tokenHash']) or type(state['consumed']) is not bool or
                    type(state['expiresAt']) not in (int, float) or not math.isfinite(state['expiresAt'])):
                raise ValueError()
            return state
        except (OSError, ValueError, TypeError, KeyError):
            raise AuthError('First-run configuration unavailable') from None

    def setup_status(self):
        if read_accounts(self.accounts_path, allow_empty=True):
            return {'required': False, 'available': False}
        state = self._bootstrap()
        closed = (self.state_dir / 'bootstrap-used').exists()
        available = not closed and not state['consumed'] and state['expiresAt'] > self.clock()
        result = {'required': True, 'available': available}
        if not available:
            result['error'] = ('Код первичной настройки истёк. Выпустите новый код на сервере.'
                               if not closed and not state['consumed'] else
                               'Первичная настройка закрыта. Требуется восстановление администратором на сервере.')
        return result

    def initialize(self, data):
        if set(data) - {'code', 'username', 'password', 'confirmPassword', 'remember'}:
            raise SetupError('Проверьте поля формы')
        user = data.get('username'); password = data.get('password'); confirm = data.get('confirmPassword')
        code = data.get('code'); remember = data.get('remember', False)
        if not isinstance(user, str) or not USER.fullmatch(user):
            raise SetupError('Логин: 1–64 латинских буквы, цифры или символы _ . @ -')
        if (not isinstance(password, str) or len(password) < 12 or len(password.encode()) > 72 or
                any(c in password for c in '\x00\r\n')):
            raise SetupError('Пароль: минимум 12 символов и максимум 72 байта UTF-8, без переноса строки.')
        if not isinstance(confirm, str) or not hmac.compare_digest(password.encode(), confirm.encode()):
            raise SetupError('Пароли не совпадают')
        if not isinstance(code, str) or not TOKEN.fullmatch(code) or type(remember) is not bool:
            raise SetupError('Проверьте одноразовый код настройки')
        if not self.setup_lock.acquire(blocking=False):
            raise SetupError('Настройка уже выполняется. Обновите страницу.', 409)
        descriptor = None; temporary = None
        try:
            lock_path = self.state_dir / 'bootstrap.lock'
            descriptor = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SetupError('Настройка уже выполняется. Обновите страницу.', 409) from None
            # Both checks happen under a process-wide file lock, before any write.
            if read_accounts(self.accounts_path, allow_empty=True):
                raise SetupError('Учётная запись уже создана. Войдите в панель.', 409)
            state = self._bootstrap(); used = self.state_dir / 'bootstrap-used'
            if used.exists() or state['consumed']:
                raise SetupError('Одноразовый код уже использован.', 409)
            if state['expiresAt'] <= self.clock():
                raise SetupError('Код первичной настройки истёк. Выпустите новый код на сервере.', 410)
            if not hmac.compare_digest(state['tokenHash'], token_digest(code)):
                raise SetupError('Неверный одноразовый код настройки', 401)
            hashed = self.hasher(password)
            if not isinstance(hashed, str) or not BCRYPT.fullmatch(hashed):
                raise AuthError('Password hashing unavailable')
            # Prepare the durable complete account before consuming the claim.
            # The dedicated accounts directory is writable only by the auth service.
            stat = self.accounts_path.stat()
            if self.accounts_path.is_symlink():
                raise AuthError('Account configuration unavailable')
            fd, temporary = tempfile.mkstemp(prefix='.first-account-', dir=str(self.accounts_path.parent))
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as output:
                output.write(user + ' ' + hashed + '\n'); output.flush(); os.fsync(output.fileno())
            # This permanent marker is committed first. A crash cannot reopen setup,
            # even if accounts are later removed. Recovery then requires a local admin.
            used_fd = os.open(str(used), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(used_fd, b'first-run-claim-consumed\n'); os.fsync(used_fd)
            finally:
                os.close(used_fd)
            directory = os.open(self.state_dir, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
            # Recheck the exact empty account inode immediately before replacement.
            current = self.accounts_path.stat()
            if (current.st_ino != stat.st_ino or current.st_dev != stat.st_dev or
                    read_accounts(self.accounts_path, allow_empty=True)):
                raise AuthError('Account configuration changed during setup')
            os.replace(temporary, self.accounts_path); temporary = None
            directory = os.open(self.accounts_path.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
            with self.lock:
                return self._new(user, hashed, remember)
        finally:
            if temporary and os.path.exists(temporary): os.unlink(temporary)
            if descriptor is not None: os.close(descriptor)
            self.setup_lock.release()

    def _load(self):
        try:
            data = json.loads(self.path.read_text())
            if set(data) != {'version', 'sessions'} or data['version'] != 1:
                raise ValueError()
            sessions = data['sessions']
            if not isinstance(sessions, dict) or len(sessions) > MAX_SESSIONS:
                raise ValueError()
            for key, value in sessions.items():
                if not DIGEST.fullmatch(key) or not isinstance(value, dict):
                    raise ValueError()
                if set(value) != {'username', 'fingerprint', 'created', 'expires', 'last_seen'}:
                    raise ValueError()
                if not USER.fullmatch(value['username']) or not DIGEST.fullmatch(value['fingerprint']):
                    raise ValueError()
                times = [value[k] for k in ('created', 'expires', 'last_seen')]
                if any(type(v) not in (int, float) or not math.isfinite(v) for v in times):
                    raise ValueError()
                if not 0 <= value['created'] <= value['last_seen'] < value['expires'] <= value['created'] + REMEMBER_TTL:
                    raise ValueError()
            self.sessions = sessions
        except (OSError, ValueError, TypeError, KeyError):
            raise AuthError('Session storage unavailable') from None

    def _save(self):
        fd, name = tempfile.mkstemp(prefix='.sessions-', dir=str(self.state_dir))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as out:
                json.dump({'version': 1, 'sessions': self.sessions}, out, separators=(',', ':'))
                out.flush()
                os.fsync(out.fileno())
            os.replace(name, self.path)
            directory = os.open(self.state_dir, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _new(self, username, hashed, remember=False, ttl=None, previous=None):
        now = self.clock()
        duration = REMEMBER_TTL if remember else DEFAULT_TTL
        if ttl is not None:
            if type(ttl) not in (int, float) or not math.isfinite(ttl) or not 0 < ttl <= duration:
                raise ValueError('Invalid session lifetime')
            duration = ttl
        self.sessions = {k: v for k, v in self.sessions.items()
                         if v['expires'] > now and now - v['last_seen'] < IDLE_TTL}
        if previous and TOKEN.fullmatch(previous):
            self.sessions.pop(token_digest(previous), None)
        while len(self.sessions) >= MAX_SESSIONS:
            oldest = min(self.sessions, key=lambda k: self.sessions[k]['last_seen'])
            del self.sessions[oldest]
        token = secrets.token_urlsafe(32)
        value = {'username': username, 'fingerprint': fingerprint(hashed),
                 'created': now, 'expires': now + duration, 'last_seen': now}
        self.sessions[token_digest(token)] = value
        try:
            self._save()
        except Exception:
            self.sessions.pop(token_digest(token), None)
            raise
        return token, dict(value)

    def create(self, username, remember=False, ttl=None):
        """Trusted local API; never exposed as an HTTP endpoint."""
        with self.lock:
            accounts = read_accounts(self.accounts_path)
            if username not in accounts:
                raise AuthError('Unknown account')
            return self._new(username, accounts[username], remember, ttl)

    def authenticate(self, username, password, remember=False, previous=None):
        accounts = read_accounts(self.accounts_path)
        # Bcrypt is deliberately outside the session lock: a login attempt
        # must not block the Caddy checks for already authenticated users.
        hashed = accounts.get(username, next(iter(accounts.values())))
        correct = self.verifier(password, hashed)
        # An unknown username still incurs a real bcrypt calculation. Its
        # verification result is ignored, including if the password matches.
        if not correct or username not in accounts:
            return None
        with self.lock:
            current = read_accounts(self.accounts_path).get(username)
            if not current or not hmac.compare_digest(current, hashed):
                return None
            return self._new(username, hashed, remember, previous=previous)

    def validate(self, token):
        if not token or not TOKEN.fullmatch(token):
            return None
        with self.lock:
            key = token_digest(token)
            value = self.sessions.get(key)
            if value is None:
                return None
            accounts = read_accounts(self.accounts_path)
            now = self.clock()
            current = accounts.get(value['username'])
            if (value['expires'] <= now or now - value['last_seen'] >= IDLE_TTL or
                    not current or not hmac.compare_digest(value['fingerprint'], fingerprint(current))):
                del self.sessions[key]
                self._save()
                return None
            # Persist at most once per minute per session, even when multiple
            # assets and dashboard requests arrive together.
            if now - value['last_seen'] >= 60:
                old_seen = value['last_seen']
                value['last_seen'] = now
                try:
                    self._save()
                except Exception:
                    value['last_seen'] = old_seen
                    raise
            return dict(value)

    def revoke(self, token):
        if token and TOKEN.fullmatch(token):
            with self.lock:
                value = self.sessions.pop(token_digest(token), None)
                if value is not None:
                    self._save()


class LoginLimiter:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.by_ip = {}
        self.all = []

    def allow(self, client):
        with self.lock:
            now = self.clock()
            cutoff = now - 300
            self.by_ip = {ip: [t for t in times if t > cutoff]
                          for ip, times in self.by_ip.items() if times[-1] > cutoff}
            self.all = [t for t in self.all if t > cutoff]
            attempts = self.by_ip.get(client, [])
            if len(attempts) >= 8 or len(self.all) >= 60:
                return False
            if client not in self.by_ip and len(self.by_ip) >= 1024:
                return False
            self.by_ip.setdefault(client, []).append(now)
            self.all.append(now)
            return True


class AuthServer(ThreadingHTTPServer):
    daemon_threads = True
    request_deadline = 15

    def __init__(self, address, store, origin, gateway, limiter=None):
        if not valid_origin(origin) or len(gateway) < 32:
            raise AuthError('Invalid authentication service configuration')
        self.store = store
        self.origin = origin
        self.gateway = gateway
        self.limiter = limiter or LoginLimiter()
        self.login_slots = threading.BoundedSemaphore(2)
        self.logout_slots = threading.BoundedSemaphore(4)
        self.request_slots = threading.BoundedSemaphore(64)
        super().__init__(address, AuthHandler)

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            try:
                request.settimeout(.2)
                request.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n'
                                b'Cache-Control: no-store\r\nConnection: close\r\n\r\n')
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()

    def handle_error(self, request, client_address):
        # Never include a request, form body or credentials in service logs.
        pass


class AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(self.server.request_deadline)
        # An idle socket timeout alone can be defeated by slowly sending a
        # byte at a time. This timer bounds the whole request, including headers.
        self.deadline_timer = threading.Timer(self.server.request_deadline, self.expire_request)
        self.deadline_timer.daemon = True
        self.deadline_timer.start()

    def expire_request(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self.deadline_timer.cancel()
        super().finish()

    def reply(self, status, data=None, headers=None):
        body = b'' if status == 204 else json.dumps(data or {}, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def gateway_ok(self):
        values = self.headers.get_all('X-Deck-Auth', [])
        return len(values) == 1 and hmac.compare_digest(values[0].encode(), self.server.gateway.encode())

    def cookie(self):
        raw = '; '.join(self.headers.get_all('Cookie', []))
        if sum(part.split('=', 1)[0].strip() == COOKIE for part in raw.split(';')) != 1:
            return None
        try:
            cookies = http.cookies.SimpleCookie()
            cookies.load(raw)
            value = cookies[COOKIE].value
            return value if TOKEN.fullmatch(value) else None
        except (http.cookies.CookieError, KeyError):
            return None

    @staticmethod
    def set_cookie(token, remember=False):
        value = COOKIE + '=' + token + '; Path=/; Secure; HttpOnly; SameSite=Strict'
        return value + ('; Max-Age=' + str(REMEMBER_TTL) if remember else '')

    @staticmethod
    def clear_cookie():
        return COOKIE + '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'

    def do_GET(self):
        if not self.gateway_ok():
            return self.reply(403, {'error': 'Запрос отклонён'})
        path = urlsplit(self.path).path
        if path not in ('/check', '/auth/session', '/auth/setup'):
            return self.reply(404, {'error': 'Не найдено'})
        try:
            if path == '/auth/setup':
                return self.reply(200, self.server.store.setup_status())
            session = self.server.store.validate(self.cookie())
            if session:
                if path == '/check':
                    return self.reply(204, headers={'X-Deck-User': session['username']})
                return self.reply(200, {'username': session['username']})
            if path == '/check':
                original = urlsplit(self.headers.get('X-Forwarded-Uri', '/')).path
                method = self.headers.get('X-Forwarded-Method', 'GET')
                if not original.startswith('/api/') and original != '/api' and method in ('GET', 'HEAD'):
                    return self.reply(303, headers={'Location': '/login/'})
            # A Strict cookie can be omitted on an external navigation. Also,
            # a late check for an old token can arrive after a successful login.
            # Neither read-only request may erase the browser's newer cookie.
            # Explicit logout clears it; successful login replaces it.
            return self.reply(401, {'error': 'Войдите в Server Deck'})
        except Exception:
            return self.reply(503, {'error': 'Вход временно недоступен'})

    def do_POST(self):
        if not self.gateway_ok():
            return self.reply(403, {'error': 'Запрос отклонён'})
        if self.path not in ('/auth/login', '/auth/logout', '/auth/setup'):
            return self.reply(404, {'error': 'Не найдено'})
        if (self.headers.get('Origin') != self.server.origin or self.headers.get('X-Deck-Request') != '1' or
                self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower() != 'application/json'):
            return self.reply(403, {'error': 'Запрос отклонён'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 8192 or self.headers.get('Transfer-Encoding'):
                return self.reply(400, {'error': 'Проверьте поля формы'})
        except ValueError:
            return self.reply(400, {'error': 'Проверьте поля формы'})
        slots = self.server.logout_slots
        if self.path in ('/auth/login', '/auth/setup'):
            slots = self.server.login_slots
            try:
                client = str(ipaddress.ip_address(self.headers.get('X-Deck-Client-IP', '')))
            except ValueError:
                client = 'unknown'
            if not self.server.limiter.allow(client):
                return self.reply(429, {'error': 'Слишком много попыток. Повторите через 5 минут.'}, {'Retry-After': '300'})
        # Reserve a slot before reading a potentially slow body. Login clients
        # cannot consume the separate check/logout capacity.
        if not slots.acquire(blocking=False):
            return self.reply(429, {'error': 'Слишком много запросов. Попробуйте позже.'}, {'Retry-After': '15'})
        try:
            return self.handle_post_body(size)
        finally:
            slots.release()

    def handle_post_body(self, size):
        try:
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                return self.reply(400, {'error': 'Проверьте поля формы'})
        except (ValueError, UnicodeError, OSError):
            return self.reply(400, {'error': 'Проверьте поля формы'})
        try:
            if self.path == '/auth/logout':
                self.server.store.revoke(self.cookie())
                return self.reply(200, {'ok': True}, {'Set-Cookie': self.clear_cookie()})
            if self.path == '/auth/setup':
                token, session = self.server.store.initialize(data)
                return self.reply(200, {'ok': True, 'username': session['username']},
                                  {'Set-Cookie': self.set_cookie(token, data.get('remember', False))})
            username = data.get('username')
            password = data.get('password')
            remember = data.get('remember', False)
            if (not isinstance(username, str) or len(username) > 64 or
                    not isinstance(password, str) or not 0 < len(password.encode()) <= 512 or
                    any(c in password for c in '\x00\r\n') or type(remember) is not bool):
                return self.reply(400, {'error': 'Проверьте поля формы'})
            result = self.server.store.authenticate(username, password, remember, self.cookie())
            if result is None:
                return self.reply(401, {'error': 'Неверный логин или пароль'})
            token, session = result
            return self.reply(200, {'ok': True, 'username': session['username']}, {'Set-Cookie': self.set_cookie(token, remember)})
        except SetupError as error:
            return self.reply(error.status, {'error': str(error)})
        except Exception:
            return self.reply(503, {'error': 'Вход временно недоступен'})


def main():
    os.umask(0o077)
    store = AuthStore(os.environ.get('DECK_ACCOUNTS_FILE', '/etc/caddy/server-deck-accounts'),
                      os.environ.get('DECK_AUTH_STATE', '/var/lib/server-deck-auth'))
    server = AuthServer(('127.0.0.1', 8768), store, os.environ.get('DECK_PUBLIC_ORIGIN', ''), os.environ.get('DECK_AUTH_GATEWAY', ''))
    server.serve_forever()


if __name__ == '__main__':
    main()
