#!/usr/bin/env python3
"""Fixed root helper for Server Deck domain changes. No shell or arbitrary argv.

Install with a dedicated restricted localhost SSH key. The stdin protocol only
allows inspect, plan and apply. --adopt is a root provisioning command; --worker
is invoked by a durable systemd unit after a confirmed, single-use plan.
"""
import argparse
import copy
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

CONFIG = pathlib.Path('/etc/server-deck/deployment.json')
APP_ENV = pathlib.Path('/etc/server-deck/server.env')
AUTH_ENV = pathlib.Path('/etc/server-deck/auth.env')
CADDY = pathlib.Path('/etc/caddy/Caddyfile')
TLS_DIR = pathlib.Path('/etc/caddy/server-deck-tls')
ROOT = pathlib.Path('/var/lib/server-deck-deployment')
CODE = pathlib.Path('/usr/local/lib/server-deck/deployment_helper.py')
RENDER = pathlib.Path('/usr/local/lib/server-deck/deployment_render.py')
ACME = pathlib.Path('/var/lib/server-deck-acme')
RENEW_HOOK = pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy/server-deck')
RENEW_UNIT = pathlib.Path('/etc/systemd/system/server-deck-certbot-renew.service')
RENEW_TIMER = pathlib.Path('/etc/systemd/system/server-deck-certbot-renew.timer')
CERTBOT = pathlib.Path('/usr/bin/certbot')
LINEAGES = pathlib.Path('/etc/letsencrypt/live')
MUTATION_LOCK = pathlib.Path('/var/lib/server-deck/mutation.lock')
FREEZE = pathlib.Path('/opt/server-deck/control-data/deployment-freeze')
ID = re.compile(r'[a-f0-9]{32}')
DOMAIN = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
SECRET = re.compile(r'[A-Za-z0-9_-]{32,128}')
TERMINAL = {'succeeded', 'failed'}
WATCHED = (CONFIG, APP_ENV, AUTH_ENV, CADDY, TLS_DIR / 'fullchain.pem', TLS_DIR / 'privkey.pem', TLS_DIR / 'previous-fullchain.pem', TLS_DIR / 'previous-privkey.pem', RENEW_HOOK, RENEW_UNIT, RENEW_TIMER)


class DeploymentError(ValueError):
    pass


def run(argv, timeout=20, input=None, check=True):
    p = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise DeploymentError('Команда настройки не завершилась: ' + pathlib.Path(argv[0]).name)
    return p


def atomic(path, body, mode=0o600, gid=None):
    path = pathlib.Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(body if isinstance(body, bytes) else body.encode())
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if gid is not None:
            os.chown(tmp, 0, gid)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def write_json(path, value):
    atomic(path, json.dumps(value, ensure_ascii=False, sort_keys=True))


def read_env(path):
    result = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or not re.fullmatch(r'[A-Z][A-Z0-9_]*', key):
            raise DeploymentError('Формат файла окружения требует проверки администратора.')
        parts = shlex.split(value)
        if len(parts) > 1:
            raise DeploymentError('Формат файла окружения требует проверки администратора.')
        result[key] = parts[0] if parts else ''
    return result


def change_origin(path, origin):
    lines = path.read_text().splitlines()
    matches = [i for i, line in enumerate(lines) if line.startswith('DECK_PUBLIC_ORIGIN=')]
    if len(matches) != 1:
        raise DeploymentError('Не удалось однозначно определить адрес панели.')
    lines[matches[0]] = 'DECK_PUBLIC_ORIGIN=' + origin
    atomic(path, '\n'.join(lines) + '\n')


def renderer():
    if not RENDER.is_file() or RENDER.is_symlink() or RENDER.stat().st_uid != 0 or RENDER.stat().st_mode & 0o022:
        raise DeploymentError('Установите защищённый шаблон конфигурации Server Deck.')
    spec = importlib.util.spec_from_file_location('_deck_deployment_render', RENDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_domain(value):
    if not isinstance(value, str) or not DOMAIN.fullmatch(value) or value != value.lower() or value.endswith(('.local', '.localhost', '.internal', '.invalid', '.test', '.example')):
        raise DeploymentError('Укажите публичный домен без протокола, пути и порта.')
    return value


def validate_email(value):
    if not isinstance(value, str) or not re.fullmatch(r'[^\s@]{1,128}@[^\s@]{1,253}\.[^\s@]{2,63}', value) or any(c in value for c in '\r\n\x00'):
        raise DeploymentError('Укажите email для Let’s Encrypt.')
    return value


def public_ip(value):
    try:
        address = ipaddress.IPv4Address(value)
        if address.is_global:
            return str(address)
    except (ValueError, TypeError):
        pass
    raise DeploymentError('Не определён публичный IPv4 сервера управления.')


def dns_addresses(domain):
    p = run(['/usr/bin/getent', 'ahostsv4', domain], timeout=8, check=False)
    rows = {line.split()[0] for line in p.stdout.splitlines() if line.split()}
    return {public_ip(value) for value in rows}


def load_configuration():
    try:
        c = json.loads(CONFIG.read_text())
    except (OSError, ValueError):
        raise DeploymentError('Управление доменом ещё не подготовлено. Выполните установку или принятие конфигурации Server Deck.')
    if not isinstance(c, dict) or c.get('version') != 1 or c.get('managed') is not True or c.get('mode') not in ('ip', 'domain'):
        raise DeploymentError('Неизвестная конфигурация развёртывания.')
    if c['mode'] == 'domain':
        validate_domain(c.get('host'))
        if c.get('port') != 443 or c.get('origin') != 'https://' + c['host']:
            raise DeploymentError('Адрес домена в конфигурации не совпал.')
    else:
        public_ip(c.get('host'))
        if type(c.get('port')) is not int or not 1024 <= c['port'] <= 65535 or c.get('origin') != 'https://' + c['host'] + ':' + str(c['port']):
            raise DeploymentError('Адрес IP в конфигурации не совпал.')
    public_ip(c.get('publicIp'))
    paths = c.get('publicPaths')
    if not isinstance(paths, list) or not paths or len(paths) > 100 or any(not isinstance(p, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', p) or '..' in p for p in paths):
        raise DeploymentError('Неизвестный список публичных ресурсов панели.')
    if read_env(APP_ENV).get('DECK_PUBLIC_ORIGIN') != c['origin'] or read_env(AUTH_ENV).get('DECK_PUBLIC_ORIGIN') != c['origin']:
        raise DeploymentError('Адрес приложения и авторизации различается; требуется проверка администратора.')
    return c


def revision():
    result = hashlib.sha256()
    for p in WATCHED:
        result.update(str(p).encode())
        result.update(p.read_bytes() if p.is_file() else b'<absent>')
    return result.hexdigest()


def last_job():
    try:
        j = json.loads((ROOT / 'last-job.json').read_text())
        return {k: j.get(k) for k in ('id', 'state', 'stage', 'createdAt', 'finishedAt', 'newOrigin', 'oldOrigin', 'error')}
    except (OSError, ValueError):
        return None


@contextmanager
def receipt_guard():
    with (ROOT / 'receipt.lock').open('a') as guard:
        fcntl.flock(guard.fileno(), fcntl.LOCK_EX)
        yield


def write_job(value):
    with receipt_guard():
        write_json(ROOT / 'last-job.json', value)


def freeze(ident):
    if FREEZE.exists():
        try:value = json.loads(FREEZE.read_text())
        except (OSError, ValueError):raise DeploymentError('Блокировка настройки требует проверки администратора.')
        if value.get('plan') != ident:
            raise DeploymentError('Другая задача смены домена требует проверки.')
        return
    write_json(FREEZE, {'plan': ident, 'createdAt': time.time()})


def unfreeze(ident):
    try:
        if json.loads(FREEZE.read_text()).get('plan') == ident:FREEZE.unlink()
    except (OSError, ValueError):
        pass


def inspect():
    c = load_configuration()
    j = last_job()
    return {'available': True, 'mode': c['mode'], 'host': c['host'], 'port': c['port'], 'origin': c['origin'],
            'email': c.get('email', ''), 'publicIp': c['publicIp'], 'certificate': 'self_signed' if c['mode'] == 'ip' else 'certbot',
            'certbotAvailable': CERTBOT.is_file(), 'busy': FREEZE.exists() or bool(j and j['state'] not in TERMINAL),
            'job': j, 'checkedAt': time.time(), 'canChange': CERTBOT.is_file() and RENDER.is_file()}


def no_active_jobs():
    path = pathlib.Path('/opt/server-deck/control-data/jobs.json')
    if path.is_file():
        try:
            jobs = json.loads(path.read_text())
        except (OSError, ValueError):
            raise DeploymentError('Не удалось проверить выполняющиеся задачи панели.')
        if any(j.get('state') not in ('succeeded', 'failed', 'needs_review', 'reviewed') for j in jobs.values()):
            raise DeploymentError('Дождитесь завершения задач панели перед сменой домена.')


def verify_target(c, domain):
    ips = dns_addresses(domain)
    if not ips or ips != {c['publicIp']}:
        raise DeploymentError('A-запись домена должна указывать только на IPv4 этого сервера управления: ' + c['publicIp'])
    # This deployment contract has only an attested IPv4. A stale AAAA record
    # must not make the IPv4-only health check look successful for all clients.
    ipv6 = run(['/usr/bin/python3', '-I', '-c',
                'import socket,sys,json\ntry:r=socket.getaddrinfo(sys.argv[1],None,socket.AF_INET6,0,0,0)\nexcept socket.gaierror as e:\n if e.errno not in (socket.EAI_NONAME,getattr(socket,"EAI_NODATA",socket.EAI_NONAME)):raise\n r=[]\nprint(json.dumps(sorted({x[4][0] for x in r})))',
                domain], timeout=8)
    try:addresses6 = json.loads(ipv6.stdout)
    except ValueError:raise DeploymentError('Не удалось проверить AAAA-запись домена.')
    if not isinstance(addresses6, list):raise DeploymentError('Не удалось проверить AAAA-запись домена.')
    for value in addresses6:
        if not isinstance(value,str):raise DeploymentError('Не удалось проверить AAAA-запись домена.')
        try:address = ipaddress.ip_address(value)
        except ValueError:continue
        if address.version == 6 and address.ipv4_mapped is None:
            raise DeploymentError('Для этой настройки удалите AAAA-запись домена: IPv6 сервера ещё не подтверждён.')
    # An unrelated web server must not be replaced or stopped to free 80/443.
    p = run(['/usr/bin/ss', '-H', '-ltnp'], timeout=8)
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3].rsplit(':', 1)[-1] in ('80', '443') and '"caddy"' not in line:
            raise DeploymentError('Порт 80 или 443 занят другой службой. Она не будет остановлена.')


def plan(data):
    if set(data) != {'action', 'domain', 'email'}:
        raise DeploymentError('Неверные поля плана.')
    domain = validate_domain(data['domain'])
    email = validate_email(data['email'])
    c = load_configuration()
    if domain == c['host'] and c['mode'] == 'domain':
        raise DeploymentError('Панель уже использует этот домен.')
    if not CERTBOT.is_file():
        raise DeploymentError('Certbot не установлен. Установите его перед настройкой домена.')
    renderer()
    if inspect()['busy']:
        raise DeploymentError('Смена домена уже выполняется; дождитесь результата.')
    no_active_jobs()
    verify_target(c, domain)
    now = time.time()
    ident = secrets.token_hex(16)
    value = {'id': ident, 'domain': domain, 'email': email, 'revision': revision(), 'createdAt': now,
             'expiresAt': now + 300, 'used': False, 'oldOrigin': c['origin'], 'newOrigin': 'https://' + domain}
    (ROOT / 'plans').mkdir(mode=0o700, parents=True, exist_ok=True)
    write_json(ROOT / 'plans' / (ident + '.json'), value)
    return {k: value[k] for k in ('id', 'domain', 'email', 'createdAt', 'expiresAt', 'oldOrigin', 'newOrigin')} | {
        'summary': ['Проверка DNS и свободных портов 80/443.', 'Выпуск сертификата Let’s Encrypt через Certbot.',
                    'Резервная копия конфигурации и автоматический откат при ошибке.',
                    'Перезагрузка конфигурации Caddy и перезапуск только Server Deck и его входа.',
                    'После смены адреса потребуется войти снова. VPN и SSH-сервисы не перезапускаются.']}


def apply(data):
    if set(data) != {'action', 'plan', 'confirmation'} or not isinstance(data['plan'], str) or not ID.fullmatch(data['plan']):
        raise DeploymentError('Неверный план.')
    path = ROOT / 'plans' / (data['plan'] + '.json')
    try:
        p = json.loads(path.read_text())
    except (OSError, ValueError):
        raise DeploymentError('План не найден; подготовьте новый.')
    if p['used'] or time.time() >= p['expiresAt'] or data['confirmation'] != p['domain']:
        raise DeploymentError('План истёк, уже использован или домен не совпал.')
    if p['revision'] != revision():
        raise DeploymentError('Конфигурация изменилась; подготовьте новый план.')
    j = last_job()
    if j and j['state'] not in TERMINAL:
        raise DeploymentError('Смена домена уже выполняется.')
    no_active_jobs()
    c = load_configuration()
    verify_target(c, p['domain'])
    freeze(p['id'])
    p['used'] = True
    write_json(path, p)
    job = {'id': p['id'], 'state': 'queued', 'stage': 'queued', 'createdAt': time.time(),
           'newOrigin': p['newOrigin'], 'oldOrigin': p['oldOrigin'], 'error': ''}
    write_job(job)
    try:
        run(['/usr/bin/systemd-run', '--quiet', '--unit=server-deck-domain-' + p['id'], '--collect',
             '--property=Type=oneshot', '/usr/bin/python3', '-I', str(CODE), '--worker', p['id']], timeout=15)
    except Exception as submit_error:
        # A lost systemd-run reply does not prove that the worker never started.
        # Preserve an already-running worker's receipt and hold every mutation.
        current = last_job()
        if current and current['id'] == p['id'] and current['state'] != 'queued':
            return {'accepted': True, 'job': current, 'newOrigin': p['newOrigin'], 'uncertain': current['state'] not in TERMINAL}
        not_found = False
        if isinstance(submit_error, DeploymentError):
            try:
                check = run(['/usr/bin/systemctl', 'show', 'server-deck-domain-' + p['id'] + '.service', '--property=LoadState', '--value'], timeout=5, check=False)
                not_found = check.returncode == 0 and check.stdout.strip() == 'not-found'
            except Exception:pass
        # Serialize the final receipt decision with worker stage/terminal writes.
        # A --collect unit may disappear only AFTER a worker wrote its result.
        with receipt_guard():
            current = last_job()
            if current and current['id'] == p['id'] and current['state'] != 'queued':
                return {'accepted': True, 'job': current, 'newOrigin': p['newOrigin'], 'uncertain': current['state'] not in TERMINAL}
            if not_found:
                job.update(state='failed', stage='submit', finishedAt=time.time(), error='Запуск задачи отклонён. Автоматического повтора нет.')
                write_json(ROOT / 'last-job.json', job)
                unfreeze(p['id'])
                raise DeploymentError(job['error'])
            job.update(state='needs_review', stage='submit_uncertain', error='Не удалось подтвердить запуск задачи. Изменения заблокированы до проверки; автоматического повтора нет.')
            write_json(ROOT / 'last-job.json', job)
            return {'accepted': True, 'job': job, 'newOrigin': p['newOrigin'], 'uncertain': True}
    return {'accepted': True, 'job': last_job() or job, 'newOrigin': p['newOrigin']}


def renew_hook():
    return renderer().renew_hook(load_configuration()['host'])


def verify_https(domain, ip):
    context = ssl.create_default_context()
    with socket.create_connection((ip, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as tls:
            tls.settimeout(10)
            tls.sendall(('GET /login/ HTTP/1.1\r\nHost: ' + domain + '\r\nConnection: close\r\n\r\n').encode())
            head = b''
            while b'\r\n' not in head and len(head) < 8192:
                chunk = tls.recv(4096)
                if not chunk:break
                head += chunk
            line = head.split(b'\r\n', 1)[0]
            if not re.fullmatch(rb'HTTP/1\.[01] 200 .*', line):
                raise DeploymentError('Новый HTTPS-адрес не прошёл контрольную проверку.')


def verify_services(domain, gateway, auth_gateway):
    """Prove both dynamic services work; a static login page is insufficient."""
    def get(port, path, headers):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            connection.request('GET', path, headers=headers)
            response = connection.getresponse()
            body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                raise DeploymentError('Служба панели вернула слишком большой ответ.')
            return response.status, body
        finally:
            connection.close()
    status, body = get(8768, '/auth/setup', {'Host': domain, 'X-Deck-Auth': auth_gateway})
    if status != 200:
        raise DeploymentError('Служба авторизации не прошла проверку.')
    auth = json.loads(body)
    if not isinstance(auth, dict) or type(auth.get('required')) is not bool or type(auth.get('available')) is not bool:
        raise DeploymentError('Ответ службы авторизации не прошёл проверку.')
    headers = {'Host': domain, 'X-Deck-Gateway': gateway}
    status, body = get(8765, '/', headers)
    token = re.search(rb'name="deck-token" content="([A-Za-z0-9_-]{32,128})"', body)
    if status != 200 or not token:
        raise DeploymentError('Server Deck не прошёл проверку после смены домена.')
    headers['X-Deck-Token'] = token.group(1).decode()
    status, body = get(8765, '/api/security-updates', headers)
    if status != 200 or not isinstance(json.loads(body), dict):
        raise DeploymentError('API панели не прошёл проверку после смены домена.')


def run_worker(ident):
    if not ID.fullmatch(ident):
        raise DeploymentError('Неверный идентификатор задачи.')
    p = json.loads((ROOT / 'plans' / (ident + '.json')).read_text())
    j = last_job()
    if not j or j['id'] != ident or j['state'] not in ('queued', 'needs_review') or p.get('used') is not True:
        raise DeploymentError('Задача не ожидает выполнения.')
    (ROOT / 'backups').mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = ROOT / 'backups' / ident
    backup.mkdir(mode=0o700)
    lock_path = MUTATION_LOCK
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lock_path.open('a') as guard:
        try:
            fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            j.update(state='failed', stage='lock', finishedAt=time.time(), error='На сервере выполняется другая задача. Автоматического повтора нет.')
            write_job(j)
            unfreeze(ident)
            return
        saved = {}
        changed = False
        def stage(value):
            j.update(state='running', stage=value)
            write_job(j)
        try:
            stage('preflight')
            no_active_jobs()
            c = load_configuration()
            if p['revision'] != revision():
                raise DeploymentError('Конфигурация изменилась после подтверждения.')
            verify_target(c, p['domain'])
            module = renderer()
            appenv = read_env(APP_ENV)
            authenv = read_env(AUTH_ENV)
            gateway = appenv.get('DECK_GATEWAY_TOKEN', '')
            auth_gateway = authenv.get('DECK_AUTH_GATEWAY', '')
            if not SECRET.fullmatch(gateway) or not SECRET.fullmatch(auth_gateway):
                raise DeploymentError('Параметры защищённого шлюза требуют проверки.')
            for index, path in enumerate(WATCHED):
                saved[str(path)] = (path.read_bytes(), path.stat().st_mode & 0o777, path.stat().st_uid, path.stat().st_gid) if path.is_file() else None
                if saved[str(path)]:
                    atomic(backup / str(index), saved[str(path)][0])
            write_json(backup / 'paths.json', list(saved))
            # Preserve the old, working HTTPS site during the ACME challenge.
            stage('certificate')
            ACME.mkdir(mode=0o755, parents=True, exist_ok=True)
            challenge = module.bootstrap_caddy(p['domain'])
            atomic(CADDY, saved[str(CADDY)][0] + b'\n' + challenge.encode(), mode=saved[str(CADDY)][1], gid=saved[str(CADDY)][3])
            changed = True
            run(['/usr/bin/caddy', 'validate', '--config', str(CADDY), '--adapter', 'caddyfile'])
            run(['/usr/bin/systemctl', 'reload', 'caddy.service'])
            certname = 'server-deck-domain-' + ident[:8]
            run(['/usr/bin/certbot', 'certonly', '--non-interactive', '--agree-tos', '--no-directory-hooks',
                 '--webroot', '-w', str(ACME), '--cert-name', certname, '-d', p['domain'], '--email', p['email']], timeout=240)
            stage('switch')
            no_active_jobs()
            lineage = LINEAGES / certname
            gid = grp.getgrnam('caddy').gr_gid
            TLS_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
            os.chown(TLS_DIR, 0, gid)
            atomic(TLS_DIR / 'fullchain.pem', (lineage / 'fullchain.pem').read_bytes(), mode=0o640, gid=gid)
            atomic(TLS_DIR / 'privkey.pem', (lineage / 'privkey.pem').read_bytes(), mode=0o640, gid=gid)
            final = module.caddy_config(p['domain'], gateway, auth_gateway, c['publicPaths'])
            # Old entry redirects to the new address. IP mode keeps its own old
            # certificate and high port; domain mode reuses Caddy's existing ACME
            # cache for the old name instead of sharing the new name's keypair.
            if saved[str(TLS_DIR / 'fullchain.pem')] and saved[str(TLS_DIR / 'privkey.pem')]:
                old_cert = TLS_DIR / 'previous-fullchain.pem'
                old_key = TLS_DIR / 'previous-privkey.pem'
                atomic(old_cert, saved[str(TLS_DIR / 'fullchain.pem')][0], mode=0o640, gid=gid)
                atomic(old_key, saved[str(TLS_DIR / 'privkey.pem')][0], mode=0o640, gid=gid)
                final += '\n' + c['origin'] + ' {\n tls ' + str(old_cert) + ' ' + str(old_key) + '\n redir ' + p['newOrigin'] + '{uri} 308\n}\n'
            else:
                final += '\n' + c['origin'] + ' {\n redir ' + p['newOrigin'] + '{uri} 308\n}\n'
            atomic(CADDY, final, mode=saved[str(CADDY)][1], gid=saved[str(CADDY)][3])
            run(['/usr/bin/caddy', 'validate', '--config', str(CADDY), '--adapter', 'caddyfile'])
            change_origin(APP_ENV, p['newOrigin'])
            change_origin(AUTH_ENV, p['newOrigin'])
            updated = dict(c, mode='domain', host=p['domain'], port=443, origin=p['newOrigin'], email=p['email'], certificateName=certname)
            write_json(CONFIG, updated)
            atomic(RENEW_HOOK, renew_hook(), mode=0o700)
            atomic(RENEW_UNIT, '[Unit]\nDescription=Renew Server Deck TLS certificates with Certbot\n[Service]\nType=oneshot\nExecStart=/usr/bin/certbot renew --quiet\n', mode=0o644)
            atomic(RENEW_TIMER, '[Unit]\nDescription=Renew Server Deck certificates twice daily\n[Timer]\nOnCalendar=*-*-* 03,15:00:00\nRandomizedDelaySec=3600\nPersistent=true\n[Install]\nWantedBy=timers.target\n', mode=0o644)
            run(['/usr/bin/systemctl', 'daemon-reload'])
            run(['/usr/bin/systemctl', 'enable', '--now', 'server-deck-certbot-renew.timer'])
            run(['/usr/bin/systemctl', 'restart', 'server-deck-auth.service'])
            run(['/usr/bin/systemctl', 'restart', 'server-deck.service'])
            run(['/usr/bin/systemctl', 'reload', 'caddy.service'])
            stage('verify')
            for _ in range(20):
                try:
                    verify_https(p['domain'], c['publicIp'])
                    verify_services(p['domain'], gateway, auth_gateway)
                    break
                except (OSError, DeploymentError):
                    time.sleep(1)
            else:
                raise DeploymentError('Новый HTTPS-адрес не ответил после смены конфигурации.')
            j.update(state='succeeded', stage='complete', finishedAt=time.time(), error='')
            write_job(j)
        except Exception as error:
            if changed:
                try:
                    if saved.get(str(RENEW_TIMER)) is None:
                        run(['/usr/bin/systemctl', 'disable', '--now', 'server-deck-certbot-renew.timer'], check=False)
                    for path, value in saved.items():
                        target = pathlib.Path(path)
                        if value is None:
                            target.unlink(missing_ok=True)
                        else:
                            atomic(target, value[0], value[1], value[3])
                            os.chown(target, value[2], value[3])
                    run(['/usr/bin/caddy', 'validate', '--config', str(CADDY), '--adapter', 'caddyfile'])
                    run(['/usr/bin/systemctl', 'daemon-reload'])
                    run(['/usr/bin/systemctl', 'restart', 'server-deck-auth.service'])
                    run(['/usr/bin/systemctl', 'restart', 'server-deck.service'])
                    run(['/usr/bin/systemctl', 'reload', 'caddy.service'])
                    for _ in range(10):
                        try:
                            verify_services(urlsplit(c['origin']).netloc, gateway, auth_gateway)
                            break
                        except (OSError, DeploymentError):time.sleep(1)
                    else:raise DeploymentError('Работа служб после отката не подтверждена.')
                    j['state'] = 'failed'
                    j['error'] = 'Смена домена отменена. Прежняя конфигурация восстановлена.'
                except Exception:
                    j['state'] = 'rollback_failed'
                    j['error'] = 'Автоматический откат не подтверждён. Требуется проверка администратора по SSH.'
            else:
                j['state'] = 'failed'
                j['error'] = str(error) if isinstance(error, DeploymentError) else 'Проверка смены домена не завершилась. Настройки не менялись.'
            j.update(stage='error', finishedAt=time.time())
            write_job(j)
        if j.get('state') in TERMINAL:
            unfreeze(ident)


def adopt_current():
    """Root-only provisioning: metadata only, no restart/config replacement."""
    if CONFIG.exists():
        return inspect()
    app = read_env(APP_ENV)
    auth = read_env(AUTH_ENV)
    origin = app.get('DECK_PUBLIC_ORIGIN', '')
    parsed = urlsplit(origin)
    if parsed.scheme != 'https' or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or origin != auth.get('DECK_PUBLIC_ORIGIN'):
        raise DeploymentError('Действующий адрес приложения и авторизации не совпал.')
    host = parsed.hostname
    cfg = CADDY.read_text()
    if not host or host not in cfg or any(x not in cfg for x in ('127.0.0.1:8765', '127.0.0.1:8766', '127.0.0.1:8768')):
        raise DeploymentError('Поддерживается только выделенная конфигурация Caddy Server Deck.')
    # Reject unrelated named sites before adopting the file as wholly managed.
    adapted = json.loads(run(['/usr/bin/caddy', 'adapt', '--config', str(CADDY), '--adapter', 'caddyfile']).stdout)
    def collect_hosts(value):
        hosts = []
        if isinstance(value, dict):
            if isinstance(value.get('host'), list):hosts.extend(value['host'])
            for child in value.values():hosts.extend(collect_hosts(child))
        elif isinstance(value, list):
            for child in value:hosts.extend(collect_hosts(child))
        return hosts
    if any(h not in (host, '*.' + host) for h in collect_hosts(adapted)):
        raise DeploymentError('Caddy обслуживает сторонние сайты; автоматическое принятие запрещено.')
    module = renderer()
    mode = 'domain'
    try:
        ip = public_ip(host)
        mode = 'ip'
    except DeploymentError:
        validate_domain(host)
        ips = dns_addresses(host)
        if len(ips) != 1:
            raise DeploymentError('Текущий домен должен иметь один публичный IPv4.')
        ip = next(iter(ips))
    port = parsed.port or 443
    if mode == 'domain' and port != 443:
        raise DeploymentError('Принятие нестандартного доменного порта не поддерживается.')
    if mode == 'ip' and not 1024 <= port <= 65535:
        raise DeploymentError('Принятие IP-адреса требует отдельного высокого порта.')
    c = dict(version=1, managed=True, mode=mode, host=host, port=port, origin=origin, email='', publicIp=ip,
             publicPaths=list(module.PUBLIC_PATHS), certificateName='server-deck' if mode == 'domain' else '')
    write_json(CONFIG, c)
    return inspect()


def protocol(request):
    if not isinstance(request, dict):
        raise DeploymentError('Ожидается объект запроса.')
    action = request.get('action')
    if action == 'inspect' and set(request) == {'action'}:
        return inspect()
    if action in ('plan', 'apply'):
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (ROOT / 'protocol.lock').open('a') as guard:
            try:fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:raise DeploymentError('Другая настройка домена уже выполняется.')
            return plan(request) if action == 'plan' else apply(request)
    raise DeploymentError('Действие не разрешено.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise SystemExit('Root helper required')
    parser = argparse.ArgumentParser()
    parser.add_argument('--adopt', action='store_true')
    parser.add_argument('--worker')
    args = parser.parse_args()
    try:
        if args.adopt:
            result = adopt_current()
        elif args.worker:
            run_worker(args.worker)
            return
        else:
            data = sys.stdin.buffer.read(16385)
            if len(data) > 16384:
                raise DeploymentError('Запрос слишком большой.')
            result = protocol(json.loads(data))
        print(json.dumps({'ok': True, 'data': result}, ensure_ascii=False))
    except Exception as error:
        message = str(error) if isinstance(error, DeploymentError) else 'Настройка домена не завершена. Требуется проверка администратора.'
        print(json.dumps({'ok': False, 'error': message, 'uncertain': not isinstance(error, DeploymentError)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
