#!/usr/bin/env python3
"""Root-only, refuse-to-overwrite installation onto a fresh supported Linux host."""
import argparse
import ast
import contextlib
import http.client
import hashlib
import ipaddress
import importlib.util
import json
import os
import pathlib
import pwd
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time

from render import APP_UNIT, AUTH_UNIT, RENEW_SERVICE, RENEW_TIMER, bootstrap_caddy, caddy_config, renew_hook, validate

APP = pathlib.Path('/opt/server-deck')
WEB = pathlib.Path('/opt/server-deck-web')
CONF = pathlib.Path('/etc/server-deck')
HOME = pathlib.Path('/var/lib/serverdeck')
HELPERS = pathlib.Path('/usr/local/lib/server-deck')
UNIT_DIR = pathlib.Path('/etc/systemd/system')


def run(command, private=False, **kwargs):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE if private else None, stderr=subprocess.PIPE if private else None, **kwargs)
    if result.returncode:
        raise RuntimeError('Команда завершилась с ошибкой: ' + command[0] + (' ' + command[1] if len(command) > 1 else '') + '. Проверьте журнал; установщик не повторяет действие автоматически.')
    return result


def put(path, data, mode=0o600, uid=0, gid=0):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(path), flags, mode)
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.chown(path, uid, gid)
    path.chmod(mode)


def replace(path, data, mode=0o640, uid=0, gid=0):
    path = pathlib.Path(path)
    temp = path.with_name(path.name + '.serverdeck-new')
    put(temp, data, mode, uid, gid)
    os.replace(temp, path)


def os_release(path=pathlib.Path('/etc/os-release')):
    data = {}
    for line in path.read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            data[key] = value.strip('"\'')
    return data


def validate_request(data):
    if not isinstance(data, dict) or set(data) != {'domain', 'email', 'publicIp', 'httpsPort'}:
        raise ValueError('Некорректный запрос установщика')
    if not all(isinstance(data[k], str) for k in ('domain', 'email', 'publicIp')):
        raise ValueError('Некорректный запрос установщика')
    address = ipaddress.ip_address(data['publicIp'])
    if address.version != 4 or not address.is_global:
        raise ValueError('Нужен публичный IPv4')
    if data['domain']:
        validate(data['domain'])
        if not re.fullmatch(r'[^\s@]{1,128}@[^\s@]{1,253}\.[^\s@]{2,63}', data['email']) or data['httpsPort'] != 443:
            raise ValueError('Некорректный email или HTTPS-порт')
    else:
        if data['email'] or data['httpsPort'] is not None and (type(data['httpsPort']) is not int or not 1024 <= data['httpsPort'] <= 65535):
            raise ValueError('Некорректный HTTPS-порт IP-режима')


def free_https_port():
    for _ in range(100):
        port = 20000 + secrets.randbelow(40000)
        with socket.socket() as sock:
            try:
                sock.bind(('0.0.0.0', port))
                return port
            except OSError:
                pass
    raise ValueError('Не удалось подобрать свободный HTTPS-порт')


def install_relative(relative):
    """Map repository folders to the stable installed application layout."""
    relative = pathlib.Path(relative)
    parts = relative.parts
    if relative.is_absolute() or '..' in parts or '\\' in relative.as_posix() or ':' in relative.as_posix():
        raise ValueError('Небезопасный путь исходников')
    if len(parts) == 2 and parts[0] == 'backend' and relative.suffix == '.py':
        return pathlib.Path(parts[1])
    if len(parts) >= 3 and parts[0] == 'frontend' and parts[1] in ('static', 'pwa'):
        return pathlib.Path(*parts[1:])
    raise ValueError('Неизвестный раздел исходников')


def selected_files(source):
    allowed_suffixes = {'.py', '.js', '.css', '.html', '.webmanifest', '.png', '.svg'}
    paths = []
    for path in sorted(source.rglob('*')):
        rel = path.relative_to(source)
        if not path.is_file():
            continue
        allowed = (len(rel.parts) == 2 and rel.parts[0] == 'backend' and path.suffix == '.py' and not path.name.startswith(('test_', 'check_', 'prepare_'))) or (len(rel.parts) >= 3 and rel.parts[0] == 'frontend' and rel.parts[1] in ('static', 'pwa') and path.suffix in allowed_suffixes - {'.py'})
        if allowed:
            if any((source.joinpath(*rel.parts[:count])).is_symlink() for count in range(1, len(rel.parts) + 1)) or path.stat().st_size > 8 * 1024 * 1024:
                raise ValueError('Небезопасный файл исходников')
            paths.append(rel)
    for rel in ('backend/server.py', 'backend/web_auth.py', 'backend/account_helper.py', 'backend/deployment_helper.py', 'frontend/static/index.html', 'frontend/pwa/login/index.html'):
        if pathlib.Path(rel) not in paths:
            raise ValueError('Пакет неполон')
    tree = ast.parse((source / 'backend/server.py').read_text(encoding='utf-8'))
    defaults = [n.value for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'DEFAULTS' for t in n.targets)]
    if len(defaults) != 1 or not isinstance(defaults[0], (ast.List, ast.Tuple)) or defaults[0].elts:
        raise ValueError('Пакет содержит непустые DEFAULTS. Установка личных данных запрещена.')
    for rel in paths:
        install_relative(rel)
        if rel.suffix == '.py':
            compile((source / rel).read_text(encoding='utf-8'), str(rel), 'exec')
    return paths


def preflight(source, data):
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise ValueError('Установщик требует root на Linux')
    if not (3, 9) <= sys.version_info[:2] <= (3, 12):
        raise ValueError('Требуется Python 3.9–3.12; auth использует системный bcrypt/crypt')
    distro = os_release()
    if (distro.get('ID'), distro.get('VERSION_ID')) not in (('ubuntu', '24.04'), ('debian', '12')):
        raise ValueError('Поддерживаются Ubuntu 24.04 и Debian 12')
    if not pathlib.Path('/run/systemd/system').is_dir() or not shutil.which('apt-get'):
        raise ValueError('Нужен Linux с systemd и APT (не контейнер без systemd)')
    for path in (APP, WEB, CONF, HOME, HELPERS, pathlib.Path('/etc/caddy'), UNIT_DIR / 'server-deck.service', UNIT_DIR / 'server-deck-auth.service', UNIT_DIR / 'server-deck-certbot-renew.timer', pathlib.Path('/etc/letsencrypt/live/server-deck'), pathlib.Path('/etc/letsencrypt/renewal/server-deck.conf'), pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy/server-deck')):
        if path.exists() or path.is_symlink():
            raise ValueError('Путь уже существует: ' + str(path) + '. Автоматическая перезапись запрещена; нужен отдельный чистый хост.')
    for username in ('serverdeck', 'caddy'):
        try:
            pwd.getpwnam(username)
        except KeyError:
            continue
        raise ValueError('Системный пользователь уже существует: ' + username)
    with contextlib.ExitStack() as stack:
        for port in ((80, 443, 8765, 8766, 8768) if data['domain'] else (data['httpsPort'], 8765, 8766, 8768)):
            for family, host in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
                try:
                    sock = stack.enter_context(socket.socket(family))
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind((host, port))
                except OSError as error:
                    if family == socket.AF_INET6 and error.errno in (97, 99):
                        continue
                    raise ValueError('Порт занят или недоступен: ' + str(port) + '. Работающие службы менять нельзя.') from None
    if shutil.disk_usage('/opt').free < 512 * 1024 * 1024:
        raise ValueError('Нужно минимум 512 МиБ свободного места в /opt')
    paths = selected_files(source)
    # Domain must resolve; ownership/routing is then proved by the ACME challenge.
    if data['domain'] and not socket.getaddrinfo(data['domain'], 80):
        raise ValueError('Домен ещё не разрешается в DNS')
    return paths


def wait_http(port, path, status, headers=None):
    for _ in range(60):
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
        try:
            conn.request('GET', path, headers=headers or {})
            response = conn.getresponse()
            response.read()
            if response.status == status:
                return
        except OSError:
            pass
        finally:
            conn.close()
        time.sleep(0.5)
    raise RuntimeError('Локальный обработчик не готов: ' + str(port))


def loopback_helper(owner, key_name, helper_name, ssh_port=22):
    """No sshd setting changes: helper key can run only one root command locally."""
    ssh_dir = HOME / '.ssh'
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    os.chown(ssh_dir, owner.pw_uid, owner.pw_gid)
    key = ssh_dir / key_name
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'serverdeck-' + key_name, '-f', str(key)], private=True)
    for path in (key, pathlib.Path(str(key) + '.pub')):
        os.chown(path, owner.pw_uid, owner.pw_gid)
    key.chmod(0o600)
    known = ''
    known_label = '127.0.0.1' if ssh_port == 22 else '[127.0.0.1]:' + str(ssh_port)
    for path in sorted(pathlib.Path('/etc/ssh').glob('ssh_host_*_key.pub')):
        parts = path.read_text().split()
        if len(parts) >= 2:
            known += known_label + ' ' + parts[0] + ' ' + parts[1] + '\n'
    if not known:
        return False
    known_path = ssh_dir / 'known_hosts'
    if not known_path.exists():
        put(known_path, known, uid=owner.pw_uid, gid=owner.pw_gid)
    else:
        existing_known = set(known_path.read_text().splitlines())
        missing_known = [line for line in known.splitlines() if line not in existing_known]
        if missing_known:
            with known_path.open('a') as output:
                output.write('\n' + '\n'.join(missing_known) + '\n')
    public = pathlib.Path(str(key) + '.pub').read_text().strip()
    line = 'restrict,from="127.0.0.1,::1",command="/usr/bin/python3 -I /usr/local/lib/server-deck/' + helper_name + '" ' + public + '\n'
    root_ssh = pathlib.Path('/root/.ssh')
    if root_ssh.is_symlink():
        raise RuntimeError('Root .ssh — символическая ссылка; ручная проверка обязательна')
    if not root_ssh.exists():
        root_ssh.mkdir(mode=0o700)
    authorized = root_ssh / 'authorized_keys'
    if authorized.is_symlink():
        raise RuntimeError('authorized_keys — символическая ссылка; ручная проверка обязательна')
    old = authorized.read_bytes() if authorized.exists() else None
    # Preserve every existing key and option. Add only our loopback forced command.
    if old is not None and not (CONF / 'root-authorized-keys.before').exists():
        put(CONF / 'root-authorized-keys.before', old.decode(), 0o600)
    with authorized.open('a', encoding='utf-8') as out:
        if old and not old.endswith(b'\n'):
            out.write('\n')
        out.write(line)
    authorized.chmod(0o600)
    command = ['runuser', '-u', 'serverdeck', '--', 'ssh', '-i', str(key), '-p', str(ssh_port), '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', 'root@127.0.0.1', '/usr/bin/python3 -I /usr/local/lib/server-deck/' + helper_name]
    probe = '{}' if helper_name == 'account_helper.py' else json.dumps({'action': 'inspect'})
    try:
        result = subprocess.run(command, input=probe, capture_output=True, text=True, timeout=15)
        reply = json.loads(result.stdout)
        available = result.returncode == 0 and (reply.get('code') == 'identity' if helper_name == 'account_helper.py' else reply.get('ok') is True)
    except (ValueError, OSError, subprocess.TimeoutExpired):
        available = False
    if not available:
        # Existing sshd policy wins; never relax root-login or password settings.
        if old is None:
            authorized.unlink()
        else:
            authorized.write_bytes(old)
            authorized.chmod(0o600)
    return available


def install(source, data, paths):
    print('Проверка чистого хоста пройдена. Устанавливаю пакеты и отдельные службы панели.')
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_SUSPEND='1', NEEDRESTART_MODE='l')
    run(['apt-get', '-o', 'APT::Update::Error-Mode=any', 'update'], env=env)
    run(['apt-get', 'install', '-y', '--no-upgrade', '--no-install-recommends', 'python3', 'openssh-client', 'openssh-server', 'openssl', 'ca-certificates', 'caddy', 'certbot'], env=env)
    run(['systemctl', 'stop', 'caddy.service'])
    run(['useradd', '--system', '--home-dir', str(HOME), '--create-home', '--shell', '/usr/sbin/nologin', 'serverdeck'])
    owner = pwd.getpwnam('serverdeck')
    caddy = pwd.getpwnam('caddy')
    APP.mkdir(mode=0o700)
    os.chown(APP, owner.pw_uid, owner.pw_gid)
    HOME.chmod(0o700)
    CONF.mkdir(mode=0o700)
    HELPERS.mkdir(mode=0o755)
    WEB.mkdir(mode=0o755)
    acme = pathlib.Path('/var/lib/server-deck-acme')
    acme.mkdir(mode=0o755)
    for rel in paths:
        target = APP / install_relative(rel)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source / rel, target)
        target.chmod(0o600)
        os.chown(target, owner.pw_uid, owner.pw_gid)
    for path in APP.rglob('*'):
        if path.is_dir():
            os.chown(path, owner.pw_uid, owner.pw_gid)
            path.chmod(0o700)
    put(APP / 'servers.json', '[]\n', uid=owner.pw_uid, gid=owner.pw_gid)
    public_paths = ['/install', '/install/', '/login', '/login/']
    for rel in paths:
        installed = install_relative(rel)
        if installed.parts[0] == 'pwa':
            target = WEB.joinpath(*installed.parts[1:])
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            shutil.copyfile(source / rel, target)
            target.chmod(0o644)
            public_paths.append('/' + '/'.join(installed.parts[1:]))
    for name in ('web_auth.py', 'account_helper.py', 'deployment_helper.py'):
        put(HELPERS / name, (source / 'backend' / name).read_text(encoding='utf-8'), mode=0o644 if name == 'web_auth.py' else 0o600)
    for script in ('reset_bootstrap.py', 'reset_account.py'):
        put(HELPERS / script, (source / 'installer' / script).read_text(encoding='utf-8'), mode=0o600)
    put(HELPERS / 'deployment_render.py', (source / 'installer/render.py').read_text(encoding='utf-8'), mode=0o600)
    accounts_dir = pathlib.Path('/etc/caddy/server-deck-accounts.d')
    accounts_dir.mkdir(mode=0o700)
    os.chown(accounts_dir, caddy.pw_uid, caddy.pw_gid)
    accounts_path = accounts_dir / 'accounts'
    put(accounts_path, '', uid=caddy.pw_uid, gid=caddy.pw_gid)
    put(CONF / 'auth-account-path', str(accounts_path) + '\n')
    auth_state = pathlib.Path('/var/lib/server-deck-auth')
    auth_state.mkdir(mode=0o700)
    os.chown(auth_state, caddy.pw_uid, caddy.pw_gid)
    code = secrets.token_urlsafe(32)
    put(auth_state / 'bootstrap.json', json.dumps(dict(version=1, tokenHash=hashlib.sha256(code.encode()).hexdigest(), expiresAt=int(time.time()) + 3600, consumed=False)), uid=caddy.pw_uid, gid=caddy.pw_gid)
    gateway, auth_gateway = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    ip_mode = not bool(data['domain'])
    host = data['domain'] or data['publicIp']
    origin = 'https://' + host + (':' + str(data['httpsPort']) if ip_mode else '')
    metadata = dict(version=1, mode='ip' if ip_mode else 'domain', host=host, port=data['httpsPort'], origin=origin, email=data['email'], publicIp=data['publicIp'], publicPaths=sorted(set(public_paths)), managed=True, certificateName='' if ip_mode else 'server-deck')
    put(CONF / 'deployment.json', json.dumps(metadata, ensure_ascii=False, indent=2) + '\n')
    ssh_port = 22
    effective_ssh = subprocess.run(['/usr/sbin/sshd', '-T'], capture_output=True, text=True, timeout=10)
    if effective_ssh.returncode == 0:
        advertised = [line.split()[1] for line in effective_ssh.stdout.splitlines() if line.startswith('port ')]
        if advertised and advertised[0].isdigit() and 1 <= int(advertised[0]) <= 65535:
            ssh_port = int(advertised[0])
    connection_parts = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection_parts) == 4 and connection_parts[3].isdigit() and 1 <= int(connection_parts[3]) <= 65535:
        ssh_port = int(connection_parts[3])
    account_ready = loopback_helper(owner, 'account_helper', 'account_helper.py', ssh_port)
    app_env = 'DECK_PUBLIC_ORIGIN=' + origin + '\nDECK_GATEWAY_TOKEN=' + gateway + '\n'
    if account_ready:
        app_env += 'DECK_ACCOUNT_SSH_HOST=127.0.0.1\nDECK_ACCOUNT_SSH_KEY=account_helper\nDECK_ACCOUNT_SSH_PORT=' + str(ssh_port) + '\n'
    # Deployment helper inspect depends on the environment files below, so add
    # its forced-command key after they and the final Caddy config exist.
    put(CONF / 'server.env', app_env)
    put(CONF / 'auth.env', 'DECK_PUBLIC_ORIGIN=' + origin + '\nDECK_AUTH_GATEWAY=' + auth_gateway + '\nDECK_AUTH_STATE=/var/lib/server-deck-auth\nDECK_ACCOUNTS_FILE=' + str(accounts_path) + '\n')
    put(UNIT_DIR / 'server-deck.service', APP_UNIT, 0o644)
    put(UNIT_DIR / 'server-deck-auth.service', AUTH_UNIT, 0o644)
    put(UNIT_DIR / 'server-deck-certbot-renew.service', RENEW_SERVICE, 0o644)
    put(UNIT_DIR / 'server-deck-certbot-renew.timer', RENEW_TIMER, 0o644)
    caddy_config_path = pathlib.Path('/etc/caddy/Caddyfile')
    shutil.copy2(caddy_config_path, CONF / 'Caddyfile.package-default')
    tls = pathlib.Path('/etc/caddy/server-deck-tls')
    tls.mkdir(mode=0o750)
    os.chown(tls, 0, caddy.pw_gid)
    if not ip_mode:
        replace(caddy_config_path, bootstrap_caddy(data['domain']), gid=caddy.pw_gid)
        run(['caddy', 'validate', '--config', str(caddy_config_path), '--adapter', 'caddyfile'], private=True)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', 'caddy.service'])
        print('Получаю сертификат Certbot: домен и порт 80 должны быть доступны из интернета.')
        run(['certbot', 'certonly', '--webroot', '-w', str(acme), '-d', data['domain'], '--cert-name', 'server-deck', '--non-interactive', '--agree-tos', '--email', data['email']])
        lineage = pathlib.Path('/etc/letsencrypt/live/server-deck')
        for name in ('fullchain.pem', 'privkey.pem'):
            shutil.copyfile(lineage / name, tls / name)
            os.chown(tls / name, 0, caddy.pw_gid)
            (tls / name).chmod(0o640)
    else:
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-days', '365', '-nodes', '-keyout', str(tls / 'privkey.pem'), '-out', str(tls / 'fullchain.pem'), '-subj', '/CN=' + host, '-addext', 'subjectAltName=IP:' + host], private=True)
        for name in ('fullchain.pem', 'privkey.pem'):
            os.chown(tls / name, 0, caddy.pw_gid)
            (tls / name).chmod(0o640)
    # The hook remains ready in IP mode; the domain helper later changes the
    # selected certificateName. No CA request is made before a domain is set.
    hook = pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy/server-deck')
    put(hook, renew_hook(data['domain'] or 'deck.example.org'), 0o750)
    replace(caddy_config_path, caddy_config(host, gateway, auth_gateway, public_paths, port=data['httpsPort'], ip_mode=ip_mode), gid=caddy.pw_gid)
    run(['caddy', 'validate', '--config', str(caddy_config_path), '--adapter', 'caddyfile'], private=True)
    deploy_ready = loopback_helper(owner, 'deployment_helper', 'deployment_helper.py', ssh_port)
    if deploy_ready:
        with (CONF / 'server.env').open('a') as output:
            output.write('DECK_DEPLOYMENT_SSH_HOST=127.0.0.1\nDECK_DEPLOYMENT_SSH_KEY=deployment_helper\nDECK_DEPLOYMENT_SSH_PORT=' + str(ssh_port) + '\n')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'server-deck.service', 'server-deck-auth.service', 'caddy.service'])
    if not ip_mode:
        # Reload, never restart, the initial HTTP challenge service.
        run(['systemctl', 'reload', 'caddy.service'])
    run(['systemctl', 'enable', '--now', 'server-deck-certbot-renew.timer'])
    wait_http(8765, '/', 403, {'Host': host + (':' + str(data['httpsPort']) if ip_mode else '')})
    wait_http(8768, '/auth/setup', 200, {'X-Deck-Auth': auth_gateway})
    # Validate real public-facing TLS locally with the domain as SNI and Host.
    context = ssl.create_default_context(cafile=str(tls / 'fullchain.pem')) if ip_mode else ssl.create_default_context()
    connection = http.client.HTTPSConnection(host, data['httpsPort'], timeout=15)
    connection.sock = context.wrap_socket(socket.create_connection(('127.0.0.1', data['httpsPort']), timeout=10), server_hostname=host)
    connection.request('GET', '/login/')
    response = connection.getresponse()
    response.read()
    if response.status != 200:
        raise RuntimeError('HTTPS-страница входа не прошла проверку')
    connection.close()
    print('HTTPS готов. Реестр серверов пуст; учётную запись создайте при первом входе.')
    print('Адрес: ' + origin + '/login/')
    print('Одноразовый код первичной настройки (действует 1 час): ' + code)
    if ip_mode:
        print('IP-режим использует собственный сертификат: браузер покажет предупреждение. Сначала сверьте отпечаток сертификата через SSH; PWA и встроенные поддомены доступны после настройки доверенного HTTPS-домена.')
        result = run(['openssl', 'x509', '-in', str(tls / 'fullchain.pem'), '-noout', '-fingerprint', '-sha256'], private=True)
        print(result.stdout.strip())
    else:
        print('Для встроенных панелей добавьте wildcard DNS *.' + host + ' на этот VPS.')
    if not account_ready or not deploy_ready:
        print('Политика SSH запретила один из локальных root helper. SSH-настройки не менялись. Проверьте доступность смены пароля и настроек домена в панели; руководство содержит ручной путь через sudo.')
    print('Установщик не менял SSH-пароли, параметры AWG, MTProxyL и правила межсетевого экрана.')



def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--request', required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    request = pathlib.Path(args.request)
    try:
        if request.is_symlink() or request.stat().st_size > 8192:
            raise ValueError('Некорректный файл запроса')
        data = json.loads(request.read_text(encoding='utf-8'))
        request.unlink()  # Do not retain plaintext after reading, even if setup fails.
        validate_request(data)
        if not data['domain'] and data['httpsPort'] is None:
            data['httpsPort'] = free_https_port()
        source = pathlib.Path(args.source).resolve()
        paths = preflight(source, data)
        install(source, data, paths)
        return 0
    except Exception as error:
        print('Установка остановлена: ' + str(error), file=sys.stderr)
        print('Существующие службы не перезаписываются. При частичной новой установке проверьте journalctl -u server-deck -u server-deck-auth -u caddy; автоматического удаления/повтора нет.', file=sys.stderr)
        return 1
    finally:
        if request.is_file() and not request.is_symlink():
            request.unlink()


if __name__ == '__main__':
    raise SystemExit(main())
