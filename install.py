#!/usr/bin/env python3
"""Interactive, secret-free launcher for a fresh Server Deck Linux controller.

Runs on Python 3.9+ on Windows, macOS and Linux. The service runs on a supported
Linux host; other operating systems use their OpenSSH client to provision it.
"""
import argparse
import ast
import io
import ipaddress
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

REPOSITORY = 'https://github.com/Atlantik56/ServerDeck'
ARCHIVE = 'https://codeload.github.com/Atlantik56/ServerDeck/tar.gz/refs/heads/main'
DOMAIN = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
USER = re.compile(r'[a-z_][a-z0-9_-]{0,31}')
ADMIN = re.compile(r'[A-Za-z0-9_.@-]{1,64}')
HOST = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}')
RUNTIME_SUFFIXES = {'.py', '.js', '.css', '.html', '.webmanifest', '.png', '.svg'}


def checked(value, pattern, label):
    if not pattern.fullmatch(value):
        raise ValueError('Неверное значение: ' + label)
    return value


def ask(value, prompt, default=None):
    if value is not None:
        return value
    answer = input(prompt + (' [' + str(default) + ']' if default is not None else '') + ': ').strip()
    return answer or default or ''


def public_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('Укажите публичный IPv4') from None
    if address.version != 4 or not address.is_global:
        raise ValueError('Укажите публичный IPv4')
    return str(address)


def config(args):
    mode = ask(args.mode, 'Где установить: ssh — Linux VPS, local — этот Linux', 'ssh')
    if mode not in ('ssh', 'local'):
        raise ValueError('Выберите ssh или local')
    if mode == 'local' and not sys.platform.startswith('linux'):
        raise ValueError('Локальный сервис поддерживает Linux. На этой ОС выберите ssh.')
    result = dict(mode=mode)
    default_ip = ''
    if mode == 'ssh':
        result['host'] = checked(ask(args.host, 'Адрес Linux VPS'), HOST, 'SSH-хост')
        result['user'] = checked(ask(args.user, 'SSH-пользователь', 'root'), USER, 'SSH-пользователь')
        result['port'] = int(ask(args.port, 'SSH-порт', 22))
        if not 1 <= result['port'] <= 65535:
            raise ValueError('Неверный SSH-порт')
        identity = ask(args.identity, 'Путь к приватному SSH-ключу (пусто — ssh-agent)', '')
        if identity:
            key = pathlib.Path(identity).expanduser().resolve()
            if not key.is_file():
                raise ValueError('SSH-ключ не найден')
            result['identity'] = str(key)
        try:
            default_ip = public_ip(result['host'])
        except ValueError:
            pass
    domain = ask(args.domain, 'Домен панели (пусто — HTTPS по IP и свободному порту)', '').lower()
    if domain:
        checked(domain, DOMAIN, 'домен')
    result['domain'] = domain
    result['publicIp'] = public_ip(ask(args.public_ip, 'Публичный IPv4 VPS', default_ip))
    result['email'] = ''
    if domain:
        result['email'] = ask(args.email, 'Email для Let’s Encrypt')
        if not re.fullmatch(r'[^\s@]{1,128}@[^\s@]{1,253}\.[^\s@]{2,63}', result['email']):
            raise ValueError('Укажите корректный email')
    result['httpsPort'] = 443 if domain else args.https_port
    if result['httpsPort'] is not None and not 1024 <= result['httpsPort'] <= 65535 and not domain:
        raise ValueError('IP HTTPS-порт должен быть от 1024 до 65535')
    return result


def source_files(root):
    root = pathlib.Path(root)
    required = ['server.py', 'web_auth.py', 'account_helper.py', 'static/index.html', 'pwa/login/index.html', 'installer/deploy_linux.py', 'installer/render.py', 'installer/reset_bootstrap.py', 'installer/reset_account.py']
    if any(not (root / p).is_file() or (root / p).is_symlink() for p in required):
        raise ValueError('Исходники неполные; нужен чистый публичный пакет ServerDeck')
    # Prevent accidental installation of an operator's private registry defaults.
    tree = ast.parse((root / 'server.py').read_text(encoding='utf-8'))
    defaults = [n.value for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'DEFAULTS' for t in n.targets)]
    if len(defaults) != 1 or not isinstance(defaults[0], (ast.List, ast.Tuple)) or defaults[0].elts:
        raise ValueError('Публичный пакет должен содержать DEFAULTS=[]; личные серверы переносить нельзя')
    selected = []
    for p in sorted(root.rglob('*')):
        rel = p.relative_to(root)
        if not p.is_file():
            continue
        allowed = (len(rel.parts) == 1 and p.suffix == '.py' and not p.name.startswith(('test_', 'check_', 'prepare_')) and p.name != 'install.py') or (rel.parts[0] in ('static', 'pwa') and p.suffix in RUNTIME_SUFFIXES) or rel.as_posix() in ('installer/deploy_linux.py', 'installer/render.py', 'installer/reset_bootstrap.py', 'installer/reset_account.py')
        if allowed:
            if p.is_symlink() or p.stat().st_size > 8 * 1024 * 1024:
                raise ValueError('Неподдерживаемый файл пакета: ' + str(rel))
            selected.append(rel)
    return selected


def extract_archive(data, destination):
    if len(data) > 32 * 1024 * 1024:
        raise ValueError('Архив слишком большой')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        total = 0
        for item in members:
            rel = pathlib.PurePosixPath(item.name)
            if rel.is_absolute() or '..' in rel.parts or not rel.parts or '\\' in item.name or ':' in item.name or not (item.isdir() or item.isfile()):
                raise ValueError('Небезопасный архив проекта')
            total += item.size
            if total > 96 * 1024 * 1024:
                raise ValueError('Распакованный проект слишком большой')
        for item in members:
            target = destination.joinpath(*pathlib.PurePosixPath(item.name).parts)
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as source:
                    target.write_bytes(source.read())
    roots = [p for p in destination.iterdir() if p.is_dir() and (p / 'server.py').is_file()]
    if len(roots) != 1:
        raise ValueError('Не найден корень проекта в архиве')
    return roots[0]


def get_source(args, temp):
    if args.source:
        return pathlib.Path(args.source).resolve()
    adjacent = pathlib.Path(__file__).resolve().parent
    if (adjacent / 'server.py').is_file():
        return adjacent
    print('Загружаю публичные исходники: ' + REPOSITORY)
    request = urllib.request.Request(ARCHIVE, headers={'User-Agent': 'ServerDeck-Installer/1'})
    with urllib.request.urlopen(request, timeout=45) as response:
        if not response.geturl().startswith('https://codeload.github.com/'):
            raise ValueError('Неожиданный адрес архива')
        data = response.read(32 * 1024 * 1024 + 1)
    return extract_archive(data, temp / 'download')


def run(command, **kwargs):
    subprocess.run(command, check=True, **kwargs)


def install_local(source, request_path):
    command = [sys.executable, str(source / 'installer/deploy_linux.py'), '--source', str(source), '--request', str(request_path)]
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        command = ['sudo', '--'] + command
    run(command)


def install_ssh(source, files, cfg, request_path, temp):
    if not shutil.which('ssh') or not shutil.which('scp'):
        raise ValueError('Установите клиент OpenSSH (ssh и scp) на этом компьютере')
    common = ['-p', str(cfg['port']), '-o', 'StrictHostKeyChecking=ask']
    scp_common = ['-P', str(cfg['port']), '-o', 'StrictHostKeyChecking=yes']
    if cfg.get('identity'):
        common += ['-i', cfg['identity'], '-o', 'IdentitiesOnly=yes']
        scp_common += ['-i', cfg['identity'], '-o', 'IdentitiesOnly=yes']
    target = cfg['user'] + '@' + cfg['host']
    # This first interactive connection leaves stdin free for SSH fingerprint/MFA.
    run(['ssh'] + common + [target, 'true'])
    common[common.index('StrictHostKeyChecking=ask')] = 'StrictHostKeyChecking=yes'
    if cfg['user'] != 'root':
        run(['ssh'] + common + [target, 'sudo -n true'])
    staged = subprocess.check_output(['ssh'] + common + [target, 'umask 077; mktemp -d /tmp/serverdeck-install.XXXXXXXX'], text=True).strip()
    if not re.fullmatch(r'/tmp/serverdeck-install\.[A-Za-z0-9]{8}', staged):
        raise ValueError('Не удалось создать защищённый каталог подготовки на VPS')
    try:
        bundle = temp / 'source.tar.gz'
        with tarfile.open(bundle, 'w:gz') as archive:
            for rel in files:
                archive.add(str(source / rel), arcname=str(rel).replace(os.sep, '/'), recursive=False)
        run(['scp'] + scp_common + [str(bundle), str(request_path), target + ':' + staged + '/'])
        command = 'tar -xzf ' + shlex.quote(staged + '/source.tar.gz') + ' -C ' + shlex.quote(staged)
        run(['ssh'] + common + [target, command])
        prefix = '' if cfg['user'] == 'root' else 'sudo -n -- '
        command = prefix + 'python3 ' + shlex.quote(staged + '/installer/deploy_linux.py') + ' --source ' + shlex.quote(staged) + ' --request ' + shlex.quote(staged + '/request.json')
        run(['ssh'] + common + [target, command])
    finally:
        subprocess.run(['ssh'] + common + [target, 'rm -rf -- ' + shlex.quote(staged)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('local', 'ssh'))
    for name in ('host', 'user', 'identity', 'domain', 'email', 'source', 'public-ip'):
        parser.add_argument('--' + name)
    parser.add_argument('--port', type=int)
    parser.add_argument('--https-port', type=int)
    parser.add_argument('--dry-run', action='store_true', help='Показать план, ничего не устанавливать и не загружать')
    parser.add_argument('--yes', action='store_true', help='Подтвердить план установки; учётная запись создаётся в браузере')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        cfg = config(args)
        print(json.dumps(dict(operation='fresh-install', config=cfg, linuxHosts=['Ubuntu 24.04', 'Debian 12'], packages=['python3', 'openssh-client', 'openssh-server', 'openssl', 'ca-certificates', 'caddy', 'certbot'], publicPorts=[80, 443] if cfg['domain'] else [cfg['httpsPort'] or 'random-free-high-port'], privatePorts=[8765, 8766, 8768], registry='empty', certificate='Certbot webroot + renewal timer' if cfg['domain'] else 'self-signed HTTPS; browser warning until a domain is configured', existingServices='abort on occupied ports or existing installation'), ensure_ascii=False, indent=2))
        if args.dry_run:
            return 0
        if not args.yes and input('Установить по этому плану на отдельный Linux-хост? [yes/нет]: ').strip().lower() != 'yes':
            print('Отменено.')
            return 0
        with tempfile.TemporaryDirectory(prefix='serverdeck-setup-') as name:
            temp = pathlib.Path(name)
            source = get_source(args, temp)
            files = source_files(source)
            req = {k: cfg[k] for k in ('domain', 'email', 'publicIp', 'httpsPort')}
            request_path = temp / 'request.json'
            request_path.write_text(json.dumps(req), encoding='utf-8')
            if os.name != 'nt':
                request_path.chmod(0o600)
            if cfg['mode'] == 'local':
                install_local(source, request_path)
            else:
                install_ssh(source, files, cfg, request_path, temp)
        print('Установка завершена. Откройте адрес и используйте одноразовый код выше для создания своей учётной записи в браузере.')
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        # Exception arguments from children never include secrets: all credentials
        # travel via a protected JSON file and SSH/SCP, never on their argv.
        print('Установка остановлена: ' + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nОтменено.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
