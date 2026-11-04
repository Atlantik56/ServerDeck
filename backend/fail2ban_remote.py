"""Narrow SSH-jail editor. Invoked over verified SSH; no shell or arbitrary paths."""
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import subprocess
import time

CONFIG = pathlib.Path('/etc/fail2ban')
MANAGED = CONFIG / 'jail.d/zzzz-server-deck.local'
STATE = pathlib.Path('/var/lib/server-deck')


def canonical_network(value):
    if not isinstance(value, str) or len(value) > 80 or '%' in value:
        raise ValueError('Укажите IP или CIDR без имени интерфейса')
    network = ipaddress.ip_network(value.strip(), strict=False)
    if network.prefixlen == 0:
        raise ValueError('Исключение всего интернета запрещено')
    # Broad exclusions disable the protection accidentally; existing ones are retained.
    if network.prefixlen < (8 if network.version == 4 else 32):
        raise ValueError('Слишком широкая сеть исключений: минимум /8 для IPv4 и /32 для IPv6')
    return str(network) if '/' in value else str(network.network_address)


def validate_settings(data):
    if not isinstance(data, dict) or set(data) != {'maxretry', 'findtime', 'bantime', 'ignoreip'}:
        raise ValueError('Допустимы maxretry, findtime, bantime и ignoreip')
    result = {}
    for key, low, high in [('maxretry', 3, 100), ('findtime', 60, 86400), ('bantime', 60, 2592000)]:
        value = data[key]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(key + ': допустимый диапазон ' + str(low) + '–' + str(high))
        result[key] = value
    if not isinstance(data['ignoreip'], list) or len(data['ignoreip']) > 64:
        raise ValueError('Допустимо не более 64 исключений')
    result['ignoreip'] = sorted(set(canonical_network(value) for value in data['ignoreip']))
    return result


def command(args, timeout=15):
    value = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=dict(os.environ, LC_ALL='C'))
    if value.returncode:
        # Never echo output: filters/actions/config may contain credentials or paths.
        raise RuntimeError('Команда проверки Fail2ban не завершена: ' + args[0] + ' (код ' + str(value.returncode) + ')')
    return value.stdout.strip()


def source_address():
    fields = os.environ.get('SSH_CONNECTION', '').split()
    if len(fields) != 4:
        raise ValueError('Не подтверждён IP SSH-подключения панели; применение запрещено')
    return str(ipaddress.ip_address(fields[0]))


def ignored_addresses(output):
    result = []
    for line in output.splitlines():
        line = line.strip().lstrip('|`- ').strip()
        if not line or line.startswith('These IP'):
            continue
        for token in line.split():
            try:
                if '%' in token:
                    raise ValueError()
                value = ipaddress.ip_network(token, strict=False)
                result.append(str(value) if '/' in token else str(value.network_address))
            except ValueError:
                raise ValueError('В действующих ignoreip есть значение, которое нельзя безопасно прочитать; редактирование остановлено')
    return sorted(set(result))


def config_revision(effective, ports, controller):
    files = []
    for path in sorted(CONFIG.rglob('*')):
        if path.is_file() and path.suffix in ('.conf', '.local'):
            if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError('Необычный файл конфигурации Fail2ban; нужна ручная проверка')
            files.append([str(path.relative_to(CONFIG)), hashlib.sha256(path.read_bytes()).hexdigest()])
    data = {'files': files, 'effective': effective, 'ports': ports, 'controller': controller}
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def inspect():
    installed = bool(shutil.which('fail2ban-client'))
    value = {'installed': installed, 'privileged': os.geteuid() == 0, 'checkedAt': time.time(), 'jail': 'sshd', 'editable': False}
    if not installed:
        value['message'] = 'Fail2ban не установлен. Установка доступна отдельным подтверждаемым действием в каталоге компонентов.'
        return value
    if not value['privileged']:
        value['message'] = 'Для проверки и применения требуется SSH-пользователь root.'
        return value
    command(['fail2ban-client', 'ping'])
    controller = source_address()
    status = command(['fail2ban-client', 'status'])
    line = next((line for line in status.splitlines() if 'Jail list:' in line), '')
    jails = sorted(filter(None, [word.strip() for word in line.partition('Jail list:')[2].split(',')]))
    value.update(jails=jails, controllerIp=controller)
    if 'sshd' not in jails:
        value['message'] = 'Активная jail sshd не найдена. Чтобы сохранить существующие правила, создание или замена другой SSH-jail автоматически не выполняется.'
        return value
    effective = {key: int(command(['fail2ban-client', 'get', 'sshd', key])) for key in ('maxretry', 'findtime', 'bantime')}
    effective['ignoreip'] = ignored_addresses(command(['fail2ban-client', 'get', 'sshd', 'ignoreip']))
    dump = command(['/usr/sbin/sshd', '-T'])
    ports = sorted(set(int(line.split()[1]) for line in dump.splitlines() if line.startswith('port ')))
    if not ports:
        raise ValueError('Не подтверждён порт SSH; применение запрещено')
    value.update(editable=True, effective=effective, sshPorts=ports, revision=config_revision(effective, ports, controller),
                 protectedIgnoreip=sorted(set(effective['ignoreip'] + [controller, '127.0.0.0/8', '::1'])),
                 message='Изменяется только jail sshd. Действующие исключения и IP подключения панели сохраняются.')
    return value


def dropin(settings, protected):
    settings = validate_settings(settings)
    ignored = sorted(set(settings['ignoreip'] + protected))
    return ('# Managed by Server Deck; only SSH jail thresholds.\n[sshd]\n'
            'maxretry = ' + str(settings['maxretry']) + '\nfindtime = ' + str(settings['findtime']) +
            '\nbantime = ' + str(settings['bantime']) + '\nignoreip = ' + ' '.join(ignored) + '\n'), ignored


def write_file(path, data, mode=0o600):
    temporary = path.with_name(path.name + '.deck-tmp')
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def apply(request):
    settings = validate_settings(request.get('settings'))
    expires = request.get('expiresAt')
    if isinstance(expires, bool) or not isinstance(expires, (int, float)) or not time.time() < expires <= time.time() + 305:
        raise ValueError('План истёк или имеет неверный срок')
    job = request.get('job', '')
    if not re.fullmatch('[0-9a-f]{32}', job):
        raise ValueError('Неверный идентификатор операции')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(STATE / 'mutation.lock', 'a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('На сервере выполняется другая операция')
        record = STATE / ('fail2ban-' + job + '.json')
        if record.exists():
            return json.loads(record.read_text())
        before = inspect()
        if not before.get('editable') or before.get('revision') != request.get('revision'):
            raise ValueError('Состояние Fail2ban или SSH изменилось; создайте новый план')
        if time.time() >= expires:
            raise ValueError('План истёк до применения')
        MANAGED.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if MANAGED.is_symlink():
            raise ValueError('Управляемый файл является ссылкой; применение запрещено')
        previous = MANAGED.read_bytes() if MANAGED.exists() else None
        previous_mode = MANAGED.stat().st_mode & 0o777 if previous is not None else 0o600
        backup = STATE / 'fail2ban-backups' / job
        backup.mkdir(mode=0o700, parents=True, exist_ok=False)
        if previous is not None: write_file(backup / 'managed.local', previous)
        write_file(backup / 'before.json', json.dumps(before, ensure_ascii=False).encode())
        content, ignored = dropin(settings, before['protectedIgnoreip'])
        write_file(record, json.dumps({'state': 'applying', 'backup': str(backup), 'job': job}).encode())
        wrote = False
        try:
            write_file(MANAGED, content.encode()); wrote = True
            command(['fail2ban-client', '-t'], timeout=25)
            # A jail reload keeps current bans; --restart, --unban and service restarts are never used.
            command(['fail2ban-client', 'reload', 'sshd'], timeout=30)
            after = inspect()
            expected = dict(settings, ignoreip=ignored)
            if not after.get('editable') or after.get('effective') != expected or after.get('sshPorts') != before['sshPorts']:
                raise RuntimeError('Новые параметры не подтверждены после reload')
            result = {'state': 'succeeded', 'job': job, 'backup': str(backup), 'after': after,
                      'message': 'Параметры jail sshd применены. SSH и VPN-службы не перезапускались; списки блокировок не очищались.'}
        except Exception:
            rolled_back = False
            if wrote:
                try:
                    if previous is None: MANAGED.unlink()
                    else: write_file(MANAGED, previous, previous_mode)
                    command(['fail2ban-client', '-t'], timeout=25)
                    command(['fail2ban-client', 'reload', 'sshd'], timeout=30)
                    restored = inspect()
                    rolled_back = restored.get('effective') == before.get('effective')
                except Exception: pass
            result = {'state': 'failed' if rolled_back else 'needs_review', 'job': job, 'backup': str(backup),
                      'rolledBack': rolled_back, 'error': 'Применение отклонено; прежние параметры восстановлены.' if rolled_back else
                      'Результат применения или отката не подтверждён. Нужна ручная проверка; повторная команда автоматически не отправляется.'}
        write_file(record, json.dumps(result, ensure_ascii=False).encode())
        return result


def dispatch(request):
    if request.get('op') == 'inspect': return inspect()
    if request.get('op') == 'apply': return apply(request)
    if request.get('op') == 'status':
        job = request.get('job', '')
        if not re.fullmatch('[0-9a-f]{32}', job): raise ValueError('Неверный идентификатор операции')
        path = STATE / ('fail2ban-' + job + '.json')
        value = json.loads(path.read_text()) if path.exists() else {'state': 'unknown'}
        value['mutationBusy'] = False
        lockpath = STATE / 'mutation.lock'
        if lockpath.exists():
            with open(lockpath, 'r') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(lock, fcntl.LOCK_UN)
                except BlockingIOError: value['mutationBusy'] = True
        return value
    raise ValueError('Неизвестное действие Fail2ban')


if __name__ == '__main__':
    try: print(json.dumps({'ok': True, 'data': dispatch(_DECK_REQUEST)}, ensure_ascii=False))
    except Exception as error: print(json.dumps({'ok': False, 'error': str(error)}, ensure_ascii=False))
