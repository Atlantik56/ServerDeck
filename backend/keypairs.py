"""List Deck SSH identities and retire unused local key files safely."""
import base64
import binascii
import os
import re
import stat
import subprocess
import tempfile


KEY_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,159}')
PRIVATE_MARKER = re.compile(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----')
SERVICE_KEYS = {'account_helper', 'deployment_helper'}
MANAGED_TARGET = re.compile(rb'server-deck:([a-z_][a-z0-9_-]{0,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,252})(?::([0-9]{1,5}))?')


def reserved_names():
    return SERVICE_KEYS | {
        os.environ.get('DECK_ACCOUNT_SSH_KEY', ''),
        os.environ.get('DECK_DEPLOYMENT_SSH_KEY', ''),
    }


def valid_name(name):
    return (isinstance(name, str) and KEY_NAME.fullmatch(name) is not None and
            not name.endswith(('.pub', '-cert')) and
            not name.startswith(('known_hosts', 'authorized_keys', 'ssh_host_')) and
            name not in ('config', 'environment', 'rc'))


def directory_fd(directory):
    return os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def read_local_file(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Путь ключа не является обычным файлом.')
        return stream.read(limit), info


def private_file(directory, name):
    data, info = read_local_file(directory, name, 130)
    if not PRIVATE_MARKER.fullmatch(data.splitlines()[0] if data else b''):
        raise ValueError('Формат приватного SSH-ключа не распознан.')
    return info


def stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def key_stamp(directory, name):
    if not valid_name(name) or name in reserved_names():
        raise ValueError('Выберите приватный SSH-ключ из списка.')
    try:
        fd = directory_fd(directory)
        try:
            return stamp(private_file(fd, name))
        finally:
            os.close(fd)
    except OSError:
        raise ValueError('SSH-ключ отсутствует или недоступен.') from None


def safe_owner(info):
    return info.st_uid == os.geteuid() and info.st_nlink == 1


def public_file(directory, name):
    try:
        data, info = read_local_file(directory, name + '.pub', 32769)
    except FileNotFoundError:
        return None, None
    fields = data.split(None, 2)
    if len(data) > 32768 or len(fields) < 2 or not safe_owner(info):
        raise ValueError('Публичный файл ключа нельзя безопасно удалить.')
    return fields, info


def usage(servers, name):
    return [{field: server[field] for field in ('id', 'name', 'host', 'user', 'port')}
            for server in servers if server['key'] == name]


def created_for(public_fields):
    if not public_fields or len(public_fields) != 3 or public_fields[0] != b'ssh-ed25519':
        return None
    match = MANAGED_TARGET.fullmatch(public_fields[2].rstrip(b'\r\n'))
    if match is None:
        return None
    try:
        blob = base64.b64decode(public_fields[1], validate=True)
    except binascii.Error:
        return None
    if len(blob) != 51 or not blob.startswith(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'):
        return None
    user, host, raw_port = match.groups()
    target = dict(user=user.decode('ascii'), host=host.decode('ascii'))
    if raw_port is not None:
        port = int(raw_port)
        if not 1 <= port <= 65535:
            return None
        target['port'] = port
    return target


def inspect_keys(directory, servers, testing=()):
    try:
        fd = directory_fd(directory)
    except FileNotFoundError:
        return {'keys': [], 'items': []}
    keys, items = [], []
    try:
        for name in sorted(os.listdir(fd)):
            if not valid_name(name):
                continue
            try:
                info = private_file(fd, name)
            except (OSError, ValueError):
                continue
            used = usage(servers, name)
            reserved = name in reserved_names()
            if not reserved:
                keys.append(name)
            reason = ''
            if reserved:
                reason = 'Служебный ключ управления панелью.'
            elif used:
                reason = 'Ключ используется сервером.'
            elif name in testing:
                reason = 'Панель проверяет подключение с этим ключом.'
            elif not safe_owner(info):
                reason = 'У ключа другой владелец или есть жёсткие ссылки.'
            origin = None
            try:
                if not reserved:
                    fields, _ = public_file(fd, name)
                    origin = created_for(fields)
            except (OSError, ValueError):
                if not reason:
                    reason = 'Публичный файл ключа нельзя безопасно удалить.'
            item = dict(name=name, usedBy=used, removable=not reason, reason=reason)
            if origin is not None:
                item['createdFor'] = origin
            items.append(item)
        return {'keys': keys, 'items': items}
    finally:
        os.close(fd)


def remove_local_key(directory, name, servers, testing=()):
    if not valid_name(name) or name in reserved_names():
        raise ValueError('Этот SSH-ключ нельзя удалить из панели.')
    if usage(servers, name) or name in testing:
        raise ValueError('Ключ сейчас используется сервером или проверкой подключения.')
    fd = directory_fd(directory)
    try:
        private = private_file(fd, name)
        if not safe_owner(private):
            raise ValueError('Владелец или число ссылок приватного ключа не позволяет его удалить.')
        public, public_info = public_file(fd, name)
        try:
            with open(os.devnull, 'rb') as empty:
                result = subprocess.run(['ssh-keygen', '-y', '-P', '', '-f', str(directory / name)],
                                        stdin=empty, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError('Не удалось проверить формат и пару ключа перед удалением.') from None
        derived = result.stdout.split(None, 2)[:2]
        if result.returncode or len(derived) != 2 or (public is not None and derived != public[:2]):
            raise ValueError('Не удалось подтвердить приватный ключ или соответствие публичного файла.')

        files = {name: private}
        if public_info is not None:
            files[name + '.pub'] = public_info
        for filename, expected in files.items():
            actual = os.stat(filename, dir_fd=fd, follow_symlinks=False)
            if stamp(actual) != stamp(expected) or not safe_owner(actual) or not stat.S_ISREG(actual.st_mode):
                raise ValueError('Файлы ключа изменились во время проверки.')

        # Retire the pair together. If the second move fails, put the first back.
        quarantine = tempfile.mkdtemp(prefix='.retired-deck-key-', dir=directory)
        retired = directory_fd(quarantine)
        moved = []
        try:
            try:
                for filename in files:
                    os.rename(filename, filename, src_dir_fd=fd, dst_dir_fd=retired)
                    moved.append(filename)
            except OSError:
                for filename in reversed(moved):
                    os.rename(filename, filename, src_dir_fd=retired, dst_dir_fd=fd)
                raise
            for filename in files:
                os.unlink(filename, dir_fd=retired)
        finally:
            os.close(retired)
            try:
                os.rmdir(quarantine)
            except OSError:
                pass  # Preserve files for manual recovery on an incomplete local operation.
    except OSError:
        raise ValueError('Не удалось завершить удаление файлов ключа. Проверьте список ключей.') from None
    finally:
        os.close(fd)
