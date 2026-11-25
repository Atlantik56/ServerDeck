"""Root side of the fixed Server Deck release-update protocol."""

import fcntl
import importlib.util
import json
import os
import pathlib
import pwd
import re
import secrets
import signal
import stat
import time
from contextlib import contextmanager
from typing import NamedTuple
from urllib.parse import urlsplit


STATE = pathlib.Path('/var/lib/server-deck-release')
APP = pathlib.Path('/opt/server-deck')
WEB = pathlib.Path('/opt/server-deck-web')
HELPERS = pathlib.Path('/usr/local/lib/server-deck')
BACKEND_SERVICE = 'server-deck.service'
AUTH_SERVICE = 'server-deck-auth.service'
TERMINAL = {'succeeded', 'failed'}
ROOT_COPIES = {
    'web_auth.py': 0o644,
    'account_helper.py': 0o600,
    'deployment_helper.py': 0o600,
    'panel_release.py': 0o600,
    'panel_update_worker.py': 0o600,
}
FILE_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}')
FILE_LIMIT = 8 * 1024 * 1024
BACKUP_LIMIT = 96 * 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
ROOT_UID = 0
ROOT_GID = 0


class FileState(NamedTuple):
    body: bytes
    mode: int
    uid: int
    gid: int


class Target(NamedTuple):
    root: pathlib.Path
    parts: tuple[str, ...]
    uid: int
    gid: int
    mode: int
    dir_mode: int


def _root_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
        raise ValueError('Небезопасный каталог обновления панели.')


def _release_code():
    # The application directory is writable by the service user. The
    # privileged worker imports release verification only from the root copy.
    _root_directory(HELPERS)
    path = HELPERS / 'panel_release.py'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022 or info.st_nlink != 1:
        raise ValueError('Помощник проверки релизов требует настройки.')
    spec = importlib.util.spec_from_file_location('_server_deck_panel_release', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def _lock(path, *, wait=True):
    _root_directory(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CREAT, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022 or info.st_nlink != 1:
            raise ValueError('Небезопасный файл блокировки обновления.')
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def _published(deployment, name, value):
    deployment.atomic(STATE / name, json.dumps(value, ensure_ascii=False, sort_keys=True), mode=0o644)


def _receipt():
    try:
        return json.loads((STATE / 'job.json').read_text())
    except FileNotFoundError:
        return None


def _installed(releases):
    try:
        value = json.loads((STATE / 'installed.json').read_text())
        releases.version_key(value['version'])
        return value
    except (OSError, KeyError, TypeError, ValueError):
        raise ValueError('Для обновления установите исходную версию панели.') from None


def _upgrade_version(releases, requested):
    if releases.version_key(requested) <= releases.version_key(_installed(releases)['version']):
        raise ValueError('Запрашиваемая версия не новее установленной.')


def _unit_name(ident):
    return 'server-deck-panel-update-' + ident


def _control_file(name):
    user = pwd.getpwnam('serverdeck')
    return Target(APP, ('control-data', name), user.pw_uid, user.pw_gid, 0o600, 0o700)


def _check_freeze(ident, deployment):
    try:
        marker = _read(_control_file('deployment-freeze'))
        if marker and json.loads(marker.body).get('plan') == ident:
            return
    except (OSError, ValueError, AttributeError):
        pass
    raise deployment.DeploymentError('Блокировка обновления панели не подтверждена.')


def _release_freeze(ident):
    target = _control_file('deployment-freeze')
    marker = _read(target)
    if marker is not None:
        if json.loads(marker.body).get('plan') != ident:
            raise ValueError('Блокировка обновления панели изменилась.')
        _put(target, marker, None)


def _check_no_active_jobs(deployment):
    try:
        current = _read(_control_file('jobs.json'))
        jobs = json.loads(current.body) if current else {}
        active = any(job.get('state') not in ('succeeded', 'failed', 'needs_review', 'reviewed')
                     for job in jobs.values())
    except (OSError, ValueError, AttributeError):
        raise deployment.DeploymentError('Не удалось проверить выполняющиеся задачи панели.') from None
    if active:
        raise deployment.DeploymentError('Дождитесь завершения остальных задач панели.')


def submit(request, deployment):
    """Queue exactly one confirmed version through the restricted root helper."""
    if not isinstance(request, dict):
        raise deployment.DeploymentError('Неверный запрос обновления Server Deck.')
    ident = request.get('requestId')
    version = request.get('version')
    if (set(request) != {'action', 'version', 'requestId'}
            or request.get('action') != 'panel-update'
            or not isinstance(ident, str) or not deployment.ID.fullmatch(ident)
            or not isinstance(version, str)):
        raise deployment.DeploymentError('Неверный запрос обновления Server Deck.')
    try:
        _root_directory(STATE)
        releases = _release_code()
        _upgrade_version(releases, version)
        with _lock(STATE / 'receipt.lock'):
            previous = _receipt()
            if previous and (previous['id'] == ident or previous['state'] not in TERMINAL):
                raise deployment.DeploymentError('Задача обновления уже зарегистрирована.')
            _check_no_active_jobs(deployment)
            _check_freeze(ident, deployment)
            job = {'id': ident, 'version': version, 'state': 'queued', 'stage': 'queued',
                   'createdAt': time.time(), 'error': ''}
            _published(deployment, 'job.json', job)
    except ValueError as error:
        raise deployment.DeploymentError(str(error)) from None
    except OSError:
        raise deployment.DeploymentError('Не удалось подготовить обновление Server Deck.') from None

    unit = _unit_name(ident)
    try:
        deployment.run(['/usr/bin/systemd-run', '--quiet', '--no-block', '--unit=' + unit, '--collect',
                        '--property=Type=oneshot', '--property=TimeoutStartSec=600s',
                        '/usr/bin/python3', '-I', str(deployment.CODE), '--panel-worker', ident], timeout=15)
    except Exception as error:
        # A lost systemd reply is not proof that the worker never started.
        missing = False
        if isinstance(error, deployment.DeploymentError):
            try:
                check = deployment.run(['/usr/bin/systemctl', 'show', unit + '.service',
                                        '--property=LoadState', '--value'], timeout=5, check=False)
                missing = check.returncode == 0 and check.stdout.strip() == 'not-found'
            except Exception:
                pass
        with _lock(STATE / 'receipt.lock'):
            current = _receipt()
            if current and current['id'] == ident and current['state'] != 'queued':
                return {'accepted': True, 'job': current}
            if missing:
                job.update(state='failed', stage='error', finishedAt=time.time(),
                           error='systemd отклонил запуск обновления панели.')
                _published(deployment, 'job.json', job)
                _release_freeze(ident)
                raise deployment.DeploymentError(job['error']) from None
            job.update(state='needs_review', stage='submit_uncertain',
                       error='Не удалось подтвердить запуск. Повтор требует проверки.')
            _published(deployment, 'job.json', job)
            return {'accepted': True, 'job': job}
    return {'accepted': True, 'job': _receipt() or job}


def _targets(files, public_paths, user):
    result = {}
    for name, body in files.items():
        parts = tuple(name.split('/'))
        if any(not FILE_NAME.fullmatch(part) for part in parts):
            raise ValueError('Небезопасный путь в архиве панели.')
        if parts[0] == 'backend' and len(parts) == 2 and parts[1].endswith('.py'):
            installed = parts[1:]
        elif len(parts) >= 3 and parts[0] == 'frontend' and parts[1] in ('static', 'pwa'):
            installed = parts[1:]
        else:
            raise ValueError('Неизвестный файл релиза Server Deck.')
        result[Target(APP, installed, user.pw_uid, user.pw_gid, 0o600, 0o700)] = body
        if installed[0] == 'pwa':
            if '/' + '/'.join(installed[1:]) not in public_paths:
                raise ValueError('Релиз требует обновить маршруты публичных ресурсов панели.')
            result[Target(WEB, installed[1:], ROOT_UID, ROOT_GID, 0o644, 0o755)] = body
        if parts[0] == 'backend' and installed[0] in ROOT_COPIES:
            result[Target(HELPERS, installed, ROOT_UID, ROOT_GID, ROOT_COPIES[installed[0]], 0o755)] = body
    return result


@contextmanager
def _directory(target, *, create=False):
    # Root never follows an application-owned symlink, including intermediate
    # directories. Replacement and backup reads use the same directory fd.
    fd = os.open(target.root, DIR_FLAGS)
    try:
        for part in ('', *target.parts[:-1]):
            if part:
                try:
                    child = os.open(part, DIR_FLAGS, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, mode=target.dir_mode, dir_fd=fd)
                    child = os.open(part, DIR_FLAGS, dir_fd=fd)
                    try:
                        os.fchown(child, target.uid, target.gid)
                        os.fchmod(child, target.dir_mode)
                        os.fsync(fd)
                    except Exception:
                        os.close(child)
                        raise
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if info.st_uid not in (ROOT_UID, target.uid) or info.st_mode & 0o022:
                raise ValueError('Небезопасный каталог файлов панели.')
        yield fd
    finally:
        os.close(fd)


def _read_at(fd, name, target):
    try:
        # O_NONBLOCK also avoids waiting on an unexpected FIFO.
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None
    with os.fdopen(source, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid not in (ROOT_UID, target.uid) or info.st_mode & 0o7022
                or info.st_size > FILE_LIMIT):
            raise ValueError('Небезопасный файл в каталоге установки.')
        body = stream.read(FILE_LIMIT + 1)
        after = os.fstat(stream.fileno())
        if len(body) > FILE_LIMIT or (info.st_mtime_ns, info.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Файл панели изменился при проверке.')
    return FileState(body, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)


def _read(target):
    try:
        with _directory(target) as fd:
            return _read_at(fd, target.parts[-1], target)
    except FileNotFoundError:
        return None


def _put(target, expected, replacement):
    name = target.parts[-1]
    with _directory(target, create=replacement is not None) as fd:
        if _read_at(fd, name, target) != expected:
            raise ValueError('Файл панели изменился во время обновления.')
        if replacement is None:
            os.unlink(name, dir_fd=fd)
        else:
            tmp = '.panel-update-' + secrets.token_hex(12)
            output = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                with os.fdopen(output, 'wb') as stream:
                    stream.write(replacement.body)
                    stream.flush()
                    os.fchown(stream.fileno(), replacement.uid, replacement.gid)
                    os.fchmod(stream.fileno(), replacement.mode)
                    os.fsync(stream.fileno())
                os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
            finally:
                try:
                    os.unlink(tmp, dir_fd=fd)
                except FileNotFoundError:
                    pass
        os.fsync(fd)


def _backup(deployment, directory, targets, installed):
    originals = {}
    backup_paths = []
    size = 0
    directory.mkdir(mode=0o700)
    (directory / 'files').mkdir(mode=0o700)
    for index, target in enumerate(targets):
        previous = _read(target)
        originals[target] = previous
        entry = {'path': str(target.root.joinpath(*target.parts)), 'file': None}
        if previous:
            size += len(previous.body)
            if size > BACKUP_LIMIT:
                raise ValueError('Прежние файлы панели слишком велики для резервной копии.')
            entry.update(file='files/' + str(index), mode=previous.mode, uid=previous.uid, gid=previous.gid)
            deployment.atomic(directory / entry['file'], previous.body)
        backup_paths.append(entry)
    deployment.atomic(directory / 'before.json',
                      json.dumps({'installed': installed, 'paths': backup_paths}, ensure_ascii=False))
    return originals


def _verify(deployment, origin, gateway, auth_gateway):
    for _ in range(12):
        try:
            deployment.verify_services(origin, gateway, auth_gateway)
            return
        except (OSError, ValueError):
            time.sleep(1)
    raise ValueError('Панель или служба входа не ответили после обновления.')


def _services(deployment, action, units):
    deployment.run(['/usr/bin/systemctl', action, *units], timeout=45)


def _interrupted(signum, frame):
    raise RuntimeError('Обновление панели прервано.')


def run_worker(ident, deployment):
    if not deployment.ID.fullmatch(ident):
        raise deployment.DeploymentError('Неверный идентификатор обновления.')
    _root_directory(STATE)

    def stage(name, **fields):
        job.update(stage=name, **fields)
        with _lock(STATE / 'receipt.lock'):
            _published(deployment, 'job.json', job)

    with _lock(STATE / 'receipt.lock'):
        job = _receipt()
        if (not job or job['id'] != ident or job['stage'] not in ('queued', 'submit_uncertain')
                or job['state'] not in ('queued', 'needs_review')):
            raise deployment.DeploymentError('Задача не ожидает запуска.')
        job.update(stage='preflight', state='running', error='', startedAt=time.time())
        _published(deployment, 'job.json', job)
    try:
        deployment.MUTATION_LOCK.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with _lock(deployment.MUTATION_LOCK, wait=False):
            handler = signal.signal(signal.SIGTERM, _interrupted)
            try:
                _run_transaction(stage, job, deployment)
            finally:
                signal.signal(signal.SIGTERM, handler)
    except BlockingIOError:
        stage('error', state='failed', finishedAt=time.time(), error='На сервере выполняется другая операция.')
    except (OSError, ValueError):
        stage('error', state='failed', finishedAt=time.time(), error='Не удалось подготовить обновление панели.')
    if job['state'] in TERMINAL:
        try:
            _release_freeze(ident)
        except (OSError, ValueError, AttributeError):
            stage('error', state='needs_review', finishedAt=time.time(),
                  error='Обновление завершено, но блокировка требует проверки по SSH.')


def _run_transaction(stage, job, deployment):
    switched = []
    stopped = False
    marker_started = False
    try:
        _check_freeze(job['id'], deployment)
        _check_no_active_jobs(deployment)
        releases = _release_code()
        installed = _installed(releases)
        _upgrade_version(releases, job['version'])
        config = deployment.load_configuration()
        origin = urlsplit(config['origin']).netloc
        gateway = deployment.read_env(deployment.APP_ENV).get('DECK_GATEWAY_TOKEN', '')
        auth_gateway = deployment.read_env(deployment.AUTH_ENV).get('DECK_AUTH_GATEWAY', '')
        if not deployment.SECRET.fullmatch(gateway) or not deployment.SECRET.fullmatch(auth_gateway):
            raise ValueError('Параметры защищённого шлюза требуют проверки.')
        stage('download')
        release = releases.fetch_latest()
        if not release or release['version'] != job['version']:
            raise ValueError('Набор опубликованных версий изменился. Проверьте обновления снова.')
        archive = releases.download_bundle(release)
        manifest, files = releases.unpack_bundle(archive, job['version'])
        user = pwd.getpwnam('serverdeck')
        targets = _targets(files, config['publicPaths'], user)
        stage('backup')
        (STATE / 'backups').mkdir(mode=0o700, exist_ok=True)
        _root_directory(STATE / 'backups')
        backup_dir = STATE / 'backups' / job['id']
        saved = _backup(deployment, backup_dir, targets, installed)
        replacements = {}
        for target, body in targets.items():
            previous = saved[target]
            if previous and previous.body == body:
                continue
            metadata = previous[1:] if previous else (target.mode, target.uid, target.gid)
            replacements[target] = FileState(body, *metadata)
        restart_auth = any(target.root == HELPERS and target.parts == ('web_auth.py',) for target in replacements)
        units = [AUTH_SERVICE, BACKEND_SERVICE] if restart_auth else [BACKEND_SERVICE]
        _check_no_active_jobs(deployment)
        _check_freeze(job['id'], deployment)
        stage('switch')
        stopped = True
        _services(deployment, 'stop', units)
        for target, replacement in replacements.items():
            switched.append(target)
            _put(target, saved[target], replacement)
        for target, replacement in replacements.items():
            if _read(target) != replacement:
                raise ValueError('Файлы установленной панели не прошли проверку.')
        _services(deployment, 'start', units)
        stage('verify')
        _verify(deployment, origin, gateway, auth_gateway)
        marker_started = True
        _published(deployment, 'installed.json', {key: manifest[key] for key in ('version', 'revision')})
        stage('complete', state='succeeded', finishedAt=time.time(), error='')
    except Exception as error:
        if stopped:
            try:
                stage('rollback')
                _services(deployment, 'stop', units)
                for target in reversed(switched):
                    current = _read(target)
                    if current != saved[target]:
                        _put(target, replacements[target], saved[target])
                if marker_started:
                    _published(deployment, 'installed.json', installed)
                _services(deployment, 'start', units)
                _verify(deployment, origin, gateway, auth_gateway)
            except Exception:
                stage('error', state='needs_review', finishedAt=time.time(),
                      error='Не удалось подтвердить откат файлов панели. Требуется проверка по SSH.')
                return
            message = 'Обновление не прошло проверку. Прежняя версия панели восстановлена.'
        else:
            message = str(error) if isinstance(error, ValueError) else 'Обновление не подготовлено. Файлы панели сохранены.'
        stage('error', state='failed', finishedAt=time.time(), error=message)
