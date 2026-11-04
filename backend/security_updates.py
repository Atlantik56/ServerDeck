"""Read-only Ubuntu CVE publication watch. It never installs or sends messages."""
import concurrent.futures
import copy
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request

CVE = 'CVE-2026-98432'
SOURCE_URL = 'https://ubuntu.com/security/cves/' + CVE + '.json'
INTERVAL = 3600
STALE = 10800
CLOCK_SKEW = 60
MAX_BODY = 2 * 1024 * 1024
PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.\-]{0,127}')
VERSION = re.compile(r'[0-9][A-Za-z0-9.+:~\-]{0,199}')
KERNEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~\-]{0,119}')
STATUSES = {'released', 'pending', 'needed', 'not-affected', 'ignored', 'deferred', 'needs-triage', 'DNE'}


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def text(value, limit=200):
    return isinstance(value, str) and len(value) <= limit and all(c >= ' ' for c in value)


def valid_version(value):
    return isinstance(value, str) and VERSION.fullmatch(value) is not None


def same_abi(kernel, version):
    release = re.match(r'^(\d+\.\d+\.\d+-\d+)(-.+)$', kernel) if isinstance(kernel, str) else None
    source = re.match(r'^(?:[0-9]+:)?(\d+\.\d+\.\d+-\d+)\.', version) if isinstance(version, str) else None
    return bool(release and source and release.group(1) == source.group(1))


def clean_text(value, limit=200):
    return ''.join(char for char in str(value or '') if char >= ' ')[:limit]


def compare_versions(installed, fixed):
    """Return installed >= fixed using Debian ordering, or None if unverified."""
    if not valid_version(installed) or not valid_version(fixed):
        return None
    dpkg = shutil.which('dpkg')
    if not dpkg:
        return None
    try:
        value = subprocess.run([dpkg, '--compare-versions', installed, 'ge', fixed],
                               capture_output=True, timeout=5)
        return True if value.returncode == 0 else False if value.returncode == 1 else None
    except (OSError, subprocess.SubprocessError):
        return None


def validate_vendor(raw):
    if isinstance(raw, (bytes, str)):
        if len(raw) > MAX_BODY:
            raise ValueError('Ответ Ubuntu превышает допустимый размер.')
        raw = json.loads(raw)
    if not isinstance(raw, dict) or raw.get('id') != CVE or not isinstance(raw.get('packages'), list) or not 1 <= len(raw['packages']) <= 1000:
        raise ValueError('Не удалось проверить формат статуса Ubuntu.')
    rows = {}
    for package in raw['packages']:
        if (not isinstance(package, dict) or not isinstance(package.get('name'), str) or
                not PACKAGE.fullmatch(package['name']) or not isinstance(package.get('statuses'), list) or len(package['statuses']) > 100):
            raise ValueError('Не удалось проверить формат статуса Ubuntu.')
        for item in package['statuses']:
            if (not isinstance(item, dict) or item.get('status') not in STATUSES or
                    not isinstance(item.get('release_codename'), str) or not re.fullmatch(r'[a-z][a-z0-9\-]{0,63}', item['release_codename']) or
                    not text(item.get('description'), 2000)):
                raise ValueError('Не удалось проверить формат статуса Ubuntu.')
            key = package['name'] + '|' + item['release_codename']
            if key in rows:
                raise ValueError('Ubuntu вернула неоднозначные статусы исходного пакета.')
            if item['status'] == 'released' and item['release_codename'] != 'upstream' and not valid_version(item['description']):
                raise ValueError('Ubuntu не указала проверяемую версию выпущенного исправления.')
            rows[key] = {'status': item['status'], 'version': item['description']}
    return rows


def fetch_official():
    class FixedRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, new_url):
            raise ValueError('Перенаправление источника Ubuntu не разрешено.')

    request = urllib.request.Request(SOURCE_URL, headers={'Accept': 'application/json', 'User-Agent': 'Server-Deck-CVE-Watch/1'})
    with urllib.request.build_opener(FixedRedirect()).open(request, timeout=15) as response:
        if response.geturl() != SOURCE_URL:
            raise ValueError('Адрес источника Ubuntu изменился; требуется проверка.')
        body = response.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError('Ответ Ubuntu превышает допустимый размер.')
    return body


def binding(server):
    value = [str(server.get(k, '')) for k in ('id', 'host', 'user', 'port')]
    return hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest()


def base_row(server):
    return {'id': server['id'], 'name': clean_text(server.get('name') or server['id'], 100),
            'host': clean_text(server.get('host', ''), 253), 'ok': False, 'checkedAt': None,
            'kernel': None, 'sourcePackage': None, 'installedVersion': None,
            'fixedVersion': None, 'vendorStatus': None, 'state': 'unknown',
            'available': None, 'affected': None, 'message': 'Проверка ещё не завершена.', 'error': ''}


class SecurityUpdateWatch:
    def __init__(self, root, servers_fn, keydir, clock=time.time, fetch_fn=None, probe_fn=None):
        self.root = pathlib.Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.root / 'state.json'
        self.servers_fn, self.keydir, self.clock = servers_fn, pathlib.Path(keydir), clock
        self.fetch_fn, self.probe_fn = fetch_fn or fetch_official, probe_fn or self._probe
        self.lock = threading.RLock()
        self.checking = False
        self.worker = None
        self.state = {'version': 1, 'checkedAt': None, 'lastGoodAt': None, 'nextCheckAt': 0,
                      'lastRequestAt': None, 'error': '', 'fixedPublished': None, 'servers': {}, 'notices': {}}
        if self.path.exists():
            try:
                if self.path.stat().st_size > 4 * MAX_BODY:
                    raise ValueError()
                stored = json.loads(self.path.read_text())
                if (not isinstance(stored, dict) or set(stored) != set(self.state) or stored['version'] != 1 or
                        not all(stored[k] is None or finite(stored[k]) for k in ('checkedAt', 'lastGoodAt', 'lastRequestAt')) or
                        not finite(stored['nextCheckAt']) or not text(stored['error'], 500) or
                        stored['fixedPublished'] is not None and type(stored['fixedPublished']) is not bool or
                        not isinstance(stored['servers'], dict) or len(stored['servers']) > 256 or
                        not isinstance(stored['notices'], dict) or len(stored['notices']) > 512):
                    raise ValueError()
                for key, row in stored['servers'].items():
                    if (not isinstance(key, str) or not isinstance(row, dict) or not isinstance(row.get('data'), dict) or
                            not re.fullmatch(r'[a-f0-9]{64}', row.get('binding', '')) or
                            row.get('lastGoodAt') is not None and not finite(row['lastGoodAt'])):
                        raise ValueError()
                    data = row['data']
                    required = set(base_row({'id': key}))
                    if (not required <= set(data) or data['id'] != key or type(data['ok']) is not bool or
                            data['state'] not in ('awaiting_release', 'available', 'published', 'reboot_required', 'fixed', 'unknown', 'unsupported') or
                            data['checkedAt'] is not None and not finite(data['checkedAt']) or
                            any(data[k] is not None and type(data[k]) is not bool for k in ('available', 'affected')) or
                            not all(text(data[k], 1000) for k in ('name', 'host', 'message', 'error'))):
                        raise ValueError()
                for key, notice in stored['notices'].items():
                    if (not re.fullmatch(r'[a-f0-9]{64}', key) or not isinstance(notice, dict) or
                            notice.get('id') != key or not re.fullmatch(r'[a-f0-9]{64}', notice.get('binding', '')) or
                            not text(notice.get('title'), 200) or not text(notice.get('message'), 1000) or
                            not finite(notice.get('createdAt')) or type(notice.get('acknowledged')) is not bool):
                        raise ValueError()
                self.state = stored
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                self.state['error'] = 'Сохранённое состояние проверки повреждено; требуется новая проверка.'

    def _save(self):
        fd, name = tempfile.mkstemp(prefix='.security-updates-', dir=str(self.root))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as handle:
                json.dump(self.state, handle, ensure_ascii=False, separators=(',', ':'))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, self.path)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _servers(self):
        values = self.servers_fn()
        if not isinstance(values, list) or len(values) > 256:
            raise ValueError('Не удалось прочитать реестр серверов.')
        if any(not isinstance(s, dict) or not isinstance(s.get('id'), str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', s['id']) for s in values):
            raise ValueError('Не удалось прочитать реестр серверов.')
        if len({s['id'] for s in values}) != len(values):
            raise ValueError('Реестр содержит повторяющийся сервер.')
        return copy.deepcopy(values)

    def snapshot(self):
        registry = self._servers()
        now = self.clock()
        with self.lock:
            state = copy.deepcopy(self.state)
            checking = self.checking
        active = {binding(s) for s in registry}
        stale = bool(state['error']) or state['lastGoodAt'] is None or now - state['lastGoodAt'] > STALE
        rows = []
        for server in registry:
            stored = state['servers'].get(server['id'], {})
            row = copy.deepcopy(stored.get('data')) if stored.get('binding') == binding(server) else None
            row = row or base_row(server)
            row.update(name=clean_text(server.get('name') or server['id'], 100), host=clean_text(server.get('host', ''), 253))
            row_stale = stale or not row['ok'] or stored.get('lastGoodAt') is None or now - stored['lastGoodAt'] > STALE
            row['stale'] = row_stale
            if row_stale:
                row.update(ok=False, state='unknown', available=None, affected=None,
                           message='Нет свежих подтверждённых данных. Последние сведения сохранены.')
            rows.append(row)
        notices = [{k: v for k, v in notice.items() if k != 'binding'} for notice in state['notices'].values() if notice['binding'] in active]
        notices.sort(key=lambda notice: notice['createdAt'], reverse=True)
        return {'cve': CVE, 'checking': checking, 'checkedAt': state['checkedAt'], 'lastGoodAt': state['lastGoodAt'],
                'nextCheckAt': state['nextCheckAt'], 'staleAfterSeconds': STALE, 'stale': stale,
                'error': state['error'], 'sourceUrl': SOURCE_URL,
                'fixedPublished': None if stale else state['fixedPublished'], 'notices': notices, 'servers': rows}

    def request_check(self):
        self._start(manual=True)
        return self.snapshot()

    def _start(self, manual=False):
        now = self.clock()
        with self.lock:
            if self.checking:
                return False
            if manual and self.state['lastRequestAt'] is not None and now - self.state['lastRequestAt'] < 60:
                raise ValueError('Повторную проверку можно запускать не чаще раза в минуту.')
            self.checking = True
            if manual:
                self.state['lastRequestAt'] = now
            self.state['nextCheckAt'] = now + INTERVAL
            try:
                self._save()
            except Exception:
                self.checking = False
                raise ValueError('Не удалось сохранить состояние проверки.') from None
            self.worker = threading.Thread(target=self._check, name='ubuntu-cve-check', daemon=True)
            self.worker.start()
        return True

    def acknowledge(self, notice_id):
        if not isinstance(notice_id, str) or not re.fullmatch(r'[a-f0-9]{64}', notice_id):
            raise ValueError('Неверное уведомление.')
        active = {binding(s) for s in self._servers()}
        with self.lock:
            notice = self.state['notices'].get(notice_id)
            if not notice or notice['binding'] not in active:
                raise ValueError('Уведомление не найдено.')
            notice['acknowledged'] = True
            try:
                self._save()
            except Exception:
                notice['acknowledged'] = False
                raise ValueError('Не удалось сохранить подтверждение уведомления.') from None
        return self.snapshot()

    def _probe(self, server):
        host, user, port, key = server.get('host'), server.get('user'), server.get('port'), server.get('key')
        if not isinstance(host, str) or not 1 <= len(host) <= 253:
            raise ValueError('Неверные параметры SSH.')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?', host):
                raise ValueError('Неверные параметры SSH.')
        if (not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user) or
                type(port) is not int or not 1 <= port <= 65535 or not isinstance(key, str) or
                key in ('', '.', '..') or pathlib.Path(key).name != key):
            raise ValueError('Неверные параметры SSH.')
        key_path = (self.keydir / key).resolve()
        if key_path.parent != self.keydir.resolve():
            raise ValueError('Неверные параметры SSH.')
        source = pathlib.Path(__file__).with_name('security_updates_remote.py').read_text()
        args = ['ssh', '-i', str(key_path), '-p', str(port), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5',
                '-o', 'ServerAliveCountMax=2', user + '@' + host, 'python3 -']
        value = subprocess.run(args, input=source, capture_output=True, text=True, timeout=60)
        if value.returncode != 0 or len(value.stdout) > MAX_BODY:
            raise ValueError('SSH-проверка сведений ядра не завершена.')
        return json.loads(value.stdout)

    def _row(self, server, facts, vendor, now):
        row = base_row(server)
        row['checkedAt'] = now
        if not isinstance(facts, dict) or not isinstance(facts.get('os'), dict):
            raise ValueError('Не удалось проверить сведения ядра.')
        if not finite(facts.get('checkedAt')) or not -CLOCK_SKEW <= now - facts['checkedAt'] <= 300:
            raise ValueError('Нет свежих сведений об операционной системе.')
        if not isinstance(facts['os'].get('id'), str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', facts['os']['id']):
            raise ValueError('Не удалось проверить операционную систему.')
        if facts['os'].get('id') != 'ubuntu':
            row.update(ok=True, state='unsupported', message='Автоматическое сопоставление поддерживается только для Ubuntu.')
            return row
        kernel, modules, image = facts.get('kernel'), facts.get('runningModules'), facts.get('runningImage')
        codename = facts['os'].get('codename')
        if (facts.get('ok') is not True or not finite(facts.get('checkedAt')) or not -CLOCK_SKEW <= now - facts['checkedAt'] <= 300 or
                not isinstance(kernel, str) or not KERNEL.fullmatch(kernel) or not isinstance(modules, dict) or not isinstance(image, dict) or
                not isinstance(codename, str) or not re.fullmatch(r'[a-z][a-z0-9\-]{0,63}', codename)):
            raise ValueError('Не удалось проверить сведения запущенного ядра.')
        source, version = modules.get('source'), modules.get('sourceVersion')
        if (str(modules.get('package', '')).split(':', 1)[0] != 'linux-modules-' + kernel or
                str(image.get('package', '')).split(':', 1)[0] not in ('linux-image-' + kernel, 'linux-image-unsigned-' + kernel) or
                not isinstance(source, str) or not PACKAGE.fullmatch(source) or not valid_version(version) or not valid_version(image.get('version'))):
            raise ValueError('Не удалось подтвердить исходный пакет запущенного ядра.')
        row.update(ok=True, kernel=kernel, sourcePackage=source, installedVersion=version, releaseCodename=codename,
                   runningImage={k: clean_text(image.get(k), 200) for k in ('package', 'version', 'source', 'sourceVersion')},
                   runningModules={k: clean_text(modules.get(k), 200) for k in ('package', 'version', 'source', 'sourceVersion')})
        status = vendor.get(source + '|' + codename)
        if status is None:
            row.update(message='Ubuntu не указала статус для точного исходного пакета и выпуска.')
            return row
        row['vendorStatus'] = status['status']
        if status['status'] == 'not-affected':
            row.update(state='fixed', affected=False, message='Ubuntu отмечает этот исходный пакет как не затронутый.')
            return row
        if status['status'] != 'released':
            row.update(state='awaiting_release', affected=True if status['status'] in ('pending', 'needed') else None,
                       message='Выпущенное исправление Ubuntu пока не подтверждено. Версия в работе не считается доступной.')
            return row
        fixed = status['version']
        row.update(fixedVersion=fixed, state='published', message='Ubuntu опубликовала исправление. Проверьте APT: доступность пакетов на этом VPS ещё не подтверждена.')
        newer = compare_versions(version, fixed)
        row['affected'] = None  # Livepatch is not evaluated by this package watch.
        signature = facts.get('versionSignature', '')
        signature_tokens = signature.split() if isinstance(signature, str) else []
        # A newer installed package with the same ABI does not attest to bytes
        # already executing in memory. Require the Ubuntu running-build token.
        release_base = re.match(r'^(\d+\.\d+\.\d+-\d+)(-.+)$', kernel)
        running_confirmed = bool(release_base and same_abi(kernel, version) and len(signature_tokens) >= 2 and signature_tokens[0] == 'Ubuntu' and
                                 signature_tokens[1] == version + release_base.group(2) and image['version'] == version)
        if newer is True and running_confirmed:
            row.update(state='fixed', affected=False, message='Сигнатура работающей сборки Ubuntu соответствует исправленной версии пакета. Livepatch и побайтовая аттестация не проверялись.')
            return row
        installed = facts.get('installedKernels')
        if isinstance(installed, list):
            for candidate in installed[:256]:
                if (isinstance(candidate, dict) and candidate.get('sourcePackage') == source and
                        valid_version(candidate.get('sourceVersion')) and candidate.get('imageVersion') == candidate['sourceVersion'] and
                        isinstance(candidate.get('kernel'), str) and KERNEL.fullmatch(candidate['kernel']) and candidate['kernel'] != kernel and
                        same_abi(candidate['kernel'], candidate['sourceVersion']) and
                        str(candidate.get('imagePackage', '')).split(':', 1)[0] in ('linux-image-' + candidate['kernel'], 'linux-image-unsigned-' + candidate['kernel']) and
                        str(candidate.get('modulesPackage', '')).split(':', 1)[0] == 'linux-modules-' + candidate['kernel'] and
                        compare_versions(candidate['sourceVersion'], fixed) is True):
                    row.update(state='reboot_required', message='Исправленное ядро установлено на диске, но не запущено. Требуется отдельное согласованное обслуживание и перезагрузка; проверьте APT.')
                    break
        return row

    def _check(self):
        try:
            registry = self._servers()
            vendor = validate_vendor(self.fetch_fn())
            now = self.clock()
            with self.lock:
                old_rows = copy.deepcopy(self.state['servers'])
            def one(server):
                try:
                    return server, self._row(server, self.probe_fn(server), vendor, self.clock())
                except Exception:
                    prior = old_rows.get(server['id'], {})
                    row = copy.deepcopy(prior['data']) if prior.get('binding') == binding(server) else base_row(server)
                    row.update(checkedAt=self.clock(), error='Не удалось подтвердить сведения ядра по SSH.',
                               ok=False, state='unknown', affected=None, available=None,
                               message='Состояние исправления на этом VPS неизвестно; работающие службы не изменялись.')
                    return server, row
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                rows = list(pool.map(one, registry))
            with self.lock:
                before = copy.deepcopy(self.state)
                active = {binding(s) for s in registry}
                self.state['notices'] = {key: notice for key, notice in self.state['notices'].items() if notice['binding'] in active}
                self.state['servers'] = {s['id']: {'binding': binding(s), 'data': row,
                    'lastGoodAt': now if row['ok'] else old_rows.get(s['id'], {}).get('lastGoodAt')
                    if old_rows.get(s['id'], {}).get('binding') == binding(s) else None} for s, row in rows}
                released = False
                all_known = True
                for server, row in rows:
                    if not row['ok'] or row['vendorStatus'] is None:
                        all_known = False
                    if row['ok'] and row['vendorStatus'] == 'released':
                        released = True
                        if row['state'] != 'fixed':
                            identity = [CVE, binding(server), row['sourcePackage'], row['releaseCodename'], row['fixedVersion']]
                            notice_id = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()
                            self.state['notices'].setdefault(notice_id, {'id': notice_id, 'binding': binding(server),
                                'title': 'Ubuntu опубликовала исправление ' + CVE,
                                'message': row['name'] + ': ' + row['sourcePackage'] + ' ' + row['fixedVersion'] + '. ' + row['message'],
                                'createdAt': now, 'acknowledged': False})
                self.state['fixedPublished'] = True if released else False if all_known and rows else None
                self.state['notices'] = dict(sorted(self.state['notices'].items(), key=lambda item: item[1]['createdAt'], reverse=True)[:512])
                self.state.update(checkedAt=now, lastGoodAt=now, nextCheckAt=now + INTERVAL, error='')
                try:
                    self._save()
                except Exception:
                    self.state = before
                    raise
        except Exception:
            with self.lock:
                self.state.update(checkedAt=self.clock(), nextCheckAt=self.clock() + INTERVAL,
                                  error='Не удалось получить и проверить свежие сведения Ubuntu. Последние данные сохранены.')
                try:
                    self._save()
                except OSError:
                    pass
        finally:
            with self.lock:
                self.checking = False

    def run(self, stop_event):
        while not stop_event.is_set():
            with self.lock:
                due = self.clock() >= self.state['nextCheckAt'] and not self.checking
            if due:
                try:
                    self._start()
                except ValueError:
                    pass
            stop_event.wait(30)
