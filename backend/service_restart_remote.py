"""One-target restarts: previews are read-only; durable workers never retry."""
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time

RS_UNIT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,180}\.service')
RS_DOCKER = re.compile(r'docker:([a-f0-9]{12,64})')
RS_MANAGED_DOCKER = ('amnezia-', 'mtproxy', 'telemt')
RS_CORE = re.compile(r'ssh|server[-_]?deck|ssh[-_]?guard|defen[cs]e|firewall|nft|iptables|ip6tables|fail2ban|firewalld|ufw|network|resolved|containerd|dockerd|docker\.service|systemd-|dbus|polkit|connman|wicked', re.I)
RS_PROTECTED = ('/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d', '/etc/nftables.conf', '/etc/fail2ban/jail.local',
                '/etc/fail2ban/jail.d', '/etc/server-deck/ssh-guard.json', '/etc/amnezia/amneziawg', '/etc/wireguard')
RS_MONITORED = ('ssh.service', 'sshd.service', 'server-deck.service', 'server-deck-auth.service',
                'server-deck-ssh-guard.service', 'fail2ban.service')
RS_DONE = ('succeeded', 'failed', 'needs_review')


def restart_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def restart_awg_digest(config):
    blocks = []; current = []
    for line in config.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        if line.startswith('['):
            if current: blocks.append(sorted(current))
            current = [line]; continue
        key, separator, value = line.partition('=')
        key = key.strip(); value = value.strip()
        if key == 'Endpoint': continue
        if key == 'AllowedIPs': value = ','.join(sorted(x.strip() for x in value.split(',')))
        current.append(key + ('=' + value if separator else ''))
    if current: blocks.append(sorted(current))
    return restart_digest(sorted(blocks))


def restart_guard_digest(value):
    def clean(item):
        if isinstance(item, list):
            return [clean(part) for part in item if not isinstance(part, dict) or not ({'metainfo', 'element'} & set(part))]
        if isinstance(item, dict):
            result = {}
            for key, part in item.items():
                if key in ('handle', 'metainfo'): continue
                if key == 'counter' and isinstance(part, dict): result[key] = {k: clean(v) for k, v in part.items() if k not in ('packets', 'bytes')}
                elif key == 'set' and isinstance(part, dict): result[key] = clean({k: v for k, v in part.items() if k != 'elem'})
                else: result[key] = clean(part)
            return result
        return item
    return restart_digest(clean(value))


def validate_restart_target(unit, services):
    if not isinstance(services, list) or len(services) > 150 or any(not isinstance(x, str) or not (RS_UNIT.fullmatch(x) or RS_DOCKER.fullmatch(x)) for x in services):
        raise ValueError('Неверный список зарегистрированных служб')
    if not isinstance(unit, str) or not (RS_UNIT.fullmatch(unit) or RS_DOCKER.fullmatch(unit)):
        raise ValueError('Неверная служба для перезапуска')
    if RS_DOCKER.fullmatch(unit):
        return 'docker'
    if unit not in services:
        raise ValueError('Служба не зарегистрирована на этом сервере')
    if RS_CORE.search(unit):
        raise ValueError('SSH, сеть, защита и службы управления не перезапускаются этой командой')
    return 'service'


def restart_preservation(before, after):
    """Compare only observed identities/configuration, never counters or traffic."""
    target = before['target']; kind = target['kind']; unit = target['unit']
    current = after.get('target', {})
    changed = current.get('active') and current.get('identity') == target.get('identity') and any(
        current.get(k) and current.get(k) != target.get(k) for k in ('invocation', 'startedAt', 'pid'))
    violations = []
    if before['bootId'] != after.get('bootId'): violations.append('Загрузка ОС изменилась без команды reboot')
    if before['configHashes'] != after.get('configHashes'): violations.append('Изменились защищённые конфигурации')
    if before.get('safety') != after.get('safety'): violations.append('Изменились forwarding или правила SSH-защиты в ядре')
    if kind == 'docker':
        if any(target.get(k) != current.get(k) for k in ('identity', 'name', 'image')): violations.append('Изменилась идентичность выбранного контейнера')
        if target.get('awg') != current.get('awg'): violations.append('Изменилась конфигурация AWG внутри выбранного контейнера')
    for name, value in before['services'].items():
        if kind == 'service' and (name == unit or value.get('Id') == target.get('identity')) or value.get('ActiveState') != 'active': continue
        if value != after.get('services', {}).get(name): violations.append('Другая служба изменилась: ' + name)
    for identity, value in before['containers'].items():
        if kind == 'docker' and identity == target['identity']: continue
        if value != after.get('containers', {}).get(identity): violations.append('Другой контейнер изменился: ' + value['name'])
    selected_awg = re.fullmatch(r'awg-quick@([A-Za-z0-9_.-]+)\.service', target['identity']) if kind == 'service' else None
    if set(before['awg']) != set(after.get('awg', {})): violations.append('Изменился состав интерфейсов AWG')
    for name, value in before['awg'].items():
        current_awg = after.get('awg', {}).get(name)
        expected = dict(value)
        if selected_awg and name == selected_awg.group(1) and current_awg:
            expected['ifindex'] = current_awg['ifindex']
        if expected != current_awg: violations.append('Интерфейс AWG изменился: ' + name)
    return bool(changed), violations


class RemoteServiceRestart:
    def __init__(self, state):
        self.state = pathlib.Path(state)

    def _run(self, args, timeout=15, check=True):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=dict(os.environ, LC_ALL='C'))
        if check and result.returncode:
            raise ValueError('Не удалось прочитать состояние ' + args[0])
        return result

    def _platform(self):
        if os.geteuid() != 0 or not pathlib.Path('/run/systemd/system').is_dir() or not shutil.which('systemctl') or not shutil.which('systemd-run'):
            raise ValueError('Перезапуск поддерживается через root SSH на Linux с systemd')

    def _service(self, unit):
        props = 'Id,Names,LoadState,ActiveState,SubState,MainPID,ActiveEnterTimestampMonotonic,ExecMainStartTimestampMonotonic,InvocationID,FragmentPath'
        result = self._run(['systemctl', 'show', '--property=' + props, '--', unit], check=False)
        value = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if not value.get('LoadState'): raise ValueError('Не удалось прочитать службу: ' + unit)
        return {k: value.get(k, '') for k in props.split(',')}

    @staticmethod
    def _safe_service_target(unit, state):
        identity = state.get('Id')
        if not identity or not RS_UNIT.fullmatch(identity): raise ValueError('Не подтверждено каноническое имя службы')
        names = [unit, identity] + state.get('Names', '').split()
        fragment = state.get('FragmentPath')
        if fragment: names.append(pathlib.Path(fragment).resolve().name)
        if any(RS_CORE.search(name) for name in names):
            raise ValueError('Псевдоним указывает на SSH, сеть, защиту или службу управления')
        return identity

    def _container(self, identity):
        template = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"state":{{json .State}}}'
        result = self._run(['docker', 'inspect', '--format', template, '--', identity])
        value = json.loads(result.stdout)
        state = value['state']; canonical = value['id']; name = value['name'].lstrip('/')
        if not re.fullmatch(r'[a-f0-9]{64}', canonical): raise ValueError('Docker не подтвердил идентичность контейнера')
        return {'id': canonical, 'name': name, 'image': value['image'], 'active': state.get('Running') is True and state.get('Status') == 'running' and not state.get('Paused'),
                'pid': str(state.get('Pid', 0)), 'startedAt': state.get('StartedAt', ''),
                'health': state.get('Health', {}).get('Status', '')}

    def _containers(self):
        if not shutil.which('docker'): return {}
        ids = self._run(['docker', 'ps', '--no-trunc', '-q']).stdout.split()
        if len(ids) > 200: raise ValueError('Слишком много контейнеров для безопасной проверки')
        result = {}
        for identity in ids:
            value = self._container(identity)
            if value['name'].lower().startswith('amnezia-awg'):
                value['awg'] = self._container_awg(value)
            result[value['id']] = value
        return result

    def _container_awg(self, container):
        identity = container['id']
        interfaces = self._run(['docker', 'exec', '--', identity, 'awg', 'show', 'interfaces'], timeout=15).stdout.split()
        if not interfaces or len(interfaces) > 100: raise ValueError('Интерфейсы AWG внутри контейнера не подтверждены')
        result = {}
        for name in interfaces:
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}', name): raise ValueError('Неверный интерфейс AWG контейнера')
            config = self._run(['docker', 'exec', '--', identity, 'awg', 'showconf', name], timeout=15).stdout
            if '[Interface]' not in config: raise ValueError('Конфигурация AWG контейнера не подтверждена')
            result[name] = restart_awg_digest(config)
        return result

    def _awg(self):
        if not shutil.which('awg'): return {}
        interfaces = self._run(['awg', 'show', 'interfaces'], timeout=10).stdout.split()
        if len(interfaces) > 100: raise ValueError('Слишком много интерфейсов AWG')
        values = {}
        for name in interfaces:
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}', name): raise ValueError('Неверное имя AWG-интерфейса')
            # Only the digest leaves this process. Roaming endpoints and all
            # runtime traffic counters are excluded from the revision.
            config = self._run(['awg', 'showconf', name], timeout=10).stdout
            values[name] = {'ifindex': int(pathlib.Path('/sys/class/net', name, 'ifindex').read_text()),
                            'configHash': restart_awg_digest(config)}
        return values

    def _config_hashes(self, services):
        paths = []
        for name in RS_PROTECTED:
            path = pathlib.Path(name)
            if path.is_file(): paths.append(path)
            elif path.is_dir(): paths.extend(p for p in path.rglob('*') if p.is_file())
        paths.extend(pathlib.Path(v['FragmentPath']) for v in services.values() if v.get('FragmentPath'))
        paths = sorted(set(paths))
        if len(paths) > 300: raise ValueError('Слишком много конфигураций для безопасной проверки')
        result = {}
        for path in paths:
            if path.stat().st_size > 4 * 1024 * 1024: raise ValueError('Защищённая конфигурация слишком большая')
            result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        return result

    def _apt_busy(self):
        busy = []
        for name in ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock', '/var/lib/apt/lists/lock', '/var/cache/apt/archives/lock'):
            if not pathlib.Path(name).exists(): continue
            with open(name, 'r+') as handle:
                try: fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: busy.append(name)
                else: fcntl.lockf(handle, fcntl.LOCK_UN)
        return busy

    def _runtime_safety(self):
        forwarding = {}
        for name in ('/proc/sys/net/ipv4/ip_forward', '/proc/sys/net/ipv6/conf/all/forwarding'):
            path = pathlib.Path(name)
            forwarding[name] = path.read_text().strip() if path.exists() else None
        guard = {'available': bool(shutil.which('nft')), 'present': False, 'structureHash': None}
        if guard['available']:
            response = self._run(['nft', '-j', 'list', 'table', 'inet', 'server_deck_ssh_guard'], check=False)
            if response.returncode == 0:
                guard.update(present=True, structureHash=restart_guard_digest(json.loads(response.stdout)))
        return {'forwarding': forwarding, 'sshGuard': guard}

    def _collect(self, req, target_required=True):
        self._platform(); services = req.get('services', [])
        unit = req.get('unit')
        if not isinstance(services, list) or len(services) > 150 or any(not isinstance(x, str) or not (RS_UNIT.fullmatch(x) or RS_DOCKER.fullmatch(x)) for x in services):
            raise ValueError('Неверный список служб')
        kind = validate_restart_target(unit, services) if target_required else None
        systemd = sorted(set(x for x in services if RS_UNIT.fullmatch(x)) | set(RS_MONITORED))
        states = {name: self._service(name) for name in systemd}
        containers = self._containers(); target = None
        if target_required and kind == 'service':
            state = states[unit]
            identity = self._safe_service_target(unit, state)
            if state['LoadState'] != 'loaded' or state['ActiveState'] != 'active' or state['SubState'] in ('start', 'stop', 'auto-restart'):
                raise ValueError('Служба отсутствует, остановлена или меняет состояние; запуск вместо перезапуска запрещён')
            target = {'unit': unit, 'kind': kind, 'identity': identity, 'name': identity, 'active': True,
                      'pid': state['MainPID'], 'startedAt': state['ExecMainStartTimestampMonotonic'] or state['ActiveEnterTimestampMonotonic'],
                      'invocation': state['InvocationID']}
        elif target_required:
            candidate = self._container(RS_DOCKER.fullmatch(unit).group(1))
            name = candidate['name'].lower()
            if not name.startswith(RS_MANAGED_DOCKER) or RS_CORE.search(name):
                raise ValueError('Этот Docker-контейнер не относится к управляемым Amnezia/MTProxyL')
            if not candidate['active']: raise ValueError('Docker-контейнер остановлен или меняет состояние; запуск запрещён')
            if candidate['id'] not in containers: raise ValueError('Контейнер исчез во время проверки')
            observed = containers[candidate['id']]
            if any(candidate[k] != observed[k] for k in ('id', 'name', 'image', 'pid', 'startedAt', 'active')):
                raise ValueError('Контейнер изменился во время проверки')
            if 'awg' in observed: candidate['awg'] = observed['awg']
            target = {**candidate, 'unit': 'docker:' + candidate['id'], 'kind': 'docker', 'identity': candidate['id'], 'invocation': ''}
        return {'bootId': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'system': self._run(['systemctl', 'is-system-running'], check=False).stdout.strip(),
                'aptBusy': self._apt_busy(), 'services': states, 'containers': containers,
                'awg': self._awg(), 'configHashes': self._config_hashes(states), 'safety': self._runtime_safety(), 'target': target}

    @staticmethod
    def _ready(info):
        if info['aptBusy']: raise ValueError('APT/dpkg занят; перезапуск не разрешён')
        if info['system'] not in ('running', 'degraded'): raise ValueError('ОС запускается или выключается')
        if info['services'].get('server-deck-ssh-guard.service', {}).get('ActiveState') == 'active' and not info.get('safety', {}).get('sshGuard', {}).get('present'):
            raise ValueError('SSH-защита запущена, но её правила в ядре не подтверждены')

    def info(self, req):
        info = self._collect(req); self._ready(info); return info

    def observe(self, req):
        return self._collect(req)

    def catalog(self, req):
        info = self._collect(req, target_required=False); self._ready(info); targets = []
        for unit in req.get('services', []):
            if not RS_UNIT.fullmatch(unit): continue
            try: validate_restart_target(unit, req['services'])
            except ValueError: continue
            state = info['services'][unit]
            try: self._safe_service_target(unit, state)
            except ValueError: continue
            if state['LoadState'] == 'loaded' and state['ActiveState'] == 'active' and state['SubState'] not in ('start', 'stop', 'auto-restart'):
                targets.append({'unit': unit, 'label': unit, 'kind': 'service', 'active': True})
        for value in info['containers'].values():
            if value['active'] and value['name'].lower().startswith(RS_MANAGED_DOCKER) and not RS_CORE.search(value['name']):
                targets.append({'unit': 'docker:' + value['id'], 'label': 'Docker · ' + value['name'], 'kind': 'docker', 'active': True})
        return {'targets': targets, 'checkedAt': time.time()}

    def _paths(self, jid):
        if not isinstance(jid, str) or not re.fullmatch(r'[a-f0-9]{32}', jid): raise ValueError('Неверный ID задачи')
        folder = self.state / 'service-restarts'
        return folder, folder / (jid + '.json'), folder / (jid + '.request.json'), folder / (jid + '.worker.py')

    @staticmethod
    def _write(path, value):
        fd, temporary = tempfile.mkstemp(prefix='.restart-', dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as out: json.dump(value, out); out.flush(); os.fsync(out.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    def schedule(self, req, source):
        folder, record, request_path, script = self._paths(req.get('job'))
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (self.state / 'mutation.lock').open('a') as lock:
            try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise ValueError('На сервере уже выполняется изменение')
            if record.exists():
                old = json.loads(record.read_text())
                if old.get('unit') != req.get('unit'): raise ValueError('ID задачи связан с другой службой')
                return {'accepted': old.get('scheduleAccepted'), 'reused': True, 'state': old['state']}
            if not isinstance(source, str) or not source or len(source) > 2 * 1024 * 1024: raise ValueError('Недоступен фиксированный обработчик')
            if type(req.get('expiresAt')) not in (int, float) or req['expiresAt'] <= time.time(): raise ValueError('План истёк')
            before = self.info(req)
            if before['target']['unit'] != req.get('unit') or restart_digest(before) != req.get('revision'): raise ValueError('Состояние изменилось; создайте новый план')
            value = {'id': req['job'], 'unit': req['unit'], 'state': 'queued', 'createdAt': time.time(), 'deadline': time.time() + 180, 'dispatchStarted': False, 'scheduleAccepted': None}
            # Mark this identity durably before the one scheduling attempt.
            self._write(record, value)
            self._write(request_path, dict(req, before=before))
            fd = os.open(str(script), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as out: out.write(source); out.flush(); os.fsync(out.fileno())
            directory = os.open(folder, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
            try:
                command = ['systemd-run', '--quiet', '--collect', '--unit=server-deck-service-' + req['job'],
                           '--on-active=2s', '--timer-property=AccuracySec=1s', '--property=Type=oneshot',
                           '--property=TimeoutStartSec=210s', '/usr/bin/python3', str(script), '--service-restart-worker', str(request_path)]
                response = self._run(command, timeout=15, check=False)
                value['scheduleAccepted'] = response.returncode == 0
            except (OSError, subprocess.TimeoutExpired): value['scheduleAccepted'] = None
            latest = json.loads(record.read_text())
            latest['scheduleAccepted'] = value['scheduleAccepted']
            if value['scheduleAccepted'] is not True and latest['state'] == 'queued':
                latest.update(state='needs_review', error='Подтверждение systemd не получено; повторной отправки нет')
            self._write(record, latest)
            return {'accepted': value['scheduleAccepted'], 'state': latest['state']}

    def status(self, req):
        _, record, _, _ = self._paths(req.get('job'))
        value = json.loads(record.read_text()) if record.exists() else {'id': req['job'], 'state': 'unknown'}
        active = False
        for suffix in ('.timer', '.service'):
            response = self._run(['systemctl', 'is-active', 'server-deck-service-' + req['job'] + suffix], timeout=8, check=False)
            active |= response.stdout.strip() in ('active', 'activating', 'deactivating')
        return dict(value, workerActive=active)

    def _restart(self, target):
        command = ['docker', 'restart', '--', target['identity']] if target['kind'] == 'docker' else ['systemctl', 'restart', '--', target['identity']]
        return self._run(command, timeout=60, check=False).returncode == 0

    def worker(self, req):
        _, record, _, _ = self._paths(req.get('job'))
        if not record.exists(): raise ValueError('Задача не подготовлена')
        with (self.state / 'mutation.lock').open('a') as lock:
            lock_deadline = time.monotonic() + 15
            while True:
                try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); break
                except BlockingIOError:
                    # Scheduling may still hold the lock when the timer fires.
                    # Waiting is bounded; no restart has yet been dispatched.
                    if time.monotonic() >= lock_deadline: return
                    time.sleep(.1)
            state = json.loads(record.read_text())
            if state.get('dispatchStarted') or state['state'] in ('succeeded', 'failed'): return
            started = False
            try:
                if type(req.get('expiresAt')) not in (int, float) or time.time() >= req['expiresAt']: raise ValueError('План истёк до выполнения')
                before = self.info(req)
                if restart_digest(before) != req.get('revision') or before != req.get('before'): raise ValueError('Состояние изменилось после предпросмотра')
                state.update(state='running', dispatchStarted=True, startedAt=time.time()); self._write(record, state); started = True
                try: state['commandConfirmed'] = self._restart(before['target'])
                except (OSError, subprocess.TimeoutExpired): state['commandConfirmed'] = None
                self._write(record, state)
                while True:
                    try:
                        after = self.observe(req); confirmed, violations = restart_preservation(before, after)
                        if confirmed:
                            state.update(state='needs_review' if violations else 'succeeded', finishedAt=time.time(),
                                         restartConfirmed=True, violations=violations,
                                         message='Выбранная служба перезапущена; остальные отслеживаемые службы и AWG сохранены. VPN-трафик этим не проверялся.' if not violations else 'Перезапуск подтверждён, но другие наблюдения требуют проверки')
                            self._write(record, state); return
                    except Exception: pass
                    if time.time() >= state['deadline']:
                        state.update(state='needs_review', finishedAt=time.time(), error='За 180 секунд перезапуск и сохранность окружения не подтверждены. Автоматического повтора нет')
                        self._write(record, state); return
                    time.sleep(3)
            except Exception:
                state.update(state='needs_review' if started else 'failed', finishedAt=time.time(), error='Предварительная проверка или наблюдение не завершены. Повтора команды нет', dispatchStarted=started)
                self._write(record, state)
