"""Expiring interactive Fail2ban plans, sharing the control-plane mutation guard."""
import copy
import json
import os
import pathlib
import secrets
import shlex
import subprocess
import time
from fail2ban_remote import validate_settings


class Fail2banManager:
    def __init__(self, control, root=None, busy_fn=None, transport=None):
        self.control = control
        self.root = pathlib.Path(root or control.root) / 'fail2ban'
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.busy_fn = busy_fn or (lambda sid: False)
        self.transport = transport
        self.plans = {}
        self.reviewing = set()
        self.source = pathlib.Path(__file__).with_name('fail2ban_remote.py').read_text()
        for path in self.root.glob('*.json'):
            try:
                value = json.loads(path.read_text())
                if value.get('state') in ('submitting', 'needs_review'):
                    self.control.busy.add(value['server'])
            except (ValueError, OSError, KeyError): pass

    @staticmethod
    def binding(server):
        return [server['host'], server['port'], server['user'], server['key']]

    def ssh(self, server, request):
        if self.transport: return self.transport(server, request)
        wrapper = "import json,sys;e=json.load(sys.stdin);exec(compile(e['source'],'<fail2ban-adapter>','exec'),{'__name__':'__main__','_DECK_REQUEST':e['request']})"
        args = ['ssh', '-i', str(self.control.keydir / server['key']), '-p', str(server['port']), '-o', 'BatchMode=yes',
                '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8',
                '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', server['user'] + '@' + server['host'],
                'python3 -c ' + shlex.quote(wrapper)]
        result = subprocess.run(args, input=json.dumps({'source': self.source, 'request': request}),
                                capture_output=True, text=True, timeout=130)
        if result.returncode: raise RuntimeError('SSH-проверка Fail2ban не завершена')
        try: value = json.loads(result.stdout)
        except ValueError: raise RuntimeError('Неизвестный ответ адаптера Fail2ban')
        if not value.get('ok'): raise ValueError(value.get('error', 'Ошибка проверки Fail2ban'))
        return value['data']

    def inspect(self, sid):
        server = self.control.server(sid)
        value = dict(self.ssh(server, {'op': 'inspect'}), server=sid, host=server['host'], name=server['name'])
        pending = []
        for path in self.root.glob('*.json'):
            try:
                item = json.loads(path.read_text())
                if item.get('server') == sid and item.get('state') in ('submitting', 'needs_review'):
                    pending.append(dict(job=path.stem, state=item['state']))
            except (ValueError, OSError): pass
        value['pendingJobs'] = pending
        return value

    def snapshot(self, sid=None):
        if sid: return self.inspect(sid)
        return {'servers': [{'server': value['id'], 'name': value['name'], 'host': value['host']} for value in self.control.servers()]}

    def plan(self, data):
        if not isinstance(data, dict) or set(data) != {'server', 'maxretry', 'findtime', 'bantime', 'ignoreip'}:
            raise ValueError('Укажите сервер и настройки jail sshd')
        settings = validate_settings({key: data[key] for key in ('maxretry', 'findtime', 'bantime', 'ignoreip')})
        c = self.control
        server = c.server(data['server'])
        with c.lock:
            if server['id'] in c.busy or self.busy_fn(server['id']): raise ValueError('На сервере выполняется другая операция')
        before = self.inspect(server['id'])
        if not before.get('editable'): raise ValueError(before.get('message', 'Настройка Fail2ban недоступна'))
        plan = {'id': secrets.token_hex(16), 'server': server['id'], 'host': server['host'], 'name': server['name'],
                'binding': self.binding(server), 'before': before, 'settings': settings, 'revision': before['revision'],
                'createdAt': time.time(), 'expiresAt': time.time() + 300, 'used': False,
                'summary': {'title': 'Настроить Fail2ban · ' + server['name'],
                            'impact': 'Меняются пороги существующей jail sshd. Новые неуспешные входы могут привести к блокировке их адреса.',
                            'preserved': 'Действующие исключения, IP подключения панели, другие jail, правила SSH и службы VPN сохраняются.',
                            'steps': ['Проверка текущей конфигурации и порта SSH', 'Резервная копия управляемого drop-in',
                                      'Проверка fail2ban-client -t и reload только jail sshd', 'Проверка параметров; откат при ошибке']}}
        plan['effectiveIgnoreip'] = sorted(set(settings['ignoreip'] + before['protectedIgnoreip']))
        with c.lock:
            self.plans = {pid: value for pid, value in self.plans.items() if not value['used'] and value['expiresAt'] > time.time()}
            self.plans[plan['id']] = plan
        return copy.deepcopy({key: value for key, value in plan.items() if key not in ('binding', 'revision', 'used')})

    def persist(self, job, value):
        path = self.root / (job + '.json')
        temporary = path.with_suffix('.tmp')
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False); stream.flush(); os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))

    def apply(self, data):
        if not isinstance(data, dict) or set(data) != {'plan', 'confirmation'}:
            raise ValueError('Укажите план и точный адрес сервера')
        c = self.control
        with c.lock:
            plan = self.plans.get(data['plan'])
            if not plan or plan['used'] or plan['expiresAt'] <= time.time(): raise ValueError('План истёк или уже использован')
            if data['confirmation'] != plan['host']: raise ValueError('Введите точный адрес сервера для подтверждения')
            server = c.server(plan['server'])
            if self.binding(server) != plan['binding']: raise ValueError('Параметры сервера изменились')
            if server['id'] in c.busy or self.busy_fn(server['id']): raise ValueError('На сервере выполняется другая операция')
            job = secrets.token_hex(16)
            self.persist(job, {'state': 'submitting', 'server': server['id'], 'createdAt': time.time(),
                               'binding': plan['binding'], 'expiresAt': plan['expiresAt']})
            c.busy.add(server['id']); plan['used'] = True
        release = False
        try:
            result = self.ssh(server, {'op': 'apply', 'job': job, 'settings': plan['settings'],
                                      'revision': plan['revision'], 'expiresAt': plan['expiresAt']})
            release = result.get('state') in ('succeeded', 'failed')
            self.persist(job, dict(result, server=server['id'], binding=plan['binding'], expiresAt=plan['expiresAt'], finishedAt=time.time()))
            return result
        except Exception:
            # Remote state is uncertain; never submit again or silently unlock mutations.
            result = {'state': 'needs_review', 'job': job,
                      'error': 'Результат применения не подтверждён. Повторная команда не отправляется. Проверьте Fail2ban через SSH.'}
            self.persist(job, dict(result, server=server['id'], binding=plan['binding'], expiresAt=plan['expiresAt'], finishedAt=time.time()))
            return result
        finally:
            if release:
                with c.lock: c.busy.discard(server['id'])

    def review(self, data):
        if not isinstance(data, dict) or set(data) != {'job', 'confirmation'}:
            raise ValueError('Укажите операцию и точный адрес сервера')
        import re
        if not isinstance(data['job'], str) or not re.fullmatch('[0-9a-f]{32}', data['job']):
            raise ValueError('Неверный идентификатор операции')
        path = self.root / (data['job'] + '.json')
        if not path.exists(): raise ValueError('Операция не найдена')
        c = self.control
        with c.lock:
            value = json.loads(path.read_text()); server = c.server(value['server'])
            if value.get('state') not in ('submitting', 'needs_review'):
                raise ValueError('Операция уже завершена или проверена')
            if data['job'] in self.reviewing:
                raise ValueError('Проверка этой операции уже выполняется')
            if data['confirmation'] != server['host']: raise ValueError('Введите точный адрес сервера')
            if self.binding(server) != value.get('binding'): raise ValueError('Параметры сервера изменились')
            if time.time() <= value.get('expiresAt', 0) + 140:
                raise ValueError('Дождитесь завершения отправленной команды и истечения плана перед ручной проверкой')
            self.reviewing.add(data['job'])
        try:
            status = self.ssh(server, {'op': 'status', 'job': data['job']})
            if status.get('mutationBusy'): raise ValueError('На сервере ещё выполняется изменение; блокировку снять нельзя')
            fresh = self.ssh(server, {'op': 'inspect'})
            if not fresh.get('editable'): raise ValueError('Текущее состояние jail sshd не подтверждено')
            with c.lock:
                current = json.loads(path.read_text())
                if current.get('state') not in ('submitting', 'needs_review'):
                    raise ValueError('Состояние операции изменилось во время проверки')
                if self.binding(c.server(server['id'])) != value['binding']:
                    raise ValueError('Параметры сервера изменились во время проверки')
                for job in getattr(c, 'jobs', {}).values():
                    owns_reservation = job.get('state') not in ('succeeded', 'failed', 'needs_review', 'reviewed') or (job.get('state') == 'needs_review' and job.get('remoteSubmitted'))
                    if job.get('server') == server['id'] and owns_reservation:
                        raise ValueError('Другая задача удерживает блокировку сервера')
                for other_path in self.root.glob('*.json'):
                    if other_path == path: continue
                    other = json.loads(other_path.read_text())
                    if other.get('server') == server['id'] and other.get('state') in ('submitting', 'needs_review'):
                        raise ValueError('Другая операция Fail2ban требует проверки')
                value.update(state='reviewed', finishedAt=time.time(), reviewedState=status.get('state'), after=fresh)
                self.persist(data['job'], value); c.busy.discard(server['id'])
            return {'state': 'reviewed', 'message': 'Текущее состояние Fail2ban проверено. Блокировка управления снята по вашему подтверждению; повторного применения не было.'}
        finally:
            with c.lock: self.reviewing.discard(data['job'])
