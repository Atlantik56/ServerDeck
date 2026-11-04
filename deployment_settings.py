"""Domain settings through a fixed, root-owned loopback helper.

This module never edits web-server configuration and never runs an arbitrary
command supplied by a browser. All writes belong to the root helper's expiring
plans and durable systemd job.
"""
import copy
import json
import os
import pathlib
import re
import subprocess
import threading
import time


class DeploymentRejected(ValueError):
    """A complete helper response proved that no mutation was accepted."""


class DeploymentSettings:
    def __init__(self, root, keydir, busy_fn=None, request_fn=None, clock=time.time, control=None):
        self.root = pathlib.Path(root)
        self.keydir = pathlib.Path(keydir)
        self.busy_fn = busy_fn or (lambda: False)
        self.clock = clock
        self.control = control
        self.freeze = self.root / 'control-data' / 'deployment-freeze'
        self.request_fn = request_fn
        self.host = os.environ.get('DECK_DEPLOYMENT_SSH_HOST', '')
        self.key = os.environ.get('DECK_DEPLOYMENT_SSH_KEY', '')
        try:self.port = int(os.environ.get('DECK_DEPLOYMENT_SSH_PORT', '22'))
        except (ValueError, TypeError):self.port = 0
        self.lock = threading.RLock()
        self.cached = None
        self.cached_at = 0

    def available(self):
        return bool(self.request_fn or (self.host in ('127.0.0.1', 'localhost') and 1 <= self.port <= 65535 and
                    re.fullmatch(r'[A-Za-z0-9_.-]{1,160}', self.key) and
                    self.key not in ('.', '..') and (self.keydir / self.key).is_file()))

    def _request(self, data):
        if self.request_fn:
            return self.request_fn(data)
        if not self.available():
            raise ValueError('Управление доменом не настроено: установите ограниченный помощник Server Deck.')
        argv = ['ssh', '-i', str(self.keydir / self.key), '-p', str(self.port), '-o', 'BatchMode=yes',
                '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5',
                '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', 'root@' + self.host,
                '/usr/bin/python3 -I /usr/local/lib/server-deck/deployment_helper.py']
        try:
            p = subprocess.run(argv, input=json.dumps(data), capture_output=True, text=True, timeout=35)
            result = json.loads(p.stdout) if p.returncode == 0 and len(p.stdout) < 131072 else None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            result = None
        if not isinstance(result, dict):
            raise ValueError('Помощник домена не ответил. Повторного изменения автоматически не будет.')
        if result.get('ok') is not True:
            if result.get('uncertain') is True:
                raise ValueError(result.get('error', 'Результат настройки домена требует проверки.'))
            raise DeploymentRejected(result.get('error', 'Помощник домена отклонил запрос.'))
        return result['data']

    def snapshot(self, force=False):
        with self.lock:
            if self.cached is not None and not force and self.clock() - self.cached_at < 5:
                value = copy.deepcopy(self.cached)
                if self.freeze.exists():value['busy'] = True
                return value
            if not self.available():
                result = {'available': False, 'origin': os.environ.get('DECK_PUBLIC_ORIGIN', ''),
                          'error': 'Для смены домена установите ограниченный помощник Server Deck.', 'busy': False}
            else:
                try:
                    result = self._request({'action': 'inspect'})
                except ValueError as exc:
                    result = {'available': False, 'origin': os.environ.get('DECK_PUBLIC_ORIGIN', ''),
                              'error': str(exc), 'busy': False}
            self.cached = result
            if self.freeze.exists():result['busy'] = True
            self.cached_at = self.clock()
            return copy.deepcopy(result)

    def refresh(self):
        return self.snapshot(True)

    def plan(self, data):
        if not isinstance(data, dict) or set(data) - {'domain', 'email'}:
            raise ValueError('Укажите только домен и email для сертификата.')
        if self.busy_fn():
            raise ValueError('Дождитесь окончания выполняющихся задач панели перед сменой домена.')
        if not isinstance(data.get('domain'), str) or not isinstance(data.get('email'), str):
            raise ValueError('Укажите домен и email для сертификата.')
        return self._request({'action': 'plan', 'domain': data['domain'], 'email': data['email']})

    def apply(self, data):
        if not isinstance(data, dict) or set(data) != {'plan', 'confirmation'}:
            raise ValueError('Подтвердите подготовленный план доменом.')
        if not isinstance(data['plan'], str) or not re.fullmatch(r'[a-f0-9]{32}', data['plan']):
            raise ValueError('Неверный план смены домена.')
        if not isinstance(data['confirmation'], str):
            raise ValueError('Введите домен для подтверждения.')
        guard = self.control.lock if self.control is not None else self.lock
        with guard:
            if self.busy_fn() or self.freeze.exists():
                raise ValueError('Дождитесь окончания выполняющихся задач панели перед сменой домена.')
            if self.control is not None:
                review = {j.get('server') for j in self.control.jobs.values() if j.get('state') == 'needs_review'}
                if set(self.control.busy) - review:
                    raise ValueError('Дождитесь окончания действия со службой или Fail2ban перед сменой домена.')
            self.freeze.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.freeze, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump({'plan': data['plan'], 'createdAt': self.clock()}, f)
                f.flush();os.fsync(f.fileno())
            try:
                result = self._request({'action': 'apply', **data})
            except DeploymentRejected:
                # A complete negative helper response precedes any accepted
                # worker. Transport loss is deliberately NOT handled here.
                try:
                    if json.loads(self.freeze.read_text()).get('plan') == data['plan']:
                        self.freeze.unlink()
                except (OSError, ValueError):pass
                raise
        with self.lock:
            self.cached = None
        return result
