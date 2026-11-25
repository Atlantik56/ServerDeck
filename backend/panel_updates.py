"""Read-only release checks and requests to the fixed deployment helper."""

import json
import pathlib
import threading
import time

from panel_release import fetch_latest, version_key


CHECK_INTERVAL = 3600
FORCE_COOLDOWN = 15
RELEASE_STATE = pathlib.Path('/var/lib/server-deck-release')


class PanelUpdates:
    def __init__(self, deployment, directory=RELEASE_STATE, fetch=fetch_latest, clock=time.time):
        self.deployment = deployment
        self.directory = pathlib.Path(directory)
        self.fetch = fetch
        self.clock = clock
        self.check_lock = threading.Lock()
        self.status_lock = threading.Lock()
        self.checked_at = 0
        self.release = None
        self.error = ''

    def _read_object(self, filename):
        try:
            with (self.directory / filename).open(encoding='utf-8') as source:
                value = json.loads(source.read(32768))
        except (OSError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def _installed(self):
        installed = self._read_object('installed.json') or {}
        try:
            version_key(installed.get('version'))
        except ValueError:
            return None
        return {key: installed.get(key) for key in ('version', 'revision')}

    def snapshot(self):
        installed = self._installed()
        supported = self.deployment.available() and installed is not None
        with self.status_lock:
            latest = self.release
            checked_at = self.checked_at
            error = self.error
        if not installed:
            state = 'unversioned'
        elif not supported:
            state = 'disabled'
        elif not latest or error:
            state = 'unknown'
        elif version_key(latest['version']) > version_key(installed['version']):
            state = 'available'
        else:
            state = 'current'
        job = self._read_object('job.json')
        return {
            'supported': supported, 'installed': installed,
            'latest': {key: latest[key] for key in ('version', 'url', 'summary') if key in latest} if latest else None,
            'state': state, 'checkedAt': checked_at, 'error': error,
            'job': {key: job[key] for key in ('id', 'version', 'state', 'stage', 'createdAt', 'finishedAt', 'error') if key in job} if job else None,
        }

    def check(self, force=False):
        if not self._installed():
            return self.snapshot()
        interval = FORCE_COOLDOWN if force else CHECK_INTERVAL
        with self.check_lock:
            with self.status_lock:
                due = not self.checked_at or self.clock() - self.checked_at >= interval
            if due:
                try:
                    release = self.fetch()
                    error = '' if release else 'В GitHub пока нет опубликованного стабильного пакета Server Deck.'
                except Exception:
                    release = None
                    error = 'Не удалось подтвердить стабильный релиз Server Deck в GitHub.'
                with self.status_lock:
                    self.release = release
                    self.error = error
                    self.checked_at = self.clock()
        return self.snapshot()

    def run(self, stop):
        while not stop.is_set():
            self.check()
            stop.wait(CHECK_INTERVAL)

    def apply(self, data):
        if not isinstance(data, dict) or set(data) != {'version'}:
            raise ValueError('Укажите версию Server Deck из центра обновлений.')
        version = data['version']
        version_key(version)
        status = self.snapshot()
        if not status['supported']:
            raise ValueError('Обновление этой установки Server Deck недоступно.')
        if status['state'] != 'available' or status['latest']['version'] != version:
            raise ValueError('Версия изменилась. Проверьте релиз ещё раз.')
        return self.deployment.apply_panel_update(version)
