"""Persistent single-service restart plans, using Control's lock and busy set."""
import copy
import secrets
import threading
import time
from service_restart_remote import restart_digest, validate_restart_target

SR_TERMINAL = {'succeeded', 'failed', 'needs_review', 'reviewed'}


class ServiceRestarts:
    def __init__(self, control):
        self.c = control; self.watching = set()

    @staticmethod
    def _binding(server):
        return [server['host'], server['port'], server['user'], server['key']]

    def _matches(self, server, binding, services):
        return self._binding(server) == binding and sorted(server['services']) == sorted(services)

    def _busy(self, sid):
        return sid in self.c.busy or any(j['server'] == sid and (j['state'] not in SR_TERMINAL or j.get('remoteSubmitted') and j['state'] == 'needs_review') for j in self.c.jobs.values())

    def targets(self, server):
        with self.c.lock:
            if self._busy(server['id']): raise ValueError('На сервере уже выполняется задача')
        return self.c.ssh(server, {'op': 'service-restart-targets', 'services': list(server['services'])})

    def plan(self, server, unit):
        validate_restart_target(unit, server['services'])
        binding = self._binding(server); services = list(server['services'])
        with self.c.lock:
            if self._busy(server['id']): raise ValueError('На сервере уже выполняется задача')
        info = self.c.ssh(server, {'op': 'service-restart-info', 'unit': unit, 'services': services})
        target = info['target']; now = time.time(); pid = secrets.token_hex(16)
        summary = {'title': 'Перезапустить · ' + target['name'], 'kind': 'service-restart', 'unit': target['unit'],
                   'impact': 'Подключения выбранной службы, включая VPN/прокси, могут прерваться. systemd также может затронуть её зависимости. Подтвердите допустимость этого перерыва. SSH, сеть и защита не выбираются этой командой.',
                   'warnings': ['Доступ к веб-панели может кратковременно прерваться при перезапуске её веб-сервера.'] if unit in ('caddy.service', 'nginx.service') else [],
                   'steps': ['Повторная проверка состояния и идентичности выбранной службы', 'Одна команда restart только для выбранной службы', 'Наблюдение до 180 секунд без повторных команд и автоматического отката'],
                   'backupRequired': False}
        plan = {'id': pid, 'kind': 'service-restart', 'server': server['id'], 'host': server['host'], 'unit': target['unit'],
                'createdAt': now, 'expiresAt': now + 300, 'used': False, 'before': info, 'revision': restart_digest(info),
                'binding': binding, 'services': services, 'summary': summary,
                'request': {'kind': 'service-restart', 'unit': target['unit']}}
        with self.c.lock:
            if self._busy(server['id']): raise ValueError('На сервере уже выполняется задача')
            if not self._matches(self.c.server(server['id']), plan['binding'], plan['services']): raise ValueError('Параметры сервера изменились')
            self.c.plans[pid] = plan
        return {k: copy.deepcopy(plan[k]) for k in ('id', 'server', 'host', 'unit', 'createdAt', 'expiresAt', 'summary')}

    def execute(self, plan, confirmation):
        c = self.c
        with c.lock:
            if plan.get('used') or plan['expiresAt'] <= time.time(): raise ValueError('План истёк или уже использован')
            if confirmation != plan['host']: raise ValueError('Введите точный адрес сервера для подтверждения')
            server = c.server(plan['server'])
            if not self._matches(server, plan['binding'], plan['services']): raise ValueError('Параметры сервера изменились')
            if self._busy(server['id']): raise ValueError('На сервере уже выполняется задача')
            plan['used'] = True; c.busy.add(server['id']); jid = secrets.token_hex(16); now = time.time()
            job = {'id': jid, 'kind': 'service-restart', 'server': server['id'], 'host': server['host'], 'unit': plan['unit'],
                   'title': plan['summary']['title'], 'state': 'submitting', 'createdAt': now, 'expiresAt': plan['expiresAt'],
                   'deadline': now + 210, 'backups': [], 'before': plan['before'], 'binding': plan['binding'], 'services': plan['services']}
            c.jobs[jid] = job
            try: c.save_jobs()
            except Exception:
                c.jobs.pop(jid, None); c.busy.discard(server['id']); plan['used'] = False; raise
        threading.Thread(target=self.submit, args=(jid, plan), daemon=True).start()
        return copy.deepcopy({k: v for k, v in job.items() if k not in ('before', 'binding')})

    def _update(self, job, **values):
        with self.c.lock: job.update(values); self.c.save_jobs()

    def submit(self, jid, plan):
        c = self.c; job = c.jobs[jid]
        try:
            server = c.server(job['server'])
            if not self._matches(server, job['binding'], job['services']): raise ValueError('Параметры сервера изменились')
            fresh = c.ssh(server, {'op': 'service-restart-info', 'unit': job['unit'], 'services': job['services']})
            if time.time() >= plan['expiresAt'] or restart_digest(fresh) != plan['revision']: raise ValueError('План истёк или состояние изменилось; команда не отправлена')
            self._update(job, remoteSubmitted=True, message='Перезапуск отправляется один раз; далее выполняется только наблюдение')
            try:
                reply = c.ssh(server, {'op': 'service-restart-schedule', 'unit': job['unit'], 'services': job['services'],
                                       'job': jid, 'revision': plan['revision'], 'expiresAt': plan['expiresAt']}, 35)
                self._update(job, commandAccepted=reply.get('accepted'))
            except Exception: self._update(job, commandAccepted=None, message='Подтверждение не получено; проверяем состояние без повторной команды')
            self._update(job, state='running'); self.monitor(jid)
        except Exception as error:
            self._update(job, state='needs_review' if job.get('remoteSubmitted') else 'failed', error=str(error), finishedAt=time.time())
            if not job.get('remoteSubmitted'):
                with c.lock: c.busy.discard(job['server'])

    def monitor(self, jid):
        c = self.c; job = c.jobs[jid]
        with c.lock:
            if jid in self.watching or job['state'] in ('succeeded', 'failed', 'reviewed'): return
            self.watching.add(jid); c.busy.add(job['server'])
        try:
            while True:
                try:
                    server = c.server(job['server'])
                    if not self._matches(server, job['binding'], job['services']): raise ValueError('Параметры сервера изменились')
                    value = c.ssh(server, {'op': 'service-restart-status', 'job': jid}, 30)
                    remote_state = value.get('state')
                    self._update(job, lastCheckAt=time.time(), workerActive=bool(value.get('workerActive')))
                    if remote_state in ('succeeded', 'failed', 'needs_review'):
                        self._update(job, **{k: v for k, v in value.items() if k not in ('id', 'unit', 'createdAt', 'deadline')})
                        if remote_state in ('succeeded', 'failed'):
                            with c.lock:
                                c.busy.discard(job['server']); c.clients_cache.pop(job['server'], None); c.software_cache.pop(job['server'], None)
                        return
                except Exception: self._update(job, message='Статус пока не подтверждён; повторная команда restart не отправляется')
                if time.time() >= job['deadline']:
                    self._update(job, state='needs_review', finishedAt=time.time(), error='За отведённое время результат не подтверждён; требуется ручная проверка')
                    return
                time.sleep(5)
        finally:
            with c.lock: self.watching.discard(jid); c.save_jobs()

    def acknowledge(self, job):
        if time.time() < job['createdAt'] + 15: raise ValueError('Дождитесь завершения отправки команды')
        server = self.c.server(job['server'])
        if not self._matches(server, job['binding'], job['services']): raise ValueError('Параметры сервера изменились')
        result = self.c.ssh(server, {'op': 'service-restart-status', 'job': job['id']})
        if result.get('workerActive') or result.get('state') in ('queued', 'running'): raise ValueError('Удалённый перезапуск ещё выполняется')
        if result.get('state') == 'unknown' and time.time() < job.get('expiresAt', 0) + 30:
            raise ValueError('Результат неизвестен; дождитесь истечения плана перед ручным снятием блокировки')
