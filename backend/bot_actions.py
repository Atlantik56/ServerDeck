"""Durable, single-use Telegram confirmations for narrowly planned restarts.

Only the authenticated transport may call this module. It supplies the paired
private chat and sender after checking message freshness and callback ownership.
There are no shell commands or network calls here: Control owns all execution.
"""
import hashlib
import hmac
import json
import math
import os
import pathlib
import re
import secrets
import tempfile
import threading
import time

from bot_menu import clip, label

TTL = 120
PAGE_SIZE = 6
DONE = {'succeeded', 'failed', 'reviewed'}
SESSION_STATES = {'selection', 'pending', 'cancelled', 'expired', 'consumed'}
AUDIT_STATES = {'reserved', 'job', 'uncertain', 'done'}
SID = re.compile(r'[A-Za-z0-9_-]{1,40}')
OPAQUE = re.compile(r'[a-f0-9]{16}')
PLAN_ID = re.compile(r'[a-f0-9]{32}')
STATES = {'backing_up': 'создание копии', 'queued': 'в очереди', 'submitting': 'отправка команды',
          'submitted': 'команда отправлена', 'running': 'выполняется', 'waiting_reboot': 'ожидание загрузки',
          'waiting_services': 'ожидание служб', 'succeeded': 'завершена', 'failed': 'ошибка',
          'needs_review': 'нужна ручная проверка', 'reviewed': 'проверена оператором'}


class ActionError(Exception):
    pass


def finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()


def actor_id(value):
    value = str(value) if type(value) is int else value
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', value):
        raise ActionError('Недопустимая учётная запись Telegram.')
    return value


class BotActions:
    def __init__(self, root, control_fn, servers_fn, clock=time.time, controller_id=None):
        self.root = pathlib.Path(root) / 'telegram-actions'
        self.path = self.root / 'state.json'
        self.control_fn, self.servers_fn, self.clock = control_fn, servers_fn, clock
        self.controller_id = controller_id
        self.lock = threading.RLock()
        self.state = {'version': 1, 'sessions': {}, 'audit': {}}
        self.storage_error = False
        try:
            if self.root.is_symlink():
                raise ValueError()
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.path.exists():
                if self.path.is_symlink() or self.path.stat().st_size > 1024 * 1024:
                    raise ValueError()
                self.state = json.loads(self.path.read_text())
                self._validate_state()
            for session in self.state['sessions'].values():
                if session['state'] in ('selection', 'pending'):
                    session['state'] = 'expired'  # Control plans are process-local.
            for item in self.state['audit'].values():
                if item['state'] == 'reserved':
                    item['state'] = 'uncertain'
            self._save()
        except Exception:
            self.storage_error = True

    def _validate_state(self):
        state = self.state
        if not isinstance(state, dict) or set(state) != {'version', 'sessions', 'audit'} or state['version'] != 1:
            raise ValueError()
        for key, maximum, allowed in [('sessions', 128, SESSION_STATES), ('audit', 256, AUDIT_STATES)]:
            rows = state[key]
            if not isinstance(rows, dict) or len(rows) > maximum:
                raise ValueError()
            for token, row in rows.items():
                if not isinstance(token, str) or not OPAQUE.fullmatch(token) or not isinstance(row, dict):
                    raise ValueError()
                if row.get('state') not in allowed or not isinstance(row.get('actor'), list) or len(row['actor']) != 2:
                    raise ValueError()
                if [actor_id(x) for x in row['actor']] != row['actor']:
                    raise ValueError()
                if not isinstance(row.get('server'), str) or not SID.fullmatch(row['server']) or not finite(row.get('createdAt')):
                    raise ValueError()
                if key == 'sessions':
                    if not finite(row.get('expiresAt')) or not isinstance(row.get('binding'), list) or len(row['binding']) != 4:
                        raise ValueError()
                    if type(row.get('messageId')) is not int or row['messageId'] <= 0:
                        raise ValueError()
                    if not isinstance(row.get('targets'), list) or len(row['targets']) > 256:
                        raise ValueError()
                    if row['state'] == 'pending' and (not isinstance(row.get('planId'), str) or not PLAN_ID.fullmatch(row['planId']) or
                            not re.fullmatch(r'[a-f0-9]{64}', row.get('confirmationHash', ''))):
                        raise ValueError()

    def _save(self):
        if self.storage_error:
            raise ActionError('Хранилище подтверждений недоступно. Действия заблокированы.')
        name = None
        try:
            fd, name = tempfile.mkstemp(prefix='.actions-', dir=str(self.root))
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as out:
                json.dump(self.state, out, ensure_ascii=False, separators=(',', ':'))
                out.flush()
                os.fsync(out.fileno())
            os.replace(name, self.path)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            self.storage_error = True
            raise ActionError('Не удалось сохранить подтверждение. Действия заблокированы.') from None
        finally:
            if name and os.path.exists(name):
                os.unlink(name)

    def invalidate_pending(self):
        with self.lock:
            if self.storage_error:
                return False
            changed = False
            for session in self.state['sessions'].values():
                if session['state'] in ('selection', 'pending'):
                    session['state'] = 'cancelled'
                    changed = True
            if changed:
                self._save()
            return True

    @staticmethod
    def _reply(text, rows=None):
        navigation = [[{'text': 'Мои задачи', 'callback_data': 'deck:act:jobs'},
                       {'text': 'К списку серверов', 'callback_data': 'deck:servers'}]]
        return {'text': clip(text, 3500), 'reply_markup': {'inline_keyboard': (rows or []) + navigation},
                'disable_web_page_preview': True}

    @staticmethod
    def _binding(server):
        host, port, user, key = [server.get(k) for k in ('host', 'port', 'user', 'key')]
        if (not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', host) or
                type(port) is not int or not 1 <= port <= 65535 or
                not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user) or
                not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,256}', key) or key in ('.', '..')):
            raise ActionError('Параметры сервера не подтверждены. Откройте панель.')
        return [host, port, user, key]

    def _server(self, sid):
        rows = self.servers_fn()
        if not isinstance(rows, list):
            raise ActionError('Реестр серверов недоступен.')
        matches = [s for s in rows if isinstance(s, dict) and s.get('id') == sid]
        if len(matches) != 1:
            raise ActionError('Сервер отсутствует или его запись изменилась. Откройте список заново.')
        self._binding(matches[0])
        return matches[0]

    def _jobs(self, control):
        snapshot = control.snapshot()
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get('jobs'), list) or not isinstance(snapshot.get('busyServers'), list):
            raise ActionError('Не удалось подтвердить отсутствие других задач. Действие заблокировано.')
        all_jobs = list(control.jobs.values()) if isinstance(getattr(control, 'jobs', None), dict) else snapshot['jobs']
        lookup = {j.get('id'): j for j in all_jobs if isinstance(j, dict) and isinstance(j.get('id'), str)}
        changed = False
        for item in self.state['audit'].values():
            if item['state'] not in ('job', 'done') or not item.get('jobId'):
                continue
            job = lookup.get(item['jobId'])
            if (not job or job.get('server') != item['server'] or job.get('host') != item['host'] or
                    job.get('kind') != item['kind'] or
                    (item['kind'] == 'service-restart' and job.get('unit') != item.get('unit'))):
                if item['state'] != 'done':
                    item['state'] = 'uncertain'
                    changed = True
                continue
            job_state = job.get('state')
            status = 'done' if job_state in DONE else 'job'
            if item.get('jobState') != job_state or item['state'] != status:
                item.update(jobState=job_state if isinstance(job_state, str) else 'unknown', state=status)
                changed = True
        if changed:
            self._save()
        return snapshot, all_jobs

    def _guard(self, control):
        snapshot, jobs = self._jobs(control)
        if any(a['state'] in ('reserved', 'uncertain', 'job') for a in self.state['audit'].values()):
            raise ActionError('Предыдущая задача бота ещё выполняется или требует ручной проверки. Откройте «Мои задачи». Повторной отправки нет.')
        if snapshot['busyServers'] or any(isinstance(j, dict) and j.get('state') not in DONE for j in jobs):
            raise ActionError('В панели уже выполняется задача или ожидается ручная проверка. Сначала завершите её; новые действия бота заблокированы.')

    def _prune(self):
        now = self.clock()
        for session in self.state['sessions'].values():
            if session['state'] in ('selection', 'pending') and session['expiresAt'] <= now:
                session['state'] = 'expired'
        while len(self.state['sessions']) >= 128:
            removable = [(k, s) for k, s in self.state['sessions'].items() if s['state'] not in ('selection', 'pending')]
            if not removable:
                raise ActionError('Слишком много неподтверждённых действий. Попробуйте позже.')
            del self.state['sessions'][min(removable, key=lambda x: x[1]['createdAt'])[0]]
        while len(self.state['audit']) >= 256:
            removable = [(k, s) for k, s in self.state['audit'].items() if s['state'] == 'done']
            if not removable:
                raise ActionError('История задач требует проверки в панели.')
            del self.state['audit'][min(removable, key=lambda x: x[1]['createdAt'])[0]]

    def _targets(self, control, server):
        engine = getattr(control, 'service_restarts', None)
        if engine is None or not callable(getattr(engine, 'targets', None)):
            return []
        result = engine.targets(server)
        if (not isinstance(result, dict) or not isinstance(result.get('targets'), list) or len(result['targets']) > 256 or
                not finite(result.get('checkedAt')) or not -30 <= self.clock() - result['checkedAt'] <= TTL):
            raise ActionError('Список доступных служб не подтверждён. Попробуйте открыть управление заново.')
        targets, seen = [], set()
        for item in result['targets']:
            if not isinstance(item, dict) or item.get('active') is not True:
                continue
            unit, kind = item.get('unit'), item.get('kind')
            if not isinstance(unit, str):
                raise ActionError('Некорректный список служб. Действие заблокировано.')
            if kind == 'service':
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,199}\.service', unit) or unit not in server.get('services', []):
                    raise ActionError('Список служб изменился. Откройте управление заново.')
            elif kind == 'docker':
                if not re.fullmatch(r'docker:[a-f0-9]{64}', unit):
                    raise ActionError('Контейнер не подтверждён по полному ID.')
            else:
                raise ActionError('Неизвестный тип службы.')
            if unit in seen:
                raise ActionError('Неоднозначный список служб.')
            seen.add(unit)
            targets.append({'unit': unit, 'kind': kind, 'label': label(item.get('label'), unit, 200)})
        return targets

    def _selection(self, token, session, page=0):
        pages = max(1, (len(session['targets']) + PAGE_SIZE - 1) // PAGE_SIZE)
        if not 0 <= page < pages:
            raise ActionError('Страница устарела. Откройте управление сервером заново.')
        rows = []
        for index in range(page * PAGE_SIZE, min((page + 1) * PAGE_SIZE, len(session['targets']))):
            target = session['targets'][index]
            rows.append([{'text': label('↻ ' + target['label'], limit=48),
                          'callback_data': 'deck:act:' + token + ':service:' + str(index)}])
        navigation = []
        if page:
            navigation.append({'text': '← Назад', 'callback_data': 'deck:act:' + token + ':page:' + str(page - 1)})
        if page + 1 < pages:
            navigation.append({'text': 'Далее →', 'callback_data': 'deck:act:' + token + ':page:' + str(page + 1)})
        if navigation:
            rows.append(navigation)
        rows += [[{'text': 'Перезагрузить VPS', 'callback_data': 'deck:act:' + token + ':reboot'}],
                 [{'text': 'Отмена', 'callback_data': 'deck:act:' + token + ':cancel'}]]
        text = ('Управление · ' + session['name'] + '\nАдрес: ' + session['binding'][0] + '\n\n'
                'Выберите службу или перезагрузку VPS. Сейчас ничего не запускается: далее будет отдельное подтверждение.\n'
                'Страница ' + str(page + 1) + '/' + str(pages))
        if not session['targets']:
            text += '\nДоступных для перезапуска служб не обнаружено.'
        return self._reply(text, rows)

    def _open(self, sid, actor, message_id):
        if type(message_id) is not int or message_id <= 0:
            raise ActionError('Исходное сообщение не подтверждено. Откройте новое меню.')
        server, control = self._server(sid), self.control_fn()
        with control.lock:
            self._guard(control)
        targets = self._targets(control, server)
        if self._binding(self._server(sid)) != self._binding(server):
            raise ActionError('Параметры сервера изменились во время проверки.')
        for session in self.state['sessions'].values():
            if session['actor'] == actor and session['state'] in ('selection', 'pending'):
                session['state'] = 'cancelled'
        self._prune()
        token = secrets.token_hex(8)
        session = {'actor': actor, 'server': sid, 'name': label(server.get('name'), sid, 160),
                   'binding': self._binding(server), 'targets': targets, 'state': 'selection',
                   'messageId': message_id,
                   'createdAt': self.clock(), 'expiresAt': self.clock() + TTL}
        self.state['sessions'][token] = session
        self._save()
        return self._selection(token, session)

    def _session(self, token, actor, states=('selection', 'pending'), message_id=None):
        session = self.state['sessions'].get(token)
        if not session or session['actor'] != actor or session['state'] not in states:
            raise ActionError('Подтверждение недоступно, отменено или уже использовано. Откройте управление заново.')
        if message_id is not None and session['messageId'] != message_id:
            raise ActionError('Кнопка относится к другому сообщению. Откройте управление заново.')
        if session['expiresAt'] <= self.clock():
            session['state'] = 'expired'
            self._save()
            raise ActionError('Подтверждение истекло. Выполните новый предпросмотр.')
        server = self._server(session['server'])
        if self._binding(server) != session['binding']:
            session['state'] = 'expired'
            self._save()
            raise ActionError('Параметры сервера изменились. Выполните новый предпросмотр.')
        return session, server

    @staticmethod
    def _raw_plan_digest(plan):
        return digest({k: plan.get(k) for k in ('id', 'kind', 'unit', 'server', 'host', 'revision', 'binding', 'services', 'before', 'request', 'summary', 'expiresAt')})

    def _plan(self, token, actor, target=None):
        session, server = self._session(token, actor, ('selection',))
        kind = 'service-restart' if target is not None else 'reboot'
        unit = session['targets'][target]['unit'] if target is not None and 0 <= target < len(session['targets']) else None
        if kind == 'service-restart' and not unit:
            raise ActionError('Служба не найдена в выбранном списке.')
        if unit and not unit.startswith('docker:') and unit not in server.get('services', []):
            raise ActionError('Служба больше не зарегистрирована. Выполните новый предпросмотр.')
        control = self.control_fn()
        with control.lock:
            self._guard(control)
        request = {'kind': kind, 'server': server['id']}
        if unit:
            request['unit'] = unit
        plan = control.plan(request)
        with control.lock:
            self._guard(control)
            self._session(token, actor, ('selection',))
            if (not isinstance(plan, dict) or not isinstance(plan.get('id'), str) or not PLAN_ID.fullmatch(plan['id']) or
                    plan.get('server') != server['id'] or plan.get('host') != session['binding'][0] or
                    not finite(plan.get('expiresAt')) or plan['expiresAt'] <= self.clock()):
                raise ActionError('Предварительный план не подтверждён. Действие не запущено.')
            summary = plan.get('summary')
            if (not isinstance(summary, dict) or type(summary.get('backupRequired')) is not bool or
                    any(summary.get(k) is False for k in ('ready', 'allowed', 'canExecute')) or
                    summary.get('blockers') or summary.get('blockingErrors')):
                raise ActionError('Предварительная проверка запрещает выполнение. Подробности — в панели.')
            raw = control.plans.get(plan['id'])
            if (not isinstance(raw, dict) or raw.get('server') != server['id'] or raw.get('host') != session['binding'][0] or
                    raw.get('binding') != session['binding'] or raw.get('request', {}).get('kind') != kind or
                    (unit and (raw.get('unit') != unit or raw.get('request', {}).get('unit') != unit))):
                raise ActionError('Точная цель плана не подтверждена.')
            recent = {s.get('confirmationHash') for s in self.state['sessions'].values()}
            recent.update(a.get('confirmationHash') for a in self.state['audit'].values())
            for _ in range(32):
                phrase = 'ПЕРЕЗАПУСТИТЬ ' + str(secrets.randbelow(900000) + 100000)
                phrase_hash = hashlib.sha256(phrase.encode()).hexdigest()
                if phrase_hash not in recent:
                    break
            else:
                raise ActionError('Не удалось подготовить уникальное подтверждение. Попробуйте позже.')
            session.update(state='pending', kind=kind, unit=unit,
                           targetLabel=session['targets'][target]['label'] if target is not None else 'VPS целиком',
                           planId=plan['id'], planHost=plan['host'], planDigest=self._raw_plan_digest(raw),
                           confirmationHash=phrase_hash, attempts=0,
                           expiresAt=min(self.clock() + TTL, plan['expiresAt']))
            self._save()
        impact = ('Все VPN, прокси, панели и SSH этого VPS временно отключатся.' if kind == 'reboot' else
                  'Соединения выбранной службы временно прервутся. Перезапускается выбранный объект; его зависимости тоже могут временно прервать работу.')
        lines = ['Подтвердите действие', '', 'Сервер: ' + session['name'], 'Адрес: ' + session['binding'][0],
                 'Цель: ' + session['targetLabel']]
        if unit:
            lines.append('Точный объект: ' + unit)
        lines += ['', impact, label(summary.get('impact'), '', 500),
                  'Готовность: предварительный план получен; перед отправкой состояние проверит исполнитель.']
        if summary.get('backupRequired') is True:
            lines.append('Резервная копия: план требует создать её перед выполнением.')
        elif summary.get('backupRequired') is False:
            lines.append('Резервная копия: этот план не требует копии; настройки не меняются.')
        else:
            lines.append('Резервная копия: требование не указано в плане.')
        warnings = summary.get('warnings')
        if isinstance(warnings, list):
            for warning in warnings[:5]:
                lines.append('⚠ ' + label(warning, 'Предупреждение — см. панель.', 180))
            if len(warnings) > 5:
                lines.append('Остальные предупреждения — в панели.')
        if server['id'] == self.controller_id or 'server-deck.service' in server.get('services', []):
            lines.append('⚠ Это сервер управления: панель и бот могут временно стать недоступны. Повторять команду нельзя.')
        lines += ['', 'В течение 120 секунд отправьте отдельным сообщением точную фразу:', phrase,
                  'Кнопки запуска нет. Отмена не выполняет действие.']
        return self._reply('\n'.join(lines),
                           [[{'text': 'Отмена', 'callback_data': 'deck:act:' + token + ':cancel'}]])

    def _confirm(self, text, actor):
        pending = [(t, s) for t, s in self.state['sessions'].items() if s['actor'] == actor and s['state'] == 'pending']
        if len(pending) != 1:
            raise ActionError('Нет действующего подтверждения для этого сообщения. Откройте новый предпросмотр.')
        token, session = pending[0]
        session, server = self._session(token, actor, ('pending',))
        if not hmac.compare_digest(hashlib.sha256(text.encode()).hexdigest(), session['confirmationHash']):
            session['attempts'] += 1
            if session['attempts'] >= 3:
                session['state'] = 'cancelled'
            self._save()
            raise ActionError('Фраза не совпала. Действие не выполнено.' + (' Подтверждение отменено; создайте новое.' if session['state'] == 'cancelled' else ' Используйте точную фразу из предпросмотра.'))
        if session.get('unit') and not session['unit'].startswith('docker:') and session['unit'] not in server.get('services', []):
            session['state'] = 'expired'; self._save()
            raise ActionError('Служба больше не зарегистрирована. Выполните новый предпросмотр.')
        control = self.control_fn()
        with control.lock:
            self._guard(control)
            _, current = self._session(token, actor, ('pending',))
            if session.get('unit') and not session['unit'].startswith('docker:') and session['unit'] not in current.get('services', []):
                session['state'] = 'expired'; self._save()
                raise ActionError('Служба больше не зарегистрирована. Выполните новый предпросмотр.')
            raw = control.plans.get(session['planId'])
            if (not isinstance(raw, dict) or raw.get('used') is not False or not finite(raw.get('expiresAt')) or
                    raw['expiresAt'] <= self.clock() or self._raw_plan_digest(raw) != session['planDigest']):
                session['state'] = 'expired'; self._save()
                raise ActionError('Исходный план истёк или изменился. Выполните новый предпросмотр; новый план автоматически не запускается.')
            self._prune()
            if session['state'] != 'pending' or session['expiresAt'] <= self.clock():
                self._save()
                raise ActionError('Подтверждение истекло. Выполните новый предпросмотр.')
            action_id = secrets.token_hex(8)
            if not isinstance(getattr(control, 'jobs', None), dict):
                raise ActionError('Хранилище задач недоступно. Действие не отправлялось.')
            before_job_ids = set(control.jobs)
            audit = {'actor': actor, 'server': session['server'], 'name': session['name'], 'host': session['binding'][0],
                     'kind': session['kind'], 'unit': session.get('unit'), 'targetLabel': session['targetLabel'],
                     'createdAt': self.clock(), 'state': 'reserved', 'confirmationHash': session['confirmationHash'],
                     'jobId': None, 'jobState': 'unknown'}
            session['state'] = 'consumed'
            self.state['audit'][action_id] = audit
            self._save()  # Durable consume before execute; a crash cannot replay it.
            try:
                job = control.execute(session['planId'], session['planHost'])
                if (not isinstance(job, dict) or not isinstance(job.get('id'), str) or not PLAN_ID.fullmatch(job['id']) or
                        job.get('server') != session['server'] or job.get('host') != session['planHost'] or
                        job.get('kind') != session['kind'] or
                        (session['kind'] == 'service-restart' and job.get('unit') != session.get('unit'))):
                    raise ValueError()
                audit.update(jobId=job['id'], jobState=job.get('state', 'unknown'), state='job')
                self._save()
            except Exception:
                new_jobs = [(jid, value) for jid, value in control.jobs.items() if jid not in before_job_ids]
                matching = [(jid, value) for jid, value in new_jobs if isinstance(value, dict) and
                            isinstance(jid, str) and PLAN_ID.fullmatch(jid) and value.get('id') == jid and
                            value.get('server') == session['server'] and value.get('host') == session['planHost'] and
                            value.get('kind') == session['kind'] and
                            (session['kind'] == 'reboot' or value.get('unit') == session.get('unit'))]
                if len(new_jobs) == 1 and len(matching) == 1:
                    jid, value = matching[0]
                    audit.update(jobId=jid, jobState=value.get('state', 'unknown'), state='job')
                    self._save()
                    return self._reply('Исполнитель сохранил задачу, но ответ не получен полностью. Проверяйте её состояние в панели; команда повторно не отправляется.',
                                       [[{'text': 'Проверить задачу', 'callback_data': 'deck:act:job:' + action_id}]])
                if not new_jobs and control.plans.get(session['planId']) is raw and raw.get('used') is False:
                    # Control contract: no used plan and no persisted job means
                    # its validation rejected the action before submission.
                    audit.update(state='done', jobState='failed', rejectedBeforeSubmission=True)
                    self._save()
                    return self._reply('Предварительная проверка отклонила действие до отправки команды. Старое подтверждение использовано; откройте новый предпросмотр. Автоматического повтора нет.')
                audit['state'] = 'uncertain'
                self._save()
                return self._reply('Результат отправки не подтверждён и не связан с задачей. Автоматического повтора нет; новые действия бота заблокированы. Нужна ручная проверка сервера и восстановление состояния действий оператором.',
                                   [[{'text': 'Проверить задачу', 'callback_data': 'deck:act:job:' + action_id}]])
        return self._reply('Задача принята.\nСервер: ' + audit['name'] + '\nЦель: ' + audit['targetLabel'] +
                           '\nСтатус: ' + STATES.get(audit['jobState'], 'уточняется') +
                           '\n\nЭто подтверждение приёма, а не завершения. Команда повторно не отправляется.',
                           [[{'text': 'Проверить задачу', 'callback_data': 'deck:act:job:' + action_id}]])

    def _status(self, actor, action_id=None):
        control = self.control_fn()
        with control.lock:
            self._jobs(control)
        records = [(k, a) for k, a in self.state['audit'].items() if a['actor'] == actor]
        if action_id is not None:
            records = [(k, a) for k, a in records if k == action_id]
            if not records:
                raise ActionError('Задача недоступна для этого чата.')
        records.sort(key=lambda x: x[1]['createdAt'], reverse=True)
        lines, buttons = ['Мои задачи', ''], []
        for key, item in records[:5]:
            status = 'результат неизвестен — нужна ручная проверка' if item['state'] in ('reserved', 'uncertain') else STATES.get(item.get('jobState'), 'состояние неизвестно')
            lines += [item['name'] + ' · ' + item['host'], item['targetLabel'] + ' — ' + status]
            if item.get('jobId'):
                lines.append('ID задачи: ' + item['jobId'])
            if item.get('jobState') in ('failed', 'needs_review') or item['state'] == 'uncertain':
                lines.append('Подробности и ручная проверка — в панели. Повторного запуска нет.')
            buttons.append([{'text': 'Обновить · ' + label(item['name'], limit=30), 'callback_data': 'deck:act:job:' + key}])
        if not records:
            lines.append('Задач, запущенных из этого чата, пока нет.')
        lines += ['', 'Показано сохранённое состояние задач Control. Эта кнопка не запускает и не повторяет команды.']
        return self._reply('\n'.join(lines), buttons)

    def handle(self, text=None, callback_data=None, *, chat_id, user_id, message_id=None):
        claimed = isinstance(callback_data, str) and callback_data.startswith(('deck:manage:', 'deck:act:'))
        typed = isinstance(text, str) and text.startswith('ПЕРЕЗАПУСТИТЬ') and len(text) <= 128
        if not claimed and not typed:
            return None
        with self.lock:
            try:
                actor = [actor_id(chat_id), actor_id(user_id)]
                if self.storage_error:
                    raise ActionError('Хранилище подтверждений недоступно. Действия заблокированы.')
                if not finite(self.clock()):
                    raise ActionError('Время подтверждения недоступно. Действие заблокировано.')
                if typed and callback_data is None:
                    return self._confirm(text, actor)
                if len(callback_data.encode()) > 64:
                    raise ActionError('Кнопка недоступна. Откройте управление заново.')
                if callback_data == 'deck:act:jobs':
                    return self._status(actor)
                match = re.fullmatch(r'deck:act:job:([a-f0-9]{16})', callback_data)
                if match:
                    return self._status(actor, match[1])
                match = re.fullmatch(r'deck:manage:([A-Za-z0-9_-]{1,40})', callback_data)
                if match:
                    return self._open(match[1], actor, message_id)
                match = re.fullmatch(r'deck:act:([a-f0-9]{16}):(cancel|reboot|page:[0-9]{1,3}|service:[0-9]{1,3})', callback_data)
                if not match:
                    raise ActionError('Кнопка недоступна. Откройте управление заново.')
                token, action = match[1], match[2]
                if type(message_id) is not int or message_id <= 0:
                    raise ActionError('Исходное сообщение не подтверждено. Откройте новое меню.')
                session, _ = self._session(token, actor, message_id=message_id)
                if action == 'cancel':
                    session['state'] = 'cancelled'; self._save()
                    return self._reply('Действие отменено. Команда не отправлялась.')
                if action.startswith('page:'):
                    if session['state'] != 'selection':
                        raise ActionError('Уже ожидается подтверждение. Отмените его, чтобы выбрать другую службу.')
                    return self._selection(token, session, int(action.split(':')[1]))
                if action == 'reboot':
                    return self._plan(token, actor)
                return self._plan(token, actor, int(action.split(':')[1]))
            except ActionError as error:
                return self._reply(str(error))
            except Exception:
                return self._reply('Не удалось проверить действие. Выполнение не подтверждено; откройте панель. Автоматического повтора нет.')
