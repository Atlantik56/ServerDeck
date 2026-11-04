"""Read-only Telegram menu renderer. No network, shell, writes or notifications.

The transport must authenticate the paired private chat before calling handle().
This module receives no chat identity and cannot replace that authorization gate.
Optional management buttons emit routes only. The authorized transport handles
those routes and their confirmations; this renderer never executes an action.
All text is plain text: callers must not enable Telegram Markdown/HTML parsing.
"""
import datetime
import math
import re
import time
import unicodedata
from urllib.parse import urlsplit

SERVER_ID = re.compile(r'[A-Za-z0-9_-]{1,40}')
SERVERS_PER_PAGE = 6
SERVICES_PER_PAGE = 10
TEXT_LIMIT = 3500  # UTF-16 units, leaving room below Telegram's 4096 limit.
MOSCOW = datetime.timezone(datetime.timedelta(hours=3))


def number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def count(value):
    return value if type(value) is int and 0 <= value <= 10 ** 12 else None


def clip(text, limit):
    result = []
    size = 0
    for char in text:
        if unicodedata.category(char) == 'Cs':
            continue
        width = 2 if ord(char) > 0xffff else 1
        if size + width > limit - 1:
            return ''.join(result) + '…'
        result.append(char)
        size += width
    return ''.join(result)


def label(value, fallback='—', limit=80):
    if not isinstance(value, str):
        return fallback
    text = ''.join(' ' if c.isspace() else c for c in value if not unicodedata.category(c).startswith('C') or c.isspace())
    return clip(' '.join(text.split()), limit) or fallback


def percent(value):
    if isinstance(value, dict):
        used, total = value.get('used'), value.get('total')
        if number(used) and number(total) and total > 0 and 0 <= used <= total:
            return used * 100 / total
        return None
    return value if number(value) and 0 <= value <= 100 else None


def pct(value):
    value = percent(value)
    return ('%.1f' % value).rstrip('0').rstrip('.') + '%' if value is not None else 'нет данных'


def stamp(value):
    if not number(value) or value <= 0:
        return 'время неизвестно'
    try:
        return datetime.datetime.fromtimestamp(value, MOSCOW).strftime('%d.%m %H:%M:%S МСК')
    except (OverflowError, ValueError, OSError):
        return 'время неизвестно'


class ReadOnlyBotMenu:
    def __init__(self, servers_fn, health_fn, security_fn=None, origin='', clock=time.time,
                 actions_enabled=False):
        self.servers_fn = servers_fn
        self.health_fn = health_fn
        self.security_fn = security_fn
        self.clock = clock
        self.actions_enabled = actions_enabled is True
        self.origin = ''
        try:
            url = urlsplit(origin)
            if (url.scheme == 'https' and url.hostname and not url.username and not url.password and
                    url.path in ('', '/') and not url.query and not url.fragment and
                    not any(c.isspace() for c in origin)):
                url.port  # Reject malformed/out-of-range ports.
                self.origin = origin.rstrip('/') + '/'
        except (TypeError, ValueError):
            pass

    def _button(self, text, data):
        return {'text': label(text, limit=48), 'callback_data': data}

    def _navigation(self):
        rows = [[self._button('Обзор', 'deck:status'), self._button('Серверы', 'deck:servers')],
                [self._button('Службы', 'deck:services'), self._button('Защита', 'deck:security')]]
        if self.actions_enabled:
            rows.append([self._button('Задачи управления', 'deck:act:jobs')])
        if self.origin:
            rows.append([{'text': 'Открыть панель ↗', 'url': self.origin}])
        return rows

    def _reply(self, text, rows=None):
        return {'text': clip(text, TEXT_LIMIT),
                'reply_markup': {'inline_keyboard': (rows or []) + self._navigation()},
                'disable_web_page_preview': True}

    def _expired(self):
        return self._reply('Кнопка устарела или недоступна. Откройте список серверов заново.')

    def _registry(self):
        try:
            raw = self.servers_fn()
        except Exception:
            return [], 'Реестр серверов сейчас недоступен.'
        if not isinstance(raw, (list, tuple)):
            return [], 'Реестр серверов сейчас недоступен.'
        result, duplicate, invalid = {}, set(), False
        for row in raw:
            if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not SERVER_ID.fullmatch(row['id']):
                invalid = True
                continue
            sid = row['id']
            if sid in result or sid in duplicate:
                result.pop(sid, None)
                duplicate.add(sid)
                invalid = True
                continue
            result[sid] = row
        note = 'Часть записей реестра недоступна.' if invalid else ''
        return list(result.values()), note

    def _health(self):
        try:
            report = self.health_fn()
            if isinstance(report, dict) and isinstance(report.get('servers'), dict):
                return report
        except Exception:
            pass
        return {'servers': {}, '_unavailable': True}

    def _row(self, server, report, now):
        row = report['servers'].get(server['id'])
        row = row if isinstance(row, dict) else {}
        sample = row.get('latest')
        sample = sample if isinstance(sample, dict) else {}
        ts = sample.get('ts')
        threshold = report.get('staleAfterSeconds', 150)
        threshold = threshold if number(threshold) and 1 <= threshold <= 600 else 150
        fresh = bool(number(ts) and ts > 0 and -30 <= now - ts <= threshold and row.get('stale') is not True)
        metrics = all(percent(sample.get(k)) is not None for k in ('cpu', 'memory', 'disk'))
        observed, containers = sample.get('services'), sample.get('containers')
        states = ('active', 'running', 'inactive', 'exited', 'failed', 'activating', 'deactivating', 'reloading')
        services = (isinstance(observed, list) and isinstance(containers, list) and
                    all(isinstance(s, dict) and isinstance(s.get('unit'), str) and s['unit'] and
                        s.get('state') in states and type(s.get('loaded')) is bool for s in observed) and
                    all(isinstance(c, dict) and isinstance(c.get('name'), str) and c['name'] and
                        c.get('state') in states for c in containers))
        configured = server.get('services')
        if services and isinstance(configured, list):
            names = {s['unit'] for s in observed}
            services = all(isinstance(unit, str) and unit in names for unit in configured)
        alerts = sample.get('alerts')
        warning = (sample.get('health') in ('warning', 'critical') or
                   isinstance(alerts, list) and any(isinstance(a, dict) and a.get('level') in ('warning', 'critical') for a in alerts) or
                   isinstance(sample.get('failed'), list) and bool(sample['failed']) or
                   isinstance(observed, list) and any(isinstance(s, dict) and
                   (s.get('state') == 'failed' or s.get('loaded') is False) for s in observed))
        if not sample:
            state, title = 'unknown', 'нет данных'
        elif not fresh:
            state, title = 'stale', 'нет свежих данных'
        elif sample.get('ok') is False:
            state, title = 'failed', 'ошибка SSH-проверки'
        elif sample.get('ok') is not True:
            state, title = 'unknown', 'результат проверки неизвестен'
        elif warning:
            state, title = 'warning', 'есть предупреждения'
        elif not metrics or not services or not isinstance(alerts, list) or sample.get('health') != 'ok':
            state, title = 'partial', 'неполные данные проверки'
        else:
            state, title = 'ok', 'проверка без предупреждений'
        return {'sample': sample, 'fresh': fresh, 'state': state, 'title': title,
                'metrics': metrics, 'services': services, 'threshold': threshold}

    @staticmethod
    def _icon(state):
        return '✅' if state == 'ok' else '❔' if state in ('unknown', 'stale') else '⚠️'

    def _overview(self, servers, note, report, now):
        lines = ['Server Deck · состояние', '']
        if not servers:
            lines.append(note or 'Серверы ещё не добавлены.')
            return self._reply('\n'.join(lines))
        states = [self._row(s, report, now) for s in servers]
        lines += ['Серверов в реестре: ' + str(len(servers)),
                  'Проверка без предупреждений: ' + str(sum(r['state'] == 'ok' for r in states)),
                  'Требуют проверки: ' + str(sum(r['state'] in ('failed', 'warning', 'partial') for r in states)),
                  'Нет свежего результата: ' + str(sum(r['state'] in ('unknown', 'stale') for r in states)), '']
        buttons = []
        for server, row in list(zip(servers, states))[:SERVERS_PER_PAGE]:
            name = label(server.get('name'), server['id'], 48)
            lines.append(self._icon(row['state']) + ' ' + name + ' — ' + row['title'])
            buttons.append([self._button(name, 'deck:server:' + server['id'])])
        if len(servers) > SERVERS_PER_PAGE:
            lines.append('Остальные серверы — в полном списке.')
        lines += ['', 'Это последние измерения, а не непрерывная проверка доступности.']
        if note:
            lines.append(note)
        return self._reply('\n'.join(lines), buttons)

    def _servers(self, servers, note, report, now, page=0, services=False):
        title = 'Выберите сервер · службы' if services else 'Серверы'
        if not servers:
            return self._reply(title + '\n\n' + (note or 'Серверы ещё не добавлены.'))
        pages = (len(servers) + SERVERS_PER_PAGE - 1) // SERVERS_PER_PAGE
        if not 0 <= page < pages:
            return self._expired()
        lines = [title + ' · ' + str(page + 1) + '/' + str(pages), '']
        buttons = []
        for server in servers[page * SERVERS_PER_PAGE:(page + 1) * SERVERS_PER_PAGE]:
            row = self._row(server, report, now)
            name = label(server.get('name'), server['id'], 48)
            lines += [self._icon(row['state']) + ' ' + name, label(server.get('host'), 'адрес неизвестен', 80) + ' · ' + row['title']]
            data = ('deck:services:' + server['id'] + ':0') if services else ('deck:server:' + server['id'])
            buttons.append([self._button(name, data)])
        # Selection pages retain their mode in the callback.
        prefix = 'deck:service_servers:' if services else 'deck:servers:'
        paging = []
        if page:
            paging.append(self._button('← Назад', prefix + str(page - 1)))
        if page + 1 < pages:
            paging.append(self._button('Далее →', prefix + str(page + 1)))
        if paging:
            buttons.append(paging)
        if note:
            lines += ['', note]
        return self._reply('\n'.join(lines), buttons)

    def _server(self, server, report, now):
        row = self._row(server, report, now)
        sample = row['sample']
        lines = [label(server.get('name'), server['id']), label(server.get('host'), 'адрес неизвестен'), '',
                 self._icon(row['state']) + ' ' + row['title'].capitalize(),
                 'Последний замер: ' + stamp(sample.get('ts'))]
        if not row['fresh']:
            lines.append('Текущее состояние неизвестно; ниже только сохранённый замер.')
        if sample.get('ok') is True:
            interval = sample.get('cpuIntervalSeconds')
            cpu = pct(sample.get('cpu'))
            if number(interval) and 0 < interval < 300:
                cpu += ' · интервал ' + ('%.2f' % interval).rstrip('0').rstrip('.') + ' с'
            lines += ['', 'ЦП: ' + cpu, 'ОЗУ: ' + pct(sample.get('memory')), 'Диск: ' + pct(sample.get('disk'))]
            if not row['metrics']:
                lines.append('Часть метрик не получена.')
            awg = sample.get('awg')
            if isinstance(awg, list):
                lines.append('')
                if not awg:
                    lines.append('AWG: интерфейсы не обнаружены в этом замере.')
                for item in awg[:6]:
                    if not isinstance(item, dict):
                        continue
                    peers, online = count(item.get('peers')), count(item.get('online'))
                    value = (str(online) + '/' + str(peers)) if peers is not None and online is not None and online <= peers else 'нет данных'
                    lines.append('AWG ' + label(item.get('interface'), limit=32) + ': ' + value + ' · handshake за 3 мин')
                if len(awg) > 6:
                    lines.append('Остальные интерфейсы — в панели.')
            if sample.get('rebootRequired') is True:
                lines += ['', 'ОС отмечает необходимость перезагрузки. Никаких действий не выполнялось.']
        elif sample:
            lines += ['', 'Ресурсы и службы в этой проверке не подтверждены.']
        buttons = [[self._button('Службы этого сервера', 'deck:services:' + server['id'] + ':0')],
                   [self._button('Обновить статус', 'deck:server:' + server['id'])]]
        if self.actions_enabled:
            buttons.append([self._button('Управление сервером', 'deck:manage:' + server['id'])])
        return self._reply('\n'.join(lines), buttons)

    @staticmethod
    def _service_state(item):
        if item is None:
            return 'нет замера'
        if item.get('loadState') == 'not-found':
            return 'не найдена'
        if item.get('loaded') is False:
            return 'не найдена или не загружена'
        state = item.get('state')
        if not isinstance(state, str):
            return 'состояние неизвестно'
        return {'active': 'работает', 'running': 'работает', 'inactive': 'остановлена',
                'exited': 'остановлена', 'failed': 'ошибка', 'activating': 'запускается',
                'deactivating': 'останавливается', 'reloading': 'перезагружается'}.get(state, 'состояние неизвестно')

    def _service_rows(self, server, sample):
        observed = {}
        service_list = sample.get('services')
        if isinstance(service_list, list):
            for item in service_list[:1000]:
                if isinstance(item, dict) and isinstance(item.get('unit'), str) and item['unit']:
                    observed[item['unit']] = item
        configured = server.get('services')
        configured = configured if isinstance(configured, list) else []
        units = list(dict.fromkeys(u for u in configured[:1000] if isinstance(u, str) and u))
        units += [u for u in observed if u not in units]
        result = [(label(unit, limit=100), self._service_state(observed.get(unit))) for unit in units]
        containers = sample.get('containers')
        if isinstance(containers, list):
            for item in containers[:1000]:
                if not isinstance(item, dict) or not isinstance(item.get('name'), str):
                    continue
                if 'docker:' + item['name'] in units:
                    continue
                result.append(('Docker · ' + label(item['name'], limit=90), self._service_state(item)))
        return result

    def _services(self, server, report, now, page):
        row = self._row(server, report, now)
        sample = row['sample']
        services = self._service_rows(server, sample)
        pages = max(1, (len(services) + SERVICES_PER_PAGE - 1) // SERVICES_PER_PAGE)
        if not 0 <= page < pages:
            return self._expired()
        lines = ['Службы · ' + label(server.get('name'), server['id'], 60),
                 'Страница ' + str(page + 1) + '/' + str(pages),
                 'Замер: ' + stamp(sample.get('ts')), '']
        if not row['fresh']:
            lines.append('Нет свежих данных. Состояния ниже относятся только к сохранённому замеру.')
        elif sample.get('ok') is not True:
            lines.append('SSH-проверка неуспешна: состояние служб не подтверждено.')
        if not row['services']:
            lines.append('Список служб или контейнеров получен не полностью.')
        if any(isinstance(items, list) and len(items) > 1000 for items in
               (server.get('services'), sample.get('services'), sample.get('containers'))):
            lines.append('Каждый исходный список ограничен первыми 1000 записями; полный список — в панели.')
        if services:
            lines += ['', *[name + ' — ' + state for name, state in services[page * SERVICES_PER_PAGE:(page + 1) * SERVICES_PER_PAGE]]]
        else:
            lines += ['', 'Наблюдаемых служб в этом замере нет. Это не доказывает отсутствие работающих сервисов.']
        lines += ['', 'Показаны службы из мониторинга и обнаруженные контейнеры. Остановленная служба не обязательно означает неисправность.']
        buttons = []
        paging = []
        if page:
            paging.append(self._button('← Назад', 'deck:services:' + server['id'] + ':' + str(page - 1)))
        if page + 1 < pages:
            paging.append(self._button('Далее →', 'deck:services:' + server['id'] + ':' + str(page + 1)))
        if paging:
            buttons.append(paging)
        buttons.append([self._button('К серверу', 'deck:server:' + server['id'])])
        if self.actions_enabled:
            buttons.append([self._button('Управление сервером', 'deck:manage:' + server['id'])])
        return self._reply('\n'.join(lines), buttons)

    def _security(self, servers, now):
        try:
            summary = self.security_fn() if self.security_fn else None
        except Exception:
            summary = None
        if not isinstance(summary, dict):
            return self._reply('Защита · наблюдения\n\nСводка защиты сейчас недоступна. Состояние защиты не подтверждено.')
        raw = summary.get('servers')
        if isinstance(raw, dict):
            rows = {sid: row for sid, row in raw.items() if isinstance(row, dict)}
        elif isinstance(raw, list):
            rows = {row['id']: row for row in raw if isinstance(row, dict) and isinstance(row.get('id'), str)}
        else:
            rows = {}
        lines = ['Защита · наблюдения', '']
        if not servers:
            lines.append('Нет доступных записей реестра серверов.')
        for server in servers[:12]:
            row = rows.get(server['id'], {})
            ts = row.get('checkedAt')
            fresh = number(ts) and -30 <= now - ts <= 300 and row.get('ok') is True and row.get('stale') is not True
            lines.append(label(server.get('name'), server['id'], 60))
            if not fresh:
                lines.append('Нет свежей успешной проверки · ' + stamp(ts))
                continue
            failed, bans = count(row.get('failedPassword10m')), count(row.get('activeSharedBans'))
            lines.append('Отказы SSH за 10 мин: ' + (str(failed) if failed is not None else 'нет данных'))
            lines.append('Действующие общие блокировки: ' + (str(bans) if bans is not None else 'нет данных'))
            lines.append('Замер: ' + stamp(ts))
        if len(servers) > 12:
            lines.append('Остальные серверы — в панели.')
        generated = summary.get('generatedAt')
        totals = summary.get('totals')
        totals = totals if isinstance(totals, dict) else {}
        new_bans = count(totals.get('newSharedBans10m'))
        if number(generated) and -30 <= now - generated <= 300 and new_bans is not None:
            lines += ['', 'Новых общих блокировок за 10 мин: ' + str(new_bans)]
        else:
            lines += ['', 'Общая статистика блокировок: нет свежих данных.']
        if number(summary.get('newestEventAt')):
            lines.append('Последнее событие: ' + stamp(summary['newestEventAt']))
        lines += ['', 'Это наблюдаемые события и счётчики; они не устанавливают личность или цель источника.']
        return self._reply('\n'.join(lines))

    def handle(self, text=None, callback_data=None):
        """Render a response only. Caller must authorize chat/user before calling."""
        try:
            action, sid, page = None, None, 0
            if callback_data is not None:
                if not isinstance(callback_data, str) or len(callback_data.encode('utf-8')) > 64:
                    return self._expired()
                if callback_data in ('deck:menu', 'deck:status', 'deck:servers', 'deck:services', 'deck:security'):
                    action = callback_data.split(':')[1]
                else:
                    match = re.fullmatch(r'deck:(servers|service_servers):([0-9]{1,4})', callback_data)
                    server_match = re.fullmatch(r'deck:server:([A-Za-z0-9_-]{1,40})', callback_data)
                    services_match = re.fullmatch(r'deck:services:([A-Za-z0-9_-]{1,40}):([0-9]{1,4})', callback_data)
                    if match:
                        action, page = match[1], int(match[2])
                    elif server_match:
                        action, sid = 'server', server_match[1]
                    elif services_match:
                        action, sid, page = 'server_services', services_match[1], int(services_match[2])
                    else:
                        return self._expired()
            elif isinstance(text, str):
                match = re.fullmatch(r'/(menu|status|servers|services|security|start)(?:@[A-Za-z0-9_]{1,64})?\s*', text.strip())
                if not match:
                    return None
                action = 'menu' if match[1] == 'start' else match[1]
            else:
                return None
            servers, note = self._registry()
            now = self.clock()
            if not number(now):
                return self._reply('Сводка сейчас недоступна. Время проверки не подтверждено.')
            if action == 'security':
                return self._security(servers, now)
            server = next((s for s in servers if s['id'] == sid), None) if sid else None
            if sid and server is None:
                return self._expired()
            report = self._health()
            if action in ('menu', 'status'):
                return self._overview(servers, note, report, now)
            if action in ('servers', 'services', 'service_servers'):
                return self._servers(servers, note, report, now, page, action != 'servers')
            if action == 'server':
                return self._server(server, report, now)
            if action == 'server_services':
                return self._services(server, report, now, page)
            return self._expired()
        except Exception:
            return self._reply('Не удалось прочитать сводку. Попробуйте позже или откройте панель.')
