"""Telegram delivery for measured server health; no credentials enter API status.

Only fresh, distinct samples advance confirmation counters. No-peer AWG states
and services that were already stopped at baseline do not imply an outage.
"""
import copy
import datetime
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
import urllib.error
import urllib.request


DEFAULT_CONFIG = {
    'enabled': False, 'criticalOnly': False, 'cpuThreshold': 85, 'memoryThreshold': 85,
    'diskThreshold': 80, 'outageConsecutive': 2, 'resourceConsecutive': 3,
    'recoveryConsecutive': 2, 'resources': True, 'services': True,
    'awg': True, 'awgRx': False, 'reboot': False, 'remindersMinutes': 0,
    'security': True, 'securityFailedThreshold': 30, 'securityBanThreshold': 20,
    'securityPacketThreshold': 1000,
    'securityConsecutive': 2, 'securityCooldownMinutes': 60, 'securityDigestHours': 6,
}
TOKEN_RE = re.compile(r'[0-9]{5,20}:[A-Za-z0-9_-]{30,80}')
UNIT_RE = re.compile(r'[A-Za-z0-9@_.:\-]{1,120}')
BOOLEAN_KEYS = {'enabled', 'criticalOnly', 'resources', 'services', 'awg', 'awgRx', 'reboot', 'security'}
SECURITY_KEYS = {'security', 'securityFailedThreshold', 'securityBanThreshold',
                 'securityPacketThreshold', 'securityConsecutive', 'securityCooldownMinutes', 'securityDigestHours'}
AWG_RX_COOLDOWN = 3600
CRITICAL_NOTICE_TTL = 900
RELEASE_CVE = 'CVE-2026-98432'
RELEASE_SOURCE = 'https://ubuntu.com/security/cves/' + RELEASE_CVE + '.json'
RELEASE_PAGE = 'https://ubuntu.com/security/' + RELEASE_CVE
RELEASE_TERMINAL = {'sent', 'failed', 'uncertain', 'expired', 'cancelled'}


def is_critical_rule(key):
    """Explicit data-plane allowlist; helper/panel names never imply an outage."""
    if not isinstance(key, str):
        return False
    if key in ('ssh', 'app:awg', 'app:mtproxyl'):
        return True
    if key.startswith('awg-container:') and key.endswith(':missing'):
        return is_awg_container(key[len('awg-container:'):-len(':missing')])
    if re.fullmatch(r'awg:[A-Za-z0-9@_.:\-]{1,120}:missing', key):
        return True
    if key.startswith('service:'):
        unit = key[len('service:'):]
        return bool(unit in {'mtproxyl.service', 'mtproxyl-telemt.service', 'telemt.service', 'mtproxy.service'} or
                    re.fullmatch(r'(?:telemt|mtproxyl)@[A-Za-z0-9_.:\-]{1,100}\.service', unit) or
                    re.fullmatch(r'awg-quick@[A-Za-z0-9_.:\-]{1,100}\.service', unit) or
                    re.fullmatch(r'amnezia(?:-?awg|wg)[0-9]*(?:@[A-Za-z0-9_.:\-]{1,80})?\.service', unit))
    if key.startswith('container:'):
        name = key[len('container:'):]
        return bool(re.fullmatch(r'(?:mtproxyl|mtproxyl-telemt|mtproxy|telemt)(?:[-_][0-9]+)?', name) or
                    is_awg_container(name))
    return False


def is_awg_container(name):
    return isinstance(name, str) and re.fullmatch(r'amnezia[-_]?awg[A-Za-z0-9_.\-]{0,80}', name.lower()) is not None


def critical_category(key):
    if not is_critical_rule(key):
        return None
    if key in ('ssh', 'app:awg', 'app:mtproxyl'):
        return key
    if key.startswith(('awg:', 'awg-container:')):
        return 'app:awg'
    name = key.split(':', 1)[1]
    return 'app:awg' if name.startswith(('awg-quick@', 'amnezia')) or is_awg_container(name) else 'app:mtproxyl'


def security_state():
    return {'baselineAt': None, 'lastSampleAt': None, 'lastEventAt': None,
            'lastNoticeAt': None, 'digestStartedAt': None, 'previous': {},
            'previousBans': 0, 'bad': 0, 'activity': False, 'pendingActivity': False,
            'peakFailed': {}, 'peakBans': 0, 'proofs': {}, 'lastError': '', 'lastCheckAt': None}


class AlertError(ValueError):
    pass


class DeliveryError(AlertError):
    def __init__(self, code=0, retry_after=0):
        self.code = int(code) if isinstance(code, (int, float)) else 0
        self.retry_after = max(0, min(3600, int(retry_after))) if finite(retry_after) else 0
        message = 'Telegram временно недоступен.'
        if self.code == 401:
            message = 'Telegram отклонил токен бота.'
        elif self.code == 403:
            message = 'Бот не может отправить сообщение в выбранный чат.'
        elif self.code == 409:
            message = 'Telegram сообщает о другом получателе обновлений этого бота.'
        elif self.code == 429:
            message = 'Telegram ограничил частоту запросов; отправка будет повторена.'
        super().__init__(message)


def clean(value, limit=140):
    text = str(value or '')
    text = ''.join(c for c in text if c >= ' ' or c == '\n')
    text = TOKEN_RE.sub('[скрыто]', text)
    text = re.sub(r'(https?://)[^\s/@]+:[^\s/@]+@', r'\1[скрыто]@', text)
    return text.strip()[:limit]


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def percent(value):
    if isinstance(value, dict) and finite(value.get('used')) and finite(value.get('total')) and value['total'] > 0:
        return value['used'] / value['total'] * 100
    return None


class TelegramClient:
    def __init__(self, token_path):
        self.token_path = pathlib.Path(token_path)

    def token(self):
        try:
            value = self.token_path.read_text().strip()
        except OSError:
            raise AlertError('Токен Telegram-бота не настроен.') from None
        if not TOKEN_RE.fullmatch(value):
            raise AlertError('Формат токена Telegram-бота неверен.')
        return value

    def configured(self):
        try:
            self.token()
            return True
        except AlertError:
            return False

    def call(self, method, data=None):
        if method not in {'getMe', 'getWebhookInfo', 'getUpdates', 'sendMessage',
                          'answerCallbackQuery', 'editMessageText', 'setMyCommands', 'setChatMenuButton'}:
            raise AlertError('Неизвестный метод Telegram.')
        # Never interpolate this URL into an exception, log, API response or argv.
        request = urllib.request.Request(
            'https://api.telegram.org/bot' + self.token() + '/' + method,
            data=json.dumps(data or {}).encode(), headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                raw = response.read(2 * 1024 * 1024)
                result = json.loads(raw)
        except urllib.error.HTTPError as error:
            retry = 0
            try:
                body = json.loads(error.read(16384))
                if method == 'editMessageText' and error.code == 400 and 'message is not modified' in str(body.get('description', '')).lower():
                    return True
                retry = body.get('parameters', {}).get('retry_after', 0)
            except (ValueError, TypeError, AttributeError):
                pass
            raise DeliveryError(error.code, retry) from None
        except (OSError, ValueError, TypeError):
            raise DeliveryError() from None
        if not isinstance(result, dict) or result.get('ok') is not True:
            code = result.get('error_code', 0) if isinstance(result, dict) else 0
            params = result.get('parameters') or {} if isinstance(result, dict) else {}
            raise DeliveryError(code, params.get('retry_after', 0))
        return result.get('result')


class AlertManager:
    def __init__(self, root, servers_fn, health_fn, token_path=None, transport=None, clock=time.time,
                 security_fn=None, bot_menu=None, bot_actions=None, security_release_fn=None):
        self.root = pathlib.Path(root) / 'telegram-alerts'
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.root / 'state.json'
        self.clock = clock
        self.servers_fn = servers_fn
        self.health_fn = health_fn
        self.security_fn = security_fn
        self.bot_menu = bot_menu
        self.bot_actions = bot_actions
        self.security_release_fn = security_release_fn
        self.next_release_scan = 0
        self.release_eligible = set()
        self.release_eligible_until = 0
        self.next_health_scan = 0
        self.next_security_scan = 0
        token_path = token_path or os.environ.get('DECK_TELEGRAM_TOKEN_FILE', '/var/lib/serverdeck/telegram.token')
        self.client = TelegramClient(token_path)
        self.transport = transport or self.client.call
        self.lock = threading.RLock()
        self.tick_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.action_lock = threading.RLock()
        self.storage_error = False
        self.state = {'version': 1, 'config': dict(DEFAULT_CONFIG), 'bot': None, 'chat': None,
                      'pairing': None, 'offset': 0, 'rules': {}, 'expectedServices': {},
                      'expectedContainers': {}, 'expectedAwg': {}, 'firstObserved': {},
                      'lastSampleAt': {}, 'awgRxPolicy': 1, 'awgRxLastNotice': {},
                      'securityState': security_state(),
                      'securityReleaseEvents': {},
                      'menuState': {'recent': [], 'lastPollAt': None, 'lastInteractionAt': None,
                                    'lastError': '', 'nextPollAt': 0, 'publishedAt': None},
                      'queue': [], 'history': [], 'nextSendAt': 0, 'lastSentAt': None,
                      'lastError': '', 'lastCheckAt': None}
        pristine = copy.deepcopy(self.state)
        if self.path.exists():
            try:
                if self.path.stat().st_size > 2 * 1024 * 1024:
                    raise ValueError()
                stored = json.loads(self.path.read_text())
                if not isinstance(stored, dict) or stored.get('version') != 1:
                    raise ValueError()
                policy = stored.get('awgRxPolicy', 0)
                if type(policy) is not int or policy not in (0, 1):
                    raise ValueError()
                for key in self.state:
                    if key in stored:
                        self.state[key] = stored[key]
                self.state['config'] = self._validate_config(self.state['config'], initial=True)
                if not all(isinstance(self.state[k], dict) for k in ('rules', 'expectedServices', 'expectedContainers', 'expectedAwg', 'firstObserved', 'lastSampleAt')):
                    raise ValueError()
                if not isinstance(self.state['queue'], list) or len(self.state['queue']) > 256 or not isinstance(self.state['history'], list):
                    raise ValueError()
                self._validate_nested()
                if self.state['config']['criticalOnly']:
                    self._filter_critical_policy()
                    self._save()
                if policy == 0:
                    # The former policy treated any RX increment as an outage.
                    # Retire only those incidents, without clearing real faults.
                    self._reset_awg_rx()
                    self.state['config']['awgRx'] = False
                    self.state['awgRxPolicy'] = 1
                    self._save()
                # A crash after Telegram accepted a message cannot be safely
                # retried automatically: Telegram has no idempotency key.
                interrupted = [q for q in self.state['queue'] if q.get('phase') == 'sending']
                for q in interrupted:
                    if q['kind'] != 'menu':
                        self._history(q, 'uncertain')
                        self._mark_critical_uncertain(q)
                        self._finish_release(q, 'uncertain')
                self.state['queue'] = [q for q in self.state['queue'] if q.get('phase') != 'sending']
                if any(q['kind'] != 'menu' for q in interrupted):
                    self.state['lastError'] = 'Результат одной отправки после перезапуска неизвестен; автоматического повтора нет.'
                if interrupted:
                    self._save()
                self._retire_finished_aggregates()
                if self._prune_release_queue():
                    self._save()
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                self.state = pristine
                self.storage_error = True
                self.state['config']['enabled'] = False
                self.state['lastError'] = 'Файл настроек Telegram повреждён. Сохраните настройки заново; уведомления приостановлены.'

    def _validate_nested(self):
        def text(value, limit=4096):
            return isinstance(value, str) and len(value) <= limit

        if type(self.state['offset']) is not int or self.state['offset'] < 0:
            raise ValueError()
        for key in ('lastSentAt', 'lastCheckAt'):
            if self.state[key] is not None and not finite(self.state[key]):
                raise ValueError()
        if not finite(self.state['nextSendAt']) or not text(self.state['lastError']):
            raise ValueError()
        security = self.state['securityState']
        if not isinstance(security, dict) or set(security) != set(security_state()):
            raise ValueError()
        for key in ('baselineAt', 'lastSampleAt', 'lastEventAt', 'lastNoticeAt', 'digestStartedAt', 'lastCheckAt'):
            if security[key] is not None and not finite(security[key]):
                raise ValueError()
        for key in ('previousBans', 'peakBans', 'bad'):
            if type(security[key]) is not int or security[key] < 0:
                raise ValueError()
        if (type(security['activity']) is not bool or type(security['pendingActivity']) is not bool or
                not text(security['lastError']) or not isinstance(security['previous'], dict) or
                not isinstance(security['peakFailed'], dict)):
            raise ValueError()
        for rows in (security['previous'], security['peakFailed']):
            if len(rows) > 256 or not all(text(k, 200) and isinstance(v, dict) and
                                         type(v.get('count')) is int and v['count'] >= 0 and
                                         text(v.get('name'), 100) and text(v.get('host'), 100) and
                                         (v.get('packets') is None or finite(v['packets']) and v['packets'] >= 0) and
                                         ('checkedAt' not in v or finite(v['checkedAt'])) for k, v in rows.items()):
                raise ValueError()
        if security['baselineAt'] is not None and security['digestStartedAt'] is None:
            raise ValueError()
        if not isinstance(security['proofs'], dict) or len(security['proofs']) > 513:
            raise ValueError()
        for key, proof in security['proofs'].items():
            if (not text(key, 250) or not isinstance(proof, dict) or
                    type(proof.get('bad')) is not int or proof['bad'] < 0 or
                    type(proof.get('armed')) is not bool or
                    proof.get('lastAt') is not None and not finite(proof['lastAt'])):
                raise ValueError()
        menu = self.state['menuState']
        if (not isinstance(menu, dict) or not isinstance(menu.get('recent'), list) or len(menu['recent']) > 3 or
                not all(finite(t) for t in menu['recent']) or not text(menu.get('lastError')) or
                not finite(menu.get('nextPollAt')) or any(menu.get(k) is not None and not finite(menu[k])
                                                       for k in ('lastPollAt', 'lastInteractionAt', 'publishedAt'))):
            raise ValueError()
        bot = self.state['bot']
        if bot is not None and (not isinstance(bot, dict) or not text(bot.get('username'), 64) or
                                not re.fullmatch(r'[A-Za-z0-9_]{5,64}', bot['username']) or type(bot.get('id')) is not int):
            raise ValueError()
        chat = self.state['chat']
        if chat is not None and (not isinstance(chat, dict) or not text(chat.get('id'), 24) or
                                 not re.fullmatch(r'-?\d{1,20}', chat['id']) or
                                 chat.get('type') not in ('private', 'group', 'supergroup') or not text(chat.get('title'), 200)):
            raise ValueError()
        pairing = self.state['pairing']
        if pairing is not None:
            if (not isinstance(pairing, dict) or not text(pairing.get('code'), 32) or
                    not re.fullmatch(r'[a-f0-9]{32}', pairing['code']) or
                    not finite(pairing.get('createdAt')) or not finite(pairing.get('expiresAt')) or
                    not 0 < pairing['expiresAt'] - pairing['createdAt'] <= 1800):
                raise ValueError()
            if 'blocked' in pairing and type(pairing['blocked']) is not bool:
                raise ValueError()
            if 'error' in pairing and not text(pairing['error']):
                raise ValueError()
        for key in ('firstObserved', 'lastSampleAt'):
            if not all(text(k, 200) and finite(v) for k, v in self.state[key].items()):
                raise ValueError()
        if (type(self.state['awgRxPolicy']) is not int or self.state['awgRxPolicy'] not in (0, 1) or
                not isinstance(self.state['awgRxLastNotice'], dict) or
                not all(text(k, 500) and finite(v) and v >= 0 for k, v in self.state['awgRxLastNotice'].items())):
            raise ValueError()
        for key in ('expectedServices', 'expectedContainers', 'expectedAwg'):
            if not all(text(k, 200) and isinstance(v, dict) and
                       all(text(n, 200) and type(flag) is bool for n, flag in v.items()) for k, v in self.state[key].items()):
                raise ValueError()
        for key, rule in self.state['rules'].items():
            if not text(key, 500) or not isinstance(rule, dict):
                raise ValueError()
            if not all(text(rule.get(k), 500) for k in ('server', 'serverName', 'host', 'rule', 'title', 'detail')):
                raise ValueError()
            if not all(type(rule.get(k)) is bool for k in ('active', 'notified')):
                raise ValueError()
            if 'deliveryUncertain' in rule and type(rule['deliveryUncertain']) is not bool:
                raise ValueError()
            if not all(type(rule.get(k)) is int and rule[k] >= 0 for k in ('bad', 'good', 'event')):
                raise ValueError()
            if rule.get('lastTs') is not None and not finite(rule['lastTs']) and not text(rule['lastTs'], 100):
                raise ValueError()
            if rule.get('since') is not None and not finite(rule['since']) or not finite(rule.get('lastSentAt')):
                raise ValueError()
        ledger = self.state['securityReleaseEvents']
        if not isinstance(ledger, dict) or len(ledger) > 512:
            raise ValueError()
        for key, record in ledger.items():
            if (not isinstance(key, str) or not re.fullmatch(r'[a-f0-9]{64}', key) or not isinstance(record, dict) or
                    record.get('status') not in RELEASE_TERMINAL | {'pending'} or
                    not all(finite(record.get(k)) for k in ('createdAt', 'updatedAt', 'expiresAt')) or
                    not isinstance(record.get('recipient'), str) or not re.fullmatch(r'[a-f0-9]{64}', record['recipient']) or
                    not isinstance(record.get('queueId'), str) or not re.fullmatch(r'[a-f0-9]{24}', record['queueId'])):
                raise ValueError()
        kinds = {'test', 'pairing', 'alarm', 'recovery', 'reminder', 'security', 'security_digest', 'menu', 'security_release'}
        for item in self.state['queue']:
            if (not isinstance(item, dict) or not text(item.get('id'), 24) or item.get('kind') not in kinds or
                    not text(item.get('text'), 3500) or not text(item.get('title'), 140) or
                    type(item.get('attempts')) is not int or not 0 <= item['attempts'] <= 5 or
                    not finite(item.get('due')) or item.get('phase') not in ('pending', 'sending')):
                raise ValueError()
            rule = item.get('rule')
            if rule is not None and (not isinstance(rule, dict) or not text(rule.get('id'), 500) or type(rule.get('event')) is not int):
                raise ValueError()
            if item['kind'] == 'menu':
                if (not finite(item.get('expiresAt')) or not isinstance(item.get('replyMarkup'), dict) or
                        item.get('editMessageId') is not None and type(item['editMessageId']) is not int):
                    raise ValueError()
            if item['kind'] in ('security', 'security_digest') and not finite(item.get('expiresAt')):
                raise ValueError()
            if 'expiresAt' in item and not finite(item['expiresAt']):
                raise ValueError()
            if item['kind'] == 'security_release':
                record = ledger.get(item.get('releaseId'))
                if (not record or record['status'] != 'pending' or record['queueId'] != item['id'] or
                        item.get('recipient') != record['recipient'] or not finite(item.get('expiresAt')) or
                        item.get('expiresAt') != record['expiresAt'] or item.get('rule') is not None or item.get('server') is not None):
                    raise ValueError()
        if len(self.state['history']) > 50:
            raise ValueError()
        for item in self.state['history']:
            if (not isinstance(item, dict) or not text(item.get('id'), 24) or not finite(item.get('time')) or
                    item.get('kind') not in kinds or item.get('status') not in ('sent', 'failed', 'uncertain') or
                    not text(item.get('title'), 140)):
                raise ValueError()

    def _save(self):
        if self.storage_error:
            return
        fd, name = tempfile.mkstemp(prefix='.telegram-', dir=str(self.root))
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

    def _validate_config(self, changes, initial=False):
        if not isinstance(changes, dict) or set(changes) - set(DEFAULT_CONFIG):
            raise AlertError('Неизвестные настройки уведомлений.')
        config = dict(DEFAULT_CONFIG if initial else self.state['config'])
        for key, value in changes.items():
            if key in BOOLEAN_KEYS:
                if type(value) is not bool:
                    raise AlertError('Переключатели уведомлений должны быть включены или выключены.')
            elif key in ('securityFailedThreshold', 'securityBanThreshold'):
                if type(value) is not int or not 10 <= value <= 100000:
                    raise AlertError('Порог SSH-активности: целое число от 10 до 100000 за 10 минут.')
            elif key == 'securityPacketThreshold':
                if type(value) is not int or not 100 <= value <= 10000000:
                    raise AlertError('Порог отброшенных новых SSH-пакетов: от 100 до 10000000 в минуту.')
            elif key == 'securityConsecutive':
                if type(value) is not int or not 2 <= value <= 10:
                    raise AlertError('SSH-активность подтверждается минимум двумя свежими проверками.')
            elif key == 'securityCooldownMinutes':
                if type(value) is not int or not 60 <= value <= 1440:
                    raise AlertError('Интервал уведомлений SSH должен быть от 60 до 1440 минут.')
            elif key == 'securityDigestHours':
                if type(value) is not int or value != 0 and not 6 <= value <= 168:
                    raise AlertError('Сводка SSH: 0 — выключена, либо от 6 до 168 часов.')
            elif key.endswith('Threshold'):
                if not finite(value) or not 1 <= value <= 100:
                    raise AlertError('Порог ресурса должен быть от 1 до 100%.')
            elif key.endswith('Consecutive'):
                if type(value) is not int or not 1 <= value <= 10:
                    raise AlertError('Число подтверждений должно быть от 1 до 10.')
            elif key == 'remindersMinutes':
                if type(value) is not int or value != 0 and not 15 <= value <= 1440:
                    raise AlertError('Повтор: 0 — выключен, либо от 15 до 1440 минут.')
            config[key] = value
        if config['criticalOnly']:
            config.update(resources=False, services=True, awg=True, awgRx=False,
                          reboot=False, security=False, remindersMinutes=0,
                          outageConsecutive=2, recoveryConsecutive=2)
        return config

    def configure(self, changes):
        with self.lock:
            config = self._validate_config(changes)
            if config['enabled'] and not self.state['chat']:
                raise AlertError('Сначала подключите чат Telegram.')
            changed = {key for key in config if config[key] != self.state['config'][key]}
            self.state['config'] = config
            health_changed = changed - SECURITY_KEYS
            if changed & SECURITY_KEYS:
                self._reset_security()
            if config['criticalOnly'] or 'criticalOnly' in changed:
                # A preset is a delivery policy, not a new observation. Keep
                # existing critical incident and recovery state/baselines.
                if config['criticalOnly']:
                    self._filter_critical_policy()
                else:
                    pending = {(item.get('rule') or {}).get('id') for item in self.state['queue']}
                    self.state['rules'] = {key: rule for key, rule in self.state['rules'].items()
                                           if rule['rule'] not in ('app:awg', 'app:mtproxyl') or rule['active'] or key in pending}
            elif health_changed == {'awgRx'}:
                self._reset_awg_rx()
            elif health_changed:
                # Changed thresholds/classes begin a fresh confirmation period;
                # do not send delayed messages under the previous policy.
                self.state['rules'] = {}
                self.state['expectedServices'] = {}
                self.state['expectedContainers'] = {}
                self.state['expectedAwg'] = {}
                self.state['queue'] = [q for q in self.state['queue'] if q.get('kind') in ('pairing', 'test', 'menu', 'security', 'security_digest', 'security_release')]
            if 'enabled' in changed:
                self._reset_security()
            self.storage_error = False
            self._save()
        return self.status()

    def _critical_item(self, item):
        reference = item.get('rule') or {}
        rule = self.state['rules'].get(reference.get('id'), {})
        return item.get('kind') in ('alarm', 'recovery') and is_critical_rule(rule.get('rule'))

    def _filter_critical_policy(self):
        grouped = {}
        for key, rule in self.state['rules'].items():
            category = critical_category(rule['rule'])
            if category:
                grouped.setdefault(str(rule['server']) + '|' + category, []).append((key, rule))
        rules, aliases = {}, {}
        for target, members in grouped.items():
            category = target.split('|', 1)[1]
            chosen = next((rule for key, rule in members if key == target), None)
            chosen = chosen or max((rule for _, rule in members), key=lambda r: (r['active'], r['notified']))
            merged = copy.deepcopy(chosen)
            if len(members) > 1 or members[0][0] != target:
                active = [rule for _, rule in members if rule['active']]
                merged.update(rule=category, active=bool(active), notified=any(r['notified'] for r in active),
                              bad=max((r['bad'] for r in active), default=0), good=0,
                              event=max(r['event'] for _, r in members),
                              deliveryUncertain=any(r.get('deliveryUncertain', False) for r in active))
                if active:
                    merged['since'] = min((r['since'] for r in active if finite(r['since'])), default=None)
                merged['lastTs'] = max((r['lastTs'] for _, r in members if finite(r['lastTs'])), default=None)
                if category.startswith('app:'):
                    merged['title'] = 'AWG недоступен' if category == 'app:awg' else 'MTProxyL недоступен'
                    merged['detail'] = clean('; '.join(sorted({r['rule'] for _, r in members})), 400)
            rules[target] = merged
            aliases.update({key: target for key, _ in members})
        self.state['rules'] = rules
        queue, seen = [], set()
        for item in self.state['queue']:
            if item['kind'] in ('test', 'pairing', 'menu', 'security_release'):
                queue.append(item)
                continue
            reference = item.get('rule') or {}
            target = aliases.get(reference.get('id'))
            rule = rules.get(target)
            if not rule or item['kind'] not in ('alarm', 'recovery'):
                continue
            if reference.get('id') == target and reference.get('event') != rule['event']:
                continue
            if item['kind'] == 'alarm' and (not rule['active'] or rule['notified']):
                continue
            if item['kind'] == 'recovery' and rule['active']:
                continue
            marker = (target, item['kind'])
            if marker in seen:
                continue
            seen.add(marker)
            item['rule'] = {'id': target, 'event': rule['event']}
            item.setdefault('expiresAt', self.clock() + CRITICAL_NOTICE_TTL)
            queue.append(item)
        self.state['queue'] = queue

    @staticmethod
    def _is_awg_rx(rule_id):
        return isinstance(rule_id, str) and re.fullmatch(r'[^|]+\|awg:[^|]+:rx', rule_id) is not None

    def _reset_awg_rx(self):
        for key, rule in list(self.state['rules'].items()):
            if self._is_awg_rx(key):
                sent = rule.get('lastSentAt')
                if finite(sent) and sent > 0:
                    self.state['awgRxLastNotice'][key] = max(sent, self.state['awgRxLastNotice'].get(key, 0))
                del self.state['rules'][key]
        self.state['queue'] = [q for q in self.state['queue']
                               if not self._is_awg_rx((q.get('rule') or {}).get('id'))]

    def status(self):
        with self.lock:
            pairing = copy.deepcopy(self.state['pairing'])
            if pairing:
                if pairing['expiresAt'] <= self.clock():
                    pairing = None
                else:
                    code = pairing['code']
                    pairing['command'] = '/deck ' + code
                    username = (self.state['bot'] or {}).get('username')
                    pairing['startUrl'] = 'https://t.me/' + username + '?start=deck_' + code if username else None
            active = []
            for rule in self.state['rules'].values():
                if rule.get('active'):
                    active.append({k: rule.get(k) for k in ('server', 'serverName', 'host', 'rule', 'title', 'detail', 'since', 'notified')})
            return {'configured': self.client.configured(), 'enabled': self.state['config']['enabled'],
                    'bot': copy.deepcopy(self.state['bot']), 'chat': copy.deepcopy(self.state['chat']),
                    'config': dict(self.state['config']), 'pairing': pairing, 'active': active,
                    'history': copy.deepcopy(self.state['history'][-50:][::-1]),
                    'queueLength': len(self.state['queue']), 'lastSentAt': self.state['lastSentAt'],
                    'lastError': self.state['lastError'], 'lastCheckAt': self.state['lastCheckAt'],
                    'security': {k: self.state['securityState'][k] for k in
                                 ('baselineAt', 'lastCheckAt', 'lastNoticeAt', 'bad', 'activity', 'lastError')},
                    'menu': dict(self.state['menuState'], enabled=bool(self.bot_menu and self.state['chat'] and self.state['chat']['type'] == 'private')),
                    'botMenuEnabled': bool(self.state['menuState'].get('publishedAt'))}

    def start_pairing(self):
        try:
            bot = self.transport('getMe', {})
            webhook = self.transport('getWebhookInfo', {})
        except AlertError:
            raise
        except Exception:
            raise AlertError('Не удалось проверить Telegram-бота.') from None
        username = bot.get('username') if isinstance(bot, dict) else None
        if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_]{5,64}', username):
            raise AlertError('Telegram не сообщил имя бота.')
        with self.action_lock:
            self._invalidate_bot_actions()
            with self.lock:
                self.state['bot'] = {'username': username, 'id': bot.get('id')}
                now = self.clock()
                self.state['pairing'] = {'code': secrets.token_hex(16), 'createdAt': now, 'expiresAt': now + 1800}
                if isinstance(webhook, dict) and webhook.get('url'):
                    self.state['pairing'].update(blocked=True, error='У этого бота уже настроен webhook. Подключение не меняет существующую интеграцию; нужен отдельный бот или согласованная смена webhook.')
                self._save()
        return self.status()

    def cancel_pairing(self):
        with self.action_lock:
            self._invalidate_bot_actions()
            with self.lock:
                self.state['pairing'] = None
                self._save()
        return self.status()

    def _invalidate_bot_actions(self):
        invalidate = getattr(self.bot_actions, 'invalidate_pending', None)
        if callable(invalidate):
            try:
                invalidate()
            except Exception:
                raise AlertError('Не удалось сбросить подтверждения управления. Подключение чата не изменено.') from None

    def _history(self, item, status):
        self.state['history'].append({'id': item['id'], 'time': self.clock(), 'kind': item['kind'],
                                      'status': status, 'server': item.get('server'), 'title': item.get('title', '')})
        del self.state['history'][:-50]

    def _mark_critical_uncertain(self, item):
        if (self.state['config']['criticalOnly'] or self._aggregate_item(item)) and self._critical_item(item) and item['kind'] == 'alarm':
            reference = item.get('rule') or {}
            rule = self.state['rules'].get(reference.get('id'))
            if rule and rule['event'] == reference.get('event') and rule['active']:
                rule['deliveryUncertain'] = True

    def _aggregate_item(self, item):
        rule = self.state['rules'].get((item.get('rule') or {}).get('id'), {})
        return rule.get('rule') in ('app:awg', 'app:mtproxyl')

    def _retire_finished_aggregates(self):
        if self.state['config']['criticalOnly']:
            return
        pending = {(item.get('rule') or {}).get('id') for item in self.state['queue']}
        self.state['rules'] = {key: rule for key, rule in self.state['rules'].items()
                               if rule['rule'] not in ('app:awg', 'app:mtproxyl') or rule['active'] or key in pending}

    def _queue(self, kind, text, title, server=None, rule=None, release=None):
        if kind == 'security_release':
            record = self.state['securityReleaseEvents'].get(release)
            if not record or record['status'] != 'pending':
                return None
        critical = self.state['config']['criticalOnly']
        if critical and kind not in ('test', 'pairing', 'menu', 'security_release'):
            known_rule = self.state['rules'].get((rule or {}).get('id'), {})
            if kind not in ('alarm', 'recovery') or not is_critical_rule(known_rule.get('rule')):
                return None
        if len(self.state['queue']) >= 256:
            self.state['lastError'] = 'Очередь уведомлений заполнена; проверьте доставку Telegram.'
            return None
        item = {'id': secrets.token_hex(12), 'kind': kind, 'text': clean(text, 3500),
                'title': clean(title), 'server': server, 'rule': rule, 'attempts': 0,
                'due': self.clock(), 'phase': 'pending'}
        if kind in ('security', 'security_digest'):
            item['expiresAt'] = self.clock() + 900
        elif kind in ('alarm', 'recovery') and (critical or self.state['rules'].get((rule or {}).get('id'), {}).get('rule') in ('app:awg', 'app:mtproxyl')):
            item['expiresAt'] = self.clock() + CRITICAL_NOTICE_TTL
        elif kind == 'security_release':
            item.update(releaseId=release, recipient=record['recipient'], expiresAt=record['expiresAt'])
        self.state['queue'].append(item)
        return item['id']

    def _recipient_binding(self):
        chat, bot = self.state['chat'], self.state['bot']
        if not chat or chat['type'] != 'private' or not bot:
            return None
        value = [bot['id'], chat['id'], chat['type']]
        return hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest()

    def _release_event(self, event):
        if (not isinstance(event, dict) or event.get('cve') != RELEASE_CVE or event.get('sourceUrl') != RELEASE_SOURCE or
                event.get('vendorStatus') != 'released' or not finite(event.get('checkedAt')) or
                not -60 <= self.clock() - event['checkedAt'] < 10800 or
                not isinstance(event.get('sourcePackage'), str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.\-]{0,127}', event['sourcePackage']) or
                not isinstance(event.get('releaseCodename'), str) or not re.fullmatch(r'[a-z][a-z0-9\-]{0,63}', event['releaseCodename']) or
                not isinstance(event.get('fixedVersion'), str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]{0,199}', event['fixedVersion']) or
                not isinstance(event.get('servers'), list) or not 1 <= len(event['servers']) <= 256):
            raise AlertError('Публикация исправления не подтверждена свежими данными Ubuntu.')
        try:
            registry = {server['id']: server for server in self.servers_fn()}
        except Exception:
            raise AlertError('Не удалось проверить реестр серверов для уведомления.') from None
        hosts, seen = [], set()
        for row in event['servers']:
            if not isinstance(row, dict) or not isinstance(row.get('id'), str):
                raise AlertError('Не удалось проверить серверы публикации исправления.')
            server = registry.get(row['id'])
            if (not server or row['id'] in seen or row.get('host') != server.get('host') or
                    row.get('state') not in ('published', 'reboot_required') or row.get('vendorStatus', 'released') != 'released' or
                    row.get('stale', False) is not False or row.get('ok', True) is not True or
                    any(not isinstance(row.get(key), str) or not re.fullmatch(r'[A-Za-z0-9.+:~_\-]{1,200}', row[key])
                        for key in ('kernel', 'installedVersion'))):
                raise AlertError('Не удалось подтвердить применимость исправления к серверам.')
            seen.add(row['id'])
            hosts.append({'id': row['id'], 'name': clean(server.get('name') or row['id'], 80),
                          'host': clean(server['host'], 253), 'kernel': row['kernel'],
                          'installedVersion': row['installedVersion'], 'state': row['state']})
        identity = [RELEASE_CVE, event['sourcePackage'], event['releaseCodename'], event['fixedVersion']]
        event_id = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()
        lines = ['🛡 Server Deck · Ubuntu опубликовала исправление ' + RELEASE_CVE,
                 event['sourcePackage'] + ' · ' + event['releaseCodename'] + ' · ' + event['fixedVersion'],
                 'Доступность пакетов в APT на этих VPS ещё не подтверждена. Обновление и перезагрузка автоматически не выполнялись.']
        for row in sorted(hosts, key=lambda value: value['id'])[:12]:
            state = 'исправленное ядро установлено, ожидает перезагрузки' if row['state'] == 'reboot_required' else 'проверьте APT'
            lines.append(row['name'] + ' · ' + row['host'] + ': ' + row['kernel'] + ' → ' + state)
        if len(hosts) > 12:
            lines.append('Всего VPS в этой группе: ' + str(len(hosts)) + '.')
        body = clean('\n'.join(lines), 3500).encode('utf-16-le', errors='replace')[:6000].decode('utf-16-le', errors='ignore')
        message = '\n'.join([body, 'Ubuntu: ' + RELEASE_PAGE, clean(self._origin(), 300)])
        return event_id, clean(message, 3500), min(self.clock() + 3600, event['checkedAt'] + 10800)

    def notify_security_release(self, event):
        """Reserve a verified publication once; only the existing worker sends."""
        event_id, message, expires = self._release_event(event)
        with self.lock:
            if self.storage_error:
                return {'accepted': False, 'reason': 'storage', 'queued': False}
            changed = self._prune_release_queue()
            record = self.state['securityReleaseEvents'].get(event_id)
            if record:
                queued = next((item for item in self.state['queue'] if item.get('releaseId') == event_id), None)
                if queued and record['status'] == 'pending' and queued['text'] != message:
                    queued['text'] = message
                    changed = True
                if changed:
                    self._save()
                return {'accepted': True, 'duplicate': True, 'eventId': event_id, 'queued': queued is not None}
            if not self.state['config']['enabled'] or not self._recipient_binding() or self.state['pairing'] is not None:
                if changed:
                    self._save()
                return {'accepted': False, 'reason': 'disabled_or_unpaired', 'queued': False}
            if len(self.state['securityReleaseEvents']) >= 512 or len(self.state['queue']) >= 256:
                if changed:
                    self._save()
                return {'accepted': False, 'reason': 'capacity', 'queued': False}
            before = copy.deepcopy(self.state)
            self.state['securityReleaseEvents'][event_id] = {'status': 'pending', 'createdAt': self.clock(),
                'updatedAt': self.clock(), 'expiresAt': expires, 'recipient': self._recipient_binding(), 'queueId': ''}
            queued_id = self._queue('security_release', message, 'Ubuntu опубликовала исправление ' + RELEASE_CVE, release=event_id)
            self.state['securityReleaseEvents'][event_id]['queueId'] = queued_id
            try:
                self._save()
            except Exception:
                self.state = before
                raise AlertError('Не удалось сохранить уведомление об исправлении.') from None
        return {'accepted': True, 'duplicate': False, 'eventId': event_id, 'queued': True}

    def _finish_release(self, item, status):
        if item.get('kind') != 'security_release':
            return
        record = self.state['securityReleaseEvents'].get(item.get('releaseId'))
        if record and record['status'] == 'pending':
            record.update(status=status, updatedAt=self.clock())

    def _prune_release_queue(self):
        before = len(self.state['queue'])
        queue = []
        for item in self.state['queue']:
            if item['kind'] != 'security_release':
                queue.append(item)
                continue
            record = self.state['securityReleaseEvents'].get(item.get('releaseId'))
            if not record or record['status'] != 'pending':
                continue
            if item['recipient'] != self._recipient_binding():
                self._finish_release(item, 'cancelled')
            elif item['expiresAt'] <= self.clock():
                self._finish_release(item, 'expired')
            else:
                queue.append(item)
        self.state['queue'] = queue
        pending = {item.get('releaseId') for item in queue if item['kind'] == 'security_release'}
        orphaned = False
        for event_id, record in self.state['securityReleaseEvents'].items():
            if record['status'] == 'pending' and event_id not in pending:
                record.update(status='cancelled', updatedAt=self.clock())
                orphaned = True
        return before != len(queue) or orphaned

    def _release_ready(self, item):
        record = self.state['securityReleaseEvents'].get(item.get('releaseId'))
        return bool(record and record['status'] == 'pending' and item['recipient'] == self._recipient_binding() and
                    self.state['pairing'] is None and item['expiresAt'] > self.clock() and
                    (self.security_release_fn is None or self.clock() < self.next_release_scan and
                     self.clock() <= self.release_eligible_until and item['releaseId'] in self.release_eligible))

    def test(self):
        with self.lock:
            if not self.state['chat']:
                raise AlertError('Сначала подключите чат Telegram.')
            if any(q['kind'] == 'test' for q in self.state['queue']):
                raise AlertError('Проверочное сообщение уже ожидает отправки.')
            recent = [h for h in self.state['history'] if h['kind'] == 'test' and self.clock() - h['time'] < 30]
            if recent:
                raise AlertError('Проверочное сообщение можно отправлять не чаще раза в 30 секунд.')
            count = len(self.servers_fn())
            self._queue('test', '✅ Server Deck\nПроверка доставки уведомлений.\nВ мониторинге серверов: ' + str(count) + '.\n' + self._origin(), 'Проверка доставки')
            self._save()
        self._flush()
        return {'ok': True, 'queued': True}

    @staticmethod
    def _origin():
        origin = os.environ.get('DECK_PUBLIC_ORIGIN', '')
        return origin if re.fullmatch(r'https://[a-z0-9.-]+', origin) else ''

    def publish_menu(self, force=False):
        """Explicit administrator action; never called on startup or by polling."""
        with self.lock:
            chat = copy.deepcopy(self.state['chat'])
            if not self.bot_menu or not chat or chat['type'] != 'private':
                raise AlertError('Сначала подключите личный чат и меню мониторинга.')
            if self.state['menuState'].get('publishedAt') and not force:
                return {'ok': True, 'botMenuEnabled': True, 'unchanged': True}
        commands = [{'command': command, 'description': description} for command, description in
                    [('menu', 'Меню мониторинга'), ('status', 'Сводка серверов'),
                     ('servers', 'Список серверов'), ('services', 'Состояние служб'),
                     ('security', 'SSH-активность и блокировки')]]
        try:
            self.transport('setMyCommands', {'commands': commands, 'scope': {'type': 'chat', 'chat_id': int(chat['id'])}})
            self.transport('setChatMenuButton', {'chat_id': int(chat['id']), 'menu_button': {'type': 'commands'}})
        except Exception:
            raise AlertError('Не удалось настроить кнопку меню Telegram. Повторите позже.') from None
        with self.lock:
            if self.state['chat'] and self.state['chat']['id'] == chat['id']:
                self.state['menuState']['publishedAt'] = self.clock()
                self._save()
        return {'ok': True, 'botMenuEnabled': True}

    def _poll_pairing(self):
        with self.lock:
            pairing = copy.deepcopy(self.state['pairing'])
            offset = self.state['offset']
            has_menu = (self.bot_menu is not None or self.bot_actions is not None) and self.state['chat'] is not None and self.state['chat']['type'] == 'private'
            next_poll = self.state['menuState']['nextPollAt']
        valid_pairing = pairing and pairing['expiresAt'] > self.clock() and not pairing.get('blocked')
        if not valid_pairing and not has_menu or self.clock() < next_poll:
            return
        try:
            updates = self.transport('getUpdates', {'offset': offset, 'timeout': 1 if has_menu else 0,
                                                   'limit': 100, 'allowed_updates': ['message', 'callback_query']})
        except AlertError as error:
            with self.lock:
                self.state['menuState']['lastError'] = str(error)
                self.state['menuState']['nextPollAt'] = self.clock() + (60 if isinstance(error, DeliveryError) and error.code == 409 else 10)
                if valid_pairing:
                    self.state['lastError'] = str(error)
                if isinstance(error, DeliveryError) and error.code == 409:
                    current = self.state['pairing']
                    if pairing and current and current['code'] == pairing['code']:
                        current['blocked'] = True
                        current['error'] = str(error)
                self._save()
            return
        except Exception:
            with self.lock:
                self.state['menuState']['lastError'] = 'Не удалось получить сообщения Telegram.'
                self.state['menuState']['nextPollAt'] = self.clock() + 10
                self._save()
            return
        if not isinstance(updates, list):
            return
        # A healthy empty long-poll is still a successful Telegram request.
        # Clear a previous transport error before processing interactions so a
        # new callback/delivery error from this batch remains visible.
        with self.lock:
            self.state['menuState']['lastError'] = ''
            self.state['menuState']['nextPollAt'] = 0
            self.state['menuState']['lastPollAt'] = self.clock()
            self._save()
        for update in updates:
            if not isinstance(update, dict) or type(update.get('update_id')) is not int:
                continue
            with self.lock:
                if self.clock() < self.state['menuState']['nextPollAt']:
                    break
                if update['update_id'] < self.state['offset']:
                    continue
                self.state['offset'] = max(self.state['offset'], update['update_id'] + 1)
                # Confirm consumption durably before any reply: a restart must
                # not resend old user interactions or unknown-chat messages.
                self.state['menuState']['lastPollAt'] = self.clock()
                self.state['menuState']['lastError'] = ''
                self._save()
                current = self.state['pairing']
                can_pair = bool(valid_pairing and current and current['code'] == pairing['code'] and current['expiresAt'] > self.clock())
            if not can_pair:
                self._handle_menu_update(update)
                continue
            message = update.get('message') or {}
            if not isinstance(message, dict):
                continue
            text = message.get('text', '').strip() if isinstance(message.get('text'), str) else ''
            code = re.escape(pairing['code'])
            match = re.fullmatch(r'(?:/start(?:@[A-Za-z0-9_]+)? deck_|/deck(?:@[A-Za-z0-9_]+)? |/deck_)' + code + r'(?:@[A-Za-z0-9_]+)?', text)
            chat = message.get('chat') or {}
            timestamp = message.get('date')
            if not match or not finite(timestamp) or timestamp < pairing['createdAt'] - 5 or timestamp > self.clock() + 60:
                # Dispatch may acquire action_lock; never invoke it while the
                # state lock is held (pairing resets take the opposite order).
                self._handle_menu_update(update)
                continue
            if not isinstance(chat, dict) or type(chat.get('id')) is not int or chat.get('type') not in ('private', 'group', 'supergroup'):
                continue
            with self.action_lock:
                with self.lock:
                    current = self.state['pairing']
                    if (not current or current['code'] != pairing['code'] or current.get('blocked') or
                            current['expiresAt'] <= self.clock()):
                        continue
                self._invalidate_bot_actions()
                with self.lock:
                    title = chat.get('title') or ' '.join(str(chat.get(k) or '') for k in ('first_name', 'last_name')) or chat.get('username') or 'Telegram'
                    self.state['chat'] = {'id': str(chat['id']), 'type': chat['type'], 'title': clean(title, 100)}
                    self.state['pairing'] = None
                    self.state['config']['enabled'] = True
                    self.state['rules'] = {}
                    for queued in self.state['queue']:
                        self._finish_release(queued, 'cancelled')
                    self.state['queue'] = []
                    self.state['lastError'] = ''
                    self.state['menuState']['recent'] = []
                    self.state['menuState']['publishedAt'] = None
                    self._reset_security()
                    self._queue('pairing', '✅ Server Deck подключён\nСюда будут приходить алерты всех серверов, добавленных в панель.\nПовторные одинаковые замеры не создают новые сообщения.\n' + self._origin(), 'Telegram подключён')
                    self._save()
            break
        with self.lock:
            self.state['menuState']['lastPollAt'] = self.clock()
            self._save()

    def _handle_menu_update(self, update):
        if self.bot_menu is None and self.bot_actions is None:
            return
        callback = update.get('callback_query')
        is_callback = isinstance(callback, dict)
        message = callback.get('message') if is_callback else update.get('message')
        if not isinstance(message, dict) or not isinstance(message.get('chat'), dict):
            return
        chat = message['chat']
        sender = callback.get('from') if is_callback else message.get('from')
        if not isinstance(sender, dict) or type(sender.get('id')) is not int:
            return
        with self.lock:
            target = copy.deepcopy(self.state['chat'])
            bot = copy.deepcopy(self.state['bot'])
        if not target or target['type'] != 'private' or type(chat.get('id')) is not int or str(chat['id']) != target['id'] or chat.get('type') != target['type']:
            return
        if target['type'] == 'private' and str(sender['id']) != target['id']:
            return
        if sender.get('is_bot') is True:
            return
        callback_id = callback.get('id') if is_callback else None
        action_text = False
        if is_callback:
            author = message.get('from') or {}
            if (not isinstance(callback_id, str) or not 1 <= len(callback_id) <= 128 or
                    not bot or not isinstance(author, dict) or author.get('id') != bot['id'] or type(message.get('message_id')) is not int):
                return
            data = callback.get('data')
            if not isinstance(data, str) or len(data.encode()) > 64:
                data = 'invalid'
            text = None
        else:
            stamp = message.get('date')
            text = message.get('text')
            if not finite(stamp) or not 0 <= self.clock() - stamp <= 300 or not isinstance(text, str) or len(text) > 512:
                return
            action_text = self.bot_actions is not None and re.fullmatch(r'ПЕРЕЗАПУСТИТЬ [0-9]{6}', text) is not None
            if not action_text and not re.match(r'^/(?:start|menu|status|servers|services|security)(?:@[A-Za-z0-9_]+)?(?:\s|$)', text):
                return
            data = None
        action_callback = is_callback and self.bot_actions is not None and data.startswith(('deck:manage:', 'deck:act:'))
        if (action_text or action_callback) and (type(message.get('message_id')) is not int or message['message_id'] <= 0):
            return
        # The action handler accepts only its own allowlisted plans and expiring
        # confirmations. Never pass it an update before destination, sender,
        # bot-message provenance and the shared interaction limit are checked.
        with self.lock:
            recent = [t for t in self.state['menuState']['recent'] if 0 <= self.clock() - t < 10]
            allowed = len(recent) < 3
            if allowed:
                recent.append(self.clock())
                self.state['menuState']['recent'] = recent
                self.state['menuState']['lastInteractionAt'] = self.clock()
                self._save()
        if is_callback:
            try:
                self.transport('answerCallbackQuery', {'callback_query_id': callback_id,
                               'text': '' if allowed else 'Подождите несколько секунд.', 'cache_time': 1})
            except Exception as error:
                if not isinstance(error, DeliveryError) or error.code in (0, 429) or error.code >= 500:
                    with self.lock:
                        self.state['menuState']['lastError'] = 'Не удалось подтвердить кнопку Telegram; повторите позже.'
                        self.state['menuState']['nextPollAt'] = self.clock() + 10
                        self._save()
        if not allowed:
            return
        try:
            if action_text or action_callback:
                with self.action_lock:
                    with self.lock:
                        # Pairing resets and actions share one gate, so a
                        # confirmation captured before re-pairing cannot run
                        # after its pending session has been invalidated.
                        if self.state['chat'] != target or self.state['pairing'] is not None:
                            return
                    response = self.bot_actions.handle(text=text, callback_data=data, chat_id=target['id'],
                                                       user_id=str(sender['id']), message_id=message['message_id'])
            elif self.bot_menu is not None:
                response = self.bot_menu.handle(text=text, callback_data=data)
            else:
                return
        except Exception:
            response = {'text': 'Не удалось обработать запрос. Повторите /menu.', 'reply_markup': {}}
        if response is None:
            return
        if not isinstance(response, dict) or not isinstance(response.get('text'), str) or not isinstance(response.get('reply_markup', {}), dict):
            return
        with self.lock:
            # Only interactive replies can coalesce; health/security events
            # already queued for delivery are never replaced by menu requests.
            message_id = message['message_id'] if is_callback else None
            self.state['queue'] = [q for q in self.state['queue'] if not (q['kind'] == 'menu' and q.get('editMessageId') == message_id)]
            item_id = self._queue('menu', response['text'], 'Меню мониторинга')
            if item_id:
                item = self.state['queue'][-1]
                item.update(replyMarkup=response.get('reply_markup', {}), editMessageId=message_id,
                            expiresAt=self.clock() + 120)
            self._save()
        self._flush()

    def _reset_security(self):
        previous = self.state['securityState']
        self.state['securityState'] = security_state()
        # Toggling settings/recipient must never bypass the global quiet period.
        self.state['securityState']['lastNoticeAt'] = previous.get('lastNoticeAt')
        self.state['queue'] = [q for q in self.state['queue'] if q['kind'] not in ('security', 'security_digest')]
        self.next_security_scan = 0

    def _security_summary(self, report, now):
        if not isinstance(report, dict) or not finite(report.get('generatedAt')) or not 0 <= now - report['generatedAt'] <= 180:
            return None
        rows = report.get('servers')
        if isinstance(rows, dict):
            rows = [dict(v, id=v.get('id', k)) for k, v in rows.items() if isinstance(v, dict)]
        if not isinstance(rows, list):
            return None
        current_ids = {s['id'] for s in self.servers_fn()}
        fresh = {}
        for row in rows:
            if not isinstance(row, dict) or row.get('id') not in current_ids or row.get('ok') is not True:
                continue
            at, count = row.get('checkedAt'), row.get('failedPassword10m')
            if not finite(at) or not 0 <= now - at <= 180 or type(count) is not int or not 0 <= count <= 1000000000:
                continue
            packets = row.get('blockedPacketsPerMinute')
            if not finite(packets) or not 0 <= packets <= 1000000000000:
                packets = None
            fresh[row['id']] = {'count': count, 'name': clean(row.get('name') or row['id'], 100),
                                'host': clean(row.get('host'), 100), 'checkedAt': at, 'packets': packets}
        if not fresh:
            return None
        totals = report.get('totals') or {}
        bans = totals.get('newSharedBans10m') if isinstance(totals, dict) else None
        if type(bans) is not int or not 0 <= bans <= 1000000000:
            bans = None
        event_at = report.get('newestEventAt')
        if not finite(event_at) or not 0 <= now - event_at <= 86400:
            event_at = None
        return {'rows': fresh, 'bans': bans, 'eventAt': event_at,
                'sampleAt': max(v['checkedAt'] for v in fresh.values())}

    def _evaluate_security(self, report, now):
        state = self.state['securityState']
        summary = self._security_summary(report, now)
        state['lastCheckAt'] = now
        if summary is None:
            state['bad'] = 0
            state['pendingActivity'] = False
            for proof in state['proofs'].values():
                proof['bad'] = 0
                proof['armed'] = False
            state['lastError'] = 'Нет свежего подтверждённого среза SSH-защиты. Состояние атаки неизвестно.'
            return
        sample_at = summary['sampleAt']
        previous_sample_at = state['lastSampleAt']
        state['lastSampleAt'] = max(sample_at, previous_sample_at or sample_at)
        state['lastError'] = ''
        if state['baselineAt'] is None:
            state['baselineAt'] = now
            state['digestStartedAt'] = now
            state['previous'] = copy.deepcopy(summary['rows'])
            state['previousBans'] = summary['bans'] or 0
            state['lastEventAt'] = summary['eventAt']
            return
        previous = state['previous']
        old_previous = dict(previous)
        old_bans = state['previousBans']
        # Hosts are collected independently. A newer measurement from one host
        # must neither confirm another host's old high value nor hide a valid
        # new measurement whose timestamp is below the cluster's current max.
        advanced = {sid for sid, row in summary['rows'].items()
                    if row['checkedAt'] > previous.get(sid, {}).get('checkedAt', -1)}
        new_event = summary['eventAt'] is not None and (state['lastEventAt'] is None or summary['eventAt'] > state['lastEventAt'])
        changed = any(v['count'] > previous.get(sid, {}).get('count', v['count']) or
                      v['packets'] is not None and v['packets'] > 0 for sid, v in summary['rows'].items() if sid in advanced)
        if new_event and advanced:
            changed = True
        if advanced and summary['bans'] is not None and summary['bans'] > state['previousBans']:
            changed = True
        if changed:
            state['activity'] = True
        for sid, value in summary['rows'].items():
            if changed or state['activity']:
                peak = state['peakFailed'].setdefault(sid, {'name': value['name'], 'host': value['host'], 'count': 0, 'packets': 0})
                peak['count'] = max(peak['count'], value['count'])
                peak['packets'] = max(peak.get('packets', 0), value['packets'] or 0)
            if sid in advanced:
                previous[sid] = copy.deepcopy(value)
        if summary['bans'] is not None:
            if state['activity']:
                state['peakBans'] = max(state['peakBans'], summary['bans'])
            state['previousBans'] = summary['bans']
        if summary['eventAt'] is not None:
            state['lastEventAt'] = max(state['lastEventAt'] or 0, summary['eventAt'])
        config = self.state['config']
        conditions = {}
        for sid, row in summary['rows'].items():
            old = old_previous.get(sid, {})
            conditions['failed:' + sid] = (row['count'] >= config['securityFailedThreshold'], row['checkedAt'],
                                          row['count'] > old.get('count', row['count']) or new_event)
            conditions['packets:' + sid] = (row['packets'] >= config['securityPacketThreshold'] if row['packets'] is not None else None,
                                           row['checkedAt'], row['packets'] is not None and row['packets'] > 0)
        conditions['bans:cluster'] = (summary['bans'] >= config['securityBanThreshold'] if summary['bans'] is not None else None,
                                     sample_at, summary['bans'] is not None and summary['bans'] > old_bans)
        for key, proof in state['proofs'].items():
            if key not in conditions:
                proof['bad'] = 0
                proof['armed'] = False
        for key, (bad, at, activity) in conditions.items():
            baseline_at = previous_sample_at if key == 'bans:cluster' else old_previous.get(key.split(':', 1)[1], {}).get('checkedAt')
            proof = state['proofs'].setdefault(key, {'lastAt': baseline_at, 'bad': 0, 'armed': False})
            if proof['lastAt'] is not None and at <= proof['lastAt']:
                continue
            if proof['lastAt'] is not None and at - proof['lastAt'] > 180:
                proof['bad'] = 0
                proof['armed'] = False
            proof['lastAt'] = at
            if not bad:
                proof['bad'] = 0
                proof['armed'] = False
            else:
                proof['armed'] = proof['armed'] or activity
                proof['bad'] = proof['bad'] + 1 if proof['armed'] else 0
        current_high = [state['proofs'][key] for key, (bad, _, _) in conditions.items() if bad]
        spike = bool(current_high)
        state['bad'] = max((proof['bad'] for proof in current_high), default=0)
        state['pendingActivity'] = any(proof['armed'] for proof in current_high)
        if not advanced:
            return
        last = state['lastNoticeAt']
        cooldown_ready = last is None or now - last >= config['securityCooldownMinutes'] * 60
        if not cooldown_ready or not state['activity'] or any(q['kind'] in ('security', 'security_digest') for q in self.state['queue']):
            return
        if spike and state['bad'] >= config['securityConsecutive']:
            self._queue_security(summary, now, digest=False)
        elif not spike and config['securityDigestHours'] and now - state['digestStartedAt'] >= config['securityDigestHours'] * 3600:
            self._queue_security(summary, now, digest=True)

    def _queue_security(self, summary, now, digest=False):
        state = self.state['securityState']
        rows = state['peakFailed'] if digest else summary['rows']
        lines = ['ℹ️ Server Deck · Сводка SSH-защиты' if digest else '🛡 Server Deck · Повышенная SSH-активность',
                 'Пиковые наблюдавшиеся окна за период:' if digest else 'Порог подтверждён последовательными срезами; текущие значения:']
        selected = sorted(rows.values(), key=lambda r: (r['count'], r.get('packets') or 0), reverse=True)
        for row in selected[:6]:
            if row['count'] or row.get('packets'):
                line = clean(row['name'], 70) + ': ' + str(row['count']) + ' неверных паролей за 10 мин'
                if row.get('packets'):
                    line += f"; отброшено новых SSH-пакетов: {row['packets']:.0f}/мин"
                lines.append(line)
        bans = state['peakBans'] if digest else summary['bans']
        if bans is not None:
            lines.append(('Максимум новых общих блокировок за 10 мин: ' if digest else 'Новых общих блокировок за 10 мин: ') + str(bans))
        stamp = datetime.datetime.fromtimestamp(summary['sampleAt'], datetime.timezone(datetime.timedelta(hours=3))).strftime('%d.%m.%Y %H:%M:%S МСК')
        lines.extend(['Это наблюдения SSH и защитных правил, а не доказательство недоступности VPN.', 'Срез: ' + stamp, self._origin()])
        kind = 'security_digest' if digest else 'security'
        if self._queue(kind, '\n'.join(lines), 'Сводка SSH-защиты' if digest else 'Повышенная SSH-активность'):
            # Reserve before transport; retries/restarts/config toggles cannot
            # create another logical security notice during this quiet period.
            state['lastNoticeAt'] = now
            state['digestStartedAt'] = now
            state['activity'] = False
            state['pendingActivity'] = False
            state['peakFailed'] = {}
            state['peakBans'] = 0
            state['bad'] = 0
            for proof in state['proofs'].values():
                proof['bad'] = 0
                proof['armed'] = False

    def _message(self, server, title, detail, sample_ts, recovered=False, reminder=False, diagnostic=False):
        try:
            timezone = datetime.timezone(datetime.timedelta(hours=3))
            stamp = datetime.datetime.fromtimestamp(sample_ts, timezone).strftime('%d.%m.%Y %H:%M:%S МСК')
        except (ValueError, OverflowError, OSError):
            stamp = 'время измерения неизвестно'
        icon = 'ℹ️' if diagnostic else '✅' if recovered else '🔔' if reminder else '⚠️'
        return '\n'.join([icon + ' Server Deck · ' + clean(title),
                          clean(server.get('name') or server['id'], 100) + ' · ' + clean(server.get('host'), 100),
                          clean(detail, 400), 'Измерение: ' + stamp, self._origin()]).strip()

    def _queue_awg_rx(self, rule_id, rule, server, title, detail, now):
        last = self.state['awgRxLastNotice'].get(rule_id)
        if last is not None and now - last < AWG_RX_COOLDOWN:
            return
        if any((q.get('rule') or {}).get('id') == rule_id for q in self.state['queue']):
            return
        queued = self._queue('alarm', self._message(server, title, detail, now, diagnostic=True),
                             title, server['id'], {'id': rule_id, 'event': rule['event']})
        if queued:
            # Reserve the interval before delivery as well, so failed attempts
            # cannot generate another logical diagnostic on each fresh sample.
            self.state['awgRxLastNotice'][rule_id] = now

    def _advance(self, server, key, bad, sample_ts, title, detail, confirmations, now, diagnostic=False):
        if self.state['config']['criticalOnly'] and not is_critical_rule(key):
            return
        category = critical_category(key)
        if (category in ('app:awg', 'app:mtproxyl') and key != category and
                str(server['id']) + '|' + category in self.state['rules']):
            return
        critical_incident = self.state['config']['criticalOnly'] or key in ('app:awg', 'app:mtproxyl')
        rule_id = str(server['id']) + '|' + key
        rule = self.state['rules'].setdefault(rule_id, {'server': server['id'], 'serverName': clean(server.get('name')), 'host': clean(server.get('host')),
                                                         'rule': key, 'active': False, 'notified': False, 'bad': 0, 'good': 0,
                                                         'lastTs': None, 'since': None, 'lastSentAt': 0, 'event': 0})
        if rule['lastTs'] == sample_ts:
            return
        if finite(rule['lastTs']) and finite(sample_ts):
            if sample_ts < rule['lastTs']:
                return
            if sample_ts - rule['lastTs'] > 180:
                rule['bad'] = rule['good'] = 0
        rule['lastTs'] = sample_ts
        rule.update(title=title, detail=detail)
        if bad is None:
            rule['bad'] = rule['good'] = 0
            return
        if bad:
            rule['good'] = 0
            if not rule['bad'] and not rule['active']:
                rule['since'] = now
            rule['bad'] += 1
            if not rule['active'] and rule['bad'] >= confirmations:
                rule['active'] = True
                rule['event'] += 1
                rule['notified'] = False
                if critical_incident:
                    rule['deliveryUncertain'] = False
                if not diagnostic:
                    self._queue('alarm', self._message(server, title, detail, now), title, server['id'], {'id': rule_id, 'event': rule['event']})
            if diagnostic and rule['active'] and not rule['notified'] and rule['bad'] >= confirmations:
                self._queue_awg_rx(rule_id, rule, server, title, detail, now)
            minutes = self.state['config']['remindersMinutes']
            if not diagnostic and rule['active'] and rule['notified'] and minutes and now - rule.get('lastSentAt', 0) >= minutes * 60:
                if not any(q.get('rule', {}).get('id') == rule_id for q in self.state['queue'] if q.get('rule')):
                    self._queue('reminder', self._message(server, title, detail, now, reminder=True), title, server['id'], {'id': rule_id, 'event': rule['event']})
        else:
            rule['bad'] = 0
            rule['good'] += 1
            if rule['active'] and rule['good'] >= self.state['config']['recoveryConsecutive']:
                rule['active'] = False
                rule['event'] += 1
                # An outage that recovered before delivery should not produce
                # a late incident or an unpaired recovery message.
                self.state['queue'] = [q for q in self.state['queue'] if not (q.get('rule') and q['rule']['id'] == rule_id)]
                attempted = critical_incident and rule.get('deliveryUncertain', False)
                if (rule['notified'] or attempted) and not diagnostic:
                    recovered_title = 'Восстановление · ' + title
                    self._queue('recovery', self._message(server, recovered_title, 'Условие тревоги не наблюдается в подтверждённых свежих проверках.', now, recovered=True), recovered_title, server['id'], {'id': rule_id, 'event': rule['event']})
                rule['notified'] = False
                if critical_incident:
                    rule['deliveryUncertain'] = False

    def _evaluate_server(self, server, latest, now):
        sid = server['id']
        config = self.state['config']
        observed = self.state['firstObserved'].setdefault(sid, now)
        timestamp = latest.get('ts') if isinstance(latest, dict) else None
        fresh = finite(timestamp) and 0 <= now - timestamp <= 180
        if fresh:
            self.state['lastSampleAt'][sid] = max(timestamp, self.state['lastSampleAt'].get(sid, 0))
        last_sample = self.state['lastSampleAt'].get(sid, observed)
        # Only an actual fresh measurement can clear an unknown-state alarm.
        # Missing data during the initial grace period is not a good check.
        unknown = False if fresh else True if (finite(timestamp) and now - timestamp > 180 or
                                               finite(timestamp) and timestamp > now + 30 or
                                               not finite(timestamp) and now - last_sample >= 180) else None
        marker = timestamp if fresh else 'missing-' + str(int(now // 60))
        self._advance(server, 'unknown', unknown, marker, 'Нет свежих измерений',
                      'Мониторинг не получил свежий замер. Состояние сервера неизвестно; это не подтверждённая недоступность VPN.', 1, now)
        if not fresh:
            self._break_counters(sid, {'unknown'})
            return
        ok = latest.get('ok') is True
        ssh_bad = not ok if not config['criticalOnly'] or type(latest.get('ok')) is bool else None
        self._advance(server, 'ssh', ssh_bad, timestamp, 'Нет доступа к серверу по SSH',
                      'TCP/SSH-проверка с сервера управления не прошла. Доступность VPN требует отдельной проверки.', config['outageConsecutive'], timestamp)
        if not ok:
            self._break_counters(sid, {'unknown', 'ssh'})
            return
        if config['criticalOnly']:
            self._evaluate_critical_components(server, latest, timestamp)
            return
        continuing = {category for category in ('app:awg', 'app:mtproxyl') if str(sid) + '|' + category in self.state['rules']}
        if continuing:
            self._evaluate_critical_components(server, latest, timestamp, continuing)
        if config['resources']:
            for field, threshold, name, value in [('cpu', 'cpuThreshold', 'ЦП', latest.get('cpu')),
                                                  ('memory', 'memoryThreshold', 'Память', percent(latest.get('memory'))),
                                                  ('disk', 'diskThreshold', 'Диск', percent(latest.get('disk')))]:
                valid = finite(value)
                detail = (f'{value:.1f}% при пороге {config[threshold]}%. Несколько последовательных измерений.' if valid else 'Нет достоверного значения ресурса.')
                self._advance(server, 'resource:' + field, value >= config[threshold] if valid else None,
                              timestamp, 'Высокая загрузка · ' + name, detail, config['resourceConsecutive'], timestamp)
        if config['services']:
            services = latest.get('services')
            expected = self.state['expectedServices'].setdefault(sid, {})
            configured = server.get('services')
            if isinstance(configured, list):
                for unit in list(expected):
                    if unit not in configured:
                        del expected[unit]
            if isinstance(services, list):
                current = {s['unit']: s for s in services if isinstance(s, dict) and UNIT_RE.fullmatch(str(s.get('unit', '')))}
                for unit, value in current.items():
                    if value.get('state') == 'active':
                        expected[unit] = True
                for unit in set(expected) | {u for u, v in current.items() if v.get('state') == 'failed'}:
                    value = current.get(unit, {})
                    failed = value.get('state') != 'active'
                    self._advance(server, 'service:' + unit, failed, timestamp, 'Проблема службы',
                                  unit + ': ' + clean(value.get('state') or 'не найдена', 50) + '. Ранее работала или отмечена failed.', config['outageConsecutive'], timestamp)
            else:
                for alert in latest.get('alerts') or []:
                    if alert.get('title') == 'Ошибка службы' and UNIT_RE.fullmatch(str(alert.get('detail', ''))):
                        unit = alert['detail']
                        self._advance(server, 'service:' + unit, True, timestamp, 'Проблема службы', unit + ': failed.', config['outageConsecutive'], timestamp)
            containers = latest.get('containers')
            expected_containers = self.state['expectedContainers'].setdefault(sid, {})
            if isinstance(containers, list):
                current = {clean(v.get('name'), 100): v for v in containers if isinstance(v, dict) and v.get('name')}
                for name, value in current.items():
                    if value.get('state') == 'active':
                        expected_containers[name] = True
                for name in set(expected_containers) | {n for n, v in current.items() if 'unhealthy' in str(v.get('description', '')).lower()}:
                    value = current.get(name, {})
                    failed = value.get('state') != 'active' or 'unhealthy' in str(value.get('description', '')).lower()
                    self._advance(server, 'container:' + name, failed, timestamp, 'Проблема контейнера',
                                  name + ': ' + ('unhealthy' if 'unhealthy' in str(value.get('description', '')).lower() else clean(value.get('state') or 'не найден', 50)), config['outageConsecutive'], timestamp)
        if config['awg']:
            interfaces = latest.get('awg')
            if isinstance(interfaces, list):
                expected_awg = self.state['expectedAwg'].setdefault(sid, {})
                current = {str(v['interface']): v for v in interfaces if isinstance(v, dict) and UNIT_RE.fullmatch(str(v.get('interface', '')))}
                for name in current:
                    expected_awg[name] = True
                for name in expected_awg:
                    self._advance(server, 'awg:' + name + ':missing', name not in current, timestamp, 'Интерфейс AWG не обнаружен',
                                  name + ': ранее был виден в проверке сервера.', config['outageConsecutive'], timestamp)
                    interface = current.get(name)
                    if interface is not None and config['awgRx']:
                        delta = interface.get('rxErrorsDelta')
                        self._advance(server, 'awg:' + name + ':rx', delta > 0 if finite(delta) else None, timestamp,
                                      'Диагностика AWG · прирост RX errors',
                                      name + ': прирост в нескольких последовательных замерах; последний RX errors +' + str(delta) +
                                      '. Диагностический счётчик сам по себе не подтверждает недоступность VPN и не устанавливает причину.',
                                      config['resourceConsecutive'], timestamp, diagnostic=True)
        if config['reboot']:
            self._advance(server, 'reboot-required', latest.get('rebootRequired') is True, timestamp,
                          'ОС запрашивает перезагрузку', 'Флаг reboot-required установлен. Перезагрузка автоматически не выполняется.', 1, timestamp)

    def _evaluate_critical_components(self, server, latest, timestamp, categories=None):
        sid = server['id']
        collection = latest.get('collectionOk')
        collection = collection if isinstance(collection, dict) else {}
        groups = {'app:awg': [], 'app:mtproxyl': []}

        def add(key, label, bad):
            category = critical_category(key)
            if category in groups:
                groups[category].append((label, bad))

        services = latest.get('services')
        current = {v['unit']: v for v in services if isinstance(v, dict) and UNIT_RE.fullmatch(str(v.get('unit', '')))} if isinstance(services, list) else {}
        expected = self.state['expectedServices'].setdefault(sid, {})
        configured = server.get('services')
        if isinstance(configured, list):
            for unit in list(expected):
                if unit not in configured:
                    del expected[unit]
        if collection.get('services') is True:
            for unit, value in current.items():
                if is_critical_rule('service:' + unit) and value.get('collectionOk') is True and value.get('state') in ('active', 'failed'):
                    expected[unit] = True
        targets = set(expected) | {unit for unit, value in current.items() if value.get('state') == 'failed'}
        for unit in targets:
            key = 'service:' + unit
            if not is_critical_rule(key):
                continue
            value = current.get(unit)
            if not isinstance(services, list) or collection.get('services') is not True or value and value.get('collectionOk') is not True:
                bad = None
            elif value is None:
                bad = True if collection.get('services') is True else None
            else:
                state = value.get('state')
                bad = False if state == 'active' else True if state in ('failed', 'inactive') else None
            add(key, unit, bad)

        containers = latest.get('containers')
        current = {clean(v.get('name'), 100): v for v in containers if isinstance(v, dict) and v.get('name')} if isinstance(containers, list) else {}
        expected = self.state['expectedContainers'].setdefault(sid, {})
        if collection.get('containers') is True:
            for name, value in current.items():
                if is_critical_rule('container:' + name) and (value.get('state') in ('active', 'failed') or
                                                             'unhealthy' in str(value.get('description', '')).lower()):
                    expected[name] = True
        targets = set(expected) | {name for name, value in current.items() if value.get('state') == 'failed' or 'unhealthy' in str(value.get('description', '')).lower()}
        for name in targets:
            key = 'container:' + name
            if not is_critical_rule(key):
                continue
            value = current.get(name)
            if not isinstance(containers, list) or collection.get('containers') is not True:
                bad = None
            elif value is None:
                bad = True if collection.get('containers') is True else None
            else:
                state = value.get('state')
                bad = True if state in ('inactive', 'failed') or 'unhealthy' in str(value.get('description', '')).lower() else False if state == 'active' else None
            add(key, name, bad)
            if is_awg_container(name):
                probe = value.get('awg') if value else None
                probe_known = (collection.get('containers') is True and value and value.get('state') == 'active' and
                               isinstance(probe, dict) and probe.get('collectionOk') is True and isinstance(probe.get('interfaces'), list) and
                               len(probe['interfaces']) <= 32 and all(isinstance(v, str) and UNIT_RE.fullmatch(v) for v in probe['interfaces']))
                add('awg-container:' + name + ':missing', name + ' · интерфейс AWG', not bool(probe['interfaces']) if probe_known else None)

        interfaces = latest.get('awg')
        current = {str(v['interface']): v for v in interfaces if isinstance(v, dict) and UNIT_RE.fullmatch(str(v.get('interface', '')))} if isinstance(interfaces, list) else {}
        expected = self.state['expectedAwg'].setdefault(sid, {})
        host_awg_known = collection.get('awg') is True and latest.get('awgSupported') is not False
        if host_awg_known:
            for name in current:
                expected[name] = True
        for name in expected:
            bad = None
            if isinstance(interfaces, list) and host_awg_known:
                bad = False if name in current else True if collection.get('awg') is True else None
            add('awg:' + name + ':missing', name, bad)

        for category, conditions in groups.items():
            if categories is not None and category not in categories:
                continue
            if not conditions and str(sid) + '|' + category not in self.state['rules']:
                continue
            failed = [name for name, bad in conditions if bad is True]
            unknown = [name for name, bad in conditions if bad is None]
            bad = True if failed else None if unknown or not conditions else False
            title = 'AWG недоступен' if category == 'app:awg' else 'MTProxyL недоступен'
            detail = ('Не работает: ' + ', '.join(failed) if failed else
                      'Нет подтверждённого состояния: ' + ', '.join(unknown) if unknown else
                      'Проверены: ' + ', '.join(name for name, _ in conditions))
            self._advance(server, category, bad, timestamp, title, clean(detail, 400), 2, timestamp)
        self._retire_finished_aggregates()

    def _break_counters(self, sid, preserve):
        for rule in self.state['rules'].values():
            if rule['server'] == sid and rule['rule'] not in preserve:
                rule['bad'] = rule['good'] = 0

    def _critical_delivery_ready(self, item, now):
        if item['kind'] == 'security_release':
            return self._release_ready(item)
        if not self._critical_item(item):
            return item['kind'] in ('test', 'pairing', 'menu')
        rule = self.state['rules'].get(item['rule']['id'], {})
        if not finite(rule.get('lastTs')) or not 0 <= now - rule['lastTs'] <= 180:
            return False
        if item['kind'] == 'alarm' and (not rule.get('active') or not rule.get('bad')):
            return False
        if item['kind'] == 'recovery' and (rule.get('active') or rule.get('good', 0) < 2):
            return False
        if rule.get('rule') == 'ssh':
            return True
        ssh = self.state['rules'].get(str(rule.get('server')) + '|ssh', {})
        return (finite(ssh.get('lastTs')) and 0 <= now - ssh['lastTs'] <= 180 and
                not ssh.get('active') and not ssh.get('bad') and ssh.get('good', 0) > 0)

    def _flush(self):
        if not self.send_lock.acquire(blocking=False):
            return
        try:
            self._flush_once()
        finally:
            self.send_lock.release()

    def _flush_once(self):
        with self.lock:
            release_changed = self._prune_release_queue()
            if not self.state['chat'] or self.clock() < self.state['nextSendAt']:
                if release_changed:
                    self._save()
                return
            queue_size = len(self.state['queue'])
            critical = self.state['config']['criticalOnly']
            if critical:
                self._filter_critical_policy()
            # A queued transition superseded by a later confirmed transition
            # must not be delivered late (for example recovery during backoff).
            self.state['queue'] = [q for q in self.state['queue'] if not q.get('rule') or
                                   (self.state['rules'].get(q['rule']['id'], {}).get('event') == q['rule']['event'])]
            self.state['queue'] = [q for q in self.state['queue'] if q['kind'] != 'menu' or q['expiresAt'] > self.clock()]
            self.state['queue'] = [q for q in self.state['queue'] if q['kind'] not in ('security', 'security_digest') or q['expiresAt'] > self.clock()]
            self.state['queue'] = [q for q in self.state['queue'] if q['kind'] not in ('alarm', 'recovery') or q.get('expiresAt', self.clock() + 1) > self.clock()]
            if critical:
                self.state['queue'] = [q for q in self.state['queue'] if not self._critical_item(q) or q['expiresAt'] > self.clock()]
            self._retire_finished_aggregates()
            if len(self.state['queue']) != queue_size or release_changed:
                self._save()
            eligible = [q for q in self.state['queue'] if q['due'] <= self.clock() and q['phase'] == 'pending' and
                        (self.state['config']['enabled'] or q['kind'] in ('test', 'pairing', 'menu')) and
                        (q['kind'] != 'security_release' or self._release_ready(q)) and
                        (not (critical or self._aggregate_item(q)) or self._critical_delivery_ready(q, self.clock()))]
            preferred = next((q for q in eligible if critical and self.state['rules'].get((q.get('rule') or {}).get('id'), {}).get('rule') == 'ssh'), None)
            ordinary = next((q for q in eligible if q['kind'] != 'security_release'), eligible[0] if eligible else None)
            due = next((q for q in eligible if q['kind'] == 'menu'), preferred or ordinary)
            if not due:
                return
            item = copy.deepcopy(due)
            due['phase'] = 'sending'
            due['attempts'] += 1
            chat_id = self.state['chat']['id']
            self._save()
        try:
            payload = {'chat_id': chat_id, 'text': item['text'], 'disable_web_page_preview': True}
            method = 'sendMessage'
            if item['kind'] == 'menu':
                payload['reply_markup'] = item['replyMarkup']
                if item.get('editMessageId') is not None:
                    method = 'editMessageText'
                    payload['message_id'] = item['editMessageId']
            self.transport(method, payload)
        except Exception as error:
            failure = error if isinstance(error, AlertError) else DeliveryError()
            with self.lock:
                queued = next((q for q in self.state['queue'] if q['id'] == item['id']), None)
                if queued is None:
                    return
                code = failure.code if isinstance(failure, DeliveryError) else 0
                error_message = str(failure) if isinstance(failure, AlertError) else 'Telegram временно недоступен.'
                if item['kind'] == 'menu':
                    self.state['menuState']['lastError'] = error_message
                else:
                    self.state['lastError'] = error_message
                retryable = code in (0, 429) or code >= 500
                ambiguous_security = item['kind'] in ('security', 'security_digest') and (code == 0 or code >= 500)
                ambiguous_release = item['kind'] == 'security_release' and (code == 0 or code >= 500)
                ambiguous_critical = (self.state['config']['criticalOnly'] or self._aggregate_item(item)) and self._critical_item(item) and (code == 0 or code >= 500)
                if ambiguous_security or ambiguous_critical or ambiguous_release:
                    self._history(queued, 'uncertain')
                    self._finish_release(queued, 'uncertain')
                    self._mark_critical_uncertain(queued)
                    self.state['queue'] = [q for q in self.state['queue'] if q['id'] != item['id']]
                    self.state['lastError'] = ('Результат отправки уведомления об исправлении неизвестен; автоматического повтора нет.' if ambiguous_release else
                                               'Результат отправки критического уведомления неизвестен; автоматического повтора нет.' if ambiguous_critical else
                                               'Результат отправки SSH-сводки неизвестен; автоматического повтора нет.')
                elif retryable and queued['attempts'] < 5 and item['kind'] != 'menu':
                    delay = failure.retry_after if isinstance(failure, DeliveryError) and failure.retry_after else min(900, 15 * 2 ** (queued['attempts'] - 1))
                    queued.update(phase='pending', due=self.clock() + delay)
                    self.state['nextSendAt'] = self.clock() + delay
                else:
                    if item['kind'] != 'menu':
                        self._history(queued, 'failed')
                        self._finish_release(queued, 'failed')
                    self.state['queue'] = [q for q in self.state['queue'] if q['id'] != item['id']]
                self._retire_finished_aggregates()
                self._save()
            return
        with self.lock:
            self.state['queue'] = [q for q in self.state['queue'] if q['id'] != item['id']]
            if item['kind'] != 'menu':
                self.state['lastSentAt'] = self.clock()
            self.state['nextSendAt'] = self.clock() + 1
            if item['kind'] == 'menu':
                self.state['menuState']['lastError'] = ''
            else:
                self.state['lastError'] = ''
            if item['kind'] != 'menu':
                self._history(item, 'sent')
                self._finish_release(item, 'sent')
            if item.get('rule'):
                if self._is_awg_rx(item['rule']['id']):
                    self.state['awgRxLastNotice'][item['rule']['id']] = self.clock()
                rule = self.state['rules'].get(item['rule']['id'])
                if rule and rule['event'] == item['rule']['event'] and item['kind'] in ('alarm', 'reminder'):
                    rule['notified'] = True
                    rule['lastSentAt'] = self.clock()
            self._retire_finished_aggregates()
            self._save()

    def tick(self):
        if not self.tick_lock.acquire(blocking=False):
            return
        try:
            if self.storage_error:
                return
            self._poll_pairing()
            with self.lock:
                enabled = self.state['config']['enabled'] and self.state['chat'] is not None
            if enabled and self.security_release_fn is not None and self.clock() >= self.next_release_scan:
                self.next_release_scan = self.clock() + 30
                with self.lock:
                    self.release_eligible = set()
                    self.release_eligible_until = 0
                try:
                    events = self.security_release_fn()
                    if not isinstance(events, list) or len(events) > 64:
                        raise AlertError('Не удалось проверить кэш публикаций.')
                    validated = [self._release_event(event)[0] for event in events]
                    with self.lock:
                        self.release_eligible = set(validated)
                        self.release_eligible_until = self.clock() + 60
                    for event in events:
                        self.notify_security_release(event)
                except Exception:
                    with self.lock:
                        self.release_eligible = set()
                        self.release_eligible_until = 0
            if enabled:
                # Registry removals must cancel pending host notifications even
                # between the more expensive health-history scans.
                current_ids = {s['id'] for s in self.servers_fn()}
                with self.lock:
                    for key in list(self.state['rules']):
                        if self.state['rules'][key]['server'] not in current_ids:
                            del self.state['rules'][key]
                    self.state['queue'] = [q for q in self.state['queue'] if not q.get('server') or q['server'] in current_ids]
            if enabled and self.clock() >= self.next_health_scan:
                self.next_health_scan = self.clock() + 10
                try:
                    servers = self.servers_fn()
                    report = self.health_fn()
                    if not isinstance(report, dict) or not isinstance(report.get('servers'), dict):
                        raise ValueError()
                except Exception:
                    with self.lock:
                        self.state['lastError'] = 'Не удалось прочитать историю мониторинга; здоровое состояние не подтверждено.'
                    servers = self.servers_fn()
                    report = {'servers': {}}
                now = self.clock()
                with self.lock:
                    ids = {s['id'] for s in servers}
                    for key in list(self.state['rules']):
                        if self.state['rules'][key]['server'] not in ids:
                            del self.state['rules'][key]
                    self.state['queue'] = [q for q in self.state['queue'] if not q.get('server') or q['server'] in ids]
                    for name in ('firstObserved', 'lastSampleAt', 'expectedServices', 'expectedContainers', 'expectedAwg'):
                        self.state[name] = {k: v for k, v in self.state[name].items() if k in ids}
                    self.state['awgRxLastNotice'] = {key: value for key, value in self.state['awgRxLastNotice'].items()
                                                     if key.split('|', 1)[0] in ids}
                    for server in servers:
                        row = report['servers'].get(server['id']) or {}
                        self._evaluate_server(server, row.get('latest'), now)
                    self.state['lastCheckAt'] = now
                    self._save()
            if enabled and self.security_fn is not None and self.state['config']['security'] and self.clock() >= self.next_security_scan:
                self.next_security_scan = self.clock() + 10
                try:
                    report = self.security_fn()
                except Exception:
                    report = None
                with self.lock:
                    self._evaluate_security(report, self.clock())
                    self._save()
            self._flush()
        finally:
            self.tick_lock.release()

    def run(self, stop_event):
        while not stop_event.is_set():
            try:
                self.tick()
            except Exception:
                with self.lock:
                    self.state['lastError'] = 'Не удалось выполнить цикл уведомлений; требуется проверка доставки.'
            chat = self.state['chat']
            stop_event.wait(1 if (self.bot_menu is not None or self.bot_actions is not None) and chat and chat['type'] == 'private' else 10)
