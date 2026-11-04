"""One bounded RF diagnostic per observed SSH outage; cached reads never probe.

This module only coordinates the existing read-only measurement providers. It
never changes routes, firewall rules, SSH credentials or notification settings.
"""
import copy
import hashlib
import json
import os
import pathlib
import threading
import time


TERMINAL = frozenset(('done', 'partial', 'error', 'unavailable', 'cancelled', 'interrupted'))
COOLDOWN = 300
DEADLINE = 900
FRESH_SECONDS = 900
MAX_SERVERS = 128


def _identity(server):
    return hashlib.sha256(json.dumps([str(server['id']), str(server['host']),
                                     int(server.get('port', 22))],
                                    separators=(',', ':')).encode()).hexdigest()


def _reason(status):
    # Raw SSH errors can contain local key paths and usernames; only expose a code.
    error = str(status.get('error', '')).lower()
    if 'host key verification failed' in error or 'remote host identification has changed' in error:
        return 'host_key'
    if 'permission denied' in error or 'authentication failed' in error:
        return 'authentication'
    if status.get('tcpOk') is True:
        return 'ssh_or_remote_error'
    return 'network_or_host'


def _native_summary(result):
    country = result.get('point', {}).get('country')
    return {'status': result.get('status', 'error'), 'country': country,
            'verdict': result.get('verdict', 'unknown') if country == 'RU' else 'point_not_ru',
            'finishedAt': result.get('finishedAt'),
            'ruPointVerified': country == 'RU'}


def _chebur_summary(result):
    probes = result.get('probes') or []
    verdicts = {value for probe in probes if isinstance(probe, dict)
                for value in (probe.get('verdicts') or []) if isinstance(value, str)}
    if 'tspu_block' in verdicts:
        verdict = 'mixed' if 'ok' in verdicts else 'provider_tspu_indication'
    elif verdicts.intersection(('sni_block', 'dns_spoofing', 'cdn_block', 'whitelist')):
        verdict = 'provider_restriction_indication'
    elif probes and verdicts == {'ok'} and result.get('status') == 'done':
        verdict = 'reachable_on_probes'
    else:
        verdict = 'unconfirmed'
    return {'status': result.get('status', 'error'), 'verdict': verdict,
            'probeCount': len(probes), 'databaseMatch': (result.get('check') or {}).get('blocked'),
            'finishedAt': result.get('finishedAt')}


class OutageDiagnostics:
    def __init__(self, path, servers_fn, native_fn, chebur_fn, clock=time.time):
        self.path = pathlib.Path(path)
        self.servers_fn, self.native_fn, self.chebur_fn = servers_fn, native_fn, chebur_fn
        self.clock = clock
        self.lock = threading.RLock()
        self.wake = threading.Event()
        try:
            saved = json.loads(self.path.read_text())
            self.rows = saved if isinstance(saved, dict) and len(saved) <= MAX_SERVERS else {}
        except (OSError, ValueError):
            self.rows = {}
        changed = False
        for sid, row in list(self.rows.items()):
            if not isinstance(row, dict) or not isinstance(row.get('identity'), str):
                del self.rows[sid]
                changed = True
                continue
            # A process restart must not replay an uncertain external request.
            if row.get('status') in ('queued', 'running'):
                row.update(status='interrupted', finishedAt=self.clock())
                for kind in ('native', 'cheburcheck'):
                    item = row.get(kind, {})
                    if item.get('status') not in TERMINAL:
                        row[kind] = {'status': 'interrupted'}
                changed = True
        if changed:
            self._save()

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.path.with_suffix('.tmp')
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(self.rows, stream, ensure_ascii=False)
        os.replace(str(temporary), str(self.path))

    def observe(self, server, status):
        """Record a monitor transition. No provider/network call occurs here."""
        sid, identity, now = str(server['id']), _identity(server), self.clock()
        down = status.get('ok') is not True
        with self.lock:
            row = self.rows.get(sid)
            if row and row.get('identity') != identity:
                row = None
                self.rows.pop(sid, None)
            if not down:
                if row and row.get('sshReachable') is False:
                    row.update(sshReachable=True, sshRecoveredAt=now)
                    if row.get('status') == 'queued':
                        row.update(status='cancelled', finishedAt=now)
                        row['native'] = {'status': 'cancelled'}
                        row['cheburcheck'] = {'status': 'cancelled'}
                    self._save()
                return False
            if row and row.get('sshReachable') is False:
                # A second outage inside the flap cooldown is delayed, not
                # suppressed forever. Once elapsed, queue that outage once.
                if not row.get('suppressedAt') or now - row.get('triggeredAt', 0) < COOLDOWN:
                    return False
            # A flap immediately after recovery does not generate another batch.
            if row and now - row.get('triggeredAt', 0) < COOLDOWN:
                row.update(sshReachable=False, suppressedAt=now)
                self._save()
                return False
            if len(self.rows) >= MAX_SERVERS and sid not in self.rows:
                # Registry-sized bounded state; remove only records absent in registry.
                registered = {str(item['id']) for item in self.servers_fn()}
                self.rows = {key: value for key, value in self.rows.items() if key in registered}
                if len(self.rows) >= MAX_SERVERS:
                    return False
            self.rows[sid] = {'server': sid, 'name': str(server.get('name') or server['host'])[:80],
                              'host': str(server['host']), 'port': int(server.get('port', 22)),
                              'identity': identity, 'triggeredAt': now, 'deadlineAt': now + DEADLINE,
                              'status': 'queued', 'sshReachable': False,
                              'tcpOk': status.get('tcpOk') is True, 'reason': _reason(status),
                              'native': {'status': 'queued'}, 'cheburcheck': {'status': 'queued'}}
            self._save()
            self.wake.set()
            return True

    def snapshot(self):
        identities = {str(server['id']): _identity(server) for server in self.servers_fn()}
        now = self.clock()
        with self.lock:
            rows = {sid: copy.deepcopy(row) for sid, row in self.rows.items()
                    if identities.get(sid) == row.get('identity')}
        for row in rows.values():
            row.pop('identity', None)
            row.pop('deadlineAt', None)
            row['stale'] = now - row.get('finishedAt', row['triggeredAt']) > FRESH_SECONDS
        return {'automatic': True, 'cooldownSeconds': COOLDOWN, 'staleAfterSeconds': FRESH_SECONDS,
                'servers': rows, 'checkedAt': now}

    def _update(self, sid, triggered, **values):
        with self.lock:
            row = self.rows.get(sid)
            if row is not None and row.get('triggeredAt') == triggered:
                row.update(values)
                self._save()

    def _provider(self, kind, manager, snapshot, server, row):
        item = row.get(kind, {})
        if item.get('status') in TERMINAL:
            return
        sid, triggered = server['id'], row['triggeredAt']
        if item.get('status') == 'running':
            result = (snapshot.get('servers') or {}).get(sid, {})
            # Capture the provider's start time after launch. A later manual
            # run must not silently replace this outage's result. NativeProbe
            # rewrites its timestamp when its thread begins, hence 1s tolerance.
            if (str(result.get('host', '')).lower() == str(server['host']).lower() and
                    abs(result.get('startedAt', 0) - item.get('providerStartedAt', item.get('requestedAt', triggered))) <= 1 and
                    result.get('status') in ('done', 'partial', 'error')):
                summary = _native_summary(result) if kind == 'native' else _chebur_summary(result)
                self._update(sid, triggered, **{kind: summary})
            return
        if kind == 'native' and snapshot.get('available') is not True:
            self._update(sid, triggered, native={'status': 'unavailable', 'verdict': 'point_unavailable',
                                                'ruPointVerified': False})
            return
        if snapshot.get('busy') or self.clock() < snapshot.get('nextStartAt', 0):
            return
        requested_at = self.clock()
        try:
            if kind == 'native':
                targets = [{'port': server.get('port', 22)}]
                if server.get('port', 22) != 443:
                    targets.append({'port': 443})
                manager.start(server, targets, interface='en0')
            else:
                manager.start(server)
            launched = (manager.snapshot().get('servers') or {}).get(sid, {})
            started_at = launched.get('startedAt', requested_at)
            self._update(sid, triggered, **{kind: {'status': 'running', 'requestedAt': requested_at,
                                                 'providerStartedAt': started_at}})
        except ValueError:
            # Existing provider rate limits or a competing manual check are retried
            # only before this outage's bounded deadline, with no extra requests.
            self._update(sid, triggered, **{kind: {'status': 'queued', 'waitReason': 'provider_busy_or_unavailable'}})
        except Exception:
            self._update(sid, triggered, **{kind: {'status': 'error', 'verdict': 'provider_unavailable'}})

    def tick(self):
        """Advance active work. Called by one worker, never the HTTP GET path."""
        now = self.clock()
        registry = {str(server['id']): server for server in self.servers_fn()}
        with self.lock:
            active = [copy.deepcopy(row) for row in self.rows.values()
                      if row.get('status') in ('queued', 'running')]
        providers = {}
        for kind, factory in (('native', self.native_fn), ('cheburcheck', self.chebur_fn)):
            if any(row.get(kind, {}).get('status') not in TERMINAL for row in active):
                try:
                    manager = factory()
                    providers[kind] = (manager, manager.snapshot())
                except Exception:
                    providers[kind] = None
        for row in sorted(active, key=lambda value: value['triggeredAt']):
            sid, triggered = row['server'], row['triggeredAt']
            server = registry.get(sid)
            if not server or _identity(server) != row['identity']:
                self._update(sid, triggered, status='cancelled', finishedAt=now)
                continue
            if now >= row['deadlineAt']:
                changes = {kind: {'status': 'error', 'verdict': 'deadline_exceeded'}
                           for kind in ('native', 'cheburcheck')
                           if row.get(kind, {}).get('status') not in TERMINAL}
                changes.update(status='partial', finishedAt=now)
                self._update(sid, triggered, **changes)
                continue
            if row.get('sshReachable') and row.get('status') == 'queued':
                self._update(sid, triggered, status='cancelled', finishedAt=now)
                continue
            self._update(sid, triggered, status='running')
            safe_server = {key: server[key] for key in ('id', 'host')}
            safe_server.update(name=str(server.get('name') or server['host'])[:80], port=int(server.get('port', 22)))
            for kind in ('native', 'cheburcheck'):
                if row.get(kind, {}).get('status') in TERMINAL:
                    continue
                pair = providers.get(kind)
                if not pair:
                    self._update(sid, triggered, **{kind: {'status': 'error', 'verdict': 'provider_unavailable'}})
                    continue
                self._provider(kind, pair[0], pair[1], safe_server, row)
                # Prevent starting several requests from the same snapshot.
                try:
                    providers[kind] = (pair[0], pair[0].snapshot())
                except Exception:
                    providers[kind] = None
            with self.lock:
                current = copy.deepcopy(self.rows.get(sid, {}))
            if (current.get('triggeredAt') == triggered and
                    all(current.get(kind, {}).get('status') in TERMINAL for kind in ('native', 'cheburcheck'))):
                status = 'done' if current['cheburcheck']['status'] == 'done' else 'partial'
                self._update(sid, triggered, status=status, finishedAt=self.clock())

    def run(self, stop):
        while not stop.is_set():
            try:
                self.tick()
            except Exception:
                # No raw provider or filesystem exception is logged as it can carry
                # a key path or request context. The worker retries bounded state.
                pass
            self.wake.wait(1)
            self.wake.clear()
