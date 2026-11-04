"""Observed security telemetry only; report() never contacts hosts or changes bans.

Collectors provide stable event IDs and explicit complete component snapshots.
Missing components retain the last good observation, with an error/freshness flag.
"""
import contextlib
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import re
import sqlite3
import time

RETENTION = 7 * 86400
STALE = 180
MAX_EVENTS = 4096
MAX_BANS = 4096
MAX_STORED_SAMPLES = 20000
MAX_STORED_EVENTS = 100000
MAX_STORED_BAN_HISTORY = 100000
KINDS = {'failed_password', 'invalid_user', 'failed_publickey', 'ban', 'unban'}
COMPONENTS = ('events', 'counters', 'localBans', 'sharedBans')


class SecurityStatsError(ValueError):
    pass


def number(value, default=None):
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else default


def text(value, limit=300):
    if not isinstance(value, str):
        return ''
    return ''.join(c for c in value if ord(c) >= 32 and ord(c) != 127)[:limit]


def ip(value):
    if not isinstance(value, str) or len(value) > 64 or '%' in value:
        raise ValueError('Invalid IP address')
    return str(ipaddress.ip_address(value))


def sid_value(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', value):
        raise ValueError('Invalid server identity')
    return value


SCHEMA = '''
CREATE TABLE IF NOT EXISTS hosts(
 sid TEXT PRIMARY KEY,first_seen REAL NOT NULL,last_attempt REAL NOT NULL,
 last_collected REAL,last_error TEXT NOT NULL,components TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS samples(
 id INTEGER PRIMARY KEY AUTOINCREMENT,sid TEXT NOT NULL,ts REAL NOT NULL,
 boot TEXT,epoch TEXT,packets INTEGER,bytes INTEGER,delta_packets INTEGER,
 delta_bytes INTEGER,interval_start REAL,reset_reason TEXT,events_ok INTEGER NOT NULL,
 UNIQUE(sid,ts));
CREATE INDEX IF NOT EXISTS security_samples_time ON samples(sid,ts);
CREATE TABLE IF NOT EXISTS events(
 sid TEXT NOT NULL,event_id TEXT NOT NULL,ts REAL NOT NULL,kind TEXT NOT NULL,
 ip TEXT NOT NULL,jail TEXT NOT NULL,reason TEXT NOT NULL,count INTEGER NOT NULL,
 PRIMARY KEY(sid,event_id));
CREATE INDEX IF NOT EXISTS security_events_time ON events(sid,ts);
CREATE TABLE IF NOT EXISTS bans(
 sid TEXT NOT NULL,scope TEXT NOT NULL,ip TEXT NOT NULL,first_observed REAL NOT NULL,
 reported_since REAL,expires_at REAL,remaining REAL,reported_at REAL NOT NULL,
 permanent INTEGER,jail TEXT NOT NULL,reason TEXT NOT NULL,
 PRIMARY KEY(sid,scope,ip));
CREATE TABLE IF NOT EXISTS ban_history(
 id INTEGER PRIMARY KEY AUTOINCREMENT,sid TEXT NOT NULL,scope TEXT NOT NULL,
 ip TEXT NOT NULL,ts REAL NOT NULL,action TEXT NOT NULL,details TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS security_ban_history_time ON ban_history(sid,ts);
CREATE TABLE IF NOT EXISTS shared_history(
 id INTEGER PRIMARY KEY AUTOINCREMENT,ip TEXT NOT NULL,ts REAL NOT NULL,action TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS security_shared_history_time ON shared_history(ts);
CREATE TABLE IF NOT EXISTS metadata(
 ip TEXT PRIMARY KEY,data TEXT NOT NULL,lookup_at REAL,lookup_error TEXT NOT NULL,error_at REAL);
'''


class SecurityStats:
    def __init__(self, path, clock=time.time):
        self.path = pathlib.Path(path).resolve()
        self.clock = clock
        self.storage_error = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as c:
                version = c.execute('PRAGMA user_version').fetchone()[0]
                if version not in (0, 1):
                    raise SecurityStatsError('Unsupported statistics schema')
                c.execute('PRAGMA journal_mode=WAL')
                c.executescript(SCHEMA)
                if version == 0:
                    c.execute('PRAGMA user_version=1')
            self.path.chmod(0o600)
        except (OSError, sqlite3.Error, SecurityStatsError):
            # Do not replace, truncate or silently recreate a damaged database.
            self.storage_error = 'Хранилище статистики защиты недоступно'

    @contextlib.contextmanager
    def _connect(self, readonly=False):
        if self.storage_error:
            raise SecurityStatsError(self.storage_error)
        c = sqlite3.connect(self.path.as_uri() + '?mode=ro' if readonly else str(self.path),
                            uri=readonly, timeout=15)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA busy_timeout=15000')
        if readonly:
            c.execute('PRAGMA query_only=ON')
        try:
            yield c
            if not readonly:
                c.commit()
        except Exception:
            if not readonly:
                c.rollback()
            raise
        finally:
            c.close()

    def _time(self, value=None):
        result = number(self.clock() if value is None else value)
        if result is None:
            raise ValueError('Invalid collection time')
        return result

    @staticmethod
    def _empty_components():
        return {k: {'checkedAt': None, 'lastGoodAt': None, 'error': 'Ещё не получено'} for k in COMPONENTS}

    @staticmethod
    def _truncated_between(component, start, end):
        if any(start <= ts <= end for ts in component.get('truncatedAt', [])):
            return True
        if any(left < end and right > start for left, right in component.get('missingRanges', [])):
            return True
        # The bounded overflow range is deliberately conservative: it can
        # overstate incompleteness, but never invent complete historical data.
        first, last = component.get('truncatedOverflowFrom'), component.get('truncatedOverflowUntil')
        if first is not None and last is not None and first <= end and last >= start:
            return True
        first, last = component.get('retentionClippedFrom'), component.get('retentionClippedUntil')
        return bool(first is not None and last is not None and first <= end and last >= start)

    def _host(self, c, sid, ts):
        row = c.execute('SELECT * FROM hosts WHERE sid=?', (sid,)).fetchone()
        if row:
            return dict(row), json.loads(row['components'])
        if c.execute('SELECT COUNT(*) FROM hosts').fetchone()[0] >= 128:
            raise SecurityStatsError('Too many monitored hosts')
        components = self._empty_components()
        c.execute('INSERT INTO hosts VALUES(?,?,?,?,?,?)',
                  (sid, ts, ts, None, '', json.dumps(components)))
        return {'sid': sid, 'first_seen': ts, 'last_attempt': ts, 'last_collected': None, 'last_error': ''}, components

    @staticmethod
    def _events(value, now):
        if not isinstance(value, list) or len(value) > MAX_EVENTS:
            raise ValueError('Неверный или слишком большой список событий')
        result = []
        for event in value:
            if not isinstance(event, dict):
                raise ValueError('Неверное событие')
            raw_identity = event.get('id')
            identity = text(raw_identity, 512)
            ts = number(event.get('ts'))
            kind = event.get('kind')
            count = event.get('count', 1)
            if not isinstance(raw_identity, str) or len(raw_identity) > 512 or not identity or ts is None or ts > now + 60 or kind not in KINDS or type(count) is not int or not 1 <= count <= 1000000:
                raise ValueError('Неверная идентичность, время или тип события')
            address = ip(event.get('sourceIp'))
            if ts >= now - RETENTION:
                result.append((hashlib.sha256(identity.encode()).hexdigest(), ts, kind, address,
                               text(event.get('jail'), 100), text(event.get('reason')), count))
        return result

    @staticmethod
    def _counters(value):
        if not isinstance(value, dict) or type(value.get('blockedPackets')) is not int or not 0 <= value['blockedPackets'] <= 9223372036854775807:
            raise ValueError('Счётчик заблокированных пакетов не получен')
        size = value.get('blockedBytes')
        if size is not None and (type(size) is not int or not 0 <= size <= 9223372036854775807):
            raise ValueError('Неверный счётчик байтов')
        return value['blockedPackets'], size

    @staticmethod
    def _bans(value, now):
        if not isinstance(value, list) or len(value) > MAX_BANS:
            raise ValueError('Неверный или слишком большой список блокировок')
        result = {}
        for raw in value:
            raw = {'ip': raw} if isinstance(raw, str) else raw
            if not isinstance(raw, dict):
                raise ValueError('Неверная блокировка')
            address = ip(raw.get('ip'))
            since = number(raw.get('since', raw.get('bannedAt')))
            if since is not None and since > now + 60:
                raise ValueError('Неверное время блокировки')
            expires = number(raw.get('expiresAt'))
            remaining = number(raw.get('remainingSeconds'))
            permanent = raw.get('permanent') if type(raw.get('permanent')) is bool else None
            if permanent is not True and (expires is not None and expires <= now or remaining is not None and remaining == 0):
                continue
            item = {'ip': address, 'since': since, 'expiresAt': expires, 'remainingSeconds': remaining,
                    'permanent': permanent, 'jail': text(raw.get('jail'), 100), 'reason': text(raw.get('reason'))}
            if address in result:
                old = result[address]
                item['jail'] = ', '.join(sorted(set(filter(None, [old['jail'], item['jail']]))))[:200]
                item['reason'] = '; '.join(sorted(set(filter(None, [old['reason'], item['reason']]))))[:600]
                item['since'] = min(old['since'], item['since']) if old['since'] is not None and item['since'] is not None else None
                if old['permanent'] is True or item['permanent'] is True:
                    item.update(permanent=True, expiresAt=None, remainingSeconds=None)
                elif old['expiresAt'] is not None and item['expiresAt'] is not None:
                    item['expiresAt'] = max(old['expiresAt'], item['expiresAt'])
                else:
                    item['expiresAt'] = None
            result[address] = item
        return result

    def _snapshot(self, c, sid, scope, items, now, baseline):
        previous = {r['ip']: dict(r) for r in c.execute('SELECT * FROM bans WHERE sid=? AND scope=?', (sid, scope))}
        global_before = {r['ip'] for r in c.execute("SELECT * FROM bans WHERE scope='shared'") if self._active_ban(r, now)} if scope == 'shared' else set()
        for address, item in items.items():
            old = previous.get(address)
            if old is not None and not self._active_ban(old, now):
                old = None  # A verified expired episode is not a stable ban.
            first = old['first_observed'] if old else now
            c.execute('INSERT OR REPLACE INTO bans VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                      (sid, scope, address, first, item['since'], item['expiresAt'], item['remainingSeconds'], now,
                       None if item['permanent'] is None else int(item['permanent']), item['jail'], item['reason']))
            if not old:
                action = 'baseline' if baseline else 'added'
                c.execute('INSERT INTO ban_history(sid,scope,ip,ts,action,details) VALUES(?,?,?,?,?,?)',
                          (sid, scope, address, now, action, json.dumps(item)))
                if scope == 'shared' and address not in global_before:
                    c.execute('INSERT INTO shared_history(ip,ts,action) VALUES(?,?,?)', (address, now, action))
                    global_before.add(address)
        for address, old in previous.items():
            if address in items:
                continue
            c.execute('DELETE FROM bans WHERE sid=? AND scope=? AND ip=?', (sid, scope, address))
            c.execute('INSERT INTO ban_history(sid,scope,ip,ts,action,details) VALUES(?,?,?,?,?,?)',
                      (sid, scope, address, now, 'removed', json.dumps({'jail': old['jail'], 'reason': old['reason']})))
            if scope == 'shared' and not c.execute("SELECT 1 FROM bans WHERE scope='shared' AND ip=? LIMIT 1", (address,)).fetchone():
                c.execute('INSERT INTO shared_history(ip,ts,action) VALUES(?,?,?)', (address, now, 'removed'))

    def _prune(self, c, now):
        cutoff = now - RETENTION
        for table in ('samples', 'events', 'ban_history', 'shared_history'):
            c.execute('DELETE FROM ' + table + ' WHERE ts<?', (cutoff,))
        for table, maximum in (('samples', MAX_STORED_SAMPLES), ('events', MAX_STORED_EVENTS), ('ban_history', MAX_STORED_BAN_HISTORY)):
            for row in c.execute('SELECT sid,COUNT(*) AS n FROM ' + table + ' GROUP BY sid').fetchall():
                if row['n'] > maximum:
                    if table == 'events':
                        bounds = c.execute('SELECT MIN(ts),MAX(ts) FROM (SELECT ts FROM events WHERE sid=? ORDER BY ts,rowid LIMIT ?)',
                                           (row['sid'], row['n'] - maximum)).fetchone()
                        stored = c.execute('SELECT components FROM hosts WHERE sid=?', (row['sid'],)).fetchone()
                        components = json.loads(stored['components'])
                        event_state = components['events']
                        event_state['retentionClippedFrom'] = min(bounds[0], event_state.get('retentionClippedFrom', bounds[0]))
                        event_state['retentionClippedUntil'] = max(bounds[1], event_state.get('retentionClippedUntil', bounds[1]))
                        c.execute('UPDATE hosts SET components=? WHERE sid=?', (json.dumps(components), row['sid']))
                    c.execute('DELETE FROM ' + table + ' WHERE rowid IN (SELECT rowid FROM ' + table + ' WHERE sid=? ORDER BY ts LIMIT ?)',
                              (row['sid'], row['n'] - maximum))
        c.execute('DELETE FROM metadata WHERE ip IN (SELECT ip FROM metadata ORDER BY COALESCE(lookup_at,error_at,0) DESC LIMIT -1 OFFSET 100000)')

    def ingest(self, sid, payload, collected_at=None):
        sid = sid_value(sid)
        if not isinstance(payload, dict):
            raise ValueError('Telemetry must be an object')
        now = self._time(collected_at if collected_at is not None else payload.get('collectedAt', self.clock()))
        if now > self._time() + 300:
            raise ValueError('Collection time is in the future')
        errors = payload.get('errors') or {}
        if not isinstance(errors, dict):
            raise ValueError('Component errors must be an object')
        values, failures = {}, {}
        for name, key, parser in [('events', 'events', lambda x: self._events(x, now)),
                                   ('counters', 'counters', self._counters),
                                   ('localBans', 'local', lambda x: self._bans(x, now)),
                                   ('sharedBans', 'shared', lambda x: self._bans(x, now))]:
            source = payload.get('bans', {}) if name.endswith('Bans') else payload
            try:
                if errors.get(name):
                    raise ValueError(text(errors[name], 500) or 'Ошибка сбора')
                if not isinstance(source, dict) or key not in source:
                    raise ValueError('Данные компонента не получены')
                value = source[key]
                if name == 'events' and payload.get('eventsTruncated') is True and isinstance(value, list) and len(value) > MAX_EVENTS:
                    # The collector delivers journal events in time order. A
                    # bounded explicit partial delivery keeps its newest tail.
                    value = value[-MAX_EVENTS:]
                values[name] = parser(value)
            except (ValueError, TypeError, OverflowError) as error:
                failures[name] = text(str(error), 500)
        try:
            with self._connect() as c:
                c.execute('BEGIN IMMEDIATE')
                host, components = self._host(c, sid, now)
                new_events = 0
                for event in values.get('events', []):
                    cursor = c.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?)', (sid,) + event)
                    new_events += cursor.rowcount
                # Late events may fill history, but an old delivery must not rewind current state.
                ordered = host['last_collected'] is None or now > host['last_collected']
                if ordered:
                    previous_events_good = components['events']['lastGoodAt']
                    previous = c.execute('SELECT * FROM samples WHERE sid=? AND packets IS NOT NULL ORDER BY ts DESC LIMIT 1', (sid,)).fetchone()
                    packets, size = values.get('counters', (None, None))
                    boot, epoch = text(payload.get('bootId'), 160), text(payload.get('counterEpoch'), 256)
                    delta, delta_bytes, start, reset = None, None, None, None
                    if packets is not None:
                        if not previous: reset = 'first_sample'
                        elif not boot or not epoch or not previous['boot'] or not previous['epoch']: reset = 'identity_missing'
                        elif boot != previous['boot']: reset = 'boot_changed'
                        elif epoch != previous['epoch']: reset = 'counter_epoch_changed'
                        elif not 0 < now - previous['ts'] <= STALE: reset = 'collection_gap'
                        elif packets < previous['packets'] or size is not None and previous['bytes'] is not None and size < previous['bytes']: reset = 'counter_decreased'
                        else:
                            delta = packets - previous['packets']; start = previous['ts']
                            if size is not None and previous['bytes'] is not None:
                                delta_bytes = size - previous['bytes']
                    c.execute('INSERT OR IGNORE INTO samples(sid,ts,boot,epoch,packets,bytes,delta_packets,delta_bytes,interval_start,reset_reason,events_ok) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                              (sid, now, boot, epoch, packets, size, delta, delta_bytes, start, reset, int('events' in values)))
                    for name, scope in [('localBans', 'local'), ('sharedBans', 'shared')]:
                        if name in values:
                            self._snapshot(c, sid, scope, values[name], now, components[name]['lastGoodAt'] is None)
                    for name in COMPONENTS:
                        components[name]['checkedAt'] = now
                        components[name]['error'] = failures.get(name, '')
                        if name in values:
                            components[name]['lastGoodAt'] = now
                    event_state = components['events']
                    missing = [pair for pair in event_state.get('missingRanges', []) if pair[1] >= self._time() - RETENTION]
                    window_start = number(payload.get('eventsWindowStart'))
                    window_end = number(payload.get('eventsWindowEnd', now))
                    if 'events' in values and window_start is not None and window_end is not None and window_start <= window_end <= now + 60:
                        previous_end = event_state.get('coverageUntil', previous_events_good)
                        if previous_end is not None and window_start > previous_end:
                            missing.append([previous_end, window_start])
                        if payload.get('eventsTruncated') is True and window_start < window_end:
                            missing.append([window_start, window_end])
                        event_state['observedFrom'] = min(window_start, event_state.get('observedFrom', window_start))
                        event_state['coverageUntil'] = max(window_end, event_state.get('coverageUntil', window_end))
                    merged = []
                    for left, right in sorted(missing):
                        if merged and left <= merged[-1][1]: merged[-1][1] = max(merged[-1][1], right)
                        else: merged.append([left, right])
                    if len(merged) > 256:
                        merged = [[merged[0][0], merged[-256][1]]] + merged[-255:]
                    event_state['missingRanges'] = merged
                    gaps = [ts for ts in event_state.get('truncatedAt', []) if ts >= self._time() - RETENTION]
                    event_state['partial'] = payload.get('eventsTruncated') is True
                    if event_state['partial'] and 'events' in values:
                        gaps.append(now)
                    if len(gaps) > 20000:
                        omitted = gaps[:-20000]
                        event_state['truncatedOverflowFrom'] = min(omitted[0], event_state.get('truncatedOverflowFrom', omitted[0]))
                        event_state['truncatedOverflowUntil'] = omitted[-1]
                        gaps = gaps[-20000:]
                    if event_state.get('truncatedOverflowUntil', 0) < self._time() - RETENTION:
                        event_state.pop('truncatedOverflowFrom', None); event_state.pop('truncatedOverflowUntil', None)
                    if event_state.get('retentionClippedUntil', 0) < self._time() - RETENTION:
                        event_state.pop('retentionClippedFrom', None); event_state.pop('retentionClippedUntil', None)
                    event_state['truncatedAt'] = gaps
                    partial_error = 'Неполные данные коллектора' if payload.get('complete') is False else ''
                    c.execute('UPDATE hosts SET last_attempt=?,last_collected=?,last_error=?,components=? WHERE sid=?',
                              (now, now, partial_error, json.dumps(components), sid))
                self._prune(c, self._time())
                return {'newEvents': new_events, 'partial': bool(failures) or payload.get('complete') is False or payload.get('eventsTruncated') is True, 'errors': failures, 'lateDelivery': not ordered}
        except sqlite3.Error as error:
            raise SecurityStatsError('Не удалось сохранить статистику защиты') from error

    def ingest_error(self, sid, error, collected_at=None):
        sid = sid_value(sid); now = self._time(collected_at)
        try:
            with self._connect() as c:
                c.execute('BEGIN IMMEDIATE')
                host, components = self._host(c, sid, now)
                if now >= host['last_attempt']:
                    c.execute('UPDATE hosts SET last_attempt=?,last_error=? WHERE sid=?',
                              (now, text(str(error), 500) or 'Ошибка сбора', sid))
                self._prune(c, self._time())
        except sqlite3.Error as exc:
            raise SecurityStatsError('Не удалось сохранить ошибку сбора') from exc

    def upsert_metadata(self, address, metadata=None, looked_up_at=None, error=None):
        address = ip(address)
        metadata = metadata or {}
        if not isinstance(metadata, dict):
            raise ValueError('Metadata must be an object')
        now = self._time(looked_up_at if looked_up_at is not None else metadata.get('lookupAt', self.clock()))
        error = error or metadata.get('lookupError')
        fields = {}
        for key in ('name', 'countrySource', 'region', 'source', 'asHolder'):
            if metadata.get(key): fields[key] = text(metadata[key], 200)
        country = metadata.get('country', '')
        if isinstance(country, str):
            codes = re.split(r'[, /;]+', country.upper())
            if codes and all(re.fullmatch(r'[A-Z]{2}', v) for v in codes): fields['country'] = ', '.join(sorted(set(codes)))
        raw_asn = metadata.get('asn', [])
        raw_asn = raw_asn if isinstance(raw_asn, list) else re.split(r'[, /;]+', str(raw_asn))
        asns = set()
        for value in raw_asn[:16]:
            value = str(value).upper().removeprefix('AS')
            if value.isdigit() and 0 < int(value) <= 4294967295: asns.add(int(value))
        if asns: fields['asn'] = ', '.join('AS' + str(v) for v in sorted(asns))
        prefix = metadata.get('prefix')
        if metadata.get('network'):
            fields['network'] = text(metadata['network'], 200)
            if '/' in fields['network'] and prefix is None: prefix = fields['network']
        if prefix:
            network = ipaddress.ip_network(prefix, strict=False)
            if ipaddress.ip_address(address) not in network: raise ValueError('IP is outside metadata network')
            fields['prefix'] = str(network)
        fields['sourceUrl'] = 'https://stat.ripe.net/' + address
        try:
            with self._connect() as c:
                c.execute('BEGIN IMMEDIATE')
                old = c.execute('SELECT * FROM metadata WHERE ip=?', (address,)).fetchone()
                if error:
                    data, stamp = (old['data'], old['lookup_at']) if old else ('{}', None)
                    c.execute('INSERT OR REPLACE INTO metadata VALUES(?,?,?,?,?)', (address, data, stamp, text(str(error), 500), now))
                else:
                    c.execute('INSERT OR REPLACE INTO metadata VALUES(?,?,?,?,?)', (address, json.dumps(fields), now, '', None))
                self._prune(c, self._time())
        except sqlite3.Error as exc:
            raise SecurityStatsError('Не удалось сохранить сведения о сети') from exc

    @staticmethod
    def _metadata(c, address):
        row = c.execute('SELECT * FROM metadata WHERE ip=?', (address,)).fetchone()
        result = {k: None for k in ('asn', 'network', 'prefix', 'asHolder', 'country', 'countrySource', 'lookupAt', 'lookupError', 'sourceUrl')}
        if row:
            result.update(json.loads(row['data'])); result['lookupAt'] = row['lookup_at']; result['lookupError'] = row['lookup_error'] or None
        return result

    def metadata_due(self, limit=12, max_age=604800, retry_after=900):
        if type(limit) is not int or not 1 <= limit <= 64:
            raise ValueError('Invalid metadata lookup limit')
        if number(max_age) is None or number(retry_after) is None:
            raise ValueError('Invalid metadata age')
        now = self._time()
        with self._connect(readonly=True) as c:
            rows = c.execute('''SELECT source.ip,MAX(source.seen) AS seen,m.lookup_at,m.lookup_error,m.error_at
                FROM (SELECT ip,ts AS seen FROM events WHERE ts>=? AND ts<=?
                      UNION ALL SELECT ip,reported_at AS seen FROM bans) source
                LEFT JOIN metadata m ON source.ip=m.ip GROUP BY source.ip ORDER BY seen DESC LIMIT 20000''',
                (now - RETENTION, now)).fetchall()
            result = []
            for row in rows:
                if not ipaddress.ip_address(row['ip']).is_global:
                    continue
                if row['error_at'] is not None and now - row['error_at'] < retry_after:
                    continue
                if row['lookup_at'] is None or now - row['lookup_at'] >= max_age or row['lookup_error']:
                    result.append(row['ip'])
                    if len(result) >= limit: break
            return result

    @staticmethod
    def _active_ban(row, now):
        return row['permanent'] == 1 or not (row['expires_at'] is not None and row['expires_at'] <= now or
                                           row['remaining'] is not None and row['reported_at'] + row['remaining'] <= now)

    @staticmethod
    def _union_bans(rows, now):
        grouped = {}
        for row in rows:
            if not SecurityStats._active_ban(row, now):
                continue
            grouped.setdefault(row['ip'], []).append(dict(row))
        result = []
        for address, items in grouped.items():
            scopes = {v['scope'] for v in items}
            since = min(v['reported_since'] for v in items) if all(v['reported_since'] is not None for v in items) else None
            permanent = True if any(v['permanent'] == 1 for v in items) else False if all(v['permanent'] == 0 for v in items) else None
            expires = max(v['expires_at'] for v in items) if permanent is not True and all(v['expires_at'] is not None for v in items) else None
            remaining_values = [max(0, v['expires_at'] - now) if v['expires_at'] is not None else max(0, v['remaining'] - (now - v['reported_at'])) if v['remaining'] is not None else None for v in items]
            remaining = max(remaining_values) if permanent is not True and all(v is not None for v in remaining_values) else None
            result.append({'ip': address, 'source': 'both' if len(scopes) == 2 else next(iter(scopes)),
                'jail': ', '.join(sorted(set(filter(None, (v['jail'] for v in items))))),
                'reason': '; '.join(sorted(set(filter(None, (v['reason'] for v in items))))),
                'since': since, 'bannedAt': since, 'firstObservedAt': min(v['first_observed'] for v in items),
                'expiresAt': expires, 'remainingSeconds': remaining, 'permanent': permanent})
        return sorted(result, key=lambda v: (-v['firstObservedAt'], v['ip']))

    @staticmethod
    def _registry(servers):
        if not isinstance(servers, (list, tuple)) or len(servers) > 128:
            raise ValueError('Invalid server registry')
        return [{'id': sid_value(s['id']), 'name': text(s.get('name'), 160), 'host': text(s.get('host'), 253)} for s in servers]

    def report(self, servers, hours=24):
        if type(hours) is not int or hours not in (1, 24, 168): raise ValueError('Unsupported time window')
        registry = self._registry(servers); now = self._time(); start = now - hours * 3600
        interval = {1: 300, 24: 3600, 168: 21600}[hours]
        result = {'generatedAt': now, 'hours': hours, 'intervalSeconds': 60, 'staleAfterSeconds': STALE,
                  'coverage': {'requestedFrom': start, 'to': now, 'retentionSeconds': RETENTION}, 'servers': []}
        try:
            with self._connect(readonly=True) as c:
                for server in registry:
                    sid = server['id']; state = c.execute('SELECT * FROM hosts WHERE sid=?', (sid,)).fetchone()
                    components = json.loads(state['components']) if state else self._empty_components()
                    for component in components.values():
                        component['stale'] = component['lastGoodAt'] is None or now - component['lastGoodAt'] > STALE
                        component['available'] = component['lastGoodAt'] is not None
                    samples = [dict(v) for v in c.execute('SELECT * FROM samples WHERE sid=? AND ts>=? AND ts<=? ORDER BY ts', (sid, start, now))]
                    events = [dict(v) for v in c.execute('SELECT * FROM events WHERE sid=? AND ts>=? AND ts<=? ORDER BY ts', (sid, start, now))]
                    oldest_sample = c.execute('SELECT MIN(ts) FROM samples WHERE sid=?', (sid,)).fetchone()[0]
                    oldest_event = c.execute('SELECT MIN(ts) FROM events WHERE sid=?', (sid,)).fetchone()[0]
                    clipped_start = components['events'].get('retentionClippedFrom')
                    if components['events'].get('retentionClippedUntil', 0) < now - RETENTION: clipped_start = None
                    history_candidates = [v for v in (oldest_sample, oldest_event, clipped_start, components['events'].get('observedFrom')) if v is not None]
                    history_start = min(history_candidates) if history_candidates else None
                    latest = c.execute('SELECT * FROM samples WHERE sid=? AND packets IS NOT NULL ORDER BY ts DESC LIMIT 1', (sid,)).fetchone()
                    totals = {kind: sum(e['count'] for e in events if e['kind'] == kind) for kind in KINDS}
                    current_bans = self._union_bans(c.execute('SELECT * FROM bans WHERE sid=?', (sid,)), now)
                    for banned in current_bans: banned.update(self._metadata(c, banned['ip']))
                    sources = {}
                    for event in events:
                        row = sources.setdefault(event['ip'], {'ip': event['ip'], 'attempts': 0, 'invalidUsers': 0, 'failedPublickeys': 0, 'firstSeen': event['ts'], 'lastSeen': event['ts']})
                        field = {'failed_password': 'attempts', 'invalid_user': 'invalidUsers', 'failed_publickey': 'failedPublickeys'}.get(event['kind'])
                        if field: row[field] += event['count']
                        row['lastSeen'] = max(row['lastSeen'], event['ts'])
                    for row in sources.values(): row.update(self._metadata(c, row['ip']))
                    source_rows = sorted(sources.values(), key=lambda x: (-x['attempts'], -x['lastSeen'], x['ip']))
                    history = []
                    for index in range(math.ceil(hours * 3600 / interval)):
                        left, right = start + index * interval, min(now, start + (index + 1) * interval)
                        if history_start is None or right < history_start: continue
                        points = [p for p in samples if left <= p['ts'] < right or right == now and p['ts'] == now]
                        observed = [e for e in events if left <= e['ts'] < right or right == now and e['ts'] == now]
                        ssh_known = any(p['events_ok'] for p in points) or bool(observed)
                        bucket_partial = self._truncated_between(components['events'], left, right)
                        observed_counts = {kind: sum(e['count'] for e in observed if e['kind'] == kind) for kind in ('failed_password', 'invalid_user', 'failed_publickey')}
                        deltas = [p for p in points if p['delta_packets'] is not None and p['interval_start'] >= start]
                        history.append({'ts': left, 'until': right, 'failedPasswords': observed_counts['failed_password'] if ssh_known and (not bucket_partial or observed_counts['failed_password']) else None,
                            'invalidUsers': observed_counts['invalid_user'] if ssh_known and (not bucket_partial or observed_counts['invalid_user']) else None,
                            'failedPublickeys': observed_counts['failed_publickey'] if ssh_known and (not bucket_partial or observed_counts['failed_publickey']) else None,
                            'eventsTruncated': bucket_partial,
                            'blockedPackets': sum(p['delta_packets'] for p in deltas) if deltas else None,
                            'observedSamples': len(points), 'unknownCounterIntervals': sum(p['delta_packets'] is None for p in points)})
                    good_deltas = [p for p in samples if p['delta_packets'] is not None and p['interval_start'] >= start]
                    failures = [v['error'] for v in components.values() if v['error']]
                    collector_error = state['last_error'] if state else ''
                    truncated_events = self._truncated_between(components['events'], start, now)
                    if truncated_events: failures.append('Количество событий — нижняя граница: применялось ограничение объёма сбора или хранения')
                    stale = not state or state['last_collected'] is None or now - state['last_collected'] > STALE
                    events_available = components['events']['available']
                    recent_counter = bool(latest and not components['counters']['error'] and not components['counters']['stale'])
                    rows = c.execute('SELECT * FROM ban_history WHERE sid=? AND ts>=? AND ts<=? ORDER BY ts DESC,id DESC LIMIT 501', (sid, start, now)).fetchall()
                    ban_history = [{'ts': v['ts'], 'ip': v['ip'], 'source': v['scope'], 'action': v['action'], **json.loads(v['details'])} for v in rows[:500]]
                    result['servers'].append({**server, 'checkedAt': state['last_attempt'] if state else None,
                        'lastGoodAt': state['last_collected'] if state else None, 'stale': stale,
                        'partial': bool(failures or collector_error), 'error': '; '.join(filter(None, [collector_error] + failures))[:1500] or None,
                        'components': {key: {k: value.get(k) for k in ('checkedAt', 'lastGoodAt', 'error', 'stale', 'available', 'partial')} for key, value in components.items()},
                        'history': history, 'historyStartedAt': history_start, 'historyIntervalSeconds': interval,
                        'ssh': {'failedPasswords': totals['failed_password'] if events_available else None,
                            'invalidUsers': totals['invalid_user'] if events_available else None,
                            'failedPublickeys': totals['failed_publickey'] if events_available else None,
                            'windowSeconds': hours * 3600, 'truncated': truncated_events or bool(components['events']['error']), 'eventsByKind': totals},
                        'firewall': {'blockedPackets': latest['packets'] if latest else None, 'blockedBytes': latest['bytes'] if latest else None,
                            'delta': latest['delta_packets'] if recent_counter else None,
                            'intervalSeconds': latest['ts'] - latest['interval_start'] if latest and latest['interval_start'] is not None else None,
                            'counterReset': bool(latest and latest['reset_reason']), 'resetReason': latest['reset_reason'] if latest else None,
                            'checkedAt': latest['ts'] if latest else None,
                            'windowBlockedPackets': sum(p['delta_packets'] for p in good_deltas) if good_deltas else None,
                            'observedSeconds': sum(p['ts'] - p['interval_start'] for p in good_deltas),
                            'unknownIntervals': sum(p['delta_packets'] is None for p in samples),
                            'boundaryIntervalsExcluded': sum(p['delta_packets'] is not None and p['interval_start'] < start for p in samples)},
                        'sources': source_rows[:500], 'sourcesTotal': len(source_rows), 'sourcesTruncated': len(source_rows) > 500,
                        'bans': current_bans, 'activeBlockedIpCount': len(current_bans),
                        'activeLocalBans': sum(v['source'] in ('local', 'both') for v in current_bans),
                        'activeSharedBans': sum(v['source'] in ('shared', 'both') for v in current_bans),
                        'banHistory': ban_history, 'banHistoryTruncated': len(rows) > 500,
                        'coverage': {'requestedFrom': start, 'observedFrom': history_start, 'to': now,
                                     'counterAttribution': 'interval-end', 'noPrehistory': True,
                                     'eventsLowerBound': truncated_events or bool(components['events']['error']),
                                     'eventsObservedFrom': components['events'].get('observedFrom'),
                                     'eventsCoveredUntil': components['events'].get('coverageUntil'),
                                     'eventsMissingRanges': [pair for pair in components['events'].get('missingRanges', []) if pair[0] < now and pair[1] > start],
                                     'retentionClipped': bool(components['events'].get('retentionClippedFrom') is not None and
                                         components['events']['retentionClippedFrom'] <= now and components['events'].get('retentionClippedUntil', 0) >= start),
                                     'retentionClippedFrom': components['events'].get('retentionClippedFrom'),
                                     'retentionClippedUntil': components['events'].get('retentionClippedUntil')}})
        except (sqlite3.Error, SecurityStatsError, OSError, ValueError, TypeError):
            result['storageError'] = 'Хранилище статистики защиты недоступно'
            result['servers'] = [{**s, 'checkedAt': None, 'stale': True, 'partial': True, 'error': result['storageError'],
                                  'ssh': {'failedPasswords': None, 'invalidUsers': None, 'failedPublickeys': None, 'windowSeconds': hours * 3600},
                                  'firewall': {'blockedPackets': None, 'delta': None, 'counterReset': False},
                                  'sources': [], 'bans': [], 'history': [], 'historyStartedAt': None} for s in registry]
        return result

    def alert_summary(self, servers):
        registry = self._registry(servers); now = self._time(); result = {'generatedAt': now, 'servers': [], 'totals': {'newSharedBans10m': 0}, 'newestEventAt': None}
        try:
            with self._connect(readonly=True) as c:
                ids = [s['id'] for s in registry]
                for server in registry:
                    state = c.execute('SELECT * FROM hosts WHERE sid=?', (server['id'],)).fetchone()
                    components = json.loads(state['components']) if state else self._empty_components()
                    last_good = components['events']['lastGoodAt']
                    count = c.execute("SELECT COALESCE(SUM(count),0) FROM events WHERE sid=? AND kind='failed_password' AND ts>=? AND ts<=?", (server['id'], now - 600, now)).fetchone()[0]
                    bans = c.execute("""SELECT COUNT(*) FROM bans WHERE sid=? AND scope='shared' AND
                        (permanent=1 OR ((expires_at IS NULL OR expires_at>?) AND
                                        (remaining IS NULL OR reported_at+remaining>?)))""", (server['id'], now, now)).fetchone()[0]
                    counter = c.execute('SELECT * FROM samples WHERE sid=? AND packets IS NOT NULL ORDER BY ts DESC LIMIT 1', (server['id'],)).fetchone()
                    counter_good = components['counters']['lastGoodAt']
                    comparable = bool(state and not state['last_error'] and not components['counters']['error'] and
                                      counter_good is not None and now - counter_good <= STALE and counter and
                                      counter['delta_packets'] is not None and counter['interval_start'] is not None and counter['ts'] > counter['interval_start'])
                    packet_rate = counter['delta_packets'] * 60 / (counter['ts'] - counter['interval_start']) if comparable else None
                    result['servers'].append({**server, 'checkedAt': state['last_attempt'] if state else None,
                        'ok': bool(state and not state['last_error'] and not components['events']['error'] and last_good is not None and now - last_good <= STALE),
                        'failedPassword10m': count, 'activeSharedBans': bans, 'blockedPacketsPerMinute': packet_rate,
                        'eventsTruncated10m': self._truncated_between(components['events'], now - 600, now)})
                if ids:
                    markers = ','.join('?' for _ in ids)
                    latest = c.execute("SELECT MAX(ts) FROM events WHERE kind='failed_password' AND sid IN (" + markers + ') AND ts<=?', ids + [now]).fetchone()[0]
                    shared_filter = """EXISTS(SELECT 1 FROM ban_history b WHERE b.ip=s.ip AND b.ts=s.ts
                        AND b.scope='shared' AND b.action='added' AND b.sid IN (""" + markers + '))'
                    shared = c.execute("SELECT MAX(s.ts) FROM shared_history s WHERE s.action='added' AND s.ts<=? AND " + shared_filter, [now] + ids).fetchone()[0]
                    result['newestEventAt'] = max(v for v in (latest, shared) if v is not None) if latest is not None or shared is not None else None
                    result['totals']['newSharedBans10m'] = c.execute("SELECT COUNT(DISTINCT s.ip) FROM shared_history s WHERE s.action='added' AND s.ts>=? AND s.ts<=? AND " + shared_filter, [now - 600, now] + ids).fetchone()[0]
        except (sqlite3.Error, SecurityStatsError, OSError, ValueError, TypeError):
            result['error'] = 'Хранилище статистики защиты недоступно'
            result['servers'] = [{**s, 'checkedAt': None, 'ok': False, 'failedPassword10m': 0, 'activeSharedBans': 0, 'blockedPacketsPerMinute': None, 'eventsTruncated10m': True} for s in registry]
        return result
