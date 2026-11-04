"""Convert fresh cached Ubuntu publications into grouped bot release events.

No network, package commands, historical panel notices or installation actions.
"""
import re
import time
from security_updates import CVE, SOURCE_URL, STALE, CLOCK_SKEW, PACKAGE, KERNEL, finite, valid_version, clean_text


def publication_events(feed, servers, now=None):
    now = time.time() if now is None else now
    if (not finite(now) or not isinstance(feed, dict) or feed.get('cve') != CVE or
            feed.get('sourceUrl') != SOURCE_URL or feed.get('fixedPublished') is not True or
            feed.get('checking') is not False or feed.get('stale') is not False or feed.get('error') or
            not finite(feed.get('lastGoodAt')) or not -CLOCK_SKEW <= now - feed['lastGoodAt'] <= STALE or
            not isinstance(feed.get('servers'), list) or len(feed['servers']) > 256 or
            not isinstance(servers, list) or len(servers) > 256):
        return []
    current = {}
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get('id'), str) or server['id'] in current:
            return []
        current[server['id']] = server
    groups = {}
    seen = set()
    for row in feed['servers']:
        if not isinstance(row, dict) or not isinstance(row.get('id'), str) or row['id'] in seen:
            return []
        seen.add(row['id'])
        server = current.get(row['id'])
        if (server is None or row.get('host') != server.get('host') or row.get('ok') is not True or
                row.get('stale') is not False or row.get('error') or row.get('vendorStatus') != 'released' or
                row.get('state') not in ('published', 'reboot_required') or
                not finite(row.get('checkedAt')) or not -CLOCK_SKEW <= now - row['checkedAt'] <= STALE):
            continue
        source, release, version = row.get('sourcePackage'), row.get('releaseCodename'), row.get('fixedVersion')
        if (not isinstance(source, str) or not PACKAGE.fullmatch(source) or not (source == 'linux' or source.startswith('linux-')) or
                not isinstance(release, str) or not re.fullmatch(r'[a-z][a-z0-9\-]{0,63}', release) or
                not valid_version(version) or not valid_version(row.get('installedVersion')) or
                not isinstance(row.get('kernel'), str) or not KERNEL.fullmatch(row['kernel'])):
            continue
        identity = source, release, version
        group = groups.setdefault(identity, {'cve': CVE, 'sourcePackage': source,
            'releaseCodename': release, 'fixedVersion': version, 'vendorStatus': 'released',
            'checkedAt': feed['lastGoodAt'], 'sourceUrl': SOURCE_URL, 'servers': []})
        group['checkedAt'] = min(group['checkedAt'], row['checkedAt'])
        group['servers'].append({'id': row['id'], 'name': clean_text(server.get('name') or row['id'], 100),
            'host': clean_text(server.get('host'), 253), 'kernel': row['kernel'],
            'installedVersion': row['installedVersion'], 'state': row['state']})
    result = []
    for identity in sorted(groups):
        group = groups[identity]
        group['servers'].sort(key=lambda row: row['id'])
        result.append(group)
    return result
