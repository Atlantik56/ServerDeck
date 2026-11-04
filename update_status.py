"""Evidence-bound stable version comparisons; no network, SSH or mutations."""
import copy
import re
import time
from urllib.parse import quote

REPOSITORIES = {'lucx':'AlexeyLCP/lucx-ui','mtproxyl':'Liafanx/MTProxyL','mtproxyl-panel':'Liafanx/MTProxyL','telemt':'telemt/telemt'}
LABELS = {'update_available':'Вышло обновление','latest':'Последняя версия репозитория','ahead':'Версия новее релиза репозитория','unknown':'Версия не подтверждена','not_installed':'Не установлен'}
MAX_RELEASE_AGE = 3600

def version_key(component, value):
    """Recognized stable versions only; a Docker tag is not a binary version."""
    if not isinstance(value,str) or not value or len(value)>240:return None
    value=value.strip()
    if component=='lucx':pattern=r'(?:(?:x-ui|lucx)(?:\s+version)?[\s:]+)?v?(\d+)\.(\d+)\.(\d+)-lucx\.(\d+)'
    elif component=='mtproxyl-panel':pattern=r'(?:(?:mtproxyl-panel(?:[\s:]+|\-v))|v)?(\d+)\.(\d+)\.(\d+)'
    elif component in ('mtproxyl','telemt'):pattern=r'(?:(?:'+re.escape(component)+r')(?:\s+version)?[\s:]+)?v?(\d+)\.(\d+)\.(\d+)'
    else:pattern=r'v?(\d+)\.(\d+)\.(\d+)'
    match=re.fullmatch(pattern,value,re.I)
    if not match or any(len(p)>9 for p in match.groups()):return None
    return tuple(int(p) for p in match.groups())

def compare_versions(component,current,target):
    a,b=version_key(component,current),version_key(component,target)
    if a is None or b is None:return 'unknown'
    return 'latest' if a==b else 'update_available' if a<b else 'ahead'

def annotate_servers(rows,upstream,checked_at=None):
    now=time.time() if checked_at is None else checked_at
    result=copy.deepcopy(rows);upstream=upstream if isinstance(upstream,dict) else {}
    stamp=upstream.get('checkedAt')
    fresh=isinstance(stamp,(int,float)) and not isinstance(stamp,bool) and -60<=now-stamp<=MAX_RELEASE_AGE
    for server in result:
        statuses={};versions=server.get('versions') if isinstance(server.get('versions'),dict) else {}
        for component,repo in REPOSITORIES.items():
            current=versions.get(component,'')
            if not current:continue
            release=upstream.get(component)
            release=release if isinstance(release,dict) else {}
            entries=release.get('releases')
            entries=entries if isinstance(entries,list) else []
            candidates=[r for r in entries if isinstance(r,dict) and version_key(component,r.get('version')) is not None]
            latest=max(candidates,key=lambda r:version_key(component,r['version'])) if candidates else None
            status='unknown';message='Не удалось подтвердить последний стабильный релиз репозитория.'
            if not server.get('ok'):message='Установленная версия не проверена: сервер недоступен.'
            elif not fresh:message='Данные релизов устарели. Повторите проверку.'
            elif release.get('ok') is not True:message='Репозиторий не ответил. Актуальность установленной версии неизвестна.'
            elif latest:
                status=compare_versions(component,current,latest['version'])
                message={'latest':'Установленная версия совпадает с последним проверенным стабильным релизом.','update_available':'Опубликована более новая стабильная версия. Установка требует предпросмотра.','ahead':'Установленная версия новее найденного стабильного релиза. Понижение автоматически не предлагается.','unknown':'Формат или источник установленной версии не позволяет надёжно сравнить её с репозиторием.'}[status]
            statuses[component]=dict(state=status,label=LABELS[status],current=str(current),latest=latest['version'] if latest else None,sourceUrl='https://github.com/'+repo+'/releases'+('/tag/'+quote(latest['version'],safe='') if latest else ''),message=message,checkedAt=stamp if fresh else None)
        server['updateStatus']=statuses
    return result

def summarize(rows):
    counts=dict(update_available=0,latest=0,ahead=0,unknown=0)
    for row in rows:
        if not row.get('ok'):counts['unknown']+=1;continue
        for status in (row.get('updateStatus') or {}).values():
            if status.get('state') in counts:counts[status['state']]+=1
    return counts
