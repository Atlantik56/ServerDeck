"""Persistent project catalogue. Importing Git metadata never executes repository code."""
import concurrent.futures
import copy
import hashlib
import json
import os
import pathlib
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from update_status import compare_versions, version_key, LABELS

MAX_BYTES = 1024 * 1024
MAX_COMPONENTS = 100
KNOWN_RECIPES = {'github.com/alexeylcp/lucx-ui': 'lucx', 'github.com/liafanx/mtproxyl': 'mtproxyl', 'github.com/telemt/telemt': 'telemt'}


def canonical_project(value):
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError('Укажите HTTPS-ссылку на проект GitHub или GitLab')
    value = value.strip()
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
            raise ValueError()
        host = (parsed.hostname or '').lower()
        parts = parsed.path.strip('/').split('/')
        if parts[-1].endswith('.git'):
            parts[-1] = parts[-1][:-4]
        if host not in ('github.com', 'gitlab.com') or len(parts) < 2 or (host == 'github.com' and len(parts) != 2):
            raise ValueError()
        if any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', x) or x in ('.', '..') for x in parts):
            raise ValueError()
        project = '/'.join(parts)
        if host == 'github.com':
            project = project.lower()
        return {'provider': 'github' if host == 'github.com' else 'gitlab', 'project': project, 'url': 'https://' + host + '/' + project}
    except (ValueError, TypeError):
        raise ValueError('Нужна ссылка на корень публичного проекта: https://github.com/owner/repo или https://gitlab.com/group/repo')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Перенаправление API не поддерживается; используйте актуальный адрес проекта')


def api_json(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in ('api.github.com', 'gitlab.com') or parsed.username or parsed.password:
        raise ValueError('Неподдерживаемый адрес API')
    request = urllib.request.Request(url, headers={'User-Agent': 'ServerDeck', 'Accept': 'application/json'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Ответ проекта превышает лимит')
    return json.loads(data)


def text(value, limit=300):
    return ''.join(c for c in str(value or '') if ord(c) >= 32)[:limit]


def safe_tag(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+/-]{0,127}', value)) and '..' not in value


def metadata(project, fetch=api_json):
    provider, name = project['provider'], project['project']
    if provider == 'github':
        base = 'https://api.github.com/repos/' + name
        info = fetch(base)
        if not isinstance(info, dict) or info.get('private') or str(info.get('full_name', '')).lower() != name.lower():
            raise ValueError('Публичный проект не подтверждён API GitHub')
        source = 'https://github.com/' + name
        rows = fetch(base + '/releases?per_page=30')
        if not isinstance(rows, list):
            raise ValueError('Неизвестный формат релизов проекта')
        releases = [dict(version=x['tag_name'], published=text(x.get('published_at'), 60), url=source + '/releases/tag/' + urllib.parse.quote(x['tag_name'], safe='')) for x in rows if isinstance(x, dict) and safe_tag(x.get('tag_name')) and not x.get('draft') and not x.get('prerelease')][:12]
    else:
        base = 'https://gitlab.com/api/v4/projects/' + urllib.parse.quote(name, safe='')
        info = fetch(base)
        if not isinstance(info, dict) or info.get('visibility') != 'public' or info.get('path_with_namespace') != name:
            raise ValueError('Публичный проект не подтверждён API GitLab')
        source = project['url']
        rows = fetch(base + '/releases?per_page=30')
        if not isinstance(rows, list):
            raise ValueError('Неизвестный формат релизов проекта')
        releases = [dict(version=x['tag_name'], published=text(x.get('released_at'), 60), url=source + '/-/releases/' + urllib.parse.quote(x['tag_name'], safe='')) for x in rows if isinstance(x, dict) and safe_tag(x.get('tag_name')) and not x.get('upcoming_release')][:12]
    return dict(name=text(info.get('name'), 100) or name, description=text(info.get('description'), 600), sourceUrl=source, releases=releases, checkedAt=time.time(), ok=True, stale=False, error='', archived=bool(info.get('archived')))


class ProjectCatalog:
    def __init__(self, root, fetch=None):
        self.path = pathlib.Path(root) / 'components.json'
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.refresh_lock = threading.Lock()
        self.fetch = fetch or api_json
        self.entries = {}
        if self.path.exists():
            data = json.loads(self.path.read_text())
            if not isinstance(data, dict) or data.get('format') != 1 or not isinstance(data.get('components'), dict):
                raise ValueError('Повреждён каталог проектов')
            self.entries = data['components']

    def save(self):
        temp = self.path.with_suffix('.tmp')
        fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(dict(format=1, components=self.entries), stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temp), str(self.path))

    def snapshot(self):
        with self.lock:
            rows=copy.deepcopy(sorted(self.entries.values(), key=lambda x: x['createdAt']))
            for row in rows:row['checking']=self.refresh_lock.locked()
            return rows

    def add(self, url):
        project = canonical_project(url)
        cid = 'git-' + hashlib.sha256(project['url'].encode()).hexdigest()[:16]
        with self.lock:
            if cid in self.entries:
                return copy.deepcopy(self.entries[cid])
            if len(self.entries) >= MAX_COMPONENTS:
                raise ValueError('В каталоге может быть не больше 100 пользовательских проектов')
        try:
            info = metadata(project, self.fetch)
        except (OSError, ValueError, KeyError, TypeError):
            raise ValueError('Не удалось проверить публичный проект и его релизы. Проверьте адрес и повторите позже; токены доступа не требуются.')
        row = dict(project, **info, id=cid, custom=True, icon='GIT', category='Проекты Git', recipeId=KNOWN_RECIPES.get(project['url'][8:].lower()), createdAt=time.time(), bindings={})
        with self.lock:
            if cid not in self.entries:
                self.entries[cid] = row
                self.save()
            return copy.deepcopy(self.entries[cid])

    def remove(self, cid):
        with self.lock:
            if cid not in self.entries:
                raise ValueError('Проект не найден в пользовательском каталоге')
            del self.entries[cid]
            self.save()
        return {'ok': True, 'message': 'Запись каталога удалена. Файлы и службы на серверах не изменялись.'}

    def bind(self, cid, sid, version):
        if not isinstance(version, str) or (version and not safe_tag(version)):
            raise ValueError('Укажите версию или тег проекта, до 128 символов')
        with self.lock:
            row = self.entries.get(cid)
            if not row:
                raise ValueError('Проект не найден')
            if version:
                row['bindings'][sid] = dict(version=version, checkedAt=time.time(), source='manual')
            else:
                row['bindings'].pop(sid, None)
            self.save()
            return copy.deepcopy(row)

    def updates(self, force=False, background=False):
        rows=self.request_refresh(force) if background else self.refresh(force)
        for row in rows:
            stable=[x for x in row.get('releases',[]) if version_key('custom',x.get('version')) is not None]
            latest=max(stable,key=lambda x:version_key('custom',x['version'])) if stable else next(iter(row.get('releases',[])),None)
            for binding in row.get('bindings',{}).values():
                state='unknown'
                if row.get('ok') is True and not row.get('stale') and -60<=time.time()-row.get('checkedAt',0)<=3600 and latest:
                    state=compare_versions('custom',binding['version'],latest['version'])
                binding['updateStatus']=dict(state=state,label=LABELS[state],current=binding['version'],latest=latest['version'] if latest else None,sourceUrl=latest['url'] if latest else row['sourceUrl'],checkedAt=row.get('checkedAt'),manual=True,message='Установленная версия указана вручную и не подтверждена автоматической проверкой сервера.' + (' Актуальность репозитория не подтверждена.' if state=='unknown' else ' Сравнение со стабильным релизом проекта.'))
        return rows

    def request_refresh(self, force=False):
        if not any(force or time.time()-row.get('checkedAt',0)>=1800 for row in self.snapshot()):
            return self.snapshot()
        if self.refresh_lock.acquire(False):
            def worker():
                try:self._refresh(force)
                finally:self.refresh_lock.release()
            threading.Thread(target=worker,name='project-catalog-refresh',daemon=True).start()
        return self.snapshot()

    def refresh(self, force=False):
        if not self.refresh_lock.acquire(False):
            return self.snapshot()
        try:
            return self._refresh(force)
        finally:
            self.refresh_lock.release()

    def _refresh(self, force=False):
        eligible=[row for row in self.snapshot() if force or time.time()-row.get('checkedAt',0)>=1800]
        def one(old):
            try:
                result=metadata(old,self.fetch)
            except (OSError,ValueError,KeyError,TypeError):
                result=dict(ok=False,stale=True,checkedAt=time.time(),error='Проверка репозитория не удалась. Сохранённые релизы могут устареть.')
            with self.lock:
                if old['id'] in self.entries:
                    self.entries[old['id']].update(result)
                    self.save()
        # Four workers, off the HTTP request thread; no remote host work.
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(one,eligible))
        return self.snapshot()
