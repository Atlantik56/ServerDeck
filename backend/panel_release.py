"""Published Server Deck runtime releases and their fixed archive format."""
import ast
import gzip
import hashlib
import hmac
import http.client
import io
import json
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zlib


REPOSITORY = 'Atlantik56/ServerDeck'
RELEASE_API = f'https://api.github.com/repos/{REPOSITORY}/releases/latest'
RELEASE_WEB = f'https://github.com/{REPOSITORY}/releases'
ASSET_NAME = 'server-deck-runtime.tar.gz'
MAX_DOWNLOAD = 16 * 1024 * 1024
MAX_EXPANDED = 48 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_FILES = 512
MAX_MANIFEST = 128 * 1024
MAX_METADATA = 1024 * 1024
CDN_HOSTS = {'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
VERSION = re.compile(r'(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}')
REVISION = re.compile(r'[a-f0-9]{40}')
SHA256 = re.compile(r'[a-f0-9]{64}')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
FRONTEND_EXTENSIONS = {'.js', '.css', '.html', '.webmanifest', '.png', '.svg'}
REQUIRED_FILES = {
    'backend/server.py', 'backend/web_auth.py', 'backend/deployment_helper.py',
    'backend/panel_release.py', 'backend/panel_update_worker.py',
    'frontend/static/index.html', 'frontend/pwa/login/index.html',
}


class ReleaseError(ValueError):
    """A remote release or a local package does not meet the runtime format."""


def version_key(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ReleaseError('Неверный номер версии Server Deck.')
    return tuple(map(int, value.split('.')))


def selected_path(path):
    """Recognize only the source namespaces deployed as application code/assets."""
    if not isinstance(path, str) or len(path) > 256:
        return False
    parts = path.split('/')
    if not all(NAME.fullmatch(part) for part in parts):
        return False
    _, separator, extension = parts[-1].rpartition('.')
    if not separator:
        return False
    if len(parts) == 2 and parts[0] == 'backend':
        return extension == 'py' and not parts[-1].startswith(('test_', 'check_', 'prepare_'))
    return (len(parts) >= 3 and parts[0] == 'frontend'
            and parts[1] in ('static', 'pwa') and '.' + extension in FRONTEND_EXTENSIONS)


def _canonical_asset(version):
    version_key(version)
    return f'{RELEASE_WEB}/download/v{version}/{ASSET_NAME}'


def _allowed_cdn(url):
    try:
        target = urllib.parse.urlsplit(url)
        return (target.scheme == 'https' and target.netloc in CDN_HOSTS
                and bool(target.path.lstrip('/')) and not target.fragment)
    except ValueError:
        return False


class _ReleaseRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, asset):
        self.asset = asset

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.asset or not _allowed_cdn(newurl):
            raise ReleaseError('GitHub вернул неожиданный адрес загрузки.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _request(url, limit, *, asset=False):
    opener = urllib.request.build_opener(_ReleaseRedirects(asset))
    request = urllib.request.Request(url, headers={
        'User-Agent': 'ServerDeck-Panel-Updater/1',
        'Accept': 'application/octet-stream' if asset else 'application/vnd.github+json',
    })
    try:
        with opener.open(request, timeout=15) as response:
            target = response.geturl()
            if target != url and not (asset and _allowed_cdn(target)):
                raise ReleaseError('GitHub вернул неожиданный адрес загрузки.')
            data = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        if not asset and error.code == 404:
            return None
        raise ReleaseError(f'GitHub ответил HTTP {error.code}.') from None
    except ReleaseError:
        raise
    except (OSError, http.client.HTTPException, ValueError):
        raise ReleaseError('Не удалось получить данные релиза GitHub.') from None
    if len(data) > limit:
        raise ReleaseError('Ответ GitHub превышает допустимый размер.')
    return data


def _parse_release(value):
    if not isinstance(value, dict) or value.get('draft') is not False or value.get('prerelease') is not False:
        raise ReleaseError('GitHub не подтвердил стабильный релиз Server Deck.')
    tag = value.get('tag_name')
    if not isinstance(tag, str) or not tag.startswith('v'):
        raise ReleaseError('GitHub вернул неподдерживаемый тег релиза.')
    version = tag[1:]
    download_url = _canonical_asset(version)
    assets = value.get('assets')
    if not isinstance(assets, list):
        raise ReleaseError('GitHub не вернул список файлов релиза.')
    packages = [candidate for candidate in assets if isinstance(candidate, dict) and candidate.get('name') == ASSET_NAME]
    if len(packages) != 1:
        raise ReleaseError('В релизе GitHub отсутствует однозначный пакет Server Deck.')
    package, = packages
    digest = package.get('digest')
    size = package.get('size')
    url = f'{RELEASE_WEB}/tag/{tag}'
    if (value.get('html_url') != url or package.get('browser_download_url') != download_url
            or not isinstance(digest, str) or not digest.startswith('sha256:')
            or not SHA256.fullmatch(digest[7:]) or type(size) is not int or not 0 < size <= MAX_DOWNLOAD):
        raise ReleaseError('Метаданные пакета GitHub не прошли проверку.')
    title = value.get('name')
    summary = ' '.join(title.split())[:180] if isinstance(title, str) else ''
    return dict(version=version, url=url, assetUrl=download_url, sha256=digest[7:], size=size, summary=summary)


def fetch_latest():
    data = _request(RELEASE_API, MAX_METADATA)
    if data is None:
        return None
    try:
        value = json.loads(data)
    except (UnicodeError, ValueError):
        raise ReleaseError('Ответ GitHub о версиях не читается.') from None
    return _parse_release(value)


def download_bundle(release):
    if not isinstance(release, dict):
        raise ReleaseError('Неподтверждённый пакет обновления Server Deck.')
    url = _canonical_asset(release.get('version'))
    digest = release.get('sha256')
    size = release.get('size')
    if (release.get('assetUrl') != url or not isinstance(digest, str) or not SHA256.fullmatch(digest)
            or type(size) is not int or not 0 < size <= MAX_DOWNLOAD):
        raise ReleaseError('Неподтверждённый пакет обновления Server Deck.')
    data = _request(url, size, asset=True)
    if len(data) != size or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), digest):
        raise ReleaseError('Размер или SHA-256 пакета не совпадает с данными GitHub.')
    return data


def _digest_files(files):
    if not REQUIRED_FILES.issubset(files) or len(files) > MAX_FILES:
        raise ReleaseError('Пакет Server Deck неполный.')
    digests = {}
    total = 0
    for path, contents in files.items():
        if not selected_path(path) or not isinstance(contents, bytes) or len(contents) > MAX_FILE:
            raise ReleaseError('Пакет содержит неподдерживаемый файл.')
        total += len(contents)
        if total > MAX_EXPANDED:
            raise ReleaseError('Пакет Server Deck слишком большой.')
        digests[path] = hashlib.sha256(contents).hexdigest()
        if path.startswith('backend/'):
            try:
                tree = ast.parse(contents, path, feature_version=(3, 11))
                compile(tree, path, 'exec', dont_inherit=True)
            except (SyntaxError, ValueError):
                raise ReleaseError('В пакете Server Deck обнаружен неверный код Python.') from None
            if path == 'backend/server.py':
                defaults = [node.value for node in tree.body if isinstance(node, ast.Assign)
                            and any(isinstance(target, ast.Name) and target.id == 'DEFAULTS' for target in node.targets)]
                if len(defaults) != 1 or not isinstance(defaults[0], (ast.List, ast.Tuple)) or defaults[0].elts:
                    raise ReleaseError('Публичный пакет должен содержать пустой реестр по умолчанию.')
    return digests


def _unique_object(items):
    result = dict(items)
    if len(result) != len(items):
        raise ReleaseError('Манифест содержит повторяющиеся записи.')
    return result


def unpack_bundle(data, version):
    version_key(version)
    if not isinstance(data, bytes) or len(data) > MAX_DOWNLOAD:
        raise ReleaseError('Недопустимый размер пакета Server Deck.')
    archive_limit = MAX_EXPANDED + (MAX_FILES + 1) * 1024 + MAX_MANIFEST + 10240
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            archive_bytes = compressed.read(archive_limit + 1)
        if len(archive_bytes) > archive_limit:
            raise ReleaseError('Распакованный пакет превышает допустимый размер.')
        entries = {}
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:') as archive:
            for member in archive:
                is_manifest = member.name == 'manifest.json'
                if (member.type != tarfile.REGTYPE or member.name in entries or len(entries) >= MAX_FILES + 1
                        or not (is_manifest or selected_path(member.name))
                        or not 0 <= member.size <= (MAX_MANIFEST if is_manifest else MAX_FILE)):
                    raise ReleaseError('Пакет содержит недопустимый путь, размер или тип файла.')
                with archive.extractfile(member) as payload:
                    entries[member.name] = payload.read()
    except (OSError, EOFError, tarfile.TarError, zlib.error):
        raise ReleaseError('Архив Server Deck повреждён.') from None
    try:
        manifest = json.loads(entries.pop('manifest.json'), object_pairs_hook=_unique_object)
    except (KeyError, UnicodeError, json.JSONDecodeError):
        raise ReleaseError('Манифест пакета Server Deck не читается.') from None
    if (not isinstance(manifest, dict) or set(manifest) != {'format', 'version', 'revision', 'files'}
            or type(manifest['format']) is not int or manifest['format'] != 1 or manifest['version'] != version
            or not isinstance(manifest['revision'], str) or not REVISION.fullmatch(manifest['revision'])
            or manifest['files'] != _digest_files(entries)):
        raise ReleaseError('Манифест или контрольные суммы файлов пакета не совпадают.')
    return manifest, entries


def pack_bundle(version, revision, files):
    version_key(version)
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ReleaseError('Требуется полный идентификатор коммита Git.')
    manifest = dict(format=1, version=version, revision=revision, files=_digest_files(files))
    serialized = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if len(serialized) > MAX_MANIFEST:
        raise ReleaseError('Манифест пакета Server Deck слишком большой.')
    output = io.BytesIO()
    with gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for path, contents in [('manifest.json', serialized), *sorted(files.items())]:
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(contents))
    result = output.getvalue()
    if len(result) > MAX_DOWNLOAD:
        raise ReleaseError('Сжатый пакет Server Deck слишком большой.')
    return result
