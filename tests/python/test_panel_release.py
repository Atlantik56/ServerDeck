import copy
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import panel_release as release


REVISION = 'a' * 40
VERSION = '1.6.0'
ROOT = pathlib.Path(__file__).resolve().parents[2]


def runtime():
    return {
        path: b'DEFAULTS = []\n' if path == 'backend/server.py' else b'# Fixture\n' if path.endswith('.py') else b'<main>Fixture</main>'
        for path in release.REQUIRED_FILES
    }


def tar_payload(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, data, member_type in entries:
            info = tarfile.TarInfo(name)
            info.type = member_type
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


class GithubReleaseTests(unittest.TestCase):
    def metadata(self):
        return {
            'draft': False,
            'prerelease': False,
            'tag_name': 'v1.6.0',
            'html_url': release.RELEASE_WEB + '/tag/v1.6.0',
            'name': 'Server Deck 1.6.0\n',
            'assets': [{
                'name': release.ASSET_NAME,
                'browser_download_url': release.RELEASE_WEB + '/download/v1.6.0/' + release.ASSET_NAME,
                'digest': 'sha256:' + hashlib.sha256(b'fixture').hexdigest(),
                'size': len(b'fixture'),
            }],
        }

    def test_check_and_download_only_bound_asset(self):
        with patch.object(release, '_request', side_effect=[json.dumps(self.metadata()).encode(), b'fixture']) as request:
            latest = release.fetch_latest()
            self.assertEqual(latest['version'], VERSION)
            self.assertEqual(latest['summary'], 'Server Deck 1.6.0')
            self.assertEqual(release.download_bundle(latest), b'fixture')
        request.assert_any_call(release.RELEASE_API, release.MAX_METADATA)
        request.assert_any_call(latest['assetUrl'], latest['size'], asset=True)

    def test_rejects_draft_duplicate_unpinned_and_offsite_assets(self):
        fixtures = []
        draft = self.metadata()
        draft['draft'] = True
        fixtures.append(draft)
        duplicate = self.metadata()
        duplicate['assets'].append(copy.deepcopy(duplicate['assets'][0]))
        fixtures.append(duplicate)
        for key, value in [('digest', None), ('browser_download_url', 'https://example.test/bundle'), ('size', True)]:
            fixture = self.metadata()
            fixture['assets'][0][key] = value
            fixtures.append(fixture)
        for fixture in fixtures:
            with self.subTest(fixture=fixture), patch.object(release, '_request', return_value=json.dumps(fixture).encode()):
                with self.assertRaises(release.ReleaseError):
                    release.fetch_latest()

    def test_no_published_release_returns_none(self):
        missing = urllib.error.HTTPError(release.RELEASE_API, 404, 'Not found', {}, None)
        with patch('urllib.request.OpenerDirector.open', side_effect=missing):
            self.assertIsNone(release.fetch_latest())

    def test_digest_failure_blocks_download(self):
        latest = release._parse_release(self.metadata())
        with patch.object(release, '_request', return_value=b'bogus!!'):
            with self.assertRaisesRegex(release.ReleaseError, 'SHA-256'):
                release.download_bundle(latest)

    def test_redirect_stays_on_exact_https_cdn(self):
        asset = release._parse_release(self.metadata())['assetUrl']
        request = urllib.request.Request(asset)
        allowed = 'https://release-assets.githubusercontent.com/download/file?signature=synthetic'
        redirect = release._ReleaseRedirects(True)
        self.assertEqual(redirect.redirect_request(request, None, 302, '', {}, allowed).full_url, allowed)
        for url in ('http://release-assets.githubusercontent.com/file',
                    'https://release-assets.githubusercontent.com.example.test/file',
                    'https://objects.githubusercontent.com:8443/file',
                    'https://user@objects.githubusercontent.com/file'):
            with self.subTest(url=url), self.assertRaises(release.ReleaseError):
                redirect.redirect_request(request, None, 302, '', {}, url)
        with self.assertRaises(release.ReleaseError):
            release._ReleaseRedirects(False).redirect_request(request, None, 302, '', {}, allowed)


class RuntimeBundleTests(unittest.TestCase):
    def test_package_is_reproducible_and_bound_to_version(self):
        files = runtime()
        data = release.pack_bundle(VERSION, REVISION, files)
        self.assertEqual(data, release.pack_bundle(VERSION, REVISION, dict(reversed(list(files.items())))))
        manifest, unpacked = release.unpack_bundle(data, VERSION)
        self.assertEqual(unpacked, files)
        self.assertEqual(manifest['revision'], REVISION)
        self.assertEqual(manifest['files']['backend/server.py'], hashlib.sha256(files['backend/server.py']).hexdigest())
        with self.assertRaises(release.ReleaseError):
            release.unpack_bundle(data, '1.6.1')

    def test_refuses_credentials_paths_and_nonempty_default_registry(self):
        for path in ('backend/servers.json', 'backend/py', 'backend/test_private.py',
                     'backend/../server.py', '/frontend/static/main.js', 'frontend/pwa/.hidden.js',
                     'frontend/static/config.pem', 'frontend/static/access.token'):
            with self.subTest(path=path), self.assertRaises(release.ReleaseError):
                release.pack_bundle(VERSION, REVISION, {**runtime(), path: b'fixture'})
        with self.assertRaisesRegex(release.ReleaseError, 'реестр'):
            release.pack_bundle(VERSION, REVISION, {**runtime(), 'backend/server.py': b'DEFAULTS = [123]\n'})

    def test_unpack_rejects_links_duplicates_and_modified_members(self):
        files = runtime()
        archive = release.pack_bundle(VERSION, REVISION, files)
        manifest, _ = release.unpack_bundle(archive, VERSION)
        entries = [('manifest.json', json.dumps(manifest).encode(), tarfile.REGTYPE)]
        entries += [(path, data, tarfile.REGTYPE) for path, data in files.items()]
        for extra in [('backend/server.py', b'fixture', tarfile.REGTYPE),
                      ('backend/more.py', b'', tarfile.SYMTYPE),
                      ('../outside.py', b'fixture', tarfile.REGTYPE)]:
            with self.subTest(extra=extra), self.assertRaises(release.ReleaseError):
                release.unpack_bundle(tar_payload([*entries, extra]), VERSION)
        modified = [(path, b'<main>Modified</main>' if path == 'frontend/static/index.html' else body, mode)
                    for path, body, mode in entries]
        with self.assertRaisesRegex(release.ReleaseError, 'контрольные суммы'):
            release.unpack_bundle(tar_payload(modified), VERSION)

    def test_builder_uses_committed_public_runtime_only(self):
        spec = importlib.util.spec_from_file_location('package_release_fixture', ROOT / 'scripts/package_release.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        fixture = {**runtime(), 'VERSION': b'1.6.0\n', 'backend/servers.json': b'private fixture',
                   'frontend/static/backup.key': b'private fixture'}
        with tempfile.TemporaryDirectory() as directory:
            repo = pathlib.Path(directory)
            builder.git(repo, 'init', '-q')
            for name, content in fixture.items():
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            builder.git(repo, 'add', '.')
            builder.git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test',
                        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Fixture')
            (repo / 'VERSION').write_text('9.9.9\n')
            (repo / 'backend/server.py').write_text('DEFAULTS = [123]\n')
            (repo / 'backend/untracked.py').write_text('PRIVATE = None\n')
            version, revision, files = builder.committed_runtime(repo, 'HEAD')
        self.assertEqual(version, VERSION)
        self.assertRegex(revision, '[a-f0-9]{40}')
        self.assertEqual(files, runtime())
