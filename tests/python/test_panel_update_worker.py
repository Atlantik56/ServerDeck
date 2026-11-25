import contextlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import panel_release
import panel_update_worker as worker


REQUEST = {'action': 'panel-update', 'version': '1.6.1', 'requestId': '1' * 32}
FILES = {
    'backend/server.py': b'new application',
    'backend/web_auth.py': b'new auth',
    'frontend/static/new.js': b'new static resource',
    'frontend/pwa/login/index.html': b'new login',
}


class Rejected(ValueError):
    pass


class FakeDeployment:
    DeploymentError = Rejected
    ID = re.compile(r'[a-f0-9]{32}')
    SECRET = re.compile(r'[A-Za-z0-9_-]{32,128}')
    CODE = pathlib.Path('/usr/local/lib/server-deck/deployment_helper.py')
    APP_ENV = pathlib.Path('/etc/server-deck/server.env')
    AUTH_ENV = pathlib.Path('/etc/server-deck/auth.env')

    def __init__(self, root):
        self.FREEZE = root / 'app' / 'control-data' / 'deployment-freeze'
        self.FREEZE.parent.mkdir()
        self.FREEZE.write_text(json.dumps({'plan': REQUEST['requestId']}))
        self.MUTATION_LOCK = root / 'mutation' / 'mutation.lock'
        self.commands = []
        self.verifications = []
        self.run_error = None
        self.paths = ['/login/index.html']
        self.reject_new_version = False
        self.reject_all_versions = False

    def atomic(self, path, body, mode=0o600):
        tmp = path.with_name(path.name + '.tmp')
        tmp.write_bytes(body if isinstance(body, bytes) else body.encode())
        tmp.chmod(mode)
        tmp.replace(path)

    def run(self, argv, **kwargs):
        self.commands.append(argv)
        if self.run_error and 'systemd-run' in argv[0]:
            raise self.run_error
        return SimpleNamespace(returncode=0, stdout='not-found')

    def load_configuration(self):
        return {'origin': 'https://203.0.113.4:8443', 'publicPaths': self.paths}

    def read_env(self, path):
        return {'DECK_GATEWAY_TOKEN': 'a' * 48, 'DECK_AUTH_GATEWAY': 'b' * 48}

    def verify_services(self, host, gateway, auth_gateway):
        current = (worker.APP / 'server.py').read_bytes()
        self.verifications.append((host, current))
        if self.reject_all_versions or (self.reject_new_version and current == FILES['backend/server.py']):
            raise Rejected('service unavailable')


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = pathlib.Path(self.directory.name)
        uid, gid = os.geteuid(), os.getegid()
        installed = root / 'release' / 'installed.json'
        for path in (root / 'app', root / 'web', root / 'helpers', installed.parent):
            path.mkdir(mode=0o700)
        self.deployment = FakeDeployment(root)
        self.release = SimpleNamespace(
            version_key=panel_release.version_key,
            fetch_latest=lambda: {'version': REQUEST['version']},
            download_bundle=lambda version: b'package',
            unpack_bundle=lambda archive, version: (
                {'version': version, 'revision': '2' * 40}, dict(FILES)),
        )
        patches = contextlib.ExitStack()
        self.addCleanup(patches.close)
        for setting, value in {
            'STATE': installed.parent, 'APP': root / 'app',
            'WEB': root / 'web', 'HELPERS': root / 'helpers',
            'ROOT_UID': uid, 'ROOT_GID': gid,
        }.items():
            patches.enter_context(patch.object(worker, setting, value))
        patches.enter_context(patch.object(worker, '_release_code', return_value=self.release))
        patches.enter_context(patch.object(worker.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=uid, pw_gid=gid)))
        patches.enter_context(patch.object(worker.time, 'sleep'))
        installed.write_text(json.dumps({'version': '1.6.0', 'revision': '1' * 40}))
        (worker.APP / 'server.py').write_bytes(b'old application')
        (worker.APP / 'servers.json').write_bytes(b'private inventory')
        (worker.WEB / 'login').mkdir()
        (worker.WEB / 'login' / 'index.html').write_bytes(b'old login')
        (worker.HELPERS / 'web_auth.py').write_bytes(b'old auth')
        (worker.HELPERS / 'unrelated.py').write_bytes(b'untouched')
        self.root = root

    def receipt(self):
        return json.loads((worker.STATE / 'job.json').read_text())

    def installed(self):
        return json.loads((worker.STATE / 'installed.json').read_text())

    def queue(self):
        return worker.submit(REQUEST, self.deployment)

    def update(self):
        self.queue()
        worker.run_worker(REQUEST['requestId'], self.deployment)

    def service_changes(self):
        return [command[1:] for command in self.deployment.commands if command[0].endswith('systemctl')]

    def test_accepts_only_new_confirmed_version_and_one_fixed_worker(self):
        for request in (
            {**REQUEST, 'url': 'https://example.test/file'},
            {**REQUEST, 'version': '1.6.0'},
            {**REQUEST, 'requestId': '../invalid'},
        ):
            with self.assertRaises(Rejected):
                worker.submit(request, self.deployment)
        self.assertTrue(self.queue()['accepted'])
        self.assertEqual(self.receipt()['stage'], 'queued')
        unit = self.deployment.commands[0]
        self.assertIn('--no-block', unit)
        self.assertEqual(unit[-2:], ['--panel-worker', REQUEST['requestId']])
        with self.assertRaises(Rejected):
            self.queue()
        self.assertEqual(len(self.deployment.commands), 1)

    def test_uncertain_submission_preserves_freeze(self):
        self.deployment.run_error = subprocess.TimeoutExpired('systemd-run', 15)
        self.assertTrue(self.queue()['accepted'])
        self.assertEqual(self.receipt()['stage'], 'submit_uncertain')
        self.assertTrue(self.deployment.FREEZE.is_file())

    def test_symlink_in_shared_job_directory_cannot_supply_control_metadata(self):
        outside = self.root / 'outside'
        outside.write_text('{}')
        (self.deployment.FREEZE.parent / 'jobs.json').symlink_to(outside)
        with self.assertRaisesRegex(Rejected, 'проверить выполняющиеся задачи'):
            self.queue()
        self.assertEqual(self.deployment.commands, [])
        self.assertEqual(outside.read_text(), '{}')

    def test_proved_missing_systemd_job_releases_its_freeze(self):
        self.deployment.run_error = Rejected('systemd-run rejected')
        with self.assertRaises(Rejected):
            self.queue()
        self.assertEqual(self.receipt()['state'], 'failed')
        self.assertFalse(self.deployment.FREEZE.exists())

    def test_update_keeps_private_state_and_verifies_services(self):
        self.update()
        self.assertEqual(self.receipt()['state'], 'succeeded')
        self.assertEqual(self.installed(), {'version': '1.6.1', 'revision': '2' * 40})
        self.assertEqual((worker.APP / 'server.py').read_bytes(), FILES['backend/server.py'])
        self.assertEqual((worker.APP / 'servers.json').read_bytes(), b'private inventory')
        self.assertEqual((worker.HELPERS / 'unrelated.py').read_bytes(), b'untouched')
        self.assertEqual((worker.HELPERS / 'web_auth.py').read_bytes(), FILES['backend/web_auth.py'])
        self.assertEqual((worker.WEB / 'login' / 'index.html').read_bytes(), FILES['frontend/pwa/login/index.html'])
        self.assertEqual(self.service_changes(), [
            ['stop', worker.AUTH_SERVICE, worker.BACKEND_SERVICE],
            ['start', worker.AUTH_SERVICE, worker.BACKEND_SERVICE],
        ])
        self.assertEqual(self.deployment.verifications, [('203.0.113.4:8443', FILES['backend/server.py'])])
        archive = worker.STATE / 'backups' / REQUEST['requestId'] / 'before.json'
        self.assertNotIn('servers.json', archive.read_text())
        self.assertFalse(self.deployment.FREEZE.exists())

    def test_auth_stays_running_when_unchanged(self):
        (worker.HELPERS / 'web_auth.py').write_bytes(FILES['backend/web_auth.py'])
        self.update()
        self.assertEqual(self.receipt()['state'], 'succeeded')
        self.assertEqual(self.service_changes(), [['stop', worker.BACKEND_SERVICE], ['start', worker.BACKEND_SERVICE]])

    def test_failed_health_check_rolls_back_executable_and_assets(self):
        self.deployment.reject_new_version = True
        self.update()
        self.assertEqual(self.receipt()['state'], 'failed')
        self.assertEqual(self.installed()['version'], '1.6.0')
        self.assertEqual((worker.APP / 'server.py').read_bytes(), b'old application')
        self.assertEqual((worker.HELPERS / 'web_auth.py').read_bytes(), b'old auth')
        self.assertEqual((worker.WEB / 'login' / 'index.html').read_bytes(), b'old login')
        self.assertFalse((worker.APP / 'static' / 'new.js').exists())
        self.assertFalse(self.deployment.FREEZE.exists())

    def test_failed_rollback_verification_requires_review(self):
        self.deployment.reject_all_versions = True
        self.update()
        self.assertEqual(self.receipt()['state'], 'needs_review')
        self.assertTrue(self.deployment.FREEZE.is_file())

    def test_symlink_is_rejected_without_touching_destination(self):
        source = worker.APP / 'server.py'
        source.unlink()
        outside = self.root / 'outside'
        outside.write_bytes(b'private')
        source.symlink_to(outside)
        self.update()
        self.assertEqual(self.receipt()['state'], 'failed')
        self.assertEqual(outside.read_bytes(), b'private')
        self.assertEqual(self.service_changes(), [])

    def test_pwa_route_change_is_rejected_before_stop(self):
        self.deployment.paths = []
        self.update()
        self.assertEqual(self.receipt()['state'], 'failed')
        self.assertEqual(self.installed()['version'], '1.6.0')
        self.assertEqual(self.service_changes(), [])


if __name__ == '__main__':
    unittest.main()
