"""Installer contract tests: no package/network/service actions are performed."""
import argparse
import grp
import os
import subprocess
import types
import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]
HERE = REPOSITORY / 'installer'
sys.path.insert(0, str(HERE))
import render
import deploy_linux
spec = importlib.util.spec_from_file_location('deck_installer', HERE / 'install.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class ConfigTests(unittest.TestCase):
    def args(self, **changes):
        values = dict(mode='ssh', host='8.8.8.8', user='root', port=22, identity='', domain='', email='', public_ip='8.8.8.8', https_port=None)
        values.update(changes)
        return argparse.Namespace(**values)

    def test_ip_mode_has_no_username_password_or_email(self):
        with patch('builtins.input', side_effect=AssertionError('unexpected prompt')):
            cfg = launcher.config(self.args())
        self.assertEqual(cfg['domain'], '')
        self.assertIsNone(cfg['httpsPort'])
        self.assertNotIn('admin', cfg)
        self.assertNotIn('password', cfg)

    def test_domain_mode_uses_certbot_port(self):
        cfg = launcher.config(self.args(domain='deck.example.org', email='owner@example.org'))
        self.assertEqual(cfg['httpsPort'], 443)
        self.assertEqual(cfg['email'], 'owner@example.org')

    def test_bad_host_options_rejected(self):
        with self.assertRaises(ValueError):
            launcher.config(self.args(host='-oProxyCommand=id'))

    def test_private_address_rejected(self):
        with self.assertRaises(ValueError):
            launcher.config(self.args(public_ip='127.0.0.1'))

    def test_bad_https_port_rejected(self):
        with self.assertRaises(ValueError):
            launcher.config(self.args(https_port=80))

    def test_domain_syntax_injection_rejected(self):
        with self.assertRaises(ValueError):
            launcher.config(self.args(domain='x.example.org\n} respond 200'))

    def test_non_linux_local_refused(self):
        with patch.object(launcher.sys, 'platform', 'win32'):
            with self.assertRaises(ValueError):
                launcher.config(self.args(mode='local'))

    def test_nondefault_ssh_known_host_label(self):
        source = (HERE / 'deploy_linux.py').read_text()
        self.assertIn("else '[127.0.0.1]:' + str(ssh_port)", source)
        self.assertIn("'-p', str(ssh_port)", source)

    def test_request_valid_and_no_credentials(self):
        data = dict(domain='', email='', publicIp='8.8.8.8', httpsPort=24443)
        deploy_linux.validate_request(data)
        with self.assertRaises(ValueError):
            deploy_linux.validate_request(dict(data, password='accidental-secret'))

    def test_invalid_request_port_bool_rejected(self):
        with self.assertRaises(ValueError):
            deploy_linux.validate_request(dict(domain='', email='', publicIp='8.8.8.8', httpsPort=True))

    def test_dryrun_does_not_download_or_execute(self):
        with patch.object(launcher, 'get_source', side_effect=AssertionError('download')), patch.object(launcher, 'run', side_effect=AssertionError('execute')), contextlib.redirect_stdout(io.StringIO()) as output:
            status = launcher.main(['--mode', 'ssh', '--host', '8.8.8.8', '--user', 'root', '--port', '22', '--identity', '', '--domain', '', '--email', '', '--public-ip', '8.8.8.8', '--dry-run'])
        self.assertEqual(status, 0)
        self.assertIn('random-free-high-port', output.getvalue())
        self.assertNotIn('tokenHash', output.getvalue())


class RenderTests(unittest.TestCase):
    def domain(self):
        return render.caddy_config('deck.example.org', 'g' * 48, 'a' * 48, render.PUBLIC_PATHS)

    def test_domain_certbot_tls_and_http_challenge(self):
        content = self.domain()
        self.assertIn('/etc/caddy/server-deck-tls/fullchain.pem', content)
        self.assertIn('http://deck.example.org', content)
        self.assertIn('/.well-known/acme-challenge/*', content)
        self.assertIn('ask http://127.0.0.1:8766/tls-ask', content)

    def test_ip_has_no_http_no_embed_no_hsts(self):
        content = render.caddy_config('8.8.8.8', 'g' * 48, 'a' * 48, render.PUBLIC_PATHS, port=24443, ip_mode=True)
        self.assertIn('https://8.8.8.8:24443 {', content)
        self.assertNotIn('http://8.8.8.8', content)
        self.assertNotIn('https:// {', content)
        self.assertNotIn('on_demand', content)
        self.assertIn('auto_https disable_redirects', content)
        self.assertNotIn('Strict-Transport-Security', content)

    def test_setup_route_unauth_gateway(self):
        self.assertIn('@deckAuth path /auth/login /auth/logout /auth/session /auth/setup', self.domain())

    def test_client_identity_headers_are_removed(self):
        self.assertIn('request_header -X-Deck-User', self.domain())
        self.assertIn('header_up -Cookie', self.domain())

    def test_bad_gateway_and_paths_rejected(self):
        with self.assertRaises(ValueError):
            render.caddy_config('deck.example.org', 'bad\n}', 'a' * 48, render.PUBLIC_PATHS)
        with self.assertRaises(ValueError):
            render.caddy_config('deck.example.org', 'g' * 48, 'a' * 48, ['/../servers.json'])

    def test_no_broad_auth_write_access(self):
        self.assertIn('ReadWritePaths=/etc/caddy/server-deck-accounts.d /var/lib/server-deck-auth', render.AUTH_UNIT)
        self.assertNotIn('ReadWritePaths=/etc/caddy\n', render.AUTH_UNIT)
        self.assertIn('NoNewPrivileges=true', render.APP_UNIT)

    def test_renewal_tracks_metadata_not_original_lineage(self):
        source = render.renew_hook('deck.example.org')
        compile(source, 'renew-hook', 'exec')
        self.assertIn("metadata.get('certificateName'", source)
        self.assertIn('fcntl.flock', source)
        self.assertIn('Certificate and private key do not match', source)
        self.assertIn('.renew-restore', source)
        self.assertIn('systemctl', source)
        self.assertNotIn('--cert-name', render.RENEW_SERVICE)

    def test_bootstrap_serves_only_challenge(self):
        content = render.bootstrap_caddy('deck.example.org')
        self.assertIn('respond 404', content)
        self.assertNotIn('reverse_proxy', content)


class RenewalTests(unittest.TestCase):
    def exercise(self, failure=None):
        with tempfile.TemporaryDirectory() as name:
            base = pathlib.Path(name)
            metadata = base / 'metadata.json'
            root = base / 'tls'
            root.mkdir()
            lineage = base / 'live/server-deck'
            lineage.mkdir(parents=True)
            for part in ('fullchain.pem', 'privkey.pem'):
                (root / part).write_bytes(('old-' + part).encode())
                (lineage / part).write_bytes(('new-' + part).encode())
            metadata.write_text(json.dumps(dict(mode='domain', certificateName='server-deck', host='deck.example.org')))
            source = render.renew_hook('deck.example.org').replace('/etc/server-deck/deployment.json', str(metadata)).replace('/etc/caddy/server-deck-tls', str(root)).replace('/etc/letsencrypt/live', str(base / 'live')).replace('/var/lib/server-deck', str(base / 'mutation'))
            failures = []
            def command(argv, **kwargs):
                if '-pubkey' in argv:
                    value = b'certificate-public-key'
                elif '-pubout' in argv:
                    value = b'wrong-key' if failure == 'mismatch' else b'certificate-public-key'
                else:
                    value = b''
                if 'reload' in argv and failure == 'reload' and not failures:
                    failures.append(True)
                    raise subprocess.CalledProcessError(1, argv)
                return types.SimpleNamespace(stdout=value)
            with patch.dict(os.environ, {'RENEWED_LINEAGE': str(lineage)}), patch.object(os, 'chown'), patch.object(grp, 'getgrnam', return_value=types.SimpleNamespace(gr_gid=1)), patch.object(subprocess, 'run', side_effect=command):
                if failure:
                    with self.assertRaises(SystemExit):
                        exec(compile(source, 'renewal-hook', 'exec'), {})
                else:
                    exec(compile(source, 'renewal-hook', 'exec'), {})
            for part in ('fullchain.pem', 'privkey.pem'):
                self.assertEqual((root / part).read_bytes(), (('old-' if failure else 'new-') + part).encode())
            self.assertFalse(list(root.glob('*.renew-*')))

    def test_valid_pair_committed(self):
        self.exercise()

    def test_mismatched_pair_keeps_old_files(self):
        self.exercise('mismatch')

    def test_failed_reload_restores_both_files(self):
        self.exercise('reload')


class PackageTests(unittest.TestCase):
    def fixture(self, root):
        for name in ['backend/server.py', 'backend/web_auth.py', 'backend/account_helper.py', 'backend/deployment_helper.py', 'frontend/static/index.html', 'frontend/pwa/login/index.html', 'installer/deploy_linux.py', 'installer/render.py', 'installer/reset_bootstrap.py', 'installer/reset_account.py']:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('DEFAULTS=[]\n' if name == 'backend/server.py' else '')

    def test_allowlist_never_copies_state_or_keys(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            self.fixture(root)
            for filename in ['servers.json', 'telegram.token', 'health.sqlite3', 'private.pem', 'check_live.py', 'test_live.py']:
                (root / filename).write_text('operator-private')
            paths = {str(p) for p in launcher.source_files(root)}
            self.assertIn('backend/server.py', paths)
            self.assertIn('installer/reset_bootstrap.py', paths)
            self.assertFalse(any(p in paths for p in ('servers.json', 'telegram.token', 'health.sqlite3', 'private.pem', 'check_live.py', 'test_live.py')))

    def test_personal_defaults_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            self.fixture(root)
            (root / 'backend/server.py').write_text("DEFAULTS=[{'host':'operator.example.org'}]\n")
            with self.assertRaises(ValueError):
                launcher.source_files(root)

    def test_symlink_source_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            self.fixture(root)
            (root / 'backend/remote.py').symlink_to(root / 'backend/server.py')
            with self.assertRaises(ValueError):
                launcher.source_files(root)

    def archive(self, filename, kind=tarfile.REGTYPE):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as archive:
            item = tarfile.TarInfo(filename)
            item.type = kind
            item.size = 1 if kind == tarfile.REGTYPE else 0
            item.linkname = '/etc/passwd'
            archive.addfile(item, io.BytesIO(b'x') if item.size else None)
        return out.getvalue()

    def test_traversal_archive_refused(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(ValueError):
                launcher.extract_archive(self.archive('../../outside'), pathlib.Path(name))

    def test_windows_separators_and_drives_refused(self):
        for member in ('repo\\..\\..\\outside', 'C:\\outside', 'repo/C:target'):
            with tempfile.TemporaryDirectory() as name:
                with self.assertRaises(ValueError):
                    launcher.extract_archive(self.archive(member), pathlib.Path(name))

    def test_symlink_archive_refused(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(ValueError):
                launcher.extract_archive(self.archive('repo/link', tarfile.SYMTYPE), pathlib.Path(name))

    def test_source_scripts_compile(self):
        for path in HERE.parent.rglob('*.py'):
            compile(path.read_text(), str(path), 'exec')


if __name__ == '__main__':
    unittest.main()
