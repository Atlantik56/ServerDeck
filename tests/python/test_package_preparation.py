"""Package preparation order and stop conditions; never executes APT or services."""
import contextlib
import io
import os
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

INSTALLER = pathlib.Path(__file__).resolve().parents[2] / 'installer'
sys.path.insert(0, str(INSTALLER))
import deploy_linux


class PackagePreparation(unittest.TestCase):
    def exercise(self, missing=(), fail=None, command_missing=None, remain=False):
        events = []
        queries = []

        def run(argv, **kwargs):
            events.append((list(argv), kwargs))
            operation = next((value for value in ('update', 'upgrade', 'install') if value in argv), None)
            if fail is not None and operation == fail:
                raise RuntimeError('fixture ' + operation + ' failure')
            return subprocess.CompletedProcess(argv, 0, '', '')

        def packages(values):
            events.append(('missing-query', list(values)))
            queries.append(True)
            return list(missing) if len(queries) == 1 or remain else []

        def which(name):
            return None if name == command_missing else '/fixture/' + name

        with patch.dict(os.environ, dict(os.environ), clear=True), \
                patch.object(deploy_linux, 'run', side_effect=run), \
                patch.object(deploy_linux, 'missing_packages', side_effect=packages), \
                patch.object(deploy_linux.shutil, 'which', side_effect=which), \
                contextlib.redirect_stdout(io.StringIO()):
            if fail or command_missing or remain:
                with self.assertRaises((RuntimeError, ValueError)):
                    deploy_linux.prepare_packages()
            else:
                deploy_linux.prepare_packages()
        return events

    @staticmethod
    def commands(events):
        return [item for item in events if isinstance(item[0], list)]

    def test_update_then_upgrade_are_mandatory_when_all_dependencies_installed(self):
        events = self.exercise()
        commands = self.commands(events)
        self.assertEqual(['update', 'upgrade'], [next(op for op in ('update', 'upgrade', 'install') if op in cmd) for cmd, _ in commands])
        self.assertIn('APT::Update::Error-Mode=any', commands[0][0])
        upgrade = commands[1][0]
        self.assertIn('-y', upgrade)
        self.assertIn('--with-new-pkgs', upgrade)
        self.assertIn('--no-remove', upgrade)
        self.assertIn('Dpkg::Options::=--force-confold', upgrade)
        self.assertGreater(events.index(next(item for item in events if item[0] == 'missing-query')), events.index(commands[1]))

    def test_only_missing_dependencies_are_installed_after_upgrade(self):
        events = self.exercise(missing=('curl', 'certbot'))
        commands = self.commands(events)
        self.assertEqual(len(commands), 3)
        install = commands[-1][0]
        self.assertIn('install', install)
        self.assertIn('--no-upgrade', install)
        self.assertIn('--no-install-recommends', install)
        self.assertIn('curl', install)
        self.assertIn('certbot', install)
        for installed in ('python3', 'openssh-server', 'openssl', 'caddy'):
            self.assertNotIn(installed, install)

    def test_package_commands_are_noninteractive_and_do_not_restart_or_reboot(self):
        commands = self.commands(self.exercise(missing=('curl',)))
        for command, options in commands:
            self.assertEqual(command[0], 'apt-get')
            self.assertNotIn('reboot', command)
            self.assertNotIn('systemctl', command)
            self.assertNotIn('sudo', command)
            self.assertEqual(options['env']['DEBIAN_FRONTEND'], 'noninteractive')
            self.assertEqual(options['env']['NEEDRESTART_SUSPEND'], '1')
            self.assertEqual(options.get('stdin'), subprocess.DEVNULL)

    def test_update_failure_prevents_upgrade_and_dependency_query(self):
        events = self.exercise(fail='update')
        self.assertEqual(len(events), 1)
        self.assertIn('update', events[0][0])

    def test_upgrade_failure_prevents_dependency_query_and_install(self):
        events = self.exercise(missing=('curl',), fail='upgrade')
        self.assertEqual(len(events), 2)
        self.assertIn('upgrade', events[-1][0])

    def test_dependency_install_failure_stops_preparation(self):
        events = self.exercise(missing=('curl',), fail='install')
        self.assertIn('install', self.commands(events)[-1][0])

    def test_dependency_still_unconfigured_after_install_is_an_error(self):
        self.exercise(missing=('curl',), remain=True)

    def test_missing_required_command_after_packages_is_an_error(self):
        self.exercise(command_missing='ss')

    def test_install_does_not_create_accounts_or_touch_services_after_prepare_failure(self):
        with patch.object(deploy_linux, 'prepare_packages', side_effect=RuntimeError('fixture package failure')), \
                patch.object(deploy_linux, 'run') as run, \
                patch.object(deploy_linux.pwd, 'getpwnam') as users, \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                deploy_linux.install(pathlib.Path('/unused-fixture'), {}, [])
        run.assert_not_called()
        users.assert_not_called()

    def test_root_administration_commands_are_discoverable_with_restricted_path(self):
        with patch.dict(os.environ, {'PATH': '/usr/bin'}):
            commands = self.commands(self.exercise())
        paths = commands[0][1]['env']['PATH'].split(os.pathsep)
        self.assertEqual(paths[0], '/usr/bin')
        self.assertIn('/usr/sbin', paths)
        self.assertIn('/sbin', paths)

    def test_command_providers_are_declared_dependencies(self):
        required = set(deploy_linux.REQUIRED_PACKAGES)
        self.assertTrue({'python3', 'curl', 'ca-certificates', 'iproute2', 'util-linux', 'passwd',
                         'openssh-client', 'openssh-server', 'openssl', 'tar', 'caddy', 'certbot'} <= required)
        self.assertEqual(len(required), len(deploy_linux.REQUIRED_PACKAGES))


class InstalledPackageDetection(unittest.TestCase):
    def test_held_installed_packages_are_preserved_without_reinstall(self):
        with patch.object(deploy_linux.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'hold ok installed', '')):
            self.assertEqual(deploy_linux.missing_packages(['openssh-server']), [])

    def test_dpkg_status_distinguishes_installed_missing_and_unconfigured(self):
        states = {'curl': (0, 'install ok installed\n'), 'certbot': (1, ''),
                  'openssl': (0, 'deinstall ok config-files'), 'python3': (0, 'install ok unpacked'),
                  'tar': (0, 'hold ok installed')}
        calls = []

        def invoke(argv, **kwargs):
            calls.append((argv, kwargs))
            package = argv[-1]
            code, output = states[package]
            return subprocess.CompletedProcess(argv, code, output, '')

        with patch.object(deploy_linux.subprocess, 'run', side_effect=invoke):
            missing = deploy_linux.missing_packages(list(states))
        self.assertEqual(set(missing), {'certbot', 'openssl', 'python3'})
        self.assertEqual(len(calls), len(states))
        for command, options in calls:
            self.assertEqual(command[0], 'dpkg-query')
            self.assertNotIn('shell', options)


if __name__ == '__main__':
    unittest.main()
