"""Manager update routing and transport checks with no SSH or service execution."""
import io
import json
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from control import Control
import control_remote as remote
from mtproxyl_update_remote import ManagerCodeUpdate


class ManagerUpdateIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.manager_root = self.root / 'mtproxyl'
        self.manager_root.mkdir()
        (self.manager_root / 'mtproxyl.sh').write_text('#!/bin/bash\nVERSION="1.7.17"\n')
        self.request = {'kind': 'update', 'component': 'mtproxyl', 'version': 'v1.7.18'}
        self.replace(patch.object(remote, 'MT', self.manager_root))
        self.versions = self.replace(patch.object(remote, 'versions', return_value={'mtproxyl': '1.7.17'}))
        self.run = self.replace(patch.object(remote, 'run', side_effect=AssertionError('Native commands are forbidden')))
        self.manager = self.replace(patch.object(remote, 'MANAGER'))
        self.urlopen = self.replace(patch('urllib.request.urlopen', return_value=self.releases()))

    def replace(self, patcher):
        self.addCleanup(patcher.stop)
        return patcher.start()

    @staticmethod
    def releases(*entries):
        return io.BytesIO(json.dumps(entries or [{'tag_name': 'v1.7.18'}]).encode())

    def test_latest_stable_manager_release_is_validated_before_adapter_plan(self):
        order = []
        self.versions.side_effect = lambda: order.append('versions') or {'mtproxyl': '1.7.17'}
        def releases(*args, **kwargs):
            order.append('releases')
            return self.releases({'tag_name': 'mtproxyl-panel-v1.3.14'},
                                 {'tag_name': 'v9.0.0', 'draft': True},
                                 {'tag_name': 'v8.0.0', 'prerelease': True},
                                 {'tag_name': 'v1.7.18'})
        self.urlopen.side_effect = releases
        expected = {'revision': 'manager-state', 'request': dict(self.request, managerRevision='manager-state')}
        self.manager.plan.side_effect = lambda request: order.append('manager') or expected

        self.assertEqual(remote.update_plan(self.request), expected)

        self.assertEqual(order, ['versions', 'releases', 'manager'])
        self.manager.plan.assert_called_once_with(self.request)
        self.urlopen.assert_called_once_with(
            'https://api.github.com/repos/Liafanx/MTProxyL/releases?per_page=50', timeout=20)
        self.run.assert_not_called()

    def test_changed_missing_or_unstable_release_never_reaches_manager(self):
        for releases in ([{'tag_name': 'v1.7.19'}, {'tag_name': 'v1.7.18'}],
                         [{'tag_name': 'v1.7.18', 'draft': True}],
                         [{'tag_name': 'v1.7.18', 'prerelease': True}], []):
            with self.subTest(releases=releases):
                self.urlopen.return_value = io.BytesIO(json.dumps(releases).encode())
                with self.assertRaisesRegex(ValueError, 'Последний релиз'):
                    remote.update_plan(self.request)
        self.manager.plan.assert_not_called()
        self.manager.apply.assert_not_called()
        self.run.assert_not_called()

    def test_failed_release_lookup_never_falls_back_to_native_update(self):
        self.urlopen.side_effect = OSError('Release service is unavailable')
        with self.assertRaises(OSError):
            remote.update_plan(self.request)
        self.manager.plan.assert_not_called()
        self.run.assert_not_called()

    def test_unknown_component_and_missing_manager_are_rejected_before_release_lookup(self):
        with self.assertRaises(ValueError):
            remote.update_plan(dict(self.request, component='unknown-manager'))
        (self.manager_root / 'mtproxyl.sh').unlink()
        with self.assertRaisesRegex(ValueError, 'не установлен'):
            remote.update_plan(self.request)
        self.urlopen.assert_not_called()
        self.manager.plan.assert_not_called()
        self.run.assert_not_called()

    def test_published_but_unreviewed_release_and_older_installation_are_refused(self):
        for installed, target in [('1.3.1', 'v1.7.18'), ('неизвестно', 'v1.7.18'),
                                  ('1.7.17', 'v1.7.19')]:
            with self.subTest(installed=installed, target=target):
                self.versions.return_value = {'mtproxyl': installed}
                self.urlopen.return_value = self.releases({'tag_name': target})
                adapter = ManagerCodeUpdate(self.manager_root, self.root / 'state',
                                            {'versions': remote.versions})
                with patch.object(remote, 'MANAGER', adapter), patch.object(adapter, '_capture') as capture:
                    with self.assertRaises(ValueError):
                        remote.update_plan(dict(self.request, version=target))
                    capture.assert_not_called()
        self.run.assert_not_called()

    def test_apply_uses_only_pinned_adapter_and_preserves_reviewed_revision(self):
        request = dict(self.request, managerRevision='reviewed-state')
        expected = {'verified': True, 'message': 'Manager code updated'}
        self.manager.apply.return_value = expected
        self.versions.side_effect = AssertionError('Generic update path must not run')

        self.assertEqual(remote.apply_update(request), expected)

        self.manager.apply.assert_called_once_with(request)
        self.versions.assert_not_called()
        self.urlopen.assert_not_called()
        self.run.assert_not_called()

    def test_adapter_rejection_has_no_native_update_fallback(self):
        self.manager.apply.side_effect = ValueError('State changed since preview')
        with self.assertRaisesRegex(ValueError, 'State changed'):
            remote.apply_update(dict(self.request, managerRevision='old-state'))
        self.manager.apply.assert_called_once()
        self.run.assert_not_called()
        self.versions.assert_not_called()

    def test_worker_revalidates_latest_release_before_any_mutation(self):
        state = self.root / 'state'
        (state / 'jobs').mkdir(parents=True)
        request = dict(self.request, job='a' * 32, revision='old-state',
                       managerRevision='old-state', expiresAt=time.time() + 300)
        self.urlopen.return_value = self.releases({'tag_name': 'v1.7.19'})
        with patch.object(remote, 'STATE', state), patch.object(remote, 'JOB_LOG', None), \
             patch.object(remote, 'baseline') as baseline:
            remote.job_worker(request)

        result = json.loads((state / 'jobs' / ('a' * 32 + '.json')).read_text())
        self.assertEqual(result['state'], 'failed')
        self.assertIn('Последний релиз', result['error'])
        baseline.assert_not_called()
        self.manager.apply.assert_not_called()
        self.run.assert_not_called()


class EmbeddedManagerAdapterTests(unittest.TestCase):
    def test_ssh_source_embeds_manager_without_remote_python_module_dependency(self):
        source = pathlib.Path(__file__).resolve().parents[2] / 'backend'
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name in ('control_remote.py', 'panel_tls.py', 'software_remote.py',
                         'mtproxyl_update_remote.py', 'reboot_remote.py', 'service_restart_remote.py'):
                (root / name).write_text((source / name).read_text())
            control = Control(root, lambda: [], root)
            self.assertNotIn('from mtproxyl_update_remote import ManagerCodeUpdate', control.remote)
            namespace = {'__name__': 'embedded_adapter_test'}
            with patch.dict(sys.modules, {'mtproxyl_update_remote': None}):
                exec(compile(control.remote, '<ssh-adapter>', 'exec'), namespace)

            manager = namespace['MANAGER']
            self.assertEqual(type(manager).__module__, 'embedded_adapter_test')
            self.assertEqual(manager.root, pathlib.Path('/opt/mtproxyl'))
            self.assertIs(manager.hooks['versions'], namespace['versions'])
            pinned = Mock()
            namespace['MANAGER'] = pinned
            request = {'component': 'mtproxyl', 'version': 'v1.7.18', 'managerRevision': 'reviewed-state'}
            namespace['apply_update'](request)
            pinned.apply.assert_called_once_with(request)


if __name__ == '__main__':
    unittest.main()
