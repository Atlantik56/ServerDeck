import copy
import json
import pathlib
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

import security_updates as watch_module
import security_updates_remote as remote
from security_updates import CVE, SecurityUpdateWatch, compare_versions, validate_vendor


def version_compare(left, right):
    if left == right:
        return True
    order = {'6.8.0-147.147': 1, '6.8.0-149.149': 2, '6.8.0-150.150': 3}
    return order[left] >= order[right] if left in order and right in order else None


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.now = 1000000.0
        self.servers = [{'id': 'one', 'name': 'First VPS', 'host': '192.0.2.1', 'user': 'root', 'port': 22, 'key': 'key'}]
        self.vendor = self.feed()
        self.facts = self.probe()
        self.calls = []
        self.comparison = patch.object(watch_module, 'compare_versions', side_effect=version_compare)
        self.comparison.start()
        self.manager = self.reopen()

    def tearDown(self):
        self.comparison.stop()
        self.temp.cleanup()

    def feed(self, status='pending', version='6.8.0-149.149', source='linux', codename='noble'):
        return {'id': CVE, 'packages': [{'name': source, 'statuses': [
            {'status': status, 'description': version, 'release_codename': codename}]}]}

    def probe(self, version='6.8.0-147.147', kernel='6.8.0-147-generic', source='linux', codename='noble'):
        return {'ok': True, 'checkedAt': self.now, 'os': {'id': 'ubuntu', 'codename': codename},
                'kernel': kernel, 'bootId': 'fake-boot', 'sourcePackage': source, 'installedVersion': version,
                'versionSignature': 'Ubuntu ' + version + '-generic 6.8.12',
                'runningImage': {'package': 'linux-image-' + kernel, 'version': version,
                                 'source': 'linux-signed', 'sourceVersion': version},
                'runningModules': {'package': 'linux-modules-' + kernel, 'version': version,
                                   'source': source, 'sourceVersion': version},
                'installedKernels': []}

    def fetch(self):
        self.calls.append('fetch')
        if isinstance(self.vendor, Exception):
            raise self.vendor
        return copy.deepcopy(self.vendor)

    def probe_fn(self, server):
        self.calls.append('probe')
        if isinstance(self.facts, Exception):
            raise self.facts
        value = copy.deepcopy(self.facts)
        value['checkedAt'] = self.now
        return value

    def reopen(self):
        return SecurityUpdateWatch(self.root, lambda: self.servers, self.root / 'keys',
                                   clock=lambda: self.now, fetch_fn=self.fetch, probe_fn=self.probe_fn)

    def check(self):
        self.manager._check()
        return self.manager.snapshot()

    def test_constructor_and_snapshot_do_no_network_or_ssh(self):
        self.manager.snapshot()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.manager.root, self.root)

    def test_pending_version_and_unrelated_upstream_release_never_publish_fix(self):
        self.vendor['packages'][0]['statuses'].append({'status': 'released', 'description': '7.3~rc7, 6.8.y', 'release_codename': 'upstream'})
        data = self.check()
        self.assertFalse(data['fixedPublished'])
        self.assertEqual(data['servers'][0]['state'], 'awaiting_release')
        self.assertIsNone(data['servers'][0]['fixedVersion'])
        self.assertFalse(data['notices'])

    def test_release_is_exact_source_and_codename_and_never_claims_apt_availability(self):
        for source, codename in [('linux-aws', 'noble'), ('linux', 'jammy'), ('linux-signed', 'noble')]:
            with self.subTest(source=source, codename=codename):
                self.vendor = self.feed('released', source=source, codename=codename)
                data = self.check()
                self.assertEqual(data['servers'][0]['state'], 'unknown')
                self.assertFalse(data['notices'])
        self.vendor = self.feed('released')
        data = self.check()
        row = data['servers'][0]
        self.assertTrue(data['fixedPublished'])
        self.assertEqual(row['state'], 'published')
        self.assertIsNone(row['available'])
        self.assertIn('Проверьте APT', row['message'])
        self.assertEqual(row['sourcePackage'], 'linux')
        self.assertEqual(row['runningImage']['source'], 'linux-signed')

    def test_acknowledgement_dedup_restart_and_new_fixed_version(self):
        self.vendor = self.feed('released')
        first = self.check()['notices'][0]
        self.manager.acknowledge(first['id'])
        self.manager = self.reopen()
        self.now += 3600
        same = self.check()['notices']
        self.assertEqual(len(same), 1)
        self.assertTrue(same[0]['acknowledged'])
        self.assertEqual(same[0]['createdAt'], first['createdAt'])
        self.vendor = self.feed('released', version='6.8.0-150.150')
        self.now += 3600
        notices = self.check()['notices']
        self.assertEqual(len(notices), 2)
        self.assertFalse(notices[0]['acknowledged'])
        self.assertNotEqual(notices[0]['id'], first['id'])
        self.assertEqual(self.manager.path.stat().st_mode & 0o777, 0o600)

    def test_identity_uses_real_release_not_first_same_version_row(self):
        self.vendor = self.feed('released', codename='jammy')
        self.vendor['packages'][0]['statuses'].append({'status': 'released', 'description': '6.8.0-149.149', 'release_codename': 'noble'})
        noble = self.check()['notices'][0]['id']
        self.facts = self.probe(codename='jammy')
        jammy = self.check()['notices']
        self.assertEqual(len(jammy), 2)
        self.assertTrue(any(notice['id'] != noble for notice in jammy))

    def test_errors_and_age_keep_notice_but_cannot_look_fresh_or_fixed(self):
        self.vendor = self.feed('released')
        original = self.check()
        good = original['lastGoodAt']
        notice = original['notices'][0]['id']
        self.now += 60
        self.vendor = RuntimeError('sensitive upstream credentials')
        data = self.check()
        self.assertEqual(data['lastGoodAt'], good)
        self.assertEqual(data['checkedAt'], self.now)
        self.assertTrue(data['stale'])
        self.assertIsNone(data['fixedPublished'])
        self.assertEqual(data['servers'][0]['state'], 'unknown')
        self.assertEqual(data['notices'][0]['id'], notice)
        self.assertNotIn('sensitive', json.dumps(data))
        self.now += 10801
        self.assertTrue(self.manager.snapshot()['stale'])

    def test_failed_ssh_keeps_kernel_evidence_but_unknown(self):
        self.vendor = self.feed('released')
        self.check()
        self.facts = RuntimeError('private ssh stderr')
        self.now += 60
        data = self.check()
        self.assertEqual(data['servers'][0]['kernel'], '6.8.0-147-generic')
        self.assertFalse(data['servers'][0]['ok'])
        self.assertTrue(data['servers'][0]['stale'])
        self.assertEqual(data['servers'][0]['state'], 'unknown')
        self.assertEqual(len(data['notices']), 1)

    def test_mixed_malformed_feed_cannot_partially_commit_released_notice(self):
        original = self.check()
        self.vendor = self.feed('released')
        self.vendor['packages'].append({'name': 'linux-aws', 'statuses': [{'status': 'released'}]})
        self.now += 60
        data = self.check()
        self.assertEqual(data['lastGoodAt'], original['lastGoodAt'])
        self.assertFalse(data['notices'])
        self.assertTrue(data['error'])
        self.assertEqual(self.calls.count('probe'), 1)

    def test_mismatching_cve_duplicate_release_and_invalid_version_fail_closed(self):
        cases = [dict(self.feed('released'), id='CVE-2026-1'), self.feed('released', version='$(touch /tmp/oops)')]
        duplicate = self.feed('released')
        duplicate['packages'][0]['statuses'] *= 2
        cases.append(duplicate)
        for feed in cases:
            with self.subTest(feed=feed), self.assertRaises(ValueError):
                validate_vendor(feed)

    def test_fixed_requires_actual_running_signature_not_only_installed_same_abi_packages(self):
        self.vendor = self.feed('released')
        self.facts = self.probe(version='6.8.0-149.149', kernel='6.8.0-149-generic')
        self.facts['versionSignature'] = ''
        self.assertEqual(self.check()['servers'][0]['state'], 'published')
        self.facts['versionSignature'] = 'Ubuntu 6.8.0-149.149-generic 6.8.12'
        row = self.check()['servers'][0]
        self.assertEqual(row['state'], 'fixed')
        self.assertFalse(row['affected'])

    def test_fixed_kernel_on_disk_requires_exact_image_module_build_pair(self):
        self.vendor = self.feed('released')
        candidate = {'kernel': '6.8.0-149-generic', 'sourcePackage': 'linux', 'sourceVersion': '6.8.0-149.149',
                     'imagePackage': 'linux-image-6.8.0-149-generic', 'imageVersion': '6.8.0-147.147',
                     'modulesPackage': 'linux-modules-6.8.0-149-generic'}
        self.facts['installedKernels'] = [candidate]
        self.assertEqual(self.check()['servers'][0]['state'], 'published')
        candidate['imageVersion'] = '6.8.0-149.149'
        self.assertEqual(self.check()['servers'][0]['state'], 'reboot_required')
        candidate['modulesPackage'] = 'linux-modules-unrelated'
        self.assertEqual(self.check()['servers'][0]['state'], 'published')

    def test_contradictory_kernel_abi_and_package_version_never_classify_fixed(self):
        self.vendor = self.feed('released')
        self.facts = self.probe(version='6.8.0-149.149', kernel='6.8.0-147-generic')
        self.assertEqual(self.check()['servers'][0]['state'], 'published')
        self.facts = self.probe()
        self.facts['installedKernels'] = [{'kernel': '6.8.0-149-generic', 'sourcePackage': 'linux',
             'sourceVersion': '6.8.0-150.150', 'imageVersion': '6.8.0-150.150',
             'imagePackage': 'linux-image-6.8.0-149-generic', 'modulesPackage': 'linux-modules-6.8.0-149-generic'}]
        self.assertEqual(self.check()['servers'][0]['state'], 'published')

    def test_comparator_unavailable_never_claims_running_fixed(self):
        self.vendor = self.feed('released')
        with patch.object(watch_module, 'compare_versions', return_value=None):
            data = self.check()
        self.assertEqual(data['servers'][0]['state'], 'published')
        self.assertIsNone(data['servers'][0]['affected'])

    def test_unsupported_os_remains_explicit_with_fresh_probe(self):
        self.facts['os']['id'] = 'debian'
        row = self.check()['servers'][0]
        self.assertEqual(row['state'], 'unsupported')
        self.assertFalse(row['stale'])

    def test_small_ntp_clock_offset_is_accepted_but_future_over_one_minute_is_unknown(self):
        vendor = validate_vendor(self.vendor)
        facts = self.probe()
        facts['checkedAt'] = self.now + 0.0152986
        row = self.manager._row(self.servers[0], facts, vendor, self.now)
        self.assertEqual(row['state'], 'awaiting_release')
        self.assertTrue(row['ok'])
        facts['checkedAt'] = self.now + 60.001
        self.manager.probe_fn = lambda server: facts
        self.assertEqual(self.check()['servers'][0]['state'], 'unknown')
        facts['os']['id'] = 'debian'
        self.assertEqual(self.check()['servers'][0]['state'], 'unknown')

    def test_removed_or_rebound_server_does_not_keep_old_panel_notice(self):
        self.vendor = self.feed('released')
        self.check()
        self.servers[0]['host'] = '192.0.2.2'
        self.assertFalse(self.manager.snapshot()['notices'])
        self.assertEqual(self.manager.snapshot()['servers'][0]['state'], 'unknown')
        self.servers.clear()
        self.assertFalse(self.check()['notices'])
        self.assertFalse(self.manager.snapshot()['servers'])

    def test_async_checks_singleflight_and_manual_rate_limit(self):
        entered, release = threading.Event(), threading.Event()
        def wait_fetch():
            entered.set()
            release.wait(2)
            return self.vendor
        self.manager.fetch_fn = wait_fetch
        self.manager.request_check()
        self.assertTrue(entered.wait(1))
        worker = self.manager.worker
        self.manager.request_check()
        self.assertIs(self.manager.worker, worker)
        release.set()
        worker.join(2)
        self.assertFalse(self.manager.checking)
        with self.assertRaises(ValueError):
            self.manager.request_check()

    def test_ssh_argv_is_fixed_and_injection_inputs_never_start_process(self):
        with patch.object(watch_module.subprocess, 'run') as run:
            for key, value in [('host', 'x; touch /tmp/oops'), ('user', 'root;id'), ('key', '../secret'), ('port', True)]:
                server = dict(self.servers[0], **{key: value})
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.manager._probe(server)
            self.assertFalse(run.called)
            run.return_value = types.SimpleNamespace(returncode=0, stdout=json.dumps(self.facts))
            self.manager._probe(self.servers[0])
            args, kwargs = run.call_args
            self.assertEqual(args[0][-2:], ['root@192.0.2.1', 'python3 -'])
            self.assertNotIn('shell', kwargs)
            self.assertNotIn('apt-get', kwargs['input'])

    def test_corrupt_nested_cache_does_not_crash_snapshot(self):
        self.check()
        value = json.loads(self.manager.path.read_text())
        value['servers']['one']['data'] = {}
        self.manager.path.write_text(json.dumps(value))
        self.manager = self.reopen()
        self.assertTrue(self.manager.snapshot()['error'])
        self.assertEqual(self.manager.snapshot()['servers'][0]['state'], 'unknown')

    def test_failed_atomic_write_rolls_back_new_notice_and_last_good_state(self):
        original = self.check()
        self.vendor = self.feed('released')
        self.now += 60
        with patch.object(self.manager, '_save', side_effect=OSError('disk full')):
            self.manager._check()
        data = self.manager.snapshot()
        self.assertEqual(data['lastGoodAt'], original['lastGoodAt'])
        self.assertFalse(data['notices'])
        self.assertTrue(data['error'])


class RemoteProbeTests(unittest.TestCase):
    def setUp(self):
        self.kernel = '6.8.0-147-generic'
        self.rows = ('linux-image-' + self.kernel + ':amd64\t6.8.0-147.147\tlinux-signed\t6.8.0-147.147\tinstalled\n' +
                     'linux-modules-' + self.kernel + ':amd64\t6.8.0-147.147\tlinux\t6.8.0-147.147\tinstalled\n')
        self.boot = '11111111-1111-1111-1111-111111111111'

    def collect(self, output=None, boots=None):
        def read(path, limit=16384):
            return {'/etc/os-release': 'ID=ubuntu\nVERSION_CODENAME=noble\n',
                    '/proc/version_signature': 'Ubuntu 6.8.0-147.147-generic 6.8.12\n',
                    '/proc/sys/kernel/random/boot_id': self.boot}[str(path)]
        with patch.object(remote, 'read_small', side_effect=read), patch.object(remote.os, 'uname', return_value=types.SimpleNamespace(release=self.kernel)), \
             patch.object(remote, 'command', return_value=(0, self.rows if output is None else output)) as command, \
             patch.object(remote.pathlib.Path, 'is_file', return_value=True):
            if boots:
                with patch.object(remote, 'boot_id', side_effect=boots):
                    value = remote.collect()
            else:
                value = remote.collect()
            self.assertEqual(command.call_args.args[0], ['dpkg-query', '-W', '-f=' + remote.PACKAGE_FORMAT, 'linux-image*', 'linux-modules*'])
            return value

    def test_signed_image_maps_exactly_to_modules_source_with_bounded_running_signature(self):
        value = self.collect()
        self.assertTrue(value['ok'])
        self.assertEqual(value['sourcePackage'], 'linux')
        self.assertEqual(value['runningImage']['source'], 'linux-signed')
        self.assertEqual(value['versionSignature'], 'Ubuntu 6.8.0-147.147-generic 6.8.12')

    def test_missing_or_duplicate_running_modules_and_boot_change_are_unknown(self):
        image_only = self.rows.splitlines()[0] + '\n'
        self.assertFalse(self.collect(image_only)['ok'])
        self.assertFalse(self.collect(self.rows + self.rows.splitlines()[1] + '\n')['ok'])
        self.assertFalse(self.collect(boots=[self.boot, '22222222-2222-2222-2222-222222222222'])['ok'])

    def test_package_metadata_cannot_inject_paths_or_commands(self):
        with self.assertRaises(ValueError):
            remote.parse_packages(self.rows.replace('linux-modules-', 'linux-modules-../../'))


class VersionOrderingTests(unittest.TestCase):
    def test_debian_backport_epoch_and_tilde_go_to_dpkg_without_semver_or_shell(self):
        with patch.object(watch_module.shutil, 'which', return_value='/usr/bin/dpkg'), patch.object(watch_module.subprocess, 'run') as run:
            run.return_value = types.SimpleNamespace(returncode=1)
            self.assertFalse(compare_versions('1:6.8.0-149.149~24.04.1', '1:6.8.0-149.149'))
            self.assertEqual(run.call_args.args[0], ['/usr/bin/dpkg', '--compare-versions', '1:6.8.0-149.149~24.04.1', 'ge', '1:6.8.0-149.149'])
            run.return_value = types.SimpleNamespace(returncode=0)
            self.assertTrue(compare_versions('2:6.8.0-1.1', '1:6.8.0-149.149'))
            self.assertIsNone(compare_versions('1; echo bad', '1.0'))


if __name__ == '__main__':
    unittest.main()
