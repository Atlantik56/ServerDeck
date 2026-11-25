import json
import pathlib
import tempfile
import unittest
from unittest.mock import Mock

from panel_updates import CHECK_INTERVAL, PanelUpdates


class PanelUpdatesTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = pathlib.Path(directory.name)
        self.deployment = Mock()
        self.deployment.available.return_value = True
        self.deployment.apply_panel_update.return_value = {'accepted': True}
        self.fetch = Mock(return_value={
            'version': '1.6.1', 'url': 'https://github.com/Atlantik56/ServerDeck/releases/tag/v1.6.1',
            'summary': 'Release notes', 'assetUrl': 'internal-download-url', 'sha256': 'internal-digest',
        })
        self.now = 1000
        self.manager = PanelUpdates(self.deployment, self.root, self.fetch, lambda: self.now)

    def save(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding='utf-8')

    def test_unversioned_installation_cannot_start_updates(self):
        self.assertEqual(self.manager.check(force=True)['state'], 'unversioned')
        self.fetch.assert_not_called()
        with self.assertRaises(ValueError):
            self.manager.apply({'version': '1.6.1'})
        self.deployment.apply_panel_update.assert_not_called()

    def test_check_hides_artifact_details_and_only_accepts_the_selected_new_version(self):
        self.save('installed.json', {'version': '1.6.0', 'revision': 'a' * 40})
        status = self.manager.check()
        self.assertEqual(status['state'], 'available')
        self.assertEqual(set(status['latest']), {'version', 'url', 'summary'})
        for data in ({'version': '1.6.0'}, {'version': '1.6.2'}, {'version': '1.6.1', 'url': 'external'}):
            with self.assertRaises(ValueError):
                self.manager.apply(data)
        self.assertEqual(self.manager.apply({'version': '1.6.1'}), {'accepted': True})
        self.deployment.apply_panel_update.assert_called_once_with('1.6.1')

    def test_failed_new_check_does_not_keep_the_previous_install_button_enabled(self):
        self.save('installed.json', {'version': '1.6.0'})
        self.manager.check()
        self.manager.check(force=True)
        self.fetch.assert_called_once()
        self.now += CHECK_INTERVAL
        self.fetch.side_effect = OSError('network fixture')
        status = self.manager.check()
        self.assertEqual(status['state'], 'unknown')
        self.assertIsNone(status['latest'])
        self.assertEqual(status['checkedAt'], self.now)
        with self.assertRaises(ValueError):
            self.manager.apply({'version': '1.6.1'})

    def test_receipt_survives_recreating_the_manager_after_restart(self):
        self.save('installed.json', {'version': '1.6.1'})
        self.save('job.json', {'id': 'b' * 32, 'version': '1.6.1', 'state': 'succeeded',
                              'stage': 'complete', 'internal': 'private fixture'})
        status = PanelUpdates(self.deployment, self.root, self.fetch, lambda: self.now).check()
        self.assertEqual(status['state'], 'current')
        self.assertEqual(status['job']['state'], 'succeeded')
        self.assertNotIn('internal', status['job'])
