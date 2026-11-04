"""Repository assets and install mapping remain valid after source reorganization."""
import argparse
import importlib.util
import io
import pathlib
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from asset_paths import static_directory

REPOSITORY=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPOSITORY/'installer'))
import deploy_linux
spec=importlib.util.spec_from_file_location('layout_launcher',REPOSITORY/'installer/install.py')
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)


class RepositoryAssets(unittest.TestCase):
    def test_checked_out_backend_uses_repository_frontend(self):
        path=static_directory(REPOSITORY/'backend')
        self.assertEqual(path,REPOSITORY/'frontend/static')
        self.assertTrue((path/'index.html').is_file())
        self.assertTrue((path/'native-theme.css').is_file())

    def test_installed_assets_win_even_when_other_frontend_exists(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);backend=root/'backend';(backend/'static').mkdir(parents=True)
            (root/'frontend/static').mkdir(parents=True);(root/'frontend/static/index.html').touch()
            self.assertEqual(static_directory(backend),backend/'static')

    def test_unrelated_runtime_does_not_read_sibling_frontend(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);runtime=root/'installed';runtime.mkdir()
            (root/'frontend/static').mkdir(parents=True);(root/'frontend/static/index.html').touch()
            self.assertEqual(static_directory(runtime),runtime/'static')
            with self.assertRaises(FileNotFoundError):(static_directory(runtime)/'index.html').read_bytes()

    def test_missing_repository_assets_do_not_substitute_an_unrelated_path(self):
        with tempfile.TemporaryDirectory() as folder:
            backend=pathlib.Path(folder)/'backend';backend.mkdir()
            self.assertEqual(static_directory(backend),backend/'static')
            with self.assertRaises(FileNotFoundError):(static_directory(backend)/'index.html').read_bytes()


class InstallationLayout(unittest.TestCase):
    def fixture(self,root):
        files={'backend/server.py':'DEFAULTS=[]\n','backend/web_auth.py':'# auth\n',
               'backend/account_helper.py':'# account\n','backend/deployment_helper.py':'# domain\n',
               'backend/control_remote.py':'# adapter\n','frontend/static/index.html':'<html>fixture</html>',
               'frontend/static/native-theme.css':'body{}','frontend/pwa/login/index.html':'<html>login</html>',
               'frontend/pwa/pwa/login.js':'// login\n','installer/deploy_linux.py':'# deploy\n',
               'installer/render.py':'# render\n','installer/reset_bootstrap.py':'# bootstrap\n',
               'installer/reset_account.py':'# reset\n','scripts/install.sh':'#!/bin/bash\n'}
        for name,body in files.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body)
        return files

    def test_distribution_payload_maps_to_existing_installation_layout(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder)/'checkout';root.mkdir();self.fixture(root)
            for name in ('backend/servers.json','backend/telegram.token','backend/private.pem',
                         'backend/test_private.py','backend/check_live.py','tests/python/test_layout.py',
                         'docs/operator.md','frontend/pwa/sessions.json'):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('do-not-copy')
            uploaded={p.as_posix() for p in launcher.source_files(root)}
            selected=deploy_linux.selected_files(root)
            self.assertIn('installer/deploy_linux.py',uploaded)
            self.assertTrue({p.as_posix() for p in selected}<=uploaded)
            installed=pathlib.Path(folder)/'installed'
            for relative in selected:
                destination=installed/deploy_linux.install_relative(relative)
                destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/relative,destination)
            self.assertTrue((installed/'server.py').is_file())
            self.assertTrue((installed/'control_remote.py').is_file())
            self.assertTrue((installed/'static/index.html').is_file())
            self.assertTrue((installed/'pwa/login/index.html').is_file())
            self.assertEqual((installed/'static/index.html').read_text(),'<html>fixture</html>')
            self.assertFalse(any((installed/name).exists() for name in ('backend','frontend','installer','tests','servers.json','telegram.token','private.pem','test_private.py','check_live.py')))
            self.assertFalse(any('operator.md' in name or 'sessions.json' in name for name in uploaded))

    def test_downloaded_repository_root_discovery_uses_backend(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=pathlib.Path(folder);source=folder/'ServerDeck-main';source.mkdir();self.fixture(source)
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w:gz') as archive:
                for path in source.rglob('*'):
                    if path.is_file():archive.add(path,arcname='ServerDeck-main/'+path.relative_to(source).as_posix())
            extracted=launcher.extract_archive(stream.getvalue(),folder/'download')
            self.assertEqual(extracted.name,'ServerDeck-main')
            self.assertIn(pathlib.Path('backend/server.py'),launcher.source_files(extracted))

    def test_local_installer_discovers_repository_above_installer_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder)/'checkout';root.mkdir();self.fixture(root)
            with patch.object(launcher,'__file__',str(root/'installer/install.py')),patch.object(launcher.urllib.request,'urlopen',side_effect=AssertionError('Local sources must not download')):
                self.assertEqual(launcher.get_source(argparse.Namespace(source=None),pathlib.Path(folder)/'scratch'),root.resolve())


if __name__=='__main__':unittest.main()
