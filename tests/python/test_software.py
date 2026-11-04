import copy, hashlib, io, json, pathlib, tarfile, tempfile, time, unittest
from unittest.mock import patch, Mock
import control_remote as remote
from control import Control
from software_remote import SoftwareAdapter, bounded_awg_script

def inventory():
    return dict(supported=True,arch='x86_64',ports=[22],versions={},containers=[],units={},configHashes={},bootId='boot',os='Ubuntu',components={k:dict(installed=False,version='',conflict=False,protected=False,candidate='1.2') for k in ('lucx','mtproxyl','mtproxyl-panel','awg','telemt','fail2ban')})

def sources(c,version):
    repo='AlexeyLCP/lucx-ui' if c in ('lucx','awg') else 'Liafanx/MTProxyL';commit='a'*40
    out=dict(repo=repo,version=version,commit=commit)
    for key,path in {'lucx':{'unit':'x-ui.service.debian','cli':'x-ui.sh'},'mtproxyl':{'installer':'install.sh'},'mtproxyl-panel':{'installer':'mtproxyl-panel/install.sh'},'awg':{'installer':'bin/install-awg-module.sh'}}[c].items():
        out[key]=dict(url='https://raw.githubusercontent.com/'+repo+'/'+commit+'/'+path,sha256='b'*64)
    if c in ('lucx','mtproxyl-panel'):
        name='x-ui-linux-amd64.tar.gz' if c=='lucx' else 'mtproxyl-panel-x86_64-linux-gnu.tar.gz'
        out['archive']=dict(url='https://github.com/'+repo+'/releases/download/'+version+'/'+name,sha256='c'*64)
    return out

class SoftwareSafetyTests(unittest.TestCase):
    def setUp(self):
        self.inv=inventory();self.adapter=SoftwareAdapter(vars(remote));self.invpatch=patch.object(self.adapter,'inventory',side_effect=lambda:copy.deepcopy(self.inv));self.invpatch.start()
    def tearDown(self):self.invpatch.stop()
    def request(self,c='lucx',kind='install',port=2053,version='v3.11.0-lucx.332'):
        return dict(kind=kind,component=c,port=port,version=version,sources=sources(c,version),serverHost='192.0.2.1',sni='example.org')
    def test_existing_config_and_docker_are_never_overwritten(self):
        self.inv['components']['lucx']['conflict']=True
        with self.assertRaisesRegex(ValueError,'поверх запрещена'):self.adapter.plan(self.request())
        self.inv['components']['lucx']['conflict']=False;self.inv['components']['lucx']['installed']=True
        with self.assertRaisesRegex(ValueError,'поверх запрещена'):self.adapter.plan(dict(self.request(),force=True))
    def test_occupied_tcp_or_udp_port_stops_before_install(self):
        self.inv['ports']+=[2053]
        with self.assertRaisesRegex(ValueError,'уже занят'):self.adapter.plan(self.request())
    def test_port_payloads_and_arbitrary_release_urls_rejected(self):
        for port in (True,22,'2053;reboot',70000):
            with self.assertRaises(ValueError):self.adapter.plan(self.request(port=port))
        req=self.request();req['sources']['archive']['url']='https://example.com/installer'
        with self.assertRaisesRegex(ValueError,'Неверная сборка'):self.adapter.plan(req)
    def test_standard_xui_not_migrated_to_lucx(self):
        self.inv['components']['lucx'].update(installed=True,version='3.11.0')
        with self.assertRaisesRegex(ValueError,'другой вариант'):self.adapter.plan(self.request(kind='update'))
    def test_awg_container_without_host_module_is_protected(self):
        self.inv['components']['awg'].update(protected=True,containers=['amnezia-awg2'])
        with self.assertRaisesRegex(ValueError,'оборвать VPN'):self.adapter.plan(self.request(c='awg'))
    def test_panel_requires_existing_manager(self):
        with self.assertRaisesRegex(ValueError,'Сначала установите MTProxyL'):self.adapter.plan(self.request(c='mtproxyl-panel',version='mtproxyl-panel-v1.3.13'))
    def test_low_memory_manager_does_not_implicitly_create_swap(self):
        self.inv.update(totalMemoryMiB=992,swapActive=False)
        with self.assertRaisesRegex(ValueError,'создаёт swap'):self.adapter.plan(self.request(c='mtproxyl',port=4433,version='v1.7.17'))
    def test_apt_cannot_remove_or_upgrade_other_packages(self):
        req=dict(kind='install',component='fail2ban')
        for result in ('Remv nginx [1.0]','Inst openssh-server [1.0] (2.0 Ubuntu [amd64])'):
            with patch.object(self.adapter,'run',return_value=result),self.assertRaisesRegex(ValueError,'других пакетов'):self.adapter.plan(req)
    def test_configuration_drift_invalidates_preview(self):
        with patch.object(self.adapter,'run',return_value='Inst fail2ban (1.2 Ubuntu [all])'):
            first=self.adapter.plan(dict(kind='install',component='fail2ban'))
            self.inv['configHashes']['/etc/mtproxyl-panel/config.toml']='changed'
            second=self.adapter.plan(first['request'])
        self.assertNotEqual(first['revision'],second['revision'])
    def test_changed_archive_hash_never_accepted(self):
        with tempfile.TemporaryDirectory() as td,patch('software_remote.urllib.request.urlopen',return_value=io.BytesIO(b'altered')):
            with self.assertRaisesRegex(ValueError,'SHA-256'):self.adapter.download(dict(url='https://example.org/a',sha256=hashlib.sha256(b'expected').hexdigest()),pathlib.Path(td)/'asset')
    def test_archive_path_traversal_and_symlinks_blocked_before_extraction(self):
        for name,kind in (('../outside',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('link',tarfile.SYMTYPE)):
            with tempfile.TemporaryDirectory() as td:
                root=pathlib.Path(td);archive=root/'a.tar.gz';dest=root/'dest';dest.mkdir()
                with tarfile.open(archive,'w:gz') as tar:
                    item=tarfile.TarInfo(name);item.type=kind;item.linkname='/etc/shadow';tar.addfile(item)
                with self.assertRaisesRegex(ValueError,'Небезопасный'):self.adapter.unpack(archive,dest)
                self.assertEqual(list(dest.iterdir()),[])
    def test_edited_awg_recipe_cannot_run(self):
        with self.assertRaisesRegex(ValueError,'проверенному рецепту'):bounded_awg_script('#!/bin/bash\nreboot\n')
    def test_expired_download_cannot_install(self):
        with tempfile.TemporaryDirectory() as td:
            req=self.request();req.update(expiresAt=time.time()-1,job='a'*32)
            with patch('software_remote.tempfile.TemporaryDirectory') as tmp,patch.object(self.adapter,'download'),patch.object(self.adapter,'install_lucx') as install,patch.dict(self.adapter.r,versions=lambda:{}):
                tmp.return_value.__enter__.return_value=td
                with self.assertRaisesRegex(ValueError,'истёк'):self.adapter.apply(req)
                install.assert_not_called()

class ControlSoftwareTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=pathlib.Path(self.temp.name);(root/'control_remote.py').write_text('')
        self.server=dict(id='one',name='One',host='192.0.2.1',user='root',port=22,key='k')
        self.c=Control(root,lambda:[self.server],root)
    def tearDown(self):self.temp.cleanup()
    def test_browser_cannot_override_source_or_backup_policy(self):
        req=dict(server='one',kind='install',component='lucx',version='v3.11.0-lucx.332',port=2053,sources={'url':'evil'},backupPanels=[],command='reboot')
        responses=[inventory(),dict(revision='r',request=dict(kind='install',component='lucx'),summary={'title':'Install'})]
        with patch.object(self.c,'release_catalog',return_value={'lucx':{'releases':[{'version':req['version']}]}}),patch('control.prepare_sources',return_value={'trusted':True}),patch.object(self.c,'ssh',side_effect=responses) as ssh:
            self.c.plan(req)
        payload=ssh.call_args_list[-1].args[1]
        self.assertEqual(payload['sources'],{'trusted':True});self.assertNotIn('command',payload);self.assertNotIn('backupPanels',payload)
    def test_host_backup_failure_on_empty_server_never_submits(self):
        job=dict(id='a'*32,server='one',state='backing_up',backups=[]);self.c.jobs[job['id']]=job
        plan=dict(server='one',request=dict(kind='install',component='lucx'),revision='r',expiresAt=time.time()+300)
        with patch.object(self.c,'ssh',return_value={}) as ssh,patch.object(self.c,'create_backup',side_effect=RuntimeError('disk full')) as backup:
            self.c.worker(job['id'],plan)
        backup.assert_called_once_with(self.server,'host','before-install');self.assertEqual([x.args[1]['op'] for x in ssh.call_args_list],['versions']);self.assertEqual(job['state'],'failed')
    def test_combined_worker_is_self_contained(self):
        root=(pathlib.Path(__file__).resolve().parents[2] / 'backend')
        combined=(root/'control_remote.py').read_text().replace('from software_remote import SoftwareAdapter',(root/'software_remote.py').read_text())
        combined=combined.replace('from reboot_remote import RemoteReboot',(root/'reboot_remote.py').read_text())
        namespace={'__name__':'deck_test'};exec(compile(combined,'<remote>','exec'),namespace)
        self.assertIn('SOFTWARE',namespace);self.assertNotIn('from software_remote import',combined)
        self.assertIn('REBOOT',namespace);self.assertNotIn('from reboot_remote import',combined)

if __name__=='__main__':unittest.main()
