"""Passive probes only: subprocesses, Linux files and network are mocked."""
import ast
import copy
import io
import json
import pathlib
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from monitor import HealthStore


ROOT = pathlib.Path(__file__).resolve().parent
CID = 'a' * 12


def probe_module():
    # remote.py is an SSH-stdin script. Load only its imports/functions so a
    # helper test can never accidentally execute the status/action dispatcher.
    tree = ast.parse((ROOT / 'remote.py').read_text())
    namespace = {}
    exec(compile(ast.Module(body=[node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))], type_ignores=[]), 'remote-probes', 'exec'), namespace)
    return namespace


def docker_row(name='amnezia-awg', state='running', identity=CID):
    return json.dumps(dict(ID=identity, Names=name, Image='amnezia-awg:latest', State=state, Status='Up 1 day'))


def status(ts=100):
    return dict(checkedAt=ts, ok=True, data=dict(cpu=10, memory={'used':20,'total':100}, disk={'used':30,'total':100}, bootId='boot-a', awg=[], services=[], containers=[], collectionOk={'services':True,'containers':True,'awg':True}, awgSupported=False, dockerSupported=True))


class CriticalProbeTests(unittest.TestCase):
    def setUp(self):
        self.probe = probe_module()
        self.probe['shutil']=types.SimpleNamespace(which=Mock(return_value='/usr/bin/tool'))

    def run_probe(self, name, responses, *args):
        runner = Mock(side_effect=responses)
        self.probe['run'] = runner
        return self.probe[name](*args), runner

    def test_docker_failure_does_not_establish_empty_inventory(self):
        result, runner = self.run_probe('collect_containers', [(1,'','daemon unavailable')])
        self.assertEqual(result, ([], False, True))
        self.assertEqual(runner.call_count, 1)
        completed, _ = self.run_probe('collect_containers', [(0,'','')])
        self.assertEqual(completed, ([], True, True))

    def test_docker_binary_absence_and_check_failure_differ(self):
        self.probe['shutil'].which.return_value=None
        missing,runner=self.run_probe('collect_containers', [])
        self.assertEqual(missing, ([], True, False))
        runner.assert_not_called()
        self.probe['shutil'].which.assert_called_with('docker')
        self.probe['shutil'].which.return_value='/usr/bin/docker'
        self.assertEqual(self.run_probe('collect_containers', [(127,'','')])[0], ([], False, True))
        self.assertEqual(self.run_probe('collect_containers', [subprocess.TimeoutExpired('docker',12)])[0], ([], False, True))
        self.probe['shutil'].which.side_effect=OSError('PATH unreadable')
        self.assertEqual(self.run_probe('collect_containers', [])[0], ([], False, None))

    def test_known_running_awg_container_probes_interfaces_readonly(self):
        result, runner = self.run_probe('collect_containers', [(0,docker_row(),''), (0,'awg0 awg1','')])
        containers, complete, supported = result
        self.assertTrue(complete and supported)
        self.assertEqual(containers[0]['awg'], {'collectionOk':True,'interfaces':['awg0','awg1']})
        self.assertEqual(runner.call_args_list[-1].args[0], ['docker','exec','--',CID,'awg','show','interfaces'])
        self.assertFalse(any('showconf' in call.args[0] for call in runner.call_args_list))

    def test_empty_interfaces_and_probe_error_are_distinct(self):
        missing, _ = self.run_probe('collect_containers', [(0,docker_row(),''), (0,'','')])
        unknown, _ = self.run_probe('collect_containers', [(0,docker_row(),''), (1,'','private diagnostic text')])
        self.assertEqual(missing[0][0]['awg'], {'collectionOk':True,'interfaces':[]})
        self.assertFalse(unknown[0][0]['awg']['collectionOk'])
        self.assertTrue(unknown[1])
        self.assertNotIn('private diagnostic text', json.dumps(unknown))

    def test_probe_timeout_and_invalid_output_are_unknown(self):
        for response in (subprocess.TimeoutExpired('docker',12), (0,'invalid/interface',''), (0,'x'*16,'')):
            with self.subTest(response=type(response).__name__):
                result, _ = self.run_probe('probe_container_awg', [response], CID)
                self.assertFalse(result['collectionOk'])
                self.assertEqual(result['interfaces'], [])
        result, runner = self.run_probe('probe_container_awg', [], '-invalid')
        self.assertFalse(result['collectionOk'])
        runner.assert_not_called()

    def test_stopped_awg_and_unknown_containers_are_not_execed(self):
        out='\n'.join((docker_row(state='exited'),docker_row('unrelated-vpn')))
        (containers, complete, _), runner = self.run_probe('collect_containers', [(0,out,'')])
        self.assertTrue(complete)
        self.assertTrue(all('awg' not in row for row in containers))
        self.assertEqual(runner.call_count, 1)

    def test_awg_name_classification_matches_critical_engine(self):
        for name in ('amnezia-awg','amnezia_awg','amneziaawg','amnezia-awg-v2','Amnezia_awg_custom.1','amneziaawg3'):
            with self.subTest(known=name):
                (containers,complete,_),runner=self.run_probe('collect_containers',[(0,docker_row(name),''),(0,'awg0','')])
                self.assertTrue(complete)
                self.assertEqual(containers[0]['awg'],{'collectionOk':True,'interfaces':['awg0']})
                self.assertEqual(runner.call_count,2)
        for name in ('unrelated-vpn','other-amnezia-awg','amnezia-openvpn','amnezia-aw','amnezia--awg','amnezia-awg'+'x'*81):
            with self.subTest(unrelated=name):
                (containers,complete,_),runner=self.run_probe('collect_containers',[(0,docker_row(name),'')])
                self.assertTrue(complete)
                self.assertNotIn('awg',containers[0])
                self.assertEqual(runner.call_count,1)

    def test_malformed_docker_inventory_is_partial_not_complete(self):
        (containers, complete, supported), _ = self.run_probe('collect_containers', [(0,docker_row()+'\n{broken',''),(0,'awg0','')])
        self.assertEqual(len(containers), 1)
        self.assertFalse(complete)
        self.assertTrue(supported)

    def test_host_awg_absent_failed_and_empty_inventory_differ(self):
        self.probe['shutil'].which.return_value=None
        missing,runner=self.run_probe('collect_host_awg', [])
        self.assertEqual(missing, ([], True, False))
        runner.assert_not_called()
        self.probe['shutil'].which.assert_called_with('awg')
        self.probe['shutil'].which.return_value='/usr/bin/awg'
        self.assertEqual(self.run_probe('collect_host_awg', [(1,'','query failed')])[0], ([], False, True))
        self.assertEqual(self.run_probe('collect_host_awg', [(0,'','')])[0], ([], True, True))
        self.assertEqual(self.run_probe('collect_host_awg', [OSError('not available')])[0], ([], False, True))
        self.probe['shutil'].which.side_effect=OSError('PATH unreadable')
        self.assertEqual(self.run_probe('collect_host_awg', [])[0], ([], False, None))

    def test_host_awg_positive_keeps_existing_metrics_shape(self):
        self.probe['open'] = Mock(side_effect=lambda *_: io.StringIO('4'))
        (interfaces, complete, supported), _ = self.run_probe('collect_host_awg', [(0,'awg1',''),(0,'public 123',''),(0,'public 10 20',''),(0,'51820','')])
        self.assertTrue(complete and supported)
        self.assertEqual(interfaces[0]['interface'], 'awg1')
        self.assertEqual(interfaces[0]['ifindex'], 4)
        self.assertEqual((interfaces[0]['peers'],interfaces[0]['rx'],interfaces[0]['tx']), (1,10,20))

    def test_service_query_failure_unknown_not_inactive(self):
        healthy='LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4'
        result, _ = self.run_probe('collect_unit_status', [(0,healthy,'')], 'x-ui.service')
        self.assertTrue(result['collectionOk'])
        failed, _ = self.run_probe('collect_unit_status', [(1,'','query failed')], 'x-ui.service')
        self.assertFalse(failed['collectionOk'])
        self.assertEqual(failed['state'], 'unknown')
        timeout, _ = self.run_probe('collect_unit_status', [subprocess.TimeoutExpired('systemctl',12)], 'x-ui.service')
        self.assertFalse(timeout['collectionOk'])
        self.assertEqual(timeout['state'], 'unknown')

    def test_legacy_unit_status_shape_preserved_for_actions(self):
        result, _ = self.run_probe('unit_status', [(0,'LoadState=loaded\nActiveState=active','')], 'x-ui.service')
        self.assertNotIn('collectionOk', result)

    def test_malformed_registered_docker_state_is_unknown(self):
        result, _ = self.run_probe('collect_unit_status', [(0,'[]','')], 'docker:'+CID)
        self.assertFalse(result['collectionOk'])
        self.assertEqual(result['state'], 'unknown')

    def test_status_dispatcher_propagates_partial_and_empty_namespace_flags(self):
        tree=ast.parse((ROOT/'remote.py').read_text())
        dispatcher=next(node for node in tree.body if isinstance(node,ast.If))
        code=compile(ast.Module(body=dispatcher.orelse,type_ignores=[]),'remote-status-dispatch','exec')
        files={'/proc/stat':'cpu 10 0 0 90 0 0 0 0','/proc/meminfo':'MemTotal: 100 kB\nMemAvailable: 80 kB\n','/proc/uptime':'1000 0','/proc/sys/kernel/random/boot_id':'boot-a'}
        for containers_ok,namespace_ok in ((True,True),(True,False),(False,True)):
            with self.subTest(containers_ok=containers_ok,namespace_ok=namespace_ok):
                ns=probe_module()
                ns.update(action='status',request={'services':[]},run=Mock(return_value=(0,'','')),open=lambda path:io.StringIO(files[path]),collect_host_awg=lambda:([],True,False),collect_containers=lambda:([{'name':'amnezia-awg','awg':{'collectionOk':namespace_ok,'interfaces':[]}}],containers_ok,True))
                ns['sqlite3']=types.SimpleNamespace(connect=Mock(side_effect=OSError()),Error=Exception)
                ns['http']=types.SimpleNamespace(client=types.SimpleNamespace(HTTPConnection=Mock(side_effect=OSError()),HTTPException=Exception))
                ns['time']=types.SimpleNamespace(monotonic=lambda:1,sleep=lambda _:None)
                ns['os']=types.SimpleNamespace(statvfs=lambda _:types.SimpleNamespace(f_blocks=100,f_frsize=1,f_bfree=80,f_bavail=80,f_files=100,f_favail=80),uname=lambda:types.SimpleNamespace(nodename='fake',release='fake'),getloadavg=lambda:(0,0,0),cpu_count=lambda:1,path=types.SimpleNamespace(exists=lambda _:False))
                exec(code,ns)
                result=ns['result']
                self.assertEqual(result['collectionOk'],{'services':True,'containers':containers_ok,'awg':containers_ok and namespace_ok})
                self.assertIs(result['containers'][0]['awg']['collectionOk'],namespace_ok)
                self.assertFalse(result['awgSupported'])


class CriticalMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = HealthStore(pathlib.Path(self.temp.name)/'health.sqlite3')

    def test_probes_preserved_through_record_and_reopen(self):
        item=status()
        item['data']['services']=[dict(unit='mtproxyl.service',state='active',loaded=True,collectionOk=True)]
        item['data']['containers']=[dict(unit='docker:'+CID,name='amnezia-awg',state='active',awg=dict(collectionOk=True,interfaces=['awg1','awg0']))]
        self.store.record('a', item)
        sample=HealthStore(self.store.path).report(['a'],now=110)['servers']['a']['latest']
        self.assertEqual(sample['collectionOk'],item['data']['collectionOk'])
        self.assertEqual(sample['services'][0]['collectionOk'],True)
        self.assertEqual(sample['containers'][0]['unit'],'docker:'+CID)
        self.assertEqual(sample['containers'][0]['awg'],{'collectionOk':True,'interfaces':['awg0','awg1']})
        self.assertFalse(sample['awgSupported'])

    def test_missing_legacy_flags_remain_unknown_not_synthesized_true(self):
        item=status();del item['data']['collectionOk']
        sample=self.store.record('a',item)
        self.assertNotIn('collectionOk',sample)

    def test_failed_inventory_records_warning_without_fabricating_container(self):
        item=status();item['data']['collectionOk'].update(containers=False,awg=False)
        sample=self.store.record('a',item)
        self.assertEqual(sample['containers'],[])
        self.assertFalse(sample['collectionOk']['containers'])
        self.assertEqual(sample['health'],'warning')
        self.assertTrue(sample['ok'])

    def test_container_probe_empty_and_failed_stay_distinct(self):
        for ok in (True,False):
            with self.subTest(complete=ok):
                item=status();item['data']['containers']=[dict(name='amnezia-awg',state='active',awg=dict(collectionOk=ok,interfaces=[]))]
                sample=self.store.record('a',item)
                self.assertIs(sample['containers'][0]['awg']['collectionOk'],ok)

    def test_invalid_container_probe_cannot_become_complete(self):
        item=status();item['data']['containers']=[dict(name='amnezia-awg',state='active',awg=dict(collectionOk=True,interfaces=['unsafe/interface'],privateKey='secret'))]
        sample=self.store.record('a',item)
        self.assertEqual(sample['containers'][0]['awg'],{'collectionOk':False,'interfaces':[]})
        self.assertNotIn('secret',json.dumps(sample))

    def test_partial_collection_breaks_awg_counter_comparison(self):
        first=status();first['data']['awg']=[dict(interface='awg1',ifindex=4,counters={'rx_errors':10})]
        self.store.record('a',first)
        partial=copy.deepcopy(first);partial['checkedAt']=160;partial['data']['collectionOk']['awg']=False;partial['data']['awg'][0]['counters']['rx_errors']=20
        sample=self.store.record('a',partial)
        self.assertIsNone(sample['awg'][0]['rxErrorsDelta'])
        next_good=copy.deepcopy(first);next_good['checkedAt']=220;next_good['data']['awg'][0]['counters']['rx_errors']=25
        self.assertIsNone(self.store.record('a',next_good)['awg'][0]['rxErrorsDelta'])


if __name__=='__main__':unittest.main()
