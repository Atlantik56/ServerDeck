import copy,json,pathlib,secrets,tempfile,time,unittest
from unittest.mock import patch,Mock
import control_remote as remote
from control import Control
from reboot_remote import RemoteReboot,reboot_digest
from reboot import missing_services

def info():return dict(bootId='before',hostname='vps',kernel='kernel',system='running',services={'x-ui.service':dict(ActiveState='active',UnitFileState='enabled')},containers={'awg':'always'},awg=['awg1'],aptBusy=[])

class RebootTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);(self.root/'control_remote.py').write_text('')
  self.s=dict(id='a',name='VPS',host='192.0.2.1',user='root',port=22,key='test_key',services=['x-ui.service'])
  self.c=Control(self.root,lambda:[self.s],self.root);self.before=info()
 def planned(self):
  with patch.object(self.c,'ssh',return_value=self.before):return self.c.plan(dict(server='a',kind='reboot'))
 def job(self,deadline=None):
  p=self.planned()
  with patch('reboot.threading.Thread') as thread:j=self.c.execute(p['id'],self.s['host'])
  if deadline is not None:self.c.jobs[j['id']]['deadline']=deadline
  return self.c.jobs[j['id']],self.c.plans[p['id']]
 def test_preview_is_read_only_and_warns_about_autostart(self):
  self.before['containers']['awg']='no'
  with patch.object(self.c,'ssh',return_value=self.before) as ssh:p=self.c.plan(dict(server='a',kind='reboot',command='reboot --force'))
  self.assertEqual(ssh.call_args.args[1]['op'],'reboot-info');self.assertTrue(p['summary']['warnings']);self.assertFalse(self.c.jobs)
 def test_wrong_confirmation_expired_plan_and_busy_are_rejected(self):
  p=self.planned()
  with self.assertRaises(ValueError):self.c.execute(p['id'],'another-host')
  self.c.busy.add('a')
  with self.assertRaises(ValueError):self.c.execute(p['id'],self.s['host'])
  self.c.busy.clear();self.c.plans[p['id']]['expiresAt']=0
  with self.assertRaises(ValueError):self.c.execute(p['id'],self.s['host'])
 def test_double_click_cannot_send_twice(self):
  j,p=self.job()
  with self.assertRaises(ValueError):self.c.execute(p['id'],self.s['host'])
  with self.assertRaises(ValueError):self.c.backup_job('a','lucx')
  self.assertNotIn('binding',self.c.snapshot()['jobs'][0])
 def test_same_boot_ssh_does_not_mean_success(self):
  j,_=self.job(time.time()-1)
  with patch.object(self.c,'ssh',return_value=self.before):self.c.reboots.monitor(j['id'])
  self.assertEqual(j['state'],'needs_review');self.assertIn('a',self.c.busy)
 def test_new_boot_and_restored_services_finish(self):
  j,_=self.job();after=dict(self.before,bootId='after')
  with patch.object(self.c,'ssh',return_value=after):self.c.reboots.monitor(j['id'])
  self.assertEqual(j['state'],'succeeded');self.assertNotIn('a',self.c.busy)
 def test_new_boot_missing_vpn_is_not_success(self):
  j,_=self.job(time.time()-1);after=dict(self.before,bootId='after',containers={})
  with patch.object(self.c,'ssh',return_value=after):self.c.reboots.monitor(j['id'])
  self.assertEqual(j['state'],'needs_review');self.assertIn('Docker: awg',j['missing'])
 def test_lost_ack_observes_without_resubmission(self):
  j,p=self.job();after=dict(self.before,bootId='after')
  with patch.object(self.c,'ssh',side_effect=[self.before,TimeoutError(),after]) as ssh:self.c.reboots.submit(j['id'],p)
  self.assertEqual(j['state'],'succeeded');self.assertEqual([a.args[1]['op'] for a in ssh.call_args_list],['reboot-info','reboot-schedule','reboot-status'])
 def test_changed_state_never_sends_reboot(self):
  j,p=self.job()
  with patch.object(self.c,'ssh',return_value=dict(self.before,bootId='other')) as ssh:self.c.reboots.submit(j['id'],p)
  self.assertEqual(j['state'],'failed');self.assertEqual(ssh.call_count,1)
 def test_restart_only_resumes_observation(self):
  j,_=self.job();j.update(remoteSubmitted=True,state='waiting_reboot');self.c.save_jobs()
  with patch('control.threading.Thread'):restored=Control(self.root,lambda:[self.s],self.root)
  with patch.object(restored,'ssh',return_value=dict(self.before,bootId='after')) as ssh:restored.resume(j['id'])
  self.assertEqual(ssh.call_args.args[1]['op'],'reboot-status');self.assertEqual(restored.jobs[j['id']]['state'],'succeeded')
 def test_remote_one_shot_is_deduplicated_and_graceful(self):
  r=RemoteReboot(self.root/'state');req=dict(job='a'*32,expiresAt=time.time()+100,revision=reboot_digest(self.before),services=[])
  with patch.object(r,'info',return_value=self.before),patch('reboot_remote.shutil.which',return_value='/usr/bin/systemctl'),patch('reboot_remote.subprocess.run',return_value=Mock(returncode=0)) as run:
   self.assertTrue(r.schedule(req)['accepted'])
   with self.assertRaisesRegex(ValueError,'уже отправлялась'):r.schedule(req)
  self.assertEqual(run.call_count,1);self.assertNotIn('--force',run.call_args.args[0]);self.assertEqual(run.call_args.args[0][-1],'reboot')
 def test_apt_blocks_reboot(self):
  r=RemoteReboot(self.root/'state');busy=dict(self.before,aptBusy=['dpkg'])
  with patch.object(r,'info',return_value=busy),patch('reboot_remote.subprocess.run') as run:
   with self.assertRaisesRegex(ValueError,'APT/dpkg'):r.schedule(dict(job='a'*32,expiresAt=time.time()+100,revision=reboot_digest(busy)))
   run.assert_not_called()

class OsUpdateTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=pathlib.Path(self.tmp.name)
  self.state=patch.object(remote,'STATE',self.path);self.state.start();self.addCleanup(self.state.stop)
  self.version=patch.object(remote,'versions',return_value={});self.version.start();self.addCleanup(self.version.stop)
 def test_missing_fresh_index_blocks_upgrade_plan(self):
  with patch('control_remote.os.geteuid',return_value=0),patch('control_remote.shutil.which',return_value='/usr/bin/apt-get'),patch.object(remote,'run') as run:
   with self.assertRaisesRegex(ValueError,'обновите список'):remote.update_plan(dict(component='os'))
   run.assert_not_called()
 def test_refresh_failure_cannot_mark_cache_ready(self):
  with patch.object(remote,'run',side_effect=RuntimeError('repo failed')):
   with self.assertRaises(RuntimeError):remote.apply_update(dict(component='os-index'))
  self.assertFalse((self.path/'apt-refreshed.json').exists())
 def test_refresh_only_updates_index(self):
  with patch.object(remote,'run',return_value='') as run:remote.apply_update(dict(component='os-index'))
  self.assertEqual(run.call_args.args[0],['apt-get','-o','APT::Update::Error-Mode=any','update'])
  self.assertTrue((self.path/'apt-refreshed.json').exists())
 def test_plan_uses_fresh_index_and_rejects_removals(self):
  (self.path/'apt-refreshed.json').write_text(json.dumps({'finishedAt':time.time()}))
  with patch('control_remote.os.geteuid',return_value=0),patch('control_remote.shutil.which',return_value='/usr/bin/apt-get'),patch.object(remote,'run',return_value='Remv nginx [1.0]'):
   with self.assertRaisesRegex(ValueError,'удаление'):remote.update_plan(dict(component='os'))
 def test_real_upgrade_command_preserves_configs_and_does_not_reboot(self):
  with patch('control_remote.subprocess.run',return_value=Mock(returncode=0,stdout='',stderr='')) as run:remote.apply_update(dict(component='os'))
  args=run.call_args.args[0];self.assertIn('--with-new-pkgs',args);self.assertIn('--no-remove',args);self.assertIn('Dpkg::Options::=--force-confold',args);self.assertEqual(args[-1],'upgrade');self.assertNotIn('reboot',args)

if __name__=='__main__':unittest.main()
