import json,os,pathlib,tempfile,unittest
from unittest.mock import patch,Mock
from account import Account

class AccountPort(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.keys=pathlib.Path(self.tmp.name);(self.keys/'helper').touch()
 def account(self,port):
  with patch.dict(os.environ,{'DECK_ACCOUNT_SSH_HOST':'127.0.0.1','DECK_ACCOUNT_SSH_KEY':'helper','DECK_ACCOUNT_SSH_PORT':str(port)}):return Account(self.keys)
 def test_default_port_remains_22(self):
  with patch.dict(os.environ,{},clear=True):self.assertEqual(Account(self.keys).port,22)
 def test_invalid_port_disables_helper(self):
  for port in ('invalid','22;exit',0,65536,-1):self.assertFalse(self.account(port).available())
 def test_custom_port_used_only_as_numeric_argv(self):
  a=self.account(2222);self.assertTrue(a.available())
  with patch('account.subprocess.run',return_value=Mock(returncode=0,stdout=json.dumps({'ok':True}))) as run:
   result=a.change('admin',{'currentPassword':'Old-account-password','newPassword':'New-account-password','confirmPassword':'New-account-password'})
  self.assertTrue(result['ok']);cmd=run.call_args.args[0];self.assertEqual(cmd[cmd.index('-p')+1],'2222');self.assertNotIn('New-account-password',' '.join(cmd))

if __name__=='__main__':unittest.main()
