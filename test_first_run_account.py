"""One-time initial ownership and auth regression checks; no real credentials."""
import concurrent.futures, http.client, json, pathlib, subprocess, tempfile, threading, unittest
from unittest.mock import Mock, patch
import web_auth as auth
import account_helper
HASH='$2b$12$'+'A'*53
CLAIM='c'*43
PASSWORD='fixture-first-password'
GATEWAY='fixture-gateway-'+'x'*40
ORIGIN='https://192.0.2.10:34871'

class Fixture(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
  self.accounts=self.root/'accounts-dir'/'accounts';self.accounts.parent.mkdir(mode=0o700);self.accounts.write_text('');self.accounts.chmod(0o600)
  self.state=self.root/'state';self.state.mkdir(mode=0o700);self.now=1000000.;self.bootstrap=self.state/'bootstrap.json'
  self.bootstrap.write_text(json.dumps({'version':1,'tokenHash':auth.token_digest(CLAIM),'expiresAt':self.now+3600,'consumed':False}));self.bootstrap.chmod(0o600)
  self.hasher=Mock(return_value=HASH);self.store=self.make_store()
 def make_store(self):
  return auth.AuthStore(self.accounts,self.state,clock=lambda:self.now,verifier=lambda p,h:p==PASSWORD and h==HASH,hasher=self.hasher)
 def data(self,**extra):
  value={'code':CLAIM,'username':'chosen-user','password':PASSWORD,'confirmPassword':PASSWORD,'remember':True};value.update(extra);return value

class StoreTests(Fixture):
 def test_chooses_account_and_normal_remembered_session(self):
  self.assertEqual(self.store.setup_status(),{'required':True,'available':True})
  token,session=self.store.initialize(self.data());self.assertEqual(self.accounts.read_text(),'chosen-user '+HASH+'\n')
  self.assertEqual(self.accounts.stat().st_mode&0o777,0o600);self.assertEqual(session['expires']-session['created'],auth.REMEMBER_TTL)
  self.assertEqual(self.store.validate(token)['username'],'chosen-user');self.assertEqual(self.make_store().validate(token)['username'],'chosen-user')
  self.assertEqual(self.store.setup_status(),{'required':False,'available':False})
  for path in self.state.iterdir():
   for secret in (CLAIM,PASSWORD,token,HASH):self.assertNotIn(secret,path.read_text())
  self.hasher.assert_called_once_with(PASSWORD)
 def test_wrong_expired_codes_never_hash_or_write(self):
  with self.assertRaises(auth.SetupError) as e:self.store.initialize(self.data(code='d'*43))
  self.assertEqual(e.exception.status,401);self.now+=3601
  with self.assertRaises(auth.SetupError) as e:self.store.initialize(self.data())
  self.assertEqual(e.exception.status,410);self.assertFalse(self.store.setup_status()['available']);self.hasher.assert_not_called();self.assertEqual(self.accounts.read_text(),'')
 def test_existing_account_cannot_be_overwritten(self):
  self.accounts.write_text('owner '+HASH+'\n')
  with self.assertRaises(auth.SetupError) as e:self.store.initialize(self.data())
  self.assertEqual(e.exception.status,409);self.assertEqual(self.accounts.read_text(),'owner '+HASH+'\n');self.hasher.assert_not_called()
 def test_restart_and_deleted_accounts_do_not_reopen_setup(self):
  self.store.initialize(self.data());self.accounts.write_text('');restarted=self.make_store();self.assertFalse(restarted.setup_status()['available'])
  with self.assertRaises(auth.SetupError) as e:restarted.initialize(self.data(username='intruder'))
  self.assertEqual(e.exception.status,409);self.assertEqual(self.accounts.read_text(),'');self.assertEqual(self.hasher.call_count,1)
 def test_empty_unprovisioned_and_malformed_accounts_fail_closed(self):
  self.bootstrap.unlink()
  with self.assertRaises(auth.AuthError):self.make_store()
  self.accounts.write_text('bad format data')
  with self.assertRaises(auth.AuthError):self.make_store()
 def test_hash_failure_does_not_consume_claim(self):
  self.hasher.side_effect=auth.AuthError('Unavailable')
  with self.assertRaises(auth.AuthError):self.store.initialize(self.data())
  self.assertEqual(self.accounts.read_text(),'');self.assertTrue(self.store.setup_status()['available']);self.assertFalse(list(self.accounts.parent.glob('.first-account-*')))
 def test_commit_failure_is_durable_fail_closed(self):
  original=auth.os.replace
  def replace(src,dst):
   if pathlib.Path(dst)==self.accounts:raise OSError('fictional disk failure')
   return original(src,dst)
  with patch('web_auth.os.replace',side_effect=replace):
   with self.assertRaises(OSError):self.store.initialize(self.data())
  self.assertEqual(self.accounts.read_text(),'');self.assertFalse(self.make_store().setup_status()['available']);self.assertFalse(list(self.accounts.parent.glob('.first-account-*')))
 def test_concurrent_independent_stores_only_one_owner(self):
  other=self.make_store();entered=threading.Event();release=threading.Event()
  def hasher(p):entered.set();release.wait(3);return HASH
  self.store.hasher=hasher
  with concurrent.futures.ThreadPoolExecutor(2) as pool:
   first=pool.submit(self.store.initialize,self.data());self.assertTrue(entered.wait(1))
   try:
    with self.assertRaises(auth.SetupError) as e:other.initialize(self.data(username='second-user'))
    self.assertEqual(e.exception.status,409)
   finally:release.set()
   first.result(timeout=3)
  self.assertEqual(self.accounts.read_text(),'chosen-user '+HASH+'\n');self.assertEqual(len(self.store.sessions),1);self.assertEqual(len(other.sessions),0)
 def test_policy_and_unsafe_names(self):
  for extra in ({'username':'<script>'},{'username':'../../root'},{'password':'short'},{'password':'a'*73},{'password':'\x00'+PASSWORD},{'confirmPassword':'mismatch'},{'remember':'true'},{'extra':'command'}):
   with self.subTest(fields=list(extra)):
    with self.assertRaises(auth.SetupError):self.store.initialize(self.data(**extra))
  self.hasher.assert_not_called();self.assertEqual(self.accounts.read_text(),'')
 def test_malformed_or_symlink_bootstrap_fails_closed(self):
  for data in ({},{'version':1,'tokenHash':'bad','expiresAt':self.now+10,'consumed':False}):
   self.bootstrap.write_text(json.dumps(data))
   with self.assertRaises(auth.AuthError):self.make_store()
  self.bootstrap.unlink();self.bootstrap.symlink_to(self.accounts)
  with self.assertRaises(auth.AuthError):self.make_store()

class HTTPTests(Fixture):
 def setUp(self):
  super().setUp();self.httpd=auth.AuthServer(('127.0.0.1',0),self.store,ORIGIN,GATEWAY);self.thread=threading.Thread(target=self.httpd.serve_forever,kwargs={'poll_interval':.01},daemon=True);self.thread.start();self.addCleanup(self.close)
 def close(self):self.httpd.shutdown();self.httpd.server_close();self.thread.join(2)
 def request(self,method='GET',data=None,headers=None):
  values={'X-Deck-Auth':GATEWAY,'X-Deck-Client-IP':'192.0.2.1','Origin':ORIGIN,'Content-Type':'application/json','X-Deck-Request':'1'};values.update(headers or {})
  c=http.client.HTTPConnection('127.0.0.1',self.httpd.server_port,timeout=4);c.request(method,'/auth/setup',json.dumps(data) if data is not None else None,values);r=c.getresponse();result=(r.status,dict(r.getheaders()),json.loads(r.read()));c.close();return result
 def test_status_is_readonly_and_no_claim_disclosure(self):
  code,headers,body=self.request();self.assertEqual(code,200);self.assertEqual(body,{'required':True,'available':True});self.assertNotIn(CLAIM,json.dumps(body));self.assertNotIn('tokenHash',body);self.assertEqual(headers['Cache-Control'],'no-store');self.hasher.assert_not_called()
 def test_gateway_origin_and_csrf_gates(self):
  for headers in ({'X-Deck-Auth':''},{'Origin':'https://evil.example'},{'Origin':'https://192.0.2.10'},{'X-Deck-Request':''},{'Content-Type':'text/plain'}):self.assertEqual(self.request('POST',self.data(),headers)[0],403)
  self.hasher.assert_not_called();self.assertEqual(self.accounts.read_text(),'')
 def test_success_cookie_and_closed_repeat(self):
  code,headers,body=self.request('POST',self.data());self.assertEqual(code,200);self.assertEqual(body,{'ok':True,'username':'chosen-user'})
  for flag in ('Secure','HttpOnly','SameSite=Strict','Max-Age=2592000'):self.assertIn(flag,headers['Set-Cookie'])
  self.assertNotIn(PASSWORD,json.dumps(body));self.assertNotIn(CLAIM,json.dumps(body));self.assertEqual(self.request('POST',self.data(username='new-owner'))[0],409)
 def test_rate_limit_bounds_claim_attempts(self):
  for _ in range(8):self.assertEqual(self.request('POST',self.data(code='d'*43))[0],401)
  self.assertEqual(self.request('POST',self.data())[0],429);self.assertEqual(self.accounts.read_text(),'');self.hasher.assert_not_called()

class ConfigurationTests(unittest.TestCase):
 def test_hasher_subprocess_password_stdin_and_bounded(self):
  with patch('web_auth.subprocess.run',return_value=subprocess.CompletedProcess([],0,HASH.encode())) as run:self.assertEqual(auth.hash_password(PASSWORD),HASH)
  args=run.call_args.args[0];options=run.call_args.kwargs;self.assertNotIn(PASSWORD,str(args));self.assertEqual(json.loads(options['input']),{'password':PASSWORD});self.assertEqual(options['timeout'],8);self.assertEqual(options['stderr'],subprocess.DEVNULL)
 def test_valid_https_ip_port_and_rejected_userinfo_paths_ports(self):
  self.assertTrue(auth.valid_origin(ORIGIN));self.assertTrue(auth.valid_origin('https://deck.example'))
  for origin in ('http://deck.example','https://user@deck.example','https://deck.example/path','https://deck.example?x=1','https://deck.example#x','https://deck.example:70000'):self.assertFalse(auth.valid_origin(origin))
 def test_root_owned_fixed_account_path_selector(self):
  with tempfile.TemporaryDirectory() as directory:
   p=pathlib.Path(directory)/'selector';self.assertEqual(account_helper.configured_accounts(p),account_helper.ACCOUNTS);p.write_text('/etc/caddy/server-deck-accounts.d/accounts\n');p.chmod(0o600)
   with patch.object(pathlib.Path,'lstat',return_value=Mock(st_uid=0,st_mode=0o100600,st_size=55)):self.assertEqual(str(account_helper.configured_accounts(p)),'/etc/caddy/server-deck-accounts.d/accounts')
   p.write_text('/tmp/arbitrary-path')
   with patch.object(pathlib.Path,'lstat',return_value=Mock(st_uid=0,st_mode=0o100600,st_size=55)):
    with self.assertRaises(account_helper.ChangeError):account_helper.configured_accounts(p)

if __name__=='__main__':unittest.main()
