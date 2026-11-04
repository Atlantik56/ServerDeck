import http.client,json,pathlib,subprocess,tempfile,threading,unittest
from http.server import ThreadingHTTPServer
from unittest.mock import Mock,patch
import account_helper as helper
from account import Account,AccountError
import server,public_access

OLD='$2b$12$'+'A'*53
NEW='$2b$12$'+'B'*53
DATA={'username':'admin','currentPassword':'old-password-123','newPassword':'new-password-456','confirmPassword':'new-password-456'}

class HelperTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name);self.path=self.root/'accounts';self.lock=self.root/'lock';self.config=self.root/'Caddyfile'
        self.original='admin '+OLD+'\nsecond '+OLD+'\n';self.path.write_text(self.original)
        self.hasher=patch.object(helper,'hash_password',return_value=NEW);self.hasher.start()
        self.verify=patch.object(helper,'verify',return_value=True);self.verify.start()
    def tearDown(self):self.verify.stop();self.hasher.stop();self.temp.cleanup()
    def change(self,data=DATA):return helper.change(data,self.path,self.config,self.lock)
    def test_success_updates_only_authenticated_user_and_never_returns_password(self):
        with patch.object(helper,'caddy',return_value=True) as c:
            result=self.change()
        self.assertTrue(result['ok']);self.assertNotIn(DATA['newPassword'],json.dumps(result))
        self.assertEqual(self.path.read_text(),'admin '+NEW+'\nsecond '+OLD+'\n')
        self.assertEqual(self.path.stat().st_mode&0o777,0o640)
        self.assertEqual([x.args[0] for x in c.call_args_list],['validate','reload'])
    def test_wrong_current_never_writes_or_reloads(self):
        with patch.object(helper,'verify',return_value=False),patch.object(helper,'caddy') as c:
            with self.assertRaises(helper.ChangeError) as e:self.change()
        self.assertEqual(e.exception.code,'current');c.assert_not_called();self.assertEqual(self.path.read_text(),self.original)
    def test_validation_and_reload_failures_restore_original(self):
        for results,code in [([False],'validate'),([True,False,True],'reload'),([True,False,False],'uncertain')]:
            with patch.object(helper,'caddy',side_effect=results):
                with self.assertRaises(helper.ChangeError) as e:self.change()
            self.assertEqual(e.exception.code,code);self.assertEqual(self.path.read_text(),self.original)
    def test_password_policy_confirmation_and_identity(self):
        bad=[dict(DATA,newPassword='short'),dict(DATA,confirmPassword='different'),dict(DATA,newPassword='я'*37,confirmPassword='я'*37),dict(DATA,newPassword='bad\npassword123',confirmPassword='bad\npassword123'),dict(DATA,username='admin\nother'),dict(DATA,currentPassword=DATA['newPassword'])]
        for value in bad:
            with self.assertRaises(helper.ChangeError):self.change(value)
        self.assertEqual(self.path.read_text(),self.original)
    def test_unknown_or_duplicate_user_does_not_write(self):
        for content in ['second '+OLD+'\n','admin '+OLD+'\nadmin '+OLD+'\n']:
            self.path.write_text(content)
            with self.assertRaises(helper.ChangeError):self.change()
            self.assertEqual(self.path.read_text(),content)

class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name);(self.root/'key').write_text('test')
        with patch.dict('os.environ',{'DECK_ACCOUNT_SSH_HOST':'192.0.2.1','DECK_ACCOUNT_SSH_KEY':'key'}):self.a=Account(self.root)
    def tearDown(self):self.temp.cleanup()
    def test_fixed_ssh_helper_identity_from_gateway_and_secrets_only_on_stdin(self):
        p=subprocess.CompletedProcess([],0,json.dumps({'ok':True}).encode(),b'')
        with patch('account.subprocess.run',return_value=p) as run:
            result=self.a.change('admin',dict(DATA,username='attacker'))
        args=run.call_args.args[0];request=json.loads(run.call_args.kwargs['input'])
        self.assertEqual(request['username'],'admin');self.assertNotIn(DATA['currentPassword'],str(args));self.assertNotIn(DATA['newPassword'],str(result))
        self.assertIn('StrictHostKeyChecking=yes',args);self.assertEqual(args[-1],'/usr/bin/python3 -I /usr/local/lib/server-deck/account_helper.py')
    def test_failed_attempts_are_rate_limited_and_not_retried(self):
        p=subprocess.CompletedProcess([],0,b'{"ok":false,"code":"current"}',b'')
        with patch('account.subprocess.run',return_value=p) as run:
            for _ in range(5):
                with self.assertRaises(AccountError):self.a.change('admin',DATA)
            with self.assertRaises(AccountError) as e:self.a.change('admin',DATA)
        self.assertEqual(e.exception.status,429);self.assertEqual(run.call_count,5)
    def test_ambiguous_failure_does_not_leak_stderr_or_retry(self):
        with patch('account.subprocess.run',side_effect=subprocess.TimeoutExpired(['ssh'],65,stderr=b'sensitive')) as run:
            with self.assertRaises(AccountError) as e:self.a.change('admin',DATA)
        self.assertNotIn('sensitive',str(e.exception));self.assertEqual(run.call_count,1)

class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.origin='https://deck.example';self.manager=Mock();self.manager.change.return_value={'ok':True}
        self.env=patch.multiple(public_access,ORIGIN=self.origin,HOST='deck.example',GATEWAY='gateway');self.env.start()
        self.obj=patch.object(server,'account',return_value=self.manager);self.obj.start();self.audit=patch.object(server,'event');self.audit.start()
        self.original_token=server.TOKEN
        self.httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler);threading.Thread(target=self.httpd.serve_forever,daemon=True).start()
    def tearDown(self):self.httpd.shutdown();self.httpd.server_close();self.audit.stop();self.obj.stop();self.env.stop();server.TOKEN=self.original_token
    def request(self,**overrides):
        headers={'Host':'deck.example','Origin':self.origin,'X-Deck-Gateway':'gateway','X-Deck-Token':server.TOKEN,'X-Deck-User':'admin','Content-Type':'application/json'};headers.update(overrides)
        c=http.client.HTTPConnection('127.0.0.1',self.httpd.server_port);c.request('POST','/api/account/password',json.dumps(DATA),headers);r=c.getresponse();body=r.read();c.close();return r.status,body
    def test_cross_origin_or_missing_auth_cannot_reach_helper(self):
        for value in [{'Origin':'https://evil.example'},{'X-Deck-Token':''},{'X-Deck-Gateway':''}]:self.assertEqual(self.request(**value)[0],403)
        self.manager.change.assert_not_called()
    def test_logout_revokes_native_sessions_without_rotating_other_pages_token(self):
        headers={'Host':'deck.example','Origin':self.origin,'X-Deck-Gateway':'gateway','X-Deck-Token':server.TOKEN,'X-Deck-User':'admin','Content-Type':'application/json'}
        with patch.object(server,'invalidate_account_sessions') as revoke:
            c=http.client.HTTPConnection('127.0.0.1',self.httpd.server_port)
            c.request('POST','/api/account/logout','{}',headers)
            r=c.getresponse();r.read();c.close()
            self.assertEqual(r.status,200);revoke.assert_called_once_with(rotate_token=False)
        self.assertEqual(server.TOKEN,self.original_token)
    def test_success_and_failure_are_returned_without_password(self):
        status,body=self.request();self.assertEqual(status,200);self.assertNotIn(DATA['newPassword'].encode(),body)
        self.assertNotEqual(server.TOKEN,self.original_token)
        self.manager.change.assert_called_once_with('admin',DATA)
        self.manager.change.side_effect=AccountError('current');self.assertEqual(self.request()[0],400)

if __name__=='__main__':unittest.main()
