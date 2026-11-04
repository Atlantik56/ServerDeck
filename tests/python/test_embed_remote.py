import json,pathlib,sqlite3,tempfile,unittest
from unittest.mock import patch
import embed_remote as remote
import control_remote as control

class Response:
    status=200
    def __init__(self,value):self.value=value
    def read(self,*args):return json.dumps(self.value).encode()
    def getheaders(self):return [('Set-Cookie','native=short-lived-session; HttpOnly')]

class CredentialTests(unittest.TestCase):
    def test_dedicated_credentials_precede_installer_and_missing_is_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            first=pathlib.Path(tmp)/'server-deck.env';second=pathlib.Path(tmp)/'install-result.env'
            second.write_text("XUI_USERNAME=old\nXUI_PASSWORD='old pass'\n")
            self.assertEqual(remote.panel_credentials([first,second])['XUI_PASSWORD'],'old pass')
            first.write_text("# integration\nXUI_USERNAME=dedicated\nXUI_PASSWORD='new pass'\n")
            self.assertEqual(remote.panel_credentials([first,second])['XUI_USERNAME'],'dedicated')
            first.unlink();second.unlink()
            with self.assertRaisesRegex(ValueError,'не настроены'):remote.panel_credentials([first,second])

    def login(self,two_factor=False,rejected=False):
        self.requests=[]
        class Connection:
            def __init__(inner,*args,**kwargs):pass
            def request(inner,method,path,body,headers):self.requests.append((method,path,json.loads(body) if body else None))
            def getresponse(inner):
                path=self.requests[-1][1]
                if path.endswith('/csrf-token'):return Response({'success':True,'obj':'csrf'})
                if path.endswith('/getTwoFactorEnable'):return Response({'success':True,'obj':two_factor})
                return Response({'success':not rejected})
            def close(inner):pass
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'db';db=sqlite3.connect(p);db.execute('create table settings(key,value)');db.execute('insert into settings values(?,?)',('webBasePath','/private/'));db.commit();db.close()
            connect=sqlite3.connect
            with patch.object(remote.sqlite3,'connect',side_effect=lambda *a,**k:connect(p)),patch.object(remote,'panel_credentials',return_value={'XUI_USERNAME':'dedicated','XUI_PASSWORD':'private-password','XUI_API_TOKEN':'private-token'}),patch.object(remote.http.client,'HTTPConnection',Connection):return remote.setup('lucx')

    def test_native_login_exports_only_session_not_password_or_api_token(self):
        value=self.login();self.assertEqual(value['cookies'],{'native':'short-lived-session'})
        self.assertEqual(self.requests[-1][2],{'username':'dedicated','password':'private-password'})
        self.assertNotIn('private-password',json.dumps(value));self.assertNotIn('private-token',json.dumps(value))

    def test_two_factor_is_not_bypassed_and_rejection_is_not_retried(self):
        with self.assertRaisesRegex(ValueError,'2FA'):self.login(two_factor=True)
        self.assertFalse(any(x[1].endswith('/login') for x in self.requests))
        with self.assertRaisesRegex(ValueError,'Повторных попыток'):self.login(rejected=True)
        self.assertEqual(sum(x[1].endswith('/login') for x in self.requests),1)

    def test_api_adapter_supports_dedicated_and_installer_fallback(self):
        for dedicated in (False,True):
            seen=[]
            class Connection:
                def __init__(self,*a,**k):pass
                def request(self,method,path,body,headers):seen.append(headers)
                def getresponse(self):return Response({'success':True,'obj':[]})
                def close(self):pass
            def exists(p):return p.name=='install-result.env' or (dedicated and p.name=='server-deck.env')
            def content(p):return 'XUI_API_TOKEN='+('dedicated-token' if p.name=='server-deck.env' else 'installer-token')
            with patch.object(control.pathlib.Path,'is_file',exists),patch.object(control.pathlib.Path,'read_text',content),patch.object(control,'db_settings',return_value={}),patch.object(control.http.client,'HTTPConnection',Connection):self.assertEqual(control.lucx('clients/list'),[])
            self.assertEqual(seen[0]['Authorization'],'Bearer '+('dedicated-token' if dedicated else 'installer-token'))

if __name__=='__main__':unittest.main()
