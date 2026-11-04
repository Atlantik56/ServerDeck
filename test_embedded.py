import base64,hashlib,http.client,json,pathlib,socket,threading,time,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import Mock
from embedded import EmbeddedManager,Bridge,mutation,valid_target

class Upstream(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def do_GET(self):
        self.server.seen.append((self.command,self.path,self.headers.get('Cookie')))
        if self.headers.get('Upgrade','').lower()=='websocket':
            key=self.headers['Sec-WebSocket-Key'];accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade');self.send_header('Sec-WebSocket-Accept',accept);self.end_headers();self.connection.sendall(b'\x81\x02OK');self.close_connection=True;return
        self.answer()
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length','0')));self.server.seen.append((self.command,self.path,self.headers.get('Cookie')));self.answer()
    def answer(self):
        body=b'{"ok":true,"data":{"theme":"light","colors":{},"configured":false}}' if self.path.endswith('/api/theme') else b'{"success":true,"authenticated":true}'
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.send_header('Set-Cookie','native=server-secret; HttpOnly');self.send_header('X-Frame-Options','DENY');self.send_header('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'");self.end_headers();self.wfile.write(body)

class EmbedTests(unittest.TestCase):
    def setUp(self):
        self.up=ThreadingHTTPServer(('127.0.0.1',0),Upstream);self.up.daemon_threads=True;self.up.seen=[]
        threading.Thread(target=self.up.serve_forever,daemon=True).start()
        self.c=SimpleNamespace(lock=threading.RLock(),busy=set(),clients_cache={},create_backup=Mock())
        self.m=EmbeddedManager(pathlib.Path(__file__).parent,lambda:self.c,None,8765)
        meta={'base':'/private/','entry':'/private/panel/','port':1234,'scheme':'http','cookies':{'native':'server-secret'},'expiresAt':time.time()+3600}
        self.b=Bridge(self.m,{'id':'s','host':'192.0.2.1'},'lucx',meta,self.up.server_port)
    def tearDown(self):self.b.close();self.up.shutdown();self.up.server_close()
    def call(self,path,method='GET',body=None,origin=None,auth=True):
        c=http.client.HTTPConnection('127.0.0.1',self.b.httpd.server_port,timeout=5);headers={}
        if auth:headers['Cookie']=self.b.cookie_name+'='+self.b.session
        if origin:headers['Origin']=origin
        c.request(method,path,body,headers);r=c.getresponse();result=r.status,dict(r.getheaders()),r.read();c.close();return result
    def test_bootstrap_requires_parent_origin_and_one_time_grant(self):
        g=self.b.new_grant()
        self.assertEqual(self.call('/_deck/bootstrap','POST','grant='+g,'http://evil.invalid',False)[0],403)
        status,headers,_=self.call('/_deck/bootstrap','POST','grant='+g,self.m.parent,False)
        self.assertEqual(status,303);self.assertIn('HttpOnly',headers['Set-Cookie']);self.assertNotIn('server-secret',headers['Set-Cookie'])
        self.assertEqual(self.call('/_deck/bootstrap','POST','grant='+g,self.m.parent,False)[0],403)
    def test_no_anonymous_access_no_native_cookie_exposure(self):
        self.assertEqual(self.call('/private/panel/',auth=False)[0],403)
        status,headers,body=self.call('/private/panel/')
        self.assertEqual(status,200);self.assertNotIn('Set-Cookie',headers);self.assertNotIn('X-Frame-Options',headers)
        self.assertIn('frame-ancestors http://127.0.0.1:8765',headers['Content-Security-Policy'])
        self.assertEqual(self.up.seen[-1][2],'native=server-secret');self.c.create_backup.assert_not_called()
    def test_revoked_manager_rejects_old_cookies_and_unused_grants(self):
        grant=self.b.new_grant();self.m.revoked=True
        self.assertEqual(self.call('/private/panel/')[0],403)
        self.assertEqual(self.call('/_deck/bootstrap','POST','grant='+grant,self.m.parent,False)[0],403)
        with self.assertRaises(ValueError):self.b.new_grant()
        self.assertFalse(self.up.seen)
    def test_webkit_opaque_form_still_requires_one_use_grant_and_fetch_metadata(self):
        g=self.b.new_grant();c=http.client.HTTPConnection('127.0.0.1',self.b.httpd.server_port,timeout=5)
        c.request('POST','/_deck/bootstrap','grant='+g,{'Origin':'null','Sec-Fetch-Site':'cross-site','Sec-Fetch-Dest':'iframe'});r=c.getresponse();self.assertEqual(r.status,403);r.read()
        c.request('POST','/_deck/bootstrap','grant='+g,{'Origin':'null','Sec-Fetch-Site':'same-site','Sec-Fetch-Dest':'iframe'});r=c.getresponse();self.assertEqual(r.status,303);r.read();c.close()
    def test_cross_origin_write_blocked_and_real_write_backed_up(self):
        p='/private/panel/api/clients/update/alice'
        self.assertEqual(self.call(p,'POST','{}','http://evil.invalid')[0],403);self.assertFalse(self.up.seen)
        self.assertEqual(self.call(p,'POST','{}',self.b.origin)[0],200);self.c.create_backup.assert_called_once();self.assertFalse(self.c.busy)
    def test_update_cannot_bypass_central_plan(self):
        self.assertEqual(self.call('/private/panel/api/server/updatePanel','POST','{}',self.b.origin)[0],502)
        self.assertFalse(self.up.seen);self.c.create_backup.assert_not_called()
    def test_theme_is_local_and_opening_never_writes_remote_theme(self):
        self.b.panel='mtproxyl'
        status,_,body=self.call('/private/api/theme');self.assertEqual(status,200);self.assertTrue(json.loads(body)['data']['configured']);self.assertEqual(json.loads(body)['data']['theme'],'dark')
        status,_,_=self.call('/private/api/panel/settings/theme','PUT',json.dumps({'theme':'light','colors':{}}),self.b.origin)
        self.assertEqual(status,200);self.assertFalse(any(x[0]=='PUT' for x in self.up.seen));self.c.create_backup.assert_not_called()
        _,_,body=self.call('/private/api/theme');self.assertEqual(json.loads(body)['data']['theme'],'light')
    def test_websocket_relays_authenticated_handshake_and_frames(self):
        sock=socket.create_connection(('127.0.0.1',self.b.httpd.server_port),timeout=5);key=base64.b64encode(b'1234567890123456').decode()
        payload='GET /private/ws HTTP/1.1\r\nHost: 127.0.0.1:'+str(self.b.httpd.server_port)+'\r\nOrigin: '+self.b.origin+'\r\nCookie: '+self.b.cookie_name+'='+self.b.session+'\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: '+key+'\r\nSec-WebSocket-Version: 13\r\n\r\n';sock.sendall(payload.encode());data=b''
        while b'\r\n\r\n' not in data:data+=sock.recv(1)
        self.assertIn(b'101',data);self.assertNotIn(b'server-secret',data)
        frame=b''
        while len(frame)<4:frame+=sock.recv(4-len(frame))
        self.assertEqual(frame,b'\x81\x02OK');sock.close();self.assertEqual(self.up.seen[-1][2],'native=server-secret')
    def test_path_traversal_and_mutation_classification(self):
        for p in ['//evil.invalid/','/private/%2e%2e/secret','/other/panel/','/private/%0d%0aInjected']:
            with self.assertRaises(ValueError):valid_target(p,'/private/')
        self.assertFalse(mutation('lucx','/private/','/private/panel/api/clients/onlines','POST'))
        self.assertFalse(mutation('lucx','/private/','/private/panel/api/setting/all','POST'))
        self.assertFalse(mutation('lucx','/private/','/private/panel/setting/all','POST'))
        with self.assertRaises(ValueError):mutation('lucx','/private/','/private/panel/server/updatePanel','POST')
        self.assertFalse(mutation('mtproxyl','/','/api/geoip/lookup','POST'))
        with self.assertRaises(ValueError):mutation('mtproxyl','/','/api/mtproxyl/engine/update','POST')

if __name__=='__main__':unittest.main()
