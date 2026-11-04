import http.client, threading, unittest, pathlib, time
from unittest.mock import patch
from http.server import ThreadingHTTPServer
import public_access as p
import server
from embedded import EmbeddedManager, Bridge

class PublicTests(unittest.TestCase):
    def setUp(self):
        self.origin='https://deck.example.test'
        self.host=self.origin[8:];self.secret='s'*48
        self.settings=patch.multiple(p, ORIGIN=self.origin, HOST=self.host, GATEWAY=self.secret)
        self.settings.start()
        self.httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        threading.Thread(target=self.httpd.serve_forever,daemon=True).start()
    def tearDown(self):
        self.httpd.shutdown();self.httpd.server_close();self.settings.stop()
    def request(self, method='GET', path='/', **headers):
        c=http.client.HTTPConnection('127.0.0.1',self.httpd.server_port)
        c.request(method,path,body='{}' if method=='POST' else None,headers=headers)
        r=c.getresponse();body=r.read();status=r.status;c.close();return status,body
    def test_backend_cannot_be_opened_without_gateway(self):
        self.assertEqual(403,self.request(Host=self.host)[0])
        self.assertEqual(403,self.request(Host=self.host,**{'X-Deck-Gateway':'wrong'})[0])
        self.assertEqual(200,self.request(Host=self.host,**{'X-Deck-Gateway':self.secret})[0])
    def test_host_and_origin_are_exact(self):
        good={'Host':self.host,'X-Deck-Gateway':self.secret,'X-Deck-Token':server.TOKEN}
        self.assertEqual(403,self.request(**dict(good,Host='evil.example'))[0])
        self.assertEqual(403,self.request('POST','/api/servers',**dict(good,Origin='https://evil.example'))[0])
        self.assertEqual(403,self.request('POST','/api/servers',**dict(good,Origin='http://127.0.0.1:8765'))[0])
    def test_certificate_permission_does_not_allow_arbitrary_names(self):
        servers=[{'id':'server-10'}]
        self.assertTrue(p.allowed_domain(self.host,servers))
        self.assertTrue(p.allowed_domain('server-10-lucx.'+self.host,servers))
        for host in ['evil.example','evil.'+self.host,'server-10-lucx.'+self.host+'.evil','server-10-lucx.'+self.host+':443']:
            self.assertFalse(p.allowed_domain(host,servers))
    def test_csp_and_gateway_credentials_are_not_exposed(self):
        self.assertNotIn('http://',p.policy())
        self.assertIn('https://*.'+self.host,p.policy())
        status,body=self.request(Host=self.host,**{'X-Deck-Gateway':self.secret})
        self.assertNotIn(self.secret.encode(),body)
    def test_bridge_cookie_is_secure_and_gateway_secret_never_reaches_vps(self):
        manager=EmbeddedManager(pathlib.Path(__file__).parent,lambda:None,None,8765)
        meta={'base':'/','entry':'/panel/','port':2053,'scheme':'http','cookies':{},'expiresAt':time.time()+300}
        b=Bridge(manager,{'id':'server-10','host':'192.0.2.1'},'lucx',meta,9)
        try:
            self.assertEqual(b.origin,'https://server-10-lucx.'+self.host)
            upstream=b.upstream_headers({'X-Deck-Gateway':self.secret,'X-Deck-Token':'browser-token','Authorization':'Basic credentials'})
            self.assertNotIn(self.secret,str(upstream));self.assertNotIn('browser-token',str(upstream));self.assertNotIn('Basic credentials',str(upstream))
            c=http.client.HTTPConnection('127.0.0.1',b.httpd.server_port)
            grant=b.new_grant()
            c.request('POST','/_deck/bootstrap','grant='+grant,{'X-Deck-Gateway':self.secret,'Origin':self.origin})
            r=c.getresponse();r.read();self.assertEqual(303,r.status);self.assertIn('; Secure',r.getheader('Set-Cookie'));c.close()
        finally:b.close()

if __name__=='__main__':unittest.main()
