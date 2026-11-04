import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import Mock,patch
import public_access
import server


class SecurityRoutes(unittest.TestCase):
    def setUp(self):
        self.store=Mock();self.store.report.return_value={'servers':[],'hours':24}
        self.manager=Mock();self.manager.status.return_value={'enabled':True,'chat':{'id':'123'},'config':{'security':True},'lastError':''}
        self.manager.configure.return_value={}
        self.env=patch.multiple(public_access,ORIGIN='https://deck.example',HOST='deck.example',GATEWAY='gateway');self.env.start()
        self.s=patch.object(server,'security_store',return_value=self.store);self.s.start()
        self.a=patch.object(server,'alerts_manager',return_value=self.manager);self.a.start()
        self.registry=patch.object(server,'servers',return_value=[]);self.registry.start()
        self.httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        threading.Thread(target=self.httpd.serve_forever,daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown();self.httpd.server_close();self.registry.stop();self.a.stop();self.s.stop();self.env.stop()

    def request(self,path='/api/security?hours=24',data=None,extra=None):
        headers={'Host':'deck.example','Origin':'https://deck.example','X-Deck-Gateway':'gateway','X-Deck-Token':server.TOKEN,'Content-Type':'application/json'};headers.update(extra or {})
        c=http.client.HTTPConnection('127.0.0.1',self.httpd.server_port);c.request('POST' if data is not None else 'GET',path,json.dumps(data) if data is not None else None,headers);r=c.getresponse();raw=r.read();code=r.status;c.close();return code,json.loads(raw)

    def test_read_requires_gateway_host_and_session_token(self):
        for extra in [{'Host':'other.example'},{'X-Deck-Gateway':''},{'X-Deck-Token':''}]:self.assertEqual(self.request(extra=extra)[0],403)
        self.store.report.assert_not_called()
        code,data=self.request();self.assertEqual(code,200);self.assertTrue(data['config']['security'])
        self.assertEqual(data['alertStatus']['connected'],True);self.assertNotIn('chat',data['alertStatus'])

    def test_period_allowlist_and_read_only_report(self):
        for hours in ['1','24','168']:
            self.assertEqual(self.request('/api/security?hours='+hours)[0],200);self.store.report.assert_called_with([],int(hours))
        self.assertEqual(self.request('/api/security?hours=100000')[0],400)
        self.manager.configure.assert_not_called()

    def test_write_same_origin_and_strict_security_fields(self):
        for extra in [{'Origin':'https://other.example'},{'X-Deck-Gateway':''},{'X-Deck-Token':''}]:self.assertEqual(self.request('/api/security/config',{'security':False},extra)[0],403)
        for body in [{'enabled':False},{'cpuThreshold':99},{'security':False,'services':False},{}]:self.assertEqual(self.request('/api/security/config',body)[0],400)
        self.manager.configure.assert_not_called()
        self.assertEqual(self.request('/api/security/config',{'security':False})[0],200)
        self.manager.configure.assert_called_once_with({'security':False})

    def test_storage_failure_is_not_a_healthy_empty_response(self):
        self.store.report.side_effect=ValueError('Хранилище недоступно');self.assertEqual(self.request()[0],503)

    def test_bot_menu_publication_is_explicit_and_same_origin_only(self):
        self.manager.publish_menu.return_value={'ok':True,'botMenuEnabled':True}
        self.assertEqual(self.request('/api/alerts/menu',{},extra={'Origin':'https://other.example'})[0],403)
        self.manager.publish_menu.assert_not_called()
        self.assertEqual(self.request('/api/alerts/menu',{})[0],200)
        self.manager.publish_menu.assert_called_once_with()

    def test_security_status_fields_and_menu_do_not_disappear(self):
        self.manager.status.return_value.update({'security':{'lastError':'delivery pending'},'menu':{'enabled':True,'publishedAt':1234}})
        code,data=self.request();self.assertEqual(code,200)
        self.assertEqual(data['alertStatus']['security']['lastError'],'delivery pending')
        self.assertTrue(data['alertStatus']['botMenuEnabled'])


if __name__=='__main__':unittest.main()
