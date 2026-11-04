import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch

import public_access
import server


class AlertRoutes(unittest.TestCase):
    def setUp(self):
        self.manager=Mock()
        self.manager.status.return_value={'configured':True,'enabled':False,'config':{},'chat':None}
        self.manager.configure.return_value={'ok':True}
        self.manager.start_pairing.return_value={'pairing':{'startUrl':'https://t.me/testbot?start=pair'}}
        self.manager.cancel_pairing.return_value={'pairing':None}
        self.manager.test.return_value={'ok':True,'queued':True}
        self.env=patch.multiple(public_access,ORIGIN='https://deck.example',HOST='deck.example',GATEWAY='gateway')
        self.env.start();self.obj=patch.object(server,'alerts_manager',return_value=self.manager);self.obj.start()
        self.httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        threading.Thread(target=self.httpd.serve_forever,daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown();self.httpd.server_close();self.obj.stop();self.env.stop()

    def request(self,path='/api/alerts',data=None,overrides=None):
        headers={'Host':'deck.example','Origin':'https://deck.example','X-Deck-Gateway':'gateway','X-Deck-Token':server.TOKEN,'Content-Type':'application/json'}
        headers.update(overrides or {})
        connection=http.client.HTTPConnection('127.0.0.1',self.httpd.server_port)
        connection.request('POST' if data is not None else 'GET',path,json.dumps(data) if data is not None else None,headers)
        response=connection.getresponse();body=response.read();code=response.status;connection.close();return code,json.loads(body)

    def test_status_is_protected_and_never_includes_configured_secret(self):
        self.assertEqual(self.request()[0],200)
        for headers in [{'X-Deck-Token':''},{'X-Deck-Gateway':''},{'Host':'evil.example'}]:
            self.assertEqual(self.request(overrides=headers)[0],403)
        self.assertEqual(self.manager.status.call_count,1)

    def test_write_routes_require_same_origin_and_csrf_and_dispatch_only_known_methods(self):
        for headers in [{'Origin':'https://evil.example'},{'X-Deck-Token':''},{'X-Deck-Gateway':''}]:
            self.assertEqual(self.request('/api/alerts/pair',{},headers)[0],403)
        self.manager.start_pairing.assert_not_called()
        for suffix,method in [('pair','start_pairing'),('cancel','cancel_pairing'),('test','test')]:
            self.assertEqual(self.request('/api/alerts/'+suffix,{})[0],200)
            getattr(self.manager,method).assert_called_once_with()
        self.assertEqual(self.request('/api/alerts/config',{'cpuThreshold':91})[0],200)
        self.manager.configure.assert_called_once_with({'cpuThreshold':91})
        self.assertEqual(self.request('/api/alerts/execute',{})[0],404)

    def test_validation_error_has_no_automatic_retry(self):
        self.manager.configure.side_effect=ValueError('Сначала подключите чат Telegram.')
        code,value=self.request('/api/alerts/config',{'enabled':True})
        self.assertEqual(code,400);self.assertIn('подключите чат',value['error'])
        self.manager.configure.assert_called_once()


if __name__=='__main__':unittest.main()
