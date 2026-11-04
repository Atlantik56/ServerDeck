"""Control integration checks; all SSH and restart execution is replaced."""
import http.client
import json
import pathlib
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch

import public_access
import server
from control import Control


class ControlIntegrationTests(unittest.TestCase):
    def test_embedded_remote_contains_restart_worker_and_dispatch(self):
        source = (pathlib.Path(__file__).resolve().parents[2] / 'backend')
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name in ('control_remote.py', 'panel_tls.py', 'software_remote.py',
                         'reboot_remote.py', 'service_restart_remote.py'):
                (root / name).write_text((source / name).read_text())
            control = Control(root, lambda: [], root)
            compile(control.remote, '<embedded-adapter>', 'exec')
            self.assertNotIn('from service_restart_remote import RemoteServiceRestart', control.remote)
            namespace = {'__name__': 'test_adapter'}
            exec(compile(control.remote, '<embedded-adapter>', 'exec'), namespace)
            engine = Mock()
            namespace['RESTART'] = engine
            for op, method in [('targets', 'catalog'), ('info', 'info'), ('status', 'status')]:
                request = {'op': 'service-restart-' + op}
                namespace['dispatch'](request)
                getattr(engine, method).assert_called_once_with(request)
            request = {'op': 'service-restart-schedule'}
            namespace['dispatch'](request, 'fixed-source')
            engine.schedule.assert_called_once_with(request, 'fixed-source')
            self.assertIn("sys.argv[1]=='--service-restart-worker'", control.remote)

    def test_web_action_and_telegram_share_one_host_reservation(self):
        target = {'id': 'one', 'host': '192.0.2.1', 'name': 'One', 'port': 22,
                  'user': 'root', 'key': 'test-key', 'services': ['x-ui.service']}
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / 'control_remote.py').write_text('')
            control = Control(root, lambda: [target], root, lock=server.LOCK)
            self.assertIs(control.lock, server.LOCK)
            entered, release = threading.Event(), threading.Event()
            def fake_ssh(selected, request):
                self.assertEqual(request, {'action': 'restart', 'unit': 'x-ui.service'})
                entered.set()
                self.assertTrue(release.wait(5))
                return {'ok': True}
            with patch.multiple(public_access, ORIGIN='https://deck.example', HOST='deck.example', GATEWAY='gateway'), \
                 patch.object(server, 'control', return_value=control), \
                 patch.object(server, 'find', return_value=target), \
                 patch.object(server, 'ssh', side_effect=fake_ssh), \
                 patch.object(server, 'event'):
                httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
                thread = threading.Thread(target=httpd.serve_forever, daemon=True)
                thread.start()
                response = []
                def request():
                    client = http.client.HTTPConnection('127.0.0.1', httpd.server_port, timeout=8)
                    headers = {'Host': 'deck.example', 'Origin': 'https://deck.example',
                               'X-Deck-Gateway': 'gateway', 'X-Deck-Token': server.TOKEN,
                               'Content-Type': 'application/json'}
                    client.request('POST', '/api/action', json.dumps({'server': 'one',
                                   'unit': 'x-ui.service', 'action': 'restart'}), headers)
                    result = client.getresponse()
                    response.append((result.status, json.loads(result.read())))
                    client.close()
                worker = threading.Thread(target=request)
                worker.start()
                try:
                    self.assertTrue(entered.wait(5))
                    self.assertIn('one', control.busy)
                    with patch.object(control, 'ssh') as remote:
                        with self.assertRaises(ValueError):
                            control.service_restarts.plan(target, 'x-ui.service')
                        remote.assert_not_called()
                finally:
                    release.set()
                    worker.join(8)
                    httpd.shutdown()
                    httpd.server_close()
                self.assertEqual(response, [(200, {'ok': True})])
                self.assertNotIn('one', control.busy)
                self.assertNotIn(('one', 'x-ui.service'), server.BUSY)


if __name__ == '__main__':
    unittest.main()
