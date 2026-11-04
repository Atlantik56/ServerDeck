"""Privilege and side-effect boundaries for the new administration routes."""
import http.client,json,threading,unittest,tempfile,pathlib
from unittest.mock import Mock,patch
from http.server import ThreadingHTTPServer
import public_access,server

class Routes(unittest.TestCase):
 def setUp(self):
  self.managers={name:Mock() for name in ('outage_diagnostics','fail2ban_manager','control','deployment_settings')}
  for name,m in self.managers.items():
   for method in ('snapshot','plan','apply','review','add_component','remove_component','bind_component','refresh'):
    getattr(m,method).return_value={'ok':True}
   p=patch.object(server,name,return_value=m);p.start();self.addCleanup(p.stop)
  for name,value in [('ORIGIN','https://deck.example'),('HOST','deck.example'),('GATEWAY','gateway')]:
   p=patch.object(public_access,name,value);p.start();self.addCleanup(p.stop)
  self.httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
  self.thread=threading.Thread(target=self.httpd.serve_forever,kwargs={'poll_interval':.01},daemon=True);self.thread.start();self.addCleanup(self.close)
 def close(self):self.httpd.shutdown();self.httpd.server_close();self.thread.join(2)
 def request(self,path,method='GET',data=None,extra=None):
  headers={'Host':'deck.example','Origin':'https://deck.example','X-Deck-Gateway':'gateway','X-Deck-Token':server.TOKEN,'Content-Type':'application/json'}
  headers.update(extra or {})
  for key in list(headers):
   if headers[key] is None:del headers[key]
  c=http.client.HTTPConnection('127.0.0.1',self.httpd.server_port,timeout=4)
  try:
   c.request(method,path,json.dumps(data) if method=='POST' else None,headers);r=c.getresponse();return r.status,json.loads(r.read())
  finally:c.close()
 def test_new_gets_require_all_access_guards(self):
  for path in ('/api/outage-diagnostics','/api/fail2ban?server=example','/api/deployment'):
   for headers in ({'Host':'other.example'},{'X-Deck-Gateway':None},{'X-Deck-Token':None}):
    self.assertEqual(self.request(path,extra=headers)[0],403)
  for m in self.managers.values():self.assertEqual(m.mock_calls,[])
 def test_read_only_outage_snapshot_never_starts_a_probe(self):
  self.assertEqual(self.request('/api/outage-diagnostics')[0],200)
  self.managers['outage_diagnostics'].snapshot.assert_called_once_with()
  self.assertEqual(self.managers['outage_diagnostics'].mock_calls,[unittest.mock.call.snapshot()])
  self.assertEqual(self.managers['control'].mock_calls,[])
 def test_fail2ban_get_has_single_explicit_host(self):
  self.assertEqual(self.request('/api/fail2ban?server=example')[0],200)
  self.managers['fail2ban_manager'].snapshot.assert_called_once_with('example')
  self.managers['fail2ban_manager'].apply.assert_not_called()
 def test_mutations_require_origin_token_gateway_and_host(self):
  paths=['/api/fail2ban/'+a for a in ('plan','apply','review')]+['/api/control/components/'+a for a in ('add','remove','bind')]+['/api/deployment/'+a for a in ('plan','apply','check')]
  for path in paths:
   for headers in ({'Origin':None},{'Origin':'https://other.example'},{'X-Deck-Token':None},{'X-Deck-Gateway':None},{'Host':'other.example'}):
    self.assertEqual(self.request(path,'POST',{},headers)[0],403)
  for m in self.managers.values():self.assertEqual(m.mock_calls,[])
 def test_components_do_not_require_or_mutate_server_registry(self):
  with patch.object(server,'find',side_effect=AssertionError('No host mutation')):
   for action,method in [('add','add_component'),('remove','remove_component'),('bind','bind_component')]:
    data={'url':'https://github.com/example/project'}
    self.assertEqual(self.request('/api/control/components/'+action,'POST',data)[0],200)
    getattr(self.managers['control'],method).assert_called_once_with(data)
 def test_fail2ban_dispatches_exactly_one_explicit_action(self):
  for action in ('plan','apply','review'):
   data={'test':'body'}
   self.assertEqual(self.request('/api/fail2ban/'+action,'POST',data)[0],200)
   getattr(self.managers['fail2ban_manager'],action).assert_called_once_with(data)
 def test_domain_get_does_not_change_config(self):
  self.assertEqual(self.request('/api/deployment')[0],200)
  self.managers['deployment_settings'].snapshot.assert_called_once_with()
  self.managers['deployment_settings'].apply.assert_not_called()
 def test_domain_check_never_accepts_mutation_arguments(self):
  self.assertEqual(self.request('/api/deployment/check','POST',{'domain':'example.com'})[0],400)
  self.managers['deployment_settings'].refresh.assert_not_called()
  self.assertEqual(self.request('/api/deployment/check','POST',{})[0],200)
  self.managers['deployment_settings'].refresh.assert_called_once_with()
 def test_domain_freeze_survives_process_state_and_blocks_all_api_mutations(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(server,'ROOT',pathlib.Path(tmp)):
   directory=pathlib.Path(tmp)/'control-data';directory.mkdir();(directory/'deployment-freeze').touch()
   for path in ('/api/control/components/add','/api/fail2ban/apply','/api/servers','/api/action','/api/account/password'):
    self.assertEqual(self.request(path,'POST',{})[0],409)
   self.assertEqual(self.request('/api/deployment')[0],200)
   self.assertEqual(self.request('/api/deployment/check','POST',{})[0],200)
  self.managers['fail2ban_manager'].apply.assert_not_called()
  self.managers['control'].add_component.assert_not_called()
 def test_invalid_json_shapes_are_rejected_before_managers(self):
  for body in ([],None,'value',123):
   self.assertEqual(self.request('/api/fail2ban/apply','POST',body)[0],400)
  self.assertEqual(self.managers['fail2ban_manager'].mock_calls,[])
 def test_outage_errors_are_generic_and_do_not_leak_secrets(self):
  self.managers['outage_diagnostics'].snapshot.side_effect=RuntimeError('secret-value')
  code,body=self.request('/api/outage-diagnostics');self.assertEqual(code,503);self.assertNotIn('secret-value',str(body))

class MonitorTransition(unittest.TestCase):
 def test_first_failed_ssh_observed_immediately_without_a_probe_in_refresh(self):
  diagnostics=Mock();health=Mock();health.record.return_value={}
  s={'id':'route-fixture','host':'203.0.113.10','port':22,'services':[]}
  with patch.dict(server.CACHE,{},clear=True),patch.object(server,'ssh',side_effect=RuntimeError('SSH error')),patch.object(server,'health_store',return_value=health),patch.object(server,'outage_diagnostics',return_value=diagnostics),patch.object(server.socket,'create_connection',side_effect=OSError('unreachable')):
   value=server.refresh(s,True)
  self.assertFalse(value['ok']);diagnostics.observe.assert_called_once_with(s,value)
  self.assertEqual(diagnostics.mock_calls,[unittest.mock.call.observe(s,value)])
 def test_diagnostic_disk_failure_cannot_turn_successful_ssh_into_outage(self):
  diagnostics=Mock();diagnostics.observe.side_effect=OSError('disk full');health=Mock();health.record.return_value={}
  s={'id':'route-fixture-2','host':'203.0.113.10','port':22,'services':[]}
  with patch.dict(server.CACHE,{},clear=True),patch.object(server,'ssh',return_value={'panels':[]}),patch.object(server,'health_store',return_value=health),patch.object(server,'outage_diagnostics',return_value=diagnostics),patch.object(server.socket,'create_connection',side_effect=OSError('unreachable')):
   self.assertTrue(server.refresh(s,True)['ok'])

if __name__=='__main__':unittest.main()
