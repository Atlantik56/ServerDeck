import copy
import json
import os
import pathlib
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import deployment_helper as h
from deployment_settings import DeploymentSettings, DeploymentRejected
import public_access


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.calls = []
        self.now = 100.0
        self.manager = DeploymentSettings(self.root, self.root, request_fn=self.request, clock=lambda: self.now)

    def tearDown(self):
        self.temp.cleanup()

    def request(self, value):
        self.calls.append(copy.deepcopy(value))
        return {'available': True, 'origin': 'https://deck.example.net', 'busy': False}

    def test_snapshot_cached_and_force_explicit(self):
        self.manager.snapshot();self.manager.snapshot()
        self.assertEqual(1, len(self.calls))
        self.manager.refresh()
        self.assertEqual(2, len(self.calls))

    def test_plan_blocked_while_control_jobs_active(self):
        self.manager.busy_fn = lambda: True
        with self.assertRaises(ValueError):self.manager.plan({'domain': 'new.example.net', 'email': 'a@example.net'})
        self.assertEqual([], self.calls)

    def test_plan_forwards_only_fixed_fields(self):
        self.manager.plan({'domain': 'new.example.net', 'email': 'a@example.net'})
        self.assertEqual({'action': 'plan', 'domain': 'new.example.net', 'email': 'a@example.net'}, self.calls[0])
        for value in ({'domain': [], 'email': 'x'}, {'domain': 'new.example.net', 'email': 'a@example.net', 'command': 'x'}):
            with self.assertRaises(ValueError):self.manager.plan(value)

    def test_apply_requires_exact_plan_shape(self):
        for value in ({'plan': '../x', 'confirmation': 'x'}, {'plan': 'a'*32, 'confirmation': 'x', 'domain': 'x'}, {'plan': 'a'*32, 'confirmation': []}):
            with self.assertRaises(ValueError):self.manager.apply(value)
        self.assertEqual([], self.calls)

    def test_fixed_loopback_target_and_validated_port(self):
        (self.root / 'key').write_text('fixture')
        with patch.dict(os.environ, {'DECK_DEPLOYMENT_SSH_HOST': '127.0.0.1', 'DECK_DEPLOYMENT_SSH_KEY': 'key', 'DECK_DEPLOYMENT_SSH_PORT': '2222'}):
            manager = DeploymentSettings(self.root, self.root)
        self.assertTrue(manager.available())
        result = subprocess.CompletedProcess([], 0, json.dumps({'ok': True, 'data': {'available': True}}), '')
        with patch('deployment_settings.subprocess.run', return_value=result) as run:
            manager.snapshot()
        argv = run.call_args.args[0]
        self.assertIn('2222', argv)
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertEqual('root@127.0.0.1', argv[-2])
        self.assertEqual('/usr/bin/python3 -I /usr/local/lib/server-deck/deployment_helper.py', argv[-1])
        for host, key, port in (('evil.example.net', 'key', '22'), ('127.0.0.1', '../key', '22'), ('127.0.0.1', 'key', '0')):
            with patch.dict(os.environ, {'DECK_DEPLOYMENT_SSH_HOST': host, 'DECK_DEPLOYMENT_SSH_KEY': key, 'DECK_DEPLOYMENT_SSH_PORT': port}):
                self.assertFalse(DeploymentSettings(self.root, self.root).available())

    def test_helper_failure_does_not_expose_transport_stderr(self):
        (self.root / 'key').write_text('fixture')
        with patch.dict(os.environ, {'DECK_DEPLOYMENT_SSH_HOST': '127.0.0.1', 'DECK_DEPLOYMENT_SSH_KEY': 'key'}):
            manager = DeploymentSettings(self.root, self.root)
        with patch('deployment_settings.subprocess.run', return_value=subprocess.CompletedProcess([], 255, '', 'SECRET MARKER')):
            self.assertNotIn('SECRET MARKER', json.dumps(manager.snapshot()))

    def test_freeze_exists_before_apply_transport_and_is_retained_on_uncertainty(self):
        def request(data):
            self.assertTrue(self.manager.freeze.exists())
            raise ValueError('transport uncertain')
        self.manager.request_fn=request
        with self.assertRaises(ValueError):self.manager.apply({'plan':'a'*32,'confirmation':'new.example.net'})
        self.assertTrue(self.manager.freeze.exists())
        self.manager.cached={'busy':False};self.manager.cached_at=self.now
        self.assertTrue(self.manager.snapshot()['busy'])

    def test_definite_helper_rejection_releases_own_freeze(self):
        def request(data):raise DeploymentRejected('rejected')
        self.manager.request_fn=request
        with self.assertRaises(DeploymentRejected):self.manager.apply({'plan':'a'*32,'confirmation':'new.example.net'})
        self.assertFalse(self.manager.freeze.exists())

    def test_other_service_reservation_blocks_domain_before_freeze(self):
        control=types.SimpleNamespace(lock=__import__('threading').RLock(),busy={'server1'},jobs={})
        manager=DeploymentSettings(self.root,self.root,request_fn=self.request,control=control)
        with self.assertRaises(ValueError):manager.apply({'plan':'a'*32,'confirmation':'new.example.net'})
        self.assertFalse(manager.freeze.exists())


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temp.name)
        names = {'CONFIG': self.base/'etc/deployment.json', 'APP_ENV': self.base/'etc/server.env', 'AUTH_ENV': self.base/'etc/auth.env',
                 'CADDY': self.base/'Caddyfile', 'TLS_DIR': self.base/'tls', 'ROOT': self.base/'state',
                 'RENDER': self.base/'render.py', 'RENEW_HOOK': self.base/'renew-hook', 'RENEW_UNIT': self.base/'renew.service',
                 'RENEW_TIMER': self.base/'renew.timer', 'ACME': self.base/'acme', 'CERTBOT': self.base/'certbot'}
        names.update(LINEAGES=self.base/'lineages', MUTATION_LOCK=self.base/'mutation.lock', FREEZE=self.base/'deployment-freeze')
        self.patchers = [patch.object(h, key, val) for key, val in names.items()]
        for p in self.patchers:p.start()
        h.CONFIG.parent.mkdir()
        h.ROOT.mkdir()
        self.config = dict(version=1, managed=True, mode='domain', host='old.example.net', port=443, origin='https://old.example.net',
                           publicIp='8.8.8.8', email='', publicPaths=['/login/'], certificateName='server-deck')
        h.CONFIG.write_text(json.dumps(self.config))
        h.APP_ENV.write_text('DECK_PUBLIC_ORIGIN=https://old.example.net\nDECK_GATEWAY_TOKEN='+'a'*48+'\n')
        h.AUTH_ENV.write_text('DECK_PUBLIC_ORIGIN=https://old.example.net\nDECK_AUTH_GATEWAY='+'b'*48+'\n')
        h.CADDY.write_text('old.example.net {\n # 127.0.0.1:8765 127.0.0.1:8766 127.0.0.1:8768\n}\n')
        h.RENDER.write_text('# fixture')
        h.CERTBOT.touch()
        h.TLS_DIR.mkdir()
        (h.TLS_DIR/'fullchain.pem').write_bytes(b'old-chain')
        (h.TLS_DIR/'privkey.pem').write_bytes(b'old-key')
        (h.TLS_DIR/'previous-fullchain.pem').write_bytes(b'older-chain')
        (h.TLS_DIR/'previous-privkey.pem').write_bytes(b'older-key')
        watched = tuple(names[k] for k in ('CONFIG', 'APP_ENV', 'AUTH_ENV', 'CADDY', 'RENEW_HOOK', 'RENEW_UNIT', 'RENEW_TIMER')) + tuple(h.TLS_DIR/p for p in ('fullchain.pem','privkey.pem','previous-fullchain.pem','previous-privkey.pem'))
        self.patchers.append(patch.object(h, 'WATCHED', watched));self.patchers[-1].start()
        self.module = types.SimpleNamespace(PUBLIC_PATHS=['/login/'], bootstrap_caddy=lambda d: 'http://'+d+' { respond 404 }\n',
                                            caddy_config=lambda *a, **kw: 'new.example.net { respond 200 }', renew_hook=lambda d: '# fixture hook')
        self.patchers += [patch.object(h, 'renderer', return_value=self.module), patch.object(h, 'no_active_jobs'),
                          patch.object(h, 'verify_target'), patch.object(h, 'run', return_value=subprocess.CompletedProcess([], 0, '', ''))]
        for p in self.patchers[-4:]:p.start()

    def tearDown(self):
        for p in reversed(self.patchers):p.stop()
        self.temp.cleanup()

    def new_plan(self):
        return h.protocol({'action': 'plan', 'domain': 'new.example.net', 'email': 'a@example.net'})

    def test_inspect_no_secrets_or_root_env_exposure(self):
        value = h.protocol({'action': 'inspect'})
        self.assertTrue(value['available'])
        self.assertTrue(value['canChange'])
        self.assertNotIn('a'*48, json.dumps(value))
        self.assertNotIn('revision', value)

    def test_plan_never_mutates_active_configuration(self):
        before = {p: p.read_bytes() for p in h.WATCHED if p.exists()}
        value = self.new_plan()
        self.assertEqual('https://new.example.net', value['newOrigin'])
        self.assertEqual(before, {p:p.read_bytes() for p in before})
        stored = json.loads((h.ROOT/'plans'/(value['id']+'.json')).read_text())
        self.assertFalse(stored['used'])
        self.assertEqual(0o600, (h.ROOT/'plans'/(value['id']+'.json')).stat().st_mode & 0o777)

    def test_confirmation_consumes_once_and_only_submits_fixed_worker(self):
        plan = self.new_plan()
        result = h.protocol({'action': 'apply', 'plan': plan['id'], 'confirmation': plan['domain']})
        self.assertTrue(result['accepted'])
        argv = h.run.call_args.args[0]
        self.assertEqual('/usr/bin/systemd-run', argv[0])
        self.assertEqual(['/usr/bin/python3', '-I', str(h.CODE), '--worker', plan['id']], argv[-5:])
        with self.assertRaises(h.DeploymentError):h.protocol({'action':'apply','plan':plan['id'],'confirmation':plan['domain']})

    def test_wrong_confirmation_and_changed_revision_are_rejected(self):
        plan = self.new_plan()
        with self.assertRaises(h.DeploymentError):h.protocol({'action':'apply','plan':plan['id'],'confirmation':'wrong.example.net'})
        h.CADDY.write_text(h.CADDY.read_text()+'# changed\n')
        with self.assertRaises(h.DeploymentError):h.protocol({'action':'apply','plan':plan['id'],'confirmation':plan['domain']})

    def test_expired_plan_and_replayed_queue_never_restart(self):
        plan = self.new_plan()
        with patch.object(h.time, 'time', return_value=plan['expiresAt']+1):
            with self.assertRaises(h.DeploymentError):h.protocol({'action':'apply','plan':plan['id'],'confirmation':plan['domain']})
        self.assertFalse(h.run.called)

    def test_uncertain_submission_stays_busy_and_no_auto_retry(self):
        plan = self.new_plan()
        with patch.object(h, 'run', side_effect=OSError('fixture')):
            result=h.protocol({'action':'apply','plan':plan['id'],'confirmation':plan['domain']})
        self.assertTrue(result['uncertain'])
        self.assertEqual('needs_review', h.last_job()['state'])
        self.assertTrue(h.inspect()['busy'])
        self.assertTrue(h.FREEZE.exists())
        self.assertTrue(json.loads((h.ROOT/'plans'/(plan['id']+'.json')).read_text())['used'])

    def test_proved_missing_systemd_unit_is_definite_rejection(self):
        plan=self.new_plan()
        def command(argv,**kwargs):
            if argv[0]=='/usr/bin/systemd-run':raise h.DeploymentError('fixture rejected')
            return subprocess.CompletedProcess(argv,0,'not-found\n','')
        with patch.object(h,'run',side_effect=command):
            with self.assertRaises(h.DeploymentError):h.protocol({'action':'apply','plan':plan['id'],'confirmation':plan['domain']})
        self.assertEqual('failed',h.last_job()['state'])
        self.assertFalse(h.FREEZE.exists())

    def test_submit_timeout_preserves_worker_running_receipt(self):
        plan=self.new_plan()
        def command(argv,**kwargs):
            job=h.last_job();job.update(state='running',stage='certificate');h.write_json(h.ROOT/'last-job.json',job)
            raise subprocess.TimeoutExpired(argv,15)
        with patch.object(h,'run',side_effect=command):
            result=h.protocol({'action':'apply','plan':plan['id'],'confirmation':plan['domain']})
        self.assertTrue(result['uncertain'])
        self.assertEqual('running',h.last_job()['state'])
        self.assertEqual('certificate',h.last_job()['stage'])
        self.assertTrue(h.FREEZE.exists())

    def test_unit_collection_cannot_overwrite_late_rollback_failure(self):
        plan=self.new_plan()
        def command(argv,**kwargs):
            if argv[0]=='/usr/bin/systemd-run':raise h.DeploymentError('fixture lost reply')
            job=h.last_job();job.update(state='rollback_failed',stage='error',error='review required');h.write_job(job)
            return subprocess.CompletedProcess(argv,0,'not-found\n','')
        with patch.object(h,'run',side_effect=command):
            result=h.protocol({'action':'apply','plan':plan['id'],'confirmation':plan['domain']})
        self.assertTrue(result['uncertain'])
        self.assertEqual('rollback_failed',h.last_job()['state'])
        self.assertTrue(h.FREEZE.exists())

    def test_unit_collection_preserves_late_success_receipt(self):
        plan=self.new_plan()
        def command(argv,**kwargs):
            if argv[0]=='/usr/bin/systemd-run':raise h.DeploymentError('fixture lost reply')
            job=h.last_job();job.update(state='succeeded',stage='complete');h.write_job(job);h.unfreeze(plan['id'])
            return subprocess.CompletedProcess(argv,0,'not-found\n','')
        with patch.object(h,'run',side_effect=command):
            result=h.protocol({'action':'apply','plan':plan['id'],'confirmation':plan['domain']})
        self.assertFalse(result['uncertain'])
        self.assertEqual('succeeded',h.last_job()['state'])
        self.assertFalse(h.FREEZE.exists())

    def test_remote_config_origin_mismatch_refused(self):
        h.AUTH_ENV.write_text('DECK_PUBLIC_ORIGIN=https://other.example.net\n')
        with self.assertRaises(h.DeploymentError):h.load_configuration()

    def test_input_cannot_supply_commands_paths_or_worker(self):
        for value in ({'action':'worker'}, {'action':'adopt'}, {'action':'inspect','path':'/etc/passwd'},
                      {'action':'plan','domain':'new.example.net','email':'a@example.net','command':'sh'}):
            with self.assertRaises(h.DeploymentError):h.protocol(value)

    def test_domains_injection_and_private_names_rejected(self):
        for value in ('https://new.example.net','new.example.net:444','new.example.net/x','new.example.net\nX','localhost','a.local','a.invalid','a.test','NEW.example.net','8.8.8.8','a@new.example.net'):
            with self.assertRaises(h.DeploymentError):h.validate_domain(value)

    def test_private_and_invalid_ip_rejected(self):
        for value in ('127.0.0.1', '10.0.0.1', '192.0.2.1', '8.8.8.8;sh', None):
            with self.assertRaises(h.DeploymentError):h.public_ip(value)

    def test_dns_must_match_only_controller_ip(self):
        self.patchers[-2].stop() # verify_target patch
        with patch.object(h, 'dns_addresses', return_value={'9.9.9.9'}):
            with self.assertRaises(h.DeploymentError):h.verify_target(self.config,'new.example.net')
        with patch.object(h,'dns_addresses',return_value={'8.8.8.8','9.9.9.9'}):
            with self.assertRaises(h.DeploymentError):h.verify_target(self.config,'new.example.net')

    def test_occupied_web_port_not_caddy_refused(self):
        self.patchers[-2].stop()
        fixture='LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1,fd=3))\n'
        def command(argv,**kwargs):return subprocess.CompletedProcess([],0,'[]' if argv[0]=='/usr/bin/python3' else fixture,'')
        with patch.object(h,'dns_addresses',return_value={'8.8.8.8'}),patch.object(h,'run',side_effect=command):
            with self.assertRaises(h.DeploymentError):h.verify_target(self.config,'new.example.net')

    def test_unattested_aaaa_is_refused_even_with_matching_ipv4(self):
        self.patchers[-2].stop()
        with patch.object(h,'dns_addresses',return_value={'8.8.8.8'}),patch.object(h,'run',return_value=subprocess.CompletedProcess([],0,'["2001:4860:4860::8888"]','')) as run:
            with self.assertRaises(h.DeploymentError):h.verify_target(self.config,'new.example.net')
        self.assertEqual(1,run.call_count)

    def test_adopt_only_writes_metadata(self):
        h.CONFIG.unlink()
        before={p:p.read_bytes() for p in (h.APP_ENV,h.AUTH_ENV,h.CADDY)}
        result=subprocess.CompletedProcess([],0,json.dumps({'apps':{'http':{'servers':{'s':{'routes':[{'match':[{'host':['old.example.net']}]}]}}}}}), '')
        with patch.object(h,'dns_addresses',return_value={'8.8.8.8'}),patch.object(h,'run',return_value=result) as run:
            value=h.adopt_current()
        self.assertTrue(value['available'])
        self.assertEqual(before,{p:p.read_bytes() for p in before})
        self.assertEqual(1,len(run.call_args_list))
        self.assertEqual('adapt',run.call_args.args[0][1])

    def test_adopt_refuses_unrelated_sites(self):
        h.CONFIG.unlink()
        result=subprocess.CompletedProcess([],0,json.dumps({'routes':[{'match':[{'host':['old.example.net','other.example.net']}]}]}),'')
        with patch.object(h,'run',return_value=result):
            with self.assertRaises(h.DeploymentError):h.adopt_current()
        self.assertFalse(h.CONFIG.exists())

    def prepare_worker(self):
        value=self.new_plan()
        h.protocol({'action':'apply','plan':value['id'],'confirmation':value['domain']})
        lineage=h.LINEAGES/('server-deck-domain-'+value['id'][:8])
        lineage.mkdir(parents=True)
        (lineage/'fullchain.pem').write_bytes(b'new-chain')
        (lineage/'privkey.pem').write_bytes(b'new-key')
        return value

    def worker_patches(self):
        return (patch.object(h.os,'chown'),patch.object(h.grp,'getgrnam',return_value=types.SimpleNamespace(gr_gid=os.getgid())),patch.object(h.time,'sleep'))

    def test_worker_checks_dynamic_backend_and_auth_not_just_static_login(self):
        value=self.prepare_worker()
        original={p:p.read_bytes() for p in h.WATCHED if p.exists()}
        a,b,c=self.worker_patches()
        def health(domain,*args):
            if domain=='new.example.net':raise h.DeploymentError('unhealthy dynamic service')
        with a,b,c,patch.object(h,'verify_https') as https,patch.object(h,'verify_services',side_effect=health) as services:
            h.run_worker(value['id'])
        self.assertEqual('failed',h.last_job()['state'])
        self.assertEqual(21,services.call_count)
        self.assertEqual(20,https.call_count)
        self.assertEqual(original,{p:p.read_bytes() for p in original})
        self.assertFalse(h.RENEW_TIMER.exists())
        self.assertFalse(h.FREEZE.exists())
        self.assertTrue(any('disable' in call.args[0] and 'server-deck-certbot-renew.timer' in call.args[0] for call in h.run.call_args_list))

    def test_worker_success_preserves_gateway_secrets_and_only_restarts_own_services(self):
        value=self.prepare_worker()
        a,b,c=self.worker_patches()
        with a,b,c,patch.object(h,'verify_https'),patch.object(h,'verify_services') as services:
            h.run_worker(value['id'])
        self.assertEqual('succeeded',h.last_job()['state'])
        self.assertEqual('https://new.example.net',json.loads(h.CONFIG.read_text())['origin'])
        self.assertEqual('a'*48,h.read_env(h.APP_ENV)['DECK_GATEWAY_TOKEN'])
        self.assertEqual('b'*48,h.read_env(h.AUTH_ENV)['DECK_AUTH_GATEWAY'])
        self.assertEqual(1,services.call_count)
        self.assertFalse(h.FREEZE.exists())
        commands=[call.args[0] for call in h.run.call_args_list]
        restarted=[command[-1] for command in commands if 'restart' in command]
        self.assertEqual(['server-deck-auth.service','server-deck.service'],restarted)
        self.assertTrue(any('--no-directory-hooks' in command for command in commands))
        self.assertIn('https://old.example.net',h.CADDY.read_text())
        self.assertIn('previous-fullchain.pem',h.CADDY.read_text())

    def test_failed_certificate_restores_config_without_entering_domain_switch(self):
        value=self.prepare_worker()
        original={p:p.read_bytes() for p in h.WATCHED if p.exists()}
        def command(argv, **kwargs):
            if 'certonly' in argv:raise h.DeploymentError('certificate fixture failure')
            return subprocess.CompletedProcess(argv,0,'','')
        a,b,c=self.worker_patches()
        with a,b,c,patch.object(h,'run',side_effect=command),patch.object(h,'verify_services') as services:
            h.run_worker(value['id'])
        self.assertEqual('failed',h.last_job()['state'])
        self.assertEqual(original,{p:p.read_bytes() for p in original})
        self.assertEqual(1,services.call_count)
        self.assertEqual('old.example.net',services.call_args.args[0])

    def test_rollback_failure_holds_global_freeze(self):
        value=self.prepare_worker()
        a,b,c=self.worker_patches()
        with a,b,c,patch.object(h,'verify_https'),patch.object(h,'verify_services',side_effect=h.DeploymentError('both names unhealthy')):
            h.run_worker(value['id'])
        self.assertEqual('rollback_failed',h.last_job()['state'])
        self.assertTrue(h.FREEZE.exists())
        self.assertTrue(h.inspect()['busy'])


class IpOriginTests(unittest.TestCase):
    def test_ip_host_includes_exact_port(self):
        with patch.multiple(public_access,ORIGIN='https://8.8.8.8:38443',HOST='8.8.8.8'):
            self.assertEqual(('8.8.8.8:38443',), public_access.hosts(8765))
            self.assertFalse(public_access.bridge_supported())
            self.assertNotIn('https://*.8.8.8.8',public_access.policy())
            self.assertTrue(public_access.allowed_domain('8.8.8.8',[]))
            self.assertFalse(public_access.allowed_domain('srv-lucx.8.8.8.8',[{'id':'srv'}]))
            with self.assertRaises(ValueError):public_access.bridge_host('srv','lucx')

    def test_domain_bridging_preserved(self):
        with patch.multiple(public_access,ORIGIN='https://deck.example.net',HOST='deck.example.net'):
            self.assertTrue(public_access.bridge_supported())
            self.assertEqual('srv-lucx.deck.example.net',public_access.bridge_host('srv','lucx'))


class DynamicHealthTests(unittest.TestCase):
    def connection(self, replies, calls):
        class Response:
            def __init__(self, status, body):self.status=status;self.body=body
            def read(self, limit):return self.body
        class Connection:
            def __init__(self, host, port, timeout):self.port=port
            def request(self, method, path, headers):calls.append((self.port,method,path,headers.copy()))
            def getresponse(self):return Response(*replies.pop(0))
            def close(self):pass
        return Connection

    def test_health_uses_auth_and_authenticated_cached_backend_api(self):
        calls=[];token='t'*43
        replies=[(200,b'{"required":false,"available":false}'),(200,('name="deck-token" content="'+token+'"').encode()),(200,b'{"cve":"fixture"}')]
        with patch.object(h.http.client,'HTTPConnection',self.connection(replies,calls)):
            h.verify_services('deck.example.net','g'*48,'a'*48)
        self.assertEqual([(8768,'GET','/auth/setup'),(8765,'GET','/'),(8765,'GET','/api/security-updates')],[c[:3] for c in calls])
        self.assertEqual(token,calls[-1][3]['X-Deck-Token'])
        self.assertEqual('g'*48,calls[-1][3]['X-Deck-Gateway'])
        self.assertNotIn('/api/state',[c[2] for c in calls])

    def test_broken_auth_cannot_pass_static_login_health(self):
        calls=[]
        with patch.object(h.http.client,'HTTPConnection',self.connection([(503,b'{}')],calls)):
            with self.assertRaises(h.DeploymentError):h.verify_services('deck.example.net','g'*48,'a'*48)
        self.assertEqual(1,len(calls))

    def test_backend_or_api_rejection_causes_health_failure(self):
        for replies in ([(200,b'{"required":false,"available":false}'),(403,b'no')],[(200,b'{"required":false,"available":false}'),(200,b'name="deck-token" content="ttttttttttttttttttttttttttttttttttttttttttt"'),(403,b'{}')]):
            with patch.object(h.http.client,'HTTPConnection',self.connection(replies,[])):
                with self.assertRaises(h.DeploymentError):h.verify_services('deck.example.net','g'*48,'a'*48)


if __name__=='__main__':unittest.main()
