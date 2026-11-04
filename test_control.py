import copy, io, json, pathlib, sqlite3, tarfile, tempfile, time, unittest
from unittest.mock import patch
from control import Control, Vault
import control_remote as remote

class VaultTests(unittest.TestCase):
    def test_round_trip_tampering_wrong_key_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);v=Vault(root/'vault');payload=b'private VPN keys\x00'*100
            blob=v.encrypt(payload,{'server':'one','panel':'lucx'})
            self.assertNotIn(payload,blob);self.assertEqual(v.decrypt(blob)[0],payload)
            self.assertEqual((root/'vault/recovery.key').stat().st_mode&0o777,0o600)
            for offset in (len(blob)-1,len(blob)//2):
                damaged=bytearray(blob);damaged[offset]^=1
                with self.assertRaises(ValueError):v.decrypt(bytes(damaged))
            with self.assertRaises(ValueError):Vault(root/'other').decrypt(blob)
            self.assertEqual(Vault(root/'vault').decrypt(blob)[0],payload)

class AdapterTests(unittest.TestCase):
    def test_full_client_update_preserves_keys_routes_and_identity(self):
        original={'id':9,'uuid':'identity-uuid','email':'alice','subId':'sub-1','privateKey':'private','publicKey':'public','preSharedKey':'psk','allowedIPs':['10.8.1.6/32'],'keepAlive':'25','reverse':{'tag':'private-route'},'limitHwid':2,'enable':True,'totalGB':12,'resetWeekday':3,'unknownFutureField':{'keep':True}}
        writes=[]
        def api(path,body=None,**kw):
            if path.startswith('clients/get/'):return {'client':copy.deepcopy(original)}
            if path.startswith('clients/update/'):
                writes.append(copy.deepcopy(body));return None
            if path=='clients/list':return [dict(original,totalGB=100)]
            raise AssertionError(path)
        with patch.object(remote,'lucx',side_effect=api):
            result=remote.apply_client({'panel':'lucx','action':'edit','name':'alice','fields':{'quota':100}})
        self.assertTrue(result['verified']);self.assertEqual(len(writes),1)
        for key in ('privateKey','publicKey','preSharedKey','allowedIPs','keepAlive','reverse','limitHwid','resetWeekday','unknownFutureField'):
            self.assertEqual(writes[0][key],original[key])
        self.assertEqual(writes[0]['id'],'identity-uuid');self.assertEqual(writes[0]['totalGB'],100)

    def test_partial_failure_is_not_retried(self):
        calls=[]
        def api(path,body=None,**kw):
            calls.append(path)
            if path.startswith('clients/get/'):return {'client':{'email':'a','uuid':'u','enable':True}}
            raise RuntimeError('Partial application')
        with patch.object(remote,'lucx',side_effect=api):
            with self.assertRaises(RuntimeError):remote.apply_client({'panel':'lucx','action':'edit','name':'a','fields':{'enabled':False}})
        self.assertEqual(sum(x.startswith('clients/update/') for x in calls),1)

    def test_proxy_expiry_uses_supported_rfc3339_and_preserves_other_limits(self):
        user={'max_tcp_conns':7,'max_unique_ips':3,'data_quota_bytes':500,'expiration_rfc3339':None,'enabled':True}
        with patch.object(remote,'mt_record',return_value=user),patch.object(remote,'mt_cli') as cli:
            remote.apply_mt_fields('alice',{'expires':1798761600000})
        cli.assert_called_once_with('secret','setlimits','alice','7','3','500','2027-01-01T00:00:00Z')

    def test_native_proxy_cli_schema_preserves_limits_traffic_and_links(self):
        native={'users':[{'label':'alice','enabled':False,'max_conns':7,'max_ips':3,'quota_bytes':500,'expires':'2027-01-01T00:00:00Z','total_bytes':123,'rate_limit_up_bps':900}], 'links':{'alice':['tg://proxy?secret=private']},'live':{'ok':True,'data':[{'username':'alice','current_connections':2}]}}
        with patch.object(remote,'mt_cli',return_value=json.dumps(native)):user=remote.mt_users()[0]
        self.assertEqual(user['max_tcp_conns'],7);self.assertEqual(user['max_unique_ips'],3);self.assertEqual(user['data_quota_bytes'],500)
        self.assertEqual(user['traffic']['total_bytes'],123);self.assertFalse(user['enabled']);self.assertEqual(user['current_connections'],2)
        self.assertEqual(user['links'],native['links']['alice']);self.assertEqual(remote.parse_expiry(user['expiration_rfc3339']),1798761600000)

    def test_failed_new_proxy_limits_remove_only_the_just_created_user(self):
        with patch.object(remote,'mt_cli') as cli,patch.object(remote,'apply_mt_fields',side_effect=RuntimeError('invalid limit')):
            with self.assertRaises(RuntimeError):remote.apply_client({'panel':'mtproxyl','action':'create','name':'new-user','fields':{'quota':1}})
        self.assertEqual(cli.call_args_list[0].args,('secret','add','new-user'))
        self.assertEqual(cli.call_args_list[1].args,('secret','remove','new-user'))

    def test_revision_drift_stops_worker_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(remote,'STATE',pathlib.Path(tmp)),patch.object(remote,'client_plan',return_value={'revision':'new'}),patch.object(remote,'apply_client') as apply:
            (pathlib.Path(tmp)/'jobs').mkdir()
            req=dict(job='a'*32,kind='client',revision='old',expiresAt=time.time()+300)
            remote.job_worker(req)
            apply.assert_not_called()
            result=json.loads((pathlib.Path(tmp)/'jobs'/('a'*32+'.json')).read_text())
            self.assertEqual(result['state'],'failed')

    def test_no_arbitrary_fields_names_or_restore_downgrade(self):
        for fields in ({'privateKey':'overwrite'},{'quota':-1},{'enabled':'false'}):
            with self.assertRaises(ValueError):remote.checked_fields(fields,'lucx')
        for name in ('x/../../y','alice\nreboot','$(reboot)','-bad'):
            with self.assertRaises(ValueError):remote.valid_name(name,'mtproxyl')
        with patch.object(remote,'versions',return_value={'lucx':'new'}):
            with self.assertRaises(ValueError):remote.restore_plan({'panel':'lucx','savedVersion':'old'})

    def test_last_enabled_proxy_client_protected(self):
        user={'username':'last','enabled':True}
        with patch.object(remote,'revisions',return_value='rev'),patch.object(remote,'mt_record',return_value=user),patch.object(remote,'mt_users',return_value=[user]):
            with self.assertRaises(ValueError):remote.client_plan({'panel':'mtproxyl','action':'delete','name':'last'})

    def test_snapshot_is_valid_sqlite_without_runtime_operations(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=pathlib.Path(tmp)/'live.db'
            with sqlite3.connect(str(db)) as c:
                c.execute('create table settings(key text,value text)');c.execute('create table clients(id integer,secret text)');c.execute("insert into clients values (1,'secret')")
            with patch.object(remote,'DB',db),patch.object(remote,'revisions',return_value='r'),patch.object(remote,'versions',return_value={'lucx':'v'}):value=remote.snapshot('lucx')
            import base64
            with tarfile.open(fileobj=io.BytesIO(base64.b64decode(value['data'])),mode='r:gz') as tar:
                restored=pathlib.Path(tmp)/'restored.db';restored.write_bytes(tar.extractfile('x-ui.db').read())
            with sqlite3.connect(str(restored)) as c:
                self.assertEqual(c.execute('pragma integrity_check').fetchone()[0],'ok');self.assertEqual(c.execute('select secret from clients').fetchone()[0],'secret')

class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
        (self.root/'control_remote.py').write_text('')
        self.server={'id':'one','host':'192.0.2.1','name':'One','key':'key','port':22,'user':'root'}
        self.c=Control(self.root,lambda:[self.server],self.root)
    def tearDown(self):self.temp.cleanup()
    def plan(self):
        with patch.object(self.c,'ssh',return_value={'revision':'r','summary':{'title':'edit'},'request':{'kind':'client','panel':'lucx'}}):return self.c.plan({'server':'one','kind':'client'})
    def test_expiry_confirmation_and_one_use(self):
        p=self.plan()
        with self.assertRaises(ValueError):self.c.execute(p['id'],'wrong-host')
        with patch('control.threading.Thread'):
            job=self.c.execute(p['id'],'192.0.2.1')
            with self.assertRaises(ValueError):self.c.execute(p['id'],'192.0.2.1')
        self.assertEqual(job['state'],'backing_up')
        self.c.busy.clear();p=self.plan();self.c.plans[p['id']]['expiresAt']=time.time()-1
        with self.assertRaises(ValueError):self.c.execute(p['id'],'192.0.2.1')
    def test_backup_failure_never_submits_remote_mutation(self):
        p=self.plan()
        with patch('control.threading.Thread'):job=self.c.execute(p['id'],'192.0.2.1')
        with patch.object(self.c,'create_backup',side_effect=RuntimeError('disk full')),patch.object(self.c,'ssh') as ssh:
            self.c.worker(job['id'],self.c.plans[p['id']]);ssh.assert_not_called()
        self.assertEqual(self.c.jobs[job['id']]['state'],'failed')

    def test_review_cannot_unlock_running_remote_task(self):
        job={'id':'j','server':'one','host':'192.0.2.1','state':'needs_review','expiresAt':time.time()-60};self.c.jobs['j']=job;self.c.busy.add('one')
        with patch.object(self.c,'ssh',return_value={'state':'needs_review','workerActive':True}):
            with self.assertRaises(ValueError):self.c.acknowledge('j','192.0.2.1')
        self.assertIn('one',self.c.busy)
        with patch.object(self.c,'ssh',return_value={'state':'needs_review','workerActive':False}) as ssh:self.c.acknowledge('j','192.0.2.1')
        self.assertEqual(job['state'],'reviewed');self.assertNotIn('one',self.c.busy)
        self.assertEqual(ssh.call_args.args[1]['op'],'job')

if __name__=='__main__':unittest.main()
