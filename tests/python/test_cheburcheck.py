import email.message, io, json, pathlib, tempfile, time, unittest
from unittest.mock import patch
import cheburcheck as cb

class Response(io.BytesIO):
    def __init__(self,body,ctype):
        super().__init__(body);self.headers=email.message.Message();self.headers['Content-Type']=ctype

def response(check=None,frames=''):
    return [Response(json.dumps(check or {'target':'192.0.2.14','blocked':False,'id':'context.token'}).encode(),'application/json'),Response(frames.encode(),'text/event-stream')]

class CheburcheckTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=pathlib.Path(self.temp.name)/'reports.json';self.service=cb.Cheburcheck(self.path)
        self.service.reports['server']=dict(host='192.0.2.14',status='running',check=None,probes=[])
    def run_worker(self,replies):
        with patch.object(cb,'request',side_effect=replies) as request:self.service.worker('server','192.0.2.14')
        return self.service.snapshot()['servers']['server'],request
    def test_static_negative_does_not_mean_reachable_without_probes(self):
        row,_=self.run_worker(response(frames='event: done\ndata: {"response_count":0,"online_probes":0}\n\n'))
        self.assertEqual(row['status'],'partial');self.assertFalse(row['check']['blocked']);self.assertIn('не установлена',row['error'])
    def test_eof_preserves_partial_results_and_no_context_persisted(self):
        row,_=self.run_worker(response(frames='event: result\ndata: {"probe_id":"1","verdicts":["tspu_block"],"region":"Москва"}\n\n'))
        self.assertEqual(row['status'],'partial');self.assertEqual(row['probes'][0]['verdicts'],['tspu_block'])
        self.assertNotIn('context.token',self.path.read_text())
    def test_mixed_results_preserved_and_duplicate_replaced(self):
        frames='event: started\ndata: {"target":"192.0.2.14","online_probes":2}\n\n'
        for item in [{'probe_id':'1','verdicts':['uncertain']},{'probe_id':'1','verdicts':['ok']},{'probe_id':'2','verdicts':['tspu_block']}]:frames+='event: result\ndata: '+json.dumps(item)+'\n\n'
        frames+='event: done\ndata: {"response_count":2,"online_probes":2}\n\n'
        row,req=self.run_worker(response(frames=frames))
        self.assertEqual(row['status'],'done');self.assertEqual([p['verdicts'] for p in row['probes']],[['ok'],['tspu_block']])
        self.assertEqual(len(req.call_args_list),2)
    def test_restart_marks_running_as_incomplete(self):
        self.service.save();other=cb.Cheburcheck(self.path)
        self.assertEqual(other.snapshot()['servers']['server']['status'],'error');self.assertFalse(other.busy)
    def test_local_targets_and_arbitrary_urls_rejected(self):
        for target in ('127.0.0.1','10.0.0.1','::1','https://evil.test/','host.local','1.2.3.4/path','x\n.test'):
            with self.subTest(target=target),self.assertRaises(ValueError):cb.target_address(target)
    def test_mismatch_does_not_launch_probes(self):
        row,req=self.run_worker(response(check={'target':'other.example','blocked':False,'id':'context.token'}))
        self.assertEqual(row['status'],'error');self.assertEqual(req.call_count,1)
    def test_rate_limit_is_local_and_does_not_retry(self):
        self.service.last_started=time.time()
        with self.assertRaises(ValueError):self.service.start({'id':'server','host':'192.0.2.14'})
    def test_unbounded_sse_line_rejected(self):
        with self.assertRaises(ValueError):list(cb.events(io.BytesIO(b'x'*131073),time.monotonic()+1))

if __name__=='__main__':unittest.main()
