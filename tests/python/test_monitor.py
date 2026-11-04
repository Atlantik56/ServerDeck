import copy,pathlib,tempfile,unittest
from monitor import HealthStore

def status(ts,ok=True):
    return dict(checkedAt=ts,ok=ok,tcpOk=ok,tcpMs=30 if ok else None,durationMs=500,data=dict(cpu=10,memory={'used':20,'total':100},disk={'used':30,'total':100},bootId='boot-a',awg=[dict(interface='awg1',ifindex=4,counters={'rx_errors':10})],services=[],containers=[]))

class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=HealthStore(pathlib.Path(self.temp.name)/'test.sqlite3')
    def tearDown(self):self.temp.cleanup()
    def test_failure_missing_and_stale_are_not_healthy(self):
        failed=self.store.record('a',dict(checkedAt=100,ok=False,error='SSH failed'))
        self.assertEqual(failed['health'],'unavailable')
        incomplete=status(160);incomplete['data']['cpu']=None
        self.assertEqual(self.store.record('a',incomplete)['health'],'warning')
        self.store.record('b',status(170))
        report=self.store.report(['a','b','never'],now=400)
        self.assertTrue(report['servers']['b']['stale'])
        self.assertTrue(report['servers']['never']['stale'])
        self.assertIsNone(report['servers']['never']['successRate'])
        self.assertEqual(report['servers']['a']['successRate'],50)
    def test_awg_delta_ignores_reset_and_observation_gap(self):
        first=self.store.record('a',status(100));self.assertIsNone(first['awg'][0]['rxErrorsDelta'])
        second=status(160);second['data']['awg'][0]['counters']['rx_errors']=15
        self.assertEqual(self.store.record('a',second)['awg'][0]['rxErrorsDelta'],5)
        reset=status(220);reset['data']['awg'][0]['ifindex']=5
        self.assertIsNone(self.store.record('a',reset)['awg'][0]['rxErrorsDelta'])
        gap=status(1000);gap['data']['awg'][0]['ifindex']=5
        self.assertIsNone(self.store.record('a',gap)['awg'][0]['rxErrorsDelta'])
    def test_persistence_success_ratio_and_recovery(self):
        for ts,ok in [(100,True),(160,False),(220,False),(280,True)]:self.store.record('a',status(ts,ok))
        reopened=HealthStore(self.store.path);r=reopened.report(['a'],now=300)['servers']['a']
        self.assertEqual(r['successRate'],50);self.assertEqual(len(r['incidents']),1)
        self.assertEqual(r['incidents'][0]['recovered'],280)
    def test_thresholds_and_intentionally_stopped_services(self):
        s=status(100);s['data']['services']=[dict(unit='optional.service',state='inactive')]
        self.assertEqual(self.store.record('a',s)['health'],'ok')
        s=status(160);s['data']['disk']['used']=95
        self.assertEqual(self.store.record('a',s)['health'],'critical')

if __name__=='__main__':unittest.main()
