import unittest
from native_probe import verdict

class NativeTests(unittest.TestCase):
    def report(self,country='RU',reference='US',direct=True,control=True):
        return dict(point={'country':country},reference={'country':reference},direct=[{'port':443,'tcp':direct}],control=[{'port':443,'tcp':control}])
    def test_no_russian_verdict_without_russian_exit(self):
        for country in [None,'US','NL']:
            self.assertEqual(verdict(self.report(country=country)),'point_not_ru')
    def test_disagreement_is_not_declared_tspu(self):
        self.assertEqual(verdict(self.report(direct=False)),'difference')
        self.assertEqual(verdict(self.report(reference='RU',direct=False)),'unconfirmed')
        self.assertEqual(verdict(self.report(direct=False,control=False)),'unconfirmed')
    def test_positive_tcp_and_missing_observations(self):
        self.assertEqual(verdict(self.report()),'reachable')
        r=self.report();r['direct']=[];self.assertEqual(verdict(r),'unknown')

if __name__=='__main__':unittest.main()
