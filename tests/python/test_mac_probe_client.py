import json, os, pathlib, tempfile, unittest
from unittest.mock import patch
from mac_probe_client import MacProbeClient

class MacProbeTests(unittest.TestCase):
    def test_offline_point_is_not_reported_healthy(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,DECK_MAC_PROBE_TOKEN='test-token'):
            p=pathlib.Path(tmp)/'probe.json';p.write_text(json.dumps({'s':{'finishedAt':1}}))
            c=MacProbeClient(p)
            with patch.object(c,'request',side_effect=OSError('offline')):
                r=c.snapshot();self.assertFalse(r['available']);self.assertFalse(r['busy']);self.assertIn('s',r['servers'])
                with self.assertRaisesRegex(ValueError,'недоступна'):c.start({'id':'s','host':'192.0.2.1'},[{'port':22}])
    def test_only_probe_data_is_sent_to_mac(self):
        with patch.dict(os.environ,DECK_MAC_PROBE_TOKEN='test-token'):
            c=MacProbeClient('/tmp/unused-deck-probe')
            with patch.object(c,'request',return_value={'started':True}) as request:
                c.start({'id':'s','host':'192.0.2.1','key':'private-key'},[{'port':22}])
                self.assertNotIn('key',request.call_args.args[1]['server'])

if __name__=='__main__':unittest.main()
