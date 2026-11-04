import copy
import unittest
from update_status import annotate_servers, compare_versions, summarize

class UpdateStatusTests(unittest.TestCase):
    def feed(self,current='v3.11.0-lucx.332',target='v3.11.0-lucx.333'):
        return [dict(server='one',ok=True,versions={'lucx':current})],dict(checkedAt=1000,lucx=dict(ok=True,releases=[dict(version=target,url='https://evil.invalid')]))
    def test_lucx_build_and_dotted_version(self):
        self.assertEqual(compare_versions('lucx','3.11.0-lucx.332','v3.11.0-lucx.333'),'update_available')
        self.assertEqual(compare_versions('lucx','3.9.0-lucx.999','v3.11.0-lucx.3'),'update_available')
    def test_known_prefixes_equal(self):
        for c,a,b in [('lucx','x-ui version: 3.11.0-lucx.332','v3.11.0-lucx.332'),('mtproxyl-panel','1.3.13','mtproxyl-panel-v1.3.13'),('telemt','telemt 3.3.25','v3.3.25'),('mtproxyl','v1.7.17','v1.7.17')]:
            self.assertEqual(compare_versions(c,a,b),'latest')
    def test_foreign_panel_unknown(self):self.assertEqual(compare_versions('lucx','3.11.0','v3.11.0-lucx.332'),'unknown')
    def test_ambiguous_versions_unknown(self):
        for x in ['',None,'latest','неизвестно','mtproxyl-telemt:3.3.25','sha256:abc','3.3.25-beta','telemt 3.3.25 commit abc','3.3.25\n3.3.25','9'*100+'.2.3',True,123]:
            self.assertEqual(compare_versions('telemt',x,'v3.3.25'),'unknown',repr(x))
    def test_custom_stable(self):
        self.assertEqual(compare_versions('custom','v1.2.9','v1.2.10'),'update_available')
        self.assertEqual(compare_versions('custom','r2026','r2027'),'unknown')
    def test_ahead(self):self.assertEqual(compare_versions('telemt','3.4.0','v3.3.25'),'ahead')
    def test_copy_and_trusted_link(self):
        rows,up=self.feed();original=copy.deepcopy((rows,up));out=annotate_servers(rows,up,1010)
        self.assertEqual((rows,up),original)
        self.assertEqual(out[0]['updateStatus']['lucx']['state'],'update_available')
        self.assertEqual(out[0]['updateStatus']['lucx']['sourceUrl'],'https://github.com/AlexeyLCP/lucx-ui/releases/tag/v3.11.0-lucx.333')
        self.assertEqual(summarize(out)['update_available'],1)
    def test_failed_fetch_unknown(self):
        rows,up=self.feed(target='v3.11.0-lucx.332');up['lucx']['ok']=False
        self.assertEqual(annotate_servers(rows,up,1010)[0]['updateStatus']['lucx']['state'],'unknown')
    def test_stale_future_unknown(self):
        for stamp in [None,'1000',True,-4000,2000]:
            rows,up=self.feed();up['checkedAt']=stamp
            self.assertEqual(annotate_servers(rows,up,1010)[0]['updateStatus']['lucx']['state'],'unknown')
    def test_empty_feed_unknown(self):
        rows,up=self.feed();up['lucx']['releases']=[]
        self.assertEqual(annotate_servers(rows,up,1010)[0]['updateStatus']['lucx']['state'],'unknown')
    def test_semantic_max(self):
        rows,up=self.feed(target='v3.9.0-lucx.9');up['lucx']['releases'].append(dict(version='v3.11.0-lucx.332'))
        self.assertEqual(annotate_servers(rows,up,1010)[0]['updateStatus']['lucx']['state'],'latest')
    def test_unreachable(self):
        rows,up=self.feed();rows[0]['ok']=False;out=annotate_servers(rows,up,1010)
        self.assertEqual(out[0]['updateStatus']['lucx']['state'],'unknown');self.assertEqual(summarize(out)['unknown'],1)
    def test_absent_not_reported_installed(self):self.assertEqual(annotate_servers([dict(ok=True,versions={})],dict(checkedAt=1000),1010)[0]['updateStatus'],{})
    def test_invalid_tags(self):
        rows,up=self.feed();up['lucx']['releases']=[dict(version='latest'),dict(version='v3.11.0-lucx.333-beta')]
        self.assertEqual(annotate_servers(rows,up,1010)[0]['updateStatus']['lucx']['state'],'unknown')
if __name__=='__main__':unittest.main()
