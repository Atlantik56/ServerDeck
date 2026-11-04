import copy
import pathlib
import stat
import tempfile
import unittest
from custom_components import ProjectCatalog, canonical_project, api_json, NoRedirect

class ProjectCatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.calls=[]
        self.info=dict(name='Example',full_name='owner/example',description='<script>example</script>',private=False)
        self.releases=[dict(tag_name='v1.0.0',published_at='2026-01-01',html_url='javascript:alert(1)'),dict(tag_name='v1.1.0',draft=False),dict(tag_name='v2.0.0',prerelease=True),dict(tag_name='v3.0.0',draft=True),dict(tag_name='../../evil')]
        self.catalog=ProjectCatalog(pathlib.Path(self.tmp.name),self.fetch)
    def tearDown(self):self.tmp.cleanup()
    def fetch(self,url):
        self.calls.append(url)
        return copy.deepcopy(self.releases if '/releases?' in url else self.info)
    def add(self):return self.catalog.add('https://github.com/Owner/Example.git/')
    def test_url_normalization(self):
        self.assertEqual(canonical_project('https://GitHub.com/Owner/Repo.git')['url'],'https://github.com/owner/repo')
        self.assertEqual(canonical_project('https://gitlab.com/group/nested/repo')['project'],'group/nested/repo')
    def test_network_and_credential_url_inputs_rejected_before_fetch(self):
        for value in ('http://github.com/o/r','https://user:password@github.com/o/r','https://github.com:443/o/r','https://127.0.0.1/o/r','https://localhost/a/b','https://github.com.evil.test/o/r','https://github.com/o/r?token=x','https://github.com/o/r#fragment','https://github.com/o/r/blob/main/install.sh','https://gitlab.com/a/%2e%2e/repo','ssh://git@github.com/o/r','https://github.com/o/..',None,{},'https://github.com/o/r\n?token=s'):
            with self.subTest(value=value),self.assertRaises(ValueError):self.catalog.add(value)
        self.assertEqual(self.calls,[])
    def test_no_api_redirect_allowed(self):
        with self.assertRaises(ValueError):NoRedirect().redirect_request(None,None,302,'',{},'http://127.0.0.1/')
    def test_external_api_rejected(self):
        for url in ('http://api.github.com/repos/o/r','https://example.com/a','https://u:p@api.github.com/repos/o/r'):
            with self.assertRaises(ValueError):api_json(url)
    def test_add_persisted_and_no_code_execution(self):
        row=self.add();self.assertTrue(row['custom']);self.assertEqual(row['provider'],'github')
        self.assertEqual(row['sourceUrl'],'https://github.com/owner/example')
        self.assertEqual([x['version'] for x in row['releases']],['v1.0.0','v1.1.0'])
        self.assertTrue(all(x['url'].startswith('https://github.com/owner/example/releases/tag/') for x in row['releases']))
        self.assertEqual(len(self.calls),2);self.assertEqual(row['bindings'],{})
        self.assertEqual(stat.S_IMODE(self.catalog.path.stat().st_mode),0o600)
        self.assertEqual(ProjectCatalog(pathlib.Path(self.tmp.name),self.fetch).snapshot()[0]['id'],row['id'])
    def test_duplicate_add_does_not_fetch_or_erase_bindings(self):
        row=self.add();self.catalog.bind(row['id'],'s','v1.0.0');count=len(self.calls)
        second=self.add();self.assertEqual(len(self.calls),count);self.assertEqual(second['bindings']['s']['version'],'v1.0.0')
    def test_private_or_identity_mismatch_rejected(self):
        for changes in ({'private':True},{'full_name':'other/repo'}):
            self.info.update(changes)
            with self.assertRaises(ValueError):self.add()
            self.assertEqual(self.catalog.snapshot(),[]);self.info.update(private=False,full_name='owner/example')
    def test_network_error_does_not_persist_or_echo_secret(self):
        self.catalog.fetch=lambda url: (_ for _ in ()).throw(OSError('token=SECRET'))
        with self.assertRaises(ValueError) as error:self.add()
        self.assertNotIn('SECRET',str(error.exception));self.assertEqual(self.catalog.snapshot(),[])
    def test_remove_only_catalog_entry(self):
        row=self.add();self.catalog.remove(row['id']);self.assertEqual(self.catalog.snapshot(),[])
        with self.assertRaises(ValueError):self.catalog.remove(row['id'])
    def test_manual_binding_persisted_clearable(self):
        row=self.add();bound=self.catalog.bind(row['id'],'one','v1.0.0');self.assertEqual(bound['bindings']['one']['source'],'manual')
        second=ProjectCatalog(pathlib.Path(self.tmp.name),self.fetch)
        self.assertEqual(second.snapshot()[0]['bindings']['one']['version'],'v1.0.0')
        self.assertEqual(self.catalog.bind(row['id'],'one','')['bindings'],{})
    def test_bad_manual_versions_rejected(self):
        row=self.add()
        for version in (None,False,[],{},'v1;reboot','../etc','a\nb','a'*129):
            with self.assertRaises(ValueError):self.catalog.bind(row['id'],'one',version)
    def test_snapshots_not_mutable_aliases(self):
        row=self.add();row['name']='changed';snap=self.catalog.snapshot();snap[0]['bindings']['server']={}
        self.assertEqual(self.catalog.snapshot()[0]['name'],'Example');self.assertEqual(self.catalog.snapshot()[0]['bindings'],{})
    def test_known_source_has_existing_recipe(self):
        self.info['full_name']='alexeylcp/lucx-ui';row=self.catalog.add('https://github.com/AlexeyLCP/lucx-ui')
        self.assertEqual(row['recipeId'],'lucx')
    def test_refresh_cache_preserves_binding(self):
        row=self.add();self.catalog.bind(row['id'],'s','v1.0.0');n=len(self.calls)
        self.catalog.refresh();self.assertEqual(len(self.calls),n)
        self.info['description']='new';rows=self.catalog.refresh(True)
        self.assertEqual(rows[0]['description'],'new');self.assertIn('s',rows[0]['bindings'])
    def test_failed_refresh_stale_never_latest(self):
        row=self.add();self.catalog.bind(row['id'],'s','v1.1.0')
        self.catalog.fetch=lambda url: (_ for _ in ()).throw(OSError('offline'))
        updated=self.catalog.updates(True)[0]
        self.assertFalse(updated['ok']);self.assertTrue(updated['stale']);self.assertEqual(updated['bindings']['s']['updateStatus']['state'],'unknown')
        self.assertEqual(len(updated['releases']),2)
    def test_manual_comparison_highest_stable_not_first(self):
        row=self.add();self.catalog.bind(row['id'],'s','v1.0.0');status=self.catalog.updates()[0]['bindings']['s']['updateStatus']
        self.assertEqual(status['latest'],'v1.1.0');self.assertEqual(status['state'],'update_available');self.assertTrue(status['manual'])
    def test_manual_latest_no_server_verification_claim(self):
        row=self.add();self.catalog.bind(row['id'],'s','v1.1.0');status=self.catalog.updates()[0]['bindings']['s']['updateStatus']
        self.assertEqual(status['state'],'latest');self.assertIn('вручную',status['message'])
    def test_unrecognized_tag_never_latest(self):
        self.releases=[dict(tag_name='release-2026')];row=self.add();self.catalog.bind(row['id'],'s','release-2026')
        self.assertEqual(self.catalog.updates()[0]['bindings']['s']['updateStatus']['state'],'unknown')
    def test_gitlab_nested_project_official_link(self):
        calls=[]
        def fetch(url):
            calls.append(url)
            if '/releases?' in url:return [dict(tag_name='v1.0.0',released_at='2026-01-01',_links={'self':'javascript:x'}),dict(tag_name='v2.0.0',upcoming_release=True)]
            return dict(name='Repo',path_with_namespace='group/sub/repo',visibility='public',description='GitLab')
        self.catalog.fetch=fetch;row=self.catalog.add('https://gitlab.com/group/sub/repo.git')
        self.assertTrue(all(u.startswith('https://gitlab.com/api/v4/projects/group%2Fsub%2Frepo') for u in calls))
        self.assertEqual(row['releases'][0]['url'],'https://gitlab.com/group/sub/repo/-/releases/v1.0.0');self.assertEqual(len(row['releases']),1)

if __name__=='__main__':unittest.main()

class ControlProjectTests(unittest.TestCase):
    def test_control_catalog_mutations_never_ssh_or_run_code(self):
        from control import Control
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);(root/'control_remote.py').write_text('')
            server=dict(id='one',name='One',host='192.0.2.1',user='root',port=22,key='key')
            control=Control(root,lambda:[server],root)
            def fetch(url):return [] if '/releases?' in url else dict(name='Example',full_name='owner/example',private=False)
            control.projects.fetch=fetch
            with patch.object(control,'ssh',side_effect=AssertionError('SSH not allowed')):
                row=control.add_component({'url':'https://github.com/owner/example'})
                control.bind_component(dict(id=row['id'],server='one',version='v1.0.0'))
                self.assertEqual(control.projects.snapshot()[0]['bindings']['one']['source'],'manual')
                for data in ({'url':'https://github.com/owner/example','command':'reboot'},{'url':'https://github.com/owner/example','sources':{}}):
                    with self.assertRaises(ValueError):control.add_component(data)
                with self.assertRaises(ValueError):control.bind_component(dict(id=row['id'],server='missing',version='v1.0.0'))
                control.remove_component({'id':row['id']})
                self.assertEqual(control.projects.snapshot(),[])
