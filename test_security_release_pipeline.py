import copy
from alerts import AlertManager, RELEASE_CVE, RELEASE_SOURCE
from security_release import publication_events
from test_critical_alerts import CriticalFixture


class ReleasePipelineTests(CriticalFixture):
    def test_fresh_publication_for_six_hosts_sends_once_across_restart(self):
        self.critical()
        for number in range(2, 7):
            self.servers.append({'id': 'host'+str(number), 'name': 'VPS '+str(number), 'host': '192.0.2.'+str(number)})
        config=copy.deepcopy(self.manager.status()['config'])
        feed={'cve': RELEASE_CVE, 'sourceUrl': RELEASE_SOURCE, 'fixedPublished': True,
              'checking': False, 'stale': False, 'error': '', 'lastGoodAt': self.now,
              'notices': [{'acknowledged': True}], 'servers': [dict(s, ok=True, stale=False,
              error='', checkedAt=self.now, vendorStatus='released', state='published',
              sourcePackage='linux', releaseCodename='noble', fixedVersion='6.8.0-149.149',
              installedVersion='6.8.0-147.147', kernel='6.8.0-147-generic') for s in self.servers]}
        provider=lambda:publication_events(feed,self.servers,self.now)
        self.manager.security_release_fn=provider
        self.assertEqual(len(provider()),1)
        self.manager.tick()
        self.assertEqual(len(self.telegram.sent),1)
        self.assertEqual(self.manager.status()['config'],config)
        for s in self.servers:self.assertIn(s['host'],self.telegram.sent[0]['text'])
        self.now+=31
        self.manager.tick()
        self.manager=AlertManager(self.root,lambda:self.servers,lambda:self.report,self.token_path,
            transport=self.telegram,clock=lambda:self.now,security_release_fn=provider)
        self.manager.tick()
        self.assertEqual(len(self.telegram.sent),1)
        self.assertEqual(len(self.manager.state['securityReleaseEvents']),1)
        self.assertFalse(self.manager.state['queue'])
