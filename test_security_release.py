"""Pure publication-event contract: no network, SSH, timers or Telegram."""
import copy
import random
import unittest
from unittest.mock import patch

from security_release import publication_events
from security_updates import CLOCK_SKEW, CVE, SOURCE_URL, STALE


class SecurityReleaseTests(unittest.TestCase):
    NOW = 100000

    def setUp(self):
        self.registry = [dict(id='host-' + str(i), name='Current server ' + str(i),
                              host='203.0.113.' + str(i + 1)) for i in range(6)]
        self.feed = dict(cve=CVE, sourceUrl=SOURCE_URL, fixedPublished=True,
                         checking=False, stale=False, error='', lastGoodAt=self.NOW - 10,
                         notices=[], servers=[self.row(server) for server in self.registry])

    def row(self, server, **changes):
        row = dict(id=server['id'], name='Old cached name', host=server['host'],
                   ok=True, stale=False, error='', vendorStatus='released',
                   state='published', checkedAt=self.NOW - 20, sourcePackage='linux',
                   releaseCodename='noble', fixedVersion='6.8.0-149.149',
                   installedVersion='6.8.0-147.147', kernel='6.8.0-147-generic')
        row.update(changes)
        return row

    def events(self, feed=None, registry=None, now=None):
        return publication_events(self.feed if feed is None else feed,
                                  self.registry if registry is None else registry,
                                  self.NOW if now is None else now)

    def test_six_hosts_emit_one_publication_with_current_registry_identity(self):
        events = self.events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual((event['cve'], event['sourcePackage'], event['releaseCodename'],
                          event['fixedVersion'], event['sourceUrl']),
                         (CVE, 'linux', 'noble', '6.8.0-149.149', SOURCE_URL))
        self.assertEqual([row['id'] for row in event['servers']],
                         [server['id'] for server in self.registry])
        self.assertEqual(event['servers'][0]['name'], 'Current server 0')
        self.assertEqual(event['checkedAt'], self.NOW - 20)

    def test_mixed_kernel_sources_are_two_groups_not_six_host_notifications(self):
        for row in self.feed['servers'][3:]:
            row.update(sourcePackage='linux-aws', fixedVersion='6.8.0-1069.74')
        events = self.events()
        self.assertEqual([(event['sourcePackage'], len(event['servers'])) for event in events],
                         [('linux', 3), ('linux-aws', 3)])

    def test_release_and_fix_version_are_each_part_of_group_identity(self):
        self.feed['servers'][1]['releaseCodename'] = 'jammy'
        self.feed['servers'][2]['fixedVersion'] = '6.8.0-150.150'
        events = self.events()
        self.assertEqual(len(events), 3)
        self.assertEqual({(event['sourcePackage'], event['releaseCodename'], event['fixedVersion'])
                          for event in events},
                         {('linux', 'noble', '6.8.0-149.149'),
                          ('linux', 'jammy', '6.8.0-149.149'),
                          ('linux', 'noble', '6.8.0-150.150')})

    def test_panel_acknowledgement_does_not_suppress_independent_channel_event(self):
        expected = self.events()
        self.feed['notices'] = [dict(id='a' * 64, acknowledged=True, cve=CVE,
                                    title='Already read in the panel')]
        self.feed['acknowledged'] = True
        for row in self.feed['servers']:
            row['acknowledged'] = True
        self.assertEqual(self.events(), expected)
        self.feed['notices'][0]['acknowledged'] = False
        self.assertEqual(self.events(), expected)

    def test_historical_notices_cannot_create_current_publication(self):
        self.feed['notices'] = [dict(id='b' * 64, acknowledged=False, cve=CVE,
                                    title='Historical published fix')]
        self.feed['servers'] = []
        self.assertEqual(self.events(), [])
        self.feed['servers'] = [self.row(self.registry[0], state='awaiting_release',
                                         vendorStatus='pending')]
        self.assertEqual(self.events(), [])

    def test_exact_cve_and_official_source_url_are_required(self):
        for key, value in [('cve', 'CVE-2026-00000'), ('cve', CVE.lower()),
                           ('sourceUrl', 'https://evil.example/' + CVE + '.json'),
                           ('sourceUrl', SOURCE_URL + '?redirect=elsewhere'),
                           ('sourceUrl', SOURCE_URL.replace('https:', 'http:'))]:
            with self.subTest(key=key, value=value):
                altered = copy.deepcopy(self.feed)
                altered[key] = value
                self.assertEqual(self.events(altered), [])

    def test_top_level_success_requires_explicit_boolean_evidence(self):
        for key, value in [('fixedPublished', False), ('fixedPublished', None),
                           ('fixedPublished', 1), ('checking', True), ('checking', 0),
                           ('stale', True), ('stale', 0), ('error', 'refresh failed')]:
            with self.subTest(key=key, value=value):
                altered = copy.deepcopy(self.feed)
                altered[key] = value
                self.assertEqual(self.events(altered), [])
        for key in ('fixedPublished', 'checking', 'stale', 'lastGoodAt'):
            with self.subTest(missing=key):
                altered = copy.deepcopy(self.feed)
                del altered[key]
                self.assertEqual(self.events(altered), [])

    def test_global_data_older_than_three_hours_is_not_a_release_event(self):
        self.feed['lastGoodAt'] = self.NOW - STALE - .01
        self.assertEqual(self.events(), [])
        self.feed['lastGoodAt'] = self.NOW - STALE
        self.assertEqual(len(self.events()), 1)

    def test_future_cache_or_host_timestamp_beyond_clock_skew_is_rejected(self):
        self.feed['lastGoodAt'] = self.NOW + CLOCK_SKEW + .01
        self.assertEqual(self.events(), [])
        self.feed['lastGoodAt'] = self.NOW + CLOCK_SKEW
        self.assertEqual(len(self.events()), 1)
        self.feed['servers'] = [self.row(self.registry[0], checkedAt=self.NOW + CLOCK_SKEW + .01)]
        self.assertEqual(self.events(), [])
        self.feed['servers'][0]['checkedAt'] = self.NOW + CLOCK_SKEW
        self.assertEqual(len(self.events()), 1)

    def test_invalid_timestamp_types_never_become_fresh(self):
        for value in (None, True, '100000', float('nan'), float('inf')):
            with self.subTest(value=repr(value)):
                altered = copy.deepcopy(self.feed)
                altered['lastGoodAt'] = value
                self.assertEqual(self.events(altered), [])
                altered = copy.deepcopy(self.feed)
                altered['servers'] = [self.row(self.registry[0], checkedAt=value)]
                self.assertEqual(self.events(altered), [])
                if value is not None:
                    self.assertEqual(publication_events(self.feed, self.registry, value), [])

    def test_only_fresh_unfixed_released_hosts_are_eligible(self):
        rejected = [dict(ok=False), dict(ok=1), dict(stale=True), dict(stale=0),
                    dict(error='SSH failed'), dict(vendorStatus='pending'),
                    dict(vendorStatus='needed'), dict(vendorStatus='not-affected'),
                    dict(state='fixed'), dict(state='awaiting_release'), dict(state='unknown'),
                    dict(state='unsupported'), dict(state='available'),
                    dict(checkedAt=self.NOW - STALE - 1)]
        for changes in rejected:
            with self.subTest(changes=changes):
                altered = copy.deepcopy(self.feed)
                altered['servers'] = [self.row(self.registry[0], **changes)]
                self.assertEqual(self.events(altered), [])

    def test_reboot_required_and_published_share_one_release_event(self):
        self.feed['servers'][0]['state'] = 'reboot_required'
        self.feed['servers'][1]['state'] = 'fixed'
        events = self.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(len(events[0]['servers']), 5)
        self.assertEqual(events[0]['servers'][0]['state'], 'reboot_required')

    def test_invalid_source_release_version_or_kernel_cannot_forge_evidence(self):
        invalid = [('sourcePackage', 'openssl'), ('sourcePackage', 'linux;reboot'),
                   ('sourcePackage', ''), ('releaseCodename', 'Noble'),
                   ('releaseCodename', '../noble'), ('fixedVersion', None),
                   ('fixedVersion', '6.8.0-149.149 (work in progress)'),
                   ('fixedVersion', '$(command)'), ('installedVersion', None),
                   ('installedVersion', 'not-a-version'), ('kernel', None),
                   ('kernel', '6.8.0-147-generic\nforged')]
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                altered = copy.deepcopy(self.feed)
                altered['servers'] = [self.row(self.registry[0], **{key: value})]
                self.assertEqual(self.events(altered), [])

    def test_removed_or_replaced_host_cannot_inherit_a_release_notice(self):
        self.feed['servers'] = [self.row(self.registry[0])]
        self.assertEqual(self.events(registry=self.registry[1:]), [])
        replacement = copy.deepcopy(self.registry)
        replacement[0]['host'] = '198.51.100.77'
        self.assertEqual(self.events(registry=replacement), [])
        replacement[0]['host'] = self.registry[0]['host']
        replacement[0]['id'] = 'replacement-id'
        self.assertEqual(self.events(registry=replacement), [])

    def test_current_registry_name_wins_and_membership_does_not_change_group_identity(self):
        first = self.events()[0]
        reduced = self.events(registry=self.registry[1:])[0]
        identity = lambda event: tuple(event[key] for key in
                                       ('cve', 'sourcePackage', 'releaseCodename', 'fixedVersion'))
        self.assertEqual(identity(first), identity(reduced))
        self.assertEqual(len(reduced['servers']), 5)
        self.assertTrue(all(row['name'].startswith('Current server ') for row in reduced['servers']))

    def test_duplicate_ids_fail_closed_instead_of_multiplying_notifications(self):
        duplicate = copy.deepcopy(self.feed)
        duplicate['servers'].append(copy.deepcopy(duplicate['servers'][0]))
        self.assertEqual(self.events(duplicate), [])
        self.assertEqual(self.events(registry=self.registry + [self.registry[0]]), [])

    def test_output_order_is_deterministic_across_registry_and_feed_reordering(self):
        self.feed['servers'][0].update(sourcePackage='linux-aws', fixedVersion='6.8.0-1069.74')
        self.feed['servers'][1].update(releaseCodename='jammy', fixedVersion='5.15.0-203.213')
        expected = self.events()
        rng = random.Random(42)
        for _ in range(8):
            feed = copy.deepcopy(self.feed)
            registry = copy.deepcopy(self.registry)
            rng.shuffle(feed['servers'])
            rng.shuffle(registry)
            self.assertEqual(self.events(feed, registry), expected)

    def test_producer_does_not_mutate_inputs_or_invoke_external_lookups(self):
        feed, registry = copy.deepcopy(self.feed), copy.deepcopy(self.registry)
        with patch('security_updates.subprocess.run', side_effect=AssertionError('No commands')), \
                patch('security_updates.urllib.request.urlopen', side_effect=AssertionError('No network')):
            self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.feed, feed)
        self.assertEqual(self.registry, registry)


if __name__ == '__main__':
    unittest.main()
