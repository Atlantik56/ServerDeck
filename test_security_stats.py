import copy
import hashlib
import json
import pathlib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from security_stats import SecurityStats, SecurityStatsError, MAX_BANS, MAX_EVENTS


class SecurityStatsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temp.name) / 'stats.sqlite3'
        self.now = 1800000000.0
        self.stats = SecurityStats(self.path, clock=lambda: self.now)
        self.servers = [{'id': 'one', 'name': 'One', 'host': '192.0.2.1'}]

    def tearDown(self):
        self.temp.cleanup()

    def payload(self, packets=100, events=None, local=None, shared=None, **changes):
        value = {'collectedAt': self.now, 'bootId': 'boot-a', 'counterEpoch': 'nft-a',
                 'counters': {'blockedPackets': packets, 'blockedBytes': packets * 10},
                 'events': events or [], 'bans': {'local': local or [], 'shared': shared or []}}
        value.update(changes)
        return value

    def event(self, identity='cursor-a', kind='failed_password', address='8.8.8.8', ts=None, count=1):
        return {'id': identity, 'kind': kind, 'sourceIp': address, 'ts': self.now if ts is None else ts, 'count': count}

    def one(self, hours=24):
        return self.stats.report(self.servers, hours)['servers'][0]

    def test_duplicate_events_samples_and_stable_bans_are_not_recounted(self):
        event = self.event()
        payload = self.payload(events=[event], local=['8.8.8.8'])
        self.assertEqual(self.stats.ingest('one', payload)['newEvents'], 1)
        self.stats.ingest('one', payload)
        self.now += 60
        result = self.stats.ingest('one', self.payload(110, events=[event], local=['8.8.8.8']))
        self.assertEqual(result['newEvents'], 0)
        row = self.one()
        self.assertEqual(row['ssh']['failedPasswords'], 1)
        self.assertEqual(row['firewall']['delta'], 10)
        self.assertEqual(len(row['banHistory']), 1)
        self.assertEqual(row['banHistory'][0]['action'], 'baseline')
        self.assertEqual(row['bans'][0]['since'], None)
        self.assertLess(row['bans'][0]['firstObservedAt'], self.now)

    def test_categories_do_not_sum_overlapping_authentication_messages(self):
        events = [self.event('a'), self.event('b', 'invalid_user'), self.event('c', 'failed_publickey')]
        self.stats.ingest('one', self.payload(events=events))
        row = self.one()
        self.assertEqual(row['ssh']['failedPasswords'], 1)
        self.assertEqual(row['ssh']['invalidUsers'], 1)
        self.assertEqual(row['ssh']['failedPublickeys'], 1)
        self.assertEqual(row['sources'][0]['attempts'], 1)
        self.assertEqual(row['sources'][0]['invalidUsers'], 1)

    def test_exact_window_boundary_and_no_invented_prehistory(self):
        events = [self.event('inside', ts=self.now - 3600), self.event('outside', ts=self.now - 3600.01)]
        self.stats.ingest('one', self.payload(events=events))
        self.assertEqual(self.one(1)['ssh']['failedPasswords'], 1)
        self.assertEqual(self.one(24)['ssh']['failedPasswords'], 2)
        self.assertEqual(self.one(168)['ssh']['failedPasswords'], 2)
        self.assertTrue(self.one()['coverage']['noPrehistory'])
        blank = self.stats.report([{'id': 'other'}], 1)['servers'][0]
        self.assertEqual(blank['history'], [])
        self.assertIsNone(blank['ssh']['failedPasswords'])
        self.assertTrue(blank['stale'])
        with self.assertRaises(ValueError): self.one(2)

    def test_counter_baseline_resets_boot_epoch_decrease_and_gap(self):
        self.stats.ingest('one', self.payload())
        self.assertIsNone(self.one()['firewall']['delta'])
        self.assertTrue(self.one()['firewall']['counterReset'])
        self.now += 60; self.stats.ingest('one', self.payload(120))
        self.assertEqual(self.one()['firewall']['delta'], 20)
        for changes, packets, reason in [({'bootId': 'boot-b'}, 200, 'boot_changed'),
                                         ({'bootId': 'boot-b', 'counterEpoch': 'nft-b'}, 210, 'counter_epoch_changed'),
                                         ({'bootId': 'boot-b', 'counterEpoch': 'nft-b'}, 5, 'counter_decreased')]:
            self.now += 60; self.stats.ingest('one', self.payload(packets, **changes))
            self.assertIsNone(self.one()['firewall']['delta'])
            self.assertEqual(self.one()['firewall']['resetReason'], reason)
        self.now += 181; self.stats.ingest('one', self.payload(15, bootId='boot-b', counterEpoch='nft-b'))
        self.assertEqual(self.one()['firewall']['resetReason'], 'collection_gap')
        self.assertEqual(self.one()['firewall']['windowBlockedPackets'], 20)

    def test_counter_boundary_interval_is_excluded_not_assigned_to_requested_window(self):
        self.now -= 3601; self.stats.ingest('one', self.payload(100))
        self.now += 60; self.stats.ingest('one', self.payload(125))
        self.now += 3541
        row = self.one(1)
        self.assertIsNone(row['firewall']['windowBlockedPackets'])
        self.assertEqual(row['firewall']['boundaryIntervalsExcluded'], 1)

    def test_partial_collector_error_keeps_last_good_bans_and_counter(self):
        event = self.event()
        self.stats.ingest('one', self.payload(events=[event], local=['8.8.8.8']))
        self.now += 60
        self.stats.ingest('one', {'bootId': 'boot-a', 'counterEpoch': 'nft-a', 'events': [],
                                 'errors': {'counters': 'nft unavailable', 'localBans': 'timeout'}})
        row = self.one()
        self.assertEqual(row['firewall']['blockedPackets'], 100)
        self.assertIsNone(row['firewall']['delta'])
        self.assertEqual(row['activeBlockedIpCount'], 1)
        self.assertIn('timeout', row['error'])
        self.assertTrue(row['partial'])
        # SSH events were collected successfully; a separate nft failure does
        # not erase that observation from the bot's SSH-only summary.
        self.assertTrue(self.stats.alert_summary(self.servers)['servers'][0]['ok'])
        self.now += 60; self.stats.ingest('one', self.payload(130, local=['8.8.8.8']))
        self.assertEqual(self.one()['firewall']['delta'], 30)
        self.assertFalse(self.one()['partial'])

    def test_failed_collection_preserves_data_and_marks_last_attempt_and_staleness(self):
        self.stats.ingest('one', self.payload(local=['8.8.8.8']))
        first = self.now
        self.now += 60; self.stats.ingest_error('one', 'SSH timeout')
        row = self.one()
        self.assertEqual(row['checkedAt'], self.now)
        self.assertEqual(row['lastGoodAt'], first)
        self.assertEqual(row['activeBlockedIpCount'], 1)
        self.assertIn('SSH timeout', row['error'])
        self.assertFalse(self.stats.alert_summary(self.servers)['servers'][0]['ok'])
        self.now += 121
        self.assertTrue(self.one()['stale'])

    def test_late_delivery_adds_deduplicated_events_without_rewinding_bans(self):
        self.stats.ingest('one', self.payload(100, local=['8.8.8.8']))
        old_time = self.now
        self.now += 60; self.stats.ingest('one', self.payload(120, local=['1.1.1.1']))
        result = self.stats.ingest('one', self.payload(50, events=[self.event('older', ts=old_time)], local=[]), collected_at=old_time)
        self.assertTrue(result['lateDelivery'])
        row = self.one()
        self.assertEqual(row['firewall']['blockedPackets'], 120)
        self.assertEqual(row['bans'][0]['ip'], '1.1.1.1')
        self.assertEqual(row['ssh']['failedPasswords'], 1)

    def test_local_shared_union_and_verified_permanence(self):
        self.stats.ingest('one', self.payload(local=[{'ip': '8.8.8.8', 'jail': 'sshd', 'permanent': True}],
                                            shared=[{'ip': '8.8.8.8', 'jail': 'shared', 'expiresAt': self.now + 600}]))
        row = self.one(); banned = row['bans'][0]
        self.assertEqual(row['activeBlockedIpCount'], 1)
        self.assertEqual(row['activeLocalBans'], 1)
        self.assertEqual(row['activeSharedBans'], 1)
        self.assertEqual(banned['source'], 'both')
        self.assertTrue(banned['permanent'])
        self.assertIsNone(banned['expiresAt'])
        self.assertIsNone(banned['remainingSeconds'])

    def test_shared_ban_alert_counts_global_ip_once_and_initial_state_quiet(self):
        self.stats.ingest('one', self.payload(shared=['8.8.8.8']))
        self.assertEqual(self.stats.alert_summary(self.servers)['totals']['newSharedBans10m'], 0)
        self.assertIsNone(self.stats.alert_summary(self.servers)['newestEventAt'])
        self.stats.ingest('two', self.payload(shared=[]))
        self.now += 60
        self.stats.ingest('one', self.payload(shared=['8.8.8.8', '1.1.1.1']))
        self.stats.ingest('two', self.payload(shared=['1.1.1.1']))
        registry = self.servers + [{'id': 'two'}]
        summary = self.stats.alert_summary(registry)
        self.assertEqual(summary['totals']['newSharedBans10m'], 1)
        newest = summary['newestEventAt']
        self.now += 60
        self.stats.ingest('one', self.payload(shared=['8.8.8.8', '1.1.1.1']))
        self.assertEqual(self.stats.alert_summary(registry)['newestEventAt'], newest)
        self.stats.ingest('two', self.payload(shared=[]))
        self.assertEqual(self.stats.alert_summary(registry)['totals']['newSharedBans10m'], 1)

    def test_alert_packet_rate_requires_fresh_comparable_interval(self):
        self.stats.ingest('one', self.payload(100))
        self.assertIsNone(self.stats.alert_summary(self.servers)['servers'][0]['blockedPacketsPerMinute'])
        self.now += 120; self.stats.ingest('one', self.payload(500))
        self.assertEqual(self.stats.alert_summary(self.servers)['servers'][0]['blockedPacketsPerMinute'], 200)
        self.now += 181
        self.assertIsNone(self.stats.alert_summary(self.servers)['servers'][0]['blockedPacketsPerMinute'])
        self.stats.ingest('one', self.payload(600))
        self.assertIsNone(self.stats.alert_summary(self.servers)['servers'][0]['blockedPacketsPerMinute'])

    def test_alert_summary_excludes_servers_outside_requested_registry(self):
        self.stats.ingest('one', self.payload())
        self.stats.ingest('two', self.payload())
        self.now += 60; self.stats.ingest('two', self.payload(shared=['8.8.8.8'], events=[self.event()]))
        summary = self.stats.alert_summary(self.servers)
        self.assertEqual(summary['totals']['newSharedBans10m'], 0)
        self.assertIsNone(summary['newestEventAt'])
        self.assertEqual(self.stats.alert_summary([{'id': 'two'}])['totals']['newSharedBans10m'], 1)

    def test_alert_newest_ignores_invalid_user_publickey_and_unban_events(self):
        meaningful = self.event('password', ts=self.now - 60)
        others = [self.event('invalid', 'invalid_user'), self.event('publickey', 'failed_publickey'), self.event('unban', 'unban')]
        self.stats.ingest('one', self.payload(events=[meaningful] + others))
        self.assertEqual(self.stats.alert_summary(self.servers)['newestEventAt'], meaningful['ts'])

    def test_verified_expiry_removes_active_bans_from_report_and_alert_summary(self):
        self.stats.ingest('one', self.payload(shared=[
            {'ip': '8.8.8.8', 'expiresAt': self.now + 30, 'permanent': False},
            {'ip': '1.1.1.1', 'remainingSeconds': 30},
            {'ip': '9.9.9.9', 'permanent': True},
            {'ip': '4.2.2.2'}]))
        self.assertEqual(self.one()['activeSharedBans'], 4)
        self.now += 31
        self.assertEqual(self.one()['activeSharedBans'], 2)
        self.assertEqual(self.stats.alert_summary(self.servers)['servers'][0]['activeSharedBans'], 2)
        self.assertEqual({v['ip'] for v in self.one()['bans']}, {'9.9.9.9', '4.2.2.2'})

    def test_expired_ip_rebanned_between_polls_gets_one_new_episode_globally(self):
        entry = {'ip': '8.8.8.8', 'expiresAt': self.now + 30, 'permanent': False}
        self.stats.ingest('one', self.payload(shared=[entry]))
        self.stats.ingest('two', self.payload(shared=[entry]))
        first_seen = self.one()['bans'][0]['firstObservedAt']
        self.now += 31
        new_entry = dict(entry, expiresAt=self.now + 600)
        self.stats.ingest('one', self.payload(shared=[new_entry]))
        registry = self.servers + [{'id': 'two'}]
        self.assertEqual(self.stats.alert_summary(registry)['totals']['newSharedBans10m'], 1)
        self.assertGreater(self.one()['bans'][0]['firstObservedAt'], first_seen)
        self.now += 60; self.stats.ingest('two', self.payload(shared=[new_entry]))
        self.assertEqual(self.stats.alert_summary(registry)['totals']['newSharedBans10m'], 1)
        self.assertEqual(self.one()['activeSharedBans'], 1)

    def test_metadata_lookup_queue_cache_and_errors_preserve_original_good_time(self):
        self.stats.ingest('one', self.payload(events=[self.event(), self.event('private', address='10.0.0.1')]))
        self.assertEqual(self.stats.metadata_due(), ['8.8.8.8'])
        original = self.now - 50
        self.stats.upsert_metadata('8.8.8.8', {'asn': ['15169', 'AS1'], 'network': 'GOOGLE', 'prefix': '8.8.8.0/24',
                                            'country': 'US, NL', 'countrySource': 'RIPE WHOIS', 'lookupAt': original})
        self.assertEqual(self.stats.metadata_due(), [])
        self.now += 60; self.stats.upsert_metadata('8.8.8.8', error='RIPE timeout')
        row = next(v for v in self.one()['sources'] if v['ip'] == '8.8.8.8')
        self.assertEqual(row['lookupAt'], original)
        self.assertEqual(row['lookupError'], 'RIPE timeout')
        self.assertEqual(row['asn'], 'AS1, AS15169')
        self.assertEqual(row['network'], 'GOOGLE')
        self.assertEqual(row['country'], 'NL, US')
        self.assertEqual(self.stats.metadata_due(), [])
        self.now += 901; self.assertEqual(self.stats.metadata_due(), ['8.8.8.8'])
        with self.assertRaises(ValueError): self.stats.upsert_metadata('8.8.8.8', {'prefix': '1.1.1.0/24'})
        with self.assertRaises(ValueError): self.stats.metadata_due(limit=10000)

    def test_bounded_and_invalid_payloads_preserve_prior_component_snapshot(self):
        self.stats.ingest('one', self.payload(local=['8.8.8.8']))
        self.now += 60
        too_many = ['1.1.1.1'] * (MAX_BANS + 1)
        result = self.stats.ingest('one', self.payload(local=too_many, events=[self.event()] * (MAX_EVENTS + 1)))
        self.assertTrue(result['partial'])
        self.assertEqual(self.one()['bans'][0]['ip'], '8.8.8.8')
        self.now += 60
        result = self.stats.ingest('one', self.payload(local=['not an IP']))
        self.assertTrue(result['partial'])
        self.assertEqual(self.one()['activeBlockedIpCount'], 1)
        with self.assertRaises(ValueError): self.stats.ingest('../bad', self.payload())

    def test_explicit_truncated_event_delivery_keeps_newest_records_and_valid_counters(self):
        events = [self.event('storm-' + str(i), ts=self.now - 60 + i / 10000) for i in range(MAX_EVENTS + 1)]
        result = self.stats.ingest('one', self.payload(100, events=events, eventsTruncated=True))
        self.assertEqual(result['newEvents'], MAX_EVENTS)
        self.assertTrue(result['partial'])
        row = self.one(1)
        self.assertTrue(row['ssh']['truncated'])
        self.assertEqual(row['ssh']['failedPasswords'], MAX_EVENTS)
        self.assertEqual(row['firewall']['blockedPackets'], 100)
        self.assertTrue(row['partial'])
        self.assertTrue(self.stats.alert_summary(self.servers)['servers'][0]['eventsTruncated10m'])
        self.now += 60; self.stats.ingest('one', self.payload(150))
        self.assertEqual(self.one(1)['firewall']['delta'], 50)
        self.assertTrue(self.one(1)['ssh']['truncated'])
        self.now += 3601; self.stats.ingest('one', self.payload(160))
        self.assertFalse(self.one(1)['ssh']['truncated'])
        self.assertTrue(self.one(24)['ssh']['truncated'])
        self.assertFalse(self.stats.alert_summary(self.servers)['servers'][0]['eventsTruncated10m'])

    def test_event_storage_cap_marks_only_overlapping_windows_as_lower_bounds(self):
        events = [self.event('old-a', ts=self.now - 4000), self.event('old-b', ts=self.now - 3990),
                  self.event('new-a', ts=self.now - 100), self.event('new-b', ts=self.now - 90)]
        with patch('security_stats.MAX_STORED_EVENTS', 2):
            self.stats.ingest('one', self.payload(events=events))
        hour = self.one(1); day = self.one(24)
        self.assertEqual(hour['ssh']['failedPasswords'], 2)
        self.assertFalse(hour['ssh']['truncated'])
        self.assertFalse(hour['coverage']['retentionClipped'])
        self.assertEqual(day['ssh']['failedPasswords'], 2)
        self.assertTrue(day['ssh']['truncated'])
        self.assertTrue(day['partial'])
        self.assertTrue(day['coverage']['eventsLowerBound'])
        self.assertTrue(day['coverage']['retentionClipped'])
        self.assertEqual(day['coverage']['retentionClippedFrom'], self.now - 4000)
        self.assertEqual(day['coverage']['retentionClippedUntil'], self.now - 3990)
        self.assertEqual(day['historyStartedAt'], self.now - 4000)
        missing = next(row for row in day['history'] if row['eventsTruncated'])
        self.assertIsNone(missing['failedPasswords'])
        self.assertFalse(self.stats.alert_summary(self.servers)['servers'][0]['eventsTruncated10m'])
        self.now += 60
        with patch('security_stats.MAX_STORED_EVENTS', 2):
            self.stats.ingest('one', self.payload(150, events=[self.event('fresh')]))
        self.assertTrue(self.one(1)['ssh']['truncated'])
        self.assertTrue(self.stats.alert_summary(self.servers)['servers'][0]['eventsTruncated10m'])

    def test_explicit_journal_coverage_gap_persists_after_good_resume(self):
        first = self.now
        self.stats.ingest('one', self.payload(eventsWindowStart=first - 60, eventsWindowEnd=first))
        self.assertEqual(self.one()['historyStartedAt'], first - 60)
        self.now += 7200
        self.stats.ingest('one', self.payload(200, eventsWindowStart=self.now - 3600, eventsWindowEnd=self.now))
        hour, day = self.one(1), self.one(24)
        self.assertFalse(hour['ssh']['truncated'])
        self.assertEqual(hour['coverage']['eventsMissingRanges'], [])
        self.assertTrue(day['ssh']['truncated'])
        self.assertTrue(day['partial'])
        self.assertEqual(day['coverage']['eventsMissingRanges'], [[first, first + 3600]])
        self.assertFalse(self.stats.alert_summary(self.servers)['servers'][0]['eventsTruncated10m'])
        self.now += 60
        self.stats.ingest('one', self.payload(250, eventsWindowStart=self.now - 3600, eventsWindowEnd=self.now))
        self.assertFalse(self.one(1)['ssh']['truncated'])
        self.assertTrue(self.one(24)['ssh']['truncated'])

    def test_two_store_instances_deduplicate_shared_database(self):
        other = SecurityStats(self.path, clock=lambda: self.now)
        event = self.event()
        self.stats.ingest('one', self.payload(events=[event]))
        self.assertEqual(other.ingest('one', self.payload(events=[event]))['newEvents'], 0)
        self.assertEqual(other.report(self.servers)['servers'][0]['ssh']['failedPasswords'], 1)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_reports_are_read_only_and_unknown_metadata_is_not_country_guessed(self):
        self.stats.ingest('one', self.payload(events=[self.event()]))
        before = self.path.read_bytes()
        row = self.one(); self.stats.alert_summary(self.servers)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertIsNone(row['sources'][0]['country'])
        self.assertIsNone(row['sources'][0]['lookupAt'])
        with self.stats._connect(readonly=True) as c:
            with self.assertRaises(sqlite3.OperationalError): c.execute('DELETE FROM events')

    def test_retention_prunes_only_old_history_and_new_error_is_not_healthy(self):
        self.stats.ingest('one', self.payload(events=[self.event()]))
        self.now += 8 * 86400
        self.stats.ingest_error('one', 'collector stopped')
        row = self.one(168)
        self.assertEqual(row['history'], [])
        self.assertTrue(row['stale'])
        self.assertEqual(row['sources'], [])
        self.assertIsNone(row['firewall']['windowBlockedPackets'])

    def test_corrupt_database_is_reported_and_never_replaced(self):
        corrupt = pathlib.Path(self.temp.name) / 'corrupt.sqlite3'
        content = b'not-a-sqlite-database\x00' * 10; corrupt.write_bytes(content)
        stats = SecurityStats(corrupt, clock=lambda: self.now)
        report = stats.report(self.servers)
        self.assertIn('storageError', report)
        self.assertTrue(report['servers'][0]['stale'])
        self.assertFalse(stats.alert_summary(self.servers)['servers'][0]['ok'])
        self.assertEqual(corrupt.read_bytes(), content)
        with self.assertRaises(SecurityStatsError): stats.ingest('one', self.payload())


if __name__ == '__main__':
    unittest.main()
