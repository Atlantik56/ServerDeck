"""Server registry actions verify SSH and operate on fixture key files only."""
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import keypairs
import public_access
import server


class RegistryRoutes(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.keydir = self.root / 'keys'
        self.keydir.mkdir(mode=0o700)
        self.first = dict(id='first', name='First', host='192.0.2.10', port=22, user='root',
                          key='imported-old', services=['ssh.service'], panels=[dict(name='Web', url='https://example.test')])
        self.second = dict(id='second', name='Second', host='192.0.2.20', port=22, user='root',
                           key='other', services=[])
        self.control = SimpleNamespace(busy=set(), jobs={}, plans={}, clients_cache={}, software_cache={})
        patches = patch.multiple(server, CONFIG=self.root/'servers.json', ROOT=self.root, KEYDIR=self.keydir,
                                 CONTROL=self.control, EMBEDDED=None, CACHE={}, BUSY=set(), TUNNELS={},
                                 REFRESH_LOCKS={}, KEY_TESTS={})
        patches.start()
        self.addCleanup(patches.stop)
        access = patch.multiple(public_access, ORIGIN='https://deck.example.test', HOST='deck.example.test', GATEWAY='fixture')
        access.start()
        self.addCleanup(access.stop)
        server.write_config([self.first, self.second])

    def key(self, name, comment='external test key'):
        path = self.keydir / name
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', comment, '-f', str(path)], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return path

    def request(self, path, body=None, **headers):
        handler = object.__new__(server.Handler)
        handler.path = path
        handler.server = SimpleNamespace(server_port=8765)
        defaults = {'Host':'deck.example.test', 'Origin':'https://deck.example.test',
                    'X-Deck-Token':server.TOKEN, 'X-Deck-Gateway':'fixture'}
        handler.headers = dict(defaults, **headers)
        handler.reply = Mock(side_effect=lambda code, result: (code, result))
        if body is None:
            return handler.do_GET()
        payload = json.dumps(body).encode()
        handler.headers['Content-Length'] = str(len(payload))
        handler.rfile = io.BytesIO(payload)
        return handler.do_POST()

    def settings(self, **changes):
        values = {key:self.first[key] for key in ('name','host','port','user','key')}
        return dict(values, server='first', **changes)

    def test_mutations_keep_gateway_origin_and_token_guards(self):
        for endpoint in ('/api/servers/update','/api/servers/remove','/api/keys/remove'):
            for header in ('Host','Origin','X-Deck-Token','X-Deck-Gateway'):
                with self.subTest(endpoint=endpoint, header=header):
                    self.assertEqual(self.request(endpoint, {}, **{header:'wrong'})[0], 403)
        self.assertEqual(self.request('/api/keys', **{'X-Deck-Token':'wrong'})[0], 403)

    def test_connection_edit_rejects_failed_ssh_before_changing_registry(self):
        self.key('new-key')
        settings = self.settings(key='new-key')
        with patch.object(server, 'ssh', side_effect=RuntimeError('Host key verification failed')) as ssh:
            self.assertEqual(self.request('/api/servers/update',settings)[0],400)
        self.assertEqual(server.find('first'), self.first)
        self.assertEqual(server.KEY_TESTS, {})
        self.assertEqual(ssh.call_args.kwargs, {'isolated': True})

    def test_connection_edit_preserves_existing_settings_and_detaches_cached_access(self):
        self.key('new-key')
        self.control.clients_cache['first'] = {'old':True}
        self.control.software_cache['first'] = {'old':True}
        self.control.plans['old'] = {'server':'first'}
        server.CACHE['first'] = {'old':True}
        tunnel = Mock()
        tunnel.poll.return_value = None
        server.TUNNELS[('first',80,'http','/')] = (tunnel, 'http://localhost')
        bridge = Mock()
        with patch.object(server, 'EMBEDDED', bridge), patch.object(server, 'ssh', return_value={'units': ['ignored']}) as ssh:
            result = self.request('/api/servers/update', self.settings(key='new-key', name='Renamed'))
        self.assertEqual(result, (200, {'ok': True, 'server': 'first'}))
        self.assertEqual(server.find('first'), dict(self.first, key='new-key', name='Renamed'))
        self.assertEqual(ssh.call_args.kwargs, {'isolated': True})
        self.assertEqual(ssh.call_args.args[1], {'action':'inventory'})
        self.assertFalse(self.control.clients_cache or self.control.software_cache or self.control.plans or server.CACHE)
        tunnel.terminate.assert_called_once()
        bridge.close_server.assert_called_once_with('first', ['192.0.2.10',22,'root','imported-old'])

    def test_name_only_edit_can_fix_a_disconnected_servers_label(self):
        with patch.object(server, 'ssh') as ssh:
            self.assertEqual(self.request('/api/servers/update', self.settings(name='Renamed'))[0],200)
        ssh.assert_not_called()

    def test_registry_removal_blocks_pending_work_and_never_deletes_its_key(self):
        old = self.key('imported-old')
        removal = {'server':'first', 'confirmed': True}
        self.assertEqual(self.request('/api/servers/remove',dict(removal,confirmed=1))[0],400)
        self.control.jobs['pending'] = {'server':'first','state':'needs_review','remoteSubmitted':True}
        self.assertEqual(self.request('/api/servers/remove',removal)[0],400)
        self.control.jobs['pending']['remoteSubmitted'] = False  # interrupted before any remote mutation
        with patch.object(server, 'ssh') as ssh:
            self.assertEqual(self.request('/api/servers/remove',removal),(200,{'ok':True}))
        ssh.assert_not_called()
        self.assertEqual(server.servers(),[self.second])
        self.assertTrue(old.is_file())
        self.assertIn('pending',self.control.jobs)
        self.assertEqual(self.request('/api/servers/remove',removal)[0],400)

    def test_stale_inventory_cannot_add_service_to_edited_server(self):
        switched = dict(self.first, host='192.0.2.30')

        def inventory(*args):
            with server.LOCK:
                server.write_config([switched, self.second])
            return {'units':[{'unit':'vpn.service'}]}

        with patch.object(server, 'ssh', side_effect=inventory):
            self.assertEqual(self.request('/api/services',{'server':'first','unit':'vpn.service'})[0],400)
        self.assertEqual(server.find('first'), switched)

    def test_used_and_service_keys_are_listed_but_cannot_be_deleted(self):
        old = self.key('imported-old')
        service = self.key('deployment_helper')
        other = self.key('old-pair')
        status, listing = self.request('/api/keys')
        self.assertEqual(status,200)
        items = {item['name']:item for item in listing['items']}
        self.assertEqual(items['imported-old']['usedBy'],
                         [{'id':'first','name':'First','host':'192.0.2.10','user':'root','port':22}])
        self.assertFalse(items['imported-old']['removable'])
        self.assertNotIn('deployment_helper', listing['keys'])
        self.assertTrue(items['old-pair']['removable'])
        for name in ('imported-old','deployment_helper','../other','old-pair.pub'):
            self.assertEqual(self.request('/api/keys/remove',{'key':name,'confirmed':True})[0],400)
        self.assertEqual(self.request('/api/keys/remove',{'key':'old-pair','confirmed':'true'})[0],400)
        self.assertEqual(self.request('/api/keys/remove',{'key':'old-pair','confirmed':True}),(200,{'ok':True}))
        self.assertFalse(other.exists() or other.with_suffix('.pub').exists())
        self.assertTrue(old.is_file() and service.is_file())

    def test_key_origin_is_reported_only_from_a_valid_managed_comment(self):
        old = self.key('rotated', 'server-deck:root@previous.example')
        external = self.key('deck_192_0_2_10_root_aabbccddee', 'sensitive external annotation')
        self.key('invalid-target', 'server-deck:root@previous.example:0')
        bad_material = self.key('invalid-public', 'server-deck:root@previous.example')
        bad_material.with_suffix('.pub').write_text('ssh-ed25519 AAAA server-deck:root@previous.example\n')
        generated = server.generate_key({'host':'current.example','user':'ubuntu','port':2222})
        status, listing = self.request('/api/keys')
        self.assertEqual(status, 200)
        items = {item['name']:item for item in listing['items']}
        self.assertEqual(items[old.name]['createdFor'], {'host':'previous.example','user':'root'})
        self.assertEqual(items[generated['key']]['createdFor'], {'host':'current.example','user':'ubuntu','port':2222})
        for name in (external.name, 'invalid-public', 'invalid-target'):
            self.assertNotIn('createdFor', items[name])
        public_blob = old.with_suffix('.pub').read_text().split()[1]
        self.assertNotIn(public_blob, json.dumps(listing))
        self.assertNotIn('sensitive external annotation', json.dumps(listing))

    def test_pair_mismatch_is_not_deleted_but_verified_private_only_key_can_be_removed(self):
        first = self.key('first-pair')
        second = self.key('second-pair')
        first.with_suffix('.pub').write_bytes(second.with_suffix('.pub').read_bytes())
        self.assertEqual(self.request('/api/keys/remove',{'key':first.name,'confirmed':True})[0],400)
        self.assertTrue(first.is_file() and first.with_suffix('.pub').is_file())
        second.with_suffix('.pub').unlink()
        self.assertEqual(self.request('/api/keys/remove',{'key':second.name,'confirmed':True})[0],200)
        self.assertFalse(second.exists())

    def test_symlink_and_hardlink_keys_are_not_removed(self):
        original = self.key('safe-pair')
        symbolic = self.keydir / 'symbolic'
        symbolic.symlink_to(original)
        os.link(original, self.keydir/'hardlink')
        for name in (original.name, symbolic.name, 'hardlink'):
            self.assertEqual(self.request('/api/keys/remove',{'key':name,'confirmed':True})[0],400)
        self.assertTrue(symbolic.is_symlink() and original.is_file())

    def test_pair_move_failure_restores_private_file(self):
        key = self.key('retry-pair')
        real_rename = os.rename

        def fail_public(source, destination, **flags):
            if source.endswith('.pub'):
                raise OSError('second move failed')
            return real_rename(source, destination, **flags)

        with patch.object(keypairs.os, 'rename', side_effect=fail_public):
            self.assertEqual(self.request('/api/keys/remove',{'key':key.name,'confirmed':True})[0],400)
        self.assertTrue(key.is_file() and key.with_suffix('.pub').is_file())

    def test_identity_check_disables_extra_ssh_identities_and_host_key_updates(self):
        with patch.object(server.subprocess,'run',return_value=SimpleNamespace(returncode=0, stdout='{}')) as run:
            self.assertEqual(server.ssh(self.first, {'action':'inventory'}, isolated=True),{})
        argv=run.call_args.args[0]
        self.assertEqual(argv[:3],['ssh','-F',os.devnull])
        self.assertIn('IdentityAgent=none',argv)
        self.assertIn('IdentitiesOnly=yes',argv)
        self.assertIn('StrictHostKeyChecking=yes',argv)
        self.assertIn('UpdateHostKeys=no',argv)
