"""Isolated regression coverage for the pinned, code-only MTProxyL update.

All paths and external observations in these tests belong to temporary fixtures.
The native manager, service commands and real firewall are never executed.
"""
import copy
import hashlib
import io
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import mtproxyl_update_remote as manager


def manager_main(version):
    return ('#!/bin/bash\nVERSION="'+version+'"\nfor _lib in utils; do\n  :\ndone\n').encode()


def release_archive(version='1.7.18', extra=(), overrides=None):
    contents={'mtproxyl.sh':manager_main(version),'version':(version+'\n').encode(),'lib/utils.sh':b'#!/bin/bash\n: # library\n'}
    contents['settings.conf']=b'not an installed configuration\n'
    contents.update(overrides or {})
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w:gz') as archive:
        for name,value in contents.items():
            member=tarfile.TarInfo('mtproxyl-'+version+'/'+name)
            member.size=len(value)
            member.mode=0o755 if name=='mtproxyl.sh' else 0o644
            archive.addfile(member,io.BytesIO(value))
        for member,payload in extra:
            archive.addfile(member,io.BytesIO(payload) if payload is not None else None)
    return data.getvalue()


class ManagerCodeUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=pathlib.Path(self.temp.name)
        self.root=self.base/'mtproxyl'
        self.root.mkdir()
        (self.root/'lib').mkdir()
        (self.root/'mtproxyl.sh').write_bytes(manager_main('1.7.17'))
        (self.root/'mtproxyl.sh').chmod(0o755)
        (self.root/'version').write_text('1.7.17\n')
        (self.root/'lib/utils.sh').write_text('#!/bin/bash\n: # old library\n')
        (self.root/'settings.conf').write_text('PROXY_PORT=443\n')
        self.state=self.base/'state'
        self.payload=release_archive()
        self.logs=[]
        self.runtime={'baseline':{},'awg':{},'docker':[],'processes':[],'nft':{},'zapretActive':False}
        self.system=self.base/'system'
        self.system.mkdir()
        self.protected=self.system/'usr/local/sbin/mtproxyl-zapret2-start.sh'
        self.protected.parent.mkdir(parents=True)
        self.protected.write_text('#!/bin/bash\n# custom AWG exclusion\n')
        self.marker=self.protected.with_name(self.protected.name+'.before-awg-exclude')
        self.marker.write_text('# historical original script\n')
        self.password=self.system/'etc/ssh/sshd_config'
        self.password.parent.mkdir(parents=True)
        self.password.write_text('PasswordAuthentication yes\n')
        self.version='1.7.17'
        source={name:hashlib.sha256(value).hexdigest() for name,value in self.code_bytes().items()}
        self.source_patch=patch.object(manager,'SOURCE_HASHES',source,create=True)
        self.source_patch.start()
        self.addCleanup(self.source_patch.stop)

    def installed_version(self):
        import re
        value=re.search(r'^VERSION="([^"\n]+)"', (self.root/'mtproxyl.sh').read_text(), re.M)
        return {'mtproxyl':value.group(1)}

    def adapter(self, **hooks):
        values={'versions':self.installed_version,'baseline':lambda:{},'log':self.logs.append,
                'runtime':lambda:copy.deepcopy(self.runtime),'download':lambda:self.payload,
                'lock_path':self.base/'native.lock','system_root':self.system}
        values.update(hooks)
        artifact=dict(manager.ARTIFACT,sha256=hashlib.sha256(self.payload).hexdigest(),size=len(self.payload))
        self.artifact_patch=patch.object(manager,'ARTIFACT',artifact)
        self.artifact_patch.start()
        self.addCleanup(self.artifact_patch.stop)
        return manager.ManagerCodeUpdate(root=self.root,state=self.state,hooks=values)

    def code_bytes(self):
        return {str(path.relative_to(self.root)):path.read_bytes() for path in [self.root/'mtproxyl.sh',self.root/'version',*sorted((self.root/'lib').glob('*.sh'))]}

    def request(self):
        return {'kind':'update','component':'mtproxyl','version':'v1.7.18'}

    def test_pinned_update_changes_code_and_preserves_configuration_password_and_patch(self):
        adapter=self.adapter()
        protected={p:p.read_bytes() for p in (self.protected,self.marker,self.password,self.root/'settings.conf')}
        plan=adapter.plan(self.request())
        self.assertEqual(plan['request']['component'],'mtproxyl')
        self.assertIn('managerRevision',plan['request'])
        result=adapter.apply(plan['request'])
        self.assertEqual(self.installed_version()['mtproxyl'],'1.7.18')
        self.assertEqual((self.root/'lib/utils.sh').read_bytes(),b'#!/bin/bash\n: # library\n')
        self.assertEqual((self.root/'mtproxyl.sh').stat().st_mode&0o777,0o755)
        self.assertEqual((self.root/'lib/utils.sh').stat().st_mode&0o777,0o644)
        for path,value in protected.items():self.assertEqual(path.read_bytes(),value)
        self.assertFalse((self.base/'native.lock').exists())

    def test_legacy_installation_without_version_metadata_can_update_exact_code(self):
        (self.root/'version').unlink()
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        self.assertFalse((self.root/'version').exists())
        result=adapter.apply(plan['request'])
        self.assertTrue(result['verified'])
        self.assertEqual((self.root/'version').read_text(),'1.7.18\n')
        self.assertEqual(self.installed_version()['mtproxyl'],'1.7.18')

    def test_rollback_removes_new_metadata_when_legacy_version_file_was_absent(self):
        (self.root/'version').unlink()
        expected={name:(self.root/name).read_bytes() for name in ('mtproxyl.sh','lib/utils.sh')}
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        original=adapter._replace
        calls=[]
        def fail_main_once(source,destination,mode):
            calls.append(str(destination))
            if len(calls)==3:raise OSError('simulated failure writing main after metadata')
            return original(source,destination,mode)
        with patch.object(adapter,'_replace',side_effect=fail_main_once):
            with self.assertRaises((ValueError,RuntimeError,OSError)):adapter.apply(plan['request'])
        self.assertFalse((self.root/'version').exists())
        for name,value in expected.items():self.assertEqual((self.root/name).read_bytes(),value)
        self.assertEqual(self.installed_version()['mtproxyl'],'1.7.17')

    def test_missing_library_is_never_accepted_as_optional_legacy_metadata(self):
        (self.root/'lib/utils.sh').unlink()
        adapter=self.adapter()
        with self.assertRaises((ValueError,RuntimeError)):adapter.plan(self.request())
        self.assertEqual(self.installed_version()['mtproxyl'],'1.7.17')

    def test_unknown_old_manager_requires_migration_instead_of_running_update(self):
        (self.root/'mtproxyl.sh').write_bytes(manager_main('1.3.2'))
        adapter=self.adapter()
        with self.assertRaisesRegex(ValueError,'1.3.2|миграц|1.7.17'):
            adapter.plan(self.request())
        self.assertEqual(self.installed_version()['mtproxyl'],'1.3.2')

    def test_browser_cannot_choose_unreviewed_version(self):
        adapter=self.adapter()
        with self.assertRaises(ValueError):adapter.plan(dict(self.request(),version='v9.9.9'))

    def test_script_drift_invalidates_apply_before_mutation(self):
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        (self.root/'lib/utils.sh').write_text('#!/bin/bash\n: # changed by administrator\n')
        expected=self.code_bytes()
        with self.assertRaises((ValueError,RuntimeError)):adapter.apply(plan['request'])
        self.assertEqual(self.code_bytes(),expected)

    def test_unreviewed_installed_library_patch_is_rejected_before_preview(self):
        (self.root/'lib/utils.sh').write_text('#!/bin/bash\n: # unreviewed local code patch\n')
        adapter=self.adapter()
        with self.assertRaises((ValueError,RuntimeError)):adapter.plan(self.request())

    def test_local_awg_patch_drift_invalidates_apply_before_mutation(self):
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        self.protected.write_text('#!/bin/bash\n# changed after preview\n')
        expected=self.code_bytes()
        with self.assertRaises((ValueError,RuntimeError)):adapter.apply(plan['request'])
        self.assertEqual(self.code_bytes(),expected)

    def test_changed_sha_never_writes_installed_code(self):
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        self.payload=self.payload+b'changed'
        expected=self.code_bytes()
        with self.assertRaises((ValueError,RuntimeError)):adapter.apply(plan['request'])
        self.assertEqual(self.code_bytes(),expected)

    def test_wrong_internal_version_and_invalid_shell_are_rejected_before_write(self):
        for overrides in ({'version':b'1.7.19\n'}, {'lib/utils.sh':b'#!/bin/bash\nif then broken\n'}, {'mtproxyl.sh':manager_main('1.7.19')}):
            with self.subTest(overrides=list(overrides)):
                self.payload=release_archive(overrides=overrides)
                adapter=self.adapter()
                plan=adapter.plan(self.request())
                expected=self.code_bytes()
                with self.assertRaises((ValueError,RuntimeError)):adapter.apply(plan['request'])
                self.assertEqual(self.code_bytes(),expected)

    def test_installed_code_symlink_is_never_followed(self):
        outside=self.base/'administrator-file.sh'
        outside.write_text('#!/bin/bash\n: # untouched external file\n')
        target=self.root/'lib/utils.sh'
        target.unlink()
        target.symlink_to(outside)
        adapter=self.adapter()
        with self.assertRaises((ValueError,RuntimeError)):adapter.plan(self.request())
        self.assertEqual(outside.read_text(),'#!/bin/bash\n: # untouched external file\n')
        self.assertTrue(target.is_symlink())

    def test_existing_native_lock_is_never_removed_or_overwritten(self):
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        lock=self.base/'native.lock'
        lock.mkdir()
        (lock/'pid').write_text('777777\n')
        (lock/'cmd').write_text('administrator operation\n')
        expected=self.code_bytes()
        with self.assertRaises((ValueError,RuntimeError)):adapter.apply(plan['request'])
        self.assertEqual(self.code_bytes(),expected)
        self.assertEqual((lock/'pid').read_text(),'777777\n')
        self.assertEqual((lock/'cmd').read_text(),'administrator operation\n')

    def test_failed_code_replacement_restores_exact_previous_code(self):
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        expected=self.code_bytes()
        original=adapter._replace
        attempts=[]
        def fail_once(source,destination,mode):
            attempts.append(str(destination))
            if len(attempts)==2:raise OSError('simulated atomic replace failure')
            return original(source,destination,mode)
        with patch.object(adapter,'_replace',side_effect=fail_once):
            with self.assertRaises((ValueError,RuntimeError,OSError)):adapter.apply(plan['request'])
        self.assertEqual(self.code_bytes(),expected)
        self.assertGreaterEqual(len(attempts),2)
        self.assertFalse((self.base/'native.lock').exists())

    def test_error_after_atomic_replace_also_restores_original_file(self):
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        expected=self.code_bytes()
        original=adapter._replace
        failed=[]
        def replace_then_fail(source,destination,mode):
            result=original(source,destination,mode)
            if not failed:
                failed.append(True)
                raise OSError('simulated directory fsync failure after os.replace')
            return result
        with patch.object(adapter,'_replace',side_effect=replace_then_fail):
            with self.assertRaises((ValueError,RuntimeError,OSError)):adapter.apply(plan['request'])
        self.assertEqual(self.code_bytes(),expected)

    def test_update_never_executes_manager_installer_or_service_commands(self):
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        original=manager.subprocess.run
        commands=[]
        def read_only_syntax(argv,*args,**kwargs):
            commands.append(list(argv))
            self.assertEqual(list(argv[:2]),['bash','-n'])
            return original(argv,*args,**kwargs)
        with patch.object(manager.subprocess,'run',side_effect=read_only_syntax):adapter.apply(plan['request'])
        self.assertGreaterEqual(len(commands),2)

    def test_runtime_drift_during_write_is_not_reported_as_success(self):
        def after_write_runtime():
            value=copy.deepcopy(self.runtime)
            if self.installed_version()['mtproxyl']=='1.7.18':value['processes']=[{'pid':999,'start':'different'}]
            return value
        adapter=self.adapter(runtime=after_write_runtime)
        plan=adapter.plan(self.request())
        with self.assertRaises((ValueError,RuntimeError)):adapter.apply(plan['request'])

    def test_backup_failure_never_starts_code_replacement(self):
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        expected=self.code_bytes()
        with patch.object(adapter,'_backup',side_effect=OSError('simulated full backup disk')),patch.object(adapter,'_replace') as replace:
            with self.assertRaises((ValueError,RuntimeError,OSError)):adapter.apply(plan['request'])
        replace.assert_not_called()
        self.assertEqual(self.code_bytes(),expected)

    def active_zapret(self, hook='prerouting'):
        self.protected.write_text('#!/bin/bash\n# preserved rules: iifname "awg*" return; oifname "awg*" return\n')
        (self.root/'nft-rules.conf').write_text("ZAPRET2_EXCLUDE_IFACES='awg* wg* tun*'\n")
        self.runtime.update(awg={'awg0':'4'},zapretActive=True,nft={'nftables':[
            {'chain':{'family':'ip','table':'mtproxyl_zapret2','name':hook,'hook':hook}},
            {'rule':{'family':'ip','table':'mtproxyl_zapret2','chain':hook,'expr':[
                {'match':{'op':'==','left':{'meta':{'key':'iifname'}},'right':'awg*'}},{'return':None}]}},
            {'rule':{'family':'ip','table':'mtproxyl_zapret2','chain':hook,'expr':[{'queue':{'num':100}}]}}
        ]})

    def test_awg_marker_with_verified_effective_exclusion_allows_preview(self):
        self.active_zapret()
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        self.assertIn('managerRevision',plan['request'])
        self.assertTrue(self.marker.is_file())

    def test_bypass_counter_is_ignored_during_effective_rule_verification(self):
        self.active_zapret()
        rule=self.runtime['nft']['nftables'][1]['rule']
        rule['expr'].insert(1,{'counter':{'packets':12,'bytes':2000}})
        adapter=self.adapter()
        self.runtime['nft']=adapter._normal_nft(self.runtime['nft'])
        plan=adapter.plan(self.request())
        self.assertIn('managerRevision',plan['request'])

    def test_native_mtprotol_table_keeps_chains_and_rules_after_normalization(self):
        self.active_zapret()
        for entry in self.runtime['nft']['nftables']:
            for body in entry.values():body['table']='MTProtoL'
        self.runtime['nft']['nftables'].insert(0,{'table':{'family':'ip','name':'MTProtoL','handle':7}})
        adapter=self.adapter()
        normalized=adapter._normal_nft(self.runtime['nft'])
        self.assertEqual(len(normalized['nftables']),4)
        self.assertTrue(any(entry.get('chain',{}).get('table')=='MTProtoL' for entry in normalized['nftables']))
        self.assertEqual(sum('rule' in entry for entry in normalized['nftables']),2)
        self.runtime['nft']=normalized
        self.assertIn('managerRevision',adapter.plan(self.request())['request'])

    def test_arbitrary_queue_table_is_retained_while_counters_are_normalized(self):
        self.active_zapret()
        for entry in self.runtime['nft']['nftables']:
            for body in entry.values():body['table']='custom_dpi_queue'
        self.runtime['nft']['nftables'][1]['rule']['expr'].insert(1,{'counter':{'packets':1,'bytes':90}})
        self.runtime['nft']['nftables'][2]['rule']['expr'].insert(0,{'counter':{'packets':2,'bytes':180}})
        self.runtime['nft']['nftables'].extend([
            {'table':{'family':'inet','name':'unrelated_fail2ban'}},
            {'chain':{'family':'inet','table':'unrelated_fail2ban','name':'input','hook':'input'}},
            {'rule':{'family':'inet','table':'unrelated_fail2ban','chain':'input','expr':[{'counter':{'packets':9,'bytes':900}},{'drop':None}]}}
        ])
        adapter=self.adapter()
        normalized=adapter._normal_nft(self.runtime['nft'])
        self.assertEqual(len(normalized['nftables']),3)
        self.assertNotIn('counter',str(normalized))
        self.assertNotIn('unrelated_fail2ban',str(normalized))
        changed=copy.deepcopy(self.runtime['nft'])
        changed['nftables'][1]['rule']['expr'][1]['counter']['packets']=999
        self.assertEqual(normalized,adapter._normal_nft(changed))
        self.runtime['nft']=normalized
        self.assertIn('managerRevision',adapter.plan(self.request())['request'])

    def test_awg_without_effective_exclusion_is_blocked_even_when_marker_exists(self):
        self.active_zapret()
        self.runtime['nft']['nftables'].pop(1)
        adapter=self.adapter()
        with self.assertRaises((ValueError,RuntimeError)):adapter.plan(self.request())

    def test_awg_return_rule_after_queue_does_not_count_as_bypass(self):
        self.active_zapret()
        entries=self.runtime['nft']['nftables']
        entries[1],entries[2]=entries[2],entries[1]
        adapter=self.adapter()
        with self.assertRaises((ValueError,RuntimeError)):adapter.plan(self.request())

    def test_effective_rule_drift_invalidates_apply_before_mutation(self):
        self.active_zapret()
        adapter=self.adapter()
        plan=adapter.plan(self.request())
        self.runtime['nft']['nftables'][2]['rule']['expr'][0]['queue']['num']=101
        expected=self.code_bytes()
        with self.assertRaises((ValueError,RuntimeError)):adapter.apply(plan['request'])
        self.assertEqual(self.code_bytes(),expected)

    def test_postrouting_exclusion_requires_output_interface(self):
        self.active_zapret(hook='postrouting')
        adapter=self.adapter()
        with self.assertRaises((ValueError,RuntimeError)):adapter.plan(self.request())

    def test_awg_configured_exclusion_must_survive_future_native_refresh(self):
        self.active_zapret()
        (self.root/'nft-rules.conf').write_text("ZAPRET2_EXCLUDE_IFACES='wg* tun*'\n")
        adapter=self.adapter()
        with self.assertRaises((ValueError,RuntimeError)):adapter.plan(self.request())

    def test_native_config_uses_reviewed_single_quote_format(self):
        self.active_zapret()
        (self.root/'nft-rules.conf').write_text('ZAPRET2_EXCLUDE_IFACES="awg* wg* tun*"\n')
        adapter=self.adapter()
        with self.assertRaises((ValueError,RuntimeError)):adapter.plan(self.request())

    def test_tar_path_traversal_and_links_are_rejected_before_code_write(self):
        cases=[]
        traversal=tarfile.TarInfo('mtproxyl-1.7.18/../../outside');traversal.size=3
        cases.append((traversal,b'bad'))
        symlink=tarfile.TarInfo('mtproxyl-1.7.18/lib/evil.sh');symlink.type=tarfile.SYMTYPE;symlink.linkname='/etc/shadow'
        cases.append((symlink,None))
        hardlink=tarfile.TarInfo('mtproxyl-1.7.18/lib/evil.sh');hardlink.type=tarfile.LNKTYPE;hardlink.linkname='mtproxyl-1.7.18/lib/utils.sh'
        cases.append((hardlink,None))
        for member,payload in cases:
            with self.subTest(member=member.name,type=member.type):
                self.payload=release_archive(extra=((member,payload),))
                adapter=self.adapter()
                plan=adapter.plan(self.request())
                expected=self.code_bytes()
                with self.assertRaises((ValueError,RuntimeError)):adapter.apply(plan['request'])
                self.assertEqual(self.code_bytes(),expected)
        self.assertFalse((self.base/'outside').exists())


if __name__=='__main__':
    unittest.main()
