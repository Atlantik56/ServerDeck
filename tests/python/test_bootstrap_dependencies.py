"""Run the real bootstrap with isolated command/package fixtures, never real APT."""
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bootstrap_launcher', ROOT / 'installer/install.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)

APT = r'''import json,os,pathlib,sys
args=sys.argv[1:]
with open(os.environ['FIXTURE_LOG'],'a') as out:out.write(json.dumps(['apt-get',*args])+'\n')
action=next((a for a in ('update','install') if a in args),'unknown')
if os.environ.get('FIXTURE_FAIL')==action:raise SystemExit(100)
if action=='install' and not os.environ.get('FIXTURE_NO_CREATE'):
 for name in ('python3','curl','tar'):
  if name in args:
   p=pathlib.Path(os.environ['FIXTURE_BIN'])/name;p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o755)
 if 'ca-certificates' in args:pathlib.Path(os.environ['FIXTURE_CA']).write_text('fixture-ca-bundle')
'''
SUDO = r'''import json,os,subprocess,sys
args=sys.argv[1:]
with open(os.environ['FIXTURE_LOG'],'a') as out:out.write(json.dumps(['sudo',*args])+'\n')
if args==['-v']:raise SystemExit(0)
if args[:2]!=['-n','--']:raise SystemExit('unexpected sudo invocation')
raise SystemExit(subprocess.run(args[2:]).returncode)
'''


class BootstrapDependencies(unittest.TestCase):
    def run_bootstrap(self, *, missing=(), ca=True, uid=0, sudo=True, dry_run=False,
                      fail='', create=True, distro='ubuntu', version='24.04', occupied=False):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);binary=root/'bin';binary.mkdir();log=root/'calls.jsonl'
            release=root/'os-release';release.write_text('ID='+distro+'\nVERSION_ID="'+version+'"\n')
            bundle=root/'ca.crt'
            if ca:bundle.write_text('fixture-ca-bundle')
            tty=root/'tty';tty.touch()
            replacements={'/etc/os-release':str(release),'/etc/ssl/certs/ca-certificates.crt':str(bundle),'/dev/tty':str(tty)}
            for p in ('/opt/server-deck','/opt/server-deck-web','/etc/server-deck','/var/lib/serverdeck','/usr/local/lib/server-deck','/etc/caddy'):
                replacements[p]=str(root/'host'/p.lstrip('/'))
            if occupied:pathlib.Path(replacements['/opt/server-deck']).mkdir(parents=True)
            source=(ROOT/'scripts/install.sh').read_text()
            source=re.sub('|'.join(re.escape(p) for p in sorted(replacements,key=len,reverse=True)),lambda m:replacements[m.group()],source)
            script=root/'install.sh';script.write_text(source)

            def command(name,body,python=False):
                p=binary/name;p.write_text(('#!'+sys.executable+'\n' if python else '#!/bin/sh\n')+body);p.chmod(0o755)
            command('uname',"printf 'Linux\\n'\n")
            command('id',"printf '"+str(uid)+"\\n'\n")
            command('apt-get',APT,True)
            if sudo:command('sudo',SUDO,True)
            (binary/'env').symlink_to('/usr/bin/env')
            for name in ('python3','curl','tar'):
                if name not in missing:command(name,'exit 0\n')
            env=dict(os.environ,PATH=str(binary),FIXTURE_LOG=str(log),FIXTURE_BIN=str(binary),FIXTURE_CA=str(bundle),FIXTURE_FAIL=fail)
            if not create:env['FIXTURE_NO_CREATE']='1'
            args=['/bin/bash',str(script),'--bootstrap-only']+(['--dry-run'] if dry_run else [])
            result=subprocess.run(args,input='',capture_output=True,text=True,env=env,timeout=10)
            calls=[json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result,calls

    def test_installed_prerequisites_skip_apt_and_wizard(self):
        result,calls=self.run_bootstrap()
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(calls,[])

    def test_root_installs_only_missing_bootstrap_dependencies(self):
        result,calls=self.run_bootstrap(missing=('python3','tar'))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(calls),2)
        self.assertIn('update',calls[0]);self.assertIn('install',calls[1])
        self.assertIn('APT::Update::Error-Mode=any',calls[0])
        self.assertIn('python3',calls[1]);self.assertIn('tar',calls[1])
        self.assertNotIn('curl',calls[1]);self.assertNotIn('ca-certificates',calls[1])
        self.assertFalse(any('upgrade' in call or 'reboot' in call for call in calls))

    def test_missing_ca_bundle_is_repaired_without_disabling_https(self):
        result,calls=self.run_bootstrap(ca=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('ca-certificates',calls[-1])
        self.assertFalse(any('--allow-unauthenticated' in call or '-k' in call for call in calls))

    def test_nonroot_uses_sudo_validation_and_noninteractive_elevation(self):
        result,calls=self.run_bootstrap(missing=('curl',),uid=1000)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(calls[0],['sudo','-v'])
        sudo_calls=[call for call in calls if call[0]=='sudo' and call!=['sudo','-v']]
        self.assertEqual(len(sudo_calls),2)
        for call in sudo_calls:
            self.assertEqual(call[1:3],['-n','--']);self.assertNotIn('-S',call)
        self.assertEqual(len([call for call in calls if call[0]=='apt-get']),2)

    def test_missing_sudo_stops_before_packages(self):
        result,calls=self.run_bootstrap(missing=('python3',),uid=1000,sudo=False)
        self.assertNotEqual(result.returncode,0);self.assertEqual(calls,[])
        self.assertIn('Root or sudo',result.stderr)

    def test_dry_run_never_installs_missing_dependencies(self):
        result,calls=self.run_bootstrap(missing=('python3','curl','tar'),ca=False,dry_run=True)
        self.assertNotEqual(result.returncode,0);self.assertEqual(calls,[])
        self.assertIn('No packages were changed',result.stderr)

    def test_dry_run_with_prerequisites_is_readonly(self):
        result,calls=self.run_bootstrap(dry_run=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(calls,[])

    def test_update_failure_prevents_install(self):
        result,calls=self.run_bootstrap(missing=('python3',),fail='update')
        self.assertNotEqual(result.returncode,0);self.assertEqual(len(calls),1)
        self.assertIn('update',calls[0])

    def test_install_failure_stops_bootstrap(self):
        result,calls=self.run_bootstrap(missing=('python3',),fail='install')
        self.assertNotEqual(result.returncode,0);self.assertEqual(len(calls),2)
        self.assertIn('install',calls[-1])

    def test_still_missing_component_after_successful_apt_stops(self):
        result,calls=self.run_bootstrap(missing=('python3',),create=False)
        self.assertNotEqual(result.returncode,0);self.assertEqual(len(calls),2)
        self.assertIn('still missing',result.stderr)

    def test_unsupported_os_is_rejected_before_packages(self):
        result,calls=self.run_bootstrap(missing=('python3',),version='24.10')
        self.assertNotEqual(result.returncode,0);self.assertEqual(calls,[])

    def test_existing_panel_is_rejected_before_packages(self):
        result,calls=self.run_bootstrap(missing=('python3',),occupied=True)
        self.assertNotEqual(result.returncode,0);self.assertEqual(calls,[])
        self.assertIn('clean dedicated host',result.stderr)


class SshBootstrapOrder(unittest.TestCase):
    def test_target_bootstrap_precedes_bundle_transfer_and_extraction(self):
        events=[]
        with tempfile.TemporaryDirectory() as folder:
            temp=pathlib.Path(folder);request=temp/'request.json';request.write_text('{}')
            cfg=dict(host='server.example.org',user='operator',port=2222)
            def run(argv,**kwargs):events.append(('run',list(argv),kwargs))
            def output(argv,**kwargs):events.append(('stage',list(argv),kwargs));return '/tmp/serverdeck-install.abcdefgh\n'
            with patch.object(launcher.shutil,'which',return_value='/fixture/bin'), \
                    patch.object(launcher,'run',side_effect=run), \
                    patch.object(launcher.subprocess,'check_output',side_effect=output), \
                    patch.object(launcher.subprocess,'run',return_value=subprocess.CompletedProcess([],0)):
                launcher.install_ssh(ROOT,[pathlib.Path('backend/server.py'),pathlib.Path('scripts/install.sh')],cfg,request,temp)
        bootstrap=next(i for i,event in enumerate(events) if '--bootstrap-only' in event[1][-1])
        staged=next(i for i,event in enumerate(events) if event[0]=='stage')
        transferred=next(i for i,event in enumerate(events) if event[1][0]=='scp')
        extracted=next(i for i,event in enumerate(events) if 'tar -xzf ' in event[1][-1])
        self.assertLess(bootstrap,staged);self.assertLess(staged,transferred);self.assertLess(transferred,extracted)
        self.assertTrue(events[bootstrap][1][-1].startswith('sudo -n -- bash'))
        self.assertEqual(events[bootstrap][2]['input'],(ROOT/'scripts/install.sh').read_text())
        self.assertTrue(events[bootstrap][2]['text'])

    def test_bootstrap_failure_does_not_upload_or_extract(self):
        events=[]
        def run(argv,**kwargs):
            events.append(list(argv))
            if '--bootstrap-only' in argv[-1]:raise subprocess.CalledProcessError(1,argv)
        with tempfile.TemporaryDirectory() as folder:
            temp=pathlib.Path(folder);request=temp/'request.json';request.write_text('{}')
            with patch.object(launcher.shutil,'which',return_value='/fixture/bin'), \
                    patch.object(launcher,'run',side_effect=run), \
                    patch.object(launcher.subprocess,'check_output') as staged:
                with self.assertRaises(subprocess.CalledProcessError):
                    launcher.install_ssh(ROOT,[],dict(host='server.example.org',user='root',port=22),request,temp)
            staged.assert_not_called()
        self.assertFalse(any(command[0]=='scp' or 'tar -xzf ' in command[-1] for command in events))


if __name__=='__main__':unittest.main()
