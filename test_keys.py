import importlib.util,json,pathlib,shlex,stat,subprocess,tempfile,unittest,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))

spec=importlib.util.spec_from_file_location('deck',pathlib.Path(__file__).with_name('server.py'))
deck=importlib.util.module_from_spec(spec);spec.loader.exec_module(deck)

class KeyTests(unittest.TestCase):
    def test_generator_and_idempotent_install(self):
        with tempfile.TemporaryDirectory() as folder:
            deck.KEYDIR=pathlib.Path(folder)/'keys'
            data={'host':'203.0.113.10','user':'root','port':2222}
            first=deck.generate_key(data);second=deck.generate_key(data)
            self.assertNotEqual(first['key'],second['key'])
            private=deck.KEYDIR/first['key']
            self.assertEqual(stat.S_IMODE(private.stat().st_mode),0o600)
            self.assertNotIn(private.read_text(),json.dumps(first))
            self.assertNotIn('PRIVATE KEY',json.dumps(first))
            subprocess.run(['ssh-keygen','-y','-f',str(private)],check=True,capture_output=True)
            outer=shlex.split(first['installCommand']);self.assertEqual(outer[:2],['sh','-c'])
            subprocess.run(['sh','-n','-c',outer[2]],check=True)
            # Execute the generated installation logic against an isolated directory only.
            authdir=pathlib.Path(folder)/'target-ssh';authdir.mkdir();authorized=authdir/'authorized_keys'
            existing='ssh-ed25519 EXISTING_KEY keep-me\n';authorized.write_text(existing)
            script=outer[2].replace('"$HOME/.ssh/authorized_keys"',shlex.quote(str(authorized))).replace('"$HOME/.ssh"',shlex.quote(str(authdir)))
            for _ in range(2):subprocess.run(['sh','-c',script],check=True)
            self.assertEqual(authorized.read_text(),existing+first['publicKey']+'\n')
            self.assertEqual(stat.S_IMODE(authorized.stat().st_mode),0o600)
            self.assertIn('-p 2222',first['connectCommand'])
            nonroot=deck.generate_key(dict(data,user='ubuntu'))
            self.assertEqual(shlex.split(nonroot['installCommand'])[:6],['sudo','-H','-u','ubuntu','sh','-c'])
    def test_rejects_injection_before_creating_files(self):
        with tempfile.TemporaryDirectory() as folder:
            deck.KEYDIR=pathlib.Path(folder)/'keys'
            for data in [{'host':'x; touch /tmp/no','user':'root'},{'host':'example.com','user':'root;id'},{'host':'example.com','port':70000}]:
                with self.assertRaises(ValueError):deck.generate_key(data)
            self.assertFalse(deck.KEYDIR.exists())

if __name__=='__main__':unittest.main()
