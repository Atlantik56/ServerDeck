"""Pinned, code-only MTProxyL manager update. Never invokes the manager CLI.

The native updater also refreshes AWG/Zapret2. This adapter deliberately replaces
only reviewed manager files and checks that protected files and running services
did not change. A failed runtime check is observational: firewall rules are never
restored automatically over another administrator's changes.
"""
import contextlib, hashlib, io, json, os, pathlib, re, secrets, shutil, stat, subprocess, tarfile, tempfile, time
from urllib.request import Request, urlopen

ARTIFACT = dict(version='1.7.18', commit='d5019cf86c7833f6956a74ff8415ab531b196d4e',
    url='https://github.com/Liafanx/MTProxyL/releases/download/v1.7.18/mtproxyl-1.7.18.tar.gz',
    sha256='6bac5a1784b22f0112fa36423e2a7e08cb147fa4fac3fb61150b11840d00cab0',
    size=612379, prefix='mtproxyl-1.7.18')
# Reviewed official v1.7.17 archive SHA-256: dfa8fb0d1aa63bcf31e7fc44188aaefd54f18d0ebab1d8c68544552b4dd06f5a.
SOURCE_HASHES = {'lib/api.sh': '78131802db46a41dfddc633932154c3e5db0318485c21affb30247db42346b4b', 'lib/argsgen.sh': 'a741718b21376fba16af96d093120b989cb637a8ed4229796f20edbd4c88aff0', 'lib/availability.sh': '015a9f640bc7ccb271d57d60537c8d0d2ef560970d615f3a21c41c00c08685dc', 'lib/awg.sh': 'fc860e714dc500f2bc06fb9d08926701770ef8b03df1e8bffbc211ca21af9b4b', 'lib/backup.sh': '7fd0394334156c7715788cb6ab02be57c5e5afcd6447bae9aeeab40ba46fab4e', 'lib/binengine.sh': '6097659b230d5a06be54e5c6a4562263bb72a8bc25a9c5f26efd8734b00c67e7', 'lib/colors.sh': '569795ccfb9ec09529d12d1a08436e9bb46bce1ac27077cff2bf589838e8f423', 'lib/config.sh': 'a7494aa4f951f2ee13d8eec0c5bc455a294e3fbb7c57a551d62d3999cf903707', 'lib/dc.sh': 'e862176bad924dcf06d5d6039185b542a755be15601837e640f70cecd4caf8ac', 'lib/detect.sh': 'b2b4140a60ef8054113c341f0e8840874fcd6f407afc40a3d2618422bf0f9c63', 'lib/docker.sh': 'aa26c5530728971de7d2df4741cd1904903e6dd1344f2f34d8ee890ab31c32de', 'lib/donor.sh': 'd208d034d4ece88e142ba5e9f99cfb61a49f6aef424212e34315247ff8a49d4b', 'lib/egress.sh': '1bcd444e7c74b5825e5c4add5d52d2fa4c352641becdea2e5656684a84539180', 'lib/engine.sh': '8dd83942b26a5aa08a64f301244fc01ca1c62adc1ff391191986b0fd183a6cac', 'lib/expert_catalog.sh': '30410f639d43287af11b771c6703f2086bcb828008b4cbb48b0ec2c9d44cccd2', 'lib/expert_mode.sh': 'e2a7a6e6a5bb4bf0f43bb01e56638f88af4d51fec6afa91dc7434257cf4e3576', 'lib/front.sh': '1d2439b881dff051758fc16114a06d2305982449202c9e38df00469d6190cfac', 'lib/geoblock.sh': '5ec085a84b1aac1934b45f478ad4af60017dd5a3d261503365ae07a55e5626e8', 'lib/geoip.sh': '330ed2b434c6eda5a55d6fe90d7564cfc1e3544d8880c7bc9ce192cae03add1e', 'lib/install.sh': '4475bbd58dff0a30ce52c49c835267448e987754b83dd8b6b42e48cd1f343167', 'lib/install_args.sh': '730e19154252335825d3b9c84513db3361354853cd69a01d99d926c18b0ace96', 'lib/ipblock.sh': '8279b01343dfb3d551b7360dbef4846e01188390129766b668856be518686936', 'lib/migrate.sh': '720c5c984aed132675ff184c20794b1787411ae6ba44586ae8a0a5f92ec849e9', 'lib/nft.sh': 'ce65dde58ee01612aefa94d4df1e9702655f891d9da891bb98f360ea87167451', 'lib/panel.sh': '825a16411c160c7f7651490c47cfb192828797dc1fec745b29c38f47c90b36c8', 'lib/secrets.sh': 'ac6a7fc2dceae82434dd93d72a18d29348568d540b7c5a6f9561c74f0c0b8be8', 'lib/selfmask.sh': 'a6f1bf8e6ac644186c0379ca847ebe5795484955411c39a8ce3f4cb1c69691c6', 'lib/settings.sh': 'e327fa8ad70584f91b1e5936b63a0f9d78d149b93a59cf982c9c003099737b9f', 'lib/settings_cli.sh': '0ebc9c6f159a6331b421f06ca719009f0315f63b8311cfcf52ede5c3fd037543', 'lib/shaping.sh': 'd33b4cbed8526fc2f424c6f856de370c5ccc18aca0e2a7860e3101e8b0e93508', 'lib/stats.sh': '02fc6a716a69f332c32f8391d51bf017e8a9323d0d20767f9dbe3e6714609949', 'lib/tgbot.sh': 'b657506bc22fdb43aa89603dfe822d9e3ad9d3873b97f99ee387bfadc6c606c3', 'lib/traffic.sh': '8010e42f4e3675b41c2b5ba60a3de7995ebd44de355a3f004754f7398fadce33', 'lib/tui_addons.sh': '3e63b6a3148844dedd90f2d7d51b6a4ac18b0ed35ea253109b8cc3f0883a4b73', 'lib/tui_awg.sh': '618314972af48a643f79482b15b6850cec26afae1a321dc605ae2539898c607c', 'lib/tui_backup.sh': '0f07299c9278a9b6fc32c497b1bfc373b845301a4383882f896a149e1e8209b9', 'lib/tui_detect.sh': 'ea7e8153d7c93505e16f46dc238eebe571675ff3ead5e8195c1c7a223927d903', 'lib/tui_donor.sh': '4b2456b7235e38b4b11c02caa10d7fcc3c3f85d19201fef3646b6dd03b423282', 'lib/tui_engine.sh': 'e2ed8e9331cbc23395a5368811dab79a419d10d70f9b8e1725821f5835d16e02', 'lib/tui_expert.sh': '965005d6ebe3ea15282e005243e11c0a1df500cf65b107c3213f470c477dd04d', 'lib/tui_ipblock.sh': '4a765aa30dc1707970278fefaf023c826418f99f632f50340bec3e277d6a3510', 'lib/tui_links.sh': '0051d1b1a4a339f6f5b7d15e880c0b0737cc84cb9548d76064a36ef1510a2450', 'lib/tui_main.sh': '53dddb2cbe44e35a4bb62bec1235114d743e70383f3fe9baca099c8dd7e0f428', 'lib/tui_nft.sh': 'e8f6a8111f15508edf5e07ceb559bcd504a53cadf2614d6602f6b2da76c8a91a', 'lib/tui_proxy.sh': 'b42870ef9796df80bf7b4acd5f593230968588665d23a0155f1e7ad32f339ae1', 'lib/tui_secrets.sh': 'b1b6126aa2aa75c9f16779e112f82a66b44de6e8083fadafa8914d63f39a28ed', 'lib/tui_security.sh': '938f1cf780f9919efb6419042554bdf964788794704ff3e822a23d7e4c1d3875', 'lib/tui_selfmask.sh': '5a6a8ca3c9b08294cf99f105dce60847b1dcd48db1710e8298cd2f7193303e1d', 'lib/tui_settings.sh': '2cee4c3ba5645cde91a131b4bb2e6be45dac4f4515927f7103c2361a208819a5', 'lib/tui_tgbot.sh': '20081eac9f858f1fa25ca4271ecfbe5f4db6ca0771e86b4a4bea6e99b3335840', 'lib/tui_traffic.sh': '92d1aba02995f9d0da3a624b98b06b74d2f28dfd33e45cdf2519517ef747ee73', 'lib/tui_warp.sh': 'c446e5b13482842f79e423eb58dec16e5266cf94d10013ddd1b21a4ee2a10ae4', 'lib/tui_web.sh': 'e1358342a73037be3abe022f8f33415b47738337a27043deeacb25a9f7c2158b', 'lib/upstream.sh': '779e5d5bdd4477e785b30c625e80869aad1a7b6e63982864ee7805d0740058c9', 'lib/utils.sh': '7db355cb536000826b9d95729f345d041a2d072e89812810d6f995000f27275e', 'lib/warp.sh': '1aa0ea22983205a8f447dc8780b99af5437ffe5a5823f2896006711abd186b06', 'lib/web.sh': 'a3ecb24bafa21d2584de9994cd12da8b6702c5a11848dc69159265858373ac56', 'mtproxyl.sh': '43ec556e71150db386bb2b07a946a3fa6b11a30cc89c0f60f4acfaf29e37b85e', 'version': '7f17a2cc716602c5b9b3a340d50399c67c6d6aa11b3d864e8cf77a17a88a7d9e'}
MAX_FILE = 2 * 1024 * 1024
MAX_EXPANDED = 24 * 1024 * 1024
CODE_NAME = re.compile(r'(?:mtproxyl\.sh|version|lib/[A-Za-z0-9_\-]+\.sh)\Z')

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

class ManagerCodeUpdate:
    def __init__(self, root, state, hooks=None):
        self.root = pathlib.Path(root)
        self.state = pathlib.Path(state)
        self.hooks = hooks or {}
        self.system_root = pathlib.Path(self.hooks.get('system_root', '/'))
        self.lock_path = pathlib.Path(self.hooks.get('lock_path', '/run/mtproxyl.lock'))

    def _sys(self, path): return self.system_root / path.lstrip('/')
    def _log(self, message): self.hooks.get('log', lambda _message: None)(message)

    def _run(self, argv):
        # Every permitted command is read-only, except writing our own staged files.
        result = subprocess.run(argv, capture_output=True, text=True, timeout=25,
                                env=dict(os.environ, LC_ALL='C'))
        if result.returncode: raise ValueError('Не удалось безопасно прочитать состояние: ' + argv[0])
        if len(result.stdout) > 8 * 1024 * 1024: raise ValueError('Слишком большой снимок состояния')
        return result.stdout

    def _files(self):
        if self.root.is_symlink() or not self.root.is_dir(): raise ValueError('Каталог MTProxyL отсутствует или является ссылкой')
        lib = self.root / 'lib'
        if lib.is_symlink() or not lib.is_dir(): raise ValueError('Небезопасный каталог библиотек MTProxyL')
        paths = [self.root / 'mtproxyl.sh', self.root / 'version'] + sorted(lib.glob('*.sh'))
        result = {}
        for path in paths:
            if path.name == 'version' and not path.exists(): continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
                raise ValueError('Небезопасный файл кода MTProxyL')
            result[str(path.relative_to(self.root))] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid, size=info.st_size)
        if 'mtproxyl.sh' not in result or not any(name.startswith('lib/') for name in result):
            raise ValueError('Неполная установка менеджера MTProxyL')
        return result

    def _protected(self):
        paths = set()
        for pattern in ('*.conf', '*.toml'):
            paths.update(self.root.glob(pattern))
        paths.update(self.root / name for name in ('.branch',))
        for name in ('/usr/local/sbin/mtproxyl-zapret2-start.sh',
                     '/usr/local/sbin/mtproxyl-zapret2-stop.sh',
                     '/usr/local/sbin/mtproxyl-zapret2-start.sh.before-awg-exclude',
                     '/etc/systemd/system/mtproxyl-zapret2.service',
                     '/etc/ssh/sshd_config', '/etc/passwd', '/etc/shadow', '/root/.ssh/authorized_keys',
                     '/etc/x-ui/server-deck.env', '/etc/x-ui/install-result.env'):
            paths.add(self._sys(name))
        for name in ('/etc/systemd/system/mtproxyl-zapret2.service.d', '/etc/ssh/sshd_config.d',
                     '/etc/amnezia', '/etc/wireguard'):
            directory = self._sys(name)
            if directory.is_symlink(): raise ValueError('Небезопасная ссылка в защищённой конфигурации')
            if directory.exists(): paths.update(p for p in directory.rglob('*') if not p.is_dir())
        result = {}
        total = 0
        for path in sorted(paths, key=str):
            key = str(path)
            if not path.exists() and not path.is_symlink(): result[key] = None; continue
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                # Configured symlinks are fingerprinted including their target content.
                target = path.resolve(strict=True)
                if not target.is_file(): raise ValueError('Неизвестная защищённая ссылка')
                link = os.readlink(path)
            elif stat.S_ISREG(info.st_mode): link = None; target = path
            else: raise ValueError('Необычный тип защищённой конфигурации')
            size = target.stat().st_size
            total += size
            if size > 8 * 1024 * 1024 or total > 48 * 1024 * 1024:
                raise ValueError('Защищённая конфигурация слишком велика для проверенного обновления')
            result[key] = dict(sha256=hashlib.sha256(target.read_bytes()).hexdigest(), link=link,
                mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        return result

    def _normal_nft(self, value):
        def clean(item):
            if isinstance(item, list): return [clean(v) for v in item if not (isinstance(v, dict) and set(v) == {'counter'})]
            if isinstance(item, dict):
                return {k: clean(v) for k, v in item.items() if k not in ('counter', 'handle', 'metainfo')}
            return item
        # Restrict to the protected queue tables; unrelated fail2ban counters and
        # automatically expiring address sets must not invalidate every preview.
        entries = value.get('nftables', [])
        tables = {(body.get('family'), body.get('table')) for entry in entries for body in entry.values()
                  if isinstance(body, dict) and (
                      any(name in str(body.get('table', '')).lower() for name in ('mtproxyl', 'mtprotol'))
                      or any(isinstance(expr, dict) and 'queue' in expr for expr in body.get('expr', [])))}
        return {'nftables': [clean(entry) for entry in entries if any(
            isinstance(body, dict) and ((body.get('family'), body.get('table', body.get('name'))) in tables)
            for body in entry.values())]}

    def _runtime(self):
        if 'runtime' in self.hooks: return self.hooks['runtime']()
        awg = {}
        for path in self._sys('/sys/class/net').glob('*'):
            if path.name.startswith(('awg', 'awgo-')):
                awg[path.name] = (path / 'ifindex').read_text().strip()
        docker = []
        if shutil.which('docker'):
            ids = self._run(['docker', 'ps', '-q', '--no-trunc']).split()
            if ids:
                for item in json.loads(self._run(['docker', 'inspect'] + ids)):
                    state = item.get('State', {})
                    docker.append(dict(id=item['Id'], name=item.get('Name', ''), image=item.get('Config', {}).get('Image', ''),
                        pid=state.get('Pid'), startedAt=state.get('StartedAt'), running=state.get('Running')))
        processes = []
        for path in self._sys('/proc').glob('[0-9]*'):
            try:
                comm = (path / 'comm').read_text().strip()
                cmd = (path / 'cmdline').read_bytes()
                if any(argument.rsplit(b'/', 1)[-1] in (b'mtproxyl.sh', b'mtproxyl') for argument in cmd.split(b'\0')):
                    # 1.7.17 predates the native lock. Its CLI must have finished
                    # before replacing code, including seemingly read-only calls.
                    raise ValueError('Выполняется команда MTProxyL; дождитесь её завершения и создайте новый план')
                if not re.search(r'telemt|mtproto|nfqws', comm, re.I): continue
                fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
                processes.append(dict(pid=int(path.name), name=comm, started=fields[19], commandHash=hashlib.sha256(cmd).hexdigest()))
            except (FileNotFoundError, ProcessLookupError): continue
        active = False
        if shutil.which('systemctl'):
            active = self._run(['systemctl', 'show', 'mtproxyl-zapret2.service', '--property=ActiveState', '--value']).strip() == 'active'
        nft = {'nftables': []}
        if shutil.which('nft'): nft = self._normal_nft(json.loads(self._run(['nft', '-j', 'list', 'ruleset'])))
        elif active: raise ValueError('Для проверки активного Zapret2 требуется nft')
        return dict(baseline=self.hooks.get('baseline', lambda: {})(), awg=awg,
                    docker=sorted(docker, key=lambda item: item['id']), processes=sorted(processes, key=lambda item: item['pid']),
                    zapretActive=active, nft=nft)

    def _capture(self):
        value = dict(code=self._files(), protected=self._protected(), runtime=self._runtime())
        self._guard(value)
        return value

    def _guard(self, snapshot):
        runtime = snapshot['runtime']
        protected_awg = bool(runtime.get('awg')) or any(re.search(r'amnezia|wireguard|awg', item.get('image', '') + item.get('name', ''), re.I)
            for item in runtime.get('docker', []))
        if not protected_awg or not runtime.get('zapretActive'): return
        script = self._sys('/usr/local/sbin/mtproxyl-zapret2-start.sh')
        text = script.read_text() if script.is_file() else ''
        if not all(token in text for token in ('awg*', 'iifname', 'oifname')):
            raise ValueError('Не подтверждено сохранение исключения awg* в стартовом скрипте Zapret2')
        config = self.root / 'nft-rules.conf'
        # Upstream's nft configuration reader accepts its native single-quoted
        # form. A shell-looking double-quoted value is not equivalent there.
        match = re.search(r"^ZAPRET2_EXCLUDE_IFACES='([^'\r\n]*)'$", config.read_text() if config.is_file() else '', re.M)
        if not match or 'awg*' not in match.group(1).split():
            raise ValueError('Перед обновлением нужно сохранить awg* в штатной настройке ZAPRET2_EXCLUDE_IFACES; иначе следующая команда менеджера может убрать локальную правку')
        entries = runtime.get('nft', {}).get('nftables', [])
        chains = {}; rules = {}
        for entry in entries:
            if 'chain' in entry:
                item = entry['chain']; chains[(item.get('family'), item.get('table'), item.get('name'))] = item
            if 'rule' in entry:
                item = entry['rule']; rules.setdefault((item.get('family'), item.get('table'), item.get('chain')), []).append(item)
        queued = 0
        for key, chain_rules in rules.items():
            indices = [i for i, rule in enumerate(chain_rules) if any('queue' in expr for expr in rule.get('expr', []))]
            if not indices: continue
            queued += 1
            hook = chains.get(key, {}).get('hook')
            needed = {'forward': ('iifname', 'oifname'), 'prerouting': ('iifname',), 'postrouting': ('oifname',), 'output': ('oifname',)}.get(hook)
            if not needed: raise ValueError('Неизвестная цепочка очереди Zapret2; обновление остановлено')
            for direction in needed:
                if not any(self._bypass(rule, direction) for rule in chain_rules[:min(indices)]):
                    raise ValueError('В активных правилах Zapret2 нет раннего обхода awg* для ' + direction)
        if not queued: raise ValueError('Не удалось проверить активные очереди Zapret2')

    @staticmethod
    def _bypass(rule, direction):
        match = False; verdict = False
        for expr in rule.get('expr', []):
            if 'counter' in expr: continue
            if 'accept' in expr or 'return' in expr: verdict = True; continue
            value = expr.get('match')
            if value == {'op': '==', 'left': {'meta': {'key': direction}}, 'right': 'awg*'}: match = True
            else: return False
        return match and verdict

    @staticmethod
    def _assert_source(code):
        # Legacy 1.7.17 installers deployed the exact code without the release
        # archive's redundant version metadata. The executable VERSION and every
        # library still have to match; no missing executable file is accepted.
        expected = {name: value for name, value in SOURCE_HASHES.items() if name != 'version' or name in code}
        if {name: meta['sha256'] for name, meta in code.items()} != expected:
            raise ValueError('Код установленного MTProxyL отличается от проверенного официального v1.7.17. Локальные изменения не будут перезаписаны; нужна отдельная проверка.')

    def _request(self, req):
        if req.get('component') != 'mtproxyl' or req.get('version', '').lstrip('v') != ARTIFACT['version']:
            raise ValueError('Проверено только обновление менеджера MTProxyL до v1.7.18')
        version = self.hooks['versions']().get('mtproxyl', '').lstrip('v')
        if version != '1.7.17':
            raise ValueError('Безопасное обновление поддерживает только MTProxyL v1.7.17 → v1.7.18. Для этой установки нужна отдельная проверка миграции; рабочие сервисы не изменены.')

    def plan(self, req):
        self._request(req)
        snapshot = self._capture()
        self._assert_source(snapshot['code'])
        revision = _digest(dict(artifact=ARTIFACT, snapshot=snapshot))
        return dict(revision=revision, request=dict(kind='update', component='mtproxyl', version='v' + ARTIFACT['version'], managerRevision=revision),
            summary=dict(title='MTProxyL: обновить код менеджера до v1.7.18',
                component='mtproxyl', current='1.7.17', target='1.7.18',
                version='v1.7.18', backupRequired=True,
                impact='Обновляется только код менеджера и библиотеки. Прокси, AWG и Zapret2 не перезапускаются; активные процессы и защищённые настройки проверяются до и после.',
                rollback='Перед записью сохраняется точный код менеджера. Ошибка замены запускает проверяемый откат файлов; ядро прокси, VPN, конфигурация и правила не меняются. Отдельное обновление ядра прокси этой операцией не выполняется.',
                warning='Только код менеджера и библиотеки. Без перезапуска прокси, AWG и Zapret2. Конфигурация, локальные исключения awg* и правила проверяются до и после.',
                source=ARTIFACT['url'], commit=ARTIFACT['commit'], sha256=ARTIFACT['sha256']))

    def _download(self):
        if 'download' in self.hooks: return self.hooks['download']()
        request = Request(ARTIFACT['url'], headers={'User-Agent': 'ServerDeck-manager-update'})
        with urlopen(request, timeout=60) as response:
            data = response.read(ARTIFACT['size'] + 1)
        return data

    def _stage(self, data, destination):
        if len(data) != ARTIFACT['size'] or hashlib.sha256(data).hexdigest() != ARTIFACT['sha256']:
            raise ValueError('Размер или SHA-256 официального архива MTProxyL не совпадает; файлы не изменены')
        files = {}; seen = set(); expanded = 0
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for item in archive:
                parts = pathlib.PurePosixPath(item.name).parts
                if not parts or parts[0] != ARTIFACT['prefix'] or any(p in ('.', '..') for p in item.name.split('/')) or item.name.startswith('/') or '\\' in item.name:
                    raise ValueError('Небезопасный путь в архиве MTProxyL')
                if item.name in seen: raise ValueError('Повтор файла в архиве MTProxyL')
                seen.add(item.name)
                if not item.isfile() and not item.isdir(): raise ValueError('Ссылки и специальные файлы в архиве MTProxyL запрещены')
                if item.size > MAX_FILE: raise ValueError('Слишком большой файл архива MTProxyL')
                expanded += item.size
                if expanded > MAX_EXPANDED or len(seen) > 1000: raise ValueError('Слишком большой архив MTProxyL')
                relative = '/'.join(parts[1:])
                if not item.isfile() or not CODE_NAME.fullmatch(relative): continue
                if relative in files: raise ValueError('Повтор пути кода в архиве MTProxyL')
                payload = archive.extractfile(item).read(MAX_FILE + 1)
                if len(payload) != item.size: raise ValueError('Неполный файл архива MTProxyL')
                path = destination / relative; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload); path.chmod(0o755 if relative == 'mtproxyl.sh' else 0o644)
                files[relative] = path
        if not {'mtproxyl.sh', 'version'} <= set(files): raise ValueError('В архиве нет полного кода менеджера')
        main = files['mtproxyl.sh'].read_text()
        if re.search(r'^VERSION="' + re.escape(ARTIFACT['version']) + r'"$', main, re.M) is None or files['version'].read_text().strip() != ARTIFACT['version']:
            raise ValueError('Версия кода в архиве не совпадает с проверенной')
        match = re.search(r'^for _lib in ([A-Za-z0-9_ \-]+); do$', main, re.M)
        if not match or any('lib/' + name + '.sh' not in files for name in match.group(1).split()):
            raise ValueError('В архиве отсутствуют обязательные библиотеки менеджера')
        for name, path in files.items():
            if name.endswith('.sh'): self._run(['bash', '-n', str(path)])
        return files

    @contextlib.contextmanager
    def _lock(self):
        # Compatible with native 1.7.18 mkdir/pid lock. Never delete even a stale
        # foreign lock: that needs separate administrator review.
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try: self.lock_path.mkdir(mode=0o700)
        except FileExistsError: raise ValueError('MTProxyL занят другой операцией; повторите после её завершения')
        try:
            (self.lock_path / 'pid').write_text(str(os.getpid()) + '\n')
            (self.lock_path / 'cmd').write_text('ServerDeck pinned code-only update\n')
            yield
        finally:
            if (self.lock_path / 'pid').is_file() and (self.lock_path / 'pid').read_text().strip() == str(os.getpid()):
                (self.lock_path / 'pid').unlink()
                (self.lock_path / 'cmd').unlink(missing_ok=True)
                self.lock_path.rmdir()

    def _backup(self, snapshot, code):
        directory = self.state / 'manager-code-backups' / (time.strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(6))
        directory.mkdir(parents=True, mode=0o700)
        for name in code:
            target = directory / 'code' / name; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(self.root / name, target)
            if hashlib.sha256(target.read_bytes()).hexdigest() != snapshot['code'][name]['sha256']:
                raise ValueError('Не удалось проверить резервную копию кода MTProxyL')
            with target.open('rb') as stream: os.fsync(stream.fileno())
        manifest = directory / 'manifest.json'
        with manifest.open('x') as stream:
            stream.write(json.dumps(dict(artifact=ARTIFACT, snapshot=snapshot), sort_keys=True))
            stream.flush(); os.fsync(stream.fileno())
        manifest.chmod(0o600)
        for path in (directory / 'code' / 'lib', directory / 'code', directory, directory.parent):
            if not path.is_dir(): continue
            fd = os.open(str(path), os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
        return directory

    def _replace(self, source, destination, mode):
        if destination.is_symlink() or destination.parent.is_symlink(): raise ValueError('Цель замены кода стала ссылкой')
        temp = destination.parent / ('.deck-code-' + secrets.token_hex(8))
        try:
            with temp.open('xb') as stream:
                stream.write(source.read_bytes()); stream.flush(); os.fsync(stream.fileno())
            temp.chmod(mode)
            os.replace(temp, destination)
            fd = os.open(str(destination.parent), os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally: temp.unlink(missing_ok=True)

    def apply(self, req):
        self._request(req)
        with self._lock():
            before = self._capture()
            self._assert_source(before['code'])
            revision = _digest(dict(artifact=ARTIFACT, snapshot=before))
            if req.get('managerRevision') != revision: raise ValueError('Состояние менеджера или защиты AWG изменилось; создайте новый план')
            self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix='.manager-code-', dir=str(self.root)) as temp:
                stage = pathlib.Path(temp)
                files = self._stage(self._download(), stage)
                # Download/syntax checking may take time: recheck before backup/write.
                if self._capture() != before: raise ValueError('Состояние изменилось во время подготовки; файлы не изменены')
                backup = self._backup(before, before['code'])
                if self._capture() != before: raise ValueError('Состояние изменилось во время копирования; файлы не изменены')
                changed = []
                order = sorted(name for name in files if name.startswith('lib/')) + ['version', 'mtproxyl.sh']
                try:
                    for name in order:
                        # Record before the operation: rename may succeed before
                        # a subsequent fsync reports a disk error.
                        changed.append(name)
                        self._replace(files[name], self.root / name, 0o755 if name == 'mtproxyl.sh' else 0o644)
                except BaseException as error:
                    rollback_ok = True
                    for name in reversed(changed):
                        try:
                            if name in before['code']:
                                meta = before['code'][name]
                                self._replace(backup / 'code' / name, self.root / name, meta['mode'])
                                os.chown(self.root / name, meta['uid'], meta['gid'])
                            else: (self.root / name).unlink(missing_ok=True)
                        except Exception: rollback_ok = False
                    if self._files() != before['code']: rollback_ok = False
                    self._log('Ошибка записи менеджера; откат кода ' + ('проверен' if rollback_ok else 'требует проверки'))
                    raise RuntimeError('Обновление кода прервано; ' + ('исходный код восстановлен' if rollback_ok else 'откат требует проверки') + '. Рабочие службы не перезапускались.') from error
                after = self._capture()
                expected = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()}
                if any(after['code'].get(name, {}).get('sha256') != value for name, value in expected.items()):
                    raise RuntimeError('Код после обновления требует проверки; службы не перезапускались')
                if before['protected'] != after['protected'] or before['runtime'] != after['runtime']:
                    raise RuntimeError('После обновления обнаружено изменение защищённого состояния; нужна проверка. Правила и службы автоматически не откатывались.')
                self._log('Проверено обновление только кода менеджера MTProxyL v1.7.17 → v1.7.18; AWG, Zapret2 и прокси сохранили состояние')
                return dict(verified=True, managerOnly=True, version=ARTIFACT['version'], backup=str(backup),
                    message='Код менеджера MTProxyL обновлён до v1.7.18. Прокси, AWG и Zapret2 не перезапускались; защищённые настройки и работающие процессы проверены.')
