"""Fixed remote recipes, injected into the existing one-shot SSH worker."""
import hashlib, io, json, os, pathlib, re, secrets, shlex, shutil, socket, subprocess, tarfile, tempfile, time, urllib.request

class SoftwareAdapter:
    def __init__(self,runtime):self.r=runtime
    def run(self,args,timeout=30):return self.r['run'](args,timeout)
    def output(self,args):
        p=subprocess.run(args,capture_output=True,text=True,timeout=20,env=dict(os.environ,LC_ALL='C'))
        return p.stdout.strip() if p.returncode==0 else ''
    def inventory(self):
        v=self.r['versions']();arch=os.uname().machine
        osinfo={}
        for line in pathlib.Path('/etc/os-release').read_text().splitlines():
            k,sep,val=line.partition('=')
            if sep:osinfo[k]=val.strip('"')
        units={}
        for unit in ('x-ui','mtproxyl','mtproxyl-panel','fail2ban','systemd-resolved'):
            out=self.output(['systemctl','show',unit+'.service','--property=LoadState,ActiveState,MainPID'])
            units[unit]=dict(line.split('=',1) for line in out.splitlines() if '=' in line)
        containers=[]
        if shutil.which('docker'):
            # Fail closed if Docker exists but its inventory cannot be read.
            for line in self.run(['docker','ps','-a','--format','{{json .}}']).splitlines():
                d=json.loads(line);containers.append(dict(name=d['Names'],image=d['Image'],state=d['State'],id=d['ID']))
        interfaces=self.run(['awg','show','interfaces']).split() if shutil.which('awg') else []
        interfaces=sorted(set(interfaces+[p.name for p in pathlib.Path('/sys/class/net').iterdir() if p.name.startswith(('awg','awgo-'))]))
        awg_containers=[d['name'] for d in containers if re.search(r'(?i)amnezia|wireguard|(^|[-_/])awg',d['name']+' '+d['image'])]
        ports=[]
        for line in self.run(['ss','-H','-lntu']).splitlines():
            parts=line.split()
            if len(parts)>4:
                try:ports.append(int(parts[4].rsplit(':',1)[1]))
                except ValueError:pass
        pkg=self.output(['dpkg-query','-W','-f=${db:Status-Status}|${Version}','fail2ban'])
        failversion=pkg.split('|',1)[1] if pkg.startswith('installed|') else ''
        candidate=re.search(r'^\s*Candidate:\s*(\S+)',self.output(['apt-cache','policy','fail2ban']),re.M)
        components={k:{'installed':bool(v.get(k)),'version':v.get(k,''),'state':units.get(k if k!='lucx' else 'x-ui',{}).get('ActiveState','')} for k in ('lucx','mtproxyl','mtproxyl-panel','telemt','awg')}
        components['lucx']['conflict']=pathlib.Path('/etc/x-ui').exists() or pathlib.Path('/usr/local/x-ui').exists() or pathlib.Path('/usr/bin/x-ui').exists() or units['x-ui'].get('LoadState')=='loaded' or any(re.search(r'(?i)lucx|[3x]-ui',x['name']+' '+x['image']) for x in containers)
        components['lucx']['foreignVariant']=bool(v.get('lucx') and 'lucx' not in v['lucx'])
        components['mtproxyl']['conflict']=pathlib.Path('/opt/mtproxyl').exists() or any('mtprox' in (x['name']+' '+x['image']).lower() or 'telemt' in x['image'].lower() for x in containers) or bool(shutil.which('telemt'))
        components['mtproxyl-panel']['conflict']=pathlib.Path('/etc/mtproxyl-panel').exists() or pathlib.Path('/opt/etc/mtproxyl-panel').exists()
        components['awg'].update(protected=bool(interfaces or awg_containers),interfaces=interfaces,containers=awg_containers)
        components['fail2ban']=dict(installed=bool(failversion),version=failversion,candidate=candidate.group(1) if candidate else '',state=units['fail2ban'].get('ActiveState',''))
        config_hashes={}
        for name in ('/opt/mtproxyl/settings.conf','/etc/mtproxyl-panel/config.toml','/etc/default/x-ui','/usr/local/sbin/mtproxyl-zapret2-start.sh'):
            p=pathlib.Path(name)
            if p.is_file():config_hashes[name]=hashlib.sha256(p.read_bytes()).hexdigest()
        supported=osinfo.get('ID') in ('ubuntu','debian') and pathlib.Path('/run/systemd/system').is_dir() and arch in ('x86_64','aarch64')
        memory=re.search(r'^MemTotal:\s*(\d+)',pathlib.Path('/proc/meminfo').read_text(),re.M)
        memory_mib=int(memory.group(1))//1024 if memory else 0
        swap_active=len(pathlib.Path('/proc/swaps').read_text().splitlines())>1
        return dict(components=components,versions=v,os=osinfo.get('PRETTY_NAME',''),arch=arch,supported=supported,ports=sorted(set(ports)),containers=containers,units=units,configHashes=config_hashes,totalMemoryMiB=memory_mib,swapActive=swap_active,bootId=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())

    def require_commands(self,names):
        missing=[n for n in names if not shutil.which(n)]
        if missing:raise ValueError('Сначала установите зависимости: '+', '.join(missing)+'. Работающие службы не изменялись.')

    def mt_mode(self):
        text=self.r['mt_cli']('mode','--json')
        for line in text.splitlines():
            if line.startswith('{'):return json.loads(line)
        raise ValueError('Установленный MTProxyL не поддерживает чтение режима. Сначала обновите менеджер.')

    def snapshot(self):
        inventory=self.inventory();files={}
        roots=('/etc/os-release','/etc/fstab','/etc/sysctl.conf','/etc/default/x-ui','/etc/mtproxyl-panel','/etc/fail2ban','/etc/amnezia','/etc/wireguard','/etc/sysctl.d','/etc/systemd/system/x-ui.service','/etc/systemd/system/x-ui.service.d','/etc/systemd/system/mtproxyl-panel.service','/usr/local/sbin/mtproxyl-zapret2-start.sh')
        for name in roots:
            root=pathlib.Path(name)
            paths=list(root.rglob('*')) if root.is_dir() else [root]
            for p in paths:
                if p.is_symlink() or not p.is_file():continue
                if p.stat().st_size>4*1024*1024:raise ValueError('Файл конфигурации превышает лимит копии')
                files['host-files/'+str(p).lstrip('/')]=p.read_bytes()
        if sum(map(len,files.values()))>20*1024*1024:raise ValueError('Конфигурация хоста превышает лимит копии')
        revision=self.r['digest']({k:hashlib.sha256(v).hexdigest() for k,v in files.items()})
        metadata=dict(format=1,panel='host',createdAt=time.time(),hostname=os.uname().nodename,revision=revision,versions=inventory['versions'],coverage='Снимок конфигурации systemd, AWG на хосте, Fail2ban, sysctl и веб-панели MTProxyL. Не образ диска: пакеты, бинарники, Docker-тома, SSH-ключи и БД LucX сюда не входят. Восстановление только вручную.')
        files['manifest.json']=json.dumps(metadata,ensure_ascii=False).encode();files['host-state.json']=json.dumps(inventory,ensure_ascii=False).encode();data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as tar:
            for name,body in files.items():
                info=tarfile.TarInfo(name);info.size=len(body);info.mode=0o600;tar.addfile(info,io.BytesIO(body))
        import base64
        return dict(metadata=metadata,data=base64.b64encode(data.getvalue()).decode(),sha256=hashlib.sha256(data.getvalue()).hexdigest())

    def validate_sources(self,req,inv):
        c=req['component'];s=req.get('sources',{});repo='AlexeyLCP/lucx-ui' if c in ('lucx','awg') else 'Liafanx/MTProxyL'
        if s.get('repo')!=repo or s.get('version')!=req['version'] or not re.fullmatch(r'[a-f0-9]{40}',s.get('commit','')):raise ValueError('Источник релиза не закреплён')
        paths={'lucx':{'unit':'x-ui.service.debian','cli':'x-ui.sh'},'mtproxyl':{'installer':'install.sh'},'mtproxyl-panel':{'installer':'mtproxyl-panel/install.sh'},'awg':{'installer':'bin/install-awg-module.sh'}}[c]
        for key,path in paths.items():
            a=s.get(key,{})
            if a.get('url')!='https://raw.githubusercontent.com/'+repo+'/'+s['commit']+'/'+path or not re.fullmatch(r'[a-f0-9]{64}',a.get('sha256','')):raise ValueError('Неверный источник рецепта')
        if c in ('lucx','mtproxyl-panel'):
            name='x-ui-linux-'+('amd64' if inv['arch']=='x86_64' else 'arm64')+'.tar.gz' if c=='lucx' else 'mtproxyl-panel-'+inv['arch']+'-linux-gnu.tar.gz'
            a=s.get('archive',{})
            if a.get('url')!='https://github.com/'+repo+'/releases/download/'+req['version']+'/'+name or not re.fullmatch(r'[a-f0-9]{64}',a.get('sha256','')):raise ValueError('Неверная сборка или контрольная сумма')

    def plan(self,req):
        c=req.get('component');kind=req.get('kind');install=kind=='install'
        if c not in ('lucx','mtproxyl','mtproxyl-panel','awg','fail2ban') or kind not in ('install','update'):raise ValueError('Этот рецепт не поддерживается')
        inv=self.inventory();item=inv['components'][c]
        if not inv['supported']:raise ValueError('Рецепты поддерживают Ubuntu/Debian с systemd, x86_64 или aarch64')
        if install and (item['installed'] or item.get('conflict')):raise ValueError('Компонент или его конфигурация уже существует. Установка поверх запрещена; используйте обновление.')
        if not install and not item['installed']:raise ValueError('Компонент не установлен')
        if c=='lucx' and item['installed'] and 'lucx' not in item['version']:raise ValueError('Обнаружен другой вариант x-ui. Автоматическая замена на LucX запрещена.')
        version=req.get('version','')
        if c!='fail2ban':
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',version):raise ValueError('Выберите стабильный релиз')
            self.validate_sources(req,inv)
        if not install and c in ('lucx','mtproxyl-panel'):
            target=tuple(map(int,re.findall(r'\d+',version)));current=tuple(map(int,re.findall(r'\d+',item['version'])))
            if target<=current:raise ValueError('Нужна более новая версия. Повторная установка и понижение запрещены.')
        normalized=dict(kind=kind,component=c,version=version,sources=req.get('sources',{}))
        port=None;details=[]
        if install and c in ('lucx','mtproxyl','mtproxyl-panel'):
            port=req.get('port')
            if isinstance(port,bool) or not isinstance(port,int) or not 1024<=port<=65535:raise ValueError('Укажите свободный порт от 1024 до 65535')
            if port in inv['ports']:raise ValueError('Порт '+str(port)+' уже занят. Работающий сервис не будет остановлен.')
            normalized['port']=port
            details.append(('Панель только на 127.0.0.1:' if c!='mtproxyl' else 'MTProto на TCP-порту ')+str(port))
        if c=='lucx':
            if shutil.disk_usage('/usr/local').free<2*1024**3:raise ValueError('Для безопасной подготовки и сохранения предыдущей сборки нужно 2 ГиБ свободного места')
            if not install and not pathlib.Path('/etc/x-ui/install-result.env').is_file():raise ValueError('Не найдены сохранённые параметры LucX; сначала подключите существующую панель')
            details+=['Проверка SHA-256 и распаковка до остановки LucX','Замена файлов панели и комплектных движков; конфигурация и пользовательские файлы сохраняются','AWG, пакеты ОС, Fail2ban и ACME не переустанавливаются']
        elif c=='mtproxyl':
            if inv.get('totalMemoryMiB',0)<=1024 and not inv.get('swapActive'):
                raise ValueError('На VPS не больше 1 ГиБ RAM и нет swap. Штатный установщик создаёт swap автоматически, поэтому этот рецепт заблокирован до отдельной подготовки сервера.')
            self.require_commands(('curl','tar','openssl','jq','awk'))
            if not (shutil.which('nano') or shutil.which('vim')):raise ValueError('Установщику нужен nano или vim; автоматическая установка пакетов в этом рецепте отключена предварительной проверкой')
            host=req.get('serverHost','');sni=req.get('sni','')
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',host) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,251}\.[A-Za-z]{2,}',sni):raise ValueError('Укажите корректный адрес и домен FakeTLS')
            normalized.update(serverHost=host,sni=sni)
            if any(p in inv['ports'] for p in (9090,9091)) or port in (9090,9091):raise ValueError('Для новой установки MTProxyL нужны свободные порты 9090 и 9091')
            # The current pinned manager supports binary carrier without installing Docker.
            if version!='v1.7.17':raise ValueError('Рецепт новой установки проверен для MTProxyL v1.7.17')
            details+=['Официальный установщик из закреплённого commit; бинарный движок, без установки Docker','Zapret2, SYN limiter, WEB Proxy и MEKO-тюнинг отключены','Создаётся новый секрет default; существующие VPN не перенастраиваются']
        elif c=='mtproxyl-panel':
            if not inv['components']['mtproxyl']['installed']:raise ValueError('Сначала установите MTProxyL')
            if install:
                self.require_commands(('curl','tar','openssl','visudo','useradd','usermod'))
                if version!='mtproxyl-panel-v1.3.13':raise ValueError('Первичная настройка проверена для панели v1.3.13')
                if sys_version()< (3,11):raise ValueError('Для встроенного входа MTProxyL требуется Python 3.11 или новее на VPS')
                mode=self.mt_mode()
                if mode.get('mode')!='manager' or mode.get('api_enabled') is not True:raise ValueError('Нужен MTProxyL Manager с уже включённым API. Движок автоматически не перенастраивается.')
            details+=['Локальная веб-панель; существующий движок и его клиенты сохраняются','Перезапускается только mtproxyl-panel.service']
        elif c=='awg':
            if item.get('protected'):raise ValueError('AWG используется интерфейсами или контейнерами. Установка/обновление модуля заблокировано, чтобы не оборвать VPN.')
            if self.output(['cat','/sys/module/amneziawg/refcnt']) not in ('','0'):raise ValueError('Модуль AWG используется ядром; обслуживание заблокировано')
            if version!='v3.11.0-lucx.332':raise ValueError('Проверен рецепт AWG из LucX .332')
            if not pathlib.Path('/lib/modules/'+os.uname().release+'/build/Makefile').exists():raise ValueError('Нет headers текущего ядра. Обновление ядра ОС из этого рецепта запрещено.')
            self.require_commands(('dkms','make','gcc','git','pkg-config','curl','modprobe','iptables','resolvconf'))
            if subprocess.run(['pkg-config','--exists','libmnl'],capture_output=True).returncode:raise ValueError('Для сборки требуется libmnl-dev')
            details+=['Сборка модуля и инструментов AWG для текущего ядра','Установка пакетов, обновление ядра, настройки DNS и sysctl исключены из рецепта','VPN-интерфейсы и клиенты автоматически не создаются']
        elif c=='fail2ban':
            version=item['candidate']
            if not version or version=='(none)' or not re.fullmatch(r'[A-Za-z0-9.+:~_-]+',version):raise ValueError('Кандидат APT не найден. Кэш пакетов автоматически не обновляется.')
            if version==item['version']:raise ValueError('В текущем кэше APT более новой версии нет')
            normalized['version']=version
            output=self.run(['apt-get','-s','--no-remove','install','fail2ban='+version],60)
            packages=[x for x in output.splitlines() if x.startswith(('Inst ','Remv ','Conf '))]
            if any(x.startswith('Remv ') or (x.startswith('Inst ') and '[' in x and not x.startswith('Inst fail2ban ')) for x in packages):raise ValueError('APT требует удаления или обновления других пакетов. Такой план не применяется.')
            normalized['packages']=packages
            details+=['Только fail2ban и новые зависимости; существующие конфиги сохраняются','Служба Fail2ban может перезапуститься; новые правила из Server Deck не создаются']
        normalized['backupPanels']=[p for p in ('lucx','mtproxyl') if inv['components'][p]['installed']]
        # Include stored panel state, not counters, so edits between preview and execute invalidate it.
        revisions={p:self.r['revisions'](p) for p in normalized['backupPanels']}
        revision=self.r['digest']([inv,normalized,revisions])
        names={'lucx':'LucX / 3x-ui','mtproxyl':'MTProxyL','mtproxyl-panel':'Веб-панель MTProxyL','awg':'AmneziaWG','fail2ban':'Fail2ban'}
        return dict(revision=revision,request=normalized,summary=dict(title=('Установить · ' if install else 'Обновить · ')+names[c],component=c,version=version,current=item['version'] or 'Не установлен',impact='Устанавливается новый компонент. Работающие службы не останавливаются рецептом.' if install else 'Обслуживание выбранного компонента может прервать его подключения. Автоперезагрузки VPS нет.',steps=details,backupRequired=True,backupNote='Будет сохранён снимок конфигурации хоста и копии установленных LucX/MTProxyL. Это не полный образ диска; Docker-тома и пакеты ОС не входят.',rollback='При ошибке задача не повторяется. Предыдущая сборка LucX и бинарник панели сохраняются на VPS; автоматического отката БД нет.',packages=normalized.get('packages'),source=(req.get('sources') or {}).get('commit')))

    def download(self,artifact,destination,limit=350*1024*1024):
        if not re.fullmatch(r'[a-f0-9]{64}',artifact.get('sha256','')):raise ValueError('Нет контрольной суммы')
        size=0;h=hashlib.sha256()
        with urllib.request.urlopen(artifact['url'],timeout=60) as response,open(destination,'xb') as output:
            while True:
                block=response.read(1024*1024)
                if not block:break
                size+=len(block)
                if size>limit:raise ValueError('Сборка превышает лимит')
                h.update(block);output.write(block)
        if h.hexdigest()!=artifact['sha256'] or size!=artifact.get('size',size):raise ValueError('Сборка изменилась или повреждена; SHA-256 не совпала')

    def unpack(self,archive,destination):
        with tarfile.open(archive,'r:gz') as tar:
            members=tar.getmembers()
            if sum(m.size for m in members)>2*1024**3:raise ValueError('Распакованная сборка слишком большая')
            names=set()
            for m in members:
                p=pathlib.PurePosixPath(m.name)
                if p.is_absolute() or '..' in p.parts or not (m.isfile() or m.isdir()) or m.name in names:raise ValueError('Небезопасный путь или ссылка в архиве')
                names.add(m.name)
            for m in members:
                target=pathlib.Path(destination)/m.name
                if m.isdir():target.mkdir(parents=True,exist_ok=True,mode=0o755)
                else:
                    target.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
                    with open(target,'xb') as f:shutil.copyfileobj(tar.extractfile(m),f)
                    target.chmod(0o755 if m.mode&0o111 else 0o644)

    def execute_script(self,path,args=(),env=None,timeout=1500):
        # Installer output may contain generated credentials: never copy it into the UI log.
        p=subprocess.run(['bash',str(path)]+list(args),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l',**(env or {})),timeout=timeout)
        if p.returncode:raise RuntimeError('Установщик завершился с кодом '+str(p.returncode)+'. Требуется проверка сервера; автоматического повтора нет.')

    def apply(self,req):
        c=req['component'];install=req['kind']=='install';sources=req.get('sources',{})
        before=self.r['versions']()
        if c=='fail2ban':
            env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l',LC_ALL='C')
            p=subprocess.run(['apt-get','-y','--no-remove','-o','Dpkg::Options::=--force-confold','install','fail2ban='+req['version']],env=env,capture_output=True,text=True,timeout=900)
            self.r['update_log'](p.stdout+'\n'+p.stderr)
            if p.returncode:raise RuntimeError('APT завершился с ошибкой; проверьте журнал задачи')
            if self.inventory()['components']['fail2ban']['version']!=req['version']:raise RuntimeError('Версия пакета не подтвердилась')
        else:
            with tempfile.TemporaryDirectory(prefix='deck-software-',dir='/usr/local') as td:
                temp=pathlib.Path(td)
                for key in ('archive','unit','cli','installer'):
                    if key in sources:self.download(sources[key],temp/key)
                if req.get('expiresAt',time.time()+1)<time.time():raise ValueError('План истёк во время скачивания. Изменения не начались.')
                if req.get('revision') and self.plan(req)['revision']!=req['revision']:raise ValueError('Состояние изменилось во время скачивания. Установка не началась; создайте новый план.')
                if c=='lucx':self.install_lucx(req,temp)
                elif c=='mtproxyl':
                    self.execute_script(temp/'installer',['--branch',sources['commit'],'--','--mode','manager','--engine','binary','--service-name','standard','--proxy-mode','mtproto','--port',str(req['port']),'--metrics-port','9090','--api-port','9091','--host',req['serverHost'],'--sni',req['sni'],'--zapret2','no','--syn-limiter','off','--meko','no','--dc-restart','off'],{'MTPROXYL_ASSUME_YES':'1'})
                    if self.r['versions']().get('mtproxyl')!=req['version'].lstrip('v'):raise RuntimeError('Версия MTProxyL после установки не подтверждена')
                    # Pin was for installation. Native updates must follow stable releases, not a commit branch.
                    branch=pathlib.Path('/opt/mtproxyl/.branch')
                    if branch.exists() and branch.read_text().strip()==sources['commit']:branch.unlink()
                    self.r['mt_users']()
                elif c=='mtproxyl-panel':self.install_mt_panel(req,temp)
                elif c=='awg':
                    raw=(temp/'installer').read_text()
                    raw=bounded_awg_script(raw)
                    (temp/'installer').write_text(raw)
                    self.execute_script(temp/'installer',['--no-kernel-upgrade'])
                    if not self.r['versions']().get('awg') or not pathlib.Path('/sys/module/amneziawg').exists() or not shutil.which('awg'):raise RuntimeError('Модуль AWG после сборки не загружен или инструменты не найдены')
        return dict(verified=True,before=before,after=self.r['versions'](),message='Компонент установлен/обновлён. Состояние проверено; прохождение VPN-трафика проверяется отдельным клиентом.')

    def install_lucx(self,req,temp):
        install=req['kind']=='install';live=pathlib.Path('/usr/local/x-ui');stage=temp/'unpacked';stage.mkdir()
        self.unpack(temp/'archive',stage);incoming=stage/'x-ui'
        if not (incoming/'x-ui').is_file() or not (incoming/'bin').is_dir():raise ValueError('Неожиданный состав сборки LucX')
        version=self.output([str(incoming/'x-ui'),'-v'])
        if version.lstrip('v')!=req['version'].lstrip('v'):raise ValueError('Версия бинарника не совпадает с релизом')
        if not install:
            # Merge custom files into the staged release before touching the live directory.
            for old in live.rglob('*'):
                relative=old.relative_to(live);new=incoming/relative
                if old.is_symlink():raise ValueError('В каталоге LucX есть пользовательские симлинки; требуется ручной план обновления')
                if old.is_file() and not new.exists():new.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(old,new)
        backup=pathlib.Path('/usr/local/x-ui.before-deck-'+req['job'])
        if backup.exists():raise ValueError('Путь предыдущей сборки уже существует')
        # Nothing has stopped until both archive validation and staging have succeeded.
        if not install:
            self.run(['systemctl','stop','x-ui.service']);os.rename(live,backup)
        os.rename(incoming,live)
        if install:
            pathlib.Path('/etc/x-ui').mkdir(mode=0o700)
            pathlib.Path('/var/log/x-ui').mkdir(mode=0o700,exist_ok=True)
            pathlib.Path('/etc/amnezia').mkdir(mode=0o700,exist_ok=True)
            user='deck_'+secrets.token_hex(4);password=secrets.token_urlsafe(30);base='/'+secrets.token_urlsafe(18)+'/'
            # New host only: never reset existing credentials or API tokens.
            p=subprocess.run([str(live/'x-ui'),'setting','-username',user,'-password',password,'-port',str(req['port']),'-webBasePath',base,'-listenIP','127.0.0.1'],cwd=str(live),capture_output=True,text=True,timeout=45)
            if p.returncode:raise RuntimeError('Не удалось создать первоначальную конфигурацию LucX')
            token_output=self.output([str(live/'x-ui'),'setting','-getApiToken'])
            match=re.search(r'apiToken:\s*(\S+)',token_output)
            if not match:raise RuntimeError('Не создан API-токен новой панели')
            values=dict(XUI_USERNAME=user,XUI_PASSWORD=password,XUI_PANEL_PORT=str(req['port']),XUI_WEB_BASE_PATH=base,XUI_API_TOKEN=match.group(1),XUI_DB_TYPE='sqlite')
            creds=pathlib.Path('/etc/x-ui/install-result.env');creds.write_text('\n'.join(k+'='+shlex.quote(v) for k,v in values.items())+'\n');creds.chmod(0o600)
            shutil.copyfile(temp/'unit','/etc/systemd/system/x-ui.service');os.chmod('/etc/systemd/system/x-ui.service',0o644)
        shutil.copyfile(temp/'cli','/usr/bin/x-ui');os.chmod('/usr/bin/x-ui',0o755)
        self.run(['systemctl','daemon-reload'])
        self.run(['systemctl','enable' if install else 'start','x-ui.service'])
        if install:self.run(['systemctl','start','x-ui.service'])
        time.sleep(3)
        if self.output(['systemctl','is-active','x-ui.service'])!='active':raise RuntimeError('LucX не запустился. Предыдущая сборка сохранена; проверьте журнал.')
        self.r['lucx_state']()

    def install_mt_panel(self,req,temp):
        stage=temp/'unpacked';stage.mkdir();self.unpack(temp/'archive',stage)
        files=[p for p in stage.rglob('*') if p.is_file() and p.name.startswith('mtproxyl-panel-')]
        if len(files)!=1:raise ValueError('Неожиданный состав сборки MTProxyL-Panel')
        binary=files[0];binary.chmod(0o755);dest=pathlib.Path('/usr/local/bin/mtproxyl-panel')
        if req['kind']=='install':
            mode=self.mt_mode();port=int(mode['api_port'])
            if not 1<=port<=65535:raise ValueError('Неверный локальный порт API')
            password=secrets.token_urlsafe(36)
            p=subprocess.run([str(binary),'hash-password'],input=password+'\n',capture_output=True,text=True,timeout=30)
            if p.returncode or not p.stdout.strip().startswith('$2'):raise RuntimeError('Не удалось подготовить пароль новой панели')
            # Native API auth_header comes from the engine TOML, never from browser input.
            import tomllib
            engine_config=pathlib.Path(mode.get('engine_config','')).resolve()
            if pathlib.Path('/opt/mtproxyl') not in engine_config.parents:raise ValueError('Нестандартный путь конфигурации движка; нужен отдельный адаптер')
            with engine_config.open('rb') as f:engine=tomllib.load(f)
            auth=engine.get('server',{}).get('api',{}).get('auth_header','')
            cfg='listen = "127.0.0.1:'+str(req['port'])+'"\ndata_dir = "/var/lib/mtproxyl-panel"\n[telemt]\nurl = "http://127.0.0.1:'+str(port)+'"\n'
            if auth:cfg+='auth_header = '+json.dumps(auth)+'\n'
            if mode.get('engine')=='binary':
                service=mode.get('engine_service','')
                if not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.service)?',service):raise ValueError('Неверное имя службы Telemt')
                service=service.removesuffix('.service');cfg+='binary_path = '+json.dumps('/opt/mtproxyl/engine/'+service)+'\nservice_name = '+json.dumps(service)+'\n'
            else:cfg+='container_name = "mtproxyl"\n'
            cfg+='[panel]\nbinary_path = "/usr/local/bin/mtproxyl-panel"\nservice_name = "mtproxyl-panel"\n[mtproxyl]\nenabled = true\nscript_path = "/opt/mtproxyl/mtproxyl.sh"\ninstall_dir = "/opt/mtproxyl"\nuse_sudo = true\n[auth]\nusername = "deck-admin"\npassword_hash = '+json.dumps(p.stdout.strip())+'\njwt_secret = '+json.dumps(secrets.token_hex(32))+'\nsession_ttl = "24h"\n'
            folder=pathlib.Path('/etc/mtproxyl-panel');folder.mkdir(mode=0o700)
            config=folder/'config.toml';config.write_text(cfg);config.chmod(0o600)
            self.execute_script(temp/'installer',['install',req['version']])
        else:
            backup=pathlib.Path(str(dest)+'.before-deck-'+req['job']);shutil.copy2(dest,backup);backup.chmod(0o700)
            staged=dest.with_name('.mtproxyl-panel-deck-'+req['job']);shutil.copy2(binary,staged);staged.chmod(0o755);os.replace(staged,dest)
            self.run(['systemctl','restart','mtproxyl-panel.service'])
        if hashlib.sha256(dest.read_bytes()).digest()!=hashlib.sha256(binary.read_bytes()).digest():raise RuntimeError('Установленный бинарник панели отличается от проверенной сборки')
        time.sleep(2)
        if self.output(['systemctl','is-active','mtproxyl-panel.service'])!='active':raise RuntimeError('Веб-панель не запустилась; проверьте журнал')

def sys_version():
    import sys
    return sys.version_info[:2]

def bounded_awg_script(source):
    """Remove the reviewed package/DNS phase; require deps and current headers in preflight."""
    if hashlib.sha256(source.encode()).hexdigest()!='b7ea9ba3e571a16466842b31130d52b2ccdf40683cd76e566934fda465001731':raise ValueError('Установщик AWG не соответствует проверенному рецепту')
    start='# Kernel meta-packages only when a module rebuild is due.'
    end='# 3. Build and install kernel module via DKMS.'
    begin=source.find(start);finish=source.find(end,begin)
    if begin<0 or finish<0:raise ValueError('Структура установщика AWG изменилась; требуется проверка рецепта')
    source=source[:begin]+'# Dependencies verified by Server Deck.\nRUNNING_KERNEL=$(uname -r)\nAWG_REBOOT_FLAG="/etc/x-ui/.awg-reboot-needed"\n[[ -f "/lib/modules/${RUNNING_KERNEL}/build/Makefile" ]] || exit 1\n'+source[finish:]
    return source
