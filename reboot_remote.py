"""Explicit, deduplicated graceful reboot. Preview/status never schedules anything."""
import fcntl, hashlib, json, os, pathlib, re, shutil, subprocess, time

def reboot_digest(info):
    return hashlib.sha256(json.dumps(info,sort_keys=True,separators=(',',':')).encode()).hexdigest()

class RemoteReboot:
    def __init__(self,state):self.state=pathlib.Path(state)
    def output(self,args):
        p=subprocess.run(args,capture_output=True,text=True,timeout=15,env=dict(os.environ,LC_ALL='C'))
        return p.stdout.strip()
    def info(self,req):
        if os.geteuid()!=0 or not pathlib.Path('/run/systemd/system').is_dir():raise ValueError('Перезагрузка поддерживается через root SSH на Linux с systemd')
        if not shutil.which('systemd-run') or not shutil.which('systemctl'):raise ValueError('На сервере нет systemd-run/systemctl')
        units=req.get('services',[])
        if not isinstance(units,list) or len(units)>150 or any(not isinstance(u,str) or not re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service',u) for u in units):raise ValueError('Неверный список служб')
        services={}
        for unit in units:
            text=self.output(['systemctl','show',unit,'--property=LoadState,ActiveState,UnitFileState'])
            value=dict(x.split('=',1) for x in text.splitlines() if '=' in x)
            if not value.get('LoadState'):raise ValueError('Не удалось прочитать состояние служб')
            services[unit]=value
        containers={}
        if shutil.which('docker'):
            p=subprocess.run(['docker','ps','-q'],capture_output=True,text=True,timeout=15)
            if p.returncode:raise ValueError('Не удалось проверить Docker перед перезагрузкой')
            ids=p.stdout.split()
            if ids:
                p=subprocess.run(['docker','inspect','--format','{{.Name}}|{{.HostConfig.RestartPolicy.Name}}']+ids,capture_output=True,text=True,timeout=15)
                if p.returncode:raise ValueError('Не удалось проверить автозапуск Docker')
                for line in p.stdout.splitlines():
                    name,policy=line.split('|',1);containers[name.lstrip('/')]=policy
        awg=[]
        if shutil.which('awg'):
            p=subprocess.run(['awg','show','interfaces'],capture_output=True,text=True,timeout=10)
            if p.returncode:raise ValueError('Не удалось проверить интерфейсы AWG')
            awg=sorted(p.stdout.split())
        apt_busy=[]
        for name in ('/var/lib/dpkg/lock-frontend','/var/lib/dpkg/lock','/var/lib/apt/lists/lock','/var/cache/apt/archives/lock'):
            if not pathlib.Path(name).exists():continue
            with open(name,'r+') as lock:
                try:fcntl.lockf(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:apt_busy.append(name)
                else:fcntl.lockf(lock,fcntl.LOCK_UN)
        system=self.output(['systemctl','is-system-running'])
        return dict(bootId=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),hostname=os.uname().nodename,kernel=os.uname().release,system=system,services=services,containers=containers,awg=awg,aptBusy=apt_busy)
    def status(self,req):
        jid=req.get('job','')
        if not re.fullmatch(r'[a-f0-9]{32}',jid):raise ValueError('Неверная задача')
        value=self.info(req)
        value['scheduled']=any(self.output(['systemctl','is-active','server-deck-reboot-'+jid+suffix]) in ('active','activating','deactivating') for suffix in ('.timer','.service'))
        return value
    def schedule(self,req):
        jid=req.get('job','')
        if not re.fullmatch(r'[a-f0-9]{32}',jid):raise ValueError('Неверная задача')
        if not isinstance(req.get('expiresAt'),(int,float)) or req['expiresAt']<time.time():raise ValueError('План перезагрузки истёк')
        self.state.mkdir(mode=0o700,exist_ok=True)
        with open(self.state/'mutation.lock','a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('На VPS выполняется другая операция')
            info=self.info(req)
            if info['aptBusy']:raise ValueError('APT/dpkg занят. Перезагрузка запрещена до завершения обновлений')
            if info['system'] not in ('running','degraded'):raise ValueError('ОС уже меняет состояние; перезагрузка не отправлена')
            if reboot_digest(info)!=req.get('revision'):raise ValueError('Состояние сервера изменилось; создайте новый план')
            record=self.state/('reboot-'+jid+'.json')
            try:fd=os.open(str(record),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            except FileExistsError:raise ValueError('Эта команда уже отправлялась. Повторная перезагрузка запрещена')
            with os.fdopen(fd,'w') as f:
                json.dump(dict(job=jid,bootId=info['bootId'],createdAt=time.time()),f);f.flush();os.fsync(f.fileno())
            # No --force, no persistent timer, and exactly one request per job.
            p=subprocess.run(['systemd-run','--quiet','--unit=server-deck-reboot-'+jid,'--on-active=5s','--timer-property=AccuracySec=1s',shutil.which('systemctl'),'reboot'],capture_output=True,text=True,timeout=12)
            return dict(accepted=p.returncode==0,error='' if p.returncode==0 else 'systemd-run не подтвердил команду; требуется проверка состояния',bootId=info['bootId'])
