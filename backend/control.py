"""Local control plane: expiring plans, encrypted off-host backups and jobs."""
import base64, concurrent.futures, hashlib, hmac, io, json, os, pathlib, re, secrets, shlex, subprocess, tarfile, tempfile, threading, time, urllib.request
from software import COMPONENTS, prepare_sources
from reboot import Reboots
from service_restart import ServiceRestarts
from custom_components import ProjectCatalog
from update_status import annotate_servers, summarize

MAGIC=b'SERVER-DECK-BACKUP-1\n'
TERMINAL={'succeeded','failed','needs_review','reviewed'}
REPOS={'lucx':'AlexeyLCP/lucx-ui','mtproxyl':'Liafanx/MTProxyL','mtproxyl-panel':'Liafanx/MTProxyL','telemt':'telemt/telemt'}

def atomic(path,value):
    temp=path.with_suffix('.tmp');fd=os.open(str(temp),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(value,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
    os.replace(str(temp),str(path))
    directory=os.open(str(path.parent),os.O_RDONLY)
    try:os.fsync(directory)
    finally:os.close(directory)

class Vault:
    def __init__(self,root):
        self.root=pathlib.Path(root);self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        key=self.root/'recovery.key'
        if not key.exists():
            fd=os.open(str(key),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as f:f.write(secrets.token_bytes(64))
        self.key=key.read_bytes()
        if len(self.key)!=64:raise ValueError('Повреждён ключ хранилища резервных копий')

    def crypt(self,data,password,decrypt=False):
        # Passphrase travels on stdin, never in argv, environment or logs.
        with tempfile.TemporaryDirectory(prefix='.crypto-',dir=str(self.root)) as tmp:
            src=pathlib.Path(tmp)/'input';src.write_bytes(data);src.chmod(0o600)
            args=['/usr/bin/openssl','enc','-aes-256-cbc','-pbkdf2','-iter','200000','-md','sha256','-in',str(src),'-pass','stdin']
            if decrypt:args.append('-d')
            p=subprocess.run(args,input=base64.b64encode(password)+b'\n',capture_output=True,timeout=30)
            if p.returncode:raise ValueError('Не удалось обработать зашифрованную копию')
            return p.stdout

    def encrypt(self,data,metadata):
        salt=secrets.token_bytes(32)
        enc=hmac.new(self.key[:32],b'encryption'+salt,hashlib.sha256).digest()
        mac=hmac.new(self.key[32:],b'authentication'+salt,hashlib.sha256).digest()
        header=json.dumps(dict(metadata,salt=base64.b64encode(salt).decode()),sort_keys=True,ensure_ascii=False).encode()
        body=MAGIC+len(header).to_bytes(4,'big')+header+self.crypt(data,enc)
        return body+hmac.new(mac,body,hashlib.sha256).digest()

    def decrypt(self,blob):
        if not blob.startswith(MAGIC) or len(blob)<len(MAGIC)+40:raise ValueError('Неизвестный формат резервной копии')
        offset=len(MAGIC);size=int.from_bytes(blob[offset:offset+4],'big')
        if size>16384 or len(blob)<offset+4+size+48:raise ValueError('Повреждён заголовок резервной копии')
        try:
            header=json.loads(blob[offset+4:offset+4+size]);salt=base64.b64decode(header['salt'],validate=True)
            if len(salt)!=32:raise ValueError()
        except Exception:raise ValueError('Повреждён заголовок резервной копии')
        mac=hmac.new(self.key[32:],b'authentication'+salt,hashlib.sha256).digest()
        if not hmac.compare_digest(hmac.new(mac,blob[:-32],hashlib.sha256).digest(),blob[-32:]):raise ValueError('Подпись копии не совпала: неверный ключ или повреждение файла')
        enc=hmac.new(self.key[:32],b'encryption'+salt,hashlib.sha256).digest()
        return self.crypt(blob[offset+4+size:-32],enc,True),header

class MutationBusy(set):
    """Existing host reservations plus a durable controller maintenance gate."""
    def __init__(self, freeze):
        super().__init__()
        self.freeze=pathlib.Path(freeze)

    def __contains__(self, sid):
        return self.freeze.exists() or super().__contains__(sid)

    def __bool__(self):
        return self.freeze.exists() or super().__len__()>0

class Control:
    def __init__(self,root,servers,keydir,lock=None):
        self.root=pathlib.Path(root)/'control-data';self.root.mkdir(mode=0o700,exist_ok=True)
        self.backup_dir=self.root/'backups';self.backup_dir.mkdir(mode=0o700,exist_ok=True)
        self.vault=Vault(self.root/'vault');self.servers=servers;self.keydir=pathlib.Path(keydir)
        self.remote=(pathlib.Path(root)/'control_remote.py').read_text()
        if 'from panel_tls import pinned_https_connection' in self.remote:
            self.remote=self.remote.replace('from panel_tls import pinned_https_connection',(pathlib.Path(root)/'panel_tls.py').read_text())
        if 'from software_remote import SoftwareAdapter' in self.remote:
            self.remote=self.remote.replace('from software_remote import SoftwareAdapter',(pathlib.Path(root)/'software_remote.py').read_text())
        if 'from mtproxyl_update_remote import ManagerCodeUpdate' in self.remote:
            self.remote=self.remote.replace('from mtproxyl_update_remote import ManagerCodeUpdate',(pathlib.Path(root)/'mtproxyl_update_remote.py').read_text())
        if 'from reboot_remote import RemoteReboot' in self.remote:
            self.remote=self.remote.replace('from reboot_remote import RemoteReboot',(pathlib.Path(root)/'reboot_remote.py').read_text())
        if 'from service_restart_remote import RemoteServiceRestart' in self.remote:
            self.remote=self.remote.replace('from service_restart_remote import RemoteServiceRestart',(pathlib.Path(root)/'service_restart_remote.py').read_text())
        self.lock=lock if lock is not None else threading.RLock();self.busy=MutationBusy(self.root/'deployment-freeze');self.software_cache={};self.on_software_change=None
        self.plans={};self.jobs={};self.clients_cache={};self.releases={}
        self.projects=ProjectCatalog(self.root)
        self.reboots=Reboots(self)
        self.service_restarts=ServiceRestarts(self)
        self.path=self.root/'jobs.json'
        if self.path.exists():
            self.jobs=json.loads(self.path.read_text())
            for job in self.jobs.values():
                if job['state'] not in TERMINAL:
                    job['state']='needs_review';job['error']='Локальная панель перезапускалась. Проверьте удалённую задачу; автоматического повтора нет.'
                if job.get('remoteSubmitted') and job['state']=='needs_review':self.busy.add(job['server'])
        for job in list(self.jobs.values()):
            if job.get('remoteSubmitted') and job['state']=='needs_review':
                threading.Thread(target=self.resume,args=(job['id'],),daemon=True).start()

    def server(self,sid):
        s=next((x for x in self.servers() if x['id']==sid),None)
        if not s:raise ValueError('Сервер не найден')
        return s

    def ssh(self,s,req,timeout=100):
        wrapper="import json,sys;e=json.load(sys.stdin);exec(compile(e['source'],'<server-deck-adapter>','exec'),{'__name__':'__main__','_DECK_REQUEST':e['request'],'_DECK_SOURCE':e['source']})"
        argv=['ssh','-i',str(self.keydir/s['key']),'-p',str(s['port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',s['user']+'@'+s['host'],'python3 -c '+shlex.quote(wrapper)]
        p=subprocess.run(argv,input=json.dumps({'source':self.remote,'request':req}),text=True,capture_output=True,timeout=timeout)
        if p.returncode:raise RuntimeError('SSH-проверка не завершена (код '+str(p.returncode)+'). Работающие службы не перезапускались из-за этой ошибки.')
        try:result=json.loads(p.stdout)
        except ValueError:raise RuntimeError('Не удалось прочитать ответ адаптера')
        if not result.get('ok'):raise ValueError(result.get('error','Ошибка адаптера'))
        return result['data']

    def catalog(self,force=False):
        def one(s):
            with self.lock:old=self.clients_cache.get(s['id'])
            if old and not force and time.time()-old['checkedAt']<30:return old
            try:row=dict(self.ssh(s,{'op':'catalog'}),server=s['id'],name=s['name'],host=s['host'],ok=True)
            except Exception as e:row=dict(server=s['id'],name=s['name'],host=s['host'],ok=False,error=str(e),clients=[],panels=[],inbounds=[],checkedAt=time.time())
            with self.lock:self.clients_cache[s['id']]=row
            return row
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:rows=list(pool.map(one,self.servers()))
        return {'servers':rows,'checkedAt':time.time()}

    def backups(self):
        rows=[]
        for p in self.backup_dir.glob('*.json'):
            try:rows.append(json.loads(p.read_text()))
            except (OSError,ValueError):pass
        return sorted(rows,key=lambda x:x['createdAt'],reverse=True)

    def create_backup(self,s,panel,reason='manual'):
        value=self.ssh(s,{'op':'snapshot','panel':panel},150)
        data=base64.b64decode(value['data'],validate=True)
        if hashlib.sha256(data).hexdigest()!=value['sha256']:raise ValueError('Контрольная сумма SSH-копии не совпала')
        bid=secrets.token_hex(16);meta=dict(id=bid,server=s['id'],serverName=s['name'],host=s['host'],panel=panel,createdAt=time.time(),reason=reason,sourceSha256=value['sha256'],revision=value['metadata']['revision'],coverage=value['metadata']['coverage'],verified=False)
        encrypted=self.vault.encrypt(data,meta)
        plain,_=self.vault.decrypt(encrypted)
        if plain!=data:raise ValueError('Проверка шифрования копии не пройдена')
        # Verify archive structure; this is not a live recovery test.
        with tarfile.open(fileobj=io.BytesIO(plain),mode='r:gz') as tar:
            names=tar.getnames()
            required={'lucx':'x-ui.db','mtproxyl':'mtproxyl.tar.gz','host':'host-state.json'}[panel]
            if 'manifest.json' not in names or required not in names:raise ValueError('Не хватает файлов в архиве')
        meta.update(verified=True,size=len(encrypted),archiveSha256=hashlib.sha256(encrypted).hexdigest(),verification='Расшифрование, контрольная сумма и состав архива. Восстановление на сервер не запускалось.')
        path=self.backup_dir/(bid+'.sdbackup');fd=os.open(str(path),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as f:f.write(encrypted)
        atomic(self.backup_dir/(bid+'.json'),meta)
        return meta

    def backup_file(self,bid):
        if not re.fullmatch(r'[0-9a-f]{32}',bid):raise ValueError('Неверный ID копии')
        path=self.backup_dir/(bid+'.sdbackup')
        if not path.is_file():raise ValueError('Копия не найдена')
        return path

    def verify_backup(self,bid):
        plain,header=self.vault.decrypt(self.backup_file(bid).read_bytes())
        if hashlib.sha256(plain).hexdigest()!=header['sourceSha256']:raise ValueError('Контрольная сумма содержимого не совпала')
        with tarfile.open(fileobj=io.BytesIO(plain),mode='r:gz') as tar:
            manifest=json.load(tar.extractfile('manifest.json'))
        return {'verified':True,'manifest':manifest,'message':'Подпись, расшифрование и контрольная сумма подтверждены. Это не проверка восстановления на сервер.'}

    def release_catalog(self,force=False):
        with self.lock:
            if self.releases and not force and time.time()-self.releases.get('checkedAt',0)<1800:return self.releases
        def fetch(component):
            repo=REPOS[component]
            try:
                request=urllib.request.Request('https://api.github.com/repos/'+repo+'/releases?per_page=30',headers={'Accept':'application/vnd.github+json','User-Agent':'Server-Deck-Local'})
                with urllib.request.urlopen(request,timeout=15) as r:releases=json.load(r)
                rows=[]
                for x in releases:
                    tag=x['tag_name']
                    if x.get('draft') or x.get('prerelease'):continue
                    if component=='lucx' and not re.fullmatch(r'v[0-9.]+-lucx\.[0-9]+',tag):continue
                    if component=='mtproxyl-panel' and not tag.startswith('mtproxyl-panel-v'):continue
                    if component in ('mtproxyl','telemt') and not re.fullmatch(r'v?\d+\.\d+\.\d+',tag):continue
                    rows.append(dict(version=tag,url=x['html_url'],published=x.get('published_at'),notes=(x.get('body') or '')[:10000]))
                return component,{'ok':True,'releases':rows[:8]}
            except Exception:return component,{'ok':False,'error':'Не удалось получить релизы GitHub. Установленная версия не считается актуальной без проверки.','releases':[]}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:result=dict(pool.map(fetch,REPOS))
        result['checkedAt']=time.time()
        with self.lock:self.releases=result
        return result

    def updates(self,force=False):
        def one(s):
            try:return dict(server=s['id'],name=s['name'],host=s['host'],ok=True,versions=self.ssh(s,{'op':'versions'}))
            except Exception as e:return dict(server=s['id'],name=s['name'],host=s['host'],ok=False,error=str(e))
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:rows=list(pool.map(one,self.servers()))
        upstream=self.release_catalog(force);checked_at=time.time()
        rows=annotate_servers(rows,upstream,checked_at)
        return {'servers':rows,'upstream':upstream,'checkedAt':checked_at,'summary':summarize(rows),'projects':self.projects.updates(force,background=True)}

    def plan(self,data):
        s=self.server(data.get('server'));kind=data.get('kind')
        if kind=='reboot':return self.reboots.plan(s)
        if kind=='service-restart':return self.service_restarts.plan(s,data.get('unit'))
        if kind not in ('client','update','restore','install'):raise ValueError('Неверный тип операции')
        if kind=='install' or (kind=='update' and data.get('component') in ('lucx','mtproxyl-panel','awg','fail2ban')):
            component=data.get('component')
            if component not in ('lucx','mtproxyl','mtproxyl-panel','awg','fail2ban'):raise ValueError('Нет рецепта установки для этого компонента')
            inv=self.ssh(s,{'op':'software-inventory'})
            version=data.get('version','')
            if component!='fail2ban':
                release_component='lucx' if component=='awg' else component
                entries=self.release_catalog().get(release_component,{}).get('releases',[])
                if version not in [r['version'] for r in entries]:raise ValueError('Выберите опубликованный стабильный релиз из каталога')
            # User-supplied URLs, hashes, commands and backup policies are never trusted.
            data=dict(server=s['id'],kind=kind,component=component,version=version,port=data.get('port'),sni=data.get('sni',''),serverHost=s['host'],sources=prepare_sources(component,version,inv['arch']))
        if kind=='restore':
            plain,header=self.vault.decrypt(self.backup_file(data.get('backup','')).read_bytes())
            if header['server']!=s['id'] or header['host']!=s['host']:raise ValueError('Восстановление разрешено только на исходный сервер')
            with tarfile.open(fileobj=io.BytesIO(plain),mode='r:gz') as tar:manifest=json.load(tar.extractfile('manifest.json'))
            data=dict(data,panel=header['panel'],savedVersion=manifest['versions'].get(header['panel']))
        if kind=='update' and data.get('component') not in ('os','os-index','telemt-rollback','awg','fail2ban'):
            component=data.get('component');version=data.get('version')
            entries=self.release_catalog().get(component,{}).get('releases',[])
            if not version or version not in [x['version'] for x in entries]:raise ValueError('Выберите проверенный опубликованный релиз')
            if component=='mtproxyl':
                if not entries or version!=entries[0]['version']:raise ValueError('Обновите список релизов и выберите последний стабильный выпуск MTProxyL')
        remote=self.ssh(s,dict(data,op='plan'))
        if kind=='restore':remote['request']['backup']=data['backup']
        pid=secrets.token_hex(16);plan=dict(id=pid,server=s['id'],host=s['host'],createdAt=time.time(),expiresAt=time.time()+300,used=False,**remote)
        with self.lock:self.plans[pid]=plan
        return {k:v for k,v in plan.items() if k not in ('request','revision','used')}

    def software(self,force=False):
        def one(s):
            with self.lock:old=self.software_cache.get(s['id'])
            if old and not force and time.time()-old['checkedAt']<60:return old
            try:row=dict(server=s['id'],name=s['name'],host=s['host'],ok=True,inventory=self.ssh(s,{'op':'software-inventory'}),checkedAt=time.time())
            except Exception as e:row=dict(server=s['id'],name=s['name'],host=s['host'],ok=False,error=str(e),checkedAt=time.time())
            with self.lock:self.software_cache[s['id']]=row
            return row
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:rows=list(pool.map(one,self.servers()))
        projects=self.projects.request_refresh(force)
        return dict(components=COMPONENTS+projects,servers=rows,upstream=self.release_catalog(force),checkedAt=time.time())

    def add_component(self,data):
        if set(data)-{'url'}:raise ValueError('Добавление проекта принимает только ссылку url')
        return self.projects.add(data.get('url'))

    def remove_component(self,data):
        if set(data)-{'id'}:raise ValueError('Неверные параметры удаления проекта')
        return self.projects.remove(data.get('id'))

    def bind_component(self,data):
        if set(data)-{'id','server','version'}:raise ValueError('Неверные параметры привязки проекта')
        s=self.server(data.get('server'))
        return self.projects.bind(data.get('id'),s['id'],data.get('version',''))

    def save_jobs(self):atomic(self.path,self.jobs)

    def execute(self,pid,confirmation):
        with self.lock:
            p=self.plans.get(pid)
            if not p or p['used'] or p['expiresAt']<time.time():raise ValueError('План уже использован или истёк. Выполните новый предпросмотр.')
            if p['request']['kind']=='reboot':return self.reboots.execute(p,confirmation)
            if p['request']['kind']=='service-restart':return self.service_restarts.execute(p,confirmation)
            if confirmation!=p['host']:raise ValueError('Для подтверждения введите IP/имя сервера')
            if p['server'] in self.busy:raise ValueError('На этом сервере уже выполняется задача')
            p['used']=True;self.busy.add(p['server'])
            jid=secrets.token_hex(16);job=dict(id=jid,server=p['server'],host=p['host'],title=p['summary']['title'],kind=p['request']['kind'],state='backing_up',createdAt=time.time(),expiresAt=p['expiresAt'],backups=[])
            job['component']=p['request'].get('component')
            self.jobs[jid]=job;self.save_jobs()
        threading.Thread(target=self.worker,args=(jid,p),daemon=True).start()
        return job.copy()

    def backup_job(self,sid,panel):
        if panel not in ('lucx','mtproxyl'):raise ValueError('Неизвестная панель')
        s=self.server(sid)
        with self.lock:
            if sid in self.busy:raise ValueError('На сервере уже выполняется задача')
            self.busy.add(sid);jid=secrets.token_hex(16)
            job=dict(id=jid,server=sid,host=s['host'],title='Резервная копия · '+panel,kind='backup',state='running',createdAt=time.time(),backups=[])
            self.jobs[jid]=job;self.save_jobs()
        def work():
            try:
                backup=self.create_backup(s,panel)
                with self.lock:job.update(state='succeeded',backups=[backup['id']],finishedAt=time.time())
            except Exception as e:
                with self.lock:job.update(state='failed',error=str(e),finishedAt=time.time())
            finally:
                with self.lock:self.busy.discard(sid);self.save_jobs()
        threading.Thread(target=work,daemon=True).start();return job.copy()

    def worker(self,jid,p):
        job=self.jobs[jid];s=self.server(p['server'])
        try:
            if p['request'].get('component')=='os-index':panels=[]
            elif p['request']['kind'] in ('client','restore'):panels=[p['request']['panel']]
            else:
                current=self.ssh(s,{'op':'versions'})
                panels=['host']+[name for name in ('lucx','mtproxyl') if current.get(name)]
            for panel in panels:
                backup=self.create_backup(s,panel,'before-'+p['request']['kind'])
                with self.lock:job['backups'].append(backup['id']);self.save_jobs()
            # No request is retried after an ambiguous SSH result.
            with self.lock:job.update(state='submitting',remoteSubmitted=True);self.save_jobs()
            request=dict(p['request'],op='execute',job=jid,revision=p['revision'],expiresAt=p['expiresAt'])
            if request['kind']=='restore':
                plain,_=self.vault.decrypt(self.backup_file(request.pop('backup')).read_bytes());request['restoreData']=base64.b64encode(plain).decode()
            self.ssh(s,request,150)
            self.poll(job,s)
            if job['state']=='succeeded' and job['kind'] in ('install','update') and job.get('component')!='os-index' and self.on_software_change:
                try:self.on_software_change(s['id'])
                except Exception:
                    with self.lock:job['inventoryNotice']='Обновите список служб: автообнаружение после задачи не завершилось.';self.save_jobs()
        except Exception as e:
            with self.lock:job.update(state='needs_review' if job.get('remoteSubmitted') else 'failed',error=str(e),finishedAt=time.time());self.save_jobs()
        finally:
            with self.lock:
                if not (job.get('remoteSubmitted') and job['state']=='needs_review'):self.busy.discard(s['id'])
                self.clients_cache.pop(s['id'],None)
                self.software_cache.pop(s['id'],None)

    def poll(self,job,s):
        for _ in range(720):
            result=self.ssh(s,{'op':'job','job':job['id']})
            with self.lock:job.update(result);self.save_jobs()
            if result['state'] in TERMINAL:return
            time.sleep(5)
        raise RuntimeError('Задача не завершилась в течение часа. Повторный запуск заблокирован использованным планом.')

    def resume(self,jid):
        job=self.jobs[jid]
        if job.get('kind')=='reboot':return self.reboots.monitor(jid)
        if job.get('kind')=='service-restart':return self.service_restarts.monitor(jid)
        try:
            s=self.server(job['server']);result=self.ssh(s,{'op':'job','job':jid})
            if result['state']=='unknown':return
            with self.lock:self.busy.add(s['id']);job.update(result);self.save_jobs()
            if result['state'] not in TERMINAL:self.poll(job,s)
        except Exception:pass
        finally:
            with self.lock:
                if job['state'] in ('succeeded','failed'):self.busy.discard(job['server'])

    def snapshot(self):
        with self.lock:jobs=sorted(({k:v for k,v in j.items() if k not in ('before','binding')} for j in self.jobs.values()),key=lambda x:x['createdAt'],reverse=True)
        freeze=getattr(self.busy,'freeze',None);maintenance=bool(freeze is not None and freeze.exists())
        return {'jobs':jobs[:100],'backups':self.backups(),'busyServers':([s['id'] for s in self.servers()] if maintenance else list(self.busy)),'maintenance':maintenance,'recoveryKeySaved':False}

    def acknowledge(self,jid,confirmation):
        with self.lock:
            job=self.jobs.get(jid)
            if not job or job['state']!='needs_review':raise ValueError('Эта задача не ожидает ручной проверки')
            s=self.server(job['server'])
            if confirmation!=s['host']:raise ValueError('Введите IP сервера после проверки его состояния')
        if job.get('kind')=='reboot':
            self.reboots.acknowledge(job);remote={}
        elif job.get('kind')=='service-restart':
            self.service_restarts.acknowledge(job);remote={}
        else:remote=self.ssh(s,{'op':'job','job':jid})
        if remote.get('workerActive') or remote.get('state') in ('queued','running','submitted'):raise ValueError('Удалённая задача ещё работает. Снимать блокировку нельзя.')
        if remote.get('state')=='unknown' and time.time()<job.get('expiresAt',time.time()+300)+30:raise ValueError('Статус удалённой задачи неизвестен. Дождитесь истечения срока плана перед ручным снятием блокировки.')
        with self.lock:
            job.update(state='reviewed',reviewedAt=time.time(),message='Оператор подтвердил проверку состояния сервера. Задача повторно не запускалась.');self.busy.discard(s['id']);self.save_jobs()
        return {'ok':True}
