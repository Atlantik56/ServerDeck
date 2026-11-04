"""Reboot plans and persistent observation, sharing the control-plane lock."""
import copy, secrets, threading, time
from reboot_remote import reboot_digest

DONE={'succeeded','failed','needs_review','reviewed'}

def missing_services(before,after):
    missing=[name for name,v in before['services'].items() if v.get('ActiveState')=='active' and after['services'].get(name,{}).get('ActiveState')!='active']
    missing+=['Docker: '+name for name in before['containers'] if name not in after['containers']]
    missing+=['AWG: '+name for name in before['awg'] if name not in after['awg']]
    return missing

class Reboots:
    def __init__(self,control):self.c=control;self.watching=set()
    def plan(self,s):
        c=self.c
        with c.lock:
            if s['id'] in c.busy:raise ValueError('На сервере уже выполняется задача')
        info=c.ssh(s,dict(op='reboot-info',services=s['services']))
        if info['aptBusy']:raise ValueError('На сервере работает APT/dpkg. Дождитесь окончания обновления')
        if info['system'] not in ('running','degraded'):raise ValueError('ОС запускается или выключается. Повторите проверку позже')
        warnings=[]
        for name,v in info['services'].items():
            if v.get('ActiveState')=='active' and v.get('UnitFileState') not in ('enabled','static','indirect','generated','alias'):warnings.append(name+': автозапуск не подтверждён ('+v.get('UnitFileState','unknown')+')')
        for name,policy in info['containers'].items():
            if policy not in ('always','unless-stopped'):warnings.append('Docker '+name+': политика '+(policy or 'no')+' не гарантирует запуск после reboot')
        pid=secrets.token_hex(16);now=time.time()
        plan=dict(id=pid,server=s['id'],host=s['host'],createdAt=now,expiresAt=now+300,used=False,revision=reboot_digest(info),before=info,binding=[s['host'],s['port'],s['user'],s['key']],request=dict(kind='reboot',services=s['services']),summary=dict(title='Перезагрузить VPS · '+s['name'],kind='reboot',impact='Все VPN, прокси, панели и SSH на этом сервере временно отключатся. Новое ядро ОС, если оно установлено, вступит в работу.',warnings=warnings,steps=['Штатная перезагрузка systemd без принудительного выключения','Контроль нового boot ID, возврата SSH и ранее активных служб/контейнеров/AWG до 10 минут','Настройки автозапуска и конфигурации не изменяются; успешный запуск служб не доказывает прохождение VPN-трафика'],backupRequired=False))
        with c.lock:c.plans[pid]=plan
        return {k:v for k,v in plan.items() if k in ('id','server','host','createdAt','expiresAt','summary')}
    def execute(self,p,confirmation):
        c=self.c
        with c.lock:
            if p['used'] or p['expiresAt']<time.time():raise ValueError('План истёк или использован; создайте новый')
            if confirmation!=p['host']:raise ValueError('Введите точный IP/домен сервера')
            s=c.server(p['server'])
            if [s['host'],s['port'],s['user'],s['key']]!=p['binding']:raise ValueError('Параметры сервера изменились')
            if s['id'] in c.busy:raise ValueError('На сервере уже выполняется задача')
            p['used']=True;c.busy.add(s['id']);jid=secrets.token_hex(16);now=time.time()
            job=dict(id=jid,kind='reboot',server=s['id'],host=s['host'],title=p['summary']['title'],state='submitting',createdAt=now,expiresAt=p['expiresAt'],deadline=now+600,backups=[],before=p['before'],services=p['request']['services'],binding=p['binding'])
            c.jobs[jid]=job;c.save_jobs()
        threading.Thread(target=self.submit,args=(jid,p),daemon=True).start()
        return copy.deepcopy({k:v for k,v in job.items() if k not in ('before','binding')})
    def update(self,job,**values):
        with self.c.lock:job.update(values);self.c.save_jobs()
    def submit(self,jid,p):
        c=self.c;job=c.jobs[jid]
        try:
            s=c.server(job['server']);fresh=c.ssh(s,dict(op='reboot-info',services=job['services']))
            if time.time()>p['expiresAt'] or reboot_digest(fresh)!=p['revision']:raise ValueError('План истёк или состояние изменилось. Перезагрузка не отправлена')
            self.update(job,remoteSubmitted=True,message='Команда отправляется один раз. Ожидаем новую загрузку ОС.')
            try:
                reply=c.ssh(s,dict(op='reboot-schedule',job=jid,services=job['services'],revision=p['revision'],expiresAt=p['expiresAt']),30)
                self.update(job,commandAccepted=bool(reply.get('accepted')))
            except Exception:self.update(job,commandAccepted=None,message='Подтверждение команды не получено. Проверяем новую загрузку без повторной отправки.')
            self.update(job,state='waiting_reboot');self.monitor(jid)
        except Exception as e:
            self.update(job,state='needs_review' if job.get('remoteSubmitted') else 'failed',error=str(e),finishedAt=time.time())
            if not job.get('remoteSubmitted'):
                with c.lock:c.busy.discard(job['server'])
    def monitor(self,jid):
        c=self.c;job=c.jobs[jid]
        with c.lock:
            if jid in self.watching:return
            if job['state'] in ('succeeded','failed','reviewed'):return
            self.watching.add(jid);c.busy.add(job['server'])
        try:
            while True:
                try:
                    s=c.server(job['server'])
                    if [s['host'],s['port'],s['user'],s['key']]!=job['binding']:raise ValueError('Параметры сервера изменились')
                    after=c.ssh(s,dict(op='reboot-status',services=job['services'],job=jid),60)
                    if after['bootId']!=job['before']['bootId']:
                        missing=missing_services(job['before'],after)
                        self.update(job,bootConfirmed=True,missing=missing,lastCheckAt=time.time(),afterBootId=after['bootId'])
                        if not missing:
                            self.update(job,state='succeeded',error=None,finishedAt=time.time(),message='Новая загрузка ОС подтверждена. SSH, ранее активные отслеживаемые службы, контейнеры и AWG-интерфейсы вернулись. VPN-трафик этим не проверялся.')
                            with c.lock:c.busy.discard(job['server']);c.clients_cache.pop(job['server'],None);c.software_cache.pop(job['server'],None)
                            return
                        self.update(job,state='waiting_services',message='Сервер загрузился. Ожидаем: '+', '.join(missing))
                    else:self.update(job,state='waiting_reboot',lastCheckAt=time.time(),message='SSH доступен, но новая загрузка ОС пока не подтверждена.')
                except Exception:self.update(job,lastCheckAt=time.time(),message='Ожидаем возврата SSH. Повторная команда reboot не отправляется.')
                if time.time()>=job['deadline']:
                    self.update(job,state='needs_review',finishedAt=time.time(),error='За 10 минут восстановление не подтверждено. Проверьте консоль провайдера и состояние служб; автоматического повтора нет.')
                    return
                time.sleep(10)
        finally:
            with c.lock:self.watching.discard(jid);c.save_jobs()
    def acknowledge(self,job):
        s=self.c.server(job['server']);after=self.c.ssh(s,dict(op='reboot-status',services=job['services'],job=job['id']))
        if after['scheduled']:raise ValueError('Команда перезагрузки ещё ожидает выполнения; блокировку снять нельзя')
        if time.time()<job['createdAt']+60:raise ValueError('Дождитесь завершения отправки команды и перепроверьте сервер')
