"""On-demand public Cheburcheck API integration. No SSH or remote installation."""
import copy, ipaddress, json, os, pathlib, re, socket, threading, time
import urllib.error, urllib.parse, urllib.request

BASE='https://cheburcheck.ru'
VERDICTS={'cdn_block','uncertain','dns_spoofing','sni_block','tspu_block','whitelist','ok'}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('Cheburcheck изменил адрес API; требуется проверка интеграции')

def request(path,accept):
    req=urllib.request.Request(BASE+path,headers={'Accept':accept,'User-Agent':'ServerDeck/1.3 (Cheburcheck integration)'})
    return urllib.request.build_opener(NoRedirect).open(req,timeout=30)

def target_address(host):
    try:
        address=ipaddress.ip_address(host)
        if not address.is_global:raise ValueError('Cheburcheck принимает только публичный адрес сервера')
        return str(address)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}',str(host)):
            raise ValueError('Укажите публичный IP или домен зарегистрированного сервера')
        if host.lower().endswith(('.local','.localhost','.internal','.test','.invalid','.example')):raise ValueError('Локальные имена не отправляются в Cheburcheck')
        return host.lower()

def events(response,deadline):
    """Bounded SSE parser. EOF without done is never considered success."""
    event='message';data=[];total=0;event_size=0
    while time.monotonic()<deadline:
        line=response.readline(131073)
        if not line:break
        total+=len(line);event_size+=len(line)
        if len(line)>131072 or total>4*1024*1024 or event_size>262144:raise ValueError('Ответ зондов превышает лимит')
        line=line.decode('utf-8').rstrip('\r\n')
        if not line:
            if data:yield event,json.loads('\n'.join(data))
            event='message';data=[];event_size=0
        elif line.startswith('event:'):event=line[6:].strip()
        elif line.startswith('data:'):data.append(line[5:].lstrip(' '))

def static_result(data,target):
    if not isinstance(data,dict) or data.get('target')!=target or type(data.get('blocked')) is not bool:
        raise ValueError('Неожиданный формат ответа Cheburcheck')
    return {k:data[k] for k in ('target','target_type','blocked','rkn_domain','ips','blocked_subnets','cdn_providers','geo','asn_info','whitelist','subnet_size','complaints') if k in data}

def probe_result(data):
    if not isinstance(data,dict) or not isinstance(data.get('probe_id'),str) or not isinstance(data.get('verdicts'),list):raise ValueError('Неожиданный формат результата зонда')
    row={k:data.get(k) for k in ('probe_id','region','provider','asn','cdn_unblocked','host_results','target_hop','dpi_hop','dns')}
    row['verdicts']=[v for v in data['verdicts'] if v in VERDICTS] or ['uncertain']
    row['receivedAt']=time.time()
    return row

class Cheburcheck:
    def __init__(self,path):
        self.path=pathlib.Path(path);self.lock=threading.RLock();self.busy=False;self.last_started=0;self.reports={}
        if self.path.exists():
            try:self.reports=json.loads(self.path.read_text())
            except (OSError,ValueError):pass
        for row in self.reports.values():
            if row.get('status')=='running':row.update(status='partial' if row.get('check') else 'error',error='Проверка прервана перезапуском панели. Запустите её заново.',finishedAt=time.time())

    def save(self):
        tmp=self.path.with_suffix('.tmp')
        fd=os.open(str(tmp),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w') as f:json.dump(self.reports,f,ensure_ascii=False)
        os.replace(tmp,self.path)

    def snapshot(self):
        with self.lock:return copy.deepcopy(dict(servers=self.reports,busy=self.busy,nextStartAt=self.last_started+20))

    def start(self,server):
        target=target_address(server['host']);sid=server['id'];now=time.time()
        with self.lock:
            if self.busy:raise ValueError('Дождитесь завершения текущей проверки Cheburcheck')
            if now-self.last_started<20:raise ValueError('Между проверками Cheburcheck нужно 20 секунд')
            previous=self.reports.get(sid,{})
            if previous.get('host')==target and now-previous.get('startedAt',0)<60:raise ValueError('Этот сервер можно перепроверить через минуту')
            row=dict(server=sid,host=target,status='running',startedAt=now,check=None,probes=[],onlineProbes=None,reportedResponses=None,error=None)
            self.busy=True;self.last_started=now;self.reports[sid]=row;self.save()
        threading.Thread(target=self.worker,args=(sid,target),daemon=True).start()

    def update(self,sid,**values):
        with self.lock:self.reports[sid].update(values);self.save()

    def worker(self,sid,target):
        try:
            with request('/api/v1/check?'+urllib.parse.urlencode({'target':target}),'application/json') as response:
                if response.headers.get_content_type()!='application/json':raise ValueError('Cheburcheck вернул не JSON')
                body=response.read(1024*1024+1)
                if len(body)>1024*1024:raise ValueError('Ответ Cheburcheck превышает лимит')
                data=json.loads(body)
            check=static_result(data,target);self.update(sid,check=check,checkReceivedAt=time.time())
            context=data.get('id')
            if not isinstance(context,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,4096}',context):raise ValueError('Сервис не выдал контекст для сетевых зондов; доступна только проверка баз')
            # Signed check context stays in memory; no credentials or privileged probe token.
            done=False;probes={};deadline=time.monotonic()+120
            with request('/api/v1/probe/'+urllib.parse.quote(context,safe=''),'text/event-stream') as response:
                if response.headers.get_content_type()!='text/event-stream':raise ValueError('Сервис не вернул поток результатов зондов')
                for event,data in events(response,deadline):
                    if not isinstance(data,dict):raise ValueError('Неожиданный ответ зондов')
                    if event=='started':
                        if data.get('target')!=target:raise ValueError('Адрес проверки зондов не совпал')
                        self.update(sid,onlineProbes=data.get('online_probes'))
                    elif event=='result':
                        row=probe_result(data);probes[row['probe_id']]=row
                        if len(probes)>400:raise ValueError('Слишком много результатов зондов')
                        self.update(sid,probes=list(probes.values()))
                    elif event=='done':
                        self.update(sid,reportedResponses=data.get('response_count'),onlineProbes=data.get('online_probes'));done=True;break
                    elif event=='error':raise ValueError('Cheburcheck сообщил об ошибке измерения')
            if not done:raise ValueError('Поток зондов завершился без итогового события; результат неполный')
            self.update(sid,status='done' if probes else 'partial',error=None if probes else 'Зонды не прислали результатов. Доступность из РФ не установлена.')
        except Exception as exc:
            if isinstance(exc,urllib.error.HTTPError):
                message={429:'Лимит Cheburcheck исчерпан. Повторите позже.',400:'Cheburcheck не смог запустить сетевую проверку этого адреса.',403:'Cheburcheck отклонил запрос.',401:'Cheburcheck отклонил контекст проверки.'}.get(exc.code,'Cheburcheck вернул HTTP '+str(exc.code))
            elif isinstance(exc,(TimeoutError,socket.timeout,urllib.error.URLError)):message='Cheburcheck не ответил вовремя или недоступен по текущему маршруту.'
            elif isinstance(exc,ValueError):message=str(exc)[:240]
            else:message='Не удалось завершить проверку Cheburcheck.'
            with self.lock:partial=bool(self.reports[sid].get('check'))
            self.update(sid,status='partial' if partial else 'error',error=message)
        finally:
            with self.lock:self.reports[sid]['finishedAt']=time.time();self.busy=False;self.save()
