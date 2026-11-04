"""Fixed SSH adapter. API credentials and protocol keys stay on the VPS.

Read operations never install packages or restart services. Mutations run as
one-shot systemd jobs, with an independent lock and a fresh revision check.
"""
import base64, copy, datetime, fcntl, hashlib, http.client, io, ipaddress, json, os, pathlib, re, secrets, shlex, shutil, sqlite3, ssl, subprocess, sys, tarfile, tempfile, time
from urllib.parse import quote, urlsplit
from panel_tls import pinned_https_connection

STATE = pathlib.Path('/var/lib/server-deck')
MT = pathlib.Path('/opt/mtproxyl')
DB = pathlib.Path('/etc/x-ui/x-ui.db')
JOB_LOG = None
ALLOWED_MT_FILES = ('settings.conf','secrets.conf','expert.conf','tunings.conf','nft-rules.conf','upstreams.conf','geoblock.conf','ipblock.conf','shaping.conf','superexpert.toml','nginx-custom.conf','selfmask-manager.conf','selfmask-reanimator.conf','backup_meta.txt')

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def run(argv,timeout=30):
    p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,env=dict(os.environ,LC_ALL='C'))
    update_log(p.stdout+'\n'+p.stderr)
    if p.returncode: raise RuntimeError('Команда не выполнена: '+str(argv[0])+' (код '+str(p.returncode)+'). Подробности — в журнале сервера.')
    return p.stdout.strip()

def update_log(text):
    if JOB_LOG is None:return
    text=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',text)
    lines=[]
    for line in text.splitlines():
        if re.search(r'(?i)password|private.?key|preshared|header.?protection|api.?token|secret|username|://[^\s]*[?&](?:token|key|auth)=',line):line='[строка с учётными данными скрыта]'
        line=re.sub(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?!\w)','[ключ скрыт]',line)
        lines.append(line[:1200])
    with JOB_LOG.open('a') as f:f.write('\n'.join(lines)[-24000:]+'\n')
    if JOB_LOG.stat().st_size>180000:
        data=JOB_LOG.read_bytes()[-120000:];JOB_LOG.write_bytes(data)

def db_settings():
    with sqlite3.connect('file:'+str(DB)+'?mode=ro',uri=True) as c:
        return dict(c.execute('select key,value from settings'))

def lucx(path,body=None,raw=False,ctype='application/json'):
    env={}
    credentials=next((p for p in (pathlib.Path('/etc/x-ui/server-deck.env'),pathlib.Path('/etc/x-ui/install-result.env')) if p.is_file()),None)
    if credentials is None:raise ValueError('На сервере не настроены учётные данные 3x-ui / LucX')
    for line in credentials.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        k,sep,v=line.partition('=')
        if sep:
            values=shlex.split(v);env[k]=values[0] if values else ''
    token=env.get('XUI_API_TOKEN','')
    if not token:raise ValueError('На сервере отсутствует API-токен LucX')
    s=db_settings();port=int(s.get('webPort',2053));base=s.get('webBasePath','/')
    if not base.startswith('/') or '\r' in base or '\n' in base:raise ValueError('Неверный путь панели')
    cert=s.get('webCertFile')
    if cert:
        conn=pinned_https_connection('127.0.0.1',port,pathlib.Path(cert).read_text(),timeout=45)
    else:conn=http.client.HTTPConnection('127.0.0.1',port,timeout=45)
    headers={'Authorization':'Bearer '+token}
    public_host=s.get('webDomain') or urlsplit(env.get('XUI_ACCESS_URL','')).hostname
    if public_host and re.fullmatch(r'[A-Za-z0-9.:-]+',public_host):headers['Host']=public_host
    if body is not None:
        headers['Content-Type']=ctype
        if not isinstance(body,bytes):body=json.dumps(body,ensure_ascii=False).encode()
    conn.request('POST' if body is not None else 'GET',base.rstrip('/')+'/panel/api/'+path,body=body,headers=headers)
    response=conn.getresponse();data=response.read(32*1024*1024);conn.close()
    if response.status!=200:raise RuntimeError('LucX API: HTTP '+str(response.status))
    if raw:return data
    result=json.loads(data)
    if result.get('success') is not True:
        # Upstream errors may include credentials. Only retain an error class.
        raise RuntimeError('LucX отклонил запрос; результат мог примениться частично. Перечитайте клиентов перед новым действием.')
    return result.get('obj')

def mt_cli(*args):return run(['/opt/mtproxyl/mtproxyl.sh']+list(args),90)

def mt_users():
    value=json.loads(mt_cli('secret','api-view'))
    links={};live=None;rows=None
    if isinstance(value,list):rows=value
    if isinstance(value,dict):
        links=value.get('links') or {};live=value.get('live')
        data=value.get('data',value)
        if isinstance(data,list):rows=data
        if isinstance(data,dict):
            for key in ('users','secrets'):
                if isinstance(data.get(key),list):rows=data[key];break
    if rows is None:raise ValueError('Неизвестный формат списка MTProxyL')
    if isinstance(live,dict):live=live.get('data',live.get('users'))
    if isinstance(live,dict):live=live.get('users')
    live_by_name={x.get('username'):x for x in live if isinstance(x,dict)} if isinstance(live,list) else {}
    result=[]
    for raw in rows:
        user=dict(raw);name=user.get('username',user.get('label'))
        if not name:raise ValueError('MTProxyL вернул пользователя без имени')
        user['username']=name
        for old,new in [('max_conns','max_tcp_conns'),('max_ips','max_unique_ips'),('quota_bytes','data_quota_bytes'),('expires','expiration_rfc3339')]:
            if old in raw:user[new]=raw[old]
        if user.get('expiration_rfc3339')=='0':user['expiration_rfc3339']=None
        if 'total_bytes' in raw:user['traffic']={'total_bytes':raw['total_bytes'],'in_bytes':raw.get('total_in'),'out_bytes':raw.get('total_out')}
        if name in links:user['links']=links[name]
        for field in ('current_connections','active_unique_ips','in_runtime'):
            if field in live_by_name.get(name,{}):user[field]=live_by_name[name][field]
        result.append(user)
    return result

def lucx_state():
    return lucx('clients/list') or [],lucx('inbounds/list') or []

def client_record(name):
    value=lucx('clients/get/'+quote(name,safe=''))
    if not isinstance(value,dict) or not isinstance(value.get('client'),dict):raise ValueError('Неизвестный формат клиента LucX')
    return value

def mt_record(name):
    return next((x for x in mt_users() if x.get('username',x.get('label'))==name),None)

def revisions(panel):
    if panel=='lucx':
        clients,inbounds=lucx_state()
        # Ignore counters and online times; include stored identity/config.
        clean=[{k:v for k,v in x.items() if k not in ('traffic','up','down','lastOnline','lastSubFetch')} for x in clients]
        ins=[{k:x.get(k) for k in ('id','protocol','enable','port','settings','streamSettings','nodeId')} for x in inbounds]
        return digest([clean,ins])
    if panel=='mtproxyl':
        files={name:hashlib.sha256((MT/name).read_bytes()).hexdigest() for name in ALLOWED_MT_FILES if (MT/name).is_file()}
        return digest(files)
    raise ValueError('Неизвестная панель')

def catalog():
    result={'panels':[],'clients':[],'inbounds':[],'checkedAt':time.time()}
    if DB.exists():
        try:
            clients,inbounds=lucx_state();imap={int(x['id']):x for x in inbounds}
            result['panels'].append({'panel':'lucx','ok':True,'count':len(clients)})
            for x in inbounds:
                result['inbounds'].append({k:x.get(k) for k in ('id','remark','protocol','enable','port','nodeId')})
            for x in clients:
                traffic=x.get('traffic') or {};ids=x.get('inboundIds') or []
                result['clients'].append(dict(panel='lucx',name=x.get('email',''),enabled=x.get('enable',True),quota=x.get('totalGB',0),expires=x.get('expiryTime',0),limitIp=x.get('limitIp',0),comment=x.get('comment',''),used=int(traffic.get('up',0))+int(traffic.get('down',0)),lastOnline=traffic.get('lastOnline',0),inboundIds=ids,protocols=sorted({imap[i].get('protocol','?') for i in ids if i in imap})))
        except Exception as e:result['panels'].append({'panel':'lucx','ok':False,'error':safe_error(e)})
    if (MT/'mtproxyl.sh').exists():
        try:
            users=mt_users();result['panels'].append({'panel':'mtproxyl','ok':True,'count':len(users)})
            for x in users:
                result['clients'].append(dict(panel='mtproxyl',name=x.get('username',x.get('label','')),enabled=x.get('enabled',True),quota=x.get('data_quota_bytes') or 0,expires=parse_expiry(x.get('expiration_rfc3339')),limitIp=x.get('max_unique_ips') or 0,maxConnections=x.get('max_tcp_conns') or 0,rateUp=x.get('rate_limit_up_bps') or 0,rateDown=x.get('rate_limit_down_bps') or 0,used=(x.get('traffic') or {}).get('total_bytes',x.get('total_octets',0)),connections=x.get('current_connections'),protocols=['MTProto'],comment=x.get('notes','')))
        except Exception as e:result['panels'].append({'panel':'mtproxyl','ok':False,'error':safe_error(e)})
    return result

def parse_expiry(value):
    if not value or value=='0':return 0
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}',value):value+='T23:59:59+00:00'
    parsed=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:parsed=parsed.replace(tzinfo=datetime.timezone.utc)
    return int(parsed.timestamp()*1000)

def valid_name(value,panel):
    if not isinstance(value,str) or not value or len(value)>128 or any(ord(c)<32 for c in value) or '/' in value:raise ValueError('Неверное имя клиента')
    if panel=='mtproxyl' and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}',value):raise ValueError('MTProxyL: латиница, цифры, _ и -, до 32 символов')
    return value

def checked_fields(fields,panel):
    allowed={'enabled','quota','expires','limitIp','comment'} if panel=='lucx' else {'enabled','quota','expires','limitIp','maxConnections','rateUp','rateDown'}
    if not isinstance(fields,dict) or set(fields)-allowed:raise ValueError('Неподдерживаемое поле клиента')
    out={}
    for k,v in fields.items():
        if k=='enabled':
            if type(v) is not bool:raise ValueError('enabled должен быть boolean')
        elif k=='comment':
            if not isinstance(v,str) or len(v)>500:raise ValueError('Комментарий слишком длинный')
        elif type(v) is not int or v<0 or v>9007199254740991:raise ValueError('Неверное числовое значение: '+k)
        out[k]=v
    if out.get('expires',0) and out['expires']<int(time.time()*1000):raise ValueError('Срок должен быть в будущем')
    if panel=='mtproxyl' and out.get('expires',0)%1000:raise ValueError('MTProxyL поддерживает срок с точностью до секунды')
    return out

def client_plan(req):
    panel=req.get('panel');op=req.get('action');name=valid_name(req.get('name'),panel)
    if panel not in ('lucx','mtproxyl') or op not in ('create','edit','delete'):raise ValueError('Неподдерживаемое действие')
    fields=checked_fields(req.get('fields',{}),panel)
    revision=revisions(panel)
    if panel=='lucx':
        clients,inbounds=lucx_state();old=next((x for x in clients if x.get('email')==name),None)
        if op=='create':
            if old:raise ValueError('Клиент уже существует')
            ids=req.get('inboundIds',[])
            if not isinstance(ids,list) or len(ids)!=1 or type(ids[0]) is not int:raise ValueError('Выберите одно входящее подключение')
            inbound=next((x for x in inbounds if x['id']==ids[0]),None)
            if not inbound or inbound.get('nodeId'):raise ValueError('Выберите локальный inbound')
            if inbound.get('protocol') not in ('awg','amneziawg','wireguard','vless','vmess','trojan','shadowsocks','hysteria','mtproto'):raise ValueError('Этот протокол пока не поддерживается для создания')
            affected=ids
        else:
            if not old:raise ValueError('Клиент не найден')
            affected=old.get('inboundIds',[])
            if not affected:raise ValueError('Клиент не привязан к inbound')
        impact='Изменение применяется ко всем подключениям этого клиента. Общий перезапуск панели из Server Deck не выполняется; панель применяет свою штатную процедуру.'
    else:
        old=mt_record(name)
        if op=='create' and old:raise ValueError('Клиент уже существует')
        if op!='create' and not old:raise ValueError('Клиент не найден')
        if op=='create' and fields.get('enabled',True) is False:raise ValueError('Новый MTProxyL-клиент сначала создаётся включённым')
        if op=='delete' or fields.get('enabled') is False:
            users=mt_users()
            if sum(bool(x.get('enabled')) for x in users)<=1 and old and old.get('enabled'):raise ValueError('Нельзя отключить или удалить последнего включённого пользователя MTProxyL')
        affected=[];impact='MTProxyL применит настройки штатными командами. Отключение/удаление отзовёт доступ выбранного пользователя.'
    return dict(revision=revision,summary={'title':{'create':'Создать клиента','edit':'Изменить клиента','delete':'Удалить клиента'}[op]+' · '+name,'panel':panel,'name':name,'fields':fields,'inboundIds':affected,'impact':impact,'backupRequired':True},request=dict(kind='client',panel=panel,action=op,name=name,fields=fields,inboundIds=req.get('inboundIds',[])))

def lucx_payload(value):
    c=copy.deepcopy(value)
    # ClientRecord uses UUID + wg-prefixed fields; the write model is Client.
    if 'uuid' in c:c['id']=c.pop('uuid')
    for old,new in [('wgPrivateKey','privateKey'),('wgPublicKey','publicKey'),('wgAllowedIPs','allowedIPs'),('wgPreSharedKey','preSharedKey'),('wgKeepAlive','keepAlive'),('wgKeepAliveRange','keepAliveRange'),('wgForwardedPorts','forwardedPorts')]:
        if old in c:c[new]=c.pop(old)
    for key in ('traffic','inboundIds','createdAt','updatedAt'):c.pop(key,None)
    return c

def create_awg_keys(c,inbound):
    settings=inbound.get('settings') or '{}'
    if isinstance(settings,str):settings=json.loads(settings)
    address=settings.get('address')
    if isinstance(address,list):address=next((x for x in address if ':' not in x),None)
    if not address:raise ValueError('У inbound нет IPv4-подсети. Создание отменено.')
    interface=ipaddress.ip_interface(address);network=interface.network
    if network.version!=4 or network.num_addresses>65536:raise ValueError('Неподдерживаемая IPv4-подсеть')
    used={interface.ip}
    _,inbounds=lucx_state();ranges=[]
    for item in inbounds:
        value=item.get('settings') or '{}'
        if isinstance(value,str):value=json.loads(value)
        for peer in value.get('clients',[]):
            ips=peer.get('allowedIPs') or []
            if isinstance(ips,str):ips=ips.split(',')
            for ip in ips:
                try:
                    r=ipaddress.ip_network(ip.strip(),strict=False)
                    if r.prefixlen:ranges.append(r)
                except ValueError:pass
    free=next((ip for ip in network.hosts() if ip not in used and not any(ip.version==r.version and ip in r for r in ranges)),None)
    if not free:raise ValueError('Нет свободного адреса клиента')
    key=run(['awg','genkey']);public=subprocess.run(['awg','pubkey'],input=key+'\n',capture_output=True,text=True,check=True).stdout.strip()
    c.update(privateKey=key,publicKey=public,preSharedKey=run(['awg','genpsk']),allowedIPs=[str(free)+'/32'],keepAlive='25')

def apply_client(req):
    panel=req['panel'];name=req['name'];op=req['action'];fields=req['fields']
    if panel=='lucx':
        if op=='delete':lucx('clients/del/'+quote(name,safe='')+'?keepTraffic=1',{})
        else:
            if op=='create':c={'email':name,'enable':True};ids=req['inboundIds']
            else:c=lucx_payload(client_record(name)['client'])
            mapping={'enabled':'enable','quota':'totalGB','expires':'expiryTime','limitIp':'limitIp','comment':'comment'}
            c.update({mapping[k]:v for k,v in fields.items()})
            if op=='create':
                inbound=next(x for x in lucx('inbounds/list') if x['id']==ids[0])
                if inbound['protocol']=='awg':create_awg_keys(c,inbound)
                lucx('clients/add',{'client':c,'inboundIds':ids})
            else:lucx('clients/update/'+quote(name,safe=''),c)
        rows=lucx('clients/list') or [];row=next((x for x in rows if x.get('email')==name),None)
        if (op=='delete' and row) or (op!='delete' and row is None):raise RuntimeError('Состояние клиента после записи не подтверждено')
        if row and any(row.get({'enabled':'enable','quota':'totalGB','expires':'expiryTime','limitIp':'limitIp','comment':'comment'}[k])!=v for k,v in fields.items()):raise RuntimeError('Часть полей после записи не совпала. Автоповтора нет.')
    else:
        if op=='delete':mt_cli('secret','remove',name)
        elif op=='create':
            mt_cli('secret','add',name)
            try:apply_mt_fields(name,fields)
            except Exception:
                # Only remove a user whose creation in this exact call
                # succeeded. Never touch pre-existing users on CLI failure.
                mt_cli('secret','remove',name)
                raise RuntimeError('Не удалось применить лимиты нового пользователя; созданный в этой операции доступ удалён')
        else:apply_mt_fields(name,fields)
        row=mt_record(name)
        if (op=='delete' and row) or (op!='delete' and not row):raise RuntimeError('Состояние MTProxyL после записи не подтверждено')
        if row and 'enabled' in fields and row.get('enabled')!=fields['enabled']:raise RuntimeError('Состояние доступа не совпало после записи')
        if row:
            actual={'quota':row.get('data_quota_bytes') or 0,'expires':parse_expiry(row.get('expiration_rfc3339')),'limitIp':row.get('max_unique_ips') or 0,'maxConnections':row.get('max_tcp_conns') or 0,'rateUp':row.get('rate_limit_up_bps') or 0,'rateDown':row.get('rate_limit_down_bps') or 0}
            if any(actual[k]!=v for k,v in fields.items() if k!='enabled'):raise RuntimeError('Часть лимитов MTProxyL после записи не совпала. Автоповтора нет.')
    return {'verified':True,'message':'Изменение подтверждено повторным чтением. Общий перезапуск из Server Deck не выполнялся.'}

def apply_mt_fields(name,fields):
    old=mt_record(name)
    if any(k in fields for k in ('maxConnections','limitIp','quota','expires')):
        expiry=fields.get('expires',parse_expiry(old.get('expiration_rfc3339')))
        expiry=datetime.datetime.fromtimestamp(expiry/1000,datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z') if expiry else '0'
        mt_cli('secret','setlimits',name,str(fields.get('maxConnections',old.get('max_tcp_conns') or 0)),str(fields.get('limitIp',old.get('max_unique_ips') or 0)),str(fields.get('quota',old.get('data_quota_bytes') or 0)),expiry)
    if 'rateUp' in fields or 'rateDown' in fields:mt_cli('secret','setrate',name,str(fields.get('rateUp',old.get('rate_limit_up_bps') or 0)),str(fields.get('rateDown',old.get('rate_limit_down_bps') or 0)))
    if 'enabled' in fields and old.get('enabled')!=fields['enabled']:mt_cli('secret','enable' if fields['enabled'] else 'disable',name)

def snapshot(panel):
    if panel=='host':return SOFTWARE.snapshot()
    revision=revisions(panel)
    with tempfile.TemporaryDirectory(prefix='server-deck-backup-') as temp:
        temp=pathlib.Path(temp);items=[]
        if panel=='lucx':
            dst=sqlite3.connect(str(temp/'x-ui.db'))
            with sqlite3.connect('file:'+str(DB)+'?mode=ro',uri=True) as src:src.backup(dst,pages=512,sleep=.05)
            check=dst.execute('pragma integrity_check').fetchone()[0];dst.close()
            if check!='ok':raise RuntimeError('SQLite integrity_check не пройден')
            items.append((temp/'x-ui.db','x-ui.db'))
            settings=db_settings()
            for key in ('webCertFile','webKeyFile'):
                p=pathlib.Path(settings.get(key,'/nonexistent'))
                if p.is_file():items.append((p,'tls/'+key))
        elif panel=='mtproxyl':
            # Native backup is read-only with respect to runtime. It includes
            # the manager's migration metadata and persistent statistics.
            output=mt_cli('backup')
            matches=re.findall(r'/opt/mtproxyl/backups/[A-Za-z0-9_.-]+\.tar\.gz',output)
            if not matches:raise RuntimeError('MTProxyL не сообщил путь резервной копии')
            p=pathlib.Path(matches[-1]).resolve()
            if p.parent!=pathlib.Path('/opt/mtproxyl/backups') or not p.is_file():raise ValueError('Неверный путь резервной копии')
            items.append((p,'mtproxyl.tar.gz'))
        else:raise ValueError('Неизвестная панель')
        if revisions(panel)!=revision:raise RuntimeError('Настройки изменились во время копирования; копия отменена')
        metadata={'format':1,'panel':panel,'createdAt':time.time(),'hostname':os.uname().nodename,'revision':revision,'versions':versions(),'coverage':'LucX: SQLite + TLS панели; MTProxyL: штатный архив менеджера. ОС, приложения и образы Docker не входят.'}
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as tar:
            raw=json.dumps(metadata,ensure_ascii=False).encode();info=tarfile.TarInfo('manifest.json');info.size=len(raw);info.mode=0o600;tar.addfile(info,io.BytesIO(raw))
            for p,name in items:
                raw=p.read_bytes();info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600;tar.addfile(info,io.BytesIO(raw))
        value=data.getvalue()
        if len(value)>24*1024*1024:raise ValueError('Архив превышает лимит 24 МБ')
        return dict(metadata=metadata,data=base64.b64encode(value).decode(),sha256=hashlib.sha256(value).hexdigest())

def versions():
    out={}
    if pathlib.Path('/usr/local/x-ui/x-ui').exists():out['lucx']=run(['/usr/local/x-ui/x-ui','-v'],10).strip()
    if (MT/'mtproxyl.sh').exists():
        match=re.search(r'^VERSION=["\']?([^"\'\n]+)',(MT/'mtproxyl.sh').read_text(),re.M)
        out['mtproxyl']=match.group(1) if match else 'неизвестно'
        if shutil.which('docker'):
            images=run(['docker','ps','--format','{{.Image}}'],10)
            out['telemt']=next((x for x in images.splitlines() if 'mtproxyl-telemt' in x),'')
        settings=MT/'settings.conf'
        if settings.exists() and re.search(r'^ENGINE_BACKEND=["\']?binary',settings.read_text(),re.M):
            match=re.search(r'^ENGINE_SERVICE_NAME=["\']?([A-Za-z0-9_-]+)',settings.read_text(),re.M)
            binary=MT/'engine'/(match.group(1) if match else 'mtproxyl-telemt')
            if binary.is_file():
                try:out['telemt']=run([str(binary),'--version'],10)
                except Exception:out['telemt']=''
    if pathlib.Path('/usr/local/bin/mtproxyl-panel').exists():
        try:
            parts=run(['/usr/local/bin/mtproxyl-panel','version'],10).split()
            out['mtproxyl-panel']=parts[1] if len(parts)>1 else 'неизвестно'
        except Exception:out['mtproxyl-panel']='неизвестно'
    out['kernel']=os.uname().release
    if shutil.which('modinfo'):
        try:out['awg']=run(['modinfo','-F','version','amneziawg'],10)
        except Exception:pass
    p=pathlib.Path('/etc/os-release')
    if p.exists():
        match=re.search(r'^PRETTY_NAME="?([^"\n]+)',p.read_text(),re.M);out['os']=match.group(1) if match else ''
    out['rebootRequired']=pathlib.Path('/var/run/reboot-required').exists()
    return out

def baseline():
    out={'services':{},'awg':{},'containers':[]}
    for unit in ('x-ui.service','mtproxyl-panel.service','mtproxyl-zapret2.service','fail2ban.service'):
        p=subprocess.run(['systemctl','show',unit,'--property=ActiveState,MainPID,ActiveEnterTimestampMonotonic'],capture_output=True,text=True,timeout=10)
        out['services'][unit]=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
    if shutil.which('awg'):
        for name in run(['awg','show','interfaces']).split():
            if re.fullmatch(r'[A-Za-z0-9_.-]+',name):out['awg'][name]=pathlib.Path('/sys/class/net/'+name+'/ifindex').read_text().strip()
    if shutil.which('docker'):
        lines=run(['docker','ps','--format','{{.ID}}|{{.Names}}|{{.Image}}']).splitlines()
        out['containers']=lines
    return out

def update_plan(req):
    component=req.get('component');version=req.get('version','')
    if component in ('lucx','mtproxyl-panel','awg','fail2ban'):return SOFTWARE.plan(req)
    if component not in ('lucx','telemt','telemt-rollback','mtproxyl','mtproxyl-panel','os','os-index'):raise ValueError('Неподдерживаемый компонент')
    if component in ('lucx','telemt') and not re.fullmatch(r'v?[0-9][A-Za-z0-9_.-]{0,70}',version):raise ValueError('Укажите опубликованную версию')
    current=versions()
    if component in ('mtproxyl','mtproxyl-panel','telemt','telemt-rollback') and not (MT/'mtproxyl.sh').exists():raise ValueError('MTProxyL не установлен')
    if component=='lucx':
        target=tuple(map(int,re.findall(r'\d+',version)));installed=tuple(map(int,re.findall(r'\d+',current.get('lucx',''))))
        if target<=installed:raise ValueError('Выберите более новую версию LucX. Понижение с возможной несовместимостью БД не выполняется автоматически.')
    if component in ('mtproxyl','mtproxyl-panel'):
        import urllib.request
        release=json.load(urllib.request.urlopen('https://api.github.com/repos/Liafanx/MTProxyL/releases?per_page=50',timeout=20))
        candidates=[x['tag_name'] for x in release if not x.get('draft') and not x.get('prerelease') and (x['tag_name'].startswith('mtproxyl-panel-v') if component=='mtproxyl-panel' else re.fullmatch(r'v?\d+\.\d+\.\d+',x['tag_name']))]
        if not candidates or candidates[0]!=version:raise ValueError('Последний релиз изменился или не подтверждён. Обновите список версий и создайте новый план.')
    if component=='mtproxyl':
        return MANAGER.plan(req)
    preview={'title':'Обновление · '+component,'component':component,'version':version,'current':current,'impact':'Возможен разрыв подключений обслуживаемого компонента. Перезагрузка ОС автоматически не выполняется.','backupRequired':True,'rollback':'Резервная копия конфигурации не откатывает пакеты ОС или миграции БД. Предыдущая версия движка может потребовать отдельного восстановления.'}
    if component=='telemt-rollback':preview.update(title='Откат движка Telemt',version='Предыдущая версия, сохранённая на сервере')
    if component in ('os','os-index'):
        if os.geteuid()!=0 or not shutil.which('apt-get'):raise ValueError('Обновление ОС поддерживается через root SSH на Debian/Ubuntu с APT')
    if component=='os-index':
        preview.update(title='APT · обновить список пакетов',impact='Загружаются только индексы репозиториев. Установка пакетов и перезапуски служб не выполняются.',backupRequired=False)
    if component=='os':
        marker=STATE/'apt-refreshed.json'
        stamp=json.loads(marker.read_text()) if marker.exists() else {}
        if time.time()-stamp.get('finishedAt',0)>900:raise ValueError('Сначала обновите список пакетов кнопкой «Обновить ОС». План требует успешного apt update не старше 15 минут.')
        output=run(['apt-get','-s','--with-new-pkgs','--no-remove','upgrade'],60)
        preview['packages']=[l for l in output.splitlines() if l.startswith(('Inst ','Remv ','Conf '))]
        if len(preview['packages'])>1500:raise ValueError('Слишком большой план обновления; требуется отдельное обслуживание')
        if any(l.startswith('Remv ') for l in output.splitlines()):raise ValueError('APT предлагает удаление пакетов. Такой план не выполняется из Server Deck.')
        preview['cacheNote']='Список пакетов успешно обновлён через apt update. Разрешены новые зависимости, удаление пакетов запрещено. Локальные конфиги сохраняются.'
        preview['title']='Обновить ОС · apt upgrade -y'
        preview['impact']='Обновление ОС может перезапустить SSH, VPN, Docker и другие службы. Подключения могут прерваться. Перезагрузка VPS автоматически не выполняется.'
    rev=digest([current,preview.get('packages',[])])
    return dict(revision=rev,summary=preview,request=dict(kind='update',component=component,version=version))

def apply_update(req):
    component=req['component'];version=req.get('version','')
    if component=='mtproxyl':return MANAGER.apply(req)
    before=versions()
    if component in ('lucx','mtproxyl-panel','awg','fail2ban'):return SOFTWARE.apply(req)
    if component=='os-index':
        run(['apt-get','-o','APT::Update::Error-Mode=any','update'],300)
        write_json(STATE/'apt-refreshed.json',dict(finishedAt=time.time()))
        return {'verified':True,'message':'Список пакетов обновлён. Установка пакетов ещё не запускалась.'}
    if component=='telemt':
        run(['/opt/mtproxyl/mtproxyl.sh','engine','update',version.lstrip('v')],1500)
        if version.lstrip('v') not in versions().get('telemt',''):raise RuntimeError('Версия Telemt после обновления не подтверждена')
    elif component=='telemt-rollback':
        run(['/opt/mtproxyl/mtproxyl.sh','engine','rollback','--yes'],1500)
        if versions().get('telemt')==before.get('telemt'):raise RuntimeError('Откат не подтверждён: версия движка не изменилась')
    elif component=='mtproxyl-panel':
        run(['/opt/mtproxyl/mtproxyl.sh','panel','update'],1500)
        target=version.removeprefix('mtproxyl-panel-').lstrip('v')
        if versions().get(component,'').lstrip('v')!=target:raise RuntimeError('Версия после обновления не совпала с планом. Требуется проверка; автоматического повтора нет.')
    else:
        env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l',LC_ALL='C')
        p=subprocess.run(['apt-get','-y','--with-new-pkgs','--no-remove','-o','Dpkg::Options::=--force-confold','upgrade'],env=env,capture_output=True,text=True,timeout=1800)
        update_log(p.stdout+'\n'+p.stderr)
        if p.returncode:raise RuntimeError('APT завершился с ошибкой. Автоповтора нет; проверьте dpkg и журнал.')
    return {'verified':True,'before':before,'after':versions(),'message':'Команда завершена. Проверьте подключение контрольным клиентом: статус процесса не подтверждает прохождение VPN-трафика.'}

def restore_plan(req):
    panel=req.get('panel')
    if panel not in ('lucx','mtproxyl'):raise ValueError('Неизвестная панель')
    current=versions();saved=req.get('savedVersion')
    if not saved or current.get(panel)!=saved:raise ValueError('Версия панели отличается от версии резервной копии. Сначала восстановите совместимую версию; автоматического понижения нет.')
    return dict(revision=revisions(panel),summary={'title':'Восстановить резервную копию · '+panel,'panel':panel,'impact':'Текущие настройки и пользователи выбранной панели будут заменены. Подключения могут прерваться. Перед восстановлением создаётся новая копия.','backupRequired':True,'savedVersion':saved},request=dict(kind='restore',panel=panel,savedVersion=saved))

def apply_restore(req):
    data=base64.b64decode(req['restoreData'],validate=True)
    if len(data)>24*1024*1024:raise ValueError('Архив слишком большой')
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tar:
        manifest=json.load(tar.extractfile('manifest.json'))
        if manifest['panel']!=req['panel'] or manifest['hostname']!=os.uname().nodename:raise ValueError('Копия принадлежит другой панели/машине')
        if req['panel']=='lucx':
            content=tar.extractfile('x-ui.db').read(24*1024*1024)
            boundary='deck-'+secrets.token_hex(20)
            body=('--'+boundary+'\r\nContent-Disposition: form-data; name="keepHostSettings"\r\n\r\ntrue\r\n--'+boundary+'\r\nContent-Disposition: form-data; name="db"; filename="x-ui.db"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+content+('\r\n--'+boundary+'--\r\n').encode()
            lucx('server/importDB',body,ctype='multipart/form-data; boundary='+boundary)
            time.sleep(6)
            if revisions('lucx')!=manifest['revision']:raise RuntimeError('Восстановление отправлено, но конфигурация не совпала с копией. Проверьте панель перед повтором.')
        else:
            content=tar.extractfile('mtproxyl.tar.gz').read(24*1024*1024)
            with tempfile.NamedTemporaryFile(prefix='deck-restore-',suffix='.tar.gz') as f:
                f.write(content);f.flush();run(['/opt/mtproxyl/mtproxyl.sh','restore',f.name],180)
            if revisions('mtproxyl')!=manifest['revision']:raise RuntimeError('Команда восстановления завершилась, но настройки отличаются. Требуется проверка; повтора нет.')
    return {'verified':True,'message':'Восстановление подтверждено сравнением конфигурации. Проверьте подключение контрольным клиентом.'}

def safe_error(exc):
    # Never return subprocess stdout/stderr or a URL carrying credentials.
    if isinstance(exc,(ValueError,RuntimeError)):return str(exc)[:500]
    return type(exc).__name__+': операция не завершена; подробности доступны на сервере'

def write_json(path,value):
    temp=path.with_suffix('.tmp');fd=os.open(str(temp),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f:json.dump(value,f,ensure_ascii=False)
    os.replace(str(temp),str(path))

def job_worker(req):
    global JOB_LOG
    jid=req['job'];path=STATE/'jobs'/(jid+'.json')
    if req.get('kind') in ('update','install'):JOB_LOG=STATE/'jobs'/(jid+'.log')
    lock=open(STATE/'mutation.lock','a')
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        write_json(path,dict(id=jid,state='failed',error='На сервере уже выполняется изменение'));return
    write_json(path,dict(id=jid,state='running',startedAt=time.time()))
    mutation_started=False
    try:
        if not isinstance(req.get('expiresAt'),(int,float)) or req['expiresAt']<time.time():raise ValueError('План истёк до начала удалённой операции. Изменение не запускалось.')
        planned={'client':client_plan,'update':update_plan,'restore':restore_plan,'install':SOFTWARE.plan}[req['kind']](req)
        if planned['revision']!=req['revision']:raise ValueError('Настройки/версии изменились после предпросмотра. Создайте новый план.')
        before=baseline()
        mutation_started=True
        result={'client':apply_client,'update':apply_update,'restore':apply_restore,'install':SOFTWARE.apply}[req['kind']](req)
        time.sleep(2)
        after=baseline();result['runtimeBefore']=before;result['runtimeAfter']=after
        for unit,value in before['services'].items():
            if value.get('ActiveState')=='active' and after['services'].get(unit,{}).get('ActiveState')!='active':raise RuntimeError('После операции служба '+unit+' не активна. Требуется проверка.')
        if req['kind'] in ('install','update'):
            component=req.get('component');allowed={'lucx':{'x-ui.service'},'mtproxyl-panel':{'mtproxyl-panel.service'},'fail2ban':{'fail2ban.service'}}.get(component,set())
            if component!='os':
                for unit,value in before['services'].items():
                    if unit not in allowed and value.get('ActiveState')=='active' and value!=after['services'].get(unit):raise RuntimeError('Во время обслуживания изменилось состояние другой службы '+unit+'. Проверьте сервер.')
                for container in before['containers']:
                    if component in ('telemt','telemt-rollback') and '|mtproxyl|' in container:continue
                    if container not in after['containers']:raise RuntimeError('Один из ранее работавших контейнеров изменился или остановлен; требуется проверка.')
                if before['awg']!=after['awg']:raise RuntimeError('Состав AWG-интерфейсов изменился во время задачи; требуется проверка.')
        write_json(path,dict(id=jid,state='succeeded',finishedAt=time.time(),result=result))
    except Exception as e:write_json(path,dict(id=jid,state='needs_review' if mutation_started else 'failed',finishedAt=time.time(),error=safe_error(e),message='Автоповтора нет. Изменение могло примениться частично.' if mutation_started else 'Предварительная проверка отклонила операцию до изменения настроек.'))
    finally:
        if req.get('kind')=='restore':
            try:(STATE/'jobs'/(jid+'.request.json')).unlink()
            except FileNotFoundError:pass
        fcntl.flock(lock,fcntl.LOCK_UN);lock.close()

def dispatch(req,source=''):
    op=req.get('op')
    if op=='service-restart-targets':return RESTART.catalog(req)
    if op=='service-restart-info':return RESTART.info(req)
    if op=='service-restart-schedule':return RESTART.schedule(req,source)
    if op=='service-restart-status':return RESTART.status(req)
    if op=='reboot-info':return REBOOT.info(req)
    if op=='reboot-status':return REBOOT.status(req)
    if op=='reboot-schedule':return REBOOT.schedule(req)
    if op=='catalog':return catalog()
    if op=='versions':return versions()
    if op=='baseline':return baseline()
    if op=='software-inventory':return SOFTWARE.inventory()
    if op=='snapshot':return snapshot(req['panel'])
    if op=='plan':return {'client':client_plan,'update':update_plan,'restore':restore_plan,'install':SOFTWARE.plan}[req.get('kind')](req)
    if op=='links':
        name=valid_name(req.get('name'),req.get('panel'))
        if req.get('panel')=='mtproxyl':return {'links':(mt_record(name) or {}).get('links',{})}
        value=client_record(name);sub=value['client'].get('subId')
        links=lucx('clients/links/'+quote(name,safe='')) or []
        awg={}
        for inbound in lucx('inbounds/list') or []:
            if inbound['id'] in value.get('inboundIds',[]) and inbound.get('protocol') in ('awg','amneziawg') and sub:
                awg[str(inbound['id'])]=(lucx('clients/awgBody/'+quote(sub,safe='')+'?format=conf&inboundId='+str(inbound['id'])) or {}).get('body','')
        return {'links':links,'awg':awg,'subscriptions':lucx('clients/subLinks/'+quote(sub,safe='')) if sub else None}
    if op=='job':
        jid=req.get('job','')
        if not re.fullmatch(r'[0-9a-f]{32}',jid):raise ValueError('Неверный ID задачи')
        path=STATE/'jobs'/(jid+'.json')
        value=json.loads(path.read_text()) if path.exists() else {'id':jid,'state':'unknown'}
        p=subprocess.run(['systemctl','is-active','server-deck-'+jid+'.service'],capture_output=True,text=True,timeout=8)
        value['workerActive']=p.stdout.strip() in ('active','activating','deactivating')
        log=STATE/'jobs'/(jid+'.log')
        if log.exists():value['log']=log.read_text(errors='replace')[-15000:]
        return value
    if op=='execute':
        jid=req.get('job','')
        if not re.fullmatch(r'[0-9a-f]{32}',jid):raise ValueError('Неверный ID задачи')
        STATE.mkdir(mode=0o700,exist_ok=True);(STATE/'jobs').mkdir(mode=0o700,exist_ok=True)
        request_path=STATE/'jobs'/(jid+'.request.json');status_path=STATE/'jobs'/(jid+'.json');script_path=STATE/'worker.py'
        if request_path.exists() or status_path.exists():return {'id':jid,'state':'submitted','reused':True}
        fd=os.open(str(script_path),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w') as f:f.write(source)
        write_json(request_path,req);write_json(status_path,{'id':jid,'state':'queued'})
        run(['systemd-run','--quiet','--collect','--unit=server-deck-'+jid,'/usr/bin/python3',str(script_path),'--job',str(request_path)],15)
        return {'id':jid,'state':'submitted'}
    raise ValueError('Неизвестная операция')

from software_remote import SoftwareAdapter
SOFTWARE=SoftwareAdapter(globals())
from mtproxyl_update_remote import ManagerCodeUpdate
MANAGER=ManagerCodeUpdate(MT,STATE,{'versions':versions,'baseline':baseline,'log':update_log})
from reboot_remote import RemoteReboot
REBOOT=RemoteReboot(STATE)
from service_restart_remote import RemoteServiceRestart
RESTART=RemoteServiceRestart(STATE)

if __name__=='__main__':
    os.umask(0o077)
    if len(sys.argv)>2 and sys.argv[1]=='--job':
        job_worker(json.loads(pathlib.Path(sys.argv[2]).read_text()))
    elif len(sys.argv)>2 and sys.argv[1]=='--service-restart-worker':
        RESTART.worker(json.loads(pathlib.Path(sys.argv[2]).read_text()))
    elif '_DECK_REQUEST' in globals():
        try:print(json.dumps({'ok':True,'data':dispatch(_DECK_REQUEST,_DECK_SOURCE)},ensure_ascii=False))
        except Exception as e:print(json.dumps({'ok':False,'error':safe_error(e)},ensure_ascii=False))
