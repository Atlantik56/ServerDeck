import concurrent.futures, datetime, http.client, json, os, re, shutil, sqlite3, subprocess, sys, time

request = json.loads(sys.argv[1])
def run(args, timeout=12):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def unit_status(unit, include_collection=False):
    if unit.startswith('docker:'):
        cid=unit.split(':',1)[1]
        code,out,err=run(['docker','inspect','--format','{{json .State}}',cid])
        d=json.loads(out) if code==0 else {}
        if not isinstance(d,dict):raise ValueError('Invalid Docker state')
        result=dict(unit=unit,loaded=code==0,state='active' if d.get('Running') else 'inactive',substate=d.get('Status','unknown'),pid=str(d.get('Pid',0)),enabled='',since=d.get('StartedAt',''),memory='',description='Docker container')
        if include_collection:result['collectionOk']=code==0 and isinstance(d.get('Running'),bool) and bool(d.get('Status'))
        return result
    code, out, err = run(['systemctl', 'show', unit, '--no-pager', '--property=Id,Description,LoadState,ActiveState,SubState,MainPID,UnitFileState,ActiveEnterTimestamp,MemoryCurrent'])
    d = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    result=dict(unit=unit, description=d.get('Description', unit), loaded=d.get('LoadState') in ('loaded','masked'), state=d.get('ActiveState', 'unknown'), substate=d.get('SubState', ''), enabled=d.get('UnitFileState', ''), pid=d.get('MainPID', '0'), since=d.get('ActiveEnterTimestamp', ''), memory=d.get('MemoryCurrent', ''))
    if include_collection:result['collectionOk']=code==0 and d.get('LoadState') in ('stub','loaded','not-found','bad-setting','error','merged','masked') and d.get('ActiveState') in ('active','reloading','inactive','failed','activating','deactivating','maintenance','refreshing')
    return result

def collect_unit_status(unit):
    try:return unit_status(unit, include_collection=True)
    except (OSError,ValueError,TypeError,subprocess.SubprocessError):
        return dict(unit=unit,loaded=False,state='unknown',substate='unknown',collectionOk=False)

def probe_container_awg(identity):
    """Interface existence only; no private configuration, peers or endpoints."""
    if not isinstance(identity,str) or not re.fullmatch(r'[0-9a-f]{12,64}',identity):
        return dict(collectionOk=False,interfaces=[],error='Неверная идентичность контейнера AWG')
    try:
        code,out,_=run(['docker','exec','--',identity,'awg','show','interfaces'])
        names=out.split()
        if code or any(not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}',name) for name in names):
            raise ValueError('AWG inventory failed')
        return dict(collectionOk=True,interfaces=sorted(set(names)))
    except (OSError,ValueError,TypeError,subprocess.SubprocessError):
        return dict(collectionOk=False,interfaces=[],error='Не удалось проверить интерфейсы AWG в контейнере')

def collect_containers():
    containers=[];supported=None
    try:
        supported=bool(shutil.which('docker'))
        if not supported:return containers,True,False
        code,out,_=run(['docker','ps','-a','--format','{{json .}}'])
        if code:return containers,False,True
        complete=True
        for line in out.splitlines():
            try:
                item=json.loads(line)
                if not isinstance(item,dict) or not re.fullmatch(r'[0-9a-f]{12,64}',item.get('ID','')) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',item.get('Names','')) or item.get('State') not in ('created','restarting','running','removing','paused','exited','dead') or not isinstance(item.get('Image'),str) or not isinstance(item.get('Status'),str):
                    raise ValueError('Incomplete Docker inventory')
                container=dict(unit='docker:'+item['ID'],name=item['Names'],image=item['Image'],state='active' if item['State']=='running' else 'inactive',loaded=True,substate=item['State'],enabled='',description=item['Status'])
                if item['State']=='running' and re.fullmatch(r'amnezia[-_]?awg[A-Za-z0-9_.\-]{0,80}',item['Names'].lower()):
                    container['awg']=probe_container_awg(item['ID'])
                containers.append(container)
            except (ValueError,TypeError,KeyError):complete=False
        return containers,complete,True
    except (OSError,ValueError,TypeError,subprocess.SubprocessError):
        return containers,False,supported

def collect_host_awg():
    awg=[];supported=None
    try:
        supported=bool(shutil.which('awg'))
        if not supported:return awg,True,False
        code,interfaces,_=run(['awg','show','interfaces'])
        if code:return awg,False,True
        complete=True
        for interface in interfaces.split():
            if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}',interface):
                complete=False;continue
            try:
                hs_code,hs,_=run(['awg','show',interface,'latest-handshakes'])
                traffic_code,traffic,_=run(['awg','show',interface,'transfer'])
                port_code,port,_=run(['awg','show',interface,'listen-port'])
                timestamps=[int(x.split()[1]) for x in hs.splitlines() if len(x.split())==2]
                transfers=[list(map(int,x.split()[1:])) for x in traffic.splitlines() if len(x.split())==3]
                counters={}
                for key in ('rx_errors','rx_frame_errors','rx_length_errors','rx_dropped','tx_errors'):
                    try:counters[key]=int(open('/sys/class/net/'+interface+'/statistics/'+key).read())
                    except (OSError,ValueError):pass
                try:ifindex=int(open('/sys/class/net/'+interface+'/ifindex').read())
                except (OSError,ValueError):ifindex=None
                now=int(datetime.datetime.now().timestamp())
                awg.append({'interface':interface,'ifindex':ifindex,'port':port,'peers':len(timestamps),'online':sum(1 for x in timestamps if x and now-x<180),'latestHandshake':max(timestamps,default=0),'rx':sum(x[0] for x in transfers),'tx':sum(x[1] for x in transfers),'counters':counters})
                if hs_code or traffic_code or port_code or ifindex is None:complete=False
            except (OSError,ValueError,TypeError,subprocess.SubprocessError):
                complete=False
        return awg,complete,True
    except (OSError,ValueError,TypeError,subprocess.SubprocessError):
        return awg,False,supported

def redact(text):
    text = re.sub(r'(?i)((?:password|private.?key|preshared.?key|header.?protection.?key|api.?token|secret)\s*[:=]\s*)\S+', r'\1[скрыто]', text)
    return re.sub(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?!\w)', '[ключ скрыт]', text)

action = request.get('action', 'status')
if action in ('start', 'stop', 'restart', 'logs'):
    unit = request['unit']
    docker=bool(re.fullmatch(r'docker:[0-9a-f]{12,64}',unit))
    if not docker and not re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service', unit):
        raise ValueError('Invalid unit')
    if action == 'logs':
        code, out, err = run(['docker','logs','--tail','100','--timestamps',unit.split(':',1)[1]] if docker else ['journalctl', '-u', unit, '-n', '100', '--no-pager', '-o', 'short-iso'], 20)
        result = {'logs': redact(out+('\n'+err if docker and err else '')), 'error': redact(err) if not docker else '', 'status': unit_status(unit)}
    else:
        if not unit_status(unit)['loaded']:
            raise ValueError('Service is not installed')
        code, out, err = run(['docker',action,unit.split(':',1)[1]] if docker else ['systemctl', action, unit], 45)
        result = {'ok': code == 0, 'error': redact(err or out), 'status': unit_status(unit)}
elif action == 'inventory':
    code, out, err = run(['systemctl', 'list-unit-files', '--type=service', '--no-pager', '--no-legend'])
    units={line.split()[0]:{'unit':line.split()[0],'enabled':line.split()[1]} for line in out.splitlines() if len(line.split())>=2 and line.split()[0].endswith('.service') and not line.split()[0].endswith('@.service')}
    _,active,_=run(['systemctl','list-units','--all','--type=service','--plain','--no-legend','--no-pager'])
    for line in active.splitlines():
        parts=line.split()
        if parts and parts[0].endswith('.service') and not parts[0].endswith('@.service'):
            units.setdefault(parts[0],{'unit':parts[0],'enabled':'runtime'})
    result={'units':sorted(units.values(),key=lambda x:x['unit'])}
else:
    cpu_start=list(map(int,open('/proc/stat').readline().split()[1:9]));cpu_started=time.monotonic()
    services = request.get('services', [])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        states = list(pool.map(collect_unit_status, services))
    containers,containers_ok,docker_supported=collect_containers()
    mem = {}
    for line in open('/proc/meminfo'):
        name, value = line.split(':', 1); mem[name] = int(value.strip().split()[0]) * 1024
    stat = os.statvfs('/')
    awg,host_awg_ok,awg_supported=collect_host_awg()
    collection_ok=dict(services=all(x.get('collectionOk') is True for x in states),containers=containers_ok,awg=host_awg_ok and containers_ok and all(x.get('awg',{}).get('collectionOk',True) for x in containers))
    panels = []
    try:
        c = sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True)
        settings = dict(c.execute('select key,value from settings')); c.close()
        panels.append({'name': '3x-ui / LucX', 'port': int(settings.get('webPort', '2053')), 'path': settings.get('webBasePath', '/'), 'scheme': 'https' if settings.get('webCertFile') else 'http', 'domain': settings.get('webDomain', ''), 'localOnly':not bool(settings.get('webCertFile'))})
    except (OSError, sqlite3.Error, ValueError): pass
    _, sockets, _ = run(['ss', '-lntp'])
    listening_tcp=set()
    for line in sockets.splitlines()[1:]:
        parts=line.split()
        if len(parts)>3 and not parts[3].startswith(('127.','[::1]','::1:')):
            try:listening_tcp.add(int(parts[3].rsplit(':',1)[1]))
            except ValueError:pass
    for line in sockets.splitlines():
        if 'mtproxyl-panel' in line:
            address = line.split()[3]
            port=int(address.rsplit(':',1)[1]);scheme='http';local=address.startswith(('127.','[::1]'))
            try:
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=2);conn.request('GET','/');response=conn.getresponse();body=response.read(256);conn.close()
                if b'HTTP request to an HTTPS server' in body:scheme='https'
            except (OSError,http.client.HTTPException):pass
            panels.append({'name': 'MTProxyL', 'port': port, 'path': '/', 'scheme': scheme, 'domain': '', 'localOnly':local or scheme=='http'})
            break
    # Caddy's local admin API supplies host routing metadata only; no config or credentials leave the server.
    try:
        conn=http.client.HTTPConnection('127.0.0.1',2019,timeout=2);conn.request('GET','/config/apps/http/servers');response=conn.getresponse();routes=json.loads(response.read(1048576));conn.close()
        domains=set()
        def hosts(value):
            if isinstance(value,dict):
                for k,v in value.items():
                    if k=='host' and isinstance(v,list):
                        domains.update(h for h in v if isinstance(h,str) and re.fullmatch(r'[A-Za-z0-9.-]+\.[A-Za-z]{2,}',h))
                    else:hosts(v)
            elif isinstance(value,list):
                for x in value:hosts(x)
        hosts(routes)
        for domain in sorted(domains):panels.append({'name':domain,'url':'https://'+domain+'/'})
    except (OSError,ValueError,http.client.HTTPException):pass
    if time.monotonic()-cpu_started<.2:time.sleep(.2)
    cpu_end=list(map(int,open('/proc/stat').readline().split()[1:9]));total=sum(cpu_end)-sum(cpu_start);idle=sum(cpu_end[3:5])-sum(cpu_start[3:5])
    _,failed,_=run(['systemctl','list-units','--state=failed','--type=service','--plain','--no-legend','--no-pager'])
    result = {'hostname': os.uname().nodename, 'kernel': os.uname().release, 'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'uptime': float(open('/proc/uptime').read().split()[0]), 'load': os.getloadavg(), 'cpu':round(max(0,min(100,(total-idle)/total*100)),1) if total else None, 'cpuIntervalSeconds':round(time.monotonic()-cpu_started,2), 'cores':os.cpu_count(), 'bootId':open('/proc/sys/kernel/random/boot_id').read().strip(), 'rebootRequired':os.path.exists('/var/run/reboot-required'), 'failedUnits':[line.split()[0] for line in failed.splitlines() if line.split() and line.split()[0].endswith('.service')], 'swap':{'total':mem.get('SwapTotal',0),'used':mem.get('SwapTotal',0)-mem.get('SwapFree',0)}, 'memory': {'total': mem['MemTotal'], 'used': mem['MemTotal']-mem['MemAvailable']}, 'disk': {'total': stat.f_blocks*stat.f_frsize, 'used': (stat.f_blocks-stat.f_bfree)*stat.f_frsize,'available':stat.f_bavail*stat.f_frsize,'inodesTotal':stat.f_files,'inodesFree':stat.f_favail}, 'services': states, 'containers':containers, 'awg': awg, 'awgSupported':awg_supported, 'dockerSupported':docker_supported, 'collectionOk':collection_ok, 'panels': panels, 'listeningTcp':sorted(listening_tcp)}
print(json.dumps(result, ensure_ascii=False))
