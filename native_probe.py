"""On-demand measurements from this Mac. Never changes routes or VPN state."""
import concurrent.futures,http.client,json,pathlib,re,socket,ssl,sys,threading,time

def connect(host,port,interface='auto',timeout=3):
    error=None
    for family,kind,proto,_,address in socket.getaddrinfo(host,port,socket.AF_INET,socket.SOCK_STREAM):
        sock=socket.socket(family,kind,proto);sock.settimeout(timeout)
        try:
            if interface!='auto':
                if sys.platform!='darwin':raise OSError('Привязка интерфейса этой версии поддерживается только на macOS')
                # IP_BOUND_IF = 25 in the installed macOS SDK netinet/in.h.
                sock.setsockopt(socket.IPPROTO_IP,25,socket.if_nametoindex(interface))
            sock.connect(address);return sock
        except OSError as e:error=e;sock.close()
    raise error or OSError('Нет IPv4-адреса цели')

def source(interface):
    errors=[]
    for host,path in [('ipinfo.io','/json'),('api.country.is','/')]:
        conn=None
        try:
            sock=connect(host,443,interface,3)
            try:secured=ssl.create_default_context().wrap_socket(sock,server_hostname=host)
            except Exception:sock.close();raise
            conn=http.client.HTTPSConnection(host,timeout=3);conn.sock=secured
            conn.request('GET',path,headers={'User-Agent':'ServerDeck-NativeProbe/1.0'});r=conn.getresponse();d=json.loads(r.read(65536))
            if r.status!=200 or not d.get('ip') or not re.fullmatch(r'[A-Z]{2}',str(d.get('country',''))):raise ValueError('Нет проверяемой географии выхода')
            return dict(interface=interface,ip=d['ip'],country=d['country'],provider=d.get('org',''),geoSource=host,verifiedAt=time.time())
        except Exception as e:errors.append(host+': '+str(e))
        finally:
            if conn:conn.close()
    return dict(interface=interface,ip=None,country=None,error='; '.join(errors),verifiedAt=time.time())

def measure(host,target,interface):
    start=time.monotonic();sock=None;r=dict(port=target['port'],tcp=False,tcpMs=None,tls='not_checked',error='')
    try:
        sock=connect(host,target['port'],interface,3);r.update(tcp=True,tcpMs=round((time.monotonic()-start)*1000,1))
        if target.get('tls'):
            try:
                sock=ssl.create_default_context().wrap_socket(sock,server_hostname=target.get('sni') or host);r['tls']='verified'
            except ssl.SSLCertVerificationError as e:r.update(tls='certificate_error',tlsError=str(e))
            except (OSError,ssl.SSLError) as e:r.update(tls='handshake_error',tlsError=str(e))
    except Exception as e:r['error']=str(e)
    finally:
        if sock:sock.close()
    return r

def verdict(report):
    if report['point'].get('country')!='RU':return 'point_not_ru'
    direct=report.get('direct',[]);control={r['port']:r for r in report.get('control',[])}
    if not direct:return 'unknown'
    if all(r['tcp'] for r in direct):return 'reachable'
    if report['reference'].get('country') and report['reference']['country']!='RU' and any(not r['tcp'] and control.get(r['port'],{}).get('tcp') for r in direct):return 'difference'
    return 'unconfirmed'

class NativeProbe:
    def __init__(self,path):
        self.path=pathlib.Path(path);self.lock=threading.RLock();self.busy=False
        try:self.reports=json.loads(self.path.read_text())
        except (OSError,ValueError):self.reports={}
    def snapshot(self):
        with self.lock:return dict(servers=json.loads(json.dumps(self.reports)),busy=self.busy,automatic=False,available=sys.platform=='darwin',reason='' if sys.platform=='darwin' else 'Точка на Mac отключена после переноса. Здесь доступен Cheburcheck; VPS не используется как точка РФ.')
    def start(self,server,targets,interface='en0'):
        if sys.platform!='darwin':raise ValueError('Для собственного измерителя нужна отдельная точка в РФ. Используйте Cheburcheck.')
        if not re.fullmatch(r'en[0-9]+',interface):raise ValueError('Выберите физический интерфейс en0, en1…')
        socket.if_nametoindex(interface)
        with self.lock:
            if self.busy:raise ValueError('Разовая проверка уже выполняется')
            self.busy=True;self.reports[server['id']]=dict(status='running',startedAt=time.time(),host=server['host'],interface=interface)
        threading.Thread(target=self.run,args=(server,targets,interface),daemon=True,name='temporary-native-probe').start()
    def run(self,server,targets,interface):
        r=dict(status='done',host=server['host'],interface=interface,startedAt=time.time())
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                direct_future=pool.submit(source,interface);control_future=pool.submit(source,'auto');r['point']=direct_future.result();r['reference']=control_future.result()
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                direct=[pool.submit(measure,server['host'],t,interface) for t in targets] if r['point'].get('country') else []
                control=[pool.submit(measure,server['host'],t,'auto') for t in targets]
                r['direct']=[x.result() for x in direct];r['control']=[x.result() for x in control]
            r['verdict']=verdict(r)
        except Exception as e:r.update(status='error',error=str(e))
        r['finishedAt']=time.time()
        with self.lock:
            self.reports[server['id']]=r;self.busy=False
            tmp=self.path.with_suffix('.tmp');tmp.write_text(json.dumps(self.reports,ensure_ascii=False,indent=2));tmp.chmod(0o600);tmp.replace(self.path)
