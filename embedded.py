"""Private per-panel origins. Native cookies never reach the browser."""
import atexit, contextlib, http.client, http.cookies, json, pathlib, re, secrets, select, shlex, socket, ssl, subprocess, threading, time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import parse_qs,urlsplit,unquote
from html import escape
import public_access
from panel_tls import pinned_https_connection

HOP={'connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade','content-length','set-cookie','x-frame-options','content-security-policy','access-control-allow-origin','access-control-allow-credentials','strict-transport-security'}
LUCX_READ_POST={'/setting/all','/setting/defaultSettings','/setting/factoryDefaults','/setting/validateRegex','/clients/onlines','/clients/onlinesByGuid','/clients/clientIpsByGuid','/clients/activeInbounds','/clients/lastOnline','/xray/getXrayResult','/xray/routeTest','/xray/testOutbound','/xray/testOutbounds','/clients/renewalPreview','/inbounds/awg/import/preview','/inbounds/wireguard/importPreview'}
LUCX_BLOCKED=('/server/updatePanel','/server/installXray/','/server/importDB','/server/rebuildAwgModule','/server/uninstallAwgModule','/server/restartAwg','/setting/restartPanel')
MT_BLOCKED={'/api/update/apply','/api/panel/update/apply','/api/mtproxyl/update/apply','/api/mtproxyl/engine/update','/api/mtproxyl/engine/rollback','/api/mtproxyl/backups/restore','/api/mtproxyl/mode','/api/mtproxyl/engine/service-name','/api/mtproxyl/engine/cleanup','/api/auto-update/config'}

def dark_html(data,base):
    """Set native theme preferences before any of the upstream app executes."""
    assets=escape(base.rstrip('/')+'/_deck/',quote=True)
    tags=('<meta name="color-scheme" content="dark"><link rel="stylesheet" href="'+assets+'theme.css"><script src="'+assets+'theme.js"></script>').encode()
    return re.sub(br'(<head\b[^>]*>)',lambda m:m.group(1)+tags,data,count=1,flags=re.I)

def valid_target(path,base):
    if not path.startswith('/') or path.startswith('//') or '\\' in path:raise ValueError('Неверный адрес панели')
    decoded=path
    for _ in range(3):decoded=unquote(decoded)
    p=urlsplit(decoded).path
    if any(x in ('.','..') for x in p.split('/')) or '\r' in decoded or '\n' in decoded:raise ValueError('Неверный путь панели')
    if base!='/' and not p.startswith(base):raise ValueError('Путь вне установленной панели')
    return path

def mutation(panel,base,path,method):
    if method in ('GET','HEAD','OPTIONS'):return False
    p=urlsplit(path).path
    rel=p[len(base.rstrip('/')):]
    if panel=='lucx':
        if rel in ('/login','/logout','/getTwoFactorEnable'):return False
        api=rel.removeprefix('/panel/api') if rel.startswith('/panel/api/') else rel.removeprefix('/panel')
        if api in LUCX_READ_POST or api.startswith(('/server/logs/','/server/xraylogs/','/server/amneziawglogs/')):return False
        if any(api==x or (x.endswith('/') and api.startswith(x)) for x in LUCX_BLOCKED):raise ValueError('Обновление, восстановление и перезапуск выполняются в центре Server Deck с предпросмотром и резервной копией.')
    else:
        if rel=='/api/auth/logout':return False
        if rel=='/api/geoip/lookup':return False
        if rel.startswith('/api/availability/'):raise ValueError('Для измерений используйте собственный раздел «Доступность» Server Deck.')
        if rel in MT_BLOCKED:raise ValueError('Используйте центр обновлений или резервные копии Server Deck. Защита работающих подключений сохраняется.')
    return True

class EmbeddedManager:
    def __init__(self,root,control,tunnel,parent_port):
        self.root=pathlib.Path(root);self.control=control;self.tunnel=tunnel;self.parent_port=parent_port
        self.parent=public_access.ORIGIN or 'http://127.0.0.1:'+str(parent_port);self.bridges={};self.lock=threading.RLock()
        self.revoked=False
        self.remote=(self.root/'embed_remote.py').read_text();atexit.register(self.close)
        self.remote=self.remote.replace('from panel_tls import pinned_https_connection',(self.root/'panel_tls.py').read_text())

    def credentials(self,s,panel):
        wrapper="import json,sys;e=json.load(sys.stdin);exec(compile(e['source'],'<server-deck-session>','exec'),{'__name__':'__main__','_DECK_REQUEST':e['request']})"
        c=self.control();cmd=['ssh','-i',str(c.keydir/s['key']),'-p',str(s['port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',s['user']+'@'+s['host'],'python3 -c '+shlex.quote(wrapper)]
        p=subprocess.run(cmd,input=json.dumps({'source':self.remote,'request':{'panel':panel}}),capture_output=True,text=True,timeout=70)
        if p.returncode:raise ValueError('Не удалось создать защищённое соединение с панелью')
        try:result=json.loads(p.stdout)
        except ValueError:raise ValueError('Не удалось прочитать ответ серверного адаптера')
        if not result.get('ok'):raise ValueError(result.get('error','Вход в панель не выполнен'))
        return result['data']

    def open(self,s,panel):
        if panel not in ('lucx','mtproxyl'):raise ValueError('Встроенный вход доступен для LucX и MTProxyL')
        key=(s['id'],panel)
        with self.lock:
            if self.revoked:raise ValueError('Войдите в Server Deck заново')
            bridge=self.bridges.get(key)
            if not bridge:
                meta=self.credentials(s,panel)
                if self.revoked:raise ValueError('Войдите в Server Deck заново')
                target=self.tunnel(s,dict(port=meta['port'],scheme=meta['scheme'],path=meta['base']))
                bridge=Bridge(self,s,panel,meta,urlsplit(target).port);self.bridges[key]=bridge
            else:bridge.refresh_auth()
            grant=bridge.new_grant()
        return {'bridge':bridge.id,'origin':bridge.origin,'entry':bridge.meta['entry'],'grant':grant,'panel':panel,'server':s['id']}

    @contextlib.contextmanager
    def guard(self,bridge,path,method):
        changes=mutation(bridge.panel,bridge.meta['base'],path,method)
        if not changes:yield;return
        c=self.control();sid=bridge.s['id']
        with c.lock:
            if sid in c.busy:raise ValueError('На сервере уже выполняется задача Server Deck')
            c.busy.add(sid)
        try:
            c.create_backup(bridge.s,bridge.panel,'before-native-panel-change '+method+' '+urlsplit(path).path)
            yield
        finally:
            with c.lock:c.busy.discard(sid);c.clients_cache.pop(sid,None)

    def close(self):
        self.revoked=True
        for b in list(self.bridges.values()):b.close()

class Bridge:
    def __init__(self,manager,s,panel,meta,target_port):
        self.manager=manager;self.s=s;self.panel=panel;self.meta=meta;self.target_port=target_port
        self.id=secrets.token_hex(10);self.cookie_name='deck_embed_'+self.id;self.session=secrets.token_urlsafe(32)
        self.grants={};self.lock=threading.RLock();self.cookies=dict(meta['cookies']);self.sockets=set();self.closed=False;self.local_theme={'theme':'dark','colors':{},'configured':True}
        self.httpd=ThreadingHTTPServer(('127.0.0.1',0),ProxyHandler);self.httpd.bridge=self;self.httpd.daemon_threads=True
        self.origin=('https://'+public_access.bridge_host(s['id'],panel)) if public_access.ORIGIN else 'http://127.0.0.1:'+str(self.httpd.server_port)
        threading.Thread(target=self.httpd.serve_forever,name='embedded-'+self.id,daemon=True).start()

    def refresh_auth(self):
        with self.lock:
            if self.meta['expiresAt']>time.time()+20:return
            meta=self.manager.credentials(self.s,self.panel)
            if (meta['port'],meta['scheme'],meta['base'])!=(self.meta['port'],self.meta['scheme'],self.meta['base']):raise ValueError('Адрес панели изменился. Перезапустите локальную панель для нового подключения.')
            self.meta=meta;self.cookies=dict(meta['cookies'])

    def new_grant(self):
        if self.manager.revoked:raise ValueError('Войдите в Server Deck заново')
        value=secrets.token_urlsafe(32)
        with self.lock:self.grants={k:v for k,v in self.grants.items() if v>time.time()};self.grants[value]=time.time()+60
        return value

    def use_grant(self,value):
        with self.lock:return not self.manager.revoked and self.grants.pop(value,0)>time.time()

    def authenticated(self,cookie):
        if self.manager.revoked or self.closed:return False
        c=http.cookies.SimpleCookie()
        try:c.load(cookie or '')
        except http.cookies.CookieError:return False
        value=c.get(self.cookie_name)
        return bool(value and secrets.compare_digest(value.value,self.session))

    def connection(self):
        if self.meta['scheme']=='https':return pinned_https_connection('127.0.0.1',self.target_port,self.meta['certificate'],timeout=60)
        return http.client.HTTPConnection('127.0.0.1',self.target_port,timeout=60)

    def upstream_headers(self,headers):
        skip=HOP|{'host','cookie','authorization','origin','referer','accept-encoding','x-forwarded-for','x-forwarded-host','x-forwarded-proto','x-deck-gateway','x-deck-token','x-deck-bridge-port'}
        out={k:v for k,v in headers.items() if k.lower() not in skip and not k.lower().startswith(('sec-fetch-','sec-ch-'))}
        host=self.s['host']+':'+str(self.meta['port'])
        out.update({'Host':host,'Origin':self.meta['scheme']+'://'+host,'X-Forwarded-Host':host,'X-Forwarded-Proto':self.meta['scheme'],'Accept-Encoding':'identity','Cookie':'; '.join(k+'='+v for k,v in self.cookies.items())})
        return out

    def accept_cookies(self,headers):
        with self.lock:
            for key,value in headers:
                if key.lower()=='set-cookie':
                    c=http.cookies.SimpleCookie();c.load(value)
                    for name,m in c.items():self.cookies[name]=m.value

    def close(self):
        self.closed=True
        for sock in list(self.sockets):
            try:sock.close()
            except OSError:pass
        self.httpd.shutdown();self.httpd.server_close();self.cookies.clear();self.grants.clear()

class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    @property
    def b(self):return self.server.bridge
    def error(self,status,message):
        if getattr(self,'headers_sent',False):self.close_connection=True;return
        body=json.dumps({'success':False,'ok':False,'msg':message,'error':{'message':message}},ensure_ascii=False).encode()
        self.close_connection=True
        self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('Connection','close');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_GET(self):self.proxy()
    def do_HEAD(self):self.proxy()
    def do_POST(self):self.proxy()
    def do_PUT(self):self.proxy()
    def do_PATCH(self):self.proxy()
    def do_DELETE(self):self.proxy()
    def do_OPTIONS(self):self.proxy()
    def end_headers(self):
        super().end_headers();self.headers_sent=True

    def proxy(self):
        self.headers_sent=False
        b=self.b
        if not public_access.gateway_ok(self.headers) or self.headers.get('Host')!='127.0.0.1:'+str(self.server.server_port):return self.error(403,'Host rejected')
        if self.path=='/_deck/bootstrap':
            origin=self.headers.get('Origin')
            opaque_navigation=origin in (None,'null') and self.headers.get('Sec-Fetch-Site') in ('same-site','same-origin') and self.headers.get('Sec-Fetch-Dest')=='iframe'
            # WebKit may serialize a no-referrer form-navigation Origin as
            # null. The one-use owner-issued grant remains mandatory.
            if self.command!='POST' or (origin!=b.manager.parent and not opaque_navigation):return self.error(403,'Bootstrap rejected')
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<2048:raise ValueError()
                value=parse_qs(self.rfile.read(size).decode()).get('grant',[''])[0]
            except Exception:return self.error(400,'Invalid bootstrap')
            if not b.use_grant(value):return self.error(403,'Session grant expired')
            self.send_response(303);self.send_header('Set-Cookie',b.cookie_name+'='+b.session+'; HttpOnly; SameSite=Strict; Path=/'+('; Secure' if public_access.ORIGIN else ''));self.send_header('Location',b.meta['entry']);self.send_header('Content-Length','0');self.send_header('Cache-Control','no-store');self.send_header('Referrer-Policy','no-referrer');self.end_headers();return
        if not b.authenticated(self.headers.get('Cookie')):return self.error(403,'Откройте панель через Server Deck')
        same_origin_form=self.headers.get('Origin') in (None,'null') and self.headers.get('Sec-Fetch-Site')=='same-origin' and self.headers.get('Sec-Fetch-Dest') in ('iframe','document')
        if self.command not in ('GET','HEAD','OPTIONS') and self.headers.get('Origin')!=b.origin and not same_origin_form:return self.error(403,'Origin rejected')
        try:
            valid_target(self.path,b.meta['base']);b.refresh_auth()
            relative=urlsplit(self.path).path[len(b.meta['base'].rstrip('/')):]
            if relative in ('/_deck/theme.js','/_deck/theme.css') and self.command in ('GET','HEAD'):
                suffix='js' if relative.endswith('.js') else 'css'
                data=(b.manager.root/'static'/('native-theme.'+suffix)).read_bytes()
                self.send_response(200);self.send_header('Content-Type','text/javascript; charset=utf-8' if suffix=='js' else 'text/css; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Length',str(len(data)));self.end_headers()
                if self.command!='HEAD':self.wfile.write(data)
                return
            if self.headers.get('Upgrade','').lower()=='websocket':return self.websocket()
            if urlsplit(self.path).path.endswith(('pwa-register.js','service-worker.js','sw.js')):
                body=b'/* PWA registration is disabled only inside this private embedded view. */';self.send_response(200);self.send_header('Content-Type','text/javascript');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
            size=int(self.headers.get('Content-Length','0'))
            if size<0 or size>48*1024*1024:raise ValueError('Размер запроса превышает лимит')
            if self.headers.get('Transfer-Encoding'):raise ValueError('Chunked requests are not supported')
            body=self.rfile.read(size) if size else None
            relative=urlsplit(self.path).path[len(b.meta['base'].rstrip('/')):]
            if b.panel=='mtproxyl' and relative=='/api/panel/settings/theme' and self.command=='PUT':
                value=json.loads(body or b'{}')
                if set(value)-{'theme','colors'} or value.get('theme') not in ('system','light','dark','mocha','parchment','matrix','custom'):raise ValueError('Неверная тема')
                colors=value.get('colors') or {}
                if not isinstance(colors,dict) or len(colors)>40 or any(not isinstance(v,str) or not re.fullmatch(r'#[A-Fa-f0-9]{3,8}',v) for v in colors.values()):raise ValueError('Неверные цвета темы')
                b.local_theme={'theme':value['theme'],'colors':colors,'configured':True}
                data=json.dumps({'ok':True,'data':b.local_theme}).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
            with b.manager.guard(b,self.path,self.command):
                conn=b.connection()
                try:
                    headers=b.upstream_headers(self.headers)
                    if body is not None:headers['Content-Length']=str(len(body))
                    conn.request(self.command,self.path,body,headers);response=conn.getresponse();pairs=response.getheaders();b.accept_cookies(pairs)
                    csp=next((v for k,v in pairs if k.lower()=='content-security-policy'),'default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: blob:; connect-src \'self\' ws: wss:')
                    csp='; '.join(x.strip() for x in csp.split(';') if not x.strip().lower().startswith('frame-ancestors'))+'; frame-ancestors '+b.manager.parent
                    streaming='text/event-stream' in response.getheader('Content-Type','')
                    data=None if streaming else response.read(48*1024*1024+1)
                    transformed=False
                    if data and response.status==200 and 'text/html' in response.getheader('Content-Type','').lower():
                        data=dark_html(data,b.meta['base']);transformed=True
                    if b.panel=='mtproxyl' and relative=='/api/theme' and self.command=='GET' and response.status==200:
                        value=json.loads(data);theme=value.get('data',{})
                        theme.update(b.local_theme or {});theme['configured']=True
                        if theme.get('theme')=='custom' and not theme.get('colors'):theme['theme']='dark'
                        value['data']=theme;data=json.dumps(value).encode();transformed=True
                    if data is not None and len(data)>48*1024*1024:raise ValueError('Ответ панели превышает лимит')
                    self.send_response(response.status)
                    for key,value in pairs:
                        if key.lower() in HOP:continue
                        if transformed and key.lower() in ('etag','last-modified','content-md5','digest'):continue
                        if key.lower()=='location':
                            target=urlsplit(value)
                            if target.scheme and target.hostname in (b.s['host'],'127.0.0.1','localhost'):value=b.origin+target.path+('?' +target.query if target.query else '')
                        if key.lower() not in ('cache-control','referrer-policy'):self.send_header(key,value)
                    self.send_header('Content-Security-Policy',csp);self.send_header('Cache-Control','no-store');self.send_header('Referrer-Policy','no-referrer')
                    if streaming:self.send_header('Connection','close');self.close_connection=True
                    else:self.send_header('Content-Length',str(len(data)))
                    self.end_headers()
                    if streaming:
                        while not b.closed:
                            chunk=response.read1(65536)
                            if not chunk:break
                            self.wfile.write(chunk);self.wfile.flush()
                    elif self.command!='HEAD':self.wfile.write(data)
                finally:conn.close()
        except (BrokenPipeError,ConnectionResetError):self.close_connection=True
        except Exception as e:
            message=str(e) if isinstance(e,ValueError) else 'Соединение с панелью не завершено. Повторная отправка изменения не выполняется.'
            self.error(502,message)

    def websocket(self):
        b=self.b
        if self.headers.get('Origin')!=b.origin:return self.error(403,'WebSocket origin rejected')
        if b.meta['scheme']=='https':
            conn=b.connection();upstream=conn.sock;conn.sock=None
        else:upstream=socket.create_connection(('127.0.0.1',b.target_port),timeout=15)
        b.sockets.update((upstream,self.connection))
        try:
            headers=b.upstream_headers(self.headers);headers.update({'Upgrade':'websocket','Connection':'Upgrade'})
            payload='GET '+self.path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n';upstream.sendall(payload.encode())
            raw=b''
            while not raw.endswith(b'\r\n\r\n'):
                value=upstream.recv(1)
                if not value or len(raw)>65536:raise ValueError('Не удалось открыть WebSocket панели')
                raw+=value
            if not raw.startswith(b'HTTP/1.1 101'):raise ValueError('Панель не разрешила WebSocket-сессию')
            lines=raw.decode('iso-8859-1').split('\r\n');safe=[lines[0]]+[line for line in lines[1:] if line and line.split(':',1)[0].lower() not in ('set-cookie','x-frame-options','content-security-policy')]
            self.connection.sendall(('\r\n'.join(safe)+'\r\n\r\n').encode('iso-8859-1'));self.close_connection=True
            upstream.settimeout(30);self.connection.settimeout(30)
            while not b.closed and not b.manager.revoked:
                ready,_,_=select.select([upstream,self.connection],[],[],1)
                if isinstance(upstream,ssl.SSLSocket) and upstream.pending() and upstream not in ready:ready.append(upstream)
                for src in ready:
                    data=src.recv(65536)
                    if not data:return
                    (self.connection if src is upstream else upstream).sendall(data)
        finally:
            b.sockets.discard(upstream);b.sockets.discard(self.connection);upstream.close()
