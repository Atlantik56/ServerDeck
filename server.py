#!/usr/bin/env python3
import argparse, atexit, base64, concurrent.futures, http.cookies, json, os, pathlib, re, secrets, signal, socket, subprocess, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import shlex
from monitor import HealthStore
from native_probe import NativeProbe
from mac_probe_client import MacProbeClient
from cheburcheck import Cheburcheck
from control import Control
from embedded import EmbeddedManager
from account import Account,AccountError
from alerts import AlertManager, DEFAULT_CONFIG as ALERT_DEFAULT_CONFIG
from security_stats import SecurityStats
from security_updates import SecurityUpdateWatch
from security_release import publication_events
from outage_diagnostics import OutageDiagnostics
from fail2ban import Fail2banManager
from deployment_settings import DeploymentSettings
from bot_menu import ReadOnlyBotMenu
from bot_actions import BotActions
import public_access

ROOT = pathlib.Path(__file__).resolve().parent
CONFIG = ROOT / 'servers.json'
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.RLock()
CACHE = {}
BUSY = set()
HISTORY = []
TUNNELS = {}
MONITOR = None
NATIVE_PROBE = None
CHEBURCHECK = None
CONTROL = None
EMBEDDED = None
ACCOUNT = None
ALERTS = None
SECURITY = None
SECURITY_UPDATES = None
OUTAGE_DIAGNOSTICS = None
FAIL2BAN = None
DEPLOYMENT = None
BOT_ACTIONS = None
MONITOR_STOP = threading.Event()
REFRESH_LOCKS = {}
KEYDIR = pathlib.Path.home() / '.ssh'
REMOTE = (ROOT / 'remote.py').read_text()
DEFAULTS = []

def write_config(servers):
    tmp = CONFIG.with_suffix('.tmp')
    fd = os.open(str(tmp), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f: json.dump(servers, f, ensure_ascii=False, indent=2)
    os.replace(str(tmp), str(CONFIG))

def servers():
    with LOCK: return json.loads(CONFIG.read_text())

def find(sid):
    return next((s for s in servers() if s['id'] == sid), None)

def valid_server(data):
    host = data.get('host', '').strip()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', host): raise ValueError('Укажите IPv4 или DNS-имя сервера')
    user = data.get('user', 'root').strip()
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user): raise ValueError('Неверное имя SSH-пользователя')
    key = data.get('key', '')
    p = (KEYDIR / key).resolve()
    if p.parent != KEYDIR.resolve() or not p.is_file() or p.name.endswith('.pub'): raise ValueError('Выберите приватный ключ из ~/.ssh')
    port = int(data.get('port', 22))
    if not 1 <= port <= 65535: raise ValueError('Неверный порт')
    return dict(id=secrets.token_hex(6), name=str(data.get('name') or host)[:80], host=host, user=user, port=port, key=key, services=[])

def generate_key(data):
    host=str(data.get('host','')).strip();user=str(data.get('user','root')).strip();port=int(data.get('port',22))
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',host):raise ValueError('Сначала укажите IP или домен сервера')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',user):raise ValueError('Проверьте SSH-пользователя')
    if not 1<=port<=65535:raise ValueError('Проверьте SSH-порт')
    KEYDIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    name='deck_'+re.sub(r'[^A-Za-z0-9_-]','_',host)[:80]+'_'+user+'_'+secrets.token_hex(5)
    path=KEYDIR/name
    # The directory is exclusively reserved first; ssh-keygen never overwrites another key.
    reservation=KEYDIR/('.'+name+'.reserve')
    reservation.mkdir(mode=0o700)
    try:
        if path.exists() or path.with_suffix('.pub').exists():raise ValueError('Имя ключа уже занято')
        p=subprocess.run(['ssh-keygen','-q','-t','ed25519','-f',str(path),'-C','server-deck:'+user+'@'+host,'-N',''],capture_output=True,text=True,timeout=20)
        if p.returncode:raise RuntimeError(p.stderr.strip() or 'Не удалось создать SSH-ключ')
        path.chmod(0o600);public_path=pathlib.Path(str(path)+'.pub');public_path.chmod(0o644)
        public=public_path.read_text().strip()
        fingerprint=subprocess.check_output(['ssh-keygen','-lf',str(public_path)],text=True,timeout=5).strip()
    finally:reservation.rmdir()
    script='set -e\numask 077\nmkdir -p "$HOME/.ssh"\nchmod 700 "$HOME/.ssh"\ntouch "$HOME/.ssh/authorized_keys"\ngrep -qxF '+shlex.quote(public)+' "$HOME/.ssh/authorized_keys" || printf \'%s\\n\' '+shlex.quote(public)+' >> "$HOME/.ssh/authorized_keys"\nchmod 600 "$HOME/.ssh/authorized_keys"'
    install=('sh -c ' if user=='root' else 'sudo -H -u '+shlex.quote(user)+' sh -c ')+shlex.quote(script)
    connect=shlex.join((['runuser','-u','serverdeck','--'] if public_access.ORIGIN else [])+['ssh','-i',str(path),'-p',str(port),'-o','IdentitiesOnly=yes',user+'@'+host])
    return dict(key=name,publicKey=public,fingerprint=fingerprint,installCommand=install,connectCommand=connect,host=host,user=user)

def ssh(s, payload):
    command = ['ssh', '-i', str(KEYDIR/s['key']), '-p', str(s['port']), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', s['user']+'@'+s['host'], 'python3 - ' + __import__('shlex').quote(json.dumps(payload))]
    p = subprocess.run(command, input=REMOTE, capture_output=True, text=True, timeout=65)
    if p.returncode: raise RuntimeError((p.stderr or p.stdout or 'SSH завершился с ошибкой')[-1800:])
    return json.loads(p.stdout)

def refresh(s, force=False):
    with LOCK:
        guard=REFRESH_LOCKS.setdefault(s['id'],threading.RLock())
    with guard:
        with LOCK:
            old = CACHE.get(s['id'])
            if old and not force and time.time()-old['checkedAt'] < 20: return old
        started=time.monotonic();tcp_ok=False;tcp_ms=None
        try:
            tcp_start=time.monotonic()
            with socket.create_connection((s['host'],s['port']),timeout=3):pass
            tcp_ok=True;tcp_ms=round((time.monotonic()-tcp_start)*1000,1)
        except OSError:pass
        try:
            data = ssh(s, {'action':'status', 'services':s['services']})
            data['panels'].extend(s.get('panels',[]))
            value = dict(ok=True, data=data, checkedAt=time.time())
        except Exception as e: value = dict(ok=False, error=str(e), checkedAt=time.time())
        value.update(tcpOk=tcp_ok,tcpMs=tcp_ms,durationMs=round((time.monotonic()-started)*1000))
        try:value['health']=health_store().record(s['id'],value)
        except Exception as e:value['monitorError']='История недоступна: '+str(e)
        with LOCK: CACHE[s['id']] = value
        try:outage_diagnostics().observe(s,value)
        except Exception:pass  # Diagnostics must never interrupt health collection.
        return value

def health_store():
    global MONITOR
    with LOCK:
        if MONITOR is None:MONITOR=HealthStore(ROOT/'health.sqlite3')
        return MONITOR

def native_probe():
    global NATIVE_PROBE
    with LOCK:
        if NATIVE_PROBE is None:NATIVE_PROBE=(MacProbeClient if os.environ.get('DECK_MAC_PROBE_TOKEN') else NativeProbe)(ROOT/'native-probe-results.json')
        return NATIVE_PROBE

def cheburcheck():
    global CHEBURCHECK
    with LOCK:
        if CHEBURCHECK is None:CHEBURCHECK=Cheburcheck(ROOT/'cheburcheck-results.json')
        return CHEBURCHECK

def outage_diagnostics():
    global OUTAGE_DIAGNOSTICS
    with LOCK:
        if OUTAGE_DIAGNOSTICS is None:
            OUTAGE_DIAGNOSTICS=OutageDiagnostics(ROOT/'control-data'/'outage-diagnostics.json',servers,native_probe,cheburcheck)
        return OUTAGE_DIAGNOSTICS

def deployment_settings():
    global DEPLOYMENT
    with LOCK:
        if DEPLOYMENT is None:
            c=control()
            DEPLOYMENT=DeploymentSettings(ROOT,KEYDIR,busy_fn=lambda:bool(BUSY) or bool(c.busy) or any(j.get('state') not in ('succeeded','failed','needs_review','reviewed') for j in c.jobs.values()),control=c)
        return DEPLOYMENT

def fail2ban_manager():
    global FAIL2BAN
    with LOCK:
        if FAIL2BAN is None:
            FAIL2BAN=Fail2banManager(control(),ROOT/'control-data',busy_fn=lambda sid:any(k[0]==sid for k in BUSY))
        return FAIL2BAN

def control():
    global CONTROL
    with LOCK:
        if CONTROL is None:
            CONTROL=Control(ROOT,servers,KEYDIR,lock=LOCK)
            CONTROL.on_software_change=register_discovered_services
        return CONTROL

def register_discovered_services(sid):
    s=find(sid)
    if not s:return
    inventory=ssh(s,{'action':'inventory'})
    known=('x-ui','telemt','mtproxy','amnezia','awg-quick','zapret','caddy','nginx','fail2ban')
    discovered=[x['unit'] for x in inventory['units'] if any(k in x['unit'] for k in known)]
    with LOCK:
        current=servers();target=next((x for x in current if x['id']==sid),None)
        if target is None:return
        target['services']=list(dict.fromkeys(target['services']+discovered));write_config(current);CACHE.pop(sid,None)

def embedded(port):
    global EMBEDDED
    with LOCK:
        if EMBEDDED is None:EMBEDDED=EmbeddedManager(ROOT,control,panel_tunnel,port)
        return EMBEDDED

def account():
    global ACCOUNT
    with LOCK:
        if ACCOUNT is None:ACCOUNT=Account(KEYDIR)
        return ACCOUNT

def invalidate_account_sessions(rotate_token=True):
    global TOKEN,EMBEDDED
    with LOCK:
        if rotate_token:TOKEN=secrets.token_urlsafe(32)
        old=EMBEDDED;EMBEDDED=None
        if old:old.revoked=True
    if old:threading.Thread(target=old.close,name='revoke-panel-sessions',daemon=True).start()

SECURITY_CONFIG_KEYS = ('security','securityFailedThreshold','securityBanThreshold','securityPacketThreshold','securityConsecutive','securityCooldownMinutes','securityDigestHours')

def security_store():
    global SECURITY
    with LOCK:
        if SECURITY is None:
            path=os.environ.get('DECK_SECURITY_DB') or ROOT/'control-data'/'security.sqlite3'
            SECURITY=SecurityStats(path)
        return SECURITY

def security_updates_watch():
    global SECURITY_UPDATES
    with LOCK:
        if SECURITY_UPDATES is None:
            SECURITY_UPDATES=SecurityUpdateWatch(ROOT/'control-data'/'security-updates',servers,KEYDIR)
        return SECURITY_UPDATES

def security_release_events():
    return publication_events(security_updates_watch().snapshot(),servers(),time.time())

def security_report(hours=24):
    data=security_store().report(servers(),hours)
    notices=alerts_manager().status()
    data['config']={k:notices.get('config',{}).get(k,ALERT_DEFAULT_CONFIG.get(k)) for k in SECURITY_CONFIG_KEYS}
    data['alertStatus']={'connected':bool(notices.get('chat')),'enabled':bool(notices.get('enabled')),
                         'lastError':notices.get('lastError',''),'security':notices.get('security',{}),
                         'botMenuEnabled':bool(notices.get('menu',{}).get('enabled')),
                         'botMenuPublishedAt':notices.get('menu',{}).get('publishedAt')}
    return data

def alerts_manager():
    global ALERTS,BOT_ACTIONS
    with LOCK:
        if ALERTS is None:
            health_fn=lambda:health_store().report([s['id'] for s in servers()],1)
            security_fn=lambda:security_store().alert_summary(servers())
            if BOT_ACTIONS is None:
                BOT_ACTIONS=BotActions(ROOT/'control-data'/'bot-control',control,servers)
            menu=ReadOnlyBotMenu(servers,health_fn,security_fn,origin=public_access.ORIGIN or '',actions_enabled=True)
            ALERTS=AlertManager(ROOT/'control-data'/'alerts',servers,health_fn,token_path=pathlib.Path(os.environ.get('DECK_TELEGRAM_TOKEN_FILE','/var/lib/serverdeck/telegram.token')),security_fn=security_fn,bot_menu=menu,bot_actions=BOT_ACTIONS,security_release_fn=security_release_events)
        return ALERTS

def monitor_loop():
    while not MONITOR_STOP.is_set():
        start=time.monotonic()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda s:refresh(s,True),servers()))
        except Exception as e:print('Monitor:',str(e),flush=True)
        MONITOR_STOP.wait(max(5,60-(time.monotonic()-start)))

def event(server, unit, action, ok):
    row = dict(time=time.time(), server=server, unit=unit, action=action, ok=ok)
    with LOCK:
        HISTORY.insert(0,row); del HISTORY[80:]
    with (ROOT/'activity.jsonl').open('a') as f: f.write(json.dumps(row,ensure_ascii=False)+'\n')

def panel_tunnel(s,panel):
    key=(s['id'],panel['port'],panel.get('scheme','http'),panel.get('path','/'))
    with LOCK:
        previous=TUNNELS.get(key)
        if previous and previous[0].poll() is None: return previous[1]
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        cmd=['ssh','-i',str(KEYDIR/s['key']),'-p',str(s['port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=20','-o','ServerAliveCountMax=3','-N','-L','127.0.0.1:'+str(port)+':127.0.0.1:'+str(panel['port']),s['user']+'@'+s['host']]
        proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(40):
            if proc.poll() is not None: raise RuntimeError('SSH-туннель не запустился')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2): break
            except OSError: time.sleep(.2)
        else:
            proc.terminate();raise RuntimeError('Тайм-аут SSH-туннеля')
        url=panel.get('scheme','http')+'://127.0.0.1:'+str(port)+(panel.get('path') or '/')
        TUNNELS[key]=(proc,url);return url

@atexit.register
def cleanup():
    MONITOR_STOP.set()
    for proc,url in TUNNELS.values():
        if proc.poll() is None: proc.terminate()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, status, data, content='application/json; charset=utf-8'):
        body = json.dumps(data,ensure_ascii=False).encode() if content.startswith('application/json') else data
        self.send_response(status); self.send_header('Content-Type',content); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Referrer-Policy','no-referrer'); self.send_header('X-Frame-Options','DENY'); self.send_header('Content-Security-Policy',public_access.policy()); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def auth(self):
        return self.headers.get('X-Deck-Token') == TOKEN
    def do_GET(self):
        if not public_access.gateway_ok(self.headers) or self.headers.get('Host') not in public_access.hosts(self.server.server_port):
            return self.reply(403,{'error':'Host rejected'})
        if self.path in ('/', '/index.html'):
            return self.reply(200,(ROOT/'static/index.html').read_bytes().replace(b'__TOKEN__',TOKEN.encode()),'text/html; charset=utf-8')
        if self.path in ('/app.js','/account.js','/account.css','/maintenance.js','/health.js','/rf.js','/control.js','/software.js','/software.css','/embedded.js','/embedded.css','/control.css','/style.css','/theme.css','/alerts.js','/alerts.css','/security.js','/security.css','/security-updates.js','/security-updates.css','/outage-diagnostics.js','/outage-diagnostics.css','/fail2ban.js','/fail2ban.css','/deployment-settings.js','/deployment-settings.css'):
            return self.reply(200,(ROOT/'static'/self.path[1:]).read_bytes(),'text/javascript; charset=utf-8' if self.path.endswith('.js') else 'text/css; charset=utf-8')
        if not self.auth(): return self.reply(403,{'error':'Откройте панель заново'})
        if self.path=='/api/deployment':
            try:return self.reply(200,deployment_settings().snapshot())
            except Exception:return self.reply(503,{'error':'Настройки адреса панели временно недоступны'})
        if self.path=='/api/outage-diagnostics':
            try:return self.reply(200,outage_diagnostics().snapshot())
            except Exception:return self.reply(503,{'error':'Диагностика SSH временно недоступна'})
        if urlparse(self.path).path=='/api/fail2ban':
            from urllib.parse import parse_qs
            query=parse_qs(urlparse(self.path).query)
            try:return self.reply(200,fail2ban_manager().snapshot(query.get('server',[None])[0]))
            except ValueError as e:return self.reply(400,{'error':str(e)})
            except Exception:return self.reply(503,{'error':'Не удалось проверить Fail2ban. Настройки не изменялись.'})
        if self.path=='/api/alerts':return self.reply(200,alerts_manager().status())
        if self.path=='/api/security-updates':
            try:return self.reply(200,security_updates_watch().snapshot())
            except Exception:return self.reply(503,{'error':'Проверка обновлений безопасности временно недоступна'})
        if self.path=='/api/account':return self.reply(200,account().status(self.headers.get('X-Deck-User','')))
        if urlparse(self.path).path=='/api/security':
            from urllib.parse import parse_qs
            query=parse_qs(urlparse(self.path).query)
            hours=query.get('hours',['24'])[0]
            if hours not in ('1','24','168'):return self.reply(400,{'error':'Неверный период'})
            try:return self.reply(200,security_report(int(hours)))
            except ValueError as e:return self.reply(503,{'error':str(e)})
        if urlparse(self.path).path.startswith('/api/control'):
            try:
                path=urlparse(self.path).path
                from urllib.parse import parse_qs
                query=parse_qs(urlparse(self.path).query)
                if path=='/api/control':return self.reply(200,control().snapshot())
                if path=='/api/control/clients':return self.reply(200,control().catalog(query.get('force')==['1']))
                if path=='/api/control/updates':return self.reply(200,control().updates(query.get('force')==['1']))
                if path=='/api/control/components':return self.reply(200,{'projects':control().projects.updates(background=True)})
                if path=='/api/control/software':return self.reply(200,control().software(query.get('force')==['1']))
                if path=='/api/control/download':
                    p=control().backup_file(query.get('id',[''])[0]);body=p.read_bytes();name='server-deck-'+p.name
                elif path=='/api/control/recovery-key':
                    body=base64.b64encode(control().vault.key)+b'\n';name='server-deck-recovery.key'
                else:return self.reply(404,{'error':'Не найдено'})
                self.send_response(200);self.send_header('Content-Type','application/octet-stream');self.send_header('Cache-Control','no-store');self.send_header('Content-Disposition','attachment; filename="'+name+'"');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
            except Exception as e:return self.reply(400,{'error':str(e)})
        if self.path == '/api/native-probe':return self.reply(200,native_probe().snapshot())
        if self.path == '/api/cheburcheck':return self.reply(200,cheburcheck().snapshot())
        if urlparse(self.path).path == '/api/health':
            from urllib.parse import parse_qs
            hours=parse_qs(urlparse(self.path).query).get('hours',['24'])[0]
            if hours not in ('1','24','168'):return self.reply(400,{'error':'Неверный период'})
            return self.reply(200,health_store().report([s['id'] for s in servers()],int(hours)))
        if self.path == '/api/state':
            ss=servers()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: results=list(pool.map(refresh,ss))
            return self.reply(200,{'servers':[dict(**s,status=r) for s,r in zip(ss,results)],'activity':HISTORY[:25]})
        if self.path == '/api/keys':
            names=[p.name for p in KEYDIR.iterdir() if p.is_file() and p.name not in ('config','known_hosts','known_hosts.old','authorized_keys') and not p.name.endswith('.pub') and 'PRIVATE KEY' in p.read_text(errors='ignore')[:100]]
            return self.reply(200,{'keys':names})
        return self.reply(404,{'error':'Не найдено'})
    def do_POST(self):
        origin=self.headers.get('Origin')
        expected=public_access.origins(self.server.server_port)
        if not public_access.gateway_ok(self.headers) or not self.auth() or origin not in expected or self.headers.get('Host') not in public_access.hosts(self.server.server_port): return self.reply(403,{'error':'Запрос отклонён'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0 < length < 16384: raise ValueError('Неверный размер запроса')
            d=json.loads(self.rfile.read(length))
            if not isinstance(d,dict):raise ValueError('Ожидается JSON-объект')
            if self.path not in ('/api/deployment/check','/api/account/logout') and (ROOT/'control-data'/'deployment-freeze').exists():
                return self.reply(409,{'error':'Идёт смена адреса панели. Новые изменения приостановлены до проверки результата.'})
            action=d.get('action')
            if self.path=='/api/security-updates' or self.path.startswith('/api/security-updates/'):
                try:
                    if self.path=='/api/security-updates/check':
                        if d:raise ValueError('Проверка не принимает дополнительные параметры')
                        return self.reply(202,security_updates_watch().request_check())
                    if self.path=='/api/security-updates/ack':
                        if set(d)!={'notice'} or not isinstance(d.get('notice'),str):raise ValueError('Укажите идентификатор уведомления')
                        return self.reply(200,security_updates_watch().acknowledge(d['notice']))
                    return self.reply(404,{'error':'Не найдено'})
                except ValueError as e:return self.reply(400,{'error':str(e)})
                except Exception:return self.reply(503,{'error':'Проверка обновлений безопасности временно недоступна'})
            if self.path.startswith('/api/deployment/'):
                try:
                    manager=deployment_settings()
                    if self.path=='/api/deployment/plan':result=manager.plan(d)
                    elif self.path=='/api/deployment/apply':result=manager.apply(d)
                    elif self.path=='/api/deployment/check':
                        if d:raise ValueError('Проверка не принимает дополнительные параметры')
                        result=manager.refresh()
                    else:return self.reply(404,{'error':'Не найдено'})
                    return self.reply(200,result)
                except ValueError as e:return self.reply(400,{'error':str(e)})
                except Exception:return self.reply(503,{'error':'Настройки адреса не удалось проверить; автоматического повтора изменения нет.'})
            if self.path.startswith('/api/fail2ban/'):
                try:
                    manager=fail2ban_manager()
                    if self.path=='/api/fail2ban/plan':result=manager.plan(d)
                    elif self.path=='/api/fail2ban/apply':result=manager.apply(d)
                    elif self.path=='/api/fail2ban/review':result=manager.review(d)
                    else:return self.reply(404,{'error':'Не найдено'})
                    return self.reply(200,result)
                except ValueError as e:return self.reply(400,{'error':str(e)})
                except Exception:return self.reply(503,{'error':'Результат операции Fail2ban требует проверки; автоматического повтора нет.'})
            if self.path=='/api/security/config':
                if not d or set(d)-set(SECURITY_CONFIG_KEYS):raise ValueError('Допустимы только настройки уведомлений о защите')
                alerts_manager().configure(d)
                return self.reply(200,security_report(24))
            if self.path.startswith('/api/alerts/'):
                try:
                    manager=alerts_manager()
                    if self.path=='/api/alerts/config':result=manager.configure(d)
                    elif self.path=='/api/alerts/pair':result=manager.start_pairing()
                    elif self.path=='/api/alerts/cancel':result=manager.cancel_pairing()
                    elif self.path=='/api/alerts/test':result=manager.test()
                    elif self.path=='/api/alerts/menu':result=manager.publish_menu()
                    else:return self.reply(404,{'error':'Не найдено'})
                    return self.reply(200,result)
                except ValueError as e:return self.reply(400,{'error':str(e)})
            if self.path=='/api/account/logout':
                invalidate_account_sessions(rotate_token=False)
                return self.reply(200,{'ok':True})
            if self.path=='/api/account/password':
                try:result=account().change(self.headers.get('X-Deck-User',''),d)
                except AccountError as e:return self.reply(e.status,{'error':str(e)})
                invalidate_account_sessions()
                try:event('Server Deck','Учётная запись','password-change',True)
                except OSError:pass  # A log failure must not misreport a completed password change.
                return self.reply(200,result)
            if self.path=='/api/embedded/open':
                s=find(d.get('server'))
                if not s:raise ValueError('Сервер не найден')
                return self.reply(200,embedded(self.server.server_port).open(s,d.get('panel')))
            if self.path.startswith('/api/control/'):
                c=control()
                if self.path=='/api/control/components/add':return self.reply(200,c.add_component(d))
                if self.path=='/api/control/components/remove':return self.reply(200,c.remove_component(d))
                if self.path=='/api/control/components/bind':return self.reply(200,c.bind_component(d))
                if self.path=='/api/control/execute':
                    with LOCK:
                        plan=c.plans.get(d.get('plan'),{})
                        if any(k[0]==plan.get('server') for k in BUSY):raise ValueError('На сервере выполняется действие со службой')
                        result=c.execute(d.get('plan'),d.get('confirmation'))
                    return self.reply(200,result)
                if self.path=='/api/control/verify':return self.reply(200,c.verify_backup(d.get('backup','')))
                if self.path=='/api/control/acknowledge':return self.reply(200,c.acknowledge(d.get('job'),d.get('confirmation')))
                s=find(d.get('server'))
                if not s:raise ValueError('Сервер не найден')
                with LOCK:
                    if any(k[0]==s['id'] for k in BUSY):raise ValueError('На сервере выполняется действие со службой')
                if self.path=='/api/control/plan':return self.reply(200,c.plan(d))
                if self.path=='/api/control/os-prepare':
                    plan=c.plan(dict(server=s['id'],kind='update',component='os-index',version=''))
                    with LOCK:
                        if any(k[0]==s['id'] for k in BUSY):raise ValueError('На сервере выполняется действие со службой')
                        result=c.execute(plan['id'],s['host'])
                    return self.reply(200,result)
                if self.path=='/api/control/backup':
                    with LOCK:
                        if any(k[0]==s['id'] for k in BUSY):raise ValueError('На сервере выполняется действие со службой')
                        result=c.backup_job(s['id'],d.get('panel'))
                    return self.reply(200,result)
                if self.path=='/api/control/links':return self.reply(200,c.ssh(s,dict(d,op='links')))
                if self.path=='/api/control/recheck':
                    job=c.jobs.get(d.get('job'))
                    if not job or job['server']!=s['id']:raise ValueError('Задача не найдена')
                    threading.Thread(target=c.resume,args=(job['id'],),daemon=True).start();return self.reply(200,{'ok':True})
                raise ValueError('Неизвестное действие')
            if self.path == '/api/keys/generate':return self.reply(200,generate_key(d))
            if self.path == '/api/servers':
                s=valid_server(d)
                # Verify identity and SSH before saving. Unknown host keys must be trusted explicitly outside this app.
                inventory=ssh(s,{'action':'inventory'})
                known=('x-ui','telemt','mtproxy','amnezia','awg-quick','zapret','caddy','nginx','fail2ban')
                s['services']=[x['unit'] for x in inventory['units'] if any(k in x['unit'] for k in known)]
                with LOCK:
                    ss=servers()
                    if any(x['host']==s['host'] and x['port']==s['port'] for x in ss): raise ValueError('Сервер уже добавлен')
                    ss.append(s);write_config(ss)
                return self.reply(200,{'ok':True})
            s=find(d.get('server'))
            if not s: raise ValueError('Сервер не найден')
            if self.path == '/api/cheburcheck':
                cheburcheck().start(s);return self.reply(200,{'started':True})
            if self.path == '/api/native-probe':
                snapshot=refresh(s);data=snapshot.get('data',{})
                ports={s['port']}
                ports.update(data.get('listeningTcp',[]))
                priority=[s['port'],443,8443,4433]
                chosen=[]
                for p in priority+sorted(ports):
                    if p in ports and p not in chosen:chosen.append(p)
                tls={p['port']:p for p in data.get('panels',[]) if p.get('scheme')=='https' and p.get('port') in ports}
                targets=[dict(port=p,tls=p in tls or p==443,sni=tls.get(p,{}).get('domain') or s['host']) for p in chosen[:6]]
                native_probe().start(s,targets,d.get('interface','en0'));return self.reply(200,{'started':True})
            if self.path == '/api/refresh': return self.reply(200,refresh(s,True))
            if self.path == '/api/inventory': return self.reply(200,ssh(s,{'action':'inventory'}))
            if self.path == '/api/panels':
                name=str(d.get('name','')).strip()[:80]
                if not name: raise ValueError('Укажите название панели')
                if d.get('kind')=='tunnel':
                    port=int(d.get('port',0));scheme=d.get('scheme','http');path=d.get('path','/')
                    if not 1<=port<=65535 or scheme not in ('http','https') or not path.startswith('/') or len(path)>300:raise ValueError('Проверьте порт, протокол и путь')
                    panel=dict(name=name,port=port,scheme=scheme,path=path,localOnly=True)
                else:
                    url=str(d.get('url','')).strip();parsed=urlparse(url)
                    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:raise ValueError('Укажите HTTP(S)-адрес без логина и пароля')
                    panel=dict(name=name,url=url)
                with LOCK:
                    ss=servers();target=next(x for x in ss if x['id']==s['id']);items=target.setdefault('panels',[])
                    if any(p['name']==name for p in items):raise ValueError('Панель с таким названием уже есть')
                    items.append(panel);write_config(ss);CACHE.pop(s['id'],None)
                return self.reply(200,{'ok':True})
            if self.path == '/api/panel':
                snapshot=refresh(s)
                panel=next((p for p in snapshot.get('data',{}).get('panels',[]) if p['name']==d.get('panel')),None)
                if not panel or not panel.get('localOnly'): raise ValueError('Локальная панель не найдена')
                return self.reply(200,{'url':panel_tunnel(s,panel),'https':panel.get('scheme')=='https'})
            unit=d.get('unit','')
            docker=bool(re.fullmatch(r'docker:[0-9a-f]{12,64}',unit))
            if not docker and not re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service',unit): raise ValueError('Неверное имя службы')
            if self.path == '/api/services':
                available=ssh(s,{'action':'inventory'})
                if unit not in [x['unit'] for x in available['units']]: raise ValueError('Служба не установлена на сервере')
                with LOCK:
                    ss=servers();target=next(x for x in ss if x['id']==s['id'])
                    if unit not in target['services']: target['services'].append(unit)
                    write_config(ss);CACHE.pop(s['id'],None)
                return self.reply(200,{'ok':True})
            allowed=s['services']
            if docker:
                snapshot=refresh(s)
                allowed=[x['unit'] for x in snapshot.get('data',{}).get('containers',[])]
            if self.path != '/api/action' or action not in ('start','stop','restart','logs') or unit not in allowed: raise ValueError('Действие не разрешено')
            key=(s['id'],unit)
            with LOCK:
                c=control()
                if s['id'] in c.busy:raise ValueError('На сервере выполняется задача центра управления')
                if key in BUSY: raise ValueError('Действие для этой службы уже выполняется')
                BUSY.add(key)
                # Share the same host reservation with durable control jobs and
                # Telegram confirmations. Logs are read-only but still avoid a
                # concurrent mutation while this request is in flight.
                c.busy.add(s['id'])
            try:
                result=ssh(s,{'action':action,'unit':unit})
                if action!='logs': event(s['name'],unit,action,result.get('ok',False))
                with LOCK: CACHE.pop(s['id'],None)
                return self.reply(200,result)
            finally:
                with LOCK: BUSY.discard(key);c.busy.discard(s['id'])
        except Exception as e: return self.reply(400,{'error':str(e)})

if __name__=='__main__':
    os.umask(0o077)
    signal.signal(signal.SIGTERM,lambda signum,frame:exit(0))
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8765);args=parser.parse_args()
    if not CONFIG.exists(): write_config(DEFAULTS)
    history_file=ROOT/'activity.jsonl'
    if history_file.exists():
        for line in reversed(history_file.read_text().splitlines()[-80:]):
            try: HISTORY.append(json.loads(line))
            except ValueError: pass
    httpd=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    public_access.start_router(servers,lambda:EMBEDDED)
    fail2ban_manager()  # Restore reservations for uncertain Fail2ban operations before accepting actions.
    threading.Thread(target=lambda:outage_diagnostics().run(MONITOR_STOP),name='outage-diagnostics',daemon=True).start()
    threading.Thread(target=monitor_loop,name='health-monitor',daemon=True).start()
    threading.Thread(target=lambda:alerts_manager().run(MONITOR_STOP),name='telegram-alerts',daemon=True).start()
    threading.Thread(target=lambda:security_updates_watch().run(MONITOR_STOP),name='security-update-watch',daemon=True).start()
    print('Server Deck: http://127.0.0.1:'+str(args.port),flush=True)
    httpd.serve_forever()
