"""Create a short-lived UI session on the VPS; never export passwords/signing keys."""
import base64, hashlib, hmac, http.client, http.cookies, json, pathlib, re, secrets, shlex, sqlite3, ssl, subprocess, time
from panel_tls import pinned_https_connection

def b64(data):return base64.urlsafe_b64encode(data).decode().rstrip('=')

def panel_credentials(paths=None):
    # A dedicated integration account takes precedence; the installer's
    # credentials remain the fallback for existing installations.
    for path in paths or ('/etc/x-ui/server-deck.env','/etc/x-ui/install-result.env'):
        p=pathlib.Path(path)
        if not p.is_file():continue
        env={}
        for line in p.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith('#'):continue
            k,sep,v=line.partition('=')
            if sep:
                parts=shlex.split(v);env[k]=parts[0] if parts else ''
        return env
    raise ValueError('3x-ui: не настроены учётные данные для встроенного входа')

def setup(panel):
    if panel=='lucx':
        with sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro',uri=True) as db:s=dict(db.execute('select key,value from settings'))
        env=panel_credentials()
        if not env.get('XUI_USERNAME') or not env.get('XUI_PASSWORD'):
            raise ValueError('3x-ui: в сохранённых учётных данных отсутствует логин или пароль')
        port=int(s.get('webPort',2053));base=s.get('webBasePath','/');cert=s.get('webCertFile','');cookies={}
        def request(path,data=None):
            if cert:
                conn=pinned_https_connection('127.0.0.1',port,pathlib.Path(cert).read_text(),timeout=15)
            else:conn=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
            headers={'Cookie':'; '.join(k+'='+v for k,v in cookies.items()),'X-Requested-With':'XMLHttpRequest'}
            if data is not None:headers.update({'Content-Type':'application/json','X-CSRF-Token':csrf})
            conn.request('POST' if data is not None else 'GET',base.rstrip('/')+path,json.dumps(data).encode() if data is not None else None,headers)
            response=conn.getresponse();body=response.read(1048576)
            for key,value in response.getheaders():
                if key.lower()=='set-cookie':
                    parsed=http.cookies.SimpleCookie();parsed.load(value)
                    for name,morsel in parsed.items():cookies[name]=morsel.value
            status=response.status;conn.close()
            if status!=200:raise ValueError('LucX: не удалось создать серверную сессию (HTTP '+str(status)+')')
            return json.loads(body)
        value=request('/csrf-token');csrf=value.get('obj')
        if not value.get('success') or not csrf:raise ValueError('LucX: CSRF-сессия не создана')
        enabled=request('/getTwoFactorEnable',{})
        if enabled.get('obj') is True:raise ValueError('На LucX включена 2FA. Автоматический вход не выполняется; требуется штатный вход с кодом.')
        value=request('/login',{'username':env.get('XUI_USERNAME',''),'password':env.get('XUI_PASSWORD','')})
        if not value.get('success'):raise ValueError('Сохранённые учётные данные LucX не подходят. Повторных попыток входа нет.')
        return {'panel':panel,'port':port,'base':base,'entry':base.rstrip('/')+'/panel/','scheme':'https' if cert else 'http','certificate':pathlib.Path(cert).read_text() if cert else '', 'cookies':cookies,'expiresAt':time.time()+4*3600}
    if panel=='mtproxyl':
        import tomllib
        proc=subprocess.run(['systemctl','show','mtproxyl-panel.service','--property=MainPID','--value'],capture_output=True,text=True,timeout=8)
        pid=int(proc.stdout.strip());args=pathlib.Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0');args=[x.decode() for x in args if x]
        config='/etc/mtproxyl-panel/config.toml'
        for i,arg in enumerate(args):
            if arg in ('--config','-config') and i+1<len(args):config=args[i+1]
            if arg.startswith('--config='):config=arg.split('=',1)[1]
        with open(config,'rb') as f:cfg=tomllib.load(f)
        auth=cfg.get('auth',{});username=auth.get('username');key=auth.get('jwt_secret')
        if not username or not key:raise ValueError('MTProxyL: конфигурация авторизации не найдена')
        now=int(time.time());header=b64(b'{"alg":"HS256","typ":"JWT"}');payload=b64(json.dumps({'sub':username,'iat':now,'exp':now+300},separators=(',',':')).encode());signed=header+'.'+payload
        token=signed+'.'+b64(hmac.new(key.encode(),signed.encode(),hashlib.sha256).digest())
        listen=cfg.get('listen',':8080');port=int(listen.rsplit(':',1)[1]);base=cfg.get('base_path','/') or '/'
        if not base.startswith('/'):base='/'+base
        if not base.endswith('/'):base+='/'
        cert=cfg.get('tls',{}).get('cert_file','')
        return {'panel':panel,'port':port,'base':base,'entry':base,'scheme':'https' if cert else 'http','certificate':pathlib.Path(cert).read_text() if cert else '', 'cookies':{'session':token},'expiresAt':now+290}
    raise ValueError('Для этой панели пока нет адаптера встроенного входа')

if __name__=='__main__':
    try:print(json.dumps({'ok':True,'data':setup(_DECK_REQUEST['panel'])}))
    except Exception as e:
        message=str(e) if isinstance(e,ValueError) else type(e).__name__+': не удалось подключить панель'
        print(json.dumps({'ok':False,'error':message}))
