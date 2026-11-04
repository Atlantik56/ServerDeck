"""One-shot root helper installed outside the app's writable directory.

Only the Caddy account hash is changed. Passwords arrive on stdin, never argv.
No CLI option can override paths, commands or target accounts storage.
"""
import fcntl,hmac,json,os,pathlib,re,subprocess,sys,tempfile

ACCOUNTS=pathlib.Path('/etc/caddy/server-deck-accounts')
CONFIG=pathlib.Path('/etc/caddy/Caddyfile')
LOCK=pathlib.Path('/run/lock/server-deck-password.lock')
ACCOUNT_SELECTOR=pathlib.Path('/etc/server-deck/auth-account-path')
ACCOUNT_PATHS={str(ACCOUNTS),'/etc/caddy/server-deck-accounts.d/accounts'}
USER=re.compile(r'[A-Za-z0-9_.@-]{1,64}')
HASH=re.compile(r'\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}')

class ChangeError(Exception):
    def __init__(self,code):self.code=code;super().__init__(code)

def validate(data):
    if not isinstance(data,dict):raise ChangeError('invalid')
    user=data.get('username');current=data.get('currentPassword');new=data.get('newPassword');confirm=data.get('confirmPassword')
    if not isinstance(user,str) or not USER.fullmatch(user):raise ChangeError('identity')
    if not all(isinstance(x,str) for x in (current,new,confirm)):raise ChangeError('invalid')
    if not current or len(current.encode())>512 or any(c in current for c in '\x00\r\n'):raise ChangeError('current')
    if len(new)<12 or len(new.encode())>72 or any(c in new for c in '\x00\r\n'):raise ChangeError('policy')
    if new!=confirm:raise ChangeError('confirmation')
    if hmac.compare_digest(current.encode(),new.encode()):raise ChangeError('same')
    return user,current,new

def verify(password,hashed):
    import crypt
    result=crypt.crypt(password,hashed)
    return bool(result and hmac.compare_digest(result,hashed))

def hash_password(password):
    import crypt
    if crypt.METHOD_BLOWFISH not in crypt.methods:raise ChangeError('unavailable')
    result=crypt.crypt(password,crypt.mksalt(crypt.METHOD_BLOWFISH,rounds=4096))
    if not HASH.fullmatch(result or ''):raise ChangeError('unavailable')
    return result

def account_hash(text,user):
    rows=[]
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        parts=line.split()
        if len(parts)!=2 or not USER.fullmatch(parts[0]) or not HASH.fullmatch(parts[1]):raise ChangeError('configuration')
        rows.append(parts)
    matching=[x for x in rows if x[0]==user]
    if len(matching)!=1:raise ChangeError('identity')
    return matching[0][1]

def replace_hash(text,user,new):
    return re.sub(r'(?m)^(\s*'+re.escape(user)+r'\s+)\S+(\s*)$',lambda m:m.group(1)+new+m.group(2),text,count=1)

def atomic(path,data,uid,gid):
    fd,name=tempfile.mkstemp(prefix='.deck-account-',dir=str(path.parent))
    try:
        os.fchmod(fd,0o640);os.fchown(fd,uid,gid)
        with os.fdopen(fd,'w') as out:out.write(data);out.flush();os.fsync(out.fileno())
        os.replace(name,path)
        directory=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)

def caddy(action,config):
    try:
        p=subprocess.run(['/usr/bin/caddy',action,'--config',str(config),'--adapter','caddyfile'],capture_output=True,timeout=20)
        return p.returncode==0
    except (OSError,subprocess.TimeoutExpired):return False

def change(data,accounts=ACCOUNTS,config=CONFIG,lock=LOCK):
    user,current,new=validate(data)
    with lock.open('a') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX)
        stat=accounts.stat();old=accounts.read_text();hashed=account_hash(old,user)
        if not verify(current,hashed):raise ChangeError('current')
        updated=replace_hash(old,user,hash_password(new))
        atomic(accounts,updated,stat.st_uid,stat.st_gid)
        if not caddy('validate',config):
            atomic(accounts,old,stat.st_uid,stat.st_gid)
            raise ChangeError('validate')
        if not caddy('reload',config):
            atomic(accounts,old,stat.st_uid,stat.st_gid)
            if not caddy('reload',config):raise ChangeError('uncertain')
            raise ChangeError('reload')
        return {'ok':True,'username':user,'reauthenticate':True}

def configured_accounts(selector=ACCOUNT_SELECTOR):
    # No caller-supplied path is accepted by the fixed SSH helper.
    if not selector.exists() and not selector.is_symlink():return ACCOUNTS
    stat=selector.lstat()
    if selector.is_symlink() or stat.st_uid!=0 or stat.st_mode&0o022 or stat.st_size>256:
        raise ChangeError('configuration')
    selected=selector.read_text().strip()
    if selected not in ACCOUNT_PATHS:raise ChangeError('configuration')
    return pathlib.Path(selected)

def main():
    os.umask(0o077)
    try:
        if os.geteuid()!=0 or len(sys.argv)!=1:raise ChangeError('unavailable')
        body=sys.stdin.buffer.read(8193)
        if len(body)>8192:raise ChangeError('invalid')
        data=json.loads(body)
        result=change(data,accounts=configured_accounts())
    except ChangeError as e:result={'ok':False,'code':e.code}
    except Exception:result={'ok':False,'code':'unavailable'}
    print(json.dumps(result))

if __name__=='__main__':main()
