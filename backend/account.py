"""Account settings for the authenticated Caddy user, via a fixed SSH helper."""
import json,os,pathlib,re,subprocess,threading,time
from account_helper import validate,ChangeError

MESSAGES={
 'invalid':'Проверьте поля формы.', 'identity':'Не удалось определить текущую учётную запись.',
 'current':'Текущий пароль неверен.', 'policy':'Новый пароль: минимум 12 символов и максимум 72 байта UTF-8, без переноса строки.',
 'confirmation':'Новые пароли не совпадают.', 'same':'Новый пароль должен отличаться от текущего.',
 'configuration':'Настройки авторизации требуют проверки администратором.',
 'unavailable':'Смена пароля сейчас недоступна. Попробуйте позже.',
 'validate':'Новые настройки не прошли проверку. Прежний пароль сохранён.',
 'reload':'Не удалось применить смену пароля. Прежний пароль восстановлен.',
 'uncertain':'Не удалось подтвердить результат. Проверьте вход с новым паролем; автоматического повтора нет.',
}
class AccountError(ValueError):
    def __init__(self,code,status=400):super().__init__(MESSAGES.get(code,code));self.status=status

class Account:
    def __init__(self,keydir):
        self.keydir=pathlib.Path(keydir);self.host=os.environ.get('DECK_ACCOUNT_SSH_HOST','');self.key=os.environ.get('DECK_ACCOUNT_SSH_KEY','')
        try:self.port=int(os.environ.get('DECK_ACCOUNT_SSH_PORT','22'))
        except (ValueError,TypeError):self.port=0
        self.lock=threading.Lock();self.attempts=[]
    def available(self):
        return bool(1<=self.port<=65535 and re.fullmatch(r'[A-Za-z0-9.-]{1,253}',self.host) and re.fullmatch(r'[A-Za-z0-9_.-]{1,160}',self.key) and self.key not in ('.','..') and (self.keydir/self.key).is_file())
    def status(self,user):
        return {'username':user,'canChangePassword':bool(user and self.available()),'minLength':12,'maxBytes':72}
    def change(self,user,data):
        request={k:data.get(k) for k in ('currentPassword','newPassword','confirmPassword')};request['username']=user
        try:validate(request)
        except ChangeError as e:raise AccountError(e.code) from None
        if not self.available():raise AccountError('unavailable',503)
        if not self.lock.acquire(blocking=False):raise AccountError('Смена пароля уже выполняется.',409)
        try:
            now=time.monotonic();self.attempts=[t for t in self.attempts if now-t<300]
            if len(self.attempts)>=5:raise AccountError('Слишком много попыток. Повторите через 5 минут.',429)
            self.attempts.append(now)
            command=['ssh','-i',str(self.keydir/self.key),'-p',str(self.port),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','root@'+self.host,'/usr/bin/python3 -I /usr/local/lib/server-deck/account_helper.py']
            try:
                p=subprocess.run(command,input=json.dumps(request).encode(),capture_output=True,timeout=65)
                if p.returncode:raise AccountError('uncertain',503)
                result=json.loads(p.stdout)
            except (subprocess.TimeoutExpired,OSError,ValueError) as e:
                if isinstance(e,AccountError):raise
                raise AccountError('uncertain',503) from None
            if result.get('ok') is not True:raise AccountError(result.get('code','unavailable'))
            self.attempts.clear()
            return {'ok':True,'username':user,'reauthenticate':True}
        finally:self.lock.release()
