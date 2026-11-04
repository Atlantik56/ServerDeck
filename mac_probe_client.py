"""Optional Mac measurement point, reachable only over a loopback SSH reverse tunnel."""
import json, os, pathlib, urllib.request, urllib.error

class MacProbeClient:
    def __init__(self,path):
        self.path=pathlib.Path(path)
        self.token=os.environ['DECK_MAC_PROBE_TOKEN']
    def request(self,path,data=None):
        request=urllib.request.Request('http://127.0.0.1:18767'+path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={'X-Deck-Probe':self.token,'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(request,timeout=6) as response:return json.load(response)
        except urllib.error.HTTPError as e:
            raise ValueError('Точка Mac отклонила запрос: '+str(e.code))
    def snapshot(self):
        try:
            result=self.request('/snapshot');result.update(available=True,reason='Временная точка Mac подключена через SSH. Измерение запускается по кнопке или автоматически при потере SSH.')
            return result
        except (OSError,ValueError):
            try:reports=json.loads(self.path.read_text())
            except (OSError,ValueError):reports={}
            return dict(servers=reports,busy=False,automatic=False,available=False,reason='Временная точка Mac сейчас недоступна. Cheburcheck работает независимо от неё.')
    def start(self,server,targets,interface='en0'):
        try:return self.request('/start',dict(server={'id':server['id'],'host':server['host']},targets=targets,interface=interface))
        except OSError:raise ValueError('Точка Mac недоступна. Включите Mac и проверьте его SSH-соединение с сервером управления.')
