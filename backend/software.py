"""Curated software recipes. No arbitrary command or installer URL from the UI."""
import hashlib, json, re, urllib.request

COMPONENTS = [
    dict(id='lucx', name='LucX / 3x-ui', icon='3X', category='Панели', description='Панель Xray и VPN. Установка на свободный хост или обновление существующей LucX.', repo='AlexeyLCP/lucx-ui', port=2053),
    dict(id='mtproxyl', name='MTProxyL', icon='TG', category='Прокси', description='Менеджер Telegram-прокси с движком Telemt. Новая установка без Zapret2 и системного тюнинга.', repo='Liafanx/MTProxyL', port=4433),
    dict(id='mtproxyl-panel', name='Веб-панель MTProxyL', icon='▤', category='Панели', description='Штатный интерфейс установленного MTProxyL. Новая панель доступна через SSH внутри Server Deck.', repo='Liafanx/MTProxyL', port=10443),
    dict(id='telemt', name='Движок Telemt', icon='↗', category='Прокси', description='Обновление движка существующего MTProxyL и возврат к сохранённой версии.', repo='telemt/telemt'),
    dict(id='awg', name='AmneziaWG', icon='⌁', category='VPN', description='Модуль и инструменты AWG. Обслуживание разрешено только без AWG-интерфейсов и контейнеров.', repo='AlexeyLCP/lucx-ui'),
    dict(id='fail2ban', name='Fail2ban', icon='◇', category='Система', description='Установка и обновление пакета из репозитория ОС. Существующие правила сохраняются.'),
]

def get_json(url):
    req=urllib.request.Request(url,headers={'Accept':'application/vnd.github+json','User-Agent':'Server-Deck-Local'})
    with urllib.request.urlopen(req,timeout=25) as r:return json.load(r)

def source_file(repo,commit,path):
    url='https://raw.githubusercontent.com/'+repo+'/'+commit+'/'+path
    with urllib.request.urlopen(url,timeout=25) as r:data=r.read(4*1024*1024+1)
    if len(data)>4*1024*1024:raise ValueError('Файл рецепта слишком большой')
    return dict(url=url,sha256=hashlib.sha256(data).hexdigest(),size=len(data))

def prepare_sources(component,version,arch):
    """Only published releases, exact asset digests and immutable source refs."""
    if component not in ('lucx','mtproxyl','mtproxyl-panel','awg'):return {}
    if arch not in ('x86_64','aarch64'):raise ValueError('Поддерживаются x86_64 и aarch64')
    repo='AlexeyLCP/lucx-ui' if component in ('lucx','awg') else 'Liafanx/MTProxyL'
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',version):raise ValueError('Неверный релиз')
    release=get_json('https://api.github.com/repos/'+repo+'/releases/tags/'+version)
    if release.get('draft') or release.get('prerelease') or release.get('tag_name')!=version:raise ValueError('Нужен опубликованный стабильный релиз')
    commit=get_json('https://api.github.com/repos/'+repo+'/commits/'+version)['sha']
    if not re.fullmatch(r'[a-f0-9]{40}',commit):raise ValueError('Не подтверждён commit релиза')
    result=dict(repo=repo,commit=commit,version=version)
    if component in ('lucx','mtproxyl-panel'):
        name=('x-ui-linux-'+('amd64' if arch=='x86_64' else 'arm64')+'.tar.gz') if component=='lucx' else 'mtproxyl-panel-'+arch+'-linux-gnu.tar.gz'
        asset=next((a for a in release.get('assets',[]) if a['name']==name),None)
        if not asset or not re.fullmatch(r'sha256:[a-f0-9]{64}',asset.get('digest') or ''):raise ValueError('В GitHub нет подтверждённой SHA-256 суммы нужной сборки')
        expected='https://github.com/'+repo+'/releases/download/'+version+'/'+name
        if asset['browser_download_url']!=expected:raise ValueError('Неожиданный адрес сборки')
        result['archive']=dict(url=expected,sha256=asset['digest'][7:],size=asset['size'])
        if component=='lucx':
            result['unit']=source_file(repo,commit,'x-ui.service.debian')
            result['cli']=source_file(repo,commit,'x-ui.sh')
        else:result['installer']=source_file(repo,commit,'mtproxyl-panel/install.sh')
    elif component=='mtproxyl':
        result['installer']=source_file(repo,commit,'install.sh')
    else:result['installer']=source_file(repo,commit,'bin/install-awg-module.sh')
    reviewed={('mtproxyl','v1.7.17'):'26008d2baceb7d89e60904e1d8a26572a02857497d382cb3ac97eeed15ca1418',('mtproxyl-panel','mtproxyl-panel-v1.3.13'):'90a1ec3071ca46d71f411d64a088960d5525d16fb69001657024110df0bd07fd',('awg','v3.11.0-lucx.332'):'b7ea9ba3e571a16466842b31130d52b2ccdf40683cd76e566934fda465001731'}
    expected=reviewed.get((component,version))
    if expected and result['installer']['sha256']!=expected:raise ValueError('Установщик изменился после проверки рецепта. Автоматический запуск запрещён.')
    return result
