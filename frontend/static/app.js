const $=s=>document.querySelector(s), token=$('meta[name="deck-token"]').content;
let state={servers:[],activity:[]}, filter='all', updating=false;
let serverWorkspace=null, restoreWorkspaceOnLoad=true;
const serverSections=new Map([
 ['overview',['Обзор','server']], ['services',['Службы','activity']],
 ['panels',['Панели','app']], ['awg',['AmneziaWG','network']],
 ['clients',['Клиенты','terminal']], ['backups',['Копии','download']],
 ['updates',['Обновления','upload']], ['history',['История','logs']]
]);
const parentServerSection=section=>({software:'updates',native:'panels'}[section]||section);
const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const bytes=n=>{n=Number(n)||0;return n>=1073741824?(n/1073741824).toFixed(1)+' ГБ':n>=1048576?(n/1048576).toFixed(1)+' МБ':n>=1024?(n/1024).toFixed(0)+' КБ':n+' Б'};
const clock=t=>new Date(t*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:'Europe/Moscow'});
const titles={'x-ui.service':'3x-ui / LucX','telemt.service':'MTProto · Telemt','mtproxyl-panel.service':'MTProxyL · панель','mtproxyl-zapret2.service':'Zapret2 · MTProto fix','caddy.service':'Caddy · HTTPS','fail2ban.service':'Fail2ban'};
const stateNames={active:'Работает',inactive:'Остановлен',failed:'Ошибка',activating:'Запускается',deactivating:'Останавливается'};
async function api(path,data){if(window.accountReauthRequired)throw Error('Войдите в Server Deck с новым паролем.');const opts={headers:{'X-Deck-Token':token}};if(data){opts.method='POST';opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(data)}const r=await fetch(path,opts);if(r.status===401){window.accountReauthRequired=true;window.location.assign('/login/');throw Error('Войдите в Server Deck заново.');}const j=await r.json();if(!r.ok)throw Error(j.error||'Ошибка запроса');return j}
function toast(text){$('#toast').textContent=text;$('#toast').classList.add('show');clearTimeout(toast.timer);toast.timer=setTimeout(()=>$('#toast').classList.remove('show'),6500)}
function modal(title,html){$('#modalTitle').textContent=title;$('#modalBody').innerHTML=html;if(!$('#modal').open)$('#modal').showModal()}
$('#closeModal').onclick=()=>$('#modal').close();$('#modal').addEventListener('click',e=>{if(e.target===$('#modal')){const b=$('#modal').getBoundingClientRect();if(e.clientX<b.left||e.clientX>b.right||e.clientY<b.top||e.clientY>b.bottom)$('#modal').close()}});
// Local, immutable SVG primitives; dynamic labels are escaped separately.
const uiIcons=Object.freeze({
 server:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6"/>',
 cpu:'<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 1v5m6-5v5M9 18v5m6-5v5M1 9h5m-5 6h5m12-6h5m-5 6h5"/>',
 memory:'<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M7 10v4m5-4v4m5-4v4M7 18v3m5-3v3m5-3v3"/>',
 disk:'<path d="m5 4-3 12v3a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-3L19 4Z"/><path d="M2 16h20m-5 3h.01M5 4h14"/>',
 activity:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
 network:'<rect x="8" y="2" width="8" height="6" rx="1"/><rect x="2" y="16" width="7" height="6" rx="1"/><rect x="15" y="16" width="7" height="6" rx="1"/><path d="M12 8v4m-6 4v-4h12v4"/>',
 clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
 refresh:'<use href="#deck-icon-refresh"/>',
 user:'<circle cx="12" cy="8" r="3.5"/><path d="M4.5 21v-2a5 5 0 0 1 5-5h5a5 5 0 0 1 5 5v2"/>',
 send:'<path d="m21 3-6.5 18-3.6-7.9L3 9.5 21 3Zm0 0L10.9 13.1"/>',
 power:'<path d="M12 2v10m-6-8a9 9 0 1 0 12 0"/>',
 download:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/>',
 upload:'<path d="M12 16V4m-5 5 5-5 5 5M4 16v4h16v-4"/>',
 logs:'<path d="M8 5h13M8 12h13M8 19h13M3 5h.01M3 12h.01M3 19h.01"/>',
 play:'<path d="m8 4 12 8-12 8Z"/>',
 stop:'<rect x="5" y="5" width="14" height="14" rx="2"/>',
 app:'<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M3 9h18M9 9v12M6 6h.01M9 6h.01"/>',
 external:'<path d="M14 3h7v7m0-7L10 14M11 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-6"/>',
 plus:'<path d="M12 5v14M5 12h14"/>',
 chevron:'<path d="m9 5 7 7-7 7"/>',
 terminal:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 8 4 4-4 4m6 0h4"/>',
 check:'<path d="m5 12 4 4L19 6"/>',
 alert:'<path d="m12 3 10 18H2Z"/><path d="M12 9v4m0 4h.01"/>',
 container:'<path d="m12 2 9 5v10l-9 5-9-5V7Zm-9 5 9 5 9-5M12 12v10M7.5 4.5l9 5"/>',
 link:'<path d="m10 13 4-4m-6 6-2 2a4 4 0 0 1-6-6l5-5a4 4 0 0 1 6 0m2 3 2-2a4 4 0 0 1 6 6l-5 5a4 4 0 0 1-6 0"/>'
});
function icon(name){const drawing=Object.prototype.hasOwnProperty.call(uiIcons,name)?uiIcons[name]:uiIcons.server;return `<svg class="ui-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${drawing}</svg>`}
const knownNumber=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0;
const presentationInitialState=state;
function formatUptime(value){if(!knownNumber(value))return '—';const days=Math.floor(value/86400),hours=Math.floor(value%86400/3600),minutes=Math.floor(value%3600/60);return days?`${days} д ${hours} ч`:hours?`${hours} ч ${minutes} мин`:`${minutes} мин`}
function metric(label,value,percent,options={}){const known=knownNumber(percent),width=known?Math.max(0,Math.min(100,percent)):null;return `<div class="resource-metric ${known?'':'metric-empty'}"><div class="metric-head"><span class="metric-label">${icon(options.icon||'activity')}${esc(label)}</span></div><div class="metric-value mono">${esc(value??'—')}</div><div class="metric-note">${esc(options.note||'Нет данных')}</div><div class="bar" aria-hidden="true">${known?`<div style="width:${width}%"></div>`:''}</div></div>`}
function serviceRow(s,v){const active=v.state==='active',exists=v.loaded,unknown=v.collectionOk===false||!['active','inactive','failed','activating','deactivating','reloading'].includes(v.state),kind=unknown?'unknown':active?'active':v.state==='failed'?'failed':'inactive',label=unknown?'Нет данных':exists?(stateNames[v.state]||v.state):'Не установлена',name=v.name?'Docker · '+v.name:titles[v.unit]||String(v.unit||'Служба').replace(/\.service$/,'');return `<div class="service-row"><div class="service-info"><div class="service-title"><span class="status-dot ${kind==='active'?'':kind==='failed'?'failed':'inactive'}" aria-hidden="true"></span><span class="service-name">${esc(name)}</span><span class="service-state-chip state-${kind}">${esc(label)}</span></div><div class="service-meta mono">${esc(v.image||v.unit||'—')}${v.awg?`<span class="service-awg-meta">${v.awg.collectionOk===true?Array.isArray(v.awg.interfaces)&&v.awg.interfaces.length?'AWG · '+esc(v.awg.interfaces.join(', ')):'AWG · интерфейс не найден':'AWG · нет данных проверки'}</span>`:''}</div></div><div class="service-actions">${exists?`<button class="small-btn" title="Журнал" aria-label="Журнал ${esc(v.unit)}" data-action="logs" data-server="${esc(s.id)}" data-unit="${esc(v.unit)}">${icon('logs')}</button><button class="small-btn ${active?'mutating-button':''}" title="${active?'Перезапустить':'Запустить'}" aria-label="${active?'Перезапустить':'Запустить'} ${esc(v.unit)}" data-action="${active?'restart':'start'}" data-server="${esc(s.id)}" data-unit="${esc(v.unit)}">${icon(active?'refresh':'play')}</button>${active?`<button class="small-btn stop" title="Остановить" aria-label="Остановить ${esc(v.unit)}" data-action="stop" data-server="${esc(s.id)}" data-unit="${esc(v.unit)}">${icon('stop')}</button>`:''}`:''}</div></div>`}
function containerRows(s,items,expanded){const active=items.filter(x=>x.state==='active'),others=items.filter(x=>x.state!=='active');return active.map(v=>serviceRow(s,v)).join('')+(others.length?`<details class="stopped" data-server-detail="${esc(s.id)}:containers"${expanded?' open':''}><summary>Другие состояния контейнеров <span class="mono">${others.length}</span></summary>${others.map(v=>serviceRow(s,v)).join('')}</details>`:'')}
function vpn(v,collectionOk=true){const latest=knownNumber(v.latestHandshake)?v.latestHandshake:null,age=latest?Math.max(0,Math.floor(Date.now()/1000-latest)):null,handshake=!collectionOk||latest===null?'Нет данных':latest===0?'Ещё не было':age<60?age+' с назад':age<3600?Math.floor(age/60)+' мин назад':age<86400?Math.floor(age/3600)+' ч назад':Math.floor(age/86400)+' д назад',online=collectionOk&&knownNumber(v.online)&&knownNumber(v.peers)?v.online+' / '+v.peers:'—',port=/^\d+$/.test(String(v.port??''))&&Number(v.port)>0&&Number(v.port)<65536?String(v.port):'—',errors=knownNumber(v.counters?.rx_errors)?v.counters.rx_errors:null;return `<div class="vpn-box"><div class="vpn-title"><div class="vpn-interface">${icon('network')}<strong class="mono">${esc(v.interface||'AWG')}</strong><span class="vpn-port mono">UDP ${esc(port)}</span></div><span class="service-state-chip ${collectionOk?'state-active':'state-unknown'}">${collectionOk?'Интерфейс обнаружен':'Неполная проверка'}</span></div><div class="vpn-details"><div class="vpn-stat"><span class="vpn-stat-label">${icon('download')}Получено</span><strong class="mono">${collectionOk&&knownNumber(v.rx)?bytes(v.rx):'—'}</strong></div><div class="vpn-stat"><span class="vpn-stat-label">${icon('upload')}Отправлено</span><strong class="mono">${collectionOk&&knownNumber(v.tx)?bytes(v.tx):'—'}</strong></div><div class="vpn-stat"><span class="vpn-stat-label">Peers · handshake &lt; 3 мин</span><strong class="mono">${esc(online)}</strong></div><div class="vpn-stat vpn-stat-handshake"><span class="vpn-stat-label">Последний handshake</span><strong class="mono">${esc(handshake)}</strong></div></div>${errors>0?`<p class="vpn-warning">${icon('alert')}RX errors: <strong class="mono">${esc(errors)}</strong><span>накопительный счётчик</span></p>`:''}</div>`}
function panelLink(s,p){const embeddedKind=p.name==='3x-ui / LucX'?'lucx':p.name==='MTProxyL'?'mtproxyl':null;if(embeddedKind)return `<button class="panel-link" data-embed-panel="${embeddedKind}" data-server="${esc(s.id)}"><span class="panel-link-label">Открыть ${esc(p.name)}</span><span class="panel-link-icon">${icon('app')}</span></button>`;if(p.url&&/^https?:\/\//.test(p.url))return `<a class="panel-link" href="${esc(p.url)}" target="_blank" rel="noopener noreferrer"><span class="panel-link-label">${esc(p.name)}</span><span class="panel-link-icon">${icon('external')}</span></a>`;if(p.localOnly)return `<button class="panel-link" data-panel="${esc(p.name)}" data-server="${esc(s.id)}"><span class="panel-link-label">${esc(p.name)}</span><span class="panel-link-icon">${icon('terminal')} SSH</span></button>`;let domain=p.domain||s.host;if(!/^[A-Za-z0-9.-]+$/.test(domain))domain=s.host;let path=p.path||'/';if(!path.startsWith('/'))path='/'+path;const port=Number(p.port);if(!Number.isInteger(port)||port<1||port>65535)return `<span class="panel-link panel-link-unavailable" aria-disabled="true"><span class="panel-link-label">${esc(p.name)} · адрес не указан</span></span>`;const url=`${p.scheme==='https'?'https':'http'}://${domain}:${port}${path}`;return `<a class="panel-link" href="${esc(url)}" target="_blank" rel="noopener noreferrer"><span class="panel-link-label">${esc(p.name)}</span><span class="panel-link-icon">${icon('external')}</span></a>`}
function serverResources(d){
 const cpu=knownNumber(d.cpu)?d.cpu:null;
 const memory=d.memory&&knownNumber(d.memory.used)&&knownNumber(d.memory.total)&&d.memory.total>0?d.memory:null;
 const disk=d.disk&&knownNumber(d.disk.used)&&knownNumber(d.disk.total)&&d.disk.total>0?d.disk:null;
 return `<div class="server-meta"><span>${icon('clock')}UP <strong>${esc(formatUptime(d.uptime))}</strong></span>${knownNumber(d.cores)?`<span>${icon('cpu')}<strong>${esc(d.cores)}</strong> CPU</span>`:''}<span class="server-kernel mono" title="Ядро">${esc(d.kernel||'Ядро: нет данных')}</span></div>
  <div class="server-metrics">${metric('CPU',cpu===null?null:cpu.toFixed(1)+'%',cpu,{icon:'cpu',note:cpu===null?'Нет измерения':knownNumber(d.cpuIntervalSeconds)?'Среднее за '+d.cpuIntervalSeconds+' с':'Измеренная загрузка'})}${metric('RAM',memory?Math.round(memory.used/memory.total*100)+'%':null,memory?memory.used/memory.total*100:null,{icon:'memory',note:memory?bytes(memory.used)+' из '+bytes(memory.total):'Нет измерения'})}${metric('Диск',disk?Math.round(disk.used/disk.total*100)+'%':null,disk?disk.used/disk.total*100:null,{icon:'disk',note:disk?bytes(disk.used)+' из '+bytes(disk.total):'Нет измерения'})}</div>`;
}
function serverError(st){
 return `<div class="error-box">${icon('alert')}<div><strong>Подключение по SSH не подтверждено</strong><p>${esc(st.error||'Нет результата проверки')}</p></div></div>`;
}
function serverStatus(s){
 const st=s.status||{},d=st.data||{},health=typeof st.health==='string'?st.health:st.health?.health;
 const stale=knownNumber(st.checkedAt)&&Date.now()/1000-st.checkedAt>150;
 const incomplete=Boolean(st.monitorError)||Object.values(d.collectionOk||{}).some(value=>value!==true);
 if(st.ok===false)return ['failed','SSH недоступен'];
 if(st.ok!==true)return ['unknown','Нет проверки'];
 if(stale||health==='stale')return ['unknown','Данные устарели'];
 if(['critical','unavailable'].includes(health))return ['failed','Есть ошибки'];
 if(health==='warning'||incomplete)return ['warning','Требует внимания'];
 return ['active','SSH доступен'];
}
function directoryRow(s){
 const [status,label]=serverStatus(s);
 return `<li><button type="button" class="server-directory-row" data-open-server="${esc(s.id)}">
  <span class="server-directory-icon">${icon('server')}</span>
  <span class="server-directory-identity"><strong class="server-directory-name">${esc(s.name)}</strong><span class="server-directory-host">${esc(s.host)}</span></span>
  <span class="server-directory-status state-${status}">${label}</span>
  <span class="server-directory-arrow" aria-hidden="true">${icon('chevron')}</span>
 </button></li>`;
}
function workspaceOverview(s){
 const st=s.status||{},disabled=st.ok?'':'disabled';
 return `${st.ok?`<section class="server-workspace-card"><div class="server-workspace-card-head"><h2>Ресурсы</h2></div>${serverResources(st.data||{})}</section>`:serverError(st)}
 <section class="server-workspace-card">
  <div class="server-workspace-card-head"><h2>Обслуживание</h2></div>
  <div class="server-workspace-actions">
   <button type="button" class="button secondary" data-fail2ban-server="${esc(s.id)}" ${disabled}>${icon('check')}Настроить Fail2ban</button>
   <button type="button" class="button secondary" data-reboot="${esc(s.id)}" ${disabled}>${icon('power')}Перезагрузить сервер</button>
  </div>
  <div class="server-task-status" data-server-task="${esc(s.id)}"></div>
 </section>`;
}
function workspaceServices(s,expanded){
 const st=s.status||{},d=st.data||{};
 if(!st.ok)return serverError(st);
 const services=Array.isArray(d.services)?d.services:[],containers=Array.isArray(d.containers)?d.containers:[];
 const servicesIncomplete=d.collectionOk?.services===false,containersIncomplete=d.collectionOk?.containers===false;
 return `<section class="server-workspace-card">
  <div class="server-workspace-card-head"><h2>Службы systemd</h2><button class="button secondary" type="button" data-add-service="${esc(s.id)}">${icon('plus')}Добавить в наблюдение</button></div>
  <div class="service-list">${services.length?services.map(v=>serviceRow(s,v)).join(''):`<div class="empty">${servicesIncomplete?'Не удалось получить состояние служб':'Нет добавленных служб'}</div>`}</div>
 </section>${containers.length||containersIncomplete?`<section class="server-workspace-card">
  <div class="server-workspace-card-head"><h2>Контейнеры Docker</h2></div>
  <div class="service-list">${containerRows(s,containers,expanded)}${containersIncomplete?'<div class="collection-note">Не удалось полностью проверить контейнеры Docker</div>':''}</div>
 </section>`:''}`;
}
function workspaceAwg(s){
 const st=s.status||{},d=st.data||{};
 const interfaces=Array.isArray(d.awg)?d.awg:[],containers=Array.isArray(d.containers)?d.containers.filter(v=>v.awg):[];
 if(!st.ok)return serverError(st);
 const complete=d.collectionOk?.awg!==false;
 const hostStatus=interfaces.length?'':complete?(d.awgSupported===false?'Утилита AWG на хосте отсутствует':'Интерфейсы AWG на хосте не обнаружены'):'Не удалось полностью проверить интерфейсы AWG';
 const containerStatus=containers.map(v=>{
  const interfaces=v.awg.interfaces;
  const status=v.awg.collectionOk===true?(Array.isArray(interfaces)&&interfaces.length?interfaces.join(', '):'Интерфейс AWG не найден'):'Нет данных проверки AWG';
  return `<div class="server-awg-status"><strong>Docker · ${esc(v.name||v.unit||'AWG')}</strong><span>${esc(status)}</span></div>`;
 }).join('');
 return `<section class="server-workspace-card"><div class="server-workspace-card-head"><h2>Интерфейсы AmneziaWG</h2></div>${interfaces.map(v=>vpn(v,complete)).join('')}${hostStatus?`<div class="server-awg-status">${esc(hostStatus)}</div>`:''}${containerStatus}</section>`;
}
function renderSummary(){
 const servers=state.servers,pending=state===presentationInitialState,online=servers.filter(s=>s.status?.ok),active=online.flatMap(s=>[...(s.status.data?.services||[]),...(s.status.data?.containers||[])]).filter(s=>s.state==='active'&&s.collectionOk!==false),partialServices=online.length<servers.length||online.some(s=>s.status.data?.collectionOk?.services===false||s.status.data?.collectionOk?.containers===false),interfaces=online.filter(s=>s.status.data?.collectionOk?.awg!==false).flatMap(s=>s.status.data?.awg||[]),knownPeers=interfaces.filter(v=>knownNumber(v.online)),vpnCount=knownPeers.reduce((n,v)=>n+v.online,0),partialPeers=online.length<servers.length||knownPeers.length!==interfaces.length||online.some(s=>s.status.data?.collectionOk?.awg===false),latest=Math.max(0,...servers.map(s=>knownNumber(s.status?.checkedAt)?s.status.checkedAt:0)),connectionNote=!servers.length?pending?updating?'Загружаем список серверов':'Список серверов ещё не загружен':'Добавьте первый сервер':online.length===servers.length?'SSH доступен на всех серверах':online.length?'Есть неподтверждённые подключения':'Нет подтверждённых подключений',items=[
  {icon:'server',label:'SSH доступен',value:servers.length?String(online.length):pending?'—':'0',suffix:' / '+servers.length,note:connectionNote},
  {icon:'activity',label:'Активные службы',value:online.length?(partialServices?'≥ ':'')+active.length:'—',note:'Добавленные службы и Docker'},
  {icon:'network',label:'AWG · недавний handshake',value:knownPeers.length?(partialPeers?'≥ ':'')+vpnCount:'—',note:knownPeers.length?'На хосте · за последние 3 минуты':'Нет данных о handshake'}
 ];
 $('#summary').innerHTML=items.map(item=>`<div><span class="summary-icon">${icon(item.icon)}</span><div class="summary-content"><span class="stat-label">${esc(item.label)}</span><strong class="stat-value mono">${esc(item.value)}${item.suffix?`<small>${esc(item.suffix)}</small>`:''}</strong><em class="stat-note">${esc(item.note)}</em></div></div>`).join('');return latest
}
function render(){
 const latest=renderSummary(),servers=$('#servers');
 $('#serverCount').textContent=state.servers.length;
 if(state!==presentationInitialState&&!servers.contains(document.activeElement)){
  servers.innerHTML=state.servers.length?`<ul class="server-directory" aria-label="Подключённые серверы">${state.servers.map(directoryRow).join('')}</ul>`:'<div class="server-directory-empty">Нет подключённых серверов</div>';
 }
 if(serverWorkspace){
  if(state.servers.some(s=>s.id===serverWorkspace.id))renderWorkspace();
  else{navigateMain('all');return;}
 }
 window.renderHealth?.();
 window.renderMaintenance?.();
 $('#updateLabel').textContent=latest?'Проверка SSH в '+clock(latest)+' МСК':'Нет данных о проверке SSH';
 renderActivity();
}
function renderActivity(){
 const s=state.servers.find(item=>item.id===serverWorkspace?.id);
 const uniqueName=s&&state.servers.filter(item=>item.name===s.name).length===1;
 const rows=s?state.activity.filter(a=>a.serverId?a.serverId===s.id:a.action!=='password-change'&&uniqueName&&a.server===s.name):state.activity;
 $('#activityRows').innerHTML=rows.length?rows.map(a=>`<div class="activity-row"><time>${clock(a.time)}</time><span>${esc(a.server)}</span><strong>${esc(a.unit)}</strong><span>${esc({start:'Запуск',stop:'Остановка',restart:'Перезапуск','password-change':'Смена пароля'}[a.action]||a.action)}</span><span class="result">${a.ok?'✓ Выполнено':'Ошибка'}</span></div>`).join(''):'<div class="empty">Действий пока нет</div>';
}
async function load(){
 if(updating||window.accountReauthRequired)return;
 updating=true;
 $('#refresh').disabled=true;
 try{
  state=await api('/api/state');
  render();
  if(restoreWorkspaceOnLoad){
   restoreWorkspaceOnLoad=false;
   restoreWorkspace();
  }
  await window.loadControlStatus?.();
  await window.loadHealth?.();
 }catch(e){toast(e.message);$('#updateLabel').textContent='Не удалось обновить'}
 finally{updating=false;$('#refresh').disabled=false}
}
$('#refresh').onclick=async()=>{if(updating)return;$('#refresh').disabled=true;try{await Promise.all(state.servers.map(s=>api('/api/refresh',{server:s.id})));await load()}catch(e){toast(e.message)}finally{$('#refresh').disabled=false}};
document.addEventListener('click',async e=>{const addPanel=e.target.closest('[data-add-panel]');if(addPanel){addPanelModal(addPanel.dataset.addPanel);return}const panel=e.target.closest('[data-panel]');if(panel){panel.disabled=true;try{const r=await api('/api/panel',{server:panel.dataset.server,panel:panel.dataset.panel});modal('Панель готова',`<p class="form-note">Соединение через SSH-туннель установлено.</p><a class="button primary" href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">Открыть ${esc(panel.dataset.panel)} ↗</a>`)}catch(e){toast(e.message)}finally{panel.disabled=false}return}const b=e.target.closest('[data-action]');if(b){const {action,server,unit}=b.dataset,s=state.servers.find(s=>s.id===server);if(action==='logs'){modal('Журнал · '+(titles[unit]||unit),'<div class="loading"><div class="spinner"></div>Загружаем журнал…</div>');try{const r=await api('/api/action',{server,unit,action});$('#modalBody').innerHTML=`<p class="form-note">${esc(s.name)} · последние 100 строк</p><pre class="logs">${esc(r.logs||r.error||'Записей нет')}</pre>`}catch(e){$('#modalBody').innerHTML=`<p class="form-error">${esc(e.message)}</p>`}return}modal(action==='stop'?'Остановить сервис?':action==='restart'?'Перезапустить сервис?':'Запустить сервис?',`<p class="form-note"><strong>${esc(titles[unit]||unit)}</strong><br>${esc(s.name)} · ${esc(s.host)}<br>${action==='stop'?'Подключения этого сервиса будут недоступны до следующего запуска.':action==='restart'?'Текущие подключения этого сервиса могут кратковременно прерваться.':'Будет запущена установленная служба.'}</p><div class="form-error" id="actionError"></div><div class="modal-actions"><button class="button secondary" id="cancelAction">Отмена</button><button class="button primary" id="confirmAction">${{start:'Запустить',stop:'Остановить',restart:'Перезапустить'}[action]}</button></div>`);$('#cancelAction').onclick=()=>$('#modal').close();$('#confirmAction').onclick=async()=>{$('#confirmAction').disabled=true;try{const r=await api('/api/action',{server,unit,action});if(!r.ok)throw Error(r.error||'Служба не выполнила действие');$('#modal').close();toast('Действие выполнено: '+unit);await load()}catch(e){$('#actionError').textContent=e.message;$('#confirmAction').disabled=false}};return}
const add=e.target.closest('[data-add-service]');if(add){const sid=add.dataset.addService;modal('Добавить сервис','<div class="loading"><div class="spinner"></div>Читаем установленные службы…</div>');try{const r=await api('/api/inventory',{server:sid});const existing=state.servers.find(s=>s.id===sid).services;const units=r.units.filter(x=>!existing.includes(x.unit));$('#modalBody').innerHTML=`<label>Поиск службы<input id="unitSearch" placeholder="Например: telemt, nginx или docker"></label><select id="unitSelect" size="9"></select><p class="form-note">Добавление показывает сервис в панели. Его состояние не изменится.</p><div id="serviceError" class="form-error"></div><div class="modal-actions"><button class="button primary" id="saveService">Добавить в панель</button></div>`;const update=()=>{$('#unitSelect').innerHTML=units.filter(x=>x.unit.toLowerCase().includes($('#unitSearch').value.toLowerCase())).map(x=>`<option value="${esc(x.unit)}">${esc(x.unit)} · ${esc(x.enabled)}</option>`).join('')};update();$('#unitSearch').oninput=update;$('#saveService').onclick=async()=>{if(!$('#unitSelect').value)return;$('#saveService').disabled=true;try{await api('/api/services',{server:sid,unit:$('#unitSelect').value});$('#modal').close();toast('Сервис добавлен');await load()}catch(e){$('#serviceError').textContent=e.message;$('#saveService').disabled=false}}}catch(e){$('#modalBody').innerHTML=`<p class="form-error">${esc(e.message)}</p>`}return}
const retry=e.target.closest('[data-retry]');if(retry){retry.disabled=true;try{await api('/api/refresh',{server:retry.dataset.retry});await load()}catch(e){toast(e.message)}finally{retry.disabled=false}}
});
$('#addServer').onclick=async()=>{
 modal('Новый сервер','<div class="loading"><div class="spinner"></div>Читаем доступные SSH-ключи…</div>');
 try{
  const r=await api('/api/keys');
  $('#modalBody').innerHTML=`<form id="serverForm"><div class="form-grid"><label class="wide">Название<input name="name" required placeholder="Например: резервный VPN"></label><label class="wide">IP-адрес или домен<input name="host" required placeholder="203.0.113.10" autocomplete="off"></label><label>SSH-пользователь<input name="user" value="root" required></label><label>SSH-порт<input name="port" type="number" value="22" min="1" max="65535" required></label><div class="wide"><label>SSH-ключ на сервере управления<div class="key-picker"><select name="key" required><option value="">Выберите ключ</option>${r.keys.map(k=>`<option>${esc(k)}</option>`).join('')}</select><button class="button secondary" type="button" id="generateKey">＋ Создать ключ</button></div></label><p class="key-hint">Отдельный Ed25519-ключ без парольной фразы. Приватная часть хранится на сервере управления с правами 600.</p></div></div><section id="keySetup" class="key-setup" hidden></section><p class="form-note">После установки ключа проверьте отпечаток сервера при первом SSH-подключении с сервера управления. Затем нажмите «Проверить и добавить».</p><div id="serverError" class="form-error"></div><div class="modal-actions"><button class="button primary" id="saveServer">Проверить и добавить</button></div></form>`;
  const form=$('#serverForm');
  for(const name of ['host','user','port'])form.elements[name].addEventListener('input',()=>{$('#keySetup').hidden=true});
  $('#generateKey').onclick=async()=>{
   const values=Object.fromEntries(new FormData(form));$('#serverError').textContent='';
   if(!values.host){$('#serverError').textContent='Сначала укажите IP или домен сервера.';form.elements.host.focus();return}
   const button=$('#generateKey');button.disabled=true;button.textContent='Создаём…';$('#saveServer').disabled=true;
   for(const name of ['host','user','port'])form.elements[name].disabled=true;
   try{
    const generated=await api('/api/keys/generate',values);
    const option=document.createElement('option');option.value=generated.key;option.textContent=generated.key;form.elements.key.appendChild(option);form.elements.key.value=generated.key;
    const setup=$('#keySetup');setup.hidden=false;
    setup.innerHTML=`<div class="key-ready">✓ Ключ создан для ${esc(generated.user)}@${esc(generated.host)}</div><p class="key-fingerprint">${esc(generated.fingerprint)}</p><div class="command-title"><strong>1. Выполните на сервере под root</strong><button type="button" class="button secondary" id="copyInstall">Копировать</button></div><pre class="logs key-command" id="installCommand">${esc(generated.installCommand)}</pre><p class="key-hint">Команда добавит только публичный ключ пользователю ${esc(generated.user)}. Существующие ключи сохранятся; повторный запуск не создаст дубликат.</p><div class="command-title"><strong>2. Выполните на VPS управления под root</strong><button type="button" class="button secondary" id="copyConnect">Копировать</button></div><pre class="logs key-command">${esc(generated.connectCommand)}</pre><p class="key-hint">Проверьте отпечаток хоста перед подтверждением доверия. Пароль сервера в эту панель вводить не нужно.</p>`;
    for(const [id,text] of [['copyInstall',generated.installCommand],['copyConnect',generated.connectCommand]])$('#'+id).onclick=async()=>{try{await navigator.clipboard.writeText(text);toast('Команда скопирована')}catch(e){toast('Выделите команду и скопируйте её вручную')}};
   }catch(e){$('#serverError').textContent=e.message}
   finally{button.disabled=false;button.textContent='＋ Создать ключ';$('#saveServer').disabled=false;for(const name of ['host','user','port'])form.elements[name].disabled=false}
  };
  form.onsubmit=async e=>{e.preventDefault();$('#saveServer').disabled=true;$('#saveServer').textContent='Проверяем подключение…';try{await api('/api/servers',Object.fromEntries(new FormData(form)));$('#modal').close();toast('Сервер добавлен');await load()}catch(e){$('#serverError').textContent=e.message;$('#saveServer').disabled=false;$('#saveServer').textContent='Проверить и добавить'}};
 }catch(e){$('#modalBody').innerHTML=`<p class="form-error">${esc(e.message)}</p>`}
};
const mainViews={
 all:['Серверы'],health:['Здоровье серверов','История нагрузки, сбоев служб и счётчиков AWG.'],
 availability:['Доступность','Проверки из России и история SSH с сервера управления.'],
 security:['Атаки и блокировки'],updates:['Центр обновлений'],activity:['История действий'],
 alerts:['Уведомления Telegram'],settings:['Настройки']
};
function showView(view){
 filter=view;
 const primary=view==='server'?'all':view;
 document.querySelectorAll('aside [data-filter]').forEach(button=>{
  const active=button.dataset.filter===primary;
  button.classList.toggle('active',active);
  if(active)button.setAttribute('aria-current','page');
  else button.removeAttribute('aria-current');
 });
 for(const name of [...document.body.classList]){
  if(name.startsWith('filter-')||name.startsWith('server-section-'))document.body.classList.remove(name);
 }
 document.body.classList.add('filter-'+view);
 if(view==='server'){
  document.body.classList.add('server-section-'+serverWorkspace.section);
  return;
 }
 const [title,description='']=mainViews[view];
 $('#pageTitle').textContent=title;
 $('#pageSubtitle').textContent=description;
 $('#pageSubtitle').hidden=!description;
}
function navigateMain(view,{writeHistory=true}={}){
 if(!Object.hasOwn(mainViews,view))return;
 if(serverWorkspace?.section==='native')window.clearEmbeddedWorkspace?.();
 serverWorkspace=null;
 if(writeHistory&&location.hash.startsWith('#server/'))history.pushState(null,'',location.pathname+location.search);
 showView(view);
 render();
 if(view==='availability')window.loadRf?.();
 window.settingsNavigate?.(view);
 window.alertsNavigate?.(view);
 window.securityNavigate?.(view);
}
for(const button of document.querySelectorAll('aside [data-filter]')){
 button.addEventListener('click',()=>navigateMain(button.dataset.filter));
}
window.activeServerWorkspace=()=>serverWorkspace;

function openServerWorkspace(id,section='overview',{writeHistory=true}={}){
 const s=state.servers.find(item=>item.id===id);
 if(!s||!serverSections.has(parentServerSection(section)))return false;
 const previous=serverWorkspace;
 if(previous?.section==='native'&&(section!=='native'||previous.id!==id))window.clearEmbeddedWorkspace?.();
 if($('#modal').open)$('#modal').close();
 serverWorkspace={id,section};
 const hash='#server/'+encodeURIComponent(id)+'/'+section;
 if(writeHistory&&location.hash!==hash)history.pushState(null,'',hash);
 showView('server');
 renderWorkspace(true);
 if(section==='history')renderActivity();
 window.renderMaintenance?.();
 if(previous?.id!==id){
  window.scrollTo(0,0);
  $('#serverWorkspaceTitle').focus({preventScroll:true});
 }else{
  $('#serverWorkspace .server-workspace-nav [aria-current="page"]')?.focus({preventScroll:true});
 }
 window.controlNavigate?.(section);
 window.softwareNavigate?.(section);
 return true;
}
window.openServerWorkspace=openServerWorkspace;

function restoreWorkspace(){
 const match=/^#server\/([^/]+)\/([^/]+)$/.exec(location.hash);
 if(match){
  try{
   const section=match[2]==='native'?'panels':match[2];
   if(openServerWorkspace(decodeURIComponent(match[1]),section,{writeHistory:false}))return;
  }catch(error){if(!(error instanceof URIError))throw error}
 }
 if(serverWorkspace)navigateMain('all',{writeHistory:false});
}
window.addEventListener('popstate',restoreWorkspace);
document.addEventListener('click',event=>{
 const entry=event.target.closest('[data-open-server]');
 if(entry){openServerWorkspace(entry.dataset.openServer,entry.dataset.openSection||'overview');return}
 if(event.target.closest('[data-server-back]')){
  const id=serverWorkspace?.id;
  navigateMain('all');
  window.scrollTo(0,0);
  [...document.querySelectorAll('[data-open-server]')].find(row=>row.dataset.openServer===id)?.focus({preventScroll:true});
  return;
 }
 const section=event.target.closest('[data-server-section]');
 if(section&&serverWorkspace)openServerWorkspace(serverWorkspace.id,section.dataset.serverSection);
});

function renderWorkspace(reset=false){
 const s=state.servers.find(item=>item.id===serverWorkspace?.id);
 if(!s)return;
 const {section}=serverWorkspace,[status,label]=serverStatus(s),checked=s.status?.checkedAt;
 if(reset){
  $('#serverWorkspaceTitle').textContent=s.name;
  $('#serverWorkspaceHost').textContent=s.user+'@'+s.host+':'+s.port;
  const nav=$('#serverWorkspaceNav');
  nav.innerHTML=[...serverSections].map(([key,[title,drawing]])=>
   `<button type="button" data-server-section="${key}"${parentServerSection(section)===key?' aria-current="page"':''}>${icon(drawing)}<span>${title}</span></button>`
  ).join('');
 }
 const statusDot=$('#serverWorkspaceStatus');
 statusDot.dataset.state=status;
 statusDot.textContent=label;
 statusDot.title=knownNumber(checked)&&checked>0?'Проверка SSH: '+clock(checked)+' МСК':'';
 const retry=$('#serverWorkspaceRefresh');
 retry.dataset.retry=s.id;
 retry.title=s.status?.ok?'Проверить SSH этого сервера':'Повторить подключение';
 const body=$('#serverWorkspaceBody');
 const expanded=Boolean(body.querySelector('details[open][data-server-detail]'));
 body.className=section==='overview'?'server-workspace-overview':'server-workspace-body';
 const content={overview:workspaceOverview,services:workspaceServices,panels:renderServerPanels,awg:workspaceAwg,updates:workspaceUpdates};
 const renderer=content[section];
 if(renderer){
  const html=renderer(s,expanded);
  if(body.innerHTML!==html&&(reset||!body.contains(document.activeElement)))body.innerHTML=html;
 }else if(reset){
  body.replaceChildren();
 }
}
function workspaceUpdates(s){
 return `<div class="server-workspace-tools"><h2>Обновления сервера</h2><button type="button" class="button secondary" data-software-server="${esc(s.id)}">${icon('plus')}Каталог компонентов</button></div>`;
}
function renderServerPanels(s){
 const st=s.status||{},panels=Array.isArray(st.data?.panels)?st.data.panels:[];
 const tiles=panels.map(p=>{
  let target=p.localOnly?'Локальный порт · SSH':(p.domain||s.host)+(p.port?':'+p.port:'');
  if(p.url){try{target=new URL(p.url).hostname}catch(_){target='Адрес панели'}}
  const lucx=p.name==='3x-ui / LucX',mtproxyl=p.name==='MTProxyL';
  const moduleKind=lucx?'lucx':mtproxyl?'mtproxyl':'web';
  const moduleType=lucx?'VPN-панель':mtproxyl?'Telegram-прокси':'Веб-интерфейс';
  const protocol=lucx||mtproxyl?'Встроена':p.localOnly?'SSH':p.scheme==='https'||p.url?.startsWith('https:')?'HTTPS':'HTTP';
  return `<article class="panel-tile module-${moduleKind}"><div class="panel-tile-top"><div class="panel-tile-icon">${lucx?'<span class="panel-tile-lettermark">3X</span>':mtproxyl?'<span class="panel-tile-lettermark">MT</span>':icon('app')}</div><span class="panel-kind">${protocol}</span></div><span class="panel-tile-type">${moduleType}</span><h3>${esc(p.name)}</h3><p class="panel-tile-address mono">${esc(target)}</p><div class="panel-tile-action">${panelLink(s,p)}</div></article>`;
 }).join('');
 return `<section class="server-workspace-card"><div class="server-workspace-card-head"><h2>Панели и приложения</h2><button type="button" class="button secondary" data-add-panel="${esc(s.id)}" aria-haspopup="dialog">${icon('plus')}Подключить панель</button></div>
 <div class="panel-tiles">${st.ok&&tiles?tiles:`<div class="empty panel-empty">${icon(st.ok?'app':'alert')}<strong>${st.ok?'Панели пока не подключены':'Нет свежих данных о панелях'}</strong><span>${st.ok?'Укажите адрес уже установленной панели.':'Проверьте SSH-подключение к серверу.'}</span></div>`}</div></section>`;
}
function addPanelModal(sid){modal('Добавить панель',`<form id="panelForm"><div class="form-grid"><label class="wide">Название<input name="name" placeholder="Например: Remnawave, Portainer, Cockpit" required></label><label class="wide">Способ подключения<select id="panelKind" name="kind"><option value="url">Открытый адрес или домен</option><option value="tunnel">Локальный порт через SSH</option></select></label><label class="wide" id="panelUrlWrap">Адрес панели<input name="url" type="url" placeholder="https://panel.example.com"></label><label id="panelPortWrap" hidden>Порт на сервере<input name="port" type="number" min="1" max="65535" placeholder="3000"></label><label id="panelSchemeWrap" hidden>Протокол<select name="scheme"><option>http</option><option>https</option></select></label><label class="wide" id="panelPathWrap" hidden>Путь<input name="path" value="/" placeholder="/"></label></div><p class="form-note">Панель уже должна быть установлена. Здесь добавляется доступ к ней; для LucX и MTProxyL доступен встроенный вход; другие приложения открываются по своему адресу.</p><div class="form-error" id="panelError"></div><div class="modal-actions"><button class="button primary" id="savePanel">Добавить панель</button></div></form>`);$('#panelKind').onchange=()=>{const tunnel=$('#panelKind').value==='tunnel';$('#panelUrlWrap').hidden=tunnel;$('#panelUrlWrap input').disabled=tunnel;for(const id of ['panelPortWrap','panelSchemeWrap','panelPathWrap']){$('#'+id).hidden=!tunnel;$('#'+id+' input, #'+id+' select').disabled=!tunnel}};$('#panelForm').onsubmit=async e=>{e.preventDefault();$('#savePanel').disabled=true;try{await api('/api/panels',{...Object.fromEntries(new FormData(e.target)),server:sid});$('#modal').close();toast('Панель добавлена');await load()}catch(e){$('#panelError').textContent=e.message;$('#savePanel').disabled=false}}}
document.addEventListener('DOMContentLoaded',load,{once:true});
setInterval(()=>{if(!document.hidden&&!$('#modal').open)load()},30000);

// Responsive navigation and presentation only; existing actions keep their handlers.
(() => {
 const compact=matchMedia('(max-width: 900px)');
 const sidebar=document.getElementById('sidebar'),main=document.getElementById('mainContent');
 const bar=document.getElementById('mobileNav'),backdrop=document.getElementById('mobileBackdrop');
 const menu=document.getElementById('mobileMore');
 let open=false,returnFocus=null,scheduled=false,viewportWidth=0,viewportHeight=0;
 const focusable=()=>[...sidebar.querySelectorAll('a[href],button:not([disabled])')].filter(x=>x.getClientRects().length&&!x.hidden);
 function closeMenu(restore=true){
  open=false;delete document.body.dataset.navOpen;backdrop.hidden=true;
  sidebar.inert=compact.matches;main.inert=false;bar.inert=false;
  sidebar.setAttribute('role','navigation');sidebar.removeAttribute('aria-modal');
  if(compact.matches)sidebar.setAttribute('aria-hidden','true');else sidebar.removeAttribute('aria-hidden');
  menu.setAttribute('aria-expanded','false');
  if(restore&&returnFocus?.isConnected)returnFocus.focus({preventScroll:true});
 }
 function openMenu(event){
  if(!compact.matches)return;if(open){closeMenu();return}
  returnFocus=event.currentTarget;open=true;document.body.dataset.navOpen='true';backdrop.hidden=false;
  sidebar.inert=false;sidebar.removeAttribute('aria-hidden');sidebar.setAttribute('role','dialog');sidebar.setAttribute('aria-modal','true');
  main.inert=true;bar.inert=true;menu.setAttribute('aria-expanded','true');
  sidebar.scrollTop=0;document.getElementById('closeMobileMenu').focus({preventScroll:true});
 }
 menu.addEventListener('click',openMenu);
 document.getElementById('closeMobileMenu').addEventListener('click',()=>closeMenu());
 backdrop.addEventListener('click',()=>closeMenu());
 document.addEventListener('keydown',event=>{
  if(!open)return;
  if(event.key==='Escape'){event.preventDefault();closeMenu()}
  if(event.key==='Tab'){
   const items=focusable(),first=items[0],last=items[items.length-1];
   if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus()}
   else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus()}
  }
 });
 document.querySelectorAll('[data-mobile-view]').forEach(button=>button.addEventListener('click',()=>{
  document.querySelector('aside [data-filter="'+button.dataset.mobileView+'"]').click();
 }));
 document.addEventListener('click',event=>{
  if(!event.target.closest('aside [data-filter]'))return;
  if(compact.matches){closeMenu(false);$('#pageTitle').focus({preventScroll:true})}
  window.scrollTo(0,0);
  sync();
 });
 const toolbarResize=new ResizeObserver(entries=>{
  for(const entry of entries)document.documentElement.style.setProperty('--native-toolbar-height',Math.ceil(entry.target.getBoundingClientRect().height)+'px');
 });
 const watched=new WeakSet();
 function sync(){
  scheduled=false;
  const selected=document.querySelector('aside .nav.active')?.dataset.filter;
  let hasQuickLink=false;
  document.querySelectorAll('[data-mobile-view]').forEach(button=>{
   const active=selected===button.dataset.mobileView;button.classList.toggle('active',active);
   hasQuickLink ||= active;
   if(active)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');
  });
  menu.classList.toggle('active',!hasQuickLink);
  document.querySelectorAll('.control-table').forEach(table=>{
   const labels=[...table.querySelectorAll('thead th')].map(x=>x.textContent.trim());
   if(table.closest('#clientsDashboard,#backupsDashboard')){
    table.classList.add('mobile-card-table');
    table.querySelectorAll('tbody tr').forEach(row=>[...row.children].forEach((cell,index)=>{
     if(cell.colSpan>1){cell.classList.add('mobile-full-cell');return}
     if(labels[index]&&cell.dataset.label!==labels[index])cell.dataset.label=labels[index];
    }));
   }else if(table.parentElement.classList.contains('control-table-wrap')){
    const wrap=table.parentElement;wrap.tabIndex=0;wrap.setAttribute('role','region');wrap.setAttribute('aria-label','Таблица: прокрутите по горизонтали, чтобы увидеть все столбцы');
   }
  });
  const toolbar=document.querySelector('.native-toolbar');
  if(toolbar&&!watched.has(toolbar)){watched.add(toolbar);toolbarResize.observe(toolbar)}
 }
 const schedule=()=>{if(!scheduled){scheduled=true;requestAnimationFrame(sync)}};
 new MutationObserver(schedule).observe(main,{childList:true,subtree:true});
 new MutationObserver(schedule).observe(document.body,{attributes:true,attributeFilter:['class']});
 function keyboard(){
  const viewport=window.visualViewport;if(!viewport)return;
  if(Math.abs(viewport.width-viewportWidth)>80){viewportWidth=viewport.width;viewportHeight=viewport.height}
  viewportHeight=Math.max(viewportHeight,viewport.height);
  const editing=/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName||'');
  if(compact.matches&&editing&&viewportHeight-viewport.height>140)document.body.dataset.keyboardOpen='true';
  else delete document.body.dataset.keyboardOpen;
 }
 window.visualViewport?.addEventListener('resize',keyboard);
 document.addEventListener('focusin',keyboard);document.addEventListener('focusout',()=>setTimeout(keyboard,0));
 compact.addEventListener('change',()=>{closeMenu(false);keyboard();schedule()});
 closeMenu(false);sync();keyboard();
})();
