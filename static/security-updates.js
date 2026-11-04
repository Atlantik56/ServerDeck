// Cached publication/inventory feed only. This UI never installs or restarts anything.
(() => {
 const CVE='CVE-2026-98432',SOURCE='https://ubuntu.com/security/CVE-2026-98432';
 const banner=document.getElementById('securityUpdatesBanner'),card=document.getElementById('securityUpdatesCard');
 if(!banner||!card)return;
 let feed=null,loading=null,busy=false,error='',signature='',readFailed=false,revision=0,followup=null,followupUntil=0;
 const rows=v=>Array.isArray(v)?v:[];
 const number=v=>typeof v==='number'&&Number.isFinite(v)?v:null;
 const text=v=>esc((typeof v==='string'||typeof v==='number'?String(v):'').slice(0,1200));
 const date=v=>number(v)&&v>0?new Date(v*1000).toLocaleString('ru-RU',{timeZone:'Europe/Moscow',day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})+' МСК':'Ещё не выполнялась';
 const shield='<svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 3 8 3v6c0 4-3.5 7-8 9-4.5-2-8-5-8-9V6l8-3Z"/><path d="M12 8v5m0 3h.01"/></svg>';
 const ageLimit=()=>number(feed?.staleAfterSeconds)>0?feed.staleAfterSeconds:10800;
 const old=ts=>!number(ts)||ts<=0||Date.now()/1000-ts>ageLimit()||ts-Date.now()/1000>60;
 const stale=()=>!feed||feed.stale===true||old(feed.lastGoodAt)||Boolean(feed.error)||readFailed;
 const fresh=s=>s.ok===true&&!s.stale&&!s.error&&!stale()&&!old(s.checkedAt);
 const notices=()=>rows(feed?.notices).filter(n=>n&&typeof n.id==='string'&&/^[a-f0-9]{64}$/.test(n.id)).sort((a,b)=>(number(b.createdAt)||0)-(number(a.createdAt)||0));
 const names={awaiting_release:'Ожидается исправление',available:'Доступно по APT',published:'Опубликовано Ubuntu',reboot_required:'Нужна перезагрузка',fixed:'Исправлено',unknown:'Нет подтверждения',unsupported:'Проверка не поддерживается'};
 function label(s){
  if(!fresh(s))return {title:'Нет свежего подтверждения',tone:'unknown'};
  if(s.available===true&&['available','published'].includes(s.state))return {title:'Доступно по APT',tone:'available'};
  if(s.state==='available')return {title:feed.fixedPublished===true?'Опубликовано Ubuntu':'Доступность по APT не подтверждена',tone:'unknown'};
  return {title:names[s.state]||names.unknown,tone:s.state==='fixed'?'fixed':s.state==='reboot_required'?'warning':s.state==='published'?'published':'unknown'};
 }
 function headline(){
  if(!feed)return {title:error?'Сведения об исправлении недоступны':'Публикация исправления пока не проверена',message:error||'Получаем сохранённые сведения Ubuntu и серверов.',tone:'unknown'};
  if(stale())return {title:'Статус исправления не подтверждён',message:error||feed.error||'Сохранённые сведения устарели. Это не подтверждает наличие или отсутствие исправления.',tone:'warning'};
  if(feed.fixedPublished===true)return {title:'Исправление опубликовано Ubuntu',message:'Доступность по APT и состояние каждого сервера показаны отдельно.',tone:'published'};
  if(feed.fixedPublished===false)return {title:'Ожидается публикация исправления',message:'По последней проверке исправление для наблюдаемых пакетов ещё не опубликовано.',tone:'pending'};
  return {title:'Публикация исправления не подтверждена',message:'Для части серверов или пакетов нет подтверждённых сведений.',tone:'unknown'};
 }
 function noticeHTML(n,compact=false){
  return `<div class="security-update-notice ${n.acknowledged?'acknowledged':''}"><div><strong>${text(n.title||'Уведомление об исправлении')}</strong>${compact?'':`<p>${text(n.message)}</p><small>${date(n.createdAt)}${n.acknowledged?' · Прочитано':''}</small>`}</div>${n.acknowledged?'':`<button type="button" class="button secondary" data-security-update-ack="${text(n.id)}" ${busy?'disabled':''}>Прочитано</button>`}</div>`;
 }
 function serverHTML(s){
  const state=label(s),known=fresh(s),vendor={released:'Опубликовано Ubuntu',pending:'Ожидается выпуск',needed:'Исправление требуется',deferred:'Отложено Ubuntu',ignored:'Исправление в этом канале не подтверждено','not-affected':'Не затронуто по данным Ubuntu','needs-triage':'Ubuntu уточняет статус',DNE:'Пакет отсутствует для выпуска'}[s.vendorStatus]||'Статус Ubuntu не получен';
  const apt=known&&s.available===true?'Доступно по APT':known&&s.available===false?'В текущих данных APT исправление не найдено':'Доступность по APT не подтверждена';
  const affected=known&&s.affected===true?'Затронуто по данным проверки':known&&s.affected===false?'Не затронуто по данным проверки':'Затронутость не подтверждена';
  return `<article class="security-update-host" data-security-update-server="${text(s.id)}"><div class="security-update-host-head"><div><h3>${text(s.name||s.host||'Сервер')}</h3><code>${text(s.host||'Адрес не указан')}</code></div><span class="security-update-state ${state.tone}">${state.title}</span></div><dl class="security-update-packages"><div><dt>Работающее ядро</dt><dd>${text(s.kernel||'Нет данных')}</dd></div><div><dt>Исходный пакет</dt><dd>${text(s.sourcePackage||'Нет данных')}</dd></div><div><dt>Установленная версия</dt><dd>${text(s.installedVersion||'Не определена')}</dd></div><div><dt>Исправленная версия Ubuntu</dt><dd>${text(s.fixedVersion||'Не опубликована или не определена')}</dd></div></dl><div class="security-update-host-facts"><span>${known?vendor:'Текущий статус Ubuntu не подтверждён'}</span><span class="${known&&s.available===true?'security-update-apt-ready':''}">${apt}</span><span>${affected}</span></div>${s.message?`<p class="security-update-message">${text(s.message)}</p>`:''}${s.error?`<p class="security-update-error">${text(s.error)}</p>`:''}${!known?'<p class="security-update-message">Текущее состояние не подтверждено. Версии выше — последние доступные сведения.</p>':''}<small class="security-update-host-time">Проверка сервера: ${date(s.checkedAt)}</small></article>`;
 }
 function render(){
  const newSignature=JSON.stringify([feed,error,busy]);if(newSignature===signature)return;signature=newSignature;
  const h=headline(),unread=notices().filter(n=>n.acknowledged!==true),notice=unread[0],checking=Boolean(feed?.checking),servers=rows(feed?.servers),known=servers.filter(fresh);
  banner.classList.toggle('has-notice',Boolean(notice));banner.classList.toggle('is-stale',stale()&&Boolean(feed));
  banner.innerHTML=`<div class="security-update-banner-mark">${shield}</div><div class="security-update-banner-copy"><span class="security-update-cve">${CVE}${notice?' · Новое уведомление':''}</span><strong>${text(notice?.title||h.title)}</strong><small>${checking?'Проверка выполняется. ':''}${notice&&stale()?'Сохранённое уведомление; текущие сведения не подтверждены. ':''}${text(feed?.checkedAt?'Проверено: '+date(feed.checkedAt):h.message)}${notice&&unread.length>1?' · Непрочитанных: '+unread.length:''}${error?' · '+text(error):''}</small></div><div class="security-update-banner-actions"><button type="button" class="button secondary" data-security-update-details>Подробнее</button>${notice?`<button type="button" class="button secondary" data-security-update-ack="${text(notice.id)}" ${busy?'disabled':''}>Прочитано</button>`:''}</div>`;
  card.innerHTML=`<article class="security-update-card"><div class="security-update-card-head"><div><div class="security-update-cve">БЕЗОПАСНОСТЬ ЯДРА · ${CVE}</div><h2>${h.title}</h2><p>${text(h.message)}</p></div><span class="security-update-state ${h.tone}">${checking?'Проверяем…':stale()?'Нет свежего подтверждения':'Сведения получены'}</span></div><div class="security-update-toolbar"><a href="${SOURCE}" class="security-update-source" target="_blank" rel="noopener noreferrer">Статус Ubuntu ↗</a><button type="button" class="button secondary" data-security-update-check ${busy||checking?'disabled':''}>${checking?'Проверка выполняется…':'Проверить сейчас'}</button></div><dl class="security-update-checks"><div><dt>Последняя попытка</dt><dd>${date(feed?.checkedAt)}</dd></div><div><dt>Успешная проверка источника</dt><dd>${date(feed?.lastGoodAt)}</dd></div><div><dt>Следующая проверка</dt><dd>${number(feed?.nextCheckAt)>0?date(feed.nextCheckAt):'Расписание ещё не получено'}</dd></div></dl><p class="security-update-note">Фоновая проверка выполняется каждый час на сервере управления. Эта карточка ничего не устанавливает и не перезагружает. «Опубликовано Ubuntu» не означает «Доступно по APT».</p>${error||feed?.error?`<p class="security-update-error" role="status">${text(error||feed.error)}</p>`:''}${feed?`<div class="security-update-overview"><span>Подтверждено по APT: <strong>${known.filter(s=>s.available===true).length}</strong></span><span>Исправлено: <strong>${known.filter(s=>s.state==='fixed').length}</strong></span><span>Не подтверждено: <strong>${servers.filter(s=>!fresh(s)||['unknown','unsupported'].includes(s.state)).length}</strong></span></div>`:''}${notices().length?`<div class="security-update-notices">${notices().slice(0,12).map(n=>noticeHTML(n)).join('')}</div>`:''}<div class="security-update-hosts">${servers.length?servers.map(serverHTML).join(''):`<p class="security-update-empty">${feed?'Сведения о серверах ещё не получены.':'Получаем сохранённые сведения. Статус исправления пока неизвестен.'}</p>`}</div></article>`;
 }
 function accept(value){if(!value||value.cve!==CVE||!Array.isArray(value.servers)||!Array.isArray(value.notices))throw Error('Ответ проверки безопасности имеет неизвестный формат.');feed=value;error='';readFailed=false;render()}
 function scheduleFollowup(){
  if(followup){clearTimeout(followup);followup=null}
  if(!document.hidden&&feed?.checking&&Date.now()<followupUntil)followup=setTimeout(()=>{followup=null;load()},2500);
 }
 async function load(){
  if(loading||busy||document.hidden)return loading;
  const generation=revision;
  loading=(async()=>{try{const value=await api('/api/security-updates');if(generation===revision)accept(value)}catch(e){if(generation===revision){readFailed=true;error=String(e.message||'Не удалось получить сведения.');render()}}finally{loading=null;scheduleFollowup()}})();return loading;
 }
 document.addEventListener('click',async event=>{
  const details=event.target.closest('[data-security-update-details]');if(details){document.querySelector('aside [data-filter="updates"]')?.click();card.scrollIntoView({block:'start',behavior:'auto'});return}
  const check=event.target.closest('[data-security-update-check]'),ack=event.target.closest('[data-security-update-ack]');
  if((!check&&!ack)||busy)return;
  busy=true;revision++;error='';if(check)followupUntil=Date.now()+60000;render();
  try{accept(await api(check?'/api/security-updates/check':'/api/security-updates/ack',check?{}:{notice:ack.dataset.securityUpdateAck}))}
  catch(e){error=String(e.message||'Не удалось сохранить результат.');render()}
  finally{busy=false;render();scheduleFollowup()}
 });
 document.addEventListener('visibilitychange',()=>{if(!document.hidden)load();else if(followup){clearTimeout(followup);followup=null}});
 setInterval(()=>{if(!document.hidden){render();load()}},60000);
 render();load();
})();
