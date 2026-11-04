// Security observations are read-only. Notifications share the existing Telegram recipient.
(() => {
 let report=null,hours=24,selected='',metric='failedPasswords',sourceSearch='',banSearch='',banScope='all',loading=null,pending=false,dirty=false,saving=false,lastError='';
 const root=document.getElementById('securityDashboard');
 const number=value=>typeof value==='number'&&Number.isFinite(value)?value:null;
 const count=value=>number(value)===null||value<0?'—':value.toLocaleString('ru-RU');
 const date=value=>number(value)&&value>0?new Date(value*1000).toLocaleString('ru-RU',{timeZone:'Europe/Moscow',day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}):'Нет данных';
 const duration=value=>number(value)===null?'неизвестный интервал':value>=86400?Math.round(value/86400)+' д':value>=3600?Math.round(value/3600)+' ч':value>=60?Math.round(value/60)+' мин':Math.round(value)+' с';
 const text=value=>esc((value===null||value===undefined?'':typeof value==='string'||typeof value==='number'||typeof value==='boolean'?String(value):'Неизвестно').slice(0,500));
 const rows=value=>Array.isArray(value)?value:[];
 const serverId=s=>String(s.id??s.server??'');
 const sshSources=s=>rows(s.sources).filter(x=>[x.attempts,x.invalidUsers,x.failedPublickeys].some(v=>number(v)!==null&&v>0));
 const sshKnown=s=>s.components?.events?.available===true||[s.ssh?.failedPasswords,s.ssh?.invalidUsers,s.ssh?.failedPublickeys].some(v=>number(v)!==null);
 const bansKnown=s=>s.components?.localBans?.available===true||s.components?.sharedBans?.available===true||rows(s.bans).length>0;
 function stale(s){return Boolean(s.stale)||!number(s.checkedAt)||Date.now()/1000-s.checkedAt>(number(report?.staleAfterSeconds)??180)}
 function visibleServers(){return rows(report?.servers).filter(s=>!selected||serverId(s)===selected)}
 function classFor(s){return s.error&&!s.partial?'error':stale(s)||s.partial?'stale':'fresh'}
 function statusFor(s){return s.error&&!s.partial?'Проверка не выполнена':stale(s)?'Нет свежих данных':s.partial?'Частичный замер':'Свежий замер'}
 function componentStale(s,names){return names.some(name=>s.components?.[name]&&(s.components[name].stale||s.components[name].error||s.components[name].available===false))}
 function shell(){
  if(root.querySelector('#securityToolbar'))return;
  root.innerHTML=`<div id="securityToolbar" class="security-toolbar"><label>Сервер<select id="securityServer" aria-label="Сервер статистики безопасности"><option value="">Все серверы</option></select></label><label>График<select id="securityMetric" aria-label="Счётчик на графиках"><option value="failedPasswords">Ошибки пароля</option><option value="invalidUsers">Неизвестные логины</option><option value="failedPublickeys">Ошибки ключа</option><option value="blockedPackets">Отброшенные пакеты</option></select></label><div class="security-period" role="group" aria-label="Период истории"><button type="button" data-security-hours="1">1 час</button><button type="button" data-security-hours="24">24 часа</button><button type="button" data-security-hours="168">7 дней</button></div><button class="button secondary" type="button" data-security-action="refresh">↻ Обновить</button><span id="securityChecked" class="security-note"></span></div><div id="securityError" class="security-error" role="status" hidden></div><div id="securitySummary" class="security-summary"></div><p id="securityCoverage" class="security-note"></p><div id="securityServers" class="security-server-grid"></div><section class="security-box"><div class="security-box-head"><div><h2>Источники попыток входа SSH</h2><p>IP и сети из проверенных журналов выбранных серверов.</p></div><span id="securitySourceCount" class="security-note"></span></div><p class="security-note security-registration">Страна регистрации сети и ASN не устанавливают местоположение человека. Время и ошибки определения указаны в строках.</p><div class="security-table-tools"><label>Поиск источника<input id="securitySourceSearch" type="search" placeholder="IP, ASN, сеть или страна" autocomplete="off"></label></div><div id="securitySources"></div></section><section class="security-box"><div class="security-box-head"><div><h2>Кто заблокирован</h2><p>Активные записи, их источник, причина и доступный срок.</p></div></div><div class="security-table-tools"><label>Список<select id="securityBanScope"><option value="all">Все источники</option><option value="local">Локальные</option><option value="shared">Общий список</option><option value="both">В обоих списках</option></select></label><label>Поиск IP<input id="securityBanSearch" type="search" placeholder="IP или причина блокировки" autocomplete="off"></label></div><div id="securityBans"></div></section><section class="security-box security-preferences"><div class="security-box-head"><div><h2>Уведомления Telegram</h2><p>Получатель настраивается в разделе «Уведомления Telegram».</p></div><button type="button" class="button secondary" data-security-action="alerts">Открыть настройки ↗</button></div><form id="securityConfigForm"><label class="security-check"><input name="security" type="checkbox">Уведомления о безопасности</label><div class="security-config-grid"><label>Всплеск: ошибок пароля SSH<input name="securityFailedThreshold" type="number" min="10" max="100000" step="1" required><small id="securityThresholdHint">Число ошибок пароля за 10 минут.</small></label><label>Новых IP в общем списке<input name="securityBanThreshold" type="number" min="10" max="100000" step="1" required><small>За 10 минут по всем серверам; первый список не считается всплеском.</small></label><label>Всплеск: отброшено пакетов/мин<input name="securityPacketThreshold" type="number" min="100" max="10000000" step="1" required><small>Пакеты, отфильтрованные до проверки пароля.</small></label><label>Проверок для подтверждения<input name="securityConsecutive" type="number" min="2" max="10" step="1" required><small>Несколько последовательных измерений.</small></label><label>Повтор всплеска, минут<input name="securityCooldownMinutes" type="number" min="60" max="1440" step="1" required><small>Минимальный интервал повтора — час.</small></label><label>Сводка каждые, часов<input name="securityDigestHours" type="number" min="0" max="168" step="1" required><small>0 — сводка выключена; иначе от 6 до 168 часов.</small></label></div><p class="security-note" id="securityPolicyNote">Настройте пороги и число проверок, чтобы отсеять одиночные попытки. Эти правила не изменяют блокировки на серверах.</p><p class="security-note" id="securityTelegramStatus"></p><p class="security-error" id="securityConfigError" role="alert"></p><div class="security-config-actions"><span class="security-note" id="securityConfigState"></span><button class="button primary" type="submit" id="securityConfigSave" disabled>Сохранить уведомления</button></div></form></section><p class="security-note security-footnote">Ошибки пароля, неизвестные логины, ошибки ключа и отброшенные пакеты — разные наблюдения; они не складываются в число атак. IP из журналов SSH не всегда совпадают с источниками пакетов, отброшенных до авторизации. Отсутствие записей не доказывает отсутствия попыток. История до начала сбора остаётся неизвестной.</p>`;
  root.querySelector('#securityServer').addEventListener('change',event=>{selected=event.target.value;renderData()});
  root.querySelector('#securityMetric').addEventListener('change',event=>{metric=event.target.value;renderData()});
  root.querySelector('#securitySourceSearch').addEventListener('input',event=>{sourceSearch=event.target.value;root.querySelector('#securitySources').innerHTML=sourceTable(visibleServers())});
  root.querySelector('#securityBanScope').addEventListener('change',event=>{banScope=event.target.value;root.querySelector('#securityBans').innerHTML=banTable(visibleServers())});
  root.querySelector('#securityBanSearch').addEventListener('input',event=>{banSearch=event.target.value;root.querySelector('#securityBans').innerHTML=banTable(visibleServers())});
  const form=root.querySelector('#securityConfigForm');
  form.addEventListener('input',()=>{dirty=true;root.querySelector('#securityConfigState').textContent='Есть несохранённые изменения'});
  form.addEventListener('submit',saveConfig);
  Array.from(form.elements).forEach(element=>{element.disabled=true});
 }
 function updateToolbar(){
  const select=root.querySelector('#securityServer'),servers=rows(report?.servers);
  const nextOptions='<option value="">Все серверы</option>'+servers.map(s=>`<option value="${text(serverId(s))}">${text(s.name||s.host||serverId(s))}</option>`).join('');
  if(select.innerHTML!==nextOptions){select.innerHTML=nextOptions;if(!servers.some(s=>serverId(s)===selected))selected='';select.value=selected}
  root.querySelectorAll('[data-security-hours]').forEach(button=>{const active=Number(button.dataset.securityHours)===hours;button.classList.toggle('selected',active);button.setAttribute('aria-pressed',String(active))});
  root.querySelector('#securityChecked').textContent=report?'Отчёт: '+date(report.generatedAt)+' МСК':'Читаем статистику…';
  const error=root.querySelector('#securityError');error.hidden=!lastError;error.textContent=lastError?'Не удалось обновить статистику: '+lastError:'';
 }
 function sumKnown(values){const known=values.filter(v=>number(v)!==null);return known.length?known.reduce((a,b)=>a+b,0):null}
 function summary(servers){
  const sources=new Set(servers.flatMap(s=>sshSources(s).map(x=>x.ip).filter(Boolean)));
  const banned=new Set(servers.flatMap(s=>rows(s.bans).map(b=>b.ip).filter(Boolean))),banRecords=servers.reduce((n,s)=>n+new Set(rows(s.bans).map(b=>b.ip)).size,0);
  return `<div><span>Ошибки пароля</span><strong>${count(sumKnown(servers.map(s=>s.ssh?.failedPasswords)))}</strong><small>По полученным журналам</small></div><div><span>Неизвестные логины</span><strong>${count(sumKnown(servers.map(s=>s.ssh?.invalidUsers)))}</strong><small>Отдельный счётчик SSH</small></div><div><span>Уникальных IP в блокировке</span><strong>${count(servers.some(bansKnown)?banned.size:null)}</strong><small>${servers.some(bansKnown)?count(banRecords)+' записей на '+servers.length+' VPS':'Списки ещё не получены'}</small></div><div><span>Источников IP</span><strong>${count(servers.some(sshKnown)?sources.size:null)}</strong><small>В полученной выборке журналов</small></div>`;
 }
 function chart(s){
  const points=rows(s.history).filter(p=>number(p.ts)!==null),end=number(report.generatedAt)??Date.now()/1000,start=end-hours*3600;
  const definitions=[['failedPasswords','Пароль','#8fa5ff'],['invalidUsers','Логины','#e6b575'],['failedPublickeys','Ключи','#c693e9'],['blockedPackets','Пакеты','#66c8b3']].filter(([key])=>key===metric);
  const available=points.filter(p=>p.ts>=start&&p.ts<=end);
  if(!available.some(p=>definitions.some(([key])=>number(p[key])!==null)))return '<div class="security-chart-empty">Измерений выбранного счётчика пока нет. Пропуски не подменяются нулями.</div>';
  const peak=Math.max(0,...available.flatMap(p=>definitions.map(([key])=>number(p[key])??0))),top=Math.max(1,peak);
  const gap=(number(s.historyIntervalSeconds)??number(report.historyIntervalSeconds)??number(report.intervalSeconds)??60)*3;
  const paths=definitions.map(([key,label,color])=>{
   let previous=null,segments=[],current=[];
   const finish=()=>{if(current.length)segments.push(current);current=[]};
   for(const p of available){
    const value=number(p[key]),reset=key==='blockedPackets'&&p.counterReset;if(value===null||reset||previous!==null&&p.ts-previous>gap)finish();
    if(value!==null&&!reset){const x=Math.max(0,Math.min(600,(p.ts-start)/(end-start)*600)),y=88-Math.max(0,value)/top*80;current.push([x,y])}
    previous=p.ts;
   }
   finish();
   return `<g fill="${color}" stroke="${color}">${segments.map(segment=>segment.length===1?`<circle cx="${segment[0][0].toFixed(2)}" cy="${segment[0][1].toFixed(2)}" r="2"/>`:`<path fill="none" stroke-width="1.7" d="${segment.map((p,i)=>(i?'L':'M')+p.map(n=>n.toFixed(2)).join(',')).join(' ')}"/>`).join('')}</g>`;
  }).join('');
  return `<div class="security-chart-top"><span>${definitions[0][1]} · за ${duration(s.historyIntervalSeconds||report.historyIntervalSeconds||report.intervalSeconds)}</span><span>Пик ${count(peak)}</span></div><svg class="security-chart" viewBox="0 0 600 96" preserveAspectRatio="none" role="img" aria-label="История выбранного счётчика за выбранный период"><path class="security-chart-grid" d="M0 88H600 M0 48H600 M0 8H600"/>${paths}</svg><div class="security-chart-axis"><span>${date(start)}</span><span>${date(end)} МСК</span></div><div class="security-chart-legend">${definitions.map(([,label,color])=>`<span><i style="background:${color}"></i>${label}</span>`).join('')}</div><p class="security-note">Наблюдение с ${date(s.historyStartedAt||available[0].ts)} МСК. Пропуски не заполнены нулями.</p>`;
 }
 function resetInfo(firewall){
  if(!firewall.counterReset)return null;
  const reason=firewall.resetReason;
  if(reason==='first_sample')return {label:'Первый замер',detail:'Прирост пакетов появится после следующей сравнимой проверки.',level:'security-note'};
  if(reason==='collection_gap')return {label:'Пропуск замеров',detail:'Между проверками был пропуск. Прирост за этот интервал неизвестен.',level:'security-warning'};
  if(reason==='counter_decreased')return {label:'Счётчик уменьшился',detail:'Счётчик уменьшился или был сброшен. Прирост за этот интервал не вычисляется.',level:'security-warning'};
  if(['boot_changed','counter_epoch_changed','identity_missing'].includes(reason))return {label:'Изменилась серия измерений',detail:'Серия измерений изменилась или не подтверждена. Прирост за этот интервал неизвестен.',level:'security-note'};
  return {label:'Нет сравнимого интервала',detail:'Для прироста нужны два сравнимых измерения счётчика.',level:'security-note'};
 }
 function serverCard(s){
  const fw=s.firewall||{},ssh=s.ssh||{},reset=resetInfo(s.firewall||{});
  const packetLabel=count(fw.windowBlockedPackets);
  const recentPackets=reset?reset.label:number(fw.delta)===null?'Нет сравнимого замера':count(fw.delta)+' за '+duration(fw.intervalSeconds);
  return `<article class="security-host-card"><div class="security-host-head"><div><h2>${text(s.name||s.host||serverId(s))}</h2><code>${text(s.host||'')}</code></div><span class="security-status ${classFor(s)}">${statusFor(s)}</span></div>${s.error?`<p class="${s.partial?'security-warning':'security-error'}">${text(s.error)}</p>`:''}<div class="security-host-metrics"><div><span>Ошибки пароля</span><strong>${count(ssh.failedPasswords)}</strong><small>Период ${duration(ssh.windowSeconds)}</small></div><div><span>Неизвестные логины</span><strong>${count(ssh.invalidUsers)}</strong><small>Период ${duration(ssh.windowSeconds)}</small></div><div><span>Ошибки ключа</span><strong>${count(ssh.failedPublickeys)}</strong><small>Период ${duration(ssh.windowSeconds)}</small></div><div><span>Отброшено пакетов</span><strong class="security-packet-value">${packetLabel}</strong><small>Известные интервалы периода</small></div></div><div class="security-host-facts"><span>Всего в счётчике: <strong>${count(fw.blockedPackets)}</strong></span><span>Последний интервал: <strong>${recentPackets}</strong></span><span>Блокировок IP: <strong>${count(bansKnown(s)?new Set(rows(s.bans).map(b=>b.ip)).size:null)}</strong></span><span>Обновлено: <strong>${date(s.checkedAt)} МСК</strong></span></div>${s.partial?'<p class="security-warning">Доступна только часть источников наблюдений.</p>':''}${number(fw.unknownIntervals)>0&&(fw.resetReason!=='first_sample'||fw.unknownIntervals>1)?`<p class="security-warning">Неизвестных интервалов счётчика: ${count(fw.unknownIntervals)}. Итог пакетов может быть неполным.</p>`:''}${ssh.truncated?'<p class="security-warning">Журнал прочитан частично: количества и список источников могут быть неполными.</p>':''}${reset?`<p class="${reset.level}">${reset.detail}</p>`:''}${stale(s)?'<p class="security-warning">Это последний доступный замер. Текущее состояние не подтверждено.</p>':''}${chart(s)}</article>`;
 }
 function sourceTable(servers){
  const all=servers.flatMap(s=>sshSources(s).map(source=>({...source,server:s}))).sort((a,b)=>(number(b.attempts)??-1)-(number(a.attempts)??-1));
  const query=sourceSearch.trim().toLocaleLowerCase('ru'),matching=all.filter(s=>!query||[s.ip,s.asn,s.network,s.prefix,s.asHolder,s.country,s.server.name,s.server.host].filter(x=>typeof x==='string'||typeof x==='number').join(' ').toLocaleLowerCase('ru').includes(query));
  root.querySelector('#securitySourceCount').textContent=matching.length+(query?' из '+all.length:'')+' записей';
  if(!all.length)return servers.some(sshKnown)?'<div class="security-empty">Источников в полученной выборке нет. Убедитесь, что замеры свежие и журналы доступны.</div>':'<div class="security-empty">Данные журналов ещё не получены. Это не означает отсутствия попыток входа.</div>';
  if(!matching.length)return '<div class="security-empty">Источников по этому фильтру нет.</div>';
  return `<div class="security-table-wrap"><table class="security-table"><thead><tr><th>IP / сервер</th><th>Ошибки SSH</th><th>Сеть и ASN</th><th>Страна регистрации</th><th>Время</th></tr></thead><tbody>${matching.slice(0,300).map(source=>`<tr><td data-label="IP / сервер"><div class="security-ip"><code>${text(source.ip||'Не указан')}</code>${source.ip?`<button class="security-copy" type="button" data-security-copy="${text(source.ip)}" aria-label="Копировать IP ${text(source.ip)}">⧉</button>`:''}</div><small>${text(source.server.name||source.server.host)}</small></td><td data-label="Попытки"><strong>Пароль: ${count(source.attempts)}</strong><small>Логины: ${count(source.invalidUsers)} · ключи: ${count(source.failedPublickeys)}</small>${source.reason?`<small>${text(source.reason)}</small>`:''}</td><td data-label="Сеть и ASN"><strong>${source.asn?text(String(source.asn).startsWith('AS')?source.asn:'AS'+source.asn):'ASN неизвестен'}</strong><small>${text(source.network||'Сеть не определена')}</small>${source.prefix?`<small>${text(source.prefix)}</small>`:''}${source.asHolder?`<small>${text(source.asHolder)}</small>`:''}${source.lookupError?`<small class="security-warning">${text(source.lookupError)}</small>`:''}</td><td data-label="Страна регистрации"><strong>${text(source.country||'Не определена')}</strong><small>${text(source.countrySource||'Источник не указан')}</small><small>Определено: ${date(source.lookupAt)} МСК</small></td><td data-label="Время"><strong>Последний: ${date(source.lastSeen)}</strong><small>Первый: ${date(source.firstSeen)} МСК</small></td></tr>`).join('')}</tbody></table></div>${matching.length>300?`<p class="security-note security-table-note">Показаны первые 300 из ${matching.length} записей. Выберите отдельный сервер для более узкой выборки.</p>`:''}`;
 }
 function remaining(ban,s){
  if(ban.permanent===true)return 'Без срока';
  const expires=number(ban.expiresAt),reported=number(ban.remainingSeconds);
  const seconds=expires!==null?expires-Date.now()/1000:reported!==null&&reported>=0?reported-Math.max(0,Date.now()/1000-(number(s.checkedAt)??Date.now()/1000)):null;
  return seconds===null?'Неизвестно':seconds<=0?'Срок истёк; ждём обновления':duration(seconds);
 }
 function banTable(servers){
  const all=servers.flatMap(s=>rows(s.bans).map(ban=>({...ban,server:s})));
  if(!all.length)return servers.some(bansKnown)?'<div class="security-empty">В последних доступных списках активных блокировок нет.</div>':'<div class="security-empty">Списки блокировок ещё не получены. Это не означает отсутствия блокировок.</div>';
  const query=banSearch.trim().toLocaleLowerCase('ru'),matching=all.filter(b=>(banScope==='all'||banScope==='both'&&b.source==='both'||banScope==='local'&&['local','both'].includes(b.source)||banScope==='shared'&&['shared','both'].includes(b.source))&&(!query||[b.ip,b.reason,b.jail,b.asn,b.network,b.prefix,b.asHolder,b.country,b.countrySource,b.server.name,b.server.host].filter(x=>typeof x==='string').join(' ').toLocaleLowerCase('ru').includes(query)));
  if(!matching.length)return '<div class="security-empty">Блокировок по этому фильтру нет.</div>';
  const sourceName=b=>({local:'Локальный список',shared:'Общий список',both:'Локальный и общий списки',fail2ban:'Fail2ban'}[b.source]||b.source||'Источник не указан');
  return `<div class="security-table-wrap"><table class="security-table"><thead><tr><th>IP / сервер</th><th>Кто заблокировал</th><th>Причина</th><th>Осталось</th></tr></thead><tbody>${matching.slice(0,300).map(ban=>`<tr><td data-label="IP / сервер"><code>${text(ban.ip||'Не указан')}</code><small>${text(ban.server.name||ban.server.host)}</small><small>${text(ban.asn||'ASN неизвестен')} · Рег.: ${text(ban.country||'не определена')}</small>${ban.network?`<small>${text(ban.network)}</small>`:''}${ban.prefix?`<small>${text(ban.prefix)}</small>`:''}${ban.asHolder?`<small>${text(ban.asHolder)}</small>`:''}<small>${text(ban.countrySource||'Источник сведений не указан')} · ${number(ban.lookupAt)?date(ban.lookupAt)+' МСК':'время определения неизвестно'}</small>${ban.lookupError?`<small class="security-warning">${text(ban.lookupError)}</small>`:''}</td><td data-label="Кто заблокировал"><strong>${text(ban.jail||ban.provider||'Не указан')}</strong><small>${text(sourceName(ban))}</small></td><td data-label="Причина"><strong>${text(ban.reason||'Причина не предоставлена источником')}</strong><small>${number(ban.bannedAt)?'Начало: '+date(ban.bannedAt)+' МСК':'Начало блокировки не предоставлено'}</small><small>Впервые замечено: ${date(ban.firstObservedAt)} МСК</small></td><td data-label="Осталось"><strong>${remaining(ban,ban.server)}</strong>${stale(ban.server)||componentStale(ban.server,ban.source==='both'?['localBans','sharedBans']:ban.source==='shared'?['sharedBans']:['localBans'])?'<small class="security-warning">Список устарел или неполон</small>':''}</td></tr>`).join('')}</tbody></table></div>${matching.length>300?'<p class="security-note security-table-note">Показаны первые 300 записей. Выберите сервер.</p>':''}`;
 }
 function renderConfig(){
  if(!report?.config||saving)return;
  const form=root.querySelector('#securityConfigForm'),c=report.config;
  Array.from(form.elements).forEach(element=>{element.disabled=false});
  const status=report.alertStatus||{},connected=status.connected??(Object.hasOwn(status,'chat')?Boolean(status.chat?.id):undefined),masterEnabled=status.enabled??status.config?.enabled;
  root.querySelector('#securityTelegramStatus').textContent=connected===false?'Telegram не подключён. Привяжите чат в общих настройках уведомлений.':masterEnabled===false?'Общий переключатель Telegram выключен. Настройки безопасности сохранятся, но сообщения пока не отправляются.':'';
  if(dirty)return;
  form.elements.security.checked=Boolean(c.security);
  for(const [key,fallback] of Object.entries({securityFailedThreshold:30,securityBanThreshold:20,securityPacketThreshold:1000,securityConsecutive:2,securityCooldownMinutes:60,securityDigestHours:6}))form.elements[key].value=number(c[key])??fallback;
  root.querySelector('#securityConfigState').textContent='';
  if(number(c.securityWindowSeconds)!==null)root.querySelector('#securityThresholdHint').textContent='Ошибок SSH за '+duration(c.securityWindowSeconds)+'.';
 }
 function renderData(){
  shell();updateToolbar();renderConfig();
  if(!report){root.querySelector('#securityServers').innerHTML=lastError?'<div class="security-empty">Статистика пока недоступна. Повторите обновление.</div>':'<div class="loading"><div class="spinner"></div>Читаем наблюдения безопасности…</div>';return}
  const servers=visibleServers();
  root.querySelector('#securitySummary').innerHTML=summary(servers);
  root.querySelector('#securityCoverage').textContent='Свежих полных замеров: '+servers.filter(s=>!stale(s)&&!s.partial).length+' из '+servers.length+'. Списки и счётчики ниже относятся к последним доступным наблюдениям.';
  root.querySelector('#securityServers').innerHTML=servers.length?servers.map(serverCard).join(''):'<div class="security-empty">Серверы ещё не добавлены или первые замеры не получены.</div>';
  root.querySelector('#securitySources').innerHTML=sourceTable(servers);
  root.querySelector('#securityBans').innerHTML=banTable(servers);
 }
 async function loadSecurity(){
  if(loading){pending=true;return loading}
  const requestedHours=hours;shell();updateToolbar();if(!report)renderData();
  loading=(async()=>{
   try{const data=await readSnapshot(requestedHours);if(!Array.isArray(data.servers))throw Error('Ответ статистики имеет неизвестный формат.');if(requestedHours===hours){report=data;lastError='';renderData()}}
   catch(error){if(requestedHours===hours){lastError=String(error.message||error);renderData()}}
   finally{loading=null;if(pending){pending=false;if(!document.hidden&&filter==='security')loadSecurity()}}
  })();return loading;
 }
 async function readSnapshot(period){
  const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),15000);
  try{
   const response=await fetch('/api/security?hours='+period,{headers:{'X-Deck-Token':token},signal:controller.signal,cache:'no-store'});
   if(response.status===401){window.accountReauthRequired=true;window.location.assign('/login/');throw Error('Войдите в Server Deck заново.')}
   let data;try{data=await response.json()}catch{throw Error('Сервис статистики вернул неизвестный ответ.')}
   if(!response.ok)throw Error(data.error||'Не удалось получить статистику.');
   return data;
  }catch(error){if(error.name==='AbortError')throw Error('Сервер не ответил за 15 секунд. Последние данные сохранены на экране.');throw error}
  finally{clearTimeout(timeout)}
 }
 async function saveConfig(event){
  event.preventDefault();const form=event.currentTarget,button=root.querySelector('#securityConfigSave'),error=root.querySelector('#securityConfigError');
  const data={security:form.elements.security.checked};
  for(const key of ['securityFailedThreshold','securityBanThreshold','securityPacketThreshold','securityConsecutive','securityCooldownMinutes','securityDigestHours'])data[key]=Number(form.elements[key].value);
  error.textContent='';
  if(['securityFailedThreshold','securityBanThreshold'].some(key=>!Number.isInteger(data[key])||data[key]<10||data[key]>100000)){error.textContent='Пороги должны быть целыми числами от 10 до 100 000.';return}
  if(!Number.isInteger(data.securityPacketThreshold)||data.securityPacketThreshold<100||data.securityPacketThreshold>10000000){error.textContent='Порог пакетов — целое число от 100 до 10 000 000 в минуту.';return}
  if(!Number.isInteger(data.securityConsecutive)||data.securityConsecutive<2||data.securityConsecutive>10){error.textContent='Число проверок — от 2 до 10.';return}
  if(!Number.isInteger(data.securityCooldownMinutes)||data.securityCooldownMinutes<60||data.securityCooldownMinutes>1440){error.textContent='Повтор всплеска — от 60 до 1440 минут.';return}
  if(!Number.isInteger(data.securityDigestHours)||data.securityDigestHours<0||data.securityDigestHours>168||data.securityDigestHours>0&&data.securityDigestHours<6){error.textContent='Период сводки — 0 или от 6 до 168 часов. 0 выключает сводку.';return}
  saving=true;button.disabled=true;
  try{await api('/api/security/config',data);dirty=false;toast('Уведомления безопасности сохранены');await loadSecurity()}
  catch(e){error.textContent=e.message}
  finally{saving=false;button.disabled=false;renderConfig()}
 }
 window.securityNavigate=view=>{if(view==='security')loadSecurity()};
 document.addEventListener('click',async event=>{
  const period=event.target.closest('[data-security-hours]');if(period){hours=Number(period.dataset.securityHours);updateToolbar();loadSecurity();return}
  const action=event.target.closest('[data-security-action]');if(action){
   if(action.dataset.securityAction==='alerts'){document.querySelector('aside [data-filter="alerts"]').click();return}
   if(action.dataset.securityAction==='refresh'){action.disabled=true;try{await loadSecurity()}finally{if(action.isConnected)action.disabled=false}}return;
  }
  const copy=event.target.closest('[data-security-copy]');if(copy){try{await navigator.clipboard.writeText(copy.dataset.securityCopy);toast('IP скопирован')}catch{toast('Не удалось скопировать. Выделите IP в таблице.')}}
 });
 document.addEventListener('visibilitychange',()=>{if(!document.hidden&&filter==='security')loadSecurity()});
 setInterval(()=>{if(!document.hidden&&filter==='security'){if(report)renderData();loadSecurity()}},30000);
})();
