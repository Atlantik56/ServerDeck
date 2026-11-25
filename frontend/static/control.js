let controlStatus={jobs:[],backups:[]},controlUpdates=null,clientRows=[],controlPoll=null,pendingClientConfig=null;
let updatesServerId='',historyServerId='',controlUpdatesScope='';
const clientCatalogs=new Map();
const updateReleaseChoices=new Map();
const panelTitle=p=>({lucx:'LucX / 3x-ui',mtproxyl:'MTProxyL',host:'Конфигурация хоста'}[p]||p);
const fullDate=t=>t>0?new Date(t).toLocaleString('ru-RU'):'Без срока';
const jobNames={waiting_reboot:'Ожидаем перезагрузку',waiting_services:'Ожидаем службы',queued:'В очереди',submitted:'Отправлена',submitting:'Отправка',backing_up:'Создаётся копия',running:'Выполняется',succeeded:'Завершена',failed:'Ошибка',needs_review:'Нужна проверка',unknown:'Статус неизвестен',reviewed:'Проверено оператором'};
const ctrlLoading=()=>'<div class="loading"><div class="spinner"></div>Читаем данные панелей…</div>';
const serverOptions=selected=>state.servers.map(s=>`<option value="${esc(s.id)}" ${s.id===selected?'selected':''}>${esc(s.name)} · ${esc(s.host)}</option>`).join('');
const ctrlError=e=>`<div class="control-error">${esc(e.message||e)}</div>`;

function controlWorkspaceId(section){
 const workspace=window.activeServerWorkspace?.();
 return workspace?.section===section?workspace.id:'';
}

function activeControlView(section,server){
 return server?controlWorkspaceId(section)===server:filter===section;
}

function controlReadPath(resource,server,force){
 const query=new URLSearchParams();
 if(force)query.set('force','1');
 if(server)query.set('server',server);
 return '/api/control/'+resource+(force||server?'?'+query:'');
}

async function readClientCatalog(server,force=false){
 const catalog=await api(controlReadPath('clients',server,force));
 clientCatalogs.set(server,catalog);
}

function clientCatalogServers(server){
 const rows=clientCatalogs.get(server)?.servers||[];
 return server?rows.filter(row=>row.server===server):rows;
}

async function controlNavigate(view){
 if(!['clients','backups','updates','history'].includes(view))return;
 const server=controlWorkspaceId(view);
 if(view==='history'){
  renderJobs();
  try{await loadControlStatus()}catch(e){if(activeControlView(view,server))$('#taskHistory').innerHTML=ctrlError(e)}
  return;
 }
 const root=$('#'+view+'Dashboard');
 if(view==='clients')await loadControlClients(false);
 if(view==='backups'){
  if(clientCatalogs.has(server))renderBackups();else root.innerHTML=ctrlLoading();
  try{
   if(!clientCatalogs.has(server))await readClientCatalog(server);
   await loadControlStatus();
   if(activeControlView(view,server))renderBackups();
  }catch(e){if(activeControlView(view,server))root.innerHTML=ctrlError(e)}
 }
 if(view==='updates'){
  if(controlUpdates&&controlUpdatesScope===server)renderUpdates();else root.innerHTML=ctrlLoading();
  try{await loadControlUpdates(false)}catch(e){if(activeControlView(view,server))root.innerHTML=ctrlError(e)}
 }
}
window.controlNavigate=controlNavigate;
window.selectUpdateServer=serverId=>{updatesServerId=serverId};
async function loadControlClients(force){
 const server=controlWorkspaceId('clients');
 if(clientCatalogs.has(server))renderClients();else $('#clientsDashboard').innerHTML=ctrlLoading();
 try{
  await readClientCatalog(server,force);
  if(activeControlView('clients',server))renderClients();
  await loadControlStatus();
 }catch(e){if(activeControlView('clients',server))$('#clientsDashboard').innerHTML=ctrlError(e)}
}
async function loadControlUpdates(force){
 const server=controlWorkspaceId('updates');
 window.resetProjectCatalogProgress?.();
 const updates=await api(controlReadPath('updates',server,force));
 if(activeControlView('updates',server)){
  controlUpdates=updates;controlUpdatesScope=server;
  renderUpdates();
 }
 await loadControlStatus();
}
function renderClients(){
 const root=$('#clientsDashboard'),scoped=controlWorkspaceId('clients');
 const sameScope=root.dataset.serverScope===scoped;
 const search=sameScope?root.querySelector('#clientSearch')?.value||'':'';
 const server=sameScope?root.querySelector('#clientServerFilter')?.value||'':'';
 const panel=sameScope?root.querySelector('#clientPanelFilter')?.value||'':'';
 root.dataset.serverScope=scoped;
 const catalog=clientCatalogServers(scoped);
 clientRows=catalog.flatMap(s=>s.clients.map(c=>({...c,server:s.server,serverName:s.name,host:s.host})));
 const errors=catalog.flatMap(s=>!s.ok?[scoped?s.error:`${s.name}: ${s.error}`]:s.panels.filter(p=>!p.ok).map(p=>`${scoped?'':s.name+' · '}${panelTitle(p.panel)}: ${p.error}`));
 const panels=catalog.flatMap(s=>s.panels.filter(p=>p.ok).map(p=>`${scoped?'':s.name+' · '}${panelTitle(p.panel)}: ${p.count} клиентов`));
 const serverFilter=scoped?'':`<select id="clientServerFilter" aria-label="Сервер клиентов"><option value="">Все серверы</option>${serverOptions(server)}</select>`;
 root.innerHTML=`
  <div class="control-toolbar client-toolbar"><input id="clientSearch" placeholder="Найти клиента" aria-label="Поиск клиентов" value="${esc(search)}">${serverFilter}<select id="clientPanelFilter" aria-label="Панель клиентов"><option value="">Все панели</option><option value="lucx">LucX / 3x-ui</option><option value="mtproxyl">MTProxyL</option></select><button class="button secondary" data-ctrl="refresh-clients">${icon('refresh')}Обновить</button><button class="button primary" data-ctrl="add-client" ${scoped&&!panels.length?'disabled':''}>＋ Новый клиент</button></div>
  ${errors.length?`<div class="control-errors">${errors.map(error=>`<div class="control-error">${esc(error)}</div>`).join('')}</div>`:''}
  <div class="client-results"><span>${clientRows.length} доступов · ${clientRows.filter(c=>c.enabled).length} включены</span>${scoped?'':'<button class="button secondary" type="button" data-job-history>История задач</button>'}</div>
  <div class="control-box"><div class="control-table-wrap"><table class="control-table mobile-card-table"><thead><tr><th>КЛИЕНТ / ПАНЕЛЬ</th><th>${scoped?'ПРОТОКОЛ':'СЕРВЕР / ПРОТОКОЛ'}</th><th>ДОСТУП</th><th>ТРАФИК / КВОТА</th><th>СРОК</th><th>ДЕЙСТВИЯ</th></tr></thead><tbody id="clientTableRows"></tbody></table></div></div><p class="control-subtle">Изменение клиента LucX распространяется на все его привязки в этой панели. Ключи существующих клиентов при изменении лимитов сохраняются.</p>
  ${panels.length?`<details class="client-coverage"><summary>Подключённые панели · ${panels.length}</summary><ul>${panels.map(panel=>`<li>${esc(panel)}</li>`).join('')}</ul></details>`:''}`;
 if($('#clientServerFilter'))$('#clientServerFilter').value=server;
 $('#clientPanelFilter').value=panel;
 for(const id of ['clientSearch','clientServerFilter','clientPanelFilter'])$('#'+id)?.addEventListener(id==='clientSearch'?'input':'change',renderClientRows);
 renderClientRows();
}
function renderClientRows(){
 const scoped=controlWorkspaceId('clients'),q=$('#clientSearch').value.toLowerCase(),server=$('#clientServerFilter')?.value,panel=$('#clientPanelFilter').value;
 $('#clientTableRows').innerHTML=clientRows.map((c,i)=>({c,i})).filter(({c})=>(!q||[c.name,c.comment,c.host,c.serverName].join(' ').toLowerCase().includes(q))&&(!server||c.server===server)&&(!panel||c.panel===panel)).map(({c,i})=>`<tr><td><strong>${esc(c.name)}</strong><small>${panelTitle(c.panel)}${c.comment?' · '+esc(c.comment):''}</small></td><td>${scoped?esc(c.protocols.join(' · ')):`${esc(c.serverName)}<small>${esc(c.protocols.join(' · '))}</small>`}</td><td><span class="control-pill ${c.enabled?'on':'off'}">${c.enabled?'Включён':'Выключен'}</span></td><td data-label="Трафик">${bytes(c.used)}<small>${c.quota?bytes(c.quota):'Без квоты'}</small></td><td data-label="Срок">${c.expires<0?'С первого подключения':esc(fullDate(c.expires))}</td><td><div class="control-actions"><button class="button secondary" data-ctrl="links" data-row="${i}">Конфиг</button><button class="button secondary" data-ctrl="edit-client" data-row="${i}">Изменить</button><button class="button secondary" data-ctrl="toggle-client" data-row="${i}">${c.enabled?'Отключить':'Включить'}</button><button class="small-btn stop" title="Удалить клиента" aria-label="Удалить ${esc(c.name)}" data-ctrl="delete-client" data-row="${i}">×</button></div></td></tr>`).join('')||'<tr><td class="mobile-full-cell" colspan="6">Клиентов по этому фильтру нет</td></tr>';
}
function localInputDate(ms){if(ms<=0)return '';const d=new Date(ms);return new Date(ms-d.getTimezoneOffset()*60000).toISOString().slice(0,16)}
function clientForm(c=null){
 const scoped=controlWorkspaceId('clients'),selectedServer=$('#clientServerFilter')?.value,selectedPanel=$('#clientPanelFilter')?.value;
 const available=clientCatalogServers(scoped).filter(s=>s.panels.some(p=>p.ok));
 const first=available.find(s=>s.server===(scoped||c?.server||selectedServer))||(scoped||c?null:available[0]);
 if(!first){toast('Нет доступных панелей');return}
 const editing=!!c,sid=first.server;
 const creationTargets=available.map(s=>`<option value="${esc(s.server)}" ${s.server===sid?'selected':''}>${esc(s.name)} · ${esc(s.host)}</option>`).join('');
 modal(editing?'Изменить · '+c.name:'Новый клиент',`<form id="controlClientForm" class="control-form"><div class="form-grid"><label class="wide">Сервер<select name="server" ${editing||scoped?'disabled':''}>${creationTargets}</select></label><label class="wide">Панель<select name="panel" ${editing?'disabled':''}><option value="lucx">LucX / 3x-ui</option><option value="mtproxyl">MTProxyL</option></select></label><label class="wide">Имя клиента<input name="name" required maxlength="128" value="${esc(c?.name||'')}" ${editing?'readonly':''} autocomplete="off"></label><label class="wide" id="clientInboundWrap" ${editing?'hidden':''}>Входящее подключение<select name="inbound"></select></label><label>Квота, ГиБ · 0 без лимита<input name="quota" type="number" min="0" step="any" value="${c?.quota?c.quota/1073741824:0}"></label><label>Максимум IP · 0 без лимита<input name="limitIp" type="number" min="0" step="1" value="${c?.limitIp||0}"></label><label class="wide">Действует до · пусто без срока<input name="expires" type="datetime-local" value="${localInputDate(c?.expires||0)}"></label><label class="wide" id="clientCommentWrap">Комментарий<input name="comment" maxlength="500" value="${esc(c?.comment||'')}"></label><label id="clientConnWrap">MTProxyL: максимум соединений<input name="maxConnections" type="number" min="0" step="1" value="${c?.maxConnections||0}"></label><label id="clientRateUpWrap">Скорость от клиента, Мбит/с<input name="rateUp" type="number" min="0" step="any" value="${(c?.rateUp||0)/1000000}"></label><label id="clientRateDownWrap">Скорость к клиенту, Мбит/с<input name="rateDown" type="number" min="0" step="any" value="${(c?.rateDown||0)/1000000}"></label><label class="wide control-check"><input name="enabled" type="checkbox" ${c?.enabled!==false?'checked':''}> Доступ включён</label></div><p class="control-form-note">${editing?'Приватные ключи, адреса, секреты и параметры протокола сохраняются.':'Для AWG ключи и свободный IPv4 генерируются на сервере. Создаётся один доступ на выбранном сервере.'}</p><p class="control-form-note">${c?.expires<0?'Текущий срок отсчитывается с первого подключения. Пустое поле сохранит этот режим.':''}</p><div id="clientFormError" class="form-error"></div><div class="modal-actions"><button class="button primary" id="previewClient">Предпросмотр изменения</button></div></form>`);
 const form=$('#controlClientForm');form.elements.panel.value=c?.panel||selectedPanel||'lucx';
 const update=()=>{
  const s=available.find(s=>s.server===form.elements.server.value);
  if(!s)return;
  for(const option of form.elements.panel.options)option.disabled=!s.panels.some(x=>x.ok&&x.panel===option.value);
  if(form.elements.panel.selectedOptions[0]?.disabled)form.elements.panel.value=[...form.elements.panel.options].find(o=>!o.disabled)?.value||'';
  const current=form.elements.panel.value,mt=current==='mtproxyl';
  $('#clientInboundWrap').hidden=editing||mt;$('#clientCommentWrap').hidden=mt;
  for(const id of ['clientConnWrap','clientRateUpWrap','clientRateDownWrap'])$('#'+id).hidden=!mt;
  form.elements.inbound.innerHTML=s.inbounds.filter(x=>!x.nodeId&&['awg','amneziawg','wireguard','vless','vmess','trojan','shadowsocks','hysteria','mtproto'].includes(x.protocol)).map(x=>`<option value="${x.id}">${esc(x.remark||'#'+x.id)} · ${esc(x.protocol)} · :${x.port}</option>`).join('');
 };form.elements.server.onchange=update;form.elements.panel.onchange=update;update();
 const initial=Object.fromEntries([...new FormData(form)]);
 form.onsubmit=async e=>{
  e.preventDefault();
  const preview=form.querySelector('#previewClient'),error=form.querySelector('#clientFormError');
  preview.disabled=true;error.textContent='';
  try{
   const panel=c?.panel||form.elements.panel.value,server=scoped||c?.server||form.elements.server.value,fields={};
   for(const k of ['quota','limitIp','expires',...(panel==='lucx'?['comment']:['maxConnections','rateUp','rateDown'])]){
    const value=form.elements[k].value;if(editing&&value===initial[k])continue;
    fields[k]=k==='comment'?value:k==='expires'?(value?new Date(value).getTime():0):Math.round(Number(value)*(k==='quota'?1073741824:k.startsWith('rate')?1000000:1));
   }
   if(!editing||form.elements.enabled.checked!==c.enabled)fields.enabled=form.elements.enabled.checked;
   if(editing&&!Object.keys(fields).length)throw Error('Настройки не изменились');
   const request={kind:'client',server,panel,action:editing?'edit':'create',name:form.elements.name.value,fields};
   if(!editing&&panel==='lucx')request.inboundIds=[Number(form.elements.inbound.value)];
   const plan=await api('/api/control/plan',request);
   if(form.isConnected&&$('#modal').open)showControlPlan(plan,editing?null:{server,panel,name:request.name});
  }catch(e){error.textContent=e.message;preview.disabled=false}
 };
}
function showControlPlan(plan,newClient=null){
 const server=state.servers.find(s=>s.id===plan.server),targetName=server?.name||plan.name||'Выбранный сервер';
 const info=plan.summary,labels={enabled:'Доступ включён',quota:'Квота, байт',expires:'Срок, мс Unix',limitIp:'Максимум IP',comment:'Комментарий',maxConnections:'Максимум соединений',rateUp:'Скорость от клиента, бит/с',rateDown:'Скорость к клиенту, бит/с'};
 const actionLabel=info.title.startsWith('Создать клиента')?'Создать клиента':info.title.startsWith('Изменить клиента')?'Применить изменения клиента':info.title.startsWith('Удалить клиента')?'Удалить клиента':info.title.startsWith('Восстановить резервную копию')?'Восстановить копию':info.component==='os'?'Обновить ОС':info.component==='os-index'?'Обновить список пакетов':info.title.startsWith('Откат')?'Выполнить откат':info.title.startsWith('Установить')?'Установить компонент':info.component?'Обновить компонент':'Применить изменение';
 const fields=Object.entries(info.fields||{}).map(([k,v])=>`${labels[k]||k}: ${v}`).join('\n');
 modal(info.title,`<div class="software-target"><strong>${esc(targetName)}</strong><span>${esc(plan.host)}</span></div><p class="control-form-note">План действителен 5 минут</p><div class="control-plan-impact">${esc(info.impact)}</div>${fields?`<pre class="control-preview">${esc(fields)}</pre>`:''}${info.current?`<pre class="control-preview">Сейчас: ${esc(JSON.stringify(info.current,null,2))}\nЦель: ${esc(info.version||'APT upgrade по текущему кэшу')}</pre>`:''}${info.packages?`<p class="control-subtle">${esc(info.cacheNote)}</p><pre class="control-preview">${esc(info.packages.join('\n')||'По текущему кэшу обновлений нет')}</pre>`:''}${info.steps?`<ul class="software-plan-steps">${info.steps.map(s=>`<li>${esc(s)}</li>`).join('')}</ul>`:''}${info.backupNote?`<p class="control-form-note">${esc(info.backupNote)}</p>`:''}${info.rollback?`<p class="control-form-note">${esc(info.rollback)}</p>`:''}<p class="control-form-note">Перед действием будет создана и проверена зашифрованная резервная копия. Если копирование или повторная проверка состояния не пройдут, действие не начнётся. Автоматического повтора при ошибке нет.</p><form id="executeControlForm"><label class="action-confirm control-check"><input id="controlActionConfirm" type="checkbox" required><span>Подтверждаю действие «${esc(info.title)}» на сервере <strong>${esc(targetName)}</strong>.</span></label><div id="controlExecuteError" class="form-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="cancelControlPlan">Отмена</button><button class="button primary" id="executeControlPlan" disabled>${esc(actionLabel)}</button></div></form>`);
 const form=$('#executeControlForm'),checkbox=$('#controlActionConfirm'),button=$('#executeControlPlan'),error=$('#controlExecuteError');let submitted=false;
 $('#cancelControlPlan').onclick=()=>$('#modal').close();checkbox.onchange=()=>{button.disabled=submitted||!checkbox.checked};
 form.onsubmit=async e=>{
  e.preventDefault();if(submitted||!checkbox.checked)return;submitted=true;button.disabled=true;checkbox.disabled=true;error.textContent='';
  let job;
  try{job=await api('/api/control/execute',{plan:plan.id,confirmation:plan.host})}
  catch(e){error.textContent=e.message+' Перечитайте результат задачи и откройте новый предпросмотр перед следующим действием.';return}
  if(form.isConnected&&$('#modal').open){
   if(newClient&&job?.id)showClientCreation(job.id,newClient);
   else $('#modal').close();
  }
  toast('Задача создана. Сначала выполняется резервное копирование.');
  try{await loadControlStatus()}catch(e){toast('Задача принята. Не удалось обновить статус: '+e.message)}
 };
}

function showClientCreation(id,client){
 modal('Создание клиента · '+client.name,`<p id="clientCreateStatus" role="status">Создаём клиента и подготавливаем конфигурацию…</p>
  <div class="modal-actions"><button type="button" class="button secondary" id="checkClientCreate">Проверить статус</button></div>`);
 const status=$('#clientCreateStatus');
 const check=$('#checkClientCreate');
 pendingClientConfig={id,client,status};
 check.onclick=async()=>{
  check.disabled=true;
  try{await loadControlStatus()}
  catch(e){status.textContent='Не удалось проверить статус. Повторите проверку.'}
  finally{check.disabled=false}
 };
}

function updateClientCreation(){
 const pending=pendingClientConfig;
 if(!pending)return false;
 const {id,client,status}=pending;
 if(!status.isConnected||!$('#modal').open){
  pendingClientConfig=null;
  return false;
 }
 const job=controlStatus.jobs.find(entry=>entry.id===id&&entry.server===client.server);
 if(!job)return false;
 if(job.state==='succeeded'){
  pendingClientConfig=null;
  void openClientConfig(client,true);
  const scope=controlWorkspaceId('clients');
  if(activeControlView('clients',scope)&&(!scope||scope===client.server)){
   void readClientCatalog(scope,true).then(()=>{
    if(activeControlView('clients',scope))renderClients();
   }).catch(()=>{toast('Не удалось обновить список клиентов. Воспользуйтесь кнопкой «Обновить».')});
  }
  return true;
 }
 if(['failed','needs_review','reviewed'].includes(job.state)){
  pendingClientConfig=null;
  status.textContent=job.state==='failed'?'Создание клиента завершилось с ошибкой. Проверьте историю задач.':'Результат создания клиента требует проверки в истории задач.';
  $('#checkClientCreate').hidden=true;
  return false;
 }
 status.textContent=(jobNames[job.state]||'Создаём клиента')+'… После завершения здесь появится конфигурация.';
 return false;
}

const clientConfigSchemes=new Set(['http','https','tg','mtproto','vless','vmess','trojan','ss','ssr','ssconf','shadowsocks','socks','socks5','hysteria','hysteria2','hy2','tuic','wireguard','wg','awg','amneziawg','amnezia','vpn']);
function clientConfigItems(data,name){
 const items=[],seen=new Set();
 function collect(value,subscription){
  if(typeof value==='string'){
   for(const line of value.split(/\r?\n/)){
    const body=line.trim();
    const scheme=/^([a-z][a-z0-9+.-]*):\/\/[^\s<>"']+$/i.exec(body)?.[1].toLowerCase();
    if(!clientConfigSchemes.has(scheme)||seen.has(body))continue;
    seen.add(body);
    const telegramWeb=/^https:\/\/t\.me\/proxy(?:\?|$)/i.test(body);
    const title=subscription?'Ссылка подписки':scheme==='tg'?'Ссылка для Telegram':telegramWeb?'Ссылка t.me':scheme==='https'||scheme==='http'?'Ссылка подключения':scheme.toUpperCase();
    items.push({title,body});
   }
  }else if(value&&typeof value==='object'){
   for(const part of Object.values(value))collect(part,subscription);
  }
 }
 collect(data.links,false);
 collect(data.subscriptions,true);
 for(const [id,body] of Object.entries(data.awg||{})){
  if(typeof body!=='string'||!body.trim()||!/^\d+$/.test(id))continue;
  items.push({title:'AmneziaVPN · подключение '+id,body,filename:'AmneziaVPN-'+name.replace(/[^A-Za-z0-9_-]/g,'_')+'-'+id+'.conf'});
 }
 return items;
}

async function copyClientConfig(item,field,status){
 try{
  await navigator.clipboard.writeText(item.body);
  status.textContent='Скопировано';
 }catch(_){
  if(!field.isConnected||!$('#modal').open)return;
  field.focus();
  field.select();
  field.setSelectionRange(0,field.value.length);
  status.textContent='Скопируйте выделенный текст вручную.';
 }
}

function downloadClientConfig(item){
 const url=URL.createObjectURL(new Blob([item.body],{type:'text/plain'}));
 const link=document.createElement('a');
 link.href=url;
 link.download=item.filename;
 link.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}

async function openClientConfig(client,created=false){
 modal('Конфигурация · '+client.name,`<div class="control-secret" data-client-config>${ctrlLoading()}</div>`);
 const root=$('[data-client-config]');
 try{
  const data=await api('/api/control/links',{server:client.server,panel:client.panel,name:client.name});
  if(!root.isConnected||!$('#modal').open)return;
  const items=clientConfigItems(data,client.name);
  root.innerHTML=`${created?'<p class="client-config-created" role="status">Клиент создан.</p>':''}
   ${items.length?`<p>Передавайте ссылки и конфиги только владельцу подключения.</p>${items.map((item,index)=>`
    <section class="client-config-item">
     <h3 id="clientConfigLabel${index}">${esc(item.title)}</h3>
     <textarea readonly rows="${item.filename?6:2}" spellcheck="false" aria-labelledby="clientConfigLabel${index}">${esc(item.body)}</textarea>
     <div class="client-config-actions">
      <button type="button" class="button primary" data-copy-client-config aria-describedby="clientConfigLabel${index}">${item.filename?'Скопировать конфиг':'Скопировать ссылку'}</button>
      ${item.filename?'<button type="button" class="button secondary" data-download-client-config>Скачать .conf</button>':''}
     </div>
     <p class="client-config-status" role="status"></p>
    </section>`).join('')}`:'<p>Панель не вернула ссылок или конфигураций для этого клиента.</p>'}`;
  root.querySelectorAll('.client-config-item').forEach((section,index)=>{
   const item=items[index];
   const field=section.querySelector('textarea');
   const status=section.querySelector('[role="status"]');
   section.querySelector('[data-copy-client-config]').onclick=()=>copyClientConfig(item,field,status);
   const download=section.querySelector('[data-download-client-config]');
   if(download)download.onclick=()=>downloadClientConfig(item);
  });
  if(created)root.querySelector('[data-copy-client-config]')?.focus({preventScroll:true});
 }catch(_){
  if(!root.isConnected||!$('#modal').open)return;
  root.innerHTML=`<p class="form-error" role="alert">${created?'Клиент создан, но конфигурацию получить не удалось.':'Не удалось получить конфигурацию клиента.'}</p>
   <button type="button" class="button secondary">Повторить загрузку</button>`;
  root.querySelector('button').onclick=()=>openClientConfig(client,created);
 }
}

$('#modal')?.addEventListener('close',()=>{
 if($('#modal').open)return;
 pendingClientConfig=null;
 $('[data-client-config]')?.remove();
});

async function loadControlStatus(){
 controlStatus=await api('/api/control');renderJobs();window.renderMaintenance?.();
 const createdClient=updateClientCreation();
 const running=hasRunningControlJob(controlStatus);
 if(running&&!controlPoll)controlPoll=setInterval(async()=>{
  try{
   const prior=controlStatus;
   const completedCreation=await loadControlStatus();
   const workspace=window.activeServerWorkspace?.(),view=workspace?.section||filter,server=workspace?.id||'';
   const finished=hasRunningControlJob(prior,server)&&!hasRunningControlJob(controlStatus,server);
   if(view==='software'&&finished)await loadSoftware(true);
   if(view==='backups'&&clientCatalogs.has(server))renderBackups();
   if(view==='clients'&&finished&&!completedCreation)await loadControlClients(true);
  }catch(e){toast(e.message)}
 },3500);
 if(!running&&controlPoll){clearInterval(controlPoll);controlPoll=null}
 return createdClient;
}
function hasRunningControlJob(snapshot,server=''){
 return snapshot.jobs.some(j=>(!server||j.server===server)&&!['succeeded','failed','needs_review','reviewed'].includes(j.state));
}
function renderJobs(){
 const root=$('#taskHistory');if(!root)return;
 const scoped=controlWorkspaceId('history'),server=scoped||historyServerId;
 const jobs=server?controlStatus.jobs.filter(j=>j.server===server):controlStatus.jobs;
 const opened=new Set([...root.querySelectorAll('[data-job-log][open]')].map(log=>log.dataset.jobLog));
 const serverFilter=scoped?'':`<div class="control-toolbar"><label class="control-server-filter">Сервер<select id="historyServer" aria-label="Сервер для задач"><option value="">Все серверы</option>${serverOptions(historyServerId)}</select></label></div>`;
 root.innerHTML=`<section class="control-jobs">${scoped?'':'<div class="section-bar"><h2>Задачи и результаты</h2></div>'}
  ${serverFilter}
  <div class="control-box">${jobs.length?jobs.map(j=>`<div class="control-job"><div><strong>${esc(j.title)}</strong><small>${scoped?'':esc(j.host)+' · '}${fullDate(j.createdAt*1000)}</small>${j.error?`<p class="warning">${esc(j.error)}</p>`:''}${j.message||j.result?.message?`<p>${esc(j.message||j.result.message)}</p>`:''}${j.kind==='reboot'||j.component==='os-index'?'':`<p>Копий перед действием: ${j.backups?.length||0}</p>`}${j.log?`<details data-job-log="${esc(j.id)}" ${opened.has(j.id)?'open':''}><summary class="control-subtle">Журнал задачи</summary><pre class="control-preview">${esc(j.log)}</pre></details>`:''}</div><div class="control-job-state"><span class="control-pill ${esc(j.state)}">${esc(jobNames[j.state]||j.state)}</span>${j.remoteSubmitted&&j.state==='needs_review'?`<button class="button secondary" data-ctrl="recheck-job" data-job="${esc(j.id)}" data-server="${esc(j.server)}">Перечитать статус</button><button class="button secondary" data-ctrl="ack-job" data-job="${esc(j.id)}" data-host="${esc(j.host)}">Снять блокировку…</button>`:''}</div></div>`).join(''):'<div class="empty">Задач пока нет</div>'}</div></section>`;
}
function renderBackups(){
 const root=$('#backupsDashboard'),scoped=controlWorkspaceId('backups');
 const rows=scoped?controlStatus.backups.filter(b=>b.server===scoped):controlStatus.backups;
 const sameScope=root.dataset.serverScope===scoped;
 const server=sameScope?root.querySelector('#backupServer')?.value:'';
 const panel=sameScope?root.querySelector('#backupPanel')?.value:'';
 root.dataset.serverScope=scoped;
 const serverPicker=scoped?'':`<select id="backupServer" aria-label="Сервер резервной копии">${serverOptions(server)}</select>`;
 root.innerHTML=`<div class="control-stats"><div class="control-stat"><span>Зашифрованных копий</span><strong>${rows.length}</strong><small>На сервере управления, в зашифрованном хранилище</small></div><div class="control-stat"><span>Проверена целостность</span><strong>${rows.filter(b=>b.verified).length}</strong><small>Расшифрование и контрольная сумма</small></div><div class="control-stat"><span>Последняя копия</span><strong style="font-size:17px">${rows[0]?fullDate(rows[0].createdAt*1000):'Ещё нет'}</strong><small>Расписание не включено</small></div></div><div class="control-note warning">Сохраните ключ восстановления отдельно от архива. Без него зашифрованные копии не расшифровать. Проверка целостности не означает проверенного восстановления на сервер.</div><div class="control-box"><div class="control-box-head"><div><h3>Создать резервную копию</h3><p>Без остановки работающих служб</p></div><button class="button secondary" data-ctrl="recovery-key">Сохранить ключ восстановления</button></div><div class="control-create-row">${serverPicker}<select id="backupPanel" aria-label="Панель резервной копии"><option value="lucx">LucX / 3x-ui</option><option value="mtproxyl">MTProxyL</option></select><button class="button primary" data-ctrl="create-backup">＋ Создать копию</button><button class="button secondary" data-ctrl="refresh-backups">${icon('refresh')}Обновить</button></div></div><div class="control-box"><div class="control-table-wrap"><table class="control-table mobile-card-table"><thead><tr><th>${scoped?'ПАНЕЛЬ':'СЕРВЕР / ПАНЕЛЬ'}</th><th>СОЗДАНА</th><th>РАЗМЕР</th><th>ПРОВЕРКА</th><th>ДЕЙСТВИЯ</th></tr></thead><tbody>${rows.map(b=>`<tr><td><strong>${scoped?esc(panelTitle(b.panel)):esc(b.serverName)}</strong>${scoped?'':`<small>${esc(b.host)} · ${esc(panelTitle(b.panel))}</small>`}</td><td data-label="Создана">${fullDate(b.createdAt*1000)}<small>${b.reason==='manual'?'По запросу':b.reason==='initial'?'Первая копия':'Перед изменением'}</small></td><td data-label="Размер">${bytes(b.size)}</td><td><span class="control-pill on">Целостность проверена</span></td><td><div class="control-actions"><button class="button secondary" data-ctrl="download-backup" data-backup="${b.id}">Скачать</button><button class="button secondary" data-ctrl="verify-backup" data-backup="${b.id}">Проверить</button>${b.panel!=='host'?`<button class="button secondary" data-ctrl="restore-backup" data-backup="${b.id}" data-server="${esc(b.server)}">Восстановить…</button>`:'<span class="control-subtle">Ручное восстановление</span>'}</div></td></tr>`).join('')||'<tr><td class="mobile-full-cell" colspan="5">Создайте первую копию выбранной панели.</td></tr>'}</tbody></table></div></div><p class="control-subtle">LucX: согласованный снимок SQLite и TLS-файлы панели. MTProxyL: штатный архив менеджера. Копии содержат секреты и зашифрованы AES-256-CBC с проверкой HMAC-SHA256. ОС, образы Docker и сторонние приложения не входят. Восстановление разрешено на исходный сервер при совпадении версии панели; текущие настройки хоста LucX сохраняются.</p>${scoped?'':'<button class="button secondary" type="button" data-job-history>История задач</button>'}`;
 const select=$('#backupPanel'),serverSelect=$('#backupServer'),create=root.querySelector('[data-ctrl="create-backup"]');
 if(panel)select.value=panel;
 const updatePanels=()=>{
  const target=scoped||serverSelect.value;
  const entry=clientCatalogServers(scoped).find(s=>s.server===target);
  for(const option of select.options)option.disabled=!entry?.panels.some(p=>p.panel===option.value&&p.ok);
  if(!select.value||select.selectedOptions[0]?.disabled)select.value=[...select.options].find(o=>!o.disabled)?.value||'';
  create.disabled=!select.value;
 };
 if(serverSelect)serverSelect.onchange=updatePanels;
 updatePanels();
}
const updateStateLabels={update_available:'Вышло обновление',latest:'Последняя версия репозитория',ahead:'Установлена версия новее релиза',unknown:'Версия не подтверждена'};
function updateSourceLink(value,label='Релиз в репозитории ↗'){
 try{const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.port||!['github.com','gitlab.com'].includes(u.hostname))return '';return `<a class="control-release-link" href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`}catch(e){return ''}
}
function updateStatusHTML(status){
 const code=Object.hasOwn(updateStateLabels,status?.state)?status.state:'unknown';
 return `<span class="update-status ${code}" data-update-state="${code}">${esc(updateStateLabels[code])}</span>`;
}
function renderCustomUpdates(s){
 return (controlUpdates.projects||[]).filter(p=>p.bindings?.[s.server]).map(p=>{
  const binding=p.bindings[s.server],status=binding.updateStatus||{state:'unknown',current:binding.version,latest:p.releases?.[0]?.version,message:'Актуальность версии пока не подтверждена.'};
  return `<div class="control-update-component custom-update-component"><div><div class="update-component-title"><strong>${esc(p.name)}</strong>${updateStatusHTML(status)}</div><dl class="update-version-pair"><div><dt>Указана вручную</dt><dd>${esc(binding.version||'Не указана')}</dd></div><div><dt>Релиз репозитория</dt><dd>${esc(status.latest||'Не получен')}</dd></div></dl><p class="control-subtle">${esc(status.message||'Версия указана оператором; наличие и состояние приложения автоматически не проверяются.')}</p><p class="control-subtle">Версия указана ${fullDate((binding.checkedAt||0)*1000)}. Проверка установки по SSH не выполнялась.</p>${updateSourceLink(p.sourceUrl,'Открыть проект ↗')}</div><div class="control-update-actions"><button class="button secondary" data-software-server="${esc(s.server)}">Изменить привязку в каталоге</button></div></div>`;
 }).join('');
}
function renderUpdates(){
 const scoped=controlWorkspaceId('updates');
 if(!controlUpdates||controlUpdatesScope!==scoped)return;
 const up=controlUpdates.upstream||{},titles={lucx:'LucX / 3x-ui',telemt:'Движок Telemt',mtproxyl:'Менеджер MTProxyL','mtproxyl-panel':'Веб-панель MTProxyL',os:'Пакеты Ubuntu / Debian'};
 const allServers=controlUpdates.servers;
 if(!scoped&&updatesServerId&&!allServers.some(s=>s.server===updatesServerId))updatesServerId='';
 const server=scoped||updatesServerId;
 const servers=server?allServers.filter(s=>s.server===server):allServers;
 const projects=(controlUpdates.projects||[]).filter(p=>!scoped||p.bindings?.[scoped]);
 const statuses=servers.flatMap(s=>Object.values(s.updateStatus||{}));
 const counts={update_available:0,latest:0,ahead:0,unknown:servers.filter(s=>!s.ok).length};
 statuses.forEach(s=>{if(s.state in counts)counts[s.state]++});
 const serverFilter=scoped?'':`<label class="control-server-filter">Сервер<select id="updatesServer" aria-label="Сервер для обновлений"><option value="">Все серверы</option>${allServers.map(s=>`<option value="${esc(s.server)}" ${s.server===updatesServerId?'selected':''}>${esc(s.name)} · ${esc(s.host)}</option>`).join('')}</select></label>`;
 const historyLink=scoped?'':`<button class="button secondary" type="button" data-job-history="${esc(updatesServerId)}">История задач</button>`;
 $('#updatesDashboard').innerHTML=`<div class="control-toolbar updates-toolbar">${serverFilter}<button class="button secondary" data-ctrl="refresh-updates">Проверить версии</button>${historyLink}<span class="control-subtle updates-checked">${scoped?'Сервер':'Серверы'} ${fullDate(controlUpdates.checkedAt*1000)}<br>Релизы ${fullDate((up.checkedAt||0)*1000)}</span></div>${window.projectCatalogProgressHTML?.(projects)||''}<div class="update-summary" aria-label="Сводка обновлений"><div class="update-summary-item available"><strong>${counts.update_available}</strong><span>Доступны обновления</span></div><div class="update-summary-item latest"><strong>${counts.latest}</strong><span>Последняя версия</span></div><div class="update-summary-item unknown"><strong>${counts.unknown}</strong><span>Нужна проверка</span></div>${counts.ahead?`<div class="update-summary-item"><strong>${counts.ahead}</strong><span>Новее релиза</span></div>`:''}</div><div class="control-note">Статусы сравнивают установленную версию с проверенными стабильными релизами проекта. Пакеты ОС и версии, указанные вручную, проверяются отдельно. Обновление начинается после предпросмотра, подтверждения сервера и резервной копии.</div><div class="control-card-grid">${servers.map(s=>`<article class="control-box" data-update-server="${esc(s.server)}">${scoped?'':`<div class="control-box-head"><div><h3>${esc(s.name)}</h3><p>${esc(s.host)}</p></div><span class="control-pill ${s.ok?'on':'off'}">${s.ok?'Доступен':'Нет данных'}</span></div>`}${s.ok?[...(s.versions.lucx?['lucx']:[]),...(s.versions.mtproxyl?['telemt','mtproxyl']:[]),...(s.versions['mtproxyl-panel']?['mtproxyl-panel']:[]),'os'].map(component=>{
 const release=up[component],entries=release?.releases||[],current=component==='os'?s.versions.os:s.versions[component]||'Не определена',status=s.updateStatus?.[component]||{state:'unknown',latest:null,message:'Недостаточно данных для сравнения.'},isOs=component==='os',atLatest=!isOs&&['latest','ahead'].includes(status.state);
 return `<div class="control-update-component"><div><div class="update-component-title"><strong>${titles[component]}</strong>${isOs?'<span class="update-status unknown">Пакеты требуют отдельной проверки</span>':updateStatusHTML(status)}</div><dl class="update-version-pair"><div><dt>${isOs?'Система':'Установлено'}</dt><dd>${esc(current)}</dd></div><div><dt>${isOs?'Источник пакетов':'Последний релиз'}</dt><dd>${esc(isOs?'Репозиторий ОС':status.latest||'Не получен')}</dd></div></dl>${isOs?'<p class="control-subtle">Версия ОС не показывает наличие обновлений пакетов. Предпросмотр обновит индекс APT и покажет точный план.</p>':`<p class="control-subtle">${esc(status.message)}</p>${updateSourceLink(status.sourceUrl)}`}${release&&!release.ok?`<p class="warning">${esc(release.error)}</p>`:''}</div><div class="control-update-actions">${!isOs?`<select data-update-release="${esc(s.server)}:${component}" aria-label="Версия ${titles[component]} на ${esc(s.host)}">${entries.map(r=>`<option value="${esc(r.version)}" ${r.version===updateReleaseChoices.get(s.server+':'+component)?'selected':''}>${esc(r.version)}</option>`).join('')}</select>`:''}<button class="button ${status.state==='update_available'?'primary':'secondary'}" data-ctrl="plan-update" data-component="${component}" data-server="${esc(s.server)}" ${!isOs&&(!entries.length||atLatest)?'disabled':''}>${atLatest?'Обновление не требуется':isOs?'Проверить пакеты…':status.state==='update_available'?'Обновить…':'Предпросмотр'}</button>${component==='telemt'?`<button class="button secondary" data-ctrl="rollback-telemt" data-server="${esc(s.server)}">Откат…</button>`:''}</div></div>`;
 }).join('')+renderCustomUpdates(s)+`<div class="control-update-component"><p>Ядро: ${esc(s.versions.kernel)}<br>Модуль AWG: ${esc(s.versions.awg||'Нет данных')}<br>${s.versions.rebootRequired?'<span class="warning">ОС запрашивает перезагрузку; автоматически не выполняется.</span>':'Запроса перезагрузки ОС нет.'}</p></div>`:`<div class="control-error">${esc(s.error)}</div>`}</article>`).join('')}</div><p class="control-subtle">LucX и Telemt устанавливаются на выбранную опубликованную версию. MTProxyL обновляется штатным CLI, его веб-панель — проверенной сборкой. Если есть локальная правка Zapret2, обновление менеджера блокируется до проверки её совместимости. Неизвестный или устаревший результат не означает актуальную версию.</p>`;window.scheduleProjectCatalogRefresh?.(projects);
}
async function downloadControl(path,name){const r=await fetch(path,{headers:{'X-Deck-Token':token}});if(!r.ok){const v=await r.json();throw Error(v.error)}const blob=await r.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
document.addEventListener('change',e=>{
 const input=e.target;
 if(input.id==='updatesServer'){
  updatesServerId=input.value;
  renderUpdates();
  $('#updatesServer').focus();
 }
 if(input.id==='historyServer'){
  historyServerId=input.value;
  renderJobs();
  $('#historyServer').focus();
 }
 if(input.dataset.updateRelease)updateReleaseChoices.set(input.dataset.updateRelease,input.value);
});
document.addEventListener('click',async e=>{
 const history=e.target.closest('[data-job-history]');
 if(history){
  historyServerId=history.dataset.jobHistory;
  renderJobs();
  document.querySelector('aside [data-filter="activity"]').click();
  return;
 }
 const b=e.target.closest('[data-ctrl]');if(!b)return;const op=b.dataset.ctrl,c=b.dataset.row!==undefined?clientRows[Number(b.dataset.row)]:null;b.disabled=true;
 try{
  if(op==='refresh-clients')await loadControlClients(true);
  if(op==='add-client')clientForm();
  if(op==='edit-client')clientForm(c);
  if(op==='toggle-client'||op==='delete-client')showControlPlan(await api('/api/control/plan',{kind:'client',server:c.server,panel:c.panel,name:c.name,action:op==='delete-client'?'delete':'edit',fields:op==='delete-client'?{}:{enabled:!c.enabled}}));
  if(op==='links')await openClientConfig(c);
  if(op==='refresh-backups'){await loadControlStatus();renderBackups()}
  if(op==='create-backup'){const server=controlWorkspaceId('backups')||$('#backupServer')?.value,panel=$('#backupPanel')?.value;if(!server||!panel)throw Error('Нет доступной панели для резервного копирования');await api('/api/control/backup',{server,panel});toast('Копирование началось. Службы продолжают работать.');await loadControlStatus();renderBackups()}
  if(op==='download-backup')await downloadControl('/api/control/download?id='+b.dataset.backup,'server-deck-'+b.dataset.backup+'.sdbackup');
  if(op==='verify-backup'){const r=await api('/api/control/verify',{backup:b.dataset.backup});modal('Проверка резервной копии',`<p class="control-form-note">${esc(r.message)}</p><pre class="control-preview">${esc(JSON.stringify(r.manifest,null,2))}</pre>`)}
  if(op==='restore-backup')showControlPlan(await api('/api/control/plan',{kind:'restore',server:b.dataset.server,backup:b.dataset.backup}));
  if(op==='recovery-key'){modal('Ключ восстановления',`<p class="control-form-note">Сохраните этот файл отдельно от резервных копий, например в защищённом хранилище. Он открывает все копии этого Server Deck. Передавать его на VPS не требуется.</p><div class="modal-actions"><button class="button primary" id="downloadRecoveryKey">Скачать ключ</button></div>`);$('#downloadRecoveryKey').onclick=async()=>{try{await downloadControl('/api/control/recovery-key','server-deck-recovery.key');toast('Ключ загружен. Сохраните его в защищённом месте.')}catch(e){toast(e.message)}}}
  if(op==='refresh-updates')await loadControlUpdates(true);
  if(op==='rollback-telemt')showControlPlan(await api('/api/control/plan',{kind:'update',server:b.dataset.server,component:'telemt-rollback',version:''}));
  if(op==='plan-update'){const component=b.dataset.component;if(component==='os'){openOsUpdate(b.dataset.server);return}const version=b.closest('.control-update-component').querySelector('select').value;showControlPlan(await api('/api/control/plan',{kind:'update',server:b.dataset.server,component,version}))}
  if(op==='ack-job'){
   const job=controlStatus.jobs.find(j=>j.id===b.dataset.job),host=job?.host||b.dataset.host,server=state.servers.find(s=>s.id===job?.server||s.host===host),targetName=server?.name||'Выбранный сервер',jobId=b.dataset.job;
   modal('Подтвердить проверку сервера',`<div class="software-target"><strong>${esc(targetName)}</strong><span>${esc(host)}</span></div><p class="control-form-note">Проверьте клиентов, службы и результат задачи. Эта кнопка только разрешает новые действия; незавершённая операция не повторяется. Блокировку работающей задачи снять нельзя.</p><form id="ackControlForm"><label class="action-confirm control-check"><input id="ackControlConfirm" type="checkbox" required><span>Я проверил состояние сервера <strong>${esc(targetName)}</strong> и разрешаю новые задачи.</span></label><div id="ackControlError" class="form-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="ackControlCancel">Отмена</button><button class="button primary" id="ackControlSubmit" disabled>Состояние проверено — разрешить новые задачи</button></div></form>`);
   const form=$('#ackControlForm'),checkbox=$('#ackControlConfirm'),button=$('#ackControlSubmit'),error=$('#ackControlError');let submitted=false;
   $('#ackControlCancel').onclick=()=>$('#modal').close();checkbox.onchange=()=>{button.disabled=submitted||!checkbox.checked};
   form.onsubmit=async ev=>{
    ev.preventDefault();if(submitted||!checkbox.checked)return;submitted=true;button.disabled=true;checkbox.disabled=true;error.textContent='';
    try{await api('/api/control/acknowledge',{job:jobId,confirmation:host})}
    catch(e){error.textContent=e.message+' Перечитайте состояние задачи перед новым подтверждением.';return}
    if(form.isConnected)$('#modal').close();try{await loadControlStatus()}catch(e){toast('Проверка подтверждена. Не удалось обновить статус: '+e.message)}
   };
  }
  if(op==='recheck-job'){await api('/api/control/recheck',{server:b.dataset.server,job:b.dataset.job});setTimeout(()=>loadControlStatus().catch(e=>toast(e.message)),2000);toast('Перечитываем статус; повторного выполнения нет.')}
 }catch(e){if(op==='links')$('#modalBody').innerHTML=ctrlError(e);else toast(e.message)}finally{if(b.isConnected)b.disabled=false}
});
