let nativeRequest=null;

window.clearEmbeddedWorkspace=()=>{
 nativeRequest=null;
 $('#nativeDashboard')?.replaceChildren();
 const nav=$('#nativeNav');
 if(nav)nav.hidden=true;
 document.body.classList.remove('native-expanded');
};
window.embeddedNavigate=view=>{
 if(view==='native'&&!$('#nativeDashboard').hasChildNodes()){
  $('#nativeDashboard').innerHTML='<div class="empty">Выберите LucX или MTProxyL в разделе «Панели и приложения».</div>';
 }
};

async function openEmbedded(server,panel){
 const s=state.servers.find(item=>item.id===server);
 if(!s||nativeRequest?.server===server&&nativeRequest.panel===panel)return;
 const scoped=typeof window.openServerWorkspace==='function';
 if(scoped)await window.openServerWorkspace(server,'native');
 else{
  const nav=$('#nativeNav');
  if(!nav)return;
  nav.hidden=false;
  nav.click();
 }
 const inPanelView=()=>{
  if(!scoped)return filter==='native';
  const workspace=window.activeServerWorkspace?.();
  return workspace?.id===server&&workspace.section==='native';
 };
 if(!inPanelView()||nativeRequest?.server===server&&nativeRequest.panel===panel)return;
 const request={server,panel};
 nativeRequest=request;
 const stillOpen=()=>nativeRequest===request&&inPanelView();
 const root=$('#nativeDashboard');
 root.innerHTML='<div class="loading"><div class="spinner"></div>Подключаем панель…</div>';
 try{
  const result=await api('/api/embedded/open',{server,panel});
  if(!stillOpen())return;
  const name=panel==='lucx'?'LucX / 3x-ui':'MTProxyL';
  const sections=panel==='lucx'?[['','Обзор'],['inbounds','Подключения'],['clients','Клиенты'],['groups','Группы'],['nodes','Узлы'],['routing','Маршрутизация'],['outbound','Исходящие'],['settings','Настройки']]:[['','Обзор'],['users','Пользователи'],['runtime','Телеметрия'],['traffic','Трафик'],['expert','Экспертные параметры']];
  if(!scoped){
   $('#pageTitle').textContent=name;
   $('#pageSubtitle').textContent=s.name+' · '+s.host;
  }
  root.innerHTML=`<div class="native-toolbar"><div><span class="control-pill on">Подключено</span><strong>${esc(name)}</strong>${scoped?'':`<span>${esc(s.host)}</span>`}</div><div><select id="nativeSection" aria-label="Раздел встроенной панели" disabled>${sections.map(([value,title])=>`<option value="${value}">${title}</option>`).join('')}</select><button class="button secondary" id="reloadNative">Переподключить</button><button class="button secondary" id="expandNative">Развернуть</button><button class="button secondary" id="closeNative">К панелям</button></div></div><p class="native-note">Перед изменением настроек создаётся резервная копия.</p><div class="native-frame-wrap" id="nativeFrameWrap"><iframe id="nativeFrame" name="nativeFrame" title="${esc(name)} · ${esc(s.host)}" referrerpolicy="no-referrer" sandbox="allow-scripts allow-same-origin allow-forms allow-downloads allow-modals allow-popups"></iframe></div>`;
  const frame=$('#nativeFrame'),section=$('#nativeSection');
  frame.onload=()=>{try{if(frame.contentWindow.location.href==='about:blank')return}catch(e){}section.disabled=false};
  section.onchange=()=>{frame.src=result.origin+result.entry+section.value};

  const form=document.createElement('form');
  form.method='POST';
  form.action=result.origin+'/_deck/bootstrap';
  form.target='nativeFrame';
  form.hidden=true;
  const grant=document.createElement('input');
  grant.name='grant';
  grant.value=result.grant;
  form.appendChild(grant);
  document.body.appendChild(form);
  try{form.submit()}finally{form.remove()}

  $('#reloadNative').onclick=()=>openEmbedded(server,panel);
  $('#expandNative').onclick=()=>{
   const expanded=document.body.classList.toggle('native-expanded');
   $('#expandNative').textContent=expanded?'Свернуть':'Развернуть';
  };
  $('#closeNative').onclick=()=>{
   window.clearEmbeddedWorkspace();
   if(scoped)window.openServerWorkspace(server,'panels');
   else document.querySelector('[data-filter="panels"]')?.click();
  };
 }catch(error){
  if(!stillOpen())return;
  root.innerHTML=`<div class="control-error">${esc(error.message)}</div><button class="button secondary" id="retryNative">Повторить подключение</button>`;
  $('#retryNative').onclick=()=>openEmbedded(server,panel);
 }finally{
  if(nativeRequest===request)nativeRequest=null;
 }
}
document.addEventListener('click',event=>{
 const button=event.target.closest('[data-embed-panel]');
 if(button)openEmbedded(button.dataset.server,button.dataset.embedPanel);
});
