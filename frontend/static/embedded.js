let nativePanel=null,nativeOpening=false;
window.embeddedNavigate=view=>{if(view==='native'&&!nativePanel)$('#nativeDashboard').innerHTML='<div class="empty">Выберите LucX или MTProxyL в разделе «Панели и приложения».</div>'};
async function openEmbedded(server,panel){
 if(nativeOpening)return;nativeOpening=true;
 const s=state.servers.find(x=>x.id===server);$('#nativeNav').hidden=false;$('#nativeNav').click();
 $('#nativeDashboard').innerHTML='<div class="loading"><div class="spinner"></div>Подключаем существующую панель…<small>Создаём отдельную защищённую сессию</small></div>';
 try{
  const r=await api('/api/embedded/open',{server,panel});if(filter!=='native')return;nativePanel={server,panel};
  const name=panel==='lucx'?'LucX / 3x-ui':'MTProxyL';const sections=panel==='lucx'?[['','Обзор'],['inbounds','Подключения'],['clients','Клиенты'],['groups','Группы'],['nodes','Узлы'],['routing','Маршрутизация'],['outbound','Исходящие'],['settings','Настройки']]:[['','Обзор'],['users','Пользователи'],['runtime','Телеметрия'],['traffic','Трафик'],['expert','Экспертные параметры']];
  $('#pageTitle').textContent=name;$('#pageSubtitle').textContent=(s?.name||server)+' · '+(s?.host||'');
  $('#nativeDashboard').innerHTML=`<div class="native-toolbar"><div><span class="control-pill on">Подключено</span><strong>${esc(name)}</strong><span>${esc(s?.host||'')}</span></div><div><select id="nativeSection" aria-label="Раздел встроенной панели" disabled>${sections.map(([value,title])=>`<option value="${value}">${title}</option>`).join('')}</select><button class="button secondary" id="reloadNative">↻ Переподключить</button><button class="button secondary" id="expandNative">Развернуть</button><button class="button secondary" id="closeNative">Закрыть</button></div></div><p class="native-note">Это действующая панель сервера. Перед изменением настроек создаётся резервная копия. Обновление и восстановление доступны через соответствующие разделы Server Deck.</p><div class="native-frame-wrap" id="nativeFrameWrap"><iframe id="nativeFrame" name="nativeFrame" title="${esc(name)} · ${esc(s?.host||'')}" referrerpolicy="no-referrer" sandbox="allow-scripts allow-same-origin allow-forms allow-downloads allow-modals allow-popups"></iframe></div>`;
  const frame=$('#nativeFrame'),section=$('#nativeSection');frame.onload=()=>{try{if(frame.contentWindow.location.href==='about:blank')return}catch(e){}section.disabled=false};section.onchange=()=>{frame.src=r.origin+r.entry+section.value};
  const form=document.createElement('form');form.method='POST';form.action=r.origin+'/_deck/bootstrap';form.target='nativeFrame';form.hidden=true;
  const grant=document.createElement('input');grant.name='grant';grant.value=r.grant;form.appendChild(grant);document.body.appendChild(form);form.submit();form.remove();
  $('#reloadNative').onclick=()=>openEmbedded(server,panel);
  $('#expandNative').onclick=()=>{document.body.classList.toggle('native-expanded');$('#expandNative').textContent=document.body.classList.contains('native-expanded')?'Свернуть':'Развернуть'};
  $('#closeNative').onclick=()=>{nativePanel=null;$('#nativeDashboard').innerHTML='';$('#nativeNav').hidden=true;document.body.classList.remove('native-expanded');document.querySelector('[data-filter="panels"]').click()};
 }catch(e){$('#nativeDashboard').innerHTML=`<div class="control-error">${esc(e.message)}</div><button class="button secondary" id="retryNative">Повторить подключение</button>`;$('#retryNative').onclick=()=>openEmbedded(server,panel)}
 finally{nativeOpening=false}
}
document.addEventListener('click',e=>{const b=e.target.closest('[data-embed-panel]');if(b)openEmbedded(b.dataset.server,b.dataset.embedPanel)});
