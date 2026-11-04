let alertsState=null,alertsLoading=false,alertsDirty=false;
const alertDate=ts=>ts?new Date(ts*1000).toLocaleString('ru-RU',{timeZone:'Europe/Moscow',day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}):'—';
const alertField=(key,label,value,min,max)=>`<label>${label}<input name="${key}" type="number" min="${min}" max="${max}" value="${Number(value)}" required></label>`;
async function loadAlerts(force=false){
 if(alertsLoading)return;alertsLoading=true;
 const root=$('#alertsDashboard');if(!alertsState)root.innerHTML='<div class="loading"><div class="spinner"></div>Читаем настройки уведомлений…</div>';
 try{alertsState=await api('/api/alerts');if(force||!root.querySelector('#alertsConfigForm')||!alertsDirty)renderAlerts()}
 catch(e){root.innerHTML=ctrlError(e)+'<button class="button secondary" data-alerts="refresh">Повторить</button>'}
 finally{alertsLoading=false}
}
window.alertsNavigate=async view=>{if(view==='alerts')await loadAlerts(true)};
function renderAlerts(){
 alertsDirty=false;
 const s=alertsState,c=s.config||{},pair=s.pairing,chat=s.chat;
 const bot=s.bot?.username?'@'+s.bot.username:'Telegram-бот';
 const root=$('#alertsDashboard');
 root.innerHTML=`<div class="alerts-top"><article class="alerts-card"><div class="alerts-card-head"><span class="alerts-icon">♧</span><div><h2>Telegram</h2><p>${esc(bot)}</p></div><span class="control-pill ${s.enabled&&chat?'on':'off'}">${s.enabled&&chat?'Уведомления включены':chat?'На паузе':'Нужна привязка'}</span></div><p>Серверы проверяются в фоне, даже когда браузер закрыт. Уведомления приходят при подтверждённой проблеме и после восстановления.</p><dl class="alerts-facts"><div><dt>Получатель</dt><dd>${chat?esc(chat.title||String(chat.id)):'Не выбран'}</dd></div><div><dt>Под наблюдением</dt><dd>Все ${state.servers.length} серверов панели</dd></div><div><dt>Последняя проверка</dt><dd>${alertDate(s.lastCheckAt)} МСК</dd></div><div><dt>Последняя отправка</dt><dd>${alertDate(s.lastSentAt)} МСК</dd></div><div><dt>В очереди</dt><dd>${Number(s.queueLength||0)}</dd></div></dl>${s.lastError?`<div class="control-error">${esc(s.lastError)}</div>`:''}${!s.configured?'<div class="control-error">Токен бота не подключён на сервере управления.</div>':''}<div class="control-actions"><button type="button" class="button primary" data-alerts="pair" ${s.configured?'':'disabled'}>${chat?'Изменить получателя':'Привязать чат'}</button><button type="button" class="button secondary" data-alerts="test" ${chat?'':'disabled'}>Отправить проверку</button><button type="button" class="button secondary" data-alerts="refresh">Обновить</button></div>${pair?`<div class="alerts-pair">${pair.blocked?`<strong>Привязка требует проверки</strong><p>${esc(pair.error||'Бот использует другое подключение. Его настройки сохранены.')}</p>`:`<strong>Подтвердите чат в Telegram</strong><p>Откройте бота по ссылке и нажмите «Запустить». Для группы отправьте команду ниже в нужный чат с ботом.</p><a class="button primary" href="${esc(pair.startUrl||'#')}" target="_blank" rel="noopener noreferrer">Открыть ${esc(bot)} ↗</a><code>${esc(pair.command||'')}</code><small>Ссылка действует до ${alertDate(pair.expiresAt)} МСК</small>`}<button type="button" class="button secondary" data-alerts="cancel">Отменить привязку</button></div>`:''}</article><article class="alerts-card"><h2>Правила оповещений</h2><form id="alertsConfigForm"><label class="alerts-check"><input name="enabled" type="checkbox" ${c.enabled?'checked':''} ${chat?'':'disabled'}>Отправлять уведомления</label><label class="alerts-check"><input name="criticalOnly" type="checkbox" ${c.criticalOnly?'checked':''}>Только критические: сервер, AWG и MTProxyL</label><p class="alerts-note">Одно сообщение о сбое и восстановлении; неактивные клиенты не считаются аварией.</p><div class="alerts-checks">${[['resources','Нагрузка CPU, память и диск'],['services','Сбои и остановка работающих служб'],['awg','Исчезновение интерфейса AWG'],['awgRx','Диагностика RX errors · не чаще раза в час'],['reboot','Запрос перезагрузки ОС']].map(([key,label])=>`<label class="alerts-check"><input name="${key}" type="checkbox" ${c[key]?'checked':''}><span data-alert-rule-label="${key}">${label}</span></label>`).join('')}</div><div class="alerts-fields">${alertField('cpuThreshold','CPU, %',c.cpuThreshold??85,10,100)}${alertField('memoryThreshold','Память, %',c.memoryThreshold??85,10,100)}${alertField('diskThreshold','Диск, %',c.diskThreshold??80,10,100)}${alertField('outageConsecutive','Проверок до тревоги о недоступности',c.outageConsecutive??2,1,10)}${alertField('resourceConsecutive','Проверок для нагрузки и диагностики RX',c.resourceConsecutive??3,1,10)}${alertField('recoveryConsecutive','Проверок для восстановления',c.recoveryConsecutive??2,1,10)}${alertField('remindersMinutes','Повтор тревоги, минут · 0 без повторов',c.remindersMinutes??0,0,1440)}</div><p class="alerts-note" id="alertsRxHint">Изменения RX errors видны в дашборде. Диагностические сообщения RX выключены по умолчанию: счётчик не доказывает отказ VPN. При включении — не чаще раза в час, без сообщений о «восстановлении». Отсутствие handshake у выключенного клиента не считается аварией.</p><div id="alertsFormError" class="form-error" role="alert"></div><div class="control-actions"><button type="submit" class="button primary" id="saveAlerts">Сохранить правила</button><button type="button" class="button secondary" data-alerts-view="health">Здоровье серверов</button></div></form></article></div><section class="alerts-card alerts-events"><h2>Текущие события</h2>${s.active?.length?s.active.map(x=>`<div class="alerts-event"><div><strong>${esc(x.serverName||x.server||'Server Deck')} · ${esc(x.title)}</strong><p>${esc(x.detail||'')}</p></div><span class="control-pill ${x.notified?'warning':''}">${x.notified?'Отправлено':x.rule?.endsWith(':rx')?'Диагностика':'Подтверждается'}</span></div>`).join(''):'<p class="alerts-note">Подтверждённых активных тревог нет.</p>'}<h3>История уведомлений</h3>${s.history?.length?[...s.history].sort((a,b)=>b.time-a.time).slice(0,20).map(x=>`<div class="alerts-event"><time>${alertDate(x.time)}</time><div><strong>${esc(x.title||x.kind||'Уведомление')}</strong><p>${esc(x.status||'')}</p></div></div>`).join(''):'<p class="alerts-note">Отправленные уведомления появятся здесь.</p>'}</section><p class="alerts-note">Мониторинг выполняет сервер управления. Для уведомления о полном отключении самого сервера управления нужна отдельная внешняя точка наблюдения.</p>`;
 $('#alertsConfigForm').onsubmit=async e=>{
  e.preventDefault();const form=e.target,b=$('#saveAlerts'),error=$('#alertsFormError');b.disabled=true;error.textContent='';
  const data={};for(const name of ['enabled','criticalOnly','resources','services','awg','awgRx','reboot'])data[name]=form.elements[name].checked;
  for(const name of data.criticalOnly?['outageConsecutive','recoveryConsecutive']:['cpuThreshold','memoryThreshold','diskThreshold','outageConsecutive','resourceConsecutive','recoveryConsecutive','remindersMinutes'])data[name]=Number(form.elements[name].value);
  if(data.criticalOnly)Object.assign(data,{resources:false,services:true,awg:true,awgRx:false,reboot:false,security:false,remindersMinutes:0,outageConsecutive:2,recoveryConsecutive:2});
  if(data.remindersMinutes>0&&data.remindersMinutes<15){error.textContent='Повтор: 0 — выключен, либо от 15 до 1440 минут.';b.disabled=false;return}
  try{await api('/api/alerts/config',data);toast('Правила уведомлений сохранены');await loadAlerts(true)}catch(e){error.textContent=e.message}finally{b.disabled=false}
 };
 const form=$('#alertsConfigForm');
 let normalValues=null;
 const criticalPreset={resources:false,services:true,awg:true,awgRx:false,reboot:false,remindersMinutes:0,outageConsecutive:2,recoveryConsecutive:2};
 const resourceFields=['cpuThreshold','memoryThreshold','diskThreshold','resourceConsecutive'];
 const hiddenRules=['resources','awgRx','reboot'];
 const syncCriticalMode=()=>{
  const critical=form.elements.criticalOnly.checked;
  if(critical&&!normalValues){
   normalValues={};for(const name of Object.keys(criticalPreset)){const input=form.elements[name];normalValues[name]=input.type==='checkbox'?input.checked:input.value}
  }
  for(const [name,value] of Object.entries(criticalPreset)){
   const input=form.elements[name];input.disabled=critical;
   if(critical){if(input.type==='checkbox')input.checked=value;else input.value=value}
   else if(normalValues){if(input.type==='checkbox')input.checked=normalValues[name];else input.value=normalValues[name]}
  }
  for(const name of resourceFields){const input=form.elements[name];input.disabled=critical;input.closest('label').hidden=critical}
  for(const name of [...hiddenRules,'remindersMinutes'])form.elements[name].closest('label').hidden=critical;
  form.querySelector('[data-alert-rule-label="services"]').textContent=critical?'Остановка MTProxyL':'Сбои и остановка работающих служб';
  $('#alertsRxHint').hidden=critical;
  if(!critical)normalValues=null;
 };
 syncCriticalMode();
 form.addEventListener('input',event=>{alertsDirty=true;if(event.target.name==='criticalOnly')syncCriticalMode()});
}
document.addEventListener('click',async e=>{
 const view=e.target.closest('[data-alerts-view]');if(view){document.querySelector('aside [data-filter="'+view.dataset.alertsView+'"]').click();return}
 const b=e.target.closest('[data-alerts]');if(!b)return;b.disabled=true;
 try{
  const action=b.dataset.alerts;
  if(action!=='refresh')await api('/api/alerts/'+action,{});
  if(action==='test')toast('Проверочное уведомление отправляется в Telegram');
  await loadAlerts(true);
 }catch(e){toast(e.message)}finally{if(b.isConnected)b.disabled=false}
});
setInterval(()=>{if(!document.hidden&&filter==='alerts')loadAlerts()},15000);
