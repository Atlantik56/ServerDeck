function renderMaintenance(){
 for(const s of state.servers){
  const busy=controlStatus.busyServers?.includes(s.id),job=controlStatus.jobs.find(j=>j.server===s.id&&(j.kind==='reboot'||['os','os-index'].includes(j.component)));
  for(const button of document.querySelectorAll(`[data-reboot="${s.id}"],[data-os-update="${s.id}"]`))button.disabled=busy||!s.status.ok;
  const box=document.querySelector(`[data-server-task="${s.id}"]`);
  if(box)box.innerHTML=job?`<span class="control-pill ${esc(job.state)}">${esc(jobNames[job.state]||job.state)}</span><span>${esc(job.title)}${job.message?' · '+esc(job.message):''}${job.error?' · '+esc(job.error):''}</span><button class="panel-link" data-maintenance-jobs>Подробности</button>`:'';
 }
}
window.renderMaintenance=renderMaintenance;
async function openReboot(sid){
 const s=state.servers.find(s=>s.id===sid);if(!s)return;
 modal('Перезагрузка · '+s.name,ctrlLoading());
 try{
  const p=await api('/api/control/plan',{server:sid,kind:'reboot'}),info=p.summary;
  modal(info.title,`<div class="software-target"><strong>${esc(s.name)}</strong><span>${esc(p.host)}</span></div><div class="control-plan-impact">${esc(info.impact)}</div>${info.warnings.length?`<div class="control-error"><strong>Проверьте автозапуск:</strong><ul>${info.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul></div>`:''}<ul class="software-plan-steps">${info.steps.map(x=>`<li>${esc(x)}</li>`).join('')}</ul><p class="form-note">После отправки отмена из панели недоступна. План действует 5 минут. Резервная копия для reboot не создаётся; её можно сделать отдельно до перезагрузки.</p><form id="rebootForm"><label class="action-confirm control-check"><input id="rebootConfirm" type="checkbox" required><span>Подтверждаю перезагрузку <strong>${esc(s.name)}</strong> и понимаю, что подключения временно прервутся.</span></label><div id="rebootError" class="form-error"></div><div class="modal-actions"><button class="button secondary" type="button" id="rebootCancel">Отмена</button><button class="button primary reboot-confirm" id="rebootSubmit" disabled>Перезагрузить этот VPS</button></div></form>`);
  const form=$('#rebootForm'),checkbox=$('#rebootConfirm'),button=$('#rebootSubmit'),error=$('#rebootError');let submitted=false;
  $('#rebootCancel').onclick=()=>$('#modal').close();checkbox.onchange=()=>{button.disabled=submitted||!checkbox.checked};
  form.onsubmit=async e=>{
   e.preventDefault();if(submitted||!checkbox.checked)return;submitted=true;button.disabled=true;checkbox.disabled=true;error.textContent='';
   try{await api('/api/control/execute',{plan:p.id,confirmation:p.host})}
   catch(e){error.textContent=e.message+' Перечитайте статус сервера и задачи перед новым предпросмотром.';return}
   if(form.isConnected)$('#modal').close();toast('Команда перезагрузки отправляется. Ожидаем возврата сервера.');
   try{await loadControlStatus()}catch(e){toast('Перезагрузка принята. Не удалось обновить статус: '+e.message)}
  };
 }catch(error){$('#modalBody').innerHTML=ctrlError(error)}
}
function openOsUpdate(sid){
 const s=state.servers.find(s=>s.id===sid);if(!s)return;
 const ready=controlStatus.jobs.find(j=>j.server===sid&&j.component==='os-index'&&j.state==='succeeded'&&Date.now()/1000-j.finishedAt<600);
 modal('Обновить ОС · '+s.name,`<div class="software-target"><strong>${esc(s.name)}</strong><span>${esc(s.host)}</span></div><p class="form-note">Сначала выполняется <code>apt update</code> — обновляется список пакетов. Затем будет показан план обновления ОС: проверьте выбранный сервер и подтвердите действие кнопкой.</p><div class="control-plan-impact">Установка пакетов может перезапустить VPN, SSH, Docker и другие службы. Автоматической перезагрузки VPS нет.</div><p class="form-note">Перед установкой создаются резервные копии конфигурации. Пакеты обновляются как при <code>apt upgrade -y</code>: новые зависимости разрешены, удаление пакетов запрещено, локальные конфиги сохраняются.</p><div id="osPrepareStatus"></div><div id="osPrepareError" class="form-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="osCancel">Закрыть</button>${ready?'<button class="button secondary" id="osReady">Показать готовый план</button>':''}<button class="button primary" id="osPrepare">Обновить список и показать план</button></div>`);
 $('#osCancel').onclick=()=>$('#modal').close();
 const show=async()=>{showControlPlan(await api('/api/control/plan',{server:sid,kind:'update',component:'os',version:''}))};
 if($('#osReady'))$('#osReady').onclick=async()=>{try{await show()}catch(e){$('#osPrepareError').textContent=e.message}};
 $('#osPrepare').onclick=async()=>{
  const button=$('#osPrepare');button.disabled=true;if($('#osReady'))$('#osReady').disabled=true;
  try{
   const job=await api('/api/control/os-prepare',{server:sid});$('#osPrepareStatus').textContent='APT обновляет список пакетов. Окно можно закрыть; задача продолжится.';
   await loadControlStatus();
   while(button.isConnected&&$('#modal').open){
    const current=controlStatus.jobs.find(j=>j.id===job.id);
    if(current&&['succeeded','failed','needs_review','reviewed'].includes(current.state)){
     if(current.state==='succeeded')await show();else throw Error(current.error||'Не удалось обновить список пакетов');return;
    }
    await new Promise(resolve=>setTimeout(resolve,1500));await loadControlStatus();
   }
  }catch(error){if($('#osPrepareError'))$('#osPrepareError').textContent=error.message;else toast(error.message)}
 };
}
window.openOsUpdate=openOsUpdate;
document.addEventListener('click',e=>{const reboot=e.target.closest('[data-reboot]');if(reboot){openReboot(reboot.dataset.reboot);return}const os=e.target.closest('[data-os-update]');if(os){openOsUpdate(os.dataset.osUpdate);return}if(e.target.closest('[data-maintenance-jobs]'))modal('Задачи сервера',jobsHTML())});
