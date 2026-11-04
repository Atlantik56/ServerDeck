/* All writes require a fresh plan and typing the selected host. */
(() => {
 let requestGeneration=0;
 const errorHTML=e=>`<p class="form-error" role="alert">${esc(e?.message||e)}</p>`;
 const number=(name,value,min,max,label)=>`<label>${label}<input name="${name}" type="number" min="${min}" max="${max}" step="1" value="${esc(value)}" required></label>`;
 function selector(servers,sid){return `<label class="wide">Сервер<select id="f2bServer">${servers.map(s=>`<option value="${esc(s.id||s.server)}" ${(s.id||s.server)===sid?'selected':''}>${esc(s.name)} · ${esc(s.host)}</option>`).join('')}</select></label>`}
 async function open(sid){
  const generation=++requestGeneration;
  const servers=Array.isArray(state?.servers)?state.servers:[];
  sid=sid||document.querySelector('#securityServer')?.value||servers[0]?.id;
  if(!sid){modal('Fail2ban','<p>Сначала добавьте сервер в Server Deck.</p>');return}
  modal('Настройка Fail2ban',`${selector(servers,sid)}<div class="loading"><div class="spinner"></div>Читаем действующую jail sshd…</div>`);
  document.querySelector('#f2bServer').onchange=e=>open(e.target.value);
  try{
   const data=await api('/api/fail2ban?server='+encodeURIComponent(sid));
   if(generation!==requestGeneration||!document.querySelector('#modal')?.open)return;
   const target=`<div class="software-target"><strong>${esc(data.name)}</strong><span>${esc(data.host)}</span></div>`;
   if(!data.editable){
    modal('Настройка Fail2ban',`${selector(servers,sid)}${target}<p class="form-note">${esc(data.message||'Редактирование недоступно')}</p>${!data.installed?'<button class="button primary" type="button" id="f2bInstall">Открыть каталог компонентов</button>':''}`);
    document.querySelector('#f2bServer').onchange=e=>open(e.target.value);
    if(document.querySelector('#f2bInstall'))document.querySelector('#f2bInstall').onclick=()=>openSoftware(sid);
    return;
   }
   const effective=data.effective,pending=data.pendingJobs||[];
   modal('Настройка Fail2ban',`${selector(servers,sid)}${target}<p class="form-note">Активная jail <strong>sshd</strong> · порты ${data.sshPorts.map(esc).join(', ')} · ${data.jails.length} jail на сервере.</p>
    ${pending.length?`<div class="f2b-pending"><strong>Есть операция с неподтверждённым результатом.</strong><p>Повторное применение заблокировано. Проверьте результат перед новым планом.</p>${pending.map(job=>`<button class="button secondary" data-f2b-review="${esc(job.job)}" data-f2b-host="${esc(data.host)}">Проверить операцию и снять блокировку…</button>`).join('')}</div>`:''}
    <form id="f2bForm"><div class="form-grid f2b-grid">${number('maxretry',effective.maxretry,3,100,'Неудачных входов до блокировки')}${number('findtime',effective.findtime,60,86400,'Окно подсчёта, секунд')}${number('bantime',effective.bantime,60,2592000,'Срок блокировки, секунд')}<label class="wide">Дополнительные исключения IP / CIDR<textarea name="ignoreip" rows="3" placeholder="Один IP или CIDR на строку" maxlength="5200"></textarea><small>Дополнительные доверенные адреса. Исключения уменьшают защиту для этих источников.</small></label></div>
    <details class="f2b-protected"><summary>Сохраняемые исключения · ${data.protectedIgnoreip.length}</summary><code>${data.protectedIgnoreip.map(esc).join('<br>')}</code><p>Действующие исключения и адрес подключения панели ${esc(data.controllerIp)} добавляются автоматически.</p></details><p class="form-note">Будут изменены только пороги jail sshd. Настройки SSH, другие jail и службы VPN сохраняются. Действующие списки блокировок не очищаются.</p><div id="f2bError" class="form-error" role="alert"></div><div class="modal-actions"><button type="button" class="button secondary" id="f2bClose">Закрыть</button><button class="button primary" id="f2bPreview" ${pending.length?'disabled':''}>Предпросмотр изменений</button></div></form>`);
   document.querySelector('#f2bServer').onchange=e=>open(e.target.value);
   document.querySelector('#f2bClose').onclick=()=>document.querySelector('#modal').close();
   document.querySelector('#f2bForm').onsubmit=async event=>{
    event.preventDefault();const form=event.target,button=form.querySelector('#f2bPreview');button.disabled=true;
    try{
     const fields=new FormData(form),plan=await api('/api/fail2ban/plan',{server:sid,maxretry:Number(fields.get('maxretry')),findtime:Number(fields.get('findtime')),bantime:Number(fields.get('bantime')),ignoreip:String(fields.get('ignoreip')).split(/[\s,]+/).filter(Boolean)});
     preview(plan);
    }catch(error){document.querySelector('#f2bError').textContent=error.message;button.disabled=false}
   };
  }catch(error){if(generation===requestGeneration)document.querySelector('#modalBody').innerHTML=errorHTML(error)}
 }
 function preview(plan){
  const fields=[['maxretry','Попыток'],['findtime','Окно, с'],['bantime','Блокировка, с']];
  modal(plan.summary.title,`<div class="software-target"><strong>${esc(plan.name)}</strong><span>${esc(plan.host)}</span></div><div class="control-plan-impact">${esc(plan.summary.impact)}</div><div class="f2b-diff"><table><thead><tr><th>Параметр</th><th>Сейчас</th><th>После применения</th></tr></thead><tbody>${fields.map(([key,label])=>`<tr><td>${label}</td><td>${esc(plan.before.effective[key])}</td><td>${esc(plan.settings[key])}</td></tr>`).join('')}</tbody></table></div><details class="f2b-protected"><summary>Итоговые исключения · ${plan.effectiveIgnoreip.length}</summary><code>${plan.effectiveIgnoreip.map(esc).join('<br>')}</code></details><p class="form-note">${esc(plan.summary.preserved)}</p><ol class="software-plan-steps">${plan.summary.steps.map(step=>`<li>${esc(step)}</li>`).join('')}</ol><form id="f2bApplyForm"><label>Введите ${esc(plan.host)} для подтверждения<input id="f2bHost" required autocomplete="off" placeholder="${esc(plan.host)}"></label><p class="form-note">План действует 5 минут. Применение отправляется один раз.</p><div id="f2bError" class="form-error" role="alert"></div><div class="modal-actions"><button class="button secondary" type="button" id="f2bBack">Назад</button><button class="button primary" id="f2bApply" disabled>Применить к этому серверу</button></div></form>`);
  document.querySelector('#f2bBack').onclick=()=>open(plan.server);
  document.querySelector('#f2bHost').oninput=e=>document.querySelector('#f2bApply').disabled=e.target.value.trim()!==plan.host;
  document.querySelector('#f2bApplyForm').onsubmit=async event=>{
   event.preventDefault();const button=document.querySelector('#f2bApply');button.disabled=true;button.textContent='Применяем и проверяем…';document.querySelector('#f2bBack').disabled=true;
   try{
    const result=await api('/api/fail2ban/apply',{plan:plan.id,confirmation:document.querySelector('#f2bHost').value.trim()});
    modal('Результат настройки Fail2ban',`<div class="software-target"><strong>${esc(plan.name)}</strong><span>${esc(plan.host)}</span></div><p class="${result.state==='succeeded'?'f2b-success':'form-error'}" role="status">${esc(result.message||result.error||result.state)}</p>${result.backup?`<p class="form-note">Резервная копия на сервере: <code>${esc(result.backup)}</code></p>`:''}<div class="modal-actions"><button class="button secondary" id="f2bResultClose">Закрыть</button><button class="button primary" id="f2bResultRead">Проверить действующие настройки</button></div>`);
    document.querySelector('#f2bResultClose').onclick=()=>document.querySelector('#modal').close();document.querySelector('#f2bResultRead').onclick=()=>open(plan.server);
   }catch(error){document.querySelector('#f2bError').textContent=error.message+' Не отправляйте повторную команду до проверки состояния.';button.textContent='Результат не подтверждён'}
  };
 }
 document.addEventListener('click',async event=>{
  const opener=event.target.closest('[data-fail2ban-server]');if(opener){open(opener.dataset.fail2banServer);return}
  const review=event.target.closest('[data-f2b-review]');if(!review)return;
  const job=review.dataset.f2bReview,host=review.dataset.f2bHost;
  modal('Проверить результат Fail2ban',`<p class="form-note">Будет проверено текущее состояние jail sshd и отсутствие другой удалённой операции. Параметры повторно не применяются.</p><form id="f2bReviewForm"><label>Введите ${esc(host)} для подтверждения ручной проверки<input name="confirmation" required autocomplete="off"></label><div id="f2bError" class="form-error"></div><div class="modal-actions"><button class="button primary">Проверить и снять блокировку</button></div></form>`);
  document.querySelector('#f2bReviewForm').onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;try{const result=await api('/api/fail2ban/review',{job,confirmation:e.target.elements.confirmation.value.trim()});modal('Fail2ban',`<p role="status">${esc(result.message)}</p>`)}catch(error){document.querySelector('#f2bError').textContent=error.message;b.disabled=false}};
 });
 function mount(){const toolbar=document.querySelector('#securityToolbar');if(!toolbar||toolbar.querySelector('[data-fail2ban-server]'))return;const button=document.createElement('button');button.type='button';button.className='button secondary';button.dataset.fail2banServer='';button.textContent='Настроить Fail2ban';toolbar.appendChild(button)}
 const security=document.querySelector('#securityDashboard');if(security)new MutationObserver(mount).observe(security,{childList:true,subtree:true});mount();
 window.openFail2ban=open;
})();
