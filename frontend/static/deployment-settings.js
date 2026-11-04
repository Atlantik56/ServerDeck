(() => {
 'use strict';
 let loading=false, info=null, activePlan=null, polling=null;
 const encode=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const container=()=>{
  let card=document.getElementById('deploymentSettings');
  if(!card){card=document.createElement('section');card.id='deploymentSettings';card.className='deployment-settings-view';card.setAttribute('aria-label','Домен и адрес панели');document.getElementById('settingsDashboard')?.after(card)}
  return card;
 };
 const isSettings=()=>document.body.classList.contains('filter-settings');
 const stageLabel=stage=>({queued:'Задача принята',preflight:'Проверка настроек',certificate:'Выпуск сертификата',switch:'Применение адреса',verify:'Проверка HTTPS',complete:'Домен подключён',error:'Требуется внимание',submit:'Не удалось запустить задачу',lock:'Сервер занят'}[stage]||'Проверка задачи');
 function render(){
  const root=container();
  if(!info){root.innerHTML='<article class="deployment-card"><h2>Домен панели</h2><p>Читаем настройки адреса…</p></article>';return}
  const busy=info.busy,job=info.job;
  root.innerHTML=`<article class="deployment-card"><div class="deployment-head"><div><h2>Домен и HTTPS</h2><p>Адрес этой панели управления</p></div><span class="control-pill ${info.mode==='domain'?'on':''}">${info.mode==='ip'?'IP · свой сертификат':info.mode==='domain'?'Домен · HTTPS':'Настройка'}</span></div><div class="deployment-current"><span>Текущий адрес</span><a href="${encode(info.origin||window.location.origin)}" rel="noopener">${encode(info.origin||window.location.origin)}</a></div>${info.mode==='ip'?'<p class="deployment-note">Сейчас используется IP и отдельный порт. Сертификат создан при установке; браузер может попросить подтвердить доверие. После подключения домена будет выпущен доверенный сертификат Let’s Encrypt. Встроенным панелям нужен домен.</p>':''}${info.error?`<p class="form-error">${encode(info.error)}</p>`:''}${info.available&&!info.canChange?'<p class="form-error">Certbot или защищённый шаблон не установлен. Требуется завершить настройку помощника на сервере управления.</p>':''}${job?`<div class="deployment-job" role="status"><strong>${encode(stageLabel(job.stage))}</strong><span>${encode(job.error||'')}</span>${job.newOrigin?`<a href="${encode(job.newOrigin)}/login/" rel="noopener">Открыть новый адрес ↗</a>`:''}</div>`:''}<form id="deploymentDomainForm"><div class="deployment-fields"><label>Домен панели<input name="domain" autocomplete="off" placeholder="deck.example.com" value="${encode(info.mode==='domain'?info.host:'')}" required ${!info.available||!info.canChange||busy?'disabled':''}></label><label>Email для сертификата<input name="email" type="email" autocomplete="email" value="${encode(info.email||'')}" required ${!info.available||!info.canChange||busy?'disabled':''}></label></div><p class="deployment-note">Сначала направьте A-запись домена на ${encode(info.publicIp||'IP сервера управления')}. Порты 80 и 443 должны быть доступны. Другие веб-серверы не будут остановлены. Применение сохраняет резервную копию и перезапускает только Server Deck и его страницу входа.</p><div id="deploymentError" class="form-error" role="alert"></div><div class="deployment-actions"><button type="submit" class="button primary" ${!info.available||!info.canChange||busy?'disabled':''}>Проверить и показать план</button><button type="button" class="button secondary" id="deploymentRefresh">Проверить состояние</button></div></form><div id="deploymentPlan"></div></article>`;
  document.getElementById('deploymentRefresh').onclick=()=>load(true,true);
  document.getElementById('deploymentDomainForm').onsubmit=async e=>{
   e.preventDefault();const form=e.currentTarget,error=document.getElementById('deploymentError'),button=form.querySelector('button[type=submit]');button.disabled=true;error.textContent='';activePlan=null;
   try{
    const values=Object.fromEntries(new FormData(form));activePlan=await api('/api/deployment/plan',{domain:values.domain.trim().toLowerCase(),email:values.email.trim()});
    document.getElementById('deploymentPlan').innerHTML=`<section class="deployment-preview"><h3>План смены адреса</h3><div class="deployment-address-change"><span>${encode(activePlan.oldOrigin)}</span><strong>→ ${encode(activePlan.newOrigin)}</strong></div><ul>${(activePlan.summary||[]).map(s=>`<li>${encode(s)}</li>`).join('')}</ul><p class="deployment-note">План действует пять минут. После смены адреса войдите с прежней учётной записью. Пароль, серверы, ключи и настройки VPN сохраняются.</p><label>Введите ${encode(activePlan.domain)} для подтверждения<input id="deploymentConfirmation" autocomplete="off"></label><div class="deployment-actions"><button type="button" class="button primary" id="deploymentApply">Подключить домен</button><button type="button" class="button secondary" id="deploymentCancel">Отмена</button></div><div id="deploymentApplyError" class="form-error" role="alert"></div></section>`;
    document.getElementById('deploymentCancel').onclick=()=>{activePlan=null;document.getElementById('deploymentPlan').innerHTML=''};
    document.getElementById('deploymentApply').onclick=apply;
    document.getElementById('deploymentConfirmation').focus();
   }catch(err){error.textContent=err.message}finally{button.disabled=false}
  };
 }
 async function apply(){
  if(!activePlan)return;
  const confirmation=document.getElementById('deploymentConfirmation').value,button=document.getElementById('deploymentApply'),error=document.getElementById('deploymentApplyError');error.textContent='';
  if(confirmation!==activePlan.domain){error.textContent='Введите домен точно, как в плане.';return}
  button.disabled=true;
  try{
   const result=await api('/api/deployment/apply',{plan:activePlan.id,confirmation});
   const newOrigin=result.newOrigin;activePlan=null;info.busy=true;info.job=result.job;render();
   const hint=document.createElement('p');hint.className='deployment-note';hint.textContent='Задача продолжит работу при закрытии страницы. Во время переключения панель может временно не отвечать. Новый адрес: '+newOrigin;container().querySelector('.deployment-card').append(hint);
   if(polling)clearInterval(polling);let tries=0;
   polling=setInterval(()=>{if(++tries>60){clearInterval(polling);polling=null;return}load(true,false)},5000);
  }catch(err){error.textContent=err.message;button.disabled=false}
 }
 async function load(force=false,showLoading=false){
  if(loading)return;loading=true;
  if(showLoading&& !activePlan)container().setAttribute('aria-busy','true');
  try{
   const next=force?await api('/api/deployment/check',{}):await api('/api/deployment');
   const oldBusy=info?.busy;info=next;
   if(!activePlan)render();
   if(oldBusy&&!info.busy&&polling){clearInterval(polling);polling=null}
  }catch(err){
   if(!info){info={available:false,error:err.message};render()}
   else if(showLoading){const node=document.getElementById('deploymentError');if(node)node.textContent=err.message}
  }finally{loading=false;container().removeAttribute('aria-busy')}
 }
 const previous=window.settingsNavigate;
 window.settingsNavigate=async view=>{const result=previous?.(view);if(view==='settings'){container();load()}return result};
 document.addEventListener('click',e=>{if(e.target.closest('[data-filter="settings"]'))load()});
 if(isSettings())load();
})();
