(() => {
 'use strict';

 const card=document.getElementById('panelUpdatesCard');
 const banner=document.getElementById('panelUpdatesBanner');
 if(!card||!banner)return;

 const checkPath='/api/panel-update';
 const applyPath=checkPath+'/apply';
 const resumeKey='server-deck-panel-update-view';
 const dismissedKey='server-deck-panel-release-dismissed';
 const watchTime=5*60*1000;
 const labels={
  current:'Установлена актуальная версия',
  available:'Доступно обновление',
  unknown:'Статус не подтверждён',
  unversioned:'Текущая версия не определена',
  disabled:'Обновление через панель недоступно',
 };
 const jobLabels={
  queued:'Задача принята',
  preflight:'Проверяем установленную панель',
  download:'Скачиваем и проверяем сборку',
  staging:'Готовим файлы обновления',
  backup:'Сохраняем предыдущую версию',
  apply:'Устанавливаем обновление и перезапускаем панель',
  verify:'Проверяем новую версию',
  rollback:'Восстанавливаем предыдущую версию',
  complete:'Обновление установлено',
  succeeded:'Обновление установлено',
  failed:'Не удалось установить обновление',
  needs_review:'Проверьте состояние панели',
 };
 const finished=new Set(['succeeded','failed','needs_review']);
 const text=value=>esc(typeof value==='string'?value.slice(0,1800):'');
 const validVersion=value=>typeof value==='string'&&/^v?\d+\.\d+\.\d+$/.test(value);
 const versionKey=value=>validVersion(value)?value.replace(/^v/,''):'';
 const date=value=>typeof value==='number'&&Number.isFinite(value)&&value>0
  ?new Date(value*1000).toLocaleString('ru-RU',{timeZone:'Europe/Moscow',day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})+' МСК'
  :'Ещё не проверяли';

 let info=null,request=null,timeout=null,error='',submitError='',checking=false,applying=false,watchUntil=0;
 let submittedVersion='',lastRender='',dismissedRelease='';
 try{dismissedRelease=localStorage.getItem(dismissedKey)||''}catch(_){}

 function releaseLink(value){
  try{
   const url=new URL(value);
   if(url.origin==='https://github.com'&&!url.username&&!url.password&&!url.search&&!url.hash
      &&/^\/Atlantik56\/ServerDeck\/releases\/tag\/v?\d+\.\d+\.\d+$/.test(url.pathname))return url.href;
  }catch(_){}
  return '';
 }

 function jobState(job){return job?.state||job?.stage||''}
 function jobBusy(job){return Boolean(job&&!finished.has(jobState(job)))}
 function awaiting(){return watchUntil>Date.now()||jobBusy(info?.job)}
 function canApply(){
  return info?.supported===true&&info.state==='available'&&validVersion(info.latest?.version)
    &&!info.error&&!error&&!checking&&!applying&&!awaiting();
 }

 function showUpdates(){
  const pageLink=document.querySelector('aside [data-filter="updates"]');
  if(!pageLink)return;
  pageLink.click();
  card.scrollIntoView({block:'start'});
  card.querySelector('h2')?.focus({preventScroll:true});
 }

 function render(){
  const signature=JSON.stringify([info,error,submitError,checking,applying,awaiting(),dismissedRelease]);
  if(lastRender===signature)return;
  lastRender=signature;
  const latest=info?.latest,installed=info?.installed,job=info?.job;
  const releaseVersion=versionKey(latest?.version);
  const offer=info?.state==='available'&&Boolean(releaseVersion)&&!info.error&&!error&&!awaiting();
  banner.hidden=!offer||dismissedRelease===releaseVersion;
  banner.innerHTML=banner.hidden?'':`
   <strong>Доступна новая версия Server Deck ${text(latest.version)}</strong>
   <div class="panel-update-actions">
    <button type="button" class="button secondary" data-panel-update-view>Открыть обновления</button>
    <button type="button" class="button secondary" data-panel-update-dismiss>Скрыть</button>
   </div>`;

  const link=releaseLink(latest?.url);
  const state=info?.state;
  const status=checking?'Проверяем GitHub…':error?'Статус не подтверждён':labels[state]||'Получаем состояние…';
  const currentJob=finished.has(jobState(job))?jobState(job):job?.stage||jobState(job);
  const jobTitle=Object.hasOwn(jobLabels,currentJob)?jobLabels[currentJob]:job?'Обновление выполняется':'Ожидаем состояние задачи';
  const revision=typeof installed?.revision==='string'?installed.revision.slice(0,12):'';
  card.innerHTML=`
   <article class="panel-update-card">
    <div class="panel-update-head">
     <h2 tabindex="-1">Обновление Server Deck</h2>
     <span class="panel-update-state ${offer?'is-available':''}">${status}</span>
    </div>
    <dl class="panel-update-versions">
     <div><dt>Установлена</dt><dd>${text(installed?.version)||'Не определена'}${revision?` <small>${text(revision)}</small>`:''}</dd></div>
     <div><dt>Стабильный релиз GitHub</dt><dd>${text(latest?.version)||'Версия не получена'}</dd></div>
     <div><dt>Последняя проверка</dt><dd>${date(info?.checkedAt)}</dd></div>
    </dl>
    ${info?.supported===false&&state!=='disabled'?'<p class="panel-update-note">Установка из интерфейса на этом сервере недоступна.</p>':''}
    ${info?.error||error?`<p class="panel-update-error" role="status">${text(error||info.error)}</p>`:''}
    ${submitError?`<p class="panel-update-error" role="status">${text(submitError)}</p>`:''}
    ${job||awaiting()?`<div class="panel-update-job" role="status"><strong>${jobTitle}</strong>
     ${job?.version?` <span>${text(job.version)}</span>`:''}
     ${job?.error||job?.message?`<p>${text(job.error||job.message)}</p>`:''}
     ${awaiting()&&error?'<p>Панель может временно не отвечать во время перезапуска. Повторяем проверку состояния.</p>':''}
    </div>`:''}
    <div class="panel-update-actions">
     <button type="button" class="button secondary" data-panel-update-check ${checking||applying||awaiting()?'disabled':''}>Проверить релизы GitHub</button>
     ${info?.supported===true&&state==='available'?`<button type="button" class="button primary" data-panel-update-preview ${canApply()?'':'disabled'}>Установить ${text(latest?.version)}…</button>`:''}
     ${link?`<a class="panel-update-link" href="${text(link)}" target="_blank" rel="noopener noreferrer">Релиз на GitHub ↗</a>`:''}
    </div>
   </article>`;
 }

 function schedule(){
  clearTimeout(timeout);
  if(!document.hidden)timeout=setTimeout(()=>load(),awaiting()?2500:60000);
 }

 async function reloadIfRestarted(){
  try{
   const oldToken=document.querySelector('meta[name="deck-token"]')?.content;
   const response=await fetch('/',{cache:'no-store',credentials:'same-origin',mode:'same-origin',redirect:'error'});
   if(!response.ok||!response.headers.get('Content-Type')?.includes('text/html'))return;
   const newToken=(await response.text()).match(/<meta name="deck-token" content="([A-Za-z0-9_-]{43})">/)?.[1];
   if(!newToken||!oldToken||newToken===oldToken)return;
   try{sessionStorage.setItem(resumeKey,'updates')}catch(_){}
   window.location.reload();
  }catch(_){}
 }

 function load(force=false){
  if(request)return request;
  if(document.hidden&&!force)return;
  checking=force;
  if(force)submitError='';
  if(checking)render();
  request=(async()=>{
   try{
    const next=await api(checkPath+(force?'?force=1':''));
    if(!next||typeof next.supported!=='boolean'||!Object.hasOwn(labels,next.state))throw Error('Неизвестный ответ проверки версии.');
    info=next;
    error='';
    const target=versionKey(submittedVersion);
    const recorded=versionKey(next.job?.version);
    if(target&&recorded===target)submitError='';
    if(target&&(versionKey(next.installed?.version)===target
       ||recorded===target&&finished.has(jobState(next.job)))){
     watchUntil=0;
     submittedVersion='';
    }
   }catch(err){
    error=String(err.message||'Не удалось проверить состояние панели.');
    if(awaiting())await reloadIfRestarted();
   }finally{
    request=null;
    checking=false;
    render();
    schedule();
   }
  })();
  return request;
 }

 function preview(){
  if(!canApply())return;
  const version=info.latest.version;
  modal('Обновить Server Deck',`
   <form id="panelUpdateConfirmForm" class="control-form">
    <p class="control-form-note">Установлена ${text(info.installed?.version)||'неизвестная версия'}. Будет установлена версия <strong>${text(version)}</strong>.</p>
    <ul class="panel-update-steps">
     <li>Проверить сборку из официального релиза GitHub.</li>
     <li>Сохранить предыдущие файлы программы.</li>
     <li>Перезапустить и проверить панель управления. Она может временно не отвечать.</li>
    </ul>
    ${info.latest.summary?`<p class="panel-update-note">${text(info.latest.summary)}</p>`:''}
    <label class="action-confirm"><input type="checkbox" id="panelUpdateConfirm" required><span>Подтверждаю установку Server Deck ${text(version)}.</span></label>
    <div class="modal-actions">
     <button type="button" class="button secondary" id="panelUpdateCancel">Отмена</button>
     <button type="submit" class="button primary" id="panelUpdateSubmit" disabled>Установить обновление</button>
    </div>
   </form>`);
  const form=document.getElementById('panelUpdateConfirmForm');
  const checkbox=document.getElementById('panelUpdateConfirm');
  const button=document.getElementById('panelUpdateSubmit');
  const dialog=document.getElementById('modal');
  document.getElementById('panelUpdateCancel').onclick=()=>dialog.close();
  checkbox.onchange=()=>{button.disabled=applying||!checkbox.checked};
  form.onsubmit=async event=>{
   event.preventDefault();
   if(!dialog.open||!checkbox.checked||applying||!canApply())return;
   if(info.latest.version!==version){
    dialog.close();
    error='Доступная версия изменилась. Проверьте её перед установкой.';
    render();
    return;
   }
   applying=true;
   button.disabled=true;
   checkbox.disabled=true;
   submittedVersion=version;
   watchUntil=Date.now()+watchTime;
   submitError='';
   render();
   try{
    const result=await api(applyPath,{version});
    if(result?.accepted!==true)throw Error('Подтверждение запуска не получено.');
    info={...info,job:result.job||{version,state:'queued'}};
    error='';
   }catch(err){
    // The service may restart before sending a response. Poll without resubmitting.
    watchUntil=Date.now()+20000;
    submitError='Не получили подтверждение запуска. '+String(err.message||'');
   }finally{
    if(form.isConnected&&dialog.open)dialog.close();
    applying=false;
    render();
    load();
   }
  };
 }

 document.addEventListener('click',event=>{
  if(event.target.closest('[data-panel-update-view]'))showUpdates();
  if(event.target.closest('[data-panel-update-dismiss]')){
   dismissedRelease=versionKey(info?.latest?.version);
   try{localStorage.setItem(dismissedKey,dismissedRelease)}catch(_){}
   render();
  }
  if(event.target.closest('[data-panel-update-check]')&&!awaiting()&&!applying)load(true);
  if(event.target.closest('[data-panel-update-preview]'))preview();
 });
 document.addEventListener('visibilitychange',()=>{
  if(document.hidden){clearTimeout(timeout);return}
  load();
 });

 let resume=false;
 try{
  resume=sessionStorage.getItem(resumeKey)==='updates';
  if(resume)sessionStorage.removeItem(resumeKey);
 }catch(_){}
 render();
 if(resume)showUpdates();
 load();
})();
