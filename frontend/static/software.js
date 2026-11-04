let softwareData=null,softwareSelected='',softwareLoading=null;
const softwareTitles={lucx:'LucX / 3x-ui',mtproxyl:'MTProxyL','mtproxyl-panel':'Веб-панель MTProxyL',telemt:'Telemt',awg:'AmneziaWG',fail2ban:'Fail2ban'};
const softwareVersions=component=>softwareData?.upstream[component==='awg'?'lucx':component]?.releases||[];
const softwareVersion=value=>String(value||'').replace(/^mtproxyl-panel-v/,'').replace(/^v/,'');

async function loadSoftware(force=false){
 if(softwareLoading)return softwareLoading;
 softwareLoading=(async()=>{
  const root=$('#softwareDashboard');
  if(!softwareData)root.innerHTML='<div class="loading"><div class="spinner"></div>Проверяем установленные компоненты и релизы…<small>Сервисы продолжают работать</small></div>';
  try{softwareData=await api('/api/control/software'+(force?'?force=1':''));renderSoftware();await loadControlStatus()}
  catch(e){root.innerHTML=ctrlError(e)+ '<button class="button secondary" data-software="refresh">Повторить проверку</button>'}
  finally{softwareLoading=null}
 })();return softwareLoading;
}
window.softwareNavigate=async view=>{if(view==='software'){resetProjectCatalogProgress();await loadSoftware(false)}};
function openSoftware(sid){softwareSelected=sid||softwareSelected;$('#modal').close();document.querySelector('[data-filter="software"]').click();if(softwareData)renderSoftware()}

function renderSoftware(){
 const root=$('#softwareDashboard'),servers=softwareData.servers;
 if(!servers.some(s=>s.server===softwareSelected))softwareSelected=servers[0]?.server||'';
 const selected=servers.find(s=>s.server===softwareSelected),inv=selected?.inventory;
 root.innerHTML=`<div class="software-toolbar"><label>Сервер<select id="softwareServer">${servers.map(s=>`<option value="${esc(s.server)}" ${s.server===softwareSelected?'selected':''}>${esc(s.name)} · ${esc(s.host)}</option>`).join('')}</select></label><button class="button secondary" data-software="refresh">↻ Проверить компоненты</button><button class="button primary" data-software="add-project">＋ Проект по ссылке Git</button><button class="button secondary" data-software="updates">Центр обновлений ↗</button></div>
 <div class="software-banner"><div><span class="software-eyebrow">КАТАЛОГ КОМПОНЕНТОВ</span><h2>Установка и обслуживание в одном месте</h2><p>Выберите компонент и проверьте план. Изменения начнутся после подтверждения сервера и резервного копирования.</p></div><span class="software-counter">${softwareData.components.length}<small>компонентов</small></span></div>
 ${selected&&!selected.ok?ctrlError(selected.error):''}
 ${inv?`<div class="software-host"><span class="live-dot"></span><strong>${esc(selected.name)}</strong><span>${esc(inv.os)} · ${esc(inv.arch)}</span><span>Проверено ${clock(selected.checkedAt)}</span></div>${!inv.supported?'<div class="control-error">Автоматические рецепты поддерживают Ubuntu/Debian с systemd на x86_64 и aarch64.</div>':''}<div class="software-grid">${softwareData.components.filter(c=>!c.custom).map(c=>softwareCard(c,selected)).join('')}</div>`:''}
 ${renderProjectCatalog(selected)}<div class="control-note software-note">Новые панели LucX и MTProxyL слушают только localhost и открываются через Server Deck. Установка не заменяет существующие панели. Занятый порт, изменение конфигурации или ошибка копирования остановят задачу.</div>
 <div class="software-existing"><span>Панель уже установлена и имеет другой адрес?</span><button class="button secondary" data-software="existing" ${selected?'':'disabled'}>Подключить существующую</button></div><div id="softwareJobs"></div>`;
 if($('#softwareServer'))$('#softwareServer').onchange=e=>{softwareSelected=e.target.value;renderSoftware()};renderJobs();scheduleProjectCatalogRefresh(softwareData.components.filter(c=>c.custom));
}
function softwareCard(c,s){
 const inv=s.inventory,x=inv.components[c.id],entries=softwareVersions(c.id),present=x.installed,dockerAwg=c.id==='awg'&&x.containers?.length;
 const kind=present?'update':'install',version=c.id==='fail2ban'?x.candidate:entries[0]?.version;
 let blocked='';
 if(!inv.supported)blocked='ОС или архитектура не поддерживается рецептом.';
 else if(c.id==='lucx'&&x.foreignVariant)blocked='Установлен другой вариант 3x-ui. Замена на LucX не выполняется автоматически.';
 else if(c.id==='awg'&&x.protected)blocked='Защищён: AWG используется интерфейсами или контейнерами. Обслуживание ядра сейчас заблокировано.';
 else if(c.id==='telemt'&&!inv.components.mtproxyl.installed)blocked='Движок устанавливается вместе с MTProxyL.';
 else if(c.id==='mtproxyl-panel'&&!inv.components.mtproxyl.installed)blocked='Сначала установите менеджер MTProxyL.';
 else if(!present&&x.conflict)blocked='Найдены существующие файлы или контейнеры. Установка поверх запрещена.';
 else if(!version)blocked=c.id==='fail2ban'?'Нет кандидата в текущем кэше APT.':'Релизы не получены. Повторите проверку.';
 else if(present&&['lucx','mtproxyl','mtproxyl-panel','fail2ban'].includes(c.id)&&softwareVersion(x.version)===softwareVersion(version))blocked='Установлена актуальная версия из доступного каталога.';
 const installedText=dockerAwg?'Работает в Docker':present?'Установлен':'Не установлен';
 const detail=dockerAwg?x.containers.join(', '):x.version||'—';
 const target=c.id==='awg'?'Рецепт '+(version||'—'):(version||'—');
 const embed=present&&['lucx','mtproxyl-panel'].includes(c.id);
 return `<article class="software-card"><div class="software-card-top"><span class="software-icon">${esc(c.icon)}</span><div><span class="software-category">${esc(c.category)}</span><h3>${esc(c.name)}</h3></div><span class="control-pill ${present||dockerAwg?'on':'off'}">${installedText}</span></div><p class="software-description">${esc(c.description)}</p><dl><div><dt>Установлено</dt><dd>${esc(detail)}</dd></div><div><dt>${c.id==='awg'?'Источник рецепта':'Доступный релиз'}</dt><dd>${esc(target)}</dd></div></dl>${blocked?`<p class="software-blocked">${esc(blocked)}</p>`:'<p class="software-ready">Проверка зависимостей и портов — в предпросмотре</p>'}<div class="software-card-actions"><button class="button ${present?'secondary':'primary'}" data-software="plan" data-component="${c.id}" data-kind="${c.id==='telemt'?'update':kind}" ${blocked?'disabled':''}>${present||c.id==='telemt'?'Обновить…':'Установить…'}</button>${embed?`<button class="button secondary" data-embed-panel="${c.id==='lucx'?'lucx':'mtproxyl'}" data-server="${esc(s.server)}">Открыть панель</button>`:''}${c.repo?`<a class="software-source" href="https://github.com/${esc(c.repo)}" target="_blank" rel="noopener noreferrer">Проект ↗</a>`:''}</div></article>`;
}
function softwareForm(component,kind){
 const s=softwareData.servers.find(s=>s.server===softwareSelected),c=softwareData.components.find(c=>c.id===component);
 if(!s?.ok||!c)return;
 const install=kind==='install',port=install&&c.port,entries=softwareVersions(component).filter(r=>!install||component!=='mtproxyl'||r.version==='v1.7.17').filter(r=>!install||component!=='mtproxyl-panel'||r.version==='mtproxyl-panel-v1.3.13').filter(r=>component!=='awg'||r.version==='v3.11.0-lucx.332');
 modal((install?'Установить · ':'Обновить · ')+c.name,`<form id="softwareForm"><div class="software-target"><strong>${esc(s.name)}</strong><span>${esc(s.host)}</span></div><div class="form-grid">${component!=='fail2ban'?`<label class="wide">${component==='awg'?'Проверенный рецепт AWG':'Версия'}<select name="version" required>${entries.map(r=>`<option value="${esc(r.version)}">${esc(r.version)}</option>`).join('')}</select></label>`:`<p class="form-note wide">Версия из текущего кэша APT: ${esc(s.inventory.components.fail2ban.candidate||'не определена')}.</p>`}${port?`<label class="wide">${component==='mtproxyl'?'Порт Telegram-прокси':'Локальный порт панели'}<input name="port" type="number" min="1024" max="65535" value="${c.port}" required><small>Занятые порты не будут освобождаться автоматически.</small></label>`:''}${install&&component==='mtproxyl'?'<label class="wide">Домен FakeTLS<input name="sni" value="autoscout24.ru" required autocomplete="off"></label>':''}</div><p class="form-note">${component==='lucx'?'Пакеты панели и комплектные движки обновляются отдельно от ядра AWG и ОС.':component==='awg'?'Перед запуском повторно проверяется отсутствие AWG-интерфейсов и контейнеров.':'Действие выполняется на одном выбранном сервере.'} ${install?'Параметры существующих клиентов не переносятся и не заменяются.':'Обновление обслуживаемого компонента может кратковременно прервать его подключения.'}</p><div id="softwareFormError" class="form-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="cancelSoftware">Отмена</button><button class="button primary" id="softwarePreview">Проверить и показать план</button></div></form>`);
 $('#cancelSoftware').onclick=()=>$('#modal').close();
 $('#softwareForm').onsubmit=async e=>{e.preventDefault();const b=$('#softwarePreview');b.disabled=true;b.textContent='Проверяем сервер и релиз…';try{const d=Object.fromEntries(new FormData(e.target));if(d.port)d.port=Number(d.port);showControlPlan(await api('/api/control/plan',{...d,server:s.server,kind,component}))}catch(error){$('#softwareFormError').textContent=error.message;b.disabled=false;b.textContent='Проверить и показать план'}};
}
document.addEventListener('click',async e=>{
 const opener=e.target.closest('[data-software-server]');if(opener){openSoftware(opener.dataset.softwareServer);return}
 const b=e.target.closest('[data-software]');if(!b)return;
 if(b.dataset.software==='add-project'){projectForm();return}
 if(b.dataset.software==='bind-project'){projectBindingForm(b.dataset.component);return}
 if(b.dataset.software==='remove-project'){projectRemoveForm(b.dataset.component);return}
 if(b.dataset.software==='recipe-project'){const c=softwareData.components.find(c=>c.id===b.dataset.component),s=softwareData.servers.find(s=>s.server===softwareSelected);if(c?.recipeId&&s?.ok)softwareForm(c.recipeId,c.recipeId==='telemt'||s.inventory.components[c.recipeId]?.installed?'update':'install');return}
 if(b.dataset.software==='plan'){softwareForm(b.dataset.component,b.dataset.kind);return}
 if(b.dataset.software==='updates'){document.querySelector('[data-filter="updates"]').click();return}
 if(b.dataset.software==='existing'){addPanelModal(softwareSelected);return}
 if(b.dataset.software==='retry-project-status'){resetProjectCatalogProgress();if(projectCatalogTimer){clearTimeout(projectCatalogTimer);projectCatalogTimer=null}await pollProjectCatalogStatus();return}
 if(b.dataset.software==='refresh'){resetProjectCatalogProgress();b.disabled=true;try{await loadSoftware(true)}finally{if(b.isConnected)b.disabled=false}}
});

function renderProjectCatalog(selected){
 const projects=softwareData.components.filter(c=>c.custom);
 return `<section class="project-catalog"><div class="section-bar"><div><h2>Ваши проекты Git</h2><p class="control-subtle">Добавьте ссылку GitHub или GitLab: описание и стабильные релизы появятся в каталоге.</p></div></div>${projectCatalogProgressHTML(projects)}${projects.length?`<div class="software-grid">${projects.map(c=>projectCard(c,selected)).join('')}</div>`:'<div class="control-box project-empty"><p>Пользовательских проектов пока нет.</p><button class="button secondary" data-software="add-project">＋ Добавить ссылку на проект</button></div>'}</section>`;
}
function projectCard(c,s){
 const binding=s&&c.bindings?.[s.server],latest=c.releases?.[0],known=!!c.recipeId;
 return `<article class="software-card project-card"><div class="software-card-top"><span class="software-icon">GIT</span><div><span class="software-category">${esc(c.provider==='gitlab'?'GitLab':'GitHub')}</span><h3>${esc(c.name)}</h3></div><span class="control-pill ${c.ok&&!c.stale?'on':'off'}">${c.checking?'Проверяем…':c.ok&&!c.stale?'Проверен':'Нет свежих данных'}</span></div><p class="software-description">${esc(c.description||'Описание проекта не опубликовано.')}</p><dl><div><dt>Последний опубликованный релиз</dt><dd>${esc(latest?.version||'Не опубликован')}</dd></div><div><dt>На выбранном сервере · вручную</dt><dd>${esc(binding?.version||'Не указано')}</dd></div></dl>${c.error?`<p class="software-blocked">${esc(c.error)}</p>`:''}<p class="control-subtle">${known?'Для проекта доступен встроенный рецепт. Предпросмотр проверит ограничения выбранного сервера.':'Рецепт установки не определён. Добавление ссылки читает сведения проекта; код из репозитория не запускается.'} ${binding?'Указанная версия не подтверждена автоматической проверкой сервера.':''}</p><div class="software-card-actions">${known&&s?.ok?`<button class="button primary" data-software="recipe-project" data-component="${esc(c.id)}">Открыть рецепт…</button>`:''}<button class="button secondary" data-software="bind-project" data-component="${esc(c.id)}" ${s?'':'disabled'}>${binding?'Изменить версию на сервере':'Указать установленную версию'}</button><a class="software-source" href="${esc(c.sourceUrl)}" target="_blank" rel="noopener noreferrer">Проект ↗</a>${latest?`<a class="software-source" href="${esc(latest.url)}" target="_blank" rel="noopener noreferrer">Релиз ↗</a>`:''}<button class="button secondary" data-software="remove-project" data-component="${esc(c.id)}">Удалить запись…</button></div></article>`;
}
function projectForm(){
 modal('Добавить компонент из Git',`<form id="projectForm"><label>Ссылка на публичный проект<input name="url" type="url" required maxlength="512" placeholder="https://github.com/owner/project" autocomplete="off" spellcheck="false"></label><p class="form-note">Поддерживаются GitHub.com и GitLab.com. Достаточно ссылки на корень проекта: Server Deck прочитает описание и релизы. Ключи, токены и установочные команды не нужны.</p><p class="form-note">Для известных проектов откроется встроенный рецепт. Для остальных появятся источник, релизы и ручная привязка установленной версии к серверу.</p><div id="projectError" class="form-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="projectCancel">Отмена</button><button class="button primary" id="projectSubmit">Добавить проект</button></div></form>`);
 $('#projectCancel').onclick=()=>$('#modal').close();$('#projectForm').onsubmit=async e=>{e.preventDefault();const b=$('#projectSubmit');b.disabled=true;b.textContent='Читаем репозиторий…';try{await api('/api/control/components/add',{url:e.target.elements.url.value.trim()});softwareData=null;controlUpdates=null;$('#modal').close();await loadSoftware(false);toast('Проект добавлен в каталог. Службы на серверах не изменялись.')}catch(error){$('#projectError').textContent=error.message;b.disabled=false;b.textContent='Добавить проект'}};
}
function projectBindingForm(cid){
 const c=softwareData.components.find(c=>c.id===cid),s=softwareData.servers.find(s=>s.server===softwareSelected);if(!c||!s)return;
 const old=c.bindings?.[s.server];
 modal('Версия проекта · '+c.name,`<form id="projectBindingForm"><p class="form-note">${esc(s.name)} · ${esc(s.host)}</p><label>Установленная версия или тег<input name="version" maxlength="128" value="${esc(old?.version||'')}" placeholder="v1.2.3" autocomplete="off" spellcheck="false" list="projectTags"></label><datalist id="projectTags">${(c.releases||[]).map(r=>`<option value="${esc(r.version)}"></option>`).join('')}</datalist><p class="form-note">Версия задаётся вами вручную и будет так помечена в центре обновлений. Это действие не устанавливает файлы и не меняет службы. Оставьте поле пустым, чтобы снять привязку.</p><div id="projectBindingError" class="form-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="projectBindingCancel">Отмена</button><button class="button primary" id="projectBindingSubmit">Сохранить сведения</button></div></form>`);
 $('#projectBindingCancel').onclick=()=>$('#modal').close();$('#projectBindingForm').onsubmit=async e=>{e.preventDefault();const b=$('#projectBindingSubmit');b.disabled=true;try{await api('/api/control/components/bind',{id:cid,server:s.server,version:e.target.elements.version.value.trim()});softwareData=null;controlUpdates=null;$('#modal').close();await loadSoftware(false)}catch(error){$('#projectBindingError').textContent=error.message;b.disabled=false}};
}
function projectRemoveForm(cid){
 const c=softwareData.components.find(c=>c.id===cid);if(!c)return;
 modal('Удалить запись · '+c.name,`<p class="form-note">Удалится запись проекта и ручные сведения о версиях из каталога Server Deck. Установленные файлы, службы и подключения серверов сохранятся.</p><div id="projectRemoveError" class="form-error"></div><div class="modal-actions"><button class="button secondary" id="projectRemoveCancel">Отмена</button><button class="button primary" id="projectRemoveSubmit">Удалить запись каталога</button></div>`);
 $('#projectRemoveCancel').onclick=()=>$('#modal').close();$('#projectRemoveSubmit').onclick=async e=>{e.target.disabled=true;try{await api('/api/control/components/remove',{id:cid});softwareData=null;controlUpdates=null;$('#modal').close();await loadSoftware(false)}catch(error){$('#projectRemoveError').textContent=error.message;e.target.disabled=false}};
}

let projectCatalogTimer=null,projectCatalogPolls=0,projectCatalogStartedAt=0,projectCatalogPaused=false,projectCatalogInFlight=false,projectCatalogReadError=false;
const projectCatalogWaitLimit=15*60*1000;
function resetProjectCatalogProgress(){if(projectCatalogTimer){clearTimeout(projectCatalogTimer);projectCatalogTimer=null}projectCatalogStartedAt=0;projectCatalogPolls=0;projectCatalogPaused=false;projectCatalogReadError=false}
function projectCatalogProgressHTML(projects){
 if(!projects.some(p=>p.checking))return '';
 if(projectCatalogPaused)return `<div class="control-note" role="status"><span>${projectCatalogReadError?'Не удалось прочитать результат проверки проектов.':'Проверка репозиториев занимает больше времени. Фоновая задача продолжает работать.'} Показаны сохранённые сведения; ожидание в браузере приостановлено.</span> <button class="button secondary" data-software="retry-project-status">Перечитать результат</button></div>`;
 return '<p class="control-subtle" role="status">Репозитории проверяются в фоне. Пока показаны сохранённые сведения; результат появится автоматически.</p>';
}
function redrawProjectCatalogStatus(){if(filter==='software'&&softwareData)renderSoftware();if(filter==='updates'&&controlUpdates)renderUpdates()}
function scheduleProjectCatalogRefresh(projects){
 if(!projects.some(p=>p.checking)){resetProjectCatalogProgress();return}
 if(projectCatalogTimer||projectCatalogInFlight||projectCatalogPaused||document.hidden||!['software','updates'].includes(filter))return;
 if(!projectCatalogStartedAt)projectCatalogStartedAt=Date.now();
 if(Date.now()-projectCatalogStartedAt>=projectCatalogWaitLimit){projectCatalogPaused=true;redrawProjectCatalogStatus();return}
 const delay=projectCatalogPolls<4?2500:projectCatalogPolls<12?10000:20000;
 projectCatalogTimer=setTimeout(async()=>{projectCatalogTimer=null;if(!['software','updates'].includes(filter)||document.hidden){resetProjectCatalogProgress();return}if(Date.now()-projectCatalogStartedAt>=projectCatalogWaitLimit){projectCatalogPaused=true;redrawProjectCatalogStatus();return}await pollProjectCatalogStatus()},delay);
}
async function pollProjectCatalogStatus(){
 if(projectCatalogInFlight||document.hidden||!['software','updates'].includes(filter))return;
 projectCatalogInFlight=true;projectCatalogPolls++;
 let rows=[];
 try{
  const data=await api('/api/control/components');rows=data.projects||[];
  if(softwareData)softwareData.components=softwareData.components.filter(c=>!c.custom).concat(rows);
  if(controlUpdates)controlUpdates.projects=rows;
  if(!rows.some(p=>p.checking))resetProjectCatalogProgress();
  redrawProjectCatalogStatus();
 }catch(e){projectCatalogPaused=true;projectCatalogReadError=true;redrawProjectCatalogStatus()}
 finally{projectCatalogInFlight=false;if(rows.some(p=>p.checking))scheduleProjectCatalogRefresh(rows)}
}
