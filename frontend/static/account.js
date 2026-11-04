let accountLoading=false,accountReady=false;
window.accountReauthRequired=false;
window.settingsNavigate=async view=>{
 if(view!=='settings'||accountLoading||accountReady)return;
 accountLoading=true;
 const root=$('#settingsDashboard');root.innerHTML='<div class="loading"><div class="spinner"></div>Читаем учётную запись…</div>';
 try{
  const info=await api('/api/account');
  root.innerHTML=`<article class="account-card"><div class="account-card-heading"><span class="account-icon">⚙</span><div><h2>Учётная запись</h2><p>Вход в Server Deck</p></div><span class="control-pill on">HTTPS</span></div><form id="accountPasswordForm"><label>Логин<input id="accountUsername" name="username" value="${esc(info.username||'')}" autocomplete="username" readonly></label><div class="account-divider"></div><h3>Сменить пароль</h3><p class="account-description">Введите текущий пароль и сохраните новый в менеджере паролей. После смены потребуется войти заново.</p><label>Текущий пароль<input id="accountCurrent" name="currentPassword" type="password" autocomplete="current-password" required ${info.canChangePassword?'':'disabled'}></label><label>Новый пароль<input id="accountNew" name="newPassword" type="password" autocomplete="new-password" minlength="12" required ${info.canChangePassword?'':'disabled'} aria-describedby="accountPasswordHint"></label><p class="account-hint" id="accountPasswordHint">Минимум 12 символов. Максимум 72 байта UTF-8: русские буквы занимают больше одного байта.</p><label>Повторите новый пароль<input id="accountConfirm" name="confirmPassword" type="password" autocomplete="new-password" minlength="12" required ${info.canChangePassword?'':'disabled'}></label><label class="account-show"><input id="accountShow" type="checkbox">Показать пароли</label><div id="accountError" class="form-error" role="alert">${info.canChangePassword?'':'Смена пароля недоступна для этого способа входа.'}</div><div class="account-actions"><button type="submit" class="button primary" id="accountSave" ${info.canChangePassword?'':'disabled'}>Сменить пароль</button></div></form><div id="accountResult" role="status" hidden></div><div class="account-divider"></div><p class="account-description">Выход закроет встроенные панели на всех устройствах. VPN-подключения продолжат работать.</p><button type="button" class="button secondary" id="accountLogout">Выйти из учётной записи</button></article>`;
  accountReady=true;
  $('#accountLogout').onclick=async()=>{
   $('#accountLogout').disabled=true;
   try{
    let nativeClosed=false;
    try{const r=await fetch('/api/account/logout',{method:'POST',headers:{'Content-Type':'application/json','X-Deck-Token':token},body:'{}'});nativeClosed=r.ok}catch{}
    const response=await fetch('/auth/logout',{method:'POST',headers:{'Content-Type':'application/json','X-Deck-Request':'1'},body:'{}'});
    if(!response.ok)throw Error('Не удалось завершить выход. Повторите попытку.');
    window.accountReauthRequired=true;window.location.replace(nativeClosed?'/login/':'/login/?notice=partial-logout');
   }catch(e){toast(e.message);$('#accountLogout').disabled=false}
  };
  const form=$('#accountPasswordForm');
  $('#accountShow').onchange=e=>{for(const id of ['accountCurrent','accountNew','accountConfirm'])$('#'+id).type=e.target.checked?'text':'password'};
  form.onsubmit=async e=>{
   e.preventDefault();const error=$('#accountError');error.textContent='';
   const data=Object.fromEntries(new FormData(form));
   if(data.newPassword!==data.confirmPassword){error.textContent='Новые пароли не совпадают.';$('#accountConfirm').focus();return}
   if(new TextEncoder().encode(data.newPassword).length>72){error.textContent='Новый пароль длиннее 72 байт UTF-8.';$('#accountNew').focus();return}
   if(data.currentPassword===data.newPassword){error.textContent='Новый пароль должен отличаться от текущего.';return}
   const button=$('#accountSave');button.disabled=true;button.textContent='Сохраняем…';
   try{
    await api('/api/account/password',data);
    window.accountReauthRequired=true;form.reset();form.hidden=true;
    const result=$('#accountResult');result.hidden=false;
    result.innerHTML='<div class="account-success">✓ Пароль изменён</div><p>Войдите заново с новым паролем. Логин остался прежним.</p><button type="button" class="button primary" id="accountRelogin">Войти с новым паролем</button>';
    $('#accountRelogin').onclick=()=>window.location.assign('/login/');
   }catch(e){error.textContent=e.message;button.disabled=false;button.textContent='Сменить пароль'}
   finally{for(const key of ['currentPassword','newPassword','confirmPassword'])data[key]=''}
  };
 }catch(e){root.innerHTML=`<div class="control-error">${esc(e.message)}</div><button class="button secondary" id="accountRetry">Повторить</button>`;$('#accountRetry').onclick=()=>window.settingsNavigate('settings')}
 finally{accountLoading=false}
};
$('#openSettings').onclick=()=>document.querySelector('[data-filter="settings"]').click();
