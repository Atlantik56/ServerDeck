(() => {
  let prompt = null;
  let installed = false, accepted = false;
  const standalone = matchMedia('(display-mode: standalone)');
  const isApp = () => standalone.matches || navigator.standalone === true;
  const buttons = () => [...document.querySelectorAll('[data-install-app]')];
  function render() {
    document.body.classList.toggle('pwa-standalone', isApp());
    document.querySelectorAll('[data-install-state]').forEach(el => {
      el.textContent = isApp() ? 'Открыто как приложение' : installed ? 'Приложение установлено' : accepted ? 'Установка подтверждена браузером' : 'Значок на экране · отдельное окно';
    });
    buttons().forEach(button => {
      button.disabled = installed || isApp();
      const label = button.querySelector('[data-install-label]');
      if (label) label.textContent = installed || isApp() ? 'Установлено' : prompt ? 'Установить приложение' : 'Как установить';
    });
  }
  window.addEventListener('beforeinstallprompt', event => {
    event.preventDefault(); prompt = event; render();
  });
  window.addEventListener('appinstalled', () => { installed = true; prompt = null; render(); });
  standalone.addEventListener('change', render);

  const dialog = document.createElement('dialog');
  dialog.className = 'pwa-dialog'; dialog.id = 'pwaInstallDialog';
  dialog.setAttribute('aria-labelledby', 'pwaInstallTitle');
  dialog.innerHTML = `<div class="pwa-dialog-heading"><h2 id="pwaInstallTitle">Server Deck на Android</h2><button type="button" class="pwa-close" aria-label="Закрыть инструкцию">×</button></div><p>Откройте эту страницу в Chrome на телефоне.</p><ol class="pwa-steps"><li>Нажмите меню <strong>⋮</strong> справа сверху.</li><li>Выберите <strong>«Добавить на главный экран»</strong> или <strong>«Установить приложение»</strong>.</li><li>Подтвердите установку. Значок Server Deck появится на экране телефона.</li></ol><p class="pwa-note">Если виден только пункт «Создать ярлык», откройте страницу в обычной вкладке Chrome и попробуйте снова. Названия пунктов зависят от браузера.</p><a class="pwa-secondary" href="/install/" target="_blank" rel="noopener">Страница установки ↗</a>`;
  document.body.appendChild(dialog);
  dialog.querySelector('.pwa-close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', event => { if (event.target === dialog) { const r = dialog.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) dialog.close(); } });

  document.addEventListener('click', async event => {
    const button = event.target.closest('[data-install-app]');
    if (!button || button.disabled) return;
    const drawerClose = document.getElementById('closeMobileMenu');
    if (document.body.hasAttribute('data-nav-open')) drawerClose?.click();
    if (!prompt) { if (!dialog.open) dialog.showModal(); return; }
    const pending = prompt; prompt = null;
    buttons().forEach(b => { b.disabled = true; });
    try {
      await pending.prompt();
      const choice = await pending.userChoice;
      if (choice.outcome === 'accepted') accepted = true;
    } catch {
      if (!dialog.open) dialog.showModal();
    } finally { render(); }
  });
  render();
  if ('serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('/pwa-sw.js', { scope: '/', updateViaCache: 'none' }).catch(() => {
      // Installation instructions stay available if the browser disables workers.
    });
  }
})();
