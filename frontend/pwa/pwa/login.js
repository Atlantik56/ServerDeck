(() => {
  const form = document.getElementById('loginForm');
  const error = document.getElementById('loginError');
  if(new URLSearchParams(location.search).get('notice')==='partial-logout')error.textContent='Вы вышли из Server Deck. Закрытие встроенных панелей не подтверждено; закройте их вкладки.';
  const password = document.getElementById('loginPassword');
  const button = document.getElementById('loginSubmit');
  const show = document.getElementById('showPassword');
  const setupForm = document.getElementById('setupForm');
  const setupButton = document.getElementById('setupSubmit');
  const setupError = document.getElementById('setupError');
  button.disabled = true;
  show.addEventListener('click', () => {
    const visible = password.type === 'password'; password.type = visible ? 'text' : 'password';
    show.textContent = visible ? 'Скрыть' : 'Показать'; show.setAttribute('aria-pressed', String(visible));
    show.setAttribute('aria-label', visible ? 'Скрыть пароль' : 'Показать пароль');
  });
  function message(e) {
    return e instanceof TypeError ? 'Нет соединения с сервером. Проверьте интернет и попробуйте снова.' : e.message;
  }
  async function submit(path, payload) {
    const response = await fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Deck-Request': '1' },
      credentials: 'same-origin', cache: 'no-store', body: JSON.stringify(payload)
    });
    let result; try { result = await response.json(); } catch { throw Error('Сервис входа временно недоступен. Попробуйте позже.'); }
    if (!response.ok) throw Error(result.error || (response.status === 429 ? 'Слишком много попыток. Попробуйте позже.' : 'Не удалось войти. Проверьте данные.'));
    // Keep the successful form intact for the browser password manager. Raw
    // passwords and claim codes are never written to cookies or browser storage.
    window.location.replace('/');
  }
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (button.disabled) return;
    error.textContent = ''; button.disabled = true; button.textContent = 'Входим…';
    const data = new FormData(form);
    const payload = { username: String(data.get('username')).trim(), password: String(data.get('password')), remember: data.has('remember') };
    try { await submit('/auth/login', payload); }
    catch (e) { error.textContent = message(e); button.disabled = false; button.textContent = 'Войти в панель →'; }
    finally { payload.password = ''; data.delete('password'); }
  });
  setupForm.addEventListener('submit', async event => {
    event.preventDefault(); if (setupButton.disabled) return;
    setupError.textContent = ''; setupButton.disabled = true; setupButton.textContent = 'Создаём учётную запись…';
    const data = new FormData(setupForm);
    const payload = { code: String(data.get('code')).trim(), username: String(data.get('username')).trim(), password: String(data.get('password')), confirmPassword: String(data.get('confirmPassword')), remember: data.has('remember') };
    try {
      if (payload.password !== payload.confirmPassword) throw Error('Пароли не совпадают');
      if (new TextEncoder().encode(payload.password).length > 72) throw Error('Пароль должен занимать не более 72 байт UTF-8.');
      await submit('/auth/setup', payload);
    } catch (e) {
      setupError.textContent = message(e); setupButton.disabled = false; setupButton.textContent = 'Создать учётную запись →';
    } finally { payload.password = ''; payload.confirmPassword = ''; payload.code = ''; data.delete('password'); data.delete('confirmPassword'); data.delete('code'); }
  });
  (async () => {
    try {
      const response = await fetch('/auth/setup', { cache: 'no-store', credentials: 'same-origin' });
      // Compatibility with an older auth gateway during a rolling deployment.
      if (response.ok) {
        const setup = await response.json();
        if (setup.required === true) {
          form.hidden = true; setupForm.hidden = false;
          document.getElementById('loginTitle').textContent = 'Создайте учётную запись';
          document.getElementById('loginSubtitle').textContent = 'Первый вход в вашу панель Server Deck.';
          document.title = 'Первый вход — Server Deck';
          setupButton.disabled = setup.available !== true;
          if (setup.available !== true) setupError.textContent = setup.error || 'Первичная настройка недоступна. Проверьте мастер установки на сервере.';
          return;
        }
      }
      button.disabled = false;
      const session = await fetch('/auth/session', { cache: 'no-store', credentials: 'same-origin' });
      if (session.ok) window.location.replace('/');
    } catch { button.disabled = false; }
  })();
})();
