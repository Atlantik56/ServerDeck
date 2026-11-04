// Network-only: never store account pages, tokens, API responses or server data.
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

const offline = `<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0c101b"><title>Server Deck — нет соединения</title>
<style>html{color-scheme:dark}body{margin:0;background:#0c101b;color:#e3eafa;font:16px/1.7 system-ui,sans-serif;min-height:100dvh;display:grid;place-items:center}main{max-width:420px;padding:28px}small{color:#8798bd;letter-spacing:.12em}h1{font-size:28px;line-height:1.3}p{color:#a4b3ce}a{display:inline-block;border-radius:12px;background:#5875ee;color:white;text-decoration:none;padding:13px 20px;margin-top:15px}</style>
<main><small>SERVER DECK</small><h1>Не удалось соединиться</h1><p>Проверьте интернет и доступность панели. Данные серверов доступны после подключения.</p><a href="/">Попробовать снова</a></main></html>`;

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || request.mode !== 'navigate' ||
      url.origin !== self.location.origin || !['/', '/index.html', '/install/', '/install/index.html'].includes(url.pathname)) return;
  event.respondWith(fetch(request).catch(() => new Response(offline, {
    status: 503,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    }
  })));
});
