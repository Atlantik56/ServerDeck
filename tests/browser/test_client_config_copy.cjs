/* The production panel and PWA installer run against synthetic local API responses. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const origin = 'https://deck.example.test';
const frontend = path.resolve(__dirname, '../../frontend');
const existingName = 'Fixture-client';
const createdName = 'New-fixture-client';
const links = {
 [existingName]: [
  'tg://proxy?server=192.0.2.21&port=443&secret=fixture-existing',
  'https://t.me/proxy?server=192.0.2.21&port=443&secret=fixture-existing',
 ],
 [createdName]: ['tg://proxy?server=192.0.2.21&port=443&secret=fixture-new'],
};
const now = Math.floor(Date.now() / 1000);
const server = {
 id: 'fixture-vps', name: 'Тестовый VPS', host: '192.0.2.21', port: 22, user: 'root',
 status: { ok: true, checkedAt: now, data: {} }, services: [],
};
const client = name => ({
 name, panel: 'mtproxyl', protocols: ['mtproto'], enabled: true, quota: 0, used: 0, expires: 0,
});
const requestFor = name => ({ server: server.id, panel: 'mtproxyl', name });
const assetTypes = {
 '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
 '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json',
};

function fixtureApi(automatic = false) {
 const requests = [], errors = [];
 let dispatched = false, jobState = 'backing_up', pendingChecks = 0, name = createdName;
 function response(pathname, method, data) {
   if (automatic && pathname === '/api/control' && dispatched && ++pendingChecks > 1) jobState = 'succeeded';
   const json = (body, status = 200) => ({ json: body, status });
   requests.push({ pathname, data, jobState });
   if (pathname === '/api/state') return json({ servers: [server], activity: [] });
   if (pathname === '/api/health') return json({ generatedAt: now, servers: {} });
   if (['/api/native-probe', '/api/cheburcheck', '/api/outage-diagnostics'].includes(pathname)) {
    return json({ servers: {} });
   }
   if (pathname === '/api/security-updates') return json({ cve: 'fixture', servers: [], notices: [] });
   if (pathname === '/api/panel-update') return json({ supported: true, installed: { version: '1.6.3' }, state: 'current' });
   if (pathname === '/api/account') return json({ username: 'fixture-operator', canChangePassword: true });
   if (pathname === '/api/control') {
    return json({ jobs: dispatched ? [{
     id: 'fixture-create-job', server: server.id, host: server.host, title: 'Создать клиента · ' + name,
     kind: 'client', state: jobState, createdAt: now,
    }] : [], backups: [], busyServers: dispatched && jobState === 'backing_up' ? [server.id] : [] });
   }
   if (pathname === '/api/control/clients') {
    const clients = [client(existingName)];
    if (dispatched && jobState === 'succeeded') clients.push(client(name));
    return json({ servers: [{
     server: server.id, name: server.name, host: server.host, ok: true, clients,
     panels: [{ panel: 'mtproxyl', ok: true, count: clients.length }], inbounds: [],
    }] });
   }
   if (pathname === '/api/control/plan' && data) {
    name = data.name;
    dispatched = false;
    jobState = 'backing_up';
    pendingChecks = 0;
    return json({
     id: 'fixture-create-plan', server: server.id, host: server.host,
     summary: { title: 'Создать клиента · ' + name, name, panel: data.panel, impact: 'Тестовый план' },
    });
   }
   if (pathname === '/api/control/execute') {
    dispatched = true;
    return json({ id: 'fixture-create-job', server: server.id, kind: 'client', state: 'backing_up' });
   }
   if (pathname === '/api/control/links' && data) {
    if (data.name === name && name !== existingName && jobState !== 'succeeded') {
     errors.push('Configuration fetched before client creation succeeded');
     return json({ error: 'Client creation is still in progress' }, 409);
    }
    return json({ links: data.name === name && name !== existingName ? links[createdName] : links[data.name] });
   }
   errors.push('Unexpected fixture API: ' + method + ' ' + pathname);
   return json({ error: 'Unexpected fixture API' }, 404);
 }
 return { response, requests, errors, finishCreation: () => { jobState = 'succeeded'; } };
}

function fixtureAsset(pathname) {
  const file = pathname === '/' ? '/index.html' : pathname;
  const isPwa = file.startsWith('/pwa/') || ['/pwa-sw.js', '/manifest.webmanifest'].includes(file);
  const base = path.join(frontend, isPwa ? 'pwa' : 'static');
  const asset = path.resolve(base, '.' + file);
  if (!asset.startsWith(base + path.sep) || !fs.existsSync(asset) || !fs.statSync(asset).isFile()) {
   return { status: 404, body: '' };
  }
  return { contentType: assetTypes[path.extname(asset)], body: fs.readFileSync(asset) };
}

function preview() {
 const http = require('node:http');
 const port = Number(process.argv[3] || 4180);
 const api = fixtureApi(true);
 const previewServer = http.createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://localhost').pathname;
  response.setHeader('Cache-Control', 'no-store');
  if (pathname.startsWith('/api/')) {
   let data = null;
   if (request.method === 'POST') {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    try { data = JSON.parse(Buffer.concat(chunks).toString()); } catch { data = null; }
   }
   const result = api.response(pathname, request.method, data);
   response.writeHead(result.status, { 'Content-Type': 'application/json; charset=utf-8' });
   response.end(JSON.stringify(result.json));
   return;
  }
  const { status = 200, contentType = 'text/plain', body } = fixtureAsset(pathname);
  response.writeHead(status, { 'Content-Type': contentType });
  response.end(body);
 });
 previewServer.listen(port, '127.0.0.1', () => console.log(`Server Deck clipboard fixture: http://127.0.0.1:${previewServer.address().port}/`));
}

async function fixture(browser, clipboardMode = 'working') {
 const context = await browser.newContext({
  viewport: { width: 390, height: 820 }, isMobile: true, hasTouch: true, serviceWorkers: 'block',
 });
 await context.addInitScript(mode => {
  Object.defineProperty(navigator, 'standalone', { value: true });
  window.fixtureClipboard = [];
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: mode === 'missing' ? undefined : {
   async writeText(text) {
    window.fixtureClipboard.push({ text, gesture: navigator.userActivation.isActive });
    if (mode === 'denied') throw new DOMException('Fixture clipboard permission denied', 'NotAllowedError');
   },
  } });
  document.execCommand = () => false;
 }, clipboardMode);
 const page = await context.newPage();
 page.setDefaultTimeout(12000);
 const api = fixtureApi();
 page.on('pageerror', error => api.errors.push(error.message));
 await page.route('**/*', async route => {
  const request = route.request();
  const url = new URL(request.url());
  if (url.origin !== origin) {
   api.errors.push('Fixture attempted an external request: ' + url.origin);
   return route.abort();
  }
  if (!url.pathname.startsWith('/api/')) return route.fulfill(fixtureAsset(url.pathname));
  const data = request.method() === 'POST' ? request.postDataJSON() : null;
  return route.fulfill(api.response(url.pathname, request.method(), data));
 });
 await page.goto(origin + '/');
 await page.locator('body.pwa-standalone').waitFor();
 await page.locator('[data-open-server="' + server.id + '"]').click();
 await page.getByRole('button', { name: 'Клиенты', exact: true }).click();
 await page.getByRole('button', { name: 'Конфиг', exact: true }).waitFor({ state: 'visible' });
 return { context, page, errors: api.errors, requests: api.requests, finishCreation: api.finishCreation };
}

const copyButtons = dialog => dialog.getByRole('button', { name: 'Скопировать ссылку', exact: true });
const linksRequests = fixture => fixture.requests.filter(request => request.pathname === '/api/control/links');

async function existingAndCreated(browser) {
 const f = await fixture(browser);
 const page = f.page;
 try {
  await page.getByRole('button', { name: 'Конфиг', exact: true }).click();
  let dialog = page.getByRole('dialog', { name: 'Конфигурация · ' + existingName });
  await copyButtons(dialog).first().waitFor();
  assert.equal(await copyButtons(dialog).count(), 2);
  assert.equal(await dialog.getByRole('heading', { name: 'Ссылка для Telegram', exact: true }).count(), 1);
  assert.equal(await dialog.getByRole('heading', { name: 'Ссылка t.me', exact: true }).count(), 1);
  assert.deepEqual(linksRequests(f).map(request => request.data), [requestFor(existingName)]);
  assert.deepEqual(await page.evaluate(() => window.fixtureClipboard), []);
  await copyButtons(dialog).nth(1).click();
  await dialog.getByText('Скопировано', { exact: true }).waitFor();
  assert.deepEqual(await page.evaluate(() => window.fixtureClipboard), [{ text: links[existingName][1], gesture: true }]);
  assert.equal(linksRequests(f).length, 1, 'Copy makes no new configuration request');
  await dialog.locator('#closeModal').click();

  await page.locator('[data-ctrl="add-client"]').click();
  await page.locator('#controlClientForm [name="name"]').fill(createdName);
  await page.locator('#previewClient').click();
  await page.locator('#controlActionConfirm').check();
  await page.locator('#executeControlPlan').click();
  dialog = page.getByRole('dialog', { name: 'Создание клиента · ' + createdName });
  await dialog.waitFor();
  assert.equal(await copyButtons(dialog).count(), 0, 'Configuration is unavailable while creation is pending');
  assert.equal(linksRequests(f).length, 1);
  f.finishCreation();

  dialog = page.getByRole('dialog', { name: 'Конфигурация · ' + createdName });
  await copyButtons(dialog).waitFor();
  assert.deepEqual(linksRequests(f).map(request => request.data), [requestFor(existingName), requestFor(createdName)]);
  assert.equal(linksRequests(f).at(-1).jobState, 'succeeded');
  assert.equal((await page.evaluate(() => window.fixtureClipboard)).length, 1, 'Creation does not write to clipboard automatically');
  await copyButtons(dialog).click();
  await dialog.getByText('Скопировано', { exact: true }).waitFor();
  assert.deepEqual((await page.evaluate(() => window.fixtureClipboard)).at(-1), { text: links[createdName][0], gesture: true });
  assert.equal(linksRequests(f).length, 2);
  assert.deepEqual(f.errors, []);
 } finally {
  await f.context.close();
 }
}

async function manualFallback(browser, mode) {
 const f = await fixture(browser, mode);
 const page = f.page;
 try {
  await page.getByRole('button', { name: 'Конфиг', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Конфигурация · ' + existingName });
  await copyButtons(dialog).first().click();
  await dialog.getByText('Скопируйте выделенный текст вручную.', { exact: true }).waitFor();
  const selected = await dialog.locator('textarea[readonly]:focus').evaluate(node => ({
   value: node.value, start: node.selectionStart, end: node.selectionEnd,
  }));
  assert.deepEqual(selected, { value: links[existingName][0], start: 0, end: links[existingName][0].length });
  assert.equal(linksRequests(f).length, 1);
  assert.deepEqual(f.errors, []);
 } finally {
  await f.context.close();
 }
}

async function run() {
 const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
 const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined });
 try {
  await existingAndCreated(browser);
  await manualFallback(browser, 'denied');
  await manualFallback(browser, 'missing');
  console.log('PASS mobile standalone mode: existing and newly created client links, direct clipboard gesture, and manual selection fallback.');
 } finally {
  await browser.close();
 }
}

if (process.argv[2] === '--preview') preview();
else run().catch(error => { console.error(error.stack); process.exitCode = 1; });
