/* Exercise the real panel shell with fixture-only API requests. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const origin = 'https://deck.example.test';
const frontend = path.resolve(__dirname, '../../frontend');
const staticRoot = path.join(frontend, 'static');
const pwaRoot = path.join(frontend, 'pwa');
const contentTypes = {
 '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
 '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json',
};
const now = Math.floor(Date.now() / 1000);
const first = {
 id: 'first', name: 'Резервный сервер', host: '192.0.2.10', user: 'root', port: 22,
 status: { ok: false, checkedAt: now, error: 'SSH fixture error' }, services: [],
};
const second = {
 id: 'second', name: 'Сервер VPN с длинным названием', host: '192.0.2.20', user: 'root', port: 22,
 services: ['x-ui.service'],
 status: { ok: true, checkedAt: now, data: {
  cpu: 12, memory: { used: 1024, total: 2048 }, disk: { used: 2048, total: 4096 },
  uptime: 3600, cores: 2, kernel: '6.8.0-fixture',
  collectionOk: { services: true, containers: true, awg: true },
  services: [{ unit: 'x-ui.service', state: 'active', loaded: true }], containers: [],
  awg: [{ interface: 'awg-fixture', port: 51820, rx: 1024, tx: 2048, online: 1, peers: 2, latestHandshake: now }],
  panels: [{ name: '3x-ui / LucX', localOnly: true }],
 } },
};
const job = (server, title) => ({
 id: `job-${server.id}`, server: server.id, host: server.host, title, kind: 'reboot',
 createdAt: now, state: 'succeeded',
});
const updates = {
 checkedAt: now,
 upstream: { checkedAt: now, lucx: { ok: true, releases: [{ version: 'v3.0.1' }, { version: 'v3.0.2' }] } },
 servers: [
  { server: first.id, name: first.name, host: first.host, ok: false, error: first.status.error },
  { server: second.id, name: second.name, host: second.host, ok: true,
   versions: { lucx: '3.0.0', os: 'Ubuntu 24.04', kernel: '6.8.0-fixture' },
   updateStatus: { lucx: { state: 'update_available', latest: 'v3.0.2' } },
  },
 ],
 projects: [],
};
const gets = {
 '/api/state': { servers: [first, second], activity: [] },
 '/api/control': { jobs: [job(second, 'Задача сервера VPN'), job(first, 'Задача резервного сервера')], backups: [], busyServers: [] },
 '/api/control/clients': { servers: [
  { server: first.id, name: first.name, host: first.host, ok: true,
   panels: [{ panel: 'lucx', ok: true, count: 0 }], clients: [], inbounds: [] },
  { server: second.id, name: second.name, host: second.host, ok: true,
   panels: [{ panel: 'lucx', ok: true, count: 0 }, { panel: 'mtproxyl', ok: true, count: 1 }],
   clients: [{ name: 'Тестовый клиент', panel: 'mtproxyl', protocols: ['mtproto'], enabled: true, used: 100, quota: 0, expires: 0 }],
   inbounds: [] },
 ] },
 '/api/control/updates': updates,
 '/api/health': { generatedAt: now, servers: {} },
 '/api/native-probe': { servers: {} },
 '/api/cheburcheck': { servers: {} },
 '/api/outage-diagnostics': { servers: {} },
 '/api/security-updates': { cve: 'CVE-2026-98432', checkedAt: now, lastGoodAt: now, servers: [], notices: [] },
 '/api/panel-update': { supported: true, installed: { version: '1.6.0' }, latest: null, state: 'unknown', checkedAt: now },
};

async function fixture(context) {
 const page = await context.newPage();
 const errors = [];
 const unexpected = [];
 const posts = [];
 page.on('pageerror', error => errors.push(error.message));
 await page.route('**/*', async route => {
  const request = route.request();
  const url = new URL(request.url());
  if (url.origin !== origin) {
   unexpected.push(`External request: ${url.origin}`);
   return route.abort();
  }
  if (url.pathname.startsWith('/api/')) {
   if (request.method() === 'GET' && Object.hasOwn(gets, url.pathname)) {
    return route.fulfill({ json: gets[url.pathname] });
   }
   if (request.method() === 'POST') {
    const data = request.postDataJSON();
    posts.push({ path: url.pathname, data });
    if (url.pathname === '/api/action' && data.action === 'logs') {
     return route.fulfill({ json: { ok: true, logs: 'fixture log: VPN service is running' } });
    }
    if (url.pathname === '/api/control/plan' && data.kind === 'update') {
     return route.fulfill({ json: {
      id: 'update-fixture', server: data.server, host: second.host,
      summary: { title: 'Предпросмотр обновления LucX', impact: 'Тестовый план', component: data.component, version: data.version },
     } });
    }
   }
   unexpected.push(`${request.method()} ${url.pathname}`);
   return route.fulfill({ status: 404, json: { error: 'Unexpected fixture request' } });
  }
  const uri = url.pathname === '/' ? '/index.html' : url.pathname;
  const assetRoot = uri.startsWith('/pwa/') || uri === '/pwa-sw.js' || uri === '/manifest.webmanifest' ? pwaRoot : staticRoot;
  const asset = path.resolve(assetRoot, '.' + uri);
  if (!asset.startsWith(assetRoot + path.sep) || !fs.existsSync(asset) || !fs.statSync(asset).isFile()) {
   return route.fulfill({ status: 404, body: '' });
  }
  return route.fulfill({ contentType: contentTypes[path.extname(asset)], body: fs.readFileSync(asset) });
 });
 await page.goto(origin);
 await page.locator(`#servers [data-server-card="${second.id}"]`).waitFor({ state: 'visible' });
 return { page, errors, unexpected, posts };
}

async function noOverflow(page, view, width) {
 const dimensions = await page.evaluate(() => ({
  available: document.documentElement.clientWidth,
  content: document.documentElement.scrollWidth,
 }));
 assert.ok(dimensions.content <= dimensions.available + 1, `${view} overflows at ${width}px (${dimensions.content} > ${dimensions.available})`);
}

async function navigate(page, view, mobile) {
 const shortcut = page.locator(`[data-mobile-view="${view}"]`);
 if (mobile && await shortcut.isVisible()) {
  await shortcut.click();
 } else {
  if (mobile) await page.locator('#mobileMore').click();
  await page.locator(`aside [data-filter="${view}"]`).click();
 }
 await page.waitForFunction(view => document.body.classList.contains(`filter-${view}`), view);
 if (mobile) assert.equal(await page.locator('#mobileMore').getAttribute('aria-expanded'), 'false');
}

async function navigationScenarios(browser, width) {
 const mobile = width < 500;
 const context = await browser.newContext({ viewport: { width, height: 820 }, isMobile: mobile, hasTouch: mobile, serviceWorkers: 'block' });
 try {
  const { page, errors, unexpected, posts } = await fixture(context);
  const card = page.locator(`#servers [data-server-card="${second.id}"]`);
  const details = card.locator('.server-details');
  const logs = details.locator('[data-action="logs"]');
  if (mobile) {
   assert.equal(await page.locator('button[aria-controls="sidebar"]:visible').count(), 1, 'The phone should offer one menu toggle');
   assert.equal(await page.locator('#mobileMore').isVisible(), true);
   assert.equal(await logs.isVisible(), false, 'Service rows should be collapsed initially on phones');
  }
  await noOverflow(page, 'Servers', width);
  if (!await logs.isVisible()) await details.locator('summary').click();
  await logs.click();
  await page.getByText('fixture log: VPN service is running').waitFor({ state: 'visible' });
  assert.deepEqual(posts.at(-1), { path: '/api/action', data: { server: second.id, unit: 'x-ui.service', action: 'logs' } });
  await page.locator('#closeModal').click();

  await card.locator('[data-server-manage]').click();
  await page.locator(`#modal [data-server-updates="${second.id}"]`).click();
  const updatesServer = page.locator('#updatesServer');
  await updatesServer.waitFor({ state: 'visible' });
  assert.equal(await updatesServer.inputValue(), second.id);
  const updateCard = page.locator(`[data-update-server="${second.id}"]`);
  await updateCard.waitFor({ state: 'visible' });
  assert.equal(await page.locator(`[data-update-server="${first.id}"]`).isVisible(), false);
  await noOverflow(page, 'Scoped updates', width);
  const release = updateCard.locator('select');
  await release.selectOption('v3.0.2');
  await updatesServer.selectOption('');
  await page.locator(`[data-update-server="${first.id}"]`).waitFor({ state: 'visible' });
  assert.equal(await page.locator('[data-update-server]:visible').count(), 2);
  await updatesServer.selectOption(first.id);
  await page.locator('#updatesDashboard').getByText(first.status.error, { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await updateCard.isVisible(), false);
  await updatesServer.selectOption(second.id);
  await updateCard.waitFor({ state: 'visible' });
  assert.equal(await release.inputValue(), 'v3.0.2');
  await updateCard.locator('[data-ctrl="plan-update"][data-component="lucx"]').click();
  await page.getByRole('heading', { name: 'Предпросмотр обновления LucX' }).waitFor({ state: 'visible' });
  assert.deepEqual(posts.at(-1), {
   path: '/api/control/plan', data: { kind: 'update', server: second.id, component: 'lucx', version: 'v3.0.2' },
  });
  await page.locator('#closeModal').click();

  const historyLink = page.locator(`#updatesDashboard [data-job-history="${second.id}"]`);
  await historyLink.click();
  const historyServer = page.locator('#historyServer');
  await historyServer.waitFor({ state: 'visible' });
  assert.equal(await historyServer.inputValue(), second.id);
  assert.deepEqual(await page.locator('#taskHistory .control-job strong').allTextContents(), ['Задача сервера VPN']);
  await historyServer.selectOption('');
  assert.equal(await page.locator('#taskHistory .control-job').count(), 2);
  assert.equal(await page.locator('.control-job').count(), 2, 'Full task history should only be rendered once');
  await noOverflow(page, 'History', width);

  await navigate(page, 'awg', mobile);
  await page.locator('.server-awg-card').getByText('awg-fixture', { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await page.locator('#servers [data-action]:visible').count(), 0, 'The AWG view should not duplicate service controls');
  assert.equal(await page.locator('#servers [data-server-manage]:visible').count(), 0);
  await noOverflow(page, 'AWG', width);

  await navigate(page, 'clients', mobile);
  const clientSearch = page.locator('#clientSearch');
  await clientSearch.waitFor({ state: 'visible' });
  await page.locator('#clientServerFilter').selectOption(second.id);
  await page.locator('#clientPanelFilter').selectOption('mtproxyl');
  await clientSearch.fill('Тестовый');
  await page.getByText('Тестовый клиент', { exact: true }).waitFor({ state: 'visible' });
  assert.ok(await page.locator('[data-ctrl="edit-client"]').isVisible());
  await noOverflow(page, 'Clients', width);
  await page.locator('[data-ctrl="add-client"]').click();
  assert.equal(await page.locator('#controlClientForm [name="server"]').inputValue(), second.id);
  assert.equal(await page.locator('#controlClientForm [name="panel"]').inputValue(), 'mtproxyl');
  await page.locator('#closeModal').click();

  await navigate(page, 'backups', mobile);
  const backupServer = page.locator('#backupServer');
  const backupPanel = page.locator('#backupPanel');
  await backupServer.waitFor({ state: 'visible' });
  await backupServer.selectOption(second.id);
  await backupPanel.selectOption('mtproxyl');
  await page.evaluate(() => renderBackups());
  assert.equal(await backupServer.inputValue(), second.id);
  assert.equal(await backupPanel.inputValue(), 'mtproxyl');
  await noOverflow(page, 'Backups', width);
  assert.equal(posts.length, 2, 'Navigation should only request service logs and one update preview');
  assert.deepEqual(unexpected, [], 'Unexpected browser requests');
  assert.deepEqual(errors, [], 'Uncaught browser errors');
 } finally {
  await context.close();
 }
}

(async () => {
 const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined });
 try {
  for (const width of [320, 390, 1440]) await navigationScenarios(browser, width);
  console.log('PASS navigation at 320, 390 and 1440px: logs, updates, history, AWG, clients and backups.');
 } finally {
  await browser.close();
 }
})().catch(error => { console.error(error.stack); process.exitCode = 1 });
