/* Exercise the real panel shell with fixture-only API requests. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

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
const backup = server => ({
 id: `backup-${server.id}`, server: server.id, serverName: server.name, host: server.host,
 panel: 'lucx', createdAt: now, size: 4096, reason: 'manual', verified: true,
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
 '/api/state': { servers: [first, second], activity: [
  { time: now, server: second.name, unit: 'x-ui.service', action: 'start', ok: true },
  { time: now, serverId: first.id, server: second.name, unit: 'first-only.service', action: 'start', ok: true },
 ] },
 '/api/control': {
  jobs: [job(second, 'Задача сервера VPN'), job(first, 'Задача резервного сервера')],
  backups: [backup(second), backup(first)],
  busyServers: [],
 },
 '/api/control/clients': { servers: [
  { server: first.id, name: first.name, host: first.host, ok: true,
   panels: [{ panel: 'lucx', ok: true, count: 1 }],
   clients: [{ name: 'Резервный клиент', panel: 'lucx', protocols: ['vless'], enabled: true, used: 0, quota: 0, expires: 0 }],
   inbounds: [] },
  { server: second.id, name: second.name, host: second.host, ok: true,
   panels: [{ panel: 'lucx', ok: true, count: 0 }, { panel: 'mtproxyl', ok: true, count: 1 }],
   clients: [{ name: 'Тестовый клиент', panel: 'mtproxyl', protocols: ['mtproto'], enabled: true, used: 100, quota: 0, expires: 0 }],
   inbounds: [] },
 ] },
 '/api/control/updates': updates,
 '/api/control/software': {
  components: [{ id: 'lucx', name: '3x-ui / LucX', description: 'VPN-панель', category: 'VPN', icon: '3X' }],
  upstream: updates.upstream,
  servers: [
   { server: first.id, name: first.name, host: first.host, ok: false, error: first.status.error },
   { server: second.id, name: second.name, host: second.host, ok: true, checkedAt: now,
    inventory: { os: 'Ubuntu 24.04', arch: 'x86_64', supported: true,
     components: { lucx: { installed: true, version: '3.0.0' } },
    },
   },
  ],
 },
 '/api/account': { username: 'fixture-operator', canChangePassword: true },
 '/api/alerts': { configured: false, enabled: false, config: {} },
 '/api/deployment': { available: true, canChange: true, busy: false, mode: 'domain', host: 'deck.example.test', origin, publicIp: '192.0.2.20' },
 '/api/health': { generatedAt: now, servers: {} },
 '/api/native-probe': { servers: {} },
 '/api/cheburcheck': { servers: {} },
 '/api/outage-diagnostics': { servers: {} },
 '/api/security-updates': { cve: 'CVE-2026-98432', checkedAt: now, lastGoodAt: now, servers: [], notices: [] },
 '/api/panel-update': { supported: true, installed: { version: '1.6.0' }, latest: null, state: 'unknown', checkedAt: now },
};

function apiResponse(method, { pathname, searchParams, origin: requestOrigin }, data) {
 if (method === 'GET' && Object.hasOwn(gets, pathname)) {
  const result = gets[pathname];
  const server = searchParams.get('server');
  return server && ['/api/control/clients', '/api/control/updates', '/api/control/software'].includes(pathname)
   ? { ...result, servers: result.servers.filter(entry => entry.server === server) }
   : result;
 }
 if (method !== 'POST') return null;
 if (pathname === '/api/action' && data?.action === 'logs') {
  return { ok: true, logs: 'fixture log: VPN service is running' };
 }
 if (pathname === '/api/control/plan' && data?.kind === 'update') {
  return {
   id: 'update-fixture', server: data.server, host: second.host,
   summary: { title: 'Предпросмотр обновления LucX', impact: 'Тестовый план', component: data.component, version: data.version },
  };
 }
 if (pathname === '/api/control/backup') return { ok: true };
 if (pathname === '/api/embedded/open' && data?.server === second.id && data.panel === 'lucx') {
  return { origin: requestOrigin, entry: '/fixture-native/', grant: 'fixture-grant' };
 }
 return null;
}

function assetResponse(pathname) {
 if (pathname === '/_deck/bootstrap' || pathname === '/fixture-native/') {
  return { contentType: 'text/html; charset=utf-8', body: '<!doctype html><html lang="ru"><title>Панель VPN</title><h1>Панель VPN · фикстура</h1></html>' };
 }
 const uri = pathname === '/' ? '/index.html' : pathname;
 const assetRoot = uri.startsWith('/pwa/') || uri === '/pwa-sw.js' || uri === '/manifest.webmanifest' ? pwaRoot : staticRoot;
 const asset = path.resolve(assetRoot, '.' + uri);
 if (!asset.startsWith(assetRoot + path.sep) || !fs.existsSync(asset) || !fs.statSync(asset).isFile()) return { status: 404, body: '' };
 return { contentType: contentTypes[path.extname(asset)], body: fs.readFileSync(asset) };
}

function preview() {
 const http = require('node:http');
 const port = Number(process.argv[3] || 4173);
 const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://127.0.0.1:${server.address().port}`);
  const { pathname } = url;
  response.setHeader('Cache-Control', 'no-store');
  if (pathname.startsWith('/api/')) {
   let data;
   if (request.method === 'POST') {
    const body = [];
    for await (const chunk of request) body.push(chunk);
    try { data = JSON.parse(Buffer.concat(body).toString()); } catch { data = null; }
   }
   const result = apiResponse(request.method, url, data);
   response.writeHead(result ? 200 : 404, { 'Content-Type': 'application/json; charset=utf-8' });
   response.end(JSON.stringify(result || { error: 'Действие недоступно в демонстрационных данных' }));
   return;
  }
  const { status = 200, contentType = 'text/plain', body } = assetResponse(pathname);
  response.writeHead(status, { 'Content-Type': contentType });
  response.end(body);
 });
 server.listen(port, '127.0.0.1', () => console.log(`Server Deck fixture: http://127.0.0.1:${server.address().port}/`));
}

async function fixture(context) {
 const page = await context.newPage();
 const errors = [];
 const unexpected = [];
 const posts = [];
 const reads = [];
 page.on('pageerror', error => errors.push(error.message));
 await page.route('**/*', async route => {
  const request = route.request();
  const url = new URL(request.url());
  if (url.origin !== origin) {
   unexpected.push(`External request: ${url.origin}`);
   return route.abort();
  }
  if (url.pathname.startsWith('/api/')) {
   const method = request.method();
   const data = method === 'POST' ? request.postDataJSON() : null;
   if (method === 'POST') posts.push({ path: url.pathname, data });
   if (method === 'GET') reads.push(url);
   const json = apiResponse(method, url, data);
   if (json) return route.fulfill({ json });
   unexpected.push(`${request.method()} ${url.pathname}`);
   return route.fulfill({ status: 404, json: { error: 'Unexpected fixture request' } });
  }
  return route.fulfill(assetResponse(url.pathname));
 });
 await page.goto(origin);
 await page.locator(`#servers [data-open-server="${second.id}"]`).waitFor({ state: 'visible' });
 return { page, errors, unexpected, posts, reads };
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

async function openSection(page, section) {
 const button = page.locator(`#serverWorkspace [data-server-section="${section}"]`);
 await button.click();
 assert.ok(await button.getAttribute('aria-current'), `The ${section} section should be marked current`);
}

async function navigationScenarios(browser, width) {
 const mobile = width < 500;
 const context = await browser.newContext({ viewport: { width, height: 820 }, isMobile: mobile, hasTouch: mobile, serviceWorkers: 'block' });
 try {
  const { page, errors, unexpected, posts, reads } = await fixture(context);
  const directory = page.locator('#servers');
  const row = server => directory.locator(`[data-open-server="${server.id}"]`);
  const workspace = page.locator('#serverWorkspace');
  const identity = workspace.locator('.server-workspace-identity');
  assert.equal(await directory.locator('[data-open-server]:visible').count(), 2);
  assert.ok(await page.locator('#refresh use').evaluate(icon => icon.getBBox().width > 0));
  assert.equal(await directory.locator('[data-action]:visible').count(), 0, 'Directory rows should open one workspace');
  assert.equal(await directory.locator('[data-server-manage]:visible').count(), 0);
  if (mobile) {
   assert.equal(await page.locator('button[aria-controls="sidebar"]:visible').count(), 1, 'The phone should offer one menu toggle');
   assert.equal(await page.locator('#mobileMore').isVisible(), true);
   assert.ok((await row(second).boundingBox()).height >= 44, 'The server row needs a comfortable touch target');
  }
  await noOverflow(page, 'Server directory', width);
  await row(second).click();
  await identity.getByText(second.name, { exact: true }).waitFor({ state: 'visible' });
  assert.ok((await identity.innerText()).includes(second.host));
  assert.equal(await directory.isVisible(), false);
  assert.ok(await workspace.locator('[data-server-section="overview"]').getAttribute('aria-current'));
  assert.equal(await page.locator('[data-action="logs"]:visible').count(), 0, 'Service controls belong in Services');
  await noOverflow(page, 'Server overview', width);

  await openSection(page, 'services');
  const logs = page.locator('[data-action="logs"]:visible');
  assert.equal(await logs.count(), 1);
  await noOverflow(page, 'Server services', width);
  await logs.click();
  await page.getByText('fixture log: VPN service is running').waitFor({ state: 'visible' });
  assert.deepEqual(posts.at(-1), { path: '/api/action', data: { server: second.id, unit: 'x-ui.service', action: 'logs' } });
  await page.locator('#closeModal').click();

  await openSection(page, 'panels');
  await workspace.locator('.panel-tile').getByRole('heading', { name: '3x-ui / LucX' }).waitFor({ state: 'visible' });
  assert.equal(await page.locator('.panel-tile:visible').count(), 1);
  assert.equal(await page.locator(`[data-add-panel="${second.id}"]:visible`).count(), 1);
  await noOverflow(page, 'Server panels', width);
  await workspace.locator('[data-embed-panel="lucx"]').click();
  await page.frameLocator('#nativeFrame').getByRole('heading', { name: 'Панель VPN · фикстура' }).waitFor({ state: 'visible' });
  assert.deepEqual(posts.at(-1), { path: '/api/embedded/open', data: { server: second.id, panel: 'lucx' } });
  await noOverflow(page, 'Embedded panel', width);
  await page.locator('#closeNative').click();
  await workspace.locator('.panel-tile').getByRole('heading', { name: '3x-ui / LucX' }).waitFor({ state: 'visible' });
  assert.equal(await page.locator('#nativeFrame').count(), 0);
  assert.ok(await workspace.locator('[data-server-section="panels"]').getAttribute('aria-current'));

  await openSection(page, 'updates');
  const updateCard = page.locator(`[data-update-server="${second.id}"]`);
  await updateCard.waitFor({ state: 'visible' });
  assert.equal(await page.locator('#updatesServer:visible').count(), 0);
  assert.equal(await page.locator('[data-update-server]:visible').count(), 1);
  assert.equal(await page.locator('#updatesDashboard [data-job-history]:visible').count(), 0);
  await noOverflow(page, 'Scoped updates', width);
  const release = updateCard.locator('select');
  await release.selectOption('v3.0.2');
  await updateCard.locator('[data-ctrl="plan-update"][data-component="lucx"]').click();
  await page.getByRole('heading', { name: 'Предпросмотр обновления LucX' }).waitFor({ state: 'visible' });
  assert.deepEqual(posts.at(-1), {
   path: '/api/control/plan', data: { kind: 'update', server: second.id, component: 'lucx', version: 'v3.0.2' },
  });
  assert.equal(await page.locator('#executeControlPlan').isDisabled(), true);
  assert.equal(await page.locator('#controlActionConfirm').isChecked(), false);
  await page.locator('#closeModal').click();

  await workspace.locator(`#serverWorkspaceBody [data-software-server="${second.id}"]`).click();
  const catalog = page.locator('#softwareDashboard');
  await catalog.getByRole('heading', { name: 'Каталог компонентов', exact: true }).waitFor({ state: 'visible' });
  assert.equal(await page.getByRole('heading',{name:'Каталог компонентов',exact:true}).count(),1);
  assert.equal(await catalog.locator('#softwareServer:visible').count(), 0);
  assert.equal(await catalog.locator('[data-job-history]:visible').count(), 0);
  assert.ok(await workspace.locator('[data-server-section="updates"]').getAttribute('aria-current'));
  await noOverflow(page, 'Server software catalog', width);
  await openSection(page, 'updates');
  await updateCard.waitFor({ state: 'visible' });
  assert.equal(await catalog.isVisible(), false);

  await openSection(page, 'history');
  const jobs = page.locator('#taskHistory .control-job');
  await jobs.getByText('Задача сервера VPN', { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await page.locator('#historyServer:visible').count(), 0);
  assert.equal(await jobs.count(), 1);
  await page.locator('#activityRows').getByText('x-ui.service', { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await page.locator('#activityRows').getByText('first-only.service', { exact: true }).count(), 0);
  await noOverflow(page, 'History', width);

  await openSection(page, 'awg');
  await page.getByText('awg-fixture', { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await page.locator('[data-action]:visible').count(), 0, 'The AWG section should not duplicate service controls');
  await noOverflow(page, 'AWG', width);

  await openSection(page, 'clients');
  const clientSearch = page.locator('#clientSearch');
  await clientSearch.waitFor({ state: 'visible' });
  assert.equal(await page.locator('#clientServerFilter:visible').count(), 0);
  assert.equal(await page.getByText('Резервный клиент', { exact: true }).isVisible(), false);
  await page.locator('#clientPanelFilter').selectOption('mtproxyl');
  await clientSearch.fill('Тестовый');
  await page.getByText('Тестовый клиент', { exact: true }).waitFor({ state: 'visible' });
  assert.ok(await page.locator('[data-ctrl="edit-client"]').isVisible());
  await noOverflow(page, 'Clients', width);
  await page.locator('[data-ctrl="add-client"]').click();
  const clientServer = page.locator('#controlClientForm [name="server"]');
  assert.equal(await clientServer.inputValue(), second.id);
  assert.equal(await clientServer.isDisabled(), true, 'A client form should stay tied to the current server');
  assert.equal(await page.locator('#controlClientForm [name="panel"]').inputValue(), 'mtproxyl');
  await page.locator('#closeModal').click();

  await openSection(page, 'backups');
  const backupPanel = page.locator('#backupPanel');
  await backupPanel.waitFor({ state: 'visible' });
  assert.equal(await page.locator('#backupServer:visible').count(), 0);
  assert.equal(await page.locator('[data-ctrl="download-backup"][data-backup="backup-first"]:visible').count(), 0);
  assert.equal(await page.locator('[data-ctrl="download-backup"][data-backup="backup-second"]:visible').count(), 1);
  await backupPanel.selectOption('mtproxyl');
  await noOverflow(page, 'Backups', width);
  const backupRequest = page.waitForRequest(request => new URL(request.url()).pathname === '/api/control/backup');
  await page.locator('[data-ctrl="create-backup"]').click();
  assert.deepEqual((await backupRequest).postDataJSON(), { server: second.id, panel: 'mtproxyl' });

  await workspace.locator('[data-server-back]').click();
  await row(first).waitFor({ state: 'visible' });
  await row(first).click();
  await identity.getByText(first.name, { exact: true }).waitFor({ state: 'visible' });
  assert.ok((await identity.innerText()).includes(first.host));
  await openSection(page, 'updates');
  await page.locator(`[data-update-server="${first.id}"]`).getByText(first.status.error, { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await updateCard.isVisible(), false, 'Switching servers should remove the former server from the workspace');
  await openSection(page, 'history');
  await jobs.getByText('Задача резервного сервера', { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await jobs.count(), 1);
  await page.reload();
  await identity.getByText(first.name, { exact: true }).waitFor({ state: 'visible' });
  await jobs.getByText('Задача резервного сервера', { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await jobs.count(), 1, 'Reloading a server link should restore the scoped section');

  if (mobile) {
   await page.locator('#mobileMore').click();
   assert.equal(await page.locator('aside [data-filter="panels"]:visible, aside [data-filter="clients"]:visible, aside [data-filter="backups"]:visible, aside [data-filter="awg"]:visible').count(), 0);
   await page.locator('#closeMobileMenu').click();
  }
  await navigate(page, 'health', mobile);
  assert.equal(await workspace.isVisible(), false);
  await page.locator('#healthDashboard').waitFor({ state: 'visible' });
  await noOverflow(page, 'Fleet health', width);
  await navigate(page, 'updates', mobile);
  await page.locator('#panelUpdatesCard').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#updatesDashboard').isVisible(), false, 'Server updates should appear only in the selected workspace');
  await noOverflow(page, 'Panel update center', width);
  await navigate(page, 'activity', mobile);
  await page.locator('#activityRows').getByText('x-ui.service', { exact: true }).waitFor({ state: 'visible' });
  await page.locator('#activityRows').getByText('first-only.service', { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await page.locator('#taskHistory .control-job:visible').count(), 0, 'The fleet log should not duplicate per-server job controls');
  await noOverflow(page, 'Fleet action log', width);
  await navigate(page, 'alerts', mobile);
  await page.locator('.alerts-icon svg').waitFor({ state: 'visible' });
  await navigate(page, 'settings', mobile);
  await page.locator('#accountUsername').waitFor({ state: 'visible' });
  assert.equal(await page.locator('.account-icon svg').isVisible(), true);
  assert.equal(await page.locator('#accountUsername').inputValue(), 'fixture-operator');
  await noOverflow(page, 'Settings', width);

  for (const endpoint of ['/api/control/clients', '/api/control/updates', '/api/control/software']) {
   assert.ok(reads.some(url => url.pathname === endpoint && url.searchParams.get('server') === second.id), `Missing scoped request for ${endpoint}`);
  }
  assert.equal(posts.length, 4, 'Navigation should only request service logs, the embedded session, one update preview, and a fixture backup');
  assert.deepEqual(unexpected, [], 'Unexpected browser requests');
  assert.deepEqual(errors, [], 'Uncaught browser errors');
 } finally {
  await context.close();
 }
}

async function run() {
 const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
 const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined });
 try {
  for (const width of [320, 390, 1440]) await navigationScenarios(browser, width);
  console.log('PASS directory and per-server workspace at 320, 390 and 1440px: services, embedded panel return, AWG, clients, backups, updates, catalog and history.');
 } finally {
  await browser.close();
 }
}

if (process.argv[2] === '--preview') preview();
else run().catch(error => { console.error(error.stack); process.exitCode = 1 });
