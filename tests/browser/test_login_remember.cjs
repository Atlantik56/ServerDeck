// Browser regression with isolated temporary profiles and fictional credentials.
// All URLs are intercepted locally; this never contacts the deployed panel.
// PLAYWRIGHT_MODULE may point to an existing Playwright installation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const origin = 'https://deck.example';
const outside = 'https://outside.test';
const cookieName = '__Host-deck_session';
const token = crypto.randomBytes(32).toString('base64url');
const password = 'fictional-test-password';
const root = path.resolve(__dirname, '../../frontend/pwa');
const options = {
  headless: true,
  executablePath: process.env.CHROME_BIN || undefined,
  viewport: { width: 393, height: 780 }, isMobile: true, hasTouch: true,
};
const lifetime = 30 * 86400;
const cookie = `${cookieName}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${lifetime}`;
const cleared = `${cookieName}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`;

async function fixture(context, oldBehaviour = false) {
  const state = { missingRoot: 0, sessionChecks: 0, submitted: null };
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    const headers = { 'cache-control': 'no-store' };
    const authorized = request.headers().cookie?.split(';').some(part => part.trim() === `${cookieName}=${token}`);
    if (url.origin === outside) return route.fulfill({ contentType: 'text/html', body: `<a href="${origin}/">Open panel</a>` });
    assert.equal(url.origin, origin, 'Unexpected external URL in isolated test');
    if (url.pathname === '/') {
      if (authorized) return route.fulfill({ contentType: 'text/html', headers, body: '<h1>Fixture dashboard</h1>' });
      state.missingRoot++;
      if (oldBehaviour) headers['set-cookie'] = cleared;
      return route.fulfill({ status: 303, headers: { ...headers, location: '/login/' }, body: '' });
    }
    if (url.pathname === '/auth/session') {
      state.sessionChecks++;
      if (!authorized && oldBehaviour) headers['set-cookie'] = cleared;
      return route.fulfill({ status: authorized ? 200 : 401, contentType: 'application/json', headers,
        body: JSON.stringify(authorized ? { username: 'fixture-admin' } : { error: 'Sign in' }) });
    }
    if (url.pathname === '/auth/login') {
      state.submitted = request.postDataJSON();
      assert.equal(state.submitted.password, password);
      return route.fulfill({ status: 200, contentType: 'application/json', headers: { ...headers, 'set-cookie': cookie },
        body: JSON.stringify({ ok: true, username: 'fixture-admin' }) });
    }
    const relative = url.pathname === '/login/' ? 'login/index.html' : url.pathname.slice(1);
    const file = path.resolve(root, relative);
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      return route.fulfill({ status: 404, body: '' });
    }
    const contentType = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png',
      '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json' }[path.extname(file)];
    return route.fulfill({ contentType, headers, body: fs.readFileSync(file) });
  });
  return state;
}

async function crossSite(oldBehaviour) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'deck-remember-test-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, options);
    const state = await fixture(context, oldBehaviour);
    await context.addCookies([{ name: cookieName, value: token, url: origin, secure: true, httpOnly: true,
      sameSite: 'Strict', expires: Date.now() / 1000 + lifetime }]);
    const page = await context.newPage();
    await page.goto(outside);
    await page.getByRole('link', { name: 'Open panel' }).click();
    if (oldBehaviour) {
      await page.locator('#loginForm').waitFor();
      await page.waitForFunction(() => document.readyState === 'complete');
      assert.equal((await context.cookies(origin)).some(c => c.name === cookieName), false);
      assert.equal(page.url(), origin + '/login/');
    } else {
      await page.getByRole('heading', { name: 'Fixture dashboard' }).waitFor();
      assert.equal((await context.cookies(origin)).some(c => c.name === cookieName), true);
      await context.close();
      context = await chromium.launchPersistentContext(profile, options);
      await fixture(context);
      const reopened = await context.newPage();
      await reopened.goto(origin);
      await reopened.getByRole('heading', { name: 'Fixture dashboard' }).waitFor();
    }
    assert.ok(state.missingRoot >= 1, 'Cross-site navigation must omit the Strict cookie');
    return true;
  } finally {
    if (context) await context.close();
    fs.rmSync(profile, { recursive: true, force: true });
  }
}

async function loginForm() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'deck-login-test-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, options);
    const state = await fixture(context);
    const page = await context.newPage();
    await page.goto(origin + '/login/');
    assert.equal(await page.locator('#loginUsername').getAttribute('autocomplete'), 'username');
    assert.equal(await page.locator('#loginPassword').getAttribute('autocomplete'), 'current-password');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false);
    await page.locator('#loginUsername').fill('fixture-admin');
    await page.locator('#loginPassword').fill(password);
    await page.locator('#loginRemember').check();
    await page.locator('#loginSubmit').click();
    await page.getByRole('heading', { name: 'Fixture dashboard' }).waitFor();
    assert.equal(state.submitted.remember, true);
    const stored = (await context.cookies(origin)).find(c => c.name === cookieName);
    assert.ok(stored.secure && stored.httpOnly && stored.sameSite === 'Strict');
    assert.ok(stored.expires > Date.now() / 1000 + 29 * 86400);
    assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
    state.submitted.password = '';
    await context.close();
    context = await chromium.launchPersistentContext(profile, options);
    await fixture(context);
    const reopened = await context.newPage();
    await reopened.goto(origin);
    await reopened.getByRole('heading', { name: 'Fixture dashboard' }).waitFor();
    return true;
  } finally {
    if (context) await context.close();
    fs.rmSync(profile, { recursive: true, force: true });
  }
}

(async () => {
  const result = {
    priorCookieDeletionReproduced: await crossSite(true),
    fixedCrossSiteOpenAndBrowserRestart: await crossSite(false),
    rememberedFormAndBrowserRestart: await loginForm(),
    physicalAndroidTested: false,
  };
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
