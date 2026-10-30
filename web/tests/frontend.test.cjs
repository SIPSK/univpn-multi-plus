/* Standalone frontend tests. This server is a mock and never controls a VPN. */
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');

const web = path.resolve(__dirname, '..');
const artifacts = path.join(__dirname, 'artifacts');
const token = 'frontend-test-token-only';
const fixtureNetworkVersion = 'a'.repeat(64);
const calls = [];
const results = [];
let offline = false;
let nativeAuth = true;
let failSettings = false;
let creationDelayMs = 0;
let creationNotice = '';
let environmentResult = { ok: true, phase: 'complete', exitCode: 0 };
let nativeDelayMs = 0;
let pendingNative = 0;
let handoffRequired = false;
let expansionInProgress = false;
let expansionTarget = '';
let expansionResult = 'credentials';
let expansionDelayMs = 0;
let targetNeedsCredentials = false;
let targetAuthentications = 0;
let nextId = 3;
const settings = { startup: false };
const profiles = [
  { id: 'a2', name: 'A2', gateway: 'vpn-a2.example', port: 443, networkVersion: fixtureNetworkVersion, status: 'disconnected', autoConnect: false, hasSavedCredential: false },
  { id: 'a5', name: 'A5', gateway: 'vpn-a5.example', port: 49999, networkVersion: fixtureNetworkVersion, status: 'connected', autoConnect: false, hasSavedCredential: false },
];

function json(res, code, body, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://127.0.0.1');
    let body;
    if (!['GET', 'HEAD'].includes(req.method)) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      body = JSON.parse(Buffer.concat(chunks).toString() || '{}');
    }
    if (url.pathname.startsWith('/api/')) {
      calls.push({ method: req.method, path: url.pathname, hasToken: req.headers['x-vpn-token'] === token, body });
      if (url.pathname === '/api/bootstrap') {
        return req.headers.cookie?.includes('frontend_session=valid')
          ? json(res, 200, { token, version: 'test' }) : json(res, 401, { error: 'Session missing' });
      }
      if (req.headers['x-vpn-token'] !== token) return json(res, 401, { error: 'Invalid token' });
      if (url.pathname === '/api/session') {
        return json(res, 200, { ok: true }, { 'Set-Cookie': 'frontend_session=valid; HttpOnly; SameSite=Strict; Path=/' });
      }
      if (url.pathname === '/api/state') {
        if (pendingNative) return json(res, 503, { error: 'Fixture native operation holds the manager lock' });
        if (offline) return json(res, 503, { error: 'Service unavailable' });
        return json(res, 200, { profiles, settings, handoffRequired, expansion: { inProgress: expansionInProgress, ...(expansionTarget && expansionInProgress ? { profileId: expansionTarget } : {}) },
          error: handoffRequired ? '请先在原客户端断开 VPN 并退出，再由网页连接。' : '',
          capabilities: { nativeAuth, otp: true, environment: true }, version: 'test' });
      }
      if (url.pathname === '/api/environment' && req.method === 'GET') {
        return json(res, 200, environmentResult);
      }
      if (url.pathname === '/api/settings' && req.method === 'POST') {
        if (failSettings) return json(res, 503, { error: '开机启动设置未保存。' });
        settings.startup = body.startup;
        return json(res, 200, { settings });
      }
      if (url.pathname === '/api/auto-connect' && req.method === 'POST') {
        for (const profile of profiles) profile.autoConnect = body.enabled;
        return json(res, 200, { ok: true });
      }
      if (url.pathname === '/api/profiles' && req.method === 'POST') {
        if (creationDelayMs) await new Promise((resolve) => setTimeout(resolve, creationDelayMs));
        const profile = { id: `vpn${nextId++}`, ...body, networkVersion: fixtureNetworkVersion, status: 'disconnected', autoConnect: false, hasSavedCredential: false };
        profiles.push(profile);
        return json(res, 201, { profile, ...(creationNotice ? { notice: creationNotice } : {}) });
      }
      const match = url.pathname.match(/^\/api\/profiles\/([^/]+)(?:\/(connect|expand-connect|otp|disconnect|credential))?$/);
      const profile = profiles.find((item) => item.id === decodeURIComponent(match?.[1] || ''));
      if (!profile) return json(res, 404, { error: 'Unknown VPN' });
      if (['connect', 'expand-connect'].includes(match[2]) && body.networkVersion !== profile.networkVersion) {
        return json(res, 409, { error: '连接地址已更新，请重新登录。', code: 'credentials_required' });
      }
      if (match[2] === 'connect') {
        if (profile.id === expansionTarget) {
          if (!targetNeedsCredentials) return json(res, 409, { error: '新增连接需要确认。', code: 'expansion_required' });
          if (!body.password) return json(res, 409, { error: '请填写登录信息。', code: 'credentials_required' });
        }
        if (nativeDelayMs) {
          pendingNative += 1;
          try { await new Promise((resolve) => setTimeout(resolve, nativeDelayMs)); }
          finally { pendingNative -= 1; }
        }
        if (body.username !== undefined || body.password !== undefined) {
          profile.hasSavedCredential = Boolean(body.remember);
          profile.autoConnect = Boolean(body.autoConnect);
        } else if (!profile.hasSavedCredential) return json(res, 422, { error: '请先登录。' });
        profile.status = profile.id === 'a2' ? 'otp' : 'connected';
        profile.canDisconnect = true;
        if (profile.id === expansionTarget) targetAuthentications += 1;
        return json(res, 202, { ok: true });
      }
      if (match[2] === 'expand-connect') {
        expansionInProgress = true;
        pendingNative += 1;
        try {
          if (expansionDelayMs) await new Promise((resolve) => setTimeout(resolve, expansionDelayMs));
        } finally {
          expansionInProgress = false;
          pendingNative -= 1;
        }
        targetNeedsCredentials = true;
        if (expansionResult === 'credentials-error') return json(res, 409, { error: '请填写登录信息。', code: 'credentials_required', details: { failedProfileIds: ['restored-one'] } });
        if (expansionResult === 'failed') return json(res, 409, { error: '新增连接未完成，配置已保留。', details: { failedProfileIds: ['restored-one'] } });
        if (expansionResult === 'connected') {
          profile.status = 'connected';
          profile.canDisconnect = true;
          targetAuthentications += 1;
          return json(res, 200, { ok: true });
        }
        return json(res, 200, { ok: true, credentialsRequired: true });
      }
      if (match[2] === 'otp') {
        if (body.code !== '830461') return json(res, 422, { error: '动态口令不正确，请重试。' });
        profile.status = 'connected';
        return json(res, 200, { ok: true });
      }
      if (match[2] === 'disconnect') {
        if (nativeDelayMs) {
          pendingNative += 1;
          try { await new Promise((resolve) => setTimeout(resolve, nativeDelayMs)); }
          finally { pendingNative -= 1; }
        }
        profile.status = 'disconnected';
        profile.canDisconnect = false;
        return json(res, 200, { ok: true });
      }
      if (match[2] === 'credential' && req.method === 'DELETE') {
        profile.hasSavedCredential = false;
        profile.autoConnect = false;
        return json(res, 200, { ok: true });
      }
      if (req.method === 'PATCH') {
        Object.assign(profile, body);
        return json(res, 200, { profile });
      }
      if (req.method === 'DELETE') {
        profiles.splice(profiles.indexOf(profile), 1);
        return json(res, 200, { ok: true });
      }
      return json(res, 405, { error: 'Method unsupported' });
    }
    const files = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'] };
    const file = files[url.pathname];
    if (!file) { res.writeHead(404); return res.end(); }
    res.writeHead(200, {
      'Content-Type': `${file[1]}; charset=utf-8`, 'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'",
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(await fs.readFile(path.join(web, file[0])));
  } catch { json(res, 500, { error: 'Mock server error' }); }
});

function passed(name) { results.push(name); process.stdout.write(`PASS ${name}\n`); }

async function main() {
  await fs.mkdir(artifacts, { recursive: true });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browserOptions = { headless: true };
  if (process.env.VPN_TEST_BROWSER) {
    await fs.access(process.env.VPN_TEST_BROWSER);
    browserOptions.executablePath = process.env.VPN_TEST_BROWSER;
  } else if (process.env.VPN_TEST_CHANNEL) {
    if (!['msedge', 'chrome'].includes(process.env.VPN_TEST_CHANNEL)) throw new Error('VPN_TEST_CHANNEL must be msedge or chrome.');
    browserOptions.channel = process.env.VPN_TEST_CHANNEL;
  }
  // Without an explicit executable/channel, Playwright uses its downloaded
  // Chromium. Install it with `npx playwright install chromium`.
  const browser = await chromium.launch(browserOptions);
  const context = await browser.newContext({ viewport: { width: 1024, height: 720 }, locale: 'zh-CN' });
  const page = await context.newPage();
  await page.addInitScript(() => {
    window.testTimeouts = [];
    const original = window.setTimeout;
    window.setTimeout = (callback, delay, ...args) => {
      window.testTimeouts.push(delay);
      return original(callback, delay, ...args);
    };
  });
  const pageErrors = [];
  const consoleMessages = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('console', (entry) => consoleMessages.push(entry.text()));
  const row = (id) => page.locator(`[data-profile-id="${id}"]`);
  try {
    await page.goto(`${origin}/#token=${token}`);
    await row('a2').waitFor();
    assert.equal(new URL(page.url()).hash, '');
    assert.ok(calls.some((call) => call.path === '/api/session' && call.method === 'POST' && call.hasToken));
    const cookies = await context.cookies();
    assert.ok(cookies.find((cookie) => cookie.name === 'frontend_session' && cookie.httpOnly && cookie.sameSite === 'Strict'));
    assert.equal(await row('a2').locator('.vpn-status').textContent(), '未连接');
    assert.equal(await row('a5').locator('.vpn-status').textContent(), '已连接');
    assert.equal(await row('a2').locator('.row-automatic input').isChecked(), false);
    assert.equal(await row('a5').locator('.row-automatic input').isChecked(), false);
    assert.equal(await page.locator('#startup-enabled').isChecked(), false);
    await page.screenshot({ path: path.join(artifacts, 'desktop.png') });
    passed('Session handshake clears fragment and shows truthful states');

    await row('a2').locator('.row-action').click();
    await row('a2').getByLabel('账号', { exact: true }).fill('test-user');
    const password = row('a2').getByLabel('密码', { exact: true });
    await password.fill('frontend-test-only');
    await password.focus();
    await page.waitForTimeout(2300);
    assert.equal(await password.inputValue(), 'frontend-test-only');
    assert.equal(await password.evaluate((input) => document.activeElement === input), true);
    passed('Status polling preserves typed input and keyboard focus');
    await row('a2').locator('.auth-panel').getByRole('button', { name: '连接', exact: true }).click();
    await row('a2').getByLabel('动态口令', { exact: true }).waitFor();
    await page.waitForFunction(() => !document.querySelector('[data-profile-id="a2"] .row-action').disabled);
    assert.ok(calls.some((call) => call.path.endsWith('/a2/connect') && call.body.username === 'test-user' && call.body.password === 'frontend-test-only'));
    assert.ok(calls.some((call) => call.path.endsWith('/a2/connect') && call.body.remember === false && call.body.autoConnect === false));
    assert.equal(await row('a2').locator('input[type="password"]').count(), 0);
    await page.screenshot({ path: path.join(artifacts, 'verification.png') });
    passed('Login routes the current request and clears the password form');

    await row('a2').getByLabel('动态口令', { exact: true }).fill('000000');
    await row('a2').getByRole('button', { name: '确认', exact: true }).click();
    await row('a2').locator('.row-error').filter({ hasText: '动态口令不正确' }).waitFor();
    assert.equal(await row('a2').getByLabel('动态口令', { exact: true }).inputValue(), '');
    await row('a2').getByLabel('动态口令', { exact: true }).fill('830461');
    await row('a2').getByRole('button', { name: '确认', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a2"]')?.dataset.status === 'connected');
    assert.equal(await row('a2').locator('.auth-panel').count(), 0);
    assert.equal(await row('a2').locator('.row-error').isVisible(), false);
    passed('OTP errors are visible, codes are cleared, and success follows server state');

    await row('a5').locator('.row-action').click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'disconnected');
    await page.reload();
    await row('a5').waitFor();
    assert.ok(calls.some((call) => call.path === '/api/bootstrap'));
    assert.equal(await row('a5').locator('.vpn-status').textContent(), '未连接');
    passed('Disconnect and F5 session restoration work without storage');

    const connectCount = () => calls.filter((call) => call.path.endsWith('/connect')).length;
    let beforeConnect = connectCount();
    await row('a5').locator('.row-automatic input').check();
    await row('a5').getByLabel('密码', { exact: true }).waitFor();
    assert.equal(await row('a5').locator('.row-automatic input').isChecked(), true);
    assert.ok(calls.some((call) => call.path === '/api/profiles/a5' && call.method === 'PATCH' && JSON.stringify(call.body) === '{"autoConnect":true}'));
    assert.equal(connectCount(), beforeConnect);
    assert.equal(settings.startup, false);
    assert.equal(await row('a5').getByLabel('自动连接', { exact: true }).isChecked(), true);
    assert.equal(await row('a5').getByLabel('保存密码', { exact: true }).isChecked(), true);
    assert.equal(await row('a5').getByLabel('保存密码', { exact: true }).isDisabled(), true);
    passed('Per-profile automatic connection changes only its flag and requests first login');

    await row('a5').getByLabel('自动连接', { exact: true }).uncheck();
    await row('a5').getByLabel('保存密码', { exact: true }).uncheck();
    await row('a5').getByLabel('自动连接', { exact: true }).check();
    assert.equal(await row('a5').getByLabel('保存密码', { exact: true }).isChecked(), true);
    await row('a5').getByLabel('账号', { exact: true }).fill('saved-test-user');
    await row('a5').getByLabel('密码', { exact: true }).fill('saved-test-password-only');
    await page.screenshot({ path: path.join(artifacts, 'login-options.png') });
    await row('a5').locator('.auth-panel').getByRole('button', { name: '连接', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'connected');
    const savedLogin = calls.filter((call) => call.path.endsWith('/a5/connect')).at(-1);
    assert.deepEqual(savedLogin.body, { username: 'saved-test-user', password: 'saved-test-password-only', remember: true, autoConnect: true, networkVersion: fixtureNetworkVersion });
    assert.equal(await row('a5').locator('.auth-panel').count(), 0);
    passed('Automatic login implies saving and submits explicit credential preferences');

    await row('a5').locator('.row-action').click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'disconnected');
    await row('a5').locator('.row-action').click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'connected');
    assert.deepEqual(calls.filter((call) => call.path.endsWith('/a5/connect')).at(-1).body, { networkVersion: fixtureNetworkVersion });
    assert.equal(await row('a5').locator('input[type="password"]').count(), 0);
    passed('Saved credentials connect with only the endpoint version and no account or password');

    await row('a5').locator('.row-action').click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'disconnected');
    await row('a5').locator('.more-button').click();
    await row('a5').getByRole('menuitem', { name: '重新登录', exact: true }).click();
    assert.equal(await row('a5').getByLabel('账号', { exact: true }).inputValue(), '');
    assert.equal(await row('a5').getByLabel('密码', { exact: true }).inputValue(), '');
    await row('a5').getByLabel('账号', { exact: true }).fill('updated-test-user');
    await row('a5').getByLabel('密码', { exact: true }).fill('updated-test-password-only');
    await row('a5').getByLabel('自动连接', { exact: true }).uncheck();
    await row('a5').locator('.auth-panel').getByRole('button', { name: '连接', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'connected');
    assert.equal(calls.filter((call) => call.path.endsWith('/a5/connect')).at(-1).body.autoConnect, false);
    assert.equal(await row('a5').locator('.row-automatic input').isChecked(), false);
    passed('Relogin opens blank fields and updates saved login preferences');

    beforeConnect = calls.filter((call) => call.path.endsWith('/disconnect')).length;
    await row('a5').locator('.more-button').click();
    await row('a5').getByRole('menuitem', { name: '忘记密码', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"] .row-menu button:nth-child(2)').hidden);
    assert.ok(calls.some((call) => call.path === '/api/profiles/a5/credential' && call.method === 'DELETE'));
    assert.equal(calls.filter((call) => call.path.endsWith('/disconnect')).length, beforeConnect);
    assert.equal(await row('a5').locator('.vpn-status').textContent(), '已连接');
    await row('a5').locator('.row-action').click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'disconnected');
    await row('a5').locator('.row-action').click();
    await row('a5').getByLabel('密码', { exact: true }).waitFor();
    assert.equal(await row('a5').getByLabel('保存密码', { exact: true }).isChecked(), false);
    await row('a5').getByRole('button', { name: '取消登录', exact: true }).click();
    passed('Forgetting credentials cancels saved login without disconnecting an active VPN');

    beforeConnect = connectCount();
    await page.getByRole('button', { name: '设置', exact: true }).click();
    await page.getByLabel('开机启动', { exact: true }).check();
    await page.waitForFunction(() => !document.querySelector('#startup-enabled').disabled && document.querySelector('#startup-enabled').checked);
    assert.equal(settings.startup, true);
    await page.getByRole('button', { name: '全部自动', exact: true }).click();
    await page.waitForFunction(() => [...document.querySelectorAll('.row-automatic input')].every((input) => input.checked && !input.disabled));
    assert.equal(settings.startup, true);
    assert.equal(connectCount(), beforeConnect);
    assert.equal(await page.locator('.auth-panel').count(), 0);
    await page.screenshot({ path: path.join(artifacts, 'settings.png') });
    await page.getByRole('button', { name: '全部取消', exact: true }).click();
    await page.waitForFunction(() => [...document.querySelectorAll('.row-automatic input')].every((input) => !input.checked && !input.disabled));
    assert.equal(settings.startup, true);
    await page.getByLabel('开机启动', { exact: true }).uncheck();
    await page.waitForFunction(() => !document.querySelector('#startup-enabled').disabled && !document.querySelector('#startup-enabled').checked);
    assert.equal(connectCount(), beforeConnect);
    assert.ok(calls.some((call) => call.path === '/api/settings' && call.body.startup === true));
    assert.ok(calls.some((call) => call.path === '/api/auto-connect' && call.body.enabled === true));
    assert.ok(calls.some((call) => call.path === '/api/auto-connect' && call.body.enabled === false));
    passed('Startup is independent from batch automatic flags and neither operation connects a VPN');

    failSettings = true;
    await page.getByLabel('开机启动', { exact: true }).check();
    await page.locator('#notice').filter({ hasText: '开机启动设置未保存' }).waitFor();
    assert.equal(await page.getByLabel('开机启动', { exact: true }).isChecked(), false);
    assert.equal(await page.getByLabel('开机启动', { exact: true }).isDisabled(), false);
    failSettings = false;
    await page.getByLabel('开机启动', { exact: true }).check();
    await page.waitForFunction(() => !document.querySelector('#startup-enabled').disabled && document.querySelector('#startup-enabled').checked);
    await page.getByLabel('开机启动', { exact: true }).uncheck();
    await page.waitForFunction(() => !document.querySelector('#startup-enabled').disabled && !document.querySelector('#startup-enabled').checked);
    await page.keyboard.press('Escape');
    assert.equal(await page.getByRole('button', { name: '设置', exact: true }).getAttribute('aria-expanded'), 'false');
    await page.reload();
    await row('a5').waitFor();
    assert.equal(await page.getByLabel('开机启动', { exact: true }).isChecked(), false);
    passed('Failed settings revert to server state and F5 keeps confirmed preferences');

    const connectionsBeforeCheck = connectCount();
    await page.getByRole('button', { name: '设置', exact: true }).click();
    await page.getByRole('button', { name: '检查环境', exact: true }).click();
    await page.locator('#notice').filter({ hasText: '环境检查通过。' }).waitFor();
    environmentResult = { ok: false, phase: 'source_preflight', exitCode: 1, errorCode: 7001 };
    await page.getByRole('button', { name: '检查环境', exact: true }).click();
    await page.locator('#notice').filter({ hasText: '环境检查未通过。' }).waitFor();
    assert.equal(await page.getByText('source_preflight', { exact: true }).count(), 0);
    assert.equal(await page.getByText('7001', { exact: true }).count(), 0);
    assert.equal(connectCount(), connectionsBeforeCheck);
    assert.ok(calls.filter((call) => call.path === '/api/environment').every((call) => call.method === 'GET'));
    await page.getByRole('button', { name: '全部取消', exact: true }).click();
    await page.waitForFunction(() => !document.querySelector('#disable-all-auto').disabled);
    await page.keyboard.press('Escape');
    passed('Environment checks are read-only and show one plain result without internal diagnostic codes');

    Object.assign(profiles.find((profile) => profile.id === 'a5'), { status: 'error', canDisconnect: true, error: '连接状态未确认，请断开后重连' });
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"] .row-action')?.textContent === '断开');
    assert.equal(await row('a5').locator('.row-action').isDisabled(), false);
    const reconnectsBeforeCleanup = connectCount();
    await row('a5').locator('.row-action').click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'disconnected');
    delete profiles.find((profile) => profile.id === 'a5').error;
    assert.equal(connectCount(), reconnectsBeforeCleanup);
    assert.equal(await row('a5').locator('.auth-panel').count(), 0);
    passed('An unconfirmed owned session stays disconnectable without starting another login');

    await page.getByRole('button', { name: '添加', exact: true }).click();
    await page.getByLabel('名称（选填）', { exact: true }).fill('<img src=x onerror="window.bad=1">');
    await page.getByLabel('网关', { exact: true }).fill('vpn.example.com');
    await page.getByLabel('端口', { exact: true }).fill('49999');
    await page.locator('#profile-dialog').getByRole('button', { name: '添加', exact: true }).click();
    await row('vpn3').waitFor();
    assert.equal(await row('vpn3').locator('img').count(), 0);
    assert.equal(await page.evaluate(() => window.bad), undefined);
    await row('vpn3').locator('.more-button').click();
    await row('vpn3').getByRole('menuitem', { name: '编辑', exact: true }).click();
    await page.getByLabel('名称（选填）', { exact: true }).fill('研究 VPN');
    await page.locator('#profile-dialog').getByRole('button', { name: '保存', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="vpn3"] .vpn-name')?.textContent === '研究 VPN · vpn.example.com:49999');
    passed('Profile create/edit use safe text rendering and proper API methods');

    await row('vpn3').locator('.more-button').click();
    await row('vpn3').getByRole('menuitem', { name: '删除', exact: true }).click();
    assert.equal(await page.locator('#delete-name').textContent(), '研究 VPN · vpn.example.com:49999');
    assert.equal(calls.filter((call) => call.method === 'DELETE' && call.path === '/api/profiles/vpn3').length, 0);
    await page.locator('#delete-dialog').getByRole('button', { name: '删除', exact: true }).click();
    await row('vpn3').waitFor({ state: 'detached' });
    passed('Delete requires an explicit confirmation');

    await page.getByRole('button', { name: '添加', exact: true }).click();
    assert.equal(await page.getByLabel('名称（选填）', { exact: true }).evaluate((input) => input.required), false);
    await page.getByLabel('网关', { exact: true }).fill('192.0.2.123');
    await page.locator('#profile-dialog').getByRole('button', { name: '添加', exact: true }).click();
    await row('vpn4').waitFor();
    assert.equal(await row('vpn4').locator('.vpn-name').textContent(), '192.0.2.123:443');
    assert.equal(calls.find((call) => call.method === 'POST' && call.path === '/api/profiles' && call.body.gateway === '192.0.2.123').body.name, '');
    await row('vpn4').locator('.more-button').click();
    await row('vpn4').getByRole('menuitem', { name: '删除', exact: true }).click();
    await page.locator('#delete-dialog').getByRole('button', { name: '删除', exact: true }).click();
    await row('vpn4').waitFor({ state: 'detached' });
    passed('Gateway and port identify a connection without a required name');

    creationDelayMs = 350;
    const createsBeforeWaiting = calls.filter((call) => call.method === 'POST' && call.path === '/api/profiles').length;
    await page.getByRole('button', { name: '添加', exact: true }).click();
    await page.getByLabel('网关', { exact: true }).fill('192.0.2.124');
    await page.locator('#profile-dialog').getByRole('button', { name: '添加', exact: true }).click();
    assert.equal(await page.locator('#save-profile').isDisabled(), true);
    await page.waitForTimeout(100);
    assert.equal(calls.filter((call) => call.method === 'POST' && call.path === '/api/profiles').length, createsBeforeWaiting + 1);
    await row('vpn5').waitFor();
    creationDelayMs = 0;
    assert.equal(calls.filter((call) => call.method === 'POST' && call.path === '/api/profiles').length, createsBeforeWaiting + 1);
    const timeouts = await page.evaluate(() => window.testTimeouts);
    assert.ok(timeouts.includes(300000));
    assert.ok(timeouts.includes(150000));
    await row('vpn5').locator('.more-button').click();
    await row('vpn5').getByRole('menuitem', { name: '删除', exact: true }).click();
    await page.locator('#delete-dialog').getByRole('button', { name: '删除', exact: true }).click();
    await row('vpn5').waitFor({ state: 'detached' });
    passed('Native creation and disconnect use long waits while pending actions stay busy without resend');

    nativeDelayMs = 3000;
    await row('a5').locator('.row-action').click();
    await row('a5').getByLabel('账号', { exact: true }).fill('long-native-test-user');
    await row('a5').getByLabel('密码', { exact: true }).fill('long-native-test-password-only');
    const longConnectsBefore = connectCount();
    await row('a5').locator('.auth-panel').getByRole('button', { name: '连接', exact: true }).click();
    await page.waitForTimeout(200);
    const stateReadsDuringConnect = calls.filter((call) => call.path === '/api/state').length;
    await page.waitForTimeout(2100);
    assert.equal(calls.filter((call) => call.path === '/api/state').length, stateReadsDuringConnect);
    assert.equal(connectCount(), longConnectsBefore + 1);
    assert.equal(await row('a5').locator('.auth-panel button[type="submit"]').isDisabled(), true);
    assert.equal(await page.locator('#notice').isVisible(), false);
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'connected');
    const disconnectsBeforeWaiting = calls.filter((call) => call.path.endsWith('/disconnect')).length;
    await row('a5').locator('.row-action').click();
    await page.waitForTimeout(200);
    const stateReadsDuringDisconnect = calls.filter((call) => call.path === '/api/state').length;
    await page.waitForTimeout(2100);
    assert.equal(calls.filter((call) => call.path === '/api/state').length, stateReadsDuringDisconnect);
    assert.equal(calls.filter((call) => call.path.endsWith('/disconnect')).length, disconnectsBeforeWaiting + 1);
    assert.equal(await row('a5').locator('.row-action').isDisabled(), true);
    assert.equal(await page.locator('#notice').isVisible(), false);
    await page.waitForFunction(() => document.querySelector('[data-profile-id="a5"]')?.dataset.status === 'disconnected');
    nativeDelayMs = 0;
    passed('Long connect and disconnect pause polling, keep controls busy and never fake offline or resubmit');

    handoffRequired = true;
    const actionsBeforeHandoff = calls.filter((call) => /\/(connect|disconnect)$/.test(call.path)).length;
    await page.locator('#notice').filter({ hasText: '请先在原客户端断开 VPN 并退出' }).waitFor();
    assert.equal(await row('a5').locator('.row-action').isDisabled(), true);
    assert.equal(await row('a2').locator('.row-action').isDisabled(), false);
    assert.equal(await page.getByRole('button', { name: '添加', exact: true }).isDisabled(), false);
    assert.equal(await row('a5').locator('.row-automatic input').isDisabled(), false);
    assert.equal(calls.filter((call) => /\/(connect|disconnect)$/.test(call.path)).length, actionsBeforeHandoff);
    handoffRequired = false;
    await page.waitForFunction(() => document.querySelector('#notice').hidden);
    assert.equal(await row('a5').locator('.row-action').isDisabled(), false);
    passed('First handoff keeps configurations visible, blocks external takeover and leaves owned controls usable');

    await row('a5').locator('.row-action').click();
    await row('a5').getByLabel('密码', { exact: true }).fill('do-not-keep-on-target-change');
    profiles.find((profile) => profile.id === 'a5').gateway = 'changed.example.com';
    await page.waitForFunction(() => !document.querySelector('[data-profile-id="a5"] input[type="password"]'));
    passed('Changing a gateway discards an unfinished credential form');

    nativeAuth = false;
    await page.locator('#notice').filter({ hasText: '网页登录尚未就绪' }).waitFor();
    assert.equal(await row('a5').locator('.row-action').isDisabled(), true);
    passed('Unavailable native authentication is not represented as working');
    nativeAuth = true;
    await page.waitForFunction(() => document.querySelector('#notice').hidden);

    offline = true;
    await page.locator('#notice').filter({ hasText: '无法连接本地服务' }).waitFor();
    assert.equal(await row('a2').locator('.vpn-status').textContent(), '状态未知');
    assert.equal(await page.getByRole('button', { name: '添加', exact: true }).isDisabled(), true);
    offline = false;
    await page.waitForFunction(() => document.querySelector('#notice').hidden);
    passed('Backend loss shows unknown state and disables mutations');

    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForFunction(() => !document.querySelector('[data-profile-id="a2"] .row-action').disabled);
    await page.screenshot({ path: path.join(artifacts, 'mobile.png') });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await page.getByRole('button', { name: '添加', exact: true }).focus();
    await page.keyboard.press('Enter');
    await page.locator('#profile-dialog[open]').waitFor();
    assert.equal(await page.getByLabel('网关', { exact: true }).evaluate((input) => document.activeElement === input), true);
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('#profile-dialog').getAttribute('open'), null);
    passed('Narrow screens and keyboard dialog navigation work');

    await page.setViewportSize({ width: 1024, height: 760 });
    profiles.splice(0, profiles.length, ...[
      { id: 'same1', name: '开发', gateway: '192.0.2.10', port: 443, status: 'connected' },
      { id: 'same2', name: '开发', gateway: '192.0.2.10', port: 443, status: 'disconnected' },
      { id: 'different', name: '开发', gateway: '192.0.2.20', port: 443, status: 'disconnected' },
      { id: 'unnamed1', name: '', gateway: '192.0.2.30', port: 49999, status: 'disconnected' },
      { id: 'unnamed2', name: '', gateway: '192.0.2.30', port: 49999, status: 'disconnected' },
    ].map((profile) => ({ ...profile, networkVersion: fixtureNetworkVersion, index: profile.status === 'connected' ? 1 : 0, autoConnect: false, hasSavedCredential: false })));
    await row('unnamed2').waitFor();
    assert.equal(await page.locator('.vpn-row').count(), 5);
    assert.equal(await row('same1').locator('.vpn-name').textContent(), '开发 · 192.0.2.10:443');
    assert.equal(await row('same2').locator('.vpn-name').textContent(), '开发 · 192.0.2.10:443 (2)');
    assert.equal(await row('different').locator('.vpn-name').textContent(), '开发 · 192.0.2.20:443');
    assert.equal(await row('unnamed1').locator('.vpn-name').textContent(), '192.0.2.30:49999');
    assert.equal(await row('unnamed2').locator('.vpn-name').textContent(), '192.0.2.30:49999 (2)');
    await row('same2').locator('.more-button').click();
    await row('same2').getByRole('menuitem', { name: '编辑', exact: true }).click();
    assert.equal(await page.getByLabel('名称（选填）', { exact: true }).inputValue(), '开发');
    await page.locator('#profile-dialog').getByRole('button', { name: '保存', exact: true }).click();
    await page.waitForFunction(() => !document.querySelector('#profile-dialog').open);
    assert.ok(calls.some((call) => call.path === '/api/profiles/same2' && call.method === 'PATCH' && call.body.name === '开发'));
    assert.equal(profiles.find((profile) => profile.id === 'same1').name, '开发');
    assert.equal(profiles.find((profile) => profile.id === 'same2').name, '开发');
    await page.screenshot({ path: path.join(artifacts, 'multiple-configurations.png') });
    passed('Duplicate configuration names and endpoints keep independent IDs with display-only suffixes');

    creationNotice = '配置已保存，连接环境创建未完成；全部退出后可再次手动连接。';
    const connectAttemptsBeforeSavedOnly = connectCount();
    const createAttemptsBeforeSavedOnly = calls.filter((call) => call.path === '/api/profiles' && call.method === 'POST').length;
    await page.getByRole('button', { name: '添加', exact: true }).click();
    await page.getByLabel('网关', { exact: true }).fill('192.0.2.50');
    await page.getByLabel('名称（选填）', { exact: true }).fill('记住新配置');
    await page.locator('#profile-dialog').getByRole('button', { name: '添加', exact: true }).click();
    await row('vpn6').waitFor();
    await page.locator('#notice').filter({ hasText: '配置已保存，连接环境创建未完成' }).waitFor();
    assert.equal(await row('vpn6').locator('.vpn-name').textContent(), '记住新配置 · 192.0.2.50:443');
    assert.equal(await row('vpn6').locator('.vpn-status').textContent(), '未连接');
    assert.equal(connectCount(), connectAttemptsBeforeSavedOnly);
    assert.equal(calls.filter((call) => call.path === '/api/profiles' && call.method === 'POST').length, createAttemptsBeforeSavedOnly + 1);
    creationNotice = '';
    passed('A saved configuration survives an incomplete environment operation with a plain notice and no automatic retry');

    expansionTarget = 'expansion-target';
    profiles.push({ id: expansionTarget, name: '新增连接', gateway: '192.0.2.80', port: 443,
      status: 'disconnected', index: 0, networkVersion: fixtureNetworkVersion, hasSavedCredential: true, autoConnect: false });
    await row(expansionTarget).waitFor();
    const expandCount = () => calls.filter((call) => call.path.endsWith('/expand-connect')).length;
    const disconnectCount = () => calls.filter((call) => call.path.endsWith('/disconnect')).length;
    const expandsBeforeCancel = expandCount();
    const disconnectsBeforeCancel = disconnectCount();
    await row(expansionTarget).locator('.row-action').click();
    await page.locator('#expand-dialog[open]').waitFor();
    assert.equal(expandCount(), expandsBeforeCancel);
    assert.equal(disconnectCount(), disconnectsBeforeCancel);
    assert.equal(await page.locator('#expand-dialog-message').textContent(), '新增并发连接需要暂时断开当前连接，创建后恢复；动态口令需你填写。');
    await page.screenshot({ path: path.join(artifacts, 'expansion-confirmation.png') });
    expansionInProgress = true;
    await page.waitForFunction(() => document.querySelector('#confirm-expand').disabled);
    assert.equal(await page.locator('#cancel-expand').isDisabled(), false);
    assert.equal(expandCount(), expandsBeforeCancel);
    expansionInProgress = false;
    await page.waitForFunction(() => !document.querySelector('#confirm-expand').disabled);
    await page.locator('#cancel-expand').click();
    await page.waitForFunction(() => !document.querySelector('#expand-dialog').open && !document.querySelector('[data-profile-id="expansion-target"] .row-action').disabled);
    assert.equal(expandCount(), expandsBeforeCancel);
    assert.equal(disconnectCount(), disconnectsBeforeCancel);
    passed('Expansion requires a short explicit confirmation and cancellation sends no expansion or disconnect');

    expansionDelayMs = 3000;
    await row(expansionTarget).locator('.row-action').click();
    await page.locator('#confirm-expand').click();
    await page.waitForTimeout(200);
    const readsDuringExpansion = calls.filter((call) => call.path === '/api/state').length;
    assert.equal(await row(expansionTarget).locator('.row-action').isDisabled(), true);
    assert.equal(await page.locator('#add-profile').isDisabled(), true);
    assert.equal(await page.locator('#settings-toggle').isDisabled(), true);
    assert.equal(await row('same2').locator('.row-automatic input').isDisabled(), true);
    await page.waitForTimeout(2100);
    assert.equal(calls.filter((call) => call.path === '/api/state').length, readsDuringExpansion);
    assert.equal(expandCount(), expandsBeforeCancel + 1);
    assert.equal(await page.locator('#notice').textContent(), '正在新增连接并恢复原连接…');
    assert.equal(await page.locator('#notice').getAttribute('class'), 'notice');
    await row(expansionTarget).getByLabel('密码', { exact: true }).waitFor();
    assert.equal(await row(expansionTarget).getByLabel('账号', { exact: true }).inputValue(), '');
    assert.equal(await row(expansionTarget).getByLabel('密码', { exact: true }).inputValue(), '');
    assert.equal(await row(expansionTarget).getByLabel('保存密码', { exact: true }).isChecked(), true);
    assert.equal(expandCount(), expandsBeforeCancel + 1);
    assert.equal(disconnectCount(), disconnectsBeforeCancel);
    expansionDelayMs = 0;
    passed('Confirmed expansion waits once with all mutations disabled and opens a blank remembered-login form');

    await row(expansionTarget).getByLabel('账号', { exact: true }).fill('new-slot-test-account');
    await row(expansionTarget).getByLabel('密码', { exact: true }).fill('new-slot-test-password-only');
    await row(expansionTarget).locator('.auth-panel').getByRole('button', { name: '连接', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="expansion-target"]')?.dataset.status === 'connected');
    assert.equal(expandCount(), expandsBeforeCancel + 1);
    assert.ok(calls.some((call) => call.path.endsWith('/expansion-target/connect') && call.body.password === 'new-slot-test-password-only' && call.body.remember === true));
    passed('Credential continuation connects the allocated target without expanding again');

    Object.assign(profiles.find((profile) => profile.id === expansionTarget), { status: 'disconnected', canDisconnect: false, hasSavedCredential: true });
    targetNeedsCredentials = false;
    expansionResult = 'credentials-error';
    await page.reload();
    await row(expansionTarget).waitFor();
    await row(expansionTarget).locator('.row-action').click();
    await page.locator('#confirm-expand').click();
    await row(expansionTarget).getByLabel('密码', { exact: true }).waitFor();
    assert.equal(await row(expansionTarget).getByLabel('账号', { exact: true }).inputValue(), '');
    assert.equal(await row(expansionTarget).getByLabel('密码', { exact: true }).inputValue(), '');
    assert.equal(await row(expansionTarget).getByLabel('保存密码', { exact: true }).isChecked(), true);
    await page.locator('#notice').filter({ hasText: '部分原连接未能恢复，请查看列表后手动连接。' }).waitFor();
    assert.equal(await row(expansionTarget).locator('.row-error').isVisible(), false);
    assert.equal(await page.getByText('restored-one', { exact: true }).count(), 0);
    passed('Structured credentials-required errors open login directly and summarize restoration failure safely');

    Object.assign(profiles.find((profile) => profile.id === expansionTarget), { status: 'disconnected', canDisconnect: false, hasSavedCredential: false });
    targetNeedsCredentials = false;
    expansionResult = 'connected';
    await page.reload();
    await row(expansionTarget).waitFor();
    await row(expansionTarget).locator('.row-action').click();
    await row(expansionTarget).getByLabel('账号', { exact: true }).fill('confirmation-closure-account');
    await row(expansionTarget).getByLabel('密码', { exact: true }).fill('confirmation-closure-password-only');
    await row(expansionTarget).getByLabel('保存密码', { exact: true }).check();
    await row(expansionTarget).locator('.auth-panel').getByRole('button', { name: '连接', exact: true }).click();
    await page.locator('#expand-dialog[open]').waitFor();
    assert.equal(await row(expansionTarget).getByLabel('密码', { exact: true }).inputValue(), '');
    await page.locator('#confirm-expand').click();
    await page.waitForFunction(() => document.querySelector('[data-profile-id="expansion-target"]')?.dataset.status === 'connected');
    const confirmedBody = calls.filter((call) => call.path.endsWith('/expansion-target/expand-connect')).at(-1).body;
    assert.deepEqual(confirmedBody, { username: 'confirmation-closure-account', password: 'confirmation-closure-password-only', remember: true, autoConnect: false, networkVersion: fixtureNetworkVersion });
    assert.equal(await row(expansionTarget).locator('input[type="password"]').count(), 0);
    passed('Manual credentials survive confirmation only in the current request continuation and clear from the form');

    Object.assign(profiles.find((profile) => profile.id === expansionTarget), { status: 'disconnected', canDisconnect: false, hasSavedCredential: false });
    targetNeedsCredentials = false;
    await page.reload();
    await row(expansionTarget).waitFor();
    await row(expansionTarget).locator('.row-action').click();
    await row(expansionTarget).getByLabel('账号', { exact: true }).fill('old-endpoint-test-account');
    await row(expansionTarget).getByLabel('密码', { exact: true }).fill('old-endpoint-test-password-only');
    const authenticationsBeforeAddressChange = targetAuthentications;
    await row(expansionTarget).locator('.auth-panel').getByRole('button', { name: '连接', exact: true }).click();
    await page.locator('#expand-dialog[open]').waitFor();
    Object.assign(profiles.find((profile) => profile.id === expansionTarget), { gateway: '192.0.2.81', networkVersion: 'b'.repeat(64) });
    await page.waitForFunction(() => document.querySelector('[data-profile-id="expansion-target"] .vpn-name')?.textContent.includes('192.0.2.81'));
    await page.locator('#confirm-expand').click();
    await row(expansionTarget).getByLabel('密码', { exact: true }).waitFor();
    const rejectedContinuation = calls.filter((call) => call.path.endsWith('/expansion-target/expand-connect')).at(-1).body;
    assert.equal(rejectedContinuation.networkVersion, fixtureNetworkVersion);
    assert.equal(rejectedContinuation.password, 'old-endpoint-test-password-only');
    assert.equal(targetAuthentications, authenticationsBeforeAddressChange);
    assert.equal(profiles.find((profile) => profile.id === expansionTarget).status, 'disconnected');
    assert.equal(await row(expansionTarget).getByLabel('账号', { exact: true }).inputValue(), '');
    assert.equal(await row(expansionTarget).getByLabel('密码', { exact: true }).inputValue(), '');
    assert.equal(await row(expansionTarget).getByLabel('保存密码', { exact: true }).isChecked(), true);
    passed('An endpoint change during expansion confirmation keeps the original version and cannot redirect old credentials');

    targetNeedsCredentials = true;
    await page.reload();
    await row(expansionTarget).waitFor();
    await row(expansionTarget).locator('.row-action').click();
    await row(expansionTarget).getByLabel('账号', { exact: true }).fill('form-snapshot-test-account');
    await row(expansionTarget).getByLabel('密码', { exact: true }).fill('form-snapshot-test-password-only');
    profiles.find((profile) => profile.id === expansionTarget).networkVersion = 'c'.repeat(64);
    await page.waitForTimeout(2300);
    assert.equal(await row(expansionTarget).getByLabel('密码', { exact: true }).inputValue(), 'form-snapshot-test-password-only');
    await row(expansionTarget).locator('.auth-panel').getByRole('button', { name: '连接', exact: true }).click();
    await page.waitForFunction(() => !document.querySelector('[data-profile-id="expansion-target"] .row-action').disabled);
    assert.equal(calls.filter((call) => call.path.endsWith('/expansion-target/connect')).at(-1).body.networkVersion, 'b'.repeat(64));
    assert.equal(targetAuthentications, authenticationsBeforeAddressChange);
    assert.equal(await row(expansionTarget).getByLabel('账号', { exact: true }).inputValue(), '');
    assert.equal(await row(expansionTarget).getByLabel('密码', { exact: true }).inputValue(), '');
    assert.equal(await row(expansionTarget).getByLabel('保存密码', { exact: true }).isChecked(), true);
    passed('A login form binds credentials to its creation-time version even after fresh state arrives');

    Object.assign(profiles.find((profile) => profile.id === expansionTarget), { status: 'disconnected', canDisconnect: false, hasSavedCredential: true });
    targetNeedsCredentials = false;
    expansionResult = 'failed';
    await page.reload();
    await row(expansionTarget).waitFor();
    const expandsBeforeFailure = expandCount();
    await row(expansionTarget).locator('.row-action').click();
    await page.locator('#confirm-expand').click();
    await row(expansionTarget).locator('.row-error').filter({ hasText: '新增连接未完成，配置已保留。' }).waitFor();
    await page.waitForTimeout(2200);
    assert.equal(expandCount(), expandsBeforeFailure + 1);
    assert.equal(await row(expansionTarget).locator('.row-action').isDisabled(), false);
    assert.equal(await row(expansionTarget).locator('.vpn-name').textContent(), '新增连接 · 192.0.2.81:443');
    await page.locator('#notice').filter({ hasText: '部分原连接未能恢复，请查看列表后手动连接。' }).waitFor();
    passed('Expansion failure preserves the target and requires a new user action instead of retrying');

    Object.assign(profiles.find((profile) => profile.id === 'same2'), { status: 'otp', canDisconnect: true });
    expansionInProgress = true;
    const mutationsBeforeRemoteExpansion = calls.filter((call) => call.method !== 'GET').length;
    await page.locator('#notice').filter({ hasText: '正在新增连接并恢复原连接…' }).waitFor();
    assert.equal(await page.locator('#add-profile').isDisabled(), true);
    assert.equal(await row(expansionTarget).locator('.row-action').isDisabled(), true);
    assert.equal(await row('same2').locator('.more-button').isDisabled(), true);
    assert.equal(await row('same2').getByLabel('动态口令', { exact: true }).isDisabled(), false);
    assert.equal(await row('same2').locator('.auth-panel').getByRole('button', { name: '确认', exact: true }).isDisabled(), false);
    const readsBeforeRemoteExpansion = calls.filter((call) => call.path === '/api/state').length;
    await page.waitForTimeout(2300);
    assert.ok(calls.filter((call) => call.path === '/api/state').length > readsBeforeRemoteExpansion);
    assert.equal(calls.filter((call) => call.method !== 'GET').length, mutationsBeforeRemoteExpansion);
    expansionInProgress = false;
    await page.waitForFunction(() => !document.querySelector('#add-profile').disabled);
    passed('Another window sees expansion as read-only progress while state polling remains active');

    assert.deepEqual(await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) })), { local: [], session: [] });
    assert.ok(calls.filter((call) => call.path !== '/api/bootstrap').every((call) => call.hasToken));
    assert.equal(pageErrors.length, 0);
    const privateValues = ['frontend-test-only', '830461', 'saved-test-password-only', 'updated-test-password-only', 'long-native-test-password-only', 'do-not-keep-on-target-change', 'new-slot-test-password-only', 'confirmation-closure-password-only', 'old-endpoint-test-password-only', 'form-snapshot-test-password-only', token];
    assert.ok(consoleMessages.every((entry) => privateValues.every((value) => !entry.includes(value))));
    passed('No credentials or tokens are stored or logged; API requests carry the token');

    const noSession = await browser.newContext();
    const untrustedPage = await noSession.newPage();
    await untrustedPage.goto(origin);
    await untrustedPage.locator('#notice').filter({ hasText: '请通过启动器打开此页面' }).waitFor();
    assert.equal(await untrustedPage.getByRole('button', { name: '添加', exact: true }).isDisabled(), true);
    await noSession.close();
    passed('Missing session fails closed with a launcher instruction');

    await fs.writeFile(path.join(artifacts, 'test-results.json'), JSON.stringify({ passed: results.length, results, mockOnly: true, realVpnActions: 0 }, null, 2));
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((error) => { process.stderr.write(`${error.stack}\n`); process.exitCode = 1; server.close(); });
