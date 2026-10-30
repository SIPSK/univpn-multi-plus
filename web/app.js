const $ = (id) => document.getElementById(id);
const list = $('vpn-list');
const rows = new Map();
const statuses = {
  disconnected: '未连接', starting: '连接中', authenticating: '验证中',
  otp: '待验证', connected: '已连接', disconnecting: '断开中',
  error: '连接失败', unknown: '状态未知',
};
const activeStatuses = new Set(['connected', 'starting', 'authenticating', 'otp', 'disconnecting']);
let token = '';
let state = { profiles: [], capabilities: { nativeAuth: false, otp: false }, settings: { startup: false } };
let online = false;
let noticeOverride = '';
let globalError = '';
let globalInfo = '';
let settingsBusy = false;
let pendingStartup;
let editingId = null;
let deletingId = null;
let pollTimer;
let refreshing = null;
let nativePending = 0;
let nativeSerial = 0;
let expansionPending = false;

function expansionBusy() {
  return expansionPending || Boolean(state.expansion?.inProgress);
}

function setText(element, value) {
  const text = String(value ?? '');
  if (element.textContent !== text) element.textContent = text;
}

function message(error, fallback = '操作未完成，请重试。') {
  const text = typeof error === 'string' ? error : error?.message;
  return text ? String(text).slice(0, 200) : fallback;
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) setText(node, text);
  return node;
}

function button(text, className, action) {
  const node = element('button', className, text);
  node.type = 'button';
  node.addEventListener('click', action);
  return node;
}

async function request(path, { method = 'GET', body, anonymous = false } = {}) {
  const controller = new AbortController();
  const nativeCreation = method === 'POST' && (path === '/api/profiles' || path.endsWith('/connect') || path.endsWith('/expand-connect'));
  const nativeDisconnect = method === 'POST' && path.endsWith('/disconnect');
  const waitsForNative = nativeCreation || nativeDisconnect;
  if (waitsForNative) { nativePending += 1; nativeSerial += 1; }
  const waitMs = nativeCreation ? 300000 : nativeDisconnect ? 150000 : path === '/api/environment' ? 45000 : method === 'GET' ? 7000 : 20000;
  const timeout = setTimeout(() => controller.abort(), waitMs);
  try {
    const headers = {};
    if (!anonymous) headers['X-VPN-Token'] = token;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, {
      method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      body: body === undefined ? undefined : JSON.stringify(body), signal: controller.signal,
    });
    let payload = null;
    if (response.headers.get('content-type')?.includes('application/json')) {
      payload = await response.json();
    }
    if (!response.ok) {
      const error = new Error(message(payload?.error || payload?.message, response.status === 401 ? '请通过启动器打开此页面。' : nativeCreation ? '添加尚未确认，请先检查连接列表。' : '操作未完成，请重试。'));
      error.status = response.status;
      if (['expansion_required', 'credentials_required', 'expansion_in_progress'].includes(payload?.code)) error.code = payload.code;
      if (Array.isArray(payload?.details?.failedProfileIds)) error.failedProfileIds = payload.details.failedProfileIds.filter((id) => typeof id === 'string' && /^[A-Za-z0-9_-]{1,48}$/.test(id)).slice(0, 1000);
      throw error;
    }
    return payload;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error(nativeCreation || nativeDisconnect ? '操作尚未确认，请先检查连接状态。' : '本地服务响应超时，请重试。');
    if (error instanceof TypeError) throw new Error('无法连接本地服务。');
    if (error instanceof SyntaxError) throw new Error('本地服务返回了无效响应。');
    throw error;
  } finally {
    clearTimeout(timeout);
    if (waitsForNative) nativePending -= 1;
  }
}

function showNotice() {
  const expanding = expansionBusy();
  const text = noticeOverride || (expanding ? '正在新增连接并恢复原连接…' : globalError || state.error || globalInfo || (!state.capabilities?.nativeAuth ? '网页登录尚未就绪。' : ''));
  $('notice').hidden = !text;
  $('notice').classList.toggle('is-error', Boolean(noticeOverride || (!expanding && (globalError || state.error))));
  setText($('notice'), text);
}

function profileById(id) {
  return state.profiles.find((profile) => String(profile.id) === String(id));
}

function baseProfileLabel(profile) {
  const endpoint = `${profile.gateway}:${profile.port}`;
  const name = String(profile.name || '').trim();
  return name ? `${name} · ${endpoint}` : endpoint;
}

function profileLabel(profile) {
  const label = baseProfileLabel(profile);
  const matching = state.profiles.filter((candidate) => baseProfileLabel(candidate) === label);
  const position = matching.findIndex((candidate) => String(candidate.id) === String(profile.id));
  return position > 0 ? `${label} (${position + 1})` : label;
}

function closeMenus() {
  $('settings-menu').hidden = true;
  $('settings-toggle').setAttribute('aria-expanded', 'false');
  for (const row of rows.values()) {
    row.menu.hidden = true;
    row.more.setAttribute('aria-expanded', 'false');
  }
}

function checkField(text, name, checked = false) {
  const wrapper = element('label', 'check-field');
  const input = document.createElement('input');
  input.type = 'checkbox';
  input.name = name;
  input.checked = checked;
  wrapper.append(input, document.createTextNode(text));
  return { wrapper, input };
}

function field(label, type, name, options = {}) {
  const wrapper = element('label', 'field', label);
  const input = document.createElement('input');
  input.type = type;
  input.name = name;
  input.required = true;
  input.autocomplete = 'off';
  input.spellcheck = false;
  input.autocapitalize = 'none';
  if (options.inputMode) input.inputMode = options.inputMode;
  if (options.maxLength) input.maxLength = options.maxLength;
  wrapper.append(input);
  return { wrapper, input };
}

function removeAuth(row) {
  if (!row.form) return;
  for (const input of row.form.querySelectorAll('input')) input.value = '';
  row.form.remove();
  row.form = null;
  row.panel = null;
}

function showAuth(row, panel, focus = false, rememberDefault = false) {
  if (row.panel === panel) {
    if (focus) row.form?.querySelector('input')?.focus();
    return;
  }
  removeAuth(row);
  if (!panel) return;
  row.panel = panel;
  const networkVersion = panel === 'login' ? row.profile.networkVersion : undefined;
  const form = element('form', `auth-panel ${panel === 'otp' ? 'otp-panel' : ''}`);
  form.autocomplete = 'off';
  form.setAttribute('aria-label', `${profileLabel(row.profile)} ${panel === 'otp' ? '动态口令' : '登录'}`);
  let username;
  let password;
  let code;
  let remember;
  let autoConnect;
  const inputs = element('div', 'auth-inputs');
  if (panel === 'login') {
    username = field('账号', 'text', 'username', { maxLength: 256 });
    password = field('密码', 'password', 'password', { maxLength: 1024 });
    inputs.append(username.wrapper, password.wrapper);
  } else {
    code = field('动态口令', 'text', 'code', { inputMode: 'numeric', maxLength: 128 });
    inputs.append(code.wrapper);
  }
  const submit = element('button', 'button button-primary', panel === 'otp' ? '确认' : '连接');
  submit.type = 'submit';
  inputs.append(submit);
  if (panel === 'login') {
    const cancel = button('×', 'icon-button', () => {
      removeAuth(row);
      row.action.focus();
    });
    cancel.setAttribute('aria-label', '取消登录');
    inputs.append(cancel);
  }
  form.append(inputs);
  if (panel === 'login') {
    const options = element('div', 'auth-options');
    remember = checkField('保存密码', 'remember', Boolean(rememberDefault || row.profile.hasSavedCredential || row.profile.autoConnect));
    autoConnect = checkField('自动连接', 'autoConnect', Boolean(row.profile.autoConnect));
    const syncRemember = () => {
      if (autoConnect.input.checked) remember.input.checked = true;
      remember.input.disabled = autoConnect.input.checked;
    };
    autoConnect.input.addEventListener('change', syncRemember);
    syncRemember();
    options.append(remember.wrapper, autoConnect.wrapper);
    form.append(options);
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (row.busy || (panel === 'login' && expansionBusy()) || !form.reportValidity()) return;
    const body = panel === 'login'
      ? { username: username.input.value.trim(), password: password.input.value, remember: remember.input.checked || autoConnect.input.checked, autoConnect: autoConnect.input.checked, ...(networkVersion === undefined ? {} : { networkVersion }) }
      : { code: code.input.value.trim() };
    if (panel === 'login' && !body.username) return username.input.focus();
    if (panel === 'otp' && !body.code) return code.input.focus();
    // Secrets remain only in the current request; never retain them in UI state.
    if (password) password.input.value = '';
    if (code) code.input.value = '';
    await operate(row, panel === 'login' ? 'connect' : 'otp', body);
  });
  row.form = form;
  row.node.insertBefore(form, row.errorNode);
  if (focus) form.querySelector('input')?.focus();
}

function createRow(profile) {
  const node = element('article', 'vpn-row');
  const main = element('div', 'row-main');
  const mark = element('div', 'vpn-mark');
  mark.setAttribute('aria-hidden', 'true');
  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  for (const [name, value] of Object.entries({ viewBox: '0 0 24 24', width: '18', height: '18', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'stroke-linejoin': 'round' })) icon.setAttribute(name, value);
  const shield = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  shield.setAttribute('d', 'M12 3 5 6v5c0 4.5 3 7.7 7 10 4-2.3 7-5.5 7-10V6L12 3Z');
  icon.append(shield);
  mark.append(icon);
  const identity = element('div', 'row-identity');
  const name = element('span', 'vpn-name');
  const status = element('span', 'vpn-status');
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  identity.append(name, status);
  const actions = element('div', 'row-actions');
  const automatic = checkField('自动', 'automatic', Boolean(profile.autoConnect));
  automatic.wrapper.classList.add('row-automatic');
  automatic.input.addEventListener('change', () => void updateAutomatic(row, automatic.input.checked));
  const action = button('连接', 'button button-primary row-action', () => onAction(row));
  const more = button('···', 'icon-button more-button', () => {
    const opening = row.menu.hidden;
    closeMenus();
    row.menu.hidden = !opening;
    more.setAttribute('aria-expanded', String(opening));
    if (opening) [...row.menu.querySelectorAll('button')].find((item) => !item.disabled && !item.hidden)?.focus();
  });
  more.setAttribute('aria-haspopup', 'menu');
  more.setAttribute('aria-expanded', 'false');
  const menu = element('div', 'row-menu');
  menu.setAttribute('role', 'menu');
  menu.hidden = true;
  const edit = button('编辑', '', () => openProfile(row.profile));
  const relogin = button('重新登录', '', () => {
    closeMenus();
    row.localError = '';
    removeAuth(row);
    showAuth(row, 'login', true);
    renderRow(row, row.profile);
  });
  const forget = button('忘记密码', '', () => {
    closeMenus();
    void operate(row, 'credential', {}, 'DELETE');
  });
  const remove = button('删除', 'delete-action', () => openDelete(row.profile));
  for (const item of [relogin, forget, edit, remove]) item.setAttribute('role', 'menuitem');
  menu.append(relogin, forget, edit, remove);
  menu.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      closeMenus(); more.focus();
    } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const enabled = [relogin, forget, edit, remove].filter((item) => !item.disabled && !item.hidden);
      const direction = event.key === 'ArrowDown' ? 1 : -1;
      if (enabled.length) enabled[(enabled.indexOf(document.activeElement) + direction + enabled.length) % enabled.length].focus();
    }
  });
  actions.append(automatic.wrapper, action, more);
  main.append(mark, identity, actions);
  const errorNode = element('p', 'form-error row-error');
  errorNode.setAttribute('role', 'alert');
  errorNode.hidden = true;
  node.append(main, menu, errorNode);
  const row = { node, mark, name, status, automatic, action, more, menu, edit, relogin, forget, remove, errorNode, profile, busy: false, localError: '', panel: null, form: null };
  return row;
}

function renderRow(row, profile) {
  if (row.profile.gateway !== profile.gateway || Number(row.profile.port) !== Number(profile.port)) {
    removeAuth(row);
    row.localError = '';
  }
  row.profile = profile;
  const currentStatus = online && statuses[profile.status] ? profile.status : 'unknown';
  const canDisconnect = Boolean(profile.canDisconnect);
  const active = activeStatuses.has(currentStatus) || canDisconnect;
  const expanding = expansionBusy();
  row.node.dataset.status = currentStatus;
  row.node.dataset.profileId = String(profile.id);
  const label = profileLabel(profile);
  setText(row.name, label);
  row.name.title = label;
  setText(row.status, statuses[currentStatus]);
  row.more.setAttribute('aria-label', `管理 ${label}`);
  row.more.disabled = !online || row.busy || expanding || currentStatus === 'unknown' || (active && !profile.hasSavedCredential);
  row.edit.disabled = row.remove.disabled = active || currentStatus === 'unknown' || !online || row.busy || expanding;
  row.edit.title = row.remove.title = active ? '请先断开连接。' : '';
  row.relogin.disabled = active || currentStatus === 'unknown' || !online || row.busy || expanding || !state.capabilities?.nativeAuth || Boolean(state.handoffRequired);
  row.relogin.title = active ? '请先断开连接。' : '';
  row.forget.hidden = !profile.hasSavedCredential;
  row.forget.disabled = !online || row.busy || expanding;
  row.automatic.input.checked = row.pendingAuto ?? Boolean(profile.autoConnect);
  row.automatic.input.disabled = !online || row.busy || settingsBusy || expanding;
  row.automatic.input.setAttribute('aria-label', `自动连接 ${label}`);
  row.automatic.wrapper.title = profile.autoConnect && !profile.hasSavedCredential ? '首次登录并保存密码后可自动连接。' : '';
  setText(row.action, currentStatus === 'connected' || (canDisconnect && ['error', 'unknown', 'disconnected'].includes(currentStatus)) ? '断开' : currentStatus === 'disconnecting' ? '断开中' : active ? '取消' : '连接');
  row.action.classList.toggle('button-primary', !active);
  row.action.disabled = !online || row.busy || expanding || (currentStatus === 'unknown' && !canDisconnect) || currentStatus === 'disconnecting' || (!active && !state.capabilities?.nativeAuth) || (state.handoffRequired && !canDisconnect);
  row.action.title = state.handoffRequired && !canDisconnect ? '请先在原客户端断开 VPN 并退出。' : !active && !state.capabilities?.nativeAuth ? '网页登录尚未就绪。' : '';
  row.action.setAttribute('aria-label', `${row.action.textContent} ${label}`);
  if (currentStatus === 'otp') {
    showAuth(row, 'otp');
  } else if (row.panel === 'otp' || (row.panel === 'login' && (active || state.handoffRequired))) {
    removeAuth(row);
  }
  if (row.form) for (const control of row.form.elements) control.disabled = row.busy || !online || (row.panel === 'login' && expanding) || (row.panel === 'otp' && !state.capabilities?.otp);
  if (row.panel === 'login' && row.form.elements.autoConnect.checked) row.form.elements.remember.disabled = true;
  const error = row.localError || (typeof profile.error === 'string' ? profile.error : '');
  row.errorNode.hidden = !error;
  setText(row.errorNode, message(error, ''));
}

function render() {
  const present = new Set();
  let position = 0;
  for (const profile of state.profiles) {
    const id = String(profile.id);
    present.add(id);
    let row = rows.get(id);
    if (!row) { row = createRow(profile); rows.set(id, row); }
    renderRow(row, profile);
    // Leave stable rows in place so polling does not steal input focus.
    if (list.children[position] !== row.node) list.insertBefore(row.node, list.children[position] || null);
    position += 1;
  }
  for (const [id, row] of rows) if (!present.has(id)) {
    removeAuth(row); row.node.remove(); rows.delete(id);
  }
  $('empty-state').hidden = state.profiles.length !== 0 || !online;
  $('loading-state').hidden = true;
  const expanding = expansionBusy();
  $('confirm-expand').disabled = expanding;
  $('add-profile').disabled = !online || expanding;
  $('settings-toggle').disabled = !online || settingsBusy || expanding;
  $('startup-enabled').checked = pendingStartup ?? Boolean(state.settings?.startup);
  $('startup-enabled').disabled = !online || settingsBusy || expanding;
  $('enable-all-auto').disabled = $('disable-all-auto').disabled = !online || settingsBusy || expanding || !state.profiles.length;
  $('check-environment').disabled = !online || settingsBusy || expanding || !state.capabilities?.environment;
  showNotice();
}

function refresh(afterMutation = false) {
  if (!token || nativePending) return Promise.resolve();
  if (refreshing) return afterMutation ? refreshing.then(() => refresh()) : refreshing;
  refreshing = (async () => {
    const startedAt = nativeSerial;
    try {
      const next = await request('/api/state');
      if (!next || !Array.isArray(next.profiles)) throw new Error('本地服务返回了无效状态。');
      state = next;
      online = true;
      noticeOverride = '';
    } catch (error) {
      if (nativePending || startedAt !== nativeSerial) return;
      online = false;
      noticeOverride = error.status === 401 ? '请通过启动器打开此页面。' : '无法连接本地服务。';
    } finally {
      render();
    }
  })().finally(() => { refreshing = null; });
  return refreshing;
}

function confirmExpansion() {
  const dialog = $('expand-dialog');
  if (dialog.open) return Promise.resolve(false);
  return new Promise((resolve) => {
    dialog.returnValue = 'cancel';
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true });
    dialog.showModal();
    $('cancel-expand').focus();
  });
}

async function operate(row, action, body = {}, method = 'POST') {
  if (row.busy || (expansionBusy() && action !== 'otp')) return;
  body = { ...body };
  if (action === 'connect' && !Object.prototype.hasOwnProperty.call(body, 'networkVersion') && row.profile.networkVersion !== undefined) {
    body.networkVersion = row.profile.networkVersion;
  }
  row.busy = true;
  row.localError = '';
  let needsCredentials = false;
  let expanding = false;
  renderRow(row, row.profile);
  try {
    let result;
    try {
      result = await request(`/api/profiles/${encodeURIComponent(row.profile.id)}/${action}`, { method, body });
    } catch (error) {
      if (action !== 'connect' || error.code !== 'expansion_required') throw error;
      if (!await confirmExpansion()) return;
      expanding = expansionPending = true;
      globalError = '';
      closeMenus();
      render();
      result = await request(`/api/profiles/${encodeURIComponent(row.profile.id)}/expand-connect`, { method: 'POST', body });
    }
    needsCredentials = result?.credentialsRequired === true;
    if (Array.isArray(result?.failedProfileIds) && result.failedProfileIds.length) globalError = '部分原连接未能恢复，请查看列表后手动连接。';
    if (['connect', 'otp', 'disconnect', 'credential'].includes(action)) removeAuth(row);
    await refresh(true);
  } catch (error) {
    needsCredentials = error.code === 'credentials_required';
    if (error.failedProfileIds?.length) globalError = '部分原连接未能恢复，请查看列表后手动连接。';
    if (!needsCredentials) row.localError = error.code === 'expansion_in_progress' ? '正在新增连接，请稍后。' : message(error);
    await refresh(true);
  } finally {
    // A confirmation continuation keeps credentials only in this invocation.
    // Drop them before creating a new, deliberately blank login form.
    for (const key of ['username', 'password', 'code']) delete body[key];
    if (expanding) expansionPending = false;
    row.busy = false;
    if (needsCredentials) {
      removeAuth(row);
      showAuth(row, 'login', true, true);
    }
    render();
  }
}

async function updateAutomatic(row, enabled) {
  if (row.busy || !online || settingsBusy || expansionBusy()) return;
  row.busy = true;
  row.pendingAuto = enabled;
  row.localError = '';
  renderRow(row, row.profile);
  try {
    await request(`/api/profiles/${encodeURIComponent(row.profile.id)}`, { method: 'PATCH', body: { autoConnect: enabled } });
    await refresh(true);
    if (enabled && !state.handoffRequired && !row.profile.hasSavedCredential && !row.profile.canDisconnect && !activeStatuses.has(row.profile.status) && state.capabilities?.nativeAuth) {
      removeAuth(row);
      showAuth(row, 'login', true);
    }
  } catch (error) {
    row.localError = message(error);
  } finally {
    row.busy = false;
    row.pendingAuto = undefined;
    renderRow(row, row.profile);
  }
}

async function updateSettings(path, body) {
  if (settingsBusy || !online || expansionBusy()) return;
  settingsBusy = true;
  if (path === '/api/settings') pendingStartup = body.startup;
  globalError = '';
  globalInfo = '';
  render();
  try {
    await request(path, { method: 'POST', body });
    await refresh(true);
  } catch (error) {
    globalError = message(error);
  } finally {
    settingsBusy = false;
    pendingStartup = undefined;
    render();
  }
}

async function checkEnvironment() {
  if (settingsBusy || !online || expansionBusy()) return;
  settingsBusy = true;
  globalError = globalInfo = '';
  render();
  try {
    const result = await request('/api/environment');
    if (result?.ok === true) globalInfo = '环境检查通过。';
    else globalError = message(result?.error, '环境检查未通过。');
  } catch (error) {
    globalError = message(error, '环境检查未完成。');
  } finally {
    settingsBusy = false;
    render();
  }
}

function onAction(row) {
  closeMenus();
  if (row.busy || expansionBusy()) return;
  if (activeStatuses.has(row.profile.status) || row.profile.canDisconnect) {
    void operate(row, 'disconnect');
  } else if (row.profile.hasSavedCredential) {
    const body = row.profile.networkVersion === undefined ? {} : { networkVersion: row.profile.networkVersion };
    void operate(row, 'connect', body);
  } else {
    row.localError = '';
    showAuth(row, 'login', true);
    renderRow(row, row.profile);
  }
}

function openProfile(profile = null) {
  if ($('save-profile').disabled || expansionBusy()) return;
  closeMenus();
  editingId = profile ? String(profile.id) : null;
  setText($('profile-dialog-title'), profile ? '编辑 VPN' : '添加 VPN');
  setText($('save-profile'), profile ? '保存' : '添加');
  $('profile-name').value = profile?.name || '';
  $('profile-gateway').value = profile?.gateway || '';
  $('profile-port').value = profile?.port || 443;
  $('profile-error').hidden = true;
  $('profile-dialog').showModal();
  $('profile-gateway').focus();
}

function openDelete(profile) {
  if ($('confirm-delete').disabled || expansionBusy()) return;
  closeMenus();
  deletingId = String(profile.id);
  setText($('delete-name'), profileLabel(profile));
  $('delete-error').hidden = true;
  $('delete-dialog').showModal();
  $('delete-dialog').querySelector('[data-close-dialog]').focus();
}

$('add-profile').addEventListener('click', () => openProfile());
$('settings-toggle').addEventListener('click', () => {
  const opening = $('settings-menu').hidden;
  closeMenus();
  $('settings-menu').hidden = !opening;
  $('settings-toggle').setAttribute('aria-expanded', String(opening));
  if (opening) $('startup-enabled').focus();
});
$('startup-enabled').addEventListener('change', () => void updateSettings('/api/settings', { startup: $('startup-enabled').checked }));
$('enable-all-auto').addEventListener('click', () => void updateSettings('/api/auto-connect', { enabled: true }));
$('disable-all-auto').addEventListener('click', () => void updateSettings('/api/auto-connect', { enabled: false }));
$('check-environment').addEventListener('click', () => void checkEnvironment());
$('settings-menu').addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    closeMenus();
    $('settings-toggle').focus();
  }
});
$('profile-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (expansionBusy() || !$('profile-form').reportValidity() || $('save-profile').disabled) return;
  const body = { name: $('profile-name').value.trim(), gateway: $('profile-gateway').value.trim(), port: Number($('profile-port').value) };
  if (!body.gateway) return $('profile-gateway').focus();
  $('save-profile').disabled = true;
  $('profile-error').hidden = true;
  globalInfo = '';
  try {
    const result = await request(editingId ? `/api/profiles/${encodeURIComponent(editingId)}` : '/api/profiles', { method: editingId ? 'PATCH' : 'POST', body });
    if (typeof result?.notice === 'string') globalInfo = message(result.notice, '');
    $('profile-dialog').close();
    await refresh(true);
  } catch (error) {
    setText($('profile-error'), message(error)); $('profile-error').hidden = false;
  } finally { $('save-profile').disabled = false; }
});
$('delete-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (expansionBusy() || !deletingId || $('confirm-delete').disabled) return;
  $('confirm-delete').disabled = true;
  $('delete-error').hidden = true;
  try {
    await request(`/api/profiles/${encodeURIComponent(deletingId)}`, { method: 'DELETE', body: {} });
    $('delete-dialog').close(); deletingId = null;
    await refresh(true);
  } catch (error) {
    setText($('delete-error'), message(error)); $('delete-error').hidden = false;
  } finally { $('confirm-delete').disabled = false; }
});
document.querySelectorAll('[data-close-dialog]').forEach((control) => control.addEventListener('click', () => control.closest('dialog').close()));
document.addEventListener('click', (event) => { if (!event.target.closest('.row-menu, .more-button, .settings-menu, #settings-toggle')) closeMenus(); });
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeMenus(); });
document.addEventListener('visibilitychange', () => { if (!document.hidden) void refresh(); });
window.addEventListener('pagehide', () => { clearTimeout(pollTimer); for (const row of rows.values()) removeAuth(row); });

async function poll() {
  await refresh();
  pollTimer = setTimeout(poll, document.hidden ? 6000 : 2000);
}

async function initialize() {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const launchToken = fragment.get('token');
  try {
    if (launchToken) {
      token = launchToken;
      try { await request('/api/session', { method: 'POST', body: {} }); }
      finally { history.replaceState(null, '', location.pathname + location.search); }
    } else {
      const bootstrap = await request('/api/bootstrap', { anonymous: true });
      if (!bootstrap?.token) throw new Error('请通过启动器打开此页面。');
      token = String(bootstrap.token);
    }
    await poll();
  } catch (error) {
    token = '';
    online = false;
    noticeOverride = error.status === 401 || error.status === 403 ? '请通过启动器打开此页面。' : message(error, '请通过启动器打开此页面。');
    render();
  }
}

void initialize();
