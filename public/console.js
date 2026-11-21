'use strict';

const overallStatusEl = document.getElementById('overall-status');
const overallStatusTextEl = document.getElementById('overall-status-text');
const networkInfoEl = document.getElementById('network-info');
const refreshNetBtn = document.getElementById('refresh-net-btn');

const wsStatusEl = document.getElementById('ws-status');
const wsUrlEl = document.getElementById('ws-url');
const wsInputEl = document.getElementById('ws-input');
const wsSendBtn = document.getElementById('ws-send-btn');
const wsPingBtn = document.getElementById('ws-ping-btn');
const wsLogEl = document.getElementById('ws-log');

const loginPanelEl = document.getElementById('login-panel');
const itemsPanelEl = document.getElementById('items-panel');
const authUserBarEl = document.getElementById('auth-user-bar');
const authUsernameEl = document.getElementById('auth-username');
const loginFormEl = document.getElementById('login-form');
const loginErrorEl = document.getElementById('login-error');
const logoutBtn = document.getElementById('logout-btn');
const itemFormEl = document.getElementById('item-form');
const itemTitleEl = document.getElementById('item-title');
const itemsListEl = document.getElementById('items-list');

let ws = null;
let wsRetryDelayMs = 1000;
let wsRetryTimer = null;

function withErrorReport(fn) {
  return Promise.resolve()
    .then(fn)
    .catch((err) => {
      appendWsLog(`Action failed: ${err.message}`);
    });
}

function appendWsLog(text) {
  const line = `[${new Date().toLocaleTimeString()}] ${text}\n`;
  wsLogEl.textContent = (line + wsLogEl.textContent).slice(0, 6000);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function apiFetch(url, options = {}) {
  const { headers: extraHeaders, ...rest } = options;
  const res = await fetch(url, {
    credentials: 'include',
    ...rest,
    headers: {
      'Content-Type': 'application/json',
      ...(extraHeaders || {})
    }
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

async function loadNetworkInfo() {
  try {
    const [health, net] = await Promise.all([
      apiFetch('/api/health'),
      apiFetch('/api/network-info')
    ]);

    overallStatusEl.classList.remove('err');
    overallStatusEl.classList.add('ok');
    overallStatusTextEl.textContent = `Running (${net.requestContext.mode})`;

    const rows = [
      ['Bind / Port', `${net.bind}:${net.port}`],
      ['Local URL', net.urls.local],
      ['Loopback URL', net.urls.loopback],
      ['LAN URL', net.urls.lan],
      ['Current Origin', net.urls.currentOrigin],
      ['Request Mode', net.requestContext.mode],
      ['Uptime', `${health.uptimeSeconds}s`],
      ['WS Clients', String(health.wsClients)]
    ];

    networkInfoEl.innerHTML = '';
    for (const [label, value] of rows) {
      const row = document.createElement('div');
      row.className = 'kv';
      const span = document.createElement('span');
      span.textContent = label;
      const strong = document.createElement('strong');
      strong.textContent = value;
      row.append(span, strong);
      networkInfoEl.appendChild(row);
    }

    document.getElementById('cf-cmd').textContent = net.tunnelCommands.cloudflare;
    document.getElementById('ngrok-cmd').textContent = net.tunnelCommands.ngrok;
  } catch (err) {
    overallStatusEl.classList.remove('ok');
    overallStatusEl.classList.add('err');
    overallStatusTextEl.textContent = 'Connection Error';
    networkInfoEl.innerHTML = `<div class="kv"><span>Error</span><strong>${escapeHtml(err.message)}</strong></div>`;
  }
}

function scheduleWsReconnect() {
  if (wsRetryTimer) return;
  const delay = wsRetryDelayMs;
  wsRetryDelayMs = Math.min(wsRetryDelayMs * 2, 30000);
  appendWsLog(`Reconnecting in ${Math.round(delay / 1000)}s...`);
  wsRetryTimer = setTimeout(() => {
    wsRetryTimer = null;
    connectWebSocket();
  }, delay);
}

function connectWebSocket() {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${window.location.host}/ws`;
  wsUrlEl.textContent = url;

  try {
    ws = new WebSocket(url);
  } catch (err) {
    wsStatusEl.textContent = 'Error';
    appendWsLog(`Failed to create WebSocket: ${err.message}`);
    scheduleWsReconnect();
    return;
  }

  ws.addEventListener('open', () => {
    wsRetryDelayMs = 1000;
    wsStatusEl.textContent = 'Connected';
    appendWsLog(`Connected to ${url}`);
  });

  ws.addEventListener('message', (event) => {
    appendWsLog(`RX: ${event.data}`);
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'items:updated') {
        loadItems().catch(() => {});
      }
    } catch {
      // ignore non-json
    }
  });

  ws.addEventListener('close', (event) => {
    wsStatusEl.textContent = `Closed (${event.code})`;
    appendWsLog(`Disconnected (code=${event.code})`);
    scheduleWsReconnect();
  });

  ws.addEventListener('error', () => {
    wsStatusEl.textContent = 'Error';
    appendWsLog('WebSocket transport error');
  });
}

async function checkAuth() {
  try {
    const me = await apiFetch('/api/auth/me');
    if (me.authenticated && me.user) {
      authUsernameEl.textContent = me.user.username;
      authUserBarEl.classList.remove('hidden');
      loginPanelEl.classList.add('hidden');
      itemsPanelEl.classList.remove('hidden');
      await loadItems();
    } else {
      authUserBarEl.classList.add('hidden');
      loginPanelEl.classList.remove('hidden');
      itemsPanelEl.classList.add('hidden');
    }
  } catch (err) {
    loginErrorEl.textContent = err.message;
  }
}

async function loadItems() {
  const data = await apiFetch('/api/items');
  itemsListEl.innerHTML = '';

  for (const item of data.items) {
    const li = document.createElement('li');
    li.className = `item-row ${item.status === 'done' ? 'done' : ''}`;

    const title = document.createElement('span');
    title.className = 'item-title';
    title.textContent = item.title;

    const actions = document.createElement('div');
    actions.className = 'item-actions';

    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'btn btn-secondary';
    toggleBtn.textContent = item.status === 'done' ? 'Reopen' : 'Done';
    toggleBtn.addEventListener('click', () => {
      const nextStatus = item.status === 'done' ? 'active' : 'done';
      withErrorReport(() =>
        apiFetch(`/api/items/${encodeURIComponent(item.id)}`, {
          method: 'PATCH',
          body: JSON.stringify({ status: nextStatus })
        }).then(loadItems)
      );
    });

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'btn btn-danger';
    delBtn.textContent = 'Delete';
    delBtn.addEventListener('click', () => {
      withErrorReport(() =>
        apiFetch(`/api/items/${encodeURIComponent(item.id)}`, { method: 'DELETE' }).then(loadItems)
      );
    });

    actions.append(toggleBtn, delBtn);
    li.append(title, actions);
    itemsListEl.appendChild(li);
  }
}

refreshNetBtn.addEventListener('click', () => {
  loadNetworkInfo();
});

wsSendBtn.addEventListener('click', () => {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    appendWsLog('Cannot send: WebSocket is not open');
    return;
  }
  const msg = wsInputEl.value.trim() || 'Echo test';
  ws.send(JSON.stringify({ type: 'echo', message: msg }));
  appendWsLog(`TX echo: ${msg}`);
});

wsPingBtn.addEventListener('click', () => {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    appendWsLog('Cannot ping: WebSocket is not open');
    return;
  }
  ws.send(JSON.stringify({ type: 'ping' }));
  appendWsLog('TX ping');
});

loginFormEl.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginErrorEl.textContent = '';
  try {
    await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('login-username').value.trim(),
        password: document.getElementById('login-password').value
      })
    });
    await checkAuth();
  } catch (err) {
    loginErrorEl.textContent = err.message;
  }
});

logoutBtn.addEventListener('click', () => {
  withErrorReport(() => apiFetch('/api/auth/logout', { method: 'POST' }).then(checkAuth));
});

itemFormEl.addEventListener('submit', (e) => {
  e.preventDefault();
  const title = itemTitleEl.value.trim();
  if (!title) return;
  withErrorReport(async () => {
    await apiFetch('/api/items', {
      method: 'POST',
      body: JSON.stringify({ title })
    });
    itemTitleEl.value = '';
    await loadItems();
  });
});

loadNetworkInfo();
connectWebSocket();
checkAuth();
