'use strict';

require('dotenv').config();

const http = require('http');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const WebSocket = require('ws');
const { WebSocketServer } = WebSocket;
const {
  CHROME_PROFILES,
  decodeBase64Url,
  extractRefererTarget,
  createProxyRouter,
  getProxySessionStats,
  clearProxySessionCookies,
  setProxySessionProfile,
  validateTargetUrl
} = require('./proxyEngine');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number.parseInt(process.env.PORT || '11643', 10);
if (Number.isNaN(PORT) || PORT < 1 || PORT > 65535) {
  console.error(`Invalid PORT value: "${process.env.PORT}". Must be 1..65535.`);
  process.exit(1);
}

const DEMO_USERNAME = process.env.DEMO_USERNAME || 'admin';
const DEMO_PASSWORD = process.env.DEMO_PASSWORD || 'admin123';
const VERBOSE_LOGGING = String(process.env.VERBOSE_LOGGING || 'false').toLowerCase() === 'true';

const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || '')
  .split(',')
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);

const PROXY_PORT = Number.parseInt(process.env.PROXY_PORT || String(PORT + 1), 10);
if (Number.isNaN(PROXY_PORT) || PROXY_PORT < 1 || PROXY_PORT > 65535 || PROXY_PORT === PORT) {
  console.error(`Invalid PROXY_PORT "${process.env.PROXY_PORT}". Must be 1..65535 and different from PORT.`);
  process.exit(1);
}
// Optional explicit proxy origin (needed for tunnels/LAN). When empty, the shell derives
// it from the page hostname plus PROXY_PORT.
const PROXY_ORIGIN_OVERRIDE = (process.env.PROXY_ORIGIN || '').trim().replace(/\/+$/, '');
const APP_ORIGINS = (process.env.APP_ORIGINS || '')
  .split(',')
  .map((o) => o.trim().replace(/\/+$/, '').toLowerCase())
  .filter(Boolean);

const SESSION_COOKIE_NAME = 'app11643_sid';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;

if (DEMO_PASSWORD === 'admin123') {
  console.warn('WARNING: DEMO_PASSWORD is the default value. Set a strong DEMO_PASSWORD in .env before exposing this server.');
}

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a), 'utf8');
  const bufB = Buffer.from(String(b), 'utf8');
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

const loginAttempts = new Map();
function checkLoginRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now - entry.windowStart > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { windowStart: now, count: 0 });
    return true;
  }
  return entry.count < LOGIN_MAX_ATTEMPTS;
}
function recordFailedLogin(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now - entry.windowStart > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { windowStart: now, count: 1 });
  } else {
    entry.count += 1;
  }
}

// ---------------------------------------------------------------------------
// Network Interface / LAN IP Detection
// ---------------------------------------------------------------------------
function isPrivateRfc1918(ip) {
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  const match = /^172\.(\d+)\./.exec(ip);
  if (match) {
    const second = Number.parseInt(match[1], 10);
    return second >= 16 && second <= 31;
  }
  return false;
}

function detectNetworkAddresses() {
  const interfaces = os.networkInterfaces();
  const candidates = [];

  for (const [ifaceName, entries] of Object.entries(interfaces)) {
    if (!entries) continue;
    for (const entry of entries) {
      const family = typeof entry.family === 'string' ? entry.family : entry.family === 4 ? 'IPv4' : 'IPv6';
      if (family !== 'IPv4' || entry.internal) continue;

      let priority = 3;
      if (isPrivateRfc1918(entry.address)) {
        const lower = ifaceName.toLowerCase();
        const isVirtual = /veth|docker|br-|vbox|vmware|hyper-v|wsl|tun|tap|wg|tailscale/.test(lower);
        priority = isVirtual ? 2 : 1;
      } else if (/^169\.254\./.test(entry.address)) {
        priority = 4;
      }

      candidates.push({
        interface: ifaceName,
        address: entry.address,
        netmask: entry.netmask,
        priority,
        isPrivateLan: isPrivateRfc1918(entry.address)
      });
    }
  }

  candidates.sort((a, b) => a.priority - b.priority);
  const primaryLanIp = candidates.length > 0 ? candidates[0].address : '127.0.0.1';
  return { primaryLanIp, interfaces: candidates };
}

// ---------------------------------------------------------------------------
// Host / Origin Validation Helpers (Localhost, LAN, Cloudflare Tunnel, ngrok)
// ---------------------------------------------------------------------------
function stripPort(hostHeader) {
  if (!hostHeader || typeof hostHeader !== 'string') return '';
  const trimmed = hostHeader.trim();
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    return end !== -1 ? trimmed.slice(0, end + 1).toLowerCase() : '';
  }
  const colonIdx = trimmed.lastIndexOf(':');
  if (colonIdx !== -1 && trimmed.indexOf(':') === colonIdx) {
    return trimmed.slice(0, colonIdx).toLowerCase();
  }
  return trimmed.toLowerCase();
}

function isValidHostHeaderSyntax(hostHeader) {
  if (!hostHeader || typeof hostHeader !== 'string') return false;
  if (hostHeader.length > 255) return false;
  if (/[\s/@\\]/.test(hostHeader)) return false;
  if (/^\[[0-9a-fA-F:]+\](:\d{1,5})?$/.test(hostHeader)) return true;
  return /^[a-zA-Z0-9.-]+(:\d{1,5})?$/.test(hostHeader);
}

function isHostPermitted(hostHeader) {
  if (!isValidHostHeaderSyntax(hostHeader)) return false;
  if (ALLOWED_HOSTS.length === 0 || ALLOWED_HOSTS.includes('*')) {
    return true;
  }
  const hostname = stripPort(hostHeader);
  return ALLOWED_HOSTS.some((pattern) => {
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1);
      return hostname.endsWith(suffix) && hostname.length > suffix.length;
    }
    return hostname === pattern;
  });
}

// Only the app's own origin (or explicitly configured APP_ORIGINS) may make credentialed
// cross-origin requests to the proxy control API or open the proxy WebSocket. Origins are
// matched exactly, never reflected blindly.
function isTrustedAppOrigin(origin, hostHeader) {
  if (!origin) return true;
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  if (APP_ORIGINS.includes(origin.replace(/\/+$/, '').toLowerCase())) return true;
  const originPort = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  return parsed.hostname === stripPort(hostHeader || '') && originPort === String(PORT);
}

// ---------------------------------------------------------------------------
// In-Memory Session & Application Store
// ---------------------------------------------------------------------------
const sessions = new Map();
const sessionSweeper = setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (now > session.expiresAt) sessions.delete(token);
  }
  for (const [ip, entry] of loginAttempts) {
    if (Date.now() - entry.windowStart > LOGIN_WINDOW_MS) loginAttempts.delete(ip);
  }
}, 10 * 60 * 1000);
sessionSweeper.unref();
const items = [
  {
    id: 'item-1',
    title: 'Verify localhost:11643 binding',
    status: 'done',
    createdAt: new Date().toISOString()
  },
  {
    id: 'item-2',
    title: 'Confirm LAN, Cloudflare Tunnel & ngrok routing',
    status: 'active',
    createdAt: new Date().toISOString()
  }
];

function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  const session = {
    token,
    username,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS
  };
  sessions.set(token, session);
  return session;
}

function getSessionFromRequest(req) {
  const cookieToken = req.cookies && req.cookies[SESSION_COOKIE_NAME];
  const authHeader = req.get('authorization');
  const bearerToken =
    authHeader && authHeader.toLowerCase().startsWith('bearer ')
      ? authHeader.slice(7).trim()
      : null;

  const token = bearerToken || cookieToken;
  if (!token) return null;

  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function requireAuth(req, res, next) {
  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({
      error: 'Authentication required',
      hint: 'POST /api/auth/login with { username, password }'
    });
  }
  req.session = session;
  return next();
}

function isHttpsRequest(req) {
  if (req.secure) return true;
  const proto = (req.get('x-forwarded-proto') || '').split(',')[0].trim().toLowerCase();
  if (proto === 'https') return true;
  const cfVisitor = req.get('cf-visitor');
  if (cfVisitor && cfVisitor.includes('"https"')) return true;
  return false;
}

function detectTunnelContext(req) {
  const host = req.get('host') || '';
  const hostname = stripPort(host);
  const hasCloudflareHeaders = Boolean(req.get('cf-ray') || req.get('cf-connecting-ip'));
  const isCloudflareHost =
    hostname.endsWith('.trycloudflare.com') || hostname.endsWith('.cfargotunnel.com');
  const isNgrokHost =
    hostname.endsWith('.ngrok.io') ||
    hostname.endsWith('.ngrok-free.app') ||
    hostname.endsWith('.ngrok-free.dev') ||
    hostname.endsWith('.ngrok.app') ||
    hostname.endsWith('.ngrok.dev');

  let mode = 'direct';
  if (hasCloudflareHeaders || isCloudflareHost) mode = 'cloudflare-tunnel';
  else if (isNgrokHost || req.get('ngrok-skip-browser-warning')) mode = 'ngrok';
  else if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]') mode = 'local';
  else if (isPrivateRfc1918(hostname) || /^169\.254\./.test(hostname)) mode = 'lan';
  else if (req.get('x-forwarded-host')) mode = 'reverse-proxy';

  return {
    mode,
    host,
    protocol: isHttpsRequest(req) ? 'https' : 'http',
    clientIp: req.get('cf-connecting-ip') || req.ip,
    forwardedHost: req.get('x-forwarded-host') || null,
    forwardedProto: req.get('x-forwarded-proto') || null,
    cfRay: req.get('cf-ray') || null
  };
}

function proxyOriginFor(req) {
  if (PROXY_ORIGIN_OVERRIDE) return PROXY_ORIGIN_OVERRIDE;
  const ctx = detectTunnelContext(req);
  const hostname = stripPort(ctx.host) || 'localhost';
  return `${ctx.protocol}://${hostname}:${PROXY_PORT}`;
}

// ---------------------------------------------------------------------------
// Express App Setup
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');

app.use((req, res, next) => {
  const hostHeader = req.get('host');
  if (!isHostPermitted(hostHeader)) {
    return res.status(400).json({
      error: 'Invalid or disallowed Host header',
      host: hostHeader || null
    });
  }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use((req, res, next) => {
  if (!VERBOSE_LOGGING && req.path === '/api/health') return next();
  const started = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - started;
    if (VERBOSE_LOGGING || res.statusCode >= 400) {
      console.log(
        `[${new Date().toISOString()}] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms) host=${req.get('host')}`
      );
    }
  });
  next();
});

app.use(cookieParser());

// The web proxy is NOT served on the app origin. It lives on its own origin (PROXY_PORT),
// so proxied third-party JavaScript cannot act as this app's origin.
app.all(['/b/*', '/p/*', '/proxy', '/proxy-ws'], (req, res) =>
  res.status(404).type('text/plain').send(`The web proxy is served from ${proxyOriginFor(req)}`)
);

// Parse JSON for app's own API routes
app.use(express.json({ limit: '1mb' }));

// Runtime config for the browser shell (proxy origin is not known at build time)
app.get('/app-config.js', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.type('application/javascript');
  res.send(
    `window.__APP_CONFIG__ = ${JSON.stringify({
      proxyOrigin: PROXY_ORIGIN_OVERRIDE,
      proxyPort: PROXY_PORT
    })};`
  );
});

// Dedicated Network Console page
app.get('/console', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'console.html'));
});

// Serve static frontend assets cleanly
app.use(
  express.static(path.join(__dirname, 'public'), {
    etag: true,
    lastModified: true,
    setHeaders(res, filePath) {
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache');
      }
    }
  })
);

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------
app.get('/api/health', (req, res) => {
  const net = detectNetworkAddresses();
  res.json({
    status: 'ok',
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
    bind: HOST,
    port: PORT,
    primaryLanIp: net.primaryLanIp,
    requestContext: detectTunnelContext(req),
    wsClients: wss ? wss.clients.size : 0
  });
});

app.get('/api/network-info', (req, res) => {
  const net = detectNetworkAddresses();
  const ctx = detectTunnelContext(req);
  const wsProto = ctx.protocol === 'https' ? 'wss' : 'ws';

  res.json({
    bind: HOST,
    port: PORT,
    urls: {
      local: `http://localhost:${PORT}`,
      loopback: `http://127.0.0.1:${PORT}`,
      lan: `http://${net.primaryLanIp}:${PORT}`,
      currentOrigin: `${ctx.protocol}://${ctx.host}`,
      websocket: `${wsProto}://${ctx.host}/ws`,
      console: `${ctx.protocol}://${ctx.host}/console`,
      proxy: `${proxyOriginFor(req)}/proxy?url=https://example.com`,
      proxyOrigin: proxyOriginFor(req)
    },
    interfaces: net.interfaces,
    requestContext: ctx,
    tunnelCommands: {
      cloudflare: `cloudflared tunnel --url http://127.0.0.1:${PORT}`,
      ngrok: `ngrok http ${PORT}`
    }
  });
});

// Authentication
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const clientKey = req.ip || 'unknown';
  if (!checkLoginRateLimit(clientKey)) {
    return res.status(429).json({ error: 'Too many failed login attempts. Try again later.' });
  }

  const usernameOk = safeEqual(username, DEMO_USERNAME);
  const passwordOk = safeEqual(password, DEMO_PASSWORD);
  if (!usernameOk || !passwordOk) {
    recordFailedLogin(clientKey);
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  loginAttempts.delete(clientKey);

  const session = createSession(username);
  const secure = isHttpsRequest(req);

  res.cookie(SESSION_COOKIE_NAME, session.token, {
    httpOnly: true,
    sameSite: 'lax',
    secure,
    maxAge: SESSION_TTL_MS,
    path: '/'
  });

  return res.json({
    authenticated: true,
    user: { username: session.username },
    token: session.token,
    expiresAt: new Date(session.expiresAt).toISOString()
  });
});

app.post('/api/auth/logout', (req, res) => {
  const session = getSessionFromRequest(req);
  if (session) {
    sessions.delete(session.token);
  }
  res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
  res.json({ authenticated: false });
});

app.get('/api/auth/me', (req, res) => {
  const session = getSessionFromRequest(req);
  if (!session) {
    return res.json({ authenticated: false, user: null });
  }
  return res.json({
    authenticated: true,
    user: { username: session.username },
    expiresAt: new Date(session.expiresAt).toISOString()
  });
});

// Protected Items CRUD API
app.get('/api/items', requireAuth, (req, res) => {
  res.json({ items });
});

app.post('/api/items', requireAuth, (req, res) => {
  const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
  if (!title) {
    return res.status(400).json({ error: 'Item title is required' });
  }
  const newItem = {
    id: `item-${crypto.randomUUID().slice(0, 8)}`,
    title: title.slice(0, 200),
    status: 'active',
    createdAt: new Date().toISOString()
  };
  items.unshift(newItem);
  broadcastWs({ type: 'items:updated', action: 'create', item: newItem });
  return res.status(201).json({ item: newItem });
});

app.patch('/api/items/:id', requireAuth, (req, res) => {
  const item = items.find((i) => i.id === req.params.id);
  if (!item) {
    return res.status(404).json({ error: 'Item not found' });
  }
  if (typeof req.body?.title === 'string' && req.body.title.trim()) {
    item.title = req.body.title.trim().slice(0, 200);
  }
  if (req.body?.status === 'active' || req.body?.status === 'done') {
    item.status = req.body.status;
  }
  broadcastWs({ type: 'items:updated', action: 'update', item });
  return res.json({ item });
});

app.delete('/api/items/:id', requireAuth, (req, res) => {
  const idx = items.findIndex((i) => i.id === req.params.id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Item not found' });
  }
  const [removed] = items.splice(idx, 1);
  broadcastWs({ type: 'items:updated', action: 'delete', item: removed });
  return res.json({ deleted: removed.id });
});

// 404 handler for unknown API routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: `API route not found: ${req.method} ${req.originalUrl}` });
});

// Fallback to Browser Proxy UI
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global error handler
app.use((err, req, res, _next) => {
  if (err.type === 'entity.too.large' || err.status === 413) {
    return res.status(413).json({ error: 'Request body too large' });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Malformed JSON body' });
  }
  console.error('Unhandled Express error:', err.message);
  if (err.message === 'Origin not allowed by CORS') {
    return res.status(403).json({ error: err.message });
  }
  return res.status(500).json({ error: 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Proxy Origin (separate listener on PROXY_PORT)
// Serves only proxy routes. Proxied third-party pages run on this origin, never on
// the app origin, so their scripts cannot call the app's authenticated APIs.
// ---------------------------------------------------------------------------
const proxyHandler = createProxyRouter({ ownPort: [PORT, PROXY_PORT], isHttpsRequest });
const proxyApp = express();
proxyApp.set('trust proxy', true);
proxyApp.disable('x-powered-by');

proxyApp.use((req, res, next) => {
  const hostHeader = req.get('host');
  if (!isHostPermitted(hostHeader)) {
    return res.status(400).json({ error: 'Invalid or disallowed Host header', host: hostHeader || null });
  }
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  return next();
});

// CORS only for the proxy control API, only for the exact app origin, with credentials.
proxyApp.use('/api/proxy', (req, res, next) => {
  const origin = req.get('origin');
  if (origin && isTrustedAppOrigin(origin, req.get('host'))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
  }
  return next();
});

proxyApp.use(cookieParser());
proxyApp.use('/api/proxy', express.json({ limit: '1mb' }));

proxyApp.get('/api/proxy/status', (req, res) => {
  res.json(getProxySessionStats(req, res, isHttpsRequest(req)));
});

proxyApp.post('/api/proxy/profile', (req, res) => {
  const profile = req.body && req.body.profile;
  if (!CHROME_PROFILES[profile]) {
    return res.status(400).json({ error: 'Invalid Chrome profile. Use "desktop" or "mobile".' });
  }
  return res.json(setProxySessionProfile(req, res, isHttpsRequest(req), profile));
});

proxyApp.post('/api/proxy/clear-cookies', (req, res) => {
  return res.json(clearProxySessionCookies(req, res, isHttpsRequest(req)));
});

// Web Proxy Route (mounted BEFORE express.json so raw upstream payloads pass untouched)
function readRawBody(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const chunks = [];
  let total = 0;
  const maxBytes = 10 * 1024 * 1024;
  let tooLarge = false;
  req.on('data', (chunk) => {
    if (tooLarge) return;
    total += chunk.length;
    if (total > maxBytes) {
      tooLarge = true;
      chunks.length = 0;
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => {
    if (tooLarge) {
      return res.status(413).json({ error: 'Request body exceeds 10 MB limit' });
    }
    req.rawBody = Buffer.concat(chunks);
    return next();
  });
  req.on('error', next);
}


proxyApp.all('/b/:token', readRawBody, (req, res) => proxyHandler(req, res));
proxyApp.use('/p/:originToken', readRawBody, (req, res) => {
  let origin = '';
  try {
    origin = decodeBase64Url(req.params.originToken);
  } catch {
    origin = '';
  }
  const subPath = req.url && req.url !== '' ? req.url : '/';
  const target = origin ? `${origin}${subPath.startsWith('/') ? subPath : `/${subPath}`}` : '';
  return proxyHandler(req, res, target);
});
proxyApp.all('/proxy', readRawBody, (req, res) => proxyHandler(req, res));

// Transparent Referer-based fallback for dynamic SPA chunks/APIs/assets on the proxy origin
proxyApp.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/proxy-ws') {
    return next();
  }
  const refTarget = extractRefererTarget(req);
  if (!refTarget) return next();
  try {
    const resolvedTarget = new URL(req.originalUrl, refTarget).toString();
    return readRawBody(req, res, () => proxyHandler(req, res, resolvedTarget));
  } catch {
    return next();
  }
});

proxyApp.use((req, res) => {
  res.status(404).type('text/plain').send('Not found');
});

// ---------------------------------------------------------------------------
// HTTP & WebSocket Servers
// ---------------------------------------------------------------------------
const server = http.createServer(app);
const proxyServer = http.createServer(proxyApp);
const wss = new WebSocketServer({ noServer: true });
const proxyWss = new WebSocketServer({ noServer: true });

function broadcastWs(payload) {
  const message = JSON.stringify(payload);
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  }
}

wss.on('connection', (ws, req) => {
  const hostHeader = req.headers.host;
  if (!isHostPermitted(hostHeader)) {
    ws.close(1008, 'Disallowed Host');
    return;
  }

  ws.isAlive = true;
  ws.send(
    JSON.stringify({
      type: 'connected',
      timestamp: new Date().toISOString(),
      host: hostHeader,
      clients: wss.clients.size
    })
  );

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', (raw) => {
    let parsed;
    try {
      parsed = JSON.parse(raw.toString());
    } catch {
      parsed = { type: 'text', message: raw.toString().slice(0, 500) };
    }

    if (parsed.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong', timestamp: new Date().toISOString() }));
      return;
    }

    if (parsed.type === 'echo') {
      ws.send(
        JSON.stringify({
          type: 'echo',
          message: String(parsed.message || '').slice(0, 500),
          timestamp: new Date().toISOString()
        })
      );
    }
  });
});

proxyWss.on('connection', async (clientWs, req) => {
  let targetWsUrl;
  try {
    const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const rawTarget = reqUrl.searchParams.get('url');
    const httpEquivalent = rawTarget
      ? rawTarget.replace(/^ws:/i, 'http:').replace(/^wss:/i, 'https:')
      : '';
    const validated = await validateTargetUrl(httpEquivalent, [PORT, PROXY_PORT]);
    validated.protocol = validated.protocol === 'https:' ? 'wss:' : 'ws:';
    targetWsUrl = validated.toString();
  } catch (err) {
    clientWs.close(1008, err.message || 'Invalid WebSocket target');
    return;
  }

  const upstreamWs = new WebSocket(targetWsUrl, {
    headers: {
      'user-agent': CHROME_PROFILES.desktop.userAgent
    }
  });

  const pendingMessages = [];

  upstreamWs.on('open', () => {
    while (pendingMessages.length > 0) {
      const [data, isBinary] = pendingMessages.shift();
      upstreamWs.send(data, { binary: isBinary });
    }
  });

  upstreamWs.on('message', (data, isBinary) => {
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(data, { binary: isBinary });
    }
  });

  clientWs.on('message', (data, isBinary) => {
    if (upstreamWs.readyState === WebSocket.OPEN) {
      upstreamWs.send(data, { binary: isBinary });
    } else if (upstreamWs.readyState === WebSocket.CONNECTING && pendingMessages.length < 50) {
      pendingMessages.push([data, isBinary]);
    }
  });

  upstreamWs.on('close', (code, reason) => {
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.close(code >= 1000 && code <= 4999 ? code : 1000, reason?.toString());
    }
  });

  clientWs.on('close', () => {
    if (upstreamWs.readyState === WebSocket.OPEN || upstreamWs.readyState === WebSocket.CONNECTING) {
      upstreamWs.close();
    }
  });

  upstreamWs.on('error', () => {
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.close(1011, 'Upstream WebSocket error');
    }
  });
});

function rejectUpgrade(socket, status, message) {
  socket.write(`HTTP/1.1 ${status} ${message}\r\nConnection: close\r\n\r\n`);
  socket.destroy();
}

server.on('upgrade', (request, socket, head) => {
  let pathname = '/';
  try {
    pathname = new URL(request.url, `http://${request.headers.host || 'localhost'}`).pathname;
  } catch {
    return socket.destroy();
  }
  if (pathname !== '/ws') return rejectUpgrade(socket, '404', 'Not Found');
  if (!isHostPermitted(request.headers.host)) return rejectUpgrade(socket, '400', 'Bad Request');
  if (!isTrustedAppOrigin(request.headers.origin, request.headers.host)) {
    return rejectUpgrade(socket, '403', 'Forbidden');
  }
  return wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

proxyServer.on('upgrade', (request, socket, head) => {
  let pathname = '/';
  try {
    pathname = new URL(request.url, `http://${request.headers.host || 'localhost'}`).pathname;
  } catch {
    return socket.destroy();
  }
  if (pathname !== '/proxy-ws') return rejectUpgrade(socket, '404', 'Not Found');
  if (!isHostPermitted(request.headers.host)) return rejectUpgrade(socket, '400', 'Bad Request');
  if (!isTrustedAppOrigin(request.headers.origin, request.headers.host)) {
    return rejectUpgrade(socket, '403', 'Forbidden');
  }
  return proxyWss.handleUpgrade(request, socket, head, (ws) => {
    proxyWss.emit('connection', ws, request);
  });
});

const heartbeatInterval = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);

wss.on('close', () => {
  clearInterval(heartbeatInterval);
});

proxyServer.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\nERROR: Proxy port ${PROXY_PORT} is already in use on ${HOST}. Set PROXY_PORT to a free port.`);
    process.exit(1);
  }
  console.error('Proxy server failed to start:', err);
  process.exit(1);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\nERROR: Port ${PORT} is already in use on ${HOST}.`);
    console.error('Do not switch ports. Identify and stop the conflicting process:');
    console.error(`  Linux/macOS: ss -tlnp | grep :${PORT}   OR   lsof -i :${PORT}`);
    console.error(`  Windows:     netstat -ano | findstr :${PORT}`);
    process.exit(1);
  }
  console.error('Server failed to start:', err);
  process.exit(1);
});

proxyServer.listen(PROXY_PORT, HOST, () => {
  console.log(`Proxy origin listening on port ${PROXY_PORT} (PROXY_ORIGIN override: ${PROXY_ORIGIN_OVERRIDE || 'none'})`);
});

server.listen(PORT, HOST, () => {
  const { primaryLanIp } = detectNetworkAddresses();
  console.log('====================================================');
  console.log('APPLICATION STARTED SUCCESSFULLY');
  console.log('====================================================');
  console.log('');
  console.log('LOCAL:');
  console.log(`http://localhost:${PORT}`);
  console.log('');
  console.log('LOOPBACK:');
  console.log(`http://127.0.0.1:${PORT}`);
  console.log('');
  console.log('LAN:');
  console.log(`http://${primaryLanIp}:${PORT}`);
  console.log('');
  console.log('BIND:');
  console.log(HOST);
  console.log('');
  console.log('PORT:');
  console.log(String(PORT));
  console.log('');
  console.log('STATUS:');
  console.log('RUNNING');
  console.log('');
  console.log('====================================================');
});

function shutdown(signal) {
  console.log(`\nReceived ${signal}, shutting down gracefully...`);
  clearInterval(heartbeatInterval);
  wss.close();
  proxyWss.close();
  proxyServer.close();
  server.close(() => {
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 5000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
