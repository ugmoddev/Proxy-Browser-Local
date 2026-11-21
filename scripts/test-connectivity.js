'use strict';

const assert = require('assert');
const http = require('http');
const WebSocket = require('ws');

const PORT = Number.parseInt(process.env.PORT || '11643', 10);
const PROXY_PORT = Number.parseInt(process.env.PROXY_PORT || String(PORT + 1), 10);
const USERNAME = process.env.DEMO_USERNAME || 'admin';
const PASSWORD = process.env.DEMO_PASSWORD || 'admin123';

function request(hostname, port, path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname,
        port,
        path,
        method: options.method || 'GET',
        headers: options.headers || {}
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8')
          });
        });
      }
    );
    req.on('error', reject);
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

function testWebSocket(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    const seen = [];
    const timer = setTimeout(() => {
      ws.terminate();
      reject(new Error('WebSocket test timed out'));
    }, 5000);

    ws.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'ping' }));
      ws.send(JSON.stringify({ type: 'echo', message: 'ws-check' }));
    });

    ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      seen.push(msg.type);
      if (seen.includes('connected') && seen.includes('pong') && seen.includes('echo')) {
        clearTimeout(timer);
        ws.close();
        resolve(seen);
      }
    });
  });
}

function wsHandshakeStatus(url, origin) {
  return new Promise((resolve) => {
    const ws = new WebSocket(url, { headers: { Origin: origin } });
    ws.on('unexpected-response', (_req, res) => {
      resolve(res.statusCode);
      ws.terminate();
    });
    ws.on('open', () => {
      resolve(200);
      ws.terminate();
    });
    ws.on('error', () => {});
  });
}

async function run() {
  function record(name, status, detail) {
    console.log(`[${status}] ${name}${detail ? ` — ${detail}` : ''}`);
  }

  // 1. Browser Proxy UI at / and Network Console at /console
  const home = await request('localhost', PORT, '/');
  assert.strictEqual(home.status, 200, 'Expected 200 on /');
  assert(home.body.includes('Browser Proxy 11643'), 'Expected Browser Proxy title on /');
  record('localhost:11643 Browser Proxy UI (/)', 'PASS', `HTTP ${home.status}`);

  const consolePage = await request('localhost', PORT, '/console');
  assert.strictEqual(consolePage.status, 200, 'Expected 200 on /console');
  assert(consolePage.body.includes('Network &amp; Application Console'), 'Expected Console title');
  record('localhost:11643 Network Console (/console)', 'PASS', `HTTP ${consolePage.status}`);

  const css = await request('localhost', PORT, '/styles.css');
  const js = await request('localhost', PORT, '/app.js');
  assert.strictEqual(css.status, 200);
  assert.strictEqual(js.status, 200);
  record('Static assets (/styles.css, /app.js)', 'PASS', 'HTTP 200');

  // 2. 127.0.0.1:11643 health & network-info
  const healthRes = await request('127.0.0.1', PORT, '/api/health');
  assert.strictEqual(healthRes.status, 200);
  const health = JSON.parse(healthRes.body);
  assert.strictEqual(health.status, 'ok');
  assert.strictEqual(health.port, PORT);
  assert.strictEqual(health.bind, '0.0.0.0');
  record('127.0.0.1:11643 /api/health', 'PASS', `bind=${health.bind}:${health.port}`);

  const lanIp = health.primaryLanIp;
  const lanRes = await request(lanIp, PORT, '/api/health');
  assert.strictEqual(lanRes.status, 200);
  record(`LAN IP (${lanIp}:${PORT}) direct check`, 'PASS', `HTTP ${lanRes.status}`);

  // 3. Multi-site Web Proxy verification + Chrome spoofing + Reader Mode
  const site1 = await request('localhost', PROXY_PORT, `/proxy?url=${encodeURIComponent('https://example.com')}`);
  assert.strictEqual(site1.status, 200);
  assert(!site1.headers['x-frame-options'], 'X-Frame-Options must be stripped');
  assert(!site1.headers['content-security-policy'], 'CSP must be stripped');
  assert.strictEqual(site1.headers['x-proxy-ua-profile'], 'desktop');
  assert(site1.body.includes('__PROXY_SHIM_ACTIVE__'), 'Client shim must be injected');
  assert(site1.body.includes('Google Chrome'), 'Chrome UA & client hints spoof must be injected');
  assert(site1.body.includes('visibilityState'), 'Always-focus visibilityState spoof must be injected');
  assert(site1.body.includes('hasFocusOverride'), 'Always-focus hasFocus spoof must be injected');
  assert(site1.body.includes('enterVirtualFullscreen'), 'Virtual fullscreen spoofer must be injected');
  assert(site1.body.includes('/b/'), 'Links must be rewritten to /b/<base64url>');
  record('Web Proxy -> https://example.com', 'PASS', 'HTTP 200, Chrome 131 spoof, Always-Focus shim');

  const bToken = Buffer.from('https://vio.edu.vn/', 'utf8').toString('base64url');
  const vioRes = await request('localhost', PROXY_PORT, `/b/${bToken}`);
  assert.strictEqual(vioRes.status, 200);
  assert(vioRes.body.includes('__PROXY_SHIM_ACTIVE__'));
  record('Web Proxy /b/<base64url> -> https://vio.edu.vn/', 'PASS', 'HTTP 200');

  const webTestToken = Buffer.from('https://ugmoddev.github.io/Web-Test/', 'utf8').toString('base64url');
  const webTestRes = await request('localhost', PROXY_PORT, `/b/${webTestToken}`);
  assert.strictEqual(webTestRes.status, 200);
  assert(!webTestRes.body.includes('fireSyntheticFocus'), 'Must not spam synthetic focus events');
  assert(webTestRes.body.includes("'focusin'"), 'Must suppress redundant focus/blur transitions');
  assert(webTestRes.body.includes('HTMLScriptElement'), 'Must hook script.src setter for SPA chunks');
  record('Web Proxy -> https://ugmoddev.github.io/Web-Test/', 'PASS', 'HTTP 200, SPA hooks + 0 focus-spam');

  const exampleToken = Buffer.from('https://example.com/', 'utf8').toString('base64url');
  const refFallbackRes = await request('localhost', PROXY_PORT, '/', {
    headers: { Referer: `http://localhost:${PROXY_PORT}/b/${exampleToken}` }
  });
  assert.strictEqual(refFallbackRes.status, 200);
  const subFallbackRes = await request('localhost', PROXY_PORT, '/subchunk-not-exist-on-example.js', {
    headers: { Referer: `http://localhost:${PROXY_PORT}/b/${exampleToken}` }
  });
  assert.strictEqual(
    subFallbackRes.headers['x-proxy-target-url'],
    'https://example.com/subchunk-not-exist-on-example.js',
    'Referer fallback must proxy sub-resources instead of serving index.html'
  );
  record('Referer fallback SPA sub-resource proxy', 'PASS', 'Proxied to upstream instead of index.html');

  const rufflePageUrl = 'https://swords-souls.game-files.crazygames.com/ruffle/swordssouls.html?v=2.14&ruffle=2025-03-18%2Fruffle.js';
  const ruffleRes = await request('localhost', PROXY_PORT, `/b/${Buffer.from(rufflePageUrl, 'utf8').toString('base64url')}`);
  assert.strictEqual(ruffleRes.status, 200);
  const crazyOriginToken = Buffer.from('https://files.crazygames.com', 'utf8').toString('base64url');
  assert(
    ruffleRes.body.includes(`/p/${crazyOriginToken}/gameframe/ruffle/2025-03-18/ruffle.js`),
    'Ruffle script must preserve /p/<origin>/directory/file.js path'
  );
  const wasmRes = await request(
    'localhost',
    PROXY_PORT,
    `/p/${crazyOriginToken}/gameframe/ruffle/2025-03-18/1418fc0d1b5ae2161499.wasm`
  );
  assert.strictEqual(wasmRes.status, 200, 'WASM component must return HTTP 200');
  assert(
    (wasmRes.headers['content-type'] || '').includes('application/wasm'),
    'WASM component must be served with application/wasm MIME type'
  );
  record('Ruffle + WASM (/p/<origin>/.../*.wasm)', 'PASS', `HTTP 200, MIME=${wasmRes.headers['content-type']}`);

  const readerRes = await request(
    'localhost',
    PROXY_PORT,
    `/proxy?url=${encodeURIComponent('https://example.com')}&mode=reader`
  );
  assert.strictEqual(readerRes.status, 200);
  assert(readerRes.body.includes('Reader Mode'), 'Expected Reader Mode output');
  record('Web Proxy Reader Mode', 'PASS', 'HTTP 200');

  const proxyStatus = await request('localhost', PROXY_PORT, '/api/proxy/status');
  assert.strictEqual(proxyStatus.status, 200);
  const proxyCookie = (proxyStatus.headers['set-cookie'] || [])[0]?.split(';')[0];
  assert(proxyCookie, 'Expected proxy session cookie');
  const proxyProfileRes = await request('localhost', PROXY_PORT, '/api/proxy/profile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: proxyCookie },
    body: JSON.stringify({ profile: 'mobile' })
  });
  assert.strictEqual(proxyProfileRes.status, 200);
  assert.strictEqual(JSON.parse(proxyProfileRes.body).profile, 'mobile');
  const clearCookiesRes = await request('localhost', PROXY_PORT, '/api/proxy/clear-cookies', {
    method: 'POST',
    headers: { Cookie: proxyCookie }
  });
  assert.strictEqual(clearCookiesRes.status, 200);
  record('Proxy Chrome Profile & Cookie API', 'PASS', 'status -> profile=mobile -> clear-cookies');

  const site2 = await request(
    'localhost',
    PROXY_PORT,
    `/proxy?url=${encodeURIComponent('https://news.ycombinator.com')}`
  );
  assert.strictEqual(site2.status, 200);
  assert(site2.body.includes('Hacker News'), 'Expected Hacker News content');
  assert(site2.body.includes('__PROXY_SHIM_ACTIVE__'), 'Expected client shim');
  record('Web Proxy -> https://news.ycombinator.com', 'PASS', 'HTTP 200, multi-site proxy verified');

  // 4. SSRF & Invalid Protocol protection
  const ssrfSelf = await request(
    'localhost',
    PROXY_PORT,
    `/proxy?url=${encodeURIComponent(`http://127.0.0.1:${PORT}/api/health`)}`
  );
  assert.strictEqual(ssrfSelf.status, 403);

  const ssrfMeta = await request(
    'localhost',
    PROXY_PORT,
    `/proxy?url=${encodeURIComponent('http://169.254.169.254/latest/meta-data/')}`
  );
  assert.strictEqual(ssrfMeta.status, 403);

  const badProto = await request(
    'localhost',
    PROXY_PORT,
    `/proxy?url=${encodeURIComponent('ftp://example.com')}`
  );
  assert.strictEqual(badProto.status, 400);
  record('Proxy SSRF & protocol guard', 'PASS', 'loopback/metadata=403, ftp=400');

  // 5. Auth flow + protected CRUD
  const unauthItems = await request('127.0.0.1', PORT, '/api/items');
  assert.strictEqual(unauthItems.status, 401);

  const loginRes = await request('localhost', PORT, '/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: USERNAME, password: PASSWORD })
  });
  assert.strictEqual(loginRes.status, 200);
  const cookieHeader = (loginRes.headers['set-cookie'] || [])[0]?.split(';')[0];
  assert(cookieHeader);

  const createRes = await request('localhost', PORT, '/api/items', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookieHeader },
    body: JSON.stringify({ title: 'Proxy smoke check' })
  });
  assert.strictEqual(createRes.status, 201);
  const created = JSON.parse(createRes.body).item;

  const delRes = await request('localhost', PORT, `/api/items/${created.id}`, {
    method: 'DELETE',
    headers: { Cookie: cookieHeader }
  });
  assert.strictEqual(delRes.status, 200);
  record('Auth & Protected CRUD API', 'PASS', 'login -> create -> delete');

  // 6. Cloudflare Tunnel & ngrok header compatibility
  const cfRes = await request('127.0.0.1', PORT, '/api/health', {
    headers: {
      Host: 'demo-tunnel.trycloudflare.com',
      'X-Forwarded-Proto': 'https',
      'CF-Connecting-IP': '203.0.113.55',
      'CF-Ray': 'test-ray-001'
    }
  });
  assert.strictEqual(JSON.parse(cfRes.body).requestContext.mode, 'cloudflare-tunnel');

  const ngrokRes = await request('127.0.0.1', PORT, '/api/health', {
    headers: {
      Host: 'demo-app.ngrok-free.app',
      'X-Forwarded-Proto': 'https',
      'Ngrok-Skip-Browser-Warning': 'true'
    }
  });
  assert.strictEqual(JSON.parse(ngrokRes.body).requestContext.mode, 'ngrok');
  record('Cloudflare Tunnel & ngrok header compatibility', 'PASS', 'HTTPS reverse-proxy ready');

  // 7. WebSocket /ws check
  const wsEvents = await testWebSocket(`ws://localhost:${PORT}/ws`);
  record('WebSocket ws://localhost:11643/ws', 'PASS', `events=${wsEvents.join(',')}`);

  // 8. Origin isolation: the app origin must not serve the proxy, and the proxy origin
  //    must not serve the app APIs (so proxied third-party JS cannot reach app data).
  const appProxyRes = await request('localhost', PORT, `/b/${bToken}`);
  assert.strictEqual(appProxyRes.status, 404, 'App origin must not serve /b/ proxy routes');
  const proxyItemsRes = await request('localhost', PROXY_PORT, '/api/items', {
    headers: { Cookie: cookieHeader }
  });
  assert.strictEqual(proxyItemsRes.status, 404, 'Proxy origin must not serve app APIs');
  const proxyLoginRes = await request('localhost', PROXY_PORT, '/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: USERNAME, password: PASSWORD })
  });
  assert.strictEqual(proxyLoginRes.status, 404, 'Proxy origin must not serve login');

  // Cross-origin credentialed reads of the control API are only allowed for the app origin.
  const corsEvil = await request('localhost', PROXY_PORT, '/api/proxy/status', {
    headers: { Origin: 'https://evil.example' }
  });
  assert.strictEqual(corsEvil.headers['access-control-allow-origin'], undefined, 'Foreign origin must not get CORS');
  const corsApp = await request('localhost', PROXY_PORT, '/api/proxy/status', {
    headers: { Origin: `http://localhost:${PORT}` }
  });
  assert.strictEqual(corsApp.headers['access-control-allow-origin'], `http://localhost:${PORT}`);
  assert.strictEqual(corsApp.headers['access-control-allow-credentials'], 'true');
  record('Origin isolation (app vs proxy origin, CORS allowlist)', 'PASS', 'app /b/ 404, proxy /api/items 404, foreign CORS denied');

  // WebSocket origin check: a foreign page must not be able to open /ws or /proxy-ws.
  const foreignWs = await wsHandshakeStatus(`ws://localhost:${PORT}/ws`, 'https://evil.example');
  assert.strictEqual(foreignWs, 403, 'Foreign Origin must be rejected on /ws');

  console.log('\nAll Browser Proxy, multi-site, SSRF, network, auth, and WebSocket checks PASSED.');
}

run().catch((err) => {
  console.error('\nTest suite failed:', err);
  process.exit(1);
});
