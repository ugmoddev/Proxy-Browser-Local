'use strict';

const crypto = require('crypto');
const dns = require('dns').promises;
const http2 = require('http2');
const net = require('net');
const { execFile } = require('child_process');
const cheerio = require('cheerio');
const { Agent } = require('undici');
const tls = require('tls');

const PROXY_COOKIE_NAME = 'app11643_proxy_sid';
const MAX_BODY_BYTES = 50 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 45000;
const ALLOW_PRIVATE_PROXY =
  String(process.env.ALLOW_PRIVATE_PROXY || 'false').toLowerCase() === 'true';

const CHROME_PROFILES = {
  desktop: {
    id: 'desktop',
    label: 'Chrome 131 (Windows)',
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    appVersion:
      '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    platform: 'Win32',
    secChUa: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    secChUaMobile: '?0',
    secChUaPlatform: '"Windows"',
    mobile: false
  },
  mobile: {
    id: 'mobile',
    label: 'Chrome 131 (Android)',
    userAgent:
      'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
    appVersion:
      '5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
    platform: 'Linux armv8l',
    secChUa: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    secChUaMobile: '?1',
    secChUaPlatform: '"Android"',
    mobile: true
  }
};

function encodeBase64Url(str) {
  return Buffer.from(String(str), 'utf8').toString('base64url');
}

function decodeBase64Url(token) {
  return Buffer.from(String(token), 'base64url').toString('utf8');
}

// In-memory Cookie Jars & settings keyed by proxy session ID
const proxySessions = new Map();
const PROXY_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const proxySweeper = setInterval(() => {
  const now = Date.now();
  for (const [sid, sess] of proxySessions) {
    if (now - sess.createdAt > PROXY_SESSION_TTL_MS) proxySessions.delete(sid);
  }
}, 60 * 60 * 1000);
proxySweeper.unref();

function getOrCreateProxySession(req, res, isHttps) {
  let sid = req.cookies && req.cookies[PROXY_COOKIE_NAME];
  if (!sid || !proxySessions.has(sid)) {
    sid = crypto.randomBytes(24).toString('hex');
    proxySessions.set(sid, {
      id: sid,
      cookies: new Map(),
      profile: 'desktop',
      createdAt: Date.now()
    });
    if (!req.cookies) req.cookies = {};
    req.cookies[PROXY_COOKIE_NAME] = sid;
    if (res) {
      res.cookie(PROXY_COOKIE_NAME, sid, {
        httpOnly: true,
        sameSite: 'lax',
        secure: Boolean(isHttps),
        maxAge: 24 * 60 * 60 * 1000,
        path: '/'
      });
    }
  }
  return proxySessions.get(sid);
}

function getProxySessionStats(req, res, isHttps) {
  const session = getOrCreateProxySession(req, res, isHttps);
  let totalCookies = 0;
  for (const domainJar of session.cookies.values()) {
    totalCookies += domainJar.size;
  }
  const profile = CHROME_PROFILES[session.profile] || CHROME_PROFILES.desktop;
  return {
    profile: profile.id,
    profileLabel: profile.label,
    userAgent: profile.userAgent,
    domainsCount: session.cookies.size,
    cookiesCount: totalCookies,
    allowPrivateProxy: ALLOW_PRIVATE_PROXY
  };
}

function clearProxySessionCookies(req, res, isHttps) {
  const session = getOrCreateProxySession(req, res, isHttps);
  session.cookies.clear();
  return getProxySessionStats(req, res, isHttps);
}

function setProxySessionProfile(req, res, isHttps, profileKey) {
  const session = getOrCreateProxySession(req, res, isHttps);
  if (CHROME_PROFILES[profileKey]) {
    session.profile = profileKey;
  }
  return getProxySessionStats(req, res, isHttps);
}

// ---------------------------------------------------------------------------
// IP / SSRF Protection
// ---------------------------------------------------------------------------
function isPrivateOrReservedIpv4(ip) {
  const parts = ip.split('.').map((n) => Number.parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function isPrivateOrReservedIp(ip) {
  if (!ip) return true;
  const cleaned = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (cleaned === '::1' || cleaned === '::') return true;
  if (cleaned.startsWith('::ffff:')) {
    return isPrivateOrReservedIpv4(cleaned.slice(7));
  }
  if (net.isIPv4(cleaned)) return isPrivateOrReservedIpv4(cleaned);
  if (net.isIPv6(cleaned)) {
    return cleaned.startsWith('fe80:') || cleaned.startsWith('fc') || cleaned.startsWith('fd');
  }
  return true;
}

function checkedLookup(hostname, options, callback) {
  const wantAll = Boolean(options && options.all);
  dns
    .lookup(hostname, { all: true, family: options && options.family ? options.family : 0 })
    .then((entries) => {
      if (!ALLOW_PRIVATE_PROXY) {
        const bad = entries.find((e) => isPrivateOrReservedIp(e.address));
        if (bad) {
          const err = Object.assign(new Error(`Blocked connection to private/reserved IP (${bad.address})`), {
            code: 'ESSRFBLOCKED'
          });
          return callback(err);
        }
      }
      if (!entries.length) return callback(new Error(`No addresses for ${hostname}`));
      if (wantAll) return callback(null, entries);
      return callback(null, entries[0].address, entries[0].family);
    })
    .catch((err) => callback(err));
}

const upstreamAgent = new Agent({
  connect: { lookup: checkedLookup, timeout: REQUEST_TIMEOUT_MS }
});

async function validateTargetUrl(rawUrl, ownPort) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw Object.assign(new Error('Missing target URL'), { statusCode: 400 });
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw Object.assign(new Error(`Invalid URL: ${rawUrl}`), { statusCode: 400 });
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw Object.assign(new Error(`Unsupported protocol: ${parsed.protocol}`), { statusCode: 400 });
  }

  const hostname = parsed.hostname.toLowerCase();
  const targetPort = parsed.port
    ? Number.parseInt(parsed.port, 10)
    : parsed.protocol === 'https:'
      ? 443
      : 80;

  const ownPorts = Array.isArray(ownPort) ? ownPort : [ownPort];
  if (
    ownPorts.includes(targetPort) &&
    (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '0.0.0.0')
  ) {
    throw Object.assign(new Error('Loopback access to the proxy server itself is blocked'), {
      statusCode: 403
    });
  }

  if (!ALLOW_PRIVATE_PROXY) {
    if (hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
      throw Object.assign(new Error(`Access to internal hostname "${hostname}" is blocked`), {
        statusCode: 403
      });
    }

    if (net.isIP(hostname)) {
      if (isPrivateOrReservedIp(hostname)) {
        throw Object.assign(new Error(`Access to private/reserved IP "${hostname}" is blocked`), {
          statusCode: 403
        });
      }
    } else {
      let resolved;
      try {
        resolved = await dns.lookup(hostname, { all: true });
      } catch {
        throw Object.assign(new Error(`DNS lookup failed for "${hostname}"`), { statusCode: 502 });
      }
      for (const entry of resolved) {
        if (isPrivateOrReservedIp(entry.address)) {
          throw Object.assign(
            new Error(`Target "${hostname}" resolves to private/reserved IP (${entry.address})`),
            { statusCode: 403 }
          );
        }
      }
    }
  }

  return parsed;
}

// ---------------------------------------------------------------------------
// Cookie Jar Helpers
// ---------------------------------------------------------------------------
function storeCookiesFromResponse(session, targetUrl, setCookieHeaders) {
  if (!session || !Array.isArray(setCookieHeaders) || setCookieHeaders.length === 0) return;

  for (const rawCookie of setCookieHeaders) {
    const parts = String(rawCookie).split(';').map((p) => p.trim());
    const [nameValue, ...attrs] = parts;
    if (!nameValue || !nameValue.includes('=')) continue;

    const eqIdx = nameValue.indexOf('=');
    const name = nameValue.slice(0, eqIdx).trim();
    const value = nameValue.slice(eqIdx + 1).trim();
    if (!name) continue;

    let domain = targetUrl.hostname.toLowerCase();
    let cookiePath = '/';
    let expires = null;
    let secure = false;

    for (const attr of attrs) {
      const [kRaw, ...vParts] = attr.split('=');
      const k = kRaw.trim().toLowerCase();
      const v = vParts.join('=').trim();
      if (k === 'domain' && v) {
        const cleanedDomain = v.replace(/^\./, '').toLowerCase();
        if (domain === cleanedDomain || domain.endsWith(`.${cleanedDomain}`)) {
          domain = cleanedDomain;
        }
      } else if (k === 'path' && v) {
        cookiePath = v.startsWith('/') ? v : '/';
      } else if (k === 'max-age' && v) {
        const secs = Number.parseInt(v, 10);
        if (!Number.isNaN(secs)) expires = Date.now() + secs * 1000;
      } else if (k === 'expires' && v && expires === null) {
        const ts = Date.parse(v);
        if (!Number.isNaN(ts)) expires = ts;
      } else if (k === 'secure') {
        secure = true;
      }
    }

    if (!session.cookies.has(domain)) {
      session.cookies.set(domain, new Map());
    }
    const domainJar = session.cookies.get(domain);
    if (expires !== null && expires <= Date.now()) {
      domainJar.delete(name);
    } else {
      domainJar.set(name, { name, value, domain, path: cookiePath, expires, secure });
    }
  }
}

function buildCookieHeaderForUrl(session, targetUrl) {
  if (!session) return '';
  const hostname = targetUrl.hostname.toLowerCase();
  const reqPath = targetUrl.pathname || '/';
  const isHttps = targetUrl.protocol === 'https:';
  const matched = [];
  const now = Date.now();

  for (const [domain, domainJar] of session.cookies.entries()) {
    if (hostname !== domain && !hostname.endsWith(`.${domain}`)) continue;
    for (const [name, cookie] of domainJar.entries()) {
      if (cookie.expires !== null && cookie.expires <= now) {
        domainJar.delete(name);
        continue;
      }
      if (cookie.secure && !isHttps) continue;
      if (!reqPath.startsWith(cookie.path)) continue;
      matched.push(`${cookie.name}=${cookie.value}`);
    }
  }

  return matched.join('; ');
}

function extractRefererTarget(req) {
  const rawRef = req.get('referer');
  if (!rawRef) return null;
  try {
    const parsedRef = new URL(rawRef);
    if (parsedRef.pathname === '/proxy' && parsedRef.searchParams.has('url')) {
      return parsedRef.searchParams.get('url');
    }
    if (parsedRef.pathname.startsWith('/b/')) {
      const token = parsedRef.pathname.slice(3).split('/')[0];
      if (token) return decodeBase64Url(token);
    }
    if (parsedRef.pathname.startsWith('/p/')) {
      const rest = parsedRef.pathname.slice(3);
      const slashIdx = rest.indexOf('/');
      const originToken = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
      const subPath = slashIdx === -1 ? '/' : rest.slice(slashIdx);
      const origin = decodeBase64Url(originToken);
      return `${origin}${subPath}${parsedRef.search || ''}`;
    }
  } catch {
    // ignore
  }
  return null;
}

// ---------------------------------------------------------------------------
// URL & Content Rewriting (/b/<base64url> for navigation, /p/<originToken>/path for assets)
// ---------------------------------------------------------------------------
function toProxyUrl(rawUrl, baseUrl, extraParams = {}) {
  if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
  const trimmed = rawUrl.trim();
  if (!trimmed) return rawUrl;

  if (
    trimmed.startsWith('#') ||
    trimmed.startsWith('/b/') ||
    trimmed.startsWith('/p/') ||
    trimmed.startsWith('/proxy?url=') ||
    /^(data|blob|mailto|tel|javascript|about):/i.test(trimmed)
  ) {
    return trimmed;
  }

  try {
    const resolved = new URL(trimmed, baseUrl);
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
      return rawUrl;
    }
    let out = `/b/${encodeBase64Url(resolved.toString())}`;
    if (extraParams.mode === 'reader') {
      out += '?mode=reader';
    }
    return out;
  } catch {
    return rawUrl;
  }
}

function toProxyAssetUrl(rawUrl, baseUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
  const trimmed = rawUrl.trim();
  if (!trimmed) return rawUrl;

  if (
    trimmed.startsWith('#') ||
    trimmed.startsWith('/b/') ||
    trimmed.startsWith('/p/') ||
    trimmed.startsWith('/proxy?url=') ||
    /^(data|blob|mailto|tel|javascript|about):/i.test(trimmed)
  ) {
    return trimmed;
  }

  try {
    const resolved = new URL(trimmed, baseUrl);
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
      return rawUrl;
    }
    const originToken = encodeBase64Url(resolved.origin);
    return `/p/${originToken}${resolved.pathname}${resolved.search}${resolved.hash}`;
  } catch {
    return rawUrl;
  }
}

function rewriteSrcset(srcset, baseUrl) {
  if (!srcset || typeof srcset !== 'string') return srcset;
  return srcset
    .split(',')
    .map((entry) => {
      const trimmed = entry.trim();
      if (!trimmed) return '';
      const parts = trimmed.split(/\s+/);
      parts[0] = toProxyAssetUrl(parts[0], baseUrl);
      return parts.join(' ');
    })
    .filter(Boolean)
    .join(', ');
}

function rewriteCss(cssText, baseUrl) {
  if (!cssText || typeof cssText !== 'string') return cssText;

  let out = cssText.replace(
    /@import\s+(["'])([^"']+)\1/gi,
    (_m, quote, url) => `@import ${quote}${toProxyAssetUrl(url, baseUrl)}${quote}`
  );

  out = out.replace(/url\(\s*(["']?)([^)"']+)\1\s*\)/gi, (_m, quote, url) => {
    const cleaned = url.trim();
    if (!cleaned || cleaned.startsWith('data:') || cleaned.startsWith('#')) {
      return `url(${quote}${cleaned}${quote})`;
    }
    return `url(${quote}${toProxyAssetUrl(cleaned, baseUrl)}${quote})`;
  });

  return out;
}

function buildClientShimScript(targetUrl, profile = CHROME_PROFILES.desktop, initialCookies = '') {
  const safeTargetJson = JSON.stringify(targetUrl).replace(/</g, '\\u003c');
  const safeProfileJson = JSON.stringify({
    userAgent: profile.userAgent,
    appVersion: profile.appVersion,
    platform: profile.platform,
    mobile: profile.mobile,
    platformName: profile.mobile ? 'Android' : 'Windows'
  }).replace(/</g, '\\u003c');
  const safeCookieJson = JSON.stringify(initialCookies || '').replace(/</g, '\\u003c');

  return `<script data-proxy-shim="true">
(function () {
  if (window.__PROXY_SHIM_ACTIVE__) return;
  window.__PROXY_SHIM_ACTIVE__ = true;
  var CURRENT_TARGET = ${safeTargetJson};
  var CHROME_PROFILE = ${safeProfileJson};
  var VIRTUAL_COOKIES = ${safeCookieJson};

  function encodeBase64Url(str) {
    var bytes = new TextEncoder().encode(String(str));
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }

  function decodeBase64Url(token) {
    var b64 = String(token || '').replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  // -------------------------------------------------------------------------
  // 1. Always Declare Browser as Google Chrome (Navigator & window.chrome)
  // -------------------------------------------------------------------------
  (function spoofChromeIdentity() {
    var navProto = Navigator.prototype || navigator.constructor.prototype;
    function defNav(prop, val) {
      try {
        Object.defineProperty(navProto, prop, {
          configurable: true,
          enumerable: true,
          get: function () { return val; }
        });
      } catch (e) {}
      try {
        Object.defineProperty(navigator, prop, {
          configurable: true,
          enumerable: true,
          get: function () { return val; }
        });
      } catch (e) {}
    }

    defNav('userAgent', CHROME_PROFILE.userAgent);
    defNav('appVersion', CHROME_PROFILE.appVersion);
    defNav('vendor', 'Google Inc.');
    defNav('platform', CHROME_PROFILE.platform);
    defNav('product', 'Gecko');
    defNav('webdriver', false);

    var uaData = {
      brands: [
        { brand: 'Google Chrome', version: '131' },
        { brand: 'Chromium', version: '131' },
        { brand: 'Not_A Brand', version: '24' }
      ],
      mobile: CHROME_PROFILE.mobile,
      platform: CHROME_PROFILE.platformName,
      getHighEntropyValues: function () {
        return Promise.resolve({
          brands: this.brands,
          mobile: this.mobile,
          platform: this.platform,
          platformVersion: CHROME_PROFILE.mobile ? '14.0.0' : '15.0.0',
          architecture: CHROME_PROFILE.mobile ? 'arm' : 'x86',
          bitness: '64',
          model: CHROME_PROFILE.mobile ? 'Pixel 8 Pro' : '',
          uaFullVersion: '131.0.0.0',
          fullVersionList: [
            { brand: 'Google Chrome', version: '131.0.0.0' },
            { brand: 'Chromium', version: '131.0.0.0' },
            { brand: 'Not_A Brand', version: '24.0.0.0' }
          ]
        });
      },
      toJSON: function () {
        return { brands: this.brands, mobile: this.mobile, platform: this.platform };
      }
    };
    defNav('userAgentData', uaData);

    if (!window.chrome) {
      try {
        window.chrome = {
          runtime: {},
          app: { isInstalled: false },
          csi: function () { return { startE: Date.now(), onloadT: Date.now(), pageT: 120 }; },
          loadTimes: function () { return { wasFetchedViaSpdy: true, npnNegotiatedProtocol: 'h2' }; }
        };
      } catch (e) {}
    }
  })();

  // -------------------------------------------------------------------------
  // 2. Always Focus & Always Visible Spoofer
  // -------------------------------------------------------------------------
  var alwaysFocusEnabled = true;
  try {
    if (localStorage.getItem('proxy11643_always_focus') === 'false') {
      alwaysFocusEnabled = false;
    }
  } catch (e) {}

  var docProto = Document.prototype || document.constructor.prototype;
  var origHiddenDesc = Object.getOwnPropertyDescriptor(docProto, 'hidden');
  var origVisDesc = Object.getOwnPropertyDescriptor(docProto, 'visibilityState');
  var origHasFocus = docProto.hasFocus ? docProto.hasFocus : document.hasFocus;
  var origAddEventListener = EventTarget.prototype.addEventListener;
  var origRAF = window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : null;
  var origCAF = window.cancelAnimationFrame ? window.cancelAnimationFrame.bind(window) : null;

  function isNativelyHidden() {
    try {
      if (origHiddenDesc && origHiddenDesc.get) {
        return Boolean(origHiddenDesc.get.call(document));
      }
    } catch (e) {}
    return false;
  }

  function defineDocProp(prop, getter) {
    try {
      Object.defineProperty(docProto, prop, { configurable: true, enumerable: true, get: getter });
    } catch (e) {}
    try {
      Object.defineProperty(document, prop, { configurable: true, enumerable: true, get: getter });
    } catch (e) {}
  }

  defineDocProp('hidden', function () {
    if (alwaysFocusEnabled) return false;
    return origHiddenDesc && origHiddenDesc.get ? origHiddenDesc.get.call(document) : false;
  });
  defineDocProp('webkitHidden', function () { return alwaysFocusEnabled ? false : isNativelyHidden(); });
  defineDocProp('mozHidden', function () { return alwaysFocusEnabled ? false : isNativelyHidden(); });
  defineDocProp('msHidden', function () { return alwaysFocusEnabled ? false : isNativelyHidden(); });
  defineDocProp('visibilityState', function () {
    if (alwaysFocusEnabled) return 'visible';
    return origVisDesc && origVisDesc.get ? origVisDesc.get.call(document) : 'visible';
  });
  defineDocProp('webkitVisibilityState', function () {
    if (alwaysFocusEnabled) return 'visible';
    return origVisDesc && origVisDesc.get ? origVisDesc.get.call(document) : 'visible';
  });

  try {
    var hasFocusOverride = function () {
      if (alwaysFocusEnabled) return true;
      return origHasFocus ? origHasFocus.call(document) : true;
    };
    Object.defineProperty(docProto, 'hasFocus', { configurable: true, writable: true, value: hasFocusOverride });
    Object.defineProperty(document, 'hasFocus', { configurable: true, writable: true, value: hasFocusOverride });
  } catch (e) {}

  var BLOCKED_GLOBAL_EVENTS = {
    visibilitychange: true,
    webkitvisibilitychange: true,
    mozvisibilitychange: true,
    msvisibilitychange: true,
    freeze: true,
    pagehide: true
  };

  Object.keys(BLOCKED_GLOBAL_EVENTS).forEach(function (evtName) {
    origAddEventListener.call(document, evtName, function (ev) {
      if (alwaysFocusEnabled) ev.stopImmediatePropagation();
    }, true);
    origAddEventListener.call(window, evtName, function (ev) {
      if (alwaysFocusEnabled) ev.stopImmediatePropagation();
    }, true);
  });

  ['blur', 'focusout', 'focus', 'focusin'].forEach(function (evtName) {
    origAddEventListener.call(window, evtName, function (ev) {
      if (alwaysFocusEnabled && (ev.target === window || ev.target === document)) {
        ev.stopImmediatePropagation();
      }
    }, true);
    origAddEventListener.call(document, evtName, function (ev) {
      if (alwaysFocusEnabled && (ev.target === window || ev.target === document)) {
        ev.stopImmediatePropagation();
      }
    }, true);
  });

  EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (
      (this === window || this === document) &&
      typeof type === 'string' &&
      typeof listener === 'function'
    ) {
      var lower = type.toLowerCase();
      if (BLOCKED_GLOBAL_EVENTS[lower]) {
        return origAddEventListener.call(this, type, function () {
          if (alwaysFocusEnabled) return undefined;
          return listener.apply(this, arguments);
        }, options);
      }
      if (lower === 'blur' || lower === 'focusout' || lower === 'focus' || lower === 'focusin') {
        return origAddEventListener.call(this, type, function (ev) {
          if (alwaysFocusEnabled && ev && (ev.target === window || ev.target === document)) {
            return undefined;
          }
          return listener.apply(this, arguments);
        }, options);
      }
    }
    return origAddEventListener.call(this, type, listener, options);
  };

  function findDescriptor(obj, propName) {
    var cur = obj;
    while (cur) {
      var d = Object.getOwnPropertyDescriptor(cur, propName);
      if (d) return d;
      cur = Object.getPrototypeOf(cur);
    }
    return null;
  }

  function trapEventProp(targetObj, propName) {
    try {
      var storedHandler = null;
      var origDesc = findDescriptor(targetObj, propName);
      Object.defineProperty(targetObj, propName, {
        configurable: true,
        get: function () { return storedHandler; },
        set: function (fn) {
          storedHandler = fn;
          if (origDesc && origDesc.set) {
            origDesc.set.call(this, function (ev) {
              if (alwaysFocusEnabled && (ev.target === window || ev.target === document || propName.indexOf('visibility') !== -1)) {
                return undefined;
              }
              return typeof fn === 'function' ? fn.apply(this, arguments) : undefined;
            });
          }
        }
      });
    } catch (e) {}
  }

  trapEventProp(window, 'onblur');
  trapEventProp(window, 'onfocus');
  trapEventProp(window, 'onfocusout');
  trapEventProp(window, 'onfocusin');
  trapEventProp(window, 'onpagehide');
  trapEventProp(document, 'onblur');
  trapEventProp(document, 'onfocus');
  trapEventProp(document, 'onfocusout');
  trapEventProp(document, 'onfocusin');
  trapEventProp(document, 'onvisibilitychange');
  trapEventProp(document, 'onwebkitvisibilitychange');

  if (origRAF && origCAF) {
    var rafTimeoutMap = new Map();
    var fakeRafSeq = 1000000;
    window.requestAnimationFrame = function (cb) {
      if (alwaysFocusEnabled && isNativelyHidden()) {
        var fakeId = ++fakeRafSeq;
        var tid = setTimeout(function () {
          rafTimeoutMap.delete(fakeId);
          cb(typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now());
        }, 32);
        rafTimeoutMap.set(fakeId, tid);
        return fakeId;
      }
      return origRAF(cb);
    };
    window.cancelAnimationFrame = function (id) {
      if (rafTimeoutMap.has(id)) {
        clearTimeout(rafTimeoutMap.get(id));
        rafTimeoutMap.delete(id);
        return;
      }
      return origCAF(id);
    };
  }

  origAddEventListener.call(window, 'message', function (ev) {
    if (!ev.data) return;
    if (ev.data.type === 'proxy:always-focus') {
      alwaysFocusEnabled = Boolean(ev.data.enabled);
    } else if (ev.data.type === 'proxy:exit-virtual-fullscreen') {
      if (typeof exitVirtualFullscreen === 'function') exitVirtualFullscreen();
    }
  });

  // -------------------------------------------------------------------------
  // 2b. Virtual Fullscreen (stays inside http://localhost:11643/ only!)
  // -------------------------------------------------------------------------
  var virtualFsElement = null;

  function ensureFsStyle() {
    if (document.getElementById('__proxy_virtual_fs_style__')) return;
    var targetParent = document.head || document.documentElement;
    if (!targetParent) return;
    var st = document.createElement('style');
    st.id = '__proxy_virtual_fs_style__';
    st.textContent =
      '[data-proxy-fullscreen="true"]{' +
      'position:fixed!important;inset:0!important;top:0!important;left:0!important;' +
      'right:0!important;bottom:0!important;width:100vw!important;height:100vh!important;' +
      'max-width:100vw!important;max-height:100vh!important;margin:0!important;' +
      'z-index:2147483647!important;box-sizing:border-box!important;' +
      '}' +
      'video[data-proxy-fullscreen="true"]{background:#000!important;object-fit:contain!important;}';
    targetParent.appendChild(st);
  }

  function dispatchFsChange(targetEl) {
    ['fullscreenchange', 'webkitfullscreenchange', 'mozfullscreenchange', 'MSFullscreenChange'].forEach(function (evtName) {
      try { document.dispatchEvent(new Event(evtName, { bubbles: true })); } catch (e) {}
      if (targetEl && targetEl.dispatchEvent) {
        try { targetEl.dispatchEvent(new Event(evtName, { bubbles: true })); } catch (e) {}
      }
    });
  }

  function enterVirtualFullscreen(el) {
    if (!el || !el.setAttribute) return Promise.resolve();
    ensureFsStyle();
    if (virtualFsElement && virtualFsElement !== el) {
      try { virtualFsElement.removeAttribute('data-proxy-fullscreen'); } catch (e) {}
    }
    virtualFsElement = el;
    el.setAttribute('data-proxy-fullscreen', 'true');
    try {
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'proxy:virtual-fullscreen', active: true, tabId: window.name || '' }, '*');
      }
    } catch (e) {}
    dispatchFsChange(el);
    return Promise.resolve();
  }

  function exitVirtualFullscreen() {
    var prev = virtualFsElement;
    if (prev) {
      try { prev.removeAttribute('data-proxy-fullscreen'); } catch (e) {}
    }
    virtualFsElement = null;
    try {
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'proxy:virtual-fullscreen', active: false, tabId: window.name || '' }, '*');
      }
    } catch (e) {}
    if (prev) dispatchFsChange(prev);
    return Promise.resolve();
  }

  defineDocProp('fullscreenEnabled', function () { return true; });
  defineDocProp('webkitFullscreenEnabled', function () { return true; });
  defineDocProp('mozFullScreenEnabled', function () { return true; });
  defineDocProp('msFullscreenEnabled', function () { return true; });
  defineDocProp('fullscreenElement', function () { return virtualFsElement; });
  defineDocProp('webkitFullscreenElement', function () { return virtualFsElement; });
  defineDocProp('webkitCurrentFullScreenElement', function () { return virtualFsElement; });
  defineDocProp('mozFullScreenElement', function () { return virtualFsElement; });
  defineDocProp('msFullscreenElement', function () { return virtualFsElement; });
  defineDocProp('fullscreen', function () { return Boolean(virtualFsElement); });
  defineDocProp('webkitIsFullScreen', function () { return Boolean(virtualFsElement); });
  defineDocProp('mozFullScreen', function () { return Boolean(virtualFsElement); });

  ['requestFullscreen', 'webkitRequestFullscreen', 'webkitRequestFullScreen', 'mozRequestFullScreen', 'msRequestFullscreen'].forEach(function (fnName) {
    try {
      Object.defineProperty(Element.prototype, fnName, {
        configurable: true,
        writable: true,
        value: function () { return enterVirtualFullscreen(this); }
      });
    } catch (e) {}
  });

  ['exitFullscreen', 'webkitExitFullscreen', 'webkitCancelFullScreen', 'mozCancelFullScreen', 'msExitFullscreen'].forEach(function (fnName) {
    try {
      Object.defineProperty(docProto, fnName, { configurable: true, writable: true, value: exitVirtualFullscreen });
      Object.defineProperty(document, fnName, { configurable: true, writable: true, value: exitVirtualFullscreen });
    } catch (e) {}
  });

  origAddEventListener.call(document, 'keydown', function (ev) {
    if (ev.key === 'Escape' && virtualFsElement) {
      exitVirtualFullscreen();
    }
  }, true);

  // -------------------------------------------------------------------------
  // 3. Virtualized document.cookie & ServiceWorker Stub
  // -------------------------------------------------------------------------
  try {
    var cookieStore = {};
    if (VIRTUAL_COOKIES) {
      VIRTUAL_COOKIES.split(';').forEach(function (pair) {
        var idx = pair.indexOf('=');
        if (idx > 0) cookieStore[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
      });
    }
    Object.defineProperty(document, 'cookie', {
      configurable: true,
      get: function () {
        return Object.keys(cookieStore).map(function (k) { return k + '=' + cookieStore[k]; }).join('; ');
      },
      set: function (val) {
        var firstPart = String(val || '').split(';')[0];
        var eq = firstPart.indexOf('=');
        if (eq > 0) {
          var k = firstPart.slice(0, eq).trim();
          var v = firstPart.slice(eq + 1).trim();
          if (k) cookieStore[k] = v;
        }
      }
    });
  } catch (e) {}

  try {
    if (navigator.serviceWorker && navigator.serviceWorker.register) {
      navigator.serviceWorker.register = function () {
        return Promise.resolve({
          scope: '/', active: null, installing: null, waiting: null,
          update: function () { return Promise.resolve(); },
          unregister: function () { return Promise.resolve(true); }
        });
      };
    }
  } catch (e) {}

  // -------------------------------------------------------------------------
  // 4. Universal Proxy URL Rewriting (/p/<origin>/path & /b/<token>)
  // -------------------------------------------------------------------------
  function resolveTargetUrl(raw) {
    if (raw == null) return raw;
    var s = String(raw).trim();
    if (!s || s.charAt(0) === '#' || s.indexOf('/b/') === 0 || s.indexOf('/p/') === 0 || s.indexOf('/proxy?url=') === 0) return s;
    if (/^(data|blob|mailto|tel|javascript|about):/i.test(s)) return s;
    if (
      s.indexOf(window.location.origin + '/b/') === 0 ||
      s.indexOf(window.location.origin + '/p/') === 0 ||
      s.indexOf(window.location.origin + '/proxy?url=') === 0
    ) {
      return s.slice(window.location.origin.length);
    }
    try {
      if (s.indexOf(window.location.origin + '/') === 0) {
        s = s.slice(window.location.origin.length);
      }
      var resolved = new URL(s, CURRENT_TARGET);
      if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return raw;
      return '/p/' + encodeBase64Url(resolved.origin) + resolved.pathname + resolved.search + resolved.hash;
    } catch (e) {
      return raw;
    }
  }

  function extractTargetFromProxyUrl(href) {
    try {
      var u = new URL(href, window.location.origin);
      if (u.pathname.indexOf('/b/') === 0) {
        return decodeBase64Url(u.pathname.slice(3).split('/')[0]);
      }
      if (u.pathname.indexOf('/p/') === 0) {
        var rest = u.pathname.slice(3);
        var slashIdx = rest.indexOf('/');
        var originToken = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
        var subPath = slashIdx === -1 ? '/' : rest.slice(slashIdx);
        return decodeBase64Url(originToken) + subPath + (u.search || '');
      }
      if (u.pathname === '/proxy' && u.searchParams.has('url')) {
        return u.searchParams.get('url');
      }
    } catch (e) {}
    return CURRENT_TARGET;
  }

  function getFaviconUrl() {
    var icon = document.querySelector('link[rel~="icon"], link[rel="shortcut icon"]');
    if (!icon) return '';
    var href = icon.getAttribute('href') || '';
    if (!href) return '';
    return href.indexOf('/b/') === 0 || href.indexOf('/p/') === 0 || href.indexOf('/proxy?url=') === 0 ? href : resolveTargetUrl(href);
  }

  function notifyParent(reason) {
    try {
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({
          type: 'proxy:state',
          reason: reason || 'update',
          tabId: window.name || '',
          url: CURRENT_TARGET,
          title: document.title || CURRENT_TARGET,
          favicon: getFaviconUrl()
        }, '*');
      }
    } catch (e) {}
  }

  function sendToParent(payload) {
    try {
      if (window.parent && window.parent !== window) {
        payload.tabId = window.name || '';
        window.parent.postMessage(payload, '*');
      }
    } catch (e) {}
  }

  function safeSerialize(arg) {
    if (typeof arg === 'string') return arg;
    if (arg === undefined) return 'undefined';
    if (arg === null) return 'null';
    if (arg instanceof Error) return arg.stack || arg.message;
    try {
      return JSON.stringify(arg);
    } catch (e) {
      return String(arg);
    }
  }

  ['log', 'info', 'warn', 'error'].forEach(function (lvl) {
    try {
      var origFn = console[lvl];
      if (typeof origFn === 'function') {
        console[lvl] = function () {
          var args = Array.prototype.slice.call(arguments);
          sendToParent({
            type: 'proxy:devtools-console',
            level: lvl,
            text: args.map(safeSerialize).join(' ')
          });
          return origFn.apply(console, args);
        };
      }
    } catch (e) {}
  });

  origAddEventListener.call(window, 'error', function (ev) {
    sendToParent({
      type: 'proxy:devtools-console',
      level: 'error',
      text: (ev && ev.message ? ev.message : 'Script error') + (ev && ev.lineno ? ' (line ' + ev.lineno + ')' : '')
    });
  });

  origAddEventListener.call(window, 'unhandledrejection', function (ev) {
    sendToParent({
      type: 'proxy:devtools-console',
      level: 'error',
      text: 'Unhandled Promise Rejection: ' + safeSerialize(ev ? ev.reason : '')
    });
  });

  if (typeof window.fetch === 'function') {
    var origFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      var started = Date.now();
      var method = (init && init.method) || (input && input.method) || 'GET';
      var rawTarget = typeof input === 'string' || input instanceof URL ? String(input) : (input && input.url) || '';
      var proxied = rawTarget ? resolveTargetUrl(rawTarget) : rawTarget;
      var displayUrl = extractTargetFromProxyUrl(proxied);
      var safeInit = init ? Object.assign({}, init) : undefined;
      if (safeInit && 'integrity' in safeInit) delete safeInit.integrity;
      var promise;
      try {
        if (typeof input === 'string' || input instanceof URL) {
          promise = origFetch(proxied, safeInit);
        } else if (input && typeof input.url === 'string') {
          var reqOpts = {
            method: (safeInit && safeInit.method) || input.method || 'GET',
            headers: (safeInit && safeInit.headers) || input.headers,
            credentials: 'same-origin'
          };
          if (reqOpts.method !== 'GET' && reqOpts.method !== 'HEAD') {
            reqOpts.body = (safeInit && safeInit.body) !== undefined ? safeInit.body : input.body;
          }
          promise = origFetch(proxied, reqOpts);
        } else {
          promise = origFetch(input, safeInit);
        }
      } catch (e) {
        promise = origFetch(proxied || input, safeInit);
      }
      return promise.then(
        function (res) {
          sendToParent({
            type: 'proxy:devtools-network',
            kind: 'fetch',
            method: String(method).toUpperCase(),
            url: displayUrl,
            status: res ? res.status : 0,
            ms: Date.now() - started
          });
          return res;
        },
        function (err) {
          sendToParent({
            type: 'proxy:devtools-network',
            kind: 'fetch',
            method: String(method).toUpperCase(),
            url: displayUrl,
            status: 'ERR',
            ms: Date.now() - started
          });
          throw err;
        }
      );
    };
  }

  if (typeof window.Worker === 'function') {
    var OrigWorker = window.Worker;
    window.Worker = function (scriptURL, options) {
      return new OrigWorker(resolveTargetUrl(scriptURL), options);
    };
    window.Worker.prototype = OrigWorker.prototype;
  }

  if (window.XMLHttpRequest && XMLHttpRequest.prototype.open) {
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      var args = Array.prototype.slice.call(arguments);
      var proxied = resolveTargetUrl(url);
      this.__proxyNetMeta = {
        method: String(method || 'GET').toUpperCase(),
        url: extractTargetFromProxyUrl(proxied)
      };
      args[1] = proxied;
      return origOpen.apply(this, args);
    };
    XMLHttpRequest.prototype.send = function () {
      var xhr = this;
      var started = Date.now();
      origAddEventListener.call(xhr, 'loadend', function () {
        if (xhr.__proxyNetMeta) {
          sendToParent({
            type: 'proxy:devtools-network',
            kind: 'xhr',
            method: xhr.__proxyNetMeta.method,
            url: xhr.__proxyNetMeta.url,
            status: xhr.status || 0,
            ms: Date.now() - started
          });
        }
      });
      return origSend.apply(this, arguments);
    };
  }

  if (navigator.sendBeacon) {
    var origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      return origBeacon(resolveTargetUrl(url), data);
    };
  }

  window.open = function (url) {
    var nextUrl = url ? extractTargetFromProxyUrl(resolveTargetUrl(url)) : '';
    if (window.parent && window.parent !== window && nextUrl) {
      window.parent.postMessage({ type: 'proxy:open-tab', url: nextUrl }, '*');
    }
    return null;
  };

  if (typeof window.WebSocket === 'function') {
    var OrigWebSocket = window.WebSocket;
    window.WebSocket = function (url, protocols) {
      var targetWsUrl = String(url);
      try {
        var parsedWs = new URL(targetWsUrl, CURRENT_TARGET);
        if (parsedWs.protocol === 'http:') parsedWs.protocol = 'ws:';
        if (parsedWs.protocol === 'https:') parsedWs.protocol = 'wss:';
        if (parsedWs.host !== window.location.host) {
          var wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
          targetWsUrl = wsProto + '//' + window.location.host + '/proxy-ws?url=' + encodeURIComponent(parsedWs.toString());
        }
      } catch (e) {}
      return protocols !== undefined ? new OrigWebSocket(targetWsUrl, protocols) : new OrigWebSocket(targetWsUrl);
    };
    window.WebSocket.prototype = OrigWebSocket.prototype;
  }

  var REWRITE_TAGS = { A: 1, AREA: 1, LINK: 1, IMG: 1, SCRIPT: 1, IFRAME: 1, FORM: 1, SOURCE: 1, VIDEO: 1, AUDIO: 1, EMBED: 1 };
  var origSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    try {
      var attr = String(name).toLowerCase();
      if ((attr === 'src' || attr === 'href' || attr === 'action' || attr === 'poster') && REWRITE_TAGS[this.tagName]) {
        value = resolveTargetUrl(value);
      }
    } catch (e) {}
    return origSetAttr.call(this, name, value);
  };

  function hookAttrProp(Proto, propName) {
    if (!Proto) return;
    try {
      var desc = Object.getOwnPropertyDescriptor(Proto, propName);
      if (!desc || !desc.set || !desc.get) return;
      Object.defineProperty(Proto, propName, {
        configurable: true,
        enumerable: true,
        get: function () {
          return desc.get.call(this);
        },
        set: function (val) {
          return desc.set.call(this, resolveTargetUrl(val));
        }
      });
    } catch (e) {}
  }

  hookAttrProp(typeof HTMLScriptElement !== 'undefined' && HTMLScriptElement.prototype, 'src');
  hookAttrProp(typeof HTMLImageElement !== 'undefined' && HTMLImageElement.prototype, 'src');
  hookAttrProp(typeof HTMLIFrameElement !== 'undefined' && HTMLIFrameElement.prototype, 'src');
  hookAttrProp(typeof HTMLLinkElement !== 'undefined' && HTMLLinkElement.prototype, 'href');
  hookAttrProp(typeof HTMLAnchorElement !== 'undefined' && HTMLAnchorElement.prototype, 'href');
  hookAttrProp(typeof HTMLSourceElement !== 'undefined' && HTMLSourceElement.prototype, 'src');
  hookAttrProp(typeof HTMLMediaElement !== 'undefined' && HTMLMediaElement.prototype, 'src');
  hookAttrProp(typeof HTMLEmbedElement !== 'undefined' && HTMLEmbedElement.prototype, 'src');
  hookAttrProp(typeof HTMLFormElement !== 'undefined' && HTMLFormElement.prototype, 'action');

  if (typeof window.EventSource === 'function') {
    var OrigEventSource = window.EventSource;
    window.EventSource = function (url, opts) {
      return new OrigEventSource(resolveTargetUrl(url), opts);
    };
    window.EventSource.prototype = OrigEventSource.prototype;
  }

  function rewriteNodeAttrs(node) {
    if (!node || node.nodeType !== 1) return;
    if (REWRITE_TAGS[node.tagName]) {
      ['href', 'src', 'action', 'poster'].forEach(function (attr) {
        if (node.hasAttribute && node.hasAttribute(attr)) {
          var cur = node.getAttribute(attr);
          var next = resolveTargetUrl(cur);
          if (cur && next && cur !== next) origSetAttr.call(node, attr, next);
        }
      });
    }
    if (node.querySelectorAll) {
      var children = node.querySelectorAll('a[href], img[src], script[src], link[href], iframe[src], form[action], source[src]');
      for (var i = 0; i < children.length; i++) rewriteNodeAttrs(children[i]);
    }
  }

  if (typeof MutationObserver === 'function') {
    var mo = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        var added = mutations[i].addedNodes;
        for (var j = 0; j < added.length; j++) rewriteNodeAttrs(added[j]);
      }
    });
    origAddEventListener.call(document, 'DOMContentLoaded', function () {
      if (document.documentElement) mo.observe(document.documentElement, { childList: true, subtree: true });
    });
  }

  ['pushState', 'replaceState'].forEach(function (fnName) {
    var orig = history[fnName];
    history[fnName] = function (state, title, url) {
      if (url) {
        try {
          var nextTarget = new URL(String(url), CURRENT_TARGET).toString();
          CURRENT_TARGET = nextTarget;
          url = '/b/' + encodeBase64Url(nextTarget);
        } catch (e) {}
      }
      var res = orig.call(this, state, title, url);
      notifyParent(fnName);
      return res;
    };
  });

  origAddEventListener.call(document, 'click', function (ev) {
    var a = ev.target && ev.target.closest ? ev.target.closest('a[href]') : null;
    if (!a) return;
    var href = a.getAttribute('href');
    if (!href || href.charAt(0) === '#' || /^javascript:/i.test(href)) return;

    var proxiedHref = href.indexOf('/b/') === 0 || href.indexOf('/proxy?url=') === 0 ? href : resolveTargetUrl(href);
    if (a.getAttribute('target') === '_blank' && window.parent && window.parent !== window) {
      ev.preventDefault();
      window.parent.postMessage({
        type: 'proxy:open-tab',
        url: extractTargetFromProxyUrl(proxiedHref)
      }, '*');
      return;
    }
    if (href !== proxiedHref) origSetAttr.call(a, 'href', proxiedHref);
  }, true);

  origAddEventListener.call(document, 'submit', function (ev) {
    var form = ev.target;
    if (!form || form.tagName !== 'FORM') return;
    var method = (form.getAttribute('method') || 'GET').toUpperCase();
    if (method !== 'GET') return;

    ev.preventDefault();
    var rawAction = form.getAttribute('action') || CURRENT_TARGET;
    var actionTarget = extractTargetFromProxyUrl(resolveTargetUrl(rawAction));
    try {
      var targetObj = new URL(actionTarget, CURRENT_TARGET);
      var fd = new FormData(form);
      fd.forEach(function (val, key) {
        if (typeof val === 'string') targetObj.searchParams.set(key, val);
      });
      window.location.href = '/b/' + encodeBase64Url(targetObj.toString());
    } catch (e) {}
  }, true);

  var tabMuted = false;
  function applyMediaMute(muted) {
    tabMuted = Boolean(muted);
    try {
      var media = document.querySelectorAll('audio, video');
      for (var i = 0; i < media.length; i++) {
        media[i].muted = tabMuted;
      }
    } catch (e) {}
  }

  origAddEventListener.call(window, 'message', function (ev) {
    if (!ev.data || typeof ev.data !== 'object') return;
    if (ev.data.type === 'proxy:print') {
      try { window.print(); } catch (e) {}
      return;
    }
    if (ev.data.type === 'proxy:mute') {
      applyMediaMute(ev.data.muted);
    } else if (ev.data.type === 'proxy:find') {
      var q = String(ev.data.query || '');
      var back = Boolean(ev.data.backward);
      var count = 0;
      var found = false;
      try {
        if (q) {
          var txt = document.body ? (document.body.innerText || '') : '';
          var lowTxt = txt.toLowerCase();
          var lowQ = q.toLowerCase();
          var pos = 0;
          while ((pos = lowTxt.indexOf(lowQ, pos)) !== -1 && count < 999) {
            count += 1;
            pos += lowQ.length;
          }
          if (typeof window.find === 'function') {
            found = window.find(q, false, back, true, false, false, false);
          }
        }
      } catch (e) {}
      sendToParent({ type: 'proxy:find-result', query: q, total: count, found: found });
    } else if (ev.data.type === 'proxy:eval') {
      try {
        var result = (0, eval)(String(ev.data.code || ''));
        sendToParent({ type: 'proxy:devtools-console', level: 'result', text: safeSerialize(result) });
      } catch (err) {
        sendToParent({ type: 'proxy:devtools-console', level: 'error', text: safeSerialize(err) });
      }
    } else if (ev.data.type === 'proxy:inspect') {
      var ls = {};
      try {
        for (var k = 0; k < localStorage.length; k++) {
          var key = localStorage.key(k);
          ls[key] = localStorage.getItem(key);
        }
      } catch (e) {}
      sendToParent({
        type: 'proxy:inspect-result',
        url: CURRENT_TARGET,
        title: document.title || '',
        cookies: document.cookie || '',
        localStorage: ls,
        html: document.documentElement ? document.documentElement.outerHTML.slice(0, 12000) : ''
      });
    }
  });

  origAddEventListener.call(document, 'DOMContentLoaded', function () {
    if (tabMuted) applyMediaMute(true);
    notifyParent('dom');
  });
  origAddEventListener.call(window, 'load', function () {
    if (tabMuted) applyMediaMute(true);
    notifyParent('load');
  });
  origAddEventListener.call(window, 'hashchange', function () { notifyParent('hashchange'); });
  notifyParent('init');
})();
</script>`;
}

const UNSAFE_URL_ATTRS = ['href', 'src', 'action', 'formaction', 'xlink:href', 'poster', 'srcset'];
const DANGEROUS_SCHEME = /^\s*(javascript|vbscript|data|file):/i;

// Reader mode renders remote content on this app's own origin, so any script-capable
// markup must be removed: event-handler attributes, javascript:/data: URLs, and
// active elements like frames, forms, objects and <base> (which can redirect links).
function sanitizeReaderDom($) {
  $('script, style, noscript, iframe, frame, frameset, object, embed, applet, form, base, meta, link, template, svg[width="0"]').remove();
  $('*').each((_i, el) => {
    const attribs = el.attribs || {};
    for (const name of Object.keys(attribs)) {
      const lower = name.toLowerCase();
      if (lower.startsWith('on') || lower === 'style' || lower === 'srcdoc') {
        $(el).removeAttr(name);
        continue;
      }
      if (UNSAFE_URL_ATTRS.includes(lower)) {
        const value = attribs[name] || '';
        const allowDataImage = lower === 'src' && /^\s*data:image\//i.test(value) && el.tagName === 'img';
        if (DANGEROUS_SCHEME.test(value) && !allowDataImage) {
          $(el).removeAttr(name);
        }
      }
    }
  });
}

function buildReaderHtml(htmlText, targetUrl) {
  const $ = cheerio.load(htmlText);
  const title = $('title').first().text().trim() || targetUrl;
  sanitizeReaderDom($);

  $('a[href]').each((_i, el) => {
    const href = $(el).attr('href');
    if (href) $(el).attr('href', toProxyUrl(href, targetUrl, { mode: 'reader' }));
  });
  $('img[src]').each((_i, el) => {
    const src = $(el).attr('src');
    if (src) $(el).attr('src', toProxyUrl(src, targetUrl));
  });

  const mainNode = $('article, main, [role="main"], #content, .content').first();
  const bodyHtml = mainNode.length > 0 ? mainNode.html() : $('body').html() || '';
  const shim = buildClientShimScript(targetUrl, CHROME_PROFILES.desktop, '');

  const esc = (s) =>
    String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

  return `<!DOCTYPE html>
<html lang="vi">
<head>
  ${shim}
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(title)} (Reader Mode)</title>
  <style>
    body { font-family: Georgia, 'Times New Roman', serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 28px 18px 64px; line-height: 1.75; }
    .reader-wrap { max-width: 760px; margin: 0 auto; background: #111827; border: 1px solid #1e293b; border-radius: 14px; padding: 28px; }
    .reader-banner { font-family: system-ui, sans-serif; font-size: 12px; color: #7dd3fc; background: rgba(56,189,248,0.12); padding: 6px 10px; border-radius: 8px; margin-bottom: 18px; display: flex; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
    .reader-banner a { color: #38bdf8; }
    h1, h2, h3 { font-family: system-ui, sans-serif; color: #f8fafc; line-height: 1.3; }
    a { color: #38bdf8; }
    img { max-width: 100%; height: auto; border-radius: 8px; margin: 12px 0; }
    pre, code { background: #020617; padding: 2px 6px; border-radius: 6px; overflow-x: auto; }
  </style>
</head>
<body>
  <div class="reader-wrap">
    <div class="reader-banner">
      <span>Reader Mode &bull; ${esc(targetUrl)}</span>
      <a href="/b/${encodeBase64Url(targetUrl)}">Xem bản đầy đủ</a>
    </div>
    <h1>${esc(title)}</h1>
    ${bodyHtml || '<p>Không trích xuất được nội dung văn bản.</p>'}
  </div>
</body>
</html>`;
}

function rewriteHtml(htmlText, targetUrl, options = {}) {
  if (options.mode === 'reader') {
    return buildReaderHtml(htmlText, targetUrl);
  }

  const $ = cheerio.load(htmlText, { decodeEntities: false });

  let effectiveBase = targetUrl;
  const baseHref = $('base[href]').first().attr('href');
  if (baseHref) {
    try {
      effectiveBase = new URL(baseHref, targetUrl).toString();
    } catch {
      effectiveBase = targetUrl;
    }
  }
  $('base').remove();

  $('meta[http-equiv]').each((_i, el) => {
    const equiv = ($(el).attr('http-equiv') || '').toLowerCase();
    if (equiv === 'content-security-policy' || equiv === 'x-frame-options') {
      $(el).remove();
    }
  });

  $('[integrity]').removeAttr('integrity');
  $('[nonce]').removeAttr('nonce');

  $('a[href], area[href]').each((_i, el) => {
    const href = $(el).attr('href');
    if (href) $(el).attr('href', toProxyUrl(href, effectiveBase));
  });

  $('link[href]').each((_i, el) => {
    const href = $(el).attr('href');
    if (href) $(el).attr('href', toProxyAssetUrl(href, effectiveBase));
  });

  $('img[src], script[src], iframe[src], frame[src], embed[src], audio[src], video[src], source[src], track[src], input[src]').each(
    (_i, el) => {
      const src = $(el).attr('src');
      if (src) $(el).attr('src', toProxyAssetUrl(src, effectiveBase));
    }
  );

  $('img[data-src], source[data-src]').each((_i, el) => {
    const dsrc = $(el).attr('data-src');
    if (dsrc) $(el).attr('data-src', toProxyAssetUrl(dsrc, effectiveBase));
  });

  $('img[srcset], source[srcset]').each((_i, el) => {
    const srcset = $(el).attr('srcset');
    if (srcset) $(el).attr('srcset', rewriteSrcset(srcset, effectiveBase));
  });

  $('link[imagesrcset]').each((_i, el) => {
    const iset = $(el).attr('imagesrcset');
    if (iset) $(el).attr('imagesrcset', rewriteSrcset(iset, effectiveBase));
  });

  $('video[poster]').each((_i, el) => {
    const poster = $(el).attr('poster');
    if (poster) $(el).attr('poster', toProxyAssetUrl(poster, effectiveBase));
  });

  $('object[data]').each((_i, el) => {
    const dataAttr = $(el).attr('data');
    if (dataAttr) $(el).attr('data', toProxyAssetUrl(dataAttr, effectiveBase));
  });

  $('form[action]').each((_i, el) => {
    const action = $(el).attr('action');
    if (action) $(el).attr('action', toProxyUrl(action, effectiveBase));
  });

  $('[style]').each((_i, el) => {
    const style = $(el).attr('style');
    if (style && /url\(/i.test(style)) {
      $(el).attr('style', rewriteCss(style, effectiveBase));
    }
  });

  $('style').each((_i, el) => {
    const content = $(el).html();
    if (content) $(el).html(rewriteCss(content, effectiveBase));
  });

  const shim = buildClientShimScript(
    targetUrl,
    options.profile || CHROME_PROFILES.desktop,
    options.cookies || ''
  );

  if ($('head').length > 0) {
    $('head').prepend(shim);
  } else if ($('html').length > 0) {
    $('html').prepend(`<head>${shim}</head>`);
  } else {
    return shim + $.html();
  }

  return $.html();
}

// ---------------------------------------------------------------------------
// Multi-Strategy Upstream Fetcher (fetch -> HTTP/2 -> Minimal -> curl)
// ---------------------------------------------------------------------------
function fetchViaHttp2(targetUrl, method, headers, bodyBuf) {
  return new Promise((resolve, reject) => {
    const h2Authority = new URL(targetUrl.origin);
    const client = http2.connect(targetUrl.origin, {
      timeout: REQUEST_TIMEOUT_MS,
      // Route the TLS socket through the checked lookup so HTTP/2 connections get the same
      // private-IP protection as the undici path.
      createConnection: () =>
        tls.connect({
          host: h2Authority.hostname,
          port: Number(h2Authority.port) || 443,
          servername: h2Authority.hostname,
          ALPNProtocols: ['h2'],
          lookup: checkedLookup
        })
    });
    client.on('error', (err) => {
      client.close();
      reject(err);
    });

    const reqHeaders = {
      ':method': method,
      ':path': targetUrl.pathname + targetUrl.search,
      ':authority': targetUrl.host,
      ':scheme': targetUrl.protocol.replace(':', '')
    };
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() !== 'host' && k.toLowerCase() !== 'connection' && v !== undefined) {
        reqHeaders[k.toLowerCase()] = v;
      }
    }

    const req = client.request(reqHeaders);
    const chunks = [];
    let total = 0;
    let status = 502;
    const respHeaders = new Map();
    const setCookies = [];

    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.close();
      client.close();
      reject(new Error('HTTP/2 request timed out'));
    });

    req.on('response', (hdrs) => {
      status = Number(hdrs[':status'] || 200);
      for (const [k, v] of Object.entries(hdrs)) {
        if (k.startsWith(':')) continue;
        if (k.toLowerCase() === 'set-cookie') {
          if (Array.isArray(v)) setCookies.push(...v);
          else if (v) setCookies.push(String(v));
        } else {
          respHeaders.set(k.toLowerCase(), Array.isArray(v) ? v.join(', ') : String(v));
        }
      }
    });

    let oversized = false;
    req.on('data', (chunk) => {
      if (oversized) return;
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        oversized = true;
        client.close();
        return reject(Object.assign(new Error('Proxied response exceeds size limit'), { statusCode: 413 }));
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (oversized) return;
      client.close();
      const zlib = require('zlib');
      let raw = Buffer.concat(chunks);
      const enc = (respHeaders.get('content-encoding') || '').toLowerCase();
      try {
        if (enc.includes('br')) raw = zlib.brotliDecompressSync(raw);
        else if (enc.includes('gzip')) raw = zlib.gunzipSync(raw);
        else if (enc.includes('deflate')) raw = zlib.inflateSync(raw);
      } catch {
        // leave raw if decompression fails
      }
      resolve({ status, headers: respHeaders, setCookies, body: raw });
    });

    req.on('error', (err) => {
      client.close();
      reject(err);
    });

    if (bodyBuf && bodyBuf.length > 0) req.write(bodyBuf);
    req.end();
  });
}

async function resolvePinnedAddress(hostname) {
  if (net.isIP(hostname)) return hostname;
  const entries = await dns.lookup(hostname, { all: true });
  if (!entries.length) throw new Error(`No addresses for ${hostname}`);
  if (!ALLOW_PRIVATE_PROXY) {
    const bad = entries.find((e) => isPrivateOrReservedIp(e.address));
    if (bad) {
      throw Object.assign(new Error(`Blocked connection to private/reserved IP (${bad.address})`), {
        statusCode: 403
      });
    }
  }
  return entries[0].address;
}

function fetchViaCurl(targetUrl, method, userAgent, cookieHeader, pinnedIp) {
  return new Promise((resolve, reject) => {
    const args = [
      '-sS',
      '--http2',
      '--max-time',
      '15',
      '-i',
      '--compressed',
      '-X',
      method,
      '-A',
      userAgent
    ];
    if (cookieHeader) {
      args.push('-H', `Cookie: ${cookieHeader}`);
    }
    if (pinnedIp) {
      const port = targetUrl.port || (targetUrl.protocol === 'https:' ? '443' : '80');
      const ipForResolve = pinnedIp.includes(':') ? `[${pinnedIp}]` : pinnedIp;
      args.push('--resolve', `${targetUrl.hostname}:${port}:${ipForResolve}`);
    }
    args.push(targetUrl.toString());

    execFile('curl', args, { encoding: 'buffer', maxBuffer: MAX_BODY_BYTES }, (err, stdout) => {
      if (err || !stdout || stdout.length === 0) {
        return reject(err || new Error('curl failed'));
      }
      const sepIdx = stdout.indexOf('\r\n\r\n');
      const lfSepIdx = stdout.indexOf('\n\n');
      const splitIdx = sepIdx !== -1 ? sepIdx : lfSepIdx;
      const splitLen = sepIdx !== -1 ? 4 : 2;
      if (splitIdx === -1) return reject(new Error('Invalid curl output'));

      const headerBlock = stdout.slice(0, splitIdx).toString('utf8');
      const body = stdout.slice(splitIdx + splitLen);
      const lines = headerBlock.split(/\r?\n/);
      const statusMatch = /^HTTP\/[\d.]+\s+(\d{3})/.exec(lines[0] || '');
      const status = statusMatch ? Number.parseInt(statusMatch[1], 10) : 200;

      const respHeaders = new Map();
      const setCookies = [];
      for (let i = 1; i < lines.length; i++) {
        const colon = lines[i].indexOf(':');
        if (colon === -1) continue;
        const k = lines[i].slice(0, colon).trim().toLowerCase();
        const v = lines[i].slice(colon + 1).trim();
        if (k === 'set-cookie') setCookies.push(v);
        else respHeaders.set(k, v);
      }
      resolve({ status, headers: respHeaders, setCookies, body });
    });
  });
}

// ---------------------------------------------------------------------------
// Network failure helpers
// ---------------------------------------------------------------------------
function isSsrfBlocked(err) {
  return Boolean(err && (err.statusCode || (err.cause && err.cause.code === 'ESSRFBLOCKED')));
}

// undici reports only "fetch failed"; surface the underlying socket/TLS code for diagnosis.
function withDetailedMessage(err) {
  const cause = err && err.cause;
  const inner = cause && Array.isArray(cause.errors) ? cause.errors[0] : cause;
  const code = (inner && inner.code) || (cause && cause.code) || (err && err.code);
  const base = err && err.message ? err.message : 'Upstream request failed';
  const detailed = Object.assign(new Error(code ? `${base} (${code})` : base), { statusCode: err && err.statusCode });
  if (cause) detailed.cause = cause;
  return detailed;
}

async function fetchViaAlternateTransport(targetUrl, method, forwardHeaders, profile) {
  if (targetUrl.protocol === 'https:') {
    try {
      return await fetchViaHttp2(targetUrl, method, forwardHeaders, null);
    } catch {
      // continue to curl
    }
  }
  try {
    const pinnedIp = await resolvePinnedAddress(targetUrl.hostname);
    return await fetchViaCurl(targetUrl, method, profile.userAgent, forwardHeaders.cookie, pinnedIp);
  } catch {
    return null;
  }
}

async function fetchUpstreamSmart(targetUrl, method, forwardHeaders, bodyBuf, profile) {
  // Attempt 1: Node fetch (undici) with Chrome 131 headers
  const fetchOptions = {
    method,
    headers: forwardHeaders,
    redirect: 'manual',
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    dispatcher: upstreamAgent
  };
  if (method !== 'GET' && method !== 'HEAD' && bodyBuf && bodyBuf.length > 0) {
    fetchOptions.body = bodyBuf;
  }

  let upstream;
  try {
    upstream = await fetch(targetUrl.toString(), fetchOptions);
  } catch (err) {
    // SSRF blocks and non-idempotent requests are never retried over another transport.
    if (isSsrfBlocked(err) || (method !== 'GET' && method !== 'HEAD')) {
      throw withDetailedMessage(err);
    }
    // Connection-level failure (TLS/RST/timeout) on a safe request: some CDNs reject
    // Node's TLS fingerprint. Retry over HTTP/2 and then curl, both SSRF-checked.
    const alt = await fetchViaAlternateTransport(targetUrl, method, forwardHeaders, profile);
    if (alt) return alt;
    throw withDetailedMessage(err);
  }
  const respHeaders = new Map();
  upstream.headers.forEach((v, k) => respHeaders.set(k.toLowerCase(), v));
  const setCookies =
    typeof upstream.headers.getSetCookie === 'function' ? upstream.headers.getSetCookie() : [];
  const arrBuf = await upstream.arrayBuffer();
  if (arrBuf.byteLength > MAX_BODY_BYTES) {
    throw Object.assign(
      new Error(`Proxied response exceeds ${MAX_BODY_BYTES / (1024 * 1024)} MB limit`),
      { statusCode: 413 }
    );
  }

  let result = {
    status: upstream.status,
    headers: respHeaders,
    setCookies,
    body: Buffer.from(arrBuf)
  };

  // If WAF/Cloudflare returned 403 or 503 on GET, retry with HTTP/2 & minimal/curl fallbacks
  if (method === 'GET' && (result.status === 403 || result.status === 503)) {
    if (targetUrl.protocol === 'https:') {
      try {
        const h2Res = await fetchViaHttp2(targetUrl, method, forwardHeaders, null);
        if (h2Res.status < 400) return h2Res;
        result = h2Res;
      } catch {
        // continue to next fallback
      }
    }

    try {
      const minimalHeaders = {
        'user-agent': profile.userAgent,
        accept: forwardHeaders.accept,
        'accept-language': forwardHeaders['accept-language']
      };
      if (forwardHeaders.cookie) minimalHeaders.cookie = forwardHeaders.cookie;
      const minFetch = await fetch(targetUrl.toString(), {
        method,
        headers: minimalHeaders,
        redirect: 'manual',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        dispatcher: upstreamAgent
      });
      if (minFetch.status < 400) {
        const mh = new Map();
        minFetch.headers.forEach((v, k) => mh.set(k.toLowerCase(), v));
        const mCookies =
          typeof minFetch.headers.getSetCookie === 'function' ? minFetch.headers.getSetCookie() : [];
        const mBody = Buffer.from(await minFetch.arrayBuffer());
        if (mBody.length > MAX_BODY_BYTES) {
          throw Object.assign(new Error('Proxied response exceeds size limit'), { statusCode: 413 });
        }
        return {
          status: minFetch.status,
          headers: mh,
          setCookies: mCookies,
          body: mBody
        };
      }
    } catch {
      // continue
    }

    try {
      const pinnedIp = await resolvePinnedAddress(targetUrl.hostname);
      const curlRes = await fetchViaCurl(
        targetUrl,
        method,
        profile.userAgent,
        forwardHeaders.cookie,
        pinnedIp
      );
      if (curlRes.status < 400) return curlRes;
    } catch {
      // keep result
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Express Middleware / Route Handler
// ---------------------------------------------------------------------------
const STRIP_RESPONSE_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'strict-transport-security',
  'content-encoding',
  'content-length',
  'transfer-encoding',
  'connection',
  'set-cookie'
]);

function renderErrorPage(statusCode, title, message, targetUrl, extraHint = '') {
  const esc = (s) =>
    String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');

  const safeEncoded = encodeBase64Url(targetUrl || '');
  const altVn =
    targetUrl && targetUrl.includes('vio.edu.com')
      ? targetUrl.replace('vio.edu.com', 'vio.edu.vn')
      : '';

  return `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>Proxy Error ${statusCode}</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; display: grid; place-items: center; min-height: 100vh; padding: 24px; }
    .box { max-width: 600px; width: 100%; background: #1e293b; border: 1px solid #334155; border-radius: 14px; padding: 24px; }
    h1 { margin: 0 0 8px; font-size: 20px; color: #f87171; }
    p { margin: 8px 0; color: #cbd5e1; line-height: 1.5; font-size: 14px; word-break: break-word; }
    code { display: block; background: #020617; padding: 10px; border-radius: 8px; color: #7dd3fc; font-size: 12px; margin-top: 12px; word-break: break-all; }
    .actions { margin-top: 16px; display: flex; gap: 10px; flex-wrap: wrap; }
    a { text-decoration: none; background: #0284c7; color: #fff; padding: 8px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; }
    a.alt { background: #334155; }
  </style>
</head>
<body>
  <div class="box">
    <h1>${esc(title)} (HTTP ${statusCode})</h1>
    <p>${esc(message)}</p>
    ${extraHint ? `<p>${esc(extraHint)}</p>` : ''}
    <code>${esc(targetUrl)}</code>
    <div class="actions">
      <a href="/b/${safeEncoded}">Thử tải lại</a>
      <a href="/b/${safeEncoded}?mode=reader" class="alt">Thử Reader Mode</a>
      ${altVn ? `<a href="/b/${encodeBase64Url(altVn)}">Mở ${esc(altVn)}</a>` : ''}
      <a href="${esc(targetUrl)}" target="_blank" rel="noopener" class="alt">Mở trực tiếp bằng Chrome thật</a>
    </div>
  </div>
</body>
</html>`;
}

function createProxyRouter({ ownPort, isHttpsRequest }) {
  return async function handleProxyRequest(req, res, overrideTarget) {
    let rawTarget = overrideTarget || req.query.url;
    if (!rawTarget && req.params && req.params.token) {
      try {
        rawTarget = decodeBase64Url(req.params.token);
      } catch {
        rawTarget = '';
      }
    }

    const mode = req.query.mode === 'reader' ? 'reader' : 'normal';
    const isHttps = isHttpsRequest(req);
    const session = getOrCreateProxySession(req, res, isHttps);
    const profileKey =
      CHROME_PROFILES[req.query.ua] ? req.query.ua : session.profile || 'desktop';
    const profile = CHROME_PROFILES[profileKey] || CHROME_PROFILES.desktop;

    let targetUrl;
    try {
      targetUrl = await validateTargetUrl(rawTarget, ownPort);
    } catch (err) {
      const code = err.statusCode || 400;
      if ((req.get('accept') || '').includes('text/html')) {
        return res
          .status(code)
          .type('html')
          .send(renderErrorPage(code, 'Proxy Blocked or Invalid URL', err.message, rawTarget));
      }
      return res.status(code).json({ error: err.message });
    }

    const upstreamAccept =
      req.get('accept') ||
      'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8';
    const isDocumentNav = upstreamAccept.includes('text/html');

    const forwardHeaders = {
      'user-agent': profile.userAgent,
      'sec-ch-ua': profile.secChUa,
      'sec-ch-ua-mobile': profile.secChUaMobile,
      'sec-ch-ua-platform': profile.secChUaPlatform,
      accept: upstreamAccept,
      'accept-language': req.get('accept-language') || 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
      'accept-encoding': 'gzip, deflate, br',
      'upgrade-insecure-requests': '1'
    };

    if (isDocumentNav) {
      forwardHeaders['sec-fetch-dest'] = 'document';
      forwardHeaders['sec-fetch-mode'] = 'navigate';
      forwardHeaders['sec-fetch-site'] = 'none';
      forwardHeaders['sec-fetch-user'] = '?1';
    }

    const realReferer = extractRefererTarget(req);
    if (realReferer) {
      forwardHeaders.referer = realReferer;
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      forwardHeaders.origin = targetUrl.origin;
    }

    const cookieHeader = buildCookieHeaderForUrl(session, targetUrl);
    if (cookieHeader) {
      forwardHeaders.cookie = cookieHeader;
    }

    const contentType = req.get('content-type');
    if (contentType) {
      forwardHeaders['content-type'] = contentType;
    }

    let upstream;
    try {
      upstream = await fetchUpstreamSmart(
        targetUrl,
        req.method,
        forwardHeaders,
        req.rawBody,
        profile
      );
    } catch (err) {
      const blocked = err.cause && err.cause.code === 'ESSRFBLOCKED';
      const code = err.statusCode || (blocked ? 403 : 502);
      const msg = blocked
        ? err.cause.message
        : err.name === 'TimeoutError'
          ? 'Upstream request timed out'
          : err.message;
      if (isDocumentNav) {
        return res
          .status(code)
          .type('html')
          .send(renderErrorPage(code, 'Upstream Connection Failed', msg, targetUrl.toString()));
      }
      return res.status(code).json({ error: msg, target: targetUrl.toString() });
    }

    storeCookiesFromResponse(session, targetUrl, upstream.setCookies);

    if (upstream.status >= 300 && upstream.status < 400 && upstream.headers.has('location')) {
      const rawLoc = upstream.headers.get('location');
      try {
        const nextUrl = new URL(rawLoc, targetUrl).toString();
        const extra = mode === 'reader' ? '?mode=reader' : '';
        return res.redirect(upstream.status, `/b/${encodeBase64Url(nextUrl)}${extra}`);
      } catch {
        // fall through
      }
    }

    // If upstream still returned 403 Forbidden on a document navigation, show helpful recovery page
    const respType = (upstream.headers.get('content-type') || '').toLowerCase();
    if (
      isDocumentNav &&
      upstream.status === 403 &&
      upstream.body.length < 2048 &&
      !respType.includes('application/json')
    ) {
      return res
        .status(403)
        .type('html')
        .send(
          renderErrorPage(
            403,
            'Website gốc từ chối kết nối proxy (403 Forbidden)',
            `Website đích đã trả về HTTP 403 (${upstream.body.toString('utf8').trim() || 'Forbidden'}) sau khi thử HTTP/1.1, HTTP/2 và header Chrome 131.`,
            targetUrl.toString(),
            'Bạn có thể thử Reader Mode, đổi sang Chrome Mobile, kiểm tra lại tên miền (ví dụ vio.edu.vn), hoặc mở trực tiếp bằng Chrome thật.'
          )
        );
    }

    upstream.headers.forEach((value, key) => {
      if (!STRIP_RESPONSE_HEADERS.has(key.toLowerCase())) {
        res.setHeader(key, value);
      }
    });
    res.setHeader('X-Proxy-Target-URL', targetUrl.toString());
    res.setHeader('X-Proxy-UA-Profile', profile.id);
    res.setHeader('Access-Control-Allow-Origin', '*');

    if (respType.includes('text/html') || respType.includes('application/xhtml+xml')) {
      const rewrittenHtml = rewriteHtml(upstream.body.toString('utf8'), targetUrl.toString(), {
        mode,
        profile,
        cookies: buildCookieHeaderForUrl(session, targetUrl)
      });
      res.status(upstream.status);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      return res.send(rewrittenHtml);
    }

    if (respType.includes('text/css')) {
      const rewrittenCss = rewriteCss(upstream.body.toString('utf8'), targetUrl.toString());
      res.status(upstream.status);
      res.setHeader('Content-Type', 'text/css; charset=utf-8');
      return res.send(rewrittenCss);
    }

    const lowerPath = targetUrl.pathname.toLowerCase();
    if (lowerPath.endsWith('.wasm')) {
      res.setHeader('Content-Type', 'application/wasm');
    } else if (lowerPath.endsWith('.swf')) {
      res.setHeader('Content-Type', 'application/x-shockwave-flash');
    } else if ((lowerPath.endsWith('.js') || lowerPath.endsWith('.mjs')) && (!respType || respType.includes('octet-stream'))) {
      res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    }

    res.status(upstream.status);
    return res.send(upstream.body);
  };
}

module.exports = {
  CHROME_PROFILES,
  encodeBase64Url,
  decodeBase64Url,
  extractRefererTarget,
  createProxyRouter,
  getProxySessionStats,
  clearProxySessionCookies,
  setProxySessionProfile,
  validateTargetUrl,
  rewriteHtml,
  rewriteCss,
  toProxyUrl,
  toProxyAssetUrl
};
