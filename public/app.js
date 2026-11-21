'use strict';

const DEFAULT_SITES = [
  { name: 'DuckDuckGo', letter: 'D', url: 'https://html.duckduckgo.com/html/' },
  { name: 'Bing', letter: 'B', url: 'https://www.bing.com/' },
  { name: 'Wikipedia', letter: 'W', url: 'https://vi.wikipedia.org/wiki/Trang_Ch%C3%ADnh' },
  { name: 'VioEdu', letter: 'V', url: 'https://vio.edu.vn/' },
  { name: 'VnExpress', letter: 'E', url: 'https://vnexpress.net' },
  { name: 'Hacker News', letter: 'Y', url: 'https://news.ycombinator.com' },
  { name: 'GitHub', letter: 'G', url: 'https://github.com/explore' },
  { name: 'MDN Docs', letter: 'M', url: 'https://developer.mozilla.org/en-US/' },
  { name: 'Web Test', letter: 'T', url: 'https://ugmoddev.github.io/Web-Test/' },
  { name: 'Example', letter: 'X', url: 'https://example.com' }
];

const SEARCH_ENGINES = {
  ddg: { label: 'DuckDuckGo', build: (q) => `https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}` },
  wiki: { label: 'Wikipedia', build: (q) => `https://vi.wikipedia.org/wiki/Special:Search?search=${encodeURIComponent(q)}` },
  bing: { label: 'Bing', build: (q) => `https://www.bing.com/search?q=${encodeURIComponent(q)}` },
  google: { label: 'Google (Light)', build: (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}&gbv=1` }
};

const GROUP_COLORS = [
  { name: 'Xanh dương', color: '#8ab4f8' },
  { name: 'Đỏ', color: '#f28b82' },
  { name: 'Vàng', color: '#fdd663' },
  { name: 'Xanh lá', color: '#81c995' },
  { name: 'Tím', color: '#c58af9' }
];

const CHROME_INTERNAL_URLS = [
  'chrome://settings',
  'chrome://history',
  'chrome://bookmarks',
  'chrome://downloads',
  'chrome://version',
  'chrome://flags'
];

const STORAGE_BOOKMARKS = 'proxy11643_bookmarks_v1';
const STORAGE_HISTORY = 'proxy11643_history_v1';
const STORAGE_READING = 'proxy11643_reading_v1';
const STORAGE_DOWNLOADS = 'proxy11643_downloads_v1';
const STORAGE_NOTES = 'proxy11643_notes_v1';
const STORAGE_SEARCH_ENGINE = 'proxy11643_search_engine_v1';
const STORAGE_ALWAYS_FOCUS = 'proxy11643_always_focus';
const STORAGE_THEME = 'proxy11643_theme';
const STORAGE_BM_VISIBLE = 'proxy11643_bm_visible';
const STORAGE_TOOLBAR_HIDDEN = 'proxy11643_toolbar_hidden';

let alwaysFocusEnabled = true;
try {
  if (localStorage.getItem(STORAGE_ALWAYS_FOCUS) === 'false') {
    alwaysFocusEnabled = false;
  }
} catch {}

// ---------------------------------------------------------------------------
// Always Focus & Always Visible on Host UI (Zero Focus/Blur Spam)
// ---------------------------------------------------------------------------
(function initParentAlwaysFocusAndKeepAlive() {
  const docProto = Document.prototype;
  const origHiddenDesc = Object.getOwnPropertyDescriptor(docProto, 'hidden');
  const origVisDesc = Object.getOwnPropertyDescriptor(docProto, 'visibilityState');
  const origHasFocus = docProto.hasFocus;
  const origAdd = EventTarget.prototype.addEventListener;

  try {
    Object.defineProperty(document, 'hidden', {
      configurable: true,
      get: () => (alwaysFocusEnabled ? false : Boolean(origHiddenDesc?.get?.call(document)))
    });
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => (alwaysFocusEnabled ? 'visible' : origVisDesc?.get?.call(document) || 'visible')
    });
    document.hasFocus = () => (alwaysFocusEnabled ? true : Boolean(origHasFocus?.call(document)));
  } catch {}

  ['visibilitychange', 'webkitvisibilitychange', 'pagehide', 'freeze'].forEach((evt) => {
    origAdd.call(window, evt, (ev) => { if (alwaysFocusEnabled) ev.stopImmediatePropagation(); }, true);
    origAdd.call(document, evt, (ev) => { if (alwaysFocusEnabled) ev.stopImmediatePropagation(); }, true);
  });

  ['blur', 'focusout', 'focus', 'focusin'].forEach((evt) => {
    origAdd.call(
      window,
      evt,
      (ev) => {
        if (alwaysFocusEnabled && (ev.target === window || ev.target === document)) {
          ev.stopImmediatePropagation();
        }
      },
      true
    );
  });

  let keepAliveAudioStarted = false;
  function startSilentAudioKeepAlive() {
    if (keepAliveAudioStarted || !alwaysFocusEnabled) return;
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    try {
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      gain.gain.value = 0.00001;
      osc.frequency.value = 1;
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      keepAliveAudioStarted = true;
    } catch {}
  }

  origAdd.call(window, 'pointerdown', () => startSilentAudioKeepAlive(), { once: true, passive: true });

  try {
    const workerBlob = new Blob(['setInterval(() => { postMessage("tick"); }, 4000);'], { type: 'application/javascript' });
    const worker = new Worker(URL.createObjectURL(workerBlob));
    worker.onmessage = () => {};
  } catch {}
})();

// DOM References
const browserAppEl = document.getElementById('browser-app');
const tabsContainer = document.getElementById('tabs-container');
const newTabBtn = document.getElementById('new-tab-btn');
const viewport = document.getElementById('viewport');
const omniboxForm = document.getElementById('omnibox-form');
const omniboxInput = document.getElementById('omnibox-input');
const omniboxDropdown = document.getElementById('omnibox-dropdown');
const omniboxLeftIcon = document.getElementById('omnibox-left-icon');
const incognitoPill = document.getElementById('incognito-pill');
const btnBack = document.getElementById('btn-back');
const btnForward = document.getElementById('btn-forward');
const btnReload = document.getElementById('btn-reload');
const btnReaderMode = document.getElementById('btn-reader-mode');
const btnBookmark = document.getElementById('btn-bookmark');
const btnExtensions = document.getElementById('btn-extensions');
const btnSidePanel = document.getElementById('btn-side-panel');
const btnToggleToolbar = document.getElementById('btn-toggle-toolbar');
const btnToggleToolbarStrip = document.getElementById('btn-toggle-toolbar-strip');
const stripToggleIcon = document.getElementById('strip-toggle-icon');
const btnCaptionMin = document.getElementById('btn-caption-min');
const btnCaptionMax = document.getElementById('btn-caption-max');
const btnCaptionClose = document.getElementById('btn-caption-close');
const btnChromeProfile = document.getElementById('btn-chrome-profile');
const btnChromeMenu = document.getElementById('btn-chrome-menu');
const btnSiteInfo = document.getElementById('btn-site-info');
const btnTabSearch = document.getElementById('btn-tab-search');
const bookmarksBar = document.getElementById('bookmarks-bar');
const netBadgeText = document.getElementById('net-badge-text');
const exitVfsBtn = document.getElementById('exit-vfs-btn');

// Find bar
const findBar = document.getElementById('find-bar');
const findInput = document.getElementById('find-input');
const findCount = document.getElementById('find-count');
const findPrev = document.getElementById('find-prev');
const findNext = document.getElementById('find-next');
const findClose = document.getElementById('find-close');

// Side Panel
const sidePanel = document.getElementById('side-panel');
const sidePanelMode = document.getElementById('side-panel-mode');
const sidePanelContent = document.getElementById('side-panel-content');
const closeSidePanel = document.getElementById('close-side-panel');

// DevTools
const devtoolsPanel = document.getElementById('devtools-panel');
const dtTabs = document.querySelectorAll('.dt-tab');
const dtRefreshBtn = document.getElementById('dt-refresh-btn');
const dtClearBtn = document.getElementById('dt-clear-btn');
const dtCloseBtn = document.getElementById('dt-close-btn');
const dtConsoleLogs = document.getElementById('dt-console-logs');
const dtNetworkLogs = document.getElementById('dt-network-logs');
const dtElementsView = document.getElementById('dt-elements-view');
const dtStorageView = document.getElementById('dt-storage-view');
const dtEvalForm = document.getElementById('dt-eval-form');
const dtEvalInput = document.getElementById('dt-eval-input');

// Chrome 3-dot Menu
const chromeMenu = document.getElementById('chrome-menu');
const menuNewTab = document.getElementById('menu-new-tab');
const menuNewIncognito = document.getElementById('menu-new-incognito');
const menuReopenClosed = document.getElementById('menu-reopen-closed');
const menuMultiOpen = document.getElementById('menu-multi-open');
const btnZoomOut = document.getElementById('btn-zoom-out');
const btnZoomIn = document.getElementById('btn-zoom-in');
const zoomLabel = document.getElementById('zoom-label');
const btnVirtualFullscreen = document.getElementById('btn-virtual-fullscreen');
const menuHistory = document.getElementById('menu-history');
const menuDownloads = document.getElementById('menu-downloads');
const menuBookmarksMgr = document.getElementById('menu-bookmarks-mgr');
const menuToggleBookmarks = document.getElementById('menu-toggle-bookmarks');
const menuToggleToolbar = document.getElementById('menu-toggle-toolbar');
const menuFind = document.getElementById('menu-find');
const menuPrint = document.getElementById('menu-print');
const menuSavePage = document.getElementById('menu-save-page');
const menuDevtools = document.getElementById('menu-devtools');
const menuToggleSplit = document.getElementById('menu-toggle-split');
const menuToggleReader = document.getElementById('menu-toggle-reader');
const menuToggleFocus = document.getElementById('menu-toggle-focus');
const menuToggleProfile = document.getElementById('menu-toggle-profile');
const menuToggleTheme = document.getElementById('menu-toggle-theme');
const menuSettings = document.getElementById('menu-settings');
const btnClearCookies = document.getElementById('btn-clear-cookies');
const btnOpenExternal = document.getElementById('btn-open-external');

const menuBmVal = document.getElementById('menu-bm-val');
const menuSplitVal = document.getElementById('menu-split-val');
const menuFocusVal = document.getElementById('menu-focus-val');
const menuProfileVal = document.getElementById('menu-profile-val');
const menuThemeVal = document.getElementById('menu-theme-val');
const menuCookiesVal = document.getElementById('menu-cookies-val');

// Tab Context Menu
const tabContextMenu = document.getElementById('tab-context-menu');
const ctxReload = document.getElementById('ctx-reload');
const ctxDuplicate = document.getElementById('ctx-duplicate');
const ctxPin = document.getElementById('ctx-pin');
const ctxMute = document.getElementById('ctx-mute');
const ctxGroup = document.getElementById('ctx-group');
const ctxUngroup = document.getElementById('ctx-ungroup');
const ctxClose = document.getElementById('ctx-close');
const ctxCloseOthers = document.getElementById('ctx-close-others');
const ctxCloseRight = document.getElementById('ctx-close-right');
const ctxReopen = document.getElementById('ctx-reopen');

// Extensions & Site Info & Tab Search & Modal
const extensionsPopover = document.getElementById('extensions-popover');
const extAlwaysFocus = document.getElementById('ext-always-focus');
const extFocusVal = document.getElementById('ext-focus-val');
const extSplitView = document.getElementById('ext-split-view');
const extSplitVal = document.getElementById('ext-split-val');
const extReaderMode = document.getElementById('ext-reader-mode');
const extDevtools = document.getElementById('ext-devtools');
const extClearCookies = document.getElementById('ext-clear-cookies');
const extCookiesSub = document.getElementById('ext-cookies-sub');

const siteInfoPopover = document.getElementById('site-info-popover');
const siteInfoHost = document.getElementById('site-info-host');
const infoFocusStatus = document.getElementById('info-focus-status');
const infoUaStatus = document.getElementById('info-ua-status');
const infoCookieStatus = document.getElementById('info-cookie-status');
const infoCopyUrl = document.getElementById('info-copy-url');
const infoAddReading = document.getElementById('info-add-reading');

const tabSearchPopover = document.getElementById('tab-search-popover');
const tabSearchInput = document.getElementById('tab-search-input');
const tabSearchList = document.getElementById('tab-search-list');

const multiModal = document.getElementById('multi-modal');
const closeMultiModal = document.getElementById('close-multi-modal');
const cancelMultiBtn = document.getElementById('cancel-multi-btn');
const launchMultiBtn = document.getElementById('launch-multi-btn');
const multiUrlsInput = document.getElementById('multi-urls-input');

// App State
let tabSeq = 0;
let groupSeq = 0;
const tabs = [];
const closedTabsStack = [];
let activeTabId = null;
let contextTabId = null;
let splitViewEnabled = false;
let splitSecondaryTabId = null;
let currentProfile = 'desktop';
let zoomPercent = 100;
let virtualFullscreenActive = false;
let cookiesCount = 0;

function loadJsonStorage(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function saveJsonStorage(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {}
}

let theme = loadJsonStorage(STORAGE_THEME, 'dark');
let bookmarksVisible = loadJsonStorage(STORAGE_BM_VISIBLE, true);
let toolbarHidden = loadJsonStorage(STORAGE_TOOLBAR_HIDDEN, false);
let defaultSearchEngine = loadJsonStorage(STORAGE_SEARCH_ENGINE, 'ddg');
let bookmarks = loadJsonStorage(STORAGE_BOOKMARKS, [
  { name: 'DuckDuckGo', url: 'https://html.duckduckgo.com/html/' },
  { name: 'Wikipedia', url: 'https://vi.wikipedia.org/wiki/Trang_Ch%C3%ADnh' },
  { name: 'VioEdu', url: 'https://vio.edu.vn/' },
  { name: 'VnExpress', url: 'https://vnexpress.net' },
  { name: 'Web Test', url: 'https://ugmoddev.github.io/Web-Test/' },
  { name: 'Example', url: 'https://example.com' }
]);
let historyLog = loadJsonStorage(STORAGE_HISTORY, []);
let readingList = loadJsonStorage(STORAGE_READING, []);
let downloadsLog = loadJsonStorage(STORAGE_DOWNLOADS, []);

function applyTheme(nextTheme) {
  theme = nextTheme === 'light' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', theme);
  menuThemeVal.textContent = theme === 'light' ? 'Sáng' : 'Tối';
  saveJsonStorage(STORAGE_THEME, theme);
}

function applyBookmarksVisibility(visible) {
  bookmarksVisible = Boolean(visible);
  bookmarksBar.classList.toggle('hidden', !bookmarksVisible);
  menuBmVal.textContent = bookmarksVisible ? 'Bật' : 'Tắt';
  saveJsonStorage(STORAGE_BM_VISIBLE, bookmarksVisible);
}

function applyToolbarHidden(hidden) {
  toolbarHidden = Boolean(hidden);
  browserAppEl.classList.toggle('toolbar-hidden', toolbarHidden);
  btnToggleToolbarStrip.classList.toggle('active', toolbarHidden);
  btnToggleToolbarStrip.title = toolbarHidden
    ? 'Hiện thanh tìm kiếm & địa chỉ (Alt+B hoặc F9)'
    : 'Ẩn thanh tìm kiếm & địa chỉ (Alt+B hoặc F9)';

  stripToggleIcon.innerHTML = toolbarHidden
    ? '<path d="M4.2 6.2a.75.75 0 0 1 1.06 0L8 8.94l2.74-2.74a.75.75 0 1 1 1.06 1.06l-3.27 3.27a.75.75 0 0 1-1.06 0L4.2 7.26a.75.75 0 0 1 0-1.06z"/>'
    : '<path d="M4.2 9.8a.75.75 0 0 0 1.06 0L8 7.06l2.74 2.74a.75.75 0 1 0 1.06-1.06L8.53 5.47a.75.75 0 0 0-1.06 0L4.2 8.74a.75.75 0 0 0 0 1.06z"/>';

  const labelEl = menuToggleToolbar.querySelector('span:first-child');
  if (labelEl) {
    labelEl.textContent = toolbarHidden ? 'Hiện thanh tìm kiếm & địa chỉ' : 'Ẩn thanh tìm kiếm & địa chỉ';
  }
  saveJsonStorage(STORAGE_TOOLBAR_HIDDEN, toolbarHidden);
}

function toggleToolbarVisibility() {
  applyToolbarHidden(!toolbarHidden);
}

function normalizeInputToUrl(raw, engineKey = defaultSearchEngine) {
  const input = (raw || '').trim();
  if (!input) return null;

  if (/^chrome:\/\//i.test(input)) {
    return input.toLowerCase();
  }
  if (/^https?:\/\//i.test(input)) {
    return input;
  }
  if (!/\s/.test(input) && /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?(\/.*)?$/.test(input)) {
    return `https://${input}`;
  }
  const engine = SEARCH_ENGINES[engineKey] || SEARCH_ENGINES.ddg;
  return engine.build(input);
}

function encodeBase64Url(str) {
  const bytes = new TextEncoder().encode(String(str));
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// The proxy runs on its own origin (PROXY_PORT). Config is served by the app at /app-config.js.
function getProxyOrigin() {
  const cfg = window.__APP_CONFIG__ || {};
  if (cfg.proxyOrigin) return cfg.proxyOrigin.replace(/\/+$/, '');
  const port = cfg.proxyPort || 11644;
  return `${window.location.protocol}//${window.location.hostname}:${port}`;
}

function buildProxyPath(targetUrl, mode = 'normal') {
  let path = `${getProxyOrigin()}/b/${encodeBase64Url(targetUrl)}?ua=${encodeURIComponent(currentProfile)}`;
  if (mode === 'reader') {
    path += '&mode=reader';
  }
  return path;
}

function addHistoryEntry(url, title, isIncognito = false) {
  if (!url || isIncognito || url.startsWith('chrome://')) return;
  historyLog = historyLog.filter((item) => item.url !== url);
  historyLog.unshift({
    url,
    title: title || url,
    visitedAt: new Date().toISOString()
  });
  historyLog = historyLog.slice(0, 80);
  saveJsonStorage(STORAGE_HISTORY, historyLog);
  if (!sidePanel.classList.contains('hidden') && sidePanelMode.value === 'history') {
    renderSidePanel();
  }
}

function getActiveTab() {
  return tabs.find((t) => t.id === activeTabId) || null;
}

function applyZoomToAllIframes() {
  zoomLabel.textContent = `${zoomPercent}%`;
  const scale = zoomPercent / 100;
  for (const tab of tabs) {
    if (!tab.iframe) continue;
    if (zoomPercent === 100) {
      tab.iframe.style.transform = '';
      tab.iframe.style.width = '100%';
      tab.iframe.style.height = '100%';
    } else {
      tab.iframe.style.transform = `scale(${scale})`;
      tab.iframe.style.width = `${100 / scale}%`;
      tab.iframe.style.height = `${100 / scale}%`;
    }
  }
}

function renderBookmarksBar() {
  bookmarksBar.innerHTML = '';
  for (const bm of bookmarks) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'bm-chip';
    btn.title = `${bm.url} (Click: mở | Ctrl+Click: thẻ mới)`;
    btn.textContent = bm.name;
    btn.addEventListener('click', (e) => {
      if (e.ctrlKey || e.metaKey) createTab(bm.url, true);
      else navigateActiveOrNew(bm.url);
    });
    btn.addEventListener('auxclick', (e) => {
      if (e.button === 1) {
        e.preventDefault();
        createTab(bm.url, true);
      }
    });
    bookmarksBar.appendChild(btn);
  }
}

function updateSplitLayout() {
  const isSplit = splitViewEnabled && tabs.length >= 2;
  viewport.classList.toggle('split-mode', isSplit);
  menuSplitVal.textContent = splitViewEnabled ? 'ON' : 'OFF';
  extSplitVal.textContent = splitViewEnabled ? 'ON' : 'OFF';

  if (isSplit) {
    if (!splitSecondaryTabId || splitSecondaryTabId === activeTabId || !tabs.some((t) => t.id === splitSecondaryTabId)) {
      const other = tabs.find((t) => t.id !== activeTabId);
      splitSecondaryTabId = other ? other.id : null;
    }
  } else {
    splitSecondaryTabId = null;
  }

  for (const tab of tabs) {
    tab.paneEl.classList.toggle('active', tab.id === activeTabId);
    tab.paneEl.classList.toggle('split-secondary', Boolean(splitViewEnabled && tab.id === splitSecondaryTabId));
  }
}

function createGlobeSvg() {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('class', 'tab-globe');
  svg.setAttribute('fill', 'currentColor');
  svg.innerHTML =
    '<path d="M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1zM2.6 8c0-.8.18-1.56.5-2.25h2.06a11.3 11.3 0 0 0-.16 2.25c0 .78.06 1.54.16 2.25H3.1A5.38 5.38 0 0 1 2.6 8zm5.4 5.4c-.83 0-1.64-1.08-2-2.65h4c-.36 1.57-1.17 2.65-2 2.65zm-2.2-3.9A10.1 10.1 0 0 1 5.65 8c0-.52.05-1.02.15-1.5h4.4c.1.48.15.98.15 1.5s-.05 1.02-.15 1.5H5.8zm4.4-4.25h-4.4C6.16 3.68 6.97 2.6 8 2.6s1.84 1.08 2.2 2.65zm.64 0c-.18-.85-.5-1.6-.92-2.2a5.42 5.42 0 0 1 2.98 2.2h-2.06zm-5.68 0H3.1a5.42 5.42 0 0 1 2.98-2.2c-.42.6-.74 1.35-.92 2.2zm5.68 5.5h2.06a5.42 5.42 0 0 1-2.98 2.2c.42-.6.74-1.35.92-2.2zM5.16 10.75c.18.85.5 1.6.92 2.2a5.42 5.42 0 0 1-2.98-2.2h2.06zm5.68-.5c.1-.71.16-1.47.16-2.25s-.06-1.54-.16-2.25h2.06c.32.69.5 1.45.5 2.25s-.18 1.56-.5 2.25h-2.06z"/>';
  return svg;
}

function sortPinnedFirst() {
  const pinned = tabs.filter((t) => t.pinned);
  const normal = tabs.filter((t) => !t.pinned);
  tabs.length = 0;
  tabs.push(...pinned, ...normal);
}

function renderTabs() {
  sortPinnedFirst();
  tabsContainer.innerHTML = '';
  let lastGroupId = null;

  for (const tab of tabs) {
    if (tab.group && tab.group.id !== lastGroupId) {
      const pill = document.createElement('span');
      pill.className = 'tab-group-pill';
      pill.style.background = tab.group.color;
      pill.textContent = tab.group.name;
      tabsContainer.appendChild(pill);
    }
    lastGroupId = tab.group ? tab.group.id : null;

    const el = document.createElement('div');
    const isSec = splitViewEnabled && tab.id === splitSecondaryTabId;
    el.className = `tab ${tab.id === activeTabId ? 'active' : ''} ${isSec ? 'split-secondary' : ''} ${tab.pinned ? 'pinned' : ''} ${tab.incognito ? 'incognito' : ''}`;
    el.setAttribute('role', 'tab');
    el.title = tab.url ? `${tab.title}\n${tab.url}` : tab.title;
    if (tab.group) {
      el.style.boxShadow = `inset 0 2px 0 ${tab.group.color}`;
    }

    if (tab.loading) {
      const spinner = document.createElement('span');
      spinner.className = 'tab-spinner';
      el.appendChild(spinner);
    } else if (tab.favicon) {
      const img = document.createElement('img');
      img.className = 'tab-favicon';
      img.src = tab.favicon;
      img.alt = '';
      img.addEventListener('error', () => img.replaceWith(createGlobeSvg()));
      el.appendChild(img);
    } else {
      el.appendChild(createGlobeSvg());
    }

    if (tab.muted) {
      const m = document.createElement('span');
      m.className = 'tab-muted-icon';
      m.textContent = '🔇';
      el.appendChild(m);
    }

    const titleSpan = document.createElement('span');
    titleSpan.className = 'tab-title';
    titleSpan.textContent = tab.title || 'Thẻ mới';

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'tab-close';
    closeBtn.textContent = '×';
    closeBtn.title = 'Đóng thẻ';
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      closeTab(tab.id);
    });

    el.addEventListener('click', (e) => {
      if (splitViewEnabled && e.shiftKey && tab.id !== activeTabId) {
        splitSecondaryTabId = tab.id;
        updateSplitLayout();
        renderTabs();
        return;
      }
      switchTab(tab.id);
    });

    el.addEventListener('auxclick', (e) => {
      if (e.button === 1 && !tab.pinned) {
        e.preventDefault();
        closeTab(tab.id);
      }
    });

    el.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      openTabContextMenu(tab, e.clientX, e.clientY);
    });

    el.append(titleSpan, closeBtn);
    tabsContainer.appendChild(el);
  }
}

function syncToolbarState() {
  const tab = getActiveTab();
  if (!tab) return;

  omniboxInput.value = tab.url || '';
  btnBack.disabled = tab.historyIndex <= 0;
  btnForward.disabled = tab.historyIndex >= tab.history.length - 1;
  const isHttp = Boolean(tab.url && /^https?:\/\//i.test(tab.url));
  btnReaderMode.classList.toggle('hidden', !isHttp);
  btnReaderMode.classList.toggle('active', tab.mode === 'reader');
  incognitoPill.classList.toggle('hidden', !tab.incognito);

  omniboxLeftIcon.innerHTML = tab.url
    ? '<path d="M3 4.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zm2.37 2.25H13.5a.75.75 0 0 0 0-1.5H5.37a2.5 2.5 0 0 1 0 1.5zM13 8.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zm-2.37.75H2.5a.75.75 0 0 0 0 1.5h8.13a2.5 2.5 0 0 1 0-1.5z"/>'
    : '<path d="M11.74 10.33a6 6 0 1 0-1.41 1.41l3.46 3.47a1 1 0 0 0 1.42-1.42l-3.47-3.46zM6.5 11a4.5 4.5 0 1 1 0-9 4.5 4.5 0 0 1 0 9z"/>';

  const isBookmarked = Boolean(tab.url && bookmarks.some((b) => b.url === tab.url));
  btnBookmark.textContent = isBookmarked ? '★' : '☆';
  btnBookmark.style.color = isBookmarked ? 'var(--accent)' : '';

  siteInfoHost.textContent = tab.url || 'Trang thẻ mới';
}

// ---------------------------------------------------------------------------
// Internal chrome:// Pages (History, Bookmarks, Downloads, Settings, Version)
// ---------------------------------------------------------------------------
function renderChromeInternalPage(paneEl, tab, chromeUrl) {
  tab.iframe = null;
  tab.loading = false;
  paneEl.innerHTML = '';

  const page = document.createElement('div');
  page.className = 'chrome-internal-page';
  const inner = document.createElement('div');
  inner.className = 'chrome-internal-inner';

  if (chromeUrl.startsWith('chrome://history')) {
    tab.title = 'Lịch sử';
    inner.innerHTML = `<h1>Lịch sử duyệt web (chrome://history)</h1>`;
    const search = document.createElement('input');
    search.className = 'chrome-internal-search';
    search.placeholder = 'Tìm kiếm trong lịch sử...';

    const clearBtn = document.createElement('button');
    clearBtn.type = 'button';
    clearBtn.className = 'secondary-btn';
    clearBtn.textContent = 'Xóa toàn bộ lịch sử';
    clearBtn.style.marginBottom = '12px';
    clearBtn.addEventListener('click', () => {
      historyLog = [];
      saveJsonStorage(STORAGE_HISTORY, historyLog);
      renderChromeInternalPage(paneEl, tab, chromeUrl);
    });

    const card = document.createElement('div');
    card.className = 'chrome-card';

    const drawList = (q = '') => {
      card.innerHTML = '';
      const filtered = historyLog.filter(
        (h) => !q || (h.title || '').toLowerCase().includes(q) || h.url.toLowerCase().includes(q)
      );
      if (filtered.length === 0) {
        card.innerHTML = '<div style="color:var(--muted);font-size:13px">Không có mục lịch sử nào.</div>';
        return;
      }
      for (const h of filtered) {
        const row = document.createElement('div');
        row.className = 'chrome-setting-row';
        row.style.cursor = 'pointer';
        row.innerHTML = `<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:75%"><strong>${escapeHtml(h.title || h.url)}</strong><br><small style="color:var(--muted)">${escapeHtml(h.url)}</small></span><small style="color:var(--muted)">${new Date(h.visitedAt).toLocaleTimeString()}</small>`;
        row.addEventListener('click', () => navigateTab(tab.id, h.url));
        card.appendChild(row);
      }
    };

    search.addEventListener('input', () => drawList(search.value.trim().toLowerCase()));
    drawList();
    inner.append(search, clearBtn, card);
  } else if (chromeUrl.startsWith('chrome://bookmarks')) {
    tab.title = 'Trình quản lý dấu trang';
    inner.innerHTML = `<h1>Dấu trang (chrome://bookmarks)</h1>`;
    const card = document.createElement('div');
    card.className = 'chrome-card';

    const addRow = document.createElement('div');
    addRow.style.display = 'flex';
    addRow.style.gap = '8px';
    addRow.style.marginBottom = '12px';
    addRow.innerHTML = `<input id="bm-new-name" class="chrome-internal-search" style="margin:0;flex:1" placeholder="Tên dấu trang"><input id="bm-new-url" class="chrome-internal-search" style="margin:0;flex:2" placeholder="https://..."><button id="bm-add-btn" class="go-btn" type="button">Thêm</button>`;
    addRow.querySelector('#bm-add-btn').addEventListener('click', () => {
      const n = addRow.querySelector('#bm-new-name').value.trim();
      const u = normalizeInputToUrl(addRow.querySelector('#bm-new-url').value.trim());
      if (!u) return;
      bookmarks.push({ name: n || u, url: u });
      saveJsonStorage(STORAGE_BOOKMARKS, bookmarks);
      renderBookmarksBar();
      renderChromeInternalPage(paneEl, tab, chromeUrl);
    });

    for (let i = 0; i < bookmarks.length; i += 1) {
      const bm = bookmarks[i];
      const row = document.createElement('div');
      row.className = 'chrome-setting-row';
      row.innerHTML = `<span style="cursor:pointer" class="bm-open-link"><strong>${escapeHtml(bm.name)}</strong><br><small style="color:var(--muted)">${escapeHtml(bm.url)}</small></span><button class="secondary-btn" type="button">Xóa</button>`;
      row.querySelector('.bm-open-link').addEventListener('click', () => navigateTab(tab.id, bm.url));
      row.querySelector('button').addEventListener('click', () => {
        bookmarks.splice(i, 1);
        saveJsonStorage(STORAGE_BOOKMARKS, bookmarks);
        renderBookmarksBar();
        renderChromeInternalPage(paneEl, tab, chromeUrl);
      });
      card.appendChild(row);
    }

    inner.append(addRow, card);
  } else if (chromeUrl.startsWith('chrome://downloads')) {
    tab.title = 'Tệp đã tải xuống';
    inner.innerHTML = `<h1>Tệp đã tải xuống (chrome://downloads)</h1>`;

    const dlForm = document.createElement('div');
    dlForm.style.display = 'flex';
    dlForm.style.gap = '8px';
    dlForm.style.marginBottom = '12px';
    dlForm.innerHTML = `<input class="chrome-internal-search" style="margin:0;flex:1" placeholder="Nhập URL file muốn tải qua Proxy (https://...)"><button class="go-btn" type="button">Tải xuống</button>`;
    dlForm.querySelector('button').addEventListener('click', () => {
      const target = normalizeInputToUrl(dlForm.querySelector('input').value.trim());
      if (target) triggerDownloadUrl(target);
    });

    const card = document.createElement('div');
    card.className = 'chrome-card';
    if (downloadsLog.length === 0) {
      card.innerHTML = '<div style="color:var(--muted);font-size:13px">Chưa có tệp nào được tải xuống. Bạn có thể lưu trang HTML bất kỳ từ menu ⋮ hoặc nhập URL ở trên.</div>';
    } else {
      for (const d of downloadsLog) {
        const row = document.createElement('div');
        row.className = 'chrome-setting-row';
        row.innerHTML = `<span><strong>${escapeHtml(d.filename)}</strong><br><small style="color:var(--muted)">${escapeHtml(d.url)}</small></span><small style="color:var(--muted)">${new Date(d.time).toLocaleTimeString()}</small>`;
        card.appendChild(row);
      }
    }
    inner.append(dlForm, card);
  } else if (chromeUrl.startsWith('chrome://settings')) {
    tab.title = 'Cài đặt';
    inner.innerHTML = `<h1>Cài đặt Chromium (chrome://settings)</h1>`;
    const card = document.createElement('div');
    card.className = 'chrome-card';

    card.innerHTML = `
      <div class="chrome-setting-row">
        <span><strong>Công cụ tìm kiếm mặc định trên Omnibox</strong></span>
        <select id="set-engine">
          <option value="ddg">DuckDuckGo</option>
          <option value="bing">Bing</option>
          <option value="wiki">Wikipedia</option>
          <option value="google">Google (Light)</option>
        </select>
      </div>
      <div class="chrome-setting-row">
        <span><strong>Giao diện Chromium</strong></span>
        <button id="set-theme-btn" class="secondary-btn" type="button">${theme === 'dark' ? 'Đang dùng: Tối (Đổi sang Sáng)' : 'Đang dùng: Sáng (Đổi sang Tối)'}</button>
      </div>
      <div class="chrome-setting-row">
        <span><strong>Always Focus &amp; Visible (0 / 0)</strong></span>
        <button id="set-focus-btn" class="secondary-btn" type="button">${alwaysFocusEnabled ? 'Đang bật (ON)' : 'Đang tắt (OFF)'}</button>
      </div>
      <div class="chrome-setting-row">
        <span><strong>User-Agent Chrome giả lập</strong></span>
        <button id="set-ua-btn" class="secondary-btn" type="button">${currentProfile === 'desktop' ? 'Chrome 131 Windows' : 'Chrome 131 Android'}</button>
      </div>
      <div class="chrome-setting-row">
        <span><strong>Hiển thị thanh dấu trang</strong></span>
        <button id="set-bm-btn" class="secondary-btn" type="button">${bookmarksVisible ? 'Đang bật' : 'Đang tắt'}</button>
      </div>
      <div class="chrome-setting-row">
        <span><strong>Xóa cookie phiên proxy (${cookiesCount})</strong></span>
        <button id="set-cookies-btn" class="secondary-btn" type="button">Xóa Cookies</button>
      </div>
    `;

    const sel = card.querySelector('#set-engine');
    sel.value = defaultSearchEngine;
    sel.addEventListener('change', () => {
      defaultSearchEngine = sel.value;
      saveJsonStorage(STORAGE_SEARCH_ENGINE, defaultSearchEngine);
    });
    card.querySelector('#set-theme-btn').addEventListener('click', () => {
      applyTheme(theme === 'dark' ? 'light' : 'dark');
      renderChromeInternalPage(paneEl, tab, chromeUrl);
    });
    card.querySelector('#set-focus-btn').addEventListener('click', () => {
      toggleAlwaysFocus();
      renderChromeInternalPage(paneEl, tab, chromeUrl);
    });
    card.querySelector('#set-ua-btn').addEventListener('click', async () => {
      await toggleChromeProfile();
      renderChromeInternalPage(paneEl, tab, chromeUrl);
    });
    card.querySelector('#set-bm-btn').addEventListener('click', () => {
      applyBookmarksVisibility(!bookmarksVisible);
      renderChromeInternalPage(paneEl, tab, chromeUrl);
    });
    card.querySelector('#set-cookies-btn').addEventListener('click', async () => {
      await handleClearCookies();
      renderChromeInternalPage(paneEl, tab, chromeUrl);
    });

    inner.appendChild(card);
  } else {
    tab.title = 'Thông tin Chromium & Flags';
    inner.innerHTML = `
      <h1>Chromium 131.0.0.0 (Proxy Engine 11643)</h1>
      <div class="chrome-card">
        <div class="chrome-setting-row"><span><strong>Bind &amp; Port</strong></span><span>0.0.0.0:11643</span></div>
        <div class="chrome-setting-row"><span><strong>User-Agent giả lập</strong></span><span>${currentProfile === 'desktop' ? 'Chrome 131 Windows (Win32)' : 'Chrome 131 Android (Pixel 8 Pro)'}</span></div>
        <div class="chrome-setting-row"><span><strong>Proxy Routing</strong></span><span>/b/&lt;base64url&gt; + Referer SPA Fallback + /proxy-ws</span></div>
        <div class="chrome-setting-row"><span><strong>Always Focus</strong></span><span>${alwaysFocusEnabled ? 'ON (Focus/Blur = 0/0)' : 'OFF'}</span></div>
        <div class="chrome-setting-row"><span><strong>Virtual Fullscreen</strong></span><span>Scoped inside localhost:11643</span></div>
        <div class="chrome-setting-row"><span><strong>Cookie Jar</strong></span><span>${cookiesCount} cookies</span></div>
      </div>
    `;
  }

  page.appendChild(inner);
  paneEl.appendChild(page);
  renderTabs();
  if (tab.id === activeTabId) syncToolbarState();
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function triggerDownloadUrl(targetUrl, suggestedName = '') {
  const proxyUrl = buildProxyPath(targetUrl, 'normal');
  const a = document.createElement('a');
  a.href = proxyUrl;
  const fallbackName =
    suggestedName || targetUrl.replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 48) + '.html';
  a.download = fallbackName;
  document.body.appendChild(a);
  a.click();
  a.remove();

  downloadsLog.unshift({
    filename: fallbackName,
    url: targetUrl,
    time: new Date().toISOString()
  });
  downloadsLog = downloadsLog.slice(0, 40);
  saveJsonStorage(STORAGE_DOWNLOADS, downloadsLog);
}

// ---------------------------------------------------------------------------
// Chrome New Tab Page (1:1 NTP)
// ---------------------------------------------------------------------------
function renderStartPageInto(paneEl, tab) {
  paneEl.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'start-page';

  const topLinks = document.createElement('div');
  topLinks.className = 'ntp-top-links';
  topLinks.innerHTML = `
    <button class="ntp-top-link" type="button" id="ntp-hist-link">Lịch sử</button>
    <button class="ntp-top-link" type="button" id="ntp-set-link">Cài đặt</button>
    <a class="ntp-top-link" href="/console" target="_blank">Console</a>
    <button class="ntp-apps-btn" type="button" title="Mở nhiều trang web cùng lúc">
      <svg viewBox="0 0 20 20" width="18" height="18" fill="currentColor">
        <circle cx="4.5" cy="4.5" r="1.5"/><circle cx="10" cy="4.5" r="1.5"/><circle cx="15.5" cy="4.5" r="1.5"/>
        <circle cx="4.5" cy="10" r="1.5"/><circle cx="10" cy="10" r="1.5"/><circle cx="15.5" cy="10" r="1.5"/>
        <circle cx="4.5" cy="15.5" r="1.5"/><circle cx="10" cy="15.5" r="1.5"/><circle cx="15.5" cy="15.5" r="1.5"/>
      </svg>
    </button>
  `;
  topLinks.querySelector('#ntp-hist-link').addEventListener('click', () => navigateTab(tab.id, 'chrome://history'));
  topLinks.querySelector('#ntp-set-link').addEventListener('click', () => navigateTab(tab.id, 'chrome://settings'));
  topLinks.querySelector('.ntp-apps-btn').addEventListener('click', () => multiModal.classList.remove('hidden'));

  const inner = document.createElement('div');
  inner.className = 'start-inner';

  const logo = document.createElement('div');
  logo.className = 'ntp-logo';
  logo.innerHTML = `<div class="ntp-wordmark">${tab.incognito ? 'Ẩn danh' : 'Google'}</div>`;

  const searchForm = document.createElement('form');
  searchForm.className = 'start-search-form';

  const searchIcon = document.createElement('span');
  searchIcon.style.color = 'var(--muted)';
  searchIcon.style.display = 'grid';
  searchIcon.innerHTML =
    '<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M11.74 10.33a6 6 0 1 0-1.41 1.41l3.46 3.47a1 1 0 0 0 1.42-1.42l-3.47-3.46zM6.5 11a4.5 4.5 0 1 1 0-9 4.5 4.5 0 0 1 0 9z"/></svg>';

  const searchInput = document.createElement('input');
  searchInput.type = 'text';
  searchInput.placeholder = 'Tìm kiếm trên Google hoặc nhập một URL';

  const engineSelect = document.createElement('select');
  engineSelect.innerHTML = `
    <option value="ddg">DuckDuckGo</option>
    <option value="bing">Bing</option>
    <option value="wiki">Wikipedia</option>
    <option value="google">Google (Light)</option>
  `;
  engineSelect.value = defaultSearchEngine;

  searchForm.append(searchIcon, searchInput, engineSelect);
  searchForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const target = normalizeInputToUrl(searchInput.value, engineSelect.value);
    if (target) navigateTab(tab.id, target);
  });

  const tilesGrid = document.createElement('div');
  tilesGrid.className = 'ntp-tiles';

  for (const site of DEFAULT_SITES) {
    const tile = document.createElement('div');
    tile.className = 'ntp-tile';
    tile.title = site.url;

    const circle = document.createElement('div');
    circle.className = 'ntp-tile-circle';
    circle.textContent = site.letter || site.name[0];

    const label = document.createElement('div');
    label.className = 'ntp-tile-label';
    label.textContent = site.name;

    const newTabBtnTile = document.createElement('button');
    newTabBtnTile.type = 'button';
    newTabBtnTile.className = 'ntp-tile-newtab';
    newTabBtnTile.textContent = '+';
    newTabBtnTile.title = 'Mở trong thẻ mới';
    newTabBtnTile.addEventListener('click', (e) => {
      e.stopPropagation();
      createTab(site.url, true);
    });

    tile.addEventListener('click', (e) => {
      if (e.ctrlKey || e.metaKey) createTab(site.url, true);
      else navigateTab(tab.id, site.url);
    });

    tile.append(newTabBtnTile, circle, label);
    tilesGrid.appendChild(tile);
  }

  inner.append(logo, searchForm, tilesGrid);

  if (historyLog.length > 0 && !tab.incognito) {
    const histTitle = document.createElement('div');
    histTitle.className = 'section-title';
    histTitle.textContent = 'Truy cập gần đây';

    const histList = document.createElement('div');
    histList.className = 'history-list';

    for (const h of historyLog.slice(0, 5)) {
      const row = document.createElement('div');
      row.className = 'history-row';
      const t = document.createElement('span');
      t.textContent = h.title || h.url;
      const u = document.createElement('span');
      u.className = 'history-url';
      u.textContent = h.url;
      row.append(t, u);
      row.addEventListener('click', () => navigateTab(tab.id, h.url));
      histList.appendChild(row);
    }

    inner.append(histTitle, histList);
  }

  const customizeBtn = document.createElement('button');
  customizeBtn.type = 'button';
  customizeBtn.className = 'ntp-customize-btn';
  customizeBtn.textContent = '✎ Tùy chỉnh Chrome';
  customizeBtn.addEventListener('click', () => {
    applyTheme(theme === 'dark' ? 'light' : 'dark');
  });

  wrap.append(topLinks, inner, customizeBtn);
  paneEl.appendChild(wrap);
}

function ensureIframe(tab) {
  if (tab.iframe) return tab.iframe;

  tab.paneEl.innerHTML = '';
  const iframe = document.createElement('iframe');
  iframe.className = 'proxy-frame';
  iframe.name = tab.id;
  iframe.setAttribute(
    'sandbox',
    'allow-forms allow-modals allow-popups allow-popups-to-escape-sandbox allow-same-origin allow-scripts'
  );
  iframe.addEventListener('load', () => {
    tab.loading = false;
    try {
      iframe.contentWindow?.postMessage({ type: 'proxy:always-focus', enabled: alwaysFocusEnabled }, '*');
      iframe.contentWindow?.postMessage({ type: 'proxy:mute', muted: Boolean(tab.muted) }, '*');
    } catch {}
    refreshProxyStats();
    renderTabs();
  });

  tab.paneEl.appendChild(iframe);
  tab.iframe = iframe;
  applyZoomToAllIframes();
  return iframe;
}

function createTab(initialUrl = '', activate = true, mode = 'normal', opts = {}) {
  const id = `tab-${++tabSeq}`;
  const paneEl = document.createElement('div');
  paneEl.className = 'tab-pane';
  paneEl.dataset.tabId = id;
  viewport.appendChild(paneEl);

  const tab = {
    id,
    title: initialUrl ? initialUrl : opts.incognito ? 'Thẻ ẩn danh' : 'Thẻ mới',
    url: '',
    mode,
    favicon: '',
    loading: false,
    pinned: Boolean(opts.pinned),
    muted: Boolean(opts.muted),
    incognito: Boolean(opts.incognito),
    group: opts.group || null,
    paneEl,
    iframe: null,
    history: [''],
    historyIndex: 0
  };

  tabs.push(tab);

  if (initialUrl) {
    navigateTab(id, initialUrl, mode);
  } else {
    renderStartPageInto(paneEl, tab);
  }

  if (activate || tabs.length === 1) {
    switchTab(id);
  } else {
    updateSplitLayout();
    renderTabs();
  }
  return tab;
}

function switchTab(tabId) {
  activeTabId = tabId;
  updateSplitLayout();
  renderTabs();
  syncToolbarState();
}

function closeTab(tabId) {
  const idx = tabs.findIndex((t) => t.id === tabId);
  if (idx === -1) return;

  const [removed] = tabs.splice(idx, 1);
  if (removed.url && !removed.incognito) {
    closedTabsStack.push({ url: removed.url, mode: removed.mode, title: removed.title });
    if (closedTabsStack.length > 25) closedTabsStack.shift();
  }
  removed.paneEl.remove();

  if (tabs.length === 0) {
    splitViewEnabled = false;
    createTab('', true);
    return;
  }

  if (splitSecondaryTabId === tabId) {
    splitSecondaryTabId = null;
  }

  if (activeTabId === tabId) {
    const next = tabs[Math.min(idx, tabs.length - 1)];
    switchTab(next.id);
  } else {
    updateSplitLayout();
    renderTabs();
  }
}

function reopenLastClosedTab() {
  const last = closedTabsStack.pop();
  if (last) createTab(last.url, true, last.mode || 'normal');
}

function loadUrlInTab(tab, targetUrl, recordHistory = true, mode = tab.mode || 'normal') {
  tab.mode = mode;
  if (!targetUrl) {
    tab.url = '';
    tab.title = tab.incognito ? 'Thẻ ẩn danh' : 'Thẻ mới';
    tab.favicon = '';
    tab.loading = false;
    tab.iframe = null;
    if (recordHistory) {
      tab.history = tab.history.slice(0, tab.historyIndex + 1);
      tab.history.push('');
      tab.historyIndex = tab.history.length - 1;
    }
    renderStartPageInto(tab.paneEl, tab);
    renderTabs();
    if (tab.id === activeTabId) syncToolbarState();
    return;
  }

  tab.url = targetUrl;
  if (recordHistory) {
    tab.history = tab.history.slice(0, tab.historyIndex + 1);
    tab.history.push(targetUrl);
    tab.historyIndex = tab.history.length - 1;
  }

  if (targetUrl.startsWith('chrome://')) {
    renderChromeInternalPage(tab.paneEl, tab, targetUrl);
    return;
  }

  tab.title = targetUrl.replace(/^https?:\/\//i, '').split('/')[0] || targetUrl;
  tab.loading = true;

  const iframe = ensureIframe(tab);
  iframe.src = buildProxyPath(targetUrl, tab.mode);
  addHistoryEntry(targetUrl, tab.title, tab.incognito);

  renderTabs();
  if (tab.id === activeTabId) syncToolbarState();
}

function navigateTab(tabId, targetUrl, mode = 'normal') {
  const tab = tabs.find((t) => t.id === tabId);
  if (!tab) return;
  loadUrlInTab(tab, targetUrl, true, mode);
}

function navigateActiveOrNew(targetUrl) {
  const tab = getActiveTab();
  if (!tab) createTab(targetUrl, true);
  else navigateTab(tab.id, targetUrl, tab.mode || 'normal');
}

function openMultipleTabs(urls) {
  const cleaned = urls.map((u) => normalizeInputToUrl(u)).filter(Boolean);
  if (cleaned.length === 0) return;

  let firstNewId = null;
  for (const url of cleaned) {
    const active = getActiveTab();
    if (active && !active.url && firstNewId === null) {
      navigateTab(active.id, url);
      firstNewId = active.id;
    } else {
      const created = createTab(url, false);
      if (firstNewId === null) firstNewId = created.id;
    }
  }
  if (firstNewId) switchTab(firstNewId);
}

// ---------------------------------------------------------------------------
// Virtual Fullscreen (scoped ONLY inside localhost:11643)
// ---------------------------------------------------------------------------
function setVirtualFullscreen(active, notifyChildren = false) {
  virtualFullscreenActive = Boolean(active);
  browserAppEl.classList.toggle('virtual-fullscreen', virtualFullscreenActive);
  exitVfsBtn.classList.toggle('hidden', !virtualFullscreenActive);
  if (!virtualFullscreenActive && notifyChildren) {
    for (const tab of tabs) {
      try {
        tab.iframe?.contentWindow?.postMessage({ type: 'proxy:exit-virtual-fullscreen' }, '*');
      } catch {}
    }
  }
}

['requestFullscreen', 'webkitRequestFullscreen', 'mozRequestFullScreen', 'msRequestFullscreen'].forEach((fnName) => {
  try {
    Element.prototype[fnName] = function () {
      setVirtualFullscreen(true);
      return Promise.resolve();
    };
  } catch {}
});

// ---------------------------------------------------------------------------
// DevTools, Find-in-Page & Message Bridge
// ---------------------------------------------------------------------------
function appendDevToolsLog(container, level, text) {
  const row = document.createElement('div');
  row.className = `dt-log-row ${level || 'log'}`;
  row.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  container.appendChild(row);
  while (container.childElementCount > 150) {
    container.firstElementChild.remove();
  }
  container.scrollTop = container.scrollHeight;
}

window.addEventListener('message', (event) => {
  const data = event.data;
  if (!data || typeof data !== 'object') return;

  // Only trust messages sent by one of our own proxy iframes. Pages loaded inside
  // the proxy are untrusted and must not be able to drive the browser shell.
  const sourceTab = tabs.find((t) => t.iframe && t.iframe.contentWindow === event.source) || null;
  if (!sourceTab) return;

  if (data.type === 'proxy:virtual-fullscreen') {
    if (data.active && sourceTab.id !== activeTabId) {
      switchTab(sourceTab.id);
    }
    setVirtualFullscreen(Boolean(data.active), false);
    return;
  }

  if (data.type === 'proxy:open-tab' && typeof data.url === 'string') {
    let safe = false;
    try {
      const parsed = new URL(data.url);
      safe = parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      safe = false;
    }
    if (safe) createTab(data.url, true);
    return;
  }

  if (data.type === 'proxy:devtools-console') {
    appendDevToolsLog(dtConsoleLogs, data.level, data.text);
    return;
  }

  if (data.type === 'proxy:devtools-network') {
    appendDevToolsLog(
      dtNetworkLogs,
      String(data.status).startsWith('4') || String(data.status).startsWith('5') || data.status === 'ERR' ? 'error' : 'log',
      `${data.method} ${data.status} (${data.ms}ms) ${data.url}`
    );
    return;
  }

  if (data.type === 'proxy:inspect-result') {
    dtElementsView.textContent = data.html || '(Trống)';
    dtStorageView.textContent =
      `URL: ${data.url}\nTitle: ${data.title}\n\n--- Document Cookies ---\n${data.cookies || '(Không có)'}\n\n--- LocalStorage ---\n${JSON.stringify(data.localStorage || {}, null, 2)}`;
    return;
  }

  if (data.type === 'proxy:find-result') {
    findCount.textContent = data.query ? `${data.found ? '✓' : '0'}/${data.total}` : '0/0';
    return;
  }

  if (data.type === 'proxy:state') {
    const tab = sourceTab;

    if (data.url && data.url !== tab.url) {
      tab.url = data.url;
      tab.history = tab.history.slice(0, tab.historyIndex + 1);
      tab.history.push(data.url);
      tab.historyIndex = tab.history.length - 1;
    }
    if (data.title) {
      tab.title = data.title;
      addHistoryEntry(tab.url, data.title, tab.incognito);
    }
    if (data.favicon) tab.favicon = data.favicon;
    if (data.reason === 'load' || data.reason === 'dom') tab.loading = false;

    renderTabs();
    if (tab.id === activeTabId) syncToolbarState();
  }
});

// Find-in-Page
function openFindBar() {
  findBar.classList.remove('hidden');
  findInput.focus();
  findInput.select();
}

function runFindInPage(backward = false) {
  const tab = getActiveTab();
  const q = findInput.value;
  if (!tab || !tab.iframe) {
    findCount.textContent = '0/0';
    return;
  }
  try {
    tab.iframe.contentWindow?.postMessage({ type: 'proxy:find', query: q, backward }, '*');
  } catch {}
}

findInput.addEventListener('input', () => runFindInPage(false));
findInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    runFindInPage(e.shiftKey);
  } else if (e.key === 'Escape') {
    findBar.classList.add('hidden');
  }
});
findPrev.addEventListener('click', () => runFindInPage(true));
findNext.addEventListener('click', () => runFindInPage(false));
findClose.addEventListener('click', () => findBar.classList.add('hidden'));

// Side Panel
function renderSidePanel() {
  const mode = sidePanelMode.value;
  sidePanelContent.innerHTML = '';

  if (mode === 'reading') {
    const addBtn = document.createElement('button');
    addBtn.type = 'button';
    addBtn.className = 'go-btn';
    addBtn.textContent = '+ Thêm trang hiện tại vào danh sách đọc';
    addBtn.addEventListener('click', addCurrentTabToReadingList);
    sidePanelContent.appendChild(addBtn);

    if (readingList.length === 0) {
      sidePanelContent.insertAdjacentHTML('beforeend', '<div style="color:var(--muted);font-size:12.5px">Danh sách đọc trống.</div>');
    } else {
      readingList.forEach((item, idx) => {
        const row = document.createElement('div');
        row.className = 'sp-item';
        row.innerHTML = `<span class="sp-item-title">${escapeHtml(item.title || item.url)}</span><button class="menu-mini-btn" type="button">&times;</button>`;
        row.querySelector('.sp-item-title').addEventListener('click', () => navigateActiveOrNew(item.url));
        row.querySelector('button').addEventListener('click', (e) => {
          e.stopPropagation();
          readingList.splice(idx, 1);
          saveJsonStorage(STORAGE_READING, readingList);
          renderSidePanel();
        });
        sidePanelContent.appendChild(row);
      });
    }
  } else if (mode === 'bookmarks') {
    bookmarks.forEach((bm) => {
      const row = document.createElement('div');
      row.className = 'sp-item';
      row.innerHTML = `<span class="sp-item-title">${escapeHtml(bm.name)}</span>`;
      row.addEventListener('click', () => navigateActiveOrNew(bm.url));
      sidePanelContent.appendChild(row);
    });
  } else if (mode === 'history') {
    historyLog.slice(0, 30).forEach((h) => {
      const row = document.createElement('div');
      row.className = 'sp-item';
      row.innerHTML = `<span class="sp-item-title">${escapeHtml(h.title || h.url)}</span>`;
      row.addEventListener('click', () => navigateActiveOrNew(h.url));
      sidePanelContent.appendChild(row);
    });
  } else if (mode === 'notes') {
    const ta = document.createElement('textarea');
    ta.className = 'sp-notes-area';
    ta.placeholder = 'Ghi chú nhanh được lưu tự động...';
    ta.value = loadJsonStorage(STORAGE_NOTES, '');
    ta.addEventListener('input', () => saveJsonStorage(STORAGE_NOTES, ta.value));
    sidePanelContent.appendChild(ta);
  }
}

function addCurrentTabToReadingList() {
  const tab = getActiveTab();
  if (!tab || !tab.url || tab.url.startsWith('chrome://')) return;
  if (!readingList.some((r) => r.url === tab.url)) {
    readingList.unshift({ title: tab.title || tab.url, url: tab.url });
    saveJsonStorage(STORAGE_READING, readingList);
  }
  sidePanel.classList.remove('hidden');
  sidePanelMode.value = 'reading';
  renderSidePanel();
}

btnSidePanel.addEventListener('click', () => {
  sidePanel.classList.toggle('hidden');
  if (!sidePanel.classList.contains('hidden')) renderSidePanel();
});
sidePanelMode.addEventListener('change', renderSidePanel);
closeSidePanel.addEventListener('click', () => sidePanel.classList.add('hidden'));

// DevTools Dock
function toggleDevTools(forceOpen = null) {
  const shouldOpen = forceOpen !== null ? forceOpen : devtoolsPanel.classList.contains('hidden');
  devtoolsPanel.classList.toggle('hidden', !shouldOpen);
  if (shouldOpen) requestDevToolsInspect();
}

function requestDevToolsInspect() {
  const tab = getActiveTab();
  if (!tab || !tab.iframe) return;
  try {
    tab.iframe.contentWindow?.postMessage({ type: 'proxy:inspect' }, '*');
  } catch {}
}

dtTabs.forEach((btn) => {
  btn.addEventListener('click', () => {
    dtTabs.forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.dt-pane').forEach((p) => p.classList.remove('active'));
    document.getElementById(`dt-pane-${btn.dataset.dt}`)?.classList.add('active');
    if (btn.dataset.dt === 'elements' || btn.dataset.dt === 'storage') {
      requestDevToolsInspect();
    }
  });
});

dtRefreshBtn.addEventListener('click', requestDevToolsInspect);
dtClearBtn.addEventListener('click', () => {
  dtConsoleLogs.innerHTML = '';
  dtNetworkLogs.innerHTML = '';
});
dtCloseBtn.addEventListener('click', () => devtoolsPanel.classList.add('hidden'));
dtEvalForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const code = dtEvalInput.value.trim();
  if (!code) return;
  appendDevToolsLog(dtConsoleLogs, 'log', `> ${code}`);
  dtEvalInput.value = '';
  const tab = getActiveTab();
  if (tab && tab.iframe) {
    try {
      tab.iframe.contentWindow?.postMessage({ type: 'proxy:eval', code }, '*');
    } catch {}
  }
});

// ---------------------------------------------------------------------------
// Omnibox Autocomplete Dropdown
// ---------------------------------------------------------------------------
function renderOmniboxSuggestions(raw) {
  const q = (raw || '').trim().toLowerCase();
  if (!q) {
    omniboxDropdown.classList.add('hidden');
    return;
  }

  const suggestions = [];
  for (const cu of CHROME_INTERNAL_URLS) {
    if (cu.includes(q)) suggestions.push({ label: cu, sub: 'Trang nội bộ Chrome', url: cu });
  }
  for (const t of tabs) {
    if (t.url && ((t.title || '').toLowerCase().includes(q) || t.url.toLowerCase().includes(q))) {
      suggestions.push({ label: t.title || t.url, sub: `Chuyển tới thẻ · ${t.url}`, switchTabId: t.id });
    }
  }
  for (const b of bookmarks) {
    if (b.name.toLowerCase().includes(q) || b.url.toLowerCase().includes(q)) {
      suggestions.push({ label: b.name, sub: `Dấu trang · ${b.url}`, url: b.url });
    }
  }
  for (const h of historyLog) {
    if ((h.title || '').toLowerCase().includes(q) || h.url.toLowerCase().includes(q)) {
      if (!suggestions.some((s) => s.url === h.url)) {
        suggestions.push({ label: h.title || h.url, sub: h.url, url: h.url });
      }
    }
  }

  const direct = normalizeInputToUrl(raw, defaultSearchEngine);
  if (direct) {
    suggestions.unshift({
      label: raw.trim(),
      sub: `Truy cập / Tìm kiếm với ${(SEARCH_ENGINES[defaultSearchEngine] || SEARCH_ENGINES.ddg).label}`,
      url: direct
    });
  }

  omniboxDropdown.innerHTML = '';
  for (const item of suggestions.slice(0, 8)) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'omni-item';
    btn.innerHTML = `<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(item.label)}</span><span class="omni-item-sub">${escapeHtml(item.sub)}</span>`;
    btn.addEventListener('mousedown', (e) => {
      e.preventDefault();
      omniboxDropdown.classList.add('hidden');
      if (item.switchTabId) switchTab(item.switchTabId);
      else if (item.url) navigateActiveOrNew(item.url);
    });
    omniboxDropdown.appendChild(btn);
  }
  omniboxDropdown.classList.toggle('hidden', suggestions.length === 0);
}

omniboxInput.addEventListener('input', () => renderOmniboxSuggestions(omniboxInput.value));
omniboxInput.addEventListener('focus', () => omniboxInput.select());
omniboxInput.addEventListener('blur', () => {
  setTimeout(() => omniboxDropdown.classList.add('hidden'), 150);
});

// ---------------------------------------------------------------------------
// Tab Context Menu & Popovers
// ---------------------------------------------------------------------------
function closeAllPopovers() {
  chromeMenu.classList.add('hidden');
  extensionsPopover.classList.add('hidden');
  siteInfoPopover.classList.add('hidden');
  tabSearchPopover.classList.add('hidden');
  tabContextMenu.classList.add('hidden');
}

function openTabContextMenu(tab, x, y) {
  closeAllPopovers();
  contextTabId = tab.id;
  ctxPin.querySelector('span').textContent = tab.pinned ? 'Bỏ ghim thẻ' : 'Ghim thẻ';
  ctxMute.querySelector('span').textContent = tab.muted ? 'Bật tiếng trang web' : 'Tắt tiếng trang web';
  tabContextMenu.style.left = `${Math.min(x, window.innerWidth - 260)}px`;
  tabContextMenu.style.top = `${Math.min(y, window.innerHeight - 320)}px`;
  tabContextMenu.classList.remove('hidden');
}

ctxReload.addEventListener('click', () => {
  closeAllPopovers();
  const tab = tabs.find((t) => t.id === contextTabId);
  if (tab && tab.url) loadUrlInTab(tab, tab.url, false, tab.mode);
});
ctxDuplicate.addEventListener('click', () => {
  closeAllPopovers();
  const tab = tabs.find((t) => t.id === contextTabId);
  if (tab) createTab(tab.url, true, tab.mode, { incognito: tab.incognito });
});
ctxPin.addEventListener('click', () => {
  closeAllPopovers();
  const tab = tabs.find((t) => t.id === contextTabId);
  if (tab) {
    tab.pinned = !tab.pinned;
    renderTabs();
  }
});
ctxMute.addEventListener('click', () => {
  closeAllPopovers();
  const tab = tabs.find((t) => t.id === contextTabId);
  if (tab) {
    tab.muted = !tab.muted;
    try {
      tab.iframe?.contentWindow?.postMessage({ type: 'proxy:mute', muted: tab.muted }, '*');
    } catch {}
    renderTabs();
  }
});
ctxGroup.addEventListener('click', () => {
  closeAllPopovers();
  const tab = tabs.find((t) => t.id === contextTabId);
  if (!tab) return;
  const idx = tab.group ? (tab.group.colorIdx + 1) % GROUP_COLORS.length : ++groupSeq % GROUP_COLORS.length;
  const preset = GROUP_COLORS[idx];
  tab.group = { id: tab.group?.id || `grp-${groupSeq}`, name: `Nhóm ${idx + 1}`, color: preset.color, colorIdx: idx };
  renderTabs();
});
ctxUngroup.addEventListener('click', () => {
  closeAllPopovers();
  const tab = tabs.find((t) => t.id === contextTabId);
  if (tab) {
    tab.group = null;
    renderTabs();
  }
});
ctxClose.addEventListener('click', () => {
  closeAllPopovers();
  if (contextTabId) closeTab(contextTabId);
});
ctxCloseOthers.addEventListener('click', () => {
  closeAllPopovers();
  const keep = tabs.filter((t) => t.id === contextTabId || t.pinned).map((t) => t.id);
  for (const t of [...tabs]) {
    if (!keep.includes(t.id)) closeTab(t.id);
  }
});
ctxCloseRight.addEventListener('click', () => {
  closeAllPopovers();
  const idx = tabs.findIndex((t) => t.id === contextTabId);
  if (idx === -1) return;
  const toClose = tabs.slice(idx + 1).filter((t) => !t.pinned).map((t) => t.id);
  toClose.forEach(closeTab);
});
ctxReopen.addEventListener('click', () => {
  closeAllPopovers();
  reopenLastClosedTab();
});

document.addEventListener('click', (e) => {
  if (
    !chromeMenu.contains(e.target) &&
    !btnChromeMenu.contains(e.target) &&
    !extensionsPopover.contains(e.target) &&
    !btnExtensions.contains(e.target) &&
    !siteInfoPopover.contains(e.target) &&
    !btnSiteInfo.contains(e.target) &&
    !tabSearchPopover.contains(e.target) &&
    !btnTabSearch.contains(e.target) &&
    !tabContextMenu.contains(e.target)
  ) {
    closeAllPopovers();
  }
});

btnChromeMenu.addEventListener('click', (e) => {
  e.stopPropagation();
  const isHidden = chromeMenu.classList.contains('hidden');
  closeAllPopovers();
  if (isHidden) chromeMenu.classList.remove('hidden');
});

btnExtensions.addEventListener('click', (e) => {
  e.stopPropagation();
  const isHidden = extensionsPopover.classList.contains('hidden');
  closeAllPopovers();
  if (isHidden) extensionsPopover.classList.remove('hidden');
});

btnSiteInfo.addEventListener('click', (e) => {
  e.stopPropagation();
  const isHidden = siteInfoPopover.classList.contains('hidden');
  closeAllPopovers();
  if (isHidden) siteInfoPopover.classList.remove('hidden');
});

infoCopyUrl.addEventListener('click', () => {
  const tab = getActiveTab();
  if (tab && tab.url && navigator.clipboard) {
    navigator.clipboard.writeText(tab.url).catch(() => {});
  }
  closeAllPopovers();
});
infoAddReading.addEventListener('click', () => {
  closeAllPopovers();
  addCurrentTabToReadingList();
});

function renderTabSearch(query = '') {
  tabSearchList.innerHTML = '';
  const q = query.trim().toLowerCase();
  const matched = tabs.filter(
    (t) => !q || (t.title || '').toLowerCase().includes(q) || (t.url || '').toLowerCase().includes(q)
  );
  for (const t of matched) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'tab-search-item';
    item.textContent = `${t.title || 'Thẻ mới'}${t.url ? ' — ' + t.url : ''}`;
    item.addEventListener('click', () => {
      switchTab(t.id);
      closeAllPopovers();
    });
    tabSearchList.appendChild(item);
  }
}

btnTabSearch.addEventListener('click', (e) => {
  e.stopPropagation();
  const isHidden = tabSearchPopover.classList.contains('hidden');
  closeAllPopovers();
  if (isHidden) {
    tabSearchPopover.classList.remove('hidden');
    tabSearchInput.value = '';
    renderTabSearch('');
    tabSearchInput.focus();
  }
});
tabSearchInput.addEventListener('input', () => renderTabSearch(tabSearchInput.value));

// Toolbar & Menu Events
newTabBtn.addEventListener('click', () => createTab('', true));
menuNewTab.addEventListener('click', () => {
  closeAllPopovers();
  createTab('', true);
});
menuNewIncognito.addEventListener('click', () => {
  closeAllPopovers();
  createTab('', true, 'normal', { incognito: true });
});
menuReopenClosed.addEventListener('click', () => {
  closeAllPopovers();
  reopenLastClosedTab();
});

omniboxForm.addEventListener('submit', (e) => {
  e.preventDefault();
  omniboxDropdown.classList.add('hidden');
  const target = normalizeInputToUrl(omniboxInput.value, defaultSearchEngine);
  if (target) navigateActiveOrNew(target);
});

btnBack.addEventListener('click', () => {
  const tab = getActiveTab();
  if (!tab || tab.historyIndex <= 0) return;
  tab.historyIndex -= 1;
  loadUrlInTab(tab, tab.history[tab.historyIndex], false);
});

btnForward.addEventListener('click', () => {
  const tab = getActiveTab();
  if (!tab || tab.historyIndex >= tab.history.length - 1) return;
  tab.historyIndex += 1;
  loadUrlInTab(tab, tab.history[tab.historyIndex], false);
});

btnReload.addEventListener('click', () => {
  const tab = getActiveTab();
  if (!tab) return;
  if (tab.url) loadUrlInTab(tab, tab.url, false, tab.mode);
  else renderStartPageInto(tab.paneEl, tab);
});

function toggleReaderMode() {
  const tab = getActiveTab();
  if (!tab || !tab.url || tab.url.startsWith('chrome://')) return;
  const nextMode = tab.mode === 'reader' ? 'normal' : 'reader';
  loadUrlInTab(tab, tab.url, false, nextMode);
}

btnReaderMode.addEventListener('click', toggleReaderMode);
menuToggleReader.addEventListener('click', () => {
  closeAllPopovers();
  toggleReaderMode();
});
extReaderMode.addEventListener('click', () => {
  closeAllPopovers();
  toggleReaderMode();
});

function toggleSplitView() {
  if (!splitViewEnabled && tabs.length < 2) createTab('', false);
  splitViewEnabled = !splitViewEnabled;
  updateSplitLayout();
  renderTabs();
}
menuToggleSplit.addEventListener('click', toggleSplitView);
extSplitView.addEventListener('click', toggleSplitView);

btnToggleToolbar.addEventListener('click', toggleToolbarVisibility);
btnToggleToolbarStrip.addEventListener('click', toggleToolbarVisibility);
btnCaptionMin.addEventListener('click', toggleToolbarVisibility);
menuToggleToolbar.addEventListener('click', () => {
  closeAllPopovers();
  toggleToolbarVisibility();
});

btnCaptionMax.addEventListener('click', () => setVirtualFullscreen(!virtualFullscreenActive, true));
btnVirtualFullscreen.addEventListener('click', () => {
  closeAllPopovers();
  setVirtualFullscreen(!virtualFullscreenActive, true);
});
exitVfsBtn.addEventListener('click', () => setVirtualFullscreen(false, true));
btnCaptionClose.addEventListener('click', () => {
  if (activeTabId) closeTab(activeTabId);
});

btnZoomOut.addEventListener('click', () => {
  zoomPercent = Math.max(60, zoomPercent - 10);
  applyZoomToAllIframes();
});
btnZoomIn.addEventListener('click', () => {
  zoomPercent = Math.min(200, zoomPercent + 10);
  applyZoomToAllIframes();
});

btnBookmark.addEventListener('click', () => {
  const tab = getActiveTab();
  if (!tab || !tab.url) return;
  const existsIdx = bookmarks.findIndex((b) => b.url === tab.url);
  if (existsIdx >= 0) bookmarks.splice(existsIdx, 1);
  else bookmarks.push({ name: (tab.title || tab.url).slice(0, 22), url: tab.url });
  saveJsonStorage(STORAGE_BOOKMARKS, bookmarks);
  renderBookmarksBar();
  syncToolbarState();
});

menuHistory.addEventListener('click', () => {
  closeAllPopovers();
  createTab('chrome://history', true);
});
menuDownloads.addEventListener('click', () => {
  closeAllPopovers();
  createTab('chrome://downloads', true);
});
menuBookmarksMgr.addEventListener('click', () => {
  closeAllPopovers();
  createTab('chrome://bookmarks', true);
});
menuSettings.addEventListener('click', () => {
  closeAllPopovers();
  createTab('chrome://settings', true);
});

menuFind.addEventListener('click', () => {
  closeAllPopovers();
  openFindBar();
});
menuPrint.addEventListener('click', () => {
  closeAllPopovers();
  const tab = getActiveTab();
  if (tab && tab.iframe && tab.iframe.contentWindow) {
    tab.iframe.contentWindow.postMessage({ type: 'proxy:print' }, getProxyOrigin());
  } else {
    window.print();
  }
});
menuSavePage.addEventListener('click', () => {
  closeAllPopovers();
  const tab = getActiveTab();
  if (tab && tab.url && !tab.url.startsWith('chrome://')) {
    triggerDownloadUrl(tab.url);
  }
});
menuDevtools.addEventListener('click', () => {
  closeAllPopovers();
  toggleDevTools();
});
extDevtools.addEventListener('click', () => {
  closeAllPopovers();
  toggleDevTools();
});

btnOpenExternal.addEventListener('click', () => {
  closeAllPopovers();
  const tab = getActiveTab();
  if (!tab || !tab.url || tab.url.startsWith('chrome://')) return;
  window.open(buildProxyPath(tab.url, tab.mode), '_blank', 'noopener');
});

menuMultiOpen.addEventListener('click', () => {
  closeAllPopovers();
  multiModal.classList.remove('hidden');
});
closeMultiModal.addEventListener('click', () => multiModal.classList.add('hidden'));
cancelMultiBtn.addEventListener('click', () => multiModal.classList.add('hidden'));
launchMultiBtn.addEventListener('click', () => {
  const lines = multiUrlsInput.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  multiModal.classList.add('hidden');
  openMultipleTabs(lines);
});

function updateAlwaysFocusUi() {
  menuFocusVal.textContent = alwaysFocusEnabled ? 'ON' : 'OFF';
  extFocusVal.textContent = alwaysFocusEnabled ? 'ON' : 'OFF';
  infoFocusStatus.textContent = alwaysFocusEnabled ? 'Đang bật (0/0)' : 'Đang tắt';
  for (const tab of tabs) {
    try {
      tab.iframe?.contentWindow?.postMessage({ type: 'proxy:always-focus', enabled: alwaysFocusEnabled }, '*');
    } catch {}
  }
}

function toggleAlwaysFocus() {
  alwaysFocusEnabled = !alwaysFocusEnabled;
  try {
    localStorage.setItem(STORAGE_ALWAYS_FOCUS, String(alwaysFocusEnabled));
  } catch {}
  updateAlwaysFocusUi();
}

menuToggleFocus.addEventListener('click', toggleAlwaysFocus);
extAlwaysFocus.addEventListener('click', toggleAlwaysFocus);

async function toggleChromeProfile() {
  const nextProfile = currentProfile === 'desktop' ? 'mobile' : 'desktop';
  try {
    const res = await fetch(`${getProxyOrigin()}/api/proxy/profile`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile: nextProfile })
    });
    const data = await res.json();
    currentProfile = data.profile;
    syncProfileUi();
    const tab = getActiveTab();
    if (tab && tab.url && !tab.url.startsWith('chrome://')) {
      loadUrlInTab(tab, tab.url, false, tab.mode);
    }
  } catch {}
}

function syncProfileUi() {
  const isMobile = currentProfile === 'mobile';
  menuProfileVal.textContent = isMobile ? 'Chrome Mobile' : 'Chrome Win';
  infoUaStatus.textContent = isMobile ? 'Chrome 131 · Android' : 'Chrome 131 · Windows';
  btnChromeProfile.querySelector('.avatar-circle').textContent = isMobile ? 'M' : 'C';
}

btnChromeProfile.addEventListener('click', toggleChromeProfile);
menuToggleProfile.addEventListener('click', () => {
  closeAllPopovers();
  toggleChromeProfile();
});
menuToggleTheme.addEventListener('click', () => applyTheme(theme === 'dark' ? 'light' : 'dark'));
menuToggleBookmarks.addEventListener('click', () => applyBookmarksVisibility(!bookmarksVisible));

async function handleClearCookies() {
  try {
    const res = await fetch(`${getProxyOrigin()}/api/proxy/clear-cookies`, {
      method: 'POST',
      credentials: 'include'
    });
    const data = await res.json();
    cookiesCount = data.cookiesCount || 0;
    menuCookiesVal.textContent = String(cookiesCount);
    infoCookieStatus.textContent = `${cookiesCount} cookies`;
    extCookiesSub.textContent = `${cookiesCount} cookies đang lưu`;
  } catch {}
}

btnClearCookies.addEventListener('click', handleClearCookies);
extClearCookies.addEventListener('click', handleClearCookies);

// Chromium Keyboard Shortcuts
window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (!findBar.classList.contains('hidden')) {
      findBar.classList.add('hidden');
    } else if (virtualFullscreenActive) {
      e.preventDefault();
      setVirtualFullscreen(false, true);
    }
    closeAllPopovers();
  } else if (e.key === 'F9') {
    e.preventDefault();
    toggleToolbarVisibility();
  } else if (e.key === 'F12' || (e.altKey && (e.key === 'i' || e.key === 'I'))) {
    e.preventDefault();
    toggleDevTools();
  } else if (e.altKey && e.shiftKey && (e.key === 'b' || e.key === 'B')) {
    e.preventDefault();
    applyBookmarksVisibility(!bookmarksVisible);
  } else if (e.altKey && !e.shiftKey && (e.key === 'b' || e.key === 'B')) {
    e.preventDefault();
    toggleToolbarVisibility();
  } else if (e.altKey && e.shiftKey && (e.key === 't' || e.key === 'T')) {
    e.preventDefault();
    reopenLastClosedTab();
  } else if (e.altKey && e.shiftKey && (e.key === 'n' || e.key === 'N')) {
    e.preventDefault();
    createTab('', true, 'normal', { incognito: true });
  } else if (e.altKey && (e.key === 't' || e.key === 'T')) {
    e.preventDefault();
    createTab('', true);
  } else if (e.altKey && (e.key === 'w' || e.key === 'W')) {
    e.preventDefault();
    if (activeTabId) closeTab(activeTabId);
  } else if (e.altKey && (e.key === 'l' || e.key === 'L')) {
    e.preventDefault();
    if (toolbarHidden) applyToolbarHidden(false);
    omniboxInput.focus();
    omniboxInput.select();
  } else if (e.altKey && (e.key === 'r' || e.key === 'R')) {
    e.preventDefault();
    btnReload.click();
  } else if (e.altKey && (e.key === 'f' || e.key === 'F')) {
    e.preventDefault();
    openFindBar();
  } else if (e.altKey && (e.key === 'h' || e.key === 'H')) {
    e.preventDefault();
    createTab('chrome://history', true);
  } else if (e.altKey && (e.key === 'j' || e.key === 'J')) {
    e.preventDefault();
    createTab('chrome://downloads', true);
  } else if (e.altKey && /^[1-9]$/.test(e.key)) {
    e.preventDefault();
    const num = Number.parseInt(e.key, 10);
    const target = num === 9 ? tabs[tabs.length - 1] : tabs[num - 1];
    if (target) switchTab(target.id);
  }
});

async function refreshProxyStats() {
  try {
    const res = await fetch(`${getProxyOrigin()}/api/proxy/status`, { credentials: 'include' });
    const data = await res.json();
    currentProfile = data.profile || 'desktop';
    cookiesCount = data.cookiesCount || 0;
    syncProfileUi();
    menuCookiesVal.textContent = String(cookiesCount);
    infoCookieStatus.textContent = `${cookiesCount} cookies`;
    extCookiesSub.textContent = `${cookiesCount} cookies đang lưu`;
  } catch {}
}

async function refreshServerBadge() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    netBadgeText.textContent = `${data.port}`;
  } catch {
    netBadgeText.textContent = 'off';
  }
}

applyTheme(theme);
applyBookmarksVisibility(bookmarksVisible);
applyToolbarHidden(toolbarHidden);
updateAlwaysFocusUi();
renderBookmarksBar();
createTab('', true);
refreshServerBadge();
refreshProxyStats();
