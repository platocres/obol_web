/* Kali / Linux first-visit CPU & motion hint smoke test.
 * Verifies OS detection (Kali/Linux x86_64 & ARM64 vs Windows/macOS/Android/CrOS),
 * first-visit #/start callout display & beacon ring on #obol-settings-toggle,
 * one-click "Turn Off Motion" action, "Appearance" panel handoff, route-leave
 * persistence, prefers-reduced-motion suppression, and house-style hygiene.
 */
'use strict';

var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.join(__dirname, '..', '..');
var iconsSrc = fs.readFileSync(path.join(ROOT, 'assets/ui/icons.js'), 'utf8');
var settingsSrc = fs.readFileSync(path.join(ROOT, 'assets/ui/settings.js'), 'utf8');

var passed = 0, failed = 0;
function check(cond, msg) {
  if (cond) { passed++; console.log('  [PASS] ' + msg); }
  else { failed++; console.error('  [FAIL] ' + msg); }
}

function makeClassList(owner) {
  var set = [];
  function sync() { owner.className = set.join(' '); }
  return {
    _reset: function (cls) { set = String(cls || '').split(/\s+/).filter(Boolean); },
    add: function (c) { if (set.indexOf(c) < 0) set.push(c); sync(); },
    remove: function (c) { var i = set.indexOf(c); if (i >= 0) set.splice(i, 1); sync(); },
    contains: function (c) { return set.indexOf(c) >= 0; },
    toggle: function (c, force) {
      var has = set.indexOf(c) >= 0;
      var want = force === undefined ? !has : !!force;
      if (want && !has) set.push(c);
      if (!want && has) set.splice(set.indexOf(c), 1);
      sync();
      return want;
    }
  };
}

function makeEl(tag, doc) {
  var attrs = {};
  var listeners = {};
  var el = {
    tagName: String(tag || 'div').toUpperCase(),
    id: '',
    type: '',
    hidden: false,
    textContent: '',
    value: '',
    title: '',
    dataset: {},
    style: { setProperty: function (k, v) { this[k] = v; } },
    children: [],
    parentNode: null,
    _html: '',
    _attrs: attrs,
    _listeners: listeners,
    appendChild: function (ch) { ch.parentNode = el; el.children.push(ch); return ch; },
    removeChild: function (ch) {
      var i = el.children.indexOf(ch);
      if (i >= 0) el.children.splice(i, 1);
      ch.parentNode = null;
      return ch;
    },
    setAttribute: function (k, v) {
      attrs[k] = String(v);
      if (k === 'id') el.id = String(v);
    },
    getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(attrs, k) ? attrs[k] : null; },
    removeAttribute: function (k) { delete attrs[k]; },
    hasAttribute: function (k) { return Object.prototype.hasOwnProperty.call(attrs, k); },
    addEventListener: function (ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); },
    dispatchEvent: function (evObj) {
      var list = listeners[evObj.type] || [];
      list.forEach(function (fn) { fn(evObj); });
    },
    focus: function () { if (doc) doc.activeElement = el; },
    contains: function (other) {
      var cur = other;
      while (cur) { if (cur === el) return true; cur = cur.parentNode; }
      return false;
    },
    closest: function (sel) {
      var cur = el;
      while (cur) {
        if (matchesSel(cur, sel)) return cur;
        cur = cur.parentNode;
      }
      return null;
    },
    querySelector: function (sel) {
      for (var i = 0; i < el.children.length; i++) {
        var ch = el.children[i];
        if (matchesSel(ch, sel)) return ch;
        var sub = ch.querySelector && ch.querySelector(sel);
        if (sub) return sub;
      }
      return null;
    },
    showPopover: function () { el._popoverOpen = true; },
    hidePopover: function () { el._popoverOpen = false; }
  };
  var cls = '';
  el.classList = makeClassList(el);
  Object.defineProperty(el, 'className', {
    get: function () { return cls; },
    set: function (v) { cls = String(v || ''); el.classList._reset(cls); }
  });
  Object.defineProperty(el, 'innerHTML', {
    get: function () { return el._html; },
    set: function (v) {
      el._html = String(v || '');
      el.children = [];
      // Materialize interactive buttons inside hint markup so querySelector + click delegation work in pure Node
      var btnRe = /<button\b([^>]*)>([\s\S]*?)<\/button>/gi, m;
      while ((m = btnRe.exec(el._html))) {
        var b = makeEl('button', doc);
        var attrStr = m[1];
        var am, attrRe = /([a-zA-Z0-9_-]+)(?:="([^"]*)")?/g;
        while ((am = attrRe.exec(attrStr))) {
          b.setAttribute(am[1], am[2] !== undefined ? am[2] : '');
          if (am[1] === 'class') b.className = am[2] || '';
        }
        b.textContent = m[2].replace(/<[^>]+>/g, '');
        el.appendChild(b);
      }
    }
  });
  return el;
}

function matchesSel(el, sel) {
  if (!el || !sel) return false;
  if (sel.charAt(0) === '#') return el.id === sel.slice(1);
  if (sel.charAt(0) === '.') return el.classList && el.classList.contains(sel.slice(1));
  var m = sel.match(/^\[([a-zA-Z0-9_-]+)\]$/);
  if (m) return el.hasAttribute && el.hasAttribute(m[1]);
  return false;
}

function createHarness(opts) {
  opts = opts || {};
  var store = Object.assign({}, opts.ls || {});
  var docListeners = {};
  var doc = {
    readyState: 'complete',
    activeElement: null,
    documentElement: null,
    body: null,
    createElement: function (tag) { return makeEl(tag, doc); },
    addEventListener: function (ev, fn) { (docListeners[ev] = docListeners[ev] || []).push(fn); },
    getElementById: function (id) {
      function find(node) {
        if (!node) return null;
        if (node.id === id) return node;
        for (var i = 0; i < (node.children || []).length; i++) {
          var r = find(node.children[i]);
          if (r) return r;
        }
        return null;
      }
      return find(doc.body) || find(doc.documentElement);
    }
  };
  doc.documentElement = makeEl('html', doc);
  doc.body = makeEl('body', doc);
  doc.activeElement = doc.body;
  if (opts.route) doc.documentElement.setAttribute('data-route', opts.route);

  var toasts = [];
  var backdropUpdates = 0;
  var tipsRefreshes = 0;
  function FakeHTMLElement() {}
  FakeHTMLElement.prototype.popover = 'manual';

  var sb = {
    HTMLElement: FakeHTMLElement,
    navigator: opts.navigator || {
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
      platform: 'Linux x86_64'
    },
    location: { hash: opts.hash || '' },
    localStorage: {
      getItem: function (k) { return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null; },
      setItem: function (k, v) { store[k] = String(v); },
      removeItem: function (k) { delete store[k]; }
    },
    matchMedia: function (q) {
      return { matches: !!(opts.reducedMotion && q.indexOf('prefers-reduced-motion') >= 0) };
    },
    addEventListener: function () {},
    document: doc,
    OBOL: {
      util: { toast: function (m) { toasts.push(m); } },
      backdrop: { update: function () { backdropUpdates++; } },
      tips: { refresh: function () { tipsRefreshes++; } },
      coins: { enabled: function () { return true; }, setEnabled: function () {}, updateMotion: function () {} }
    }
  };
  sb.window = sb;
  sb.globalThis = sb;
  var ctx = vm.createContext(sb);
  vm.runInContext(iconsSrc, ctx);
  vm.runInContext(settingsSrc, ctx);
  return {
    sb: sb,
    doc: doc,
    store: store,
    toasts: toasts,
    docListeners: docListeners,
    counts: function () { return { backdropUpdates: backdropUpdates, tipsRefreshes: tipsRefreshes }; }
  };
}

// 1. House style & hygiene
check(!/[\u2014\u2013]/.test(settingsSrc), 'settings.js contains no em dashes or en dashes');

// 2. OS / Platform detection matrix
(function testPlatformDetection() {
  var h = createHarness({ route: 'home' });
  var isLinux = h.sb.OBOL.settings.isLinuxClient;
  check(isLinux({ userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0', platform: 'Linux x86_64' }) === true,
    'Detects Kali Linux Firefox x86_64');
  check(isLinux({ userAgent: 'Mozilla/5.0 (Wayland; Linux aarch64; rv:128.0) Gecko/20100101 Firefox/128.0', platform: 'Linux aarch64' }) === true,
    'Detects Kali Linux ARM64 (Apple Silicon VM)');
  check(isLinux({ userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36', platform: 'Linux x86_64', userAgentData: { platform: 'Linux' } }) === true,
    'Detects Kali Linux Chromium via userAgentData.platform');
  check(isLinux({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0', platform: 'Win32' }) === false,
    'Suppresses hint on Windows');
  check(isLinux({ userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15', platform: 'MacIntel' }) === false,
    'Suppresses hint on macOS');
  check(isLinux({ userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Mobile Safari/537.36', platform: 'Linux armv8l' }) === false,
    'Suppresses hint on Android despite Linux kernel token');
  check(isLinux({ userAgent: 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36', platform: 'Linux x86_64' }) === false,
    'Suppresses hint on ChromeOS');
})();

// 3. Windows visitor on #/start does NOT see the hint
(function testWindowsSuppressed() {
  var h = createHarness({
    route: 'start',
    navigator: { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', platform: 'Win32' }
  });
  var hint = h.doc.getElementById('obol-motion-hint');
  var btn = h.doc.getElementById('obol-settings-toggle');
  check(hint && hint.hidden === true && !btn.classList.contains('is-hinting'),
    'Non-Linux visitor on #/start does not get the Kali motion hint');
})();

// 4. Kali visitor on first-time #/start sees flashy hint + beacon + one-click Turn Off Motion works
(function testKaliFirstVisitTurnOffMotion() {
  var h = createHarness({}); // route not committed yet at boot
  var hint = h.doc.getElementById('obol-motion-hint');
  var btn = h.doc.getElementById('obol-settings-toggle');
  check(hint.hidden === true, 'Hint waits until router commits the landing route');

  // Router commits #/start
  h.doc.documentElement.setAttribute('data-route', 'start');
  h.sb.OBOL.settings.syncHint('start');
  check(hint.hidden === false && hint._popoverOpen === true, 'Hint opens when Kali user lands on #/start for the first time');
  check(btn.classList.contains('is-hinting'), 'Appearance gear button gets .is-hinting beacon ring');
  check(hint.getAttribute('role') === 'dialog' && hint.getAttribute('aria-labelledby') === 'obol-motion-hint-title',
    'Hint carries role="dialog" and aria-labelledby accessibility semantics');
  var offBtn = hint.querySelector('[data-mh-off]');
  check(h.doc.activeElement === offBtn, 'Primary Turn Off Motion button receives programmatic focus');

  // Click "Turn Off Motion"
  hint.dispatchEvent({ type: 'click', target: offBtn, stopPropagation: function () {} });
  check(h.store['obol.motion'] === 'off', 'Clicking Turn Off Motion persists obol.motion=off');
  check(h.store['obol.kali-motion-hint'] === '1', 'Clicking Turn Off Motion persists hint dismissal');
  check(h.doc.documentElement.getAttribute('data-motion') === 'off', 'Clicking Turn Off Motion sets html[data-motion="off"]');
  check(hint.hidden === true && !btn.classList.contains('is-hinting'), 'Hint hides and beacon stops immediately');
  check(h.counts().backdropUpdates >= 1 && h.counts().tipsRefreshes >= 1, 'Backdrop and header tips refresh immediately when motion turns off');
  check(h.toasts.length === 1 && /low-CPU mode/i.test(h.toasts[0]), 'Confirmation toast fires when motion is turned off');

  // Re-entering #/start does not re-show
  h.sb.OBOL.settings.syncHint('start');
  check(hint.hidden === true, 'Hint does not reappear on subsequent #/start renders');
})();

// 5. Navigating away from #/start after seeing the hint marks first-visit complete; Appearance CTA opens settings panel
(function testRouteLeaveAndAppearanceHandoff() {
  var h1 = createHarness({ route: 'start' });
  var hint1 = h1.doc.getElementById('obol-motion-hint');
  check(hint1.hidden === false, 'Kali hint displays on initial #/start render');
  h1.doc.documentElement.setAttribute('data-route', 'home');
  h1.sb.OBOL.settings.syncHint('home');
  check(hint1.hidden === true && h1.store['obol.kali-motion-hint'] === '1',
    'Leaving #/start after seeing the hint hides it and records first-visit completion');

  var h2 = createHarness({ route: 'start' });
  var hint2 = h2.doc.getElementById('obol-motion-hint');
  var panel2 = h2.doc.getElementById('obol-settings-panel');
  var openBtn = hint2.querySelector('[data-mh-open]');
  hint2.dispatchEvent({ type: 'click', target: openBtn, stopPropagation: function () {} });
  check(hint2.hidden === true && panel2.hidden === false && h2.store['obol.kali-motion-hint'] === '1',
    'Clicking Appearance inside the hint dismisses the hint and opens #obol-settings-panel');

  var h3 = createHarness({ route: 'start', reducedMotion: true });
  check(h3.doc.getElementById('obol-motion-hint').hidden === true,
    'OS prefers-reduced-motion: reduce suppresses the motion hint because motion is already disabled');
})();

if (failed > 0) {
  console.error('\nFAILED: ' + failed + ' check(s) failed.');
  process.exit(1);
}
console.log('\nALL ' + passed + ' KALI MOTION HINT CHECKS PASSED.');
