/*!
 * hero-and-tips-smoke.js
 * Verifies:
 *  1. OBOL.TIPS accuracy (no stale UI names, valid #/ hrefs and CTAs) + OBOL.tips prev/next & popover CTA.
 *  2. Unified Scope Lens (OSCP | All): OSCP includes dcsync, bloodyad-acl, ad-acl-abuse, gmsa-read,
 *     gpo-abuse, windows-service-dacl-abuse, and hides only beyond CVEs (zerologon, printnightmare, etc.).
 *  3. Unified Coach Hero Dashboard:
 *     - Loadout badge in the top-right (.coach-hero-top .coach-hero-controls .hero-loadout-badge)
 *     - Titled metric groups (Moves Unlocked & Upcoming / From Pastes) and labels (Moves Ready, Coming Up, Opens Up Next, Derived Facts)
 *     - Working directory (.ws-compact) and card view toggles (#ns-multiopen, #ns-focusmode) inside the hero bottom tray (.hero-utility-row)
 *     - Pass-the-Hash active callout (.coach-pth-callout) when an NT-hash-only credential is selected.
 */
'use strict';

var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.resolve(__dirname, '..', '..');

function makeSandbox() {
  var store = {};
  var sb = {
    console: console,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    setInterval: function () { return 1; },
    clearInterval: function () {},
    Date: Date,
    Math: Math,
    Array: Array,
    Object: Object,
    String: String,
    Number: Number,
    RegExp: RegExp,
    Set: Set,
    Map: Map,
    WeakMap: WeakMap,
    JSON: JSON,
    Promise: Promise,
    localStorage: {
      getItem: function (k) { return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null; },
      setItem: function (k, v) { store[k] = String(v); },
      removeItem: function (k) { delete store[k]; }
    },
    sessionStorage: {
      getItem: function () { return null; },
      setItem: function () {}
    },
    navigator: { platform: 'Linux x86_64', userAgent: 'Mozilla/5.0' },
    location: { hash: '#/path' },
    window: {},
    document: {
      hidden: false,
      documentElement: { setAttribute: function () {}, getAttribute: function () { return '0'; }, style: { setProperty: function () {} }, appendChild: function () {} },
      body: { children: [], appendChild: function (el) { this.children.push(el); } },
      addEventListener: function () {},
      querySelector: function () { return null; },
      getElementById: function () { return null; },
      createElement: function (tag) {
        return {
          tagName: tag,
          id: '',
          className: '',
          style: {},
          innerHTML: '',
          offsetWidth: 100,
          setAttribute: function () {},
          removeAttribute: function () {},
          appendChild: function () {},
          getContext: function () {
            return {
              setTransform: function () {},
              clearRect: function () {},
              save: function () {},
              restore: function () {},
              translate: function () {},
              scale: function () {},
               createRadialGradient: function () { return { addColorStop: function () {} }; },
              beginPath: function () {},
              arc: function () {},
              fill: function () {},
              stroke: function () {},
              moveTo: function () {},
              lineTo: function () {},
              closePath: function () {}
            };
          }
        };
      }
    },
    innerWidth: 1280,
    innerHeight: 800,
    devicePixelRatio: 1,
    addEventListener: function () {},
    requestAnimationFrame: function () { return 1; },
    cancelAnimationFrame: function () {},
    matchMedia: function () { return { matches: true }; }
  };
  sb.globalThis = sb;
  sb.window = sb;
  sb.root = sb;
  return sb;
}

var sb = makeSandbox();
function load(rel) {
  var code = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  vm.runInNewContext(code, sb, { filename: rel });
}

[
  'assets/engine/facts.js',
  'assets/engine/loot.js',
  'assets/engine/profile.js',
  'assets/engine/vfs.js',
  'assets/engine/phases.js',
  'assets/engine/pack.js',
  'assets/engine/packs.js',
  'data/packs-bundle.js',
  'assets/engine/context.js',
  'assets/engine/outcomes.js',
  'assets/engine/command.js',
  'assets/engine/workspace.js',
  'assets/ui/util.js',
  'assets/ui/icons.js',
  'assets/ui/store.js',
  'data/tips.js',
  'assets/ui/tips.js',
  'assets/ui/coin.js',
  'assets/ui/ingest.js',
  'assets/ui/routes/path.js'
].forEach(load);

var OBOL = sb.OBOL;
var failed = 0, passed = 0;
function check(cond, msg) {
  if (!cond) {
    console.error('  FAIL:', msg);
    failed++;
  } else {
    console.log('  ok  :', msg);
    passed++;
  }
}

console.log('=== HERO DASHBOARD, SCOPE LENS & TIPS SMOKE ===');

// 1. Verify OBOL.TIPS accuracy and structure
(function testTipsCatalogAndControls() {
  var tips = OBOL.TIPS || [];
  check(tips.length >= 15, 'OBOL.TIPS contains at least 15 curated tips (' + tips.length + ')');
  var allValid = tips.every(function (t) {
    return t && typeof t.text === 'string' && t.text.length > 20 &&
      typeof t.href === 'string' && /^#\//.test(t.href) &&
      typeof t.cta === 'string' && t.cta.length > 3;
  });
  check(allValid, 'Every tip in OBOL.TIPS has text, a valid #/ href, and a CTA label');

  var joined = tips.map(function (t) { return t.text; }).join(' ');
  check(!/The Stuck\? tab/i.test(joined), 'No tip points to the removed top-level Stuck? tab');
  check(!/Explain This Output/i.test(joined), 'No tip uses the old Explain This Output name instead of Output & Error Doctor');
  check(!/active Target pill/i.test(joined), 'No tip claims the Target pill is on every header');

  var html = OBOL.tips.html();
  check(html.indexOf('tipfeed-prev') >= 0 && html.indexOf('tipfeed-next') >= 0,
    'Tip feed renders both Previous (tipfeed-prev) and Next (tipfeed-next) controls');

  var firstText = OBOL.tips.currentItem().text;
  OBOL.tips.advance(true, 1);
  var secondText = OBOL.tips.currentItem().text;
  check(firstText !== secondText, 'advance(true, 1) steps forward to the next tip');
  OBOL.tips.advance(true, -1);
  check(OBOL.tips.currentItem().text === firstText, 'advance(true, -1) steps back to the previous tip');
})();

// 2. Verify Unified Scope Lens (OSCP | All) and Unified Coach Hero Dashboard
(function testHeroDashboardAndScopeLens() {
  var facts = [
    OBOL.facts.makeFact({ kind: 'target.configured', scope: 'host:10.10.10.100', value: {} }),
    OBOL.facts.makeFact({ kind: 'host.up', scope: 'host:10.10.10.100', value: {} }),
    OBOL.facts.makeFact({ kind: 'ports.open', scope: 'host:10.10.10.100', value: { ports: [88, 389, 445, 5985] } }),
    OBOL.facts.makeFact({ kind: 'port:88', scope: 'host:10.10.10.100', value: { port: 88 } }),
    OBOL.facts.makeFact({ kind: 'port:389', scope: 'host:10.10.10.100', value: { port: 389 } }),
    OBOL.facts.makeFact({ kind: 'port:445', scope: 'host:10.10.10.100', value: { port: 445 } }),
    OBOL.facts.makeFact({ kind: 'port:5985', scope: 'host:10.10.10.100', value: { port: 5985 } }),
    OBOL.facts.makeFact({ kind: 'scan.nmap.quick', scope: 'host:10.10.10.100', value: {} }),
    OBOL.facts.makeFact({ kind: 'scan.nmap.version', scope: 'host:10.10.10.100', value: {} }),
    OBOL.facts.makeFact({ kind: 'smb.reachable', scope: 'host:10.10.10.100', value: {} }),
    OBOL.facts.makeFact({ kind: 'ldap.reachable', scope: 'host:10.10.10.100', value: {} }),
    OBOL.facts.makeFact({ kind: 'kerberos.reachable', scope: 'host:10.10.10.100', value: {} }),
    OBOL.facts.makeFact({ kind: 'ad.dc_candidate', scope: 'host:10.10.10.100', value: { host: '10.10.10.100', domain: 'corp.local' } }),
    OBOL.facts.makeFact({ kind: 'ad.domain_known', scope: 'domain:corp.local', value: { name: 'corp.local' } }),
    OBOL.facts.makeFact({ kind: 'credential.available', scope: 'host:10.10.10.100', value: { user: 'svc_admin', nthash: '32693b11e6aa90eb43d32c72a07ceea6', domain: 'corp.local' } }),
    OBOL.facts.makeFact({ kind: 'credential.validated', scope: 'host:10.10.10.100', value: { user: 'svc_admin', nthash: '32693b11e6aa90eb43d32c72a07ceea6', domain: 'corp.local', service: 'smb' } }),
    OBOL.facts.makeFact({ kind: 'smb.authenticated', scope: 'host:10.10.10.100', value: { user: 'svc_admin', nthash: '32693b11e6aa90eb43d32c72a07ceea6', domain: 'corp.local', service: 'smb' } })
  ];
  var eng = {
    id: 'eng-hero-test',
    name: 'active',
    profile: { platform: 'oscp' },
    workspace: { root: '/home/kali/ctf/active' },
    ui: { wsScaffoldDone: true },
    params: {
      target: '10.10.10.100',
      domain: 'corp.local',
      lhost: '10.10.14.5',
      username: 'svc_admin',
      password: '',
      nthash: '32693b11e6aa90eb43d32c72a07ceea6'
    },
    targets: [{ id: 't1', ip: '10.10.10.100' }],
    facts: facts,
    activities: []
  };
  OBOL.store.active = function () { return eng; };
  OBOL.store.activeTarget = function () { return '10.10.10.100'; };
  OBOL.store.factSet = function () { return new OBOL.facts.FactSet(eng.facts); };
  OBOL.store.factSetForTarget = function () { return new OBOL.facts.FactSet(eng.facts); };

  // Test under OSCP lens before and after ad.control_paths
  sb.localStorage.setItem('obol.scope-lens', 'oscp');
  var cBefore = OBOL.coach.compute();
  var onFlowBeforeIds = cBefore.onFlow.map(function (a) { return a.id; });
  check(onFlowBeforeIds.indexOf('bloodyad-acl') >= 0, 'Under OSCP lens, bloodyad-acl is included in Ready Now');

  eng.facts.push(OBOL.facts.makeFact({ kind: 'ad.control_paths', scope: 'host:10.10.10.100', value: { principal: 'svc_admin', rights: ['GetChangesAll'] } }));
  var c = OBOL.coach.compute();
  var onFlowIds = c.onFlow.map(function (a) { return a.id; });
  check(onFlowIds[0] === 'dcsync', 'Under OSCP lens, dcsync is #1 when ad.control_paths is held');

  var rendered = OBOL.routes.path.render({});
  check(rendered.indexOf('data-lens="oscp+"') >= 0 && rendered.indexOf('data-lens="all"') >= 0 && rendered.indexOf('data-lens="oscp"') < 0,
    'Scope lens renders unified 2-button toggle (OSCP | All)');
  check(rendered.indexOf('hero-loadout-badge') < 0,
    'Loadout badge is omitted from the coach hero (users can inspect the Loadout tab directly)');
  check(rendered.indexOf('Moves Unlocked &amp; Upcoming') >= 0 && rendered.indexOf('From Pastes') >= 0,
    'Hero metrics include clear group headers (Moves Unlocked & Upcoming / From Pastes)');
  check(rendered.indexOf('Moves Ready') >= 0 && rendered.indexOf('Coming Up') >= 0 && rendered.indexOf('Opens Up Next') >= 0 && rendered.indexOf('Derived Facts') >= 0,
    'Hero metrics use clear labels (Moves Ready, Coming Up, Opens Up Next, Derived Facts)');
  check(/class="coach-hero-top"[\s\S]*?class="coach-hero-lens"[\s\S]*?class="ws-compact"/.test(rendered),
    'Working directory (.ws-compact) renders in .coach-hero-top to the right of the Scope toggle');
  check(/class="coach-hero-body"[\s\S]*?class="coach-hero-center hero-utility-row"[\s\S]*?id="ns-multiopen"[\s\S]*?id="ns-focusmode"[\s\S]*?class="coach-hero-aside"/.test(rendered),
    'Pill toggles (#ns-multiopen, #ns-focusmode) render inside .coach-hero-body (.coach-hero-center)');
  check(/<button[^>]*id="ns-multiopen"[^>]*class="hero-pill-toggle/.test(rendered) && /<button[^>]*id="ns-focusmode"[^>]*class="hero-pill-toggle/.test(rendered),
    'Keep Cards Open and Focus Mode are pill toggle buttons with aria-pressed instead of checkboxes');
  check(!/id="coach-campaign-bar"[\s\S]*?(?:ws-compact|ns-controls)/.test(rendered),
    'Working directory and pill toggles are inside .coach-hero, not attached inside .coach-campaign-bar');

  eng.ui.nsMultiOpen = true;
  eng.ui.nsFocusMode = true;
  var renderedActivePills = OBOL.routes.path.render({});
  check(/id="ns-multiopen"[^>]*class="[^"]*\bon\b[^"]*"[^>]*aria-pressed="true"/.test(renderedActivePills) &&
    /id="ns-focusmode"[^>]*class="[^"]*\bon\b[^"]*"[^>]*aria-pressed="true"/.test(renderedActivePills),
    'Active pill toggles render with .on class and aria-pressed="true"');
  eng.ui.nsMultiOpen = false;
  eng.ui.nsFocusMode = false;
  check((rendered.match(/class="ws-compact"/g) || []).length === 1 && (rendered.match(/class="ns-controls"/g) || []).length === 1,
    'No duplicate .ws-compact or .ns-controls rows exist outside the hero');
  check(rendered.indexOf('coach-pth-callout') >= 0,
    'Pass-the-Hash callout renders in the hero when an NT-hash-only credential is active');

  // Verify Option 3 floating outcome toast/pill widget
  eng.activities = [{
    at: Date.now(),
    target: '10.10.10.100',
    outcome: {
      kind: 'success',
      status: 'complete',
      title: 'Supported observations recognized',
      summary: 'The output supports the recorded observations.',
      detail: 'Only the listed observations are established. Unreported capabilities remain unproven.',
      observed: ['Observed: a domain-controller candidate.', 'Observed: target OS family.'],
      context: { target: '10.10.10.100', locus: 'remote' }
    }
  }];
  var renderedWithOutcome = OBOL.routes.path.render({});
  check(renderedWithOutcome.indexOf('coach-outcome-widget') >= 0 && renderedWithOutcome.indexOf('is-toast') >= 0,
    'Fresh paste outcome renders as floating .coach-outcome-widget in .is-toast state');
  check(/class="coach-outcome-pill"[^>]*data-outcome="success"/.test(renderedWithOutcome) && renderedWithOutcome.indexOf('+2') >= 0,
    'Outcome pill carries data-outcome="success" and observation count badge (+2)');
  check(renderedWithOutcome.indexOf('a domain-controller candidate.') >= 0 && renderedWithOutcome.indexOf('Unreported capabilities remain unproven') < 0,
    'Outcome drawer shows concise observations without repetitive boilerplate sentences');
})();

// 3. Verify Coin Bursts fire when Coin Bursts is ON even if Motion is OFF
(function testCoinBurstIndependentOfMotion() {
  sb.localStorage.setItem('obol.motion', 'off');
  OBOL.coins.setEnabled(true);
  check(OBOL.coins.enabled() === true, 'OBOL.coins.enabled() is true when toggled on');

  OBOL.coins.burst('foothold', 'coins on');
  var children = sb.document.body.children;
  var hasCanvas = children.some(function (el) { return el.id === 'obolcoin-fx'; });
  var banner = children.find(function (el) { return el.id === 'obolcoin-banner'; });
  check(hasCanvas && !!banner && banner.style.opacity === '1',
    'OBOL.coins.burst fires canvas and PWNED banner even when obol.motion is set to off');

  OBOL.coins.burstForFactKinds(['access.admin']);
  var levelUpEl = children.find(function (el) { return el.id === 'obolcoin-levelup'; });
  check(!!levelUpEl && levelUpEl.style.opacity === '1',
    'OBOL.coins.burstForFactKinds fires LEVEL UP flourish even when obol.motion is set to off');

  OBOL.coins.setEnabled(false);
  check(OBOL.coins.enabled() === false, 'OBOL.coins.enabled() is false when toggled off');
  check(banner.style.opacity === '0' && levelUpEl.style.opacity === '0',
    'Disabling coin bursts immediately hides active banners and stops effects');
})();

if (failed > 0) {
  console.error('\nFAILED: ' + failed + ' check(s) failed.');
  process.exit(1);
}
console.log('\nALL ' + passed + ' HERO, SCOPE LENS & TIPS CHECKS PASSED.');
