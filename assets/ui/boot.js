/*!
 * obol ui — boot.js — app entrypoint. Inits the store, wires the shell (engagement picker,
 * params, facts panel), registers routes, and starts the router. Route bundles beyond the
 * critical path are loaded lazily by the router's ensure() hooks (see lazy.js).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;

  var PARAM_FIELDS = [
    { key: 'target', label: 'Target', ph: '10.10.10.10' },
    { key: 'domain', label: 'Domain', ph: 'corp.local' },
    { key: 'username', label: 'User', ph: 'administrator' },
    { key: 'password', label: 'Password', ph: '', secret: true },
    { key: 'nthash', label: 'NT hash', ph: '', secret: true },
    { key: 'lhost', label: 'LHOST', ph: '10.10.14.2' },
  ];

  function esc(s) { return U.esc(s); }

  function renderSidebar() {
    var eng = OBOL.store.active();
    if (!eng) return;
    var params = eng.params || {};

    // engagement picker
    var engSel = document.getElementById('eng-select');
    if (engSel) {
      engSel.innerHTML = OBOL.store.listEngagements().map(function (e) {
        return '<option value="' + esc(e.id) + '"' + (e.id === OBOL.store.activeId() ? ' selected' : '') + '>' + esc(e.name) + '</option>';
      }).join('');
    }

    // params
    var paramsEl = document.getElementById('params');
    if (paramsEl) {
      // Redaction is opt-in across obol: a secret you recovered shows in cleartext by default so you can
      // read the password you just selected, and is masked (type=password) only when the report's Redact
      // Secrets toggle is on. This matches the credential switcher and the coach rail — no field hides a
      // value you own unless you asked it to.
      var redact = !!(eng.ui || {}).reportRedact;
      paramsEl.innerHTML = PARAM_FIELDS.map(function (f) {
        var v = params[f.key] || '';
        return '<label class="param"><span>' + esc(f.label) + '</span>'
          + '<input data-param="' + esc(f.key) + '" type="' + (f.secret && redact ? 'password' : 'text') + '" '
          + 'value="' + U.attr(v) + '" placeholder="' + esc(f.ph) + '" autocomplete="off" spellcheck="false"'
          + (f.secret ? ' data-secret="1"' : '') + '></label>';
      }).join('');
    }

    // credential switcher (collected creds → click to fill commands)
    if (OBOL.credbar) OBOL.credbar.render();

    // facts panel
    var factsEl = document.getElementById('facts-list');
    if (factsEl) {
      var fs = OBOL.store.factSet();
      if (!fs.facts.length) {
        factsEl.innerHTML = '<li class="facts-empty">No facts yet. Add one below, or paste tool output on Evidence.</li>';
      } else {
        // Collapse by (kind, scope): several facts can share a claim but differ in an incidental
        // value — ldap.reachable proven by nmap AND nxc, or service.msrpc seen on six high ports —
        // so one row per claim (with an ×N count) reads far cleaner than a pile of identical labels.
        var groups = {}, order = [];
        fs.facts.forEach(function (f) {
          var key = f.kind + '\x00' + f.scope;
          if (!groups[key]) { groups[key] = { kind: f.kind, scope: f.scope, facts: [], newest: f.created_at }; order.push(key); }
          var g = groups[key];
          g.facts.push(f);
          if (f.created_at > g.newest) g.newest = f.created_at;
        });
        factsEl.innerHTML = order.map(function (k) { return groups[k]; })
          .sort(function (a, b) { return b.newest - a.newest; })
          .map(function (g) {
            var newest = g.facts.slice().sort(function (a, b) { return b.created_at - a.created_at; })[0];
            var cls = newest.state === 'refuted' ? 'refuted' : (newest.state === 'inconclusive' ? 'incon' : 'ok');
            // distinct ports (or other small ids) across the group, for the tooltip
            var ports = g.facts.map(function (f) { return (f.value || {}).port; }).filter(function (p) { return p != null; });
            var uports = ports.filter(function (p, i) { return ports.indexOf(p) === i; }).sort(function (a, b) { return a - b; });
            var count = g.facts.length;
            var title = g.scope + (uports.length ? ' · ports ' + uports.join(', ') : '') + (count > 1 ? ' · ' + count + ' observations' : '');
            return '<li class="fact-item ' + cls + '" title="' + esc(title) + '">'
              + '<code>' + esc(g.kind) + '</code>'
              + (count > 1 ? '<span class="fact-count" aria-label="' + count + ' observations">×' + count + '</span>' : '')
              + '<button class="fact-del" data-fact-kind="' + esc(g.kind) + '" data-fact-scope="' + esc(g.scope) + '" title="Remove">×</button></li>';
          }).join('');
      }
    }
  }

  function wireShell() {
    // engagement switch / new
    var engSel = document.getElementById('eng-select');
    if (engSel) engSel.addEventListener('change', function () { OBOL.store.setActive(engSel.value).then(function () { OBOL.router.render(); }); });
    var engNew = document.getElementById('eng-new');
    if (engNew) engNew.addEventListener('click', function () {
      // The full new-run setup (platform profile, machine type, scope, Kali working directory) lives
      // in the home screen's "New Engagement" form. Route there and focus it rather than spawning a
      // name-only engagement that skips every option. The form's Create & Launch makes a fresh run
      // when one is already configured, so nothing here is destroyed.
      OBOL.router.go('home');
      var tries = 0;
      (function focusSetup() {
        var setup = document.getElementById('eng-setup');
        if (!setup) { if (tries++ < 20) return void setTimeout(focusSetup, 30); return; }
        setup.scrollIntoView({ behavior: 'smooth', block: 'start' });
        var nameEl = document.getElementById('eng-name');
        if (nameEl) { try { nameEl.focus({ preventScroll: true }); } catch (e) { try { nameEl.focus(); } catch (e2) {} } }
        setup.classList.add('eng-setup-flash');
        setTimeout(function () { setup.classList.remove('eng-setup-flash'); }, 1400);
      })();
    });

    // params (input -> store)
    var paramsEl = document.getElementById('params');
    if (paramsEl) paramsEl.addEventListener('input', function (e) {
      var t = e.target.closest('[data-param]'); if (!t) return;
      var key = t.getAttribute('data-param'), val = t.value;
      OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params[key] = val; }, 'params');
    });

    // guided fact picker (sidebar) — friendly labels + an advanced raw-kind escape hatch
    var fpEl = document.getElementById('fact-pick');
    if (fpEl && OBOL.factpick) OBOL.factpick.mount(fpEl, function (kind) {
      var scope = 'host:' + ((OBOL.store.active().params || {}).target || 'target');
      OBOL.store.addFacts([OBOL.facts.makeFact({ kind: kind, scope: scope, source: 'manual' })], 'facts');
      renderSidebar(); OBOL.router.render();
      U.toast('Fact added: ' + kind);
    });

    // remove fact
    var factsEl = document.getElementById('facts-list');
    if (factsEl) U.on(factsEl, 'click', '.fact-del', function (e, t) {
      var kind = t.getAttribute('data-fact-kind'), scope = t.getAttribute('data-fact-scope');
      OBOL.store.update(function (eng) {
        eng.facts = (eng.facts || []).filter(function (f) { return !(f.kind === kind && f.scope === scope); });
      }, 'facts');
      renderSidebar(); OBOL.router.render();
    });

    // credential switcher click/keyboard handling (delegated, wired once)
    if (OBOL.credbar) OBOL.credbar.mount();

    // (skin/motion/opacity live in the bottom-right ⚙ settings panel — see settings.js)

    // re-render sidebar whenever state changes
    OBOL.store.onChange(function () { renderSidebar(); });
  }

  function registerRoutes() {
    var R = OBOL.router;
    // Coach + evidence + home + targets are in the critical bundle.
    ['home', 'targets', 'evidence', 'path'].forEach(function (name) {
      if (OBOL.routes[name]) R.register(name, OBOL.routes[name]);
    });
    // Lazy routes (tools, domain, checklist, report, graph) register themselves when loaded.
    if (OBOL.lazy) OBOL.lazy.registerLazyRoutes(R);
    R.setDefault('home');
  }

  function boot() {
    var view = document.getElementById('view');
    OBOL.router.mount(view);
    OBOL.store.init().then(function () {
      // pre-paint skin already applied by inline head script; ensure sidebar + routes.
      renderSidebar();
      wireShell();
      registerRoutes();
      if (OBOL.palette) OBOL.palette.init();
      OBOL.router.start();
      document.documentElement.classList.remove('obol-booting');
      document.documentElement.setAttribute('data-obol-boot', 'ready');
    }).catch(function (err) {
      document.documentElement.setAttribute('data-obol-boot', 'failed');
      if (view) view.innerHTML = '<div class="boot-error">Boot failed: ' + esc(err && err.message) + '</div>';
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  OBOL.app = { renderSidebar: renderSidebar };
})(typeof globalThis !== 'undefined' ? globalThis : this);
