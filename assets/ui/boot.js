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
    { key: 'domain', label: 'Domain', ph: 'htb.local' },
    { key: 'username', label: 'User', ph: 'svc-alfresco' },
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
      paramsEl.innerHTML = PARAM_FIELDS.map(function (f) {
        var v = params[f.key] || '';
        return '<label class="param"><span>' + esc(f.label) + '</span>'
          + '<input data-param="' + esc(f.key) + '" type="' + (f.secret ? 'password' : 'text') + '" '
          + 'value="' + U.attr(v) + '" placeholder="' + esc(f.ph) + '" autocomplete="off" spellcheck="false"></label>';
      }).join('');
    }

    // facts panel
    var factsEl = document.getElementById('facts-list');
    if (factsEl) {
      var fs = OBOL.store.factSet();
      if (!fs.facts.length) {
        factsEl.innerHTML = '<li class="facts-empty">No facts yet. Add one below, or paste tool output on Evidence.</li>';
      } else {
        factsEl.innerHTML = fs.facts.slice().sort(function (a, b) { return b.created_at - a.created_at; }).map(function (f) {
          var cls = f.state === 'refuted' ? 'refuted' : (f.state === 'inconclusive' ? 'incon' : 'ok');
          return '<li class="fact-item ' + cls + '" title="' + esc(f.scope) + '">'
            + '<code>' + esc(f.kind) + '</code>'
            + '<button class="fact-del" data-fact-kind="' + esc(f.kind) + '" data-fact-scope="' + esc(f.scope) + '" title="Remove">×</button></li>';
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
      var name = prompt('New engagement name:', 'HTB / Lab');
      if (name) OBOL.store.createEngagement(name).then(function () { renderSidebar(); OBOL.router.render(); });
    });

    // params (input -> store)
    var paramsEl = document.getElementById('params');
    if (paramsEl) paramsEl.addEventListener('input', function (e) {
      var t = e.target.closest('[data-param]'); if (!t) return;
      var key = t.getAttribute('data-param'), val = t.value;
      OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params[key] = val; }, 'params');
    });

    // quick add fact
    var addBtn = document.getElementById('fact-add');
    var addInput = document.getElementById('fact-input');
    function addFact() {
      var kind = (addInput.value || '').trim();
      if (!kind) return;
      var scope = 'host:' + ((OBOL.store.active().params || {}).target || 'target');
      OBOL.store.addFacts([OBOL.facts.makeFact({ kind: kind, scope: scope, source: 'manual' })], 'facts');
      addInput.value = '';
      renderSidebar(); OBOL.router.render();
      U.toast('Fact added: ' + kind);
    }
    if (addBtn) addBtn.addEventListener('click', addFact);
    if (addInput) addInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') addFact(); });

    // remove fact
    var factsEl = document.getElementById('facts-list');
    if (factsEl) U.on(factsEl, 'click', '.fact-del', function (e, t) {
      var kind = t.getAttribute('data-fact-kind'), scope = t.getAttribute('data-fact-scope');
      OBOL.store.update(function (eng) {
        eng.facts = (eng.facts || []).filter(function (f) { return !(f.kind === kind && f.scope === scope); });
      }, 'facts');
      renderSidebar(); OBOL.router.render();
    });

    // skin picker
    var skinSel = document.getElementById('skin-select');
    if (skinSel) {
      skinSel.value = OBOL.store.pref().skin || 'obol';
      skinSel.addEventListener('change', function () {
        document.documentElement.setAttribute('data-skin', skinSel.value);
        OBOL.store.setPref('skin', skinSel.value);
      });
    }

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
