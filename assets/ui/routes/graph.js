/*!
 * obol ui - routes/graph.js - the path graph surface (inline SVG from OBOL.graph).
 * Toggle between the live path (done + next) and the whole methodology DAG,
 * and scope to the active target (default when a target is selected) or engagement-wide.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return (U && U.esc) ? U.esc(s) : String(s == null ? '' : s); }

  function activeTargetOf(eng) {
    if (OBOL.store && typeof OBOL.store.activeTarget === 'function') {
      var at = OBOL.store.activeTarget();
      if (at) return at;
    }
    return (eng && (eng.activeTarget || (eng.params && eng.params.target))) || '';
  }

  function scopedFacts(eng) {
    var ui = (eng && eng.ui) || {};
    var scope = ui.graphScope || 'target';
    var tgt = activeTargetOf(eng);
    if (scope !== 'all' && tgt && OBOL.store && typeof OBOL.store.factSetForTarget === 'function') {
      return OBOL.store.factSetForTarget(tgt);
    }
    if (OBOL.store && typeof OBOL.store.factSet === 'function') return OBOL.store.factSet();
    if (OBOL.state && typeof OBOL.state.facts === 'function') return OBOL.state.facts();
    return null;
  }

  function render() {
    var eng = (OBOL.store && OBOL.store.active && OBOL.store.active()) || {};
    var ui = eng.ui || {};
    var showAll = !!ui.graphAll;
    var tgt = activeTargetOf(eng);
    var scopeAll = ui.graphScope === 'all';
    var facts = scopedFacts(eng);
    var pack = OBOL.packs.actions();
    var svg = OBOL.graph.buildGraphSvg(facts, pack, showAll);
    var scopeToggle = tgt
      ? '<label class="graph-toggle"><input type="checkbox" id="g-scope"' + (scopeAll ? ' checked' : '') + '> engagement-wide (all targets)</label>'
      : '';
    return '<section class="graph-route">'
      + '<div class="graph-head"><h1 class="route-h1">Path graph' + (tgt && !scopeAll ? ' · ' + esc(tgt) : '') + '</h1>'
      + '<div class="graph-toggles">'
      + scopeToggle
      + '<label class="graph-toggle"><input type="checkbox" id="g-all"' + (showAll ? ' checked' : '') + '> show whole methodology</label>'
      + '</div></div>'
      + '<p class="route-sub">Proven facts and done/next moves on your current path, laid out by phase. Toggle to see every methodology branch OBOL can drive. Drag to pan, scroll to zoom.</p>'
      + (OBOL.graphview ? OBOL.graphview.html(svg) : '<div class="graph-scroll" id="g-scroll">' + svg + '</div>')
      + '</section>';
  }

  function mounted(ctx) {
    var mount = (ctx && ctx.mount) || document;
    if (OBOL.graphtip && OBOL.graphtip.hide) OBOL.graphtip.hide();
    if (OBOL.graphview) OBOL.graphview.attach(mount);
    var eng = (OBOL.store && OBOL.store.active && OBOL.store.active()) || {};
    var facts = scopedFacts(eng);
    if (OBOL.graphtip && OBOL.graph.buildNodeInfo && facts) {
      var dirs = (OBOL.workspace && OBOL.workspace.tokens) ? OBOL.workspace.tokens(eng) : {};
      var info = OBOL.graph.buildNodeInfo(facts, OBOL.packs.actions(),
        { params: eng.params, profile: eng.profile, workspace: dirs, includeAll: !!(eng.ui || {}).graphAll });
      OBOL.graphtip.attach(mount, info);
    }
    var cb = document.getElementById('g-all');
    if (cb) cb.addEventListener('change', function () {
      OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.graphAll = cb.checked; }, 'ui');
      OBOL.router.render();
    });
    var scb = document.getElementById('g-scope');
    if (scb) scb.addEventListener('change', function () {
      OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.graphScope = scb.checked ? 'all' : 'target'; }, 'ui');
      OBOL.router.render();
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.graph = { render: render, mounted: mounted, scopedFacts: scopedFacts };
})(typeof globalThis !== 'undefined' ? globalThis : this);
