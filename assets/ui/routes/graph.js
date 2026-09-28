/*!
 * obol ui — routes/graph.js — the path graph surface (inline SVG from OBOL.graph).
 * Toggle between the live path (done + next) and the whole methodology DAG.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;

  function render() {
    var facts = OBOL.store.factSet();
    var pack = OBOL.packs.actions();
    var showAll = (OBOL.store.active().ui || {}).graphAll;
    var svg = OBOL.graph.buildGraphSvg(facts, pack, !!showAll);
    return '<section class="graph-route">'
      + '<div class="graph-head"><h1 class="route-h1">Path graph</h1>'
      + '<label class="graph-toggle"><input type="checkbox" id="g-all"' + (showAll ? ' checked' : '') + '> show whole methodology</label></div>'
      + '<p class="route-sub">Proven facts and done/next moves on your current path, laid out by phase. Toggle to see every methodology branch obol can drive. Drag to pan, scroll to zoom.</p>'
      + (OBOL.graphview ? OBOL.graphview.html(svg) : '<div class="graph-scroll" id="g-scroll">' + svg + '</div>')
      + '</section>';
  }

  function mounted(ctx) {
    if (OBOL.graphview) OBOL.graphview.attach(ctx && ctx.mount ? ctx.mount : document);
    var cb = document.getElementById('g-all');
    if (cb) cb.addEventListener('change', function () {
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.graphAll = cb.checked; }, 'ui');
      OBOL.router.render();
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.graph = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
