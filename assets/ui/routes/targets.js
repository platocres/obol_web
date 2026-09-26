/*!
 * obol ui — routes/targets.js — target list + add/remove. Targets seed the engagement's
 * scope and give the coach per-host context. Adding a target mints a target.configured /
 * host.up fact so the coach immediately surfaces the nmap-first recon move.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function render() {
    var eng = OBOL.store.active();
    var targets = (eng && eng.targets) || [];
    var rows = targets.length ? targets.map(function (t) {
      return '<article class="tcard" data-tid="' + esc(t.id) + '">'
        + '<div class="tcard-dot ' + (t.os ? ('os-' + esc(t.os)) : '') + '"></div>'
        + '<a class="tcard-main" href="#/target/' + esc(t.ip || t.id) + '"><div class="tcard-ip">' + esc(t.ip || t.hostname || '?') + '</div>'
        + (t.hostname ? '<div class="tcard-host">' + esc(t.hostname) + '</div>' : '')
        + '</a>'
        + '<div class="tcard-meta">' + (t.os ? '<span class="pill">' + esc(t.os) + '</span>' : '') + '</div>'
        + '<button class="tcard-del" data-tid="' + esc(t.id) + '" title="Remove">×</button>'
        + '</article>';
    }).join('') : '<div class="coach-empty">No targets yet. Add one below to start the coach.</div>';

    return '<section class="targets">'
      + '<h1 class="route-h1">Targets</h1>'
      + '<div class="ev-row targets-add">'
      + '<input id="t-ip" class="ev-cmd" placeholder="IP or CIDR, e.g. 10.10.10.10">'
      + '<input id="t-host" class="ev-cmd" placeholder="hostname (optional)">'
      + '<button id="t-add" class="btn-primary">Add Target</button>'
      + '</div>'
      + '<div class="tgrid">' + rows + '</div>'
      + '</section>';
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    var addBtn = document.getElementById('t-add');
    if (addBtn) addBtn.addEventListener('click', function () {
      var ip = ((document.getElementById('t-ip') || {}).value || '').trim();
      var host = ((document.getElementById('t-host') || {}).value || '').trim();
      if (!ip && !host) return;
      var id = 't-' + Date.now().toString(36);
      OBOL.store.update(function (eng) {
        eng.targets = eng.targets || [];
        eng.targets.push({ id: id, ip: ip, hostname: host, os: '' });
        if (!eng.params) eng.params = {};
        if (!eng.params.target) eng.params.target = ip || host;
      }, 'targets');
      // seed facts so the coach lights up
      var scope = 'host:' + (ip || host);
      OBOL.store.addFacts([
        OBOL.facts.makeFact({ kind: 'target.configured', scope: scope, source: 'targets' }),
      ], 'facts');
      OBOL.app.renderSidebar();
      U.toast('Target added — coach updated');
      OBOL.router.render();
    });
    U.on(mount, 'click', '.tcard-del', function (e, t) {
      var id = t.getAttribute('data-tid');
      OBOL.store.update(function (eng) { eng.targets = (eng.targets || []).filter(function (x) { return x.id !== id; }); }, 'targets');
      OBOL.router.render();
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.targets = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
