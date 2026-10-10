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

  // A rich per-target dossier card: access badge, OS, domain, open ports, reachable services, flags, and
  // the next move the coach would run on that box. Built from the SHARED projection (OBOL.targets.all) so
  // it never drifts from the engagement hub's board. Reuses the hub card's styled sub-elements (hb-*).
  function dossierCard(info) {
    var b = info.badge || { label: 'SCAN', cls: 'hb-acc-disc' };
    var ports = info.ports.slice(0, 12).map(function (p) { return '<span class="hb-port">' + p + '</span>'; }).join('')
      + (info.ports.length > 12 ? '<span class="hb-port hb-port-more">+' + (info.ports.length - 12) + '</span>' : '');
    var svcs = (info.svcs || []).slice(0, 7).map(function (s) { return '<span class="tgt-svc">' + esc(s) + '</span>'; }).join('');
    var flags = info.flags
      ? '<span class="hb-flags">' + OBOL.ic('flag') + ' ' + info.flags + ' Flag' + (info.flags === 1 ? '' : 's') + '</span>'
      : '<span class="hb-flags hb-noflag">No Flags Yet</span>';
    var nextHtml = info.next ? '<span class="hb-next" title="' + U.attr(info.next) + '">→ ' + esc(info.next) + '</span>'
      : (info.lvl === 'privileged' ? '<span class="hb-next hb-next-done">Owned</span>' : '');
    return '<article class="hb-tcard tgt-card hb-lvl-' + info.lvl + '" data-tid="' + esc(info.t.id) + '">'
      + '<button class="tcard-del" data-tid="' + esc(info.t.id) + '" title="Remove target" aria-label="Remove target ' + U.attr(info.ip) + '">×</button>'
      + '<a class="hb-tcard-main tgt-main" href="#/target/' + U.attr(info.ip) + '">'
      + '<div class="hb-tcard-top"><span class="hb-tname">' + esc(info.host || info.ip) + '</span>'
      + (info.host ? '<span class="hb-tip">' + esc(info.ip) + '</span>' : '')
      + '<span class="hb-acc ' + b.cls + '">' + b.label + '</span></div>'
      + '<div class="tgt-meta">'
      + '<div class="tgt-row"><span class="tgt-k">OS</span><span class="tgt-v' + (info.os ? '' : ' tgt-empty') + '">' + (info.os ? esc(U.titleCase(info.os)) : 'Not Yet Fingerprinted') + '</span></div>'
      + '<div class="tgt-row"><span class="tgt-k">Domain</span><span class="tgt-v' + (info.domain ? '' : ' tgt-empty') + '">' + (info.domain ? esc(info.domain) : 'None Known Yet') + '</span></div>'
      + '</div>'
      + '<div class="tgt-ports"><span class="tgt-k">Ports</span><div class="hb-ports">' + (ports || '<span class="hb-port-none">No Ports Yet</span>') + '</div></div>'
      + (svcs ? '<div class="tgt-svcs">' + svcs + '</div>' : '')
      + '<div class="hb-tfoot">' + flags + nextHtml + '</div>'
      + '</a></article>';
  }

  function render() {
    var eng = OBOL.store.active();
    var targets = (eng && eng.targets) || [];
    var infos = (OBOL.targets && OBOL.targets.all) ? OBOL.targets.all(eng) : [];
    var rows = targets.length
      ? '<div class="tgrid">' + (infos.length ? infos.map(dossierCard).join('')
          : targets.map(function (t) { return dossierCard({ t: t, ip: t.ip || t.id, host: t.hostname || '', os: t.os || '', lvl: 'discovered', badge: { label: 'SCAN', cls: 'hb-acc-disc' }, ports: [], flags: 0, domain: '', svcs: [], next: '' }); }).join('')) + '</div>'
      : '<div class="coach-empty">No Targets Yet. Add one below and the coach lights up with your first recon move.</div>';

    var count = targets.length;
    return '<section class="targets">'
      + '<h1 class="route-h1">Targets</h1>'
      + '<p class="route-sub">Add the boxes in scope. Each target seeds a fact so the coach immediately surfaces the nmap-first recon move for it.</p>'
      + '<div class="targets-add">'
      + '<div class="targets-add-h">Add A Target</div>'
      + '<div class="targets-add-row">'
      + '<label class="targets-add-field"><span>IP Or CIDR</span><input id="t-ip" class="ev-cmd" placeholder="e.g. 10.10.10.10" autocomplete="off" spellcheck="false" inputmode="decimal"></label>'
      + '<label class="targets-add-field"><span>Hostname <span class="targets-add-opt">(Optional)</span></span><input id="t-host" class="ev-cmd" placeholder="e.g. dc01.corp.local" autocomplete="off" spellcheck="false"></label>'
      + '<button id="t-add" class="btn-primary targets-add-btn">Add Target</button>'
      + '</div></div>'
      + '<div class="targets-grid-h"><h2 class="coach-sec-h">In Scope</h2><span class="pill">' + count + ' Target' + (count === 1 ? '' : 's') + '</span></div>'
      + rows
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
      U.toast('Target added, coach updated');
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
