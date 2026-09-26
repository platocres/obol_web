/*!
 * obol ui — routes/target.js — the per-target page, emulating obol-local's target Overview:
 * the attack-chain bar (where this box is on the kill chain), the ATTACK PATH (proven facts +
 * done/next moves as a phase-column graph), a coarse access level, ranked next moves scoped to
 * this target, captured flags, and the proven-fact storyline. Reached at #/target/<ip>.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  var ACCESS = {
    discovered: { label: 'Discovered', cls: 'a-disc' },
    enumerated: { label: 'Enumerated', cls: 'a-enum' },
    credentialed: { label: 'Credentialed', cls: 'a-cred' },
    foothold: { label: 'Foothold', cls: 'a-foot' },
    privileged: { label: 'Privileged', cls: 'a-priv' },
  };

  function accessLevel(f) {
    if (f.has('access.system') || f.has('access.admin') || f.has('access.root')) return 'privileged';
    if (f.has('foothold.windows') || f.has('foothold.linux') || f.has('access.shell') || f.has('winrm.authenticated') || f.has('foothold.webshell')) return 'foothold';
    if (f.has('credential.available') || f.has('credential.candidate')) return 'credentialed';
    if (f.facts.some(function (x) { return x.state === 'supported' && x.kind.indexOf('target.') !== 0 && x.kind.indexOf('host.') !== 0; })) return 'enumerated';
    return 'discovered';
  }

  function findTarget(ip) {
    var eng = OBOL.store.active();
    return (eng.targets || []).find(function (t) { return t.ip === ip || t.id === ip; }) || null;
  }

  function render(ctx) {
    var ip = ctx.args[0];
    var eng = OBOL.store.active();
    var t = findTarget(ip);
    if (!t) return '<section class="target-route"><h1 class="route-h1">Target ' + esc(ip) + '</h1><div class="coach-empty">No such target in this engagement. <a href="#/targets">Back to Targets</a></div></section>';
    ip = t.ip || ip;

    var facts = OBOL.store.factSetForTarget(ip);
    var pack = OBOL.packs.actions();
    var focus = (OBOL.profile && eng.profile) ? OBOL.profile.machineFocus(eng.profile.machine_type) : [];
    var moves = OBOL.pack.nextActions(facts, pack, { focusPrefixes: focus });
    var lvl = accessLevel(facts);
    var reached = OBOL.phases.phaseIndex(OBOL.phases.targetPhase(facts));
    var frontier = OBOL.phases.frontierIndex(facts);

    // attack-chain bar
    var chain = OBOL.phases.PHASES.map(function (p, i) {
      return '<span class="spine-node ph-' + p + (i <= reached ? ' reached' : '') + (i === frontier ? ' frontier' : '') + '">' + p + '</span>';
    }).join('<span class="spine-sep">›</span>');

    // captured flags
    var flags = [];
    ['objective.root_flag', 'objective.local_flag', 'objective.flag'].forEach(function (k) {
      if (facts.has(k)) flags.push(k.split('.').pop().replace('_', ' '));
    });

    // storyline: proven facts grouped by phase (what's been established, in order)
    var proven = facts.facts.filter(function (x) { return x.state === 'supported'; });
    var byPhase = {}; OBOL.phases.PHASES.forEach(function (p) { byPhase[p] = []; });
    proven.forEach(function (x) { var ph = OBOL.phases.phaseOfKind(x.kind); (byPhase[ph] = byPhase[ph] || []).push(x.kind); });
    var story = OBOL.phases.PHASES.filter(function (p) { return byPhase[p] && byPhase[p].length; }).map(function (p) {
      var uniq = byPhase[p].filter(function (v, i, a) { return a.indexOf(v) === i; });
      return '<li class="story-row"><span class="ph-chip ph-' + p + '">' + p + '</span>'
        + '<span class="story-facts">' + uniq.map(function (k) { return esc(OBOL.pack.friendly(k)); }).join(', ') + '</span></li>';
    }).join('');

    // top scoped moves (compact, copy-ready)
    var params = eng.params || {};
    var moveHtml = moves.slice(0, 6).map(function (a) {
      var v = OBOL.command.fillCommand(a, facts, { params: params, profile: eng.profile }, 0);
      return '<article class="tmove"><div class="tmove-head"><span class="ph-chip ph-' + OBOL.phases.phaseOfAction(a) + '">' + OBOL.phases.phaseOfAction(a) + '</span>'
        + '<span class="tmove-title">' + esc(a.title) + '</span>'
        + '<button class="btn-copy" data-copy="' + U.attr(v.filled) + '">copy</button></div>'
        + '<pre class="cmd-run"><code>' + esc(v.filled) + '</code></pre></article>';
    }).join('');

    // attack path graph, scoped to this target
    var svg = OBOL.graph ? OBOL.graph.buildGraphSvg(facts, pack, false) : '<div class="coach-empty">graph loading…</div>';

    var acc = ACCESS[lvl];
    return '<section class="target-route">'
      + '<div class="target-head"><a class="crumb" href="#/targets">Targets</a> / '
      + '<h1 class="route-h1 inline">' + esc(ip) + (t.hostname ? ' <span class="thost">' + esc(t.hostname) + '</span>' : '') + '</h1>'
      + '<span class="acc-pill ' + acc.cls + '">' + acc.label + '</span>'
      + (flags.length ? '<span class="pill flag-pill">🚩 ' + flags.map(esc).join(', ') + '</span>' : '') + '</div>'
      + '<div class="home-spine target-chain">' + chain + '</div>'

      + '<div class="target-grid">'
      + '<div class="target-col">'
      + '<h2 class="coach-sec-h">Attack path</h2>'
      + '<div class="graph-scroll">' + svg + '</div>'
      + '<h2 class="coach-sec-h">Storyline — what\'s proven</h2>'
      + (story ? '<ul class="story-list">' + story + '</ul>' : '<div class="coach-empty">Nothing proven yet — run the recon move.</div>')
      + '</div>'
      + '<div class="target-col">'
      + '<h2 class="coach-sec-h">Next moves for this target</h2>'
      + (moveHtml || '<div class="coach-empty">No moves — paste evidence to unlock.</div>')
      + '<a class="btn-ghost" href="#/path">Full Coach →</a>'
      + '</div>'
      + '</div>'
      + '</section>';
  }

  function mounted(ctx) {
    U.on(ctx.mount, 'click', '.btn-copy', function (e, b) {
      U.copy(b.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.target = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
