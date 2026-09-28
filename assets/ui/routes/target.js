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

    // captured flags — rich entries (slot label, file, value) so the operator can confirm each capture
    // at a glance (a real flag, not a stray hash) and knows which flag came from where.
    var SLOT_LABEL = { root: 'Root flag', local: 'Local flag', user: 'Local flag' };
    var flagFacts = [];
    ['objective.root_flag', 'objective.local_flag', 'objective.flag'].forEach(function (k) {
      facts.values(k).forEach(function (v) { flagFacts.push({ kind: k, value: v || {} }); });
    });
    function flagLabel(e) {
      var v = e.value || {};
      return SLOT_LABEL[v.slot] || (e.kind.split('.').pop().replace('_flag', '').replace('flag', 'flag').replace(/^\w/, function (c) { return c.toUpperCase(); }) + ' flag');
    }
    var flags = flagFacts.map(flagLabel);
    // Located-but-not-captured: found remotely (nxc/smb), still to be read on-host for the report.
    var capturedVals = {}, capturedSlots = {};
    flagFacts.forEach(function (e) { var v = e.value || {}; if (v.flag) capturedVals[v.flag] = 1; if (v.slot) capturedSlots[v.slot] = 1; });
    var locSeen = {};
    var locatedFacts = facts.values('objective.flag_located').filter(function (v) {
      v = v || {};
      if ((v.flag && capturedVals[v.flag]) || (v.slot && capturedSlots[v.slot])) return false;
      var key = v.path || v.flag || v.slot || ''; if (locSeen[key]) return false; locSeen[key] = 1; return true;
    });
    var shotsForSlot = function (slot) {
      return (eng.screenshots || []).filter(function (s) { return s.target === ip && (s.slot === slot || (slot === 'local' && s.slot === 'user')); });
    };
    var flagCard = (flagFacts.length || locatedFacts.length)
      ? '<h2 class="coach-sec-h">Captured Flags</h2><input type="file" id="flag-ss-file" accept="image/*" hidden><ul class="flag-cards">' + flagFacts.map(function (e) {
          var v = e.value || {}; var val = v.flag || '';
          var slot = v.slot === 'user' ? 'local' : (v.slot || 'flag');
          var shots = shotsForSlot(slot);
          return '<li class="flag-card flag-' + esc(v.slot || 'flag') + '">'
            + '<div class="flag-card-h"><span class="flag-slot">🚩 ' + esc(flagLabel(e)) + '</span>'
            + (v.name ? '<span class="flag-file" title="' + U.attr(v.path || v.name) + '">' + esc(v.name) + '</span>' : '') + '</div>'
            + (val ? '<code class="flag-val" title="' + U.attr(val) + '">' + esc(val) + '</code><button class="btn-copy flag-copy" data-copy="' + U.attr(val) + '">copy</button>' : '')
            + '<div class="flag-proof">' + (shots.length
              ? shots.map(function (s) { return '<span class="flag-shot-wrap"><img class="flag-shot" src="' + esc(s.data_uri) + '" alt="proof screenshot"><button class="flag-shot-rm" data-rm="' + esc(s.id) + '" title="Remove">✕</button></span>'; }).join('')
                + '<span class="flag-proof-ok">✓ proof screenshot attached</span>'
              : '<button class="flag-attach" data-slot="' + esc(slot) + '">📎 Attach proof screenshot</button>'
                + '<span class="flag-proof-note">flag + ipconfig in one interactive-shell frame — OffSec requires the image</span>')
            + '</div></li>';
        }).join('')
        + locatedFacts.map(function (v) {
          v = v || {}; var SL = { root: 'Root flag', local: 'Local flag', user: 'Local flag' };
          var label = SL[v.slot] || 'Flag';
          return '<li class="flag-card flag-located">'
            + '<div class="flag-card-h"><span class="flag-slot">📍 ' + esc(label) + ' <em>located</em></span>'
            + (v.name ? '<span class="flag-file" title="' + U.attr(v.path || v.name) + '">' + esc(v.path || v.name) + '</span>' : '') + '</div>'
            + '<div class="flag-locnote">Found remotely — read it from an interactive shell on this host so it counts for the report (OffSec scores a remote read zero).</div>'
            + '</li>';
        }).join('') + '</ul>'
      : '';

    // Attack Path bar: the ordered, causal path actually walked (what led to what → the flags),
    // reconstructed from the run ledger + prereq graph, rendered as a dense horizontal block ribbon.
    // Each block synthesizes obol-local's two surfaces: the milestone + concrete subject (attack_path)
    // AND the command that produced it + real causal link (storyline). Off-path parents get "← from".
    var steps = OBOL.chain.build({ facts: facts, activities: eng.activities || [], actions: pack, host: ip });
    var story = OBOL.chainview.ribbon(steps);

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
    // Identity at a glance — IP / Hostname / Domain, each labelled, the hostname brighter. The hostname
    // and domain fill in the moment obol proves them; until then the slot reads "not captured yet".
    var idn = OBOL.store.targetIdentity(ip);
    function identRow(label, val, cls, title) {
      return '<div class="ident-row"><dt>' + label + '</dt>'
        + '<dd class="' + cls + (val ? '' : ' ident-empty') + '"' + (title ? ' title="' + U.attr(title) + '"' : '') + '>'
        + (val ? esc(val) : 'not captured yet') + '</dd></div>';
    }
    return '<section class="target-route">'
      + '<div class="target-head">'
      + '<div class="target-crumbs"><a class="crumb" href="#/targets">Targets</a>'
      + '<span class="acc-pill ' + acc.cls + '">' + acc.label + '</span>'
      + (flags.length ? '<span class="pill flag-pill">🚩 ' + flags.map(esc).join(', ') + '</span>' : '') + '</div>'
      + '<dl class="ident target-ident">'
      + '<div class="ident-row"><dt>IP</dt><dd class="ident-ip"><h1 class="route-h1 inline">' + esc(idn.ip) + '</h1></dd></div>'
      + identRow('Hostname', idn.hostname, 'ident-host', idn.hostname && idn.fqdn !== idn.hostname ? idn.fqdn : '')
      + identRow('Domain', idn.domain, 'ident-dom', '')
      + '</dl></div>'
      + '<div class="home-spine target-chain">' + chain + '</div>'

      + '<div class="target-grid">'
      + '<div class="target-col">'
      + '<h2 class="coach-sec-h">Attack Path — What Led to What</h2>'
      + (story ? '<div class="apath-flow">' + story + '</div>' : '<div class="coach-empty">Nothing proven yet — run the recon move.</div>')
      + '<h2 class="coach-sec-h">Path Graph</h2>'
      + (OBOL.graphview ? OBOL.graphview.html(svg) : '<div class="graph-scroll">' + svg + '</div>')
      + '</div>'
      + '<div class="target-col">'
      + flagCard
      + '<h2 class="coach-sec-h">Next moves for this target</h2>'
      + (moveHtml || '<div class="coach-empty">No moves — paste evidence to unlock.</div>')
      + '<a class="btn-ghost" href="#/path">Full Coach →</a>'
      + '</div>'
      + '</div>'
      + '</section>';
  }

  function mounted(ctx) {
    var mount = ctx.mount || document;
    if (OBOL.graphview) OBOL.graphview.attach(mount);
    if (OBOL.graphtip && OBOL.graph && OBOL.graph.buildNodeInfo) {
      var eng = OBOL.store.active();
      var ip = (location.hash.split('/')[2] || (eng.params || {}).target || '');
      var facts = OBOL.store.factSetForTarget ? OBOL.store.factSetForTarget(ip) : OBOL.store.factSet();
      var dirs = (OBOL.workspace && OBOL.workspace.tokens) ? OBOL.workspace.tokens(eng) : {};
      var info = OBOL.graph.buildNodeInfo(facts, OBOL.packs.actions(), { params: eng.params, profile: eng.profile, workspace: dirs });
      OBOL.graphtip.attach(mount, info);
    }
    U.on(mount, 'click', '.btn-copy', function (e, b) {
      U.copy(b.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    // per-flag proof screenshot: attach (bound to the flag's slot + this host) / remove.
    var tgtIp = location.hash.split('/')[2] || (OBOL.store.active().params || {}).target || '';
    var ssInput = mount.querySelector('#flag-ss-file');
    var pendingSlot = '';
    U.on(mount, 'click', '.flag-attach', function (e, b) { pendingSlot = b.getAttribute('data-slot') || ''; if (ssInput) ssInput.click(); });
    if (ssInput) ssInput.addEventListener('change', function () {
      var files = Array.prototype.slice.call(ssInput.files || []); var pending = files.length; if (!pending) return;
      files.forEach(function (f) {
        var r = new FileReader();
        r.onload = function () {
          OBOL.store.update(function (eng) {
            eng.screenshots = eng.screenshots || [];
            eng.screenshots.push({ id: 'ss-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), data_uri: r.result, caption: '', slot: pendingSlot, target: tgtIp, at: Date.now() });
          }, 'screenshots');
          if (--pending === 0) { U.toast('Proof screenshot attached'); OBOL.router.render(); }
        };
        r.onerror = function () { if (--pending === 0) OBOL.router.render(); };
        r.readAsDataURL(f);
      });
      ssInput.value = '';
    });
    U.on(mount, 'click', '.flag-shot-rm', function (e, b) {
      var id = b.getAttribute('data-rm');
      OBOL.store.update(function (eng) { eng.screenshots = (eng.screenshots || []).filter(function (s) { return s.id !== id; }); }, 'screenshots');
      OBOL.router.render();
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.target = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
