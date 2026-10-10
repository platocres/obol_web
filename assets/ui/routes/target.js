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

  // the proven facts for this box (one row per kind), for the Evidence half of the spine
  function provenKinds(facts) {
    var seen = {}, out = [];
    facts.facts.forEach(function (x) {
      if (x.state !== 'supported') return;
      if (x.kind.indexOf('target.') === 0) return;
      if (seen[x.kind]) return; seen[x.kind] = 1; out.push(x.kind);
    });
    return out;
  }

  // the Evidence half of the spine: what you have proven about this box + a way to add more.
  // One paste feeds the engagement-wide report, filed under this host (see the global paste, phase 3).
  function evidencePanel(ip, facts) {
    var kinds = provenKinds(facts);
    var rows = kinds.length
      ? '<ul class="tw-facts">' + kinds.slice(0, 10).map(function (k) {
          return '<li><span class="tw-fcheck" aria-hidden="true">' + OBOL.ic('spark') + '</span>'
            + '<span class="tw-flabel">' + esc(U.titleCase(OBOL.pack.friendly(k))) + '</span>'
            + '<code class="tw-fkind">' + esc(k) + '</code></li>';
        }).join('') + '</ul>' + (kinds.length > 10 ? '<div class="tw-facts-more">+' + (kinds.length - 10) + ' more proven</div>' : '')
      : '<div class="tw-ev-empty">Nothing proven here yet. Run a move, then paste its output.</div>';
    // Inline paste — stays on this box's page (no jarring jump to the Evidence tab). Facts are routed to
    // this host's scope; a big dump or a screenshot still has a link out to the full Evidence surface.
    return '<div class="tw-ev-head"><button type="button" class="btn-primary tw-ev-paste" data-tw-paste aria-expanded="false">' + OBOL.ic('clip') + ' Paste Output For This Box</button></div>'
      + '<div class="tw-ingest" data-ip="' + U.attr(ip) + '" hidden>'
      + '<textarea class="tw-ingest-text" placeholder="Paste this box’s command output here — prompt, command, and all output. obol mints only what it proves and files it under ' + esc(ip) + '. You stay right here on this box." spellcheck="false"></textarea>'
      + '<div class="tw-ingest-row"><button type="button" class="btn-primary tw-ingest-go">Ingest → Facts</button>'
      + '<a class="tw-ingest-ev" href="#/evidence/">Big Output Or A Screenshot? Full Evidence ↗</a>'
      + '<span class="tw-ingest-result" role="status"></span></div></div>'
      + rows
      + '<div class="tw-ev-note">Every fact minted here lands in the engagement report, filed under <b>' + esc(ip) + '</b>.</div>';
  }

  // contextual launchers: open the global Tools / Playbooks library already filled for this box.
  function launchers(ip) {
    return '<div class="tw-launchers">'
      + '<button type="button" class="tw-launch" data-launch="tools" data-ip="' + U.attr(ip) + '">'
      + '<span class="tw-launch-ic">' + OBOL.ic('bolt') + '</span>'
      + '<span class="tw-launch-txt"><b>Build a command</b><span>Open Tools, filled for ' + esc(ip) + '.</span></span></button>'
      + '<button type="button" class="tw-launch" data-launch="playbooks" data-ip="' + U.attr(ip) + '">'
      + '<span class="tw-launch-ic">' + OBOL.ic('box') + '</span>'
      + '<span class="tw-launch-txt"><b>Run a playbook</b><span>A ready-made sequence, charged with this box.</span></span></button>'
      + '</div>';
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
    var dirs = (OBOL.workspace && OBOL.workspace.tokens) ? OBOL.workspace.tokens(eng) : {};
    // Rank this box's moves with the SAME shared logic the coach/hub use (report-only writeup checks
    // excluded, frontier-ready first), scoped to this host's facts — so "Next Steps for this box" never
    // disagrees with the full coach or the hub.
    var moves = (OBOL.coach && OBOL.coach.rankFor) ? OBOL.coach.rankFor(facts).onFlow
      : OBOL.pack.rankActions(facts, pack, { focusPrefixes: focus });
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
            + '<div class="flag-card-h"><span class="flag-slot">' + OBOL.ic('flag') + ' ' + esc(flagLabel(e)) + '</span>'
            + (v.name ? '<span class="flag-file" title="' + U.attr(v.path || v.name) + '">' + esc(v.name) + '</span>' : '') + '</div>'
            + (val ? '<code class="flag-val" title="' + U.attr(val) + '">' + esc(val) + '</code><button class="btn-copy flag-copy" data-copy="' + U.attr(val) + '">copy</button>' : '')
            + '<div class="flag-proof">' + (shots.length
              ? shots.map(function (s) { return '<span class="flag-shot-wrap"><img class="flag-shot" src="' + esc(s.data_uri) + '" alt="proof screenshot"><button class="flag-shot-rm" data-rm="' + esc(s.id) + '" title="Remove">✕</button></span>'; }).join('')
                + '<span class="flag-proof-ok">✓ proof screenshot attached</span>'
              : '<button class="flag-attach" data-slot="' + esc(slot) + '">' + OBOL.ic('clip') + ' Attach proof screenshot</button>'
                + '<span class="flag-proof-note">flag + ipconfig in one interactive-shell frame, OffSec requires the image</span>')
            + '</div></li>';
        }).join('')
        + locatedFacts.map(function (v) {
          v = v || {}; var SL = { root: 'Root flag', local: 'Local flag', user: 'Local flag' };
          var label = SL[v.slot] || 'Flag';
          return '<li class="flag-card flag-located">'
            + '<div class="flag-card-h"><span class="flag-slot">' + OBOL.ic('pin') + ' ' + esc(label) + ' <em>located</em></span>'
            + (v.name ? '<span class="flag-file" title="' + U.attr(v.path || v.name) + '">' + esc(v.path || v.name) + '</span>' : '') + '</div>'
            + '<div class="flag-locnote">Found remotely, read it from an interactive shell on this host so it counts for the report (OffSec scores a remote read zero).</div>'
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
      var v = OBOL.command.fillCommand(a, facts, { params: params, profile: eng.profile, workspace: dirs }, 0);
      // The "Set Up First" prep step (e.g. write loot/users.txt from the users obol proved) — the SAME step
      // the coach renders, so a move whose command reads a file you must create first never ships here
      // without the command that creates it.
      var prep = (OBOL.coach && OBOL.coach.prepBlock) ? OBOL.coach.prepBlock(a, facts, dirs) : '';
      return '<article class="tmove"><div class="tmove-head"><span class="ph-chip ph-' + OBOL.phases.phaseOfAction(a) + '">' + esc(U.titleCase(OBOL.phases.phaseOfAction(a))) + '</span>'
        + '<span class="tmove-title">' + esc(a.title) + '</span>'
        + '<button class="btn-copy" data-copy="' + U.attr(v.filled) + '">copy</button></div>'
        + prep
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
      + (flags.length ? '<span class="pill flag-pill">' + OBOL.ic('flag') + ' ' + flags.map(esc).join(', ') + '</span>' : '') + '</div>'
      + '<dl class="ident target-ident">'
      + '<div class="ident-row"><dt>IP</dt><dd class="ident-ip"><h1 class="route-h1 inline">' + esc(idn.ip) + '</h1></dd></div>'
      + identRow('Hostname', idn.hostname, 'ident-host', idn.hostname && idn.fqdn !== idn.hostname ? idn.fqdn : '')
      + identRow('Domain', idn.domain, 'ident-dom', '')
      + '</dl></div>'
      + '<div class="home-spine target-chain">' + chain + '</div>'

      // the spine: the working loop for this box, Next Steps beside Evidence
      + '<div class="tw-spine">'
      + '<section class="tw-panel tw-next"><div class="tw-panel-h"><span class="tw-panel-l">Next Steps for this box</span><span class="tw-panel-tag">ranked by the coach</span></div>'
      + '<div class="tw-panel-b">' + (moveHtml || '<div class="coach-empty">No moves yet, paste evidence to unlock.</div>')
      + '<a class="btn-ghost tw-fullcoach" href="#/path">Full coach →</a></div></section>'
      + '<section class="tw-panel tw-ev"><div class="tw-panel-h"><span class="tw-panel-l">Evidence &amp; proven facts</span><span class="tw-panel-tag">this box, feeds the report</span></div>'
      + '<div class="tw-panel-b">' + evidencePanel(ip, facts) + '</div></section>'
      + '</div>'
      + launchers(ip)

      + '<div class="target-grid">'
      + '<div class="target-col">'
      + '<h2 class="coach-sec-h">Attack Path: What Led to What</h2>'
      + (story ? '<div class="apath-flow">' + story + '</div>' : '<div class="coach-empty">Nothing proven yet, run the recon move.</div>')
      + '<h2 class="coach-sec-h">Path Graph</h2>'
      + (OBOL.graphview ? OBOL.graphview.html(svg) : '<div class="graph-scroll">' + svg + '</div>')
      + '</div>'
      + '<div class="target-col">'
      + flagCard
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
    // inline paste for this box: toggle the box, then ingest in place (routed to this host's scope) and
    // re-render — the operator never leaves the target view.
    U.on(mount, 'click', '[data-tw-paste]', function (e, t) {
      var box = mount.querySelector('.tw-ingest'); if (!box) return;
      var open = box.hasAttribute('hidden');
      if (open) box.removeAttribute('hidden'); else box.setAttribute('hidden', '');
      t.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) { var ta = box.querySelector('.tw-ingest-text'); if (ta) ta.focus(); }
    });
    U.on(mount, 'click', '.tw-ingest-go', function (e, t) {
      var box = t.closest('.tw-ingest'); if (!box) return;
      var ta = box.querySelector('.tw-ingest-text'), out = box.querySelector('.tw-ingest-result');
      var text = (ta && ta.value) || '';
      if (!text.trim()) { if (out) out.textContent = 'Paste the output first.'; return; }
      var ip = box.getAttribute('data-ip') || '';
      if (out) out.textContent = 'Reading…'; t.disabled = true;
      if (!(OBOL.ingest && OBOL.ingest.ensureParsers)) { if (out) out.textContent = 'Parsers unavailable.'; t.disabled = false; return; }
      OBOL.ingest.ensureParsers().then(function (okp) {
        if (!okp) { if (out) out.textContent = 'Parsers still loading, try again.'; t.disabled = false; return; }
        var r = OBOL.ingest.run({ text: text, scope: 'host:' + ip, source: 'paste' });
        if (!r || !r.ok) { if (out) out.textContent = (r && r.reason === 'parsers') ? 'Parsers still loading, try again.' : 'Nothing to parse.'; t.disabled = false; return; }
        if (r.added) { U.toast('Minted ' + r.added + ' fact' + (r.added === 1 ? '' : 's') + ', updating this box'); OBOL.router.render(); }
        else { t.disabled = false; if (out) out.textContent = r.facts.length ? ('Recognized ' + r.facts.length + ', nothing new (already known).') : 'No facts recognized (output saved).'; }
      });
    });
    // contextual launchers: make this box the active target, then open the global Tools / Playbooks
    // library already filled for it.
    U.on(mount, 'click', '[data-launch]', function (e, t) {
      var ip = t.getAttribute('data-ip'), where = t.getAttribute('data-launch');
      OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.target = ip; }, 'params');
      if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
      OBOL.router.go(where);
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
