/*!
 * obol ui — routes/path.js — THE COACH (Next Path).
 * A pure proof-gated coach: ranked next moves from the engine, each with its *why*, its
 * copy-ready command variant(s), its *does-not-prove* honesty line, and what it *produces*.
 * NO toggles/switches here — command *building* lives in the Tools route. Blocked moves are
 * listed with their unmet-prereq reason; adding the unlocking fact promotes them live.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;

  function esc(s) { return U.esc(s); }

  function phaseChip(phase) {
    return '<span class="ph-chip ph-' + esc(phase) + '">' + esc(phase) + '</span>';
  }

  function producesChips(action) {
    if (!action.produces.length) return '';
    var chips = action.produces.map(function (k) {
      return '<span class="fact-chip" title="' + esc(k) + '">' + esc(OBOL.pack.friendly(k)) + '</span>';
    }).join('');
    return '<div class="move-produces"><span class="mini-label">proves</span>' + chips + '</div>';
  }

  function commandsBlock(action, facts, params) {
    var filled = OBOL.command.fillAll(action, facts, { params: params, profile: (OBOL.store.active() || {}).profile });
    return filled.map(function (v, i) {
      var unfilled = OBOL.command.unfilledTokens(v.filled);
      var warn = unfilled.length
        ? '<div class="cmd-needs">needs: ' + unfilled.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(', ') + '</div>'
        : '';
      var note = v.note ? '<div class="cmd-note">' + esc(v.note) + '</div>' : '';
      // hands-on guidance for obol web: big output → tee to a file and attach it in Evidence.
      var webNote = v.webNote ? '<div class="cmd-webnote">✋ ' + esc(v.webNote) + '</div>' : '';
      var label = action.sequence ? ('step ' + (i + 1)) : (i === 0 ? 'preferred' : 'alt ' + i);
      return '<div class="cmd">'
        + '<div class="cmd-head"><span class="cmd-tag">' + esc(v.tool || action.tool || 'cmd') + '</span>'
        + '<span class="cmd-variant">' + label + '</span>'
        + '<button class="btn-copy" data-copy="' + U.attr(v.filled) + '" title="Copy command">copy</button></div>'
        + '<pre class="cmd-run"><code>' + esc(v.filled) + '</code></pre>'
        + note + webNote + warn + '</div>';
    }).join('');
  }

  function moveCard(action, facts, params, opts) {
    opts = opts || {};
    var why = U.firstSentence(action.hypothesis || action.proves || action.title);
    var dnp = action.does_not_prove
      ? '<div class="move-dnp"><span class="mini-label">does not prove</span>' + esc(action.does_not_prove) + '</div>'
      : '';
    var toolLink = (action.tool || (action.tools && action.tools[0]))
      ? '<a class="btn-ghost" href="#/tools/' + esc(action.tool || action.tools[0]) + '">Build in Tools ↗</a>'
      : '';
    return '<article class="move' + (opts.primary ? ' move-primary' : '') + '" data-action="' + esc(action.id) + '">'
      + '<header class="move-head">' + phaseChip(OBOL.phases.phaseOfAction(action))
      + '<h3 class="move-title">' + esc(action.title) + '</h3></header>'
      + '<p class="move-why">' + esc(why) + '</p>'
      + commandsBlock(action, facts, params)
      + producesChips(action) + dnp
      + '<footer class="move-actions">'
      + '<button class="btn-ghost btn-pasteback" data-action="' + esc(action.id) + '">Paste result ↴</button>'
      + toolLink
      + '<button class="btn-ghost btn-done" data-action="' + esc(action.id) + '">Mark done</button>'
      + (action.refs && action.refs.length ? '<span class="move-refs">' + action.refs.length + ' ref' + (action.refs.length > 1 ? 's' : '') + '</span>' : '')
      + '</footer></article>';
  }

  // A cluster of blocked moves that share one unlocking prerequisite: "prove X → these open".
  function blockedGroup(g) {
    var cap = 12;
    var reason = String(g.reason || '').replace(/^blocked until\s*/i, '');
    var items = g.actions.slice(0, cap).map(function (a) {
      return '<li class="blocked-item">' + phaseChip(OBOL.phases.phaseOfAction(a))
        + '<span class="blocked-title">' + esc(a.title) + '</span></li>';
    }).join('');
    var more = g.actions.length > cap ? '<li class="blocked-more">…and ' + (g.actions.length - cap) + ' more</li>' : '';
    return '<section class="blocked-group">'
      + '<div class="blocked-group-head"><span class="blocked-unlock">unlock →</span>'
      + '<span class="blocked-reason">' + esc(reason) + '</span>'
      + '<span class="blocked-count">' + g.actions.length + '</span></div>'
      + '<ul class="blocked-items">' + items + more + '</ul></section>';
  }

  // The live context rail (wide screens): access level, next move, flags, creds, recent evidence.
  // Shared with the per-target page via OBOL.rail.html.
  function railCard(title, inner) { return '<div class="rail-card"><div class="rail-h">' + esc(title) + '</div>' + inner + '</div>'; }
  function buildRail(eng, facts, topMove) {
    var access = facts.has('access.system') ? ['SYSTEM', 'sys'] : facts.has('access.admin') ? ['Admin / root', 'adm']
      : (facts.has('foothold.windows') || facts.has('foothold.linux') || facts.has('access.shell')) ? ['Foothold', 'fh']
      : facts.has('credential.available') ? ['Credentialed', 'cred'] : ['Recon', 'recon'];
    var flags = (facts.facts || []).filter(function (f) { return String(f.kind).indexOf('objective.') === 0 && f.state !== 'refuted'; });
    var creds = [];
    try { creds = facts.values('credential.available') || []; } catch (e) { creds = []; }
    var acts = (eng && eng.activities || []).slice(0, 4);
    return '<aside class="context-rail" aria-label="Live context">'
      + railCard('Access', '<div class="rail-access ra-' + access[1] + '">' + esc(access[0]) + '</div>')
      + railCard('Next move', topMove ? ('<div class="rail-move">' + esc(topMove.title) + '</div>') : '<div class="rail-empty">Log evidence to unlock moves.</div>')
      + railCard('Flags (' + flags.length + ')', flags.length
        ? '<ul class="rail-list">' + flags.map(function (f) { var v = f.value || {}; return '<li><span>' + esc(v.slot || f.kind.split('.').pop()) + '</span>' + (v.name ? '<span class="rail-produced">' + esc(v.name) + '</span>' : '') + '</li>'; }).join('') + '</ul>'
        : '<div class="rail-empty">None captured yet.</div>')
      + railCard('Credentials (' + creds.length + ')', creds.length
        ? '<ul class="rail-list">' + creds.slice(0, 6).map(function (c) { return '<li><span>' + esc(c.user || c.username || 'user') + (c.domain ? '@' + esc(c.domain) : '') + '</span></li>'; }).join('') + '</ul>'
        : '<div class="rail-empty">None validated yet.</div>')
      + railCard('Recent evidence', acts.length
        ? '<ul class="rail-list rail-acts">' + acts.map(function (a) { var c = a.command || 'paste'; return '<li title="' + U.attr(c) + '"><code>' + esc(c.length > 30 ? c.slice(0, 30) + '…' : c) + '</code><span class="rail-produced">' + ((a.produced || []).length) + '</span></li>'; }).join('') + '</ul>'
        : '<div class="rail-empty">Paste tool output on Evidence.</div>')
      + '</aside>';
  }
  OBOL.rail = { html: buildRail };

  function render(ctx) {
    var eng = OBOL.store.active();
    var facts = OBOL.store.factSet();
    var params = (eng && eng.params) || {};
    var pack = OBOL.packs.actions();
    var doneIds = {};
    Object.keys((eng && eng.checklist) || {}).forEach(function (k) { if (eng.checklist[k] === 'done') doneIds[k] = true; });

    var focus = (OBOL.profile && eng && eng.profile) ? OBOL.profile.machineFocus(eng.profile.machine_type) : [];
    var ranked = OBOL.pack.nextActions(facts, pack, { doneIds: doneIds, focusPrefixes: focus });
    var frontier = OBOL.phases.frontierIndex(facts);
    var onFlow = [], comingUp = [];
    ranked.forEach(function (a) {
      if (OBOL.phases.prematurity(a, facts) === 0) onFlow.push(a); else comingUp.push(a);
    });
    var locked = OBOL.pack.lockedActions(facts, pack);

    var factCount = Object.keys(facts.kinds()).length;
    var phaseName = OBOL.phases.PHASES[frontier] || 'recon';

    var html = '<div class="withrail"><section class="coach">';
    // hero
    html += '<div class="coach-hero">'
      + '<div class="coach-hero-main">'
      + '<div class="coach-kicker">Next move · frontier: <strong>' + esc(phaseName) + '</strong></div>'
      + '<h1 class="coach-h1">' + (onFlow.length ? esc(onFlow[0].title) : 'Log evidence to unlock moves') + '</h1>'
      + '<p class="coach-sub">' + (onFlow.length ? esc(U.firstSentence(onFlow[0].hypothesis || '')) : 'Paste tool output on the Evidence route (or add a fact) and the coach ranks your next commands.') + '</p>'
      + '</div>'
      + '<div class="coach-metrics">'
      + '<div class="metric"><span class="metric-n">' + onFlow.length + '</span><span class="metric-l">ready</span></div>'
      + '<div class="metric"><span class="metric-n">' + comingUp.length + '</span><span class="metric-l">coming up</span></div>'
      + '<div class="metric"><span class="metric-n">' + locked.length + '</span><span class="metric-l">blocked</span></div>'
      + '<div class="metric"><span class="metric-n">' + factCount + '</span><span class="metric-l">facts</span></div>'
      + '</div></div>';

    // ready (on-flow) moves
    if (onFlow.length) {
      html += '<div class="coach-section"><h2 class="coach-sec-h">Ready now</h2>';
      onFlow.forEach(function (a, i) { html += moveCard(a, facts, params, { primary: i === 0 }); });
      html += '</div>';
    } else {
      html += '<div class="coach-empty">No on-flow moves yet. Start with a scan on the Evidence route, or add a target fact.</div>';
    }

    // coming up (premature but eligible)
    if (comingUp.length) {
      html += '<details class="coach-section coach-comingup"><summary class="coach-sec-h">Coming up — eligible but ahead of your frontier (' + comingUp.length + ')</summary>';
      comingUp.forEach(function (a) { html += moveCard(a, facts, params, {}); });
      html += '</details>';
    }

    // blocked with reasons
    if (locked.length) {
      // Group by the prerequisite that unlocks them, most-unlocking first: one "prove X" can
      // open many moves, so the operator sees what to hunt for instead of a flat 60-row wall.
      var groups = {};
      locked.forEach(function (p) { (groups[p.reason] = groups[p.reason] || []).push(p.action); });
      var groupList = Object.keys(groups).map(function (r) { return { reason: r, actions: groups[r] }; })
        .sort(function (a, b) { return b.actions.length - a.actions.length; });
      html += '<details class="coach-section coach-blocked"><summary class="coach-sec-h">Blocked — grouped by what unlocks them ('
        + locked.length + ' moves · ' + groupList.length + ' prerequisite' + (groupList.length === 1 ? '' : 's') + ')</summary>'
        + '<div class="blocked-groups">';
      groupList.forEach(function (g) { html += blockedGroup(g); });
      html += '</div></details>';
    }

    html += '</section>' + buildRail(eng, facts, onFlow[0]) + '</div>';
    return html;
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    // copy buttons
    U.on(mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    // mark done
    U.on(mount, 'click', '.btn-done', function (e, t) {
      var id = t.getAttribute('data-action');
      OBOL.store.update(function (eng) { eng.checklist = eng.checklist || {}; eng.checklist[id] = 'done'; }, 'done');
      U.toast('Marked done — recomputing');
      OBOL.router.render();
    });
    // paste-back: jump to evidence route pinned to this action
    U.on(mount, 'click', '.btn-pasteback', function (e, t) {
      var id = t.getAttribute('data-action');
      try { sessionStorage.setItem('obol-pasteback-action', id); } catch (err) {}
      OBOL.router.go('evidence/' + id);
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.path = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
