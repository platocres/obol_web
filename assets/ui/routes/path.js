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
      return '<span class="fact-chip" title="' + esc(k) + '">' + esc(OBOL.util.titleCase(OBOL.pack.friendly(k))) + '</span>';
    }).join('');
    return '<div class="move-produces"><span class="mini-label">proves</span>' + chips + '</div>';
  }

  function commandsBlock(action, filled) {
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
    var filled = OBOL.command.fillAll(action, facts, { params: params, profile: (OBOL.store.active() || {}).profile, workspace: OBOL.workspace.tokens(OBOL.store.active()) });
    var prefCmd = (filled[0] && filled[0].filled) || action.command || '';
    // Inline ingestion: paste this move's output right here — the coach mints facts and advances,
    // so a first-timer never has to guess where the output goes. Big dumps still go to Evidence.
    var ingestBox = '<div class="move-ingest" data-action="' + esc(action.id) + '" data-cmd="' + U.attr(prefCmd) + '" hidden>'
      + '<textarea class="mi-text" placeholder="Paste this command\'s full output here — prompt, command and all. The coach reads it, mints only what it proves, and advances." spellcheck="false"></textarea>'
      + '<div class="mi-row"><button class="btn-primary mi-go" data-action="' + esc(action.id) + '">Ingest → Facts</button>'
      + '<a class="mi-evlink" href="#/evidence/' + esc(action.id) + '">Big output or a screenshot? Full Evidence ↗</a>'
      + '<span class="mi-result" role="status"></span></div></div>';
    return '<article class="move' + (opts.primary ? ' move-primary' : '') + '" data-action="' + esc(action.id) + '">'
      + '<header class="move-head">' + phaseChip(OBOL.phases.phaseOfAction(action))
      + '<h3 class="move-title">' + esc(action.title) + '</h3></header>'
      + '<p class="move-why">' + esc(why) + '</p>'
      + commandsBlock(action, filled)
      + producesChips(action) + dnp
      + '<footer class="move-actions">'
      + '<button class="btn-ghost btn-pasteback" data-action="' + esc(action.id) + '" aria-expanded="false">Paste Output ↴</button>'
      + toolLink
      + '<button class="btn-ghost btn-done" data-action="' + esc(action.id) + '">Mark Done</button>'
      + (action.refs && action.refs.length ? '<span class="move-refs">' + action.refs.length + ' ref' + (action.refs.length > 1 ? 's' : '') + '</span>' : '')
      + '</footer>'
      + ingestBox + '</article>';
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

    // one-time workspace scaffold: create the output tree once, then every command below writes
    // into it and tells you which file to attach. Dismissible; auto-hides once you're rolling.
    if (OBOL.workspace.isConfigured(eng) && !((eng.ui || {}).wsScaffoldDone) && factCount < 3) {
      var scaffold = OBOL.workspace.scaffold(eng);
      var scandir = OBOL.workspace.tokens(eng).scandir;
      html += '<div class="ws-banner">'
        + '<div class="ws-banner-h">📁 Set up your working directory — run this once on your Kali box:</div>'
        + '<pre class="cmd-run"><code>' + esc(scaffold) + '</code></pre>'
        + '<div class="ws-banner-actions"><button class="btn-copy" data-copy="' + U.attr(scaffold) + '">copy</button>'
        + '<button class="btn-ghost ws-done">Got It</button></div>'
        + '<div class="ws-banner-note">Commands below write into <code>' + esc(scandir) + '</code> — run one, then attach its output file in Evidence.</div>'
        + '</div>';
    }

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
    // The router replaces #view's innerHTML each render but REUSES the #view element, so delegated
    // listeners bound on it would stack on every re-render — the Paste-Output toggle would then fire
    // an even number of times (open→closed = no-op) and ingests would duplicate. Bind on the coach's
    // own container instead: it's recreated on each render, so its listeners die with the old DOM.
    var mount = ctx.mount.querySelector('.withrail') || ctx.mount;
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
    // dismiss the workspace scaffold banner
    U.on(mount, 'click', '.ws-done', function () {
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.wsScaffoldDone = true; }, 'ui');
      OBOL.router.render();
    });
    // paste-back: toggle this move's inline ingestion box (no route jump — ingest right here)
    U.on(mount, 'click', '.btn-pasteback', function (e, t) {
      var art = t.closest('.move'); if (!art) return;
      var box = art.querySelector('.move-ingest'); if (!box) return;
      var open = box.hasAttribute('hidden');
      if (open) { box.removeAttribute('hidden'); } else { box.setAttribute('hidden', ''); }
      t.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) { var ta = box.querySelector('.mi-text'); if (ta) ta.focus(); }
    });
    // inline ingest: parse this move's output, mint facts, advance the coach
    U.on(mount, 'click', '.mi-go', function (e, t) {
      var box = t.closest('.move-ingest'); if (!box) return;
      var ta = box.querySelector('.mi-text'), out = box.querySelector('.mi-result');
      var text = (ta && ta.value) || '';
      if (!text.trim()) { if (out) out.textContent = 'Paste the output first.'; return; }
      if (out) out.textContent = 'Reading…';
      t.disabled = true;
      OBOL.ingest.ensureParsers().then(function (okp) {
        if (!okp) { if (out) out.textContent = 'Parsers still loading — try again.'; t.disabled = false; return; }
        var r = OBOL.ingest.run({ text: text, command: box.getAttribute('data-cmd') || '',
          actionId: box.getAttribute('data-action') || '', source: 'paste' });
        if (!r.ok) { if (out) out.textContent = r.reason === 'parsers' ? 'Parsers still loading — try again.' : 'Nothing to parse.'; t.disabled = false; return; }
        if (r.added) {
          U.toast('Minted ' + r.added + ' fact' + (r.added === 1 ? '' : 's') + ' — recomputing');
          OBOL.router.render(); // coach advances: the move may now be satisfied and new moves appear
        } else {
          t.disabled = false;
          if (out) {
            // The output is always saved as evidence; only fact extraction may come up empty.
            out.innerHTML = r.parseError
              ? ('Output saved — the parser skipped part of it, no new facts. <a href="#/evidence/' + esc(box.getAttribute('data-action') || '') + '">Open in Evidence ↗</a>')
              : r.facts.length
                ? ('Recognized ' + r.facts.length + ', nothing new (already known).')
                : 'No facts recognized (output saved). <a href="#/evidence/' + esc(box.getAttribute('data-action') || '') + '">Set the command in Evidence ↗</a>';
          }
        }
      });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.path = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
