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

  // Scope lens (teaching filter, orthogonal to fact-gating): narrow the visible moves to a syllabus level
  // so a newcomer isn't handed the whole arsenal at once. Default 'oscp+' hides only the handful of
  // genuinely out-of-scope edge CVEs (zerologon/noPac/PrintNightmare/MS14-068/SCCM/WSUS); the operator
  // flips it any time. Persisted per-browser; a read in a private window simply falls back to the default.
  var LENS_KEY = 'obol.scope-lens', LENS_ORDER = { oscp: 0, 'oscp+': 1, beyond: 2, all: 2 };
  function lensGet() { try { var v = localStorage.getItem(LENS_KEY); return (v === 'oscp' || v === 'oscp+' || v === 'all') ? v : 'oscp+'; } catch (e) { return 'oscp+'; } }
  function lensSet(v) { try { localStorage.setItem(LENS_KEY, v); } catch (e) {} }
  function scopeAllowed(scope, lens) { if (lens === 'all') return true; return LENS_ORDER[scope || 'oscp'] <= LENS_ORDER[lens]; }

  // Small badges on each move: locus (where you operate) + scope (syllabus level). Both are derived in the
  // engine; the scope badge appears only above core so it reads as "heads-up, this is advanced", not noise.
  var LOCUS_LABEL = { R: ['remote', 'off-host from Kali'], F: ['on-host', 'one-shot command on the box'], I: ['interactive', 'interactive session on the box'] };
  function locusBadge(a) {
    var m = LOCUS_LABEL[a.locus] || LOCUS_LABEL.R;
    return '<span class="move-locus locus-' + esc(a.locus || 'R') + '" title="' + esc(m[1]) + '">' + esc(m[0]) + '</span>';
  }
  function scopeBadge(a) {
    if (!a.scope || a.scope === 'oscp') return '';
    var lbl = a.scope === 'beyond' ? 'beyond OSCP' : 'OSCP+';
    return '<span class="move-scope scope-' + esc(a.scope === 'beyond' ? 'beyond' : 'plus') + '" title="syllabus level: ' + esc(a.scope) + '">' + esc(lbl) + '</span>';
  }

  function phaseChip(phase) {
    return '<span class="ph-chip ph-' + esc(phase) + '">' + esc(phase) + '</span>';
  }

  // A slim one-line status strip linking to the global Loadout: not-set-up CTA, or a synced summary that
  // nudges a re-sync once the box snapshot is stale. Reads the per-browser profile straight from
  // localStorage (no dependency on the lazy arsenal.js), so it renders on the coach without loading it.
  var ARSENAL_STALE_DAYS = 21;
  function arsenalProfile() { try { return JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null'); } catch (e) { return null; } }
  function arsenalStrip() {
    var p = arsenalProfile();
    if (!p) {
      return '<a class="lo-strip lo-strip-cta" href="#/loadout"><span class="lo-strip-ico">⚙</span>'
        + '<span class="lo-strip-txt">Set up your attack box — obol tailors every command to the tools you have</span>'
        + '<span class="lo-strip-go">Loadout →</span></a>';
    }
    var present = 0; try { Object.keys(p.tools || {}).forEach(function (k) { if (p.tools[k] && p.tools[k].present) present++; }); } catch (e) {}
    var ageDays = p.savedAt ? (Date.now() - p.savedAt) / 86400000 : 0;
    var stale = ageDays > ARSENAL_STALE_DAYS;
    var txt = stale
      ? ('Loadout synced ' + Math.round(ageDays) + 'd ago — re-sync your box?')
      : ('Loadout: ' + present + ' tools · ' + (p.staged || []).length + ' staged ready');
    return '<a class="lo-strip ' + (stale ? 'lo-strip-stale' : 'lo-strip-ok') + '" href="#/loadout">'
      + '<span class="lo-strip-ico">' + (stale ? '⚠' : '✓') + '</span>'
      + '<span class="lo-strip-txt">' + esc(txt) + '</span><span class="lo-strip-go">Loadout →</span></a>';
  }

  function producesChips(action) {
    if (!action.produces.length) return '';
    var chips = action.produces.map(function (k) {
      return '<span class="fact-chip" title="' + esc(k) + '">' + esc(OBOL.util.titleCase(OBOL.pack.friendly(k))) + '</span>';
    }).join('');
    return '<div class="move-produces"><span class="mini-label">Proves</span>' + chips + '</div>';
  }

  // Tokens that come from proven facts, the engagement params, or the workspace — the operator fills
  // these on the sidebar or by pasting evidence, so they stay a "needs:" hint, not a text box.
  var DERIVED_TOKENS = {
    target: 1, domain: 1, basedn: 1, dc: 1, user: 1, password: 1, nthash: 1, lhost: 1,
    userlist: 1, hashfile: 1, wordlist: 1, dc_netbios: 1, dc_account: 1, domain_sid: 1,
    target_sam: 1, group: 1, ca_name: 1, template: 1, pfx: 1, nmap_ports: 1, krbtgt_hash: 1,
  };
  // Ad-hoc, operator-supplied free-text tokens get an inline fill box right on the card (the coach
  // stays a builder-free surface — this only completes a placeholder, no toggles). Nice labels/hints:
  var FILL_LABEL = { command: 'run on host', cmd: 'command', lport: 'listener port', rport: 'remote port', payload: 'payload', outfile: 'output file', url: 'URL', share: 'share', file: 'file', listener: 'listener' };
  var FILL_PH = { command: 'e.g. whoami /all', cmd: 'e.g. id', lport: '4444', payload: 'windows/x64/…', outfile: 'out.txt', url: 'http://…', share: 'C$', file: 'C:\\path\\file' };

  function commandsBlock(action, filled) {
    // Coach awareness: mark each variant obol has already seen you run (from the activity ledger) and, for
    // a non-sequenced move, float the un-run variants up so "preferred" is the next thing left to do — a
    // command you already ran (or one whose effect is already proven) stops being re-suggested at the top.
    var eng = OBOL.store.active() || {};
    var acts = eng.activities || [], params = eng.params || {};
    // Match on the TEMPLATE (v.run), not the filled command: a filled command carries the real domain /
    // user / password / target (pulled from facts and the active credential, which params may not hold), and
    // those lab-specific values would never appear in the recovered dispatch of an attached dump. The
    // template keeps them as {{tokens}} — stripped from the signature — so only the true action verbs remain.
    var items = filled.map(function (v, i) { return { v: v, i: i, ran: OBOL.command.commandWasRun(v.run || v.filled, acts, params) }; });
    if (!action.sequence) items = items.filter(function (x) { return !x.ran; }).concat(items.filter(function (x) { return x.ran; }));
    var firstUnrun = -1;
    for (var fu = 0; fu < items.length; fu++) { if (!items[fu].ran) { firstUnrun = fu; break; } }
    return items.map(function (x, pos) {
      var v = x.v, i = x.i;
      var unfilled = OBOL.command.unfilledTokens(v.filled);
      var derived = unfilled.filter(function (t) { return DERIVED_TOKENS[t]; });
      var fillable = unfilled.filter(function (t) { return !DERIVED_TOKENS[t]; });
      var warn = derived.length
        ? '<div class="cmd-needs">needs: ' + derived.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(', ') + '</div>'
        : '';
      // an inline input per ad-hoc token; typing substitutes live into the command + copy button.
      var fillRow = fillable.length
        ? '<div class="cmd-fill-row">' + fillable.map(function (t) {
            return '<label class="cmd-fill-lbl"><span>' + esc(FILL_LABEL[t] || t) + '</span>'
              + '<input class="cmd-fill" data-tok="' + esc(t) + '" placeholder="' + esc(FILL_PH[t] || ('value for ' + t)) + '" autocomplete="off" spellcheck="false"></label>';
          }).join('') + '</div>'
        : '';
      var note = v.note ? '<div class="cmd-note">' + esc(v.note) + '</div>' : '';
      // hands-on guidance for obol web: big output → tee to a file and attach it in Evidence.
      var webNote = v.webNote ? '<div class="cmd-webnote">✋ ' + esc(v.webNote) + '</div>' : '';
      var label = action.sequence ? ('step ' + (i + 1))
        : (x.ran ? 'already run' : (pos === firstUnrun ? 'preferred' : 'alt ' + pos));
      var ranTag = (x.ran && !action.sequence)
        ? '<span class="cmd-ran" title="obol saw this command in your run ledger — run the next one instead">✓ ran</span>' : '';
      return '<div class="cmd' + (x.ran ? ' cmd-ran-done' : '') + (fillable.length ? ' cmd-fillable' : '') + '"'
        + (fillable.length ? ' data-tmpl="' + U.attr(v.filled) + '"' : '') + '>'
        + '<div class="cmd-head"><span class="cmd-tag">' + esc(v.tool || action.tool || 'cmd') + '</span>'
        + '<span class="cmd-variant">' + label + '</span>' + ranTag
        + (v.win && !x.ran ? '<span class="cmd-win">☠ Pwn This Target</span>' : '')
        + '<button class="btn-copy" data-copy="' + U.attr(v.filled) + '" title="Copy command">copy</button></div>'
        + '<pre class="cmd-run"><code>' + esc(v.filled) + '</code></pre>'
        + fillRow + note + webNote + warn + '</div>';
    }).join('');
  }

  // "Set up the file this move reads" — obol proved the user list / hashes, so it hands back a
  // copy-paste heredoc that writes the exact file {{userlist}}/{{hashfile}} now points at. This is
  // the browser stand-in for obol-local materializing loot/users.txt on disk: obol can't write the
  // operator's box, so it gives them the one command that does, with the names it already parsed.
  function prepStep(tag, variant, cmd, note) {
    return '<div class="cmd cmd-prep">'
      + '<div class="cmd-head"><span class="cmd-tag">' + esc(tag) + '</span>'
      + '<span class="cmd-variant">' + esc(variant) + '</span>'
      + '<button class="btn-copy" data-copy="' + U.attr(cmd) + '" title="Copy command">copy</button></div>'
      + '<pre class="cmd-run"><code>' + esc(cmd) + '</code></pre>'
      + (note ? '<div class="cmd-note">' + esc(note) + '</div>' : '') + '</div>';
  }

  function prepBlock(action, facts, dirs) {
    if (!OBOL.loot) return '';
    var steps = '';
    // {{userlist}} — the move reads it and obol has proven users to write into it.
    if (OBOL.loot.actionUsesToken(action, 'userlist')) {
      var users = OBOL.loot.usernames(facts);
      var ulCmd = OBOL.loot.userlistCommand(facts, dirs);
      if (users.length && ulCmd) {
        steps += prepStep('write', 'creates ' + OBOL.loot.userlistPath(dirs),
          ulCmd, 'Run once — the ' + users.length + ' users obol proved, written where every command below reads them.');
      }
    }
    // {{hashfile}} as an INPUT (a crack move) — obol holds the roasted hashes as facts but no file
    // was written (a stdout roast), so give the operator the line that lays them down for cracking.
    var reqs = [].concat(action.requires_all || []);
    var cracksHashes = reqs.some(function (r) { return /^hash\./.test(r); });
    if (cracksHashes && OBOL.loot.actionUsesToken(action, 'hashfile')) {
      var hfCmd = OBOL.loot.hashfileCommand(facts, action, dirs);
      if (hfCmd) {
        steps += prepStep('write', 'creates ' + OBOL.loot.hashfilePath(dirs, action),
          hfCmd, 'Lay the roasted hashes obol captured into the file the crack reads.');
      }
    }
    return steps ? '<div class="move-prep"><span class="mini-label">Set Up First</span>' + steps + '</div>' : '';
  }

  function moveCard(action, facts, params, opts) {
    opts = opts || {};
    var why = U.firstSentence(action.hypothesis || action.proves || action.title);
    var dnp = action.does_not_prove
      ? '<div class="move-dnp"><span class="mini-label">Does Not Prove</span>' + esc(action.does_not_prove) + '</div>'
      : '';
    var toolLink = (action.tool || (action.tools && action.tools[0]))
      ? '<a class="btn-ghost" href="#/tools/' + esc(action.tool || action.tools[0]) + '">Build in Tools ↗</a>'
      : '';
    var dirs = OBOL.workspace.tokens(OBOL.store.active());
    var filled = OBOL.command.fillAll(action, facts, { params: params, profile: (OBOL.store.active() || {}).profile, workspace: dirs });
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
      + locusBadge(action) + scopeBadge(action)
      + '<h3 class="move-title">' + esc(action.title) + '</h3></header>'
      + '<p class="move-why">' + esc(why) + '</p>'
      + prepBlock(action, facts, dirs)
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
    var objFacts = (facts.facts || []).filter(function (f) { return String(f.kind).indexOf('objective.') === 0 && f.state !== 'refuted'; });
    var flags = objFacts.filter(function (f) { return f.kind !== 'objective.flag_located'; });
    // Located-but-not-captured: found remotely (nxc/smb), still to be read from an on-host shell for the
    // report. Hide any whose value we have already captured on-host.
    var capturedVals = {}, capturedSlots = {};
    flags.forEach(function (f) { var v = f.value || {}; if (v.flag) capturedVals[v.flag] = 1; if (v.slot) capturedSlots[v.slot] = 1; });
    var locSeen = {};
    var located = objFacts.filter(function (f) {
      if (f.kind !== 'objective.flag_located') return false;
      var v = f.value || {};
      if ((v.flag && capturedVals[v.flag]) || (v.slot && capturedSlots[v.slot])) return false; // already captured on-host
      var key = v.path || v.flag || v.slot || ''; if (locSeen[key]) return false; locSeen[key] = 1; return true;
    });
    // Use the same deduped gather as the left switcher, so one recovered credential proven on two scopes
    // (e.g. host:10.x and host:10.y) shows ONCE here, not twice.
    var creds = [];
    try { creds = (OBOL.creds && OBOL.creds.gather) ? OBOL.creds.gather(eng, facts) : (facts.values('credential.available') || []); } catch (e) { creds = []; }
    var acts = (eng && eng.activities || []).slice(0, 4);
    return '<aside class="context-rail" aria-label="Live context">'
      + railCard('Access', '<div class="rail-access ra-' + access[1] + '">' + esc(access[0]) + '</div>')
      + railCard('Next move', topMove ? ('<div class="rail-move">' + esc(topMove.title) + '</div>') : '<div class="rail-empty">Log evidence to unlock moves.</div>')
      + railCard('Flags (' + flags.length + ')', (flags.length || located.length)
        ? '<ul class="rail-list rail-flags">' + flags.map(function (f) {
            var v = f.value || {}; var SL = { root: 'Root flag', local: 'Local flag', user: 'Local flag' };
            var label = SL[v.slot] || (f.kind.split('.').pop().replace('_', ' '));
            var val = v.flag || '';
            // Show the WHOLE flag (wrapped, selectable, click-to-copy) — a captured flag is the deliverable.
            return '<li class="rail-flag"><div class="rail-flag-h"><span>🚩 ' + esc(label) + '</span>'
              + (v.name ? '<span class="rail-flag-file" title="' + U.attr(v.path || v.name) + '">' + esc(v.name) + '</span>' : '') + '</div>'
              + (val ? '<code class="rail-flag-val" data-copy="' + U.attr(val) + '" title="Click to copy">' + esc(val) + '</code>' : '') + '</li>';
          }).join('')
          + located.map(function (f) {
            var v = f.value || {}; var SL = { root: 'Root flag', local: 'Local flag', user: 'Local flag' };
            var label = SL[v.slot] || 'Flag';
            return '<li class="rail-located" title="' + U.attr('located remotely at ' + (v.path || v.name || '') + ' — read it from an on-host shell for the report') + '"><span>📍 ' + esc(label) + ' <em>located</em></span><span class="rail-produced">capture on-host</span></li>';
          }).join('')
          + '</ul>' + (located.length ? '<div class="rail-note">📍 located remotely — read on the host (interactive shell) so it counts for the report.</div>' : '')
        : '<div class="rail-empty">None captured yet.</div>')
      + railCard('Credentials (' + creds.length + ')', creds.length
        ? '<ul class="rail-list">' + creds.slice(0, 6).map(function (c) {
            var secret = c.secret || c.password || c.nthash || c.hash || '';
            var redact = !!((eng || {}).ui || {}).reportRedact;
            var shown = !secret ? '' : (redact ? '••••••••' : (secret.length > 22 ? secret.slice(0, 22) + '…' : secret));
            return '<li><span>' + esc(c.user || c.username || 'user') + (c.domain ? '@' + esc(c.domain) : '') + '</span>'
              + (shown ? '<span class="rail-secret"' + (redact ? '' : ' title="' + U.attr(secret) + '"') + '>' + esc(shown) + '</span>' : '') + '</li>';
          }).join('') + '</ul>'
        : '<div class="rail-empty">None validated yet.</div>')
      + railCard('Recent evidence', (acts.length
        ? '<ul class="rail-list rail-acts">' + acts.map(function (a) { var c = a.command || (a.file ? a.file : 'pasted output'); return '<li title="' + U.attr(c) + '"><code>' + esc(c.length > 30 ? c.slice(0, 30) + '…' : c) + '</code><span class="rail-produced">' + ((a.produced || []).length) + '</span></li>'; }).join('') + '</ul>'
        : '<div class="rail-empty">Paste tool output on Evidence.</div>')
        + '<a class="rail-link" href="#/history">View full Run Log →</a>')
      + '</aside>';
  }
  OBOL.rail = { html: buildRail };

  function render(ctx) {
    var eng = OBOL.store.active();
    var facts = OBOL.store.factSet();
    var params = (eng && eng.params) || {};
    var pack = OBOL.packs.actions();
    var doneIds = {};
    // 'done' = the operator ticked it; 'empty' = its tool ran and proved nothing (a useless path RIGHT NOW,
    // e.g. no SCCM in this environment). Both retire the move from the ready list. The un-retire test is per
    // MOVE, not per fact-KIND: a move stays retired only while NONE of its OWN runs ever produced a fact,
    // and comes back the moment a run attributed to it produces one (new evidence revealing it is no longer
    // a dead end). Checking the fact kind globally was wrong — sccm-enum "produces" credential.candidate,
    // which you already hold from an unrelated AS-REP crack, so it never retired.
    function moveEverProduced(actionId) {
      return (eng.activities || []).some(function (a) { return a && a.action_id === actionId && (a.produced || []).length > 0; });
    }
    Object.keys((eng && eng.checklist) || {}).forEach(function (k) {
      var st = eng.checklist[k];
      if (st === 'done') { doneIds[k] = true; return; }
      if (st === 'empty' && !moveEverProduced(k)) doneIds[k] = true; // never paid off → stay retired
    });

    var focus = (OBOL.profile && eng && eng.profile) ? OBOL.profile.machineFocus(eng.profile.machine_type) : [];
    var ranked = (OBOL.pack.rankActions || OBOL.pack.nextActions)(facts, pack, { doneIds: doneIds, focusPrefixes: focus });
    var frontier = OBOL.phases.frontierIndex(facts);
    var onFlow = [], comingUp = [];
    ranked.forEach(function (a) {
      if (OBOL.phases.prematurity(a, facts) === 0) onFlow.push(a); else comingUp.push(a);
    });
    var locked = OBOL.pack.lockedActions(facts, pack);

    // Scope lens: filter the visible moves to the chosen syllabus level. Count what the lens hides so the
    // operator always knows there's more one click away (never a silent disappearance).
    var lens = lensGet();
    function inLens(a) { return scopeAllowed(a.scope, lens); }
    var hiddenBy = 0;
    function applyLens(arr) { var kept = arr.filter(inLens); hiddenBy += arr.length - kept.length; return kept; }
    onFlow = applyLens(onFlow);
    comingUp = applyLens(comingUp);
    locked = locked.filter(function (p) { if (inLens(p.action)) return true; hiddenBy++; return false; });

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
      + '<div class="metric"><span class="metric-n">' + onFlow.length + '</span><span class="metric-l">Ready</span></div>'
      + '<div class="metric"><span class="metric-n">' + comingUp.length + '</span><span class="metric-l">Coming Up</span></div>'
      + '<div class="metric"><span class="metric-n">' + locked.length + '</span><span class="metric-l">Blocked</span></div>'
      + '<div class="metric"><span class="metric-n">' + factCount + '</span><span class="metric-l">Facts</span></div>'
      + '</div></div>';

    html += arsenalStrip();

    // Scope lens control: a newcomer-safe syllabus filter. OSCP (core only) · OSCP+ (adds modern AD) ·
    // All (the full arsenal, edge CVEs included). The hidden-count hint keeps it honest.
    html += '<div class="coach-lens" role="group" aria-label="Syllabus scope filter">'
      + '<span class="coach-lens-label">Scope</span>'
      + ['oscp', 'oscp+', 'all'].map(function (v) {
          var txt = v === 'oscp' ? 'OSCP' : (v === 'oscp+' ? 'OSCP+' : 'All');
          return '<button type="button" class="lens-opt' + (lens === v ? ' on' : '') + '" data-lens="' + v + '"'
            + ' aria-pressed="' + (lens === v ? 'true' : 'false') + '">' + txt + '</button>';
        }).join('')
      + (hiddenBy ? '<span class="coach-lens-hint">' + hiddenBy + ' move' + (hiddenBy === 1 ? '' : 's') + ' above this level — tap <strong>All</strong> to show</span>' : '')
      + '</div>';

    // Planned route to the objective: the planner's lowest-cost dependable path from what's proven to
    // the goal. Re-planned on every render as evidence accrues. A plausible route, not a promise — the
    // box decides which steps actually land; this sharpens as you capture more.
    var route = OBOL.pack.planPath ? OBOL.pack.planPath(facts, pack, {}) : null;
    if (route && route.reachable && route.path && route.path.length > 1 && factCount > 1) {
      html += '<details class="coach-route"><summary class="coach-sec-h">Planned route to the objective'
        + ' <span class="coach-route-n">' + route.path.length + ' steps</span></summary>'
        + '<ol class="coach-route-list">'
        + route.path.map(function (id, i) {
          var a = pack.filter(function (x) { return x.id === id; })[0];
          return '<li class="coach-route-step' + (i === 0 ? ' next' : '') + '">' + esc(a ? a.title : id) + '</li>';
        }).join('')
        + '</ol>'
        + '<div class="coach-route-note">The shortest dependable path from what you’ve proven to the goal — it re-plans as you capture evidence. A plausible route, not a guarantee.</div>'
        + '</details>';
    }

    // one-time workspace scaffold: create the output tree once, then every command below writes
    // into it and tells you which file to attach. Dismissible; auto-hides once you're rolling.
    if (OBOL.workspace.isConfigured(eng) && !((eng.ui || {}).wsScaffoldDone) && factCount < 3) {
      var scaffold = OBOL.workspace.scaffold(eng);
      var scandir = OBOL.workspace.tokens(eng).scandir;
      var stamp = OBOL.workspace.promptStamp ? OBOL.workspace.promptStamp((params || {}).lhost_iface || '') : (OBOL.workspace.PROMPT_STAMP_ZSH || '');
      html += '<div class="ws-banner">'
        + '<div class="ws-banner-h">📁 Set up your working directory — run this once on your Kali box:</div>'
        + '<pre class="cmd-run"><code>' + esc(scaffold) + '</code></pre>'
        + '<div class="ws-banner-actions"><button class="btn-copy" data-copy="' + U.attr(scaffold) + '">copy</button>'
        + '<button class="btn-ghost ws-done">Got It</button></div>'
        + '<div class="ws-banner-note">Commands below write into <code>' + esc(scandir) + '</code> — run one, then attach its output file in Evidence.</div>'
        + (stamp
          ? ('<details class="ws-stamp"><summary>Optional: stamp your prompt with the time + VPN IP <span class="ev-import-tag">recommended</span></summary>'
            + '<div class="ws-banner-note">Paste this into <code>~/.zshrc</code> once. It prints a dim <code>[UTC time] [tun0:IP]</code> line before each prompt (your prompt is untouched), so later you can paste your <strong>whole session</strong> into Evidence and obol orders it correctly and auto-fills your <code>{{lhost}}</code>.</div>'
            + '<pre class="cmd-run"><code>' + esc(stamp) + '</code></pre>'
            + '<div class="ws-banner-actions"><button class="btn-copy" data-copy="' + U.attr(stamp) + '">copy</button></div>'
            + '</details>')
          : '')
        + '</div>';
    }

    // ready (on-flow) moves — cap the visible list to the top few so a late-game frontier (where the whole
    // pack is technically "ready") doesn't bury the actual next move under an encyclopedia. The rest fold
    // into a collapsed "More ready moves" so nothing is lost, just quieted.
    var READY_CAP = 6;
    if (onFlow.length) {
      var top = onFlow.slice(0, READY_CAP), rest = onFlow.slice(READY_CAP);
      html += '<div class="coach-section"><h2 class="coach-sec-h">Ready now</h2>';
      top.forEach(function (a, i) { html += moveCard(a, facts, params, { primary: i === 0 }); });
      html += '</div>';
      if (rest.length) {
        html += '<details class="coach-section coach-more"><summary class="coach-sec-h">More ready moves — lower priority right now (' + rest.length + ')</summary>';
        rest.forEach(function (a) { html += moveCard(a, facts, params, {}); });
        html += '</details>';
      }
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
    U.on(mount, 'click', '.rail-flag-val', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Flag copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    U.on(mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    // inline free-text token fill ({{command}} etc.): substitute live into the command + copy button.
    U.on(mount, 'input', '.cmd-fill', function (e, t) {
      var cmd = t.closest('.cmd'); if (!cmd) return;
      var out = cmd.getAttribute('data-tmpl') || '';
      Array.prototype.forEach.call(cmd.querySelectorAll('.cmd-fill'), function (inp) {
        var val = (inp.value || '').trim();
        if (val) out = out.split('{{' + inp.getAttribute('data-tok') + '}}').join(val);
      });
      var code = cmd.querySelector('.cmd-run code'); if (code) code.textContent = out;
      var copy = cmd.querySelector('.btn-copy'); if (copy) copy.setAttribute('data-copy', out);
    });
    // scope lens: persist the choice and re-render the coach at the new syllabus level
    U.on(mount, 'click', '.lens-opt', function (e, t) {
      var v = t.getAttribute('data-lens'); if (!v) return;
      lensSet(v);
      OBOL.router.render();
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
          var aid = box.getAttribute('data-action') || '';
          var toolNm = ((box.getAttribute('data-cmd') || '').trim().split(/\s+/)[0] || '').split('/').pop().replace(/\.(py|exe)$/, '') || 'the tool';
          var bodyLines = text.trim().split(/\r?\n/).filter(function (l) { return l.trim(); }).length;
          // The move's tool ran to completion and proved nothing HERE (a useless path right now — e.g. no
          // SCCM in the environment): acknowledge it and retire the move from the coach instead of
          // re-suggesting a command already run. Guarded so a junk paste or a broken/denied run does NOT
          // retire — and so RE-PASTING evidence that already paid off (this MOVE produced facts on an
          // earlier run) never buries a move you still need. Judged per move (its own activities), not by a
          // fact-kind that some unrelated move may have produced.
          var eng2 = OBOL.store.active() || {};
          var moveEverPaid = (eng2.activities || []).some(function (a) { return a && a.action_id === aid && (a.produced || []).length > 0; });
          if (aid && !moveEverPaid && !r.parseError && r.recognizedTool && !r.looksError && bodyLines >= 2) {
            OBOL.store.update(function (engg) { engg.checklist = engg.checklist || {}; engg.checklist[aid] = 'empty'; }, 'done');
            U.toast(toolNm + ' ran — nothing found here. Retired from the coach.');
            OBOL.router.render();
            return;
          }
          t.disabled = false;
          if (out) {
            // The output is always saved as evidence; only fact extraction may come up empty.
            out.innerHTML = r.parseError
              ? ('Output saved — the parser skipped part of it, no new facts. <a href="#/evidence/' + esc(aid) + '">Open in Evidence ↗</a>')
              : r.facts.length
                ? ('Recognized ' + r.facts.length + ', nothing new (already known).')
                : 'No facts recognized (output saved). <a href="#/evidence/' + esc(aid) + '">Set the command in Evidence ↗</a>';
          }
        }
      });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.path = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
