/*!
 * obol ui, routes/library.js, the LIBRARY tab.
 *
 * A read-only catalogue of everything obol knows, for exploring on your own terms (not the coach, not
 * ranked). Four lenses, as sub-tabs, opening on Moves:
 *   Moves    : a faceted card browser (lane / phase / port / service / tool / OS / kind + search),
 *              lane-hued, reusing the Next Steps tile. Each move expands to its commands, field notes,
 *              Build In Workbench, and Seed Into Stuck?. A "Relevant To My Box" toggle (when an
 *              engagement is active) narrows to the moves eligible against your facts (NOT a ranker fork,
 *              just the move's own eligibility).
 *   Commands : the hero lens. Every distinct command template obol carries, deduped, with back-link
 *              chips to every move that uses it, grouped Tool -> Capability (nxc split by protocol), with
 *              a Flatten toggle and a search. Phase-tinted. Auto-filled from the active engagement. One tap copies.
 *   ATT&CK   : a library-scoped matrix (what obol CAN do): every technique obol performs, tactic-coloured,
 *              each opening to the moves AND example commands behind it. Distinct from the Findings tab's
 *              engagement-scoped matrix (what you HAVE done).
 *   Stuck?   : the Ferryman, folded in unchanged (delegates to OBOL.routes.stuck).
 *
 * Boundaries (identical to the rest of obol): presentation only. It reads OBOL.library (pure engine over
 * the pack), the one filler (OBOL.command), and the active engagement's facts for fill/relevance. It
 * writes nothing, never forks the ranker, never changes the move graph. Pack commands are the source of truth.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr(s); }
  function L() { return OBOL.library || {}; }
  function pack() { try { return OBOL.packs.actions() || []; } catch (e) { return []; } }

  var LENSES = [
    { id: 'moves', label: 'Moves' },
    { id: 'commands', label: 'Commands' },
    { id: 'attack', label: 'ATT&CK' },
    { id: 'stuck', label: 'Stuck?' },
  ];

  // ── module state (per lens; all throwaway, none touches OBOL.store) ──────────────────────────────
  var _mount = null;
  var _lens = 'moves';
  // Moves lens. _mExp is a SET of open move ids: click toggles one, it stays open until clicked again,
  // and any number can be open at once (Expand All / Collapse All drive the whole set).
  var _mSel = {};          // { group: [keys] }
  var _mQ = '';            // search
  var _mExp = {};          // { moveId: true } open cards
  var _mRelevant = false;  // "relevant to my box" toggle
  var _facetOpen = { lane: true, phase: true, service: false, port: false, tool: false, os: false, tag: false };
  // Commands lens. _cGroup is the organizing axis; _cExp is the SET of open command cards; _cGrpClosed
  // tracks which top-level groups the user collapsed (default open).
  var _cQ = '';
  var _cGroup = 'tool';    // 'tool' | 'phase' | 'lane' | 'flat'
  var _cExp = {};          // { templateKey: true } open cards
  var _cGrpClosed = {};    // { groupKey: true } collapsed groups
  // ATT&CK lens
  var _aSel = '';          // selected technique code

  function hasEng() { try { return !!(OBOL.store && OBOL.store.active && OBOL.store.active()); } catch (e) { return false; } }
  function engFacts() { try { return OBOL.store.factSet(); } catch (e) { return new OBOL.facts.FactSet([]); } }
  function engParams() { try { return (OBOL.store.active() || {}).params || {}; } catch (e) { return {}; } }
  function reducedMotion() { try { return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } }

  // ── sub-tab bar ──────────────────────────────────────────────────────────────────────────────────
  function tabsHtml() {
    return '<nav class="lib-tabs" aria-label="Library lenses">' + LENSES.map(function (t) {
      var on = t.id === _lens;
      return '<a class="lib-tab' + (on ? ' active' : '') + '" href="#/library/' + t.id + '"'
        + (on ? ' aria-current="page"' : '') + '>' + esc(t.label) + '</a>';
    }).join('') + '</nav>';
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // MOVES LENS
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  function laneClassForMove(move) {
    var pk = L().laneOf(move.id);
    return 'lane-' + (L().laneHue ? L().laneHue(pk) : 'checks');
  }
  function locusLabel(l) { return l === 'R' ? 'On Your Box' : (l === 'F' ? 'On The Target' : (l === 'I' ? 'Interactive' : '')); }

  function wbTargetsFor(move) {
    // Reuse the Stuck? route's Build In Workbench classifier when it is loaded (same group), else nothing.
    try { if (OBOL.routes.stuck && OBOL.routes.stuck._wbTargets) return OBOL.routes.stuck._wbTargets(move); } catch (e) {}
    return [];
  }

  function moveCmdRows(move) {
    var facts = engFacts(), params = engParams(), filled = [];
    try { filled = OBOL.command.fillAll(move, facts, { params: params }); } catch (e) { filled = []; }
    var cmds = (move.commands && move.commands.length) ? move.commands : (move.command ? [{ run: move.command }] : []);
    if (!cmds.length) return '<p class="lib-cmd-none">This move carries no command template (it is a decision or a manual step).</p>';
    return cmds.map(function (c, i) {
      var text = (filled[i] && filled[i].filled) || c.run || '';
      if (!text) return '';
      return '<div class="lib-cmd"><code>' + esc(text) + '</code>'
        + '<button class="btn-copy lib-copy" data-copy="' + attr(text) + '" aria-label="Copy command">Copy</button></div>'
        + (c.note ? '<p class="lib-cmd-note">' + esc(c.note) + '</p>' : '');
    }).join('');
  }
  function moveNoteBlock(move) {
    var note = OBOL.fieldNote ? OBOL.fieldNote(move, 0) : null;
    if (!note) return '';
    var html = '';
    var land = (note.land || []).slice(0, 3);
    if (land.length) html += '<div class="lib-fn"><span class="lib-fn-l">How To Land It</span><ul>' + land.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul></div>';
    if (note.win) html += '<div class="lib-fn"><span class="lib-fn-l">You Win When</span><p>' + esc(note.win) + '</p></div>';
    var miss = (note.mistakes || []).slice(0, 2);
    if (miss.length) html += '<div class="lib-fn"><span class="lib-fn-l">Common Mistakes</span><ul>' + miss.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul></div>';
    return html;
  }
  function moveWhy(move) {
    var note = OBOL.fieldNote ? OBOL.fieldNote(move, 0) : null;
    if (note && note.when) return note.when;
    if (move.hypothesis) return U.firstSentence ? U.firstSentence(move.hypothesis) : move.hypothesis;
    if (move.proves) return move.proves;
    return 'A reference move. Open it for its commands and field notes.';
  }
  function moveActions(move) {
    var out = '';
    var wb = wbTargetsFor(move);
    (wb || []).forEach(function (x) {
      out += '<a class="lib-act" href="#/workbench/' + esc(x.tab) + '">' + esc(x.label) + ' <span aria-hidden="true">&rarr;</span></a>';
    });
    out += '<button type="button" class="lib-act lib-seed" data-seed-move="' + esc(move.id) + '">Seed Into Stuck? <span aria-hidden="true">&rarr;</span></button>';
    return '<div class="lib-move-actions">' + out + '</div>';
  }
  function moveTile(move) {
    var ph = L().phaseOf ? L().phaseOf(move) : (move.phase || 'enum');
    var selected = !!_mExp[move.id];
    var loc = locusLabel(move.locus);
    var laneLabel = L().laneLabel(L().laneOf(move.id));
    var cls = 'ns-card lib-move ' + laneClassForMove(move) + ' ns-ph-' + ph + (selected ? ' selected is-glow' + (reducedMotion() ? '' : ' ns-bloom') : '');
    // Show the phase chip unless it would just echo the lane name (the Recon lane at the recon phase
    // would otherwise read "Recon Recon").
    var phChip = (String(laneLabel).toLowerCase() === String(ph).toLowerCase())
      ? '' : '<span class="ns-chip ns-phase ph-' + esc(ph) + '">' + esc(U.titleCase(ph)) + '</span>';
    var head = '<div class="ns-card-head">'
      + '<span class="ns-chip lib-lane-chip">' + esc(laneLabel) + '</span>' + phChip
      + (loc ? '<span class="ns-chip">' + esc(loc) + '</span>' : '') + '</div>';
    var foot = '<div class="ns-foot">' + esc(moveWhy(move)) + '</div>';
    var body = selected
      ? '<div class="ns-body">' + moveCmdRows(move) + moveNoteBlock(move) + moveActions(move) + '</div>'
      : '';
    return '<article class="' + cls + '" tabindex="0" role="button" aria-expanded="' + (selected ? 'true' : 'false') + '"'
      + ' data-move="' + esc(move.id) + '" aria-label="' + attr((move.title || move.id) + ', open its commands and notes') + '">'
      + head + '<h3 class="ns-title">' + esc(move.title || move.id) + '</h3>' + foot + body + '</article>';
  }

  function facetSidebarHtml() {
    var facets = L().facets(pack());
    return '<aside class="lib-facets" aria-label="Filter moves">' + facets.map(function (f) {
      var open = !!_facetOpen[f.group];
      var active = (_mSel[f.group] || []).length;
      var chips = f.values.map(function (v) {
        var on = (_mSel[f.group] || []).indexOf(v.key) >= 0;
        var hue = (f.group === 'lane' && v.hue) ? ' lane-' + v.hue : '';
        return '<button type="button" class="lib-facet' + (on ? ' on' : '') + hue + '" data-facet="' + esc(f.group) + '" data-val="' + esc(v.key) + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
          + '<span class="lib-facet-l">' + esc(v.label) + '</span><span class="lib-facet-n">' + v.count + '</span></button>';
      }).join('');
      return '<details class="lib-facet-grp"' + (open ? ' open' : '') + ' data-grp="' + esc(f.group) + '">'
        + '<summary><span class="lib-facet-h">' + esc(f.label) + '</span>'
        + (active ? '<span class="lib-facet-active">' + active + '</span>' : '') + '</summary>'
        + '<div class="lib-facet-vals">' + chips + '</div></details>';
    }).join('') + '</aside>';
  }

  function movesResultsHtml() {
    var list = L().filter(pack(), _mSel, _mQ);
    if (_mRelevant && hasEng()) {
      var facts = engFacts();
      list = list.filter(function (a) { try { return a.eligible && a.eligible(facts); } catch (e) { return false; } });
    }
    var total = pack().length;
    var xpand = list.length ? '<div class="lib-xpand"><button type="button" class="lib-clear" data-mexpand>Expand All</button><button type="button" class="lib-clear" data-mcollapse>Collapse All</button></div>' : '';
    var head = '<div class="lib-results-head"><span class="lib-count">' + list.length + ' of ' + total + ' moves</span>'
      + xpand + anyActiveFilterHtml() + '</div>';
    if (!list.length) {
      return head + '<p class="lib-empty">No moves match those filters. Clear a facet or widen your search.</p>';
    }
    // Order phase-first (recon -> loot), then lane, then title. Phase-first is the natural methodology
    // reading order AND it interleaves the lanes, so the opening screen shows the full lane-hue spectrum
    // (recon from AD, Web, Recon, DB side by side) instead of one lane's colour clumped at the top.
    var PH = { recon: 0, enum: 1, creds: 2, access: 3, escalate: 4, loot: 5 };
    list.sort(function (a, b) {
      var pa = PH[L().phaseOf(a)] || 0, pb = PH[L().phaseOf(b)] || 0;
      if (pa !== pb) return pa - pb;
      var la = (OBOL.ACTION_PACKS || []).indexOf(L().laneOf(a.id)), lb = (OBOL.ACTION_PACKS || []).indexOf(L().laneOf(b.id));
      if (la !== lb) return la - lb;
      return (a.title || a.id).localeCompare(b.title || b.id);
    });
    return head + '<div class="ns-grid lib-moves-grid">' + list.map(moveTile).join('') + '</div>';
  }
  function anyActiveFilterHtml() {
    var n = Object.keys(_mSel).reduce(function (s, g) { return s + (_mSel[g] || []).length; }, 0) + (_mQ ? 1 : 0) + (_mRelevant ? 1 : 0);
    return n ? '<button type="button" class="lib-clear" data-clear-moves>Clear Filters</button>' : '';
  }

  function movesLensHtml() {
    var relevant = hasEng()
      ? '<label class="lib-toggle"><input type="checkbox" id="lib-relevant"' + (_mRelevant ? ' checked' : '') + '><span>Only What Is Relevant To My Box</span></label>'
      : '';
    return '<div class="lib-lens lib-lens-moves">'
      + '<div class="lib-lens-bar">'
      + '<div class="lib-search"><input type="search" id="lib-moves-q" value="' + attr(_mQ) + '" placeholder="Search moves, tools, commands" autocomplete="off" spellcheck="false" aria-label="Search moves"></div>'
      + relevant + '</div>'
      + '<div class="lib-split">' + facetSidebarHtml()
      + '<section class="lib-results" id="lib-moves-results" aria-live="polite">' + movesResultsHtml() + '</section>'
      + '</div></div>';
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // COMMANDS LENS (hero)
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  function phaseTintClass(ph) { return 'ns-ph-' + (ph || 'enum'); }
  function fillTemplate(tpl) {
    if (!hasEng()) return tpl;
    try { return L().fill(tpl, engFacts(), engParams()) || tpl; } catch (e) { return tpl; }
  }
  function cmdCard(entry) {
    var key = entry.template;
    var selected = !!_cExp[key];
    var shown = fillTemplate(entry.template);
    var moves = entry.moves || [];
    var moveChips = moves.slice(0, selected ? moves.length : 3).map(function (m) {
      return '<a class="lib-cmd-move" href="#/library/moves" data-jump-move="' + esc(m.id) + '" title="' + attr(m.title) + '">' + esc(m.title) + '</a>';
    }).join('');
    var more = (!selected && moves.length > 3) ? '<span class="lib-cmd-more">+' + (moves.length - 3) + ' more</span>' : '';
    var note = '';
    if (selected) {
      var withNote = moves.filter(function (m) { return m.note; });
      if (withNote.length) note = '<div class="lib-cmd-notes">' + withNote.map(function (m) {
        return '<p class="lib-cmd-ctx"><span class="lib-cmd-ctx-m">' + esc(m.title) + '</span> ' + esc(m.note) + '</p>';
      }).join('') + '</div>';
    }
    var ph = entry.phase || 'enum';
    return '<article class="lib-ccard ' + phaseTintClass(ph) + (selected ? ' selected' : '') + '" data-tpl="' + attr(key) + '">'
      + '<div class="lib-ccard-top">'
      + '<code class="lib-ccard-run">' + esc(shown) + '</code>'
      + '<button type="button" class="btn-copy lib-copy" data-copy="' + attr(shown) + '" aria-label="Copy command">Copy</button></div>'
      + '<div class="lib-ccard-moves"><span class="ns-chip ns-phase ph-' + esc(ph) + ' lib-ccard-ph">' + esc(U.titleCase(ph)) + '</span>'
      + '<span class="lib-ccard-used">Used by</span>' + moveChips + more + '</div>'
      + note + '</article>';
  }
  var CGROUPS = [['tool', 'Tool'], ['phase', 'Phase'], ['lane', 'Lane'], ['flat', 'Flat']];
  function commandsBodyHtml() {
    if (_cGroup === 'flat') {
      var list = L().commandCatalog(pack()), needle = (_cQ || '').trim().toLowerCase();
      if (needle) list = list.filter(function (e) {
        return (e.template + ' ' + e.tool + ' ' + e.capability + ' ' + e.phase + ' ' + L().laneLabel(e.lane) + ' ' + (e.moves || []).map(function (m) { return m.title; }).join(' ')).toLowerCase().indexOf(needle) >= 0;
      });
      list.sort(function (a, b) { return (b.moves.length - a.moves.length) || a.template.localeCompare(b.template); });
      if (!list.length) return '<p class="lib-empty">No commands match that search.</p>';
      return '<div class="lib-cmd-list lib-cmd-flat">' + list.map(cmdCard).join('') + '</div>';
    }
    var groups = L().commandsGrouped(pack(), _cQ, _cGroup);
    if (!groups.length) return '<p class="lib-empty">No commands match that search.</p>';
    return groups.map(function (g) {
      var subs = g.subs.map(function (c) {
        return '<div class="lib-cap"><h4 class="lib-cap-h">' + esc(c.label) + ' <span class="lib-cap-n">' + c.cmds.length + '</span></h4>'
          + '<div class="lib-cmd-list">' + c.cmds.map(cmdCard).join('') + '</div></div>';
      }).join('');
      var open = !_cGrpClosed[g.key];
      var hue = g.hue ? ' style="--ghue:' + g.hue + '"' : '';
      return '<details class="lib-tool-grp"' + (open ? ' open' : '') + ' data-grp="' + attr(g.key) + '"' + hue + '>'
        + '<summary><span class="lib-tool-h">' + esc(g.label) + '</span>'
        + '<span class="lib-tool-n">' + g.count + '</span></summary><div class="lib-caps">' + subs + '</div></details>';
    }).join('');
  }
  // the Expand/Collapse row + the results, refreshed together on a group-by or search change. Kept in
  // its own container (id=lib-cmd-area) so the Group By control and search stay put, exactly as the Moves
  // facet sidebar stays put while only #lib-moves-results refreshes (delegated handlers never detach).
  function commandsAreaHtml() {
    var expandAll = (_cGroup === 'flat') ? ''
      : '<div class="lib-results-head lib-cmd-head"><div class="lib-xpand"><button type="button" class="lib-clear" data-cexpand>Expand All</button><button type="button" class="lib-clear" data-ccollapse>Collapse All</button></div></div>';
    return expandAll + '<section class="lib-results" id="lib-cmd-results" aria-live="polite">' + commandsBodyHtml() + '</section>';
  }
  function commandsLensHtml() {
    var cat = L().commandCatalog(pack());
    var fillNote = hasEng() ? '<span class="lib-fillnote">Filled from your active engagement.</span>' : '<span class="lib-fillnote">Tokens like {{target}} fill once you open an engagement.</span>';
    var groupBy = '<div class="lib-groupby" role="group" aria-label="Group commands by">'
      + '<span class="lib-groupby-l">Group By</span>'
      + CGROUPS.map(function (g) { return '<button type="button" class="lib-seg' + (_cGroup === g[0] ? ' on' : '') + '" data-cgroup="' + g[0] + '" aria-pressed="' + (_cGroup === g[0] ? 'true' : 'false') + '">' + esc(g[1]) + '</button>'; }).join('')
      + '</div>';
    return '<div class="lib-lens lib-lens-commands">'
      + '<div class="lib-lens-bar">'
      + '<div class="lib-search"><input type="search" id="lib-cmd-q" value="' + attr(_cQ) + '" placeholder="Search commands, tools, moves" autocomplete="off" spellcheck="false" aria-label="Search commands"></div>'
      + groupBy + '<span class="lib-count">' + cat.length + ' distinct commands</span>' + fillNote + '</div>'
      + '<div id="lib-cmd-area">' + commandsAreaHtml() + '</div></div>';
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // ATT&CK LENS (library-scoped: what obol CAN do)
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  function tacticHue(id) {
    var tacs = L().tactics ? L().tactics() : [];
    var i = 0; for (var j = 0; j < tacs.length; j++) { if (tacs[j].id === id) { i = j; break; } }
    return 'hsl(' + ((i * 37) % 360) + ', 62%, 56%)';
  }
  function tacticName(id) {
    var tacs = L().tactics ? L().tactics() : [];
    for (var j = 0; j < tacs.length; j++) { if (tacs[j].id === id) return tacs[j].name; }
    return id;
  }
  function attackLensHtml() {
    var techs = L().techniqueLibrary(pack());
    if (!techs.length) return '<div class="lib-lens lib-lens-attack"><p class="lib-empty">The ATT&CK map is not loaded in this build.</p></div>';
    // group techniques by their first tactic, in ATT&CK matrix order.
    var tacs = L().tactics ? L().tactics() : [];
    var byTac = {};
    techs.forEach(function (t) { var k = (t.tactics && t.tactics[0]) || 'other'; (byTac[k] = byTac[k] || []).push(t); });
    var order = tacs.map(function (t) { return t.id; }).filter(function (id) { return byTac[id]; });
    Object.keys(byTac).forEach(function (k) { if (order.indexOf(k) < 0) order.push(k); });
    var cols = order.map(function (tid) {
      var hue = tacticHue(tid);
      var cells = byTac[tid].map(function (t) {
        var on = t.id === _aSel;
        var cN = t.cmdCount || 0;
        return '<button type="button" class="lib-tcell' + (on ? ' on' : '') + '" data-tech="' + esc(t.id) + '" style="--tac:' + hue + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
          + '<span class="lib-tcell-n">' + esc(t.name) + '</span>'
          + '<span class="lib-tcell-meta">' + esc(t.id) + ' &middot; ' + t.moves.length + ' move' + (t.moves.length === 1 ? '' : 's')
          + (cN ? ' &middot; ' + cN + ' cmd' + (cN === 1 ? '' : 's') : '') + '</span></button>';
      }).join('');
      return '<div class="lib-tcol" style="--tac:' + hue + '"><h3 class="lib-tcol-h">' + esc(tacticName(tid)) + '</h3><div class="lib-tcol-cells">' + cells + '</div></div>';
    }).join('');
    var detail = _aSel ? attackDetailHtml(_aSel, techs) : '<div class="lib-tdetail lib-tdetail-empty"><p>Select a technique to see the obol moves and commands behind it.</p></div>';
    return '<div class="lib-lens lib-lens-attack">'
      + '<p class="lib-attack-intro">Every ATT&CK technique obol can perform, with the moves and commands behind each. This is what obol <em>can</em> do, the whole lineup. For what you have actually done on a box, see the Findings tab\'s matrix.</p>'
      + '<div class="lib-attack-split"><div class="lib-matrix">' + cols + '</div>' + detail + '</div></div>';
  }
  function attackDetailHtml(code, techs) {
    var t = null; for (var i = 0; i < techs.length; i++) { if (techs[i].id === code) { t = techs[i]; break; } }
    if (!t) return '';
    var hue = tacticHue((t.tactics && t.tactics[0]) || 'other');
    var pk = pack(), byId = {}; pk.forEach(function (a) { byId[a.id] = a; });
    var moveList = t.moves.map(function (m) {
      var mv = byId[m.id];
      var cmd = mv && mv.commands && mv.commands[0] ? fillTemplate(mv.commands[0].run) : '';
      return '<li class="lib-tmove"><a href="#/library/moves" data-jump-move="' + esc(m.id) + '" class="lib-tmove-t">' + esc(m.title) + '</a>'
        + '<span class="lib-tmove-lane lane-' + esc(L().laneHue(L().laneOf(m.id))) + '">' + esc(L().laneLabel(L().laneOf(m.id))) + '</span>'
        + (cmd ? '<div class="lib-cmd"><code>' + esc(cmd) + '</code><button class="btn-copy lib-copy" data-copy="' + attr(cmd) + '" aria-label="Copy command">Copy</button></div>' : '')
        + '</li>';
    }).join('');
    var tactics = (t.tactics || []).map(function (id) { return '<span class="lib-ttag">' + esc(tacticName(id)) + '</span>'; }).join('');
    var link = t.url ? '<a class="lib-tlink" href="' + attr(t.url) + '" target="_blank" rel="noopener noreferrer">ATT&CK reference <span aria-hidden="true">&rarr;</span></a>' : '';
    return '<div class="lib-tdetail" style="--tac:' + hue + '">'
      + '<div class="lib-tdetail-head"><span class="lib-tdetail-id">' + esc(t.id) + '</span><h3 class="lib-tdetail-n">' + esc(t.name) + '</h3></div>'
      + '<div class="lib-ttags">' + tactics + '</div>'
      + '<h4 class="lib-tdetail-sub">obol Moves (' + t.moves.length + ')</h4><ul class="lib-tmoves">' + moveList + '</ul>'
      + link + '</div>';
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // SHELL + RENDER
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  var INTRO = '<p class="lib-intro">Browse everything obol knows. No ranking, no engagement needed: the full lineup of moves and commands, mapped onto ATT&CK, yours to explore.</p>';

  function lensBody() {
    if (_lens === 'moves') return movesLensHtml();
    if (_lens === 'commands') return commandsLensHtml();
    if (_lens === 'attack') return attackLensHtml();
    if (_lens === 'stuck') { try { return OBOL.routes.stuck.render({ name: 'stuck', args: [], mount: _mount }); } catch (e) { return '<p class="lib-empty">Stuck? is loading.</p>'; } }
    return '';
  }
  function render(ctx) {
    _mount = ctx.mount;
    var lens = (ctx.args && ctx.args[0]) || 'moves';
    if (!LENSES.some(function (t) { return t.id === lens; })) lens = 'moves';
    _lens = lens;
    return '<section class="library lib-lens-' + _lens + '">'
      + '<div class="lib-head"><h1 class="route-h1">Library</h1>' + INTRO + '</div>'
      + tabsHtml()
      + '<div class="lib-body" id="lib-body">' + lensBody() + '</div></section>';
  }

  // in-place refreshers (avoid a full hash navigation on every facet/search change)
  function refreshMoves() { var el = _mount && _mount.querySelector('#lib-moves-results'); if (el) el.innerHTML = movesResultsHtml(); }
  function refreshFacets() { var el = _mount && _mount.querySelector('.lib-facets'); if (el) el.outerHTML = facetSidebarHtml(); }
  // Keep each facet group's "N selected" badge in sync WITHOUT rebuilding the sidebar (which would
  // collapse the open <details> and lose scroll). A toggle updates only the badges, so a count never
  // goes stale, which is what left "Lane 2" showing after both lanes were deselected.
  function updateFacetBadges() {
    if (!_mount) return;
    var grps = _mount.querySelectorAll('.lib-facet-grp');
    for (var i = 0; i < grps.length; i++) {
      var d = grps[i], g = d.getAttribute('data-grp'), n = (_mSel[g] || []).length;
      var sum = d.querySelector('summary'); if (!sum) continue;
      var badge = sum.querySelector('.lib-facet-active');
      if (n) { if (!badge) { badge = document.createElement('span'); badge.className = 'lib-facet-active'; sum.appendChild(badge); } badge.textContent = n; }
      else if (badge) { badge.parentNode.removeChild(badge); }
    }
  }
  function refreshCommands() { var el = _mount && _mount.querySelector('#lib-cmd-results'); if (el) el.innerHTML = commandsBodyHtml(); }
  // group-by change: update the segmented control in place and refresh only the area below it (the
  // controls and search stay in the DOM, so no delegated handler detaches).
  function refreshCommandsArea() {
    var segs = _mount.querySelectorAll('.lib-seg');
    for (var i = 0; i < segs.length; i++) { var on = segs[i].getAttribute('data-cgroup') === _cGroup; segs[i].classList.toggle('on', on); segs[i].setAttribute('aria-pressed', on ? 'true' : 'false'); }
    var area = _mount.querySelector('#lib-cmd-area'); if (area) area.innerHTML = commandsAreaHtml();
  }
  function refreshAttack() { var el = _mount && _mount.querySelector('#lib-body'); if (el) el.innerHTML = attackLensHtml(); }
  // the moves matching the current facets/search/relevance (same selection movesResultsHtml renders).
  function currentMoves() {
    var list = L().filter(pack(), _mSel, _mQ);
    if (_mRelevant && hasEng()) { var f = engFacts(); list = list.filter(function (a) { try { return a.eligible && a.eligible(f); } catch (e) { return false; } }); }
    return list;
  }

  // ── mount ──────────────────────────────────────────────────────────────────────────────────────
  function mounted(ctx) {
    _mount = ctx.mount;
    var rootEl = _mount.querySelector('.library') || _mount;

    // shared: copy
    U.on(rootEl, 'click', '.lib-copy', function (e, t) { e.stopPropagation(); U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); }); });

    if (_lens === 'moves') {
      U.on(rootEl, 'input', '#lib-moves-q', function (e, t) { _mQ = t.value; refreshMoves(); });
      U.on(rootEl, 'change', '#lib-relevant', function (e, t) { _mRelevant = !!t.checked; refreshMoves(); });
      U.on(rootEl, 'click', '.lib-facet', function (e, t) {
        var g = t.getAttribute('data-facet'), v = t.getAttribute('data-val');
        var arr = _mSel[g] = _mSel[g] || [];
        var i = arr.indexOf(v); if (i >= 0) arr.splice(i, 1); else arr.push(v);
        if (!arr.length) delete _mSel[g];
        t.classList.toggle('on'); t.setAttribute('aria-pressed', t.classList.contains('on') ? 'true' : 'false');
        updateFacetBadges(); refreshMoves();
      });
      U.on(rootEl, 'click', '[data-clear-moves]', function () { _mSel = {}; _mQ = ''; _mRelevant = false; var q = _mount.querySelector('#lib-moves-q'); if (q) q.value = ''; var r = _mount.querySelector('#lib-relevant'); if (r) r.checked = false; refreshFacets(); refreshMoves(); });
      // remember which facet groups are open
      U.on(rootEl, 'toggle', '.lib-facet-grp', function (e, t) { var g = t.getAttribute('data-grp'); if (g) _facetOpen[g] = t.open; });
      // expand/collapse a move tile. Multi-open: a click toggles THIS card and leaves every other open
      // card open, so you can read several side by side; click again to close one.
      function toggleMove(id) { if (!id) return; if (_mExp[id]) delete _mExp[id]; else _mExp[id] = true; refreshMoves(); }
      U.on(rootEl, 'click', '.lib-move', function (e, t) {
        if (e.target && e.target.closest && e.target.closest('.ns-body')) return;
        toggleMove(t.getAttribute('data-move'));
      });
      U.on(rootEl, 'keydown', '.lib-move', function (e, t) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
          if (e.target && e.target.closest && e.target.closest('.ns-body')) return;
          e.preventDefault(); toggleMove(t.getAttribute('data-move'));
        }
      });
      U.on(rootEl, 'click', '[data-mexpand]', function () { currentMoves().forEach(function (a) { _mExp[a.id] = true; }); refreshMoves(); });
      U.on(rootEl, 'click', '[data-mcollapse]', function () { _mExp = {}; refreshMoves(); });
      // Seed Into Stuck?: seed the move's gating facts into the Stuck? sandbox, then switch to that lens.
      U.on(rootEl, 'click', '.lib-seed', function (e, t) {
        e.stopPropagation();
        var id = t.getAttribute('data-seed-move'), mv = null, pk = pack();
        for (var i = 0; i < pk.length; i++) { if (pk[i].id === id) { mv = pk[i]; break; } }
        if (mv && OBOL.routes.stuck && OBOL.routes.stuck.seed) {
          var kinds = (mv.requires_all || []).concat((mv.requires_any || []).slice(0, 1));
          try { OBOL.routes.stuck.seed(kinds, engParams()); } catch (err) {}
          OBOL.router.go('library/stuck');
        }
      });
    } else if (_lens === 'commands') {
      U.on(rootEl, 'input', '#lib-cmd-q', function (e, t) { _cQ = t.value; refreshCommands(); });
      // Group By axis: re-render the whole lens (the control, the Expand/Collapse row, and the body).
      U.on(rootEl, 'click', '[data-cgroup]', function (e, t) { var g = t.getAttribute('data-cgroup'); if (g && g !== _cGroup) { _cGroup = g; _cGrpClosed = {}; refreshCommandsArea(); } });
      // Expand/Collapse All drive the top-level <details> directly (no re-render), and remember the
      // collapsed set so a later search re-render keeps the choice.
      U.on(rootEl, 'click', '[data-cexpand]', function () { _cGrpClosed = {}; var ds = _mount.querySelectorAll('.lib-tool-grp'); for (var i = 0; i < ds.length; i++) ds[i].open = true; });
      U.on(rootEl, 'click', '[data-ccollapse]', function () { _cGrpClosed = {}; var ds = _mount.querySelectorAll('.lib-tool-grp'); for (var i = 0; i < ds.length; i++) { ds[i].open = false; var k = ds[i].getAttribute('data-grp'); if (k) _cGrpClosed[k] = true; } });
      // multi-open command cards (same model as the Moves tiles)
      U.on(rootEl, 'click', '.lib-ccard', function (e, t) {
        if (e.target && (e.target.closest('.lib-copy') || e.target.closest('a'))) return;
        var k = t.getAttribute('data-tpl'); if (_cExp[k]) delete _cExp[k]; else _cExp[k] = true; refreshCommands();
      });
      // jump to a move from a command's back-link: switch to Moves lens, search it in.
      U.on(rootEl, 'click', '[data-jump-move]', function (e, t) { e.preventDefault(); jumpToMove(t.getAttribute('data-jump-move')); });
    } else if (_lens === 'attack') {
      U.on(rootEl, 'click', '.lib-tcell', function (e, t) { var c = t.getAttribute('data-tech'); _aSel = (_aSel === c) ? '' : c; refreshAttack(); });
      U.on(rootEl, 'click', '[data-jump-move]', function (e, t) { e.preventDefault(); jumpToMove(t.getAttribute('data-jump-move')); });
    } else if (_lens === 'stuck') {
      try { if (OBOL.routes.stuck && OBOL.routes.stuck.mounted) OBOL.routes.stuck.mounted({ name: 'stuck', args: [], mount: _mount }); } catch (e) {}
    }
  }

  // jump to a move in the Moves lens, pre-searched and expanded.
  function jumpToMove(id) {
    if (!id) return;
    var pk = pack(), mv = null; for (var i = 0; i < pk.length; i++) { if (pk[i].id === id) { mv = pk[i]; break; } }
    _mSel = {}; _mQ = mv ? (mv.title || id) : id; _mExp = {}; _mExp[id] = true; _mRelevant = false;
    OBOL.router.go('library/moves');
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.library = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
