/*!
 * obol ui — routes/study.js — Study mode (milestone 1: the AD vertical slice).
 *
 * Left: the AD lane as a clickable, phase-grouped graph. Right: the selected node, in one of two
 * gears — WATCH (the derived conditional cell: what it is → prereqs → remote-first commands → real
 * sample output with the signal highlighted → proves/opens → common mistake) or YOUR TURN
 * (retrieval practice: a situation, multiple choice, a verdict on every answer, the cell as reward).
 *
 * All content comes from OBOL.study (derived from the packs) + OBOL.STUDY_FIXTURES. No hand-authored
 * lessons live here — this file is rendering + interaction only.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;

  var _view = 'map';             // 'map' (pick a lane) | 'graph' (all lanes) | 'node' (study one step)
  var _from = 'map';             // where a node was opened from, so "back" returns there
  var _gear = 'watch';           // 'watch' | 'practice'
  var _sel = 'asrep-roast';      // selected lane node
  var _autolane = false;         // Watch: auto-advance through the whole chain
  var _autoplay = false;         // start the replay as soon as the next node mounts (chain mode)
  var _rpToken = null;           // cancel token for the running replay's timers
  var _atlasPath = [];           // Atlas: the custom path being drawn (ordered node ids)
  var _scenario = null;          // Atlas: the active fixed scenario key (null = free-draw)
  var _az = null;                // Atlas pan/zoom state {tx,ty,k}; null = fit on mount
  var _path = [];                // the compiled path currently being studied
  var _pathName = 'Your custom path';
  var _pathMode = false;         // node view follows _path instead of the move's lane

  function esc(s) { return U.esc(String(s == null ? '' : s)); }
  function study() { return OBOL.study; }
  // raw fact kind → the human phrase the packs already carry (ad.user_list → "a domain user list")
  function human(k) { try { return (OBOL.pack && OBOL.pack.friendly) ? OBOL.pack.friendly(k) : k; } catch (e) { return k; } }
  function factChips(list, cls) {
    return (list || []).map(function (x) { return '<span class="study-chip ' + (cls || '') + '" title="' + U.attr(x) + '">' + esc(human(x)) + '</span>'; }).join('');
  }
  // wrap code-ish fragments in prose as real <code> (backticked spans, $hashes, fact.kinds, CONSTANTS)
  function codeify(s) {
    var out = esc(String(s == null ? '' : s));
    out = out.replace(/`([^`]+)`/g, '<code class="study-ic">$1</code>');
    out = out.replace(/(\$[A-Za-z0-9$]{2,})/g, '<code class="study-ic">$1</code>');
    out = out.replace(/\b([a-z][a-z0-9]*(?:\.[a-z0-9_]+)+)\b/g, function (m) { return m.length >= 6 ? '<code class="study-ic">' + m + '</code>' : m; });
    out = out.replace(/\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b/g, '<code class="study-ic">$1</code>');
    return out;
  }

  function locusClass(rank) { return 'study-loc-' + rank; }
  function locusGlyph(label) { return label === 'REMOTE' ? '🛰' : (label === 'OFFLINE' ? '💾' : '🖥'); }

  function laneKeyOf(moveId) { var e = study().laneEntry(moveId); return e ? e.laneKey : 'ad'; }
  function laneMeta(key) { var ls = study().lanes(); for (var i = 0; i < ls.length; i++) if (ls[i].key === key) return ls[i]; return { name: key }; }

  // ---- left: the current lane (or custom path) as a rail --------------------------------------
  function graphPanel() {
    var html = '', header;
    if (_pathMode && _path.length) {
      header = _pathName + ' · click a step';
      _path.forEach(function (id, i) {
        var m = study().cellFor(id); if (!m) return;
        var lk = laneKeyOf(id);
        var cls = 'study-gnode lane-' + lk + (id === _sel ? ' active' : '') + (i > 0 ? ' linked' : '');
        html += '<button type="button" class="' + cls + '" data-node="' + U.attr(id) + '">'
          + '<span class="study-gn-t">' + esc(m.title) + '</span>'
          + '<span class="study-gn-k">' + esc(laneMeta(lk).short) + (m.proves && m.proves.length ? ' · gets you ' + esc(human(m.proves[0])) : '') + '</span>'
          + '</button>';
      });
    } else {
      var lk2 = laneKeyOf(_sel), lane = study().lane(lk2), lastPhase = null;
      header = laneMeta(lk2).name + ' · click a step';
      lane.forEach(function (n, i) {
        if (n.phase !== lastPhase) { html += '<div class="study-phase">' + esc(n.phase) + '</div>'; lastPhase = n.phase; }
        var cls = 'study-gnode lane-' + lk2 + (n.id === _sel ? ' active' : '') + (i > 0 ? ' linked' : '');
        html += '<button type="button" class="' + cls + '" data-node="' + U.attr(n.id) + '">'
          + '<span class="study-gn-t">' + esc(n.title) + '</span>'
          + (n.proves && n.proves.length ? '<span class="study-gn-k">gets you ' + esc(human(n.proves[0])) + '</span>' : '')
          + '</button>';
      });
    }
    return '<div class="study-panel study-graph-panel">'
      + '<p class="study-panel-h">' + esc(header) + '</p>'
      + '<div class="study-graph">' + html + '</div>'
      + '<button type="button" class="study-graph-all" data-graph>\u229e Open the Atlas (all lanes)</button>'
      + '</div>';
  }

  // ---- shared bits ----------------------------------------------------------------------------
  function chips(list, cls) {
    return (list || []).map(function (x) { return '<span class="study-chip ' + (cls || '') + '">' + esc(x) + '</span>'; }).join('');
  }
  function commandBlock(cmd) {
    return '<div class="study-cmd ' + locusClass(cmd.rank) + '">'
      + '<div class="study-cmd-h"><span class="study-loc">' + locusGlyph(cmd.locus) + ' ' + esc(cmd.locus) + '</span>'
      + '<span class="study-cmd-tool">' + esc(cmd.tool) + '</span>'
      + '<span class="study-cmd-tag">' + esc(cmd.tag) + '</span></div>'
      + '<pre class="study-cmd-run">' + esc(cmd.run) + '</pre>'
      + (cmd.note ? '<div class="study-cmd-why">↳ ' + codeify(cmd.note) + '</div>' : '')
      + '</div>';
  }
  function outputBlock(output) {
    if (!output || !output.text) return '';
    var sig = output.signal || '';
    var lines = output.text.split('\n').map(function (ln) {
      var hot = sig && ln.indexOf(sig) >= 0;
      return '<span class="study-ln' + (hot ? ' hot' : '') + '">' + esc(ln || ' ') + '</span>';
    }).join('');
    return '<div class="study-term">' + lines + '</div>'
      + (output.teach ? '<div class="study-annot"><span class="study-ar">↳</span><div>' + esc(output.teach) + '</div></div>' : '');
  }
  // ---- the replay player (the star of Watch): one remote-first command runs, output streams, the
  // signal lights up, the facts it mints pop. Markup only — the controller lives in mounted(). ----
  function replayPlayer(rp) {
    if (!rp) return '';
    return '<div class="study-replay" data-move="' + U.attr(rp.id) + '">'
      + '<div class="study-replay-bar"><span class="study-replay-title">▶ Watch it run</span>'
      + '<span class="study-replay-loc">' + locusGlyph(rp.locus) + ' ' + esc(rp.locus) + ' · ' + esc(rp.tool) + '</span></div>'
      + '<div class="study-replay-term" id="rp-term"><div class="rp-idle">Press <b>Play</b> — watch <b>' + esc(rp.tool) + '</b> run against the target and the result land, the way it would on a real box.</div></div>'
      + '<div class="study-replay-facts" id="rp-facts"></div>'
      + '<div class="study-replay-ctrl">'
      + '<button type="button" class="study-rp-btn primary" data-rp="play">▶ Play</button>'
      + '<button type="button" class="study-rp-btn" data-rp="skip">⏭ Skip to result</button>'
      + '<button type="button" class="study-rp-btn" data-rp="restart">↺ Replay</button>'
      + '<label class="study-rp-auto"><input type="checkbox" data-rp="autolane"' + (_autolane ? ' checked' : '') + '> auto-play the whole chain</label>'
      + '<span class="study-rp-prog"></span>'
      + '</div></div>';
  }

  // ---- right: WATCH (replay up top, derived reference below) -----------------------------------
  function cellPanel() {
    var cell = study().cellFor(_sel, { profile: (OBOL.arsenal && OBOL.arsenal.profileGet && OBOL.arsenal.profileGet()) || null });
    if (!cell) return '<div class="study-panel"><p class="study-sub">Node unavailable in this build.</p></div>';
    var rp = study().replayFor(_sel);
    var h = '<div class="study-panel">';
    h += '<div class="study-cell-h"><h2 class="study-cell-title">' + esc(cell.title) + '</h2>'
      + (cell.phase ? '<span class="study-badge b-phase">' + esc(cell.phase) + '</span>' : '')
      + (cell.scope ? '<span class="study-badge b-scope">' + esc(cell.scope === 'oscp' ? 'OSCP core' : cell.scope) + '</span>' : '')
      + (cell.locus ? '<span class="study-badge b-locus">' + esc(cell.locus === 'R' ? 'runs remotely' : (cell.locus === 'F' ? 'runs on the target' : 'interactive on the target')) + '</span>' : '')
      + '</div>';
    if (cell.whatItIs) h += '<p class="study-cell-sub">' + codeify(cell.whatItIs) + '</p>';

    h += '<div class="study-startfrom"><span class="study-sf-l">Starting from</span> '
      + (cell.prereqFacts.length ? factChips(cell.prereqFacts, 'proven') : '<span class="study-dim">nothing — this is an opening move</span>')
      + (cell.producedBy.length ? '<span class="study-via">you\'d have run ' + cell.producedBy.slice(0, 2).map(function (x) { return '<b>' + esc(x.title) + '</b>'; }).join(' · ') + '</span>' : '')
      + '</div>';

    // the replay
    h += replayPlayer(rp);

    // the alternatives, folded away
    if (cell.commands.length > 1) {
      h += '<details class="study-allcmds"><summary>All ' + cell.commands.length + ' ways to run this · remote-first</summary>'
        + cell.commands.map(commandBlock).join('') + '</details>';
    }

    h += '<div class="study-seg study-outcome"><div class="study-seg-l">What you walk away with <span class="study-seg-note">— and the moves it unlocks</span></div>'
      + '<div class="study-flow">' + factChips(cell.proves, 'proof')
      + (cell.opens.length ? '<span class="study-arr">unlocks →</span>' + cell.opens.slice(0, 4).map(function (x) { return '<span class="study-chip study-next" data-goto="' + U.attr(x.id) + '">' + esc(x.title) + ' →</span>'; }).join('') : '')
      + '</div></div>';

    if (cell.rulesOut) h += '<div class="study-mistake"><span class="study-mi">⚠</span><div><b>Watch out:</b> ' + codeify(cell.rulesOut) + '</div></div>';

    h += '</div>';
    return h;
  }

  // ---- right: YOUR TURN (practice) ------------------------------------------------------------
  function practicePanel() {
    var q = study().practiceFor(_sel);
    if (!q) return '<div class="study-panel"><p class="study-sub">No practice for this node yet.</p></div>';
    var letters = 'ABCDEFGH';
    var h = '<div class="study-panel">';
    h += '<div class="study-scn"><div class="study-scn-l">The situation</div><p>' + codeify(q.situation || 'Given where you are, what\'s your next move?') + '</p></div>';
    h += '<div class="study-q">What\'s your next move?</div><div class="study-choices">';
    q.choices.forEach(function (c, i) {
      var missingTxt = (c.missing || []).map(function (mk) { return /^one of:/.test(mk) ? ('one of: ' + mk.replace(/^one of:\s*/, '').split(' / ').map(human).join(' or ')) : human(mk); });
      var missing = missingTxt.length ? ' data-missing="' + U.attr(missingTxt.join('; ')) + '"' : '';
      h += '<button type="button" class="study-choice" data-verdict="' + U.attr(c.verdict) + '" data-cid="' + U.attr(c.id) + '"' + missing
        + (c.coach ? ' data-coach="' + U.attr(c.coach) + '"' : '') + '>'
        + '<span class="study-tag">' + letters[i] + '</span>'
        + '<span class="study-ct">' + esc(c.title) + '</span></button>';
    });
    h += '</div><div class="study-verdict" id="study-verdict"></div>';
    h += '<div class="study-reveal-slot" id="study-reveal-slot"></div>';
    h += '</div>';
    return h;
  }

  // ---- the MAP (Learn landing): pick a lane, pick a step, or head to setup / an engagement --------
  function pathStrip(lane) {
    return '<div class="study-path">' + lane.map(function (n, i) {
      return (i ? '<span class="study-path-arr">→</span>' : '')
        + '<button type="button" class="study-path-node" data-open="' + U.attr(n.id) + '">'
        + '<span class="study-path-ph">' + esc(n.phase) + '</span>'
        + '<span class="study-path-t">' + esc(n.title) + '</span></button>';
    }).join('') + '</div>';
  }
  function door(href, glyph, title, desc) {
    return '<a class="study-door" href="' + href + '"><span class="study-door-g">' + glyph + '</span>'
      + '<span class="study-door-t">' + esc(title) + '</span><span class="study-door-d">' + esc(desc) + '</span></a>';
  }
  function mapView() {
    var ls = study().lanes();
    var h = '<section class="study-route study-map">';
    h += '<div class="study-hero"><h1 class="study-hero-h">Learn the methodology</h1>'
      + '<p class="study-hero-p">obol teaches offensive security as a decision graph — <b>know what to do, and why, from what you\'ve found.</b> '
      + 'Pick a path below and step through it: watch each move play out like it would on a real box, or test yourself.</p></div>';
    h += '<div class="study-lanes">' + ls.map(function (L) {
      return '<button type="button" class="study-lane-card active lane-' + L.key + '" data-open="' + U.attr(L.firstId) + '">'
        + '<div class="study-lane-name">' + esc(L.name) + ' <span class="study-lane-badge">' + L.count + ' steps</span></div>'
        + '<div class="study-lane-desc">' + esc(L.desc) + '</div>'
        + '<div class="study-lane-go">Start the path →</div></button>';
    }).join('') + '</div>';
    h += '<button type="button" class="study-graph-cta" data-graph>⊞ See the whole methodology as one graph →</button>';
    h += '<div class="study-doors">'
      + door('#/loadout', '⚙', 'Set up your box', 'Install the toolset so the commands you learn match your own machine.')
      + door('#/home', '▶', 'Start an engagement', 'Working a real box? Track it — paste output, get your next move.')
      + '</div>';
    return h + '</section>';
  }

  // ---- the full methodology graph: every lane, every step, pickable ---------------------------
  function atlasView() {
    // --- the Atlas: a zoomable/pannable methodology graph you draw custom paths through ----------
    var NW = 184, NH = 50, CGAP = 66, RGAP = 54, LEFT = 150, TOP = 54;
    var A = study().atlas();
    var pos = {};
    A.nodes.forEach(function (n) { var x = LEFT + n.col * (NW + CGAP), y = TOP + n.row * (NH + RGAP); pos[n.id] = { x: x, y: y, cx: x + NW / 2, cy: y + NH / 2 }; });
    var W = LEFT + A.cols * (NW + CGAP) + 20, H = TOP + A.laneOrder.length * (NH + RGAP) + 20;

    function edgePath(a, b, cross) {
      var p1 = pos[a], p2 = pos[b]; if (!p1 || !p2) return '';
      if (!cross) { var x1 = p1.x + NW, y1 = p1.cy, x2 = p2.x, y2 = p2.cy, mx = (x1 + x2) / 2; return 'M' + x1 + ',' + y1 + ' C' + mx + ',' + y1 + ' ' + mx + ',' + y2 + ' ' + x2 + ',' + y2; }
      var sx = p1.cx, sy = (p2.cy > p1.cy ? p1.y + NH : p1.y), ex = p2.cx, ey = (p2.cy > p1.cy ? p2.y : p2.y + NH);
      return 'M' + sx + ',' + sy + ' C' + sx + ',' + ((sy + ey) / 2) + ' ' + ex + ',' + ((sy + ey) / 2) + ' ' + ex + ',' + ey;
    }
    var laneEdgeSvg = A.laneEdges.map(function (e) { return '<path class="atlas-edge atlas-edge-lane lane-' + study().laneEntry(e.from).laneKey + '" d="' + edgePath(e.from, e.to, false) + '"/>'; }).join('');
    var crossEdgeSvg = A.crossEdges.map(function (e) { return '<path class="atlas-edge atlas-edge-cross" d="' + edgePath(e.from, e.to, true) + '"><title>' + esc(e.note || '') + '</title></path>'; }).join('');
    var nodeSvg = A.nodes.map(function (n) {
      var p = pos[n.id], proof = (n.proves && n.proves[0]) ? human(n.proves[0]) : '';
      return '<g class="atlas-node lane-' + n.lane + '" data-anode="' + U.attr(n.id) + '" data-cx="' + p.cx + '" data-cy="' + p.cy + '" transform="translate(' + p.x + ',' + p.y + ')">'
        + '<rect class="an-box" width="' + NW + '" height="' + NH + '" rx="9"/>'
        + '<text class="an-badge" x="9" y="-7"></text>'
        + '<text class="an-ph" x="11" y="17">' + esc(n.phase.toUpperCase()) + '</text>'
        + '<text class="an-t" x="11" y="32">' + esc(n.title.length > 26 ? n.title.slice(0, 25) + '…' : n.title) + '</text>'
        + '<text class="an-sub" x="11" y="45">' + esc(proof ? ('→ ' + (proof.length > 28 ? proof.slice(0, 27) + '…' : proof)) : '') + '</text>'
        + '</g>';
    }).join('');
    var laneLabels = A.laneOrder.map(function (lk, row) { var meta = laneMeta(lk); var y = TOP + row * (NH + RGAP) + NH / 2; return '<text class="atlas-lanelabel lane-' + lk + '" x="12" y="' + (y + 4) + '">' + esc(meta.short || meta.name) + '</text>'; }).join('');

    return '<section class="study-route study-atlas-route">'
      + '<div class="study-top"><button type="button" class="study-back" data-back-map>← Paths</button>'
      + '<div class="study-crumb"><b>Study</b> · Atlas <span class="study-map-path-note">drag to pan · scroll to zoom · click steps to draw a path</span></div>'
      + '<div class="atlas-ctrl"><button type="button" class="study-rp-btn" data-az="out">−</button>'
      + '<button type="button" class="study-rp-btn" data-az="reset">fit</button>'
      + '<button type="button" class="study-rp-btn" data-az="in">+</button></div></div>'
      + '<div class="atlas-scenarios"><span class="atlas-scen-l">Common scenarios</span>'
      + study().scenarios().map(function (s) { return '<button type="button" class="atlas-scen' + (s.key === _scenario ? ' on' : '') + '" data-scen="' + U.attr(s.key) + '" title="' + U.attr(s.desc) + '">' + esc(s.name) + '</button>'; }).join('')
      + '<span class="atlas-scen-or">or click steps to draw your own</span></div>'
      + '<div class="atlas-stage" id="atlas-stage">'
      + '<svg class="atlas-svg" id="atlas-svg"><g class="atlas-view" id="atlas-view" data-w="' + W + '" data-h="' + H + '">'
      + laneLabels + '<g class="atlas-edges">' + laneEdgeSvg + crossEdgeSvg + '</g>'
      + '<path class="atlas-pathline" id="atlas-pathline" d=""/>'
      + '<g class="atlas-nodes">' + nodeSvg + '</g></g></svg>'
      + '</div>'
      + '<div class="atlas-tray" id="atlas-tray"></div>'
      + '</section>';
  }

  function nodeView() {
    var right = _gear === 'practice' ? practicePanel() : cellPanel();
    return '<section class="study-route">'
      + '<div class="study-top">'
      + '<button type="button" class="study-back" data-back>← ' + (_pathMode ? 'Your path' : (_from === 'atlas' ? 'The Atlas' : 'All paths')) + '</button>'
      + '<div class="study-crumb"><b>Study</b> · ' + esc(laneMeta(laneKeyOf(_sel)).name) + ' · <span class="study-here">' + esc((study().cellFor(_sel) || {}).title || _sel) + '</span></div>'
      + '<div class="study-gears">'
      + '<button type="button" class="study-gear' + (_gear === 'watch' ? ' on' : '') + '" data-gear="watch">▶ Watch</button>'
      + '<button type="button" class="study-gear' + (_gear === 'practice' ? ' on' : '') + '" data-gear="practice">✎ Your turn</button>'
      + '</div></div>'
      + '<div class="study-cols">' + graphPanel() + right + '</div>'
      + '</section>';
  }

  function render(ctx) {
    if (ctx && ctx.args && ctx.args[0] && study().cellFor(ctx.args[0])) { _sel = ctx.args[0]; _view = 'node'; _pathMode = false; _path = []; }
    return _view === 'map' ? mapView() : (_view === 'atlas' ? atlasView() : nodeView());
  }

  // ---- replay controller ----------------------------------------------------------------------
  function cancelReplay() { if (_rpToken) { _rpToken.cancelled = true; _rpToken = null; } }
  function runReplay(mount, instant) {
    cancelReplay();
    var player = mount.querySelector('.study-replay'); if (!player) return;
    var rp = study().replayFor(player.getAttribute('data-move')); if (!rp) return;
    var term = mount.querySelector('#rp-term'), facts = mount.querySelector('#rp-facts'), prog = mount.querySelector('.study-rp-prog');
    if (!term) return;
    var token = { cancelled: false }; _rpToken = token;
    term.innerHTML = ''; if (facts) facts.innerHTML = '';
    var seq = (_pathMode && _path.length) ? _path.slice() : study().lane(laneKeyOf(rp.id)).map(function (x) { return x.id; });
    var idx = seq.indexOf(rp.id);
    if (prog) prog.textContent = 'step ' + (idx + 1) + ' / ' + seq.length;
    function popFacts(delay) {
      (rp.proves || []).forEach(function (f, k) { setTimeout(function () { if (token.cancelled || !facts) return; var c = document.createElement('span'); c.className = 'study-chip proof rp-pop'; c.textContent = '+ ' + human(f); facts.appendChild(c); }, delay + k * 260); });
      var nextId = rp.next;
      if (_pathMode && _path.length) { var pi = _path.indexOf(rp.id); nextId = (pi >= 0 && pi < _path.length - 1) ? _path[pi + 1] : null; }
      if (_autolane && nextId) setTimeout(function () { if (token.cancelled) return; _sel = nextId; _autoplay = true; OBOL.router.render(); }, delay + (rp.proves.length * 260) + 1400);
    }
    if (instant) {
      var html = '<div class="rp-line rp-cmd"><span class="rp-prompt">kali$</span> ' + esc(rp.command) + '</div>'
        + rp.outputLines.map(function (ln) { var hot = rp.signal && ln.indexOf(rp.signal) >= 0; return '<div class="rp-line rp-out' + (hot ? ' hot' : '') + '">' + esc(ln || ' ') + '</div>' + (hot && rp.teach ? '<div class="rp-cap">← ' + codeify(rp.teach) + '</div>' : ''); }).join('');
      term.innerHTML = html; term.scrollTop = term.scrollHeight; popFacts(200); return;
    }
    var promptLine = document.createElement('div'); promptLine.className = 'rp-line rp-cmd';
    promptLine.innerHTML = '<span class="rp-prompt">kali$</span> <span class="rp-typed"></span><span class="rp-cursor">▋</span>';
    term.appendChild(promptLine);
    var typed = promptLine.querySelector('.rp-typed'), cmd = rp.command, ci = 0;
    (function typeCmd() {
      if (token.cancelled) return;
      if (ci <= cmd.length) { typed.textContent = cmd.slice(0, ci); ci++; setTimeout(typeCmd, 16); return; }
      var cur = promptLine.querySelector('.rp-cursor'); if (cur) cur.remove();
      var i = 0;
      (function nextLine() {
        if (token.cancelled) return;
        if (i >= rp.outputLines.length) { popFacts(300); return; }
        var ln = rp.outputLines[i], el = document.createElement('div');
        var hot = rp.signal && ln.indexOf(rp.signal) >= 0;
        el.className = 'rp-line rp-out' + (hot ? ' hot' : ''); el.textContent = ln || ' ';
        term.appendChild(el); term.scrollTop = term.scrollHeight;
        if (hot && rp.teach) { var cap = document.createElement('div'); cap.className = 'rp-cap'; cap.innerHTML = '← ' + codeify(rp.teach); term.appendChild(cap); term.scrollTop = term.scrollHeight; }
        i++; setTimeout(nextLine, hot ? 1100 : 230);
      })();
    })();
  }

  // ---- Atlas interaction ----------------------------------------------------------------------
  function atlasApply(view) { view.setAttribute('transform', 'translate(' + _az.tx + ',' + _az.ty + ') scale(' + _az.k + ')'); }
  function atlasLOD(stage) { var k = _az.k; stage.setAttribute('data-lod', k < 0.62 ? 'far' : (k < 1.05 ? 'mid' : 'near')); }
  function atlasPathD(mount) {
    if (_atlasPath.length < 2) return '';
    var pts = _atlasPath.map(function (id) { var g = mount.querySelector('.atlas-node[data-anode="' + id + '"]'); return g ? (g.getAttribute('data-cx') + ',' + g.getAttribute('data-cy')) : null; }).filter(Boolean);
    return pts.length < 2 ? '' : 'M' + pts.join(' L');
  }
  function scenName(key) { var s = study().scenario(key); return s ? s.name : ''; }
  function atlasTray(mount) {
    var tray = mount.querySelector('#atlas-tray'); if (!tray) return;
    if (!_atlasPath.length) { tray.innerHTML = '<span class="atlas-tray-hint">Pick a <b>common scenario</b> above, or click steps in order to draw your own path — then study it as one guided run.</span>'; return; }
    var lead = _scenario ? ('<span class="atlas-tray-name">' + esc(scenName(_scenario)) + '</span>') : '<span class="atlas-tray-name custom">Custom path</span>';
    var chips = _atlasPath.map(function (id, i) { var c = study().cellFor(id); return '<span class="atlas-trchip lane-' + laneKeyOf(id) + '">' + (i + 1) + '. ' + esc(c ? c.title : id) + '</span>'; }).join('<span class="atlas-trarr">→</span>');
    tray.innerHTML = lead + '<div class="atlas-tray-path">' + chips + '</div>'
      + '<div class="atlas-tray-act"><button type="button" class="study-rp-btn" data-atlas="clear">clear</button>'
      + '<button type="button" class="study-rp-btn primary" data-atlas="study">▶ Study this path (' + _atlasPath.length + ') →</button></div>';
  }
  function syncScen(mount) { Array.prototype.forEach.call(mount.querySelectorAll('.atlas-scen'), function (c) { c.classList.toggle('on', c.getAttribute('data-scen') === _scenario); }); }
  function atlasSelection(mount) {
    Array.prototype.forEach.call(mount.querySelectorAll('.atlas-node'), function (g) {
      var i = _atlasPath.indexOf(g.getAttribute('data-anode'));
      g.classList.toggle('sel', i >= 0);
      var b = g.querySelector('.an-badge'); if (b) b.textContent = i >= 0 ? (i + 1) : '';
    });
    var pl = mount.querySelector('#atlas-pathline'); if (pl) pl.setAttribute('d', atlasPathD(mount));
    syncScen(mount);
    atlasTray(mount);
  }
  function wireAtlas(mount) {
    var stage = mount.querySelector('#atlas-stage'), view = mount.querySelector('#atlas-view');
    if (!stage || !view) return;
    var W = +view.getAttribute('data-w'), H = +view.getAttribute('data-h');
    function fit() { var r = stage.getBoundingClientRect(); var k = Math.min((r.width - 24) / W, (r.height - 24) / H, 1.1); k = Math.max(k, 0.3); _az = { k: k, tx: (r.width - W * k) / 2, ty: 12 }; atlasApply(view); atlasLOD(stage); }
    function zoomAround(mx, my, f) { var nk = Math.max(0.3, Math.min(2.4, _az.k * f)), ratio = nk / _az.k; _az.tx = mx - (mx - _az.tx) * ratio; _az.ty = my - (my - _az.ty) * ratio; _az.k = nk; atlasApply(view); atlasLOD(stage); }
    if (!_az) fit(); else { atlasApply(view); atlasLOD(stage); }
    atlasSelection(mount);
    var down = null, moved = false;
    stage.addEventListener('pointerdown', function (e) { var g = e.target.closest && e.target.closest('.atlas-node'); down = { x: e.clientX, y: e.clientY, tx: _az.tx, ty: _az.ty, node: g }; moved = false; try { stage.setPointerCapture(e.pointerId); } catch (x) {} });
    stage.addEventListener('pointermove', function (e) { if (!down) return; var dx = e.clientX - down.x, dy = e.clientY - down.y; if (Math.abs(dx) + Math.abs(dy) > 4) moved = true; _az.tx = down.tx + dx; _az.ty = down.ty + dy; atlasApply(view); });
    stage.addEventListener('pointerup', function () { var wasMoved = moved, g = down && down.node; down = null; if (wasMoved || !g) return; var id = g.getAttribute('data-anode'), i = _atlasPath.indexOf(id); if (i >= 0) _atlasPath.splice(i, 1); else _atlasPath.push(id); _scenario = null; atlasSelection(mount); });
    stage.addEventListener('wheel', function (e) { e.preventDefault(); var r = stage.getBoundingClientRect(); zoomAround(e.clientX - r.left, e.clientY - r.top, e.deltaY < 0 ? 1.12 : 0.89); }, { passive: false });
    U.on(mount, 'click', '[data-az]', function (e, t) { var a = t.getAttribute('data-az'); if (a === 'in' || a === 'out') { var r = stage.getBoundingClientRect(); zoomAround(r.width / 2, r.height / 2, a === 'in' ? 1.2 : 0.83); } else fit(); });
    U.on(mount, 'click', '[data-atlas="clear"]', function () { _atlasPath = []; _scenario = null; atlasSelection(mount); });
    U.on(mount, 'click', '[data-atlas="study"]', function () { if (!_atlasPath.length) return; _path = _atlasPath.slice(); _pathName = _scenario ? scenName(_scenario) : 'Your custom path'; _pathMode = true; _from = 'atlas'; _sel = _path[0]; _view = 'node'; OBOL.router.render(); });
    // toggle a fixed scenario on/off (loads its steps as the path)
    U.on(mount, 'click', '[data-scen]', function (e, t) {
      var key = t.getAttribute('data-scen');
      if (key === _scenario) { _scenario = null; _atlasPath = []; }
      else { var s = study().scenario(key); if (s) { _scenario = key; _atlasPath = s.steps.slice(); } }
      atlasSelection(mount);
    });
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    cancelReplay();
    // map/graph: open a lane/step → node view (remember where we came from)
    U.on(mount, 'click', '[data-open]', function (e, t) { _from = (_view === 'atlas' ? 'atlas' : 'map'); _sel = t.getAttribute('data-open'); _view = 'node'; OBOL.router.render(); });
    U.on(mount, 'click', '[data-back]', function () { _view = _from; OBOL.router.render(); });
    U.on(mount, 'click', '[data-back-map]', function () { _view = 'map'; OBOL.router.render(); });
    U.on(mount, 'click', '[data-graph]', function () { _view = 'atlas'; OBOL.router.render(); });
    // node select + "opens →" jumps + goto chips → re-render
    U.on(mount, 'click', '[data-node]', function (e, t) { _sel = t.getAttribute('data-node'); OBOL.router.render(); });
    U.on(mount, 'click', '[data-goto]', function (e, t) { _sel = t.getAttribute('data-goto'); _view = 'node'; OBOL.router.render(); });
    // gear toggle → re-render
    U.on(mount, 'click', '[data-gear]', function (e, t) { _gear = t.getAttribute('data-gear'); OBOL.router.render(); });
    // replay controls
    U.on(mount, 'click', '[data-rp="play"]', function () { runReplay(mount, false); });
    U.on(mount, 'click', '[data-rp="restart"]', function () { runReplay(mount, false); });
    U.on(mount, 'click', '[data-rp="skip"]', function () { runReplay(mount, true); });
    U.on(mount, 'change', '[data-rp="autolane"]', function (e, t) { _autolane = !!t.checked; });
    // auto-start when a chain step mounts
    if (_view === 'node' && _gear === 'watch' && _autoplay) { _autoplay = false; setTimeout(function () { runReplay(mount, false); }, 250); }
    // the Atlas: pan / zoom / semantic LOD / draw a custom path
    if (_view === 'atlas') setTimeout(function () { wireAtlas(mount); }, 30);
    // practice: answer a choice (local DOM update, keeps the answered state)
    U.on(mount, 'click', '.study-choice', function (e, t) {
      var verdict = t.getAttribute('data-verdict'), coach = t.getAttribute('data-coach') || '', missing = t.getAttribute('data-missing') || '';
      Array.prototype.forEach.call(mount.querySelectorAll('.study-choice'), function (c) { c.classList.remove('ok', 'alt', 'bad', 'dimmed'); if (c !== t) c.classList.add('dimmed'); });
      t.classList.add(verdict === 'correct' ? 'ok' : (verdict === 'alt' ? 'alt' : 'bad'));
      var vbox = mount.querySelector('#study-verdict'), slot = mount.querySelector('#study-reveal-slot');
      if (slot) slot.innerHTML = '';
      var head, body;
      if (verdict === 'correct') { head = '✓ Exactly.'; body = 'That\'s the move. Here\'s how it plays out →'; }
      else if (verdict === 'alt') { head = '~ Also valid — but weigh it.'; body = coach ? codeify(coach) : 'A legal move here; consider the tradeoff against the cleaner path.'; }
      else { head = '✗ Not yet.'; body = (coach ? codeify(coach) : 'This needs something you don\'t have.') + (missing ? ' <span class="study-missing">Still need: ' + esc(missing) + '</span>' : ''); }
      if (vbox) {
        vbox.className = 'study-verdict show ' + (verdict === 'correct' ? 'ok' : (verdict === 'alt' ? 'alt' : 'bad'));
        vbox.innerHTML = '<div class="study-vh">' + head + '</div><div>' + body + '</div>'
          + (verdict === 'correct' ? '<button type="button" class="study-reveal-btn">See how it plays out ↓</button>' : '');
      }
    });
    // reveal the worked cell on a correct answer
    U.on(mount, 'click', '.study-reveal-btn', function (e, t) {
      var slot = mount.querySelector('#study-reveal-slot'); if (!slot) return;
      var save = _gear; _gear = 'watch'; var cellHtml = cellPanel(); _gear = save;
      // strip the outer panel wrapper so it nests cleanly
      slot.innerHTML = '<div class="study-reveal">' + cellHtml.replace(/^<div class="study-panel">/, '').replace(/<\/div>$/, '') + '</div>';
      t.style.display = 'none';
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.study = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
