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
  var _collapsed = {};           // Atlas: laneKey -> true when that lane band is folded shut
  var _atlasQuery = '';          // Atlas: current search text (dims non-matching steps)

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
  function masteryGlyph(id) {
    var mk = study().mastery()[id] || {};
    if (mk.correct) return '<span class="study-gn-m done" title="You answered this correctly">✓</span>';
    if (mk.studied) return '<span class="study-gn-m seen" title="You\'ve watched this step">◐</span>';
    return '';
  }
  function graphPanel() {
    var html = '', header;
    if (_pathMode && _path.length) {
      header = _pathName + ' · click a step';
      _path.forEach(function (id, i) {
        var m = study().cellFor(id); if (!m) return;
        var lk = laneKeyOf(id);
        var cls = 'study-gnode lane-' + lk + (id === _sel ? ' active' : '') + (i > 0 ? ' linked' : '');
        html += '<button type="button" class="' + cls + '" data-node="' + U.attr(id) + '">'
          + '<span class="study-gn-t">' + esc(m.title) + masteryGlyph(id) + '</span>'
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
          + '<span class="study-gn-t">' + esc(n.title) + masteryGlyph(n.id) + '</span>'
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
    var idle = rp.hasOutput
      ? 'Press <b>Play</b> — watch <b>' + esc(rp.tool) + '</b> run against the target and the result land, the way it would on a real box.'
      : 'Press <b>Play</b> to watch <b>' + esc(rp.tool) + '</b> run. <span class="rp-nosample">A captured sample of this step’s output is still being written — you’ll see the command and what it proves.</span>';
    return '<div class="study-replay" data-move="' + U.attr(rp.id) + '">'
      + '<div class="study-replay-bar"><span class="study-replay-title">▶ Watch it run</span>'
      + '<span class="study-replay-loc">' + locusGlyph(rp.locus) + ' ' + esc(rp.locus) + ' · ' + esc(rp.tool) + '</span></div>'
      + '<div class="study-replay-term" id="rp-term"><div class="rp-idle">' + idle + '</div></div>'
      + '<div class="study-replay-facts" id="rp-facts"></div>'
      + '<div class="study-replay-ctrl">'
      + '<button type="button" class="study-rp-btn primary" data-rp="play">▶ Play</button>'
      + (rp.hasOutput ? '<button type="button" class="study-rp-btn" data-rp="skip">⏭ Skip to result</button>' : '')
      + '<button type="button" class="study-rp-btn" data-rp="restart">↺ Replay</button>'
      + '<label class="study-rp-auto"><input type="checkbox" data-rp="autolane"' + (_autolane ? ' checked' : '') + '> auto-play the whole chain</label>'
      + '<span class="study-rp-prog"></span>'
      + '</div></div>';
  }

  // ---- "Run it from" toggle: remote (your box) vs on the target (after a shell) -----------------
  function osForMove(cell) {
    var lk = cell.laneKey || laneKeyOf(cell.id);
    if (lk === 'windows' || lk === 'ad') return 'windows';
    if (lk === 'linux') return 'linux';
    var blob = (cell.commands || []).map(function (c) { return (c.run || '') + ' ' + (c.tool || ''); }).join(' ').toLowerCase();
    if (/powershell|(^| )cmd |winrm|\.exe|certutil|evil-winrm|rubeus|mssql|xfreerdp|impacket|nxc (smb|ldap|winrm)/.test(blob)) return 'windows';
    return 'linux';
  }
  function connectCmd(os) {
    return os === 'windows'
      ? { tool: 'evil-winrm', run: "evil-winrm -i 10.10.10.10 -u <user> -p '<password>'", note: 'get an interactive shell on the box over WinRM (5985), then run the command there', locus: 'ON-TARGET', tag: 'connect first', rank: 2 }
      : { tool: 'ssh', run: 'ssh <user>@10.10.10.10', note: 'get an interactive shell on the box, then run the command there', locus: 'ON-TARGET', tag: 'connect first', rank: 2 };
  }
  function runWaysPanel(cell) {
    var cmds = cell.commands || [];
    if (!cmds.length) return '';
    var remote = cmds.filter(function (c) { return c.rank === 0 || c.rank === 1; });   // your box: remote + offline
    var onhost = cmds.filter(function (c) { return c.rank === 2; });                    // on the target
    var conn = connectCmd(osForMove(cell));
    var remotePane = remote.length
      ? remote.map(commandBlock).join('')
      : '<div class="rw-note">This move is normally run <b>on the target</b> after you have a shell — switch the toggle.</div>';
    var hostPane = '<div class="rw-connect">' + commandBlock(conn) + '</div>'
      + (onhost.length
        ? onhost.map(commandBlock).join('')
        : '<div class="rw-note">Once you are on the box, run the same command locally — the built-ins shown, or the tool staged as in the replay above. (Remotely, you can also wrap it: <code class="study-ic">' + esc(osForMove(cell) === 'windows' ? 'nxc winrm 10.10.10.10 -u <user> -p <password> -x "…"' : 'ssh <user>@10.10.10.10 "…"') + '</code>.)</div>');
    return '<div class="study-runways">'
      + '<div class="rw-head"><span class="rw-label">Run it from</span>'
      + '<button type="button" class="rw-tab on" data-runway="remote">🛰 your box <span class="rw-n">' + remote.length + '</span></button>'
      + '<button type="button" class="rw-tab" data-runway="onhost">🖥 on the target <span class="rw-n">' + onhost.length + '</span></button></div>'
      + '<div class="rw-pane" data-pane="remote">' + remotePane + '</div>'
      + '<div class="rw-pane" data-pane="onhost" hidden>' + hostPane + '</div>'
      + '</div>';
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

    // Run-it-from toggle: the same move, two ways — remotely from your box, or on the target after you
    // get a shell (with the connect step shown). Reuses the pack's own remote-first command loci.
    h += runWaysPanel(cell);

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
    var q = study().practiceFor(_sel, _pathMode && _path.length ? _path : null);
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
      var pr = study().laneProgress(L.key), pct = pr.total ? Math.round(pr.studied / pr.total * 100) : 0;
      return '<button type="button" class="study-lane-card active lane-' + L.key + '" data-open="' + U.attr(L.firstId) + '">'
        + '<div class="study-lane-name">' + esc(L.name) + ' <span class="study-lane-badge">' + L.count + ' steps</span></div>'
        + '<div class="study-lane-desc">' + esc(L.desc) + '</div>'
        + '<div class="study-lane-foot"><div class="study-lane-bar"><span style="width:' + pct + '%"></span></div>'
        + '<span class="study-lane-go">' + (pr.studied ? pr.studied + ' / ' + pr.total + ' studied · continue →' : 'Start the path →') + '</span></div></button>';
    }).join('') + '</div>';
    h += '<div class="study-browse"><span class="study-browse-l">Or browse by</span>'
      + '<button type="button" class="study-browse-b" data-graph>⊞ the whole graph</button>'
      + '<button type="button" class="study-browse-b" data-ports>⊟ open port — what you actually see first</button></div>';
    h += '<div class="study-doors">'
      + door('#/loadout', '⚙', 'Set up your box', 'Install the toolset so the commands you learn match your own machine.')
      + door('#/home', '▶', 'Start an engagement', 'Working a real box? Track it — paste output, get your next move.')
      + '</div>';
    return h + '</section>';
  }

  // ---- the BY-EVIDENCE view: what is in front of you (a port, a shell, a hash) and what it unlocks.
  // Two tiers: open ports first (how you actually start), then "once you are in" evidence. Each entry
  // is an ordered mini-lane, so it reads with the same flow as the methodology lanes.
  function evidenceCard(e, mk) {
    var isPort = e.tier === 'ports';
    var head = isPort
      ? '<div class="port-card-h"><span class="port-num">' + esc(e.port) + (e.proto ? '<span class="port-proto">/' + esc(e.proto) + '</span>' : '') + '</span>'
        + '<span class="port-svc">' + esc(e.label) + '</span></div>'
      : '<div class="port-card-h ev-access-h"><span class="port-svc">' + esc(e.label) + '</span></div>';
    var moves = e.moves.map(function (m, i) {
      var studied = (mk[m.id] || {}).studied ? ' done' : '';
      return (i ? '<span class="ev-arrow">→</span>' : '')
        + '<button type="button" class="port-move lane-' + m.laneKey + studied + '" data-open="' + U.attr(m.id) + '">' + esc(m.title) + '</button>';
    }).join('');
    return '<div class="port-card' + (e.key === 'scan' ? ' port-scan' : '') + (isPort ? '' : ' ev-access') + '">'
      + head
      + '<p class="port-sig">' + esc(e.signal) + '</p>'
      + '<div class="port-moves ev-flow">' + moves + '</div>'
      + '</div>';
  }
  function portsView() {
    var ev = study().evidence(), mk = study().mastery();
    var portsT = ev.filter(function (e) { return e.tier === 'ports'; });
    var accessT = ev.filter(function (e) { return e.tier === 'access'; });
    var h = '<section class="study-route study-ports">';
    h += '<div class="study-top"><button type="button" class="study-back" data-back-map>← Paths</button>'
      + '<div class="study-crumb"><b>Study</b> · By what you have found</div></div>';
    h += '<div class="study-hero"><h1 class="study-hero-h">What do I do with <i>this</i>?</h1>'
      + '<p class="study-hero-p">This is how you actually operate. You scan, and a list of open ports comes back. Each one is a signal: it tells you what the box runs and which moves it opens. '
      + 'Once you are in, the signal changes to what you are holding, a shell, a hash, a credential. Find yours, read what it means, and step into the move.</p></div>';
    h += '<h2 class="ev-tier-h">Open ports, what you see first</h2>';
    h += '<div class="port-grid">' + portsT.map(function (e) { return evidenceCard(e, mk); }).join('') + '</div>';
    h += '<h2 class="ev-tier-h">Once you are in, what you are holding</h2>';
    h += '<div class="port-grid ev-access-grid">' + accessT.map(function (e) { return evidenceCard(e, mk); }).join('') + '</div>';
    return h + '</section>';
  }

  // ---- the full methodology graph: every lane, every step, pickable ---------------------------
  // Layout: each lane is a horizontal *band*. Its steps wrap across up to MAXC columns so a 48-step
  // lane like AD reads as a compact block of rows instead of one 12,000px line. A band can be folded
  // shut (its steps collapse to a dot strip) so you can hide lanes you're not working. Everything is
  // derived from study().atlas(); positions are computed once in atlasLayout() and shared by the SVG,
  // the edges, the path-line and the minimap.
  var MAXC = 8, NW = 172, NH = 46, CGAP = 18, RGAP = 20, LEFT = 118, TOP = 10, BANDHEAD = 28, BANDGAP = 16;
  function atlasLayout() {
    var A = study().atlas();
    var colW = NW + CGAP, rowH = NH + RGAP, pos = {}, bands = [], y = TOP, maxRight = LEFT + MAXC * colW;
    A.lanes.forEach(function (L) {
      var collapsed = !!_collapsed[L.key];
      var laneNodes = A.nodes.filter(function (n) { return n.lane === L.key; });
      var rows = collapsed ? 0 : Math.ceil(laneNodes.length / MAXC) || 1;
      var top = y, h = BANDHEAD + (collapsed ? 6 : rows * rowH);
      if (!collapsed) laneNodes.forEach(function (n, idx) {
        var col = idx % MAXC, lr = Math.floor(idx / MAXC);
        var x = LEFT + col * colW, ny = top + BANDHEAD + lr * rowH;
        pos[n.id] = { x: x, y: ny, cx: x + NW / 2, cy: ny + NH / 2, lr: lr };
        if (x + NW > maxRight) maxRight = x + NW;
      });
      bands.push({ key: L.key, name: L.name, short: L.short, count: laneNodes.length, top: top, h: h, collapsed: collapsed, rows: rows, nodes: laneNodes });
      y += h + BANDGAP;
    });
    return { A: A, pos: pos, bands: bands, colW: colW, rowH: rowH, W: maxRight + 24, H: y + 6 };
  }

  function edgePath(pos, a, b, cross) {
    var p1 = pos[a], p2 = pos[b]; if (!p1 || !p2) return '';
    if (cross) { var sx = p1.cx, sy = (p2.cy > p1.cy ? p1.y + NH : p1.y), ex = p2.cx, ey = (p2.cy > p1.cy ? p2.y : p2.y + NH); return 'M' + sx + ',' + sy + ' C' + sx + ',' + ((sy + ey) / 2) + ' ' + ex + ',' + ((sy + ey) / 2) + ' ' + ex + ',' + ey; }
    if (p1.lr === p2.lr && p2.x > p1.x) { var x1 = p1.x + NW, y1 = p1.cy, x2 = p2.x, y2 = p2.cy, mx = (x1 + x2) / 2; return 'M' + x1 + ',' + y1 + ' C' + mx + ',' + y1 + ' ' + mx + ',' + y2 + ' ' + x2 + ',' + y2; }
    // a step that wraps to the next row: drop out of the bottom and curve back up to the row start
    var bx = p1.cx, by = p1.y + NH, tx = p2.cx, ty = p2.y, my = (by + ty) / 2;
    return 'M' + bx + ',' + by + ' C' + bx + ',' + my + ' ' + tx + ',' + my + ' ' + tx + ',' + ty;
  }

  function atlasView() {
    var LY = atlasLayout(), A = LY.A, pos = LY.pos, M = study().mastery();
    var laneEdgeSvg = A.laneEdges.map(function (e) { var d = edgePath(pos, e.from, e.to, false); return d ? '<path class="atlas-edge atlas-edge-lane lane-' + study().laneEntry(e.from).laneKey + '" d="' + d + '"/>' : ''; }).join('');
    var crossEdgeSvg = A.crossEdges.map(function (e) { var d = edgePath(pos, e.from, e.to, true); return d ? '<path class="atlas-edge atlas-edge-cross" d="' + d + '"><title>' + esc(e.note || '') + '</title></path>' : ''; }).join('');
    var nodeSvg = A.nodes.map(function (n) {
      var p = pos[n.id]; if (!p) return '';
      var proof = (n.proves && n.proves[0]) ? human(n.proves[0]) : '', mk = M[n.id] || {};
      var glyph = mk.correct ? '✓' : (mk.studied ? '◐' : '');
      return '<g class="atlas-node lane-' + n.lane + (mk.correct ? ' done' : (mk.studied ? ' seen' : '')) + '" data-anode="' + U.attr(n.id) + '" data-cx="' + p.cx + '" data-cy="' + p.cy + '" transform="translate(' + p.x + ',' + p.y + ')">'
        + '<rect class="an-box" width="' + NW + '" height="' + NH + '" rx="9"/>'
        + '<text class="an-badge" x="9" y="-7"></text>'
        + '<text class="an-mastery" x="' + (NW - 11) + '" y="17">' + glyph + '</text>'
        + '<text class="an-ph" x="11" y="16">' + esc(n.phase.toUpperCase()) + '</text>'
        + '<text class="an-t" x="11" y="31">' + esc(n.title.length > 24 ? n.title.slice(0, 23) + '…' : n.title) + '</text>'
        + '<text class="an-sub" x="11" y="43">' + esc(proof ? ('→ ' + (proof.length > 26 ? proof.slice(0, 25) + '…' : proof)) : '') + '</text>'
        + '</g>';
    }).join('');
    var bandSvg = LY.bands.map(function (b) {
      var prog = study().laneProgress(b.key);
      var label = '<g class="atlas-band lane-' + b.key + (b.collapsed ? ' collapsed' : '') + '" data-band="' + U.attr(b.key) + '">'
        + '<rect class="ab-bg" x="4" y="' + b.top + '" width="' + (LY.W - 8) + '" height="' + b.h + '" rx="10"/>'
        + '<text class="ab-chev" x="14" y="' + (b.top + 19) + '">' + (b.collapsed ? '▸' : '▾') + '</text>'
        + '<text class="atlas-lanelabel lane-' + b.key + '" x="30" y="' + (b.top + 19) + '">' + esc(b.short) + '</text>'
        + '<text class="ab-count" x="' + (LY.W - 20) + '" y="' + (b.top + 19) + '">' + prog.studied + '/' + b.count + '</text>';
      if (b.collapsed) {
        // folded: a strip of dots so the lane's size and progress still read at a glance
        var dots = b.nodes.map(function (n, i) { var mk = (study().mastery()[n.id] || {}); var cls = mk.correct ? ' done' : (mk.studied ? ' seen' : ''); return '<circle class="ab-dot' + cls + '" cx="' + (118 + i * 11) + '" cy="' + (b.top + 15) + '" r="3.2"/>'; }).join('');
        label += dots;
      }
      return label + '</g>';
    }).join('');

    return '<section class="study-route study-atlas-route">'
      + '<div class="study-top"><button type="button" class="study-back" data-back-map>← Paths</button>'
      + '<div class="study-crumb"><b>Study</b> · Atlas <span class="study-map-path-note">drag to pan · scroll to zoom · click a step to add it to a path · click a lane title to fold it</span></div>'
      + '<div class="atlas-ctrl">'
      + '<input type="search" class="atlas-search" id="atlas-search" placeholder="Search steps…" value="' + U.attr(_atlasQuery) + '" autocomplete="off" spellcheck="false">'
      + '<button type="button" class="study-rp-btn" data-az="out">−</button>'
      + '<button type="button" class="study-rp-btn" data-az="reset">fit</button>'
      + '<button type="button" class="study-rp-btn" data-az="in">+</button></div></div>'
      + '<div class="atlas-scenarios"><span class="atlas-scen-l">Common scenarios</span>'
      + study().scenarios().map(function (s) { return '<button type="button" class="atlas-scen' + (s.key === _scenario ? ' on' : '') + '" data-scen="' + U.attr(s.key) + '" title="' + U.attr(s.desc) + '">' + esc(s.name) + '</button>'; }).join('')
      + '<span class="atlas-scen-or">or click steps to draw your own</span></div>'
      + '<div class="atlas-stage" id="atlas-stage">'
      + '<svg class="atlas-svg" id="atlas-svg"><g class="atlas-view" id="atlas-view" data-w="' + LY.W + '" data-h="' + LY.H + '">'
      + '<g class="atlas-bands">' + bandSvg + '</g>'
      + '<g class="atlas-edges">' + laneEdgeSvg + crossEdgeSvg + '</g>'
      + '<path class="atlas-pathline" id="atlas-pathline" d=""/>'
      + '<g class="atlas-nodes">' + nodeSvg + '</g></g></svg>'
      + '<div class="atlas-minimap" id="atlas-minimap"><svg id="atlas-mini-svg" class="atlas-mini-svg"></svg><div class="atlas-mini-vp" id="atlas-mini-vp"></div></div>'
      + '<div class="atlas-empty" id="atlas-empty" hidden>No step matches “<span id="atlas-empty-q"></span>”.</div>'
      + '</div>'
      + '<div class="atlas-tray" id="atlas-tray"></div>'
      + '</section>';
  }

  function nodeView() {
    var right = _gear === 'practice' ? practicePanel() : cellPanel();
    return '<section class="study-route">'
      + '<div class="study-top">'
      + '<button type="button" class="study-back" data-back>← ' + (_pathMode ? 'Your path' : (_from === 'atlas' ? 'The Atlas' : (_from === 'ports' ? 'Open ports' : 'All paths'))) + '</button>'
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
    return _view === 'map' ? mapView() : (_view === 'atlas' ? atlasView() : (_view === 'ports' ? portsView() : nodeView()));
  }

  // ---- replay controller ----------------------------------------------------------------------
  // The replay walks rp.steps in order. A multi-step fixture (a tunnel set up on both your box and the
  // target) gets a "on your box (Kali)" / "on the target" header before each step's prompt, so the
  // learner always sees WHERE each command runs and in what order. The prompt itself (kali$ / target$)
  // also reflects the locus.
  function cancelReplay() { if (_rpToken) { _rpToken.cancelled = true; _rpToken = null; } }
  function stepHeader(where) {
    return where === 'host'
      ? '<div class="rp-step-h rp-host"><span class="rp-where-glyph">🎯</span> on the target — the compromised host</div>'
      : '<div class="rp-step-h rp-local"><span class="rp-where-glyph">🖥</span> on your box (Kali)</div>';
  }
  function promptFor(where) { return where === 'host' ? 'target$' : 'kali$'; }
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
    if (prog) prog.textContent = 'move ' + (idx + 1) + ' / ' + seq.length + (rp.multi ? ' · ' + rp.steps.length + ' setup steps' : '');
    var steps = rp.steps && rp.steps.length ? rp.steps : [{ where: 'local', command: rp.command, outputLines: rp.outputLines }];
    var multi = steps.length > 1;
    function popFacts(delay) {
      study().markStudied(rp.id, 'studied');   // watching a move through counts as having studied it
      (rp.proves || []).forEach(function (f, k) { setTimeout(function () { if (token.cancelled || !facts) return; var c = document.createElement('span'); c.className = 'study-chip proof rp-pop'; c.textContent = '+ ' + human(f); facts.appendChild(c); }, delay + k * 260); });
      var nextId = rp.next;
      if (_pathMode && _path.length) { var pi = _path.indexOf(rp.id); nextId = (pi >= 0 && pi < _path.length - 1) ? _path[pi + 1] : null; }
      if (_autolane && nextId) setTimeout(function () { if (token.cancelled) return; _sel = nextId; _autoplay = true; OBOL.router.render(); }, delay + (rp.proves.length * 260) + 1400);
    }
    function lineHtml(ln) {
      var hot = rp.signal && ln.indexOf(rp.signal) >= 0;
      return '<div class="rp-line rp-out' + (hot ? ' hot' : '') + '">' + esc(ln || ' ') + '</div>'
        + (hot && rp.teach ? '<div class="rp-cap">← ' + codeify(rp.teach) + '</div>' : '');
    }
    if (instant) {
      var html = steps.map(function (s) {
        var head = multi ? stepHeader(s.where) : '';
        var cmdLine = '<div class="rp-line rp-cmd"><span class="rp-prompt' + (s.where === 'host' ? ' host' : '') + '">' + promptFor(s.where) + '</span> ' + esc(s.command) + '</div>';
        return head + cmdLine + (s.outputLines || []).map(lineHtml).join('');
      }).join('');
      term.innerHTML = html; term.scrollTop = term.scrollHeight; popFacts(200); return;
    }
    // animated: type each step's command, stream its output, then move to the next step
    var si = 0;
    (function nextStep() {
      if (token.cancelled) return;
      if (si >= steps.length) { popFacts(300); return; }
      var s = steps[si];
      if (multi) { var h = document.createElement('div'); h.innerHTML = stepHeader(s.where); term.appendChild(h.firstChild); term.scrollTop = term.scrollHeight; }
      var promptLine = document.createElement('div'); promptLine.className = 'rp-line rp-cmd';
      promptLine.innerHTML = '<span class="rp-prompt' + (s.where === 'host' ? ' host' : '') + '">' + promptFor(s.where) + '</span> <span class="rp-typed"></span><span class="rp-cursor">▋</span>';
      term.appendChild(promptLine); term.scrollTop = term.scrollHeight;
      var typed = promptLine.querySelector('.rp-typed'), cmd = s.command || '', ci = 0;
      (function typeCmd() {
        if (token.cancelled) return;
        if (ci <= cmd.length) { typed.textContent = cmd.slice(0, ci); ci++; setTimeout(typeCmd, 14); return; }
        var cur = promptLine.querySelector('.rp-cursor'); if (cur) cur.remove();
        var lines = s.outputLines || [];
        if (!lines.length) {
          if (si === steps.length - 1 && !rp.hasOutput) { var ns = document.createElement('div'); ns.className = 'rp-line rp-nosample-line'; ns.textContent = '· sample output for this step is still being captured — but you can see the command above and what it proves below ·'; term.appendChild(ns); }
          si++; setTimeout(nextStep, 500); return;
        }
        var i = 0;
        (function nextLine() {
          if (token.cancelled) return;
          if (i >= lines.length) { si++; setTimeout(nextStep, multi ? 650 : 300); return; }
          var ln = lines[i], el = document.createElement('div');
          var hot = rp.signal && ln.indexOf(rp.signal) >= 0;
          el.className = 'rp-line rp-out' + (hot ? ' hot' : ''); el.textContent = ln || ' ';
          term.appendChild(el); term.scrollTop = term.scrollHeight;
          if (hot && rp.teach) { var cap = document.createElement('div'); cap.className = 'rp-cap'; cap.innerHTML = '← ' + codeify(rp.teach); term.appendChild(cap); term.scrollTop = term.scrollHeight; }
          i++; setTimeout(nextLine, hot ? 1100 : 220);
        })();
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
  // a plain-language read-out of what (if anything) is wrong with the drawn path
  function pathWarnings() {
    if (_atlasPath.length < 2) return '';
    var v = study().validatePath(_atlasPath); if (v.ok) return '';
    var lines = v.issues.map(function (iss) {
      var c = study().cellFor(iss.id), title = c ? c.title : iss.id;
      if (iss.kind === 'unknown') return '<b>Step ' + (iss.idx + 1) + '</b> (' + esc(title) + ') isn\'t in this build.';
      var missing = (iss.missing || []).map(function (mk) { return /^one of:/.test(mk) ? ('one of: ' + mk.replace(/^one of:\s*/, '').split(' / ').map(human).join(' or ')) : human(mk); });
      return '<b>Step ' + (iss.idx + 1) + '</b> (' + esc(title) + ') needs ' + missing.map(function (x) { return '<i>' + esc(x) + '</i>'; }).join(', ') + ' — nothing earlier in this path gets you that.';
    });
    return '<div class="atlas-tray-warn"><span class="atw-i">🔒</span><div><b>Locked doors on this path:</b> '
      + lines.join(' ') + ' Add the step that opens each, or start where you already have the keys.</div></div>';
  }
  function atlasTray(mount) {
    var tray = mount.querySelector('#atlas-tray'); if (!tray) return;
    if (!_atlasPath.length) { tray.innerHTML = '<span class="atlas-tray-hint">Pick a <b>common scenario</b> above, or click steps in order to draw your own path — then study it as one guided run.</span>'; return; }
    var lead = _scenario ? ('<span class="atlas-tray-name">' + esc(scenName(_scenario)) + '</span>') : '<span class="atlas-tray-name custom">Custom path</span>';
    var chips = _atlasPath.map(function (id, i) { var c = study().cellFor(id); return '<span class="atlas-trchip lane-' + laneKeyOf(id) + '">' + (i + 1) + '. ' + esc(c ? c.title : id) + '</span>'; }).join('<span class="atlas-trarr">→</span>');
    tray.innerHTML = '<div class="atlas-tray-row">' + lead + '<div class="atlas-tray-path">' + chips + '</div>'
      + '<div class="atlas-tray-act"><button type="button" class="study-rp-btn" data-atlas="clear">clear</button>'
      + '<button type="button" class="study-rp-btn primary" data-atlas="study">▶ Study this path (' + _atlasPath.length + ') →</button></div></div>'
      + pathWarnings();
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
  // dim every step that doesn't match the search; returns the first matching node's id (for centring)
  function applyQuery(mount) {
    var q = _atlasQuery.trim().toLowerCase(), first = null, nMatch = 0;
    Array.prototype.forEach.call(mount.querySelectorAll('.atlas-node'), function (g) {
      var id = g.getAttribute('data-anode'), c = study().cellFor(id);
      var hay = (id + ' ' + (c ? c.title : '') + ' ' + (c && c.proves ? c.proves.map(human).join(' ') : '')).toLowerCase();
      var hit = !q || hay.indexOf(q) >= 0;
      g.classList.toggle('dim', !!q && !hit);
      g.classList.toggle('qmatch', !!q && hit);
      if (q && hit) { nMatch++; if (!first) first = id; }
    });
    var empty = mount.querySelector('#atlas-empty'); if (empty) { empty.hidden = !(q && nMatch === 0); var eq = mount.querySelector('#atlas-empty-q'); if (eq) eq.textContent = _atlasQuery; }
    return q ? first : null;
  }
  function wireAtlas(mount) {
    var stage = mount.querySelector('#atlas-stage'), view = mount.querySelector('#atlas-view');
    if (!stage || !view) return;
    var W = +view.getAttribute('data-w'), H = +view.getAttribute('data-h');
    var mini = mount.querySelector('#atlas-minimap'), miniSvg = mount.querySelector('#atlas-mini-svg'), miniVp = mount.querySelector('#atlas-mini-vp');
    var MINIW = 164, miniK = Math.min(MINIW / W, 120 / H), miniH = Math.round(H * miniK);
    if (miniSvg) {
      miniSvg.setAttribute('viewBox', '0 0 ' + W + ' ' + H); miniSvg.setAttribute('width', Math.round(W * miniK)); miniSvg.setAttribute('height', miniH);
      miniSvg.innerHTML = atlasLayout().bands.map(function (b) { return '<rect class="amm-band lane-' + b.key + '" x="4" y="' + b.top + '" width="' + (W - 8) + '" height="' + b.h + '" rx="8"/>'; }).join('');
      if (mini) mini.style.width = Math.round(W * miniK) + 'px';
    }
    function updateMini() {
      if (!miniVp) return; var r = stage.getBoundingClientRect();
      var vx = (-_az.tx / _az.k) * miniK, vy = (-_az.ty / _az.k) * miniK, vw = (r.width / _az.k) * miniK, vh = (r.height / _az.k) * miniK;
      miniVp.style.left = Math.max(0, vx) + 'px'; miniVp.style.top = Math.max(0, vy) + 'px';
      miniVp.style.width = Math.min(vw, Math.round(W * miniK)) + 'px'; miniVp.style.height = Math.min(vh, miniH) + 'px';
    }
    function apply() { atlasApply(view); atlasLOD(stage); updateMini(); }
    function fit() { var r = stage.getBoundingClientRect(); var k = Math.min((r.width - 24) / W, (r.height - 24) / H, 1.1); k = Math.max(k, 0.26); _az = { k: k, tx: (r.width - W * k) / 2, ty: 12 }; apply(); }
    function zoomAround(mx, my, f) { var nk = Math.max(0.26, Math.min(2.4, _az.k * f)), ratio = nk / _az.k; _az.tx = mx - (mx - _az.tx) * ratio; _az.ty = my - (my - _az.ty) * ratio; _az.k = nk; apply(); }
    function centerOn(id) { var g = mount.querySelector('.atlas-node[data-anode="' + id + '"]'); if (!g) return; var r = stage.getBoundingClientRect(); var cx = +g.getAttribute('data-cx'), cy = +g.getAttribute('data-cy'); _az.tx = r.width / 2 - cx * _az.k; _az.ty = r.height / 2 - cy * _az.k; apply(); }
    if (!_az) fit(); else apply();
    atlasSelection(mount);
    if (_atlasQuery) applyQuery(mount);
    var down = null, moved = false;
    stage.addEventListener('pointerdown', function (e) { if (e.target.closest && (e.target.closest('.atlas-band') || e.target.closest('.atlas-minimap'))) { down = null; return; } var g = e.target.closest && e.target.closest('.atlas-node'); down = { x: e.clientX, y: e.clientY, tx: _az.tx, ty: _az.ty, node: g }; moved = false; try { stage.setPointerCapture(e.pointerId); } catch (x) {} });
    stage.addEventListener('pointermove', function (e) { if (!down) return; var dx = e.clientX - down.x, dy = e.clientY - down.y; if (Math.abs(dx) + Math.abs(dy) > 4) moved = true; _az.tx = down.tx + dx; _az.ty = down.ty + dy; apply(); });
    stage.addEventListener('pointerup', function () { var wasMoved = moved, g = down && down.node; down = null; if (wasMoved || !g) return; var id = g.getAttribute('data-anode'), i = _atlasPath.indexOf(id); if (i >= 0) _atlasPath.splice(i, 1); else _atlasPath.push(id); _scenario = null; atlasSelection(mount); });
    stage.addEventListener('wheel', function (e) { e.preventDefault(); var r = stage.getBoundingClientRect(); zoomAround(e.clientX - r.left, e.clientY - r.top, e.deltaY < 0 ? 1.12 : 0.89); }, { passive: false });
    // minimap: click to recentre the stage on that point
    if (mini) mini.addEventListener('click', function (e) { var r = mini.getBoundingClientRect(), sr = stage.getBoundingClientRect(); var cx = (e.clientX - r.left) / miniK, cy = (e.clientY - r.top) / miniK; _az.tx = sr.width / 2 - cx * _az.k; _az.ty = sr.height / 2 - cy * _az.k; apply(); });
    U.on(mount, 'click', '[data-az]', function (e, t) { var a = t.getAttribute('data-az'); if (a === 'in' || a === 'out') { var r = stage.getBoundingClientRect(); zoomAround(r.width / 2, r.height / 2, a === 'in' ? 1.2 : 0.83); } else fit(); });
    U.on(mount, 'click', '[data-atlas="clear"]', function () { _atlasPath = []; _scenario = null; atlasSelection(mount); });
    U.on(mount, 'click', '[data-atlas="study"]', function () { if (!_atlasPath.length) return; _path = _atlasPath.slice(); _pathName = _scenario ? scenName(_scenario) : 'Your custom path'; _pathMode = true; _from = 'atlas'; _sel = _path[0]; _view = 'node'; OBOL.router.render(); });
    // fold / unfold a lane band (full re-render — the whole layout reflows around it; the pan/zoom persists)
    U.on(mount, 'click', '[data-band]', function (e, t) { var k = t.getAttribute('data-band'); _collapsed[k] = !_collapsed[k]; OBOL.router.render(); });
    // search: dim non-matches, centre the first hit
    U.on(mount, 'input', '#atlas-search', function (e, t) { _atlasQuery = t.value || ''; var first = applyQuery(mount); if (first) centerOn(first); });
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
    U.on(mount, 'click', '[data-open]', function (e, t) { _from = (_view === 'atlas' ? 'atlas' : (_view === 'ports' ? 'ports' : 'map')); _sel = t.getAttribute('data-open'); _view = 'node'; OBOL.router.render(); });
    U.on(mount, 'click', '[data-back]', function () { _view = _from; OBOL.router.render(); });
    U.on(mount, 'click', '[data-back-map]', function () { _view = 'map'; OBOL.router.render(); });
    U.on(mount, 'click', '[data-graph]', function () { _view = 'atlas'; OBOL.router.render(); });
    U.on(mount, 'click', '[data-ports]', function () { _view = 'ports'; OBOL.router.render(); });
    // node select + "opens →" jumps + goto chips → re-render
    U.on(mount, 'click', '[data-node]', function (e, t) { _sel = t.getAttribute('data-node'); OBOL.router.render(); });
    U.on(mount, 'click', '[data-goto]', function (e, t) { _sel = t.getAttribute('data-goto'); _view = 'node'; OBOL.router.render(); });
    // gear toggle → re-render
    U.on(mount, 'click', '[data-gear]', function (e, t) { _gear = t.getAttribute('data-gear'); OBOL.router.render(); });
    // "Run it from" toggle: remote (your box) vs on the target — local DOM swap, no re-render
    U.on(mount, 'click', '[data-runway]', function (e, t) {
      var way = t.getAttribute('data-runway');
      Array.prototype.forEach.call(mount.querySelectorAll('.rw-tab'), function (b) { b.classList.toggle('on', b.getAttribute('data-runway') === way); });
      Array.prototype.forEach.call(mount.querySelectorAll('.rw-pane'), function (p) { p.hidden = p.getAttribute('data-pane') !== way; });
    });
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
      if (verdict === 'correct') { head = '✓ Exactly.'; body = 'That\'s the move. Here\'s how it plays out →'; study().markStudied(_sel, 'correct'); }
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
