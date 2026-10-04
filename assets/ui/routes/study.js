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

  var _view = 'map';             // 'map' (pick a lane / step) | 'node' (study one step)
  var _gear = 'watch';           // 'watch' | 'practice'
  var _sel = 'asrep-roast';      // selected lane node
  var _autolane = false;         // Watch: auto-advance through the whole chain
  var _autoplay = false;         // start the replay as soon as the next node mounts (chain mode)
  var _rpToken = null;           // cancel token for the running replay's timers

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

  // ---- left: the lane graph -------------------------------------------------------------------
  function graphPanel() {
    var lane = study().lane(), lastPhase = null, html = '';
    lane.forEach(function (n, i) {
      if (n.phase !== lastPhase) { html += '<div class="study-phase">' + esc(n.phase) + '</div>'; lastPhase = n.phase; }
      var cls = 'study-gnode' + (n.id === _sel ? ' active' : '') + (i > 0 ? ' linked' : '');
      html += '<button type="button" class="' + cls + '" data-node="' + U.attr(n.id) + '">'
        + '<span class="study-gn-t">' + esc(n.title) + '</span>'
        + (n.proves && n.proves.length ? '<span class="study-gn-k">gets you ' + esc(human(n.proves[0])) + '</span>' : '')
        + '</button>';
    });
    return '<div class="study-panel study-graph-panel">'
      + '<p class="study-panel-h">Active Directory lane · click a node</p>'
      + '<div class="study-graph">' + html + '</div>'
      + '<p class="study-graph-foot">A guided path through the AD methodology. Milestone 1 — more lanes to come.</p>'
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
  function comingLane(name, desc) {
    return '<div class="study-lane-card coming"><div class="study-lane-name">' + esc(name) + '</div>'
      + '<div class="study-lane-desc">' + esc(desc) + '</div><div class="study-lane-soon">more lanes coming</div></div>';
  }
  function door(href, glyph, title, desc) {
    return '<a class="study-door" href="' + href + '"><span class="study-door-g">' + glyph + '</span>'
      + '<span class="study-door-t">' + esc(title) + '</span><span class="study-door-d">' + esc(desc) + '</span></a>';
  }
  function mapView() {
    var lane = study().lane();
    var h = '<section class="study-route study-map">';
    h += '<div class="study-hero"><h1 class="study-hero-h">Learn the methodology</h1>'
      + '<p class="study-hero-p">obol teaches offensive security as a decision graph — <b>know what to do, and why, from what you\'ve found.</b> '
      + 'Pick a path below and step through it: watch each move play out like it would on a real box, or test yourself.</p></div>';
    h += '<div class="study-lanes">'
      + '<button type="button" class="study-lane-card active" data-open="' + U.attr(lane[0].id) + '">'
      + '<div class="study-lane-name">Active Directory <span class="study-lane-badge">' + lane.length + ' steps</span></div>'
      + '<div class="study-lane-desc">From an anonymous foothold to owning the domain — enumerate, roast, crack, abuse ACLs, DCSync.</div>'
      + '<div class="study-lane-go">Start the path →</div></button>'
      + comingLane('Web Exploitation', 'LFI, SQLi, file upload → a shell on the box.')
      + comingLane('Linux Privesc', 'sudo, SUID, cron, capabilities → root.')
      + comingLane('Windows Privesc', 'services, tokens, AlwaysInstallElevated → SYSTEM.')
      + '</div>';
    h += '<div class="study-map-path"><div class="study-map-path-h">Active Directory · the whole path <span class="study-map-path-note">click any step to study it</span></div>'
      + pathStrip(lane) + '</div>';
    h += '<div class="study-doors">'
      + door('#/loadout', '⚙', 'Set up your box', 'Install the toolset so the commands you learn match your own machine.')
      + door('#/home', '▶', 'Start an engagement', 'Working a real box? Track it — paste output, get your next move.')
      + '</div>';
    return h + '</section>';
  }

  function nodeView() {
    var right = _gear === 'practice' ? practicePanel() : cellPanel();
    return '<section class="study-route">'
      + '<div class="study-top">'
      + '<button type="button" class="study-back" data-back>← All paths</button>'
      + '<div class="study-crumb"><b>Study</b> · Active Directory · <span class="study-here">' + esc((study().cellFor(_sel) || {}).title || _sel) + '</span></div>'
      + '<div class="study-gears">'
      + '<button type="button" class="study-gear' + (_gear === 'watch' ? ' on' : '') + '" data-gear="watch">▶ Watch</button>'
      + '<button type="button" class="study-gear' + (_gear === 'practice' ? ' on' : '') + '" data-gear="practice">✎ Your turn</button>'
      + '</div></div>'
      + '<div class="study-cols">' + graphPanel() + right + '</div>'
      + '</section>';
  }

  function render(ctx) {
    if (ctx && ctx.args && ctx.args[0] && study().cellFor(ctx.args[0])) { _sel = ctx.args[0]; _view = 'node'; }
    return _view === 'map' ? mapView() : nodeView();
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
    var laneIds = study().AD_LANE.map(function (x) { return x.id; }), idx = laneIds.indexOf(rp.id);
    if (prog) prog.textContent = 'step ' + (idx + 1) + ' / ' + laneIds.length;
    function popFacts(delay) {
      (rp.proves || []).forEach(function (f, k) { setTimeout(function () { if (token.cancelled || !facts) return; var c = document.createElement('span'); c.className = 'study-chip proof rp-pop'; c.textContent = '+ ' + human(f); facts.appendChild(c); }, delay + k * 260); });
      if (_autolane && rp.next) setTimeout(function () { if (token.cancelled) return; _sel = rp.next; _autoplay = true; OBOL.router.render(); }, delay + (rp.proves.length * 260) + 1400);
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

  function mounted(ctx) {
    var mount = ctx.mount;
    cancelReplay();
    // map: open a lane/step → node view
    U.on(mount, 'click', '[data-open]', function (e, t) { _sel = t.getAttribute('data-open'); _view = 'node'; OBOL.router.render(); });
    U.on(mount, 'click', '[data-back]', function () { _view = 'map'; OBOL.router.render(); });
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
