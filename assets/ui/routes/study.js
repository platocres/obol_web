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

  var _gear = 'watch';           // 'watch' | 'practice'
  var _sel = 'asrep-roast';      // selected lane node

  function esc(s) { return U.esc(String(s == null ? '' : s)); }
  function study() { return OBOL.study; }

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
        + (n.proves && n.proves.length ? '<span class="study-gn-k">proves · ' + esc(n.proves[0]) + '</span>' : '')
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
      + (cmd.note ? '<div class="study-cmd-why">↳ ' + esc(cmd.note) + '</div>' : '')
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
  // ---- right: WATCH (the derived cell) --------------------------------------------------------
  function cellPanel() {
    var cell = study().cellFor(_sel, { profile: (OBOL.arsenal && OBOL.arsenal.profileGet && OBOL.arsenal.profileGet()) || null });
    if (!cell) return '<div class="study-panel"><p class="study-sub">Node unavailable in this build.</p></div>';
    var h = '<div class="study-panel">';
    h += '<div class="study-cell-h"><h2 class="study-cell-title">' + esc(cell.title) + '</h2>'
      + (cell.phase ? '<span class="study-badge b-phase">' + esc(cell.phase) + '</span>' : '')
      + (cell.scope ? '<span class="study-badge b-scope">' + esc(cell.scope === 'oscp' ? 'OSCP core' : cell.scope) + '</span>' : '')
      + (cell.locus ? '<span class="study-badge b-locus">' + esc(cell.locus === 'R' ? 'remote' : (cell.locus === 'F' ? 'on-host' : 'interactive')) + '</span>' : '')
      + '</div>';
    if (cell.whatItIs) h += '<p class="study-cell-sub">' + esc(cell.whatItIs) + '</p>';

    h += '<div class="study-seg"><div class="study-seg-l">🔑 To be here, you\'d have proved</div>'
      + '<div class="study-chips">' + (cell.prereqFacts.length ? chips(cell.prereqFacts, 'proven') : '<span class="study-dim">nothing — an opening move</span>') + '</div>'
      + (cell.producedBy.length ? '<div class="study-via">via ' + cell.producedBy.slice(0, 3).map(function (x) { return '<b>' + esc(x.title) + '</b>'; }).join(' · ') + '</div>' : '')
      + '</div>';

    h += '<div class="study-seg"><div class="study-seg-l">▶ You\'d run <span class="study-seg-note">— remote-first; prefer what needs the least access</span></div>'
      + cell.commands.map(commandBlock).join('') + '</div>';

    if (cell.output) h += '<div class="study-seg"><div class="study-seg-l">▌ You\'d likely see</div>' + outputBlock(cell.output) + '</div>';

    h += '<div class="study-seg"><div class="study-seg-l">✓ This proves · what it opens</div>'
      + '<div class="study-flow">' + chips(cell.proves, 'proof')
      + (cell.opens.length ? '<span class="study-arr">→ opens</span>' + cell.opens.slice(0, 4).map(function (x) { return '<span class="study-chip study-next" data-goto="' + U.attr(x.id) + '">' + esc(x.title) + ' →</span>'; }).join('') : '')
      + '</div></div>';

    if (cell.rulesOut) h += '<div class="study-mistake"><span class="study-ic">⚠</span><div><b>Watch out:</b> ' + esc(cell.rulesOut) + '</div></div>';

    h += '</div>';
    return h;
  }

  // ---- right: YOUR TURN (practice) ------------------------------------------------------------
  function practicePanel() {
    var q = study().practiceFor(_sel);
    if (!q) return '<div class="study-panel"><p class="study-sub">No practice for this node yet.</p></div>';
    var letters = 'ABCDEFGH';
    var h = '<div class="study-panel">';
    h += '<div class="study-scn"><div class="study-scn-l">The situation</div><p>' + esc(q.situation || 'Given where you are, what\'s your next move?') + '</p></div>';
    h += '<div class="study-q">What\'s your next move?</div><div class="study-choices">';
    q.choices.forEach(function (c, i) {
      var missing = (c.missing && c.missing.length) ? ' data-missing="' + U.attr(c.missing.join(', ')) + '"' : '';
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

  function render(ctx) {
    if (ctx && ctx.args && ctx.args[0] && study().cellFor(ctx.args[0])) _sel = ctx.args[0];
    var right = _gear === 'practice' ? practicePanel() : cellPanel();
    return '<section class="study-route">'
      + '<div class="study-top">'
      + '<div class="study-crumb"><b>Study</b> · Active Directory · <span class="study-here">' + esc((study().cellFor(_sel) || {}).title || _sel) + '</span></div>'
      + '<div class="study-gears">'
      + '<button type="button" class="study-gear' + (_gear === 'watch' ? ' on' : '') + '" data-gear="watch">▶ Watch</button>'
      + '<button type="button" class="study-gear' + (_gear === 'practice' ? ' on' : '') + '" data-gear="practice">✎ Your turn</button>'
      + '</div></div>'
      + '<div class="study-cols">' + graphPanel() + right + '</div>'
      + '</section>';
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    // node select + "opens →" jumps + goto chips → re-render
    U.on(mount, 'click', '[data-node]', function (e, t) { _sel = t.getAttribute('data-node'); OBOL.router.render(); });
    U.on(mount, 'click', '[data-goto]', function (e, t) { _sel = t.getAttribute('data-goto'); OBOL.router.render(); });
    // gear toggle → re-render
    U.on(mount, 'click', '[data-gear]', function (e, t) { _gear = t.getAttribute('data-gear'); OBOL.router.render(); });
    // practice: answer a choice (local DOM update, keeps the answered state)
    U.on(mount, 'click', '.study-choice', function (e, t) {
      var verdict = t.getAttribute('data-verdict'), coach = t.getAttribute('data-coach') || '', missing = t.getAttribute('data-missing') || '';
      Array.prototype.forEach.call(mount.querySelectorAll('.study-choice'), function (c) { c.classList.remove('ok', 'alt', 'bad', 'dimmed'); if (c !== t) c.classList.add('dimmed'); });
      t.classList.add(verdict === 'correct' ? 'ok' : (verdict === 'alt' ? 'alt' : 'bad'));
      var vbox = mount.querySelector('#study-verdict'), slot = mount.querySelector('#study-reveal-slot');
      if (slot) slot.innerHTML = '';
      var head, body;
      if (verdict === 'correct') { head = '✓ Exactly.'; body = 'That\'s the move. Here\'s how it plays out →'; }
      else if (verdict === 'alt') { head = '~ Also valid — but weigh it.'; body = coach || 'A legal move here; consider the tradeoff against the cleaner path.'; }
      else { head = '✗ Not yet.'; body = (coach || 'This needs something you don\'t have.') + (missing ? ' <span class="study-missing">Missing: ' + esc(missing) + '</span>' : ''); }
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
