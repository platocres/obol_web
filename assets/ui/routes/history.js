/*!
 * obol ui — routes/history.js — the Run Log: every command run / evidence ingested on this engagement,
 * newest first, with what it proved and its full saved output. The coach shows only the moves that matter
 * for the attack path; this is the complete record for review across runs. Read-only over the ledger.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function when(ts) {
    if (!ts) return '';
    try { return new Date(ts).toLocaleString(); } catch (e) { return ''; }
  }
  // What to show as the command: the honest command, or a clear label when a file/output-only paste
  // carried none (so the row is never blank).
  function label(a) {
    if (a.command) return a.command;
    if (a.file) return 'attached file: ' + a.file;
    if (a.dispatch) return a.dispatch + '  (recognized from output)';
    return (a.tool && a.tool !== 'paste') ? a.tool + '  (pasted output)' : 'pasted output';
  }

  function render() {
    var eng = OBOL.store.active() || {};
    var acts = (eng.activities || []);
    if (!acts.length) {
      return '<section class="history-route"><h1 class="route-h1">Run Log</h1>'
        + '<p class="route-sub">No commands logged yet. Everything you paste or attach on the Evidence route — the command and its full output — is recorded here so you can review the whole run later.</p></section>';
    }
    var rows = acts.map(function (a, i) {
      var cmd = label(a);
      var produced = (a.produced || []);
      var chips = produced.length
        ? produced.slice(0, 12).map(function (k) { return '<span class="hl-fact">' + esc(k) + '</span>'; }).join('') + (produced.length > 12 ? '<span class="hl-fact hl-more">+' + (produced.length - 12) + '</span>' : '')
        : '<span class="hl-nofact">no new facts</span>';
      var out = a.stdout || a.sample || '';
      var body = out
        ? '<details class="hl-out"><summary>output (' + (String(out).split(/\r?\n/).length) + ' lines)</summary><pre class="hl-pre">' + esc(out) + '</pre></details>'
        : '';
      var tgt = a.target || (a.scope || '').replace(/^host:/, '');
      return '<article class="hl-row" data-hl="' + i + '">'
        + '<div class="hl-head">'
        + '<span class="hl-time">' + esc(when(a.at)) + '</span>'
        + (tgt ? '<span class="pill hl-tgt">' + esc(tgt) + '</span>' : '')
        + (a.action_id ? '<span class="hl-move" title="move">' + esc(a.action_id) + '</span>' : '')
        + '<button class="btn-copy hl-copy" data-copy="' + U.attr(a.command || cmd) + '" title="Copy command">copy</button>'
        + '</div>'
        + '<pre class="hl-cmd"><code>' + esc(cmd) + '</code></pre>'
        + '<div class="hl-facts">' + chips + '</div>'
        + body
        + '</article>';
    }).join('');

    return '<section class="history-route"><h1 class="route-h1">Run Log</h1>'
      + '<p class="route-sub">Every command run on <strong>' + esc(eng.name || 'this engagement') + '</strong> (' + acts.length + '), newest first — with what it proved and its full saved output. Search to find one fast.</p>'
      + '<input class="hl-filter" type="search" placeholder="Filter commands and output…" autocomplete="off" spellcheck="false" aria-label="Filter the run log">'
      + '<div class="hl-list">' + rows + '</div></section>';
  }

  function mounted(ctx) {
    // Bind on the route's own recreated container (not the reused #view), so listeners die with the DOM.
    var mount = ctx.mount.querySelector('.history-route') || ctx.mount;
    U.on(mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    U.on(mount, 'input', '.hl-filter', function (e, t) {
      var q = (t.value || '').toLowerCase().trim();
      Array.prototype.forEach.call(mount.querySelectorAll('.hl-row'), function (row) {
        row.hidden = !!q && row.textContent.toLowerCase().indexOf(q) < 0;
      });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.history = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
