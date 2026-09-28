/*!
 * obol ui — graphtip.js — hover/focus cards for path-graph nodes. On hovering (or keyboard-focusing) a
 * node, a floating card explains what it is, why it matters, the note (proven / ready / locked), the
 * command to run — with a copy button — and references. Content comes from OBOL.graph.buildNodeInfo.
 * The card is position:fixed on <body> so the graphview's overflow:hidden never clips it.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util || {};
  function esc(s) { return U.esc ? U.esc(String(s == null ? '' : s)) : String(s == null ? '' : s); }
  function attr(s) { return U.attr ? U.attr(String(s == null ? '' : s)) : esc(s); }

  var _card = null, _hideT = null;
  function ensureCard() {
    if (_card) return _card;
    _card = document.createElement('div');
    _card.className = 'gv-card';
    _card.setAttribute('role', 'dialog');
    _card.addEventListener('mouseenter', function () { clearTimeout(_hideT); });
    _card.addEventListener('mouseleave', scheduleHide);
    _card.addEventListener('click', function (e) {
      var b = e.target.closest && e.target.closest('[data-gvcopy]'); if (!b) return;
      var cmd = b.getAttribute('data-gvcopy');
      if (U.copy) U.copy(cmd).then(function (ok) { if (U.toast) U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    document.body.appendChild(_card);
    return _card;
  }
  function scheduleHide() { clearTimeout(_hideT); _hideT = setTimeout(hide, 200); }
  function hide() { if (_card) _card.style.display = 'none'; }

  function render(info) {
    var c = ensureCard();
    var ph = info.phase ? '<span class="gv-card-ph ph-' + esc(info.phase) + '">' + esc(info.phase) + '</span>' : '';
    var html = '<div class="gv-card-h">' + ph + '<span class="gv-card-title">' + esc(info.title) + '</span></div>';
    if (info.note) html += '<div class="gv-card-note gv-' + esc(info.state || '') + '">' + esc(info.note) + '</div>';
    if (info.explain) html += '<div class="gv-card-explain">' + esc(info.explain) + '</div>';
    if (info.command) {
      html += '<div class="gv-card-cmdlbl">' + esc(info.command_label || 'Command') + '</div>'
        + '<div class="gv-card-cmd"><code>' + esc(info.command) + '</code>'
        + '<button class="gv-card-copy" data-gvcopy="' + attr(info.command) + '" title="Copy command" aria-label="Copy command">⧉</button></div>';
    }
    if (info.refs && info.refs.length) {
      html += '<div class="gv-card-refs">' + info.refs.map(function (r) { return '<a href="' + attr(r) + '" target="_blank" rel="noopener">ref ↗</a>'; }).join(' · ') + '</div>';
    }
    c.innerHTML = html;
  }
  function position(c, el) {
    c.style.display = 'block'; c.style.visibility = 'hidden'; c.style.left = '0'; c.style.top = '0';
    var r = el.getBoundingClientRect(), cw = c.offsetWidth, ch = c.offsetHeight, pad = 8;
    var left = r.left + r.width / 2 - cw / 2, top = r.bottom + 8;
    if (top + ch + pad > window.innerHeight && r.top - ch - 8 > pad) top = r.top - ch - 8;
    left = Math.max(pad, Math.min(left, window.innerWidth - cw - pad));
    top = Math.max(pad, Math.min(top, window.innerHeight - ch - pad));
    c.style.left = left + 'px'; c.style.top = top + 'px'; c.style.visibility = 'visible';
  }

  function attach(scope, nodeInfo) {
    scope = scope || document; nodeInfo = nodeInfo || {};
    var nodes = scope.querySelectorAll ? scope.querySelectorAll('[data-nid]') : [];
    Array.prototype.forEach.call(nodes, function (el) {
      if (el._gvtip) return; el._gvtip = true;
      var info = nodeInfo[el.getAttribute('data-nid')]; if (!info) return;
      function show() { clearTimeout(_hideT); render(info); position(ensureCard(), el); }
      el.addEventListener('mouseenter', show);
      el.addEventListener('mouseleave', scheduleHide);
      el.addEventListener('focus', show);
      el.addEventListener('blur', scheduleHide);
      el.addEventListener('click', function (e) { e.stopPropagation(); show(); });
    });
  }
  OBOL.graphtip = { attach: attach, hide: hide };
})(typeof globalThis !== 'undefined' ? globalThis : this);
