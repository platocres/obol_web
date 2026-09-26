/*!
 * obol ui — palette.js — the ⌘K / Ctrl+K command palette. Fuzzy-searches every methodology
 * command (across all pack actions) plus nav routes; Enter copies the command with {{tokens}}
 * filled from the active engagement's params + facts + profile, or navigates for a route.
 * Always available (global keydown); the index builds lazily on first open.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;

  var overlay = null, input = null, list = null, sel = 0, items = [], filtered = [];
  var cmdIndex = null;

  function esc(s) { return U.esc(s); }

  function buildIndex() {
    if (cmdIndex) return cmdIndex;
    var out = [];
    // nav routes
    document.querySelectorAll('header nav a[href^="#/"]').forEach(function (a) {
      out.push({ kind: 'nav', label: a.textContent.trim(), hint: 'go to', href: a.getAttribute('href') });
    });
    // every pack action command variant
    (OBOL.packs ? OBOL.packs.actions() : []).forEach(function (act) {
      var cmds = (act.commands && act.commands.length) ? act.commands : [{ run: act.command, tool: act.tool }];
      cmds.forEach(function (c) {
        if (!c || !c.run) return;
        out.push({ kind: 'cmd', label: act.title, hint: (c.tool || act.tool || 'cmd'), run: c.run, lane: OBOL.phases.phaseOfAction(act) });
      });
    });
    cmdIndex = out;
    return out;
  }

  // score: all query tokens present; earlier + prefix wins. -Infinity = no match.
  function score(text, q) {
    text = text.toLowerCase();
    var toks = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!toks.length) return 0;
    var s = 0;
    for (var i = 0; i < toks.length; i++) {
      var idx = text.indexOf(toks[i]);
      if (idx < 0) return -Infinity;
      s -= idx; if (idx === 0) s += 50;
    }
    return s;
  }

  function refresh(q) {
    var idx = buildIndex();
    if (!q) { filtered = idx.slice(0, 40); }
    else {
      filtered = idx.map(function (it) { return { it: it, s: score(it.label + ' ' + it.hint + ' ' + (it.run || ''), q) }; })
        .filter(function (x) { return isFinite(x.s); })
        .sort(function (a, b) { return b.s - a.s; })
        .slice(0, 40).map(function (x) { return x.it; });
    }
    sel = 0;
    renderList();
  }

  function fill(run) {
    try { return OBOL.command.fillTemplate(run, OBOL.store.factSet(), { params: (OBOL.store.active() || {}).params, profile: (OBOL.store.active() || {}).profile }); }
    catch (e) { return run; }
  }

  function renderList() {
    list.innerHTML = filtered.map(function (it, i) {
      var right = it.kind === 'cmd' ? '<code class="pal-run">' + esc(fill(it.run)) + '</code>' : '<span class="pal-go">' + esc(it.href) + '</span>';
      var tag = it.kind === 'cmd' ? '<span class="ph-chip ph-' + esc(it.lane) + '">' + esc(it.hint) + '</span>' : '<span class="pal-navtag">nav</span>';
      return '<li class="pal-item' + (i === sel ? ' sel' : '') + '" data-i="' + i + '">' + tag
        + '<span class="pal-label">' + esc(it.label) + '</span>' + right + '</li>';
    }).join('') || '<li class="pal-empty">No matches</li>';
    var s = list.querySelector('.pal-item.sel'); if (s) s.scrollIntoView({ block: 'nearest' });
  }

  function open() {
    if (!overlay) build();
    overlay.classList.add('show');
    input.value = ''; refresh('');
    setTimeout(function () { input.focus(); }, 0);
  }
  function close() { if (overlay) overlay.classList.remove('show'); }
  function isOpen() { return overlay && overlay.classList.contains('show'); }

  function activate(i) {
    var it = filtered[i]; if (!it) return;
    if (it.kind === 'nav') { close(); OBOL.router.go(it.href); return; }
    U.copy(fill(it.run)).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    close();
  }

  function build() {
    overlay = document.createElement('div');
    overlay.className = 'pal-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.innerHTML = '<div class="pal-box"><input class="pal-input" type="text" placeholder="Search commands &amp; pages…  (Enter copies with your target/creds filled)" aria-label="Command search" spellcheck="false">'
      + '<ul class="pal-list" role="listbox"></ul>'
      + '<div class="pal-foot">↑↓ move · Enter copy/go · Esc close</div></div>';
    document.body.appendChild(overlay);
    input = overlay.querySelector('.pal-input');
    list = overlay.querySelector('.pal-list');
    input.addEventListener('input', function () { refresh(input.value); });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(sel + 1, filtered.length - 1); renderList(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(sel - 1, 0); renderList(); }
      else if (e.key === 'Enter') { e.preventDefault(); activate(sel); }
      else if (e.key === 'Escape') { e.preventDefault(); close(); }
    });
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) { close(); return; }
      var li = e.target.closest('.pal-item'); if (li) activate(+li.getAttribute('data-i'));
    });
  }

  function init() {
    document.addEventListener('keydown', function (e) {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); isOpen() ? close() : open(); }
    });
  }

  OBOL.palette = { init: init, open: open, close: close };
})(typeof globalThis !== 'undefined' ? globalThis : this);
