/*!
 * obol ui — quickpaste.js — the one global paste.
 *
 * A header-reachable overlay (the trigger lives in the sticky appbar, so it is available from any
 * surface, Learn included) that runs the SAME ingest pipeline as the Evidence route: conservative
 * parsers mint only proven facts, each command's facts auto-route to the host it names, and any new
 * host is registered automatically. This is purely an additional entry point; the full Evidence
 * surface (file-attach, proof screenshots, the import panel) is unchanged.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(String(s == null ? '' : s)); }

  var _overlay = null, _lastFocus = null;

  function routeOptions() {
    var eng = OBOL.store.active() || {};
    var cur = (eng.params || {}).target || '';
    var ts = (eng.targets || []).map(function (t) { return t.ip || ''; }).filter(Boolean);
    return '<option value="auto">Auto-route by the IP in the output (recommended)</option>'
      + ts.map(function (ip) { return '<option value="' + U.attr(ip) + '"' + (ip === cur ? ' selected' : '') + '>Force everything onto ' + esc(ip) + '</option>'; }).join('');
  }

  function build() {
    var ov = document.createElement('div');
    ov.className = 'qp-overlay';
    ov.setAttribute('role', 'dialog');
    ov.setAttribute('aria-modal', 'true');
    ov.setAttribute('aria-label', 'Paste evidence');
    ov.innerHTML = '<div class="qp-panel">'
      + '<div class="qp-head"><span class="qp-title">Paste evidence</span>'
      + '<button type="button" class="qp-x" data-qp-close aria-label="Close">×</button></div>'
      + '<p class="qp-sub">Paste one command’s output, or a whole terminal session. Conservative parsers mint only the facts the output actually proves, and each lands on the host it names. New hosts are added for you.</p>'
      + '<textarea id="qp-text" class="qp-text" placeholder="Paste nmap, nxc, ffuf, secretsdump… output here" spellcheck="false" aria-label="Pasted output"></textarea>'
      + '<div class="qp-row"><label class="qp-route">Route facts to <select id="qp-route" aria-label="Route facts to">' + routeOptions() + '</select></label>'
      + '<button type="button" class="btn-primary" id="qp-go">Mint facts</button></div>'
      + '<div class="qp-result" id="qp-result" role="status" aria-live="polite"></div>'
      + '</div>';
    // focus trap: keep Tab within the panel while the dialog is open
    ov.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      var f = ov.querySelectorAll('button, textarea, select, a[href]');
      f = Array.prototype.filter.call(f, function (el) { return !el.disabled && el.offsetParent !== null; });
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
    document.body.appendChild(ov);
    return ov;
  }

  function open() {
    _lastFocus = document.activeElement;
    if (!_overlay) _overlay = build();
    var sel = _overlay.querySelector('#qp-route'); if (sel) sel.innerHTML = routeOptions();
    _overlay.querySelector('#qp-result').innerHTML = '';
    _overlay.querySelector('#qp-text').value = '';
    _overlay.classList.add('open');
    setTimeout(function () { var t = _overlay && _overlay.querySelector('#qp-text'); if (t) t.focus(); }, 30);
  }
  function close() {
    if (_overlay) _overlay.classList.remove('open');
    try { if (_lastFocus && _lastFocus.focus) _lastFocus.focus(); } catch (e) {}
  }

  // A raw, output-only paste (no shell prompt to segment on) is a single command's result: route it by
  // the host the output names, register that host if new, and run it through the same parser pipeline.
  function rawPaste(text, route) {
    var eng = OBOL.store.active() || {};
    var known = (eng.targets || []).map(function (t) { return t.ip; }).filter(Boolean);
    var tip = (route && route !== 'auto') ? route : (OBOL.ingest.detectTarget('', text, { known: known }) || (eng.params || {}).target || '');
    if (tip && known.indexOf(tip) < 0) {
      OBOL.store.update(function (e) {
        e.targets = e.targets || [];
        if (!e.targets.some(function (t) { return t.ip === tip; })) e.targets.push({ id: 't-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5), ip: tip, hostname: '', os: '', source: 'paste' });
        if (!e.params) e.params = {}; if (!e.params.target) e.params.target = tip;
      }, 'targets');
      if (OBOL.facts) OBOL.store.addFacts([OBOL.facts.makeFact({ kind: 'target.configured', scope: 'host:' + tip, source: 'paste' })], 'facts');
    }
    var rr = OBOL.ingest.run({ text: text, scope: tip ? ('host:' + tip) : undefined, source: 'paste' });
    return { ok: !!(rr && rr.ok), added: (rr && rr.added) || 0, imported: 1, hosts: tip ? [tip] : [] };
  }

  function mint() {
    var text = (_overlay.querySelector('#qp-text').value || '');
    var route = _overlay.querySelector('#qp-route').value || 'auto';
    var resEl = _overlay.querySelector('#qp-result');
    if (!text.trim()) { resEl.innerHTML = '<span class="qp-err">Paste some output first.</span>'; return; }
    resEl.innerHTML = '<span class="qp-wait">Reading…</span>';
    OBOL.ingest.ensureParsers().then(function (okp) {
      if (!okp) { resEl.innerHTML = '<span class="qp-err">Parsers are unavailable right now.</span>'; return; }
      var r;
      try { r = OBOL.ingest.importSession(text, { target: route, fileName: '' }); }
      catch (e) { r = { ok: false, reason: (e && e.message) || 'error' }; }
      // No prompt-anchored commands found: it is a single raw output paste, not a full session.
      if (r && r.ok && r.imported === 0) { try { r = rawPaste(text, route); } catch (e) { r = { ok: false, reason: (e && e.message) || 'error' }; } }
      if (!r || !r.ok) { resEl.innerHTML = '<span class="qp-err">Could not read that (' + esc((r && r.reason) || 'error') + ').</span>'; return; }
      var hosts = r.hosts || [];
      var msg;
      if (r.added === 0) {
        msg = '<span class="qp-warn">No new facts. That output did not prove anything the coach did not already know.</span>';
      } else {
        msg = '<b>Minted ' + r.added + ' fact' + (r.added === 1 ? '' : 's') + '</b> from ' + r.imported + ' command' + (r.imported === 1 ? '' : 's');
        if (hosts.length) msg += ', filed under ' + hosts.map(function (h) { return '<code>' + esc(h) + '</code>'; }).join(', ');
        msg += '.';
      }
      resEl.innerHTML = '<div class="qp-ok">' + msg + ' <a href="#/evidence" data-qp-close>Open Evidence →</a></div>';
      if (OBOL.router) OBOL.router.render();
      try { U.toast(r.added ? ('Minted ' + r.added + ' fact' + (r.added === 1 ? '' : 's')) : 'Nothing new proven'); } catch (e) {}
    });
  }

  function wire() {
    document.addEventListener('click', function (e) {
      if (e.target.closest && e.target.closest('#nav-paste')) { open(); return; }
      if (!_overlay || !_overlay.classList.contains('open')) return;
      if (e.target.closest('[data-qp-close]')) { close(); return; }
      if (e.target === _overlay) { close(); return; }
      if (e.target.closest('#qp-go')) { mint(); return; }
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && _overlay && _overlay.classList.contains('open')) close();
    });
  }

  OBOL.quickpaste = { open: open, close: close };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();
})(typeof globalThis !== 'undefined' ? globalThis : this);
