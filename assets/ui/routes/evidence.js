/*!
 * obol ui — routes/evidence.js — paste tool output, mint facts, recompute the coach.
 * Uses OBOL.parsers (ported obol-local parsers) when available; the paste is analyzed and
 * facts are added conservatively (parsers never invent facts). A manual fact composer is the
 * always-available fallback. When arrived via a coach "Paste result" jump, the pinned action
 * is shown as context and its command primes the parser dispatcher.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function pinnedAction(ctx) {
    var id = (ctx.args && ctx.args[0]) || null;
    if (!id) { try { id = sessionStorage.getItem('obol-pasteback-action'); } catch (e) {} }
    if (!id) return null;
    return OBOL.packs.actions().find(function (a) { return a.id === id; }) || null;
  }

  function render(ctx) {
    var pin = pinnedAction(ctx);
    var parsersReady = !!(OBOL.parsers && OBOL.parsers.parseActionOutput);
    var pinBlock = '';
    if (pin) {
      var facts = OBOL.store.factSet();
      var v = OBOL.command.fillCommand(pin, facts, { params: (OBOL.store.active().params || {}) }, 0);
      pinBlock = '<div class="ev-pin"><div class="ev-pin-h">Paste result for</div>'
        + '<div class="ev-pin-title">' + esc(pin.title) + '</div>'
        + '<pre class="cmd-run"><code>' + esc(v.filled) + '</code></pre>'
        + '<div class="ev-pin-dnp">' + (pin.does_not_prove ? ('Remember: does not prove ' + esc(pin.does_not_prove)) : '') + '</div></div>';
    }
    return '<section class="evidence">'
      + '<h1 class="route-h1">Evidence</h1>'
      + '<p class="route-sub">Paste real tool output. Conservative parsers mint proven facts; the coach recomputes. Nothing is inferred that the output doesn\'t show.</p>'
      + pinBlock
      + '<div class="ev-paste">'
      + '<textarea id="ev-text" class="ev-textarea" placeholder="Paste nmap / netexec / ldapsearch / ffuf / whatever you ran…" spellcheck="false"></textarea>'
      + '<div class="ev-row">'
      + '<input id="ev-cmd" class="ev-cmd" placeholder="(optional) the exact command you ran — helps routing" value="' + (pin ? U.attr(pin.command) : '') + '">'
      + '<button id="ev-parse" class="btn-primary"' + (parsersReady ? '' : ' disabled') + '>' + (parsersReady ? 'Parse → facts' : 'Loading parsers…') + '</button>'
      + '</div>'
      + '<div id="ev-result" class="ev-result"></div>'
      + '</div>'
      + '<details class="ev-manual"><summary>Add a fact manually</summary>'
      + '<div class="ev-row"><input id="ev-mkind" class="ev-cmd" placeholder="fact kind, e.g. smb.reachable">'
      + '<button id="ev-madd" class="btn-ghost">Add fact</button></div>'
      + '<div class="ev-hint">Fact kinds gate the methodology. Common: <code>host.up</code>, <code>ports.open</code>, <code>ldap.reachable</code>, <code>credential.available</code>, <code>foothold.linux</code>.</div>'
      + '</details>'
      + '</section>';
  }

  function runParse(mount) {
    var text = (document.getElementById('ev-text') || {}).value || '';
    var cmd = (document.getElementById('ev-cmd') || {}).value || '';
    if (!text.trim()) { U.toast('Paste some output first'); return; }
    if (!(OBOL.parsers && OBOL.parsers.parseActionOutput)) { U.toast('Parsers not loaded yet'); return; }
    var params = OBOL.store.active().params || {};
    var scope = 'host:' + (params.target || 'target');
    var res;
    try {
      res = OBOL.parsers.parseActionOutput({ command: cmd, stdout: text, source: cmd || 'paste', scope: scope, domain: params.domain || '' });
    } catch (e) { U.toast('Parse error: ' + (e && e.message), 'err'); return; }
    var facts = (res && res.facts) || [];
    var added = OBOL.store.addFacts(facts, 'evidence');
    // record activity
    OBOL.store.update(function (eng) {
      eng.activities = eng.activities || [];
      eng.activities.unshift({ at: Date.now(), command: cmd, source: 'paste', produced: facts.map(function (f) { return f.kind; }), sample: text.slice(0, 400) });
    }, 'activity');
    var resEl = document.getElementById('ev-result');
    if (resEl) {
      if (!facts.length) {
        resEl.innerHTML = '<div class="ev-none">No facts recognized in that output (nothing invented). Try the exact command hint, or add a fact manually.</div>';
      } else {
        resEl.innerHTML = '<div class="ev-added">Minted ' + added + ' new fact' + (added === 1 ? '' : 's') + ' (' + facts.length + ' recognized):</div>'
          + '<ul class="ev-factlist">' + facts.map(function (f) {
            return '<li class="' + esc(f.state) + '"><code>' + esc(f.kind) + '</code> <span class="ev-fscope">' + esc(f.scope) + '</span></li>';
          }).join('') + '</ul>'
          + '<a class="btn-primary" href="#/path">See updated coach →</a>';
      }
    }
    OBOL.app.renderSidebar();
    U.toast(added ? ('Minted ' + added + ' fact' + (added === 1 ? '' : 's')) : 'No new facts');
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    // Lazy-load parsers if not present, then enable the button.
    if (!(OBOL.parsers && OBOL.parsers.parseActionOutput) && OBOL.lazy) {
      OBOL.lazy.loadGroup('parsers').then(function () {
        var b = document.getElementById('ev-parse');
        if (b) { b.disabled = false; b.textContent = 'Parse → facts'; }
      }).catch(function () {});
    }
    var parseBtn = document.getElementById('ev-parse');
    if (parseBtn) parseBtn.addEventListener('click', function () { runParse(mount); });
    var maddBtn = document.getElementById('ev-madd');
    if (maddBtn) maddBtn.addEventListener('click', function () {
      var kind = ((document.getElementById('ev-mkind') || {}).value || '').trim();
      if (!kind) return;
      var scope = 'host:' + ((OBOL.store.active().params || {}).target || 'target');
      OBOL.store.addFacts([OBOL.facts.makeFact({ kind: kind, scope: scope, source: 'manual' })], 'facts');
      OBOL.app.renderSidebar();
      U.toast('Fact added: ' + kind);
      document.getElementById('ev-mkind').value = '';
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.evidence = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
