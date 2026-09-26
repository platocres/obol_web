/*!
 * obol ui — routes/checklist.js — the attack-chain checklist: the FULL pack catalogue as a
 * static, tickable services→commands reference, grouped by phase (the exhaustive companion to
 * the coach's prioritized subset). Tick state persists per engagement (localStorage/IndexedDB).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function render() {
    var eng = OBOL.store.active();
    var facts = OBOL.store.factSet();
    var params = (eng && eng.params) || {};
    var ticks = (eng && eng.checkTicks) || {};
    var pack = OBOL.packs.actions();

    var byPhase = {}; OBOL.phases.PHASES.forEach(function (p) { byPhase[p] = []; });
    pack.forEach(function (a) { (byPhase[OBOL.phases.phaseOfAction(a)] = byPhase[OBOL.phases.phaseOfAction(a)] || []).push(a); });

    var total = pack.length, done = Object.keys(ticks).filter(function (k) { return ticks[k]; }).length;
    var html = '<section class="checklist">'
      + '<h1 class="route-h1">Checklist</h1>'
      + '<p class="route-sub">Every methodology action, grouped by attack-chain phase — tick as you go. This is the exhaustive reference; the coach on Next Steps ranks the evidence-relevant subset. ' + done + '/' + total + ' ticked.</p>';

    OBOL.phases.PHASES.forEach(function (p) {
      var items = (byPhase[p] || []).slice().sort(function (a, b) { return b.priority - a.priority; });
      if (!items.length) return;
      html += '<div class="chk-phase"><div class="chk-phase-h"><span class="ph-chip ph-' + p + '">' + p + '</span>'
        + '<span class="mini-label">' + items.length + ' actions</span></div>';
      items.forEach(function (a) {
        // Fill exactly like the coach (facts + params + profile) so commands become copy-ready
        // as facts are collected; unfilled {{tokens}} are flagged with what would complete them.
        var variants = OBOL.command.fillAll(a, facts, { params: params, profile: (eng && eng.profile), workspace: OBOL.workspace.tokens(eng) });
        var v = variants[0] || { filled: '' };
        var unfilled = v.filled ? OBOL.command.unfilledTokens(v.filled) : [];
        var on = !!ticks[a.id];
        var cmd = v.filled
          ? '<button type="button" class="chk-cmd ' + (unfilled.length ? 'chk-needs' : 'chk-ready') + '" data-copy="' + U.attr(v.filled)
            + '" title="' + (unfilled.length ? ('needs: ' + esc(unfilled.join(', '))) : 'click to copy') + '"><code>' + esc(v.filled) + '</code></button>'
          : '';
        html += '<div class="chk-item' + (on ? ' checked' : '') + '">'
          + '<label class="chk-tick"><input type="checkbox" data-chk="' + esc(a.id) + '"' + (on ? ' checked' : '') + '>'
          + '<span class="chk-t">' + esc(a.title) + '</span></label>'
          + cmd
          + '</div>';
      });
      html += '</div>';
    });
    html += '</section>';
    return html;
  }

  function mounted(ctx) {
    U.on(ctx.mount, 'change', 'input[data-chk]', function (e, t) {
      var id = t.getAttribute('data-chk'), on = t.checked;
      OBOL.store.update(function (eng) { eng.checkTicks = eng.checkTicks || {}; if (on) eng.checkTicks[id] = true; else delete eng.checkTicks[id]; }, 'checklist');
      var item = t.closest('.chk-item'); if (item) item.classList.toggle('checked', on);
    });
    U.on(ctx.mount, 'click', '.chk-cmd', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.checklist = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
