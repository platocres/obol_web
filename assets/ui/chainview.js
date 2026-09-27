/*!
 * obol ui — chainview.js — shared renderer for the Attack Path ribbon.
 * One place builds the dense "what led to what → the flags" block ribbon from a chain (engine/
 * chain.js), so the per-target page and the engagement-wide view are byte-for-byte identical — a
 * single-target engagement's ribbon looks exactly like that target's own page.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  // Render the ordered chain steps into the block ribbon's inner HTML.
  function ribbon(steps) {
    return steps.map(function (s, i) {
      var prevKind = i > 0 ? steps[i - 1].kind : null;
      var fromPrev = i === 0 || !s.enabledBy.length || s.enabledBy.indexOf(prevKind) !== -1;
      var arrow = i === 0 ? ''
        : '<span class="apath-arrow' + (fromPrev ? '' : ' jump') + '" aria-hidden="true">→</span>';
      var jumped = s.enabledBy.filter(function (k) { return k !== prevKind; });
      var from = (!fromPrev && jumped.length)
        ? '<div class="apath-from">← from ' + jumped.map(function (k) { return esc(U.titleCase(OBOL.pack.friendly(k))); }).join(', ') + '</div>' : '';
      var tech = s.technique ? '<span class="apath-tech">' + esc(s.technique) + '</span>' : '';
      var detail = s.detail ? '<div class="apath-detail">' + esc(s.detail.length > 96 ? s.detail.slice(0, 94) + '…' : s.detail) + '</div>' : '';
      var cmd = s.command ? '<code class="apath-cmd" title="' + U.attr(s.command) + '">' + esc(s.command.length > 60 ? s.command.slice(0, 58) + '…' : s.command) + '</code>' : '';
      var title = U.titleCase(s.label);
      return arrow + '<article class="apath-block ph-' + esc(s.phase) + (s.isFlag ? ' apath-flag' : '') + '">'
        + '<div class="apath-cat"><span class="ph-chip ph-' + esc(s.phase) + '">' + esc(s.phase) + '</span>' + tech + '</div>'
        + '<div class="apath-title">' + (s.isFlag ? '🚩 ' : '') + esc(title) + '</div>'
        + detail + cmd + from + '</article>';
    }).join('');
  }

  // Build the chain for one host and return the full `.apath-flow` (or '' when nothing walked yet).
  function hostFlow(ip, activities) {
    if (!(OBOL.chain && OBOL.store)) return '';
    var facts = OBOL.store.factSetForTarget(ip);
    var steps = OBOL.chain.build({ facts: facts, activities: activities || (OBOL.store.active().activities || []), actions: OBOL.packs.actions(), host: ip });
    return steps.length ? '<div class="apath-flow">' + ribbon(steps) + '</div>' : '';
  }

  // The engagement-wide Attack Path: one host's ribbon per target that has walked something, each
  // under a compact "IP hostname" header (shown even for a single target — a glanceable anchor).
  // Returns '' when nothing has been walked anywhere yet.
  function engagement() {
    var eng = (OBOL.store && OBOL.store.active()) || {};
    var acts = eng.activities || [];
    var flows = (eng.targets || []).map(function (t) {
      var ip = t.ip || t.host; if (!ip) return null;
      var flow = hostFlow(ip, acts);
      return flow ? { ip: ip, flow: flow } : null;
    }).filter(Boolean);
    if (!flows.length) return '';
    return flows.map(function (f) {
      // Labelled identity strip — IP always, hostname/domain as obol proves them (a glanceable anchor).
      var idn = (OBOL.store && OBOL.store.targetIdentity) ? OBOL.store.targetIdentity(f.ip) : { ip: f.ip, hostname: '', domain: '' };
      function chip(k, v, cls) { return '<span class="ident-inline"><span class="ii-k">' + k + '</span><span class="ii-v ' + (cls || '') + '">' + esc(v) + '</span></span>'; }
      var strip = chip('IP', idn.ip, '') + (idn.hostname ? chip('Hostname', idn.hostname, 'ident-host') : '') + (idn.domain ? chip('Domain', idn.domain, '') : '');
      return '<div class="apath-host"><div class="apath-host-h ident-strip">' + strip + '</div>' + f.flow + '</div>';
    }).join('');
  }

  OBOL.chainview = { ribbon: ribbon, hostFlow: hostFlow, engagement: engagement };
})(typeof globalThis !== 'undefined' ? globalThis : this);
