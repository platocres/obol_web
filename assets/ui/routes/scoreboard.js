/*!
 * obol ui — routes/scoreboard.js — flag / objective scoreboard with OSCP-style scoring.
 * Per-target local/root flag slots (from captured-flag facts), plus the profile's points model
 * (points per slot, pass threshold, and the OSCP AD-set all-or-nothing block). Honest: a slot is
 * "captured" only when a flag fact was recorded; proof-required platforms show the requirement.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function slotState(facts, slot) {
    if (slot === 'local') return facts.has('objective.local_flag') || facts.has('objective.flag');
    if (slot === 'root') return facts.has('objective.root_flag');
    return facts.has('objective.flag');
  }
  // The captured flag's actual value (hash), so the scoreboard shows the real token, copy-pasteable,
  // not just a "captured" pill. Returns '' when the slot was located but never read on-host.
  function slotFlag(facts, slot) {
    var kinds = slot === 'local' ? ['objective.local_flag', 'objective.flag'] : (slot === 'root' ? ['objective.root_flag'] : ['objective.flag']);
    for (var i = 0; i < kinds.length; i++) {
      var vs = facts.values(kinds[i]) || [];
      for (var j = 0; j < vs.length; j++) { if (vs[j] && vs[j].flag) return String(vs[j].flag); }
    }
    return '';
  }
  function flagCell(hash, got, label) {
    if (got && hash) {
      return '<span class="score-flag got">' + OBOL.ic('flag') + ' <code class="score-flag-h" data-copy="' + U.attr(hash) + '" title="Click to copy">' + esc(hash) + '</code></span>';
    }
    if (got) return '<span class="score-chip got">' + OBOL.ic('flag') + ' ' + esc(label) + ' <span class="score-flag-note">read on host</span></span>';
    return '<span class="score-chip miss">' + esc(label) + '</span>';
  }

  function render() {
    var eng = OBOL.store.active();
    var hosts = eng.targets || [];
    var proof = OBOL.profile.resolveProofConfig(eng.profile);
    var pts = proof.points || { local: 10, root: 10, flag: 10 };
    var adSet = (proof.ad_set || []).map(function (h) { return h.toLowerCase(); });

    var total = 0, adAllRooted = adSet.length > 0;
    var rows = hosts.map(function (h) {
      var f = OBOL.store.factSetForTarget(h.ip);
      var local = slotState(f, 'local'), rooted = slotState(f, 'root');
      var inAd = adSet.indexOf(String(h.ip).toLowerCase()) >= 0 || adSet.indexOf(String(h.hostname || '').toLowerCase()) >= 0;
      if (!inAd) { if (local) total += pts.local || 10; if (rooted) total += pts.root || 10; }
      if (inAd && !rooted) adAllRooted = false;
      return '<tr' + (inAd ? ' class="ad-row"' : '') + '><td><a href="#/target/' + esc(h.ip) + '">' + esc(h.ip) + (h.hostname ? ' <span class="thost">' + esc(h.hostname) + '</span>' : '') + '</a>' + (inAd ? ' <span class="pill">AD set</span>' : '') + '</td>'
        + '<td>' + flagCell(slotFlag(f, 'local'), local, 'local') + '</td><td>' + flagCell(slotFlag(f, 'root'), rooted, 'root') + '</td></tr>';
    }).join('');

    var adPoints = (adSet.length && adAllRooted) ? (proof.ad_set_points || 0) : 0;
    total += adPoints;
    var threshold = proof.pass_threshold || 0;
    var passing = threshold ? total >= threshold : null;

    // The point total is OSCP-exam scoring, meaningless on a lab box, so it surfaces only in exam mode.
    var exam = OBOL.profile.isExamPlatform((eng.profile || {}).platform);
    var scoreLine = !exam ? ''
      : threshold
        ? '<div class="score-total ' + (passing ? 'pass' : 'fail') + '"><span class="score-n">' + total + '</span> / ' + threshold + ' to pass' + (passing ? ' · passing ✓' : '') + '</div>'
        : '<div class="score-total"><span class="score-n">' + total + '</span> points captured</div>';

    return '<section class="score-route"><h1 class="route-h1">Flags</h1>'
      + '<p class="route-sub">' + (proof.platform_name ? esc(proof.platform_name) + ' · ' : '') + 'Captured flags per target. Click a flag to copy its value.'
      + (proof.required ? ' This platform requires a compliant proof screenshot (flag + host-identity in one frame) for each slot, capture it in your report.' : '')
      + (adSet.length ? ' The AD set (' + esc(adSet.join(', ')) + ') scores all-or-nothing (' + (proof.ad_set_points || 0) + ').' : '')
      + '</p>'
      + scoreLine
      + (hosts.length ? '<table class="score-table"><thead><tr><th>Target</th><th>Local</th><th>Root</th></tr></thead><tbody>' + rows + '</tbody></table>'
        : '<div class="coach-empty">No targets yet, launch an engagement.</div>')
      + (proof.points_note ? '<p class="route-sub score-note">' + esc(proof.points_note) + '</p>' : '')
      + '</section>';
  }

  function mounted(ctx) {
    U.on(ctx.mount, 'click', '[data-copy]', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Flag copied' : 'Copy failed', ok ? '' : 'err'); });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.scoreboard = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
