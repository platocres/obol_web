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
      function chip(on, label) { return '<span class="score-chip ' + (on ? 'got' : 'miss') + '">' + (on ? '🚩 ' : '') + label + '</span>'; }
      return '<tr' + (inAd ? ' class="ad-row"' : '') + '><td><a href="#/target/' + esc(h.ip) + '">' + esc(h.ip) + (h.hostname ? ' <span class="thost">' + esc(h.hostname) + '</span>' : '') + '</a>' + (inAd ? ' <span class="pill">AD set</span>' : '') + '</td>'
        + '<td>' + chip(local, 'local') + '</td><td>' + chip(rooted, 'root') + '</td></tr>';
    }).join('');

    var adPoints = (adSet.length && adAllRooted) ? (proof.ad_set_points || 0) : 0;
    total += adPoints;
    var threshold = proof.pass_threshold || 0;
    var passing = threshold ? total >= threshold : null;

    var scoreLine = threshold
      ? '<div class="score-total ' + (passing ? 'pass' : 'fail') + '"><span class="score-n">' + total + '</span> / ' + threshold + ' to pass' + (passing ? ' — passing ✓' : '') + '</div>'
      : '<div class="score-total"><span class="score-n">' + total + '</span> points captured</div>';

    return '<section class="score-route"><h1 class="route-h1">Scoreboard</h1>'
      + '<p class="route-sub">' + esc(proof.platform_name) + ' — captured flags per target.'
      + (proof.required ? ' This platform requires a compliant proof screenshot (flag + host-identity in one frame) for each slot — capture it in your report.' : '')
      + (adSet.length ? ' The AD set (' + esc(adSet.join(', ')) + ') scores all-or-nothing (' + (proof.ad_set_points || 0) + ').' : '')
      + '</p>'
      + scoreLine
      + (hosts.length ? '<table class="score-table"><thead><tr><th>Target</th><th>Local</th><th>Root</th></tr></thead><tbody>' + rows + '</tbody></table>'
        : '<div class="coach-empty">No targets yet — launch an engagement.</div>')
      + (proof.points_note ? '<p class="route-sub score-note">' + esc(proof.points_note) + '</p>' : '')
      + '</section>';
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.scoreboard = { render: render };
})(typeof globalThis !== 'undefined' ? globalThis : this);
