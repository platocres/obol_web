/*!
 * obol ui - routes/scoreboard.js - flag / objective scoreboard with OSCP-style scoring.
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

    if (proof.no_flags) {
      var objRows = hosts.map(function (h) {
        var f = OBOL.store.factSetForTarget(h.ip);
        var fh = f.has('foothold.windows') || f.has('foothold.linux') || f.has('access.shell') || f.has('winrm.authenticated') || f.has('foothold.webshell');
        var adm = f.has('access.system') || f.has('access.admin') || f.has('access.root');
        var dom = f.has('loot.ntds') || f.has('ad.domain_admin') || f.has('ad.domain_control');
        var cell = function (ok, lbl) {
          return ok ? '<span class="score-chip got">' + OBOL.ic('check') + ' ' + esc(lbl) + '</span>'
                    : '<span class="score-chip miss">Pending</span>';
        };
        return '<tr><td><a href="#/target/' + esc(h.ip) + '">' + esc(h.ip) + (h.hostname ? ' <span class="thost">' + esc(h.hostname) + '</span>' : '') + '</a></td>'
          + '<td>' + cell(fh || adm, 'Foothold') + '</td>'
          + '<td>' + cell(adm, 'Admin / Root') + '</td>'
          + '<td>' + (f.has('ad.dc_candidate') || dom ? cell(dom, 'Domain Admin / NTDS') : '<span class="score-chip miss">N/A</span>') + '</td></tr>';
      }).join('');
      return '<section class="score-route"><h1 class="route-h1">Objectives &amp; Compromise Matrix</h1>'
        + '<p class="route-sub">' + (proof.platform_name ? esc(proof.platform_name) + ' · ' : '') + 'This engagement profile does not use local.txt / proof.txt flags. Progress is tracked by host compromise, privilege escalation, and domain takeover.'
        + '</p>'
        + (hosts.length ? '<table class="score-table"><thead><tr><th>Target</th><th>Initial Access</th><th>Admin / Root</th><th>Domain Objective</th></tr></thead><tbody>' + objRows + '</tbody></table>'
          : '<div class="coach-empty">No targets yet, launch an engagement.</div>')
        + (proof.points_note ? '<p class="route-sub score-note">' + esc(proof.points_note) + '</p>' : '')
        + '</section>';
    }

    var total = 0, flagCount = 0, rootedMap = {};
    var rows = hosts.map(function (h) {
      var f = OBOL.store.factSetForTarget(h.ip);
      var local = slotState(f, 'local'), rooted = slotState(f, 'root');
      if (local) flagCount++;
      if (rooted) {
        flagCount++;
        if (h.ip) rootedMap[String(h.ip).toLowerCase()] = true;
        if (h.hostname) rootedMap[String(h.hostname).toLowerCase()] = true;
      }
      var inAd = adSet.indexOf(String(h.ip).toLowerCase()) >= 0 || adSet.indexOf(String(h.hostname || '').toLowerCase()) >= 0;
      if (!inAd) { if (local) total += pts.local || 10; if (rooted) total += pts.root || 10; }
      return '<tr' + (inAd ? ' class="ad-row"' : '') + '><td><a href="#/target/' + esc(h.ip) + '">' + esc(h.ip) + (h.hostname ? ' <span class="thost">' + esc(h.hostname) + '</span>' : '') + '</a>' + (inAd ? ' <span class="pill">AD set</span>' : '') + '</td>'
        + '<td>' + flagCell(slotFlag(f, 'local'), local, 'local') + '</td><td>' + flagCell(slotFlag(f, 'root'), rooted, 'root') + '</td></tr>';
    }).join('');

    var adAllRooted = adSet.length >= 3 && adSet.every(function (ip) { return !!rootedMap[ip]; });
    var adPoints = adAllRooted ? (proof.ad_set_points || 0) : 0;
    total += adPoints;
    var threshold = proof.pass_threshold || 0;
    var passing = threshold ? total >= threshold : null;

    var exam = OBOL.profile.isExamPlatform((eng.profile || {}).platform);
    var isCpts = ((eng.profile || {}).platform === 'cpts');
    var scoreLine = !exam ? ''
      : threshold
        ? '<div class="score-total ' + (passing ? 'pass' : 'fail') + '"><span class="score-n">' + total + '</span> / ' + threshold + (isCpts ? ' flags to pass' : ' to pass') + (passing ? ' · passing ✓' : '') + '</div>'
        : '<div class="score-total"><span class="score-n">' + total + '</span> points captured</div>';

    var pfHtml = '';
    if (OBOL.report && typeof OBOL.report.buildContext === 'function' && typeof OBOL.report.preflightCheck === 'function') {
      try {
        var repCtx = OBOL.report.buildContext({
          facts: OBOL.store.factSet(),
          targets: (hosts || []).map(function (t) { return Object.assign({}, t, { host: t.host || t.ip }); }),
          activities: eng.activities || [],
          params: eng.params || {},
          profile: eng.profile || {},
        });
        var pf = OBOL.report.preflightCheck(repCtx);
        if (pf && pf.warnings && pf.warnings.length > 0) {
          pfHtml = '<div class="score-preflight warn">Pre-Flight: ' + pf.warnings.length + ' report readiness warning' + (pf.warnings.length === 1 ? '' : 's') + ' (<a href="#/report">view report</a>)</div>';
        } else if (pf && repCtx.proofs && repCtx.proofs.length > 0) {
          pfHtml = '<div class="score-preflight clean">Pre-Flight Clean: all captured flags have proof context and reproduction chains</div>';
        }
      } catch (e) {}
    }

    return '<section class="score-route"><h1 class="route-h1">Flags</h1>'
      + '<p class="route-sub">' + (proof.platform_name ? esc(proof.platform_name) + ' · ' : '') + 'Captured flags per target. Click a flag to copy its value.'
      + (proof.required ? ' This platform requires a compliant proof screenshot (flag + host-identity in one frame) for each slot, capture it in your report.' : '')
      + (adSet.length ? ' The AD set (' + esc(adSet.join(', ')) + ') scores all-or-nothing (' + (proof.ad_set_points || 0) + ').' : '')
      + '</p>'
      + scoreLine
      + pfHtml
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
