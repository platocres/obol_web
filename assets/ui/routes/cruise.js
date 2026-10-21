/*!
 * obol ui - routes/cruise.js - Zero-Config Phase-by-Phase Engagement Autopilot.
 * Supports two profiles:
 *   - OSCP Exam Safe ('exam'): Multi-hypothesis safe enumeration, hash cracking & staging; checkpoints
 *     before shells/exploits with pre-filled Manual Strike commands.
 *   - Lab Full Autopilot ('lab'): End-to-end flag capture chaining enum -> hash crack -> cred validation ->
 *     automatic remote foothold -> local.txt & proof.txt capture in one script.
 *
 * Includes:
 *   1. Profile Switch (OSCP Exam Safe vs. Lab Full Autopilot) & Scope Bar.
 *   2. 5-Stage Progress Pipeline (with Stage 5 Zero-Config Pivot integrated directly into the pipeline).
 *   3. 4-Part Operational Handoff Card (At-a-Glance Run Stats, Confirmed Ledger vs. Ruled-Out Hypotheses,
 *      "Why Next" Theory of the Case, and Ready Manual Strikes).
 *   4. Active Stage Station Card & Paste Station with Loadout-grade neon buttons.
 * House style: no em or en dashes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr ? U.attr(s) : esc(s); }
  function ic(n) { try { return OBOL.ic ? OBOL.ic(n) : ''; } catch (e) { return ''; } }

  var _lastPaste = null;
  var _lastEngId = null;
  var _selectedStage = null;

  function optsFor(eng) {
    return {
      params: (eng && eng.params) || {},
      profile: (eng && eng.profile) || {},
      workspace: (OBOL.workspace && OBOL.workspace.tokens) ? OBOL.workspace.tokens(eng) : {},
    };
  }

  function modeOf(eng) {
    var m = eng && eng.ui && eng.ui.cruiseMode;
    return (m === 'lab') ? 'lab' : 'exam';
  }

  function cruiseFactsFor(eng) {
    var t = ((eng && eng.params && eng.params.target) || '').trim();
    if (t && t.indexOf('/') < 0 && !/\s/.test(t) && OBOL.store && typeof OBOL.store.factSetForTarget === 'function') {
      return OBOL.store.factSetForTarget(t);
    }
    return OBOL.store.factSet();
  }

  function targetActivities(eng) {
    var all = (eng && eng.activities) || [];
    var t = ((eng && eng.params && eng.params.target) || '').trim();
    if (!t || t.indexOf('/') >= 0 || /\s/.test(t)) return all;
    var filtered = all.filter(function (a) { return a && (a.target === t || a.scope === 'host:' + t); });
    return filtered;
  }

  var STAGE1_RECON_IDS = {
    'nmap-quick': 1, 'nmap-full-tcp': 1, 'nmap-vuln-scripts': 1, 'nmap-udp-top': 1,
    'recon-smb-anon': 1, 'smb-anon': 1, 'smb-shares': 1, 'ad-user-enum': 1,
    'ad-anon-ldap-enum': 1, 'ldap-rootdse': 1, 'recon-dns': 1, 'recon-ftp': 1,
    'ssh-banner': 1, 'recon-nfs': 1, 'recon-snmp': 1, 'check-web-headers': 1, 'web-dir-enum': 1,
  };

  function cruiseDoneIds(eng) {
    var out = OBOL.store.doneIdsForTarget ? OBOL.store.doneIdsForTarget((eng.params || {}).target, cruiseFactsFor(eng), eng) : {};
    targetActivities(eng).forEach(function (a) {
      var id = a && (a.action_id || a.move_id);
      if (id && STAGE1_RECON_IDS[id] && (!a.blockers || !a.blockers.length)) {
        out[id] = 1;
      }
    });
    return out;
  }

  function downloadScript(filename, text) {
    try {
      var blob = new Blob([text], { type: 'text/x-shellscript' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      return true;
    } catch (e) { return false; }
  }

  function renderProfileSwitch(mode) {
    var isExam = mode !== 'lab';
    var isLab = mode === 'lab';
    return '<div class="cr-modes" role="radiogroup" aria-label="Cruise Autopilot Profile">'
      + '<button type="button" class="cr-mode mode-exam' + (isExam ? ' is-on' : '') + '" data-cr-mode="exam" aria-pressed="' + (isExam ? 'true' : 'false') + '">'
      + '  <div class="cr-mode-head">'
      + '    <span class="cr-mode-dot"></span>'
      + '    <span class="cr-mode-t">OSCP Exam Safe</span>'
      + '    <span class="cr-mode-pill">100% Exam-Legal</span>'
      + '  </div>'
      + '  <span class="cr-mode-s">Chains multi-hypothesis enumeration, credential validation, offline hash cracking, and ./www/ staging. Checkpoints before shells or exploits.</span>'
      + '</button>'
      + '<button type="button" class="cr-mode mode-lab' + (isLab ? ' is-on' : '') + '" data-cr-mode="lab" aria-pressed="' + (isLab ? 'true' : 'false') + '">'
      + '  <div class="cr-mode-head">'
      + '    <span class="cr-mode-dot"></span>'
      + '    <span class="cr-mode-t">Lab Full Autopilot</span>'
      + '    <span class="cr-mode-pill lab-pill">End-to-End Flags</span>'
      + '  </div>'
      + '  <span class="cr-mode-s">Automates the full kill-chain in labs: multi-hypothesis enum, auto-crack, active foothold/exploit execution, and remote local.txt + proof.txt capture.</span>'
      + '</button>'
      + '</div>';
  }

  function renderScopeBar(eng, facts) {
    var params = (eng && eng.params) || {};
    var curTarget = (params.target || '').trim();
    var targets = (eng && eng.targets) || [];
    var chips = targets.filter(function (t) { return t && t.ip; }).map(function (t) {
      var on = t.ip === curTarget;
      var label = t.ip + (t.hostname ? (' (' + t.hostname + ')') : '');
      return '<button type="button" class="cr-target-chip' + (on ? ' is-on' : '') + '" data-cr-target="' + attr(t.ip) + '">'
        + '<span class="cr-target-dot"></span>'
        + '<span class="cr-target-ip mono">' + esc(label) + '</span>'
        + (t.os ? ('<span class="cr-target-os">' + esc(t.os) + '</span>') : '')
        + '</button>';
    }).join('');

    var subChips = '';
    if (facts && typeof facts.values === 'function') {
      var rvals = facts.values('pivot.candidate') || [];
      var subs = [];
      rvals.forEach(function (rv) {
        ((rv && rv.subnets) || []).forEach(function (s) { if (subs.indexOf(s) < 0) subs.push(s); });
      });
      if (subs.length) {
        subChips = subs.map(function (s) {
          var on = curTarget === s;
          return '<button type="button" class="cr-target-chip cr-subnet-chip' + (on ? ' is-on' : '') + '" data-cr-target="' + attr(s) + '" title="Discovered internal subnet - click to run Stage 1 sweep across this CIDR">'
            + '<span class="cr-target-ip mono">Subnet ' + esc(s) + '</span>'
            + '</button>';
        }).join('');
      }
    }

    return '<section class="cr-scope-bar tool-card station-card lane-recon">'
      + '<div class="cr-scope-row">'
      + '  <div class="cr-scope-left">'
      + '    <span class="cr-scope-k">ACTIVE SCOPE</span>'
      + '    <div class="cr-target-chips">'
      + (chips || '<span class="muted small">No host selected yet</span>')
      + subChips
      + '    </div>'
      + '  </div>'
      + '  <form class="cr-scope-form" id="cr-scope-form">'
      + '    <input type="text" id="cr-target-input" class="bind-input cr-target-input mono" value="' + attr(curTarget) + '" placeholder="IP, IPs, or CIDR (e.g. 10.10.10.5 or 172.16.5.0/24)" aria-label="Target IP or Subnet">'
      + '    <button type="submit" class="cr-btn-neon neon-cyan cr-target-set">Set Scope</button>'
      + '  </form>'
      + '</div>'
      + '</section>';
  }

  function renderPipeline(stPlan, selectedStageId) {
    var autoId = stPlan.activeStageId;
    var cards = stPlan.stages.map(function (st) {
      var isSel = st.id === selectedStageId;
      var isAuto = st.id === autoId;
      var statusLabel = st.status === 'done' ? 'Done' : (isAuto ? 'Current Stage' : (st.status === 'ready' ? 'Unlocked' : 'Upcoming'));
      return '<button type="button" class="cr-stage-step st-' + attr(st.status) + (isSel ? ' is-selected' : '') + (isAuto ? ' is-auto' : '') + ' cr-ph-' + attr(st.phase) + '" data-cr-stage="' + attr(st.id) + '">'
        + '<div class="cr-stage-top">'
        + '  <span class="cr-stage-num">' + esc(st.badge) + '</span>'
        + '  <span class="cr-stage-state">' + (st.status === 'done' ? '&#10003; ' : '') + esc(statusLabel) + '</span>'
        + '</div>'
        + '<div class="cr-stage-name">' + esc(st.label) + '</div>'
        + '<div class="cr-stage-where mono">' + esc(st.where) + '</div>'
        + '</button>';
    }).join('');

    var overrideNotice = (selectedStageId !== autoId)
      ? ('<div class="cr-stage-override">'
        + '<span>Inspecting <b>' + esc(selectedStageId.toUpperCase()) + '</b> manually. Recommended stage for current facts: <b>Stage ' + (stPlan.activeIndex + 1) + '</b>.</span>'
        + '<button type="button" class="cr-btn-glass small" data-cr-stage="' + attr(autoId) + '">Return to Stage ' + (stPlan.activeIndex + 1) + '</button>'
        + '</div>')
      : '';

    return '<section class="cr-pipeline-wrap">'
      + '<div class="cr-pipeline" role="tablist" aria-label="Cruise Engagement Stages">' + cards + '</div>'
      + overrideNotice
      + '</section>';
  }

  function renderCheckpointRow(cp, mode) {
    var a = cp.action;
    var ph = cp.phase || 'access';
    var badgeTxt = mode === 'lab' ? 'INCLUDED IN LAB AUTOPILOT (OR RUN BY HAND)' : 'MANUAL OSCP CHECKPOINT';
    return '<div class="cr-cp-item cr-ph-' + attr(ph) + '">'
      + '<div class="cr-cp-head">'
      + '  <span class="cr-cp-badge">' + esc(badgeTxt) + '</span>'
      + '  <strong class="cr-cp-title">' + esc(a.title) + '</strong>'
      + '  <span class="cr-cp-phase">' + esc(ph) + '</span>'
      + '  <div class="cr-cp-actions">'
      + '    <button type="button" class="cr-btn-neon neon-amber small cr-copy" data-copy="' + attr(cp.command) + '" data-copy-action="' + attr(a.id) + '" data-copy-locus="' + attr(OBOL.pack.commandExecutionLocus ? OBOL.pack.commandExecutionLocus((a.commands || [])[cp.cmdIndex || 0]) : OBOL.pack.defaultCommandLocus(a)) + '">' + ic('copy') + 'Copy Command</button>'
      + '    <a class="cr-btn-glass small" href="#/path" title="View full move breakdown in Next Steps">Open in Next Steps &rarr;</a>'
      + '  </div>'
      + '</div>'
      + (a.proves ? ('<div class="cr-cp-why">' + esc(a.proves) + '</div>') : '')
      + '<pre class="cr-cp-cmd mono"><code>' + esc(cp.command) + '</code></pre>'
      + '</div>';
  }

  function renderHandoff(handoff) {
    var stPlan = handoff.stagePlan;
    var rec = handoff.recommendation;
    var stats = handoff.stats || {};
    var highlights = handoff.highlights || [];
    var ruledOut = handoff.ruledOut || [];
    var cps = stPlan.checkpoints;

    var activeCps = [];
    if (stPlan.activeStageId === 'foothold') {
      activeCps = cps.escalate.slice(0, 3);
    } else if (stPlan.activeStageId === 'loot' || stPlan.activeStageId === 'pivot') {
      activeCps = cps.lateral.slice(0, 3);
    } else {
      activeCps = cps.foothold.slice(0, 3);
    }

    var pasteBanner = '';
    if (_lastPaste) {
      var pKinds = (_lastPaste.kinds || []).slice(0, 8);
      pasteBanner = '<div class="cr-paste-debrief is-neutral">'
        + OBOL.ingest.renderOutcome(_lastPaste.outcome)
        + (pKinds.length ? ('<div class="cr-paste-debrief-chips">' + pKinds.map(function (k) { return '<span class="cr-fact-chip mono">' + esc(k) + '</span>'; }).join('') + '</div>') : '')
        + '</div>';
    }

    // 1. At-a-glance stats bar
    var statsBar = '<div class="cr-stats-bar">'
      + '<div class="cr-stat"><span class="cr-stat-k">Steps Run</span><span class="cr-stat-v mono">' + (stats.stepsRun || 0) + (stats.paidSteps ? (' <small>(' + stats.paidSteps + ' hit)</small>') : '') + '</span></div>'
      + '<div class="cr-stat"><span class="cr-stat-k">Open Ports</span><span class="cr-stat-v mono">' + (stats.openPorts || 0) + '</span></div>'
      + '<div class="cr-stat"><span class="cr-stat-k">Creds &amp; Hashes</span><span class="cr-stat-v mono">' + (stats.credsAndHashes || 0) + '</span></div>'
      + '<div class="cr-stat ' + (stats.localFlag ? 'is-ok' : '') + '"><span class="cr-stat-k">local.txt</span><span class="cr-stat-v mono">' + (stats.localFlag ? '&#10003; Captured' : 'Pending') + '</span></div>'
      + '<div class="cr-stat ' + (stats.rootFlag ? 'is-ok' : '') + '"><span class="cr-stat-k">proof.txt</span><span class="cr-stat-v mono">' + (stats.rootFlag ? '&#10003; Captured' : 'Pending') + '</span></div>'
      + '<div class="cr-stat"><span class="cr-stat-k">Ruled Out</span><span class="cr-stat-v mono">' + (stats.ruledOutCount || 0) + '</span></div>'
      + '</div>';

    // 2. Confirmed Ledger vs. Ruled-Out Hypotheses
    var hiGrid = highlights.length
      ? ('<div class="cr-hi-grid">' + highlights.map(function (h) {
          return '<div class="cr-hi-pill kind-' + attr(h.kind) + '">'
            + '<span class="cr-hi-k">' + esc(h.label) + '</span>'
            + '<span class="cr-hi-v mono">' + esc(h.value) + '</span>'
            + '</div>';
        }).join('') + '</div>')
      : '<div class="cr-hi-empty muted small">No target facts minted yet. Run <b>Stage 1 (Multi-Hypothesis Recon &amp; Triage)</b> below and paste the terminal log back here.</div>';

    var ruledOutRow = ruledOut.length
      ? ('<div class="cr-ruled-row">'
        + '<span class="cr-ruled-k">RULED OUT / CHECKED:</span>'
        + '<div class="cr-ruled-chips">' + ruledOut.map(function (r) { return '<span class="cr-ruled-chip mono">' + esc(r) + '</span>'; }).join('') + '</div>'
        + '</div>')
      : '';

    // 3. Why Next ("Theory of the Case")
    var whyBox = rec.whyNext
      ? ('<div class="cr-why-box">'
        + '<span class="cr-why-k">WHY THIS NEXT SCRIPT (THEORY OF THE CASE)</span>'
        + '<p class="cr-why-p">' + esc(rec.whyNext) + '</p>'
        + '</div>')
      : '';

    // 4. Manual Strike Checkpoints
    var cpBlock = '';
    if (activeCps.length) {
      cpBlock = '<div class="cr-cp-section">'
        + '<div class="cr-cp-sec-head">'
        + '  <span class="cr-cp-sec-k">' + (stPlan.mode === 'lab' ? 'UNLOCKED FOOTHOLD / PRIVESC STRIKES (AUTO-BATCHED IN LAB SCRIPT OR COPY BELOW)' : 'READY MANUAL STRIKES (OSCP HUMAN CHECKPOINT)') + '</span>'
        + '  <span class="muted small">' + (stPlan.mode === 'lab' ? 'Lab Full Autopilot chains these automatically, or you can copy any individual command below.' : 'OSCP rules require a human to initiate shells, logins, and privilege escalation exploits.') + '</span>'
        + '</div>'
        + '<div class="cr-cp-list">' + activeCps.map(function (cp) { return renderCheckpointRow(cp, stPlan.mode); }).join('') + '</div>'
        + '</div>';
    }

    return '<section class="cr-handoff tool-card station-card">'
      + pasteBanner
      + '<div class="cr-handoff-top">'
      + '  <div class="cr-handoff-rec">'
      + '    <span class="cr-handoff-badge">' + esc(rec.badge) + '</span>'
      + '    <h2 class="cr-handoff-title">' + esc(rec.title) + '</h2>'
      + '    <p class="cr-handoff-detail">' + esc(rec.detail) + '</p>'
      + '  </div>'
      + '</div>'
      + statsBar
      + whyBox
      + '<div class="cr-handoff-ledger">'
      + '  <span class="cr-ledger-k">CONFIRMED TARGET LEDGER (WHAT PAID OFF)</span>'
      + hiGrid
      + ruledOutRow
      + '</div>'
      + cpBlock
      + '</section>';
  }

  function renderActiveStation(stPlan, selectedStageId, eng, facts, pack) {
    // Stage 5 (Pivot) renders the Zero-Config Pivot & Tunnel Station directly as the active station!
    if (selectedStageId === 'pivot' && OBOL.pivotStationUI && OBOL.pivotStationUI.card) {
      return '<section class="cr-pivot-stage">' + OBOL.pivotStationUI.card(true) + '</section>';
    }

    var st = stPlan.stages.filter(function (s) { return s.id === selectedStageId; })[0] || stPlan.stages[0];
    var opts = optsFor(eng);
    if (!OBOL.cruise.validTarget(opts.params.target)) {
      return '<section class="cr-station tool-card"><h2>Target Required</h2><p role="status">Configure a valid target or target scope before generating a Cruise script.</p></section>';
    }
    var scriptCtx = {
      mode: stPlan.mode,
      params: opts.params,
      profile: opts.profile,
      workspace: opts.workspace,
      facts: facts,
      pack: pack,
      osFamily: stPlan.osFamily,
      doneIds: cruiseDoneIds(eng),
    };
    var script = OBOL.cruise.buildStageScript(st.id, scriptCtx);
    var oneLiner = OBOL.cruise.buildStageOneLiner(st.id, scriptCtx);
    var targetSlug = ((opts.params.target || 'target').replace(/[^A-Za-z0-9._-]/g, '_')) || 'target';
    var fileName = 'obol-stage' + st.num + '-' + st.id + '-' + stPlan.mode + '-' + targetSlug + st.ext;
    var lhost = opts.params.lhost || '<LHOST>';

    var pillsHtml = st.pills.map(function (p) {
      return '<span class="cr-cap-pill">' + esc(p) + '</span>';
    }).join('');
    if (st.id === 'enum' && stPlan.examPlan && stPlan.examPlan.batch.length) {
      pillsHtml = '<span class="cr-cap-pill is-highlight">' + stPlan.examPlan.batch.length + ' Unlocked Pack Moves Included</span>' + pillsHtml;
    }

    var onHostBlock = '';
    if (st.id === 'foothold' || st.id === 'loot') {
      var shellAccess = (OBOL.cruise && OBOL.cruise.buildHostShellAccess)
        ? OBOL.cruise.buildHostShellAccess(st.id, scriptCtx)
        : null;
      var osBadge = stPlan.osFamily === 'windows' ? 'Windows cmd / Evil-WinRM' : 'Linux sh / bash';
      var serveCmd = 'python3 -m http.server 80 --directory www';
      var flagsBanner = '';
      if (shellAccess && (shellAccess.localFlag || shellAccess.rootFlag)) {
        var flagRows = [];
        if (shellAccess.localFlag) {
          flagRows.push('<div class="cr-staging-bar" style="margin-top:6px">'
            + '<span class="mono"><b>local.txt (user.txt):</b> <code>' + esc(shellAccess.localFlag.flag) + '</code>'
            + (shellAccess.localFlag.path ? (' <span class="muted">(' + esc(shellAccess.localFlag.path) + ')</span>') : '')
            + '</span>'
            + '<button type="button" class="cr-btn-glass small cr-copy" data-copy="' + attr(shellAccess.localFlag.flag) + '">' + ic('copy') + 'Copy local.txt</button>'
            + '</div>');
        }
        if (shellAccess.rootFlag) {
          flagRows.push('<div class="cr-staging-bar" style="margin-top:6px">'
            + '<span class="mono"><b>proof.txt (root.txt):</b> <code>' + esc(shellAccess.rootFlag.flag) + '</code>'
            + (shellAccess.rootFlag.path ? (' <span class="muted">(' + esc(shellAccess.rootFlag.path) + ')</span>') : '')
            + '</span>'
            + '<button type="button" class="cr-btn-glass small cr-copy" data-copy="' + attr(shellAccess.rootFlag.flag) + '">' + ic('copy') + 'Copy proof.txt</button>'
            + '</div>');
        }
        var alreadyDoneNote = (st.id === 'loot' && shellAccess.localFlag && shellAccess.rootFlag)
          ? '<div class="cr-onhost-sub muted small" style="margin-top:6px">Both flags were already captured remotely from Kali during Stage 2. You only need the interactive shell below if you want an OSCP exam screenshot (<code>whoami</code> + <code>ipconfig</code> + flag inside an interactive host shell), or you can run the Stage 4 <code>.sh</code> script on Kali to dump full SAM/LSA/NTDS secrets and auto-launch the shell.</div>'
          : '';
        flagsBanner = '<div class="cr-onhost-box" style="border-color:rgba(16,185,129,0.45);margin-bottom:10px">'
          + '<div class="cr-onhost-head"><span class="cr-onhost-k" style="color:#34d399">CAPTURED FLAGS ON LEDGER</span></div>'
          + flagRows.join('')
          + alreadyDoneNote
          + '</div>';
      }

      var loginSection = '';
      if (shellAccess && shellAccess.loginCmd) {
        loginSection = '<div class="cr-onhost-box" style="margin-bottom:10px">'
          + '<div class="cr-onhost-head">'
          + '  <span class="cr-onhost-k">STEP A: LOG ONTO TARGET HOST FROM KALI (INTERACTIVE SHELL)</span>'
          + '  <button type="button" class="cr-btn-neon neon-emerald small cr-copy" data-copy="' + attr(shellAccess.loginCmd) + '">' + ic('copy') + 'Copy Host Login Command</button>'
          + '</div>'
          + '<pre class="cr-onhost-cmd mono"><code>' + esc(shellAccess.loginCmd) + '</code></pre>'
          + (shellAccess.altLoginCmd
            ? ('<div class="cr-staging-bar">'
              + '<span class="muted small">Alt shell (<code class="mono">' + esc(shellAccess.altLoginCmd.split(' ')[0]) + '</code>): <code class="mono">' + esc(shellAccess.altLoginCmd) + '</code></span>'
              + '<button type="button" class="cr-btn-glass small cr-copy" data-copy="' + attr(shellAccess.altLoginCmd) + '">' + ic('copy') + 'Copy Alt Login</button>'
              + '</div>')
            : '')
          + '<div class="cr-onhost-head" style="margin-top:10px">'
          + '  <span class="cr-onhost-k">STEP B: RUN INSIDE TARGET SHELL FOR OSCP SCREENSHOT (WHOAMI + IP + FLAGS)</span>'
          + '  <button type="button" class="cr-btn-neon neon-cyan small cr-copy" data-copy="' + attr(shellAccess.proofCmd) + '">' + ic('copy') + 'Copy OSCP Proof One-Liner</button>'
          + '</div>'
          + '<pre class="cr-onhost-cmd mono"><code>' + esc(shellAccess.proofCmd) + '</code></pre>'
          + '</div>';
      }

      var triageSection = '';
      if (oneLiner) {
        triageSection = '<div class="cr-onhost-box">'
          + '<div class="cr-onhost-head">'
          + '  <span class="cr-onhost-k">FULL ON-HOST ENUMERATION &amp; PROOF ONE-LINER (' + esc(osBadge.toUpperCase()) + ')</span>'
          + '  <button type="button" class="cr-btn-glass small cr-copy" data-copy="' + attr(oneLiner) + '">' + ic('copy') + 'Copy Triage One-Liner</button>'
          + '</div>'
          + '<pre class="cr-onhost-cmd mono"><code>' + esc(oneLiner) + '</code></pre>'
          + '<div class="cr-staging-bar">'
          + '  <span class="muted small">Need to transfer <code>linpeas.sh</code> / <code>winPEASx64.exe</code> / <code>PrintSpoofer64.exe</code> from Kali (' + esc(lhost) + ')?</span>'
          + '  <button type="button" class="cr-btn-glass small cr-copy" data-copy="' + attr(serveCmd) + '">' + ic('copy') + 'Copy Kali HTTP Server (' + esc(serveCmd) + ')</button>'
          + '</div>'
          + '</div>';
      }
      onHostBlock = flagsBanner + loginSection + triageSection;
    }

    var dynamicMovesBlock = '';
    if (st.id === 'enum' && stPlan.examPlan && stPlan.examPlan.batch.length) {
      var movePills = stPlan.examPlan.batch.map(function (b, idx) {
        var isAct = b.tier !== 'safe';
        return '<span class="cr-move-chip mono' + (isAct ? ' is-active-tier' : '') + '" title="' + attr(b.action.proves || b.action.title) + '">' + (idx + 1) + '. ' + esc(b.action.title) + (isAct ? ' [Lab Strike]' : '') + '</span>';
      }).join('');
      dynamicMovesBlock = '<div class="cr-dynamic-moves">'
        + '<span class="cr-ledger-k">FRONTIER MOVES EMBEDDED IN THIS SCRIPT (' + stPlan.examPlan.batch.length + ')</span>'
        + '<div class="cr-move-chips">' + movePills + '</div>'
        + '</div>';
    }

    var wsRoot = (OBOL.workspace && OBOL.workspace.rootFor)
      ? OBOL.workspace.rootFor(eng)
      : ((opts.workspace && opts.workspace.root && opts.workspace.root !== '.') ? String(opts.workspace.root).trim() : '');
    var targetArg = ' ' + OBOL.command.shellQuote(opts.params.target);
    var cdPrefix = wsRoot ? ('cd ' + OBOL.command.shellQuote(wsRoot) + ' && ') : '';
    var runHint = (st.ext === '.bat')
      ? fileName
      : (cdPrefix + 'bash ~/Downloads/' + fileName + targetArg);

    var kaliRunBox = '';
    if (st.ext === '.sh') {
      var stageLogMap = {
        recon: 'obol-stage1-*.log',
        enum: 'obol-stage2-*.log',
        foothold: 'obol-stage3-*.log',
        loot: 'obol-stage4-*.log',
      };
      var stageLogRel = 'scans/' + (stageLogMap[st.id] || 'obol-stage*.log');
      var stageLogFull = wsRoot ? (wsRoot + '/' + stageLogRel) : ('./' + stageLogRel);
      var runLabel = wsRoot
        ? ('RUN ON KALI (EXECUTES FROM ~/Downloads IN ' + esc(wsRoot) + ')')
        : 'RUN ON KALI (EXECUTES FROM ~/Downloads IN CURRENT DIR)';
      var extraNote = (st.id === 'loot')
        ? ' Runs remote proof + secret dump from Kali and then opens an interactive shell on the target.'
        : '';
      kaliRunBox = '<div class="cr-onhost-box cr-kali-run-box">'
        + '<div class="cr-onhost-head">'
        + '  <span class="cr-onhost-k">' + runLabel + '</span>'
        + '  <button type="button" class="cr-btn-neon neon-emerald small cr-copy" data-copy="' + attr(runHint) + '">' + ic('copy') + 'Copy Run Command</button>'
        + '</div>'
        + '<pre class="cr-onhost-cmd mono"><code>' + esc(runHint) + '</code></pre>'
        + '<div class="cr-onhost-sub muted small">Log file saved to: <code class="mono">' + esc(stageLogFull) + '</code> (exact path is printed at the end of the run; use <b>Attach Log File</b> below or paste terminal output).' + extraNote + '</div>'
        + '</div>';
    }

    var neonHue = st.id === 'recon' ? 'neon-cyan' : (st.id === 'enum' ? 'neon-indigo' : (st.id === 'foothold' ? 'neon-amber' : 'neon-purple'));

    return '<section class="cr-station tool-card station-card cr-ph-' + attr(st.phase) + '" data-stage-id="' + attr(st.id) + '">'
      + '<div class="cr-station-head">'
      + '  <div class="cr-station-title-wrap">'
      + '    <div class="cr-station-eyebrow">'
      + '      <span class="cr-stage-pill">' + esc(st.badge) + '</span>'
      + '      <span class="cr-where-pill mono">' + esc(st.where) + '</span>'
      + (wsRoot ? ('<span class="cr-where-pill mono" title="Configured Kali working directory">Dir: ' + esc(wsRoot) + '</span>') : '')
      + '      <span class="cr-zero-pill">' + (stPlan.mode === 'lab' ? 'Lab Full Autopilot' : 'OSCP Exam Safe') + '</span>'
      + '    </div>'
      + '    <h2 class="cr-station-title">' + esc(st.label) + '</h2>'
      + '    <p class="cr-station-sum">' + esc(st.sum) + '</p>'
      + '  </div>'
      + '</div>'
      + '<div class="cr-cap-row">' + pillsHtml + '</div>'
      + dynamicMovesBlock
      + onHostBlock
      + '<div class="cr-station-actions">'
      + '  <button type="button" class="cr-btn-neon ' + neonHue + ' cr-dl-stage" data-stage="' + attr(st.id) + '" data-filename="' + attr(fileName) + '" data-runcmd="' + attr(runHint) + '">' + ic('download') + '1. Download ' + esc(st.badge) + ' (' + esc(st.ext) + ')</button>'
      + '  <button type="button" class="cr-btn-neon neon-emerald cr-copy" data-copy="' + attr(runHint) + '">' + ic('copy') + '2. Copy Run Command</button>'
      + '  <button type="button" class="cr-btn-glass cr-copy" data-copy="' + attr(script) + '">' + ic('copy') + 'Copy Full Script</button>'
      + '</div>'
      + kaliRunBox
      + '<details class="cr-script-preview">'
      + '  <summary class="cr-script-sum"><span>Inspect Generated ' + esc(st.badge) + ' Script (' + script.split('\n').length + ' lines)</span><span class="muted small">Self-segmenting OBOL STEP markers included</span></summary>'
      + '  <pre class="cr-script-code mono"><code>' + esc(script) + '</code></pre>'
      + '</details>'
      + '</section>';
  }

  function renderPasteStation(eng, selectedStageId) {
    var wsRoot = (OBOL.workspace && OBOL.workspace.rootFor)
      ? OBOL.workspace.rootFor(eng)
      : String((eng && eng.params && eng.params.workdir) || '').trim().replace(/\/+$/, '');
    var logGlobMap = {
      recon: 'obol-stage1-*.log',
      enum: 'obol-stage2-*.log',
      foothold: 'obol-stage3-*.log',
      loot: 'obol-stage4-*.log',
    };
    var logGlob = logGlobMap[selectedStageId] || 'obol-stage*.log';
    var logDir = (wsRoot ? (wsRoot + '/scans/') : 'scans/') + logGlob;
    return '<section class="cr-paste tool-card station-card">'
      + '<div class="cr-paste-head">'
      + '  <div>'
      + '    <span class="cr-scope-k">PASTE &amp; ADVANCE</span>'
      + '    <h3 class="cr-paste-title">Paste Stage Output or Attach Log File</h3>'
      + '  </div>'
      + '  <label class="cr-btn-glass small cr-file-btn">'
      + '    ' + ic('upload') + 'Attach Log File'
      + '    <input type="file" id="cr-paste-file" accept=".log,.txt,.xml,.gnmap,.nmap,.json" style="display:none">'
      + '  </label>'
      + '</div>'
      + '<p class="cr-paste-sub muted small">Each stage script automatically saves a full transcript to <code class="mono">' + esc(logDir) + '</code> on Kali (and prints the exact path when finished). Click <b>Attach Log File</b> to select that <code class="mono">.log</code> file, or paste your terminal output directly below.</p>'
      + '<textarea id="cr-paste-box" class="cr-paste-box mono" rows="6" placeholder="Paste terminal output or click Attach Log File to load ' + attr(logDir) + '..."></textarea>'
      + '<div class="cr-paste-row">'
      + '  <button type="button" class="cr-btn-neon neon-emerald" id="cr-paste-go">' + ic('check') + 'Ingest &amp; Update Handoff</button>'
      + '  <span class="cr-paste-msg" aria-live="polite"></span>'
      + '</div>'
      + '</section>';
  }

  function renderLoadoutBar(readiness) {
    if (!readiness || !readiness.synced) {
      return '<section class="cr-loadout-bar is-unsynced tool-card station-card">'
        + '<div class="cr-lo-main">'
        + '  <div class="cr-lo-head-row">'
        + '    <span class="cr-lo-pill is-warn">STEP 0 &middot; LOADOUT NOT SYNCED</span>'
        + '    <strong>Run the Loadout script first so every tool, wordlist, and transfer payload is guaranteed on your box.</strong>'
        + '  </div>'
        + '  <div class="cr-lo-sub muted small">Installs tools omitted from default Kali (<code>certipy-ad</code>, <code>bloodyAD</code>, <code>kerbrute</code>, <code>ligolo-proxy</code>, <code>chisel</code>, <code>feroxbuster</code>, <code>rustscan</code>), stages target payloads (<code>linpeas.sh</code>, <code>winPEASx64.exe</code>, <code>PrintSpoofer.exe</code>, <code>GodPotato.exe</code>) into <code>~/.obol/arsenal/www</code>, unzips <code>rockyou.txt</code>, and patches <code>evil-winrm</code> / <code>hashcat</code>.</div>'
        + '</div>'
        + '<div class="cr-lo-actions">'
        + '  <button type="button" class="cr-btn-neon neon-amber small" id="cr-dl-loadout">' + ic('download') + 'Download download-loadout.sh</button>'
        + '  <a class="cr-btn-glass small" href="#/loadout">Open Loadout Tab &rarr;</a>'
        + '</div>'
        + '</section>';
    }

    var hasGap = readiness.stageMissing && readiness.stageMissing.length > 0;
    if (!hasGap) return '';

    var stageLabel = readiness.stageId ? readiness.stageId.toUpperCase() : 'STAGE';
    return '<section class="cr-loadout-bar is-gap tool-card station-card">'
      + '<div class="cr-lo-main">'
      + '  <div class="cr-lo-head-row">'
      + '    <span class="cr-lo-pill is-warn">&#9888; STAGE TOOLS MISSING (' + readiness.stageMissing.length + ')</span>'
      + '    <span class="cr-lo-gap-note">Missing on last Loadout sync for <b>' + esc(stageLabel) + '</b>: '
      + readiness.stageMissing.map(function (m) { return '<code class="cr-lo-miss-chip">' + esc(m) + '</code>'; }).join(' ')
      + ' (re-run Loadout to install, or rely on Cruise runtime fallback shims).</span>'
      + '  </div>'
      + '</div>'
      + '<div class="cr-lo-actions">'
      + '  <button type="button" class="cr-btn-neon neon-amber small" id="cr-dl-loadout">' + ic('download') + 'Download download-loadout.sh</button>'
      + '  <a class="cr-btn-glass small" href="#/loadout">Inspect Loadout &rarr;</a>'
      + '</div>'
      + '</section>';
  }

  function render() {
    var eng = OBOL.store.active();
    var engId = (eng && eng.id) || null;
    if (engId !== _lastEngId) {
      _lastEngId = engId;
      _lastPaste = null;
      _selectedStage = null;
    }
    var facts = cruiseFactsFor(eng);
    var pack = (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];
    var opts = optsFor(eng);
    var mode = modeOf(eng);
    var handoff = OBOL.cruise.summarizeHandoff(facts, pack, {
      mode: mode,
      doneIds: cruiseDoneIds(eng),
      fill: opts,
      activities: targetActivities(eng),
    });
    var stPlan = handoff.stagePlan;
    var selectedStageId = (eng && eng.ui && eng.ui.cruiseStage) || _selectedStage || stPlan.activeStageId;
    if (!stPlan.stages.some(function (s) { return s.id === selectedStageId; })) {
      selectedStageId = stPlan.activeStageId;
    }
    var readiness = OBOL.cruise.checkArsenalReadiness
      ? OBOL.cruise.checkArsenalReadiness(selectedStageId, stPlan)
      : { synced: false };

    var syncedHeaderPill = readiness && readiness.synced
      ? ('<a href="#/loadout" class="cr-lo-pill is-ok" style="text-decoration:none" title="Loadout synced: ' + readiness.readyCount + '/' + readiness.totalCount + ' tools ready, ' + (readiness.stagedCount || 0) + ' payloads staged in ~/.obol/arsenal/www">&#10003; Loadout Synced (' + readiness.readyCount + '/' + readiness.totalCount + ')</a>')
      : '';

    return '<div class="page cruise-page">'
      + '<div class="page-head">'
      + '  <div>'
      + '    <div class="cr-top">'
      + '      <h1>Cruise</h1>'
      + '      <span class="cr-exp">' + (mode === 'lab' ? 'Lab Full Autopilot &middot; End-to-End Flags' : 'OSCP Exam Safe &middot; Multi-Hypothesis Autopilot') + '</span>'
      + syncedHeaderPill
      + (OBOL.help ? OBOL.help.btn('cruise') : '')
      + '    </div>'
      + '    <p class="muted">Select your target or subnet, choose your engagement profile, and run one multi-hypothesis stage script at a time. Paste the output back to see what paid off, what was ruled out, and why the next script does what it does.</p>'
      + '  </div>'
      + '</div>'
      + renderLoadoutBar(readiness)
      + renderProfileSwitch(mode)
      + renderScopeBar(eng, OBOL.store.factSet ? OBOL.store.factSet() : facts)
      + renderPipeline(stPlan, selectedStageId)
      + renderHandoff(handoff)
      + renderActiveStation(stPlan, selectedStageId, eng, facts, pack)
      + renderPasteStation(eng, selectedStageId)
      + '</div>';
  }

  function setTargetScope(val) {
    var clean = String(val || '').trim();
    if (!clean) { U.toast('Enter a target IP or CIDR subnet first.', 'err'); return; }
    _lastPaste = null;
    _selectedStage = null;
    var firstIp = clean.split(/\s+/)[0];
    OBOL.store.update(function (e) {
      e.params = e.params || {};
      e.targets = e.targets || [];
      var prev = String(e.params.target || '').trim();
      if (prev && prev.indexOf('/') < 0 && !/\s/.test(prev) && !e.targets.some(function (t) { return t && t.ip === prev; })) {
        e.targets.push({ id: 't-' + Date.now().toString(36) + '-prev', ip: prev, hostname: '', os: '', source: 'cruise' });
      }
      e.params.target = clean;
      if (firstIp && firstIp.indexOf('/') < 0 && !e.targets.some(function (t) { return t && t.ip === firstIp; })) {
        e.targets.push({ id: 't-' + Date.now().toString(36), ip: firstIp, hostname: '', os: '', source: 'cruise' });
      }
      e.activeTarget = (firstIp && firstIp.indexOf('/') < 0) ? firstIp : null;
      if (e.ui) delete e.ui.cruiseStage;
    }, 'params');
    if (OBOL.facts && OBOL.store.addFacts && firstIp && firstIp.indexOf('/') < 0) {
      OBOL.store.addFacts([OBOL.facts.makeFact({ kind: 'target.configured', scope: 'host:' + firstIp, source: 'cruise' })], 'facts');
    }
    if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    OBOL.router.render();
    U.toast('Active scope set to ' + clean);
  }

  function processIngest(text, fileName, mount) {
    var msg = mount.querySelector('.cr-paste-msg');
    if (!text || !text.trim()) {
      if (msg) { msg.textContent = 'Paste some output or attach a log file first.'; msg.className = 'cr-paste-msg err'; }
      return;
    }
    if (msg) { msg.textContent = 'Parsing output and updating Handoff...'; msg.className = 'cr-paste-msg'; }

    var beforeKinds = {};
    try {
      (OBOL.store.factSet().facts || []).forEach(function (f) { if (f && f.kind) beforeKinds[f.kind] = 1; });
    } catch (e) {}

    var finish = function (r) {
      if (!r || !r.ok) {
        if (msg) { msg.textContent = 'Could not parse output (' + ((r && r.reason) || 'error') + ').'; msg.className = 'cr-paste-msg err'; }
        return;
      }
      var added = (r.added != null) ? r.added : 0;
      var newKinds = [];
      try {
        (OBOL.store.factSet().facts || []).forEach(function (f) {
          if (f && f.kind && !beforeKinds[f.kind] && newKinds.indexOf(f.kind) < 0) newKinds.push(f.kind);
        });
      } catch (e) {}
      if (r.arsenal && r.arsenal.ok) {
        newKinds.unshift('loadout.synced (' + r.arsenal.present + ' tools)');
      }
      if (r.workspaceSync && r.workspaceSync.ok) {
        newKinds.unshift('workspace.synced (' + r.workspaceSync.confirmed + ' confirmed)');
      }
      if (r.targetsImported && r.targetsImported.ok) {
        newKinds.unshift('targets.imported (' + (r.targetsImported.added || 0) + ')');
      }
      _lastPaste = {
        at: Date.now(),
        added: added,
        commands: r.imported || 1,
        kinds: newKinds,
        arsenal: r.arsenal || null,
        outcome: r.outcome || null,
      };
      if (r.outcome && r.outcome.conclusive) {
        _selectedStage = null;
        OBOL.store.update(function (e) { if (e.ui) delete e.ui.cruiseStage; }, 'cruise-stage');
      }
      var toastMsg = r.outcome ? OBOL.ingest.outcomeMessage(r)
        : (r.arsenal && r.arsenal.ok ? ('Loadout synced (' + r.arsenal.present + ' tools)') : 'Output saved for review');
      U.toast(toastMsg);
      OBOL.router.render();
    };

    var runIngest = function (okp) {
      var r = null;
      try {
        r = okp && OBOL.ingest.importSession ? OBOL.ingest.importSession(text, { target: 'auto', fileName: fileName || '' }) : null;
        if (r && r.ok && r.imported === 0) r = OBOL.ingest.run({ text: text, source: 'cruise', fileName: fileName || '' });
        else if (!r) r = OBOL.ingest.run({ text: text, source: 'cruise', fileName: fileName || '' });
      } catch (x) {
        try { r = OBOL.ingest.run({ text: text, source: 'cruise', fileName: fileName || '' }); }
        catch (y) { r = { ok: false, reason: (y && y.message) || 'error' }; }
      }
      finish(r);
    };

    if (OBOL.ingest && OBOL.ingest.ensureParsers) {
      OBOL.ingest.ensureParsers().then(runIngest);
    } else {
      runIngest(true);
    }
  }

  function triggerLoadoutDownload() {
    var go = function () {
      if (!OBOL.arsenal || !OBOL.arsenal.buildScript) {
        U.toast('Loadout script generator unavailable', 'err');
        return;
      }
      var promptStamp = true;
      try { promptStamp = localStorage.getItem('obol.arsenal-promptstamp') !== '0'; } catch (e) {}
      var ok = downloadScript('download-loadout.sh', OBOL.arsenal.buildScript({ promptStamp: promptStamp }));
      U.toast(ok ? 'download-loadout.sh downloaded - run it on Kali, then paste back!' : 'Download failed', ok ? '' : 'err');
    };
    if (OBOL.arsenal && OBOL.arsenal.buildScript) {
      go();
    } else if (OBOL.lazy && OBOL.lazy.loadGroup) {
      OBOL.lazy.loadGroup('loadout').then(go);
    } else {
      go();
    }
  }

  function mounted(ctx) {
    var mount = (ctx && ctx.mount) || ctx;
    if (!mount || !mount.querySelector) return;

    var pvCard = mount.querySelector('.pivot-station');
    if (pvCard && OBOL.pivotStationUI) {
      var pvBody = pvCard.querySelector('.station-body');
      if (pvBody) OBOL.pivotStationUI.mount(pvBody);
    }

    U.on(mount, 'click', '#cr-dl-loadout', function (e) {
      e.preventDefault();
      triggerLoadoutDownload();
    });

    U.on(mount, 'click', '[data-cr-mode]', function (e, el) {
      e.preventDefault();
      var m = el.getAttribute('data-cr-mode') === 'lab' ? 'lab' : 'exam';
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.cruiseMode = m;
      }, 'cruise-mode');
      OBOL.router.render();
      U.toast(m === 'lab' ? 'Switched to Lab Full Autopilot (End-to-End Flags)' : 'Switched to OSCP Exam Safe mode');
    });

    U.on(mount, 'click', '[data-cr-target]', function (e, el) {
      e.preventDefault();
      var ip = el.getAttribute('data-cr-target');
      if (ip) setTargetScope(ip);
    });

    var scopeForm = mount.querySelector('#cr-scope-form');
    if (scopeForm) {
      scopeForm.addEventListener('submit', function (e) {
        e.preventDefault();
        var inp = mount.querySelector('#cr-target-input');
        if (inp) setTargetScope(inp.value);
      });
    }

    U.on(mount, 'click', '[data-cr-stage]', function (e, el) {
      e.preventDefault();
      var stId = el.getAttribute('data-cr-stage');
      if (!stId) return;
      _selectedStage = stId;
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.cruiseStage = stId;
      }, 'cruise-stage');
      OBOL.router.render();
    });

    U.on(mount, 'click', '.cr-copy', function (e, el) {
      e.preventDefault();
      var text = el.getAttribute('data-copy') || '';
      if (el.getAttribute('data-copy-action') && OBOL.ingest) OBOL.ingest.setLastCopied({ command: text, actionId: el.getAttribute('data-copy-action'),
        target: ((OBOL.store.active() || {}).params || {}).target || '', executionLocus: el.getAttribute('data-copy-locus') || 'remote' });
      U.copy(text).then(function (ok) { U.toast(ok ? 'Copied to clipboard' : 'Copy failed', ok ? '' : 'err'); });
    });

    U.on(mount, 'click', '.cr-dl-stage', function (e, el) {
      e.preventDefault();
      var stId = el.getAttribute('data-stage') || 'recon';
      var fname = el.getAttribute('data-filename') || ('obol-' + stId + '.sh');
      var eng = OBOL.store.active();
      var facts = cruiseFactsFor(eng);
      var pack = (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];
      var opts = optsFor(eng);
      var mode = modeOf(eng);
      var doneIds = cruiseDoneIds(eng);
      var stPlan = OBOL.cruise.planStages(facts, pack, { mode: mode, doneIds: doneIds, fill: opts });
      var script = OBOL.cruise.buildStageScript(stId, {
        mode: mode,
        params: opts.params,
        profile: opts.profile,
        workspace: opts.workspace,
        facts: facts,
        pack: pack,
        osFamily: stPlan.osFamily,
        doneIds: doneIds,
      });
      if (!script) { U.toast('Configure a valid target before generating a Cruise script.', 'err'); return; }
      var ok = downloadScript(fname, script);
      var runCmd = el.getAttribute('data-runcmd') || '';
      if (ok && runCmd && U.copy) {
        U.copy(runCmd).then(function (copied) {
          U.toast(copied ? ('Downloaded ' + fname + ' & copied Run command') : ('Downloaded ' + fname));
        });
      } else {
        U.toast(ok ? ('Downloaded ' + fname) : 'Download failed', ok ? '' : 'err');
      }
    });

    U.on(mount, 'click', '#cr-paste-go', function (e) {
      e.preventDefault();
      var box = mount.querySelector('#cr-paste-box');
      processIngest((box && box.value) || '', '', mount);
    });

    var fileInp = mount.querySelector('#cr-paste-file');
    if (fileInp) {
      fileInp.addEventListener('change', function () {
        var f = fileInp.files && fileInp.files[0];
        if (!f) return;
        var reader = new FileReader();
        reader.onload = function () {
          processIngest(String(reader.result || ''), f.name, mount);
        };
        reader.readAsText(f);
      });
    }
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.cruise = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
