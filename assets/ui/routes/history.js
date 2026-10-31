/*!
 * obol ui - routes/history.js - the Run Log & Respawn Replay:
 * Every command run / evidence ingested on this engagement, with two modes:
 *   1. All Activity (Newest First): full historical audit ledger.
 *   2. Respawn Replay (Oldest -> Newest): chronological step-by-step replay of milestone / runnable
 *      commands (automatically updated to any new Re-IP target address and LHOST) + 1-click /etc/hosts fixer.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  var _mode = 'all';            // 'all' (newest first) | 'replay' (oldest -> newest)
  var _replayFilter = 'path';   // 'path' (key milestones / attack path) | 'all-cmds' (all runnable commands)
  var _targetFilter = 'all';    // 'all' | '<ip>'
  var _query = '';
  var _lastEngId = null;

  function when(ts) {
    if (!ts) return '';
    try { return new Date(ts).toLocaleString(); } catch (e) { return ''; }
  }

  function label(a) {
    if (a.command) return a.command;
    if (a.file) return 'attached file: ' + a.file;
    if (a.dispatch) return a.dispatch + '  (recognized from output)';
    return (a.tool && a.tool !== 'paste') ? a.tool + '  (pasted output)' : 'pasted output';
  }

  function activityTarget(a) {
    if (!a) return '';
    return a.target || (String(a.scope || '').indexOf('host:') === 0 ? String(a.scope).slice(5) : '');
  }

  // Build set of action_ids that appear on any target's causal Attack Path
  function causalActionSet(eng, targetFilter) {
    var set = {};
    if (!OBOL.chain || !OBOL.packs || !OBOL.store) return set;
    var pack = OBOL.packs.actions() || [];
    var targets = (eng.targets || []).map(function (t) { return t.ip || t.id; }).filter(Boolean);
    if (!targets.length && eng.params && eng.params.target) targets.push(eng.params.target);
    targets.forEach(function (ip) {
      if (targetFilter && targetFilter !== 'all' && ip !== targetFilter) return;
      try {
        var fs = OBOL.store.factSetForTarget ? OBOL.store.factSetForTarget(ip) : OBOL.store.factSet();
        var steps = OBOL.chain.build({ facts: fs, activities: eng.activities || [], actions: pack, host: ip }) || [];
        steps.forEach(function (s) {
          if (s && s.actionId) set[s.actionId] = true;
          if (s && s.id) set[s.id] = true;
        });
      } catch (e) {}
    });
    return set;
  }

  var MILESTONE_FACT_RE = /^(foothold\.|access\.|credential\.|hash\.|loot\.|privesc\.|ad\.|adcs\.|kerberos\.|smb\.writable|web\.sqli|web\.lfi|web\.rfi|web\.upload|web\.cmd_injection|web\.ssti|web\.deserialization|web\.ssrf|tunnel\.|pivot\.|objective\.)/;

  function isMilestoneActivity(a, causalIds) {
    if (!a || !a.command) return false;
    var actId = a.action_id || a.actionId || '';
    if (actId && causalIds[actId]) return true;
    var prod = a.produced || [];
    if (prod.some(function (k) { return MILESTONE_FACT_RE.test(k); })) return true;
    return false;
  }

  function renderReIpBanner(eng) {
    var reIpTargets = (eng.targets || []).filter(function (t) {
      if (!t || !Array.isArray(t.previousIps) || !t.previousIps.length) return false;
      if (_targetFilter !== 'all' && (t.ip || t.id) !== _targetFilter) return false;
      return true;
    });
    if (!reIpTargets.length) return '';

    var items = reIpTargets.map(function (t) {
      var ip = t.ip || t.id;
      var oldIp = t.previousIps[t.previousIps.length - 1];
      var sedCmd = (OBOL.targets && OBOL.targets.hostsFixCmd)
        ? OBOL.targets.hostsFixCmd(oldIp, ip, t.hostname, t.domain)
        : ("sudo sed -i 's/" + oldIp.replace(/\./g, '\\.') + "/" + ip + "/g' /etc/hosts");
      return '<div class="hl-reip-item">'
        + '<div class="hl-reip-main">'
        + '  <span class="hl-reip-kicker">RESPAWN RE-IP ACTIVE</span>'
        + '  <span class="hl-reip-txt">Target <strong>' + esc(t.hostname ? (t.hostname + ' (' + ip + ')') : ip) + '</strong> migrated from <code>' + esc(oldIp) + '</code> &rarr; <code>' + esc(ip) + '</code>. All Run Log commands below have been updated to <code>' + esc(ip) + '</code>.</span>'
        + '</div>'
        + '<div class="hl-reip-hosts">'
        + '  <span class="hl-reip-hosts-l">Update <code>/etc/hosts</code> on Kali:</span>'
        + '  <code class="hl-reip-sed">' + esc(sedCmd) + '</code>'
        + '  <button type="button" class="btn-copy small" data-copy="' + U.attr(sedCmd) + '">Copy /etc/hosts Fix</button>'
        + '</div>'
        + '</div>';
    }).join('');

    return '<div class="hl-reip-banner station-card neon-lane-amber">' + items + '</div>';
  }

  function render() {
    var eng = OBOL.store.active() || {};
    if (eng.id && eng.id !== _lastEngId) {
      if (_lastEngId !== null) {
        _mode = 'all';
        _replayFilter = 'path';
        _targetFilter = 'all';
        _query = '';
      }
      _lastEngId = eng.id;
    }

    // Consume one-shot navigation hint from "Save & Replay in Run Log ->"
    try {
      var navMode = sessionStorage.getItem('obol.history.mode');
      var navTgt = sessionStorage.getItem('obol.history.target');
      if (navMode) {
        _mode = navMode === 'replay' ? 'replay' : 'all';
        sessionStorage.removeItem('obol.history.mode');
      }
      if (navTgt) {
        _targetFilter = navTgt;
        sessionStorage.removeItem('obol.history.target');
      }
    } catch (e) {}

    var acts = (eng.activities || []);
    if (!acts.length) {
      return '<section class="history-route"><h1 class="route-h1">Run Log</h1>'
        + renderReIpBanner(eng)
        + '<p class="route-sub">No commands logged yet. Everything you paste or attach on the Evidence route (the command and its full output) is recorded here so you can review or replay the run later.</p></section>';
    }

    // Collect distinct targets present in targets list or activities
    var targetList = [], seenTgt = {};
    (eng.targets || []).forEach(function (t) {
      var ip = t && (t.ip || t.id);
      if (ip && !seenTgt[ip]) { seenTgt[ip] = 1; targetList.push(ip); }
    });
    acts.forEach(function (a) {
      var ip = activityTarget(a);
      if (ip && !seenTgt[ip]) { seenTgt[ip] = 1; targetList.push(ip); }
    });
    if (_targetFilter !== 'all' && !seenTgt[_targetFilter]) _targetFilter = 'all';

    // Target-filtered slice
    var scopedActs = acts.filter(function (a) {
      if (_targetFilter === 'all') return true;
      return activityTarget(a) === _targetFilter;
    });

    // Compute Replay sets (Oldest -> Newest chronological order)
    // Note: `eng.activities` is stored newest-first (unshift on ingest), or check timestamps (`a.at`)
    var chronological = scopedActs.slice().sort(function (a, b) {
      return (a.at || 0) - (b.at || 0);
    });
    var runnableChrono = chronological.filter(function (a) { return !!(a && a.command); });
    var causalIds = causalActionSet(eng, _targetFilter);
    var milestoneChrono = runnableChrono.filter(function (a) { return isMilestoneActivity(a, causalIds); });
    // Fallback: if no high-level milestones yet, include any runnable command that minted facts
    if (!milestoneChrono.length) {
      milestoneChrono = runnableChrono.filter(function (a) { return (a.produced && a.produced.length > 0) || a.addedCount > 0; });
    }
    if (!milestoneChrono.length) {
      milestoneChrono = runnableChrono;
    }

    var displayList;
    if (_mode === 'replay') {
      displayList = (_replayFilter === 'path') ? milestoneChrono : runnableChrono;
    } else {
      displayList = scopedActs;
    }

    var q = (_query || '').toLowerCase().trim();
    if (q) {
      displayList = displayList.filter(function (a) {
        var hay = [label(a), a.originalCommand || '', a.action_id || '', activityTarget(a), (a.produced || []).join(' '), a.stdout || a.sample || ''].join(' ').toLowerCase();
        return hay.indexOf(q) >= 0;
      });
    }

    var rows = displayList.map(function (a, i) {
      var cmd = label(a);
      var produced = (a.produced || []);
      var chips = produced.length
        ? produced.slice(0, 12).map(function (k) {
            var friendly = (OBOL.pack && OBOL.pack.friendly) ? (OBOL.pack.friendly(k) || k) : k;
            return '<span class="hl-fact" title="' + U.attr(k) + '">' + esc(friendly) + '</span>';
          }).join('') + (produced.length > 12 ? '<span class="hl-fact hl-more">+' + (produced.length - 12) + '</span>' : '')
        : '<span class="hl-nofact">no new facts</span>';
      var out = a.stdout || a.sample || '';
      var isHtmlBody = /<(?:!doctype\s+html|html|form)\b/i.test(out);
      var lineCount = String(out).split(/\r?\n/).length;
      var body = out
        ? '<details class="hl-out' + (isHtmlBody ? ' html-collapse' : '') + '"><summary>' + (isHtmlBody ? 'HTML response body - collapsed (' : 'output (') + lineCount + ' lines)</summary><pre class="hl-pre" tabindex="0"><code>' + esc(out) + '</code></pre></details>'
        : '';
      var tgt = activityTarget(a);
      var stepBadge = _mode === 'replay'
        ? '<span class="hl-step-num">Step ' + (i + 1) + '</span>'
        : '';
      var reIpBadge = a.reIpFrom
        ? '<span class="hl-reip-badge" title="Original command before Re-IP: ' + U.attr(a.originalCommand || '') + '">Re-IP: ' + esc(a.reIpFrom) + ' &rarr; ' + esc(tgt || 'new IP') + '</span>'
        : (a.reLhostFrom ? '<span class="hl-reip-badge" title="Original command: ' + U.attr(a.originalCommand || '') + '">LHOST updated</span>' : '');

      return '<article class="hl-row' + (_mode === 'replay' ? ' hl-row-replay' : '') + '" data-hl="' + i + '">'
        + '<div class="hl-head">'
        + stepBadge
        + '<span class="hl-time">' + esc(when(a.at)) + '</span>'
        + (tgt ? '<span class="pill hl-tgt">' + esc(tgt) + '</span>' : '')
        + (a.action_id ? '<span class="hl-move" title="move">' + esc(a.action_id) + '</span>' : '')
        + reIpBadge
        + '<button type="button" class="btn-copy hl-copy" data-copy="' + U.attr(a.command || cmd) + '" title="Copy command">copy</button>'
        + '</div>'
        + '<pre class="hl-cmd" tabindex="0"><code>' + esc(cmd) + '</code></pre>'
        + (_mode === 'replay' ? '' : (a.outcome && OBOL.ingest ? OBOL.ingest.renderOutcome(a.outcome, { noPrompt: true }) : ''))
        + '<div class="hl-facts">' + chips + '</div>'
        + body
        + '</article>';
    }).join('');

    var modeBar = '<div class="hl-toolbar">'
      + '<div class="hl-mode-group" role="group" aria-label="Run Log mode">'
      + '  <button type="button" class="hb-tf-pill' + (_mode === 'all' ? ' on' : '') + '" data-hl-mode="all">All Activity (Newest First) <span class="hb-tf-n">' + scopedActs.length + '</span></button>'
      + '  <button type="button" class="hb-tf-pill' + (_mode === 'replay' ? ' on' : '') + '" data-hl-mode="replay">&#8635; Respawn Replay (Oldest &rarr; Newest) <span class="hb-tf-n">' + milestoneChrono.length + '</span></button>'
      + '</div>'
      + (_mode === 'replay'
          ? '<div class="hl-submode-group" role="group" aria-label="Replay filter">'
            + '<button type="button" class="hb-tf-pill' + (_replayFilter === 'path' ? ' on' : '') + '" data-hl-rfilter="path">Key Milestones / Attack Path <span class="hb-tf-n">' + milestoneChrono.length + '</span></button>'
            + '<button type="button" class="hb-tf-pill' + (_replayFilter === 'all-cmds' ? ' on' : '') + '" data-hl-rfilter="all-cmds">All Runnable Commands <span class="hb-tf-n">' + runnableChrono.length + '</span></button>'
            + '</div>'
          : '')
      + (targetList.length > 1
          ? '<div class="hl-tgt-group" role="group" aria-label="Target filter">'
            + '<button type="button" class="hb-tf-pill' + (_targetFilter === 'all' ? ' on' : '') + '" data-hl-tgt="all">All Targets</button>'
            + targetList.map(function (ip) {
                return '<button type="button" class="hb-tf-pill' + (_targetFilter === ip ? ' on' : '') + '" data-hl-tgt="' + U.attr(ip) + '">' + esc(ip) + '</button>';
              }).join('')
            + '</div>'
          : '')
      + '</div>';

    var replayBanner = _mode === 'replay'
      ? '<div class="hl-replay-guide ws-clear-box">'
        + '<strong>Respawn Replay Mode (Chronological Step 1 &rarr; Step ' + displayList.length + '):</strong> '
        + 'Work top-to-bottom to re-establish your foothold on a reset or respawned lab box. Every command below already reflects your current target IP and LHOST.'
        + '</div>'
      : '';

    return '<section class="history-route">'
      + '<div class="targets-top-bar">'
      + '  <div>'
      + '    <h1 class="route-h1">Run Log</h1>'
      + '    <p class="route-sub">Every command run on <strong>' + esc(OBOL.store.runLabel ? OBOL.store.runLabel(eng) : (eng.name || 'this engagement')) + '</strong> (' + acts.length + '), with full saved output and chronological Respawn Replay.</p>'
      + '  </div>'
      + '  <a class="cr-btn-glass small" href="#/home">&larr; Engagement Hub</a>'
      + '</div>'
      + renderReIpBanner(eng)
      + modeBar
      + replayBanner
      + '<input class="hl-filter" type="search" value="' + U.attr(_query) + '" placeholder="Filter commands and output..." autocomplete="off" spellcheck="false" aria-label="Filter the run log">'
      + '<div class="hl-list">' + rows + '<div class="coach-empty hl-filter-empty"' + (rows ? ' hidden' : '') + '>No commands match your filter.</div></div>'
      + '</section>';
  }

  function mounted(ctx) {
    var mount = ctx.mount.querySelector('.history-route') || ctx.mount;
    U.on(mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    U.on(mount, 'click', '[data-hl-mode]', function (e, btn) {
      _mode = btn.getAttribute('data-hl-mode') || 'all';
      OBOL.router.render();
    });
    U.on(mount, 'click', '[data-hl-rfilter]', function (e, btn) {
      _replayFilter = btn.getAttribute('data-hl-rfilter') || 'path';
      OBOL.router.render();
    });
    U.on(mount, 'click', '[data-hl-tgt]', function (e, btn) {
      _targetFilter = btn.getAttribute('data-hl-tgt') || 'all';
      OBOL.router.render();
    });
    U.on(mount, 'input', '.hl-filter', function (e, t) {
      _query = t.value || '';
      var q = _query.toLowerCase().trim();
      var anyVisible = false;
      Array.prototype.forEach.call(mount.querySelectorAll('.hl-row'), function (row) {
        var hide = !!q && row.textContent.toLowerCase().indexOf(q) < 0;
        row.hidden = hide;
        if (!hide) anyVisible = true;
      });
      var emptyEl = mount.querySelector('.hl-filter-empty');
      if (emptyEl) emptyEl.hidden = anyVisible;
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.history = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
