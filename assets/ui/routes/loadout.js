/*!
 * obol ui — routes/loadout.js — THE LOADOUT (step zero: set up your attack box).
 * Leftmost tab. Two faces from one route:
 *   - no machine profile yet  -> a guided quickstart (download the script, run it, paste the result back)
 *   - profile present          -> the live inventory (what's installed / staged / cached on your box)
 * Plus the Arsenal catalog (every tool obol covers, with install/stage recipes) and the Workspace
 * scaffold. Never a gate: everything here is optional; skip it and every command still works canonical.
 * The browser only GENERATES a setup script and READS the pasted-back inventory — it never executes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  var _hideKali = true;   // "not on Kali" default view (toggle persists for the session)

  var CLASS_LABEL = {
    kali: 'on Kali', builtin: 'built-in', apt: 'apt', pipx: 'pipx', git: 'git clone',
    go: 'go', material: 'fetch', 'stage-win': 'stage → www/', 'stage-lin': 'stage',
  };
  function classBadge(e) {
    var on = e.on_kali ? ' lo-badge-ok' : '';
    return '<span class="lo-badge' + on + '">' + esc(CLASS_LABEL[e.class] || e.class) + '</span>';
  }
  // per-tool live state from the pasted-back profile (or null when unsynced)
  function toolState(e, prof) {
    if (!prof) return '';
    var t = (prof.tools || {})[e.key];
    var stagedHit = (prof.staged || []).indexOf(e.dest || '') >= 0;
    if (t && t.present) {
      var inv = t.invocation && t.invocation !== e.canonical ? ' as <code>' + esc(t.invocation) + '</code>' : '';
      return '<span class="lo-state lo-have">✓ installed' + inv + '</span>';
    }
    if (stagedHit) return '<span class="lo-state lo-have">✓ staged</span>';
    if (e.class === 'kali' || e.class === 'builtin') return '<span class="lo-state lo-miss">not found — unusual on Kali</span>';
    return '<span class="lo-state lo-miss">not yet — run the script</span>';
  }

  function toolCard(e, prof) {
    var recipe = e.install
      ? '<div class="lo-recipe"><code>' + esc(e.install) + '</code><button class="btn-copy" data-copy="' + U.attr(e.install) + '">copy</button></div>'
      : (e.class === 'stage-win' || e.class === 'material' || e.class === 'stage-lin')
        ? '<div class="lo-recipe lo-fetch">fetched + staged by <code>download-arsenal.sh</code></div>' : '';
    var prov = e.source ? '<span class="lo-src">' + esc(e.source) + (e.license ? ' · ' + esc(e.license) : '') + '</span>' : '';
    var av = e.av_note ? '<div class="lo-av">⚠ ' + esc(e.av_note) + '</div>' : '';
    return '<article class="lo-tool">'
      + '<div class="lo-tool-h"><span class="lo-tool-name">' + esc(e.label || e.key) + '</span>' + classBadge(e) + toolState(e, prof) + '</div>'
      + (e.purpose ? '<div class="lo-tool-why">' + esc(e.purpose) + '</div>' : '')
      + recipe + av
      + (prov ? '<div class="lo-tool-foot">' + prov + '</div>' : '')
      + '</article>';
  }

  // group the arsenal for display: action-needed classes first, Kali-defaults last (collapsible)
  var ORDER = ['pipx', 'git', 'go', 'apt', 'material', 'stage-lin', 'stage-win', 'kali', 'builtin'];
  function arsenalSection(prof) {
    var A = OBOL.ARSENAL || {}, seen = {}, groups = {};
    Object.keys(A).sort().forEach(function (k) {
      var e = A[k]; if (!e || seen[e.key]) return; seen[e.key] = 1;
      (groups[e.class] = groups[e.class] || []).push(e);
    });
    var html = '<div class="coach-section"><div class="lo-sec-head"><h2 class="coach-sec-h">Arsenal</h2>'
      + '<label class="lo-toggle"><input type="checkbox" id="lo-hidekali"' + (_hideKali ? ' checked' : '') + '> hide tools Kali already ships</label></div>';
    ORDER.forEach(function (cls) {
      var list = groups[cls]; if (!list || !list.length) return;
      if (_hideKali && (cls === 'kali' || cls === 'builtin')) return;
      html += '<div class="lo-group"><div class="lo-group-h">' + esc(CLASS_LABEL[cls] || cls)
        + ' <span class="lo-group-n">' + list.length + '</span></div><div class="lo-grid">'
        + list.map(function (e) { return toolCard(e, prof); }).join('') + '</div></div>';
    });
    if (_hideKali) {
      var kaliN = (groups.kali || []).length + (groups.builtin || []).length;
      html += '<div class="lo-kali-note">' + kaliN + ' more tools ship with Kali — nothing to do. Untick above to list them.</div>';
    }
    return html + '</div>';
  }

  function quickstart(prof) {
    var synced = !!prof;
    var when = synced ? timeAgo(prof.savedAt) : '';
    var head = synced
      ? '<div class="lo-synced"><span class="lo-synced-dot"></span> Loadout synced <strong>' + esc(when) + '</strong> — '
        + countSummary(prof) + ' <button class="btn-ghost lo-resync">Re-sync</button></div>'
      : '';
    var steps = '<ol class="lo-steps">'
      + '<li><span class="lo-step-n">1</span><div><strong>Download the setup script</strong><div class="lo-step-sub">One file; fetches every tool obol uses that Kali doesn\'t ship, and stages the Windows binaries.</div>'
      + '<button class="btn-primary lo-download">Download download-arsenal.sh</button></div></li>'
      + '<li><span class="lo-step-n">2</span><div><strong>Run it on your Kali box</strong><div class="lo-step-sub">Safe to re-run — it only does the missing work.</div>'
      + '<div class="lo-recipe"><code>chmod +x download-arsenal.sh &amp;&amp; ./download-arsenal.sh</code><button class="btn-copy" data-copy="chmod +x download-arsenal.sh &amp;&amp; ./download-arsenal.sh">copy</button></div></div></li>'
      + '<li><span class="lo-step-n">3</span><div><strong>Paste the result back</strong><div class="lo-step-sub">The script ends by printing an <code>OBOL-ARSENAL</code> block — paste the whole thing here and obol learns your box.</div>'
      + '<textarea class="lo-paste" placeholder="Paste the OBOL-ARSENAL block (or the whole script output) here…" spellcheck="false"></textarea>'
      + '<div class="lo-paste-row"><button class="btn-primary lo-ingest">Stock my Loadout</button><span class="lo-paste-msg" role="status"></span></div></div></li>'
      + '</ol>';
    return '<div class="lo-quick' + (synced ? ' lo-quick-done' : '') + '">' + head
      + (synced ? '<details class="lo-redetails"><summary>Set up again / on another box</summary>' + steps + '</details>' : steps)
      + '</div>';
  }

  function workspaceSection() {
    var eng = OBOL.store.active();
    if (!OBOL.workspace || !eng) return '';
    var scaffold = OBOL.workspace.scaffold(eng);
    var scandir = OBOL.workspace.tokens(eng).scandir;
    return '<div class="coach-section"><h2 class="coach-sec-h">Workspace</h2>'
      + '<p class="route-sub">Your on-box working tree. Run this once; every coach command writes into it.</p>'
      + '<pre class="cmd-run"><code>' + esc(scaffold) + '</code></pre>'
      + '<div class="ws-banner-actions"><button class="btn-copy" data-copy="' + U.attr(scaffold) + '">copy</button></div>'
      + '<div class="ws-banner-note">Commands below write into <code>' + esc(scandir) + '</code>. Staged Windows binaries land in your <code>www/</code> to serve to targets.</div>'
      + '</div>';
  }

  function countSummary(prof) {
    var present = 0; Object.keys(prof.tools || {}).forEach(function (k) { if (prof.tools[k] && prof.tools[k].present) present++; });
    var wl = Object.keys(prof.wordlists || {}).length;
    return present + ' tools · ' + (prof.staged || []).length + ' staged' + (wl ? ' · ' + wl + ' wordlist' + (wl === 1 ? '' : 's') : '');
  }
  function timeAgo(t) {
    if (!t) return 'just now';
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 90) return 'just now';
    if (s < 5400) return Math.round(s / 60) + ' min ago';
    if (s < 129600) return Math.round(s / 3600) + 'h ago';
    return Math.round(s / 86400) + 'd ago';
  }

  function render() {
    var prof = OBOL.arsenal ? OBOL.arsenal.profileGet() : null;
    var A = OBOL.ARSENAL || {};
    var total = 0, seen = {}; Object.keys(A).forEach(function (k) { if (A[k] && !seen[A[k].key]) { seen[A[k].key] = 1; total++; } });
    var html = '<section class="coach lo-route">'
      + '<div class="coach-hero"><div class="coach-hero-main">'
      + '<div class="coach-kicker">Step zero · <strong>your attack box</strong></div>'
      + '<h1 class="coach-h1">Loadout</h1>'
      + '<p class="coach-sub">' + (prof
          ? 'obol knows your box and tailors every command to the tools you actually have.'
          : 'Set up your Kali box once — obol generates the script, you run it, paste the result back. Optional: skip it and every command still works.')
      + '</p></div>'
      + '<div class="coach-metrics"><div class="metric"><span class="metric-n">' + total + '</span><span class="metric-l">Tools obol uses</span></div>'
      + (prof ? '<div class="metric"><span class="metric-n">' + countSummary(prof).split(' ')[0] + '</span><span class="metric-l">On your box</span></div>' : '')
      + '</div></div>';
    if (!prof) html += '<p class="lo-skip">New here? Do this first. Or <a href="#/home">skip to Engagements →</a> — nothing here blocks you.</p>';
    html += quickstart(prof);
    html += arsenalSection(prof);
    html += workspaceSection();
    return html + '</section>';
  }

  function doDownload() {
    if (!OBOL.arsenal || !OBOL.arsenal.buildScript) { U.toast('Arsenal module still loading — try again', 'err'); return; }
    var text = OBOL.arsenal.buildScript();
    var blob = new Blob([text], { type: 'text/x-shellscript' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'download-arsenal.sh';
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
    U.toast('download-arsenal.sh downloaded');
  }

  function mounted(ctx) {
    var mount = ctx.mount.querySelector('.lo-route') || ctx.mount;
    U.on(mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    U.on(mount, 'click', '.lo-download', function () { doDownload(); });
    U.on(mount, 'change', '#lo-hidekali', function (e, t) { _hideKali = !!t.checked; OBOL.router.render(); });
    U.on(mount, 'click', '.lo-resync', function () {
      var ta = mount.querySelector('.lo-paste'); var det = mount.querySelector('.lo-redetails');
      if (det) det.open = true;
      if (ta) { ta.scrollIntoView({ behavior: 'smooth', block: 'center' }); ta.focus(); }
    });
    U.on(mount, 'click', '.lo-ingest', function (e, t) {
      var box = mount.querySelector('.lo-paste'), msg = mount.querySelector('.lo-paste-msg');
      var text = (box && box.value) || '';
      if (!text.trim()) { if (msg) msg.textContent = 'Paste the script output first.'; return; }
      var r = OBOL.arsenal.ingestInventory(text);
      if (!r.ok) { if (msg) { msg.textContent = r.reason; msg.className = 'lo-paste-msg err'; } return; }
      U.toast('Loadout stocked — ' + r.present + ' tools, ' + r.staged + ' staged');
      OBOL.router.render();  // flip to the synced face
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.loadout = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
