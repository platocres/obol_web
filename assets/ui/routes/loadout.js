/*!
 * obol ui — routes/loadout.js — THE LOADOUT (step zero: set up your attack box).
 * Leftmost tab, GLOBAL (per-browser), not per-engagement — it describes the operator's Kali box.
 * Two faces from one route:
 *   - no machine profile yet → a guided quickstart (download the script, run it, paste the result back)
 *   - profile present         → "Your Box": a map of where everything lives, plus the live Arsenal state
 * The Arsenal is collapsed into per-category rows with at-a-glance summaries so the page stays short.
 * Never a gate: skip it and every command still works canonical. The browser only GENERATES a setup
 * script and READS the pasted-back inventory — it never fetches or executes anything.
 * (Workspace is per-engagement and lives on the Engagements screen, not here.)
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function titleCase(s) { return String(s || '').replace(/\w\S*/g, function (w) { return w.charAt(0).toUpperCase() + w.slice(1); }); }

  var _hideKali = true;   // "to fetch" view by default — the tools Kali doesn't already ship

  // Prompt-stamp opt-in (persisted). Default ON but always shown + explained before download, so the
  // shell change is never a surprise — the operator sees exactly what it does and can untick it.
  var STAMP_KEY = 'obol.arsenal-promptstamp';
  function stampOn() { try { return localStorage.getItem(STAMP_KEY) !== '0'; } catch (e) { return true; } }
  function stampSet(on) { try { localStorage.setItem(STAMP_KEY, on ? '1' : '0'); } catch (e) {} }

  var CLASS_LABEL = {
    kali: 'on Kali', builtin: 'built-in', apt: 'apt', pipx: 'pipx', git: 'git', go: 'go',
    material: 'fetched', 'stage-lin': 'staged', 'stage-win': 'staged → www/',
  };
  // category display order (most-reached-for first); unknown categories fall to the end.
  var CAT_ORDER = ['AD', 'Credentials', 'Recon', 'Web', 'Windows enum', 'Windows privesc',
    'Linux enum', 'Linux privesc', 'Lateral', 'Cracking', 'Tunnel', 'MITM', 'Database',
    'Exploitation', 'Support', 'Built-in'];

  function classBadge(e) {
    return '<span class="lo-badge' + (e.on_kali ? ' lo-badge-ok' : '') + '">' + esc(CLASS_LABEL[e.class] || e.class) + '</span>';
  }
  function needsFetch(e) { return !(e.class === 'kali' || e.class === 'builtin'); }
  function isPresent(e, prof) {
    if (!prof) return false;
    var t = (prof.tools || {})[e.key];
    if (t && t.present) return true;
    return (prof.staged || []).indexOf(e.dest || '') >= 0 || !!((prof.digests || {})[e.key]);
  }
  function toolState(e, prof) {
    if (!prof) return '';
    if (isPresent(e, prof)) {
      var t = (prof.tools || {})[e.key];
      var inv = t && t.invocation && t.invocation !== e.canonical ? ' as <code>' + esc(t.invocation) + '</code>' : '';
      return '<span class="lo-state lo-have">✓ ready' + inv + '</span>';
    }
    if (needsFetch(e)) return '<span class="lo-state lo-todo">run the script</span>';
    return '<span class="lo-state lo-miss">not found</span>';
  }

  function toolCard(e, prof) {
    var recipe = e.install
      ? '<div class="lo-recipe"><code>' + esc(e.install) + '</code><button class="btn-copy" data-copy="' + U.attr(e.install) + '">Copy</button></div>'
      : needsFetch(e) ? '<div class="lo-recipe lo-fetch">Fetched &amp; staged by the setup script.</div>' : '';
    var av = e.av_note ? '<div class="lo-av">⚠ ' + esc(e.av_note) + '</div>' : '';
    var prov = e.source ? '<div class="lo-tool-foot"><span class="lo-src">' + esc(e.source) + (e.license ? ' · ' + esc(e.license) : '') + '</span></div>' : '';
    return '<article class="lo-tool">'
      + '<div class="lo-tool-h"><span class="lo-tool-name">' + esc(e.label || e.key) + '</span>' + classBadge(e) + toolState(e, prof) + '</div>'
      + (e.purpose ? '<div class="lo-tool-why">' + esc(e.purpose) + '</div>' : '')
      + recipe + av + prov + '</article>';
  }

  // group arsenal entries by category, de-duped
  function byCategory() {
    var A = OBOL.ARSENAL || {}, seen = {}, cats = {};
    Object.keys(A).sort().forEach(function (k) {
      var e = A[k]; if (!e || seen[e.key]) return; seen[e.key] = 1;
      (cats[e.category || 'Support'] = cats[e.category || 'Support'] || []).push(e);
    });
    return cats;
  }
  function catOrder(cats) {
    var keys = Object.keys(cats);
    keys.sort(function (a, b) {
      var ia = CAT_ORDER.indexOf(a), ib = CAT_ORDER.indexOf(b);
      if (ia < 0) ia = 99; if (ib < 0) ib = 99;
      return ia - ib || (a < b ? -1 : 1);
    });
    return keys;
  }

  function arsenalSection(prof) {
    var cats = byCategory(), keys = catOrder(cats);
    var head = '<div class="lo-sec-head"><h2 class="lo-h2">Arsenal</h2>'
      + '<div class="lo-sec-tools"><span class="lo-find" title="Press ⌘K / Ctrl-K">⌘K to find a tool</span>'
      + '<label class="lo-toggle"><input type="checkbox" id="lo-hidekali"' + (_hideKali ? ' checked' : '') + '> Hide tools Kali ships</label></div></div>';
    var rows = keys.map(function (cat) {
      var list = cats[cat];
      var shown = _hideKali ? list.filter(needsFetch) : list;
      var fetchN = list.filter(needsFetch).length;
      var haveN = prof ? list.filter(function (e) { return isPresent(e, prof); }).length : 0;
      var kaliN = list.length - fetchN;
      // a category with nothing to fetch, in "hide Kali" mode → a thin satisfied row, not an expander
      if (_hideKali && !shown.length) {
        return '<div class="lo-cat lo-cat-flat"><span class="lo-cat-name">' + esc(titleCase(cat)) + '</span>'
          + '<span class="lo-cat-sum">' + list.length + ' ship with Kali ✓</span></div>';
      }
      var summary = [];
      if (prof) summary.push(haveN + ' ready');
      summary.push(fetchN + ' to fetch');
      if (!_hideKali && kaliN) summary.push(kaliN + ' on Kali');
      return '<details class="lo-cat"><summary class="lo-cat-h"><span class="lo-cat-name">' + esc(titleCase(cat)) + '</span>'
        + '<span class="lo-cat-sum">' + summary.join(' · ') + '</span></summary>'
        + '<div class="lo-grid">' + shown.map(function (e) { return toolCard(e, prof); }).join('') + '</div></details>';
    }).join('');
    return '<div class="lo-block">' + head + rows + '</div>';
  }

  // "Your Box": a compact map of where the arsenal lives on the host (synced face only).
  function hostMap(prof) {
    var A = OBOL.ARSENAL || {};
    var cache = Object.keys(prof.digests || {});
    var winCache = cache.filter(function (k) { return A[k] && (A[k].class === 'stage-win'); });
    var linCache = cache.filter(function (k) { return A[k] && (A[k].class === 'material' || A[k].class === 'stage-lin'); });
    var staged = prof.staged || [];
    var wl = prof.wordlists || {};
    var tools = prof.tools || {};
    var present = Object.keys(tools).filter(function (k) { return tools[k] && tools[k].present; });
    // pipx tools live on ~/.local/bin; git run-from-repo tools live in ~/tools (reported via `cloned`, or
    // inferred by class for older profiles). Kali-default tools live on the system PATH — the hero's
    // "ready" count already covers those, so the map shows only what the script actually PUT on the box.
    var pipx = present.filter(function (k) { return A[k] && A[k].class === 'pipx'; });
    var cloned = Object.keys(prof.cloned || {});
    if (!cloned.length) cloned = present.filter(function (k) { return A[k] && A[k].class === 'git'; });
    function chips(arr, n) {
      var head = arr.slice(0, n || 6).map(function (x) { return '<span class="lo-chip">' + esc(x) + '</span>'; }).join('');
      return head + (arr.length > (n || 6) ? '<span class="lo-chip lo-chip-more">+' + (arr.length - (n || 6)) + '</span>' : '');
    }
    function node(path, arr) {
      if (!arr.length) return '';
      return '<div class="lo-fs-row"><code class="lo-fs-path">' + esc(path) + '</code>'
        + '<span class="lo-fs-n">' + arr.length + '</span><div class="lo-fs-chips">' + chips(arr) + '</div></div>';
    }
    var rows = node('~/.obol/arsenal/win', staged.length ? staged : winCache)
      + node('~/.obol/arsenal', linCache)
      + node('~/.local/bin', pipx)
      + node('~/tools', cloned)
      + node('/usr/share/wordlists', Object.keys(wl));
    return '<div class="lo-block"><div class="lo-sec-head"><h2 class="lo-h2">Your Box</h2>'
      + '<span class="lo-synced-chip"><span class="lo-synced-dot"></span> synced ' + esc(timeAgo(prof.savedAt)) + '</span></div>'
      + '<div class="lo-fs">' + (rows || '<div class="lo-fs-empty">Nothing staged yet — run the setup script.</div>') + '</div></div>';
  }

  function quickstart(prof) {
    var synced = !!prof;
    var steps = '<ol class="lo-steps">'
      + '<li><span class="lo-step-n">1</span><div><div class="lo-step-t">Download The Setup Script</div>'
      + '<div class="lo-step-sub">One file. Fetches every tool obol uses that Kali doesn\'t ship and stages the Windows binaries — a fresh box to ready in one run.</div>'
      + '<label class="lo-optin"><input type="checkbox" class="lo-stamp-opt"' + (stampOn() ? ' checked' : '') + '> Also format my terminal prompt <span class="lo-optin-rec">recommended</span></label>'
      + '<div class="lo-optin-why">Prepends a dim <code>[UTC time · tun0 IP]</code> line before each prompt — <strong>your prompt itself is untouched</strong>. obol reads it to stitch a pasted whole-session into a correct timeline and auto-fill your VPN IP (<code>{{lhost}}</code>). It\'s additive and reversible (one block in <code>~/.zshrc</code>); untick to skip — everything else works the same.</div>'
      + '<button class="btn-primary lo-download">Download download-arsenal.sh</button></div></li>'
      + '<li><span class="lo-step-n">2</span><div><div class="lo-step-t">Run It On Your Kali Box</div>'
      + '<div class="lo-step-sub">Run it as your normal user (not <code>sudo</code>). This assumes it landed in <code>~/Downloads</code> — adjust the path if you saved it elsewhere. Safe to re-run; it only does the missing work.</div>'
      + '<div class="lo-recipe"><code>cd ~/Downloads &amp;&amp; chmod +x download-arsenal.sh &amp;&amp; ./download-arsenal.sh</code><button class="btn-copy" data-copy="cd ~/Downloads &amp;&amp; chmod +x download-arsenal.sh &amp;&amp; ./download-arsenal.sh">Copy</button></div></div></li>'
      + '<li><span class="lo-step-n">3</span><div><div class="lo-step-t">Paste The Result Back</div>'
      + '<div class="lo-step-sub">The script ends by printing an <code>OBOL-ARSENAL</code> block — paste the whole thing here and obol learns your box.</div>'
      + '<textarea class="lo-paste" placeholder="Paste the OBOL-ARSENAL block (or the whole script output) here…" spellcheck="false"></textarea>'
      + '<div class="lo-paste-row"><button class="btn-primary lo-ingest">Stock My Loadout</button><span class="lo-paste-msg" role="status"></span></div></div></li>'
      + '</ol>';
    if (!synced) {
      return '<div class="lo-block"><h2 class="lo-h2">Set Up — One Time, ~2 Minutes</h2>' + steps + '</div>';
    }
    return '<details class="lo-block lo-setup-done"><summary class="lo-h2 lo-setup-sum">Set Up Again / On Another Box</summary>' + steps + '</details>';
  }

  function countSummary(prof) {
    var present = 0; Object.keys(prof.tools || {}).forEach(function (k) { if (prof.tools[k] && prof.tools[k].present) present++; });
    return present;
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
    var A = OBOL.ARSENAL || {}, total = 0, seen = {};
    Object.keys(A).forEach(function (k) { if (A[k] && !seen[A[k].key]) { seen[A[k].key] = 1; total++; } });
    var html = '<section class="coach lo-route">'
      + '<div class="coach-hero"><div class="coach-hero-main">'
      + '<div class="coach-kicker">Step Zero · <strong>Your Attack Box</strong></div>'
      + '<h1 class="coach-h1">Loadout</h1>'
      + '<p class="coach-sub">' + (prof
          ? 'obol knows your box and tailors every command to the tools you actually have.'
          : 'Set up your Kali box once — obol generates the script, you run it, paste the result back. Optional: skip it and every command still works.')
      + '</p></div>'
      + '<div class="coach-metrics"><div class="metric"><span class="metric-n">' + total + '</span><span class="metric-l">Tools Obol Uses</span></div>'
      + (prof ? '<div class="metric"><span class="metric-n">' + countSummary(prof) + '</span><span class="metric-l">Ready On Your Box</span></div>' : '')
      + '</div></div>';
    if (!prof) html += '<p class="lo-skip">New here? Do this first — or <a href="#/home">skip to Engagements →</a>. Nothing here blocks you.</p>';
    html += quickstart(prof);
    if (prof) html += hostMap(prof);
    html += arsenalSection(prof);
    return html + '</section>';
  }

  function doDownload(mount) {
    if (!OBOL.arsenal || !OBOL.arsenal.buildScript) { U.toast('Arsenal module still loading — try again', 'err'); return; }
    var cb = mount && mount.querySelector('.lo-stamp-opt');
    var promptStamp = cb ? !!cb.checked : stampOn();
    var blob = new Blob([OBOL.arsenal.buildScript({ promptStamp: promptStamp })], { type: 'text/x-shellscript' });
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
    U.on(mount, 'click', '.lo-download', function () { doDownload(mount); });
    U.on(mount, 'change', '.lo-stamp-opt', function (e, t) { stampSet(!!t.checked); });
    U.on(mount, 'change', '#lo-hidekali', function (e, t) { _hideKali = !!t.checked; OBOL.router.render(); });
    U.on(mount, 'click', '.lo-ingest', function (e, t) {
      var box = mount.querySelector('.lo-paste'), msg = mount.querySelector('.lo-paste-msg');
      var text = (box && box.value) || '';
      if (!text.trim()) { if (msg) msg.textContent = 'Paste the script output first.'; return; }
      var r = OBOL.arsenal.ingestInventory(text);
      if (!r.ok) { if (msg) { msg.textContent = r.reason; msg.className = 'lo-paste-msg err'; } return; }
      U.toast('Loadout stocked — ' + r.present + ' tools, ' + r.staged + ' staged');
      OBOL.router.render();
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.loadout = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
