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
  function cap1(s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); }
  // category → CSS color-class slug (lo-catc-<slug>); the colors live in obol.css so they follow the skin.
  function catSlug(c) { return String(c || 'support').toLowerCase().replace(/[^a-z0-9]+/g, '-'); }

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
    if (e.manual) return '<span class="lo-state lo-todo">manual fetch</span>';
    if (needsFetch(e)) return '<span class="lo-state lo-todo">run the script</span>';
    return '<span class="lo-state lo-miss">not found</span>';
  }

  function toolCard(e, prof) {
    var recipe = e.manual
      ? '<div class="lo-recipe lo-fetch">No published release — grab it from <a href="' + U.attr(e.manual_url || '#') + '" target="_blank" rel="noopener">' + esc(e.source || 'upstream') + ' ↗</a> and drop it in <code>~/.obol/arsenal/win</code>.</div>'
      : e.install
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

  // Reconcile the pasted-back inventory against what obol EXPECTS: this is the operator's self-check that
  // "everything I think I installed actually installed, and everything I think ships with Kali is really here".
  // Buckets (de-duped, builtins excluded — shell/coreutils are never probed):
  //   ready         present (on PATH, cloned, or staged+digested)
  //   alt           present but under a non-canonical name (informational — command-rewrite handles it)
  //   fetchMissing  the script fetches/installs it, but it's not on the box (install didn't run or failed)
  //   manualMissing no published artifact to auto-fetch — needs a manual grab
  //   kaliMissing   obol assumed Kali ships it, but a default install didn't (metapackage gap / misflag)
  function reconcile(prof) {
    var A = OBOL.ARSENAL || {}, seen = {};
    var miss = (prof && prof.missing) || {};   // what the last script run TRIED to install but couldn't (key -> source hint)
    var r = { ready: [], alt: [], fetchMissing: [], installFailed: [], manualMissing: [], kaliMissing: [] };
    Object.keys(A).forEach(function (k) {
      var e = A[k]; if (!e || seen[e.key]) return; seen[e.key] = 1;
      if (e.class === 'builtin') { r.ready.push(e); return; }   // shell/coreutils/target-side commands — always available
      if (isPresent(e, prof)) {
        r.ready.push(e);
        var t = (prof.tools || {})[e.key];
        if (t && t.present && t.invocation && t.invocation !== e.canonical) r.alt.push(e);
        return;
      }
      if (e.manual) r.manualMissing.push(e);
      else if (needsFetch(e)) {
        if (Object.prototype.hasOwnProperty.call(miss, e.key)) r.installFailed.push(e);  // script tried, couldn't
        else r.fetchMissing.push(e);                                                      // not attempted yet — run the script
      }
      else if (e.os !== 'windows') r.kaliMissing.push(e);   // a Windows command absent from Kali is expected, not a gap
    });
    return r;
  }

  function reconList(arr, mode, prof) {
    return '<ul class="lo-recon-list">' + arr.slice().sort(function (a, b) {
      return (a.label || a.key) < (b.label || b.key) ? -1 : 1;
    }).map(function (e) {
      var extra = '';
      if (mode === 'manual' && e.manual_url) extra = ' — <a href="' + U.attr(e.manual_url) + '" target="_blank" rel="noopener">get it ↗</a>';
      else if (mode === 'install' && e.install) extra = ' — <code>' + esc(e.install) + '</code>';
      else if (mode === 'failed') {
        var h = ((prof && prof.missing) || {})[e.key] || e.manual_url || (e.gh_repo ? 'https://github.com/' + e.gh_repo : '') || e.install || '';
        if (/^https?:\/\//.test(h)) extra = ' — <a href="' + U.attr(h) + '" target="_blank" rel="noopener">find it ↗</a>';
        else if (h) extra = ' — <code>' + esc(h) + '</code>';
      }
      else if (mode === 'alt') { var t = (prof.tools || {})[e.key] || {}; extra = ' — present as <code>' + esc(t.invocation || '') + '</code>'; }
      return '<li>' + esc(e.label || e.key) + extra + '</li>';
    }).join('') + '</ul>';
  }

  function reconBand(prof) {
    var r = reconcile(prof);
    function pill(arr, cls, label, note, body) {
      if (!arr.length) return '';
      return '<details class="lo-recon-d"><summary class="lo-recon-pill ' + cls + '">' + arr.length + ' ' + label + '</summary>'
        + '<div class="lo-recon-body">' + (note ? '<p class="lo-recon-note">' + note + '</p>' : '') + body + '</div></details>';
    }
    var band = '<span class="lo-recon-pill lo-rp-ok" title="Accounted for on your box">' + r.ready.length + ' ready</span>'
      + pill(r.installFailed, 'lo-rp-bad', 'couldn\'t install',
          'The setup script tried to install these and couldn\'t (no package, a 404, a failed build). Grab each from its source, drop it on your PATH (or in <code>~/.obol/arsenal</code>), and re-paste.',
          reconList(r.installFailed, 'failed', prof))
      + pill(r.fetchMissing, 'lo-rp-warn', 'to install',
          'obol\'s setup script fetches these — they\'re not on your box yet. Re-run Step 2 (<code>./download-arsenal.sh</code>) and paste back.',
          reconList(r.fetchMissing, 'install', prof))
      + pill(r.manualMissing, 'lo-rp-warn', 'manual',
          'No published release to auto-fetch — grab these by hand, then drop them in <code>~/.obol/arsenal/win</code>.',
          reconList(r.manualMissing, 'manual', prof))
      + pill(r.kaliMissing, 'lo-rp-bad', 'expected on Kali, missing',
          'obol assumed a Kali default install ships these, but yours didn\'t — likely a larger-metapackage tool (<code>apt install &lt;name&gt;</code>) or a flag to fix. Flag it to me if a core one shows here.',
          reconList(r.kaliMissing, 'plain', prof))
      + pill(r.alt, 'lo-rp-info', 'aliased',
          'Present under a different name than the canonical one — obol\'s command-rewrite already adapts to these.',
          reconList(r.alt, 'alt', prof));
    return '<div class="lo-recon">' + band + '</div>';
  }

  // "Your Box": a reconciliation band + a map of where the arsenal lives on the host (synced face only).
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
    // resolve a staged filename → its ARSENAL entry (via dest), so a chip knows its category + description.
    var byDest = {}; Object.keys(A).forEach(function (k) { var e = A[k]; if (e && e.dest && !byDest[e.dest]) byDest[e.dest] = e; });

    // hover card for a tool chip: name, colored category, what-it-is/for, invocation + where it lives.
    function card(e, inv, path) {
      if (!e) return '';
      var cat = e.category || 'Support';
      return '<span class="lo-ti-card" role="tooltip">'
        + '<span class="lo-ti-card-h"><span class="lo-ti-name">' + esc(e.label || e.key) + '</span>'
        + '<span class="lo-cat-badge lo-catc-' + catSlug(cat) + '">' + esc(titleCase(cat)) + '</span></span>'
        + ((e.desc || e.purpose) ? '<span class="lo-ti-why">' + esc(cap1(e.desc || e.purpose)) + '</span>' : '')
        + (e.example ? '<span class="lo-ti-eg"><span class="lo-ti-eg-l">Example</span><code>' + esc(e.example) + '</code></span>' : '')
        + '<span class="lo-ti-meta">' + (inv ? '<code class="lo-ti-inv">' + esc(inv) + '</code>' : '')
        + (path ? '<code class="lo-ti-path">' + esc(path) + '</code>' : '') + '</span></span>';
    }
    // a tool chip: a category-colored dot + name, with the hover card tucked inside (hover/focus reveals it).
    function chip(it) {
      var cat = it.e ? (it.e.category || 'Support') : '';
      return '<span class="lo-ti' + (it.e ? '' : ' lo-ti-plain') + '"' + (it.e ? ' tabindex="0"' : '') + '>'
        + '<span class="lo-ti-dot lo-catc-' + catSlug(cat) + '"></span>'
        + '<span class="lo-ti-label">' + esc(it.label) + '</span>'
        + card(it.e, it.inv, it.path) + '</span>';
    }
    // node: collapsed summary = path + count + the distinct category colors inside (no name echo). Open → chips.
    function node(path, items) {
      if (!items.length) return '';
      var seenCat = {};
      items.forEach(function (it) { if (it.e) seenCat[it.e.category || 'Support'] = 1; });
      var dots = Object.keys(seenCat).sort().map(function (c) {
        return '<span class="lo-nd-dot lo-catc-' + catSlug(c) + '" title="' + U.attr(titleCase(c)) + '"></span>';
      }).join('');
      var body = items.map(chip).join('');
      return '<details class="lo-fs-node"><summary class="lo-fs-row"><code class="lo-fs-path">' + esc(path) + '</code>'
        + '<span class="lo-fs-n">' + items.length + '</span><span class="lo-nd-dots">' + dots + '</span></summary>'
        + '<div class="lo-fs-items">' + body + '</div></details>';
    }
    function winItem(f) { var e = byDest[f]; return { label: f, e: e, inv: (e && e.canonical) || '', path: '~/.obol/arsenal/win/' + f }; }
    function keyItem(k, path) { var e = A[k]; return { label: (e && e.label) || k, e: e, inv: (tools[k] && tools[k].invocation) || (e && e.canonical) || k, path: path }; }
    var winNames = staged.length ? staged : winCache.map(function (k) { return (A[k] && A[k].dest) || k; });
    var rows = node('~/.obol/arsenal/win', winNames.map(winItem))
      + node('~/.obol/arsenal', linCache.map(function (k) { return keyItem(k, '~/.obol/arsenal/' + ((A[k] && A[k].dest) || k)); }))
      + node('~/.local/bin', pipx.map(function (k) { return keyItem(k, (tools[k] && tools[k].path) || ''); }))
      + node('~/tools', cloned.map(function (k) { return keyItem(k, (prof.cloned && prof.cloned[k]) || (tools[k] && tools[k].path) || ''); }))
      + node('/usr/share/wordlists', Object.keys(wl).map(function (n) { return { label: n, e: null, inv: '', path: wl[n] }; }));
    return '<div class="lo-block"><div class="lo-sec-head"><h2 class="lo-h2">Your Box</h2>'
      + '<span class="lo-synced-chip"><span class="lo-synced-dot"></span> synced ' + esc(timeAgo(prof.savedAt)) + '</span></div>'
      + reconBand(prof)
      + '<p class="lo-fs-cap">Where the script put things — expand a path, then hover a tool to see what it does.</p>'
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
      + '<div class="lo-step-sub">The script ends by printing a block fenced between two <code>✂</code> lines — select everything between them (including the <code>✂</code> lines is fine) and paste it here. obol learns your box.</div>'
      + '<textarea class="lo-paste" placeholder="Paste the OBOL-ARSENAL block (or the whole script output) here…" spellcheck="false"></textarea>'
      + '<div class="lo-paste-row"><button class="btn-primary lo-ingest">Stock My Loadout</button><span class="lo-paste-msg" role="status"></span></div></div></li>'
      + '</ol>';
    if (!synced) {
      return '<div class="lo-block"><h2 class="lo-h2">Set Up — One Time, ~2 Minutes</h2>' + steps + '</div>';
    }
    return '<details class="lo-block lo-setup-done"><summary class="lo-h2 lo-setup-sum">Set Up Again / On Another Box</summary>' + steps + '</details>';
  }

  // "Ready on your box" = how many of the tools obol uses are actually present — on PATH, cloned to ~/tools,
  // staged to serve, or cached as a material. Counts the same way the reconciliation band does (isPresent over
  // the registry) so the hero number and "Your Box" agree instead of showing two different "ready" totals.
  function countSummary(prof) {
    var A = OBOL.ARSENAL || {}, seen = {}, n = 0;
    Object.keys(A).forEach(function (k) {
      var e = A[k]; if (!e || seen[e.key]) return; seen[e.key] = 1;
      if (e.class === 'builtin' || isPresent(e, prof)) n++;   // builtins (shells/coreutils/target cmds) are always available
    });
    return n;
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
