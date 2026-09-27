/*!
 * obol ui — routes/evidence.js — paste tool output, mint facts, recompute the coach.
 * Uses OBOL.parsers (ported obol-local parsers) when available; the paste is analyzed and
 * facts are added conservatively (parsers never invent facts). A manual fact composer is the
 * always-available fallback. When arrived via a coach "Paste result" jump, the pinned action
 * is shown as context and its command primes the parser dispatcher.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function pinnedAction(ctx) {
    var id = (ctx.args && ctx.args[0]) || null;
    if (!id) { try { id = sessionStorage.getItem('obol-pasteback-action'); } catch (e) {} }
    if (!id) return null;
    return OBOL.packs.actions().find(function (a) { return a.id === id; }) || null;
  }

  // Point the attach hint at the engagement's scans/ directory when a workspace is set.
  function fileHintPath() {
    try {
      var eng = OBOL.store.active();
      if (OBOL.workspace && OBOL.workspace.isConfigured(eng)) {
        return ' from <code>' + esc(OBOL.workspace.tokens(eng).scandir) + '/</code>';
      }
    } catch (e) {}
    return ' (redirect it there with <code>… | tee out.txt</code>)';
  }

  // Whole-session import — the "catch me up on the entire box" panel. Paste a full terminal capture (or
  // attach several), obol splits it into per-command segments, stitches them chronologically, and runs
  // each through the same parsers. Collapsed by default so the single-command flow above stays primary.
  function importSection() {
    var ws = OBOL.workspace || {};
    var eng = OBOL.store.active();
    var iface = (eng && eng.params && eng.params.lhost_iface) || '';
    var stamp = ws.promptStamp ? ws.promptStamp(iface) : (ws.PROMPT_STAMP_ZSH || '');
    var capture = ws.captureCmd ? ws.captureCmd(eng) : 'script -q -f session.log';
    var targets = (eng && eng.targets) || [];
    var tOpts = '<option value="auto">Auto-route by IP (recommended)</option>'
      + targets.map(function (t) {
        var ip = t.ip || t.hostname; if (!ip) return '';
        return '<option value="' + U.attr(ip) + '">' + esc(ip) + (t.hostname && t.ip ? (' · ' + t.hostname) : '') + '</option>';
      }).join('');
    return '<details class="ev-import"><summary>Import a Full Session <span class="ev-import-tag">catch up on the whole box</span></summary>'
      + '<p class="ev-hint">Already deep into a box? Paste (or attach) your <strong>entire terminal</strong> from this run — every command and its output. obol splits it into per-command segments, orders them by time, skips duplicates, and mints facts from all of them at once, so the coach jumps straight to your real frontier.</p>'
      + '<textarea id="ev-imp-text" class="ev-textarea" placeholder="Paste your whole session — many commands and all their output. obol finds each command by its prompt line." spellcheck="false"></textarea>'
      + '<label class="ev-imp-route"><span>Route facts to</span><select id="ev-imp-target" class="ev-cmd">' + tOpts + '</select></label>'
      + '<div class="ev-hint ev-imp-route-hint">Auto-route reads the target IP from each command (<code>nxc smb 10.0.0.5</code>, <code>--host 10.0.0.5</code>…) and files its facts under that host — your VPN/<code>tun0</code> address is never treated as a target. New hosts you touch are added automatically. Pick a specific target to force everything onto one host.</div>'
      + '<details class="ev-imp-remap"><summary>Box got reverted? Remap an old IP</summary>'
      + '<div class="ev-imp-remap-row"><input id="ev-imp-oldip" class="ev-cmd" placeholder="old IP in your capture (e.g. 10.129.95.9)" autocomplete="off" spellcheck="false" inputmode="decimal">'
      + '<span class="ev-imp-arrow">→</span>'
      + '<input id="ev-imp-newip" class="ev-cmd" placeholder="' + esc((eng && eng.params && eng.params.target) || 'current target IP') + '" value="' + U.attr((eng && eng.params && eng.params.target) || '') + '" autocomplete="off" spellcheck="false" inputmode="decimal"></div>'
      + '<div class="ev-hint">If the lab reset and the target IP changed, obol rewrites the old IP to the new one across the whole capture before parsing — so you don\'t have to hand-edit your log. New IP defaults to your current target.</div>'
      + '</details>'
      + '<div class="ev-row">'
      + '<label class="ev-filebtn" for="ev-imp-file">⭱ Attach Session File(s)…</label>'
      + '<input type="file" id="ev-imp-file" class="ev-file" accept=".txt,.log,.out,text/plain" multiple hidden>'
      + '<button id="ev-imp-go" class="btn-primary">Import Session</button>'
      + '</div>'
      + '<div id="ev-imp-result" class="ev-result"></div>'
      + '<details class="ev-import-setup"><summary>Set your terminal up like this (recommended, one-time)</summary>'
      + '<p class="ev-hint">These are optional, but they make imports far more accurate — obol reads a UTC timestamp to stitch tabs in order, and your VPN IP to auto-fill <code>{{lhost}}</code> for coercion/relay/reverse-shell commands.</p>'
      + '<div class="ev-setup-step"><div class="ev-setup-lbl">1 · Stamp every prompt with the time + VPN IP <span class="ev-import-tag">non-destructive — keeps your prompt</span></div>'
      + '<pre class="cmd-run"><code id="ev-stamp-code">' + esc(stamp) + '</code></pre>'
      + '<button class="ev-copy" data-copy="ev-stamp-code">Copy zsh Snippet</button>'
      + '<span class="ev-file-hint">Append to <code>~/.zshrc</code> and run <code>source ~/.zshrc</code>. Appends a hook — it composes with oh-my-zsh / powerlevel10k and leaves your existing prompt alone.</span></div>'
      + '<div class="ev-setup-step"><div class="ev-setup-lbl">2 · Record a whole session to a file (optional)</div>'
      + '<pre class="cmd-run"><code id="ev-capture-code">' + esc(capture) + '</code></pre>'
      + '<button class="ev-copy" data-copy="ev-capture-code">Copy Capture Command</button>'
      + '<span class="ev-file-hint"><code>script</code> logs everything you run and its output. When you\'re done, <kbd>Ctrl-D</kbd> to stop, then attach the <code>.log</code> above. Works with or without the prompt tweak — timestamps just come out cleaner with it.</span></div>'
      + '</details>'
      + '</details>';
  }

  function shotsSection() {
    var eng = OBOL.store.active();
    var shots = (eng && eng.screenshots) || [];
    var grid = shots.length ? shots.map(function (s) {
      return '<figure class="ev-shot"><img src="' + U.attr(s.data_uri) + '" alt="' + U.attr(s.caption || 'proof') + '">'
        + '<figcaption>' + esc(s.caption || '(no caption)') + (s.slot ? ' · <span class="pill">' + esc(s.slot) + '</span>' : '')
        + '<button class="ev-shot-del" data-shot="' + esc(s.id) + '" title="Remove">×</button></figcaption></figure>';
    }).join('') : '<div class="ev-hint">No screenshots yet.</div>';
    return '<div class="ev-shots"><h2 class="coach-sec-h">Proof screenshots</h2>'
      + '<p class="ev-hint">Attach PNGs (for OSCP: the flag <em>and</em> a host-identity command like <code>ip a</code>/<code>hostname</code> in one frame). They embed into your exported report.</p>'
      + '<div class="ev-row"><input type="file" id="ss-file" accept="image/*" multiple>'
      + '<input id="ss-cap" class="ev-cmd" placeholder="caption (e.g. proof.txt on 10.10.10.10)">'
      + '<select id="ss-slot" class="ev-cmd"><option value="">slot…</option><option value="local">local</option><option value="root">root</option><option value="other">other</option></select></div>'
      + '<div class="ev-shot-grid">' + grid + '</div></div>';
  }

  function render(ctx) {
    var pin = pinnedAction(ctx);
    var parsersReady = !!(OBOL.parsers && OBOL.parsers.parseActionOutput);
    var pinBlock = '';
    if (pin) {
      var facts = OBOL.store.factSet();
      var v = OBOL.command.fillCommand(pin, facts, { params: (OBOL.store.active().params || {}), workspace: OBOL.workspace.tokens(OBOL.store.active()) }, 0);
      pinBlock = '<div class="ev-pin"><div class="ev-pin-h">Paste result for</div>'
        + '<div class="ev-pin-title">' + esc(pin.title) + '</div>'
        + '<pre class="cmd-run"><code>' + esc(v.filled) + '</code></pre>'
        + '<div class="ev-pin-dnp">' + (pin.does_not_prove ? ('Remember: does not prove ' + esc(pin.does_not_prove)) : '') + '</div></div>';
    }
    return '<section class="evidence">'
      + '<h1 class="route-h1">Evidence</h1>'
      + '<p class="route-sub">Paste your <strong>whole terminal</strong> — the command you ran <em>and</em> its full output. Conservative parsers mint only proven facts (nothing is inferred that the output doesn\'t show), the coach recomputes, and the raw command+output is kept as verbatim evidence for your report.</p>'
      + pinBlock
      + '<div class="ev-paste">'
      + '<textarea id="ev-text" class="ev-textarea" placeholder="Select your whole terminal and paste it here — prompt, command, and all output. e.g.&#10;&#10;$ nmap -sC -sV -oN nmap/full 10.10.10.10&#10;Starting Nmap 7.94 ...&#10;PORT     STATE SERVICE&#10;53/tcp   open  domain&#10;88/tcp   open  kerberos-sec&#10;389/tcp  open  ldap&#10;..." spellcheck="false"></textarea>'
      + '<div class="ev-row">'
      + '<input id="ev-cmd" class="ev-cmd" placeholder="command (auto-detected from your paste — only set this if the paste is output-only)" value="' + (pin ? U.attr(pin.command) : '') + '">'
      + '<button id="ev-parse" class="btn-primary"' + (parsersReady ? '' : ' disabled') + '>' + (parsersReady ? 'Parse → Facts' : 'Loading parsers…') + '</button>'
      + '</div>'
      // Attach an output file for firehose tools too big to paste (bloodyAD, full ldapsearch,
      // wide nxc/gobuster sweeps). Read locally, parsed the same way, stored capped. Nothing uploaded.
      + '<div class="ev-row ev-file-row">'
      + '<label class="ev-filebtn" for="ev-file">⭱ Attach Output File…</label>'
      + '<input type="file" id="ev-file" class="ev-file" accept=".txt,.log,.out,.json,.ldif,.csv,.tsv,text/plain" hidden>'
      + '<span class="ev-file-hint">Too big to paste? Attach the tool\'s output file' + fileHintPath() + ' — parsed on your machine, only a sample is kept. Set the command above if the file is output-only.</span>'
      + '</div>'
      + '<div class="ev-hint ev-paste-hint">Tip: paste the full output even if it looks noisy — the parser ignores what it doesn\'t recognize, and the extra context makes your report\'s evidence blocks complete.</div>'
      + '<div id="ev-result" class="ev-result"></div>'
      + '</div>'
      + importSection()
      + shotsSection()
      + '<details class="ev-manual"><summary>Add a fact manually</summary>'
      + '<p class="ev-hint">Pick what you\'ve confirmed and the coach advances — use this when you did something obol\'s parsers can\'t read (a manual exploit, an unsupported tool).</p>'
      + '<div id="ev-factpick" class="fact-pick"></div>'
      + '</details>'
      + '</section>';
  }

  // Ingest via the shared core (OBOL.ingest), then render the Evidence route's result panel.
  function ingest(text, cmd, meta) {
    meta = meta || {};
    var r = OBOL.ingest.run({ text: text, command: cmd, source: meta.source, fileName: meta.fileName });
    if (!r.ok) {
      if (r.reason === 'empty') U.toast('Nothing to parse — the ' + (meta.fileName ? 'file' : 'paste') + ' is empty');
      else U.toast('Parsers not loaded yet');
      return;
    }
    var origin = r.fileName ? (esc(r.fileName) + ' · ' + r.lines.toLocaleString() + ' lines') : null;
    var resEl = document.getElementById('ev-result');
    if (resEl) {
      if (!r.facts.length) {
        resEl.innerHTML = '<div class="ev-none">' + (origin ? ('Read ' + origin + ' — no ') : 'No ')
          + 'facts recognized (output saved; nothing invented). '
          + (r.parseError ? 'The parser skipped part of this output (see the browser console). ' : '')
          + 'Set the command above if the output is on its own, or add a fact manually.</div>';
      } else {
        resEl.innerHTML = '<div class="ev-added">Minted ' + r.added + ' new fact' + (r.added === 1 ? '' : 's') + ' (' + r.facts.length + ' recognized)'
          + (origin ? (' from ' + origin) : '') + ':</div>'
          + '<ul class="ev-factlist">' + r.facts.map(function (f) {
            return '<li class="' + esc(f.state) + '"><code>' + esc(f.kind) + '</code> <span class="ev-fscope">' + esc(f.scope) + '</span></li>';
          }).join('') + '</ul>'
          + '<a class="btn-primary" href="#/path">See Updated Coach →</a>';
      }
    }
    U.toast(r.added ? ('Minted ' + r.added + ' fact' + (r.added === 1 ? '' : 's') + (meta.fileName ? ' from file' : '')) : 'No new facts');
  }
  function runParse() {
    ingest((document.getElementById('ev-text') || {}).value || '',
      (document.getElementById('ev-cmd') || {}).value || '', { source: 'paste' });
  }
  // Read an attached output file as text and ingest it (no upload — FileReader is local).
  var FILE_MAX = 25 * 1024 * 1024; // 25 MB guard: even huge AD dumps are well under this
  function ingestFile(file) {
    if (!file) return;
    if (!(OBOL.parsers && OBOL.parsers.parseActionOutput)) { U.toast('Parsers still loading — try again in a second'); return; }
    if (file.size > FILE_MAX) { U.toast('That file is over 25 MB — attach the relevant portion instead', 'err'); return; }
    var r = new FileReader();
    r.onload = function () {
      ingest(String(r.result || ''), (document.getElementById('ev-cmd') || {}).value || '', { source: 'file', fileName: file.name });
    };
    r.onerror = function () { U.toast('Could not read that file', 'err'); };
    r.readAsText(file);
  }

  // The coach's current top move, named for the post-import summary. Mirrors path.js's frontier
  // computation (retired 'done'/'empty' moves excluded, machine focus applied) so the summary points at
  // the same move the coach will show. Best-effort — returns '' if anything is unavailable.
  function topNextMove() {
    try {
      var eng = OBOL.store.active(), facts = OBOL.store.factSet(), pack = OBOL.packs.actions();
      var doneIds = {};
      function moveEverProduced(id) { return (eng.activities || []).some(function (a) { return a && a.action_id === id && (a.produced || []).length > 0; }); }
      Object.keys((eng && eng.checklist) || {}).forEach(function (k) {
        var st = eng.checklist[k];
        if (st === 'done' || (st === 'empty' && !moveEverProduced(k))) doneIds[k] = true;
      });
      var focus = (OBOL.profile && eng && eng.profile) ? OBOL.profile.machineFocus(eng.profile.machine_type) : [];
      var ranked = OBOL.pack.nextActions(facts, pack, { doneIds: doneIds, focusPrefixes: focus }) || [];
      var top = ranked.find(function (a) { return OBOL.phases.prematurity(a, facts) === 0; }) || ranked[0];
      return top ? top.title : '';
    } catch (e) { return ''; }
  }

  // Run the whole-session import: paste text + any attached files, all through OBOL.ingest.importSession.
  function runImport() {
    var resEl = document.getElementById('ev-imp-result');
    var pasted = (document.getElementById('ev-imp-text') || {}).value || '';
    var inputs = window._obolImpFiles ? window._obolImpFiles.slice() : [];
    if (pasted.trim()) inputs.push(pasted);
    if (!inputs.length) { U.toast('Paste a session or attach a file first'); return; }
    if (!(OBOL.parsers && OBOL.parsers.parseActionOutput)) { U.toast('Parsers still loading — try again in a second'); return; }
    var routeTo = (document.getElementById('ev-imp-target') || {}).value || 'auto';
    var oldIp = ((document.getElementById('ev-imp-oldip') || {}).value || '').trim();
    var newIp = ((document.getElementById('ev-imp-newip') || {}).value || '').trim();
    var IPRE = /^(\d{1,3}\.){3}\d{1,3}$/;
    var remap = (oldIp && newIp && IPRE.test(oldIp) && IPRE.test(newIp) && oldIp !== newIp) ? [{ from: oldIp, to: newIp }] : null;
    if (oldIp && !remap) { U.toast('Remap needs two different valid IPs — ignoring it', 'err'); }
    var r = OBOL.ingest.importSession(inputs, { source: 'session', target: routeTo, remap: remap });
    if (!r || !r.ok) { U.toast('Could not import that session'); return; }
    var next = topNextMove();
    if (resEl) {
      resEl.innerHTML = '<div class="ev-added">Imported ' + r.imported + ' command' + (r.imported === 1 ? '' : 's')
        + ' → minted ' + r.added + ' new fact' + (r.added === 1 ? '' : 's')
        + (r.hosts && r.hosts.length > 1 ? (' across ' + r.hosts.length + ' hosts') : '')
        + (r.dupes ? (' · skipped ' + r.dupes + ' duplicate' + (r.dupes === 1 ? '' : 's')) : '')
        + (r.remapped ? (' · remapped ' + r.remapped + ' IP occurrence' + (r.remapped === 1 ? '' : 's')) : '') + '.'
        + (r.hosts && r.hosts.length ? ('<div class="ev-imp-tools">Hosts: ' + r.hosts.map(function (h) { return '<code>' + esc(h) + '</code>'; }).join(' ') + '</div>') : '')
        + (r.tools && r.tools.length ? ('<div class="ev-imp-tools">Tools seen: ' + r.tools.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(' ') + '</div>') : '')
        + (next ? ('<div class="ev-imp-next">Next move: <strong>' + esc(next) + '</strong></div>') : '')
        + '</div><a class="btn-primary" href="#/path">See Updated Coach →</a>';
    }
    U.toast(r.added ? ('Imported ' + r.imported + ' commands · ' + r.added + ' new facts') : ('Imported ' + r.imported + ' commands · no new facts'));
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    window._obolImpFiles = [];
    // Lazy-load parsers if not present, then enable the button.
    if (!(OBOL.parsers && OBOL.parsers.parseActionOutput) && OBOL.lazy) {
      OBOL.lazy.loadGroup('parsers').then(function () {
        var b = document.getElementById('ev-parse');
        if (b) { b.disabled = false; b.textContent = 'Parse → Facts'; }
      }).catch(function () {});
    }
    var parseBtn = document.getElementById('ev-parse');
    if (parseBtn) parseBtn.addEventListener('click', function () { runParse(); });
    // attach output file → read locally + ingest through the same pipeline
    var fileEl = document.getElementById('ev-file');
    if (fileEl) fileEl.addEventListener('change', function () {
      var f = fileEl.files && fileEl.files[0];
      ingestFile(f);
      fileEl.value = ''; // allow re-attaching the same file
    });
    // ── whole-session import ──────────────────────────────────────────────────────────────────────
    var impFileEl = document.getElementById('ev-imp-file');
    if (impFileEl) impFileEl.addEventListener('change', function () {
      var files = Array.prototype.slice.call(impFileEl.files || []);
      if (!files.length) return;
      var over = files.filter(function (f) { return f.size > FILE_MAX; });
      if (over.length) { U.toast('Skipping ' + over.length + ' file(s) over 25 MB — attach the relevant portion', 'err'); }
      files = files.filter(function (f) { return f.size <= FILE_MAX; });
      var pending = files.length, names = [];
      if (!pending) { impFileEl.value = ''; return; }
      files.forEach(function (f) {
        var r = new FileReader();
        r.onload = function () { window._obolImpFiles.push(String(r.result || '')); names.push(f.name); if (--pending === 0) done(); };
        r.onerror = function () { if (--pending === 0) done(); };
        r.readAsText(f);
      });
      function done() {
        var el = document.getElementById('ev-imp-result');
        if (el) el.innerHTML = '<div class="ev-hint">Attached ' + window._obolImpFiles.length + ' file(s): ' + names.map(esc).join(', ') + '. Add a paste too if you like, then <strong>Import Session</strong>.</div>';
        impFileEl.value = '';
      }
    });
    var impGo = document.getElementById('ev-imp-go');
    if (impGo) impGo.addEventListener('click', function () { runImport(); });
    U.on(mount, 'click', '.ev-copy', function (e, t) {
      var el = document.getElementById(t.getAttribute('data-copy'));
      if (!el) return;
      U.copy(el.textContent).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    // screenshots: attach (readAsDataURL, stored inline for report embedding) + remove
    var ssFile = document.getElementById('ss-file');
    if (ssFile) ssFile.addEventListener('change', function () {
      var cap = (document.getElementById('ss-cap') || {}).value || '';
      var slot = (document.getElementById('ss-slot') || {}).value || '';
      var tgt = (OBOL.store.active().params || {}).target || '';
      var files = Array.prototype.slice.call(ssFile.files || []);
      var pending = files.length;
      if (!pending) return;
      files.forEach(function (f) {
        var r = new FileReader();
        r.onload = function () {
          OBOL.store.update(function (eng) {
            eng.screenshots = eng.screenshots || [];
            eng.screenshots.push({ id: 'ss-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), data_uri: r.result, caption: cap, slot: slot, target: tgt, at: Date.now() });
          }, 'screenshots');
          if (--pending === 0) { U.toast('Screenshot(s) attached'); OBOL.router.render(); }
        };
        r.onerror = function () { if (--pending === 0) OBOL.router.render(); };
        r.readAsDataURL(f);
      });
    });
    U.on(mount, 'click', '.ev-shot-del', function (e, t) {
      var id = t.getAttribute('data-shot');
      OBOL.store.update(function (eng) { eng.screenshots = (eng.screenshots || []).filter(function (s) { return s.id !== id; }); }, 'screenshots');
      OBOL.router.render();
    });

    var fpEl = document.getElementById('ev-factpick');
    if (fpEl && OBOL.factpick) OBOL.factpick.mount(fpEl, function (kind) {
      var scope = 'host:' + ((OBOL.store.active().params || {}).target || 'target');
      OBOL.store.addFacts([OBOL.facts.makeFact({ kind: kind, scope: scope, source: 'manual' })], 'facts');
      OBOL.app.renderSidebar();
      U.toast('Fact added: ' + kind);
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.evidence = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
