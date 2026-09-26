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

  function mounted(ctx) {
    var mount = ctx.mount;
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
