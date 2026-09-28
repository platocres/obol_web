/*!
 * obol ui — routes/domain.js — BloodHound domain analysis, 100% client-side.
 * Upload a SharpHound zip (or BloodHound-CE JSONs) -> OBOL.bloodhound parses + derives the
 * high-value census + owned→DA attack paths + a self-contained printable report. Analysis runs
 * in a Web Worker when available (big zips stay off the main thread), else on the main thread.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function ownedFromEngagement() {
    var eng = OBOL.store.active();
    var owned = [];
    (eng.credentials || []).forEach(function (c) { if (c.user) owned.push(String(c.user).toUpperCase()); });
    if (eng.params && eng.params.username) owned.push(String(eng.params.username).toUpperCase());
    return owned.filter(function (v, i, a) { return v && a.indexOf(v) === i; });
  }

  // Fill the query-card commands from what this engagement already knows: the DC/target host, the
  // operator's listener IP, and (on-screen only) the owned account's secret. includeSecret is false
  // for the exportable report so hashes/passwords never land in a shareable document.
  function cmdCtx(owned, includeSecret) {
    var eng = OBOL.store.active() || {}, params = eng.params || {};
    var dc = null;
    try {
      var facts = OBOL.store.factSet();
      var dcf = (facts.values && facts.values('ad.dc_candidate')) || [];
      if (dcf[0] && dcf[0].host) dc = dcf[0].host;
      var ctxOut = { dc: dc || params.target || null, host: params.target || null, lhost: params.lhost || null, secret: null, pw: null, nt: null };
      if (includeSecret && owned && owned.length) {
        var firstUser = String(owned[0]).split('@')[0].toLowerCase();
        var creds = [];
        try { creds = (OBOL.creds && OBOL.creds.gather) ? OBOL.creds.gather(eng, facts) : (eng.credentials || []); }
        catch (e) { creds = eng.credentials || []; }
        var c = creds.filter(function (x) { return x && x.user && String(x.user).toLowerCase() === firstUser; })[0];
        if (c) {
          var h = c.nthash || c.hash, pw = c.password || c.plaintext || c.secret;
          // carry the RAW secret parts too, so per-tool auth syntax (evil-winrm -H, xfreerdp /pth,
          // impacket -hashes) is built correctly for a hash-only identity — not a blank -p ''.
          if (h && /^[a-fA-F0-9]{32}$/.test(String(h))) { ctxOut.secret = '-H ' + h; ctxOut.nt = h; }
          else if (pw) { ctxOut.secret = "-p '" + pw + "'"; ctxOut.pw = pw; }
        }
      }
      return ctxOut;
    } catch (e) { return { dc: params.target || null, host: params.target || null, lhost: params.lhost || null, secret: null }; }
  }

  function render() {
    var eng = OBOL.store.active();
    var summary = eng && eng.bloodhound;
    var html = '<section class="domain-route">'
      + '<h1 class="route-h1">Domain (BloodHound)</h1>'
      + '<p class="route-sub">Upload a SharpHound <code>.zip</code> (or BloodHound-CE <code>.json</code> files). Everything is parsed and analysed in your browser — nothing is uploaded anywhere.</p>'
      + '<div class="bh-drop" id="bh-drop" tabindex="0" role="button">Drop a SharpHound .zip here, or click to choose files'
      + '<input type="file" id="bh-file" accept=".zip,.json" multiple hidden></div>'
      + '<div id="bh-status" class="route-sub"></div>';

    if (summary) {
      var owned = ownedFromEngagement();
      var view = OBOL.bloodhound.domainView(summary, owned, cmdCtx(owned, true));
      html += '<div class="bh-summary-head"><h2 class="coach-sec-h">' + esc(summary.domain || 'domain')
        + ' — ' + (summary.users ? summary.users.length : 0) + ' users, ' + (summary.computers ? summary.computers.length : 0) + ' computers</h2>'
        + '<div class="ev-row"><input id="bh-owned" class="ev-cmd" placeholder="owned principals (comma-separated), e.g. ADMINISTRATOR@CORP.LOCAL" value="' + U.attr(owned.join(', ')) + '">'
        + '<button id="bh-recompute" class="btn-ghost">Recompute Paths</button>'
        + '<button id="bh-report" class="btn-primary">Open Report</button></div></div>';

      // Interactive attack-path graph (parity with obol-local's draggable domain graph).
      html += '<h2 class="coach-sec-h">Attack-path graph</h2>'
        + '<div id="bh-graph" class="bh-graph-host">'
        + (owned.length ? '' : '<div class="coach-empty">Enter an owned principal above to derive and graph owned→Domain-Admin paths.</div>')
        + '</div>';

      // PlumHound-style query board: one card per high-value query with matched principals + the
      // exact commands obol would run against it.
      html += '<h2 class="coach-sec-h">High-value queries (PlumHound-style)</h2><div class="bh-census">';
      (view.sections || []).forEach(function (s) {
        var items = s.items || s.principals || [];
        var n = items.length || s.count || 0;
        var cls = /admin|dcsync|unconstrained|domain admin|enterprise/i.test(s.title) ? 'crit' : (/kerberoast|as-?rep|roast/i.test(s.title) ? 'warn' : '');
        var cmds = (s.commands || []).slice(0, 3).map(function (c) {
          var line = typeof c === 'string' ? c : (c.run || c.cmd || c.command || '');
          return line ? '<div class="bh-cmd"><code>' + esc(line) + '</code><button class="btn-copy" data-copy="' + U.attr(line) + '">copy</button></div>' : '';
        }).join('');
        // Expandable detail: the matched accounts/hosts behind the count (e.g. the five DCSync principals).
        var detail = items.length
          ? '<details class="bh-detail"><summary>' + items.length + ' ' + (items.length === 1 ? 'match' : 'matches') + '</summary>'
            + '<ul class="bh-princ">' + items.map(function (p) { return '<li>' + esc(p) + '</li>'; }).join('') + '</ul></details>'
          : '';
        html += '<div class="bh-card"><h3>' + esc(s.title) + '</h3>'
          + '<div class="bh-count ' + cls + '">' + n + '</div>'
          + (s.hint ? '<div class="bh-hint">' + esc(s.hint) + '</div>' : '')
          + (s.cash ? '<div class="bh-cash">' + esc(s.cash) + '</div>' : '')
          + detail
          + (cmds ? '<div class="bh-cmds">' + cmds + '</div>' : '')
          + '</div>';
      });
      html += '</div>';
      html += '<div id="bh-report-slot"></div>';
    }
    html += '</section>';
    return html;
  }

  function readFile(file) {
    return new Promise(function (resolve) {
      var r = new FileReader();
      var isZip = /\.zip$/i.test(file.name);
      r.onload = function () { resolve({ name: file.name, arrayBuffer: isZip ? r.result : undefined, text: isZip ? undefined : r.result }); };
      r.onerror = function () { resolve(null); };
      if (isZip) r.readAsArrayBuffer(file); else r.readAsText(file);
    });
  }

  async function ingest(fileList) {
    var status = document.getElementById('bh-status');
    if (status) status.textContent = 'Parsing ' + fileList.length + ' file(s) in your browser…';
    var files = (await Promise.all(Array.prototype.map.call(fileList, readFile))).filter(Boolean);
    try {
      var summary = await OBOL.bloodhound.parse(files);
      var owned = ownedFromEngagement();
      var paths = OBOL.bloodhound.ownedPaths(summary, owned);
      var facts = OBOL.bloodhound.toFacts(summary, paths, 'domain:' + (summary.domain || 'domain'));
      // Keep the transient _graph on the persisted summary so the interactive graph + census can
      // be re-derived (and owned-principal recompute works) after reload — obol-local drops it only
      // because its server keeps a lean SQLite store; the browser's IndexedDB can hold it.
      OBOL.store.update(function (eng) { eng.bloodhound = summary; }, 'bloodhound');
      OBOL.store.addFacts(facts, 'bloodhound');
      OBOL.app.renderSidebar();
      U.toast('Ingested ' + (summary.domain || 'domain') + ' — ' + facts.length + ' facts');
      OBOL.router.render();
    } catch (e) {
      if (status) status.textContent = 'Parse failed: ' + (e && e.message);
      U.toast('BloodHound parse failed', 'err');
    }
  }

  function mounted(ctx) {
    var drop = document.getElementById('bh-drop');
    var input = document.getElementById('bh-file');
    if (drop && input) {
      drop.addEventListener('click', function () { input.click(); });
      drop.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
      input.addEventListener('change', function () { if (input.files.length) ingest(input.files); });
      ['dragover', 'dragenter'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('drag'); }); });
      ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('drag'); }); });
      drop.addEventListener('drop', function (e) { if (e.dataTransfer && e.dataTransfer.files.length) ingest(e.dataTransfer.files); });
    }
    var rec = document.getElementById('bh-recompute');
    if (rec) rec.addEventListener('click', function () {
      var owned = ((document.getElementById('bh-owned') || {}).value || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      OBOL.store.update(function (eng) { eng.params = eng.params || {}; if (owned[0]) eng.params.username = owned[0]; }, 'params');
      OBOL.router.render();
    });
    // render the interactive attack-path graph
    var eng0 = OBOL.store.active();
    if (eng0 && eng0.bloodhound && OBOL.bhgraph) {
      var owned0 = ownedFromEngagement();
      var view0 = OBOL.bloodhound.domainView(eng0.bloodhound, owned0);
      var host = document.getElementById('bh-graph');
      var g = view0.analysis && view0.analysis.graph;
      if (host && g && g.nodes && g.nodes.length) {
        OBOL.bhgraph.renderInto(host, g, { onNodeClick: function (id) { U.toast(id); } });
      }
    }
    // copy buttons on the query cards
    U.on(mount, 'click', '.btn-copy', function (e, b) {
      var v = b.getAttribute('data-copy'); if (v) U.copy(v).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    var rep = document.getElementById('bh-report');
    if (rep) rep.addEventListener('click', function () {
      var eng = OBOL.store.active();
      if (!eng.bloodhound) return;
      var owned = ownedFromEngagement();
      var view = OBOL.bloodhound.domainView(eng.bloodhound, owned, cmdCtx(owned, false));
      var htmlDoc = OBOL.bloodhound.domainReportHtml(eng.bloodhound, view);
      var slot = document.getElementById('bh-report-slot');
      if (slot) slot.innerHTML = '<h2 class="coach-sec-h">Domain report</h2><iframe class="bh-report-frame" id="bh-frame"></iframe>';
      var frame = document.getElementById('bh-frame');
      if (frame) frame.srcdoc = htmlDoc;
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.domain = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
