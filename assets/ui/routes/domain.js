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
      var view = OBOL.bloodhound.domainView(summary, owned);
      html += '<div class="bh-summary-head"><h2 class="coach-sec-h">' + esc(summary.domain || 'domain')
        + ' — ' + (summary.users ? summary.users.length : 0) + ' users, ' + (summary.computers ? summary.computers.length : 0) + ' computers</h2>'
        + '<div class="ev-row"><input id="bh-owned" class="ev-cmd" placeholder="owned principals (comma-separated), e.g. SVC-ALFRESCO@HTB.LOCAL" value="' + U.attr(owned.join(', ')) + '">'
        + '<button id="bh-recompute" class="btn-ghost">Recompute paths</button>'
        + '<button id="bh-report" class="btn-primary">Open report</button></div></div>';

      html += '<div class="bh-census">';
      (view.sections || []).forEach(function (s) {
        var n = (s.principals && s.principals.length) || s.count || 0;
        var cls = /admin|dcsync|unconstrained|domain admin|enterprise/i.test(s.title) ? 'crit' : (/kerberoast|as-?rep|roast/i.test(s.title) ? 'warn' : '');
        html += '<div class="bh-card"><h3>' + esc(s.title) + '</h3>'
          + '<div class="bh-count ' + cls + '">' + n + '</div>'
          + (s.hint ? '<div class="bh-hint">' + esc(s.hint) + '</div>' : '')
          + (s.principals && s.principals.length ? '<div class="bh-princ">' + s.principals.slice(0, 8).map(esc).join(', ') + (s.principals.length > 8 ? ' …' : '') + '</div>' : '')
          + '</div>';
      });
      html += '</div>';

      var paths = OBOL.bloodhound.ownedPaths(summary, owned);
      if (paths && paths.paths && paths.paths.length) {
        html += '<h2 class="coach-sec-h">Owned → Domain Admin paths (' + paths.paths.length + ')</h2><ul class="blocked-list">';
        paths.paths.slice(0, 12).forEach(function (p) {
          var chain = (p.chain || p).map(function (h) { return esc(h.name || h); }).join(' → ');
          html += '<li class="blocked-row"><span class="blocked-title mono">' + chain + '</span></li>';
        });
        html += '</ul>';
      } else if (owned.length) {
        html += '<div class="coach-empty">No owned→DA path found from ' + esc(owned.join(', ')) + ' in this collection.</div>';
      } else {
        html += '<div class="coach-empty">Enter an owned principal above to derive owned→Domain-Admin attack paths.</div>';
      }
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
      if (OBOL.bloodhound.dropGraph) OBOL.bloodhound.dropGraph(summary);
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
    var rep = document.getElementById('bh-report');
    if (rep) rep.addEventListener('click', function () {
      var eng = OBOL.store.active();
      if (!eng.bloodhound) return;
      var owned = ownedFromEngagement();
      var view = OBOL.bloodhound.domainView(eng.bloodhound, owned);
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
