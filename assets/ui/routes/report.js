/*!
 * obol ui — routes/report.js — the OSCP/report surface, driven by the ported OBOL.report
 * pipeline (profiles → ordered sections → md/html), two-layer redaction (on by default),
 * readiness validation, and download. Enriches findings from data/reportmeta.js.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function ctxOf(includeSecrets) {
    var eng = OBOL.store.active();
    return OBOL.report.buildContext({
      facts: OBOL.store.factSet(),
      actions: (OBOL.packs && OBOL.packs.actions) ? OBOL.packs.actions() : [],
      // engagement targets carry `ip`; the report engine keys on `host`.
      targets: (eng.targets || []).map(function (t) { return Object.assign({}, t, { host: t.host || t.ip }); }),
      activities: eng.activities || [],
      credentials: eng.credentials || [],
      params: eng.params || {},
      screenshots: eng.screenshots || [],
      notes: eng.reportNotes || {},
      reportmeta: (root.OBOL_REPORTMETA || root.OBOL && root.OBOL.reportmeta) || null,
      includeSecrets: !!includeSecrets,
      name: eng.name,
      platform: (eng.profile || {}).platform || (eng.params || {}).platform || '',
      candidate: (eng.profile || {}).candidate || '',
      osid: (eng.profile || {}).osid || '',
    });
  }

  function notesEditor() {
    var eng = OBOL.store.active();
    var targets = eng.targets || [];
    var notes = eng.reportNotes || {};
    if (!targets.length) return '';
    return '<details class="rep-notes"><summary>Report notes — per-host summary &amp; exploitation steps (woven into the walkthrough)</summary>'
      + targets.map(function (t) {
        var ip = t.ip || t.host; var n = notes[ip] || {};
        return '<div class="rep-note" data-host="' + esc(ip) + '"><div class="rep-note-h">' + esc(t.hostname || ip) + ' · ' + esc(ip) + '</div>'
          + '<textarea class="rep-note-fld rep-note-summary" data-host="' + esc(ip) + '" placeholder="One-paragraph summary: how this host was compromised…">' + esc(n.summary || '') + '</textarea>'
          + '<textarea class="rep-note-fld rep-note-steps" data-host="' + esc(ip) + '" placeholder="Exploitation steps, one per line (rendered as a numbered list)…">' + esc(n.steps || '') + '</textarea></div>';
      }).join('') + '</details>';
  }

  function render() {
    var eng = OBOL.store.active();
    var ui = eng.ui || {};
    var profile = ui.reportProfile || OBOL.report.defaultFor(ctxOf(true)) || 'oscp';
    // Full detail is shown by default; redaction is opt-in (for a report you intend to share).
    var redact = !!ui.reportRedact;
    var includeSecrets = !redact;
    var ctx = ctxOf(includeSecrets);
    var blocks = OBOL.report.document(profile, ctx);
    var bodyHtml = OBOL.report.toHtml(blocks);
    var gaps = OBOL.report.validate(profile, ctx) || [];

    var profOpts = Object.keys(OBOL.report.PROFILES).map(function (p) {
      return '<option value="' + esc(p) + '"' + (p === profile ? ' selected' : '') + '>' + esc(p) + '</option>';
    }).join('');

    return '<section class="report-route">'
      + '<h1 class="route-h1">Report</h1>'
      + '<div class="rep-controls">'
      + '<div class="rep-opts">'
      + '<label class="rep-opt">Profile <select id="rep-profile">' + profOpts + '</select></label>'
      + (OBOL.report.isExamProfile(profile)
        ? '<label class="rep-opt">Candidate <input type="text" id="rep-candidate" value="' + U.attr((eng.profile || {}).candidate || '') + '" placeholder="Your name" autocomplete="off" spellcheck="false"></label>'
          + '<label class="rep-opt">OSID <input type="text" id="rep-osid" value="' + U.attr((eng.profile || {}).osid || '') + '" placeholder="OS-XXXXX" autocomplete="off" spellcheck="false"></label>'
        : '')
      + '<label class="rep-opt"><input type="checkbox" id="rep-redact"' + (redact ? ' checked' : '') + '> Redact Secrets <span class="rep-opt-note">(off — full detail shown)</span></label>'
      + '</div>'
      + '<div class="rep-actions"><span class="rep-export-lbl">Download</span>'
      + '<button id="rep-print" class="rep-exp" title="Paper view — choose “Save as PDF” in the print dialog">PDF</button>'
      + '<button id="rep-md" class="rep-exp" title="Markdown">.md</button>'
      + '<button id="rep-html" class="rep-exp" title="Self-contained HTML">.html</button>'
      + '<button id="rep-docx" class="rep-exp" title="Word document">.docx</button>'
      + '</div>'
      + '</div>'
      + (gaps.length ? ('<div class="rep-gaps">Readiness gaps:<ul>' + gaps.map(function (g) { return '<li>' + esc(g.message || g) + '</li>'; }).join('') + '</ul></div>') : '')
      + notesEditor()
      + '<div class="rep-out" id="rep-out">' + bodyHtml + '</div>'
      + '</section>';
  }

  function download(name, data, mime) {
    var blob = (data instanceof Blob) ? data : new Blob([data], { type: mime });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  function mounted(ctx) {
    var eng = OBOL.store.active();

    // per-host report notes: persist on input, refresh the preview on blur.
    var notesWrap = document.querySelector('.rep-notes');
    if (notesWrap) {
      notesWrap.addEventListener('input', function (e) {
        var ta = e.target; if (!ta.classList || !ta.classList.contains('rep-note-fld')) return;
        var host = ta.getAttribute('data-host'); if (!host) return;
        var field = ta.classList.contains('rep-note-steps') ? 'steps' : 'summary';
        OBOL.store.update(function (en) {
          en.reportNotes = en.reportNotes || {};
          en.reportNotes[host] = en.reportNotes[host] || {};
          en.reportNotes[host][field] = ta.value;
        }, 'reportNotes');
      });
      notesWrap.addEventListener('change', function (e) {
        if (e.target && e.target.classList && e.target.classList.contains('rep-note-fld')) OBOL.router.render();
      });
    }

    var prof = document.getElementById('rep-profile');
    if (prof) prof.addEventListener('change', function () {
      OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.reportProfile = prof.value; }, 'ui');
      OBOL.router.render();
    });
    var red = document.getElementById('rep-redact');
    if (red) red.addEventListener('change', function () {
      OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.reportRedact = red.checked; }, 'ui');
      OBOL.router.render();
    });
    // Candidate name + OSID for OffSec exam reports: fill them right here. Rebuild only the report
    // BODY on each keystroke (not the whole route) so the input keeps focus while the cover updates.
    function refreshBody() {
      var e2 = OBOL.store.active(), ui2 = e2.ui || {};
      var p2 = ui2.reportProfile || OBOL.report.defaultFor(ctxOf(true)) || 'oscp';
      var out = document.getElementById('rep-out');
      if (out) out.innerHTML = OBOL.report.toHtml(OBOL.report.document(p2, ctxOf(!ui2.reportRedact)));
    }
    function bindProfileField(id, key) {
      var el = document.getElementById(id);
      if (el) el.addEventListener('input', function () {
        OBOL.store.update(function (e) { e.profile = e.profile || {}; e.profile[key] = el.value; }, 'profile');
        refreshBody();
      });
    }
    bindProfileField('rep-candidate', 'candidate');
    bindProfileField('rep-osid', 'osid');
    function currentProfile() { return (OBOL.store.active().ui || {}).reportProfile || 'oscp'; }
    function stemFor(p, c) {
      try { return OBOL.report.filenameStem(p, c) || ('obol-report-' + p); } catch (e) { return 'obol-report-' + p; }
    }
    var md = document.getElementById('rep-md');
    if (md) md.addEventListener('click', function () {
      try {
        var p = currentProfile(), c = ctxOf(!(OBOL.store.active().ui || {}).reportRedact);
        download(stemFor(p, c) + '.md', OBOL.report.toMarkdown(OBOL.report.document(p, c)), 'text/markdown');
      } catch (e) { U.toast('Could not build .md', 'err'); }
    });
    var htmlBtn = document.getElementById('rep-html');
    if (htmlBtn) htmlBtn.addEventListener('click', function () {
      try {
        var p = currentProfile(), c = ctxOf(!(OBOL.store.active().ui || {}).reportRedact);
        var stem = stemFor(p, c);
        var doc = OBOL.report.htmlDocument(OBOL.report.toHtml(OBOL.report.document(p, c)), stem);
        download(stem + '.html', doc, 'text/html');
      } catch (e) { U.toast('Could not build .html', 'err'); }
    });
    // Paper view + PDF via the browser print dialog (print CSS styles the report as paper).
    var printBtn = document.getElementById('rep-print');
    if (printBtn) printBtn.addEventListener('click', function () { try { window.print(); } catch (e) {} });
    // .docx — build the OOXML parts and zip them with JSZip (loaded with the report bundle).
    var docxBtn = document.getElementById('rep-docx');
    if (docxBtn) docxBtn.addEventListener('click', function () {
      var JSZip = root.JSZip;
      if (!JSZip || !OBOL.report.docxFiles) { U.toast('Still loading — try again in a second', 'err'); return; }
      var p = currentProfile(), c = ctxOf(!(OBOL.store.active().ui || {}).reportRedact);
      var stem = stemFor(p, c);
      try {
        var files = OBOL.report.docxFiles(OBOL.report.document(p, c));
        var zip = new JSZip();
        files.forEach(function (f) { zip.file(f.path, f.data, f.base64 ? { base64: true } : undefined); });
        zip.generateAsync({ type: 'blob', mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' })
          .then(function (blob) { download(stem + '.docx', blob); })
          .catch(function () { U.toast('Could not build .docx', 'err'); });
      } catch (e) { U.toast('Could not build .docx', 'err'); }
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.report = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
