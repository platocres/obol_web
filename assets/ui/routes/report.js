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
    var profile = ui.reportProfile || OBOL.report.defaultFor(ctxOf(false)) || 'oscp';
    var includeSecrets = !!ui.reportSecrets;
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
      + '<label>Profile <select id="rep-profile">' + profOpts + '</select></label>'
      + '<label><input type="checkbox" id="rep-secrets"' + (includeSecrets ? ' checked' : '') + '> include secrets (default redacted)</label>'
      + '<button id="rep-md" class="btn-ghost">Download .md</button>'
      + '<button id="rep-html" class="btn-primary">Download .html</button>'
      + '</div>'
      + (gaps.length ? ('<div class="rep-gaps">Readiness gaps:<ul>' + gaps.map(function (g) { return '<li>' + esc(g.message || g) + '</li>'; }).join('') + '</ul></div>') : '')
      + notesEditor()
      + '<div class="rep-out" id="rep-out">' + bodyHtml + '</div>'
      + '</section>';
  }

  function download(name, text, mime) {
    var blob = new Blob([text], { type: mime });
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
    var sec = document.getElementById('rep-secrets');
    if (sec) sec.addEventListener('change', function () {
      OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.reportSecrets = sec.checked; }, 'ui');
      OBOL.router.render();
    });
    function currentProfile() { return (OBOL.store.active().ui || {}).reportProfile || 'oscp'; }
    var md = document.getElementById('rep-md');
    if (md) md.addEventListener('click', function () {
      var p = currentProfile(), c = ctxOf((OBOL.store.active().ui || {}).reportSecrets);
      var stem = (OBOL.report.filenameStem && OBOL.report.filenameStem(p, c)) || ('obol-report-' + p);
      download(stem + '.md', OBOL.report.toMarkdown(OBOL.report.document(p, c)), 'text/markdown');
    });
    var htmlBtn = document.getElementById('rep-html');
    if (htmlBtn) htmlBtn.addEventListener('click', function () {
      var p = currentProfile(), c = ctxOf((OBOL.store.active().ui || {}).reportSecrets);
      var stem = (OBOL.report.filenameStem && OBOL.report.filenameStem(p, c)) || ('obol-report-' + p);
      var doc = '<!doctype html><meta charset="utf-8"><title>' + esc(stem) + '</title>' + OBOL.report.toHtml(OBOL.report.document(p, c));
      download(stem + '.html', doc, 'text/html');
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.report = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
