/*!
 * obol ui - routes/report.js - the OSCP/report surface, driven by the ported OBOL.report
 * pipeline (profiles → ordered sections → md/html), two-layer redaction (on by default),
 * readiness validation, and download. Enriches findings from data/reportmeta.js.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  var PROFILE_LABELS = {
    oscp: 'OSCP Exam Report (OffSec)',
    cpts: 'HTB CPTS Exam Report',
    pnpt: 'TCM PNPT Assessment Report',
    generic: 'Client / Organization Pentest',
    executive: 'Executive Summary Report',
    technical: 'Technical Assessment Report',
    oswp: 'OSWP Wireless Exam Report',
  };

  var QUICK_PROFILES = [
    { id: 'oscp', label: 'OffSec OSCP', badge: 'Exam + Flags' },
    { id: 'cpts', label: 'HTB CPTS', badge: '14 Flags + CVSS/CWE' },
    { id: 'pnpt', label: 'TCM PNPT', badge: 'No Flags · AD/Net' },
    { id: 'generic', label: 'Client Pentest', badge: 'Organization' },
  ];

  function activeEng() {
    return OBOL.store.active() || { params: {}, profile: {}, ui: {}, targets: [], facts: [], activities: [], credentials: [], screenshots: [] };
  }

  function ctxOf(includeSecrets) {
    var eng = activeEng();
    var prof = eng.profile || {};
    var params = eng.params || {};
    return OBOL.report.buildContext({
      facts: OBOL.store.factSet(),
      actions: (OBOL.packs && OBOL.packs.actions) ? OBOL.packs.actions() : [],
      // engagement targets carry `ip`; the report engine keys on `host`.
      targets: (eng.targets || []).map(function (t) { return Object.assign({}, t, { host: t.host || t.ip }); }),
      activities: eng.activities || [],
      credentials: eng.credentials || [],
      params: params,
      screenshots: eng.screenshots || [],
      notes: eng.reportNotes || {},
      workspace: eng.workspace || {},
      engId: eng.id,
      reportmeta: (root.OBOL_REPORTMETA || root.OBOL && root.OBOL.reportmeta) || null,
      includeSecrets: !!includeSecrets,
      name: eng.name,
      platform: prof.platform || params.platform || '',
      candidate: prof.candidate || params.candidate || '',
      osid: prof.osid || params.osid || '',
      client: prof.client || params.client || '',
      execSummary: prof.execSummary || params.execSummary || '',
    });
  }

  // Split rendered HTML into realistic paper sheets at explicit page-breaks and major H2/H3/H4 boundaries
  // when a section grows past a single page's visual budget (~3600 chars of markup).
  function paginateHtml(bodyHtml, stem, title) {
    var rawChunks = String(bodyHtml || '').split('<div class="page-break"></div>').map(function (s) { return s.trim(); }).filter(Boolean);
    for (var i = 0; i < rawChunks.length - 1; i++) {
      var trailMatch = rawChunks[i].match(/(\s*<h2\b[^>]*>[\s\S]*?<\/h2>)\s*$/i);
      if (trailMatch && rawChunks[i].length > trailMatch[0].length) {
        rawChunks[i] = rawChunks[i].slice(0, rawChunks[i].length - trailMatch[0].length).trim();
        rawChunks[i + 1] = trailMatch[1].trim() + '\n' + rawChunks[i + 1];
      }
    }
    var pages = [];
    rawChunks.forEach(function (chunk) {
      if (chunk.length <= 3800 || !/<h[234]\b/i.test(chunk)) {
        pages.push(chunk);
        return;
      }
      var parts = chunk.split(/(?=<h[234]\b)/i);
      var acc = '';
      parts.forEach(function (part) {
        var accHasBody = /<(?:p|table|ul|ol|pre|div|figure)\b/i.test(acc);
        if (!acc || !accHasBody) {
          acc = acc ? (acc + '\n' + part) : part;
        } else if ((acc.length + part.length) > 3400) {
          pages.push(acc);
          acc = part;
        } else {
          acc += '\n' + part;
        }
      });
      if (acc) pages.push(acc);
    });
    if (!pages.length) pages.push('<p>No report content generated yet.</p>');
    var total = pages.length;
    return {
      total: total,
      html: pages.map(function (pageContent, idx) {
        var pageNum = idx + 1;
        return '<article class="rep-sheet' + (pageNum === 1 ? ' rep-sheet-cover' : '') + '" data-page="' + pageNum + '">'
          + '<header class="rep-sheet-hdr">'
          + '<span class="rep-sheet-doc">' + esc(title || 'Assessment Report') + '</span>'
          + '<span class="rep-sheet-stem">' + esc(stem) + '.pdf</span>'
          + '</header>'
          + '<div class="rep-sheet-body">' + pageContent + '</div>'
          + '<footer class="rep-sheet-ftr">'
          + '<span>Confidential Assessment Deliverable</span>'
          + '<span>Page ' + pageNum + ' of ' + total + '</span>'
          + '</footer>'
          + '</article>';
      }).join('\n'),
    };
  }

  function notesEditor(ctx, profileObj) {
    var eng = activeEng();
    var targets = eng.targets || [];
    var notes = eng.reportNotes || {};
    var prof = eng.profile || {};
    var showExec = !!(profileObj && profileObj.exec_summary);
    if (!targets.length && !showExec) return '';
    return '<details class="rep-notes"><summary>Authoring Studio: Executive Summary &amp; Per-Host Walkthrough Prose <span class="rep-opt-note">(auto-written from your command ledger when left blank, or customize below)</span></summary>'
      + (showExec
        ? '<div class="rep-note rep-note-exec"><div class="rep-note-h">Executive Summary Override (Client / PNPT / CPTS)</div>'
          + '<textarea class="rep-note-fld" id="rep-exec-summary" placeholder="Leave blank to use the auto-synthesized executive summary, or write a custom client-facing narrative here...">' + esc(prof.execSummary || '') + '</textarea></div>'
        : '')
      + targets.map(function (t) {
        var ip = t.ip || t.host; var n = notes[ip] || {};
        return '<div class="rep-note" data-host="' + esc(ip) + '">'
          + '<div class="rep-note-h-row">'
          + '<span class="rep-note-h">' + esc(t.hostname || t.label || ip) + ' · ' + esc(ip) + '</span>'
          + '<button type="button" class="rep-autodraft-btn" data-host="' + esc(ip) + '" title="Populate fields with the auto-synthesized operator prose so you can tweak it">Load Auto-Draft Prose</button>'
          + '</div>'
          + '<textarea class="rep-note-fld rep-note-summary" data-host="' + esc(ip) + '" placeholder="Host narrative (auto-generated from OS, open ports, initial vector, and privilege reached when left blank)...">' + esc(n.summary || '') + '</textarea>'
          + '<textarea class="rep-note-fld rep-note-steps" data-host="' + esc(ip) + '" placeholder="Optional step-by-step reproduction override, one step per line...">' + esc(n.steps || '') + '</textarea></div>';
      }).join('') + '</details>';
  }

  function submissionDrawer(profile, ctx) {
    if (!OBOL.report || typeof OBOL.report.submissionHelper !== 'function') return '';
    var sub = OBOL.report.submissionHelper(profile, ctx);
    return '<details class="rep-submission">'
      + '<summary>Submission &amp; Deliverable Packaging · <code>' + esc(sub.archiveName) + '</code></summary>'
      + '<div class="rep-sub-body">'
      + '<p class="rep-sub-note">' + esc(sub.note) + '</p>'
      + '<div class="rep-sub-grid">'
      + '<div class="rep-sub-card"><div class="rep-sub-lbl">1. Save PDF as</div><div class="rep-sub-cmd"><code id="rep-sub-pdf">' + esc(sub.pdfName) + '</code><button type="button" class="rep-copy-btn" data-copy="' + U.attr(sub.pdfName) + '">Copy</button></div></div>'
      + '<div class="rep-sub-card"><div class="rep-sub-lbl">2. Build Archive</div><div class="rep-sub-cmd"><code id="rep-sub-arch">' + esc(sub.archiveCmd) + '</code><button type="button" class="rep-copy-btn" data-copy="' + U.attr(sub.archiveCmd) + '">Copy</button></div></div>'
      + '<div class="rep-sub-card"><div class="rep-sub-lbl">3. Verify Checksum</div><div class="rep-sub-cmd"><code id="rep-sub-hash">' + esc(sub.hashCmd) + '</code><button type="button" class="rep-copy-btn" data-copy="' + U.attr(sub.hashCmd) + '">Copy</button></div></div>'
      + '</div>'
      + '</div></details>';
  }

  function render() {
    var eng = OBOL.store.active() || { params: {}, profile: {}, ui: {}, targets: [], facts: [], activities: [], credentials: [], screenshots: [] };
    var ui = eng.ui || {};
    var baseCtx = ctxOf(true);
    var profile = ui.reportProfile || OBOL.report.defaultFor(baseCtx) || 'oscp';
    var zoom = ui.reportZoom || '0.85';
    var viewMode = ui.reportViewMode || 'pages';
    // Full detail is shown by default; redaction is opt-in (for a report you intend to share).
    var redact = !!ui.reportRedact;
    var includeSecrets = !redact;
    var ctx = ctxOf(includeSecrets);
    var profileObj = OBOL.report.resolve(profile, ctx);
    var blocks = OBOL.report.document(profile, ctx);
    var bodyHtml = OBOL.report.toHtml(blocks);
    var stem = OBOL.report.filenameStem(profileObj, ctx);
    var paged = paginateHtml(bodyHtml, stem, profileObj.title);
    var outlineItems = (OBOL.report.outline ? OBOL.report.outline(blocks) : []);
    var gaps = OBOL.report.validate(profile, ctx) || [];
    var pf = (!profileObj.no_flags && OBOL.report && typeof OBOL.report.preflightCheck === 'function') ? OBOL.report.preflightCheck(ctx) : null;
    var pfHtml = '';
    if (pf) {
      if (pf.warnings && pf.warnings.length > 0) {
        var fixFor = function (w) {
          if (w.code === 'MISSING_PROOF_CONTEXT') return 'Paste terminal capture showing flag with whoami and IP address (e.g. whoami; ip a; cat proof.txt).';
          if (w.code === 'MISSING_INITIAL_ACCESS') return 'Record an initial access finding or execute and paste the initial foothold command chain.';
          if (w.code === 'MISSING_PRIVESC') return 'Record a privilege escalation finding or execute and paste the privesc command chain.';
          if (w.code === 'EXAM_RESTRICTED_TOOL') return 'Remove commands using prohibited tools (such as sqlmap) from the activity log.';
          return 'Provide missing evidence or chain details.';
        };
        pfHtml = '<details class="rep-preflight" open><summary><span class="rep-preflight-title">Report Readiness Pre-Flight (' + pf.warnings.length + ')</span></summary>'
          + '<ul class="rep-preflight-list">'
          + pf.warnings.map(function (w) {
            return '<li class="rep-preflight-item ' + esc(w.level || 'warn') + '">'
              + '<span class="rep-preflight-badge ' + esc(w.level || 'warn') + '">' + esc(w.level || 'warn') + '</span> '
              + (w.host ? ('<span class="rep-preflight-host">' + esc(w.host) + '</span> ') : '')
              + '<span class="rep-preflight-msg">' + esc(w.message) + '</span>'
              + '<div class="rep-preflight-fix">Fix: ' + esc(fixFor(w)) + '</div>'
              + '</li>';
          }).join('')
          + '</ul></details>';
      } else if (ctx.proofs && ctx.proofs.length > 0) {
        pfHtml = '<div class="rep-preflight-clean">Pre-Flight Clean: all captured flags have proof context and reproduction chains</div>';
      }
    }

    var profOpts = Object.keys(OBOL.report.PROFILES).map(function (p) {
      var lbl = PROFILE_LABELS[p] || (OBOL.report.PROFILES[p] && OBOL.report.PROFILES[p].name) || p;
      return '<option value="' + esc(p) + '"' + (p === profileObj.id ? ' selected' : '') + '>' + esc(lbl) + '</option>';
    }).join('');

    var quickPills = QUICK_PROFILES.map(function (qp) {
      var active = qp.id === profileObj.id;
      return '<button type="button" class="rep-prof-pill' + (active ? ' active' : '') + '" data-prof="' + esc(qp.id) + '">'
        + '<span class="rep-prof-pill-name">' + esc(qp.label) + '</span>'
        + '<span class="rep-prof-pill-badge">' + esc(qp.badge) + '</span>'
        + '</button>';
    }).join('');

    var isOffsec = OBOL.report.isExamProfile(profileObj.id);
    var showClientField = (profileObj.id === 'pnpt' || profileObj.id === 'generic' || profileObj.id === 'executive' || profileObj.id === 'cpts');

    var previewInner = '';
    if (viewMode === 'md') {
      previewInner = '<div class="rep-sheet rep-sheet-md"><pre class="rep-md-pre">' + esc(OBOL.report.toMarkdown(blocks)) + '</pre></div>';
    } else if (viewMode === 'continuous') {
      previewInner = '<div class="rep-sheet rep-sheet-continuous"><div class="rep-sheet-body">' + bodyHtml + '</div></div>';
    } else {
      previewInner = paged.html;
    }

    var totalFindings = ((ctx.findings && ctx.findings.targets) || []).reduce(function (s, t) { return s + ((t.findings || []).length); }, 0);

    return '<section class="report-route">'
      + '<div class="rep-header-bar">'
      + '<div><h1 class="route-h1">Report Studio</h1><p class="rep-subtitle">' + esc(profileObj.note || '') + '</p></div>'
      + '<div class="rep-prof-pills" role="group" aria-label="Quick report templates">' + quickPills + '</div>'
      + '</div>'
      + '<div class="rep-controls">'
      + '<div class="rep-opts">'
      + '<label class="rep-opt">Template <select id="rep-profile">' + profOpts + '</select></label>'
      + '<label class="rep-opt">' + (isOffsec ? 'Candidate' : 'Assessor') + ' <input type="text" id="rep-candidate" value="' + U.attr((eng.profile || {}).candidate || '') + '" placeholder="Your name" autocomplete="off" spellcheck="false"></label>'
      + (isOffsec
        ? '<label class="rep-opt">OSID <input type="text" id="rep-osid" value="' + U.attr((eng.profile || {}).osid || '') + '" placeholder="OS-XXXXX" autocomplete="off" spellcheck="false"></label>'
        : '')
      + (showClientField
        ? '<label class="rep-opt">Client <input type="text" id="rep-client" value="' + U.attr((eng.profile || {}).client || '') + '" placeholder="Organization" autocomplete="off" spellcheck="false"></label>'
        : '')
      + '<label class="rep-opt"><input type="checkbox" id="rep-redact"' + (redact ? ' checked' : '') + '> Redact Secrets <span class="rep-opt-note">(' + (redact ? 'on, safe to share' : 'off, full detail') + ')</span></label>'
      + '</div>'
      + '<div class="rep-toolbar-right">'
      + '<div class="rep-view-controls" role="group" aria-label="Preview mode and zoom">'
      + '<button type="button" class="rep-view-btn' + (viewMode === 'pages' ? ' active' : '') + '" data-view="pages" title="Paginated paper sheets">Pages (' + paged.total + ')</button>'
      + '<button type="button" class="rep-view-btn' + (viewMode === 'continuous' ? ' active' : '') + '" data-view="continuous" title="Continuous single-column scroll">Continuous</button>'
      + '<button type="button" class="rep-view-btn' + (viewMode === 'md' ? ' active' : '') + '" data-view="md" title="Raw Markdown source">Markdown</button>'
      + '<span class="rep-zoom-sep">|</span>'
      + '<button type="button" class="rep-zoom-btn' + (zoom === '0.72' ? ' active' : '') + '" data-zoom="0.72" title="Fit full page in viewport">72%</button>'
      + '<button type="button" class="rep-zoom-btn' + (zoom === '0.85' ? ' active' : '') + '" data-zoom="0.85" title="Default balanced studio view">85%</button>'
      + '<button type="button" class="rep-zoom-btn' + (zoom === '1' ? ' active' : '') + '" data-zoom="1" title="Actual 100% print scale">100%</button>'
      + '</div>'
      + '<div class="rep-actions"><span class="rep-export-lbl">Export</span>'
      + '<button id="rep-print" class="rep-exp" title="Paper view, choose Save as PDF in the print dialog">PDF</button>'
      + '<button id="rep-docx" class="rep-exp" title="Editable Microsoft Word document (.docx)">.docx</button>'
      + '<button id="rep-md" class="rep-exp" title="Markdown source (.md)">.md</button>'
      + '<button id="rep-html" class="rep-exp" title="Self-contained HTML (.html)">.html</button>'
      + '</div>'
      + '</div>'
      + '</div>'
      + (gaps.length ? ('<div class="rep-gaps">Readiness checks:<ul>' + gaps.map(function (g) { return '<li>' + esc(g.message || g) + '</li>'; }).join('') + '</ul></div>') : '')
      + pfHtml
      + submissionDrawer(profileObj.id, ctx)
      + notesEditor(ctx, profileObj)
      + '<div class="rep-studio-layout">'
      + '<aside class="rep-studio-rail" aria-label="Report outline">'
      + '<div class="rep-rail-stats">'
      + '<div class="rep-rail-stat"><span class="rep-rail-val" id="rep-stat-pages">' + paged.total + '</span><span class="rep-rail-lbl">Pages</span></div>'
      + '<div class="rep-rail-stat"><span class="rep-rail-val">' + (ctx.targets || []).length + '</span><span class="rep-rail-lbl">Targets</span></div>'
      + '<div class="rep-rail-stat"><span class="rep-rail-val">' + totalFindings + '</span><span class="rep-rail-lbl">Findings</span></div>'
      + (!profileObj.no_flags ? '<div class="rep-rail-stat"><span class="rep-rail-val">' + (ctx.proofCount || 0) + '</span><span class="rep-rail-lbl">Proofs</span></div>' : '')
      + '</div>'
      + '<div class="rep-rail-title">Document Outline</div>'
      + '<nav class="rep-outline-nav" id="rep-outline-nav">'
      + outlineItems.map(function (item) {
        return '<a href="#' + esc(item.anchor) + '" class="rep-outline-link lvl-' + item.level + '" data-anchor="' + esc(item.anchor) + '">' + esc(item.text) + '</a>';
      }).join('')
      + '</nav>'
      + '</aside>'
      + '<div class="rep-out rep-mode-' + esc(viewMode) + '" id="rep-out" style="--rep-zoom:' + esc(zoom) + '">'
      + '<div class="rep-sheets" id="rep-sheets">' + previewInner + '</div>'
      + '</div>'
      + '</div>'
      + '</section>';
  }

  function download(name, data, mime) {
    var blob = (data instanceof Blob) ? data : new Blob([data], { type: mime });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  function mounted() {
    // per-host report notes & executive summary override: persist on input, refresh preview on change.
    var notesWrap = document.querySelector('.rep-notes');
    if (notesWrap) {
      notesWrap.addEventListener('input', function (e) {
        var ta = e.target; if (!ta.classList || !ta.classList.contains('rep-note-fld')) return;
        if (ta.id === 'rep-exec-summary') {
          OBOL.store.update(function (en) {
            en.profile = en.profile || {};
            en.profile.execSummary = ta.value;
          }, 'profile');
          refreshBody();
          return;
        }
        var host = ta.getAttribute('data-host'); if (!host) return;
        var field = ta.classList.contains('rep-note-steps') ? 'steps' : 'summary';
        OBOL.store.update(function (en) {
          en.reportNotes = en.reportNotes || {};
          en.reportNotes[host] = en.reportNotes[host] || {};
          en.reportNotes[host][field] = ta.value;
        }, 'reportNotes');
        refreshBody();
      });
      notesWrap.querySelectorAll('.rep-autodraft-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var host = btn.getAttribute('data-host');
          if (!host) return;
          var c = ctxOf(!(activeEng().ui || {}).reportRedact);
          var t = (c.targets || []).find(function (x) { return x.host === host; });
          if (!t) return;
          var hFindings = ((c.findings && c.findings.targets) || []).find(function (x) { return x.host === host; });
          var fList = (hFindings && hFindings.findings) || [];
          var split = OBOL.report.splitFindingsByPhase ? OBOL.report.splitFindingsByPhase(fList, t) : [[], []];
          var summary = OBOL.report.autoHostSummary ? OBOL.report.autoHostSummary(t, split[0], split[1]) : '';
          var steps = (t.findings || []).map(function (f) { return (f.evidence || '').trim(); })
            .filter(function (ev, i, a) { return ev && a.indexOf(ev) === i; })
            .slice(0, 8)
            .map(function (ev) { return OBOL.report.describeCommandStep ? OBOL.report.describeCommandStep(ev, t.label || host, '') : ev; })
            .join('\n');
          OBOL.store.update(function (en) {
            en.reportNotes = en.reportNotes || {};
            en.reportNotes[host] = { summary: summary, steps: steps };
          }, 'reportNotes');
          OBOL.router.render();
          U.toast('Auto-draft prose loaded for ' + host, 'ok');
        });
      });
    }

    // Quick profile pills
    document.querySelectorAll('.rep-prof-pill').forEach(function (pill) {
      pill.addEventListener('click', function () {
        var p = pill.getAttribute('data-prof');
        if (!p) return;
        OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.reportProfile = p; }, 'ui');
        OBOL.router.render();
      });
    });

    // View mode & Zoom buttons
    document.querySelectorAll('.rep-view-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var v = btn.getAttribute('data-view');
        if (!v) return;
        OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.reportViewMode = v; }, 'ui');
        OBOL.router.render();
      });
    });
    document.querySelectorAll('.rep-zoom-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var z = btn.getAttribute('data-zoom');
        if (!z) return;
        OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.reportZoom = z; }, 'ui');
        var out = document.getElementById('rep-out');
        if (out) out.style.setProperty('--rep-zoom', z);
        document.querySelectorAll('.rep-zoom-btn').forEach(function (b) { b.classList.toggle('active', b === btn); });
      });
    });

    // Outline navigation links (smooth scroll inside #rep-out)
    var outlineNav = document.getElementById('rep-outline-nav');
    if (outlineNav) {
      outlineNav.addEventListener('click', function (ev) {
        var link = ev.target.closest('.rep-outline-link');
        if (!link) return;
        ev.preventDefault();
        var anchor = link.getAttribute('data-anchor');
        var out = document.getElementById('rep-out');
        if (!out || !anchor) return;
        var targetEl = out.querySelector('[id="' + anchor.replace(/"/g, '\\"') + '"]');
        if (targetEl) targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    }

    // Submission helper copy buttons
    document.querySelectorAll('.rep-copy-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var text = btn.getAttribute('data-copy') || '';
        if (text) {
          U.copy(text).then(function (ok) { U.toast(ok ? ('Copied: ' + text) : 'Copy failed', ok ? 'ok' : 'err'); });
        }
      });
    });

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

    // Candidate name, OSID, Client: rebuild only the sheets on each keystroke so the input keeps focus.
    function refreshBody() {
      var e2 = activeEng(), ui2 = e2.ui || {};
      var c2 = ctxOf(!ui2.reportRedact);
      var p2 = ui2.reportProfile || OBOL.report.defaultFor(c2) || 'oscp';
      var profObj = OBOL.report.resolve(p2, c2);
      var blocks2 = OBOL.report.document(p2, c2);
      var html2 = OBOL.report.toHtml(blocks2);
      var stem2 = OBOL.report.filenameStem(profObj, c2);
      var viewMode2 = ui2.reportViewMode || 'pages';
      var sheetsWrap = document.getElementById('rep-sheets');
      if (sheetsWrap) {
        if (viewMode2 === 'md') {
          sheetsWrap.innerHTML = '<div class="rep-sheet rep-sheet-md"><pre class="rep-md-pre">' + esc(OBOL.report.toMarkdown(blocks2)) + '</pre></div>';
        } else if (viewMode2 === 'continuous') {
          sheetsWrap.innerHTML = '<div class="rep-sheet rep-sheet-continuous"><div class="rep-sheet-body">' + html2 + '</div></div>';
        } else {
          var pg = paginateHtml(html2, stem2, profObj.title);
          sheetsWrap.innerHTML = pg.html;
          var st = document.getElementById('rep-stat-pages');
          if (st) st.textContent = String(pg.total);
        }
      }
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
    bindProfileField('rep-client', 'client');

    function currentProfile() {
      var ui = (activeEng().ui || {});
      return ui.reportProfile || OBOL.report.defaultFor(ctxOf(true)) || 'oscp';
    }
    function stemFor(p, c) {
      try { return OBOL.report.filenameStem(p, c) || ('obol-report-' + p); } catch (e) { return 'obol-report-' + p; }
    }
    var md = document.getElementById('rep-md');
    if (md) md.addEventListener('click', function () {
      try {
        var p = currentProfile(), c = ctxOf(!(activeEng().ui || {}).reportRedact);
        download(stemFor(p, c) + '.md', OBOL.report.toMarkdown(OBOL.report.document(p, c)), 'text/markdown');
      } catch (e) { U.toast('Could not build .md', 'err'); }
    });
    var htmlBtn = document.getElementById('rep-html');
    if (htmlBtn) htmlBtn.addEventListener('click', function () {
      try {
        var p = currentProfile(), c = ctxOf(!(activeEng().ui || {}).reportRedact);
        var stem = stemFor(p, c);
        var doc = OBOL.report.htmlDocument(OBOL.report.toHtml(OBOL.report.document(p, c)), stem);
        download(stem + '.html', doc, 'text/html');
      } catch (e) { U.toast('Could not build .html', 'err'); }
    });
    var printBtn = document.getElementById('rep-print');
    if (printBtn) printBtn.addEventListener('click', function () { try { window.print(); } catch (e) {} });
    var docxBtn = document.getElementById('rep-docx');
    if (docxBtn) docxBtn.addEventListener('click', function () {
      var JSZip = root.JSZip;
      if (!JSZip || !OBOL.report.docxFiles) { U.toast('Still loading, try again in a second', 'err'); return; }
      var p = currentProfile(), c = ctxOf(!(activeEng().ui || {}).reportRedact);
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
