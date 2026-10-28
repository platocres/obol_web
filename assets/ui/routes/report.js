/*!
 * obol ui - routes/report.js - the OSCP/report surface, driven by the ported OBOL.report
 * pipeline (profiles -> ordered sections -> md/html/docx), AST block-level sheet pagination,
 * two-layer redaction, readiness validation, and download. Enriches findings from data/reportmeta.js.
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
      targets: (eng.targets || []).map(function (t) { return Object.assign({}, t, { host: t.host || t.ip }); }),
      activities: eng.activities || [],
      credentials: eng.credentials || [],
      params: params,
      screenshots: eng.screenshots || [],
      notes: eng.reportNotes || {},
      workspace: eng.workspace || {},
      engId: eng.id,
      reportmeta: (root.OBOL_REPORTMETA || (root.OBOL && root.OBOL.reportmeta)) || null,
      includeSecrets: !!includeSecrets,
      hideUnreached: (eng.ui || {}).reportHideUnreached !== false,
      name: eng.name,
      platform: prof.platform || params.platform || '',
      candidate: prof.candidate || params.candidate || '',
      osid: prof.osid || params.osid || '',
      client: prof.client || params.client || '',
      execSummary: prof.execSummary || params.execSummary || '',
    });
  }

  // Estimate visual line height of a single AST block on an A4/US-Letter paper sheet (~44 visual lines).
  // Base64 screenshot URIs (`shot_data_uri`, `data_uri`) are weighted by rendered visual height rather
  // than byte length, and composite blocks (`proof`, `figure`, `pre`, `table`) never split mid-tag.
  var PAGE_LINE_BUDGET = 44;

  function rowVisualLines(row) {
    if (!Array.isArray(row) || !row.length) return 1.5;
    var totalChars = 0, maxColChars = 0;
    for (var i = 0; i < row.length; i++) {
      var len = String(row[i] == null ? '' : row[i]).length;
      totalChars += len;
      if (len > maxColChars) maxColChars = len;
    }
    var wrapped = Math.max(Math.ceil(maxColChars / 54), Math.ceil(totalChars / 74));
    return Math.min(12, Math.max(1.45, wrapped * 1.12 + 0.35));
  }

  function blockVisualLines(b) {
    if (!b || !b.t) return 0;
    switch (b.t) {
      case 'pagebreak':
        return 0;
      case 'heading':
        return b.level === 1 ? 4.2 : (b.level === 2 ? 3.4 : (b.level === 3 ? 2.6 : 2.1));
      case 'para':
        return 1.1 + Math.max(1, Math.ceil(String(b.text || '').length / 82)) * 1.15;
      case 'callout':
        return 2.0 + Math.max(1, Math.ceil(String(b.text || '').length / 76)) * 1.15;
      case 'divider':
        return 1.4;
      case 'kv':
        return 1.4 + ((b.pairs && b.pairs.length) || 0) * 1.65;
      case 'toc':
        return 3.4 + ((b.items && b.items.length) || 0) * 1.25;
      case 'bullets': {
        var sumB = 1.0;
        (b.items || []).forEach(function (it) {
          sumB += Math.max(1.25, Math.ceil(String(it || '').length / 78) * 1.15);
        });
        return sumB;
      }
      case 'code': {
        var cLines = String(b.text || '').split('\n').length;
        return 2.4 + Math.min(26, Math.max(1, cLines) * 1.1);
      }
      case 'terminal': {
        var cmdLines = Math.max(1, Math.ceil(String(b.command || '').length / 70));
        var outLines = b.output ? String(b.output).replace(/\n+$/, '').split('\n').length : 0;
        return 2.8 + Math.min(26, (cmdLines + outLines) * 1.08);
      }
      case 'proof': {
        var pWeight = 9.5;
        if (b.block) {
          pWeight += 1.6 + Math.min(18, Math.max(3, String(b.block).split('\n').length * 1.08));
        }
        if (b.shot_data_uri) {
          pWeight += 15.5;
        }
        return pWeight;
      }
      case 'image':
        return (b.is_render ? 15.5 : 19.0) + (b.caption ? 1.4 : 0);
      case 'table': {
        var tWeight = 2.2 + (b.caption ? 1.3 : 0);
        (b.rows || []).forEach(function (r) { tWeight += rowVisualLines(r); });
        return tWeight;
      }
      default:
        return 2.0;
    }
  }

  function isKeepWithNext(b) {
    if (!b || !b.t) return false;
    if (b.t === 'heading') return true;
    if (b.t === 'para' && /^\*\*[^*\r\n]{2,90}\*\*:?\s*$/.test(String(b.text || '').trim())) return true;
    return false;
  }

  function pageHasBody(pageBlocks) {
    for (var i = 0; i < pageBlocks.length; i++) {
      var b = pageBlocks[i];
      if (b && b.t && b.t !== 'pagebreak' && !isKeepWithNext(b)) return true;
    }
    return false;
  }

  // AST-level sheet paginator: serializes each page independently via OBOL.report.toHtml(pageBlocks)
  // so wrapper tags (<div class="proof-item">, <table>, <figure>, <pre>) can never split across sheets,
  // and splits multi-page tables cleanly with repeated <thead> column headers.
  function paginateBlocks(blocks, stem, title) {
    var pages = [];
    var cur = [];
    var curLines = 0;

    function flush() {
      if (!cur.length) return;
      var carry = [];
      if (pageHasBody(cur)) {
        while (cur.length && isKeepWithNext(cur[cur.length - 1])) {
          carry.unshift(cur.pop());
        }
      }
      if (cur.length) pages.push(cur);
      cur = carry;
      curLines = 0;
      for (var i = 0; i < cur.length; i++) curLines += blockVisualLines(cur[i]);
    }

    (blocks || []).forEach(function (b) {
      if (!b || !b.t) return;

      if (b.t === 'pagebreak') {
        if (pageHasBody(cur)) flush();
        return;
      }

      if (b.t === 'heading') {
        var hw = blockVisualLines(b);
        var minFollow = b.level <= 2 ? 9 : 6;
        if (pageHasBody(cur) && ((b.level === 2 && curLines >= 29) || (curLines + hw + minFollow > PAGE_LINE_BUDGET))) {
          flush();
        }
        cur.push(b);
        curLines += hw;
        return;
      }

      // Split oversized tables across sheets while repeating headers on every continuation page.
      if (b.t === 'table' && Array.isArray(b.rows) && b.rows.length > 0) {
        var baseHdr = 2.2 + (b.caption ? 1.3 : 0);
        var firstRowH = rowVisualLines(b.rows[0]);
        if (pageHasBody(cur) && (curLines + baseHdr + firstRowH > PAGE_LINE_BUDGET)) {
          flush();
        }
        var idx = 0, sliceIdx = 0;
        while (idx < b.rows.length) {
          var hdrCost = 2.2 + ((sliceIdx === 0 && b.caption) ? 1.3 : (b.caption ? 1.3 : 0));
          if (pageHasBody(cur) && (curLines + hdrCost + rowVisualLines(b.rows[idx]) > PAGE_LINE_BUDGET)) {
            flush();
          }
          var sliceRows = [];
          var sliceLines = hdrCost;
          while (idx < b.rows.length) {
            var rh = rowVisualLines(b.rows[idx]);
            if (sliceRows.length > 0 && (curLines + sliceLines + rh > PAGE_LINE_BUDGET)) break;
            sliceRows.push(b.rows[idx]);
            sliceLines += rh;
            idx++;
          }
          cur.push({
            t: 'table',
            headers: b.headers || [],
            rows: sliceRows,
            caption: sliceIdx === 0 ? (b.caption || '') : (b.caption ? (b.caption + ' (continued)') : ''),
          });
          curLines += sliceLines;
          sliceIdx++;
          if (idx < b.rows.length) flush();
        }
        return;
      }

      // Split oversized unordered bullet lists (e.g. long Evidence lists) cleanly across sheets.
      if (b.t === 'bullets' && !b.ordered && Array.isArray(b.items) && b.items.length > 10 && (curLines + blockVisualLines(b) > PAGE_LINE_BUDGET)) {
        var bIdx = 0;
        while (bIdx < b.items.length) {
          var firstItH = Math.max(1.25, Math.ceil(String(b.items[bIdx] || '').length / 78) * 1.15);
          if (pageHasBody(cur) && (curLines + 1.0 + firstItH > PAGE_LINE_BUDGET)) flush();
          var chunkItems = [], chunkH = 1.0;
          while (bIdx < b.items.length) {
            var ih = Math.max(1.25, Math.ceil(String(b.items[bIdx] || '').length / 78) * 1.15);
            if (chunkItems.length > 0 && (curLines + chunkH + ih > PAGE_LINE_BUDGET)) break;
            chunkItems.push(b.items[bIdx]);
            chunkH += ih;
            bIdx++;
          }
          cur.push({ t: 'bullets', ordered: false, items: chunkItems });
          curLines += chunkH;
          if (bIdx < b.items.length) flush();
        }
        return;
      }

      var w = blockVisualLines(b);
      if (pageHasBody(cur) && (curLines + w > PAGE_LINE_BUDGET)) {
        flush();
      }
      cur.push(b);
      curLines += w;
    });

    if (cur.length) pages.push(cur);
    if (!pages.length) pages.push([{ t: 'para', text: 'No report content generated yet.' }]);

    var total = pages.length;
    return {
      total: total,
      pages: pages,
      html: pages.map(function (pageBlocks, idx) {
        var pageNum = idx + 1;
        var pageContent = OBOL.report.toHtml(pageBlocks);
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
    var redact = !!ui.reportRedact;
    var hideUnreached = ui.reportHideUnreached !== false;
    var includeSecrets = !redact;
    var ctx = ctxOf(includeSecrets);
    var profileObj = OBOL.report.resolve(profile, ctx);
    var blocks = OBOL.report.document(profile, ctx);
    var stem = OBOL.report.filenameStem(profileObj, ctx);
    var paged = paginateBlocks(blocks, stem, profileObj.title);
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
      previewInner = '<div class="rep-sheet rep-sheet-continuous"><div class="rep-sheet-body">' + OBOL.report.toHtml(blocks) + '</div></div>';
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
      + '<label class="rep-opt" title="When checked, unreached phases, uncaptured flags, and boilerplate recommendations are hidden until supported by evidence"><input type="checkbox" id="rep-hide-unreached"' + (hideUnreached ? ' checked' : '') + '> Hide Unreached <span class="rep-opt-note">(' + (hideUnreached ? 'on, evidence only' : 'off, full skeleton') + ')</span></label>'
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

    document.querySelectorAll('.rep-prof-pill').forEach(function (pill) {
      pill.addEventListener('click', function () {
        var p = pill.getAttribute('data-prof');
        if (!p) return;
        OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.reportProfile = p; }, 'ui');
        OBOL.router.render();
      });
    });

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
    var hideUn = document.getElementById('rep-hide-unreached');
    if (hideUn) hideUn.addEventListener('change', function () {
      OBOL.store.update(function (e) { e.ui = e.ui || {}; e.ui.reportHideUnreached = hideUn.checked; }, 'ui');
      OBOL.router.render();
    });

    function refreshBody() {
      var e2 = activeEng(), ui2 = e2.ui || {};
      var c2 = ctxOf(!ui2.reportRedact);
      var p2 = ui2.reportProfile || OBOL.report.defaultFor(c2) || 'oscp';
      var profObj = OBOL.report.resolve(p2, c2);
      var blocks2 = OBOL.report.document(p2, c2);
      var stem2 = OBOL.report.filenameStem(profObj, c2);
      var viewMode2 = ui2.reportViewMode || 'pages';
      var sheetsWrap = document.getElementById('rep-sheets');
      if (sheetsWrap) {
        if (viewMode2 === 'md') {
          sheetsWrap.innerHTML = '<div class="rep-sheet rep-sheet-md"><pre class="rep-md-pre">' + esc(OBOL.report.toMarkdown(blocks2)) + '</pre></div>';
        } else if (viewMode2 === 'continuous') {
          sheetsWrap.innerHTML = '<div class="rep-sheet rep-sheet-continuous"><div class="rep-sheet-body">' + OBOL.report.toHtml(blocks2) + '</div></div>';
        } else {
          var pg = paginateBlocks(blocks2, stem2, profObj.title);
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
  OBOL.routes.report = { render: render, mounted: mounted, paginateBlocks: paginateBlocks };
})(typeof globalThis !== 'undefined' ? globalThis : this);
