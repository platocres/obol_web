/*!
 * obol ui — routes/findings.js — cross-host findings roll-up (parity with obol-local `obol findings`).
 * Gathers finding.<category> facts across every host in the engagement, grouped by severity then
 * category, each with its host (scope), evidence, and remediation (enriched from reportmeta when
 * that bundle is loaded). Read-only projection over the fact ledger — nothing is invented.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  var SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  function normSev(s) { s = String(s || '').toLowerCase(); return SEV_ORDER.indexOf(s) >= 0 ? s : 'info'; }

  function gather() {
    var facts = OBOL.store.factSet();
    var meta = root.OBOL_REPORTMETA || null;
    var out = [];
    facts.facts.forEach(function (f) {
      if (f.state !== 'supported' || f.kind.indexOf('finding.') !== 0) return;
      var v = f.value || {};
      var enrich = (meta && (v.card || v.lane) && meta.cards) ? (meta.cards[v.card] || {}) : {};
      out.push({
        title: v.title || v.name || f.kind.split('.').slice(1).join('.'),
        category: v.category || f.kind.split('.')[1] || 'finding',
        severity: normSev(v.severity),
        host: (f.scope || '').replace(/^host:/, '').replace(/^domain:/, '') || 'engagement',
        evidence: v.evidence || v.detail || '',
        remediation: v.remediation || v.fix || enrich.fix || '',
        refs: v.cve || enrich.cve || '',
      });
    });
    return out;
  }

  function render() {
    var findings = gather();
    if (!findings.length) {
      return '<section class="findings-route"><h1 class="route-h1">Findings</h1>'
        + '<p class="route-sub">No findings yet. Run the findings-check moves (HTTP headers, TLS, methods, CORS, DNS email, component CVEs…) and paste the output on Evidence — catalogued findings roll up here across every host.</p></section>';
    }
    var bySev = {}; SEV_ORDER.forEach(function (s) { bySev[s] = []; });
    findings.forEach(function (f) { (bySev[f.severity] = bySev[f.severity] || []).push(f); });

    var counts = SEV_ORDER.filter(function (s) { return bySev[s].length; })
      .map(function (s) { return '<span class="sev-count sev-' + s + '">' + bySev[s].length + ' ' + s + '</span>'; }).join('');

    var body = SEV_ORDER.filter(function (s) { return bySev[s].length; }).map(function (s) {
      var rows = bySev[s].map(function (f) {
        return '<article class="finding sev-' + s + '"><div class="finding-head">'
          + '<span class="sev-chip sev-' + s + '">' + s + '</span>'
          + '<span class="finding-title">' + esc(f.title) + '</span>'
          + '<span class="pill">' + esc(f.host) + '</span>'
          + '<span class="finding-cat">' + esc(f.category) + '</span></div>'
          + (f.evidence ? '<div class="finding-ev"><span class="mini-label">evidence</span> ' + esc(String(f.evidence).slice(0, 300)) + '</div>' : '')
          + (f.remediation ? '<div class="finding-fix"><span class="mini-label">fix</span> ' + esc(f.remediation) + '</div>' : '')
          + (f.refs ? '<div class="finding-refs">' + esc(f.refs) + '</div>' : '')
          + '</article>';
      }).join('');
      return '<div class="finding-group">' + rows + '</div>';
    }).join('');

    return '<section class="findings-route"><h1 class="route-h1">Findings</h1>'
      + '<p class="route-sub">Catalogued, proof-bound findings across all hosts (' + findings.length + '). ' + counts + '</p>'
      + body + '</section>';
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.findings = { render: render };
})(typeof globalThis !== 'undefined' ? globalThis : this);
