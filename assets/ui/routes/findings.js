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

  // Attribute a catalog finding to a host: the first host-scoped fact of one of the kinds that
  // triggered the match (host:<ip> → ip). If it matched only on domain-/engagement-scoped facts
  // (or on flag/header/tech observations with no trigger kinds), fall back to the primary target.
  function hostForFinding(facts, triggerKinds, primary) {
    if (triggerKinds && triggerKinds.length) {
      var tk = {}; triggerKinds.forEach(function (k) { tk[k] = 1; });
      for (var i = 0; i < facts.facts.length; i++) {
        var f = facts.facts[i];
        if (f.state === 'supported' && tk[f.kind] && String(f.scope).indexOf('host:') === 0) {
          return f.scope.slice(5);
        }
      }
    }
    return primary;
  }

  function gather() {
    var facts = OBOL.store.factSet();
    var meta = root.OBOL_REPORTMETA || null;
    var out = [], seen = {};
    function push(fnd) {
      var key = fnd.title.toLowerCase() + '|' + fnd.host;
      if (seen[key]) return; seen[key] = 1; out.push(fnd);
    }
    // 1) catalogued finding.* facts (web-check parsers), enriched from reportmeta when loaded.
    facts.facts.forEach(function (f) {
      if (f.state !== 'supported' || f.kind.indexOf('finding.') !== 0) return;
      var v = f.value || {};
      var enrich = (meta && (v.card || v.lane) && meta.cards) ? (meta.cards[v.card] || {}) : {};
      push({
        title: v.title || v.name || f.kind.split('.').slice(1).join('.'),
        category: v.category || f.kind.split('.')[1] || 'finding',
        severity: normSev(v.severity),
        host: (f.scope || '').replace(/^host:/, '').replace(/^domain:/, '') || 'engagement',
        evidence: v.evidence || v.detail || '',
        remediation: v.remediation || v.fix || enrich.fix || '',
        refs: v.cve || enrich.cve || '',
      });
    });
    // 2) derive findings from what the operator actually RAN and PROVED: an activity whose action
    // carries a report block and that minted at least one fact IS a finding (no over-claim — it's
    // tied to real evidence). This is what fills the roll-up on AD/host boxes with no web checks.
    var eng = OBOL.store.active() || {};
    var actions = (OBOL.packs && OBOL.packs.actions) ? OBOL.packs.actions() : [];
    var byId = {}; actions.forEach(function (a) { byId[a.id] = a; });
    (eng.activities || []).forEach(function (act) {
      if (!act || !act.action_id || !(act.produced || []).length) return;
      var a = byId[act.action_id]; if (!a || !a.report || !a.report.finding) return;
      var sev = normSev(a.report.severity);
      if (sev === 'info') return; // skip informational-only recon notes
      push({
        title: a.report.finding,
        category: (a.produces && a.produces[0] ? a.produces[0].split('.')[0] : 'finding'),
        severity: sev,
        host: (act.scope || '').replace(/^host:/, '').replace(/^domain:/, '') || act.target || 'engagement',
        evidence: act.command || '',
        remediation: '', refs: '',
      });
    });
    // 3) fact-driven catalog findings: the ported match engine (assets/engine/findings.js) matched
    // against the cross-host fact ledger. Each is attributed to the host whose facts triggered it.
    if (OBOL.findings && OBOL.findings.assess) {
      var primary = (eng.targets && eng.targets[0] && eng.targets[0].ip) || 'engagement';
      OBOL.findings.assess(facts).forEach(function (v) {
        push({
          title: v.title,
          category: v.category || 'finding',
          severity: normSev(v.severity),
          host: hostForFinding(facts, v.trigger_kinds, primary),
          evidence: v.evidence || '',
          remediation: v.remediation || '',
          refs: v.cve || (v.refs && v.refs.length ? v.refs[0] : '') || '',
        });
      });
    }
    return out;
  }

  function render() {
    var findings = gather();
    if (!findings.length) {
      return '<section class="findings-route"><h1 class="route-h1">Findings</h1>'
        + '<p class="route-sub">No findings yet. Run coach moves and paste the output on Evidence — every move that carries a report finding (anonymous bind, AS-REP roastable, weak password, exposed shares, HTTP/TLS checks…) rolls up here across every host once it is proven.</p></section>';
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
