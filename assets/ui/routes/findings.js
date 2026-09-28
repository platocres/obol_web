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

  // Resolve a host key (an IP, or "engagement"/"domain:…") to its proven identity so a finding can carry
  // both the IP and the hostname — the anchor a severity-sorted list needs to say *which box* it is on.
  function identity(host) {
    if (!host || /[^0-9.]/.test(host)) return { ip: host, hostname: '' };
    try { return (OBOL.store && OBOL.store.targetIdentity) ? OBOL.store.targetIdentity(host) : { ip: host, hostname: '' }; }
    catch (e) { return { ip: host, hostname: '' }; }
  }
  function hostPill(host) {
    var id = identity(host), hn = id && id.hostname ? id.hostname : '';
    return '<span class="pill finding-host"' + (hn ? ' title="' + U.attr(host + ' — ' + hn) + '"' : '') + '>'
      + esc(host) + (hn ? '<span class="finding-hostname">' + esc(hn) + '</span>' : '') + '</span>';
  }

  function findingCard(f, showHost) {
    return '<article class="finding sev-' + f.severity + '"><div class="finding-head">'
      + '<span class="sev-chip sev-' + f.severity + '">' + f.severity + '</span>'
      + '<span class="finding-title">' + esc(f.title) + '</span>'
      + (showHost ? hostPill(f.host) : '')
      + '<span class="finding-cat">' + esc(f.category) + '</span></div>'
      + (f.evidence ? '<div class="finding-ev"><span class="mini-label">Evidence</span> ' + esc(String(f.evidence).slice(0, 300)) + '</div>' : '')
      + (f.remediation ? '<div class="finding-fix"><span class="mini-label">Fix</span> ' + esc(f.remediation) + '</div>' : '')
      + (f.refs ? '<div class="finding-refs">' + esc(f.refs) + '</div>' : '')
      + '</article>';
  }
  function sevRank(s) { var i = SEV_ORDER.indexOf(s); return i < 0 ? SEV_ORDER.length : i; }

  // Grouped by severity (worst first); each finding names its host+hostname so the roll-up doubles as
  // the report's severity-ordered finding list.
  function bySeverity(findings) {
    var bySev = {}; SEV_ORDER.forEach(function (s) { bySev[s] = []; });
    findings.forEach(function (f) { (bySev[f.severity] = bySev[f.severity] || []).push(f); });
    return SEV_ORDER.filter(function (s) { return bySev[s].length; }).map(function (s) {
      return '<div class="finding-group">' + bySev[s].map(function (f) { return findingCard(f, true); }).join('') + '</div>';
    }).join('');
  }
  // Grouped by target (each box's worst severity first); within a host, findings are severity-ordered.
  function byTarget(findings) {
    var byHost = {}, order = [];
    findings.forEach(function (f) { if (!byHost[f.host]) { byHost[f.host] = []; order.push(f.host); } byHost[f.host].push(f); });
    order.sort(function (a, b) {
      var wa = Math.min.apply(null, byHost[a].map(function (f) { return sevRank(f.severity); }));
      var wb = Math.min.apply(null, byHost[b].map(function (f) { return sevRank(f.severity); }));
      return wa - wb || byHost[b].length - byHost[a].length || String(a).localeCompare(String(b));
    });
    return order.map(function (host) {
      var group = byHost[host].slice().sort(function (a, b) { return sevRank(a.severity) - sevRank(b.severity); });
      var id = identity(host), hn = id && id.hostname ? id.hostname : '';
      var breakdown = SEV_ORDER.filter(function (s) { return group.some(function (f) { return f.severity === s; }); })
        .map(function (s) { var n = group.filter(function (f) { return f.severity === s; }).length;
          return '<span class="sev-count sev-' + s + '">' + n + ' ' + s + '</span>'; }).join('');
      return '<div class="finding-host-group">'
        + '<div class="finding-host-h"><span class="fhh-ip">' + esc(host) + '</span>'
        + (hn ? '<span class="fhh-name">' + esc(hn) + '</span>' : '')
        + '<span class="fhh-count">' + group.length + ' finding' + (group.length === 1 ? '' : 's') + '</span>'
        + '<span class="fhh-sevs">' + breakdown + '</span></div>'
        + '<div class="finding-group">' + group.map(function (f) { return findingCard(f, false); }).join('') + '</div></div>';
    }).join('');
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

    var hostCount = (function () { var h = {}; findings.forEach(function (f) { h[f.host] = 1; }); return Object.keys(h).length; })();
    var sort = ((OBOL.store.active() || {}).ui || {}).findingsSort === 'target' ? 'target' : 'severity';
    var toggle = hostCount > 1
      ? '<div class="findings-sort" role="group" aria-label="Group findings by">'
        + '<span class="mini-label">Group by</span>'
        + '<button type="button" class="fsort-btn' + (sort === 'severity' ? ' active' : '') + '" data-fsort="severity">Severity</button>'
        + '<button type="button" class="fsort-btn' + (sort === 'target' ? ' active' : '') + '" data-fsort="target">Target</button>'
        + '</div>'
      : '';
    var body = (sort === 'target' && hostCount > 1) ? byTarget(findings) : bySeverity(findings);

    return '<section class="findings-route"><div class="findings-head"><h1 class="route-h1">Findings</h1>' + toggle + '</div>'
      + '<p class="route-sub">Catalogued, proof-bound findings across ' + hostCount + ' host' + (hostCount === 1 ? '' : 's')
      + ' (' + findings.length + '). ' + counts + '</p>'
      + body + '</section>';
  }

  function mounted(ctx) {
    var mount = (ctx && ctx.mount) || document;
    U.on(mount, 'click', '.fsort-btn', function (e, t) {
      var v = t.getAttribute('data-fsort') === 'target' ? 'target' : 'severity';
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.findingsSort = v; }, 'ui');
      OBOL.router.render();
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.findings = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
