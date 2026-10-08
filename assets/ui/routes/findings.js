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
    return '<span class="pill finding-host"' + (hn ? ' title="' + U.attr(host + '' + hn) + '"' : '') + '>'
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

  // ── Frameworks sub-views (ATT&CK matrix, Defensive, Compliance, CVEs) ──────────────────────
  function parentOf(id) { return String(id).indexOf('.') >= 0 ? String(id).split('.')[0] : String(id); }

  function fwModel() {
    try {
      if (!(OBOL.frameworks && OBOL.ATTACK && OBOL.ATTACK.techniques)) return null;
      var acts = (OBOL.store.active() || {}).activities || [];
      return OBOL.frameworks.compute(OBOL.store.factSet(), { activities: acts });
    } catch (e) { return null; }
  }

  var FW_TABS = [['findings', 'Findings'], ['attack', 'ATT&CK'], ['defensive', 'Defensive'], ['compliance', 'Compliance'], ['cves', 'CVEs']];
  function fwTabBar(active) {
    return '<div class="fw-tabs" role="tablist">' + FW_TABS.map(function (t) {
      return '<button type="button" class="fw-tab' + (t[0] === active ? ' active' : '') + '" data-fwview="' + t[0]
        + '" role="tab" aria-selected="' + (t[0] === active) + '">' + esc(t[1]) + '</button>';
    }).join('') + '</div>';
  }

  // One technique's defensive card: what you did, D3FEND countermeasures, ATT&CK detection, data
  // sources, mitigations. Reused by the Defensive view and the matrix cell detail.
  function techCardHtml(def) {
    return '<div class="fw-tech"><div class="fw-tech-h"><a href="' + U.attr(def.url || 'https://attack.mitre.org/techniques/' + def.id.replace('.', '/') + '/') + '" target="_blank" rel="noopener">' + esc(def.id) + '</a> ' + esc(def.name) + '</div>'
      + (def.findings && def.findings.length ? '<div class="fw-tech-row"><span class="mini-label">You Did</span> ' + def.findings.map(function (t) { return '<span class="fw-chip you">' + esc(t) + '</span>'; }).join('') + '</div>' : '')
      + (def.d3fend && def.d3fend.length ? '<div class="fw-tech-row"><span class="mini-label">D3FEND Counters</span> ' + def.d3fend.map(function (c) { return '<span class="fw-chip d3" title="' + U.attr(c.id) + '">' + esc(c.name) + '</span>'; }).join('') + '</div>' : '')
      + (def.detection ? '<div class="fw-tech-row"><span class="mini-label">Detect</span> <span class="fw-tech-det">' + esc(def.detection) + '</span></div>' : '')
      + (def.dataSources && def.dataSources.length ? '<div class="fw-tech-row"><span class="mini-label">Data Sources</span> ' + def.dataSources.map(function (d) { return '<span class="fw-chip">' + esc(d) + '</span>'; }).join('') + '</div>' : '')
      + (def.mitigations && def.mitigations.length ? '<div class="fw-tech-row"><span class="mini-label">ATT&CK Mitigations</span> ' + def.mitigations.map(function (d) { return '<span class="fw-chip">' + esc(d) + '</span>'; }).join('') + '</div>' : '')
      + '</div>';
  }

  function renderAttack(m) {
    var A = m.attack;
    if (!A.tactics.length || !A.usedTotal) {
      return '<p class="route-sub">No ATT&CK techniques are mapped from your current findings yet. As you prove more moves (and as the findings coverage grows), the matrix cells light up here. ATT&CK v' + esc(A.version || '') + '.</p>';
    }
    var usedCols = A.tactics.filter(function (c) { return c.usedCount; }).length;
    var kcStrip = '<div class="fw-kc">' + m.killchain.map(function (s, i) {
      var n = s.techniques.length;
      return (i ? '<span class="fw-kc-arrow">›</span>' : '') + '<span class="fw-kc-stage' + (n ? ' hit' : '') + '">' + esc(s.name) + (n ? ' <b>' + n + '</b>' : '') + '</span>';
    }).join('') + '</div>';
    var cols = A.tactics.map(function (col) {
      var cells = col.cells.map(function (c) {
        var aria = c.id + ' ' + c.name + (c.used ? ', used this engagement' + (c.subs.length ? ' (' + c.subs.length + ' sub-technique' + (c.subs.length === 1 ? '' : 's') + ')' : '') : ', not observed');
        return '<button type="button" class="fw-cell' + (c.used ? ' used' : '') + '" data-tech="' + U.attr(c.id) + '"'
          + ' aria-label="' + U.attr(aria) + '"' + (c.used ? '' : ' tabindex="-1"') + '>'
          + '<span class="fw-cell-n">' + esc(c.name) + '</span>'
          + (c.subs.length ? '<span class="fw-cell-st" aria-hidden="true">' + c.subs.length + '</span>' : '') + '</button>';
      }).join('');
      return '<div class="fw-col"><div class="fw-col-h"><span class="fw-col-n">' + esc(col.name) + '</span>'
        + '<span class="fw-col-c">' + col.total + ' technique' + (col.total === 1 ? '' : 's')
        + (col.usedCount ? '<span class="fw-col-hit">' + col.usedCount + ' used</span>' : '') + '</span></div>'
        + '<div class="fw-col-cells">' + cells + '</div></div>';
    }).join('');
    var mode = (((OBOL.store.active() || {}).ui || {}).fwMatrixMode === 'compact') ? 'compact' : 'labeled';
    var toggle = '<div class="fw-mx-toggle" role="group" aria-label="Matrix density">'
      + '<button type="button" class="fw-mx-btn' + (mode === 'labeled' ? ' active' : '') + '" data-fwmx="labeled">Labeled</button>'
      + '<button type="button" class="fw-mx-btn' + (mode === 'compact' ? ' active' : '') + '" data-fwmx="compact">Compact</button></div>';
    return '<p class="route-sub">Your ATT&CK coverage this engagement: <b>' + A.usedTotal + '</b> technique' + (A.usedTotal === 1 ? '' : 's') + ' across <b>' + usedCols + '</b> tactic' + (usedCols === 1 ? '' : 's') + '. Coloured by what you did: a blue team’s SIEM would be trying to detect these. Click a lit cell for detail. ATT&CK v' + esc(A.version || '') + '.</p>'
      + kcStrip + toggle
      + '<div class="fw-matrix-wrap"><div class="fw-matrix fw-matrix--' + mode + '">' + cols + '</div></div>'
      + '<div id="fw-detail" class="fw-detail"><p class="fw-detail-hint">Select a lit technique above to see what you did, how it is detected, and how it is countered.</p></div>';
  }

  // The detail for one matrix cell: every used technique under it (the cell id, or its sub-techniques).
  function techDetail(m, cellId) {
    var ids = Object.keys(m.use).filter(function (u) { return u === cellId || parentOf(u) === cellId; });
    var defs = ids.map(function (id) { return m.defensive.find(function (d) { return d.id === id; }); }).filter(Boolean);
    if (!defs.length) return '<p class="fw-detail-hint">Nothing recorded for this technique.</p>';
    return defs.map(techCardHtml).join('');
  }

  // The cursor-following hover card for an ATT&CK matrix cell (works in Labeled and Compact alike).
  // For a LIT cell it flips to the engagement: the findings that evidence it (severity + CVE/KEV), the
  // commands you actually ran, its used sub-techniques, then the blue-team view (how it is detected and
  // countered). For an UNLIT cell it teaches: what the technique is and how a defender would spot it.
  function fwHoverHtml(m, cellId) {
    var cat = (OBOL.ATTACK && OBOL.ATTACK.techniques) || {};
    var tacs = (OBOL.ATTACK && OBOL.ATTACK.tactics) || [];
    var t = cat[cellId] || {};
    var ids = Object.keys(m.use).filter(function (u) { return u === cellId || parentOf(u) === cellId; });
    var tacNames = (t.ta || []).map(function (s) { var ta = tacs.find(function (x) { return x.id === s; }); return ta ? ta.name : s; });
    var head = '<div class="fw-hc-h"><span class="fw-hc-id">' + esc(cellId) + '</span> <span class="fw-hc-n">' + esc(t.n || cellId) + '</span></div>'
      + (tacNames.length ? '<div class="fw-hc-tac">' + tacNames.map(function (n) { return '<span class="fw-hc-tag">' + esc(n) + '</span>'; }).join('') + '</div>' : '');

    if (!ids.length) {
      var un = '<div class="fw-hc-un">Not observed this engagement.</div>';
      if (t.det) un += '<div class="fw-hc-row"><span class="fw-hc-lbl">A Defender Spots It By</span> ' + esc(String(t.det).slice(0, 220)) + (String(t.det).length > 220 ? '…' : '') + '</div>';
      return '<div class="fw-hovercard not-used">' + head + un + '</div>';
    }

    var fins = [], moves = [], subs = {}, det = t.det || '', d3names = {};
    ids.forEach(function (u) {
      if (u !== cellId) subs[u] = 1;
      (m.use[u] || []).forEach(function (c) { if (c.k === 'm') moves.push(c); else fins.push(c); });
      var d = m.defensive.find(function (x) { return x.id === u; });
      if (d) { if (!det && d.detection) det = d.detection; (d.d3fend || []).forEach(function (c) { d3names[c.name] = 1; }); }
    });

    var body = '';
    if (fins.length) {
      body += '<div class="fw-hc-lbl">In This Engagement</div><ul class="fw-hc-list">' + fins.slice(0, 6).map(function (c) {
        return '<li>' + (c.sev ? '<span class="sev-chip sev-' + esc(normSev(c.sev)) + '">' + esc(normSev(c.sev)) + '</span> ' : '') + esc(c.t)
          + (c.cve ? ' <span class="fw-hc-cve">' + esc(c.cve) + '</span>' : '')
          + (c.kev ? ' <span class="fw-hc-kev">KEV</span>' : '') + '</li>';
      }).join('') + '</ul>' + (fins.length > 6 ? '<div class="fw-hc-more">plus ' + (fins.length - 6) + ' more</div>' : '');
    }
    if (moves.length) {
      body += '<div class="fw-hc-lbl">You Ran</div><ul class="fw-hc-cmds">' + moves.slice(0, 4).map(function (c) {
        return '<li><code>' + esc(String(c.t).slice(0, 72)) + (String(c.t).length > 72 ? '…' : '') + '</code></li>';
      }).join('') + '</ul>' + (moves.length > 4 ? '<div class="fw-hc-more">plus ' + (moves.length - 4) + ' more</div>' : '');
    }
    if (Object.keys(subs).length) {
      body += '<div class="fw-hc-row"><span class="fw-hc-lbl">Sub-Techniques</span> ' + Object.keys(subs).sort().map(function (s) { return '<span class="fw-hc-tag">' + esc(s) + '</span>'; }).join('') + '</div>';
    }
    if (det) body += '<div class="fw-hc-row"><span class="fw-hc-lbl">Blue Team Detects</span> ' + esc(String(det).slice(0, 170)) + (String(det).length > 170 ? '…' : '') + '</div>';
    if (Object.keys(d3names).length) body += '<div class="fw-hc-row"><span class="fw-hc-lbl">Countered By</span> ' + Object.keys(d3names).slice(0, 4).map(function (n) { return '<span class="fw-hc-tag d3">' + esc(n) + '</span>'; }).join('') + '</div>';
    body += '<div class="fw-hc-foot">Click for full detail</div>';
    return '<div class="fw-hovercard">' + head + body + '</div>';
  }

  var D3_TACTIC_DEF = {
    Model: 'Asset inventory and modelling', Harden: 'Reduce the attack surface before an attack',
    Detect: 'Identify adversary activity', Isolate: 'Contain and limit access',
    Deceive: 'Mislead the adversary', Evict: 'Remove the adversary', Restore: 'Return to a known-good state',
  };
  function renderDefensive(m) {
    if (!m.defensive.length) return '<p class="route-sub">No techniques to defend against yet. Prove some findings first.</p>';
    var out = '<p class="route-sub">How a blue team catches and stops what you did, as the MITRE D3FEND defensive-tactic matrix. Each countermeasure below counters one or more of the ATT&CK techniques you used.</p>';
    // the D3FEND matrix: coloured tactic columns with the countermeasures that answer your findings
    var d3 = m.d3fend || { tactics: [] };
    if (d3.tactics.length) {
      out += '<div class="fw-d3-wrap"><div class="fw-d3-matrix">' + d3.tactics.map(function (col) {
        var cls = 'd3t-' + col.tactic.toLowerCase();
        var cells = col.items.map(function (it) {
          return '<div class="fw-d3-cell ' + cls + '" title="' + U.attr(it.id + '  ' + it.name + '  (counters ' + it.counters.join(', ') + ')') + '">'
            + '<span class="fw-d3-n">' + esc(it.name) + '</span>'
            + '<span class="fw-d3-c">' + it.counters.length + '</span></div>';
        }).join('');
        return '<div class="fw-d3-col"><div class="fw-d3-h ' + cls + '"><span class="fw-d3-tn">' + esc(col.tactic) + '</span>'
          + '<span class="fw-d3-td">' + esc(D3_TACTIC_DEF[col.tactic] || '') + '</span></div>'
          + '<div class="fw-d3-cells">' + cells + '</div></div>';
      }).join('') + '</div></div>';
    }
    // per-ATT&CK-technique detail (detection, data sources, mitigations) below the matrix
    out += '<h2 class="coach-sec-h">Per Technique</h2><div class="fw-tech-grid">' + m.defensive.map(techCardHtml).join('') + '</div>';
    return out;
  }

  function complianceSection(title, list, opts) {
    opts = opts || {};
    if (!list.length) {
      return opts.showEmpty ? '<div class="fw-comp-sec' + (opts.dim ? ' dim' : '') + '"><h3>' + esc(title) + '</h3><p class="fw-empty">' + esc(opts.emptyMsg || 'None mapped from your findings yet.') + '</p></div>' : '';
    }
    return '<div class="fw-comp-sec"><h3>' + esc(title) + ' <span class="fw-comp-n">' + list.length + '</span></h3>'
      + '<ul class="fw-comp-list">' + list.map(function (e) {
          return '<li><span class="fw-comp-k">' + esc(e.title || e.key) + (e.csf ? ' <span class="fw-csf">' + esc(e.csf) + '</span>' : '') + '</span>'
            + '<span class="fw-comp-f">' + e.findings.length + ' finding' + (e.findings.length === 1 ? '' : 's') + '</span></li>';
        }).join('') + '</ul></div>';
  }
  function renderCompliance(m) {
    var c = m.compliance;
    if (!(c.nist.length || c.cis.length || c.pci.length || c.cwe.length || c.owasp.length)) {
      return '<p class="route-sub">No compliance mappings from your current findings yet.</p>';
    }
    return '<p class="route-sub">Controls and weakness classes your findings map to, for the report and the blue-team conversation. CIS and PCI fill in as the findings coverage grows.</p>'
      + '<div class="fw-comp-grid">'
      + complianceSection('NIST SP 800-53', c.nist, { showEmpty: true })
      + complianceSection('NIST CSF Function', [], { showEmpty: false })
      + complianceSection('CIS Controls v8', c.cis, { showEmpty: true, emptyMsg: 'Populated as the findings coverage pass maps CIS safeguards.' })
      + complianceSection('PCI DSS v4', c.pci, { showEmpty: true, dim: true, emptyMsg: 'Shown when the engagement touches cardholder-data scope.' })
      + complianceSection('CWE (Weakness Class)', c.cwe, { showEmpty: true })
      + complianceSection('OWASP Top 10', c.owasp, { showEmpty: true })
      + '</div>';
  }

  function renderCves(m) {
    if (!m.cves.length) return '<p class="route-sub">No CVEs detected in your findings yet.</p>';
    var kevN = m.cves.filter(function (c) { return c.kev; }).length;
    return '<p class="route-sub"><b>' + m.cves.length + '</b> CVE' + (m.cves.length === 1 ? '' : 's') + ' detected'
      + (kevN ? ', <b>' + kevN + '</b> actively exploited (CISA KEV)' : '') + '. Actively-exploited first.</p>'
      + '<div class="fw-cve-list">' + m.cves.map(function (c) {
          var fix = (c.findings.find(function (x) { return x.remediation; }) || {}).remediation || '';
          return '<div class="fw-cve' + (c.kev ? ' kev' : '') + '"><div class="fw-cve-h">'
            + '<a href="https://nvd.nist.gov/vuln/detail/' + U.attr(c.cve) + '" target="_blank" rel="noopener">' + esc(c.cve) + '</a>'
            + (c.kev ? '<span class="fw-badge kev">Actively Exploited (KEV)</span>' : '')
            + (c.ransomware ? '<span class="fw-badge rw">Ransomware</span>' : '')
            + (c.due ? '<span class="fw-cve-due">CISA due ' + esc(c.due) + '</span>' : '') + '</div>'
            + '<div class="fw-cve-f">' + c.findings.map(function (x) { return '<span class="sev-chip sev-' + esc(normSev(x.severity)) + '">' + esc(normSev(x.severity)) + '</span> ' + esc(x.title); }).join('<br>') + '</div>'
            + (fix ? '<div class="finding-fix"><span class="mini-label">Fix</span> ' + esc(fix) + '</div>' : '') + '</div>';
        }).join('') + '</div>';
  }

  // The classic Findings list (severity/target grouped), extracted so the sub-tab can switch to it.
  function renderFindingsList(findings) {
    var bySev = {}; SEV_ORDER.forEach(function (s) { bySev[s] = []; });
    findings.forEach(function (f) { (bySev[f.severity] = bySev[f.severity] || []).push(f); });
    var counts = SEV_ORDER.filter(function (s) { return bySev[s].length; })
      .map(function (s) { return '<span class="sev-count sev-' + s + '">' + bySev[s].length + ' ' + s + '</span>'; }).join('');
    var hostCount = (function () { var h = {}; findings.forEach(function (f) { h[f.host] = 1; }); return Object.keys(h).length; })();
    var sort = ((OBOL.store.active() || {}).ui || {}).findingsSort === 'target' ? 'target' : 'severity';
    var toggle = hostCount > 1
      ? '<div class="findings-sort" role="group" aria-label="Group findings by"><span class="mini-label">Group by</span>'
        + '<button type="button" class="fsort-btn' + (sort === 'severity' ? ' active' : '') + '" data-fsort="severity">Severity</button>'
        + '<button type="button" class="fsort-btn' + (sort === 'target' ? ' active' : '') + '" data-fsort="target">Target</button></div>'
      : '';
    var body = (sort === 'target' && hostCount > 1) ? byTarget(findings) : bySeverity(findings);
    return toggle
      + '<p class="route-sub">Catalogued, proof-bound findings across ' + hostCount + ' host' + (hostCount === 1 ? '' : 's')
      + ' (' + findings.length + '). ' + counts + '</p>' + body;
  }

  function render() {
    var findings = gather();
    var active = ((OBOL.store.active() || {}).ui || {}).findingsView || 'findings';
    if (active !== 'findings' && !findings.length) active = 'findings';
    var head = '<section class="findings-route"><div class="findings-head"><h1 class="route-h1">Findings</h1></div>' + fwTabBar(active);

    if (active === 'findings') {
      if (!findings.length) {
        return head + '<p class="route-sub">No findings yet. Run coach moves and paste the output on Evidence, every move that carries a report finding (anonymous bind, AS-REP roastable, weak password, exposed shares, HTTP/TLS checks…) rolls up here across every host once it is proven. The ATT&CK, Defensive, Compliance and CVE views light up from these.</p></section>';
      }
      return head + renderFindingsList(findings) + '</section>';
    }
    var m = fwModel();
    if (!m || !m.ready) return head + '<p class="route-sub">Framework data is still loading. Reopen this view in a moment.</p></section>';
    var body = active === 'attack' ? renderAttack(m)
      : active === 'defensive' ? renderDefensive(m)
      : active === 'compliance' ? renderCompliance(m)
      : active === 'cves' ? renderCves(m) : '';
    return head + body + '</section>';
  }

  function mounted(ctx) {
    var mount = (ctx && ctx.mount) || document;
    U.on(mount, 'click', '.fsort-btn', function (e, t) {
      var v = t.getAttribute('data-fsort') === 'target' ? 'target' : 'severity';
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.findingsSort = v; }, 'ui');
      OBOL.router.render();
    });
    // sub-view tabs (Findings / ATT&CK / Defensive / Compliance / CVEs)
    U.on(mount, 'click', '.fw-tab', function (e, t) {
      var v = t.getAttribute('data-fwview') || 'findings';
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.findingsView = v; }, 'ui');
      OBOL.router.render();
    });
    // ATT&CK matrix density toggle (Labeled chips <-> Compact square heatmap), swapped in place.
    U.on(mount, 'click', '.fw-mx-btn', function (e, b) {
      var mode = b.getAttribute('data-fwmx') === 'compact' ? 'compact' : 'labeled';
      var mx = mount.querySelector('.fw-matrix');
      if (mx) { mx.classList.remove('fw-matrix--labeled', 'fw-matrix--compact'); mx.classList.add('fw-matrix--' + mode); }
      mount.querySelectorAll('.fw-mx-btn').forEach(function (x) { x.classList.toggle('active', x === b); });
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.fwMatrixMode = mode; }, 'ui');
    });

    // matrix cell -> technique detail (ATT&CK view), rendered in place without a full re-render
    U.on(mount, 'click', '.fw-cell.used', function (e, t) {
      var id = t.getAttribute('data-tech'); if (!id) return;
      var slot = document.getElementById('fw-detail'); if (!slot) return;
      var m = fwModel(); if (!m) return;
      mount.querySelectorAll('.fw-cell.sel').forEach(function (c) { c.classList.remove('sel'); });
      t.classList.add('sel');
      slot.innerHTML = techDetail(m, id);
      try { slot.scrollIntoView({ block: 'nearest' }); } catch (x) {}
    });

    // Rich cursor-following hover card over ATT&CK cells (Labeled and Compact). Built from the cached
    // model; the card lives on <body> (so it floats above the scroll container) and follows the pointer.
    (function () {
      var wrap = mount.querySelector('.fw-matrix-wrap'); if (!wrap) return;
      // drop any stale float from a prior mount so the body node never accumulates
      document.querySelectorAll('.fw-hovercard-float').forEach(function (n) { n.remove(); });
      var card = null, curId = null, model = null;
      function ensure() { if (!card) { card = document.createElement('div'); card.className = 'fw-hovercard-float'; card.setAttribute('aria-hidden', 'true'); document.body.appendChild(card); } return card; }
      function place(x, y) {
        var c = card; if (!c) return;
        var w = c.offsetWidth || 300, h = c.offsetHeight || 150, vw = window.innerWidth, vh = window.innerHeight;
        var left = x + 16; if (left + w > vw - 8) left = x - w - 16; if (left < 8) left = 8;
        var top = y + 18; if (top + h > vh - 8) top = y - h - 18; if (top < 8) top = 8;
        c.style.left = left + 'px'; c.style.top = top + 'px';
      }
      function show(cell, x, y) {
        var id = cell.getAttribute('data-tech'); if (!id) { hide(); return; }
        if (!model) model = fwModel(); if (!model) return;
        if (id !== curId) { ensure().innerHTML = fwHoverHtml(model, id); curId = id; }
        card.classList.add('on'); place(x, y);
      }
      function hide() { if (card) card.classList.remove('on'); curId = null; }
      wrap.addEventListener('mousemove', function (e) {
        var cell = e.target && e.target.closest ? e.target.closest('.fw-cell') : null;
        if (cell) show(cell, e.clientX, e.clientY); else hide();
      });
      wrap.addEventListener('mouseleave', hide);
    })();
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.findings = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
