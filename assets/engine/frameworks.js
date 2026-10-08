/*!
 * obol engine — frameworks.js
 * Map the engagement's findings (and the ATT&CK techniques they carry) onto security frameworks for
 * the Frameworks view: MITRE ATT&CK (an offensive coverage matrix, flipped from Splunk's defensive
 * one), the Lockheed Cyber Kill Chain, MITRE D3FEND countermeasures + ATT&CK detection (the defensive
 * lens), and a compliance rollup (NIST 800-53 / CSF, CIS v8, PCI v4, CWE, OWASP), plus detected CVEs
 * with the CISA KEV "actively exploited" flag.
 *
 * Pure projection over OBOL.findings.assess(fs) + the bundled reference data (OBOL.ATTACK, OBOL.D3FEND,
 * OBOL.FRAMEWORK_TABLES, OBOL.KEV). No network, no writes, no ranker involvement. A technique counts as
 * "used" when a matched finding carries it (a recorded move proves a finding, so this is the recorded-
 * moves-to-ATT&CK trail); a sub-technique lights its parent's matrix cell and is listed in the detail.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function A() { return OBOL.ATTACK || { tactics: [], techniques: {} }; }
  function D() { return OBOL.D3FEND || { names: {}, map: {} }; }
  function T() { return OBOL.FRAMEWORK_TABLES || {}; }
  function parentOf(id) { return String(id).indexOf('.') >= 0 ? String(id).split('.')[0] : String(id); }

  // The set of ATT&CK techniques the engagement touched, from the matched findings' `attack` field,
  // each with the findings that evidence it.
  function techniqueUse(findings) {
    var use = {}; // Txxxx (as authored, may be a sub) -> [finding titles]
    (findings || []).forEach(function (f) {
      if (!f.attack) return;
      var label = f.title || f.key || '';
      var arr = use[f.attack] = use[f.attack] || [];
      if (arr.indexOf(label) < 0) arr.push(label);
    });
    return use;
  }

  // The ATT&CK matrix model: every tactic (in matrix order) with its TOP-LEVEL techniques as cells; a
  // cell is "used" if the technique or any of its sub-techniques was used. Mirrors Splunk's matrix,
  // coloured by what YOU did rather than what a defender can detect.
  function attackMatrix(use) {
    var cat = A();
    var usedTop = {};    // top-level technique id -> { subs:{}, findings:[] }
    Object.keys(use).forEach(function (tid) {
      var top = parentOf(tid);
      var rec = usedTop[top] = usedTop[top] || { subs: {}, findings: [] };
      if (tid !== top) rec.subs[tid] = 1;
      use[tid].forEach(function (k) { if (rec.findings.indexOf(k) < 0) rec.findings.push(k); });
    });
    var tactics = (cat.tactics || []).map(function (ta) {
      var cells = [];
      Object.keys(cat.techniques).forEach(function (id) {
        var t = cat.techniques[id];
        if (t.sub) return;                       // cells are top-level techniques
        if ((t.ta || []).indexOf(ta.id) < 0) return;
        var u = usedTop[id];
        cells.push({
          id: id, name: t.n, used: !!u,
          subs: u ? Object.keys(u.subs).sort() : [],
          findings: u ? u.findings.slice() : [],
        });
      });
      cells.sort(function (a, b) { return (b.used - a.used) || (a.id < b.id ? -1 : 1); });
      return { id: ta.id, name: ta.name, cells: cells, usedCount: cells.filter(function (c) { return c.used; }).length, total: cells.length };
    }).filter(function (col) { return col.total > 0; });
    var usedTotal = Object.keys(usedTop).length;
    return { tactics: tactics, usedTop: usedTop, usedTotal: usedTotal, version: cat.version };
  }

  // Lockheed Cyber Kill Chain rollup: used techniques bucketed by stage (via the tactic -> stage map).
  function killChain(use) {
    var tbl = T(), cat = A();
    var kc = tbl.KILL_CHAIN || [], tacToKc = tbl.ATTACK_TACTIC_TO_KC || {};
    var buckets = {};
    Object.keys(use).forEach(function (tid) {
      var t = cat.techniques[tid] || cat.techniques[parentOf(tid)];
      var tactics = (t && t.ta) || [];
      var seen = {};
      tactics.forEach(function (ta) {
        var stage = tacToKc[ta]; if (!stage || seen[stage]) return; seen[stage] = 1;
        (buckets[stage] = buckets[stage] || []).push({ id: tid, name: (cat.techniques[tid] || {}).n || tid });
      });
    });
    return kc.map(function (s) { return { id: s.id, name: s.name, techniques: buckets[s.id] || [] }; });
  }

  // Defensive lens: for each USED technique, its D3FEND countermeasures + ATT&CK detection + data sources
  // + ATT&CK's own mitigations. "How a blue team catches and stops what you did."
  function defensive(use) {
    var cat = A(), d3 = D();
    return Object.keys(use).sort().map(function (tid) {
      var t = cat.techniques[tid] || {};
      var codes = d3.map[tid] || d3.map[parentOf(tid)] || [];
      var d3fend = codes.map(function (c) { return { id: c, name: d3.names[c] || c }; });
      return {
        id: tid, name: t.n || tid, url: t.url || '',
        detection: t.det || '', dataSources: t.ds || [], mitigations: t.mit || [],
        d3fend: d3fend, findings: use[tid].slice(),
      };
    });
  }

  // Compliance rollup from the matched findings' framework fields. CIS/PCI light up once the coverage
  // pass populates them; NIST/CWE/OWASP are populated today.
  function compliance(findings) {
    var tbl = T();
    var nistFam = tbl.NIST_FAMILY || {}, famCsf = tbl.NIST_FAMILY_TO_CSF || {}, cisV8 = tbl.CIS_V8 || {}, pciV4 = tbl.PCI_V4 || {};
    function group() { return { map: {}, list: [] }; }
    function add(g, key, title, fk) {
      var e = g.map[key]; if (!e) { e = g.map[key] = { key: key, title: title, findings: [] }; g.list.push(e); }
      if (fk && e.findings.indexOf(fk) < 0) e.findings.push(fk);
    }
    var nist = group(), cis = group(), pci = group(), cwe = group(), owasp = group();
    (findings || []).forEach(function (f) {
      var fk = f.key || f.title || '';
      if (f.nist) { var fam = String(f.nist).split('-')[0]; add(nist, f.nist, nistFam[fam] ? (f.nist + ': ' + nistFam[fam]) : f.nist, fk); nist.map[f.nist].csf = famCsf[fam] || ''; }
      if (f.cis) String(f.cis).split(/[,\s]+/).filter(Boolean).forEach(function (c) { var n = c.replace(/^CIS[-\s]?/i, ''); add(cis, n, 'CIS ' + n + (cisV8[n] ? ': ' + cisV8[n] : ''), fk); });
      if (f.pci) String(f.pci).split(/[,\s]+/).filter(Boolean).forEach(function (p) { var n = p.replace(/^PCI[-\s]?/i, '').split('.')[0]; add(pci, n, 'PCI Req ' + p + (pciV4[n] ? ': ' + pciV4[n] : ''), fk); });
      if (f.cwe) add(cwe, f.cwe, f.cwe, fk);
      (f.refs || []).forEach(function (r) { var m = /owasp\.org\/.*?(A\d{2})[:_ ]/i.exec(r) || /(A0?\d{1,2})[:_ -]\d{4}/.exec(r); if (m) add(owasp, m[1].toUpperCase(), 'OWASP ' + m[1].toUpperCase(), fk); });
    });
    function fin(g) { g.list.sort(function (a, b) { return b.findings.length - a.findings.length || (a.key < b.key ? -1 : 1); }); return g.list; }
    return { nist: fin(nist), cis: fin(cis), pci: fin(pci), cwe: fin(cwe), owasp: fin(owasp) };
  }

  // Detected CVEs from matched findings, with the CISA KEV overlay (actively exploited + ransomware).
  function cves(findings) {
    var kev = (OBOL.KEV && OBOL.KEV.map) || {};
    var byCve = {};
    (findings || []).forEach(function (f) {
      if (!f.cve) return;
      String(f.cve).split(/[,\s]+/).filter(Boolean).forEach(function (id) {
        id = id.trim().toUpperCase(); if (!/^CVE-\d{4}-\d+$/.test(id)) return;
        var e = byCve[id]; if (!e) { var k = kev[id]; e = byCve[id] = { cve: id, kev: !!k, ransomware: !!(k && k.rw), due: (k && k.due) || '', findings: [] }; }
        e.findings.push({ key: f.key, title: f.title, severity: f.severity, remediation: f.remediation });
      });
    });
    var list = Object.keys(byCve).map(function (k) { return byCve[k]; });
    var sev = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    list.sort(function (a, b) {
      if (a.kev !== b.kev) return b.kev - a.kev;
      var as = Math.max.apply(null, a.findings.map(function (x) { return sev[x.severity] || 0; }));
      var bs = Math.max.apply(null, b.findings.map(function (x) { return sev[x.severity] || 0; }));
      return bs - as || (a.cve < b.cve ? 1 : -1);
    });
    return list;
  }

  // Top-level: compute every framework model from a FactSet. `findings` may be passed in to avoid a
  // second assess() call.
  function compute(fs, opts) {
    opts = opts || {};
    var findings = opts.findings || (OBOL.findings ? OBOL.findings.assess(fs) : []);
    var use = techniqueUse(findings);
    return {
      findings: findings,
      use: use,
      attack: attackMatrix(use),
      killchain: killChain(use),
      defensive: defensive(use),
      compliance: compliance(findings),
      cves: cves(findings),
      ready: !!(OBOL.ATTACK && OBOL.ATTACK.techniques),
    };
  }

  OBOL.frameworks = {
    compute: compute,
    techniqueUse: techniqueUse,
    attackMatrix: attackMatrix,
    killChain: killChain,
    defensive: defensive,
    compliance: compliance,
    cves: cves,
  };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.frameworks; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
