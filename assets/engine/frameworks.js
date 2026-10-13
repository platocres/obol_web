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
  function techniqueUse(findings, activities) {
    // Txxxx (as authored, may be a sub) -> [contribution objects] so the matrix, the detail panel and the
    // hover card can show the real engagement evidence: findings ({k:'f', t:title, sev, cve, kev}) and the
    // recorded moves that lit the technique ({k:'m', t:command}). `.t` is the display label either way.
    var use = {};
    var byKind = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byKind) || {};
    var byMove = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byMove) || {};
    function add(tid, c) { if (!tid) return; var arr = use[tid] = use[tid] || []; if (!arr.some(function (x) { return x.k === c.k && x.t === c.t; })) arr.push(c); }
    (findings || []).forEach(function (f) {
      var tid = f.attack;
      if (!tid) { (f.trigger_kinds || []).some(function (k) { if (byKind[k]) { tid = byKind[k]; return true; } return false; }); }
      add(tid, { k: 'f', t: f.title || f.key || '', sev: f.severity || '', cve: f.cve || '', kev: !!f.kev });
    });
    (activities || []).forEach(function (act) {
      if (!act) return;
      var cmd = String(act.command || act.title || '').trim();
      // Prefer the move's authored technique (BY_MOVE names the ACT). Only fall back to the produced
      // fact kinds when the move is not named, so a spray lights T1110.003, not also T1078.
      var mv = act.action_id || act.id || '';
      if (mv && byMove[mv]) { add(byMove[mv], { k: 'm', t: cmd }); return; }
      (act.produced || []).forEach(function (k) { if (byKind[k]) add(byKind[k], { k: 'm', t: cmd }); });
    });
    return use;
  }
  function useLabels(arr) { return (arr || []).map(function (c) { return c.t; }); }

  // Example-command resolver: for a technique, the obol move(s) whose action performs it, with a
  // representative command filled for teaching. Powers the grayed-cell hover ("you have not done this
  // yet, here is what it looks like in obol") and the D3FEND "what this blocks" line. Pure over `pack`.
  var EXAMPLE_TOKENS = {
    target: '10.10.10.10', ip: '10.10.10.10', rhost: '10.10.10.10', host: '10.10.10.10',
    lhost: '10.10.14.2', lport: '4444', domain: 'DOMAIN.LOCAL', dc: 'DC01', dc_ip: '10.10.10.10',
    user: 'user', username: 'user', password: 'Password123', hash: 'aad3b435b51404ee:<nthash>',
    hashfile: 'hashes.txt', userlist: 'users.txt', wordlist: '/usr/share/wordlists/rockyou.txt',
    basedn: 'DC=domain,DC=local', url: 'http://10.10.10.10/', port: '80', share: 'SHARE',
    binary: '<binary>', service: '<service>', spn: '<spn>', file: '<file>',
  };
  function exampleFill(run, params) {
    params = params || {};
    return String(run || '').replace(/\{\{(\w+)\}\}/g, function (m, tok) {
      var v = params[tok];
      if (v !== undefined && v !== null && String(v).length) return String(v);
      if (EXAMPLE_TOKENS[tok] !== undefined) return EXAMPLE_TOKENS[tok];
      return m;   // leave an unknown token visible rather than invent one
    });
  }
  // Earliest-phase-first ordering: show the most ACCESSIBLE way into a technique first (kerberoast
  // before golden ticket for T1558), not the highest-impact one. Pack priority is a late-game weight,
  // so phase ordinal (recon<enum<creds<access<escalate<loot) is the right teaching order.
  var PHASE_ORD = { recon: 0, enum: 1, creds: 2, access: 3, escalate: 4, loot: 5 };
  function movePhaseOrd(a) {
    try { if (OBOL.phases && OBOL.phases.phaseOfAction) { var p = OBOL.phases.phaseOfAction(a); if (p in PHASE_ORD) return PHASE_ORD[p]; } } catch (e) {}
    return 3;   // neutral middle when phases are unavailable
  }
  function exampleCommands(technique, pack, opts) {
    opts = opts || {};
    var max = opts.max || 2, params = opts.params || {};
    var byKind = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byKind) || {};
    var byMove = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byMove) || {};
    function underCell(t) { return t === technique || parentOf(t) === technique; }
    var cand = [], seen = {};
    function consider(a, why) {
      if (!a || seen[a.id]) return;
      var cmds = (a.commands && a.commands.length) ? a.commands : (a.command ? [{ run: a.command, tool: a.tool }] : []);
      if (!cmds.length) return;
      var c = cmds[0], run = exampleFill(c.run || a.command || '', params);
      if (!run) return;
      seen[a.id] = 1;
      cand.push({ moveId: a.id, title: a.title || a.id, tool: c.tool || a.tool || '', run: run, why: why,
        more: cmds.length - 1, ord: movePhaseOrd(a), pri: a.priority || 0 });
    }
    // primary: BY_MOVE names the move's act (the authored, correct technique for that move)
    (pack || []).forEach(function (a) { if (byMove[a.id] && underCell(byMove[a.id])) consider(a, 'act'); });
    // secondary: a produced fact maps to the technique (skip advice moves and any BY_MOVE-named move,
    // whose technique is its BY_MOVE one, not a cell its produced fact happens to touch)
    (pack || []).forEach(function (a) {
      if (seen[a.id] || byMove[a.id]) return;
      if ([].concat(a.produces || []).some(function (k) { return byKind[k] && underCell(byKind[k]); })) consider(a, 'proves');
    });
    cand.sort(function (a, b) { return a.ord - b.ord || b.pri - a.pri || (a.moveId < b.moveId ? -1 : 1); });
    return cand.slice(0, max).map(function (e) { return { moveId: e.moveId, title: e.title, tool: e.tool, run: e.run, why: e.why, more: e.more }; });
  }

  // The set of TOP-LEVEL technique ids obol can perform (has an example command for), so the matrix
  // can mark a grayed cell as "you have not done this, but obol can show you." Pure over `pack`.
  function coveredTechniques(pack) {
    var byKind = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byKind) || {};
    var byMove = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byMove) || {};
    var set = {};
    function mark(t) { if (!t) return; set[t] = 1; set[parentOf(t)] = 1; }
    (pack || []).forEach(function (a) {
      if (byMove[a.id]) { mark(byMove[a.id]); return; }
      [].concat(a.produces || []).forEach(function (k) { if (byKind[k]) mark(byKind[k]); });
    });
    return set;
  }

  // The ATT&CK matrix model: every tactic (in matrix order) with its TOP-LEVEL techniques as cells; a
  // cell is "used" if the technique or any of its sub-techniques was used. Mirrors Splunk's matrix,
  // coloured by what YOU did rather than what a defender can detect.
  function attackMatrix(use, covered) {
    var cat = A();
    covered = covered || {};
    var usedTop = {};    // top-level technique id -> { subs:{}, findings:[] }
    Object.keys(use).forEach(function (tid) {
      var top = parentOf(tid);
      var rec = usedTop[top] = usedTop[top] || { subs: {}, findings: [] };
      if (tid !== top) rec.subs[tid] = 1;
      useLabels(use[tid]).forEach(function (lbl) { if (rec.findings.indexOf(lbl) < 0) rec.findings.push(lbl); });
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
          covered: !!covered[id],              // obol has an example command for this technique
          subs: u ? Object.keys(u.subs).sort() : [],
          findings: u ? u.findings.slice() : [],
        });
      });
      // Stable, ATT&CK-Navigator-like order: alphabetical by technique name (not used-first), so the
      // grid reads like the standard matrix and used cells show as a heatmap wherever they fall.
      cells.sort(function (a, b) { return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0); });
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
        d3fend: d3fend, findings: useLabels(use[tid]),
      };
    });
  }

  // D3FEND defensive-tactic matrix: the union of the countermeasures across the used ATT&CK techniques,
  // grouped into the 7 D3FEND tactics (Model/Harden/Detect/Isolate/Deceive/Evict/Restore). Renders as a
  // recognizable D3FEND matrix, each tactic a coloured column, each countermeasure listing what it counters.
  function d3fendMatrix(defList) {
    var d3 = D();
    var order = d3.tacticOrder || ['Harden', 'Detect', 'Isolate', 'Evict'];
    var tac = d3.tactics || {};
    var byCode = {};
    (defList || []).forEach(function (dfn) {
      (dfn.d3fend || []).forEach(function (c) {
        var e = byCode[c.id] || (byCode[c.id] = { id: c.id, name: c.name, tactic: tac[c.id] || '', counters: [] });
        if (e.counters.indexOf(dfn.id) < 0) e.counters.push(dfn.id);
      });
    });
    var cols = order.map(function (t) {
      var items = Object.keys(byCode).filter(function (k) { return byCode[k].tactic === t; }).map(function (k) { return byCode[k]; });
      items.sort(function (a, b) { return a.name < b.name ? -1 : 1; });
      return { tactic: t, items: items };
    }).filter(function (c) { return c.items.length; });
    return { tactics: cols, total: Object.keys(byCode).length };
  }

  // Compliance rollup from the matched findings' framework fields. CIS/PCI light up once the coverage
  // pass populates them; NIST/CWE/OWASP are populated today.
  function compliance(findings) {
    var tbl = T();
    var nistFam = tbl.NIST_FAMILY || {}, famCsf = tbl.NIST_FAMILY_TO_CSF || {}, cisV8 = tbl.CIS_V8 || {}, pciV4 = tbl.PCI_V4 || {};
    var nToCis = tbl.NIST_TO_CIS || {}, nToPci = tbl.NIST_TO_PCI || {};
    function crosswalk(map, nist) { var fam = String(nist).split('-')[0]; return map[nist] || (map._family && map._family[fam]) || []; }
    function group() { return { map: {}, list: [] }; }
    function add(g, key, title, fk) {
      var e = g.map[key]; if (!e) { e = g.map[key] = { key: key, title: title, findings: [] }; g.list.push(e); }
      if (fk && e.findings.indexOf(fk) < 0) e.findings.push(fk);
    }
    var nist = group(), cis = group(), pci = group(), cwe = group(), owasp = group();
    (findings || []).forEach(function (f) {
      var fk = f.key || f.title || '';
      if (f.nist) { var fam = String(f.nist).split('-')[0]; add(nist, f.nist, nistFam[fam] ? (f.nist + ': ' + nistFam[fam]) : f.nist, fk); nist.map[f.nist].csf = famCsf[fam] || ''; }
      // CIS: explicit field, else derived from the authored NIST control via the crosswalk.
      var cisNums = f.cis ? String(f.cis).split(/[,\s]+/).filter(Boolean).map(function (c) { return c.replace(/^CIS[-\s]?/i, ''); }) : (f.nist ? crosswalk(nToCis, f.nist) : []);
      cisNums.forEach(function (n) { add(cis, n, 'CIS ' + n + (cisV8[n] ? ': ' + cisV8[n] : ''), fk); });
      // PCI: explicit field, else derived from the NIST control.
      var pciNums = f.pci ? String(f.pci).split(/[,\s]+/).filter(Boolean).map(function (p) { return p.replace(/^PCI[-\s]?/i, ''); }) : (f.nist ? crosswalk(nToPci, f.nist) : []);
      pciNums.forEach(function (p) { var n = String(p).split('.')[0]; add(pci, n, 'PCI Req ' + p + (pciV4[n] ? ': ' + pciV4[n] : ''), fk); });
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
    var use = techniqueUse(findings, opts.activities || []);
    var def = defensive(use);
    var pack = opts.pack || (OBOL.packs && OBOL.packs.actions ? OBOL.packs.actions() : []);
    return {
      findings: findings,
      use: use,
      pack: pack,
      attack: attackMatrix(use, coveredTechniques(pack)),
      killchain: killChain(use),
      defensive: def,
      d3fend: d3fendMatrix(def),
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
    d3fendMatrix: d3fendMatrix,
    compliance: compliance,
    cves: cves,
    exampleCommands: exampleCommands,
    exampleFill: exampleFill,
    coveredTechniques: coveredTechniques,
  };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.frameworks; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
