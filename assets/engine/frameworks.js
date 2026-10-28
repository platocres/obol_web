/*!
 * obol engine - frameworks.js
 * Map the engagement's findings (and the ATT&CK techniques + recorded commands they carry) onto security
 * frameworks for the Frameworks view: MITRE ATT&CK, Lockheed Cyber Kill Chain, MITRE D3FEND countermeasures
 * + concrete blue-team detection/telemetry/hardening playbooks, a drill-down compliance rollup (NIST 800-53 /
 * CSF 2.0, CIS v8, PCI DSS v4, MITRE CWE, OWASP Top 10), and detected CVEs with the CISA KEV overlay.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function A() { return OBOL.ATTACK || { tactics: [], techniques: {} }; }
  function D() { return OBOL.D3FEND || { names: {}, map: {}, urls: {}, mitigations: {}, playbooks: {} }; }
  function T() { return OBOL.FRAMEWORK_TABLES || {}; }
  function parentOf(id) { return String(id).indexOf('.') >= 0 ? String(id).split('.')[0] : String(id); }

  // Incidental facts that many active offensive commands mint alongside their primary artifact
  // (e.g. an LDAP Kerberoast also minting ad.dc_candidate, or a crack/spray also minting credential.available).
  var INCIDENTAL_KINDS = {
    'ad.dc_candidate': 1, 'ad.domain_known': 1, 'ad.base_dn': 1,
    'credential.available': 1, 'credential.validated': 1, 'credential.plaintext': 1, 'credential.candidate': 1,
    'host.up': 1,
  };

  // The set of ATT&CK techniques the engagement touched, from matched findings + recorded activities.
  function techniqueUse(findings, activities) {
    var use = {};
    var byKind = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byKind) || {};
    var byMove = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byMove) || {};
    var byCmd = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byCmd) || [];
    function add(tid, c) {
      if (!tid) return;
      var arr = use[tid] = use[tid] || [];
      if (!arr.some(function (x) { return x.k === c.k && x.t === c.t; })) arr.push(c);
    }
    (findings || []).forEach(function (f) {
      if (!f) return;
      var tid = f.attack;
      if (!tid) {
        (f.trigger_kinds || []).some(function (k) {
          if (byKind[k]) { tid = byKind[k]; return true; }
          return false;
        });
      }
      add(tid, {
        k: 'f',
        t: f.title || f.key || '',
        id: f.id || f.key || '',
        sev: f.severity || '',
        host: f.host || '',
        fix: f.remediation || '',
        cve: f.cve || '',
        kev: !!f.kev,
      });
    });
    (activities || []).forEach(function (act) {
      if (!act) return;
      var cmd = String(act.command || act.title || '').trim();
      var mv = act.action_id || act.id || '';
      // 1) Authored move -> technique mapping wins.
      if (mv && byMove[mv]) { add(byMove[mv], { k: 'm', t: cmd }); return; }
      // 2) Command-signature regex fallback for global pastes without action_id.
      if (cmd && byCmd.length) {
        for (var i = 0; i < byCmd.length; i++) {
          var pair = byCmd[i];
          if (pair && pair[0] && pair[0].test(cmd)) {
            add(pair[1], { k: 'm', t: cmd });
            return;
          }
        }
      }
      // 3) Produced-fact fallback, filtering incidental facts when a specific fact is present.
      var prod = (act.produced || []).filter(function (k) { return !!byKind[k]; });
      var specific = prod.filter(function (k) { return !INCIDENTAL_KINDS[k]; });
      (specific.length ? specific : prod).forEach(function (k) {
        add(byKind[k], { k: 'm', t: cmd });
      });
    });
    return use;
  }
  function useLabels(arr) { return (arr || []).map(function (c) { return c.t; }); }

  // Example-command resolver: for a technique, the OBOL move(s) whose action performs it, with a
  // representative command filled for teaching.
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
      return m;
    });
  }
  var PHASE_ORD = { recon: 0, enum: 1, creds: 2, access: 3, escalate: 4, loot: 5 };
  function movePhaseOrd(a) {
    try { if (OBOL.phases && OBOL.phases.phaseOfAction) { var p = OBOL.phases.phaseOfAction(a); if (p in PHASE_ORD) return PHASE_ORD[p]; } } catch (e) {}
    return 3;
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
    (pack || []).forEach(function (a) { if (byMove[a.id] && underCell(byMove[a.id])) consider(a, 'act'); });
    (pack || []).forEach(function (a) {
      if (seen[a.id] || byMove[a.id]) return;
      if ([].concat(a.produces || []).some(function (k) { return byKind[k] && underCell(byKind[k]); })) consider(a, 'proves');
    });
    cand.sort(function (a, b) { return a.ord - b.ord || b.pri - a.pri || (a.moveId < b.moveId ? -1 : 1); });
    return cand.slice(0, max).map(function (e) { return { moveId: e.moveId, title: e.title, tool: e.tool, run: e.run, why: e.why, more: e.more }; });
  }

  // The set of technique ids OBOL can perform (has an example command or catalog/fact mapping for).
  function coveredTechniques(pack) {
    var byKind = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byKind) || {};
    var byMove = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byMove) || {};
    var byCmd = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byCmd) || [];
    var set = {};
    function mark(t) { if (!t) return; set[t] = 1; set[parentOf(t)] = 1; }
    if (pack && pack.length) {
      pack.forEach(function (a) {
        if (byMove[a.id]) { mark(byMove[a.id]); return; }
        [].concat(a.produces || []).forEach(function (k) { if (byKind[k]) mark(byKind[k]); });
      });
    } else {
      Object.keys(byMove).forEach(function (k) { mark(byMove[k]); });
      Object.keys(byKind).forEach(function (k) { mark(byKind[k]); });
      byCmd.forEach(function (pair) { if (pair && pair[1]) mark(pair[1]); });
      (OBOL.findingsCatalog || OBOL.FINDINGS_CATALOG || []).forEach(function (c) { if (c && c.attack) mark(c.attack); });
    }
    return set;
  }

  // The ATT&CK matrix model: every tactic (in matrix order) with its TOP-LEVEL techniques as cells.
  function attackMatrix(use, covered) {
    var cat = A();
    covered = arguments.length >= 2 && covered ? covered : coveredTechniques();
    var usedTop = {};
    Object.keys(use).forEach(function (tid) {
      var top = parentOf(tid);
      var rec = usedTop[top] = usedTop[top] || { subs: {}, findings: [] };
      if (tid !== top) rec.subs[tid] = 1;
      useLabels(use[tid]).forEach(function (lbl) { if (rec.findings.indexOf(lbl) < 0) rec.findings.push(lbl); });
    });
    var distinctAll = {}, distinctCovered = {};
    var tactics = (cat.tactics || []).map(function (ta) {
      var cells = [];
      Object.keys(cat.techniques).forEach(function (id) {
        var t = cat.techniques[id];
        if (t.sub) return;
        if ((t.ta || []).indexOf(ta.id) < 0) return;
        var u = usedTop[id];
        var isCov = !!covered[id];
        distinctAll[id] = 1;
        if (u || isCov) distinctCovered[id] = 1;
        cells.push({
          id: id, name: t.n, used: !!u,
          covered: isCov,
          subs: u ? Object.keys(u.subs).sort() : [],
          findings: u ? u.findings.slice() : [],
        });
      });
      cells.sort(function (a, b) { return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0); });
      return {
        id: ta.id,
        name: ta.name,
        cells: cells,
        usedCount: cells.filter(function (c) { return c.used; }).length,
        coveredCount: cells.filter(function (c) { return c.used || c.covered; }).length,
        total: cells.length,
      };
    }).filter(function (col) { return col.total > 0; });
    var usedTotal = Object.keys(usedTop).length;
    return {
      tactics: tactics,
      usedTop: usedTop,
      usedTotal: usedTotal,
      coveredTotal: Object.keys(distinctCovered).length,
      enterpriseTotal: Object.keys(distinctAll).length,
      version: cat.version,
    };
  }

  // Lockheed Cyber Kill Chain rollup: used techniques bucketed by stage.
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

  var TACTIC_DEFAULT_D3 = {
    'reconnaissance': ['D3-NTA', 'D3-ITF'],
    'resource-development': ['D3-SU', 'D3-FHRA'],
    'initial-access': ['D3-SU', 'D3-MFA', 'D3-ITF'],
    'execution': ['D3-PSA', 'D3-SEA', 'D3-EAL'],
    'persistence': ['D3-SICA', 'D3-PSA', 'D3-LAM'],
    'privilege-escalation': ['D3-PH', 'D3-SU', 'D3-ACH'],
    'defense-evasion': ['D3-EAL', 'D3-PSA', 'D3-PH'],
    'credential-access': ['D3-CH', 'D3-SPP', 'D3-DAM'],
    'discovery': ['D3-PSA', 'D3-OSM', 'D3-NTA'],
    'lateral-movement': ['D3-MFA', 'D3-ITF', 'D3-RTSD'],
    'collection': ['D3-FA', 'D3-FE', 'D3-UBA'],
    'command-and-control': ['D3-NTA', 'D3-OTF'],
    'exfiltration': ['D3-OTF', 'D3-NTA'],
    'impact': ['D3-PH', 'D3-PSA'],
  };

  // Defensive lens: for each USED technique, its D3FEND countermeasures + ATT&CK detection + telemetry
  // Event IDs + concrete hardening steps + linked MITRE M10xx mitigations. Guaranteed zero blank rows.
  function defensive(use) {
    var cat = A(), d3 = D();
    var pbs = d3.playbooks || {}, mitCatalog = d3.mitigations || {}, d3Urls = d3.urls || {}, d3Tac = d3.tactics || {};
    return Object.keys(use).sort().map(function (tid) {
      var top = parentOf(tid);
      var t = cat.techniques[tid] || {}, pt = cat.techniques[top] || {};
      var pb = pbs[tid] || {}, ppb = pbs[top] || {};
      var tactics = (t.ta && t.ta.length ? t.ta : (pt.ta || []));
      var tacId = tactics[0] || 'discovery';
      var tpb = (pbs._tactic && pbs._tactic[tacId]) || {};

      var codes = d3.map[tid] || d3.map[top] || TACTIC_DEFAULT_D3[tacId] || ['D3-PSA', 'D3-PH'];
      var d3fend = codes.map(function (c) {
        return {
          id: c,
          name: d3.names[c] || c,
          tactic: d3Tac[c] || '',
          url: d3Urls[c] || 'https://d3fend.mitre.org/',
        };
      });

      var detection = t.det || pb.det || pt.det || ppb.det || tpb.det || '';
      var dataSources = (t.ds && t.ds.length) ? t.ds.slice()
        : (pb.telemetry && pb.telemetry.length) ? pb.telemetry.slice()
        : (ppb.telemetry && ppb.telemetry.length) ? ppb.telemetry.slice()
        : (tpb.telemetry ? tpb.telemetry.slice() : []);

      // Prefer real preventive/detective MITRE mitigations over STIX's "Do Not Mitigate" placeholder.
      var rawMits = (t.mit && t.mit.length ? t.mit : (pt.mit && pt.mit.length ? pt.mit : [])).slice();
      var cleanMits = rawMits.filter(function (m) { return m !== 'Do Not Mitigate' && m !== 'Pre-compromise'; });
      if (!cleanMits.length) {
        cleanMits = (pb.mit && pb.mit.length) ? pb.mit.slice()
          : (ppb.mit && ppb.mit.length) ? ppb.mit.slice()
          : (tpb.mit && tpb.mit.length) ? tpb.mit.slice()
          : rawMits;
      }
      var seenMit = {};
      var mitigations = cleanMits.filter(function (m) {
        if (!m || seenMit[m]) return false;
        seenMit[m] = 1;
        return true;
      });
      var mitigationItems = mitigations.map(function (name) {
        var info = mitCatalog[name] || {};
        return {
          name: name,
          id: info.id || '',
          url: info.url || 'https://attack.mitre.org/mitigations/',
          action: info.action || '',
        };
      });

      // Merge engagement finding fixes + playbook hardening + top M10xx guidance into concrete steps.
      var hardening = [], seenHard = {};
      function pushHard(s) {
        s = String(s || '').trim();
        if (!s) return;
        var norm = s.toLowerCase();
        if (seenHard[norm]) return;
        seenHard[norm] = 1;
        hardening.push(s);
      }
      (use[tid] || []).forEach(function (c) { if (c && c.k === 'f' && c.fix) pushHard(c.fix); });
      (pb.hardening || ppb.hardening || tpb.hardening || []).forEach(pushHard);
      if (hardening.length < 2) {
        mitigationItems.slice(0, 2).forEach(function (mi) { if (mi.action) pushHard(mi.action); });
      }

      return {
        id: tid,
        name: t.n || pt.n || tid,
        url: t.url || ('https://attack.mitre.org/techniques/' + tid.replace('.', '/') + '/'),
        tactics: tactics,
        detection: detection,
        dataSources: dataSources,
        mitigations: mitigations,
        mitigationItems: mitigationItems,
        hardening: hardening,
        d3fend: d3fend,
        findings: useLabels(use[tid]),
        contributions: (use[tid] || []).slice(),
      };
    });
  }

  // D3FEND defensive-tactic matrix: union of countermeasures across used ATT&CK techniques, grouped into
  // the 7 D3FEND tactics (Model/Harden/Detect/Isolate/Deceive/Evict/Restore).
  function d3fendMatrix(defList) {
    var d3 = D();
    var order = d3.tacticOrder || ['Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore'];
    var tac = d3.tactics || {}, urls = d3.urls || {};
    var byCode = {};
    (defList || []).forEach(function (dfn) {
      (dfn.d3fend || []).forEach(function (c) {
        var e = byCode[c.id] || (byCode[c.id] = {
          id: c.id,
          name: c.name,
          tactic: tac[c.id] || c.tactic || '',
          url: urls[c.id] || c.url || 'https://d3fend.mitre.org/',
          counters: [],
        });
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

  function splitCodes(val) {
    if (!val) return [];
    if (Array.isArray(val)) {
      var flat = [];
      val.forEach(function (v) { flat = flat.concat(splitCodes(v)); });
      return flat;
    }
    return String(val).split(/[,;]+/).map(function (s) {
      return String(s).split(':')[0].trim();
    }).filter(Boolean);
  }

  // Compliance rollup with exact control/weakness titles, plain-English summaries, official URLs,
  // full mapped finding objects for inline drill-down, and NIST CSF 2.0 function rollup.
  function compliance(findings) {
    var tbl = T();
    var nistFam = tbl.NIST_FAMILY || {}, famCsf = tbl.NIST_FAMILY_TO_CSF || {};
    var nistControls = tbl.NIST_CONTROLS || {}, cisV8 = tbl.CIS_V8 || {}, cisDet = tbl.CIS_DETAILS || {};
    var pciV4 = tbl.PCI_V4 || {}, pciDet = tbl.PCI_DETAILS || {};
    var cweCat = tbl.CWE_CATALOG || {}, owaspTop = tbl.OWASP_TOP10 || {};
    var nToCis = tbl.NIST_TO_CIS || {}, nToPci = tbl.NIST_TO_PCI || {};
    var techComp = tbl.TECHNIQUE_TO_COMPLIANCE || {};
    var byKind = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byKind) || {};

    function crosswalk(map, nist) {
      var fam = String(nist).split('-')[0];
      return map[nist] || (map._family && map._family[fam]) || [];
    }
    function group() { return { map: {}, list: [] }; }
    function add(g, key, meta, fk, fItem) {
      var e = g.map[key];
      if (!e) {
        e = g.map[key] = {
          key: key,
          title: meta.title || key,
          shortTitle: meta.shortTitle || meta.title || key,
          family: meta.family || '',
          csf: meta.csf || '',
          summary: meta.summary || '',
          url: meta.url || '',
          findings: [],
          findingItems: [],
        };
        g.list.push(e);
      }
      if (fk && e.findings.indexOf(fk) < 0) e.findings.push(fk);
      if (fItem && !e.findingItems.some(function (x) { return x.id === fItem.id; })) {
        e.findingItems.push(fItem);
      }
    }

    var nist = group(), cis = group(), pci = group(), cwe = group(), owasp = group();

    (findings || []).forEach(function (f, idx) {
      if (!f) return;
      var fk = f.id || (f.key && f.host ? (f.key + '|' + f.host) : (f.key || f.title || ('f-' + idx)));
      var fItem = {
        id: f.id || fk,
        key: f.key || fk,
        title: f.title || f.key || 'Finding',
        severity: f.severity || 'info',
        host: f.host || '',
        category: f.category || '',
        evidence: f.evidence || '',
        remediation: f.remediation || '',
        attack: f.attack || '',
      };

      var tid = f.attack || '';
      if (!tid && f.trigger_kinds) {
        (f.trigger_kinds || []).some(function (k) { if (byKind[k]) { tid = byKind[k]; return true; } return false; });
      }
      var fallback = tid ? (techComp[tid] || techComp[parentOf(tid)] || null) : null;

      var nistCodes = splitCodes(f.nist);
      if (!nistCodes.length && fallback && fallback.nist) nistCodes = [fallback.nist];

      var cweCodes = splitCodes(f.cwe);
      if (!cweCodes.length && fallback && fallback.cwe) cweCodes = [fallback.cwe];

      nistCodes.forEach(function (rawCode) {
        var code = rawCode.toUpperCase();
        var fam = code.split('-')[0];
        var ctrl = nistControls[code];
        var famName = nistFam[fam] || '';
        var title = ctrl
          ? (code + ': ' + ctrl.name + (famName && ctrl.name !== famName ? ' (' + famName + ')' : ''))
          : (famName ? (code + ': ' + famName) : code);
        var shortTitle = ctrl ? (code + ': ' + ctrl.name) : title;
        add(nist, code, {
          title: title,
          shortTitle: shortTitle,
          family: famName,
          csf: famCsf[fam] || '',
          summary: (ctrl && ctrl.summary) || '',
          url: tbl.nistUrl ? tbl.nistUrl(code) : ('https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=' + encodeURIComponent(code)),
        }, fk, fItem);
      });

      var cisNums = [];
      if (f.cis) {
        var cisSrc = (Array.isArray(f.cis) ? f.cis.join(',') : String(f.cis))
          .replace(/\bCIS(?:\s+Controls?(?:\s+v\d+(?:\.\d+)?)?)?[-\s]*/gi, ' ');
        (cisSrc.match(/\d+(?:\.\d+)*/g) || []).forEach(function (n) {
          if (cisNums.indexOf(n) < 0) cisNums.push(n);
        });
      } else {
        nistCodes.forEach(function (nc) {
          crosswalk(nToCis, nc.toUpperCase()).forEach(function (n) { if (cisNums.indexOf(n) < 0) cisNums.push(n); });
        });
      }
      cisNums.forEach(function (n) {
        var base = String(n).split('.')[0];
        add(cis, base, {
          title: 'CIS ' + base + (cisV8[base] ? ': ' + cisV8[base] : ''),
          shortTitle: 'CIS ' + base + (cisV8[base] ? ': ' + cisV8[base] : ''),
          summary: cisDet[base] || '',
          url: 'https://www.cisecurity.org/controls/v8',
        }, fk, fItem);
      });

      var pciNums = [];
      if (f.pci) {
        var pciSrc = (Array.isArray(f.pci) ? f.pci.join(',') : String(f.pci))
          .replace(/\bv\d+(?:\.\d+)?\b/gi, ' ')
          .replace(/\bPCI[-\s]*(?:DSS[-\s]*)?(?:Req(?:uirement)?[-\s]*)?/gi, ' ');
        (pciSrc.match(/\d+(?:\.\d+)*/g) || []).forEach(function (p) {
          if (pciNums.indexOf(p) < 0) pciNums.push(p);
        });
      } else {
        nistCodes.forEach(function (nc) {
          crosswalk(nToPci, nc.toUpperCase()).forEach(function (p) { if (pciNums.indexOf(p) < 0) pciNums.push(p); });
        });
      }
      pciNums.forEach(function (p) {
        var n = String(p).split('.')[0];
        add(pci, n, {
          title: 'PCI Req ' + p + (pciV4[n] ? ': ' + pciV4[n] : ''),
          shortTitle: 'PCI Req ' + n + (pciV4[n] ? ': ' + pciV4[n] : ''),
          summary: pciDet[n] || '',
          url: 'https://www.pcisecuritystandards.org/standards/pci-dss/',
        }, fk, fItem);
      });

      cweCodes.forEach(function (rawCwe) {
        var code = rawCwe.toUpperCase();
        if (code.indexOf('CWE-') !== 0 && /^\d+$/.test(code)) code = 'CWE-' + code;
        var info = cweCat[code];
        add(cwe, code, {
          title: info ? (code + ': ' + info.name) : code,
          shortTitle: info ? (code + ': ' + info.name) : code,
          summary: (info && info.summary) || '',
          url: tbl.cweUrl ? tbl.cweUrl(code) : 'https://cwe.mitre.org/',
        }, fk, fItem);
      });

      var owaspCodes = [];
      if (f.owasp) {
        splitCodes(f.owasp).forEach(function (o) {
          var m0 = /(A0?\d{1,2})/i.exec(o);
          if (m0) owaspCodes.push(m0[1].toUpperCase());
        });
      }
      var refList = Array.isArray(f.refs) ? f.refs : (f.refs ? [f.refs] : []);
      refList.forEach(function (r) {
        var m = /owasp\.org\/.*?(A\d{2})[:_ -]/i.exec(r) || /(A0?\d{1,2})[:_ -]\d{4}/i.exec(r);
        if (m) {
          var oc = m[1].toUpperCase();
          if (oc.length === 2) oc = 'A0' + oc.slice(1);
          if (owaspCodes.indexOf(oc) < 0) owaspCodes.push(oc);
        }
      });
      owaspCodes.forEach(function (oc) {
        var info = owaspTop[oc];
        add(owasp, oc, {
          title: info ? ('OWASP ' + oc + ':2021 - ' + info.name) : ('OWASP ' + oc),
          shortTitle: info ? (oc + ': ' + info.name) : ('OWASP ' + oc),
          summary: (info && info.summary) || '',
          url: (info && info.url) || 'https://owasp.org/Top10/',
        }, fk, fItem);
      });
    });

    function fin(g) {
      g.list.sort(function (a, b) {
        return b.findings.length - a.findings.length || String(a.key).localeCompare(String(b.key), undefined, { numeric: true });
      });
      return g.list;
    }

    var nistList = fin(nist);
    var csfDefs = tbl.NIST_CSF || [];
    var csfRollup = csfDefs.map(function (fn) {
      var ctrls = nistList.filter(function (e) { return e.csf === fn.id; });
      var fSeen = {};
      ctrls.forEach(function (e) { e.findings.forEach(function (fk) { fSeen[fk] = 1; }); });
      return {
        id: fn.id,
        name: fn.name,
        summary: fn.summary || '',
        controls: ctrls.map(function (e) { return e.key; }),
        findingCount: Object.keys(fSeen).length,
      };
    });

    return {
      nist: nistList,
      cis: fin(cis),
      pci: fin(pci),
      cwe: fin(cwe),
      owasp: fin(owasp),
      csf: csfRollup,
    };
  }

  // Detected CVEs from matched findings (f.cve, f.cves, f.refs, f.title), with CISA KEV overlay.
  function cves(findings) {
    var kev = (OBOL.KEV && OBOL.KEV.map) || {};
    var byCve = {};
    function extractCves(f) {
      var found = [], seen = {};
      function scan(v) {
        if (!v) return;
        if (Array.isArray(v)) { v.forEach(scan); return; }
        var re = /\b(CVE-\d{4}-\d{4,})\b/gi, m;
        var s = String(v);
        while ((m = re.exec(s)) !== null) {
          var id = m[1].toUpperCase();
          if (!seen[id]) { seen[id] = 1; found.push(id); }
        }
      }
      scan(f.cve);
      scan(f.cves);
      scan(f.refs);
      scan(f.title);
      return found;
    }
    (findings || []).forEach(function (f) {
      if (!f) return;
      var ids = extractCves(f);
      if (!ids.length) return;
      ids.forEach(function (id) {
        var e = byCve[id];
        if (!e) {
          var k = kev[id];
          e = byCve[id] = {
            cve: id,
            kev: !!k,
            ransomware: !!(k && k.rw),
            due: (k && k.due) || '',
            nvdUrl: 'https://nvd.nist.gov/vuln/detail/' + id,
            mitreUrl: 'https://www.cve.org/CVERecord?id=' + id,
            kevUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            hosts: [],
            findings: [],
          };
        }
        if (f.host && e.hosts.indexOf(f.host) < 0) e.hosts.push(f.host);
        var fid = f.id || f.key || f.title || '';
        if (!e.findings.some(function (x) { return (x.id || x.key || x.title) === fid && x.host === (f.host || ''); })) {
          e.findings.push({
            id: f.id || '',
            key: f.key || '',
            title: f.title || id,
            severity: f.severity || 'info',
            host: f.host || '',
            evidence: f.evidence || '',
            remediation: f.remediation || '',
          });
        }
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

  // Top-level: compute every framework model from a FactSet.
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
