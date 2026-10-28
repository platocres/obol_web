/*!
 * obol ui - routes/findings.js - cross-host findings roll-up + Frameworks Studio.
 * Unifies catalog findings, finding.* facts, and operator-proven activities (enriched via reportmeta,
 * ATT&CK, D3FEND, NIST 800-53/CSF 2.0, CIS v8, PCI DSS v4, MITRE CWE, OWASP Top 10, and CISA KEV),
 * deduplicates overlapping move/catalog hits, suppresses redundant validation milestones when root-cause
 * findings exist, and renders 100% clickable external references + cross-tab jump chips.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr(s); }
  function parentOf(id) { return String(id).indexOf('.') >= 0 ? String(id).split('.')[0] : String(id); }
  function slug(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'item'; }

  // Per-host collapse state for the by-target grouping, remembered per browser, per engagement.
  function fhKey(host) { return 'obol.fh:' + ((OBOL.store && OBOL.store.activeId && OBOL.store.activeId()) || '') + ':' + host; }
  function fhOpen(host) { try { var v = localStorage.getItem(fhKey(host)); return v == null ? true : v === '1'; } catch (e) { return true; } }
  function fhSetOpen(host, open) { try { localStorage.setItem(fhKey(host), open ? '1' : '0'); } catch (e) {} }

  var SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  function normSev(s) { s = String(s || '').toLowerCase(); return SEV_ORDER.indexOf(s) >= 0 ? s : 'info'; }
  function sevRank(s) { var i = SEV_ORDER.indexOf(s); return i < 0 ? SEV_ORDER.length : i; }

  // Post-compromise operational validation / shell-delivery milestones that should not clutter the
  // vulnerability list once a root-cause credential or exploit finding is already recorded.
  var MILESTONE_MOVES = {
    'validate-credential': 1, 'cred-reuse-sweep': 1, 'win-interactive-shell': 1,
    'lateral-exec': 1, 'own-domain-pth': 1, 'linux-remote-exec': 1, 'ssh-key-login': 1,
    'rdp-connect': 1, 'winrm-shell': 1, 'smb-admin-exec': 1, 'psexec-shell': 1, 'wmiexec-shell': 1,
  };
  var MILESTONE_TITLE_RE = /^(?:valid credentials?|credential(?:s)? validated|interactive (?:windows|linux|remote) shell|remote command execution via valid|authenticated (?:smb|winrm|ssh|rdp) session)$/i;
  var MILESTONE_ONLY_FACT_RE = /^(?:credential\.(?:validated|available|plaintext|candidate)|(?:smb|winrm|ssh|rdp|ldap|mssql)\.authenticated|access\.(?:shell|user|admin|root|system)|foothold\.)/;

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

  function parseCodeFirst(arrOrStr) {
    if (!arrOrStr) return '';
    if (Array.isArray(arrOrStr)) {
      return arrOrStr.map(function (x) { return String(x).split(':')[0].trim(); }).filter(Boolean).join(', ');
    }
    return String(arrOrStr).split(',').map(function (x) { return String(x).split(':')[0].trim(); }).filter(Boolean).join(', ');
  }

  function extractCveIds(val) {
    var out = [], seen = {};
    function scan(v) {
      if (!v) return;
      if (Array.isArray(v)) { v.forEach(scan); return; }
      var re = /\b(CVE-\d{4}-\d{4,})\b/gi, m;
      var s = String(v);
      while ((m = re.exec(s)) !== null) {
        var id = m[1].toUpperCase();
        if (!seen[id]) { seen[id] = 1; out.push(id); }
      }
    }
    scan(val);
    return out;
  }

  function labelForRefUrl(url) {
    var u = String(url || '');
    if (/attack\.mitre\.org/i.test(u)) {
      var mt = /techniques\/(T\d{4})(?:\/(\d{3}))?/i.exec(u);
      return { label: mt ? ('ATT&CK ' + mt[1].toUpperCase() + (mt[2] ? '.' + mt[2] : '')) : 'MITRE ATT&CK', kind: 'attack' };
    }
    if (/cwe\.mitre\.org/i.test(u)) {
      var mc = /definitions\/(\d+)/i.exec(u);
      return { label: mc ? ('CWE-' + mc[1]) : 'MITRE CWE', kind: 'cwe' };
    }
    if (/d3fend\.mitre\.org/i.test(u)) return { label: 'MITRE D3FEND', kind: 'd3' };
    if (/nvd\.nist\.gov/i.test(u)) {
      var mn = /(CVE-\d{4}-\d{4,})/i.exec(u);
      return { label: mn ? ('NVD ' + mn[1].toUpperCase()) : 'NVD', kind: 'cve' };
    }
    if (/csrc\.nist\.gov|nist\.gov/i.test(u)) return { label: 'NIST Standard', kind: 'nist' };
    if (/owasp\.org/i.test(u)) {
      var mo = /(A\d{2})[:_ -]/i.exec(u);
      return { label: mo ? ('OWASP ' + mo[1].toUpperCase()) : 'OWASP', kind: 'owasp' };
    }
    if (/cisa\.gov/i.test(u)) return { label: 'CISA Advisory', kind: 'kev' };
    if (/microsoft\.com/i.test(u)) return { label: 'Microsoft Advisory', kind: 'vendor' };
    if (/cisecurity\.org/i.test(u)) return { label: 'CIS Controls', kind: 'cis' };
    if (/pcisecuritystandards\.org/i.test(u)) return { label: 'PCI DSS', kind: 'pci' };
    if (/github\.com/i.test(u)) return { label: 'GitHub Advisory', kind: 'vendor' };
    if (/portswigger\.net/i.test(u)) return { label: 'PortSwigger', kind: 'vendor' };
    try {
      var host = new URL(u).hostname.replace(/^www\./i, '');
      return { label: host, kind: 'ref' };
    } catch (e) {
      return { label: 'Reference', kind: 'ref' };
    }
  }

  function enrichFindingLinks(f) {
    var tbl = OBOL.FRAMEWORK_TABLES || {};
    var d3 = OBOL.D3FEND || {};
    var byKind = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byKind) || {};
    var kevMap = (OBOL.KEV && OBOL.KEV.map) || {};
    var techComp = tbl.TECHNIQUE_TO_COMPLIANCE || {};

    if (!f.attack && f.trigger_kinds && f.trigger_kinds.length) {
      f.trigger_kinds.some(function (k) { if (byKind[k]) { f.attack = byKind[k]; return true; } return false; });
    }
    var fallback = f.attack ? (techComp[f.attack] || techComp[parentOf(f.attack)] || null) : null;
    if (!f.nist && fallback && fallback.nist) f.nist = fallback.nist;
    if (!f.cwe && fallback && fallback.cwe) f.cwe = fallback.cwe;

    if (!f.remediation && f.attack && d3.playbooks) {
      var pb = d3.playbooks[f.attack] || d3.playbooks[parentOf(f.attack)];
      if (pb && pb.hardening && pb.hardening.length) f.remediation = pb.hardening[0];
    }

    var cveList = extractCveIds([f.cve, f.cves, f.refs, f.title]);
    f.cves = cveList;
    if (!f.cve && cveList.length) f.cve = cveList.join(', ');
    f.kev = cveList.some(function (id) { return !!kevMap[id]; });

    var ext = [], seenUrl = {}, seenLabel = {};
    function addLink(url, label, kind) {
      if (!url || !/^https?:\/\//i.test(url)) return;
      var cleanUrl = url.trim();
      var normKey = cleanUrl.toLowerCase().replace(/^http:\/\//, 'https://').replace(/\/+$/, '');
      var normLbl = String(label || '').trim().toLowerCase();
      if (seenUrl[normKey]) return;
      if (normLbl && /^(?:att&ck\s|cwe-|nist\s|nvd\s|cisa\s)/i.test(normLbl) && seenLabel[normLbl]) return;
      seenUrl[normKey] = 1;
      if (normLbl) seenLabel[normLbl] = 1;
      ext.push({ url: cleanUrl, label: label, kind: kind || 'ref' });
    }

    if (f.attack) {
      var tUrl = (OBOL.ATTACK && OBOL.ATTACK.techniques && OBOL.ATTACK.techniques[f.attack] && OBOL.ATTACK.techniques[f.attack].url)
        || ('https://attack.mitre.org/techniques/' + f.attack.replace('.', '/') + '/');
      addLink(tUrl, 'ATT&CK ' + f.attack, 'attack');
    }

    parseCodeFirst(f.cwe).split(/,\s*/).filter(Boolean).forEach(function (code) {
      code = code.toUpperCase();
      if (code.indexOf('CWE-') !== 0 && /^\d+$/.test(code)) code = 'CWE-' + code;
      var u = tbl.cweUrl ? tbl.cweUrl(code) : ('https://cwe.mitre.org/data/definitions/' + code.replace(/^CWE-/i, '') + '.html');
      addLink(u, code, 'cwe');
    });

    parseCodeFirst(f.nist).split(/,\s*/).filter(Boolean).forEach(function (code) {
      code = code.toUpperCase();
      var u = tbl.nistUrl ? tbl.nistUrl(code) : ('https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=' + encodeURIComponent(code));
      addLink(u, 'NIST ' + code, 'nist');
    });

    cveList.forEach(function (id) {
      addLink('https://nvd.nist.gov/vuln/detail/' + id, 'NVD ' + id, 'cve');
      if (kevMap[id]) {
        addLink('https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'CISA KEV', 'kev');
      }
    });

    var rawRefs = Array.isArray(f.refs) ? f.refs : (f.refs ? [f.refs] : []);
    rawRefs.forEach(function (r) {
      String(r || '').split(/[\s,;]+/).filter(Boolean).forEach(function (tok) {
        if (/^https?:\/\//i.test(tok)) {
          var info = labelForRefUrl(tok);
          addLink(tok, info.label, info.kind);
        } else if (/^CVE-\d{4}-\d{4,}$/i.test(tok)) {
          var cid = tok.toUpperCase();
          addLink('https://nvd.nist.gov/vuln/detail/' + cid, 'NVD ' + cid, 'cve');
        } else if (/^(?:MS\d{2}-\d{3}|KB\d{6,})$/i.test(tok)) {
          var up = tok.toUpperCase();
          addLink('https://learn.microsoft.com/en-us/search/?terms=' + encodeURIComponent(up), 'Microsoft ' + up, 'vendor');
        }
      });
    });

    f.extLinks = ext;

    var jumps = [];
    if (f.attack) {
      jumps.push({ view: 'attack', target: parentOf(f.attack), label: 'ATT&CK ' + parentOf(f.attack) });
      jumps.push({ view: 'defensive', target: f.attack, label: 'Defensive' });
    }
    var firstComp = parseCodeFirst(f.nist).split(/,\s*/).filter(Boolean)[0] || parseCodeFirst(f.cwe).split(/,\s*/).filter(Boolean)[0];
    if (firstComp) jumps.push({ view: 'compliance', target: firstComp.toUpperCase(), label: 'Compliance' });
    if (cveList.length) jumps.push({ view: 'cves', target: cveList[0], label: cveList[0] });
    f.jumps = jumps;

    return f;
  }

  function gather() {
    var facts = OBOL.store.factSet();
    var meta = root.OBOL_REPORTMETA || null;
    var byMove = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byMove) || {};
    var byKind = (OBOL.ATTACK_MOVE && OBOL.ATTACK_MOVE.byKind) || {};
    var out = [], seen = {}, coveredTriggerKinds = {}, coveredTechByHost = {};

    function markTech(host, tid, fnd) {
      if (!tid) return;
      coveredTechByHost[(host || '*') + '|' + tid] = fnd;
      coveredTechByHost['*|' + tid] = fnd;
    }

    function push(fnd) {
      fnd.host = fnd.host || 'engagement';
      fnd.severity = normSev(fnd.severity);
      var key = String(fnd.title || '').toLowerCase() + '|' + fnd.host;
      if (seen[key]) return seen[key];
      fnd.id = 'fnd-' + slug(fnd.key || fnd.title) + '-' + slug(fnd.host) + '-' + (out.length + 1);
      seen[key] = fnd;
      out.push(fnd);
      if (fnd.attack) markTech(fnd.host, fnd.attack, fnd);
      return fnd;
    }

    // 1) Catalogued finding.* facts (web-check parsers), enriched from reportmeta when loaded.
    facts.facts.forEach(function (f) {
      if (f.state !== 'supported' || f.kind.indexOf('finding.') !== 0) return;
      var v = f.value || {};
      var cardId = v.card || '';
      var cardMeta = (meta && cardId && meta.cards && meta.cards[cardId]) || {};
      var refMeta = (meta && cardId && meta.references && meta.references.cards && meta.references.cards[cardId]) || {};
      var mitre0 = (cardMeta.mitre && cardMeta.mitre[0]) ? String(cardMeta.mitre[0]).split(':')[0].trim() : '';
      push({
        key: f.kind,
        title: v.title || v.name || f.kind.split('.').slice(1).join('.'),
        category: v.category || f.kind.split('.')[1] || 'finding',
        severity: normSev(v.severity),
        host: (f.scope || '').replace(/^host:/, '').replace(/^domain:/, '') || 'engagement',
        evidence: v.evidence || v.detail || '',
        remediation: v.remediation || v.fix || cardMeta.fix || '',
        attack: v.attack || byMove[cardId] || mitre0 || '',
        nist: v.nist || parseCodeFirst(refMeta.nist) || '',
        cwe: v.cwe || parseCodeFirst(refMeta.cwe) || '',
        cve: parseCodeFirst(v.cve || cardMeta.cve),
        refs: [].concat(v.refs || [], v.url ? [v.url] : []),
      });
    });

    var eng = OBOL.store.active() || {};
    var primary = (eng.targets && eng.targets[0] && eng.targets[0].ip) || 'engagement';

    // 2) Fact-driven catalog findings (assets/engine/findings.js + data/findings-catalog.js).
    if (OBOL.findings && OBOL.findings.assess) {
      OBOL.findings.assess(facts).forEach(function (v) {
        var h = hostForFinding(facts, v.trigger_kinds, primary);
        (v.trigger_kinds || []).forEach(function (tk) {
          coveredTriggerKinds[h + '|' + tk] = 1;
          coveredTriggerKinds['*|' + tk] = 1;
        });
        var fnd = push({
          key: v.key || slug(v.title),
          title: v.title,
          category: v.category || 'finding',
          severity: normSev(v.severity),
          host: h,
          evidence: v.evidence || '',
          remediation: v.remediation || '',
          attack: v.attack || '',
          nist: v.nist || '',
          cwe: v.cwe || '',
          cis: v.cis || '',
          pci: v.pci || '',
          cve: v.cve || '',
          refs: Array.isArray(v.refs) ? v.refs.slice() : (v.refs ? [v.refs] : []),
          trigger_kinds: v.trigger_kinds ? v.trigger_kinds.slice() : [],
        });
        (v.trigger_kinds || []).forEach(function (tk) {
          if (byKind[tk]) markTech(h, byKind[tk], fnd);
        });
      });
    }

    // 3) Operator-proven activities whose pack action carries a report block, deduplicated against
    // catalog findings and filtered to suppress redundant operational validation/shell milestones.
    var actions = (OBOL.packs && OBOL.packs.actions) ? OBOL.packs.actions() : [];
    var byId = {}; actions.forEach(function (a) { byId[a.id] = a; });
    var NON_VULN_FACT_RE = /^(blocker\.|credential\.validation$|objective\.|proof\.|smb\.reachable$|http\.reachable$|ldap\.reachable$|kerberos\.reachable$|winrm\.reachable$|ssh\.reachable$|host\.|os\.|ad\.domain_known$|ad\.base_dn$|ad\.dc_candidate$)/;
    var GENERIC_REQ_RE = /^(foothold\.|access\.|credential\.(?:available|plaintext|candidate)$|smb\.authenticated$|winrm\.authenticated$|http\.reachable$|port:)/;

    var deferredMilestones = [];

    (eng.activities || []).forEach(function (act) {
      if (!act || !act.action_id || /^flag-hunt-/.test(act.action_id) || !(act.produced || []).length) return;
      var a = byId[act.action_id]; if (!a || !a.report || !a.report.finding) return;
      var sev = normSev(a.report.severity);
      if (sev === 'info') return;
      var aProduces = Array.isArray(a.produces) ? a.produces : [];
      var rawProd = (act.produced || []).filter(function (k) { return !NON_VULN_FACT_RE.test(k); });
      var meaningfulProd = rawProd.filter(function (k) {
        return !aProduces.length || aProduces.indexOf(k) >= 0;
      });
      if (!meaningfulProd.length) return;
      var h = (act.scope || '').replace(/^host:/, '').replace(/^domain:/, '') || act.target || primary || 'engagement';
      var specReqs = [].concat(a.requires_all || [], a.requires_any || []).filter(function (k) { return !GENERIC_REQ_RE.test(k); });
      var uncoveredProd = meaningfulProd.filter(function (k) { return !coveredTriggerKinds[h + '|' + k] && !coveredTriggerKinds['*|' + k]; });
      if (!uncoveredProd.length) return;
      if (specReqs.length && specReqs.some(function (k) { return coveredTriggerKinds[h + '|' + k] || coveredTriggerKinds['*|' + k]; })
          && uncoveredProd.every(function (k) { return /^(access\.|foothold\.|credential\.|hash\.|loot\.)/.test(k); })) return;

      var cardMeta = (meta && meta.cards && meta.cards[act.action_id]) || {};
      var lane = a.lane || a.category || '';
      var laneMeta = (meta && meta.laneDefaults && meta.laneDefaults[lane]) || {};
      var refCardMeta = (meta && meta.references && meta.references.cards && meta.references.cards[act.action_id]) || {};
      var refLaneMeta = (meta && meta.references && meta.references.lanes && meta.references.lanes[lane]) || {};
      var mitre0 = (cardMeta.mitre && cardMeta.mitre[0]) ? String(cardMeta.mitre[0]).split(':')[0].trim() : '';
      var tid = byMove[act.action_id] || mitre0 || '';
      if (!tid) {
        uncoveredProd.some(function (k) { if (byKind[k]) { tid = byKind[k]; return true; } return false; });
      }

      // Deduplicate when a catalog finding already covers this exact offensive technique on the host/domain
      // (for example, catalog `gpp-cpassword` + activity `gpp-passwords` both proving T1552.006).
      var existingTechFnd = tid ? (coveredTechByHost[h + '|' + tid] || coveredTechByHost['*|' + tid]) : null;
      if (existingTechFnd) {
        if (!existingTechFnd.evidence && act.command) existingTechFnd.evidence = act.command;
        return;
      }

      var isMilestone = !!MILESTONE_MOVES[act.action_id]
        || MILESTONE_TITLE_RE.test(String(a.report.finding || '').trim())
        || uncoveredProd.every(function (k) { return MILESTONE_ONLY_FACT_RE.test(k); });

      var candidate = {
        key: act.action_id,
        title: a.report.finding,
        category: (a.produces && a.produces[0] ? a.produces[0].split('.')[0] : 'finding'),
        severity: sev,
        host: h,
        evidence: act.command || '',
        remediation: a.report.remediation || cardMeta.fix || laneMeta.fix || '',
        attack: tid,
        nist: parseCodeFirst(refCardMeta.nist) || parseCodeFirst(refLaneMeta.nist) || '',
        cwe: parseCodeFirst(refCardMeta.cwe) || parseCodeFirst(refLaneMeta.cwe) || '',
        cve: parseCodeFirst(a.cve || cardMeta.cve),
        refs: [].concat(a.refs || []),
        trigger_kinds: uncoveredProd.slice(),
      };

      if (isMilestone) {
        deferredMilestones.push(candidate);
        return;
      }
      uncoveredProd.forEach(function (tk) { coveredTriggerKinds[h + '|' + tk] = 1; });
      push(candidate);
    });

    // Only emit an operational credential/access milestone when no root-cause weakness finding exists
    // yet (e.g., an assumed-breach engagement starting from supplied credentials).
    if (!out.length && deferredMilestones.length) {
      var m0 = deferredMilestones[0];
      if (MILESTONE_TITLE_RE.test(m0.title)) {
        m0.title = 'Compromised or Reused Credentials Accepted Across Target Services';
      }
      m0.attack = m0.attack || 'T1078';
      m0.nist = m0.nist || 'IA-5';
      m0.cwe = m0.cwe || 'CWE-522';
      m0.remediation = m0.remediation || 'Rotate the affected password immediately, enforce phishing-resistant MFA, deploy Windows LAPS for unique local admin passwords, and restrict privileged accounts via AD Tiering.';
      push(m0);
    }

    out.forEach(enrichFindingLinks);
    return out;
  }

  function identity(host) {
    if (!host || /[^0-9.]/.test(host)) return { ip: host, hostname: '' };
    try { return (OBOL.store && OBOL.store.targetIdentity) ? OBOL.store.targetIdentity(host) : { ip: host, hostname: '' }; }
    catch (e) { return { ip: host, hostname: '' }; }
  }
  function hostPill(host) {
    if (!host) return '';
    var id = identity(host), hn = id && id.hostname ? id.hostname : '';
    var tip = hn && hn !== host ? (host + ' · ' + hn) : host;
    return '<span class="pill finding-host"' + (hn ? ' title="' + attr(tip) + '"' : '') + '>'
      + esc(host) + (hn ? '<span class="finding-hostname">' + esc(hn) + '</span>' : '') + '</span>';
  }

  function findingLinksRow(f) {
    var extHtml = (f.extLinks || []).map(function (l) {
      return '<a class="f-ref-chip kind-' + esc(l.kind) + '" href="' + attr(l.url) + '" target="_blank" rel="noopener">'
        + esc(l.label) + ' <span class="f-ext-arr" aria-hidden="true">↗</span></a>';
    }).join('');
    var jumpHtml = (f.jumps || []).map(function (j) {
      return '<button type="button" class="f-jump-chip" data-fwjump="' + attr(j.view) + '" data-target="' + attr(j.target) + '" title="Open in ' + attr(j.view.toUpperCase()) + ' tab">'
        + esc(j.label) + ' <span aria-hidden="true">→</span></button>';
    }).join('');
    if (!extHtml && !jumpHtml) return '';
    return '<div class="finding-links">'
      + (extHtml ? '<div class="finding-ext-links">' + extHtml + '</div>' : '')
      + (jumpHtml ? '<div class="finding-jump-links">' + jumpHtml + '</div>' : '')
      + '</div>';
  }

  function findingCard(f, showHost) {
    return '<article class="finding sev-' + esc(f.severity) + '" id="' + attr(f.id || '') + '"><div class="finding-head">'
      + '<span class="sev-chip sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span>'
      + '<span class="finding-title">' + esc(f.title) + '</span>'
      + (f.kev ? '<span class="fw-badge kev">CISA KEV</span>' : '')
      + (showHost ? hostPill(f.host) : '')
      + '<span class="finding-cat">' + esc(f.category) + '</span></div>'
      + (f.evidence ? '<div class="finding-ev"><span class="mini-label">Evidence</span> ' + esc(String(f.evidence).slice(0, 320)) + '</div>' : '')
      + (f.remediation ? '<div class="finding-fix"><span class="mini-label">Fix</span> ' + esc(f.remediation) + '</div>' : '')
      + findingLinksRow(f)
      + '</article>';
  }

  function bySeverity(findings) {
    var bySev = {}; SEV_ORDER.forEach(function (s) { bySev[s] = []; });
    findings.forEach(function (f) { (bySev[f.severity] = bySev[f.severity] || []).push(f); });
    return SEV_ORDER.filter(function (s) { return bySev[s].length; }).map(function (s) {
      return '<div class="finding-group">' + bySev[s].map(function (f) { return findingCard(f, true); }).join('') + '</div>';
    }).join('');
  }

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
      var open = fhOpen(host);
      return '<details class="finding-host-group" data-fhkey="' + attr(host) + '"' + (open ? ' open' : '') + '>'
        + '<summary class="finding-host-h"><span class="fhh-ip">' + esc(host) + '</span>'
        + (hn ? '<span class="fhh-name">' + esc(hn) + '</span>' : '')
        + '<span class="fhh-count">' + group.length + ' finding' + (group.length === 1 ? '' : 's') + '</span>'
        + '<span class="fhh-sevs">' + breakdown + '</span></summary>'
        + '<div class="finding-group">' + group.map(function (f) { return findingCard(f, false); }).join('') + '</div></details>';
    }).join('');
  }

  // ── Frameworks sub-views (ATT&CK matrix, Defensive, Compliance, CVEs) ──────────────────────
  function fwModel(precomputedFindings) {
    try {
      if (!(OBOL.frameworks && OBOL.ATTACK && OBOL.ATTACK.techniques)) return null;
      var acts = (OBOL.store.active() || {}).activities || [];
      var fnds = precomputedFindings || gather();
      return OBOL.frameworks.compute(OBOL.store.factSet(), { findings: fnds, activities: acts });
    } catch (e) { return null; }
  }

  var FW_TABS = [
    ['findings', 'Findings'],
    ['attack', 'ATT&CK'],
    ['defensive', 'Defensive'],
    ['compliance', 'Compliance'],
    ['cves', 'CVEs'],
  ];
  function fwTabBar(active, counts) {
    counts = counts || {};
    return '<div class="fw-tabs" role="tablist">' + FW_TABS.map(function (t) {
      var n = counts[t[0]];
      var badge = (typeof n === 'number' && n > 0) ? (' <span class="fw-tab-n">' + n + '</span>') : '';
      return '<button type="button" class="fw-tab' + (t[0] === active ? ' active' : '') + '" data-fwview="' + t[0]
        + '" role="tab" aria-selected="' + (t[0] === active) + '">' + esc(t[1]) + badge + '</button>';
    }).join('') + '</div>';
  }

  // Full blue-team card for one used ATT&CK technique: zero empty rows, clickable D3FEND + M10xx links,
  // concrete Event IDs / Sysmon / auditd telemetry, and merged engagement + playbook hardening steps.
  function techCardHtml(def, i) {
    function row(labelCls, label, inner) {
      return '<div class="fw-tech-row"><span class="mini-label ' + labelCls + '">' + label + '</span><div class="fw-tech-vals">' + inner + '</div></div>';
    }
    var hue = 'fw-tc-' + ((i || 0) % 6);
    var url = def.url || ('https://attack.mitre.org/techniques/' + def.id.replace('.', '/') + '/');
    var tacBadges = (def.tactics || []).slice(0, 2).map(function (ta) {
      return '<span class="fw-tech-tac">' + esc(ta.replace(/-/g, ' ')) + '</span>';
    }).join('');

    var d3Chips = (def.d3fend || []).map(function (c) {
      var cUrl = c.url || 'https://d3fend.mitre.org/';
      return '<a class="fw-chip d3 fw-chip-link" href="' + attr(cUrl) + '" target="_blank" rel="noopener" title="' + attr(c.id + (c.tactic ? ' (' + c.tactic + ')' : '')) + '">'
        + esc(c.name) + ' <span class="fw-chip-code">' + esc(c.id) + '</span> <span aria-hidden="true">↗</span></a>';
    }).join('');

    var mitItems = (def.mitigationItems && def.mitigationItems.length)
      ? def.mitigationItems
      : (def.mitigations || []).map(function (m) { return { name: m, id: '', url: 'https://attack.mitre.org/mitigations/', action: '' }; });
    var mitChips = mitItems.map(function (m) {
      return '<a class="fw-chip mit fw-chip-link" href="' + attr(m.url || 'https://attack.mitre.org/mitigations/') + '" target="_blank" rel="noopener"'
        + (m.action ? ' title="' + attr(m.action) + '"' : '') + '>'
        + (m.id ? '<span class="fw-chip-code">' + esc(m.id) + '</span> ' : '')
        + esc(m.name) + ' <span aria-hidden="true">↗</span></a>';
    }).join('');

    var hardHtml = (def.hardening && def.hardening.length)
      ? '<ul class="fw-hard-list">' + def.hardening.map(function (h) { return '<li>' + esc(h) + '</li>'; }).join('') + '</ul>'
      : '';

    return '<article class="fw-tech ' + hue + '" id="fw-tech-' + attr(def.id) + '" data-techid="' + attr(def.id) + '">'
      + '<div class="fw-tech-h"><a href="' + attr(url) + '" target="_blank" rel="noopener">' + esc(def.id) + ' ↗</a> '
      + '<span class="fw-tech-title">' + esc(def.name) + '</span>' + tacBadges + '</div>'
      + (def.findings && def.findings.length ? row('fw-lbl-you', 'You Did', def.findings.slice(0, 5).map(function (t) {
          return '<span class="fw-chip you">' + esc(String(t).slice(0, 96)) + (String(t).length > 96 ? '…' : '') + '</span>';
        }).join('')) : '')
      + (d3Chips ? row('fw-lbl-d3', 'D3FEND Counters', d3Chips) : '')
      + (def.detection ? row('fw-lbl-det', 'Detect', '<span class="fw-tech-det">' + esc(def.detection) + '</span>') : '')
      + (def.dataSources && def.dataSources.length ? row('fw-lbl-data', 'Telemetry &amp; Event IDs', def.dataSources.map(function (d) {
          return '<span class="fw-chip data">' + esc(d) + '</span>';
        }).join('')) : '')
      + (hardHtml ? '<div class="fw-tech-row"><span class="mini-label fw-lbl-hard">Concrete Hardening</span>' + hardHtml + '</div>' : '')
      + (mitChips ? row('fw-lbl-mit', 'ATT&amp;CK Mitigations', mitChips) : '')
      + '</article>';
  }

  function renderAttack(m) {
    var A = m.attack;
    var ui = (OBOL.store.active() || {}).ui || {};
    var scope = (ui.fwAttackScope === 'used' || ui.fwAttackScope === 'all') ? ui.fwAttackScope : 'obol';
    if (!A.usedTotal && scope === 'used') scope = 'obol';
    var mode = (ui.fwMatrixMode === 'compact') ? 'compact' : 'labeled';

    if (!A.tactics.length) {
      return '<p class="route-sub">ATT&CK catalog is unavailable.</p>';
    }

    var usedCols = A.tactics.filter(function (c) { return c.usedCount; }).length;
    var kcStrip = '<div class="fw-kc">' + m.killchain.map(function (s, i) {
      var n = s.techniques.length;
      return (i ? '<span class="fw-kc-arrow">›</span>' : '') + '<span class="fw-kc-stage' + (n ? ' hit' : '') + '">' + esc(s.name) + (n ? ' <b>' + n + '</b>' : '') + '</span>';
    }).join('') + '</div>';

    var visibleCols = A.tactics.map(function (col) {
      var filtered = col.cells.filter(function (c) {
        if (scope === 'used') return c.used;
        if (scope === 'obol') return c.used || c.covered;
        return true;
      });
      return { id: col.id, name: col.name, cells: filtered, usedCount: col.usedCount, coveredCount: col.coveredCount, total: col.total };
    }).filter(function (col) { return col.cells.length > 0; });

    var colsHtml = visibleCols.map(function (col, ci) {
      var cells = col.cells.map(function (c) {
        var canShow = !c.used && c.covered;
        var aria = c.id + ' ' + c.name + (c.used ? ', used this engagement' + (c.subs.length ? ' (' + c.subs.length + ' sub-technique' + (c.subs.length === 1 ? '' : 's') + ')' : '') : (canShow ? ', not done yet, OBOL has an example' : ', out of OBOL scope'));
        return '<button type="button" class="fw-cell' + (c.used ? ' used' : (canShow ? ' can-show' : ' out-scope')) + '" data-tech="' + attr(c.id) + '"'
          + ' aria-label="' + attr(aria) + '"' + (c.used || canShow ? '' : ' tabindex="-1"') + '>'
          + '<span class="fw-cell-body"><span class="fw-cell-id">' + esc(c.id) + '</span><span class="fw-cell-n">' + esc(c.name) + '</span></span>'
          + (c.subs.length ? '<span class="fw-cell-st" aria-hidden="true">' + c.subs.length + '</span>'
             : (canShow ? '<span class="fw-cell-dot" aria-hidden="true"></span>' : '')) + '</button>';
      }).join('');
      var subCountLabel = scope === 'all'
        ? (col.total + ' tech')
        : (col.cells.length + ' in view');
      return '<div class="fw-col fw-tac-' + (ci % 14) + '" data-tactic="' + attr(col.id) + '"><div class="fw-col-h"><span class="fw-col-n">' + esc(col.name) + '</span>'
        + '<span class="fw-col-c"><span>' + esc(subCountLabel) + '</span>'
        + (col.usedCount ? '<span class="fw-col-hit">' + col.usedCount + ' hit</span>' : '') + '</span></div>'
        + '<div class="fw-col-cells">' + cells + '</div></div>';
    }).join('');

    var toolbar = '<div class="fw-mx-bar">'
      + '<div class="fw-mx-toggle" role="group" aria-label="Matrix scope">'
      + '<button type="button" class="fw-scope-btn' + (scope === 'obol' ? ' active' : '') + '" data-fwscope="obol">OBOL Scope <span class="fw-btn-cnt">' + (A.coveredTotal || 0) + '</span></button>'
      + '<button type="button" class="fw-scope-btn' + (scope === 'used' ? ' active' : '') + '" data-fwscope="used"' + (!A.usedTotal ? ' disabled' : '') + '>Used Only <span class="fw-btn-cnt">' + (A.usedTotal || 0) + '</span></button>'
      + '<button type="button" class="fw-scope-btn' + (scope === 'all' ? ' active' : '') + '" data-fwscope="all">Full Enterprise <span class="fw-btn-cnt">' + (A.enterpriseTotal || 222) + '</span></button>'
      + '</div>'
      + '<div class="fw-mx-toggle" role="group" aria-label="Matrix density">'
      + '<button type="button" class="fw-mx-btn' + (mode === 'labeled' ? ' active' : '') + '" data-fwmx="labeled">Labeled</button>'
      + '<button type="button" class="fw-mx-btn' + (mode === 'compact' ? ' active' : '') + '" data-fwmx="compact">Compact</button>'
      + '</div>'
      + '<div class="fw-mx-legend" aria-label="Cell legend">'
      + '<span class="fw-leg-item"><span class="fw-leg-sw used"></span>Hit This Run</span>'
      + '<span class="fw-leg-item"><span class="fw-leg-sw ready"></span>OBOL Ready (Click for Command)</span>'
      + (scope === 'all' ? '<span class="fw-leg-item"><span class="fw-leg-sw out"></span>Enterprise Reference</span>' : '')
      + '</div>'
      + '</div>';

    var intro = A.usedTotal
      ? ('Your ATT&amp;CK coverage this engagement: <b>' + A.usedTotal + '</b> top-level technique' + (A.usedTotal === 1 ? '' : 's') + ' across <b>' + usedCols + '</b> tactic' + (usedCols === 1 ? '' : 's') + '. Alert-lit cells mark what you executed or proved; tactic-tinted cells show techniques OBOL can demonstrate with a copyable command. ATT&amp;CK v' + esc(A.version || '') + '.')
      : ('No engagement moves recorded yet, showing the <b>' + (A.coveredTotal || 0) + '</b> ATT&amp;CK techniques OBOL covers across its offensive packs. Click any cell to inspect the copyable OBOL command. ATT&amp;CK v' + esc(A.version || '') + '.');

    return '<p class="route-sub">' + intro + '</p>'
      + kcStrip + toolbar
      + '<div class="fw-matrix-wrap"><div class="fw-matrix fw-matrix--' + mode + '">' + colsHtml + '</div></div>'
      + '<div id="fw-detail" class="fw-detail"><p class="fw-detail-hint">Select an alert-lit technique for what you did, its Event ID telemetry, and concrete hardening. Select any tactic-tinted cell for the copyable OBOL command that performs it.</p></div>';
  }

  function techDetail(m, cellId) {
    var ids = Object.keys(m.use).filter(function (u) { return u === cellId || parentOf(u) === cellId; });
    var defs = ids.map(function (id) { return m.defensive.find(function (d) { return d.id === id; }); }).filter(Boolean);
    if (!defs.length) return '<p class="fw-detail-hint">Nothing recorded for this technique.</p>';
    return '<div class="fw-tech-grid">' + defs.map(techCardHtml).join('') + '</div>';
  }

  function exampleDetail(m, cellId) {
    var cat = (OBOL.ATTACK && OBOL.ATTACK.techniques) || {}, t = cat[cellId] || {};
    var pack = (m && m.pack) || (OBOL.packs && OBOL.packs.actions ? OBOL.packs.actions() : []);
    var params = {}; try { params = (OBOL.store.active() || {}).params || {}; } catch (e) {}
    var ex = OBOL.frameworks.exampleCommands(cellId, pack, { params: params, max: 4 });
    if (!ex.length) return '<p class="fw-detail-hint">No OBOL example command for this Enterprise technique.</p>';
    var url = t.url || ('https://attack.mitre.org/techniques/' + cellId.replace('.', '/') + '/');
    return '<div class="fw-ex-head"><a href="' + attr(url) + '" target="_blank" rel="noopener">' + esc(cellId) + ' ↗</a> ' + esc(t.n || cellId)
      + ' <span class="fw-ex-sub">You have not executed this technique yet. Representative OBOL pack commands:</span></div>'
      + '<div class="fw-ex-grid">' + ex.map(function (e) {
          return '<div class="fw-ex"><div class="fw-ex-h">' + esc(e.title) + (e.tool ? ' <span class="fw-ex-tool">' + esc(e.tool) + '</span>' : '') + '</div>'
            + '<div class="fw-ex-cmd"><code>' + esc(e.run) + '</code>'
            + '<button type="button" class="btn-copy" data-copy="' + attr(e.run) + '" title="Copy command" aria-label="Copy command">Copy</button></div></div>';
        }).join('') + '</div>'
      + '<p class="fw-ex-note">Example values substitute active engagement parameters when known, falling back to teaching placeholders.</p>';
  }

  function fwExamplesHtml(m, technique, opts) {
    opts = opts || {};
    var pack = (m && m.pack) || (OBOL.packs && OBOL.packs.actions ? OBOL.packs.actions() : []);
    var params = {};
    try { params = (OBOL.store.active() || {}).params || {}; } catch (e) {}
    var ex = OBOL.frameworks.exampleCommands(technique, pack, { params: params, max: opts.max || 2 });
    if (!ex.length) return '';
    return '<div class="fw-hc-lbl">' + esc(opts.label || 'In OBOL This Looks Like') + '</div>'
      + ex.map(function (e) {
          return '<div class="fw-hc-ex"><div class="fw-hc-exh">' + esc(e.tool || e.title)
            + (e.tool ? ' <span class="fw-hc-exm">' + esc(e.title) + '</span>' : '') + '</div>'
            + '<code class="fw-hc-exc">' + esc(e.run) + '</code></div>';
        }).join('');
  }

  function fwHoverHtml(m, cellId) {
    var cat = (OBOL.ATTACK && OBOL.ATTACK.techniques) || {};
    var tacs = (OBOL.ATTACK && OBOL.ATTACK.tactics) || [];
    var d3Pb = (OBOL.D3FEND && OBOL.D3FEND.playbooks) || {};
    var t = cat[cellId] || {};
    var ids = Object.keys(m.use).filter(function (u) { return u === cellId || parentOf(u) === cellId; });
    var tacNames = (t.ta || []).map(function (s) { var ta = tacs.find(function (x) { return x.id === s; }); return ta ? ta.name : s; });
    var head = '<div class="fw-hc-h"><span class="fw-hc-id">' + esc(cellId) + '</span> <span class="fw-hc-n">' + esc(t.n || cellId) + '</span></div>'
      + (tacNames.length ? '<div class="fw-hc-tac">' + tacNames.map(function (n) { return '<span class="fw-hc-tag">' + esc(n) + '</span>'; }).join('') + '</div>' : '');

    var detText = t.det || (d3Pb[cellId] && d3Pb[cellId].det) || '';
    if (!ids.length) {
      var examples = fwExamplesHtml(m, cellId, { label: 'In OBOL This Looks Like' });
      var un = '<div class="fw-hc-un">' + (examples ? 'Not executed yet this run.' : 'Not observed this engagement.') + '</div>';
      if (detText) un += '<div class="fw-hc-row"><span class="fw-hc-lbl">A Defender Spots It By</span> ' + esc(String(detText).slice(0, 220)) + (String(detText).length > 220 ? '…' : '') + '</div>';
      un += examples;
      return '<div class="fw-hovercard not-used' + (examples ? ' can-show' : '') + '">' + head + un + '</div>';
    }

    var fins = [], moves = [], subs = {}, det = detText, d3names = {};
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
    body += '<div class="fw-hc-foot">Click for full blue-team playbook</div>';
    return '<div class="fw-hovercard">' + head + body + '</div>';
  }

  function fwD3HoverHtml(m, name, code, counterIds) {
    var cat = (OBOL.ATTACK && OBOL.ATTACK.techniques) || {};
    var head = '<div class="fw-hc-h">' + (code ? '<span class="fw-hc-id">' + esc(code) + '</span> ' : '') + '<span class="fw-hc-n">' + esc(name || 'Countermeasure') + '</span></div>'
      + '<div class="fw-hc-tac"><span class="fw-hc-tag d3">MITRE D3FEND Countermeasure</span></div>';
    var techNames = counterIds.map(function (id) { return cat[id] && cat[id].n ? (id + ' ' + cat[id].n) : id; });
    var body = techNames.length ? '<div class="fw-hc-row"><span class="fw-hc-lbl">Counters Your Moves</span> '
      + techNames.slice(0, 5).map(function (n) { return '<span class="fw-hc-tag">' + esc(n) + '</span>'; }).join('')
      + (techNames.length > 5 ? ' <span class="fw-hc-more">plus ' + (techNames.length - 5) + ' more</span>' : '') + '</div>' : '';
    var pack = (m && m.pack) || (OBOL.packs && OBOL.packs.actions ? OBOL.packs.actions() : []);
    var params = {}; try { params = (OBOL.store.active() || {}).params || {}; } catch (e) {}
    var cmds = [], seen = {};
    counterIds.forEach(function (id) {
      OBOL.frameworks.exampleCommands(id, pack, { params: params, max: 2 }).forEach(function (e) { if (!seen[e.moveId]) { seen[e.moveId] = 1; cmds.push(e); } });
    });
    if (cmds.length) {
      body += '<div class="fw-hc-lbl">OBOL Commands This Blocks</div>'
        + cmds.slice(0, 3).map(function (e) {
            return '<div class="fw-hc-ex"><div class="fw-hc-exh">' + esc(e.tool || e.title)
              + (e.tool ? ' <span class="fw-hc-exm">' + esc(e.title) + '</span>' : '') + '</div>'
              + '<code class="fw-hc-exc">' + esc(e.run) + '</code></div>';
          }).join('');
    }
    body += '<div class="fw-hc-foot">Click to filter Per Technique cards below</div>';
    return '<div class="fw-hovercard can-show">' + head + body + '</div>';
  }

  var D3_TACTIC_DEF = {
    Model: 'Asset inventory and modelling', Harden: 'Reduce the attack surface before an attack',
    Detect: 'Identify adversary activity', Isolate: 'Contain and limit access',
    Deceive: 'Mislead the adversary', Evict: 'Remove the adversary', Restore: 'Return to a known-good state',
  };

  function renderDefensive(m) {
    if (!m.defensive.length) return '<p class="route-sub">No techniques to defend against yet. Run and paste moves in the Cockpit or Evidence tab first.</p>';
    var ui = (OBOL.store.active() || {}).ui || {};
    var activeD3 = ui.fwD3Filter || '';
    var d3 = m.d3fend || { tactics: [] };
    var activeItem = null;
    d3.tactics.forEach(function (col) {
      col.items.forEach(function (it) { if (it.id === activeD3) activeItem = it; });
    });
    if (!activeItem) activeD3 = '';

    var out = '<p class="route-sub">Blue-team detection, Event ID telemetry, and concrete hardening for every ATT&amp;CK technique observed this engagement, organized by the MITRE D3FEND defensive-tactic matrix. Click any D3FEND countermeasure to filter the technique cards below.</p>';

    if (d3.tactics.length) {
      out += '<div class="fw-d3-wrap"><div class="fw-d3-matrix">' + d3.tactics.map(function (col) {
        var cells = col.items.map(function (it) {
          var isSel = it.id === activeD3;
          return '<button type="button" class="fw-d3-cell' + (isSel ? ' active' : '') + '" data-d3id="' + attr(it.id) + '" data-d3name="' + attr(it.name) + '" data-counters="' + attr(it.counters.join(',')) + '"'
            + ' aria-pressed="' + isSel + '" aria-label="' + attr(it.name + ' (' + it.id + '), filter ' + it.counters.length + ' technique' + (it.counters.length === 1 ? '' : 's')) + '">'
            + '<span class="fw-d3-n">' + esc(it.name) + '</span>'
            + '<span class="fw-d3-code">' + esc(it.id) + '</span>'
            + '<span class="fw-d3-c">' + it.counters.length + '</span></button>';
        }).join('');
        return '<div class="fw-d3-col fw-d3t-' + esc(col.tactic.toLowerCase()) + '"><div class="fw-d3-h"><span class="fw-d3-tn">' + esc(col.tactic) + '</span>'
          + '<span class="fw-d3-td">' + esc(D3_TACTIC_DEF[col.tactic] || '') + '</span></div>'
          + '<div class="fw-d3-cells">' + cells + '</div></div>';
      }).join('') + '</div></div>';
    }

    var visibleDefs = activeItem
      ? m.defensive.filter(function (dfn) { return activeItem.counters.indexOf(dfn.id) >= 0; })
      : m.defensive;

    var filterBanner = activeItem
      ? '<div class="fw-d3-filter-bar">'
        + '<span class="fw-d3-fb-lbl">Filtered by D3FEND Countermeasure:</span> '
        + '<b>' + esc(activeItem.name) + '</b> <span class="fw-chip-code">' + esc(activeItem.id) + '</span>'
        + '<span class="fw-d3-fb-cnt">(' + visibleDefs.length + ' of ' + m.defensive.length + ' techniques)</span>'
        + '<a class="f-ref-chip kind-d3" href="' + attr(activeItem.url || 'https://d3fend.mitre.org/') + '" target="_blank" rel="noopener">MITRE D3FEND ↗</a>'
        + '<button type="button" class="fw-d3-clear" data-d3clear="1">Show All (' + m.defensive.length + ')</button>'
        + '</div>'
      : '';

    out += '<div class="fw-sec-head"><h2 class="coach-sec-h">Per Technique (' + visibleDefs.length + ')</h2></div>'
      + filterBanner
      + '<div class="fw-tech-grid">' + visibleDefs.map(techCardHtml).join('') + '</div>';
    return out;
  }

  function complianceSection(id, title, subtitle, list, opts) {
    opts = opts || {};
    if (!list.length) {
      if (!opts.showEmpty) return '';
      return '<section class="fw-comp-sec fw-comp--' + esc(id) + ' is-empty">'
        + '<div class="fw-comp-head"><div><h3>' + esc(title) + ' <span class="fw-comp-n">0</span></h3>'
        + (subtitle ? '<div class="fw-comp-sub">' + esc(subtitle) + '</div>' : '')
        + '</div></div>'
        + '<p class="fw-empty">' + esc(opts.emptyMsg || 'No controls mapped from current findings yet.') + '</p></section>';
    }
    var itemsHtml = list.map(function (e, idx) {
      var fItems = e.findingItems || [];
      var count = fItems.length || e.findings.length;
      var openAttr = (list.length === 1 && idx === 0) ? ' open' : '';
      var findingsDrill = fItems.map(function (fi) {
        return '<div class="fw-comp-fcard sev-' + esc(normSev(fi.severity)) + '">'
          + '<div class="fw-comp-fhead">'
          + '<span class="sev-chip sev-' + esc(normSev(fi.severity)) + '">' + esc(normSev(fi.severity)) + '</span>'
          + '<span class="fw-comp-ftitle">' + esc(fi.title) + '</span>'
          + (fi.host ? hostPill(fi.host) : '')
          + (fi.id ? '<button type="button" class="f-jump-chip" data-fwjump="findings" data-target="' + attr(fi.id) + '">View Finding →</button>' : '')
          + '</div>'
          + (fi.evidence ? '<div class="fw-comp-fev"><span class="mini-label">Evidence</span> <code>' + esc(String(fi.evidence).slice(0, 180)) + (String(fi.evidence).length > 180 ? '…' : '') + '</code></div>' : '')
          + (fi.remediation ? '<div class="fw-comp-ffix"><span class="mini-label">Fix</span> ' + esc(fi.remediation) + '</div>' : '')
          + '</div>';
      }).join('');

      return '<details class="fw-comp-item" data-comp-key="' + attr(String(e.key).toUpperCase()) + '"' + openAttr + '>'
        + '<summary class="fw-comp-sum">'
        + '<span class="fw-comp-k">'
        + '<span class="fw-comp-title">' + esc(e.shortTitle || e.title || e.key) + '</span>'
        + (e.family && (e.shortTitle || '') !== (e.title || '') ? ' <span class="fw-comp-fam">' + esc(e.family) + '</span>' : '')
        + (e.csf ? ' <span class="fw-csf">' + esc(e.csf) + '</span>' : '')
        + '</span>'
        + '<span class="fw-comp-f">' + count + ' finding' + (count === 1 ? '' : 's') + '</span>'
        + '</summary>'
        + '<div class="fw-comp-body">'
        + '<div class="fw-comp-desc">'
        + (e.summary ? '<p class="fw-comp-summary">' + esc(e.summary) + '</p>' : '')
        + (e.url ? '<a class="f-ref-chip kind-' + esc(id) + '" href="' + attr(e.url) + '" target="_blank" rel="noopener">' + esc(opts.linkLabel || 'Official Standard') + ' ↗</a>' : '')
        + '</div>'
        + (findingsDrill ? '<div class="fw-comp-findings">' + findingsDrill + '</div>' : '')
        + '</div></details>';
    }).join('');

    return '<section class="fw-comp-sec fw-comp--' + esc(id) + '" data-comp-sec="' + attr(id) + '">'
      + '<div class="fw-comp-head"><div><h3>' + esc(title) + ' <span class="fw-comp-n">' + list.length + '</span></h3>'
      + (subtitle ? '<div class="fw-comp-sub">' + esc(subtitle) + '</div>' : '')
      + '</div>'
      + '<button type="button" class="fw-comp-expall" data-comp-expall="' + attr(id) + '">Expand All</button>'
      + '</div>'
      + '<div class="fw-comp-list">' + itemsHtml + '</div></section>';
  }

  function renderCompliance(m) {
    var c = m.compliance;
    if (!(c.nist.length || c.cis.length || c.pci.length || c.cwe.length || c.owasp.length)) {
      return '<p class="route-sub">No compliance mappings from your current findings yet. Prove findings in the Cockpit or Evidence tab to populate control and weakness crosswalks.</p>';
    }
    var csfStrip = (c.csf && c.csf.length)
      ? '<div class="fw-csf-strip" aria-label="NIST CSF 2.0 Function Posture">' + c.csf.map(function (fn) {
          var hit = fn.findingCount > 0;
          return '<div class="fw-csf-card fw-csf--' + esc(fn.id.toLowerCase()) + (hit ? ' hit' : '') + '" title="' + attr(fn.summary || '') + '">'
            + '<div class="fw-csf-top"><span class="fw-csf-id">' + esc(fn.id) + '</span><span class="fw-csf-name">' + esc(fn.name) + '</span>'
            + '<span class="fw-csf-cnt">' + fn.findingCount + '</span></div>'
            + '<div class="fw-csf-ctrls">' + (fn.controls.length ? esc(fn.controls.join(', ')) : 'No findings mapped') + '</div>'
            + '</div>';
        }).join('') + '</div>'
      : '';

    return '<p class="route-sub">Regulatory controls, security benchmarks, and root-cause weakness classes implicated by your engagement findings. Click any control or weakness row to drill into the requirement, official standard link, and mapped host evidence.</p>'
      + csfStrip
      + '<div class="fw-comp-grid">'
      + complianceSection('nist', 'NIST SP 800-53 Rev 5', 'Federal & enterprise security controls', c.nist, { showEmpty: true, linkLabel: 'NIST CSRC Catalog' })
      + complianceSection('cis', 'CIS Controls v8', 'Prioritized enterprise defense safeguards', c.cis, { showEmpty: true, linkLabel: 'CIS Controls v8', emptyMsg: 'Populated automatically from mapped NIST controls and host findings.' })
      + complianceSection('pci', 'PCI DSS v4.0', 'Payment & segmentation security requirements', c.pci, { showEmpty: true, linkLabel: 'PCI Security Standards', emptyMsg: 'Populated when findings implicate network, configuration, or authentication controls.' })
      + complianceSection('cwe', 'MITRE CWE', 'Root-cause software & configuration weakness classes', c.cwe, { showEmpty: true, linkLabel: 'MITRE CWE Definition' })
      + complianceSection('owasp', 'OWASP Top 10 (2021)', 'Web & application security categories', c.owasp, { showEmpty: true, linkLabel: 'OWASP Top 10', emptyMsg: 'No web-application OWASP Top 10 findings recorded on this target set (expected on pure AD/infrastructure labs).' })
      + '</div>';
  }

  function renderCves(m) {
    if (!m || !m.cves || !m.cves.length) {
      return '<p class="route-sub">No CVEs detected in your current findings. Engagement exposures rooted in misconfigurations, weak credentials, or AD ACLs appear on the Findings, ATT&amp;CK, Defensive, and Compliance tabs.</p>';
    }
    var kevN = m.cves.filter(function (c) { return c.kev; }).length;
    return '<p class="route-sub"><b>' + m.cves.length + '</b> CVE' + (m.cves.length === 1 ? '' : 's') + ' implicated by your findings'
      + (kevN ? ', including <b>' + kevN + '</b> in the CISA Known Exploited Vulnerabilities (KEV) catalog' : '') + '. Actively exploited CVEs sort first.</p>'
      + '<div class="fw-cve-list">' + m.cves.map(function (c) {
          var fix = (c.findings.find(function (x) { return x.remediation; }) || {}).remediation || '';
          var hostBadges = (c.hosts || []).map(hostPill).join('');
          return '<article class="fw-cve' + (c.kev ? ' kev' : '') + '" id="fw-cve-' + attr(c.cve) + '">'
            + '<div class="fw-cve-h">'
            + '<span class="fw-cve-id">' + esc(c.cve) + '</span>'
            + (c.kev ? '<span class="fw-badge kev">Actively Exploited (CISA KEV)</span>' : '')
            + (c.ransomware ? '<span class="fw-badge rw">Known Ransomware Use</span>' : '')
            + hostBadges
            + (c.due ? '<span class="fw-cve-due">CISA remediation due ' + esc(c.due) + '</span>' : '')
            + '</div>'
            + '<div class="fw-cve-f">' + c.findings.map(function (x) {
                return '<div class="fw-cve-frow">'
                  + '<span class="sev-chip sev-' + esc(normSev(x.severity)) + '">' + esc(normSev(x.severity)) + '</span> '
                  + '<span class="fw-cve-ftitle">' + esc(x.title) + '</span>'
                  + (x.id ? ' <button type="button" class="f-jump-chip" data-fwjump="findings" data-target="' + attr(x.id) + '">View Finding →</button>' : '')
                  + '</div>';
              }).join('') + '</div>'
            + (fix ? '<div class="finding-fix"><span class="mini-label">Fix</span> ' + esc(fix) + '</div>' : '')
            + '<div class="finding-links"><div class="finding-ext-links">'
            + '<a class="f-ref-chip kind-cve" href="' + attr(c.nvdUrl || ('https://nvd.nist.gov/vuln/detail/' + c.cve)) + '" target="_blank" rel="noopener">NVD ' + esc(c.cve) + ' ↗</a>'
            + '<a class="f-ref-chip kind-ref" href="' + attr(c.mitreUrl || ('https://www.cve.org/CVERecord?id=' + c.cve)) + '" target="_blank" rel="noopener">CVE.org Record ↗</a>'
            + (c.kev ? '<a class="f-ref-chip kind-kev" href="' + attr(c.kevUrl || 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog') + '" target="_blank" rel="noopener">CISA KEV Catalog ↗</a>' : '')
            + '</div></div>'
            + '</article>';
        }).join('') + '</div>';
  }

  function renderFindingsList(findings) {
    var bySev = {}; SEV_ORDER.forEach(function (s) { bySev[s] = []; });
    findings.forEach(function (f) { (bySev[f.severity] = bySev[f.severity] || []).push(f); });
    var counts = SEV_ORDER.filter(function (s) { return bySev[s].length; })
      .map(function (s) { return '<span class="sev-count sev-' + s + '">' + bySev[s].length + ' ' + s + '</span>'; }).join('');
    var hostCount = (function () { var h = {}; findings.forEach(function (f) { h[f.host] = 1; }); return Object.keys(h).length; })();
    var sort = ((OBOL.store.active() || {}).ui || {}).findingsSort === 'severity' ? 'severity' : 'target';
    var toggle = '<div class="findings-sort" role="group" aria-label="Group findings by"><span class="mini-label">Group by</span>'
      + '<button type="button" class="fsort-btn' + (sort === 'target' ? ' active' : '') + '" data-fsort="target">Target</button>'
      + '<button type="button" class="fsort-btn' + (sort === 'severity' ? ' active' : '') + '" data-fsort="severity">Severity</button></div>';
    var body = sort === 'severity' ? bySeverity(findings) : byTarget(findings);
    return toggle
      + '<p class="route-sub">Proof-bound, deduplicated security findings across ' + hostCount + ' target' + (hostCount === 1 ? '' : 's')
      + ' (' + findings.length + '). ' + counts + '</p>' + body;
  }

  function render() {
    var findings = gather();
    var m = fwModel(findings);
    var compCount = m && m.compliance
      ? (m.compliance.nist.length + m.compliance.cis.length + m.compliance.pci.length + m.compliance.cwe.length + m.compliance.owasp.length)
      : 0;
    var tabCounts = {
      findings: findings.length,
      attack: (m && m.attack && m.attack.usedTotal) || 0,
      defensive: (m && m.defensive && m.defensive.length) || 0,
      compliance: compCount,
      cves: (m && m.cves && m.cves.length) || 0,
    };
    var active = ((OBOL.store.active() || {}).ui || {}).findingsView || 'findings';
    var head = '<section class="findings-route"><div class="findings-head"><h1 class="route-h1">Findings</h1></div>' + fwTabBar(active, tabCounts);

    if (active === 'findings') {
      if (!findings.length) {
        return head + '<p class="route-sub">No findings yet. Run Cockpit moves and paste terminal output on Evidence: every proven exposure (anonymous bind, GPP cpassword, Kerberoasting, AS-REP roastable accounts, weak credentials, exposed shares, web/service vulnerabilities) rolls up here with clickable MITRE/NIST/CWE references and powers the ATT&amp;CK, Defensive, Compliance, and CVE views.</p></section>';
      }
      return head + renderFindingsList(findings) + '</section>';
    }
    if (!m || !m.ready) return head + '<p class="route-sub">Framework data is still loading. Reopen this view in a moment.</p></section>';
    var body = active === 'attack' ? renderAttack(m)
      : active === 'defensive' ? renderDefensive(m)
      : active === 'compliance' ? renderCompliance(m)
      : active === 'cves' ? renderCves(m) : '';
    return head + body + '</section>';
  }

  function clearHoverCards() {
    document.querySelectorAll('.fw-hovercard-float').forEach(function (n) { n.remove(); });
  }

  function flashTarget(el) {
    if (!el) return;
    el.classList.remove('is-jump-target');
    void el.offsetWidth;
    el.classList.add('is-jump-target');
    try { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (e) {
      try { el.scrollIntoView(); } catch (e2) {}
    }
    setTimeout(function () { el.classList.remove('is-jump-target'); }, 2200);
  }

  function focusCrossTabTarget(view, target) {
    if (!target) return;
    requestAnimationFrame(function () {
      var mount = document.getElementById('view') || document;
      if (view === 'attack') {
        var cell = mount.querySelector('.fw-cell[data-tech="' + target.replace(/"/g, '') + '"]');
        if (cell) {
          cell.click();
          flashTarget(cell);
        }
      } else if (view === 'defensive') {
        var card = document.getElementById('fw-tech-' + target) || document.getElementById('fw-tech-' + parentOf(target));
        flashTarget(card);
      } else if (view === 'compliance') {
        var det = mount.querySelector('details.fw-comp-item[data-comp-key="' + target.toUpperCase().replace(/"/g, '') + '"]');
        if (det) {
          det.open = true;
          flashTarget(det);
        }
      } else if (view === 'cves') {
        var cveEl = document.getElementById('fw-cve-' + target.toUpperCase());
        flashTarget(cveEl);
      } else if (view === 'findings') {
        var fEl = document.getElementById(target);
        if (fEl) {
          var hostDet = fEl.closest ? fEl.closest('details.finding-host-group') : null;
          if (hostDet) hostDet.open = true;
          flashTarget(fEl);
        }
      }
    });
  }

  function mounted(ctx) {
    var mount = (ctx && ctx.mount) || document;
    clearHoverCards();

    U.on(mount, 'click', '.fsort-btn', function (e, t) {
      var v = t.getAttribute('data-fsort') === 'severity' ? 'severity' : 'target';
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.findingsSort = v; }, 'ui');
      OBOL.router.render();
    });

    Array.prototype.forEach.call(mount.querySelectorAll('details.finding-host-group[data-fhkey]'), function (d) {
      if (d._fhBound) return; d._fhBound = true;
      d.addEventListener('toggle', function () { fhSetOpen(d.getAttribute('data-fhkey'), d.open); });
    });

    // Sub-view tabs (Findings / ATT&CK / Defensive / Compliance / CVEs)
    U.on(mount, 'click', '.fw-tab', function (e, t) {
      var v = t.getAttribute('data-fwview') || 'findings';
      clearHoverCards();
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.findingsView = v; }, 'ui');
      OBOL.router.render();
    });

    // Cross-tab jump chips (Findings <-> ATT&CK / Defensive / Compliance / CVEs)
    U.on(mount, 'click', '[data-fwjump]', function (e, btn) {
      e.preventDefault();
      e.stopPropagation();
      var view = btn.getAttribute('data-fwjump') || 'findings';
      var target = btn.getAttribute('data-target') || '';
      clearHoverCards();
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.findingsView = view;
        if (view === 'defensive') eng.ui.fwD3Filter = '';
        if (view === 'attack' && eng.ui.fwAttackScope === 'used') eng.ui.fwAttackScope = 'obol';
      }, 'ui');
      OBOL.router.render();
      focusCrossTabTarget(view, target);
    });

    // ATT&CK matrix scope filter (OBOL Scope / Used Only / Full Enterprise)
    U.on(mount, 'click', '.fw-scope-btn', function (e, b) {
      if (b.disabled) return;
      var sc = b.getAttribute('data-fwscope') || 'obol';
      clearHoverCards();
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.fwAttackScope = sc; }, 'ui');
      OBOL.router.render();
    });

    // ATT&CK matrix density toggle (Labeled <-> Compact)
    U.on(mount, 'click', '.fw-mx-btn', function (e, b) {
      var mode = b.getAttribute('data-fwmx') === 'compact' ? 'compact' : 'labeled';
      var mx = mount.querySelector('.fw-matrix');
      if (mx) { mx.classList.remove('fw-matrix--labeled', 'fw-matrix--compact'); mx.classList.add('fw-matrix--' + mode); }
      mount.querySelectorAll('.fw-mx-btn').forEach(function (x) { x.classList.toggle('active', x === b); });
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.fwMatrixMode = mode; }, 'ui');
    });

    // ATT&CK matrix cell -> detail panel
    U.on(mount, 'click', '.fw-cell.used, .fw-cell.can-show', function (e, t) {
      var id = t.getAttribute('data-tech'); if (!id) return;
      var slot = document.getElementById('fw-detail'); if (!slot) return;
      var m = fwModel(); if (!m) return;
      mount.querySelectorAll('.fw-cell.sel').forEach(function (c) { c.classList.remove('sel'); });
      t.classList.add('sel');
      slot.innerHTML = t.classList.contains('used') ? techDetail(m, id) : exampleDetail(m, id);
      try { slot.scrollIntoView({ block: 'nearest' }); } catch (x) {}
    });

    // Defensive D3FEND matrix click-to-filter + reset
    U.on(mount, 'click', '.fw-d3-cell', function (e, cell) {
      var id = cell.getAttribute('data-d3id') || '';
      clearHoverCards();
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.fwD3Filter = (eng.ui.fwD3Filter === id) ? '' : id;
      }, 'ui');
      OBOL.router.render();
    });
    U.on(mount, 'click', '[data-d3clear]', function () {
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.fwD3Filter = ''; }, 'ui');
      OBOL.router.render();
    });

    // Compliance per-card Expand All / Collapse All toggle
    U.on(mount, 'click', '[data-comp-expall]', function (e, btn) {
      var secId = btn.getAttribute('data-comp-expall');
      var sec = mount.querySelector('.fw-comp-sec[data-comp-sec="' + secId + '"]');
      if (!sec) return;
      var items = Array.prototype.slice.call(sec.querySelectorAll('details.fw-comp-item'));
      var anyClosed = items.some(function (d) { return !d.open; });
      items.forEach(function (d) { d.open = anyClosed; });
      btn.textContent = anyClosed ? 'Collapse All' : 'Expand All';
    });

    // Copy example command
    U.on(mount, 'click', '.fw-ex-cmd .btn-copy', function (e, b) {
      U.copy(b.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    function attachHover(wrap, cellSel, keyAttr, htmlFor) {
      if (!wrap) return;
      var card = null, curKey = null, model = null;
      function ensure() {
        if (!card) {
          card = document.createElement('div');
          card.className = 'fw-hovercard-float';
          card.setAttribute('aria-hidden', 'true');
          document.body.appendChild(card);
          if (!window._obolFwHoverHashWired) {
            window._obolFwHoverHashWired = true;
            window.addEventListener('hashchange', function () {
              document.querySelectorAll('.fw-hovercard-float').forEach(function (n) { n.classList.remove('on'); });
            });
          }
        }
        return card;
      }
      function place(x, y) {
        var c = card; if (!c) return;
        var w = c.offsetWidth || 300, h = c.offsetHeight || 150, vw = window.innerWidth, vh = window.innerHeight;
        var left = x + 16; if (left + w > vw - 8) left = x - w - 16; if (left < 8) left = 8;
        var top = y + 18; if (top + h > vh - 8) top = y - h - 18; if (top < 8) top = 8;
        c.style.left = left + 'px'; c.style.top = top + 'px';
      }
      function show(cell, x, y) {
        var key = cell.getAttribute(keyAttr); if (!key) { hide(); return; }
        if (!model) model = fwModel(); if (!model) return;
        if (key !== curKey) { var html = htmlFor(model, cell); if (!html) { hide(); return; } ensure().innerHTML = html; curKey = key; }
        card.classList.add('on'); place(x, y);
      }
      function hide() { if (card) card.classList.remove('on'); curKey = null; }
      wrap.addEventListener('mousemove', function (e) {
        var cell = e.target && e.target.closest ? e.target.closest(cellSel) : null;
        if (cell) show(cell, e.clientX, e.clientY); else hide();
      });
      wrap.addEventListener('mouseleave', hide);
    }
    attachHover(mount.querySelector('.fw-matrix-wrap'), '.fw-cell', 'data-tech', function (m, cell) {
      return fwHoverHtml(m, cell.getAttribute('data-tech'));
    });
    attachHover(mount.querySelector('.fw-d3-wrap'), '.fw-d3-cell', 'data-d3id', function (m, cell) {
      return fwD3HoverHtml(m, cell.getAttribute('data-d3name'), cell.getAttribute('data-d3id'), (cell.getAttribute('data-counters') || '').split(',').filter(Boolean));
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.findings = { render: render, mounted: mounted, unmount: clearHoverCards, gather: gather };
})(typeof globalThis !== 'undefined' ? globalThis : this);
