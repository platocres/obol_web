/*!
 * obol engine — findings.js
 * Findings catalog match engine. A faithful JS port of obol-local/obol/findings.py:
 * a fact-driven projection that matches the shipped findings catalog
 * (data/findings-catalog.js → OBOL.findingsCatalog) against a target's proven facts.
 *
 * Every catalog entry carries report metadata (severity + CWE/ATT&CK/NIST + a required
 * remediation and refs) and a `match` rule evaluated against a FactSet. Rule shapes:
 *   {facts_any:[kinds]}                  obol PROVED one of these weaknesses
 *   {facts_all:[kinds]}                  obol PROVED all of these
 *   {flag:"..."}                         an observation fact listed that flag
 *   {fact_value:{kind,field,equals|in}}  a shared fact discriminated by a value field
 *   {header_absent:"..."}                we saw response headers and this one was missing
 *   {tech:"..",version_lt:".."}          a detected tech below the fixed version (candidate)
 *
 * KEV/CVE overlay is stubbed here (kev is always false) — the web edition does not ship
 * the CISA KEV pack. Environment-agnostic: attaches to the global so it works in the
 * window and inside a Web Worker.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // severity → rank (higher sorts first); confidence and the KEV flag break ties.
  var SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  // the observation facts whose `flags` list the catalog's {flag:...} rules match against.
  var FLAG_FACTS = ['tls.info', 'dns.email', 'http.cookies', 'http.cors', 'http.methods',
    'http.headers', 'http.body', 'smb.signing', 'http.exposed', 'http.redirect', 'dns.takeover'];

  // "<component> <version>" inside a free-text tech string ("WordPress 5.8", "jQuery v1.12.4",
  // "Apache/2.4.49"). The name is lazy so it stops at the first separator before the version;
  // 'v' is a separator so a "v1.2.3" prefix is stripped from the version.
  var TECH_VER_RE = /([A-Za-z][A-Za-z0-9 _.\-]*?)[ \/_v\-]+(\d+(?:\.\d+){1,3})/gi;

  function versionTuple(v) {
    // Best-effort numeric version tuple ('3.5.10' -> [3,5,10]); non-numeric parts drop out.
    var parts = [];
    var chunks = String(v).replace(/-/g, '.').replace(/_/g, '.').split('.');
    for (var i = 0; i < chunks.length; i++) {
      var num = chunks[i].replace(/[^0-9]/g, '');
      if (num === '') break;
      parts.push(parseInt(num, 10));
    }
    return parts;
  }

  function tupleLt(a, b) {
    // Python tuple ordering: element-wise, shorter-is-smaller when a prefix.
    var n = Math.max(a.length, b.length);
    for (var i = 0; i < n; i++) {
      var x = i < a.length ? a[i] : undefined;
      var y = i < b.length ? b[i] : undefined;
      if (x === undefined) return true;   // a exhausted first → a < b
      if (y === undefined) return false;  // b exhausted first → a > b
      if (x !== y) return x < y;
    }
    return false; // equal
  }

  function versionLt(a, b) {
    // True if version `a` is strictly below `b` (both best-effort parsed).
    var ta = versionTuple(a), tb = versionTuple(b);
    return ta.length > 0 && tupleLt(ta, tb);
  }

  function observedFlags(fs) {
    // Every `flags` entry across the observation facts a findings-check produced.
    var flags = {};
    for (var i = 0; i < FLAG_FACTS.length; i++) {
      var vals = fs.values(FLAG_FACTS[i]);
      for (var j = 0; j < vals.length; j++) {
        var fl = vals[j].flags || [];
        for (var k = 0; k < fl.length; k++) flags[String(fl[k])] = true;
      }
    }
    return flags; // plain object used as a set
  }

  function presentHeaders(fs) {
    // (did we observe response headers?, the lowercased header names present).
    var seen = false, names = {};
    var vals = fs.values('http.headers');
    for (var i = 0; i < vals.length; i++) {
      seen = true;
      var hdrs = vals[i].headers || {};
      for (var name in hdrs) {
        if (Object.prototype.hasOwnProperty.call(hdrs, name)) names[String(name).toLowerCase()] = true;
      }
    }
    return { seen: seen, names: names };
  }

  function iterTechStrings(v) {
    // Every free-text tech string inside a legacy `web.tech` fact value ({items:[...]}).
    var out = [];
    var items = v.items || [];
    for (var i = 0; i < items.length; i++) {
      var item = items[i];
      if (typeof item === 'string') out.push(item);
      else if (item && typeof item === 'object') out.push(String(item.value || item.version || item.name || ''));
    }
    return out;
  }

  function techVersions(fs) {
    // (lowercased tech name, version) pairs from a host's `web.tech` facts, reading BOTH the
    // precise {name, version} shape and the legacy {items:[...]} free-text recon shape.
    var out = [];
    var vals = fs.values('web.tech');
    for (var i = 0; i < vals.length; i++) {
      var v = vals[i];
      var name = String(v.name || v.tech || '').toLowerCase();
      var ver = String(v.version || '');
      if (name && ver) out.push([name, ver]);
      var strings = iterTechStrings(v);
      for (var s = 0; s < strings.length; s++) {
        TECH_VER_RE.lastIndex = 0;
        var m;
        while ((m = TECH_VER_RE.exec(strings[s])) !== null) {
          out.push([m[1].trim().toLowerCase().replace(/ /g, ''), m[2]]);
        }
      }
    }
    return out;
  }

  function matchRule(fnd, fs) {
    // Return the evidence string if this finding's rule matches the facts, else null.
    var m = fnd.match || {};
    var i;
    var factsAny = m.facts_any || [];
    if (factsAny.length) {
      for (i = 0; i < factsAny.length; i++) {
        if (fs.has(factsAny[i])) return 'proven: ' + factsAny[i];
      }
      return null;
    }
    var factsAll = m.facts_all || [];
    if (factsAll.length) {
      for (i = 0; i < factsAll.length; i++) {
        if (!fs.has(factsAll[i])) return null;
      }
      return 'proven: ' + factsAll.join(', ');
    }
    var flag = m.flag;
    if (flag) {
      return observedFlags(fs)[flag] ? ('observed: ' + flag) : null;
    }
    var fv = m.fact_value;
    if (fv) {
      var want = fv.equals;
      var wantIn = fv['in'] || [];
      var vals = fs.values(fv.kind || '');
      for (i = 0; i < vals.length; i++) {
        var val = vals[i][fv.field || ''];
        if ((want !== undefined && want !== null && val === want) || (wantIn.length && wantIn.indexOf(val) >= 0)) {
          return 'proven: ' + fv.kind + '.' + fv.field + '=' + val;
        }
      }
      return null;
    }
    var header = m.header_absent;
    if (header) {
      var ph = presentHeaders(fs);
      return (ph.seen && !ph.names[header.toLowerCase()]) ? ('response missing `' + header + '`') : null;
    }
    var tech = m.tech;
    if (tech) {
      var vlt = m.version_lt || '';
      var tv = techVersions(fs);
      for (i = 0; i < tv.length; i++) {
        if (tv[i][0] === tech.toLowerCase() && (!vlt || versionLt(tv[i][1], vlt))) {
          return tech + ' ' + tv[i][1] + ' detected (< ' + (vlt || 'any') + ')';
        }
      }
      return null;
    }
    return null; // a rule-less entry never auto-matches
  }

  function matchTriggerKinds(match) {
    // The observation fact-kinds a catalog `match` rule keys off — the facts obol recorded
    // that PROVE this finding (used to attribute a finding to the host whose facts triggered it).
    if (!match) return [];
    var ks = [];
    ['facts_any', 'facts_all'].forEach(function (key) {
      (match[key] || []).forEach(function (k) { if (typeof k === 'string') ks.push(k); });
    });
    var fv = match.fact_value;
    if (fv && typeof fv === 'object' && fv.kind) ks.push(String(fv.kind));
    return ks;
  }

  function findingView(fnd, evidence, kev) {
    // The client/report-facing dict for a matched finding, with the KEV overlay applied.
    var hit = fnd.cve ? kev[fnd.cve] : null; // KEV stubbed → always undefined
    return {
      key: fnd.key || '', title: fnd.title || '', category: fnd.category || 'other',
      severity: fnd.severity || 'info', confidence: fnd.confidence || 'confirmed',
      cwe: fnd.cwe || '', attack: fnd.attack || '', nist: fnd.nist || '', cve: fnd.cve || '',
      remediation: fnd.remediation || '', refs: fnd.refs || [], evidence: evidence,
      trigger_kinds: matchTriggerKinds(fnd.match),
      kev: !!hit,
    };
  }

  function sortCmp(a, b) {
    // Sort findings: KEV first, then severity, then confirmed-before-candidate, then title.
    var ak = a.kev ? 1 : 0, bk = b.kev ? 1 : 0;
    if (ak !== bk) return bk - ak;
    var as = SEV_RANK[a.severity] || 0, bs = SEV_RANK[b.severity] || 0;
    if (as !== bs) return bs - as;
    var ac = a.confidence === 'confirmed' ? 0 : 1, bc = b.confidence === 'confirmed' ? 0 : 1;
    if (ac !== bc) return ac - bc;
    var at = a.title || '', bt = b.title || '';
    return at < bt ? -1 : (at > bt ? 1 : 0);
  }

  function loadCatalog() {
    // The findings catalog (data/findings-catalog.js → OBOL.findingsCatalog); [] on error.
    return (OBOL.findingsCatalog && OBOL.findingsCatalog.length) ? OBOL.findingsCatalog : [];
  }

  function assess(fs) {
    // Every catalog finding whose rule matches these facts, severity-sorted. A projection —
    // safe to call on read. KEV overlay is stubbed (kev:false). `fs` is an OBOL.facts.FactSet.
    var kev = {}; // stubbed: no KEV pack in the web edition
    var out = [];
    if (!fs) return out;
    var catalog = loadCatalog();
    for (var i = 0; i < catalog.length; i++) {
      var fnd = catalog[i];
      var ev = matchRule(fnd, fs);
      if (ev === null) continue;
      out.push(findingView(fnd, ev, kev));
    }
    out.sort(sortCmp);
    return out;
  }

  OBOL.findings = {
    SEV_RANK: SEV_RANK,
    versionLt: versionLt,
    matchTriggerKinds: matchTriggerKinds,
    loadCatalog: loadCatalog,
    assess: assess,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
