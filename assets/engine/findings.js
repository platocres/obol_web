/*!
 * obol engine — findings.js
 * Findings catalog match engine. A faithful JS port of 
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

  var STD_SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy'
  ];
  var HEADER_ALIASES = {
    'hsts': 'strict-transport-security',
    'csp': 'content-security-policy'
  };
  var FLAG_ALIASES = [
    ['cors_null_origin', 'cors_null'],
    ['cors_origin_reflection', 'cors_origin_reflected'],
    ['missing_spf', 'dns_no_spf'],
    ['weak_spf', 'dns_weak_spf'],
    ['missing_dmarc', 'dns_no_dmarc'],
    ['dmarc_policy_none', 'dns_weak_dmarc'],
    ['tls_outdated_protocol', 'tls_outdated'],
    ['tls_cert_expired', 'tls_expired'],
    ['tls_cert_validation_failed', 'tls_validation_failed'],
    ['hsts_short', 'hsts_weak']
  ];

  function observedFlags(fs) {
    // Every `flags` entry across the observation facts a findings-check produced,
    // plus derived flags from structured fields minted by parsers/findings.js.
    var out = {};
    for (var i = 0; i < FLAG_FACTS.length; i++) {
      var kind = FLAG_FACTS[i];
      var vals = fs.values(kind);
      for (var j = 0; j < vals.length; j++) {
        var v = vals[j] || {};
        if (Array.isArray(v.flags)) {
          for (var k = 0; k < v.flags.length; k++) out[String(v.flags[k])] = 1;
        }
        if (kind === 'http.headers') {
          if (v.server && /\d+\.\d+/.test(String(v.server))) out['server_version_disclosed'] = 1;
        } else if (kind === 'http.methods') {
          if (Array.isArray(v.risky) && v.risky.length) out['http_methods_risky'] = 1;
        } else if (kind === 'http.cors') {
          var orig = v.origin || v.allow_origin || '';
          if (v.misconfigured || orig === 'null' || orig === '*' || v.allow_credentials) {
            if (orig === 'null') { out['cors_null_origin'] = 1; out['cors_null'] = 1; }
            else if (orig === '*') { out['cors_wildcard'] = 1; }
            else if (v.misconfigured || v.allow_credentials) { out['cors_origin_reflection'] = 1; out['cors_origin_reflected'] = 1; }
          }
        } else if (kind === 'http.exposed') {
          if (Array.isArray(v.files) && v.files.length) out['exposed_file'] = 1;
        } else if (kind === 'dns.email') {
          if (v.spf === null || v.spf === '' || v.spf === false) { out['missing_spf'] = 1; out['dns_no_spf'] = 1; }
          else if (typeof v.spf === 'string' && /\+all/i.test(v.spf)) { out['spf_plus_all'] = 1; out['dns_weak_spf'] = 1; }
          else if ((typeof v.spf === 'string' && /[~?]all/i.test(v.spf)) || (v.spf === true && v.weak)) { out['weak_spf'] = 1; out['dns_weak_spf'] = 1; }
          if (v.dmarc === null || v.dmarc === '' || v.dmarc === false) { out['missing_dmarc'] = 1; out['dns_no_dmarc'] = 1; }
          else if ((typeof v.dmarc === 'string' && /p=none/i.test(v.dmarc)) || (v.dmarc === true && v.weak)) { out['dmarc_policy_none'] = 1; out['dns_weak_dmarc'] = 1; }
        } else if (kind === 'dns.takeover') {
          if (v.target || v.fingerprint) out['subdomain_takeover'] = 1;
        } else if (kind === 'tls.info') {
          if (Array.isArray(v.weak_protocols) && v.weak_protocols.length) { out['tls_outdated_protocol'] = 1; out['tls_outdated'] = 1; }
          if (v.cert_issue === 'self-signed') out['tls_self_signed'] = 1;
          if (v.cert_issue === 'expired') { out['tls_cert_expired'] = 1; out['tls_expired'] = 1; }
          if (v.cert_issue) { out['tls_cert_validation_failed'] = 1; out['tls_validation_failed'] = 1; }
        } else if (kind === 'smb.signing') {
          if (v.required === false || v.enabled === false || v.signing === false) out['smb_signing_disabled'] = 1;
        }
      }
    }
    for (var a = 0; a < FLAG_ALIASES.length; a++) {
      var f1 = FLAG_ALIASES[a][0], f2 = FLAG_ALIASES[a][1];
      if (out[f1]) out[f2] = 1;
      if (out[f2]) out[f1] = 1;
    }
    if (out['spf_plus_all']) out['dns_weak_spf'] = 1;
    return out; // plain object used as a set
  }

  function presentHeaders(fs) {
    // (did we observe response headers?, the lowercased header names present).
    var seen = false, names = {};
    var vals = fs.values('http.headers');
    for (var i = 0; i < vals.length; i++) {
      var v = vals[i] || {};
      seen = true;
      var hasHeadersMap = v.headers && typeof v.headers === 'object' && !Array.isArray(v.headers);
      if (hasHeadersMap) {
        for (var name in v.headers) {
          if (Object.prototype.hasOwnProperty.call(v.headers, name)) {
            var hk = String(name).toLowerCase();
            names[hk] = '1';
            if (HEADER_ALIASES[hk]) names[HEADER_ALIASES[hk]] = '1';
          }
        }
      }
      if (Array.isArray(v.present)) {
        for (var p = 0; p < v.present.length; p++) {
          var pk = String(v.present[p]).toLowerCase();
          names[pk] = '1';
          if (HEADER_ALIASES[pk]) names[HEADER_ALIASES[pk]] = '1';
        }
      }
      if (v.server) {
        names['server'] = v.server;
      }
      if (Array.isArray(v.missing) && !hasHeadersMap) {
        var miss = {};
        for (var m = 0; m < v.missing.length; m++) {
          var mk = String(v.missing[m]).toLowerCase();
          miss[mk] = 1;
          if (HEADER_ALIASES[mk]) miss[HEADER_ALIASES[mk]] = 1;
        }
        for (var s = 0; s < STD_SECURITY_HEADERS.length; s++) {
          var sh = STD_SECURITY_HEADERS[s];
          if (!miss[sh]) names[sh] = '1';
        }
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
      if (!m.fact_value) return null;
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

  function flagSourceKinds(flag) {
    var f = String(flag || '');
    if (f === 'smb_signing_disabled') return ['smb.signing'];
    if (f === 'http_methods_risky') return ['http.methods'];
    if (f.indexOf('cors_') === 0) return ['http.cors'];
    if (f === 'exposed_file') return ['http.exposed'];
    if (f === 'server_version_disclosed' || f === 'tech_disclosed' || f === 'csp_weak' || f === 'hsts_short' || f === 'hsts_weak') return ['http.headers'];
    if (f.indexOf('spf_') === 0 || f === 'weak_spf' || f === 'missing_spf' || f.indexOf('dmarc_') === 0 || f === 'missing_dmarc' || f.indexOf('dns_') === 0) return ['dns.email'];
    if (f === 'subdomain_takeover') return ['dns.takeover'];
    if (f.indexOf('tls_') === 0) return ['tls.info'];
    if (f.indexOf('cookie_') === 0) return ['http.cookies'];
    if (f === 'mixed_content' || f === 'password_autocomplete' || f === 'csrf_missing') return ['http.body'];
    if (f === 'http_no_redirect' || f === 'http_serves_content') return ['http.redirect'];
    return FLAG_FACTS.slice();
  }

  function matchTriggerKinds(match) {
    // The observation fact-kinds a catalog `match` rule keys off - the facts obol recorded
    // that PROVE this finding (used to attribute a finding to the host whose facts triggered it).
    if (!match) return [];
    var ks = [];
    ['facts_any', 'facts_all'].forEach(function (key) {
      (match[key] || []).forEach(function (k) { if (typeof k === 'string') ks.push(k); });
    });
    var fv = match.fact_value;
    if (fv && typeof fv === 'object' && fv.kind) ks.push(String(fv.kind));
    if (match.header_absent) ks.push('http.headers');
    if (match.tech) ks.push('web.tech', 'web.server');
    if (match.flag) {
      flagSourceKinds(match.flag).forEach(function (k) { ks.push(k); });
    }
    return ks;
  }

  function findingView(fnd, evidence, kev) {
    // The client/report-facing dict for a matched finding, with the KEV overlay applied.
    var hit = fnd.cve ? kev[String(fnd.cve).trim().toUpperCase()] : null;
    var atk = Array.isArray(fnd.attack) ? (fnd.attack[0] || '') : (fnd.attack || '');
    return {
      key: fnd.key || '', title: fnd.title || '', category: fnd.category || 'other',
      severity: fnd.severity || 'info', confidence: fnd.confidence || 'confirmed',
      cwe: fnd.cwe || '', attack: atk, nist: fnd.nist || '', cve: fnd.cve || '',
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
    // CISA KEV overlay, from the bundled lookup (data/kev-catalog.js) when it is loaded; empty otherwise.
    var kev = (OBOL.KEV && OBOL.KEV.map) || {};
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
