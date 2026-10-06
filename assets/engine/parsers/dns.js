/*!
 * obol engine — parsers/dns.js — internal-resolver interrogation.
 *
 * The pivot value chain's DNS link: you discovered the foothold's internal resolver (scan.local.dns),
 * you query it, and what it answers names the rest of the estate. In an AD environment the resolver is
 * almost always a domain controller, and it will hand you the domain name and the DCs outright:
 *   - SRV records _ldap._tcp.dc._msdcs.<domain> / _kerberos._tcp.<domain> point straight at the DCs
 *   - a zone transfer (AXFR), when the resolver allows it, dumps every A record in the zone
 *   - SOA / NS records name the authoritative server (a DC) and the domain
 * So this parser turns a dig / nslookup / host paste into the two facts that unlock the whole AD lane
 * (ad.domain_known, ad.dc_candidate) plus a terminal dns.zone receipt of the transferred records.
 *
 * Conservative: a DC candidate is minted only with a concrete IP (an SRV target resolved against the
 * zone's own A records, or an A/NS/SOA host with an address in the same paste); a bare NXDOMAIN /
 * refused / empty answer mints nothing.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon; if (!C) return;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  function isRoutable(ip) {
    var o = String(ip).split('.'); if (o.length !== 4) return false;
    for (var i = 0; i < 4; i++) { var n = +o[i]; if (!(o[i] !== '' && n >= 0 && n <= 255)) return false; }
    var a = +o[0];
    return a !== 127 && a < 224 && !(a === 169 && +o[1] === 254) && ip !== '0.0.0.0';
  }
  // Strip a trailing dot from a FQDN and lowercase it, so acme.local. and ACME.local compare equal.
  function norm(name) { return String(name || '').replace(/\.$/, '').toLowerCase(); }

  function _parse_dns(text, ws, source, facts) {
    var t = String(text || ''); if (!t) return;
    // nothing to read: an error / empty answer alone mints no fact
    if (/\b(NXDOMAIN|SERVFAIL|REFUSED|connection timed out|Transfer failed|communications error)\b/i.test(t) && !/\bIN\s+(?:A|SRV|SOA|NS)\b/i.test(t) && !/service\s*=/.test(t)) return;

    var aRec = {};      // fqdn -> ip  (from A records across dig / nslookup / host / AXFR)
    var names = {};      // every fqdn seen (for the zone receipt)
    var domain = '', dcNames = {}, m;

    // A records — dig/AXFR row "name. TTL IN A 1.2.3.4", host "name has address 1.2.3.4",
    // nslookup "Name: name \n Address: 1.2.3.4"
    var reA = /([A-Za-z0-9_.-]+?)\.?\s+(?:\d+\s+)?IN\s+A\s+(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reA.exec(t))) { var nm = norm(m[1]); if (isRoutable(m[2])) { aRec[nm] = m[2]; names[nm] = 1; } }
    var reHost = /([A-Za-z0-9_.-]+?)\s+has address\s+(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reHost.exec(t))) { var nh = norm(m[1]); if (isRoutable(m[2])) { aRec[nh] = m[2]; names[nh] = 1; } }
    // Windows nslookup prints an A record as "host  internet address = 1.2.3.4"
    var reNslA = /([A-Za-z0-9_.-]+?)\s+internet address\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reNslA.exec(t))) { var na = norm(m[1]); if (isRoutable(m[2])) { aRec[na] = m[2]; names[na] = 1; } }

    // SOA / NS — the authoritative host is a DC, and the owner name is the domain
    var reSoa = /([A-Za-z0-9_.-]+?)\.?\s+(?:\d+\s+)?IN\s+SOA\s+([A-Za-z0-9_.-]+)/i;
    m = reSoa.exec(t); if (m) { domain = domain || norm(m[1]); dcNames[norm(m[2])] = 1; }
    var reNs = /([A-Za-z0-9_.-]+?)\.?\s+(?:\d+\s+)?IN\s+NS\s+([A-Za-z0-9_.-]+)/gi;
    while ((m = reNs.exec(t))) { domain = domain || norm(m[1]); dcNames[norm(m[2])] = 1; }

    // SRV — the DC locators. dig row "_ldap._tcp.dc._msdcs.acme.local. IN SRV 0 100 389 dc01.acme.local."
    // and nslookup "_ldap._tcp.dc._msdcs.acme.local  service = 0 100 389 dc01.acme.local"
    var reSrv = /_(?:ldap|kerberos|gc|kpasswd)\._tcp(?:\.[A-Za-z0-9_.-]*?)?\.([A-Za-z0-9.-]+?)\.?\s+(?:(?:\d+\s+)?IN\s+SRV|service\s*=)\s+\d+\s+\d+\s+\d+\s+([A-Za-z0-9_.-]+)/gi;
    while ((m = reSrv.exec(t))) {
      var srvDom = norm(m[1]).replace(/^dc\._msdcs\./, '');
      if (!domain) domain = srvDom;
      dcNames[norm(m[2])] = 1;
    }
    // Windows nslookup's multi-line SRV: the owner line "_ldap._tcp.dc._msdcs.<domain>  SRV service
    // location:" gives the domain, and "svr hostname = dc01.<domain>" (A resolved separately above)
    // names the DC.
    var reSrvOwner = /_(?:ldap|kerberos|gc|kpasswd)\._tcp\.([A-Za-z0-9_.-]+?)\s+(?:\d+\s+)?(?:IN\s+)?SRV\b/i;
    m = reSrvOwner.exec(t); if (m && !domain) domain = norm(m[1]).replace(/^dc\._msdcs\./, '');
    var reSvrHost = /svr hostname\s*=\s*([A-Za-z0-9_.-]+)/gi;
    while ((m = reSvrHost.exec(t))) dcNames[norm(m[1])] = 1;

    Object.keys(names).forEach(function (n) { if (!domain && n.indexOf('.') > 0 && aRec[n]) { /* leave domain to authoritative records */ } });

    if (domain) _add(facts, mkFact('ad.domain_known', 'domain:' + domain, { name: domain, tool: 'dns' }, S, source));

    // Mint a DC candidate for every authoritative/locator host we can pin to an address.
    Object.keys(dcNames).forEach(function (dc) {
      var ip = aRec[dc];
      if (ip) _add(facts, mkFact('ad.dc_candidate', 'host:' + ip, { hostname: dc, domain: domain, via: 'dns', tool: 'dns' }, S, source));
    });

    // Zone receipt: the records a successful AXFR dumped (terminal; feeds the report / target list).
    var recs = Object.keys(aRec);
    if (recs.length >= 2) _add(facts, mkFact('dns.zone', 'host:' + ws.target, { domain: domain, records: recs.slice(0, 64).map(function (n) { return n + ' ' + aRec[n]; }) }, S, source));
  }

  C._parse_dns = _parse_dns;
})(typeof globalThis !== 'undefined' ? globalThis : this);
