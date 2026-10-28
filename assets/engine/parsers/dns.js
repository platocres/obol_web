/*!
 * obol engine - parsers/dns.js - internal-resolver interrogation.
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

  function _parse_dns(text, ws, source, facts, command) {
    var t = String(text || ''); if (!t) return;
    var msDnsM = /Microsoft\s+DNS\s+([0-9.]+(?:\s*\([0-9A-Fa-f]+\))?)/i.exec(t);
    if (msDnsM) {
      var msVer = 'Microsoft DNS ' + msDnsM[1].trim();
      _add(facts, mkFact('dns.reachable', 'host:' + ws.target, { port: 53, version: msVer, tool: 'dig' }, S, source));
      _add(facts, mkFact('service.dns', 'host:' + ws.target, { port: 53, protocol: 'tcp', service: 'dns', version: msVer }, S, source));
      if (C._add_os_observation) C._add_os_observation(facts, ws, source, 'windows', msVer, 'high', 'dns', true);
    }
    // nothing to read: an error / empty answer alone mints no fact
    if (/\b(NXDOMAIN|SERVFAIL|REFUSED|connection timed out|Transfer failed|communications error)\b/i.test(t) && !/\bIN\s+(?:A|SRV|SOA|NS)\b/i.test(t) && !/service\s*=/.test(t)) return;

    var aRec = {};      // fqdn -> ip  (from A records across dig / nslookup / host / AXFR)
    var names = {};      // every fqdn seen (for the zone receipt)
    var domain = '', dcNames = {}, m;

    // A records - dig/AXFR row "name. TTL IN A 1.2.3.4", host "name has address 1.2.3.4",
    // nslookup "Name: name \n Address: 1.2.3.4"
    var reA = /(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,253}?)\.?\s+(?:\d+\s+)?IN\s+A\s+(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reA.exec(t))) { var nm = norm(m[1]); if (isRoutable(m[2])) { aRec[nm] = m[2]; names[nm] = 1; } }
    var reHost = /(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,253}?)\s+has address\s+(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reHost.exec(t))) { var nh = norm(m[1]); if (isRoutable(m[2])) { aRec[nh] = m[2]; names[nh] = 1; } }
    // Windows nslookup prints an A record as "host  internet address = 1.2.3.4"
    var reNslA = /(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,253}?)\s+internet address\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})/gi;
    while ((m = reNslA.exec(t))) { var na = norm(m[1]); if (isRoutable(m[2])) { aRec[na] = m[2]; names[na] = 1; } }
    // Standard nslookup block "Name:\tdc01.corp.local\nAddress: 10.10.10.10"
    var reNslBlock = /^Name:\s*([A-Za-z0-9_.-]{1,253})\s*\r?\nAddress(?:es)?:\s*(\d{1,3}(?:\.\d{1,3}){3})/gim;
    while ((m = reNslBlock.exec(t))) { var nb = norm(m[1]); if (isRoutable(m[2])) { aRec[nb] = m[2]; names[nb] = 1; } }

    // dig +short <hostname> prints only the resolved IPv4 on its own line; correlate the queried
    // hostname from the command (or echoed prompt line) with the bare routable IPv4 in the output.
    var cmdHint = String(command || source || '');
    if (!/\bdig\b/i.test(cmdHint)) {
      var digEcho = t.match(/^[^\r\n$#%>]*[$#%>]\s*(dig\b[^\r\n]*)/im) || t.match(/^\s*(dig\b[^\r\n]*)/im);
      if (digEcho) cmdHint = digEcho[1];
    }
    if (Object.keys(aRec).length === 0 && /\bdig\b/i.test(cmdHint) && /\+short\b/i.test(cmdHint)) {
      var qHost = '', qPtrIp = '';
      var cToks = cmdHint.replace(/^[\s\S]*?\bdig\b/i, '').trim().split(/\s+/);
      for (var ti = 0; ti < cToks.length; ti++) {
        var tok = cToks[ti].replace(/^['"]|['"]$/g, '');
        if (!tok || tok.charAt(0) === '@' || tok.charAt(0) === '+') continue;
        if (tok === '-x' && ti + 1 < cToks.length) { qPtrIp = cToks[++ti].replace(/^['"]|['"]$/g, ''); continue; }
        if (tok.charAt(0) === '-') { if (/^-[ptkbyc]$/i.test(tok)) ti++; continue; }
        if (/^(?:A|AAAA|ANY|AXFR|IXFR|CNAME|MX|NS|PTR|SOA|SRV|TXT|CAA|DNSKEY|DS|NAPTR|SPF|HINFO|IN|CH|HS)$/i.test(tok)) continue;
        if (/^(?![0-9.]+$)[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+\.?$/.test(tok)) { qHost = norm(tok); break; }
      }
      var outLines = t.split(/\r?\n/);
      for (var li = 0; li < outLines.length; li++) {
        var ln = outLines[li].trim();
        if (!ln || /\bdig\b/i.test(ln) || ln.charAt(0) === ';') continue;
        if (qHost && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ln) && isRoutable(ln)) {
          aRec[qHost] = ln; names[qHost] = 1; break;
        }
        if (qPtrIp && isRoutable(qPtrIp) && /^(?![0-9.]+$)[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+\.?$/.test(ln)) {
          var ptrName = norm(ln);
          aRec[ptrName] = qPtrIp; names[ptrName] = 1; break;
        }
      }
    }

    // SOA / NS - the authoritative host is a DC, and the owner name is the domain
    var reSoa = /(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,253}?)\.?\s+(?:\d+\s+)?IN\s+SOA\s+([A-Za-z0-9_.-]+)/i;
    m = reSoa.exec(t); if (m) { domain = domain || norm(m[1]); dcNames[norm(m[2])] = 1; }
    var reNs = /(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,253}?)\.?\s+(?:\d+\s+)?IN\s+NS\s+([A-Za-z0-9_.-]+)/gi;
    while ((m = reNs.exec(t))) { domain = domain || norm(m[1]); dcNames[norm(m[2])] = 1; }

    // SRV - the DC locators. dig row "_ldap._tcp.dc._msdcs.acme.local. IN SRV 0 100 389 dc01.acme.local."
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

    Object.keys(names).forEach(function (n) {
      if (/^dc\d*\.[a-z0-9.-]+\.[a-z]{2,}$/i.test(n) && aRec[n]) {
        dcNames[n] = 1;
        if (!domain) domain = n.split('.').slice(1).join('.');
      }
    });

    if (domain) _add(facts, mkFact('ad.domain_known', 'domain:' + domain, { name: domain, tool: 'dns' }, S, source));

    // Mint a DC candidate for every authoritative/locator host we can pin to an address.
    Object.keys(dcNames).forEach(function (dc) {
      var ip = aRec[dc];
      if (ip) _add(facts, mkFact('ad.dc_candidate', 'host:' + ip, { hostname: dc, domain: domain, via: 'dns', tool: 'dns' }, S, source));
    });

    // Zone receipt: the records a successful AXFR dumped (terminal; feeds the report / target list).
    var recs = Object.keys(aRec);
    if (recs.length >= 2) {
      _add(facts, mkFact('dns.zone', 'host:' + ws.target, { domain: domain, records: recs.slice(0, 64).map(function (n) { return n + ' ' + aRec[n]; }) }, S, source));
    } else {
      // A plain forward lookup (dig/host/nslookup resolving one name to an address) is not a zone transfer,
      // but the name->IP mapping is a real recon receipt: it confirms the host at that IP and the name to
      // put in /etc/hosts. Mint it only when the zone receipt did not fire and the name is not already a DC
      // candidate (ad.dc_candidate already carries that mapping). Terminal; feeds the report / target list.
      recs.forEach(function (n) {
        if (dcNames[n]) return;
        _add(facts, mkFact('dns.a_record', 'host:' + aRec[n], { name: n, ip: aRec[n], tool: 'dns' }, S, source));
      });
    }
  }

  C._parse_dns = _parse_dns;
  C._parse_dns_zone = _parse_dns;
})(typeof globalThis !== 'undefined' ? globalThis : this);
