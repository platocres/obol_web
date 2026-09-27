/*!
 * obol engine — parsers/nmap.js
 * Faithful JS port of obol-local/obol/parsers/nmap.py.
 * Structured-first: nmap -oX XML when a DOMParser is available (with XXE/size guards);
 * otherwise the text-regex path. A port maps to reachability, never a vuln or access.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  var _NMAPRUN_BLOCK_RE = /<nmaprun\b[\s\S]*?<\/nmaprun>/i;
  var _PORTLINE_RE = /^\s*\d+\/(?:tcp|udp)\b/i;

  function _clean_version(v) {
    v = (v || '').trim();
    return (!v || _PORTLINE_RE.test(v)) ? '' : v;
  }

  function _normalize_service(service) {
    var cleaned = service.toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '');
    var aliases = {
      'microsoft-ds': 'smb', 'netbios-ssn': 'smb', 'domain': 'dns',
      'ms-wbt-server': 'rdp', 'ssl-http': 'https',
    };
    return aliases[cleaned] || cleaned || 'unknown';
  }
  C._normalize_service = _normalize_service;

  function _looks_like_ad_ldap(text) {
    return /Active Directory|Domain Controller|Global Catalog|ldap-rootdse/i.test(text);
  }
  C._looks_like_ad_ldap = _looks_like_ad_ldap;

  function _parse_service_reachability(port, proto, service, ws, source, facts) {
    var sl = service.toLowerCase();
    var value = { port: port, protocol: proto };
    if (service) value.service = service;
    var h = 'host:' + ws.target;
    if (port === 53 || sl === 'domain' || sl === 'dns') _add(facts, mkFact('dns.reachable', h, value, S, source));
    if (port === 161 || sl.indexOf('snmp') >= 0) _add(facts, mkFact('snmp.reachable', h, value, S, source));
    if (proto !== 'tcp') return;
    if (port === 21 || sl === 'ftp') _add(facts, mkFact('ftp.reachable', h, value, S, source));
    if (port === 22 || sl === 'ssh') _add(facts, mkFact('ssh.reachable', h, value, S, source));
    if ([389, 636, 3268, 3269].indexOf(port) >= 0 || sl.indexOf('ldap') >= 0) _add(facts, mkFact('ldap.reachable', h, value, S, source));
    if ([445, 139].indexOf(port) >= 0 || sl === 'microsoft-ds' || sl === 'netbios-ssn') _add(facts, mkFact('smb.reachable', h, value, S, source));
    if (port === 88 || sl.indexOf('kerberos') >= 0) _add(facts, mkFact('kerberos.reachable', h, value, S, source));
    if (port === 3389 || sl === 'ms-wbt-server' || sl.indexOf('rdp') >= 0) {
      _add(facts, mkFact('rdp.reachable', h, value, S, source));
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'rdp'), 'medium', 'nmap', false);
    }
    if ([5985, 5986].indexOf(port) >= 0 || sl.indexOf('wsman') >= 0 || sl.indexOf('winrm') >= 0) {
      _add(facts, mkFact('winrm.reachable', h, value, S, source));
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'winrm'), 'medium', 'nmap', false);
    }
    if ([80, 443, 8080, 8000, 8443].indexOf(port) >= 0 || sl === 'http' || sl === 'https' || sl === 'ssl/http') _add(facts, mkFact('http.reachable', h, value, S, source));
  }
  C._parse_service_reachability = _parse_service_reachability;

  function _parse_nmap_script_facts(text, ws, source, facts) {
    var context = {}, h = 'host:' + ws.target;
    var domains = {};
    reAll(C._NMAP_DOMAIN_NAME_RE, text).forEach(function (m) { domains[m.groups.domain.trim().toLowerCase()] = true; });
    var fqdns = {};
    reAll(C._NMAP_FQDN_RE, text).forEach(function (m) { fqdns[m.groups.fqdn.trim().toLowerCase()] = true; });
    reAll(C._NMAP_FQDN_RE, text).forEach(function (m) {
      var parts = m.groups.fqdn.trim().toLowerCase().split('.').filter(Boolean);
      if (parts.length > 2) domains[parts.slice(1).join('.')] = true;
    });
    var domKeys = C.uniqueSortedCI(Object.keys(domains));
    var domain = domKeys.length ? domKeys[0] : '';
    if (domain) {
      context.domain = domain;
      _add(facts, mkFact('ad.domain_known', 'domain:' + domain, { name: domain }, S, source));
      _add(facts, mkFact('ad.base_dn', 'domain:' + domain, { base_dn: C._base_dn_from_domain(domain) }, S, source));
      _add(facts, mkFact('host.domain', h, { domain: domain }, S, source));
    }
    var names = {};
    reAll(C._NMAP_COMPUTER_NAME_RE, text).forEach(function (m) { names[m.groups.name.trim()] = true; });
    var nameKeys = C.uniqueSortedCI(Object.keys(names));
    if (nameKeys.length) {
      context.name = nameKeys[0];
      _add(facts, mkFact('host.hostname', h, { name: context.name }, S, source));
    }
    C.uniqueSortedCI(Object.keys(fqdns)).forEach(function (fqdn) {
      var parts = fqdn.split('.').filter(Boolean);
      var value = { fqdn: fqdn };
      if (parts.length) value.hostname = parts[0];
      if (parts.length > 1) value.domain = parts.slice(1).join('.');
      _add(facts, mkFact('host.fqdn', h, value, S, source));
    });
    var signing = reSearch(C._NMAP_SMB_SIGNING_RE, text);
    if (signing) {
      var sv = { enabled: true, tool: 'nmap' };
      if (signing.groups.required) sv.required = true;
      else if (signing[0].toLowerCase().indexOf('but not required') >= 0) sv.required = false;
      _add(facts, mkFact('smb.signing', h, sv, S, source));
    }
    var titles = [];
    reAll(C._NMAP_HTTP_TITLE_RE, text).forEach(function (m) {
      var t = m.groups.title.trim();
      if (!t) return;
      var tl = t.toLowerCase();
      if (tl.indexOf('did not follow redirect') === 0 || tl.indexOf("site doesn't have a title") === 0) return;
      titles.push(t);
    });
    if (titles.length) _add(facts, mkFact('web.title', h, { titles: C.uniqueSortedCI(titles).slice(0, 10) }, S, source));
    var headers = C.uniqueSortedCI(reAll(C._NMAP_HTTP_SERVER_RE, text).map(function (m) { return m.groups.header.trim(); }).filter(Boolean));
    if (headers.length) _add(facts, mkFact('web.server', h, { headers: headers.slice(0, 10) }, S, source));
    var generators = C.uniqueSortedCI(reAll(C._NMAP_HTTP_GENERATOR_RE, text).map(function (m) { return m.groups.generator.trim(); }).filter(Boolean));
    var tech = generators.map(function (item) { return { name: 'generator', value: item }; });
    var redirects = C.uniqueSortedCI(reAll(C._NMAP_HTTP_REDIRECT_RE, text).map(function (m) { return m.groups.location.trim(); }).filter(Boolean));
    if (redirects.length) _add(facts, mkFact('http.redirect', h, { locations: redirects.slice(0, 10) }, S, source));
    if (tech.length) _add(facts, mkFact('web.tech', h, { items: tech.slice(0, 20), tool: 'nmap' }, S, source));
    if (reSearch(C._NMAP_FTP_ANON_RE, text)) {
      _add(facts, mkFact('ftp.reachable', h, { tool: 'nmap' }, S, source));
      _add(facts, mkFact('ftp.anonymous_login', h, { tool: 'nmap' }, S, source));
    }
    if (text.toLowerCase().indexOf('ssh-hostkey') >= 0) {
      var keys = reAll(C._NMAP_SSH_HOSTKEY_RE, text).map(function (m) {
        return { bits: parseInt(m.groups.bits, 10), fingerprint: m.groups.fingerprint, type: m.groups.kind.trim() };
      });
      if (keys.length) {
        _add(facts, mkFact('ssh.reachable', h, { tool: 'nmap' }, S, source));
        _add(facts, mkFact('ssh.hostkey', h, { keys: keys.slice(0, 10), count: keys.length }, S, source));
      }
    }
    var snmpValues = {};
    if (text.toLowerCase().indexOf('snmp-info') >= 0) {
      reAll(C._NMAP_SNMP_FIELD_RE, text).forEach(function (m) { snmpValues[m.groups.key.toLowerCase()] = m.groups.value.trim(); });
    }
    if (Object.keys(snmpValues).length) {
      _add(facts, mkFact('snmp.reachable', h, { tool: 'nmap' }, S, source));
      _add(facts, mkFact('snmp.info', h, snmpValues, S, source));
      if (snmpValues.name) _add(facts, mkFact('host.hostname', h, { name: snmpValues.name }, S, source));
    }
    return context;
  }
  C._parse_nmap_script_facts = _parse_nmap_script_facts;

  function _parse_nmap_xml(text, ws, source, facts, actionId) {
    text = text || '';
    // XXE hardening: reject entity DEFINITIONS and a DOCTYPE internal subset (where entities live).
    // nmap ALWAYS emits a bare `<!DOCTYPE nmaprun>` (no subset), which is inert — allow it, or real
    // nmap XML never parses. The <nmaprun>…</nmaprun> block extracted below excludes the doctype
    // anyway, and DOMParser (application/xml) is non-validating and never fetches external DTDs.
    if (/<!ENTITY/i.test(text) || /<!DOCTYPE[^>]*\[/i.test(text)) return false;
    var block = _NMAPRUN_BLOCK_RE.exec(text);
    if (!block) return false;
    var xml = block[0];
    if (xml.length > 8000000) return false;
    if (typeof DOMParser === 'undefined') return false; // Node fixture path uses text regexes
    var doc;
    try {
      doc = new DOMParser().parseFromString(xml, 'application/xml');
      if (doc.getElementsByTagName('parsererror').length) return false;
    } catch (e) { return false; }
    var h = 'host:' + ws.target;
    // The inline coach box tags a paste with the move's OWN suggested command, which may not be what
    // the operator actually ran. nmap XML carries the real invocation in <nmaprun args="…">, so fold
    // that into the flag signal — otherwise a `-sC -sV` scan pasted onto the fast-scan move never
    // proves scan.nmap.version and the coach re-suggests a scan the operator already ran.
    var nmaprunEl = doc.querySelector('nmaprun');
    var cmdL = (source + ' ' + ((nmaprunEl && nmaprunEl.getAttribute('args')) || '')).toLowerCase();

    var host = doc.querySelector('host');
    var status = host ? host.querySelector('status') : null;
    var hostDown = status && status.getAttribute('state') === 'down';
    if (host && !hostDown) _add(facts, mkFact('host.up', h, { target: ws.target }, S, source));

    var openPorts = {};
    Array.prototype.forEach.call(doc.querySelectorAll('port'), function (portEl) {
      var st = portEl.querySelector('state');
      if (!st || st.getAttribute('state') !== 'open') return;
      var port = parseInt(portEl.getAttribute('portid'), 10);
      if (isNaN(port)) return;
      var proto = (portEl.getAttribute('protocol') || 'tcp').toLowerCase();
      var value = { port: port, protocol: proto };
      var svc = portEl.querySelector('service');
      if (svc) {
        var name = (svc.getAttribute('name') || '').trim();
        var version = _clean_version([svc.getAttribute('product'), svc.getAttribute('version'), svc.getAttribute('extrainfo')].filter(Boolean).join(' '));
        if (name) value.service = name;
        if (version) value.version = version;
      }
      openPorts[port + '/' + proto] = value;
    });
    var summary = [];
    Object.keys(openPorts).sort().forEach(function (k) {
      var value = openPorts[k];
      summary.push(value.port);
      _add(facts, mkFact('port:' + value.port, h, value, S, source));
      if (value.service) _add(facts, mkFact('service.' + _normalize_service(value.service), h, value, S, source));
      _parse_service_reachability(value.port, value.protocol, value.service || '', ws, source, facts);
    });
    if (summary.length) _add(facts, mkFact('ports.open', h, { ports: uniqSortedNums(summary) }, S, source));

    var scriptText = Array.prototype.map.call(doc.querySelectorAll('script'), function (el) { return el.getAttribute('output') || ''; }).filter(Boolean).join('\n');

    // Scan-profile markers, now that we can also read the CONTENT: a scan that returned service
    // versions or NSE script output IS a version/script scan, whatever command it was tagged with.
    var hasVersionInfo = !!scriptText.trim() || Object.keys(openPorts).some(function (k) { return openPorts[k].version; });
    // ANY nmap scan that returned open ports has done the port discovery — mark it so the coach stops
    // offering a basic port scan after a targeted -p <list> or -sV scan (which never carries -p-).
    if (summary.length || actionId.indexOf('nmap-fast') >= 0 || actionId.indexOf('all-ports') >= 0 || cmdL.indexOf('-p-') >= 0) _add(facts, mkFact('scan.nmap.quick', h, { profile: 'open-port-discovery' }, S, source));
    if (actionId.indexOf('version') >= 0 || cmdL.indexOf('-sc') >= 0 || cmdL.indexOf('-sv') >= 0 || hasVersionInfo) _add(facts, mkFact('scan.nmap.version', h, { profile: 'service-version' }, S, source));
    if (actionId.indexOf('udp') >= 0 || cmdL.indexOf(' -su') >= 0) _add(facts, mkFact('scan.nmap.udp', h, { profile: 'udp' }, S, source));

    var bannerBlob = scriptText + '\n' + Object.keys(openPorts).map(function (k) { return openPorts[k].version; }).filter(Boolean).join('\n');
    if (!facts.some(function (f) { return f.kind === 'host.os_family'; })) C._add_os_from_text(bannerBlob, ws, source, facts, 'nmap', 'high', true);
    var scriptContext = scriptText.trim() ? _parse_nmap_script_facts(scriptText, ws, source, facts) : {};
    var tcpPorts = Object.keys(openPorts).map(function (k) { return openPorts[k]; }).filter(function (v) { return v.protocol === 'tcp'; }).map(function (v) { return v.port; });
    if ([88, 389, 445].every(function (p) { return tcpPorts.indexOf(p) >= 0; }) || _looks_like_ad_ldap(scriptText)) {
      var value = { ports: [88, 389, 445].filter(function (p) { return tcpPorts.indexOf(p) >= 0; }) };
      Object.keys(scriptContext).forEach(function (k) { value[k] = scriptContext[k]; });
      _add(facts, mkFact('ad.dc_candidate', h, value, S, source));
    }
    return true;
  }
  C._parse_nmap_xml = _parse_nmap_xml;

  function uniqSortedNums(arr) {
    var s = {};
    arr.forEach(function (n) { s[n] = true; });
    return Object.keys(s).map(Number).sort(function (a, b) { return a - b; });
  }

  function _parse_nmap(text, ws, source, facts, actionId) {
    if (_parse_nmap_xml(text, ws, source, facts, actionId)) return;
    var h = 'host:' + ws.target, srcL = source.toLowerCase();
    var openPorts = {};
    C._add_os_from_text(text, ws, source, facts, 'nmap', 'high', true);

    reAll(C._NMAP_DISCOVERED_RE, text).forEach(function (m) {
      var port = parseInt(m.groups.port, 10), proto = m.groups.proto.toLowerCase();
      openPorts[port + '/' + proto] = { port: port, protocol: proto };
    });
    reAll(C._NMAP_OPEN_RE, text).forEach(function (m) {
      var portText = m.groups.port, line = m[0];
      var proto = line.toLowerCase().indexOf(portText + '/udp') >= 0 ? 'udp' : 'tcp';
      var port = parseInt(portText, 10);
      var service = (m.groups.service || '').trim();
      var version = _clean_version(m.groups.version);
      var value = { port: port, protocol: proto };
      if (service) value.service = service;
      if (version) value.version = version;
      openPorts[port + '/' + proto] = value;
    });

    if (/Host is up|Nmap scan report for/i.test(text)) {
      var value = { target: ws.target };
      var latency = /Host is up \(([^)]+)\)/i.exec(text);
      if (latency) value.latency = latency[1];
      _add(facts, mkFact('host.up', h, value, S, source));
    }
    var scanSeen = Object.keys(openPorts).length > 0 || /Host is up|Nmap done|Nmap scan report for/i.test(text);
    // Read the real flags where nmap prints them (the `-oN` header's "as:" line), and infer the
    // profile from CONTENT: service/version columns or NSE script output (`| line`) mean a version/
    // script scan ran, whatever command the paste was tagged with — so one paste advances the coach.
    var asCmd = (/^#\s*Nmap\b.*?\bas:\s*(.+)$/im.exec(text) || [])[1] || '';
    var cmdL = (source + ' ' + asCmd).toLowerCase();
    var hasVersionInfo = Object.keys(openPorts).some(function (k) { return openPorts[k].version; }) || /^\|[_ ]/m.test(text);
    // any scan that found open ports IS port discovery (see XML path) — so a targeted -p/-sV paste
    // still retires the basic-port-scan move instead of leaving it in "ready now".
    if (scanSeen && (Object.keys(openPorts).length > 0 || actionId.indexOf('nmap-fast') >= 0 || actionId.indexOf('all-ports') >= 0 || cmdL.indexOf('-p-') >= 0)) _add(facts, mkFact('scan.nmap.quick', h, { profile: 'open-port-discovery' }, S, source));
    if (scanSeen && (actionId.indexOf('version') >= 0 || cmdL.indexOf('-sc') >= 0 || cmdL.indexOf('-sv') >= 0 || hasVersionInfo)) _add(facts, mkFact('scan.nmap.version', h, { profile: 'service-version' }, S, source));
    if (scanSeen && (actionId.indexOf('udp') >= 0 || cmdL.indexOf(' -su') >= 0)) _add(facts, mkFact('scan.nmap.udp', h, { profile: 'udp' }, S, source));
    if (scanSeen && (actionId.indexOf('vuln') >= 0 || srcL.indexOf('--script vuln') >= 0 || srcL.indexOf('-script vuln') >= 0)) _add(facts, mkFact('scan.nmap.vuln', h, { profile: 'nse-vuln' }, S, source));

    var summary = [];
    Object.keys(openPorts).sort().forEach(function (k) {
      var value = openPorts[k];
      summary.push(value.port);
      _add(facts, mkFact('port:' + value.port, h, value, S, source));
      if (value.service) _add(facts, mkFact('service.' + _normalize_service(value.service), h, value, S, source));
      _parse_service_reachability(value.port, value.protocol, value.service || '', ws, source, facts);
    });
    if (summary.length) _add(facts, mkFact('ports.open', h, { ports: uniqSortedNums(summary) }, S, source));

    var scriptContext = _parse_nmap_script_facts(text, ws, source, facts);
    var tcpPorts = Object.keys(openPorts).map(function (k) { return openPorts[k]; }).filter(function (v) { return v.protocol === 'tcp'; }).map(function (v) { return v.port; });
    if ([88, 389, 445].every(function (p) { return tcpPorts.indexOf(p) >= 0; }) || _looks_like_ad_ldap(text)) {
      var value = { ports: [88, 389, 445].filter(function (p) { return tcpPorts.indexOf(p) >= 0; }) };
      Object.keys(scriptContext).forEach(function (k) { value[k] = scriptContext[k]; });
      _add(facts, mkFact('ad.dc_candidate', h, value, S, source));
    }
  }
  C._parse_nmap = _parse_nmap;

})(typeof globalThis !== 'undefined' ? globalThis : this);
