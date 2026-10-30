/*!
 * obol engine - parsers/nmap.js
 * Faithful JS port of
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

  function _has_positive_ms17_010(text) {
    var re = /(?:smb-vuln-ms17-010|ms17-?010|CVE-2017-0144)[\s\S]{0,350}/gi, m;
    while ((m = re.exec(text)) !== null) {
      var chunk = m[0];
      var nextScript = /\n\|[_ ]\s*[a-z0-9]+-[a-z0-9-]+:/i.exec(chunk.slice(15));
      if (nextScript) chunk = chunk.slice(0, 15 + nextScript.index);
      if (/\bNOT\s+VULNERABLE\b|:\s*false\b|ERROR:/i.test(chunk)) continue;
      if (/\bVULNERABLE\b/i.test(chunk)) return true;
    }
    return false;
  }

  function _parse_service_reachability(port, proto, service, ws, source, facts) {
    var sl = service.toLowerCase();
    var value = { port: port, protocol: proto };
    if (service) value.service = service;
    var h = 'host:' + ws.target;
    if (port === 53 || sl === 'domain' || sl === 'dns') _add(facts, mkFact('dns.reachable', h, value, S, source));
    if (port === 161 || sl.indexOf('snmp') >= 0) _add(facts, mkFact('snmp.reachable', h, value, S, source));
    if (port === 69 || sl === 'tftp') _add(facts, mkFact('tftp.reachable', h, value, S, source));
    if (proto !== 'tcp') return;
    var hasLinuxOs = facts.some(function (f) { return (f.kind === 'host.os_family' || f.kind === 'host.os_hint') && f.value && f.value.family === 'linux'; });
    var promoteWin = !hasLinuxOs;
    if (port === 21 || sl === 'ftp') _add(facts, mkFact('ftp.reachable', h, value, S, source));
    if (port === 22 || sl === 'ssh') _add(facts, mkFact('ssh.reachable', h, value, S, source));
    if (port === 23 || sl === 'telnet') _add(facts, mkFact('telnet.reachable', h, value, S, source));
    if ([512, 513, 514].indexOf(port) >= 0 || sl === 'exec' || sl === 'login' || sl === 'shell') _add(facts, mkFact('rservices.reachable', h, value, S, source));
    if (port >= 6000 && port <= 6009 && (sl.indexOf('x11') >= 0 || port === 6000)) _add(facts, mkFact('x11.reachable', h, value, S, source));
    if ([25, 465, 587].indexOf(port) >= 0 || sl.indexOf('smtp') >= 0) {
      _add(facts, mkFact('smtp.reachable', h, value, S, source));
      _add(facts, mkFact('mail.reachable', h, value, S, source));
    }
    if ([110, 143, 993, 995].indexOf(port) >= 0 || sl.indexOf('pop3') >= 0 || sl.indexOf('imap') >= 0) {
      _add(facts, mkFact('mail.reachable', h, value, S, source));
    }
    if ([5900, 5901, 5902].indexOf(port) >= 0 || sl.indexOf('vnc') >= 0) {
      _add(facts, mkFact('vnc.reachable', h, value, S, source));
    }
    if (port === 873 || sl.indexOf('rsync') >= 0) _add(facts, mkFact('rsync.reachable', h, value, S, source));
    if (port === 2049 || sl.indexOf('nfs') >= 0) _add(facts, mkFact('nfs.reachable', h, value, S, source));
    if ([389, 636, 3268, 3269].indexOf(port) >= 0 || sl.indexOf('ldap') >= 0) _add(facts, mkFact('ldap.reachable', h, value, S, source));
    if ([445, 139].indexOf(port) >= 0 || sl === 'microsoft-ds' || sl === 'netbios-ssn') _add(facts, mkFact('smb.reachable', h, value, S, source));
    if (port === 88 || sl.indexOf('kerberos') >= 0) {
      _add(facts, mkFact('kerberos.reachable', h, value, S, source));
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'kerberos'), 'medium', 'nmap', promoteWin);
    }
    if (port === 135 || sl === 'msrpc') {
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'msrpc'), 'medium', 'nmap', promoteWin);
    }
    if (port === 3268 || port === 3269 || sl.indexOf('globalcat') >= 0) {
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'globalcat'), 'medium', 'nmap', promoteWin);
    }
    if (port === 1433 || sl === 'ms-sql-s' || sl.indexOf('mssql') >= 0) {
      _add(facts, mkFact('mssql.reachable', h, value, S, source));
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'ms-sql-s'), 'medium', 'nmap', promoteWin);
    }
    if (port === 3389 || sl === 'ms-wbt-server' || sl.indexOf('rdp') >= 0) {
      _add(facts, mkFact('rdp.reachable', h, value, S, source));
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'rdp'), 'medium', 'nmap', promoteWin);
    }
    var isHttpApiPort = port === 47001;
    var isWinrmPort = !isHttpApiPort && ([5985, 5986].indexOf(port) >= 0 || sl.indexOf('wsman') >= 0 || sl.indexOf('winrm') >= 0);
    if (isHttpApiPort) {
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'httpapi'), 'medium', 'nmap', promoteWin);
    }
    if (isWinrmPort) {
      _add(facts, mkFact('winrm.reachable', h, value, S, source));
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'winrm'), 'medium', 'nmap', promoteWin);
    }
    // WS-Management / HTTPAPI on 5985/5986/47001 is WinRM/HTTP.sys, not a browsable web app, so it must not
    // mint http.reachable (nmap labels it "http") or it would unlock the web-exploit moves on an AD box.
    if (!isWinrmPort && !isHttpApiPort && ([80, 443, 8080, 8000, 8443].indexOf(port) >= 0 || sl === 'http' || sl === 'https' || sl === 'ssl/http')) _add(facts, mkFact('http.reachable', h, value, S, source));
  }
  C._parse_service_reachability = _parse_service_reachability;

  function _parse_nmap_script_facts(text, ws, source, facts, extraHeaders) {
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
      var mode = (signing.groups && signing.groups.mode || '').toLowerCase();
      var sv = { enabled: true, tool: 'nmap' };
      if (mode === 'disabled') {
        sv.enabled = false;
        sv.required = false;
      } else if (mode === 'required' || (signing.groups && signing.groups.required)) {
        sv.required = true;
      } else if (mode === 'supported' || signing[0].toLowerCase().indexOf('but not required') >= 0) {
        sv.required = false;
      }
      _add(facts, mkFact('smb.signing', h, sv, S, source));
    }
    if (_has_positive_ms17_010(text)) {
      _add(facts, mkFact('smb.ms17_010', h, { cve: 'CVE-2017-0144', via: 'nmap-nse' }, S, source));
    }
    if (/\bSMBv1\b[^\r\n]{0,120}?\b(?:enabled|true|dangerous)\b|\bNT LM 0\.12\s*\(SMBv1\)/i.test(text)) {
      _add(facts, mkFact('smb.smbv1', h, { enabled: true, tool: 'nmap' }, S, source));
    }
    if (/smb-enum-shares:/i.test(text)) {
      var nseShares = [];
      reAll(/\\\\[^\s\\]+\\([A-Za-z0-9_$.-]+)\s*:/g, text).forEach(function (m) { nseShares.push(m[1]); });
      if (nseShares.length) {
        _add(facts, mkFact('smb.shares', h, { shares: C.uniqueSortedCI(nseShares), tool: 'nmap' }, S, source));
      }
    }
    if (/x11-access:[\s\S]{0,120}?X server access is granted/i.test(text)) {
      _add(facts, mkFact('x11.unauth', h, { port: 6000, tool: 'nmap' }, S, source));
    }
    if (/mongodb-databases:/i.test(text) && !/errmsg|unauthorized|Authentication failed/i.test(text)) {
      _add(facts, mkFact('mongo.unauth', h, { port: 27017, tool: 'nmap' }, S, source));
      var mDbs = [];
      reAll(/^\|\s+name\s*=\s*([A-Za-z0-9_.-]+)/gim, text).forEach(function (m) { mDbs.push(m[1]); });
      if (mDbs.length) _add(facts, mkFact('db.tables', h, { databases: C.uniqueSortedCI(mDbs), engine: 'mongodb' }, S, source));
    }
    if (/oracle-sid-brute:/i.test(text)) {
      var oBlk = (/oracle-sid-brute:([\s\S]*?)(?:\n\d+\/|\nNmap done|$)/i.exec(text) || [])[1] || '';
      var oSids = [];
      reAll(/^\|\s*_?([A-Za-z0-9_]{2,20})\s*$/gim, oBlk).forEach(function (m) { oSids.push(m[1]); });
      if (oSids.length) _add(facts, mkFact('oracle.sid', h, { sid: oSids[0], sids: C.uniqueSortedCI(oSids) }, S, source));
    }
    if (/memcached-info:[\s\S]{0,250}?(?:Process ID|Uptime)/i.test(text)) {
      _add(facts, mkFact('memcached.open', h, { port: 11211, tool: 'nmap' }, S, source));
    }
    if (/smtp-enum-users:/i.test(text)) {
      var sBlk = (/smtp-enum-users:([\s\S]*?)(?:\n\d+\/|\nNmap done|$)/i.exec(text) || [])[1] || '';
      var sUsers = [];
      reAll(/^\|\s*_?([A-Za-z0-9._-]+)(?:\s|$)/gim, sBlk).forEach(function (m) {
        if (!/^(?:Method|Couldn't|Commands)/i.test(m[1])) sUsers.push(m[1]);
      });
      if (sUsers.length) _add(facts, mkFact('smtp.users', h, { users: C.uniqueSortedCI(sUsers) }, S, source));
    }
    if (/smtp-open-relay:[\s\S]{0,160}?Server is an open relay/i.test(text)) {
      _add(facts, mkFact('smtp.open_relay', h, { open_relay: true, tool: 'nmap' }, S, source));
    }
    if (/tftp-enum:/i.test(text)) {
      var tBlk = (/tftp-enum:([\s\S]*?)(?:\n\d+\/|\nNmap done|$)/i.exec(text) || [])[1] || '';
      var tFiles = [];
      reAll(/^\|\s*_?([^\s|][^\r\n]*)$/gim, tBlk).forEach(function (m) { tFiles.push(m[1].trim()); });
      if (tFiles.length) _add(facts, mkFact('loot.files', h, { files: tFiles, tool: 'nmap-tftp' }, S, source));
    }
    var hasHttpReachable = facts.some(function (f) { return f && f.kind === 'http.reachable'; });
    var titles = [];
    reAll(C._NMAP_HTTP_TITLE_RE, text).forEach(function (m) {
      var t = m.groups.title.trim();
      if (!t) return;
      var tl = t.toLowerCase();
      if (tl.indexOf('did not follow redirect') === 0 || tl.indexOf("site doesn't have a title") === 0) return;
      if (!hasHttpReachable && /^(?:not found|404 not found|bad request|400 bad request|service unavailable|503 service unavailable)$/i.test(tl)) return;
      titles.push(t);
    });
    if (titles.length) _add(facts, mkFact('web.title', h, { titles: C.uniqueSortedCI(titles).slice(0, 10) }, S, source));
    var rawHeaders = reAll(C._NMAP_HTTP_SERVER_RE, text).map(function (m) { return m.groups.header.trim(); });
    if (Array.isArray(extraHeaders) && extraHeaders.length) rawHeaders = rawHeaders.concat(extraHeaders);
    var headers = C.uniqueSortedCI(rawHeaders
      .filter(Boolean).filter(function (hdr) { return !C._isNonWebServerHeader(hdr); }));
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

  function xmlAttr(attrs, name) {
    var m = new RegExp('(?:^|\\s)' + name + '\\s*=\\s*(["\'])([\\s\\S]*?)\\1', 'i').exec(attrs || '');
    return m ? m[2].replace(/&#(x[0-9a-f]+|[0-9]+);/gi, function (_, n) {
      var point = n[0].toLowerCase() === 'x' ? parseInt(n.slice(1), 16) : parseInt(n, 10);
      return point <= 0x10ffff ? String.fromCodePoint(point) : '';
    }).replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&') : '';
  }

  function _parse_nmap_xml(text, ws, source, facts, actionId, command) {
    if (!/<nmaprun\b/i.test(text || '')) return false;
    // Never fall back to text parsing of rejected XML or expand an external entity.
    if (/<!ENTITY/i.test(text) || /<!DOCTYPE[^>]*\[/i.test(text) || text.length > 8000000) return true;
    var block = _NMAPRUN_BLOCK_RE.exec(text);
    var startIdx = block ? -1 : text.search(/<nmaprun\b/i);
    var xml = block ? block[0] : (startIdx >= 0 ? text.slice(startIdx) : '');
    if (!xml) return true;
    var runAttrs = (/<nmaprun\b([^>]*)>/i.exec(xml) || [])[1];
    var hosts = xml.match(/<host\b[^>]*>[\s\S]*?(?:<\/host>|$)/gi) || [];
    hosts.forEach(function (host) {
      var status = /<status\b([^>]*)>/i.exec(host);
      if (status && xmlAttr(status[1], 'state') === 'down') return;
      var addresses = host.match(/<address\b[^>]*>/gi) || [], address = '';
      ['ipv4', 'ipv6'].some(function (type) {
        return addresses.some(function (el) {
          if (xmlAttr(el, 'addrtype') !== type) return false;
          address = xmlAttr(el, 'addr'); return !!address;
        });
      });
      if (!address && hosts.length === 1) address = ws.target;
      if (!address) return;
      var hostWs = Object.assign({}, ws, { target: ws.context && ws.context.forceTarget ? ws.target : address });
      var scriptLines = (host.match(/<script\b[^>]*>/gi) || []).map(function (el) { return xmlAttr(el, 'output'); }).join('\n');
      _parse_nmap_single('<nmaprun>\n' + host + '\n' + scriptLines, hostWs, source, facts, actionId || '', (command || '') + ' ' + xmlAttr(runAttrs, 'args'));
    });
    return true;
  }
  C._parse_nmap_xml = _parse_nmap_xml;

  function uniqSortedNums(arr) {
    var s = {};
    arr.forEach(function (n) { s[n] = true; });
    return Object.keys(s).map(Number).sort(function (a, b) { return a - b; });
  }

  function _nmap_flags(rawCmd) {
    var toks = String(rawCmd || '').trim().split(/\s+/).filter(Boolean);
    var out = { version: false, script: false, udp: false, allPorts: false };
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t === '-oN' || t === '-oX' || t === '-oG' || t === '-oA' || t === '-iL' || t === '-S' || t === '-e' || t === '-D' || t === '--datadir' || t === '--stylesheet') { i++; continue; }
      if (t.indexOf('--') === 0) {
        var tl = t.toLowerCase();
        if (tl === '--version-all' || tl === '--version-light' || tl.indexOf('--version-intensity') === 0) out.version = true;
        if (tl.indexOf('--script') === 0) out.script = true;
        continue;
      }
      if (t.charAt(0) !== '-' || t.length < 2) continue;
      if (t === '-p-') { out.allPorts = true; continue; }
      if (/^-[pPitTdDSebMo]/.test(t)) continue;
      if (t === '-A' || /^-[vn0-9]*A[vn0-9]*$/.test(t)) { out.version = true; out.script = true; }
      if (/^-s[A-Za-z]*V/.test(t)) out.version = true;
      if (/^-s[A-Za-z]*C/.test(t)) out.script = true;
      if (/^-s[A-Za-z]*U/.test(t)) out.udp = true;
    }
    return out;
  }

  function _unescape_nmap_fp(s) {
    return String(s || '').replace(/\\x20/gi, ' ').replace(/\\r/g, '\r').replace(/\\n/g, '\n').replace(/\\t/g, '\t');
  }

  function _parse_nmap_single(text, ws, source, facts, actionId, command) {
    var h = 'host:' + ws.target, srcL = (source + ' ' + (command || '')).toLowerCase();
    var openPorts = {}, portBlocks = {};
    var snmpOs = /^\s*[|_ ]*description:\s*(Linux\b[^\r\n]*)/im.exec(text);
    if (snmpOs) C._add_os_observation(facts, ws, source, 'linux', snmpOs[1], 'high', 'nmap-snmp', true);
    var osText = text.replace(/^\s*\d+\/(?:tcp|udp)\s+(?:closed|filtered|unfiltered|open\|filtered)\b[^\r\n]*$/gim, '');
    C._add_os_from_text(osText, ws, source, facts, 'nmap', 'high', true);

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
    var curPortKey = '';
    text.split(/\r?\n/).forEach(function (ln) {
      var pm = C._NMAP_OPEN_RE.exec(ln);
      if (pm && pm.groups) {
        var pNum = parseInt(pm.groups.port, 10);
        var pProto = ln.toLowerCase().indexOf(pm.groups.port + '/udp') >= 0 ? 'udp' : 'tcp';
        curPortKey = pNum + '/' + pProto;
        return;
      }
      if (curPortKey && /^\s*\|/.test(ln)) {
        portBlocks[curPortKey] = (portBlocks[curPortKey] ? portBlocks[curPortKey] + '\n' : '') + ln;
      } else if (!/^\s*$/.test(ln)) {
        curPortKey = '';
      }
    });
    var sfRe = /SF-Port(\d{1,5})-TCP:([^\r\n]+(?:\r?\nSF:[^\r\n]+)*)/gi, sfm;
    while ((sfm = sfRe.exec(text)) !== null) {
      var sfKey = parseInt(sfm[1], 10) + '/tcp';
      var sfDecoded = _unescape_nmap_fp(sfm[2].replace(/\r?\nSF:/g, ''));
      portBlocks[sfKey] = (portBlocks[sfKey] ? portBlocks[sfKey] + '\n' : '') + sfDecoded;
    }
    var gnmapRe = /\b(\d{1,5})\/open\/(tcp|udp)\/[^\/,\r\n]*\/([^\/,\s\r\n]*)\/[^\/,\r\n]*\/([^\/,\r\n]*)/gi, gm;
    while ((gm = gnmapRe.exec(text)) !== null) {
      var gPort = parseInt(gm[1], 10), gProto = gm[2].toLowerCase();
      var gSvc = (gm[3] || '').trim(), gVer = _clean_version(gm[4] || '');
      var gVal = { port: gPort, protocol: gProto };
      if (gSvc) gVal.service = gSvc;
      if (gVer) gVal.version = gVer;
      openPorts[gPort + '/' + gProto] = gVal;
    }
    var rustRe = /^\s*Open\s+(?:\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?):(\d{1,5})\s*$/gim, rm;
    while ((rm = rustRe.exec(text)) !== null) {
      var rPort = parseInt(rm[1], 10);
      if (rPort > 0 && rPort <= 65535 && !openPorts[rPort + '/tcp']) {
        openPorts[rPort + '/tcp'] = { port: rPort, protocol: 'tcp' };
      }
    }
    if (text.indexOf('<nmaprun') >= 0) {
      var xmlPortRe = /<port\b([^>]*)>([\s\S]*?)(?:<\/port>|(?=<port\b|<\/ports>|<\/host>|$))/gi, xpm;
      while ((xpm = xmlPortRe.exec(text)) !== null) {
        var xProto = xmlAttr(xpm[1], 'protocol').toLowerCase(), xPort = parseInt(xmlAttr(xpm[1], 'portid'), 10), xBody = xpm[2];
        if (!/^(tcp|udp)$/.test(xProto) || !xPort || xPort > 65535 || !/<state\s+[^>]*?\bstate=["']open["']/i.test(xBody)) continue;
        var xVal = { port: xPort, protocol: xProto };
        var xSvcM = /<service\b([^>]*?)>/i.exec(xBody);
        if (xSvcM) {
          var xAttrs = xSvcM[1], xName = xmlAttr(xAttrs, 'name');
          var xFullVer = _clean_version(['product', 'version', 'extrainfo'].map(function (key) { return xmlAttr(xAttrs, key); }).filter(Boolean).join(' '));
          if (xName) xVal.service = xName;
          if (xFullVer) xVal.version = xFullVer;
          var xFp = xmlAttr(xAttrs, 'servicefp');
          if (xFp) {
            var xKeyFp = xPort + '/' + xProto;
            portBlocks[xKeyFp] = (portBlocks[xKeyFp] ? portBlocks[xKeyFp] + '\n' : '') + _unescape_nmap_fp(xFp);
          }
        }
        var xScripts = (xBody.match(/<script\b[^>]*>/gi) || []).map(function (el) { return xmlAttr(el, 'output'); }).filter(Boolean);
        if (xScripts.length) {
          var xKeySc = xPort + '/' + xProto;
          portBlocks[xKeySc] = (portBlocks[xKeySc] ? portBlocks[xKeySc] + '\n' : '') + xScripts.join('\n');
        }
        openPorts[xPort + '/' + xProto] = xVal;
      }
      var xmlOsLines = [];
      var xOsRe = /<osmatch\s+[^>]*?\bname=["']([^"']+)["']/gi, xom;
      while ((xom = xOsRe.exec(text)) !== null) xmlOsLines.push('OS details: ' + xom[1]);
      var xVerLines = Object.keys(openPorts).map(function (k) { return openPorts[k].version; }).filter(Boolean);
      if (xmlOsLines.length || xVerLines.length) {
        C._add_os_from_text(xmlOsLines.concat(xVerLines).join('\n'), ws, source, facts, 'nmap', 'high', true);
      }
    }

    if (Object.keys(openPorts).length || /Host is up|Status:\s*Up\b|<status\s+[^>]*?\bstate=["']up["']/i.test(text)) {
      var value = { target: ws.target };
      var latency = /Host is up \(([^)]+)\)/i.exec(text);
      if (latency) value.latency = latency[1];
      _add(facts, mkFact('host.up', h, value, S, source));
    }
    var scanSeen = (Object.keys(openPorts).length > 0 || /Host is up|Nmap done|Nmap scan report for|Status:\s*Up\b|<nmaprun\b/i.test(text)) && !/\b0 hosts up\b|\bHost seems down\b/i.test(text);
    // Read the real flags where nmap prints them (the `-oN` header's "as:" line), and infer the
    // profile from CONTENT: service/version columns or NSE script output (`| line`) mean a version/
    // script scan ran, whatever command the paste was tagged with - so one paste advances the coach.
    var asCmd = (/^#\s*Nmap\b[^\r\n]{0,200}?\bas:\s*(.+)$/im.exec(text) || [])[1] || '';
    var rawCmdAll = (command || '') + ' ' + asCmd + ' ' + (source || '');
    var cmdL = (srcL + ' ' + asCmd).toLowerCase();
    var nFlags = _nmap_flags(rawCmdAll);
    var hasVersionInfo = Object.keys(openPorts).some(function (k) { return openPorts[k].version; }) || /^[ \t]*\|[_ ]/m.test(text);
    var hasUdpOpen = Object.keys(openPorts).some(function (k) { return openPorts[k].protocol === 'udp'; });
    var hasVulnScript = /--script[=\s]+[^\r\n]*vuln/i.test(cmdL) || /\bVULNERABLE:\b|\|\s*_?(?:http|smb|ssl|ftp|rdp|rmi)-vuln-[a-z0-9-]+:/i.test(text);
    // any scan that found open ports IS port discovery (see XML path) - so a targeted -p/-sV paste
    // still retires the basic-port-scan move instead of leaving it in "ready now".
    if (Object.keys(openPorts).length > 0 || (scanSeen && (actionId.indexOf('nmap-fast') >= 0 || actionId.indexOf('all-ports') >= 0 || nFlags.allPorts || cmdL.indexOf('-p-') >= 0))) _add(facts, mkFact('scan.nmap.quick', h, { profile: 'open-port-discovery' }, S, source));
    if (scanSeen && (actionId.indexOf('version') >= 0 || nFlags.version || nFlags.script || cmdL.indexOf('-sc') >= 0 || cmdL.indexOf('-sv') >= 0 || hasVersionInfo)) _add(facts, mkFact('scan.nmap.version', h, { profile: 'service-version' }, S, source));
    if (scanSeen && (actionId.indexOf('udp') >= 0 || nFlags.udp || cmdL.indexOf('-su') >= 0 || hasUdpOpen)) _add(facts, mkFact('scan.nmap.udp', h, { profile: 'udp' }, S, source));
    if (scanSeen && (actionId.indexOf('vuln') >= 0 || hasVulnScript)) _add(facts, mkFact('scan.nmap.vuln', h, { profile: 'nse-vuln' }, S, source));
    // specific CVE verdict: smb-vuln-ms17-010 flagging the host VULNERABLE unlocks the EternalBlue move.
    // Conservative - require the positive NSE verdict and skip any "NOT VULNERABLE" result.
    if (_has_positive_ms17_010(text)) _add(facts, mkFact('smb.ms17_010', h, { cve: 'CVE-2017-0144', via: 'nmap-nse' }, S, source));

    var summary = [], fpServerHeaders = [];
    Object.keys(openPorts).sort().forEach(function (k) {
      var value = openPorts[k];
      summary.push(value.port);
      _add(facts, mkFact('port:' + value.port, h, value, S, source));
      if (value.service) {
        var normSvc = (value.port === 47001 && /^(?:winrm|http|wsman)$/i.test(value.service)) ? 'httpapi' : _normalize_service(value.service);
        _add(facts, mkFact('service.' + normSvc, h, value, S, source));
      }
      _parse_service_reachability(value.port, value.protocol, value.service || '', ws, source, facts);
      var pBlk = portBlocks[k] || '';
      if (value.protocol === 'tcp' && pBlk && [5985, 5986, 47001].indexOf(value.port) < 0 && !/winrm|wsman|httpapi/i.test(value.service || '') && /HTTP\/1\.[01]\s+[1-5]\d{2}\b/i.test(pBlk)) {
        var rawSrv = [];
        reAll(/^\s*(?:\|[_ ]?\s*)?Server:\s*([^\r\n"\\]+?)\s*$/im, pBlk).forEach(function (sm) {
          var sh = sm[1].trim();
          if (sh) rawSrv.push(sh);
        });
        reAll(/^\s*(?:\|[_ ]?\s*)?_?http-server-header:\s*([^\r\n]+?)\s*$/im, pBlk).forEach(function (sm) {
          var sh = sm[1].trim();
          if (sh) rawSrv.push(sh);
        });
        var validSrv = rawSrv.filter(function (hdr) { return !C._isNonWebServerHeader(hdr); });
        if (rawSrv.length === 0 || validSrv.length > 0) {
          validSrv.forEach(function (hdr) { fpServerHeaders.push(hdr); });
          var httpSvcVal = { port: value.port, protocol: 'tcp', service: 'http' };
          if (value.version || validSrv[0]) httpSvcVal.version = value.version || validSrv[0];
          _add(facts, mkFact('service.http', h, httpSvcVal, S, source));
          _add(facts, mkFact('http.reachable', h, { port: value.port, protocol: 'tcp', service: value.service || 'http' }, S, source));
        }
      }
    });
    if (summary.length) {
      _add(facts, mkFact('ports.open', h, { ports: uniqSortedNums(summary) }, S, source));
      if (cmdL.indexOf('proxychains') >= 0 || (ws && ws._hasProxychains) || actionId === 'proxychains-nmap-tcp') {
        _add(facts, mkFact('pivot.ports', h, { ports: uniqSortedNums(summary), via: 'proxychains' }, S, source));
      }
    }

    var scriptContext = _parse_nmap_script_facts(text, ws, source, facts, fpServerHeaders);
    var tcpPorts = Object.keys(openPorts).map(function (k) { return openPorts[k]; }).filter(function (v) { return v.protocol === 'tcp'; }).map(function (v) { return v.port; });
    if ([88, 389, 445].every(function (p) { return tcpPorts.indexOf(p) >= 0; }) || _looks_like_ad_ldap(text)) {
      var value = { ports: [88, 389, 445].filter(function (p) { return tcpPorts.indexOf(p) >= 0; }) };
      Object.keys(scriptContext).forEach(function (k) { value[k] = scriptContext[k]; });
      _add(facts, mkFact('ad.dc_candidate', h, value, S, source));
    }
  }

  function _parse_nmap(text, ws, source, facts, actionId, command) {
    if (_parse_nmap_xml(text, ws, source, facts, actionId, command)) return;
    var reportMatches = reAll(/^\s*Nmap scan report for\s+([^\r\n]+)/im, text);
    if (reportMatches.length > 1) {
      var parts = text.split(/(?=^\s*Nmap scan report for\b)/im);
      var header = '';
      for (var i = 0; i < parts.length; i++) {
        var blk = parts[i];
        var hm = /^\s*Nmap scan report for\s+(?:[^\r\n(]+\((\d{1,3}(?:\.\d{1,3}){3})\)|(\d{1,3}(?:\.\d{1,3}){3})|(\S+))/im.exec(blk);
        if (!hm) { header += blk + '\n'; continue; }
        var bTarget = hm[1] || hm[2] || ws.target;
        var bWs = Object.assign({}, ws, { target: ws.context && ws.context.forceTarget ? ws.target : bTarget });
        _parse_nmap_single(header + blk, bWs, source, facts, actionId, command);
      }
      return;
    }
    _parse_nmap_single(text, ws, source, facts, actionId, command);
  }
  C._parse_nmap = _parse_nmap;

})(typeof globalThis !== 'undefined' ? globalThis : this);
