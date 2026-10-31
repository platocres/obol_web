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
  var _NON_HTTP_WIRE_SVC_RE = /^(?:mongodb|mysql|mysqlx|postgresql|redis|memcached|amqp|jdwp|msrpc|ms-sql-s|netbios-ssn|microsoft-ds|ssh|ftp|smtp|pop3|imap|ldap|ldaps|kerberos(?:-sec)?|rdp|ms-wbt-server|vnc)$/i;
  var _DRIVER_PORT_HTTP_DIAG_RE = /trying to access MongoDB over HTTP on the native driver port/i;
  var _HTTP_SERVER_VER_RE = /^(Apache httpd|Apache Tomcat(?:\/Coyote JSP engine)?|nginx|Microsoft IIS httpd|Jetty|lighttpd|Caddy|Cherokee|Cheroot(?: httpd)?|WEBrick(?: httpd)?|MiniServ|Werkzeug|gunicorn|TornadoServer|SimpleHTTPServer|CUPS|ttyd|ShellInABox|Waitress|Thin|Puma|Cowboy)\s+v?([0-9][0-9A-Za-z._-]*)/i;
  var _IDENT_STOCK_USERS_RE = /^(?:root|nobody|nogroup|daemon|www-data|apache|nginx|postgres|mysql|redis|sshd|unknown|bin|sys|sync|mail|lp|uucp|proxy|backup|list|irc|gnats|systemd-network|systemd-resolve|messagebus|postfix|dovecot|ftp|smmsp|ntp|rpc|rpcuser|avahi|haldaemon|dbus)$/i;

  function _extract_http_ls_paths(blockText) {
    if (!/http-ls:/i.test(blockText || '')) return [];
    var lines = String(blockText).split(/\r?\n/);
    var inLs = false, curVol = '/', found = [];
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var hdrM = /^\s*(?:\|[_ ]*)?http-ls:\s*(.*)$/i.exec(raw);
      if (hdrM) {
        inLs = true;
        curVol = '/';
        var hVol = /\bVolume\s+(\/\S*)/i.exec(hdrM[1] || '');
        if (hVol) curVol = hVol[1].trim();
        continue;
      }
      if (!inLs) continue;
      if (!/^\s*\|/.test(raw)) { inLs = false; continue; }
      if (/^\s*(?:\|[_ ]*)?[a-z0-9]+-[a-z0-9_.-]+:(?!\/\/)/i.test(raw)) { inLs = false; continue; }
      var body = raw.replace(/^\s*\|[_ ]?\s*/, '');
      var volM = /^Volume\s+(\/\S*)/i.exec(body);
      if (volM) { curVol = volM[1].trim() || '/'; continue; }
      var rowM = /^(?:[\d.]+[KMGTPB]?|-)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?\s+(.+?)\s*$/i.exec(body);
      if (rowM) {
        var entry = rowM[1].trim();
        if (!entry || /^\.\.?\/?$/.test(entry)) continue;
        var normPath = entry.charAt(0) === '/'
          ? entry
          : ((curVol === '/' ? '/' : curVol.replace(/\/+$/, '') + '/') + entry);
        found.push(normPath);
      }
    }
    return C.uniqueSortedCI(found);
  }

  function _extract_http_enum_paths(blockText) {
    if (!blockText || !/http-enum:/i.test(blockText)) return [];
    var lines = String(blockText).split(/\r?\n/);
    var inEnum = false, found = [];
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var hdrM = /^\s*(?:\|[_ ]*)?http-enum:\s*(.*)$/i.exec(raw);
      if (hdrM) {
        var inlineM = /^(\/[A-Za-z0-9._~\/%-]{1,120}?):\s+/.exec(hdrM[1] || '');
        if (inlineM) {
          var inNorm = C._url_path(inlineM[1]);
          if (inNorm && inNorm !== '/') found.push(inNorm);
        }
        inEnum = !/^\s*\|_/.test(raw);
        continue;
      }
      if (!inEnum) continue;
      if (!/^\s*\|/.test(raw)) { inEnum = false; continue; }
      if (/^\s*(?:\|[_ ]*)?[a-z0-9]+-[a-z0-9_.-]+:(?!\/\/)/i.test(raw)) { inEnum = false; continue; }
      var rowM = /^\s*\|[_ ]\s+(\/[A-Za-z0-9._~\/%-]{1,120}?):\s+/.exec(raw);
      if (rowM) {
        var norm = C._url_path(rowM[1]);
        if (norm && norm !== '/') found.push(norm);
      }
      if (/^\s*\|_/.test(raw)) inEnum = false;
    }
    return C.uniqueSortedCI(found);
  }

  function _push_robots_tokens(chunk, out) {
    if (!chunk) return;
    chunk.trim().split(/\s+/).forEach(function (tok) {
      if (!tok || tok.charAt(0) !== '/') return;
      var cleaned = tok.replace(/\*+$/, '').replace(/[?#].*$/, '');
      if (!cleaned || cleaned === '/' || !/^\/[A-Za-z0-9._~\/%-]{1,120}$/.test(cleaned)) return;
      var norm = C._url_path(cleaned);
      if (norm && norm !== '/') out.push(norm);
    });
  }

  function _extract_http_robots_paths(blockText) {
    if (!blockText || !/http-robots\.txt:/i.test(blockText)) return [];
    var lines = String(blockText).split(/\r?\n/);
    var inRobots = false, found = [];
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var hdrM = /^\s*(?:\|[_ ]*)?http-robots\.txt:\s*(.*)$/i.exec(raw);
      if (hdrM) {
        var hdrRest = (hdrM[1] || '').trim();
        if (/\b0\s+disallowed\s+entries\b|couldn't\s+find/i.test(hdrRest)) {
          inRobots = false;
          continue;
        }
        var afterHdr = hdrRest.replace(/^.*?\bdisallowed\s+entr(?:y|ies)(?:\s*\(\d+\s+shown\))?\s*/i, '');
        if (afterHdr !== hdrRest && afterHdr) _push_robots_tokens(afterHdr, found);
        inRobots = !/^\s*\|_/.test(raw);
        continue;
      }
      if (!inRobots) continue;
      if (!/^\s*\|/.test(raw)) { inRobots = false; continue; }
      if (/^\s*(?:\|[_ ]*)?[a-z0-9]+-[a-z0-9_.-]+:(?!\/\/)/i.test(raw)) { inRobots = false; continue; }
      var body = raw.replace(/^\s*\|(?:_\s*|\s+)/, '').trim();
      _push_robots_tokens(body, found);
      if (/^\s*\|_/.test(raw)) inRobots = false;
    }
    return C.uniqueSortedCI(found);
  }

  function _collect_nmap_http_paths(blockText) {
    if (!blockText || !/http-(?:ls|enum|robots\.txt):/i.test(blockText)) return null;
    var all = [], tools = [];
    if (/http-ls:/i.test(blockText)) {
      var ls = _extract_http_ls_paths(blockText);
      if (ls.length) { all = all.concat(ls); tools.push('nmap-http-ls'); }
    }
    if (/http-enum:/i.test(blockText)) {
      var en = _extract_http_enum_paths(blockText);
      if (en.length) { all = all.concat(en); tools.push('nmap-http-enum'); }
    }
    if (/http-robots\.txt:/i.test(blockText)) {
      var rb = _extract_http_robots_paths(blockText);
      if (rb.length) { all = all.concat(rb); tools.push('nmap-http-robots'); }
    }
    var paths = C.uniqueSortedCI(all);
    if (!paths.length) return null;
    var val = {
      paths: paths.slice(0, 500),
      count: paths.length,
      tool: tools.length === 1 ? tools[0] : 'nmap-nse'
    };
    if (C._WEB_INTERESTING_RE) {
      var interesting = paths.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
      if (interesting.length) val.interesting = interesting.slice(0, 200);
    }
    return val;
  }

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
    var slClean = sl.replace(/\?$/, '');
    var value = { port: port, protocol: proto };
    if (service) value.service = service;
    var h = 'host:' + ws.target;
    if (port === 53 || sl === 'domain' || sl === 'dns') _add(facts, mkFact('dns.reachable', h, value, S, source));
    if (((port === 161 || port === 162) && proto === 'udp') || /^snmp(?:d|-trap)?$/i.test(slClean)) _add(facts, mkFact('snmp.reachable', h, value, S, source));
    if (port === 69 || sl === 'tftp') _add(facts, mkFact('tftp.reachable', h, value, S, source));
    if (proto !== 'tcp') return;
    var hasLinuxOs = facts.some(function (f) { return (f.kind === 'host.os_family' || f.kind === 'host.os_hint') && f.value && f.value.family === 'linux'; });
    var promoteWin = !hasLinuxOs;
    if (port === 21 || sl === 'ftp') _add(facts, mkFact('ftp.reachable', h, value, S, source));
    if (port === 22 || sl === 'ssh') _add(facts, mkFact('ssh.reachable', h, value, S, source));
    if (slClean === 'telnet' || (port === 23 && (!slClean || slClean === 'unknown' || slClean === 'tcpwrapped'))) _add(facts, mkFact('telnet.reachable', h, value, S, source));
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
      _add(facts, mkFact('db.reachable', h, value, S, source));
      C._add_os_observation(facts, ws, source, 'windows', port + '/' + proto + ' ' + (service || 'ms-sql-s'), 'medium', 'nmap', promoteWin);
    }
    if (port === 5432 || sl.indexOf('postgres') >= 0) {
      _add(facts, mkFact('postgres.reachable', h, value, S, source));
      _add(facts, mkFact('db.reachable', h, value, S, source));
    }
    if (port === 3306 || sl.indexOf('mysql') >= 0 || sl.indexOf('mariadb') >= 0) {
      _add(facts, mkFact('mysql.reachable', h, value, S, source));
      _add(facts, mkFact('db.reachable', h, value, S, source));
    }
    if (port === 6379 || sl.indexOf('redis') >= 0) {
      _add(facts, mkFact('redis.reachable', h, value, S, source));
      _add(facts, mkFact('db.reachable', h, value, S, source));
    }
    if (port === 27017 || slClean.indexOf('mongo') >= 0) {
      _add(facts, mkFact('mongo.reachable', h, value, S, source));
      _add(facts, mkFact('db.reachable', h, value, S, source));
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
    if (!isWinrmPort && !isHttpApiPort && ([80, 443, 8080, 8000, 8443].indexOf(port) >= 0 || slClean === 'http' || slClean === 'https' || slClean === 'ssl/http' || slClean === 'http-proxy' || slClean === 'http-alt' || slClean === 'https-alt' || slClean === 'ssl/http-proxy' || slClean === 'ssl/http-alt' || slClean === 'ipp' || slClean === 'ssl/ipp')) _add(facts, mkFact('http.reachable', h, value, S, source));
  }
  C._parse_service_reachability = _parse_service_reachability;

  function _normalize_nmap_ldap_domain(rawDom) {
    var d = String(rawDom || '').trim().toLowerCase();
    if (!d) return '';
    if (/0\.$/.test(d)) {
      var cand0 = d.slice(0, -2);
      if (/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/.test(cand0) && /\.[a-z]{2,}$/.test(cand0) && !C._IPV4_RE.test(cand0)) {
        return cand0;
      }
    }
    if (/\.$/.test(d)) {
      var candDot = d.slice(0, -1);
      if (/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/.test(candDot) && !C._IPV4_RE.test(candDot)) {
        return candDot;
      }
    }
    return (/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/.test(d) && !C._IPV4_RE.test(d)) ? d : '';
  }

  function _extract_positive_nse_cves(text) {
    if (!text || !/\bState:\s*VULNERABLE\b/i.test(text)) return [];
    var blocks = [];
    var cur = [];
    String(text).split(/\r?\n/).forEach(function (ln) {
      if (/^[ \t]*\|(?:_[ \t]?|[ \t])[a-z0-9]+-[a-z0-9_-]+:(?!\/\/)/i.test(ln)) {
        if (cur.length) blocks.push(cur.join('\n'));
        cur = [ln];
      } else if (/^[ \t]*\|/.test(ln)) {
        if (cur.length) cur.push(ln);
        else cur = [ln];
      } else {
        if (cur.length) { blocks.push(cur.join('\n')); cur = []; }
      }
    });
    if (cur.length) blocks.push(cur.join('\n'));
    if (/<script\b/i.test(text)) {
      (String(text).match(/<script\b[^>]*>/gi) || []).forEach(function (el) {
        var out = xmlAttr(el, 'output');
        if (out) blocks.push(out);
      });
    }
    var cves = [];
    blocks.forEach(function (blk) {
      if (!/\bState:\s*VULNERABLE\b/i.test(blk)) return;
      var subBlocks = [blk];
      if (/\bState:\s*NOT\s+VULNERABLE\b/i.test(blk)) {
        var parts = blk.split(/(?=^[ \t]*\|?[_ ]?[ \t]*(?:NOT[ \t]+)?VULNERABLE:[ \t]*$)/im);
        subBlocks = parts.length > 1 ? parts : [];
      }
      subBlocks.forEach(function (sb) {
        if (!/\bState:\s*VULNERABLE\b/i.test(sb) || /\bState:\s*NOT\s+VULNERABLE\b/i.test(sb)) return;
        reAll(/\bCVE-\d{4}-\d{4,7}\b/i, sb).forEach(function (m) {
          cves.push(m[0].toUpperCase());
        });
      });
    });
    return C.uniqueSortedCI(cves);
  }

  function _parse_nmap_script_facts(text, ws, source, facts, extraHeaders) {
    var context = {}, h = 'host:' + ws.target;
    var domains = {};
    reAll(C._NMAP_DOMAIN_NAME_RE, text).forEach(function (m) { domains[m.groups.domain.trim().toLowerCase()] = true; });
    if (C._NMAP_LDAP_BANNER_DOMAIN_RE) {
      reAll(C._NMAP_LDAP_BANNER_DOMAIN_RE, text).forEach(function (m) {
        var normDom = _normalize_nmap_ldap_domain(m.groups && m.groups.domain);
        if (normDom) domains[normDom] = true;
      });
    }
    var fqdns = {};
    reAll(C._NMAP_FQDN_RE, text).forEach(function (m) { fqdns[m.groups.fqdn.trim().toLowerCase()] = true; });
    reAll(/^\s*Nmap scan report for\s+([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\s+\(\d{1,3}(?:\.\d{1,3}){3}\)/gim, text).forEach(function (m) {
      var candHost = (m[1] || '').replace(/\.$/, '').toLowerCase();
      if (!candHost || C._IPV4_RE.test(candHost) || /^\d+(?:\.\d+)+$/.test(candHost)) return;
      if (/^localhost(?:\.|$)/i.test(candHost)) return;
      if (!/\.[a-z][a-z0-9-]*$/i.test(candHost)) return;
      fqdns[candHost] = true;
    });
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
    reAll(C._NMAP_COMPUTER_NAME_RE, text).forEach(function (m) {
      var rawN = m.groups.name.trim();
      if (rawN.indexOf('.') >= 0) rawN = rawN.split('.')[0];
      if (rawN) names[rawN] = true;
    });
    var nameKeys = C.uniqueSortedCI(Object.keys(names));
    if (nameKeys.length) {
      context.name = nameKeys[0];
      _add(facts, mkFact('host.hostname', h, { name: context.name }, S, source));
    }
    var redirects = C.uniqueSortedCI(reAll(C._NMAP_HTTP_REDIRECT_RE, text).map(function (m) { return m.groups.location.trim(); }).filter(Boolean));
    redirects.forEach(function (loc) {
      var hm = /^https?:\/\/(?!\[)(?:[^\/:?#"'\s@]+@)?([^\/:?#"'\s]+)/i.exec(loc);
      var candHost = hm ? hm[1].replace(/\.$/, '').toLowerCase() : '';
      if (!candHost || C._IPV4_RE.test(candHost) || /^\d+(?:\.\d+)+$/.test(candHost)) return;
      if (/^localhost(?:\.|$)/i.test(candHost)) return;
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(candHost)) return;
      if (!/\.[a-z][a-z0-9-]*$/i.test(candHost)) return;
      fqdns[candHost] = true;
    });
    reAll(/(?:(?<![A-Za-z0-9-])smtp-commands:\s*|<script\b[^>]*\bid=["']smtp-commands["'][^>]*\boutput=["']\s*)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)\b/gi, text).forEach(function (m) {
      var candHost = (m[1] || '').replace(/\.$/, '').toLowerCase();
      if (!candHost || C._IPV4_RE.test(candHost) || /^\d+(?:\.\d+)+$/.test(candHost)) return;
      if (/^localhost(?:\.|$)/i.test(candHost)) return;
      if (!/\.[a-z][a-z0-9-]*$/i.test(candHost)) return;
      fqdns[candHost] = true;
    });
    if (/ssl-cert/i.test(text)) {
      var addSslCertHost = function (rawHost) {
        var candHost = String(rawHost || '').trim().replace(/^\*\./, '').replace(/\.$/, '').toLowerCase();
        if (!candHost || candHost.indexOf('.') < 0) return;
        if (C._IPV4_RE.test(candHost) || /^\d+(?:\.\d+)+$/.test(candHost)) return;
        if (/^(?:localhost|ip6-localhost)(?:\.|$)/i.test(candHost)) return;
        if (/\.(?:localdomain|in-addr\.arpa|ip6\.arpa|invalid|test)$/i.test(candHost)) return;
        if (/(?:^|\.)example\.(?:com|org|net|edu)$/i.test(candHost)) return;
        if (/^(?:ubuntu|debian|kali|centos|fedora|redhat|rhel|suse|archlinux|plesk|parallels|cpanel|whm|traefik\.default|kubernetes\.default(?:\.svc(?:\.cluster\.local)?)?)$/i.test(candHost)) return;
        if (/(?:^|\.)(?:letsencrypt\.org|digicert\.com|sectigo\.com|comodoca\.com|godaddy\.com|globalsign\.com|cloudflare\.com|amazonaws\.com|cloudfront\.net|aka(?:mai|maiedge)\.net|windows\.net|office\.com|microsoft\.com|entrust\.net|verisign\.com|identrust\.com|google(?:trustservices)?\.com|apple\.com|ubuntu\.com|debian\.org|kali\.org)$/i.test(candHost)) return;
        if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(candHost)) return;
        if (!/\.[a-z][a-z0-9-]{1,}$/.test(candHost)) return;
        fqdns[candHost] = true;
      };
      reAll(/(?:ssl-cert:\s*Subject:[^\r\n]*?(?:commonName|CN)\s*=\s*|<script\b[^>]*\bid=["']ssl-cert["'][^>]*\boutput=["'][^"']*?Subject:[^"'\r\n]*?(?:commonName|CN)\s*=\s*|<elem\b[^>]*\bkey=["']commonName["'][^>]*>\s*)(\*\.[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})/gi, text).forEach(function (m) {
        addSslCertHost(m[1]);
      });
      reAll(/Subject Alternative Name:[^\r\n"']*/gi, text).forEach(function (m) {
        reAll(/\bDNS\s*:\s*(\*\.[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})/gi, m[0]).forEach(function (dm) {
          addSslCertHost(dm[1]);
        });
      });
    }
    var emittedHostDoms = {};
    if (domain) emittedHostDoms[domain.toLowerCase()] = true;
    C.uniqueSortedCI(Object.keys(fqdns)).forEach(function (fqdn) {
      var parts = fqdn.split('.').filter(Boolean);
      var value = { fqdn: fqdn };
      if (parts.length) value.hostname = parts[0];
      if (parts.length === 2) value.domain = fqdn;
      else if (parts.length > 2) value.domain = parts.slice(1).join('.');
      _add(facts, mkFact('host.fqdn', h, value, S, source));
      if (value.domain && !emittedHostDoms[value.domain.toLowerCase()]) {
        emittedHostDoms[value.domain.toLowerCase()] = true;
        _add(facts, mkFact('host.domain', h, { domain: value.domain }, S, source));
      }
    });
    if (/auth-owners/i.test(text)) {
      var identUsers = [];
      reAll(/(?:(?<![A-Za-z0-9-])auth-owners:\s*|<script\b[^>]*\bid=["']auth-owners["'][^>]*\boutput=["']\s*)([A-Za-z_][A-Za-z0-9_.-]{0,31})\b/gi, text).forEach(function (m) {
        var u = (m[1] || '').trim();
        if (u && !_IDENT_STOCK_USERS_RE.test(u)) identUsers.push(u);
      });
      if (identUsers.length) {
        var uniqIdent = C.uniqueSortedCI(identUsers);
        _add(facts, mkFact('host.users', h, { users: uniqIdent, count: uniqIdent.length, via: 'ident' }, S, source));
      }
    }
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
    var nseCves = _extract_positive_nse_cves(text);
    if (nseCves.length) {
      _add(facts, mkFact('exploit.candidate', h, { cves: nseCves, via: 'nmap-nse' }, S, source));
    }
    if (/\bSMBv1\b[^\r\n]{0,120}?\b(?:enabled|true|dangerous)\b|\bNT LM 0\.12\s*\(SMBv1\)/i.test(text)) {
      _add(facts, mkFact('smb.smbv1', h, { enabled: true, tool: 'nmap' }, S, source));
    }
    if (/smb-security-mode[\s\S]{0,200}?(?:\baccount_used:\s*guest\b|key=["']account_used["']>\s*guest\s*<)/i.test(text)) {
      _add(facts, mkFact('smb.guest_session', h, { tool: 'nmap' }, S, source));
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
    if (/rsync-list-modules:/i.test(text)) {
      var rBlk = (/rsync-list-modules:([\s\S]*?)(?:\n\d+\/|\nService Info:|\nOS details:|\nNmap done|$)/i.exec(text) || [])[1] || '';
      var rMods = [], rEntries = [], rUsers = [], rSeen = {};
      var rGenericModRe = /^(?:files?|data|pub|public|shared?|shares?|backups?|bak|www|web|webroot|html|htdocs|docs?|documents?|media|images?|img|static|assets?|uploads?|downloads?|ftp|rsync|src|source|code|git|repos?|svn|logs?|tmp|temp|var|opt|etc|usr|srv|mnt|home|users?|root|admin|administrator|guest|anonymous|test|testing|dev|prod|staging|archive|archives|packages?|pkg|dist|mirror|mirrors|ubuntu|debian|centos|fedora|alpine|kali|kernel|cpan|cran|ctan|gnu)$/i;
      reAll(/^\s*\|[_\s]+(?!rsync-list-modules:)([A-Za-z0-9_.-]{1,64})(?:(?:\t+|\s+)([^\r\n]*))?$/gim, rBlk).forEach(function (m) {
        var modName = m[1].trim(), modComment = (m[2] || '').trim();
        if (!modName || /^(?:ERROR|WARNING|@RSYNCD)/i.test(modName)) return;
        var mk = modName.toLowerCase();
        if (!rSeen[mk]) {
          rSeen[mk] = true;
          rMods.push(modName);
          rEntries.push({ name: modName, comment: modComment });
        }
        if (/^[A-Za-z_][A-Za-z0-9_-]{1,31}$/.test(modName) && !rGenericModRe.test(modName) && /\bhome\b/i.test(modComment)) {
          rUsers.push(modName);
        }
      });
      if (rMods.length) {
        _add(facts, mkFact('host.up', h, { target: ws.target }, S, source));
        if (!facts.some(function (f) { return f && /^port:/.test(f.kind) && f.value && f.value.service === 'rsync'; }) && !facts.some(function (f) { return f && f.kind === 'port:873'; })) {
          var rsPortM = /(?:^|\s)-p\s*(\d{1,5})\b/.exec(String(source || ''));
          var rsPort = rsPortM ? parseInt(rsPortM[1], 10) : 873;
          if (!(rsPort >= 1 && rsPort <= 65535)) rsPort = 873;
          _add(facts, mkFact('port:' + rsPort, h, { port: rsPort, protocol: 'tcp', service: 'rsync' }, S, source));
        }
        _add(facts, mkFact('service.rsync', h, { port: 873, protocol: 'tcp', service: 'rsync' }, S, source));
        _add(facts, mkFact('rsync.reachable', h, { port: 873, tool: 'nmap' }, S, source));
        _add(facts, mkFact('rsync.modules', h, { modules: rMods, entries: rEntries, count: rMods.length, tool: 'nmap' }, S, source));
        if (rUsers.length) {
          _add(facts, mkFact('host.users', h, { users: C.uniqueSortedCI(rUsers), via: 'rsync-modules' }, S, source));
        }
      }
    }
    if (/redis-info:/i.test(text) || (/^\s*\|\s*Version:\s*\d+\.\d+/im.test(text) && /^\s*\|_?\s*Role:\s*(?:master|slave|replica)\b/im.test(text))) {
      var rdBlkM = /redis-info:([\s\S]*?)(?:\n\d+\/|\nService Info:|\nOS details:|\nNmap done|$)/i.exec(text);
      var rdBlk = rdBlkM ? rdBlkM[1] : text;
      var rdVerM = /^\s*\|_?\s*Version:\s*([0-9][0-9A-Za-z._-]*)/im.exec(rdBlk);
      var rdOsM = /^\s*\|_?\s*OS:\s*([^\r\n]+)/im.exec(rdBlk);
      var rdPortM = /^(\d{1,5})\/tcp\s+open\s+redis\b/im.exec(text) || /(?:^|\s)-p\s*(\d{1,5})\b/.exec(String(source || ''));
      var rdPort = rdPortM ? parseInt(rdPortM[1], 10) : 6379;
      if (!(rdPort >= 1 && rdPort <= 65535)) rdPort = 6379;
      _add(facts, mkFact('host.up', h, { target: ws.target }, S, source));
      _add(facts, mkFact('port:' + rdPort, h, { port: rdPort, protocol: 'tcp', service: 'redis', version: rdVerM ? ('Redis key-value store ' + rdVerM[1]) : undefined }, S, source));
      _add(facts, mkFact('service.redis', h, { port: rdPort, protocol: 'tcp', service: 'redis', version: rdVerM ? ('Redis key-value store ' + rdVerM[1]) : undefined }, S, source));
      _add(facts, mkFact('redis.reachable', h, { port: rdPort, tool: 'nmap' }, S, source));
      _add(facts, mkFact('db.reachable', h, { service: 'redis', port: rdPort, tool: 'nmap' }, S, source));
      _add(facts, mkFact('redis.unauth', h, { port: rdPort, tool: 'nmap' }, S, source));
      if (rdVerM) {
        _add(facts, mkFact('service.version', h, { port: rdPort, service: 'redis', product: 'Redis', version: rdVerM[1], raw: 'Redis ' + rdVerM[1] }, S, source));
      }
      if (rdOsM && C._add_os_from_text) {
        C._add_os_from_text(rdOsM[1].trim(), ws, source, facts, 'nmap-redis', 'high', true);
      }
    }
    if (/http-(?:ls|enum|robots\.txt):/i.test(text) && !facts.some(function (f) { return f && f.kind === 'web.paths'; })) {
      var scriptPathsVal = _collect_nmap_http_paths(text);
      if (scriptPathsVal) {
        _add(facts, mkFact('web.paths', h, scriptPathsVal, S, source));
      }
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
    var termSurfaces = headers.concat(titles);
    facts.forEach(function (f) {
      if (f && /^port:\d+$/.test(f.kind) && f.value) {
        if (f.value.version) termSurfaces.push(String(f.value.version));
        if (f.value.service) termSurfaces.push(String(f.value.service));
      }
    });
    var seenWebTerms = {};
    termSurfaces.forEach(function (surf) {
      var tm = /\b(ttyd|wetty|gotty|shellinabox)\b/i.exec(surf || '');
      if (tm) seenWebTerms[tm[1].toLowerCase()] = true;
    });
    Object.keys(seenWebTerms).sort().forEach(function (prod) {
      tech.push({ name: 'web-terminal', value: prod });
      _add(facts, mkFact('service.web_terminal', h, { product: prod, tool: 'nmap' }, S, source));
    });
    if (/\/exhibitor\/v1\/ui\//i.test(text) || redirects.some(function (r) { return /\/exhibitor\/v1\/ui\//i.test(r); }) || titles.some(function (tItem) { return /\/exhibitor\/v1\/ui\//i.test(tItem); })) {
      tech.push({ name: 'console', value: 'exhibitor' });
    }
    if (/http-auth/i.test(text)) {
      var authBlocks = [];
      var curAuth = [];
      String(text).split(/\r?\n/).forEach(function (ln) {
        if (/^[ \t]*\|[_ ]?[ \t]*http-auth:/i.test(ln)) {
          if (curAuth.length) authBlocks.push(curAuth.join('\n'));
          curAuth = [ln];
        } else if (curAuth.length) {
          if (/^[ \t]*\|/.test(ln) && !/^[ \t]*\|(?:_[ \t]?|[ \t])[a-z0-9]+-[a-z0-9_.-]+:(?!\/\/)/i.test(ln)) {
            curAuth.push(ln);
            if (/^[ \t]*\|_/.test(ln)) { authBlocks.push(curAuth.join('\n')); curAuth = []; }
          } else {
            authBlocks.push(curAuth.join('\n'));
            curAuth = [];
          }
        }
      });
      if (curAuth.length) authBlocks.push(curAuth.join('\n'));
      if (/<script\b/i.test(text)) {
        (String(text).match(/<script\b[^>]*>/gi) || []).forEach(function (el) {
          if (/^http-auth$/i.test(xmlAttr(el, 'id'))) {
            var out = xmlAttr(el, 'output');
            if (out) authBlocks.push(out);
          }
        });
      }
      var seenRealms = {};
      authBlocks.forEach(function (blk) {
        reAll(/\bBasic\s+realm\s*=\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\r\n]+))/gi, blk).forEach(function (rm) {
          var rawRealm = (rm[1] || rm[2] || rm[3] || '').replace(/\\x0[dDaA]/g, '').replace(/^["']|["']$/g, '').trim();
          if (!rawRealm || seenRealms[rawRealm.toLowerCase()]) return;
          seenRealms[rawRealm.toLowerCase()] = true;
          _add(facts, mkFact('http.headers', h, {
            scheme: 'Basic',
            realm: rawRealm,
            headers: { 'www-authenticate': 'Basic realm="' + rawRealm + '"' },
            tool: 'nmap'
          }, S, source));
        });
      });
    }
    if (redirects.length) _add(facts, mkFact('http.redirect', h, { locations: redirects.slice(0, 10) }, S, source));
    if (tech.length) _add(facts, mkFact('web.tech', h, { items: tech.slice(0, 20), tool: 'nmap' }, S, source));
    generators.forEach(function (gen) {
      var cmsM = /^(WordPress|Joomla!?|Drupal|Magento|Ghost|MediaWiki|TYPO3)(?:\s+CMS)?(?:\s+v?([0-9][0-9A-Za-z._-]*))?(?=$|[\s(\-])/i.exec(gen);
      if (cmsM) {
        _add(facts, mkFact('web.cms', h, {
          cms: cmsM[1].toLowerCase().replace(/!$/, ''),
          version: cmsM[2] || '',
          tool: 'nmap'
        }, S, source));
      }
    });
    if (reSearch(C._NMAP_FTP_ANON_RE, text) || (/ftp-anon/i.test(text) && /\[NSE:\s*writeable\]/i.test(text))) {
      _add(facts, mkFact('ftp.reachable', h, { tool: 'nmap' }, S, source));
      _add(facts, mkFact('ftp.anonymous_login', h, { tool: 'nmap' }, S, source));
      if (/\[NSE:\s*writeable\]/i.test(text)) {
        _add(facts, mkFact('ftp.anon_write', h, { tool: 'nmap', anonymous: true }, S, source));
      }
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
    return String(s || '').replace(/\\x20/gi, ' ').replace(/\\r/g, '\r').replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\\./g, '.');
  }

  function _parse_nmap_single(text, ws, source, facts, actionId, command) {
    var h = 'host:' + ws.target, srcL = (source + ' ' + (command || '')).toLowerCase();
    var openPorts = {}, portBlocks = {};
    var snmpOs = /^\s*[|_ ]*description:\s*(Linux\b[^\r\n]*)/im.exec(text);
    if (snmpOs) C._add_os_observation(facts, ws, source, 'linux', snmpOs[1], 'high', 'nmap-snmp', true);
    var osText = text
      .replace(/^\s*\d+\/(?:tcp|udp)\s+(?:closed|filtered|unfiltered|open\|filtered)\b[^\r\n]*$/gim, '')
      .replace(/^\s*(?:\|[_ ]?\s*)?215[ \t]+UNIX emulated by FileZilla\b[^\r\n]*$/gim, '')
      .replace(/([%(])P=[A-Za-z0-9._-]+/g, '$1');
    C._add_os_from_text(osText, ws, source, facts, 'nmap', 'high', true);

    var explicitOpenSet = {}, explicitNonOpenSet = {};
    reAll(C._NMAP_OPEN_RE, text).forEach(function (m) {
      var pText = m.groups.port, ln = m[0];
      var pr = ln.toLowerCase().indexOf(pText + '/udp') >= 0 ? 'udp' : 'tcp';
      explicitOpenSet[parseInt(pText, 10) + '/' + pr] = true;
    });
    reAll(/^[ \t]*(?<port>\d{1,5})\/(?<proto>tcp|udp)[ \t]+(?:closed|filtered|unfiltered)\b/gim, text).forEach(function (m) {
      var key = parseInt(m.groups.port, 10) + '/' + m.groups.proto.toLowerCase();
      if (!explicitOpenSet[key]) explicitNonOpenSet[key] = true;
    });

    reAll(C._NMAP_DISCOVERED_RE, text).forEach(function (m) {
      var port = parseInt(m.groups.port, 10), proto = m.groups.proto.toLowerCase();
      if (explicitNonOpenSet[port + '/' + proto]) return;
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
      if (curPortKey && (/^\s*\|/.test(ln) || /^\s+[a-z0-9]+-[a-z0-9_.-]+:(?!\/\/)/i.test(ln))) {
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
      if (rPort > 0 && rPort <= 65535 && !openPorts[rPort + '/tcp'] && !explicitNonOpenSet[rPort + '/tcp']) {
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
    var hasVulnScript = /--script[=\s]+[^\r\n]*vuln/i.test(cmdL) || /\bState:\s*VULNERABLE\b|^\s*\|\s*VULNERABLE:\s*$|\|\s*_?(?:http|smb|ssl|ftp|rdp|rmi)-vuln-[a-z0-9-]+:/im.test(text);
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
      var rawSvcClean = String(value.service || '').replace(/\?$/, '');
      var normSvc = '';
      if (value.service) {
        if (value.port === 47001 && /^(?:winrm|http|https|ssl[\/-]http|wsman|httpapi)$/i.test(rawSvcClean)) {
          normSvc = 'httpapi';
        } else if ((value.port === 5985 || value.port === 5986) && /^(?:winrm|http|https|ssl[\/-]http|wsman|httpapi)$/i.test(rawSvcClean)) {
          normSvc = 'winrm';
        } else {
          normSvc = _normalize_service(rawSvcClean || value.service);
        }
        _add(facts, mkFact('service.' + normSvc, h, value, S, source));
      }
      _parse_service_reachability(value.port, value.protocol, value.service || '', ws, source, facts);
      var pBlk = portBlocks[k] || '';
      var pBlkDec = pBlk ? _unescape_nmap_fp(pBlk) : '';
      var promotedNonHttpProto = false;

      if (value.protocol === 'tcp' && pBlkDec && (!rawSvcClean || /^(?:unknown|tcpwrapped|unassigned)$/i.test(rawSvcClean))) {
        var ftpGreetM = /(?:^|[\r\n"|\s])220[- ]([^\r\n"\\]*(?:FTP|FileZilla|vsFTPd|ProFTPD|Pure-FTPd|Microsoft FTP)[^\r\n"\\]*)/i.exec(pBlkDec);
        var smtpGreetM = !ftpGreetM ? /(?:^|[\r\n"|\s])220[- ]([^\r\n"\\]*\bESMTP\b[^\r\n"\\]*)/i.exec(pBlkDec) : null;
        var sshGreetM = (!ftpGreetM && !smtpGreetM) ? /(?:^|[\r\n"|\s])(SSH-2\.0-[^\r\n"\\]+)/.exec(pBlkDec) : null;
        var vncGreetM = (!ftpGreetM && !smtpGreetM && !sshGreetM) ? /(?:^|[\r\n"|\s])(RFB 00\d\.\d{3})\b/.exec(pBlkDec) : null;
        if (ftpGreetM) {
          var ftpLine = ftpGreetM[1].trim();
          var ftpVerM = /\b(FileZilla(?:\s+Server)?|vsFTPd|ProFTPD|Pure-FTPd|Microsoft\s+FTP(?:\s+Service)?)\s+v?([0-9][0-9A-Za-z._-]*)/i.exec(ftpLine);
          var ftpSvcVal = { port: value.port, protocol: 'tcp', service: 'ftp' };
          if (ftpVerM) ftpSvcVal.version = ftpVerM[1] + ' ' + ftpVerM[2];
          _add(facts, mkFact('service.ftp', h, ftpSvcVal, S, source));
          _add(facts, mkFact('ftp.reachable', h, { port: value.port, protocol: 'tcp', service: 'ftp' }, S, source));
          _add(facts, mkFact('ftp.banner', h, { port: value.port, banner: ftpLine, banners: [ftpLine] }, S, source));
          if (ftpVerM) {
            _add(facts, mkFact('service.version', h, {
              port: value.port,
              service: 'ftp',
              product: ftpVerM[1],
              version: ftpVerM[2],
              raw: ftpLine
            }, S, source));
          }
          promotedNonHttpProto = true;
        } else if (smtpGreetM) {
          var smtpLine = smtpGreetM[1].trim();
          _add(facts, mkFact('service.smtp', h, { port: value.port, protocol: 'tcp', service: 'smtp' }, S, source));
          _add(facts, mkFact('smtp.reachable', h, { port: value.port, protocol: 'tcp', service: 'smtp' }, S, source));
          _add(facts, mkFact('mail.reachable', h, { port: value.port, protocol: 'tcp', service: 'smtp' }, S, source));
          _add(facts, mkFact('smtp.banner', h, { port: value.port, banner: smtpLine, banners: [smtpLine] }, S, source));
          promotedNonHttpProto = true;
        } else if (sshGreetM) {
          var sshBanner = sshGreetM[1].trim();
          var sshVerM = /^SSH-2\.0-([A-Za-z0-9._]+?)(?:[_-]([0-9][0-9A-Za-z._p-]*))?(?:\s|$)/.exec(sshBanner);
          _add(facts, mkFact('service.ssh', h, { port: value.port, protocol: 'tcp', service: 'ssh', version: sshBanner }, S, source));
          _add(facts, mkFact('ssh.reachable', h, { port: value.port, protocol: 'tcp', service: 'ssh' }, S, source));
          _add(facts, mkFact('ssh.banner', h, { port: value.port, banner: sshBanner, banners: [sshBanner] }, S, source));
          if (sshVerM) {
            _add(facts, mkFact('service.version', h, {
              port: value.port,
              service: 'ssh',
              product: sshVerM[1],
              version: sshVerM[2] || '',
              raw: sshBanner
            }, S, source));
          }
          promotedNonHttpProto = true;
        } else if (vncGreetM) {
          var rfbVer = vncGreetM[1].trim();
          _add(facts, mkFact('service.vnc', h, { port: value.port, protocol: 'tcp', service: 'vnc', version: rfbVer }, S, source));
          _add(facts, mkFact('vnc.reachable', h, { port: value.port, protocol: 'tcp', service: 'vnc' }, S, source));
          promotedNonHttpProto = true;
        }
      } else if (value.protocol === 'tcp' && pBlkDec && (/^ftp(?:-data)?$/i.test(rawSvcClean) || normSvc === 'ftp')) {
        var knownFtpGreetM = /(?:^|[\r\n"|\s])220[- ]([^\r\n"\\]{2,160})/i.exec(pBlkDec);
        if (knownFtpGreetM && !/\bE?SMTP\b/i.test(knownFtpGreetM[1])) {
          var knownFtpLine = knownFtpGreetM[1].trim();
          if (knownFtpLine) {
            _add(facts, mkFact('ftp.banner', h, { port: value.port, banner: knownFtpLine, banners: [knownFtpLine] }, S, source));
          }
        }
      }

      if (value.protocol === 'tcp' && pBlk && /http-(?:ls|enum|robots\.txt):/i.test(pBlk)) {
        var portPathsVal = _collect_nmap_http_paths(pBlk);
        if (portPathsVal) {
          portPathsVal.port = value.port;
          _add(facts, mkFact('web.paths', h, portPathsVal, S, source));
        }
      }

      if (value.protocol === 'tcp' && [5985, 5986, 47001].indexOf(value.port) < 0 &&
          /^(?:http|https|ssl[\/-]http|http-alt|http-proxy|https-alt|ssl[\/-]http-alt|ssl[\/-]http-proxy|ipp|ssl[\/-]ipp)$/i.test(rawSvcClean) && value.version) {
        var httpVerM = _HTTP_SERVER_VER_RE.exec(value.version);
        if (httpVerM && !C._isNonWebServerHeader(value.version)) {
          _add(facts, mkFact('service.version', h, {
            port: value.port,
            service: normSvc || 'http',
            product: httpVerM[1],
            version: httpVerM[2],
            raw: value.version
          }, S, source));
          if (!pBlk || !reSearch(C._NMAP_HTTP_SERVER_RE, pBlk)) {
            fpServerHeaders.push(value.version);
          }
        }
      }

      if (value.protocol === 'tcp' && pBlkDec && !promotedNonHttpProto &&
          [5985, 5986, 47001].indexOf(value.port) < 0 &&
          !/winrm|wsman|httpapi/i.test(rawSvcClean) &&
          !_NON_HTTP_WIRE_SVC_RE.test(rawSvcClean) &&
          !_DRIVER_PORT_HTTP_DIAG_RE.test(pBlkDec) &&
          /HTTP\/1\.[01]\s+[1-5]\d{2}\b/i.test(pBlkDec)) {
        var rawSrv = [];
        reAll(/^\s*(?:\|[_ ]?\s*)?Server:\s*([^\r\n"\\]+?)\s*$/im, pBlkDec).forEach(function (sm) {
          var sh = sm[1].trim();
          if (sh) rawSrv.push(sh);
        });
        reAll(/^\s*(?:\|[_ ]?\s*)?_?http-server-header:\s*([^\r\n]+?)\s*$/im, pBlkDec).forEach(function (sm) {
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
    var hasKerbAndDir = tcpPorts.indexOf(88) >= 0 && [389, 636, 3268, 3269, 9389].some(function (p) { return tcpPorts.indexOf(p) >= 0; });
    var hasAdwsAndLdap = tcpPorts.indexOf(9389) >= 0 && [389, 636, 3268, 3269].some(function (p) { return tcpPorts.indexOf(p) >= 0; });
    if (hasKerbAndDir || hasAdwsAndLdap || _looks_like_ad_ldap(text)) {
      var value = { ports: [88, 389, 445, 636, 3268, 3269, 9389].filter(function (p) { return tcpPorts.indexOf(p) >= 0; }) };
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
