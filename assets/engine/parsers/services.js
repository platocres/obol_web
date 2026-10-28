/*!
 * obol engine - parsers/services.js
 * Faithful JS port of
 * Generic service metadata: HTTP, SSH, FTP, SNMP - reachability/fingerprints only.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  function _parse_http_metadata(text, ws, source, facts) {
    var h = 'host:' + ws.target;
    var headerOnlyText = String(text || '');
    var bodySplit = /\r?\n\r?\n|<\s*(?:!doctype|html|head|body)\b/i.exec(headerOnlyText);
    if (bodySplit && bodySplit.index > 0) headerOnlyText = headerOnlyText.slice(0, bodySplit.index);
    C._add_os_from_text(headerOnlyText, ws, source, facts, 'http', 'medium', true);
    var statusValues = [];
    reAll(C._HTTP_STATUS_RE, text).forEach(function (m) {
      var value = { status: parseInt(m.groups.status, 10) };
      var reason = (m.groups.reason || '').trim();
      if (reason) value.reason = reason;
      statusValues.push(value);
    });
    reAll(/^https?:\/\/\S+\s+\[(?<status>\d{3})(?:\s+(?<reason>[^\]\r\n]+))?\]/im, text).forEach(function (m) {
      var value = { status: parseInt(m.groups.status, 10) };
      var reason = (m.groups.reason || '').trim();
      if (reason) value.reason = reason;
      statusValues.push(value);
    });
    if (statusValues.length) {
      _add(facts, mkFact('http.reachable', h, { tool: 'http-client' }, S, source));
      _add(facts, mkFact('http.response', h, { responses: statusValues.slice(0, 10) }, S, source));
    }
    var servers = {}, redirects = {}, contentTypes = {}, tech = [];
    reAll(C._HTTP_HEADER_RE, text).forEach(function (m) {
      var key = m.groups.key.toLowerCase(), value = m.groups.value.trim();
      if (!value) return;
      if (key === 'server') servers[value] = true;
      else if (key === 'x-powered-by') tech.push({ name: 'x-powered-by', value: value });
      else if (key === 'location') redirects[value] = true;
      else if (key === 'content-type') contentTypes[value] = true;
    });
    reAll(/\bHTTPServer\[[^\]]*\]\[(?<srv>[^\]\r\n]+)\]/i, text).forEach(function (m) {
      if (m.groups && m.groups.srv && m.groups.srv.trim()) servers[m.groups.srv.trim()] = true;
    });
    reAll(C._WHATWEB_PLUGIN_RE, text).forEach(function (m) {
      var name = m.groups.name.trim(), value = m.groups.value.trim();
      var nl = name.toLowerCase();
      if (['title', 'ip', 'country', 'email', 'summary'].indexOf(nl) >= 0) return;
      if (nl === 'httpserver' || nl === 'server') servers[value] = true;
      else if (nl === 'redirectlocation') redirects[value] = true;
      else tech.push({ name: name, value: value });
    });
    var titleMatch = /\bTitle\[(?<title>[^\]\r\n]+)\]/.exec(text);
    if (titleMatch && titleMatch.groups.title.trim()) _add(facts, mkFact('web.title', h, { titles: [titleMatch.groups.title.trim()] }, S, source));
    var svHeaders = C.uniqueSortedCI(Object.keys(servers)).filter(function (hdr) { return !(C._isNonWebServerHeader && C._isNonWebServerHeader(hdr)); });
    if (svHeaders.length) {
      _add(facts, mkFact('http.reachable', h, { tool: 'http-client' }, S, source));
      _add(facts, mkFact('web.server', h, { headers: svHeaders.slice(0, 10) }, S, source));
    }
    // Reachability from a returned response body, even when the fetch printed no status line and no
    // Server header: a curl/wget fetch that renders an HTML document, a proxychains-tunneled fetch
    // whose chain reports OK and returns a page, or a PowerShell Invoke-WebRequest wrapper that
    // reports "HTTP Error <code>", all prove the host answered over HTTP. A name resolution or
    // connection failure returns no body and is deliberately excluded (the response-body evidence is
    // absent), so an unreachable name never mints this.
    if (!facts.some(function (f) { return f.kind === 'http.reachable'; })) {
      var sawResponseBody = /<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]|<title[\s>]/i.test(text)
        || /\bHTTP Error\s+\d{3}\b/i.test(text);
      var sawConnFailure = /could not be resolved|could not resolve host|name or service not known|connection refused|failed to connect|connection timed out|connection reset|no route to host|network is unreachable/i.test(text);
      if (sawResponseBody && !sawConnFailure) {
        _add(facts, mkFact('http.reachable', h, { tool: 'http-client' }, S, source));
      }
    }
    if (Object.keys(redirects).length) _add(facts, mkFact('http.redirect', h, { locations: C.uniqueSortedCI(Object.keys(redirects)).slice(0, 10) }, S, source));
    if (Object.keys(contentTypes).length) C.uniqueSortedCI(Object.keys(contentTypes)).forEach(function (item) { tech.push({ name: 'content-type', value: item }); });
    if (tech.length) {
      var dedup = [], seen = {};
      tech.forEach(function (item) {
        var key = item.name.toLowerCase() + '|' + item.value.toLowerCase();
        if (seen[key]) return;
        seen[key] = true;
        dedup.push(item);
      });
      _add(facts, mkFact('web.tech', h, { items: dedup.slice(0, 20) }, S, source));
    }
  }
  C._parse_http_metadata = _parse_http_metadata;

  function _parse_ssh_banner(text, ws, source, facts) {
    var banners = C.uniqueSortedCI(reAll(C._SSH_BANNER_RE, text).map(function (m) { return m[0].trim(); }));
    if (!banners.length) return;
    C._add_os_from_text(banners.join('\n'), ws, source, facts, 'ssh', 'medium', true);
    _add(facts, mkFact('ssh.reachable', 'host:' + ws.target, { tool: 'banner' }, S, source));
    _add(facts, mkFact('ssh.banner', 'host:' + ws.target, { banners: banners.slice(0, 10) }, S, source));
  }
  C._parse_ssh_banner = _parse_ssh_banner;

  // A CONFIRMED FTP upload: an upload-specific initiation token AND a success
  // marker. Discriminators matter so a download never trips it: "Ok to send
  // data" (vsftpd) and "bytes sent in" (ftp client) are store-only, the inverse
  // of a RETR's "Opening ... for" / "bytes received in". This proves the FTP
  // root is writable (webroot-upload-to-webshell), the precise signal that move
  // wants instead of a bare "port 21 is open" gate.
  var _FTP_UPLOAD_INIT_RE = /(?:^|\s)STOR\b|\bftp>\s*(?:m?put)\b|^\s*(?:m?put)\s+\S|150\s+Ok to send data/im;
  var _FTP_UPLOAD_OK_RE = /226[\s-](?:Transfer complete|Transfer okay)|\bbytes sent in\b|\bUpload(?:ed|\s+complete)\b/i;
  // A directory listing returned over the FTP data channel (interactive `ftp> ls` / `dir`). Two row
  // shapes appear: the Windows IIS line "MM-DD-YY  HH:MMAM/PM  <size|<DIR>>  name" and the Unix long
  // listing "drwxr-xr-x  N owner group  size  Mon DD  (year|HH:MM)  name". Rows are only read inside an
  // FTP transfer context (the dispatcher gates this parser), so a stray date or permission line never
  // mints on its own.
  var _FTP_IIS_ROW_RE = /^\s*(?<date>\d{2}-\d{2}-\d{2})\s+\d{2}:\d{2}(?:AM|PM)\s+(?<size><DIR>|[\d,]+)\s+(?<name>\S.*?)\s*$/i;
  var _FTP_UNIX_ROW_RE = /^\s*(?<perm>[-dlbcps](?:[-rwxsStT]{9}))\s+\d+\s+\S+\s+\S+\s+(?<size>\d+)\s+\w{3}\s+\d{1,2}\s+(?:\d{4}|\d{1,2}:\d{2})\s+(?<name>\S.*?)\s*$/;

  function _parse_ftp_output(text, ws, command, source, facts) {
    var banners = [], loginSuccess = false;
    reAll(C._FTP_BANNER_RE, text).forEach(function (m) {
      var banner = (m.groups.banner || m.groups.login || '').trim();
      if (banner) banners.push(banner);
      if (m.groups.login) loginSuccess = true;
    });
    var writeOk = reSearch(_FTP_UPLOAD_INIT_RE, text) && reSearch(_FTP_UPLOAD_OK_RE, text);
    var hasFtpSession = !!(banners.length || loginSuccess || writeOk || /^\s*(?:ftp>|1(?:25|50)[ -](?:Data connection|Opening|Here comes the directory listing|Ok to send data|Transfer starting)|2(?:00|20|26|27|29|30)[ -]|331[ -]|Connected to\b)/im.test(text));
    var ftpFiles = [];
    text.split(/\r?\n/).forEach(function (line) {
      if (!hasFtpSession) return;
      var im = _FTP_IIS_ROW_RE.exec(line);
      if (im) {
        var inm = im.groups.name.trim();
        if (inm && inm !== '.' && inm !== '..') ftpFiles.push({ share: '', path: inm, size: im.groups.size === '<DIR>' ? '' : im.groups.size.replace(/,/g, '') });
        return;
      }
      var um = _FTP_UNIX_ROW_RE.exec(line);
      if (um) {
        var unm = um.groups.name.trim().replace(/[ \t]+->[ \t]+[^\r\n]*$/, '');
        if (unm && unm !== '.' && unm !== '..') ftpFiles.push({ share: '', path: unm, size: um.groups.size });
      }
    });
    if (!banners.length && !loginSuccess && !writeOk && !ftpFiles.length) return;
    var h = 'host:' + ws.target;
    C._add_os_from_text(text, ws, source, facts, 'ftp', 'medium', true);
    _add(facts, mkFact('ftp.reachable', h, { tool: 'ftp-client' }, S, source));
    if (banners.length) _add(facts, mkFact('ftp.banner', h, { banners: C.uniqueSortedCI(banners).slice(0, 10) }, S, source));
    var anonInText = /\bName\s*\([^)]*\):\s*(?:anonymous|ftp)\b|\bUSER\s+(?:anonymous|ftp)\b|331[\s-]+(?:Anonymous|Guest|Password required for anonymous)\b|230[\s-]+(?:Anonymous|Guest)\b|\bAnonymous FTP login allowed\b/i.test(text);
    var isAnon = /\banonymous\b/i.test(command) || anonInText;
    if (loginSuccess && isAnon) _add(facts, mkFact('ftp.anonymous_login', h, { tool: 'ftp-client' }, S, source));
    if (writeOk) _add(facts, mkFact('ftp.anon_write', h, { tool: 'ftp-client', anonymous: isAnon }, S, source));
    if (ftpFiles.length && C._emit_file_loot) C._emit_file_loot(facts, h, ftpFiles, 'ftp', 'ftp-listing', text, ws, source);
  }
  C._parse_ftp_output = _parse_ftp_output;

  // LanManager users table (enterprises.77.1.2.25.1.1.*): each STRING is a local/SMB account name -
  // the spray list an SNMP read hands you for free. A running-process command line
  // (hrSWRunParameters / hrSWRunName) may carry a password inline -> a candidate cred.
  var _SNMP_USER_RE = /(?:^|\D)77\.1\.2\.25\.1\.1[.\d]*\s*=\s*STRING:\s*"?(?<user>[^"\r\n]+?)"?\s*$/gim;
  var _SNMP_RUNPARAM_RE = /(?:hrSWRun(?:Parameters|Name)|(?:iso|\.?1)\.3\.6\.1\.2\.1\.25\.4\.2\.1\.[45])[.\d]*\s*=\s*STRING:\s*"?(?<val>[^"\r\n]+)/gi;
  var _SNMP_PROC_PW_RE = /(?:-p|--password|--pass|pwd|passwd)[=\s]+['"]?(?<pw>[^\s'"]{3,})/i;
  var _SNMP_PROC_USER_RE = /(?:-u|--user(?:name)?)[=\s]+['"]?(?<user>[^\s'"]{2,})/i;
  var _ONESIXTYONE_RE = /^\s*\d{1,3}(?:\.\d{1,3}){3}\s+\[(?<community>[A-Za-z0-9_.\-@!$%^&+=]{1,64})\]\s+(?<description>\S[^\r\n]*)/m;

  function _parse_snmp_output(text, ws, command, source, facts) {
    var lowered = text.toLowerCase();
    var hasMibLines = /(?:snmpv2-mib|host-resources-mib|if-mib|ip-mib|tcp-mib|udp-mib|iso\.3\.6\.1|\.1\.3\.6\.1)[^\r\n]{0,120}=\s*(?:string|integer|oid|ipaddress|timeticks|counter\d*|gauge\d*|hex-string|bits):/i.test(text) || _ONESIXTYONE_RE.test(text);
    if (!hasMibLines && ['timeout', 'no response from', 'authorizationerror', 'authentication failure'].some(function (m) { return lowered.indexOf(m) >= 0; })) return;
    if (lowered.indexOf('snmpv2-mib::') < 0 && lowered.indexOf('= string:') < 0
        && lowered.indexOf('iso.3.6.1') < 0 && text.indexOf('.1.3.6.1') < 0
        && !_ONESIXTYONE_RE.test(text)) return;
    var h = 'host:' + ws.target, value = {};
    [['description', C._SNMP_SYSDESCR_RE], ['name', C._SNMP_SYSNAME_RE], ['location', C._SNMP_SYSLOCATION_RE], ['contact', C._SNMP_SYSCONTACT_RE]].forEach(function (pair) {
      var m = reSearch(pair[1], text);
      if (m) value[pair[0]] = C.stripChars(m.groups.value.trim(), '"');
    });
    var community = C._command_arg(command, ['-c', '--community']);
    if (!community) {
      var one = _ONESIXTYONE_RE.exec(text);
      if (one) {
        community = one.groups.community.trim();
        if (value.description === undefined) value.description = one.groups.description.trim();
      }
    }
    if (community) _add(facts, mkFact('snmp.community', h, { community: community }, S, source));
    _add(facts, mkFact('snmp.reachable', h, { tool: 'snmp' }, S, source));

    // the LanMan users table hands you a spray list; a running-process command line may carry a secret
    var users = [];
    reAll(_SNMP_USER_RE, text).forEach(function (m) {
      var u = m.groups.user.trim();
      if (u && users.indexOf(u) < 0 && u.length >= 1 && u.length <= 64) users.push(u);
    });
    if (users.length) _add(facts, mkFact('ad.user_list', h, { users: users, count: users.length, method: 'snmp' }, S, source));
    var seenPw = {};
    reAll(_SNMP_RUNPARAM_RE, text).forEach(function (m) {
      var pw = reSearch(_SNMP_PROC_PW_RE, m.groups.val);
      if (!pw) return;
      var secret = pw.groups.pw;
      if (seenPw[secret] || ['password', 'changeme', 'null'].indexOf(secret.toLowerCase()) >= 0) return;
      seenPw[secret] = true;
      var cred = { password: secret, via: 'snmp-process' };
      var um = reSearch(_SNMP_PROC_USER_RE, m.groups.val);
      if (um) cred.user = um.groups.user;
      _add(facts, mkFact('credential.candidate', h, cred, S, source));
    });

    if (Object.keys(value).length) {
      _add(facts, mkFact('snmp.info', h, value, S, source));
      C._add_os_from_text(Object.keys(value).map(function (k) { return String(value[k]); }).join('\n'), ws, source, facts, 'snmp', 'high', true);
      if (value.name) _add(facts, mkFact('host.hostname', h, { name: value.name }, S, source));
    }
  }
  C._parse_snmp_output = _parse_snmp_output;

  // SQLite dump (`sqlite3 <db> .dump`) -> credential.candidate. The TERMINAL path's mirror of the
  // native ingest_sqlite reader: obol types `curl ... && sqlite3 db .dump`, and the captured
  // INSERT/CREATE-TABLE stream is parsed here so a leaked app store still yields logins.
  var _SQLD_CREATE_RE = /CREATE TABLE\s+["`\[]?(?<t>\w+)["`\]]?\s*\((?<cols>[^\r\n]{1,4000})\)/gi;
  var _SQLD_INSERT_RE = /INSERT INTO\s+["`\[]?(?<t>\w+)["`\]]?\s*(?:\([^)\r\n]{0,1000}\))?\s*VALUES\s*\((?<vals>[^\r\n]{1,4000})\)\s*;/gi;
  var _SQLD_USER_COL = /^(?:user(?:name)?|uname|login|email|account|name|admin)$/i;
  var _SQLD_SECRET_COL = /^(?:pass(?:word|wd)?|pwd|secret|hash|passhash|pw)$/i;
  var _SQLD_HASH_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{56}|[0-9a-f]{64}|[0-9a-f]{128}|\$(?:2[aby]|1|5|6|y)\$[^\s]+)$/i;

  function _sqld_split(blob) {
    // Split one SQL VALUES(...) tuple into its top-level tokens, honoring `'…''…'` quoting.
    var out = [], cur = '', inStr = false, i = 0, n = blob.length;
    while (i < n) {
      var c = blob[i];
      if (inStr) {
        if (c === "'") {
          if (i + 1 < n && blob[i + 1] === "'") { cur += "'"; i += 2; continue; }
          inStr = false;
        } else { cur += c; }
        i += 1;
        continue;
      }
      if (c === "'") inStr = true;
      else if (c === ',') { out.push(cur.trim()); cur = ''; }
      else cur += c;
      i += 1;
    }
    out.push(cur.trim());
    return out;
  }
  C._sqld_split = _sqld_split;

  function _strip_col_quotes(s) { return C.stripChars(s, '"`[]'); }

  function _parse_sqlite_dump(text, ws, source, facts) {
    var colsByTable = {};
    reAll(_SQLD_CREATE_RE, text).forEach(function (m) {
      var names = _sqld_split(m.groups.cols).filter(function (seg) { return seg.trim(); }).map(function (seg) {
        var first = (_strip_col_quotes(seg.trim()).trim().split(/\s+/)[0] || '');
        return _strip_col_quotes(first);
      });
      colsByTable[m.groups.t.toLowerCase()] = names;
    });
    var seen = {};
    reAll(_SQLD_INSERT_RE, text).forEach(function (m) {
      var table = m.groups.t.toLowerCase();
      var cols = colsByTable[table];
      var vals = _sqld_split(m.groups.vals);
      if (!cols || cols.length !== vals.length) return;
      var row = {};
      for (var i = 0; i < cols.length; i++) row[cols[i]] = vals[i];
      var userCols = cols.filter(function (c) { return _SQLD_USER_COL.test(c); });
      var secretCols = cols.filter(function (c) { return _SQLD_SECRET_COL.test(c); });
      secretCols.forEach(function (sc) {
        var secret = (row[sc] || '').trim();
        if (!secret || secret.toUpperCase() === 'NULL' || secret.length > 4096) return;
        var user = '';
        for (var j = 0; j < userCols.length; j++) { var v = (row[userCols[j]] || '').trim(); if (v) { user = v; break; } }
        var cred = { via: 'exposed-sqlite', table: table };
        if (user) cred.user = user.slice(0, 128);
        if (_SQLD_HASH_RE.test(secret)) cred.hash = secret;
        else cred.password = secret;
        var fp = (cred.user || '') + '|' + (cred.hash || cred.password);
        if (seen[fp]) return;
        seen[fp] = true;
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, cred, S, source));
      });
    });
  }
  C._parse_sqlite_dump = _parse_sqlite_dump;

  function _parse_rsync_nfs(text, ws, command, source, facts) {
    if (!text) return;
    var h = 'host:' + ws.target;
    var lc = String(command || '').toLowerCase();
    if (/\brsync\b/.test(lc) && !/connection refused|failed to connect|timed out|@ERROR:/i.test(text)) {
      if (/^[drwxlst-]{10}\s+[\d,]+\s+\d{4}\/\d{2}\/\d{2}|^\s*[A-Za-z0-9_.-]+\s{2,}\S/m.test(text)) {
        _add(facts, mkFact('rsync.reachable', h, { port: 873, tool: 'rsync' }, S, source));
      }
    }
    if ((/\bshowmount\b/.test(lc) || /^Export list for\s+\S+:/im.test(text) || /^NFS\s+\d{1,3}(?:\.\d{1,3}){3}\s+2049\b/im.test(text)) && !/clnt_create:\s*RPC|connection refused|timed out/i.test(text)) {
      _add(facts, mkFact('nfs.reachable', h, { port: 2049, tool: 'showmount' }, S, source));
    }
  }
  C._parse_rsync_nfs = _parse_rsync_nfs;

})(typeof globalThis !== 'undefined' ? globalThis : this);
