/*!
 * obol engine — parsers/services.js
 * Faithful JS port of obol-local/obol/parsers/services.py.
 * Generic service metadata: HTTP, SSH, FTP, SNMP — reachability/fingerprints only.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  function _parse_http_metadata(text, ws, source, facts) {
    var h = 'host:' + ws.target;
    C._add_os_from_text(text, ws, source, facts, 'http', 'medium', false);
    var statusValues = [];
    reAll(C._HTTP_STATUS_RE, text).forEach(function (m) {
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
    reAll(C._WHATWEB_PLUGIN_RE, text).forEach(function (m) {
      var name = m.groups.name.trim(), value = m.groups.value.trim();
      var nl = name.toLowerCase();
      if (['title', 'ip', 'country', 'email', 'summary'].indexOf(nl) >= 0) return;
      if (nl === 'httpserver' || nl === 'server') servers[value] = true;
      else tech.push({ name: name, value: value });
    });
    var titleMatch = /\bTitle\[(?<title>[^\]\r\n]+)\]/.exec(text);
    if (titleMatch && titleMatch.groups.title.trim()) _add(facts, mkFact('web.title', h, { titles: [titleMatch.groups.title.trim()] }, S, source));
    if (Object.keys(servers).length) _add(facts, mkFact('web.server', h, { headers: C.uniqueSortedCI(Object.keys(servers)).slice(0, 10) }, S, source));
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
    C._add_os_from_text(banners.join('\n'), ws, source, facts, 'ssh', 'medium', false);
    _add(facts, mkFact('ssh.reachable', 'host:' + ws.target, { tool: 'banner' }, S, source));
    _add(facts, mkFact('ssh.banner', 'host:' + ws.target, { banners: banners.slice(0, 10) }, S, source));
  }
  C._parse_ssh_banner = _parse_ssh_banner;

  function _parse_ftp_output(text, ws, command, source, facts) {
    var banners = [], loginSuccess = false;
    reAll(C._FTP_BANNER_RE, text).forEach(function (m) {
      var banner = (m.groups.banner || m.groups.login || '').trim();
      if (banner) banners.push(banner);
      if (m.groups.login) loginSuccess = true;
    });
    if (!banners.length && !loginSuccess) return;
    var h = 'host:' + ws.target;
    _add(facts, mkFact('ftp.reachable', h, { tool: 'ftp-client' }, S, source));
    if (banners.length) _add(facts, mkFact('ftp.banner', h, { banners: C.uniqueSortedCI(banners).slice(0, 10) }, S, source));
    if (loginSuccess && /\banonymous\b/i.test(command)) _add(facts, mkFact('ftp.anonymous_login', h, { tool: 'ftp-client' }, S, source));
  }
  C._parse_ftp_output = _parse_ftp_output;

  // LanManager users table (enterprises.77.1.2.25.1.1.*): each STRING is a local/SMB account name —
  // the spray list an SNMP read hands you for free. A running-process command line
  // (hrSWRunParameters / hrSWRunName) may carry a password inline → a candidate cred.
  var _SNMP_USER_RE = /(?:^|\D)77\.1\.2\.25\.1\.1[.\d]*\s*=\s*STRING:\s*"?(?<user>[^"\r\n]+?)"?\s*$/gim;
  var _SNMP_RUNPARAM_RE = /hrSWRun(?:Parameters|Name)[.\d]*\s*=\s*STRING:\s*"?(?<val>[^"\r\n]+)/gi;
  var _SNMP_PROC_PW_RE = /(?:-p|--password|--pass|pwd|passwd)[=\s]+['"]?(?<pw>[^\s'"]{3,})/i;
  var _SNMP_PROC_USER_RE = /(?:-u|--user(?:name)?)[=\s]+['"]?(?<user>[^\s'"]{2,})/i;

  function _parse_snmp_output(text, ws, command, source, facts) {
    var lowered = text.toLowerCase();
    if (['timeout', 'no response from', 'authorizationerror', 'authentication failure'].some(function (m) { return lowered.indexOf(m) >= 0; })) return;
    if (lowered.indexOf('snmpv2-mib::') < 0 && lowered.indexOf('= string:') < 0
        && lowered.indexOf('iso.3.6.1') < 0 && text.indexOf('.1.3.6.1') < 0
        && !/\[[^\]]+\]\s+\S/.test(text)) return;
    var h = 'host:' + ws.target, value = {};
    [['description', C._SNMP_SYSDESCR_RE], ['name', C._SNMP_SYSNAME_RE], ['location', C._SNMP_SYSLOCATION_RE], ['contact', C._SNMP_SYSCONTACT_RE]].forEach(function (pair) {
      var m = reSearch(pair[1], text);
      if (m) value[pair[0]] = C.stripChars(m.groups.value.trim(), '"');
    });
    var community = C._command_arg(command, ['-c', '--community']);
    if (!community) {
      var one = /\[(?<community>[^\]]+)\]\s+(?<description>.+)/.exec(text);
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

  // SQLite dump (`sqlite3 <db> .dump`) → credential.candidate. The TERMINAL path's mirror of the
  // native ingest_sqlite reader: obol types `curl … && sqlite3 db .dump`, and the captured
  // INSERT/CREATE-TABLE stream is parsed here so a leaked app store still yields logins.
  var _SQLD_CREATE_RE = /CREATE TABLE\s+["`\[]?(?<t>\w+)["`\]]?\s*\((?<cols>.+)\)/gi;
  var _SQLD_INSERT_RE = /INSERT INTO\s+["`\[]?(?<t>\w+)["`\]]?\s*(?:\([^)]*\))?\s*VALUES\s*\((?<vals>.+)\)\s*;/gi;
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

})(typeof globalThis !== 'undefined' ? globalThis : this);
