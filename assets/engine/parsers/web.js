/*!
 * obol engine — parsers/web.js
 * Faithful JS port of the fixture-reachable parsers in obol-local/obol/parsers/web.py:
 * wpscan, content discovery, git source, sqlmap, and the manual web-exploitation success
 * signals (LFI/XXE, cmdi/SSTI/deser/jenkins, SQLi, SSRF/IMDS, NoSQLi, JWT, IDOR, XSS).
 * None of the exploit signals promote to a foothold, shell, or validated credential.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  function _parse_wpscan(text, ws, source, facts) {
    var h = 'host:' + ws.target;
    var section = reSearch(C._WPSCAN_USER_SECTION_RE, text);
    var users = [];
    if (section) {
      reAll(C._WPSCAN_USER_RE, section[0]).forEach(function (m) {
        var u = m.groups.u.trim();
        if (C._valid_username(u) && ['finished', 'requests'].indexOf(u.toLowerCase()) < 0) users.push(u);
      });
    }
    var seen = {}, uu = [];
    users.forEach(function (u) { if (!seen[u]) { seen[u] = true; uu.push(u); } });
    if (uu.length) _add(facts, mkFact('web.users', h, { users: uu, count: uu.length, tool: 'wpscan' }, S, source));
    var version = reSearch(C._WPSCAN_VERSION_RE, text);
    reAll(C._WPSCAN_VULN_RE, text).forEach(function (m) {
      var title = m.groups.t.trim().slice(0, 160);
      if (!title) return;
      var val = { key: 'wordpress', name: title, source: 'wpscan (candidate lead, not confirmed)' };
      if (version) val.version = version.groups.v;
      _add(facts, mkFact('exploit.candidate', h, val, S, 'wpscan finding — candidate lead, not confirmed (' + source + ')'));
    });
    reAll(C._WPSCAN_LOGIN_RE, text).forEach(function (m) {
      _add(facts, mkFact('credential.candidate', h, { kind: 'wordpress_login', user: m.groups.u.trim(), password: m.groups.p.trim(), via: 'wpscan' }, S, source));
    });
  }
  C._parse_wpscan = _parse_wpscan;

  function _parse_web_content(text, ws, source, facts) {
    var paths = {};
    reAll(C._WEB_GOBUSTER_RE, text).forEach(function (m) { if (m.groups.code !== '404') paths[m.groups.path] = true; });
    reAll(C._WEB_FEROX_RE, text).forEach(function (m) { if (m.groups.code !== '404') paths[C._url_path(m.groups.url)] = true; });
    reAll(C._WEB_DIRB_RE, text).forEach(function (m) { if (m.groups.code !== '404') paths[C._url_path(m.groups.url)] = true; });
    reAll(C._WEB_FFUF_RE, text).forEach(function (m) {
      var token = m.groups.token;
      if (m.groups.code === '404' || token[0] === ':' || token.toLowerCase() === 'status') return;
      paths[token[0] === '/' ? token : '/' + token] = true;
    });
    reAll(C._WEB_WFUZZ_RE, text).forEach(function (m) {
      if (m.groups.code === '404') return;
      var payload = m.groups.payload.trim();
      if (payload) paths[payload[0] === '/' ? payload : '/' + payload] = true;
    });
    var keys = Object.keys(paths).filter(function (p) { return p && p.toLowerCase().indexOf('http') !== 0; });
    if (!keys.length) return;
    var ordered = C.uniqueSortedCI(keys);
    var value = { paths: ordered.slice(0, 50), count: ordered.length };
    var interesting = ordered.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
    if (interesting.length) value.interesting = interesting.slice(0, 20);
    _add(facts, mkFact('web.content_map', 'host:' + ws.target, value, S, source));
  }
  C._parse_web_content = _parse_web_content;

  var _PARAM_URL_RE = /[?&][A-Za-z_][\w.]*=/;
  var _FORM_INPUT_RE = /<input\b[^>]*\bname\s*=/i;
  var _UPLOAD_FORM_RE = /type\s*=\s*["']?\s*file\b|enctype\s*=\s*["']?\s*multipart\/form-data/i;

  function _parse_web_surface(text, ws, command, source, facts) {
    var t = text || '', h = 'host:' + ws.target;
    if (reSearch(_PARAM_URL_RE, t) || reSearch(_FORM_INPUT_RE, t) || reSearch(_PARAM_URL_RE, command || '')) _add(facts, mkFact('web.parameterized', h, { evidence: 'parameter or form input observed' }, S, source));
    if (reSearch(_UPLOAD_FORM_RE, t)) _add(facts, mkFact('web.upload_form', h, { evidence: 'file-upload form' }, S, source));
  }
  C._parse_web_surface = _parse_web_surface;

  function _secret_snippets(text) {
    var snippets = [], seen = {};
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line || line.length > 260) return;
      var m = reSearch(C._SOURCE_SECRET_RE, line);
      if (!m) return;
      var key = m.groups.key.toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      snippets.push({ key: key, line: line.slice(0, 220) });
    });
    return snippets;
  }
  C._secret_snippets = _secret_snippets;

  function _parse_git_source(text, ws, command, source, facts) {
    var branch = '';
    var head = reSearch(C._GIT_HEAD_RE, text);
    if (head) branch = head.groups.branch;
    var lc = command.toLowerCase();
    var sourceFound = !!head || (lc.indexOf('git-dumper') >= 0 && reSearch(C._GIT_DUMPER_SUCCESS_RE, text) && !/\b(?:error|failed|not found|403|404)\b/i.test(text));
    if (sourceFound) {
      var value = { kind: 'git', tool: lc.indexOf('git-dumper') >= 0 ? 'git-dumper' : 'curl' };
      if (branch) value.branch = branch;
      _add(facts, mkFact('web.source', 'host:' + ws.target, value, S, source));
    }
    var secrets = _secret_snippets(text);
    if (secrets.length) _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'source_secret', count: secrets.length, secrets: secrets.slice(0, 20) }, S, source));
  }
  C._parse_git_source = _parse_git_source;

  function _parse_sqlmap(text, ws, source, facts) {
    if (!text.trim()) return;
    var h = 'host:' + ws.target;
    var vuln = reSearch(C._SQLMAP_VULN_RE, text);
    if (vuln) _add(facts, mkFact('web.sqli_confirmed', h, { tool: 'sqlmap', evidence: C._line_for_match(text, vuln) }, S, source));
    var dbms = '';
    var dbmsMatch = reSearch(C._SQLMAP_DBMS_RE, text);
    if (dbmsMatch) dbms = dbmsMatch.groups.dbms.trim();
    var databaseNames = [];
    if (reSearch(C._SQLMAP_DATABASE_HEADER_RE, text)) {
      var set = {};
      reAll(C._SQLMAP_STAR_ROW_RE, text).forEach(function (m) {
        var n = m.groups.name;
        if (['available', 'database', 'databases'].indexOf(n.toLowerCase()) < 0) set[n] = true;
      });
      databaseNames = C.uniqueSortedCI(Object.keys(set));
    }
    if (databaseNames.length || dbms) {
      var value = { tool: 'sqlmap' };
      if (dbms) value.dbms = dbms;
      if (databaseNames.length) { value.databases = databaseNames.slice(0, 50); value.count = databaseNames.length; }
      _add(facts, mkFact('db.databases', h, value, S, source));
    }
    var tableRefs = reAll(C._SQLMAP_TABLE_RE, text).map(function (m) { return { database: m.groups.database, table: m.groups.table }; });
    if (tableRefs.length) _add(facts, mkFact('db.tables', h, { tool: 'sqlmap', tables: tableRefs.slice(0, 50) }, S, source));
    var colSet = {};
    reAll(/\b(user(?:name)?|login|email|pass(?:word)?|passwd|pwd|hash|token|api[_-]?key)\b/i, text).forEach(function (m) { colSet[m[1].toLowerCase()] = true; });
    var credentialColumns = C.uniqueSortedCI(Object.keys(colSet));
    if (credentialColumns.length && (reSearch(C._SQLMAP_DUMP_RE, text) || text.toLowerCase().indexOf('dump') >= 0 || tableRefs.length)) {
      var v2 = { tool: 'sqlmap', credential_columns: credentialColumns.slice(0, 20) };
      if (tableRefs.length) v2.tables = tableRefs.slice(0, 20);
      _add(facts, mkFact('db.creds', h, v2, S, source));
      _add(facts, mkFact('credential.candidate', h, { kind: 'database_dump_secret', count: credentialColumns.length, sources: credentialColumns.slice(0, 20) }, S, source));
    }
    var shell = reSearch(C._SQLMAP_OS_SHELL_RE, text);
    if (shell) _add(facts, mkFact('foothold.webshell', h, { tool: 'sqlmap', method: 'os-shell', evidence: C._line_for_match(text, shell) }, S, source));
  }
  C._parse_sqlmap = _parse_sqlmap;

  var _IDOR_FFUF_HIT_RE = /Status:\s*200,\s*Size:\s*(?<size>\d+)/;
  var _IDOR_JSON_ID_RE = /"(?:id|user_?id|account_?id)"\s*:\s*"?(?<id>\d{1,10})"?/;

  function _parse_web_idor(text, ws, source, facts) {
    var h = 'host:' + ws.target;
    var sizes = {};
    reAll(_IDOR_FFUF_HIT_RE, text).forEach(function (m) { sizes[m.groups.size] = true; });
    if (Object.keys(sizes).length >= 2) {
      _add(facts, mkFact('web.idor_candidate', h, { via: 'ffuf', distinct_responses: Object.keys(sizes).length, evidence: 'multiple 200s with differing response sizes across object ids' }, S, source));
      return;
    }
    var ids = {};
    reAll(_IDOR_JSON_ID_RE, text).forEach(function (m) { ids[m.groups.id] = true; });
    var status200 = reAll(/HTTP\/[\d.]+\s+200/, text).length;
    if (Object.keys(ids).length >= 2 && status200 >= 2) {
      _add(facts, mkFact('web.idor_candidate', h, { via: 'curl', distinct_records: Object.keys(ids).length, evidence: 'distinct object records returned across ids' }, S, source));
    }
  }
  C._parse_web_idor = _parse_web_idor;

  function _parse_web_xss(text, ws, source, facts) {
    var low = text.toLowerCase();
    var hit = '', kind = 'reflected';
    if (low.indexOf('xssprobe') >= 0) hit = 'reflected probe marker';
    else if (/<script[^>]*>[^<]*alert\s*\(/.test(low) || /<svg[^>]*\son(?:load|error)\s*=/.test(low) || /<img[^>]*\sonerror\s*=\s*["']?alert/.test(low)) hit = 'reflected script/event-handler payload';
    else if (/<script[^>]*>[^<]*document\.(?:cookie|location)/.test(low) || /<script[^>]*>[^<]*new\s+image\(\)\.src/.test(low)) { hit = 'stored script exfiltrating document.cookie'; kind = 'stored'; }
    if (!hit) return;
    _add(facts, mkFact('web.xss_confirmed', 'host:' + ws.target, { kind: kind, evidence: hit }, S, source));
  }
  C._parse_web_xss = _parse_web_xss;

  function _php_filter_source(text) {
    var tokens = reAll(C._B64_TOKEN_RE, text).map(function (m) { return m[0]; });
    tokens.sort(function (a, b) { return b.length - a.length; });
    for (var i = 0; i < tokens.length; i++) {
      var tok = tokens[i];
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(tok)) continue;
      var decoded = C.b64decode(tok);
      if (decoded && (decoded.indexOf('<?php') >= 0 || decoded.indexOf('<?=') >= 0)) return decoded;
    }
    return '';
  }
  C._php_filter_source = _php_filter_source;

  function _parse_web_lfi(actionId, text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var method = actionId === 'xxe' ? 'xxe' : 'path_traversal';
    var filesRead = [], osFamily = '';
    var passwdHead = reSearch(C._LFI_PASSWD_RE, text);
    if (passwdHead && reSearch(C._LFI_PASSWD_SECOND_RE, text)) {
      osFamily = 'linux';
      filesRead.push('/etc/passwd');
      if (actionId === 'lfi-probe') _add(facts, mkFact('web.lfi_confirmed', h, { file: '/etc/passwd', os: 'linux', method: method, evidence: C._line_for_match(text, passwdHead) }, S, source));
    }
    var win = reSearch(C._LFI_WIN_INI_RE, text);
    if (win) {
      osFamily = osFamily || 'windows';
      var param = reSearch(C._LFI_FILE_PARAM_RE, command);
      var winFile = param ? param.groups.path : 'windows_system_file';
      filesRead.push(winFile);
      if (actionId === 'lfi-probe') _add(facts, mkFact('web.lfi_confirmed', h, { file: winFile, os: 'windows', method: method, evidence: C._line_for_match(text, win) }, S, source));
    }
    var lc = command.toLowerCase();
    if (lc.indexOf('php://filter') >= 0 || lc.indexOf('convert.base64') >= 0) {
      var decoded = _php_filter_source(text);
      if (decoded) {
        var p2 = reSearch(C._LFI_FILE_PARAM_RE, command);
        var resource = p2 ? p2.groups.path : 'php_source';
        filesRead.push(resource);
        if (actionId === 'lfi-probe') _add(facts, mkFact('web.lfi_confirmed', h, { file: resource, method: 'php_filter', kind: 'php_source' }, S, source));
        _add(facts, mkFact('web.source', h, { kind: 'php', via: method }, S, source));
      }
    }
    if (filesRead.length) {
      var uniq = C.uniqueSortedCI(filesRead);
      _add(facts, mkFact('loot.files', h, { files: uniq, via: method, tool: 'web' }, S, source));
      if (actionId === 'xxe') _add(facts, mkFact('web.xxe_confirmed', h, { files: uniq, evidence: passwdHead ? C._line_for_match(text, passwdHead) : 'file content returned' }, S, source));
    }
    if (osFamily) C._add_os_observation(facts, ws, source, osFamily, (passwdHead || win) ? C._line_for_match(text, passwdHead || win) : osFamily, 'medium', 'web-' + actionId, false);
  }
  C._parse_web_lfi = _parse_web_lfi;

  function _parse_web_cmdi(actionId, text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var method = { 'command-injection': 'os_command_injection', ssti: 'template_injection', 'web-shells': 'web_shell', 'file-upload': 'uploaded_web_shell', deserialization: 'insecure_deserialization', 'tomcat-deploy': 'tomcat_war_deploy', 'jenkins-access': 'jenkins_script_console' }[actionId] || actionId;
    var uid = reSearch(C._CMDI_UID_RE, text);
    var win = reSearch(C._CMDI_WIN_RE, text);
    if (!uid && !win) return;
    var osFamily = uid ? 'linux' : 'windows';
    var evidence = C._line_for_match(text, uid || win);
    _add(facts, mkFact('web.cmdi_confirmed', h, { os: osFamily, method: method, evidence: evidence }, S, source));
    if (method === 'template_injection') _add(facts, mkFact('web.ssti_confirmed', h, { method: 'template_injection', evidence: evidence }, S, source));
    else if (method === 'insecure_deserialization') _add(facts, mkFact('web.deserial_confirmed', h, { method: 'insecure_deserialization', evidence: evidence }, S, source));
    if (actionId === 'file-upload') _add(facts, mkFact('web.upload_confirmed', h, { method: 'executable_upload', evidence: evidence }, S, source));
    C._add_os_observation(facts, ws, source, osFamily, evidence, 'medium', 'web-' + actionId, false);
  }
  C._parse_web_cmdi = _parse_web_cmdi;

  function _sql_dbms_from_error(text) {
    var l = text.toLowerCase();
    if (l.indexOf('mariadb') >= 0) return 'MariaDB';
    if (l.indexOf('mysql') >= 0 || l.indexOf('mysqli') >= 0) return 'MySQL';
    if (/\bORA-\d{5}\b/.test(text)) return 'Oracle';
    if (l.indexOf('postgresql') >= 0 || l.indexOf('pg_query') >= 0 || l.indexOf('pg_exec') >= 0) return 'PostgreSQL';
    if (l.indexOf('sql server') >= 0 || l.indexOf('system.data.sqlclient') >= 0 || l.indexOf('incorrect syntax near') >= 0) return 'Microsoft SQL Server';
    if (l.indexOf('sqlite') >= 0) return 'SQLite';
    return '';
  }
  C._sql_dbms_from_error = _sql_dbms_from_error;

  function _parse_web_sqli_manual(text, ws, source, facts) {
    var h = 'host:' + ws.target;
    var match = reSearch(C._SQL_ERROR_RE, text);
    if (match) {
      var value = { tool: 'manual', method: 'error_based', evidence: C._line_for_match(text, match) };
      var dbms = _sql_dbms_from_error(text);
      if (dbms) value.dbms = dbms;
      _add(facts, mkFact('web.sqli_confirmed', h, value, S, source));
      return;
    }
    if (/union\s+select/i.test(text)) {
      var ver = reSearch(C._SQL_VERSION_BANNER_RE, text);
      if (ver) _add(facts, mkFact('web.sqli_confirmed', h, { tool: 'manual', method: 'union_based', dbms: ver[0], evidence: C._line_for_match(text, ver) }, S, source));
    }
  }
  C._parse_web_sqli_manual = _parse_web_sqli_manual;

  var _INTERNAL_TARGET_RE = /(?:127\.0\.0\.1|localhost|\[::1\]|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b)/i;
  var _URL_CRED_RE = /:\/\/(?<u>[^:/@\s]{1,64}):(?<p>[^@/\s]{3,})@/;
  var _RESP_USER_RE = /['"]?(?:user(?:name)?|login|db_?user)['"]?\s*[:=]\s*['"]?(?<u>[\w.@\-]{2,64})/i;
  var _RESP_PASS_RE = /['"]?(?:pass(?:word|wd)?|secret|db_?pass|api[_-]?key|token)['"]?\s*[:=]\s*['"]?(?<p>[^\s'",}]{4,})/i;
  var _RESP_CRED_STOPWORDS = ['true', 'false', 'null', 'none', 'changeme', 'password', 'example', 'string'];

  function _looks_like_api_response(text) {
    var t = (text || '').trim();
    if (!t) return false;
    if (t[0] === '{' || t[0] === '[') return true;
    if (t.toLowerCase().indexOf('application/json') >= 0) return true;
    return reAll(/"[\w.\-]+"\s*:/, t).length >= 2;
  }
  C._looks_like_api_response = _looks_like_api_response;

  function _mine_response_credentials(text) {
    text = text || '';
    var out = [], seen = {};
    reAll(_URL_CRED_RE, text).forEach(function (m) {
      var key = m.groups.u + '|' + m.groups.p;
      if (!seen[key]) { seen[key] = true; out.push({ user: m.groups.u, password: m.groups.p }); }
    });
    var um = reSearch(_RESP_USER_RE, text);
    var docUser = um ? um.groups.u : '';
    reAll(_RESP_PASS_RE, text).forEach(function (m) {
      var pw = m.groups.p;
      if (_RESP_CRED_STOPWORDS.indexOf(pw.toLowerCase()) >= 0) return;
      var cred = { password: pw };
      if (docUser) cred.user = docUser;
      var key = (cred.user || '') + '|' + pw;
      if (!seen[key]) { seen[key] = true; out.push(cred); }
    });
    return out.slice(0, 10);
  }
  C._mine_response_credentials = _mine_response_credentials;

  function _parse_web_ssrf(actionId, text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var imds = reSearch(C._IMDS_MARKER_RE, text);
    var akid = reSearch(C._AWS_KEY_RE, text);
    var secret = reSearch(C._AWS_SECRET_RE, text);
    var internal = reSearch(_INTERNAL_TARGET_RE, command || '');
    var method = actionId === 'xxe' ? 'xxe' : 'ssrf';
    var mined = _mine_response_credentials(text);
    var confirmed = false;
    if (imds || akid) {
      _add(facts, mkFact('web.ssrf_confirmed', h, { method: method, target: 'cloud_metadata', evidence: C._line_for_match(text, imds || akid) }, S, source));
      confirmed = true;
    } else if (internal && (mined.length || _looks_like_api_response(text))) {
      _add(facts, mkFact('web.ssrf_confirmed', h, { method: method, target: 'internal_service', evidence: internal[0] }, S, source));
      confirmed = true;
    }
    if (!confirmed) return;
    if (akid && secret) {
      var cred = { kind: 'aws_sts_credentials', access_key_id: akid.groups.akid, secret_access_key: secret.groups.secret, via: method };
      var token = reSearch(C._AWS_TOKEN_RE, text);
      if (token) cred.session_token = token.groups.token;
      _add(facts, mkFact('credential.candidate', h, cred, S, source));
    }
    mined.forEach(function (cred) {
      var v = {};
      Object.keys(cred).forEach(function (k) { v[k] = cred[k]; });
      v.source = method + '-response';
      _add(facts, mkFact('credential.candidate', h, v, S, source));
    });
  }
  C._parse_web_ssrf = _parse_web_ssrf;

  function _parse_web_nosqli(text, ws, command, source, facts) {
    if (!reSearch(C._NOSQL_OP_RE, command)) return;
    var success = reSearch(C._NOSQL_SUCCESS_RE, text);
    var redirect = reSearch(C._LOGIN_REDIRECT_RE, text);
    var cookie = reSearch(C._SET_COOKIE_SESSION_RE, text);
    var evidence;
    if (success) evidence = C._line_for_match(text, success);
    else if (redirect && cookie) evidence = C._line_for_match(text, redirect);
    else return;
    _add(facts, mkFact('web.nosqli_confirmed', 'host:' + ws.target, { method: 'operator_injection', vector: 'authentication_bypass', evidence: evidence }, S, source));
  }
  C._parse_web_nosqli = _parse_web_nosqli;

  function _parse_web_jwt(text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var secret = '';
    var key = reSearch(C._JWT_TOOL_KEY_RE, text);
    if (key) secret = key.groups.secret || key.groups.secret2 || '';
    if (!secret) {
      var cracked = reSearch(C._JWT_HASHCAT_RE, text);
      if (cracked) secret = cracked.groups.secret;
    }
    if (secret) {
      _add(facts, mkFact('web.jwt_secret', h, { secret: secret, algorithm: 'HMAC', tool: 'jwt-crack' }, S, source));
      _add(facts, mkFact('credential.candidate', h, { kind: 'jwt_signing_secret', secret: secret }, S, source));
    }
    var forged = reSearch(C._JWT_FORGE_RE, command) || reSearch(C._JWT_FORGE_RE, text);
    var accepted = reSearch(C._WEB_AUTHZ_SUCCESS_RE, text);
    if (forged && accepted) _add(facts, mkFact('web.authz_bypass', h, { method: 'jwt', vector: 'forged_token', evidence: C._line_for_match(text, accepted) }, S, source));
  }
  C._parse_web_jwt = _parse_web_jwt;

  function _parse_web_exploit_output(actionId, text, ws, command, source, facts) {
    if (!text.trim()) return;
    if (C._WEB_LFI_ACTION_IDS.has(actionId)) _parse_web_lfi(actionId, text, ws, command, source, facts);
    if (C._WEB_CMDI_ACTION_IDS.has(actionId)) _parse_web_cmdi(actionId, text, ws, command, source, facts);
    if (C._WEB_SQLI_ACTION_IDS.has(actionId)) _parse_web_sqli_manual(text, ws, source, facts);
    if (C._WEB_SSRF_ACTION_IDS.has(actionId)) _parse_web_ssrf(actionId, text, ws, command, source, facts);
    if (C._WEB_NOSQLI_ACTION_IDS.has(actionId)) _parse_web_nosqli(text, ws, command, source, facts);
    if (C._WEB_JWT_ACTION_IDS.has(actionId)) _parse_web_jwt(text, ws, command, source, facts);
    if (C._WEB_XSS_ACTION_IDS.has(actionId)) _parse_web_xss(text, ws, source, facts);
    if (C._WEB_IDOR_ACTION_IDS.has(actionId)) _parse_web_idor(text, ws, source, facts);
  }
  C._parse_web_exploit_output = _parse_web_exploit_output;

})(typeof globalThis !== 'undefined' ? globalThis : this);
