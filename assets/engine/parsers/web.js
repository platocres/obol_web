/*!
 * obol engine - parsers/web.js
 * Faithful JS port of the fixture-reachable parsers in
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
    var isWpscan = /WordPress version|\bWPScan\b|wp-content|wp-includes|\bwordpress\b/i.test(text);
    var version = reSearch(C._WPSCAN_VERSION_RE, text);
    if (isWpscan) {
      var cmsVal = { cms: 'wordpress', tool: 'wpscan' };
      if (version && version.groups && version.groups.v) cmsVal.version = version.groups.v;
      _add(facts, mkFact('web.cms', h, cmsVal, S, source));
      _add(facts, mkFact('web.tech', h, { items: [{ name: 'WordPress', value: cmsVal.version || 'detected' }], tool: 'wpscan' }, S, source));
    }
    var section = reSearch(C._WPSCAN_USER_SECTION_RE, text);
    var users = [];
    if (section) {
      reAll(C._WPSCAN_USER_RE, section[0]).forEach(function (m) {
        var u = m.groups.u.trim();
        if (C._valid_username(u) && ['finished', 'requests'].indexOf(u.toLowerCase()) < 0) users.push(u);
      });
    }
    var inlineUsers = reSearch(/User\(s\)\s+Identified\s*:\s*([^\r\n]+)/i, text);
    if (inlineUsers && inlineUsers[1]) {
      inlineUsers[1].split(/[,\s]+/).forEach(function (u) {
        u = u.trim();
        if (C._valid_username(u) && ['identified', 'found', 'none'].indexOf(u.toLowerCase()) < 0) users.push(u);
      });
    }
    var seen = {}, uu = [];
    users.forEach(function (u) { if (!seen[u]) { seen[u] = true; uu.push(u); } });
    if (uu.length) _add(facts, mkFact('web.users', h, { users: uu, count: uu.length, tool: 'wpscan' }, S, source));
    var vulnSeen = {};
    reAll(C._WPSCAN_VULN_RE, text).forEach(function (m) {
      var title = m.groups.t.trim().slice(0, 160);
      if (!title || vulnSeen[title]) return;
      vulnSeen[title] = true;
      var val = { key: 'wordpress', name: title, source: 'wpscan (candidate lead, not confirmed)' };
      if (version) val.version = version.groups.v;
      _add(facts, mkFact('exploit.candidate', h, val, S, 'wpscan finding, candidate lead, not confirmed (' + source + ')'));
    });
    reAll(/(?:vulnerable\s+(?:plugin|theme)\s*[:\-]\s*(?<p>[^\r\n]+)|(?<cve>CVE-\d{4}-\d{3,7}))/gi, text).forEach(function (m) {
      var title = ((m.groups && (m.groups.p || m.groups.cve)) || m[0]).trim().slice(0, 160);
      if (!title || vulnSeen[title]) return;
      vulnSeen[title] = true;
      var val = { key: 'wordpress', name: title, source: 'wpscan (candidate lead, not confirmed)' };
      if (version) val.version = version.groups.v;
      _add(facts, mkFact('exploit.candidate', h, val, S, 'wpscan finding, candidate lead, not confirmed (' + source + ')'));
    });
    reAll(C._WPSCAN_LOGIN_RE, text).forEach(function (m) {
      var u = m.groups.u.trim(), p = m.groups.p.trim();
      _add(facts, mkFact('credential.candidate', h, { kind: 'wordpress_login', user: u, password: p, via: 'wpscan' }, S, source));
      if (C._add_plaintext_credential) C._add_plaintext_credential(facts, ws, source, u, p, 'wpscan', '', 'wordpress');
    });
    reAll(/Username:\s*(?<u>[^,\r\n]+),\s*Password:\s*(?<p>\S+)/gi, text).forEach(function (m) {
      var u = m.groups.u.trim(), p = m.groups.p.trim();
      _add(facts, mkFact('credential.candidate', h, { kind: 'wordpress_login', user: u, password: p, via: 'wpscan' }, S, source));
      if (C._add_plaintext_credential) C._add_plaintext_credential(facts, ws, source, u, p, 'wpscan', '', 'wordpress');
    });
  }
  C._parse_wpscan = _parse_wpscan;

  // A discovered path that leaks a credential-bearing artifact obol can fetch + read: an app SQLite
  // store, an exposed VCS dir, a backup archive, or a config/env/dump. Order matters (git/archive/
  // config win over the liberal sqlite `.../db` catch).
  var _ARTIFACT_SQLITE_RE = /\.(?:db|sqlite3?|s3db)$|\/(?:db|database|data)$/i;
  var _ARTIFACT_GIT_RE = /\/\.git(?:\/|$)|\/\.svn(?:\/|$)/i;
  var _ARTIFACT_ARCHIVE_RE = /\.(?:zip|rar|7z|tar|tar\.gz|tgz|tar\.bz2)$/i;
  var _ARTIFACT_CONFIG_RE = /\.(?:env|config|conf|cfg|ini|ya?ml|json|xml|properties|sql|bak|old|save|swp|inc)$|(?:config|configuration|settings|wp-config|web\.config|\.env)(?:\.php|\.inc)?$/i;
  var _BASE_URL_RE = /(?<base>https?:\/\/[^/\s"']+)/i;

  function _classify_artifact(path) {
    if (reSearch(_ARTIFACT_GIT_RE, path)) return 'git';
    if (reSearch(_ARTIFACT_ARCHIVE_RE, path)) return 'archive';
    if (reSearch(_ARTIFACT_CONFIG_RE, path)) return 'config';
    if (reSearch(_ARTIFACT_SQLITE_RE, path)) return 'sqlite';
    return '';
  }
  C._classify_artifact = _classify_artifact;

  function _exposed_artifacts(paths, command, ws, source, facts) {
    var m = reSearch(_BASE_URL_RE, command || '');
    var base = m ? m.groups.base : '';
    var seen = {}, count = 0;
    for (var i = 0; i < paths.length; i++) {
      var path = paths[i];
      var kind = _classify_artifact(path);
      if (!kind) continue;
      var url = (base && path.charAt(0) === '/') ? (base + path) : (base ? base + '/' + path : path);
      if (seen[url]) continue;
      seen[url] = true;
      count++;
      _add(facts, mkFact('web.exposed_artifact', 'host:' + ws.target, { url: url, path: path, kind: kind }, S, source));
      if (count >= 15) break;
    }
  }
  C._exposed_artifacts = _exposed_artifacts;

  function _parse_web_content(text, ws, source, facts, command) {
    var paths = {};
    reAll(C._WEB_GOBUSTER_RE, text).forEach(function (m) { if (m.groups.code !== '404') paths[C._url_path(m.groups.path)] = true; });
    reAll(C._WEB_FEROX_RE, text).forEach(function (m) { if (m.groups.code !== '404') paths[C._url_path(m.groups.url)] = true; });
    reAll(C._WEB_DIRB_RE, text).forEach(function (m) { if (m.groups.code !== '404') paths[C._url_path(m.groups.url)] = true; });
    if (C._WEB_DIRSEARCH_RE) {
      reAll(C._WEB_DIRSEARCH_RE, text).forEach(function (m) {
        if (m.groups.code !== '404') paths[C._url_path(m.groups.path || m.groups.url)] = true;
      });
    }
    reAll(C._WEB_FFUF_RE, text).forEach(function (m) {
      var token = m.groups.token;
      if (m.groups.code === '404' || token[0] === ':' || token.toLowerCase() === 'status' || token === '[Status:') return;
      var p = /^https?:\/\//i.test(token) ? C._url_path(token) : (token[0] === '/' ? token : '/' + token);
      if (p) paths[p] = true;
    });
    reAll(/\[\s*Status:\s*(?<code>\d{3})[^\]]*\][\s\S]{0,160}?\|\s*URL\s*\|\s*(?<url>https?:\/\/\S+)/gi, text).forEach(function (m) {
      if (m.groups.code !== '404') paths[C._url_path(m.groups.url)] = true;
    });
    reAll(C._WEB_WFUZZ_RE, text).forEach(function (m) {
      if (m.groups.code === '404') return;
      var payload = m.groups.payload.trim();
      if (!payload) return;
      var p = /^https?:\/\//i.test(payload) ? C._url_path(payload) : (payload[0] === '/' ? payload : '/' + payload);
      if (p) paths[p] = true;
    });
    if (command && C._is_web_content_command && C._is_web_content_command(command)) {
      reAll(/^\s*(?<url>https?:\/\/[^\s"'<>]+)\s*$/gim, text).forEach(function (m) {
        var p = C._url_path(m.groups.url);
        if (p && p !== '/') paths[p] = true;
      });
    }
    var keys = Object.keys(paths).filter(function (p) { return p && p.toLowerCase().indexOf('http') !== 0; });
    if (!keys.length) return;
    var ordered = C.uniqueSortedCI(keys);
    var value = { paths: ordered.slice(0, 50), count: ordered.length };
    var interesting = ordered.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
    if (interesting.length) value.interesting = interesting.slice(0, 20);
    _add(facts, mkFact('web.content_map', 'host:' + ws.target, value, S, source));
    _exposed_artifacts(ordered, command || '', ws, source, facts);
  }
  C._parse_web_content = _parse_web_content;

  function _parse_nikto(text, ws, source, facts, command) {
    var h = 'host:' + ws.target, paths = {}, vulns = [];
    reAll(C._NIKTO_FINDING_RE, text).forEach(function (m) {
      var raw = (m.groups.text || '').trim();
      var p = (m.groups.path || '').trim();
      var fullLine = (p ? (p + ': ' + raw) : raw);
      var low = fullLine.toLowerCase();
      if (C._NIKTO_NOISE_PREFIXES.some(function (px) { return low.indexOf(px) === 0; })) return;
      var pm = p || ((/^(\/[^\s:]+):/.exec(raw) || [])[1] || '');
      if (pm && pm.charAt(0) === '/') paths[pm] = true;
      if (/\b(?:CVE-\d{4}-\d+|OSVDB-\d+|vulnerable|backdoor|remote code|command execution|directory traversal|default account|default password|phpinfo|admin)\b/i.test(fullLine)) {
        vulns.push(fullLine.slice(0, 160));
      }
    });
    var pKeys = C.uniqueSortedCI(Object.keys(paths));
    if (pKeys.length) {
      var val = { paths: pKeys.slice(0, 50), count: pKeys.length, tool: 'nikto' };
      var inter = pKeys.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
      if (inter.length) val.interesting = inter.slice(0, 20);
      _add(facts, mkFact('web.content_map', h, val, S, source));
      _exposed_artifacts(pKeys, command || '', ws, source, facts);
    }
    vulns.slice(0, 10).forEach(function (v) {
      _add(facts, mkFact('exploit.candidate', h, { key: 'nikto', name: v, source: 'nikto' }, S, source));
    });
  }
  C._parse_nikto = _parse_nikto;

  function _parse_ffuf_json(text, ws, source, facts, command) {
    try {
      var obj = JSON.parse(text);
      if (!obj || !Array.isArray(obj.results)) return false;
      var paths = {};
      obj.results.forEach(function (r) {
        if (!r || r.status === 404) return;
        var p = r.url ? C._url_path(r.url) : (r.input && r.input.FUZZ ? '/' + r.input.FUZZ : '');
        if (p) paths[p] = true;
      });
      var ordered = C.uniqueSortedCI(Object.keys(paths));
      if (!ordered.length) return true;
      var val = { paths: ordered.slice(0, 50), count: ordered.length };
      var inter = ordered.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
      if (inter.length) val.interesting = inter.slice(0, 20);
      _add(facts, mkFact('web.content_map', 'host:' + ws.target, val, S, source));
      _exposed_artifacts(ordered, command || '', ws, source, facts);
      return true;
    } catch (e) { return false; }
  }
  C._parse_ffuf_json = _parse_ffuf_json;

  function _parse_feroxbuster_json(text, ws, source, facts, command) {
    var paths = {}, matched = false;
    String(text || '').split(/\r?\n/).forEach(function (line) {
      line = line.trim();
      if (!line || line.charAt(0) !== '{') return;
      try {
        var r = JSON.parse(line);
        if (r && (r.type === 'response' || r.url) && r.status && r.status !== 404) {
          matched = true;
          var p = C._url_path(r.url || r.path || '');
          if (p) paths[p] = true;
        }
      } catch (e) {}
    });
    if (!matched) return false;
    var ordered = C.uniqueSortedCI(Object.keys(paths));
    if (ordered.length) {
      var val = { paths: ordered.slice(0, 50), count: ordered.length };
      var inter = ordered.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
      if (inter.length) val.interesting = inter.slice(0, 20);
      _add(facts, mkFact('web.content_map', 'host:' + ws.target, val, S, source));
      _exposed_artifacts(ordered, command || '', ws, source, facts);
    }
    return true;
  }
  C._parse_feroxbuster_json = _parse_feroxbuster_json;

  function _parse_httpx_json(text, ws, source, facts) {
    var h = 'host:' + ws.target, matched = false, titles = [], techs = [], servers = {};
    String(text || '').split(/\r?\n/).forEach(function (line) {
      line = line.trim();
      if (!line) return;
      if (line.charAt(0) === '{') {
        try {
          var r = JSON.parse(line);
          if (r && (r.url || r['status-code'] || r.status_code)) {
            matched = true;
            if (r.title) titles.push(r.title);
            if (r.webserver) servers[r.webserver] = true;
            if (Array.isArray(r.tech)) r.tech.forEach(function (t) { techs.push({ name: 'httpx', value: t }); });
          }
        } catch (e) {}
      } else {
        var m = /^(https?:\/\/\S+)\s+\[(\d{3})\](.*)$/.exec(line);
        if (m) {
          matched = true;
          var brackets = reAll(/\[([^\]]+)\]/g, m[3]).map(function (b) { return b[1].trim(); }).filter(Boolean);
          if (brackets.length >= 1) titles.push(brackets[0]);
          brackets.slice(1).forEach(function (b) { techs.push({ name: 'httpx', value: b }); });
        }
      }
    });
    if (!matched) return false;
    _add(facts, mkFact('http.reachable', h, { tool: 'httpx' }, S, source));
    if (titles.length) _add(facts, mkFact('web.title', h, { titles: C.uniqueSortedCI(titles).slice(0, 10) }, S, source));
    var sv = C.uniqueSortedCI(Object.keys(servers));
    if (sv.length) _add(facts, mkFact('web.server', h, { headers: sv.slice(0, 10) }, S, source));
    if (techs.length) _add(facts, mkFact('web.tech', h, { items: techs.slice(0, 20), tool: 'httpx' }, S, source));
    return true;
  }
  C._parse_httpx_json = _parse_httpx_json;

  function _parse_nuclei_json(text, ws, source, facts) {
    var h = 'host:' + ws.target, matched = false;
    String(text || '').split(/\r?\n/).forEach(function (line) {
      line = line.trim();
      if (!line) return;
      if (line.charAt(0) === '{') {
        try {
          var r = JSON.parse(line);
          if (r && (r['template-id'] || r.templateID) && r.info) {
            matched = true;
            var tid = r['template-id'] || r.templateID;
            var sev = (r.info.severity || 'info').toLowerCase();
            if (['critical', 'high', 'medium'].indexOf(sev) >= 0 || /^CVE-\d{4}-\d+/i.test(tid)) {
              _add(facts, mkFact('exploit.candidate', h, { key: tid, name: r.info.name || tid, severity: sev, source: 'nuclei' }, S, source));
            }
          }
        } catch (e) {}
      } else {
        var m = /^\[(?<tid>[A-Za-z0-9_.:-]+)\]\s+\[(?<proto>[A-Za-z0-9_-]+)\]\s+\[(?<sev>critical|high|medium|low|info)\]\s+(?<target>\S+)/i.exec(line);
        if (m) {
          matched = true;
          var sev2 = m.groups.sev.toLowerCase();
          if (['critical', 'high', 'medium'].indexOf(sev2) >= 0 || /^CVE-\d{4}-\d+/i.test(m.groups.tid)) {
            _add(facts, mkFact('exploit.candidate', h, { key: m.groups.tid, name: m.groups.tid, severity: sev2, source: 'nuclei' }, S, source));
          }
        }
      }
    });
    return matched;
  }
  C._parse_nuclei_json = _parse_nuclei_json;

  // arjun (HTTP parameter discovery) -> web.param_candidate. The endpoint is the URL arjun was
  // pointed at (`-u`); the parameters are the names it reports finding. Attack surface (a parameter
  // that exists), never a vulnerability, the probe loop is what proves any of them injectable.
  var _ARJUN_URL_RE = /-u\s+['"]?(?<url>https?:\/\/[^\s'"]+)/i;
  var _ARJUN_FOUND_RE = /parameters?\s+(?:found|detected)\s*[:\-]?\s*(?<names>[A-Za-z0-9_,\s.\-()]+)/gi;
  var _ARJUN_FUZZ_RE = /[?&](?<name>[A-Za-z_][\w.\-]*)=FUZZ/gi;
  var _ARJUN_NAME_RE = /^[A-Za-z_][\w.\-]{0,63}$/;

  function _parse_arjun(text, ws, command, source, facts) {
    var m = reSearch(_ARJUN_URL_RE, (command || '') + '\n' + (text || ''));
    var url = m ? m.groups.url : '';
    var names = [];
    reAll(_ARJUN_FOUND_RE, text).forEach(function (hit) {
      hit.groups.names.replace(/\n/g, ',').split(',').forEach(function (raw) {
        var name = raw.replace(/\s*\([A-Za-z]+\)\s*$/, '').trim();
        if (_ARJUN_NAME_RE.test(name) && ['found', 'detected'].indexOf(name.toLowerCase()) < 0) names.push(name);
      });
    });
    reAll(_ARJUN_FUZZ_RE, text).forEach(function (hit) { names.push(hit.groups.name); });
    var seen = {}, count = 0;
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      if (seen[name]) continue;
      seen[name] = true;
      _add(facts, mkFact('web.param_candidate', 'host:' + ws.target, { url: url, param: name, method: 'GET' }, S, source));
      if (++count >= 40) break;
    }
  }
  C._parse_arjun = _parse_arjun;

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
    var sourceFound = !!head || ((lc.indexOf('git-dumper') >= 0 || /\[\+\]\s*Fetching\s+\.git\//i.test(text)) && reSearch(C._GIT_DUMPER_SUCCESS_RE, text) && !/\b(?:error|failed|not found|403|404)\b/i.test(text));
    if (sourceFound) {
      var value = { kind: 'git', tool: (lc.indexOf('git-dumper') >= 0 || /\[\+\]\s*Fetching\s+\.git\//i.test(text)) ? 'git-dumper' : 'curl' };
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
    if (!vuln && /all tested parameters do not appear to be injectable|does not seem to be injectable/i.test(text)) return;
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
    if (credentialColumns.length && (reSearch(C._SQLMAP_DUMP_RE, text) || /\bdumped to CSV file\b|\bfetching entries for table\b/i.test(text) || tableRefs.length)) {
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
    if (Object.keys(ids).length >= 2 && (status200 >= 2 || /"(?:username|user|email|role|api_?key|secret|password)"\s*:/i.test(text))) {
      _add(facts, mkFact('web.idor_candidate', h, { via: 'curl', distinct_records: Object.keys(ids).length, evidence: 'distinct object records returned across ids' }, S, source));
      return;
    }
    if (Object.keys(ids).length === 1 && /"(?:api_?key|secret|password|private_?token|ssn)"\s*:\s*"[^"\r\n]{4,}"|"(?:role|isAdmin|admin)"\s*:\s*(?:"admin"|true)/i.test(text)) {
      _add(facts, mkFact('web.idor_candidate', h, { via: 'curl', distinct_records: 1, evidence: 'privileged/sensitive object record returned' }, S, source));
    }
  }
  C._parse_web_idor = _parse_web_idor;

  function _parse_web_xss(text, ws, source, facts) {
    var low = text.toLowerCase();
    var hit = '', kind = 'reflected';
    if (low.indexOf('xssprobe') >= 0) hit = 'reflected probe marker';
    else if (/<script[^>]{0,200}>[^<]{0,400}alert\s*\(/.test(low) || /<svg[^>]{0,200}\son(?:load|error)\s*=/.test(low) || /<img[^>]{0,200}\sonerror\s*=\s*["']?alert/.test(low)) hit = 'reflected script/event-handler payload';
    else if (/<script[^>]{0,200}>[^<]{0,400}document\.(?:cookie|location)/.test(low) || /<script[^>]{0,200}>[^<]{0,400}new\s+image\(\)\.src/.test(low)) { hit = 'stored script exfiltrating document.cookie'; kind = 'stored'; }
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
    var isXxe = actionId === 'xxe' || /<!ENTITY\b/i.test(command || '') || /<!ENTITY\b/i.test(text || '');
    var method = isXxe ? 'xxe' : 'path_traversal';
    var isLfiMove = actionId === 'lfi-probe' || actionId === 'lfi-secret-harvest' || actionId === 'operator-ingest' || !actionId;
    var filesRead = [], osFamily = '';
    var passwdHead = reSearch(C._LFI_PASSWD_RE, text);
    if (passwdHead && reSearch(C._LFI_PASSWD_SECOND_RE, text)) {
      osFamily = 'linux';
      filesRead.push('/etc/passwd');
      if (isLfiMove && !isXxe) _add(facts, mkFact('web.lfi_confirmed', h, { file: '/etc/passwd', os: 'linux', method: method, evidence: C._line_for_match(text, passwdHead) }, S, source));
    }
    var shadowHead = reSearch(/^root:\$(?:1|2[abxy]|5|6|y)\$[^\r\n:]+:/m, text);
    if (shadowHead) {
      osFamily = 'linux';
      filesRead.push('/etc/shadow');
      if (isLfiMove && !isXxe) _add(facts, mkFact('web.lfi_confirmed', h, { file: '/etc/shadow', os: 'linux', method: method, evidence: C._line_for_match(text, shadowHead) }, S, source));
    }
    var environHit = reSearch(/(?:DOCUMENT_ROOT|SCRIPT_FILENAME|HTTP_USER_AGENT)=\/[^\x00\r\n]+/, text);
    if (environHit) {
      osFamily = 'linux';
      filesRead.push('/proc/self/environ');
      if (isLfiMove && !isXxe) _add(facts, mkFact('web.lfi_confirmed', h, { file: '/proc/self/environ', os: 'linux', method: method, evidence: C._line_for_match(text, environHit) }, S, source));
    }
    var win = reSearch(C._LFI_WIN_INI_RE, text);
    if (win) {
      osFamily = osFamily || 'windows';
      var param = reSearch(C._LFI_FILE_PARAM_RE, command);
      var winFile = param ? param.groups.path : 'windows_system_file';
      filesRead.push(winFile);
      if (isLfiMove && !isXxe) _add(facts, mkFact('web.lfi_confirmed', h, { file: winFile, os: 'windows', method: method, evidence: C._line_for_match(text, win) }, S, source));
    }
    var lc = (command || '').toLowerCase();
    var decoded = (lc.indexOf('php://filter') >= 0 || lc.indexOf('convert.base64') >= 0 || /^[A-Za-z0-9+/]{40,}={0,2}\s*$/m.test(text)) ? _php_filter_source(text) : '';
    if (decoded) {
      var p2 = reSearch(C._LFI_FILE_PARAM_RE, command);
      var resource = p2 ? p2.groups.path : 'php_source';
      filesRead.push(resource);
      if (isLfiMove && !isXxe) _add(facts, mkFact('web.lfi_confirmed', h, { file: resource, method: 'php_filter', kind: 'php_source' }, S, source));
      _add(facts, mkFact('web.source', h, { kind: 'php', via: method }, S, source));
      var decSecrets = _secret_snippets(decoded);
      var minedDec = _mine_response_credentials(decoded);
      if (minedDec.length) {
        minedDec.forEach(function (c) { _add(facts, mkFact('credential.candidate', h, Object.assign({ kind: 'source_secret', via: 'lfi' }, c), S, source)); });
      } else if (decSecrets.length) {
        _add(facts, mkFact('credential.candidate', h, { kind: 'source_secret', count: decSecrets.length, secrets: decSecrets.slice(0, 20) }, S, source));
      }
    }
    if (actionId === 'lfi-secret-harvest' || (!decoded && /(?:<\?php|DB_PASSWORD|db_pass|connectionString)/i.test(text))) {
      var rawSecrets = _secret_snippets(text);
      var minedRaw = _mine_response_credentials(text);
      if (rawSecrets.length || minedRaw.length) {
        var p3 = reSearch(C._LFI_FILE_PARAM_RE, command);
        filesRead.push(p3 ? p3.groups.path : 'config_file');
        if (minedRaw.length) {
          minedRaw.forEach(function (c) { _add(facts, mkFact('credential.candidate', h, Object.assign({ kind: 'source_secret', via: 'lfi' }, c), S, source)); });
        } else {
          _add(facts, mkFact('credential.candidate', h, { kind: 'source_secret', count: rawSecrets.length, secrets: rawSecrets.slice(0, 20) }, S, source));
        }
      }
    }
    if (filesRead.length) {
      var uniq = C.uniqueSortedCI(filesRead);
      _add(facts, mkFact('loot.files', h, { files: uniq, via: method, tool: 'web' }, S, source));
      if (isXxe) _add(facts, mkFact('web.xxe_confirmed', h, { files: uniq, evidence: passwdHead ? C._line_for_match(text, passwdHead) : 'file content returned' }, S, source));
    }
    if (osFamily) C._add_os_observation(facts, ws, source, osFamily, (passwdHead || win) ? C._line_for_match(text, passwdHead || win) : osFamily, 'medium', 'web-' + (actionId || 'lfi'), false);
  }
  C._parse_web_lfi = _parse_web_lfi;

  function _parse_web_cmdi(actionId, text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var cmdAndText = (command || '') + '\n' + (text || '');
    // SSTI math / config evaluation check (e.g., {{7*7}} -> 49 or 7777777)
    if (actionId === 'ssti' || (/(\{\{\s*7\s*\*\s*(?:7|'7')|\$\{\s*7\s*\*\s*7|<%=\s*7\s*\*\s*7)/.test(cmdAndText))) {
      var sstiHit = reSearch(/\b(?:49|7777777)\b|<Config\b|\bssti/i, text);
      if (sstiHit) {
        _add(facts, mkFact('web.ssti_confirmed', h, { method: 'template_injection', evidence: C._line_for_match(text, sstiHit) }, S, source));
      }
    }
    // File upload / verb-tampering HTTP 201 or JSON upload success check
    if (actionId === 'file-upload' || actionId === 'verb-tampering' || actionId === 'http-put-webshell') {
      var upHit = reSearch(/"status"\s*:\s*"uploaded"|\b(?:file|shell)\s+uploaded\b|HTTP\/[12](?:\.\d)?\s+201\s+Created/i, text);
      if (upHit) {
        _add(facts, mkFact('web.upload_confirmed', h, { method: 'executable_upload', evidence: C._line_for_match(text, upHit) }, S, source));
      }
    }
    var uid = reSearch(C._CMDI_UID_RE, text);
    var win = reSearch(C._CMDI_WIN_RE, text);
    if (!uid && !win) return;
    var effId = actionId;
    if (!effId || effId === 'operator-ingest') {
      if (/ysoserial|ObjectInputStream|rO0AB|java\.io/i.test(cmdAndText)) effId = 'deserialization';
      else if (/\/scriptText|--data-urlencode\s+['"]?script=|println\s*\(/i.test(cmdAndText)) effId = 'jenkins-access';
      else if (/ognl|#context|struts/i.test(cmdAndText)) effId = 'check-struts2';
      else if (/\{\{|\$\{/.test(command || '')) effId = 'ssti';
      else if (/\.(?:php|jsp|asp|aspx)\?(?:cmd|c|exec)=/i.test(command || '')) effId = 'web-shells';
      else effId = 'command-injection';
    }
    var method = { 'command-injection': 'os_command_injection', ssti: 'template_injection', 'web-shells': 'web_shell', 'file-upload': 'uploaded_web_shell', deserialization: 'insecure_deserialization', 'tomcat-deploy': 'tomcat_war_deploy', 'jenkins-access': 'jenkins_script_console' }[effId] || effId;
    var osFamily = uid ? 'linux' : 'windows';
    var evidence = C._line_for_match(text, uid || win);
    _add(facts, mkFact('web.cmdi_confirmed', h, { os: osFamily, method: method, evidence: evidence }, S, source));
    if (method === 'template_injection') _add(facts, mkFact('web.ssti_confirmed', h, { method: 'template_injection', evidence: evidence }, S, source));
    else if (method === 'insecure_deserialization') _add(facts, mkFact('web.deserial_confirmed', h, { method: 'insecure_deserialization', evidence: evidence }, S, source));
    if (effId === 'file-upload') _add(facts, mkFact('web.upload_confirmed', h, { method: 'executable_upload', evidence: evidence }, S, source));
    // For the moves whose purpose is to land a shell (SSTI->RCE, a PUT'd webshell, abusing an authz
    // bypass into an upload), command output in the paste is the foothold itself.
    if (C._WEB_RCE_FOOTHOLD_IDS && C._WEB_RCE_FOOTHOLD_IDS.has(effId)) _add(facts, mkFact('foothold.webshell', h, { os: osFamily, method: method, evidence: evidence }, S, source));
    C._add_os_observation(facts, ws, source, osFamily, evidence, 'medium', 'web-' + effId, false);
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

  var _INTERNAL_TARGET_RE = /(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|\[::1\]|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b)/i;
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
      // also a typed cloud-credential lead, so the cloud post-exploitation move can key on it directly
      // (the generic credential.candidate still drives the cred loop). NOT cloud.aws_access: a key read
      // from metadata is a candidate to try with aws-cli, not proof of access, per the proof discipline.
      _add(facts, mkFact('cloud.credential', h, { provider: 'aws', access_key_id: akid.groups.akid, temporary: /^ASIA/.test(akid.groups.akid), via: method }, S, source));
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
    if (!reSearch(C._NOSQL_OP_RE, (command || '') + '\n' + (text || ''))) return;
    var success = reSearch(C._NOSQL_SUCCESS_RE, text);
    var redirect = reSearch(C._LOGIN_REDIRECT_RE, text);
    var cookie = reSearch(C._SET_COOKIE_SESSION_RE, text);
    var evidence;
    if (success) evidence = C._line_for_match(text, success);
    else if (redirect && cookie) evidence = C._line_for_match(text, redirect);
    else return;
    var h = 'host:' + ws.target;
    _add(facts, mkFact('web.nosqli_confirmed', h, { method: 'operator_injection', vector: 'authentication_bypass', evidence: evidence }, S, source));
    _add(facts, mkFact('web.authz_bypass', h, { method: 'nosqli', vector: 'operator_injection', evidence: evidence }, S, source));
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
    var jwtTok = reSearch(/\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/, (text || '') + '\n' + (command || ''));
    if (jwtTok && C.b64decode) {
      var parts = jwtTok[0].split('.');
      var hdrDec = C.b64decode(parts[0].replace(/-/g, '+').replace(/_/g, '/'));
      var payDec = C.b64decode(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
      if (/"alg"\s*:\s*"none"/i.test(hdrDec)) forged = forged || [hdrDec];
      if (!accepted && payDec && C._WEB_AUTHZ_SUCCESS_RE.test(payDec)) accepted = reSearch(C._WEB_AUTHZ_SUCCESS_RE, payDec);
    }
    if (forged && accepted) _add(facts, mkFact('web.authz_bypass', h, { method: 'jwt', vector: 'forged_token', evidence: C._line_for_match(text, accepted) }, S, source));
  }
  C._parse_web_jwt = _parse_web_jwt;

  function _parse_web_exploit_output(actionId, text, ws, command, source, facts) {
    if (!text.trim()) return;
    var isGeneric = !actionId || actionId === 'operator-ingest';
    if (isGeneric || C._WEB_LFI_ACTION_IDS.has(actionId)) _parse_web_lfi(actionId, text, ws, command, source, facts);
    if (C._WEB_CMDI_ACTION_IDS.has(actionId) || (isGeneric && /\b(?:curl|wget|httpie|burp|ysoserial)\b|^HTTP\/[12]\./im.test((command || '') + '\n' + text))) {
      _parse_web_cmdi(actionId, text, ws, command, source, facts);
    }
    if (isGeneric || C._WEB_SQLI_ACTION_IDS.has(actionId)) _parse_web_sqli_manual(text, ws, source, facts);
    if (isGeneric || C._WEB_SSRF_ACTION_IDS.has(actionId)) _parse_web_ssrf(actionId, text, ws, command, source, facts);
    if (isGeneric || C._WEB_NOSQLI_ACTION_IDS.has(actionId)) _parse_web_nosqli(text, ws, command, source, facts);
    if (isGeneric || C._WEB_JWT_ACTION_IDS.has(actionId)) _parse_web_jwt(text, ws, command, source, facts);
    if (isGeneric || C._WEB_XSS_ACTION_IDS.has(actionId)) _parse_web_xss(text, ws, source, facts);
    if (isGeneric || C._WEB_IDOR_ACTION_IDS.has(actionId)) _parse_web_idor(text, ws, source, facts);
  }
  C._parse_web_exploit_output = _parse_web_exploit_output;

  // Product fingerprints that gate a specific exploit move. Shape-based and
  // conservative: each mints only on a signature that genuinely identifies the
  // product (a dedicated response header, or the product name in a title/body),
  // so an unrelated web paste mints nothing. These are the precise triggers the
  // matching moves want instead of a bare "port 80/8080 is open" gate.
  //
  // Jenkins: the X-Jenkins / X-Hudson response headers are definitive (Hudson
  // was Jenkins' former name and the header persists); the CLI port header and
  // the "Welcome to Jenkins!" / "Dashboard [Jenkins]" chrome are strong backups.
  var _FP_JENKINS_RE = /^\s*X-(?:Jenkins|Hudson)(?:-(?:Session|CLI2?-Port))?\s*:/im;
  var _FP_JENKINS_BODY_RE = /Welcome to Jenkins!|Dashboard \[Jenkins\]|<[^>]*id=["']?jenkins|Manage Jenkins/i;
  // NVMS-1000 (TVT) network video management, CVE-2019-20085 directory traversal.
  // The product names itself in the login page title and asset paths.
  var _FP_NVMS_RE = /NVMS[\s-]?1000|\/vh_www\/|TVT[\s_-]?NVMS/i;

  function _parse_web_fingerprint(text, ws, source, facts) {
    if (!text || !text.trim()) return;
    var h = 'host:' + ws.target;
    if (reSearch(_FP_JENKINS_RE, text)) {
      _add(facts, mkFact('web.fingerprint.jenkins', h, { via: 'response-header', evidence: C._line_for_match(text, reSearch(_FP_JENKINS_RE, text)) }, S, source));
    } else if (reSearch(_FP_JENKINS_BODY_RE, text)) {
      _add(facts, mkFact('web.fingerprint.jenkins', h, { via: 'page-chrome' }, S, source));
    }
    if (reSearch(_FP_NVMS_RE, text)) {
      _add(facts, mkFact('web.fingerprint.nvms', h, { via: 'product-name', product: 'NVMS-1000' }, S, source));
    }
  }
  C._parse_web_fingerprint = _parse_web_fingerprint;

})(typeof globalThis !== 'undefined' ? globalThis : this);
