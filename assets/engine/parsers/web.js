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

  function _is_sql_client_output(text, ws, command) {
    var t = String(text || '');
    var cmd = String(command || '');
    if (/^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(t)) return false;
    if (/<(?:!doctype\s+html|html|head|body|form|input|script|title|meta)\b/i.test(t)) return false;
    if (/\b(?:curl|wget|httpie|whatweb|ffuf|gobuster|feroxbuster|nikto|httpx|nuclei|wpscan)\b/i.test(cmd)) return false;
    var promptCtx = [
      ws && ws.context && ws.context.promptLine,
      ws && ws.context && ws.context.followPrompt
    ].filter(Boolean).join('\n');
    var combined = promptCtx ? (promptCtx + '\n' + t) : t;
    if (/^\s*(?:mysql|MariaDB\s*\[[^\]]*\]|postgres[-=#]*|sqlite3?|SQL(?:\s*\([^)]*\))?)\s*>/im.test(combined)) return true;
    if (/^\s*(?:sudo\s+)?(?:mysql|psql|sqlite3?|mssqlclient(?:\.py)?|impacket-mssqlclient|sqlcmd|sqlplus)\b/i.test(cmd)) return true;
    if (/\b\d+\s+rows?\s+in\s+set\b/i.test(t) && /^\s*\|\s*Database\s*\|\s*$/im.test(t)) return true;
    if (/^\s*\(\d+\s+rows?\)\s*$/im.test(t) && /^\s*List of databases\b/im.test(t)) return true;
    return false;
  }
  C._is_sql_client_output = _is_sql_client_output;

  function _parse_wpscan(text, ws, source, facts) {
    if (_is_sql_client_output(text, ws, '')) return;
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
  var _GOBUSTER_REL_RE = /^[ \t]*(?:Found:[ \t]*)?(?:(?<origin>https?:\/\/[^/\s]+))?(?<path>\/?[A-Za-z0-9_.~%-][^\s()]*)[ \t]+\(Status:[ \t]*(?<code>\d{3})\)(?:[ \t]+\[Size:[ \t]*\d+\])?(?:[ \t]+\[-->[^\]]*\])?[ \t]*$/gim;

  function _normalize_origin_url(rawOrigin) {
    var m = /^(https?):\/\/([^/\s"'?#:]+)(?::(\d{1,5}))?/i.exec(String(rawOrigin || '').trim());
    if (!m) return { origin: '', port: 0 };
    var scheme = m[1].toLowerCase();
    var host = m[2];
    var port = m[3] ? parseInt(m[3], 10) : (scheme === 'https' ? 443 : 80);
    if (!port || port < 1 || port > 65535) port = (scheme === 'https' ? 443 : 80);
    var isDefault = (scheme === 'http' && port === 80) || (scheme === 'https' && port === 443);
    return {
      origin: scheme + '://' + host + (isDefault ? '' : ':' + port),
      port: port
    };
  }

  function _extract_web_origin(text, command, ws) {
    var cmd = String(command || '').replace(/(?:^|\s)(?:-x|--proxy|--replay-proxy)\s+(?:"[^"]*"|'[^']*'|\S+)/gi, ' ');
    var t = String(text || '');
    var flagM = /(?:^|\s)(?:-u|--url|-host|-h)\s+['"]?(https?:\/\/[^/\s"'?#]+)/i.exec(cmd);
    if (flagM) return _normalize_origin_url(flagM[1]);
    var cmdUrlM = /(https?:\/\/[^/\s"'?#]+)/i.exec(cmd);
    if (cmdUrlM) return _normalize_origin_url(cmdUrlM[1]);
    var bannerM = /(?:^\s*\[\+\]\s*Url:\s*|^\s*[+|*]?\s*Target(?:\s+URL)?\s*:\s*|::\s*URL\s*:\s*|URL_BASE\s*:\s*)(https?:\/\/[^/\s"'?#]+)/im.exec(t);
    if (bannerM) return _normalize_origin_url(bannerM[1]);
    var rowUrlM = /(https?:\/\/[^/\s"'?#]+)\//i.exec(t);
    if (rowUrlM) return _normalize_origin_url(rowUrlM[1]);
    var niktoPortM = /^\+\s*Target Port:\s*(\d{1,5})\b/im.exec(t);
    if (niktoPortM) {
      var nPort = parseInt(niktoPortM[1], 10);
      var nHostM = /^\+\s*Target (?:Hostname|IP):\s*([^\s\r\n]+)/im.exec(t);
      var nHost = (nHostM && nHostM[1]) || (ws && ws.target) || '';
      var nScheme = (/^\+\s*SSL Info:/im.test(t) || nPort === 443 || nPort === 8443) ? 'https' : 'http';
      if (nHost && nPort >= 1 && nPort <= 65535) {
        return _normalize_origin_url(nScheme + '://' + nHost + ':' + nPort);
      }
    }
    var niktoCmdPortM = /\bnikto\b[^\r\n]*?(?:-p|-port)\s+(\d{1,5})\b/i.exec(cmd);
    if (niktoCmdPortM) {
      var ncPort = parseInt(niktoCmdPortM[1], 10);
      var ncHostM = /(?:-h|-host)\s+['"]?([^/\s"':]+)/i.exec(cmd);
      var ncHost = (ncHostM && ncHostM[1]) || (ws && ws.target) || '';
      var ncScheme = (/\s-ssl\b/i.test(cmd) || ncPort === 443 || ncPort === 8443) ? 'https' : 'http';
      if (ncHost && ncPort >= 1 && ncPort <= 65535) {
        return _normalize_origin_url(ncScheme + '://' + ncHost + ':' + ncPort);
      }
    }
    return { origin: '', port: 0 };
  }
  C._extract_web_origin = _extract_web_origin;

  function _classify_artifact(path) {
    if (reSearch(_ARTIFACT_GIT_RE, path)) return 'git';
    if (reSearch(_ARTIFACT_ARCHIVE_RE, path)) return 'archive';
    if (reSearch(_ARTIFACT_CONFIG_RE, path)) return 'config';
    if (reSearch(_ARTIFACT_SQLITE_RE, path)) return 'sqlite';
    return '';
  }
  C._classify_artifact = _classify_artifact;

  function _exposed_artifacts(paths, command, ws, source, facts, fallbackOrigin) {
    var m = reSearch(_BASE_URL_RE, command || '');
    var base = m ? m.groups.base : (fallbackOrigin || '');
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
    var isGobusterCtx = /\bgobuster\b/i.test(command || '') || /\bGobuster\s+v?\d/i.test(text || '') || /\(Status:\s*\d{3}\)[ \t]+\[Size:\s*\d+\]/i.test(text || '');
    reAll(C._WEB_GOBUSTER_RE, text).forEach(function (m) {
      if (m.groups.code !== '404') {
        var rawP = m.groups.path || '';
        var normP = rawP.charAt(0) === '/' || /^https?:\/\//i.test(rawP) ? C._url_path(rawP) : C._url_path('/' + rawP);
        if (normP) paths[normP] = true;
      }
    });
    reAll(_GOBUSTER_REL_RE, text).forEach(function (m) {
      if (m.groups.code === '404') return;
      var rawRel = (m.groups.path || '').trim();
      if (!rawRel) return;
      if (rawRel.charAt(0) !== '/' && !m.groups.origin && !isGobusterCtx) return;
      var normRel = rawRel.charAt(0) === '/' ? C._url_path(rawRel) : C._url_path('/' + rawRel);
      if (normRel) paths[normRel] = true;
    });
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
    var meta = _extract_web_origin(text, command, ws);
    var value = { paths: ordered.slice(0, 500), count: ordered.length };
    if (meta.origin) value.origin = meta.origin;
    if (meta.port) value.port = meta.port;
    var interesting = ordered.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
    if (interesting.length) value.interesting = interesting.slice(0, 200);
    _add(facts, mkFact('web.content_map', 'host:' + ws.target, value, S, source));
    _add(facts, mkFact('web.paths', 'host:' + ws.target, value, S, source));
    var uploadPath = ordered.find(function (p) { return /(?:^|\/)upload(?:s|\.[a-z0-9]+)?(?:\b|\/|$)/i.test(p); });
    if (uploadPath) _add(facts, mkFact('web.upload_form', 'host:' + ws.target, { path: uploadPath, evidence: 'upload endpoint discovered: ' + uploadPath }, S, source));
    _exposed_artifacts(ordered, command || '', ws, source, facts, meta.origin);
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
      var meta = _extract_web_origin(text, command, ws);
      var val = { paths: pKeys.slice(0, 500), count: pKeys.length, tool: 'nikto' };
      if (meta.origin) val.origin = meta.origin;
      if (meta.port) val.port = meta.port;
      var inter = pKeys.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
      if (inter.length) val.interesting = inter.slice(0, 200);
      _add(facts, mkFact('web.content_map', h, val, S, source));
      _exposed_artifacts(pKeys, command || '', ws, source, facts, meta.origin);
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
      var paths = {}, firstUrl = '';
      obj.results.forEach(function (r) {
        if (!r || r.status === 404) return;
        if (!firstUrl && r.url) firstUrl = r.url;
        var p = r.url ? C._url_path(r.url) : (r.input && r.input.FUZZ ? '/' + r.input.FUZZ : '');
        if (p) paths[p] = true;
      });
      var ordered = C.uniqueSortedCI(Object.keys(paths));
      if (!ordered.length) return true;
      var meta = _extract_web_origin(firstUrl || (obj.config && obj.config.url) || '', command || (obj.commandline || ''), ws);
      var val = { paths: ordered.slice(0, 500), count: ordered.length };
      if (meta.origin) val.origin = meta.origin;
      if (meta.port) val.port = meta.port;
      var inter = ordered.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
      if (inter.length) val.interesting = inter.slice(0, 200);
      _add(facts, mkFact('web.content_map', 'host:' + ws.target, val, S, source));
      _exposed_artifacts(ordered, command || '', ws, source, facts, meta.origin);
      return true;
    } catch (e) { return false; }
  }
  C._parse_ffuf_json = _parse_ffuf_json;

  function _parse_feroxbuster_json(text, ws, source, facts, command) {
    var paths = {}, matched = false, firstUrl = '';
    String(text || '').split(/\r?\n/).forEach(function (line) {
      line = line.trim();
      if (!line || line.charAt(0) !== '{') return;
      try {
        var r = JSON.parse(line);
        if (r && (r.type === 'response' || r.url) && r.status && r.status !== 404) {
          matched = true;
          if (!firstUrl && r.url) firstUrl = r.url;
          var p = C._url_path(r.url || r.path || '');
          if (p) paths[p] = true;
        }
      } catch (e) {}
    });
    if (!matched) return false;
    var ordered = C.uniqueSortedCI(Object.keys(paths));
    if (ordered.length) {
      var meta = _extract_web_origin(firstUrl, command, ws);
      var val = { paths: ordered.slice(0, 500), count: ordered.length };
      if (meta.origin) val.origin = meta.origin;
      if (meta.port) val.port = meta.port;
      var inter = ordered.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
      if (inter.length) val.interesting = inter.slice(0, 200);
      _add(facts, mkFact('web.content_map', 'host:' + ws.target, val, S, source));
      _exposed_artifacts(ordered, command || '', ws, source, facts, meta.origin);
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
          var brackets = reAll(/\[([^\]\r\n]{1,200})\]/g, m[3]).map(function (b) { return b[1].trim(); }).filter(Boolean);
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
        var name = raw.replace(/[ \t]*\([A-Za-z]+\)[ \t]*$/, '').trim();
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
  var _LOGIN_FORM_RE = /<input\b[^>]*\btype\s*=\s*["']?\s*password\b/i;
  var _OCR_USER_INPUT_RE = /\[Input[^\]]*(?:User(?:name)?|Email|Login|Account)[^\]]*\]/i;
  var _OCR_PASS_INPUT_RE = /\[Input[^\]]*Pass(?:word|wd|code)?[^\]]*\]/i;
  var _HTTP_AUTH_PARAM_USER_RE = /(?:^|[?&\s"'{,])["']?(?:user(?:name)?|email|login|uid|usr)["']?\s*[:=]\s*["']?[^&\s"',}]+/i;
  var _HTTP_AUTH_PARAM_PASS_RE = /(?:^|[?&\s"'{,])["']?(?:pass(?:word|wd)?|pwd)["']?\s*[:=]\s*["']?[^&\s"',}]+/i;
  var _HTTP_AUTH_ENDPOINT_RE = /(?:^(?:>\s*)?(?:POST|GET)\s+\/[^\s?]*?(?:login|signin|sign-in|auth|authenticate)\b|https?:\/\/[^/\s"']+\/[^\s"'?#]*?(?:login|signin|sign-in|auth|authenticate)\b)/im;

  function _parse_web_surface(text, ws, command, source, facts) {
    if (_is_sql_client_output(text, ws, command)) return;
    var t = text || '', cmd = command || '', h = 'host:' + ws.target;
    var cmdAndText = cmd + '\n' + t;
    var hasOcrLogin = reSearch(_OCR_USER_INPUT_RE, t) && reSearch(_OCR_PASS_INPUT_RE, t);
    var isHttpExchange = /\b(?:curl|wget|httpie)\b/i.test(cmd)
      || /^(?:[<>]\s*)?(?:POST|GET)\s+\/\S+\s+HTTP\/[12]/im.test(t)
      || /^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(t)
      || /^URL:\s*https?:\/\/\S+/im.test(t);
    var hasHttpAuthParams = isHttpExchange && reSearch(_HTTP_AUTH_PARAM_USER_RE, cmdAndText) && reSearch(_HTTP_AUTH_PARAM_PASS_RE, cmdAndText);
    var hasHttpAuthPost = isHttpExchange && reSearch(_HTTP_AUTH_ENDPOINT_RE, cmdAndText)
      && (/\s(?:-d|--data(?:-\w+)?|-F)\s/i.test(' ' + cmd) || /^(?:>\s*)?POST\s+\//im.test(t) || hasHttpAuthParams);
    var hasConnFailure = /curl:\s*\(\d+\)|Connection refused|Could not resolve host|Failed to connect|No route to host/i.test(t);
    var hasLiveCmdResponse = t.trim().length > 0 && !hasConnFailure && !/^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+404\b/im.test(t);

    if (reSearch(_PARAM_URL_RE, t) || reSearch(_FORM_INPUT_RE, t) || (hasLiveCmdResponse && reSearch(_PARAM_URL_RE, cmd)) || hasOcrLogin || hasHttpAuthParams || hasHttpAuthPost) {
      _add(facts, mkFact('web.parameterized', h, { evidence: hasOcrLogin ? 'OCR browser form input controls' : 'parameter or form input observed' }, S, source));
    }
    if (reSearch(_UPLOAD_FORM_RE, t)) _add(facts, mkFact('web.upload_form', h, { evidence: 'file-upload form' }, S, source));
    if (reSearch(_LOGIN_FORM_RE, t) || hasOcrLogin || hasHttpAuthParams || hasHttpAuthPost) {
      _add(facts, mkFact('web.login_form', h, { evidence: hasOcrLogin ? 'OCR browser login form controls' : 'password input form' }, S, source));
    }
    if ((hasOcrLogin || ((hasHttpAuthParams || hasHttpAuthPost) && t.trim().length > 0)) && !hasConnFailure) {
      _add(facts, mkFact('http.reachable', h, { via: hasOcrLogin ? 'ocr-surface' : 'http-auth-surface' }, S, source));
    }
  }
  C._parse_web_surface = _parse_web_surface;

  var _DIFF_CRED_DENY = {
    changeme: 1, change_me: 1, password: 1, secret: 1, example: 1, placeholder: 1,
    none: 1, null: 1, true: 1, false: 1, todo: 1, redacted: 1, xxx: 1, xxxx: 1,
    your_password: 1, your_user: 1, username: 1, user: 1
  };
  var _DIFF_USER_ASSIGN_RE = /^(?:define\(\s*['"]([\w.-]*?(?:user(?:name)?|usr|uid|login|account)[\w.-]*)['"]\s*,\s*['"]([^'"\r\n]{1,96})['"]|(?:(?:public|private|protected|var|let|const|static|final|export)\s+)*['"$@]?((?:[A-Za-z_][\w.-]*?)?(?:user(?:name)?|usr|uid|login|account)[\w.-]*)['"]?\s*(?:=>|[:=])\s*['"]([^'"\r\n]{1,96})['"])/i;
  var _DIFF_PASS_ASSIGN_RE = /^(?:define\(\s*['"]([\w.-]*?(?:pass(?:word|wd)?|pwd|secret|key)[\w.-]*)['"]\s*,\s*['"]([^'"\r\n]{3,128})['"]|(?:(?:public|private|protected|var|let|const|static|final|export)\s+)*['"$@]?((?:[A-Za-z_][\w.-]*?)?(?:pass(?:word|wd)?|pwd|secret|key)[\w.-]*)['"]?\s*(?:=>|[:=])\s*['"]([^'"\r\n]{3,128})['"])/i;

  function _valid_diff_token(v, isUser) {
    var s = String(v || '').trim();
    if (!s || (isUser ? s.length < 2 : s.length < 3) || s.length > 128) return false;
    var low = s.toLowerCase();
    if (_DIFF_CRED_DENY[low]) return false;
    if (isUser && (low === 'user' || low === 'username' || low === 'dbuser' || low === 'db_user')) return false;
    if (/^\$\{.*\}$|^<.*>$|^%.*%$|^\$\w+$|^\{\{.*\}\}$/.test(s)) return false;
    if (!isUser && /^(?:https?:\/\/|\/|\.\.?\/|[A-Za-z]:\\)/.test(s)) return false;
    return true;
  }

  function _extract_diff_cred_pairs(text) {
    var t = String(text || '');
    if (!/^@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@|^diff --git\s+/m.test(t)) return [];
    var lines = t.split(/\r?\n/);
    var pairs = [], seen = {};
    var curFile = '', inHunk = false;
    var usersMinus = [], usersPlus = [], usersCtx = [];
    var passMinus = [], passPlus = [], passCtx = [];
    var hunkText = [];

    function flushHunk() {
      if (!inHunk) return;
      var hunkBlob = curFile + '\n' + hunkText.join('\n');
      var isDb = /(?:database|db_|_db\b|mysql|mysqli|pdo|pgsql|postgres|mssql|sqlsrv|sqlite|jdbc|hibernate|datasource|wp-config|configuration\.php)/i.test(hunkBlob);
      function pairLists(uList, pList, requireChanged) {
        for (var ui = 0; ui < uList.length; ui++) {
          for (var pi = 0; pi < pList.length; pi++) {
            if (requireChanged && !uList[ui].changed && !pList[pi].changed) continue;
            var u = uList[ui].val, p = pList[pi].val;
            var k = u + '\x00' + p;
            if (seen[k]) continue;
            seen[k] = true;
            pairs.push({
              user: u,
              password: p,
              userKey: uList[ui].key,
              passKey: pList[pi].key,
              file: curFile,
              isDb: isDb || /(?:db|sql|mysql|pg|mongo|redis)/i.test(uList[ui].key + ' ' + pList[pi].key)
            });
          }
        }
      }
      pairLists(usersMinus, passMinus, false);
      pairLists(usersPlus, passPlus, false);
      if (!pairs.length || (usersMinus.length + usersPlus.length === 0) || (passMinus.length + passPlus.length === 0)) {
        var allU = usersMinus.concat(usersPlus, usersCtx);
        var allP = passMinus.concat(passPlus, passCtx);
        pairLists(allU, allP, true);
      }
      usersMinus = []; usersPlus = []; usersCtx = [];
      passMinus = []; passPlus = []; passCtx = [];
      hunkText = [];
    }

    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var dgM = /^diff --git a\/(\S+)\s+b\/(\S+)/.exec(raw);
      if (dgM) {
        flushHunk();
        inHunk = false;
        curFile = dgM[2] || dgM[1];
        continue;
      }
      var fhM = /^(?:---|\+\+\+)\s+(?:[ab]\/)?(\S+)/.exec(raw);
      if (fhM && fhM[1] !== '/dev/null') {
        flushHunk();
        inHunk = false;
        curFile = fhM[1];
        continue;
      }
      if (/^@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@/.test(raw)) {
        flushHunk();
        inHunk = true;
        continue;
      }
      if (!inHunk) continue;
      var pfx = raw.charAt(0);
      if (pfx !== '+' && pfx !== '-' && pfx !== ' ') {
        if (/^(?:commit\s+[0-9a-f]{7,40}|index\s+[0-9a-f]+\.\.[0-9a-f]+)/i.test(raw)) {
          flushHunk();
          inHunk = false;
        }
        continue;
      }
      var body = raw.slice(1).trim();
      if (!body || /^(?:\/\/|#|\/\*|\*)/.test(body)) continue;
      hunkText.push(body);
      if (pfx === '+' || pfx === '-') {
        var emM = /^(?:[\w.-]+\s*[:=]\s*)?['"]?(?<user>[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}):(?<pw>[^\s'"`;,]{4,64})['"]?[;,]?$/.exec(body);
        if (emM && _valid_diff_token(emM.groups.user, true) && _valid_diff_token(emM.groups.pw, false) && !/^\d{2}(?::\d{2})/.test(emM.groups.pw)) {
          var emKey = emM.groups.user + '\x00' + emM.groups.pw;
          if (!seen[emKey]) {
            seen[emKey] = true;
            pairs.push({
              user: emM.groups.user,
              password: emM.groups.pw,
              userKey: 'email',
              passKey: 'password',
              file: curFile,
              isDb: false
            });
          }
        }
      }
      var um = _DIFF_USER_ASSIGN_RE.exec(body);
      if (um) {
        var uKey = um[1] || um[3], uVal = um[2] || um[4];
        if (!/(?:pass(?:word|wd)?|pwd|secret)/i.test(uKey) && _valid_diff_token(uVal, true)) {
          var uEntry = { key: uKey, val: uVal.trim(), changed: pfx === '+' || pfx === '-' };
          if (pfx === '-') usersMinus.push(uEntry);
          else if (pfx === '+') usersPlus.push(uEntry);
          else usersCtx.push(uEntry);
        }
      }
      var pm = _DIFF_PASS_ASSIGN_RE.exec(body);
      if (pm) {
        var pKey = pm[1] || pm[3], pVal = pm[2] || pm[4];
        if (!/(?:user(?:name)?|usr|uid|login|account)/i.test(pKey) && _valid_diff_token(pVal, false)) {
          var pEntry = { key: pKey, val: pVal.trim(), changed: pfx === '+' || pfx === '-' };
          if (pfx === '-') passMinus.push(pEntry);
          else if (pfx === '+') passPlus.push(pEntry);
          else passCtx.push(pEntry);
        }
      }
    }
    flushHunk();
    return pairs;
  }
  C._extract_diff_cred_pairs = _extract_diff_cred_pairs;

  function _secret_snippets(text) {
    var snippets = [], seen = {};
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim().replace(/^[+-]\s*/, '');
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
    var h = 'host:' + ws.target;
    var branch = '';
    var head = reSearch(C._GIT_HEAD_RE, text);
    if (head) branch = head.groups.branch;
    var lc = (command || '').toLowerCase();
    var hasGitDiff = /^diff --git\s+a\//m.test(text) || (/^commit\s+[0-9a-f]{7,40}\b/m.test(text) && /^@@\s+-\d+/m.test(text)) || (/\bgit\s+(?:show|log|diff)\b/.test(lc) && /^@@\s+-\d+/m.test(text));
    var hasGitDumpSuccess = (lc.indexOf('git-dumper') >= 0 || /\[\+\]\s*Fetching\s+\.git\//i.test(text)) && reSearch(C._GIT_DUMPER_SUCCESS_RE, text);
    var sourceFound = !!head || hasGitDiff || (hasGitDumpSuccess && (!/\b(?:error|failed|not found|403|404)\b/i.test(text) || /(?:Fetching|Downloading)\s+[^\r\n]*\b(?:HEAD|refs\/heads|objects\/pack|config|index)\b|\[\+\]\s*Running\s+git\s+checkout/i.test(text)));
    if (sourceFound) {
      var toolName = (lc.indexOf('git-dumper') >= 0 || /\[\+\]\s*Fetching\s+\.git\//i.test(text)) ? 'git-dumper' : (hasGitDiff ? 'git' : 'curl');
      var value = { kind: 'git', tool: toolName };
      if (branch) value.branch = branch;
      _add(facts, mkFact('web.source', h, value, S, source));
    }
    var diffPairs = _extract_diff_cred_pairs(text);
    diffPairs.forEach(function (pair) {
      var credVal = { user: pair.user, password: pair.password, method: 'git-diff' };
      if (pair.file) credVal.file = pair.file;
      _add(facts, mkFact('credential.plaintext', h, credVal, S, source));
      _add(facts, mkFact('credential.password', h, credVal, S, source));
      _add(facts, mkFact('credential.available', h, credVal, S, source));
      _add(facts, mkFact('credential.candidate', h, { kind: 'git_diff_credential', user: pair.user, password: pair.password, file: pair.file || undefined, via: 'git-diff' }, S, source));
      if (pair.isDb) {
        _add(facts, mkFact('db.creds', h, { user: pair.user, password: pair.password, file: pair.file || undefined, via: 'git-diff' }, S, source));
      }
    });
    var secrets = _secret_snippets(text);
    if (secrets.length && !diffPairs.length) _add(facts, mkFact('credential.candidate', h, { kind: 'source_secret', count: secrets.length, secrets: secrets.slice(0, 20) }, S, source));
  }
  C._parse_git_source = _parse_git_source;

  function _parse_sqlmap(text, ws, source, facts, command) {
    if (!text.trim()) return;
    var h = 'host:' + ws.target;
    var cmdStr = String(command || '') + ' ' + String(source || '');
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
    var hasDumpedTable = tableRefs.length > 0;
    if (!tableRefs.length && /\[\d+\s+tables?\]/i.test(text)) {
      var curDbM = /Database:\s*([A-Za-z0-9_$.-]+)/i.exec(text) || /(?:^|\s)-D\s+['"]?([A-Za-z0-9_$.-]+)/i.exec(cmdStr);
      var curDb = curDbM ? curDbM[1] : '';
      var tblBlockRe = /\[\d+\s+tables?\][\s\S]*?\+[+-]+\+\r?\n((?:\|[ \t]*[^\s|\r\n][^|\r\n]*\|\r?\n)+)\+[+-]+\+/gi, tbm;
      while ((tbm = tblBlockRe.exec(text)) !== null) {
        tbm[1].split(/\r?\n/).forEach(function (rLine) {
          var rm = /^\|\s*([A-Za-z0-9_$.-]+)\s*\|$/.exec(rLine.trim());
          if (rm) tableRefs.push({ database: curDb, table: rm[1] });
        });
      }
    }
    if (!tableRefs.length && /\b--dump\b/i.test(cmdStr) && /\+[+-]+\+\r?\n\|/.test(text)) {
      var dumpTblM = /(?:^|\s)-T\s+['"]?([A-Za-z0-9_$.-]+)/i.exec(cmdStr);
      var dumpDbM = /(?:^|\s)-D\s+['"]?([A-Za-z0-9_$.-]+)/i.exec(cmdStr);
      if (dumpTblM) {
        tableRefs.push({ database: dumpDbM ? dumpDbM[1] : '', table: dumpTblM[1] });
        hasDumpedTable = true;
      }
    }
    if (tableRefs.length) {
      _add(facts, mkFact('db.tables', h, { tool: 'sqlmap', tables: tableRefs.slice(0, 50) }, S, source));
      if (!vuln) _add(facts, mkFact('web.sqli_confirmed', h, { tool: 'sqlmap', evidence: 'sqlmap enumerated database tables' }, S, source));
    }
    if (/database management system users privileges:/i.test(text) && /\bprivilege:\s*(?:FILE|SUPER|ALL\s+PRIVILEGES|DBA)\b/i.test(text)) {
      _add(facts, mkFact('db.admin', h, { tool: 'sqlmap', detail: 'elevated DBMS user privilege (FILE/SUPER/DBA) confirmed' }, S, source));
      if (!vuln) _add(facts, mkFact('web.sqli_confirmed', h, { tool: 'sqlmap', evidence: 'sqlmap enumerated DBMS privileges' }, S, source));
    }
    var colSet = {};
    var textNoUrls = text.replace(/https?:\/\/\S+/gi, '');
    reAll(/\b(user(?:name)?|login|email|pass(?:word)?|passwd|pwd|hash|token|api[_-]?key)\b/i, textNoUrls).forEach(function (m) { colSet[m[1].toLowerCase()] = true; });
    var credentialColumns = C.uniqueSortedCI(Object.keys(colSet));
    var hasDumpSignal = !!(reSearch(C._SQLMAP_DUMP_RE, text) || /\bdumped to CSV file\b|\bfetching entries for table\b/i.test(text) || hasDumpedTable);
    if (credentialColumns.length && hasDumpSignal) {
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
    if (_is_sql_client_output(text, ws, '')) return;
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
