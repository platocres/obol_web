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
      var wpMeta = _extract_web_origin(text, '', ws);
      if (!facts.some(function (f) { return f && f.kind === 'http.reachable' && f.scope === h; })) {
        var wpHr = { via: 'wpscan' };
        if (wpMeta.origin) wpHr.origin = wpMeta.origin;
        if (wpMeta.port) wpHr.port = wpMeta.port;
        _add(facts, mkFact('http.reachable', h, wpHr, S, source));
      }
      var techItems = [{ name: 'WordPress', value: cmsVal.version || 'detected' }];
      var seenSlugVer = Object.create(null);
      var stanzas = String(text || '').split(/^\s*\[\+\]\s+/m);
      for (var si = 1; si < stanzas.length; si++) {
        var stz = stanzas[si];
        var locM = /\bLocation:\s*https?:\/\/[^\s'"]*\/wp-content\/(plugins|themes)\/([A-Za-z0-9_.-]+)\/?/i.exec(stz);
        var hdrSlugM = !locM && /^(?:WordPress\s+theme\s+in\s+use:\s*)?([a-z0-9][a-z0-9_-]{1,63})[ \t]*\r?\n/i.exec(stz);
        var verM = /^\s*\|\s*Version:\s*([0-9][0-9.a-zA-Z_-]*)/im.exec(stz);
        if (!verM) continue;
        var extKind = locM ? locM[1].toLowerCase() : (/^WordPress\s+theme\s+in\s+use:/i.test(stz) ? 'themes' : (/\bLocation:\s*https?:\/\/|\bFound By:/i.test(stz) ? 'plugins' : ''));
        var slug = locM ? locM[2] : (hdrSlugM ? hdrSlugM[1] : '');
        if (!extKind || !slug || /^(?:wordpress|headers|xmlrpc|readme|robots|users|enumerating|finished)$/i.test(slug)) continue;
        var extVer = verM[1];
        var svKey = extKind + ':' + slug.toLowerCase() + ':' + extVer;
        if (seenSlugVer[svKey]) continue;
        seenSlugVer[svKey] = 1;
        var isTheme = extKind === 'themes';
        techItems.push({ name: slug, value: extVer, category: isTheme ? 'wordpress-theme' : 'wordpress-plugin' });
        _add(facts, mkFact('exploit.versioned_banner', h, {
          product: (isTheme ? 'WordPress Theme ' : 'WordPress Plugin ') + slug,
          version: extVer,
          search_query: slug + ' ' + extVer,
          via: 'wpscan'
        }, S, source));
      }
      _add(facts, mkFact('web.tech', h, { items: techItems, tool: 'wpscan' }, S, source));
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

  var _POST_FUZZ_DATA_RE = /(?:^|\s)(?:-d|--data(?:-\w+)?)\s+(?:"[^"]*FUZZ[^"]*"|'[^']*FUZZ[^']*'|\S*FUZZ\S*)/;
  var _SQLI_FUZZ_PAYLOAD_RE = /['"\\]|%27|%22|%5c|--|\b(?:or|and|union|select|sleep|waitfor)\b/i;

  function _is_post_body_fuzz_cmd(command) {
    var cmd = String(command || '');
    if (!_POST_FUZZ_DATA_RE.test(cmd)) return false;
    var urls = reAll(/https?:\/\/[^\s'"]+/gi, cmd);
    for (var i = 0; i < urls.length; i++) {
      var uNoQuery = urls[i][0].split('?')[0];
      if (uNoQuery.indexOf('FUZZ') >= 0) return false;
    }
    return true;
  }

  function _parse_web_content(text, ws, source, facts, command) {
    var h = 'host:' + ws.target;
    if (_is_post_body_fuzz_cmd(command)) {
      var sawPostLive = false, sqli500Payload = '';
      reAll(C._WEB_WFUZZ_RE, text).forEach(function (m) {
        if (m.groups.code !== '000') sawPostLive = true;
        if (m.groups.code === '500' && !sqli500Payload && _SQLI_FUZZ_PAYLOAD_RE.test(m.groups.payload || '')) {
          sqli500Payload = (m.groups.payload || '').trim();
        }
      });
      reAll(C._WEB_FFUF_RE, text).forEach(function (m) {
        if (m.groups.code !== '000') sawPostLive = true;
        if (m.groups.code === '500' && !sqli500Payload && _SQLI_FUZZ_PAYLOAD_RE.test(m.groups.token || '')) {
          sqli500Payload = (m.groups.token || '').trim();
        }
      });
      _add(facts, mkFact('web.parameterized', h, { method: 'POST', via: 'post-fuzz', evidence: 'POST body parameter fuzzing' }, S, source));
      if (sawPostLive && !facts.some(function (f) { return f && f.kind === 'http.reachable' && f.scope === h; })) {
        var pfMeta = _extract_web_origin(text, command, ws);
        var pfHr = { via: 'post-fuzz' };
        if (pfMeta.origin) pfHr.origin = pfMeta.origin;
        if (pfMeta.port) pfHr.port = pfMeta.port;
        _add(facts, mkFact('http.reachable', h, pfHr, S, source));
      }
      if (sqli500Payload) {
        _add(facts, mkFact('web.sqli_candidate', h, { method: 'POST', via: 'post-fuzz-500', payload: sqli500Payload.slice(0, 80) }, S, source));
      }
      return;
    }
    var paths = {}, pathCodes = Object.create(null), hasLiveStatus = false;
    function recordPath(normP, code) {
      if (!normP) return;
      paths[normP] = true;
      if (code) {
        var cStr = String(code);
        if (!pathCodes[normP] || /^(?:200|201|204|301|302|307|308)$/.test(cStr)) pathCodes[normP] = cStr;
        if (/^(?:200|201|204|301|302|307|308|401|403)$/.test(cStr)) hasLiveStatus = true;
      }
    }
    var isGobusterCtx = /\bgobuster\b/i.test(command || '') || /\bGobuster\s+v?\d/i.test(text || '') || /\(Status:\s*\d{3}\)[ \t]+\[Size:\s*\d+\]/i.test(text || '');
    reAll(C._WEB_GOBUSTER_RE, text).forEach(function (m) {
      if (m.groups.code !== '404') {
        var rawP = m.groups.path || '';
        var normP = rawP.charAt(0) === '/' || /^https?:\/\//i.test(rawP) ? C._url_path(rawP) : C._url_path('/' + rawP);
        recordPath(normP, m.groups.code);
      }
    });
    reAll(_GOBUSTER_REL_RE, text).forEach(function (m) {
      if (m.groups.code === '404') return;
      var rawRel = (m.groups.path || '').trim();
      if (!rawRel) return;
      if (rawRel.charAt(0) !== '/' && !m.groups.origin && !isGobusterCtx) return;
      var normRel = rawRel.charAt(0) === '/' ? C._url_path(rawRel) : C._url_path('/' + rawRel);
      recordPath(normRel, m.groups.code);
    });
    reAll(C._WEB_FEROX_RE, text).forEach(function (m) { if (m.groups.code !== '404') recordPath(C._url_path(m.groups.url), m.groups.code); });
    reAll(C._WEB_DIRB_RE, text).forEach(function (m) { if (m.groups.code !== '404') recordPath(C._url_path(m.groups.url), m.groups.code); });
    if (C._WEB_DIRSEARCH_RE) {
      reAll(C._WEB_DIRSEARCH_RE, text).forEach(function (m) {
        if (m.groups.code !== '404') recordPath(C._url_path(m.groups.path || m.groups.url), m.groups.code);
      });
    }
    reAll(C._WEB_FFUF_RE, text).forEach(function (m) {
      var token = m.groups.token;
      if (m.groups.code === '404' || token[0] === ':' || token.toLowerCase() === 'status' || token === '[Status:') return;
      var p = /^https?:\/\//i.test(token) ? C._url_path(token) : (token[0] === '/' ? token : '/' + token);
      recordPath(p, m.groups.code);
    });
    reAll(/\[\s*Status:\s*(?<code>\d{3})[^\]]*\][\s\S]{0,160}?\|\s*URL\s*\|\s*(?<url>https?:\/\/\S+)/gi, text).forEach(function (m) {
      if (m.groups.code !== '404') recordPath(C._url_path(m.groups.url), m.groups.code);
    });
    reAll(C._WEB_WFUZZ_RE, text).forEach(function (m) {
      if (m.groups.code === '404') return;
      var payload = m.groups.payload.trim();
      if (!payload) return;
      var p = /^https?:\/\//i.test(payload) ? C._url_path(payload) : (payload[0] === '/' ? payload : '/' + payload);
      recordPath(p, m.groups.code);
    });
    if (command && C._is_web_content_command && C._is_web_content_command(command)) {
      reAll(/^\s*(?<url>https?:\/\/[^\s"'<>]+)\s*$/gim, text).forEach(function (m) {
        var p = C._url_path(m.groups.url);
        if (p && p !== '/') {
          recordPath(p, '200');
        }
      });
    }
    var keys = Object.keys(paths).filter(function (p) { return p && p.toLowerCase().indexOf('http') !== 0; });
    if (!keys.length) return;
    var h = 'host:' + ws.target;
    var ordered = C.uniqueSortedCI(keys);
    var meta = _extract_web_origin(text, command, ws);
    var value = { paths: ordered.slice(0, 500), count: ordered.length };
    if (meta.origin) value.origin = meta.origin;
    if (meta.port) value.port = meta.port;
    var interesting = ordered.filter(function (p) { return reSearch(C._WEB_INTERESTING_RE, p); });
    if (interesting.length) value.interesting = interesting.slice(0, 200);
    _add(facts, mkFact('web.content_map', h, value, S, source));
    _add(facts, mkFact('web.paths', h, value, S, source));
    if (hasLiveStatus && !facts.some(function (f) { return f && f.kind === 'http.reachable' && f.scope === h; })) {
      var hrVal = { via: 'web-content' };
      if (meta.origin) hrVal.origin = meta.origin;
      if (meta.port) hrVal.port = meta.port;
      _add(facts, mkFact('http.reachable', h, hrVal, S, source));
    }
    var wpCoreSeen = Object.create(null), wpCoreCount = 0;
    for (var wpi = 0; wpi < ordered.length; wpi++) {
      var wpM = /^\/(wp-admin|wp-content|wp-includes|wp-login\.php|xmlrpc\.php)(?:\/|$|\?)/i.exec(ordered[wpi]);
      if (wpM) {
        var wpKey = wpM[1].toLowerCase();
        if (!wpCoreSeen[wpKey]) { wpCoreSeen[wpKey] = 1; wpCoreCount++; }
      }
    }
    if (wpCoreCount >= 2 && !facts.some(function (f) { return f && f.kind === 'web.cms' && f.scope === h; })) {
      _add(facts, mkFact('web.cms', h, { cms: 'wordpress', via: 'web-content' }, S, source));
    }
    var loginPath = ordered.find(function (p) {
      if (!/^\/(?:wp-login\.php|(?:[a-z0-9_-]+\/)?login(?:\.php|\.html|\.htm|\.aspx|\.asp|\.jsp)?|signin(?:\.php|\.html)?)(?:\/|$|\?)/i.test(p)) return false;
      var code = pathCodes[p];
      return !code || /^(?:200|301|302|307|308)$/.test(code);
    });
    if (loginPath && !facts.some(function (f) { return f && f.kind === 'web.login_form' && f.scope === h; })) {
      _add(facts, mkFact('web.login_form', h, { path: loginPath, evidence: 'login endpoint discovered: ' + loginPath, via: 'web-content' }, S, source));
    }
    var uploadPath = ordered.find(function (p) { return /(?:^|\/)upload(?:s|\.[a-z0-9]+)?(?:\b|\/|$)/i.test(p); });
    if (uploadPath) _add(facts, mkFact('web.upload_form', h, { path: uploadPath, evidence: 'upload endpoint discovered: ' + uploadPath }, S, source));
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
      var effCmd = String(command || (obj.commandline || ''));
      var h = 'host:' + ws.target;
      if (_is_post_body_fuzz_cmd(effCmd)) {
        var sawLive = false, sqliPay = '';
        obj.results.forEach(function (r) {
          if (!r) return;
          if (r.status) sawLive = true;
          var fz = (r.input && r.input.FUZZ) ? String(r.input.FUZZ) : '';
          if (r.status === 500 && !sqliPay && _SQLI_FUZZ_PAYLOAD_RE.test(fz)) sqliPay = fz;
        });
        _add(facts, mkFact('web.parameterized', h, { method: 'POST', via: 'post-fuzz', evidence: 'POST body parameter fuzzing' }, S, source));
        if (sawLive && !facts.some(function (f) { return f && f.kind === 'http.reachable' && f.scope === h; })) {
          _add(facts, mkFact('http.reachable', h, { via: 'post-fuzz' }, S, source));
        }
        if (sqliPay) {
          _add(facts, mkFact('web.sqli_candidate', h, { method: 'POST', via: 'post-fuzz-500', payload: sqliPay.slice(0, 80) }, S, source));
        }
        return true;
      }
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

  function _extract_http_request_only(cmd, t) {
    var parts = [String(cmd || '')];
    var lines = String(t || '').split(/\r?\n/);
    var inRawReq = false;
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (/^>\s*/.test(ln)) {
        parts.push(ln.replace(/^>\s*/, ''));
        continue;
      }
      if (i === 0 && /^(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\/\S*\s+HTTP\/[12]/i.test(ln)) {
        inRawReq = true;
      }
      if (inRawReq) {
        if (/^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/i.test(ln)) break;
        parts.push(ln);
      }
    }
    return parts.join('\n');
  }

  function _parse_xml_ldap_bind_creds(text, ws, source, facts) {
    var t = String(text || '');
    if (t.indexOf('<bind-dn>') < 0 || t.indexOf('<bind-password>') < 0) return;
    var h = 'host:' + ws.target;
    var dnRe = /<bind-dn>\s*CN=([^,<\r\n]+)\s*,\s*([^<\r\n]*DC=[^<\r\n]+)<\/bind-dn>/gi;
    var pwM = /<bind-password>\s*([^<\r\n]+?)\s*<\/bind-password>/i.exec(t);
    if (!pwM || !pwM[1]) return;
    var bindPw = pwM[1].trim();
    var dm;
    while ((dm = dnRe.exec(t)) !== null) {
      var bindUser = dm[1].trim();
      var fullDn = 'CN=' + bindUser + ',' + dm[2].trim();
      var dcParts = reAll(/DC=([A-Za-z0-9-]+)/gi, fullDn).map(function (m) { return m[1]; });
      var domainName = dcParts.join('.').toLowerCase();
      var baseDn = dcParts.map(function (p) { return 'DC=' + p; }).join(',');
      if (domainName) {
        var domScope = 'domain:' + domainName;
        _add(facts, mkFact('ad.domain_known', domScope, { domain: domainName, via: 'xml-bind-dn' }, S, source));
        _add(facts, mkFact('ad.base_dn', domScope, { base_dn: baseDn, domain: domainName, via: 'xml-bind-dn' }, S, source));
        _add(facts, mkFact('host.domain', h, { domain: domainName, via: 'xml-bind-dn' }, S, source));
      }
      if (C._add_plaintext_credential) {
        C._add_plaintext_credential(facts, ws, source, bindUser, bindPw, domainName, 'xml-bind-dn');
      } else {
        var cv = { user: bindUser, password: bindPw, domain: domainName || undefined, method: 'xml-bind-dn' };
        _add(facts, mkFact('credential.plaintext', h, cv, S, source));
        _add(facts, mkFact('credential.password', h, cv, S, source));
        _add(facts, mkFact('credential.available', h, cv, S, source));
      }
      _add(facts, mkFact('credential.candidate', h, { kind: 'ldap_bind_credential', user: bindUser, password: bindPw, domain: domainName || undefined, via: 'xml-bind-dn' }, S, source));
    }
  }
  C._parse_xml_ldap_bind_creds = _parse_xml_ldap_bind_creds;

  function _parse_web_surface(text, ws, command, source, facts) {
    if (_is_sql_client_output(text, ws, command)) return;
    if (C._is_public_reference_http_cmd && C._is_public_reference_http_cmd(command, ws)) return;
    if (C._is_outbound_simplehttp_callback && C._is_outbound_simplehttp_callback(text, command, ws)) return;
    if (/\bftp:\/\/[^\s'"]+/i.test(command || '') && !/\bhttps?:\/\/[^\s'"]+/i.test(command || '') && !/^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(text || '')) return;
    var t = text || '', cmd = command || '', h = 'host:' + ws.target;
    var cmdAndText = cmd + '\n' + t;
    var reqOnlyText = _extract_http_request_only(cmd, t);
    var hasHtmlFormMarkup = /<(?:form|input|html|body)\b/i.test(t);
    var hasOcrLogin = reSearch(_OCR_USER_INPUT_RE, t) && reSearch(_OCR_PASS_INPUT_RE, t);
    var isOcrUrlPage = /^URL:\s*https?:\/\/\S+/im.test(t) || /^(?:GET|POST|HEAD)\s+https?:\/\/\S+/i.test(cmd);
    var isHttpExchange = /\b(?:curl|wget|httpie)\b/i.test(cmd)
      || /^(?:[<>]\s*)?(?:POST|GET)\s+\/\S+\s+HTTP\/[12]/im.test(t)
      || /^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(t)
      || isOcrUrlPage;
    var hasHttpAuthParams = isHttpExchange && reSearch(_HTTP_AUTH_PARAM_USER_RE, reqOnlyText) && reSearch(_HTTP_AUTH_PARAM_PASS_RE, reqOnlyText);
    var hasHttpAuthPost = isHttpExchange && reSearch(_HTTP_AUTH_ENDPOINT_RE, reqOnlyText)
      && (/\s(?:-d|--data(?:-\w+)?|-F)\s/i.test(' ' + cmd) || /^(?:>\s*)?POST\s+\//im.test(reqOnlyText) || hasHttpAuthParams);
    var hasConnFailure = /curl:\s*\(\d+\)|Connection refused|Could not resolve host|The remote name could not be resolved|WebCmdletWebResponseException|Invoke-WebRequest[^\r\n]*WebException|Name or service not known|Temporary failure in name resolution|Failed to connect|No route to host/i.test(t);
    var isHelpOrVerCmd = /(?:^|\s)(?:--help|-h|--version|-V|--manual|-M)(?:\s|$)/.test(cmd)
      || /^\s*Usage:\s*(?:curl|wget|http)\b/im.test(t);
    var isOutboundReqOnly = !!(C._is_outbound_http_request_only && C._is_outbound_http_request_only(t));
    var hasLiveCmdResponse = t.trim().length > 0 && !hasConnFailure && !isHelpOrVerCmd && !isOutboundReqOnly && !/^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+404\b/im.test(t);

    var hasInboundHttpReq = !isHelpOrVerCmd && /^(?:[<>]\s*)?(?:POST|GET)\s+\/\S+\s+HTTP\/[12]/im.test(t);
    if (!isHelpOrVerCmd && (((hasLiveCmdResponse || hasInboundHttpReq) && reSearch(_PARAM_URL_RE, reqOnlyText)) || (hasHtmlFormMarkup && (reSearch(_PARAM_URL_RE, t) || reSearch(_FORM_INPUT_RE, t))) || (hasLiveCmdResponse && reSearch(_PARAM_URL_RE, cmd)) || hasOcrLogin || hasHttpAuthParams || hasHttpAuthPost)) {
      _add(facts, mkFact('web.parameterized', h, { evidence: hasOcrLogin ? 'OCR browser form input controls' : 'parameter or form input observed' }, S, source));
    }
    if (!isHelpOrVerCmd && hasHtmlFormMarkup && reSearch(_UPLOAD_FORM_RE, t)) _add(facts, mkFact('web.upload_form', h, { evidence: 'file-upload form' }, S, source));
    if (!isHelpOrVerCmd && ((hasHtmlFormMarkup && reSearch(_LOGIN_FORM_RE, t)) || hasOcrLogin || hasHttpAuthPost || (hasHttpAuthParams && /\s(?:-d|--data(?:-\w+)?|-F)\s/i.test(' ' + cmd)))) {
      _add(facts, mkFact('web.login_form', h, { evidence: hasOcrLogin ? 'OCR browser login form controls' : 'password input form' }, S, source));
    }
    if (!isHelpOrVerCmd && (hasOcrLogin || (isOcrUrlPage && t.trim().length > 0 && !isOutboundReqOnly) || ((hasHttpAuthParams || hasHttpAuthPost) && t.trim().length > 0 && !isOutboundReqOnly) || (/\b(?:curl|wget|httpie)\b/i.test(cmd) && hasLiveCmdResponse)) && !hasConnFailure) {
      _add(facts, mkFact('http.reachable', h, { via: hasOcrLogin ? 'ocr-surface' : (isOcrUrlPage ? 'web-page' : ((hasHttpAuthParams || hasHttpAuthPost) ? 'http-auth-surface' : 'http-client')) }, S, source));
    }

    // Manual boolean-blind / time-based SQL injection probes in curl/wget/httpie requests
    if (!isHelpOrVerCmd && hasLiveCmdResponse && /\b(?:curl|wget|httpie)\b/i.test(cmd)
        && /(?:[\s+'"(&?]|%[0-9A-Fa-f]{2})(?:and|or)(?:[\s+'")&]|%[0-9A-Fa-f]{2})[^\r\n]{0,96}?(?:(?:substring|substr|mid|ascii|ord|pg_sleep|sleep|benchmark)\s*(?:\(|%28)|@@version\b|waitfor(?:%20|\+|\s)+delay)/i.test(cmd)) {
      _add(facts, mkFact('web.parameterized', h, { evidence: 'SQL expression probe in HTTP request' }, S, source));
      _add(facts, mkFact('web.sqli_candidate', h, { via: 'manual-probe', evidence: 'boolean or time-based SQL probe in HTTP request' }, S, source));
    }

    // Laravel session cookie
    if (/^\s*(?:<\s*)?Set-Cookie:\s*laravel_session=/im.test(t)) {
      _add(facts, mkFact('web.tech', h, { name: 'laravel', product: 'Laravel', via: 'cookie' }, S, source));
      if (!hasConnFailure) _add(facts, mkFact('http.reachable', h, { via: 'laravel-cookie' }, S, source));
    }

    // GraphQL introspection & validation errors
    if (/"data"\s*:\s*\{[\s\S]{0,600}?"__(?:schema|type)"\s*:/.test(t)) {
      _add(facts, mkFact('web.graphql_schema', h, { introspection: true, via: 'graphql-introspection' }, S, source));
      _add(facts, mkFact('web.tech', h, { name: 'graphql', product: 'GraphQL', via: 'introspection' }, S, source));
      if (!hasConnFailure) _add(facts, mkFact('http.reachable', h, { via: 'graphql' }, S, source));
    } else if (/"errors"\s*:\s*\[[\s\S]{0,600}?Cannot query field\b/i.test(t)) {
      _add(facts, mkFact('web.tech', h, { name: 'graphql', product: 'GraphQL', via: 'validation-error' }, S, source));
      if (!hasConnFailure) _add(facts, mkFact('http.reachable', h, { via: 'graphql' }, S, source));
    }

    // Spring Boot /actuator/sessions active session map
    var hasActuatorSessionsCtx = /actuator\/sessions\b/i.test(cmdAndText);
    var jsonBodyCand = t.trim();
    var hdrSplitIdx = t.search(/\r?\n\r?\n[\[{]/);
    if (hdrSplitIdx >= 0) jsonBodyCand = t.slice(hdrSplitIdx).trim();
    var parsedJsonObj = null;
    if (jsonBodyCand && (jsonBodyCand.charAt(0) === '{' || jsonBodyCand.charAt(0) === '[')) {
      try { parsedJsonObj = JSON.parse(jsonBodyCand); } catch (_je) {}
    }
    if (parsedJsonObj && typeof parsedJsonObj === 'object' && !Array.isArray(parsedJsonObj)) {
      var jKeys = Object.keys(parsedJsonObj);
      var allSessionPairs = jKeys.length > 0 && jKeys.every(function (k) {
        var v = parsedJsonObj[k];
        return /^(?:[0-9a-fA-F]{24,64}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})$/.test(k)
          && typeof v === 'string' && /^[A-Za-z0-9_.@-]{2,64}$/.test(v);
      });
      var sessionsArr = Array.isArray(parsedJsonObj.sessions) ? parsedJsonObj.sessions : null;
      if (hasActuatorSessionsCtx || allSessionPairs || (sessionsArr && sessionsArr.some(function (s) { return s && s.id && (s.principalName || s.username); }))) {
        var actUsers = [];
        if (sessionsArr) {
          sessionsArr.forEach(function (s) {
            if (!s || typeof s !== 'object') return;
            var su = s.principalName || s.username || '';
            var sid = s.id || s.sessionId || '';
            if (typeof su === 'string' && /^[A-Za-z0-9_.@-]{2,64}$/.test(su) && sid) {
              actUsers.push(su);
              _add(facts, mkFact('credential.candidate', h, { kind: 'session_token', user: su, token: String(sid), service: 'http', endpoint: '/actuator/sessions', via: 'actuator-sessions' }, S, source));
            }
          });
        }
        jKeys.forEach(function (k) {
          var v = parsedJsonObj[k];
          if (typeof v === 'string' && /^[A-Za-z0-9_.@-]{2,64}$/.test(v)) {
            actUsers.push(v);
            _add(facts, mkFact('credential.candidate', h, { kind: 'session_token', user: v, token: k, service: 'http', endpoint: '/actuator/sessions', via: 'actuator-sessions' }, S, source));
          }
        });
        if (actUsers.length) {
          var uniqAct = C.uniqueSortedCI(actUsers);
          _add(facts, mkFact('web.actuator', h, { endpoint: '/actuator/sessions', users: uniqAct, count: uniqAct.length }, S, source));
          if (!hasConnFailure) _add(facts, mkFact('http.reachable', h, { via: 'actuator-sessions' }, S, source));
        }
      }
    }

    // Valid non-error JSON API response over curl/wget/httpie -> http.reachable
    if (parsedJsonObj !== null && !hasConnFailure && /\b(?:curl|wget|httpie)\b/i.test(cmd)
        && !facts.some(function (f) { return f && f.kind === 'http.reachable' && f.scope === h; })) {
      _add(facts, mkFact('http.reachable', h, { via: 'json-api' }, S, source));
    }

    // XML LDAP <bind-dn> + <bind-password> configuration response
    _parse_xml_ldap_bind_creds(t, ws, source, facts);

    // Web application user roster sections (e.g., "REGISTERED USERS" / "ACTIVE USERS" / "USER LIST")
    if ((isHttpExchange || hasHtmlFormMarkup) && !hasConnFailure && /\b(?:REGISTERED|ACTIVE|DIRECTORY)\s+USERS\b|\bUSERS?\s+LIST\b/i.test(t)) {
      var rLines = t.replace(/<[^>]+>/g, '\n').split(/\r?\n/);
      var inRoster = false, rosterUsers = [];
      for (var rli = 0; rli < rLines.length; rli++) {
        var rln = rLines[rli].trim();
        if (!inRoster) {
          if (/^(?:REGISTERED\s+USERS|ACTIVE\s+USERS|DIRECTORY\s+USERS|USERS?\s+LIST)\s*:?\s*$/i.test(rln)) {
            inRoster = true;
          }
          continue;
        }
        if (!rln) continue;
        var rEntryM = /^([A-Za-z][A-Za-z0-9_.-]{1,31})(?:\s*:\s*(?:ID-[A-Za-z0-9_-]+|Active|Disabled|Enabled|Inactive|Online|Offline|Admin|User|Guest|\d+)|\s+(?:Active|Disabled|Enabled|Inactive|Online|Offline))$/i.exec(rln);
        if (rEntryM) {
          var ru = rEntryM[1];
          if (!/^(?:user|users|username|status|total|listing|name|account|phone|ip|id|none|null)$/i.test(ru)
              && (!C._valid_username || C._valid_username(ru, false))) {
            rosterUsers.push(ru);
          }
          continue;
        }
        if (rosterUsers.length >= 2) break;
      }
      var uniqRoster = C.uniqueSortedCI(rosterUsers);
      if (uniqRoster.length >= 2) {
        _add(facts, mkFact('web.users', h, { users: uniqRoster, count: uniqRoster.length, via: 'web-roster' }, S, source));
      }
    }

    // Inline labeled credential disclosures on web notes/pages (e.g., "my creds for gogs: user:secret")
    if ((isHttpExchange || hasHtmlFormMarkup) && !hasConnFailure && !isOutboundReqOnly && /\b(?:creds?|credentials?|login|account)\b/i.test(t)) {
      var noteCredRe = /\b(?:creds?|credentials?|login|account)\b[^\r\n:]{0,48}:\s*['"]?([A-Za-z_][A-Za-z0-9_.-]{1,31}):([^\s'"<>]{4,128})['"]?\s*$/gim;
      var ncm, seenNotePair = {};
      while ((ncm = noteCredRe.exec(t)) !== null) {
        var nUser = ncm[1], nPass = ncm[2].replace(/[.,;]+$/, '');
        if (/^(?:https?|ftp|mailto|urn|tel|ssh|javascript|localhost)$/i.test(nUser)) continue;
        if (/^\d{1,2}:\d{2}/.test(nPass) || /^\d+$/.test(nUser)) continue;
        if (C._valid_username && !C._valid_username(nUser, false)) continue;
        if (C._valid_password && !C._valid_password(nPass)) continue;
        var nKey = nUser + '\x00' + nPass;
        if (seenNotePair[nKey]) continue;
        seenNotePair[nKey] = 1;
        var noteCv = { user: nUser, password: nPass, service: 'http', method: 'web-note-disclosure' };
        _add(facts, mkFact('credential.plaintext', h, noteCv, S, source));
        _add(facts, mkFact('credential.password', h, noteCv, S, source));
        _add(facts, mkFact('credential.available', h, noteCv, S, source));
        _add(facts, mkFact('credential.candidate', h, { kind: 'web_disclosed_credential', user: nUser, password: nPass, via: 'web-note-disclosure' }, S, source));
      }
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
      if (!um && !pm && /\\r\\n|\\n|(?:user(?:name)?|login)\s*[:=]/i.test(body)) {
        var subLines = body.replace(/\\r\\n|\\n/g, '\n').split('\n');
        for (var sli = 0; sli < subLines.length; sli++) {
          var sub = subLines[sli].trim().replace(/^['"`]+|['"`;,]+$/g, '');
          var inlU = /(?:^|\b)(user(?:name)?|login|uid|account)\s*[:=]\s*([^\s'"\\;,]{2,96})/i.exec(sub);
          if (inlU && _valid_diff_token(inlU[2], true)) {
            var inlUEnt = { key: inlU[1], val: inlU[2].trim(), changed: pfx === '+' || pfx === '-' };
            if (pfx === '-') usersMinus.push(inlUEnt);
            else if (pfx === '+') usersPlus.push(inlUEnt);
            else usersCtx.push(inlUEnt);
          }
          var inlP = /(?:^|\b)(pass(?:word|wd)?|pwd|secret)\s*[:=]\s*([^\s'"\\;,]{3,128})/i.exec(sub);
          if (inlP && _valid_diff_token(inlP[2], false)) {
            var inlPEnt = { key: inlP[1], val: inlP[2].trim(), changed: pfx === '+' || pfx === '-' };
            if (pfx === '-') passMinus.push(inlPEnt);
            else if (pfx === '+') passPlus.push(inlPEnt);
            else passCtx.push(inlPEnt);
          }
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
    var gitHead200M = /Testing\s+(https?:\/\/[^\s]+\/\.git\/HEAD)\s+\[200\]/i.exec(text);
    if (gitHead200M) {
      _add(facts, mkFact('http.exposed', h, { kind: 'git', url: gitHead200M[1], path: '/.git/HEAD', status: 200, tool: 'git-dumper' }, S, source));
      _add(facts, mkFact('web.exposed_artifact', h, { kind: 'git', url: gitHead200M[1], path: '/.git/HEAD' }, S, source));
      _add(facts, mkFact('http.reachable', h, { via: 'git-dumper' }, S, source));
    }
    var hasGitDumpSuccess = ((lc.indexOf('git-dumper') >= 0 || /\[\+\]\s*Fetching\s+\.git\//i.test(text)) && reSearch(C._GIT_DUMPER_SUCCESS_RE, text)) || !!gitHead200M;
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
    var asciiTblRe = /^\+(?:-+\+)+[ \t]*\r?\n\|([^\r\n]+)\|[ \t]*\r?\n\+(?:-+\+)+[ \t]*\r?\n((?:\|[^\r\n]+\|[ \t]*\r?\n)+)\+(?:-+\+)+/gm;
    var atm;
    while ((atm = asciiTblRe.exec(text)) !== null) {
      var hdrCells = atm[1].split('|').map(function (c) { return c.trim(); });
      var uIdx = -1, pIdx = -1;
      for (var hci = 0; hci < hdrCells.length; hci++) {
        var hc = hdrCells[hci];
        if (uIdx < 0 && /^(?:user(?:_?name)?|uname|login|email|account|usr|admin(?:_?user)?)$/i.test(hc)) uIdx = hci;
        else if (pIdx < 0 && /^(?:pass(?:word|wd|_?hash)?|pwd|hash|secret|user_pass)$/i.test(hc)) pIdx = hci;
      }
      if (uIdx < 0 || pIdx < 0) continue;
      hasDumpedTable = true;
      var dataRows = atm[2].split(/\r?\n/);
      for (var dri = 0; dri < dataRows.length; dri++) {
        var dr = dataRows[dri].trim();
        if (!dr || dr.charAt(0) !== '|') continue;
        var rowInner = dr.slice(1, dr.charAt(dr.length - 1) === '|' ? -1 : dr.length);
        var cells = rowInner.split('|').map(function (c) { return c.trim(); });
        if (uIdx >= cells.length || pIdx >= cells.length) continue;
        var rUser = cells[uIdx], rSec = cells[pIdx];
        if (!rUser || !rSec || /^(?:<blank>|null|none|-+)$/i.test(rUser) || /^(?:<blank>|null|none|-+)$/i.test(rSec)) continue;
        var crackedInlineM = /^([0-9a-fA-F]{16,128}|\$[^\s(]+|\*[0-9A-Fa-f]{40})\s+\(([^)\r\n]{1,64})\)$/.exec(rSec);
        if (crackedInlineM) {
          var crPw = crackedInlineM[2].trim();
          if (C._add_plaintext_credential) C._add_plaintext_credential(facts, ws, source, rUser, crPw, '', 'sqlmap-dump');
          _add(facts, mkFact('db.creds', h, { user: rUser, password: crPw, tool: 'sqlmap', via: 'sqlmap-dump' }, S, source));
        } else if (/^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}|\*[0-9A-Fa-f]{40}|\$(?:1|2[abxy]|5|6|y|P|H|apr1|pbkdf2)[^\s]*|pbkdf2_sha\d+\$[^\s]+|sha256:\d+:[^\s]+)$/i.test(rSec)) {
          _add(facts, mkFact('hash.crackable', h, { user: rUser, hash: rSec, via: 'sqlmap-dump' }, S, source));
          _add(facts, mkFact('credential.candidate', h, { kind: 'database_dump_hash', user: rUser, hash: rSec, via: 'sqlmap-dump' }, S, source));
        } else {
          if (C._add_plaintext_credential) C._add_plaintext_credential(facts, ws, source, rUser, rSec, '', 'sqlmap-dump');
          _add(facts, mkFact('db.creds', h, { user: rUser, password: rSec, tool: 'sqlmap', via: 'sqlmap-dump' }, S, source));
        }
      }
    }
    var credentialColumns = C.uniqueSortedCI(Object.keys(colSet));
    var hasDumpSignal = !!(reSearch(C._SQLMAP_DUMP_RE, text) || /\bdumped to CSV file\b|\bfetching entries for table\b/i.test(text) || hasDumpedTable);
    if (credentialColumns.length && hasDumpSignal) {
      var v2 = { tool: 'sqlmap', credential_columns: credentialColumns.slice(0, 20) };
      if (tableRefs.length) v2.tables = tableRefs.slice(0, 20);
      _add(facts, mkFact('db.creds', h, v2, S, source));
      _add(facts, mkFact('credential.candidate', h, { kind: 'database_dump_secret', count: credentialColumns.length, sources: credentialColumns.slice(0, 20) }, S, source));
      if (!vuln && !tableRefs.length) _add(facts, mkFact('web.sqli_confirmed', h, { tool: 'sqlmap', evidence: 'sqlmap dumped table credentials' }, S, source));
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
    var adminIniMd5M = /(?:^|\r?\n)\s*(?:\[Administrator\][\s\S]{0,240}?\r?\n\s*Password|AdministratorPassword)\s*=\s*([0-9a-fA-F]{32})\b/i.exec(text || '');
    if (adminIniMd5M) {
      osFamily = osFamily || 'windows';
      var iniParam = reSearch(C._LFI_FILE_PARAM_RE, command);
      var iniFile = iniParam ? iniParam.groups.path : 'administrator_ini';
      filesRead.push(iniFile);
      var md5Hex = adminIniMd5M[1].toLowerCase();
      if (isLfiMove && !isXxe) _add(facts, mkFact('web.lfi_confirmed', h, { file: iniFile, os: 'windows', method: method, evidence: '[Administrator] Password=' + md5Hex }, S, source));
      _add(facts, mkFact('hash.crackable', h, { user: 'Administrator', hash: md5Hex, format: 'raw-md5', hash_type: 'md5', via: 'lfi' }, S, source));
      _add(facts, mkFact('credential.candidate', h, { kind: 'hashed_ini_password', user: 'Administrator', hash: md5Hex, hash_type: 'md5', via: 'lfi' }, S, source));
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
    if (osFamily) C._add_os_observation(facts, ws, source, osFamily, (passwdHead || shadowHead || environHit || win) ? C._line_for_match(text, passwdHead || shadowHead || environHit || win) : osFamily, 'high', 'web-' + (actionId || 'lfi'), true);
  }
  C._parse_web_lfi = _parse_web_lfi;

  var _WEBSHELL_UPLOAD_RECEIPT_RE = /(?:(?:File\s+Renamed\s+to|Shell\s+(?:Uploaded|URL|Location|Ready)|Uploaded\s+(?:to|shell|file)?|Webshell\s+(?:at|url|uploaded|location)?)\s*(?:!?\s*(?:Access\s+at|URL|at))?\s*[:\-=>]+\s*(?:https?:\/\/[^\s"'<>]+|\/[^\s"'<>]+|[A-Za-z0-9_./-]+\.(?:php[0-9]?|phtml|jsp|jspx|asp|aspx))\b|(?:https?:\/\/[^\s"'<>]+|\/[^\s"'<>]*)\/(?:wp-content\/uploads|uploads?|files?|media|content)\/[^\s"'<>]+\.(?:php[0-9]?|phtml|jsp|jspx|asp|aspx)\b)/i;
  var _WEB_EXPLOIT_REPL_WHOAMI_RE = /^[ \t]{0,80}(?:(?:cmd|shell|rce|exploit|pwn|webshell|os-shell)[^>%\r\n]{0,24}[>#$:][ \t]*|(?![ \t\r\n])(?:[^\r\n]{0,80}?\b)?command\b[^:\r\n]{0,40}:[ \t]*(?:execute[ \t]+)?|[>#$][ \t]*)?whoami[ \t]*\r?\n(?:[ \t]*(?:\[[^\]\r\n]{1,24}\][^\r\n]{0,160}|(?:Result|Output|Response)[ \t]*:[ \t]*)?\r?\n){0,2}[ \t]*(www-data|apache|nginx|http|httpd|lighttpd|tomcat\d*|nobody|root)[ \t]*$/im;
  var _WEB_EXPLOIT_PROMPT_WHOAMI_CUSTOM_RE = /^[ \t]{0,80}(?:(?:cmd|shell|rce|exploit|pwn|webshell|os-shell|pseudo-term)[^>%\r\n]{0,24}[>#$:][ \t]*|(?![ \t\r\n])(?:[^\r\n]{0,80}?\b)?command\b[^:\r\n]{0,40}:[ \t]*(?:execute[ \t]+)?|[>#$][ \t]*)whoami[ \t]*\r?\n(?:[ \t]*\r?\n){0,2}[ \t]*([a-z_][a-z0-9_-]{1,31})[ \t]*$/im;
  var _REPL_WHOAMI_DENY_RE = /^(?:whoami|id|pwd|ls|dir|cat|sh|bash|zsh|dash|python[23]?|ruby|perl|php|curl|wget|echo|exit|quit|help|error|warning|failed|failure|denied|forbidden|unauthorized|invalid|null|none|true|false|unknown|not|no|yes|ok|done|connecting|connected|sending|sent|loading|waiting|testing|checking|running|starting|stopped|closed|usage|syntax|exception|traceback|target|host|server|payload|exploit|shell|command|result|output|response|status)$/i;
  C._WEBSHELL_UPLOAD_RECEIPT_RE = _WEBSHELL_UPLOAD_RECEIPT_RE;
  C._WEB_EXPLOIT_REPL_WHOAMI_RE = _WEB_EXPLOIT_REPL_WHOAMI_RE;

  function _decode_pct_ascii(s) {
    return String(s || '').replace(/\+/g, ' ').replace(/%([0-9A-Fa-f]{2})/g, function (full, hx) {
      var code = parseInt(hx, 16);
      return (code >= 0x20 && code <= 0x7e) ? String.fromCharCode(code) : full;
    });
  }

  function _extract_inbound_http_body_for_ssti(text) {
    var t = String(text || '');
    if (/^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(t)) {
      var blocks = t.split(/\r?\n\r?\n/);
      var lastHdrIdx = -1;
      for (var bi = 0; bi < blocks.length; bi++) {
        if (/^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(blocks[bi])) lastHdrIdx = bi;
      }
      if (lastHdrIdx >= 0 && lastHdrIdx + 1 < blocks.length) {
        return blocks.slice(lastHdrIdx + 1).join('\n\n');
      }
    }
    return t.replace(/^[ \t]*>[ \t]*[^\r\n]*$/gm, '');
  }

  function _detect_arithmetic_ssti(cmdStr, text) {
    var reqProbe = _decode_pct_ascii(cmdStr) + '\n' + _decode_pct_ascii(_extract_http_request_only(cmdStr, text));
    if (!/(?:\{\{|\$\{|<%=|#\{)/.test(reqProbe)) return null;
    var respBody = _extract_inbound_http_body_for_ssti(text);
    if (!/\S/.test(respBody)) return null;

    function validDelimPair(openD, closeD) {
      if (openD === '{{') return closeD === '}}';
      if (openD === '<%=') return closeD === '%>';
      return (openD === '${' || openD === '#{') && closeD === '}';
    }

    var mulRe = /(\{\{|\$\{|<%=|#\{)\s*(\d{1,5})\s*\*\s*(\d{1,5})\s*(\}\}|\}|%>)/g;
    var mm;
    while ((mm = mulRe.exec(reqProbe)) !== null) {
      if (!validDelimPair(mm[1], mm[4])) continue;
      var a = parseInt(mm[2], 10), b = parseInt(mm[3], 10);
      var prod = a * b;
      if (!(a >= 2 && b >= 2 && prod >= 10)) continue;
      var rawExpr = mm[0];
      if (respBody.indexOf(rawExpr) >= 0) continue;
      var prodStr = String(prod);
      var valRe = new RegExp('(?:^|[^0-9A-Za-z_.:])(' + prodStr + ')(?![0-9A-Za-z_.:])');
      var vm = valRe.exec(respBody);
      if (vm) {
        return { expression: rawExpr, evaluated: prodStr, match: vm };
      }
    }

    var repRe = /(\{\{|\$\{|<%=|#\{)\s*(?:(\d{1,2})\s*\*\s*['"]([A-Za-z0-9])['"]|['"]([A-Za-z0-9])['"]\s*\*\s*(\d{1,2}))\s*(\}\}|\}|%>)/g;
    var rm;
    while ((rm = repRe.exec(reqProbe)) !== null) {
      if (!validDelimPair(rm[1], rm[6])) continue;
      var cnt = parseInt(rm[2] || rm[5], 10);
      var ch = rm[3] || rm[4];
      if (!(cnt >= 4 && cnt <= 32 && ch)) continue;
      var repStr = new Array(cnt + 1).join(ch);
      if (respBody.indexOf(rm[0]) >= 0) continue;
      var repM = new RegExp('(?:^|[^0-9A-Za-z_])(' + repStr + ')(?:[^0-9A-Za-z_]|$)').exec(respBody);
      if (repM) {
        return { expression: rm[0], evaluated: repStr, match: repM };
      }
    }
    return null;
  }

  function _parse_web_cmdi(actionId, text, ws, command, source, facts) {
    if (C._is_public_reference_http_cmd && C._is_public_reference_http_cmd(command, ws)) return;
    var h = 'host:' + ws.target;
    var cmdStr = String(command || '');
    var cmdAndText = cmdStr + '\n' + (text || '');
    var isContentScannerCmd = (C._is_web_content_command && C._is_web_content_command(cmdStr))
      || /\b(?:gobuster|ffuf|feroxbuster|dirb|dirsearch|wfuzz|nikto|wpscan|whatweb)\b/i.test(cmdStr);
    // SSTI math / config evaluation check (e.g., {{4*4}} -> 16, {{7*7}} -> 49, {{7*'7'}} -> 7777777)
    var arithSsti = !isContentScannerCmd ? _detect_arithmetic_ssti(cmdStr, text) : null;
    if (arithSsti) {
      _add(facts, mkFact('web.ssti_confirmed', h, {
        method: 'template_injection',
        expression: arithSsti.expression,
        evaluated: arithSsti.evaluated,
        evidence: C._line_for_match(text, arithSsti.match)
      }, S, source));
      if ((/\bhttps?:\/\/[^\s'"]+/i.test(cmdAndText) || /\b(?:curl|wget|httpie)\b/i.test(cmdStr))
          && !facts.some(function (f) { return f && f.kind === 'http.reachable' && f.scope === h; })) {
        _add(facts, mkFact('http.reachable', h, { via: 'web-ssti' }, S, source));
      }
    } else if (actionId === 'ssti' || (/(\{\{\s*7\s*\*\s*(?:7|'7')|\$\{\s*7\s*\*\s*7|<%=\s*7\s*\*\s*7)/.test(cmdAndText))) {
      var sstiHit = reSearch(/\b(?:49|7777777)\b|<Config\b|\bssti/i, text);
      if (sstiHit) {
        _add(facts, mkFact('web.ssti_confirmed', h, { method: 'template_injection', evidence: C._line_for_match(text, sstiHit) }, S, source));
      }
    }
    var isHttpOrExploitScriptCtx = !isContentScannerCmd && (
      /\b(?:curl|wget|httpie|burp|ysoserial|python3?|ruby|perl|php)\b/i.test(cmdStr)
      || /\bhttps?:\/\/[^\s'"]+/i.test(cmdAndText)
      || /^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(text || '')
      || /^\s*\[\+\]/m.test(text || '')
    );
    // File upload / verb-tampering HTTP 201, JSON upload success, or exploit webshell upload receipt
    var uploadReceiptHit = !isContentScannerCmd && (
      /\[\+\]|\b(?:uploaded|renamed|webshell|exploit|success|shell)\b|HTTP\/[12](?:\.\d)?\s+20[01]\b/i.test(cmdAndText)
    ) ? reSearch(_WEBSHELL_UPLOAD_RECEIPT_RE, text) : null;
    if (uploadReceiptHit || actionId === 'file-upload' || actionId === 'verb-tampering' || actionId === 'http-put-webshell') {
      var upHit = uploadReceiptHit || reSearch(/"status"\s*:\s*"uploaded"|\b(?:file|shell)\s+uploaded\b|HTTP\/[12](?:\.\d)?\s+201\s+Created/i, text);
      if (upHit) {
        _add(facts, mkFact('web.upload_confirmed', h, { method: 'executable_upload', evidence: C._line_for_match(text, upHit) }, S, source));
      }
    }
    var uid = reSearch(C._CMDI_UID_RE, text) || reSearch(C._LINUX_ID_RE, text);
    var win = reSearch(C._CMDI_WIN_RE, text)
      || reSearch(/\b(?:nt authority\\(?:system|network service|local service)|iis apppool\\[a-z0-9_.-]+)\b/i, text);
    var replWhoami = null;
    if (!uid && !win && !isContentScannerCmd && /\bwhoami\b/i.test(text)) {
      var wm = reSearch(_WEB_EXPLOIT_REPL_WHOAMI_RE, text);
      if (wm) {
        var hasReplPromptPrefix = /^[ \t]{0,80}(?:(?:cmd|shell|rce|exploit|pwn|webshell|os-shell)[^>%\r\n]{0,24}[>#$:][ \t]*|(?![ \t\r\n])(?:[^\r\n]{0,80}?\b)?command\b[^:\r\n]{0,40}:[ \t]*(?:execute[ \t]+)?|[>#$][ \t]*)whoami\b/i.test(wm[0]);
        if (hasReplPromptPrefix || (isHttpOrExploitScriptCtx && !/^\s*whoami\s*$/i.test(cmdStr))) {
          replWhoami = wm;
        }
      } else if (isHttpOrExploitScriptCtx && !/^\s*whoami\s*$/i.test(cmdStr)) {
        var cwm = reSearch(_WEB_EXPLOIT_PROMPT_WHOAMI_CUSTOM_RE, text);
        if (cwm && cwm[1] && !_REPL_WHOAMI_DENY_RE.test(cwm[1])) {
          replWhoami = cwm;
        }
      }
    }
    var hasUploadExecSuccess = !!(uploadReceiptHit && (
      uid || win || replWhoami
      || /\[\+\]\s*(?:[^\r\n]*\b(?:shell|rce|executed|exploited|pwned|success|ready|uploaded)\b)|(?:\bshell\s+(?:uploaded|ready|url|location)\b|\bFile\s+Renamed\s+to\b)/i.test(text)
    ));
    var icmpEchoM = /\bIP\s+(\d{1,3}(?:\.\d{1,3}){3})\s+>\s+\d{1,3}(?:\.\d{1,3}){3}:\s+ICMP\s+echo\s+request\b/i.exec(text || '');
    if (icmpEchoM && (!ws.target || ws.target === 'unknown' || icmpEchoM[1] === ws.target)) {
      _add(facts, mkFact('web.cmdi_confirmed', h, { method: 'os_command_injection', via: 'icmp-callback', source_ip: icmpEchoM[1], evidence: C._line_for_match(text, icmpEchoM) }, S, source));
    }
    if (!uid && !win && !replWhoami && !hasUploadExecSuccess) return;
    var effId = actionId;
    if (!effId || effId === 'operator-ingest') {
      if (uploadReceiptHit) effId = 'file-upload';
      else if (/ysoserial|ObjectInputStream|rO0AB|java\.io/i.test(cmdAndText)) effId = 'deserialization';
      else if (/\/scriptText|--data-urlencode\s+['"]?script=|println\s*\(/i.test(cmdAndText)) effId = 'jenkins-access';
      else if (/ognl|#context|struts/i.test(cmdAndText)) effId = 'check-struts2';
      else if (/\{\{|\$\{/.test(cmdStr)) effId = 'ssti';
      else if (/\.(?:php|jsp|asp|aspx)\?(?:cmd|c|exec)=/i.test(cmdStr)) effId = 'web-shells';
      else effId = 'command-injection';
    }
    var method = { 'command-injection': 'os_command_injection', ssti: 'template_injection', 'web-shells': 'web_shell', 'file-upload': 'uploaded_web_shell', deserialization: 'insecure_deserialization', 'tomcat-deploy': 'tomcat_war_deploy', 'jenkins-access': 'jenkins_script_console' }[effId] || effId;
    var isAspUpload = !!(uploadReceiptHit && /\.(?:asp|aspx)\b/i.test(uploadReceiptHit[0]));
    var osFamily = (uid || replWhoami) ? 'linux' : (win || isAspUpload ? 'windows' : 'linux');
    var activeHit = uid || win || replWhoami || uploadReceiptHit;
    var evidence = C._line_for_match(text, activeHit);
    var cmdiVal = { os: osFamily, method: method, evidence: evidence };
    if (replWhoami && replWhoami[1]) cmdiVal.user = replWhoami[1].toLowerCase();
    _add(facts, mkFact('web.cmdi_confirmed', h, cmdiVal, S, source));
    var hasHttpTransport = /\bhttps?:\/\/[^\s'"]+/i.test(cmdAndText)
      || /^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(text || '')
      || Boolean(replWhoami || uploadReceiptHit)
      || (/\b(?:curl|wget|httpie)\b/i.test(cmdStr) && !/\bftp:\/\/[^\s'"]+/i.test(cmdStr));
    if (hasHttpTransport && !facts.some(function (f) { return f && f.kind === 'http.reachable' && f.scope === h; })) {
      var hrMeta = _extract_web_origin(text, command, ws);
      var hrVal = { via: 'web-cmdi' };
      if (hrMeta.port) hrVal.port = hrMeta.port;
      if (hrMeta.origin) hrVal.origin = hrMeta.origin;
      _add(facts, mkFact('http.reachable', h, hrVal, S, source));
    }
    if (method === 'template_injection') _add(facts, mkFact('web.ssti_confirmed', h, { method: 'template_injection', evidence: evidence }, S, source));
    else if (method === 'insecure_deserialization') _add(facts, mkFact('web.deserial_confirmed', h, { method: 'insecure_deserialization', evidence: evidence }, S, source));
    if (effId === 'file-upload' && !uploadReceiptHit) _add(facts, mkFact('web.upload_confirmed', h, { method: 'executable_upload', evidence: evidence }, S, source));
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
      if (/^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/.test(pw)) return;
      var cred = { password: pw };
      if (docUser) cred.user = docUser;
      var key = (cred.user || '') + '|' + pw;
      if (!seen[key]) { seen[key] = true; out.push(cred); }
    });
    return out.slice(0, 10);
  }
  C._mine_response_credentials = _mine_response_credentials;

  function _parse_web_ssrf(actionId, text, ws, command, source, facts) {
    if (/^\s*(?:sudo\s+)?msfvenom\b|\bLHOST\s*=|\bLPORT\s*=/i.test(command || '')) return;
    var h = 'host:' + ws.target;
    var imds = reSearch(C._IMDS_MARKER_RE, text);
    var akid = reSearch(C._AWS_KEY_RE, text);
    var secret = reSearch(C._AWS_SECRET_RE, text);
    var lhost = (ws && ws.context && ws.context.params && ws.context.params.lhost) || '';
    var isDisclosedServerSource = /(?:<\?php\b|<%@\s*(?:Page|Import|Language)\b|^\s*(?:from\s+(?:flask|django|fastapi)\s+import|import\s+express)\b)/im.test(text || '');
    var hasExplicitSsrfParam = /[?&][A-Za-z0-9_.-]+=(?:https?|gopher|dict|file)(?::\/\/|%3A%2F%2F)/i.test(command || '');
    var internalMatches = (isDisclosedServerSource && !hasExplicitSsrfParam) ? [] : reAll(_INTERNAL_TARGET_RE, text || '');
    var internal = null;
    for (var ii = 0; ii < internalMatches.length; ii++) {
      var candIp = internalMatches[ii][0];
      if (candIp && candIp !== (ws && ws.target) && candIp !== lhost) {
        internal = internalMatches[ii];
        break;
      }
    }
    if (!internal && command) {
      var cmdParamM = /[?&][A-Za-z0-9_.-]+=(?:https?(?::\/\/|%3A%2F%2F))?(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|\[::1\])\b/i.exec(command);
      if (cmdParamM) internal = [cmdParamM[1]];
    }
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
    if (C._is_public_reference_http_cmd && C._is_public_reference_http_cmd(command, ws)) return;
    var isGeneric = !actionId || actionId === 'operator-ingest';
    if (isGeneric || C._WEB_LFI_ACTION_IDS.has(actionId)) _parse_web_lfi(actionId, text, ws, command, source, facts);
    if (isGeneric || C._WEB_CMDI_ACTION_IDS.has(actionId)) {
      if (C._WEB_CMDI_ACTION_IDS.has(actionId) || (/\b(?:curl|wget|httpie|burp|ysoserial|python3?|ruby|perl|php)\b|\bhttps?:\/\/[^\s'"]+/i.test(command || '') || /^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b|<\/?(?:!doctype|html|head|body|pre)\b/im.test(text) || _WEBSHELL_UPLOAD_RECEIPT_RE.test(text) || _WEB_EXPLOIT_REPL_WHOAMI_RE.test(text) || _WEB_EXPLOIT_PROMPT_WHOAMI_CUSTOM_RE.test(text))) {
        _parse_web_cmdi(actionId, text, ws, command, source, facts);
      }
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

  function _parse_web_fingerprint(text, ws, source, facts, command) {
    var t = String(text || '');
    var cmd = String(command || '');
    if (!t.trim() && !cmd.trim()) return;
    if (_is_sql_client_output(t, ws, cmd)) return;
    if (C._is_outbound_simplehttp_callback && C._is_outbound_simplehttp_callback(t, cmd, ws)) return;
    var h = 'host:' + ws.target;
    var jHdrM = reSearch(_FP_JENKINS_RE, t);
    if (jHdrM) {
      _add(facts, mkFact('web.fingerprint.jenkins', h, { via: 'response-header', evidence: C._line_for_match(t, jHdrM) }, S, source));
      var jVerM = /^\s*X-Jenkins\s*:\s*(\d+\.\d+(?:\.\d+)?)\b/im.exec(t);
      if (jVerM && jVerM[1]) {
        var jVer = jVerM[1];
        _add(facts, mkFact('exploit.versioned_banner', h, { product: 'Jenkins', version: jVer, search_query: 'Jenkins ' + jVer, via: 'x-jenkins-header' }, S, source));
        var jParts = jVer.split('.').map(function (n) { return parseInt(n, 10); });
        var isCve2024_23897 = jParts.length === 2
          ? (jParts[0] < 2 || (jParts[0] === 2 && jParts[1] <= 441))
          : (jParts[0] < 2 || (jParts[0] === 2 && (jParts[1] < 426 || (jParts[1] === 426 && jParts[2] <= 2))));
        if (isCve2024_23897) {
          _add(facts, mkFact('vuln.jenkins', h, { product: 'Jenkins', version: jVer, cve: 'CVE-2024-23897', via: 'x-jenkins-header', lead: true }, S, source));
        }
      }
    } else if (reSearch(_FP_JENKINS_BODY_RE, t)) {
      _add(facts, mkFact('web.fingerprint.jenkins', h, { via: 'page-chrome' }, S, source));
    }
    if ((/\bjenkins-cli\.jar\b/i.test(cmd) || /\bjenkins-cli\b/i.test(cmd))
        && (/(?:ERROR:\s*(?:Too many arguments:|Failed to parse\b|No argument is allowed:|CmdLineException)|(?:ERROR:|:\s*)No such (?:job|item|node)\b)/i.test(t)
          || (/\s@\/[^\s'"]+/.test(cmd) && t.trim() && !/\b(?:Connection refused|Unable to Unable|Failed to connect)\b/i.test(t)))) {
      var cliPathM = /\s@(\/[^\s'"]+)/.exec(cmd);
      var cliPath = cliPathM ? cliPathM[1] : 'jenkins_cli_leak';
      _add(facts, mkFact('loot.files', h, { files: [cliPath], path: cliPath, tool: 'jenkins-cli', via: 'jenkins-cli-file-read' }, S, source));
    }
    if (reSearch(_FP_NVMS_RE, t)) {
      _add(facts, mkFact('web.fingerprint.nvms', h, { via: 'product-name', product: 'NVMS-1000' }, S, source));
    }

    // Raw HTTP response header fingerprinting (supports command-less HTTP pastes as well as curl -i/-v)
    if (/^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(t)) {
      var httpStartIdx = t.search(/^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im);
      var fromHttp = httpStartIdx >= 0 ? t.slice(httpStartIdx) : t;
      var blankSepM = /\r?\n\s*(?:<\s*)?\r?\n/.exec(fromHttp);
      var hdrBlock = blankSepM ? fromHttp.slice(0, blankSepM.index) : fromHttp;
      var rawTechItems = [];
      reAll(/^\s*(?:<\s*)?(X-Powered-By|X-Generator|X-AspNet(?:Mvc)?-Version)\s*:\s*([^\r\n]+)/gim, hdrBlock).forEach(function (hm) {
        var hName = hm[1].toLowerCase();
        var hVal = hm[2].trim();
        if (hVal) rawTechItems.push({ name: hName, value: hVal });
      });
      if (rawTechItems.length && !facts.some(function (f) { return f && f.kind === 'web.tech' && f.scope === h; })) {
        _add(facts, mkFact('web.tech', h, { items: rawTechItems, via: 'http-header' }, S, source));
      }
      var backendFqdns = {}, backendDoms = {};
      reAll(/^\s*(?:<\s*)?X-(?:Backend-Server|Served-By|Upstream|Vhost|Host|Original-Host|Forwarded-Server)\s*:\s*([^\r\n]+)/gim, hdrBlock).forEach(function (bm) {
        var cand = String(bm[1] || '').trim().split(/[,;\s]/)[0].replace(/:\d+$/, '').replace(/\.$/, '').toLowerCase();
        if (!cand || cand.indexOf('.') < 0) return;
        if ((C._IPV4_RE && C._IPV4_RE.test(cand)) || /^\d+(?:\.\d+)+$/.test(cand)) return;
        if (/^(?:localhost|ip6-localhost)(?:\.|$)|^cache-[a-z0-9-]+$/i.test(cand)) return;
        if (/\.(?:localdomain|invalid|test|fastly\.net|cloudfront\.net|amazonaws\.com|akamaiedge\.net|akamai\.net|cloudflare\.com)$/i.test(cand)) return;
        if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(cand)) return;
        if (!/\.[a-z][a-z0-9-]{1,}$/.test(cand)) return;
        backendFqdns[cand] = 1;
      });
      Object.keys(backendFqdns).sort().forEach(function (bf) {
        var bParts = bf.split('.').filter(Boolean);
        var bDom = bParts.length > 2 ? bParts.slice(1).join('.') : bf;
        backendDoms[bDom] = 1;
        _add(facts, mkFact('host.fqdn', h, { fqdn: bf, hostname: bParts[0], domain: bDom, via: 'http-header' }, S, source));
      });
      Object.keys(backendDoms).sort().forEach(function (bd) {
        _add(facts, mkFact('host.domain', h, { domain: bd }, S, source));
      });
    }

    // Apache Tomcat Manager text API ("OK - Listed applications..." / "OK - Deployed application...")
    var tomcatListM = /^\s*OK - Listed applications for virtual host \[([^\]]*)\]/im.exec(t);
    var tomcatDepM = /^\s*OK - Deployed application at context path \[(\/[^\]]*)\]/im.exec(t);
    if (tomcatListM || tomcatDepM) {
      _add(facts, mkFact('http.reachable', h, { via: 'tomcat-manager' }, S, source));
      _add(facts, mkFact('web.tech', h, { name: 'tomcat', product: 'Apache Tomcat', via: 'tomcat-manager' }, S, source));
      _add(facts, mkFact('vuln.tomcat_manager', h, { product: 'Apache Tomcat', endpoint: '/manager/text', via: 'tomcat-manager' }, S, source));
      if (tomcatDepM) {
        _add(facts, mkFact('web.upload_confirmed', h, {
          method: 'tomcat_manager_deploy',
          context_path: tomcatDepM[1],
          extensions: ['war'],
          exec_confirmed: false
        }, S, source));
      }
      var tcAuthM = /(?:^|\s)(?:-u|--user)\s+(?:'([^:'\r\n]+):([^'\r\n]*)'|"([^:"\r\n]+):([^"\r\n]*)"|([^:'"\s]+):([^\s'"]+))/i.exec(cmd)
        || /https?:\/\/([^:/@\s'"]+):([^@\s'"]+)@/i.exec(cmd);
      if (tcAuthM) {
        var tcUser = tcAuthM[1] || tcAuthM[3] || tcAuthM[5] || '';
        var tcPass = tcAuthM[2] || tcAuthM[4] || tcAuthM[6] || '';
        if (tcUser && tcPass) {
          _add(facts, mkFact('credential.validated', h, {
            user: tcUser,
            password: tcPass,
            service: 'http',
            protocol: 'tomcat-manager',
            outcome: 'accepted'
          }, S, source));
          if (C._add_plaintext_credential) {
            C._add_plaintext_credential(facts, ws, source, tcUser, tcPass, '', 'tomcat-manager', '');
          }
          var tcCv = { user: tcUser, password: tcPass, service: 'http', method: 'tomcat-manager' };
          _add(facts, mkFact('credential.plaintext', h, tcCv, S, source));
          _add(facts, mkFact('credential.password', h, tcCv, S, source));
          _add(facts, mkFact('credential.available', h, tcCv, S, source));
        }
      }
    }
  }
  C._parse_web_fingerprint = _parse_web_fingerprint;

  var _WEBDAV_EXEC_EXT_RE = /^(?:aspx?|ashx|asmx|php\d?|phtml|phar|jsp|jspx|war|cfm|pl|py|cgi|sh|shtml)$/i;

  function _parse_webdav_output(text, ws, command, source, facts) {
    var t = String(text || '');
    var cmd = String(command || '');
    if (!/\b(?:davtest|cadaver)\b/i.test(cmd) && !/\bTesting DAV connection\b|\bOPEN\s+SUCCEED:\s*https?:\/\/|^dav:\/[^>]*>/im.test(t)) return;
    var h = 'host:' + ws.target;
    var isCadaver = /\bcadaver\b/i.test(cmd) || /^dav:\/[^>]*>/m.test(t);
    var openM = /\bOPEN\s+SUCCEED:\s*(https?:\/\/\S+)/i.exec(t);
    var upUrlM = /\bUpload\s+succeeded:\s*(https?:\/\/\S+)/i.exec(t);
    var putSuccAll = reAll(/\bPUT\s+([A-Za-z0-9_.-]+)\s+SUCCEED(?::\s*(\S+))?/gi, t);
    var execSuccAll = reAll(/\bEXEC\s+([A-Za-z0-9_.-]+)\s+SUCCEED(?::\s*(\S+))?/gi, t);
    var mkcolSucc = /\bMKCOL\s+\S*\s*SUCCEED\b|\bCreating\s+[`'"]?[^`'":\r\n]+[`'"]?:\s+succeeded\b/i.test(t);
    var cadaverPrompt = /^dav:\/[^>]*>/m.test(t);
    var cadaverUpM = /\bUploading\s+(\S+)\s+to\s+[`'"]?([^\s`'":]+)[`'"]?:[\s\S]{0,200}?\b(?:succeeded|100(?:\.0)?%\s+of\s+\d+\s+bytes\s+succeeded)\b/i.exec(t);
    var cadaverMoveExecM = /\b(?:Moving|Renaming)\s+[`'"]?(\S+?)[`'"]?\s+to\s+[`'"]?([^\s`'":]+\.(?:aspx?|ashx|php\d?|phtml|jsp|jspx|cfm|pl|py|cgi))[`'"]?:\s+succeeded\b/i.exec(t);

    var davSucceeded = !!(openM || upUrlM || putSuccAll.length || execSuccAll.length || mkcolSucc || cadaverPrompt || cadaverUpM || cadaverMoveExecM);
    if (!davSucceeded) return;

    var hrVal = { via: isCadaver ? 'cadaver' : 'davtest' };
    if (openM && openM[1]) hrVal.url = openM[1];
    else if (upUrlM && upUrlM[1]) hrVal.url = upUrlM[1];
    _add(facts, mkFact('http.reachable', h, hrVal, S, source));

    var methods = [];
    if (putSuccAll.length || upUrlM || cadaverUpM) methods.push('PUT');
    if (mkcolSucc) methods.push('MKCOL');
    if (/\bDELETE\b[^\r\n]*\bSUCCEED\b|\bDeleting\s+[^\r\n]*\bsucceeded\b/i.test(t)) methods.push('DELETE');
    if (/\bMOVE\b[^\r\n]*\bSUCCEED\b|\b(?:Moving|Renaming)\s+[^\r\n]*\bsucceeded\b/i.test(t) || cadaverMoveExecM) methods.push('MOVE');
    if (methods.length) {
      _add(facts, mkFact('http.methods', h, { methods: methods, risky: methods.slice(), flags: ['http_methods_risky'], via: 'webdav' }, S, source));
    }

    var execExts = [];
    putSuccAll.forEach(function (pm) {
      var ext = String(pm[1] || '').replace(/^\./, '');
      if (_WEBDAV_EXEC_EXT_RE.test(ext)) execExts.push(ext.toLowerCase());
    });
    execSuccAll.forEach(function (em) {
      var ext = String(em[1] || '').replace(/^\./, '');
      if (ext) execExts.push(ext.toLowerCase());
    });
    if (upUrlM && upUrlM[1]) {
      var uExtM = /\.([A-Za-z0-9]+)(?:[?#]|$)/.exec(upUrlM[1]);
      if (uExtM && _WEBDAV_EXEC_EXT_RE.test(uExtM[1])) execExts.push(uExtM[1].toLowerCase());
    }
    if (cadaverUpM) {
      var cDest = cadaverUpM[2] || cadaverUpM[1] || '';
      var cExtM = /\.([A-Za-z0-9]+)$/.exec(cDest);
      if (cExtM && _WEBDAV_EXEC_EXT_RE.test(cExtM[1])) execExts.push(cExtM[1].toLowerCase());
    }
    if (upUrlM || execSuccAll.length || execExts.length || cadaverMoveExecM) {
      var upVal = {
        method: 'webdav_put',
        tool: isCadaver ? 'cadaver' : 'davtest',
        exec_confirmed: execSuccAll.length > 0
      };
      if (upUrlM && upUrlM[1]) upVal.url = upUrlM[1];
      if (execExts.length) upVal.extensions = C.uniqueSortedCI(execExts);
      _add(facts, mkFact('web.upload_confirmed', h, upVal, S, source));
    }

    var authM = /(?:^|\s)-+auth(?:entication)?\s+(?:'([^:'\s]+):([^']*)'|"([^:"\s]+):([^"]*)"|([^:'"\s]+):([^\s'"]+))/i.exec(cmd)
      || /https?:\/\/([^:/@\s'"]+):([^@\s'"]+)@/i.exec(cmd);
    if (authM && !/\bOPEN\s+FAIL\b|\b401\s+Unauthorized\b|\bAuthentication\s+failed\b/i.test(t)) {
      var aUser = authM[1] || authM[3] || authM[5] || '';
      var aPass = authM[2] || authM[4] || authM[6] || '';
      if (aUser && aPass) {
        _add(facts, mkFact('credential.validated', h, {
          user: aUser,
          password: aPass,
          service: 'http',
          protocol: 'webdav',
          via: isCadaver ? 'cadaver' : 'davtest'
        }, S, source));
      }
    }
  }
  C._parse_webdav_output = _parse_webdav_output;

  function _parse_exploit_poc_verdicts(text, ws, command, source, facts) {
    var t = String(text || '');
    if (!t || !/\[[*+]\]/.test(t)) return;
    if ((C._looks_like_edb_script && C._looks_like_edb_script(t, command))
        || (C._looks_like_searchsploit && C._looks_like_searchsploit(t, command))) return;
    var cmd = String(command || '');
    var h = 'host:' + ws.target;
    var lines = t.split(/\r?\n/);
    var confirmedCves = [], seenCve = {};

    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (!ln) continue;

      if (/^\s*\[\+\]/.test(ln)) {
        var hasNeg = /\b(?:isn['\u2019]?t|aren['\u2019]?t|wasn['\u2019]?t|weren['\u2019]?t|not|non|never|no|false|patched|immune|mitigated|failed|safe)\b/i.test(ln);
        if (!hasNeg) {
          var cveM = /^\s*\[\+\]\s*Checking\s+(?:if\s+)?[^\r\n]*?\bvulnerable\s+to\s+(CVE-\d{4}-\d{4,7})\b[^\r\n]*?\b(?:YES|VULNERABLE|CONFIRMED|TRUE)\b/i.exec(ln)
            || /^\s*\[\+\]\s*(?:The\s+)?(?:target|host|server|service|instance|endpoint)\s+(?:is|appears(?:\s+to\s+be)?|seems)\s+vulnerable\s+to\s+(CVE-\d{4}-\d{4,7})\b/i.exec(ln)
            || /^\s*\[\+\]\s*(CVE-\d{4}-\d{4,7})\s*[:\-]+\s*(?:VULNERABLE|YES|CONFIRMED)\b/i.exec(ln);
          if (cveM) {
            var cveUp = cveM[1].toUpperCase();
            if (!seenCve[cveUp]) {
              seenCve[cveUp] = 1;
              confirmedCves.push({ cve: cveUp, evidence: ln.trim() });
            }
          }
        }

        var loginOkM = /^\s*\[\+\]\s*(?:Login|Logged\s+in|Authentication|Authenticated)\s+(?:successful|succeeded|ok)(?:\s+as\s+['"]?([A-Za-z0-9_.@-]+)['"]?)?[!\s.]*$/i.exec(ln);
        if (loginOkM) {
          var flagUserM = /(?:^|\s)(?:-u|--user(?:name)?)\s+(?:'([^']+)'|"([^"]+)"|([^\s'"]+))/i.exec(cmd);
          var flagPassM = /(?:^|\s)(?:-p|--pass(?:word)?)\s+(?:'([^']+)'|"([^"]+)"|([^\s'"]+))/i.exec(cmd);
          var lUser = loginOkM[1] || (flagUserM && (flagUserM[1] || flagUserM[2] || flagUserM[3])) || '';
          var lPass = (flagPassM && (flagPassM[1] || flagPassM[2] || flagPassM[3])) || '';
          var cvVal = { service: 'http', via: 'poc-login', evidence: ln.trim() };
          if (lUser) cvVal.user = lUser;
          if (lPass) cvVal.password = lPass;
          _add(facts, mkFact('credential.validated', h, cvVal, S, source));
        }
      }

      if (/^\s*\[[*+]\]/.test(ln)) {
        var keyM = /^\s*\[[*+]\]\s*(?:([A-Za-z0-9_.-]{2,32})\s+)?(?:auth(?:entication)?\s+|api\s+|master\s+|access\s+|session\s+|admin\s+)?(key|token|secret)\s+(?:obtained|extracted|recovered|leaked|retrieved|found|captured)\s*:\s*['"]?([A-Za-z0-9+/=._:-]{8,256})['"]?\s*$/i.exec(ln);
        if (keyM && !/^(?:none|null|false|failed|error|empty|n\/a)$/i.test(keyM[3])) {
          var kcVal = {
            kind: 'extracted_' + keyM[2].toLowerCase(),
            key: keyM[3],
            via: 'poc-output',
            evidence: ln.trim()
          };
          if (keyM[1] && !/^(?:the|a|an|new|valid)$/i.test(keyM[1])) kcVal.user = keyM[1];
          _add(facts, mkFact('credential.candidate', h, kcVal, S, source));
        }
      }
    }

    if (confirmedCves.length) {
      var cveList = confirmedCves.map(function (x) { return x.cve; });
      _add(facts, mkFact('exploit.candidate', h, {
        cve: cveList[0],
        cves: cveList,
        via: 'poc-check',
        evidence: confirmedCves[0].evidence
      }, S, source));
    }
  }
  C._parse_exploit_poc_verdicts = _parse_exploit_poc_verdicts;

  // ---- Tier B: Raw Burp Suite / HTTP Request Parser -> web.http_request_captured ---- //
  var _RAW_HTTP_REQ_START_RE = /^(?:[ \t]*\r?\n)*[ \t]*(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)[ \t]+(\/\S*|https?:\/\/\S+)[ \t]+HTTP\/(?:1\.[01]|2(?:\.0)?)[ \t]*\r?$/im;

  function _looks_like_raw_http_request(text) {
    var s = String(text || '').trim();
    if (!s) return false;
    if (/^(?:[ \t]*\r?\n)*[ \t]*(?:>[ \t]*)?(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)[ \t]+\S+[ \t]+HTTP\/(?:1\.[01]|2(?:\.0)?)[ \t]*\r?$/im.test(s) === false) return false;
    // Reject curl -v / response transcripts that also carry an inbound HTTP status line
    if (/^[ \t]*(?:<[ \t]*)?HTTP\/(?:1\.[01]|2(?:\.0)?)[ \t]+\d{3}\b/im.test(s)) return false;
    // Reject curl -v prefixed request lines (> GET / ...) unless bare HTTP headers with Host: follow
    if (/^[ \t]*>[ \t]*(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b/im.test(s)) return false;
    return /^[ \t]*Host:[ \t]*\S+/im.test(s);
  }
  C._looks_like_raw_http_request = _looks_like_raw_http_request;

  function _parse_raw_http_request(text, ws, command, source, facts) {
    if (!_looks_like_raw_http_request(text)) return;
    var trimmed = String(text || '').replace(/^(?:[ \t]*\r?\n)+/, '');
    var splitM = /\r?\n\r?\n/.exec(trimmed);
    var headBlock = splitM ? trimmed.slice(0, splitM.index) : trimmed;
    var body = splitM ? trimmed.slice(splitM.index + splitM[0].length) : '';
    var headLines = headBlock.split(/\r?\n/);
    if (!headLines.length) return;

    var reqLineM = /^\s*(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\/\S*|https?:\/\/\S+)\s+HTTP\/(?:1\.[01]|2(?:\.0)?)\s*$/i.exec(headLines[0]);
    if (!reqLineM) return;
    var method = reqLineM[1].toUpperCase();
    var rawTarget = reqLineM[2];
    var scheme = '';
    var hostFromUrl = '';
    var path = rawTarget;
    var fullUrlM = /^(https?):\/\/([^\/\s]+)(\/.*)?$/i.exec(rawTarget);
    if (fullUrlM) {
      scheme = fullUrlM[1].toLowerCase();
      hostFromUrl = fullUrlM[2];
      path = fullUrlM[3] || '/';
    }

    var headers = {};
    var headerList = [];
    for (var i = 1; i < headLines.length; i++) {
      var hl = headLines[i];
      var col = hl.indexOf(':');
      if (col <= 0) continue;
      var hName = hl.slice(0, col).trim();
      var hVal = hl.slice(col + 1).trim();
      if (!hName) continue;
      headerList.push({ name: hName, value: hVal });
      headers[hName.toLowerCase()] = hVal;
    }

    var host = headers['host'] || hostFromUrl || (ws && ws.target) || '';
    if (!host) return;
    if (!scheme) {
      var origHdr = headers['origin'] || headers['referer'] || '';
      if (/^https:\/\//i.test(origHdr) || /:443$/.test(host)) scheme = 'https';
      else scheme = 'http';
    }
    var origin = scheme + '://' + host;
    if (path.charAt(0) !== '/') path = '/' + path;
    var qIdx = path.indexOf('?');
    var pathname = qIdx >= 0 ? path.slice(0, qIdx) : path;
    var query = qIdx >= 0 ? path.slice(qIdx + 1) : '';
    var contentType = headers['content-type'] || '';
    var cookies = headers['cookie'] || '';

    var params = [];
    if (query) {
      query.split('&').forEach(function (pair) {
        if (!pair) return;
        var eq = pair.indexOf('=');
        var k = eq >= 0 ? pair.slice(0, eq) : pair;
        var v = eq >= 0 ? pair.slice(eq + 1) : '';
        if (k) {
          try { k = decodeURIComponent(k); } catch (_e) {}
          try { v = decodeURIComponent(v.replace(/\+/g, ' ')); } catch (_e2) {}
          params.push({ name: k, value: v.slice(0, 256), loc: 'query' });
        }
      });
    }

    var boundary = '';
    var bndM = /multipart\/form-data\s*;\s*boundary=(?:"([^"]+)"|([^\s;]+))/i.exec(contentType);
    if (bndM) {
      boundary = bndM[1] || bndM[2] || '';
      if (boundary && body) {
        var parts = body.split('--' + boundary);
        for (var pi = 1; pi < parts.length; pi++) {
          var part = parts[pi];
          if (!part || /^--/.test(part.trim())) continue;
          var pSplit = /\r?\n\r?\n/.exec(part);
          if (!pSplit) continue;
          var pHead = part.slice(0, pSplit.index);
          var pVal = part.slice(pSplit.index + pSplit[0].length).replace(/\r?\n$/, '');
          var nameM = /\bname="([^"]+)"/i.exec(pHead);
          if (!nameM) continue;
          var fnM = /\bfilename="([^"]*)"/i.exec(pHead);
          var ctM = /^Content-Type:\s*([^\r\n]+)/im.exec(pHead);
          params.push({
            name: nameM[1],
            value: pVal.slice(0, 256),
            filename: fnM ? fnM[1] : '',
            partContentType: ctM ? ctM[1].trim() : '',
            loc: 'multipart'
          });
        }
      }
    } else if (body && (/application\/json/i.test(contentType) || /^\s*\{[\s\S]*\}\s*$/.test(body))) {
      try {
        var parsedJson = JSON.parse(body);
        if (parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
          Object.keys(parsedJson).slice(0, 30).forEach(function (jk) {
            var jv = parsedJson[jk];
            params.push({
              name: jk,
              value: (jv === null || jv === undefined) ? '' : (typeof jv === 'object' ? JSON.stringify(jv) : String(jv)).slice(0, 256),
              loc: 'json'
            });
          });
        }
      } catch (_je) {}
    } else if (body && (/xml/i.test(contentType) || /^\s*<(?:!DOCTYPE|\?xml|[A-Za-z_])/i.test(body))) {
      var xmlRe = /<([A-Za-z_][A-Za-z0-9_.:-]{0,40})>([^<]{0,200})<\/\1>/g;
      var xm, seenXml = Object.create(null);
      while ((xm = xmlRe.exec(body)) !== null && params.length < 30) {
        if (seenXml[xm[1]]) continue;
        seenXml[xm[1]] = 1;
        params.push({ name: xm[1], value: xm[2], loc: 'xml' });
      }
    } else if (body && /[A-Za-z0-9_.\[\]-]+=/.test(body)) {
      body.trim().split('&').slice(0, 30).forEach(function (pair) {
        if (!pair) return;
        var eq = pair.indexOf('=');
        if (eq <= 0) return;
        var k = pair.slice(0, eq);
        var v = pair.slice(eq + 1);
        try { k = decodeURIComponent(k); } catch (_e3) {}
        try { v = decodeURIComponent(v.replace(/\+/g, ' ')); } catch (_e4) {}
        params.push({ name: k, value: v.slice(0, 256), loc: 'body' });
      });
    }

    var hScope = 'host:' + ((ws && ws.target) ? ws.target : host.replace(/:\d+$/, ''));
    _add(facts, mkFact('web.http_request_captured', hScope, {
      method: method,
      path: path,
      pathname: pathname,
      query: query,
      host: host,
      scheme: scheme,
      origin: origin,
      url: origin + path,
      contentType: contentType,
      cookies: cookies,
      headers: headers,
      headerList: headerList,
      boundary: boundary,
      params: params,
      body: body.slice(0, 8192),
      raw: trimmed.slice(0, 16384)
    }, S, source));
  }
  C._parse_raw_http_request = _parse_raw_http_request;

})(typeof globalThis !== 'undefined' ? globalThis : this);
