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
    var trimmedHttp = String(text || '').trim();
    if (/^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP\/\d(?:\.\d)?\b/.test(trimmedHttp) &&
        !/^\s*(?:<\s*)?HTTP\/\d(?:\.\d)?\s+\d{3}\b/m.test(trimmedHttp)) {
      return [];
    }
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
  var _FTP_UNIX_ROW_RE = /^\s*(?<perm>[-dlbcps](?:[-rwxsStT]{9})[@+.]?)\s+\d+\s+\S+\s+\S+\s+(?<size>\d+)\s+\w{3}\s+\d{1,2}\s+(?:\d{4}|\d{1,2}:\d{2})\s+(?<name>\S.*?)\s*$/;
  var _FTP_WEBROOT_MARKER_RE = /^(?:iisstart\.(?:htm|html|png)|aspnet_client|web\.config|index\.(?:php|html?|aspx?|jsp)|default\.(?:aspx?|htm|html)|wp-config\.php|wwwroot|public_html|htdocs)$/i;
  var _MAIL_220_BANNER_RE = /\b(?:E?SMTP|LMTP|Postfix|Exim|Sendmail|Haraka|Exchange\s+SMTP|Mail\s+(?:Server|Service|Transfer))\b/i;
  var _FTP_VERBS_PRESENT_RE = /\b(?:PASV|EPSV|SYST|LIST|NLST|STOR|APPE|CWD|PWD|FEAT|RETR)\b|^\s*ftp>|^\s*(?:227|229|230|331)[ -]/im;

  function _extract_ftp_stream_creds(text) {
    var lines = String(text || '').split(/\r?\n/);
    var pendingUser = '', creds = [], seen = {};
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      var um = /^\s*(?:(?:\d+\s+[\d.]+\s+\S+\s*(?:->|\u2192)\s*\S+\s+FTP\s+\d+\s+Request:\s*)|(?:[>C]:?\s*))?USER\s+([^\r\n]+?)\s*$/i.exec(ln);
      if (um) {
        var u = um[1].trim();
        pendingUser = (!/^(?:anonymous|ftp|<[^>]+>)$/i.test(u)) ? u : '';
        continue;
      }
      var pm = /^\s*(?:(?:\d+\s+[\d.]+\s+\S+\s*(?:->|\u2192)\s*\S+\s+FTP\s+\d+\s+Request:\s*)|(?:[>C]:?\s*))?PASS\s+([^\r\n]+?)\s*$/i.exec(ln);
      if (pm && pendingUser) {
        var p = pm[1].trim();
        if (p && !/^(?:<[^>]+>|\*+|\[redacted\])$/i.test(p)) {
          var key = pendingUser.toLowerCase() + ':' + p;
          if (!seen[key]) {
            seen[key] = true;
            creds.push({ user: pendingUser, password: p });
          }
        }
        pendingUser = '';
      }
    }
    return creds;
  }

  function _emit_ftp_stream_creds(facts, ws, h, source, creds) {
    var domScope = C._scope_for_domain ? C._scope_for_domain(ws) : h;
    creds.forEach(function (c) {
      var cleanU = C._clean_username ? C._clean_username(c.user) : c.user;
      if (!cleanU || !c.password) return;
      if (C._valid_password && !C._valid_password(c.password)) return;
      _add(facts, mkFact('credential.candidate', h, { user: cleanU, password: c.password, service: 'ftp', via: 'ftp-stream' }, S, source));
      if (C._add_plaintext_credential) {
        C._add_plaintext_credential(facts, ws, source, cleanU, c.password, '', 'ftp-stream', '');
      } else {
        _add(facts, mkFact('credential.plaintext', h, { user: cleanU, password: c.password, via: 'ftp-stream' }, S, source));
        _add(facts, mkFact('credential.available', domScope, { user: cleanU, password: c.password, method: 'ftp-stream' }, S, source));
      }
    });
  }

  function _parse_ftp_output(text, ws, command, source, facts) {
    var banners = [], loginSuccess = false;
    reAll(C._FTP_BANNER_RE, text).forEach(function (m) {
      if (m.groups.banner && _MAIL_220_BANNER_RE.test(m.groups.banner)) return;
      var banner = (m.groups.banner || m.groups.login || '').trim();
      if (banner) banners.push(banner);
      if (m.groups.login) loginSuccess = true;
    });
    var cmdStr = String(command || '');
    var ftpUriM = /\bftps?:\/\/(?:[^\/\s@'"]+@)?(?:\[[^\]]+\]|[^\/:\s'"]+)(?::(\d{1,5}))?(?=[\/'"\s]|$)/i.exec(cmdStr);
    var hasFtpUri = !!ftpUriM;
    var ftpUriPort = (ftpUriM && ftpUriM[1]) ? parseInt(ftpUriM[1], 10) : 0;
    if (ftpUriPort < 1 || ftpUriPort > 65535) ftpUriPort = 0;
    var isExplicitFtpCmd = hasFtpUri || /(?:^|\s|[\/\\])(?:l?ftp|ncftp(?:ls|get|put)?)\b/i.test(cmdStr);
    var isMailCmd = !isExplicitFtpCmd && (
      /\b(?:smtps?|imaps?|pop3s?):\/\//i.test(cmdStr)
      || /\b(?:swaks|smtp-user-enum)\b/i.test(cmdStr)
      || /(?:^|\s)(?:nc|ncat|netcat|telnet|openssl)\b[^\r\n]*?(?:[:\s])(25|465|587|110|143|993|995)(?:\s|$)/i.test(cmdStr)
    );
    var isSmtpOnlyTranscript = !isExplicitFtpCmd
      && /\b(?:EHLO|HELO|MAIL\s+FROM\s*:|RCPT\s+TO\s*:|ESMTP)\b/i.test(text)
      && !_FTP_VERBS_PRESENT_RE.test(text);
    if (isMailCmd || isSmtpOnlyTranscript) {
      banners = [];
      loginSuccess = false;
    }

    var h = 'host:' + ws.target;
    var streamCreds = _extract_ftp_stream_creds(text);
    var allKnownFacts = [].concat(facts || [], (ws && ws.facts) || [], (ws && ws.seedFacts) || []);
    var hasKnownTargetFtp = allKnownFacts.some(function (f) {
      return f && f.scope === h && (f.kind === 'port:21' || f.kind === 'ftp.reachable');
    });
    var isEmbeddedPcapStream = !cmdStr.trim() && !isExplicitFtpCmd && !hasKnownTargetFtp && (
      /^\s*#\s*wireshark\b|\b[A-Za-z0-9_./-]+\.pcap(?:ng)?\b|\b(?:tcpdump|tshark|wireshark)\b/im.test(text)
      || (/\bLinux version\s+\d+\.\d+/.test(text) && streamCreds.length > 0)
    );
    if (isEmbeddedPcapStream) {
      if (streamCreds.length) _emit_ftp_stream_creds(facts, ws, h, source, streamCreds);
      return;
    }

    var hasFtpListingShape = reAll(/^\s*[-dlbcps][-rwxsStT]{9}[@+.]?\s+\d+\s+ftp\s+ftp\s+\d+\s+\w{3}\s+\d{1,2}\s+(?:\d{4}|\d{1,2}:\d{2})\s+\S/gm, text).length >= 2;
    var mkdirCreatedOk = !isMailCmd && !isSmtpOnlyTranscript && /^\s*257\s+"[^"\r\n]+"[^\r\n]*\bcreated\b/im.test(text);
    var writeOk = (!isMailCmd && !isSmtpOnlyTranscript && reSearch(_FTP_UPLOAD_INIT_RE, text) && reSearch(_FTP_UPLOAD_OK_RE, text)) || mkdirCreatedOk;
    var hasFtpAnchorLine = !isMailCmd && !isSmtpOnlyTranscript && String(text || '').split(/\r?\n/).some(function (ln) {
      if (/^\s*220[ -]/i.test(ln)) return !_MAIL_220_BANNER_RE.test(ln);
      return /^\s*(?:ftp>|local:\s*\S.*?\s+remote:\s*\S|1(?:25|50)[ -](?:Data connection|Opening|Here comes the directory listing|Ok to send data|Transfer starting)|2(?:00|26|27|29|30|57)[ -]|331[ -]|Connected to\b)/i.test(ln);
    });
    var hasFtpSession = !isMailCmd && !isSmtpOnlyTranscript && !!(banners.length || loginSuccess || writeOk || isExplicitFtpCmd || hasFtpListingShape || hasFtpAnchorLine);
    var ftpFiles = [], ftpDownloaded = [], seenDl = {}, webrootMarkers = [];
    var hasDownloadComplete = !isMailCmd && !isSmtpOnlyTranscript && /(?:^|\n)\s*226[\s-]|\bTransfer complete\b|\b\d+\s+bytes\s+received\s+in\b/i.test(text);
    if (hasDownloadComplete) {
      var addDlFile = function (rawName) {
        var fn = C.stripChars(String(rawName || '').trim(), '"\'');
        if (!fn || fn === '.' || fn === '..' || /^-(?:a|l|la|al)$/i.test(fn)) return;
        var key = fn.toLowerCase();
        if (seenDl[key]) return;
        seenDl[key] = true;
        ftpDownloaded.push({ share: '', path: fn, size: '' });
      };
      reAll(/^\s*local:\s*(?<local>\S.*?)\s+remote:\s*(?<remote>\S.*?)\s*$/gim, text).forEach(function (m) {
        addDlFile(m.groups.remote || m.groups.local);
      });
      reAll(/(?:^\s*ftp>\s*(?:m?get|recv)|\bRETR)\s+["']?(?<file>[^\s"'\r\n]+)["']?/gim, cmdStr + '\n' + text).forEach(function (m) {
        addDlFile(m.groups.file);
      });
      reAll(/^\s*1(?:25|50)[ -][^\r\n]*?\bfor\s+["']?(?<file>[^\s"'()\r\n]+)["']?(?:\s*\(\d+\s*bytes\))?/gim, text).forEach(function (m) {
        if (!/^(?:\/bin\/ls|directory|file\s+list)$/i.test(m.groups.file)) addDlFile(m.groups.file);
      });
      if (!ftpDownloaded.length) {
        var cmdGetM = /\b(?:l?ftp|ncftpget)\b[^\r\n]*?\bget\s+["']?([^\s"';&|]+)["']?/i.exec(cmdStr);
        if (cmdGetM) addDlFile(cmdGetM[1]);
      }
    }
    var seenFtpAnchor = isExplicitFtpCmd || hasFtpListingShape;
    var seenFtpPrompt = /^\s*ftp>/im.test(cmdStr);
    text.split(/\r?\n/).forEach(function (line) {
      if (!hasFtpSession) return;
      if (/^\s*ftp>/i.test(line)) {
        seenFtpPrompt = true;
        seenFtpAnchor = true;
      } else if (/^\s*220[ -]/i.test(line) && !_MAIL_220_BANNER_RE.test(line)) {
        seenFtpAnchor = true;
      } else if (/^\s*(?:1(?:25|50)[ -](?:Data connection|Opening|Here comes the directory listing|Ok to send data|Transfer starting)|2(?:00|26|27|29|30|57)[ -]|331[ -]|Connected to\b)/i.test(line)) {
        seenFtpAnchor = true;
      }
      if (!seenFtpAnchor) return;
      var im = _FTP_IIS_ROW_RE.exec(line);
      if (im) {
        var inm = im.groups.name.trim();
        if (inm && inm !== '.' && inm !== '..') {
          ftpFiles.push({ share: '', path: inm, size: im.groups.size === '<DIR>' ? '' : im.groups.size.replace(/,/g, '') });
          var ibase = inm.split(/[\\/]/).pop();
          if (_FTP_WEBROOT_MARKER_RE.test(ibase)) webrootMarkers.push(ibase);
        }
        return;
      }
      var um = _FTP_UNIX_ROW_RE.exec(line);
      if (um) {
        var unm = um.groups.name.trim().replace(/[ \t]+->[ \t]+[^\r\n]*$/, '');
        if (unm && unm !== '.' && unm !== '..') {
          if (/^\/(?:root|etc|proc|sys|dev)(?:\/|$)/.test(unm) && !seenFtpPrompt) return;
          ftpFiles.push({ share: '', path: unm, size: um.groups.size });
          var ubase = unm.split(/[\\/]/).pop();
          if (_FTP_WEBROOT_MARKER_RE.test(ubase)) webrootMarkers.push(ubase);
        }
      }
    });
    if (!banners.length && !loginSuccess && !writeOk && !ftpFiles.length && !ftpDownloaded.length) return;
    var ftpOsText = String(text || '')
      .replace(/^\s*Remote system type is [^\r\n]*$/gim, '')
      .replace(/^\s*215[ \t]+UNIX emulated by FileZilla\b[^\r\n]*$/gim, '');
    C._add_os_from_text(ftpOsText, ws, source, facts, 'ftp', 'medium', true);
    var ftpReachVal = { tool: 'ftp-client' };
    if (ftpUriPort) ftpReachVal.port = ftpUriPort;
    _add(facts, mkFact('ftp.reachable', h, ftpReachVal, S, source));
    if (banners.length) _add(facts, mkFact('ftp.banner', h, { banners: C.uniqueSortedCI(banners).slice(0, 10) }, S, source));
    var anonInText = /\bName\s*\([^)]*\):\s*(?:anonymous|ftp)\b|\bUSER\s+(?:anonymous|ftp)\b|331[\s-]+(?:Anonymous|Guest|Password required for anonymous)\b|230[\s-]+(?:Anonymous|Guest)\b|\bAnonymous FTP login allowed\b/i.test(text);
    var isAnon = /\banonymous\b/i.test(command) || anonInText;
    if (loginSuccess && isAnon) _add(facts, mkFact('ftp.anonymous_login', h, { tool: 'ftp-client' }, S, source));
    if (loginSuccess && !isAnon) {
      var ftpUserM = /^\s*Name\s*\([^)\r\n]*\):\s*([A-Za-z0-9._$@-]{1,64})\s*$/im.exec(text)
        || /^\s*(?:--->?\s*)?USER\s+([A-Za-z0-9._$@-]{1,64})\s*$/im.exec(text)
        || /^\s*331[\s-]+(?:Password required for|User|Please specify the password for)\s+['"]?([A-Za-z0-9._$@-]{1,64})['"]?(?:[\s.,:]|$)/im.exec(text)
        || /^\s*230[\s-]+User\s+['"]?([A-Za-z0-9._$@-]{1,64})['"]?\s+logged\s+in\b/im.exec(text)
        || /\bftps?:\/\/([^\/:\s@'"]+)(?::[^\/\s@'"]*)?@/i.exec(cmdStr)
        || /\blftp\b[^\r\n]*?\s-u\s+['"]?([^,\s'"]+)/i.exec(cmdStr);
      var ftpAuthUser = ftpUserM ? (C._clean_username ? C._clean_username(ftpUserM[1]) : ftpUserM[1].trim()) : '';
      if (/^(?:logged|login|ok|successful|connected|access|granted|welcome|anonymous|ftp)$/i.test(ftpAuthUser)) ftpAuthUser = '';
      var ftpAuthVal = { service: 'ftp', tool: 'ftp-client' };
      if (ftpUriPort) ftpAuthVal.port = ftpUriPort;
      if (ftpAuthUser && (!C._valid_username || C._valid_username(ftpAuthUser, false))) ftpAuthVal.user = ftpAuthUser;
      _add(facts, mkFact('ftp.authenticated', h, ftpAuthVal, S, source));
      var ftpValidVal = Object.assign({}, ftpAuthVal, { outcome: 'accepted' });
      _add(facts, mkFact('credential.validated', h, ftpValidVal, S, source));
    }
    if (loginSuccess && streamCreds.length) _emit_ftp_stream_creds(facts, ws, h, source, streamCreds);
    if (writeOk) _add(facts, mkFact('ftp.anon_write', h, { tool: 'ftp-client', anonymous: isAnon }, S, source));
    if (ftpFiles.length && C._emit_file_loot) C._emit_file_loot(facts, h, ftpFiles, 'ftp', (hasFtpUri && !banners.length) ? 'ftp-list' : 'ftp-listing', text, ws, source);
    if (ftpDownloaded.length) {
      if (C._emit_file_loot) {
        C._emit_file_loot(facts, h, ftpDownloaded, 'ftp', 'ftp-download', text, ws, source);
      } else {
        var dlPaths = ftpDownloaded.map(function (e) { return e.path; });
        _add(facts, mkFact('loot.files', h, { count: dlPaths.length, files: dlPaths, entries: ftpDownloaded, via: 'ftp-download', tool: 'ftp' }, S, source));
      }
      ftpDownloaded.forEach(function (e) {
        var base = String(e.path || '').split(/[\\/]/).pop() || '';
        if (/\.(?:zip|7z|rar|tar|gz|tgz|bz2|xz|pfx|p12|kdbx|psafe3|bak|ezip|jks|keystore)$/i.test(base)) {
          _add(facts, mkFact('loot.material', h, { kind: 'archive_loot', file: base, path: e.path, via: 'ftp-download' }, S, source));
        }
      });
    }
    if (webrootMarkers.length) {
      _add(facts, mkFact('config.review', h, { kind: 'ftp_webroot_exposed', files: C.uniqueSortedCI(webrootMarkers), via: 'ftp' }, S, source));
    }
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
  var _SNMP_HRSW_INSTALLED_RE = /^\s*(?:(?:HOST-RESOURCES-MIB::)?hrSWInstalledName\.\d+|(?:iso|\.?1)\.3\.6\.1\.2\.1\.25\.6\.3\.1\.2\.\d+)\s*=\s*STRING:\s*"?(?<pkg>[^"\r\n]+?)"?\s*$/im;
  var _SNMP_CRED_CLIENT_RE = /\b(PuTTY|WinSCP|FileZilla|KeePass(?:\s*2|\s*XC)?|TightVNC|RealVNC|UltraVNC|mRemoteNG|RDCMan|Remote Desktop Connection Manager|SuperPuTTY|HeidiSQL|DBeaver)\b/i;
  var _SNMP_OS_BASELINE_RE = /^(?:Microsoft\s+(?:Visual\s+C\+\+|Windows|\.NET|Edge|Update|Silverlight|Office|OneDrive|SQL\s+Server\s+(?:\d+\s+)?(?:Native\s+Client|Setup|Browser|T-SQL|Transact-SQL|System\s+CLR))|Windows\s+(?:SDK|Software\s+Development\s+Kit|Driver\s+Package)|(?:Security\s+)?Update\s+for\s+(?:Microsoft|Windows)|Hotfix\s+for|KB\d{5,}|VMware\s+Tools|VirtualBox\s+Guest\s+Additions|QEMU\s+guest\s+agent|OpenSSH|Google\s+Chrome|Mozilla\s+(?:Firefox|Maintenance)|7-Zip|Notepad\+\+|Git\b|Python\s+\d|Node\.js|Go\s+Programming\s+Language|Java\s+\d|Java\s+Auto\s+Updater|Intel\(R\)|AMD\s+|NVIDIA\s+|Realtek\s+|PuTTY|WinSCP)\b|^linux-(?:image|headers|modules|libc)|^(?:lib[a-z0-9.+-]+|gcc|g\+\+|glibc|libc6|systemd|udev|bash|coreutils|apt|dpkg|rpm|yum|dnf|tzdata|ca-certificates|openssl|openssh-(?:client|server)|curl|wget|vim|nano|perl|python3?-[a-z0-9.+-]+)(?:[-_]\d|$)/i;
  var _SNMP_MIB_ASSIGN_RE = /^\s*(?<oid>[A-Za-z0-9-]+::[A-Za-z0-9_."-]+|(?:iso|\.?1)(?:\.\d+){4,})\s*=\s*(?<type>[A-Za-z0-9-]+):\s*(?<rest>.*)$/;
  var _SNMP_EXTEND_CMD_OID_RE = /^(?:(?:NET-SNMP-EXTEND-MIB::)?nsExtend(?:Command|Args)\b|(?:iso|\.?1)\.3\.6\.1\.4\.1\.8072\.1\.3\.2\.3\.1\.[23]\b|(?:UCD-SNMP-MIB::)?extCommand\b|(?:iso|\.?1)\.3\.6\.1\.4\.1\.2021\.8\.1\.3\b)/i;
  var _SNMP_EXTEND_OUT_OID_RE = /^(?:(?:NET-SNMP-EXTEND-MIB::)?nsExtend(?:Output1Line|OutputFull|OutLine)\b|(?:iso|\.?1)\.3\.6\.1\.4\.1\.8072\.1\.3\.2\.(?:3\.1\.[45]|4\.1\.2)\b|(?:UCD-SNMP-MIB::)?extOutput\b|(?:iso|\.?1)\.3\.6\.1\.4\.1\.2021\.8\.1\.101\b)/i;
  var _SNMP_CHPASSWD_RE = /\becho\s+(?:-[neE]+\s+)?['"]?(?<user>[A-Za-z0-9._-]+):(?<pass>[^'"|\r\n]+?)['"]?\s*\|\s*(?:sudo\s+)?(?:\/usr\/sbin\/|\/sbin\/)?chpasswd\b/gi;
  var _SNMP_PW_RESET_HINT_RE = /\b(?:(?:reset(?:ting)?|chang(?:e|ing)|set(?:ting)?|restor(?:e|ing))\s+(?:the\s+)?password\s+(?:of|for)\s+(?:user\s+)?['"]?(?<user>[A-Za-z0-9._-]{2,32})['"]?(?:\s+to\s+['"]?(?<pw>[^\s'"]{3,64})['"]?)?|password\s+(?:of|for)\s+(?:user\s+)?['"]?(?<user2>[A-Za-z0-9._-]{2,32})['"]?\s+(?:was\s+)?(?:reset|changed|set)(?:\s+to\s+['"]?(?<pw2>[^\s'"]{3,64})['"]?)?)/gi;

  function _emit_snmp_plaintext_cred(facts, ws, h, source, user, pw, method) {
    var u = C._clean_username(user);
    var p = String(pw || '').trim();
    if (!u || !p) return;
    if (C._add_plaintext_credential) {
      C._add_plaintext_credential(facts, ws, source, u, p, '', method, '');
    }
    var domScope = C._scope_for_domain(ws);
    _add(facts, mkFact('credential.plaintext', h, { user: u, password: p, via: method }, S, source));
    _add(facts, mkFact('credential.available', domScope, { user: u, password: p, method: method }, S, source));
  }

  function _parse_snmp_output(text, ws, command, source, facts) {
    var lowered = text.toLowerCase();
    var hasMibLines = /(?:snmpv2-mib|host-resources-mib|net-snmp-extend-mib|ucd-snmp-mib|if-mib|ip-mib|tcp-mib|udp-mib|hrswinstalledname|nsextend\w*|ext(?:names|command|output)|(?:iso|\.?1)\.3\.6\.1)[^\r\n]{0,160}=\s*(?:string|integer|oid|ipaddress|timeticks|counter\d*|gauge\d*|hex-string|bits):/i.test(text) || _ONESIXTYONE_RE.test(text);
    if (!hasMibLines && ['timeout', 'no response from', 'authorizationerror', 'authentication failure'].some(function (m) { return lowered.indexOf(m) >= 0; })) return;
    if (!hasMibLines && lowered.indexOf('snmpv2-mib::') < 0 && lowered.indexOf('= string:') < 0
        && lowered.indexOf('iso.3.6.1') < 0 && !/(?:^|\D)1\.3\.6\.1\./.test(text)
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

    var snmpListenPorts = {};
    reAll(/(?:TCP-MIB::tcpConnState|(?:iso|\.?1)\.3\.6\.1\.2\.1\.6\.13\.1\.1)\.(\d{1,3}(?:\.\d{1,3}){3})\.(\d{1,5})\.[^\r\n]*=\s*(?:INTEGER:\s*)?(?:listen\s*\(\s*2\s*\)|2\b)/gi, text).forEach(function (tm) {
      var lp = parseInt(tm[2], 10);
      if (lp >= 1 && lp <= 65535) snmpListenPorts[lp] = 1;
    });
    var snmpListenList = Object.keys(snmpListenPorts).map(Number).sort(function (a, b) { return a - b; });
    if (snmpListenList.length) {
      _add(facts, mkFact('scan.local.listeners', h, { ports: snmpListenList.slice(0, 48), via: 'snmp' }, S, source));
    }

    // the LanMan users table hands you a spray list; a running-process command line may carry a secret
    var users = [];
    reAll(_SNMP_USER_RE, text).forEach(function (m) {
      var u = m.groups.user.trim();
      if (u && users.indexOf(u) < 0 && u.length >= 1 && u.length <= 64) users.push(u);
    });
    if (users.length) _add(facts, mkFact('ad.user_list', h, { users: users, count: users.length, method: 'snmp' }, S, source));
    var seenPw = {};
    reAll(_SNMP_RUNPARAM_RE, text).forEach(function (m) {
      var paramVal = C.stripChars((m.groups.val || '').trim(), '"').trim();
      var pw = reSearch(_SNMP_PROC_PW_RE, paramVal);
      if (pw) {
        var secret = pw.groups.pw;
        if (!seenPw[secret] && ['password', 'changeme', 'null'].indexOf(secret.toLowerCase()) < 0) {
          seenPw[secret] = true;
          var cred = { password: secret, via: 'snmp-process' };
          var um = reSearch(_SNMP_PROC_USER_RE, paramVal);
          if (um) cred.user = um.groups.user;
          _add(facts, mkFact('credential.candidate', h, cred, S, source));
        }
      }
      reAll(/(?:^|[\s"'\/\\])([A-Za-z0-9_.-]+\.(?:sh|py|pl|rb|ps1|bat|cmd))\s+["']?([A-Za-z0-9._-]{2,32})["']?\s+["']?([^\s"']{8,64})["']?(?=\s|["']|$)/gi, paramVal).forEach(function (sm) {
        var posUser = C._clean_username(sm[2]);
        var posPw = (sm[3] || '').trim();
        if (!posUser || !posPw || posUser.charAt(0) === '-' || posPw.charAt(0) === '-') return;
        if (/^\d+$/.test(posUser) || /^(?:start|stop|restart|status|run|backup|restore|check|sync|test|init|install|update|true|false)$/i.test(posUser)) return;
        if (/[\/\\]/.test(posPw) || /^https?:/i.test(posPw) || /\.(?:txt|log|conf|cfg|ini|json|xml|ya?ml|sql|db|zip|tar|gz|bak|sh|py|pl|rb)$/i.test(posPw)) return;
        if (!C._valid_username(posUser, false) || !C._valid_password(posPw)) return;
        var pKey = posUser.toLowerCase() + '|' + posPw;
        if (seenPw[pKey] || seenPw[posPw]) return;
        seenPw[pKey] = true;
        seenPw[posPw] = true;
        _add(facts, mkFact('credential.candidate', h, { user: posUser, password: posPw, via: 'snmp-process' }, S, source));
      });
      reAll(/(?:^|[\s"'\/\\])([A-Za-z0-9_.-]+\.(?:sh|py|pl|rb|ps1|bat|cmd))\s+["']?([^\s"']{8,64})["']?\s*$/gi, paramVal).forEach(function (sm1) {
        var singlePw = (sm1[2] || '').trim();
        if (!singlePw || singlePw.charAt(0) === '-' || seenPw[singlePw]) return;
        if (/[\/\\]/.test(singlePw) || /^https?:/i.test(singlePw) || /\.(?:txt|log|conf|cfg|ini|json|xml|ya?ml|sql|db|zip|tar|gz|bak|sh|py|pl|rb)$/i.test(singlePw)) return;
        if (!/[A-Za-z]/.test(singlePw) || !/[\d!@#$%^&*+=-]/.test(singlePw) || !C._valid_password(singlePw)) return;
        seenPw[singlePw] = true;
        _add(facts, mkFact('credential.candidate', h, { password: singlePw, via: 'snmp-process' }, S, source));
      });
    });

    // hrSWInstalledName (HOST-RESOURCES-MIB / 1.3.6.1.2.1.25.6.3.1.2): installed software inventory
    var installedSoftware = [], credClients = [], swCandidates = [], seenSw = {};
    reAll(_SNMP_HRSW_INSTALLED_RE, text).forEach(function (m) {
      var pkg = C.stripChars((m.groups.pkg || '').trim(), '"').trim();
      if (!pkg) return;
      var pkLow = pkg.toLowerCase();
      if (!seenSw[pkLow]) {
        seenSw[pkLow] = true;
        installedSoftware.push(pkg);
      }
      var ccm = _SNMP_CRED_CLIENT_RE.exec(pkg);
      if (ccm) credClients.push(ccm[1]);
      if (_SNMP_OS_BASELINE_RE.test(pkg)) return;
      var cleaned = pkg.replace(/\s*\((?:64-bit|32-bit|x64|x86|amd64)\)/gi, '').trim();
      var vm = /^(?<prod>[A-Za-z][A-Za-z0-9 _.+-]{1,60}?)(?:\s+(?:(?:version|release|ver\.?|v)\s*)?|[\/-])(?<ver>\d+\.\d+(?:\.\d+){0,3}[a-z0-9.-]*)\b/i.exec(cleaned);
      if (!vm || !vm.groups) return;
      var prod = vm.groups.prod.replace(/\s+(?:version|release|ver\.?|v)$/i, '').replace(/\s{2,}/g, ' ').trim();
      var ver = vm.groups.ver.trim();
      if (!prod || prod.length < 2 || /^(?:version|release|build|update|kb)$/i.test(prod)) return;
      var majMin = ver.split('.').slice(0, 2).join('.');
      var sq = prod + ' ' + majMin;
      if (!swCandidates.some(function (c) { return c.product.toLowerCase() === prod.toLowerCase() && c.version === ver; })) {
        swCandidates.push({ product: prod, version: ver, search_query: sq, raw: pkg });
      }
    });
    if (installedSoftware.length) value.installed_software = installedSoftware.slice(0, 50);
    if (credClients.length) {
      _add(facts, mkFact('config.review', h, { kind: 'credential_client_installed', clients: C.uniqueSortedCI(credClients), via: 'snmp' }, S, source));
    }
    if (swCandidates.length) {
      swCandidates.forEach(function (c) {
        _add(facts, mkFact('service.version', h, { product: c.product, version: c.version, raw: c.raw, via: 'snmp' }, S, source));
      });
      var bestSw = swCandidates[0];
      _add(facts, mkFact('exploit.versioned_banner', h, {
        product: bestSw.product,
        version: bestSw.version,
        search_query: bestSw.search_query,
        all: swCandidates.slice(0, 5),
        via: 'snmp'
      }, S, source));
    }

    // NET-SNMP-EXTEND-MIB (.1.3.6.1.4.1.8072.1.3.2.*) and UCD-SNMP-MIB (extCommand / extOutput)
    var extendCmds = [], extendOutputs = [], curExtBucket = null;
    text.split(/\r?\n/).forEach(function (line) {
      var am = _SNMP_MIB_ASSIGN_RE.exec(line);
      if (am && am.groups) {
        var oid = am.groups.oid, vType = am.groups.type.toLowerCase(), rest = C.stripChars((am.groups.rest || '').trim(), '"');
        if (vType === 'string' && _SNMP_EXTEND_CMD_OID_RE.test(oid)) {
          if (rest) extendCmds.push(rest);
          curExtBucket = { arr: extendCmds };
          return;
        }
        if (vType === 'string' && _SNMP_EXTEND_OUT_OID_RE.test(oid)) {
          extendOutputs.push(rest);
          curExtBucket = { arr: extendOutputs };
          return;
        }
        curExtBucket = null;
        return;
      }
      if (curExtBucket && curExtBucket.arr.length && line.trim()) {
        curExtBucket.arr[curExtBucket.arr.length - 1] += '\n' + C.stripChars(line.trim(), '"');
      }
    });
    if (extendCmds.length) value.extend_commands = extendCmds.slice(0, 20);
    if (extendOutputs.length) value.extend_output = extendOutputs.filter(Boolean).slice(0, 20);

    var stockExecRe = /^\/(?:usr\/)?s?bin\/(?:sh|bash|dash|zsh|echo|cat|id|whoami|uname|date|true|false|env|python[0-9.]*|perl|awk|sed|grep)$/i;
    var seenProg = {};
    extendCmds.concat(extendOutputs).forEach(function (blob) {
      if (!blob) return;
      reAll(/(?:^|[\s"'])(\.?\/(?:home|root|opt|var|srv|tmp|etc|usr\/local)\/[A-Za-z0-9_./+-]+|[A-Za-z]:\\(?:Users|Temp|opt|srv|inetpub|scripts|ProgramData)\\[^\s"']+)/g, blob).forEach(function (pm) {
        var rawPath = pm[1].trim();
        var cleanPath = rawPath.indexOf('./') === 0 ? rawPath.slice(1) : rawPath;
        if (stockExecRe.test(cleanPath) || seenProg[cleanPath.toLowerCase()]) return;
        seenProg[cleanPath.toLowerCase()] = true;
        var baseName = cleanPath.split(/[\\/]/).pop();
        if (!baseName) return;
        _add(facts, mkFact('host.notable_program', h, {
          name: baseName,
          path: cleanPath,
          reason: 'snmp extend command',
          os: cleanPath.indexOf('\\') >= 0 ? 'windows' : 'linux'
        }, S, source));
      });
      reAll(_SNMP_CHPASSWD_RE, blob).forEach(function (cm) {
        var cu = (cm.groups.user || '').trim(), cp = (cm.groups.pass || '').trim();
        if (cu && cp) _emit_snmp_plaintext_cred(facts, ws, h, source, cu, cp, 'snmp-extend');
      });
      var pwFlag = reSearch(_SNMP_PROC_PW_RE, blob);
      if (pwFlag && pwFlag.groups && pwFlag.groups.pw) {
        var sec = pwFlag.groups.pw;
        if (!seenPw[sec] && ['password', 'changeme', 'null'].indexOf(sec.toLowerCase()) < 0) {
          seenPw[sec] = true;
          var eCred = { password: sec, via: 'snmp-extend' };
          var eum = reSearch(_SNMP_PROC_USER_RE, blob);
          if (eum && eum.groups && eum.groups.user) {
            eCred.user = eum.groups.user;
            _emit_snmp_plaintext_cred(facts, ws, h, source, eCred.user, sec, 'snmp-extend');
          }
          _add(facts, mkFact('credential.candidate', h, eCred, S, source));
        }
      }
      reAll(_SNMP_PW_RESET_HINT_RE, blob).forEach(function (hm) {
        var hu = C.stripChars((hm.groups.user || hm.groups.user2 || '').trim(), '.,;:!?"\'');
        var hpw = C.stripChars((hm.groups.pw || hm.groups.pw2 || '').trim(), '.,;:!?"\'');
        if (!hu || /^(?:user|users|account|default|all|the|your|system)$/i.test(hu)) return;
        if (hpw && !/^(?:default|the|its|new|old|original|initial|null|none|blank|empty)$/i.test(hpw)) {
          _emit_snmp_plaintext_cred(facts, ws, h, source, hu, hpw, 'snmp-extend');
          _add(facts, mkFact('credential.candidate', h, { user: hu, password: hpw, via: 'snmp-extend' }, S, source));
        } else {
          _add(facts, mkFact('credential.candidate', h, { user: hu, via: 'snmp-extend' }, S, source));
        }
      });
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
  var _SQLD_CREATE_RE = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:["`\[]?\w+["`\]]?\.)?["`\[]?(?<t>\w+)["`\]]?\s*\((?<cols>[\s\S]{1,8000}?)\)\s*(?:ENGINE\s*=|DEFAULT\s+CHARSET|WITHOUT\s+ROWID|;)/gi;
  var _SQLD_INSERT_RE = /INSERT\s+INTO\s+(?:["`\[]?\w+["`\]]?\.)?["`\[]?(?<t>\w+)["`\]]?\s*(?:\((?<icols>[^)\r\n]{1,1000})\))?\s*VALUES\s*(?<vblob>[\s\S]{1,16000}?)\s*;/gi;
  var _SQLD_CONSTRAINT_COL_RE = /^(?:(?:PRIMARY|UNIQUE|FOREIGN|FULLTEXT|SPATIAL)\s+)?(?:KEY|INDEX|CONSTRAINT|CHECK)\b/i;
  var _SQLD_USER_COL = /^(?:user(?:name)?|uname|login|email|account|name|admin)$/i;
  var _SQLD_SECRET_COL = /^(?:pass(?:word|wd)?|pwd|secret|hash|passhash|pw)$/i;
  var _SQLD_HASH_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{56}|[0-9a-f]{64}|[0-9a-f]{128}|\*[0-9a-f]{40}|\$(?:2[abxy]|1|5|6|y|apr1|P|H|pbkdf2[^$]*|argon2[id]*)\$[^\s]+|pbkdf2[:_][^\s]+|sha(?:1|256|512)[:$][^\s]+)$/i;

  function _sqld_split(blob) {
    // Split one SQL VALUES(...) tuple or CREATE TABLE column list into top-level tokens, honoring quoting and parens.
    var out = [], cur = '', inStr = false, depth = 0, i = 0, n = blob.length;
    while (i < n) {
      var c = blob[i];
      if (inStr) {
        if (c === '\\' && i + 1 < n && (blob[i + 1] === "'" || blob[i + 1] === '\\') && !/^\s*[,)]/.test(blob.slice(i + 2))) {
          cur += blob[i + 1];
          i += 2;
          continue;
        }
        if (c === "'") {
          if (i + 1 < n && blob[i + 1] === "'") { cur += "'"; i += 2; continue; }
          inStr = false;
        } else { cur += c; }
        i += 1;
        continue;
      }
      if (c === "'") inStr = true;
      else if (c === '(') { depth += 1; cur += c; }
      else if (c === ')' && depth > 0) { depth -= 1; cur += c; }
      else if (c === ',' && depth === 0) { out.push(cur.trim()); cur = ''; }
      else cur += c;
      i += 1;
    }
    out.push(cur.trim());
    return out;
  }
  C._sqld_split = _sqld_split;

  function _sqld_extract_tuples(vblob) {
    var tuples = [], inStr = false, depth = 0, start = -1, i = 0, n = (vblob || '').length;
    while (i < n) {
      var c = vblob[i];
      if (inStr) {
        if (c === '\\' && i + 1 < n && (vblob[i + 1] === "'" || vblob[i + 1] === '\\') && !/^\s*[,)]/.test(vblob.slice(i + 2))) {
          i += 2;
          continue;
        }
        if (c === "'") {
          if (i + 1 < n && vblob[i + 1] === "'") { i += 2; continue; }
          inStr = false;
        }
        i += 1;
        continue;
      }
      if (c === "'") {
        inStr = true;
      } else if (c === '(') {
        if (depth === 0) start = i + 1;
        depth += 1;
      } else if (c === ')') {
        if (depth > 0) {
          depth -= 1;
          if (depth === 0 && start >= 0) {
            tuples.push(vblob.slice(start, i));
            start = -1;
          }
        }
      }
      i += 1;
    }
    return tuples;
  }

  function _strip_col_quotes(s) { return C.stripChars(s, '"`[]'); }

  function _parse_sqlite_dump(text, ws, source, facts) {
    var h = 'host:' + ws.target;
    var colsByTable = {};
    reAll(_SQLD_CREATE_RE, text).forEach(function (m) {
      var names = [];
      _sqld_split(m.groups.cols).forEach(function (seg) {
        var trimmed = seg.trim();
        if (!trimmed || _SQLD_CONSTRAINT_COL_RE.test(trimmed)) return;
        var first = (_strip_col_quotes(trimmed).trim().split(/[\s(]+/)[0] || '');
        var cleanCol = _strip_col_quotes(first);
        if (cleanCol) names.push(cleanCol);
      });
      if (names.length) colsByTable[m.groups.t.toLowerCase()] = names;
    });
    var seen = {};
    reAll(_SQLD_INSERT_RE, text).forEach(function (m) {
      var table = m.groups.t.toLowerCase();
      var cols = null;
      if (m.groups.icols && m.groups.icols.trim()) {
        cols = _sqld_split(m.groups.icols).map(function (c) { return _strip_col_quotes(c.trim()); }).filter(Boolean);
      } else {
        cols = colsByTable[table];
      }
      if (!cols || !cols.length) return;
      var userCols = cols.filter(function (c) { return _SQLD_USER_COL.test(c); });
      var secretCols = cols.filter(function (c) { return _SQLD_SECRET_COL.test(c); });
      if (!secretCols.length) return;
      var tuples = _sqld_extract_tuples(m.groups.vblob);
      tuples.forEach(function (tupleStr) {
        var vals = _sqld_split(tupleStr);
        if (cols.length !== vals.length) return;
        var row = {};
        for (var i = 0; i < cols.length; i++) row[cols[i]] = vals[i];
        secretCols.forEach(function (sc) {
          var secret = (row[sc] || '').trim();
          if (!secret || secret.toUpperCase() === 'NULL' || secret.length > 4096) return;
          var user = '';
          for (var j = 0; j < userCols.length; j++) {
            var v = (row[userCols[j]] || '').trim();
            if (v && v.toUpperCase() !== 'NULL') { user = v; break; }
          }
          var cred = { via: 'exposed-sqlite', table: table };
          if (user) cred.user = user.slice(0, 128);
          var isHash = _SQLD_HASH_RE.test(secret);
          if (isHash) cred.hash = secret;
          else cred.password = secret;
          var fp = (cred.user || '') + '|' + (cred.hash || cred.password);
          if (seen[fp]) return;
          seen[fp] = true;
          _add(facts, mkFact('credential.candidate', h, cred, S, source));
          if (isHash) {
            var hVal = { hash: secret, kind: 'sql-dump', table: table };
            if (cred.user) hVal.user = cred.user;
            _add(facts, mkFact('hash.crackable', h, hVal, S, source));
          } else if (C._valid_password && C._valid_password(secret)) {
            var cleanU = user ? C._clean_username(user) : '';
            if (cleanU && C._valid_username && C._valid_username(cleanU, false) && C._add_plaintext_credential) {
              C._add_plaintext_credential(facts, ws, source, cleanU, secret, '', 'sql-dump', '');
            } else {
              var pVal = { password: secret, table: table, method: 'sql-dump' };
              if (user) pVal.user = user.slice(0, 128);
              _add(facts, mkFact('credential.plaintext', h, pVal, S, source));
              _add(facts, mkFact('credential.available', h, pVal, S, source));
            }
          }
        });
      });
    });
  }
  C._parse_sqlite_dump = _parse_sqlite_dump;

  function _parse_rsync_nfs(text, ws, command, source, facts) {
    if (!text) return;
    var h = 'host:' + ws.target;
    var cmdStr = String(command || '');
    var lc = cmdStr.toLowerCase();
    var rGenericModRe = /^(?:files?|data|pub|public|shared?|shares?|backups?|bak|www|web|webroot|html|htdocs|docs?|documents?|media|images?|img|static|assets?|uploads?|downloads?|ftp|rsync|src|source|code|git|repos?|svn|logs?|tmp|temp|var|opt|etc|usr|srv|mnt|home|users?|root|admin|administrator|guest|anonymous|test|testing|dev|prod|staging|archive|archives|packages?|pkg|dist|mirror|mirrors|ubuntu|debian|centos|fedora|alpine|kali|kernel|cpan|cran|ctan|gnu)$/i;
    if (/\brsync\b/.test(lc) && !/connection refused|failed to connect|timed out|@ERROR:/i.test(text)) {
      var rsFiles = [], rsSeenF = {};
      reAll(/^[bcdlps-][rwxstST-]{9}[+@.]?\s+[\d,]+\s+\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+(\S[^\r\n]*)$/gm, text).forEach(function (m) {
        var fn = m[1].trim().replace(/[ \t]+->[ \t]+[^\r\n]*$/, '');
        if (!fn || fn === '.' || fn === '..') return;
        if (!rsSeenF[fn.toLowerCase()]) { rsSeenF[fn.toLowerCase()] = true; rsFiles.push(fn); }
      });
      if (rsFiles.length) {
        _add(facts, mkFact('rsync.reachable', h, { port: 873, tool: 'rsync' }, S, source));
        _add(facts, mkFact('loot.files', h, { files: rsFiles, count: rsFiles.length, tool: 'rsync', via: 'rsync-list' }, S, source));
        var modTargetM = /(?:rsync:\/\/[^\/\s'"]+\/|::)([A-Za-z0-9_.-]{1,32})(?:\/|\s|['"]|$)/i.exec(cmdStr);
        var modTarget = modTargetM ? modTargetM[1] : '';
        var hasHomeDotfile = rsFiles.some(function (f) {
          var base = f.split('/').pop();
          return /^\.(?:ssh|bash_history|bashrc|bash_profile|bash_logout|profile|zshrc|zsh_history|viminfo|gnupg|config|local|cache)$/i.test(base);
        });
        if (modTarget && /^[a-z_][a-z0-9_-]{1,31}$/.test(modTarget) && !rGenericModRe.test(modTarget) && hasHomeDotfile) {
          _add(facts, mkFact('host.users', h, { users: [modTarget], via: 'rsync-home' }, S, source));
        }
      } else {
        var rsMods = [], rsEntries = [], rsUsers = [], rsSeenM = {};
        reAll(/^[ \t]*([A-Za-z0-9_.-]{1,64})(?:\t+|[ \t]{2,})(\S[^\r\n]*)$/gm, text).forEach(function (m) {
          var mn = m[1].trim(), mc = m[2].trim();
          if (/^(?:@RSYNCD|MOTD|rsync|receiving|sent|total|speedup|WARNING|ERROR)$/i.test(mn)) return;
          var mk = mn.toLowerCase();
          if (!rsSeenM[mk]) {
            rsSeenM[mk] = true;
            rsMods.push(mn);
            rsEntries.push({ name: mn, comment: mc });
          }
          if (/^[a-z_][a-z0-9_-]{1,31}$/.test(mn) && !rGenericModRe.test(mn) && /\bhome\b/i.test(mc)) {
            rsUsers.push(mn);
          }
        });
        if (rsMods.length) {
          _add(facts, mkFact('rsync.reachable', h, { port: 873, tool: 'rsync' }, S, source));
          _add(facts, mkFact('rsync.modules', h, { modules: rsMods, entries: rsEntries, count: rsMods.length, tool: 'rsync' }, S, source));
          if (rsUsers.length) {
            _add(facts, mkFact('host.users', h, { users: C.uniqueSortedCI(rsUsers), via: 'rsync-modules' }, S, source));
          }
        }
      }
    }
    if ((/\bshowmount\b/.test(lc) || /^Export list for\s+\S+:/im.test(text) || /^NFS\s+\d{1,3}(?:\.\d{1,3}){3}\s+2049\b/im.test(text)) && !/clnt_create:\s*RPC|connection refused|timed out/i.test(text)) {
      _add(facts, mkFact('nfs.reachable', h, { port: 2049, tool: 'showmount' }, S, source));
    }
  }
  C._parse_rsync_nfs = _parse_rsync_nfs;

  function _b64DecodeUtf8(token) {
    var s = String(token || '').trim();
    if (!s || !/^[A-Za-z0-9+/]{2,}={0,2}$/.test(s) || (s.length % 4 !== 0)) return '';
    try {
      if (typeof Buffer !== 'undefined') return Buffer.from(s, 'base64').toString('utf8');
      if (typeof atob === 'function') return atob(s);
    } catch (_e) {}
    return '';
  }

  function _cleanSmtpUser(raw) {
    var u = String(raw || '').replace(/^[\x00-\x20]+|[\x00-\x20]+$/g, '');
    return (u && /^[\x21-\x7e]{1,128}$/.test(u)) ? u : '';
  }

  function _extractSmtpAuthUser(text, command) {
    var t = String(text || '');
    var cmd = String(command || '');
    var lines = t.split(/\r?\n/);

    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i].replace(/^\s*(?:(?:<[-~*]{1,3}|[-~*]{1,3}>|[CS]:|[<>])\s*)?/, '').trim();
      var plainInline = /^AUTH\s+PLAIN\s+([A-Za-z0-9+/]{4,}={0,2})\s*$/i.exec(ln);
      if (plainInline) {
        var decPlain = _b64DecodeUtf8(plainInline[1]);
        if (decPlain) {
          var pParts = decPlain.split('\x00');
          var pu = _cleanSmtpUser(pParts.length >= 2 ? (pParts[1] || pParts[0]) : pParts[0]);
          if (pu) return pu;
        }
      }
      var loginInline = /^AUTH\s+LOGIN\s+([A-Za-z0-9+/]{2,}={0,2})\s*$/i.exec(ln);
      if (loginInline) {
        var lu = _cleanSmtpUser(_b64DecodeUtf8(loginInline[1]));
        if (lu) return lu;
      }
      if (/^334[\s-]+(?:VXNlcm5hbWU6|dXNlcm5hbWU6|VXNlcm5hbWU=)/i.test(ln)) {
        for (var j = i + 1; j < lines.length && j <= i + 3; j++) {
          var cand = lines[j].replace(/^\s*(?:(?:<[-~*]{1,3}>?|[-~*]{1,3}>|[CS]:|[<>])\s*)?/, '').trim();
          if (!cand) continue;
          if (/^(?:334|235|535)\b/.test(cand)) break;
          var cu = _cleanSmtpUser(_b64DecodeUtf8(cand));
          if (cu) return cu;
        }
      }
    }

    var inAuthLogin = false, inAuthPlain = false;
    for (var k = 0; k < lines.length; k++) {
      var cl = lines[k].replace(/^\s*(?:(?:<[-~*]{1,3}>?|[-~*]{1,3}>|[CS]:|[<>])\s*)?/, '').trim();
      if (!cl) continue;
      if (/^AUTH\s+LOGIN\s*$/i.test(cl)) { inAuthLogin = true; inAuthPlain = false; continue; }
      if (/^AUTH\s+PLAIN\s*$/i.test(cl)) { inAuthPlain = true; inAuthLogin = false; continue; }
      if (/^334\b/.test(cl)) continue;
      if (/^(?:235|5\d\d|QUIT|MAIL\s+FROM|EHLO|HELO)\b/i.test(cl)) { inAuthLogin = false; inAuthPlain = false; continue; }
      if (inAuthPlain && /^[A-Za-z0-9+/]{4,}={0,2}$/.test(cl)) {
        var dp = _b64DecodeUtf8(cl);
        if (dp) {
          var pp = dp.split('\x00');
          var ppu = _cleanSmtpUser(pp.length >= 2 ? (pp[1] || pp[0]) : pp[0]);
          if (ppu) return ppu;
        }
        inAuthPlain = false;
      } else if (inAuthLogin && /^[A-Za-z0-9+/]{2,}={0,2}$/.test(cl)) {
        var dlu = _cleanSmtpUser(_b64DecodeUtf8(cl));
        if (dlu) return dlu;
        inAuthLogin = false;
      }
    }

    var swaksM = /(?:--auth-user|--au|-au)(?:=|\s+)['"]?([^\s'"]+)['"]?/i.exec(cmd + '\n' + t);
    if (swaksM) {
      var su = _cleanSmtpUser(swaksM[1]);
      if (su) return su;
    }
    return '';
  }

  function _parse_smtp_output(text, a1, a2, a3, a4) {
    var ws, command = '', source = 'smtp', facts = [];
    if (a1 && typeof a1 === 'object' && !Array.isArray(a1)) {
      ws = a1;
      if (Array.isArray(a4)) {
        command = typeof a2 === 'string' ? a2 : '';
        source = typeof a3 === 'string' ? a3 : (command || 'smtp');
        facts = a4;
      } else if (Array.isArray(a3)) {
        source = typeof a2 === 'string' ? a2 : 'smtp';
        facts = a3;
        command = typeof a4 === 'string' ? a4 : '';
      } else {
        command = typeof a2 === 'string' ? a2 : '';
        source = typeof a3 === 'string' ? a3 : (command || 'smtp');
      }
    } else {
      command = typeof a1 === 'string' ? a1 : '';
      facts = Array.isArray(a2) ? a2 : [];
      var ipM = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(command) || /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(String(text || ''));
      ws = { target: ipM ? ipM[1] : 'unknown' };
      source = command || 'smtp';
    }
    var t = String(text || '');
    if (!t) return facts;
    var h = 'host:' + ((ws && ws.target) || 'unknown');
    var banners = [];
    reAll(/^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?220[\s-]([^\r\n]*\b(?:E?SMTP|LMTP|Postfix|Exim|Sendmail|Haraka|MailEnable)\b[^\r\n]*)/gim, t).forEach(function (m) {
      var b = (m[1] || '').trim();
      if (b) banners.push(b);
    });
    var hasAuthContext = /\bAUTH\s+(?:LOGIN|PLAIN|CRAM-MD5|NTLM)\b/i.test(t) ||
      /\b334[\s-]+(?:VXNlcm5hbWU6|dXNlcm5hbWU6|UGFzc3dvcmQ6)/i.test(t) ||
      /(?:--auth(?:-user)?|--au|-au|-a)\b/i.test(command);
    var has235Success = /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?235[\s-][^\r\n]*(?:authenticated|Authentication\s+success(?:ful|eeded)?|2\.7\.0\s+Authentication)\b/im.test(t);

    if (banners.length || (hasAuthContext && has235Success)) {
      _add(facts, mkFact('smtp.reachable', h, { tool: 'smtp-client' }, S, source));
      _add(facts, mkFact('mail.reachable', h, { tool: 'smtp-client' }, S, source));
    }
    if (banners.length) {
      C._add_os_from_text(banners.join('\n'), ws, source, facts, 'smtp', 'medium', true);
      _add(facts, mkFact('smtp.banner', h, { banner: banners[0], banners: C.uniqueSortedCI(banners).slice(0, 10) }, S, source));
    }
    if (hasAuthContext && has235Success) {
      var user = _extractSmtpAuthUser(t, command);
      var credVal = { service: 'smtp', outcome: 'accepted' };
      if (user) credVal.user = user;
      _add(facts, mkFact('credential.validated', h, credVal, S, source));
    }

    var smtpEnumUsers = [];
    reAll(/^\s*(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9._-]+):\s+([A-Za-z0-9_.+-]{1,64})\s+exists\s*$/gim, t).forEach(function (m) {
      var eu = (m[1] || '').trim();
      if (eu) smtpEnumUsers.push(eu);
    });
    var isSmtpUserEnumRun = /\bStarting\s+smtp-user-enum\b|#{5,}\s*Scan\s+completed\s*#{5,}/i.test(t)
      || (/\bsmtp-user-enum\b/i.test(command) && /\b\d+\s+results?\b/i.test(t));
    var hasSmtpConnErr = /\b(?:Connection\s+refused|Connection\s+timed\s+out|No\s+route\s+to\s+host|Network\s+is\s+unreachable|Can't\s+connect)\b/i.test(t);
    if (smtpEnumUsers.length) {
      var uniqSmtpUsers = C.uniqueSortedCI(smtpEnumUsers);
      _add(facts, mkFact('smtp.reachable', h, { tool: 'smtp-user-enum' }, S, source));
      _add(facts, mkFact('mail.reachable', h, { tool: 'smtp-user-enum' }, S, source));
      _add(facts, mkFact('host.users', h, { users: uniqSmtpUsers, count: uniqSmtpUsers.length, via: 'smtp-vrfy' }, S, source));
      uniqSmtpUsers.forEach(function (u) {
        _add(facts, mkFact('credential.candidate', h, { user: u, username_only: true, service: 'smtp', via: 'smtp-user-enum' }, S, source));
      });
    } else if (isSmtpUserEnumRun && !hasSmtpConnErr) {
      _add(facts, mkFact('smtp.reachable', h, { tool: 'smtp-user-enum' }, S, source));
      _add(facts, mkFact('mail.reachable', h, { tool: 'smtp-user-enum' }, S, source));
    }
    return facts;
  }
  C._parse_smtp_output = _parse_smtp_output;

  var _IMAP_BANNER_RE = /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?\*\s+OK\b(?<banner>[^\r\n]*?\b(?:IMAP4(?:rev1)?|IMAPrev1)\b[^\r\n]*)$/im;
  var _IMAP_LOGIN_CMD_RE = /^\s*(?:(?:[-~*]{1,3}>|C:|>)\s*)?(?<tag>[A-Za-z0-9._?-]+)\s+LOGIN\s+(?:"(?<qu>[^"\r\n]+)"|'(?<su>[^'\r\n]+)'|(?<u>\S+))\s+(?:"(?<qp>[^"\r\n]*)"|'(?<sp>[^'\r\n]*)'|(?<p>\S+))[ \t]*$/gim;
  var _IMAP_TAGGED_RES_RE = /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?(?<tag>[A-Za-z0-9._?-]+)\s+(?<status>OK|NO|BAD)\b(?<rest>[^\r\n]*)$/gim;
  C._IMAP_BANNER_RE = _IMAP_BANNER_RE;

  function _inferImapPort(command) {
    var cmd = String(command || '');
    if (!cmd) return 143;
    var imapsM = /\bimaps:\/\/(?:[^\/\s@'"]+@)?(?:\[[^\]]+\]|[^\/:\s'"]+)(?::(\d{1,5}))?/i.exec(cmd);
    if (imapsM) {
      var sp = imapsM[1] ? parseInt(imapsM[1], 10) : 993;
      return (sp >= 1 && sp <= 65535) ? sp : 993;
    }
    var imapM = /\bimap:\/\/(?:[^\/\s@'"]+@)?(?:\[[^\]]+\]|[^\/:\s'"]+)(?::(\d{1,5}))?/i.exec(cmd);
    if (imapM) {
      var ip = imapM[1] ? parseInt(imapM[1], 10) : 143;
      return (ip >= 1 && ip <= 65535) ? ip : 143;
    }
    var connM = /(?:-connect|TCP4?:)\s*(?:\[[^\]]+\]|[^:\s'"]+):(\d{1,5})\b/i.exec(cmd);
    if (connM) {
      var cp = parseInt(connM[1], 10);
      if (cp >= 1 && cp <= 65535) return cp;
    }
    var ncM = /\b(?:nc|ncat|netcat|telnet)\b[^\r\n]*?\s(\d{1,5})\s*$/i.exec(cmd);
    if (ncM) {
      var np = parseInt(ncM[1], 10);
      if (np >= 1 && np <= 65535) return np;
    }
    return 143;
  }

  function _parse_imap_output(text, a1, a2, a3, a4) {
    var ws, command = '', source = 'imap', facts = [];
    if (a1 && typeof a1 === 'object' && !Array.isArray(a1)) {
      ws = a1;
      if (Array.isArray(a4)) {
        command = typeof a2 === 'string' ? a2 : '';
        source = typeof a3 === 'string' ? a3 : (command || 'imap');
        facts = a4;
      } else if (Array.isArray(a3)) {
        source = typeof a2 === 'string' ? a2 : 'imap';
        facts = a3;
        command = typeof a4 === 'string' ? a4 : '';
      } else {
        command = typeof a2 === 'string' ? a2 : '';
        source = typeof a3 === 'string' ? a3 : (command || 'imap');
      }
    } else {
      command = typeof a1 === 'string' ? a1 : '';
      facts = Array.isArray(a2) ? a2 : [];
      var ipM = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(command) || /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(String(text || ''));
      ws = { target: ipM ? ipM[1] : 'unknown' };
      source = command || 'imap';
    }
    var t = String(text || '');
    if (!t) return facts;
    var h = 'host:' + ((ws && ws.target) || 'unknown');
    var port = _inferImapPort(command);
    var banners = [];
    reAll(_IMAP_BANNER_RE, t).forEach(function (m) {
      var b = ((m.groups && m.groups.banner) || m[0] || '').trim();
      if (b) banners.push(b);
    });

    var resByTag = {};
    reAll(_IMAP_TAGGED_RES_RE, t).forEach(function (m) {
      var tag = ((m.groups && m.groups.tag) || '').toLowerCase();
      if (!tag) return;
      resByTag[tag] = {
        status: ((m.groups && m.groups.status) || '').toUpperCase(),
        rest: ((m.groups && m.groups.rest) || '').trim()
      };
    });

    var loginMatches = reAll(_IMAP_LOGIN_CMD_RE, t);
    var sawImapAuthOutcome = false;

    if (banners.length) {
      C._add_os_from_text(banners.join('\n'), ws, source, facts, 'imap', 'medium', true);
      _add(facts, mkFact('mail.reachable', h, { protocol: 'imap', port: port }, S, source));
      _add(facts, mkFact('service.imap.banner', h, { port: port, banner: banners[0], banners: C.uniqueSortedCI(banners).slice(0, 10) }, S, source));
    }

    loginMatches.forEach(function (m) {
      var g = m.groups || {};
      var tag = (g.tag || '').toLowerCase();
      var res = tag ? resByTag[tag] : null;
      if (!res) return;
      var rawUser = (g.qu || g.su || g.u || '').trim();
      var rawPass = (g.qp !== undefined ? g.qp : (g.sp !== undefined ? g.sp : (g.p || ''))).trim();
      var cleanUser = C._clean_username ? C._clean_username(rawUser) : rawUser;
      if (res.status === 'OK') {
        sawImapAuthOutcome = true;
        _add(facts, mkFact('mail.reachable', h, { protocol: 'imap', port: port }, S, source));
        var credVal = { service: 'imap', protocol: 'imap', port: port, outcome: 'accepted' };
        if (cleanUser || rawUser) credVal.user = cleanUser || rawUser;
        _add(facts, mkFact('credential.validated', h, credVal, S, source));
        if (cleanUser && rawPass && (!C._valid_password || C._valid_password(rawPass))) {
          if (C._add_plaintext_credential) {
            C._add_plaintext_credential(facts, ws, source, cleanUser, rawPass, '', 'imap-login', '');
          } else {
            var domScope = C._scope_for_domain ? C._scope_for_domain(ws) : h;
            _add(facts, mkFact('credential.plaintext', h, { user: cleanUser, password: rawPass, via: 'imap-login' }, S, source));
            _add(facts, mkFact('credential.available', domScope, { user: cleanUser, password: rawPass, method: 'imap-login' }, S, source));
          }
        }
      } else if (res.status === 'NO') {
        sawImapAuthOutcome = true;
        if (banners.length) _add(facts, mkFact('mail.reachable', h, { protocol: 'imap', port: port }, S, source));
        var failVal = { service: 'imap', protocol: 'imap', port: port, reason: res.rest || 'LOGIN failed' };
        if (cleanUser || rawUser) failVal.user = cleanUser || rawUser;
        _add(facts, mkFact('blocker.logon_failure', h, failVal, S, source));
      }
    });

    if (!sawImapAuthOutcome && banners.length && /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?[A-Za-z0-9._?-]+\s+NO\b[^\r\n]*\b(?:LOGIN|AUTHENTICATIONFAILED|auth(?:entication)?\s+failed|invalid\s+(?:user|credentials|password|login))\b/im.test(t)) {
      _add(facts, mkFact('blocker.logon_failure', h, { service: 'imap', protocol: 'imap', port: port, reason: 'LOGIN failed' }, S, source));
    }

    return facts;
  }
  C._parse_imap_output = _parse_imap_output;

  var _POP3_BANNER_RE = /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?\+OK\b(?<banner>[^\r\n]*?\b(?:POP3|Dovecot|Cyrus|Courier|qpopper|MailEnable|hMailServer|popa3d|ready)\b[^\r\n]*)$/im;
  var _POP3_PUBLIC_MAIL_DOMAINS_RE = /^(?:localhost(?:\.localdomain)?|example\.(?:com|org|net)|gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|live\.com|msn\.com|icloud\.com|aol\.com|protonmail\.com)$/i;
  var _POP3_SYSTEM_MAILBOX_RE = /^(?:mailer-daemon|postmaster|noreply|no-reply|daemon|nobody)$/i;
  C._POP3_BANNER_RE = _POP3_BANNER_RE;

  function _inferPop3Port(command) {
    var cmd = String(command || '');
    if (!cmd) return 110;
    var pop3sM = /\bpop3s:\/\/(?:[^\/\s@'"]+@)?(?:\[[^\]]+\]|[^\/:\s'"]+)(?::(\d{1,5}))?/i.exec(cmd);
    if (pop3sM) {
      var sp = pop3sM[1] ? parseInt(pop3sM[1], 10) : 995;
      return (sp >= 1 && sp <= 65535) ? sp : 995;
    }
    var pop3M = /\bpop3:\/\/(?:[^\/\s@'"]+@)?(?:\[[^\]]+\]|[^\/:\s'"]+)(?::(\d{1,5}))?/i.exec(cmd);
    if (pop3M) {
      var pp = pop3M[1] ? parseInt(pop3M[1], 10) : 110;
      return (pp >= 1 && pp <= 65535) ? pp : 110;
    }
    var connM = /(?:-connect|TCP4?:)\s*(?:\[[^\]]+\]|[^:\s'"]+):(\d{1,5})\b/i.exec(cmd);
    if (connM) {
      var cp = parseInt(connM[1], 10);
      if (cp >= 1 && cp <= 65535) return cp;
    }
    var ncM = /\b(?:nc|ncat|netcat|telnet)\b[^\r\n]*?\s(\d{1,5})\s*$/i.exec(cmd);
    if (ncM) {
      var np = parseInt(ncM[1], 10);
      if (np >= 1 && np <= 65535) return np;
    }
    return 110;
  }

  function _unpack_service_args(text, a1, a2, a3, a4, defaultSource) {
    var ws, command = '', source = defaultSource, facts = [];
    if (a1 && typeof a1 === 'object' && !Array.isArray(a1)) {
      ws = a1;
      if (Array.isArray(a4)) {
        command = typeof a2 === 'string' ? a2 : '';
        source = typeof a3 === 'string' ? a3 : (command || defaultSource);
        facts = a4;
      } else if (Array.isArray(a3)) {
        source = typeof a2 === 'string' ? a2 : defaultSource;
        facts = a3;
        command = typeof a4 === 'string' ? a4 : '';
      } else {
        command = typeof a2 === 'string' ? a2 : '';
        source = typeof a3 === 'string' ? a3 : (command || defaultSource);
      }
    } else {
      command = typeof a1 === 'string' ? a1 : '';
      facts = Array.isArray(a2) ? a2 : [];
      var ipM = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(command) || /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(String(text || ''));
      ws = { target: ipM ? ipM[1] : 'unknown' };
      source = command || defaultSource;
    }
    return { ws: ws, command: command, source: source, facts: facts };
  }

  function _parse_pop3_output(text, a1, a2, a3, a4) {
    var unpacked = _unpack_service_args(text, a1, a2, a3, a4, 'pop3');
    var ws = unpacked.ws, command = unpacked.command, source = unpacked.source, facts = unpacked.facts;
    var t = String(text || '');
    if (!t) return facts;
    var h = 'host:' + ((ws && ws.target) || 'unknown');
    var port = _inferPop3Port(command);
    var banners = [];
    reAll(_POP3_BANNER_RE, t).forEach(function (m) {
      var b = ((m.groups && m.groups.banner) || m[0] || '').trim();
      if (b) banners.push(b);
    });
    var isPop3Cmd = /\bpop3s?:\/\//i.test(command) || /(?:^|\s)(?:nc|ncat|netcat|telnet|openssl)\b[^\r\n]*?(?:[:\s])(?:110|995)(?:\s|$)/i.test(command);
    var hasPop3Dialog = /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?\+OK\b/im.test(t) && (
      banners.length > 0
      || isPop3Cmd
      || /^\s*(?:(?:[-~*]{1,3}>|C:|>)\s*)?(?:USER\s+\S+|STAT|LIST|UIDL|RETR\s+\d+|TOP\s+\d+\s+\d+)\s*$/im.test(t)
      || /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?\+OK\s+(?:Logged\s+in|Mailbox\s+locked|\d+\s+\d+\s*$)/im.test(t)
    );
    if (!hasPop3Dialog) return facts;

    if (banners.length) {
      C._add_os_from_text(banners.join('\n'), ws, source, facts, 'pop3', 'medium', true);
    }
    _add(facts, mkFact('mail.reachable', h, { protocol: 'pop3', port: port }, S, source));

    var lines = t.split(/\r?\n/);
    var pendingUser = '', pendingPass = '', stage = '';
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      var um = /^\s*(?:(?:[-~*]{1,3}>|C:|>)\s*)?USER\s+([^\r\n]+?)\s*$/i.exec(ln);
      if (um) {
        pendingUser = um[1].trim();
        pendingPass = '';
        stage = 'user';
        continue;
      }
      var pm = /^\s*(?:(?:[-~*]{1,3}>|C:|>)\s*)?PASS\s+([^\r\n]+?)\s*$/i.exec(ln);
      if (pm && pendingUser) {
        pendingPass = pm[1].trim();
        stage = 'pass';
        continue;
      }
      var okM = /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?\+OK\b([^\r\n]*)$/i.exec(ln);
      if (okM && pendingUser) {
        var okRest = (okM[1] || '').trim();
        var isExplicitLoginOk = /\b(?:Logged\s+in|Mailbox\s+(?:locked|open)|maildrop\s+has|user\s+logged\s+in|authentication\s+succeeded)\b/i.test(okRest);
        if (stage === 'pass' || (stage === 'user' && isExplicitLoginOk)) {
          var cleanUser = C._clean_username ? C._clean_username(pendingUser) : pendingUser;
          var credVal = { service: 'pop3', protocol: 'pop3', port: port, outcome: 'accepted' };
          if (cleanUser || pendingUser) credVal.user = cleanUser || pendingUser;
          _add(facts, mkFact('credential.validated', h, credVal, S, source));
          if (cleanUser && pendingPass && !/^(?:<[^>]+>|\*+|\[redacted\])$/i.test(pendingPass) && (!C._valid_password || C._valid_password(pendingPass))) {
            if (C._add_plaintext_credential) {
              C._add_plaintext_credential(facts, ws, source, cleanUser, pendingPass, '', 'pop3-login', '');
            } else {
              var domScope = C._scope_for_domain ? C._scope_for_domain(ws) : h;
              _add(facts, mkFact('credential.plaintext', h, { user: cleanUser, password: pendingPass, via: 'pop3-login' }, S, source));
              _add(facts, mkFact('credential.available', domScope, { user: cleanUser, password: pendingPass, method: 'pop3-login' }, S, source));
            }
          }
          stage = 'authed';
        }
        continue;
      }
      var errM = /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?-ERR\b([^\r\n]*)$/i.exec(ln);
      if (errM && (stage === 'pass' || /\b(?:AUTH|authentication|login|invalid|password|logon)\b/i.test(errM[1] || ''))) {
        var failUser = pendingUser ? (C._clean_username ? C._clean_username(pendingUser) : pendingUser) : '';
        var failVal = { service: 'pop3', protocol: 'pop3', port: port, reason: (errM[1] || '').trim() || 'Authentication failed' };
        if (failUser) failVal.user = failUser;
        _add(facts, mkFact('blocker.logon_failure', h, failVal, S, source));
        stage = '';
      }
    }

    var mailUsers = [], mailFqdns = {};
    reAll(/^\s*(?:From|To|Cc|Delivered-To|Return-Path)\s*:\s*([^\r\n]+)$/gim, t).forEach(function (hm) {
      reAll(/([A-Za-z0-9_.+-]{1,64})@([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)/g, hm[1]).forEach(function (em) {
        var mu = em[1].trim();
        var md = em[2].replace(/\.$/, '').toLowerCase();
        if (!md || _POP3_PUBLIC_MAIL_DOMAINS_RE.test(md)) return;
        if ((C._IPV4_RE && C._IPV4_RE.test(md)) || /^\d+(?:\.\d+)+$/.test(md)) return;
        mailFqdns[md] = true;
        if (mu && !_POP3_SYSTEM_MAILBOX_RE.test(mu)) {
          mailUsers.push(mu);
        }
      });
    });
    if (mailUsers.length) {
      var uniqPopUsers = C.uniqueSortedCI(mailUsers);
      _add(facts, mkFact('host.users', h, { users: uniqPopUsers, count: uniqPopUsers.length, via: 'pop3-mail' }, S, source));
    }
    C.uniqueSortedCI(Object.keys(mailFqdns)).forEach(function (fqdn) {
      var parts = fqdn.split('.').filter(Boolean);
      var fVal = { fqdn: fqdn };
      if (parts.length > 2) {
        fVal.hostname = parts[0];
        fVal.domain = parts.slice(1).join('.');
      } else {
        fVal.domain = fqdn;
      }
      _add(facts, mkFact('host.fqdn', h, fVal, S, source));
    });

    return facts;
  }
  C._parse_pop3_output = _parse_pop3_output;

  var _IDENT_STOCK_ACCOUNTS_RE = /^(?:root|nobody|nogroup|daemon|www-data|apache|nginx|postgres|mysql|redis|sshd|unknown|<unknown>|bin|sys|sync|mail|lp|uucp|proxy|backup|list|irc|gnats|systemd-network|systemd-resolve|messagebus|postfix|dovecot|ftp|smmsp|ntp|rpc|rpcuser|avahi|haldaemon|dbus)$/i;

  function _parse_ident_output(text, a1, a2, a3, a4) {
    var unpacked = _unpack_service_args(text, a1, a2, a3, a4, 'ident-user-enum');
    var ws = unpacked.ws, source = unpacked.source, facts = unpacked.facts;
    var t = String(text || '');
    if (!t) return facts;
    var h = 'host:' + ((ws && ws.target) || 'unknown');
    var nonStock = [];
    reAll(/^\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\s+([A-Za-z_][A-Za-z0-9_.-]{0,31}|<unknown>)\s*$/gm, t).forEach(function (m) {
      var u = (m[3] || '').trim();
      if (u && !_IDENT_STOCK_ACCOUNTS_RE.test(u)) {
        nonStock.push(u);
      }
    });
    if (nonStock.length) {
      var uniqIdent = C.uniqueSortedCI(nonStock);
      _add(facts, mkFact('host.users', h, { users: uniqIdent, count: uniqIdent.length, via: 'ident' }, S, source));
    }
    return facts;
  }
  C._parse_ident_output = _parse_ident_output;
  C._parse_ident_user_enum = _parse_ident_output;

  var _X509_PUBLIC_CA_DENY_RE = /\.(?:letsencrypt\.org|digicert\.com|sectigo\.com|comodoca\.com|godaddy\.com|globalsign\.com|cloudflare\.com|amazonaws\.com|cloudfront\.net|aka(?:mai|maiedge)\.net|windows\.net|office\.com|microsoft\.com|entrust\.net|verisign\.com)$/i;

  function _parse_x509_cert(text, a1, a2, a3, a4) {
    var unpacked = _unpack_service_args(text, a1, a2, a3, a4, 'openssl-x509');
    var ws = unpacked.ws, command = unpacked.command, source = unpacked.source, facts = unpacked.facts;
    var t = String(text || '');
    if (!t) return facts;
    var cmd = String(command || '');
    var isX509Ctx = /\bopenssl\b[^\r\n]*\b(?:x509|s_client)\b/i.test(cmd)
      || /\bCertificate:\s*\r?\n\s*Data:/i.test(t)
      || /\bX509v3 Subject Alternative Name:\s*\r?\n/i.test(t)
      || (/^\s*Subject:\s*[^\r\n]*\bCN\s*=/im.test(t) && /^\s*Issuer:\s*[^\r\n]*\b(?:CN|DC|O)\s*=/im.test(t));
    if (!isX509Ctx) return facts;

    var h = 'host:' + ((ws && ws.target) || 'unknown');
    var fqdns = {}, bareDoms = {};
    function addCertName(raw) {
      var cand = String(raw || '').trim().replace(/^\*\./, '').replace(/\.$/, '').toLowerCase();
      if (!cand || cand.indexOf('.') < 0) return;
      if ((C._IPV4_RE && C._IPV4_RE.test(cand)) || /^\d+(?:\.\d+)+$/.test(cand)) return;
      if (/^(?:localhost|ocsp\.|crl\.)/i.test(cand) || _X509_PUBLIC_CA_DENY_RE.test(cand)) return;
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(cand)) return;
      if (!/\.[a-z][a-z0-9-]{1,}$/.test(cand)) return;
      fqdns[cand] = true;
    }

    reAll(/^\s*subject[=:]\s*[^\r\n]*?\bCN\s*=\s*([A-Za-z0-9*.-]+\.[A-Za-z]{2,})\b/gim, t).forEach(function (m) {
      addCertName(m[1]);
    });
    reAll(/\bDNS\s*:\s*([A-Za-z0-9*.-]+\.[A-Za-z]{2,})\b/gi, t).forEach(function (m) {
      addCertName(m[1]);
    });

    var names = C.uniqueSortedCI(Object.keys(fqdns));
    if (!names.length) return facts;

    var allKnown = [].concat(facts || [], (ws && ws.facts) || [], (ws && ws.seedFacts) || []);
    var hasLinuxOs = allKnown.some(function (f) {
      return f && f.scope === h && (f.kind === 'host.os_family' || f.kind === 'host.os_hint' || f.kind === 'os.guess') && f.value && f.value.family === 'linux';
    });
    var isLdapsOrAdPort = /(?::|\s)(?:636|3269|389|3268|5986|88|3389)\b|\bldaps?\b/i.test(cmd + ' ' + (source || ''))
      || allKnown.some(function (f) {
        return f && f.scope === h && (f.kind === 'port:636' || f.kind === 'port:3269' || f.kind === 'port:389' || f.kind === 'port:88' || f.kind === 'ldap.reachable' || f.kind === 'kerberos.reachable' || f.kind === 'ad.dc_candidate');
      });
    var hasAdCertMarkers = /\bDC\s*=\s*[A-Za-z0-9-]+|ldap:\/\/\/|1\.3\.6\.1\.4\.1\.311|\bCN\s*=\s*[A-Za-z0-9._-]+-CA\b/i.test(t);

    names.forEach(function (fqdn) {
      var parts = fqdn.split('.').filter(Boolean);
      var fVal = { fqdn: fqdn, via: 'x509' };
      var dom = '';
      if (parts.length > 2) {
        fVal.hostname = parts[0];
        dom = parts.slice(1).join('.');
        fVal.domain = dom;
      } else {
        fVal.hostname = parts[0];
        dom = fqdn;
        fVal.domain = fqdn;
      }
      _add(facts, mkFact('host.fqdn', h, fVal, S, source));
      if (dom) bareDoms[dom] = { hostLabel: parts.length > 2 ? parts[0] : '' };
    });

    Object.keys(bareDoms).sort().forEach(function (dom) {
      _add(facts, mkFact('host.domain', h, { domain: dom }, S, source));
      var hostLbl = bareDoms[dom].hostLabel;
      var hasBothHostAndZone = !!(hostLbl && fqdns[dom]);
      if (!hasLinuxOs && (isLdapsOrAdPort || hasAdCertMarkers || hasBothHostAndZone || /^dc\d*[-a-z0-9]*$/i.test(hostLbl) || /\.(?:local|corp|internal|lan)$/i.test(dom))) {
        _add(facts, mkFact('ad.domain_known', 'domain:' + dom, { name: dom, via: 'x509' }, S, source));
        if (C._base_dn_from_domain) {
          _add(facts, mkFact('ad.base_dn', 'domain:' + dom, { base_dn: C._base_dn_from_domain(dom) }, S, source));
        }
      }
    });
    return facts;
  }
  C._parse_x509_cert = _parse_x509_cert;
  C._parse_openssl_x509 = _parse_x509_cert;
  C._parse_tls_cert = _parse_x509_cert;

  OBOL.parsers = OBOL.parsers || {};
  OBOL.parsers.services = Object.assign(OBOL.parsers.services || {}, {
    _parse_http_metadata: _parse_http_metadata,
    _parse_ssh_banner: _parse_ssh_banner,
    _parse_ftp_output: _parse_ftp_output,
    _parse_sqlite_dump: _parse_sqlite_dump,
    _parse_rsync_nfs: _parse_rsync_nfs,
    _parse_smtp_output: _parse_smtp_output,
    _parse_imap_output: _parse_imap_output,
    _parse_pop3_output: _parse_pop3_output,
    _parse_ident_output: _parse_ident_output,
    _parse_ident_user_enum: _parse_ident_output,
    _parse_x509_cert: _parse_x509_cert
  });
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.parsers.services; }

})(typeof globalThis !== 'undefined' ? globalThis : this);
