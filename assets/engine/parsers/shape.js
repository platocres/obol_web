/*!
 * obol engine - parsers/shape.js
 * The output-shape fallback (Approach A): a final pass that recognizes common tool output by its
 * SHAPE, not by the command that produced it, so a paste with no command line (or a command the
 * dispatcher does not key on) still yields the facts the shape unambiguously proves.
 *
 * It is strictly additive and conservative:
 *   - every branch is guarded by `facts` it would duplicate, so it only fills gaps the command-keyed
 *     dispatch left, and never changes a result a real parser already produced;
 *   - every recognizer is anchored (line-start port rows, a real HTTP status line / Server header, a
 *     literal $krb5asrep$ / $krb5tgs$ hash token), so prose and unrelated output mint nothing;
 *   - hash shapes delegate to the real hash parsers, so the fact TYPE is always correct.
 * Facts are never invented: a shape that does not match adds nothing.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  if (!C || !C.mkFact) return;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  function hasKind(facts, kind) { return facts.some(function (f) { return f.kind === kind; }); }
  function hasPrefix(facts, pre) { return facts.some(function (f) { return f.kind && f.kind.indexOf(pre) === 0; }); }
  function uniqNums(arr) { var s = {}; arr.forEach(function (n) { s[n] = 1; }); return Object.keys(s).map(Number).sort(function (a, b) { return a - b; }); }

  function _parse_shape(text, ws, source, facts) {
    text = String(text || '');
    if (text.length > 10485760) text = text.slice(0, 10485760);
    if (C._normalize_cr) text = C._normalize_cr(text);
    if (C._strip_tmux_split) text = C._strip_tmux_split(text);
    if (C._unwrap_kerberos_hashes) text = C._unwrap_kerberos_hashes(text);
    if (!text.trim()) return;
    var h = 'host:' + ws.target;

    // (1) A bare "N/tcp open service" port table (or gnmap / masscan / rustscan row), pasted without an
    //     nmap command line. The row pattern is anchored and excludes open|filtered.
    if (!hasPrefix(facts, 'port:') && /(?:\d\/(?:tcp|udp)\b|\bOpen\s+\S+:\d+|\d\/open\/)/i.test(text)) {
      var rowRe = /^[ \t]*(\d{1,5})\/(tcp|udp)[ \t]+open(?![|\w])(?:[ \t]+(\S+))?/i;
      var discRe = /Discovered open port (\d{1,5})\/(tcp|udp) on \S+/i;
      var rustRe = /^\s*Open\s+(?:\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?):(\d{1,5})\s*$/i;
      var gnmapRe = /\b(\d{1,5})\/open\/(tcp|udp)\/[^\/,\r\n]*\/([^\/,\s\r\n]*)/gi;
      var summary = [], seen = {};
      function addShapePort(port, proto, service) {
        if (!port || port > 65535) return;
        proto = (proto || 'tcp').toLowerCase();
        var key = port + '/' + proto;
        if (seen[key]) return; seen[key] = 1;
        service = (service || '').trim();
        var value = { port: port, protocol: proto, via: 'shape' };
        if (service && service.toLowerCase() !== 'open') value.service = service;
        _add(facts, mkFact('port:' + port, h, value, S, source));
        if (value.service && C._normalize_service) _add(facts, mkFact('service.' + C._normalize_service(value.service), h, value, S, source));
        if (C._parse_service_reachability) C._parse_service_reachability(port, proto, value.service || '', ws, source, facts);
        summary.push(port);
      }
      if (/\/(?:tcp|udp)\b|->\s*\[/i.test(text)) {
        text.split(/\r?\n/).forEach(function (line) {
          var mm = rowRe.exec(line);
          if (mm) { addShapePort(parseInt(mm[1], 10), mm[2], mm[3]); return; }
          var dm = discRe.exec(line);
          if (dm) { addShapePort(parseInt(dm[1], 10), dm[2], ''); return; }
          var rm = rustRe.exec(line);
          if (rm) { addShapePort(parseInt(rm[1], 10), 'tcp', ''); return; }
          var gm;
          gnmapRe.lastIndex = 0;
          while ((gm = gnmapRe.exec(line)) !== null) {
            addShapePort(parseInt(gm[1], 10), gm[2], gm[3]);
          }
        });
      }
      if (summary.length) {
        _add(facts, mkFact('ports.open', h, { ports: uniqNums(summary), via: 'shape' }, S, source));
        if (!hasKind(facts, 'host.os_family') && C._add_os_from_text) {
          var osPortText = text.replace(/^\s*\d+\/(?:tcp|udp)\s+(?:closed|filtered|unfiltered|open\|filtered)\b[^\r\n]*$/gim, '');
          C._add_os_from_text(osPortText, ws, source, facts, 'shape', 'medium', true);
        }
      }
    }

    // (2) A bare HTTP response (a real status line, or a Server header), pasted without a web-client
    //     command. The dispatcher gates its HTTP parsers on curl/whatweb/wget/etc., so a raw response
    //     saved to a file mints nothing. A status line or a Server header is an unambiguous web signal.
    var isNslookup = /^Server:[ \t]*\S+[ \t]*\r?\nAddress(?:es)?[ \t]*:/im.test(text);
    var isSqlPaste = !!(C._is_sql_client_output && C._is_sql_client_output(text, ws, source));
    var isHttpShape = !isNslookup && !isSqlPaste && (/^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(text) || /^(?:<\s*)?Server:[ \t]*\S/im.test(text));
    if (isHttpShape && !hasKind(facts, 'http.reachable')) {
      _add(facts, mkFact('http.reachable', h, { via: 'shape' }, S, source));
      var servers = [];
      (text.match(/^(?:<\s*)?Server:[ \t]*(.+)$/gim) || []).forEach(function (l) {
        var v = l.replace(/^(?:<\s*)?Server:[ \t]*/i, '').trim();
        if (v && servers.indexOf(v) < 0) servers.push(v);
      });
      var webServers = servers.filter(function (hdr) { return !(C._isNonWebServerHeader && C._isNonWebServerHeader(hdr)); });
      if (webServers.length) _add(facts, mkFact('web.server', h, { headers: webServers.slice(0, 10), via: 'shape' }, S, source));
      if (!hasKind(facts, 'host.os_family') && C._add_os_from_text) {
        var hdrEndIdx = text.search(/\r?\n\r?\n|<html\b|<!doctype\b/i);
        var httpHdrBlock = hdrEndIdx >= 0 ? text.slice(0, hdrEndIdx) : text.slice(0, 4096);
        C._add_os_from_text(httpHdrBlock, ws, source, facts, 'shape', 'medium', true);
      }
    }

    // (3) A crackable-hash blob, pasted without the tool that produced it. Skip if the paste is
    //     already cracking output (e.g. hashcat --show `<hash>:<plaintext>`), so the plaintext isn't
    //     re-appended into the hash token.
    var isCrack = (C._is_cracking_command && C._is_cracking_command(source))
      || (text.indexOf('$krb5') >= 0 && /\$krb5(?:asrep|tgs)\$[^\s:]+\$[0-9a-f]{32,}:[^\s:]+/i.test(text))
      || (text.indexOf('::') >= 0 && /\b[A-Za-z0-9_.$ -]{1,64}::[A-Za-z0-9_.-]{1,64}:[0-9a-f]{16}:(?:[0-9a-f]{32}|[0-9a-f]{48}):[0-9a-f]{32,}:[^\s:]+/i.test(text));
    if (!isCrack && text.indexOf('$krb5asrep$') >= 0 && !hasKind(facts, 'hash.asrep') && C._parse_asrep_hashes) C._parse_asrep_hashes(text, ws, source, facts);
    if (!isCrack && text.indexOf('$krb5tgs$') >= 0 && !hasKind(facts, 'hash.tgs') && C._parse_tgs_hashes) C._parse_tgs_hashes(text, ws, source, facts);
    if (!isCrack && text.indexOf('::') >= 0 && !hasKind(facts, 'credential.netntlm')) {
      var netNtlmShapeRe = /\b([A-Za-z0-9_.$ -]{1,64})::([A-Za-z0-9_.-]{1,64}):([0-9a-fA-F]{16}):([0-9a-fA-F]{32}|[0-9a-fA-F]{48}):([0-9a-fA-F]{32,})(?![^\s"'])/g, mNn;
      var seenNnShape = Object.create(null);
      while ((mNn = netNtlmShapeRe.exec(text)) !== null) {
        var nnFull = mNn[0].trim();
        if (seenNnShape[nnFull]) continue;
        seenNnShape[nnFull] = 1;
        var nnUser = mNn[1].trim(), nnDom = mNn[2].trim();
        var nnFmt = mNn[4].length === 48 ? 'netntlmv1' : 'netntlmv2';
        var nnVal = { user: nnUser, domain: nnDom, hash: nnFull, format: nnFmt, hash_type: nnFmt, via: 'shape' };
        _add(facts, mkFact('credential.netntlm', h, nnVal, S, source));
        _add(facts, mkFact('hash.crackable', h, nnVal, S, source));
        _add(facts, mkFact('hash.candidate', h, nnVal, S, source));
        _add(facts, mkFact('credential.candidate', h, { user: nnUser, domain: nnDom, hash: nnFull, kind: nnFmt, via: 'shape' }, S, source));
      }
    }
    if (/^(?:ServicePrincipalName\s+Name|Name\s+MemberOf\s+PasswordLastSet)/im.test(text) && !hasKind(facts, 'ad.user_list') && C._parse_impacket_roast_table) {
      C._parse_impacket_roast_table(text, ws, source, facts);
    }
    if (!isCrack && text.indexOf(':::') >= 0 && !hasKind(facts, 'hash.ntlm') && !hasKind(facts, 'loot.sam')
        && /^(?:[A-Za-z0-9._-]+\\)?[A-Za-z0-9_.$-]+:\d{3,6}:(?:[0-9a-fA-F]{32}|NO PASSWORD\*+|\.{2,4}|\*+):[0-9a-fA-F]{32}:::/m.test(text)) {
      var samParser = C._parse_sam_hashes || C._parse_ntlm_dump;
      if (samParser) samParser(text, ws, '', source, facts);
    }

    // (4) Share download/upload output or GPP cpassword XML/grep without command
    if (((text.indexOf('getting file ') >= 0 && !hasKind(facts, 'loot.files'))
        || (text.indexOf('putting file ') >= 0 && !hasKind(facts, 'smb.writable_share')))
        && C._parse_share_inventory) {
      C._parse_share_inventory(text, ws, 'smbclient', source, facts);
    }
    if ((text.indexOf('cpassword=') >= 0 || text.indexOf('cpassword =') >= 0) && !facts.some(function (f) { return f && (f.kind === 'loot.gpp' || (f.kind === 'credential.candidate' && f.value && (f.value.kind === 'gpp' || f.value.kind === 'gpp_cpassword'))); }) && C._parse_gpp_artifacts) {
      C._parse_gpp_artifacts(text, ws, source, facts);
    }

    // (4b) Commandless PowerUp Write-HijackDll / Write-UserAddMSI / HijackablePath stanzas and DPAPI SecureString blobs
    if ((/\bAbuseFunction\s*:\s*(?:Write-HijackDll|Write-UserAddMSI)\b|\bHijackablePath\s*:/i.test(text))
        && !hasKind(facts, 'privesc.dll_hijack_candidate') && !hasKind(facts, 'privesc.always_install_elevated')
        && C._parse_privesc_output) {
      C._parse_privesc_output('windows-enum', text, ws, '', source, facts);
    }
    if (/\b01000000d08c9ddf0115d1118c7a00c04fc297eb[0-9a-fA-F]{160,}\b/i.test(text) && !hasKind(facts, 'privesc.stored_credentials')) {
      if (C._parse_windows_creds) {
        C._parse_windows_creds(text, ws, '', source, facts);
      } else {
        _add(facts, mkFact('privesc.stored_credentials', h, { kinds: ['dpapi'], count: 1, via: 'shape' }, S, source));
        _add(facts, mkFact('credential.candidate', h, { kind: 'dpapi_securestring', via: 'shape' }, S, source));
      }
    }

    // (5) Ligolo-ng or Chisel tunnel establishment / session shape pasted without command
    if ((/(\[Tunnel\] Interface ligolo is UP|session connected|Agent joined:)/i.test(text) || /ligolo-proxy[^\r\n]{0,80}?listening/i.test(text)) && !hasKind(facts, 'tunnel.route')) {
      _add(facts, mkFact('tunnel.route', h, { via: 'ligolo', shape: true }, S, source));
      _add(facts, mkFact('pivot.active', h, { via: 'ligolo', shape: true }, S, source));
    } else if ((/\bclient:\s+Connected\s*\(Latency|\btun:\s+proxy#R:/i.test(text)) && !hasKind(facts, 'tunnel.route')) {
      _add(facts, mkFact('tunnel.route', h, { via: 'chisel', shape: true }, S, source));
      _add(facts, mkFact('pivot.active', h, { via: 'chisel', shape: true }, S, source));
    }

    // (6) Raw SQLite database dump, table schema, or multi-row delimited user + digest dump shape
    var hasSqliteSchema = /SQLite format 3|CREATE TABLE\s+/i.test(text);
    if ((text.indexOf('|') >= 0 || hasSqliteSchema) && /(SQLite format 3|CREATE TABLE\s+(?:partners|users|accounts|credentials)|^\s*\d+\|[a-zA-Z0-9_.-]+\|\$2[aby]\$)/im.test(text) && !hasKind(facts, 'loot.material')) {
      _add(facts, mkFact('loot.material', h, { kind: 'sqlite_db', via: 'shape' }, S, source));
    }
    var _EMPTY_SHAPE_DIGEST_RE = /^(?:d41d8cd98f00b204e9800998ecf8427e|31d6cfe0d16ae931b73c59d7e0c089c0|aad3b435b51404eeaad3b435b51404ee|da39a3ee5e6b4b0d3255bfef95601890afd80709|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|0{32,128}|f{32,128})$/i;
    function _detectShapeDigestFormat(tok) {
      if (!tok || tok.length < 16) return '';
      if (/^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{50,}$/.test(tok)) return 'bcrypt';
      if (/^\$(?:1|5|6|y|apr1|P|H|NT)\$[^\s|,;]{8,}$/.test(tok)) return 'modular';
      if (/^\*[0-9A-Fa-f]{40}$/.test(tok) && !/^\*(?:0{40}|f{40})$/i.test(tok)) return 'mysql-sha1';
      if (/^md5[0-9a-fA-F]{32}$/.test(tok) && !_EMPTY_SHAPE_DIGEST_RE.test(tok.slice(3))) return 'postgres-md5';
      if (/^SCRAM-SHA-256\$\d+:[^\s|,;]+$/i.test(tok)) return 'postgres-scram-sha-256';
      if (/^pbkdf2_sha(?:1|256|512)\$\d+\$[^\s|,;]+$/i.test(tok)) return 'pbkdf2';
      if (/^sha(?:256|512)\$[A-Za-z0-9./$+=]{20,}$/i.test(tok)) return 'sha-crypt-web';
      if (/^[0-9a-fA-F]{32}$/.test(tok) && !_EMPTY_SHAPE_DIGEST_RE.test(tok)) return 'raw-md5';
      if (/^[0-9a-fA-F]{40}$/.test(tok) && !_EMPTY_SHAPE_DIGEST_RE.test(tok)) return 'raw-sha1';
      if (/^[0-9a-fA-F]{64}$/.test(tok) && !_EMPTY_SHAPE_DIGEST_RE.test(tok)) return 'raw-sha256';
      return '';
    }
    if (!isCrack && !hasKind(facts, 'hash.crackable') && !hasKind(facts, 'hash.ntlm')
        && (text.indexOf('\t') >= 0 || text.indexOf('|') >= 0 || text.indexOf(',') >= 0 || text.indexOf(';') >= 0)) {
      var delims = ['\t', '|', ',', ';'];
      var rawShapeLines = text.split(/\r?\n/);
      var maxDumpScan = Math.min(rawShapeLines.length, 5000);
      for (var dIdx = 0; dIdx < delims.length; dIdx++) {
        var dCh = delims[dIdx];
        if (text.indexOf(dCh) < 0) continue;
        var dumpRows = [], seenDumpPair = Object.create(null);
        for (var rli = 0; rli < maxDumpScan; rli++) {
          var rLn = rawShapeLines[rli].trim();
          if (!rLn || rLn.indexOf(dCh) < 0 || /^[+\-=|\s]+$/.test(rLn)) continue;
          if (/^[0-9a-fA-F]{32,64}\s{2,}\S/.test(rLn) || /^(?:[A-Za-z0-9._-]+\\)?[A-Za-z0-9_.$-]+:\d+:(?:[0-9a-fA-F]{32}|NO PASSWORD\*+|\.{2,4}|\*+):[0-9a-fA-F]{32}:::/.test(rLn)) continue;
          var dTrim = dCh === '|' ? rLn.replace(/^\||\|$/g, '') : rLn;
          var dCells = dTrim.split(dCh).map(function (c) { return c.trim().replace(/^['"]|['"]$/g, '').trim(); });
          if (dCells.length < 2 || dCells.length > 12) continue;
          var startCol = /^\d{1,10}$/.test(dCells[0]) ? 1 : 0;
          var rowUser = '', rowHash = '', rowFmt = '';
          for (var ci = startCol; ci < dCells.length; ci++) {
            var cellVal = dCells[ci];
            if (!cellVal) continue;
            if (!rowFmt) {
              var candFmt = _detectShapeDigestFormat(cellVal);
              if (candFmt) { rowHash = cellVal; rowFmt = candFmt; continue; }
            }
            if (!rowUser && /^[A-Za-z0-9._@-]{2,48}$/.test(cellVal) && /[A-Za-z]/.test(cellVal)
                && !/^[0-9a-fA-F]{16,}$/.test(cellVal)
                && !/^(?:id|uid|user|username|name|login|email|mail|pass|password|passwd|hash|digest|role|active|enabled|true|false|null|none|status|created_at|updated_at)$/i.test(cellVal)
                && (cellVal.indexOf('@') > 0 || !/\.(?:txt|php|html?|js|css|png|jpg|jpeg|gif|zip|tar|gz|exe|dll|sh|py|sql|db|bak|log|xml|json)$/i.test(cellVal))) {
              rowUser = cellVal;
            }
          }
          if (rowUser && rowHash && rowFmt) {
            var dpKey = rowUser.toLowerCase() + ':' + rowHash;
            if (!seenDumpPair[dpKey]) {
              seenDumpPair[dpKey] = 1;
              dumpRows.push({ user: rowUser, hash: rowHash, format: rowFmt });
            }
          }
        }
        var hasSelfEvidencingHash = dumpRows.some(function (r) { return r.format && r.format.indexOf('raw-') !== 0; });
        var minDumpRows = (hasSqliteSchema || hasSelfEvidencingHash) ? 1 : 2;
        if (dumpRows.length >= minDumpRows) {
          for (var dri = 0; dri < dumpRows.length; dri++) {
            var dr = dumpRows[dri];
            var dhVal = { user: dr.user, hash: dr.hash, format: dr.format, hash_type: dr.format, via: 'shape' };
            _add(facts, mkFact('hash.candidate', h, dhVal, S, source));
            _add(facts, mkFact('hash.crackable', h, dhVal, S, source));
            _add(facts, mkFact('credential.candidate', h, { user: dr.user, hash: dr.hash, kind: 'delimited_dump', via: 'shape' }, S, source));
          }
          if ((dCh === '|' || dCh === '\t') && (hasSqliteSchema || dumpRows.length >= 2) && !hasKind(facts, 'loot.material')) {
            _add(facts, mkFact('loot.material', h, { kind: 'sqlite_db', count: dumpRows.length, via: 'shape' }, S, source));
          }
          break;
        }
      }
    }

    // (6b) Debug / assertion digest-comparison leak shape (e.g. Rust assert_eq!, Go/C++/Python test panic)
    if (!isCrack && (/assertion\s+failed/i.test(text) || (/\bleft\s*:/i.test(text) && /\bright\s*:/i.test(text)) || (/\bexpected\s*:/i.test(text) && /\bactual\s*:/i.test(text)))) {
      var mAssert = /(?:left|expected)\s*[:=]\s*[`"']*([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})[`"']*[\s,;]+(?:right|actual)\s*[:=]\s*[`"']*([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})[`"']*/i.exec(text);
      if (mAssert && mAssert[1].length === mAssert[2].length) {
        var aLen = mAssert[1].length;
        var aFmt = aLen === 32 ? 'raw-md5' : (aLen === 40 ? 'raw-sha1' : (aLen === 64 ? 'raw-sha256' : 'raw-sha512'));
        var seenAssert = Object.create(null);
        [mAssert[1], mAssert[2]].forEach(function (dg) {
          var dgLow = dg.toLowerCase();
          if (seenAssert[dgLow] || _EMPTY_SHAPE_DIGEST_RE.test(dgLow)) return;
          seenAssert[dgLow] = 1;
          var aVal = { hash: dgLow, format: aFmt, hash_type: aFmt, via: 'shape-assertion' };
          _add(facts, mkFact('hash.candidate', h, aVal, S, source));
          _add(facts, mkFact('hash.crackable', h, aVal, S, source));
        });
      }
    }

    // (6c) Headerless PowerShell Get-ChildItem / dir attribute rows
    if (!hasKind(facts, 'loot.files') && /^[ \t]*(?:d|[arhs-])[arhs-]{4,5}[ \t]+(?:\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}|\d{4}[\/.-]\d{1,2}[\/.-]\d{1,2})[ \t]+\d{1,2}:\d{2}/im.test(text)) {
      var psRowRe = /^[ \t]*((?:d|[arhs-])[arhs-]{4,5})[ \t]+(?:\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}|\d{4}[\/.-]\d{1,2}[\/.-]\d{1,2})[ \t]+\d{1,2}:\d{2}(?::\d{2})?(?:[ \t]*[AP]M)?[ \t]+([^\r\n]+)$/gim;
      var psFiles = [], psSeen = Object.create(null), mPsRow;
      while ((mPsRow = psRowRe.exec(text)) !== null) {
        var psMode = mPsRow[1], psTail = mPsRow[2].trim();
        var psName = psMode.charAt(0).toLowerCase() === 'd'
          ? psTail.replace(/^<DIR>[ \t]+/i, '').trim()
          : psTail.replace(/^(?:<DIR>|\d+)[ \t]+/i, '').trim();
        if (!psName || psName === '.' || psName === '..' || psSeen[psName]) continue;
        psSeen[psName] = 1;
        psFiles.push(psName);
        var psBase = psName.split(/[\\\/]/).pop();
        if (/^(?:local|user|proof|root)\.txt$/i.test(psBase) && !hasKind(facts, 'objective.flag_located')) {
          _add(facts, mkFact('objective.flag_located', h, {
            file: psName,
            slot: /^(?:proof|root)\.txt$/i.test(psBase) ? 'root' : 'user',
            via: 'shape'
          }, S, source));
        }
      }
      if (psFiles.length) {
        _add(facts, mkFact('loot.files', h, { files: psFiles.slice(0, 200), count: psFiles.length, tool: 'powershell', via: 'shape' }, S, source));
      }
    }

    // (6c-posix) POSIX ls -l rows and multi-entry directory/find listings containing canonical flag files
    if (!isHttpShape && !/[╔╚╠═]{2,}|══╣|\bLinEnum\b|\bSuidEnum\b/i.test(text)) {
      var posixLsRe = /^[ \t]*[dl-][rwxstST-]{9}[.+@]?[ \t]+\d+[ \t]+\S+[ \t]+\S+[ \t]+\d+(?:[.,]\d+)?[KMGTPE]?[ \t]+(?:[A-Z][a-z]{2}[ \t]+\d{1,2}[ \t]+(?:\d{2}:\d{2}|\d{4})|\d{4}-\d{2}-\d{2}[ \t]+\d{2}:\d{2}(?::\d{2})?(?:[ \t]*[+-]\d{4})?)[ \t]+([^\r\n]+)$/gim;
      var lsFiles = [], lsSeen = Object.create(null), mLs;
      var promptCwd = '';
      var ctxPromptStr = (ws && ws.context && ws.context.promptLine) ? String(ws.context.promptLine) : '';
      if (ctxPromptStr) {
        var pCwdM = /(?:\[[^\]:\s]+@[^\]:\s]+[:\s]+([^\]]+)\]|[^\s@]+@[^\s:]+:([^\r\n$#%>\]]+))\s*[#$%]/.exec(ctxPromptStr);
        var rawCwd = pCwdM ? String(pCwdM[1] || pCwdM[2] || '').trim() : '';
        if (rawCwd && rawCwd.charAt(0) === '/') promptCwd = rawCwd.replace(/\/+$/, '');
      }
      if (!promptCwd && source) {
        var pgDirM = /\bpg_ls_dir\s*\(\s*'(\/[^'\r\n]+)'\s*\)/i.exec(String(source));
        if (pgDirM && pgDirM[1]) promptCwd = pgDirM[1].replace(/\/+$/, '');
      }
      function recordFlagCandidate(entryName) {
        var cleanEntry = String(entryName || '').replace(/\s+->\s+.*$/, '').trim();
        if (!cleanEntry || cleanEntry === '.' || cleanEntry === '..') return;
        var base = cleanEntry.split(/[\\\/]/).pop();
        if (!/^(?:local|user|proof|root)\.txt$/i.test(base)) return;
        var resolvedPath = (cleanEntry.indexOf('/') < 0 && cleanEntry.indexOf('\\') < 0 && promptCwd)
          ? (promptCwd + '/' + cleanEntry)
          : cleanEntry;
        var slot = /^(?:proof|root)\.txt$/i.test(base) ? 'root' : 'local';
        var alreadySlot = facts.some(function (f) {
          return f && f.kind === 'objective.flag_located' && f.value && (f.value.slot === slot || f.value.file === resolvedPath || f.value.path === resolvedPath);
        });
        if (!alreadySlot) {
          _add(facts, mkFact('objective.flag_located', h, {
            path: resolvedPath,
            file: resolvedPath,
            slot: slot,
            via: 'shape'
          }, S, source));
        }
      }
      if (/[dl-][rwx-]{2}[rwxstST-][rwx-]{2}[rwxstST-][rwx-]{2}[rwxstST-]/.test(text)) {
        while ((mLs = posixLsRe.exec(text)) !== null) {
          if (mLs[1].indexOf('--->') >= 0) continue;
          var lsEntry = mLs[1].replace(/\s+->\s+.*$/, '').trim();
          if (!lsEntry || lsEntry === '.' || lsEntry === '..' || lsSeen[lsEntry]) continue;
          if (/^\/(?:usr\/(?:bin|sbin|lib|lib64|libexec)|bin|sbin|lib|lib64)\//i.test(lsEntry)) continue;
          lsSeen[lsEntry] = 1;
          lsFiles.push(lsEntry);
          recordFlagCandidate(lsEntry);
        }
      }
      if (lsFiles.length && !hasKind(facts, 'loot.files')) {
        _add(facts, mkFact('loot.files', h, { files: lsFiles.slice(0, 200), count: lsFiles.length, tool: 'ls', via: 'shape' }, S, source));
      }
      if ((text.indexOf('.txt') >= 0 || text.indexOf('.TXT') >= 0) && /(?:^|[\\\/\s])(?:local|user|proof|root)\.txt\b/i.test(text)) {
        var findFlagRe = /^[ \t]*((?:\/|\.\.?\/|[A-Za-z]:\\)[^\r\n:*?"<>|]*?[\\\/](?:local|user|proof|root)\.txt)[ \t]*$/gim;
        var mFf, findFiles = [];
        while ((mFf = findFlagRe.exec(text)) !== null) {
          var ffPath = mFf[1].trim();
          findFiles.push(ffPath);
          recordFlagCandidate(ffPath);
        }
        if (findFiles.length && !hasKind(facts, 'loot.files')) {
          _add(facts, mkFact('loot.files', h, { files: findFiles.slice(0, 200), count: findFiles.length, tool: 'find', via: 'shape' }, S, source));
        }
        var isBareLsCmd = /^\s*(?:sudo\s+)?(?:ls|dir)\b|\bpg_ls_dir\s*\(/i.test(source || '');
        if (!lsFiles.length && !findFiles.length) {
          var rawDirLines = text.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean);
          if (rawDirLines.length >= (isBareLsCmd ? 1 : 2) && rawDirLines.length <= 60) {
            var dirToks = [], allFilenameLines = true;
            for (var dli = 0; dli < rawDirLines.length; dli++) {
              var curDirLn = rawDirLines[dli];
              if (/^total\s+\d+$/i.test(curDirLn) || /^\(\d+\s+rows?\)$/i.test(curDirLn) || /^[-+]{3,}$/.test(curDirLn)) continue;
              if (dli + 1 < rawDirLines.length && /^[-+]{3,}$/.test(rawDirLines[dli + 1]) && /^[A-Za-z_][A-Za-z0-9_]*$/.test(curDirLn)) continue;
              if (dli === rawDirLines.length - 1 && /^[A-Za-z_][A-Za-z0-9_]*=[#>-]$/.test(curDirLn)) continue;
              if (/^\|.*\|$/.test(curDirLn)) curDirLn = curDirLn.replace(/^\|\s*|\s*\|$/g, '');
              var lToks = curDirLn.split(/\s+/).filter(Boolean);
              if (!lToks.length) continue;
              if (lToks.length > 8) { allFilenameLines = false; break; }
              for (var dti = 0; dti < lToks.length; dti++) {
                var dTok = lToks[dti];
                if (dTok === '.' || dTok === '..') continue;
                if (!/^\.?[A-Za-z0-9_.-]{1,64}\/?$/.test(dTok) || /^(?:cat|type|more|less|head|tail|find|ls|dir|cd|rm|cp|mv)$/i.test(dTok)) {
                  allFilenameLines = false;
                  break;
                }
                dirToks.push(dTok.replace(/\/$/, ''));
              }
              if (!allFilenameLines) break;
            }
            if (allFilenameLines && dirToks.length >= (isBareLsCmd ? 1 : 2)
                && dirToks.some(function (tk) { return /^(?:local|user|proof|root)\.txt$/i.test(tk); })) {
              for (var fti = 0; fti < dirToks.length; fti++) recordFlagCandidate(dirToks[fti]);
              if (!hasKind(facts, 'loot.files')) {
                _add(facts, mkFact('loot.files', h, { files: dirToks.slice(0, 200), count: dirToks.length, tool: 'ls', via: 'shape' }, S, source));
              }
            }
          }
        }
      }
    }

    // (6d) Document metadata (exiftool / PDF metadata) Author & Creator username shape
    if (!hasKind(facts, 'web.users') && /^[ \t]*(?:Author|Creator)[ \t]*:/im.test(text)) {
      var hasExifBanner = /^[ \t]*ExifTool Version Number[ \t]*:[ \t]*\S/im.test(text);
      var metaFieldMatches = !hasExifBanner ? (text.match(/^[ \t]*(?:File Name|File Size|File Type|MIME Type|PDF Version|Create Date|Modify Date|Producer|Creator Tool|Page Count|Linearized|Title|Subject)[ \t]*:[ \t]*\S/gim) || []) : [];
      if (hasExifBanner || metaFieldMatches.length >= 3) {
        var metaAuthorRe = /^[ \t]*(?:Author|Creator)[ \t]*:[ \t]*([^\r\n]+)$/gim;
        var generatorNoiseRe = /\b(?:Writer|Calc|Impress|Draw|Math|LibreOffice|OpenOffice|Microsoft|Office|Word|Excel|PowerPoint|Outlook|Visio|Publisher|Adobe|Acrobat|InDesign|Illustrator|Photoshop|Distiller|FrameMaker|LiveCycle|Quartz|Mac\s*OS|macOS|Preview|Pages|Keynote|Numbers|Ghostscript|wkhtmltopdf|LaTeX|pdflatex|xelatex|lualatex|TeX|dvips|Mozilla|Firefox|Chrome|Chromium|Safari|Edge|Skia|ReportLab|PyPDF\d*|pypdf|fpdf\d*|TCPDF|DOMPDF|mPDF|iText|Apache\s*FOP|PDFBox|Cairo|Pango|ImageMagick|GraphicsMagick|GIMP|Inkscape|Canva|Figma|Scanner|Scan|Printer|Xerox|Canon|Epson|HP|Brother|Ricoh|Konica|Unknown|None|Null|N\/A|Untitled|Default|System|User|Admin|Administrator|root|guest|test)\b/i;
        var metaUsers = [], metaSeen = Object.create(null), mAuth;
        function addMetaUser(uCand) {
          var uClean = String(uCand || '').trim();
          if (!uClean || uClean.length < 2 || uClean.length > 32 || metaSeen[uClean]) return;
          if (C._valid_username && !C._valid_username(uClean, false)) return;
          metaSeen[uClean] = 1;
          metaUsers.push(uClean);
        }
        while ((mAuth = metaAuthorRe.exec(text)) !== null) {
          var rawAuthor = mAuth[1].trim().replace(/^['"]|['"]$/g, '').trim();
          if (!rawAuthor || rawAuthor.length < 2 || rawAuthor.length > 48 || /^\d+$/.test(rawAuthor)) continue;
          if (/[\\\/]|https?:/i.test(rawAuthor) || generatorNoiseRe.test(rawAuthor)) continue;
          var emailM = /^([A-Za-z0-9._-]+)@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.exec(rawAuthor);
          if (emailM) {
            addMetaUser(emailM[1].toLowerCase());
          } else if (/^[A-Za-z][A-Za-z0-9._-]{1,31}$/.test(rawAuthor)) {
            addMetaUser(/^[A-Z][a-z]+$/.test(rawAuthor) ? rawAuthor.toLowerCase() : rawAuthor);
          } else {
            var twoWordM = /^([A-Z][a-z]{1,20})[ \t]+([A-Z][a-z]{1,24})$/.exec(rawAuthor);
            if (twoWordM) {
              addMetaUser((twoWordM[1].charAt(0) + twoWordM[2]).toLowerCase());
              addMetaUser(twoWordM[1].toLowerCase());
            }
          }
        }
        if (metaUsers.length) {
          _add(facts, mkFact('web.users', h, { users: metaUsers, count: metaUsers.length, tool: 'exiftool', via: 'shape' }, S, source));
        }
      }
    }

    // (6e) Command-less PEM / OpenSSH / PuTTY private key shape
    if (/-----BEGIN (?:OPENSSH|RSA|DSA|EC|ENCRYPTED(?: PRIVATE KEY)?) PRIVATE KEY-----|PuTTY-User-Key-File-\d/.test(text)) {
      var isEncPem = /ENCRYPTED|Proc-Type:\s*4\s*,\s*ENCRYPTED|DEK-Info:/i.test(text)
        || /\bb3BlbnNzaC1rZXktdjEAAAAA(?!BG5vbmU)[A-Za-z0-9+/]{4}/.test(text);
      if (!hasKind(facts, 'loot.ssh_key')) _add(facts, mkFact('loot.ssh_key', h, { encrypted: isEncPem, via: 'shape' }, S, source));
      if (!hasKind(facts, 'credential.ssh_key')) _add(facts, mkFact('credential.ssh_key', h, { encrypted: isEncPem, via: 'shape' }, S, source));
      if (!hasKind(facts, 'credential.certificate')) _add(facts, mkFact('credential.certificate', h, { kind: 'private_key', encrypted: isEncPem, via: 'shape' }, S, source));
      if (isEncPem && !hasKind(facts, 'hash.crackable')) {
        _add(facts, mkFact('hash.crackable', h, { format: 'ssh', hash_type: 'ssh', tool: 'ssh2john', via: 'shape' }, S, source));
        _add(facts, mkFact('hash.candidate', h, { format: 'ssh', hash_type: 'ssh', tool: 'ssh2john', via: 'shape' }, S, source));
      }
    }

    // (6f) Command-less 10-field BSD master.passwd, standard 7-field /etc/passwd, and LinPEAS box-drawing section slices
    if (!hasKind(facts, 'loot.shadow') && text.indexOf(':$') >= 0 && C._parse_shadow_file
        && /^[a-z_][a-z0-9_.-]{0,31}:\$(?:1|2[abxy]|5|6|y)\$[^\s:]+:\d+:\d+:[^:\r\n]*:\d+:\d+:[^:\r\n]*:\/[^\s:]*:[^\r\n]*$/im.test(text)) {
      C._parse_shadow_file(text, '', ws, source, facts);
    }
    if (!isHttpShape && text.indexOf(':/') >= 0 && !/\b(?:curl|wget|httpie|burp|ffuf|wfuzz|sqlmap)\b|\bhttps?:\/\//i.test(source || '')) {
      var pwRowRe = /^[ \t]*([a-z_][a-z0-9_.-]{0,31}):([^:\r\n]*):(\d+):(\d+):([^:\r\n]*):(\/[^\s:]*):(\/[^\s:\r\n]*)[ \t]*$/gm;
      var pwRows = [], pwHumans = [], pwSeen = Object.create(null), mPw;
      while ((mPw = pwRowRe.exec(text)) !== null) {
        var pwUser = mPw[1], pwUid = parseInt(mPw[3], 10), pwShell = mPw[7];
        pwRows.push(mPw[0].trim());
        var hasLoginShell = /(?:\/(?:ba|da|z|k|a|tc|c)?sh|\/fish)$/i.test(pwShell) && !/(?:nologin|false)$/i.test(pwShell);
        if ((pwUid === 0 || (pwUid >= 1000 && pwUid < 65534) || hasLoginShell) && !pwSeen[pwUser]) {
          pwSeen[pwUser] = 1;
          pwHumans.push(pwUser);
        }
      }
      if (pwRows.length >= 3) {
        if (C._add_os_observation) {
          C._add_os_observation(facts, ws, source, 'linux', pwRows[0], 'high', 'passwd-shape', true);
        }
        if (!hasKind(facts, 'config.review')) {
          _add(facts, mkFact('config.review', h, { kind: 'passwd', users: pwHumans, count: pwRows.length, via: 'shape' }, S, source));
        }
      }
    }
    if (/(?:\u2554\u2550+\u2563|\u2560\u2550+\u2563)\s*[A-Za-z]/.test(text)
        && !(C._looks_like_winpeas && C._looks_like_winpeas(text))
        && C._parse_privesc_output) {
      C._parse_privesc_output('linux-enum', text, ws, '', source, facts);
    }

    // (6g) Colon-aligned `<principal> : <32-hex>` NTLM hash summary table shape
    if (!isCrack && !hasKind(facts, 'hash.ntlm') && text.indexOf(':') >= 0
        && /^[ \t]*[A-Za-z0-9_.$\\@-]{2,64}[ \t]*:[ \t]*[0-9a-fA-F]{32}[ \t]*$/m.test(text.length > 8192 ? text.slice(0, 8192) : text)) {
      var colonTblLines = text.split(/\r?\n/);
      var colonRowRe = /^[ \t]*([A-Za-z0-9_.$\\@-]{2,64})[ \t]*:[ \t]*([0-9a-fA-F]{32})[ \t]*$/;
      var colonRows = [], colonSeen = Object.create(null), colonContentCount = 0;
      for (var cli = 0; cli < colonTblLines.length && cli < 5000; cli++) {
        var cRaw = colonTblLines[cli].trim();
        if (!cRaw || /^[-=+*#|\s]+$/.test(cRaw)) continue;
        colonContentCount++;
        var cm = colonRowRe.exec(cRaw);
        if (!cm) continue;
        var cPrin = cm[1], cHex = cm[2].toLowerCase();
        if (/^(?:0{32}|f{32}|d41d8cd98f00b204e9800998ecf8427e)$/.test(cHex)) continue;
        if (/^[0-9a-fA-F]{16,}$/.test(cPrin)) continue;
        if (/^(?:md5|md5sum|etag|hash|digest|checksum|uuid|guid|id|token|session|key|iv|salt|nonce|signature)$/i.test(cPrin)) continue;
        if (/\.(?:exe|dll|zip|tar|gz|tgz|txt|pdf|doc|docx|xls|xlsx|png|jpg|jpeg|gif|iso|bin|elf|sh|py|php|js|jar|war|bak|sql|db)$/i.test(cPrin)) continue;
        var cKey = cPrin.toLowerCase() + ':' + cHex;
        if (!colonSeen[cKey]) {
          colonSeen[cKey] = 1;
          colonRows.push({ principal: cPrin, nthash: cHex });
        }
      }
      if (colonRows.length >= 3 && colonContentCount > 0 && (colonRows.length / colonContentCount) >= 0.6) {
        var tblDomScope = C._scope_for_domain ? C._scope_for_domain(ws) : h;
        var emittedNtds = false;
        for (var cri = 0; cri < colonRows.length; cri++) {
          var cr = colonRows[cri];
          var cDom = '', cUser = cr.principal;
          if (cUser.indexOf('\\') >= 0) {
            var bsIdx = cUser.indexOf('\\');
            cDom = cUser.slice(0, bsIdx);
            cUser = cUser.slice(bsIdx + 1);
          } else if (cUser.indexOf('@') > 0) {
            var atIdx = cUser.indexOf('@');
            cDom = cUser.slice(atIdx + 1);
            cUser = cUser.slice(0, atIdx);
          }
          if (!cUser) continue;
          var ntTblVal = { user: cUser, nthash: cr.nthash, hash: cr.nthash, hash_type: 'ntlm', secret_type: 'NT', via: 'shape-ntlm-table' };
          if (cDom) ntTblVal.domain = cDom;
          _add(facts, mkFact('hash.ntlm', h, ntTblVal, S, source));
          _add(facts, mkFact('credential.candidate', h, { user: cUser, domain: cDom || undefined, nthash: cr.nthash, hash: cr.nthash, kind: 'ntlm_table', via: 'shape-ntlm-table' }, S, source));
          if (cUser.toLowerCase() === 'krbtgt' && cr.nthash !== '31d6cfe0d16ae931b73c59d7e0c089c0') {
            _add(facts, mkFact('hash.krbtgt', tblDomScope, { user: 'krbtgt', nthash: cr.nthash, via: 'shape-ntlm-table' }, S, source));
            if (!emittedNtds && !hasKind(facts, 'loot.ntds')) {
              emittedNtds = true;
              _add(facts, mkFact('loot.ntds', tblDomScope, { count: colonRows.length, via: 'shape-ntlm-table' }, S, source));
            }
          } else if (cUser.charAt(cUser.length - 1) !== '$'
                     && !/^(?:guest|defaultaccount|wdagutilityaccount)$/i.test(cUser)
                     && cr.nthash !== '31d6cfe0d16ae931b73c59d7e0c089c0') {
            _add(facts, mkFact('credential.ntlm_hash', h, ntTblVal, S, source));
            _add(facts, mkFact('credential.available', h, ntTblVal, S, source));
          }
        }
      }
    }

    // (7) Ping TTL heuristic: TTL 60..64 -> Linux os_hint, TTL 124..128 -> Windows os_hint (promote = false)
    if (!hasKind(facts, 'host.os_family') && !hasKind(facts, 'host.os_hint') && C._add_os_observation && /ttl=/i.test(text)) {
      var mTtl = /\b\d+\s+bytes\s+from\s+\S+[^\r\n]{0,120}?\bttl=(\d{1,3})\b/i.exec(text) || /Reply from \S+:\s+bytes=\d+\s+time[=<]\S+\s+TTL=(\d{1,3})/i.exec(text);
      if (mTtl) {
        var ttl = parseInt(mTtl[1], 10);
        if (ttl >= 60 && ttl <= 64) {
          C._add_os_observation(facts, ws, source, 'linux', mTtl[0], 'medium', 'ping-ttl', false);
        } else if (ttl >= 124 && ttl <= 128) {
          C._add_os_observation(facts, ws, source, 'windows', mTtl[0], 'medium', 'ping-ttl', false);
        }
      }
    }

    // (8) Un-keyed OS / kernel / version shapes (uname -a, /proc/version, uname -r, /etc/os-release, lsb_release, ver, sudo -V, pkexec --version)
    // Skip raw HTTP HTML bodies unless the HTTP response also proves RCE / LFI (e.g. uid=0(root) or root:x:0:0:).
    var isWebRceShape = /uid=\d+\([A-Za-z0-9_.-]+\)|^root:[x*!]:0:0:/m.test(text);
    if (!isHttpShape || isWebRceShape) {
      if (!hasKind(facts, 'host.kernel')) {
        var mUname = C._UNAME_RE && C._UNAME_RE.exec(text);
        var mProcVer = !mUname && /Linux version\s+([0-9][^\s]+)/i.exec(text);
        var mBareKernel = !mUname && !mProcVer && /^\s*([2-6]\.\d+\.\d+-(?:[0-9A-Za-z.+_-]*(?:generic|amd64|i[3-6]86|arm64|el\d|kali|debian|ubuntu|arch|alpine)[0-9A-Za-z.+_-]*|\d+-[A-Za-z0-9.+_-]+))\s*$/m.exec(text);
        if (mUname || mProcVer || mBareKernel) {
          var kStr = mUname ? ((mUname.groups && mUname.groups.kernel) || mUname[2]) : (mProcVer ? mProcVer[1] : mBareKernel[1].trim());
          var archStr = mUname ? ((mUname.groups && mUname.groups.arch) || mUname[3]) : '';
          var kLine = (mUname ? mUname[0] : (mProcVer ? mProcVer[0] : mBareKernel[0])).trim();
          _add(facts, mkFact('host.kernel', h, { kernel: kStr, via: 'shape' }, S, source));
          if (archStr && !hasKind(facts, 'host.arch')) {
            _add(facts, mkFact('host.arch', h, { arch: archStr, via: 'shape' }, S, source));
          }
          if (C._add_os_observation) {
            var kProd = C._os_product_from_label ? C._os_product_from_label(kLine, 'linux') : null;
            C._add_os_observation(facts, ws, source, 'linux', kLine, 'high', 'uname', true, kProd);
          }
          var isRemoteSnmpOrScan = /\b(?:snmpwalk|snmp-check|onesixtyone|nmap)\b/i.test(source || '');
          if (!isRemoteSnmpOrScan && C._check_linux_kernel_vulns) C._check_linux_kernel_vulns(kStr, ws, source, facts);
        }
        var mWinVer = /Microsoft Windows \[Version\s+([0-9.]+)\]/i.exec(text);
        if (mWinVer) {
          var wVer = mWinVer[1].trim();
          _add(facts, mkFact('host.kernel', h, { kernel: wVer, tool: 'ver', via: 'shape' }, S, source));
          if (C._add_os_observation) {
            C._add_os_observation(facts, ws, source, 'windows', mWinVer[0], 'high', 'ver', true, 'Windows ' + wVer);
          }
        }
      }
      var mOsRel = /PRETTY_NAME\s*=\s*["']?([^"'\r\n]+)["']?/i.exec(text) || /Distributor ID:\s*(\S+)/i.exec(text);
      if (mOsRel && C._add_os_observation) {
        C._add_os_observation(facts, ws, source, 'linux', mOsRel[0], 'high', 'os-release', true, mOsRel[1].trim());
      }
      var mSudoV = /Sudo(?:\s+version|\s+policy\s+plugin\s+version)\s+(1\.(?:8\.(?:[2-9]|[12]\d|3[01])|9\.[0-5](?:p1)?))\b/i.exec(text);
      if (mSudoV && !hasKind(facts, 'vuln.baron_samedit')) {
        _add(facts, mkFact('vuln.baron_samedit', h, { version: mSudoV[1], cve: 'CVE-2021-3156', via: 'shape', lead: true }, S, source));
      }
      var mPkexec = /pkexec\s+version\s+(0\.(?:0\d\d|10[0-5]))\b/i.exec(text);
      if (mPkexec && !hasKind(facts, 'vuln.polkit')) {
        _add(facts, mkFact('vuln.polkit', h, { version: mPkexec[1], cve: 'CVE-2021-4034', via: 'shape', lead: true }, S, source));
      }
    }

    _parse_family_resemblance(text, ws, source, facts);
  }

  function _parse_family_resemblance(text, ws, source, facts) {
    text = String(text || '');
    if (text.length > 10485760) text = text.slice(0, 10485760);
    if (!text.trim()) return;
    var h = 'host:' + ws.target;
    var domScope = C._scope_for_domain ? C._scope_for_domain(ws) : h;
    if (text.length > 65536
        && !/\b(?:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember|AddSelf|AllExtendedRights|ENROLLEE_SUPPLIES_SUBJECT|ESC\d+|SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeBackupPrivilege|SeRestorePrivilege|NOPASSWD|cap_[a-z_]+\+[eip]+)\b/i.test(text)) {
      return;
    }
    var lines = text.split(/\r?\n/);

    // 1. AD ACL / Object Control Family
    // Lines containing both an ACL right token and a target/principal identifier
    var isHttpResp = /^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(text);
    var isKnownLinux = (ws && (ws.facts || ws.seedFacts) || []).some(function (f) {
      return f && f.scope === h && (f.kind === 'foothold.linux' || (f.kind === 'host.os_family' && f.value && f.value.family === 'linux'));
    });
    if (!hasKind(facts, 'ad.acl_lead') && !hasKind(facts, 'ad.control_paths') && !isHttpResp && !isKnownLinux) {
      var aclRightRe = /\b(GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember|AddSelf|AllExtendedRights|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|WriteSPN|WriteProperty)\b/i;
      var aclPrincipalRe = /(?:CN=|DC=|@|(?<![a-zA-Z0-9._-])[a-zA-Z0-9._-]{1,64}\\[a-zA-Z0-9._-]{1,64}|\bDomain Admins\b|\bBackup Operators\b|\bDnsAdmins\b|\bUsers\b|\bComputers\b)/i;
      var matchedAclRight = '', matchedPrincipal = '';
      for (var i = 0; i < lines.length; i++) {
        var l = lines[i];
        var mr = aclRightRe.exec(l);
        if (!mr) continue;
        var mp = aclPrincipalRe.exec(l);
        if (mp) {
          matchedAclRight = mr[1];
          matchedPrincipal = mp[0];
          break;
        }
      }
      if (matchedAclRight) {
        _add(facts, mkFact('ad.acl_lead', domScope, { right: matchedAclRight, principal: matchedPrincipal, via: 'shape' }, S, source));

      }
    }

    // 2. ADCS / Certificate Template Family
    // Output containing both a CA/template header and an explicit vulnerability/ESC signal
    if (!hasKind(facts, 'adcs.vulnerable')) {
      var adcsHeaderRe = /(?:CA Name|Template Name|pKIEnrollmentService|Certipy|Certificate Authorities)/i;
      var adcsVulnRe = /(?:Enrollee\s*Supplies\s*Subject["']?\s*:\s*(?:True|true)|ENROLLEE_SUPPLIES_SUBJECT|\bESC[1-9]\d?\b|\[!\]\s*Vulnerabilities)/i;
      if (adcsHeaderRe.test(text) && adcsVulnRe.test(text)) {
        var esc = [];
        if (/\bESC1\b|Enrollee\s*Supplies\s*Subject["']?\s*:\s*(?:True|true)|ENROLLEE_SUPPLIES_SUBJECT/i.test(text)) esc.push('ESC1');
        var escM = text.match(/\bESC([2-9]|1[0-5])\b/gi) || [];
        escM.forEach(function (e) {
          var up = e.toUpperCase();
          if (esc.indexOf(up) < 0) esc.push(up);
        });
        _add(facts, mkFact('adcs.vulnerable', domScope, { esc: esc, via: 'shape' }, S, source));
      }
    }

    // 3. Kerberos SPN & AS-REP Directory Entry Family
    // Output containing both an identity field and either a <service>/<host> SPN pattern or DONT_REQ_PREAUTH
    if (!hasKind(facts, 'ad.user_list')) {
      var idFieldRe = /(?:sAMAccountName|\bcn:|\bUser:)\s*[:=]\s*([A-Za-z0-9._-]+)/gi;
      var spnRe = /\b(MSSQLSvc|HTTP|cifs|ldap|host|wsman|krbtgt|exchangeMDB)\/(?![0-9]+(?:\.[0-9]+)?\b)([A-Za-z0-9._-]*[A-Za-z][A-Za-z0-9._-]*)/i;
      var asrepRe = /(?:DONT_REQ_PREAUTH|UF_DONT_REQUIRE_PREAUTH|DoesNotRequirePreAuth\s*:\s*True)/i;
      if (spnRe.test(text) || asrepRe.test(text)) {
        var foundUsers = [], foundUsersSeen = Object.create(null), mId;
        while ((mId = idFieldRe.exec(text)) !== null) {
          var uName = mId[1];
          if (uName && !foundUsersSeen[uName] && !/\//.test(uName)) { foundUsersSeen[uName] = 1; foundUsers.push(uName); }
        }
        if (foundUsers.length) {
          _add(facts, mkFact('ad.user_list', domScope, { users: foundUsers, count: foundUsers.length, via: 'shape' }, S, source));
        }
      }
    }

    // 4. Share Table Family
    // Multi-line table containing at least one standard share alongside permission tokens (READ, WRITE, Disk),
    // or a bare command-less SMB share list containing >= 2 canonical share anchors.
    if (!hasKind(facts, 'smb.shares')) {
      var stdShareRe = /(?:^|\s)(?:IPC\$|ADMIN\$|C\$|SYSVOL|NETLOGON)(?=\s|$)/i;
      var permRe = /\b(READ|WRITE|Disk)\b/i;
      if (stdShareRe.test(text) && permRe.test(text)) {
        _add(facts, mkFact('smb.shares', h, { via: 'shape' }, S, source));
        var hasRead = false, hasWrite = false;
        for (var j = 0; j < lines.length; j++) {
          var row = lines[j];
          if (/(?:^|\s)(?:IPC\$|PRINT\$)(?=\s|$)/i.test(row) || /\bNO\s+ACCESS\b/i.test(row)) continue;
          if (/\bREAD\b/i.test(row)) hasRead = true;
          if (/\bWRITE\b/i.test(row)) hasWrite = true;
        }
        if (hasRead && !hasKind(facts, 'smb.readable_share')) _add(facts, mkFact('smb.readable_share', h, { via: 'shape' }, S, source));
        if (hasWrite && !hasKind(facts, 'smb.writable_share')) _add(facts, mkFact('smb.writable_share', h, { via: 'shape' }, S, source));
      } else if (C._parse_smb_shares && lines.length <= 32 && (text.match(/^[ \t]*(?:ADMIN\$|C\$|IPC\$|SYSVOL|NETLOGON|PRINT\$)[ \t]*$/gim) || []).length >= 2) {
        C._parse_smb_shares(text, ws, source, facts);
      }
    }

    // 5. Active Directory Domain & Domain Controller Property Block Family
    // Key-value blocks containing >= 3 canonical AD domain/DC properties without requiring a visible command
    if (!isHttpResp && !isKnownLinux && (!hasKind(facts, 'ad.domain_known') || !hasKind(facts, 'ad.dc_candidate'))) {
      var adPropRe = /^[ \t]*(Forest|DomainControllers|DomainMode|DomainModeLevel|PdcRoleOwner|RidRoleOwner|InfrastructureRoleOwner|ParentDomain|HighestCommittedUsn|Partitions|InboundConnections|OutboundConnections)[ \t]*:[ \t]*([^\r\n]*)$/gim;
      var seenAdKeys = Object.create(null), adKeyCount = 0, adProps = Object.create(null), mAdp;
      while ((mAdp = adPropRe.exec(text)) !== null) {
        var ak = mAdp[1].toLowerCase(), av = mAdp[2].trim();
        if (!av && ak !== 'parentdomain' && ak !== 'inboundconnections' && ak !== 'outboundconnections') continue;
        if (!seenAdKeys[ak]) { seenAdKeys[ak] = 1; adKeyCount++; }
        if (!adProps[ak] && av) adProps[ak] = av;
      }
      if (adKeyCount >= 3 && (adProps.forest || adProps.domaincontrollers || adProps.pdcroleowner || adProps.partitions)) {
        var domFqdn = '';
        var forestClean = String(adProps.forest || '').replace(/^[{\s"']+|[}\s"']+$/g, '');
        if (/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(forestClean)) domFqdn = forestClean.toLowerCase();
        if (!domFqdn) {
          var domFieldM = /^[ \t]*Domain[ \t]*:[ \t]*([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)[ \t]*$/im.exec(text);
          if (domFieldM) domFqdn = domFieldM[1].toLowerCase();
        }
        if (!domFqdn && adProps.domaincontrollers) {
          var nameDomM = /^[ \t]*Name[ \t]*:[ \t]*([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)[ \t]*$/im.exec(text);
          if (nameDomM) domFqdn = nameDomM[1].toLowerCase();
        }
        var dcHost = '';
        var dcSrc = adProps.domaincontrollers || adProps.pdcroleowner || adProps.ridroleowner || '';
        var dcHostM = /([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)/.exec(dcSrc);
        if (dcHostM) {
          dcHost = dcHostM[1];
          if (!domFqdn && dcHost.indexOf('.') > 0) domFqdn = dcHost.slice(dcHost.indexOf('.') + 1).toLowerCase();
        } else if (adProps.highestcommittedusn || adProps.partitions) {
          var dcNameM = /^[ \t]*Name[ \t]*:[ \t]*([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)[ \t]*$/im.exec(text);
          if (dcNameM) dcHost = dcNameM[1];
        }
        var dcIpM = /^[ \t]*IPAddress[ \t]*:[ \t]*(\d{1,3}(?:\.\d{1,3}){3})[ \t]*$/im.exec(text);
        var targetDomScope = domFqdn ? ('domain:' + domFqdn) : domScope;
        if (domFqdn) {
          if (!hasKind(facts, 'ad.domain_known')) {
            _add(facts, mkFact('ad.domain_known', targetDomScope, { name: domFqdn, domain: domFqdn, via: 'shape' }, S, source));
          }
          if (!hasKind(facts, 'host.domain')) {
            _add(facts, mkFact('host.domain', h, { domain: domFqdn, via: 'shape' }, S, source));
          }
        }
        if (!hasKind(facts, 'ad.dc_candidate')) {
          var dcVal = { via: 'shape' };
          if (dcHost) dcVal.dc = dcHost;
          if (dcIpM) dcVal.dc_ip = dcIpM[1];
          if (domFqdn) dcVal.domain = domFqdn;
          _add(facts, mkFact('ad.dc_candidate', h, dcVal, S, source));
        }
      }
    }
  }
  C._parse_family_resemblance = _parse_family_resemblance;

  C._parse_shape = _parse_shape;

  // ---- known-exploit fingerprint recognizer ---------------------------------------------------
  // When pasted service/version output (an nmap -sV banner, a whatweb line, a CHANGELOG, an nmap
  // vuln-script verdict) names a product+version, or a CVE/handshake token, that a promoted
  // known-exploit module targets, mint a vuln.<name> LEAD so the coach lights that exact module.
  // Strictly conservative and anchored on specific version/product/CVE tokens, so unrelated output
  // mints nothing. A lead is a candidate to try, never proof of exploitation: the module's own
  // produces fact (a real shell) is what proves the box, exactly as the proof discipline requires.
  var _SHELLSHOCK_EXPLICIT_RE = /\bShellshock\b|CVE-2014-6271|(?:^|[^A-Za-z0-9-])http-shellshock\b(?![\s\S]{0,160}?\bNOT\s+VULNERABLE\b)[\s\S]{0,160}?\bVULNERABLE\b|\(\)\s*\{\s*:;\s*\}\s*;/i;
  var _SHELLSHOCK_CGI_SCRIPT_RE = /\/cgi-bin\/[A-Za-z0-9_.-]+\.(?:cgi|sh|pl|py)\b/i;
  var VULN_SIGS = [
    { fact: 'vuln.vsftpd_234', re: /\bvsftpd[\s_-]*2\.3\.4\b/i, cve: 'CVE-2011-2523' },
    { fact: 'vuln.proftpd_modcopy', re: /\bproftpd\s+1\.3\.5[a-z]?\b|\bmod_copy\b/i, cve: 'CVE-2015-3306' },
    { fact: 'vuln.samba_usermap', re: /\bsamba\s+(?:smbd\s+)?3\.0\.2[0-5][a-d]?\b|(?:^|[^A-Za-z0-9-])smb-vuln-cve2007-2447\b(?![\s\S]{0,120}?\bNOT\s+VULNERABLE\b)[\s\S]{0,120}?\bVULNERABLE\b/i, cve: 'CVE-2007-2447' },
    { fact: 'vuln.smbghost', re: /\bSMBGhost\b|CVE-2020-0796/i, cve: 'CVE-2020-0796' },
    { fact: 'vuln.bluekeep', re: /\bBlueKeep\b|CVE-2019-0708|(?:^|[^A-Za-z0-9-])rdp-vuln-ms19-0708\b(?![\s\S]{0,120}?\bNOT\s+VULNERABLE\b)[\s\S]{0,120}?\bVULNERABLE\b/i, cve: 'CVE-2019-0708' },
    { fact: 'vuln.shellshock', re: /\bShellshock\b|CVE-2014-6271|http-shellshock|\/cgi-bin\/[A-Za-z0-9_.-]+\.(?:cgi|sh|pl|py)\b|\(\)\s*\{\s*:;\s*\}\s*;/i, cve: 'CVE-2014-6271' },
    { fact: 'vuln.heartbleed', re: /\bHeartbleed\b|CVE-2014-0160|(?:^|[^A-Za-z0-9-])ssl-heartbleed\b(?![\s\S]{0,120}?\bNOT\s+VULNERABLE\b)[\s\S]{0,120}?\bVULNERABLE\b/i, cve: 'CVE-2014-0160' },
    { fact: 'vuln.drupalgeddon2', re: /\bDrupalgeddon|CVE-2018-7600|\bDrupal\s*[78]\.\d/i, cve: 'CVE-2018-7600' },
    { fact: 'vuln.phpmyadmin_lfi', re: /\bphpMyAdmin\s*4\.8(?:\.[01])?(?![.\d])\b|CVE-2018-12613/i, cve: 'CVE-2018-12613' },
    { fact: 'vuln.webmin', re: /\b(?:MiniServ|Webmin)[\/\s]+1\.(?:89\d|9[0-2]\d|9(?![.\d]))\b|CVE-2019-15107/i, cve: 'CVE-2019-15107' },
    { fact: 'vuln.usermin', re: /\bUsermin\b/i, cve: '' },
    { fact: 'vuln.usermin_rce', re: /\bUsermin\s*(?:v?1\.[89]|1\.820)|EDB-50234/i, cve: 'EDB-50234' },
    { fact: 'vuln.ofbiz', re: /\bOFBiz\b|CVE-2020-9496/i, cve: 'CVE-2020-9496' },
    { fact: 'vuln.cacti', re: /\bCacti\b|CVE-2022-46169/i, cve: 'CVE-2022-46169' },
    { fact: 'vuln.zabbix', re: /\bZabbix\b|CVE-2022-23131/i, cve: 'CVE-2022-23131' },
    { fact: 'vuln.splunk', re: /\bSplunk\b|CVE-2023-46214/i, cve: '' },
    { fact: 'vuln.text4shell', re: /\bText4Shell\b|commons[-_. ]?text|CVE-2022-42889/i, cve: 'CVE-2022-42889' },
    { fact: 'vuln.freeswitch', re: /(?:(?<![\/\\.-])\bFreeSWITCH\b(?![\/\\.-])|\bmod_event_socket\b|\b8021\/tcp\s+open[^\r\n]{0,80}?[Ff]ree[Ss][Ww][Ii][Tt][Cc][Hh]|\b[Cc]ontent-[Tt]ype:\s*auth\/request\b)/, cve: '' },
    { fact: 'vuln.jdwp', re: /JDWP-?Handshake|Java Debug Wire|-Xrunjdwp:transport=dt_socket|-agentlib:jdwp=(?:transport=dt_socket|[^\s]*address=)|Found Runtime\.getRuntime\(\)/i, cve: '' },
    { fact: 'vuln.aerospike', re: /\bAerospike\s+(?:Server|Enterprise|Community|Database|\d)|3000\/tcp\s+open[^\r\n]{0,80}?aerospike|"service(?:Name)?"\s*:\s*"aerospike"|CVE-2020-13151/i, cve: 'CVE-2020-13151' },
    { fact: 'vuln.aerospike_udf', re: /\bAerospike[^\r\n]{0,60}?\b5\.[01]\b|cve-2020-13151/i, cve: 'CVE-2020-13151' },
    { fact: 'vuln.pico_cms', re: /Pico CMS|Pico v[0-9.]+/i, cve: '' },
    { fact: 'vuln.screen_suid', re: /screen-4\.5\.0|GNU Screen 4\.5\.0|Screen version 4\.05\.00/i, cve: 'CVE-2017-5618' },
    { fact: 'vuln.wifi_mouse', re: /\b(?:WiFi|Mobile)\s*Mouse\b|(?<!General Purpose )\bMouse\s*Server\b/i, cve: '' },
    { fact: 'vuln.solr', re: /\bApache Solr\b|\bSolr[^\r\n]{0,60}?(?:8\.[0-3]|7\.|6\.|5\.)|CVE-2019-17558/i, cve: 'CVE-2019-17558' },
    { fact: 'vuln.achat', re: /\bA(?:Chat|chat)\s*(?:v?0\.150|beta7)|CVE-2015-8278/i, cve: 'CVE-2015-8278' },
    { fact: 'vuln.nibbleblog', re: /\bNibbleblog\b|CVE-2015-6967/i, cve: 'CVE-2015-6967' },
    { fact: 'vuln.iis6_webdav', re: /Microsoft[- ]IIS(?: httpd|\/)?\s*6\.0[^\r\n]{0,120}?WebDAV|CVE-2017-7269|ScStoragePathFromUrl|ExplodingCan/i, cve: 'CVE-2017-7269' },
    { fact: 'vuln.prtg', re: /PRTG Network Monitor|Paessler PRTG/i, cve: '' },
    { fact: 'vuln.gitlab', re: /GitLab Community Edition|GitLab Enterprise Edition/i, cve: '' },
    { fact: 'vuln.october_cms', re: /\bOctober\s*CMS(?:\s*(?:v?1\.[0-9.]+|Build\s*\d+))?/i, cve: '' },
    { fact: 'vuln.rejetto_hfs', re: /HttpFileServer\s*2\.[0-3]|\bHFS\s*2\.[0-3]|\brejetto\b/i, cve: 'CVE-2014-6287' },
    { fact: 'vuln.coldfusion', re: /\bColdFusion\s*(?:8|9|10|MX)\b|\/CFIDE\/|CVE-2010-2861/i, cve: 'CVE-2010-2861' },
    { fact: 'vuln.oracle_tns', re: /Oracle TNS Listener|TNSLSNR|1521\/tcp\s+open[^\r\n]{0,80}?oracle/i, cve: '' },
    { fact: 'vuln.h2_console', re: /H2 Database|h2-console|(?:8082|9092)\/tcp\s+open[^\r\n]{0,80}?h2/i, cve: '' },
    { fact: 'vuln.chkrootkit', re: /\bchkrootkit\s+0\.[0-4][0-9]?\b|CVE-2014-0476/i, cve: 'CVE-2014-0476' },
    { fact: 'vuln.zabbix_agent', re: /Zabbix Agent|10050\/tcp\s+open[^\r\n]{0,80}?zabbix/i, cve: '' },
    { fact: 'vuln.myfaces_jsf', re: /javax\.faces\.ViewState|Apache MyFaces|\bMyFaces\b/i, cve: '' },
    { fact: 'vuln.node_serialize', re: /node-serialize|_\$\$ND_FUNC\$\$_/i, cve: 'CVE-2017-5941' },
    { fact: 'vuln.gitea', re: /\bGitea\b|Git with a cup of tea/i, cve: '' },
  ];
  var _VULN_SIGS_HINT_RE = /(?:CVE-\d{4}-|EDB-\d+|vsftpd|proftpd|mod_copy|samba|smbd|SMBGhost|BlueKeep|rdp-vuln|Shellshock|cgi-bin|Heartbleed|Drupal|phpMyAdmin|MiniServ|Webmin|Usermin|OFBiz|Cacti|Zabbix|Splunk|Text4Shell|commons|FreeSWITCH|mod_event_socket|JDWP|Java Debug|Xrunjdwp|agentlib:jdwp|getRuntime|Aerospike|aerospike|Pico|screen-4\.5|Screen 4|Mouse|Solr|AChat|Nibbleblog|IIS|WebDAV|ScStoragePathFromUrl|ExplodingCan|PRTG|GitLab|October|HttpFileServer|HFS|rejetto|ColdFusion|CFIDE|Oracle TNS|TNSLSNR|1521\/tcp|H2 Database|h2-console|8082\/tcp|9092\/tcp|chkrootkit|10050\/tcp|MyFaces|ViewState|node-serialize|ND_FUNC|Gitea|cup of tea)/i;
  function _parse_vulnmatch(text, ws, source, facts, command) {
    text = String(text || ''); if (!text.trim() || !_VULN_SIGS_HINT_RE.test(text)) return;
    var cleanText = /\b(?:closed|filtered|unfiltered|open\|filtered)\b/i.test(text)
      ? text.replace(/^\s*\d+\/(?:tcp|udp)\s+(?:closed|filtered|unfiltered|open\|filtered)\b[^\r\n]*$/gim, '')
      : text;
    if (/^\s*\[\-\]\s*(?:this instance is patched|[^\r\n]*\bis not vulnerable\b|exploit failed|target is patched)\b/im.test(cleanText)
        && !/\buid=\d+\(|NT AUTHORITY\\SYSTEM|^\s*\[\+\]\s*(?:shell|pwned|vulnerable|success|executed|command)\b/im.test(cleanText)) {
      return;
    }
    var cmdCheck = String(command !== undefined ? command : (source || '')).trim();
    var isLocalPathListingCmd = /^\s*(?:sudo\s+)?(?:find|ls|dir|pwd|cd|locate|which|whereis)\b/i.test(cmdCheck);
    var isNmapContext = /\b(?:Nmap scan report for|Starting Nmap|fingerprint-strings:|SF-Port\d+)\b/i.test(cleanText) || /\bnmap\b/i.test(cmdCheck);
    var h = 'host:' + ws.target;
    for (var i = 0; i < VULN_SIGS.length; i++) {
      var s = VULN_SIGS[i];
      if (isLocalPathListingCmd && s.fact !== 'vuln.screen_suid' && s.fact !== 'vuln.chkrootkit') continue;
      if (!s.re.test(cleanText) || hasKind(facts, s.fact)) continue;
      if (s.fact === 'vuln.shellshock' && !_SHELLSHOCK_EXPLICIT_RE.test(cleanText)) {
        if (isNmapContext) continue;
        var cgiLines = cleanText.split(/\r?\n/);
        var hasPositiveCgi = false;
        for (var cli = 0; cli < cgiLines.length; cli++) {
          var cLn = cgiLines[cli];
          if (_SHELLSHOCK_CGI_SCRIPT_RE.test(cLn) && /\b(?:200|301|302|500)\b/.test(cLn) && !/\b(?:403|404)\b/.test(cLn)) {
            hasPositiveCgi = true;
            break;
          }
        }
        if (!hasPositiveCgi) continue;
      }
      if (s.fact === 'vuln.jdwp'
          && /(?:Failed to connect|Connection refused|Connection timed out|Errno \d+)/i.test(cleanText)
          && !/(?:-Xrunjdwp:transport=dt_socket|-agentlib:jdwp=)/i.test(cleanText)) {
        continue;
      }
      _add(facts, mkFact(s.fact, h, { cve: s.cve || null, via: 'vulnmatch', lead: true }, S, source));
    }
  }
  C._parse_vulnmatch = _parse_vulnmatch;
  function parse(text, scope, cmd, existingFacts) {
    var textStr = String(text || '');
    if (C._ANSI_RE) textStr = textStr.replace(C._ANSI_RE, '');
    if (!textStr.trim()) return [];
    var s = String(scope || '').trim();
    var target = (s.indexOf('host:') === 0 ? s.slice(5) : (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s) ? s : '')) || 'target';
    var seed = Array.isArray(existingFacts) ? existingFacts.slice() : [];
    var ws = { target: target, domainSeed: '', seedFacts: seed, facts: seed };
    var source = cmd ? (C._ANSI_RE ? String(cmd).replace(C._ANSI_RE, '') : String(cmd)) : 'shape';
    var baseFacts = seed.slice();
    var initialLen = baseFacts.length;
    _parse_shape(textStr, ws, source, baseFacts);
    _parse_vulnmatch(textStr, ws, source, baseFacts);
    return baseFacts.slice(initialLen);
  }
  OBOL.parsers = OBOL.parsers || {};
  OBOL.parsers.shape = { parse: parse };
})(typeof globalThis !== 'undefined' ? globalThis : this);
