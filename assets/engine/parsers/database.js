/*!
 * obol engine - parsers/database.js
 * Faithful JS port of
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  var _MSSQL_WHOAMI_RE = /\bnt (?:service|authority)\\[\w$.-]+|(?<![A-Za-z]:\\)\b(?![A-Za-z]:\\)[A-Za-z0-9_.-]{2,32}\\[A-Za-z0-9_.$-]{2,32}\s*$|uid=\d+\(/im;
  var _DB_ACCESS_DENIED_RE = /access denied|authentication failed|login failed|permission denied|ERROR 1045|can't connect to|connection refused|could not connect to server|timeout expired|login failed for user|ERROR 200[235]|FATAL:\s*(?:(?:password|Peer|Ident|SCRAM|GSSAPI|PAM|LDAP|certificate|RADIUS|BSD)\s+authentication failed|no pg_hba\.conf entry for host\b|database\s+"[^"\r\n]+"\s+is not currently accepting connections|role\s+"[^"\r\n]+"\s+is not permitted to log in)|ORA-01017|MongoServerError:\s*(?:command\s+\S+\s+)?requires\s+authentication|\bnot\s+authorized\s+on\s+\S+\s+to\s+execute\s+command\b|\bcodeName:\s*['"]Unauthorized['"]/i;
  var _MONGO_AUTH_DENIED_RE = /MongoServerError:\s*(?:command\s+\S+\s+)?requires\s+authentication|\bnot\s+authorized\s+on\s+\S+\s+to\s+execute\s+command\b|\bcodeName:\s*['"]Unauthorized['"]|Mongo(?:Server|Network)?Error:\s*Authentication\s+failed|\berrmsg:\s*['"][^'"]*(?:requires\s+authentication|not\s+authorized|auth\s+failed)/i;
  var _MONGO_CONN_FAIL_RE = /\b(?:ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EHOSTUNREACH|connect\s+ECONNREFUSED|connection\s+refused|timed?\s*out|couldn't\s+connect\s+to\s+server)\b/i;
  var _MONGO_POSITIVE_DATA_RE = /\b(?:admin|local|config)\s+\d+(?:\.\d+)?\s*[KMGT]?i?B\b|\[\s*\{\s*['"_A-Za-z0-9$]+['"]?\s*:|\bObjectId\s*\(\s*['"][0-9a-fA-F]{24}['"]\s*\)|["']ok["']\s*:\s*1\b/i;
  var _REDIS_DENIED_RE = /\b(?:NOAUTH\b|WRONGPASS\b|NOPERM\b|ERR\s+(?:invalid\s+password|Client\s+sent\s+AUTH|operation\s+not\s+permitted|authentication\s+required)|Could\s+not\s+connect\s+to\s+Redis|Connection\s+refused|Connection\s+timed\s+out)\b/i;

  function _unescape_resp_bulk_string(rawStr) {
    var inner = String(rawStr || '');
    if (inner.length >= 2 && inner.charAt(0) === '"' && inner.charAt(inner.length - 1) === '"') {
      inner = inner.slice(1, -1);
    }
    return inner.replace(/\\(n|r|t|"|\\|x([0-9a-fA-F]{2}))/g, function (_, tok, hex) {
      if (tok === 'n') return '\n';
      if (tok === 'r') return '\r';
      if (tok === 't') return '\t';
      if (tok === '"') return '"';
      if (tok === '\\') return '\\';
      if (hex) return String.fromCharCode(parseInt(hex, 16));
      return tok;
    });
  }
  var _DB_HASH_ROW_RE = /\b(?<user>[A-Za-z0-9_.@-]{2,64})\b(?:[ \t]*[|:\t][ \t]*[^\s|:\t\r\n][^\r\n|:\t]{0,160}){0,6}?[ \t]*[|:\t][ \t]*(?<hash>\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}|\$(?:P|H|S|1|5|6|y|apr1)\$[^\s|\t]+|pbkdf2_sha(?:1|256|512)\$\d+\$[^\s|\t]+|\*[0-9A-Fa-f]{40}|(?:0x)?[a-fA-F0-9]{32,128})\b/;
  var _DB_HASH_REV_ROW_RE = /(?<hash>\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}|\$(?:P|H|S|1|5|6|y|apr1)\$[^\s|\t:]+|pbkdf2_sha(?:1|256|512)\$\d+\$[^\s|\t:]+|\*[0-9A-Fa-f]{40})(?:[ \t]*[|:\t][ \t]*[^\s|:\t\r\n][^\r\n|:\t]{0,160}){0,5}?[ \t]*[|:\t][ \t]*(?<user>[A-Za-z0-9_.@-]{2,48})\b/;
  var _XP_CMDSHELL_DENIED_RE = /The EXECUTE permission was denied|Configuration option 'xp_cmdshell' does not exist|SQL Server blocked access to procedure/i;

  function _db_tool(low) {
    if (/\b(?:nxc|netexec|crackmapexec|cme)\b/.test(low)) return 'nxc';
    var tools = ['mssqlclient', 'sqlcmd', 'mysql', 'psql', 'pymongo', 'mongosh', 'mongo', 'redis-cli', 'sqlite3', 'sqlite', 'odat', 'sqlplus'];
    for (var i = 0; i < tools.length; i++) if (low.indexOf(tools[i]) >= 0) return tools[i];
    return 'database';
  }

  // Pull the values out of a single-column result listing (the shape SHOW DATABASES / SHOW TABLES
  // prints). Two forms appear in the wild: the boxed ASCII grid an interactive client draws
  // (| value |, one column, no interior pipe), and the bare newline-separated list a one-shot
  // `mysql -e 'show tables'` prints (a header line then one identifier per line). Separator rules
  // and client chatter (Query OK, "Database changed", completion hints) are dropped.
  function _db_listing_names(text) {
    var names = [], m, re = /^\s*\|\s*([^|\r\n]+?)\s*\|\s*$/gm;
    while ((m = re.exec(text)) !== null) names.push(m[1].trim());
    if (names.length) return names;
    if (/^\s*-+\+[-+]+\s*$/m.test(text)) {
      var pLines = text.split(/\r?\n/);
      var sepIdx = -1;
      for (var pi = 0; pi < pLines.length; pi++) {
        if (/^\s*-+\+[-+]+\s*$/.test(pLines[pi])) { sepIdx = pi; break; }
      }
      if (sepIdx > 0) {
        var hdrCells = pLines[sepIdx - 1].split('|').map(function (c) { return c.trim().toLowerCase(); });
        var colIdx = 0;
        for (var hi = 0; hi < hdrCells.length; hi++) {
          if (hdrCells[hi] === 'name' || hdrCells[hi] === 'datname' || hdrCells[hi] === 'tablename' || hdrCells[hi] === 'table_name') {
            colIdx = hi;
            break;
          }
        }
        for (var ri = sepIdx + 1; ri < pLines.length; ri++) {
          var rLn = pLines[ri];
          if (!rLn.trim() || /^\s*\(\d+\s+rows?\)\s*$/i.test(rLn)) break;
          if (rLn.indexOf('|') < 0) continue;
          var rCells = rLn.split('|');
          if (colIdx < rCells.length) {
            var cellVal = rCells[colIdx].trim();
            if (cellVal && /^[A-Za-z0-9_$][A-Za-z0-9_$.-]*$/.test(cellVal)) names.push(cellVal);
          }
        }
        if (names.length) return names;
      }
    }
    if (/^\s*-{2,}(?:[ \t]+-{2,})+\s*$/m.test(text)) {
      var sLines = text.split(/\r?\n/);
      var uIdx = -1;
      for (var si = 0; si < sLines.length; si++) {
        if (/^\s*-{2,}(?:[ \t]+-{2,})+\s*$/.test(sLines[si])) { uIdx = si; break; }
      }
      if (uIdx > 0) {
        var spans = [], dm, dRe = /-{2,}/g;
        while ((dm = dRe.exec(sLines[uIdx])) !== null) spans.push({ start: dm.index, end: dm.index + dm[0].length });
        if (spans.length >= 2) {
          var targetCol = 0;
          var hdrLn = sLines[uIdx - 1];
          for (var ci = 0; ci < spans.length; ci++) {
            var hEnd = ci + 1 < spans.length ? spans[ci + 1].start : hdrLn.length;
            var hName = hdrLn.slice(spans[ci].start, hEnd).trim().toLowerCase();
            if (hName === 'name' || hName === 'database' || hName === 'datname' || hName === 'tablename' || hName === 'table_name') {
              targetCol = ci;
              break;
            }
          }
          for (var sri = uIdx + 1; sri < sLines.length; sri++) {
            var srLn = sLines[sri];
            if (!srLn.trim() || /^\s*(?:\(\d+\s+rows?(?:\s+affected)?\)|SQL(?:\s*\([^)]*\))?>|\d+>)/i.test(srLn)) break;
            var cStart = spans[targetCol].start;
            var cEnd = targetCol + 1 < spans.length ? spans[targetCol + 1].start : srLn.length;
            var cVal = srLn.slice(cStart, cEnd).trim();
            if (!cVal) {
              var wsToks = srLn.trim().split(/\s+/);
              cVal = wsToks[targetCol] || '';
            }
            if (cVal && /^[A-Za-z0-9_$][A-Za-z0-9_$.-]*$/.test(cVal)) names.push(cVal);
          }
          if (names.length) return names;
        }
      }
    }
    text.split(/\r?\n/).forEach(function (ln) {
      var t = ln.trim();
      if (!t || /^[-+]+$/.test(t) || /^\(\d+\s+rows?\)$/i.test(t)) return;
      if (/\b(?:Query OK|rows? in set|Warning|Reading table information|Database changed|turn off this feature|Empty set|Bye|Aborted|Ctrl-C|List of databases|List of relations)\b/i.test(t)) return;
      if (/^[A-Za-z0-9_$][A-Za-z0-9_$.-]*$/.test(t)) names.push(t);
    });
    return names;
  }

  var _EMPTY_DB_DIGEST_RE = /^(?:0x)?(?:d41d8cd98f00b204e9800998ecf8427e|31d6cfe0d16ae931b73c59d7e0c089c0|aad3b435b51404eeaad3b435b51404ee|da39a3ee5e6b4b0d3255bfef95601890afd80709|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)$/i;
  var _SELF_EVIDENCING_DB_HASH_RE = /(?:\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}|\$(?:1|5|6|y|P|H|S|apr1)\$[^\s|'"\t]+|pbkdf2_sha(?:1|256|512)\$\d+\$[^\s|'"\t]+|\bsha(?:256|512)\$[A-Za-z0-9./$+=]{20,}|\*[0-9A-Fa-f]{40}\b|\bmd5[0-9a-fA-F]{32}\b|\bSCRAM-SHA-256\$\d+:[^\s|'"\t]+)/g;

  function _detect_db_hash_format(hsh) {
    var s = String(hsh || '');
    if (/^\$2[abxy]\$/i.test(s)) return 'bcrypt';
    if (/^\$(?:P|H)\$/i.test(s)) return 'phpass';
    if (/^\$1\$|^\$apr1\$/i.test(s)) return 'md5crypt';
    if (/^\$5\$/i.test(s)) return 'sha256crypt';
    if (/^\$6\$/i.test(s)) return 'sha512crypt';
    if (/^\$y\$/i.test(s)) return 'yescrypt';
    if (/^pbkdf2_sha/i.test(s)) return 'pbkdf2';
    if (/^sha256\$/i.test(s)) return 'sha256-django';
    if (/^sha512\$/i.test(s)) return 'sha512-django';
    if (/^\*[0-9A-Fa-f]{40}$/.test(s)) return 'mysql-sha1';
    if (/^md5[0-9a-fA-F]{32}$/.test(s)) return 'postgres-md5';
    if (/^SCRAM-SHA-256\$\d+:/i.test(s)) return 'postgres-scram-sha-256';
    var hex = s.replace(/^0x/i, '');
    if (/^[0-9a-fA-F]{32}$/.test(hex)) return 'raw-md5';
    if (/^[0-9a-fA-F]{40}$/.test(hex)) return 'raw-sha1';
    if (/^[0-9a-fA-F]{64}$/.test(hex)) return 'raw-sha256';
    if (/^[0-9a-fA-F]{128}$/.test(hex)) return 'raw-sha512';
    return 'modular';
  }

  var _DB_INTERACTIVE_PROMPT_LINE_RE = /^\s*(?:mysql\s*>|MariaDB\s*\[[^\]]*\]\s*>|[A-Za-z][A-Za-z0-9_.-]{0,62}=[#>](?:\s|$)|SQL(?:\s*\([^)]*\))?\s*>|1>\s|sqlite3?\s*>)/im;
  var _DB_ECHOED_PW_LINE_RE = /^[ \t]{0,2}(?:Enter[ \t]+[Pp]assword|Password)(?:[ \t]+for[ \t]+(?:user[ \t]+)?([A-Za-z0-9_.-]+))?:[ \t]*([^\s\r\n]+)[ \t]*$/;
  var _DB_PROMPT_USER_LINE_RE = /^[ \t]{0,2}(?:Password[ \t]+for[ \t]+(?:user[ \t]+)?([A-Za-z0-9_.-]+):|Enter[ \t]+user-?name:[ \t]*([A-Za-z0-9_.$#-]+))[ \t]*$/i;

  function _is_valid_echoed_db_pw(pw) {
    var s = String(pw || '').trim();
    if (!s) return false;
    if (C._valid_password && !C._valid_password(s)) return false;
    if (/^(?:<[^>]+>|\[redacted\]|mysql>|postgres=[#>]|SQL>|MariaDB|psql|Welcome|Connected|Type|\[\*\]|\[\+\]|\[-\]|ERROR|FATAL|ORA-\d+)$/i.test(s)) return false;
    if (/^(?:\$(?:1|2[abxy]|5|6|y|P|H|S|apr1)\$|\*[0-9A-Fa-f]{40}$|md5[0-9a-fA-F]{32}$|SCRAM-SHA-256\$|pbkdf2_)/i.test(s)) return false;
    return true;
  }

  function _extract_db_login_cred(text, command, sessionText, svc) {
    var user = '', password = '';
    var lines = String(text || '').split(/\r?\n/);
    for (var i = 0; i < lines.length && i < 20; i++) {
      var ln = lines[i];
      if (/^\*{3,}\s*\d+\.\s*row\b/i.test(ln) || /^\s*\+[-+]+\+\s*$/.test(ln)) break;
      var pm = _DB_ECHOED_PW_LINE_RE.exec(ln);
      if (pm) {
        if (pm[1] && !user) user = pm[1];
        if (_is_valid_echoed_db_pw(pm[2])) password = pm[2].trim();
        break;
      }
      var um = _DB_PROMPT_USER_LINE_RE.exec(ln);
      if (um && !user) user = (um[1] || um[2] || '').trim();
    }
    var cmd = String(command || '');
    if (!user && cmd) {
      var flagM = /(?:^|\s)(?:-U|-u|--username|--user)(?:=|\s+)['"]?([A-Za-z0-9_.\\$-]+)['"]?/.exec(cmd)
        || /(?:^|\s)-u([A-Za-z0-9_.-]{2,32})(?=\s|$)/.exec(cmd)
        || /\b(?:postgres(?:ql)?|mysql|mariadb|mssql|oracle):\/\/([A-Za-z0-9_.-]+)(?::[^\s@\/]+)?@/i.exec(cmd);
      if (flagM) user = flagM[1];
      if (!user && /\bmssqlclient/i.test(cmd)) {
        var msM = /(?:^|\s)['"]?(?:[A-Za-z0-9_.-]+[\/\\])?([A-Za-z0-9_.$-]+)(?::[^\s@'"]+)?@[A-Za-z0-9_.-]+/.exec(cmd);
        if (msM) user = msM[1];
      }
      if (!user && /\bsqlplus\b/i.test(cmd)) {
        var oraM = /\bsqlplus\s+(?:-[A-Za-z0-9]+\s+)*['"]?([A-Za-z0-9_.$#-]+)(?:\/[^\s@'"]+)?(?:@[^\s'"]+)?['"]?/i.exec(cmd);
        if (oraM && !/^(?:as|\/nolog|nolog)$/i.test(oraM[1])) user = oraM[1];
      }
    }
    if (!user) {
      var sqlPromptM = /\bSQL\s*\((?:[^)\\]+\s*\\)?([A-Za-z0-9_.$-]+)\s+/.exec(sessionText || '');
      if (sqlPromptM) user = sqlPromptM[1];
      else if (svc === 'mssql') {
        var nxcM = /MSSQL\b[^\r\n]*\[\+\]\s*(?:[^\\\s:]+\s*\\)?([A-Za-z0-9_.$-]+):/i.exec(text || '');
        if (nxcM) user = nxcM[1];
      } else if (svc === 'postgresql' && /^\s*postgres=[#>](?:\s|$)/m.test(sessionText || '')) {
        user = 'postgres';
      }
    }
    var cleanUser = user ? (C._clean_username ? C._clean_username(user) : user.trim()) : '';
    if (cleanUser && C._valid_username && !C._valid_username(cleanUser, false)) cleanUser = '';
    return { user: cleanUser, password: password };
  }

  function _le32HexToUint(h8) {
    var b0 = parseInt(h8.slice(0, 2), 16);
    var b1 = parseInt(h8.slice(2, 4), 16);
    var b2 = parseInt(h8.slice(4, 6), 16);
    var b3 = parseInt(h8.slice(6, 8), 16);
    return ((b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0);
  }

  function _parse_redis_requirepass(text, ws, source, facts) {
    if (!text) return;
    var h = 'host:' + ws.target;
    reAll(/^[ \t]*requirepass[ \t]+['"]?([^\s'"#\r\n]{4,128})['"]?[ \t]*$/gm, text).forEach(function (m) {
      var rpPw = (m[1] || '').trim();
      if (!rpPw || (C._valid_password && !C._valid_password(rpPw))) return;
      var rpVal = { password: rpPw, service: 'redis', via: 'redis-conf' };
      _add(facts, mkFact('credential.plaintext', h, rpVal, S, source));
      _add(facts, mkFact('credential.available', h, { password: rpPw, service: 'redis', method: 'redis-conf' }, S, source));
      _add(facts, mkFact('db.creds', h, rpVal, S, source));
    });
  }
  C._parse_redis_requirepass = _parse_redis_requirepass;

  function _parse_database_output(text, ws, command, source, facts) {
    text = String(text || '');
    if (/^\s*(?:where(?:\.exe)?|which|whereis|type\s+-a|command\s+-v|get-command|gcm|dir|ls|gci|get-childitem|find)\b/i.test(command || '')) return;
    if (/^\s*(?:sudo\s+)?(?:[\w.~/-]+[\\/])?(?:mongo(?:sh)?|psql|mysql|mariadb|redis-cli|sqlcmd|sqlite3?)(?:\.exe)?\s+(?:--version|-version|--help|-help|-\?|-V|-h)\s*$/i.test(command || '')) return;
    if (/^\s*MongoDB shell version\b/im.test(text) && /\bBuild Info:\s*\{/i.test(text) && !/\bconnecting to:\s*mongodb/i.test(text)) return;
    var ctx = (ws && ws.context) || {};
    var followPrompt = ctx.followPrompt ? String(ctx.followPrompt) : '';
    var promptLine = ctx.promptLine ? String(ctx.promptLine) : '';
    if (!text.trim() && !promptLine.trim() && !followPrompt.trim()) return;
    var h = 'host:' + ws.target, low = (command || '').toLowerCase();
    var denied = reSearch(_DB_ACCESS_DENIED_RE, text);

    // NetExec MSSQL: nxc runs xp_cmdshell for you (auto-enables it), so its -x/-X/-q output is a command
    // result with no literal "xp_cmdshell" banner. Treat an nxc-mssql exec whose output carries a shell
    // identity (NT AUTHORITY\SYSTEM, DOMAIN\user, uid=) as the same foothold the mssqlclient path mints.
    var nxcMssql = /\b(?:nxc|netexec|crackmapexec|cme)\s+mssql\b/.test(low);
    if ((text.toLowerCase().indexOf('xp_cmdshell') >= 0 || low.indexOf('xp_cmdshell') >= 0 || (nxcMssql && /\s-[xXq]\b/.test(command))) && !_XP_CMDSHELL_DENIED_RE.test(text)) {
      var m = reSearch(_MSSQL_WHOAMI_RE, text);
      if (m) {
        var ident = C._line_for_match(text, m).trim();
        if (!/^[A-Za-z]:\\/i.test(ident)) {
          var toolName = nxcMssql ? 'nxc' : 'mssqlclient';
          var val = { service: 'mssql', method: 'xp_cmdshell', identity: ident, tool: toolName };
          _add(facts, mkFact('foothold.windows', h, val, S, source));
          if (reSearch(C._SYSTEM_ID_RE, ident)) {
            _add(facts, mkFact('access.system', h, { identity: 'nt authority\\system', method: 'xp_cmdshell', tool: toolName }, S, source));
            _add(facts, mkFact('access.admin', h, { identity: 'nt authority\\system', method: 'xp_cmdshell', tool: toolName }, S, source));
          }
          C._add_os_observation(facts, ws, source, 'windows', 'xp_cmdshell command execution (' + ident + ')', 'high', 'mssql', true);
        }
      } else if (/^\s*Directory of\s+[A-Za-z]:\\/im.test(text) || /Volume Serial Number is\s+[0-9A-F]{4}-[0-9A-F]{4}/i.test(text)) {
        var toolName2 = nxcMssql ? 'nxc' : 'mssqlclient';
        _add(facts, mkFact('foothold.windows', h, { service: 'mssql', method: 'xp_cmdshell', identity: 'mssql', tool: toolName2 }, S, source));
        C._add_os_observation(facts, ws, source, 'windows', 'xp_cmdshell dir output', 'high', 'mssql', true);
      }
    }
    if (/\b(?:CONTROL\s+SERVER|IMPERSONATE\s+ANY\s+LOGIN)\b/i.test(text) || /^\s*SYS\s+DBA\s+YES\b/im.test(text)) {
      _add(facts, mkFact('db.admin', h, { tool: _db_tool(low), detail: 'elevated database server privilege confirmed' }, S, source));
    }

    if (/\bSRV_NAME\b|\bsp_linkedservers\b|\benum_links\b/i.test(text + '\n' + command)) {
      var linked = [];
      reAll(/^\s*([A-Za-z0-9_.-]{2,64})\s+(?:SQLNCLI|MSOLEDBSQL|SQLOLEDB|SQL Server)\b/gim, text).forEach(function (lm) {
        var srv = lm[1].trim();
        if (srv.toUpperCase() !== 'SRV_NAME') linked.push(srv);
      });
      if (linked.length) {
        var uLinks = C.uniqueSortedCI(linked);
        _add(facts, mkFact('mssql.linked_servers', h, { servers: uLinks, count: uLinks.length }, S, source));
        _add(facts, mkFact('db.linked_server', h, { servers: uLinks, count: uLinks.length }, S, source));
      }
    }

    var hashes = [], seen = {};
    if (['password', 'hash', 'users', 'user', 'partners', 'accounts', 'credential', 'sqlite', 'authentication_string', 'pass', 'person', 'pg_shadow', 'pg_authid'].some(function (k) { return (text + '\n' + low).toLowerCase().indexOf(k) >= 0; }) || /^\s*\d+\|[^|\r\n]+\|\$(?:2[abxy]|1|5|6|y|P|H|S|apr1)\$/im.test(text) || /pbkdf2_sha(?:1|256|512)\$\d+\$/i.test(text)) {
      reAll(_DB_HASH_ROW_RE, text).concat(reAll(_DB_HASH_REV_ROW_RE, text)).forEach(function (m) {
        var hsh = m.groups.hash, usr = m.groups.user;
        if (!usr || /^(?:null|true|false|\d+)$/i.test(usr)) return;
        if (_EMPTY_DB_DIGEST_RE.test(hsh)) return;
        if (/^[0-9a-fA-F]{32,128}$/.test(hsh) && /(?:uuid|guid|session|token|_id|commit|checksum|sha1|sha256|md5|serial|ssl_|binlog)/i.test(usr)) return;
        if (seen[hsh.toLowerCase()] || hsh.toLowerCase() === 'password' || hsh.toLowerCase() === 'email') return;
        seen[hsh.toLowerCase()] = true;
        hashes.push({ user: usr, hash: hsh });
      });
    }
    // Table-agnostic self-evidencing cryptographic hash rows (MCF, MySQL *SHA1, Postgres md5/SCRAM-SHA-256)
    text.split(/\r?\n/).forEach(function (rowLn) {
      if (!rowLn || (rowLn.indexOf('$') < 0 && rowLn.indexOf('*') < 0 && !/\bmd5[0-9a-fA-F]{32}\b/.test(rowLn))) return;
      if (!/SCRAM-SHA-256\$/i.test(rowLn) && (rowLn.match(/:/g) || []).length >= 5 && rowLn.indexOf('|') < 0) return;
      _SELF_EVIDENCING_DB_HASH_RE.lastIndex = 0;
      var shm = _SELF_EVIDENCING_DB_HASH_RE.exec(rowLn);
      if (!shm) return;
      var hsh = shm[0];
      if (_EMPTY_DB_DIGEST_RE.test(hsh) || seen[hsh.toLowerCase()]) return;
      var delim = rowLn.indexOf('|') >= 0 ? '|' : (rowLn.indexOf('\t') >= 0 ? '\t' : (rowLn.indexOf(',') >= 0 ? ',' : null));
      var rawCells = delim ? rowLn.split(delim) : rowLn.trim().split(/\s+/);
      var cells = [];
      for (var ci = 0; ci < rawCells.length; ci++) {
        var cTrim = rawCells[ci].trim().replace(/^['"]|['"]$/g, '');
        if (cTrim !== '' || (ci > 0 && ci < rawCells.length - 1)) cells.push(cTrim);
      }
      if (cells.length < 2) return;
      var hIdx = -1;
      for (var hi = 0; hi < cells.length; hi++) {
        if (cells[hi].indexOf(hsh) >= 0) { hIdx = hi; break; }
      }
      if (hIdx < 0) return;
      var bestUser = '', bestDist = 999;
      for (var ui = 0; ui < cells.length; ui++) {
        if (ui === hIdx) continue;
        var cand = cells[ui];
        if (!cand || cand.indexOf(hsh) >= 0) continue;
        if (!/^[A-Za-z_][A-Za-z0-9_.@+-]{1,48}$/.test(cand)) continue;
        if (/^(?:null|true|false|yes|no|t|f|usename|username|user|login|passwd|password|rolname|rolpassword|table|select|from|where)$/i.test(cand)) continue;
        var dist = Math.abs(ui - hIdx) * 2 + (ui > hIdx ? 1 : 0);
        if (dist < bestDist) { bestDist = dist; bestUser = cand; }
      }
      if (bestUser) {
        seen[hsh.toLowerCase()] = true;
        hashes.push({ user: bestUser, hash: hsh });
      }
    });
    if (hashes.length) {
      _add(facts, mkFact('loot.material', h, { kind: 'db_hashes', entries: hashes.slice(0, 5000), count: hashes.length, via: 'database', tool: _db_tool(low) }, S, source));
      _add(facts, mkFact('db.hashes', h, { entries: hashes.slice(0, 5000), count: hashes.length, tool: _db_tool(low) }, S, source));
      hashes.slice(0, 5000).forEach(function (entry) {
        var fmt = _detect_db_hash_format(entry.hash);
        _add(facts, mkFact('credential.candidate', h, { kind: 'database_hash', user: entry.user, hash: entry.hash, format: fmt, via: 'database' }, S, source));
        _add(facts, mkFact('hash.candidate', h, { user: entry.user, hash: entry.hash, format: fmt, via: 'database' }, S, source));
        _add(facts, mkFact('hash.crackable', h, { user: entry.user, hash: entry.hash, format: fmt, via: 'database' }, S, source));
      });
    }

    // Pipe-delimited SQL SELECT cleartext user/password rows & MSSQL SUSER_SID() binary SID hex
    var isSqlmapCtx = /\bsqlmap\b/i.test(command || '') || /\bback-end DBMS:\s/i.test(text);
    var sqlCtxHay = (command || '') + '\n' + promptLine + '\n' + text;
    var hasCleartextSelectCtx = !isSqlmapCtx && (/\bSELECT\b[\s\S]{1,180}?\bFROM\s+(?:[A-Za-z0-9_]+\.)?[`"'\[]?(?:users?|accounts?|members?|admins?|logins?|credentials?|auth\w*|tbl_users?|wp_users|staff|employees?|operators?|customers?)\b/i.test(sqlCtxHay)
      || /(?:^|\n)\s*sqlite3?>\s*/i.test(promptLine + '\n' + text));
    if (hasCleartextSelectCtx && text.indexOf('|') >= 0) {
      var hdrUserIdx = -1, hdrPassIdx = -1, seenClearPair = {};
      text.split(/\r?\n/).forEach(function (rawLn) {
        var ln = rawLn.trim();
        if (!ln || ln.indexOf('|') < 0 || /^[\s|+-]+$/.test(ln) || /^\(\d+\s+rows?\)$/i.test(ln)) return;
        ln = ln.replace(/^\s*(?:sqlite3?|mysql|MariaDB\s*\[[^\]]*\]|postgres[-=#]*|SQL(?:\s*\([^)]*\))?)>\s*/i, '');
        if (/^\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|PRAGMA|\.[a-z]+)\b/i.test(ln)) return;
        var rawParts = ln.split('|').map(function (c) { return c.trim(); });
        if (rawParts.length >= 3 && rawParts[0] === '' && rawParts[rawParts.length - 1] === '') {
          rawParts = rawParts.slice(1, -1);
        } else if (rawParts.length >= 2 && rawParts[rawParts.length - 1] === '') {
          rawParts = rawParts.slice(0, -1);
        }
        if (rawParts.length < 2 || rawParts.length > 8) return;
        var lowParts = rawParts.map(function (c) { return c.toLowerCase(); });
        var uH = -1, pH = -1;
        for (var hi = 0; hi < lowParts.length; hi++) {
          if (uH < 0 && /^(?:user(?:name|_name)?|uname|login|account|email)$/.test(lowParts[hi])) uH = hi;
          if (pH < 0 && /^(?:pass(?:word|wd)?|pwd|pw|secret|cleartext)$/.test(lowParts[hi])) pH = hi;
        }
        if (uH >= 0 && pH >= 0) {
          hdrUserIdx = uH;
          hdrPassIdx = pH;
          return;
        }
        var uCand = '', pCand = '';
        if (hdrUserIdx >= 0 && hdrPassIdx >= 0 && hdrUserIdx < rawParts.length && hdrPassIdx < rawParts.length) {
          uCand = rawParts[hdrUserIdx];
          pCand = rawParts[hdrPassIdx];
        } else {
          var startIdx = /^\d+$/.test(rawParts[0]) ? 1 : 0;
          var foundUIdx = -1;
          for (var ci = startIdx; ci < rawParts.length - 1; ci++) {
            var cellU = rawParts[ci];
            if (!cellU || /^\d+$/.test(cellU) || /^(?:id|uid|user|username|login|name|email|mail|role|admin|pass|passwd|password|pwd|hash|secret|token|status|active|created|updated|null|true|false)$/i.test(cellU)) continue;
            var cleanedCellU = C._clean_username ? C._clean_username(cellU) : cellU;
            if (cleanedCellU && C._valid_username && C._valid_username(cleanedCellU, false)) {
              uCand = cleanedCellU;
              foundUIdx = ci;
              break;
            }
          }
          if (foundUIdx >= 0) {
            for (var pi = foundUIdx + 1; pi < rawParts.length; pi++) {
              var cellP = rawParts[pi];
              if (!cellP || /^\d+$/.test(cellP)) continue;
              if (/^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/.test(cellP)) continue;
              if (/^\d{4}-\d{2}-\d{2}/.test(cellP)) continue;
              if (/^(?:true|false|null|none|yes|no|admin|administrator|user|member|guest|staff|moderator|editor|author|subscriber|enabled|disabled|active|inactive)$/i.test(cellP)) continue;
              if (/^(?:https?:\/\/|\/[A-Za-z0-9_.-]+\/)/.test(cellP)) continue;
              pCand = cellP;
              break;
            }
          }
        }
        var finalU = C._clean_username ? C._clean_username(uCand) : uCand;
        var finalP = (pCand || '').trim();
        if (!finalU || !finalP || finalP.length < 4 || finalP.length > 64) return;
        if (!C._valid_username(finalU, false) || !C._valid_password(finalP)) return;
        if (/^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{56}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}|\*[0-9a-fA-F]{40}|\$(?:1|2[abxy]|5|6|y|P|H|S|apr1)\$[^\s]+|md5[0-9a-fA-F]{32}|SCRAM-SHA-256\$\d+:[^\s]+|pbkdf2_)/i.test(finalP)) return;
        var pairKey = finalU.toLowerCase() + '|' + finalP;
        if (seenClearPair[pairKey]) return;
        seenClearPair[pairKey] = true;
        _add(facts, mkFact('credential.candidate', h, { kind: 'database_plaintext', user: finalU, password: finalP, via: 'database' }, S, source));
        if (C._add_plaintext_credential) {
          C._add_plaintext_credential(facts, ws, source, finalU, finalP, '', 'database', '');
        } else {
          _add(facts, mkFact('credential.plaintext', h, { user: finalU, password: finalP, via: 'database' }, S, source));
          _add(facts, mkFact('credential.available', h, { user: finalU, password: finalP, method: 'database' }, S, source));
        }
      });
    }

    reAll(/\b(?:0x)?010([45])00000000000515000000([0-9a-fA-F]{8})([0-9a-fA-F]{8})([0-9a-fA-F]{8})(?:([0-9a-fA-F]{8}))?\b/gi, text).forEach(function (sm) {
      var sa1 = _le32HexToUint(sm[2]), sa2 = _le32HexToUint(sm[3]), sa3 = _le32HexToUint(sm[4]);
      if (sa1 === 0 && sa2 === 0 && sa3 === 0) return;
      var domSid = 'S-1-5-21-' + sa1 + '-' + sa2 + '-' + sa3;
      _add(facts, mkFact('ad.domain_sid', C._scope_for_domain(ws), { sid: domSid, domain_sid: domSid, via: 'mssql-suser-sid' }, S, source));
    });

    _parse_redis_requirepass(text, ws, source, facts);

    var isRedisCmd = /\bredis-cli\b/i.test(command || '')
      || /^\s*(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9._-]+):\d{1,5}>\s*/m.test(text + '\n' + promptLine + '\n' + followPrompt);
    var redisPortM = /\bredis-cli\b[^\r\n]*?\s-p\s+(\d{1,5})\b/i.exec(command || '')
      || /^\s*(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9._-]+):(\d{1,5})>/m.exec(promptLine + '\n' + followPrompt + '\n' + text);
    var redisPort = redisPortM ? parseInt(redisPortM[1], 10) : 6379;
    if (!(redisPort >= 1 && redisPort <= 65535)) redisPort = 6379;
    var isAlreadyOpenRedisRepl = /^\s*(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9._-]+):\d{1,5}>/.test(promptLine);
    var redisAuthM = (isRedisCmd || low.indexOf('redis') >= 0)
      ? (/\bredis-cli\b[^\r\n]*?(?:\s(?:-a|--pass)\s+['"]?([^\s'"]+)['"]?|\bredis:\/\/[^:\s/'"]*:([^@\s'"]+)@|\bauth\s+['"]?([^\s'"]+)['"]?)/i.exec(command || '')
        || /^(?:\s*(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9._-]+):\d{1,5}>\s*)?auth\s+['"]?([^\s'"\r\n]+)['"]?\s*$/im.exec(promptLine + '\n' + text))
      : null;
    var redisAuthSecret = redisAuthM ? (redisAuthM[1] || redisAuthM[2] || redisAuthM[3] || '').trim() : '';
    var hasRedisAuthSupplied = !!redisAuthSecret || /\bNOAUTH\b/i.test(text);
    var hasRedisBareReply = isRedisCmd && !_REDIS_DENIED_RE.test(text) && /^(?:\+OK|OK|\+PONG|PONG|\(integer\)\s+\d+)\s*$/im.test(text);
    var hasLiveRedisFollowPrompt = isRedisCmd && !/(?:Could\s+not\s+connect\s+to\s+Redis|Connection\s+refused|Connection\s+timed\s+out)/i.test(text)
      && /^\s*(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9._-]+):\d{1,5}>\s*$/m.test(followPrompt);
    var isRedisHit = ((low.indexOf('redis') >= 0 || isRedisCmd || /^redis_version:/im.test(text)) && (text.toLowerCase().indexOf('# server') >= 0 || /^redis_version:/im.test(text) || /^\+PONG\b|^PONG\b|^\+OK\b/im.test(text) || /^\s*\d+\)\s+"/m.test(text))) || hasRedisBareReply;
    if (redisAuthSecret && !_REDIS_DENIED_RE.test(text) && (isRedisHit || hasLiveRedisFollowPrompt || /^\s*(?:\+OK|OK|\+PONG|PONG)\s*$/im.test(text))) {
      _add(facts, mkFact('credential.validated', h, { service: 'redis', tool: 'redis-cli', outcome: 'accepted' }, S, source));
      _add(facts, mkFact('db.session', h, { service: 'redis', tool: 'redis-cli', detail: 'authenticated database session established' }, S, source));
      _add(facts, mkFact('service.redis', h, { port: redisPort, protocol: 'tcp', service: 'redis', tool: 'redis-cli' }, S, source));
      _add(facts, mkFact('redis.reachable', h, { port: redisPort, tool: 'redis-cli' }, S, source));
      _add(facts, mkFact('db.reachable', h, { service: 'redis', port: redisPort, tool: 'redis-cli' }, S, source));
    }
    if ((isRedisHit || hasLiveRedisFollowPrompt || (isRedisCmd && /\b(?:NOAUTH|WRONGPASS|NOPERM)\b/i.test(text))) && !/(?:Could\s+not\s+connect\s+to\s+Redis|Connection\s+refused|Connection\s+timed\s+out)/i.test(text)) {
      _add(facts, mkFact('service.redis', h, { port: redisPort, protocol: 'tcp', service: 'redis', tool: 'redis-cli' }, S, source));
      _add(facts, mkFact('redis.reachable', h, { port: redisPort, tool: 'redis-cli' }, S, source));
      _add(facts, mkFact('db.reachable', h, { service: 'redis', port: redisPort, tool: 'redis-cli' }, S, source));
    }
    var redisSeedPool = (ws && (ws.seedFacts || ws.facts)) || [];
    var hasPriorRedisAuth = Array.isArray(redisSeedPool) && redisSeedPool.some(function (f) {
      return f && f.kind === 'credential.validated' && f.value && String(f.value.service || '').toLowerCase() === 'redis';
    });
    if (isRedisHit) {
      if (!denied && !_REDIS_DENIED_RE.test(text) && !hasRedisAuthSupplied && !(isAlreadyOpenRedisRepl && hasPriorRedisAuth)) {
        _add(facts, mkFact('config.review', h, { kind: 'unauthenticated_redis', service: 'redis', detail: 'redis responded to INFO/KEYS without authentication' }, S, source));
        _add(facts, mkFact('redis.unauth', h, { port: redisPort, tool: 'redis-cli' }, S, source));
      }
    }

    var sqlFlagFileM = /\b(?:load_file|pg_read_file|xp_cmdshell|openrowset)\b[^\r\n]*?\b(proof|root|local|user)\.txt\b/i.exec((command || '') + '\n' + promptLine + '\n' + text);
    if (sqlFlagFileM) {
      var sqlFlagCellM = /^\s*\|\s*([0-9a-fA-F]{32})\s*\|\s*$/m.exec(text);
      if (sqlFlagCellM) {
        var flagKindName = /^(?:proof|root)$/i.test(sqlFlagFileM[1]) ? 'objective.root_flag' : 'objective.user_flag';
        var flagFileName = sqlFlagFileM[1].toLowerCase() + '.txt';
        _add(facts, mkFact('proof.captured', h, { file: flagFileName, hash: sqlFlagCellM[1], via: 'sql-file-read' }, S, source));
        _add(facts, mkFact(flagKindName, h, { file: flagFileName, hash: sqlFlagCellM[1], via: 'sql-file-read' }, S, source));
      }
    }

    // Redis module / Lua command execution (system.exec, shell.exec, redis.exec, os.execute, eval) or RESP-escaped shell stdout
    var combinedRedisCtx = (command || '') + '\n' + text + '\n' + promptLine;
    var hasRedisExecVerb = (isRedisCmd || low.indexOf('redis') >= 0) && /\b(?:system\.exec|shell\.exec|redis\.exec|cmd\.exec|os\.execute|\beval\b)\b/i.test(combinedRedisCtx);
    var respQuotedMatches = reAll(/"(?:[^"\\\r\n]|\\.)*"/g, text);
    var hasRespEscapedShell = respQuotedMatches.some(function (qm) {
      var qs = qm[0];
      return /\\[nr]/.test(qs) && (/(?:e?uid)=\d+\(/i.test(qs) || /\bLinux\s+\S+\s+\d+\.\d+/i.test(qs) || /\bnt\s+(?:authority|service)\\\\/i.test(qs));
    });
    if ((hasRedisExecVerb || hasRespEscapedShell) && !_REDIS_DENIED_RE.test(text)) {
      var unwrappedChunks = [];
      if (respQuotedMatches.length) {
        respQuotedMatches.forEach(function (qm) {
          var uq = _unescape_resp_bulk_string(qm[0]).trim();
          if (uq) unwrappedChunks.push(uq);
        });
      } else if (hasRedisExecVerb) {
        var rawTrimmed = text.trim();
        if (rawTrimmed) unwrappedChunks.push(_unescape_resp_bulk_string(rawTrimmed));
      }
      if (unwrappedChunks.length) {
        var unwrapped = unwrappedChunks.join('\n');
        if (C._parse_ssh_exec) {
          C._parse_ssh_exec(unwrapped, ws, '', source, facts);
        }
        if (C._parse_privesc_output) {
          C._parse_privesc_output('', unwrapped, ws, '', source, facts);
        }
        if (!reSearch(C._LINUX_ID_RE, unwrapped) && /\bwhoami\b/i.test(combinedRedisCtx) && C._parse_posix_whoami_escalation) {
          C._parse_posix_whoami_escalation(unwrapped, ws, 'whoami', source, facts);
        }
        if (C._SYSTEM_ID_RE && reSearch(C._SYSTEM_ID_RE, unwrapped)) {
          _add(facts, mkFact('foothold.windows', h, { service: 'redis', method: 'redis-exec', identity: 'nt authority\\system' }, S, source));
          _add(facts, mkFact('access.shell', h, { service: 'redis', os: 'windows', user: 'nt authority\\system' }, S, source));
          _add(facts, mkFact('access.admin', h, { service: 'redis', method: 'redis-exec', identity: 'nt authority\\system' }, S, source));
          _add(facts, mkFact('access.system', h, { service: 'redis', method: 'redis-exec', identity: 'nt authority\\system' }, S, source));
          C._add_os_observation(facts, ws, source, 'windows', 'redis command execution (nt authority\\system)', 'high', 'redis', true);
        } else if (C._WHOAMI_ID_RE) {
          var winIdM = reSearch(C._WHOAMI_ID_RE, unwrapped);
          if (winIdM && winIdM.groups && winIdM.groups.id) {
            var winId = winIdM.groups.id.trim();
            _add(facts, mkFact('foothold.windows', h, { service: 'redis', method: 'redis-exec', identity: winId }, S, source));
            _add(facts, mkFact('access.shell', h, { service: 'redis', os: 'windows', user: winId }, S, source));
            if (/(?:^|\\)administrator$/i.test(winId)) {
              _add(facts, mkFact('access.admin', h, { service: 'redis', method: 'redis-exec', identity: winId }, S, source));
            }
            C._add_os_observation(facts, ws, source, 'windows', 'redis command execution (' + winId + ')', 'high', 'redis', true);
          }
        }
        var hasRootFact = facts.some(function (f) { return f && f.kind === 'access.root' && f.scope === h; });
        var hasAdminFact = facts.some(function (f) { return f && f.kind === 'access.admin' && f.scope === h; });
        if (hasRootFact && !hasAdminFact) {
          _add(facts, mkFact('access.admin', h, { service: 'redis', identity: 'root', method: 'redis-exec' }, S, source));
        }
      }
    }

    // Interactive schema enumeration: SHOW DATABASES / SHOW TABLES print the database or table
    // inventory, the map of what to loot next. parser-signatures already declares the database parser
    // emits db.databases/db.tables (the sqlmap, mongo, and nxc-mssql paths mint them); this fills the
    // same kinds for the interactive mysql/mariadb/mssql/psql session, which previously minted nothing
    // from a bare `show tables;`/`show databases;` in a sub-shell. Gated on the command verb so a
    // multi-column select or describe grid (interior pipes, different intent) never enters here.
    var showDb = /\bshow\s+(?:databases|schemas)\b/i.test(low)
      || /\bselect\s+(?:TOP\s+\d+\s+)?(?:\*|name(?:\s*,[^\r\n]+)?)\s+from\s+(?:master\.\s*(?:\.\s*)?(?:dbo\.\s*)?|(?:sys|dbo)\.\s*)?sysdatabases\b/i.test(low + '\n' + promptLine + '\n' + text)
      || /\bselect\s+name\s+from\s+(?:master\.\s*)?(?:sys\.\s*)?databases\b/i.test(low + '\n' + promptLine + '\n' + text)
      || /\bselect\s+datname\s+from\s+(?:pg_catalog\.)?pg_database\b/i.test(low + '\n' + text)
      || /(?:^|\n)\s*\\l(?:ist)?\+?(?:\s|;|$)/i.test((command || '') + '\n' + text)
      || /^\s*List of databases\s*$/im.test(text)
      || /(?:^|\n)\s*(?:mysql|MariaDB\s*\[[^\]]*\]|SQL(?:\s*\([^)]*\))?|postgres=#?)\s*>\s*show\s+(?:databases|schemas)\b/i.test(text);
    var showTbl = /\bshow\s+tables\b/i.test(low)
      || /\bselect\s+(?:tablename|table_name)\s+from\s+(?:(?:pg_catalog\.)?pg_tables|information_schema\.tables)\b/i.test(low + '\n' + text)
      || /(?:^|\n)\s*\\dt\+?(?:\s|;|$)/i.test((command || '') + '\n' + text)
      || /^\s*List of relations\s*$/im.test(text)
      || /(?:^|\n)\s*(?:mysql|MariaDB\s*\[[^\]]*\]|SQL(?:\s*\([^)]*\))?|postgres=#?)\s*>\s*show\s+tables\b/i.test(text)
      || /^\s*\|\s*Tables_in_[^|\r\n]+\|\s*$/im.test(text);
    if (showDb || showTbl) {
      if (showDb && showTbl) {
        var dbNames = [], tblNames = [], curKind = 'db';
        text.split(/\r?\n/).forEach(function (ln) {
          if (/\bshow\s+(?:databases|schemas)\b|^\s*\|\s*(?:Database|schema_name)\s*\|\s*$/i.test(ln)) { curKind = 'db'; return; }
          if (/\bshow\s+tables\b|^\s*\|\s*Tables_in_[^|\r\n]+\|\s*$/i.test(ln)) { curKind = 'tbl'; return; }
          var pm = /^\s*\|\s*([^|\r\n]+?)\s*\|\s*$/.exec(ln);
          var nm = pm ? pm[1].trim() : '';
          if (!nm) return;
          var lo = nm.toLowerCase();
          if (lo === 'database' || lo === 'databases' || lo === 'schema_name' || lo === 'name' || lo === 'datname' || lo === 'tablename' || lo === 'table_name' || /^tables_in_/i.test(nm)) return;
          var bucket = curKind === 'tbl' ? tblNames : dbNames;
          if (bucket.indexOf(nm) < 0) bucket.push(nm);
        });
        if (dbNames.length) _add(facts, mkFact('db.databases', h, { tool: _db_tool(low), databases: dbNames.slice(0, 500), count: dbNames.length }, S, source));
        if (tblNames.length) _add(facts, mkFact('db.tables', h, { tool: _db_tool(low), tables: tblNames.slice(0, 500), count: tblNames.length }, S, source));
      } else {
        var listNames = [];
        _db_listing_names(text).forEach(function (nm) {
          var lo = nm.toLowerCase();
          if (lo === 'database' || lo === 'databases' || lo === 'schema_name' || lo === 'name' || lo === 'datname' || lo === 'tablename' || lo === 'table_name' || /^tables_in_/i.test(nm)) return;
          if (listNames.indexOf(nm) < 0) listNames.push(nm);
        });
        if (listNames.length) {
          if (showDb) _add(facts, mkFact('db.databases', h, { tool: _db_tool(low), databases: listNames.slice(0, 500), count: listNames.length }, S, source));
          else _add(facts, mkFact('db.tables', h, { tool: _db_tool(low), tables: listNames.slice(0, 500), count: listNames.length }, S, source));
        }
      }
    }

    var mongoSessionCtx = text + (followPrompt ? '\n' + followPrompt : '') + (promptLine ? '\n' + promptLine : '');
    var isMongoContext = low.indexOf('mongo') >= 0 || /\bUsing Mongosh:|\bCurrent Mongosh Log ID:|\bConnecting to:\s*mongodb:\/\/|\bMongoServerError:|\btest>\s/i.test(mongoSessionCtx);
    var hasMongoPositiveData = _MONGO_POSITIVE_DATA_RE.test(text);
    var isMongoAuthDenied = isMongoContext && !_MONGO_CONN_FAIL_RE.test(text) && (_MONGO_AUTH_DENIED_RE.test(text) || (!!denied && !hasMongoPositiveData && /\b(?:requires\s+authentication|unauthorized|authentication\s+failed|access\s+denied)\b/i.test(text)));
    if (isMongoAuthDenied && !hasMongoPositiveData) {
      var mongoToolName = _db_tool(low);
      if (mongoToolName === 'database') mongoToolName = /\bmongosh\b/i.test(mongoSessionCtx) ? 'mongosh' : 'mongo';
      _add(facts, mkFact('db.reachable', h, { service: 'mongodb', port: 27017, tool: mongoToolName }, S, source));
      _add(facts, mkFact('blocker.access_denied', h, { service: 'mongodb', reason: 'auth_required' }, S, source));
    }

    var isPgRejectionCtx = low.indexOf('psql') >= 0
      || /\bpsql:\s*(?:error:\s*)?(?:connection to server[^\r\n]*failed:\s*)?FATAL:/i.test(text)
      || /\bFATAL:\s*no pg_hba\.conf entry for host\b/i.test(text);
    if (isPgRejectionCtx) {
      var pgPortM = /(?:^|\s)-p\s+(\d{1,5})\b/.exec(command || '') || /\bport\s+(\d{1,5})\s+failed:\s*FATAL:/i.exec(text);
      var pgPort = pgPortM ? parseInt(pgPortM[1], 10) : 5432;
      if (!(pgPort >= 1 && pgPort <= 65535)) pgPort = 5432;
      if (/\bFATAL:\s*(?:no pg_hba\.conf entry for host\b|database\s+"[^"\r\n]+"\s+is not currently accepting connections|role\s+"[^"\r\n]+"\s+is not permitted to log in)/i.test(text)) {
        _add(facts, mkFact('postgres.reachable', h, { port: pgPort, tool: 'psql' }, S, source));
        _add(facts, mkFact('db.reachable', h, { service: 'postgresql', port: pgPort, tool: 'psql' }, S, source));
        _add(facts, mkFact('blocker.access_denied', h, { service: 'postgresql', reason: 'pg_hba_rejected' }, S, source));
      } else if (/\bFATAL:\s*(?:password|Peer|Ident|SCRAM|GSSAPI|PAM|LDAP|certificate|RADIUS|BSD)\s+authentication failed for user\b/i.test(text)) {
        _add(facts, mkFact('postgres.reachable', h, { port: pgPort, tool: 'psql' }, S, source));
        _add(facts, mkFact('db.reachable', h, { service: 'postgresql', port: pgPort, tool: 'psql' }, S, source));
        _add(facts, mkFact('blocker.logon_failure', h, { service: 'postgresql', reason: 'auth_failed' }, S, source));
      }
    }

    // A successful interactive login -> db.session, the fact that unlocks the DB post-exploitation
    // (loot the tables, or MSSQL xp_cmdshell). Conservative: a recognizable engine-specific success
    // banner/prompt AND no access-denied line, so a failed login or an unrelated paste mints nothing.
    if (!denied) {
      var sessionText = text
        + (followPrompt ? '\n' + followPrompt : '')
        + (_DB_INTERACTIVE_PROMPT_LINE_RE.test(promptLine) ? '\n' + promptLine : '');
      var sessionTextNoPaths = sessionText.replace(/[A-Za-z]:\\[^\r\n]*\.(?:exe|dll)\b/gi, '');
      var tlow = sessionText.toLowerCase(), svc = null;
      if ((low.indexOf('mysql') >= 0 || /\bmariadb\b|\bversion\(\)/i.test(sessionText) || /^\s*mysql\s*>|Welcome to the (?:MySQL|MariaDB) monitor/im.test(sessionText)) &&
          (/\bmysql\s*>/.test(sessionText) || /mariadb\s*\[/i.test(sessionText) || /Welcome to the (?:MySQL|MariaDB) monitor/i.test(sessionText) || tlow.indexOf('information_schema') >= 0 ||
           /\bversion\(\)/i.test(sessionText) || /server version:\s*\S/i.test(sessionText) ||
           /^\s*\d+\.\d+\.\d+(?!\.\d)(?:-[A-Za-z0-9._-]+)?\s*$/im.test(text))) svc = 'mysql';
      else if ((low.indexOf('mssqlclient') >= 0 || low.indexOf('sqlcmd') >= 0 || /\bSQL\s*\([^)]+\)\s*>|\bENVCHANGE\(DATABASE\)|\bImpacket\b[\s\S]{0,240}\bSQL\s*>/i.test(sessionText)) &&
               (/\bSQL\s*(?:\([^)]*\)\s*)?>/.test(sessionText) || /microsoft sql server|\bENVCHANGE\(DATABASE\)/i.test(sessionTextNoPaths) || /^\s*1>\s/m.test(sessionText))) svc = 'mssql';
      // NetExec MSSQL auth success: the protocol banner line "MSSQL <ip> <port> <host> [+] dom\user:pw (Pwn3d!)".
      else if (nxcMssql && (/MSSQL\b[^\n]*\[\+\]/i.test(text) || /\(Pwn3d!\)/i.test(text))) svc = 'mssql';
      else if ((low.indexOf('psql') >= 0 || /\bPostgreSQL\s+\d+\.\d+\s+on\b|\bpsql\s*\(\d+\.\d+/i.test(sessionText) || /^\s*[A-Za-z][A-Za-z0-9_.-]{0,62}=[#>](?:\s|$)/m.test(sessionText) || /\b(?:pg_shadow|pg_database|pg_authid|pg_tables)\b/i.test(low + '\n' + sessionText)) &&
               (/list of (?:databases|relations)/i.test(sessionText) || /^\s*[A-Za-z0-9_.-]+=[#>]/m.test(sessionText) || /^\s*\(\d+\s+rows?\)\s*$/im.test(sessionText) || tlow.indexOf('template0') >= 0 || /\bPostgreSQL\s+\d+\.\d+|\bpsql\s*\(\d+\.\d+/i.test(sessionText))) svc = 'postgresql';
      else if ((low.indexOf('sqlplus') >= 0 || low.indexOf('odat') >= 0 || /Connected to:\s*Oracle Database|SQL\*Plus:\s*Release/i.test(sessionText)) &&
               (/connected to:/i.test(sessionText) || /^\s*SQL\s*>/m.test(sessionText) || /\[\+\]\s*Valid credential:/i.test(text))) svc = 'oracle';
      else if (!isMongoAuthDenied && !_MONGO_CONN_FAIL_RE.test(text) &&
               (low.indexOf('mongo') >= 0 || /\badmin\s+\d+(?:\.\d+)?\s*[KMGT]?i?B\b[\s\S]{0,120}\bconfig\s+\d+/i.test(text)) &&
               (hasMongoPositiveData || ((/\bUsing MongoDB:\s*\d|\bCurrent Mongosh Log ID:\s*[0-9a-f]{16,}|\bMongoDB server version:\s*\d|\bImplicit session:\s*session\s*\{/i.test(sessionText) || /^\s*(?:rs\d+:(?:PRIMARY|SECONDARY)|test|admin|config|local|[A-Za-z0-9_-]{2,32})>\s*(?:show\s+(?:dbs|databases|collections|users)|use\s+\S+|db\.|$)/im.test(sessionText)) && !/Mongo(?:Server|Network)?Error:/i.test(sessionText)))) {
        svc = 'mongodb';
        _add(facts, mkFact('mongo.unauth', h, { port: 27017, tool: 'mongosh' }, S, source));
      }
      else if ((low.indexOf('sqlite') >= 0 || /SQLite format 3|CREATE TABLE/i.test(text)) && (/\bsqlite\s*>/i.test(sessionText) || /CREATE TABLE/i.test(text) || low.indexOf('.schema') >= 0 || low.indexOf('.tables') >= 0 || low.indexOf('select') >= 0)) svc = 'sqlite';
      else if (isRedisHit && !_REDIS_DENIED_RE.test(sessionText)) svc = 'redis';
      if (svc) {
        var dbTool = _db_tool(low);
        _add(facts, mkFact('db.session', h, { service: svc, tool: dbTool, detail: 'authenticated database session established' }, S, source));
        if (svc !== 'sqlite') {
          _add(facts, mkFact('db.reachable', h, { service: svc, tool: dbTool }, S, source));
        }
        if (svc === 'mssql' || svc === 'postgresql' || svc === 'mysql' || svc === 'oracle') {
          var loginCred = _extract_db_login_cred(text, command, sessionText, svc);
          var validVal = { service: svc, tool: dbTool, outcome: 'accepted' };
          if (loginCred.user) validVal.user = loginCred.user;
          _add(facts, mkFact('credential.validated', h, validVal, S, source));
          if (loginCred.password) {
            var credVal = { password: loginCred.password, service: svc, tool: dbTool, via: svc + '-login' };
            if (loginCred.user) credVal.user = loginCred.user;
            _add(facts, mkFact('credential.plaintext', h, credVal, S, source));
            _add(facts, mkFact('credential.available', h, credVal, S, source));
          }
        }
        if (svc === 'mssql') {
          _add(facts, mkFact('mssql.authenticated', h, { service: 'mssql', tool: dbTool }, S, source));
          if (/\bSQL\s*\([^)]*\bdbo@master\)|(?:^|[\s/\\])sa(?::|@|\s+dbo@)/i.test(sessionText + '\n' + (command || '')) || /\(Pwn3d!\)|\bsysadmin\b|\bCONTROL\s+SERVER\b/i.test(text)) {
            _add(facts, mkFact('mssql.sysadmin', h, { service: 'mssql', role: 'sysadmin', tool: dbTool }, S, source));
            _add(facts, mkFact('db.admin', h, { engine: 'mssql', role: 'sysadmin', tool: dbTool }, S, source));
          }
        }
      }
    }
  }
  C._parse_database_output = _parse_database_output;

})(typeof globalThis !== 'undefined' ? globalThis : this);
