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
  var _DB_ACCESS_DENIED_RE = /access denied|authentication failed|login failed|permission denied|ERROR 1045|can't connect to|connection refused|could not connect to server|timeout expired|login failed for user|ERROR 200[235]|FATAL:\s+password authentication failed|ORA-01017/i;
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

  function _parse_database_output(text, ws, command, source, facts) {
    text = String(text || '');
    var ctx = (ws && ws.context) || {};
    var promptCtx = [ctx.promptLine || '', ctx.followPrompt || ''].filter(Boolean).join('\n').trim();
    if (!text.trim() && !promptCtx) return;
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

    var isRedisHit = (low.indexOf('redis') >= 0 || /^redis_version:/im.test(text)) && (text.toLowerCase().indexOf('# server') >= 0 || /^redis_version:/im.test(text) || /^\+PONG\b|^PONG\b|^\+OK\b/im.test(text) || /^\s*\d+\)\s+"/m.test(text));
    if (isRedisHit) {
      if (!denied && text.toLowerCase().indexOf('noauth') < 0) {
        _add(facts, mkFact('config.review', h, { kind: 'unauthenticated_redis', service: 'redis', detail: 'redis responded to INFO/KEYS without authentication' }, S, source));
        _add(facts, mkFact('redis.unauth', h, { port: 6379, tool: 'redis-cli' }, S, source));
      }
    }

    // Interactive schema enumeration: SHOW DATABASES / SHOW TABLES print the database or table
    // inventory, the map of what to loot next. parser-signatures already declares the database parser
    // emits db.databases/db.tables (the sqlmap, mongo, and nxc-mssql paths mint them); this fills the
    // same kinds for the interactive mysql/mariadb/mssql/psql session, which previously minted nothing
    // from a bare `show tables;`/`show databases;` in a sub-shell. Gated on the command verb so a
    // multi-column select or describe grid (interior pipes, different intent) never enters here.
    var showDb = /\bshow\s+(?:databases|schemas)\b/i.test(low)
      || /\bselect\s+name\s+from\s+(?:master\.\s*)?(?:sys\.\s*)?databases\b/i.test(low + '\n' + text)
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

    // A successful interactive login -> db.session, the fact that unlocks the DB post-exploitation
    // (loot the tables, or MSSQL xp_cmdshell). Conservative: a recognizable engine-specific success
    // banner/prompt AND no access-denied line, so a failed login or an unrelated paste mints nothing.
    if (!denied) {
      var sessionText = promptCtx ? (text + '\n' + promptCtx) : text;
      var tlow = sessionText.toLowerCase(), svc = null;
      if ((low.indexOf('mysql') >= 0 || /\bmariadb\b|\bversion\(\)/i.test(sessionText)) &&
          (/\bmysql\s*>/.test(sessionText) || /mariadb\s*\[/i.test(sessionText) || tlow.indexOf('information_schema') >= 0 ||
           /\bversion\(\)/i.test(sessionText) || /server version:\s*\S/i.test(sessionText) ||
           /^\s*\d+\.\d+\.\d+(?!\.\d)(?:-[A-Za-z0-9._-]+)?\s*$/im.test(text))) svc = 'mysql';
      else if ((low.indexOf('mssqlclient') >= 0 || low.indexOf('sqlcmd') >= 0 || /\bSQL\s*\([^)]+\)>/.test(sessionText)) &&
               (/\bSQL\s*[>(]/.test(sessionText) || /microsoft sql server/i.test(sessionText) || /^\s*1>\s/m.test(sessionText))) svc = 'mssql';
      // NetExec MSSQL auth success: the protocol banner line "MSSQL <ip> <port> <host> [+] dom\user:pw (Pwn3d!)".
      else if (nxcMssql && (/MSSQL\b[^\n]*\[\+\]/i.test(text) || /\(Pwn3d!\)/i.test(text))) svc = 'mssql';
      else if ((low.indexOf('psql') >= 0 || /\bPostgreSQL\s+\d+\.\d+\s+on\b/i.test(sessionText) || /\b(?:pg_shadow|pg_database|pg_authid|pg_tables)\b/i.test(low + '\n' + sessionText)) &&
               (/list of (?:databases|relations)/i.test(sessionText) || /^\s*\w+=[#>]/m.test(sessionText) || /^\s*\(\d+\s+rows?\)\s*$/im.test(sessionText) || tlow.indexOf('template0') >= 0 || /\bPostgreSQL\s+\d+\.\d+/i.test(sessionText))) svc = 'postgresql';
      else if ((low.indexOf('sqlplus') >= 0 || low.indexOf('odat') >= 0 || /Connected to:\s*Oracle Database/i.test(sessionText)) &&
               (/connected to:/i.test(sessionText) || /^\s*SQL>/m.test(sessionText) || /\[\+\]\s*Valid credential:/i.test(text))) svc = 'oracle';
      else if ((low.indexOf('mongo') >= 0 || /\badmin\s+\d+(?:\.\d+)?\s*[KMGT]?i?B\b[\s\S]{0,120}\bconfig\s+\d+/i.test(text)) &&
               (/\b(?:admin|local|config)\s+\d+(?:\.\d+)?\s*[KMGT]?i?B\b/i.test(text) || /test>|\bmongosh\b/i.test(sessionText))) {
        svc = 'mongodb';
        _add(facts, mkFact('mongo.unauth', h, { port: 27017, tool: 'mongosh' }, S, source));
      }
      else if ((low.indexOf('sqlite') >= 0 || /SQLite format 3|CREATE TABLE/i.test(text)) && (/\bsqlite\s*>/i.test(sessionText) || /CREATE TABLE/i.test(text) || low.indexOf('.schema') >= 0 || low.indexOf('.tables') >= 0 || low.indexOf('select') >= 0)) svc = 'sqlite';
      else if (isRedisHit && tlow.indexOf('noauth') < 0) svc = 'redis';
      if (svc) {
        _add(facts, mkFact('db.session', h, { service: svc, tool: _db_tool(low), detail: 'authenticated database session established' }, S, source));
        if (svc === 'mssql') {
          _add(facts, mkFact('mssql.authenticated', h, { service: 'mssql', tool: _db_tool(low) }, S, source));
          _add(facts, mkFact('credential.validated', h, { service: 'mssql', tool: _db_tool(low), outcome: 'accepted' }, S, source));
          if (/\bSQL\s*\([^)]*\bdbo@master\)|(?:^|[\s/\\])sa(?::|@|\s+dbo@)/i.test(sessionText + '\n' + (command || '')) || /\(Pwn3d!\)|\bsysadmin\b|\bCONTROL\s+SERVER\b/i.test(text)) {
            _add(facts, mkFact('mssql.sysadmin', h, { service: 'mssql', role: 'sysadmin', tool: _db_tool(low) }, S, source));
            _add(facts, mkFact('db.admin', h, { engine: 'mssql', role: 'sysadmin', tool: _db_tool(low) }, S, source));
          }
        }
      }
    }
  }
  C._parse_database_output = _parse_database_output;

})(typeof globalThis !== 'undefined' ? globalThis : this);
