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
  var _DB_HASH_ROW_RE = /\b(?<user>[A-Za-z0-9_.@-]{2,64})\b(?:\s*[|:]\s*[A-Za-z0-9_.%:-]+)?\s*[|:]\s*(?<hash>\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}|\$(?:P|H|1|5|6|y|apr1)\$[^\s|]+|\*[0-9A-Fa-f]{40}|(?:0x)?[a-fA-F0-9]{32,128})\b/;
  var _XP_CMDSHELL_DENIED_RE = /The EXECUTE permission was denied|Configuration option 'xp_cmdshell' does not exist|SQL Server blocked access to procedure/i;

  function _db_tool(low) {
    if (/\b(?:nxc|netexec|crackmapexec|cme)\b/.test(low)) return 'nxc';
    var tools = ['mssqlclient', 'sqlcmd', 'mysql', 'psql', 'pymongo', 'mongosh', 'mongo', 'redis-cli', 'sqlite3', 'sqlite', 'odat', 'sqlplus'];
    for (var i = 0; i < tools.length; i++) if (low.indexOf(tools[i]) >= 0) return tools[i];
    return 'database';
  }

  function _parse_database_output(text, ws, command, source, facts) {
    if (!text.trim()) return;
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
      }
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
    if (['password', 'hash', 'users', 'user', 'partners', 'accounts', 'credential', 'sqlite', 'authentication_string'].some(function (k) { return (text + '\n' + low).toLowerCase().indexOf(k) >= 0; }) || /^\s*\d+\|[^|\r\n]+\|\$(?:2[aby]|1|5|6|y|P|H|apr1)\$/im.test(text)) {
      reAll(_DB_HASH_ROW_RE, text).forEach(function (m) {
        var hsh = m.groups.hash;
        if (seen[hsh.toLowerCase()] || hsh.toLowerCase() === 'password' || hsh.toLowerCase() === 'email') return;
        seen[hsh.toLowerCase()] = true;
        hashes.push({ user: m.groups.user, hash: hsh });
      });
    }
    if (hashes.length) {
      _add(facts, mkFact('loot.material', h, { kind: 'db_hashes', entries: hashes.slice(0, 50), count: hashes.length, via: 'database', tool: _db_tool(low) }, S, source));
      _add(facts, mkFact('db.hashes', h, { entries: hashes.slice(0, 50), count: hashes.length, tool: _db_tool(low) }, S, source));
      hashes.slice(0, 20).forEach(function (entry) {
        _add(facts, mkFact('credential.candidate', h, { kind: 'database_hash', user: entry.user, hash: entry.hash, via: 'database' }, S, source));
      });
    }

    var isRedisHit = (low.indexOf('redis') >= 0 || /^redis_version:/im.test(text)) && (text.toLowerCase().indexOf('# server') >= 0 || /^redis_version:/im.test(text) || /^\+PONG\b|^PONG\b|^\+OK\b/im.test(text) || /^\s*\d+\)\s+"/m.test(text));
    if (isRedisHit) {
      if (!denied && text.toLowerCase().indexOf('noauth') < 0) {
        _add(facts, mkFact('config.review', h, { kind: 'unauthenticated_redis', service: 'redis', detail: 'redis responded to INFO/KEYS without authentication' }, S, source));
        _add(facts, mkFact('redis.unauth', h, { port: 6379, tool: 'redis-cli' }, S, source));
      }
    }

    // A successful interactive login -> db.session, the fact that unlocks the DB post-exploitation
    // (loot the tables, or MSSQL xp_cmdshell). Conservative: a recognizable engine-specific success
    // banner/prompt AND no access-denied line, so a failed login or an unrelated paste mints nothing.
    if (!denied) {
      var tlow = text.toLowerCase(), svc = null;
      if ((low.indexOf('mysql') >= 0 || /\bmariadb\b|\bversion\(\)/i.test(text)) &&
          (/\bmysql\s*>/.test(text) || /mariadb\s*\[/i.test(text) || tlow.indexOf('information_schema') >= 0 ||
           /\bversion\(\)/i.test(text) || /server version:\s*\S/i.test(text) ||
           /^\s*\d+\.\d+\.\d+(?!\.\d)(?:-[A-Za-z0-9._-]+)?\s*$/im.test(text))) svc = 'mysql';
      else if ((low.indexOf('mssqlclient') >= 0 || low.indexOf('sqlcmd') >= 0 || /\bSQL\s*\([^)]+\)>/.test(text)) &&
               (/\bSQL\s*[>(]/.test(text) || /microsoft sql server/i.test(text) || /^\s*1>\s/m.test(text))) svc = 'mssql';
      // NetExec MSSQL auth success: the protocol banner line "MSSQL <ip> <port> <host> [+] dom\user:pw (Pwn3d!)".
      else if (nxcMssql && (/MSSQL\b[^\n]*\[\+\]/i.test(text) || /\(Pwn3d!\)/i.test(text))) svc = 'mssql';
      else if ((low.indexOf('psql') >= 0 || /\bPostgreSQL\s+\d+\.\d+\s+on\b/i.test(text)) &&
               (/list of databases/i.test(text) || /^\s*\w+=[#>]/m.test(text) || tlow.indexOf('template0') >= 0 || /\bPostgreSQL\s+\d+\.\d+/i.test(text))) svc = 'postgresql';
      else if ((low.indexOf('sqlplus') >= 0 || low.indexOf('odat') >= 0 || /Connected to:\s*Oracle Database/i.test(text)) &&
               (/connected to:/i.test(text) || /^\s*SQL>/m.test(text) || /\[\+\]\s*Valid credential:/i.test(text))) svc = 'oracle';
      else if ((low.indexOf('mongo') >= 0 || /\badmin\s+\d+(?:\.\d+)?\s*[KMGT]?i?B\b[\s\S]{0,120}\bconfig\s+\d+/i.test(text)) &&
               (/\b(?:admin|local|config)\s+\d+(?:\.\d+)?\s*[KMGT]?i?B\b/i.test(text) || /test>|\bmongosh\b/i.test(text))) {
        svc = 'mongodb';
        _add(facts, mkFact('mongo.unauth', h, { port: 27017, tool: 'mongosh' }, S, source));
      }
      else if ((low.indexOf('sqlite') >= 0 || /SQLite format 3|CREATE TABLE/i.test(text)) && (/\bsqlite\s*>/i.test(text) || /CREATE TABLE/i.test(text) || low.indexOf('.schema') >= 0 || low.indexOf('.tables') >= 0 || low.indexOf('select') >= 0)) svc = 'sqlite';
      else if (isRedisHit && tlow.indexOf('noauth') < 0) svc = 'redis';
      if (svc) _add(facts, mkFact('db.session', h, { service: svc, tool: _db_tool(low), detail: 'authenticated database session established' }, S, source));
    }
  }
  C._parse_database_output = _parse_database_output;

})(typeof globalThis !== 'undefined' ? globalThis : this);
