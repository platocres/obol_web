/*!
 * obol engine — parsers/database.js
 * Faithful JS port of obol-local/obol/parsers/database.py.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  var _MSSQL_WHOAMI_RE = /\bnt (?:service|authority)\\[\w$.-]+|\b[\w.-]+\\[\w$.-]+\s*$|uid=\d+\(/im;
  var _DB_ACCESS_DENIED_RE = /access denied|authentication failed|login failed|permission denied|ERROR 1045/i;
  var _DB_HASH_ROW_RE = /\b(?<user>[A-Za-z0-9_.@-]{2,64})\b[^\n|]*[|:]\s*(?<hash>\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}|[a-f0-9]{32,128})/;

  function _db_tool(low) {
    var tools = ['mssqlclient', 'mysql', 'psql', 'pymongo', 'mongosh', 'mongo', 'redis-cli'];
    for (var i = 0; i < tools.length; i++) if (low.indexOf(tools[i]) >= 0) return tools[i];
    return 'database';
  }

  function _parse_database_output(text, ws, command, source, facts) {
    if (!text.trim()) return;
    var h = 'host:' + ws.target, low = command.toLowerCase();
    var denied = reSearch(_DB_ACCESS_DENIED_RE, text);

    if (text.toLowerCase().indexOf('xp_cmdshell') >= 0) {
      var m = reSearch(_MSSQL_WHOAMI_RE, text);
      if (m) {
        var ident = C._line_for_match(text, m).trim();
        var val = { service: 'mssql', method: 'xp_cmdshell', identity: ident, tool: 'mssqlclient' };
        _add(facts, mkFact('foothold.windows', h, val, S, source));
        C._add_os_observation(facts, ws, source, 'windows', 'xp_cmdshell command execution (' + ident + ')', 'high', 'mssql', true);
      }
    }

    var hashes = [], seen = {};
    if (['password', 'hash', 'users'].some(function (k) { return text.toLowerCase().indexOf(k) >= 0; })) {
      reAll(_DB_HASH_ROW_RE, text).forEach(function (m) {
        var hsh = m.groups.hash;
        if (seen[hsh.toLowerCase()] || hsh.toLowerCase() === 'password' || hsh.toLowerCase() === 'email') return;
        seen[hsh.toLowerCase()] = true;
        hashes.push({ user: m.groups.user, hash: hsh });
      });
    }
    if (hashes.length) {
      _add(facts, mkFact('loot.material', h, { kind: 'db_hashes', entries: hashes.slice(0, 50), count: hashes.length, via: 'database', tool: _db_tool(low) }, S, source));
    }

    if (low.indexOf('redis') >= 0 && (text.toLowerCase().indexOf('# server') >= 0 || /^\s*\d+\)\s+"/m.test(text))) {
      if (!denied && text.toLowerCase().indexOf('noauth') < 0) {
        _add(facts, mkFact('config.review', h, { kind: 'unauthenticated_redis', service: 'redis', detail: 'redis responded to INFO/KEYS without authentication' }, S, source));
      }
    }
  }
  C._parse_database_output = _parse_database_output;

})(typeof globalThis !== 'undefined' ? globalThis : this);
