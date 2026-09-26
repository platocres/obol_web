/*!
 * obol engine — parsers/websource.js
 * Port of the fixture-reachable §33 web source/disclosure parsers from
 * obol-local/obol/parsers/websource.py: product-signature fingerprint and the SQLi oracle
 * (differential boolean + reflected UNION column). The remaining OSWE content-gated parsers
 * (verbose_error, source_secret, pem_key, js_framework, graphql, phpinfo, dependency_manifest,
 * git_exposed, xmlrpc, cracked_hash, weak_hashing) are intentionally NOT ported — see index.js.
 * Like the Python module, `_add` here appends (no cross-pass dedup).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  function normalizeTarget(t) {
    t = String(t || '').trim();
    t = t.replace(/^\w+:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
    return t;
  }
  function _scope(ws) { return ws && ws.target ? 'host:' + normalizeTarget(ws.target) : ''; }
  function _add(facts, fact) { facts.push(fact); }

  // ---- product-signature fingerprint ---- //
  var _PRODUCT_SIGS = [
    ['moodle', /(?:Powered by\s+Moodle|<meta name="keywords" content="moodle)/i, /Moodle\s+(\d+\.\d+(?:\.\d+)?)/i, 'authenticated RCE via a crafted plugin/quiz; check MoodleScan + CVEs'],
    ['gitea', /Powered by\s+Gitea/i, /Gitea\s+Version:\s*(\d+\.\d+\.\d+)/i, 'enum /explore/users + repos to review; git-hook RCE if admin'],
    ['gitbucket', /\bGitBucket\b/i, /GitBucket\s+(\d+\.\d+(?:\.\d+)?)/i, 'plugin/H2-console RCE; repo review'],
    ['gogs', /Powered by\s+Gogs/i, /Gogs\s+Version:\s*(\d+\.\d+(?:\.\d+){0,2})/i, 'enum /explore/users + repos to review; git-hook RCE if admin; Gogs CVE-2018-18925 (auth-bypass/RCE), path-traversal'],
    ['gitlab', /GitLab (?:Community|Enterprise) Edition|Powered by\s+GitLab|content=["']GitLab["']/i, /GitLab(?:\s+(?:Community|Enterprise)\s+Edition)?\s+v?(\d+\.\d+\.\d+)/i, 'check /help & /api/v4/version; user-enum via /users; ExifTool unauth RCE (CVE-2021-22205) — pin the exact version for the CVE match'],
    ['zabbix', /Zabbix\s+SIA|<title>\s*Zabbix/i, /Zabbix\s+(\d+\.\d+(?:\.\d+)?)/i, 'auth bypass / SQLi CVEs; script-item RCE as Admin'],
    ['cacti', /Cacti(?:\s+Group|<)|The Cacti Group/i, /Version\s+(\d+\.\d+(?:\.\d+)?)/i, 'CVE-2022-46169 unauth RCE; SQLi chains'],
    ['apache-ofbiz', /Apache\s+OFBiz/i, /OFBiz\s+(\d+\.\d+(?:\.\d+)?)/i, 'XML-RPC deserialization (CVE-2020-9496 / groovy)'],
    ['sharepoint', /MicrosoftSharePointTeamServices|_layouts\/15\//i, /MicrosoftSharePointTeamServices:\s*(\d+\.\d+(?:\.\d+){0,2})/i, 'ToolPane/ViewState deserialization RCE'],
    ['mojoportal', /\bmojoPortal\b/i, /mojoPortal\s+(\d+\.\d+(?:\.\d+)?)/i, 'file-upload / XSS chains'],
    ['helpdeskz', /\bHelpDeskZ\b/i, /HelpDeskZ\s+v?(\d+\.\d+(?:\.\d+)?)/i, 'unauth file-upload RCE (CVE-2014-6308-class)'],
    ['phpmyadmin', /\bphpMyAdmin\b|pma_username/i, /phpMyAdmin\s+(\d+\.\d+\.\d+)/i, 'LOAD_FILE/INTO OUTFILE, SQL console, known LFI/RCE CVEs'],
    ['gophish', /\bgophish\b|X-Gophish/i, null, 'admin panel default creds; phishing infra'],
    ['jamovi', /\bjamovi\b/i, /jamovi\s+(\d+\.\d+(?:\.\d+)?)/i, 'Rj-editor / compute-module RCE'],
    ['splunk', /Splunk\s+(?:Enterprise|Inc)|\/en-US\/account\/login/i, /Splunk[^\d]{0,20}(\d+\.\d+\.\d+)/i, 'custom-app scripted-input RCE; splunk.secret → $7$ decrypt'],
    ['powershell-web-access', /PowerShell Web Access|\/pswa\//i, null, 'gateway to any Windows host — try captured/guessed domain creds'],
  ];

  function _has_product_signature(text) {
    return _PRODUCT_SIGS.some(function (r) { return reSearch(r[1], text || ''); });
  }
  C._has_product_signature = _has_product_signature;

  function _parse_product_signature(text, ws, command, source, facts) {
    for (var i = 0; i < _PRODUCT_SIGS.length; i++) {
      var tech = _PRODUCT_SIGS[i][0], sigRx = _PRODUCT_SIGS[i][1], verRx = _PRODUCT_SIGS[i][2], lead = _PRODUCT_SIGS[i][3];
      if (!reSearch(sigRx, text || '')) continue;
      var value = { name: tech, product: true, lead: lead };
      if (verRx) {
        var m = reSearch(verRx, text || '');
        if (m) value.version = m[1];
      }
      _add(facts, mkFact('web.tech', _scope(ws), value, S, source));
      return;
    }
  }
  C._parse_product_signature = _parse_product_signature;

  // ---- SQLi oracle: differential boolean + reflected UNION column ---- //
  var _SQLI_TRUE_RE = /(?:['"]\s*)?(?:OR|\|\|)\s*(?:['"]?1['"]?\s*=\s*['"]?1['"]?|1\s*=\s*1|['"]a['"]\s*=\s*['"]a['"]|TRUE)\b|['"]\s*(?:--\s|--$|#|\/\*)/im;
  var _SQLI_FALSE_RE = /(?:['"]\s*)?(?:OR|AND|&&)\s*(?:['"]?1['"]?\s*=\s*['"]?2['"]?|1\s*=\s*2|['"]a['"]\s*=\s*['"]b['"]|FALSE)\b/i;
  var _LOGIN_SUCCESS_RE = /HTTP\/\d(?:\.\d)?\s+30[27]\b|Location:\s*\/?(?:dashboard|home|admin|account|profile|welcome)|Set-Cookie:\s*(?:session|auth|token|connect\.sid|PHPSESSID|JSESSIONID|express)|\bWelcome\b|\bLogged in\b|login successful|authentication successful|"(?:success|authenticated|logged_?in|auth)"\s*:\s*true/i;
  var _LOGIN_FAILURE_RE = /HTTP\/\d(?:\.\d)?\s+(?:401|403)\b|\bInvalid\b|\bincorrect\b|login failed|authentication failed|access denied|\bWrong\b|bad credentials|user (?:not found|does not exist)|"(?:success|authenticated|logged_?in)"\s*:\s*false/i;
  var _S = '(?:\\s|%20|\\+)+';
  var _UNION_MARKER_RE = new RegExp('union' + _S + '(?:all' + _S + ')?select\\b[^\\n]*?[\'"](?<marker>(?=[A-Za-z0-9_]*[A-Za-z])[A-Za-z0-9_]{6,40})[\'"]', 'i');
  var _SQLITE_VER_CALL_RE = new RegExp('union' + _S + '(?:all' + _S + ')?select\\b[^\\n]*?sqlite_version\\s*\\(', 'i');
  var _SQLITE_VER_OUT_RE = /\b3\.\d+\.\d+\b/;
  var _SQL_MARKER_DENY = new Set(['select', 'union', 'null', 'from', 'where', 'concat', 'version', 'database', 'user', 'table', 'column', 'schema', 'information_schema', 'group_concat', 'password', 'username']);

  function _reflected_union_marker(text) {
    var t = text || '';
    var lines = t.split(/\r?\n/);
    var matches = reAll(_UNION_MARKER_RE, t);
    for (var i = 0; i < matches.length; i++) {
      var marker = matches[i].groups.marker;
      if (_SQL_MARKER_DENY.has(marker.toLowerCase())) continue;
      for (var j = 0; j < lines.length; j++) {
        var low = lines[j].toLowerCase();
        if (lines[j].indexOf(marker) >= 0 && !(low.indexOf('union') >= 0 && low.indexOf('select') >= 0)) return marker;
      }
    }
    return '';
  }
  C._reflected_union_marker = _reflected_union_marker;

  function _parse_sqli_oracle(text, ws, command, source, facts) {
    var t = text || '', h = 'host:' + ws.target;
    if (reSearch(_SQLI_TRUE_RE, t) && reSearch(_SQLI_FALSE_RE, t) && reSearch(_LOGIN_SUCCESS_RE, t) && reSearch(_LOGIN_FAILURE_RE, t)) {
      _add(facts, mkFact('web.sqli_confirmed', h, { tool: 'manual', method: 'differential_boolean', evidence: 'true vs false payload produced differing responses (boolean-based oracle)' }, S, source));
    }
    var marker = _reflected_union_marker(t);
    if (marker) {
      _add(facts, mkFact('web.sqli_confirmed', h, { tool: 'manual', method: 'reflected_column', marker: marker, evidence: "injected UNION sentinel '" + marker + "' reflected in the response" }, S, source));
    } else if (reSearch(_SQLITE_VER_CALL_RE, t)) {
      var lines = t.split(/\r?\n/);
      for (var i = 0; i < lines.length; i++) {
        var low = lines[i].toLowerCase();
        if (low.indexOf('union') >= 0 || low.indexOf('select') >= 0 || low.indexOf('sqlite_version') >= 0) continue;
        if (reSearch(_SQLITE_VER_OUT_RE, lines[i])) {
          _add(facts, mkFact('web.sqli_confirmed', h, { tool: 'manual', method: 'reflected_column', dbms: 'SQLite', evidence: 'sqlite_version() result reflected: ' + lines[i].trim().slice(0, 80) }, S, source));
          break;
        }
      }
    }
  }
  C._parse_sqli_oracle = _parse_sqli_oracle;

  function _has_sqli_oracle(text) {
    var low = (text || '').toLowerCase();
    if (low.indexOf('union') >= 0 && low.indexOf('select') >= 0) return true;
    return !!(reSearch(_SQLI_TRUE_RE, text || '') && reSearch(_SQLI_FALSE_RE, text || ''));
  }
  C._has_sqli_oracle = _has_sqli_oracle;

})(typeof globalThis !== 'undefined' ? globalThis : this);
