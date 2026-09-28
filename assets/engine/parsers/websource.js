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

  // ---- secret-in-source (signing keys, config/framework secrets, VCS tokens, connection URIs) ---- //
  // Signing keys and config secrets disclosed in recovered source (LFI / .git dump / decompile /
  // verbose error). A JWT signing key → web.jwt_secret + credential.candidate; a DB/config/framework
  // password, a VCS PAT, or a credentialed connection URI → credential.candidate. Leads to validate.
  var _SECRET_DENY = {
    changeme: 1, change_me: 1, password: 1, secret: 1, 'your-256-bit-secret': 1, yoursecret: 1,
    xxx: 1, xxxx: 1, todo: 1, none: 1, null: 1, example: 1, placeholder: 1, redacted: 1,
  };
  var _PLACEHOLDER_RE = /^\$\{.*\}$|^<.*>$|^%.*%$|^\$\w+$|^\{\{.*\}\}$/;
  var _GETBYTES_RE = /GetBytes\(\s*["'](?<s>[^"']{6,})["']/g;
  var _SIGNING_MARK_RE = /SymmetricSecurityKey|SigningCredentials|JwtSecurityToken|HmacSha\d|new HMAC|jwt\.sign/i;
  var _SECRET_KEY_RE = /SECRET_KEY['"]?\]?\s*[:=]\s*["'](?<s>[^"']{6,})["']/gi;
  var _JWT_SIGN_RE = /jwt\.sign\([^,]+,\s*["'](?<s>[^"']{6,})["']/gi;
  var _CONFIG_PW_RE = /(?<key>hibernate\.connection\.password|spring\.datasource\.password|jdbc\.password|datasource\.password|connection\.password)\s*[:=]\s*["']?(?<s>[^\s"';]{3,})/gi;
  // Field-style DB/service credential (decompiled jar / source): `sqlPass = "…"`, `dbPassword = "…"`.
  var _FIELD_CRED_RE = /\b(?<key>(?:sql|db|database|mysql|mssql|postgres|pg|jdbc|ftp|smtp|imap|redis|mongo|ldap|admin|root)_?(?:pass(?:word|wd)?|pwd))\s*=\s*["'](?<s>[^"']{3,})["']/gi;
  // A framework-config password field with a quoted literal value (PHP / WordPress define / .env).
  var _PHP_PW_RE = /(?:public|private|protected|var|static)?\s*\$(?<key>\w*(?:pass(?:word|wd)?|pwd))\s*=\s*["'](?<s>[^"']{3,})["']/gi;
  var _DEFINE_PW_RE = /define\(\s*["'](?<key>\w*(?:pass(?:word|wd)?|pwd)\w*)["']\s*,\s*["'](?<s>[^"']{3,})["']/gi;
  var _ENV_PW_RE = /^\s*(?:export\s+)?(?<key>[A-Z][A-Z0-9_]*(?:PASS(?:WORD|WD)?|PWD))\s*=\s*["']?(?<s>[^\s"'#]{3,})/gm;
  // A credential embedded in a connection URI: mysql://user:pass@host, ftp://u:p@host, etc.
  var _URI_CRED_RE = /(?<scheme>[a-z][a-z0-9+.\-]{1,15}):\/\/(?<user>[^:/@\s]{1,64}):(?<s>[^@/\s]{3,64})@(?<host>[\w.\-]+)/gi;
  // A version-control access token — a GitHub PAT (classic gh?_ / fine-grained github_pat_) or a
  // GitLab glpat-. The token IS the credential.
  var _VCS_TOKEN_RE = /\b(?<token>gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,})\b/g;

  function _clean_secret(val) {
    val = (val || '').trim();
    if (!val || _SECRET_DENY[val.toLowerCase()] || _PLACEHOLDER_RE.test(val)) return '';
    return val;
  }
  C._clean_secret = _clean_secret;

  function _has_source_secret(text) {
    var t = text || '';
    return !!(reSearch(_SIGNING_MARK_RE, t) || reSearch(_SECRET_KEY_RE, t)
      || reSearch(_CONFIG_PW_RE, t) || reSearch(_FIELD_CRED_RE, t)
      || reSearch(_PHP_PW_RE, t) || reSearch(_DEFINE_PW_RE, t)
      || reSearch(_ENV_PW_RE, t) || reSearch(_URI_CRED_RE, t)
      || reSearch(_VCS_TOKEN_RE, t));
  }
  C._has_source_secret = _has_source_secret;

  function _parse_source_secret(text, ws, command, source, facts) {
    var t = text || '', scope = _scope(ws), seen = {};

    // JWT-specific idioms → web.jwt_secret (a *JWT* signing secret).
    var jwtSecrets = [];
    if (reSearch(_SIGNING_MARK_RE, t)) {
      reAll(_GETBYTES_RE, t).forEach(function (m) { var s = _clean_secret(m.groups.s); if (s) jwtSecrets.push(s); });
    }
    reAll(_JWT_SIGN_RE, t).forEach(function (m) { var s = _clean_secret(m.groups.s); if (s) jwtSecrets.push(s); });
    jwtSecrets.forEach(function (s) {
      if (seen[s]) return;
      seen[s] = true;
      _add(facts, mkFact('web.jwt_secret', scope, { secret: s, algorithm: 'HMAC', via: 'source-disclosure' }, S, source));
      _add(facts, mkFact('credential.candidate', scope, { kind: 'jwt_signing_secret', secret: s, source: 'source-disclosure' }, S, source));
    });

    // A generic SECRET_KEY assignment is app signing material — a candidate lead, not a JWT claim.
    reAll(_SECRET_KEY_RE, t).forEach(function (m) {
      var s = _clean_secret(m.groups.s);
      if (!s || seen[s]) return;
      seen[s] = true;
      _add(facts, mkFact('credential.candidate', scope, { kind: 'app_signing_secret', secret: s, source: 'source-disclosure' }, S, source));
    });

    [_CONFIG_PW_RE, _FIELD_CRED_RE, _PHP_PW_RE, _DEFINE_PW_RE, _ENV_PW_RE].forEach(function (rx) {
      reAll(rx, t).forEach(function (m) {
        var s = _clean_secret(m.groups.s);
        if (!s || seen[s]) return;
        seen[s] = true;
        _add(facts, mkFact('credential.candidate', scope, { kind: 'config_secret', password: s, key: m.groups.key.toLowerCase(), source: 'source-disclosure' }, S, source));
      });
    });

    // a VCS access token (GitHub PAT / GitLab glpat) — the token itself is the credential.
    reAll(_VCS_TOKEN_RE, t).forEach(function (m) {
      var tok = m.groups.token;
      if (seen[tok]) return;
      seen[tok] = true;
      _add(facts, mkFact('credential.candidate', scope, { kind: 'vcs_token', token: tok, source: 'source-disclosure' }, S, source));
    });

    // a credential embedded in a connection URI keeps its username too (a login lead).
    reAll(_URI_CRED_RE, t).forEach(function (m) {
      var s = _clean_secret(m.groups.s);
      if (!s || seen[s]) return;
      seen[s] = true;
      _add(facts, mkFact('credential.candidate', scope, { kind: 'connection_uri', user: m.groups.user, password: s, scheme: m.groups.scheme.toLowerCase(), host: m.groups.host, source: 'source-disclosure' }, S, source));
    });
  }
  C._parse_source_secret = _parse_source_secret;

})(typeof globalThis !== 'undefined' ? globalThis : this);
