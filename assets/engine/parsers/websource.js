/*!
 * obol engine - parsers/websource.js
 * Port of the fixture-reachable §33 web source/disclosure parsers from
 *  product-signature fingerprint and the SQLi oracle
 * (differential boolean + reflected UNION column). The remaining OSWE content-gated parsers
 * (verbose_error, source_secret, pem_key, js_framework, graphql, phpinfo, dependency_manifest,
 * git_exposed, xmlrpc, cracked_hash, weak_hashing) are intentionally NOT ported - see index.js.
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
  function _add(facts, fact) { if (C && C._add) C._add(facts, fact); else if (facts) facts.push(fact); }

  // ---- product-signature fingerprint ---- //
  var _PRODUCT_SIGS = [
    ['moodle', /(?:Powered by\s+Moodle|<meta name="keywords" content="moodle)/i, /Moodle\s+(\d+\.\d+(?:\.\d+)?)/i, 'authenticated RCE via a crafted plugin/quiz; check MoodleScan + CVEs'],
    ['gitea', /Powered by\s+Gitea/i, /Gitea\s+Version:\s*(\d+\.\d+\.\d+)/i, 'enum /explore/users + repos to review; git-hook RCE if admin'],
    ['gitbucket', /\bGitBucket\b/i, /GitBucket\s+(\d+\.\d+(?:\.\d+)?)/i, 'plugin/H2-console RCE; repo review'],
    ['gogs', /Powered by\s+Gogs/i, /Gogs\s+Version:\s*(\d+\.\d+(?:\.\d+){0,2})/i, 'enum /explore/users + repos to review; git-hook RCE if admin; Gogs CVE-2018-18925 (auth-bypass/RCE), path-traversal'],
    ['gitlab', /GitLab (?:Community|Enterprise) Edition|Powered by\s+GitLab|content=["']GitLab["']/i, /GitLab(?:\s+(?:Community|Enterprise)\s+Edition)?\s+v?(\d+\.\d+\.\d+)/i, 'check /help & /api/v4/version; user-enum via /users; ExifTool unauth RCE (CVE-2021-22205), pin the exact version for the CVE match'],
    ['zabbix', /Zabbix\s+SIA|<title>\s*Zabbix/i, /Zabbix\s+(\d+\.\d+(?:\.\d+)?)/i, 'auth bypass / SQLi CVEs; script-item RCE as Admin'],
    ['cacti', /Cacti(?:\s+Group|<)|The Cacti Group/i, /Version\s+(\d+\.\d+(?:\.\d+)?)/i, 'CVE-2022-46169 unauth RCE; SQLi chains'],
    ['apache-ofbiz', /Apache\s+OFBiz/i, /OFBiz\s+(\d+\.\d+(?:\.\d+)?)/i, 'XML-RPC deserialization (CVE-2020-9496 / groovy)'],
    ['sharepoint', /MicrosoftSharePointTeamServices|_layouts\/15\//i, /MicrosoftSharePointTeamServices:\s*(\d+\.\d+(?:\.\d+){0,2})/i, 'ToolPane/ViewState deserialization RCE'],
    ['mojoportal', /\bmojoPortal\b/i, /mojoPortal\s+(\d+\.\d+(?:\.\d+)?)/i, 'file-upload / XSS chains'],
    ['helpdeskz', /\bHelpDeskZ\b/i, /HelpDeskZ\s+v?(\d+\.\d+(?:\.\d+)?)/i, 'unauth file-upload RCE (CVE-2014-6308-class)'],
    ['phpmyadmin', /\bphpMyAdmin\b|pma_username/i, /phpMyAdmin\s+(\d+\.\d+\.\d+)/i, 'LOAD_FILE/INTO OUTFILE, SQL console, known LFI/RCE CVEs'],
    ['gophish', /\bgophish\b|X-Gophish/i, null, 'admin panel default creds; phishing infra'],
    ['jamovi', /\bjamovi\b/i, /jamovi\s+(\d+\.\d+(?:\.\d+)?)/i, 'Rj-editor / compute-module RCE'],
    ['splunk', /Splunk\s+(?:Enterprise|Inc)|\/en-US\/account\/login/i, /Splunk[^\d]{0,20}(\d+\.\d+\.\d+)/i, 'custom-app scripted-input RCE; splunk.secret -> $7$ decrypt'],
    ['powershell-web-access', /PowerShell Web Access|\/pswa\//i, null, 'gateway to any Windows host, try captured/guessed domain creds'],
  ];

  var _ANY_PRODUCT_SIG_RE = new RegExp(_PRODUCT_SIGS.map(function (r) { return '(?:' + r[1].source + ')'; }).join('|'), 'i');
  var _OUTBOUND_HTTP_REQ_RE = /^(?:[ \t]*(?:(?:\*|\{|\}|#+[ \t]*Request\b)[^\r\n]*)?\r?\n)*[ \t]*(?:>[ \t]*)?(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[ \t]+\S[^\r\n]{0,2048}?[ \t]+HTTP\/[12](?:\.\d)?\b/i;
  var _INBOUND_HTTP_RESP_LINE_RE = /^[ \t]*(?:<[ \t]*)?HTTP\/[12](?:\.\d)?[ \t]+\d{3}\b/im;
  var _OUTBOUND_HTTP_REQ_LINE_RE = /^[ \t]*(?:>[ \t]*)?(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[ \t]+\S(?:\S*[ \t]*$|[^\r\n]{0,2048}?[ \t]+HTTP\/[12](?:\.\d)?\b[ \t]*$)/im;

  function _is_outbound_http_request_only(text) {
    var tr = String(text || '').trim();
    if (!_OUTBOUND_HTTP_REQ_RE.test(tr)) return false;
    return !_INBOUND_HTTP_RESP_LINE_RE.test(tr);
  }
  C._is_outbound_http_request_only = _is_outbound_http_request_only;

  function _inbound_http_segment(text) {
    var s = String(text || '');
    var respM = _INBOUND_HTTP_RESP_LINE_RE.exec(s);
    if (respM) {
      if (respM.index === 0) return s;
      var preResp = s.slice(0, respM.index);
      if (/^[ \t]*#+[ \t]*Request\b/im.test(preResp) || _OUTBOUND_HTTP_REQ_LINE_RE.test(preResp)) {
        return s.slice(respM.index);
      }
      return s;
    }
    if (_OUTBOUND_HTTP_REQ_RE.test(s)) {
      return '';
    }
    return s;
  }
  C._inbound_http_segment = _inbound_http_segment;

  function _is_unix_account_dump(text) {
    var t = String(text || '');
    if (/^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(t) || /<(?:!doctype\s+html|html|head|body|title|meta|form)\b/i.test(t)) return false;
    return /^(?:[a-z_][a-z0-9_.-]{0,31}):(?:[^:\r\n]*):\d+:\d+:[^:\r\n]*:\/[^\s:]*:[^\r\n]*$/im.test(t)
      || /^(?:[a-z_][a-z0-9_.-]{0,31}):\$(?:1|2[abxy]|5|6|y)\$[^\s:]+:\d*:\d*:\d*:\d*:/im.test(t);
  }
  C._is_unix_account_dump = _is_unix_account_dump;

  function _is_sql_session_paste(text, ws, command) {
    if (C && C._is_sql_client_output && C._is_sql_client_output(text, ws, command)) return true;
    var t = String(text || '');
    if (/^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(t) || /<(?:!doctype\s+html|html|head|body|title|meta|form)\b/i.test(t)) return false;
    if (/\b\d+\s+rows?\s+in\s+set\b/i.test(t) && /^\s*\|\s*Database\s*\|\s*$/im.test(t)) return true;
    if (/^\s*(?:mysql|MariaDB\s*\[[^\]]*\]|postgres[-=#]*|sqlite3?|SQL(?:\s*\([^)]*\))?)\s*>/im.test(t)) return true;
    return false;
  }
  var _HTML_VER_COMMENT_RE = /<!--\s*([A-Za-z][A-Za-z0-9_.-]{2,31})\s+version\s+(\d+\.\d+(?:\.\d+){0,2})(?:\s*\[(\d+)\])?/i;
  var _HTML_VER_COMMENT_DENY_RE = /^(?:html|xhtml|xml|css|svg|doctype|template|theme|build|release|version|page|file|script|style|header|footer|jquery|bootstrap|modernizr|fontawesome)$/i;

  function _has_product_signature(text, ws, command) {
    if (!text) return false;
    var hasHtmlVer = text.indexOf('<!--') >= 0 && _HTML_VER_COMMENT_RE.test(text);
    if (!hasHtmlVer && !_ANY_PRODUCT_SIG_RE.test(text)) return false;
    if (_is_outbound_http_request_only(text) || _is_unix_account_dump(text) || _is_sql_session_paste(text, ws, command)) return false;
    if (hasHtmlVer) {
      var hm = _HTML_VER_COMMENT_RE.exec(text);
      if (hm && !_HTML_VER_COMMENT_DENY_RE.test(hm[1])) return true;
    }
    return _PRODUCT_SIGS.some(function (r) { return reSearch(r[1], text || ''); });
  }
  C._has_product_signature = _has_product_signature;

  function _parse_product_signature(text, ws, command, source, facts) {
    if (Array.isArray(source) && !facts) { facts = source; source = command; command = ''; }
    if (_is_outbound_http_request_only(text) || _is_unix_account_dump(text) || _is_sql_session_paste(text, ws, command)) return;
    var scope = _scope(ws), matchedKnown = false;
    for (var i = 0; i < _PRODUCT_SIGS.length; i++) {
      var tech = _PRODUCT_SIGS[i][0], sigRx = _PRODUCT_SIGS[i][1], verRx = _PRODUCT_SIGS[i][2], lead = _PRODUCT_SIGS[i][3];
      if (!reSearch(sigRx, text || '')) continue;
      var value = { name: tech, product: true, lead: lead };
      if (verRx) {
        var m = reSearch(verRx, text || '');
        if (m) value.version = m[1];
      }
      _add(facts, mkFact('web.tech', scope, value, S, source));
      matchedKnown = true;
      break;
    }
    if (text && text.indexOf('<!--') >= 0) {
      var hvcM = _HTML_VER_COMMENT_RE.exec(text);
      if (hvcM && !_HTML_VER_COMMENT_DENY_RE.test(hvcM[1])) {
        var hvProd = hvcM[1], hvVer = hvcM[2];
        if (!matchedKnown) {
          var hvVal = { name: hvProd.toLowerCase(), product: hvProd, version: hvVer, via: 'html-comment' };
          if (hvcM[3]) hvVal.build = hvcM[3];
          _add(facts, mkFact('web.tech', scope, hvVal, S, source));
        }
        _add(facts, mkFact('service.version', scope, { service: 'http', product: hvProd, version: hvVer, via: 'html-comment' }, S, source));
        _add(facts, mkFact('exploit.versioned_banner', scope, { product: hvProd, version: hvVer, search_query: hvProd + ' ' + hvVer, via: 'html-comment' }, S, source));
      }
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
    if (Array.isArray(source) && !facts) { facts = source; source = command; command = ''; }
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
  // verbose error). A JWT signing key -> web.jwt_secret + credential.candidate; a DB/config/framework
  // password, a VCS PAT, or a credentialed connection URI -> credential.candidate. Leads to validate.
  var _SECRET_DENY = {
    changeme: 1, change_me: 1, password: 1, secret: 1, 'your-256-bit-secret': 1, yoursecret: 1,
    xxx: 1, xxxx: 1, todo: 1, none: 1, null: 1, example: 1, placeholder: 1, redacted: 1,
    testpassword: 1, mysecretpassword: 1, yourpassword: 1, enterpassword: 1, 'p@ssw0rd': 1, passw0rd: 1
  };
  var _PLACEHOLDER_RE = /^\$\{.*\}$|^<.*>$|^%.*%$|^\$\w+$|^\{\{.*\}\}$|^\$(?:user(?:name)?|pass(?:word|wd)?|pwd|uname|login|email|hash|secret|token|input|req(?:uest)?|post|get|row|data|this|self|args?|argv|param|val(?:ue)?)(?:$|->|\[)|^\$[A-Za-z_]\w*(?:->|\[)|^['".\s]*\$[A-Za-z_]\w*['".\s]*$/i;
  var _GETBYTES_RE = /GetBytes\(\s*["'](?<s>[^"']{6,})["']/g;
  var _SIGNING_MARK_RE = /SymmetricSecurityKey|SigningCredentials|JwtSecurityToken|HmacSha\d|new HMAC|jwt\.sign/i;
  var _SECRET_KEY_RE = /\b(?:SECRET_KEY(?:_BASE)?|secret_key_base|app_secret|jwt_secret)['"]?\]?\s*[:=]\s*(?:["'](?<s>[^"'\r\n]{6,})["']|(?<uval>[0-9a-fA-F]{32,256})\b)/gi;
  var _JWT_SIGN_RE = /jwt\.sign\([^,]+,\s*["'](?<s>[^"']{6,})["']/gi;
  var _CONFIG_PW_RE = /(?<key>hibernate\.connection\.password|spring\.datasource\.password|jdbc\.password|datasource\.password|connection\.password)\s*[:=]\s*["']?(?<s>[^\s"';]{3,})/gi;
  // Field-style DB/service credential (decompiled jar / source): `sqlPass = "…"`, `dbPassword = "…"`.
  var _FIELD_CRED_RE = /\b(?<key>(?:sql|db|database|mysql|mssql|postgres|pg|jdbc|ftp|smtp|imap|redis|mongo|ldap|admin|root)_?(?:pass(?:word|wd)?|pwd))\s*=\s*["'](?<s>[^"']{3,})["']/gi;
  // A framework-config password field with a quoted literal value (PHP / WordPress define / .env).
  var _PHP_PW_RE = /(?:(?:public|private|protected|var|static)\s+)?\$(?<key>\w{0,64}(?:pass(?:word|wd)?|pwd))\s*=\s*["'](?<s>[^"']{3,})["']/gi;
  var _PHP_SUBSCRIPT_PW_RE = /\$\w{1,48}(?:\[\s*(?:['"][A-Za-z0-9_.-]{1,48}['"]|\$\w+)\s*\])*?\[\s*['"](?<key>[A-Za-z0-9_.-]{0,48}?(?:pass(?:word|wd)?|pwd|[_.-]pass))['"]\s*\]\s*=\s*["'](?<s>[^"'\r\n]{3,128})["']/gi;
  var _DEFINE_PW_RE = /define\(\s*["'](?<key>\w{0,64}(?:pass(?:word|wd)?|pwd)\w{0,64})["']\s*,\s*["'](?<s>[^"']{3,})["']/gi;
  var _ENV_PW_RE = /^\s*(?:export\s+)?(?<key>[A-Z][A-Z0-9_]*(?:PASS(?:WORD|WD)?|PWD))\s*=\s*["']?(?<s>[^\s"'#]{3,})/gm;
  // A credential embedded in a connection URI: mysql://user:pass@host, ftp://u:p@host, etc.
  var _URI_CRED_RE = /\b(?<scheme>[a-z][a-z0-9+.\-]{1,15}):\/\/(?<user>[^:/@\s]{1,64}):(?<s>[^@/\s]{3,64})@(?<host>[\w.\-]+)/gi;
  // A version-control access token, a GitHub PAT (classic gh?_ / fine-grained github_pat_) or a
  // GitLab glpat-. The token IS the credential.
  var _VCS_TOKEN_RE = /\b(?<token>gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,})\b/g;
  // A pasted PRIVATE KEY (id_rsa / .pem / .ppk-exported) is a key IN HAND -> credential.certificate, which
  // lights ssh-key-login. This is the payoff of pulling an id_rsa a share-spider flagged.
  var _PRIVKEY_RE = /-{3,5}BEGIN (?:OPENSSH|RSA|DSA|EC|PGP|ENCRYPTED(?: PRIVATE KEY)?) PRIVATE KEY-{2,5}|PuTTY-User-Key-File-\d/;
  var _REDIS_REQUIREPASS_RE = /^[ \t]*requirepass[ \t]+(?:"([^"\r\n]{3,128})"|'([^'\r\n]{3,128})'|([^\s'"#\r\n]{3,128}))[ \t]*(?:#.*)?$/gim;
  var _MONIT_HTTPD_PORT_RE = /\bset\s+httpd\s+port\s+(\d{1,5})\b/i;
  var _MONIT_ALLOW_CRED_RE = /^[ \t]*allow[ \t]+["']?([A-Za-z_][A-Za-z0-9_.-]{1,47})["']?:(?:"([^"\r\n]{3,128})"|'([^'\r\n]{3,128})'|([^\s"'#;\r\n]{3,128}))["']?(?:[ \t]+(?:readonly|read-only))?[ \t]*(?:#.*)?$/gim;
  // A password inside a DB connection string (web.config / appsettings / JDBC): "...;Password=P@ss;...".
  // The field regexes above want a quoted literal; a connection string is semicolon-delimited, so catch it
  // directly - but only in a connection-string context, so a stray "pwd=" elsewhere isn't a false positive.
  var _CONNSTR_CTX_RE = /connectionstring|connection string|data source|initial catalog|integrated security|\bserver\s*=|jdbc:|\buid\s*=/i;
  var _CONNSTR_PW_RE = /(?:password|pwd)\s*=\s*(?<s>[^;"'\s>&]{3,})/gi;
  // A bare ini/conf/yaml credential field read straight from a config file: disclosed over HTTP
  // (curl/wget of a .conf/.ini) or on-host (cat/type/Get-Content). The field regexes above want a
  // known prefix and a quoted literal; this catches the unprefixed, unquoted config field that a
  // real config dump uses: `password = "IcingaWeb2DBPassword"`, `DBPassword=bloooarskybluh`,
  // `db_pass = SampleSecret123!`, `legacyPwd = SampleEncodedPass`. Line-anchored (key at
  // line start after at most a little indentation) so prose ("the password is X") never matches.
  // Key must END in password/passwd/pwd or <word>_pass (so `bypass`, `password_hash`, `passwd_min`
  // do not match); value guarded below against SecureString/.NET type names, URLs, and binary blobs.
  var _INI_PW_RE = /^[ \t]{0,12}(?!(?:forgot|reset|change|update|lost)[_.\-]?password\b)(?:(?:const|let|var|final|export)[ \t]+)?(?<key>[\w.\-]{0,40}?(?:password|passwd|pwd|[_.]pass))[ \t]*[:=][ \t]*(?:"(?<dq>[^"\r\n]{3,64})"|'(?<sq>[^'\r\n]{3,64})'|(?![ \t]*["'])(?<s>[^\s"'#;]{3,64})(?=[ \t]*(?:[#;]|\/\/|$)))/gim;

  function _clean_secret(val) {
    val = (val || '').trim();
    if (!val || val.indexOf('\x60') >= 0 || val.indexOf('$(') >= 0) return '';
    if (_SECRET_DENY[val.toLowerCase()] || _PLACEHOLDER_RE.test(val) || /<%|%>/.test(val)) return '';
    return val;
  }
  C._clean_secret = _clean_secret;

  // A plaintext config-field value must look like a usable secret, not a type/boolean/blob or
  // unquoted client/server code expression (DOM lookup, env lookup, request param, function call).
  var _CFG_VAL_TYPE_RE = /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){2,}$/;
  var _CFG_VAL_WORD_RE = /^(?:true|false|yes|no|on|off|nil|enabled|disabled|required|optional|empty|default|unset|automatic|manual|files|compat|systemd|sss|nis|ldap|myhostname|mymachines|resolve|dns|mdns4_minimal|sufficient|requisite|include|substack|write|read|create_child|delete_child|full_control|generic_all|generic_write)$/i;
  var _CODE_EXPR_SECRET_RE = /^(?:document\.|window\.|navigator\.|location\.|localStorage\.|sessionStorage\.|form\.|this\.|self\.|process\.env\b|os\.environ\b|os\.getenv\b|System\.getenv\b|\$_(?:POST|GET|REQUEST|COOKIE|SERVER|ENV|SESSION)\b|req\.(?:body|query|params|headers|cookies)\b|request\.(?:form|args|json|values|POST|GET|DATA)\b|[A-Za-z_$][A-Za-z0-9_$.]*\s*\(|[A-Za-z_$][A-Za-z0-9_$.]*\[|[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+\.(?:value|password|passwd|pwd|pass|text|innerText|textContent)\b)/i;
  function _valid_config_pw(val) {
    if (!/^[\x21-\x7e]{3,64}$/.test(val)) return false;
    if (val.indexOf('\x60') >= 0 || val.indexOf('$(') >= 0) return false;
    if (_CFG_VAL_WORD_RE.test(val) || _CFG_VAL_TYPE_RE.test(val) || _CODE_EXPR_SECRET_RE.test(val)) return false;
    if (/^(?:\/|\.\.?\/|~\/|[A-Za-z]:\\|[a-z][a-z0-9+.\-]*:\/\/|[{[\]()}])/i.test(val)) return false;
    return true;
  }

  // A freeform labeled credential block: a plaintext leak (an exposed credentials.txt, a readme, a
  // notes file) that lists accounts as a bracketed section header followed by a bare username line
  // and a bare password line, with no key=value delimiter for the field extractors above to catch.
  // Example (`/admin-dir/credentials.txt`):
  //   [Internal mail account]
  //   j.bloggs@acme.internal
  //   SampleSecret#2026!
  // The bracketed header must name a credential (account/login/credential/creds/password); the next
  // two non-empty lines are read as username then password, each shape-validated, so a bracketed
  // section that is not a credential list ([INFO], [options]) with two prose lines under it never
  // mints. House style: no em or en dashes.
  var _CREDHDR_RE = /^[ \t]*\[[^\]\n]{1,60}\][ \t]*$/;
  var _CREDHDR_WORD_RE = /\b(?:accounts?|credentials?|creds|logins?|passwords?)\b/i;
  var _CREDHDR_FAST_RE = /\[[^\]\r\n]{0,60}\b(?:accounts?|credentials?|creds|logins?|passwords?)\b/i;
  var _LEAK_USER_RE = /^[A-Za-z0-9][\w.@+\-]{0,63}$/;
  function _labeled_cred_pairs(text) {
    if (!text || text.indexOf('[') < 0 || !_CREDHDR_FAST_RE.test(text)) return [];
    var lines = (text || '').split(/\r?\n/), pairs = [], i = 0;
    while (i < lines.length) {
      var h = lines[i];
      if (!_CREDHDR_RE.test(h) || !_CREDHDR_WORD_RE.test(h)) { i++; continue; }
      var j = i + 1;
      while (j < lines.length && !lines[j].trim()) j++;         // skip blank lines after the header
      var run = [];
      while (j < lines.length && lines[j].trim() && !_CREDHDR_RE.test(lines[j]) && run.length < 10) { run.push(lines[j].trim()); j++; }
      if ((run.length === 2 || run.length === 3) && _LEAK_USER_RE.test(run[0])) {
        var s = _clean_secret(run[1]);
        if (s && _valid_config_pw(s)) pairs.push({ label: h.replace(/^[ \t]*\[|\][ \t]*$/g, '').trim(), user: run[0], password: s });
      }
      i = j > i ? j : i + 1;
    }
    return pairs;
  }
  function _has_labeled_creds(text) { return _labeled_cred_pairs(text).length > 0; }
  C._has_labeled_creds = _has_labeled_creds;

  var _ASSOC_ARRAY_SECRET_HINT_RE = /['"](?:[A-Za-z0-9_.-]+_)?(?:pass(?:word|wd)?|pwd|dbpass|secret|api[_-]?key|token)['"]\s*=>\s*['"][^'"\r\n]{1,128}['"]/i;
  var _XML_ATTR_SECRET_HINT_RE = /<(?:[A-Za-z0-9_.-]+:)?(?:param|property|add|setting|item|entry|var|option|user|account|login|member|admin|server|resource)\b[^>\r\n]{0,1024}?\b(?:(?:name|key|id)\s*=\s*["'][^"'\r\n]{0,128}(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token)["']|(?:password|passwd|pwd|secret)\s*=\s*["'][^"'\r\n]{1,256}["'])[^>\r\n]{0,1024}\/?>/i;
  var _DB_CONNECTOR_HINT_RE = /\b(?:mysqli_connect|new\s+mysqli|new\s+PDO|pg_p?connect|SqlConnection|DriverManager\.getConnection)\b|\.(?:put|setProperty)\s*\(\s*"(?:password|pass|pwd)"|\bjdbc:(?:mysql|mariadb|postgresql|sqlserver|oracle|h2|sqlite):|\bspring\.datasource\.(?:username|password|url)\b|^\s*datasource:\s*\r?\n[\s\S]{1,240}?\busername:\s*\S+|define\s*\(\s*['"](?:(?:DB|MYSQL|PG|MSSQL|SQL)_?[A-Z0-9_]*USER(?:NAME)?|[A-Z0-9_]*(?:DB|MYSQL|PG|MSSQL|SQL)_?USER(?:NAME)?)['"]|\$(?:db|database|mysql|pg|postgres|mssql|sql)_?(?:user(?:name)?|pass(?:word|wd)?|pwd)\s*=|\$\w{1,48}(?:\[[^\]]+\])*?\[\s*['"](?:(?:db|database|mysql|pg|postgres|mssql|sql)_?)?(?:user(?:name)?|pass(?:word|wd)?|pwd)['"]\s*\]\s*=|(?:User\s*Id|UID)\s*=[^\r\n;]+;[^\r\n]*(?:Password|PWD)\s*=|(?:Password|PWD)\s*=[^\r\n;]+;[^\r\n]*(?:User\s*Id|UID)\s*=|['"](?:db(?:name|_name|_user|_pass)?|database)['"]\s*=>/im;

  function _has_source_secret(text) {
    var t = text || '';
    if (!t) return false;
    var hasEq = t.indexOf('=') >= 0;
    var hasColon = t.indexOf(':') >= 0;
    var hasEqOrColon = hasEq || hasColon;
    var hasDollar = t.indexOf('$') >= 0;
    var hasParen = t.indexOf('(') >= 0;
    var hasProto = hasColon && t.indexOf('://') >= 0;
    var hasVcsHint = t.indexOf('gh') >= 0 || t.indexOf('github_pat_') >= 0 || t.indexOf('glpat-') >= 0;
    var hasPrivKeyHint = t.indexOf('PRIVATE KEY--') >= 0 || t.indexOf('PuTTY-User-Key-File-') >= 0;
    var hasArrow = hasEq && t.indexOf('=>') >= 0;
    var hasXmlTag = t.indexOf('<') >= 0 && t.indexOf('>') >= 0;
    var hasDbHint = hasArrow || hasDollar || t.indexOf('connect') >= 0 || t.indexOf('Connect') >= 0 || t.indexOf('PDO') >= 0
      || t.indexOf('jdbc:') >= 0 || t.indexOf('spring.datasource') >= 0 || t.indexOf('datasource:') >= 0
      || t.indexOf('DB') >= 0 || t.indexOf('MYSQL') >= 0 || t.indexOf('setProperty') >= 0 || t.indexOf('.put(') >= 0
      || (t.indexOf(';') >= 0 && (t.indexOf('Password') >= 0 || t.indexOf('password') >= 0 || t.indexOf('PWD') >= 0));
    var pemHintText = hasPrivKeyHint && /<\?php\b|<(?:!doctype|html|script|!--)/i.test(t)
      ? t.replace(/<!--[\s\S]*?-->/g, '').replace(/\/\*[\s\S]*?\*\//g, '')
      : t;
    return !!((hasPrivKeyHint && reSearch(_PRIVKEY_RE, pemHintText))
      || (hasVcsHint && reSearch(_VCS_TOKEN_RE, t))
      || (hasProto && reSearch(_URI_CRED_RE, t))
      || (t.indexOf('requirepass') >= 0 && reSearch(_REDIS_REQUIREPASS_RE, t))
      || ((_MONIT_HTTPD_PORT_RE.test(t) || /\bcheck\s+process\b|\bset\s+daemon\b/i.test(t)) && (reSearch(_MONIT_ALLOW_CRED_RE, t) || _MONIT_HTTPD_PORT_RE.test(t)))
      || (hasXmlTag && t.indexOf('<bind-dn>') >= 0 && t.indexOf('<bind-password>') >= 0)
      || reSearch(_SIGNING_MARK_RE, t)
      || (hasEqOrColon && reSearch(_SECRET_KEY_RE, t))
      || (hasEqOrColon && reSearch(_CONFIG_PW_RE, t))
      || (hasEq && reSearch(_FIELD_CRED_RE, t))
      || (hasDollar && hasEq && (reSearch(_PHP_PW_RE, t) || (t.indexOf('[') >= 0 && reSearch(_PHP_SUBSCRIPT_PW_RE, t))))
      || (hasParen && reSearch(_DEFINE_PW_RE, t))
      || (hasEq && reSearch(_ENV_PW_RE, t))
      || (hasEqOrColon && reSearch(_INI_PW_RE, t))
      || (hasArrow && reSearch(_ASSOC_ARRAY_SECRET_HINT_RE, t))
      || (hasXmlTag && reSearch(_XML_ATTR_SECRET_HINT_RE, t))
      || (hasDbHint && reSearch(_DB_CONNECTOR_HINT_RE, t))
      || _has_labeled_creds(t)
      || (hasEq && reSearch(_CONNSTR_CTX_RE, t) && reSearch(_CONNSTR_PW_RE, t)));
  }
  C._has_source_secret = _has_source_secret;

  function _parse_source_secret(text, ws, command, source, facts) {
    if (C._is_public_reference_http_cmd && C._is_public_reference_http_cmd(command, ws)) return;
    var t = text || '', scope = _scope(ws), seen = {};
    if (!t) return;
    var hasEq = t.indexOf('=') >= 0;
    var hasColon = t.indexOf(':') >= 0;
    var hasEqOrColon = hasEq || hasColon;
    var hasDollar = t.indexOf('$') >= 0;
    var hasParen = t.indexOf('(') >= 0;
    var hasProto = hasColon && t.indexOf('://') >= 0;
    var hasVcsHint = t.indexOf('gh') >= 0 || t.indexOf('github_pat_') >= 0 || t.indexOf('glpat-') >= 0;
    var hasPrivKeyHint = t.indexOf('PRIVATE KEY--') >= 0 || t.indexOf('PuTTY-User-Key-File-') >= 0;

    if (C && C._extract_diff_cred_pairs && (t.indexOf('\n+') >= 0 || t.indexOf('\n-') >= 0 || t.charAt(0) === '+' || t.charAt(0) === '-')) {
      var diffPairs = C._extract_diff_cred_pairs(t);
      diffPairs.forEach(function (pair) {
        var pairKey = 'diff:' + pair.user + ':' + pair.password;
        if (seen[pairKey]) return;
        seen[pairKey] = true;
        seen[pair.password] = true;
        var credVal = { user: pair.user, password: pair.password, method: 'git-diff' };
        if (pair.file) credVal.file = pair.file;
        _add(facts, mkFact('credential.plaintext', scope, credVal, S, source));
        _add(facts, mkFact('credential.password', scope, credVal, S, source));
        _add(facts, mkFact('credential.available', scope, credVal, S, source));
        _add(facts, mkFact('credential.candidate', scope, { kind: 'git_diff_credential', user: pair.user, password: pair.password, file: pair.file || undefined, via: 'git-diff' }, S, source));
        if (pair.isDb) {
          _add(facts, mkFact('db.creds', scope, { user: pair.user, password: pair.password, file: pair.file || undefined, via: 'git-diff' }, S, source));
        }
      });
    }

    // JWT-specific idioms → web.jwt_secret (a *JWT* signing secret).
    var jwtSecrets = [];
    if (reSearch(_SIGNING_MARK_RE, t)) {
      if (hasParen) reAll(_GETBYTES_RE, t).forEach(function (m) { var s = _clean_secret(m.groups.s); if (s) jwtSecrets.push(s); });
    }
    if (hasParen) reAll(_JWT_SIGN_RE, t).forEach(function (m) { var s = _clean_secret(m.groups.s); if (s) jwtSecrets.push(s); });
    jwtSecrets.forEach(function (s) {
      if (seen[s]) return;
      seen[s] = true;
      _add(facts, mkFact('web.jwt_secret', scope, { secret: s, algorithm: 'HMAC', via: 'source-disclosure' }, S, source));
      _add(facts, mkFact('credential.candidate', scope, { kind: 'jwt_signing_secret', secret: s, source: 'source-disclosure' }, S, source));
    });

    // A generic SECRET_KEY assignment is app signing material, a candidate lead, not a JWT claim.
    if (hasEqOrColon && /secret/i.test(t)) {
      reAll(_SECRET_KEY_RE, t).forEach(function (m) {
        var rawS = (m.groups && (m.groups.s || m.groups.uval)) || '';
        var s = _clean_secret(rawS);
        if (!s || seen[s]) return;
        seen[s] = true;
        _add(facts, mkFact('credential.candidate', scope, { kind: 'app_signing_secret', secret: s, source: 'source-disclosure' }, S, source));
        if (/\bsecret_key_base\b/i.test(m[0]) || (m.groups && m.groups.uval)) {
          var sdVal = { kind: 'config_file' };
          if (/\bsecret_key_base\b/i.test(m[0])) sdVal.framework = 'rails';
          _add(facts, mkFact('web.source_disclosed', scope, sdVal, S, source));
        }
      });
    }

    var pwRxList = [];
    if (hasEqOrColon) pwRxList.push(_CONFIG_PW_RE);
    if (hasEq) pwRxList.push(_FIELD_CRED_RE);
    if (hasDollar && hasEq) {
      pwRxList.push(_PHP_PW_RE);
      if (t.indexOf('[') >= 0) pwRxList.push(_PHP_SUBSCRIPT_PW_RE);
    }
    if (hasParen) pwRxList.push(_DEFINE_PW_RE);
    if (hasEq) pwRxList.push(_ENV_PW_RE);
    pwRxList.forEach(function (rx) {
      reAll(rx, t).forEach(function (m) {
        var s = _clean_secret(m.groups.s);
        if (!s || seen[s] || _CODE_EXPR_SECRET_RE.test(s)) return;
        if ((rx === _CONFIG_PW_RE || rx === _ENV_PW_RE) && !/["']/.test(m[0]) && s.slice(-1) === ':') return;
        seen[s] = true;
        _add(facts, mkFact('credential.candidate', scope, { kind: 'config_secret', password: s, key: m.groups.key.toLowerCase(), source: 'source-disclosure' }, S, source));
      });
    });

    // a freeform labeled credential block (plaintext leak: bracket header + bare user + bare pass),
    // the shape an exposed credentials.txt uses where there is no key=value delimiter to key on.
    _labeled_cred_pairs(t).forEach(function (p) {
      if (seen[p.password]) return;
      seen[p.password] = true;
      _add(facts, mkFact('credential.candidate', scope, { kind: 'labeled_leak', user: p.user, password: p.password, label: p.label, source: 'labeled-leak' }, S, source));
    });

    // a bare ini/conf credential field (unprefixed/unquoted), read from a config file over HTTP or
    // on-host. Same config_secret lead as above, but with the extra value guards (no SecureString,
    // no binary blob, no boolean) the looser line-anchored shape needs. Guard against interactive
    // CLI authentication prompt echoes ("Password: <typed>") in su/sudo/ssh/impacket/auth failures.
    if (hasEqOrColon) {
      var isInteractiveAuthCli = /^\s*(?:sudo\s+)?(?:su|sudo|ssh|kinit|smbclient|rpcclient|psql|mysql|mssqlclient|impacket-[\w-]+|GetNPUsers(?:\.py)?|GetUserSPNs(?:\.py)?|secretsdump(?:\.py)?|psexec(?:\.py)?|wmiexec(?:\.py)?|smbexec(?:\.py)?|atexec(?:\.py)?|dcomexec(?:\.py)?)\b/i.test(command || '')
        || /(?:su:\s*Authentication failure|Sorry,\s*try again|Login incorrect|Cannot authenticate\b|doesn't have UF_DONT_REQUIRE_PREAUTH set|KDC_ERR_PREAUTH_FAILED|Permission denied\s*\(|STATUS_LOGON_FAILURE)/i.test(t);
      reAll(_INI_PW_RE, t).forEach(function (m) {
        if (isInteractiveAuthCli && /^[ \t]*(?:Enter[ \t]+)?Password[ \t]*:/i.test(m[0])) return;
        if (!m.groups.dq && !m.groups.sq && m.groups.s && m.groups.s.slice(-1) === ':') return;
        var evLine = C._line_for_match ? C._line_for_match(t, m) : m[0];
        var rawIniVal = m.groups.dq || m.groups.sq || m.groups.s || '';
        if (rawIniVal.indexOf('$') >= 0 && /\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|WHERE\s+)/i.test(evLine)) return;
        if (!m.groups.dq && !m.groups.sq && /^[0-9a-fA-F]{32}$/.test(rawIniVal) && /\[Administrator\]\s*\r?\n\s*Password=/i.test(t)) return;
        var s = _clean_secret(rawIniVal);
        if (!s || seen[s] || !_valid_config_pw(s)) return;
        seen[s] = true;
        _add(facts, mkFact('credential.candidate', scope, { kind: 'config_secret', password: s, key: m.groups.key.toLowerCase(), source: 'config-field' }, S, source));
      });
    }

    // a VCS access token (GitHub PAT / GitLab glpat), the token itself is the credential.
    if (hasVcsHint) {
      reAll(_VCS_TOKEN_RE, t).forEach(function (m) {
        var tok = m.groups.token;
        if (seen[tok]) return;
        seen[tok] = true;
        _add(facts, mkFact('credential.candidate', scope, { kind: 'vcs_token', token: tok, source: 'source-disclosure' }, S, source));
      });
    }

    // a pasted private key is a key in hand → credential.certificate (lights ssh-key-login).
    var pemText = hasPrivKeyHint && /<\?php\b|<(?:!doctype|html|script|!--)/i.test(t)
      ? t.replace(/<!--[\s\S]*?-->/g, '').replace(/\/\*[\s\S]*?\*\//g, '')
      : t;
    if (hasPrivKeyHint && reSearch(_PRIVKEY_RE, pemText)) {
      var isEncKey = /ENCRYPTED|Proc-Type:\s*4\s*,\s*ENCRYPTED|DEK-Info:/i.test(pemText)
        || /\bb3BlbnNzaC1rZXktdjEAAAAA(?!BG5vbmU)[A-Za-z0-9+/]{4}/.test(pemText);
      var isX509CertPair = /-{3,5}BEGIN CERTIFICATE-{2,5}|\b(?:Certify|certipy|pkcs12|x509|Certificate\s+Template)\b/i.test(pemText)
        && !/-{3,5}BEGIN OPENSSH PRIVATE KEY-{2,5}|PuTTY-User-Key-File-\d/.test(pemText);
      _add(facts, mkFact('credential.certificate', scope, { kind: isX509CertPair ? 'x509_keypair' : 'private_key', encrypted: isEncKey, source: 'source-disclosure' }, S, source));
      if (!/-{3,5}BEGIN PGP PRIVATE KEY-{2,5}/.test(pemText) && !isX509CertPair) {
        _add(facts, mkFact('loot.ssh_key', scope, { encrypted: isEncKey, via: 'source-disclosure' }, S, source));
        _add(facts, mkFact('credential.ssh_key', scope, { encrypted: isEncKey, via: 'source-disclosure' }, S, source));
      }
      if (isEncKey && !isX509CertPair) {
        _add(facts, mkFact('hash.crackable', scope, { format: 'ssh', hash_type: 'ssh', tool: 'ssh2john', via: 'source-disclosure' }, S, source));
        _add(facts, mkFact('hash.candidate', scope, { format: 'ssh', hash_type: 'ssh', tool: 'ssh2john', via: 'source-disclosure' }, S, source));
      }
    }

    // Redis requirepass directive in redis.conf
    if (t.indexOf('requirepass') >= 0) {
      reAll(_REDIS_REQUIREPASS_RE, t).forEach(function (m) {
        var rp = _clean_secret(m[1] || m[2] || m[3] || '');
        if (!rp || !_valid_config_pw(rp)) return;
        var rpKey = 'redis:' + rp;
        if (seen[rpKey]) return;
        seen[rpKey] = true;
        seen[rp] = true;
        var rVal = { user: 'default', password: rp, service: 'redis', method: 'redis-conf' };
        _add(facts, mkFact('credential.plaintext', scope, rVal, S, source));
        _add(facts, mkFact('credential.password', scope, rVal, S, source));
        _add(facts, mkFact('credential.available', scope, rVal, S, source));
        _add(facts, mkFact('db.creds', scope, { user: 'default', password: rp, service: 'redis', via: 'redis-conf' }, S, source));
        _add(facts, mkFact('credential.candidate', scope, { kind: 'redis_requirepass', password: rp, service: 'redis', source: 'redis-conf' }, S, source));
      });
    }

    // Monit control file (set httpd port <N> + allow <user>:<password>)
    var monitPortM = _MONIT_HTTPD_PORT_RE.exec(t);
    var isMonitCtx = !!monitPortM || /\bmonitrc\b/i.test(command || '') || (/\bcheck\s+process\b/i.test(t) && /\bset\s+daemon\b/i.test(t));
    if (isMonitCtx) {
      var mPort = monitPortM ? parseInt(monitPortM[1], 10) : 0;
      if (mPort > 0 && mPort <= 65535) {
        _add(facts, mkFact('scan.local.listeners', scope, {
          ports: [mPort],
          listeners: [{ addr: '127.0.0.1', port: mPort, proto: 'tcp', service: 'monit' }],
          via: 'monitrc'
        }, S, source));
      }
      reAll(_MONIT_ALLOW_CRED_RE, t).forEach(function (m) {
        var mu = m[1].trim(), mp = _clean_secret(m[2] || m[3] || m[4] || '');
        if (!mu || !mp || !_valid_config_pw(mp) || /^(?:localhost|\d+)$/i.test(mu)) return;
        var mKey = 'monit:' + mu + ':' + mp;
        if (seen[mKey]) return;
        seen[mKey] = true;
        seen[mp] = true;
        var mVal = { user: mu, password: mp, service: 'monit', method: 'monitrc' };
        if (mPort > 0) mVal.port = mPort;
        _add(facts, mkFact('credential.plaintext', scope, mVal, S, source));
        _add(facts, mkFact('credential.password', scope, mVal, S, source));
        _add(facts, mkFact('credential.available', scope, mVal, S, source));
        _add(facts, mkFact('credential.candidate', scope, { kind: 'monit_httpd_credential', user: mu, password: mp, service: 'monit', port: mPort || undefined, source: 'monitrc' }, S, source));
      });
    }

    // XML LDAP <bind-dn> + <bind-password> configuration read on-host or via source disclosure
    if (t.indexOf('<bind-dn>') >= 0 && t.indexOf('<bind-password>') >= 0 && C._parse_xml_ldap_bind_creds) {
      C._parse_xml_ldap_bind_creds(t, ws, source, facts);
    }

    // a password inside a DB connection string (only in a connection-string context).
    if (hasEq && reSearch(_CONNSTR_CTX_RE, t)) {
      reAll(_CONNSTR_PW_RE, t).forEach(function (m) {
        var s = _clean_secret(m.groups.s);
        if (!s || seen[s]) return;
        seen[s] = true;
        _add(facts, mkFact('credential.candidate', scope, { kind: 'connection_string', password: s, source: 'source-disclosure' }, S, source));
      });
    }

    // a credential embedded in a connection URI keeps its username too (a login lead).
    if (hasProto) {
      reAll(_URI_CRED_RE, t).forEach(function (m) {
        var s = _clean_secret(m.groups.s);
        if (!s || seen[s]) return;
        seen[s] = true;
        var u = (m.groups.user || '').trim();
        var sch = m.groups.scheme.toLowerCase();
        _add(facts, mkFact('credential.candidate', scope, { kind: 'connection_uri', user: u, password: s, scheme: sch, host: m.groups.host, source: 'source-disclosure' }, S, source));
        if (u && !_SECRET_DENY[u.toLowerCase()] && !_PLACEHOLDER_RE.test(u) && /^(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|mssql|sqlserver|redis|amqp|ftp|ssh)$/.test(sch)) {
          _add(facts, mkFact('credential.available', scope, { user: u, password: s, service: sch, host: m.groups.host, method: 'source-dsn' }, S, source));
        }
      });
    }

    // Quoted PHP/Ruby associative-array ('user' => '...', 'password' => '...') credentials & secrets
    if (t.indexOf('=>') >= 0) _parse_assoc_array_secrets(t, scope, source, facts, seen);

    // Self-closing XML attribute (<param name="password" value="..."/>) credentials & secrets
    if (t.indexOf('<') >= 0 && t.indexOf('>') >= 0) _parse_xml_attr_secrets(t, scope, source, facts, seen);

    // Hardcoded DB connector calls and full User+Password DSN strings in disclosed source
    if (t.indexOf('=>') >= 0 || hasDollar || t.indexOf('connect') >= 0 || t.indexOf('Connect') >= 0 || t.indexOf('PDO') >= 0
        || t.indexOf('jdbc:') >= 0 || t.indexOf('spring.datasource') >= 0 || t.indexOf('datasource:') >= 0
        || t.indexOf('DB') >= 0 || t.indexOf('MYSQL') >= 0 || t.indexOf('setProperty') >= 0 || t.indexOf('.put(') >= 0
        || t.indexOf('Password') >= 0 || t.indexOf('password') >= 0 || t.indexOf('PWD') >= 0 || t.indexOf('PASS') >= 0) {
      _parse_source_db_connectors(t, scope, source, facts, seen);
    }
  }
  C._parse_source_secret = _parse_source_secret;

  function _valid_assoc_or_xml_secret(rawVal, minLen) {
    var s = _clean_secret(rawVal);
    if (!s || s.length < (minLen || 3) || s.length > 128) return '';
    if (!/^[\x21-\x7e]+$/.test(s)) return '';
    if (/^(?:\$[A-Za-z_{]|ENV\[|AQAAANCMnd8BFdER)/.test(s)) return '';
    if (_CFG_VAL_WORD_RE.test(s) || _CFG_VAL_TYPE_RE.test(s) || _CODE_EXPR_SECRET_RE.test(s)) return '';
    if (/^(?:\/|\.\.?\/|~\/|[A-Za-z]:\\|[a-z][a-z0-9+.\-]*:\/\/|[{[\]()}])/i.test(s)) return '';
    return s;
  }

  function _valid_assoc_or_xml_user(rawUser) {
    var u = String(rawUser || '').trim();
    if (!u || u.length < 2 || u.length > 64) return '';
    if (/^(?:\$[A-Za-z_{]|ENV\[)/.test(u)) return '';
    if (_SECRET_DENY[u.toLowerCase()] || _PLACEHOLDER_RE.test(u)) return '';
    if (/^(?:user|username|dbuser|db_user|your_user|login|account|null|none|true|false|empty)$/i.test(u)) return '';
    if (!/^[A-Za-z0-9_.@+\-$\\]+$/.test(u)) return '';
    return u;
  }

  function _parse_assoc_array_secrets(text, scope, source, facts, seen) {
    var t = String(text || '');
    if (t.indexOf('=>') < 0) return;
    var lines = t.split(/\r?\n/);
    var users = [], secrets = [];
    var pairRe = /['"]([A-Za-z0-9_.-]{1,48})['"]\s*=>\s*['"]([^'"\r\n]{1,128})['"]/g;
    var userKeyRe = /^(?:(?:[A-Za-z0-9_.-]+_)?(?:user(?:name)?|login|uname)|dbuser|db_user)$/i;
    var secKeyRe = /^(?:(?:[A-Za-z0-9_.-]+_)?(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token)|dbpass|db_pass|apikey)$/i;
    var secKeyDenyRe = /(?:policy|reset|forgot|change|update|min|max|age|len|expir|prompt|file|path|url|uri|algo)/i;

    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (!ln || ln.indexOf('=>') < 0 || ln.length > 2048) continue;
      pairRe.lastIndex = 0;
      var m;
      while ((m = pairRe.exec(ln)) !== null) {
        var k = m[1], v = m[2];
        if (userKeyRe.test(k)) {
          var vu = _valid_assoc_or_xml_user(v);
          if (vu) users.push({ line: i, key: k, user: vu });
        } else if (secKeyRe.test(k) && !secKeyDenyRe.test(k)) {
          var vs = _valid_assoc_or_xml_secret(v, 3);
          if (vs) secrets.push({ line: i, key: k, secret: vs });
        }
      }
    }
    if (!secrets.length) return;

    var dbWindowRe = /(?:['"](?:db(?:name|_name)?|database|host|driver|type|port|charset|dsn|adapter)['"]\s*=>|\b(?:mysql|mariadb|pgsql|postgres|postgresql|mssql|sqlsrv|sqlite|pdo|database|db_config|dbconfig|db_conn)\b)/i;
    for (var si = 0; si < secrets.length; si++) {
      var secItem = secrets[si];
      var bestUser = null, bestDist = 999;
      for (var ui = 0; ui < users.length; ui++) {
        var dist = Math.abs(users[ui].line - secItem.line);
        if (dist <= 12 && dist < bestDist) {
          bestDist = dist;
          bestUser = users[ui];
        }
      }
      if (bestUser) {
        var lo = Math.max(0, Math.min(bestUser.line, secItem.line) - 6);
        var hi = Math.min(lines.length - 1, Math.max(bestUser.line, secItem.line) + 6);
        var winStr = lines.slice(lo, hi + 1).join('\n');
        var isDb = dbWindowRe.test(winStr) || /^db/i.test(bestUser.key) || /^db/i.test(secItem.key);
        var svc = /\b(?:pgsql|postgres|postgresql)\b/i.test(winStr) ? 'postgres'
          : (/\b(?:mssql|sqlsrv|sqlserver)\b/i.test(winStr) ? 'mssql'
          : (/\bsqlite\b/i.test(winStr) ? 'sqlite' : (isDb ? 'mysql' : 'app')));
        if (isDb) {
          var dbNameM = /['"](?:db(?:name|_name)?|database)['"]\s*=>\s*['"]([^'"\r\n]{1,96})['"]/i.exec(winStr);
          var hostM = /['"]host['"]\s*=>\s*['"]([^'"\r\n]{1,96})['"]/i.exec(winStr);
          var extra = {};
          if (dbNameM) extra.dbname = dbNameM[1].trim();
          if (hostM) extra.host = hostM[1].trim();
          _emitConcreteSourceCred(facts, scope, source, seen, bestUser.user, secItem.secret, svc, 'assoc-array', true, extra);
        } else {
          var pairKey = 'pair:' + bestUser.user + ':' + secItem.secret;
          if (!seen[pairKey]) {
            seen[pairKey] = true;
            var pVal = { user: bestUser.user, password: secItem.secret, secret_type: 'plaintext', method: 'assoc-array' };
            _add(facts, mkFact('credential.plaintext', scope, pVal, S, source));
            _add(facts, mkFact('credential.available', scope, pVal, S, source));
          }
          if (!seen[secItem.secret]) {
            seen[secItem.secret] = true;
            _add(facts, mkFact('credential.candidate', scope, { kind: 'config_secret', user: bestUser.user, password: secItem.secret, key: secItem.key.toLowerCase(), source: 'assoc-array' }, S, source));
          }
        }
      } else if (secItem.secret.length >= 4 && !seen[secItem.secret]) {
        seen[secItem.secret] = true;
        var kLow = secItem.key.toLowerCase();
        _add(facts, mkFact('credential.candidate', scope, { kind: 'config_secret', password: secItem.secret, key: kLow, source: 'assoc-array' }, S, source));
        _add(facts, mkFact('credential.password', scope, { password: secItem.secret, key: kLow, via: 'assoc-array' }, S, source));
      }
    }
  }

  function _parse_xml_attr_secrets(text, scope, source, facts, seen) {
    var t = String(text || '');
    if (t.indexOf('<') < 0 || t.indexOf('>') < 0 || !_XML_ATTR_SECRET_HINT_RE.test(t)) return;
    if (/<encryptionMethod>\s*(?!None\b|ClearText\b|Plain(?:text)?\b|False\b|0\b)[A-Za-z0-9_.-]+/i.test(t)) return;
    var lines = t.split(/\r?\n/);
    var tagRe = /<(?:[A-Za-z0-9_.-]+:)?(?:param|property|add|setting|item|entry|var|option|user|account|login|member|admin|server|resource)\b([^>\r\n]*)\/?>/gi;
    var userKeyRe = /^(?:(?:[A-Za-z0-9_.-]+[_.-])?(?:user(?:name)?|login|account|uid)|dbuser)$/i;
    var secKeyRe = /^(?:(?:[A-Za-z0-9_.-]+[_.-])?(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token)|dbpass|apikey)$/i;
    var secKeyDenyRe = /(?:policy|reset|forgot|change|update|min|max|age|len|expir|prompt|file|path|url|uri|algo)/i;
    var xmlUsers = [], xmlSecrets = [];

    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (!ln || ln.indexOf('<') < 0 || ln.length > 2048) continue;
      tagRe.lastIndex = 0;
      var tm;
      while ((tm = tagRe.exec(ln)) !== null) {
        var attrs = tm[1] || '';
        if (/\bstoreAsClearText\s*=\s*["']?false["']?/i.test(attrs) || /\bencrypted\s*=\s*["']?(?:true|1)["']?/i.test(attrs)) continue;
        var directUserM = /\b(?:user(?:name)?|login|uid)\s*=\s*["']([^"'\r\n]+)["']/i.exec(attrs);
        var directSecM = /\b(password|passwd|pwd|secret)\s*=\s*["']([^"'\r\n]+)["']/i.exec(attrs);
        if (directUserM) {
          var du = _valid_assoc_or_xml_user(directUserM[1]);
          if (du) xmlUsers.push({ line: i, user: du });
        }
        if (directSecM) {
          var ds = _valid_assoc_or_xml_secret(directSecM[2], 3);
          if (ds) xmlSecrets.push({ line: i, key: directSecM[1].toLowerCase(), secret: ds });
          continue;
        }
        var nameM = /\b(?:name|key|id)\s*=\s*["']([^"'\r\n]+)["']/i.exec(attrs);
        var valM = /\bvalue\s*=\s*["']([^"'\r\n]+)["']/i.exec(attrs);
        if (!nameM || !valM) continue;
        var attrName = nameM[1].trim(), attrVal = valM[1];
        if (userKeyRe.test(attrName)) {
          var xu = _valid_assoc_or_xml_user(attrVal);
          if (xu) xmlUsers.push({ line: i, user: xu });
        } else if (secKeyRe.test(attrName) && !secKeyDenyRe.test(attrName)) {
          var xs = _valid_assoc_or_xml_secret(attrVal, 3);
          if (xs) xmlSecrets.push({ line: i, key: attrName.toLowerCase(), secret: xs });
        }
      }
    }

    for (var xsi = 0; xsi < xmlSecrets.length; xsi++) {
      var xSec = xmlSecrets[xsi];
      var bestXmlUser = null, bestXmlDist = 999;
      for (var xui = 0; xui < xmlUsers.length; xui++) {
        var xDist = Math.abs(xmlUsers[xui].line - xSec.line);
        if (xDist <= 12 && xDist < bestXmlDist) {
          bestXmlDist = xDist;
          bestXmlUser = xmlUsers[xui];
        }
      }
      if (bestXmlUser) {
        var xPairKey = 'pair:' + bestXmlUser.user + ':' + xSec.secret;
        if (!seen[xPairKey]) {
          seen[xPairKey] = true;
          var xpVal = { user: bestXmlUser.user, password: xSec.secret, secret_type: 'plaintext', method: 'xml-attribute' };
          _add(facts, mkFact('credential.plaintext', scope, xpVal, S, source));
          _add(facts, mkFact('credential.password', scope, xpVal, S, source));
          _add(facts, mkFact('credential.available', scope, xpVal, S, source));
        }
        if (!seen[xSec.secret]) {
          seen[xSec.secret] = true;
          _add(facts, mkFact('credential.candidate', scope, { kind: 'config_secret', user: bestXmlUser.user, password: xSec.secret, key: xSec.key, source: 'xml-attribute' }, S, source));
        }
      } else if (!seen[xSec.secret]) {
        seen[xSec.secret] = true;
        _add(facts, mkFact('credential.candidate', scope, { kind: 'config_secret', password: xSec.secret, key: xSec.key, source: 'xml-attribute' }, S, source));
        _add(facts, mkFact('credential.password', scope, { password: xSec.secret, key: xSec.key, via: 'xml-attribute' }, S, source));
      }
    }
  }

  function _resolvePhpVars(text) {
    var vars = {};
    var assignRe = /\$([A-Za-z_][A-Za-z0-9_]{0,48})\s*=\s*["']([^"'\r\n]{1,96})["']\s*;/g;
    reAll(assignRe, text).forEach(function (m) {
      vars[m[1]] = m[2];
    });
    return vars;
  }

  function _resolveArgToken(tok, phpVars) {
    var s = String(tok || '').trim();
    if (!s) return '';
    if ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'")) {
      return s.slice(1, -1).trim();
    }
    if (s[0] === '$' && phpVars && phpVars[s.slice(1)]) {
      return phpVars[s.slice(1)].trim();
    }
    return '';
  }

  function _emitConcreteSourceCred(facts, scope, source, seen, user, pw, service, idiom, emitDbCreds, extra) {
    var u = String(user || '').trim();
    var p = _clean_secret(pw);
    if (!u || !p || !_valid_config_pw(p)) return;
    if (_SECRET_DENY[u.toLowerCase()] || _PLACEHOLDER_RE.test(u) || /^(?:user|username|dbuser|db_user|your_user)$/i.test(u)) return;
    var pairKey = 'pair:' + u + ':' + p;
    if (seen[pairKey]) return;
    seen[pairKey] = true;
    var avVal = { user: u, password: p, service: service, method: idiom };
    if (extra && extra.host) avVal.host = extra.host;
    if (extra && extra.port) avVal.port = extra.port;
    if (extra && extra.dbname) avVal.database = extra.dbname;
    _add(facts, mkFact('credential.available', scope, avVal, S, source));
    if (emitDbCreds) {
      _add(facts, mkFact('credential.plaintext', scope, avVal, S, source));
      _add(facts, mkFact('credential.password', scope, avVal, S, source));
      _add(facts, mkFact('db.creds', scope, Object.assign({ user: u, password: p, service: service, via: idiom }, extra || {}), S, source));
    }
    if (!seen[p]) {
      seen[p] = true;
      _add(facts, mkFact('credential.candidate', scope, { kind: 'source_db_credential', user: u, password: p, service: service, source: idiom }, S, source));
    }
  }

  function _parse_source_db_connectors(text, scope, source, facts, seen) {
    var t = String(text || '');
    if (!_DB_CONNECTOR_HINT_RE.test(t)) return;
    seen = seen || {};
    var phpVars = t.indexOf('$') >= 0 ? _resolvePhpVars(t) : {};

    // 1. mysqli_connect(host, user, pass[, db]) / new mysqli(host, user, pass[, db])
    var mysqliRe = /\b(?:mysqli_connect|new\s+mysqli)\s*\(\s*([^,)\r\n]+)\s*,\s*([^,)\r\n]+)\s*,\s*([^,)\r\n]+)/gi;
    reAll(mysqliRe, t).forEach(function (m) {
      var u = _resolveArgToken(m[2], phpVars);
      var p = _resolveArgToken(m[3], phpVars);
      _emitConcreteSourceCred(facts, scope, source, seen, u, p, 'mysql', 'mysqli_connect');
    });

    // 2. new PDO(dsn, user, pass)
    var pdoRe = /\bnew\s+PDO\s*\(\s*([^,)\r\n]+)\s*,\s*([^,)\r\n]+)\s*,\s*([^,)\r\n]+)/gi;
    reAll(pdoRe, t).forEach(function (m) {
      var dsn = _resolveArgToken(m[1], phpVars) || m[1];
      var svc = /pgsql/i.test(dsn) ? 'postgresql' : (/sqlsrv|mssql/i.test(dsn) ? 'mssql' : 'mysql');
      var u = _resolveArgToken(m[2], phpVars);
      var p = _resolveArgToken(m[3], phpVars);
      _emitConcreteSourceCred(facts, scope, source, seen, u, p, svc, 'pdo');
    });

    // 3.SqlConnection / ADO.NET / web.config connection strings with both User Id/UID and Password/PWD
    var adoLines = t.split(/\r?\n/);
    for (var i = 0; i < adoLines.length; i++) {
      var ln = adoLines[i];
      if (!/(?:SqlConnection|connectionString|Data Source|Server\s*=)/i.test(ln)) continue;
      var um = /\b(?:User\s*Id|UID|Username)\s*=\s*([^;"'\r\n<>]+)/i.exec(ln);
      var pm = /\b(?:Password|PWD)\s*=\s*([^;"'\r\n<>]+)/i.exec(ln);
      if (um && pm) {
        _emitConcreteSourceCred(facts, scope, source, seen, um[1].trim(), pm[1].trim(), 'mssql', 'sqlconnection');
      }
    }

    // 4. PostgreSQL libpq key-value DSN in pg_connect("host=... dbname=... user=... password=...")
    var pgRe = /\bpg_p?connect\s*\(\s*(?:(['"])([\s\S]{8,400}?)\1|(\$[A-Za-z_][A-Za-z0-9_]*))/gi;
    reAll(pgRe, t).forEach(function (m) {
      var dsnStr = m[2] || (m[3] ? _resolveArgToken(m[3], phpVars) : '');
      if (!dsnStr) return;
      var uM = /\buser\s*=\s*(?:'([^']+)'|"([^"]+)"|([^\s'"]+))/i.exec(dsnStr);
      var pM = /\bpassword\s*=\s*(?:'([^']+)'|"([^"]+)"|([^\s'"]+))/i.exec(dsnStr);
      if (!uM || !pM) return;
      var pgU = (uM[1] || uM[2] || uM[3] || '').trim();
      var pgP = (pM[1] || pM[2] || pM[3] || '').trim();
      var hM = /\bhost\s*=\s*(?:'([^']+)'|"([^"]+)"|([^\s'"]+))/i.exec(dsnStr);
      var ptM = /\bport\s*=\s*(\d+)/i.exec(dsnStr);
      var dbM = /\bdbname\s*=\s*(?:'([^']+)'|"([^"]+)"|([^\s'"]+))/i.exec(dsnStr);
      var extra = {};
      if (hM) extra.host = (hM[1] || hM[2] || hM[3] || '').trim();
      if (ptM) extra.port = parseInt(ptM[1], 10);
      if (dbM) extra.dbname = (dbM[1] || dbM[2] || dbM[3] || '').trim();
      _emitConcreteSourceCred(facts, scope, source, seen, pgU, pgP, 'postgres', 'pg_connect', true, extra);
    });

    // 5. Paired PHP define('DB_*USER*', '...') + define('DB_*PASS*', '...') constants (underscore optional)
    var defUserM = /\bdefine\s*\(\s*['"](?:(?:DB|MYSQL|PG|MSSQL|SQL)_?[A-Z0-9_]*USER(?:NAME)?|[A-Z0-9_]*(?:DB|MYSQL|PG|MSSQL|SQL)_?USER(?:NAME)?)['"]\s*,\s*['"]([^'"\r\n]{1,96})['"]\s*\)/i.exec(t);
    var defPassM = /\bdefine\s*\(\s*['"](?:(?:DB|MYSQL|PG|MSSQL|SQL)_?[A-Z0-9_]*PASS(?:WORD|WD)?|(?:DB|MYSQL|PG|MSSQL|SQL)_?PWD|[A-Z0-9_]*(?:DB|MYSQL|PG|MSSQL|SQL)_?(?:PASS(?:WORD|WD)?|PWD))['"]\s*,\s*['"]([^'"\r\n]{3,96})['"]\s*\)/i.exec(t);
    if (defUserM && defPassM) {
      var defDbM = /\bdefine\s*\(\s*['"](?:(?:DB|MYSQL|PG|MSSQL|SQL)_?(?:NAME|DATABASE)|[A-Z0-9_]*DB_?NAME)['"]\s*,\s*['"]([^'"\r\n]{1,96})['"]\s*\)/i.exec(t);
      var defHostM = /\bdefine\s*\(\s*['"](?:(?:DB|MYSQL|PG|MSSQL|SQL)_?(?:HOST|SERVER)|[A-Z0-9_]*DB_?HOST)['"]\s*,\s*['"]([^'"\r\n]{1,96})['"]\s*\)/i.exec(t);
      var defSvc = /\b(?:pgsql|postgres|pg_connect)\b/i.test(t) ? 'postgres' : (/\b(?:mssql|sqlsrv)\b/i.test(t) ? 'mssql' : 'mysql');
      var defExtra = {};
      if (defDbM) defExtra.dbname = defDbM[1].trim();
      if (defHostM) defExtra.host = defHostM[1].trim();
      _emitConcreteSourceCred(facts, scope, source, seen, defUserM[1].trim(), defPassM[1].trim(), defSvc, 'php-define', true, defExtra);
    }

    // 5b. Paired scalar PHP DB variables ($db_user / $db_password, $dbuser / $dbpass, $mysql_user / $mysql_pass)
    var phpVarKeys = Object.keys(phpVars);
    if (phpVarKeys.length >= 2) {
      var pvUser = '', pvPass = '', pvDb = '', pvHost = '', pvSvcHint = '';
      for (var pvi = 0; pvi < phpVarKeys.length; pvi++) {
        var pvk = phpVarKeys[pvi];
        if (!pvUser && /^(?:(?:db|database|mysql|pg|postgres|mssql|sql)_?user(?:name)?|user(?:name)?_?(?:db|database|mysql|pg))$/i.test(pvk)) {
          pvUser = phpVars[pvk];
          if (/pg|postgres/i.test(pvk)) pvSvcHint = 'postgres';
          else if (/mssql/i.test(pvk)) pvSvcHint = 'mssql';
        } else if (!pvPass && /^(?:(?:db|database|mysql|pg|postgres|mssql|sql)_?(?:pass(?:word|wd)?|pwd)|(?:pass(?:word|wd)?|pwd)_?(?:db|database|mysql|pg))$/i.test(pvk)) {
          pvPass = phpVars[pvk];
          if (!pvSvcHint && /pg|postgres/i.test(pvk)) pvSvcHint = 'postgres';
          else if (!pvSvcHint && /mssql/i.test(pvk)) pvSvcHint = 'mssql';
        } else if (!pvDb && /^(?:(?:db|database|mysql|pg|postgres|mssql|sql)_?(?:name|db)|dbname)$/i.test(pvk)) {
          pvDb = phpVars[pvk];
        } else if (!pvHost && /^(?:(?:db|database|mysql|pg|postgres|mssql|sql)_?(?:host|server)|dbhost)$/i.test(pvk)) {
          pvHost = phpVars[pvk];
        }
      }
      if (pvUser && pvPass) {
        var pvSvc = pvSvcHint || (/\b(?:pgsql|postgres|pg_connect)\b/i.test(t) ? 'postgres' : (/\b(?:mssql|sqlsrv)\b/i.test(t) ? 'mssql' : 'mysql'));
        var pvExtra = {};
        if (pvDb) pvExtra.dbname = pvDb.trim();
        if (pvHost) pvExtra.host = pvHost.trim();
        _emitConcreteSourceCred(facts, scope, source, seen, pvUser, pvPass, pvSvc, 'php-db-vars', true, pvExtra);
      }
    }

    // 5c. Paired subscripted PHP config array assignments ($conf['mysql_user'] + $conf['mysql_pass'], $cfg['Servers'][$i]['password'])
    if (t.indexOf('$') >= 0 && t.indexOf('[') >= 0) {
      var subLines = t.split(/\r?\n/);
      var subAssignRe = /\$([A-Za-z_][A-Za-z0-9_]{0,47})((?:\[\s*(?:['"][A-Za-z0-9_.-]{1,48}['"]|\$[A-Za-z_][A-Za-z0-9_]*)\s*\])*)\[\s*['"]([A-Za-z0-9_.-]{1,48})['"]\s*\]\s*=\s*['"]([^'"\r\n]{1,128})['"]/g;
      var subUserKeyRe = /^(?:(?:[A-Za-z0-9_.-]+_)?(?:user(?:name)?|login|uname)|dbuser|mysqluser|pguser)$/i;
      var subPassKeyRe = /^(?:(?:[A-Za-z0-9_.-]+_)?(?:pass(?:word|wd)?|pwd)|dbpass|mysqlpass|pgpass)$/i;
      var subDbKeyRe = /^(?:(?:[A-Za-z0-9_.-]+_)?(?:db(?:name)?|database)|mysql_?database)$/i;
      var subHostKeyRe = /^(?:(?:[A-Za-z0-9_.-]+_)?(?:host|server)|dbhost|mysql_?host)$/i;
      var subUsers = [], subPasses = [], subDbs = [], subHosts = [];
      for (var sli = 0; sli < subLines.length; sli++) {
        var sln = subLines[sli];
        if (!sln || sln.indexOf('$') < 0 || sln.indexOf('[') < 0 || sln.length > 2048) continue;
        subAssignRe.lastIndex = 0;
        var sm;
        while ((sm = subAssignRe.exec(sln)) !== null) {
          var sRoot = sm[1], sChain = sm[2] || '', sKey = sm[3], sVal = sm[4];
          if (subUserKeyRe.test(sKey)) {
            var su = _valid_assoc_or_xml_user(sVal);
            if (su) subUsers.push({ line: sli, root: sRoot, chain: sChain, key: sKey, user: su });
          } else if (subPassKeyRe.test(sKey)) {
            var sp = _valid_assoc_or_xml_secret(sVal, 3);
            if (sp) subPasses.push({ line: sli, root: sRoot, chain: sChain, key: sKey, secret: sp });
          } else if (subDbKeyRe.test(sKey)) {
            subDbs.push({ line: sli, root: sRoot, val: sVal.trim() });
          } else if (subHostKeyRe.test(sKey)) {
            subHosts.push({ line: sli, root: sRoot, val: sVal.trim() });
          }
        }
      }
      for (var spi = 0; spi < subPasses.length; spi++) {
        var spItem = subPasses[spi], bestSubU = null, bestSubDist = 999;
        for (var sui = 0; sui < subUsers.length; sui++) {
          if (subUsers[sui].root !== spItem.root) continue;
          var sDist = Math.abs(subUsers[sui].line - spItem.line);
          if (sDist <= 15 && sDist < bestSubDist) {
            bestSubDist = sDist;
            bestSubU = subUsers[sui];
          }
        }
        if (bestSubU) {
          var subHintStr = [spItem.root, spItem.chain, spItem.key, bestSubU.key].join(' ');
          var isSubDb = /(?:db|database|mysql|mariadb|pgsql|postgres|mssql|sqlsrv|servers)/i.test(subHintStr)
            || subDbs.some(function (d) { return d.root === spItem.root && Math.abs(d.line - spItem.line) <= 15; });
          var subSvc = /(?:pgsql|postgres)/i.test(subHintStr) ? 'postgres' : (/(?:mssql|sqlsrv)/i.test(subHintStr) ? 'mssql' : 'mysql');
          var subExtra = {};
          for (var sdi = 0; sdi < subDbs.length; sdi++) {
            if (subDbs[sdi].root === spItem.root && Math.abs(subDbs[sdi].line - spItem.line) <= 15) { subExtra.dbname = subDbs[sdi].val; break; }
          }
          for (var shi = 0; shi < subHosts.length; shi++) {
            if (subHosts[shi].root === spItem.root && Math.abs(subHosts[shi].line - spItem.line) <= 15) { subExtra.host = subHosts[shi].val; break; }
          }
          _emitConcreteSourceCred(facts, scope, source, seen, bestSubU.user, spItem.secret, isSubDb ? subSvc : 'app', 'php-array-config', isSubDb, subExtra);
        }
      }
    }

    // 6. Java JDBC: DriverManager.getConnection(...), Properties.put/setProperty("user", ...)+("password", ...), and jdbc:...user=...&password=...
    var jdbcEngineM = /\bjdbc:(mysql|mariadb|postgresql|sqlserver|oracle|sqlite):/i.exec(t);
    var defaultJdbcSvc = jdbcEngineM
      ? (jdbcEngineM[1].toLowerCase() === 'mariadb' ? 'mysql' : (jdbcEngineM[1].toLowerCase() === 'sqlserver' ? 'mssql' : jdbcEngineM[1].toLowerCase()))
      : 'mysql';

    var dmRe = /\bDriverManager\.getConnection\s*\(\s*(?:"jdbc:([a-z0-9]+):[^"\r\n]*"|[A-Za-z_$][A-Za-z0-9_$.]*)\s*,\s*"([^"\r\n]{1,64})"\s*,\s*"([^"\r\n]{1,128})"\s*\)/gi;
    reAll(dmRe, t).forEach(function (m) {
      var rawEng = (m[1] || '').toLowerCase();
      var svc = rawEng === 'mariadb' ? 'mysql' : (rawEng === 'sqlserver' ? 'mssql' : (rawEng || defaultJdbcSvc));
      _emitConcreteSourceCred(facts, scope, source, seen, m[2].trim(), m[3].trim(), svc, 'jdbc-drivermanager', true);
    });

    var propLines = t.split(/\r?\n/);
    var propUsers = [], propSecrets = [];
    var propPutRe = /\.(?:put|setProperty)\s*\(\s*"(user(?:name)?|password|pass|pwd)"\s*,\s*"([^"\r\n]{1,128})"\s*\)/gi;
    for (var pli = 0; pli < propLines.length; pli++) {
      var pln = propLines[pli];
      if (!pln || (pln.indexOf('.put') < 0 && pln.indexOf('.setProperty') < 0)) continue;
      propPutRe.lastIndex = 0;
      var pm2;
      while ((pm2 = propPutRe.exec(pln)) !== null) {
        var pk = pm2[1].toLowerCase(), pv = pm2[2];
        if (pk === 'user' || pk === 'username') propUsers.push({ line: pli, user: pv.trim() });
        else propSecrets.push({ line: pli, secret: pv.trim() });
      }
    }
    for (var psi = 0; psi < propSecrets.length; psi++) {
      for (var pui = 0; pui < propUsers.length; pui++) {
        if (Math.abs(propUsers[pui].line - propSecrets[psi].line) <= 15) {
          _emitConcreteSourceCred(facts, scope, source, seen, propUsers[pui].user, propSecrets[psi].secret, defaultJdbcSvc, 'jdbc-properties', true);
          break;
        }
      }
    }

    var jdbcUrlRe = /\bjdbc:(mysql|mariadb|postgresql|sqlserver|oracle):\/\/[^\s"'?]+\?([^\s"']+)/gi;
    reAll(jdbcUrlRe, t).forEach(function (m) {
      var q = m[2] || '';
      var jpM = /(?:^|&)password=([^&"'\s]+)/i.exec(q);
      if (!jpM) return;
      var juM = /(?:^|&)user=([^&"'\s]+)/i.exec(q);
      if (!juM) return;
      var rawEng = m[1].toLowerCase();
      var svc = rawEng === 'mariadb' ? 'mysql' : (rawEng === 'sqlserver' ? 'mssql' : rawEng);
      _emitConcreteSourceCred(facts, scope, source, seen, juM[1].trim(), jpM[1].trim(), svc, 'jdbc-url', true);
    });

    // 7. Spring Boot spring.datasource.(url|username|password) (.properties and application.yml)
    var sdUserM = /^[ \t]*spring\.datasource\.username[ \t]*[:=][ \t]*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s'"#\r\n]+))/im.exec(t);
    var sdPassM = /^[ \t]*spring\.datasource\.password[ \t]*[:=][ \t]*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s'"#\r\n]+))/im.exec(t);
    var sdUrlM = /^[ \t]*spring\.datasource\.url[ \t]*[:=][ \t]*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s'"#\r\n]+))/im.exec(t);
    if (!sdUserM || !sdPassM) {
      var ymlBlockM = /^[ \t]*datasource:[ \t]*\r?\n((?:[ \t]{2,}[^\r\n]+\r?\n?){2,10})/im.exec(t);
      if (ymlBlockM) {
        var yb = ymlBlockM[1];
        if (!sdUserM) sdUserM = /^[ \t]*username[ \t]*:[ \t]*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s'"#\r\n]+))/im.exec(yb);
        if (!sdPassM) sdPassM = /^[ \t]*password[ \t]*:[ \t]*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s'"#\r\n]+))/im.exec(yb);
        if (!sdUrlM) sdUrlM = /^[ \t]*url[ \t]*:[ \t]*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s'"#\r\n]+))/im.exec(yb);
      }
    }
    if (sdUserM && sdPassM) {
      var sdUser = (sdUserM[1] || sdUserM[2] || sdUserM[3] || '').trim();
      var sdPass = (sdPassM[1] || sdPassM[2] || sdPassM[3] || '').trim();
      var sdUrl = sdUrlM ? (sdUrlM[1] || sdUrlM[2] || sdUrlM[3] || '').trim() : '';
      var sdEngM = /\bjdbc:(mysql|mariadb|postgresql|sqlserver|oracle|h2|sqlite):/i.exec(sdUrl);
      var sdRawEng = sdEngM ? sdEngM[1].toLowerCase() : '';
      var sdSvc = sdRawEng === 'mariadb' ? 'mysql' : (sdRawEng === 'sqlserver' ? 'mssql' : (sdRawEng || defaultJdbcSvc));
      var sdExtra = {};
      var sdHostDbM = /jdbc:[a-z0-9]+:\/\/([^/:?;\s]+)(?::(\d+))?(?:\/([A-Za-z0-9_.-]+))?/i.exec(sdUrl);
      if (sdHostDbM) {
        if (sdHostDbM[1]) sdExtra.host = sdHostDbM[1];
        if (sdHostDbM[2]) sdExtra.port = parseInt(sdHostDbM[2], 10);
        if (sdHostDbM[3]) sdExtra.dbname = sdHostDbM[3];
      }
      _emitConcreteSourceCred(facts, scope, source, seen, sdUser, sdPass, sdSvc, 'spring-datasource', true, sdExtra);
    }
  }
  C._parse_source_db_connectors = _parse_source_db_connectors;

  var _ORIG_HAS_SOURCE_SECRET = _has_source_secret;
  _has_source_secret = function (text) {
    var t = text || '';
    if (!t) return false;
    if (_is_outbound_http_request_only(t) && /Content-Disposition:\s*form-data;/i.test(t)) return false;
    return _ORIG_HAS_SOURCE_SECRET(t)
      || !!((t.indexOf('\n+') >= 0 || t.indexOf('\n-') >= 0 || t.charAt(0) === '+' || t.charAt(0) === '-') && C && C._extract_diff_cred_pairs && C._extract_diff_cred_pairs(t).length > 0);
  };
  C._has_source_secret = _has_source_secret;

  // ---- Step 1A: Disclosed web source, HTTP 500 stack traces, and phpinfo() tables ---- //
  var _LOCAL_TOOL_CMD_RE = /^\s*(?:sudo\s+)?(?:python[23]?|pip[23]?|2to3|gcc|g\+\+|impacket-[\w-]+|bloodyad|certipy(?:-ad)?|nxc|netexec|crackmapexec|sqlmap|searchsploit)\b/i;
  var _CONFIG_SYNTAX_ERR_LINE_RE = /^\s*(?:Error|Fatal|Warning):\s*invalid line \d+ in \S+:[^\r\n]*$/gim;

  function _has_web_disclosure(text, command) {
    var cmdStr = String(command || '');
    if (/\b(?:swaks|sendmail|smtp-user-enum)\b|\b(?:nc|ncat|netcat|telnet|openssl\s+s_client)\b[^\r\n]*\s(?:25|110|143|465|587|993|995)\b/i.test(cmdStr)) return false;
    if (/^\s*(?:(?:<-|<--|S:)?\s*220[\s-][^\r\n]*\bE?SMTP\b|(?:<-|<--|S:)?\s*\+OK\b[^\r\n]*(?:POP3|Dovecot)|\* OK\b[^\r\n]*IMAP4|(?:->|-->|C:)?\s*(?:EHLO|HELO|MAIL\s+FROM:|RCPT\s+TO:)\s+\S)/im.test(text || '')) return false;
    var t = _inbound_http_segment(text);
    if (!/\S/.test(t)) return false;
    if (!/php|Fatal error|Parse error|Warning:|Traceback|500\b|Werkzeug|Server Error|Error:|flask|django|fastapi|express|<configuration/i.test(t)) return false;
    if (_is_outbound_http_request_only(t)) return false;
    if (C._looks_like_edb_script && C._looks_like_edb_script(t, command)) return false;
    var tNoCfgErr = /invalid line \d+ in /i.test(t) ? t.replace(_CONFIG_SYNTAX_ERR_LINE_RE, '') : t;
    if (!/\S/.test(tNoCfgErr)) return false;
    // phpinfo() table
    if (/PHP Version\s+\d+\.\d+/i.test(tNoCfgErr) && /\b(?:DOCUMENT_ROOT|disable_functions|Loaded Configuration File|PHP Extension)\b/i.test(tNoCfgErr)) return true;
    // PHP verbose fatal/warning error with server path
    if (/\b(?:Fatal error|Parse error|Warning):\s+(?:Uncaught\s+)?[^\r\n]+?\s+in\s+(?:\/(?:var\/www|srv|opt|app|home|usr\/share)\/[^\s:]+\.php|[A-Za-z]:\\(?:inetpub|xampp|wamp|www)[^\r\n:]+\.php)\s+on line\s+\d+/i.test(tNoCfgErr)) return true;
    // Stack trace leaking server application path
    if (!(_LOCAL_TOOL_CMD_RE.test(command || '') && !/^\s*(?:<\s*)?HTTP\/[12]/im.test(tNoCfgErr))) {
      if (/Traceback \(most recent call last\):[\s\S]{1,1600}?File\s+"(\/(?:var\/www|app|srv|opt|usr\/src\/app|home\/[^/]+\/(?:app|web|site))\/[^"]+\.py)"/i.test(tNoCfgErr)) return true;
      if (/(?:HTTP\/[12](?:\.\d)?\s+500\b|500 Internal Server Error|Werkzeug Debugger|Server Error in '\/' Application)[\s\S]{1,2400}?(?:Traceback \(most recent call last\):|\/var\/www\/|\/usr\/src\/app\/|\/app\/|[A-Za-z]:\\inetpub\\|at\s+\S+\s+\(\/[^\r\n)]+:\d+:\d+\))/i.test(tNoCfgErr)) return true;
      if (/^\s*Error:[^\r\n]+\r?\n(?:\s+at\s+[^\r\n(]+\((?:\/(?:var\/www|app|srv|opt|usr\/src\/app)\/|[A-Za-z]:\\(?:inetpub|app|www)\\)[^)\r\n]+:\d+:\d+\)\r?\n?)+/m.test(tNoCfgErr)) return true;
    }
    // Recovered server-side source (LFI, .git dump, backup file)
    if (/<\?php\b/i.test(tNoCfgErr) && !/\b(?:echo|curl|wget)\b[^\r\n]*<\?php/i.test(command || '')) return true;
    if (/^\s*(?:from\s+flask\s+import\b|from\s+django\.[A-Za-z0-9_.]+\s+import\b|from\s+fastapi\s+import\b)/m.test(tNoCfgErr)) return true;
    if (/\brequire\s*\(\s*['"]express['"]\s*\)|\bimport\s+express\s+from\s+['"]express['"]/i.test(tNoCfgErr)) return true;
    if (/<configuration\b[^>]*>[\s\S]{0,2000}?<(?:connectionStrings|system\.web)\b/i.test(tNoCfgErr)) return true;
    return false;
  }
  C._has_web_disclosure = _has_web_disclosure;

  function _parse_web_disclosure(text, ws, command, source, facts) {
    var t = _inbound_http_segment(text);
    if (!_has_web_disclosure(t, command)) return;
    var scope = _scope(ws);
    var kind = 'source_code';
    var details = { kind: kind };

    if (/PHP Version\s+(\d+\.\d+(?:\.\d+)?)/i.test(t) && /\b(?:DOCUMENT_ROOT|disable_functions|Loaded Configuration File)\b/i.test(t)) {
      var pvM = /PHP Version\s+(\d+\.\d+(?:\.\d+)?)/i.exec(t);
      details.kind = 'phpinfo';
      if (pvM) details.php_version = pvM[1];
      var docM = /DOCUMENT_ROOT\s*(?:<\/td><td[^>]*>|[|=>\t ]+)\s*([\/A-Za-z0-9_.:\\-]{3,140})/i.exec(t);
      if (docM) {
        details.document_root = docM[1].trim();
        details.app_base_path = details.document_root;
      }
      var disM = /disable_functions\s*(?:<\/td><td[^>]*>|[|=>\t ]+)\s*([A-Za-z0-9_,\s-]{2,200})/i.exec(t);
      if (disM) details.disable_functions = disM[1].trim().slice(0, 160);
    } else if (/Traceback \(most recent call last\):|\bFatal error:\s|500 Internal Server Error|Server Error in '\/' Application|^\s*Error:[^\r\n]+\r?\n\s+at\s+/im.test(t)) {
      details.kind = 'stack_trace';
      var pathM = /(\/(?:var\/www|app|srv|opt|usr\/src\/app|home)\/[A-Za-z0-9_./-]+\.(?:py|php|js|ts|rb|java|go)|[A-Za-z]:\\(?:inetpub|xampp|wamp|app|www)\\[A-Za-z0-9_.\\-]+\.(?:cs|aspx|php|js|py))/i.exec(t);
      if (pathM) {
        details.leaked_path = pathM[1];
        details.source_path = pathM[1];
      }
    } else if (/<\?php\b/i.test(t)) {
      details.language = 'php';
    } else if (/from\s+(?:flask|django|fastapi)\b/i.test(t)) {
      details.language = 'python';
    } else if (/require\s*\(\s*['"]express['"]\s*\)|import\s+express\b/i.test(t)) {
      details.language = 'javascript';
    } else if (/<connectionStrings\b|<system\.web\b/i.test(t)) {
      details.language = 'aspnet';
    }
    if (!details.source_path && command) {
      var cmdResM = /(?:resource=|file=|page=|path=)([\/A-Za-z0-9_.-]+\.(?:php|py|js|ts|cs|aspx|config|json|xml))/i.exec(command)
        || /https?:\/\/[^/\s"']+(\/[^\s"'?#]+\.(?:php|py|js|ts|cs|aspx|config|txt|bak|old))/i.exec(command);
      if (cmdResM) details.source_path = cmdResM[1];
    }

    _add(facts, mkFact('web.source_disclosed', scope, details, S, source));
  }
  C._parse_web_disclosure = _parse_web_disclosure;

  // ---- Step 1B: Disclosed dependency manifests (package.json, composer.json, requirements.txt, pom.xml, build.gradle, CHANGELOG) ---- //
  var _COMMONS_TEXT_VULN_RE = /\b(?:Apache\s+Commons\s+Text|commons-text)\s*[:=-]?\s*v?(1\.[5-9](?:\.\d+)?)\b/i;

  function _has_web_manifest(text, command) {
    var t = String(text || '');
    if (!/\S/.test(t)) return false;
    var hasQuote = t.indexOf('"') >= 0 || t.indexOf("'") >= 0;
    var hasLt = t.indexOf('<') >= 0;
    var hasPinOp = t.indexOf('==') >= 0 || t.indexOf('~=') >= 0;
    var hasRubyGems = t.indexOf('rubygems.org') >= 0;
    if (!hasQuote && !hasLt && !hasPinOp && !hasRubyGems && !_COMMONS_TEXT_VULN_RE.test(t)) return false;
    if (C._looks_like_edb_script && C._looks_like_edb_script(t, command)) return false;
    if (hasQuote && /"(?:dependencies|devDependencies)"\s*:\s*\{[\s\S]{2,2000}?\}/.test(t)) return true;
    if (hasQuote && /"require(?:-dev)?"\s*:\s*\{[\s\S]{2,2000}?\}/.test(t) && (/"php"\s*:/.test(t) || /"[a-z0-9_.-]+\/[a-z0-9_.-]+"\s*:/.test(t))) return true;
    if (hasLt && /<dependencies\b[^>]*>[\s\S]{10,4000}?<artifactId>[^<]+<\/artifactId>[\s\S]{1,400}?<version>[^<]+<\/version>/i.test(t)) return true;
    if (hasQuote && /\b(?:implementation|api|compile(?:Only)?|runtimeOnly)\s*\(?\s*['"][A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[0-9][A-Za-z0-9_.-]*['"]/.test(t)) return true;
    if (_COMMONS_TEXT_VULN_RE.test(t)) return true;
    if (hasPinOp) {
      var reqLines = t.match(/^[ \t]*[A-Za-z0-9][A-Za-z0-9_.-]{1,50}[ \t]*(?:==|~=)[ \t]*\d+\.\d+(?:\.\d+)?[A-Za-z0-9.*+-]*[ \t]*(?:#.*)?$/gm);
      if (reqLines && (reqLines.length >= 2 || (reqLines.length >= 1 && /requirements[^\s/]*\.txt\b/i.test(command || '')))) return true;
    }
    if (hasQuote) {
      var gemLines = t.match(/^[ \t]*gem[ \t]+['"][A-Za-z0-9_.-]+['"](?:[ \t]*,[ \t]*['"][^'"]+['"])?/gm);
      if (gemLines && (gemLines.length >= 2 || (/^[ \t]*source[ \t]+['"]https?:\/\/rubygems\.org/im.test(t) && gemLines.length >= 1) || (/\bgemfile\b/i.test(command || '') && gemLines.length >= 1))) return true;
    }
    if (hasRubyGems && /^GEM\r?\n[ \t]+remote:[ \t]+https?:\/\/rubygems\.org/m.test(t) && /^[ \t]{4}[A-Za-z0-9_.-]+[ \t]+\(\d+\.\d+[^)]*\)[ \t]*$/m.test(t)) return true;
    return false;
  }
  C._has_web_manifest = _has_web_manifest;

  function _parse_web_manifest(text, ws, command, source, facts) {
    var t = String(text || '');
    if (!_has_web_manifest(t, command)) return;
    var scope = _scope(ws);
    var packages = [], seenPkg = {}, manifestType = '';

    function addPkg(name, ver) {
      var n = String(name || '').trim();
      var v = String(ver || '').trim().replace(/^[\^~>=<v\s]+/, '');
      if (!n || !v || n === 'php' || seenPkg[n.toLowerCase()]) return;
      seenPkg[n.toLowerCase()] = 1;
      packages.push({ name: n, version: v });
    }

    // 1. JSON manifests: package.json / composer.json
    if (t.indexOf('{') >= 0 && /"(?:dependencies|devDependencies|require|require-dev)"\s*:/.test(t)) {
      var blockRe = /"(dependencies|devDependencies|require|require-dev)"\s*:\s*\{([^}]*)\}/g;
      reAll(blockRe, t).forEach(function (bm) {
        var sec = bm[1];
        if (!manifestType) manifestType = (sec === 'require' || sec === 'require-dev') ? 'composer.json' : 'package.json';
        reAll(/"([^"\r\n]+)"\s*:\s*"([^"\r\n]+)"/g, bm[2]).forEach(function (kv) {
          addPkg(kv[1], kv[2]);
        });
      });
    }

    // 2. Maven pom.xml
    if (!packages.length && /<dependency\b/i.test(t)) {
      manifestType = 'pom.xml';
      reAll(/<dependency\b[^>]*>([\s\S]*?)<\/dependency>/gi, t).forEach(function (dm) {
        var aid = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/i.exec(dm[1]);
        var ver = /<version>\s*([^<\s$]+)\s*<\/version>/i.exec(dm[1]);
        if (aid && ver) addPkg(aid[1], ver[1]);
      });
    }

    // 3. Gradle build.gradle
    if (!packages.length && /\b(?:implementation|api|compile(?:Only)?|runtimeOnly)\b/.test(t)) {
      var gMatches = reAll(/\b(?:implementation|api|compile(?:Only)?|runtimeOnly)\s*\(?\s*['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([0-9][A-Za-z0-9_.-]*)['"]/g, t);
      if (gMatches.length) {
        manifestType = 'build.gradle';
        gMatches.forEach(function (gm) { addPkg(gm[2], gm[3]); });
      }
    }

    // 4. Python requirements.txt
    if (!packages.length) {
      var rMatches = reAll(/^[ \t]*([A-Za-z0-9][A-Za-z0-9_.-]{1,50})[ \t]*(?:==|~=|>=)[ \t]*(\d+\.\d+(?:\.\d+)?[A-Za-z0-9.*+-]*)[ \t]*(?:#.*)?$/gm, t);
      if (rMatches.length) {
        manifestType = 'requirements.txt';
        rMatches.forEach(function (rm) { addPkg(rm[1], rm[2]); });
      }
    }

    // 4b. Ruby Gemfile / Gemfile.lock
    if (!packages.length && /^GEM\r?\n[ \t]+remote:[ \t]+https?:\/\/rubygems\.org/m.test(t)) {
      var glMatches = reAll(/^[ \t]{4}([A-Za-z0-9_.-]+)[ \t]+\(([0-9][A-Za-z0-9_.-]*)\)[ \t]*$/gm, t);
      if (glMatches.length) {
        manifestType = 'Gemfile.lock';
        glMatches.forEach(function (glm) { addPkg(glm[1], glm[2]); });
      }
    }
    if (!packages.length && /^[ \t]*gem[ \t]+['"][A-Za-z0-9_.-]+['"]/m.test(t)) {
      var gemMatches = reAll(/^[ \t]*gem[ \t]+['"]([A-Za-z0-9_.-]+)['"](?:[ \t]*,[ \t]*['"]([^'"]+)['"])?/gm, t);
      if (gemMatches.length) {
        manifestType = 'Gemfile';
        gemMatches.forEach(function (gm) { addPkg(gm[1], gm[2] || 'unpinned'); });
      }
    }

    // 5. CHANGELOG / release-note vulnerable library disclosure (Apache Commons Text 1.5 - 1.9)
    var ctM = _COMMONS_TEXT_VULN_RE.exec(t);
    if (ctM) {
      if (!manifestType) manifestType = 'changelog';
      addPkg('commons-text', ctM[1]);
    }

    if (!packages.length) return;
    var manifestPath = '';
    if (command) {
      var mpM = /(?:https?|ftp):\/\/[^/\s"']+(\/[^\s"'?#]*(?:package\.json|composer\.json|requirements[^\s"'?#]*\.txt|pom\.xml|build\.gradle|Gemfile(?:\.lock)?|changelog[^\s"'?#]*))/i.exec(command)
        || /(\/[^\s"']*(?:package\.json|composer\.json|requirements[^\s"']*\.txt|pom\.xml|build\.gradle|Gemfile(?:\.lock)?|changelog[^\s"']*))/i.exec(command);
      if (mpM) manifestPath = mpM[1];
    }
    var mVal = {
      manifest_type: manifestType || 'manifest',
      packages: packages.slice(0, 40),
      count: packages.length
    };
    if (manifestPath) mVal.manifest_path = manifestPath;
    _add(facts, mkFact('web.manifest_disclosed', scope, mVal, S, source));

    packages.forEach(function (pkg) {
      var pLow = pkg.name.toLowerCase();
      if ((pLow === 'commons-text' || pLow === 'org.apache.commons:commons-text' || pLow === 'apache commons text') && /^1\.[5-9](?:\.\d+)?$/.test(pkg.version)) {
        _add(facts, mkFact('exploit.versioned_banner', scope, {
          product: 'Apache Commons Text',
          version: pkg.version,
          cve: 'CVE-2022-42889',
          search_query: 'Apache Commons Text ' + pkg.version,
          via: 'web-manifest'
        }, S, source));
        _add(facts, mkFact('vuln.text4shell', scope, {
          product: 'Apache Commons Text',
          version: pkg.version,
          cve: 'CVE-2022-42889',
          via: 'web-manifest',
          lead: true
        }, S, source));
      }
    });
  }
  C._parse_web_manifest = _parse_web_manifest;

  // ---- Step 2B: Dangerous server-side web vulnerability sinks ---- //
  var _WEB_VULN_SINKS = [
    { category: 'cmdi', sink: 'php_shell_exec', re: /\b(?:shell_exec|passthru|proc_open|pcntl_exec)\s*\([^);\r\n]*\$[A-Za-z_]/i },
    { category: 'cmdi', sink: 'php_system_exec', re: /\b(?:system|exec|popen)\s*\([^);\r\n]*\$[A-Za-z_{]/i },
    { category: 'cmdi', sink: 'node_child_process_exec', re: /\bchild_process\s*\.\s*(?:exec|execSync)\s*\(|\bexec(?:Sync)?\s*\([^);\r\n]*\breq\.(?:body|query|params|headers)/i },
    { category: 'cmdi', sink: 'python_shell_exec', re: /\bos\.(?:system|popen)\s*\([^)\r\n]*(?:request\.|f["']|\+)|\bsubprocess\.(?:Popen|run|call|check_output)\s*\([\s\S]{0,160}?shell\s*=\s*True/i },
    { category: 'deserialization', sink: 'python_pickle_loads', re: /\b(?:cPickle|pickle|_pickle|dill)\.loads?\s*\(|\bjsonpickle\.decode\s*\(/ },
    { category: 'deserialization', sink: 'yaml_unsafe_load', re: /\byaml\.(?:load|unsafe_load)\s*\((?![^)\r\n]*SafeLoader)/ },
    { category: 'deserialization', sink: 'php_unserialize', re: /\bunserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|base64_decode\s*\(|\$[A-Za-z_])/i },
    { category: 'deserialization', sink: 'node_unserialize', re: /\b(?:serialize\.unserialize|node-serialize)\b/i },
    { category: 'type_juggling', sink: 'php_strcmp_loose', re: /\bstrcmp\s*\([^)\r\n]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|pass|pwd|token|hash|secret)[^)\r\n]*\)\s*==(?!=)\s*0\b/i },
    { category: 'type_juggling', sink: 'php_loose_auth_compare', re: /(?:\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]|\$[A-Za-z0-9_]*(?:pass(?:word)?|pwd|hash|token|secret|hmac|auth|otp)[A-Za-z0-9_]*)\s*==(?!=)\s*(?:\$[A-Za-z0-9_]+|['"]0e\d+['"])|(?:md5|sha1)\s*\([^)\r\n]+\)\s*==(?!=)/i },
    { category: 'nosql_injection', sink: 'nosql_raw_req_body', re: /\.(?:find|findOne|findOneAndUpdate|countDocuments)\s*\(\s*(?:req\.(?:body|query)\b|\{\s*['"]?[A-Za-z0-9_]+['"]?\s*:\s*req\.(?:body|query)\.[A-Za-z0-9_]+(?:\s*,\s*['"]?[A-Za-z0-9_]+['"]?\s*:\s*req\.(?:body|query)\.[A-Za-z0-9_]+)?\s*\})/ }
  ];

  var _WEB_SOURCE_CONTEXT_RE = /(?:<\?php\b|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|\breq\.(?:body|query|params|cookies|headers)\b|\brequest\.(?:args|form|json|cookies|values|GET|POST)\b|\brequire\s*\(\s*['"](?:express|child_process|node-serialize|js-yaml)['"]|\bfrom\s+(?:flask|django|fastapi)\s+import\b|@app\.(?:route|get|post)\b|\brouter\.(?:get|post|put|use)\b)/i;

  function _has_web_vuln_sinks(text, command) {
    var t = _inbound_http_segment(text);
    if (!/\S/.test(t)) return false;
    var cmdStr = String(command || '');
    if (!/^\s*(?:<\s*)?HTTP\/[12]/im.test(t)) {
      if (/^\s*(?:sudo\s+)?(?:echo|printf|cat\s*(?:<<|>)|tee|exiftool|convert|magick|msfvenom)\b/i.test(cmdStr)) return false;
      if (/[12]?>>?\s*['"]?[^\s'"]+\.(?:php[0-9]?|phtml|phar|inc|jsp|jspx|asp|aspx|png|jpe?g|gif)\b/i.test(cmdStr)) return false;
    }
    if (!_WEB_SOURCE_CONTEXT_RE.test(t)) return false;
    if (_is_outbound_http_request_only(t)) return false;
    if (C._looks_like_edb_script && C._looks_like_edb_script(t, command)) return false;
    for (var i = 0; i < _WEB_VULN_SINKS.length; i++) {
      if (_WEB_VULN_SINKS[i].re.test(t)) return true;
    }
    return false;
  }
  C._has_web_vuln_sinks = _has_web_vuln_sinks;

  function _parse_web_vuln_sinks(text, ws, command, source, facts) {
    var t = _inbound_http_segment(text);
    if (!/^\s*(?:<\s*)?HTTP\/[12]/im.test(t) && C._is_attacker_local_turn && C._is_attacker_local_turn(ws, command, text)) return;
    if (!_has_web_vuln_sinks(t, command)) return;
    var scope = _scope(ws);
    var hits = [];
    for (var i = 0; i < _WEB_VULN_SINKS.length; i++) {
      var rule = _WEB_VULN_SINKS[i];
      var m = reSearch(rule.re, t);
      if (!m) continue;
      var evLine = (C._line_for_match ? C._line_for_match(t, m) : m[0]).trim().slice(0, 180);
      hits.push({ sink: rule.sink, category: rule.category, evidence: evLine });
    }
    if (!hits.length) return;
    var top = hits[0];
    _add(facts, mkFact('web.vuln_sink', scope, {
      sink: top.sink,
      category: top.category,
      evidence: top.evidence,
      sinks: hits
    }, S, source));
    _add(facts, mkFact('vuln.web_sink', scope, {
      sink: top.sink,
      category: top.category,
      lead: true
    }, S, source));
  }
  C._parse_web_vuln_sinks = _parse_web_vuln_sinks;

})(typeof globalThis !== 'undefined' ? globalThis : this);
