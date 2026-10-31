/*!
 * obol engine - parsers/edb.js
 * 3-stage closed-loop Exploit-DB (searchsploit) triage and script auto-adapter:
 *   Stage 0: non-stock versioned product banner -> service.version + exploit.versioned_banner
 *            (only when no dedicated vuln.* signature already matched the paste).
 *   Stage 1: searchsploit ASCII table and -j JSON parser -> filters dos/ paths, flags and
 *            demotes Metasploit modules to preserve the 1-host exam budget, scores PoCs by
 *            impact class, extension usability, and version-range match -> exploit.edb_candidate.
 *            "Exploits: No Results" mints zero facts so outcomes.js retires the dry probe.
 *   Stage 2: mirrored PoC script inspector -> extracts argparse/optparse/sys.argv CLI usage and
 *            hardcoded target/LHOST/LPORT constants, plus pre-flight static hazards:
 *            exploit.hazard_py2, exploit.hazard_burp_proxy, exploit.hazard_c_compile.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  if (!C) return;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  // Stock OS, runtime, web server, database, frontend library, and scanner baselines.
  // Subtracted in Stage 0 so routine infrastructure headers never spam searchsploit lookups.
  var _STOCK_BANNER_PRODUCT_RE = /^(?:apache(?: httpd| tomcat| coyote)?|tomcat|httpd|nginx|openresty|microsoft[- ]iis|iis|microsoft[- ]httpapi|microsoft[- ]windows(?:[- ]rpc)?|microsoft|windows(?: server| nt| rpc)?|lighttpd|caddy|gunicorn|uvicorn|werkzeug(?:\s+httpd)?|waitress|tornado|jetty|kestrel|node(?:\.js)?|express|phusion passenger|passenger|cloudflare|varnish|squid|haproxy|traefik|php|asp\.net|python|python2|python3|cpython|ruby|perl|java|openjdk|openssl|libssh2?|mod_[a-z0-9_]+|openssh|dropbear|postfix|dovecot|exim|sendmail|isc bind|bind|named|dnsmasq|unbound|msrpc|microsoft-ds|netbios-ssn|kerberos(?:-sec)?|ms-wbt-server|winrm|mysql|mariadb|postgresql|postgres|microsoft sql server|mssql|sql server|redis|memcached|mongodb|sqlite3?|openldap|ldap|wordpress|drupal|joomla|phpmyadmin|bootstrap|jquery(?: ui| migrate)?|modernizr|fontawesome|font awesome|tailwind(?:css)?|react|vue(?:\.js)?|angular(?:\.js)?|popper(?:\.js)?|lodash|moment(?:\.js)?|axios|hugo|jekyll|gatsby|next(?:\.js)?|nuxt(?:\.js)?|ubuntu|debian|centos|redhat|rhel|fedora|alpine|freebsd|openbsd|netbsd|linux(?: kernel)?|gnu|samba(?: smbd)?|smbd|nmbd|rpcbind|nfs|nmap|masscan|rustscan|nikto|whatweb|gobuster|ffuf|feroxbuster|wpscan|sqlmap|curl|wget|httpie|python-requests|python-urllib3?|mozilla|chrome|chromium|safari|gecko|applewebkit|edge|opera|http|https|ssl|tls|tlsv1|ssh|ftp|smtp|pop3|imap|tcp|udp|ip|ipv4|ipv6|version|build|release|server|client|daemon|service|welcome|copyright|powered|generator)$/i;

  function _cleanProductName(raw) {
    var s = String(raw || '')
      .replace(/\([^)]*\)/g, ' ')
      .replace(/\[[^\]]*\]/g, ' ')
      .replace(/^[\s\-:|/]+|[\s\-:|/]+$/g, '')
      .replace(/\s+/g, ' ')
      .trim();
    s = s.replace(/^(?:Welcome to|Powered by|Running)\s+/i, '').trim();
    s = s.replace(/\s+(?:v|ver\.?|version|release|build)$/i, '').trim();
    return s;
  }

  function _isStockBannerProduct(product) {
    var p = _cleanProductName(product).toLowerCase();
    if (!p || p.length < 2 || p.length > 56) return true;
    if (/^\d+(?:\.\d+)*$/.test(p)) return true;
    if (!/[a-z]/i.test(p)) return true;
    if (_STOCK_BANNER_PRODUCT_RE.test(p)) return true;
    if (/^(?:apache|nginx|openssh|microsoft|windows|linux|ubuntu|debian|php|openssl|mozilla|curl|nmap|nikto|whatweb|gobuster|ffuf|feroxbuster|wpscan|sqlmap)\b/i.test(p)
        && !/\b(?:james|ofbiz|archiva|airflow|superset|activemq|druid|guacamole|nifi|pulsar|rocketmq|roller|shiro|tapestry|wicket)\b/i.test(p)) {
      return true;
    }
    return false;
  }

  function _parseSemverTuple(verStr) {
    var m = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(String(verStr || ''));
    if (!m) return null;
    return [parseInt(m[1], 10), parseInt(m[2], 10), m[3] !== undefined ? parseInt(m[3], 10) : 0, m[3] !== undefined];
  }

  function _cmpSemver(a, b) {
    for (var i = 0; i < 3; i++) {
      var av = a[i] || 0, bv = b[i] || 0;
      if (av !== bv) return av - bv;
    }
    return 0;
  }

  function _versionScoreAgainstTitle(targetVerStr, title) {
    if (!targetVerStr || !title) return 0;
    var tv = _parseSemverTuple(targetVerStr);
    if (!tv) return 0;
    var t = String(title);
    var normTarget = tv[3] ? (tv[0] + '.' + tv[1] + '.' + tv[2]) : (tv[0] + '.' + tv[1]);
    var majMin = tv[0] + '.' + tv[1];

    // Exact version token in title
    var exactRe = new RegExp('(?:^|[^0-9.])v?' + normTarget.replace(/\./g, '\\.') + '(?![0-9.])', 'i');
    if (exactRe.test(t)) return 35;

    // Wildcard like 1.4.x or 7.x
    var wildMinRe = new RegExp('(?:^|[^0-9.])v?' + tv[0] + '\\.' + tv[1] + '\\.x\\b', 'i');
    var wildMajRe = new RegExp('(?:^|[^0-9.])v?' + tv[0] + '\\.x\\b', 'i');
    if (wildMinRe.test(t)) return 26;
    if (wildMajRe.test(t)) return 18;

    // Range like 1.2.0 - 1.5.0 or 1.2 to 1.5
    var rangeM = /(?:^|[^0-9.])v?(\d+\.\d+(?:\.\d+)?)\s*(?:-|to|through)\s*v?(\d+\.\d+(?:\.\d+)?)/i.exec(t);
    if (rangeM) {
      var lo = _parseSemverTuple(rangeM[1]), hi = _parseSemverTuple(rangeM[2]);
      if (lo && hi) {
        return (_cmpSemver(tv, lo) >= 0 && _cmpSemver(tv, hi) <= 0) ? 28 : -25;
      }
    }

    // Inequality like < 7.2.5, <= 7.2.1, prior to 7.3, before 2.4.0
    var cmpM = /(<=|<|prior to|before)\s*v?(\d+\.\d+(?:\.\d+)?)/i.exec(t);
    if (cmpM) {
      var bound = _parseSemverTuple(cmpM[2]);
      if (bound) {
        var c = _cmpSemver(tv, bound);
        var inclusive = cmpM[1] === '<=';
        return (inclusive ? c <= 0 : c < 0) ? 28 : -28;
      }
    }

    // Major.minor match when title only lists 2-part version
    var mmRe = new RegExp('(?:^|[^0-9.])v?' + majMin.replace(/\./g, '\\.') + '(?![0-9.])', 'i');
    if (mmRe.test(t)) return 22;

    // If title explicitly names a different version of the same product, slightly demote
    if (/\b\d+\.\d+(?:\.\d+)?\b/.test(t)) return -10;
    return 0;
  }

  function _langFromExt(ext) {
    var e = String(ext || '').toLowerCase();
    var map = {
      py: 'python', sh: 'bash', bash: 'bash', c: 'c', cpp: 'cpp', cc: 'cpp',
      rb: 'ruby', php: 'php', pl: 'perl', txt: 'text', md: 'text',
      ps1: 'powershell', js: 'javascript', html: 'html', java: 'java', go: 'go'
    };
    return map[e] || e || 'unknown';
  }

  function _scoreEdbCandidate(cand, targetVersion) {
    var title = cand.title || '';
    var ext = cand.ext || '';
    var score = 0;

    if (/\b(?:Remote Code Execution|RCE|Command Injection|OS Command|Command Execution|Arbitrary File Upload|Unrestricted File Upload|Code Execution|Deserialization|Object Injection|Eval Injection|Template Injection|SSTI|Backdoor)\b/i.test(title)) {
      score += 100;
    } else if (/\b(?:Auth(?:entication)? Bypass|SQL Injection|SQLi|Local File Inclusion|LFI|Remote File Inclusion|RFI|Arbitrary File Read|Directory Traversal|Path Traversal|XXE|SSRF|File Disclosure|Credential|Password Reset)\b/i.test(title)) {
      score += 65;
    } else if (/\b(?:Privilege Escalation|PrivEsc|Local Root|SUID|Kernel)\b/i.test(title)) {
      score += 35;
    } else {
      score += 10;
    }

    if (/\b(?:Unauth(?:enticated)?|Pre-?Auth)\b/i.test(title)) {
      score += 25;
    } else if (/\b(?:Auth(?:enticated)?|\(Auth\)|Post-?Auth|Admin(?:istrator)? Only)\b/i.test(title)) {
      score -= 18;
    }

    if (/\b(?:Denial of Service|DoS|Crash)\b/i.test(title) && !/\b(?:RCE|Code Execution|Command)\b/i.test(title)) {
      score -= 70;
    }

    var extBonus = { py: 25, sh: 22, txt: 20, md: 18, php: 18, pl: 14, ps1: 14, js: 14, c: 12, cpp: 11, rb: 10 };
    score += (extBonus[ext] || 5);

    if (cand.verified) score += 8;
    if (cand.metasploit) score -= 85;
    score += _versionScoreAgainstTitle(targetVersion, title);

    return score;
  }

  var _EDB_REL_PATH_RE = /((?:\/usr\/share\/exploitdb\/exploits\/|exploits\/)?(?:[a-z0-9_+-]+\/)+(?:webapps|remote|local|dos|platform|shellcodes)\/(\d+)\.([a-z0-9]+))\s*$/i;

  function _looks_like_searchsploit(text, command) {
    var t = String(text || '');
    var cmd = String(command || '');
    if (!t.trim()) return false;
    var isExamineOrMirror = /\bsearchsploit\b[^\r\n]*\s(?:-[a-zA-Z]*[xm]|--examine|--mirror)\b/i.test(cmd);
    if (/Exploit Title\s+\|\s+Path/i.test(t)) return true;
    if (/Exploits:\s*No Results/i.test(t)) return true;
    if (/"RESULTS_EXPLOIT"\s*:\s*\[/i.test(t)) return true;
    if (/\bsearchsploit\b/i.test(cmd) && !isExamineOrMirror) return true;
    if (t.indexOf('|') >= 0 && /^\s*[^|\r\n]{5,140}\|\s*(?:\/usr\/share\/exploitdb\/exploits\/|exploits\/)?[a-z0-9_+-]+\/(?:webapps|remote|local|dos|platform)\/\d+\.[a-z0-9]+\s*$/im.test(t)) {
      return true;
    }
    return false;
  }

  function _discoverTargetVersion(command, facts, ws) {
    var mCmd = /\bsearchsploit\b[^\r\n]*?\b(\d+\.\d+(?:\.\d+)?)\b/i.exec(String(command || ''));
    if (mCmd) return mCmd[1];
    var pools = [facts || [], (ws && ws.seedFacts) || []];
    for (var pi = 0; pi < pools.length; pi++) {
      var list = pools[pi];
      for (var i = 0; i < list.length; i++) {
        var f = list[i];
        if (!f || !f.value) continue;
        if ((f.kind === 'exploit.versioned_banner' || f.kind === 'service.version' || f.kind === 'web.tech') && f.value.version) {
          var mv = /(\d+\.\d+(?:\.\d+)?)/.exec(String(f.value.version));
          if (mv) return mv[1];
        }
      }
    }
    return '';
  }

  // ---- Stage 1: searchsploit ASCII table and -j JSON parser ----
  function _parse_searchsploit(text, ws, command, source, facts) {
    var t = String(text || '');
    if (!t.trim()) return;
    var targetVer = _discoverTargetVersion(command, facts, ws);
    var rawCandidates = [];
    var seenIds = {};

    // 1. JSON mode (searchsploit -j)
    if (t.indexOf('"RESULTS_EXPLOIT"') >= 0) {
      var jsonStart = t.indexOf('{');
      var jsonEnd = t.lastIndexOf('}');
      if (jsonStart >= 0 && jsonEnd > jsonStart) {
        try {
          var parsed = JSON.parse(t.slice(jsonStart, jsonEnd + 1));
          var arr = Array.isArray(parsed.RESULTS_EXPLOIT) ? parsed.RESULTS_EXPLOIT : [];
          for (var ji = 0; ji < arr.length; ji++) {
            var item = arr[ji] || {};
            var jTitle = String(item.Title || '').trim();
            var jPath = String(item.Path || item['EDB-ID'] || '').trim();
            var jType = String(item.Type || '').toLowerCase();
            if (jType === 'dos' || /(?:^|\/)dos\//i.test(jPath)) continue;
            var pm = /(\d+)\.([a-z0-9]+)$/i.exec(jPath);
            var jId = String(item['EDB-ID'] || (pm && pm[1]) || '').trim();
            var jExt = pm ? pm[2].toLowerCase() : 'txt';
            if (!jId || !jTitle || seenIds[jId]) continue;
            seenIds[jId] = 1;
            var normPath = jPath.replace(/^.*?\/exploits\//, '');
            var isMsfJ = /\(Metasploit\)|\bMetasploit\b/i.test(jTitle) || (jExt === 'rb' && /metasploit/i.test(jPath));
            rawCandidates.push({
              edb_id: jId,
              edb_file: jId + '.' + jExt,
              edb_path: normPath || (jId + '.' + jExt),
              ext: jExt,
              lang: _langFromExt(jExt),
              title: jTitle,
              metasploit: isMsfJ,
              verified: String(item.Verified || '') === '1' || item.Verified === true
            });
          }
          if (!rawCandidates.length) return;
        } catch (_e) {
          // fall through to line parser if JSON was partial
        }
      }
    }

    // 2. Standard ASCII table mode
    if (!rawCandidates.length) {
      var inShellcodes = false;
      var lines = t.split(/\r?\n/);
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        if (/^\s*Shellcodes:\s/i.test(line) || /^\s*Shellcode Title\s+\|/i.test(line)) {
          inShellcodes = true;
          continue;
        }
        if (/^\s*Exploits:\s/i.test(line) || /^\s*Exploit Title\s+\|/i.test(line)) {
          inShellcodes = false;
          continue;
        }
        if (inShellcodes || line.indexOf('|') < 0) continue;
        var sepIdx = line.lastIndexOf('|');
        var leftTitle = line.slice(0, sepIdx).trim();
        var rightPath = line.slice(sepIdx + 1).trim();
        if (!leftTitle || !rightPath || /^Exploit Title$/i.test(leftTitle) || /^[-=+]+$/.test(leftTitle)) continue;
        var mPath = _EDB_REL_PATH_RE.exec(rightPath);
        if (!mPath) continue;
        var fullRel = mPath[1];
        var edbId = mPath[2];
        var ext = mPath[3].toLowerCase();
        if (/(?:^|\/)dos\//i.test(fullRel) || /(?:^|\/)shellcodes\//i.test(fullRel)) continue;
        if (seenIds[edbId]) continue;
        seenIds[edbId] = 1;
        var cleanRel = fullRel.replace(/^.*?\/exploits\//, '');
        var isMsf = /\(Metasploit\)|\bMetasploit\b/i.test(leftTitle) || (ext === 'rb' && /metasploit/i.test(fullRel));
        rawCandidates.push({
          edb_id: edbId,
          edb_file: edbId + '.' + ext,
          edb_path: cleanRel,
          ext: ext,
          lang: _langFromExt(ext),
          title: leftTitle,
          metasploit: isMsf,
          verified: false
        });
      }
    }

    // Dry probe ("Exploits: No Results" or only dos/ entries filtered out): mint zero facts.
    if (!rawCandidates.length) return;

    for (var ci = 0; ci < rawCandidates.length; ci++) {
      rawCandidates[ci].score = _scoreEdbCandidate(rawCandidates[ci], targetVer);
    }
    rawCandidates.sort(function (a, b) {
      if (b.score !== a.score) return b.score - a.score;
      return parseInt(b.edb_id, 10) - parseInt(a.edb_id, 10);
    });

    var metasploitOnly = rawCandidates.every(function (c) { return !!c.metasploit; });
    var top = rawCandidates[0];
    var h = 'host:' + ws.target;
    _add(facts, mkFact('exploit.edb_candidate', h, {
      edb_id: top.edb_id,
      edb_file: top.edb_file,
      edb_path: top.edb_path,
      lang: top.lang,
      title: top.title,
      metasploit_only: metasploitOnly,
      candidates: rawCandidates.slice(0, 8).map(function (c) {
        return {
          edb_id: c.edb_id,
          edb_file: c.edb_file,
          edb_path: c.edb_path,
          lang: c.lang,
          title: c.title,
          metasploit: c.metasploit,
          score: c.score
        };
      })
    }, S, source));
  }

  // ---- Stage 2: Mirrored Exploit-DB script inspector & pre-flight hazard detector ----
  var _EDB_HEADER_RE = /(?:^|\n)\s*(?:#|\/\/|\/\*+|\*|--|REM\b)\s*(?:Exploit Title|EDB-ID|Exploit-DB|Exploit Author)\s*:/i;
  var _EDB_CANONICAL_META_RE = /(?:^|\n)[ \t]*(?:#|\/\/|\/\*+|\*|--|REM\b)[ \t]*(Exploit Title|Exploit Author|Date|Vendor Homepage|Software Link|Version|Tested on|CVE|EDB-ID)[ \t]*:/gi;
  var _LEGACY_POC_META_RE = /(?:^|\n)[ \t]*(?:#|\/\/|\/\*+|\*|--|REM\b)[ \t]*(?:CVE[ \t]*[:=-]?[ \t]*CVE-\d{4}-\d{4,7}|[^\r\n]*\bCVE-\d{4}-\d{4,7}\b)/i;
  var _LEGACY_POC_AUTHOR_SW_RE = /(?:^|\n)[ \t]*(?:#|\/\/|\/\*+|\*)[ \t]*Author[ \t]*:[\s\S]{0,240}?(?:^|\n)[ \t]*(?:#|\/\/|\/\*+|\*)[ \t]*(?:Software|Vendor|Affected|Vulnerable|Vulnerability|Advisory|Tested\s+on)[ \t]*:/i;
  var _LEGACY_POC_EXPLOIT_IND_RE = /\b(?:urllib2|requests|httplib|http\.client|cookielib|socket|argparse|optparse|sys\.argv|pwntools|shellcode|payload|exploit)\b/i;
  var _EDB_INSPECT_CMD_RE = /\b(?:head|cat|bat|batcat|less|more|nl|sed|awk|grep|egrep|rg|searchsploit\s+(?:-[a-zA-Z]*x|--examine))\b[^\r\n]*?\b(\d{4,6})\.(py|sh|c|cpp|cc|rb|php|pl|txt|md|ps1|js|java)\b/i;
  var _EDB_EXAMINE_BARE_CMD_RE = /\bsearchsploit\s+(?:-[a-zA-Z]*x|--examine)\s+(?:\S*\/)?(\d{3,6})(?:\.(py|sh|c|cpp|cc|rb|php|pl|txt|md|ps1|js|java))?\b/i;
  var _SCRIPT_BODY_HINT_RE = /(?:^#!\/|^\s*(?:import|from)\s+[A-Za-z0-9_.]+|^\s*#include\s*[<"]|\bargparse\.ArgumentParser\b|\bsys\.argv\[|\brequests\.(?:get|post|put|Session)\b|\burllib2?\b|\bcurl\s+-|\bjavac\s+|\bint\s+main\s*\(|\bfunction\s+[A-Za-z_])/m;

  function _countEdbCanonicalHeaders(t) {
    var seen = {}, count = 0;
    var matches = C.reAll(_EDB_CANONICAL_META_RE, t);
    for (var i = 0; i < matches.length; i++) {
      var k = String(matches[i][1] || '').toLowerCase();
      if (k && !seen[k]) { seen[k] = 1; count++; }
    }
    return count;
  }

  function _detectPythonStringSyntaxHazard(text, command) {
    var s = String(text || '').replace(/\r\n/g, '\n');
    var cmdStr = String(command || '');
    var headM = /\bhead\b[^\r\n]*?(?:-n\s*|-)(\d+)\b/i.exec(cmdStr);
    var headLimit = headM ? parseInt(headM[1], 10) : (/\bhead\b/i.test(cmdStr) ? 10 : 0);
    var lineCount = s.replace(/\n$/, '').split('\n').length;
    var maybeTruncated = !!(headLimit > 0 && lineCount >= headLimit);
    var i = 0, n = s.length, line = 1;
    var quote = null, openLine = 1;
    while (i < n) {
      var ch = s[i];
      if (!quote) {
        if (ch === '\n') { line++; i++; continue; }
        if (ch === '#') {
          while (i < n && s[i] !== '\n') i++;
          continue;
        }
        if (ch === '"' || ch === "'") {
          var q3 = ch + ch + ch;
          if (s.slice(i, i + 3) === q3) {
            quote = q3; openLine = line; i += 3;
          } else {
            quote = ch; openLine = line; i += 1;
          }
          continue;
        }
        i++;
      } else if (quote.length === 3) {
        if (ch === '\n') { line++; i++; continue; }
        if (ch === '\\') {
          if (i + 1 < n && s[i + 1] === '\n') line++;
          i += 2;
          continue;
        }
        if (s.slice(i, i + 3) === quote) {
          quote = null; i += 3; continue;
        }
        i++;
      } else {
        if (ch === '\\') {
          if (i + 1 < n && s[i + 1] === '\n') { line++; i += 2; continue; }
          i += 2;
          continue;
        }
        if (ch === '\n') {
          return { issue: 'unterminated_string_newline', line: openLine, quote: quote };
        }
        if (ch === quote) {
          quote = null; i++; continue;
        }
        i++;
      }
    }
    if (quote && !maybeTruncated) {
      return { issue: quote.length === 3 ? 'unterminated_triple_quote' : 'unterminated_string_eof', line: openLine, quote: quote };
    }
    return null;
  }

  function _is_scanner_or_nmap_report(t, cmd) {
    if (cmd && /\b(?:nmap|rustscan|masscan|nikto|wpscan|nuclei)\b/i.test(cmd)) return true;
    if (/<nmaprun\b/i.test(t)) return true;
    if ((/^\s*Nmap scan report for\b|^\s*PORT\s+STATE\s+SERVICE\b/im.test(t)) && /^\s*\d+\/(?:tcp|udp)\s+open\s/im.test(t)) return true;
    if (/^\s*\d+\/(?:tcp|udp)\s+open\s/im.test(t) && /^[ \t]*\|[_ ][A-Za-z0-9_.-]+:/m.test(t)) return true;
    return false;
  }

  function _looks_like_edb_script(text, command) {
    var t = String(text || '');
    if (!/\S/.test(t)) return false;
    var cmd = String(command || '');
    var hasCmd = /\S/.test(cmd);
    var cmdIsInspect = hasCmd && (_EDB_INSPECT_CMD_RE.test(cmd) || _EDB_EXAMINE_BARE_CMD_RE.test(cmd));
    if (!cmdIsInspect) {
      if (_is_scanner_or_nmap_report(t, cmd)) return false;
      if (hasCmd) {
        if (!/exploit|edb-id/i.test(t)) return false;
      } else {
        if (!/exploit|edb-id|cve-\d{4}-|author[ \t]*:/i.test(t)) return false;
      }
    }
    // Do not misclassify a searchsploit results table, HTTP response, or a bare searchsploit -m receipt without code
    if (/Exploit Title\s+\|\s+Path/i.test(t) || /"RESULTS_EXPLOIT"\s*:\s*\[/i.test(t) || /Exploits:\s*No Results/i.test(t)) {
      return false;
    }
    if (/^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(t) || /<!doctype\s+html|<html[\s>]/i.test(t)) {
      return false;
    }
    if (cmdIsInspect) return true;
    if (_EDB_HEADER_RE.test(t) && (_SCRIPT_BODY_HINT_RE.test(t) || /\bUsage\s*:/i.test(t) || /CVE-\d{4}-\d+/i.test(t) || _countEdbCanonicalHeaders(t) >= 2)) {
      // Exclude bare 6-line `searchsploit -m` summary output when no script lines follow
      if (/^\s*Exploit:\s+[^\r\n]+\r?\n\s*URL:\s+https?:\/\/www\.exploit-db\.com\/exploits\/\d+/i.test(t) && !_SCRIPT_BODY_HINT_RE.test(t)) {
        return false;
      }
      return true;
    }
    if (/https?:\/\/(?:www\.)?exploit-db\.com\/exploits\/\d+/i.test(t) && _SCRIPT_BODY_HINT_RE.test(t)) {
      return true;
    }
    if (!hasCmd && (_LEGACY_POC_META_RE.test(t) || _LEGACY_POC_AUTHOR_SW_RE.test(t)) && _SCRIPT_BODY_HINT_RE.test(t) && _LEGACY_POC_EXPLOIT_IND_RE.test(t)) {
      return true;
    }
    return false;
  }

  function _inferTargetArchAndOs(facts, ws, text) {
    var os = '', arch = '';
    if (/^\s*#include\s*<(?:windows|winsock2|ws2tcpip|tlhelp32)\.h>/im.test(text)) os = 'windows';
    var pools = [facts || [], (ws && ws.seedFacts) || []];
    for (var pi = 0; pi < pools.length; pi++) {
      var list = pools[pi];
      for (var i = 0; i < list.length; i++) {
        var f = list[i];
        if (!f) continue;
        if (!os) {
          if (f.kind === 'foothold.windows' || f.kind === 'os.windows') os = 'windows';
          else if (f.kind === 'foothold.linux' || f.kind === 'os.linux') os = 'linux';
          else if (f.kind === 'host.os_family' && f.value && f.value.family) os = String(f.value.family).toLowerCase();
        }
        if (!arch && f.value) {
          var raw = JSON.stringify(f.value);
          if (/\b(?:i[3456]86|x86_32|32-bit)\b/i.test(raw)) arch = 'x86';
          else if (/\b(?:x86_64|amd64|64-bit)\b/i.test(raw)) arch = 'x86_64';
          else if (/\b(?:aarch64|arm64)\b/i.test(raw)) arch = 'arm64';
        }
      }
    }
    return { os: os || 'linux', arch: arch || 'x86_64' };
  }

  function _parse_edb_script(text, ws, command, source, facts) {
    var t = String(text || '');
    var cmd = String(command || '');
    if (!t.trim()) return;
    if (!(cmd && (_EDB_INSPECT_CMD_RE.test(cmd) || _EDB_EXAMINE_BARE_CMD_RE.test(cmd))) && _is_scanner_or_nmap_report(t, cmd)) return;

    var edbId = '', edbFile = '', ext = '';
    var mCmd = _EDB_INSPECT_CMD_RE.exec(cmd);
    if (mCmd) {
      edbId = mCmd[1];
      ext = mCmd[2].toLowerCase();
      edbFile = edbId + '.' + ext;
    } else {
      var mExam = _EDB_EXAMINE_BARE_CMD_RE.exec(cmd);
      if (mExam) {
        edbId = mExam[1];
        if (mExam[2]) {
          ext = mExam[2].toLowerCase();
          edbFile = edbId + '.' + ext;
        }
      }
    }
    if (!edbFile) {
      var mCopy = /Copied to:\s*(?:\S*\/)?(\d{4,6})\.([a-z0-9]+)/i.exec(t);
      if (mCopy) {
        edbId = mCopy[1];
        ext = mCopy[2].toLowerCase();
        edbFile = edbId + '.' + ext;
      }
    }
    if (!edbId) {
      var mUrl = /exploit-db\.com\/exploits\/(\d{3,6})/i.exec(t) || /EDB-ID\s*:\s*(\d{3,6})/i.exec(t);
      if (mUrl) edbId = mUrl[1];
    }

    var lang = ext ? _langFromExt(ext) : '';
    if (!lang) {
      if (/^#!\/[^\r\n]*python/im.test(t) || /^\s*(?:import|from)\s+(?:requests|urllib2?|sys|argparse|socket|pwntools|pwn)\b/m.test(t)) {
        lang = 'python'; ext = 'py';
      } else if (/^\s*#include\s*<(?:stdio|stdlib|unistd|sys\/|windows|pthread)/m.test(t)) {
        lang = 'c'; ext = 'c';
      } else if (/^#!\/[^\r\n]*(?:bash|\/sh)\b/im.test(t)) {
        lang = 'bash'; ext = 'sh';
      } else if (/^<\?php\b/im.test(t)) {
        lang = 'php'; ext = 'php';
      } else if (/^#!\/[^\r\n]*ruby/im.test(t) || /\bclass\s+MetasploitModule\b/.test(t)) {
        lang = 'ruby'; ext = 'rb';
      } else {
        lang = 'text'; ext = 'txt';
      }
    }
    if (!edbFile) edbFile = (edbId || 'exploit') + '.' + (ext || 'py');

    // Extract CLI flags from argparse / optparse / getopt
    var cliFlags = [];
    var seenFlag = {};
    var argBlocks = C.reAll(/add_(?:argument|option)\s*\(([^)]+)\)/g, t);
    for (var ai = 0; ai < argBlocks.length; ai++) {
      var fmAll = C.reAll(/['"](--?[A-Za-z0-9][A-Za-z0-9_-]*)['"]/g, argBlocks[ai][1]);
      for (var fi = 0; fi < fmAll.length; fi++) {
        var fl = fmAll[fi][1];
        if (!seenFlag[fl]) { seenFlag[fl] = 1; cliFlags.push(fl); }
      }
    }

    // Extract Usage: line and sys.argv[1..N]
    var usageM = /[Uu]sage\s*:\s*([^\r\n"'`]{4,140})/.exec(t);
    var usageLine = usageM ? usageM[1].trim() : '';
    var argvMatches = C.reAll(/\bsys\.argv\[\s*(\d+)\s*\]/g, t);
    var maxArgv = 0;
    for (var vi = 0; vi < argvMatches.length; vi++) {
      var idx = parseInt(argvMatches[vi][1], 10);
      if (idx > maxArgv && idx <= 16) maxArgv = idx;
    }

    // Extract hardcoded author target/callback constants
    var hardcoded = [];
    var seenConst = {};
    var codeLines = t.split(/\r?\n/);
    var uncommentedLines = [];
    for (var li = 0; li < codeLines.length; li++) {
      var rawLine = codeLines[li];
      var trimmed = rawLine.trim();
      if (!trimmed || /^(?:#|\/\/|\*|\/\*|--|REM\b)/i.test(trimmed)) continue;
      uncommentedLines.push(rawLine);
      var cm = /^\s*(\$)?([A-Za-z_][A-Za-z0-9_]{1,24})\s*=\s*(['"][^'"\r\n]{1,120}['"]|\d{2,5})\s*(?:;|#.*|\/\/.*)?$/.exec(rawLine);
      if (cm) {
        var hasDollar = !!cm[1];
        var cname = cm[2];
        var cval = cm[3];
        if (/^(?:target|target_url|target_ip|base_url|url|host|rhost|rport|victim|victim_ip|lhost|lport|attacker|attacker_ip|srvhost|srvport)$/i.test(cname)) {
          var ckey = cname.toLowerCase();
          if (!seenConst[ckey]) {
            seenConst[ckey] = 1;
            hardcoded.push({ name: cname, value: cval.replace(/^['"]|['"]$/g, ''), numeric: /^\d+$/.test(cval), dollar: hasDollar });
          }
        }
      }
    }
    var activeCode = uncommentedLines.join('\n');
    var h = 'host:' + ws.target;
    var hazards = [];

    // Hazard 1: Python 2 syntax or stdlib modules
    var isPythonish = lang === 'python' || /^#!\/[^\r\n]*python/im.test(t) || /^\s*(?:import|from)\s+[A-Za-z0-9_.]+\b/m.test(activeCode);
    if (isPythonish) {
      var py2Indicators = [];
      if (/^#!\/[^\r\n]*python2\b/im.test(t)) py2Indicators.push('python2_shebang');
      if (/^\s*print\s+(?!\()(?:["']|r["']|[A-Za-z_][A-Za-z0-9_.]*(?:\s*[%+,]|\s*$))/m.test(activeCode)) {
        py2Indicators.push('print_statement');
      }
      var py2ModM = /^\s*(?:import\s+(urllib2|cookielib|urlparse|httplib|Queue|commands|cPickle|ConfigParser|SocketServer)\b|from\s+(urllib2|cookielib|urlparse|httplib|Queue|commands|cPickle|ConfigParser|SocketServer)\s+import\b)/m.exec(activeCode);
      if (py2ModM) py2Indicators.push('import_' + (py2ModM[1] || py2ModM[2]));
      if (/\braw_input\s*\(/.test(activeCode)) py2Indicators.push('raw_input');
      if (/^\s*except\s+[A-Za-z_][A-Za-z0-9_.() ]*\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*:/m.test(activeCode)) {
        py2Indicators.push('except_comma');
      }
      if (py2Indicators.length) {
        hazards.push('py2');
        _add(facts, mkFact('exploit.hazard_py2', h, {
          edb_file: edbFile,
          indicators: py2Indicators,
          fix_cmd: '2to3 -w ' + edbFile + ' && dos2unix ' + edbFile + " && sed -i '1i # -*- coding: utf-8 -*-' " + edbFile
        }, S, source));
      }
    }

    // Hazard 2: Hardcoded Burp / debug proxy left in active code
    var proxyM = /\bproxies\s*=\s*\{[^}]*?(https?:\/\/(?:127\.0\.0\.1|localhost):(?:8080|8081|8000|8888)\/?)/i.exec(activeCode)
      || /\bproxy\s*=\s*['"](https?:\/\/(?:127\.0\.0\.1|localhost):(?:8080|8081)\/?)['"]/i.exec(activeCode);
    if (proxyM) {
      hazards.push('burp_proxy');
      _add(facts, mkFact('exploit.hazard_burp_proxy', h, {
        edb_file: edbFile,
        proxy: proxyM[1],
        sed_cmd: "sed -i -E 's/,?[[:space:]]*proxies[[:space:]]*=[[:space:]]*[^,)]+//g; s/^[[:space:]]*proxies[[:space:]]*=[[:space:]]*\\{[^}]*\\}/proxies = {}/g' " + edbFile
      }, S, source));
    }

    // Hazard 3: C / C++ exploit requiring architecture/glibc-matched compilation
    var isCSource = lang === 'c' || lang === 'cpp' || /^\s*#include\s*<(?:stdio|stdlib|unistd|sys\/|windows|winsock2|pthread|openssl)/m.test(t);
    if (isCSource) {
      hazards.push('c_compile');
      var gccCommentM = /((?:[A-Za-z0-9_-]*gcc|g\+\+|clang)\s+[^\r\n*`]+?)(?:\*\/|\r|\n|$)/i.exec(t);
      var gccComment = gccCommentM ? gccCommentM[1].trim() : '';
      var extraFlags = [];
      ['-pthread', '-lpthread', '-lcrypt', '-lssl', '-lcrypto', '-ldl', '-lutil', '-lrt', '-m32', '-static', '-lws2_32'].forEach(function (fl) {
        if (gccComment.indexOf(fl) >= 0) extraFlags.push(fl);
      });
      if (!extraFlags.length && /#include\s*<pthread\.h>/.test(t)) extraFlags.push('-pthread');
      if (/#include\s*<crypt\.h>/.test(t) && extraFlags.indexOf('-lcrypt') < 0) extraFlags.push('-lcrypt');
      var envInfo = _inferTargetArchAndOs(facts, ws, t);
      var recCompiler = 'gcc';
      var recFlags = [];
      if (envInfo.os === 'windows') {
        recCompiler = envInfo.arch === 'x86' ? 'i686-w64-mingw32-gcc' : 'x86_64-w64-mingw32-gcc';
      } else {
        if (envInfo.arch === 'x86' && extraFlags.indexOf('-m32') < 0) recFlags.push('-m32');
        if (extraFlags.indexOf('-static') < 0) recFlags.push('-static');
      }
      extraFlags.forEach(function (fl) { if (recFlags.indexOf(fl) < 0) recFlags.push(fl); });
      var outBin = (edbId ? ('edb_' + edbId) : 'exploit_bin') + (envInfo.os === 'windows' ? '.exe' : '');
      var recCmd = recCompiler + ' ' + recFlags.join(' ') + (recFlags.length ? ' ' : '') + edbFile + ' -o ' + outBin;
      _add(facts, mkFact('exploit.hazard_c_compile', h, {
        edb_file: edbFile,
        gcc_comment: gccComment,
        flags: recFlags,
        target_os: envInfo.os,
        target_arch: envInfo.arch,
        compile_cmd: recCmd
      }, S, source));
    }

    // Hazard 4: Brittle client-side version-string gate / early exit
    var verGateM = /\b(?:this instance is patched|target is (?:patched|not vulnerable)|is not vulnerable|not a vulnerable version|version[^\r\n"']{0,40}not (?:vulnerable|supported))\b/i.exec(activeCode);
    if (verGateM && /\b(?:version|ver|banner|release|split|replace|startswith|compare)\b/i.test(activeCode)) {
      hazards.push('version_gate');
      _add(facts, mkFact('exploit.hazard_version_gate', h, {
        edb_file: edbFile,
        indicator: verGateM[0],
        note: 'script contains a client-side version comparison gate that may exit early on multi-part or backported versions'
      }, S, source));
    }

    // Hazard 5: Unterminated multi-line string literal in Python 3 PoC
    if (isPythonish) {
      var py3StrHaz = _detectPythonStringSyntaxHazard(t, cmd);
      if (py3StrHaz) {
        hazards.push('py3_syntax');
        _add(facts, mkFact('exploit.hazard_py3_syntax', h, {
          edb_file: edbFile,
          issue: py3StrHaz.issue,
          line: py3StrHaz.line,
          check_cmd: 'python3 -m py_compile ' + edbFile
        }, S, source));
      }
    }

    // Hazard 6: Retired javac -source / -target 1.[567] flags rejected by modern JDKs
    var javacM = /\bjavac\b[^\r\n]*?(?:-(?:source|target)\s+(?:1\.[567]|[567])\b)/i.exec(activeCode);
    if (javacM) {
      hazards.push('java_target');
      _add(facts, mkFact('exploit.hazard_java_target', h, {
        edb_file: edbFile,
        javac_cmd: javacM[0].trim(),
        fix_cmd: "sed -i -E 's/-(source|target)[[:space:]]+(1\\.[567]|[567])/-\\1 8/g' " + edbFile
      }, S, source));
    }

    var workingCopy = /\.[A-Za-z0-9]+$/.test(edbFile)
      ? edbFile.replace(/(\.[A-Za-z0-9]+)$/, '_obol$1')
      : (edbFile + '_obol');
    var needsConstPatch = hardcoded.length > 0 && cliFlags.length === 0 && maxArgv === 0 && !isCSource;
    var stripBurpProxy = hazards.indexOf('burp_proxy') >= 0 && !isCSource;
    var patchPlan = {
      needs_patch: !!(needsConstPatch || stripBurpProxy),
      needs_const_patch: !!needsConstPatch,
      strip_burp_proxy: !!stripBurpProxy,
      working_copy: workingCopy,
      hardcoded: hardcoded,
      cli_flags: cliFlags,
      sys_argv_count: maxArgv
    };

    _add(facts, mkFact('exploit.script_inspected', h, {
      edb_id: edbId || null,
      edb_file: edbFile,
      lang: lang,
      cli_flags: cliFlags,
      usage: usageLine,
      sys_argv_count: maxArgv,
      hardcoded_constants: hardcoded,
      hazards: hazards,
      patch_plan: patchPlan
    }, S, source));
    _add(facts, mkFact('vuln.edb_poc_inspected', h, {
      edb_id: edbId || null,
      edb_file: edbFile,
      lang: lang,
      lead: true
    }, S, source));
  }

  // ---- Stage 0: Versioned non-stock product banner -> dynamic searchsploit trigger ----
  var _PROD_WORD_SRC = '[A-Za-z][A-Za-z0-9_.+-]*(?:\\/(?!v?\\d+\\.\\d+)[A-Za-z0-9_.+-]+)*';
  var _PROD_VER_SEP_SRC = '(?:[ \\t]*\\/[ \\t]*(?=v?\\d+\\.\\d+)|[ \\t]+(?:(?:Version|ver\\.?)[ \\t:]+)?|[ \\t]*:[ \\t]*(?=v?\\d+\\.\\d+))';
  var _PROD_VER_STR_RE = new RegExp('^(' + _PROD_WORD_SRC + '(?:[ \\t-]+' + _PROD_WORD_SRC + '){0,5}?)' + _PROD_VER_SEP_SRC + 'v?(\\d+\\.\\d+(?:\\.\\d+)*(?:[-a-zA-Z0-9.]*)?)\\b', 'i');
  var _SLASH_BANNER_TOK_RE = new RegExp('(' + _PROD_WORD_SRC + '(?:[ -]' + _PROD_WORD_SRC + '){0,2})\\/v?(\\d+\\.\\d+(?:\\.\\d+)*(?:[-a-zA-Z0-9.]*)?)\\b', 'g');

  function _extractProdVerFromStr(str) {
    var s = String(str || '').trim();
    if (!s) return null;
    var m = _PROD_VER_STR_RE.exec(s);
    if (!m) return null;
    var prod = _cleanProductName(m[1]);
    var ver = m[2];
    if (_isStockBannerProduct(prod)) return null;
    return { product: prod, version: ver };
  }

  function _parse_versioned_banner_for_edb(text, ws, command, source, facts) {
    var t = String(text || '');
    if (!/\S/.test(t)) return;
    if (_looks_like_searchsploit(t, command) || _looks_like_edb_script(t, command)) return;
    if (!Array.isArray(facts)) return;

    // Yield cleanly whenever a dedicated CVE/product move (vuln.*) or WordPress scanner already covers this paste
    for (var fi = 0; fi < facts.length; fi++) {
      var fk = facts[fi] && facts[fi].kind;
      if (!fk) continue;
      if (/^vuln\./.test(fk) || fk === 'exploit.edb_candidate' || fk === 'exploit.script_inspected' || fk === 'exploit.versioned_banner') {
        return;
      }
    }

    var candidates = [];
    var seenKey = {};
    function pushCandidate(prod, ver) {
      var p = _cleanProductName(prod);
      var v = String(ver || '').trim().replace(/^v/i, '');
      if (!p || !v || !/^\d+\.\d+/.test(v)) return;
      if (_isStockBannerProduct(p)) return;
      var k = p.toLowerCase() + '@' + v.toLowerCase();
      if (seenKey[k]) return;
      seenKey[k] = 1;
      var mm = /^(\d+\.\d+)/.exec(v);
      candidates.push({
        product: p,
        version: v,
        search_query: p + ' ' + (mm ? mm[1] : v)
      });
    }

    function pushHeaderCandidates(rawHdr) {
      var hdrVal = String(rawHdr || '').replace(/\([^)]*\)/g, ' ').trim();
      if (!hdrVal) return;
      var slashTokens = C.reAll(_SLASH_BANNER_TOK_RE, hdrVal);
      for (var sti = 0; sti < slashTokens.length; sti++) {
        pushCandidate(slashTokens[sti][1], slashTokens[sti][2]);
      }
      var spv = _extractProdVerFromStr(hdrVal);
      if (spv) pushCandidate(spv.product, spv.version);
    }

    // 1. Inspect already-parsed facts (web.tech, service.*, web.server, ftp.banner, ssh.banner)
    for (var i = 0; i < facts.length; i++) {
      var f = facts[i];
      if (!f || !f.value) continue;
      var val = f.value;
      if (f.kind === 'web.tech') {
        if (typeof val.product === 'string' && val.product && val.version) pushCandidate(val.product, val.version);
        if (typeof val.name === 'string' && val.name && val.version) pushCandidate(val.name, val.version);
        if (Array.isArray(val.items)) {
          for (var ii = 0; ii < val.items.length; ii++) {
            var it = val.items[ii] || {};
            var pv = _extractProdVerFromStr(it.value || '');
            if (pv) pushCandidate(pv.product, pv.version);
            else if (typeof it.name === 'string' && it.name && it.value && /^\d+\.\d+/.test(String(it.value).trim())) {
              pushCandidate(it.name, String(it.value).trim());
            }
          }
        }
      } else if (f.kind.indexOf('service.') === 0 || f.kind === 'web.server' || f.kind === 'ftp.banner' || f.kind === 'ssh.banner') {
        if (typeof val.product === 'string' && val.product && val.version) pushCandidate(val.product, val.version);
        if (Array.isArray(val.headers)) {
          for (var hi = 0; hi < val.headers.length; hi++) {
            pushHeaderCandidates(val.headers[hi]);
          }
        }
        if (Array.isArray(val.banners)) {
          for (var bi = 0; bi < val.banners.length; bi++) {
            var bbpv = _extractProdVerFromStr(val.banners[bi]);
            if (bbpv) pushCandidate(bbpv.product, bbpv.version);
          }
        }
        var rawBanner = val.banner || val.server || val.version || val.info || '';
        if (rawBanner) {
          var bpv = _extractProdVerFromStr(rawBanner);
          if (bpv) pushCandidate(bpv.product, bpv.version);
        }
      }
    }

    // 2. Inspect raw text banners (HTML generator/powered-by/title, HTTP Server/X-Powered-By, 220 greetings, Nmap -sV rows)
    var hasHtmlLt = t.indexOf('<') >= 0;
    if (hasHtmlLt) {
      var metaGenMatches = C.reAll(/<meta\b[^>]*?\bname=["']generator["'][^>]*?\bcontent=["']([^"']{3,90})["']/gi, t)
        .concat(C.reAll(/<meta\b[^>]*?\bcontent=["']([^"']{3,90})["'][^>]*?\bname=["']generator["']/gi, t));
      for (var mi = 0; mi < metaGenMatches.length; mi++) {
        var mpv = _extractProdVerFromStr(metaGenMatches[mi][1]);
        if (mpv) pushCandidate(mpv.product, mpv.version);
      }
    }

    if (/powered by/i.test(t)) {
      var poweredMatches = C.reAll(/\bPowered by\s+([A-Za-z][A-Za-z0-9_.+-]*(?:[ \t]+[A-Za-z][A-Za-z0-9_.+-]*){0,4}?)(?:[ \t]+(?:Version|ver\.?))?[ \t\/:-]+v?(\d+\.\d+(?:\.\d+)*)/gi, t);
      for (var pwi = 0; pwi < poweredMatches.length; pwi++) {
        pushCandidate(poweredMatches[pwi][1], poweredMatches[pwi][2]);
      }
    }

    if (hasHtmlLt) {
      var titleMatches = C.reAll(/<title>\s*([A-Za-z][A-Za-z0-9_.+-]*(?:[ \t]+[A-Za-z][A-Za-z0-9_.+-]*){0,4}?)(?:[ \t]+(?:Version|ver\.?))?[ \t:|/-]+v?(\d+\.\d+(?:\.\d+)*)\s*<\/title>/gi, t);
      for (var ti = 0; ti < titleMatches.length; ti++) {
        pushCandidate(titleMatches[ti][1], titleMatches[ti][2]);
      }
    }

    var docHasSrvHdr = /(?:Server|X-Powered-By|X-Generator|X-Application|http-server-header)\s*:/i.test(t);
    var docHasGreet220 = /^\s*220[- ]/m.test(t);
    var docHasNmapOpen = /^\s*\d+\/(?:tcp|udp)\s+open\s/im.test(t);
    var docHasAppCat = /\b(?:CMS|CRM|ERP|LMS|HRM|FMS|Portal|Management System|Manager|Helpdesk|Webmail|FTP Server|Mail Server|File Server)\b/i.test(t);
    if (docHasSrvHdr || docHasGreet220 || docHasNmapOpen || docHasAppCat) {
      var lines = t.split(/\r?\n/);
      for (var li2 = 0; li2 < lines.length; li2++) {
        var ln = lines[li2];
        if (!ln || /^\s*(?:User-Agent|Referer|Accept|Starting Nmap|Nmap done|- Nikto)/i.test(ln)) continue;

        // HTTP Server / X-Powered-By / X-Generator / Nmap http-server-header tokens
        if (docHasSrvHdr && ln.indexOf(':') >= 0) {
          var hdrM = /^\s*(?:(?:<\s*)?(?:Server|X-Powered-By|X-Generator|X-Application)|(?:[|_][ \t]*)?_?http-server-header)\s*:\s*(.+)$/i.exec(ln);
          if (hdrM) {
            pushHeaderCandidates(hdrM[1]);
            continue;
          }
        }

        // 220 FTP/SMTP/service greeting banners
        if (docHasGreet220) {
          var greetM = /^\s*220[- ](?:Welcome to\s+)?([A-Za-z][A-Za-z0-9_.+-]*(?:[ \t]+[A-Za-z][A-Za-z0-9_.+-]*){0,3}?)(?:[ \t]+(?:FTP|SMTP|Mail|File)[ \t]+(?:Server|Daemon|Service))?(?:[ \t]+(?:Version|ver\.?))?[ \t\/]+v?(\d+\.\d+(?:\.\d+)*)/i.exec(ln);
          if (greetM) {
            pushCandidate(greetM[1], greetM[2]);
            continue;
          }
        }

        // Nmap -sV open port version column
        if (docHasNmapOpen && ln.indexOf('/') >= 0) {
          var nmapM = /^\s*\d+\/(?:tcp|udp)\s+open\s+\S+\s+(.+)$/i.exec(ln);
          if (nmapM) {
            var rawSvcRest = nmapM[1].replace(/^(?:syn-ack|udp-response|localhost-response|reset|arp-response|nd-response|echo-reply|timestamp-reply|proto-response)(?:\s+ttl\s+\d+)?(?:\s+|$)/i, '');
            var svcCol = rawSvcRest.replace(/\([^)]*\)/g, ' ').replace(/\bhttpd\b/gi, '').replace(/\s+/g, ' ').trim();
            var npv = _extractProdVerFromStr(svcCol);
            if (npv) pushCandidate(npv.product, npv.version);
            continue;
          }
        }

        // Explicit app category banner (e.g. "Wing FTP Server 7.2.1", "Fuel CMS 1.4.1", "OpenNetAdmin v18.1.1")
        if (docHasAppCat) {
          var appCatM = /\b([A-Za-z][A-Za-z0-9_.+-]*(?:[ \t]+[A-Za-z][A-Za-z0-9_.+-]*){0,3}?[ \t]+(?:CMS|CRM|ERP|LMS|HRM|FMS|Portal|Management System|Manager|Helpdesk|Webmail|FTP Server|Mail Server|File Server))(?:[ \t]+(?:Version|ver\.?))?[ \t\/:-]+v?(\d+\.\d+(?:\.\d+)*)/i.exec(ln);
          if (appCatM) {
            pushCandidate(appCatM[1], appCatM[2]);
          }
        }
      }
    }

    if (!candidates.length) return;
    var best = candidates[0];
    var h = 'host:' + ws.target;
    _add(facts, mkFact('service.version', h, {
      product: best.product,
      version: best.version,
      search_query: best.search_query,
      all: candidates.slice(0, 5)
    }, S, source));
    _add(facts, mkFact('exploit.versioned_banner', h, {
      product: best.product,
      version: best.version,
      search_query: best.search_query,
      all: candidates.slice(0, 5)
    }, S, source));
  }

  C._looks_like_searchsploit = _looks_like_searchsploit;
  C._parse_searchsploit = _parse_searchsploit;
  C._looks_like_edb_script = _looks_like_edb_script;
  C._parse_edb_script = _parse_edb_script;
  C._parse_versioned_banner_for_edb = _parse_versioned_banner_for_edb;
})(typeof globalThis !== 'undefined' ? globalThis : this);
