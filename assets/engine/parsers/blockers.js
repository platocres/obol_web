/*!
 * obol engine - parsers/blockers.js - the "cryptic wall" detectors.
 *
 * Classic lab traps are rarely a real defence - they are an error message a learner has not seen
 * before, and the fix is one command. Each recognizer below reads a pasted failure and mints a
 * blocker.* fact so the matching fix/guidance move surfaces with the exact remedy. Everything here is
 * content-gated and additive: a benign paste mints nothing, and a blocker only appears once the user's
 * own output shows the wall, so Next Steps is never cluttered by advice for a wall they have not hit.
 *
 * These are DIAGNOSTIC facts, not attack evidence: they say "here is why your command failed and how to
 * get past it", which is a different muscle from the attack-fact parsers, hence their own small module.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon; if (!C) return;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  // kind -> the signature that proves the wall. Ordered; several may fire from one paste.
  var WALLS = [
    // recon: nmap says the host is down because ICMP is filtered - the #1 beginner trap. Fix: -Pn.
    { kind: 'blocker.host_down', re: /Note:\s*Host seems down|0 hosts up|host (?:seems|appears) to be down|increase .*--host-timeout/i },
    // name resolution: a box addressed by a hostname (target.internal) that is not in /etc/hosts.
    { kind: 'blocker.name_resolution', re: /Could not resolve host(?:name)?|Name or service not known|Temporary failure in name resolution|Name does not resolve|getaddrinfo .*Name or service|DNS resolution failed:|The DNS query name does not exist|nameserver\s+\S+\s+is not an IP address/i },
    // a uploaded script with Windows CRLF line endings: "/bin/bash^M: bad interpreter".
    { kind: 'blocker.crlf', re: /bad interpreter:\s*No such file or directory|[\^]M: bad interpreter|\r': bad interpreter|cannot execute:\s*required file not found/i },
    // a command that needs a real terminal (sudo, su, ssh interactive) from a dumb shell.
    { kind: 'blocker.no_tty', re: /sudo:\s*(?:no tty present|a (?:terminal|password) is required)|must be run from a terminal|no tty present and no askpass|the input device is not a TTY/i },
    // Windows Defender / AMSI eating a payload.
    { kind: 'blocker.amsi', re: /This script contains malicious content and has been blocked|contains a virus or potentially unwanted software|Operation did not complete successfully because the file contains a virus|AMSI_RESULT_DETECTED|failed with error code 0x80508023/i },
    // SeImpersonate potato that picked the wrong technique for the Windows build.
    { kind: 'blocker.potato', re: /CoGetInstanceFromIStorage|RpcServerRegisterIf.*failed|the handle is invalid|CreateProcessAsUser.*(?:failed|1314)|BITS.*(?:not|disabled)|potato.*fail|Operation failed or timed out/i },
    // web fuzzing throttled by a WAF / rate limiter. The separator before "limit" must be a space or a
    // hyphen ("rate limited", "rate-limiting"), NOT nothing: "ratelimit" with no separator is nmap's own
    // --defeat-rst-ratelimit flag line, which is informational and must never raise this blocker.
    { kind: 'blocker.rate_limited', re: /(?:HTTP\/[0-9.]+\s+429\b|\bstatus(?:\s+code)?\s*[:=]\s*429\b|\b429\s+Too Many Requests\b)|Too Many Requests|\brate[ -]limit(?:ed|ing| exceeded| reached)\b|x-rate-limit-remaining\s*:\s*0\b|temporarily blocked|request(?:s)? (?:have been )?throttled/i },
    // http vs https mismatch: curl/tooling hitting the wrong scheme.
    { kind: 'blocker.tls_scheme', re: /SSL.*WRONG_VERSION_NUMBER|wrong version number|record layer failure|sslv3 alert handshake failure|routines::?(?:unexpected eof|wrong version)|CA_MD_TOO_WEAK|ca md too weak|'SSL routines'/i },
    // hashcat/john refusing the hash: wrong mode, a username: prefix left on, or CRLF in the hash file.
    { kind: 'blocker.hash_format', re: /Token length exception|No hashes loaded|No password hashes loaded(?: with these settings)?|Separator unmatched|Signature unmatched|Line-length exception|Hashfile '[^']*' on line \d+|Please specify the hash-mode with -m/i },
    // a reverse shell that never calls back - the payload ran but egress is filtered.
    { kind: 'blocker.egress_blocked', re: /nc:.*(?:Connection refused|No route to host|Network is unreachable)|Ncat: (?:Connection refused|TIMEOUT|No route to host)|socat.*(?:Connection refused|refused)|curl:\s*\(7\)\s*Failed to connect/i },
    // NTLM relay refused because the target requires SMB signing (relay-tool phrasing, not nxc's enum
    // "signing:True" line) - relay to a host that has signing OFF instead.
    { kind: 'blocker.smb_signing', re: /signing is required(?:,| )|SMB signing is enabled|SigningRequired\s*[:=]\s*True|signing.*required.*(?:attack won|relay|abort)/i },
    // Kerberos says the principal/SPN/host is unknown - almost always an IP instead of the FQDN, a
    // wrong SPN, or a case/realm mistake.
    { kind: 'blocker.kerberos_spn', re: /KDC_ERR_S_PRINCIPAL_UNKNOWN|KDC_ERR_C_PRINCIPAL_UNKNOWN|Server not found in Kerberos database|Principal (?:unknown|not found in)|KDC_ERR_PADATA_TYPE_NOSUPP|NT_STATUS_NO_LOGON_SERVERS/i },
    // Responder running but catching nothing because its own SMB/HTTP servers are off (or your smbd is
    // squatting the port).
    { kind: 'blocker.responder_quiet', re: /(?:SMB|HTTP) server\s*\[OFF\]|Responder[^\n]*\[OFF\]|\[OFF\][^\n]*(?:SMB|HTTP)/i },
    // gobuster/ffuf hitting a wildcard/catch-all response and refusing to run until you filter it.
    { kind: 'blocker.web_wildcard', re: /the server returns a status code that matches the provided options for non existing urls|To continue please exclude the status code|use the "--wildcard" switch|WildcardResponse|Wildcard response found:/i },
    // access denied / permission barriers (service refused authenticated access or local account confusion).
    { kind: 'blocker.access_denied', re: /STATUS_ACCESS_DENIED|Access is denied|0xc0000022|\[\!\]\s*Access Denied\b|E_ACCESSDENIED|CERTSRV_E_TEMPLATE_DENIED|ERROR 1130 \(HY000\)|is not allowed to connect to this (?:MySQL|MariaDB) server|Certificate is not valid for client authentication|KDC_ERR_CLIENT_NOT_TRUSTED|\bMsg 15247\b|User does not have permission to perform this action|You do not have permission to run the RECONFIGURE statement|Cannot open Service Control Manager|This operation might require other privileges|MongoServerError:\s*(?:command\s+\S+\s+)?requires\s+authentication|\bnot\s+authorized\s+on\s+\S+\s+to\s+execute\s+command\b|\bcodeName:\s*['"]Unauthorized['"]|^\s*\(error\)\s+(?:NOPERM|ERR\s+[^\r\n]*(?:permission|not\s+permitted|protected\s+mode|disabled|denied))\b/im },
    // authentication rejected (bad password or wrong account scope).
    { kind: 'blocker.logon_failure', re: /STATUS_LOGON_FAILURE|0xc000006d|WinRMAuthorizationError|KDC_ERR_CLIENT_REVOKED|GSSAPI::GssApiError[\s\S]{0,240}?Invalid token was supplied|ldap_bind:\s*Invalid credentials|Authentication failure|Failed to authenticate|Login failed for user|\[\!\]\s*Authentication error\b|ERROR 1045 \(28000\)|Access denied for user|Error de inicio de sesi[o\u00f3]n del usuario|Unable to connect to LDAP, verify your credentials|^\s*\(error\)\s+(?:WRONGPASS|NOAUTH\s+Authentication\s+required|ERR\s+invalid\s+(?:username-password|password))\b/im },
    // Kerberos clock skew: DC rejected ticket because time drift > 5 mins.
    { kind: 'blocker.clock_skew', re: /KRB_AP_ERR_SKEW|clock skew too great|time difference too large|Ticket not yet valid/i },
    // hashcat/john cannot use the GPU/OpenCL (common in a VM) - fall back to CPU / --force.
    { kind: 'blocker.hashcat_env', re: /No devices found\/left|clGetPlatformIDs|No OpenCL compatible|ADL_Main_Control_Create|increase.*--force|You can use --force to override/i },
    // anonymous LDAP bind rejected by DC policy (DSID-0C09075A).
    { kind: 'blocker.ldap_anonymous_disabled', re: /000004DC:\s*LdapErr:\s*DSID-0C09075A|operationsError.*successful bind must be completed|In order to perform this operation a successful bind must be completed|anonymous bind disallowed|LDAP channel binding or signing is required|LDAP Authentication is refused because LDAP signing is enabled/i },
    // NetExec --get-file quietly defaulting to administrative C$ share instead of the target share.
    { kind: 'blocker.nxc_c_share_denied', re: /from share ["']C\$["']|Error writing file .* from share ["']C\$["']|(?:share\s+["']?C\$["']?|enumerating\s+C\$).*(?:0xc0000022|STATUS_ACCESS_DENIED)/i },
    // account in Protected Users group: KDC refuses RC4/DES Kerberos tickets and NTLM authentication.
    { kind: 'blocker.protected_users', re: /KDC_ERR_ETYPE_NOSUPP|KDC has no support for encryption type|(?:member of|in|blocked by)\s+["']?Protected Users/i },
    // delegation target account has AccountNotDelegated = True (Marked Sensitive).
    { kind: 'blocker.account_not_delegated', re: /AccountNotDelegated\s*:\s*True|KDC_ERR_BADOPTION|account is marked as sensitive and cannot be delegated/i },
    // WinRM port 5985 closed / connection refused (evil-winrm failing on non-WinRM targets, or WMI Set-WSManQuickConfig failing before creating listener).
    { kind: 'blocker.winrm_closed', re: /ECONNREFUSED.*(?:5985|evil-winrm)|Connection refused.*(?:port 5985|5985)|Cannot establish connection to remote endpoint.*5985|Set-WSManQuickConfig\s*:\s*Access is denied/i },
    // NetExec --spider usage banner from missing positional share/pattern arguments.
    { kind: 'blocker.nxc_spider_usage', re: /usage:\s*nxc\s+smb.*--spider|--spider:\s*(?:expected|error)|nxc smb: error:.*--spider|--spider requires|arguments are required:\s*share/i },
    // xp_cmdshell disabled on MSSQL server.
    { kind: 'blocker.xp_cmdshell_disabled', re: /SQL Server blocked access to procedure 'sys\.xp_cmdshell'|EXECUTE permission was denied on the object 'xp_cmdshell'/i },
    // cracking exhausted: wordlist or hash exhaustion.
    { kind: 'blocker.cracking_exhausted', re: /Status\.+:\s*Exhausted|\b0\s+password\s+hashes\s+cracked\b|^\s*0g\s+\d+:\d+:\d+:\d+\s+DONE\b/im },
    // DCSync failed: principal lacks Replicating Directory Changes rights (ERROR_DS_DRA_BAD_DN / ERROR_DS_DRA_ACCESS_DENIED).
    { kind: 'blocker.dcsync_denied', re: /DRSUAPI\s+SessionError:\s*code:\s*0x20f7\s*-\s*ERROR_DS_DRA_BAD_DN|ERROR_DS_DRA_BAD_DN|ERROR_DS_DRA_ACCESS_DENIED|Policy SPN target name validation might be restricting full DRSUAPI dump/i },
    // NetExec --bloodhound blocked by default ~/.nxc/nxc.conf BloodHound-CE setting.
    { kind: 'blocker.nxc_bh_config', re: /Your configuration has BloodHound-CE enabled,\s*however this version is currently unsupported/i },
    // MachineAccountQuota is 0: domain users cannot create a machine account without GenericAll/CreateChild on an OU.
    { kind: 'blocker.maq_zero', re: /MachineAccountQuota\s*[:=]\s*0\b/i },
    // certutil rejected its arguments: a usage/arg error (flipped URL/path order, missing -f, extra token),
    // so the download or encode never ran. The success lines (command completed successfully) must not match.
    { kind: 'blocker.certutil_usage', re: /CertUtil:\s*(?:Too many arguments|Too few arguments|Missing \w+ argument|The parameter is incorrect)|Expected no more than \d+ args?, received \d+|Expected at least \d+ args?/i },
    // password change rejected by domain password policy (minimum length, complexity, history, or minimum password age).
    { kind: 'blocker.password_restriction', re: /(?:NT_)?STATUS_PASSWORD_RESTRICTION|0xc000006c|password does not meet the password policy requirements/i },
    // legacy Python 2 PoC executed under Python 3: print without parens, PEP 263 non-ASCII byte, removed py2 stdlib module, or str/bytes mismatch.
    { kind: 'blocker.py2_syntax_or_module', re: /SyntaxError:\s*Missing parentheses in call to 'print'|SyntaxError:\s*Non-ASCII character '\\x[0-9a-fA-F]{2}'|(?:ModuleNotFoundError|ImportError):\s*No module named ['"]?(?:urllib2|urlparse|cookielib|httplib|Queue|commands|cPickle|ConfigParser|SocketServer)['"]?|TypeError:\s*(?:a bytes-like object is required, not 'str'|cannot use a string pattern on a bytes-like object)/ },
    // Kali / Debian PEP 668 externally-managed pip error or missing third-party PoC dependency (pycryptodome Crypto, bs4, pwntools, impacket, etc.).
    { kind: 'blocker.python_dep_or_pep668', re: /error:\s*externally-managed-environment|(?:ModuleNotFoundError|ImportError):\s*No module named ['"]?(?:Crypto|Cryptodome|bs4|requests_toolbelt|pwn|pwntools|impacket|colorama|termcolor|jwt|yaml)['"]?/ },
    // exploit script failing at runtime because the author left a hardcoded localhost:8080/8081/8888 debug proxy in requests/urllib.
    { kind: 'blocker.hardcoded_proxy', re: /ProxyError[^\r\n]*(?:127\.0\.0\.1|localhost)[^\r\n]*(?:8080|8081|8000|8888)|(?:127\.0\.0\.1|localhost)[^\r\n]*(?:8080|8081|8000|8888)[^\r\n]*ProxyError|Cannot connect to proxy[^\r\n]*(?:127\.0\.0\.1|localhost)(?::|,?\s*port=)(?:8080|8081|8000|8888)/i },
    // TLS handshake failing on a self-signed or mismatched lab certificate in Python requests/urllib/OpenSSL.
    { kind: 'blocker.tls_cert_verify', re: /\bSSLCertVerificationError\b|\bCERTIFICATE_VERIFY_FAILED\b/ },
    // compiled C/C++ exploit failing on target due to host/target GLIBC version skew, missing 32-bit multilib headers, or wrong ELF architecture.
    { kind: 'blocker.glibc_or_arch_mismatch', re: /version ['`"]?GLIBC_2\.\d+(?:\.\d+)?['`"]? not found|gnu\/stubs-32\.h:\s*No such file or directory|cannot execute binary file:\s*Exec format error/i },
  ];

  function _parse_op_blockers(text, ws, command, source, facts) {
    var t = String(text || ''); if (!t) return;
    var h = 'host:' + ws.target;
    function addWall(wall, content) {
      var lines = content.split(/\r?\n/).filter(function (line) { return wall.re.test(line); });
      if (!lines.length) lines = [content];
      lines.forEach(function (line) {
        var row = /^\s*(SMB|LDAP|WINRM|RDP|SSH|FTP|MSSQL|WMI)\s+(\S+)\s+(\d+)\s+\S+\s+(?:\[[-*]\]\s*)?(.*)$/i.exec(line);
        var lineWs = row ? Object.assign({}, ws, { target: C._observed_host ? C._observed_host(ws, row[2]) : row[2], observedTarget: row[2] }) : ws;
        var value = { tool: C._exec_tool ? C._exec_tool(command || '') : '', via: 'blocker-detect', service: row ? row[1].toLowerCase() : (((ws || {}).context || {}).service || '') };
        value.stage = wall.kind === 'blocker.logon_failure' || wall.kind === 'blocker.password_change' || wall.kind === 'blocker.account_restricted' ? 'authentication' : (wall.kind === 'blocker.access_denied' ? 'authorization' : 'environment');
        if (row) {
          value.port = +row[3];
          var parsed = C._parse_auth_material ? C._parse_auth_material(row[4].replace(/[ \t]+STATUS_[A-Z_]+[^\r\n]*$/i, '')) : [];
          if (parsed[0]) value.domain = parsed[0];
          if (parsed[1]) value.user = parsed[1];
          if (parsed[2] && !/^(?:\*{3,}|<redacted>|\[redacted\])$/i.test(parsed[2])) value.password = parsed[2];
        }
        if (C._auth_observation) value = C._auth_observation(lineWs, value);
        delete value.password; delete value.nthash;
        _add(facts, mkFact(wall.kind, 'host:' + lineWs.target, value, S, source));
      });
    }
    var isHttp200Html = /^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+200\b/im.test(t) && /<!doctype\s+html|<html[\s>]|<body[\s>]|<h[1-6][\s>]|<p[\s>]/i.test(t);
    var isWebShellCmd = command && /cmd=|exec=|shell\.php|cmd\.jsp|cmd\.asp/i.test(command);
    if (isHttp200Html && !isWebShellCmd) {
      var hdrSplit = /\r?\n\r?\n|<\s*(?:!doctype|html|head|body)\b/i.exec(t);
      if (hdrSplit && hdrSplit.index > 0) t = t.slice(0, hdrSplit.index);
    }
    var isNmap = (command && /^\s*(?:(?:sudo|proxychains4?|time)\s+(?:-[a-zA-Z0-9]+\s+)*)*nmap\b/i.test(command)) || /Starting Nmap|Nmap scan report for/i.test(t);
    var isRoastOrEnum = command && /--asreproast|--kerberoast|--users|GetNPUsers|GetUserSPNs/i.test(command);
    var isEnum4linux = (command && /\benum4linux(?:-ng)?\b/i.test(command)) || /^ENUM4LINUX - next generation/im.test(t);
    var enum4linuxSucceeded = isEnum4linux && /\[\+\]\s*(?:Found \d+\s+(?:user|group|share)|Server allows authentication|Appears to be|Long domain name|Domain SID)/i.test(t);
    var isAnonSmbProbe = (command && /^(?:smb-anon|ad-user-enum)\b/i.test(command))
      || (/\[\+\]\s*[^\\\r\n]*\\:\s*$/im.test(t) && !/\[\+\]\s*[^\\\r\n]*\\[A-Za-z0-9._$-]+:/im.test(t));
    // Strip nmap script probe lines so unauthenticated NSE probe outputs (like ms10-061: NT_STATUS_ACCESS_DENIED)
    // never masquerade as operational authentication/execution blockers for the operator.
    var tWithoutNse = t.indexOf('NT_STATUS_ACCESS_DENIED') >= 0
      ? t.replace(/^\|\s*[-_a-zA-Z0-9]+:\s*NT_STATUS_ACCESS_DENIED.*$/gim, '')
         .replace(/^\|_[-_a-zA-Z0-9]+:\s*NT_STATUS_ACCESS_DENIED.*$/gim, '')
      : t;
    for (var i = 0; i < WALLS.length; i++) {
      var w = WALLS[i];
      if (w.kind === 'blocker.access_denied') {
        var hasPositiveSmbEnum = facts && facts.some(function (f) { return f && (f.kind === 'smb.readable_share' || f.kind === 'smb.shares'); });
        var isPassiveFileRead = command && /^\s*(?:(?:sudo(?:\s+-u\s+\S+)?)\s+)?(?:cat|head|tail|less|more|bat|batcat|nl|strings)\b/i.test(command)
          && !/[|;&`]|\$\(|\b(?:curl|wget|ssh|nxc|netexec|smbclient|rpcclient|ldapsearch|psql|mysql|mongosh|redis-cli)\b/i.test(command);
        if (isNmap || isRoastOrEnum || enum4linuxSucceeded || isAnonSmbProbe || hasPositiveSmbEnum || isPassiveFileRead) continue;
        var tNoWsmanLoopback = tWithoutNse.indexOf('Set-WSManQuickConfig') >= 0
          ? tWithoutNse.replace(/^[^\r\n]*Set-WSManQuickConfig\s*:\s*Access is denied[^\r\n]*$/gim, '')
          : tWithoutNse;
        if (w.re.test(tNoWsmanLoopback)) {
          addWall(w, tNoWsmanLoopback);
        }
        continue;
      }
      if (w.kind === 'blocker.egress_blocked' && /curl:\s*\(7\)\s*Failed to connect/i.test(t)) {
        var tgtStr = String((ws && ws.target) || '');
        var isRemoteTargetCurl = (tgtStr && (String(command || '').indexOf(tgtStr) >= 0 || t.indexOf(tgtStr) >= 0))
          || (command && /^\s*curl\b/i.test(command) && !/\s-(?:o|O|-output)\b/i.test(command) && !/\|\s*(?:sh|bash)\b/i.test(command));
        if (isRemoteTargetCurl) continue;
      }
      if (w.kind === 'blocker.potato' && /Operation failed or timed out/i.test(t) && !/CoGetInstanceFromIStorage|RpcServerRegisterIf.*failed|the handle is invalid|CreateProcessAsUser.*(?:failed|1314)|BITS.*(?:not|disabled)|potato.*fail/i.test(t)) {
        if (!/(?:printspoofer|[a-z0-9_]*potato)/i.test(String(command || '') + '\n' + t)) continue;
      }
      if (w.kind === 'blocker.rate_limited') {
        var tRate = /x-rate-limit-/i.test(t)
          ? t.replace(/^\s*(?:[<>*]\s*)?x-rate-limit-(?:limit|reset|window|policy|retry-after)\s*:[^\r\n]*$/gim, '')
             .replace(/^\s*(?:[<>*]\s*)?x-rate-limit-remaining\s*:\s*(?!0\b)\d+[^\r\n]*$/gim, '')
          : t;
        if (w.re.test(tRate)) addWall(w, tRate);
        continue;
      }
      if (w.kind === 'blocker.dcsync_denied') {
        var hasNtdsDump = /^(?:[^\\\r\n:]+\\)?[^\s:\r\n]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::\s*$/m.test(t)
          || /\bkrbtgt:(?:\d+:)?[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::/i.test(t)
          || (facts && facts.some(function (f) { return f && (f.kind === 'loot.ntds' || f.kind === 'hash.krbtgt'); }));
        if (hasNtdsDump) continue;
      }
      if (w.kind === 'blocker.logon_failure' && (enum4linuxSucceeded || /\\\$krb5(?:asrep|tgs)\$|Testing credentials \(\$krb5/i.test(t) || (/^(?:bloodyad-acl|dcsync)\b/i.test(command || '') && /Traceback \(most recent call last\):|SessionError:\s*STATUS_LOGON_FAILURE/i.test(t)))) continue;
      if (w.re.test(t)) addWall(w, t);
    }
  }
  C._parse_op_blockers = _parse_op_blockers;
})(typeof globalThis !== 'undefined' ? globalThis : this);
