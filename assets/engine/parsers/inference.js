/*!
 * obol engine - parsers/inference.js
 * Wittgensteinian Contextual Inference Engine (Tier 3) & Causal Entailment Gate Synchronizer.
 *
 * Philosophical & Architectural Model:
 *   1. Logical Atomism (Tractatus): Terminal outputs are decomposed into ~45 universal atomic
 *      primitives (IPv4/v6, CIDRs, ports, identities, SIDs, DNs, SPNs, modular/hex hashes,
 *      paths, permission tokens, ACL verbs, ADCS flags, HTTP status/headers, and polarity).
 *   2. Language Games & Family Resemblance (Philosophical Investigations): Rather than relying
 *      solely on brittle tool-specific syntax, meaning is derived from how atoms co-occur within
 *      2D structural geometry (dynamic header-mapped tables, Key-Value object blocks, statistical
 *      outlier rows) interpreted through the active language game:
 *        - Operator Attention Frame (copiedQueue move contract + recent activities[0..2] + Workbench)
 *        - Shell Prompt & Command-Echo Telemetry (attacker vs target locus, cwd, subshell, input echo subtraction)
 *        - Wrapper-Delta Diffing (isolating payload output across consecutive same-endpoint pastes)
 *        - Host Phase & Global Entity Index (binding known engagement users/hosts/shares to new atoms)
 *   3. Out-of-Order Immunity & Causal Entailment: Context is a booster/disambiguator, never a
 *      blocker. When an operator jumps ahead of gated moves, catalog-wide move matching (across all
 *      eligible and blocked moves) and causal entailment backfill implied prerequisite gates
 *      (host.up, service .reachable, OS family, foothold, domain linkage) while keeping skipped
 *      broad discovery scans available.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  if (!C || !C.mkFact) return;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;

  function hasKind(facts, kind) {
    for (var i = 0; i < facts.length; i++) if (facts[i] && facts[i].kind === kind) return true;
    return false;
  }
  function hasPrefix(facts, pre) {
    for (var i = 0; i < facts.length; i++) if (facts[i] && facts[i].kind && facts[i].kind.indexOf(pre) === 0) return true;
    return false;
  }

  // ---- Boilerplate & Noise Dictionaries (Negative-Space Filtering) ----------------------------
  var _BOILERPLATE_USERS = {
    guest: 1, defaultaccount: 1, wdagutilityaccount: 1, krbtgt: 1,
    daemon: 1, bin: 1, sys: 1, sync: 1, games: 1, man: 1, lp: 1, mail: 1,
    news: 1, uucp: 1, proxy: 1, backup: 1, list: 1, irc: 1, gnats: 1,
    nobody: 1, _apt: 1, messagebus: 1, sshd: 1, tss: 1, uuidd: 1,
    tcpdump: 1, landscape: 1, pollinate: 1, 'systemd-network': 1,
    'systemd-resolve': 1, 'systemd-timesync': 1, 'systemd-coredump': 1,
    'fwupd-refresh': 1, usbmux: 1, dnsmasq: 1, avahi: 1, colord: 1,
    geoclue: 1, pulse: 1, rtkit: 1, saned: 1, hplip: 1, gdm: 1,
    users: 1, computers: 1, builtin: 1, system: 1, 'domain controllers': 1,
    foreignsecurityprincipals: 1, 'managed service accounts': 1, 'program data': 1,
    'local service': 1, 'network service': 1, localservice: 1, networkservice: 1,
    defaultapppool: 1, iusr: 1, iwam: 1, anonymous: 1, 'anonymous logon': 1,
    everyone: 1, 'authenticated users': 1, 'domain users': 1, 'domain computers': 1,
    'enterprise admins': 1, 'schema admins': 1, administrators: 1,
    'print operators': 1, 'server operators': 1, 'account operators': 1,
    'cryptographic operators': 1, dnsupdateproxy: 1,
    example: 1, test: 1, sample: 1, demo: 1, placeholder: 1, your_username: 1,
    username_here: 1, myuser: 1, foo: 1, bar: 1,
    'nt authority': 1, 'nt service': 1, 'window manager': 1, 'font driver host': 1,
    'iis apppool': 1, workgroup: 1,
    'null': 1, none: 1, 'true': 1, 'false': 1, unknown: 1, error: 1, failed: 1,
    denied: 1, invalid: 1, status: 1, version: 1, server: 1, client: 1, target: 1,
    host: 1, domain: 1, user: 1, username: 1, login: 1, password: 1, secret: 1,
    'admin$': 1, 'ipc$': 1, 'c$': 1, 'print$': 1, http: 1, https: 1, ldap: 1,
    smb: 1, tcp: 1, udp: 1, initshutdown: 1, eventlog: 1, srvsvc: 1, atsvc: 1,
    wkssvc: 1, samr: 1, lsarpc: 1, lsass: 1, netlogon: 1, spoolss: 1, winreg: 1,
    svcctl: 1, ntsvcs: 1, epmapper: 1, browser: 1, davhlp: 1, currentversion: 1,
    currentcontrolset: 1, microsoft: 1, windows: 1
  };
  var _ATTACKER_HOSTS = /^(?:kali|parrot|attacker|hacky|pwnbox|exegol|localhost|ubuntu-vm|commando|slingshot|pentest|offsec|htb|tryhackme|vagrant|arch|archlinux|blackarch|debian-vm|vbox|vmware)$/i;
  var _REMOTE_OFFENSIVE_TOOLS = /^\s*(?:nmap|masscan|rustscan|impacket-[\w.-]+|GetNPUsers[\w.]*|GetUserSPNs[\w.]*|secretsdump[\w.]*|wmiexec[\w.]*|psexec[\w.]*|smbexec[\w.]*|atexec[\w.]*|dcomexec[\w.]*|lookupsid[\w.]*|getTGT[\w.]*|getST[\w.]*|addcomputer[\w.]*|bloodyAD|dacledit[\w.]*|owneredit[\w.]*|certipy[\w-]*|nxc|netexec|crackmapexec|cme|smbclient|smbmap|rpcclient|enum4linux[\w-]*|ldapsearch|kerbrute|evil-winrm|ffuf|gobuster|feroxbuster|wfuzz|dirb|dirsearch|nikto|whatweb|httpx|nuclei|hydra|john|hashcat|responder|ntlmrelayx[\w.]*|sqlmap|bloodhound[\w.-]*|pywhisker[\w.]*|sccmhunter[\w.]*|snmpwalk|onesixtyone|showmount)\b/i;

  function _strip_cmd_wrappers(cmd) {
    var s = String(cmd || '').trim();
    var prev;
    do {
      prev = s;
      s = s.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S+)\s+)+/, '')
           .replace(/^(?:sudo(?:\s+-[ugU]\s+\S+|\s+-[A-Za-z]+)*|proxychains4?(?:\s+-f\s+\S+|\s+-q)*|time|env|nice(?:\s+-n\s+\S+)?|timeout(?:\s+-[a-zA-Z0-9]+)*\s+\S+|stdbuf(?:\s+-[ioe]\S+)+)\s+/i, '');
    } while (s !== prev);
    return s.trim();
  }
  var _PUBLIC_EMAIL_DOMAINS = /^(?:gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|live\.com|icloud\.com|aol\.com|protonmail\.com|proton\.me|example\.com|example\.org|example\.net|test\.com|domain\.com|company\.com|github\.com|gitlab\.com|microsoft\.com|google\.com|apache\.org|debian\.org|ubuntu\.com|kali\.org|offsec\.com|offensive-security\.com|cpython\.org|python\.org|openssl\.org|nmap\.org)$/i;
  var _EMPTY_NTHASH = '31d6cfe0d16ae931b73c59d7e0c089c0';
  var _EMPTY_LMHASH = 'aad3b435b51404eeaad3b435b51404ee';
  var _EMPTY_MD5 = 'd41d8cd98f00b204e9800998ecf8427e';

  function isBoilerplateUser(u) {
    if (!u) return true;
    var raw = String(u).trim();
    if (raw.indexOf('.') >= 0 && /\.(?:zip|tar|gz|tgz|rar|7z|bak|sql|db|sqlite|txt|log|xml|json|yml|yaml|ini|conf|cfg|php|py|sh|exe|dll|ps1|bat|cmd|vbs|jar|war|pem|key|pfx|kdbx|ova|vmdk|iso|img|pdf|doc|docx|xls|xlsx)$/i.test(raw)) return true;
    var low = raw.toLowerCase();
    if (low.indexOf('\\') >= 0 || low.indexOf('/') >= 0) low = low.replace(/^.*[\\\/]/, '');
    if (low.indexOf('@') >= 0) low = low.slice(0, low.indexOf('@'));
    if (!low || low.length < 2 || low.length > 64) return true;
    if (_BOILERPLATE_USERS[low] === 1) return true;
    return false;
  }

  var _DECODE_FAIL_RE = /\b(?:ciphertext length (?:was|is) not divisible by|not divisible by (?:8|16)\b|bad decrypt|wrong final block length|block length is not|data not multiple of block length|padding (?:error|is invalid|cannot be removed)|decryption failed|unable to decrypt|invalid (?:hex|base64|ciphertext|key length|iv length|padding)|cipherfinal|corrupt(?:ed)?\s+(?:data|block|ciphertext)|incorrect\s+padding|binascii\.error|unicodedecodeerror)\b/i;

  function _windowHasDecodeFailure(linesArr, idx) {
    if (!linesArr) return false;
    var lo = Math.max(0, idx - 6), hi = Math.min(linesArr.length - 1, idx + 3);
    for (var wi = lo; wi <= hi; wi++) {
      if (_DECODE_FAIL_RE.test(linesArr[wi] || '')) return true;
    }
    return false;
  }

  function isPlaceholderSecret(s, echoSet) {
    if (s === undefined || s === null) return true;
    var clean = String(s).trim().replace(/^['"]|['"]$/g, '').trim();
    if (!clean || clean.length < 3 || clean.length > 256) return true;
    if (/[\x00-\x08\x0e-\x1f\x7f-\x9f\ufffd]/.test(clean)) return true;
    if (clean.indexOf('\x60') >= 0 || clean.indexOf('$(') >= 0 || clean.indexOf('${') >= 0) return true;
    if (echoSet && echoSet[clean.toLowerCase()]) return true;
    if (/^(?:null|none|false|true|empty|nil|undefined|n\/a|na|tbd|todo|changeme|change_me|password|passwd|secret|user|username|account|login|domain|host|server|your_password|password_here|secret_here|api_key_here|token_here|testpassword|mysecretpassword|yourpassword|enterpassword|p@ssw0rd|passw0rd|example|sample|test|placeholder|redacted|hidden|masked|encrypted|not\s*set|write|read|create_child|delete_child|full_control|generic_all|generic_write|\*+|\.+|-+|_+|<[^>]+>|\[[^\]]+\]|\{[^}]+\}|0x0+)$/i.test(clean)) return true;
    if (/^(?:NOPASSWD(?::.*)?|PASSWD(?::.*)?|SETENV(?::.*)?|NOEXEC(?::.*)?|LOG_INPUT(?::.*)?|LOG_OUTPUT(?::.*)?|ALL)$/i.test(clean)) return true;
    if (/^\(ALL(?::[^)]*)?\)/i.test(clean) || /\bNOPASSWD:/i.test(clean)) return true;
    if (/^(?:https?:\/\/|#[0-9a-fA-F]{3,8}$|\d+(?:px|em|rem|ms|s|%|pt|vh|vw)$)/.test(clean)) return true;
    if (/^(?:document\.|window\.|navigator\.|location\.|localStorage\.|sessionStorage\.|form\.|this\.|self\.|process\.env\b|os\.environ\b|os\.getenv\b|System\.getenv\b|\$_(?:POST|GET|REQUEST|COOKIE|SERVER|ENV|SESSION)\b|req\.(?:body|query|params|headers|cookies)\b|request\.(?:form|args|json|values|POST|GET|DATA)\b|[A-Za-z_$][A-Za-z0-9_$.]*\s*\(|[A-Za-z_$][A-Za-z0-9_$.]*\[|[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*){2,}$)/i.test(clean)) return true;
    return false;
  }

  function _is_dos_emulator_ctx(command, text, promptLine) {
    if (C && typeof C.isDosEmulatorContext === 'function') {
      return !!C.isDosEmulatorContext(command, text, promptLine);
    }
    var combined = String(command || '') + '\n' + String(text || '');
    if (/\bdosbox\b|Drive [A-Z] is mounted as (?:local directory|internal Virtual Drive)|\bMOUNT\s+[A-Za-z]\s+\/(?:\s|$)/i.test(combined)) {
      return true;
    }
    var promptCtx = String(promptLine || '') + '\n' + String(text || '');
    if (/^\s*[A-Za-z]:\\>/m.test(promptCtx) && /(?:^|\s|[><|"'=])\/(?:etc|usr|bin|sbin|var|home|root|tmp|opt)\//.test(combined)) {
      return true;
    }
    return false;
  }

  function _isHelpOrUsageOutput(text, command) {
    if (/\b(?:--help|-h|\s\/\?)\s*$/i.test(String(command || '').trim())) return true;
    var s = String(text || '');
    if (/^\s*(?:usage|options|positional arguments|optional arguments):\s*$/im.test(s) && /^\s*-[a-zA-Z],\s+--[a-zA-Z0-9_-]+/m.test(s)) return true;
    return false;
  }

  // Co-mint actionable credential/hash facts alongside credential.candidate so downstream
  // gates (requires_all: ["credential.available"], ["hash.ntlm"], ["hash.crackable"]) and
  // store/context credential registration unlock without deadlocking.
  function _emit_credential_facts(facts, scope, credObj, source, allowBare32HexNtlm) {
    if (!credObj) return;
    var u = String(credObj.user || '').trim();
    var hasValidUser = u && !isBoilerplateUser(u);
    var dom = String(credObj.domain || '').trim();
    var via = credObj.via || 'context-inference';
    var pw = credObj.password ? String(credObj.password).trim().replace(/^(["'])(.*)\1$/, '$2').trim() : '';
    var nt = credObj.nthash ? String(credObj.nthash).trim().toLowerCase() : '';
    var rawHash = credObj.hash ? String(credObj.hash).trim() : '';
    var isExplicitDbOrMd5 = credObj.kind === 'database_hash'
      || /md5/i.test(String(credObj.format || credObj.hash_type || ''));
    if (isExplicitDbOrMd5 && nt && !rawHash) {
      rawHash = nt;
      nt = '';
    }

    if (!nt && rawHash && /^[0-9a-fA-F]{32}$/.test(rawHash)) {
      if (allowBare32HexNtlm && !isExplicitDbOrMd5) {
        nt = rawHash.toLowerCase();
        rawHash = '';
      }
    } else if (!nt && rawHash && /^(?:aad3b435b51404eeaad3b435b51404ee|NO PASSWORD\*+):([0-9a-fA-F]{32})$/i.test(rawHash)) {
      nt = rawHash.split(':')[1].toLowerCase();
      rawHash = '';
    } else if (!nt && rawHash && allowBare32HexNtlm && !isExplicitDbOrMd5 && /^[0-9a-fA-F]{32}:([0-9a-fA-F]{32})$/i.test(rawHash)) {
      nt = rawHash.split(':')[1].toLowerCase();
      rawHash = '';
    }
    if (nt === _EMPTY_NTHASH || nt === _EMPTY_LMHASH || nt === _EMPTY_MD5) nt = '';
    if (rawHash && /^[0-9a-fA-F]{32}$/.test(rawHash)) {
      var lowRaw32 = rawHash.toLowerCase();
      if (lowRaw32 === _EMPTY_NTHASH || lowRaw32 === _EMPTY_LMHASH || lowRaw32 === _EMPTY_MD5) rawHash = '';
    }

    var candVal = { via: via };
    if (hasValidUser) candVal.user = u;
    if (dom) candVal.domain = dom;
    if (credObj.file) candVal.file = credObj.file;
    if (credObj.kind) candVal.kind = credObj.kind;

    if (nt) {
      candVal.nthash = nt;
      candVal.hash = nt;
      _add(facts, mkFact('credential.candidate', scope, candVal, S, source));
      if (hasValidUser) {
        var ntVal = { user: u, nthash: nt, hash: nt, hash_type: 'ntlm', secret_type: 'NT', via: via };
        if (dom) ntVal.domain = dom;
        _add(facts, mkFact('hash.ntlm', scope, ntVal, S, source));
        _add(facts, mkFact('credential.ntlm_hash', scope, ntVal, S, source));
        _add(facts, mkFact('credential.available', scope, ntVal, S, source));
      }
      return;
    }

    if (rawHash) {
      candVal.hash = rawHash;
      if (credObj.format) candVal.format = credObj.format;
      _add(facts, mkFact('credential.candidate', scope, candVal, S, source));
      var hVal = { hash: rawHash, via: via };
      if (hasValidUser) hVal.user = u;
      if (dom) hVal.domain = dom;
      if (credObj.format) hVal.format = credObj.format;
      if (credObj.hash_type) hVal.hash_type = credObj.hash_type;
      if (/^[0-9a-fA-F]{32}$/.test(rawHash) && !hVal.format && !hVal.hash_type) {
        hVal.format = 'md5';
        hVal.hash_type = 'md5';
      }
      if (/^\$krb5tgs\$/i.test(rawHash)) {
        hVal.hash_type = 'krb5tgs';
        _add(facts, mkFact('hash.tgs', scope, hVal, S, source));
        _add(facts, mkFact('hash.crackable', scope, hVal, S, source));
        _add(facts, mkFact('hash.candidate', scope, hVal, S, source));
      } else if (/^\$krb5asrep\$/i.test(rawHash)) {
        hVal.hash_type = 'krb5asrep';
        _add(facts, mkFact('hash.asrep', scope, hVal, S, source));
        _add(facts, mkFact('hash.crackable', scope, hVal, S, source));
        _add(facts, mkFact('hash.candidate', scope, hVal, S, source));
      } else if (/^\$DCC2\$/i.test(rawHash)) {
        hVal.hash_type = 'mscache2';
        _add(facts, mkFact('hash.mscache2', scope, hVal, S, source));
        _add(facts, mkFact('hash.mscache', scope, hVal, S, source));
        _add(facts, mkFact('hash.crackable', scope, hVal, S, source));
        _add(facts, mkFact('hash.candidate', scope, hVal, S, source));
      } else {
        var modTagM = /^\$(pkzip2?|zip2|7z|rar[35]?|pfx(?:ng)?|keepass|sshng|ansible)\$/i.exec(rawHash);
        if (modTagM && !hVal.hash_type) {
          var modTagLow = modTagM[1].toLowerCase().replace(/^pkzip2$/, 'pkzip').replace(/^pfxng$/, 'pfx').replace(/^rar[35]$/, 'rar');
          hVal.hash_type = modTagLow;
          if (!hVal.format) hVal.format = modTagLow;
        }
        _add(facts, mkFact('hash.crackable', scope, hVal, S, source));
        _add(facts, mkFact('hash.candidate', scope, hVal, S, source));
        if (/^\$(?:pkzip2?|zip2|7z|rar[35]?|pfx(?:ng)?|keepass|ansible)\$/i.test(rawHash) && !hasKind(facts, 'loot.material')) {
          var matVal = { kind: hVal.hash_type || 'encrypted_archive', via: via };
          if (credObj.file) matVal.file = credObj.file;
          _add(facts, mkFact('loot.material', scope, matVal, S, source));
        }
      }
      return;
    }

    if (pw) {
      candVal.password = pw;
      _add(facts, mkFact('credential.candidate', scope, candVal, S, source));
      if (hasValidUser) {
        var pVal = { user: u, password: pw, secret_type: 'plaintext', via: via };
        if (dom) pVal.domain = dom;
        _add(facts, mkFact('credential.plaintext', scope, pVal, S, source));
        _add(facts, mkFact('credential.available', scope, pVal, S, source));
      }
    }
  }

  // ---- Axis 2A: Shell Prompt Telemetry Extractor ----------------------------------------------
  var _PROMPT_BANNER_SKIP_RE = /^(?:listening on \[|connect to \[[^\]]+\] from |Connection received on |Ncat:\s|Trying \d+\.|Connected to |Escape character is |Microsoft Windows \[Version |\(c\) Microsoft Corporation)/i;

  function _is_interactive_session_launcher_cmd(command, hasLocalCtxPrompt) {
    var cmd = String(command || '').trim();
    if (!cmd) return true;
    if (/\bpty\.spawn\s*\(/i.test(cmd) || /\bscript\b[^\r\n]*\/dev\/null\b/i.test(cmd)) return true;
    if ((C._is_ssh_command && C._is_ssh_command(cmd)) || /^\s*(?:sudo\s+|proxychains4?\s+)?(?:ssh|sshpass|evil-winrm)\b/i.test(cmd)) return true;
    if (/\b(?:nc|ncat|netcat)\b[^\r\n]*-[A-Za-z0-9]*l/i.test(cmd) || /\bsocat\b[^\r\n]*\b(?:TCP\d*-)?LISTEN\b/i.test(cmd)) return true;
    if (/^\s*(?:sudo\s+)?su(?:\s|$)/i.test(cmd)) return true;
    if (/^\s*(?:\/[A-Za-z0-9_./-]*\/|\.?\/)?(?:ba|da|z|k|a)?sh\b/i.test(cmd)) return true;
    if (/^\s*(?:sudo|doas)\b/i.test(cmd)) {
      var unwrapped = _strip_cmd_wrappers(cmd);
      if (/\b(?:python[23]?|perl|ruby|php|curl|wget|httpie|nmap|masscan|rustscan|ffuf|gobuster|feroxbuster|wpscan|sqlmap)\b|--rhosts?\b|\bhttps?:\/\//i.test(unwrapped)) {
        return false;
      }
      return true;
    }
    if (hasLocalCtxPrompt && /^\s*psql\b/i.test(cmd)) return true;
    return false;
  }

  function _extract_prompt_telemetry(rawText, ws, command) {
    var rawStr = String(rawText || '');
    var ctxPrompt = (ws && ws.context && ws.context.promptLine) ? String(ws.context.promptLine) : '';
    var followPrompt = (ws && ws.context && ws.context.followPrompt) ? String(ws.context.followPrompt) : '';
    var lhost = (ws && ws.context && ws.context.params && ws.context.params.lhost) || '';
    var priorFacts = ((ws && Array.isArray(ws.facts)) ? ws.facts : []).concat((ws && Array.isArray(ws.seedFacts)) ? ws.seedFacts : []);
    var hasLinuxTargetFoothold = priorFacts.some(function (f) {
      return f && (f.kind === 'foothold.linux' || f.kind === 'access.root');
    });
    var hasTargetContainerCtx = priorFacts.some(function (f) {
      return f && /^privesc\.(?:docker|docker_group|container_group|lxd|lxd_group|group_lxd)$/.test(f.kind);
    });
    var nonAdminWhoamiInTurn = /\bwhoami\b/i.test(String(command || '') + '\n' + rawStr)
      && /^[ \t]*[A-Za-z0-9_.-]+\\(?!administrator\b|system\b|sistema\b)[A-Za-z0-9_.$-]+[ \t]*$/im.test(rawStr)
      && !/^[ \t]*(?:nt authority\\system|[A-Za-z0-9_.-]+\\administrator)[ \t]*$/im.test(rawStr);

    function _scanPromptLines(linesArr, hasExternalTrailing, fromCtx) {
      var out = {
        locus: '',
        user: '',
        host: '',
        cwd: '',
        osFamily: '',
        subshell: '',
        isPrivileged: false,
        hasCommand: false,
        promptLine: '',
        fromContextPrompt: !!fromCtx,
        origin: fromCtx ? 'prompt_telemetry' : 'stdout_telemetry'
      };
      var nonEmptyChecked = 0;
      var limit = Math.min(linesArr.length, 40);
      for (var i = 0; i < limit && nonEmptyChecked < 10; i++) {
        var l = String(linesArr[i] || '').replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '').trim();
        if (!l) continue;
        if (!fromCtx && _PROMPT_BANNER_SKIP_RE.test(l)) continue;
        nonEmptyChecked++;
        var hasTrailingOutput = (i < linesArr.length - 1) || !!hasExternalTrailing;

        // Two-line Kali/Parrot top or bottom box-drawing prompt (always attacker remote locus)
        if (/^[┌╭]──/.test(l) || /^[└╰]─\s*[#$%>]/.test(l)) {
          out.locus = 'remote';
          out.promptLine = l;
          var kaliTopM = /[┌╭]──\s*\(([a-zA-Z0-9_.-]+)(?:@|\u327f)([a-zA-Z0-9_.-]+)\)-\[([^\]]+)\]/.exec(l);
          if (kaliTopM) {
            out.user = kaliTopM[1];
            out.host = kaliTopM[2];
            out.cwd = kaliTopM[3];
          }
          break;
        }

        // Subshell prompts (smbclient, mysql, psql, mssqlclient, ftp, redis, meterpreter)
        if (/^smb:\s*\\[^>]*>/i.test(l)) { out.subshell = 'smb'; out.promptLine = l; break; }
        if (/^(?:mysql|MariaDB\s*\[[^\]]*\])\s*>/i.test(l)) { out.subshell = 'mysql'; out.promptLine = l; break; }
        if (/^SQL\s*\(([^)]*)\)\s*>/i.test(l)) {
          var sqM = /^SQL\s*\(([^)]*)\)\s*>/i.exec(l);
          out.subshell = 'mssql'; out.user = sqM ? sqM[1].trim().split(/\s+/)[0] : ''; out.promptLine = l; break;
        }
        if (/^[a-zA-Z_][a-zA-Z0-9_]*=[#>-]\s+/.test(l) && !/[{"'\[]/.test(l)) { out.subshell = 'psql'; out.promptLine = l; break; }
        if (/^ftp>\s*/i.test(l)) { out.subshell = 'ftp'; out.promptLine = l; break; }
        if (/^meterpreter\s*>/i.test(l)) { out.subshell = 'meterpreter'; out.locus = 'local'; out.hasCommand = true; out.promptLine = l; break; }
        if (/^\d{1,3}(?:\.\d{1,3}){3}:6379>\s*/.test(l)) { out.subshell = 'redis'; out.promptLine = l; break; }

        // Windows OpenSSH prompt: `[domain\]user@HOST C:\path> [cmd]`
        var winSshM = /^(?:([A-Za-z0-9_.-]+)\\)?([A-Za-z0-9_.$-]+)@([A-Za-z0-9_.-]+)\s+([A-Za-z]:\\[^>\r\n]*)>\s*(.*)$/.exec(l);
        if (winSshM) {
          out.user = winSshM[2];
          out.host = winSshM[3];
          out.cwd = winSshM[4].trim();
          out.osFamily = 'windows';
          out.locus = 'local';
          out.hasCommand = !!String(winSshM[5] || '').trim() || hasTrailingOutput;
          out.promptLine = l;
          var isSshDotSvcAdmin = /^C:\\Users\\Administrator\\\.[A-Za-z0-9_.-]+(?:\\|$)/i.test(out.cwd);
          if (/^administrator$/i.test(out.user)
              || (/^C:\\Users\\Administrator(?:\\|$)/i.test(out.cwd) && !isSshDotSvcAdmin && !nonAdminWhoamiInTurn)) {
            out.isPrivileged = true;
          }
          break;
        }

        // Windows PowerShell / Evil-WinRM / cmd.exe prompt
        var winPs = /^(?:\*?Evil-WinRM\*?\s+)?PS\s+([A-Za-z]:\\[^>\r\n]*)>\s*(.*)$/i.exec(l);
        var winCmd = !winPs && /^([A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)>\s*(.*)$/.exec(l);
        if (winPs || winCmd) {
          var cwdWin = (winPs ? winPs[1] : winCmd[1]).trim();
          var cmdAfterWin = (winPs ? winPs[2] : winCmd[2]).trim();
          if (winCmd && _is_dos_emulator_ctx(cmdAfterWin || command, rawStr, l)) continue;
          out.cwd = cwdWin;
          out.osFamily = 'windows';
          out.locus = 'local';
          out.hasCommand = !!cmdAfterWin || hasTrailingOutput;
          out.promptLine = l;
          var isDotSvcUnderAdmin = /^C:\\Users\\Administrator\\\.[A-Za-z0-9_.-]+(?:\\|$)/i.test(cwdWin);
          var uMatch = /^C:\\Users\\([^\\>\r\n]+)/i.exec(cwdWin);
          if (uMatch && !/^(?:Public|Default|All Users)$/i.test(uMatch[1])) {
            if (/^administrator$/i.test(uMatch[1])) {
              if (!isDotSvcUnderAdmin && !nonAdminWhoamiInTurn) {
                out.user = uMatch[1];
                out.isPrivileged = true;
              }
            } else {
              out.user = uMatch[1];
            }
          }
          break;
        }

        // Unix / Kali / Bash prompt:
        // Requires either `[user@host cwd]$` brackets, OR `user@host:cwd$` colon, OR `user@host$` with no space before sigil.
        // Rejects `admin@corp.local # comment` (space between UPN and `#` without brackets or `:`).
        var nixBracketM = /^(?:\([^)]+\)\s*)?\[([a-zA-Z0-9_.-]+)(?:@|\u327f)([a-zA-Z0-9_.-]+)(?:[:\s]+([^\]]*))?\]\s*([#$%])\s*(.*)$/.exec(l);
        var nixColonM = !nixBracketM && /^(?:\([^)]+\)\s*)?([a-zA-Z0-9_.-]+)(?:@|\u327f)([a-zA-Z0-9_-]+)(?::([^\r\n$#%>\]]*))([#$%])\s*(.*)$/.exec(l);
        var nixTightM = !nixBracketM && !nixColonM && /^(?:\([^)]+\)\s*)?([a-zA-Z0-9_.-]+)(?:@|\u327f)([a-zA-Z0-9_-]+)([#$%])(?:\s+(\S.*)|\s*)$/.exec(l);
        var nixM = nixBracketM || nixColonM || nixTightM;
        if (nixM) {
          var u = nixM[1], h = nixM[2];
          var cwdNix = nixTightM ? '' : String(nixM[3] || '').trim();
          var sigil = nixTightM ? nixM[3] : nixM[4];
          var rawTail = String(nixTightM ? nixM[4] : (nixM[5] || ''));
          var cmdAfterNix = rawTail.trim();
          var promptPrefixOnly = rawTail ? l.slice(0, l.length - rawTail.length) : l;
          out.user = u;
          out.host = h;
          out.cwd = cwdNix;
          out.hasCommand = !!cmdAfterNix || hasTrailingOutput;
          out.promptLine = l;
          var hasTunStamp = /\[(?:tun|tap|vpn|wg)\d*:/i.test(promptPrefixOnly) || (lhost && promptPrefixOnly.indexOf(lhost) >= 0);
          var isLocalDockerToolContainer = /^[0-9a-f]{12}$/i.test(h)
            && !hasLinuxTargetFoothold && !hasTargetContainerCtx
            && (/\bdocker\s+(?:run|exec)\b/i.test(String(command || '') + '\n' + rawStr)
                || /^\s*(?:sqlite3|strings|objdump|readelf|gdb|radare2|r2|gcc|g\+\+|python[23]?|john|hashcat|openssl|file|tar|unzip|7za?|apk|apt(?:-get)?|pip3?|gem|cargo)\b/i.test(_strip_cmd_wrappers(cmdAfterNix || command || '')));
          if (_ATTACKER_HOSTS.test(h) || _ATTACKER_HOSTS.test(u) || hasTunStamp || isLocalDockerToolContainer || _REMOTE_OFFENSIVE_TOOLS.test(_strip_cmd_wrappers(cmdAfterNix))) {
            out.locus = 'remote';
          } else {
            out.locus = 'local';
            out.osFamily = 'linux';
            if (sigil === '#' || u === 'root') out.isPrivileged = true;
          }
          break;
        }

        // Bare sh-5.1$ / bash-5.0# or custom argv[0] SUID bash (<progname>-5.1#) prompt
        var shM = /^(?:(?:sh|bash|zsh|dash|ksh)-[\d.]+|(?!(?:HTTP|TLS|SSL|SSH|CVE|PHP|GCC|GDB)-)[A-Za-z0-9_.-]{2,32}-[3-6]\.\d+(?:\.\d+)?)\s*([#$])\s*(.*)$/.exec(l);
        if (shM) {
          out.locus = 'local';
          out.osFamily = 'linux';
          out.isPrivileged = shM[1] === '#';
          out.user = out.isPrivileged ? 'root' : '';
          out.hasCommand = !!(shM[2] && shM[2].trim()) || hasTrailingOutput;
          out.promptLine = l;
          break;
        }

        // Alpine / Ash / BusyBox absolute-path prompt: `/root # [cmd]`, `/var/www/html $ [cmd]`, `/ # [cmd]`
        var alpineM = /^(\/(?:[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*\/?)?)[ \t]+([#$])(?:[ \t]+(\S.*)|[ \t]*)$/.exec(l);
        if (alpineM) {
          var alpPath = alpineM[1];
          var alpSig = alpineM[2];
          var alpTail = String(alpineM[3] || '').trim();
          var isKnownUnixRootPath = alpPath === '/' || alpPath === '/root' || alpPath === '/tmp'
            || /^\/(?:home|var|opt|srv|etc|usr|app|data|run|mnt)\b/.test(alpPath);
          var isShellTail = !alpTail || fromCtx
            || /^(?:id|whoami|uname|cat|ls|pwd|cd|find|env|ps|ip|ifconfig|netstat|ss|crontab|sudo|su|chmod|chown|cp|mv|rm|echo|python[23]?|sh|bash|ash|apk|wget|curl|nc|socat|tar|grep|awk|sed|head|tail|strings|hostname)\b/.test(alpTail);
          if (isKnownUnixRootPath && isShellTail) {
            out.locus = 'local';
            out.osFamily = 'linux';
            out.cwd = alpPath;
            out.isPrivileged = alpSig === '#' || alpPath === '/root' || alpPath.indexOf('/root/') === 0;
            out.user = out.isPrivileged ? 'root' : '';
            out.hasCommand = !!alpTail || hasTrailingOutput;
            out.promptLine = l;
            break;
          }
        }

        // Bare `#` or `# <cmd>` after established Linux foothold + `/root` working directory transition
        if (hasLinuxTargetFoothold
            && (/\bcd\s+\/root\b/.test(String(command || '') + '\n' + rawStr)
                || /^\/root\s*$/m.test(rawStr)
                || /\/root\b/.test(ctxPrompt))
            && /^#(?:[ \t]+((?:id|whoami|pwd|ls|cat|head|tail|find|uname|hostname|ip|ifconfig|ps|chmod|chown|cp|mv|rm|crontab|grep)\b.*))?$/.test(l)) {
          out.locus = 'local';
          out.osFamily = 'linux';
          out.cwd = '/root';
          out.isPrivileged = true;
          out.user = 'root';
          out.hasCommand = true;
          out.promptLine = l;
          break;
        }
      }
      return out;
    }

    var promptHeadStr = rawStr.length > 8192 ? rawStr.slice(0, 8192) : rawStr;
    var stdoutRes = _scanPromptLines(promptHeadStr.split(/\r?\n/), rawStr.length > 8192, false);
    if (stdoutRes.promptLine) return stdoutRes;

    var ctxRes = ctxPrompt ? _scanPromptLines(ctxPrompt.split(/\r?\n/), Boolean(rawStr.trim()), true) : null;

    if (followPrompt && _is_interactive_session_launcher_cmd(command, Boolean(ctxRes && ctxRes.locus === 'local'))) {
      var followRes = _scanPromptLines(followPrompt.split(/\r?\n/), true, false);
      if (followRes.promptLine) {
        followRes.fromFollowPrompt = true;
        return followRes;
      }
    }

    if (ctxRes && ctxRes.promptLine) return ctxRes;

    stdoutRes.origin = '';
    return stdoutRes;
  }
  C._extract_prompt_telemetry = _extract_prompt_telemetry;

  // ---- Axis 2B: Command Argument, Echo Subtraction & Semantic Hint Extractor -------------------
  function _extract_command_semantics(command, ws) {
    var cmd = String(command || '').trim();
    var echoSet = Object.create(null);
    var res = {
      raw: cmd,
      tool: '',
      inputUser: '',
      inputSecret: '',
      inputDomain: '',
      inputPort: 0,
      inputService: '',
      fileSchemaHint: '',
      targetPath: '',
      echoSet: echoSet
    };
    var target = (ws && ws.target) || '';
    if (target) echoSet[target.toLowerCase()] = 1;
    if (!cmd) return res;

    var strippedCmd = _strip_cmd_wrappers(cmd);
    var toks = C._tokenize ? C._tokenize(strippedCmd || cmd) : (strippedCmd || cmd).split(/\s+/);
    for (var i = 0; i < toks.length; i++) {
      var tk = String(toks[i] || '').replace(/^['"]|['"]$/g, '');
      if (!tk) continue;
      if (tk.length >= 2) echoSet[tk.toLowerCase()] = 1;
      if (!res.tool && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(tk) && !/^(?:sudo|proxychains4?|time|env|python3?)$/i.test(tk) && tk.charAt(0) !== '-') {
        res.tool = tk.split(/[\\\/]/).pop().toLowerCase().replace(/\.(?:py|exe|sh|pl|rb)$/i, '');
      }
      var nextTk = (i + 1 < toks.length) ? String(toks[i + 1] || '').replace(/^['"]|['"]$/g, '') : '';
      if (/^(?:-u|--user|--username|-l|--login)$/i.test(tk) && nextTk) {
        res.inputUser = nextTk;
        echoSet[nextTk.toLowerCase()] = 1;
      } else if (/^(?:-p|--pass|--password|-H|--hashes|-k)$/i.test(tk) && nextTk) {
        res.inputSecret = nextTk;
        echoSet[nextTk.toLowerCase()] = 1;
      } else if (/^(?:-d|--domain|-r|--realm)$/i.test(tk) && nextTk) {
        res.inputDomain = nextTk;
        echoSet[nextTk.toLowerCase()] = 1;
      } else if (/^(?:-P|--port)$/i.test(tk) && /^\d{1,5}$/.test(nextTk)) {
        res.inputPort = parseInt(nextTk, 10);
      }

      // Extract domain from impacket-style `corp.local/user:pass@target` or `corp.local/` argument
      var impDomM = /^([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\/(?:[^\/\s]*)?$/.exec(tk);
      if (impDomM && !/^https?:/i.test(tk) && !res.inputDomain) {
        res.inputDomain = impDomM[1];
      }

      // Semantic file / URL endpoint schema hints
      if (/^(?:\/etc\/passwd|.*\\etc\\passwd)$/i.test(tk)) { res.fileSchemaHint = 'unix_passwd'; res.targetPath = tk; }
      else if (/^(?:\/etc\/shadow|.*shadow\.bak)$/i.test(tk)) { res.fileSchemaHint = 'unix_shadow'; res.targetPath = tk; }
      else if (/(?:^|[\\\/])(?:\.env|[^\\\/]*\.(?:ini|conf|cfg|xml|yml|yaml|properties)|wp-config\.php|config\.php|configuration\.php|settings\.py|local_settings\.py|web\.config|unattend\.xml|sysprep\.xml|Groups\.xml|Services\.xml|ScheduledTasks\.xml|DataSources\.xml|Printers\.xml|\.git-credentials|\.npmrc)$/i.test(tk)) {
        res.fileSchemaHint = 'config_secret'; res.targetPath = tk;
      } else if (/(?:^|[\\\/])(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|[^\\\/]*\.(?:pem|ppk|pfx|p12|kdbx))$/i.test(tk)) {
        res.fileSchemaHint = 'key_or_vault'; res.targetPath = tk;
      } else if (/(?:^|[\\\/])[^\\\/]*\.(?:sql|db|sqlite|sqlite3|mdb)$/i.test(tk)) {
        res.fileSchemaHint = 'database_dump'; res.targetPath = tk;
      } else if (/^https?:\/\/[^\/\s]+\/(?:api\/)?(?:v\d+\/)?(?:users|accounts|members|admins|credentials|export|dump)\b/i.test(tk)) {
        res.fileSchemaHint = 'api_users'; res.targetPath = tk;
      }
    }
    if (/^(?:nxc|netexec|crackmapexec|cme)$/i.test(res.tool) && toks.length > 1) {
      var proto = String(toks[1] || '').toLowerCase();
      if (/^(?:smb|ldap|winrm|mssql|ssh|ftp|rdp|wmi)$/.test(proto)) res.inputService = proto;
    }
    return res;
  }
  C._extract_command_semantics = _extract_command_semantics;

  // ---- Axis 1C: Wrapper-Delta Diffing Against Prior Activity -----------------------------------
  function _compute_wrapper_delta(text, ws, command) {
    var ctx = (ws && ws.context) || {};
    var frame = ctx.attentionFrame || {};
    var recent = frame.recentActivities || [];
    var prior = recent[0];
    if (!prior || !prior.stdout || prior.stdout === text) return null;
    if (prior.target && ws && ws.target && prior.target !== ws.target) return null;

    var s = String(text || '');
    var isWebOrMarkup = /\b(?:curl|wget|httpie)\b/i.test(command || '')
      || /\b(?:curl|wget|httpie)\b/i.test(prior.command || '')
      || /^HTTP\/[12]\./im.test(s)
      || /<(?:!DOCTYPE|html|head|body|div|p|pre|span|header|footer|nav|main|section|article)\b/i.test(s);
    if (!isWebOrMarkup) return null;

    var curLines = s.split(/\r?\n/);
    var prevLines = String(prior.stdout || '').split(/\r?\n/);
    if (curLines.length < 5 || prevLines.length < 5) return null;

    var prevSet = Object.create(null);
    for (var i = 0; i < prevLines.length; i++) {
      var pl = prevLines[i].trim();
      if (pl) prevSet[pl] = 1;
    }
    var shared = 0, delta = [];
    for (var j = 0; j < curLines.length; j++) {
      var cl = curLines[j], ct = cl.trim();
      if (!ct) continue;
      if (prevSet[ct]) shared++;
      else delta.push(cl);
    }
    var totalNonEmpty = shared + delta.length;
    if (totalNonEmpty < 5 || shared / totalNonEmpty < 0.45 || !delta.length) return null;
    return {
      sharedCount: shared,
      deltaCount: delta.length,
      deltaText: delta.join('\n'),
      deltaLines: delta
    };
  }
  C._compute_wrapper_delta = _compute_wrapper_delta;

  // ---- Axis 3A: Dynamic 2D Table Header Mapper ------------------------------------------------
  var _COL_PATTERNS = [
    { role: 'user', re: /^(?:user(?:[ _]*name)?|login(?:[ _]*name)?|samaccountname|userprincipalname|account(?:[ _]*name)?|principal|member(?:[ _]*name)?|owner|trustee|grantee|uid|cn)$/i },
    { role: 'identity_fallback', re: /^(?:name|email|e-mail|mail|handle|nick)$/i },
    { role: 'computer', re: /^(?:dnshostname|computer(?:[ _]*name)?|workstation|machine(?:[ _]*name)?)$/i },
    { role: 'secret', re: /^(?:pass(?:word|wd)?(?:[ _]*hash)?|secret(?:[ _]*key)?|(?:nt(?:lm)?[ _]*)?hash|nthash|ntlm|cleartext|credential|token|api[ _]*key|admpwd|cpassword)$/i },
    { role: 'share', re: /^(?:share(?:[ _]*name)?|disk|folder|volume|export|mount(?:[ _]*point)?)$/i },
    { role: 'perm', re: /^(?:perm(?:ission)?s?|access(?:[ _]*rights?)?|rights?|priv(?:ilege)?s?|mode|acl)$/i },
    { role: 'port', re: /^(?:port|local[ _]*port|lport|port\/proto)$/i },
    { role: 'state', re: /^(?:state|status(?:[ _]*code)?|http[ _]*status|result|code)$/i },
    { role: 'proto', re: /^(?:proto(?:col)?)$/i },
    { role: 'service', re: /^(?:service(?:[ _]*name)?|banner|version|product|daemon|application)$/i },
    { role: 'path', re: /^(?:(?:file|url|uri|binary|service|image)[ _]*path|path|file(?:name)?|location|uri|url|endpoint|target|binary|command|task(?:torun)?|imagepath)$/i },
    { role: 'spn', re: /^(?:service[ _]*principal(?:[ _]*name)?|serviceprincipalname|spn)$/i },
    { role: 'domain', re: /^(?:domain(?:[ _]*name)?|realm|workgroup|dns[ _]*domain)$/i },
    { role: 'right', re: /^(?:right|acl[ _]*right|ace|extended[ _]*right|permission[ _]*right|relation(?:ship)?)$/i }
  ];

  var _TABLE_HDR_HINT_RE = /\b(?:user(?:[ _]*name)?|login(?:[ _]*name)?|samaccountname|userprincipalname|account(?:[ _]*name)?|principal|member(?:[ _]*name)?|owner|trustee|grantee|uid|cn|name|email|e-mail|mail|handle|nick|dnshostname|computer(?:[ _]*name)?|workstation|machine(?:[ _]*name)?|pass(?:word|wd)?|secret|nthash|ntlm|hash|cleartext|credential|token|api[ _]*key|admpwd|cpassword|share(?:[ _]*name)?|disk|folder|volume|export|mount|perm(?:ission)?s?|access|rights?|priv(?:ilege)?s?|mode|acl|port|lport|state|status|result|code|proto(?:col)?|service|banner|version|product|daemon|application|path|file(?:name)?|location|uri|url|endpoint|target|binary|command|task(?:torun)?|imagepath|spn|domain|realm|workgroup|ace|relation(?:ship)?)\b/i;
  var _SINGLE_AD_COL_RE = /^(?:cn|samaccountname|userprincipalname|member|membername|dnshostname)$/i;

  function _normalizeTableLine(line) {
    var s = String(line || '');
    if (!/[\u2500-\u257f]/.test(s)) return s;
    return s
      .replace(/[│┃║]/g, '|')
      .replace(/[─━═]/g, '-')
      .replace(/[┼┏┳┓┡╇┩┗┻┛├┤┬┴┌┐└┘]/g, '+');
  }

  function _classifyHeaderCell(cell) {
    var clean = String(cell || '').trim().replace(/^[\[\("']|[\]\)"':]$/g, '').trim();
    if (!clean || clean.length > 36) return '';
    for (var i = 0; i < _COL_PATTERNS.length; i++) {
      if (_COL_PATTERNS[i].re.test(clean)) return _COL_PATTERNS[i].role;
    }
    return '';
  }

  function _splitRowCells(line, mode) {
    if (mode === 'single') {
      return [line.trim()];
    }
    if (mode === 'pipe') {
      var trimmed = line.trim().replace(/^\||\|$/g, '');
      return trimmed.split('|').map(function (c) { return c.trim(); });
    }
    if (mode === 'tab') {
      return line.trim().split(/\t+/).map(function (c) { return c.trim(); });
    }
    if (mode === 'csv') {
      return line.trim().split(/[ \t]*,[ \t]*/).map(function (c) { return c.trim().replace(/^['"]|['"]$/g, ''); });
    }
    return line.trim().split(/[ \t]{2,}/).map(function (c) { return c.trim(); });
  }

  function _parse_dynamic_tables(lines, opts) {
    var tables = [];
    if (!Array.isArray(lines) || lines.length < 2) return tables;
    var adTableCtx = !!(opts && opts.adTableCtx);
    var limit = Math.min(lines.length, 100000);

    for (var i = 0; i < limit - 1; i++) {
      var rawHdr = lines[i];
      if (!rawHdr || rawHdr.length > 512) continue;
      if (!adTableCtx && rawHdr.indexOf('  ') < 0 && rawHdr.indexOf('|') < 0 && rawHdr.indexOf('\t') < 0 && rawHdr.indexOf(',') < 0 && !/[\u2502\u2503\u2551]/.test(rawHdr)) continue;
      if (!_TABLE_HDR_HINT_RE.test(rawHdr)) continue;
      var l = _normalizeTableLine(rawHdr).trim();
      if (!l || /^[\-+|=:*#\s]{2,}$/.test(l)) continue;

      var nextLine = (i + 1 < limit) ? _normalizeTableLine(lines[i + 1]).trim() : '';
      var mode = '';
      if (l.indexOf('|') >= 0 && l.split('|').length >= 3) mode = 'pipe';
      else if (l.indexOf('\t') >= 0 && l.split(/\t+/).length >= 2) mode = 'tab';
      else if (l.indexOf(',') >= 0 && l.split(',').length >= 2 && !/[ \t]{2,}/.test(l)) mode = 'csv';
      else if (/[ \t]{2,}/.test(l)) mode = 'space';
      else if (adTableCtx && _SINGLE_AD_COL_RE.test(l) && /^[\-=]{2,}$/.test(nextLine)) mode = 'single';
      else continue;

      var hdrCells = _splitRowCells(l, mode);
      var isSingleAdCol = (hdrCells.length === 1 && adTableCtx && _SINGLE_AD_COL_RE.test(hdrCells[0]));
      if ((!isSingleAdCol && hdrCells.length < 2) || hdrCells.length > 14) continue;

      var colRoles = [], matchedRoles = 0;
      for (var c = 0; c < hdrCells.length; c++) {
        var r = _classifyHeaderCell(hdrCells[c]);
        colRoles.push(r);
        if (r) matchedRoles++;
      }
      var hasIdentityPeerCol = colRoles.indexOf('secret') >= 0 || colRoles.indexOf('spn') >= 0 || colRoles.indexOf('right') >= 0;
      for (var fc = 0; fc < colRoles.length; fc++) {
        if (colRoles[fc] === 'identity_fallback') {
          if (hasIdentityPeerCol) {
            colRoles[fc] = 'user';
          } else {
            colRoles[fc] = '';
            matchedRoles--;
          }
        }
      }
      var hasSepLine = (isSingleAdCol ? /^[\-+|=:\s]{2,}$/.test(nextLine) : /^[\-+|=:\s]{4,}$/.test(nextLine)) && /[-=]/.test(nextLine);
      if (matchedRoles < 2 && !(matchedRoles === 1 && hasSepLine)) continue;

      var startRow = hasSepLine ? i + 2 : i + 1;
      var rows = [];
      for (var rIdx = startRow; rIdx < limit && rows.length < 5000; rIdx++) {
        var rl = _normalizeTableLine(lines[rIdx]).trim();
        if (!rl) {
          if (rows.length > 0) break;
          continue;
        }
        if ((isSingleAdCol ? /^[\-+|=:\s]{2,}$/.test(rl) : /^[\-+|=:\s]{4,}$/.test(rl)) && /[-=]/.test(rl)) continue;
        if (/^(?:\[\*\]|\[\-\]|\[\!\]|\d+\s+rows?\s+in\s+set|\(\d+\s+rows?\))/i.test(rl)) break;
        if (isSingleAdCol && !/^(?:CN=|[A-Za-z0-9_.$-]+(?:@[A-Za-z0-9_.-]+)?|[A-Za-z0-9_.-]+\\[A-Za-z0-9_.$-]+)$/i.test(rl)) {
          if (rows.length > 0) break;
          continue;
        }

        var cells = _splitRowCells(rl, mode);
        if (cells.length === 1 && mode === 'space') {
          cells = rl.split(/\s+/);
        }
        if (cells.length < (isSingleAdCol ? 1 : 2)) {
          if (rows.length > 0) break;
          continue;
        }
        var rowObj = { _raw: rl };
        var populated = 0;
        for (var k = 0; k < colRoles.length && k < cells.length; k++) {
          var role = colRoles[k];
          if (role && cells[k] !== '' && !rowObj[role]) {
            rowObj[role] = cells[k];
            populated++;
          }
        }
        if (populated > 0) rows.push(rowObj);
      }

      if (rows.length > 0) {
        tables.push({ mode: mode, roles: colRoles, headers: hdrCells, rows: rows });
        i = startRow + rows.length - 1;
      }
    }
    return tables;
  }
  C._parse_dynamic_tables = _parse_dynamic_tables;

  // ---- Interactive CLI Password Prompt Echo Guard ---------------------------------------------
  var _INTERACTIVE_PW_TOOL_RE = /\b(?:su|sudo|ssh|scp|sftp|impacket-[\w.-]+|GetNPUsers|GetUserSPNs|secretsdump|psexec|wmiexec|smbexec|atexec|dcomexec|mssqlclient|evil-winrm|smbclient|rpcclient|ldapsearch|mysql|psql|ftp|telnet|kinit|runas)\b/i;
  var _INTERACTIVE_AUTH_FAIL_RE = /(?:\[\-\]|Authentication failure|Login incorrect|Sorry, try again|Permission denied|UF_DONT_REQUIRE_PREAUTH|Cannot authenticate|Logon failure|STATUS_LOGON_FAILURE|Access denied|^su:\s)/i;

  function _isInteractivePasswordPromptEcho(linesArr, idx, fullText, command) {
    var ln = String((linesArr && linesArr[idx]) || '');
    if (!ln || ln.indexOf(':') < 0 || !/password/i.test(ln)) return false;
    if (/^\s*\[sudo\]\s*password\s+for\s+[^:\r\n]+:\s*\S*\s*$/i.test(ln)) return true;
    if (/^\s*[^\s:'"]+@[A-Za-z0-9_.-]+'s\s+password:\s*\S*\s*$/i.test(ln)) return true;
    if (!/^\s*(?:Enter\s+)?Password(?:\s+for\s+[^\r\n:]+)?\s*:\s*\S+\s*$/i.test(ln)) return false;
    var nextWindow = [linesArr[idx + 1] || '', linesArr[idx + 2] || ''].join('\n');
    if (_INTERACTIVE_AUTH_FAIL_RE.test(nextWindow)) return true;
    var prevWindow = [linesArr[idx - 1] || '', linesArr[idx - 2] || ''].join('\n');
    var hasSiblingIdentityKv = /^\s*(?:Login|User(?:name)?|Account|sAMAccountName)\s*[:=]\s*\S/im.test(prevWindow + '\n' + (linesArr[idx + 1] || ''));
    if (!hasSiblingIdentityKv && (_INTERACTIVE_PW_TOOL_RE.test(command || '') || /Impacket v\d+\.\d+/i.test(fullText || ''))) {
      return true;
    }
    return false;
  }

  // ---- Axis 3B: Key-Value Paragraph / Block Grouper (including XML leaf elements) -------------
  var _KV_LINE_RE = /^\s*(?:(?:\[[*+\-!]\]|[-*•>])\s+)?["']?([A-Za-z][A-Za-z0-9_.\-\/ ()]{1,42}?)["']?\s*(?:: base64:|:|=)\s*(\S[^\r\n]*)$/;
  var _XML_LEAF_GLOBAL_RE = /<([A-Za-z][A-Za-z0-9_.:-]{1,39})(?:\s+([^>\r\n]*))?>([^<\r\n]{1,256})<\/\1>|(<\/(?:[A-Za-z0-9_.-]+:)?(?:logonCredentials|credentials|server|account|user|connection|entry|item|record|host|profile)>)/gi;
  var _XML_ATTR_LEAF_GLOBAL_RE = /<(?:[A-Za-z0-9_.-]+:)?(?:param|property|add|setting|item|entry|var|option)\b([^>\r\n]*)\/?>/gi;
  var _HTML_LAYOUT_TAG_RE = /^(?:td|th|tr|div|span|p|a|li|ul|ol|h[1-6]|b|i|u|strong|em|code|pre|title|option|label|button|script|style)$/i;
  var _XML_CLOSE_BLOCK_RE = /^\s*<\/(?:[A-Za-z0-9_.-]+:)?(?:logonCredentials|credentials|server|account|user|connection|entry|item|record|host|profile)>\s*$/i;
  var _BLOCK_START_KEY_RE = /^(?:dn|distinguishedname|cn|samaccountname|name|username|user|account|login|principal|member|uid|upn|userprincipalname|spn|serviceprincipalname|objectsid|sid|template[ _]?name|ca[ _]?name|taskname|service[ _]?name|service|target|object|trustee|host|ip|id)$/i;
  var _SECTION_DIVIDER_RE = /^\s*(?:\[(?:Record|Entry|Object|User|Account|Template|Service|Task|Rule|ACE|Share)\b[^\r\n\]]{0,120}\]|[-=*]{3,}(?:\s+[^-=*\s][^\r\n]{0,120}?\s+[-=*]{3,})?)\s*$/i;

  function _group_kv_blocks(lines, fullText, command) {
    var blocks = [], cur = null;
    if (!Array.isArray(lines)) return blocks;
    var limit = Math.min(lines.length, 100000);
    var docHasLt = fullText ? (fullText.indexOf('<') >= 0) : true;

    for (var i = 0; i < limit; i++) {
      var raw = lines[i];
      if (!raw || raw.length > 2048) continue;
      var t = raw.trim();
      var c0 = t ? t.charCodeAt(0) : 0;
      if (!t || ((c0 === 45 || c0 === 61 || c0 === 42 || c0 === 91 || c0 === 93 || c0 === 123 || c0 === 125 || c0 === 44 || c0 === 60)
          && (/^[-=*]{3,}$/.test(t) || /^[{}[\],]+$/.test(t) || (docHasLt && c0 === 60 && _XML_CLOSE_BLOCK_RE.test(t)) || (t.length <= 240 && _SECTION_DIVIDER_RE.test(t))))) {
        if (cur && cur._count >= 2) blocks.push(cur);
        cur = null;
        continue;
      }
      var lineHasLt = docHasLt && t.indexOf('<') >= 0;
      if (!lineHasLt && ((c0 >= 48 && c0 <= 57) || (raw.indexOf(':') < 0 && raw.indexOf('=') < 0))) continue;
      if (_isInteractivePasswordPromptEcho(lines, i, fullText, command)) continue;

      var pairs = [];
      if (lineHasLt && t.indexOf('</') > 1) {
        _XML_LEAF_GLOBAL_RE.lastIndex = 0;
        var xm;
        while ((xm = _XML_LEAF_GLOBAL_RE.exec(raw)) !== null) {
          if (xm[4]) {
            pairs.push({ closeBlock: true });
            continue;
          }
          var xTag = xm[1].replace(/^.*:/, '');
          if (_HTML_LAYOUT_TAG_RE.test(xTag)) continue;
          var xAttrs = xm[2] || '';
          var xVal = xm[3].trim();
          if (!xVal) continue;
          if (/\bstoreAsClearText\s*=\s*["']?false["']?/i.test(xAttrs) || /\bencrypted\s*=\s*["']?(?:true|1)["']?/i.test(xAttrs)) continue;
          if (/^(?:pass(?:word|wd)?|pwd|secret)$/i.test(xTag) && /^AQAAANCMnd8BFdER/.test(xVal)) continue;
          pairs.push({ k: xTag, v: xVal });
        }
      }
      if (!pairs.length && lineHasLt && t.indexOf('=') > 1) {
        _XML_ATTR_LEAF_GLOBAL_RE.lastIndex = 0;
        var xam;
        while ((xam = _XML_ATTR_LEAF_GLOBAL_RE.exec(raw)) !== null) {
          var xaBody = xam[1] || '';
          if (/\bstoreAsClearText\s*=\s*["']?false["']?/i.test(xaBody) || /\bencrypted\s*=\s*["']?(?:true|1)["']?/i.test(xaBody)) continue;
          var xaKeyM = /\b(?:name|key|id)\s*=\s*(?:"([^"\r\n]{1,64})"|'([^'\r\n]{1,64})')/i.exec(xaBody);
          var xaValM = /\bvalue\s*=\s*(?:"([^"\r\n]{1,256})"|'([^'\r\n]{1,256})')/i.exec(xaBody);
          if (!xaKeyM || !xaValM) continue;
          var xaKey = (xaKeyM[1] || xaKeyM[2] || '').trim();
          var xaVal = (xaValM[1] || xaValM[2] || '').trim();
          if (!xaKey || !xaVal) continue;
          if (/^(?:[A-Za-z0-9_.-]*(?:pass(?:word|wd)?|pwd)|pw|secret)$/i.test(xaKey) && /^AQAAANCMnd8BFdER/.test(xaVal)) continue;
          pairs.push({ k: xaKey, v: xaVal });
        }
      }
      if (!pairs.length) {
        if (raw.indexOf(':') < 0 && raw.indexOf('=') < 0) continue;
        var m = _KV_LINE_RE.exec(raw);
        if (!m) continue;
        var kvKeyRaw = m[1].trim();
        var kvValTrim = m[2].trim().replace(/,\s*$/, '');
        var kvWasQuoted = /^(["']).*\1$/.test(kvValTrim);
        var kvValUnq = kvValTrim.replace(/^(["'])(.*)\1$/, '$2').trim();
        if (!kvWasQuoted && kvValUnq.charAt(kvValUnq.length - 1) === ':'
            && /^(?:[A-Za-z0-9_.-]*(?:pass(?:word|wd)?|pwd)|pw|secret|cleartext)$/i.test(kvKeyRaw)) {
          var subUserCand = kvValUnq.slice(0, -1).trim();
          if (/^[A-Za-z0-9_.-]{2,32}$/.test(subUserCand) && !isBoilerplateUser(subUserCand) && i + 1 < limit) {
            var nxtKvLn = String(lines[i + 1] || '').trim();
            if (nxtKvLn && nxtKvLn.length >= 3 && nxtKvLn.length <= 128 && !/\s/.test(nxtKvLn)
                && nxtKvLn.charAt(nxtKvLn.length - 1) !== ':' && !isPlaceholderSecret(nxtKvLn, null)) {
              pairs.push({ k: 'user', v: subUserCand }, { k: kvKeyRaw, v: nxtKvLn });
              i++;
            } else {
              continue;
            }
          } else {
            continue;
          }
        } else {
          pairs.push({
            k: kvKeyRaw,
            v: kvValUnq
          });
        }
      }

      for (var pi = 0; pi < pairs.length; pi++) {
        if (pairs[pi].closeBlock) {
          if (cur && cur._count >= 2) blocks.push(cur);
          cur = null;
          continue;
        }
        var k = pairs[pi].k, v = pairs[pi].v;
        var kLow = k.toLowerCase().replace(/[\s\-()\/.]+/g, '_').replace(/^_+|_+$/g, '');
        if (/^(?:http|https|ftp|ldap|smb|ssh|mailto|file)$/i.test(kLow)) continue;

        if (cur && ((_BLOCK_START_KEY_RE.test(k) && cur[kLow] !== undefined && cur._count >= 2) || cur._count >= 120)) {
          blocks.push(cur);
          cur = null;
        }
        if (!cur) cur = { _count: 0, _lines: [] };
        if (cur[kLow] === undefined) {
          cur[kLow] = v;
        } else if (Array.isArray(cur[kLow])) {
          cur[kLow].push(v);
        } else {
          cur[kLow] = [cur[kLow], v];
        }
        cur._count++;
        if (cur._lines[cur._lines.length - 1] !== t) cur._lines.push(t);
      }
    }
    if (cur && cur._count >= 2) blocks.push(cur);
    return blocks;
  }
  C._group_kv_blocks = _group_kv_blocks;

  // ---- Axis 3C: Statistical Outlier Row Detector ----------------------------------------------
  function _lineStructuralShape(line) {
    var t = line.trim();
    if (!t) return '';
    var pfx = '';
    var pm = /^(\[[+\-*!]\]|\d{3}\b|ERR|FAIL|WARN|OK)/i.exec(t);
    if (pm) pfx = pm[1].toUpperCase();
    var statusM = /\b(?:Status|Code)\s*[:=]\s*(\d{3})\b/i.exec(t) || /^\s*(\d{3})\s+/.exec(t);
    var status = statusM ? statusM[1] : '';
    var words = t.split(/\s+/).length;
    var bucket = Math.round(words / 2) * 2;
    return pfx + '|' + status + '|' + bucket;
  }

  function _find_statistical_outliers(lines) {
    if (!Array.isArray(lines) || lines.length < 10) return [];
    var nonEmpty = [];
    for (var i = 0; i < lines.length && nonEmpty.length < 500; i++) {
      var t = lines[i].trim();
      if (t && !/^[=\-#*]{3,}/.test(t)) nonEmpty.push(t);
    }
    if (nonEmpty.length < 10) return [];
    var counts = Object.create(null), dominantShape = '', maxCount = 0;
    var shapes = [];
    for (var j = 0; j < nonEmpty.length; j++) {
      var sh = _lineStructuralShape(nonEmpty[j]);
      shapes.push(sh);
      counts[sh] = (counts[sh] || 0) + 1;
      if (counts[sh] > maxCount) { maxCount = counts[sh]; dominantShape = sh; }
    }
    if (maxCount / nonEmpty.length < 0.80) return [];
    var outliers = [];
    for (var k = 0; k < nonEmpty.length; k++) {
      if (shapes[k] !== dominantShape) outliers.push(nonEmpty[k]);
    }
    return outliers.length <= 5 ? outliers : [];
  }
  C._find_statistical_outliers = _find_statistical_outliers;

  // ---- Axis 4: The ~45-Atom Lexicon Extractor -------------------------------------------------
  var _ATOM_IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  var _ATOM_CIDR_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\/(?:[89]|[12]\d|3[0-2])\b/g;
  var _ATOM_PORT_PROTO_RE = /\b(\d{1,5})\/(tcp|udp)\b/gi;
  var _ATOM_URI_PATH_RE = /(?:^|[\s"'(])(\/[A-Za-z0-9_.\-\/]{1,120})(?=[\s"')]|$)/g;
  var _ATOM_HTTP_STATUS_RE = /(?:^HTTP\/[12](?:\.\d)?\s+(\d{3})\b|\b(?:Status|Code)\s*[:=]\s*(\d{3})\b|\(\s*Status:\s*(\d{3})\s*\)|\[\s*Status:\s*(\d{3})\b)/im;
  var _ATOM_DOM_USER_RE = /(?<![\\/:A-Za-z0-9_.-])((?:nt authority|nt service|iis apppool|window manager|font driver host)|[A-Za-z0-9_.-]{2,32})\\([A-Za-z0-9_.\-$]{2,48})(?=$|[^A-Za-z0-9_.\-$\\/])/gi;
  var _ATOM_WIN_SVC_WHOAMI_RE = /^[ \t]*((?:nt authority|nt service|iis apppool|window manager|font driver host)\\[A-Za-z0-9_.$-](?:[A-Za-z0-9_.$ -]{0,62}[A-Za-z0-9_.$-])?)[ \t]*$/im;
  var _ATOM_UPN_RE = /\b([A-Za-z0-9_.\-]{2,48})@([A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+)\b/g;
  var _ATOM_POSIX_ID_RE = /(?<![A-Za-z]{2})uid=(\d+)\(([^)\r\n]{1,48})\)\s+gid=(\d+)\(([^)\r\n]{1,48})\)(?:\s+euid=(\d+)\(([^)\r\n]{1,48})\))?/i;
  var _ATOM_WIN_SID_RE = /\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b/g;
  var _ATOM_LDAP_DN_RE = /\b(?:CN|OU|DC)=[^,\r\n]{1,64}(?:,(?:CN|OU|DC)=[^,\r\n]{1,64})+\b/gi;
  var _ATOM_SPN_RE = /(?<![\/\\.A-Za-z0-9_-])(MSSQLSvc|HTTP|cifs|ldap|host|wsman|krbtgt|exchangeMDB|termsrv|vnc|nfs|ipp|restrictedkrbhost|wsmansvc|dns|gc|smtp|imap|pop3?|kadmin|netlogon)\/(?![0-9]+(?:\.[0-9]+)?\b)([A-Za-z0-9_.\-]*[A-Za-z][A-Za-z0-9_.\-]*(?::\d{1,5})?)\b/gi;
  var _ATOM_MOD_HASH_RE = /(?:\$krb5(?:tgs|asrep)\$[^\s"']+|(?:\$DCC2\$\d+#[^#\s]+#[0-9a-fA-F]{32})|\$(?:2[abxy]|5|6|1|y|NT|apr1|keepass|pfx(?:ng)?|pkzip2?|zip2|7z|rar[35]?|sshng|ansible|pdf|office|sntp-ms|rakp)\$[^\s"':]+|pbkdf2_sha(?:1|256|512)\$[^\s"']+)/gi;
  var _ATOM_NTHASH_PAIR_RE = /(?:^|\b|:)(?:aad3b435b51404eeaad3b435b51404ee|[0-9a-fA-F]{32}|NO PASSWORD\*+):([0-9a-fA-F]{32})\b/gi;
  var _ATOM_HEX32_RE = /\b([0-9a-fA-F]{32})\b/g;
  var _ATOM_JWT_RE = /\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*\b/g;
  var _ATOM_KV_SECRET_RE = /\b(?:[A-Za-z0-9_]*(?:pass(?:word|wd)?|pwd)|[A-Za-z0-9_]*[a-z0-9_]pw|pw|secret|api[_-]?key|access[_-]?token|auth[_-]?token|ms-?mcs-?admpwd|mslaps-password|cleartext)\s*[:=]\s*(?:"([^"\r\n]{3,128})"|'([^'\r\n]{3,128})'|(?![ \t]*["'])([^\s'"\r\n,;]{3,128})(?=[ \t]*(?:[,;#]|\/\/|$)))/gi;
  var _ATOM_WIN_PATH_RE = /\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\s]+\\)*[^\\/:*?"<>|\r\n\s]+/g;
  var _ATOM_UNC_PATH_RE = /\\\\[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+(?:\\[^\r\n\s"']*)?/g;
  var _ATOM_POSIX_PATH_RE = /(?:^|[\s"':=])(\/(?:etc|var|opt|home|root|usr|tmp|srv|proc|dev|mnt|media|run)\/[A-Za-z0-9_.\-\/]{1,120})/g;
  var _ATOM_PERM_MODE_RE = /(?:-[rwxstS-]{9}|\b(?:READ|WRITE|NO\s+ACCESS|NOPASSWD|ALL=\(ALL(?::ALL)?\)|SERVICE_ALL_ACCESS|FILE_ALL_ACCESS|cap_[a-z_]+\+[eip]+)\b|\((?:F|M|W|RX|R)\))/gi;
  var _ATOM_ACL_VERB_RE = /\b(GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember|AddSelf|AllExtendedRights|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|WriteSPN|WriteProperty)\b/gi;
  var _ATOM_ADCS_FLAG_RE = /\b(ESC(?:[1-9]|1[0-5])|ENROLLEE_SUPPLIES_SUBJECT|CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT|Certificate\s+Request\s+Agent|Any\s+Purpose)\b/gi;
  var _ATOM_DELEG_RE = /\b(msDS-AllowedToDelegateTo|msDS-AllowedToActOnBehalfOfOtherIdentity|TRUSTED_FOR_DELEGATION|TRUSTED_TO_AUTH_FOR_DELEGATION)\b/gi;
  var _ATOM_WIN_PRIV_RE = /\b(SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeDebugPrivilege|SeLoadDriverPrivilege|SeTakeOwnershipPrivilege|SeManageVolumePrivilege|SeCreateTokenPrivilege|SeTcbPrivilege)\b/gi;
  var _ATOM_POS_POLARITY_RE = /(?:\[\+\]|\bSUCCESS(?:FUL|FULLY)?\b|\bVALID\b|\bPwn3d!|\bOPEN\b|\bENABLED\b|\bAUTHENTICATED\b|\bGRANTED\b|\bVULNERABLE\b|\bCRACKED\b|\bFOUND\b)/i;
  var _ATOM_NEG_POLARITY_RE = /(?:\[\-\]|\[\!\]|\bFAILED\b|\bFAILURE\b|\bDENIED\b|\bERROR\b|\bREFUSED\b|\bINVALID\b|\bCLOSED\b|\bFILTERED\b|\bDISABLED\b|\bNOT\s+VULNERABLE\b|\bNOT\s+FOUND\b|\b0\s+results\b|\b0\s+hosts\s+up\b|\bNo\s+entries\b|\busage:|\bTraceback\b)/i;

  function _lineHasNegPolarity(lines, idx) {
    var ln = lines[idx] || '';
    if (_ATOM_NEG_POLARITY_RE.test(ln)) return true;
    if (idx > 0) {
      var prev = lines[idx - 1] || '';
      if ((/\[\-\]|\b(?:FAILED|FAILURE|DENIED|INVALID|REJECTED|REFUSED|ERROR)\b/i.test(prev)) && !/\[\+\]|\b(?:SUCCESS|VALID|AUTHENTICATED)\b/i.test(ln)) {
        return true;
      }
    }
    return false;
  }

  function _subnet24(ip) {
    var m = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/.exec(String(ip || '').trim());
    return m ? m[1] : '';
  }

  function _isPrivateIpv4(ip, allowZero) {
    var p = String(ip || '').split('.').map(Number);
    if (p.length !== 4 || p.some(function (n) { return isNaN(n) || n < 0 || n > 255; })) return false;
    var minOctet = allowZero ? 0 : 1;
    if (p[0] === 10) return p[3] >= minOctet && p[3] < 255;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return p[3] >= minOctet && p[3] < 255;
    if (p[0] === 192 && p[1] === 168) return p[3] >= minOctet && p[3] < 255;
    return false;
  }

  var _LAB_VPN_SUBNET_RE = /^(?:192\.168\.(?:45|48|49)|10\.10\.(?:14|15|16|17)|10\.8\.0)$/;
  var _ROUTING_OR_IFACE_RE = /\b(?:inet\s+\d|netmask\s+255|brd\s+\d|scope\s+(?:global|link)|IPv4\s+Address|Subnet\s+Mask|Default\s+Gateway|Network\s+Destination|Genmask|Kernel\s+IP\s+routing\s+table|proto\s+kernel|\bdev\s+(?:eth|ens|enp|eno|wlan|tun|tap|docker|br-|veth|lo)\S*|\blladdr\s+[0-9a-f]{2}:)/i;

  function _extract_atoms(text, ws, cmdSem, preSplitLines) {
    var s = String(text || '');
    if (s.length > 10485760) s = s.slice(0, 10485760);
    var target = (ws && ws.target) || '';
    var lhost = (ws && ws.context && ws.context.params && ws.context.params.lhost) || '';
    var targetSub = _subnet24(target);
    var lhostSub = _subnet24(lhost);
    var echoSet = (cmdSem && cmdSem.echoSet) || Object.create(null);

    var ipv4s = [], newSubnetIps = [], cidrs = [], ports = [], uriPaths = [], domUsers = [], upns = [];
    var sids = [], dns = [], spns = [], modHashes = [], ntHashes = [], jwts = [], kvSecrets = [], multilineKvCreds = [];
    var winPaths = [], uncPaths = [], posixPaths = [], permModes = [], aclVerbs = [], adcsFlags = [], delegAttrs = [], winPrivs = [];
    var MAX_ATOM_ITEMS = 5000;
    function pushUniq(arr, val) {
      if (arr.length >= MAX_ATOM_ITEMS) return;
      var k = String(val || '').trim();
      if (!k) return;
      var seen = arr._seen || (arr._seen = Object.create(null));
      if (seen[k]) return;
      seen[k] = 1;
      arr.push(k);
    }

    var excludedPivotIps = Object.create(null), excludedPivotSubs = Object.create(null);
    if (s.indexOf('connect to [') >= 0) {
      var connRe = /connect to \[(\d{1,3}(?:\.\d{1,3}){3})\] from [^\r\n]*\[(\d{1,3}(?:\.\d{1,3}){3})\]/gi, connM;
      while ((connM = connRe.exec(s)) !== null) {
        excludedPivotIps[connM[1]] = 1;
        var connSub1 = _subnet24(connM[1]);
        if (connSub1) excludedPivotSubs[connSub1] = 1;
        excludedPivotIps[connM[2]] = 1;
      }
    }
    var hasRoutingOrIfaces = _ROUTING_OR_IFACE_RE.test(s);

    var m, seenRawIp = Object.create(null);
    if (s.indexOf('.') >= 0) {
      _ATOM_IPV4_RE.lastIndex = 0;
      while ((m = _ATOM_IPV4_RE.exec(s)) !== null) {
        if (ipv4s.length >= MAX_ATOM_ITEMS) break;
        var ip = m[0];
        if (seenRawIp[ip]) continue;
        seenRawIp[ip] = 1;
        if (!_isPrivateIpv4(ip, false)) continue;
        pushUniq(ipv4s, ip);
        var sub = _subnet24(ip);
        if (ip !== target && ip !== lhost && sub && sub !== targetSub && sub !== lhostSub
            && !excludedPivotIps[ip] && !excludedPivotSubs[sub]
            && (hasRoutingOrIfaces || !_LAB_VPN_SUBNET_RE.test(sub))) {
          pushUniq(newSubnetIps, ip);
        }
      }
    }
    if (s.indexOf('/') >= 0) {
      _ATOM_CIDR_RE.lastIndex = 0;
      while ((m = _ATOM_CIDR_RE.exec(s)) !== null) {
        if (cidrs.length >= MAX_ATOM_ITEMS) break;
        var cidrParts = m[0].split('/');
        var cIp = cidrParts[0], cPfx = parseInt(cidrParts[1], 10);
        if (cPfx >= 8 && cPfx <= 30 && _isPrivateIpv4(cIp, true)) {
          var cSub = _subnet24(cIp);
          if (cSub !== targetSub && cSub !== lhostSub && !excludedPivotSubs[cSub]
              && (hasRoutingOrIfaces || !_LAB_VPN_SUBNET_RE.test(cSub))) {
            var o = cIp.split('.').map(Number);
            var bits = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
            var mask = (0xFFFFFFFF << (32 - cPfx)) >>> 0;
            var net = (bits & mask) >>> 0;
            var canonCidr = [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.') + '/' + cPfx;
            pushUniq(cidrs, canonCidr);
          }
        }
      }
      _ATOM_PORT_PROTO_RE.lastIndex = 0;
      while ((m = _ATOM_PORT_PROTO_RE.exec(s)) !== null) {
        if (ports.length >= MAX_ATOM_ITEMS) break;
        var pNum = parseInt(m[1], 10);
        if (pNum >= 1 && pNum <= 65535) pushUniq(ports, pNum + '/' + m[2].toLowerCase());
      }
      _ATOM_URI_PATH_RE.lastIndex = 0;
      while ((m = _ATOM_URI_PATH_RE.exec(s)) !== null) {
        if (uriPaths.length >= 200) break;
        var up = m[1];
        if (!/^\/(?:etc|var|opt|home|root|usr|tmp|proc|dev|sys|bin|sbin|lib|run)\b/.test(up) && up.length > 1) {
          pushUniq(uriPaths, up);
        }
      }
    }
    if (s.indexOf('\\') >= 0) {
      var wgSet = Object.create(null);
      wgSet['workgroup'] = 1;
      var wgRe = /\(name:([^)\r\n]+)\)\s*\(domain:([^)\r\n]+)\)/gi, wgM;
      while ((wgM = wgRe.exec(s)) !== null) {
        var wn = wgM[1].trim().toLowerCase(), wd = wgM[2].trim().toLowerCase();
        if (wn && wd && (wn === wd || wd === 'workgroup')) { wgSet[wn] = 1; wgSet[wd] = 1; }
      }
      _ATOM_DOM_USER_RE.lastIndex = 0;
      while ((m = _ATOM_DOM_USER_RE.exec(s)) !== null) {
        if (domUsers.length >= MAX_ATOM_ITEMS) break;
        var dom = m[1], usr = m[2];
        if (wgSet[dom.toLowerCase()]) continue;
        if (/^(?:nt authority|nt service|iis apppool|window manager|font driver host|builtin)$/i.test(dom)) continue;
        if (!/^(?:http|https|C|D|E|HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|Microsoft|Windows|WINNT|Program|System32|SysWOW64|Users|inetpub|pipe|ipc|rpc|ncacn_np|ncacn_ip_tcp|ncalrpc|System|CurrentVersion|CurrentControlSet|Software|Policies|Classes)$/i.test(dom) && !isBoilerplateUser(usr)) {
          pushUniq(domUsers, dom + '\\' + usr);
        }
      }
    }
    if (s.indexOf('@') >= 0) {
      _ATOM_UPN_RE.lastIndex = 0;
      while ((m = _ATOM_UPN_RE.exec(s)) !== null) {
        if (upns.length >= MAX_ATOM_ITEMS) break;
        if (!isBoilerplateUser(m[1]) && !_PUBLIC_EMAIL_DOMAINS.test(m[2])) pushUniq(upns, m[0]);
      }
    }
    var posixIdM = s.indexOf('uid=') >= 0 ? _ATOM_POSIX_ID_RE.exec(s) : null;
    var hasEuidRoot = /\beuid=0\(root\)/i.test(s);
    var posixId = posixIdM ? {
      uid: (hasEuidRoot || (posixIdM[5] !== undefined && parseInt(posixIdM[5], 10) === 0)) ? 0 : parseInt(posixIdM[1], 10),
      user: (hasEuidRoot || (posixIdM[5] !== undefined && parseInt(posixIdM[5], 10) === 0)) ? (posixIdM[6] || 'root') : posixIdM[2],
      gid: parseInt(posixIdM[3], 10),
      group: posixIdM[4]
    } : (hasEuidRoot ? { uid: 0, user: 'root', gid: 0, group: 'root' } : null);

    if (s.indexOf('S-1-5-21-') >= 0) {
      _ATOM_WIN_SID_RE.lastIndex = 0;
      while ((m = _ATOM_WIN_SID_RE.exec(s)) !== null) { if (sids.length >= MAX_ATOM_ITEMS) break; pushUniq(sids, m[0]); }
    }
    if (s.indexOf('=') >= 0 && /\b(?:CN|OU|DC)=/i.test(s)) {
      _ATOM_LDAP_DN_RE.lastIndex = 0;
      while ((m = _ATOM_LDAP_DN_RE.exec(s)) !== null) { if (dns.length >= MAX_ATOM_ITEMS) break; pushUniq(dns, m[0]); }
    }
    if (s.indexOf('/') >= 0) {
      _ATOM_SPN_RE.lastIndex = 0;
      while ((m = _ATOM_SPN_RE.exec(s)) !== null) { if (spns.length >= MAX_ATOM_ITEMS) break; pushUniq(spns, m[0]); }
    }
    if (s.indexOf('$') >= 0 || /pbkdf2_sha/i.test(s)) {
      _ATOM_MOD_HASH_RE.lastIndex = 0;
      while ((m = _ATOM_MOD_HASH_RE.exec(s)) !== null) { if (modHashes.length >= MAX_ATOM_ITEMS) break; pushUniq(modHashes, m[0]); }
    }
    if (s.indexOf(':') >= 0) {
      _ATOM_NTHASH_PAIR_RE.lastIndex = 0;
      while ((m = _ATOM_NTHASH_PAIR_RE.exec(s)) !== null) {
        if (ntHashes.length >= MAX_ATOM_ITEMS) break;
        var nt = m[1].toLowerCase();
        if (nt !== _EMPTY_NTHASH && nt !== _EMPTY_LMHASH && nt !== _EMPTY_MD5 && !echoSet[nt]) pushUniq(ntHashes, nt);
      }
    }
    if (s.indexOf('eyJ') >= 0) {
      _ATOM_JWT_RE.lastIndex = 0;
      while ((m = _ATOM_JWT_RE.exec(s)) !== null) { if (jwts.length >= MAX_ATOM_ITEMS) break; pushUniq(jwts, m[0]); }
    }

    var sLines = (Array.isArray(preSplitLines) && text === s) ? preSplitLines : s.split(/\r?\n/);
    var sLineCap = Math.min(sLines.length, 100000);
    var kvHintRe = /(?:pass|pwd|[a-z0-9_]pw\b|\bpw\s*[:=]|secret|key|token|admpwd|cleartext)/i;
    var docHasLt = s.indexOf('<') >= 0;
    var hasXmlNonPlainEnc = docHasLt && s.indexOf('encryptionMethod') >= 0 && /<encryptionMethod>\s*(?!None\b|ClearText\b|Plain(?:text)?\b|False\b|0\b)[A-Za-z0-9_.-]+/i.test(s);
    var xmlSecTagRe = /<(?:[A-Za-z0-9_.-]+:)?(pass(?:word|wd)?|pwd|pw|secret|cpassword|apikey|api_key)(?:\s+([^>\r\n]*))?>([^<\r\n]{3,128})<\/(?:[A-Za-z0-9_.-]+:)?\1>/gi;
    var xmlAttrSecRe = /<(?:[A-Za-z0-9_.-]+:)?(?:param|property|add|setting|item|entry|var|option)\b([^>\r\n]*)\/?>/gi;
    for (var sli = 0; sli < sLineCap; sli++) {
      var sLn = sLines[sli];
      if (!sLn || sLn.length > 2048 || !kvHintRe.test(sLn)) continue;
      if (_isInteractivePasswordPromptEcho(sLines, sli, s, cmdSem && cmdSem.raw)) continue;
      if (_windowHasDecodeFailure(sLines, sli)) continue;
      if (docHasLt && !hasXmlNonPlainEnc && sLn.indexOf('<') >= 0 && sLn.indexOf('</') > 1) {
        xmlSecTagRe.lastIndex = 0;
        var xsm, matchedXmlSec = false;
        while ((xsm = xmlSecTagRe.exec(sLn)) !== null) {
          matchedXmlSec = true;
          if (!/\bstoreAsClearText\s*=\s*["']?false["']?/i.test(xsm[2] || '') && !/\bencrypted\s*=\s*["']?(?:true|1)["']?/i.test(xsm[2] || '')) {
            var xSecVal = xsm[3].trim();
            if (!/^AQAAANCMnd8BFdER/.test(xSecVal) && !isPlaceholderSecret(xSecVal, echoSet)) {
              pushUniq(kvSecrets, xSecVal);
            }
          }
        }
        if (matchedXmlSec) continue;
      }
      if (docHasLt && !hasXmlNonPlainEnc && sLn.indexOf('<') >= 0 && sLn.indexOf('=') > 1) {
        xmlAttrSecRe.lastIndex = 0;
        var xasm, matchedXmlAttrSec = false;
        while ((xasm = xmlAttrSecRe.exec(sLn)) !== null) {
          var xasBody = xasm[1] || '';
          if (/\bstoreAsClearText\s*=\s*["']?false["']?/i.test(xasBody) || /\bencrypted\s*=\s*["']?(?:true|1)["']?/i.test(xasBody)) continue;
          var xasKeyM = /\b(?:name|key|id)\s*=\s*(?:"([^"\r\n]{1,64})"|'([^'\r\n]{1,64})')/i.exec(xasBody);
          var xasValM = /\bvalue\s*=\s*(?:"([^"\r\n]{3,128})"|'([^'\r\n]{3,128})')/i.exec(xasBody);
          if (!xasKeyM || !xasValM) continue;
          var xasKey = (xasKeyM[1] || xasKeyM[2] || '').trim();
          if (!/^(?:(?!(?:no|by)pass)[A-Za-z0-9_.-]*(?:pass(?:word|wd)?|pwd)|pw|secret|cpassword|apikey|api_key|access_token|auth_token)$/i.test(xasKey)) continue;
          matchedXmlAttrSec = true;
          var xasVal = (xasValM[1] || xasValM[2] || '').trim();
          if (!/^AQAAANCMnd8BFdER/.test(xasVal) && !isPlaceholderSecret(xasVal, echoSet)) {
            pushUniq(kvSecrets, xasVal);
          }
        }
        if (matchedXmlAttrSec) continue;
      }
      _ATOM_KV_SECRET_RE.lastIndex = 0;
      var checkedNeg = false, isNeg = false;
      while ((m = _ATOM_KV_SECRET_RE.exec(sLn)) !== null) {
        if (/^(?:no|by)pass(?:word|wd)?\s*[:=]/i.test(m[0])) continue;
        if (!checkedNeg) { checkedNeg = true; isNeg = _lineHasNegPolarity(sLines, sli); }
        if (isNeg) break;
        var secVal = (m[1] || m[2] || m[3] || '').trim();
        if (!m[1] && !m[2] && secVal.charAt(secVal.length - 1) === ':') {
          var subUserAtom = secVal.slice(0, -1).trim();
          if (/^[A-Za-z0-9_.-]{2,32}$/.test(subUserAtom) && !isBoilerplateUser(subUserAtom) && sli + 1 < sLineCap) {
            var nxtSecLn = String(sLines[sli + 1] || '').trim();
            if (nxtSecLn && nxtSecLn.length >= 3 && nxtSecLn.length <= 128 && !/\s/.test(nxtSecLn)
                && nxtSecLn.charAt(nxtSecLn.length - 1) !== ':' && !_lineHasNegPolarity(sLines, sli + 1)
                && !isPlaceholderSecret(nxtSecLn, echoSet)) {
              multilineKvCreds.push({ user: subUserAtom, password: nxtSecLn });
            }
          }
          continue;
        }
        if (!m[1] && !m[2] && /^(?:\/(?:bin|sbin|usr|etc|var|opt|srv|home|root|tmp|dev|proc|sys|lib)\b|~\/|[A-Za-z]:\\)/i.test(secVal)) continue;
        if (/^\s*pwd?\s*[:=]/i.test(m[0]) && /^(?:\/|~\/|[A-Za-z]:\\)/.test(secVal)) continue;
        if (!isPlaceholderSecret(secVal, echoSet)) pushUniq(kvSecrets, secVal);
      }
    }

    if (s.indexOf(':\\') >= 0) {
      _ATOM_WIN_PATH_RE.lastIndex = 0;
      while ((m = _ATOM_WIN_PATH_RE.exec(s)) !== null) { if (winPaths.length >= MAX_ATOM_ITEMS) break; pushUniq(winPaths, m[0]); }
    }
    if (s.indexOf('\\\\') >= 0) {
      _ATOM_UNC_PATH_RE.lastIndex = 0;
      var lhostNorm = String(lhost || '').trim().toLowerCase();
      while ((m = _ATOM_UNC_PATH_RE.exec(s)) !== null) {
        if (uncPaths.length >= MAX_ATOM_ITEMS) break;
        var uIdx = m.index;
        if (uIdx >= 2 && /[A-Za-z]:$/.test(s.slice(uIdx - 2, uIdx))) continue;
        if (uIdx >= 1 && /[\\\/]/.test(s.charAt(uIdx - 1))) continue;
        if (uIdx > 0) {
          var preUnc = s.slice(Math.max(0, uIdx - 240), uIdx);
          if (/[?&#][A-Za-z0-9_.\-\[\]]+=['"]?$/.test(preUnc)
              || /https?:\/\/[^\s"']*?[?&#][A-Za-z0-9_.\-\[\]]+=[^\s"'&#]*$/i.test(preUnc)) continue;
        }
        var upParts = m[0].replace(/^\\\\/, '').split('\\');
        var uncHost = String(upParts[0] || '').trim();
        var uncHostLow = uncHost.toLowerCase();
        if (!uncHost || uncHost === '.' || uncHostLow === 'localhost' || uncHost === '127.0.0.1' || (upParts[1] && upParts[1].toLowerCase() === 'pipe')) continue;
        if (lhostNorm && uncHostLow === lhostNorm) continue;
        if (_isPrivateIpv4(uncHost, false) && target && uncHost !== target) {
          var uncSub = _subnet24(uncHost);
          if ((lhostSub && uncSub === lhostSub) || (_isPrivateIpv4(target, false) && uncSub !== targetSub)) continue;
        }
        pushUniq(uncPaths, m[0]);
      }
    }
    if (s.indexOf('/') >= 0) {
      _ATOM_POSIX_PATH_RE.lastIndex = 0;
      while ((m = _ATOM_POSIX_PATH_RE.exec(s)) !== null) { if (posixPaths.length >= MAX_ATOM_ITEMS) break; pushUniq(posixPaths, m[1]); }
    }
    _ATOM_PERM_MODE_RE.lastIndex = 0;
    while ((m = _ATOM_PERM_MODE_RE.exec(s)) !== null) { if (permModes.length >= MAX_ATOM_ITEMS) break; pushUniq(permModes, m[0]); }
    if (s.indexOf('Generic') >= 0 || s.indexOf('Write') >= 0 || s.indexOf('ForceChange') >= 0 || s.indexOf('Add') >= 0 || s.indexOf('AllExtended') >= 0 || s.indexOf('Read') >= 0) {
      _ATOM_ACL_VERB_RE.lastIndex = 0;
      while ((m = _ATOM_ACL_VERB_RE.exec(s)) !== null) { if (aclVerbs.length >= MAX_ATOM_ITEMS) break; pushUniq(aclVerbs, m[1]); }
    }
    if (s.indexOf('ESC') >= 0 || s.indexOf('ENROLLEE') >= 0 || s.indexOf('Certificate') >= 0 || s.indexOf('Any Purpose') >= 0) {
      _ATOM_ADCS_FLAG_RE.lastIndex = 0;
      while ((m = _ATOM_ADCS_FLAG_RE.exec(s)) !== null) { if (adcsFlags.length >= MAX_ATOM_ITEMS) break; pushUniq(adcsFlags, m[1]); }
    }
    if (s.indexOf('msDS-') >= 0 || s.indexOf('TRUSTED_') >= 0) {
      _ATOM_DELEG_RE.lastIndex = 0;
      while ((m = _ATOM_DELEG_RE.exec(s)) !== null) { if (delegAttrs.length >= MAX_ATOM_ITEMS) break; pushUniq(delegAttrs, m[1]); }
    }
    if (s.indexOf('Privilege') >= 0 || s.indexOf('privilege') >= 0) {
      _ATOM_WIN_PRIV_RE.lastIndex = 0;
      while ((m = _ATOM_WIN_PRIV_RE.exec(s)) !== null) { if (winPrivs.length >= MAX_ATOM_ITEMS) break; pushUniq(winPrivs, m[1]); }
    }

    var httpStatusM = _ATOM_HTTP_STATUS_RE.exec(s);
    var httpStatus = httpStatusM ? parseInt(httpStatusM[1] || httpStatusM[2] || httpStatusM[3] || httpStatusM[4], 10) : 0;

    return {
      ipv4s: ipv4s,
      newSubnetIps: newSubnetIps,
      cidrs: cidrs,
      ports: ports,
      uriPaths: uriPaths,
      httpStatus: httpStatus,
      domUsers: domUsers,
      upns: upns,
      posixId: posixId,
      sids: sids,
      dns: dns,
      spns: spns,
      modHashes: modHashes,
      ntHashes: ntHashes,
      jwts: jwts,
      kvSecrets: kvSecrets,
      multilineKvCreds: multilineKvCreds,
      hasRoutingOrIfaces: hasRoutingOrIfaces,
      winPaths: winPaths,
      uncPaths: uncPaths,
      posixPaths: posixPaths,
      permModes: permModes,
      aclVerbs: aclVerbs,
      adcsFlags: adcsFlags,
      delegAttrs: delegAttrs,
      winPrivs: winPrivs,
      hasPosPolarity: _ATOM_POS_POLARITY_RE.test(s),
      hasNegPolarity: _ATOM_NEG_POLARITY_RE.test(s)
    };
  }
  C._extract_atoms = _extract_atoms;

  // ---- Axis 1B: Catalog-Wide Move Matcher (Including Gated/Blocked Moves) ----------------------
  function _canonicalToolName(t) {
    var s = String(t || '').trim().split(/[\\\/]/).pop().toLowerCase().replace(/\.(?:py|exe|sh|pl|rb)$/i, '');
    if (/^(?:nxc|netexec|crackmapexec|cme)$/.test(s)) return 'nxc';
    if (s.indexOf('impacket-') === 0) return s.slice(9);
    if (s === 'certipy-ad') return 'certipy';
    if (s === 'enum4linux-ng') return 'enum4linux';
    if (s === 'bloodhound-python') return 'bloodhound';
    return s;
  }

  function _match_catalog_move(command, atoms, ws) {
    var packs = (OBOL.packs && typeof OBOL.packs.actions === 'function') ? OBOL.packs.actions() : [];
    if (!packs || !packs.length) return null;
    var cmdLow = _strip_cmd_wrappers(command).toLowerCase();
    if (!cmdLow) return null;

    var cmdForWords = cmdLow
      .replace(/\b[a-z]:\\[^\s"']*/gi, ' ')
      .replace(/(?:^|[\s"'=])\/(?:users|home|var|opt|tmp|etc|usr|windows|program)[^\s"']*/gi, ' ');
    var hasExploitOrAuthOp = /\b(?:select|union|sleep|waitfor|information_schema)\b|(?:authorization|cookie)\s*:|bearer\s+/i.test(cmdLow);

    var cmdTool = _canonicalToolName(cmdLow.split(/\s+/)[0]);
    var isHttpTool = cmdTool === 'curl' || cmdTool === 'wget' || cmdTool === 'httpie';
    var hasXmlEvidence = /<!doctype|<!entity|<\?xml|application\/xml|text\/xml|\.xml\b|xmlns[:=]/i.test(String(command || ''));
    var hasGraphqlEvidence = /\/graphql\b|"query"\s*:|\b__schema\b|\b__type\b|\bIntrospectionQuery\b/i.test(String(command || ''));
    var bestMove = null, bestScore = 0;

    for (var i = 0; i < packs.length; i++) {
      var m = packs[i];
      if (!m || !m.commands) continue;
      if (isHttpTool && m.id && /xxe/i.test(m.id) && !hasXmlEvidence) continue;
      var score = 0;
      if (m.id && cmdLow.indexOf(m.id.toLowerCase()) >= 0) score += 8;
      if (hasGraphqlEvidence && m.id && /graphql/i.test(m.id)) score += 8;

      for (var c = 0; c < m.commands.length; c++) {
        var cmdObj = m.commands[c];
        if (!cmdObj) continue;
        var mToolRaw = m.tool || '';
        var meta = cmdObj._infMeta;
        if (!meta || meta.mTool !== mToolRaw) {
          var rawRun = _strip_cmd_wrappers(String(cmdObj.run || '')).toLowerCase();
          var rawFlags = rawRun ? (rawRun.replace(/\{\{[^}]+\}\}/g, '').match(/(?:--?[a-zA-Z0-9_-]+|\b(?:smb|ldap|winrm|mssql|ssh|ftp|rdp|find|auth|req|shadow|account|get|set|add|dump|enum|shares|users|groups|pass-pol|laps|gmsa|bloodhound|spider_plus)\b)/g) || []) : [];
          var uniqFlags = [], seenMetaFl = Object.create(null);
          for (var mf = 0; mf < rawFlags.length; mf++) {
            var mfl = rawFlags[mf];
            if (mfl.length < 2 || /^-(?:u|p|d|h|i|t|o|v)$/i.test(mfl) || seenMetaFl[mfl]) continue;
            seenMetaFl[mfl] = 1;
            var mIsFlag = mfl.charAt(0) === '-';
            uniqFlags.push({
              fl: mfl,
              isFlag: mIsFlag,
              isHttpShortNoise: /^-(?:x|s|k|l|b|c)$/i.test(mfl),
              isCommonWord: !mIsFlag && /^(?:users|admin|login|index)$/i.test(mfl),
              wordRe: mIsFlag ? null : new RegExp('(?:^|[^a-z0-9_\\\\/])' + mfl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?:$|[^a-z0-9_\\\\/])', 'i')
            });
          }
          meta = {
            mTool: mToolRaw,
            cRun: rawRun,
            cTool: _canonicalToolName(cmdObj.tool || mToolRaw || (rawRun ? rawRun.split(/\s+/)[0] : '')),
            cRunTool: rawRun ? _canonicalToolName(rawRun.split(/\s+/)[0]) : '',
            flags: uniqFlags
          };
          try { Object.defineProperty(cmdObj, '_infMeta', { value: meta, enumerable: false, configurable: true }); } catch (_e) {}
        }
        var cRun = meta.cRun;
        if (!cRun) continue;

        if (cmdTool && (meta.cTool === cmdTool || meta.cRunTool === cmdTool || cRun.indexOf(cmdTool) === 0)) {
          score = Math.max(score, 3);
          var tmplFlags = meta.flags;
          var flagHits = 0, flagMisses = 0;
          for (var f = 0; f < tmplFlags.length; f++) {
            var fObj = tmplFlags[f];
            if (isHttpTool && fObj.isHttpShortNoise) continue;
            if (fObj.isCommonWord && !hasExploitOrAuthOp) continue;
            var fl = fObj.fl;
            var hit = fObj.isFlag ? (cmdLow.indexOf(fl) >= 0) : fObj.wordRe.test(cmdForWords);
            if (hit) {
              flagHits += (fl.length > 4 ? 3 : ((isHttpTool && fl === '-f') ? 2 : 1));
            } else if (fl.length > 4 && fObj.isFlag) {
              flagMisses += 2;
            }
          }
          var candScore = 3 + flagHits - flagMisses;
          if (candScore > score) score = candScore;
        }
      }
      if (score > bestScore && score >= 5) {
        bestScore = score;
        bestMove = m;
      }
    }
    return bestMove ? { id: bestMove.id, title: bestMove.title, produces: (bestMove.produces || []).slice(), phase: bestMove.phase || '', score: bestScore } : null;
  }
  C._match_catalog_move = _match_catalog_move;

  // ---- Axis 5: Global Engagement Entity Indexer ------------------------------------------------
  function _isUserBoundaryChar(ch) {
    if (!ch) return true;
    var c = ch.charCodeAt(0);
    return !((c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 95 || c === 46 || c === 45);
  }
  function _hasUserTokenCI(lnLow, uKey) {
    var pos = 0;
    while ((pos = lnLow.indexOf(uKey, pos)) >= 0) {
      var before = pos > 0 ? lnLow.charAt(pos - 1) : '';
      var after = (pos + uKey.length < lnLow.length) ? lnLow.charAt(pos + uKey.length) : '';
      if (_isUserBoundaryChar(before) && _isUserBoundaryChar(after)) return true;
      pos += uKey.length;
    }
    return false;
  }

  function _build_global_entity_index(ws) {
    var target = (ws && ws.target) || '';
    var targetScope = target ? ('host:' + target) : '';
    var allFacts = (ws && (ws.facts || ws.seedFacts)) || [];
    if ((!allFacts || !allFacts.length) && OBOL.store) {
      try {
        if (target && typeof OBOL.store.factSetForTarget === 'function') {
          var tf = OBOL.store.factSetForTarget(target);
          if (tf && tf.facts) allFacts = tf.facts;
        } else if (typeof OBOL.store.factSet === 'function') {
          var fs = OBOL.store.factSet();
          if (fs && fs.facts) allFacts = fs.facts;
        }
      } catch (_e) {}
    }
    var users = Object.create(null);
    var domains = Object.create(null);
    var shares = Object.create(null);
    var hasFoothold = false, osFamily = '', isDc = false, hostDomain = '', hasAdOrWinCtx = false;

    for (var p = 0; p < allFacts.length; p++) {
      var pf = allFacts[p];
      if (!pf || pf.state !== 'supported') continue;
      if (pf.scope === targetScope || !targetScope) {
        var pv = pf.value || {};
        if (pf.kind === 'foothold.linux' || pf.kind === 'access.root') { hasFoothold = true; osFamily = 'linux'; }
        if (pf.kind === 'foothold.windows' || pf.kind === 'access.system' || (pf.kind === 'access.admin' && osFamily !== 'linux')) { hasFoothold = true; osFamily = 'windows'; hasAdOrWinCtx = true; }
        if (pf.kind === 'host.os_family' && pv.family) {
          osFamily = String(pv.family).toLowerCase();
          if (osFamily === 'windows') hasAdOrWinCtx = true;
        }
        if (pf.kind === 'ad.dc_candidate') { isDc = true; hasAdOrWinCtx = true; }
        if (pf.kind === 'host.domain' && pv.domain) hostDomain = String(pv.domain).toLowerCase();
      }
    }

    for (var i = 0; i < allFacts.length; i++) {
      var f = allFacts[i];
      if (!f || f.state !== 'supported') continue;
      if (targetScope && f.scope && f.scope.indexOf('host:') === 0 && f.scope !== targetScope) continue;
      if (osFamily === 'linux' && !hostDomain && f.scope && f.scope.indexOf('domain:') === 0) continue;
      var v = f.value || {};
      if (osFamily !== 'linux' && /^(?:ad\.user_list|ad\.domain_known|smb\.authenticated|winrm\.authenticated|hash\.(?:ntlm|tgs|asrep|mscache|krbtgt)|credential\.ntlm_hash)$/.test(f.kind || '')) {
        hasAdOrWinCtx = true;
      }
      if ((f.kind === 'ad.user_list' || f.kind === 'host.users') && Array.isArray(v.users)) {
        var cachedUsers = v.users._infCleanCache;
        if (!cachedUsers || cachedUsers.len !== v.users.length) {
          var pairs = [];
          for (var ui = 0; ui < v.users.length; ui++) {
            var entryU = v.users[ui];
            var rawU = String((typeof entryU === 'string' ? entryU : (entryU && (entryU.user || entryU.username))) || '').trim();
            if (!rawU) continue;
            var clean = (rawU.indexOf('\\') >= 0 || rawU.indexOf('/') >= 0) ? rawU.replace(/^.*[\\\/]/, '') : rawU;
            if (clean.indexOf('@') >= 0) clean = clean.slice(0, clean.indexOf('@'));
            if (clean && !isBoilerplateUser(clean)) pairs.push(clean.toLowerCase(), clean);
          }
          cachedUsers = { len: v.users.length, pairs: pairs };
          try { Object.defineProperty(v.users, '_infCleanCache', { value: cachedUsers, enumerable: false, configurable: true }); } catch (_e) {}
        }
        var uPairs = cachedUsers.pairs;
        for (var upi = 0; upi < uPairs.length; upi += 2) {
          users[uPairs[upi]] = uPairs[upi + 1];
        }
      }
      if (/^credential\.|^hash\./.test(f.kind)) {
        var cu = v.user || v.username || '';
        if (cu && !isBoilerplateUser(cu)) {
          var cl = String(cu).trim().replace(/^.*[\\\/]/, '').replace(/@.*$/, '');
          if (cl) users[cl.toLowerCase()] = cl;
        }
      }
      if (v.domain && String(v.domain).indexOf('.') >= 0 && osFamily !== 'linux') {
        domains[String(v.domain).toLowerCase()] = String(v.domain);
      }
      if (f.kind === 'smb.shares' && Array.isArray(v.shares)) {
        v.shares.forEach(function (sh) {
          var name = typeof sh === 'string' ? sh : (sh && sh.name);
          if (name) shares[String(name).toLowerCase()] = name;
        });
      }
    }
    if (osFamily === 'linux') hasAdOrWinCtx = false;
    return {
      users: users,
      userKeys: Object.keys(users),
      domains: domains,
      shares: shares,
      hasFoothold: hasFoothold,
      osFamily: osFamily,
      isDc: isDc,
      hasAdOrWinCtx: hasAdOrWinCtx
    };
  }

  // ---- Tier 3: Main Wittgensteinian Contextual Inference Pass ----------------------------------
  function _parse_inference(text, ws, command, source, facts, actionId, opts) {
    if (/^\s*(?:sudo\s+)?msfvenom\b/i.test(command || '')) return;
    text = String(text || '');
    if (C._normalize_cr && text.indexOf('\r') >= 0) text = C._normalize_cr(text);
    if (C._strip_tmux_split && (text.indexOf('\u2502') >= 0 || text.indexOf('\u2503') >= 0)) text = C._strip_tmux_split(text);
    if (C._unwrap_kerberos_hashes && (text.indexOf('$krb5') >= 0 || text.indexOf('$KRB5') >= 0)) text = C._unwrap_kerberos_hashes(text);
    if (text.length > 10485760) text = text.slice(0, 10485760);
    var hasCtxPromptTelemetry = !!(ws && ws.context && (ws.context.followPrompt || ws.context.promptLine));
    if (!text.trim() && !hasCtxPromptTelemetry) return;
    if (_isHelpOrUsageOutput(text, command)) {
      for (var hi = facts.length - 1; hi >= 0; hi--) {
        if (facts[hi] && /^(?:credential\.|hash\.|ad\.)/.test(facts[hi].kind || '')) facts.splice(hi, 1);
      }
      return;
    }
    ws = ws || { target: 'target' };
    var h = 'host:' + ws.target;
    var rawDomScope = C._scope_for_domain ? C._scope_for_domain(ws) : h;
    var domScope = (rawDomScope && rawDomScope !== 'domain:domain' && rawDomScope !== 'domain:') ? rawDomScope : h;

    // 1. Extract Prompt Telemetry, Command Semantics, Wrapper Delta, and Global Entity Index
    var promptMeta = _extract_prompt_telemetry(text, ws, command);
    var cmdSem = _extract_command_semantics(command, ws);
    var delta = _compute_wrapper_delta(text, ws, command);
    var fullLines = text.split(/\r?\n/);
    var analysisText = (delta && delta.deltaText) ? delta.deltaText : text;
    var lines = analysisText === text ? fullLines : analysisText.split(/\r?\n/);
    var atoms = _extract_atoms(analysisText, ws, cmdSem, lines);
    var globalIdx = _build_global_entity_index(ws);

    // Resolve Active Move Intent (Attention Frame -> Explicit ActionId -> Catalog-Wide Move Match)
    var ctx = ws.context || {};
    var frame = ctx.attentionFrame || {};
    var matchedCopy = frame.matchedCopy || (opts && opts._inferenceContext && opts._inferenceContext.attention) || null;
    var catalogMove = frame.matchedCatalogMove || ((!actionId && !(matchedCopy && matchedCopy.actionId)) ? _match_catalog_move(command, atoms, ws) : null);
    var expectedProduces = [];
    if (matchedCopy && Array.isArray(matchedCopy.produces)) expectedProduces = expectedProduces.concat(matchedCopy.produces);
    if (catalogMove && Array.isArray(catalogMove.produces)) expectedProduces = expectedProduces.concat(catalogMove.produces);
    if (actionId && OBOL.packs && typeof OBOL.packs.actions === 'function') {
      var actObj = OBOL.packs.actions().find(function (a) { return a && a.id === actionId; });
      if (actObj && Array.isArray(actObj.produces)) expectedProduces = expectedProduces.concat(actObj.produces);
    }
    function expects(kindOrPrefix) {
      return expectedProduces.some(function (p) { return p === kindOrPrefix || p.indexOf(kindOrPrefix) === 0; });
    }

    // Distinguish substantive Tier 1 payload facts from incidental reachability/header/OS/hint facts
    // so an HTTP header (`http.reachable`), `LDAP` keyword (`ldap.reachable`), single `loot.shadow`,
    // or hint-only `credential.candidate` (no user/password/hash) never blocks Tier 3 from extracting
    // custom tables, KV blocks, or hashes in the body.
    var hasSubstantiveTier1Fact = facts.some(function (f) {
      if (!f || !f.kind || (f.value && (f.value.via === 'shape' || f.value.via === 'vulnmatch'))) return false;
      if (/^(?:http|ldap|smb|db|ssh|ftp|winrm|kerberos|rdp|rpc|mssql|mysql)\.reachable$/.test(f.kind)) return false;
      if (/^(?:web\.(?:server|source_disclosed)|host\.os_hint|host\.os_family|host\.up|vuln\.|loot\.shadow$|blocker\.|credential\.(?:validation|authorization)$)/.test(f.kind)) return false;
      if (f.kind === 'credential.candidate' && (!f.value || (!f.value.user && !f.value.password && !f.value.nthash && !f.value.hash))) return false;
      return true;
    });

    var isRemoteScanner = /\b(?:nmap|masscan|rustscan|snmpwalk|snmpbulkwalk|snmp-check|onesixtyone|ffuf|gobuster|feroxbuster|wfuzz|dirb|dirsearch|nikto|whatweb|httpx|nuclei)\b/i.test(command || '');
    var isWebClient = /\b(?:curl|wget|httpie|sqlmap)\b/i.test(command || '') || /^HTTP\/[12]\./im.test(text);
    var isSshCmd = !!(C._is_ssh_command && C._is_ssh_command(command));

    // 2. Shell Prompt Telemetry Inference (Local Target Shell vs Subshells)
    function _tagPromptFact(fact, fromCtx) {
      if (!fact) return fact;
      fact.origin = fromCtx ? 'prompt_telemetry' : 'stdout_telemetry';
      if (fromCtx && fact.value && typeof fact.value === 'object') fact.value.prompt_only = true;
      return fact;
    }
    var isRawHttpDumpWithoutTargetShell = isWebClient && !promptMeta.fromContextPrompt && /^HTTP\/[12]\./im.test(text) && !promptMeta.host;
    var isPromptOnlyStructuredLinux = !promptMeta.hasCommand && !String(command || '').trim() && !text.trim()
      && promptMeta.osFamily === 'linux' && Boolean(promptMeta.user && promptMeta.host);
    if (promptMeta.locus === 'local' && (promptMeta.hasCommand || isPromptOnlyStructuredLinux) && !isRemoteScanner && !isRawHttpDumpWithoutTargetShell && !isSshCmd) {
      if (promptMeta.osFamily === 'linux') {
        if (!hasKind(facts, 'foothold.linux') && !globalIdx.hasFoothold) {
          var fVal = { method: cmdSem.tool || 'shell', via: 'prompt-telemetry' };
          if (promptMeta.user) fVal.identity = promptMeta.user;
          _add(facts, _tagPromptFact(mkFact('foothold.linux', h, fVal, S, source), promptMeta.fromContextPrompt));
          if (C._add_os_observation) C._add_os_observation(facts, ws, source, 'linux', promptMeta.promptLine, 'high', 'prompt', true);
        }
        if (promptMeta.isPrivileged) {
          if (!hasKind(facts, 'access.root')) {
            _add(facts, _tagPromptFact(mkFact('access.root', h, { identity: 'root', method: cmdSem.tool || 'shell', via: 'prompt-telemetry' }, S, source), promptMeta.fromContextPrompt));
          }
          if (!hasKind(facts, 'access.admin')) {
            _add(facts, _tagPromptFact(mkFact('access.admin', h, { identity: 'root', method: cmdSem.tool || 'shell', via: 'prompt-telemetry' }, S, source), promptMeta.fromContextPrompt));
          }
        }
      } else if (promptMeta.osFamily === 'windows'
          && !_is_dos_emulator_ctx(command, text, promptMeta.promptLine)
          && !(globalIdx.osFamily === 'linux' && !/^(?:\*?Evil-WinRM\*?\s+)?PS\s+/i.test(promptMeta.promptLine || '') && !/Microsoft Windows|Volume Serial Number|C:\\Windows|NT AUTHORITY\\/i.test(text))) {
        if (!hasKind(facts, 'foothold.windows') && !globalIdx.hasFoothold) {
          var wVal = { method: cmdSem.tool || 'shell', via: 'prompt-telemetry' };
          if (promptMeta.user) wVal.identity = promptMeta.user;
          _add(facts, _tagPromptFact(mkFact('foothold.windows', h, wVal, S, source), promptMeta.fromContextPrompt));
          if (C._add_os_observation) C._add_os_observation(facts, ws, source, 'windows', promptMeta.promptLine, 'high', 'prompt', true);
        }
        if (promptMeta.isPrivileged && !hasKind(facts, 'access.admin')) {
          _add(facts, _tagPromptFact(mkFact('access.admin', h, { identity: promptMeta.user || 'Administrator', method: cmdSem.tool || 'shell', via: 'prompt-telemetry' }, S, source), promptMeta.fromContextPrompt));
        }
      }
    } else if (isSshCmd && promptMeta.locus === 'local' && promptMeta.osFamily === 'linux' && !promptMeta.fromContextPrompt
        && !/\b(?:Permission denied|Authentication failed|Connection refused|Connection timed out|Connection closed by|Host key verification failed|No route to host|Could not resolve hostname)\b/i.test(text)) {
      if (!hasKind(facts, 'ssh.authenticated')) {
        var sshFpAuth = { service: 'ssh', via: 'prompt-telemetry' };
        if (promptMeta.user) sshFpAuth.user = promptMeta.user;
        _add(facts, _tagPromptFact(mkFact('ssh.authenticated', h, sshFpAuth, S, source), false));
      }
      if (!hasKind(facts, 'foothold.linux') && !globalIdx.hasFoothold) {
        var sshFpFh = { method: 'ssh', via: 'prompt-telemetry' };
        if (promptMeta.user) sshFpFh.identity = promptMeta.user;
        _add(facts, _tagPromptFact(mkFact('foothold.linux', h, sshFpFh, S, source), false));
        if (C._add_os_observation) C._add_os_observation(facts, ws, source, 'linux', promptMeta.promptLine, 'high', 'ssh', true);
      }
      if (promptMeta.isPrivileged) {
        if (!hasKind(facts, 'access.root')) {
          _add(facts, _tagPromptFact(mkFact('access.root', h, { identity: 'root', method: 'ssh', via: 'prompt-telemetry' }, S, source), false));
        }
        if (!hasKind(facts, 'access.admin')) {
          _add(facts, _tagPromptFact(mkFact('access.admin', h, { identity: 'root', method: 'ssh', via: 'prompt-telemetry' }, S, source), false));
        }
      }
    }

    // Machine-account `%USERNAME%` (`<HOSTNAME>$`) in local Windows shell -> NT AUTHORITY\SYSTEM
    if (!isRemoteScanner && !isWebClient && !hasKind(facts, 'access.system') && /\becho\s+%username%/i.test((command || '') + '\n' + text)) {
      var mMachEnv = /^[ \t]*([A-Za-z][A-Za-z0-9_-]{1,14}\$)[ \t]*$/m.exec(text);
      if (mMachEnv) {
        var sysFact = mkFact('access.system', h, { identity: mMachEnv[1], method: 'machine-account-env', via: 'context-inference' }, S, source);
        sysFact.origin = 'stdout_telemetry';
        _add(facts, sysFact);
        if (!hasKind(facts, 'access.admin')) {
          var admSysFact = mkFact('access.admin', h, { identity: mMachEnv[1], method: 'machine-account-env', via: 'context-inference' }, S, source);
          admSysFact.origin = 'stdout_telemetry';
          _add(facts, admSysFact);
        }
        if (!hasKind(facts, 'foothold.windows') && !globalIdx.hasFoothold) {
          var fwFact = mkFact('foothold.windows', h, { identity: mMachEnv[1], method: 'machine-account-env', via: 'context-inference' }, S, source);
          fwFact.origin = 'stdout_telemetry';
          _add(facts, fwFact);
        }
      }
    }

    // Subshell prompt reachability & auth inference
    if (promptMeta.subshell === 'smb' && !hasKind(facts, 'smb.shares')) {
      _add(facts, _tagPromptFact(mkFact('smb.reachable', h, { via: 'prompt-telemetry' }, S, source), promptMeta.fromContextPrompt));
    } else if ((promptMeta.subshell === 'mysql' || promptMeta.subshell === 'psql' || promptMeta.subshell === 'mssql') && !hasKind(facts, 'db.reachable')) {
      _add(facts, _tagPromptFact(mkFact('db.reachable', h, { engine: promptMeta.subshell, via: 'prompt-telemetry' }, S, source), promptMeta.fromContextPrompt));
    }
    if (!text.trim()) return;
    if (C._is_public_reference_http_cmd && C._is_public_reference_http_cmd(command, ws)) return;

    // 2B. SPN FQDN & Domain Extraction (`SPN(n) = <Service>/<host>.<domain>` / `setspn` / `atoms.spns`)
    var isKnownLinuxCtx = globalIdx.osFamily === 'linux' || facts.some(function (f) {
      return f && (f.kind === 'foothold.linux' || f.kind === 'access.root'
        || (f.kind === 'host.os_family' && f.value && String(f.value.family || '').toLowerCase() === 'linux'));
    });
    var hasExplicitSpnAnchor = /\b(?:SPN\(\d+\)\s*=|servicePrincipalName|setspn|\$krb5tgs\$|GetUserSPNs)\b/i.test(analysisText + '\n' + (command || ''));
    if (!isKnownLinuxCtx && (atoms.spns.length > 0 || /^\s*SPN\(\d+\)\s*=/im.test(analysisText))
        && (!isWebClient || hasExplicitSpnAnchor)
        && (hasExplicitSpnAnchor || !(C._is_attacker_local_turn && C._is_attacker_local_turn(ws, command, text)))) {
      var spnCands = atoms.spns.slice();
      var spnLineRe = /^\s*SPN\(\d+\)\s*=\s*([A-Za-z][A-Za-z0-9_.-]*\/[^\s"']+)/gim, spnLm;
      while ((spnLm = spnLineRe.exec(analysisText)) !== null) {
        if (spnCands.indexOf(spnLm[1]) < 0) spnCands.push(spnLm[1]);
      }
      var knownAdSpnSvcRe = /^(?:mssqlsvc|https?|cifs|ldaps?|host|wsmans?|wsmansvc|rpcss|termsrv|restrictedkrbhost|dns|kadmin|nfs|smtp|imap|pop3?|gc|exchange\w*|vnc|ipp|netlogon|dfsr-[a-z0-9-]+)$/i;
      var spnFileExtRe = /\.(?:php|html?|js|css|json|xml|txt|png|jpe?g|gif|svg|ico|exe|dll|ps1|bat|cmd|vbs|sh|py|rb|pl|jar|war|zip|tar|gz|7z|rar|log|bak|old|conf|cfg|ini|yml|yaml|sql|db|sqlite3?|mdb)$/i;
      var publicSpnDomainRe = /(?:^|\.)(?:cloudfront\.net|amazonaws\.com|azurewebsites\.net|akamai[a-z0-9-]*\.net|fastly\.net|cloudflare\.com|jsdelivr\.net|unpkg\.com|googleapis\.com|gstatic\.com|bootstrapcdn\.com|jquery\.com|fontawesome\.com|github\.io|githubusercontent\.com|microsoft\.com|windows\.net|office\.com|live\.com|msecnd\.net|w3\.org|schema\.org|mozilla\.org|wordpress\.org|wordpress\.com|gravatar\.com|wp\.com|digicert\.com|verisign\.com|letsencrypt\.org)$/i;
      for (var spi = 0; spi < spnCands.length; spi++) {
        var spnRaw = String(spnCands[spi] || '').trim();
        var spnSlash = spnRaw.indexOf('/');
        if (spnSlash <= 0) continue;
        var spnSvc = spnRaw.slice(0, spnSlash).toLowerCase();
        if (spnSvc === 'krbtgt') continue;
        if (!hasExplicitSpnAnchor && !knownAdSpnSvcRe.test(spnSvc)) continue;
        var spnHostPart = spnRaw.slice(spnSlash + 1).split('/')[0].split(':')[0].replace(/\.$/, '').trim();
        if (spnFileExtRe.test(spnHostPart)) continue;
        if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){2,}$/.test(spnHostPart)) continue;
        if (!/\.[A-Za-z]{2,24}$/.test(spnHostPart)) continue;
        var spnFqdn = spnHostPart.toLowerCase();
        var spnDomain = spnFqdn.slice(spnFqdn.indexOf('.') + 1);
        if (_PUBLIC_EMAIL_DOMAINS.test(spnDomain) || publicSpnDomainRe.test(spnDomain)) continue;
        if (!hasKind(facts, 'host.fqdn')) {
          _add(facts, mkFact('host.fqdn', h, { fqdn: spnFqdn, via: 'spn' }, S, source));
        }
        if (!hasKind(facts, 'host.domain')) {
          _add(facts, mkFact('host.domain', h, { domain: spnDomain, via: 'spn' }, S, source));
        }
        var spnDomScope = 'domain:' + spnDomain;
        if (!facts.some(function (f) { return f && f.kind === 'ad.domain_known' && f.scope === spnDomScope; })) {
          _add(facts, mkFact('ad.domain_known', spnDomScope, { domain: spnDomain, name: spnDomain, via: 'spn' }, S, source));
        }
        if (domScope === h) domScope = spnDomScope;
        break;
      }
    }

    var hasEngagementCtx = !!(opts && (opts.entail || (opts.context && (opts.context.target || opts.context.attentionFrame || opts.context.selectionSource))));
    var hasTier1CredOrHash = facts.some(function (f) {
      if (!f || !f.kind) return false;
      if (/^(?:credential\.(?:available|plaintext|ntlm_hash)|hash\.(?:ntlm|tgs|asrep|mscache2|crackable)|db\.creds)$/.test(f.kind)) return true;
      if (f.kind === 'credential.candidate' && f.value && f.value.user && (f.value.password || f.value.nthash || f.value.hash)) return true;
      return false;
    });
    var isDedicatedTier1CredTool = /\b(?:mimikatz|sekurlsa|lsadump|pypykatz|secretsdump|samdump2|hashdump|gmsadumper|lsassy|nanodump|nxc|netexec|crackmapexec|cme|ldapsearch|bloodhound|sharphound|certipy|linpeas|winpeas|privesccheck|powerview|get-netuser|get-domainuser|sqlmap)\b/i.test(command || '')
      || /^(?:linpeas|winpeas|linux-enum|windows-enum|dcsync|sam-dump|lsass-dump|ntds-dump|sqlmap)/.test(actionId || '')
      || /^\s*(?:sudo\s+(?:-[A-Za-z]*l\b|--list\b)|doas\b)/i.test(command || '')
      || hasKind(facts, 'privesc.sudo_rights');
    function _hasExtractedSecretFor(uCand, sCand) {
      var uLow = String(uCand || '').trim().toLowerCase();
      var sClean = String(sCand || '').trim();
      var sLow = sClean.toLowerCase();
      return facts.some(function (f) {
        if (!f || !f.value) return false;
        var fv = f.value;
        var fu = String(fv.user || '').trim().toLowerCase();
        var fp = String(fv.password || fv.nthash || fv.hash || '').trim();
        if (sClean && fp && (fp === sClean || fp.toLowerCase() === sLow)) return true;
        if (sClean && Array.isArray(fv.values) && fv.values.indexOf(sClean) >= 0) return true;
        if (uLow && fu && fu === uLow && (fp || (Array.isArray(fv.values) && fv.values.length > 0))) return true;
        return false;
      });
    }
    var hasUnmetContract = expectedProduces.length > 0 && !expectedProduces.some(function (pk) {
      if (hasKind(facts, pk)) return true;
      if ((pk === 'web.rce' || pk === 'foothold.linux') && hasKind(facts, 'web.cmdi_confirmed')) return true;
      return false;
    });
    var hasPositionalMd5Tuple = (analysisText.indexOf("',") >= 0 || analysisText.indexOf('",') >= 0 || analysisText.indexOf("' ,") >= 0 || analysisText.indexOf('" ,') >= 0)
      && /(?:array\s*\(|[\[(])\s*['"][A-Za-z0-9_.\-$]{2,48}['"]\s*,\s*['"][0-9a-fA-F]{32}['"]/i.test(analysisText);
    var turnIsDbOrMd5OrWebCtx = isKnownLinuxCtx || isWebClient
      || promptMeta.subshell === 'mysql' || promptMeta.subshell === 'psql'
      || cmdSem.fileSchemaHint === 'database_dump'
      || hasKind(facts, 'db.hashes') || hasKind(facts, 'db.creds')
      || /\b(?:SELECT\s+[\s\S]{1,160}?\bFROM\b|INSERT\s+INTO\b|mysql|mariadb|postgres|psql|sqlite3?|phpmyadmin|wp_users|md5sum|\bmd5\s*\()/i.test((command || '') + '\n' + analysisText)
      || facts.some(function (f) {
        return f && ((f.kind === 'credential.candidate' && f.value && f.value.kind === 'database_hash')
          || (f.kind === 'hash.crackable' && f.value && /md5/i.test(String(f.value.format || f.value.hash_type || ''))));
      });
    var turnHasWinOrNtlmCtx = !isKnownLinuxCtx && (globalIdx.hasAdOrWinCtx || globalIdx.osFamily === 'windows' || globalIdx.isDc
      || promptMeta.osFamily === 'windows' || atoms.sids.length > 0 || atoms.domUsers.length > 0
      || /\b(?:ntlm|nthash|sam|ntds|lsass|mimikatz|secretsdump|rc4_hmac|aad3b435b51404eeaad3b435b51404ee)\b/i.test((command || '') + '\n' + analysisText));
    var allowBare32HexNtlm = Boolean(turnHasWinOrNtlmCtx && !turnIsDbOrMd5OrWebCtx);

    // Multiline `Password: <user>:\n<secret>` bindings and PoC password-reset announcements
    if (atoms.multilineKvCreds && atoms.multilineKvCreds.length > 0 && !(hasTier1CredOrHash && isDedicatedTier1CredTool)) {
      for (var mki = 0; mki < atoms.multilineKvCreds.length; mki++) {
        var mkPair = atoms.multilineKvCreds[mki];
        if (!_hasExtractedSecretFor(mkPair.user, mkPair.password)) {
          _emit_credential_facts(facts, h, { user: mkPair.user, password: mkPair.password, via: 'multiline-kv-secret' }, source, allowBare32HexNtlm);
        }
      }
    }
    if (analysisText.length >= 20 && /password/i.test(analysisText)) {
      var pocResetRe = /\b(?:new|reset|temporary|generated|created)\s+password\s+for\s+(?:the\s+)?(?:user\s+)?['"]?([A-Za-z0-9_.@-]{2,32})['"]?(?:\s+user)?\s+(?:is|=|:)\s*(?:"([^"\r\n]{4,64})"|'([^'\r\n]{4,64})'|([^\s'"\r\n]{4,64}))/gi;
      var prM;
      while ((prM = pocResetRe.exec(analysisText)) !== null) {
        var prUser = String(prM[1] || '').trim();
        var prPw = String(prM[2] || prM[3] || prM[4] || '').trim();
        if (!prM[2] && !prM[3]) prPw = prPw.replace(/[.,;]+$/, '');
        if (!prUser || !prPw || prPw.length < 4 || isBoilerplateUser(prUser) || isPlaceholderSecret(prPw, cmdSem.echoSet)) continue;
        if (!_hasExtractedSecretFor(prUser, prPw)) {
          _emit_credential_facts(facts, h, { user: prUser, password: prPw, via: 'poc-password-reset' }, source, allowBare32HexNtlm);
        }
      }
    }

    var hasUnhandledMultiSectionCredOrTable = !isDedicatedTier1CredTool
      && (atoms.kvSecrets.length > 0 || atoms.modHashes.length > 0 || atoms.ntHashes.length > 0
        || (atoms.multilineKvCreds && atoms.multilineKvCreds.length > 0)
        || hasPositionalMd5Tuple
        || /^\s*[+|│┃║][^\r\n]+[+|│┃║]\s*$/m.test(analysisText));
    if (hasSubstantiveTier1Fact && !hasEngagementCtx && !delta && !hasUnmetContract && !hasUnhandledMultiSectionCredOrTable) return;

    // 3. 2D Structural Geometry: Dynamic Tables (always parsed on fullLines so wrapper-delta never strips table headers) & Key-Value Blocks
    var isAdTableCtx = expects('ad.user_list') || expects('ad.computer_list') || /\bget-(?:net|ad|domain)(?:user|groupmember|computer|member)\b/i.test(command || '');
    var tables = _parse_dynamic_tables(fullLines, { adTableCtx: isAdTableCtx });
    var kvBlocks = _group_kv_blocks(lines, analysisText, command);

    // 3A. Dynamic Table Inference (Survives column reordering & format changes)
    for (var ti = 0; ti < tables.length; ti++) {
      var tbl = tables[ti];
      var roles = tbl.roles;
      var hasUserCol = roles.indexOf('user') >= 0;
      var hasComputerCol = roles.indexOf('computer') >= 0;
      var hasSecretCol = roles.indexOf('secret') >= 0;
      var hasShareCol = roles.indexOf('share') >= 0;
      var hasPermCol = roles.indexOf('perm') >= 0;
      var hasPortCol = roles.indexOf('port') >= 0;
      var hasStateCol = roles.indexOf('state') >= 0;
      var hasPathCol = roles.indexOf('path') >= 0;
      var hasSpnCol = roles.indexOf('spn') >= 0;
      var hasRightCol = roles.indexOf('right') >= 0;

      // (i) User + Secret table (Database dump, credential table, password manager export, custom dump tool)
      if (hasUserCol && hasSecretCol && !(hasTier1CredOrHash && isDedicatedTier1CredTool)) {
        var dbCtx = promptMeta.subshell === 'mysql' || promptMeta.subshell === 'psql' || promptMeta.subshell === 'mssql'
          || cmdSem.fileSchemaHint === 'database_dump' || expects('db.');
        for (var r1 = 0; r1 < tbl.rows.length; r1++) {
          var row1 = tbl.rows[r1];
          var u1 = String(row1.user || '').trim().replace(/^['"]|['"]$/g, '');
          var s1 = String(row1.secret || '').trim().replace(/^['"]|['"]$/g, '');
          if (!u1 || !s1 || isBoilerplateUser(u1) || isPlaceholderSecret(s1, cmdSem.echoSet)) continue;
          if (_hasExtractedSecretFor(u1, s1)) continue;
          var isHash1 = /^(?:\$[0-9a-zA-Z_-]+\$|[0-9a-fA-F]{32,128}$|pbkdf2_sha)/i.test(s1);
          var credVal = { user: u1, via: 'context-table' };
          if (isHash1) credVal.hash = s1;
          else credVal.password = s1;
          if (row1.domain) credVal.domain = row1.domain;
          _emit_credential_facts(facts, h, credVal, source, allowBare32HexNtlm && !dbCtx);
          if (dbCtx && !isHash1) _add(facts, mkFact('db.creds', h, credVal, S, source));
        }
      }

      // (ii) Share + Permission table (Any SMB/NFS/custom share enumeration tool regardless of column order)
      if (hasShareCol && (hasPermCol || expects('smb.shares'))) {
        var shareNames = [], hasReadSh = false, hasWriteSh = false;
        for (var r2 = 0; r2 < tbl.rows.length; r2++) {
          var row2 = tbl.rows[r2];
          var shName = String(row2.share || '').trim();
          var perm = String(row2.perm || row2._raw || '').toUpperCase();
          if (!shName || /^[-=]+$/.test(shName)) continue;
          shareNames.push(shName);
          if (!/^(?:IPC\$|PRINT\$)$/i.test(shName) && !/\bNO\s*ACCESS\b|\bDENIED\b/.test(perm)) {
            if (/\bREAD\b|\bOK\b|\bDISK\b|\bR\b/.test(perm)) hasReadSh = true;
            if (/\bWRITE\b|\bFULL\b|\bW\b|\bRW\b/.test(perm)) { hasWriteSh = true; hasReadSh = true; }
          }
        }
        if (shareNames.length) {
          var existingSh = facts.find(function (f) { return f && f.kind === 'smb.shares'; });
          if (existingSh && existingSh.value && existingSh.value.via === 'shape' && !existingSh.value.shares) {
            existingSh.value.shares = shareNames;
            existingSh.value.via = 'context-table';
          } else if (!existingSh) {
            _add(facts, mkFact('smb.shares', h, { shares: shareNames, via: 'context-table' }, S, source));
          }
          if (hasReadSh && !hasKind(facts, 'smb.readable_share')) _add(facts, mkFact('smb.readable_share', h, { via: 'context-table' }, S, source));
          if (hasWriteSh && !hasKind(facts, 'smb.writable_share')) _add(facts, mkFact('smb.writable_share', h, { via: 'context-table' }, S, source));
        }
      }

      // (iii) Port + State (+ Service) table (Custom port scanner, netstat/ss variant, firewall table)
      if (hasPortCol && hasStateCol && !hasPrefix(facts, 'port:')) {
        var openSummary = [];
        for (var r3 = 0; r3 < tbl.rows.length; r3++) {
          var row3 = tbl.rows[r3];
          var st3 = String(row3.state || '').toLowerCase();
          if (!/\b(?:open|listen(?:ing)?|up|allow(?:ed)?)\b/.test(st3) || /closed|filtered|down/.test(st3)) continue;
          var pm3 = /(\d{1,5})(?:\/(tcp|udp))?/i.exec(String(row3.port || ''));
          if (!pm3) continue;
          var pNum3 = parseInt(pm3[1], 10);
          var proto3 = (pm3[2] || row3.proto || 'tcp').toLowerCase();
          if (pNum3 < 1 || pNum3 > 65535) continue;
          var svc3 = String(row3.service || '').trim();
          var pVal3 = { port: pNum3, protocol: proto3, via: 'context-table' };
          if (svc3) pVal3.service = svc3;
          _add(facts, mkFact('port:' + pNum3, h, pVal3, S, source));
          if (C._parse_service_reachability) C._parse_service_reachability(pNum3, proto3, svc3, ws, source, facts);
          if (openSummary.indexOf(pNum3) < 0) openSummary.push(pNum3);
        }
        if (openSummary.length) {
          openSummary.sort(function (a, b) { return a - b; });
          _add(facts, mkFact('ports.open', h, { ports: openSummary, via: 'context-table' }, S, source));
        }
      }

      // (iv) Path + Status table (Web content discovery / route scanner with custom column layout)
      if (hasPathCol && hasStateCol && !hasKind(facts, 'web.paths')) {
        var foundPaths = [];
        for (var r4 = 0; r4 < tbl.rows.length; r4++) {
          var row4 = tbl.rows[r4];
          var codeM = /\b(200|201|204|301|302|307|401|403)\b/.exec(String(row4.state || ''));
          var pth = String(row4.path || '').trim();
          if (codeM && pth && (pth.charAt(0) === '/' || /^https?:\/\//i.test(pth))) {
            var cleanPth = C._url_path ? C._url_path(pth) : pth;
            if (cleanPth && foundPaths.indexOf(cleanPth) < 0) foundPaths.push(cleanPth);
          }
        }
        if (foundPaths.length) {
          _add(facts, mkFact('web.paths', h, { paths: foundPaths.slice(0, 500), count: foundPaths.length, via: 'context-table' }, S, source));
          if (!hasKind(facts, 'web.content_map')) _add(facts, mkFact('web.content_map', h, { paths: foundPaths.slice(0, 500), count: foundPaths.length, via: 'context-table' }, S, source));
          if (!hasKind(facts, 'http.reachable')) _add(facts, mkFact('http.reachable', h, { via: 'context-table' }, S, source));
        }
      }

      // (v) User + SPN / Right / Domain table (Directory enumeration with reordered or 1-col underlined columns)
      if (hasUserCol && !hasSecretCol && (hasSpnCol || hasRightCol || isAdTableCtx || globalIdx.isDc)) {
        var tblUsers = [], tblUsersSeen = Object.create(null);
        for (var r5 = 0; r5 < tbl.rows.length; r5++) {
          var row5 = tbl.rows[r5];
          var u5 = String(row5.user || '').trim().replace(/^CN=/i, '').replace(/,.*$/, '').replace(/^.*[\\\/]/, '').replace(/@.*$/, '');
          if (u5 && !isBoilerplateUser(u5) && C._valid_username && C._valid_username(u5, false) && !tblUsersSeen[u5]) {
            tblUsersSeen[u5] = 1;
            tblUsers.push(u5);
          }
          _ATOM_ACL_VERB_RE.lastIndex = 0;
          var rightVerbM = row5.right ? _ATOM_ACL_VERB_RE.exec(String(row5.right)) : null;
          if (rightVerbM && row5.user && !hasKind(facts, 'ad.acl_lead')) {
            _add(facts, mkFact('ad.acl_lead', domScope, { right: rightVerbM[1], principal: u5 || row5.user, via: 'context-table' }, S, source));
          }
        }
        if (tblUsers.length && !hasKind(facts, 'ad.user_list') && (hasSpnCol || isAdTableCtx || globalIdx.isDc || atoms.sids.length > 0 || atoms.dns.length > 0)) {
          _add(facts, mkFact('ad.user_list', domScope, { users: tblUsers, count: tblUsers.length, via: 'context-table' }, S, source));
        }
      }

      // (vi) Directory Computer table (`dnshostname` / `ComputerName`)
      if (hasComputerCol && !hasKind(facts, 'ad.computer_list') && (isAdTableCtx || globalIdx.isDc || atoms.sids.length > 0 || atoms.dns.length > 0)) {
        var tblComps = [], tblCompsSeen = Object.create(null);
        for (var r6 = 0; r6 < tbl.rows.length; r6++) {
          var c6 = String(tbl.rows[r6].computer || '').trim().replace(/^CN=/i, '').replace(/,.*$/, '');
          if (c6 && /^[A-Za-z0-9_.$-]{2,64}$/.test(c6) && !tblCompsSeen[c6.toLowerCase()]) {
            tblCompsSeen[c6.toLowerCase()] = 1;
            tblComps.push(c6);
          }
        }
        if (tblComps.length) {
          _add(facts, mkFact('ad.computer_list', domScope, { computers: tblComps, count: tblComps.length, via: 'context-table' }, S, source));
        }
      }
    }

    // 3B. Key-Value Object Block Inference (Order-independent attribute co-occurrence)
    var blockUsers = [], blockUsersSeen = Object.create(null);
    for (var bi = 0; bi < kvBlocks.length; bi++) {
      var blk = kvBlocks[bi];
      var blkText = (blk._lines || []).join('\n');
      var isXmlEncryptedBlk = !!(blk.encryptionmethod && !/^(?:none|cleartext|plain|plaintext|false|0)$/i.test(String(Array.isArray(blk.encryptionmethod) ? blk.encryptionmethod[0] : blk.encryptionmethod).trim()));
      var hasDecodeErrBlk = _DECODE_FAIL_RE.test(blkText);
      var suffixLoginVal = '', suffixPwVal = '';
      var blkKeys = Object.keys(blk);
      for (var bki = 0; bki < blkKeys.length; bki++) {
        var bk = blkKeys[bki];
        if (bk.charAt(0) === '_') continue;
        if (!suffixLoginVal && /^(?:user|admin|svc|db|app|sql|ftp|ssh|mail|account|auth)_?(?:login|user(?:name)?)$/.test(bk)) {
          suffixLoginVal = blk[bk];
        } else if (!suffixPwVal && (bk === 'pw' || bk === 'pwd' || /^(?:[a-z0-9_]+_)?[a-z0-9]*(?:pw|pwd|pass(?:word|wd)?)$/.test(bk)) && !/(?:hash|reset|forgot|change|update|policy|min|max|age|len|expir|prompt|file|path)/.test(bk)) {
          suffixPwVal = blk[bk];
        }
      }
      var hasExplicitIdField = !!(blk.samaccountname || blk.username || blk.user || blk.login || blk.account || blk.userprincipalname || blk.upn || blk.uid || suffixLoginVal);
      var hasIdentityPeer = !!(blk.password || blk.pass || blk.passwd || blk.pw || blk.pwd || suffixPwVal || blk.secret || blk.nthash || blk.ntlm || blk.hash || blk.cleartext || blk['ms_mcs_admpwd'] || blk['mslaps_password'] || blk.cpassword || blk.serviceprincipalname || blk.spn || blk.objectsid || blk.sid);
      var blkUser = blk.samaccountname || blk.username || blk.user || blk.login || blk.account || blk.userprincipalname || blk.upn || suffixLoginVal || (hasIdentityPeer ? (blk.cn || blk.name) : '') || '';
      if (Array.isArray(blkUser)) blkUser = blkUser[0];
      blkUser = String(blkUser || '').trim().replace(/^CN=/i, '').replace(/,.*$/, '').replace(/^.*[\\\/]/, '').replace(/@.*$/, '');

      var blkSec = (isXmlEncryptedBlk || hasDecodeErrBlk) ? '' : (blk.password || blk.pass || blk.passwd || blk.pw || blk.pwd || suffixPwVal || blk.secret || blk.nthash || blk.ntlm || blk.hash || blk.cleartext || blk['ms_mcs_admpwd'] || blk['mslaps_password'] || blk.cpassword || '');
      if (Array.isArray(blkSec)) blkSec = blkSec[0];
      blkSec = String(blkSec || '').trim().replace(/^['"]|['"]$/g, '');
      if ((blk.pw || blk.pwd) && blkSec === String(blk.pw || blk.pwd).trim() && /^(?:\/|~\/|[A-Za-z]:\\)/.test(blkSec)) blkSec = '';

      // KV Block: User + Secret
      if (!(hasTier1CredOrHash && isDedicatedTier1CredTool) && blkUser && blkSec && !isBoilerplateUser(blkUser) && !isPlaceholderSecret(blkSec, cmdSem.echoSet) && !_hasExtractedSecretFor(blkUser, blkSec)) {
        var isHashKv = /^(?:\$[0-9a-zA-Z_-]+\$|[0-9a-fA-F]{32,128}$|pbkdf2_sha)/i.test(blkSec);
        var kvCred = { user: blkUser, via: 'context-kv-block' };
        if (isHashKv) kvCred.hash = blkSec;
        else kvCred.password = blkSec;
        if (blk.domain) {
          var blkDom = String(Array.isArray(blk.domain) ? blk.domain[0] : blk.domain).trim();
          if (blkDom && !isPlaceholderSecret(blkDom, null)) kvCred.domain = blkDom;
        }
        _emit_credential_facts(facts, h, kvCred, source, allowBare32HexNtlm);
      }

      // KV Block: Directory User with SPN / AS-REP / SID / DN
      if (blkUser && !isBoilerplateUser(blkUser) && C._valid_username && C._valid_username(blkUser, false)) {
        if (blk.serviceprincipalname || blk.spn || blk.objectsid || blk.sid || (hasExplicitIdField && (blk.distinguishedname || blk.dn)) || blk.userprincipalname || blk.upn || expects('ad.user_list')) {
          if (!blockUsersSeen[blkUser]) { blockUsersSeen[blkUser] = 1; blockUsers.push(blkUser); }
        }
      }

      // KV Block: ACL Trustee / Principal + Right
      var aclPrincipal = blk.trustee || blk.principal || blk.grantee || blkUser || blk.target || blk.object || '';
      if (Array.isArray(aclPrincipal)) aclPrincipal = aclPrincipal[0];
      _ATOM_ACL_VERB_RE.lastIndex = 0;
      var kvAclM = _ATOM_ACL_VERB_RE.exec(blkText);
      var isBloodyWritableBlock = /\bbloodyad\b.*\bget\s+writable\b/i.test(command || '')
        || (/^\s*distinguishedName\s*:/im.test(blkText) && /\b(?:WRITE_PROP|WRITE_OWNER|WRITE_DACL|GENERIC_ALL|GENERIC_WRITE|CONTROL_ACCESS|CREATE_CHILD|SELF)\b/.test(blkText));
      var hasAdAclContext = !!(blk.activedirectoryrights || blk.objectdn || blk.objectsid || blk.inheritedobjecttype || blk.acetype || blk.ace || blk.trustee || blk.grantee || atoms.sids.length > 0 || atoms.dns.length > 0 || globalIdx.isDc || expects('ad.acl_lead') || expects('ad.control_paths'));
      if (!isBloodyWritableBlock && aclPrincipal && kvAclM && hasAdAclContext && !isWebClient && globalIdx.osFamily !== 'linux' && !hasKind(facts, 'ad.acl_lead')) {
        _add(facts, mkFact('ad.acl_lead', domScope, { right: kvAclM[1], principal: String(aclPrincipal).trim(), via: 'context-kv-block' }, S, source));
      }

      // KV Block: ADCS Template Name + Explicit Enrollment vulnerability signal
      var tmplName = blk.template_name || blk.templatename || ((blk.ca || blk.ca_name || blk.certificate_authority || /template|enrollee/i.test(blkText)) ? (blk.cn || blk.name) : '') || '';
      if (Array.isArray(tmplName)) tmplName = tmplName[0];
      var hasExplicitAdcsVuln = /\bESC(?:[1-9]|1[0-5])\b|Enrollee\s*Supplies\s*Subject["']?\s*[:=]\s*(?:True|true|1|Enabled)|ENROLLEE_SUPPLIES_SUBJECT|CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT|\[!\]\s*Vulnerabilities/i.test(blkText);
      if (tmplName && hasExplicitAdcsVuln && !/got error|failed/i.test(blkText)) {
        var escHits = [];
        if (/\bESC1\b|Enrollee\s*Supplies\s*Subject["']?\s*[:=]\s*(?:True|true|1|Enabled)|ENROLLEE_SUPPLIES_SUBJECT|CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT/i.test(blkText)) {
          escHits.push('ESC1');
        }
        var escMatches = blkText.match(/\bESC(?:[1-9]|1[0-5])\b/gi) || [];
        for (var emi = 0; emi < escMatches.length; emi++) {
          var eu = escMatches[emi].toUpperCase();
          if (escHits.indexOf(eu) < 0) escHits.push(eu);
        }
        var existingAdcs = facts.find(function (f) { return f && f.kind === 'adcs.vulnerable'; });
        if (existingAdcs && existingAdcs.value && existingAdcs.value.via === 'shape' && !existingAdcs.value.template) {
          existingAdcs.value.template = String(tmplName).trim();
          if (escHits.length) existingAdcs.value.esc = escHits;
          existingAdcs.value.via = 'context-kv-block';
        } else if (!existingAdcs) {
          _add(facts, mkFact('adcs.vulnerable', domScope, { template: String(tmplName).trim(), esc: escHits, via: 'context-kv-block' }, S, source));
        }
      }

      // KV Block: Delegation attribute on principal
      if (blkUser && _ATOM_DELEG_RE.test(blkText) && !hasKind(facts, 'ad.delegation')) {
        var delegTarget = blk['msds_allowedtodelegateto'] || blk['msds_allowedtoactonbehalfofotheridentity'] || '';
        if (delegTarget && !/^(?:write|read|create_child|delete_child|full_control|generic_all|generic_write|true|false)$/i.test(String(delegTarget).trim())) {
          _add(facts, mkFact('ad.delegation', domScope, { principal: blkUser, target: delegTarget, via: 'context-kv-block' }, S, source));
        }
      }

      // KV Block: Windows Unquoted / Weak Service Permission
      var svcName = blk.service_name || blk.servicename || blk.service || '';
      var svcPath = blk.path || blk.binary_path || blk.binary_path_name || blk.imagepath || blk.pathname || '';
      if (Array.isArray(svcName)) svcName = svcName[0];
      if (Array.isArray(svcPath)) svcPath = svcPath[0];
      if (svcName && svcPath && !isRemoteScanner && !isWebClient) {
        var sPathClean = String(svcPath).trim();
        if (sPathClean.charAt(0) !== '"' && !/^C:\\Windows\\/i.test(sPathClean) && /^[A-Za-z]:\\[^"\r\n]*\s+[^"\r\n]*\.exe\b/i.test(sPathClean) && !hasKind(facts, 'privesc.unquoted_service')) {
          _add(facts, mkFact('privesc.unquoted_service', h, { service: String(svcName).trim(), path: sPathClean, via: 'context-kv-block' }, S, source));
          if (!hasKind(facts, 'privesc.unquoted_service_path')) {
            _add(facts, mkFact('privesc.unquoted_service_path', h, { services: [sPathClean], count: 1, via: 'context-kv-block' }, S, source));
          }
        }
        if (/\b(?:SERVICE_ALL_ACCESS|FILE_ALL_ACCESS|CHANGE_CONFIG|WRITE_DAC|FullControl|Modify)\b|\((?:F|M|W)\)/i.test(blkText) && !hasKind(facts, 'privesc.weak_service_permission')) {
          _add(facts, mkFact('privesc.weak_service_permission', h, { service: String(svcName).trim(), path: sPathClean, via: 'context-kv-block' }, S, source));
        }
      }
    }
    if (blockUsers.length && !hasKind(facts, 'ad.user_list')) {
      _add(facts, mkFact('ad.user_list', domScope, { users: blockUsers, count: blockUsers.length, via: 'context-kv-block' }, S, source));
    }

    // 4. Global Engagement Entity Cross-Referencing (Known User + New Secret/Hash/Right on Same Line)
    if (globalIdx.userKeys.length > 0 && !hasTier1CredOrHash) {
      var entityLineCap = Math.min(lines.length, 100000);
      var entityKvHintRe = /(?:pass|pwd|[a-z0-9_]pw\b|\bpw\s*[:=]|secret|key|token|admpwd|cleartext)/i;
      _ATOM_HEX32_RE.lastIndex = 0;
      var docHasHex32 = _ATOM_HEX32_RE.test(analysisText);
      for (var li = 0; li < entityLineCap; li++) {
        var ln = lines[li].trim();
        if (!ln || ln.length > 2048) continue;
        // Fast pre-check: skip lines without any secret or hash candidate before scanning globalIdx.userKeys or polarity
        var hasKvCand = false, hasNtCand = false, hasModCand = false, hasHexCand = false;
        if (atoms.kvSecrets.length > 0 && (ln.indexOf('=') >= 0 || ln.indexOf(':') >= 0) && entityKvHintRe.test(ln)) {
          _ATOM_KV_SECRET_RE.lastIndex = 0;
          hasKvCand = _ATOM_KV_SECRET_RE.test(ln);
        }
        if (!hasKvCand && atoms.ntHashes.length > 0 && ln.indexOf(':') >= 0) {
          _ATOM_NTHASH_PAIR_RE.lastIndex = 0;
          hasNtCand = _ATOM_NTHASH_PAIR_RE.test(ln);
        }
        if (!hasKvCand && !hasNtCand && atoms.modHashes.length > 0 && (ln.indexOf('$') >= 0 || ln.indexOf('pbkdf2') >= 0)) {
          _ATOM_MOD_HASH_RE.lastIndex = 0;
          hasModCand = _ATOM_MOD_HASH_RE.test(ln);
        }
        if (!hasKvCand && !hasNtCand && !hasModCand && docHasHex32 && ln.length >= 32) {
          _ATOM_HEX32_RE.lastIndex = 0;
          hasHexCand = _ATOM_HEX32_RE.test(ln);
        }
        var hasLineSecret = hasKvCand || hasNtCand || hasModCand || hasHexCand;
        if (!hasLineSecret || _lineHasNegPolarity(lines, li) || _windowHasDecodeFailure(lines, li)) continue;
        var lnLow = ln.toLowerCase();

        for (var uk = 0; uk < globalIdx.userKeys.length; uk++) {
          var uKey = globalIdx.userKeys[uk];
          if (!_hasUserTokenCI(lnLow, uKey)) continue;
          var canonicalUser = globalIdx.users[uKey];

          _ATOM_KV_SECRET_RE.lastIndex = 0;
          var kvM, matchedKvSec = false;
          while ((kvM = _ATOM_KV_SECRET_RE.exec(ln)) !== null) {
            if (/^(?:no|by)pass(?:word|wd)?\s*[:=]/i.test(kvM[0])) continue;
            var kvSecCand = (kvM[1] || kvM[2] || kvM[3] || '').trim();
            if (!kvM[1] && !kvM[2] && kvSecCand.charAt(kvSecCand.length - 1) === ':') continue;
            if (kvSecCand && !isPlaceholderSecret(kvSecCand, cmdSem.echoSet)) {
              _emit_credential_facts(facts, h, { user: canonicalUser, password: kvSecCand, via: 'global-entity-bind' }, source, allowBare32HexNtlm);
              matchedKvSec = true;
            }
          }
          if (matchedKvSec) continue;
          _ATOM_NTHASH_PAIR_RE.lastIndex = 0;
          var ntM = _ATOM_NTHASH_PAIR_RE.exec(ln);
          if (ntM && ntM[1] && ntM[1].toLowerCase() !== _EMPTY_NTHASH && ntM[1].toLowerCase() !== _EMPTY_MD5 && !cmdSem.echoSet[ntM[1].toLowerCase()]) {
            var isUnambigNt = /(?:aad3b435b51404eeaad3b435b51404ee|NO PASSWORD\*+):[0-9a-fA-F]{32}/i.test(ntM[0]) || /:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::/.test(ln);
            if (isUnambigNt || allowBare32HexNtlm) {
              _emit_credential_facts(facts, h, { user: canonicalUser, nthash: ntM[1].toLowerCase(), via: 'global-entity-bind' }, source, true);
            } else {
              _emit_credential_facts(facts, h, { user: canonicalUser, hash: ntM[0].replace(/^:/, ''), format: 'md5', via: 'global-entity-bind' }, source, false);
            }
            continue;
          }
          _ATOM_MOD_HASH_RE.lastIndex = 0;
          var mhM = _ATOM_MOD_HASH_RE.exec(ln);
          if (mhM && mhM[0] && !cmdSem.echoSet[mhM[0].toLowerCase()]) {
            _emit_credential_facts(facts, h, { user: canonicalUser, hash: mhM[0], via: 'global-entity-bind' }, source, allowBare32HexNtlm);
            continue;
          }
          if (!/\b(?:md5|md5sum|sha1|sha256|checksum|uuid|guid|commit|etag|session[_-]?id)\b/i.test(ln) && !/[0-9a-fA-F]{32}\s{2,}\S+\.\w+/.test(ln)) {
            _ATOM_HEX32_RE.lastIndex = 0;
            var hxM;
            while ((hxM = _ATOM_HEX32_RE.exec(ln)) !== null) {
              var hx = hxM[1].toLowerCase();
              if (hx !== _EMPTY_NTHASH && hx !== _EMPTY_LMHASH && hx !== _EMPTY_MD5 && !cmdSem.echoSet[hx]) {
                _emit_credential_facts(facts, h, { user: canonicalUser, hash: hx, via: 'global-entity-bind' }, source, allowBare32HexNtlm);
                break;
              }
            }
          }
        }
      }
    }

    // 5. Semantic File Hint & Temporal Chaining (Orphan Secrets & Locate -> Inspect)
    if (atoms.kvSecrets.length > 0 && !(hasTier1CredOrHash && isDedicatedTier1CredTool)) {
      var recentActs = (frame && frame.recentActivities) || [];
      var priorUser = '';
      if (atoms.domUsers.length === 1) priorUser = atoms.domUsers[0].split('\\')[1];
      else if (atoms.upns.length === 1) priorUser = atoms.upns[0].split('@')[0];
      else if (globalIdx.userKeys.length === 1) priorUser = globalIdx.users[globalIdx.userKeys[0]];
      else if (recentActs.length > 0 && (!recentActs[0].target || recentActs[0].target === ws.target) && recentActs[0].context && recentActs[0].context.principal) {
        priorUser = String(recentActs[0].context.principal).replace(/^.*[\\\/]/, '');
      }
      for (var si = 0; si < atoms.kvSecrets.length; si++) {
        var sec = atoms.kvSecrets[si];
        if (_hasExtractedSecretFor(priorUser, sec)) continue;
        var cObj = { password: sec, via: cmdSem.fileSchemaHint ? ('file-hint:' + cmdSem.fileSchemaHint) : 'context-atom' };
        if (priorUser && !isBoilerplateUser(priorUser)) cObj.user = priorUser;
        if (cmdSem.targetPath) cObj.file = cmdSem.targetPath;
        _emit_credential_facts(facts, h, cObj, source, allowBare32HexNtlm);
      }
    }

    // 6. Phase-Aware Internal Subnet / Pivot Inference
    var lhostForPivot = (ws && ws.context && ws.context.params && ws.context.params.lhost) || '';
    var lhostSubForPivot = _subnet24(lhostForPivot);
    var isListenerCmd = /\b(?:nc|ncat|netcat|penelope|socat|pwncat)\b[^\r\n]*(?:\s-[A-Za-z0-9]*l|\bLISTEN\b)/i.test(command || '');
    if (!isWebClient && !isRemoteScanner
        && !(isListenerCmd && !atoms.hasRoutingOrIfaces)
        && (globalIdx.hasFoothold || promptMeta.locus === 'local' || expects('network.subnet_candidate') || expects('host.arp_neighbor') || expects('scan.local.'))
        && (atoms.newSubnetIps.length > 0 || atoms.cidrs.length > 0)
        && !hasKind(facts, 'network.subnet_candidate') && !hasKind(facts, 'host.arp_neighbor')) {
      var candSubnets = [];
      for (var ci = 0; ci < atoms.cidrs.length; ci++) {
        var cidrIp = atoms.cidrs[ci].split('/')[0];
        if (_subnet24(cidrIp) !== _subnet24(ws.target) && _subnet24(cidrIp) !== lhostSubForPivot) candSubnets.push(atoms.cidrs[ci]);
      }
      for (var ni = 0; ni < atoms.newSubnetIps.length; ni++) {
        var sub24 = _subnet24(atoms.newSubnetIps[ni]) + '.0/24';
        if (candSubnets.indexOf(sub24) < 0) candSubnets.push(sub24);
      }
      if (candSubnets.length) {
        _add(facts, mkFact('network.subnet_candidate', h, { subnets: candSubnets, hosts: atoms.newSubnetIps.slice(0, 200), via: 'context-phase-pivot' }, S, source));
      }
      if (atoms.newSubnetIps.length) {
        _add(facts, mkFact('host.arp_neighbor', h, { neighbors: atoms.newSubnetIps.slice(0, 200), via: 'context-phase-pivot' }, S, source));
      }
    }

    // 7. Co-Occurrence Rules for Unhandled Host / Directory / Web / Hash / Port Leads
    var maxLineScan = Math.min(lines.length, 100000);

    // 7A. Windows Token Privilege Lead (SeImpersonate / SeBackup etc. without Disabled on the same line)
    if (atoms.winPrivs.length > 0 && !isRemoteScanner && !isWebClient && !hasKind(facts, 'privesc.windows_privilege')) {
      var enabledPrivs = [];
      for (var wl = 0; wl < maxLineScan; wl++) {
        var wLine = lines[wl];
        if (wLine.length > 2048) continue;
        _ATOM_WIN_PRIV_RE.lastIndex = 0;
        var pm = _ATOM_WIN_PRIV_RE.exec(wLine);
        if (pm && !/\b(?:Disabled|Removed)\b/i.test(wLine)) {
          if (enabledPrivs.indexOf(pm[1]) < 0) enabledPrivs.push(pm[1]);
        }
      }
      if (enabledPrivs.length) {
        _add(facts, mkFact('privesc.windows_privilege', h, { privileges: enabledPrivs, via: 'context-cooccurrence' }, S, source));
      }
    }

    // 7B. Statistical Outlier & Per-Line URI + HTTP Status Co-Occurrence
    if (!hasKind(facts, 'web.paths') && (atoms.uriPaths.length > 0 || analysisText.indexOf('/') >= 0)) {
      var coPaths = [], coPathsSeen = Object.create(null);
      for (var uli = 0; uli < maxLineScan && coPaths.length < 500; uli++) {
        var uLine = lines[uli];
        if (uLine.length > 2048 || uLine.indexOf('/') < 0) continue;
        var stMatch = /\b(?:Status|Code|HTTP(?:\/[12](?:\.\d)?)?)\s*[:=\/]?\s*(200|201|204|301|302|307|401|403)\b/i.exec(uLine)
          || /\[\s*(200|201|204|301|302|307|401|403)\b/.exec(uLine)
          || /^\s*(200|201|204|301|302|307|401|403)\s+(?:GET|POST|HEAD|\d+[BKMbkm]?|\S+\s+\/)/i.exec(uLine);
        if (!stMatch) continue;
        _ATOM_URI_PATH_RE.lastIndex = 0;
        var upM = _ATOM_URI_PATH_RE.exec(uLine);
        if (upM && upM[1] && !/^\/(?:etc|var|opt|home|root|usr|tmp|proc|dev|sys|bin|sbin|lib|run)\b/.test(upM[1])) {
          if (!coPathsSeen[upM[1]]) { coPathsSeen[upM[1]] = 1; coPaths.push(upM[1]); }
        }
      }
      if (!coPaths.length && (expects('web.paths') || atoms.httpStatus > 0)) {
        var outliers = _find_statistical_outliers(lines);
        for (var oi = 0; oi < outliers.length; oi++) {
          _ATOM_URI_PATH_RE.lastIndex = 0;
          var om = _ATOM_URI_PATH_RE.exec(outliers[oi]);
          if (om && om[1] && !/\b(?:404|400|502|503)\b/.test(outliers[oi])) {
            if (!coPathsSeen[om[1]]) { coPathsSeen[om[1]] = 1; coPaths.push(om[1]); }
          }
        }
      }
      if (coPaths.length) {
        _add(facts, mkFact('web.paths', h, { paths: coPaths.slice(0, 500), count: coPaths.length, via: 'context-cooccurrence' }, S, source));
        if (!hasKind(facts, 'web.content_map')) _add(facts, mkFact('web.content_map', h, { paths: coPaths.slice(0, 500), count: coPaths.length, via: 'context-cooccurrence' }, S, source));
        if (!hasKind(facts, 'http.reachable')) _add(facts, mkFact('http.reachable', h, { via: 'context-cooccurrence' }, S, source));
      }
    }

    // 7C. Port + Positive Polarity Co-Occurrence (`80/tcp ... OPEN` or `Port 445 (tcp) ... OPEN/SUCCEEDED`)
    if (!hasPrefix(facts, 'port:') && (atoms.ports.length > 0 || /\b(?:tcp|udp)\b/i.test(analysisText))) {
      var atomOpenPorts = [];
      for (var pli = 0; pli < maxLineScan; pli++) {
        var pLine = lines[pli];
        if (pLine.length > 2048) continue;
        if (!/\b(?:open|listen(?:ing)?|succeeded|connected)\b/i.test(pLine) || /\b(?:closed|filtered|refused|unreachable|denied|down)\b/i.test(pLine)) continue;
        var ppM = /\b(\d{1,5})\/(tcp|udp)\b(?:\s+\w+)?(?:\s+([a-zA-Z0-9_.-]+))?/i.exec(pLine)
          || /\bport\s+(\d{1,5})\b[^\r\n]*?\b(tcp|udp)\b/i.exec(pLine);
        if (!ppM) continue;
        var pPort = parseInt(ppM[1], 10);
        var pProto = (ppM[2] || 'tcp').toLowerCase();
        var pSvc = (ppM[3] && !/^(?:open|succeeded|connected|on|to|at)$/i.test(ppM[3])) ? ppM[3] : '';
        if (pPort >= 1 && pPort <= 65535) {
          var pv = { port: pPort, protocol: pProto, via: 'context-cooccurrence' };
          if (pSvc) pv.service = pSvc;
          _add(facts, mkFact('port:' + pPort, h, pv, S, source));
          if (C._parse_service_reachability) C._parse_service_reachability(pPort, pProto, pSvc, ws, source, facts);
          if (atomOpenPorts.indexOf(pPort) < 0) atomOpenPorts.push(pPort);
        }
      }
      if (atomOpenPorts.length) {
        atomOpenPorts.sort(function (a, b) { return a - b; });
        _add(facts, mkFact('ports.open', h, { ports: atomOpenPorts, via: 'context-cooccurrence' }, S, source));
      }
    }

    // 7D. POSIX Identity (`uid=33(www-data) gid=33(www-data)`) Co-Occurrence
    var isLocalAttackerOrDockerTurn = !isWebClient
      && ((C._is_attacker_local_turn && C._is_attacker_local_turn(ws, command, text))
          || (promptMeta.locus === 'remote' && /^[0-9a-f]{12}$/i.test(promptMeta.host || '')));
    if (atoms.posixId && !isRemoteScanner && !isLocalAttackerOrDockerTurn) {
      if (isWebClient && !hasKind(facts, 'web.rce')) {
        _add(facts, mkFact('web.rce', h, { user: atoms.posixId.user, uid: atoms.posixId.uid, via: 'context-cooccurrence' }, S, source));
      }
      if (!hasKind(facts, 'foothold.linux') && !globalIdx.hasFoothold && !_ATTACKER_HOSTS.test(atoms.posixId.user)
          && (!isWebClient || hasEngagementCtx || !hasKind(facts, 'web.cmdi_confirmed'))) {
        _add(facts, mkFact('foothold.linux', h, { identity: atoms.posixId.user, method: isWebClient ? 'web-rce' : (cmdSem.tool || 'shell'), via: 'context-cooccurrence' }, S, source));
        if (C._add_os_observation) C._add_os_observation(facts, ws, source, 'linux', 'uid=' + atoms.posixId.uid + '(' + atoms.posixId.user + ')', 'high', 'id', true);
      }
      if (atoms.posixId.uid === 0 && !_ATTACKER_HOSTS.test(atoms.posixId.user)) {
        if (!hasKind(facts, 'access.root')) {
          _add(facts, mkFact('access.root', h, { identity: 'root', method: cmdSem.tool || 'shell', via: 'context-cooccurrence' }, S, source));
        }
        if (!hasKind(facts, 'access.admin')) {
          _add(facts, mkFact('access.admin', h, { identity: 'root', method: cmdSem.tool || 'shell', via: 'context-cooccurrence' }, S, source));
        }
      }
    }

    // 7D-Win. Multi-Word Windows Built-in Service Authority Identity (`iis apppool\defaultapppool`, `nt service\...`, `nt authority\...`)
    if (!isRemoteScanner && analysisText.indexOf('\\') >= 0) {
      var winSvcM = _ATOM_WIN_SVC_WHOAMI_RE.exec(analysisText);
      if (winSvcM && winSvcM[1]) {
        var winSvcId = winSvcM[1].trim();
        var winSvcParts = winSvcId.split('\\');
        var winAuthDom = winSvcParts[0].toLowerCase();
        var winAuthAcct = (winSvcParts[1] || '').toLowerCase();
        if (isWebClient && !hasKind(facts, 'web.rce')) {
          _add(facts, mkFact('web.rce', h, { user: winSvcId, os: 'windows', via: 'context-cooccurrence' }, S, source));
        }
        if (!hasKind(facts, 'foothold.windows') && !globalIdx.hasFoothold) {
          _add(facts, mkFact('foothold.windows', h, { identity: winSvcId, method: isWebClient ? 'web-rce' : (cmdSem.tool || 'shell'), via: 'context-cooccurrence' }, S, source));
          if (C._add_os_observation) C._add_os_observation(facts, ws, source, 'windows', winSvcId, 'high', 'whoami', true);
        }
        if (winAuthDom === 'nt authority' && /^(?:system|sistema|syst\u00e8me)$/i.test(winAuthAcct)) {
          if (!hasKind(facts, 'access.system')) {
            _add(facts, mkFact('access.system', h, { identity: winSvcId, method: cmdSem.tool || 'shell', via: 'context-cooccurrence' }, S, source));
          }
          if (!hasKind(facts, 'access.admin')) {
            _add(facts, mkFact('access.admin', h, { identity: winSvcId, method: cmdSem.tool || 'shell', via: 'context-cooccurrence' }, S, source));
          }
        }
      }
    }

    // 7E-krbtgt. Direct `krbtgt` Hash-Binding Exemption (`krbtgt` remains boilerplate for prose/user-lists,
    // but co-occurrence with a valid 32-hex NTLM or 64-hex AES-256 key on the same line proves hash.krbtgt)
    if (!hasKind(facts, 'hash.krbtgt') && /\bkrbtgt\b/i.test(analysisText)) {
      for (var kli = 0; kli < maxLineScan; kli++) {
        var kLn = lines[kli];
        if (!kLn || kLn.length > 2048 || !/\bkrbtgt\b/i.test(kLn) || _lineHasNegPolarity(lines, kli)) continue;
        if (/^\s*(?:impacket-)?(?:ticketer|getTGT|getST|Rubeus)\b/i.test(kLn)) continue;
        var kNtM = /\bkrbtgt:(?:\d+:)?(?:[0-9a-fA-F]{32}|NO PASSWORD\*+|\.{2,4}|\*+):([0-9a-fA-F]{32}):::/i.exec(kLn)
          || /(?:^|[\s\\])krbtgt\s*[:=]\s*([0-9a-fA-F]{32})\b/i.exec(kLn)
          || /\bkrbtgt:rc4_hmac:([0-9a-fA-F]{32})\b/i.exec(kLn)
          || (/\b(?:ntlm|nthash|rc4)\b/i.test(kLn) && /\b([0-9a-fA-F]{32})\b/.exec(kLn));
        var kAesM = !kNtM && (/\bkrbtgt:aes256-cts-hmac-sha1-96:([0-9a-fA-F]{64})\b/i.exec(kLn)
          || /(?:^|[\s\\])krbtgt\s*[:=]\s*([0-9a-fA-F]{64})\b/i.exec(kLn)
          || (/\baes256\b/i.test(kLn) && /\b([0-9a-fA-F]{64})\b/.exec(kLn)));
        if (kNtM && kNtM[1]) {
          var kNt = kNtM[1].toLowerCase();
          if (kNt !== _EMPTY_NTHASH && kNt !== _EMPTY_LMHASH && kNt !== _EMPTY_MD5 && !/^(?:0{32}|f{32})$/.test(kNt) && !cmdSem.echoSet[kNt]) {
            _add(facts, mkFact('hash.krbtgt', domScope, { user: 'krbtgt', nthash: kNt, via: 'inference-hash-bind' }, S, source));
            break;
          }
        } else if (kAesM && kAesM[1]) {
          var kAes = kAesM[1].toLowerCase();
          if (!/^(?:0{64}|f{64})$/.test(kAes) && !cmdSem.echoSet[kAes]) {
            _add(facts, mkFact('hash.krbtgt', domScope, { user: 'krbtgt', aes256: kAes, via: 'inference-hash-bind' }, S, source));
            break;
          }
        }
      }
    }

    // 7I. Credential-Delivery Announcement + Adjacent 2-Line `<principal>` / `<secret>` Pair
    // Handles plaintext emails, notes, and OOXML/HTML (`word/document.xml`) paragraphs without key=value syntax.
    if (/\b(?:credentials?|creds?|login\s+details?|account\s+details?)\b/i.test(analysisText)) {
      var docParaLines = lines;
      if (/<\/(?:w:p|p|div|li|tr)>|<br\s*\/?>/i.test(analysisText)) {
        docParaLines = analysisText
          .replace(/<\/(?:w:p|p|div|li|tr)>|<br\s*\/?>/gi, '\n')
          .replace(/<[^>]+>/g, '')
          .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
          .split(/\r?\n/);
      }
      var credAnnounceRe = /(?:\b(?:below\s+(?:you\s+(?:can|will)\s+find|are|is)|here(?:'s|\s+are|\s+is)|(?:please\s+)?find\s+below|use\s+the\s+following|following\s+are)\b[^\r\n]{0,80}?\b(?:credentials?|creds?|login\s+details?|account\s+details?)\b|\b(?:your|temporary|initial|new|updated|default|login|access)\s+(?:login\s+)?(?:credentials?|creds?)\s+(?:are(?:\s+as\s+follows|\s+below)?|below)\b|\b(?:credentials?|creds?)\s+(?:are\s+as\s+follows|below)\s*:?\s*$)/i;
      var docUserSkipRe = /^(?:thanks|thank|regards|sincerely|best|cheers|welcome|dear|please|hello|hi|hey|note|warning|important|username|user|login|password|pass|account|credentials|creds|http|https|mailto)$/i;
      var docCap = Math.min(docParaLines.length, 20000);
      for (var dli = 0; dli < docCap; dli++) {
        var dLn = String(docParaLines[dli] || '').trim();
        if (!dLn || dLn.length > 512 || !credAnnounceRe.test(dLn)) continue;
        var nextNonEmpty = [];
        for (var dnj = dli + 1; dnj < docCap && nextNonEmpty.length < 4; dnj++) {
          var dnTrim = String(docParaLines[dnj] || '').trim();
          if (!dnTrim) continue;
          if (/^[-=*#]{3,}$/.test(dnTrim)) break;
          nextNonEmpty.push(dnTrim);
        }
        for (var np = 0; np + 1 < nextNonEmpty.length && np <= 1; np++) {
          var uDoc = nextNonEmpty[np], pDoc = nextNonEmpty[np + 1];
          if (!/^[A-Za-z][A-Za-z0-9._-]{1,31}(?:@[A-Za-z0-9.-]+\.[A-Za-z]{2,})?$/.test(uDoc)) continue;
          if (docUserSkipRe.test(uDoc) || isBoilerplateUser(uDoc)) continue;
          if (!/^[\x21-\x7e]{8,64}$/.test(pDoc) || docUserSkipRe.test(pDoc)) continue;
          if (/^(?:https?:\/\/|\/|[A-Za-z]:\\|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$)/i.test(pDoc)) continue;
          if (isPlaceholderSecret(pDoc, cmdSem.echoSet)) continue;
          var clsCount = (/[a-z]/.test(pDoc) ? 1 : 0) + (/[A-Z]/.test(pDoc) ? 1 : 0) + (/[0-9]/.test(pDoc) ? 1 : 0) + (/[^A-Za-z0-9]/.test(pDoc) ? 1 : 0);
          var hasNonWordEntropy = /[0-9]|[^A-Za-z0-9]|[a-z][A-Z]/.test(pDoc);
          if (clsCount < 2 || !hasNonWordEntropy) continue;
          if (!_hasExtractedSecretFor(uDoc, pDoc)) {
            var docCredVal = { user: uDoc, password: pDoc, secret_type: 'plaintext', via: 'inference-doc-cred-pair', unvalidated: true };
            _add(facts, mkFact('credential.candidate', h, docCredVal, S, source));
            _add(facts, mkFact('credential.plaintext', h, docCredVal, S, source));
            _add(facts, mkFact('credential.available', h, docCredVal, S, source));
          }
          break;
        }
      }
    }

    // 7E. Unhandled NTLM Pair (`lm:nt`) & Modular Hash (`$2y$`, `$6$`, `$krb5tgs$`, `$krb5asrep$`, `$DCC2$`) Co-Occurrence
    var hasUnhandledNtPair7E = atoms.ntHashes.length > 0 && !hasKind(facts, 'hash.ntlm') && !isDedicatedTier1CredTool;
    var hasUnhandledModOrTuple7E = (atoms.modHashes.length > 0 || hasPositionalMd5Tuple)
      && !hasTier1CredOrHash && !hasKind(facts, 'hash.tgs') && !hasKind(facts, 'hash.asrep') && !hasKind(facts, 'hash.crackable');
    if (hasUnhandledNtPair7E || hasUnhandledModOrTuple7E) {
      for (var hli = 0; hli < maxLineScan; hli++) {
        var hLine = lines[hli].trim();
        if (!hLine) continue;
        var hasDollarLine = hLine.indexOf('$') >= 0;
        var isLongJohnModLine = hasDollarLine && /\$(?:pkzip2?|zip2|7z|rar[35]?|pfx(?:ng)?|keepass|sshng|ansible)\$/i.test(hLine);
        if (hLine.length > (hasDollarLine ? 65536 : 2048)) continue;
        if (!isLongJohnModLine && _lineHasNegPolarity(lines, hli)) continue;

        // Extract candidate username from the same line (`DOMAIN\user`, `user@domain`, `user:rid:lm:nt`, `user:$2y$...`, or `array('user', '$2a$...')`)
        var lineUser = '', lineDom = '', lineFile = '';
        _ATOM_DOM_USER_RE.lastIndex = 0;
        var duM = _ATOM_DOM_USER_RE.exec(hLine);
        if (duM && !isBoilerplateUser(duM[2])) { lineDom = duM[1]; lineUser = duM[2]; }
        if (!lineUser) {
          var colonUserM = /^([A-Za-z0-9_.\-$/]{2,96}):(?:\d+:|\$)/.exec(hLine)
            || /\b(?:user(?:name)?|account|login)\s*[:=]\s*['"]?([A-Za-z0-9_.\-$]{2,48})/i.exec(hLine)
            || /(?:array\s*\(|[\[(])\s*['"]([A-Za-z0-9_.\-$]{2,48})['"]\s*,\s*['"](?:\$(?:1|2[abxy]|5|6|y|apr1)\$|pbkdf2_sha(?:1|256|512)\$|[0-9a-fA-F]{32}['"])/i.exec(hLine);
          if (colonUserM) {
            if (isLongJohnModLine || /[\/]|\.(?:zip|7z|rar|pfx|p12|kdbx|pem|key|id_rsa|yml|yaml|vault)$/i.test(colonUserM[1])) {
              lineFile = colonUserM[1];
            } else if (!isBoilerplateUser(colonUserM[1])) {
              lineUser = colonUserM[1];
            }
          }
        }

        _ATOM_NTHASH_PAIR_RE.lastIndex = 0;
        var ntpM = _ATOM_NTHASH_PAIR_RE.exec(hLine);
        if (ntpM && ntpM[1]) {
          var ntVal = ntpM[1].toLowerCase();
          if (ntVal !== _EMPTY_NTHASH && ntVal !== _EMPTY_LMHASH && ntVal !== _EMPTY_MD5 && !cmdSem.echoSet[ntVal]) {
            var isUnambigCoNt = /(?:aad3b435b51404eeaad3b435b51404ee|NO PASSWORD\*+):[0-9a-fA-F]{32}/i.test(ntpM[0]) || /:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::/.test(hLine) || Boolean(lineDom);
            if (isUnambigCoNt || allowBare32HexNtlm) {
              _emit_credential_facts(facts, h, { user: lineUser, domain: lineDom, nthash: ntVal, via: 'context-cooccurrence' }, source, true);
            } else {
              _emit_credential_facts(facts, h, { user: lineUser, domain: lineDom, hash: ntpM[0].replace(/^:/, ''), format: 'md5', via: 'context-cooccurrence' }, source, false);
            }
            continue;
          }
        }

        _ATOM_MOD_HASH_RE.lastIndex = 0;
        var modM = _ATOM_MOD_HASH_RE.exec(hLine);
        if (modM && modM[0] && !cmdSem.echoSet[modM[0].toLowerCase()]) {
          _emit_credential_facts(facts, h, { user: lineUser, domain: lineDom, file: lineFile || undefined, hash: modM[0], via: 'context-cooccurrence' }, source);
          continue;
        }

        var tupleMd5M = /(?:array\s*\(|[\[(])\s*['"]([A-Za-z0-9_.\-$]{2,48})['"]\s*,\s*['"]([0-9a-fA-F]{32})['"]/.exec(hLine);
        if (tupleMd5M && !isBoilerplateUser(tupleMd5M[1])) {
          var tupleHex = tupleMd5M[2].toLowerCase();
          if (tupleHex !== _EMPTY_MD5 && tupleHex !== _EMPTY_NTHASH && tupleHex !== _EMPTY_LMHASH
              && !/^(?:0{32}|f{32})$/.test(tupleHex) && !cmdSem.echoSet[tupleHex]) {
            var tupVal = { user: tupleMd5M[1], hash: tupleHex, hash_type: 'md5', format: 'md5', via: 'context-cooccurrence' };
            _add(facts, mkFact('credential.candidate', h, tupVal, S, source));
            _add(facts, mkFact('hash.crackable', h, tupVal, S, source));
            _add(facts, mkFact('hash.candidate', h, tupVal, S, source));
          }
        }
      }
    }

    // 7E-pkzip. zip2john stderr banner (`ver 2.0 efh ... PKZIP Encr:`) when stdout hash was redirected to file,
    // plus guaranteed loot.material co-minting whenever an archive/keystore modular hash is present.
    if (analysisText.indexOf('PKZIP Encr:') >= 0 && /\bver\s+\d+\.\d+\b[^\r\n]*\bPKZIP\s+Encr:/i.test(analysisText)) {
      if (!hasKind(facts, 'loot.material')) {
        _add(facts, mkFact('loot.material', h, { kind: 'pkzip', tool: 'zip2john', via: 'context-cooccurrence' }, S, source));
      }
      if (!hasKind(facts, 'hash.crackable')) {
        _add(facts, mkFact('hash.crackable', h, { format: 'pkzip', hash_type: 'pkzip', tool: 'zip2john', via: 'context-cooccurrence' }, S, source));
        _add(facts, mkFact('hash.candidate', h, { format: 'pkzip', hash_type: 'pkzip', tool: 'zip2john', via: 'context-cooccurrence' }, S, source));
      }
    }
    if (!hasKind(facts, 'loot.material') && atoms.modHashes.length > 0) {
      for (var mhi = 0; mhi < atoms.modHashes.length; mhi++) {
        var archModM = /^\$(pkzip2?|zip2|7z|rar[35]?|pfx(?:ng)?|keepass|ansible)\$/i.exec(atoms.modHashes[mhi]);
        if (archModM) {
          var archKind = archModM[1].toLowerCase().replace(/^pkzip2$/, 'pkzip').replace(/^pfxng$/, 'pfx').replace(/^rar[35]$/, 'rar');
          _add(facts, mkFact('loot.material', h, { kind: archKind, via: 'context-cooccurrence' }, S, source));
          break;
        }
      }
    }

    // 7F. Domain\User or UPN + Cleartext Auth Success Co-Occurrence (`CORP\svc_sql:Winter2026! ... AUTHENTICATED / Pwn3d!`)
    if (atoms.domUsers.length > 0 || atoms.upns.length > 0) {
      for (var ali = 0; ali < maxLineScan; ali++) {
        var aLine = lines[ali];
        if (aLine.length > 2048 || _lineHasNegPolarity(lines, ali)) continue;
        if (!/\b(?:Pwn3d!|AUTHENTICATED|LOGIN\s+OK|SUCCESS(?:FUL|FULLY)?|VALID\s+CREDENTIALS?)\b|\[\+\]/i.test(aLine)) continue;
        if (/^\s*(?:SMB|LDAP|WINRM|SSH|MSSQL|RDP|FTP|WMI)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+\s+\[[+-]\]/i.test(aLine) && hasTier1CredOrHash) continue;
        var authPairM = /\b([A-Za-z0-9_.-]{2,32})\\([A-Za-z0-9_.\-$]{2,48}):([^\s'"\r\n]{3,128})/.exec(aLine)
          || /\b([A-Za-z0-9_.\-]{2,48})@([A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+):([^\s'"\r\n]{3,128})/.exec(aLine);
        if (!authPairM) continue;
        var aDom = authPairM[0].indexOf('\\') >= 0 ? authPairM[1] : authPairM[2];
        var aUsr = authPairM[0].indexOf('\\') >= 0 ? authPairM[2] : authPairM[1];
        var aSec = authPairM[3];
        if (isBoilerplateUser(aUsr) || isPlaceholderSecret(aSec, null)) continue;
        // Guard against LM:NT or RID:LM:NT hash dump rows matching 7F when prefixed with `[+]`
        var isHashPairSec = /^(?:\d+:)?(?:(?:[0-9a-fA-F]{32}|NO PASSWORD\*+):)?([0-9a-fA-F]{32})(?:::.*)?$/i.exec(aSec);
        var hasExplicitAuthVerdict = /\b(?:Pwn3d!|AUTHENTICATED|LOGIN\s+OK|STATUS_SUCCESS|SUCCESS(?:FUL|FULLY)?|VALID\s+CREDENTIALS?)\b/i.test(aLine);
        if (isHashPairSec) {
          var ntCandidate = isHashPairSec[1].toLowerCase();
          if (ntCandidate === _EMPTY_NTHASH || ntCandidate === _EMPTY_LMHASH || ntCandidate === _EMPTY_MD5) continue;
          _emit_credential_facts(facts, h, { user: aUsr, domain: aDom, nthash: ntCandidate, via: 'context-cooccurrence' }, source);
          if (!hasExplicitAuthVerdict) continue;
        } else {
          _emit_credential_facts(facts, h, { user: aUsr, domain: aDom, password: aSec, via: 'context-cooccurrence' }, source);
        }
        var aProto = cmdSem.inputService || (/\bwinrm\b|5985/i.test(aLine) ? 'winrm' : /\bldap\b|389/i.test(aLine) ? 'ldap' : /\bssh\b|22\b/i.test(aLine) ? 'ssh' : 'smb');
        if (aProto && !hasKind(facts, aProto + '.authenticated')) {
          _add(facts, mkFact(aProto + '.authenticated', h, { user: aUsr, domain: aDom, via: 'context-cooccurrence' }, S, source));
        }
        if (/\bPwn3d!/i.test(aLine) && !hasKind(facts, 'access.admin')) {
          _add(facts, mkFact('access.admin', h, { user: aUsr, domain: aDom, via: 'context-cooccurrence' }, S, source));
        }
      }

      // Directory User List Co-Occurrence (Domain\User or UPN + SID / SPN / DN / ad.user_list contract)
      var isLocalTokenInspect = /\b(?:whoami|klist|token::(?:list|elevate|whoami)|sekurlsa::|lsadump::(?:sam|secrets|cache))\b/i.test((command || '') + '\n' + analysisText)
        || /(?:PRIVILEGES INFORMATION|TOKEN INFORMATION|USER INFORMATION|->\s*Impersonated\s*!)/i.test(analysisText);
      var isStaticPsOrRegAcl = /\bImport-Module\s+ActiveDirectory\b|\bfunction\s+[A-Za-z]+-[A-Za-z0-9]+\b|\bCmdletBinding\s*\(|\bparam\s*\(|\bforeach\s*\(\s*\$/i.test(analysisText)
        || /\bGet-Acl\b|Microsoft\.PowerShell\.Core\\Registry::|\bRegistryRights\s*:/i.test((command || '') + '\n' + analysisText);
      if (!hasKind(facts, 'ad.user_list') && !isLocalTokenInspect && !isStaticPsOrRegAcl && !/\b(?:rpcdump|rpcinfo)\b/i.test(command || '') && !/Protocol:\s*\[MS-/i.test(analysisText) && (atoms.sids.length > 0 || atoms.spns.length > 0 || atoms.dns.length > 0 || expects('ad.user_list'))) {
        var coUsers = [], coUsersSeen = Object.create(null);
        var inUserLow = (cmdSem.inputUser || '').toLowerCase();
        for (var dui = 0; dui < atoms.domUsers.length; dui++) {
          var duName = atoms.domUsers[dui].split('\\')[1];
          if (duName && duName.toLowerCase() !== inUserLow && !isBoilerplateUser(duName) && !coUsersSeen[duName]) { coUsersSeen[duName] = 1; coUsers.push(duName); }
        }
        for (var upi = 0; upi < atoms.upns.length; upi++) {
          var upName = atoms.upns[upi].split('@')[0];
          if (upName && upName.toLowerCase() !== inUserLow && !isBoilerplateUser(upName) && !coUsersSeen[upName]) { coUsersSeen[upName] = 1; coUsers.push(upName); }
        }
        var minCoUsers = (expects('ad.user_list') || atoms.dns.length > 0 || atoms.spns.length > 0) ? 1 : 2;
        if (coUsers.length >= minCoUsers) {
          _add(facts, mkFact('ad.user_list', domScope, { users: coUsers, count: coUsers.length, via: 'context-cooccurrence' }, S, source));
        }
      }
    }

    // 7G. UNC Share Path Co-Occurrence (`\\host\ShareName\...`)
    var isNetLocalGroupOrUser = /\bnet1?(?:\.exe)?\s+(?:localgroup|group|user)\b/i.test(command || '')
      || /^\s*Alias name\s+\S+[\s\S]{0,320}?^\s*Members\s*\r?\n-+/im.test(analysisText);
    if (atoms.uncPaths.length > 0 && !isNetLocalGroupOrUser && !hasKind(facts, 'smb.shares')) {
      var uncShares = [];
      var gLhost = String((ws && ws.context && ws.context.params && ws.context.params.lhost) || '').trim().toLowerCase();
      var gLhostSub = _subnet24(gLhost);
      var gTarget = String(ws.target || '').trim();
      var gTargetSub = _subnet24(gTarget);
      for (var uci = 0; uci < atoms.uncPaths.length; uci++) {
        var uncParts = atoms.uncPaths[uci].replace(/^\\\\/, '').split('\\');
        var gUncHost = String(uncParts[0] || '').trim();
        var gUncHostLow = gUncHost.toLowerCase();
        if (!gUncHost || gUncHost === '.' || gUncHostLow === 'localhost' || gUncHost === '127.0.0.1' || (uncParts[1] && uncParts[1].toLowerCase() === 'pipe')) continue;
        if (gLhost && gUncHostLow === gLhost) continue;
        if (_isPrivateIpv4(gUncHost, false) && gTarget && gUncHost !== gTarget) {
          var gUncSub = _subnet24(gUncHost);
          if ((gLhostSub && gUncSub === gLhostSub) || (_isPrivateIpv4(gTarget, false) && gUncSub !== gTargetSub)) continue;
        }
        if (uncParts.length >= 2 && uncParts[1] && uncShares.indexOf(uncParts[1]) < 0) {
          uncShares.push(uncParts[1]);
        }
      }
      if (uncShares.length) {
        _add(facts, mkFact('smb.shares', h, { shares: uncShares, via: 'context-cooccurrence' }, S, source));
      }
    }

    // 7H. POSIX Path + Permission Mode Co-Occurrence (SUID, Capabilities, Writable /etc/passwd or /etc/shadow)
    if ((atoms.posixPaths.length > 0 || atoms.permModes.length > 0) && !isRemoteScanner && !isWebClient) {
      var suidBins = [], suidSeen = Object.create(null), capBins = [], capEntries = [], capSeen = Object.create(null);
      for (var pxi = 0; pxi < maxLineScan; pxi++) {
        var pxLine = lines[pxi];
        if (!pxLine || pxLine.length > 2048) continue;
        if (pxLine.indexOf('s') >= 0 || pxLine.indexOf('S') >= 0 || pxLine.indexOf('w') >= 0) {
          var pxTrim = pxLine.trim();
          if (/^-[rwx-]{2}[sS][rwxstS-]{6}[.+@]?\s+\d+\s+/.test(pxTrim)) {
            _ATOM_POSIX_PATH_RE.lastIndex = 0;
            var spM = _ATOM_POSIX_PATH_RE.exec(pxLine);
            if (spM && spM[1] && !suidSeen[spM[1]]) {
              var sPath = spM[1];
              var sBase = sPath.split('/').pop().toLowerCase();
              var sBaseNorm = sBase.replace(/-[0-9.]+$/, '');
              var isNonStdSuidPath = /(?:^|\/)(?:opt|usr\/local|home|var|srv|tmp)\//i.test(sPath);
              var isInterestingSuid = (C._SUID_INTERESTING && (C._SUID_INTERESTING.test(sBase) || C._SUID_INTERESTING.test(sBaseNorm)))
                || (isNonStdSuidPath && !(C._is_stock_suid && C._is_stock_suid(sPath)));
              if (isInterestingSuid && !(C._is_stock_suid && C._is_stock_suid(sPath)) && !/^(?:passwd|su|sudo|gpasswd|newgrp|chsh|chfn|mount|umount|fusermount3?|ping6?|unix_chkpwd|ssh-keysign|polkit-agent-helper-1|dbus-daemon-launch-helper|halt|reboot|poweroff|shutdown|telinit|runlevel)$/i.test(sBase)) {
                suidSeen[sPath] = 1;
                suidBins.push(sPath);
              }
            }
          }
          if (/^-[rwx-]{7}w[rwx-]\s+.*\s+\/etc\/(?:passwd|shadow)\b/.test(pxTrim) && !hasKind(facts, 'privesc.writable_etc')) {
            _add(facts, mkFact('privesc.writable_etc', h, { line: pxTrim, via: 'context-cooccurrence' }, S, source));
            if (!hasKind(facts, 'privesc.passwd_writable')) {
              _add(facts, mkFact('privesc.passwd_writable', h, { path: '/etc/passwd', world_writable: true, via: 'context-cooccurrence' }, S, source));
            }
          }
        }
        if (pxLine.indexOf('cap_') >= 0) {
          var capMatch = /\b(cap_[a-z0-9_,]+(?:\+[eip]+|=ep|=eip|=p))/i.exec(pxLine);
          if (capMatch && (C._DANGEROUS_CAPS ? C._DANGEROUS_CAPS.test(capMatch[1]) : /\bcap_(?:setuid|setgid|dac_override|dac_read_search|chown|fowner|sys_admin|sys_ptrace|sys_module|sys_rawio|sys_chroot|net_admin|bpf)\b/i.test(capMatch[1]))) {
            _ATOM_POSIX_PATH_RE.lastIndex = 0;
            var cpM = _ATOM_POSIX_PATH_RE.exec(pxLine);
            if (cpM && cpM[1] && !capSeen[cpM[1]]) {
              capSeen[cpM[1]] = 1;
              capBins.push(cpM[1]);
              capEntries.push({ path: cpM[1], capabilities: capMatch[1].replace(/^=/, '+') });
            }
          }
        }
      }
      if (suidBins.length && !hasKind(facts, 'privesc.suid')) {
        _add(facts, mkFact('privesc.suid', h, { binaries: suidBins.slice(0, 500), via: 'context-cooccurrence' }, S, source));
        if (!hasKind(facts, 'privesc.suid_candidate')) {
          _add(facts, mkFact('privesc.suid_candidate', h, { paths: suidBins.slice(0, 500), count: suidBins.length, via: 'context-cooccurrence' }, S, source));
        }
      }
      if (capBins.length && !hasKind(facts, 'privesc.capabilities')) {
        _add(facts, mkFact('privesc.capabilities', h, { binaries: capBins.slice(0, 500), entries: capEntries.slice(0, 500), via: 'context-cooccurrence' }, S, source));
        if (!hasKind(facts, 'privesc.capability')) {
          _add(facts, mkFact('privesc.capability', h, { entries: capEntries.slice(0, 500), count: capEntries.length, via: 'context-cooccurrence' }, S, source));
        }
      }
    }
  }
  C._parse_inference = _parse_inference;

  // ---- Causal Entailment & Gate Synchronizer (Out-of-Order Jump Support) -----------------------
  // When an operator jumps ahead of gated moves in a live engagement (opts.context is present),
  // co-mint the logically implied prerequisite gates (host.up, service .reachable, OS family,
  // foothold, and domain linkage) so downstream moves in pack.js unlock immediately, while
  // deliberately leaving broad discovery scans (scan.nmap.quick / scan.nmap.version) unsettled
  // so skipped recon stays visible.
  function _apply_causal_entailment(facts, ws, command, text, source, opts) {
    if (!Array.isArray(facts) || !facts.length) return;
    var hasEngagementCtx = !!(opts && (opts.entail || (opts.context && (opts.context.target || opts.context.attentionFrame || opts.context.selectionSource))));
    if (!hasEngagementCtx) return;

    ws = ws || { target: 'target' };
    var h = 'host:' + ws.target;
    var existing = (ws.facts || ws.seedFacts || []);

    function alreadyHeld(kind, scopeCheck) {
      for (var j = 0; j < facts.length; j++) {
        if (facts[j] && facts[j].kind === kind && (!scopeCheck || facts[j].scope === scopeCheck)) return true;
      }
      for (var i = 0; i < existing.length; i++) {
        var ef = existing[i];
        if (ef && ef.state === 'supported' && ef.kind === kind && (!scopeCheck || ef.scope === scopeCheck)) return true;
      }
      return false;
    }
    function ensureFact(kind, scope, val) {
      if (alreadyHeld(kind, scope)) return;
      _add(facts, mkFact(kind, scope, Object.assign({ via: 'causal-entailment' }, val || {}), S, source));
    }
    function resolveEntailedPort(proto, defaultPort, svcMatchRe, factVal) {
      if (factVal && Number(factVal.port) > 0) return Number(factVal.port);
      var allFacts = facts.concat(existing);
      for (var pi = 0; pi < allFacts.length; pi++) {
        var pf = allFacts[pi];
        if (!pf || pf.state !== 'supported' || pf.scope !== h) continue;
        if ((pf.kind === proto + '.reachable' || pf.kind === 'service.' + proto) && pf.value && Number(pf.value.port) > 0) {
          return Number(pf.value.port);
        }
      }
      for (var pti = 0; pti < allFacts.length; pti++) {
        var ptf = allFacts[pti];
        if (!ptf || ptf.state !== 'supported' || ptf.scope !== h || !/^port:\d+$/.test(ptf.kind || '')) continue;
        if (ptf.value && svcMatchRe.test(String(ptf.value.service || ''))) {
          var pNum = Number(ptf.value.port) || parseInt(ptf.kind.slice(5), 10);
          if (pNum > 0) return pNum;
        }
      }
      var cmdStr = String(command || '');
      if (cmdStr) {
        var uriPm = new RegExp('\\b' + proto + ':\\/\\/[^/\\s"\':]+:(\\d{1,5})\\b', 'i').exec(cmdStr);
        if (uriPm && Number(uriPm[1]) > 0 && Number(uriPm[1]) <= 65535) return Number(uriPm[1]);
        if (proto === 'ftp') {
          var ftpPm = /\bftp(?:-ssl)?\s+(?:-[A-Za-z]+\s+)*\S+\s+(\d{2,5})\b/i.exec(cmdStr)
            || /\blftp\b[^\r\n]*?\s-p\s*(\d{1,5})\b/i.exec(cmdStr);
          if (ftpPm && Number(ftpPm[1]) > 0 && Number(ftpPm[1]) <= 65535) return Number(ftpPm[1]);
        } else if (proto === 'ssh') {
          var sshPm = /\bssh\b[^\r\n]*?\s-p\s*(\d{1,5})\b/i.exec(cmdStr);
          if (sshPm && Number(sshPm[1]) > 0 && Number(sshPm[1]) <= 65535) return Number(sshPm[1]);
        } else if (proto === 'winrm') {
          var winrmPm = /\bevil-winrm\b[^\r\n]*?\s-P\s*(\d{1,5})\b/i.exec(cmdStr);
          if (winrmPm && Number(winrmPm[1]) > 0 && Number(winrmPm[1]) <= 65535) return Number(winrmPm[1]);
        }
      }
      return defaultPort;
    }
    var isFtpOnlyEntCmd = /\bftp:\/\/[^\s'"]+/i.test(command || '')
      && !/\bhttps?:\/\/[^\s'"]+/i.test(command || '')
      && !/^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(text || '');

    var isKnownLinuxHost = facts.concat(existing).some(function (ef) {
      if (!ef || ef.state !== 'supported' || ef.scope !== h) return false;
      return ef.kind === 'foothold.linux' || ef.kind === 'access.root'
        || (ef.kind === 'host.os_family' && ef.value && String(ef.value.family || '').toLowerCase() === 'linux');
    });

    // Discover domain FQDN from facts, command semantics, LDAP DNs, or UPNs so out-of-order AD
    // commands (kerbrute -d corp.local, GetNPUsers corp.local/, secretsdump) never land in an
    // unlinked `domain:corp.local` scope that store.factSetForTarget drops.
    var inferredDomain = '';
    for (var di = 0; di < facts.length; di++) {
      var df = facts[di];
      if (!df) continue;
      if (df.scope && df.scope.indexOf('domain:') === 0) {
        var dCand = df.scope.slice(7).trim();
        if (dCand && dCand !== 'domain' && dCand.indexOf('.') > 0) { inferredDomain = dCand.toLowerCase(); break; }
      }
      if (df.value && df.value.domain && String(df.value.domain).indexOf('.') > 0) {
        inferredDomain = String(df.value.domain).trim().toLowerCase();
        break;
      }
    }
    if (!inferredDomain && !isKnownLinuxHost && ws.domainSeed && String(ws.domainSeed).indexOf('.') > 0) {
      inferredDomain = String(ws.domainSeed).trim().toLowerCase();
    }
    if (!inferredDomain && !isKnownLinuxHost && command) {
      var cmdSemEnt = _extract_command_semantics(command, ws);
      if (cmdSemEnt.inputDomain && cmdSemEnt.inputDomain.indexOf('.') > 0) {
        inferredDomain = cmdSemEnt.inputDomain.toLowerCase();
      }
    }
    if (!inferredDomain && !isKnownLinuxHost && text) {
      var dcM = /\bDC=([A-Za-z0-9_-]+)\s*,\s*DC=([A-Za-z0-9_-]+)(?:\s*,\s*DC=([A-Za-z0-9_-]+))?/i.exec(text);
      if (dcM) {
        inferredDomain = [dcM[1], dcM[2], dcM[3]].filter(Boolean).join('.').toLowerCase();
      }
    }

    var isWebOrRemoteCmd = /\b(?:curl|wget|httpie|whatweb|httpx|nuclei|wpscan|dirb|dirsearch|wfuzz|sqlmap|nmap|masscan|rustscan|ffuf|gobuster|feroxbuster|nikto|snmpwalk|snmpbulkwalk|searchsploit)\b/i.test(command || '')
      || /^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(text || '')
      || /<!doctype\s+html|<\/?(?:html|head|body|pre)\b|<\?(?:php|=)|<%@?\s|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/i.test(text || '')
      || (!command && facts.some(function (sf) { return sf && sf.state === 'supported' && /^web\.(?:source_disclosed|vuln_sink|manifest_disclosed)$/.test(sf.kind || ''); }));

    var hasDbOrMd5EntCtx = isKnownLinuxHost || isWebOrRemoteCmd
      || /\b(?:SELECT\s+[\s\S]{1,160}?\bFROM\b|INSERT\s+INTO\b|mysql|mariadb|postgres|psql|sqlite3?|phpmyadmin|wp_users|md5sum|\bmd5\s*\()/i.test((command || '') + '\n' + (text || ''))
      || facts.some(function (sf) {
        return sf && (sf.kind === 'db.hashes' || sf.kind === 'db.creds'
          || (sf.kind === 'credential.candidate' && sf.value && sf.value.kind === 'database_hash')
          || (sf.kind === 'hash.crackable' && sf.value && /md5/i.test(String(sf.value.format || sf.value.hash_type || ''))));
      });
    var hasWinOrAdEntCtx = !isKnownLinuxHost && facts.concat(existing).some(function (ef) {
      if (!ef || ef.state !== 'supported') return false;
      return /^(?:foothold\.windows|access\.system|ad\.|adcs\.|smb\.authenticated|winrm\.authenticated|hash\.(?:ntlm|tgs|asrep|mscache|krbtgt)|credential\.ntlm_hash)$/.test(ef.kind || '')
        || (ef.kind === 'host.os_family' && ef.value && String(ef.value.family || '').toLowerCase() === 'windows');
    });
    var entAllowBare32HexNtlm = Boolean(hasWinOrAdEntCtx && !hasDbOrMd5EntCtx);

    var hasAdEvidence = false;
    var snapshot = facts.slice();
    for (var i = 0; i < snapshot.length; i++) {
      var f = snapshot[i];
      if (!f || f.state !== 'supported') continue;
      if (f.scope === 'domain:domain' || f.scope === 'domain:') {
        f.scope = (inferredDomain && !isKnownLinuxHost) ? ('domain:' + inferredDomain) : h;
      } else if (inferredDomain && !isKnownLinuxHost && f.scope === h && /^(?:ad\.|adcs\.|hash\.(?:tgs|asrep|krbtgt)|loot\.ntds)/.test(f.kind || '')) {
        f.scope = 'domain:' + inferredDomain;
      }
      var k = f.kind || '';
      var v = f.value || {};

      // Promote inferred/shaped credential.candidate facts with user+secret into credential.available / hash.*
      if (k === 'credential.candidate' && (v.user || v.hash) && (v.password || v.nthash || v.hash)) {
        _emit_credential_facts(facts, h, v, source, entAllowBare32HexNtlm);
      }

      // 1. Positive Progress Entailments
      if (/^smb\.(?:shares|readable_share|writable_share|authenticated|null_session|guest_session|ms17_010)$/.test(k)) {
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('port:445', h, { port: 445, protocol: 'tcp', service: 'microsoft-ds' });
        ensureFact('smb.reachable', h, { port: 445 });
      }
      else if (/^(?:ad\.|adcs\.|hash\.(?:tgs|asrep|krbtgt)|ldap\.authenticated|kerberos\.tickets|loot\.ntds)/.test(k)) {
        ensureFact('host.up', h, { target: ws.target });
        var isWorkgroupSmb = false;
        if (text) {
          var wgEntM = /\(name:([^)\r\n]+)\)\s*\(domain:([^)\r\n]+)\)/i.exec(text);
          if (wgEntM && (wgEntM[1].trim().toLowerCase() === wgEntM[2].trim().toLowerCase() || /^workgroup$/i.test(wgEntM[2].trim()))) {
            isWorkgroupSmb = true;
          }
        }
        var isNonDcUserEnum = isWorkgroupSmb || ((k === 'ad.user_list') && (
          /^(?:rid|smb-rid|samr|rpc|snmp|enum4linux)$/i.test(String(v.method || v.via || ''))
          || (/\b(?:rpcclient|lookupsid|samrdump|enum4linux|snmpwalk)\b/i.test(command || '') && !/\b(?:ldap|kerbrute|getuserspns|getnpusers)\b/i.test(command || ''))
        ));
        if (isNonDcUserEnum && !/\bsnmp/i.test(String(v.method || command || ''))) {
          ensureFact('port:445', h, { port: 445, protocol: 'tcp', service: 'microsoft-ds' });
          ensureFact('smb.reachable', h, { port: 445 });
        } else if (!isKnownLinuxHost && !isNonDcUserEnum) {
          hasAdEvidence = true;
          ensureFact('ldap.reachable', h, { port: 389 });
          ensureFact('kerberos.reachable', h, { port: 88 });
          ensureFact('ad.dc_candidate', h, { ports: [88, 389, 445] });
          if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
            C._add_os_observation(facts, ws, source, 'windows', 'Entailed by Active Directory evidence', 'high', 'entailment', true);
          }
        }
      }
      else if (/^web\.|^http\.reachable$|^vuln\.(?:shellshock|drupalgeddon2|phpmyadmin_lfi|webmin|cacti|zabbix|ofbiz|solr|web_sink)/.test(k)) {
        ensureFact('host.up', h, { target: ws.target });
        if (isFtpOnlyEntCmd && k !== 'http.reachable') {
          var ftpWebPort = resolveEntailedPort('ftp', 21, /^ftp\b/i, v);
          ensureFact('port:' + ftpWebPort, h, { port: ftpWebPort, protocol: 'tcp', service: 'ftp' });
          ensureFact('ftp.reachable', h, { port: ftpWebPort });
        } else {
          ensureFact('http.reachable', h, {});
        }
      }
      else if (k === 'winrm.authenticated') {
        var winrmPort = resolveEntailedPort('winrm', 5985, /^(?:wsman|winrm|httpapi)\b/i, v);
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('port:' + winrmPort, h, { port: winrmPort, protocol: 'tcp', service: 'wsman' });
        ensureFact('winrm.reachable', h, { port: winrmPort });
        if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
          C._add_os_observation(facts, ws, source, 'windows', 'Entailed by WinRM authentication', 'high', 'entailment', true);
        }
      }
      else if (k === 'ssh.authenticated' || k === 'ssh.banner' || k === 'ssh.hostkey') {
        var sshPort = resolveEntailedPort('ssh', 22, /^ssh\b/i, v);
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('port:' + sshPort, h, { port: sshPort, protocol: 'tcp', service: 'ssh' });
        ensureFact('ssh.reachable', h, { port: sshPort });
      }
      else if (k === 'ftp.authenticated' || k === 'ftp.anonymous_login' || k === 'ftp.banner') {
        var ftpPort = resolveEntailedPort('ftp', 21, /^ftp\b/i, v);
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('port:' + ftpPort, h, { port: ftpPort, protocol: 'tcp', service: 'ftp' });
        ensureFact('ftp.reachable', h, { port: ftpPort });
      }
      else if (/^db\./.test(k)) {
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('db.reachable', h, {});
      }
      else if (k === 'access.root') {
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('foothold.linux', h, { method: 'entailed-by-root' });
        ensureFact('access.admin', h, { identity: 'root', method: 'entailed-by-root' });
        if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
          C._add_os_observation(facts, ws, source, 'linux', 'Entailed by Linux root access', 'high', 'entailment', true);
        }
      }
      else if (k === 'access.system') {
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('foothold.windows', h, { method: 'entailed-by-system' });
        ensureFact('access.admin', h, { identity: 'SYSTEM', method: 'entailed-by-system' });
        if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
          C._add_os_observation(facts, ws, source, 'windows', 'Entailed by Windows SYSTEM access', 'high', 'entailment', true);
        }
      }
      else if (/^privesc\.(?:sudo|sudo_rights|sudo_binary|script_sink|suid|suid_candidate|capabilities|capability|cron|cron_writable|cron_wildcard|writable_etc|passwd_writable|PATH|ld_preload|docker|docker_group|lxd|lxd_group|group_lxd|container_group)$/.test(k) && !isWebOrRemoteCmd) {
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('foothold.linux', h, { method: 'entailed-by-privesc' });
        if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
          C._add_os_observation(facts, ws, source, 'linux', 'Entailed by Linux local privilege enumeration', 'high', 'entailment', true);
        }
      }
      else if (k === 'privesc.privileged_group' && !isWebOrRemoteCmd) {
        ensureFact('host.up', h, { target: ws.target });
        var privGrpText = JSON.stringify(v || {});
        var isWinPrivGrp = v.os === 'windows'
          || alreadyHeld('foothold.windows', h)
          || /\b(?:Backup Operators|Server Operators|Print Operators|Account Operators|DnsAdmins|Hyper-V Administrators|Cryptographic Operators|Network Configuration Operators|Remote Management Users|Event Log Readers|Exchange Windows Permissions|Organization Management|BUILTIN\\)\b/i.test(privGrpText)
          || (!isKnownLinuxHost && facts.some(function (f) { return f && f.kind === 'host.os_family' && f.scope === h && f.value && String(f.value.family || '').toLowerCase() === 'windows'; }));
        if (isWinPrivGrp && !isKnownLinuxHost) {
          ensureFact('foothold.windows', h, { method: 'entailed-by-privesc' });
          if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
            C._add_os_observation(facts, ws, source, 'windows', 'Entailed by Windows privileged group membership', 'high', 'entailment', true);
          }
        } else {
          ensureFact('foothold.linux', h, { method: 'entailed-by-privesc' });
          if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
            C._add_os_observation(facts, ws, source, 'linux', 'Entailed by Linux privileged group membership', 'high', 'entailment', true);
          }
        }
      }
      else if (/^privesc\.(?:windows_privilege|unquoted_service|unquoted_service_path|weak_service_permission|always_install_elevated|autologon|autorun|scheduled_task|stored_creds|stored_credentials|dll_hijack_candidate|patch_gap|sebackup|serestore|semanagevolume|wsl|wsus)$/.test(k) && !isWebOrRemoteCmd) {
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('foothold.windows', h, { method: 'entailed-by-privesc' });
        if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
          C._add_os_observation(facts, ws, source, 'windows', 'Entailed by Windows local privilege enumeration', 'high', 'entailment', true);
        }
      }
      else if (/^privesc\.(?:custom_binary|path_hijack_candidate|library_or_script_hijack)$/.test(k) && !isWebOrRemoteCmd) {
        ensureFact('host.up', h, { target: ws.target });
        var isWinArtifact = v.os === 'windows'
          || alreadyHeld('foothold.windows', h)
          || /^[A-Za-z]:\\|\.(?:dll|ps1|bat|cmd|vbs|exe)$/i.test(String(v.path || v.via_binary || v.target || v.hijack_bin || ''))
          || /\b(?:Process\.Start|ProcessStartInfo|DllImport|LoadLibrary|ilspycmd)\b/i.test(String(v.call || command || text || ''));
        if (isWinArtifact && !isKnownLinuxHost) {
          ensureFact('foothold.windows', h, { method: 'entailed-by-privesc' });
          if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
            C._add_os_observation(facts, ws, source, 'windows', 'Entailed by Windows custom binary triage', 'high', 'entailment', true);
          }
        } else {
          ensureFact('foothold.linux', h, { method: 'entailed-by-privesc' });
          if (!alreadyHeld('host.os_family', h) && C._add_os_observation) {
            C._add_os_observation(facts, ws, source, 'linux', 'Entailed by Linux custom binary triage', 'high', 'entailment', true);
          }
        }
      }

      // 2. Protocol-Rejection Entailment
      else if (k === 'ssh.key_rejected') {
        var sshRejPort = resolveEntailedPort('ssh', 22, /^ssh\b/i, v);
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('port:' + sshRejPort, h, { port: sshRejPort, protocol: 'tcp', service: 'ssh' });
        ensureFact('ssh.reachable', h, { port: sshRejPort });
      }
      else if (k === 'blocker.ldap_anonymous_disabled') {
        hasAdEvidence = true;
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('port:389', h, { port: 389, protocol: 'tcp', service: 'ldap' });
        ensureFact('ldap.reachable', h, { port: 389 });
        ensureFact('ad.dc_candidate', h, { ports: [389] });
      }
      else if (k === 'blocker.clock_skew' || k === 'blocker.kerberos_spn' || k === 'blocker.protected_users') {
        hasAdEvidence = true;
        ensureFact('host.up', h, { target: ws.target });
        ensureFact('port:88', h, { port: 88, protocol: 'tcp', service: 'kerberos-sec' });
        ensureFact('kerberos.reachable', h, { port: 88 });
        ensureFact('ad.dc_candidate', h, { ports: [88] });
      }
      else if ((k === 'blocker.logon_failure' || k === 'blocker.access_denied' || k === 'blocker.password_restriction') && !isWebOrRemoteCmd) {
        var svc = String(v.service || (ws.context && ws.context.service) || '').toLowerCase();
        if (!svc) {
          if (/STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED|0xc000006d|0xc0000022/i.test(text || '')) svc = 'smb';
          else if (/ERROR 1045|MySQL|MariaDB/i.test(text || '')) svc = 'mysql';
          else if (/LdapErr|LDAP/i.test(text || '')) svc = 'ldap';
        }
        if (svc === 'smb') {
          ensureFact('host.up', h, { target: ws.target });
          ensureFact('port:445', h, { port: 445, protocol: 'tcp', service: 'microsoft-ds' });
          ensureFact('smb.reachable', h, { port: 445 });
        } else if (svc === 'ldap') {
          ensureFact('host.up', h, { target: ws.target });
          ensureFact('port:389', h, { port: 389, protocol: 'tcp', service: 'ldap' });
          ensureFact('ldap.reachable', h, { port: 389 });
        } else if (svc === 'winrm') {
          var winrmBlkPort = resolveEntailedPort('winrm', 5985, /^(?:wsman|winrm|httpapi)\b/i, v);
          ensureFact('host.up', h, { target: ws.target });
          ensureFact('port:' + winrmBlkPort, h, { port: winrmBlkPort, protocol: 'tcp', service: 'wsman' });
          ensureFact('winrm.reachable', h, { port: winrmBlkPort });
        } else if (svc === 'ssh') {
          var sshBlkPort = resolveEntailedPort('ssh', 22, /^ssh\b/i, v);
          ensureFact('host.up', h, { target: ws.target });
          ensureFact('port:' + sshBlkPort, h, { port: sshBlkPort, protocol: 'tcp', service: 'ssh' });
          ensureFact('ssh.reachable', h, { port: sshBlkPort });
        } else if (svc === 'ftp') {
          var ftpBlkPort = resolveEntailedPort('ftp', 21, /^ftp\b/i, v);
          ensureFact('host.up', h, { target: ws.target });
          ensureFact('port:' + ftpBlkPort, h, { port: ftpBlkPort, protocol: 'tcp', service: 'ftp' });
          ensureFact('ftp.reachable', h, { port: ftpBlkPort });
        } else if (svc === 'mysql' || svc === 'mssql' || svc === 'psql') {
          ensureFact('host.up', h, { target: ws.target });
          ensureFact('db.reachable', h, { engine: svc });
        }
      }
    }

    // 3. Domain Linkage Entailment (Ensures store.factSetForTarget links domain:<fqdn> to host:<target>)
    if (inferredDomain && !isKnownLinuxHost && (hasAdEvidence || facts.some(function (f) { return f && f.scope === 'domain:' + inferredDomain; }))) {
      var dScope = 'domain:' + inferredDomain;
      ensureFact('host.domain', h, { domain: inferredDomain });
      ensureFact('ad.domain_known', dScope, { name: inferredDomain, domain: inferredDomain });
      var baseDn = 'DC=' + inferredDomain.split('.').join(',DC=');
      ensureFact('ad.base_dn', dScope, { base_dn: baseDn, domain: inferredDomain });
    }
  }
  C._apply_causal_entailment = _apply_causal_entailment;

  OBOL.inference = {
    extractPromptTelemetry: _extract_prompt_telemetry,
    extractCommandSemantics: _extract_command_semantics,
    computeWrapperDelta: _compute_wrapper_delta,
    parseDynamicTables: _parse_dynamic_tables,
    groupKvBlocks: _group_kv_blocks,
    findOutliers: _find_statistical_outliers,
    extractAtoms: _extract_atoms,
    matchCatalogMove: _match_catalog_move,
    infer: _parse_inference,
    entail: _apply_causal_entailment
  };

})(typeof globalThis !== 'undefined' ? globalThis : this);
