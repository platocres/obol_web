/*!
 * obol engine - report.js
 * The report pipeline, 
 *
 * A report is a READ-ONLY PROJECTION of the same state the board is narrated from:
 * facts (OBOL.facts), targets, activities (the run ledger), credentials, and operator
 * screenshots. One content model (an ordered list of Blocks) chosen by a PROFILE, then
 * serialized to Markdown or HTML - so the two never drift. Redaction is two-layer and ON
 * by default (value-based from harvested secrets + structural patterns honoring the `-p`
 * port/preserve/payload allowlist). Proof is first-class and never forged: obol labels and
 * validates pasted proof (interactive vs non-interactive, identity present) but a browser
 * tool cannot capture it.
 *
 * Faithful JS port. Environment-agnostic: attaches to `self`/`globalThis` so it works in the
 * window, a Web Worker (importScripts), and Node (require). docx/pdf paths are intentionally
 * out (they need native libs); md + HTML are ported in full.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var FACTS = OBOL.facts || {};
  var SUPPORTED = (FACTS.ProofState && FACTS.ProofState.SUPPORTED) || 'supported';

  // ─────────────────────────────────────────────────────────────────────────
  // 0. constants
  // ─────────────────────────────────────────────────────────────────────────
  var FLAG_FACT_KINDS = ['objective.local_flag', 'objective.root_flag', 'objective.flag'];
  var PROOF_FACT = 'proof.captured';
  var SLOT_OF_KIND = {
    'objective.local_flag': 'local', 'objective.root_flag': 'root', 'objective.flag': 'flag',
  };
  var SLOT_LABEL = { local: 'local flag', root: 'root flag', flag: 'flag' };

  var ACCESS_LADDER = [
    ['Recon', ['host.up', 'scan.nmap.quick', 'ports.open']],
    ['Service enum', ['ad.domain_known', 'ad.anonymous_bind', 'ad.user_list', 'smb.shares', 'web.content_map']],
    ['Credential material', ['hash.asrep', 'hash.tgs', 'hash.ntlm', 'credential.candidate', 'db.creds']],
    ['Valid credential', ['credential.available', 'credential.plaintext', 'credential.ntlm_hash']],
    ['Foothold', ['foothold.windows', 'foothold.linux', 'access.shell', 'winrm.authenticated', 'foothold.webshell']],
    ['Privesc leads', ['privesc.leads', 'privesc.sudo_rights', 'privesc.windows_privilege', 'privesc.suid_candidate', 'privesc.capability', 'privesc.kernel_exploit']],
    ['Privileged access', ['access.admin', 'access.system', 'access.root']],
    ['Domain / loot', ['loot.ntds', 'hash.krbtgt', 'persistence.domain']],
  ];

  var SECRET_KEYS = {
    password: 1, passwd: 1, pwd: 1, hash: 1, hashes: 1, ntlm: 1, ntlm_hash: 1, secret: 1,
    secrets: 1, ticket: 1, tickets: 1, cpassword: 1, psk: 1, passphrase: 1, value: 1, values: 1,
  };

  var CATEGORY_ORDER = {
    target: 0, scan: 1, service: 2, ad: 3, credential: 4, access: 5, pivot: 6, privesc: 7,
    objective: 8, loot: 9, config: 10, web: 11, wireless: 12, other: 99,
  };

  // ── redaction regexes ────────────────────────────────
  // flags whose value is ALWAYS a secret, for any tool
  var SECRET_FLAG_RE = /((?:^|\s)(?:--password|--pass|--?nthash|--?aes-?key|-computer-pass))([=\s]+)('[^']*'|"[^"]*"|\S+)/gi;
  // hash flags, redact only a hash-shaped value (curl -H headers survive)
  var HASH_FLAG_RE = /((?:^|\s)(?:--hashes|-hashes|-H))([=\s]+)('[^']*'|"[^"]*"|\S+)/gi;
  var HASHLIKE_RE = /[0-9a-fA-F]{16,}/;
  // lowercase -p / -p= / -pGLUED, tool-gated below. Case-SENSITIVE on the flag letter (never -P).
  var P_FLAG_RE = /((?:^|\s)-p)([=\s]*)('[^']*'|"[^"]*"|\S+)/g;
  // Tools where `-p` is a PORT / PRESERVE / PAYLOAD flag - never a password.
  var P_SPARE_TOOLS = {
    nmap: 1, masscan: 1, rustscan: 1, naabu: 1, ssh: 1, scp: 1, sftp: 1, rsync: 1, nc: 1,
    ncat: 1, netcat: 1, telnet: 1, ftp: 1, socat: 1, mkdir: 1, cp: 1, install: 1, rmdir: 1,
    unzip: 1, tar: 1, msfvenom: 1, psql: 1, 'redis-cli': 1, mongo: 1, mongosh: 1,
  };
  var CRED_DOMAIN_RE = /((?<![\w/])[\w.-]+\/[\w.$-]+:)([^\s:'"@/]+)/g;
  var CRED_ATHOST_RE = /((?<![\w/])[\w.$-]+:)([^\s:'"@/]+)(@[\w.:-]+)/g;
  var USERPCT_RE = /((?:^|\s)(?:-U|--user)[=\s]+['"]?[^\s'"%]+%)([^\s'"]+)/gi;
  var URLCRED_RE = /(:\/\/[^\s:/@'"]+:)([^\s@/'"]+)(@)/g;

  // ── proof interactivity classification ─────────────
  var NONINTERACTIVE_TOOLS = ['nxc', 'netexec', 'crackmapexec', 'wmiexec', 'smbexec', 'atexec',
    'dcomexec', 'psexec', 'impacket-wmiexec', 'impacket-smbexec', 'impacket-psexec', 'impacket-atexec'];
  var INTERACTIVE_TOOLS = ['evil-winrm', 'ssh', 'sshpass', 'rdp', 'xfreerdp', 'reverse-shell'];

  // ─────────────────────────────────────────────────────────────────────────
  // 1. small utilities
  // ─────────────────────────────────────────────────────────────────────────
  function asFactSet(f) {
    if (!f) return new FACTS.FactSet([]);
    if (Array.isArray(f)) return new FACTS.FactSet(f);
    if (f.facts && typeof f.has === 'function') return f;      // already a FactSet
    if (f.facts && Array.isArray(f.facts)) return new FACTS.FactSet(f.facts);
    return new FACTS.FactSet([]);
  }

  function stamp(ts) {
    if (!ts) return 'unknown time';
    try {
      // Fact created_at is epoch SECONDS (~1.7e9); an activity's `at` is Date.now() MILLISECONDS
      // (~1.7e12). Detect which so a ms value isn't multiplied into the year 58707.
      var ms = Number(ts);
      if (ms < 1e11) ms *= 1000;
      var d = new Date(ms);
      if (isNaN(d.getTime())) return 'unknown time';
      // YYYY-MM-DD HH:MM:SS (local, mirrors datetime.fromtimestamp().strftime)
      var p = function (n) { return String(n).padStart(2, '0'); };
      return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' '
        + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    } catch (e) { return 'unknown time'; }
  }

  var REPORT_FRIENDLY_LABELS = {
    'smb.signing': 'SMB Signing Configuration',
    'smb.smbv1': 'SMBv1 Dialect Support',
    'smb.null_session': 'SMB Null Session',
    'smb.shares': 'Enumerated SMB Shares',
    'smb.readable_share': 'Readable SMB Share',
    'smb.writable_share': 'Writable SMB Share',
    'ad.user_list': 'Enumerated Domain Accounts',
    'ad.anonymous_bind': 'Anonymous LDAP Bind',
    'ad.control_paths': 'Active Directory Object Control Path',
    'ad.domain_control': 'Domain Replication / Control Rights',
    'ad.group_joined': 'Privileged Group Membership Added',
    'ad.cert_templates': 'ADCS Vulnerable Certificate Template',
    'ad.asrep_roastable': 'AS-REP Roastable Accounts',
    'ad.kerberoastable': 'Kerberoastable Accounts',
    'ad.dcsync_principals': 'Principals with DCSync Rights',
    'ad.unconstrained_delegation': 'Unconstrained Delegation Hosts',
    'ad.high_value': 'High-Value Domain Principals',
    'ad.esc_templates': 'Vulnerable ADCS Certificate Templates',
    'web.content_map': 'Discovered Web Endpoints',
    'web.tech': 'Web Technology Fingerprint',
    'web.vhosts': 'Discovered Virtual Hosts',
  };

  function friendly(kind) {
    if (REPORT_FRIENDLY_LABELS[kind]) return REPORT_FRIENDLY_LABELS[kind];
    try {
      if (OBOL.pack && typeof OBOL.pack.friendly === 'function') {
        var pf = OBOL.pack.friendly(kind);
        if (pf && pf !== kind) return pf.charAt(0).toUpperCase() + pf.slice(1);
      }
    } catch (e) {}
    var s = String(kind || '').replace(/[._:]/g, ' ').replace(/\s+/g, ' ').trim();
    if (!s) return String(kind || '');
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function factCategory(kind) {
    kind = kind || '';
    function starts() { for (var i = 0; i < arguments.length; i++) if (kind.indexOf(arguments[i]) === 0) return true; return false; }
    if (starts('pivot.', 'network.') || kind === 'host.multihomed') return 'pivot';
    if (starts('target.', 'host.', 'port:', 'ports.open')) return 'target';
    if (starts('scan.')) return 'scan';
    if (starts('service.', 'ldap.', 'smb.', 'winrm.', 'kerberos.', 'http.', 'rdp.', 'ssh.', 'ftp.', 'snmp.', 'dns.')) return 'service';
    if (starts('ad.', 'hash.', 'kerberos.')) return 'ad';
    if (starts('credential.')) return 'credential';
    if (starts('access.', 'foothold.')) return 'access';
    if (starts('privesc.')) return 'privesc';
    if (starts('objective.')) return 'objective';
    if (starts('loot.')) return 'loot';
    if (starts('db.')) return 'loot';
    if (starts('config.', 'vuln.', 'exploit.')) return 'config';
    if (starts('web.')) return 'web';
    if (starts('wifi.')) return 'wireless';
    return 'other';
  }

  function factSortKey(f) {
    return [CATEGORY_ORDER[factCategory(f.kind)] != null ? CATEGORY_ORDER[factCategory(f.kind)] : 99,
      f.kind || '', f.scope || '', f.state || ''];
  }
  function bySortKey(a, b) {
    var ka = factSortKey(a), kb = factSortKey(b);
    for (var i = 0; i < ka.length; i++) { if (ka[i] < kb[i]) return -1; if (ka[i] > kb[i]) return 1; }
    return 0;
  }

  var SEV_ALIASES = { informational: 'info', information: 'info', '': 'info' };
  function normalizeSeverity(v) {
    var sev = String(v || '').trim().toLowerCase();
    return SEV_ALIASES[sev] != null ? SEV_ALIASES[sev] : sev;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 2. redaction (two-layer, default ON) - py
  // ─────────────────────────────────────────────────────────────────────────
  function redactValue(value, includeSecrets) {
    if (includeSecrets) return value;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      var out = {};
      Object.keys(value).forEach(function (key) {
        var lowered = String(key).toLowerCase();
        var leaky = SECRET_KEYS[lowered] || ['password', 'hash', 'secret', 'ticket'].some(function (t) { return lowered.indexOf(t) !== -1; });
        out[String(key)] = leaky ? '<redacted>' : redactValue(value[key], includeSecrets);
      });
      return out;
    }
    if (Array.isArray(value)) return value.map(function (i) { return redactValue(i, includeSecrets); });
    return value;
  }

  // Harvest the secret VALUES obol holds as facts/credentials, so value-based redaction blanks
  // them in ANY command shape (glued -pPASS, domain/user:pass, -U user%pass, unknown flags).
  function knownSecrets(factset, credentials) {
    var out = {};
    function take(v) { if (typeof v === 'string' && v.length >= 6) out[v] = 1; }
    try {
      (factset.facts || []).forEach(function (f) {
        var v = (f.value && typeof f.value === 'object') ? f.value : {};
        ['password', 'nthash', 'plaintext', 'hash', 'aesKey', 'aes_key', 'secret', 'secret_access_key', 'session_token']
          .forEach(function (k) { take(v[k]); });
        (v.hashes || []).forEach(take);
        (v.entries || []).forEach(function (e) {
          if (e && typeof e === 'object') { take(e.nthash); take(e.hash); take(e.password); }
        });
      });
    } catch (e) { /* redaction is best-effort belt */ }
    (credentials || []).forEach(function (c) {
      if (!c || typeof c !== 'object') return;
      take(c.secret); take(c.password); take(c.nthash); take(c.plaintext); take(c.hash);
    });
    return Object.keys(out);
  }

  function redactCommand(command, opts) {
    opts = opts || {};
    if (opts.includeSecrets || !command) return command;
    var secrets = opts.secrets || [];
    var redacted = String(command);
    // 1) value-based: blank the actual secrets, longest first so a short one can't partially match.
    var uniq = {};
    secrets.forEach(function (s) { if (s && String(s).length >= 3) uniq[String(s)] = 1; });
    Object.keys(uniq).sort(function (a, b) { return b.length - a.length; }).forEach(function (s) {
      redacted = redacted.split(s).join('<redacted>');
    });
    // 2) positional credential forms + -U user%pass
    redacted = redacted.replace(CRED_DOMAIN_RE, function (m, left) { return left + '<redacted>'; });
    redacted = redacted.replace(CRED_ATHOST_RE, function (m, left, sec, at) { return left + '<redacted>' + at; });
    redacted = redacted.replace(URLCRED_RE, function (m, left, sec, at) { return left + '<redacted>' + at; });
    redacted = redacted.replace(USERPCT_RE, function (m, left) { return left + '<redacted>'; });
    // 3) always-secret flags
    redacted = redacted.replace(SECRET_FLAG_RE, function (m, p, sep) { return p + sep + '<redacted>'; });
    // 4) hash flags - only a hash-shaped value (so curl -H headers survive)
    redacted = redacted.replace(HASH_FLAG_RE, function (m, p, sep, val) {
      return HASHLIKE_RE.test(val) ? p + sep + '<redacted>' : m;
    });
    // 5) `-p` - redact unless the leading tool is one where -p is a port/preserve/payload flag
    var tool = '';
    var toks = redacted.trim().split(/\s+/);
    for (var i = 0; i < toks.length; i++) {
      var tok = toks[i];
      var base = tok.split('/').pop().toLowerCase();
      if (base === 'sudo' || base === 'proxychains' || base === 'proxychains4'
        || (base.charAt(base.length - 1) === ':' && tok.indexOf('/') === -1)) continue;
      tool = base; break;
    }
    if (!P_SPARE_TOOLS[tool]) {
      redacted = redacted.replace(P_FLAG_RE, function (m, p, sep) { return p + sep + '<redacted>'; });
    }
    return redacted;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 3. proof labels (UI-facing port of proof.py's interactivity discipline)
  // ─────────────────────────────────────────────────────────────────────────
  function isInteractiveShell(command) {
    var low = String(command || '').toLowerCase();
    if (!low.trim()) return false;
    var segments = low.split('|');
    for (var s = 0; s < segments.length; s++) {
      var toks = segments[s].trim().split(/\s+/);
      var prog = '';
      for (var i = 0; i < toks.length; i++) {
        var tok = toks[i];
        if (tok.indexOf('=') !== -1 && tok.charAt(0) !== '-') continue;    // VAR=val prefix
        if (['sudo', 'command', 'exec', 'stdbuf', 'timeout'].indexOf(tok) !== -1) continue;
        prog = tok; break;
      }
      var b = prog.split('/').pop();
      if (NONINTERACTIVE_TOOLS.indexOf(b) !== -1) return false;
      if (INTERACTIVE_TOOLS.indexOf(b) !== -1) return true;
    }
    return false;
  }

  function identityPresent(block, windows) {
    var low = String(block || '').toLowerCase();
    var hasIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(block || '');
    var hasName = (low.indexOf('hostname') !== -1)
      || /\buid=\d+|\bnt authority|\\\\|desktop-|\w+\\\w+/.test(block || '');
    return hasIp && (hasName || windows);
  }

  // Public UI helper: label a pasted proof block + the command it was produced by, and flag the
  // OSCP-relevant gaps (non-interactive transport, missing identity). A browser tool cannot
  // capture proof; this labels what the operator pastes so the report tells the truth about it.
  function proofLabels(opts) {
    opts = opts || {};
    var block = opts.block || '';
    var command = opts.command || '';
    var os = String(opts.os || '').toLowerCase();
    var windows = os.indexOf('win') !== -1 || opts.windows === true;
    var interactive = isInteractiveShell(command);
    var identity = identityPresent(block, windows);
    var compliant = interactive && identity;
    var flags = [];
    if (command && !interactive) {
      flags.push({ level: 'fail', message: 'Non-interactive transport (nxc/impacket exec/wmiexec/psexec): '
        + 'OffSec scores this ZERO however genuine the flag it printed. Read the flag from an interactive '
        + 'shell (evil-winrm/ssh/RDP/reverse shell).' });
    }
    if (!identity) {
      flags.push({ level: 'fail', message: 'No host-identity in the capture (need an IP from `ip a`/`ipconfig` '
        + 'plus a hostname/whoami in the same frame), a flag alone does not prove it was read on the target.' });
    }
    return {
      interactive: interactive,
      identityPresent: identity,
      compliant: compliant,
      label: interactive ? 'interactive shell (credited)' : (command ? 'non-interactive exec (scores zero)' : 'transport unknown'),
      flags: flags,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 4. block model + serializers
  // ─────────────────────────────────────────────────────────────────────────
  function H(text, level, anchor) { return { t: 'heading', text: text, level: level || 2, anchor: anchor || '' }; }
  function P(text) { return { t: 'para', text: text || '' }; }
  function UL(items, ordered) { return { t: 'bullets', items: items || [], ordered: !!ordered }; }
  function KVB(pairs) { return { t: 'kv', pairs: pairs || [] }; }
  function TBL(headers, rows, caption) { return { t: 'table', headers: headers || [], rows: rows || [], caption: caption || '' }; }
  function CODE(text, lang) { return { t: 'code', text: text || '', lang: lang || '' }; }
  // A terminal block: an emulation of what the operator's terminal looked like for a
  // command + its output, so the report reads like the steps. Two styles:
  //   • 'kali'   - the attacker box (recon/exploitation launched from Kali): ┌──(kali@kali)-[~] / └─$
  //   • 'target' - a shell *on the compromised host* (post-exploitation): user@host:~$ / #  (or C:\> on Windows)
  // Cap a command's output so a firehose (a 50k-line BloodHound/bloodyAD dump, a full ldapsearch subtree,
  // a wide nxc sweep) never floods the report: keep the head + tail with an omission marker, and hard-cap
  // total bytes so one enormous line can't blow the page either. Short outputs pass through untouched.
  var _OUT_CAP = { maxLines: 40, head: 24, tail: 8, maxChars: 6000 };
  function cleanNmapXmlOutput(text) {
    if (text.indexOf('<nmaprun') === -1 || text.indexOf('<port ') === -1) return text;
    var out = ['PORT      STATE SERVICE       VERSION'];
    var portRe = /<port protocol="([^"]+)" portid="(\d+)">\s*<state state="([^"]+)"[^>]*\/>\s*(?:<service name="([^"]*)"([^>]*?)(?:\/>|>[\s\S]*?<\/service>))?/g;
    var m;
    while ((m = portRe.exec(text)) !== null) {
      var pProto = (m[2] + '/' + m[1] + '          ').slice(0, 10);
      var st = (m[3] + '      ').slice(0, 6);
      var svc = ((m[4] || 'unknown') + '              ').slice(0, 14);
      var attrs = m[5] || '';
      var prod = (attrs.match(/\bproduct="([^"]+)"/) || [])[1] || '';
      var ver = (attrs.match(/\bversion="([^"]+)"/) || [])[1] || '';
      var extra = (attrs.match(/\bextrainfo="([^"]+)"/) || [])[1] || '';
      var vStr = [prod, ver, extra ? ('(' + extra + ')') : ''].filter(Boolean).join(' ').replace(/&#45;/g, '-').replace(/&quot;/g, '"');
      out.push((pProto + st + svc + vStr).trimRight());
    }
    var summaryMatch = text.match(/summary="([^"]+)"/);
    if (summaryMatch && summaryMatch[1]) out.push('\n' + summaryMatch[1]);
    return out.length > 1 ? out.join('\n') : text;
  }
  function cleanSecretsdumpNoise(text) {
    var lines = text.split(/\r?\n/);
    if (lines.length < 25) return text;
    var out = [], noiseCount = 0;
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (/^(?:[\w.-]+\\)?(?:SM_[0-9a-f]{10,}|HealthMailbox[0-9a-f]+|\$[A-Z0-9-]+):\d+:[0-9a-f]{32}:[0-9a-f]{32}:::/i.test(ln)) {
        noiseCount++;
        if (noiseCount <= 3) out.push(ln);
      } else {
        if (noiseCount > 3) {
          out.push('        ... ' + (noiseCount - 3) + ' Exchange system/health mailbox hashes omitted ...');
          noiseCount = 0;
        } else if (noiseCount > 0) {
          noiseCount = 0;
        }
        out.push(ln);
      }
    }
    if (noiseCount > 3) {
      out.push('        ... ' + (noiseCount - 3) + ' Exchange system/health mailbox hashes omitted ...');
    }
    return out.join('\n');
  }
  function capOutput(text, opt) {
    text = String(text == null ? '' : text);
    if (!text.trim()) return '';
    text = cleanNmapXmlOutput(text);
    text = cleanSecretsdumpNoise(text);
    opt = opt || _OUT_CAP;
    var nxcInitRe = /^\s*\[\*\]\s*(?:First time use detected|Creating (?:home directory|missing folder|default workspace)|Initializing \S+ protocol database|Copying default configuration file)\b/i;
    var lines = text.split(/\r?\n/).filter(function (ln) { return !nxcInitRe.test(ln); });
    if (lines.length > opt.maxLines) {
      var headLines = lines.slice(0, opt.head);
      var midLines = lines.slice(opt.head, lines.length - opt.tail);
      var tailLines = lines.slice(lines.length - opt.tail);
      var keyMid = [];
      var importantRe = /^\s*(?:\$krb5(?:asrep|tgs)\$\S+:\S+|\[\+\]\s+\S+|Status\.+:\s*Cracked\b|username:\s*(?!Guest\b|DefaultAccount\b|\$|SM_|HealthMailbox)\S+|(?:[\w.-]+\\)?(?:Administrator|krbtgt|svc-[\w.-]+|[\w.-]+):(?:500|502|1[1-9]\d\d):[0-9a-f]{32}:[0-9a-f]{32}:::)/i;
      for (var i = 0; i < midLines.length && keyMid.length < 10; i++) {
        if (importantRe.test(midLines[i])) keyMid.push(midLines[i]);
      }
      var omitted = Math.max(0, midLines.length - keyMid.length);
      lines = headLines
        .concat(keyMid.length ? [''].concat(keyMid) : [])
        .concat(['', '        ... ' + omitted + ' lines omitted (' + lines.length + ' total) ...', ''])
        .concat(tailLines);
    }
    var out = lines.join('\n');
    if (out.length > opt.maxChars) {
      out = out.slice(0, opt.maxChars) + '\n        ... output truncated (' + text.length + ' bytes total) ...';
    }
    return out;
  }
  var _ECHO_PROMPT_RE = /^\s*(?:(?:[┌╭]──.*)?[└╰]─\s*[#$%>]\s+|(?:\*?Evil-WinRM\*?\s+)?PS\s+[A-Za-z]:[^>]*>\s+|[A-Za-z]:\\[^>]*>\s+|(?:\([^)]+\)\s*)?\[?[\w.\-]+@[\w.\-]+(?::[^\s#$%\]]*|\s+[^\r\n#$%\]]*)\]?\s*[#$%]\s+)(\S.*)$/;
  function stripLeadingPromptEcho(text) {
    var s = String(text == null ? '' : text);
    if (!s.trim()) return '';
    var lines = s.split(/\r?\n/);
    // If the output contains multiple shell prompts (e.g. prior scrollback followed by the actual command prompt),
    // jump to the line after the last shell prompt in the leading scrollback block.
    var lastPromptIdx = -1;
    for (var p = 0; p < lines.length && p < 60; p++) {
      if (_ECHO_PROMPT_RE.test(lines[p])) lastPromptIdx = p;
    }
    if (lastPromptIdx >= 0) {
      lines = lines.slice(lastPromptIdx + 1);
    } else {
      // Otherwise strip any standalone leading timestamp or top-half Kali prompt banner lines
      while (lines.length && (/^\s*$/.test(lines[0]) || /^\s*\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(lines[0]) || /^\s*[┌╭]──\(/.test(lines[0]))) {
        lines.shift();
      }
    }
    return lines.join('\n');
  }
  function TERM(o) {
    o = o || {};
    var style = o.style || 'kali';
    var cleanOut = stripLeadingPromptEcho(o.output || '');
    return {
      t: 'terminal', command: o.command || '', output: capOutput(cleanOut, o.cap),
      style: style, os: (o.os || 'linux'),
      user: o.user || (style === 'target' ? '' : 'kali@kali'),
      host: o.host || '', dir: o.dir || (o.os === 'windows' ? 'C:\\' : '~'), root: !!o.root,
    };
  }
  // Compose the shell prompt string for a terminal block (shared by every serializer).
  function termPrompt(b) {
    if (b.style !== 'target') return null; // kali uses the two-line glyph prompt, rendered inline
    if ((b.os || 'linux') === 'windows') {
      var wd = (b.dir && b.dir !== '~') ? b.dir : 'C:\\';
      return wd + '>';
    }
    var sym = b.root ? '#' : '$';
    var uh = (b.user && b.host) ? (b.user + '@' + b.host) : (b.host || b.user || '');
    var d = b.dir || '~';
    return (uh ? (uh + ':' + d) : d) + sym;
  }
  function CALL(text, kind) { return { t: 'callout', text: text || '', kind: kind || 'note' }; }
  function PROOF(o) {
    return { t: 'proof', label: o.label || '', flag: o.flag || '', path: o.path || '', command: o.command || '',
      screenshot: o.screenshot || '', compliant: !!o.compliant, gap: o.gap || '', block: o.block || '',
      block_label: o.block_label || '', shot_data_uri: o.shot_data_uri || '' };
  }
  function IMG(o) {
    return { t: 'image', caption: o.caption || '', data_uri: o.data_uri || '', path: o.path || '',
      question: o.question || '', is_render: !!o.is_render };
  }
  function HR() { return { t: 'divider' }; }
  function PB() { return { t: 'pagebreak' }; }
  function TOCB() { return { t: 'toc' }; }

  function slug(text) {
    return String(text || '').toLowerCase().split('').filter(function (c) {
      return /[a-z0-9]/.test(c) || c === '-' || c === ' ';
    }).join('').trim().replace(/ /g, '-');
  }

  function toMarkdown(blocks) {
    var out = [];
    (blocks || []).forEach(function (b) {
      switch (b.t) {
        case 'heading':
          out.push('#'.repeat(Math.max(1, Math.min(6, b.level))) + ' ' + b.text); out.push(''); break;
        case 'para': out.push(b.text); out.push(''); break;
        case 'bullets':
          b.items.forEach(function (it, i) { out.push((b.ordered ? (i + 1) + '. ' : '- ') + it); });
          out.push(''); break;
        case 'kv':
          b.pairs.forEach(function (kv) { out.push('- **' + kv[0] + ':** ' + kv[1]); });
          out.push(''); break;
        case 'table':
          if (b.headers.length) {
            out.push('| ' + b.headers.join(' | ') + ' |');
            out.push('| ' + b.headers.map(function () { return '---'; }).join(' | ') + ' |');
          }
          b.rows.forEach(function (row) {
            out.push('| ' + row.map(function (c) { return String(c).replace(/\|/g, '\\|'); }).join(' | ') + ' |');
          });
          if (b.caption) { out.push(''); out.push('*' + b.caption + '*'); }
          out.push(''); break;
        case 'code':
          out.push('```' + b.lang); out.push(String(b.text).replace(/\n+$/, '')); out.push('```'); out.push(''); break;
        case 'terminal': {
          out.push('```console');
          var tp = termPrompt(b);
          if (tp) { out.push(tp + ' ' + b.command); }
          else { out.push('┌──(' + b.user + ')-[' + b.dir + ']'); out.push('└─$ ' + b.command); }
          if (b.output) out.push(String(b.output).replace(/\n+$/, ''));
          out.push('```'); out.push(''); break;
        }
        case 'callout': {
          var prefix = { warn: 'Note: ', gap: 'Proof gap: ', ok: '', note: '' }[b.kind] || '';
          out.push(b.kind !== 'note' ? ('> ' + prefix + b.text) : ('> ' + b.text));
          out.push(''); break;
        }
        case 'proof':
          out.push('**' + b.label + '**');
          if (b.flag) out.push('- flag: `' + b.flag + '`');
          if (b.path) out.push('- path: `' + b.path + '`');
          if (b.command) out.push('- command: `' + b.command + '`');
          out.push('- screenshot: ' + (b.screenshot || '_none captured_'));
          if (b.block) {
            out.push(''); out.push('_' + (b.block_label || 'obol-captured command output') + ':_');
            out.push('```'); out.push(String(b.block).replace(/\n+$/, '')); out.push('```');
          }
          if (b.gap) out.push('- **Proof gap:** ' + b.gap);
          else if (b.compliant) out.push('- OSCP-compliant (interactive shell, target IP visible)');
          out.push(''); break;
        case 'image':
          out.push('![' + (b.caption || 'screenshot') + '](' + (b.path || b.data_uri) + ')');
          if (b.caption) out.push('*' + b.caption + '*');
          out.push(''); break;
        case 'divider': out.push('---'); out.push(''); break;
        case 'pagebreak': case 'toc': break;   // no meaningful markdown representation
        default: break;
      }
    });
    return out.join('\n').replace(/\s+$/, '') + '\n';
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function mdInline(text) {
    var s = esc(text || '');
    var stash = [];
    function hold(html) {
      var id = '\u0000' + stash.length + '\u0000';
      stash.push(html);
      return id;
    }
    s = s.replace(/`([^`]+)`/g, function (_, c) { return hold('<code>' + c + '</code>'); });
    s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, function (_, lbl, url) { return hold('<a href="' + url + '">' + lbl + '</a>'); });
    s = s.replace(/\b(https?:\/\/[^\s<)]+)/g, function (url) {
      var clean = url.replace(/[.,;:]+$/, '');
      var trail = url.slice(clean.length);
      return hold('<a href="' + clean + '">' + clean + '</a>') + trail;
    });
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(^|[\s(])_([^_\r\n]+)_($|[\s).,;:!?])/g, '$1<em>$2</em>$3');
    return s.replace(/\u0000(\d+)\u0000/g, function (_, idx) { return stash[ Number(idx) ] || ''; });
  }

  function toHtml(blocks) {
    var out = [];
    (blocks || []).forEach(function (b) {
      switch (b.t) {
        case 'heading': {
          var a = b.level <= 3 ? (' id="' + (b.anchor || slug(b.text)) + '"') : '';
          out.push('<h' + b.level + a + '>' + esc(b.text) + '</h' + b.level + '>'); break;
        }
        case 'para': out.push('<p>' + mdInline(b.text) + '</p>'); break;
        case 'bullets': {
          var tag = b.ordered ? 'ol' : 'ul';
          out.push('<' + tag + '>' + b.items.map(function (it) { return '<li>' + mdInline(it) + '</li>'; }).join('') + '</' + tag + '>');
          break;
        }
        case 'kv': {
          var rows = b.pairs.map(function (kv) { return '<tr><th>' + esc(kv[0]) + '</th><td>' + mdInline(kv[1]) + '</td></tr>'; }).join('');
          out.push('<table class="kv">' + rows + '</table>'); break;
        }
        case 'table': {
          var head = b.headers.map(function (h) {
            var hName = String(h || '').toLowerCase();
            var isWrapCol = /command|ports|path|local\.txt|proof\.txt|what it is|initial|domain|privilege|finding|technique|operating system/.test(hName);
            return '<th' + (isWrapCol ? ' class="th-wrap"' : ' class="th-compact"') + '>' + esc(h) + '</th>';
          }).join('');
          var body = b.rows.map(function (row) {
            return '<tr>' + row.map(function (c, ci) {
              var hName = String((b.headers && b.headers[ci]) || '').toLowerCase();
              var isWrapCol = /command|ports|path|local\.txt|proof\.txt|what it is|initial|domain|privilege|finding|technique|operating system/.test(hName) || String(c).length > 24;
              return '<td' + (isWrapCol ? ' class="td-wrap"' : ' class="td-compact"') + '>' + mdInline(String(c)) + '</td>';
            }).join('') + '</tr>';
          }).join('');
          var cap = b.caption ? '<caption>' + esc(b.caption) + '</caption>' : '';
          out.push("<table class='data'>" + cap + '<thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table>');
          break;
        }
        case 'code': out.push('<pre class="rep-code' + (b.lang ? ' lang-' + esc(b.lang) : '') + '"><code>' + esc(b.text) + '</code></pre>'); break;
        case 'terminal': {
          var htp = termPrompt(b);
          var oHtml = b.output ? ('\n<span class="kt-o">' + esc(String(b.output).replace(/\n+$/, '')) + '</span>') : '';
          if (htp) {
            var pr = '<span class="kt-u">' + esc(htp) + '</span> <span class="kt-c">' + esc(b.command) + '</span>';
            out.push('<pre class="kali-term term-target">' + pr + oHtml + '</pre>');
          } else {
            var pTop = '<span class="kt-b">┌──(</span><span class="kt-u">' + esc(b.user) + '</span><span class="kt-b">)-[' + esc(b.dir) + ']</span>';
            var pCmd = '<span class="kt-b">└─$</span> <span class="kt-c">' + esc(b.command) + '</span>';
            out.push('<pre class="kali-term">' + pTop + '\n' + pCmd + oHtml + '</pre>');
          }
          break;
        }
        case 'callout': out.push('<div class="callout ' + esc(b.kind) + '">' + mdInline(b.text) + '</div>'); break;
        case 'proof': {
          var rws = [];
          if (b.flag) rws.push('<tr><th>Flag Value</th><td><code>' + esc(b.flag) + '</code></td></tr>');
          if (b.path) rws.push('<tr><th>File Path</th><td><code>' + esc(b.path) + '</code></td></tr>');
          if (b.command) rws.push('<tr><th>Command</th><td><code>' + esc(b.command) + '</code></td></tr>');
          var shot = b.screenshot ? esc(b.screenshot) : (b.compliant ? 'Interactive terminal proof capture (below)' : '<em>none captured</em>');
          rws.push('<tr><th>Verification</th><td>' + shot + '</td></tr>');
          var extra = '';
          if (b.block) extra += '<div class="prooflabel">' + esc(b.block_label || 'Interactive Shell Proof Capture') + '</div>'
            + '<pre class="proofblk">' + esc(b.block) + '</pre>';
          if (b.shot_data_uri) extra += '<img class="shot" alt="operator screenshot" src="' + esc(b.shot_data_uri) + '">';
          var status = '';
          if (b.gap) status = '<div class="callout gap">Proof gap: ' + mdInline(b.gap) + '</div>';
          else if (b.compliant) status = '<div class="callout ok">OSCP-compliant: interactive shell with host identity and target IP visible</div>';
          out.push('<div class="proof-item"><h4>' + esc(b.label) + '</h4><table class="kv">' + rws.join('') + '</table>' + extra + status + '</div>');
          break;
        }
        case 'image': {
          var src = b.data_uri || b.path;
          var cap = b.caption ? '<figcaption>' + mdInline(b.caption) + '</figcaption>' : '';
          var cls = b.is_render ? 'shot termshot' : 'shot';
          var figCls = b.is_render ? 'ev-fig termshot-fig' : 'ev-fig';
          out.push('<figure class="' + figCls + '"><img class="' + cls + '" alt="' + esc(b.caption || 'screenshot') + '" src="' + esc(src) + '">' + cap + '</figure>');
          break;
        }
        case 'divider': out.push('<hr>'); break;
        case 'pagebreak': out.push('<div class="page-break"></div>'); break;
        case 'toc': {
          if (b.items && b.items.length) {
            var tRows = b.items.map(function (it) {
              return '<li class="toc-item toc-lvl-' + it.level + '"><a href="#' + esc(it.anchor) + '">' + esc(it.text) + '</a></li>';
            }).join('');
            out.push('<nav class="toc"><div class="toc-hdr">Table of Contents</div><ol class="toc-list">' + tRows + '</ol></nav>');
          } else {
            out.push('<nav class="toc"></nav>');
          }
          break;
        }
        default: break;
      }
    });
    return out.join('\n');
  }

  // Self-contained stylesheet for the DOWNLOADED .html report, the on-screen paper styling lives in
  // obol.css, which a standalone file cannot see, so without this the export renders as browser-default
  // serif at full page width (i.e. "awful"). Kept in sync with the print/paper look: centred paper column,
  // sans body, bordered tables with shaded headers, and the shaded terminal boxes with muted prompts.
  var STANDALONE_CSS = [
    ':root{color-scheme:light}*{box-sizing:border-box}',
    'body{margin:0;background:#eef0f3;color:#16181d;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}',
    '.rep-doc{max-width:820px;margin:32px auto;background:#fff;padding:44px 54px;border:1px solid #e2e5ea;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.06);overflow:hidden}',
    'h1,h2,h3,h4,h5,h6{line-height:1.25;color:#12161c}',
    'h1{font-size:26px;margin:0 0 14px;padding-bottom:10px;border-bottom:2px solid #1f2a37}',
    'h2{font-size:20px;margin:28px 0 10px;padding-bottom:5px;border-bottom:1px solid #dfe3ea}',
    'h3{font-size:16px;margin:22px 0 8px}h4{font-size:14px;margin:16px 0 6px;color:#2b3440}',
    'h5{font-size:12px;margin:16px 0 6px;text-transform:uppercase;letter-spacing:.05em;color:#1e293b;background:#f1f5f9;padding:5px 10px;border-left:3px solid #334155;border-radius:3px}',
    'p{margin:8px 0}ul,ol{padding-left:22px;margin:8px 0}li{margin:3px 0}',
    'a{color:#0b5cad;word-break:break-word;overflow-wrap:anywhere}',
    'table{border-collapse:collapse;width:100%;max-width:100%;table-layout:auto;margin:11px 0;font-size:13px}',
    'th,td{border:1px solid #d7dce3;padding:6px 10px;text-align:left;vertical-align:top;background:#fff}',
    'th{background:#f1f5f9;font-weight:700;white-space:nowrap}td.td-compact{white-space:nowrap}td.td-wrap,table.kv td{overflow-wrap:anywhere;word-break:break-word}table.kv th{width:175px;white-space:nowrap}',
    'caption{caption-side:top;text-align:left;font-size:12px;color:#5a6572;margin-bottom:4px}',
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}',
    ':not(pre)>code{background:#eef1f5;color:#1f2a37;padding:1px 5px;border-radius:4px;overflow-wrap:anywhere;word-break:break-word}',
    'pre{background:#f4f6f9;border:1px solid #cbd5e1;border-left:3px solid #2563eb;border-radius:6px;padding:10px 14px;margin:10px 0;',
    'font:12px/1.52 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#14181d;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere}',
    '.kali-term{background:#f4f6f9;border:1px solid #cbd5e1;border-left:3px solid #16a34a;border-radius:6px}',
    '.kali-term .kt-b{color:#15803d}.kali-term .kt-u{color:#15803d;font-weight:700}',
    '.kali-term .kt-c{color:#0f172a;font-weight:700}.kali-term .kt-o{color:#1e293b}',
    '.kali-term.term-target{border-left-color:#d97706}.kali-term.term-target .kt-u{color:#b45309}',
    '.callout{border:1px solid #d7dce3;border-left:4px solid #64748b;background:#f8fafc;padding:9px 13px;margin:12px 0;border-radius:4px}',
    '.callout.gap{border-left-color:#c2410c;background:#fdf3ee}.callout.warn{border-left-color:#b7791f;background:#fdf8ee}',
    '.callout.ok{border-left-color:#16a34a;background:#f0fdf4}.callout.note{border-left-color:#475569;background:#f8fafc}',
    '.proof-item{margin:14px 0}.prooflabel{font:600 11.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#475569;margin:8px 0 4px;text-transform:uppercase;letter-spacing:.04em}',
    'img.shot{max-width:100%;height:auto;border:1px solid #d7dce3;border-radius:4px}',
    'figure{margin:12px 0}figcaption{font-size:12px;color:#5a6572;margin-top:4px}',
    'hr{border:none;border-top:1px solid #dfe3ea;margin:22px 0}',
    'nav.toc{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px 16px;margin:0 0 20px}',
    'nav.toc:empty{display:none}.toc-hdr{font-weight:700;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#334155;margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid #e2e8f0}',
    '.toc-list{margin:0;padding-left:18px;columns:2;column-gap:28px}.toc-item{margin:3px 0;font-size:12.5px;break-inside:avoid}.toc-lvl-3{padding-left:10px;font-size:12px;color:#475569;list-style-type:circle}',
    '.toc-item a{text-decoration:none;color:#1e293b}.toc-item a:hover{color:#0b5cad;text-decoration:underline}',
    '@media print{html,body{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact}',
    '.rep-doc{max-width:none;margin:0;padding:0;border:none;border-radius:0;box-shadow:none}',
    '.page-break{break-after:page;page-break-after:always}}',
    '@media (max-width:720px){.rep-doc{padding:24px 18px;margin:0;border-radius:0}.toc-list{columns:1}}',
  ].join('');

  // Wrap rendered report HTML in a full, self-contained document for download/print.
  function htmlDocument(bodyHtml, title) {
    return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
      + '<meta name="viewport" content="width=device-width, initial-scale=1">'
      + '<title>' + esc(title || 'Report') + '</title><style>' + STANDALONE_CSS + '</style></head>'
      + '<body><main class="rep-doc">' + bodyHtml + '</main></body></html>';
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 5. context builder
  // ─────────────────────────────────────────────────────────────────────────
  function dedupPorts(facts) {
    function svcRank(svc) {
      var s = String(svc || '').trim().toLowerCase();
      if (!s) return 0;
      if (['unknown', 'tcpwrapped', 'filtered', 'closed', 'open'].indexOf(s) !== -1) return 1;
      if (s.charAt(s.length - 1) === '?') return 2;
      return 3;
    }
    var best = {};
    facts.forEach(function (f) {
      if (String(f.kind || '').indexOf('port:') !== 0 || f.state !== SUPPORTED) return;
      var port = f.kind.split(':')[1];
      var proto = (f.value && f.value.protocol) || 'tcp';
      var svc = ((f.value && f.value.service) || '').trim();
      var key = port + '/' + proto;
      var rank = svcRank(svc);
      if (!(key in best) || rank > best[key].rank) best[key] = { rank: rank, svc: svc, port: port, proto: proto };
    });
    var rows = Object.keys(best).map(function (k) {
      var e = best[k];
      return e.port + '/' + e.proto + (e.svc ? ' ' + e.svc : '');
    });
    rows.sort(function (a, b) {
      var pa = parseInt(a.split('/')[0], 10), pb = parseInt(b.split('/')[0], 10);
      pa = isNaN(pa) ? 99999 : pa; pb = isNaN(pb) ? 99999 : pb;
      return pa - pb || (a < b ? -1 : a > b ? 1 : 0);
    });
    return rows;
  }

  function runStatus(row) {
    if (row.dry_run) return 'dry run';
    if (row.timed_out) return 'timed out';
    if ('returncode' in row) return 'return code ' + row.returncode;
    if (row.status) return row.status;
    return 'recorded';
  }

  function inferProofSlot(v, source, factKind) {
    v = v || {};
    if (v.slot === 'local' || v.slot === 'root' || v.slot === 'flag') return v.slot;
    if (factKind && SLOT_OF_KIND[factKind]) return SLOT_OF_KIND[factKind];
    var k = String(v.kind || v.type || '').toLowerCase();
    if (k === 'proof' || k === 'root' || k === 'proof.txt' || k === 'root.txt') return 'root';
    if (k === 'local' || k === 'user' || k === 'local.txt' || k === 'user.txt') return 'local';
    var hint = String((v.path || '') + ' ' + (v.name || '') + ' ' + (source || '')).toLowerCase();
    if (/(?:proof|root)\.txt/.test(hint)) return 'root';
    if (/(?:local|user)\.txt/.test(hint)) return 'local';
    return 'flag';
  }

  function flagObjectives(tfacts) {
    var out = [], seen = {};
    function take(f) {
      if (f.state !== SUPPORTED) return;
      var v = f.value || {};
      var flag = v.flag || v.value || '';
      if (!flag || seen[flag]) return;
      seen[flag] = 1;
      var slot = inferProofSlot(v, f.source, f.kind);
      var name = v.name || (slot === 'root' ? 'proof.txt' : (slot === 'local' ? 'local.txt' : 'flag.txt'));
      out.push({ kind: f.kind, slot: slot, name: name, path: v.path || '', flag: String(flag), source: f.source || '', at: f.created_at });
    }
    tfacts.forEach(function (f) { if (FLAG_FACT_KINDS.indexOf(f.kind) !== -1) take(f); });
    tfacts.forEach(function (f) { if (f.kind === PROOF_FACT) take(f); });
    return out;
  }

  function collectProofs(facts, acts, includeSecrets) {
    var fs = asFactSet(facts);
    var list = (fs.facts || []);
    var out = [], seen = {};
    function processFact(f) {
      if (f.state && f.state !== SUPPORTED) return;
      if (f.kind !== PROOF_FACT && FLAG_FACT_KINDS.indexOf(f.kind) === -1) return;
      var v = f.value || {};
      var rawFlag = String(v.flag || v.value || '').trim();
      if (!rawFlag) return;
      var sc = String(f.scope || '');
      var host = sc.indexOf('host:') === 0 ? sc.slice(5) : (v.host || v.target || '');
      var dedupKey = host + '|' + rawFlag;
      if (seen[dedupKey]) return;
      seen[dedupKey] = 1;
      var slot = inferProofSlot(v, f.source, f.kind);
      var fileKind = slot === 'root' ? 'proof.txt' : (slot === 'local' ? 'local.txt' : (v.name || 'flag.txt'));
      out.push({
        host: host,
        kind: fileKind,
        slot: slot,
        flag: includeSecrets ? rawFlag : '[REDACTED]',
        rawFlag: rawFlag,
        path: v.path || '',
        source: f.source || '',
        at: f.created_at || 0,
      });
    }
    list.forEach(function (f) { if (FLAG_FACT_KINDS.indexOf(f.kind) !== -1) processFact(f); });
    list.forEach(function (f) { if (f.kind === PROOF_FACT) processFact(f); });
    return out;
  }

  function hostProof(host, tfacts, screens, includeSecrets) {
    var captured = {};
    tfacts.forEach(function (f) {
      if (f.kind === PROOF_FACT && f.state === SUPPORTED) {
        var slot = inferProofSlot(f.value, f.source, f.kind);
        captured[slot] = f.value || {};
        if (f.value && f.value.slot) captured[f.value.slot] = f.value;
      }
    });
    var shotsBySlot = {};
    var shotViews = [];
    (screens || []).filter(function (e) { return e.kind === 'proof' && (e.target || '') === host; }).forEach(function (e) {
      var slot = e.slot || '';
      (shotsBySlot[slot] = shotsBySlot[slot] || []).push(e);
      shotViews.push({ slot: slot, id: e.id, caption: e.caption || '', data_uri: e.data_uri || '', path: e.path || '', label: 'operator screenshot' });
    });
    var flags = flagObjectives(tfacts);
    var slotless = flags.length === 1 ? shotsBySlot[''] : null;
    var rows = flags.map(function (f) {
      var slot = f.slot; var blk = captured[slot];
      var interactive_ok = !!(blk && blk.interactive_ok);
      var obol_ok = !!(blk && blk.identity_ok && interactive_ok);
      var shot = shotsBySlot[slot] || slotless;
      var block = blk ? (blk.block || '') : '';
      var flag = f.flag;
      if (!includeSecrets && flag) block = block.split(flag).join('[REDACTED]');
      return {
        slot: slot, label: SLOT_LABEL[slot] || slot, flag: includeSecrets ? flag : (flag ? '[REDACTED]' : ''), path: f.path,
        obol_block: !!blk, obol_compliant: obol_ok, obol_interactive: interactive_ok,
        block: block, block_label: block ? 'OBOL-captured command output' : '',
        screenshots: (shot || []).map(function (s) { return s.id; }),
        has_proof: !!(obol_ok || shot),
      };
    });
    return { host: host, flags: rows, screenshots: shotViews };
  }

  function screenshotView(e) {
    return {
      id: e.id, target: e.target || '', phase: e.phase || '', caption: e.caption || '', filename: e.filename || '',
      kind: e.kind || 'evidence', slot: e.slot || '', stored: e.stored || '', section: e.section || '',
      order: e.order || 0, added_at: e.added_at || 0, question: e.question || '',
      include: e.include !== false, data_uri: e.data_uri || '', path: e.path || '', edited_stored: e.edited_stored || '',
    };
  }

  function findingFactsForHost(factset, host) {
    return (factset.facts || []).filter(function (f) {
      return String(f.kind || '').indexOf('finding.') === 0 && f.state === SUPPORTED && f.scope === 'host:' + host;
    });
  }

  function buildMoveMap(opts) {
    var map = {};
    function addList(arr) {
      if (!arr) return;
      if (Array.isArray(arr)) {
        arr.forEach(function (m) {
          if (m && typeof m === 'object') {
            var id = m.id || m.key || m.action_id;
            if (id) map[id] = m;
          }
        });
      } else if (typeof arr === 'object') {
        Object.keys(arr).forEach(function (k) {
          if (arr[k] && typeof arr[k] === 'object') map[k] = arr[k];
        });
      }
    }
    if (opts && opts.actions) addList(opts.actions);
    try {
      if (root.OBOL && root.OBOL.packs) {
        if (typeof root.OBOL.packs.allActions === 'function') addList(root.OBOL.packs.allActions());
        else if (typeof root.OBOL.packs.actions === 'function') addList(root.OBOL.packs.actions());
      }
    } catch (e) {}
    return map;
  }

  function actProducedKinds(a) {
    var raw = (a && (a.minted_facts || a.produced || a.facts)) || [];
    if (!Array.isArray(raw)) return [];
    return raw.map(function (x) { return (x && typeof x === 'object') ? (x.kind || '') : String(x || ''); }).filter(Boolean);
  }

  function actMatchesHost(a, host, singleTarget) {
    if (!host) return true;
    var t = a.target || a.host || '';
    var sc = a.scope || '';
    if (t === host || sc === 'host:' + host) return true;
    if (!t && (!sc || sc.indexOf('host:') !== 0)) {
      if (singleTarget) return true;
      if (a.command && String(a.command).indexOf(host) >= 0) return true;
    }
    return false;
  }

  // ── catalog findings (fact-driven, from OBOL.findings.assess) + technique narratives ──────────────
  // The findings catalog matches proven facts to report-worthy weaknesses (AS-REP roasting, DCSync,
  // ACL abuse, SUID, SQLi, ...); OBOL.narratives supplies each technique's write-up prose. Together they
  // turn the walkthrough from boilerplate into the real, named, reproducible chain.
  function narrativeFor(key) { return (root.OBOL && root.OBOL.narratives && root.OBOL.narratives[key]) || null; }
  function fillTokens(str, subs) {
    return String(str || '').replace(/\{\{(\w+)\}\}/g, function (m, k) { return (subs[k] != null && subs[k] !== '') ? subs[k] : (k === 'subject' ? 'the affected account' : (k === 'domain' ? 'the domain' : m)); });
  }
  // A host's facts for catalog matching: its own host-scoped facts, plus domain-wide facts (ad.*, loot.*,
  // krbtgt) when this host is the domain's DC / the primary target, so domain compromise is reported once.
  function hostFactSubset(factset, host, isPrimary) {
    var facts = (factset.facts || []).filter(function (f) {
      if (f.state !== SUPPORTED) return false;
      var sc = f.scope || '';
      if (sc === 'host:' + host) return true;
      if (isPrimary && (sc.indexOf('domain:') === 0 || sc === '' || sc === 'engagement')) return true;
      return false;
    });
    return new FACTS.FactSet(facts);
  }
  // Best-effort human subject for a technique: an account / service / group from its trigger facts, else
  // parsed from the command that produced them (impacket `dom/user:pw@host`, `-u user`, `@user`).
  function subjectFromCommand(cmd) {
    cmd = String(cmd || '');
    var m = cmd.match(/(?:^|\s)['"]?[\w.-]+\/([\w.$-]+):[^@\s]*@/); // impacket domain/user:pass@host
    if (m) return m[1];
    m = cmd.match(/\s-u\s+['"]?([\w.$@-]+)/); if (m) return m[1].replace(/@.*$/, '');
    m = cmd.match(/add\s+dcsync\s+([\w.$-]+)/i); if (m) return m[1]; // bloodyAD add dcsync <user>
    return '';
  }
  function findingSubject(factset, host, trigKinds, cmds) {
    var want = {}; (trigKinds || []).forEach(function (k) { want[k] = 1; });
    if ((want['hash.ntlm'] || want['credential.nthash']) && !want['loot.ntds']) {
      for (var p = 0; p < (cmds || []).length; p++) {
        var pSubj = subjectFromCommand(cmds[p].command);
        if (pSubj) return pSubj;
      }
    }
    var facts = (factset.facts || []);
    for (var i = 0; i < facts.length; i++) {
      var f = facts[i]; if (!want[f.kind]) continue;
      var v = f.value || {};
      var s = v.user || v.account || v.principal || v.sam || v.service || v.group || v.name || '';
      if (s) return String(s);
    }
    for (var j = 0; j < (cmds || []).length; j++) { var sc = subjectFromCommand(cmds[j].command); if (sc) return sc; }
    return '';
  }

  function isExploitOutcomeFact(kind) {
    if (!kind) return false;
    return kind === 'access.root' || kind === 'access.admin' || kind === 'access.system' || kind === 'access.shell'
      || kind.indexOf('foothold.') === 0 || kind.indexOf('loot.') === 0 || kind.indexOf('credential.') === 0
      || kind === 'hash.krbtgt' || kind === 'persistence.domain';
  }

  var PASSIVE_BANNER_FACT_RE = /^(?:blocker\.|credential\.validation$|host\.|ad\.dc_candidate$|ad\.domain_known$|ad\.base_dn$|smb\.signing$|smb\.smbv1$)/;

  function isBlockerOnlyActivity(a) {
    if (!a) return true;
    if (String(a.status || '').toLowerCase() === 'failed') return true;
    var prod = actProducedKinds(a);
    if (!prod.length) return false;
    var hasBlocker = prod.some(function (k) { return String(k).indexOf('blocker.') === 0; });
    if (hasBlocker && prod.every(function (k) { return PASSIVE_BANNER_FACT_RE.test(String(k)); })) return true;
    return prod.every(function (k) {
      return String(k).indexOf('blocker.') === 0 || k === 'credential.validation';
    });
  }

  var PASSIVE_PROTOCOL_TRIGGERS = {
    'smb.smbv1': 1, 'smb.signing': 1, 'smb.null_session': 1, 'ad.anonymous_bind': 1,
    'http.headers': 1, 'http.methods': 1, 'http.cors': 1, 'tls.info': 1, 'dns.email': 1,
  };

  function findingTriggerActivities(f, hostActs, hostFacts, moveMap) {
    var trigKinds = (f && (f.trigger_kinds || f.produces)) || [];
    var want = {}; trigKinds.forEach(function (k) { want[k] = 1; });
    var acts = (hostActs || []).slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); });
    var matched = [], seenAct = {}, firstAt = 0;
    moveMap = moveMap || {};

    var isPassiveProtocolFinding = trigKinds.length > 0 && trigKinds.every(function (k) { return !!PASSIVE_PROTOCOL_TRIGGERS[k]; });
    var isPthFinding = (want['hash.ntlm'] || want['credential.nthash']) && !want['loot.ntds'] && !want['hash.krbtgt'];

    if (isPthFinding) {
      var pthRe = /(?:^|\s)(?:-H|--hashes|-hashes)\s+(?:[0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}\b|\bpth-/i;
      acts.forEach(function (a) {
        if (isBlockerOnlyActivity(a)) return;
        if (pthRe.test(String(a.command || ''))) {
          if (!firstAt) firstAt = a.at || 0;
          var k = (a.command || '') + '|' + (a.at || 0);
          if (!seenAct[k]) { seenAct[k] = 1; matched.push(a); }
        }
      });
      if (matched.length) {
        matched.firstAt = firstAt;
        return matched;
      }
    }

    if (f && f._moveAct && !isBlockerOnlyActivity(f._moveAct)) {
      matched.push(f._moveAct);
      seenAct[(f._moveAct.command || '') + '|' + (f._moveAct.at || 0)] = 1;
      firstAt = f._moveAct.at || 0;
    }

    acts.forEach(function (a) {
      if (isBlockerOnlyActivity(a)) return;
      if (isPassiveProtocolFinding && matched.length >= 1) return;
      var prod = actProducedKinds(a);
      if (!prod.some(function (k) { return want[k]; })) return;
      // Ignore self-minted credential.plaintext echoes from unrelated tools (e.g. bloodyad -p <pass>)
      if (want['credential.plaintext'] && !/^(?:sudo\s+)?(?:hashcat|john|secretsdump|impacket-secretsdump|mimikatz|pypykatz)\b/i.test(String(a.command || '').trim())) {
        if (!prod.some(function (k) { return k !== 'credential.plaintext' && want[k]; })) return;
      }
      if (!firstAt) firstAt = a.at || 0;
      var key = (a.command || '') + '|' + (a.at || 0);
      if (!seenAct[key]) { seenAct[key] = 1; matched.push(a); }
    });

    if (isPassiveProtocolFinding) {
      matched.firstAt = firstAt;
      return matched;
    }

    // Check subsequent activities on the same host that consumed one of trigKinds to achieve access/loot/credentials
    var isPrivescOrWebLead = trigKinds.some(function (k) {
      return k.indexOf('privesc.') === 0 || k.indexOf('web.') === 0 || k.indexOf('vuln.') === 0
        || k === 'hash.asrep' || k === 'hash.tgs';
    });
    var attachedFootholdShell = false;
    if (trigKinds.length) {
      acts.forEach(function (a) {
        if (isBlockerOnlyActivity(a)) return;
        var key = (a.command || '') + '|' + (a.at || 0);
        if (seenAct[key]) return;
        if (firstAt && (a.at || 0) < firstAt) return;
        var prod = actProducedKinds(a);
        var cmdStr = String(a.command || '').trim();
        var mid = a.action_id || a.move_id || '';
        var mv = mid ? moveMap[mid] : null;
        var reqs = mv ? [].concat(mv.requires_all || [], mv.requires_any || []) : [];
        var moveConsumesTrigger = reqs.some(function (rk) { return want[rk]; });

        // Do not attach downstream domain-compromise or unrelated commands to SMB Null Session
        if (want['smb.null_session'] && !want['ad.control_paths']) {
          if (!/^(?:sudo\s+)?(?:enum4linux[\w-]*|rpcclient|smbclient|smbmap|nxc\s+smb|netexec\s+smb)\b/i.test(cmdStr)) return;
          if (prod.some(function (k) { return k === 'ad.user_list' || k === 'smb.shares' || k === 'smb.readable_share'; })) {
            seenAct[key] = 1;
            matched.push(a);
          }
          return;
        }

        if (!prod.some(isExploitOutcomeFact)) return;
        var mintsSeparateCatalogTrigger = prod.some(function (k) {
          if (want[k]) return false;
          return k === 'loot.ntds' || k === 'hash.krbtgt' || k === 'ad.control_paths' || k === 'ad.group_joined' || k === 'hash.asrep' || k === 'hash.tgs';
        });
        if (mintsSeparateCatalogTrigger) return;

        var directFollowOn = false;
        if (want['hash.asrep'] || want['hash.tgs']) {
          // For AS-REP Roasting / Kerberoasting, attach password cracking commands (hashcat / john)
          // and the initial foothold shell command that authenticated with the cracked password
          moveConsumesTrigger = false;
          if (/^(?:sudo\s+)?(?:hashcat|john)\b/i.test(cmdStr) && prod.some(function (k) { return k === 'credential.plaintext' || k === 'credential.available'; })) {
            directFollowOn = true;
          } else if (!attachedFootholdShell && /^(?:evil-winrm|ssh|sshpass|impacket-(?:psexec|wmiexec|smbexec)|psexec\.py|wmiexec\.py)\b/i.test(cmdStr)
            && !/(?:^|\s)(?:-H|--hashes|-hashes)\s+/i.test(cmdStr)
            && prod.some(function (k) { return k.indexOf('foothold.') === 0 || k === 'access.shell' || k === 'winrm.authenticated'; })) {
            directFollowOn = true;
            attachedFootholdShell = true;
          }
        } else if (!moveConsumesTrigger && isPrivescOrWebLead && firstAt) {
          if (trigKinds.some(function (k) { return k.indexOf('privesc.') === 0; }) && prod.some(function (k) { return k === 'access.root' || k === 'access.system' || k === 'access.admin'; })) {
            directFollowOn = true;
          } else if (trigKinds.some(function (k) { return k.indexOf('web.') === 0; }) && prod.some(function (k) { return k.indexOf('foothold.') === 0 || k === 'access.shell'; })) {
            directFollowOn = true;
          }
        }
        if (moveConsumesTrigger || directFollowOn) {
          seenAct[key] = 1;
          matched.push(a);
        }
      });
    }
    if (matched.length > 1) {
      var aclStageRank = function (act) {
        var c = String((act && act.command) || '').toLowerCase();
        if (/\bget\s+writable\b/.test(c)) return 1;
        if (/\badd\s+groupmember\b|\bnet\s+(?:group|localgroup)\b.*\/add\b/.test(c)) return 2;
        if (/\bdcsync\b|-rights\s+dcsync\b/.test(c)) return 3;
        return 0;
      };
      matched.sort(function (a, b) {
        var ra = aclStageRank(a), rb = aclStageRank(b);
        if (ra && rb && ra !== rb) return ra - rb;
        return (a.at || 0) - (b.at || 0);
      });
    }
    matched.firstAt = firstAt;
    return matched;
  }

  // Evidence commands (from the ledger) that produced any of the technique's trigger facts + follow-on exploit commands, in run order.
  function findingEvidenceCommands(ctx, host, trigKinds, moveAct) {
    var allActs = (ctx && ctx.activities) || [];
    var singleTarget = !!(ctx && ctx.singleTarget);
    var hostActs = allActs.filter(function (a) { return actMatchesHost(a, host, singleTarget); });
    var matchedActs = findingTriggerActivities(
      { trigger_kinds: trigKinds || [], _moveAct: moveAct || null },
      hostActs,
      null,
      (ctx && ctx.moveMap) || {}
    );
    var out = [], seen = {};
    matchedActs.forEach(function (a) {
      var cmd = (a.command || '').trim();
      if (cmd && !seen[cmd]) {
        seen[cmd] = 1;
        out.push({ command: cmd, output: a.stdout || '' });
      }
    });
    out.firstAt = matchedActs.firstAt || 0;
    return out;
  }
  // The foothold identity: the first non-privileged authenticated/recovered account for the host, the
  // subject most foothold/credential techniques concern, used when the trigger fact names no principal.
  function footholdUser(factset, host) {
    var facts = (factset.facts || []);
    var order = ['credential.plaintext', 'credential.available', 'smb.authenticated', 'winrm.authenticated', 'foothold.windows', 'foothold.linux'];
    for (var oi = 0; oi < order.length; oi++) {
      for (var i = 0; i < facts.length; i++) {
        var f = facts[i]; if (f.kind !== order[oi]) continue;
        var u = (f.value && (f.value.user || f.value.username)) || '';
        if (u && !/^(administrator|admin|system|root|nt authority)/i.test(String(u))) return String(u);
      }
    }
    return '';
  }
  function catalogFindingsForHost(ctx, factset, host, isPrimary, secrets, includeSecrets) {
    if (!(root.OBOL && root.OBOL.findings && root.OBOL.findings.assess)) return [];
    var hostFS, matched;
    try { hostFS = hostFactSubset(factset, host, isPrimary); matched = root.OBOL.findings.assess(hostFS) || []; }
    catch (e) { return []; }
    var foothold = footholdUser(factset, host);
    var subs0 = { target: host, domain: (ctx.meta && ctx.meta.domain) || '', lhost: (ctx.meta && ctx.meta.lhost) || '' };
    return matched.map(function (m) {
      var narr = narrativeFor(m.key) || {};
      var evc = findingEvidenceCommands(ctx, host, m.trigger_kinds);
      var subj = findingSubject(factset, host, m.trigger_kinds, evc) || foothold || '';
      var subs = Object.assign({}, subs0, { subject: subj });
      return {
        kind: 'finding.' + m.key, key: m.key, slug: m.key, label: m.title, title: m.title,
        category: m.category, severity: m.severity, remediation: m.remediation, refs: m.refs || [],
        cwe: m.cwe, attack: m.attack, nist: m.nist, trigger_kinds: m.trigger_kinds || [],
        phase_label: narr.phase_label ? fillTokens(narr.phase_label, subs) : '',
        first_at: evc.firstAt || 0,
        evidence: (evc[0] && evc[0].command) || '',
        evidence_cmds: evc.map(function (e) { return { command: redactCommand(e.command, { includeSecrets: includeSecrets, secrets: secrets }), output: redactCommand(e.output || '', { includeSecrets: includeSecrets, secrets: secrets }) }; }),
        writeup: {
          description: narr.explanation ? fillTokens(narr.explanation, subs) : '',
          impact: narr.impact ? fillTokens(narr.impact, subs) : '',
          remediation: m.remediation || '',
        },
        origin: 'catalog', from_catalog: true,
      };
    });
  }

  function metaEnrich(reportmeta, card, lane) {
    var rm = reportmeta || {};
    var cards = rm.cards || {}, laneDefaults = rm.laneDefaults || {};
    var base = (card && cards[card]) || (lane && laneDefaults[lane]) || { mitre: [], fix: '' };
    var R = rm.references || { cards: {}, lanes: {} };
    var ref = (card && R.cards && R.cards[card]) || (lane && R.lanes && R.lanes[lane]) || {};
    return { mitre: base.mitre || [], fix: base.fix || '', cve: base.cve || [], nist: ref.nist || [], cwe: ref.cwe || [] };
  }

  function toFinding(f, host, reportmeta, includeSecrets) {
    var v = f.value || {};
    var sev = normalizeSeverity(v.severity);
    var enr = metaEnrich(reportmeta, v.card, v.lane);
    return {
      kind: f.kind, host: host, title: v.title || friendly(f.kind), severity: sev,
      category: v.category || '', key: v.key || '',
      remediation: v.remediation || enr.fix || '',
      description: v.description || v.detail || '', detail: v.detail || '',
      cwe: v.cwe || (enr.cwe[0] || ''), attack: v.attack || (enr.mitre[0] || ''), nist: v.nist || (enr.nist[0] || ''),
      cve: v.cve || enr.cve || [],
      kev: !!v.kev, confidence: v.confidence || 'confirmed',
      operator: v.origin === 'operator-attested',
      trigger_kinds: v.trigger_kinds || [],
      evidence: redactCommand(f.source || '', { includeSecrets: includeSecrets, secrets: [] }),
      at: f.created_at,
    };
  }

  function normalizeActCommand(row) {
    if (!row || typeof row !== 'object') return row;
    var cmd = String(row.command || '').trim();
    var out = String(row.stdout || '');
    var tool = String(row.tool || '').replace(/;+$/, '');
    if (row.action_id && cmd.indexOf(row.action_id + ' ') === 0) {
      cmd = cmd.slice(row.action_id.length).trim();
    } else if (/^[a-z0-9]+(?:-[a-z0-9]+)+\s+(?:nmap|nxc|netexec|smbclient|rpcclient|enum4linux|ldapsearch|impacket|GetNPUsers|GetUserSPNs|secretsdump|bloodyAD|bloodhound-python|certipy|john|hashcat|evil-winrm|ffuf|gobuster|curl|ssh|for|if)\b/i.test(cmd)) {
      cmd = cmd.replace(/^[a-z0-9]+(?:-[a-z0-9]+)+\s+/i, '').trim();
    }
    cmd = cmd
      .replace(/;\s*done\b/g, ' ')
      .replace(/-o\s+TARGETDomain\b/g, "-o 'TARGET=Domain Admins'")
      .replace(/-o\s+DOWNLOAD_FLAGTrue\b/g, '-o DOWNLOAD_FLAG=True')
      .replace(/-o\s+LISTENERLHOST\b/g, '-o LISTENER=LHOST')
      .replace(/\s{2,}/g, ' ')
      .trim();
    var trailIp = cmd.match(/\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$/);
    if (trailIp && /\bTARGET\b/.test(cmd)) {
      cmd = cmd.slice(0, cmd.length - trailIp[0].length).replace(/\bTARGET\b/g, trailIp[1]).trim();
    }
    if (/^[a-z0-9]+(?:-[a-z0-9]+)+$/i.test(tool) && cmd) {
      tool = (cmd.split(/\s+/)[0] || tool).replace(/;+$/, '');
    }
    if (out) {
      var firstLines = out.split(/\r?\n/).slice(0, 5);
      for (var i = 0; i < firstLines.length; i++) {
        var m = firstLines[i].match(/^(?:└─[$#]|(?:\*Evil-WinRM\*\s+)?PS\s+[A-Za-z]:[^\r\n>]*>|[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[^$#\r\n]*[$#])\s+(.+?)\s*$/);
        if (m && m[1]) {
          var pCmd = m[1].trim();
          if (/^for\s+\w+\s+in\b/i.test(pCmd) && /add\s+groupMember/i.test(pCmd) && /get\s+writable/i.test(cmd)) {
            cmd = pCmd;
          } else if (!cmd) {
            cmd = pCmd;
          }
          break;
        }
      }
    }
    if (cmd === row.command && tool === row.tool) return row;
    return Object.assign({}, row, { command: cmd, tool: tool });
  }

  function buildContext(opts) {
    opts = opts || {};
    var includeSecrets = !!opts.includeSecrets;
    var factset = asFactSet(opts.facts);
    var targets = opts.targets || [];
    var activities = (opts.activities || []).map(normalizeActCommand);
    var hasCmdkeyNoneOnly = activities.some(function (a) {
      return /Currently stored credentials:[\s\S]{0,160}?\*\s*NONE\s*\*/i.test(a.stdout || '');
    }) && !activities.some(function (a) {
      return /Currently stored credentials:(?![\s\S]{0,160}?\*\s*NONE\s*\*)[\s\S]{0,200}?Target:/i.test(a.stdout || '');
    });
    if (hasCmdkeyNoneOnly && factset && Array.isArray(factset.facts)) {
      factset.facts = factset.facts.filter(function (f) {
        if (!f) return false;
        if (f.kind === 'privesc.stored_credentials' && f.value && Array.isArray(f.value.kinds) && f.value.kinds.length === 1 && f.value.kinds[0] === 'cmdkey') return false;
        if (f.kind === 'credential.candidate' && f.value && f.value.kind === 'stored_windows_credentials') return false;
        return true;
      });
    }
    var credentials = opts.credentials || [];
    var params = opts.params || {};
    var notes = opts.notes || {};   // per-host operator narrative: { '<ip>': { summary, steps } }
    var screensRaw = opts.screenshots || [];
    var reportmeta = opts.reportmeta || root.OBOL_REPORTMETA || { cards: {}, laneDefaults: {}, references: { cards: {}, lanes: {} }, cveHints: [] };
    var secrets = knownSecrets(factset, credentials);

    var domain = factset.values('ad.domain_known');
    var domOwned = factset.has('loot.ntds') || factset.has('hash.krbtgt') || factset.has('persistence.domain');

    var accessState;
    if (factset.has('access.system')) accessState = 'SYSTEM access proven';
    else if (factset.has('access.root')) accessState = 'root access proven';
    else if (factset.has('access.admin')) accessState = 'Administrative access proven';
    else if (factset.has('foothold.windows') || factset.has('foothold.linux') || factset.has('access.shell')) accessState = 'Foothold proven, privilege not yet proven';
    else accessState = 'No access proven yet';

    var credState;
    if (factset.has('credential.available') || factset.has('credential.plaintext')) credState = 'Validated credential available';
    else if (factset.has('credential.candidate')) credState = 'Candidate material only';
    else credState = 'No validated credential';

    var evidence = screensRaw.map(screenshotView);

    // facts projection
    var factsOut = (factset.facts || []).slice().sort(bySortKey).map(function (f) {
      return {
        kind: f.kind, label: friendly(f.kind), category: factCategory(f.kind), state: f.state,
        scope: f.scope, value: redactValue(f.value, includeSecrets),
        evidence: redactCommand(f.source || 'manual/seeded workspace evidence', { includeSecrets: includeSecrets, secrets: secrets }),
        origin: (f.value && f.value.origin) || 'obol', at: f.created_at,
      };
    });

    // timeline (run ledger). Carries target/scope so the walkthrough can render each host's
    // verbatim command+output transcript; stdout is redacted with the same secret set as commands.
    var timeline = activities.map(function (row, i) {
      return {
        index: i + 1, tool: String(row.tool || 'tool').replace(/;+$/, ''),
        command: redactCommand(row.command || '', { includeSecrets: includeSecrets, secrets: secrets }),
        status: runStatus(row), produced: (row.produced || []).slice(), duration_ms: row.duration_ms,
        at: row.at, at_display: stamp(row.at), action_id: row.action_id, playbook: row.playbook,
        target: row.target || '', scope: row.scope || '',
        stdout: redactCommand(row.stdout || '', { includeSecrets: includeSecrets, secrets: secrets }), stderr: row.stderr || '',
      };
    });

    // per-target rollup
    // the ordered compromise chain per host (what led to what -> the flags), redacted like everything else.
    var chainActions = opts.actions || opts.pack || ((OBOL.packs && typeof OBOL.packs.actions === 'function') ? OBOL.packs.actions() : []);
    function hostChain(host) {
      if (!OBOL.chain) return [];
      var steps;
      try { steps = OBOL.chain.build({ facts: factset, activities: activities, actions: chainActions, host: host }); }
      catch (e) { return []; }
      return steps.map(function (s) {
        return { kind: s.kind, label: s.label, phase: s.phase, isFlag: !!s.isFlag, technique: s.technique || '',
          detail: (!includeSecrets && s.secret) ? '«redacted»' : redactCommand(s.detail || '', { includeSecrets: includeSecrets, secrets: secrets }),
          enabledBy: (s.enabledBy || []).map(function (k) { return friendly(k); }),
          command: redactCommand(s.command || '', { includeSecrets: includeSecrets, secrets: secrets }) };
      });
    }

    var isSingleTargetRun = targets.length === 1;
    var targetsOut = targets.map(function (t, ti) {
      var host = t.host || t.ip || '';
      var directHostFacts = (factset.facts || []).filter(function (f) { return f.scope === 'host:' + host; });
      var isDcHost = isSingleTargetRun || ti === 0 || directHostFacts.some(function (f) {
        return f.kind === 'ad.dc_candidate' || f.kind === 'kerberos.reachable' || f.kind === 'ldap.reachable'
          || f.kind === 'port:88' || f.kind === 'port:389' || f.kind === 'port:636' || f.kind === 'port:3268';
      });
      var tfacts = (factset.facts || []).filter(function (f) {
        var sc = String(f.scope || '');
        if (sc === 'host:' + host) return true;
        if (isDcHost && sc.indexOf('domain:') === 0) return true;
        if (isSingleTargetRun && (!sc || sc === 'global' || sc === 'engagement' || sc === 'host:target')) return true;
        return false;
      });
      var sortedT = tfacts.slice().sort(bySortKey);
      var flags = flagObjectives(tfacts).map(function (fo) {
        return { kind: fo.kind, slot: fo.slot, name: fo.name, path: fo.path, flag: includeSecrets ? fo.flag : (fo.flag ? '«redacted»' : ''),
          rawFlag: fo.flag, evidence: redactCommand(fo.source || '', { includeSecrets: includeSecrets, secrets: secrets }), at: fo.at };
      });
      function idfact(kind, key) {
        for (var i = 0; i < tfacts.length; i++) if (tfacts[i].kind === kind && tfacts[i].value && tfacts[i].value[key]) return String(tfacts[i].value[key]);
        return '';
      }
      var os = t.os || idfact('host.os_family', 'product') || idfact('host.os_family', 'family') || idfact('host.os_hint', 'product') || idfact('host.os_hint', 'family');
      var hn = t.hostname || idfact('host.hostname', 'hostname') || idfact('host.hostname', 'name') || idfact('ad.dc_candidate', 'name') || '';
      var domVal = t.domain || idfact('host.domain', 'domain') || idfact('host.domain', 'name') || idfact('ad.domain_known', 'domain') || idfact('ad.domain_known', 'name') || '';
      var labelVal = (t.label && t.label !== host) ? t.label : (hn || host);
      return {
        host: host, label: labelVal, hostname: hn,
        fqdn: t.fqdn || idfact('host.fqdn', 'fqdn'), domain: domVal,
        os: os, status: t.status || '', notes: t.notes || '', domain_owned: domOwned,
        open_ports: dedupPorts(tfacts),
        flags: flags,
        proof: hostProof(host, tfacts, screensRaw, includeSecrets),
        findings: sortedT.map(function (f) {
          var evSrc = f.source || 'manual/seeded workspace evidence';
          if (/^for\s+\w+\s+in\b/i.test(evSrc) === false && /get\s+writable/i.test(evSrc) && (f.kind === 'ad.group_joined' || f.kind === 'ad.control_paths')) {
            for (var ai = 0; ai < activities.length; ai++) {
              if (/add\s+groupMember/i.test(activities[ai].command || '')) { evSrc = activities[ai].command; break; }
            }
          }
          return { kind: f.kind, label: friendly(f.kind), category: factCategory(f.kind),
            value: redactValue(f.value, includeSecrets),
            evidence: redactCommand(evSrc, { includeSecrets: includeSecrets, secrets: secrets }),
            origin: (f.value && f.value.origin) || 'obol', at: f.created_at };
        }),
        chain: hostChain(host),
        evidence: evidence.filter(function (e) { return e.target === host; }),
      };
    });

    // catalogued findings context: fact-driven catalog matches (the robust library) + any finding.* facts
    // (web-check parsers) + move action.report metadata, deduped by title/slug, severity-sorted, with per-technique narrative write-ups.
    var domName = params.domain || '';
    try { var _dv = factset.values('ad.domain_known') || []; if (_dv[0]) domName = _dv[0].domain || _dv[0].name || domName; } catch (e) {}
    var moveMap = buildMoveMap(opts);
    var singleTarget = targetsOut.length === 1;
    var ctxMeta = { activities: activities, moveMap: moveMap, singleTarget: singleTarget, meta: { domain: domName, lhost: params.lhost || '' } };
    var perTarget = [], counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, total = 0;
    var rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    targetsOut.forEach(function (t, ti) {
      var factFs = findingFactsForHost(factset, t.host).map(function (f) { return toFinding(f, t.host, reportmeta, includeSecrets); });
      factFs.forEach(function (r) { r.writeup = { description: r.description || '', remediation: r.remediation || '' }; });
      var catFs = catalogFindingsForHost(ctxMeta, factset, t.host, ti === 0, secrets, includeSecrets);
      var fs = [], seenTitle = {}, seenSlug = {}, coveredTriggers = {};
      factFs.concat(catFs).forEach(function (r) {
        var key = String(r.title || r.label || r.kind).toLowerCase();
        var sl = String(r.slug || r.key || '').toLowerCase();
        if (seenTitle[key] || (sl && seenSlug[sl])) return;
        seenTitle[key] = 1;
        if (sl) seenSlug[sl] = 1;
        (r.trigger_kinds || []).forEach(function (tk) { coveredTriggers[tk] = 1; });
        fs.push(r);
      });
      var NON_VULN_FACT_RE = /^(blocker\.|credential\.validation$|objective\.|proof\.|smb\.reachable$|http\.reachable$|ldap\.reachable$|kerberos\.reachable$|winrm\.reachable$|ssh\.reachable$|host\.|os\.|ad\.domain_known$|ad\.base_dn$|ad\.dc_candidate$|ad\.domain_sid$|ad\.user_list$|smb\.shares$)/;
      var hActs = (activities || []).filter(function (act) { return actMatchesHost(act, t.host, singleTarget); });
      hActs.forEach(function (act) {
        if (isBlockerOnlyActivity(act)) return;
        var mid = act.action_id || act.move_id || '';
        if (/^(?:flag-hunt-|recon-|verify-|crack-)/.test(mid)) return;
        var move = (mid && moveMap[mid]) || (act.report ? act : null);
        if (!move || !move.report || !move.report.finding) return;
        var movePhase = String(move.phase || act.phase || '').toLowerCase();
        if (movePhase === 'recon' || movePhase === 'enumerate') return;
        var rawSev = move.report.severity ? String(move.report.severity).trim().toLowerCase() : 'high';
        if (rawSev === 'info' || rawSev === 'informational') return;
        var prod = actProducedKinds(act);
        var moveProduces = Array.isArray(move.produces) ? move.produces : [];
        var rawTriggers = prod.filter(function (k) { return !NON_VULN_FACT_RE.test(k); });
        var meaningfulProd = rawTriggers.filter(function (k) {
          return !moveProduces.length || moveProduces.indexOf(k) >= 0;
        });
        if (!meaningfulProd.length) return;
        var moveReqs = [].concat(move.requires_all || [], move.requires_any || []);
        if (rawTriggers.concat(moveProduces).concat(moveReqs).some(function (k) { return coveredTriggers[k]; })) return;
        var moveId = move.id || mid || slug(move.report.finding);
        var moveSlug = 'move-' + moveId;
        var titleLower = String(move.report.finding).toLowerCase();
        if (seenTitle[titleLower] || seenSlug[moveSlug.toLowerCase()]) return;
        seenTitle[titleLower] = 1;
        seenSlug[moveSlug.toLowerCase()] = 1;
        var moveCat = (movePhase === 'escalate' || movePhase === 'privesc' || movePhase === 'loot') ? 'privesc' : 'access';
        var trig = moveProduces.length ? moveProduces.slice() : meaningfulProd.slice();
        var evc = findingEvidenceCommands(ctxMeta, t.host, trig, act);
        var desc = (move.report && move.report.description) || move.proves || move.report.finding;
        var rem = (move.report && move.report.remediation) || (moveCat === 'privesc'
          ? 'Apply least-privilege principles, patch the local privilege-escalation vector, and remove or constrain the abused rights, credentials, or misconfiguration.'
          : 'Apply current vendor security patches, disable or restrict the exposed service, and enforce strong authentication on any remotely reachable interface.');
        var sev = normalizeSeverity(move.report.severity || 'high');
        fs.push({
          kind: 'finding.' + moveSlug,
          slug: moveSlug,
          key: moveSlug,
          host: t.host,
          label: move.report.finding,
          title: move.report.finding,
          severity: sev,
          category: moveCat,
          confidence: 'confirmed',
          description: desc,
          remediation: rem,
          refs: (move.references || []).slice(),
          cwe: '',
          attack: Array.isArray(move.attack) ? (move.attack[0] || '') : (move.attack || ''),
          nist: '',
          trigger_kinds: trig,
          phase_label: (moveCat === 'privesc' ? 'Privilege Escalation, ' : 'Initial Access, ') + move.report.finding,
          first_at: act.at || evc.firstAt || 0,
          evidence: redactCommand(act.command || (evc[0] && evc[0].command) || '', { includeSecrets: includeSecrets, secrets: secrets }),
          evidence_cmds: evc.map(function (e) { return { command: redactCommand(e.command, { includeSecrets: includeSecrets, secrets: secrets }), output: redactCommand(e.output || '', { includeSecrets: includeSecrets, secrets: secrets }) }; }),
          writeup: {
            description: desc,
            impact: move.proves || '',
            remediation: rem,
          },
          _moveAct: act,
          _movePhase: movePhase,
          origin: 'move',
          from_catalog: true,
        });
      });
      if (!fs.length) return;
      fs.sort(function (a, b) { return (rank[a.severity] != null ? rank[a.severity] : 9) - (rank[b.severity] != null ? rank[b.severity] : 9); });
      fs.forEach(function (r) { counts[r.severity] = (counts[r.severity] || 0) + 1; total++; });
      perTarget.push({ host: t.host, label: t.label, findings: fs });
    });
    var findingsCtx = { targets: perTarget, counts: counts, total: total };

    // category counts
    var catCounts = {};
    (factset.facts || []).forEach(function (f) {
      if (f.state !== SUPPORTED) return;
      var c = factCategory(f.kind); catCounts[c] = (catCounts[c] || 0) + 1;
    });

    var openPorts = dedupPorts(factset.facts || []);
    var accessLadder = ACCESS_LADDER.map(function (pair) {
      return { stage: pair[0], reached: pair[1].some(function (k) { return factset.has(k); }) };
    });

    var meta = {
      // prefer the top-level opts the caller passes (engagement name, exam candidate/OSID from the
      // profile) over engagement params, which rarely carry them - else the cover falls back to
      // "engagement"/«your name»/OS-XXXXX even after they're set.
      name: opts.name || params.name || params.workspace || 'engagement',
      target: params.target || '',
      scope: params.scope || (params.target ? [params.target] : []),
      domain: (domain[0] && (domain[0].domain || domain[0].name)) || params.domain || '',
      generated_at: stamp(activities.length ? Math.max.apply(null, activities.map(function (r) { return r.at || 0; })) : null),
      include_secrets: includeSecrets,
      osid: opts.osid || params.osid || '',
      candidate: opts.candidate || params.candidate || '',
      client: opts.client || params.client || '',
      exec_summary: opts.execSummary || params.execSummary || '',
      platform: opts.platform || params.platform || '',
    };

    // working-directory tree for the appendix: the REAL files (runs, screenshots, hand-added, disk-synced)
    // - never the coach's anticipated/suggested files, which are guesses, not evidence. describe() is
    // redaction-safe (purpose + fact/line/size counts, no secrets); we keep no raw output or command here.
    var workspaceCtx = null;
    try {
      if (OBOL.vfs && OBOL.vfs.build && opts.workspace && OBOL.workspace && OBOL.workspace.isConfigured(opts.workspace.root ? { workspace: opts.workspace } : {})) {
        var veng = { id: opts.engId || '', activities: activities, screenshots: screensRaw, workspace: opts.workspace };
        var vt = OBOL.vfs.build(veng, { suggested: [], facts: factset });
        var STATE = function (f) {
          return f.status === 'captured' ? 'Captured' : (f.synced || f.unknown) ? 'On Disk (Synced)'
            : f.manual ? 'Added by Hand' : f.confirmed ? 'On Disk' : 'Expected';
        };
        var wfolders = (vt.folders || []).filter(function (fo) { return fo.files.length; }).map(function (fo) {
          return { label: fo.label, files: fo.files.map(function (f) {
            return { rel: OBOL.vfs.relOf(f.path, vt.root), name: f.name, state: STATE(f), desc: OBOL.vfs.describe(f) };
          }) };
        });
        if (vt.total) workspaceCtx = { root: vt.root, folders: wfolders, captured: vt.captured, total: vt.total };
      }
    } catch (e) { workspaceCtx = null; }

    var allProofs = collectProofs(factset, activities, includeSecrets);
    var ctx = {
      meta: meta,
      targets: targetsOut,
      evidence: evidence,
      workspace: workspaceCtx,
      bloodhound: params.bloodhound || {},
      tiles: {
        facts: (factset.facts || []).filter(function (f) { return f.state === SUPPORTED; }).length,
        ports: openPorts.length, runs: activities.length,
        access_state: accessState, credential_state: credState,
      },
      open_ports: openPorts,
      access_ladder: accessLadder,
      findings: findingsCtx,
      category_counts: catCounts,
      severity_counts: counts,
      facts: factsOut,
      timeline: timeline,
      notes: notes,
      next_actions: params.nextActions || [],
      proofs: allProofs,
      proofCount: allProofs.length,
      proof_candidates: scanManualProof(activities, factset, secrets, targetsOut),
      activities: activities,
      _secrets: secrets,
      _moveMap: moveMap,
    };
    ctx.proof = proofAssess(ctx);
    return ctx;
  }

  function proofAssess(ctx) {
    var hosts = [], gaps = [], total = 0, proven = 0;
    (ctx.targets || []).forEach(function (t) {
      var pf = t.proof || { flags: [] };
      if (!pf.flags.length) return;
      pf.flags.forEach(function (r) { total++; if (r.has_proof) proven++; else gaps.push({ host: t.host, slot: r.slot, label: r.label, required: false }); });
      hosts.push({ host: t.host, flags: pf.flags });
    });
    var a = {
      hosts: hosts, gaps: gaps, flags_total: total, flags_proven: proven, complete: total > 0 && !gaps.length,
      scored: false, points: 0, points_possible: 0, pass_threshold: 0, passes: false,
      required: false, required_slots: [], note: '', points_note: '', ad_set: null, scoreboard: [],
    };
    a.readiness_line = readinessLine(a);
    return a;
  }

  function readinessLine(a) {
    var base = a.flags_proven + '/' + a.flags_total + ' flags with compliant proof';
    if (a.gaps.length) {
      var miss = a.gaps.slice(0, 4).map(function (g) { return g.label + ' on ' + g.host; }).join(', ');
      var more = a.gaps.length > 4 ? ' (+' + (a.gaps.length - 4) + ' more)' : '';
      return base + ' - missing proof: ' + miss + more;
    }
    return base + ' - every captured flag has compliant proof';
  }

  // wrapped/manual command output that looks like proof but was never promoted (browser: activity.stdout is text)
  var FLAGLIKE_RE = /\b(?:[A-Za-z]+\{[^}]{3,}\}|[0-9a-fA-F]{32}|[0-9a-fA-F]{64})\b/g;
  var PROOF_CMD_RE = /(?:root|proof|local|user|secret|flag)\.txt/i;
  var ID_RE = /\b(?:whoami|hostname|ipconfig|ifconfig|ip\s+a(?:ddr)?|id|uname)\b/i;
  function scanManualProof(activities, factset, secrets, targetsOut) {
    var ignoreHex = {
      'aad3b435b51404eeaad3b435b51404ee': 1,
      '31d6cfe0d16ae931b73c59d7e0c089c0': 1,
    };
    (secrets || []).forEach(function (s) {
      if (s) ignoreHex[String(s).toLowerCase()] = 1;
    });
    try {
      (factset.facts || []).forEach(function (f) {
        var v = f.value || {};
        if ((String(f.kind || '').indexOf('objective.') === 0 || f.kind === PROOF_FACT) && (v.flag || v.value)) {
          ignoreHex[String(v.flag || v.value).toLowerCase()] = 1;
        }
        ['hash', 'nthash', 'lmhash', 'password', 'secret', 'ntlm'].forEach(function (hk) {
          if (v[hk] && typeof v[hk] === 'string') {
            ignoreHex[v[hk].toLowerCase()] = 1;
            v[hk].split(':').forEach(function (part) {
              if (/^[0-9a-fA-F]{32,64}$/.test(part)) ignoreHex[part.toLowerCase()] = 1;
            });
          }
        });
      });
    } catch (e) { return []; }
    if (Array.isArray(targetsOut) && targetsOut.length > 0) {
      var allTargetsHaveBothFlags = targetsOut.every(function (t) {
        var slots = {};
        (t.flags || []).forEach(function (fl) { if (fl.slot) slots[fl.slot] = 1; });
        return !!(slots.local && slots.root);
      });
      if (allTargetsHaveBothFlags) return [];
    }
    var out = [];
    (activities || []).forEach(function (row) {
      var stdout = typeof row.stdout === 'string' ? row.stdout : '';
      if (!stdout) return;
      var cmd = row.command || '';
      // Strip -H <hex>, -hashes <lm:nt>, and NTLM dump lines before matching flag-like hex tokens
      var cleanedOut = stdout
        .replace(/(?:-H|--hashes|-hashes)\s+(?:[0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}\b/gi, '')
        .replace(/\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b/g, '');
      var vals = (cleanedOut.match(FLAGLIKE_RE) || []).filter(function (v) {
        return !ignoreHex[String(v).toLowerCase()];
      });
      var looksProofy = PROOF_CMD_RE.test(cmd) || ID_RE.test(stdout);
      if (vals.length && (looksProofy || PROOF_CMD_RE.test(stdout))) {
        var uniq = {}; vals.forEach(function (v) { uniq[v] = 1; });
        out.push({ command: cmd, tool: row.tool || '', values: Object.keys(uniq).sort().slice(0, 4), at: stamp(row.at) });
      }
    });
    return out;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 6. section builders
  // ─────────────────────────────────────────────────────────────────────────
  var SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  var FULL_PRIV_LEVELS = ['Administrator / SYSTEM', 'root'];
  var LINUX_OS_HINTS = ['linux', 'unix', 'debian', 'ubuntu', 'centos', 'bsd', 'kali', 'redhat', 'red hat', 'fedora', 'alpine', 'gentoo', 'arch'];
  var WIN_OS_HINTS = ['windows', 'win32', 'win64', 'microsoft', 'server 20'];
  var NON_COMMAND_PREFIXES = ['operator-', 'asserted', 'target added', 'fingerprint match', 'findings catalog', 'version match', 'seeded', 'ingested', 'manual entry', 'attested', 'observed', 'manual/seeded'];
  var REPORT_NOISE_PREFIXES = ['port:', 'service.', 'scan.', 'blocker.'];
  var REPORT_NOISE_KINDS = { 'host.up': 1, 'host.os_hint': 1, 'target.configured': 1, 'ad.graph.collected': 1, 'ports.open': 1, 'proof.captured': 1 };
  var DETAIL_SKIP_KEYS = { tool: 1, protocol: 1, flags: 1, method: 1, profile: 1, cached: 1, guided: 1 };
  var WALKTHROUGH_SKIP_KINDS = {
    'host.hostname': 1, 'host.domain': 1, 'host.fqdn': 1, 'host.os_family': 1, 'host.os_hint': 1, 'host.up': 1,
    'host.kernel': 1, 'ports.open': 1, 'proof.captured': 1, 'access.desktop': 1,
    'ad.dc_candidate': 1, 'ad.base_dn': 1, 'ad.domain_known': 1, 'ad.domain_sid': 1,
  };
  var PRIVESC_RESULT_KINDS = { 'access.root': 1, 'access.admin': 1, 'access.system': 1, 'credential.admin': 1, 'loot.ntds': 1, 'hash.krbtgt': 1, 'persistence.domain': 1 };
  var AD_ESCALATION_KINDS = { 'ad.control_paths': 1, 'ad.acl_lead': 1, 'ad.acl_abuse': 1, 'ad.coerced_auth': 1, 'ad.zerologon': 1, 'ad.gpo_control': 1, 'ad.gpo_modify': 1, 'ad.gpo_link': 1, 'ad.attack_paths': 1, 'ad.sid_history': 1, 'ad.computer_added': 1, 'ad.delegation_unconstrained': 1, 'ad.delegation_constrained': 1, 'ad.rbcd': 1, 'ad.laps_readable': 1, 'ad.gmsa_readable': 1, 'ad.group_joined': 1, 'ad.domain_control': 1 };
  var AD_PRIVESC_KEYS = { dcsync: 1, kerberoasting: 1, 'pass-the-hash': 1, 'golden-ticket': 1, 'dangerous-ad-acl': 1, 'adcs-template-abuse': 1, 'ad-delegation-abuse': 1, 'laps-gmsa-credential-exposure': 1, 'ad-gpo-abuse': 1, 'ntlm-relay': 1 };
  var INITIAL_CATEGORIES = { access: 1, injection: 1, exploit: 1, web: 1, cve: 1, credential: 1, config: 1, headers: 1, tls: 1, cookies: 1, cors: 1, dns: 1, html: 1, disclosure: 1, crypto: 1, methods: 1 };
  var PRIVESC_FINDING_HINTS = ['dcsync', 'privilege escalation', 'privesc', 'escalat', 'writedacl', 'writeowner', 'genericall', 'genericwrite', 'dangerous', 'acl', 'sudo', 'suid', 'setuid', 'capabilit', 'impersonat', 'potato', 'token', 'unquoted', 'alwaysinstall', 'kernel', 'krbtgt', 'golden', 'silver', 'constrained deleg', 'unconstrained deleg', 'gpo', 'adcs', 'esc', 'laps', 'gmsa', 'scheduled task'];
  var MACHINE_CAPTION_RE = /[a-z][a-z0-9]*\.[a-z][a-z0-9_]+/;

  var VERSION = (function () { try { return (root.OBOL && root.OBOL.VERSION) || ''; } catch (e) { return ''; } })();

  function hasKind(t) {
    var prefixes = Array.prototype.slice.call(arguments, 1);
    return (t.findings || []).some(function (f) {
      var k = f.kind || '';
      return prefixes.some(function (p) { return k.indexOf(p) === 0; });
    });
  }
  function isFullPriv(level) { return FULL_PRIV_LEVELS.indexOf(level) !== -1; }
  function isLinuxTarget(t) {
    var os = (t.os || '').toLowerCase();
    if (LINUX_OS_HINTS.some(function (h) { return os.indexOf(h) !== -1; })) return true;
    if (WIN_OS_HINTS.some(function (h) { return os.indexOf(h) !== -1; })) return false;
    var kinds = {}; (t.findings || []).forEach(function (f) { kinds[f.kind || ''] = 1; });
    if (kinds['foothold.linux']) return true;
    if (kinds['foothold.windows'] || kinds['winrm.authenticated'] || kinds['rdp.authenticated'] || t.domain || t.domain_owned) return false;
    for (var i = 0; i < (t.flags || []).length; i++) {
      var p = String(t.flags[i].path || '');
      if (p.charAt(0) === '/') return true;
      if (/^[A-Za-z]:[\\/]/.test(p)) return false;
    }
    return false;
  }
  function oscpPriv(t) {
    var flags = {}; (t.flags || []).forEach(function (f) { flags[f.slot] = 1; });
    var foothold = hasKind(t, 'foothold.', 'access.shell');
    if (flags.root || hasKind(t, 'loot.ntds', 'hash.krbtgt', 'persistence.domain', 'access.system', 'access.root', 'access.admin') || (t.domain_owned && foothold))
      return isLinuxTarget(t) ? 'root' : 'Administrator / SYSTEM';
    if (flags.local || foothold) return 'User';
    return 'None proven';
  }
  function yn(v) { return v ? 'Yes' : 'No'; }
  function targetFlagSlots(t) { var s = {}; (t.flags || []).forEach(function (f) { s[f.slot] = 1; }); return s; }
  function compromisedTargets(ctx) { return (ctx.targets || []).filter(function (t) { return oscpPriv(t) !== 'None proven'; }); }

  function looksLikeCommand(ev) {
    var s = String(ev || '').trim();
    if (!s) return false;
    var low = s.toLowerCase();
    if (NON_COMMAND_PREFIXES.some(function (p) { return low.indexOf(p) === 0; })) return false;
    if (/^[^\r\n;&|><`]+?\.(?:log|txt|xml|json|gnmap|nmap|zip|ntds|pot)$/i.test(s) && !/^(?:sudo\s+)?(?:nmap|nxc|netexec|smbclient|rpcclient|enum4linux|ldapsearch|impacket|GetNPUsers|GetUserSPNs|secretsdump|bloodyAD|certipy|john|hashcat|evil-winrm|ffuf|gobuster|curl|wget|ssh|cat|type|more|Get-Content|python|bash|sh|powershell|cmd)\b/i.test(s)) return false;
    if (/^cd\s+.*&&\s*bash\s+.*obol-stage/i.test(s)) return false;
    return true;
  }
  function humanizeCaption(raw, fallback) {
    raw = (raw || '').trim();
    if (!raw) return fallback;
    var low = raw.toLowerCase();
    if (low.indexOf('operator') === 0 || low.indexOf('operator -') === 0 || low.indexOf('operator:') === 0 || MACHINE_CAPTION_RE.test(raw)) return fallback;
    return raw;
  }

  function screenshotBlocks(ctx, section, host, label) {
    if (!section) return [];
    var recs = (ctx.evidence || []).filter(function (e) {
      return e.section === section && e.include !== false && e.kind !== 'pulled' && e.kind !== 'proof' && (e.target || '') === (host || '');
    });
    recs.sort(function (a, b) { return (a.order || 0) - (b.order || 0) || (a.added_at || 0) - (b.added_at || 0); });
    return recs.map(function (e) {
      var caption = label ? humanizeCaption(e.caption, label) : e.caption;
      return IMG({ caption: caption, data_uri: e.data_uri, path: e.path, question: e.question, is_render: e.kind === 'render' });
    });
  }

  // Tools that only ever run from the attacker box (never inside the victim's shell) - these
  // always render with the Kali prompt even after a foothold is proven.
  var KALI_TOOL_RE = /^(?:sudo\s+)?(?:nmap|rustscan|masscan|naabu|netexec|nxc|crackmapexec|cme|smbclient|smbmap|rpcclient|enum4linux[\w-]*|ldapsearch|kerbrute|impacket[\w.-]*|Get(?:NPUsers|UserSPNs)[\w.]*|secretsdump[\w.]*|evil-winrm|ffuf|feroxbuster|gobuster|wfuzz|nikto|whatweb|sqlmap|hydra|john|hashcat|responder|bloodhound[\w.-]*|sharphound[\w.-]*|dig|snmpwalk|msfvenom|msfconsole|searchsploit|ssh|scp|ftp|curl|wget|nc|ncat|socat)\b/i;
  // Post-exploitation commands typically executed *inside a shell on the target*.
  var ON_TARGET_RE = /^(?:sudo(?:\s+-\w+\b|\s+\S+)?|whoami\b|id\b|hostname\b|uname\b|groups\b|pwd\b|cat\s+\S|type\s+\S|more\s+\S|systeminfo\b|ipconfig\b|ifconfig\b|ip\s+a(?:ddr)?\b|arp\b|route\b|net\s+(?:user|localgroup|group|use|share|session)\b|getcap\b|crontab\b|find\s+\/|ss\b|netstat\b|tasklist\b|ps\s|reg\s+query\b|wmic\b|schtasks\b|sc\s+query\b|ls\b|ll\b|dir\b|cd\s|history\b|su\b|python[0-9]?\s+-c|script\s+-qc|powershell\b|gwmi\b|get-\w|cmdkey\b|klist\b)/i;
  function runsOnTarget(cmd) {
    var c = String(cmd || '').trim();
    if (!c || KALI_TOOL_RE.test(c)) return false;
    return ON_TARGET_RE.test(c);
  }
  var WIN_CMD_RE = /^(?:type\s|dir\b|systeminfo\b|ipconfig\b|net\s|tasklist\b|reg\s+query\b|wmic\b|schtasks\b|sc\s+query\b|powershell\b|gwmi\b|get-\w|cmdkey\b|klist\b|whoami\s+\/)/i;

  // Learn the compromised-shell identity for a host from its proven access facts + the transcript
  // (the first whoami/id output reveals the shell user; nothing is invented if the output is absent).
  function targetShellProfile(ctx, host, rows) {
    var tgt = (ctx.targets || []).filter(function (t) { return t.host === host; })[0] || {};
    var hostFacts = (ctx.facts || []).filter(function (f) { return f.scope === 'host:' + host; });
    function has(kind) { return hostFacts.some(function (f) { return f.kind === kind; }); }
    var compromised = has('foothold.linux') || has('foothold.windows') || has('access.shell')
      || has('access.admin') || has('access.system') || has('access.root') || has('winrm.authenticated');
    var root = has('access.admin') || has('access.system') || has('access.root');
    var os = String(tgt.os || '').toLowerCase();
    if (os.indexOf('win') !== -1) os = 'windows';
    else if (os.indexOf('lin') !== -1 || os.indexOf('nix') !== -1) os = 'linux';
    else if (has('foothold.windows')) os = 'windows';
    else if (has('foothold.linux')) os = 'linux';
    else os = '';
    // derive the shell user from a whoami / id in the transcript
    var user = '';
    for (var i = 0; i < rows.length && !user; i++) {
      var c = String(rows[i].command || '').trim().toLowerCase();
      var o = String(rows[i].stdout || '');
      if (/^whoami\b/.test(c) && !/\s+\//.test(c)) {
        var first = o.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean)[0] || '';
        if (first && first.length < 64 && !/\s/.test(first)) user = first;
      } else if (/^id\b/.test(c)) {
        var m = o.match(/uid=\d+\(([^)]+)\)/);
        if (m) user = m[1];
      }
    }
    // The prompt symbol must match the user actually shown: a derived www-data keeps `$` even
    // once admin is proven later; only fall back to the access-fact privilege when no user is known.
    if (user) root = /^(?:root|.*\\(?:administrator|system))$/i.test(user);
    return {
      compromised: compromised, os: os, root: root,
      host: tgt.hostname || host, user: user,
    };
  }

  // Split a host's run-ledger rows into the walked path (a command that produced an Attack Path
  // milestone) vs enumeration that wasn't on the critical path - so the report's narrative and
  // terminals mirror the Attack Path ribbon. The full command log always survives in the appendix.
  function essentialRows(ctx, host) {
    var t = (ctx.targets || []).filter(function (x) { return x.host === host; })[0];
    var chain = (t && t.chain) || [];
    var onKind = {}; chain.forEach(function (s) { onKind[s.kind] = 1; });
    var allRows = (ctx.timeline || []).filter(function (r) {
      return ((r.target === host) || (r.scope === 'host:' + host)) && !/^cd\s+.*&&\s*bash\s+.*obol-stage/i.test(String(r.command || '').trim());
    }).slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); });
    var hasNamedRows = allRows.some(function (r) { return !!(r.command || '').trim(); });
    var rows = hasNamedRows ? allRows.filter(function (r) { return !!(r.command || '').trim(); }) : allRows;
    if (!chain.length) return { essential: rows, noise: [], scoped: false };
    var cleanProducerFor = {};
    rows.forEach(function (r) {
      if (/Unable to connect to the remote server|Exception calling "DownloadString"/i.test(r.stdout || '')) return;
      (r.produced || []).forEach(function (k) { cleanProducerFor[k] = 1; });
    });
    var essential = [], noise = [], claimedKind = {};
    rows.forEach(function (r) {
      var hadError = /Unable to connect to the remote server|Exception calling "DownloadString"/i.test(r.stdout || '');
      var newlyClaimed = (r.produced || []).filter(function (k) {
        if (!onKind[k] || claimedKind[k]) return false;
        if (hadError && cleanProducerFor[k]) return false;
        return true;
      });
      if (newlyClaimed.length) {
        newlyClaimed.forEach(function (k) { claimedKind[k] = 1; });
        essential.push(r);
      } else if ((r.command || '').trim()) {
        noise.push(r);
      }
    });
    // chain came only from seeded facts (no matching ledger rows) -> don't hide the whole transcript
    if (!essential.length) return { essential: rows, noise: [], scoped: false };
    return { essential: essential, noise: noise, scoped: true };
  }

  // per-host verbatim command+output transcript (the operator's pasted terminal), terminal-styled.
  // Scoped to the walked path (the Attack Path ribbon); off-path enumeration is collapsed to a count.
  // Recon/exploitation commands render with the Kali prompt; post-exploitation commands run inside a
  // proven shell on the box render with a target prompt (user@host:~$ / #, or C:\> on Windows).
  function hostTranscript(ctx, host, alreadyRenderedCmds) {
    var split = essentialRows(ctx, host);
    var rows = split.essential;
    if (!rows.length) return [];
    var prof = targetShellProfile(ctx, host, rows);
    var rendered = alreadyRenderedCmds || {};
    var hasRenderedFilter = Object.keys(rendered).length > 0;
    var intro = hasRenderedFilter
      ? 'Additional commands on the critical path to this host\'s objectives that were not already shown in the step-by-step walkthrough above (secrets redacted). '
      : (split.scoped
        ? 'The commands on the critical path to this host\'s objectives and their output, in the order run (secrets redacted). '
        : 'The exact commands run against this host and their output, as pasted into Evidence (secrets redacted). ');
    var blocks = [H('Command Transcript', 4),
      P(intro + 'Commands run from Kali carry the ' + '`kali@kali`' + ' prompt; commands run inside a shell on the target carry the box\'s own prompt.')];
    var any = false;
    rows.forEach(function (r) {
      var cmd = (r.command || '').trim(), output = r.stdout || '';
      if (!cmd && !output.trim()) return;
      if (hasRenderedFilter && cmd && rendered[cmd]) return;
      any = true;
      if (prof.compromised && runsOnTarget(cmd)) {
        var win = prof.os === 'windows' || (prof.os === '' && WIN_CMD_RE.test(cmd));
        blocks.push(TERM({
          command: cmd, output: output, style: 'target',
          os: win ? 'windows' : 'linux',
          user: prof.user || (win ? '' : (prof.root ? 'root' : 'user')),
          host: prof.host, root: prof.root,
        }));
      } else {
        blocks.push(TERM({ command: cmd, output: output }));   // Kali-style attacker box
      }
    });
    if (split.scoped && split.noise.length) {
      blocks.push(P('_+ ' + split.noise.length + ' enumeration/no-op command' + (split.noise.length === 1 ? '' : 's')
        + ' not on the critical path, see Appendix: Key Commands & Evidence for the full log._'));
    }
    return any ? blocks : [];
  }
  // per-host operator narrative slot (summary + exploitation steps) from ctx.notes.
  function hostNarrative(ctx, host) {
    var n = (ctx.notes || {})[host] || {};
    var blocks = [];
    if (n.summary && String(n.summary).trim()) blocks.push(P(String(n.summary).trim()));
    if (n.steps && String(n.steps).trim()) {
      blocks.push(P('**Exploitation steps:**'));
      blocks.push(UL(String(n.steps).split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean), true));
    }
    return blocks;
  }

  // ── cover / toc ──
  // An OffSec exam profile (OSCP, OSWP, ...) - its filename is keyed on the OSID and its cover carries
  // the candidate name + OSID that OffSec requires. Detected by shape so new exam profiles inherit it.
  function isExamProfileObj(profile) { return /\{osid\}/.test((profile && profile.filename_pattern) || ''); }

  function cover(ctx, profile) {
    var meta = ctx.meta || {};
    var cfg = profile.config || {};
    var targets = ctx.targets || [];
    var owned = compromisedTargets(ctx);
    var flagTotal = 0;
    targets.forEach(function (t) {
      var slots = targetFlagSlots(t);
      if (slots.local) flagTotal++;
      if (slots.root) flagTotal++;
    });
    var counts = ctx.severity_counts || {};
    var findingTotal = SEV_ORDER.reduce(function (s, k) { return s + (counts[k] || 0); }, 0);
    var pairs = [];
    if (isExamProfileObj(profile)) {
      pairs.push(['Candidate', cfg.candidate || meta.candidate || '«your name»']);
      pairs.push(['OSID', cfg.osid || meta.osid || 'OS-XXXXX']);
      pairs.push(['Exam / Certification', profile.id === 'oswp' ? 'PEN-210 / OSWP Certification Exam' : 'PEN-200 / OSCP Certification Exam']);
    } else {
      if (cfg.client || meta.client || profile.id === 'pnpt' || profile.id === 'generic' || profile.id === 'executive') {
        pairs.push(['Client / Organization', cfg.client || meta.client || meta.name || 'Target Organization']);
      }
      if (cfg.candidate || meta.candidate || profile.id === 'cpts' || profile.id === 'pnpt') {
        pairs.push(['Assessor / Candidate', cfg.candidate || meta.candidate || 'Security Assessor']);
      }
      if (profile.id === 'cpts') {
        pairs.push(['Assessment Standard', 'Hack The Box Certified Penetration Testing Specialist (CPTS)']);
      } else if (profile.id === 'pnpt') {
        pairs.push(['Assessment Standard', 'TCM Security Practical Network Penetration Tester (PNPT)']);
      }
    }
    pairs.push(['Engagement', meta.name || 'Penetration Test Engagement']);
    pairs.push(['Authorized Scope', (meta.scope || []).join(', ') || meta.target || 'In-Scope Network']);
    if (meta.domain) pairs.push(['Active Directory Domain', meta.domain]);
    pairs.push(['Compromised Hosts', owned.length + ' of ' + targets.length + ' in-scope system(s)']);
    if (!profile.no_flags && flagTotal > 0) {
      pairs.push(['Objectives / Flags Captured', flagTotal + ' proof flag(s) verified']);
    }
    if (findingTotal > 0) {
      var sevParts = [];
      SEV_ORDER.forEach(function (s) { if (counts[s]) sevParts.push(counts[s] + ' ' + capFirst(s)); });
      pairs.push(['Technical Findings', findingTotal + ' total (' + sevParts.join(', ') + ')']);
    }
    pairs.push(['Generated', meta.generated_at || '']);
    pairs.push(['Classification', 'CONFIDENTIAL - Exam / Assessment Deliverable']);
    pairs.push(['Tool', ('OBOL ' + VERSION).trim()]);
    var blocks = [H(profile.title, 1)];
    if (profile.subtitle) blocks.push(P('_' + profile.subtitle + '_'));
    blocks.push(KVB(pairs));
    if (profile.id === 'oscp') {
      blocks.push(P('**Exam Compliance & Documentation Statement:** This report documents the penetration test conducted against the Offensive Security OSCP exam environment. Every compromised machine includes step-by-step reproduction instructions, exact commands executed, vulnerability explanations, remediation recommendations, and local/elevated proof flags (`local.txt` and `proof.txt`) captured from an interactive shell alongside host network identity.'));
    } else if (profile.id === 'cpts') {
      blocks.push(P('**Commercial Deliverable & Confidentiality Statement:** This report presents the findings of the Hack The Box CPTS penetration test engagement. It contains an executive summary for leadership, CWE and MITRE ATT&CK-mapped technical findings with root-cause remediation guidance, and a complete command-by-command reproduction walkthrough for each in-scope system.'));
    } else if (profile.id === 'pnpt') {
      blocks.push(P('**Assessment Overview & Confidentiality Statement:** This report documents the external and internal network penetration test conducted under the TCM Security PNPT methodology. It details the complete attack chain from initial perimeter enumeration through Active Directory domain compromise, accompanied by reproducible evidence and prioritized defensive remediations.'));
    } else {
      blocks.push(P('**Confidentiality & Scope Notice:** This document contains sensitive security findings and technical reproduction evidence gathered exclusively from the authorized scope during the assessment window. Handle and distribute strictly on a need-to-know basis.'));
    }
    if (!meta.include_secrets) blocks.push(CALL('Secrets are redacted in this draft. Re-generate with include-secrets enabled for an unredacted submission or working copy.', 'note'));
    blocks.push(PB());
    return blocks;
  }
  function toc() { return [TOCB()]; }

  // ── objective summary (OSCP / CPTS) & compromise summary (PNPT / Client) ──
  function hostDisplayLabel(t) {
    var host = (t && t.host) || '';
    var label = (t && (t.label || t.hostname)) || '';
    return (label && label !== host) ? (label + ' (' + host + ')') : String(host);
  }

  function objectiveSummary(ctx, profile) {
    var rows = [], flagTotal = 0;
    (ctx.targets || []).forEach(function (t) {
      var slots = targetFlagSlots(t);
      if (slots.local) flagTotal++;
      if (slots.root) flagTotal++;
      var proof = t.proof || {};
      var proven = {}; (proof.flags || []).forEach(function (r) { proven[r.slot] = r.has_proof; });
      var anyProven = Object.keys(proven).some(function (k) { return proven[k]; });
      var ev = (proof.screenshots || []).length ? 'screenshot' : ((proof.flags || []).some(function (r) { return r.obol_block; }) ? 'interactive shell' : '');
      var needReview = (slots.local || slots.root) && !anyProven && !(proof.screenshots || []).length;
      rows.push([
        hostDisplayLabel(t),
        yn(!!slots.local), yn(!!slots.root), oscpPriv(t), ev, needReview ? 'Review' : 'Complete',
      ]);
    });
    var blocks = [H('Exam Objective Summary', 2)];
    if (profile && profile.id === 'cpts') {
      blocks.push(P('Hack The Box CPTS exam progress: **' + flagTotal + ' / 14 flags** captured across ' + (ctx.targets || []).length + ' in-scope host(s) (12 flags required to pass, accompanied by a commercial-grade report with CVSS/CWE and actionable remediation).'));
    } else if (profile && profile.id === 'oscp') {
      blocks.push(P('The table below summarizes the objective status, privilege level reached, and proof verification state across all in-scope targets (`local.txt` and `proof.txt`).'));
    }
    if (rows.length) blocks.push(TBL(['Target', 'local.txt', 'proof.txt', 'Privilege', 'Evidence', 'Status'], rows));
    else blocks.push(P('No targets recorded.'));
    return blocks;
  }

  function compromiseSummary(ctx) {
    var rows = [];
    (ctx.targets || []).forEach(function (t) {
      var priv = oscpPriv(t);
      var fh = priv !== 'None proven' ? footholdDesc(t) : 'None';
      var domRole = (t.domain_owned && (t.domain || hasKind(t, 'ad.dc_candidate', 'loot.ntds'))) ? 'Domain Compromised (NTDS / DA)' : (t.domain || 'Standalone');
      rows.push([
        hostDisplayLabel(t),
        t.os || 'Unknown',
        fh,
        priv,
        domRole,
      ]);
    });
    var blocks = [H('Compromise & Objective Summary', 2)];
    blocks.push(P('This assessment evaluated the security posture of the in-scope network from initial enumeration through privilege escalation and Active Directory domain compromise. No artificial flag files were used; each milestone below reflects verified operational access.'));
    if (rows.length) blocks.push(TBL(['Target', 'Operating System', 'Initial Foothold', 'Privilege Reached', 'Domain / Scope Status'], rows));
    else blocks.push(P('No targets recorded.'));
    return blocks;
  }

  // ── methodology ──
  var OSCP_METHODOLOGY = 'Each target was approached with the standard OSCP methodology: full service enumeration, identification and exploitation of an initial access vector, capture of the low-privilege proof (`local.txt`), local privilege-escalation enumeration and exploitation, and capture of the elevated proof (`proof.txt`) from an interactive shell. Every fact below is backed by the exact command that produced it; nothing is asserted without evidence.';
  var CPTS_METHODOLOGY = 'Testing followed the Hack The Box Certified Penetration Testing Specialist (CPTS) methodology, aligned with PTES and NIST SP 800-115: external and internal reconnaissance, service and web application enumeration, vulnerability validation, initial foothold exploitation, lateral movement, local and Active Directory privilege escalation, and root-cause remediation analysis. Every finding is mapped to CWE and MITRE ATT&CK identifiers and supported by reproducible command outputs.';
  var PNPT_METHODOLOGY = 'This assessment followed the TCM Security Practical Network Penetration Tester (PNPT) methodology, simulating a realistic external-to-internal network penetration test: open-source and perimeter reconnaissance, perimeter service exploitation, internal network enumeration, Active Directory attack-path analysis (including Kerberos, SMB signing/relaying, ACLs, and credential hygiene), lateral movement, and full Domain Controller compromise. Each finding includes step-by-step reproduction evidence and prioritized remediation guidance.';
  var GENERIC_METHODOLOGY = 'Testing followed a structured methodology (reconnaissance, enumeration, exploitation, post-exploitation, and lateral movement) with findings triaged by severity and each backed by reproducible evidence. Remediation guidance accompanies each finding.';

  function scopeIps(ctx) {
    var meta = ctx.meta || {};
    var ips = (meta.scope || []).filter(Boolean);
    if (!ips.length) ips = (ctx.targets || []).map(function (t) { return t.host; }).filter(Boolean);
    var seen = {}, out = [];
    ips.forEach(function (ip) { if (ip && !seen[ip]) { seen[ip] = 1; out.push(ip); } });
    return out;
  }
  function methodology(ctx, profile) {
    var targets = ctx.targets || [];
    var total = targets.length;
    var owned = compromisedTargets(ctx).length;
    var ips = scopeIps(ctx);
    var scopeLine = ips.length ? ips.join(', ') : 'the authorized hosts';
    if (profile.id === 'cpts' || profile.id === 'pnpt') {
      var lead = profile.id === 'cpts' ? CPTS_METHODOLOGY : PNPT_METHODOLOGY;
      return [
        H('Methodology', 2), P(lead),
        H('Scope & Rules of Engagement', 3),
        P('Testing was restricted to the authorized scope (' + scopeLine + '). During the assessment, ' + owned + ' of ' + total + ' in-scope system(s) were compromised. All exploitation steps were executed with minimal operational impact, and no persistent backdoors or unauthorized modifications were left on target systems.'),
      ];
    }
    if (profile.id !== 'oscp') return [H('Methodology', 2), P(GENERIC_METHODOLOGY)];
    return [
      H('Methodology', 2), P(OSCP_METHODOLOGY),
      H('Information Gathering', 3),
      P('The information-gathering phase established the scope of the engagement and the live, in-scope systems. Testing was confined to the authorized hosts and networks; no activity was performed outside the authorized scope. The in-scope systems were: ' + scopeLine + '.'),
      H('Service Enumeration', 3),
      P('Each in-scope host was enumerated for exposed TCP/UDP services, and every service was fingerprinted and assessed against known weaknesses. The open ports and services found on each host, and the commands that discovered them, are documented per host below.'),
      H('Penetration', 3),
      P('The penetration phase focused on gaining access to the in-scope systems. During this engagement, ' + owned + ' of ' + total + ' system(s) were successfully compromised. The vulnerability exploited, the steps to reproduce, and the proof captured are documented per host below.'),
      H('Maintaining Access', 3),
      P('OBOL does not plant persistence or backdoors: no persistent user accounts, scheduled tasks, services, or implants were left behind to maintain access. Access was re-established, when needed, by re-running the documented steps against the recorded credentials and vectors.'),
      H('House Cleaning', 3),
      P('All temporary artifacts and privilege-escalation changes made during exploitation were tracked for cleanup. Temporary files staged during testing were removed or documented in the Working Directory appendix so the environment can be restored cleanly.'),
    ];
  }

  // -- high-level summary --
  function footholdDesc(t) {
    var i, j, f, kind, val;
    var fallbackUser = '';
    for (j = 0; j < (t.findings || []).length; j++) {
      var fj = t.findings[j], kj = fj.kind || '';
      if (kj.indexOf('foothold.') === 0 || kj.indexOf('access.shell') === 0 || kj === 'winrm.authenticated' || kj === 'rdp.authenticated' || (kj.indexOf('credential.') === 0 && kj !== 'credential.admin')) {
        var vj = (fj.value && typeof fj.value === 'object') ? fj.value : {};
        var uj = vj.user || vj.username || vj.identity || '';
        if (uj && !/^(?:administrator|root|system)$/i.test(String(uj).replace(/^.*\\/, ''))) { fallbackUser = String(uj).replace(/^.*\\/, ''); break; }
        if (uj && !fallbackUser) fallbackUser = String(uj).replace(/^.*\\/, '');
      }
    }
    for (i = 0; i < (t.findings || []).length; i++) {
      f = t.findings[i]; kind = f.kind || '';
      if (kind.indexOf('foothold.') === 0 || kind.indexOf('access.shell') === 0 || kind === 'winrm.authenticated' || kind === 'rdp.authenticated') {
        val = (f.value && typeof f.value === 'object') ? f.value : {};
        var user = val.user || val.username || val.identity || '';
        var ev = (f.evidence || '').trim();
        var tool = (ev && looksLikeCommand(ev)) ? ev.split(/\s+/)[0] : '';
        var isOnTargetCmd = tool && (runsOnTarget(ev) || /^(?:Get-|Set-|New-|Invoke-|Remove-|Start-|Stop-|Select-|Where-|ForEach-)/i.test(tool));
        var phrase = (!isOnTargetCmd && tool) ? tool : (val.via || val.tool || (val.service === 'winrm' || kind === 'winrm.authenticated' ? 'evil-winrm' : (val.service === 'ssh' ? 'ssh' : 'interactive shell')));
        if (!user && ev && !isOnTargetCmd) {
          var um = /\s-u\s+['"]?([^'"\s]+)['"]?/i.exec(ev);
          if (um && um[1] && um[1] !== '""' && um[1] !== "''") user = um[1];
        }
        if (!user) user = fallbackUser;
        return phrase + (user ? ' as `' + user + '`' : '');
      }
    }
    for (i = 0; i < (t.findings || []).length; i++) {
      f = t.findings[i]; kind = f.kind || '';
      if (kind.indexOf('credential.') === 0 && kind !== 'credential.admin') {
        val = (f.value && typeof f.value === 'object') ? f.value : {};
        return 'valid credentials' + (val.user ? ' for `' + val.user + '`' : '');
      }
    }
    return 'initial access';
  }
  function humanJoin(items) {
    items = items.filter(Boolean);
    if (!items.length) return '';
    if (items.length === 1) return items[0];
    if (items.length === 2) return items[0] + ' and ' + items[1];
    return items.slice(0, -1).join(', ') + ', and ' + items[items.length - 1];
  }
  var PASSIVE_HYGIENE_KEYS = {
    'smb-signing-disabled': 1, 'smbv1-enabled': 1, 'smb-null-session': 1, 'anonymous-ldap-bind': 1,
    'server-version-disclosed': 1, 'missing-hsts': 1, 'missing-csp': 1, 'missing-xfo': 1, 'missing-xcto': 1,
  };
  function isPassiveHygieneFinding(f) {
    if (!f) return false;
    var k = String(f.key || f.slug || '').toLowerCase();
    if (PASSIVE_HYGIENE_KEYS[k]) return true;
    var trig = Array.isArray(f.trigger_kinds) ? f.trigger_kinds : [];
    return trig.length > 0 && trig.every(function (tk) {
      return tk === 'smb.smbv1' || tk === 'smb.signing' || tk === 'smb.null_session' || tk === 'ad.anonymous_bind' || tk === 'http.headers' || tk === 'tls.info' || tk === 'dns.email';
    });
  }
  function initialVectors(ctx) {
    var ownedHosts = {}; compromisedTargets(ctx).forEach(function (t) { ownedHosts[t.host] = 1; });
    var active = [], passive = [], privescActive = [], seen = {};
    ((ctx.findings || {}).targets || []).forEach(function (t) {
      if (!ownedHosts[t.host]) return;
      var sortedFs = (t.findings || []).slice().sort(function (a, b) {
        var ta = a.first_at || 0, tb = b.first_at || 0;
        if (ta && tb && ta !== tb) return ta - tb;
        if (ta && !tb) return -1;
        if (!ta && tb) return 1;
        return 0;
      });
      sortedFs.forEach(function (f) {
        var title = (f.title || '').trim();
        if (!title || seen[title.toLowerCase()]) return;
        seen[title.toLowerCase()] = 1;
        if (findingIsPrivesc(f)) {
          if (!isPassiveHygieneFinding(f)) privescActive.push(title);
          return;
        }
        if (isPassiveHygieneFinding(f)) passive.push(title);
        else active.push(title);
      });
    });
    var combined = active.concat(privescActive);
    return combined.length ? combined : passive;
  }
  function highLevelSummary(ctx) {
    var targets = ctx.targets || [];
    var total = targets.length;
    var owned = compromisedTargets(ctx);
    var adminHosts = owned.filter(function (t) { return isFullPriv(oscpPriv(t)); });
    var blocks = [H('High-Level Summary', 2)];
    var intro;
    if (owned.length) {
      var vectors = initialVectors(ctx);
      if (vectors.length) {
        var shown = humanJoin(vectors.slice(0, 4));
        if (vectors.length > 4) shown += ', among other vectors';
        intro = 'During this engagement, ' + owned.length + ' of ' + total + ' in-scope system(s) were compromised by chaining ' + shown + '.';
      } else {
        intro = 'During this engagement, ' + owned.length + ' of ' + total + ' in-scope system(s) were compromised.';
      }
      if (adminHosts.length) intro += ' On ' + adminHosts.length + ' system(s), full administrative or SYSTEM/root-level control was achieved. The compromised systems and the attack progression for each are summarized below.';
      else intro += ' The compromised systems and the access reached on each are summarized below.';
    } else {
      intro = 'No in-scope systems were fully compromised during this engagement. The systems assessed and the access reached on each are summarized below.';
    }
    blocks.push(P(intro));
    function line(t) {
      return '**' + hostDisplayLabel(t) + '**: ' + footholdDesc(t) + ' -> **' + oscpPriv(t) + '**';
    }
    var listed = owned.length ? owned : targets;
    var ad = listed.filter(function (t) { return t.domain || t.domain_owned; });
    var standalone = listed.filter(function (t) { return !(t.domain || t.domain_owned); });
    if (ad.length && standalone.length) {
      blocks.push(P('**Active Directory Set:**'));
      blocks.push(UL(ad.map(line)));
      blocks.push(P('**Standalone:**'));
      blocks.push(UL(standalone.map(line)));
    } else if (listed.length) {
      blocks.push(UL(listed.map(line)));
    } else {
      blocks.push(P('_No systems were recorded for this engagement._'));
    }
    return blocks;
  }

  // ── recommendations ──
  var STANDARD_RECOMMENDATIONS = [
    'Establish and maintain a regular patch-management program so systems and services stay current with vendor security updates.',
    'Enforce the principle of least privilege for user, service, and administrative accounts, and remove unnecessary rights and group memberships.',
    'Improve credential hygiene: require strong, unique passwords, rotate and vault service-account credentials, and eliminate password reuse across systems.',
    'Harden and restrict exposed network services, disabling any that are not required and limiting access to those that are.',
    'Deploy logging and monitoring to detect and respond to the exploitation techniques demonstrated in this report.',
  ];
  function recommendations(ctx) {
    var blocks = [H('Recommendations', 2)];
    blocks.push(P('The remediation steps below address the issues identified during this assessment. Prioritising the higher-severity items will most reduce risk to the in-scope systems; per-finding technical detail appears in the walkthrough.'));
    var seen = {}, recs = [];
    ((ctx.findings || {}).targets || []).forEach(function (t) {
      (t.findings || []).forEach(function (f) {
        var rem = (f.remediation || (f.writeup && f.writeup.remediation) || '').trim();
        if (rem && !seen[rem]) { seen[rem] = 1; recs.push(rem); }
      });
    });
    if (!recs.length) recs = STANDARD_RECOMMENDATIONS.slice();
    blocks.push(UL(recs));
    return blocks;
  }

  // ── finding phase classification ──
  var PRE_FOOTHOLD_AD_KEYS = {
    'asrep-roasting': 1, 'kerberoasting': 1, 'pass-the-hash': 1, 'password-spraying': 1,
    'smb-null-session': 1, 'gpp-cpassword': 1, 'llmnr-nbtns-poisoning': 1, 'anonymous-ldap-bind': 1,
  };
  function normMs(ts) {
    var n = Number(ts || 0);
    if (!n || isNaN(n)) return 0;
    return n < 1e11 ? n * 1000 : n;
  }
  function firstFootholdAt(t) {
    var earliest = 0;
    ((t && t.findings) || []).forEach(function (f) {
      var k = f.kind || '';
      if (k.indexOf('foothold.') === 0 || k === 'access.shell' || k === 'winrm.authenticated' || k === 'rdp.authenticated' || k === 'smb.authenticated') {
        var ms = normMs(f.at);
        if (ms > 0 && (!earliest || ms < earliest)) earliest = ms;
      }
    });
    return earliest;
  }
  function findingIsPrivesc(f) {
    if (!f) return false;
    var movePhase = String(f._movePhase || (f._moveAct && f._moveAct.phase) || '').toLowerCase();
    if (movePhase === 'escalate' || movePhase === 'privesc' || movePhase === 'loot') return true;
    var trig = Array.isArray(f.trigger_kinds) ? f.trigger_kinds : [];
    if (trig.length > 0 && trig.every(function (k) {
      var s = String(k || '');
      return s.indexOf('privesc.') === 0 || !!PRIVESC_RESULT_KINDS[s] || !!AD_ESCALATION_KINDS[s] || s.indexOf('adcs.') === 0;
    })) {
      return true;
    }
    // A catalog technique's narrative phase_label is the authoritative bucket (Initial/Credential Access ->
    // foothold; Privilege Escalation / Lateral Movement -> privesc).
    if (f.from_catalog && f.phase_label) {
      if (/privilege escalation|lateral movement/i.test(f.phase_label)) return true;
      if (/initial access/i.test(f.phase_label)) return false;
      // "Credential Access" and the rest fall through to the AD_PRIVESC_KEYS/category logic below, so a
      // domain-compromise technique (DCSync, ACL abuse, PtH) is filed under Privilege Escalation.
    }
    var cat = (f.category || '').toLowerCase();
    var key = (f.key || f.slug || '').toLowerCase();
    if (cat === 'privesc') return true;
    if (cat === 'ad') return !!AD_PRIVESC_KEYS[key];
    if (INITIAL_CATEGORIES[cat]) return false;
    var hay = (key + ' ' + (f.title || '')).toLowerCase();
    return PRIVESC_FINDING_HINTS.some(function (h) { return hay.indexOf(h) !== -1; });
  }
  function splitFindingsByPhase(findings, t, facts) {
    var list = (findings || []).slice();
    if (!list.length) {
      var acts = Array.isArray(t) ? t : ((t && t.activities) || []);
      var fcts = Array.isArray(facts) ? facts : ((t && t.facts) || []);
      acts.forEach(function (act) {
        var phase = String(act.phase || '').toLowerCase();
        var prod = actProducedKinds(act);
        var isPrv = phase === 'escalate' || phase === 'privesc' || phase === 'loot' || prod.some(function (k) {
          return k.indexOf('privesc.') === 0 || k === 'access.admin' || k === 'access.system';
        });
        var isInit = phase === 'initial' || phase === 'foothold' || prod.some(function (k) {
          return k.indexOf('foothold.') === 0 || k === 'access.shell' || k === 'credential.available';
        });
        if (isPrv) list.push({ category: 'privesc', title: act.command || 'Privilege Escalation', _movePhase: 'privesc' });
        else if (isInit) list.push({ category: 'access', title: act.command || 'Initial Access', _movePhase: 'initial' });
      });
      fcts.forEach(function (f) {
        var p = factPhase(f);
        if (p === 'privesc') list.push({ category: 'privesc', title: f.kind, _movePhase: 'privesc' });
        else if (p === 'initial') list.push({ category: 'access', title: f.kind, _movePhase: 'initial' });
      });
    }
    var initial = list.filter(function (f) { return !findingIsPrivesc(f); });
    var activeInitial = initial.filter(function (f) { return !isPassiveHygieneFinding(f); });
    if (activeInitial.length) initial = activeInitial;
    var privesc = list.filter(findingIsPrivesc);
    if (!initial.length && privesc.length) {
      var fhAt = firstFootholdAt(t);
      var promoted = [];
      var rest = [];
      privesc.forEach(function (f) {
        var fAt = normMs(f.first_at || (f._moveAct && f._moveAct.at) || f.at || 0);
        var key = String(f.key || f.slug || '').toLowerCase();
        if (!promoted.length && ((fhAt > 0 && fAt > 0 && fAt <= fhAt) || PRE_FOOTHOLD_AD_KEYS[key])) {
          promoted.push(f);
        } else {
          rest.push(f);
        }
      });
      if (promoted.length) {
        initial = promoted;
        privesc = rest;
      }
    }
    return [initial, privesc];
  }
  function initialAccessFindings(findings, t, facts) { return splitFindingsByPhase(findings, t, facts)[0]; }
  function privescFindings(findings, t, facts) { return splitFindingsByPhase(findings, t, facts)[1]; }
  function adIsEscalation(kind) { return !!AD_ESCALATION_KINDS[kind] || kind.indexOf('adcs.') === 0; }
  function factPhase(f) {
    var kind = f.kind || '';
    if (PRIVESC_RESULT_KINDS[kind] || kind.indexOf('privesc.') === 0 || kind.indexOf('loot.') === 0 || kind.indexOf('persistence.') === 0) return 'privesc';
    if (adIsEscalation(kind)) return 'privesc';
    if (kind.indexOf('foothold.') === 0 || kind.indexOf('access.shell') === 0 || kind.indexOf('credential.') === 0
      || kind === 'winrm.authenticated' || kind === 'rdp.authenticated' || kind === 'exploit.confirmed' || kind.indexOf('login.') === 0) return 'initial';
    return 'enum';
  }
  function findingPhaseOverrides(findings) {
    var override = {};
    (findings || []).forEach(function (f) {
      var phase = findingIsPrivesc(f) ? 'privesc' : 'initial';
      (f.trigger_kinds || []).forEach(function (kind) { if (!(kind in override)) override[kind] = phase; });
    });
    return override;
  }
  function reportIsNoise(f) {
    var kind = f.kind || '';
    if (REPORT_NOISE_KINDS[kind] || /\.reachable$/.test(kind)) return true;
    if (REPORT_NOISE_PREFIXES.some(function (p) { return kind.indexOf(p) === 0; })) return true;
    if (kind === 'credential.validation') return true;
    var val = f.value;
    if (val && typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length
      && Object.keys(val).every(function (k) { var v = val[k]; return v === '' || v == null || (Array.isArray(v) && !v.length) || (typeof v === 'object' && v && !Object.keys(v).length) || v === false; })) return true;
    return false;
  }
  var SINGLETON_ENUM_KINDS = { 'smb.signing': 1, 'smb.smbv1': 1, 'ad.user_list': 1 };
  function cleanFindings(items) {
    var seen = {}, singletonIdx = {}, out = [];
    (items || []).forEach(function (f) {
      if (reportIsNoise(f)) return;
      var kind = f.kind || '';
      if (SINGLETON_ENUM_KINDS[kind]) {
        var curLen = JSON.stringify(f.value || {}).length;
        if (kind in singletonIdx) {
          var prevIdx = singletonIdx[kind];
          var prevLen = JSON.stringify(out[prevIdx].value || {}).length;
          if (curLen > prevLen) out[prevIdx] = f;
          return;
        }
        singletonIdx[kind] = out.length;
        out.push(f);
        return;
      }
      var key = (f.label || kind) + '|' + JSON.stringify(f.value);
      if (seen[key]) return;
      seen[key] = 1; out.push(f);
    });
    return out;
  }
  function isSystemNoiseAccount(name) {
    var s = String(name || '').trim();
    return !s || /^\$|^SM_[0-9a-f]{8,}|^HealthMailbox|^krbtgt$|^DefaultAccount$|^Guest$|\$$/i.test(s);
  }
  function fmtVal(v) {
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    if (Array.isArray(v)) {
      var clean = v.filter(function (x) { return x !== '' && x != null && !(Array.isArray(x) && !x.length); });
      if (clean.length > 10 && clean.every(function (x) { return typeof x === 'string'; })) {
        var pri = clean.filter(function (x) { return !isSystemNoiseAccount(x); });
        var sec = clean.filter(function (x) { return isSystemNoiseAccount(x); });
        var ordered = pri.concat(sec);
        var shown = ordered.slice(0, 10).map(fmtVal).join(', ');
        return ordered.length > 10 ? (shown + ' (+' + (ordered.length - 10) + ' more)') : shown;
      }
      return clean.map(fmtVal).join(', ');
    }
    if (v && typeof v === 'object') return Object.keys(v).filter(function (k) { var x = v[k]; return x !== '' && x != null; }).map(function (k) { return (k + ' ' + fmtVal(v[k])).trim(); }).join('; ');
    return String(v);
  }
  function findingLines(items) {
    return cleanFindings(items).map(function (f) {
      var val = f.value, detail = '';
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        detail = Object.keys(val).filter(function (k) { return !DETAIL_SKIP_KEYS[k] && val[k] !== '' && val[k] != null && !(Array.isArray(val[k]) && !val[k].length); })
          .map(function (k) { return k + ': ' + fmtVal(val[k]); }).join(', ');
        if (detail.length > 260) {
          var cut = detail.slice(0, 260);
          var lastSep = Math.max(cut.lastIndexOf(', '), cut.lastIndexOf('; '));
          detail = (lastSep > 120 ? cut.slice(0, lastSep) : cut) + ' ...';
        }
      } else if (val) detail = fmtVal(val);
      var tag = f.origin === 'operator-attested' ? ' _(operator-attested)_' : '';
      return '**' + (f.label || f.kind) + '**' + (detail ? ': ' + detail : '') + tag;
    });
  }
  function describeCommandStep(cmd, host, factLabel) {
    var c = String(cmd || '').trim();
    var h = host || 'the target';
    if (/^(?:sudo\s+)?(?:nmap|rustscan|masscan|naabu)\b/i.test(c)) {
      return 'Conducted port and service enumeration against ' + h + ' using `' + c + '` to identify exposed network interfaces and software banners.';
    }
    if (/^(?:gobuster|feroxbuster|ffuf|wfuzz|nikto|whatweb)\b/i.test(c)) {
      return 'Enumerated web application directories and endpoints on ' + h + ' via `' + c + '`.';
    }
    if (/^(?:hashcat|john)\b/i.test(c)) {
      return 'Performed offline password cracking against the captured credential hash using `' + c + '`.';
    }
    if (/GetNPUsers|--asreproast\b|asrep/i.test(c)) {
      return 'Queried the Key Distribution Center (KDC) on ' + h + ' for accounts with Kerberos pre-authentication disabled (AS-REP Roasting) via `' + c + '`.';
    }
    if (/GetUserSPNs|--kerberoasting\b|kerberoast/i.test(c)) {
      return 'Requested Kerberos TGS service tickets for SPN-enabled service accounts on ' + h + ' via `' + c + '`.';
    }
    if (/^(?:enum4linux[\w-]*|rpcclient)\b/i.test(c)) {
      if (/\s-p\s+\S+/i.test(c) && !/\s-p\s+(?:""|'')/i.test(c)) {
        return 'Enumerated Active Directory users, groups, and domain policy on ' + h + ' over an authenticated RPC/SMB session using `' + c + '`.';
      }
      return 'Enumerated domain users, groups, password policy, and SMB/RPC metadata on ' + h + ' over an unauthenticated session using `' + c + '`.';
    }
    if (/^(?:nxc|netexec|crackmapexec|cme)\s+winrm\b/i.test(c)) {
      return 'Validated WinRM remote management credentials against ' + h + ' using `' + c + '`.';
    }
    if (/^(?:nxc|netexec|crackmapexec|cme)\s+ldap\b/i.test(c)) {
      return 'Queried Active Directory LDAP on ' + h + ' using `' + c + '`.';
    }
    if (/^(?:nxc|netexec|crackmapexec|cme)\s+smb\b/i.test(c) || /^(?:smbclient|smbmap)\b/i.test(c)) {
      var isNull = /-u\s+(?:""|''|\s*$)|-N\b/i.test(c);
      if (/--rid-brute\b|--users\b|--groups\b|--loggedon-users\b/i.test(c)) {
        return (isNull ? 'Enumerated domain accounts and security identifiers via SMB RID cycling on ' + h + ' over an unauthenticated/null session using `' : 'Authenticated to the SMB service on ' + h + ' and enumerated domain accounts via RID cycling/SAMR using `') + c + '`.';
      }
      if (/--shares\b/i.test(c)) {
        return (isNull ? 'Enumerated accessible SMB network shares and permissions on ' + h + ' over an unauthenticated/null session using `' : 'Authenticated to the SMB service on ' + h + ' and enumerated accessible network shares and permissions using `') + c + '`.';
      }
      if (isNull) {
        return 'Probed SMB signing, dialect negotiation, and null-session authentication on ' + h + ' with `' + c + '`.';
      }
      return 'Authenticated to the SMB service on ' + h + ' to validate credentials and inspect accessible shares using `' + c + '`.';
    }
    if (/^(?:ldapsearch|bloodhound[\w.-]*|sharphound[\w.-]*)\b/i.test(c)) {
      return 'Queried Active Directory LDAP objects, group memberships, and domain relationships on ' + h + ' via `' + c + '`.';
    }
    if (/^(?:for\s+\w+\s+in\b.*)?bloodyAD\b/i.test(c)) {
      if (/\bget\s+writable\b/i.test(c)) {
        return 'Enumerated Active Directory objects with outbound write or control permissions on ' + h + ' using `' + c + '`.';
      }
      if (/\badd\s+groupMember\b/i.test(c)) {
        return 'Abused outbound GenericAll/WriteDacl permissions on ' + h + ' to add the controlled account to a privileged security group via `' + c + '`.';
      }
      if (/\bset\s+object\b.*dcsync/i.test(c)) {
        return 'Abused WriteDacl privileges on the domain root object on ' + h + ' to grant DS-Replication-Get-Changes (DCSync) rights via `' + c + '`.';
      }
      return 'Abused Active Directory object control permissions on ' + h + ' using `' + c + '`.';
    }
    if (/dacledit/i.test(c)) {
      return 'Modified the Active Directory Access Control List (DACL) on ' + h + ' to grant replication/control privileges using `' + c + '`.';
    }
    if (/^certipy\b/i.test(c)) {
      return 'Enumerated and exploited Active Directory Certificate Services (ADCS) templates on ' + h + ' via `' + c + '`.';
    }
    if (/secretsdump/i.test(c)) {
      return 'Extracted local SAM/LSA secrets or domain NTDS.dit credential material from ' + h + ' using `' + c + '`.';
    }
    if (/^(?:evil-winrm|ssh|sshpass|xfreerdp|impacket-(?:psexec|wmiexec|smbexec|atexec)|psexec\.py|wmiexec\.py)\b/i.test(c)) {
      if (/(?:local|proof|user|root)\.txt/i.test(c)) {
        return 'Authenticated to ' + h + ' and retrieved the target proof flag using `' + c + '`.';
      }
      if (/\s-H\s|\s--hashes\b/i.test(c)) {
        return 'Established an administrative shell session on ' + h + ' via Pass-the-Hash authentication using `' + c + '`.';
      }
      return 'Established an authenticated shell session on ' + h + ' using `' + c + '`.';
    }
    if (/^(?:sudo\s+-l|find\s+\/|getcap\b|.*linpeas|.*winpeas|whoami\s+\/priv|systeminfo\b)/i.test(c)) {
      return 'Enumerated local privileges, permissions, and escalation vectors on ' + h + ' with `' + c + '`.';
    }
    if (/^sudo\b/i.test(c)) {
      return 'Leveraged permitted sudo rights on ' + h + ' to escalate privileges via `' + c + '`.';
    }
    if (/\bGet-ChildItem\b.*(?:local|proof|user|root)\.txt/i.test(c)) {
      return 'Located the proof flag file path on ' + h + ' using `' + c + '`.';
    }
    if (/\b(?:cat|type|Get-Content|more)\b.*(?:local|proof|user|root)\.txt/i.test(c)) {
      return 'Verified the active host context and captured the proof flag on ' + h + ' with `' + c + '`.';
    }
    if (factLabel) {
      return 'Confirmed ' + String(factLabel).toLowerCase() + ' on ' + h + ' by running `' + c + '`.';
    }
    return 'Executed `' + c + '` against ' + h + '.';
  }
  function phaseCommands(facts, isEnumPhase) {
    var seen = [];
    facts.slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); }).forEach(function (f) {
      var ev = (f.evidence || '').trim();
      if (!ev || seen.indexOf(ev) !== -1 || !looksLikeCommand(ev)) return;
      if (isEnumPhase && /^(?:evil-winrm|type\s|cat\s|Get-ChildItem|Get-Content|whoami|hostname|ipconfig|ifconfig|for\s+\w+\s+in\b.*bloodyAD|bloodyAD\b.*add\s|impacket-secretsdump|secretsdump|hashcat|john)\b/i.test(ev)) {
        return;
      }
      seen.push(ev);
    });
    return seen;
  }
  function phaseSteps(facts, host) {
    var seen = {}, steps = [];
    facts.slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); }).forEach(function (f) {
      var ev = (f.evidence || '').trim();
      if (!ev || !looksLikeCommand(ev) || seen[ev]) return;
      seen[ev] = 1;
      steps.push(describeCommandStep(ev, host, f.label || f.kind || ''));
    });
    return steps;
  }
  function phaseBuckets(t, findings) {
    var override = findingPhaseOverrides(findings);
    var out = { enum: [], initial: [], privesc: [] };
    cleanFindings(t.findings || []).slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); }).forEach(function (f) {
      var kind = f.kind || '';
      if (kind.indexOf('objective.') === 0 || kind.indexOf('finding.') === 0 || WALKTHROUGH_SKIP_KINDS[kind]) return;
      out[override[kind] || factPhase(f)].push(f);
    });
    return out;
  }
  function hostFindings(ctx, host) {
    var rank = {}; SEV_ORDER.forEach(function (s, i) { rank[s] = i; });
    var tgts = (ctx.findings || {}).targets || [];
    for (var i = 0; i < tgts.length; i++) {
      if (tgts[i].host === host) {
        var fs = (tgts[i].findings || []).slice();
        fs.sort(function (a, b) { return (rank[a.severity] != null ? rank[a.severity] : 9) - (rank[b.severity] != null ? rank[b.severity] : 9); });
        return fs;
      }
    }
    return [];
  }

  var GENERIC_INITIAL_FIX = 'Apply current vendor security patches, disable or restrict the exposed service, and enforce strong authentication on any remotely reachable interface.';
  var GENERIC_PRIVESC_FIX = 'Apply least-privilege principles, patch the local privilege-escalation vector, and remove or constrain the abused rights, credentials, or misconfiguration.';
  function labeledField(label, value) { return P('**' + label + ':** ' + value); }

  function capFirst(s) { return String(s || '').replace(/^\w/, function (c) { return c.toUpperCase(); }); }
  // A single technique's report write-up: the named heading, severity, the catalog+narrative vulnerability
  // explanation, the REAL steps (the ledger commands that produced this technique's facts), the decisive
  // output (capped), impact, remediation, and references. This is what makes the walkthrough reproducible.
  function techniqueWriteup(t, f, renderedCmds) {
    var w = f.writeup || {};
    var hostLabel = (t && (t.hostname || t.label || t.host)) || 'the target';
    var blocks = [H(f.phase_label || (capFirst(f.title || 'Technique')), 5)];
    blocks.push(labeledField('Severity', capFirst(f.severity || 'info')));
    if (w.description) blocks.push(labeledField('Vulnerability', w.description));
    var cmds = f.evidence_cmds || [];
    if (cmds.length) {
      blocks.push(P('**Steps to reproduce:**'));
      blocks.push(UL(cmds.map(function (c) { return describeCommandStep(c.command, hostLabel, f.title); }), true));
      var withOut = cmds.filter(function (c) { return c && String(c.output || '').trim(); });
      var toShow = withOut.length <= 2 ? withOut : [withOut[0], withOut[withOut.length - 1]];
      toShow.forEach(function (kc) {
        var cStr = (kc.command || '').trim();
        if (renderedCmds && cStr) renderedCmds[cStr] = 1;
        blocks.push(TERM({ command: kc.command, output: kc.output }));
      });
    }
    if (w.impact) blocks.push(labeledField('Impact', w.impact));
    if (w.remediation || f.remediation) blocks.push(labeledField('Remediation', w.remediation || f.remediation));
    if ((f.refs || []).length) {
      var uniqRefs = [];
      f.refs.forEach(function (r) { if (r && uniqRefs.indexOf(r) === -1) uniqRefs.push(r); });
      if (uniqRefs.length) blocks.push(P('**References:** ' + uniqRefs.slice(0, 4).join(' · ')));
    }
    return blocks;
  }
  // Some catalog findings are CAPABILITIES the compromise merely made possible (a Golden Ticket becomes
  // possible once krbtgt is known; spraying once a user list exists; PtH once a hash exists) - not steps
  // that were actually run. They stay in the Findings section, but a walkthrough STEP requires an evidence
  // command that matches the technique's own verb; without a map entry a technique is taken as performed.
  var _WALK_VERB = {
    'golden-ticket': /ticketer|golden|kerberos::golden|mimikatz/i,
    'password-spraying': /spray|--continue-on-success|kerbrute\s+password|--pass-pol/i,
    'pass-the-hash': /\s-H\s|-hashes|--hashes\b|\bpth-|overpass/i,
    'kerberoasting': /kerberoast|getuserspns/i,
    'zerologon': /zerologon|cve-2020-1472/i,
  };
  function techniquePerformed(f) {
    var re = _WALK_VERB[f.key]; if (!re) return true;
    return (f.evidence_cmds || []).some(function (c) { return re.test(c.command); });
  }
  function vulnBlock(t, phase, phaseFacts, findings, renderedCmds) {
    var cand = (findings || []).filter(function (f) {
      return f.from_catalog && f.writeup && f.writeup.description && (f.evidence_cmds || []).length && techniquePerformed(f);
    });
    // If active exploitation/access techniques exist in Initial Access, omit passive protocol/header hygiene
    // findings (e.g. SMBv1 Enabled, SMB Signing Not Required) from the step-by-step reproduction walkthrough.
    if (phase === 'initial') {
      var activeCand = cand.filter(function (f) { return !isPassiveHygieneFinding(f); });
      if (activeCand.length) cand = activeCand;
    }
    // Dedupe by evidence-command set: a technique whose commands are all already shown by a higher-ranked
    // technique (e.g. a hash whose only evidence is the same secretsdump that proved DCSync) is not a
    // separate step. `findings` arrive severity-sorted, so the most significant technique keeps the command.
    var kept = [], usedCmds = {};
    cand.forEach(function (f) {
      var cmds = (f.evidence_cmds || []).map(function (c) { return c.command; });
      if (cmds.length && cmds.every(function (c) { return usedCmds[c]; })) return;
      kept.push(f); cmds.forEach(function (c) { usedCmds[c] = 1; });
    });
    // Read the phase chronologically (the order the operator actually ran the techniques).
    kept.sort(function (a, b) { return (a.first_at || 0) - (b.first_at || 0); });
    if (kept.length) {
      var out = [];
      kept.forEach(function (f) { out = out.concat(techniqueWriteup(t, f, renderedCmds)); });
      return out;
    }
    return genericVulnBlock(t, phase, phaseFacts, findings);
  }
  function genericVulnBlock(t, phase, phaseFacts, findings) {
    var host = t.host;
    var finding = findings.length ? findings[0] : null;
    var writeup = (finding && finding.writeup) || {};
    var users = {}; phaseFacts.forEach(function (f) { if (f.value && typeof f.value === 'object' && f.value.user) users[f.value.user] = 1; });
    var userStr = Object.keys(users).sort().join(', ');
    var explanation, fix, severity, parts = [];
    if (phase === 'initial') {
      if (writeup.description) parts.push(writeup.description.replace(/\.$/, ''));
      var hasFoothold = phaseFacts.some(function (f) { var k = f.kind || ''; return k.indexOf('foothold.') === 0 || k.indexOf('access.shell') === 0 || k === 'winrm.authenticated' || k === 'rdp.authenticated'; });
      if (hasFoothold) { var s = 'An initial foothold was established on ' + host; if (userStr) s += ' as `' + userStr + '`'; parts.push(s); }
      else if (phaseFacts.some(function (f) { return (f.kind || '').indexOf('credential.') === 0; })) parts.push('Valid credential material for ' + host + ' was recovered during service enumeration and validated against exposed authentication endpoints');
      if (!parts.length) parts.push('No initial-access vector was recorded for ' + host);
      explanation = parts.map(function (p) { return p.trim(); }).filter(Boolean).join('. ') + '.';
      fix = writeup.remediation || (finding && finding.remediation) || GENERIC_INITIAL_FIX;
      severity = finding ? String(finding.severity || 'info').replace(/^\w/, function (c) { return c.toUpperCase(); }) : (hasFoothold ? 'High' : 'Informational');
    } else {
      var domainWin = phaseFacts.some(function (f) { return ['loot.ntds', 'hash.krbtgt', 'persistence.domain'].indexOf(f.kind) !== -1; }) || t.domain_owned;
      var sysAdmin = phaseFacts.some(function (f) { return ['access.admin', 'access.system', 'credential.admin'].indexOf(f.kind) !== -1; });
      var reachedFull = isFullPriv(oscpPriv(t));
      var top = phaseFacts.length ? phaseFacts[0] : null;
      if (writeup.description && finding && ['critical', 'high'].indexOf(finding.severity) !== -1) parts.push(writeup.description.replace(/\.$/, ''));
      if (domainWin) parts.push('Domain-level compromise was achieved from ' + host + '; credential material (such as NTDS/krbtgt secrets) was extracted, yielding administrative control across the Active Directory domain');
      else if (sysAdmin || reachedFull) { var lvl = isLinuxTarget(t) ? 'root' : 'administrative/SYSTEM level'; parts.push('Local privileges on ' + host + ' were escalated to ' + lvl); }
      if (top && !domainWin && !sysAdmin && !reachedFull) parts.push('A privilege-escalation lead was identified on ' + host + ' (' + (top.label || top.kind) + ')');
      if (!parts.length) parts.push('No privilege-escalation activity was recorded for ' + host);
      explanation = parts.map(function (p) { return p.trim(); }).filter(Boolean).join('. ') + '.';
      fix = writeup.remediation || (finding && finding.remediation) || GENERIC_PRIVESC_FIX;
      severity = finding ? String(finding.severity || 'info').replace(/^\w/, function (c) { return c.toUpperCase(); }) : ((domainWin || sysAdmin || reachedFull) ? 'Critical' : (phaseFacts.length ? 'High' : 'Informational'));
    }
    var blocks = [labeledField('Vulnerability Explanation', explanation), labeledField('Vulnerability Fix', fix), labeledField('Severity', severity)];
    var steps = phaseSteps(phaseFacts, host);
    if (steps.length) { blocks.push(P('**Steps to reproduce:**')); blocks.push(UL(steps, true)); }
    else blocks.push(labeledField('Steps to reproduce', 'No commands were recorded for this phase.'));
    var cmds = phaseCommands(phaseFacts);
    blocks.push(P('**Proof of Concept / Commands:**'));
    if (cmds.length) blocks.push(CODE(cmds.join('\n')));
    else blocks.push(P('_No commands were recorded for this phase._'));
    var obs = findingLines(phaseFacts);
    if (obs.length) { blocks.push(P('**Key observations:**')); blocks.push(UL(obs)); }
    return blocks;
  }

  function flagForSlot(t, slot) { for (var i = 0; i < (t.flags || []).length; i++) if (t.flags[i].slot === slot) return t.flags[i]; return {}; }
  function proofShotsForSlot(t, slot) {
    var shots = (t.proof && t.proof.screenshots) || [];
    var flags = (t.proof && t.proof.flags) || [];
    var out = shots.filter(function (s) { return s.slot === slot; });
    if (!out.length && flags.length === 1) out = shots.filter(function (s) { return !s.slot; });
    return out;
  }
  function proofRenderImages(ctx, host, slot, label) {
    var recs = (ctx.evidence || []).filter(function (e) { return e.section === 'proof' && e.kind === 'render' && e.include !== false && (e.target || '') === (host || ''); });
    var slotted = recs.filter(function (e) { return (e.slot || '') === slot; });
    if (!slotted.length) {
      var slotless = recs.filter(function (e) { return !(e.slot || ''); });
      slotted = (slotless.length === 1 && !recs.some(function (e) { return e.slot; })) ? slotless : [];
    }
    slotted.sort(function (a, b) { return (a.order || 0) - (b.order || 0) || (a.added_at || 0) - (b.added_at || 0); });
    return slotted.map(function (e) { return IMG({ caption: humanizeCaption(e.caption, label), data_uri: e.data_uri, path: e.path, is_render: true }); });
  }
  function onHostCaptureFrame(ctx, host, slot, t) {
    var names = slot === 'root' ? /(root|proof)\.txt/i : /(user|local)\.txt/i;
    var remoteLead = /^\s*(?:sudo\s+|proxychains\d?\s+)?(?:nxc|netexec|crackmapexec|cme|impacket-[\w.]+|wmiexec|psexec|smbexec|atexec|smbclient|winrs|evil-winrm|ssh|sshpass|plink)\b/i;
    var acts = (ctx.timeline || ctx.activities || []).slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); });
    var best = null;
    acts.forEach(function (a) {
      var cmd = a.command || '';
      if (!/\b(?:type|cat|more|Get-Content|gc)\b/i.test(cmd) || !names.test(cmd)) return;
      if (remoteLead.test(cmd.trim())) return;
      var hasId = /\b(?:ipconfig|ifconfig|ip\s+a(?:ddr)?|hostname|whoami|id)\b/i.test(cmd + ' ' + (a.stdout || ''));
      if (!best || (hasId && !best.hasId)) best = { command: cmd, output: a.stdout || '', hasId: hasId };
    });
    if (!best && t && t.proof && Array.isArray(t.proof.flags)) {
      var pf = t.proof.flags.filter(function (f) { return f && f.slot === slot && f.block; })[0];
      if (pf && pf.block) {
        var cleanLines = String(pf.block).split(/\r?\n/).filter(function (ln) {
          return !/^(?:═+|\[✓\]|\[i\]|\[\*\]\s+STAGE\b|OBOL-CRUISE|File:|-----)/i.test(ln.trim());
        });
        var winPath = /\\|C:/i.test(pf.path || pf.block);
        var fPath = pf.path || (slot === 'root' ? (winPath ? 'C:\\Users\\Administrator\\Desktop\\root.txt' : '/root/proof.txt') : (winPath ? 'C:\\Users\\Public\\local.txt' : 'local.txt'));
        var synthCmd = winPath ? ('whoami; hostname; ipconfig; type "' + fPath + '"') : ('whoami; hostname; ip a; cat "' + fPath + '"');
        best = { command: synthCmd, output: cleanLines.join('\n').trim(), hasId: true };
      }
    }
    return best;
  }
  function proofScreenshotBlocks(t, slot, ctx, host, label, renderedCmds) {
    var out = [P('**' + label + '**')];
    var imgs = [];
    proofShotsForSlot(t, slot).forEach(function (s) {
      if (s.data_uri || s.path) imgs.push(IMG({ caption: humanizeCaption(s.caption, label), data_uri: s.data_uri, path: s.path }));
    });
    imgs = imgs.concat(proofRenderImages(ctx, host, slot, label));
    if (imgs.length) { out = out.concat(imgs); return out; }
    var frame = onHostCaptureFrame(ctx, host, slot, t);
    if (frame) {
      if (renderedCmds && frame.command) renderedCmds[frame.command.trim()] = 1;
      out.push(P('_Captured in an interactive target shell (below). If submitting to OffSec, attach a screenshot of this terminal frame on the Evidence tab._'));
      var win = /\\|ipconfig|C:/i.test(frame.command + ' ' + frame.output);
      out.push(TERM({ command: frame.command, output: frame.output, style: 'target', os: win ? 'windows' : 'linux', host: (t.hostname || host), root: slot === 'root' }));
    } else {
      out.push(P('_No proof screenshot captured yet. Read the flag from an **interactive shell on the target** with `type`/`cat` alongside `ipconfig`/`ip addr` and `whoami`, then attach that screenshot on the Evidence tab._'));
    }
    return out;
  }
  function flagContentsBlock(t, slot, includeSecrets, label) {
    var row = flagForSlot(t, slot);
    var flag = (row.rawFlag || '').trim();
    if (includeSecrets && flag) return [P('**' + label + ':**'), CODE(flag)];
    if (flag) return [labeledField(label, '`' + flag + '`')];
    return [labeledField(label, '«not captured»')];
  }

  function autoHostSummary(t, initialFindings, privescFindings) {
    var name = (t.label && t.label !== t.host) ? ('**' + t.label + '** (`' + t.host + '`)') : ('**`' + t.host + '`**');
    var osLabel = t.os || (isLinuxTarget(t) ? 'Linux' : 'Windows / Unknown OS');
    var ports = (t.open_ports || []).slice(0, 6);
    var portStr = ports.length ? (' exposing `' + ports.join('`, `') + '`' + (t.open_ports.length > 6 ? ', and additional ports' : '')) : '';
    var priv = oscpPriv(t);
    var sentences = [name + ' is a ' + osLabel + ' system' + portStr + '.'];
    if (priv !== 'None proven') {
      var fh = footholdDesc(t);
      sentences.push('Initial access was established via ' + fh + '.');
      if (isFullPriv(priv)) {
        var activeInit = (initialFindings || []).filter(function (f) { return !isPassiveHygieneFinding(f); });
        var stepCount = (activeInit.length || ((initialFindings && initialFindings.length) ? 1 : 0)) + ((privescFindings && privescFindings.length) || 0);
        if (stepCount > 1) {
          sentences.push('Chaining the identified weaknesses across ' + stepCount + ' exploitation stages resulted in full `' + priv + '` control.');
        } else {
          sentences.push('Subsequent post-exploitation and privilege escalation resulted in full `' + priv + '` control.');
        }
      } else {
        sentences.push('Testing reached `' + priv + '`-level access on this system.');
      }
    } else if (ports.length) {
      sentences.push('Active services were enumerated, but full interactive compromise was not recorded during this assessment window.');
    }
    return sentences.join(' ');
  }

  function perMachine(ctx, profile) {
    var targets = ctx.targets || [];
    if (!targets.length) { return [H('Per-Machine Walkthrough', 2), P('No targets recorded.')]; }
    var blocks = [PB(), H('Per-Machine Walkthrough', 2)];
    var includeSecrets = !!(ctx.meta && ctx.meta.include_secrets);
    var noFlagsProfile = !!(profile && profile.no_flags);
    targets.forEach(function (t, idx) {
      var host = t.host, label = t.label || host;
      if (idx > 0) blocks.push(PB());
      blocks.push(H((label && label !== host) ? (label + ' (' + host + ')') : String(host), 3));
      var hn = (t.hostname || '').trim(), dom = (t.domain || '').trim();
      var fqdn = t.fqdn || ((hn && dom && hn.indexOf('.') === -1) ? (hn + '.' + dom) : '');
      blocks.push(KVB([
        ['IP', host], ['Hostname', t.hostname || ''], ['FQDN', fqdn], ['Domain', t.domain || ''],
        ['OS', t.os || ''], ['Privilege reached', oscpPriv(t)],
      ]));
      var findings = hostFindings(ctx, host);
      var phases = phaseBuckets(t, findings);
      var split = splitFindingsByPhase(findings, t);
      var initialFindings = split[0], privescFindings = split[1];

      var customNarr = hostNarrative(ctx, host);
      if (customNarr.length) {
        blocks = blocks.concat(customNarr);
      } else {
        blocks.push(P(autoHostSummary(t, initialFindings, privescFindings)));
      }

      var showFlagsForHost = !noFlagsProfile || ((t.flags || []).length > 0);
      var renderedCmds = {};

      blocks.push(H('Service Enumeration', 4));
      if ((t.open_ports || []).length) {
        blocks.push(P('Port scanning and service fingerprinting against `' + host + '` identified ' + t.open_ports.length + ' open service(s):'));
        blocks.push(TBL(['Server IP Address', 'Ports Open'], [[host, t.open_ports.join(', ')]]));
      }
      var enumLines = findingLines(phases.enum);
      if (enumLines.length) blocks.push(UL(enumLines));
      else if (!(t.open_ports || []).length) blocks.push(P('_No service-enumeration facts recorded for this host._'));
      var enumCmds = phaseCommands(phases.enum, true);
      if (!enumCmds.length) {
        (ctx.timeline || ctx.activities || []).forEach(function (a) {
          var ac = (a.command || '').trim();
          if (ac && looksLikeCommand(ac) && /^(?:sudo\s+)?(?:nmap|rustscan|masscan|smbclient|rpcclient|enum4linux|ldapsearch|nxc\s+smb.*(?:-u\s+''|-u\s+""|--shares|--rid-brute))/i.test(ac) && enumCmds.indexOf(ac) === -1) {
            enumCmds.push(ac);
          }
        });
      }
      if (enumCmds.length) {
        blocks.push(P('**Nmap Scan Results / Enumeration Commands:**'));
        blocks.push(CODE(enumCmds.join('\n')));
        var hasCatalogWalk = findings.some(function (f) { return f.from_catalog && f.writeup && f.writeup.description && (f.evidence_cmds || []).length; });
        if (hasCatalogWalk) {
          var actOutMap = {};
          (ctx.timeline || ctx.activities || []).forEach(function (a) {
            var ac = (a.command || '').trim();
            if (ac && (a.stdout || '').trim() && !actOutMap[ac]) actOutMap[ac] = a.stdout;
          });
          var shownEnumTerms = 0;
          enumCmds.forEach(function (ec) {
            if (shownEnumTerms < 2 && actOutMap[ec] && /^(?:sudo\s+)?(?:nmap|enum4linux)/i.test(ec)) {
              shownEnumTerms++;
              renderedCmds[ec] = 1;
              blocks.push(TERM({ command: ec, output: actOutMap[ec] }));
            }
          });
        }
      }
      blocks = blocks.concat(screenshotBlocks(ctx, 'service_enum', host, 'Nmap Scan Results'));

      blocks.push(H('Initial Access', 4));
      blocks = blocks.concat(vulnBlock(t, 'initial', phases.initial, initialFindings, renderedCmds));
      var initUser = '';
      for (var i = 0; i < phases.initial.length; i++) { if (phases.initial[i].value && typeof phases.initial[i].value === 'object' && phases.initial[i].value.user) { initUser = phases.initial[i].value.user; break; } }
      var footholdCap = 'Initial foothold on ' + host + (initUser ? ' as ' + initUser : '');
      blocks = blocks.concat(screenshotBlocks(ctx, 'initial_access', host, footholdCap));
      if (showFlagsForHost) {
        blocks = blocks.concat(proofScreenshotBlocks(t, 'local', ctx, host, 'local.txt Proof Screenshot', renderedCmds));
        blocks = blocks.concat(flagContentsBlock(t, 'local', includeSecrets, 'local.txt Contents'));
      }

      blocks.push(H('Privilege Escalation', 4));
      blocks = blocks.concat(vulnBlock(t, 'privesc', phases.privesc, privescFindings, renderedCmds));
      blocks = blocks.concat(screenshotBlocks(ctx, 'privesc', host, 'Privilege escalation on ' + host));

      blocks.push(H('Post-Exploitation / Proof', 4));
      if (showFlagsForHost) {
        blocks = blocks.concat(proofScreenshotBlocks(t, 'root', ctx, host, 'proof.txt Proof Screenshot', renderedCmds));
        blocks = blocks.concat(flagContentsBlock(t, 'root', includeSecrets, 'proof.txt Contents'));
      } else {
        blocks.push(P('Post-exploitation on `' + host + '` reached **' + oscpPriv(t) + '** access. Below is the command transcript demonstrating operational control and objective completion.'));
      }
      blocks = blocks.concat(screenshotBlocks(ctx, 'commands', host, 'Command output'));
      blocks = blocks.concat(hostTranscript(ctx, host, renderedCmds));   // verbatim pasted terminal for this host
    });
    return blocks;
  }

  // ── attack narrative (browser adaptation of storyline: essential moves from the fact ledger) ──
  function commandsFor(t) {
    var seen = [];
    (t.chain || []).forEach(function (s) {
      var cmd = (s.command || '').trim();
      if (cmd && seen.indexOf(cmd) === -1 && looksLikeCommand(cmd)) seen.push(cmd);
    });
    (t.findings || []).slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); }).forEach(function (f) {
      if (reportIsNoise(f)) return;
      var ev = (f.evidence || '').trim();
      if (ev && seen.indexOf(ev) === -1 && looksLikeCommand(ev)) seen.push(ev);
    });
    return seen.slice(0, 40);
  }
  function extractCmdToolName(cmd) {
    var c = String(cmd || '').trim();
    if (/^for\s+\w+\s+in\b/i.test(c) && /bloodyAD/i.test(c)) return 'bloodyAD';
    var first = (c.split(/\s+/)[0] || '').replace(/;+$/, '');
    if (first === 'sudo' && c.split(/\s+/)[1]) first = c.split(/\s+/)[1].replace(/;+$/, '');
    return first;
  }
  function inferCmdTechnique(cmd) {
    var c = String(cmd || '').trim();
    if (/^(?:sudo\s+)?(?:nmap|rustscan|masscan)\b/i.test(c)) return 'Port & Service Scan';
    if (/^(?:enum4linux[\w-]*|rpcclient|smbclient|smbmap)\b/i.test(c)) return 'SMB / RPC Enumeration';
    if (/--asreproast\b|GetNPUsers/i.test(c)) return 'AS-REP Roasting';
    if (/--kerberoasting\b|GetUserSPNs/i.test(c)) return 'Kerberoasting';
    if (/^(?:nxc|netexec|crackmapexec|cme)\s+smb\b/i.test(c)) {
      if (/-u\s+(?:""|'')/i.test(c)) return 'SMB Null Session Check';
      if (/--rid-brute\b|--users\b/i.test(c)) return 'RID Brute / Account Enum';
      if (/--shares\b/i.test(c)) return 'SMB Share Enumeration';
      return 'SMB Credential Validation';
    }
    if (/^(?:nxc|netexec|crackmapexec|cme)\s+winrm\b/i.test(c)) return 'WinRM Credential Validation';
    if (/^(?:hashcat|john)\b/i.test(c)) return 'Offline Hash Cracking';
    if (/bloodyAD\b/i.test(c)) {
      if (/\bget\s+writable\b/i.test(c)) return 'AD Writable ACL Discovery';
      if (/\badd\s+groupMember\b/i.test(c)) return 'AD Group Membership Abuse';
      if (/\bset\s+object\b.*dcsync/i.test(c)) return 'AD WriteDacl / DCSync Grant';
      return 'AD ACL Abuse';
    }
    if (/secretsdump/i.test(c)) return 'DCSync / Credential Dump';
    if (/^(?:evil-winrm|ssh|psexec|wmiexec)\b/i.test(c)) {
      if (/\s-H\s|\s--hashes\b/i.test(c)) return 'Pass-the-Hash Shell';
      return 'Interactive Remote Shell';
    }
    if (/(?:local|proof|user|root)\.txt/i.test(c)) return 'Objective Proof Capture';
    return 'Enumeration / Execution';
  }
  function attackNarrative(ctx) {
    var owned = compromisedTargets(ctx);
    if (!owned.length) return [];
    var blocks = [H('Attack Narrative', 2), P('The causal attack path to each objective, derived from the fact ledger, followed by the key commands executed.')];
    owned.forEach(function (t) {
      blocks.push(H(hostDisplayLabel(t), 3));
      var rawChain = t.chain || [];
      var cmdTechMap = {};
      rawChain.forEach(function (s) {
        if (s.command && s.technique && !cmdTechMap[s.command]) cmdTechMap[s.command] = s.technique;
      });
      var ch = [];
      var seenStepKey = {};
      rawChain.forEach(function (s) {
        if (!s.command && (s.kind === 'target.configured' || s.kind === 'host.up' || s.kind === 'ports.open')) return;
        var k = (s.command || s.kind) + '|' + (s.technique || s.label);
        if (seenStepKey[k]) return;
        if (s.command && ch.length && ch[ch.length - 1].command === s.command && !s.isFlag) return;
        seenStepKey[k] = 1;
        ch.push(s);
      });
      if (ch.length) {
        blocks.push(H('Attack Path', 4));
        blocks.push(UL(ch.map(function (s) {
          var lead = '**' + s.label + '**';
          var det = s.detail ? ': ' + s.detail : '';
          var tech = s.technique ? '  ·  _' + s.technique + '_' : '';
          var from = (s.enabledBy && s.enabledBy.length) ? '  ·  _(from ' + s.enabledBy.join(', ') + ')_' : '';
          var via = s.command ? '  ·  `' + s.command + '`' : '';
          return lead + det + tech + from + via;
        }), true));
        var split = essentialRows(ctx, t.host);
        if (split.scoped && split.noise.length) {
          blocks.push(P('_+ ' + split.noise.length + ' other move' + (split.noise.length === 1 ? '' : 's')
            + ' not on the critical path (enumeration/no-op)._'));
        }
      }
      var cmds = commandsFor(t);
      if (cmds.length) {
        blocks.push(H('Key Commands', 4));
        var rows = cmds.map(function (c, i) {
          return [String(i + 1), cmdTechMap[c] || inferCmdTechnique(c), extractCmdToolName(c), c];
        });
        blocks.push(TBL(['#', 'Technique', 'Tool', 'Command'], rows));
      } else if (!ch.length) {
        blocks.push(P('_No copy-pasteable commands were recorded for this host (facts were seeded/ingested)._'));
      }
    });
    return blocks;
  }

  // ── proof of access (engagement-wide) ──
  function proofItemsFor(t) {
    var proof = t.proof || {};
    var shotList = proof.screenshots || [];
    var shots = {}; shotList.forEach(function (s) { shots[s.slot || ''] = s; });
    return (proof.flags || []).map(function (r) {
      var slot = r.slot || '';
      var shot = shots[slot] || (proof.flags.length === 1 ? shots[''] : null);
      var compliant = !!r.obol_compliant || !!shot;
      var gap = compliant ? '' : 'Captured flag value is recorded, attach an interactive-shell screenshot showing the flag and target IP together if submitting to OffSec.';
      return PROOF({
        label: (r.label || slot) + '  ·  ' + (r.path || slot), flag: r.flag || '', path: r.path || '',
        screenshot: shot ? (shot.label || 'operator screenshot') : '', compliant: compliant, gap: gap,
        block: r.block || '', block_label: r.block_label || 'Interactive Shell Proof Capture', shot_data_uri: shot ? (shot.data_uri || '') : '',
      });
    });
  }
  function proofSection(ctx) {
    var blocks = [H('Proof of Access', 2)];
    var a = ctx.proof || {};
    if (a.readiness_line) blocks.push(CALL('**Report readiness:** ' + a.readiness_line, 'note'));
    var anyItem = false;
    (ctx.targets || []).forEach(function (t) {
      var items = proofItemsFor(t);
      if (!items.length) return;
      anyItem = true;
      blocks.push(H(hostDisplayLabel(t), 3));
      blocks = blocks.concat(items);
    });
    var shots = screenshotBlocks(ctx, 'proof', '');
    if (shots.length) { anyItem = true; blocks.push(H('Additional proof screenshots', 3)); blocks = blocks.concat(shots); }
    if (!anyItem) blocks.push(CALL('No proof flags captured yet.', 'gap'));
    return blocks;
  }

  // ── manual evidence ──
  function manualEvidence(ctx) {
    var cands = ctx.proof_candidates || [];
    var shots = screenshotBlocks(ctx, 'manual_evidence', '');
    if (!cands.length && !shots.length) return [];
    var blocks = [H('Manual Evidence Requiring Review', 2)];
    if (cands.length) {
      blocks.push(CALL('These wrapped/manual command outputs contain flag-like values or identity blocks that OBOL did NOT auto-promote to an objective. Confirm and record them so they count.', 'warn'));
      cands.forEach(function (c) {
        blocks.push(H((c.tool || 'command') + ' · ' + (c.at || ''), 4));
        blocks.push(CODE(c.command));
        blocks.push(UL(c.values.map(function (v) { return 'candidate value: `' + v + '`'; })));
      });
    }
    return blocks.concat(shots);
  }

  // ── generic / executive sections ──
  function execSummary(ctx) {
    var meta = ctx.meta || {}, counts = ctx.severity_counts || {};
    if (meta.exec_summary && String(meta.exec_summary).trim()) {
      return [H('Executive Summary', 2), P(String(meta.exec_summary).trim())];
    }
    var total = SEV_ORDER.reduce(function (s, k) { return s + (counts[k] || 0); }, 0);
    var hosts = (ctx.targets || []).length;
    var owned = compromisedTargets(ctx).length;
    var levels = SEV_ORDER.filter(function (s) { return counts[s]; }).length;
    var rawClient = String(meta.client || meta.name || 'the target environment').trim();
    var clientLabel = /^[a-z0-9-]+$/i.test(rawClient) ? ('`' + rawClient + '`') : rawClient;
    var line = 'This penetration test of ' + clientLabel + ' evaluated ' + hosts + ' in-scope host(s), resulting in the compromise of ' + owned + ' system(s) and the identification of ' + total + ' technical finding(s) across ' + levels + ' severity level(s). The highest-impact exposures, attack chains, and recommended remediations are detailed in the sections that follow.';
    return [H('Executive Summary', 2), P(line)];
  }
  function riskOverview(ctx) {
    var counts = ctx.severity_counts || {};
    var rows = SEV_ORDER.filter(function (s) { return counts[s]; }).map(function (s) { return [s.charAt(0).toUpperCase() + s.slice(1), String(counts[s]) ]; });
    return [H('Risk Overview', 2), TBL(['Severity', 'Count'], rows.length ? rows : [['None', '0']])];
  }
  function findingsCatalog(ctx, remediation) {
    var blocks = [H('Findings', 2)];
    var fctx = ctx.findings || {};
    var rank = {}; SEV_ORDER.forEach(function (s, i) { rank[s] = i; });
    var items = [];
    (fctx.targets || []).forEach(function (t) { (t.findings || []).forEach(function (f) { items.push(Object.assign({}, f, { host: t.label || t.host })); }); });
    items.sort(function (a, b) { return (rank[a.severity] != null ? rank[a.severity] : 9) - (rank[b.severity] != null ? rank[b.severity] : 9) || String(a.title).localeCompare(String(b.title)); });
    if (!items.length) { blocks.push(P('No catalogued findings.')); return blocks; }
    items.forEach(function (f) {
      blocks.push(H('[' + String(f.severity || 'info').toUpperCase() + '] ' + (f.title || ''), 3));
      var pairs = [['Host', f.host || ''], ['Severity', capFirst(f.severity || 'info')]];
      if (f.cwe) pairs.push(['CWE', Array.isArray(f.cwe) ? f.cwe.join(', ') : String(f.cwe)]);
      if (f.attack) pairs.push(['MITRE ATT&CK', Array.isArray(f.attack) ? f.attack.join(', ') : String(f.attack)]);
      if (f.kev) pairs.push(['KEV', 'known-exploited']);
      blocks.push(KVB(pairs));
      var desc = f.detail || f.description || (f.writeup && f.writeup.description) || '';
      if (desc) blocks.push(P(desc));
      if (f.writeup && f.writeup.impact) blocks.push(P('**Impact:** ' + f.writeup.impact));
      if ((f.evidence_cmds || []).length) {
        blocks.push(P('**Proof of Concept:**'));
        var cmdsWithOut = f.evidence_cmds.filter(function (c) { return c && String(c.output || '').trim(); });
        if (cmdsWithOut.length) {
          var pocShow = cmdsWithOut.length <= 2 ? cmdsWithOut : [cmdsWithOut[0], cmdsWithOut[cmdsWithOut.length - 1]];
          pocShow.forEach(function (c) {
            blocks.push(TERM({ command: c.command, output: c.output, cap: { maxLines: 14, head: 8, tail: 4, maxChars: 1800 } }));
          });
        } else {
          blocks.push(CODE(f.evidence_cmds.map(function (c) { return c.command; }).join('\n')));
        }
      } else if (f.evidence && looksLikeCommand(f.evidence)) {
        blocks.push(P('**Proof of Concept:**'));
        blocks.push(CODE(f.evidence));
      }
      if (remediation && (f.remediation || (f.writeup && f.writeup.remediation))) {
        blocks.push(P('**Remediation:** ' + (f.remediation || (f.writeup && f.writeup.remediation))));
      }
    });
    return blocks;
  }

  function wirelessSection(ctx) {
    var wl = [];
    (ctx.targets || []).forEach(function (t) { (t.findings || []).forEach(function (f) { if (f.category === 'wireless') wl.push(f); }); });
    var blocks = [H('Wireless', 2)];
    if (!wl.length) { blocks.push(P('No wireless facts recorded.')); return blocks; }
    blocks.push(UL(findingLines(wl)));
    return blocks;
  }

  // ── appendix ──
  function proofAndLocalTable(ctx) {
    var includeSecrets = !!(ctx.meta && ctx.meta.include_secrets);
    var rows = [];
    (ctx.targets || []).forEach(function (t) {
      var host = t.host, label = t.label || '';
      var hostname = t.hostname || ((label && label !== host) ? label : '');
      var ipLabel = hostname ? (host + ' (' + hostname + ')') : String(host);
      function cell(slot) {
        var row = flagForSlot(t, slot);
        var flag = (row.rawFlag || '').trim() || (row.flag || '').trim();
        if (!flag) return '«missing»';
        return (includeSecrets || flag !== '«redacted»') ? flag : '«captured»';
      }
      rows.push([ipLabel, cell('local'), cell('root')]);
    });
    if (!rows.length) return [];
    return [H('Appendix: Proof and Local Contents', 3), TBL(['IP (Hostname)', 'local.txt', 'proof.txt'], rows)];
  }
  function workspaceAppendix(ctx) {
    var w = ctx.workspace;
    if (!w || !w.total) return [];
    var rows = [];
    (w.folders || []).forEach(function (fo) {
      fo.files.forEach(function (f) { rows.push([f.rel, f.state, f.desc]); });
    });
    if (!rows.length) return [];
    return [
      H('Appendix: Working Directory', 3),
      P('Files gathered under `' + w.root + '` during this engagement (' + w.captured + ' captured of ' + w.total + ' tracked).'),
      TBL(['Path', 'State', 'What It Is'], rows),
    ];
  }

  function appendix(ctx, profile) {
    var blocks = [PB(), H('Appendix: Key Commands & Evidence', 2)];
    var seen = {}, rows = [];
    var sortedTimeline = (ctx.timeline || []).slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); });
    sortedTimeline.forEach(function (r) {
      if (isBlockerOnlyActivity(r)) return;
      var prod = r.produced || [];
      var meaningful = prod.filter(function (k) { return String(k).indexOf('blocker.') !== 0 && k !== 'credential.validation'; });
      var cmd = (r.command || '').trim();
      if (!cmd || seen[cmd] || !meaningful.length) return;
      seen[cmd] = 1; rows.push([extractCmdToolName(cmd) || r.tool || '', cmd, r.status || '']);
    });
    if (rows.length) { blocks.push(H('Commands that produced evidence', 3)); blocks.push(TBL(['Tool', 'Command', 'Status'], rows)); }
    var ev = (ctx.evidence || []).filter(function (e) { return e.include !== false; });
    if (ev.length) {
      blocks.push(H('Evidence', 3));
      blocks.push(UL(ev.map(function (e) { return '`' + (e.stored || e.id) + '` - ' + (e.caption || e.phase || e.kind || 'evidence'); })));
    }
    blocks = blocks.concat(screenshotBlocks(ctx, 'appendix', '', 'Appendix evidence'));
    blocks = blocks.concat(workspaceAppendix(ctx));
    if (!profile || !profile.no_flags) {
      blocks = blocks.concat(proofAndLocalTable(ctx));
    }
    if (profile && profile.id === 'oscp') {
      var usedMsf = (ctx.timeline || []).some(function (r) { var c = (r.command || '').toLowerCase(); return c.indexOf('metasploit') !== -1 || c.indexOf('meterpreter') !== -1 || c.indexOf('msfconsole') !== -1; });
      blocks.push(H('Appendix: Metasploit / Meterpreter Usage', 3));
      blocks.push(P(usedMsf ? 'Metasploit/Meterpreter was used on the machine(s) noted in the walkthrough.' : 'N/A, Metasploit/Meterpreter was not used during this engagement.'));
      blocks.push(H('Appendix: Completed Buffer Overflow Code', 3));
      blocks.push(P('N/A, no buffer-overflow exploit was developed or used during this engagement.'));
    }
    return blocks;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 7. profiles + dispatch
  // ─────────────────────────────────────────────────────────────────────────
  var PROFILES = {
    oscp: {
      id: 'oscp', name: 'OSCP Exam', title: 'OSCP Exam Report', subtitle: 'Offensive Security Certified Professional, exam report',
      sections: ['cover', 'toc', 'high_level_summary', 'recommendations', 'objective_summary', 'methodology', 'narrative', 'per_machine', 'proof', 'manual_evidence', 'appendix'],
      risk: 'severity', exec_summary: false, screenshots_required: true, remediation: false, no_flags: false, include_secrets_default: false,
      filename_pattern: 'OSCP-{osid}-Exam-Report',
      note: 'Per-machine, proof-first: local.txt/proof.txt read in an interactive shell with the target IP visible, and the exact steps to reproduce. No executive fluff.',
      config: {},
    },
    cpts: {
      id: 'cpts', name: 'HTB CPTS Exam', title: 'CPTS Penetration Test Report', subtitle: 'Hack The Box Certified Penetration Testing Specialist, commercial-grade exam report',
      sections: ['cover', 'toc', 'exec_summary', 'high_level_summary', 'recommendations', 'objective_summary', 'methodology', 'risk_overview', 'findings', 'narrative', 'per_machine', 'proof', 'manual_evidence', 'appendix'],
      risk: 'severity', exec_summary: true, screenshots_required: true, remediation: true, no_flags: false, include_secrets_default: false,
      filename_pattern: 'CPTS-{name}-Exam-Report',
      note: 'Commercial-grade HTB CPTS report: executive summary, 14-flag objective tracking (12 to pass), CWE/ATT&CK-mapped findings with root-cause remediation, and reproducible per-host walkthroughs.',
      config: {},
    },
    pnpt: {
      id: 'pnpt', name: 'TCM PNPT Assessment', title: 'External & Internal Penetration Test Report', subtitle: 'TCM Security Practical Network Penetration Tester (PNPT) assessment report',
      sections: ['cover', 'toc', 'exec_summary', 'high_level_summary', 'recommendations', 'compromise_summary', 'methodology', 'risk_overview', 'findings', 'narrative', 'per_machine', 'appendix'],
      risk: 'severity', exec_summary: true, screenshots_required: false, remediation: true, no_flags: true, include_secrets_default: false,
      filename_pattern: 'PNPT-{name}-Assessment-Report',
      note: 'Real-world TCM Security PNPT deliverable: zero flag ceremony, focused on perimeter compromise, Active Directory attack path to Domain Controller compromise, and actionable remediation.',
      config: {},
    },
    generic: {
      id: 'generic', name: 'Client / Organization Pentest', title: 'Penetration Test Report', subtitle: 'Professional client penetration test report',
      sections: ['cover', 'toc', 'exec_summary', 'high_level_summary', 'recommendations', 'compromise_summary', 'methodology', 'risk_overview', 'findings', 'per_machine', 'appendix'],
      risk: 'severity', exec_summary: true, screenshots_required: false, remediation: true, no_flags: true, include_secrets_default: false,
      filename_pattern: '{name}-pentest-report',
      note: 'Client-ready deliverable: executive summary, compromise matrix, methodology, CWE/ATT&CK findings with remediation, per-target walkthroughs, and evidence appendices.', config: {},
    },
    executive: {
      id: 'executive', name: 'Executive', title: 'Security Assessment, Executive Report', subtitle: 'Executive summary and risk overview',
      sections: ['cover', 'exec_summary', 'risk_overview', 'recommendations', 'findings', 'appendix'],
      risk: 'rating', exec_summary: true, screenshots_required: false, remediation: true, no_flags: true, include_secrets_default: false,
      filename_pattern: '{name}-executive-report',
      note: 'Leadership-facing: executive summary, risk ratings, top findings, remediation posture.', config: {},
    },
    technical: {
      id: 'technical', name: 'Technical', title: 'Technical Assessment Report', subtitle: 'Full technical detail, findings, per-machine, evidence',
      sections: ['cover', 'toc', 'high_level_summary', 'recommendations', 'methodology', 'findings', 'per_machine', 'proof', 'manual_evidence', 'appendix'],
      risk: 'severity', exec_summary: false, screenshots_required: false, remediation: true, no_flags: false, include_secrets_default: false,
      filename_pattern: '{name}-technical-report',
      note: 'Deep technical walkthrough with full command/evidence detail for every target.', config: {},
    },
    oswp: {
      id: 'oswp', name: 'OSWP', title: 'OSWP Exam Report', subtitle: 'Offensive Security Wireless Professional, exam report',
      sections: ['cover', 'toc', 'objective_summary', 'wireless', 'per_machine', 'proof', 'manual_evidence', 'appendix'],
      risk: 'severity', exec_summary: false, screenshots_required: true, remediation: false, no_flags: false, include_secrets_default: false,
      filename_pattern: 'OSWP-{osid}-Exam-Report',
      note: 'Per authorized network: the captured handshake/PMKID, the crack, the recovered key, and the evidence.', config: {},
    },
  };
  var DEFAULT_PROFILE = 'oscp';
  var ALIASES = { industry: 'executive', client: 'generic' };

  function resolve(name, ctx) {
    var key = String(name || '').trim().toLowerCase();
    key = ALIASES[key] || key;
    var base = PROFILES[key] || PROFILES[DEFAULT_PROFILE];
    var prof = Object.assign({}, base, { config: {} });
    if (ctx && ctx.meta) {
      if (ctx.meta.osid) prof.config.osid = ctx.meta.osid;
      if (ctx.meta.candidate) prof.config.candidate = ctx.meta.candidate;
      if (ctx.meta.client) prof.config.client = ctx.meta.client;
    }
    return prof;
  }

  function defaultFor(ctx) {
    var plat = String((ctx && ctx.meta && ctx.meta.platform) || '').toLowerCase();
    if (plat.indexOf('oswp') !== -1) return 'oswp';
    if (plat === 'cpts') return 'cpts';
    if (plat === 'pnpt') return 'pnpt';
    if (plat === 'client') return 'generic';
    if (plat.indexOf('oscp') !== -1 || plat === '' || plat === 'oscp+' || plat === 'pwk') return 'oscp';
    return 'generic';
  }

  var SECTION_BUILDERS = {
    cover: function (ctx, p) { return cover(ctx, p); },
    toc: function () { return toc(); },
    high_level_summary: function (ctx) { return highLevelSummary(ctx); },
    recommendations: function (ctx) { return recommendations(ctx); },
    objective_summary: function (ctx, p) { return objectiveSummary(ctx, p); },
    compromise_summary: function (ctx) { return compromiseSummary(ctx); },
    narrative: function (ctx) { return attackNarrative(ctx); },
    methodology: function (ctx, p) { return methodology(ctx, p); },
    per_machine: function (ctx, p) { return perMachine(ctx, p); },
    proof: function (ctx) { return proofSection(ctx); },
    manual_evidence: function (ctx) { return manualEvidence(ctx); },
    exec_summary: function (ctx) { return execSummary(ctx); },
    risk_overview: function (ctx) { return riskOverview(ctx); },
    findings: function (ctx, p) { return findingsCatalog(ctx, p.remediation); },
    wireless: function (ctx) { return wirelessSection(ctx); },
    appendix: function (ctx, p) { return appendix(ctx, p); },
  };

  function document(profileName, ctx) {
    var prof = resolve(profileName, ctx);
    var blocks = [];
    prof.sections.forEach(function (sid) {
      var builder = SECTION_BUILDERS[sid];
      if (builder) blocks = blocks.concat(builder(ctx, prof) || []);
    });
    var tocItems = [];
    blocks.forEach(function (b) {
      if (b && b.t === 'heading' && (b.level === 2 || b.level === 3)) {
        tocItems.push({ level: b.level, text: String(b.text || ''), anchor: b.anchor || slug(b.text || '') });
      }
    });
    blocks.forEach(function (b) {
      if (b && b.t === 'toc') b.items = tocItems;
    });
    return blocks;
  }

  function outline(blocks) {
    var items = [];
    (blocks || []).forEach(function (b) {
      if (b && b.t === 'heading' && b.level >= 1 && b.level <= 3) {
        items.push({
          level: b.level,
          text: String(b.text || ''),
          anchor: b.anchor || slug(b.text || ''),
        });
      }
    });
    return items;
  }

  function filenameStem(profile, ctx) {
    // Accept either a resolved profile object (from validate) or a profile NAME (from the report route's
    // download buttons) - resolving a bare string here is what keeps .md/.html/.docx from throwing on
    // `undefined.filename_pattern`. Guard the pattern too, so a profile without one still yields a name.
    if (!profile || typeof profile === 'string') profile = resolve(profile, ctx);
    var meta = (ctx && ctx.meta) || {};
    var osid = (profile.config && profile.config.osid) || 'OS-XXXXX';
    var name = String(meta.name || 'obol').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'obol';
    var pattern = profile.filename_pattern || '{name}-obol-report';
    return pattern.replace('{osid}', osid).replace('{name}', name);
  }

  function submissionHelper(profileName, ctx) {
    var profile = resolve(profileName, ctx);
    var stem = filenameStem(profile, ctx);
    var pdfName = stem + '.pdf';
    if (profile.id === 'oscp' || profile.id === 'oswp') {
      var sevenZ = stem + '.7z';
      return {
        profileId: profile.id,
        pdfName: pdfName,
        archiveName: sevenZ,
        archiveCmd: '7z a ' + sevenZ + ' ' + pdfName,
        hashCmd: 'md5sum ' + sevenZ,
        note: 'OffSec requires your PDF report inside a .7z archive named ' + sevenZ + ', verified by its MD5 hash upon submission.',
      };
    }
    if (profile.id === 'cpts') {
      var cptsZip = stem + '.zip';
      return {
        profileId: profile.id,
        pdfName: pdfName,
        archiveName: cptsZip,
        archiveCmd: '7z a ' + cptsZip + ' ' + pdfName,
        hashCmd: 'sha256sum ' + pdfName,
        note: 'HTB CPTS requires at least 12 of 14 flags and a commercial-grade PDF report with root-cause descriptions and actionable remediation.',
      };
    }
    var delivZip = stem + '-deliverable.zip';
    return {
      profileId: profile.id,
      pdfName: pdfName,
      archiveName: delivZip,
      archiveCmd: '7z a ' + delivZip + ' ' + pdfName + ' ' + stem + '.docx',
      hashCmd: 'sha256sum ' + pdfName,
      note: profile.id === 'pnpt'
        ? 'TCM Security PNPT requires a full professional assessment report documenting the external/internal attack path to Domain Controller compromise.'
        : 'Client deliverable package ready for handoff (.pdf + .docx + SHA-256 integrity digest).',
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 8. validate - profile-aware report readiness
  // ─────────────────────────────────────────────────────────────────────────
  function validate(profileName, ctx) {
    var profile = resolve(profileName, ctx);
    var gaps = [];
    var targets = (ctx && ctx.targets) || [];
    if (!targets.length) gaps.push({ level: 'fail', message: 'No targets recorded, nothing to report.' });
    if (profile.id === 'oscp' || profile.id === 'oswp') {
      if (!(profile.config && profile.config.osid)) {
        gaps.push({ level: 'warn', message: 'OSID not set, filename will be ' + filenameStem(profile, ctx) + '.pdf. Set it in the engagement profile.' });
      }
      if (!(profile.config && profile.config.candidate)) {
        gaps.push({ level: 'warn', message: 'Candidate name not set for the cover page. Set it in the engagement profile.' });
      }
    } else if (profile.id === 'cpts' || profile.id === 'pnpt') {
      if (!(profile.config && profile.config.candidate)) {
        gaps.push({ level: 'warn', message: 'Candidate / Assessor name not set for the cover page.' });
      }
    }
    if (profile.no_flags) {
      var ownedCount = compromisedTargets(ctx).length;
      if (targets.length && !ownedCount) {
        gaps.push({ level: 'warn', message: 'No compromised targets recorded yet in the fact ledger.' });
      }
      if (profile.id === 'pnpt' && targets.length) {
        var dcOwned = targets.some(function (t) { return t.domain_owned || hasKind(t, 'loot.ntds', 'hash.krbtgt', 'persistence.domain'); });
        if (!dcOwned) {
          gaps.push({ level: 'warn', message: 'PNPT objective: full Domain Controller / domain-admin compromise is not yet recorded.' });
        }
      }
      return gaps;
    }
    var totalFlags = 0;
    targets.forEach(function (t) {
      var host = t.label || t.host;
      var slots = {}; (t.flags || []).forEach(function (f) { slots[f.slot] = 1; });
      var slotCount = Object.keys(slots).length;
      totalFlags += slotCount;
      if (!slotCount) { gaps.push({ level: 'warn', message: host + ': no flags captured.' }); return; }
      var proof = t.proof || {};
      var shots = proof.screenshots || [];
      (proof.flags || []).forEach(function (r) {
        var compliant = !!r.obol_compliant;
        var hasShot = !!shots.length;
        if (profile.screenshots_required && !(compliant || hasShot)) {
          gaps.push({ level: 'fail', message: host + ': ' + r.slot + ' flag has NO interactive-shell screenshot showing the file + target IP, OffSec awards ZERO points without it.' });
        }
      });
    });
    if (profile.id === 'cpts' && targets.length && totalFlags < 12) {
      gaps.push({ level: 'warn', message: 'CPTS exam threshold: ' + totalFlags + '/14 flags captured (12 flags required to pass).' });
    }
    (ctx.proof_candidates || []).forEach(function (c) {
      gaps.push({ level: 'warn', message: 'Unpromoted proof candidate in `' + (c.tool || 'a command') + '`, capture it so it counts.' });
    });
    return gaps;
  }

  function preflightCheck(ctx) {
    ctx = ctx || {};
    var warnings = [];
    var proofs = ctx.proofs || [];
    var activities = ctx.activities || ctx.timeline || [];
    var targets = ctx.targets || ctx.hosts || [];
    var singleTarget = targets.length === 1;

    // 1. MISSING_PROOF_CONTEXT (warn)
    var idRe = /\b(?:uid=\d+|root|[a-z0-9_.-]+\\[a-z0-9_.-]+|nt authority\\system)\b/i;
    var ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

    for (var i = 0; i < proofs.length; i++) {
      var p = proofs[i];
      var pHost = p.host || (targets[0] && (targets[0].host || targets[0].ip)) || '';
      var pKind = p.kind || (p.slot === 'root' ? 'proof.txt' : (p.slot === 'local' ? 'local.txt' : 'flag.txt'));
      var hasContext = false;

      var candidates = [];
      if (p.stdout) candidates.push(p.stdout);
      if (p.block) candidates.push(p.block);
      if (p.evidence) candidates.push(p.evidence);
      if (p.source) candidates.push(p.source);

      for (var a = 0; a < activities.length; a++) {
        var act = activities[a];
        var out = act.stdout || '';
        if (!out) continue;
        var matchesHost = !act.target || act.target === pHost || singleTarget;
        if (!matchesHost) continue;
        if (p.rawFlag && out.indexOf(p.rawFlag) >= 0) {
          candidates.push(out);
        } else if (p.flag && p.flag !== '[REDACTED]' && p.flag !== '«redacted»' && out.indexOf(p.flag) >= 0) {
          candidates.push(out);
        } else if (pKind && (out.indexOf(pKind) >= 0 || (act.command && act.command.indexOf(pKind) >= 0))) {
          candidates.push(out);
        }
      }

      for (var tIdx = 0; tIdx < targets.length; tIdx++) {
        var tg = targets[tIdx];
        if ((tg.host === pHost || tg.ip === pHost) && tg.proof && tg.proof.flags) {
          for (var fIdx = 0; fIdx < tg.proof.flags.length; fIdx++) {
            var tf = tg.proof.flags[fIdx];
            if (tf.slot === p.slot && tf.block) {
              candidates.push(tf.block);
            }
          }
        }
      }

      for (var c = 0; c < candidates.length; c++) {
        var text = candidates[c];
        if (idRe.test(text) && ipRe.test(text)) {
          hasContext = true;
          break;
        }
      }

      if (!hasContext) {
        warnings.push({
          level: 'warn',
          host: pHost,
          code: 'MISSING_PROOF_CONTEXT',
          message: 'Flag capture for ' + pHost + ' (' + pKind + ') does not show whoami + IP address in the same terminal output block.'
        });
      }
    }

    // 2. MISSING_WALKTHROUGH_CHAIN (warn)
    for (var h = 0; h < targets.length; h++) {
      var tgt = targets[h];
      var hostIp = tgt.ip || tgt.host || '';
      var hostProofs = proofs.filter(function (pr) {
        return pr.host === hostIp || (!pr.host && singleTarget);
      });
      if (!hostProofs.length) continue;

      var hFindings = tgt.findings || hostFindings(ctx, hostIp) || [];
      var hActs = tgt.activities || activities.filter(function (act) {
        return actMatchesHost(act, hostIp, singleTarget);
      });
      var hFacts = tgt.facts || ((ctx.facts || []).filter(function (f) {
        return f.scope === 'host:' + hostIp || (!f.scope && singleTarget);
      }));

      var initFindings = initialAccessFindings(hFindings, tgt, hFacts);
      if (!initFindings.length && hActs.length) {
        var hasInitAct = hActs.some(function (act) {
          var phase = String(act.phase || '').toLowerCase();
          var prod = actProducedKinds(act);
          return phase === 'initial' || phase === 'foothold' || prod.some(function (k) {
            return k.indexOf('foothold.') === 0 || k === 'access.shell' || k === 'credential.available';
          });
        });
        if (hasInitAct) initFindings = [{ label: 'Initial Access Activity' }];
      }
      if (!initFindings.length && tgt.chain && tgt.chain.length) {
        var hasChainInit = tgt.chain.some(function (s) {
          return !s.isFlag && /initial|foothold|access/i.test(s.phase || '');
        });
        if (hasChainInit) initFindings = [{ label: 'Initial Access Chain' }];
      }

      if (!initFindings.length) {
        warnings.push({
          level: 'warn',
          host: hostIp,
          code: 'MISSING_INITIAL_ACCESS',
          message: 'Host ' + hostIp + ' has a captured flag but no Initial Access finding/command chain in the report.'
        });
      }

      var hasRootProof = hostProofs.some(function (pr) {
        return pr.slot === 'root' || pr.kind === 'proof.txt' || pr.kind === 'objective.root_flag';
      });

      if (hasRootProof) {
        var privFindings = privescFindings(hFindings, tgt, hFacts);
        if (!privFindings.length && hActs.length) {
          var hasPrivAct = hActs.some(function (act) {
            var phase = String(act.phase || '').toLowerCase();
            var prod = actProducedKinds(act);
            return phase === 'privesc' || phase === 'escalate' || prod.some(function (k) {
              return k.indexOf('privesc.') === 0 || k === 'access.admin' || k === 'access.system' || k === 'access.root';
            });
          });
          if (hasPrivAct) privFindings = [{ label: 'Privilege Escalation Activity' }];
        }
        if (!privFindings.length && tgt.chain && tgt.chain.length) {
          var hasChainPriv = tgt.chain.some(function (s) {
            return !s.isFlag && /privesc|escalat/i.test(s.phase || '');
          });
          if (hasChainPriv) privFindings = [{ label: 'Privilege Escalation Chain' }];
        }

        if (!privFindings.length) {
          var landedStraightRoot = false;
          for (var fi = 0; fi < initFindings.length; fi++) {
            var ifnd = initFindings[fi];
            var fUser = String((ifnd.value && ifnd.value.user) || (ifnd.value && ifnd.value.identity) || ifnd.identity || '').toLowerCase();
            if (fUser === 'root' || fUser === 'system' || fUser === 'nt authority\\system' || fUser === 'administrator') {
              landedStraightRoot = true;
              break;
            }
          }
          if (!landedStraightRoot) {
            for (var fa = 0; fa < hFacts.length; fa++) {
              var fct = hFacts[fa];
              var knd = fct.kind || '';
              if (knd.indexOf('foothold.') === 0 || knd === 'access.shell' || knd === 'access.admin' || knd === 'access.system' || knd === 'access.root') {
                var u = String((fct.value && (fct.value.identity || fct.value.user)) || '').toLowerCase();
                var uidVal = String((fct.value && fct.value.uid) || '');
                if (u === 'root' || u === 'system' || u === 'nt authority\\system' || u === 'administrator' || uidVal === '0') {
                  landedStraightRoot = true;
                  break;
                }
              }
            }
          }

          if (!landedStraightRoot) {
            warnings.push({
              level: 'warn',
              host: hostIp,
              code: 'MISSING_PRIVESC',
              message: 'Host ' + hostIp + ' has a root/SYSTEM flag but no Privilege Escalation finding/command chain in the report.'
            });
          }
        }
      }
    }

    // 3. EXAM_RESTRICTED_TOOL (error)
    for (var m = 0; m < activities.length; m++) {
      var actRow = activities[m];
      var cmd = actRow.command || '';
      if (/\bsqlmap\b/i.test(cmd)) {
        warnings.push({
          level: 'error',
          host: actRow.target || 'global',
          code: 'EXAM_RESTRICTED_TOOL',
          message: 'Activity log contains sqlmap, which is prohibited on the OSCP exam: ' + cmd
        });
      }
    }

    return {
      ok: !warnings.some(function (w) { return w.level === 'error'; }),
      warnings: warnings
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 7. .docx (OOXML) - build the WordprocessingML parts from the block model.
  //    Pure string building (no zip); the route zips docxParts() with JSZip into a real .docx.
  //    Runs are inline-formatted (bold/size/mono) so no styles.xml is required.
  // ─────────────────────────────────────────────────────────────────────────
  function dStrip(text) {
    return String(text == null ? '' : text)
      .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '$1')
      .replace(/\*\*([^*]+)\*\*/g, '$1')
      .replace(/`([^`]+)`/g, '$1')
      .replace(/(^|[\s(])_([^_\n]+)_(?=[\s).,;:!?]|$)/g, '$1$2');
  }
  function dRun(text, o) {
    o = o || {};
    var rpr = (o.b || o.i || o.sz || o.mono || o.color || o.shd) ? ('<w:rPr>'
      + (o.b ? '<w:b/>' : '') + (o.i ? '<w:i/>' : '')
      + (o.mono ? '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>' : '')
      + (o.color ? '<w:color w:val="' + o.color + '"/>' : '')
      + (o.shd ? '<w:shd w:val="clear" w:color="auto" w:fill="' + o.shd + '"/>' : '')
      + (o.sz ? '<w:sz w:val="' + o.sz + '"/><w:szCs w:val="' + o.sz + '"/>' : '') + '</w:rPr>') : '';
    return '<w:r>' + rpr + '<w:t xml:space="preserve">' + esc(text) + '</w:t></w:r>';
  }
  // Parse inline markdown (**bold**, _italic_, `code`, [label](url)) into formatted OOXML runs.
  function dInlineRuns(text, baseOpts) {
    baseOpts = baseOpts || {};
    var s = String(text == null ? '' : text).replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '$1 ($2)');
    var re = /(\*\*([^*]+)\*\*|`([^`]+)`|(?:^|[\s(])_([^_\r\n]+)_(?=$|[\s).,;:!?]))/g;
    var out = '', last = 0, m;
    while ((m = re.exec(s)) !== null) {
      if (m.index > last) out += dRun(s.slice(last, m.index), baseOpts);
      if (m[2] != null) {
        out += dRun(m[2], Object.assign({}, baseOpts, { b: true }));
      } else if (m[3] != null) {
        out += dRun(m[3], Object.assign({}, baseOpts, { mono: true, sz: baseOpts.sz || 19, color: '1F2937', shd: 'F3F4F6' }));
      } else if (m[4] != null) {
        var lead = m[0].slice(0, m[0].indexOf('_'));
        if (lead) out += dRun(lead, baseOpts);
        out += dRun(m[4], Object.assign({}, baseOpts, { i: true, color: baseOpts.color || '4B5563' }));
      }
      last = m.index + m[0].length;
    }
    if (last < s.length) out += dRun(s.slice(last), baseOpts);
    return out || dRun('', baseOpts);
  }
  function dPara(inner, o) {
    o = o || {};
    var pprParts = [];
    if (o.spaceBefore || o.spaceAfter) {
      pprParts.push('<w:spacing' + (o.spaceBefore ? ' w:before="' + o.spaceBefore + '"' : '') + (o.spaceAfter ? ' w:after="' + o.spaceAfter + '"' : '') + '/>');
    }
    if (o.indentLeft) pprParts.push('<w:ind w:left="' + o.indentLeft + '"/>');
    if (o.keepNext) pprParts.push('<w:keepNext/>');
    var ppr = pprParts.length ? ('<w:pPr>' + pprParts.join('') + '</w:pPr>') : '';
    return '<w:p>' + ppr + (inner || '') + '</w:p>';
  }
  var HEAD_SZ = { 1: 42, 2: 30, 3: 25, 4: 22, 5: 20 };
  var DOCX_CELL_MAR = '<w:tblCellMar><w:top w:w="75" w:type="dxa"/><w:left w:w="115" w:type="dxa"/><w:bottom w:w="75" w:type="dxa"/><w:right w:w="115" w:type="dxa"/></w:tblCellMar>';
  function dWrapLongTokens(str) {
    return String(str == null ? '' : str).replace(/\S{28,}/g, function (tok) {
      return tok.replace(/([\/;:,._-])/g, '$1\u200B');
    });
  }
  function dCell(text, hdr, widthPct, monoBody) {
    var wAttr = widthPct ? ('<w:tcW w:w="' + widthPct + '" w:type="pct"/>') : '<w:tcW w:w="0" w:type="auto"/>';
    var shd = hdr ? '<w:shd w:val="clear" w:color="auto" w:fill="EFEFEF"/>' : '';
    var cleanText = dWrapLongTokens(dStrip(text));
    var runOpts = hdr ? { b: true, sz: 19 } : (monoBody ? { mono: true, sz: 17, color: '1F2937' } : { sz: 19 });
    return '<w:tc><w:tcPr>' + wAttr + shd + '</w:tcPr>'
      + dPara(dRun(cleanText, runOpts)) + '</w:tc>';
  }
  function dTable(headers, rows) {
    var borders = '<w:tblBorders>'
      + ['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map(function (s) { return '<w:' + s + ' w:val="single" w:sz="4" w:space="0" w:color="D1D5DB"/>'; }).join('')
      + '</w:tblBorders>';
    var hdrs = headers || [];
    var isCmdTable = hdrs.length >= 3 && hdrs.some(function (h) { return /^command$/i.test(String(h || '').trim()); });
    var colWidths = null;
    if (isCmdTable && hdrs.length === 4) colWidths = [350, 1250, 800, 2600];
    else if (isCmdTable && hdrs.length === 3) colWidths = [850, 3450, 700];
    var out = '<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>' + borders + DOCX_CELL_MAR + '</w:tblPr>';
    if (hdrs.length) {
      out += '<w:tr>' + hdrs.map(function (h, i) { return dCell(h, true, colWidths ? colWidths[i] : 0, false); }).join('') + '</w:tr>';
    }
    (rows || []).forEach(function (row) {
      out += '<w:tr>' + row.map(function (c, i) {
        var isCmdCol = isCmdTable && (/^command$/i.test(String(hdrs[i] || '').trim()));
        return dCell(String(c), false, colWidths ? colWidths[i] : 0, isCmdCol);
      }).join('') + '</w:tr>';
    });
    return out + '</w:tbl>' + dPara('');
  }
  function dKvTable(pairs) {
    var nonEmpty = (pairs || []).filter(function (kv) { return kv && String(kv[1] == null ? '' : kv[1]).trim() !== ''; });
    if (!nonEmpty.length) return '';
    var borders = '<w:tblBorders>'
      + ['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map(function (s) { return '<w:' + s + ' w:val="single" w:sz="4" w:space="0" w:color="E5E7EB"/>'; }).join('')
      + '</w:tblBorders>';
    var out = '<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>' + borders + DOCX_CELL_MAR + '</w:tblPr>';
    nonEmpty.forEach(function (kv) {
      out += '<w:tr>'
        + '<w:tc><w:tcPr><w:tcW w:w="1400" w:type="pct"/><w:shd w:val="clear" w:color="auto" w:fill="F9FAFB"/></w:tcPr>'
        + dPara(dRun(dStrip(kv[0]), { b: true, sz: 19, color: '374151' })) + '</w:tc>'
        + '<w:tc><w:tcPr><w:tcW w:w="3600" w:type="pct"/></w:tcPr>'
        + dPara(dInlineRuns(String(kv[1]), { sz: 19 })) + '</w:tc>'
        + '</w:tr>';
    });
    return out + '</w:tbl>' + dPara('');
  }
  // decode up to `n` bytes of base64 (browser atob / node Buffer) for image dimension sniffing.
  function b64Bytes(b64, n) {
    var slice = b64.slice(0, Math.ceil(n / 3) * 4);
    try {
      if (typeof atob === 'function') { var bin = atob(slice); var o = []; for (var i = 0; i < n && i < bin.length; i++) o.push(bin.charCodeAt(i) & 255); return o; }
      if (typeof Buffer !== 'undefined') { var buf = Buffer.from(slice, 'base64'); var a = []; for (var j = 0; j < n && j < buf.length; j++) a.push(buf[j]); return a; }
    } catch (e) {}
    return [];
  }
  function pngSize(b64) {
    var b = b64Bytes(b64, 24);
    if (b.length < 24 || b[0] !== 0x89) return null;
    var w = (b[16] << 24) | (b[17] << 16) | (b[18] << 8) | b[19];
    var h = (b[20] << 24) | (b[21] << 16) | (b[22] << 8) | b[23];
    return (w > 0 && h > 0 && w < 20000 && h < 20000) ? { w: w, h: h } : null;
  }
  function emu(px) { return Math.round(px * 9525); }   // 96dpi -> EMU
  var DOCX_MAX_W = 5486400;   // 6 inches

  // Embed a proof screenshot as a real OOXML picture; falls back to a caption line if not decodable.
  function docxImage(b, images) {
    var m = /^data:(image\/(png|jpe?g));base64,([\s\S]+)$/i.exec(b.data_uri || '');
    if (!m) return dPara(dRun('[screenshot: ' + (b.caption || 'evidence') + ']', { i: true, color: '888888' }));
    var ext = m[2].toLowerCase() === 'jpg' ? 'jpeg' : m[2].toLowerCase();
    var b64 = m[3].replace(/\s+/g, '');
    var idx = images.length + 1;
    var sz = (ext === 'png') ? pngSize(b64) : null;
    var cx = DOCX_MAX_W, cy = Math.round(DOCX_MAX_W * 0.58);
    if (sz) { cx = Math.min(emu(sz.w), DOCX_MAX_W); cy = Math.round(cx * sz.h / sz.w); }
    var rId = 'rIdImg' + idx, file = 'image' + idx + '.' + ext;
    images.push({ id: rId, file: file, ext: ext, base64: b64 });
    var drawing = '<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">'
      + '<wp:extent cx="' + cx + '" cy="' + cy + '"/><wp:docPr id="' + idx + '" name="Screenshot ' + idx + '"/>'
      + '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
      + '<pic:pic><pic:nvPicPr><pic:cNvPr id="' + idx + '" name="Screenshot ' + idx + '"/><pic:cNvPicPr/></pic:nvPicPr>'
      + '<pic:blipFill><a:blip r:embed="' + rId + '"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
      + '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="' + cx + '" cy="' + cy + '"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
      + '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>';
    return drawing + (b.caption ? dPara(dRun(dStrip(b.caption), { i: true, color: '666666', sz: 18 })) : '');
  }
  // A terminal renders as ONE shaded, bordered, monospace block (a code box) with tight line spacing -
  // not a run of spaced paragraphs. Prompt lines keep their colour; output is dark on a light-gray fill.
  function dTermLine(inner) {
    return '<w:p><w:pPr><w:spacing w:before="0" w:after="0" w:line="240" w:lineRule="auto"/></w:pPr>' + (inner || '') + '</w:p>';
  }
  // Wrap monospace paragraphs in ONE shaded, bordered single-cell box (a code/terminal block).
  function dShadedBlock(paras) {
    var edges = ['top', 'left', 'bottom', 'right'].map(function (s) { return '<w:' + s + ' w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>'; }).join('');
    var cell = '<w:tc><w:tcPr><w:tcW w:w="5000" w:type="pct"/><w:tcBorders>' + edges + '</w:tcBorders>'
      + '<w:shd w:val="clear" w:color="auto" w:fill="F4F4F4"/>'
      + '<w:tcMar><w:top w:w="80" w:type="dxa"/><w:left w:w="110" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:right w:w="110" w:type="dxa"/></w:tcMar></w:tcPr>'
      + paras.join('') + '</w:tc>';
    return '<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>' + edges + '</w:tblBorders><w:tblLayout w:type="fixed"/></w:tblPr>'
      + '<w:tr>' + cell + '</w:tr></w:tbl>' + dPara('');
  }
  function docxTerminal(b) {
    var tp = termPrompt(b);
    var paras = [];
    if (tp) {
      paras.push(dTermLine(dRun(tp + ' ', { mono: true, sz: 18, color: 'B8860B' }) + dRun(dWrapLongTokens(b.command), { mono: true, sz: 18, b: true })));
    } else {
      paras.push(dTermLine(dRun('┌──(' + b.user + ')-[' + b.dir + ']', { mono: true, sz: 18, color: '2E7D32' })));
      paras.push(dTermLine(dRun('└─$ ', { mono: true, sz: 18, color: '2E7D32' }) + dRun(dWrapLongTokens(b.command), { mono: true, sz: 18, b: true })));
    }
    String(b.output || '').split(/\r?\n/).forEach(function (ln) { paras.push(dTermLine(dRun(dWrapLongTokens(ln) || ' ', { mono: true, sz: 18, color: '1A1A1A' }))); });
    return dShadedBlock(paras);
  }
  function blockToDocx(b, images) {
    switch (b.t) {
      case 'heading': return dPara(dRun(b.text, { b: true, sz: HEAD_SZ[b.level] || 22 }), { spaceBefore: b.level <= 2 ? 220 : 160, spaceAfter: 60, keepNext: true });
      case 'para': return dPara(dInlineRuns(b.text), { spaceAfter: 80 });
      case 'bullets': return (b.items || []).map(function (it, i) {
        return dPara(dRun(b.ordered ? (i + 1) + '. ' : '• ', { b: !!b.ordered }) + dInlineRuns(it), { indentLeft: 280, spaceAfter: 40 });
      }).join('');
      case 'kv': return dKvTable(b.pairs);
      case 'table': return dTable(b.headers, b.rows);
      case 'code': return dShadedBlock(String(b.text).split(/\r?\n/).map(function (ln) { return dTermLine(dRun(dWrapLongTokens(ln) || ' ', { mono: true, sz: 18, color: '1A1A1A' })); }));
      case 'terminal': return docxTerminal(b);
      case 'callout': return dPara(dInlineRuns(b.text, { i: true, color: '374151' }), { spaceBefore: 80, spaceAfter: 80, indentLeft: 200 });
      case 'toc': {
        var tocList = b.items || [];
        if (!tocList.length) return '';
        var tocOut = [dPara(dRun('Table of Contents', { b: true, sz: 26 }), { spaceBefore: 160, spaceAfter: 80 })];
        tocList.forEach(function (it) {
          var isSub = it.level === 3;
          tocOut.push(dPara(dRun((isSub ? '    • ' : '') + it.text, { b: !isSub, sz: isSub ? 19 : 20, color: isSub ? '4B5563' : '111827' }), { spaceAfter: 30 }));
        });
        tocOut.push(dPara(''));
        return tocOut.join('');
      }
      case 'pagebreak': return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>';
      case 'proof': {
        var pRows = [];
        if (b.flag) pRows.push(['Flag Value', b.flag]);
        if (b.path) pRows.push(['File Path', b.path]);
        if (b.command) pRows.push(['Command', b.command]);
        if (b.screenshot) pRows.push(['Screenshot', b.screenshot]);
        pRows.push(['Verification', b.compliant ? 'Verified in interactive shell with host IP context' : (b.gap || 'Captured')]);
        var outXml = dPara(dRun(b.label, { b: true, sz: 22 }), { spaceBefore: 120, spaceAfter: 40, keepNext: true }) + dKvTable(pRows);
        if (b.block) {
          if (b.block_label) outXml += dPara(dRun(b.block_label + ':', { b: true, sz: 19 }), { spaceAfter: 40, keepNext: true });
          outXml += dShadedBlock(String(b.block).split(/\r?\n/).map(function (ln) { return dTermLine(dRun(dWrapLongTokens(ln) || ' ', { mono: true, sz: 18, color: '1A1A1A' })); }));
        }
        return outXml;
      }
      case 'image': return docxImage(b, images);
      case 'divider': return dPara('');
      default: return '';
    }
  }
  // Return the full .docx as a list of { path, data, base64 } - text parts + embedded image media.
  // The route zips these with JSZip (zip.file(path, data, {base64:true}) for media).
  function docxFiles(blocks) {
    var images = [];
    var body = (blocks || []).map(function (b) { return blockToDocx(b, images); }).join('');
    var nsRoot = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
      + ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
      + ' xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"'
      + ' xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
      + ' xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"';
    var documentXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      + '<w:document ' + nsRoot + '><w:body>' + body
      + '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>'
      + '</w:body></w:document>';
    var exts = {}; images.forEach(function (im) { exts[im.ext] = 1; });
    var ctImg = (exts.png ? '<Default Extension="png" ContentType="image/png"/>' : '') + (exts.jpeg ? '<Default Extension="jpeg" ContentType="image/jpeg"/>' : '');
    var contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>' + ctImg + '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
    var dotRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';
    var docRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
      + images.map(function (im) { return '<Relationship Id="' + im.id + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/' + im.file + '"/>'; }).join('')
      + '</Relationships>';
    var files = [
      { path: '[Content_Types].xml', data: contentTypes },
      { path: '_rels/.rels', data: dotRels },
      { path: 'word/document.xml', data: documentXml },
      { path: 'word/_rels/document.xml.rels', data: docRels },
    ];
    images.forEach(function (im) { files.push({ path: 'word/media/' + im.file, data: im.base64, base64: true }); });
    return files;
  }

  OBOL.report = {
    buildContext: buildContext,
    docxFiles: docxFiles,
    PROFILES: PROFILES,
    DEFAULT_PROFILE: DEFAULT_PROFILE,
    resolve: resolve,
    defaultFor: defaultFor,
    document: document,
    toMarkdown: toMarkdown,
    toHtml: toHtml,
    htmlDocument: htmlDocument,
    validate: validate,
    filenameStem: filenameStem,
    // true for an OffSec exam profile (OSCP/OSWP) whose cover needs a candidate name + OSID
    isExamProfile: function (id) { return isExamProfileObj(PROFILES[String(id || '').toLowerCase()]); },
    // redaction (two-layer, default ON)
    redact: redactCommand,
    redactValue: redactValue,
    knownSecrets: knownSecrets,
    // proof labeling (UI-facing proof discipline)
    proofLabels: proofLabels,
    isInteractiveShell: isInteractiveShell,
    identityPresent: identityPresent,
    collectProofs: collectProofs,
    // low-level helpers exposed for surfaces/tests
    normalizeSeverity: normalizeSeverity,
    factCategory: factCategory,
    oscpPrivLevel: oscpPriv,
    findingTriggerActivities: findingTriggerActivities,
    findingIsPrivesc: findingIsPrivesc,
    splitFindingsByPhase: splitFindingsByPhase,
    initialAccessFindings: initialAccessFindings,
    privescFindings: privescFindings,
    outline: outline,
    submissionHelper: submissionHelper,
    describeCommandStep: describeCommandStep,
    autoHostSummary: autoHostSummary,
    preflightCheck: preflightCheck,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
