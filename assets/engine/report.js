/*!
 * obol engine — report.js
 * The report pipeline, ported from obol-local/obol/report.py + report_profiles/*.
 *
 * A report is a READ-ONLY PROJECTION of the same state the board is narrated from:
 * facts (OBOL.facts), targets, activities (the run ledger), credentials, and operator
 * screenshots. One content model (an ordered list of Blocks) chosen by a PROFILE, then
 * serialized to Markdown or HTML — so the two never drift. Redaction is two-layer and ON
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
  // 0. constants (ported from report.py)
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
    ['Privileged access', ['access.admin', 'access.system']],
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

  // ── redaction regexes (ported, JS-native) ────────────────────────────────
  // flags whose value is ALWAYS a secret, for any tool
  var SECRET_FLAG_RE = /((?:^|\s)(?:--password|--pass|--?nthash|--?aes-?key|-computer-pass))([=\s]+)('[^']*'|"[^"]*"|\S+)/gi;
  // hash flags — redact only a hash-shaped value (curl -H headers survive)
  var HASH_FLAG_RE = /((?:^|\s)(?:--hashes|-hashes|-H))([=\s]+)('[^']*'|"[^"]*"|\S+)/gi;
  var HASHLIKE_RE = /[0-9a-fA-F]{16,}/;
  // lowercase -p / -p= / -pGLUED — tool-gated below. Case-SENSITIVE on the flag letter (never -P).
  var P_FLAG_RE = /((?:^|\s)-p)([=\s]*)('[^']*'|"[^"]*"|\S+)/g;
  // Tools where `-p` is a PORT / PRESERVE / PAYLOAD flag — never a password.
  var P_SPARE_TOOLS = {
    nmap: 1, masscan: 1, rustscan: 1, naabu: 1, ssh: 1, scp: 1, sftp: 1, rsync: 1, nc: 1,
    ncat: 1, netcat: 1, telnet: 1, ftp: 1, socat: 1, mkdir: 1, cp: 1, install: 1, rmdir: 1,
    unzip: 1, tar: 1, msfvenom: 1, psql: 1, 'redis-cli': 1, mongo: 1, mongosh: 1,
  };
  var CRED_DOMAIN_RE = /((?<![\w/])[\w.-]+\/[\w.$-]+:)([^\s:'"@/]+)/g;
  var CRED_ATHOST_RE = /((?<![\w/])[\w.$-]+:)([^\s:'"@/]+)(@[\w.:-]+)/g;
  var USERPCT_RE = /((?:^|\s)(?:-U|--user)[=\s]+['"]?[^\s'"%]+%)([^\s'"]+)/gi;
  var URLCRED_RE = /(:\/\/[^\s:/@'"]+:)([^\s@/'"]+)(@)/g;

  // ── proof interactivity classification (ported from proof.py) ─────────────
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
      var d = new Date(Number(ts) * 1000);
      if (isNaN(d.getTime())) return 'unknown time';
      // YYYY-MM-DD HH:MM:SS (local, mirrors datetime.fromtimestamp().strftime)
      var p = function (n) { return String(n).padStart(2, '0'); };
      return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' '
        + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    } catch (e) { return 'unknown time'; }
  }

  function friendly(kind) {
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
  // 2. redaction (two-layer, default ON) — ported from report.py
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
    // 4) hash flags — only a hash-shaped value (so curl -H headers survive)
    redacted = redacted.replace(HASH_FLAG_RE, function (m, p, sep, val) {
      return HASHLIKE_RE.test(val) ? p + sep + '<redacted>' : m;
    });
    // 5) `-p` — redact unless the leading tool is one where -p is a port/preserve/payload flag
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
        + 'plus a hostname/whoami in the same frame) — a flag alone does not prove it was read on the target.' });
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
  // 4. block model (ported from report_profiles/_doc.py) + serializers
  // ─────────────────────────────────────────────────────────────────────────
  function H(text, level, anchor) { return { t: 'heading', text: text, level: level || 2, anchor: anchor || '' }; }
  function P(text) { return { t: 'para', text: text || '' }; }
  function UL(items, ordered) { return { t: 'bullets', items: items || [], ordered: !!ordered }; }
  function KVB(pairs) { return { t: 'kv', pairs: pairs || [] }; }
  function TBL(headers, rows, caption) { return { t: 'table', headers: headers || [], rows: rows || [], caption: caption || '' }; }
  function CODE(text, lang) { return { t: 'code', text: text || '', lang: lang || '' }; }
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
        case 'callout': {
          var prefix = { warn: '⚠️ ', gap: '🔴 ', ok: '✅ ', note: '> ' }[b.kind] || '> ';
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
          if (b.gap) out.push('- 🔴 **proof gap:** ' + b.gap);
          else if (b.compliant) out.push('- ✅ OSCP-compliant (interactive shell, target IP visible)');
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
    s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2">$1</a>');
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
    return s;
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
          var head = b.headers.map(function (h) { return '<th>' + esc(h) + '</th>'; }).join('');
          var body = b.rows.map(function (row) {
            return '<tr>' + row.map(function (c) { return '<td>' + mdInline(String(c)) + '</td>'; }).join('') + '</tr>';
          }).join('');
          var cap = b.caption ? '<caption>' + esc(b.caption) + '</caption>' : '';
          out.push("<table class='data'>" + cap + '<thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table>');
          break;
        }
        case 'code': out.push('<pre><code>' + esc(b.text) + '</code></pre>'); break;
        case 'callout': out.push('<div class="callout ' + esc(b.kind) + '">' + mdInline(b.text) + '</div>'); break;
        case 'proof': {
          var rws = [];
          if (b.flag) rws.push('<tr><th>flag</th><td><code>' + esc(b.flag) + '</code></td></tr>');
          if (b.path) rws.push('<tr><th>path</th><td><code>' + esc(b.path) + '</code></td></tr>');
          if (b.command) rws.push('<tr><th>command</th><td><code>' + esc(b.command) + '</code></td></tr>');
          var shot = b.screenshot ? esc(b.screenshot) : '<em>none captured</em>';
          rws.push('<tr><th>screenshot</th><td>' + shot + '</td></tr>');
          var extra = '';
          if (b.block) extra += '<div class="prooflabel">' + esc(b.block_label || 'obol-captured command output') + '</div>'
            + '<pre class="proofblk">' + esc(b.block) + '</pre>';
          if (b.shot_data_uri) extra += '<img class="shot" alt="operator screenshot" src="' + esc(b.shot_data_uri) + '">';
          var status = '';
          if (b.gap) status = '<div class="callout gap">proof gap: ' + mdInline(b.gap) + '</div>';
          else if (b.compliant) status = '<div class="callout ok">OSCP-compliant — interactive shell, target IP visible</div>';
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
        case 'toc': out.push('<nav class="toc"></nav>'); break;
        default: break;
      }
    });
    return out.join('\n');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 5. context builder (ported from report.py build_report_context)
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

  function flagObjectives(tfacts) {
    var out = [], seen = {};
    tfacts.forEach(function (f) {
      if (FLAG_FACT_KINDS.indexOf(f.kind) === -1 || f.state !== SUPPORTED) return;
      var v = f.value || {}; var flag = v.flag || '';
      if (!flag || seen[flag]) return;
      seen[flag] = 1;
      out.push({ kind: f.kind, slot: v.slot || SLOT_OF_KIND[f.kind], name: v.name || '', path: v.path || '', flag: flag, source: f.source || '', at: f.created_at });
    });
    return out;
  }

  function hostProof(host, tfacts, screens, includeSecrets) {
    var captured = {};
    tfacts.forEach(function (f) {
      if (f.kind === PROOF_FACT && f.state === SUPPORTED) captured[(f.value && f.value.slot) || ''] = f.value || {};
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
        block: block, block_label: block ? 'obol-captured command output' : '',
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

  function buildContext(opts) {
    opts = opts || {};
    var includeSecrets = !!opts.includeSecrets;
    var factset = asFactSet(opts.facts);
    var targets = opts.targets || [];
    var activities = opts.activities || [];
    var credentials = opts.credentials || [];
    var params = opts.params || {};
    var screensRaw = opts.screenshots || [];
    var reportmeta = opts.reportmeta || root.OBOL_REPORTMETA || { cards: {}, laneDefaults: {}, references: { cards: {}, lanes: {} }, cveHints: [] };
    var secrets = knownSecrets(factset, credentials);

    var domain = factset.values('ad.domain_known');
    var domOwned = factset.has('loot.ntds') || factset.has('hash.krbtgt') || factset.has('persistence.domain');

    var accessState;
    if (factset.has('access.system')) accessState = 'SYSTEM access proven';
    else if (factset.has('access.admin')) accessState = 'Administrative access proven';
    else if (factset.has('foothold.windows') || factset.has('foothold.linux') || factset.has('access.shell')) accessState = 'Foothold proven, privilege not yet proven';
    else accessState = 'No access proven yet';

    var credState;
    if (factset.has('credential.available')) credState = 'Validated credential available';
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

    // timeline (run ledger)
    var timeline = activities.map(function (row, i) {
      return {
        index: i + 1, tool: row.tool || 'tool',
        command: redactCommand(row.command || '', { includeSecrets: includeSecrets, secrets: secrets }),
        status: runStatus(row), produced: (row.produced || []).slice(), duration_ms: row.duration_ms,
        at: row.at, at_display: stamp(row.at), action_id: row.action_id, playbook: row.playbook,
        stdout: row.stdout || '', stderr: row.stderr || '',
      };
    });

    // per-target rollup
    var targetsOut = targets.map(function (t) {
      var host = t.host;
      var tfacts = (factset.facts || []).filter(function (f) { return f.scope === 'host:' + host; });
      var sortedT = tfacts.slice().sort(bySortKey);
      var flags = flagObjectives(tfacts).map(function (fo) {
        return { kind: fo.kind, slot: fo.slot, name: fo.name, path: fo.path, flag: includeSecrets ? fo.flag : (fo.flag ? '«redacted»' : ''),
          rawFlag: fo.flag, evidence: redactCommand(fo.source || '', { includeSecrets: includeSecrets, secrets: secrets }), at: fo.at };
      });
      function idfact(kind, key) {
        for (var i = 0; i < tfacts.length; i++) if (tfacts[i].kind === kind && tfacts[i].value && tfacts[i].value[key]) return String(tfacts[i].value[key]);
        return '';
      }
      var os = t.os || idfact('host.os_family', 'family') || idfact('host.os_hint', 'family');
      return {
        host: host, label: t.label || host, hostname: t.hostname || idfact('host.hostname', 'hostname'),
        fqdn: t.fqdn || idfact('host.fqdn', 'fqdn'), domain: t.domain || idfact('host.domain', 'domain'),
        os: os, status: t.status || '', notes: t.notes || '', domain_owned: domOwned,
        open_ports: dedupPorts(tfacts),
        flags: flags,
        proof: hostProof(host, tfacts, screensRaw, includeSecrets),
        findings: sortedT.map(function (f) {
          return { kind: f.kind, label: friendly(f.kind), category: factCategory(f.kind),
            value: redactValue(f.value, includeSecrets),
            evidence: redactCommand(f.source || 'manual/seeded workspace evidence', { includeSecrets: includeSecrets, secrets: secrets }),
            origin: (f.value && f.value.origin) || 'obol', at: f.created_at };
        }),
        evidence: evidence.filter(function (e) { return e.target === host; }),
      };
    });

    // catalogued findings context (backed by reportmeta) + severity tally
    var perTarget = [], counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, total = 0;
    targetsOut.forEach(function (t) {
      var fs = findingFactsForHost(factset, t.host).map(function (f) { return toFinding(f, t.host, reportmeta, includeSecrets); });
      if (!fs.length) return;
      var rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      fs.sort(function (a, b) { return (rank[a.severity] != null ? rank[a.severity] : 9) - (rank[b.severity] != null ? rank[b.severity] : 9); });
      fs.forEach(function (r) {
        counts[r.severity] = (counts[r.severity] || 0) + 1; total++;
        r.writeup = { description: r.description || '', remediation: r.remediation || '' };
      });
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
      name: params.name || params.workspace || 'engagement',
      target: params.target || '',
      scope: params.scope || (params.target ? [params.target] : []),
      domain: (domain[0] && domain[0].name) || params.domain || '',
      generated_at: stamp(activities.length ? Math.max.apply(null, activities.map(function (r) { return r.at || 0; })) : null),
      include_secrets: includeSecrets,
      osid: params.osid || '',
      candidate: params.candidate || '',
      platform: params.platform || '',
    };

    var ctx = {
      meta: meta,
      targets: targetsOut,
      evidence: evidence,
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
      next_actions: params.nextActions || [],
      proof_candidates: scanManualProof(activities, factset),
      _secrets: secrets,
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
      return base + ' — missing proof: ' + miss + more;
    }
    return base + ' — every captured flag has compliant proof';
  }

  // wrapped/manual command output that looks like proof but was never promoted (browser: activity.stdout is text)
  var FLAGLIKE_RE = /\b(?:[A-Za-z]+\{[^}]{3,}\}|[0-9a-fA-F]{32}|[0-9a-fA-F]{64})\b/g;
  var PROOF_CMD_RE = /(?:root|proof|local|user|secret|flag)\.txt/i;
  var ID_RE = /\b(?:whoami|hostname|ipconfig|ifconfig|ip\s+a(?:ddr)?|id|uname)\b/i;
  function scanManualProof(activities, factset) {
    var captured = {};
    try {
      (factset.facts || []).forEach(function (f) {
        if (String(f.kind || '').indexOf('objective.') === 0 && f.value && f.value.flag) captured[f.value.flag] = 1;
      });
    } catch (e) { return []; }
    var out = [];
    (activities || []).forEach(function (row) {
      var stdout = typeof row.stdout === 'string' ? row.stdout : '';
      if (!stdout) return;
      var cmd = row.command || '';
      var vals = (stdout.match(FLAGLIKE_RE) || []).filter(function (v) { return !captured[v]; });
      var looksProofy = PROOF_CMD_RE.test(cmd) || ID_RE.test(stdout);
      if (vals.length && (looksProofy || PROOF_CMD_RE.test(stdout))) {
        var uniq = {}; vals.forEach(function (v) { uniq[v] = 1; });
        out.push({ command: cmd, tool: row.tool || '', values: Object.keys(uniq).sort().slice(0, 4), at: stamp(row.at) });
      }
    });
    return out;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 6. section builders (ported from report_profiles/_sections.py)
  // ─────────────────────────────────────────────────────────────────────────
  var SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  var FULL_PRIV_LEVELS = ['Administrator / SYSTEM', 'root'];
  var LINUX_OS_HINTS = ['linux', 'unix', 'debian', 'ubuntu', 'centos', 'bsd', 'kali', 'redhat', 'red hat', 'fedora', 'alpine', 'gentoo', 'arch'];
  var WIN_OS_HINTS = ['windows', 'win32', 'win64', 'microsoft', 'server 20'];
  var NON_COMMAND_PREFIXES = ['operator-', 'asserted', 'target added', 'fingerprint match', 'findings catalog', 'version match', 'seeded', 'ingested', 'manual entry', 'attested', 'observed'];
  var REPORT_NOISE_PREFIXES = ['port:', 'service.', 'scan.'];
  var REPORT_NOISE_KINDS = { 'host.up': 1, 'host.os_hint': 1, 'target.configured': 1, 'ad.graph.collected': 1 };
  var DETAIL_SKIP_KEYS = { tool: 1, protocol: 1, flags: 1, method: 1, profile: 1, cached: 1, guided: 1 };
  var WALKTHROUGH_SKIP_KINDS = { 'host.hostname': 1, 'host.domain': 1, 'host.fqdn': 1, 'host.os_family': 1, 'host.os_hint': 1, 'host.up': 1 };
  var PRIVESC_RESULT_KINDS = { 'access.admin': 1, 'access.system': 1, 'credential.admin': 1, 'loot.ntds': 1, 'hash.krbtgt': 1, 'persistence.domain': 1 };
  var AD_ESCALATION_KINDS = { 'ad.control_paths': 1, 'ad.acl_lead': 1, 'ad.coerced_auth': 1, 'ad.zerologon': 1, 'ad.gpo_control': 1, 'ad.attack_paths': 1, 'ad.sid_history': 1, 'ad.computer_added': 1 };
  var AD_PRIVESC_KEYS = { dcsync: 1, kerberoasting: 1, 'pass-the-hash': 1, 'golden-ticket': 1, 'dangerous-ad-acl': 1, 'adcs-template-abuse': 1 };
  var INITIAL_CATEGORIES = { access: 1, injection: 1, exploit: 1, web: 1, cve: 1, credential: 1, config: 1, headers: 1, tls: 1, cookies: 1, cors: 1, dns: 1, html: 1, disclosure: 1, crypto: 1, methods: 1 };
  var PRIVESC_FINDING_HINTS = ['dcsync', 'privilege escalation', 'privesc', 'escalat', 'writedacl', 'writeowner', 'genericall', 'genericwrite', 'dangerous', 'acl', 'sudo', 'suid', 'setuid', 'capabilit', 'impersonat', 'potato', 'token', 'unquoted', 'alwaysinstall', 'kernel', 'krbtgt', 'golden', 'silver', 'constrained deleg', 'unconstrained deleg', 'gpo', 'adcs', 'esc'];
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
    if (flags.root || hasKind(t, 'loot.ntds', 'hash.krbtgt', 'persistence.domain', 'access.system') || (t.domain_owned && foothold))
      return isLinuxTarget(t) ? 'root' : 'Administrator / SYSTEM';
    if (flags.local || foothold) return 'User';
    return 'None proven';
  }
  function yn(v) { return v ? '✅ yes' : '— no'; }
  function targetFlagSlots(t) { var s = {}; (t.flags || []).forEach(function (f) { s[f.slot] = 1; }); return s; }
  function compromisedTargets(ctx) { return (ctx.targets || []).filter(function (t) { return oscpPriv(t) !== 'None proven'; }); }

  function looksLikeCommand(ev) {
    var low = (ev || '').toLowerCase();
    if (NON_COMMAND_PREFIXES.some(function (p) { return low.indexOf(p) === 0; })) return false;
    if (ev.indexOf('—') !== -1) return false;         // em-dash = descriptive lineage note
    return true;
  }
  function humanizeCaption(raw, fallback) {
    raw = (raw || '').trim();
    if (!raw) return fallback;
    var low = raw.toLowerCase();
    if (low.indexOf('operator —') === 0 || low.indexOf('operator -') === 0 || low.indexOf('operator:') === 0 || MACHINE_CAPTION_RE.test(raw)) return fallback;
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

  // ── cover / toc ──
  function cover(ctx, profile) {
    var meta = ctx.meta || {};
    var cfg = profile.config || {};
    var pairs = [];
    if (profile.id === 'oscp') {
      pairs.push(['Candidate', cfg.candidate || '«your name»']);
      pairs.push(['OSID', cfg.osid || 'OS-XXXXX']);
    }
    pairs.push(['Engagement', meta.name || '']);
    pairs.push(['Scope', (meta.scope || []).join(', ') || meta.target || '—']);
    if (meta.domain) pairs.push(['Domain', meta.domain]);
    pairs.push(['Generated', meta.generated_at || '—']);
    pairs.push(['Tool', ('obol ' + VERSION).trim()]);
    var blocks = [H(profile.title, 1), KVB(pairs)];
    if (!meta.include_secrets) blocks.push(CALL('Secrets are redacted in this draft. Re-generate with include-secrets for a private working copy.', 'note'));
    return blocks;
  }
  function toc() { return [TOCB()]; }

  // ── objective summary (OSCP) ──
  function objectiveSummary(ctx) {
    var rows = [];
    (ctx.targets || []).forEach(function (t) {
      var slots = targetFlagSlots(t);
      var proof = t.proof || {};
      var proven = {}; (proof.flags || []).forEach(function (r) { proven[r.slot] = r.has_proof; });
      var anyProven = Object.keys(proven).some(function (k) { return proven[k]; });
      var ev = (proof.screenshots || []).length ? 'screenshot' : ((proof.flags || []).some(function (r) { return r.obol_block; }) ? 'obol block' : '—');
      var needReview = (slots.local || slots.root) && !anyProven && !(proof.screenshots || []).length;
      rows.push([
        (t.label || t.host) + ' (' + t.host + ')',
        yn(!!slots.local), yn(!!slots.root), oscpPriv(t), ev, needReview ? '⚠ review' : 'ok',
      ]);
    });
    var blocks = [H('Exam Objective Summary', 2)];
    if (rows.length) blocks.push(TBL(['Target', 'local.txt', 'proof.txt', 'Privilege', 'Evidence', 'Status'], rows));
    else blocks.push(P('No targets recorded.'));
    return blocks;
  }

  // ── methodology ──
  var OSCP_METHODOLOGY = 'Each target was approached with the standard OSCP methodology: full service enumeration, identification and exploitation of an initial access vector, capture of the low-privilege proof (`local.txt`), local privilege-escalation enumeration and exploitation, and capture of the elevated proof (`proof.txt`) from an interactive shell. Every fact below is backed by the exact command that produced it; nothing is asserted without evidence.';
  var GENERIC_METHODOLOGY = 'Testing followed a structured methodology — reconnaissance, enumeration, exploitation, post-exploitation, and lateral movement — with findings triaged by severity and each backed by reproducible evidence. Remediation guidance accompanies each finding.';

  function scopeIps(ctx) {
    var meta = ctx.meta || {};
    var ips = (meta.scope || []).filter(Boolean);
    if (!ips.length) ips = (ctx.targets || []).map(function (t) { return t.host; }).filter(Boolean);
    var seen = {}, out = [];
    ips.forEach(function (ip) { if (ip && !seen[ip]) { seen[ip] = 1; out.push(ip); } });
    return out;
  }
  function methodology(ctx, profile) {
    if (profile.id !== 'oscp') return [H('Methodology', 2), P(GENERIC_METHODOLOGY)];
    var targets = ctx.targets || [];
    var total = targets.length;
    var owned = compromisedTargets(ctx).length;
    var ips = scopeIps(ctx);
    var scopeLine = ips.length ? ips.join(', ') : 'the authorized hosts';
    return [
      H('Methodology', 2), P(OSCP_METHODOLOGY),
      H('Information Gathering', 3),
      P('The information-gathering phase established the scope of the engagement and the live, in-scope systems. Testing was confined to the authorized hosts and networks; no activity was performed outside the authorized scope. The in-scope systems were: ' + scopeLine + '.'),
      H('Service Enumeration', 3),
      P('Each in-scope host was enumerated for exposed TCP/UDP services, and every service was fingerprinted and assessed against known weaknesses. The open ports and services found on each host, and the commands that discovered them, are documented per host below.'),
      H('Penetration', 3),
      P('The penetration phase focused on gaining access to the in-scope systems. During this engagement, ' + owned + ' of ' + total + ' system(s) were successfully compromised. The vulnerability exploited, the steps to reproduce, and the proof captured are documented per host below.'),
      H('Maintaining Access', 3),
      P('obol does not plant persistence or backdoors: no user accounts, services, or implants were installed to maintain access. Access was re-established, when needed, by re-running the documented steps against the recorded credentials/vectors.'),
      H('House Cleaning', 3),
      P('No artifacts were left on the in-scope systems beyond the evidence captured for this report. Any files staged during testing were removed, and no accounts or services were added — nothing requires clean-up by the system owner.'),
    ];
  }

  // ── high-level summary ──
  function footholdDesc(t) {
    var i, f, kind, val;
    for (i = 0; i < (t.findings || []).length; i++) {
      f = t.findings[i]; kind = f.kind || '';
      if (kind.indexOf('foothold.') === 0 || kind.indexOf('access.shell') === 0 || kind === 'winrm.authenticated' || kind === 'rdp.authenticated') {
        val = (f.value && typeof f.value === 'object') ? f.value : {};
        var user = val.user || val.username || '';
        var ev = (f.evidence || '').trim();
        var tool = (ev && looksLikeCommand(ev)) ? ev.split(/\s+/)[0] : '';
        var phrase = tool || 'interactive shell';
        return phrase + (user ? ' as ' + user : '');
      }
    }
    for (i = 0; i < (t.findings || []).length; i++) {
      f = t.findings[i]; kind = f.kind || '';
      if (kind.indexOf('credential.') === 0 && kind !== 'credential.admin') {
        val = (f.value && typeof f.value === 'object') ? f.value : {};
        return 'valid credentials' + (val.user ? ' for ' + val.user : '');
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
  function initialVectors(ctx) {
    var ownedHosts = {}; compromisedTargets(ctx).forEach(function (t) { ownedHosts[t.host] = 1; });
    var titles = [], seen = {};
    ((ctx.findings || {}).targets || []).forEach(function (t) {
      if (!ownedHosts[t.host]) return;
      (t.findings || []).forEach(function (f) {
        if (findingIsPrivesc(f)) return;
        var title = (f.title || '').trim();
        if (title && !seen[title.toLowerCase()]) { seen[title.toLowerCase()] = 1; titles.push(title); }
      });
    });
    return titles;
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
        intro = 'During this engagement, ' + owned.length + ' of ' + total + ' in-scope system(s) were compromised, primarily through ' + shown + '.';
      } else {
        intro = 'During this engagement, ' + owned.length + ' of ' + total + ' in-scope system(s) were compromised.';
      }
      if (adminHosts.length) intro += ' On ' + adminHosts.length + ' system(s), administrative or SYSTEM-level control was achieved. The compromised systems and the initial vector for each are listed below.';
      else intro += ' The compromised systems and the initial vector for each are listed below.';
    } else {
      intro = 'No in-scope systems were fully compromised during this engagement. The systems assessed and the access reached on each are summarised below.';
    }
    blocks.push(P(intro));
    function line(t) {
      var label = t.label || t.host;
      var name = (label && label !== t.host) ? (label + ' (' + t.host + ')') : String(t.host);
      return name + ' — ' + footholdDesc(t) + ' → ' + oscpPriv(t);
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
  function findingIsPrivesc(f) {
    var cat = (f.category || '').toLowerCase();
    var key = (f.key || '').toLowerCase();
    if (cat === 'privesc') return true;
    if (cat === 'ad') return !!AD_PRIVESC_KEYS[key];
    if (INITIAL_CATEGORIES[cat]) return false;
    var hay = (key + ' ' + (f.title || '')).toLowerCase();
    return PRIVESC_FINDING_HINTS.some(function (h) { return hay.indexOf(h) !== -1; });
  }
  function splitFindingsByPhase(findings) {
    return [findings.filter(function (f) { return !findingIsPrivesc(f); }), findings.filter(findingIsPrivesc)];
  }
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
  function cleanFindings(items) {
    var seen = {}, out = [];
    (items || []).forEach(function (f) {
      if (reportIsNoise(f)) return;
      var key = (f.label || f.kind) + '|' + JSON.stringify(f.value);
      if (seen[key]) return;
      seen[key] = 1; out.push(f);
    });
    return out;
  }
  function fmtVal(v) {
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    if (Array.isArray(v)) return v.filter(function (x) { return x !== '' && x != null && !(Array.isArray(x) && !x.length); }).map(fmtVal).join(', ');
    if (v && typeof v === 'object') return Object.keys(v).filter(function (k) { var x = v[k]; return x !== '' && x != null; }).map(function (k) { return (k + ' ' + fmtVal(v[k])).trim(); }).join('; ');
    return String(v);
  }
  function findingLines(items) {
    return cleanFindings(items).map(function (f) {
      var val = f.value, detail = '';
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        detail = Object.keys(val).filter(function (k) { return !DETAIL_SKIP_KEYS[k] && val[k] !== '' && val[k] != null && !(Array.isArray(val[k]) && !val[k].length); })
          .map(function (k) { return k + ': ' + fmtVal(val[k]); }).join(', ').slice(0, 220);
      } else if (val) detail = fmtVal(val);
      var tag = f.origin === 'operator-attested' ? ' _(operator-attested)_' : '';
      return '**' + (f.label || f.kind) + '**' + (detail ? ' — ' + detail : '') + tag;
    });
  }
  function phaseCommands(facts) {
    var seen = [];
    facts.slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); }).forEach(function (f) {
      var ev = (f.evidence || '').trim();
      if (ev && seen.indexOf(ev) === -1 && looksLikeCommand(ev)) seen.push(ev);
    });
    return seen;
  }
  function phaseSteps(facts) {
    var seen = {}, steps = [];
    facts.slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); }).forEach(function (f) {
      var ev = (f.evidence || '').trim();
      if (!ev || !looksLikeCommand(ev) || seen[ev]) return;
      seen[ev] = 1;
      steps.push((f.label || f.kind || 'result') + ' — `' + ev + '`');
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

  function vulnBlock(t, phase, phaseFacts, findings) {
    var host = t.host;
    var finding = findings.length ? findings[0] : null;
    var writeup = (finding && finding.writeup) || {};
    var users = {}; phaseFacts.forEach(function (f) { if (f.value && typeof f.value === 'object' && f.value.user) users[f.value.user] = 1; });
    var userStr = Object.keys(users).sort().join(', ');
    var explanation, fix, severity, parts = [];
    if (phase === 'initial') {
      if (writeup.description) parts.push(writeup.description.replace(/\.$/, ''));
      var hasFoothold = phaseFacts.some(function (f) { var k = f.kind || ''; return k.indexOf('foothold.') === 0 || k.indexOf('access.shell') === 0 || k === 'winrm.authenticated' || k === 'rdp.authenticated'; });
      if (hasFoothold) { var s = 'An initial foothold was established on ' + host; if (userStr) s += ' as ' + userStr; parts.push(s); }
      else if (phaseFacts.some(function (f) { return (f.kind || '').indexOf('credential.') === 0; })) parts.push('Valid credential material for ' + host + ' was recovered during enumeration');
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
      if (domainWin) parts.push('Domain-level compromise was achieved from ' + host + ' — credential material (e.g. the NTDS/krbtgt secrets) was extracted, yielding administrative control across the domain');
      else if (sysAdmin || reachedFull) { var lvl = isLinuxTarget(t) ? 'root' : 'administrative/SYSTEM level'; parts.push('Local privileges on ' + host + ' were escalated to ' + lvl); }
      if (top && !domainWin && !sysAdmin && !reachedFull) parts.push('A privilege-escalation lead was identified on ' + host + ' (' + (top.label || top.kind) + ')');
      if (!parts.length) parts.push('No privilege-escalation was recorded for ' + host);
      explanation = parts.map(function (p) { return p.trim(); }).filter(Boolean).join('. ') + '.';
      fix = writeup.remediation || (finding && finding.remediation) || GENERIC_PRIVESC_FIX;
      severity = finding ? String(finding.severity || 'info').replace(/^\w/, function (c) { return c.toUpperCase(); }) : ((domainWin || sysAdmin || reachedFull) ? 'Critical' : (phaseFacts.length ? 'High' : 'Informational'));
    }
    var blocks = [labeledField('Vulnerability Explanation', explanation), labeledField('Vulnerability Fix', fix), labeledField('Severity', severity)];
    var steps = phaseSteps(phaseFacts);
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
  function proofScreenshotBlocks(t, slot, ctx, host, label) {
    var out = [P('**' + label + '**')];
    var imgs = [];
    proofShotsForSlot(t, slot).forEach(function (s) {
      if (s.data_uri || s.path) imgs.push(IMG({ caption: humanizeCaption(s.caption, label), data_uri: s.data_uri, path: s.path }));
    });
    imgs = imgs.concat(proofRenderImages(ctx, host, slot, label));
    if (imgs.length) out = out.concat(imgs);
    else out.push(P('_No proof screenshot was captured for this slot. Read the flag file in an interactive shell with the target IP visible for a compliant proof._'));
    return out;
  }
  function flagContentsBlock(t, slot, includeSecrets, label) {
    var row = flagForSlot(t, slot);
    var flag = (row.rawFlag || '').trim();
    if (includeSecrets && flag) return [P('**' + label + ':**'), CODE(flag)];
    if (flag) return [labeledField(label, '«redacted»')];
    return [labeledField(label, '«not captured»')];
  }

  function perMachine(ctx, profile) {
    var blocks = [H('Per-Machine Walkthrough', 2)];
    var targets = ctx.targets || [];
    if (!targets.length) { blocks.push(P('No targets recorded.')); return blocks; }
    var includeSecrets = !!(ctx.meta && ctx.meta.include_secrets);
    targets.forEach(function (t) {
      var host = t.host, label = t.label || host;
      blocks.push(PB());
      blocks.push(H(label + ' — ' + host, 3));
      var hn = (t.hostname || '').trim(), dom = (t.domain || '').trim();
      var fqdn = t.fqdn || ((hn && dom && hn.indexOf('.') === -1) ? (hn + '.' + dom) : '—');
      blocks.push(KVB([
        ['IP', host], ['Hostname', t.hostname || '—'], ['FQDN', fqdn], ['Domain', t.domain || '—'],
        ['OS', t.os || '—'], ['Privilege reached', oscpPriv(t)],
      ]));
      var findings = hostFindings(ctx, host);
      var phases = phaseBuckets(t, findings);
      var split = splitFindingsByPhase(findings);
      var initialFindings = split[0], privescFindings = split[1];

      blocks.push(H('Service Enumeration', 4));
      if ((t.open_ports || []).length) blocks.push(TBL(['Server IP Address', 'Ports Open'], [[host, t.open_ports.join(', ')]]));
      var enumLines = findingLines(phases.enum);
      if (enumLines.length) blocks.push(UL(enumLines));
      else if (!(t.open_ports || []).length) blocks.push(P('_No service-enumeration facts recorded for this host._'));
      var enumCmds = phaseCommands(phases.enum);
      if (enumCmds.length) { blocks.push(P('**Nmap Scan Results / Enumeration Commands:**')); blocks.push(CODE(enumCmds.join('\n'))); }
      blocks = blocks.concat(screenshotBlocks(ctx, 'service_enum', host, 'Nmap Scan Results'));

      blocks.push(H('Initial Access', 4));
      blocks = blocks.concat(vulnBlock(t, 'initial', phases.initial, initialFindings));
      var initUser = '';
      for (var i = 0; i < phases.initial.length; i++) { if (phases.initial[i].value && typeof phases.initial[i].value === 'object' && phases.initial[i].value.user) { initUser = phases.initial[i].value.user; break; } }
      var footholdCap = 'Initial foothold on ' + host + (initUser ? ' as ' + initUser : '');
      blocks = blocks.concat(screenshotBlocks(ctx, 'initial_access', host, footholdCap));
      blocks = blocks.concat(proofScreenshotBlocks(t, 'local', ctx, host, 'local.txt Proof Screenshot'));
      blocks = blocks.concat(flagContentsBlock(t, 'local', includeSecrets, 'local.txt Contents'));

      blocks.push(H('Privilege Escalation', 4));
      blocks = blocks.concat(vulnBlock(t, 'privesc', phases.privesc, privescFindings));
      blocks = blocks.concat(screenshotBlocks(ctx, 'privesc', host, 'Privilege escalation on ' + host));

      blocks.push(H('Post-Exploitation / Proof', 4));
      blocks = blocks.concat(proofScreenshotBlocks(t, 'root', ctx, host, 'proof.txt Proof Screenshot'));
      blocks = blocks.concat(flagContentsBlock(t, 'root', includeSecrets, 'proof.txt Contents'));
      blocks = blocks.concat(screenshotBlocks(ctx, 'commands', host, 'Command output'));
    });
    return blocks;
  }

  // ── attack narrative (browser adaptation of storyline: essential moves from the fact ledger) ──
  function commandsFor(t) {
    var seen = [];
    (t.findings || []).slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); }).forEach(function (f) {
      var ev = (f.evidence || '').trim();
      if (ev && seen.indexOf(ev) === -1 && looksLikeCommand(ev)) seen.push(ev);
    });
    return seen.slice(0, 40);
  }
  function attackNarrative(ctx) {
    var owned = compromisedTargets(ctx);
    if (!owned.length) return [];
    var blocks = [H('Attack Narrative', 2), P('The path to each objective, derived from the fact ledger (any methodology). Everything else was enumeration/noise.')];
    owned.forEach(function (t) {
      blocks.push(H((t.label || t.host) + ' (' + t.host + ')', 3));
      var cmds = commandsFor(t);
      if (cmds.length) {
        var rows = cmds.map(function (c, i) { return [String(i + 1), '—', (c.split(/\s+/)[0] || ''), c]; });
        blocks.push(TBL(['#', 'Technique', 'Tool', 'Command'], rows));
      } else {
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
      var gap = compliant ? '' : 'captured value present but no interactive-shell screenshot showing the file contents AND the target IP — OffSec awards ZERO points without it.';
      return PROOF({
        label: (r.label || slot) + '  ·  ' + (r.path || slot), flag: r.flag || '', path: r.path || '',
        screenshot: shot ? (shot.label || 'operator screenshot') : '', compliant: compliant, gap: gap,
        block: r.block || '', block_label: r.block_label || '', shot_data_uri: shot ? (shot.data_uri || '') : '',
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
      blocks.push(H((t.label || t.host) + ' (' + t.host + ')', 3));
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
      blocks.push(CALL('These wrapped/manual command outputs contain flag-like values or identity blocks that obol did NOT auto-promote to an objective. Confirm and record them so they count.', 'warn'));
      cands.forEach(function (c) {
        blocks.push(H((c.tool || 'command') + ' — ' + (c.at || ''), 4));
        blocks.push(CODE(c.command));
        blocks.push(UL(c.values.map(function (v) { return 'candidate value: `' + v + '`'; })));
      });
    }
    return blocks.concat(shots);
  }

  // ── generic / executive sections ──
  function execSummary(ctx) {
    var meta = ctx.meta || {}, counts = ctx.severity_counts || {};
    var total = SEV_ORDER.reduce(function (s, k) { return s + (counts[k] || 0); }, 0);
    var hosts = (ctx.targets || []).length;
    var levels = SEV_ORDER.filter(function (s) { return counts[s]; }).length;
    var line = 'This assessment of ' + (meta.name || 'the environment') + ' covered ' + hosts + ' host(s) and identified ' + total + ' finding(s) across ' + levels + ' severity level(s). The highest-impact issues and the overall risk posture are summarised below; per-finding detail and remediation follow.';
    return [H('Executive Summary', 2), P(line)];
  }
  function riskOverview(ctx) {
    var counts = ctx.severity_counts || {};
    var rows = SEV_ORDER.filter(function (s) { return counts[s]; }).map(function (s) { return [s.charAt(0).toUpperCase() + s.slice(1), String(counts[s]) ]; });
    return [H('Risk Overview', 2), TBL(['Severity', 'Count'], rows.length ? rows : [['—', '0']])];
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
      var pairs = [['Host', f.host || '']];
      if (f.kev) pairs.push(['KEV', 'known-exploited']);
      blocks.push(KVB(pairs));
      if (f.detail || f.description) blocks.push(P(f.detail || f.description));
      if (remediation && f.remediation) blocks.push(P('**Remediation:** ' + f.remediation));
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
        var flag = (row.rawFlag || '').trim();
        if (!flag) return '«missing»';
        return includeSecrets ? flag : '«captured»';
      }
      rows.push([ipLabel, cell('local'), cell('root')]);
    });
    if (!rows.length) return [];
    return [H('Appendix: Proof and Local Contents', 3), TBL(['IP (Hostname)', 'local.txt', 'proof.txt'], rows)];
  }
  function appendix(ctx, profile) {
    var blocks = [PB(), H('Appendix: Key Commands & Evidence', 2)];
    var seen = {}, rows = [];
    (ctx.timeline || []).forEach(function (r) {
      var cmd = (r.command || '').trim();
      if (!cmd || seen[cmd] || !(r.produced && r.produced.length)) return;
      seen[cmd] = 1; rows.push([r.tool || '', cmd, r.status || '']);
    });
    if (rows.length) { blocks.push(H('Commands that produced evidence', 3)); blocks.push(TBL(['Tool', 'Command', 'Status'], rows)); }
    var ev = (ctx.evidence || []).filter(function (e) { return e.include !== false; });
    if (ev.length) {
      blocks.push(H('Evidence', 3));
      blocks.push(UL(ev.map(function (e) { return '`' + (e.stored || e.id) + '` — ' + (e.caption || e.phase || e.kind || 'evidence'); })));
    }
    blocks = blocks.concat(screenshotBlocks(ctx, 'appendix', '', 'Appendix evidence'));
    blocks = blocks.concat(proofAndLocalTable(ctx));
    if (profile && profile.id === 'oscp') {
      var usedMsf = (ctx.timeline || []).some(function (r) { var c = (r.command || '').toLowerCase(); return c.indexOf('metasploit') !== -1 || c.indexOf('meterpreter') !== -1 || c.indexOf('msfconsole') !== -1; });
      blocks.push(H('Appendix: Metasploit / Meterpreter Usage', 3));
      blocks.push(P(usedMsf ? 'Metasploit/Meterpreter was used on the machine(s) noted in the walkthrough.' : 'N/A — Metasploit/Meterpreter was not used during this engagement.'));
      blocks.push(H('Appendix: Completed Buffer Overflow Code', 3));
      blocks.push(P('N/A — no buffer-overflow exploit was developed or used during this engagement.'));
    }
    return blocks;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 7. profiles + dispatch (ported from report_profiles/__init__.py)
  // ─────────────────────────────────────────────────────────────────────────
  var PROFILES = {
    oscp: {
      id: 'oscp', name: 'OSCP', title: 'OSCP Exam Report', subtitle: 'Offensive Security Certified Professional — exam report',
      sections: ['cover', 'toc', 'high_level_summary', 'recommendations', 'objective_summary', 'methodology', 'narrative', 'per_machine', 'proof', 'manual_evidence', 'appendix'],
      risk: 'severity', exec_summary: false, screenshots_required: true, remediation: false, include_secrets_default: false,
      filename_pattern: 'OSCP-{osid}-Exam-Report',
      note: 'Per-machine, proof-first: local.txt/proof.txt read in an interactive shell with the target IP visible, and the exact steps to reproduce. No executive fluff.',
      config: {},
    },
    generic: {
      id: 'generic', name: 'Generic Pentest', title: 'Penetration Test Report', subtitle: 'Professional penetration test report',
      sections: ['cover', 'toc', 'high_level_summary', 'recommendations', 'methodology', 'findings', 'per_machine', 'proof', 'manual_evidence', 'appendix'],
      risk: 'severity', exec_summary: false, screenshots_required: false, remediation: true, include_secrets_default: false,
      filename_pattern: '{name}-pentest-report',
      note: 'Methodology, findings with remediation, per-target detail, and evidence appendices.', config: {},
    },
    executive: {
      id: 'executive', name: 'Executive', title: 'Security Assessment — Executive Report', subtitle: 'Executive summary and risk overview',
      sections: ['cover', 'exec_summary', 'risk_overview', 'findings', 'appendix'],
      risk: 'rating', exec_summary: true, screenshots_required: false, remediation: true, include_secrets_default: false,
      filename_pattern: '{name}-executive-report',
      note: 'Leadership-facing: executive summary, risk ratings, top findings, remediation posture.', config: {},
    },
    technical: {
      id: 'technical', name: 'Technical', title: 'Technical Assessment Report', subtitle: 'Full technical detail — findings, per-machine, evidence',
      sections: ['cover', 'toc', 'high_level_summary', 'recommendations', 'methodology', 'findings', 'per_machine', 'proof', 'manual_evidence', 'appendix'],
      risk: 'severity', exec_summary: false, screenshots_required: false, remediation: true, include_secrets_default: false,
      filename_pattern: '{name}-technical-report',
      note: 'Deep technical walkthrough with full command/evidence detail for every target.', config: {},
    },
    oswp: {
      id: 'oswp', name: 'OSWP', title: 'OSWP Exam Report', subtitle: 'Offensive Security Wireless Professional — exam report',
      sections: ['cover', 'toc', 'objective_summary', 'wireless', 'per_machine', 'proof', 'manual_evidence', 'appendix'],
      risk: 'severity', exec_summary: false, screenshots_required: true, remediation: false, include_secrets_default: false,
      filename_pattern: 'OSWP-{osid}-Exam-Report',
      note: 'Per authorized network: the captured handshake/PMKID, the crack, the recovered key, and the evidence.', config: {},
    },
  };
  var DEFAULT_PROFILE = 'oscp';
  var ALIASES = { industry: 'executive', cpts: 'technical' };

  function resolve(name, ctx) {
    var key = String(name || '').trim().toLowerCase();
    key = ALIASES[key] || key;
    var base = PROFILES[key] || PROFILES[DEFAULT_PROFILE];
    var prof = Object.assign({}, base, { config: {} });
    if (ctx && ctx.meta) {
      if (ctx.meta.osid) prof.config.osid = ctx.meta.osid;
      if (ctx.meta.candidate) prof.config.candidate = ctx.meta.candidate;
    }
    return prof;
  }

  function defaultFor(ctx) {
    var plat = String((ctx && ctx.meta && ctx.meta.platform) || '').toLowerCase();
    if (plat.indexOf('oswp') !== -1) return 'oswp';
    if (plat === 'cpts') return 'technical';
    if (plat.indexOf('oscp') !== -1 || plat === '' || plat === 'oscp+' || plat === 'pwk') return 'oscp';
    return 'generic';
  }

  var SECTION_BUILDERS = {
    cover: function (ctx, p) { return cover(ctx, p); },
    toc: function () { return toc(); },
    high_level_summary: function (ctx) { return highLevelSummary(ctx); },
    recommendations: function (ctx) { return recommendations(ctx); },
    objective_summary: function (ctx) { return objectiveSummary(ctx); },
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
    return blocks;
  }

  function filenameStem(profile, ctx) {
    var meta = (ctx && ctx.meta) || {};
    var osid = (profile.config && profile.config.osid) || 'OS-XXXXX';
    var name = String(meta.name || 'obol').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'obol';
    return profile.filename_pattern.replace('{osid}', osid).replace('{name}', name);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 8. validate — OSCP readiness (ported from report_profiles.validate)
  // ─────────────────────────────────────────────────────────────────────────
  function validate(profileName, ctx) {
    var profile = resolve(profileName, ctx);
    var gaps = [];
    var targets = (ctx && ctx.targets) || [];
    if (!targets.length) gaps.push({ level: 'fail', message: 'No targets recorded — nothing to report.' });
    if (profile.id === 'oscp' || profile.id === 'oswp') {
      if (!(profile.config && profile.config.osid)) {
        gaps.push({ level: 'warn', message: 'OSID not set — filename will be ' + filenameStem(profile, ctx) + '.pdf. Set it in the engagement profile.' });
      }
      if (!(profile.config && profile.config.candidate)) {
        gaps.push({ level: 'warn', message: 'Candidate name not set for the cover page. Set it in the engagement profile.' });
      }
    }
    targets.forEach(function (t) {
      var host = t.label || t.host;
      var slots = {}; (t.flags || []).forEach(function (f) { slots[f.slot] = 1; });
      if (!Object.keys(slots).length) { gaps.push({ level: 'warn', message: host + ': no flags captured.' }); return; }
      var proof = t.proof || {};
      var shots = proof.screenshots || [];
      (proof.flags || []).forEach(function (r) {
        var compliant = !!r.obol_compliant;
        var hasShot = !!shots.length;
        if (profile.screenshots_required && !(compliant || hasShot)) {
          gaps.push({ level: 'fail', message: host + ': ' + r.slot + ' flag has NO interactive-shell screenshot showing the file + target IP — OffSec awards ZERO points without it.' });
        }
      });
    });
    (ctx.proof_candidates || []).forEach(function (c) {
      gaps.push({ level: 'warn', message: 'Unpromoted proof candidate in `' + (c.tool || 'a command') + '` — capture it so it counts.' });
    });
    return gaps;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // public API
  // ─────────────────────────────────────────────────────────────────────────
  OBOL.report = {
    buildContext: buildContext,
    PROFILES: PROFILES,
    DEFAULT_PROFILE: DEFAULT_PROFILE,
    resolve: resolve,
    defaultFor: defaultFor,
    document: document,
    toMarkdown: toMarkdown,
    toHtml: toHtml,
    validate: validate,
    filenameStem: filenameStem,
    // redaction (two-layer, default ON)
    redact: redactCommand,
    redactValue: redactValue,
    knownSecrets: knownSecrets,
    // proof labeling (UI-facing proof discipline)
    proofLabels: proofLabels,
    isInteractiveShell: isInteractiveShell,
    identityPresent: identityPresent,
    // low-level helpers exposed for surfaces/tests
    normalizeSeverity: normalizeSeverity,
    factCategory: factCategory,
    oscpPrivLevel: oscpPriv,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
