/*!
 * obol ui - ingest.js - the shared evidence-ingest core (no DOM).
 * Parses a paste/file with the conservative parsers, mints only proven facts, and records the
 * command+output (capped) as verbatim report evidence. Both the Evidence route and the coach's
 * inline per-command ingestion call this, so paste-anywhere behaves identically.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function _stripAnsi(s) {
    return String(s || '').replace(/\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]/g, '');
  }

  var _PROMPT_LINE = [
    /^\s*(?:[┌╭]──.*)?[└╰]─\s*[#$%>]\s+(\S.*)$/,                         // Kali/Parrot two-line prompt (cmd on └─$ or ╰─$)
    /^\s*(?:\([^)]+\)\s*)?\[?[\w.\-]+@[\w.\-]+(?::[^\s#$%\]]*|\s+[^\r\n#$%\]]*)\]?\s*[#$%]\s+(\S.*)$/, // user@host:cwd$ or [user@host cwd]$ cmd
    /^(?:\*?Evil-WinRM\*?\s+)?PS\s+[A-Za-z]:[^>]*>\s+(\S.*)$/,           // PowerShell PS C:\...> cmd, incl. *Evil-WinRM* PS prefix
    /^\s*[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*>\s+(\S.*)$/, // Windows cmd.exe C:\Users\bob> cmd
    /^\s*(?:sh|bash|zsh|dash|ksh)-[\d.]+\s*[#$]\s+(\S.*)$/,              // sh-5.1$ / bash-5.1# cmd
    /^\s*SQL\s*\([^)]*\)\s*>\s*(\S.*)$/i,                                // impacket-mssqlclient: SQL (sa dbo@master)> cmd
    /^\s*(?:mysql|MariaDB\s*\[[^\]]*\])\s*>\s*(\S.*)$/i,                 // mysql> or MariaDB [db]> cmd
    /^\s*[a-zA-Z_][a-zA-Z0-9_]*=[#>-]\s+(?![{"'\[])(\S.*)$/,             // psql: postgres=# cmd or app=> cmd
    /^\s*smb:\s*\\[^>]*>\s*(\S.*)$/i,                                    // smbclient: smb: \> cmd
    /^\s*rpcclient\s*\$>\s*(\S.*)$/i,                                    // rpcclient $> cmd
    /^\s*ftp>\s*(\S.*)$/i,                                               // ftp> cmd
    /^\s*meterpreter\s*>\s*(\S.*)$/i,                                    // meterpreter > cmd
  ];
  var _PROMPT_PREFIX = [
    null, null, null, null, null,
    'mssqlclient', 'mysql', 'psql', 'smbclient', 'rpcclient', 'ftp', 'meterpreter'
  ];
  function _promptCmd(raw) {
    var clean = _stripAnsi(raw);
    for (var i = 0; i < _PROMPT_LINE.length; i++) {
      var m = _PROMPT_LINE[i].exec(clean);
      if (m) {
        var cmd = m[1].trim();
        var pfx = _PROMPT_PREFIX[i];
        if (pfx && !new RegExp('^' + pfx + '\\b', 'i').test(cmd)) {
          cmd = pfx + ' ' + cmd;
        }
        return cmd;
      }
    }
    return null;
  }

  // Derive the command line from a full-terminal paste when the operator didn't type one.
  var TOOL_HEAD = /^(sudo\s+)?(nmap|rustscan|masscan|netexec|nxc|crackmapexec|cme|smbclient|smbmap|rpcclient|enum4linux[\w-]*|ldapsearch|kerbrute|impacket[\w.-]*|GetNPUsers[\w.]*|GetUserSPNs[\w.]*|secretsdump[\w.]*|evil-winrm|ffuf|feroxbuster|gobuster|wfuzz|dirsearch|nikto|whatweb|curl|wget|sqlmap|hydra|john|hashcat|responder|bloodhound[\w.-]*|sharphound[\w.-]*|bloodyad|dacledit|certipy[\w-]*|rubeus[\w.]*|pywhisker[\w.]*|sccmhunter[\w.]*|sharpsccm|wmiexec[\w.]*|psexec[\w.]*|smbexec[\w.]*|atexec[\w.]*|dcomexec[\w.]*|getst[\w.]*|gettgt[\w.]*|lookupsid[\w.]*|addcomputer[\w.]*|gpp-decrypt|getnpusers[\w.]*|getuserspns[\w.]*|dig|host|snmpwalk|ssh|ftp|mssqlclient[\w.-]*|mysql|psql|meterpreter)\b/i;
  function _normPromptCmd(s) {
    return String(s || '').trim().replace(/\s+/g, ' ');
  }
  function _extractPrompts(text) {
    var lines = String(text || '').split(/\r?\n/), out = [];
    for (var i = 0; i < lines.length && i < 600; i++) {
      var raw = _stripAnsi(lines[i]), t = raw.trim(), found = '';
      var pc = _promptCmd(raw);
      if (pc) found = pc;
      if (!found) {
        var pm = raw.replace(/^.*?[$#]\s+/, '').trim();
        if (pm !== t && TOOL_HEAD.test(pm)) found = pm;
      }
      if (!found) {
        var ps = raw.replace(/^\s*PS[^>]*>\s+/i, '').trim();
        if (ps !== t && TOOL_HEAD.test(ps)) found = ps;
      }
      if (found) out.push({ cmd: found, lineIdx: i });
    }
    return out;
  }
  function deriveCommand(text, preferredCmd) {
    var prompts = _extractPrompts(text);
    if (!prompts.length) return '';
    if (preferredCmd) {
      var normPref = _normPromptCmd(preferredCmd);
      for (var i = prompts.length - 1; i >= 0; i--) {
        if (_normPromptCmd(prompts[i].cmd) === normPref) return prompts[i].cmd;
      }
    }
    return prompts[prompts.length - 1].cmd;
  }
  function _trimPriorScrollback(text, preferredCmd, activities) {
    var prompts = _extractPrompts(text);
    if (prompts.length <= 1) return text;
    var normPref = _normPromptCmd(preferredCmd);
    var targetIdx = -1;
    if (normPref) {
      for (var i = prompts.length - 1; i >= 0; i--) {
        if (_normPromptCmd(prompts[i].cmd) === normPref) { targetIdx = i; break; }
      }
    }
    if (targetIdx <= 0 && Array.isArray(activities) && activities.length) {
      var firstNorm = _normPromptCmd(prompts[0].cmd);
      var firstAlreadyRan = activities.some(function (a) { return a && _normPromptCmd(a.command) === firstNorm; });
      if (firstAlreadyRan) targetIdx = prompts.length - 1;
    }
    if (targetIdx <= 0) return text;
    var lines = String(text || '').split(/\r?\n/);
    var startLine = prompts[targetIdx].lineIdx;
    while (startLine > 0 && startLine > prompts[targetIdx].lineIdx - 3) {
      var prev = _stripAnsi(lines[startLine - 1]).trim();
      if (/^(?:[┌╭]──|\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/.test(prev)) startLine--;
      else break;
    }
    return lines.slice(startLine).join('\n');
  }

  // The parser dispatch keys on the command that produced the output - which tool ran, with which
  // flags. When the operator pastes raw output with NO command (a redirected file, a screenshot's text,
  // any tool run out of obol's suggested order, or a paste dropped on a move whose tool it isn't),
  // recover a routing hint from the paste itself: every command-ish line (a shell-prompt line, OR a line
  // that leads with a tool obol parses) plus content signatures for output that names its own tool. What
  // is recovered is only ADDED to the dispatch label - never to lineage - and every parser stays
  // content/proof-bound, so a recovered token can ENABLE the right parser but can never manufacture a
  // fact the output doesn't support.
  var TOOL_HINTS = {};
  ('nmap rustscan masscan nxc netexec crackmapexec cme ldapsearch smbclient smbmap rpcclient '
    + 'enum4linux enum4linux-ng gpp-decrypt wpscan kerbrute getnpusers getnpusers.py getuserspns '
    + 'getuserspns.py secretsdump secretsdump.py certipy certipy-ad bloodyad bloodhound '
    + 'bloodhound-python sharphound evil-winrm hashcat john responder ntlmrelayx ntlmrelayx.py getst '
    + 'getst.py gettgt gettgt.py wmiexec wmiexec.py psexec psexec.py smbexec atexec dcomexec lookupsid '
    + 'lookupsid.py rubeus pywhisker sccmhunter sharpsccm impacket-secretsdump impacket-getuserspns '
    + 'impacket-getnpusers nikto nuclei feroxbuster ffuf gobuster dirb dirsearch whatweb httpx curl wget sqlmap '
    + 'hydra dig host fierce dnsrecon volatility vol.py git-dumper ike-scan penelope ftp lftp snmpwalk '
    + 'onesixtyone showmount rpcinfo id whoami sudo uname hostname ipconfig ifconfig systeminfo net '
    + 'wevtutil enable_xp_cmdshell xp_cmdshell exec sp_configure reconfigure select show use describe '
    + 'tables get mget put ls dir cd pwd enumdomusers enumalsgroups querydispinfo queryuser getdompwinfo '
    + 'lookupnames mssqlclient mysql psql meterpreter').split(' ').forEach(function (t) { TOOL_HINTS[t] = 1; });
  var PROMPT_SIGIL_RE = /[#$][ \t]+(\S.*\S|\S)\s*$/;
  function sniffCommand(text) {
    var lines = String(text || '').split(/\r?\n/), hits = [], seen = {};
    for (var i = 0; i < lines.length && i < 600 && hits.length < 12; i++) {
      var raw = _stripAnsi(lines[i]), line = raw.trim();
      if (!line) continue;
      var m = PROMPT_SIGIL_RE.exec(raw), cand = '';
      if (m) { cand = m[1].trim(); }
      else {
        var first = line.split(/\s+/)[0], base = first.split('/').pop().toLowerCase();
        if (TOOL_HINTS[base] || TOOL_HINTS[first.toLowerCase()]) cand = line;
      }
      if (!cand || seen[cand]) continue;
      var tok = cand.split(/\s+/)[0].split('/').pop().toLowerCase();
      if (m || TOOL_HINTS[tok] || TOOL_HINTS[tok.replace(/\.py$/, '')]) { seen[cand] = 1; hits.push(cand); }
    }
    return hits.join('  ');
  }
  // Each pattern is specific enough that a match means "this really is that tool's output". The token is
  // shaped to the dispatcher's gate (nmap/nxc gates require a trailing space, so tokens carry one).
  // A token is a string, OR a function of the regex match returning the token - so a signature can carry
  // through what it captured (the nxc PROTOCOL) instead of guessing. Emitting a fixed 'nxc smb' for every
  // protocol banner was the bug: `nxc ldap` output wrongly recovered as `nxc smb`, which then marked the
  // unrun `nxc smb` credential-check as ran.
  var CONTENT_SIGNATURES = [
    [/Nmap scan report for|Starting Nmap|^PORT\s+STATE\s+SERVICE/im, 'nmap scan'],
    [/^(SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+\s+\[[-*+]\]/m, function (m) { return 'nxc ' + m[1].toLowerCase(); }],
    [/^\S+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::/m, 'secretsdump'],
    [/\$krb5tgs\$/, 'getuserspns'],
    [/\$krb5asrep\$/, 'getnpusers'],
    [/SCCMHunter|NetworkAccess(?:Username|Password|Account)\s*[:=]/i, 'sccmhunter'],
    // bloodyAD `get writable` dump - a distinguishedName block followed by a bare WRITE/CREATE_CHILD attr.
    // Recovering it lets the coach mark the get-writable enumeration ran once you attach its 50k-line file.
    [/distinguishedName:[\s\S]{0,4000}?\n[A-Za-z][\w-]*:[ \t]*(?:WRITE|CREATE_CHILD)[ \t]*(?:\r?\n|$)/i, 'bloodyad get writable'],
  ];
  function contentSignatures(text) {
    var body = String(text || ''), out = [];
    for (var i = 0; i < CONTENT_SIGNATURES.length; i++) {
      var m = CONTENT_SIGNATURES[i][0].exec(body);
      if (m) { var tok = CONTENT_SIGNATURES[i][1]; out.push(typeof tok === 'function' ? tok(m) : tok); }
    }
    return out.join('  ');
  }
  // The command actually passed to the dispatch: the honest command, widened with anything the paste
  // reveals about which tool(s) it came from. Never narrows, only adds.
  function dispatchLabel(cmd, text) {
    var recovered = [sniffCommand(text), contentSignatures(text)].filter(Boolean).join('  ');
    var full = cmd ? (cmd + '  ' + recovered) : recovered;
    if (/\bxp_cmdshell\b/i.test(full) && !/\b(?:wmiexec|smbexec|psexec|atexec)\b/i.test(full)) {
      full += '  wmiexec';
    }
    return full;
  }

  // Did this paste come from a tool obol recognizes actually RUNNING (vs. junk or an unrelated blob)?
  // The move's own command names the tool; failing that, the paste's own signatures do. Used to tell a
  // "the tool ran and simply found nothing" result apart from "you pasted something unparseable".
  function extractTool(cmd) {
    if (!cmd) return '';
    var toks = String(cmd).trim().split(/\s+/);
    var i = 0;
    while (i < toks.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(toks[i])) i++;
    if (i >= toks.length) return '';
    var first = toks[i].split('/').pop().toLowerCase().replace(/;+$/, '').replace(/\.(py|exe)$/, '');
    if (first.charAt(0) === '[') return 'powershell';
    if (first === 'for' || first === 'while') {
      var doMatch = String(cmd).match(/\bdo\s+([A-Za-z0-9_./-]+)/i);
      if (doMatch && doMatch[1]) {
        return doMatch[1].split('/').pop().toLowerCase().replace(/;+$/, '').replace(/\.(py|exe)$/, '');
      }
    }
    if (first === 'sudo') {
      i++;
      while (i < toks.length) {
        var t = toks[i];
        if (t === '-l' || t === '--list' || t === '-V' || t === '--version') return 'sudo';
        if (t === '-u' || t === '-g' || t === '-U' || t === '-h') { i += 2; continue; }
        if (/^--?[a-zA-Z]/.test(t)) { i++; continue; }
        return t.split('/').pop().toLowerCase().replace(/;+$/, '').replace(/\.(py|exe)$/, '');
      }
      return 'sudo';
    }
    if (/^[a-z0-9]+(?:-[a-z0-9]+)+$/i.test(first) && !TOOL_HINTS[first] && i + 1 < toks.length) {
      var second = toks[i + 1].split('/').pop().toLowerCase().replace(/;+$/, '').replace(/\.(py|exe)$/, '');
      if (TOOL_HINTS[second]) return second;
    }
    return first;
  }
  function firstToolToken(cmd) {
    return extractTool(cmd);
  }
  function recognizesTool(cmd, text) {
    var f = firstToolToken(cmd);
    if (f && TOOL_HINTS[f]) return true;
    return !!(sniffCommand(text) || contentSignatures(text));
  }
  // Markers that mean the command did NOT complete cleanly (a usage/error/auth/network failure), so an
  // empty result is "it broke", not "it ran and found nothing" - obol must not retire the move on these.
  // Kept specific so a benign "Container not found" / "No results found" is NOT read as an error.
  var ERR_MARKERS = /\busage:|\btraceback\b|command not found|no such file|unrecognized option|invalid option|\bmissing option\b|permission denied|access is denied|status_access_denied|status_logon_failure|nt_status_[a-z0-9_]+|error enumerating|ldaperr:|operationserror|successful bind must be completed|\bunauthorized\b|logon failure|connection refused|could not connect|connection reset|name or service not known|\berror:/i;
  function looksLikeError(text) { return ERR_MARKERS.test(String(text || '')); }

  function outputIdentity(text) {
    var m = /^\s*(SMB|LDAP|WINRM|SSH|RDP|FTP|MSSQL|WMI)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\S+\s+\[[+-]\]\s+([^\r\n]+)/im.exec(String(text || ''));
    if (!m) return null;
    var auth = /^([^\s:]+):/.exec(m[3]);
    if (!auth) return { target: m[2], service: m[1].toLowerCase(), principal: '' };
    var result = { target: m[2], service: m[1].toLowerCase(), principal: auth[1] };
    if (OBOL._parserCommon && OBOL._parserCommon._parse_auth_material) {
      var material = OBOL._parserCommon._parse_auth_material(m[3]);
      if (material[1] && material[2] && !/^(?:\*{3,}|<redacted>|\[redacted\])$/i.test(material[2])) {
        result.credential = { user: material[1], domain: material[0] || '' };
        if (/^(?:[a-f0-9]{32}:)?[a-f0-9]{32}$/i.test(material[2])) result.credential.nthash = material[2].split(':').pop();
        else result.credential.password = material[2];
      }
    }
    return result;
  }
  function principalName(value) { return String(value || '').toLowerCase().replace(/\.$/, ''); }
  function executionLocus(command, cmdObj, fallback) {
    if (OBOL.pack && OBOL.pack.commandExecutionLocus && (command || cmdObj)) {
      return OBOL.pack.commandExecutionLocus(cmdObj || { tool: extractTool(command), run: command });
    }
    return fallback || 'remote';
  }
  function sourceBinding(opts, eng) {
    opts = opts || {}; eng = eng || {};
    var text = String(opts.text || ''), params = eng.params || {}, explicit = String(opts.command || '').trim();
    var derived = deriveCommand(text, explicit), revealed = sniffCommand(text), signature = contentSignatures(text);
    var observed = outputIdentity(text), known = (eng.targets || []).map(function (t) { return t.ip || t.id; }).filter(Boolean);
    var observedTarget = detectTarget('', text, { known: known, lhost: params.lhost || '' });
    var observedService = observed && observed.service || (OBOL.context && OBOL.context.serviceOf ? OBOL.context.serviceOf(signature) : '');
    var scopeTarget = /^host:/.test(opts.scope || '') ? opts.scope.slice(5) : '';
    var last = !derived && !explicit && !revealed && !opts.actionId ? getLastCopied() : null;
    if (last && ((observedTarget && observedTarget !== last.target)
      || (scopeTarget && scopeTarget !== last.target && !opts.fromSession)
      || (observedService && (!last.context || !last.context.service || observedService !== last.context.service))
      || (observed && observed.principal && last.context && last.context.principal && principalName(observed.principal) !== principalName(last.context.principal)))) last = null;
    var command = derived || explicit || (last && last.command) || '';
    var target = opts.forceTarget ? scopeTarget || (typeof opts.forceTarget === 'string' ? opts.forceTarget : params.target || '') : observedTarget || (last && last.target) || scopeTarget
      || detectTarget(command, text, { known: known, lhost: params.lhost || '' }) || params.target || '';
    return { command: command, derived: derived, last: last, observed: observed, target: target,
      service: observedService || (OBOL.context && OBOL.context.serviceOf ? OBOL.context.serviceOf(command) : ''),
      actionId: opts.actionId || (last && last.actionId) || '',
      locus: opts.executionLocus || (last && last.locus) || executionLocus(command, opts.commandObj, opts.locus),
      source: opts.forceTarget ? 'forced-target' : derived ? 'pasted-command' : explicit ? 'supplied-command' : last ? 'copied-command' : observedTarget || signature ? 'output' : 'selected-target',
      conflicts: scopeTarget && observedTarget && scopeTarget !== observedTarget && !opts.forceTarget ? ['observed-host-differs-from-selected-target'] : [] };
  }
  function resolveInputContext(binding, opts, eng, params) {
    if (opts.context && (!binding.target || opts.context.target === binding.target)
      && (!binding.observed || !binding.observed.principal || principalName(binding.observed.principal) === principalName(opts.context.principal))
      && (!binding.service || !opts.context.service || binding.service === opts.context.service)) return opts.context;
    if (!(OBOL.context && OBOL.context.resolve)) return { target: binding.target, targetDomain: params.domain || '', params: params, service: binding.service, locus: binding.locus };
    var options = { engagement: eng, target: binding.target, params: params, command: binding.command,
      actionId: binding.actionId, service: binding.service, locus: binding.locus };
    if (binding.last && binding.last.context) options.credentialId = binding.last.context.credentialId || null;
    var actual = credFromCommand(binding.command) || (binding.observed && binding.observed.credential), candidates = [];
    if (actual && OBOL.context.credentials && OBOL.context.material) {
      var actualMaterial = OBOL.context.material(actual);
      var observedRealm = binding.observed && binding.observed.principal.indexOf('\\') > 0 ? binding.observed.principal.split('\\')[0] : '';
      candidates = OBOL.context.credentials(eng).filter(function (c) {
        return principalName(c.user) === principalName(actualMaterial.user)
          && (!(actualMaterial.domain || observedRealm) || principalName(c.domain) === principalName(actualMaterial.domain || observedRealm))
          && (actualMaterial.nthash ? principalName(c.nthash) === principalName(actualMaterial.nthash) : c.password === actualMaterial.password);
      });
      options.credentialId = candidates.length === 1 ? candidates[0].id : null;
    } else if (binding.observed && binding.observed.principal) {
      var user = binding.observed.principal;
      candidates = OBOL.context.credentials(eng).filter(function (c) { return principalName(c.principal) === principalName(user); });
      // A username without a matching bound command cannot establish which secret version was used.
      if (!binding.last) options.credentialId = null;
    }
    var result = OBOL.context.resolve(options);
    result.selectionSource = binding.source;
    result.conflicts = (result.conflicts || []).concat(binding.conflicts || []);
    if (!result.credentialId && binding.observed && binding.observed.principal) {
      result.principal = binding.observed.principal;
      var split = result.principal.split('\\');
      if (split.length > 1) result.authRealm = split[0];
    }
    return result;
  }
  function observedTargets(text) {
    var found = [], re = /^(?:\s*(?:SMB|LDAP|WINRM|SSH|RDP|FTP|MSSQL|WMI)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+|Nmap scan report for (?:[^\n(]+\()?((?:\d{1,3}\.){3}\d{1,3})\)?\s*$)/gmi, m;
    while ((m = re.exec(String(text || '')))) { var ip = m[1] || m[2]; if (found.indexOf(ip) < 0) found.push(ip); }
    return found;
  }
  function preview(opts) {
    var eng = OBOL.store.active() || {}, binding = sourceBinding(opts, eng);
    var ctx = resolveInputContext(binding, opts || {}, eng, Object.assign({}, eng.params || {}, { target: binding.target }));
    var result = OBOL.context && OBOL.context.snapshot ? OBOL.context.snapshot(ctx) : { target: binding.target, service: binding.service, locus: binding.locus };
    result.source = binding.source; result.conflicts = (ctx.conflicts || []).slice();
    return result;
  }

  // The operator's own attacker IP, read from a terminal prompt like the Kali/HTB `[tun0:10.10.14.191]`
  // (also tap/vpn/wg/eth). This is YOUR listener/LHOST - obol fills {{lhost}} with it so coercion, relay
  // and reverse-shell commands form without hand-typing your VPN address on every box.
  var _LHOST_RE = /\[(?:tun|tap|vpn|wg|eth|wlan)\d*[:\/ ]\s*(\d{1,3}(?:\.\d{1,3}){3})\]/i;
  function detectLhost(text) {
    var m = _LHOST_RE.exec(String(text || ''));
    return m ? m[1] : '';
  }

  // Which HOST a command/output is about - so a whole-session import can route each command's facts to the
  // right target instead of dumping them all on the active one. The RHOST is almost always a positional
  // argument of the command (`nxc smb 10.0.0.5`, `bloodyAD --host 10.0.0.5`, `secretsdump ...@10.0.0.5`); we
  // fall back to the host the tool NAMES in its output (`Nmap scan report for X`, an `SMB X 445 ...` banner).
  // The operator's OWN machine is never a target: its LHOST (from the [tun0:...] stamp), any IP in a
  // listener/interface flag, loopback, and any address its interface dumps reveal (opts.self) are excluded.
  // Returns '' when nothing routable is found - the caller then leaves the command on the active target.
  var _IPV4_G = /(?<![\d.\/A-Za-z])(?:\d{1,3}\.){3}\d{1,3}(?![\d.\/])/g;
  var _LISTENER_FLAG = /^(?:-l|--lhost|-lh|lhost|--listener|--interface-ip|--local-ip|--lip|--lhost=.*)$/i;
  var _OUT_HOST_RE = [
    /Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})/i,   // nmap: "...report for host (10.0.0.5)"
    /^(?:SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+/im,  // nxc/cme banner
  ];
  function _isRoutableIp(ip) {
    var o = String(ip).split('.'); if (o.length !== 4) return false;
    for (var i = 0; i < 4; i++) { var n = +o[i]; if (!(o[i] !== '' && n >= 0 && n <= 255)) return false; }
    // reject loopback (127/8), link-local (169.254/16), 0/8, multicast/reserved (>=224), and network/broadcast (.0/.255)
    var o0 = +o[0], o1 = +o[1], o3 = +o[3];
    if (o0 === 0 || o0 === 127 || o0 >= 224 || (o0 === 169 && o1 === 254) || o3 === 0 || o3 === 255) return false;
    return true;
  }
  // Commands that dump the operator's OWN interfaces - their output is the Kali box's addresses, never a
  // target. Used to widen the self-IP exclusion so `nmap <my-own-ip>` etc. can't mint a Kali "target".
  var _IFACE_CMD = /^(?:sudo\s+)?(?:ip\s+(?:-\d\s+)?a(?:ddr)?\b|ifconfig\b|hostname\s+-I\b|ipconfig\b)/i;
  var _INET_RE = /\binet6?\s+(\d{1,3}(?:\.\d{1,3}){3})/gi;
  function selfIpsFromInterfaceDump(command, stdout) {
    if (!_IFACE_CMD.test(String(command || '').trim())) return [];
    var out = String(stdout || ''), ips = {}, m;
    _INET_RE.lastIndex = 0;
    while ((m = _INET_RE.exec(out))) { if (_isRoutableIp(m[1])) ips[m[1]] = 1; }
    // `hostname -I` prints a bare space-separated list of the box's addresses (no "inet" prefix)
    if (/hostname\s+-I\b/i.test(command)) (out.match(_IPV4_G) || []).forEach(function (ip) { if (_isRoutableIp(ip)) ips[ip] = 1; });
    return Object.keys(ips);
  }
  function detectTarget(command, stdout, opts) {
    opts = opts || {};
    var known = opts.known || [], excl = {};
    if (opts.lhost) excl[opts.lhost] = 1;
    (opts.self || []).forEach(function (ip) { if (ip) excl[ip] = 1; });   // the Kali box's own addresses
    var cmd = String(command || '');
    // exclude any IP that sits right after a listener/interface flag (coercer -l <ip>, msfvenom LHOST=...)
    var toks = cmd.split(/[\s=]+/);
    for (var i = 0; i < toks.length - 1; i++) { if (_LISTENER_FLAG.test(toks[i]) && _isRoutableIp(toks[i + 1] || '')) excl[toks[i + 1]] = 1; }
    var cip = (cmd.match(_IPV4_G) || []).filter(function (ip) { return _isRoutableIp(ip) && !excl[ip]; });
    // prefer a command IP that is already a known engagement target (strongest signal it's a real host)
    for (var k = 0; k < cip.length; k++) { if (known.indexOf(cip[k]) >= 0) return cip[k]; }
    if (cip.length) return cip[0];
    // no target in the command - trust only the host the tool explicitly names in its output
    var out = String(stdout || '');
    for (var r = 0; r < _OUT_HOST_RE.length; r++) { var m = _OUT_HOST_RE[r].exec(out); if (m && _isRoutableIp(m[1]) && !excl[m[1]]) return m[1]; }
    return '';
  }
  // Every address that belongs to the OPERATOR (never a target): the params LHOST, every [tun/tap/...:IP]
  // prompt stamp across the captures, and every interface-dump address. Gathered once before routing.
  function selfIps(texts, segs, paramLhost) {
    var self = {};
    if (paramLhost) self[paramLhost] = 1;
    (texts || []).forEach(function (t) {
      var s = String(t || ''), m; _LHOST_G.lastIndex = 0;
      while ((m = _LHOST_G.exec(s))) { if (m[1]) self[m[1]] = 1; }
    });
    (segs || []).forEach(function (s) { selfIpsFromInterfaceDump(s.command, s.stdout).forEach(function (ip) { self[ip] = 1; }); });
    return Object.keys(self);
  }
  var _LHOST_G = /\[(?:tun|tap|vpn|wg|eth|wlan)\d*[:\/ ]\s*(\d{1,3}(?:\.\d{1,3}){3})\]/gi;

  // Rewrite one IP to another throughout a capture - for a reverted lab whose target IP changed. The match
  // is bounded so 10.129.95.6 never rewrites inside 10.129.95.66, and only whole dotted-quads are touched.
  // pairs: [{from, to}]. Returns { text, count } so the UI can confirm how many occurrences were remapped.
  function remapIps(text, pairs) {
    var body = String(text || ''), total = 0;
    (pairs || []).forEach(function (p) {
      if (!p || !p.from || !p.to || p.from === p.to) return;
      if (!_isRoutableIp(p.from) && !/^(\d{1,3}\.){3}\d{1,3}$/.test(p.from)) return;
      var re = new RegExp('(?<![\\d.])' + p.from.replace(/\./g, '\\.') + '(?![\\d.])', 'g');
      body = body.replace(re, function () { total++; return p.to; });
    });
    return { text: body, count: total };
  }

  function ready() { return !!(OBOL.parsers && OBOL.parsers.parseActionOutput); }
  function classifyOutcome(input) {
    if (OBOL.outcomes && OBOL.outcomes.classify) return OBOL.outcomes.classify(input);
    return { version: 1, kind: 'unknown', status: 'unresolved', retryable: true, conclusive: false, retireCommand: false, retireMove: false,
      title: 'Output saved; outcome unresolved', summary: 'Outcome interpretation is unavailable. The evidence is retained and this attempt remains available.',
      detail: 'Reload the application to restore the outcome interpreter.', established: [], unresolved: ['Outcome interpretation unavailable.'], next: 'review', context: {} };
  }
  function renderOutcome(outcome) {
    if (OBOL.outcomes && OBOL.outcomes.render) return OBOL.outcomes.render(outcome);
    return '<div class="outcome-receipt" data-outcome="unknown" role="status">Output saved; outcome unresolved. The attempt remains available.</div>';
  }
  function outcomeMessage(result) {
    var outcome = result && (result.outcome || result);
    return OBOL.outcomes && OBOL.outcomes.describe ? OBOL.outcomes.describe(outcome) : 'Output saved; review the recorded observations and context.';
  }
  var _healedEngs = {};
  function _healLegacyActivities() {
    if (!ready() || !OBOL.store || !OBOL.store.active) return false;
    var eng = OBOL.store.active();
    if (!eng || !eng.id || _healedEngs[eng.id]) return false;
    _healedEngs[eng.id] = 1;
    var acts = eng.activities || [];
    var targetsToHeal = acts.filter(function (a) {
      return a && a.stdout && /\benum4linux(?:-ng)?\b/i.test(a.command || a.dispatch || '')
        && (!(a.produced || []).some(function (k) { return k === 'ad.user_list'; })
          || (a.produced || []).some(function (k) { return k === 'blocker.protected_users'; }));
    });
    if (!targetsToHeal.length) return false;
    var healingScopes = {};
    targetsToHeal.forEach(function (a) { healingScopes['host:' + (a.target || (eng.params && eng.params.target) || 'target')] = true; });
    OBOL.store.update(function (e) {
      e.facts = (e.facts || []).filter(function (f) {
        if (!f || !/^blocker\.(?:access_denied|logon_failure|protected_users)$/.test(f.kind)) return true;
        if (!healingScopes[f.scope]) return true;
        return !/\benum4linux(?:-ng)?\b/i.test(String(f.source || ''));
      });
    }, 'facts');
    var anyAdded = false;
    targetsToHeal.forEach(function (act) {
      var tIp = act.target || (eng.params && eng.params.target) || 'target';
      var dom = OBOL.store.targetIdentity ? OBOL.store.targetIdentity(tIp).domain : (eng.params && eng.params.domain) || '';
      var healStdout = String(act.stdout || '').replace(/[ \t]+$/gm, '');
      if (/\.\.\. \[truncated,/.test(healStdout) && /'501':[\s\S]{1,120}?username:\s*Guest/i.test(healStdout) && !/username:\s*krbtgt/i.test(healStdout)) {
        healStdout += "\n'502':\n  username: krbtgt\n'503':\n  username: DefaultAccount\n";
      }
      var res = OBOL.parsers.parseActionOutput({
        actionId: act.action_id || 'recon-smb-anon',
        command: act.dispatch || act.command || 'enum4linux-ng',
        stdout: healStdout,
        source: act.command || 'enum4linux-ng',
        scope: 'host:' + tIp,
        domain: dom
      });
      var facts = (res && res.facts) || [];
      var progressFacts = facts.filter(function (f) { return f && !/^(blocker\.|credential\.validation$)/.test(f.kind); });
      var blockers = facts.filter(function (f) { return /^blocker\./.test(f.kind); }).map(function (f) { return f.kind; });
      var added = progressFacts.length ? OBOL.store.addFacts(progressFacts, 'evidence') : 0;
      if (added > 0) anyAdded = true;
      OBOL.store.update(function (e) {
        var found = (e.activities || []).find(function (x) { return x && x.at === act.at && x.command === act.command; });
        if (found) {
          found.produced = facts.map(function (f) { return f.kind; });
          found.addedCount = (found.addedCount || 0) + added;
          found.blockers = blockers;
        }
        if (e.checklist && e.checklist[OBOL.store.checklistKey('recon-smb-anon', tIp)] && String(e.checklist[OBOL.store.checklistKey('recon-smb-anon', tIp)]).indexOf('empty:') === 0 && progressFacts.some(function (f) { return f.kind === 'ad.user_list'; })) {
          delete e.checklist[OBOL.store.checklistKey('recon-smb-anon', tIp)];
        }
      }, 'evidence');
    });
    return anyAdded || targetsToHeal.length > 0;
  }
  // Resolve to true once the (lazily-loaded) parser group is available.
  function ensureParsers() {
    if (ready()) { _healLegacyActivities(); return Promise.resolve(true); }
    if (OBOL.lazy && OBOL.lazy.loadGroup) return OBOL.lazy.loadGroup('parsers').then(function () {
      var ok = ready();
      if (ok) _healLegacyActivities();
      return ok;
    }).catch(function () { return false; });
    return Promise.resolve(false);
  }

  // Intercept an OBOL-ARSENAL v1 machine-inventory block pasted into global QuickPaste or Evidence
  // so the operator does not have to be on the #/loadout route for paste-back to work.
  function _tryArsenalIngest(text) {
    var s = String(text || '');
    var idx = s.indexOf('OBOL-ARSENAL');
    if (idx < 0) return null;
    if (OBOL.arsenal && typeof OBOL.arsenal.ingestInventory === 'function') {
      var res = OBOL.arsenal.ingestInventory(s);
      return res && res.ok ? res : null;
    }
    var scan = s.slice(idx);
    var start = scan.indexOf('{');
    if (start < 0) return null;
    var depth = 0, inStr = false, esc = false, end = -1;
    for (var p = start; p < scan.length; p++) {
      var c = scan[p];
      if (inStr) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') inStr = false; continue; }
      if (c === '"') inStr = true;
      else if (c === '{') depth++;
      else if (c === '}') { depth--; if (depth === 0) { end = p + 1; break; } }
    }
    if (end < 0) return null;
    var obj;
    try { obj = JSON.parse(scan.slice(start, end)); } catch (e) { return null; }
    if (!obj || typeof obj !== 'object' || !obj.tools) return null;
    obj.savedAt = Date.now();
    try { localStorage.setItem('obol.arsenal-profile', JSON.stringify(obj)); } catch (e) {}
    if (OBOL.store && typeof OBOL.store.update === 'function') {
      try {
        OBOL.store.update(function (eng) {
          if (!eng) return;
          eng.params = eng.params || {};
          if (obj.lhost && !eng.params.lhost) {
            eng.params.lhost = obj.lhost;
            eng.params.lhost_iface = obj.lhost_iface || 'tun0';
          }
          if (obj.tooldir && !eng.params.toolsDir) {
            eng.params.toolsDir = obj.tooldir;
          }
        }, 'arsenal-sync');
      } catch (e) {}
    }
    try { if (OBOL.ctxbar && typeof OBOL.ctxbar.render === 'function') OBOL.ctxbar.render(); } catch (e) {}
    try { if (OBOL.app && typeof OBOL.app.renderSidebar === 'function') OBOL.app.renderSidebar(); } catch (e) {}
    var present = 0;
    Object.keys(obj.tools || {}).forEach(function (k) { if (obj.tools[k] && obj.tools[k].present) present++; });
    return { ok: true, present: present, staged: (obj.staged || []).length, wordlists: Object.keys(obj.wordlists || {}).length, lhost: obj.lhost || '', lhost_iface: obj.lhost_iface || '' };
  }

  function _tryWorkspaceSnapshot(text) {
    var s = String(text || '');
    if (!(OBOL.vfs && typeof OBOL.vfs.parseSnapshot === 'function' && typeof OBOL.vfs.reconcile === 'function')) return null;
    var hasMarker = /OBOL-WS-SNAPSHOT/i.test(s);
    var hasTabManifest = /^(?!\s*#)[A-Za-z0-9._\/-]+\t\d+\t\d{4}-\d{2}-\d{2}/m.test(s);
    if (!hasMarker && !hasTabManifest) return null;
    var snapText = s;
    if (hasMarker) {
      var m = /(?:#{2,}\s*)?OBOL-WS-SNAPSHOT[^\r\n]*\r?\n([\s\S]*?)(?:###\s*END\b|$)/i.exec(s);
      if (m) snapText = m[1];
    }
    var entries = OBOL.vfs.parseSnapshot(snapText);
    if (!entries || !entries.length) return null;
    var eng = (OBOL.store && typeof OBOL.store.active === 'function') ? OBOL.store.active() : {};
    var r = OBOL.vfs.reconcile(eng || {}, entries);
    if (OBOL.store && typeof OBOL.store.update === 'function') {
      try {
        OBOL.store.update(function (e) {
          if (!e) return;
          e.workspace = e.workspace || {};
          e.workspace.overrides = r.overrides;
        }, 'ws-sync');
      } catch (e) {}
    }
    try { if (OBOL.app && typeof OBOL.app.renderSidebar === 'function') OBOL.app.renderSidebar(); } catch (e) {}
    return { ok: true, confirmed: r.confirmed || 0, adopted: r.adopted || 0, missing: r.missing || 0, total: r.total || entries.length };
  }

  function _stripArsenalBlock(text) {
    return String(text || '')
      .replace(/OBOL-ARSENAL(?:\s+v\d+)?\r?\n\{[^\r\n]*\}\r?\n?/g, '')
      .replace(/──\s*Copy these two lines[\s\S]*$/g, '');
  }

  function _stripWorkspaceSnapshot(text) {
    return String(text || '')
      .replace(/^[^\r\n]*echo\s+['"]###\s*OBOL-WS-SNAPSHOT['"][^\r\n]*\r?\n?/gim, '')
      .replace(/(?:#{2,}\s*)?OBOL-WS-SNAPSHOT[^\r\n]*\r?\n[\s\S]*?(?:###\s*END[^\r\n]*\r?\n?|$)/gi, '');
  }

  function _hasNonSetupCommands(text) {
    var s = String(text || '').trim();
    if (!s) return false;
    if (/={3,}\s*OBOL STEP\s+\d+:/i.test(s)) return true;
    var segs = splitSession(s);
    var realSegs = segs.filter(function (seg) {
      return seg && seg.command && !/download-loadout\.sh|setup-kali\.sh|OBOL-WS-SNAPSHOT|OBOL-ARSENAL/i.test(seg.command);
    });
    if (realSegs.length > 0) return true;
    if (segs.length > 0) return false;
    if (/OBOL Loadout|Tools ready:|Wordlists mapped:|~/.test(s) && !recognizesTool('', s)) return false;
    return recognizesTool('', s);
  }

  function _tryPureTargetsImport(text) {
    if (!(OBOL.targets && typeof OBOL.targets.importBulk === 'function')) return null;
    var lines = String(text || '').split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) { return l && !/^#/.test(l); });
    if (!lines.length || lines.length > 500) return null;
    var ipOrHostsRe = /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2}|\s+[a-zA-Z0-9][a-zA-Z0-9._-]+(?:\s+[a-zA-Z0-9][a-zA-Z0-9._-]+)*)?$/;
    if (!lines.every(function (l) { return ipOrHostsRe.test(l); })) return null;
    var syncRes = null;
    try {
      OBOL.targets.importBulk(text, function (res) { syncRes = res; });
    } catch (e) { return null; }
    return (syncRes && syncRes.ok && (syncRes.added || syncRes.updated || syncRes.cidrs)) ? syncRes : null;
  }

  // Parse + mint + record. No DOM, no toast - the caller renders the outcome.
  //   opts = { text, command?, source?, fileName?, actionId? }
  // returns { ok, added, facts, cmd, lines, fileName } or { ok:false, reason:'empty'|'parsers'|'error', error? }
  function run(opts) {
    opts = opts || {};
    var text = opts.text || '';
    if (!text.trim()) return { ok: false, reason: 'empty' };
    var ar = null, ws = null;
    if (!opts.fromSession) {
      ar = _tryArsenalIngest(text);
      if (ar && ar.ok) text = _stripArsenalBlock(text);
      ws = _tryWorkspaceSnapshot(text);
      if (ws && ws.ok) text = _stripWorkspaceSnapshot(text);
      if (((ar && ar.ok) || (ws && ws.ok)) && !_hasNonSetupCommands(text)) {
        return { ok: true, arsenal: ar, workspaceSync: ws, added: 0, facts: [], imported: 1, commands: 1,
          cmd: ar ? 'obol-arsenal' : 'obol-workspace', lines: String(opts.text || '').split(/\r?\n/).length,
          fileName: opts.fileName || '', parseError: '', recognizedTool: true, looksError: false, epoch: 'anon', blockers: [] };
      }
      var hasCruiseSteps = /={3,}\s*OBOL STEP\s+\d+:/i.test(text);
      var rawOptCheck = (opts.command && opts.command.trim()) || '';
      if (hasCruiseSteps || (!rawOptCheck && !opts.actionId && splitSession(text).length > 1)) {
        if (!ready()) return { ok: false, reason: 'parsers' };
        var fixedTarget = (opts.scope && opts.scope.indexOf('host:') === 0) ? opts.scope.slice(5) : 'auto';
        var sRes = importSession(text, { target: opts.forceTarget ? fixedTarget : 'auto', fileName: opts.fileName || '', source: opts.source || 'paste' });
        if (sRes && sRes.ok) {
          if (ar && ar.ok) sRes.arsenal = ar;
          if (ws && ws.ok) sRes.workspaceSync = ws;
          return sRes;
        }
      }
    }
    if (!ready()) return { ok: false, reason: 'parsers' };
    // Route on what the paste ACTUALLY shows (its prompt/command line) over the move's canned
    // command, so pasting any tool's output into any move's box still reaches the right parser and
    // mints its facts - the coach is proof-gated, so out-of-order evidence just unlocks the right
    // moves. Fall back to the caller's command only when the paste carries no command line of its own
    // (e.g. raw redirected output); nmap XML still self-identifies from its <nmaprun args>.
    var eng = OBOL.store.active();
    var params = (eng && eng.params) || {};
    var rawOptCmd = (opts.command && opts.command.trim()) || '';
    var trimmedText = _trimPriorScrollback(text, rawOptCmd, (eng && eng.activities) || []).replace(/[ \t]+$/gm, '');
    var binding = sourceBinding(Object.assign({}, opts, { text: trimmedText }), eng);
    var inferredCmd = binding.derived, cmd = binding.command, lastCopiedFallback = binding.last;
    // Widen the DISPATCH label with whatever the paste reveals about its tool, so output-only pastes and
    // out-of-order evidence still reach the right parser. Lineage/tool below stay the honest `cmd`.
    var dispatchCmd = dispatchLabel(cmd, trimmedText);
    var firstTok = rawOptCmd.split(/\s+/)[0] || '';
    var originalAction = opts.actionId || '';
    if (inferredCmd && rawOptCmd && (extractTool(inferredCmd) !== extractTool(rawOptCmd)
      || (OBOL.context && OBOL.context.serviceOf && OBOL.context.serviceOf(inferredCmd) !== OBOL.context.serviceOf(rawOptCmd)))) originalAction = '';
    var inferredActId = originalAction || (/^[a-z0-9]+(?:-[a-z0-9]+)+$/i.test(firstTok) ? firstTok : '') || (lastCopiedFallback ? lastCopiedFallback.actionId : '');
    if (!inferredActId && cmd) {
      if (/\bbloodyAD\b/i.test(cmd)) inferredActId = 'bloodyad-acl';
      else if (/\bdacledit(?:\.py)?\b|\bowneredit(?:\.py)?\b/i.test(cmd)) inferredActId = 'ad-acl-abuse';
      else if (/\b(?:impacket-)?secretsdump(?:\.py)?\b/i.test(cmd) && /-just-dc/i.test(cmd)) inferredActId = 'dcsync';
      else if (/\bbloodhound-python\b|--bloodhound\b/i.test(cmd)) inferredActId = 'bloodhound-collect';
      else if (/\b(?:impacket-)?GetNPUsers(?:\.py)?\b|--asreproast\b/i.test(cmd)) inferredActId = 'asrep-roast';
      else if (/\b(?:impacket-)?GetUserSPNs(?:\.py)?\b|--kerberoasting\b/i.test(cmd)) inferredActId = 'kerberoast';
    }
    var parseText = trimmedText;
    if (/\bxp_cmdshell\b/i.test(cmd) && !/\bxp_cmdshell\b/i.test(trimmedText)) {
      parseText = cmd + '\n' + trimmedText;
    }
    // Learn the operator's LHOST from the paste's own prompt (`[tun0:10.10.14.191]`) when not already set,
    // so {{lhost}} stops reading "needs: lhost" the moment a real terminal capture goes through.
    if (!params.lhost) {
      var lh = detectLhost(text);
      if (lh) { OBOL.store.update(function (e) { e.params = e.params || {}; e.params.lhost = lh; }, 'params'); params = (OBOL.store.active() || {}).params || params; }
    }
    // Scope the facts to a specific host. A whole-session import passes the per-command host it auto-routed
    // to (opts.scope); a normal paste checks whether the command/output explicitly names a known configured
    // target, falling back to the engagement's active target.
    var knownIps = ((eng && eng.targets) || []).map(function (t) { return t && (t.ip || t.id); }).filter(Boolean);
    var routedIp = binding.target || params.target || 'target';
    var scope = opts.scope && !/^host:/.test(opts.scope) ? opts.scope : ('host:' + routedIp);
    var scopeIp = scope.indexOf('host:') === 0 ? scope.slice(5) : (params.target || '');
    params = Object.assign({}, params, { target: scopeIp || params.target });
    if (OBOL.store.targetIdentity && knownIps.length > 1) params.domain = OBOL.store.targetIdentity(scopeIp).domain || '';
    binding.target = scopeIp; binding.actionId = inferredActId;
    var resolvedContext = resolveInputContext(binding, opts, eng, params);
    var routing = { mode: opts.forceTarget ? 'forced' : 'observed', target: scopeIp, sourceTargets: observedTargets(trimmedText) };
    if (opts.forceTarget) resolvedContext = Object.assign({}, resolvedContext, { forceTarget: scopeIp });
    if (resolvedContext.params) params = resolvedContext.params;
    var contextSnapshot = OBOL.context && OBOL.context.snapshot ? OBOL.context.snapshot(resolvedContext)
      : OBOL.outcomes && OBOL.outcomes.snapshot ? OBOL.outcomes.snapshot(resolvedContext) : { target: scopeIp };
    contextSnapshot.routing = routing;
    var res, parseError = '';
    try {
      res = OBOL.parsers.parseActionOutput({ actionId: inferredActId, command: dispatchCmd, stdout: parseText, source: opts.fileName || cmd || 'paste', scope: scope, domain: resolvedContext.targetDomain || '', context: resolvedContext, observedAt: typeof opts.at === 'number' ? opts.at / 1000 : undefined });
    } catch (e) { res = { facts: [] }; parseError = (e && e.message) || 'parse failed'; }
    if (res && res.error) parseError = res.error; // a sub-parser threw but earlier facts survived
    var facts = (res && res.facts) || [];
    var existingFs = OBOL.store.factSetForTarget ? OBOL.store.factSetForTarget(scopeIp) : OBOL.store.factSet();
    var epoch = (OBOL.pack && OBOL.pack.accessEpoch) ? OBOL.pack.accessEpoch(existingFs || (OBOL.store && OBOL.store.factSet && OBOL.store.factSet())) : 'anon';
    var blockers = facts.filter(function (f) { return /^(?:blocker\.|ssh\.key_rejected$)/.test(f.kind); }).map(function (f) { return f.kind; });
    var progressFacts = facts.filter(function (f) { return f && !/^(?:blocker\.|ssh\.key_rejected$|credential\.(?:validation|authorization)$)/.test(f.kind); });
    var metaFacts = facts.filter(function (f) { return f && /^(?:blocker\.|ssh\.key_rejected$|credential\.(?:validation|authorization)$)/.test(f.kind); });
    var outcome = classifyOutcome({ text: trimmedText, command: cmd || dispatchCmd, actionId: inferredActId,
      facts: facts, previousFacts: existingFs, parseError: parseError, diagnostics: (res && res.diagnostics) || [], context: resolvedContext });
    outcome.routing = routing;
    var added = OBOL.store.addFacts(progressFacts, 'evidence');
    if (metaFacts.length) OBOL.store.addFacts(metaFacts, 'evidence');
    if (!blockers.length && OBOL.store && typeof OBOL.store.retractFactKind === 'function') {
      function proven(pattern) {
        return facts.some(function (f) { return f.state === 'supported' && f.scope === scope && pattern.test(f.kind); });
      }
      var observationAt = typeof opts.at === 'number' ? opts.at / 1000 : Date.now() / 1000;
      function clear(kind, matches, domainRepair) {
        var fsClear = OBOL.store.factSet(), before = fsClear.facts.length;
        fsClear.facts = fsClear.facts.filter(function (f) {
          if (f.kind !== kind || (f.created_at && f.created_at > observationAt)) return true;
          var sameScope = f.scope === scope;
          if (domainRepair && /^domain:/.test(f.scope || '')) {
            var realm = String(resolvedContext.authRealm || resolvedContext.targetDomain || '').toLowerCase().replace(/\.$/, '');
            sameScope = !!realm && f.scope.slice(7).toLowerCase().replace(/\.$/, '') === realm;
          }
          return !sameScope || (matches && !matches(f));
        });
        if (fsClear.facts.length !== before) OBOL.store.setFacts(fsClear, 'retract');
      }
      var authProof = facts.filter(function (f) { return f.state === 'supported' && f.scope === scope && /^(credential\.validated|(?:smb|ldap|winrm|rdp|ssh)\.authenticated)$/.test(f.kind); });
      function sameAuthentication(f) {
        var v = f.value || {};
        return authProof.some(function (p) {
          var pv = p.value || {}, service = pv.service || (/\.authenticated$/.test(p.kind) ? p.kind.split('.')[0] : '');
          if (!service || !v.service || service !== v.service) return false;
          if (v.credentialId && pv.credentialId) return v.credentialId === pv.credentialId;
          if (v.credentialFingerprint && pv.credentialFingerprint) return v.credentialFingerprint === pv.credentialFingerprint;
          return false; // Ambiguous legacy observations are not cleared by another identity's success.
        });
      }
      var kerberosSuccess = facts.some(function (f) {
        return f.state === 'supported' && /^(kerberos\.tickets|hash\.(asrep|tgs))$/.test(f.kind);
      });
      if (kerberosSuccess || (/\b(?:ntpdate|ntpsec-ntpdate|rdate)\b/i.test(cmd) && /(?:step|adjust) time|offset\s+[-+]?\d|time server/i.test(trimmedText))) clear('blocker.clock_skew', null, true);
      if (proven(/^(credential\.validated|(?:smb|ldap|winrm|rdp|ssh)\.authenticated)$/)) {
        clear('blocker.logon_failure', sameAuthentication); clear('blocker.password_change', sameAuthentication);
      }
      if (proven(/^winrm\.authenticated$/)) clear('blocker.winrm_closed');
      if (/xp_cmdshell/i.test(cmd) && proven(/^(access\.system|foothold\.windows)$/)) clear('blocker.xp_cmdshell_disabled');
      if (facts.some(function (f) { return f.state === 'supported' && f.kind === 'credential.available' && /^(john|hashcat)/.test((f.value || {}).method || ''); })) {
        var sameOperation = function (f) { return !!cmd && f.source === cmd; };
        clear('blocker.hash_format', sameOperation); clear('blocker.hashcat_env', sameOperation); clear('blocker.cracking_exhausted', sameOperation);
      }
    }

    var CAP = 48000;
    var lines = trimmedText.split(/\r?\n/).length;
    var stored = trimmedText.length > CAP
      ? (trimmedText.slice(0, CAP) + '\n... [truncated, ' + (trimmedText.length - CAP) + ' more chars, ' + lines + ' lines total]')
      : trimmedText;
    OBOL.store.update(function (e) {
      e.activities = e.activities || [];
      // `command` stays the honest lineage (may be empty for an attached file); `dispatch` is the widened
      // routing label obol recovered from the content - the coach's "already run" check reads it so an
      // ATTACHED dump (no typed command) still marks the command that produced it ran.
      e.activities.unshift({ at: opts.at || Date.now(), command: cmd, dispatch: (dispatchCmd !== cmd ? dispatchCmd : ''),
        source: opts.source || 'paste', tool: (extractTool(cmd) || 'paste'),
        target: scopeIp || params.target || '', scope: scope, file: opts.fileName || '', action_id: inferredActId || '',
        produced: facts.map(function (f) { return f.kind; }), addedCount: added, epoch: epoch, blockers: blockers,
        parseError: parseError, parseDiagnostics: (res && res.diagnostics) || [], outcome: outcome, context: contextSnapshot, routing: routing,
        stdout: stored, sample: trimmedText.slice(0, 400) });
    }, 'activity');
    var recognized = recognizesTool(cmd, trimmedText);
    var looksErr = looksLikeError(trimmedText);
    // The outcome belongs to this attempt. Never exhaust an entire move because a paste added
    // no facts, looked clean, or happened to have two lines. Command suppression consults the
    // conclusive outcome and the exact resolved context instead.
    if (!opts.fromSession && added === 0 && !facts.length && !recognized && !looksErr && !rawOptCmd && !opts.actionId) {
      var tImp = _tryPureTargetsImport(trimmedText);
      if (tImp && tImp.ok) {
        if (!opts.quiet && OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
        return { ok: true, arsenal: ar || null, workspaceSync: ws || null, targetsImported: tImp, added: tImp.added || 0,
          facts: [], imported: 1, commands: 1, cmd: 'targets-import', lines: lines, fileName: opts.fileName || '',
          parseError: '', recognizedTool: true, looksError: false, epoch: epoch, blockers: [] };
      }
    }
    // `quiet` - a batch session import re-renders ONCE at the end instead of per command.
    if (!opts.quiet && OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    // Signals for the caller's "this move ran but proved nothing" decision: did a tool obol knows about
    // actually run (recognized), and did it fail rather than simply come up empty (looksError)?
    return { ok: true, arsenal: ar || null, workspaceSync: ws || null, added: added, facts: facts, imported: 1, commands: 1,
      cmd: cmd, lines: lines, fileName: opts.fileName || '',
      parseError: parseError, diagnostics: (res && res.diagnostics) || [], recognizedTool: recognized, looksError: looksErr,
      epoch: epoch, blockers: blockers, outcome: outcome, context: contextSnapshot };
  }

  // -- Whole-session import ------------------------------------------------------------------------
  // Split a full terminal capture (many commands + their output) into per-command segments, so obol can
  // catch up on an entire box at once - the "get me un-stuck" path. A segment begins at a prompt/command
  // line and runs until the next one; the timestamp on a Kali prompt (`[2026-09-27 17:17:38 UTC]`) is
  // captured so multiple tabs/files can be stitched into one chronological history.
  var _BARE_PROMPT = /^\s*([#$])\s+(\S.*)$/;                            // bare "$ cmd" / "# cmd" (last resort)
  var _PROSE_COMMENT_HEAD = /^(?:get|select|show|use|describe|tables|host|net|id|dir|for|run|edit|see)$/i;
  // A Cruise batch script fences each command's output with an echo marker ("===== OBOL STEP n: <id> =====").
  // The script runs non-interactively (no shell prompt to split on), so the marker IS the segment boundary:
  // it starts a new segment whose command is the move id, so each move's output parses in isolation (correct
  // per-move facts, no cross-command misattribution) with no dependence on the Loadout prompt stamp.
  var _CRUISE_MARK = /^\s*(?:(?:SMB|WINRM|SSH|LDAP|WMI|MSSQL|RDP|FTP)\s+\S+\s+\d+\s+\S+\s+)?={3,}\s*OBOL STEP\s+\d+:\s*(\S.*?)\s*={3,}\s*$/;
  var _NXC_BANNER_HEAD = /^\s*(?:SMB|WINRM|SSH|LDAP|WMI|MSSQL|RDP|FTP)\s+\S+\s+\d+\s+\S+\s+\[[*+]\]/;
  var _TS_RE = /\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/;          // a prompt timestamp -> epoch ms
  function _ts(line) {
    var m = _TS_RE.exec(line || ''); if (!m) return null;
    var t = Date.parse(m[1] + 'T' + m[2] + 'Z'); return isNaN(t) ? null : t;
  }
  // Segment one capture into [{command, stdout, ts}], newest-of-the-block timestamp carried from its prompt
  // (or the line just above it, where the Kali prompt prints the time). Heredocs (cat > f <<'EOF' ... EOF)
  // are swallowed into their command's block so their body is not mistaken for more commands.
  function splitSession(text) {
    var lines = String(text || '').split(/\r?\n/), segs = [], cur = null, prev = '', prev2 = '', heredoc = null, preBanners = [];
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var clean = _stripAnsi(raw);
      if (heredoc !== null) { if (cur) cur.stdout.push(raw); if (clean.trim() === heredoc) heredoc = null; prev2 = prev; prev = clean; continue; }
      // Cruise step marker: a hard segment boundary. The marker line itself is not output.
      var mk = _CRUISE_MARK.exec(clean);
      if (mk) {
        if (cur) segs.push(cur);
        cur = { command: mk[1].trim(), stdout: (!cur && preBanners.length) ? preBanners.slice() : [], ts: _ts(clean) };
        preBanners = [];
        prev2 = prev; prev = clean; continue;
      }
      if (!cur && _NXC_BANNER_HEAD.test(clean)) preBanners.push(raw);
      var cmd = _promptCmd(clean);
      // A bare "$ cmd" / "# cmd" is a weak signal - tool output is full of lines that start with "# "
      // (config/comment dumps, "# Nmap 7.94 scan initiated...") or "$ " - so accept one only when what
      // follows leads with a lowercase CLI tool obol knows (and is not a prose/comment word after '#').
      if (cmd == null) {
        var bm = _BARE_PROMPT.exec(clean);
        if (bm) {
          var sigil = bm[1], body = bm[2].trim();
          var rawFirstWord = body.split(/\s+/)[0] || '';
          var ft = firstToolToken(body);
          var isCommentProse = sigil === '#' && (/^[A-Z]/.test(rawFirstWord) || _PROSE_COMMENT_HEAD.test(rawFirstWord));
          if (!isCommentProse && TOOL_HINTS[ft]) cmd = body;
        }
      }
      if (cmd != null) {
        if (cur) segs.push(cur);
        // the stamp may be inline on the prompt (Kali), or on a stamp line 1-2 rows above (obol's precmd tweak)
        cur = { command: cmd, stdout: [], ts: _ts(clean) || _ts(prev) || _ts(prev2) };
        var hd = /<<-?\s*['"]?([A-Za-z_][\w]*)['"]?/.exec(cmd); if (hd) heredoc = hd[1];
      } else if (cur) { cur.stdout.push(raw); }
      prev2 = prev; prev = clean;
    }
    if (cur) segs.push(cur);
    return segs.map(function (s) { return { command: s.command, stdout: s.stdout.join('\n').replace(/^\n+|\n+$/g, ''), ts: s.ts }; });
  }

  // The credential a command authenticated WITH, its -u / -H / -p (and -d). Used to activate the identity
  // you actually escalated with, rather than hardcoding "Administrator" or guessing at the first credential.
  function credFromCommand(cmd) {
    cmd = String(cmd || '');
    var u = /(?:^|\s)-u\s+'([^']*)'|(?:^|\s)-u\s+"([^"]*)"|(?:^|\s)-u\s+(\S+)/.exec(cmd);
    var user = u ? (u[1] !== undefined ? u[1] : (u[2] !== undefined ? u[2] : u[3])) : '';
    if (!user || user === "''" || user === '""') return null;   // an empty (null-session) user is not a credential
    var h = /(?:^|\s)-H\s+'?"?([0-9a-fA-F]{32}(?::[0-9a-fA-F]{32})?)/.exec(cmd);
    var p = /(?:^|\s)-p\s+'([^']*)'|(?:^|\s)-p\s+"([^"]*)"|(?:^|\s)-p\s+(\S+)/.exec(cmd);
    var d = /(?:^|\s)-d\s+'([^']*)'|(?:^|\s)-d\s+"([^"]*)"|(?:^|\s)-d\s+(\S+)/.exec(cmd);
    var out = { user: user };
    if (h) { var hh = h[1]; out.nthash = hh.indexOf(':') >= 0 ? hh.split(':').pop() : hh; }
    else if (p) { var pw = p[1] !== undefined ? p[1] : (p[2] !== undefined ? p[2] : p[3]); if (pw === '' ) return null; out.password = pw; }
    else return null;                                            // -u with no secret is not usable
    if (d) { var dm = d[1] !== undefined ? d[1] : (d[2] !== undefined ? d[2] : d[3]); if (dm) out.domain = dm; }
    return out;
  }
  // The strongest access an activity's command proved (most-recent first), and its credential - so import
  // can make the escalated identity active. Tiers: admin/foothold > authenticated session.
  function escalationCred(activities) {
    var tiers = [['access.admin', 'access.system', 'foothold.windows', 'foothold.linux', 'winrm.authenticated', 'rdp.authenticated'],
      ['smb.authenticated', 'ldap.authenticated']];
    for (var t = 0; t < tiers.length; t++) {
      for (var i = 0; i < (activities || []).length; i++) {
        var a = activities[i];
        if (!a || !a.produced || !a.produced.some(function (k) { return tiers[t].indexOf(k) >= 0; })) continue;
        var c = credFromCommand(a.command);
        if (c) return c;
      }
    }
    return null;
  }

  // Known engagement target IPs (to bias auto-routing toward real hosts).
  function _knownTargets(eng) {
    return ((eng && eng.targets) || []).map(function (t) { return t && t.ip; }).filter(Boolean);
  }
  // Make sure a routed-to host has a target record + a target.configured fact, so its facts show up on a
  // target card / the scoreboard instead of landing on a host the operator never added. Only called for a
  // host obol positively routed evidence to during import.
  function _ensureTarget(ip) {
    if (!ip) return;
    var eng = OBOL.store.active();
    if (((eng && eng.targets) || []).some(function (t) { return t && t.ip === ip; })) return;
    OBOL.store.update(function (e) {
      e.targets = e.targets || [];
      if (!e.targets.some(function (t) { return t && t.ip === ip; })) e.targets.push({ id: 't-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5), ip: ip, hostname: '', os: '', source: 'import' });
      if (!e.params) e.params = {};
      if (!e.params.target) e.params.target = ip;
    }, 'targets');
    if (OBOL.facts && OBOL.store.addFacts) OBOL.store.addFacts([OBOL.facts.makeFact({ kind: 'target.configured', scope: 'host:' + ip, source: 'import' })], 'facts');
  }

  // After an import, fold a target that was added by HOSTNAME only (no IP) into the IP record for the same
  // box, once a proven host.hostname fact ties the name to an IP. Prevents "DC01" (typed up front) and the
  // auto-created "10.0.0.5" from lingering as two cards for one host. Only merges on a proven name↔IP match;
  // distinct hosts are never combined. Returns the number of duplicate cards removed.
  function reconcileTargets() {
    var eng = OBOL.store.active();
    if (!eng || !(eng.targets || []).length) return 0;
    var SUP = OBOL.facts.ProofState.SUPPORTED, nameToIp = {};
    (eng.facts || []).map(OBOL.facts.factFromJson).forEach(function (f) {
      if (!f || f.state !== SUP) return;
      if ((f.kind === 'host.hostname' || f.kind === 'host.fqdn') && String(f.scope).indexOf('host:') === 0) {
        var ip = f.scope.slice(5), v = f.value || {}, name = String(v.name || v.hostname || v.fqdn || '').split('.')[0].toLowerCase();
        if (name && _isRoutableIp(ip)) nameToIp[name] = ip;
      }
    });
    var removed = 0;
    OBOL.store.update(function (e) {
      var ts = e.targets || [];
      // 1) backfill an IP onto a hostname-only card when the name resolves to one
      ts.forEach(function (t) { if (t && !t.ip && t.hostname && nameToIp[String(t.hostname).toLowerCase()]) t.ip = nameToIp[String(t.hostname).toLowerCase()]; });
      // 2) collapse duplicates that now share an IP - keep the first, fill its blanks from the rest
      var byIp = {}, keep = [];
      ts.forEach(function (t) {
        if (!t) return;
        if (!t.ip) { keep.push(t); return; }               // still no IP -> leave as its own card
        var prim = byIp[t.ip];
        if (!prim) { byIp[t.ip] = t; keep.push(t); return; }
        prim.hostname = prim.hostname || t.hostname || '';
        prim.os = prim.os || t.os || '';
        removed++;                                           // drop the duplicate
      });
      e.targets = keep;
    }, 'targets');
    return removed;
  }

  // Import one or more captures. Segments are stitched chronologically by prompt timestamp (null carries the
  // previous one so a tab's order is kept), de-duplicated (the same command+output pasted twice is ignored),
  // and each is run through the normal ingest pipeline. Returns a summary for the UI.
  //   opts = { fileName?, target?, remap? }  target: 'auto' (default) routes each command to the host it
  //   names, and registers any new host it lands facts on; a specific IP forces every command onto that
  //   host. remap: [{from,to}] rewrites an old IP to the current one first (a reverted lab's target changed).
  function importSession(inputs, opts) {
    opts = opts || {};
    var texts = Array.isArray(inputs) ? inputs.slice() : [inputs];
    var arsenalHit = null, wsHit = null;
    for (var ai = 0; ai < texts.length; ai++) {
      var ar = _tryArsenalIngest(texts[ai]);
      if (ar && ar.ok) {
        arsenalHit = ar;
        texts[ai] = _stripArsenalBlock(texts[ai]);
      }
      var ws = _tryWorkspaceSnapshot(texts[ai]);
      if (ws && ws.ok) {
        wsHit = ws;
        texts[ai] = _stripWorkspaceSnapshot(texts[ai]);
      }
    }
    if ((arsenalHit && arsenalHit.ok) || (wsHit && wsHit.ok)) {
      var hasRemainingCmds = texts.some(function (t) { return _hasNonSetupCommands(t); });
      if (!hasRemainingCmds) {
        var setupTools = [];
        if (arsenalHit && arsenalHit.ok) setupTools.push('obol-arsenal');
        if (wsHit && wsHit.ok) setupTools.push('obol-workspace');
        return { ok: true, arsenal: arsenalHit, workspaceSync: wsHit, commands: 1, imported: 1, dupes: 0, added: 0,
          facts: [], blockers: [], recognizedTool: true, looksError: false, epoch: 'anon', lines: 1, fileName: opts.fileName || '', parseError: '',
          tools: setupTools, hosts: [], merged: 0, remapped: 0 };
      }
    }
    if (!ready()) return { ok: false, reason: 'parsers' };
    // Reverted-box remap: rewrite the old target IP to the new one across every capture BEFORE anything else,
    // so routing, facts and the recorded evidence all land on the host the operator is actually on now.
    var remapped = 0;
    if (opts.remap && opts.remap.length) {
      texts = texts.map(function (t) { var r = remapIps(t, opts.remap); remapped += r.count; return r.text; });
    }
    var eng = OBOL.store.active();
    var params = (eng && eng.params) || {};
    var routeMode = opts.target || 'auto';
    var fixed = (routeMode !== 'auto' && routeMode) ? String(routeMode) : '';
    // Learn the operator's LHOST up front (from any capture's [tun0:...] stamp) so it is excluded from
    // target auto-routing even on the very first command - before run() gets a chance to persist it.
    var lhost = params.lhost || '';
    if (!lhost) { for (var ti = 0; ti < texts.length && !lhost; ti++) lhost = detectLhost(texts[ti]); }
    var known = _knownTargets(eng);
    var all = [];
    texts.forEach(function (t, fi) {
      var segs = splitSession(t), carry = null;
      // No prompt recognized (an unusual or stripped shell, or output pasted without its prompt line): do
      // not silently import nothing. Parse the whole blob as one capture, exactly as a raw paste would, so
      // the flag read, the service banner, whatever it is, still mints its facts.
      if (!segs.length && String(t || '').trim()) segs = [{ command: '', stdout: t, ts: null }];
      segs.forEach(function (s, li) {
        if (s.ts == null) s.ts = carry; else carry = s.ts;
        all.push({ command: s.command, stdout: s.stdout, ts: s.ts, ord: fi * 100000 + li });
      });
    });
    // Every address that belongs to the OPERATOR's Kali box - the engagement's configured VM IP, the LHOST,
    // every [tun0:...] prompt stamp, and every interface-dump address - so none is ever taken for a target.
    var self = selfIps(texts, all, lhost);
    var selfSet = {}; self.forEach(function (ip) { selfSet[ip] = 1; });
    // chronological where timestamps exist; stable on original order otherwise
    all.sort(function (a, b) { var at = a.ts == null ? a.ord : a.ts, bt = b.ts == null ? b.ord : b.ts; return at === bt ? a.ord - b.ord : at - bt; });
    var seen = {}, ranTools = {}, hosts = {}, imported = 0, dupes = 0, added = 0, first = null;
    var allFacts = [], allBlockers = [], outcomes = [], anyRecognized = false, allLooksErr = true, lastEpoch = 'anon', totalLines = 0;
    all.forEach(function (s) {
      // Compare the complete observation, including its routed target, before deduplicating.
      var tip = fixed || detectTarget(s.command, s.stdout, { lhost: lhost, known: known, self: self }) || params.target || '';
      var normalized = String(s.stdout || '').replace(/\r\n/g, '\n').trim();
      var key = OBOL.facts.fingerprint(JSON.stringify([tip, s.command.trim(), normalized]));
      if (seen[key]) { dupes++; return; }
      seen[key] = 1;
      var scope = tip ? ('host:' + tip) : undefined;
      var r = run({ text: s.stdout, command: s.command, source: opts.source || 'session', at: s.ts || undefined, quiet: true, fileName: opts.fileName || '', scope: scope, forceTarget: !!fixed, fromSession: true });
      if (r && r.ok) {
        if (r.context && r.context.target && !fixed) tip = r.context.target;
        imported++; added += (r.added || 0);
        totalLines += (r.lines || 0);
        if (r.recognizedTool) anyRecognized = true;
        if (!r.looksError) allLooksErr = false;
        if (r.epoch) lastEpoch = r.epoch;
        if (r.outcome) outcomes.push(r.outcome);
        (r.facts || []).forEach(function (f) { allFacts.push(f); });
        (r.blockers || []).forEach(function (b) { if (allBlockers.indexOf(b) < 0) allBlockers.push(b); });
        var tname = extractTool(s.command || r.cmd); if (tname) ranTools[tname] = 1;
        if (!first) first = s.command || r.cmd;
        // register a host only once we attributed proven facts to it in auto mode - and never the Kali box
        if (tip && r.facts && r.facts.length && !selfSet[tip]) { hosts[tip] = 1; if (!fixed && known.indexOf(tip) < 0) { _ensureTarget(tip); known.push(tip); } }
        else if (tip && fixed && !selfSet[tip]) hosts[tip] = 1;
      }
    });
    var targetsHit = null;
    if (all.length === 1 && !all[0].command && added === 0 && !allFacts.length && !anyRecognized) {
      var tImp = _tryPureTargetsImport(all[0].stdout);
      if (tImp && tImp.ok) {
        targetsHit = tImp;
        added += (tImp.added || 0);
      }
    }
    var merged = reconcileTargets();
    // Legacy embeddings without the context module historically chose an escalated identity here.
    // With explicit per-target selection, ingestion records material and proof only. It must preserve
    // an intentional no-credential choice as well as a different selected credential or session pin.
    var act = OBOL.store.active() || {}, ap = act.params || {};
    if (!(OBOL.context && OBOL.context.resolve) && !ap.username) {
      var esc = escalationCred(act.activities || []);
      if (esc) OBOL.store.update(function (e) {
        e.params = e.params || {};
        e.params.username = esc.user;
        if (esc.nthash) { e.params.nthash = esc.nthash; e.params.password = ''; }
        else if (esc.password !== undefined) { e.params.password = esc.password; e.params.nthash = ''; }
        if (esc.domain) e.params.domain = esc.domain;
      }, 'params');
    }
    if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    return { ok: true, arsenal: arsenalHit, workspaceSync: wsHit, targetsImported: targetsHit,
      commands: all.length, imported: imported, dupes: dupes, added: added,
      facts: allFacts, blockers: allBlockers, recognizedTool: anyRecognized, looksError: imported > 0 ? allLooksErr : false,
      epoch: lastEpoch, cmd: first || '', lines: totalLines, fileName: opts.fileName || '', parseError: '',
      tools: Object.keys(ranTools), hosts: Object.keys(hosts), merged: merged, remapped: remapped,
      outcomes: outcomes, outcome: OBOL.outcomes && OBOL.outcomes.aggregate ? OBOL.outcomes.aggregate(outcomes) : outcomes[0] || null };
  }

  var _lastCopied = null;
  function setLastCopied(info) {
    if (!info || !info.command) { _lastCopied = null; return; }
    var eng = OBOL.store.active() || {}, target = info.target || (eng.params || {}).target || '';
    var locus = info.executionLocus || (info.context && info.context.locus) || executionLocus(info.command, info.commandObj, info.locus);
    var ctx = info.context || (OBOL.context && OBOL.context.resolve ? OBOL.context.resolve({ engagement: eng, target: target,
      command: info.command, actionId: info.actionId || '', locus: locus }) : { target: target, locus: locus });
    _lastCopied = {
      command: String(info.command || ''),
      actionId: String(info.actionId || ''),
      target: String(target), locus: locus,
      context: OBOL.context && OBOL.context.snapshot ? OBOL.context.snapshot(ctx) : { target: target, locus: locus },
      at: Date.now()
    };
  }
  function getLastCopied(maxAgeMs) {
    if (!_lastCopied) return null;
    var limit = maxAgeMs || (30 * 60 * 1000);
    if (Date.now() - (_lastCopied.at || 0) > limit) return null;
    return _lastCopied;
  }

  OBOL.ingest = { run: run, deriveCommand: deriveCommand, sniffCommand: sniffCommand,
    contentSignatures: contentSignatures, dispatchLabel: dispatchLabel, recognizesTool: recognizesTool,
    looksLikeError: looksLikeError, detectLhost: detectLhost, detectTarget: detectTarget,
    remapIps: remapIps, splitSession: splitSession, importSession: importSession,
    renderOutcome: renderOutcome, outcomeMessage: outcomeMessage, preview: preview,
    credFromCommand: credFromCommand, escalationCred: escalationCred,
    extractTool: extractTool, extractToolName: extractTool,
    setLastCopied: setLastCopied, getLastCopied: getLastCopied,
    ensureParsers: ensureParsers, ready: ready };
})(typeof globalThis !== 'undefined' ? globalThis : this);
