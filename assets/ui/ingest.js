/*!
 * obol ui — ingest.js — the shared evidence-ingest core (no DOM).
 * Parses a paste/file with the conservative parsers, mints only proven facts, and records the
 * command+output (capped) as verbatim report evidence. Both the Evidence route and the coach's
 * inline per-command ingestion call this, so paste-anywhere behaves identically.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // Derive the command line from a full-terminal paste when the operator didn't type one.
  var TOOL_HEAD = /^(sudo\s+)?(nmap|rustscan|masscan|netexec|nxc|crackmapexec|cme|smbclient|smbmap|rpcclient|enum4linux[\w-]*|ldapsearch|kerbrute|impacket[\w.-]*|GetNPUsers[\w.]*|GetUserSPNs[\w.]*|secretsdump[\w.]*|evil-winrm|ffuf|feroxbuster|gobuster|wfuzz|nikto|whatweb|curl|wget|sqlmap|hydra|john|hashcat|responder|bloodhound[\w.-]*|sharphound[\w.-]*|bloodyad|dacledit|certipy[\w-]*|rubeus[\w.]*|pywhisker[\w.]*|sccmhunter[\w.]*|sharpsccm|wmiexec[\w.]*|psexec[\w.]*|smbexec[\w.]*|atexec[\w.]*|dcomexec[\w.]*|getst[\w.]*|gettgt[\w.]*|lookupsid[\w.]*|addcomputer[\w.]*|gpp-decrypt|getnpusers[\w.]*|getuserspns[\w.]*|dig|host|snmpwalk|ssh|ftp)\b/i;
  function deriveCommand(text) {
    var lines = String(text || '').split(/\r?\n/);
    for (var i = 0; i < lines.length && i < 40; i++) {
      var raw = lines[i], t = raw.trim();
      // Derive ONLY from a prompt-anchored line — a genuine terminal paste always carries the prompt,
      // and requiring it is what keeps tool OUTPUT (nmap's "Nmap scan report for 10.x", "Host is up
      // …") from being mistaken for a command. Handles the kali two-line prompt (└─$ / └─#),
      // user@host:cwd$/#, a bare $/#, and PowerShell (PS …>). No prompt → '' (caller keeps its own
      // command). The sigil must actually be stripped (pm/ps differ from the trimmed line).
      var pm = raw.replace(/^.*?[$#]\s+/, '').trim();       // after "…$ " / "…# "
      if (pm !== t && TOOL_HEAD.test(pm)) return pm;
      var ps = raw.replace(/^\s*PS[^>]*>\s+/i, '').trim();  // PowerShell "PS …> "
      if (ps !== t && TOOL_HEAD.test(ps)) return ps;
    }
    return '';
  }

  // The parser dispatch keys on the command that produced the output — which tool ran, with which
  // flags. When the operator pastes raw output with NO command (a redirected file, a screenshot's text,
  // any tool run out of obol's suggested order, or a paste dropped on a move whose tool it isn't),
  // recover a routing hint from the paste itself: every command-ish line (a shell-prompt line, OR a line
  // that leads with a tool obol parses) plus content signatures for output that names its own tool. What
  // is recovered is only ADDED to the dispatch label — never to lineage — and every parser stays
  // content/proof-bound, so a recovered token can ENABLE the right parser but can never manufacture a
  // fact the output doesn't support. Ported from obol-local's _sniff_command / _content_signatures.
  var TOOL_HINTS = {};
  ('nmap rustscan masscan nxc netexec crackmapexec cme ldapsearch smbclient smbmap rpcclient '
    + 'enum4linux enum4linux-ng gpp-decrypt wpscan kerbrute getnpusers getnpusers.py getuserspns '
    + 'getuserspns.py secretsdump secretsdump.py certipy certipy-ad bloodyad bloodhound '
    + 'bloodhound-python sharphound evil-winrm hashcat john responder ntlmrelayx ntlmrelayx.py getst '
    + 'getst.py gettgt gettgt.py wmiexec wmiexec.py psexec psexec.py smbexec atexec dcomexec lookupsid '
    + 'lookupsid.py rubeus pywhisker sccmhunter sharpsccm impacket-secretsdump impacket-getuserspns '
    + 'impacket-getnpusers nikto nuclei feroxbuster ffuf gobuster dirb whatweb httpx curl wget sqlmap '
    + 'hydra dig host fierce dnsrecon volatility vol.py git-dumper ike-scan penelope ftp lftp snmpwalk '
    + 'onesixtyone showmount rpcinfo id whoami sudo uname hostname ipconfig ifconfig systeminfo net '
    + 'wevtutil').split(' ').forEach(function (t) { TOOL_HINTS[t] = 1; });
  var PROMPT_SIGIL_RE = /[#$][ \t]+(\S.*\S|\S)\s*$/;
  function sniffCommand(text) {
    var lines = String(text || '').split(/\r?\n/), hits = [], seen = {};
    for (var i = 0; i < lines.length && i < 600 && hits.length < 12; i++) {
      var raw = lines[i], line = raw.trim();
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
  // A token is a string, OR a function of the regex match returning the token — so a signature can carry
  // through what it captured (the nxc PROTOCOL) instead of guessing. Emitting a fixed 'nxc smb' for every
  // protocol banner was the bug: `nxc ldap` output wrongly recovered as `nxc smb`, which then marked the
  // unrun `nxc smb` credential-check as ✓ ran.
  var CONTENT_SIGNATURES = [
    [/Nmap scan report for|Starting Nmap|^PORT\s+STATE\s+SERVICE/im, 'nmap scan'],
    [/^(SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+\s+\[[-*+]\]/m, function (m) { return 'nxc ' + m[1].toLowerCase(); }],
    [/^\S+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::/m, 'secretsdump'],
    [/\$krb5tgs\$/, 'getuserspns'],
    [/\$krb5asrep\$/, 'getnpusers'],
    [/SCCMHunter|NetworkAccess(?:Username|Password|Account)\s*[:=]/i, 'sccmhunter'],
    // bloodyAD `get writable` dump — a distinguishedName block followed by a bare WRITE/CREATE_CHILD attr.
    // Recovering it lets the coach mark the get-writable enumeration ✓ ran once you attach its 50k-line file.
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
    if (!recovered) return cmd;
    return cmd ? (cmd + '  ' + recovered) : recovered;
  }

  // Did this paste come from a tool obol recognizes actually RUNNING (vs. junk or an unrelated blob)?
  // The move's own command names the tool; failing that, the paste's own signatures do. Used to tell a
  // "the tool ran and simply found nothing" result apart from "you pasted something unparseable".
  function firstToolToken(cmd) {
    return (String(cmd || '').trim().split(/\s+/)[0] || '').split('/').pop().toLowerCase().replace(/\.(py|exe)$/, '');
  }
  function recognizesTool(cmd, text) {
    var f = firstToolToken(cmd);
    if (f && TOOL_HINTS[f]) return true;
    return !!(sniffCommand(text) || contentSignatures(text));
  }
  // Markers that mean the command did NOT complete cleanly (a usage/error/auth/network failure), so an
  // empty result is "it broke", not "it ran and found nothing" — obol must not retire the move on these.
  // Kept specific so a benign "Container not found" / "No results found" is NOT read as an error.
  var ERR_MARKERS = /\busage:|\btraceback\b|command not found|no such file|unrecognized option|invalid option|\bmissing option\b|permission denied|access is denied|\bunauthorized\b|logon failure|connection refused|could not connect|connection reset|name or service not known|\berror:/i;
  function looksLikeError(text) { return ERR_MARKERS.test(String(text || '')); }

  // The operator's own attacker IP, read from a terminal prompt like the Kali/HTB `[tun0:10.10.14.191]`
  // (also tap/vpn/wg/eth). This is YOUR listener/LHOST — obol fills {{lhost}} with it so coercion, relay
  // and reverse-shell commands form without hand-typing your VPN address on every box.
  var _LHOST_RE = /\[(?:tun|tap|vpn|wg|eth|wlan)\d*[:\/ ]\s*(\d{1,3}(?:\.\d{1,3}){3})\]/i;
  function detectLhost(text) {
    var m = _LHOST_RE.exec(String(text || ''));
    return m ? m[1] : '';
  }

  // Which HOST a command/output is about — so a whole-session import can route each command's facts to the
  // right target instead of dumping them all on the active one. The RHOST is almost always a positional
  // argument of the command (`nxc smb 10.0.0.5`, `bloodyAD --host 10.0.0.5`, `secretsdump …@10.0.0.5`); we
  // fall back to the host the tool NAMES in its output (`Nmap scan report for X`, an `SMB X 445 …` banner).
  // The operator's OWN machine is never a target: its LHOST (from the [tun0:…] stamp), any IP in a
  // listener/interface flag, loopback, and any address its interface dumps reveal (opts.self) are excluded.
  // Returns '' when nothing routable is found — the caller then leaves the command on the active target.
  var _IPV4_G = /(?:\d{1,3}\.){3}\d{1,3}/g;
  var _LISTENER_FLAG = /^(?:-l|--lhost|-lh|lhost|--listener|--interface-ip|--local-ip|--lip|--lhost=.*)$/i;
  var _OUT_HOST_RE = [
    /Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})/i,   // nmap: "…report for host (10.0.0.5)"
    /^(?:SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+/im,  // nxc/cme banner
  ];
  function _isRoutableIp(ip) {
    var o = String(ip).split('.'); if (o.length !== 4) return false;
    for (var i = 0; i < 4; i++) { var n = +o[i]; if (!(o[i] !== '' && n >= 0 && n <= 255)) return false; }
    // reject loopback (127/8) and link-local (169.254/16) and the broadcast/unspecified addresses — none
    // of these is ever a remote target, and 127/169.254 are always the operator's own box.
    return +o[0] !== 127 && !(+o[0] === 169 && +o[1] === 254) && ip !== '0.0.0.0' && ip !== '255.255.255.255';
  }
  // Commands that dump the operator's OWN interfaces — their output is the Kali box's addresses, never a
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
    // exclude any IP that sits right after a listener/interface flag (coercer -l <ip>, msfvenom LHOST=…)
    var toks = cmd.split(/[\s=]+/);
    for (var i = 0; i < toks.length - 1; i++) { if (_LISTENER_FLAG.test(toks[i]) && _isRoutableIp(toks[i + 1] || '')) excl[toks[i + 1]] = 1; }
    var cip = (cmd.match(_IPV4_G) || []).filter(function (ip) { return _isRoutableIp(ip) && !excl[ip]; });
    // prefer a command IP that is already a known engagement target (strongest signal it's a real host)
    for (var k = 0; k < cip.length; k++) { if (known.indexOf(cip[k]) >= 0) return cip[k]; }
    if (cip.length) return cip[0];
    // no target in the command — trust only the host the tool explicitly names in its output
    var out = String(stdout || '');
    for (var r = 0; r < _OUT_HOST_RE.length; r++) { var m = _OUT_HOST_RE[r].exec(out); if (m && _isRoutableIp(m[1]) && !excl[m[1]]) return m[1]; }
    return '';
  }
  // Every address that belongs to the OPERATOR (never a target): the params LHOST, every [tun/tap/…:IP]
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

  function ready() { return !!(OBOL.parsers && OBOL.parsers.parseActionOutput); }
  // Resolve to true once the (lazily-loaded) parser group is available.
  function ensureParsers() {
    if (ready()) return Promise.resolve(true);
    if (OBOL.lazy && OBOL.lazy.loadGroup) return OBOL.lazy.loadGroup('parsers').then(ready).catch(function () { return false; });
    return Promise.resolve(false);
  }

  // Parse + mint + record. No DOM, no toast — the caller renders the outcome.
  //   opts = { text, command?, source?, fileName?, actionId? }
  // returns { ok, added, facts, cmd, lines, fileName } or { ok:false, reason:'empty'|'parsers'|'error', error? }
  function run(opts) {
    opts = opts || {};
    var text = opts.text || '';
    if (!text.trim()) return { ok: false, reason: 'empty' };
    if (!ready()) return { ok: false, reason: 'parsers' };
    // Route on what the paste ACTUALLY shows (its prompt/command line) over the move's canned
    // command, so pasting any tool's output into any move's box still reaches the right parser and
    // mints its facts — the coach is proof-gated, so out-of-order evidence just unlocks the right
    // moves. Fall back to the caller's command only when the paste carries no command line of its own
    // (e.g. raw redirected output); nmap XML still self-identifies from its <nmaprun args>.
    var derived = deriveCommand(text);
    var cmd = derived || (opts.command && opts.command.trim()) || '';
    // Widen the DISPATCH label with whatever the paste reveals about its tool, so output-only pastes and
    // out-of-order evidence still reach the right parser. Lineage/tool below stay the honest `cmd`.
    var dispatchCmd = dispatchLabel(cmd, text);
    var eng = OBOL.store.active();
    var params = (eng && eng.params) || {};
    // Learn the operator's LHOST from the paste's own prompt (`[tun0:10.10.14.191]`) when not already set,
    // so {{lhost}} stops reading "needs: lhost" the moment a real terminal capture goes through.
    if (!params.lhost) {
      var lh = detectLhost(text);
      if (lh) { OBOL.store.update(function (e) { e.params = e.params || {}; e.params.lhost = lh; }, 'params'); params = (OBOL.store.active() || {}).params || params; }
    }
    // Scope the facts to a specific host. A whole-session import passes the per-command host it auto-routed
    // to (opts.scope); a normal paste falls back to the engagement's active target.
    var scope = opts.scope || ('host:' + (params.target || 'target'));
    var scopeIp = scope.indexOf('host:') === 0 ? scope.slice(5) : (params.target || '');
    var res, parseError = '';
    try {
      res = OBOL.parsers.parseActionOutput({ command: dispatchCmd, stdout: text, source: opts.fileName || cmd || 'paste', scope: scope, domain: params.domain || '' });
    } catch (e) { res = { facts: [] }; parseError = (e && e.message) || 'parse failed'; }
    if (res && res.error) parseError = res.error; // a sub-parser threw but earlier facts survived
    var facts = (res && res.facts) || [];
    var added = OBOL.store.addFacts(facts, 'evidence');
    var CAP = 24000;
    var lines = text.split(/\r?\n/).length;
    var stored = text.length > CAP
      ? (text.slice(0, CAP) + '\n… [truncated — ' + (text.length - CAP) + ' more chars, ' + lines + ' lines total]')
      : text;
    OBOL.store.update(function (e) {
      e.activities = e.activities || [];
      // `command` stays the honest lineage (may be empty for an attached file); `dispatch` is the widened
      // routing label obol recovered from the content — the coach's "already run" check reads it so an
      // ATTACHED dump (no typed command) still marks the command that produced it ✓ ran.
      e.activities.unshift({ at: opts.at || Date.now(), command: cmd, dispatch: (dispatchCmd !== cmd ? dispatchCmd : ''),
        source: opts.source || 'paste', tool: (cmd.split(/\s+/)[0] || 'paste'),
        target: scopeIp || params.target || '', scope: scope, file: opts.fileName || '', action_id: opts.actionId || '',
        produced: facts.map(function (f) { return f.kind; }), stdout: stored, sample: text.slice(0, 400) });
    }, 'activity');
    // `quiet` — a batch session import re-renders ONCE at the end instead of per command.
    if (!opts.quiet && OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    // Signals for the caller's "this move ran but proved nothing" decision: did a tool obol knows about
    // actually run (recognized), and did it fail rather than simply come up empty (looksError)?
    return { ok: true, added: added, facts: facts, cmd: cmd, lines: lines, fileName: opts.fileName || '',
      parseError: parseError, recognizedTool: recognizesTool(cmd, text), looksError: looksLikeError(text) };
  }

  // ── Whole-session import ────────────────────────────────────────────────────────────────────────
  // Split a full terminal capture (many commands + their output) into per-command segments, so obol can
  // catch up on an entire box at once — the "get me un-stuck" path. A segment begins at a prompt/command
  // line and runs until the next one; the timestamp on a Kali prompt (`[2026-09-27 17:17:38 UTC]`) is
  // captured so multiple tabs/files can be stitched into one chronological history.
  var _PROMPT_LINE = [
    /^\s*(?:┌──.*)?└─[#$]\s+(\S.*)$/,                                   // Kali two-line prompt (cmd on └─$)
    /^[\w.\-]+@[\w.\-]+:[^\s#$]*\s*[#$]\s+(\S.*)$/,                      // user@host:cwd$ cmd
    /^PS\s+[A-Za-z]:[^>]*>\s+(\S.*)$/,                                   // PowerShell PS C:\...> cmd
  ];
  var _BARE_PROMPT = /^\s*[#$]\s+(\S.*)$/;                              // bare "$ cmd" / "# cmd" (last resort)
  var _TS_RE = /\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/;          // a prompt timestamp → epoch ms
  function _promptCmd(raw) {
    for (var i = 0; i < _PROMPT_LINE.length; i++) { var m = _PROMPT_LINE[i].exec(raw); if (m) return m[1].trim(); }
    return null;
  }
  function _ts(line) {
    var m = _TS_RE.exec(line || ''); if (!m) return null;
    var t = Date.parse(m[1] + 'T' + m[2] + 'Z'); return isNaN(t) ? null : t;
  }
  // Segment one capture into [{command, stdout, ts}], newest-of-the-block timestamp carried from its prompt
  // (or the line just above it, where the Kali prompt prints the time). Heredocs (cat > f <<'EOF' … EOF)
  // are swallowed into their command's block so their body is not mistaken for more commands.
  function splitSession(text) {
    var lines = String(text || '').split(/\r?\n/), segs = [], cur = null, prev = '', prev2 = '', heredoc = null;
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      if (heredoc !== null) { if (cur) cur.stdout.push(raw); if (raw.trim() === heredoc) heredoc = null; prev2 = prev; prev = raw; continue; }
      var cmd = _promptCmd(raw);
      // A bare "$ cmd" / "# cmd" is a weak signal — tool output is full of lines that start with "# "
      // (config/comment dumps) or "$ " — so accept one only when what follows leads with a tool obol
      // knows. Strong prompts (Kali └─$, user@host, PS …>) are matched above with no such gate.
      if (cmd == null) { var bm = _BARE_PROMPT.exec(raw); if (bm && TOOL_HINTS[firstToolToken(bm[1])]) cmd = bm[1].trim(); }
      if (cmd != null) {
        if (cur) segs.push(cur);
        // the stamp may be inline on the prompt (Kali), or on a stamp line 1–2 rows above (obol's precmd tweak)
        cur = { command: cmd, stdout: [], ts: _ts(raw) || _ts(prev) || _ts(prev2) };
        var hd = /<<-?\s*['"]?([A-Za-z_][\w]*)['"]?/.exec(cmd); if (hd) heredoc = hd[1];
      } else if (cur) { cur.stdout.push(raw); }
      prev2 = prev; prev = raw;
    }
    if (cur) segs.push(cur);
    return segs.map(function (s) { return { command: s.command, stdout: s.stdout.join('\n').replace(/^\n+|\n+$/g, ''), ts: s.ts }; });
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
      // 2) collapse duplicates that now share an IP — keep the first, fill its blanks from the rest
      var byIp = {}, keep = [];
      ts.forEach(function (t) {
        if (!t) return;
        if (!t.ip) { keep.push(t); return; }               // still no IP → leave as its own card
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
  //   opts = { fileName?, target? }  target: 'auto' (default) routes each command to the host it names, and
  //   registers any new host it lands facts on; a specific IP forces every command onto that host.
  function importSession(inputs, opts) {
    opts = opts || {};
    if (!ready()) return { ok: false, reason: 'parsers' };
    var texts = Array.isArray(inputs) ? inputs : [inputs];
    var eng = OBOL.store.active();
    var params = (eng && eng.params) || {};
    var routeMode = opts.target || 'auto';
    var fixed = (routeMode !== 'auto' && routeMode) ? String(routeMode) : '';
    // Learn the operator's LHOST up front (from any capture's [tun0:…] stamp) so it is excluded from
    // target auto-routing even on the very first command — before run() gets a chance to persist it.
    var lhost = params.lhost || '';
    if (!lhost) { for (var ti = 0; ti < texts.length && !lhost; ti++) lhost = detectLhost(texts[ti]); }
    var known = _knownTargets(eng);
    var all = [];
    texts.forEach(function (t, fi) {
      var segs = splitSession(t), carry = null;
      segs.forEach(function (s, li) {
        if (s.ts == null) s.ts = carry; else carry = s.ts;
        all.push({ command: s.command, stdout: s.stdout, ts: s.ts, ord: fi * 100000 + li });
      });
    });
    // Every address that belongs to the OPERATOR's Kali box — the engagement's configured VM IP, the LHOST,
    // every [tun0:…] prompt stamp, and every interface-dump address — so none is ever taken for a target.
    var self = selfIps(texts, all, lhost);
    var selfSet = {}; self.forEach(function (ip) { selfSet[ip] = 1; });
    // chronological where timestamps exist; stable on original order otherwise
    all.sort(function (a, b) { var at = a.ts == null ? a.ord : a.ts, bt = b.ts == null ? b.ord : b.ts; return at === bt ? a.ord - b.ord : at - bt; });
    var seen = {}, ranTools = {}, hosts = {}, imported = 0, dupes = 0, added = 0, first = null;
    all.forEach(function (s) {
      var firstOut = (s.stdout.split(/\r?\n/).find(function (l) { return l.trim(); }) || '').slice(0, 120);
      var key = s.command.replace(/\s+/g, ' ').trim() + '|' + firstOut;
      if (seen[key]) { dupes++; return; }
      seen[key] = 1;
      // Route this command to a host: the fixed target, else the one it names, else the active target.
      var tip = fixed || detectTarget(s.command, s.stdout, { lhost: lhost, known: known, self: self }) || params.target || '';
      var scope = tip ? ('host:' + tip) : undefined;
      var r = run({ text: s.stdout, command: s.command, source: 'session', at: s.ts || undefined, quiet: true, fileName: opts.fileName || '', scope: scope });
      if (r && r.ok) {
        imported++; added += (r.added || 0); ranTools[(s.command.split(/\s+/)[0] || '').toLowerCase()] = 1;
        if (!first) first = s.command;
        // register a host only once we attributed proven facts to it in auto mode — and never the Kali box
        if (tip && r.facts && r.facts.length && !selfSet[tip]) { hosts[tip] = 1; if (!fixed && known.indexOf(tip) < 0) { _ensureTarget(tip); known.push(tip); } }
        else if (tip && fixed && !selfSet[tip]) hosts[tip] = 1;
      }
    });
    var merged = reconcileTargets();
    if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
    return { ok: true, commands: all.length, imported: imported, dupes: dupes, added: added,
      tools: Object.keys(ranTools), hosts: Object.keys(hosts), merged: merged };
  }

  OBOL.ingest = { run: run, deriveCommand: deriveCommand, sniffCommand: sniffCommand,
    contentSignatures: contentSignatures, dispatchLabel: dispatchLabel, recognizesTool: recognizesTool,
    looksLikeError: looksLikeError, detectLhost: detectLhost, detectTarget: detectTarget,
    splitSession: splitSession, importSession: importSession,
    ensureParsers: ensureParsers, ready: ready };
})(typeof globalThis !== 'undefined' ? globalThis : this);
