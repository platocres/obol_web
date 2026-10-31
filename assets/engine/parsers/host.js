/*!
 * obol engine - parsers/host.js
 * Faithful JS port of  (command-exec / shell footholds
 * and Linux/Windows local-privesc leads). Leads never prove admin/root/SYSTEM by themselves.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  function _exec_tool(command, text) {
    var l = (command || '').toLowerCase();
    var tools = ['evil-winrm', 'wmiexec', 'psexec', 'atexec', 'smbexec', 'dcomexec'];
    for (var i = 0; i < tools.length; i++) if (l.indexOf(tools[i]) >= 0) return tools[i];
    if (l.indexOf('enter-pssession') >= 0) return 'winrs';
    if (C._is_ssh_command && C._is_ssh_command(command || '')) return 'ssh';
    if (/\b(?:nxc|netexec|crackmapexec|cme)\s+/.test(l)) return 'nxc';
    if (text) {
      if (/\*Evil-WinRM\*|Evil-WinRM shell/i.test(text)) return 'evil-winrm';
      for (var j = 0; j < tools.length; j++) {
        if (new RegExp('\\b(?:impacket-)?' + tools[j] + '(?:\\.py)?\\b', 'i').test(text)) return tools[j];
      }
      if (/Launching semi-interactive shell - Careful what you execute[\s\S]{0,200}?Press help for extra shell commands/i.test(text)) return 'wmiexec';
      if (/Requesting shares on\s+\S+\.\.\.[\s\S]{0,300}?(?:Creating service|Starting service)\b/i.test(text)) return 'psexec';
      if (/Launching semi-interactive shell/i.test(text)) return 'smbexec';
    }
    return 'exec';
  }
  C._exec_tool = _exec_tool;

  function _normalize_identity(identity) {
    identity = identity.trim();
    if (identity.toLowerCase() === 'nt authority\\system') return 'nt authority\\system';
    return identity;
  }
  C._normalize_identity = _normalize_identity;

  function _is_dos_emulator(command, text, promptLine) {
    if (typeof C.isDosEmulatorContext === 'function') {
      return !!C.isDosEmulatorContext(command, text, promptLine);
    }
    var combined = String(command || '') + '\n' + String(text || '');
    if (/\bdosbox\b|Drive [A-Z] is mounted as (?:local directory|internal Virtual Drive)|\bMOUNT\s+[A-Za-z]\s+\/(?:\s|$)/i.test(combined)) {
      return true;
    }
    var promptHay = String(promptLine || '') + '\n' + String(text || '');
    if (/^\s*[A-Za-z]:\\>/m.test(promptHay) && /(?:^|\s|[><|"'=])\/(?:etc|usr|bin|sbin|var|home|root|tmp|opt)\//.test(combined)) {
      return true;
    }
    return false;
  }

  function _parse_command_execution(text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var promptCtx = [
      ws && ws.context && ws.context.promptLine,
      ws && ws.context && ws.context.followPrompt
    ].filter(Boolean).join('\n');
    var fullExecText = promptCtx ? (String(text || '') + '\n' + promptCtx) : String(text || '');
    var identities = reAll(C._WHOAMI_ID_RE, text).map(function (m) { return _normalize_identity(m.groups.id); }).filter(Boolean);
    if (_is_dos_emulator(command, fullExecText, promptCtx) && identities.length === 0) return;
    var isSystem = identities.some(function (identity) { return identity.toLowerCase() === 'nt authority\\system'; });
    var isAdminWhoami = identities.some(function (identity) { return /(?:^|[\\/])administrator$/i.test(identity); });
    var interactive = !!reSearch(C._INTERACTIVE_RE, fullExecText)
      || (command || '').toLowerCase().indexOf('enter-pssession') >= 0
      || /^\s*(?:PS\s+)?[A-Za-z]:\\[^>\r\n]*>/im.test(fullExecText)
      || /^\s*(?:[A-Za-z0-9_.-]+\\)?[A-Za-z0-9_.$-]+@[A-Za-z0-9_.-]+\s+[A-Za-z]:\\[^>\r\n]*>/im.test(fullExecText)
      || /^\s*(?:Volume in drive [A-Za-z]\b|Directory of [A-Za-z]:\\)/im.test(text || '');
    var executed = identities.length > 0 || !!reSearch(C._EXEC_SUCCESS_RE, fullExecText) || interactive;
    var cmdAndText = (command || '') + '\n' + (text || '');
    var rdpEnableAttempt = /fDenyTSConnections|Remote Desktop Users|TermService|group\s*=\s*["']?remote desktop/i.test(cmdAndText);
    var winrmEnableAttempt = /Remote Management Users|winrm\s+quickconfig|Enable-PSRemoting|WinRM-HTTP|AllowAutoConfig|WinRMInit/i.test(cmdAndText);
    var winrmEnableFailed = /\b(?:Set-WSManQuickConfig\s*:\s*Access is denied|WsManError|WSManFault|Microsoft\.WSMan\.Management\.SetWSManQuickConfigCommand)\b|Errno::ECONNREFUSED[^\r\n]*5985/i.test(text || '');
    var rdpEnableFailed = /\b(?:OpenSCManager\s+FAILED\s+5)\b|reg:\s*ERROR:\s*Access is denied/i.test(text || '');
    var textForExecSuccess = winrmEnableFailed
      ? String(text || '').replace(/WinRM (?:service )?(?:already is|is already)[^\r\n]*/gi, '')
      : String(text || '');
    var execFailed = /\b(?:STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED|Access is denied|System error 5 has occurred|rpc_s_access_denied|SessionError:.*STATUS_)\b/i.test(text || '')
      && !/\(Pwn3d!\)|\[\+\]\s*Executed command|The command completed successfully|The operation completed successfully|WinRM (?:service )?is already|WinRM has been updated|Updated \d+ rule\(s\)/i.test(textForExecSuccess);
    if ((execFailed || (winrmEnableAttempt && !rdpEnableAttempt && winrmEnableFailed && !/\(Pwn3d!\)|\[\+\]\s*Executed command/i.test(text || ''))) && identities.length === 0) return;
    var enableConfirmed = (rdpEnableAttempt && !rdpEnableFailed || winrmEnableAttempt && !winrmEnableFailed)
      && /\(Pwn3d!\)|\[\+\]\s*Executed command|The command completed successfully|The operation completed successfully|WinRM (?:service )?is already|WinRM has been updated|Updated \d+ rule\(s\)|SUCCESS:\s*The scheduled task|^\s*Ok\.\s*$/im.test(textForExecSuccess);
    if (!executed && !enableConfirmed) return;
    var tool = _exec_tool(command, text);
    if (executed) {
      var footholdValue = { method: tool };
      var nonSystem = identities.filter(function (i) { return i.toLowerCase() !== 'nt authority\\system'; });
      if (!nonSystem.length && !isSystem) {
        var pm = /^\s*(?:\*?Evil-WinRM\*?\s+)?(?:PS\s+)?[A-Za-z]:\\Users\\([A-Za-z0-9._-]+)(\\[^>"'\r\n]*)?>/im.exec(fullExecText);
        var isDotSvcSubdir = !!(pm && pm[1] && /^administrator$/i.test(pm[1]) && pm[2] && /^\\\.[A-Za-z0-9_.-]+(?:\\|$)/.test(pm[2]));
        if (pm && pm[1] && !/^(Public|Default|All Users)$/i.test(pm[1]) && !isDotSvcSubdir) nonSystem.push(pm[1]);
      }
      if (!nonSystem.length && !isSystem) {
        var sshWinPm = /^\s*(?:[A-Za-z0-9_.-]+\\)?([A-Za-z0-9_.$-]+)@[A-Za-z0-9_.-]+\s+[A-Za-z]:\\[^>\r\n]*>/im.exec(fullExecText);
        if (sshWinPm && sshWinPm[1]) nonSystem.push(sshWinPm[1]);
      }
      if (!nonSystem.length && !isSystem && command) {
        var cmdUser = C._command_arg ? C._command_arg(command, ['-u', '--user', '--username', '-l']) : '';
        if (!cmdUser) {
          var impM = /\b(?:impacket-[\w.-]+|(?:wmi|ps|smb|at|dcom)exec(?:\.py)?|ssh(?:\.exe)?)\b[^\r\n]*?(?:['"](?:[^/'":@\s]+[\\/])?([A-Za-z0-9._$-]+)(?::[^@'"]*)?@|(?:^|\s)(?:[^/'":@\s]+[\\/])?([A-Za-z0-9._$-]+)(?::[^\s@'"]*)?@(?:[A-Za-z0-9_.-]+))/i.exec(command);
          if (impM) cmdUser = impM[1] || impM[2] || '';
        }
        if (cmdUser) {
          var cleanedCmdUser = C._clean_username ? C._clean_username(cmdUser) : cmdUser;
          if (cleanedCmdUser) nonSystem.push(cleanedCmdUser);
        }
      }
      if (nonSystem.length && /(?:^|[\\/])administrator$/i.test(nonSystem[0])) isAdminWhoami = true;
      if (nonSystem.length) {
        footholdValue.identity = nonSystem[0];
        for (var i = facts.length - 1; i >= 0; i--) {
          var f = facts[i];
          if (f.kind === 'foothold.windows' && f.scope === h && !('identity' in f.value)) facts.splice(i, 1);
        }
      }
      _add(facts, mkFact('foothold.windows', h, footholdValue, S, source));
      C._add_os_observation(facts, ws, source, 'windows', 'Windows command execution output', 'high', tool, true);
      if (isSystem) {
        _add(facts, mkFact('access.system', h, { identity: 'nt authority\\system', method: tool }, S, source));
        _add(facts, mkFact('access.admin', h, { identity: 'nt authority\\system', method: tool }, S, source));
      }
      var lowCmd = (command || '').toLowerCase();
      var isXpCmdshell = /xp_cmdshell/i.test(command || '') || /xp_cmdshell/i.test(text || '');
      if (!isSystem && (isAdminWhoami || (!isXpCmdshell && (['wmiexec', 'psexec', 'smbexec', 'atexec', 'dcomexec'].indexOf(tool) >= 0 || ['wmiexec', 'atexec'].some(function (t) { return lowCmd.indexOf(t) >= 0; }))))) {
        _add(facts, mkFact('access.admin', h, { identity: nonSystem.length ? nonSystem[0] : '', method: tool, note: isAdminWhoami ? 'whoami administrator' : 'local admin, wmiexec/atexec require it' }, S, source));
      }
      if (interactive && (C._INTERACTIVE_WIN_TOOLS.has(tool) || isSystem || isAdminWhoami)) {
        var deskVal = { session: C._INTERACTIVE_WIN_TOOLS.has(tool) ? tool : 'cmd' };
        if (nonSystem.length) {
          deskVal.user = nonSystem[0];
          if (/(?:^|[\\/])administrator$/i.test(nonSystem[0])) deskVal.admin = true;
        }
        if (isSystem || isAdminWhoami || (!isXpCmdshell && ['wmiexec', 'psexec', 'smbexec', 'atexec', 'dcomexec'].indexOf(tool) >= 0)) {
          deskVal.admin = true;
        }
        _add(facts, mkFact('access.desktop', h, deskVal, S, source));
      }
    }
    var execConfirmed = executed || enableConfirmed;
    if (execConfirmed && !execFailed) {
      if (rdpEnableAttempt && !rdpEnableFailed) {
        _add(facts, mkFact('port:3389', h, { port: 3389, protocol: 'tcp', service: 'ms-wbt-server', state: 'open', via: 'remote-enable' }, S, source));
        _add(facts, mkFact('rdp.reachable', h, { port: 3389, tool: tool || 'nxc' }, S, source));
        _add(facts, mkFact('host.rdp_enabled', h, { port: 3389, tool: tool || 'nxc' }, S, source));
      }
      if (winrmEnableAttempt && !winrmEnableFailed) {
        _add(facts, mkFact('port:5985', h, { port: 5985, protocol: 'tcp', service: 'wsman', state: 'open', via: 'remote-enable' }, S, source));
        _add(facts, mkFact('winrm.reachable', h, { port: 5985, tool: tool || 'nxc' }, S, source));
        _add(facts, mkFact('host.winrm_enabled', h, { port: 5985, tool: tool || 'nxc' }, S, source));
      }
    }
  }
  C._parse_command_execution = _parse_command_execution;

  function _is_local_enum_report(text, command) {
    var cmd = String(command || '').toLowerCase();
    return /\b(?:linpeas|winpeas|linux-exploit-suggester|les\.sh|getcap)\b|\bsudo\s+-l\b|\bfind\s+[^\r\n]*-perm\b/.test(cmd) ||
      /(?:╣|={3,})[^\r\n]*(?:Current user|Operative system|Capabilities)|Executing Linux Exploit Suggester|Files with capabilities \(limited to/i.test(text);
  }
  C._is_local_enum_report = _is_local_enum_report;

  var _SSH_EXEC_FAIL_RE = /\b(?:Permission denied|Authentication failed|Connection refused|Connection timed out|Connection closed by|Connection reset by|Host key verification failed|No route to host|Could not resolve hostname|no matching (?:host key|key exchange|cipher)|no mutual signature|Too many authentication failures)\b/i;
  var _SSH_USAGE_NOISE_RE = /^\s*usage:\s*ssh\b/im;
  var _SSH_POSTAUTH_WELCOME_RE = /^\s*Welcome to (?:Ubuntu|Debian|Alpine|CentOS|Red Hat|Fedora|Kali|Rocky|AlmaLinux|SUSE|openSUSE|Arch Linux|Gentoo|FreeBSD)\b[^\r\n]*/im;
  var _SSH_POSTAUTH_LASTLOGIN_RE = /^\s*Last login:\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}/im;
  var _SSH_RESTRICTED_BANNER_RE = /\b(?:You are in a )?(?:limited shell|restricted shell|lshell|rbash)\b|Type '\?' or 'help' to get the list of allowed commands|\*\*\*\s*forbidden\s*(?:command|character|path)/i;
  var _ATTACKER_PROMPT_ENTITY_RE = /^(?:kali|parrot|attacker|hacky|pwnbox|exegol|localhost|ubuntu-vm|commando|slingshot|pentest|offsec|htb|tryhackme|vagrant|archlinux|blackarch)$/i;
  var _ATTACKER_REMOTE_OR_LISTENER_CMD_RE = /\b(?:ssh|sshpass|scp|sftp|curl|wget|httpie|nc|ncat|netcat|socat|rlwrap|pwncat(?:-cs)?|penelope|chisel|ligolo[a-z0-9_-]*|nxc|netexec|crackmapexec|cme|evil-winrm|winrs|xfreerdp|rdesktop|impacket-[a-z0-9_-]+|(?:wmi|ps|smb|at|dcom)exec(?:\.py)?|msfconsole|telnet|rlogin|rsh|rexec|psql|sqlplus|odat|mysql|mariadb|mssqlclient(?:\.py)?|sqsh|redis-cli|mongosh|mongo|ftp|lftp|smbclient|rpcclient|ldapsearch|bloodyad|certipy(?:-ad)?|kerbrute|snmpwalk|snmp-check|onesixtyone|enum4linux(?:-ng)?|nikto|sqlmap|wfuzz|ffuf|gobuster|feroxbuster|dirsearch|wpscan|nuclei|httpx|git-dumper|ansible(?:-playbook)?|kubectl|docker\s+-H)\b|\bhttps?:\/\/|(?:^|\s)(?:--?(?:rhost|target|host|url)|-H)\s+\S|\b(?:python[23]?|ruby|perl|php|bash|sh)\s+[^\r\n]*(?:exploit|rce|pwn|shell|cve[-_])/i;

  function _parse_unix_prompt_line(rawLine, opts) {
    var l = String(rawLine || '').replace(C._ANSI_RE || /\x1b\[[0-9;?]*[ -/]*[@-~]/g, '').trim();
    if (!l || /^[┌╭└╰]──/.test(l) || /\[(?:tun|tap|vpn|wg)\d*:/i.test(l)) return null;
    var bm = /^(?:\([^)]+\)\s*)?\[([A-Za-z0-9_.-]+)(?:@|\u327f)([A-Za-z0-9_.-]+)(?:[:\s]+([^\]]*))?\]\s*([#$%])(?:\s+.*)?$/.exec(l);
    if (bm) {
      return { user: bm[1], host: bm[2], cwd: (bm[3] || '').trim(), sigil: bm[4], raw: l };
    }
    var cm = /^(?:\([^)]+\)\s*)?([A-Za-z0-9_.-]+)(?:@|\u327f)([A-Za-z0-9_.-]+):([^\r\n$#%>\]]*)([#$%])(?:\s+.*)?$/.exec(l);
    if (cm) {
      return { user: cm[1], host: cm[2], cwd: (cm[3] || '').trim(), sigil: cm[4], raw: l };
    }
    var tm = /^(?:\([^)]+\)\s*)?([A-Za-z0-9_.-]+)(?:@|\u327f)([A-Za-z0-9_.-]+)([#$%])(?:\s+\S.*|\s*)$/.exec(l);
    if (tm) {
      return { user: tm[1], host: tm[2], cwd: '', sigil: tm[3], raw: l };
    }
    var sm = /^((?:ba|da|z|k|a)?sh-[0-9.]+)\s*([#$])(?:\s+.*)?$/i.exec(l);
    if (sm) {
      return { user: sm[2] === '#' ? 'root' : '', host: '', cwd: '', sigil: sm[2], isBareSh: true, raw: l };
    }
    var csm = /^(?!(?:HTTP|TLS|SSL|SSH|CVE|PHP|GCC|GDB)-)([A-Za-z0-9_.-]{2,32}-[3-6]\.\d+(?:\.\d+)?)\s*([#$])(?:\s+.*)?$/.exec(l);
    if (csm) {
      return { user: csm[2] === '#' ? 'root' : '', host: '', cwd: '', sigil: csm[2], isBareSh: true, raw: l };
    }
    var apm = opts && opts.isPromptCtx
      ? /^(\/(?:[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*\/?)?)[ \t]+([#$])(?:\s+.*)?$/.exec(l)
      : /^(\/(?:[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*\/?)?)[ \t]+([#$])(?:[ \t]*|[ \t]+(?:id|whoami|pwd|ls|cat|uname|hostname|ps|env|sh|bash|ash|su|sudo|cd|find|exit)\b.*)$/.exec(l);
    if (apm) {
      return { user: apm[2] === '#' ? 'root' : '', host: '', cwd: apm[1], sigil: apm[2], isBareSh: true, raw: l };
    }
    return null;
  }

  function _is_attacker_prompt_string(promptLine) {
    if (!promptLine) return false;
    var first = String(promptLine).replace(C._ANSI_RE || /\x1b\[[0-9;?]*[ -/]*[@-~]/g, '').split(/\r?\n/)[0].trim();
    if (!first) return false;
    if (/\[(?:tun|tap|vpn|wg)\d*:/i.test(first)) return true;
    var boxM = /^[┌╭]──\s*\(([A-Za-z0-9_.-]+)(?:@|\u327f)([A-Za-z0-9_.-]+)\)/.exec(first);
    if (boxM && (_ATTACKER_PROMPT_ENTITY_RE.test(boxM[1]) || _ATTACKER_PROMPT_ENTITY_RE.test(boxM[2]))) return true;
    var p = _parse_unix_prompt_line(first, { isPromptCtx: true });
    if (p && ((p.user && _ATTACKER_PROMPT_ENTITY_RE.test(p.user)) || (p.host && _ATTACKER_PROMPT_ENTITY_RE.test(p.host)))) return true;
    return false;
  }
  C._is_attacker_prompt_string = _is_attacker_prompt_string;

  function _is_attacker_local_turn(ws, command, text) {
    var promptLine = (ws && ws.context && ws.context.promptLine) || '';
    if (!_is_attacker_prompt_string(promptLine)) return false;
    var cmd = String(command || '').trim();
    if (_ATTACKER_REMOTE_OR_LISTENER_CMD_RE.test(cmd)) return false;
    var tgt = String((ws && ws.target) || '').trim().toLowerCase();
    if (tgt && tgt !== 'unknown' && cmd.toLowerCase().indexOf(tgt) >= 0) return false;
    var dom = String((ws && ws.domainSeed) || '').trim().toLowerCase();
    if (dom && cmd.toLowerCase().indexOf(dom) >= 0) return false;
    if (text) {
      if (/\b(?:connect to \[[^\]]+\] from|Connection received on|listening on \[any\] \d+|\bMeterpreter session \d+ opened|\bCommand shell session \d+ opened)\b/i.test(text)) return false;
      if (_match_verified_remote_unix_prompt(text, promptLine).matched) return false;
    }
    return true;
  }
  C._is_attacker_local_turn = _is_attacker_local_turn;

  function _is_outbound_simplehttp_callback(text, command, ws) {
    var t = String(text || '');
    if (!/(?:^\s*(?:<\s*)?Server:\s*SimpleHTTP\/\d|HTTPServer\[[^\]]*SimpleHTTP\/|\bSimpleHTTP\/\d+(?:\.\d+)*\s+Python\/\d)/im.test(t)) return false;
    var cmd = String(command || '');
    var urlHosts = [];
    if (/\b(?:wget|curl|iwr|invoke-webrequest|irm|invoke-restmethod|certutil|bitsadmin|fetch|aria2c|axel|lwp-download|python[23]?)\b/i.test(cmd)) {
      reAll(/https?:\/\/(?:\[([0-9a-fA-F:]+)\]|([^/:?\s'"#]+))/gi, cmd).forEach(function (m) {
        var uh = (m[1] || m[2] || '').toLowerCase();
        if (uh) urlHosts.push(uh);
      });
    }
    reAll(/^--\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}--\s+https?:\/\/(?:\[([0-9a-fA-F:]+)\]|([^/:?\s'"#]+))/gim, t).forEach(function (m) {
      var uh = (m[1] || m[2] || '').toLowerCase();
      if (uh) urlHosts.push(uh);
    });
    if (!urlHosts.length) return false;
    var tgt = String((ws && ws.target) || '').trim().toLowerCase();
    var dom = String((ws && ws.domainSeed) || '').trim().toLowerCase();
    var knownTargetHosts = Object.create(null);
    if (tgt && tgt !== 'unknown') knownTargetHosts[tgt] = 1;
    if (dom) knownTargetHosts[dom] = 1;
    var pools = [(ws && ws.facts) || [], (ws && ws.seedFacts) || []];
    for (var pi = 0; pi < pools.length; pi++) {
      var arr = pools[pi];
      if (!Array.isArray(arr)) continue;
      for (var fi = 0; fi < arr.length; fi++) {
        var f = arr[fi];
        if (!f || !f.value) continue;
        if (f.kind === 'host.hostname' || f.kind === 'host.fqdn' || f.kind === 'web.vhost') {
          var hv = String(f.value.hostname || f.value.fqdn || f.value.vhost || f.value.name || '').trim().toLowerCase();
          if (hv) knownTargetHosts[hv] = 1;
        }
      }
    }
    var hasKnownTarget = Object.keys(knownTargetHosts).length > 0;
    for (var hi = 0; hi < urlHosts.length; hi++) {
      var hName = urlHosts[hi];
      if (hName === '127.0.0.1' || hName === 'localhost' || hName === '::1' || hName === '0.0.0.0') return false;
      if (knownTargetHosts[hName]) return false;
      if (dom && hName.length > dom.length + 1 && hName.slice(-(dom.length + 1)) === '.' + dom) return false;
    }
    if (hasKnownTarget) return true;
    var promptLine = (ws && ws.context && ws.context.promptLine) || '';
    var hasTargetPrompt = !!(promptLine && !_is_attacker_prompt_string(promptLine) && (_parse_unix_prompt_line(promptLine, { isPromptCtx: true }) || /^\s*(?:PS\s+)?[A-Za-z]:\\[^>\r\n]*>/i.test(promptLine)));
    var isStagingTransfer = /\b(?:certutil\b[^\r\n]*-urlcache|bitsadmin\b[^\r\n]*\/transfer|curl\b[^\r\n]*(?:-[A-Za-z]*[oO]\b|--output\b|>\s*\S)|\b(?:iwr|invoke-webrequest)\b[^\r\n]*(?:-outfile|-o)\b)/i.test(cmd)
      || /(?:^|\r?\n)\s*Saving to:\s*[`'"]/i.test(t);
    return hasTargetPrompt || isStagingTransfer;
  }
  C._is_outbound_simplehttp_callback = _is_outbound_simplehttp_callback;

  function _match_verified_remote_unix_prompt(promptStr, callerPromptLine, opts) {
    if (!promptStr) return { matched: false };
    var allowSameHost = !!(opts && opts.allowSameHost);
    var isPromptCtx = !!(opts && opts.isPromptCtx);
    var callerParsed = callerPromptLine ? _parse_unix_prompt_line(String(callerPromptLine).split(/\r?\n/)[0], { isPromptCtx: true }) : null;
    var callerHostLow = (callerParsed && callerParsed.host) ? callerParsed.host.toLowerCase() : '';
    var callerUserLow = (callerParsed && callerParsed.user) ? callerParsed.user.toLowerCase() : '';
    var callerSigil = (callerParsed && callerParsed.sigil) || '';
    var lines = String(promptStr).split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var p = _parse_unix_prompt_line(lines[i], { isPromptCtx: isPromptCtx });
      if (!p) continue;
      if (p.host && _ATTACKER_PROMPT_ENTITY_RE.test(p.host)) continue;
      if (p.user && _ATTACKER_PROMPT_ENTITY_RE.test(p.user)) continue;
      if (!p.isBareSh) {
        if (!allowSameHost && callerHostLow && p.host.toLowerCase() === callerHostLow) continue;
        if (allowSameHost && callerHostLow && p.host.toLowerCase() === callerHostLow
            && callerUserLow === p.user.toLowerCase() && callerSigil === p.sigil) continue;
      }
      var isRoot = p.sigil === '#' || (p.user && p.user.toLowerCase() === 'root');
      return { matched: true, user: p.user || '', host: p.host || '', sigil: p.sigil, isRoot: !!isRoot, raw: p.raw };
    }
    return { matched: false };
  }

  function _emit_echoed_ssh_password(text, fallbackUser, h, source, facts) {
    if (!text) return;
    var pm = /^\s*([^\s:'"@]+)@[A-Za-z0-9_.-]+'s\s+password:\s*([^\s\r\n]{3,128})\s*$/im.exec(text);
    if (!pm) return;
    var u = C._clean_username ? C._clean_username(pm[1]) : pm[1].trim();
    if (!u && fallbackUser) u = fallbackUser;
    var pw = pm[2].trim().replace(/^(['"])(.*)\1$/, '$2').trim();
    if (!u || !pw) return;
    if (C._valid_password && !C._valid_password(pw)) return;
    if (/^(?:<[^>]+>|\[[^\]]+\]|\{[^}]+\}|\*+|\.+|-+|redacted|hidden|masked|Permission|Welcome|Last|Linux|Ubuntu|Debian|Warning|Error)$/i.test(pw)) return;
    var cVal = { user: u, password: pw, service: 'ssh', secret_type: 'plaintext', via: 'ssh-password-prompt' };
    _add(facts, mkFact('credential.candidate', h, cVal, S, source));
    _add(facts, mkFact('credential.plaintext', h, cVal, S, source));
    _add(facts, mkFact('credential.available', h, cVal, S, source));
  }

  function _extract_ssh_cmd_user(command) {
    if (!command) return '';
    var uArg = C._command_arg ? C._command_arg(command, ['-l']) : '';
    if (uArg) return C._clean_username(uArg);
    var m = /(?:^|\s)['"]?(?:[A-Za-z0-9_.-]+\\)?([A-Za-z0-9_.$-]+)@[A-Za-z0-9_.-]+/.exec(command);
    return m && m[1] ? C._clean_username(m[1]) : '';
  }

  function _count_distinct_linux_uids(text) {
    if (!text || text.indexOf('uid=') < 0) return 0;
    var seen = Object.create(null), count = 0;
    reAll(C._LINUX_ID_RE, text).forEach(function (mm) {
      var u = mm.groups && mm.groups.uid;
      if (u !== undefined && !seen[u]) { seen[u] = 1; count++; }
    });
    return count;
  }

  function _parse_ssh_exec(text, ws, command, source, facts) {
    if (_is_local_enum_report(text, command)) return;
    var isMultiUidDump = _count_distinct_linux_uids(text) >= 2
      || /All users\s*&\s*groups/i.test(text || '')
      || /^\s*id\s+(?:-[A-Za-z]+\s+)*root\s*$/i.test(command || '');
    var h = 'host:' + ws.target;
    var cs = ((command || '') + ' ' + (source || '')).toLowerCase();
    var isSshCmd = (C._is_ssh_command && C._is_ssh_command(command || '')) || /\bssh\b/.test(cs);
    if (!isSshCmd && _is_attacker_local_turn(ws, command, text)) return;
    if (isMultiUidDump && !isSshCmd) return;
    var m = isMultiUidDump ? null : reSearch(C._LINUX_ID_RE, text || '');
    if (!m) {
      if (!isSshCmd || _SSH_EXEC_FAIL_RE.test(text || '') || _SSH_USAGE_NOISE_RE.test(text || '')) return;
      var welcomeM = _SSH_POSTAUTH_WELCOME_RE.exec(text || '');
      var lastLoginM = _SSH_POSTAUTH_LASTLOGIN_RE.exec(text || '');
      var restrictedM = _SSH_RESTRICTED_BANNER_RE.exec(text || '');
      var callerPrompt = (ws && ws.context && ws.context.promptLine) || '';
      var followPrompt = (ws && ws.context && ws.context.followPrompt) || '';
      var inBodyPrompt = _match_verified_remote_unix_prompt(text || '', callerPrompt);
      var followPromptMatch = _match_verified_remote_unix_prompt(followPrompt, callerPrompt, { isPromptCtx: true });
      var landedPrompt = followPromptMatch.matched ? followPromptMatch : inBodyPrompt;
      if (!landedPrompt.matched && (welcomeM || lastLoginM)) {
        var fpClean = String(followPrompt || '').replace(C._ANSI_RE || /\x1b\[[0-9;?]*[ -/]*[@-~]/g, '').trim();
        var bodyLines = String(text || '').replace(C._ANSI_RE || /\x1b\[[0-9;?]*[ -/]*[@-~]/g, '').split(/\r?\n/);
        var lastBodyLine = '';
        for (var bli = bodyLines.length - 1; bli >= 0; bli--) {
          if (bodyLines[bli].trim()) { lastBodyLine = bodyLines[bli].trim(); break; }
        }
        var bareSigM = /^([#$])(?:\s+(?:id|whoami|pwd|ls|uname|cat|sh|bash|su|sudo|cd|find)\b.*)?$/.exec(fpClean)
          || /^([#$])$/.exec(lastBodyLine);
        if (bareSigM) {
          landedPrompt = { matched: true, user: bareSigM[1] === '#' ? 'root' : '', host: '', sigil: bareSigM[1], isRoot: bareSigM[1] === '#', raw: bareSigM[0] };
        }
      }
      var hasVerifiedLanding = landedPrompt.matched;
      if (!restrictedM && !((welcomeM || lastLoginM) && hasVerifiedLanding) && !hasVerifiedLanding) return;
      var sshUser = _extract_ssh_cmd_user(command) || (landedPrompt.matched ? landedPrompt.user : '');
      _emit_echoed_ssh_password(text, sshUser, h, source, facts);
      var authVal = { service: 'ssh', tool: 'ssh' };
      if (sshUser) authVal.user = sshUser;
      _add(facts, mkFact('ssh.authenticated', h, authVal, S, source));
      _add(facts, mkFact('access.shell', h, { service: 'ssh' }, S, source));
      var fhVal = { service: 'ssh' };
      if (sshUser) fhVal.identity = sshUser;
      _add(facts, mkFact('foothold.linux', h, fhVal, S, source));
      var osEvidence = (restrictedM || welcomeM || lastLoginM)
        ? (restrictedM || welcomeM || lastLoginM)[0].trim()
        : (landedPrompt.raw || 'SSH remote Unix shell prompt');
      C._add_os_observation(facts, ws, source, 'linux', osEvidence, 'high', 'ssh', true);
      if (restrictedM) {
        var rVal = { service: 'ssh', shell: 'restricted', stage: 'authorization', via: 'ssh-banner' };
        if (sshUser) rVal.user = sshUser;
        _add(facts, mkFact('blocker.account_restricted', h, rVal, S, source));
      } else if ((sshUser && sshUser.toLowerCase() === 'root') || (landedPrompt.matched && landedPrompt.isRoot)) {
        _add(facts, mkFact('access.admin', h, { service: 'ssh', identity: 'root', uid: 0 }, S, source));
        _add(facts, mkFact('access.root', h, { method: 'ssh' }, S, source));
      }
      return;
    }
    var user = m.groups.user.trim();
    var svc = isSshCmd ? 'ssh' : 'shell';
    if (cs.indexOf('psql') >= 0 || cs.indexOf('postgres') >= 0) svc = 'postgresql';
    else if (cs.indexOf('elastic') >= 0) svc = 'elasticsearch';
    else if (cs.indexOf('rsync') >= 0) svc = 'rsync';
    else if (cs.indexOf('nfs') >= 0) svc = 'nfs';
    else if (cs.indexOf('tftp') >= 0) svc = 'tftp';
    else if (cs.indexOf('vnc') >= 0) svc = 'vnc';
    if (svc === 'ssh') {
      _emit_echoed_ssh_password(text, user, h, source, facts);
      _add(facts, mkFact('ssh.authenticated', h, { service: 'ssh', user: user, tool: 'ssh' }, S, source));
    }
    _add(facts, mkFact('access.shell', h, { service: svc }, S, source));
    _add(facts, mkFact('foothold.linux', h, { service: svc, identity: user }, S, source));
    C._add_os_observation(facts, ws, source, 'linux', m[0], 'high', svc, true);
    if (_SSH_RESTRICTED_BANNER_RE.test(text || '')) {
      _add(facts, mkFact('blocker.account_restricted', h, { service: svc, shell: 'restricted', user: user, stage: 'authorization', via: 'ssh-banner' }, S, source));
    }
    if (m.groups.uid === '0' || (m.groups.euid && m.groups.euid === '0') || /\beuid=0\(root\)/i.test(text)) {
      _add(facts, mkFact('access.admin', h, { service: svc, identity: user, uid: 0 }, S, source));
      _add(facts, mkFact('access.root', h, { method: 'shell' }, S, source));
    }
  }
  C._parse_ssh_exec = _parse_ssh_exec;

  // SSH key login FAILED - the cryptic errors OffSec lab authors lean on to stall people who do not know
  // the trick. Recognize each cause from the pasted client output and mint ssh.key_rejected (carrying the
  // cause) so the troubleshooter move surfaces the exact fix. Conservative: a successful login (uid= in
  // the same paste) mints nothing here.
  var _SSH_KEY_CAUSES = [
    { cause: 'unprotected', re: /UNPROTECTED PRIVATE KEY FILE|permissions\s+0?\d{3,4}\s+for\s+.*are too open|bad permissions|it is required that your private key files are NOT accessible/i },
    { cause: 'passphrase', re: /enter passphrase for key|load key.*incorrect passphrase|bad passphrase/i },
    { cause: 'legacy_algo', re: /no mutual signature (?:algorithm|supported)|send_pubkey_test:\s*no mutual|sign_and_send_pubkey:\s*signing failed|userauth_pubkey:\s*unsupported public key algorithm/i },
    { cause: 'bad_format', re: /Load key .*:\s*(?:invalid format|error in libcrypto)|Load key .*:\s*format not supported|key_load_private/i },
    { cause: 'publickey_denied', re: /Permission denied\s*\(publickey/i },
  ];
  function _parse_ssh_key_diagnostics(text, ws, source, facts) {
    var t = String(text || '');
    if (reSearch(C._LINUX_ID_RE, t)) return;                 // a uid= line means it actually logged in
    var causes = [];
    _SSH_KEY_CAUSES.forEach(function (c) { if (c.re.test(t)) causes.push(c.cause); });
    if (!causes.length) return;
    _add(facts, mkFact('ssh.key_rejected', 'host:' + ws.target, { cause: causes[0], causes: causes }, S, source));
  }
  C._parse_ssh_key_diagnostics = _parse_ssh_key_diagnostics;

  function _parse_nxc_rdp(text, ws, command, source, facts) {
    if (text.indexOf('[+]') < 0) return;
    var plusLineM = /^\s*RDP\s+(\S+)\s+(\d+)\s+\S+\s+\[\+\]\s*(.*)$/im.exec(text);
    var h = 'host:' + ws.target;
    var user = C._command_arg(command, ['-u', '--user', '--username']);
    var domain = C._command_arg(command, ['-d', '--domain']) || '';
    if (plusLineM && plusLineM[3]) {
      var credTail = plusLineM[3].replace(/(?:[ \t]+\([^)\r\n]*\))+[ \t]*$/, '').trim();
      var domUserM = /^(?:([^\\:\s]+)\\)?([^:\s(]+):/.exec(credTail);
      if (domUserM) {
        if (!domain && domUserM[1]) domain = domUserM[1].trim();
        if (!user && domUserM[2]) user = domUserM[2].trim();
      }
    }
    var cleanUser = user ? C._clean_username(user) : '';
    var value = { service: 'rdp', tool: 'nxc' };
    if (cleanUser) value.user = cleanUser;
    if (domain) value.domain = domain;
    var obs = Object.assign({}, value, { outcome: 'accepted' });
    if (C._auth_observation) obs = C._auth_observation(ws, obs);
    delete obs.password; delete obs.nthash;
    _add(facts, mkFact('rdp.authenticated', h, value, S, source));
    _add(facts, mkFact('credential.validated', h, obs, S, source));
    C._add_os_observation(facts, ws, source, 'windows', 'nxc rdp authentication succeeded', 'high', 'nxc', true);

    var requestedExec = /(?:^|\s)-[xX]\s+\S/.test(command || '');
    var nonBannerOut = String(text || '').split(/\r?\n/).filter(function (ln) {
      var tr = ln.trim();
      if (!tr) return false;
      if (/^\s*RDP\s+\S+\s+\d+\s+\S+\s+\[[*+-]\]/i.test(tr) && !/\[\+\]\s*Executed command/i.test(tr)) return false;
      return true;
    });
    var hasExecOutput = requestedExec && (/\[\+\]\s*Executed command/i.test(text) || nonBannerOut.length > 0 || (C._WHOAMI_ID_RE && C._WHOAMI_ID_RE.test(text)));
    if (hasExecOutput) {
      var foothold = { method: 'rdp' };
      if (cleanUser) foothold.identity = cleanUser;
      _add(facts, mkFact('foothold.windows', h, foothold, S, source));
      if (C._WHOAMI_ID_RE && C._WHOAMI_ID_RE.test(text)) {
        _parse_command_execution(text, ws, command, source, facts);
      }
    }
    if (/\(Pwn3d!\)/i.test(text) || (hasExecOutput && cleanUser && cleanUser.toLowerCase() === 'administrator')) {
      _add(facts, mkFact('access.admin', h, { service: 'rdp' }, S, source));
    }
  }
  C._parse_nxc_rdp = _parse_nxc_rdp;

  var _FREERDP_FAIL_RE = /\b(?:ERRCONNECT_(?:LOGON_FAILURE|AUTHENTICATION_FAILED|PASSWORD_EXPIRED|PASSWORD_MUST_CHANGE|ACCOUNT_DISABLED|ACCOUNT_LOCKED_OUT|CONNECT_TRANSPORT_FAILED)|STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED|Authentication failure|unable to connect to|connectError)\b/i;

  function _parse_xfreerdp(text, ws, command, source, facts) {
    var t = String(text || '');
    if (_FREERDP_FAIL_RE.test(t)) return;
    var logonM = /Logon Info V\d+\s*\[([^\]]+)\]/i.exec(t);
    var authOnlyOk = /Authentication only,\s*exit status 0\b/i.test(t);
    var freerdpV2Ok = /Remote framebuffer format PIXEL_FORMAT_|Loading Dynamic Virtual Channel rdpgfx/i.test(t);
    if (!logonM && !authOnlyOk && !freerdpV2Ok) return;
    var h = 'host:' + ws.target;
    var user = '';
    if (logonM && logonM[1]) {
      var rawIdent = logonM[1].replace(/\s*\(\d+\)\s*$/, '').trim();
      user = C._clean_username ? C._clean_username(rawIdent) : rawIdent.split(/[\\/]/).pop();
    }
    if (!user && command) {
      var uM = /\/u:(?:'([^']+)'|"([^"]+)"|(\S+))/i.exec(command);
      if (uM) user = C._clean_username ? C._clean_username(uM[1] || uM[2] || uM[3]) : (uM[1] || uM[2] || uM[3]);
    }
    var value = { service: 'rdp', tool: 'xfreerdp' };
    if (user) value.user = user;
    var isAdmin = !!(user && /^administrator$/i.test(user));
    _add(facts, mkFact('port:3389', h, { port: 3389, protocol: 'tcp', service: 'ms-wbt-server', state: 'open' }, S, source));
    _add(facts, mkFact('rdp.reachable', h, { port: 3389, tool: 'xfreerdp' }, S, source));
    _add(facts, mkFact('rdp.authenticated', h, value, S, source));
    if (!authOnlyOk) {
      var foothold = { method: 'rdp' };
      if (user) foothold.identity = user;
      _add(facts, mkFact('foothold.windows', h, foothold, S, source));
      _add(facts, mkFact('access.desktop', h, { session: 'xfreerdp', user: user || '', admin: isAdmin }, S, source));
    }
    if (isAdmin) _add(facts, mkFact('access.admin', h, { service: 'rdp', identity: user, method: 'xfreerdp' }, S, source));
    C._add_os_observation(facts, ws, source, 'windows', 'xfreerdp interactive login succeeded', 'high', 'xfreerdp', true);
  }
  C._parse_xfreerdp = _parse_xfreerdp;

  function _parse_penelope(text, ws, source, facts) {
    var got = reSearch(C._PENELOPE_GOT_RE, text);
    var upgraded = !!reSearch(C._PENELOPE_UPGRADE_RE, text);
    if (!got && !upgraded) return;
    var h = 'host:' + ws.target;
    var info = got ? got.groups.info.trim() : '';
    var haystack = (info + '\n' + text).toLowerCase();
    var osName = haystack.indexOf('windows') >= 0 ? 'windows' : (haystack.indexOf('linux') >= 0 ? 'linux' : '');
    var value = { handler: 'penelope' };
    if (osName) value.os = osName;
    var sid = reSearch(C._PENELOPE_SID_RE, text);
    if (sid) value.session_id = sid.groups.sid;
    var hostm = reSearch(C._PENELOPE_HOST_RE, info);
    if (hostm) { value.hostname = hostm.groups.host; value.source_ip = hostm.groups.ip; }
    _add(facts, mkFact('access.shell', h, value, S, source));
    if (osName === 'windows') {
      C._add_os_observation(facts, ws, source, 'windows', info || 'penelope reported Windows shell', 'high', 'penelope', true);
      _add(facts, mkFact('foothold.windows', h, { method: 'penelope' }, S, source));
      _add(facts, mkFact('access.desktop', h, { session: 'penelope' }, S, source));
    } else if (osName === 'linux') {
      C._add_os_observation(facts, ws, source, 'linux', info || 'penelope reported Linux shell', 'high', 'penelope', true);
      _add(facts, mkFact('foothold.linux', h, { method: 'penelope' }, S, source));
    }
  }
  C._parse_penelope = _parse_penelope;

  function _resolve_active_linux_principal(text, ws, facts) {
    if (text) {
      var sudoUserM = /\bUser\s+([A-Za-z_][A-Za-z0-9_.-]{0,31})\s+may run the following commands/i.exec(text);
      if (sudoUserM && sudoUserM[1] && sudoUserM[1].toLowerCase() !== 'root') return sudoUserM[1];
    }
    var promptLine = ws && ws.context && ws.context.promptLine;
    if (promptLine && typeof _parse_unix_prompt_line === 'function') {
      var pObj = _parse_unix_prompt_line(String(promptLine).split(/\r?\n/)[0]);
      if (pObj && pObj.user && pObj.user.toLowerCase() !== 'root'
          && !_ATTACKER_PROMPT_ENTITY_RE.test(pObj.user)
          && (!pObj.host || !_ATTACKER_PROMPT_ENTITY_RE.test(pObj.host))) {
        return pObj.user;
      }
    }
    if (text && C._LINUX_ID_RE) {
      var allIdx = text.search(/All users\s*&\s*groups/i);
      var idScope = allIdx > 0 ? text.slice(0, allIdx) : text;
      var idMs = reAll(C._LINUX_ID_RE, idScope);
      var nonRootIds = [];
      for (var ii = 0; ii < idMs.length; ii++) {
        var iu = (idMs[ii].groups && idMs[ii].groups.user ? idMs[ii].groups.user : '').trim();
        if (iu && iu.toLowerCase() !== 'root' && !_ATTACKER_PROMPT_ENTITY_RE.test(iu) && nonRootIds.indexOf(iu) < 0) {
          nonRootIds.push(iu);
        }
      }
      if (nonRootIds.length === 1) return nonRootIds[0];
    }
    var pools = [facts || [], (ws && ws.facts) || [], (ws && ws.seedFacts) || []];
    for (var pi = 0; pi < pools.length; pi++) {
      var arr = pools[pi];
      if (!Array.isArray(arr)) continue;
      for (var fi = arr.length - 1; fi >= 0; fi--) {
        var f = arr[fi];
        if (!f || !f.value) continue;
        if (f.kind === 'foothold.linux' && f.value.identity && String(f.value.identity).toLowerCase() !== 'root') {
          return String(f.value.identity);
        }
        if (f.kind === 'access.shell' && f.value.os === 'linux' && f.value.user && String(f.value.user).toLowerCase() !== 'root') {
          return String(f.value.user);
        }
      }
    }
    return '';
  }

  function _add_host_privesc_fact(facts, ws, source, kind, value, leadKinds) {
    _add(facts, mkFact(kind, 'host:' + ws.target, value, S, source));
    if (kind.indexOf('privesc.') === 0 && kind !== 'privesc.leads') leadKinds[kind] = true;
  }
  function _add_privesc_leads(facts, ws, source, leadKinds) {
    var kinds = Object.keys(leadKinds);
    if (!kinds.length) return;
    kinds.sort();
    var val = { kinds: kinds, count: kinds.length };
    if (leadKinds && leadKinds._principal) val.principal = leadKinds._principal;
    _add(facts, mkFact('privesc.leads', 'host:' + ws.target, val, S, source));
  }

  var _GTFOBINS_SUDO = {
    vi: 'vi', vim: 'vim', nano: 'nano', pico: 'pico', less: 'less', more: 'more', man: 'man', awk: 'awk', gawk: 'gawk',
    sed: 'sed', ed: 'ed', find: 'find', nmap: 'nmap', python: 'python', python2: 'python', python3: 'python',
    perl: 'perl', ruby: 'ruby', php: 'php', lua: 'lua', node: 'node', bash: 'bash', sh: 'sh', zsh: 'zsh',
    ash: 'ash', csh: 'csh', ksh: 'ksh', busybox: 'busybox',
    env: 'env', docker: 'docker', tar: 'tar', zip: 'zip', git: 'git', ftp: 'ftp', gdb: 'gdb', make: 'make',
    strace: 'strace', ltrace: 'ltrace',
    cp: 'cp', mv: 'mv', dd: 'dd', tee: 'tee', chmod: 'chmod', chown: 'chown',
    wget: 'wget', curl: 'curl', aria2c: 'aria2c', ssh: 'ssh', scp: 'scp', rsync: 'rsync',
    socat: 'socat', nc: 'nc', tcpdump: 'tcpdump', openssl: 'openssl', mysql: 'mysql', psql: 'psql', sqlite3: 'sqlite3',
    systemctl: 'systemctl', journalctl: 'journalctl', service: 'service',
    apt: 'apt', 'apt-get': 'apt-get', yum: 'yum', dnf: 'dnf', pip: 'pip', pip3: 'pip', npm: 'npm', composer: 'composer',
    screen: 'screen', tmux: 'tmux', xargs: 'xargs', cat: 'cat', base64: 'base64', cut: 'cut', flock: 'flock',
    apache2: 'apache2', nginx: 'nginx', openvpn: 'openvpn', capsh: 'capsh', setarch: 'setarch', time: 'time', timeout: 'timeout',
    watch: 'watch', expect: 'expect', ionice: 'ionice', nice: 'nice', nohup: 'nohup', stdbuf: 'stdbuf',
    taskset: 'taskset', chroot: 'chroot', nsenter: 'nsenter', unshare: 'unshare', doas: 'doas',
    'ansible-playbook': 'ansible-playbook', logrotate: 'logrotate', borg: 'borg', restic: 'restic'
  };

  function _normalize_gtfobin(base) {
    base = String(base || '').toLowerCase();
    if (_GTFOBINS_SUDO[base]) return _GTFOBINS_SUDO[base];
    var stripped = base.replace(/\.(?:basic|tiny|nox|gtk3?|athena|orig|distrib)$/i, '').replace(/[0-9.]+$/, '');
    if (_GTFOBINS_SUDO[stripped]) return _GTFOBINS_SUDO[stripped];
    return '';
  }

  var _STOCK_SUID_BINS = new Set([
    'passwd', 'su', 'sudo', 'sudoedit', 'mount', 'umount', 'chsh', 'chfn', 'newgrp', 'gpasswd',
    'fusermount', 'fusermount3', 'pkexec', 'polkit-agent-helper-1', 'ssh-keysign',
    'dbus-daemon-launch-helper', 'unix_chkpwd', 'chage', 'expiry', 'ping', 'ping6',
    'traceroute6.iputils', 'pppd', 'ntfs-3g', 'xorg.wrap', 'x', 'xorg', 'lppasswd', 'mtr', 'uuidd',
    'snap-confine', 'snap-device-helper', 'bwrap',
    'mount.cifs', 'mount.nfs', 'umount.nfs', 'at', 'crontab', 'pam_timestamp_check', 'pt_chown',
    'halt', 'reboot', 'poweroff', 'shutdown', 'telinit', 'runlevel', 'wall', 'write',
    'usernetctl', 'userhelper', 'grub2-set-bootflag',
    'ssh-agent', 'bsd-write', 'mlocate', 'plocate', 'locate', 'slocate',
    'dotlockfile', 'dotlock.mailutils', 'mail-lock', 'mail-unlock', 'mail-touchlock',
    'lockfile', 'lockfile.procmail', 'mutt_dotlock', 'pam_extrausers_chkpwd',
    'postdrop', 'postqueue', 'utempter', 'camel-lock-helper-1.2', 'netreport'
  ]);
  var _STOCK_SNAP_RUNTIME_RE = /^\/snap\/(?:core\d*|snapd|bare|gtk-common-themes|gnome-[^/]+)\//i;

  function _is_stock_suid(p) {
    var s = String(p || '').trim();
    if (_STOCK_SNAP_RUNTIME_RE.test(s)) return true;
    var base = s.split('/').pop().toLowerCase();
    if (base === 'sudoedit') return false;
    return _STOCK_SUID_BINS.has(base) && /^\/(?:usr\/)?(?:bin|sbin|lib|lib64|libexec)\//i.test(s);
  }
  C._is_stock_suid = _is_stock_suid;

  function _is_stock_sgid_ls_line(line, p) {
    if (/^-[rwx-]{2}[sS]/.test(line)) return false;
    var s = String(p || '').trim();
    if (/^\/usr\/games\//i.test(s)) return true;
    if (/^\/(?:usr\/)?bin\/screen$/i.test(s) && /^\S+\s+\d+\s+\S+\s+utmp\b/i.test(line)) return true;
    return false;
  }

  var _STOCK_LINUX_BINS_RE = /^(?:systemd(?:-[a-z0-9_-]+)?|init|halt|reboot|poweroff|shutdown|telinit|runlevel|systemctl|service|journalctl|kthreadd|kworker|ksoftirqd|migration|rcu_[a-z_]+|watchdog|dbus-daemon|dbus-broker|sshd|cron|crond|atd|anacron|rsyslogd|syslogd|journald|udevd|NetworkManager|wpa_supplicant|dhclient|dhcpcd|ntpd|chronyd|timesyncd|irqbalance|acpid|polkitd|accounts-daemon|udisksd|upowerd|ModemManager|avahi-daemon|cupsd|lppasswd|mtr|uuidd|pt_chown|pppd|chage|expiry|unix_chkpwd|pam_timestamp_check|sudoedit|thermald|snapd|containerd|containerd-shim[^\s]*|dockerd|kubelet|agetty|getty|login|auditd|multipathd|lvmetad|lvm|mdadm|smartd|postfix|master|qmgr|pickup|tlsmgr|dovecot|exim4?|mysqld|mariadbd|postgres|postmaster|redis-server|memcached|mongod|nginx|apache2|httpd|lighttpd|php-fpm[0-9.]*|smbd|nmbd|winbindd|rpcbind|rpc\.[a-z0-9_-]+|nfsd|named|dnsmasq|unbound|X|Xorg|Xwayland|gdm[0-9-]*|lightdm|VBoxService|VBoxClient|vmtoolsd|VGAuthService|qemu-ga|hv_[a-z0-9_]+|cloud-init|unattended-upgrade[a-z-]*|apt|apt-get|dpkg|yum|dnf|rpm|logrotate|run-parts|test|\[|true|false|echo|printf|sleep|date|uname|hostname|id|whoami|groups|ls|dir|vdir|grep|egrep|fgrep|rg|wc|sort|uniq|head|tail|tr|cut|paste|join|split|stat|readlink|realpath|dirname|basename|which|whereis|file|strings|ldd|objdump|readelf|nm|strip|ip|ifconfig|netstat|ss|route|arp|ping|ping6|ps|top|htop|kill|pkill|pgrep|df|du|free|lsblk|blkid|fdisk|mount|umount|mkfs(?:\.[a-z0-9]+)?|fsck(?:\.[a-z0-9]+)?|e2scrub[a-z_]*|fstrim|wall|write|mesg|screen(?:-4\.[0-9.]+)?|linpeas(?:\.sh)?|pspy(?:32|64)?(?:s)?|les\.sh|linux-exploit-suggester(?:\.sh)?|chisel|ligolo[a-z0-9_-]*|agent)$/i;

  var _LINUX_CUSTOM_DIR_RE = /^\/(?:opt|usr\/local|srv|var\/backups|home|root|var\/tmp|tmp|dev\/shm|var\/www)\//i;
  var _NON_EXEC_EXT_RE = /\.(?:conf|cfg|ini|json|xml|ya?ml|txt|log|md|rst|csv|pid|sock|lock|service|timer|target|mount|socket|path|slice|scope|gz|bz2|xz|zst|zip|tar|tgz|bak|old|orig|swp|pem|crt|cer|key|pub|db|sqlite3?|sql|html?|css|png|jpe?g|gif|svg|ico|pdf)$/i;

  var _THIRD_PARTY_SUDO_BINS = { borg: 1, restic: 1, 'ansible-playbook': 1, composer: 1 };

  function _check_linux_custom_binary(rawPath) {
    var p = String(rawPath || '').trim().replace(/^['"]+|['",;)]+$/g, '');
    if (!p || p.charAt(0) !== '/' || p.slice(-1) === '/') return null;
    if (!/^\/[A-Za-z_][A-Za-z0-9._-]*\/.+/.test(p)) return null;
    if (_STOCK_SNAP_RUNTIME_RE.test(p)) return null;
    if (/^\/(?:proc|sys|dev\/(?!shm\/)|run|etc\/(?:passwd|shadow|group|hosts|fstab|crontab|sudoers|resolv\.conf|issue|motd)|var\/log|var\/lib|var\/spool|var\/cache|var\/run)\b/i.test(p)) return null;
    var base = p.split('/').pop();
    if (!base || base === '.' || base === '..' || base.indexOf('*') >= 0) return null;
    if (_NON_EXEC_EXT_RE.test(base)) return null;
    var lowBase = base.toLowerCase();
    var inCustomDir = _LINUX_CUSTOM_DIR_RE.test(p);
    if (!inCustomDir && _STOCK_SUID_BINS.has(lowBase)) return null;
    if (!inCustomDir && !_THIRD_PARTY_SUDO_BINS[lowBase] && _normalize_gtfobin(lowBase)) return null;
    if (!inCustomDir && _STOCK_LINUX_BINS_RE.test(lowBase)) return null;
    if (inCustomDir && /^(?:linpeas|pspy|les\.sh|linux-exploit-suggester|chisel|agent)/i.test(lowBase)) return null;
    if (!inCustomDir && /^\/(?:lib|lib64|usr\/lib|usr\/lib64|usr\/share)\//i.test(p)) return null;
    return { path: p, binary: base };
  }

  var _WIN_STOCK_PATH_RE = /^[A-Za-z]:\\(?:Windows\\|(?:Program Files(?: \(x86\))?|ProgramData)\\(?:Windows Defender(?: Advanced Threat Protection)?|Windows Mail|Windows Media Player|Windows NT|Windows Photo Viewer|Windows Portable Devices|Windows Security|Windows Sidebar|WindowsPowerShell|PowerShell|Microsoft(?:\b|\s|\.)[^\\]*|Common Files\\Microsoft Shared|Internet Explorer|MSBuild|Reference Assemblies|dotnet|PackageManagement|VMware\\VMware Tools|Oracle\\VirtualBox Guest Additions|Amazon\\(?:EC2ConfigService|SSM|Xen|PV Drivers)|Google\\Compute Engine|QEMU-GA|Cloudbase Solutions)\\)/i;
  var _WIN_TOOL_IGNORE_RE = /(?:^|\\)(?:winpeas[A-Za-z0-9_-]*|privesccheck|seatbelt|sharphound|rubeus|mimikatz|accesschk(?:64)?|procdump(?:64)?|godpotato|printspoofer|juicypotato|sweetpotato|roguepotato|efspotato|nc(?:64)?|chisel|plink|agent)\.(?:exe|ps1|bat)$/i;

  function _check_windows_custom_binary(rawLine) {
    var s = String(rawLine || '').trim();
    if (!s) return null;
    var matches = reAll(/(?:"([A-Za-z]:\\[^"\r\n|<>?*]+?\.(?:exe|bat|cmd|ps1|vbs|jar))"|'([A-Za-z]:\\[^'\r\n|<>?*]+?\.(?:exe|bat|cmd|ps1|vbs|jar))'|([A-Za-z]:\\(?:[^"\r\n|<>?*:\s]+\\)*[^"\r\n|<>?*:\\]+?\.(?:exe|bat|cmd|ps1|vbs|jar))\b)/gi, s);
    for (var i = 0; i < matches.length; i++) {
      var cand = (matches[i][1] || matches[i][2] || matches[i][3] || '').trim();
      if (!cand) continue;
      // If the outer launcher is cmd.exe / powershell.exe / wscript.exe / cscript.exe, continue to inspect the script argument
      if (/\\(?:cmd|powershell|pwsh|wscript|cscript|conhost|rundll32|regsvr32|msiexec|schtasks|sc)\.exe$/i.test(cand) && matches.length > i + 1) {
        continue;
      }
      if (_WIN_STOCK_PATH_RE.test(cand) || _WIN_TOOL_IGNORE_RE.test(cand)) continue;
      var bin = cand.split('\\').pop();
      return { path: cand, binary: bin };
    }
    return null;
  }

  var _USERSPACE_SUGGESTER_CVE_RE = /\b(?:CVE-2021-3156|baron\s+samedit|sudoedit|CVE-2021-4034|CVE-2021-3560|pwnkit|polkit|pkexec|CVE-2023-4911|looney\s+tunables|CVE-2019-7304|snapd|dirtysock)\b/i;

  function _parse_kernel_exploits(text, ws, command, source, facts, leadKinds) {
    var hits = [], cves = [], names = {};
    var kernelHits = [], kernelCves = [], kernelNames = {};
    var userspaceHits = [];
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      var cve = reSearch(C._CVE_RE, line);
      if (!cve) continue;
      if (reSearch(C._KERNEL_EXPLOIT_NEGATION_RE, line)) continue;
      var low = line.toLowerCase();
      var named = C._KERNEL_EXPLOIT_NAMES.filter(function (n) { return low.indexOf(n) >= 0; })[0] || '';
      var bracketed = low.indexOf('[cve-') >= 0;
      if (!(bracketed || named || reSearch(C._EXPLOIT_PROBABILITY_RE, line))) continue;
      var clipped = line.slice(0, 200);
      var cveUp = cve[0].toUpperCase();
      hits.push(clipped);
      cves.push(cveUp);
      if (named) names[named] = true;
      if (_USERSPACE_SUGGESTER_CVE_RE.test(line)) {
        userspaceHits.push(clipped);
      } else {
        kernelHits.push(clipped);
        kernelCves.push(cveUp);
        if (named) kernelNames[named] = true;
      }
      if (hits.length >= 20) break;
    }
    if (!hits.length) return;
    if (kernelHits.length > 0) {
      var value = { cves: C.uniqueSortedCI(cves), kernel_cves: C.uniqueSortedCI(kernelCves), evidence: hits, count: kernelHits.length };
      var nk = Object.keys(names);
      if (nk.length) value.names = nk.sort();
      _add_host_privesc_fact(facts, ws, source, 'privesc.kernel_exploit', value, leadKinds);
    }
    _add(facts, mkFact('exploit.candidate', 'host:' + ws.target, { tool: 'linux-exploit-suggester', cves: C.uniqueSortedCI(cves), findings: hits }, S, source));
    var h = 'host:' + ws.target;
    var cveSetStr = cves.join(',');
    if (names['dirtycow'] || names['dirty cow'] || cveSetStr.indexOf('CVE-2016-5195') >= 0) {
      _add(facts, mkFact('vuln.dirtycow', h, { cve: 'CVE-2016-5195', via: 'exploit-suggester', lead: true }, S, source));
    }
    if (names['dirtypipe'] || names['dirty pipe'] || cveSetStr.indexOf('CVE-2022-0847') >= 0) {
      _add(facts, mkFact('vuln.dirtypipe', h, { cve: 'CVE-2022-0847', via: 'exploit-suggester', lead: true }, S, source));
    }
    if (names['baron samedit'] || names['sudoedit'] || cveSetStr.indexOf('CVE-2021-3156') >= 0) {
      _add(facts, mkFact('vuln.baron_samedit', h, { cve: 'CVE-2021-3156', via: 'exploit-suggester', lead: true }, S, source));
      leadKinds['vuln.baron_samedit'] = true;
    }
    if (names['pwnkit'] || names['polkit'] || names['pkexec'] || cveSetStr.indexOf('CVE-2021-4034') >= 0) {
      _add(facts, mkFact('vuln.polkit', h, { cve: 'CVE-2021-4034', via: 'exploit-suggester', lead: true }, S, source));
      leadKinds['vuln.polkit'] = true;
    }
    if (userspaceHits.length > 0 && kernelHits.length === 0) {
      leadKinds['exploit.candidate'] = true;
    }
  }

  function _collect_known_owned_linux_users(ws, facts, callerPromptObj) {
    var owned = Object.create(null);
    if (callerPromptObj && callerPromptObj.user && !_ATTACKER_PROMPT_ENTITY_RE.test(callerPromptObj.user)
        && (!callerPromptObj.host || !_ATTACKER_PROMPT_ENTITY_RE.test(callerPromptObj.host))) {
      owned[callerPromptObj.user.toLowerCase()] = 1;
    }
    var pools = [facts || [], (ws && ws.facts) || [], (ws && ws.seedFacts) || []];
    for (var pi = 0; pi < pools.length; pi++) {
      var list = pools[pi];
      if (!Array.isArray(list)) continue;
      for (var i = 0; i < list.length; i++) {
        var f = list[i];
        if (!f || !f.value) continue;
        if (f.kind === 'foothold.linux' && f.value.identity) owned[String(f.value.identity).toLowerCase()] = 1;
        else if ((f.kind === 'ssh.authenticated' || f.kind === 'access.shell' || f.kind === 'credential.validated') && f.value.user) {
          owned[String(f.value.user).toLowerCase()] = 1;
        }
      }
    }
    return owned;
  }

  function _parse_linux_privesc_output(text, ws, command, source, facts, leadKinds) {
    if (_is_attacker_local_turn(ws, command, text)) return;
    var lowered = text.toLowerCase(), lc = (command || '').toLowerCase(), h = 'host:' + ws.target;
    var textNoPem = String(text || '').replace(/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g, '');
    var loweredNoPem = textNoPem.toLowerCase();
    var activePrincipal = _resolve_active_linux_principal(textNoPem, ws, facts);
    if (activePrincipal && leadKinds) {
      try { Object.defineProperty(leadKinds, '_principal', { value: activePrincipal, enumerable: false, writable: true, configurable: true }); } catch (_e) {}
    }

    function _emit_linux_priv_groups(groupsArr, userLabel, allowAdmVideo) {
      if (groupsArr.indexOf('lxd') >= 0 || groupsArr.indexOf('lxc') >= 0) {
        var lxdVal = { groups: groupsArr };
        if (userLabel) lxdVal.user = userLabel;
        _add_host_privesc_fact(facts, ws, source, 'privesc.lxd_group', lxdVal, leadKinds);
      }
      if (groupsArr.indexOf('docker') >= 0) {
        var docVal = { groups: groupsArr };
        if (userLabel) docVal.user = userLabel;
        _add_host_privesc_fact(facts, ws, source, 'privesc.docker_group', docVal, leadKinds);
      }
      var privMatches = groupsArr.filter(function (g) {
        return g === 'disk' || g === 'shadow' || (allowAdmVideo && (g === 'adm' || g === 'video'));
      });
      if (privMatches.length && (!userLabel || userLabel.toLowerCase() !== 'root')) {
        var pgVal = { groups: privMatches, os: 'linux' };
        if (userLabel) pgVal.user = userLabel;
        _add_host_privesc_fact(facts, ws, source, 'privesc.privileged_group', pgVal, leadKinds);
      }
    }

    var allIdMatches = reAll(C._LINUX_ID_RE, textNoPem);
    var distinctUidCount = _count_distinct_linux_uids(textNoPem);
    var isAllUsersTable = /All users\s*&\s*groups/i.test(textNoPem);
    var callerPromptObj = (ws && ws.context && ws.context.promptLine)
      ? _parse_unix_prompt_line(String(ws.context.promptLine).split(/\r?\n/)[0])
      : null;
    var isNonRootCallerDollarPrompt = !!(callerPromptObj && callerPromptObj.sigil === '$'
      && (!callerPromptObj.user || callerPromptObj.user.toLowerCase() !== 'root'));
    var explicitIdTargetM = /^\s*id\s+(?:-[A-Za-z]+\s+)*([A-Za-z_][A-Za-z0-9_.-]*)\s*$/i.exec(command || '');

    if (allIdMatches.length && (distinctUidCount >= 2 || isAllUsersTable)) {
      C._add_os_observation(facts, ws, source, 'linux', allIdMatches[0][0], 'high', 'local-enum', true);
      var ownedUsers = _collect_known_owned_linux_users(ws, facts, callerPromptObj);
      var hasAnyOwned = Object.keys(ownedUsers).length > 0;
      var allUsersSectionIdx = textNoPem.search(/All users\s*&\s*groups/i);
      var humanUsers = [];
      for (var imi = 0; imi < allIdMatches.length; imi++) {
        var im = allIdMatches[imi];
        var iu = im.groups.user.trim();
        var uidNum = parseInt(im.groups.uid, 10);
        var iLine = C._line_for_match(textNoPem, im) || im[0];
        var iGroups = C.uniqueSortedCI(reAll(/\d+\(([^)]+)\)/, iLine).map(function (gm) { return gm[1].toLowerCase(); }));
        if (uidNum >= 1000 && uidNum < 65534) humanUsers.push(iu);
        var hasEuidZero = (im.groups.euid && im.groups.euid === '0') || /\beuid=0\(root\)/i.test(iLine);
        var isPreAllUsersRoot = uidNum === 0 && allUsersSectionIdx > 0 && im.index < allUsersSectionIdx && !isNonRootCallerDollarPrompt;
        if ((uidNum !== 0 && hasEuidZero) || isPreAllUsersRoot || (uidNum === 0 && ownedUsers['root'] && !isNonRootCallerDollarPrompt)) {
          _add(facts, mkFact('access.admin', h, { identity: iu, uid: 0, method: 'local-enum' }, S, source));
          _add(facts, mkFact('access.root', h, { method: 'shell' }, S, source));
        }
        if (uidNum !== 0) {
          var isPreAllUsersUid = allUsersSectionIdx > 0 && im.index < allUsersSectionIdx;
          if (ownedUsers[iu.toLowerCase()] || isPreAllUsersUid) {
            _emit_linux_priv_groups(iGroups, iu, true);
          } else if (uidNum >= 1000 && uidNum < 65534) {
            _emit_linux_priv_groups(iGroups, iu, !hasAnyOwned);
          }
        }
      }
      if (humanUsers.length) {
        var uniqHumans = C.uniqueSortedCI(humanUsers);
        _add(facts, mkFact('host.users', h, { users: uniqHumans, count: uniqHumans.length, via: 'id-table' }, S, source));
      }
    } else if (allIdMatches.length === 1) {
      var idMatch = allIdMatches[0];
      var user = idMatch.groups.user.trim();
      C._add_os_observation(facts, ws, source, 'linux', idMatch[0], 'high', 'local-enum', true);
      var idLine = C._line_for_match(textNoPem, idMatch) || idMatch[0];
      var groups = C.uniqueSortedCI(reAll(/\d+\(([^)]+)\)/, idLine).map(function (m) { return m[1].toLowerCase(); }));
      var inspectedOtherUser = !!(explicitIdTargetM && isNonRootCallerDollarPrompt && callerPromptObj.user
        && explicitIdTargetM[1].toLowerCase() !== callerPromptObj.user.toLowerCase());
      if (!inspectedOtherUser || explicitIdTargetM[1].toLowerCase() !== 'root') {
        _emit_linux_priv_groups(groups, user, true);
      }
      var hasExplicitEuidZero = (idMatch.groups.euid && idMatch.groups.euid === '0') || /\beuid=0\(root\)/i.test(idLine);
      var canMintRootFromSingleId = !inspectedOtherUser && (
        hasExplicitEuidZero
        || (idMatch.groups.uid === '0' && !(_is_local_enum_report(text, command) && isNonRootCallerDollarPrompt))
      );
      if (canMintRootFromSingleId) {
        _add(facts, mkFact('access.admin', h, { identity: user, uid: 0, method: 'local-enum' }, S, source));
        _add(facts, mkFact('access.root', h, { method: 'shell' }, S, source));
      }
    } else if (lc.indexOf('whoami') >= 0 && /(?:^|\n)\s*root\s*(?:\n|$)/i.test(textNoPem)) {
      _add(facts, mkFact('access.admin', h, { identity: 'root', method: 'whoami' }, S, source));
      _add(facts, mkFact('access.root', h, { method: 'shell' }, S, source));
    } else if (/\bgroups\b/i.test(lc)) {
      var bareGroups = C.uniqueSortedCI((textNoPem.match(/\b(?:docker|lxd|lxc|disk|adm|shadow|video)\b/gi) || []).map(function (g) { return g.toLowerCase(); }));
      _emit_linux_priv_groups(bareGroups, '', true);
    }

    var uname = reSearch(C._UNAME_RE, textNoPem);
    if (uname) {
      _add_host_privesc_fact(facts, ws, source, 'host.kernel', { kernel: uname.groups.kernel, tool: 'uname', evidence: uname[0].trim().slice(0, 220) }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'host.arch', { arch: uname.groups.arch, tool: 'uname' }, leadKinds);
      C._add_os_observation(facts, ws, source, 'linux', uname[0], 'high', 'uname', true, C._os_product_from_label(textNoPem, 'linux'));
      if (C._check_linux_kernel_vulns) C._check_linux_kernel_vulns(uname.groups.kernel, ws, source, facts, leadKinds);
    } else {
      var procVer = /Linux version\s+([0-9][^\s]+)/i.exec(textNoPem)
        || /\bKernel\s+version\s*:\s*([2-6]\.\d+(?:\.\d+)?[^\s\r\n]*)/i.exec(textNoPem)
        || /\bKernel:\s*(?:Linux\s+)?([2-6]\.\d+\.\d+-[0-9A-Za-z.+_-]+)/i.exec(textNoPem);
      var bareKernel = /^\s*([2-6]\.\d+\.\d+-[0-9A-Za-z.+_-]+)\s*$/m.exec(textNoPem);
      var kMatch = procVer || ((lc.indexOf('uname') >= 0 || (bareKernel && /(?:generic|amd64|i[3-6]86|arm64|el\d|kali|debian|ubuntu|arch|alpine|-\d+-)/i.test(bareKernel[1]))) ? bareKernel : null);
      if (kMatch && kMatch[1]) {
        _add_host_privesc_fact(facts, ws, source, 'host.kernel', { kernel: kMatch[1].trim(), tool: 'uname', evidence: kMatch[0].trim().slice(0, 220) }, leadKinds);
        C._add_os_observation(facts, ws, source, 'linux', kMatch[0], 'high', 'uname', true, C._os_product_from_label(textNoPem, 'linux'));
        if (C._check_linux_kernel_vulns) C._check_linux_kernel_vulns(kMatch[1].trim(), ws, source, facts, leadKinds);
      }
      var lesArchM = /\bArchitecture\s*:\s*(i[3-6]86|x86_64|amd64|arm64|aarch64|armv\d\w*)\b/i.exec(textNoPem);
      if (lesArchM && lesArchM[1]) {
        _add_host_privesc_fact(facts, ws, source, 'host.arch', { arch: lesArchM[1], tool: 'linux-exploit-suggester' }, leadKinds);
      }
    }

    var osRel = /PRETTY_NAME\s*=\s*["']?([^"'\r\n]+)["']?/i.exec(textNoPem) || /Distributor ID:\s*(\S+)/i.exec(textNoPem) || /\b(?:OS|Operating System):\s*((?:Debian|Ubuntu|CentOS|Red Hat|Fedora|Kali|Alpine|Arch|Rocky|AlmaLinux|SUSE|openSUSE|Gentoo|FreeBSD)[^\r\n]*)/i.exec(textNoPem);
    if (osRel && osRel[1]) {
      C._add_os_observation(facts, ws, source, 'linux', osRel[0], 'high', 'os-release', true, osRel[1].trim());
    }

    var sudoVer = /Sudo(?:\s+version|\s+policy\s+plugin\s+version)\s+(1\.(?:8\.(?:[2-9]|[12]\d|3[01])|9\.[0-5](?:p1)?))\b/i.exec(textNoPem);
    if (sudoVer && sudoVer[1]) {
      _add(facts, mkFact('vuln.baron_samedit', h, { cve: 'CVE-2021-3156', version: sudoVer[1], lead: true }, S, source));
    }
    var sudoChrootVer = /Sudo(?:\s+version|\s+policy\s+plugin\s+version)\s+(1\.9\.(?:1[4-6](?:p\d+)?|17(?:p0)?(?![0-9p])))\b/i.exec(textNoPem);
    if (sudoChrootVer && sudoChrootVer[1]) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.sudo', { cve: 'CVE-2025-32463', version: sudoChrootVer[1], via: 'sudo-chroot' }, leadKinds);
    }

    var pkexecVer = /pkexec\s+version\s+(0\.(?:0\d\d|10[0-5]))\b/i.exec(textNoPem);
    if (pkexecVer && pkexecVer[1]) {
      _add(facts, mkFact('vuln.polkit', h, { cve: 'CVE-2021-4034', version: pkexecVer[1], lead: true }, S, source));
    }

    var imVerM = /Version:\s+ImageMagick\s+(6\.\d+\.\d+-\d+|7\.0\.\d+-\d+|7\.1\.(?:0-\d+|1-(?:[0-2]?\d|3[0-5])))\b/i.exec(textNoPem);
    if (imVerM && imVerM[1]) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.library_or_script_hijack', {
        target: 'ImageMagick ' + imVerM[1],
        target_type: 'so',
        reason: 'imagemagick_delegate_la_search_path',
        cve: 'CVE-2024-41817'
      }, leadKinds);
    }

    var sudoEntries = [];
    var hasDoas = /\bpermit\s+(?:nopass\s+)?\S+(?:\s+as\s+root)?/i.test(textNoPem);
    var hasEnvKeep = /env_keep\s*\+?=\s*["']?[^\r\n"']*\b(?:LD_PRELOAD|LD_LIBRARY_PATH)\b/i.test(textNoPem);
    if (loweredNoPem.indexOf('may run the following commands') >= 0 || loweredNoPem.indexOf('nopasswd:') >= 0 || hasDoas || hasEnvKeep) {
      textNoPem.split(/\r?\n/).forEach(function (raw) {
        var line = raw.trim();
        if (!line) return;
        var ll = line.toLowerCase();
        if (/env_keep\s*\+?=\s*["']?[^\r\n"']*\b(?:LD_PRELOAD|LD_LIBRARY_PATH)\b/i.test(line)) {
          sudoEntries.push(line.slice(0, 220));
          return;
        }
        if (/\bpermit\s+(?:nopass\s+)?\S+/i.test(line)) {
          sudoEntries.push(line.slice(0, 220));
          return;
        }
        if (ll.indexOf('matching defaults') === 0 || ll.indexOf('user ') === 0 || ll.indexOf('sudoers') === 0) return;
        if (reSearch(C._ID_LINE_RE, line)) return;
        if (ll.indexOf('nopasswd:') >= 0 || /\([^)\r\n]{1,120}\)[ \t]+\S+/.test(line)) sudoEntries.push(line.slice(0, 220));
      });
    }
    if (sudoEntries.length) {
      var sudoRightsVal = { entries: C.uniqueSortedCI(sudoEntries).slice(0, 20), nopasswd: sudoEntries.some(function (e) { return /nopasswd|nopass/i.test(e); }) };
      if (activePrincipal) sudoRightsVal.principal = activePrincipal;
      _add_host_privesc_fact(facts, ws, source, 'privesc.sudo_rights', sudoRightsVal, leadKinds);
      var seenBins = {};
      sudoEntries.forEach(function (entry) {
        var nopasswd = /nopasswd|nopass/i.test(entry);
        var wildcard = entry.indexOf('*') >= 0;
        var toks = reAll(/(\/[^\s,]+)/, entry).map(function (m) { return m[1]; });
        toks.forEach(function (tok) {
          var base = tok.split('/').pop().toLowerCase();
          var gid = _normalize_gtfobin(base);
          if (!gid || seenBins[base]) return;
          seenBins[base] = true;
          var fixedScript = '';
          for (var k = 0; k < toks.length; k++) {
            var t = toks[k];
            if (t !== tok && !_normalize_gtfobin(t.split('/').pop().toLowerCase())) { fixedScript = t; break; }
          }
          var val = { bin: base, path: tok, gtfobins_id: gid, wildcard: wildcard, nopasswd: nopasswd, ref: 'https://gtfobins.github.io/gtfobins/' + gid + '/#sudo' };
          if (fixedScript) val.fixed_script = fixedScript;
          _add_host_privesc_fact(facts, ws, source, 'privesc.sudo_binary', val, leadKinds);
        });
      });
    }

    var _FHS_SUID_PATH_RE = /^\/(?:usr|bin|sbin|opt|var|etc|home|root|srv|tmp|snap|lib|lib64|libexec|nix|mnt|media|run|dev\/shm)\/[A-Za-z0-9._\/-]+$/i;
    var _ANCHORED_LS_SUID_RE = /^-[rwx-]{2}[sS][rwxstST-]{6}[.+@]?\s+\d+\s+\S+|^-[rwx-]{5}[sS][rwxstST-]{3}[.+@]?\s+\d+\s+\S+/;
    var suidPaths = {};
    var suidFind = ['-perm -4000', '-perm -u=s', '-perm /4000', '-perm /u=s', '-perm -2000', '-perm -g=s', '-perm /6000', '-perm -6000'].some(function (t) { return lc.indexOf(t) >= 0; }) || /\bfind\s+\/.*-perm\b/i.test(textNoPem);
    var findCmdConstraintOk = !/\bfind\b/i.test(command || '') || (/(?:-perm\b|-[246]000\b|[+-][ug]?s\b)/i.test(command || '') && !/\s-type\s+d\b/i.test(command || ''));
    var isStructuredEnumReport = /══╣|^\s*╣\s+[A-Z]|Linux Privilege Escalation Awesome Script|\bUseful software\b|\bLinEnum\b/im.test(textNoPem);
    var bareSuidList = findCmdConstraintOk && !isStructuredEnumReport && !/\bfind\s+[^\r\n]*\s-type\s+d\b/i.test(textNoPem) && (textNoPem.match(/^\s*\/(?:usr\/|bin\/|sbin\/|opt\/|srv\/|var\/backups\/|home\/)[A-Za-z0-9._\/-]+\s*$/gm) || []).length >= 2;
    var isSuidEnum = /-~>\s*https?:\/\/gtfobins\.github\.io\/gtfobins\/|\[(?:~|#)\]\s*(?:Custom\s+SUID\s+Binaries|SUID\s+Binaries\s+in\s+GTFO)/i.test(textNoPem);
    if (suidFind || isSuidEnum || loweredNoPem.indexOf('suid') >= 0 || loweredNoPem.indexOf('sgid') >= 0 || loweredNoPem.indexOf('rws') >= 0 || /^[ \t]*-[rwx-]{5}[sS][rwxstST-]{3}[.+@]?\s+\d+\s+\S+/m.test(textNoPem) || bareSuidList) {
      var inSuidEnumActiveSection = false;
      textNoPem.split(/\r?\n/).forEach(function (raw) {
        var line = raw.trim();
        if (!line || line.indexOf('/proc/') >= 0) return;
        if (isSuidEnum) {
          if (/^\[(?:~|#)\]\s*(?:Custom\s+SUID\s+Binaries|SUID\s+Binaries\s+in\s+GTFO)/i.test(line)) {
            inSuidEnumActiveSection = true;
            return;
          }
          if (/^\[[!*+]\]\s*(?:Default\s+Binaries|SUID)/i.test(line)) {
            if (/Default\s+Binaries/i.test(line)) inSuidEnumActiveSection = false;
            return;
          }
          var gtfoArrowM = /^(\/[A-Za-z0-9._\/-]+)\s+-~>\s*https?:\/\/gtfobins\.github\.io\/gtfobins\/([A-Za-z0-9_.-]+)/i.exec(line);
          if (gtfoArrowM && _FHS_SUID_PATH_RE.test(gtfoArrowM[1]) && !_is_stock_suid(gtfoArrowM[1])) {
            suidPaths[gtfoArrowM[1]] = true;
            return;
          }
          if (inSuidEnumActiveSection && _FHS_SUID_PATH_RE.test(line) && !_is_stock_suid(line)) {
            suidPaths[line] = true;
            return;
          }
        }
        if (_ANCHORED_LS_SUID_RE.test(line)) {
          var mm = reSearch(C._SUID_PATH_RE, line);
          if (mm && mm.groups && mm.groups.path && (suidFind || _FHS_SUID_PATH_RE.test(mm.groups.path)) && !_is_stock_suid(mm.groups.path) && !_is_stock_sgid_ls_line(line, mm.groups.path)) {
            suidPaths[mm.groups.path] = true;
          }
          return;
        }
        if ((suidFind || bareSuidList) && line[0] === '/' && line.indexOf(' ') < 0 && (suidFind || _FHS_SUID_PATH_RE.test(line)) && !_is_stock_suid(line)) {
          suidPaths[line] = true;
        }
      });
    }
    var suidKeys = Object.keys(suidPaths);
    if (suidKeys.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.suid_candidate', { paths: suidKeys.sort().slice(0, 500), count: suidKeys.length }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'privesc.suid', { binaries: suidKeys.sort().slice(0, 500), paths: suidKeys.sort().slice(0, 500), count: suidKeys.length }, leadKinds);
    }
    if (suidKeys.some(function (p) { return /screen-4\.5\.0/i.test(p); }) || /screen-4\.5\.0|GNU Screen 4\.5\.0|Screen version 4\.05\.00/i.test(textNoPem)) {
      _add_host_privesc_fact(facts, ws, source, 'vuln.screen_suid', { cve: 'CVE-2017-5618', via: 'suid-scan' }, leadKinds);
    }

    var caps = reAll(C._CAPABILITY_RE, textNoPem).map(function (m) { return { path: m.groups.path, capabilities: m.groups.caps.trim() }; }).filter(function (c) {
      if (/\/(?:ping6?|mtr-packet|traceroute6\.iputils)$/i.test(c.path) && /^cap_net_raw(?:=[eip]+|\+[eip]+)?$/i.test(c.capabilities)) return false;
      if (C._DANGEROUS_CAPS && !C._DANGEROUS_CAPS.test(c.capabilities)) return false;
      return true;
    });
    if (caps.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.capability', { entries: caps.slice(0, 500), count: caps.length }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'privesc.capabilities', { entries: caps.slice(0, 500), binaries: caps.slice(0, 500).map(function (c) { return c.path; }), count: caps.length }, leadKinds);
    }

    var emittedWritablePasswd = false;
    reAll(/^(?<mode>-[rwxstST-]{9})[.+@]?\s+\d+\s+(?<owner>[A-Za-z0-9_.-]+)\s+(?<group>[A-Za-z0-9_.-]+)\s+\d+[^\r\n]*\s(?<path>\/etc\/(?:passwd|shadow))\s*$/gm, textNoPem).forEach(function (pm) {
      var mode = pm.groups.mode;
      var owner = pm.groups.owner || '';
      var etcPath = pm.groups.path || '/etc/passwd';
      var ownerWritableNonRoot = mode[2] === 'w' && owner.toLowerCase() !== 'root';
      var groupWritable = mode[5] === 'w';
      var worldWritable = mode[8] === 'w';
      if (ownerWritableNonRoot || groupWritable || worldWritable) {
        emittedWritablePasswd = true;
        var pwVal = { path: etcPath, mode: mode, owner: owner, owner_writable: ownerWritableNonRoot, world_writable: worldWritable, group_writable: groupWritable };
        if (etcPath === '/etc/passwd') {
          _add_host_privesc_fact(facts, ws, source, 'privesc.writable_passwd', pwVal, leadKinds);
          _add_host_privesc_fact(facts, ws, source, 'privesc.passwd_writable', pwVal, leadKinds);
        }
        _add_host_privesc_fact(facts, ws, source, 'privesc.writable_etc', pwVal, leadKinds);
        if (/\bls\b[^\r\n]*\/etc\/(?:passwd|shadow)\b/i.test(command || '')) {
          _add(facts, mkFact('loot.files', h, { files: [etcPath], path: etcPath, count: 1, via: 'writable-passwd' }, S, source));
        }
      }
    });
    reAll(C._PASSWD_MODE_RE, textNoPem).forEach(function (passwd) {
      var mode = passwd.groups.mode;
      var etcPath = (passwd.groups && passwd.groups.path) || '/etc/passwd';
      var groupWritable = mode[5] === 'w', worldWritable = mode[8] === 'w';
      if (groupWritable || worldWritable) {
        emittedWritablePasswd = true;
        if (etcPath === '/etc/passwd') {
          _add_host_privesc_fact(facts, ws, source, 'privesc.writable_passwd', { path: etcPath, mode: mode, world_writable: worldWritable, group_writable: groupWritable }, leadKinds);
        }
        _add_host_privesc_fact(facts, ws, source, 'privesc.passwd_writable', { path: etcPath, mode: mode, world_writable: worldWritable, group_writable: groupWritable }, leadKinds);
        _add_host_privesc_fact(facts, ws, source, 'privesc.writable_etc', { path: etcPath, mode: mode, world_writable: worldWritable, group_writable: groupWritable }, leadKinds);
      }
    });
    if (!emittedWritablePasswd && /Writable passwd file\?[^\r\n]*\/etc\/passwd is writable/i.test(textNoPem)) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.writable_passwd', { path: '/etc/passwd', via: 'linpeas' }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'privesc.passwd_writable', { path: '/etc/passwd', via: 'linpeas' }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'privesc.writable_etc', { path: '/etc/passwd', via: 'linpeas' }, leadKinds);
    }

    var cgroupContM = /:(?:[^:\r\n]*:)?\/(docker|kubepods|lxc|containerd|podman)[\/-][0-9a-f]{12,64}/i.exec(textNoPem);
    var dockerEnvM = !cgroupContM && /(?:^|\r?\n)[ \t]*(?:-[rwxstST-]{9}[.+@]?\s+\d+\s+\S+\s+\S+\s+\d+[^\r\n]*\s)?(\/\.dockerenv|\/run\/\.containerenv)[ \t]*$/m.exec(textNoPem);
    if (cgroupContM || dockerEnvM) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.container', {
        runtime: cgroupContM ? cgroupContM[1].toLowerCase() : 'container',
        evidence: (cgroupContM ? cgroupContM[0] : dockerEnvM[0]).trim().slice(0, 200)
      }, leadKinds);
    }
    var hasWritableDockerSock = /Docker socket \/var\/run\/docker\.sock is writable/i.test(textNoPem);
    if (!hasWritableDockerSock && textNoPem.indexOf('docker.sock') >= 0) {
      var dsM = /^s(?<mode>[rwxstST-]{9})[.+@]?\s+\d+\s+(?<owner>\S+)\s+(?<group>\S+)\s+[^\r\n]*\/var\/run\/docker\.sock\b/m.exec(textNoPem);
      if (dsM && dsM.groups) {
        var dsMode = dsM.groups.mode;
        if (dsMode[7] === 'w' || (dsMode[1] === 'w' && dsM.groups.owner.toLowerCase() !== 'root') || (dsMode[4] === 'w' && dsM.groups.group.toLowerCase() !== 'root')) {
          hasWritableDockerSock = true;
        }
      }
    }
    if (hasWritableDockerSock) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.docker_group', { socket: '/var/run/docker.sock', via: 'writable-docker-sock' }, leadKinds);
    }

    reAll(/^\s*\[!\]\s*([a-z]{3}\d{3})\s+Can we write to ([^\r\n.?]+?)\??\.+\s*yes!/gim, textNoPem).forEach(function (lm) {
      var lseTarget = lm[2].trim();
      if (/passwd/i.test(lseTarget)) {
        _add_host_privesc_fact(facts, ws, source, 'privesc.writable_passwd', { path: '/etc/passwd', via: 'lse', check: lm[1] }, leadKinds);
      } else if (/systemd|service/i.test(lseTarget)) {
        _add_host_privesc_fact(facts, ws, source, 'privesc.writable_service', { target: lseTarget, via: 'lse', check: lm[1] }, leadKinds);
      } else if (/cron/i.test(lseTarget)) {
        _add_host_privesc_fact(facts, ws, source, 'privesc.cron', { jobs: [lm[0].trim()], count: 1, via: 'lse' }, leadKinds);
        _add_host_privesc_fact(facts, ws, source, 'privesc.cron_writable', { evidence: [lm[0].trim()], via: 'lse' }, leadKinds);
      } else {
        _add_host_privesc_fact(facts, ws, source, 'privesc.writable_service', { target: lseTarget, via: 'lse', check: lm[1] }, leadKinds);
      }
    });
    reAll(/You have write privileges over (\/?(?:etc|lib|usr\/lib)\/systemd\/system\/\S+\.service|\S+\.service)\b/gi, textNoPem).forEach(function (sm) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.writable_service', { service: sm[1], path: sm[1], via: 'linpeas' }, leadKinds);
    });

    if (loweredNoPem.indexOf('no_root_squash') >= 0 && !/\b(?:showmount|nmap)\b/i.test(command || '') && !/^Export list for\s+/im.test(textNoPem || '')) {
      var exports = textNoPem.split(/\r?\n/).filter(function (l) { return l.toLowerCase().indexOf('no_root_squash') >= 0; }).map(function (l) { return l.trim(); });
      _add_host_privesc_fact(facts, ws, source, 'privesc.nfs_no_root_squash', { exports: exports.slice(0, 20), count: exports.length || 1 }, leadKinds);
    }

    var writableLsPaths = Object.create(null);
    var readonlyOrRootLsPaths = Object.create(null);
    textNoPem.split(/\r?\n/).forEach(function (raw) {
      var tl = raw.trim();
      if (!tl || tl.length > 2048) return;
      var pm = /(?:^|\s)(\/[A-Za-z0-9._\/-]+)$/.exec(tl);
      if (!pm || !pm[1]) return;
      if (/^[-d][r-][w-][xsStT-](?:[r-]w[xsStT-][r-][w-][xsStT-]|[r-][w-][xsStT-][r-]w[xsStT-])/.test(tl)) {
        writableLsPaths[pm[1]] = 1;
      } else if (/^[-d][r-]-[xsStT-][r-]-[xsStT-][r-]-[xsStT-]/.test(tl)
          || /^[-d][rwx-]{3}[r-]-[xsStT-][r-]-[xsStT-][.+@]?\s+\d+\s+root\s+/i.test(tl)) {
        readonlyOrRootLsPaths[pm[1]] = 1;
      }
    });
    var cronOwnedUsers = _collect_known_owned_linux_users(ws, facts, callerPromptObj);
    if (activePrincipal && activePrincipal.toLowerCase() !== 'root') {
      cronOwnedUsers[activePrincipal.toLowerCase()] = 1;
    }

    var hasHijackableCronPath = false, hasWritableCronPath = false;
    reAll(/^\s*PATH\s*=\s*([^\r\n#]+)/gim, textNoPem).forEach(function (pm) {
      var segs = pm[1].trim().replace(/^['"]|['"]$/g, '').split(':');
      var sysBinIdx = 999, customBinIdx = 999, writableBinIdx = 999;
      for (var si = 0; si < segs.length; si++) {
        var sg = segs[si].trim().replace(/\/+$/, '');
        if ((sg === '/bin' || sg === '/usr/bin') && si < sysBinIdx) sysBinIdx = si;
        if (/^\/(?:usr\/local\/s?bin|tmp|var\/tmp|dev\/shm|home\/|opt\/)/i.test(sg) && si < customBinIdx) customBinIdx = si;
        var homeSegM = /^\/home\/([^/\s]+)/i.exec(sg);
        var isWritableHomeSeg = !!(homeSegM && !readonlyOrRootLsPaths[sg] && cronOwnedUsers[homeSegM[1].toLowerCase()]);
        if ((/^\/(?:tmp|var\/tmp|dev\/shm)(?:\/|$)/i.test(sg) || isWritableHomeSeg || !!writableLsPaths[sg]) && si < writableBinIdx) writableBinIdx = si;
      }
      if (customBinIdx < sysBinIdx) hasHijackableCronPath = true;
      if (writableBinIdx < sysBinIdx) hasWritableCronPath = true;
    });
    var _WILDCARD_ARCHIVER_RE = /\b(tar|rsync|chown|chmod|7z|7za|7zr|zip)\b[^\r\n;|&]*?(?:\s(?:[\w./-]*\/)?\*(?:\.[A-Za-z0-9]{1,8})?(?=\s|$|[;|&><)]))/i;
    var _STOCK_CRON_NOISE_RE = /\brun-parts\b|\/etc\/cron\.(?:hourly|daily|weekly|monthly)\b|\bdebian-sa1\b|\banacron\b|\be2scrub\b|\bfstrim\b|\/usr\/lib\/php\/sessionclean\b|\bcertbot\b|\bapt-compat\b|\bdpkg\b|\blogrotate\b|\bsysstat\b/i;
    var writableCronLines = [], scheduledCronLines = [], wildcardCronEv = [];
    textNoPem.split(/\r?\n/).forEach(function (l) {
      var trimmed = l.trim();
      if (!trimmed) return;
      if (/cron|timer|systemd|\.service\b/i.test(l) && (/\b(writable|world-writable|777|666)\b/i.test(l) || /^-[r-][w-][xsStT-](?:[r-]w[xsStT-]|[r-][w-][xsStT-][r-]w[xsStT-])|\brwx/i.test(trimmed))) {
        writableCronLines.push(trimmed);
        return;
      }
      if (lc.indexOf('-writable') >= 0 && /^\s*\/(?:etc|lib|usr\/lib)\/(?:systemd|cron)[^\s]*$/i.test(l)) {
        writableCronLines.push(trimmed);
        return;
      }
      var isScheduledJob = false, schedCmd = '', isHijackableRunParts = false, isWritableRunParts = false;
      var cronLineM = /^\s*(?:(?:[0-9*,/-]+\s+){5}|@(?:reboot|hourly|daily|weekly|monthly)\s+)(?:root\s+)?(?<cmd>cd\s+\/[^\r\n#]+|run-parts\b[^\r\n#]*|(?:\/|(?:sh|bash|python\d?|perl|php|ruby|tar|rsync|7z[ar]?|zip)\s+\/?)[^\r\n#]+)/i.exec(l);
      if (cronLineM) {
        var rawCronCmd = cronLineM.groups && cronLineM.groups.cmd ? cronLineM.groups.cmd : l;
        var hasRunParts = /\brun-parts\b/i.test(rawCronCmd);
        var isSubHourly = /^\s*\*\/\d+\s+/.test(l);
        var isUnqualRunParts = hasRunParts && !/(?:\/usr)?\/s?bin\/run-parts\b/.test(rawCronCmd);
        isHijackableRunParts = isUnqualRunParts && ((hasHijackableCronPath && isSubHourly) || hasWritableCronPath);
        isWritableRunParts = isUnqualRunParts && hasWritableCronPath;
        if (!_STOCK_CRON_NOISE_RE.test(l) || (hasRunParts && (isSubHourly || isHijackableRunParts))) {
          isScheduledJob = true;
          schedCmd = rawCronCmd;
        }
      }
      if (!isScheduledJob) {
        var sysCronM = /\bCRON\[\d+\]:\s*\(root\)\s*CMD\s*\((.+)\)\s*$/i.exec(l)
          || /\bCRON\[\d+\]:\s*\(root\)\s*CMD\s*\(([^)\r\n]+)\)/i.exec(l);
        if (sysCronM) {
          var sysHasUnqualRp = /\brun-parts\b/i.test(sysCronM[1]) && !/(?:\/usr)?\/s?bin\/run-parts\b/.test(sysCronM[1]);
          if (!_STOCK_CRON_NOISE_RE.test(sysCronM[1]) || (sysHasUnqualRp && hasWritableCronPath)) {
            isScheduledJob = true;
            schedCmd = sysCronM[1];
            if (sysHasUnqualRp && hasWritableCronPath) isWritableRunParts = true;
          }
        }
      }
      if (isScheduledJob) {
        scheduledCronLines.push(trimmed);
        var refsWritableTarget = reAll(/(\/[A-Za-z0-9._\/-]+)/g, trimmed).some(function (m) {
          return !!writableLsPaths[m[1]];
        });
        var refsWritableTree = /(?:^|\s|['"=])\/(?:tmp|var\/tmp|dev\/shm)\/\S+/.test(schedCmd);
        var refsWritableHome = reAll(/(?:^|\s|['"=])(\/home\/([^/\s]+)\/[^\s'";|&)#]+)/g, schedCmd).some(function (hm) {
          var fullP = hm[1], homeOwner = (hm[2] || '').toLowerCase();
          if (writableLsPaths[fullP]) return true;
          if (readonlyOrRootLsPaths[fullP]) return false;
          return !!cronOwnedUsers[homeOwner];
        });
        var wcArchM = _WILDCARD_ARCHIVER_RE.exec(schedCmd);
        if (wcArchM) wildcardCronEv.push({ tool: wcArchM[1].toLowerCase(), evidence: trimmed.slice(0, 220) });
        if (refsWritableTarget || refsWritableTree || refsWritableHome || wcArchM || isWritableRunParts) writableCronLines.push(trimmed);
      }
    });
    var cronLines = C.uniqueSortedCI(writableCronLines.concat(scheduledCronLines));
    if (writableCronLines.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.cron_writable', { evidence: C.uniqueSortedCI(writableCronLines).slice(0, 20) }, leadKinds);
    }
    if (wildcardCronEv.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.cron_wildcard', { tool: wildcardCronEv[0].tool, evidence: wildcardCronEv[0].evidence, count: wildcardCronEv.length }, leadKinds);
    }
    if (cronLines.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.cron', { jobs: cronLines.slice(0, 20), count: cronLines.length }, leadKinds);
    }

    var isInteractiveExploitCmd = /\b(?:python[23]?|perl|ruby)\s+-c\b|\bos\.set(?:e?[ug]id)\s*\(/i.test(command || '');
    var pspyItems = [];
    var processLines = textNoPem.split(/\r?\n/).filter(function (l) {
      var trimmed = l.trim();
      if (!trimmed) return false;
      var pspyM = /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+CMD:\s*UID=(\d+)\s+PID=(\d+)\s*\|\s*(.+)$/.exec(trimmed);
      if (pspyM) {
        var pspyCmd = pspyM[3].trim();
        if (!pspyCmd || /^\[[^\]]+\]$/.test(pspyCmd) || /\bpspy(?:32|64)?s?\b/i.test(pspyCmd)) return false;
        pspyItems.push({ uid: parseInt(pspyM[1], 10), pid: parseInt(pspyM[2], 10), command: pspyCmd });
        return true;
      }
      if (/\b(?:python[23]?|perl|ruby)\s+-c\b|\bos\.set(?:e?[ug]id)\s*\(/i.test(l) && !/\bUID=0\b.*\bPID=/i.test(l) && !/\bCMD:/i.test(l)) return false;
      return /\bUID=0(?!\()\b|\broot\b.*\bCMD\b|\bCMD:/i.test(l);
    }).map(function (l) { return l.trim(); });
    if (!isInteractiveExploitCmd && processLines.length && (/\bpspy(?:32|64)?s?\b/i.test(lc) || pspyItems.length > 0 || loweredNoPem.indexOf('uid=0') >= 0 || loweredNoPem.indexOf('cmd:') >= 0)) {
      var procLeadVal = { commands: processLines.slice(0, 30) };
      if (pspyItems.length) procLeadVal.items = pspyItems.slice(0, 30);
      _add_host_privesc_fact(facts, ws, source, 'privesc.process_lead', procLeadVal, leadKinds);
    }

    // Step 1: OS-Baseline Subtraction + Location Anomaly -> privesc.custom_binary (Linux)
    var linCustom = [], seenLinCustom = {};
    function pushLinCustom(rawPath, ctxName) {
      var hit = _check_linux_custom_binary(rawPath);
      if (!hit) return;
      var k = hit.path + '|' + ctxName;
      if (seenLinCustom[k]) return;
      seenLinCustom[k] = 1;
      linCustom.push({ custom_bin: hit.path, path: hit.path, binary: hit.binary, context: ctxName, os: 'linux' });
    }
    suidKeys.forEach(function (p) { pushLinCustom(p, 'suid'); });
    caps.forEach(function (c) { pushLinCustom(c.path, 'cap'); });
    sudoEntries.forEach(function (entry) {
      reAll(/(?:^|[\s(=,;'"|&])(\/[A-Za-z_][^\s,;'"|&]*)/g, entry).forEach(function (m) { pushLinCustom(m[1], 'sudo'); });
    });
    cronLines.forEach(function (cl) {
      reAll(/(?:^|[\s(=,;'"|&])(\/[A-Za-z_][^\s,;'"|&>#)]*)/g, cl).forEach(function (m) { pushLinCustom(m[1], 'cron'); });
    });
    var unexpDir = '', inUserAddedExec = false;
    textNoPem.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line) return;
      var unexpHdrM = /^(?:(?:[\u2554\u2560\u250c\u251c]?[\u2550\u2500]+[\u2563\u2524]|={3,}|-{3,})\s*)?(?:Unexpected in|Files inside)\s+(\/[A-Za-z0-9_.\-\/]*)(?:\s*\([^)]*\))?(?:\s*:\s*(.*))?$/i.exec(line);
      if (unexpHdrM) {
        unexpDir = unexpHdrM[1].replace(/\/+$/, '') || '/';
        inUserAddedExec = false;
        if (unexpHdrM[2] && unexpHdrM[2].trim()) {
          unexpHdrM[2].trim().split(/\s+/).forEach(function (tok) {
            if (!tok || tok === '.' || tok === '..') return;
            var fullInline = tok.charAt(0) === '/' ? tok : ((unexpDir === '/' ? '' : unexpDir) + '/' + tok);
            pushLinCustom(fullInline, 'unexpected-dir');
            var inlHit = _check_linux_custom_binary(fullInline);
            if (inlHit) _add(facts, mkFact('host.notable_program', h, { name: inlHit.binary, path: inlHit.path, reason: 'unexpected file in ' + unexpDir, os: 'linux' }, S, source));
          });
        }
        return;
      }
      if (/(?:[\u2550\u2500]+[\u2563\u2524]|={3,}|-{3,})\s*Executable files potentially added by user\b/i.test(line)) {
        inUserAddedExec = true;
        unexpDir = '';
        return;
      }
      if (/[\u2550\u2500]+[\u2563\u2524]/.test(line)) {
        unexpDir = '';
        inUserAddedExec = false;
        return;
      }
      if (inUserAddedExec) {
        var uaM = /^\d{4}-\d{2}-\d{2}\+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(\/[^\s\r\n]+)$/.exec(line);
        if (uaM) {
          pushLinCustom(uaM[1], 'user-added');
          var uaHit = _check_linux_custom_binary(uaM[1]);
          if (uaHit) _add(facts, mkFact('host.notable_program', h, { name: uaHit.binary, path: uaHit.path, reason: 'user-added executable', os: 'linux' }, S, source));
          return;
        }
      }
      if (unexpDir) {
        var lsUnexpM = /^-[rwxstST-]{9}[.+@]?\s+\d+\s+\S+\s+\S+\s+\d+\s+(?:[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+|\d{4}-\d{2}-\d{2}\s+[\d:]+\s+)(\S[^\r\n]*)$/.exec(line);
        if (lsUnexpM) {
          var fNameOnly = lsUnexpM[1].split(/\s+->\s+/)[0].trim();
          if (fNameOnly && fNameOnly !== '.' && fNameOnly !== '..') {
            var fullUnexp = fNameOnly.charAt(0) === '/' ? fNameOnly : ((unexpDir === '/' ? '' : unexpDir) + '/' + fNameOnly);
            pushLinCustom(fullUnexp, 'unexpected-dir');
            var unHit = _check_linux_custom_binary(fullUnexp);
            if (unHit) _add(facts, mkFact('host.notable_program', h, { name: unHit.binary, path: unHit.path, reason: 'unexpected file in ' + unexpDir, os: 'linux' }, S, source));
          }
          return;
        }
        if (/^\/[A-Za-z0-9_.\-\/]+$/.test(line) && line.indexOf(unexpDir === '/' ? '/' : (unexpDir + '/')) === 0) {
          pushLinCustom(line, 'unexpected-dir');
          var bareHit = _check_linux_custom_binary(line);
          if (bareHit) _add(facts, mkFact('host.notable_program', h, { name: bareHit.binary, path: bareHit.path, reason: 'unexpected file in ' + unexpDir, os: 'linux' }, S, source));
          return;
        }
      }
      var sysM = /^\s*Exec(?:Start|StartPre|StartPost|Reload)\s*=\s*[-+@!]*(\/[^\s;'"|&]+)/i.exec(line);
      if (sysM) { pushLinCustom(sysM[1], 'service'); return; }
      var psM = /^root\s+\d+\s+(?:\d+(?:\.\d+)?\s+){2,8}(?:[\w?:.-]+\s+){1,5}(\/[^\s;'"|&\]]+)(?:\s+([^\r\n]+))?$/i.exec(line)
        || /^root\s+\d+\s+\d+\s+\d+\s+\S+\s+\S+\s+[\d:]+\s+(\/[^\s;'"|&\]]+)(?:\s+([^\r\n]+))?$/i.exec(line);
      if (psM) {
        pushLinCustom(psM[1], 'service');
        if (psM[2]) reAll(/(\/(?:opt|usr\/local|srv|var\/backups|home)\/[^\s;'"|&]+)/g, psM[2]).forEach(function (am) { pushLinCustom(am[1], 'service'); });
      }
    });
    processLines.forEach(function (pl) {
      reAll(/(?:^|[\s(=,;'"|&])(\/[A-Za-z_][^\s,;'"|&>#]*)/g, pl).forEach(function (m) { pushLinCustom(m[1], 'service'); });
    });
    if (linCustom.length) {
      var topLin = linCustom[0];
      _add_host_privesc_fact(facts, ws, source, 'privesc.custom_binary', {
        custom_bin: topLin.path,
        path: topLin.path,
        binary: topLin.binary,
        context: topLin.context,
        os: 'linux',
        candidates: linCustom.slice(0, 20)
      }, leadKinds);
    }

    var secretScanText = String(text || '').replace(/^\s*(?:\[sudo\]\s+password\s+for\s+[^:\r\n]+|(?:Enter\s+)?Password)\s*:\s*[^\r\n]*$/gim, '');
    if (!/\b(?:su:\s*Authentication failure|Login incorrect|Sorry,\s*try again|doesn't have UF_DONT_REQUIRE_PREAUTH set)\b/i.test(text || '') && reSearch(C._LOCAL_FILE_SECRET_RE, secretScanText)) {
      _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'local_file_secret', evidence: 'local loot output' }, S, source));
    }

    _parse_kernel_exploits(textNoPem, ws, command, source, facts, leadKinds);

    if (Object.keys(leadKinds).length > 0
        && /(?:^|[\s'"=:])\/(?:etc|usr|var|opt|home|root)\//.test(textNoPem)
        && !facts.some(function (f) { return f && f.kind === 'host.os_family'; })) {
      C._add_os_observation(facts, ws, source, 'linux', 'Linux privesc enumeration', 'medium', 'local-enum', true);
    }
  }
  C._parse_linux_privesc_output = _parse_linux_privesc_output;

  function _parse_windows_privesc_output(text, ws, command, source, facts, leadKinds) {
    var lowered = text.toLowerCase(), h = 'host:' + ws.target;
    var observedSystem = reAll(C._WHOAMI_ID_RE, text).some(function (m) { return m.groups.id.toLowerCase() === 'nt authority\\system'; });
    if (observedSystem) {
      C._add_os_observation(facts, ws, source, 'windows', 'Windows local command output', 'high', 'local-enum', true);
      _add(facts, mkFact('access.system', h, { identity: 'nt authority\\system', method: 'local-enum' }, S, source));
      _add(facts, mkFact('access.admin', h, { identity: 'nt authority\\system', method: 'local-enum' }, S, source));
    }
    var sysinfo = {};
    reAll(C._SYSTEMINFO_FIELD_RE, text).forEach(function (m) { sysinfo[m.groups.key.toLowerCase()] = m.groups.value.trim(); });
    if (Object.keys(sysinfo).length) {
      var osName = sysinfo['os name'] || '', osVersion = sysinfo['os version'] || '';
      if (osName || osVersion) {
        _add_host_privesc_fact(facts, ws, source, 'host.kernel', { kernel: [osName, osVersion].filter(Boolean).join(' '), tool: 'systeminfo' }, leadKinds);
        C._add_os_observation(facts, ws, source, 'windows', (osName || osVersion), 'high', 'systeminfo', true, (osName || ('Windows ' + osVersion)).trim());
      }
      if (sysinfo['system type']) _add_host_privesc_fact(facts, ws, source, 'host.arch', { arch: sysinfo['system type'], tool: 'systeminfo' }, leadKinds);
    } else {
      var winVer = /Microsoft Windows \[Version\s+([0-9.]+)\]/i.exec(text);
      if (winVer && winVer[1]) {
        _add_host_privesc_fact(facts, ws, source, 'host.kernel', { kernel: winVer[1].trim(), tool: 'ver' }, leadKinds);
        C._add_os_observation(facts, ws, source, 'windows', winVer[0], 'high', 'ver', true, 'Windows ' + winVer[1].trim());
      }
    }

    var privileges = [];
    reAll(C._WIN_PRIV_RE, text).forEach(function (m) {
      var name = m.groups.name, state = m.groups.state.toLowerCase();
      if ((state === 'enabled' || state === 'disabled' || state === 'habilitada' || state === 'habilitado' || state === 'deshabilitada' || state === 'deshabilitado') && C._DANGEROUS_WIN_PRIVS.has(name.toLowerCase())) privileges.push(name);
    });
    reAll(/^\s*Privilege\s*:\s*(?<name>Se[A-Za-z0-9]+Privilege)\b/gim, text).forEach(function (m) {
      var name = m.groups.name;
      if (C._DANGEROUS_WIN_PRIVS.has(name.toLowerCase())) privileges.push(name);
    });
    if (privileges.length) {
      var uniqPrivs = C.uniqueSortedCI(privileges);
      _add_host_privesc_fact(facts, ws, source, 'privesc.windows_privilege', { privileges: uniqPrivs, state: 'Enabled' }, leadKinds);
      var lowPrivs = uniqPrivs.map(function (p) { return p.toLowerCase(); });
      if (lowPrivs.indexOf('seimpersonateprivilege') >= 0 || lowPrivs.indexOf('seassignprimarytokenprivilege') >= 0) {
        var impPriv = lowPrivs.indexOf('seimpersonateprivilege') >= 0 ? 'SeImpersonatePrivilege' : 'SeAssignPrimaryTokenPrivilege';
        _add_host_privesc_fact(facts, ws, source, 'privesc.seimpersonate', { privilege: impPriv, state: 'Enabled' }, leadKinds);
      }
      if (lowPrivs.indexOf('sebackupprivilege') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.sebackup', { privilege: 'SeBackupPrivilege', state: 'Enabled' }, leadKinds);
      if (lowPrivs.indexOf('serestoreprivilege') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.serestore', { privilege: 'SeRestorePrivilege', state: 'Enabled' }, leadKinds);
      if (lowPrivs.indexOf('semanagevolumeprivilege') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.semanagevolume', { privilege: 'SeManageVolumePrivilege', state: 'Enabled' }, leadKinds);
    }

    reAll(/^\s*(?:BUILTIN\\Administrators\b[^\r\n]*?\bS-1-5-32-544\b|BUILTIN\\Administrators\b|[A-Za-z0-9_.-]+\\Administrators\b[^\r\n]*?\bS-1-5-32-544\b|[^\r\n]*?\bS-1-5-32-544\b)\s+(?<attrs>[^\r\n]+)$/gim, text).forEach(function (gm) {
      var attrs = gm.groups.attrs || '';
      if (/\bGroup used for deny only\b/i.test(attrs)) {
        if (leadKinds) leadKinds['uac-token-filter'] = true;
      } else if (/\bEnabled group\b/i.test(attrs)) {
        _add(facts, mkFact('access.admin', h, { group: 'BUILTIN\\Administrators', sid: 'S-1-5-32-544', method: 'whoami-groups' }, S, source));
      }
    });

    var privGroups = [];
    var winGroupRe = /(?:BUILTIN\\|(?<![A-Za-z0-9._-])[A-Za-z0-9._-]{1,64}\\|\b)(Backup Operators|DnsAdmins|Server Operators|Print Operators|Account Operators|Hyper-V Administrators|Exchange Windows Permissions|Organization Management)\b/gi;
    var gm;
    while ((gm = winGroupRe.exec(text)) !== null) {
      if (privGroups.indexOf(gm[1]) < 0) privGroups.push(gm[1]);
    }
    if (privGroups.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.privileged_group', { groups: C.uniqueSortedCI(privGroups), count: privGroups.length }, leadKinds);
    }

    if (/\bAbuseFunction\s*:\s*Write-UserAddMSI\b/i.test(text)) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.always_install_elevated', { hklm: true, hkcu: true, via: 'powerup' }, leadKinds);
    }
    if (lowered.indexOf('alwaysinstallelevated') >= 0) {
      var aieHklm = false, aieHkcu = false, currentHive = '';
      if (/\b(?:HKLM|HKEY_LOCAL_MACHINE)\b/i.test(command || '') && !/\b(?:HKCU|HKEY_CURRENT_USER)\b/i.test(command || '')) currentHive = 'hklm';
      else if (/\b(?:HKCU|HKEY_CURRENT_USER)\b/i.test(command || '') && !/\b(?:HKLM|HKEY_LOCAL_MACHINE)\b/i.test(command || '')) currentHive = 'hkcu';
      text.split(/\r?\n/).forEach(function (raw) {
        if (reSearch(C._HKLM_HEADER_RE, raw)) currentHive = 'hklm';
        else if (reSearch(C._HKCU_HEADER_RE, raw)) currentHive = 'hkcu';
        var vm = reSearch(C._AIE_VALUE_RE, raw);
        if (!vm) return;
        var enabled = parseInt(vm.groups.val, 16) !== 0;
        if (currentHive === 'hklm') aieHklm = enabled;
        else if (currentHive === 'hkcu') aieHkcu = enabled;
      });
      var priorFacts = (ws && (ws.facts || ws.seedFacts)) || [];
      var hasPriorHklm = priorFacts.some(function (pf) {
        return pf && pf.state === 'supported' && pf.scope === h && pf.kind === 'config.review' && pf.value && pf.value.kind === 'always_install_elevated_hive' && pf.value.aie_hklm === true;
      });
      var hasPriorHkcu = priorFacts.some(function (pf) {
        return pf && pf.state === 'supported' && pf.scope === h && pf.kind === 'config.review' && pf.value && pf.value.kind === 'always_install_elevated_hive' && pf.value.aie_hkcu === true;
      });
      if ((aieHklm || hasPriorHklm) && (aieHkcu || hasPriorHkcu)) {
        _add_host_privesc_fact(facts, ws, source, 'privesc.always_install_elevated', { hklm: true, hkcu: true }, leadKinds);
      } else if (aieHklm) {
        _add(facts, mkFact('config.review', h, { kind: 'always_install_elevated_hive', hive: 'hklm', aie_hklm: true, enabled: true }, S, source));
      } else if (aieHkcu) {
        _add(facts, mkFact('config.review', h, { kind: 'always_install_elevated_hive', hive: 'hkcu', aie_hkcu: true, enabled: true }, S, source));
      }
    }

    var unquoted = [];
    if (lowered.indexOf('.exe') >= 0) {
      text.split(/\r?\n/).forEach(function (raw) {
        var line = raw.trim();
        if (!line || line.toLowerCase().indexOf('.exe') < 0) return;
        var mPath = /(?:BINARY_PATH_NAME|Binary Path Name|PathName|Path)\s*[:=]\s*(.+)$/i.exec(line);
        var cand = mPath ? mPath[1].trim() : line;
        var mWin = /(["']?)([A-Za-z]:\\[^"\r\n[\]]*?\.exe)\b/i.exec(cand);
        if (!mWin || mWin[1]) return;
        var winPath = mWin[2].trim();
        if (/\s/.test(winPath) && !/^C:\\Windows\\(?:System32|SysWOW64)\\[^\s\\]+\.exe$/i.test(winPath)) {
          unquoted.push(line.slice(0, 220));
        }
      });
    }
    if (unquoted.length) _add_host_privesc_fact(facts, ws, source, 'privesc.unquoted_service_path', { services: C.uniqueSortedCI(unquoted).slice(0, 20), count: C.uniqueSortedCI(unquoted).length }, leadKinds);

    var weakService = [], lastRwHighPriv = false;
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line) { lastRwHighPriv = false; return; }
      var rwM = /^\s*(?:RW|R|W)\s+(.+?)\s*$/i.exec(raw);
      if (rwM) {
        lastRwHighPriv = _WIN_HIGHPRIV_ACL_PRINCIPAL_RE.test(rwM[1].trim());
      } else if (!/^\s+/.test(raw)) {
        lastRwHighPriv = false;
      }
      if (lastRwHighPriv || _line_has_only_highpriv_acl(line)) return;
      if (reSearch(C._WEAK_SVC_ACCESS_RE, line) || reSearch(C._LOWPRIV_WRITE_ACE_RE, line) || (C._WEAK_SERVICE_PERM_RE && reSearch(C._WEAK_SERVICE_PERM_RE, line))) weakService.push(line.slice(0, 220));
    });
    var powerUpAbuseBins = [];
    if (/AbuseFunction\s*:|\bCheck\s*:\s*ModifiableServiceFile\b/i.test(text)) {
      String(text).split(/\r?\n\s*\r?\n/).forEach(function (stanza) {
        var abM = /^\s*AbuseFunction\s*:\s*(Install-ServiceBinary|Write-ServiceBinary|Invoke-ServiceAbuse)\b([^\r\n]*)/im.exec(stanza);
        var modCheck = !abM && /^\s*Check\s*:\s*ModifiableServiceFile\b/im.test(stanza);
        if (!abM && !modCheck) return;
        var fileM = /^\s*(?:ModifiableFile|UnquotedService|Path)\s*:\s*['"]?([A-Za-z]:\\[^\r\n'"]+?\.exe)\b/im.exec(stanza);
        var fnName = abM ? abM[1] : 'ModifiableServiceFile';
        var abEv = (fileM ? (fileM[1] + ' -> ') : '') + fnName + ((abM && abM[2]) || '').trim();
        weakService.push(abEv.slice(0, 220));
        if (fileM && fileM[1]) {
          powerUpAbuseBins.push({ path: fileM[1].trim(), abuseFunction: fnName });
        }
      });
    }
    if (weakService.length) _add_host_privesc_fact(facts, ws, source, 'privesc.weak_service_permission', { evidence: C.uniqueSortedCI(weakService).slice(0, 30) }, leadKinds);

    var stored = [];
    var cmdkeyNone = /Currently stored credentials:[\s\S]{0,160}?\*\s*NONE\s*\*/i.test(text);
    [['Target:', 'cmdkey'], ['Currently stored credentials', 'cmdkey'], ['Saved ', 'cmdkey'], ['DefaultPassword', 'autologon'], ['unattend.xml', 'unattend'], ['sysprep', 'sysprep'], ['confCons.xml', 'mRemoteNG'], ['.rdp', 'rdp_file'], ['simontatham', 'putty'], ['winscp', 'winscp'], ['vncpassword', 'vnc']].forEach(function (pair) {
      if (pair[1] === 'cmdkey' && cmdkeyNone) return;
      if (pair[0] === 'DefaultPassword' && !/DefaultPassword\s+REG_SZ\s+\S+/i.test(text)) return;
      if (lowered.indexOf(pair[0].toLowerCase()) >= 0) stored.push(pair[1]);
    });
    var hasDpapiBlob = /\b01000000d08c9ddf0115d1118c7a00c04fc297eb[0-9a-fA-F]{160,}\b/i.test(text);
    if (hasDpapiBlob) stored.push('dpapi');
    if (stored.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.stored_credentials', { kinds: C.uniqueSortedCI(stored), count: C.uniqueSortedCI(stored).length }, leadKinds);
      if (hasDpapiBlob) {
        _add(facts, mkFact('credential.candidate', h, { kind: 'dpapi_securestring', via: 'dpapi-blob' }, S, source));
      }
      if (!hasDpapiBlob || stored.length > 1) {
        _add(facts, mkFact('credential.candidate', h, { kind: 'stored_windows_credentials' }, S, source));
      }
    }

    var dllHits = text.split(/\r?\n/).filter(function (raw) { var l = raw.toLowerCase(); return l.indexOf('.dll') >= 0 && (l.indexOf('name not found') >= 0 || l.indexOf('path not found') >= 0); }).map(function (raw) { return raw.trim().slice(0, 220); });
    reAll(/^\s*HijackablePath\s*:\s*([^\r\n]+)/gim, text).forEach(function (hm) {
      var hp = hm[1].trim().replace(/^['"]|['"]$/g, '');
      if (hp) dllHits.push(('HijackablePath: ' + hp).slice(0, 220));
    });
    reAll(/^\s*AbuseFunction\s*:\s*(Write-HijackDll\b[^\r\n]*)/gim, text).forEach(function (am) {
      dllHits.push(am[1].trim().slice(0, 220));
    });
    if (dllHits.length) _add_host_privesc_fact(facts, ws, source, 'privesc.dll_hijack_candidate', { evidence: C.uniqueSortedCI(dllHits).slice(0, 20), count: C.uniqueSortedCI(dllHits).length }, leadKinds);

    // Step 1: OS-Baseline Subtraction + Location Anomaly -> privesc.custom_binary (Windows)
    var winCustom = [], seenWinCustom = {};
    function pushWinCustom(rawStr, ctxName) {
      var hit = _check_windows_custom_binary(rawStr);
      if (!hit) return;
      var k = hit.path.toLowerCase();
      if (seenWinCustom[k]) return;
      seenWinCustom[k] = 1;
      winCustom.push({ custom_bin: hit.path, path: hit.path, binary: hit.binary, context: ctxName, os: 'windows' });
    }
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line || !/[A-Za-z]:\\/i.test(line)) return;
      if (/\b(?:BINARY_PATH_NAME|Binary Path Name|PathName|ImagePath|Image Path|Launch String|Task To Run)\s*[:=]/i.test(line)) {
        var ctx = /Launch String|Image Path|Autorun/i.test(line) ? 'autorun' : (/Task To Run/i.test(line) ? 'task' : 'service');
        pushWinCustom(line, ctx);
        return;
      }
      if (/^[A-Za-z0-9_.-]{2,64}\s+(?:"[A-Za-z]:\\[^"\r\n]+\.(?:exe|bat|cmd|ps1|vbs)"|[A-Za-z]:\\[^\r\n]+?\.(?:exe|bat|cmd|ps1|vbs))\s+(?:Auto|Manual|Disabled|Running|Stopped)\b/i.test(line)) {
        pushWinCustom(line, 'service');
        return;
      }
      if (/\b(?:sc\s+qc|wmic\s+service|win32_service|autorun)/i.test((command || '') + '\n' + text) && /\.(?:exe|bat|cmd|ps1|vbs)\b/i.test(line)) {
        pushWinCustom(line, 'service');
      }
    });
    powerUpAbuseBins.forEach(function (item) {
      var cleanP = item.path;
      var k = cleanP.toLowerCase();
      if (seenWinCustom[k]) return;
      if (/^C:\\Windows\\(?:System32|SysWOW64|WinSxS)\\/i.test(cleanP)) return;
      seenWinCustom[k] = 1;
      var baseName = cleanP.split(/[\\/]/).pop() || cleanP;
      winCustom.push({ custom_bin: cleanP, path: cleanP, binary: baseName, context: 'powerup-service', abuse_function: item.abuseFunction, os: 'windows' });
    });
    var isDirQCmd = /\bdir\b[^\r\n]*\/q\b/i.test(command || '');
    var curDirQ = '';
    text.split(/\r?\n/).forEach(function (raw) {
      var dirHdrM = /^\s*Directory of\s+([A-Za-z]:\\[^\r\n]+?)\s*$/i.exec(raw);
      if (dirHdrM) { curDirQ = dirHdrM[1].trim(); return; }
      var dqM = isDirQCmd
        ? /^\s*\d{1,4}[\/.-]\d{1,2}[\/.-]\d{1,4}\s+\d{1,2}:\d{2}(?:\s*[AP]M)?\s+(?!<)([\d,]+)\s+((?:NT AUTHORITY|BUILTIN|NT SERVICE|[A-Za-z0-9_.-]+)\\[A-Za-z0-9_. $-]+?|[A-Za-z0-9_.$-]+)\s+([^\r\n\\/:*?"<>|]+?\.(?:exe|bat|ps1))\s*$/i.exec(raw)
        : /^\s*\d{1,4}[\/.-]\d{1,2}[\/.-]\d{1,4}\s+\d{1,2}:\d{2}(?:\s*[AP]M)?\s+(?!<)([\d,]+)\s+((?:NT AUTHORITY|BUILTIN|NT SERVICE|[A-Za-z0-9_.-]+)\\[A-Za-z0-9_.$-]+)\s+([^\r\n\\/:*?"<>|]+?\.(?:exe|bat|ps1))\s*$/i.exec(raw);
      if (!dqM) return;
      var dqOwner = dqM[2].trim();
      var dqFile = dqM[3].trim();
      if (/^(?:NT AUTHORITY\\(?:SYSTEM|LOCAL SERVICE|NETWORK SERVICE|TrustedInstaller)|BUILTIN\\Administrators|NT SERVICE\\TrustedInstaller|(?:[^\\]+\\)?(?:Administrator|SYSTEM|TrustedInstaller))$/i.test(dqOwner)) return;
      if (/^(?:nc64?|ncat|netcat|socat|chisel|plink|pscp|ligolo|agent|winpeas\S*|seatbelt|sharphound|rubeus|mimikatz|powercat|juicypotato\S*|sweetpotato\S*|godpotato\S*|printspoofer\S*|roguepotato\S*|efspotato\S*|accesschk\S*)\.(?:exe|bat|ps1)$/i.test(dqFile)) return;
      var dqFull = curDirQ ? (C.stripChars(curDirQ, '\\/') + '\\' + dqFile) : dqFile;
      if (/^[A-Za-z]:\\(?:Windows|Program Files(?: \(x86\))?)(?:\\|$)/i.test(dqFull)) return;
      var dqKey = dqFull.toLowerCase();
      if (seenWinCustom[dqKey]) return;
      seenWinCustom[dqKey] = 1;
      winCustom.push({ custom_bin: dqFull, path: dqFull, binary: dqFile, owner: dqOwner, context: 'dir-q-owner', os: 'windows' });
    });
    if (winCustom.length) {
      var topWin = winCustom[0];
      _add_host_privesc_fact(facts, ws, source, 'privesc.custom_binary', {
        custom_bin: topWin.path,
        path: topWin.path,
        binary: topWin.binary,
        context: topWin.context,
        os: 'windows',
        candidates: winCustom.slice(0, 20)
      }, leadKinds);
    }

    var patchLines = text.split(/\r?\n/).filter(function (l) { return /\bMS\d{2}-\d{3}\b|CVE-\d{4}-\d+|missing patches?|exploit/i.test(l); }).map(function (l) { return l.trim(); });
    if (patchLines.length && (/wes(?:\.py|ng)?|windows[- ]exploit[- ]suggester|missing patches?|found vulnerabilities|\[\*\]\s*initiating winsploit|\[\s*[EM]\s*\]\s*MS\d{2}-\d{3}\s*:|\[\*\]\s*Appears vulnerable to\s+CVE-\d{4}-\d{4,7}|\[!\]\s*(?:CVE-\d{4}-\d{4,7}|MS\d{2}-\d{3})\s*:/i.test((command || '') + '\n' + text))) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.patch_gap', { evidence: patchLines.slice(0, 30) }, leadKinds);
      _add(facts, mkFact('exploit.candidate', h, { tool: 'windows-exploit-suggester', findings: patchLines.slice(0, 30) }, S, source));
    }
  }
  C._parse_windows_privesc_output = _parse_windows_privesc_output;

  function _looks_like_linux_enum(text) {
    var raw = String(text || '');
    var t = raw.length > 65536 ? (raw.slice(0, 32768) + '\n' + raw.slice(-32768)) : raw;
    if (!t.trim()) return false;
    if (/^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(t)) return false;
    return !!(
      reSearch(C._UNAME_RE, t) ||
      /PRETTY_NAME\s*=/i.test(t) ||
      /Distributor ID:\s*\S+/i.test(t) ||
      /Linux version\s+[0-9]/i.test(t) ||
      /\b(?:OS|Operating System):\s*(?:Debian|Ubuntu|CentOS|Red Hat|Fedora|Kali|Alpine|Arch|Rocky|AlmaLinux|SUSE|openSUSE|Gentoo|FreeBSD)\b[\s\S]{0,200}?\bKernel:\s*(?:Linux\s+)?[2-6]\.\d+\.\d+/i.test(t) ||
      /^\s*[2-6]\.\d+\.\d+-(?:[0-9A-Za-z.+_-]*(?:generic|amd64|i[3-6]86|arm64|el\d|kali|debian|ubuntu|arch|alpine)[0-9A-Za-z.+_-]*|\d+-[A-Za-z0-9.+_-]+)\s*$/m.test(t) ||
      /Linux Privilege Escalation Awesome Script|linpeas/i.test(t) ||
      /══╣|^\s*\u2550+\u2563\s+\S/m.test(t) ||
      /Available information:[\s\S]{0,320}?Kernel version:\s*[2-6]\.\d|Possible Exploits:\s*(?:\r?\n)+\s*\[\+\]\s*\[CVE-\d{4}-\d+\]/i.test(t) ||
      /^\s*\[!\]\s*[a-z]{3}\d{3}\s+Can we\b/im.test(t) ||
      reSearch(C._CAPABILITY_RE, t) ||
      reSearch(C._PASSWD_MODE_RE, t) ||
      /^-[r-][w-][xsStT-][rwxstST-]{6}[.+@]?\s+\d+\s+(?!root\b)[A-Za-z0-9_.-]+\s+\S+\s+\d+[^\r\n]*\s\/etc\/passwd\s*$/m.test(t) ||
      /Writable passwd file\?[^\r\n]*\/etc\/passwd is writable|Docker socket \/var\/run\/docker\.sock is writable|You have write privileges over \S+\.service/i.test(t) ||
      /:(?:[^:\r\n]*:)?\/(?:docker|kubepods|lxc|containerd|podman)[\/-][0-9a-f]{12,64}/i.test(t) ||
      /no_root_squash/i.test(t) ||
      /\bUID=0\b.*\bCMD\b|\bCMD:\s*UID=0\b/i.test(t) ||
      /^\s*\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+CMD:\s*UID=\d+\s+PID=\d+\s*\|/m.test(t) ||
      /-~>\s*https?:\/\/gtfobins\.github\.io\/gtfobins\/|\[(?:~|#)\]\s*(?:Default\s+SUID\s+Binaries|Custom\s+SUID\s+Binaries|SUID\s+Binaries\s+in\s+GTFO)|\bSuidEnum\b|\bSUID3NUM\b/i.test(t) ||
      /\bCRON\[\d+\]:\s*\(root\)\s*CMD\s*\(/i.test(t) ||
      /^\s*(?:(?:[0-9*,/-]+\s+){5}|@(?:reboot|hourly|daily|weekly|monthly)\s+)(?:root\s+)?(?:cd\s+\/|\/(?:opt|home|tmp|var|srv|etc|usr\/local)\/|(?:sh|bash|python\d?|perl|php|ruby)\s+\/)/im.test(t) ||
      /^\s*ExecStart\s*=\s*[-+@!]*\/(?:opt|usr\/local|srv|var\/backups|home)\//im.test(t) ||
      /^root\s+\d+\s+(?:\d+(?:\.\d+)?\s+){2,8}(?:[\w?:.-]+\s+){1,5}\/(?:opt|usr\/local|srv|var\/backups|home)\/\S+/im.test(t) ||
      /\bpermit\s+nopass\b/i.test(t) ||
      /\bfind\s+\/.*-perm\b/i.test(t) ||
      /\bgetcap\b/i.test(t) ||
      /(?:^|\r?\n)[ \t]*\/(?:usr\/local\/|usr\/|bin\/|sbin\/|opt\/|srv\/|var\/backups\/|home\/)[A-Za-z0-9._\/-]+[ \t]*\r?\n[ \t]*\/(?:usr\/local\/|usr\/|bin\/|sbin\/|opt\/|srv\/|var\/backups\/|home\/)[A-Za-z0-9._\/-]+(?=[ \t]*(?:\r?\n|$))/.test(t) ||
      /^\s*-[rwxstST-]{9}\s+\d+\s+root\s+/m.test(t) ||
      /^[ \t]*-(?:[rwx-]{2}[sS][rwxstST-]{6}|[rwx-]{5}[sS][rwxstST-]{3})[.+@]?\s+\d+\s+\S+/m.test(t) ||
      /CVE-\d{4}-\d{4,7}.*?\b(?:dirty|pwnkit|polkit|samedit|overlayfs)/i.test(t) ||
      /Sudo(?:\s+version|\s+policy\s+plugin\s+version)\s+\d/i.test(t) ||
      /pkexec\s+version\s+\d/i.test(t) ||
      /\bgroups=[^\r\n]*\((?:docker|lxd|lxc|adm|disk|shadow|video)\)/i.test(t)
    );
  }
  C._looks_like_linux_enum = _looks_like_linux_enum;

  function _looks_like_windows_enum(text) {
    var raw = String(text || '');
    var t = raw.length > 65536 ? (raw.slice(0, 32768) + '\n' + raw.slice(-32768)) : raw;
    if (!t.trim()) return false;
    return !!(
      /^\s*OS Name:\s*Microsoft(?:\s*\(R\)|r|\u00ae)?\s+Windows\b/im.test(t) ||
      (/\bOS Version:\s*\d+\.\d+\.\d+/i.test(t) && /\bSystem Type:\s*(?:x64|x86)/i.test(t)) ||
      /Microsoft Windows \[Version\s+[0-9.]+\]/i.test(t) ||
      /Saved [A-Z0-9_-]+ credentials|Currently stored credentials:/i.test(t) ||
      /\b01000000d08c9ddf0115d1118c7a00c04fc297eb[0-9a-fA-F]{160,}\b/i.test(t) ||
      /ServiceName\s*:\s*\S+[\s\S]{1,200}?PathName\s*:/i.test(t) ||
      /\b(?:BINARY_PATH_NAME|Binary Path Name|PathName|Image Path|Launch String)\s*[:=]\s*["']?[A-Za-z]:\\/i.test(t) ||
      /^\s*[A-Za-z0-9_.-]{2,64}\s+(?:"[A-Za-z]:\\[^"\r\n]+\.(?:exe|bat|cmd|ps1|vbs)"|[A-Za-z]:\\[^\r\n]+?\.(?:exe|bat|cmd|ps1|vbs))\s+(?:Auto|Manual|Disabled|Running|Stopped)\b/im.test(t) ||
      /^\s*\d{1,4}[\/.-]\d{1,2}[\/.-]\d{1,4}\s+\d{1,2}:\d{2}(?:\s*[AP]M)?\s+(?!<)[\d,]+\s+(?:NT AUTHORITY|BUILTIN|NT SERVICE|[A-Za-z0-9_.-]+)\\[A-Za-z0-9_.$-]+\s+[^\r\n\\/:*?"<>|]+?\.(?:exe|bat|ps1)\s*$/im.test(t) ||
      /\b(?:Backup Operators|DnsAdmins|Server Operators|Print Operators)\b[\s\S]{0,80}?\bS-1-5-/i.test(t) ||
      /^\s*(?:BUILTIN\\Administrators|[^\r\n]*\bS-1-5-32-544\b)\s+.*?\b(?:Enabled group|Group used for deny only)\b/im.test(t) ||
      /^\s*Privilege\s*:\s*Se[A-Za-z0-9]+Privilege\b/im.test(t) ||
      /\bAbuseFunction\s*:\s*(?:Install-ServiceBinary|Write-ServiceBinary|Invoke-ServiceAbuse|Write-UserAddMSI|Write-HijackDll)\b/i.test(t) ||
      /\bHijackablePath\s*:|Checking for AlwaysInstallElevated|\bCheck\s*:\s*(?:ModifiableServiceFile|DLL Hijacking)/i.test(t) ||
      /Found vulnerabilities|\bMS\d{2}-\d{3}\b.*CVE-\d{4}-\d+|\[\*\]\s*initiating winsploit|\[\s*[EM]\s*\]\s*MS\d{2}-\d{3}\s*:|\[\*\]\s*Appears vulnerable to\s+CVE-\d{4}-\d{4,7}|\[!\]\s*(?:CVE-\d{4}-\d{4,7}|MS\d{2}-\d{3})\s*:/i.test(t) ||
      /\.dll\b.*(?:NAME NOT FOUND|PATH NOT FOUND)/i.test(t) ||
      reSearch(C._WIN_PRIV_RE, t) ||
      (C._WEAK_SERVICE_PERM_RE && reSearch(C._WEAK_SERVICE_PERM_RE, t)) ||
      reSearch(C._AIE_VALUE_RE, t)
    );
  }
  C._looks_like_windows_enum = _looks_like_windows_enum;

  function _parse_privesc_output(a1, a2, a3, a4, a5, a6) {
    var actionId = a1, text = a2, ws = a3, command = a4, source = a5, facts = a6;
    if (Array.isArray(a5) && typeof a6 === 'string') {
      text = a1; ws = a2; command = a3; source = a4; facts = a5; actionId = a6;
    }
    if (!text || !String(text).trim()) return;
    text = String(text).replace(C._ANSI_RE, '');
    var leadKinds = {};
    var isLinAct = C._LINUX_PRIVESC_ACTION_IDS.has(actionId);
    var isWinAct = C._WINDOWS_PRIVESC_ACTION_IDS.has(actionId);
    if (isLinAct || (!isWinAct && _looks_like_linux_enum(text))) _parse_linux_privesc_output(text, ws, command, source, facts, leadKinds);
    if (isWinAct || (!isLinAct && _looks_like_windows_enum(text))) _parse_windows_privesc_output(text, ws, command, source, facts, leadKinds);
    _add_privesc_leads(facts, ws, source, leadKinds);
  }
  C._parse_privesc_output = _parse_privesc_output;

  function _looks_like_whoami_priv(text) {
    var raw = text || '';
    var t = raw.length > 65536 ? (raw.slice(0, 32768) + '\n' + raw.slice(-32768)) : raw;
    return !!(
      reSearch(C._WIN_PRIV_RE, t) ||
      /^\s*Privilege\s*:\s*Se[A-Za-z0-9]+Privilege\b/im.test(t) ||
      /\b(?:Backup Operators|DnsAdmins|Server Operators|Print Operators)\b[\s\S]{0,80}?\bS-1-5-/i.test(t) ||
      /^\s*(?:BUILTIN\\Administrators|[^\r\n]*\bS-1-5-32-544\b)\s+.*?\b(?:Enabled group|Group used for deny only)\b/im.test(t)
    );
  }
  C._looks_like_whoami_priv = _looks_like_whoami_priv;

  function _parse_whoami_priv(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var leadKinds = {};
    _parse_windows_privesc_output(text, ws, command, source, facts, leadKinds);
    _add_privesc_leads(facts, ws, source, leadKinds);
  }
  C._parse_whoami_priv = _parse_whoami_priv;

  function _looks_like_sudo_l(text) {
    var t = text || '';
    var lowered = t.toLowerCase();
    return lowered.indexOf('may run the following commands') >= 0 || lowered.indexOf('nopasswd:') >= 0 ||
      /\bpermit\s+(?:nopass\s+)?\S+\s+as\s+root\b/i.test(t) ||
      /env_keep\s*\+?=\s*["']?[^\r\n"']*\b(?:LD_PRELOAD|LD_LIBRARY_PATH)\b/i.test(t);
  }
  C._looks_like_sudo_l = _looks_like_sudo_l;

  function _parse_sudo_l(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var leadKinds = {};
    _parse_linux_privesc_output(text, ws, command, source, facts, leadKinds);
    _add_privesc_leads(facts, ws, source, leadKinds);
  }
  C._parse_sudo_l = _parse_sudo_l;

  // ── net user / net localgroup / net group (Windows account enumeration) ────────────
  // A `net localgroup administrators` members list → config.review (local_admins) so the admin set reaches
  // the report. A `net user <name> /domain` showing domain-group membership (Global Group memberships
  // *Domain Users/*Domain Admins), or a `net group … /domain` members listing, CLEARLY names domain
  // accounts → ad.user_list. A purely-local `net user` grid (`User accounts for \\HOST`) → config.review
  // (local_users): a local-users signal only, NEVER a domain user list (no over-claiming).
  var _NET_USER_NAME_RE = /^\s*User name\s+(?<user>\S+)/im;
  var _NET_LOCALGROUP_HDR_RE = /^\s*Alias name\s+(?<group>\S.*?)\s*$/im;
  var _NET_DOMAIN_MEMBERSHIP_RE = /Global Group memberships[^\r\n]*\bDomain (?:Users|Admins|Computers)\b/i;
  var _NET_LOCAL_ACCOUNTS_HDR_RE = /^\s*User accounts for\b/im;
  var _NET_COMPLETED_RE = /The command completed/i;

  function _looks_like_net_output(text) {
    var t = text || '';
    return !!(reSearch(_NET_LOCALGROUP_HDR_RE, t) || reSearch(_NET_USER_NAME_RE, t) ||
              reSearch(_NET_LOCAL_ACCOUNTS_HDR_RE, t) || reSearch(_NET_DOMAIN_MEMBERSHIP_RE, t));
  }
  C._looks_like_net_output = _looks_like_net_output;

  // the rows between the dashed separator line and "The command completed", trimmed & non-empty
  function _net_block_lines(text) {
    var lines = String(text || '').split(/\r?\n/), out = [], started = false;
    for (var i = 0; i < lines.length; i++) {
      if (/^-{5,}\s*$/.test(lines[i].trim())) { started = true; continue; }
      if (!started) continue;
      if (_NET_COMPLETED_RE.test(lines[i])) break;
      var t = lines[i].trim();
      if (t) out.push(t);
    }
    return out;
  }
  function _net_accounts_from_rows(rows) {
    var out = [];
    rows.forEach(function (row) {
      row.split(/\s{2,}|\t+/).forEach(function (tok) {
        var u = C._clean_username(C.stripChars(tok, '*'));
        if (C._valid_username(u, false)) out.push(u);
      });
    });
    return C.uniqueSortedCI(out);
  }

  function _norm_principal_name(s) {
    return String(s || '').trim().replace(/^.*[\\/]/, '').replace(/@.*$/, '').toLowerCase();
  }

  function _is_owned_principal(user, ws, currentFacts) {
    var targetUser = _norm_principal_name(user);
    if (!targetUser) return false;
    var promptStr = [
      ws && ws.context && ws.context.promptLine,
      ws && ws.context && ws.context.followPrompt
    ].filter(Boolean).join('\n');
    if (promptStr) {
      var winProfM = /[A-Za-z]:\\Users\\([A-Za-z0-9_.$-]+)(?:[\\>]|$)/i.exec(promptStr);
      if (winProfM && _norm_principal_name(winProfM[1]) === targetUser) return true;
      var promptUserM = /^\s*(?:\([^)]+\)\s*)?\[?(?:[A-Za-z0-9_.-]+\\)?([A-Za-z0-9_.$-]+)@[A-Za-z0-9_.-]+/m.exec(promptStr);
      if (promptUserM && _norm_principal_name(promptUserM[1]) === targetUser) return true;
    }
    var all = [].concat((ws && (ws.facts || ws.seedFacts)) || [], currentFacts || []);
    for (var i = 0; i < all.length; i++) {
      var f = all[i];
      if (!f || f.state !== 'supported' || !f.value) continue;
      var k = f.kind || '';
      var v = f.value;
      if (k === 'foothold.windows' || k === 'foothold.linux' || k === 'access.shell'
          || /\.authenticated$/.test(k) || k === 'credential.available' || k === 'credential.validated') {
        var cand = _norm_principal_name(v.user || v.identity || v.username || v.principal || '');
        if (cand && cand === targetUser) return true;
      }
    }
    return false;
  }

  function _parse_net_accounts(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    var h = 'host:' + ws.target, lc = (command || '').toLowerCase();
    // 1) net localgroup administrators → local admin members (config.review lead)
    var lg = reSearch(_NET_LOCALGROUP_HDR_RE, text);
    var isAdminGroup = lc.indexOf('localgroup') >= 0 && lc.indexOf('admin') >= 0;
    if (lg || isAdminGroup) {
      var group = lg ? lg.groups.group.trim() : 'administrators';
      if (/admin/i.test(group) || isAdminGroup) {
        var members = C.uniqueSortedCI(_net_block_lines(text).filter(function (m) { return !/^Members$/i.test(m); })).slice(0, 50);
        if (members.length) _add(facts, mkFact('config.review', h, { kind: 'local_admins', group: group, members: members }, S, source));
      }
    }
    // 2) net user <name> /domain showing domain-group membership → ad.user_list + ad.group_list + privileged group leads
    var domainMembership = reSearch(_NET_DOMAIN_MEMBERSHIP_RE, text)
      || (/Global Group memberships/i.test(text) && (/\/domain\b/i.test(lc) || /processed at a domain controller/i.test(text)));
    var nm = reSearch(_NET_USER_NAME_RE, text);
    if (nm) {
      var user = C._clean_username(nm.groups.user);
      var grpMap = {};
      var grpSecM = /(?:Local Group Memberships|Global Group memberships)[\s\S]*?(?=The command completed|$)/i.exec(text);
      if (grpSecM) {
        reAll(/\*([A-Za-z0-9][A-Za-z0-9 _.-]*?)(?=\s{2,}|\s*\*|\r?\n|$)/g, grpSecM[0]).forEach(function (gm) {
          var gName = gm[1].trim();
          if (gName && !/^none$/i.test(gName)) grpMap[gName] = true;
        });
      }
      var userGroups = C.uniqueSortedCI(Object.keys(grpMap));
      var privGroups = userGroups.filter(function (g) {
        return /^(?:Backup Operators|Account Operators|Server Operators|Print Operators|DnsAdmins|Domain Admins|Enterprise Admins|Schema Admins|Administrators|Remote Management Users|Exchange Windows Permissions)$/i.test(g);
      });
      if (domainMembership && C._valid_username(user, false)) {
        var domain = C._domain_from_facts(ws);
        var domScope = C._scope_for_domain(ws, domain);
        _add(facts, mkFact('ad.user_list', domScope, { users: [user], count: 1, method: 'net' }, S, source));
        if (userGroups.length) {
          _add(facts, mkFact('ad.group_list', domScope, { groups: userGroups, user: user, count: userGroups.length, method: 'net' }, S, source));
        }
        if (privGroups.length) {
          _add(facts, mkFact('ad.acl_lead', domScope, { principal: user, user: user, group: privGroups[0], groups: privGroups, targets: privGroups, method: 'net-user-domain' }, S, source));
        }
      }
      var hostPrivGroups = privGroups.filter(function (g) {
        return /^(?:Backup Operators|Account Operators|Server Operators|Print Operators|DnsAdmins)$/i.test(g);
      });
      if (hostPrivGroups.length && C._valid_username(user, false)) {
        _add(facts, mkFact('privesc.privileged_group', h, { user: user, group: hostPrivGroups[0], groups: hostPrivGroups, via: 'net-user' }, S, source));
      }
      var adminGroups = userGroups.filter(function (g) {
        return /^(?:Administrators|Domain Admins|Enterprise Admins)$/i.test(g);
      });
      if (adminGroups.length && C._valid_username(user, false) && _is_owned_principal(user, ws, facts)) {
        _add(facts, mkFact('access.admin', h, { user: user, identity: user, group: adminGroups[0], groups: adminGroups, via: 'net-user' }, S, source));
      }
    }
    // 3) net group "<name>" /domain members listing → ad.user_list (domain group members)
    if (lc.indexOf('net group') >= 0 && lc.indexOf('/domain') >= 0) {
      var gmembers = _net_accounts_from_rows(_net_block_lines(text));
      if (gmembers.length) _add(facts, mkFact('ad.user_list', C._scope_for_domain(ws, C._domain_from_facts(ws)), { users: gmembers, count: gmembers.length, method: 'net' }, S, source));
    }
    // 4) purely-local `net user` grid (User accounts for \\HOST) → local-users signal (NOT a domain list)
    if (reSearch(_NET_LOCAL_ACCOUNTS_HDR_RE, text) && !domainMembership) {
      var locals = _net_accounts_from_rows(_net_block_lines(text));
      if (locals.length) _add(facts, mkFact('config.review', h, { kind: 'local_users', users: locals.slice(0, 50) }, S, source));
    }
  }
  C._parse_net_accounts = _parse_net_accounts;

  // ── winPEAS / PrivescCheck.ps1 → the existing Windows local-privesc logic ──────────
  // winPEAS/PrivescCheck print section banners + findings (SeImpersonatePrivilege: Enabled,
  // AlwaysInstallElevated, unquoted service paths, weak service ACLs, credentials-in-files). Route the
  // whole paste through _parse_windows_privesc_output so it mints privesc.windows_privilege / privesc.leads
  // (and privesc.stored_credentials where creds-in-files show). winPEAS writes privileges in the COLON
  // form `SeXxxPrivilege: Enabled`, which the whoami-style _WIN_PRIV_RE (name · description · state) misses,
  // so normalize that one idiom to the space form (with a filler token) before the shared parser runs.
  function _looks_like_winpeas(text) {
    var t = String(text || '').replace(C._ANSI_RE, '');
    if (/winpeas|privesccheck|peass-ng|\bPEASS\b/i.test(t)) return true;
    if (/Checking (?:Token privileges|Credentials in files|AlwaysInstallElevated|Unquoted|Service)/i.test(t)) return true;
    if (/(?:╔═+╣|╠═+╣)[^\r\n]*(?:Security Packages|executable files in non-default|Services Information|Applications Information|Autoruns|Scheduled Applications|Windows Credentials)/i.test(t)) return true;
    if (/\bFile\s+Permissions\s+["']?[A-Za-z]:\\[^"'\r\n]+\.(?:exe|dll|ps1|bat|cmd|vbs|msi|sys)["']?\s*:/i.test(t)) return true;
    if (/\b(?:Path|ImagePath|BinaryPathName|Command)\s*:\s*["']?[A-Za-z]:\\[^"'\r\n:*?<>|]+?\.(?:exe|dll|ps1|bat|cmd|vbs|msi|sys)\b[\s\S]{0,400}?^[ \t]*File\s+Permissions\s*:/im.test(t)) return true;
    return /^\s*Se[A-Za-z0-9]+Privilege\s*:\s*(?:Enabled|Disabled)\s*$/im.test(t);
  }
  C._looks_like_winpeas = _looks_like_winpeas;

  var _WIN_HIGHPRIV_ACL_PRINCIPAL_RE = /^(?:NT AUTHORITY\\SYSTEM|LocalSystem|SYSTEM|BUILTIN\\Administrators|Administrators|NT SERVICE\\TrustedInstaller|TrustedInstaller|CREATOR OWNER|APPLICATION PACKAGE AUTHORITY\\.*|ALL APPLICATION PACKAGES|ALL RESTRICTED APPLICATION PACKAGES|S-1-5-18|S-1-5-32-544|[^\\]+\\(?:Domain Admins|Enterprise Admins|Administrator))$/i;
  function _line_has_only_highpriv_acl(line) {
    var s = String(line || '').trim();
    if (!s) return false;
    var clauseRe = /((?:NT AUTHORITY|BUILTIN|NT SERVICE|APPLICATION PACKAGE AUTHORITY|[A-Za-z0-9_.-]+)\\[A-Za-z0-9_. $-]{2,64}|\b(?:LocalSystem|SYSTEM|Administrators|TrustedInstaller|CREATOR OWNER|ALL (?:RESTRICTED )?APPLICATION PACKAGES|Everyone|Authenticated Users|INTERACTIVE|Users|S-1-5-\d+(?:-\d+)*)\b)[ \t]*(?:\[[^\]]+\]|:(?:\([A-Za-z,]+\))+|:[ \t]*(?:SERVICE_[A-Z_]+|CHANGE_CONFIG|WRITE_DAC|WRITE_OWNER|AllAccess|GenericAll|GenericWrite|Modify|FullControl|WriteData))\b/gi;
    var m, sawAny = false;
    while ((m = clauseRe.exec(s)) !== null) {
      sawAny = true;
      if (!_WIN_HIGHPRIV_ACL_PRINCIPAL_RE.test(m[1].trim())) return false;
    }
    return sawAny;
  }
  var _WINPEAS_WRITABLE_BIN_RE = /(?:File\s+Permissions\s+)?["']?(?<path>[A-Za-z]:\\[^"'\r\n:*?<>|]+?\.(?:exe|dll|ps1|bat|cmd|vbs|msi|sys))["']?\s*[:(]\s*(?<principal>(?:[A-Za-z0-9_.-]+\\)?[A-Za-z0-9_. $-]{2,64}?)\s*(?:\[(?<rights1>[^\]]*(?:WriteData|CreateFiles|AllAccess|GenericAll|GenericWrite|Modify|FullControl|\bWrite\b)[^\]]*)\]|:\s*(?<rights2>AllAccess|GenericAll|GenericWrite|Modify|FullControl|WriteData(?:\/CreateFiles)?)\b)/gi;

  function _emit_writable_win_custom_binary(facts, ws, source, rawPath, principal, rights, leadKinds) {
    var cleanPath = String(rawPath || '').replace(/^Microsoft\.PowerShell\.Core\\FileSystem::/i, '').trim().replace(/^["']|["']$/g, '');
    var prin = String(principal || '').trim();
    if (!cleanPath || !/\.(?:exe|dll|ps1|bat|cmd|vbs|msi|sys)$/i.test(cleanPath)) return false;
    if (!prin || _WIN_HIGHPRIV_ACL_PRINCIPAL_RE.test(prin)) return false;
    if (/^C:\\Windows\\(?:System32|SysWOW64|WinSxS)\\/i.test(cleanPath)) return false;
    var base = cleanPath.split(/[\\/]/).pop() || cleanPath;
    var val = {
      custom_bin: cleanPath,
      path: cleanPath,
      binary: base,
      principal: prin,
      rights: String(rights || 'Modify').trim(),
      context: 'acl',
      os: 'windows'
    };
    _add_host_privesc_fact(facts, ws, source, 'privesc.custom_binary', val, leadKinds);
    return true;
  }

  function _parse_winpeas(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var h = 'host:' + ws.target;
    var netRe = /\b([A-Za-z0-9_.$-]{1,48})::([A-Za-z0-9_.-]{1,64}):([0-9a-fA-F]{16}):([0-9a-fA-F]{32}|[0-9a-fA-F]{48}):([0-9a-fA-F]{32,})\b/g, nm;
    while ((nm = netRe.exec(text)) !== null) {
      var nUser = C._clean_username(nm[1]);
      if (!nUser || !C._valid_username(nUser, false)) continue;
      var nDom = nm[2], nFmt = nm[4].length === 48 ? 'netntlmv1' : 'netntlmv2', nHash = nm[0];
      _add(facts, mkFact('credential.netntlm', h, { kind: nFmt, user: nUser, users: [nUser], domain: nDom, count: 1, via: 'winpeas' }, S, source));
      _add(facts, mkFact('credential.candidate', h, { kind: nFmt, user: nUser, domain: nDom, hash: nHash, via: 'winpeas' }, S, source));
      _add(facts, mkFact('hash.candidate', h, { format: nFmt, user: nUser, domain: nDom, hash: nHash, via: 'winpeas' }, S, source));
      _add(facts, mkFact('hash.crackable', h, { format: nFmt, user: nUser, domain: nDom, hash: nHash, via: 'winpeas' }, S, source));
    }
    var norm = text.replace(/^(\s*)(Se[A-Za-z0-9]+Privilege)\s*:\s*(Enabled|Disabled)\b/gim, '$1$2  state  $3');
    var leadKinds = {};
    _parse_windows_privesc_output(norm, ws, command, source, facts, leadKinds);
    _WINPEAS_WRITABLE_BIN_RE.lastIndex = 0;
    var wm, wpEv = [];
    while ((wm = _WINPEAS_WRITABLE_BIN_RE.exec(text)) !== null) {
      var wRights = wm.groups.rights1 || wm.groups.rights2 || 'WriteData';
      if (_emit_writable_win_custom_binary(facts, ws, source, wm.groups.path, wm.groups.principal, wRights, leadKinds)) {
        wpEv.push((wm.groups.path + ' ' + wm.groups.principal + ' [' + wRights + ']').slice(0, 220));
      }
    }
    var lastWpBin = '';
    text.split(/\r?\n/).forEach(function (wLine) {
      var trimmedWp = wLine.trim();
      if (!trimmedWp || /^={4,}/.test(trimmedWp)) { lastWpBin = ''; return; }
      var pathM = /\b(?:Path|ImagePath|BinaryPathName|Command)\s*:\s*["']?([A-Za-z]:\\[^"'\r\n:*?<>|]+?\.(?:exe|dll|ps1|bat|cmd|vbs|msi|sys))\b/i.exec(trimmedWp);
      if (pathM) lastWpBin = pathM[1];
      if (!lastWpBin) return;
      var fpM = /^File\s+Permissions\s*:\s*(?<principal>(?:[A-Za-z0-9_.-]+\\)?[A-Za-z0-9_. $-]{2,64}?)\s*(?:\[(?<rights1>[^\]]*(?:WriteData|CreateFiles|AllAccess|GenericAll|GenericWrite|Modify|FullControl|\bWrite\b)[^\]]*)\]|:\s*(?<rights2>AllAccess|GenericAll|GenericWrite|Modify|FullControl|WriteData(?:\/CreateFiles)?)\b)/i.exec(trimmedWp);
      if (fpM) {
        var fpRights = fpM.groups.rights1 || fpM.groups.rights2 || 'WriteData';
        if (_emit_writable_win_custom_binary(facts, ws, source, lastWpBin, fpM.groups.principal, fpRights, leadKinds)) {
          wpEv.push((lastWpBin + ' ' + fpM.groups.principal + ' [' + fpRights + ']').slice(0, 220));
        }
      }
    });
    if (wpEv.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.weak_service_permission', { evidence: C.uniqueSortedCI(wpEv).slice(0, 30), tool: 'winpeas' }, leadKinds);
    }
    _add_privesc_leads(facts, ws, source, leadKinds);
  }
  C._parse_winpeas = _parse_winpeas;

  // sudo-allowed script read → injectable sink lead
  var _SCRIPT_SINKS = [
    ['gitpython_ext', /\.clone_from\s*\(|git\.Repo\.clone|from\s+git\s+import/i, 'CVE-2022-24439'],
    ['os_system', /os\.system\s*\(|os\.popen\s*\(/i, ''],
    ['subprocess_shell', /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/i, ''],
    ['eval_exec', /\b(?:eval|exec)\s*\(/i, ''],
    ['tarfile_extract', /\.extractall\s*\(/i, ''],
    ['yaml_unsafe_load', /yaml\.load\s*\((?![^)]*Loader)/i, ''],
  ];
  var _ARG_SOURCE_RE = /sys\.argv|\bargv\b|\$\{?1\b|\$@|getopt|argparse|input\s*\(/i;
  var _FILE_READ_CMDS = ['cat ', 'type ', 'more ', 'less ', 'head ', 'tail ', 'get-content'];

  var _SCRIPT_WILDCARD_ARCHIVER_RE = /\b(tar|rsync|chown|chmod|7z|7za|7zr|zip)\b[^\r\n;|&]*?(?:\s(?:[\w./-]*\/)?\*(?:\.[A-Za-z0-9]{1,8})?(?=\s|$|[;|&><)]))/i;

  function _parse_script_sinks(text, command, ws, source, facts) {
    var t = text || '', cmd = (command || '').toLowerCase();
    var isRead = _FILE_READ_CMDS.some(function (w) { return cmd.indexOf(w) >= 0; });
    var hasShebang = /^#!\s*\/(?:usr\/)?bin\/(?:env\s+)?(?:ba|da|z|k|a)?sh\b/m.test(t);
    var isShellScript = hasShebang || (isRead && /\.sh(?:\s|['"]|$)/i.test(command || ''));
    var looksLikeCode = t.indexOf('def ') >= 0 || t.indexOf('import ') >= 0 || t.slice(0, 64).replace(/^\s+/, '').indexOf('#!') === 0;
    if (!(isRead || looksLikeCode || isShellScript)) return;
    if (isShellScript && /\*|\btar\b|\brsync\b|\b7z|\bzip\b|\bchown\b|\bchmod\b/i.test(t)) {
      var hasDirContext = /\bcd\s+\S+|\/(?:var\/www|tmp|var\/tmp|dev\/shm|opt|home|srv|var\/backups)\/|\buploads?\b/i.test(t);
      if (hasDirContext) {
        var sLines = t.split(/\r?\n/);
        for (var si = 0; si < sLines.length; si++) {
          var sTrim = sLines[si].trim();
          if (!sTrim || sTrim.charAt(0) === '#') continue;
          var wcM = _SCRIPT_WILDCARD_ARCHIVER_RE.exec(sTrim);
          if (wcM) {
            var wcLeads = {};
            var activePrin = _resolve_active_linux_principal('', ws, facts);
            if (activePrin) {
              try { Object.defineProperty(wcLeads, '_principal', { value: activePrin, enumerable: false, writable: true, configurable: true }); } catch (_e) {}
            }
            var sPathM = /(\/[^\s'"]{1,200}\.sh|[A-Za-z0-9_./-]+\.sh)\b/.exec(command || '');
            var wcVal = { kind: 'wildcard_archiver', tool: wcM[1].toLowerCase(), evidence: sTrim.slice(0, 220) };
            if (sPathM) wcVal.script = sPathM[1];
            _add_host_privesc_fact(facts, ws, source, 'privesc.cron_writable', wcVal, wcLeads);
            _add_host_privesc_fact(facts, ws, source, 'privesc.cron_wildcard', wcVal, wcLeads);
            _add_privesc_leads(facts, ws, source, wcLeads);
            break;
          }
        }
      }
    }
    var hasArg = !!reSearch(_ARG_SOURCE_RE, t);
    for (var i = 0; i < _SCRIPT_SINKS.length; i++) {
      var sink = _SCRIPT_SINKS[i][0], rx = _SCRIPT_SINKS[i][1], cve = _SCRIPT_SINKS[i][2];
      var m = reSearch(rx, t);
      if (!m || !hasArg) continue;
      var value = { sink: sink, evidence: C._line_for_match(t, m) };
      if (cve) value.cve = cve;
      var fm = /(\/[^\s'"]{1,200}\.(?:py|sh|pl|rb|php))/.exec(command || '');
      if (fm) value.script = fm[1];
      _add(facts, mkFact('privesc.script_sink', 'host:' + ws.target, value, S, source));
      break;
    }
  }
  C._parse_script_sinks = _parse_script_sinks;

  // ── Windows cleartext-cred idioms + PuTTY/plink/WinSCP stored creds (§33) ──────────
  // Cleartext credentials typed into a script/history/config, plus PuTTY's plaintext registry proxy
  // credential and a saved plink `-pw` command line → credential.candidate MATERIAL to try (never
  // access.* - §34 validates it into credential.available). A login the same transcript shows was
  // DENIED right after is skipped, so a failed `mysql -p'wrong'` never becomes a lead.
  var _WIN_CRED_RES = [
    ['net-use', /net\s+use\s+\\\\\S+\s+\/user:(?<user>\S+)\s+(?<pw>\S+)/gi],
    ['net-use', /net\s+use\s+\\\\\S+\s+(?<pw>\S+)\s+\/user:(?<user>\S+)/gi],
    ['cmdkey', /cmdkey\s+\/(?:add|generic):\S+\s+\/user:(?<user>\S+)\s+\/pass:(?<pw>\S+)/gi],
    ['psexec', /psexec\S*\s.*?-u\s+(?<user>\S+)\s+-p\s+(?<pw>\S+)/gi],
    ['sqlcmd', /sqlcmd\s.*?-U\s+(?<user>\S+)\s+-P\s+(?<pw>\S+)/gi],
    ['mysql', /mysql\s.*?-u\s*(?<user>\S+)\s+-p(?<pw>\S+)/gi],
    ['createprocesswithlogonw', /CreateProcessWithLogonW\s*\(\s*['"](?<user>[^'"]+)['"]\s*,\s*['"][^'"]*['"]\s*,\s*['"](?<pw>[^'"]+)['"]/gi],
    ['runas', /runas\s+\/user:(?<user>\S+)\s+.*?\/(?:savecred|smartcard)?.*?['"](?<pw>[^'"]+)['"]/gi],
    // A saved PuTTY/plink command line carries the password inline before the user@host.
    ['plink', /plink(?:\.exe)?['")\s].*?-pw\s+['"]?(?<pw>[^'"\s]+)['"]?\s+(?<user>[^@\s'"]+)@(?<host>[^\s'"]+)/gi],
  ];
  var _PS_SECURESTRING_RE = /ConvertTo-SecureString\s+['"](?<pw>[^'"]+)['"]\s+-AsPlainText/gi;
  // PuTTY stores a session proxy credential in plaintext in the registry
  // (HKCU\Software\SimonTatham\PuTTY\Sessions\<name>): ProxyUsername/ProxyPassword REG_SZ values.
  var _PUTTY_PROXYPW_RE = /ProxyPassword\s+REG_SZ\s+(?<pw>\S.*\S|\S)\s*$/im;
  var _PUTTY_PROXYUSER_RE = /ProxyUsername\s+REG_SZ\s+(?<user>\S+)/i;
  var _LOGIN_DENIED_RE = /access denied|authentication fail|logon failure|login failed|ERROR 1045/i;

  var _PLINK_PW_LINE_RE = /\b(?:plink|pscp)(?:\.exe)?\b[^\r\n]*?\s-pw\s+(?:'([^'\r\n]+)'|"([^"\r\n]+)"|([^\s'"]+))/i;
  var _HIST_CMD_RE = /(?:ConsoleHost_history|\.(?:bash|zsh|sh|ash)_history|\bhistory\b)/i;
  var _HIST_CUSTOM_BIN_LINE_RE = /^\s*(?:&\s*)?(?:"([A-Za-z]:\\(?:Users|ProgramData|tools|apps|opt|temp)\\[^"\r\n]+?\.(?:exe|bat|cmd|ps1|py)|\/(?:opt|home|usr\/local|srv|var\/backups)\/[^"\r\n]+)"|'([A-Za-z]:\\(?:Users|ProgramData|tools|apps|opt|temp)\\[^'\r\n]+?\.(?:exe|bat|cmd|ps1|py)|\/(?:opt|home|usr\/local|srv|var\/backups)\/[^'\r\n]+)'|([A-Za-z]:\\(?:Users|ProgramData|tools|apps|opt|temp)\\[^\s"'\r\n]+?\.(?:exe|bat|cmd|ps1|py)|\/(?:opt|home|usr\/local|srv|var\/backups)\/[^\s"'\r\n]+))\s+([^\r\n|;>&]+)$/im;
  var _HIST_ACTION_VERB_RE = /^(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|\/bin\/(?:ba)?sh|(?:ba)?sh|admin|administrator|system|root|exec|run|shell|whoami|id)$/i;
  var _HIST_NONSECRET_WORD_RE = /^(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|sh|bash|whoami|id|admin|administrator|root|system|exec|run|shell|start|stop|restart|status|install|uninstall|update|test|check|help|list|show|get|set|add|del|delete|remove|enable|disable|true|false|localhost|quiet|full|all|fast|service|client|server)$/i;
  var _HIST_IGNORE_TOOL_RE = /^(?:chisel|plink|pscp|putty|nc|nc64|ncat|netcat|socat|curl|wget|certutil|git|ssh|scp|python[23]?|powershell|pwsh|cmd|rundll32|regsvr32|msiexec|icacls|accesschk\d*|schtasks|net|sc|ligolo|agent|nmap)(?:\.(?:exe|bat|cmd|ps1|py|sh))?$/i;

  function _char_classes(s) {
    var c = 0;
    if (/[a-z]/.test(s)) c++;
    if (/[A-Z]/.test(s)) c++;
    if (/[0-9]/.test(s)) c++;
    if (/[^A-Za-z0-9]/.test(s)) c++;
    return c;
  }

  var _PS_TUTORIAL_PW_DENY_RE = /^(?:testpassword|mysecretpassword|yourpassword|enterpassword|p@ssw0rd|passw0rd|password|changeme|secret|placeholder|example)$/i;
  var _DPAPI_HEX_BLOB_RE = /\b01000000d08c9ddf0115d1118c7a00c04fc297eb[0-9a-fA-F]{160,}\b/i;

  function _has_windows_creds(text, command) {
    text = text || '';
    if (reSearch(_PS_SECURESTRING_RE, text) || reSearch(_PUTTY_PROXYPW_RE, text) || _PLINK_PW_LINE_RE.test(text) || _DPAPI_HEX_BLOB_RE.test(text)) return true;
    if ((_HIST_CMD_RE.test(command || '') || _HIST_CUSTOM_BIN_LINE_RE.test(text)) && _HIST_CUSTOM_BIN_LINE_RE.test(text)) return true;
    return _WIN_CRED_RES.some(function (pair) { return reSearch(pair[1], text); });
  }
  C._has_windows_creds = _has_windows_creds;

  function _parse_windows_creds(text, ws, command, source, facts) {
    if (C._is_public_reference_http_cmd && C._is_public_reference_http_cmd(command, ws)) return;
    text = text || '';
    var h = 'host:' + ws.target, seen = {};
    _WIN_CRED_RES.forEach(function (pair) {
      var idiom = pair[0], rx = pair[1];
      reAll(rx, text).forEach(function (m) {
        var user = m.groups.user, pw = m.groups.pw;
        // skip a credential whose login the transcript shows was rejected right after it
        var tail = text.slice(m.index + m[0].length, m.index + m[0].length + 120);
        if (reSearch(_LOGIN_DENIED_RE, tail)) return;
        if (!user || !pw) return;
        var cleanPw = C.stripChars(pw, "'\"");
        var key = user + '|' + cleanPw;
        if (seen[key]) return;
        seen[key] = true;
        _add(facts, mkFact('credential.candidate', h, { user: user, password: cleanPw, via: idiom }, S, source));
        if (idiom === 'plink' && C._valid_username(C._clean_username(user), false) && C._valid_password(cleanPw)) {
          if (C._add_plaintext_credential) C._add_plaintext_credential(facts, ws, source, C._clean_username(user), cleanPw, '', 'plink', '');
        }
      });
    });
    // General single/double/unquoted plink/pscp -pw '<secret>' with <user>@<host> or -l <user> anywhere on the line
    text.split(/\r?\n/).forEach(function (line) {
      var pm = _PLINK_PW_LINE_RE.exec(line);
      if (!pm) return;
      var pw = (pm[1] || pm[2] || pm[3] || '').trim();
      if (!pw) return;
      var lineNoPw = line.replace(/\s-pw\s+(?:'[^'\r\n]*'|"[^"\r\n]*"|[^\s'"]+)/i, ' ');
      var uhM = /(?:^|[\s'"])([A-Za-z0-9_.$-]+)@([A-Za-z0-9_.-]+)/.exec(lineNoPw);
      var lM = /\s-l\s+['"]?([A-Za-z0-9_.$-]+)['"]?/.exec(lineNoPw);
      var rawU = (uhM && uhM[1]) || (lM && lM[1]) || '';
      var cleanU = rawU ? C._clean_username(rawU) : '';
      var key = cleanU + '|' + pw;
      if (!seen[key]) {
        seen[key] = true;
        var cVal = { password: pw, via: 'plink' };
        if (cleanU) cVal.user = cleanU;
        if (uhM && uhM[2]) cVal.host = uhM[2];
        _add(facts, mkFact('credential.candidate', h, cVal, S, source));
      }
      if (cleanU && C._valid_username(cleanU, false) && C._valid_password(pw)) {
        if (C._add_plaintext_credential) {
          C._add_plaintext_credential(facts, ws, source, cleanU, pw, '', 'plink', '');
        } else {
          var pVal = { user: cleanU, password: pw, method: 'plink' };
          _add(facts, mkFact('credential.plaintext', h, pVal, S, source));
          _add(facts, mkFact('credential.available', h, pVal, S, source));
        }
      }
    });
    // Custom-binary CLI secret positional arguments in ConsoleHost_history.txt / .bash_history
    var isHistCmd = _HIST_CMD_RE.test(command || '');
    text.split(/\r?\n/).forEach(function (line) {
      var hm = /^(?:\s*(?:&\s*)?)(?:"([A-Za-z]:\\(?:Users|ProgramData|tools|apps|opt|temp)\\[^"\r\n]+?\.(?:exe|bat|cmd|ps1|py)|\/(?:opt|home|usr\/local|srv|var\/backups)\/[^"\r\n]+)"|'([A-Za-z]:\\(?:Users|ProgramData|tools|apps|opt|temp)\\[^'\r\n]+?\.(?:exe|bat|cmd|ps1|py)|\/(?:opt|home|usr\/local|srv|var\/backups)\/[^'\r\n]+)'|([A-Za-z]:\\(?:Users|ProgramData|tools|apps|opt|temp)\\[^\s"'\r\n]+?\.(?:exe|bat|cmd|ps1|py)|\/(?:opt|home|usr\/local|srv|var\/backups)\/[^\s"'\r\n]+))\s+([^\r\n|;>&]+)$/i.exec(line);
      if (!hm) return;
      var binFull = hm[1] || hm[2] || hm[3] || '';
      var argTail = (hm[4] || '').trim();
      var binBase = binFull.split(/[\\/]/).pop() || '';
      if (!binBase || _NOTABLE_IGNORE_RE.test(binFull) || _HIST_IGNORE_TOOL_RE.test(binBase)) return;
      var args = C._tokenize ? C._tokenize(argTail) : argTail.split(/\s+/);
      if (!args.length || args.length > 4) return;
      var hasActionCompanion = args.some(function (a) { return _HIST_ACTION_VERB_RE.test(a); });
      if (!hasActionCompanion && !isHistCmd) return;
      args.forEach(function (tok) {
        if (!tok || tok.length < 6 || tok.length > 64) return;
        if (/^[-/]/.test(tok) || /[\\/:]/.test(tok)) return;
        if (/^\d+$/.test(tok) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(tok)) return;
        if (_HIST_NONSECRET_WORD_RE.test(tok)) return;
        var cls = _char_classes(tok);
        if (cls < 2 || (!hasActionCompanion && (tok.length < 8 || cls < 2))) return;
        if (!C._valid_password(tok)) return;
        var hKey = 'hist|' + tok;
        if (seen[hKey]) return;
        seen[hKey] = true;
        _add(facts, mkFact('credential.candidate', h, { password: tok, binary: binBase, via: 'history-custom-cli' }, S, source));
      });
    });
    reAll(_PS_SECURESTRING_RE, text).forEach(function (m) {
      var pw = (m.groups.pw || '').trim();
      if (!pw || _PS_TUTORIAL_PW_DENY_RE.test(pw) || /^\$[A-Za-z_]|^<[^>]+>$/.test(pw)) return;
      var key = '|' + pw;
      if (seen[key]) return;
      seen[key] = true;
      _add(facts, mkFact('credential.candidate', h, { password: pw, via: 'convertto-securestring' }, S, source));
    });
    if (_DPAPI_HEX_BLOB_RE.test(text)) {
      _add(facts, mkFact('credential.candidate', h, { kind: 'dpapi_securestring', via: 'dpapi-blob' }, S, source));
      if (!facts.some(function (f) { return f && f.kind === 'privesc.stored_credentials' && f.scope === h; })) {
        var dpLeadKinds = {};
        _add_host_privesc_fact(facts, ws, source, 'privesc.stored_credentials', { kinds: ['dpapi'], count: 1 }, dpLeadKinds);
        _add_privesc_leads(facts, ws, source, dpLeadKinds);
      }
    }
    // PuTTY stored proxy credential - pair the ProxyPassword value with the nearest ProxyUsername.
    var pwm = reSearch(_PUTTY_PROXYPW_RE, text);
    if (pwm) {
      var pw2 = C.stripChars(pwm.groups.pw.trim(), "'\"");
      var um = reSearch(_PUTTY_PROXYUSER_RE, text);
      var user2 = um ? um.groups.user : '';
      var key2 = user2 + '|' + pw2;
      if (pw2 && pw2 !== '0' && !seen[key2]) {
        seen[key2] = true;
        var val = { password: pw2, via: 'putty_registry' };
        if (user2) val.user = user2;
        _add(facts, mkFact('credential.candidate', h, val, S, source));
      }
    }
  }
  C._parse_windows_creds = _parse_windows_creds;

  // ── Notable local programs ("unblock a stuck box") → host.notable_program ─────────
  // A bespoke executable/script in a user-controllable location, or whose NAME suggests it holds/uses
  // secrets. A lead to inspect ("run this and read what it leaks"), never access on its own.
  var _NOTABLE_NAME_RE = /admin|tool(?:kit)?|connect|console|backup|restore|cred(?:ential)?|passw|secret|vault|keepass|manage(?:r|ment)?|deploy|launch(?:er)?|updat(?:e|er)|agent|helper|remote|vpn|token|keychain|setup|install(?:er)?|\bsvc\b|service|runner|automat/i;
  var _NOTABLE_EXE_RE = /(?<![\w.\-])(?<name>[\w.\-]{1,60}\.(?:exe|bat|cmd|ps1|vbs|sh|py|pl|rb|jar|bin|run|elf))\b/gi;
  var _NOTABLE_DIRHDR_RE = /Directory of\s+(?<d>[A-Za-z]:\\[^\r\n]+?)\s*$/im;
  var _NOTABLE_LDIR_RE = /^(?<d>\/[^\r\n:]+):\s*$/;
  var _NOTABLE_IGNORE_RE = /\\Windows\\(?:System32|SysWOW64|WinSxS|servicing|Microsoft\.NET)\\|\/usr\/(?:bin|sbin|lib)\/|(?:^|[\\/])(?:s?bin)\/|python\d|\bpip\d?\b|winpeas|linpeas|pspy|mimikatz|rubeus|powerview|seatbelt|sharphound|godpotato|printspoofer|\.dll$|conhost|svchost|dllhost|taskhostw?|msedge|chrome|firefox|OneDrive|Teams\.exe/i;
  var _NOTABLE_USER_LOC_RE = /[A-Za-z]:\\Users\\[^\\\r\n]+\\(?:Desktop|Documents|Downloads|Public|Scripts)|\/home\/[^/\r\n]+\/|\/root\/|\/opt\/|\/tmp\/|\/srv\/|\/usr\/local\/|\/var\/backups\//i;
  var _NOTABLE_WIN_EXT_RE = /\.(?:exe|bat|cmd|ps1|vbs)$/i;

  var _SW_TABLE_HDR_RE = /^(?!.*\b(?:ModuleType|CommandType|ExportedCommands)\b)\s*(?:ProgramName|DisplayName|Name)(?:\s{2,}|\t+)(?:DisplayVersion|Version)\b/im;
  var _SW_FL_CHECK_RE = /^\s*(?:ProgramName|DisplayName)\s*:\s*\S+[\s\S]{1,240}?^\s*(?:DisplayVersion|Version)\s*:\s*\d+\.\d+/im;
  var _SW_BASELINE_IGNORE_RE = /^(?:Microsoft\s+(?:Visual\s+C\+\+|Windows\b|\.NET\b|Edge\b|Update\b|OneDrive\b|Silverlight\b|Office\b|SQL\s+Server\s+\d*\s*(?:Native\s+Client|Setup|T-SQL|Transact-SQL|Browser|System\s+CLR)|ASP\.NET\b|Application\s+Error\s+Reporting|SDK\b|System\s+Center|VC\+\+|PowerShell|GameInput|WebView2)|Windows\s+(?:Software\s+Development\s+Kit|SDK|Driver\s+Package|App\s+Certification|Defender|PC\s+Health)|\.NET\s+Framework|VMware\s+Tools|VirtualBox\s+Guest\s+Additions|QEMU\s+guest\s+agent|Spice\s+Guest\s+Tools|XenServer\s+Tools|Google\s+(?:Chrome|Update)|Mozilla\s+(?:Firefox|Maintenance\s+Service)|PowerShellGet|PackageManagement|PSReadLine|Pester|ThreadJob|CimCmdlets)(?:\b|(?=\s|$|[().,/:-]))/i;

  function _re_escape(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function _has_notable_programs(text) {
    if (!text) return false;
    var t = text.length > 65536 ? (text.slice(0, 32768) + '\n' + text.slice(-32768)) : text;
    return !!(reSearch(_NOTABLE_EXE_RE, t) || _SW_TABLE_HDR_RE.test(t) || _SW_FL_CHECK_RE.test(t)
      || /(?:[\u2550\u2500]+[\u2563\u2524]|={3,}|-{3,})\s*(?:Unexpected in|Files inside|Executable files potentially added by user)\b/i.test(t));
  }
  C._has_notable_programs = _has_notable_programs;

  function _emit_installed_software_row(facts, h, source, rawName, rawVer, seenSw) {
    var progName = String(rawName || '').trim().replace(/^["']|["']$/g, '');
    var progVerRaw = String(rawVer || '').trim().replace(/^["']|["']$/g, '');
    if (!progName || progName.length < 2 || progName.length > 120 || /^-+$/.test(progName) || !/[A-Za-z]{2,}/.test(progName)) return;
    if (_SW_BASELINE_IGNORE_RE.test(progName)) return;
    var verM = /\b(\d+\.\d+(?:\.\d+)*)\b/.exec(progVerRaw);
    if (!verM) return;
    var verTok = verM[1];
    var swKey = progName.toLowerCase() + '|' + verTok;
    if (seenSw[swKey]) return;
    seenSw[swKey] = 1;
    var cleanProd = progName
      .replace(/\s*\((?:x64|x86|64-bit|32-bit|amd64)[^)]*\)\s*/gi, ' ')
      .replace(/\s+v?\d+(?:\.\d+)+\b.*$/i, '')
      .replace(/\s+/g, ' ')
      .trim() || progName;
    var mmVerM = /^(\d+\.\d+)/.exec(verTok);
    var shortVer = mmVerM ? mmVerM[1] : verTok;
    _add(facts, mkFact('host.notable_program', h, { name: progName, version: verTok, reason: 'installed third-party software', os: 'windows' }, S, source));
    _add(facts, mkFact('exploit.versioned_banner', h, { product: cleanProd, version: verTok, search_query: (cleanProd + ' ' + shortVer).trim(), os: 'windows', via: 'installed-software' }, S, source));
  }

  function _split_sw_row_by_spaces(rLn, nameCol, verCol) {
    var parts = rLn.trim().split(/\s{2,}/);
    if (parts.length < 2) return null;
    if (verCol < nameCol) {
      return { name: parts.slice(1).join(' '), ver: parts[0] };
    }
    var vIdx = -1;
    for (var pi = 1; pi < parts.length; pi++) {
      if (/^["']?[vV]?\d+\.\d+/.test(parts[pi].trim())) { vIdx = pi; break; }
    }
    if (vIdx < 0) {
      if (verCol < parts.length && /\d+\.\d+/.test(parts[verCol])) vIdx = verCol;
      else vIdx = 1;
    }
    return { name: parts.slice(0, vIdx).join(' '), ver: parts[vIdx] };
  }

  function _sw_col_boundary_ok(rLn, colIdx, colStart, hasDash) {
    if (colStart === 0) return true;
    if (colStart >= rLn.length) return false;
    if (colIdx === 0) return /^\s*$/.test(rLn.slice(0, colStart));
    return hasDash ? /\s/.test(rLn.charAt(colStart - 1)) : (colStart >= 2 && /\s{2}$/.test(rLn.slice(0, colStart)));
  }

  function _parse_notable_programs(text, ws, source, facts) {
    var seen = {}, seenSw = {}, currentDir = '', h = 'host:' + ws.target;
    var lines = String(text || '').split(/\r?\n/);
    if (_SW_TABLE_HDR_RE.test(text)) {
      for (var ti = 0; ti < lines.length; ti++) {
        var hdr = lines[ti];
        if (!/^(?!.*\b(?:ModuleType|CommandType|ExportedCommands)\b)\s*(?:ProgramName|DisplayName|Name)(?:\s{2,}|\t+)(?:DisplayVersion|Version)\b/i.test(hdr)) continue;
        var hasDash = (ti + 1 < lines.length) && /^\s*-+(?:\s+-+)+\s*$/.test(lines[ti + 1]);
        var colStarts = [], colNames = [];
        if (hasDash) {
          var dLine = lines[ti + 1], dm2, dRe = /-+/g;
          while ((dm2 = dRe.exec(dLine)) !== null) colStarts.push(dm2.index);
          for (var ci = 0; ci < colStarts.length; ci++) {
            var ce = (ci + 1 < colStarts.length) ? colStarts[ci + 1] : hdr.length;
            colNames.push(hdr.slice(colStarts[ci], ce).trim().toLowerCase());
          }
        } else {
          var hRe = /\S+/g, hm2;
          while ((hm2 = hRe.exec(hdr)) !== null) {
            colStarts.push(hm2.index);
            colNames.push(hm2[0].trim().toLowerCase());
          }
        }
        var nameCol = -1, verCol = -1;
        for (var cni = 0; cni < colNames.length; cni++) {
          if (nameCol < 0 && /^(?:programname|displayname|name)$/.test(colNames[cni])) nameCol = cni;
          if (verCol < 0 && /^(?:displayversion|version)$/.test(colNames[cni])) verCol = cni;
        }
        if (nameCol < 0 || verCol < 0) continue;
        var rowStart = hasDash ? ti + 2 : ti + 1;
        for (var ri = rowStart; ri < lines.length; ri++) {
          var rLn = lines[ri];
          if (!rLn.trim()) break;
          if (/^\s*(?:PS\s+[A-Za-z]:\\|\*Evil-WinRM\*\s+PS\b|[A-Za-z]:\\[^>\r\n]*>)/i.test(rLn)) break;
          var rName = '', rVer = '';
          if (rLn.trim().indexOf('\t') >= 0) {
            var tParts = rLn.trim().split(/\t+/);
            rName = tParts[nameCol] || '';
            rVer = tParts[verCol] || '';
          } else if (colStarts[verCol] < rLn.length && (!hasDash ? /\s{2,}/.test(rLn.trim()) : true)) {
            var nStart = colStarts[nameCol], vStart = colStarts[verCol];
            var nEnd = (nameCol + 1 < colStarts.length) ? colStarts[nameCol + 1] : rLn.length;
            var vEnd = (verCol + 1 < colStarts.length) ? colStarts[verCol + 1] : rLn.length;
            var boundaryOk = _sw_col_boundary_ok(rLn, nameCol, nStart, hasDash) &&
                             _sw_col_boundary_ok(rLn, verCol, vStart, hasDash);
            if (boundaryOk) {
              rName = rLn.slice(nStart, Math.min(nEnd, rLn.length)).trim();
              rVer = rLn.slice(vStart, Math.min(vEnd, rLn.length)).trim();
            }
            var verValid = !!rName && !!rVer && /^["']?[vV]?\d+\.\d+/.test(rVer) &&
                           (verCol + 1 < colStarts.length || !/\s{2,}/.test(rVer)) &&
                           !/\s{2,}["']?[vV]?\d+\.\d+/.test(rName);
            if (!boundaryOk || !verValid) {
              var spFallback = _split_sw_row_by_spaces(rLn, nameCol, verCol);
              if (spFallback) { rName = spFallback.name; rVer = spFallback.ver; }
            }
          } else {
            var spFallback2 = _split_sw_row_by_spaces(rLn, nameCol, verCol);
            if (spFallback2) { rName = spFallback2.name; rVer = spFallback2.ver; }
          }
          _emit_installed_software_row(facts, h, source, rName, rVer, seenSw);
        }
      }
    }
    if (_SW_FL_CHECK_RE.test(text)) {
      String(text || '').split(/\r?\n\s*\r?\n/).forEach(function (blk) {
        var nmM = /^\s*(?:ProgramName|DisplayName)\s*:\s*(.+)$/im.exec(blk);
        var vrM = /^\s*(?:DisplayVersion|Version)\s*:\s*(.+)$/im.exec(blk);
        if (nmM && vrM) _emit_installed_software_row(facts, h, source, nmM[1], vrM[1], seenSw);
      });
    }
    var inNotableUserAdded = false;
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/\bin\s+[\w.]+\s*\(|^\s*File\s+"[^"]+",\s+line\s+\d+|^\s*Traceback\b|\b[\w]+\.run\s*\(|^\s*usage:\s+\S+/i.test(line)) continue;
      var lpDirM = /(?:[\u2550\u2500]+[\u2563\u2524]|={3,}|-{3,})\s*(?:Unexpected in|Files inside)\s+(\/[A-Za-z0-9_.\-\/]+)/i.exec(line);
      if (lpDirM) { currentDir = lpDirM[1].trim().replace(/\/+$/, ''); inNotableUserAdded = false; continue; }
      if (/(?:[\u2550\u2500]+[\u2563\u2524]|={3,}|-{3,})\s*Executable files potentially added by user\b/i.test(line)) {
        inNotableUserAdded = true;
        currentDir = '';
        continue;
      }
      if (/[\u2550\u2500]+[\u2563\u2524]/.test(line)) { currentDir = ''; inNotableUserAdded = false; continue; }
      if (inNotableUserAdded) {
        var uaPathM = /^\s*\d{4}-\d{2}-\d{2}\+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(\/[^\s\r\n]+)\s*$/.exec(line);
        if (uaPathM) {
          var uaCustom = _check_linux_custom_binary(uaPathM[1]);
          if (uaCustom && !reSearch(_NOTABLE_IGNORE_RE, uaCustom.path)) {
            var uaKey = uaCustom.path.toLowerCase();
            if (!seen[uaKey]) {
              seen[uaKey] = true;
              _add(facts, mkFact('host.notable_program', h, { name: uaCustom.binary, path: uaCustom.path, reason: 'user-added executable', os: 'linux' }, S, source));
              if (Object.keys(seen).length >= 15) return;
            }
          }
          continue;
        }
      }
      var dm = reSearch(_NOTABLE_DIRHDR_RE, line);
      if (dm) { currentDir = dm.groups.d.trim(); continue; }
      var lm = _NOTABLE_LDIR_RE.exec(line);
      if (lm) { currentDir = lm.groups.d.trim(); continue; }
      var exeMatches = reAll(_NOTABLE_EXE_RE, line);
      for (var ei = 0; ei < exeMatches.length; ei++) {
        var name = exeMatches[ei].groups.name.trim();
        if (!name) continue;
        // resolve the file's path: a full path on this line, else the current directory context
        var full = new RegExp("(?:[A-Za-z]:\\\\[^\\s\"'|<>]+|/[^\\s\"'|<>]+)?" + _re_escape(name)).exec(line);
        var token = full ? full[0] : name;
        var path;
        if (token.indexOf('\\') >= 0 || token.indexOf('/') >= 0) path = token;
        else if (currentDir) {
          var sep = currentDir.indexOf('\\') >= 0 ? '\\' : '/';
          path = C.stripChars(currentDir, '\\/') + sep + name;
        } else path = name;
        if (reSearch(_NOTABLE_IGNORE_RE, path)) continue;
        var suggestive = !!reSearch(_NOTABLE_NAME_RE, name);
        var userLoc = !!reSearch(_NOTABLE_USER_LOC_RE, path);
        if (!(suggestive || userLoc)) continue;
        var key = path.toLowerCase();
        if (seen[key]) continue;
        seen[key] = true;
        var reason = (suggestive && userLoc) ? 'suggestive name in a user location'
          : suggestive ? 'suggestive name' : 'bespoke program in a user location';
        var win = !!(reSearch(_NOTABLE_WIN_EXT_RE, name) || path.indexOf('\\') >= 0);
        _add(facts, mkFact('host.notable_program', h, { name: name, path: path, reason: reason, os: win ? 'windows' : 'linux' }, S, source));
        if (Object.keys(seen).length >= 15) return;
      }
    }
  }
  C._parse_notable_programs = _parse_notable_programs;

  // ── schtasks /query /v → scheduled-task privesc lead ───────────────────────────────
  // `schtasks /query /v /fo list` prints one block per task: `TaskName:`, `Run As User:`,
  // `Task To Run:`. A task that runs as SYSTEM or an admin AND points at a concrete path is a privesc
  // lead (replace/overwrite that binary - or its directory - and you inherit the run-as identity).
  // Content-gated: only a block that names a privileged run-as AND a path mints; a task run as the
  // current user, or one with no path (N/A / a COM handler), mints nothing.
  var _SCHTASKS_FIELD_RE = /^\s*(?<key>TaskName|Run As User|Task To Run)\s*:\s*(?<value>.+?)\s*$/gim;
  var _SCHTASKS_PRIV_RUNAS_RE = /\b(?:system|localsystem|administrator|admin|domain admins|nt authority\\system)\b/i;
  var _SCHTASKS_PATH_RE = /(?:[A-Za-z]:\\|\\\\)[^\r\n]+/;

  function _looks_like_schtasks(text) {
    var t = text || '';
    return /^\s*Task To Run\s*:/im.test(t) && /^\s*Run As User\s*:/im.test(t);
  }
  C._looks_like_schtasks = _looks_like_schtasks;

  function _parse_schtasks(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var tasks = [], cur = null;
    reAll(_SCHTASKS_FIELD_RE, text).forEach(function (m) {
      var key = m.groups.key.toLowerCase(), val = m.groups.value.trim();
      if (key === 'taskname') { if (cur) tasks.push(cur); cur = { name: val, run_as: '', run: '' }; return; }
      if (!cur) cur = { name: '', run_as: '', run: '' };
      if (key === 'run as user') cur.run_as = val;
      else if (key === 'task to run') cur.run = val;
    });
    if (cur) tasks.push(cur);
    var leads = [], seen = {};
    tasks.forEach(function (t) {
      if (!t.run_as || !t.run) return;
      if (!_SCHTASKS_PRIV_RUNAS_RE.test(t.run_as)) return;
      var pm = reSearch(_SCHTASKS_PATH_RE, t.run);
      if (!pm) return;
      var pathTok = pm[0].trim();
      var key = (t.name + '|' + pathTok).toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      leads.push({ task: t.name, run_as: t.run_as, path: pathTok });
    });
    if (!leads.length) return;
    var leadKinds = {};
    _add_host_privesc_fact(facts, ws, source, 'privesc.scheduled_task', { tasks: leads.slice(0, 20), count: leads.length }, leadKinds);
    var taskCustom = [], seenTaskCustom = {};
    leads.forEach(function (item) {
      var hit = _check_windows_custom_binary(item.path);
      if (!hit) return;
      var k = hit.path.toLowerCase();
      if (seenTaskCustom[k]) return;
      seenTaskCustom[k] = 1;
      taskCustom.push({ custom_bin: hit.path, path: hit.path, binary: hit.binary, context: 'task', task: item.task, os: 'windows' });
    });
    if (taskCustom.length) {
      var topTask = taskCustom[0];
      _add_host_privesc_fact(facts, ws, source, 'privesc.custom_binary', {
        custom_bin: topTask.path,
        path: topTask.path,
        binary: topTask.binary,
        context: 'task',
        os: 'windows',
        candidates: taskCustom.slice(0, 20)
      }, leadKinds);
    }
    _add_privesc_leads(facts, ws, source, leadKinds);
  }
  C._parse_schtasks = _parse_schtasks;

  // ── reg query → Winlogon autologon / stored credentials ────────────────────────────
  // Winlogon autologon (DefaultUserName/DefaultPassword REG_SZ) is a real cleartext login; common
  // stored-cred keys (VNC Password, PuTTY session proxy creds, SNMP ValidCommunities) are candidate
  // material. Content-gated so an unrelated reg dump with no credential-ish value mints nothing.
  var _REG_DEFAULT_PW_RE = /^\s*DefaultPassword\s+(?:REG_SZ\s+|:\s*)(?<pw>\S.*?)\s*$/im;
  var _REG_DEFAULT_USER_RE = /^\s*DefaultUserName\s+(?:REG_SZ\s+|:\s*)(?<user>\S.*?)\s*$/im;
  var _REG_DEFAULT_DOMAIN_RE = /^\s*DefaultDomainName\s+(?:REG_SZ\s+|:\s*)(?<dom>\S.*?)\s*$/im;
  var _REG_VNC_PW_RE = /^\s*(?:Password|ControlPassword|PasswordViewOnly)\s+REG_(?:BINARY|SZ)\s+(?<pw>\S.*?)\s*$/im;
  var _REG_PROXY_PW_RE = /^\s*ProxyPassword\s+REG_SZ\s+(?<pw>\S.*?)\s*$/im;
  var _REG_PROXY_USER_RE = /^\s*ProxyUsername\s+REG_SZ\s+(?<user>\S+)/im;
  var _REG_PUTTY_SESSION_RE = /SimonTatham\\PuTTY\\Sessions/i;
  var _REG_SNMP_COMMUNITIES_RE = /SNMP\\Parameters\\ValidCommunities/i;
  var _REG_VALUE_NAME_RE = /^\s*(?<name>\S+)\s+REG_(?:SZ|DWORD|BINARY|EXPAND_SZ|MULTI_SZ|QWORD)\s+/i;

  function _looks_like_reg_query(text) {
    var t = text || '';
    if (reSearch(_REG_DEFAULT_PW_RE, t)) return true;
    if (/vnc/i.test(t) && reSearch(_REG_VNC_PW_RE, t)) return true;
    if (reSearch(_REG_PUTTY_SESSION_RE, t) || reSearch(_REG_PROXY_PW_RE, t)) return true;
    if (reSearch(_REG_SNMP_COMMUNITIES_RE, t)) return true;
    return false;
  }
  C._looks_like_reg_query = _looks_like_reg_query;

  function _parse_reg_query(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var h = 'host:' + ws.target, kinds = {};
    // 1) Winlogon autologon -> cleartext credential
    var pwm = reSearch(_REG_DEFAULT_PW_RE, text);
    if (pwm) {
      var pw = C.stripChars(pwm.groups.pw.trim(), "'\"");
      if (pw && pw !== '0') {
        var val = { password: pw, via: 'winlogon_autologon' };
        var um = reSearch(_REG_DEFAULT_USER_RE, text);
        if (um) { var u = C._clean_username(um.groups.user.trim()); if (u) val.user = u; }
        var dm = reSearch(_REG_DEFAULT_DOMAIN_RE, text);
        if (dm && dm.groups.dom.trim()) val.domain = dm.groups.dom.trim();
        _add(facts, mkFact('credential.candidate', h, val, S, source));
        if (val.user && C._valid_username(val.user, false) && C._valid_password(pw) && C._add_plaintext_credential) {
          C._add_plaintext_credential(facts, ws, source, val.user, pw, val.domain || C._domain_from_facts(ws), 'winlogon_autologon', '');
        }
        kinds.autologon = true;
      }
    }
    // 2) VNC stored password
    if (/vnc/i.test(text)) {
      var vm = reSearch(_REG_VNC_PW_RE, text);
      if (vm) {
        var vpw = C.stripChars(vm.groups.pw.trim(), "'\"");
        if (vpw) {
          _add(facts, mkFact('credential.candidate', h, { kind: 'vnc_password', value: vpw, via: 'vnc_registry' }, S, source));
          kinds.vnc = true;
        }
      }
    }
    // 3) PuTTY session proxy credential (stored in plaintext under PuTTY\Sessions)
    if (reSearch(_REG_PUTTY_SESSION_RE, text) || reSearch(_REG_PROXY_PW_RE, text)) {
      var ppm = reSearch(_REG_PROXY_PW_RE, text);
      if (ppm) {
        var ppw = C.stripChars(ppm.groups.pw.trim(), "'\"");
        if (ppw && ppw !== '0') {
          var pval = { password: ppw, via: 'putty_registry' };
          var pum = reSearch(_REG_PROXY_USER_RE, text);
          if (pum) { var pu = C._clean_username(pum.groups.user.trim()); if (pu) pval.user = pu; }
          _add(facts, mkFact('credential.candidate', h, pval, S, source));
        }
      }
      kinds.putty = true;
    }
    // 4) SNMP community strings (the value NAMES under the ValidCommunities key)
    if (reSearch(_REG_SNMP_COMMUNITIES_RE, text)) {
      var communities = [], seenC = {}, inBlock = false;
      text.split(/\r?\n/).forEach(function (raw) {
        if (reSearch(_REG_SNMP_COMMUNITIES_RE, raw)) { inBlock = true; return; }
        if (/^\s*HKEY_/i.test(raw)) { inBlock = false; return; }
        if (!inBlock) return;
        var vn = reSearch(_REG_VALUE_NAME_RE, raw);
        if (vn) {
          var name = vn.groups.name.trim();
          if (name && name.toLowerCase() !== '(default)' && !seenC[name.toLowerCase()]) { seenC[name.toLowerCase()] = true; communities.push(name); }
        }
      });
      if (communities.length) {
        _add(facts, mkFact('credential.candidate', h, { kind: 'snmp_community', communities: communities.slice(0, 20), via: 'snmp_registry' }, S, source));
        kinds.snmp = true;
      }
    }
    var kindList = C.uniqueSortedCI(Object.keys(kinds));
    if (kindList.length) _add(facts, mkFact('privesc.stored_credentials', h, { kinds: kindList, count: kindList.length }, S, source));
  }
  C._parse_reg_query = _parse_reg_query;

  var _ICACLS_PATH_RE = /(?:[A-Za-z]:\\|\\\\)(?:[^\r\n:()]|:(?=\\))*?\.(?:exe|dll|bat|cmd|ps1|sys|msi|vbs|jar|scr)\b/i;
  var _ICACLS_DIR_PATH_RE = /[A-Za-z]:\\(?:[^\r\n:()]|:(?=\\))*(?:Program Files(?: \(x86\))?|ProgramData|inetpub|xampp|wamp)(?:\\[^\r\n:()]*)?/i;
  var _ACCESSCHK_WRITE_RE = /^\s*(?:RW|W)\s+(?:BUILTIN\\Users|Everyone|NT AUTHORITY\\(?:Authenticated Users|INTERACTIVE)|Authenticated Users|\bUsers\b)/im;
  var _ACCESSCHK_SVC_HDR_RE = /^\s*RW\s+([A-Za-z0-9_.-]{2,64})\s*$/;

  var _REG_CLSID_PATH_RE = /(?:Microsoft\.PowerShell\.Core\\Registry::)?(?:HKEY_CLASSES_ROOT|HKCR|HKLM:?\\SOFTWARE\\Classes|HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes):?\\CLSID\\\{[0-9A-Fa-f-]{36}\}(?:\\InProcServer32|\b)/i;
  var _ICACLS_INHERITED_ACE_RE = /(?:^|\s)(?<principal>(?:[A-Za-z0-9_.-]+\\)?[A-Za-z0-9_. $-]{2,64}?):(?:\((?:I|OI|CI|IO|NP)\))+\((?<rights>F|M|W|GW|GA|WD|AD|WA|[^\r\n()]*?(?:WD|AD|WriteData|CreateFiles|Modify|Full)[^\r\n()]*)\)/i;
  var _ICACLS_NONADMIN_WRITE_ACE_RE = /(?:^|\s)(?<principal>(?:[A-Za-z0-9_.-]+\\)[A-Za-z0-9_. $-]{2,64}|Everyone|Authenticated Users|Users):(?:\((?:I|OI|CI|IO|NP)\))*\((?<rights>F|M|W|GW|GA|WD|AD|WA|[^\r\n()]*?(?:WD|AD|WriteData|CreateFiles|Modify|Full)[^\r\n()]*)\)/i;
  var _GETACL_INLINE_ALLOW_RE = /(?<principal>(?:[A-Za-z0-9_.-]+\\)[A-Za-z0-9_. $-]{2,48}|Everyone|Authenticated Users|Users)\s+Allow\s+(?<rights>(?:FullControl|Modify|WriteData|CreateFiles|WriteKey|SetValue|CreateSubKey|GenericAll|GenericWrite|\bWrite\b)(?:,\s*[A-Za-z]+)*)/gi;
  var _GETACL_HDR_RE = /^\s*Path\s+Owner\s+Access\b|^\s*(?:FileSystemRights|RegistryRights)\s*:|(?:HKEY_CLASSES_ROOT|HKCR|HKLM:?\\SOFTWARE\\Classes):?\\CLSID\\\{[0-9A-Fa-f-]{36}\}/im;

  function _looks_like_icacls_accesschk(text) {
    var raw = text || '';
    var t = raw.length > 65536 ? (raw.slice(0, 32768) + '\n' + raw.slice(-32768)) : raw;
    var hasColonParen = t.indexOf(':') >= 0 && t.indexOf('(') >= 0;
    return !!(reSearch(C._LOWPRIV_WRITE_ACE_RE, t) || (hasColonParen && (_ICACLS_INHERITED_ACE_RE.test(t) || _ICACLS_NONADMIN_WRITE_ACE_RE.test(t))) || _GETACL_HDR_RE.test(t) || reSearch(_ACCESSCHK_WRITE_RE, t) || (reSearch(C._WEAK_SVC_ACCESS_RE, t) && /^\s*RW\s+[A-Za-z0-9_.-]+\s*$/m.test(t)));
  }
  C._looks_like_icacls_accesschk = _looks_like_icacls_accesschk;

  function _program_path_from_line(line) {
    var rm = reSearch(_REG_CLSID_PATH_RE, String(line || ''));
    if (rm) return rm[0].replace(/^Microsoft\.PowerShell\.Core\\Registry::/i, '').trim();
    var cleaned = String(line || '').replace(/Microsoft\.PowerShell\.Core\\FileSystem::/gi, '');
    var m = reSearch(_ICACLS_PATH_RE, cleaned);
    if (m) return m[0].trim();
    m = reSearch(_ICACLS_DIR_PATH_RE, cleaned);
    if (m) return m[0].trim();
    var sm = _ACCESSCHK_SVC_HDR_RE.exec(cleaned);
    if (sm && !/^(?:BUILTIN|Everyone|Authenticated|Users|NT)$/i.test(sm[1])) return sm[1].trim();
    return '';
  }

  function _parse_icacls_accesschk(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var currentPath = '', evidence = [], seen = {}, paths = {}, leadKinds = {};
    var cmdPathM = _program_path_from_line(command || '') || (/\bget-acl\b[^\r\n]*?([A-Za-z]:\\[^"'\s|]+|\S+\.(?:exe|dll|ps1|bat|cmd|vbs))/i.exec(command || '') || [])[1] || '';
    if (cmdPathM) currentPath = cmdPathM.replace(/^["']|["']$/g, '').trim();

    var lastRwHighPriv = false;
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.replace(/[ \t]+$/, '');
      if (!line.trim()) { lastRwHighPriv = false; return; }
      var p = _program_path_from_line(line);
      if (p) currentPath = p;
      var relBinM = !currentPath ? /^\s*([A-Za-z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd|vbs))\s+\S+\\/i.exec(line) : null;
      if (relBinM) currentPath = relBinM[1];
      var rwM = /^\s*(?:RW|R|W)\s+(.+?)\s*$/i.exec(raw);
      if (rwM) {
        lastRwHighPriv = _WIN_HIGHPRIV_ACL_PRINCIPAL_RE.test(rwM[1].trim());
      } else if (!/^\s+/.test(raw)) {
        lastRwHighPriv = false;
      }
      if (!currentPath || lastRwHighPriv || _line_has_only_highpriv_acl(line)) return;

      var aceM = _ICACLS_NONADMIN_WRITE_ACE_RE.exec(line) || _ICACLS_INHERITED_ACE_RE.exec(line);
      var validNonAdminAce = !!(aceM && !_WIN_HIGHPRIV_ACL_PRINCIPAL_RE.test(aceM.groups.principal.trim()));
      var matchedGetAcl = false;
      _GETACL_INLINE_ALLOW_RE.lastIndex = 0;
      var gam;
      while ((gam = _GETACL_INLINE_ALLOW_RE.exec(line)) !== null) {
        var gaPrin = gam.groups.principal.trim();
        if (_WIN_HIGHPRIV_ACL_PRINCIPAL_RE.test(gaPrin)) continue;
        matchedGetAcl = true;
        _emit_writable_win_custom_binary(facts, ws, source, currentPath, gaPrin, gam.groups.rights, leadKinds);
      }

      if (!(reSearch(C._LOWPRIV_WRITE_ACE_RE, line) || validNonAdminAce || matchedGetAcl || reSearch(_ACCESSCHK_WRITE_RE, line) || reSearch(C._WEAK_SVC_ACCESS_RE, line))) return;
      if (validNonAdminAce) {
        _emit_writable_win_custom_binary(facts, ws, source, currentPath, aceM.groups.principal, aceM.groups.rights, leadKinds);
      } else if (reSearch(C._LOWPRIV_WRITE_ACE_RE, line)) {
        var lpM = /((?:BUILTIN\\Users|Everyone|Authenticated Users|NT AUTHORITY\\Authenticated Users|\bUsers\b))/i.exec(line);
        _emit_writable_win_custom_binary(facts, ws, source, currentPath, lpM ? lpM[1] : 'Users', 'Modify', leadKinds);
      }
      var trimmed = line.trim();
      var ev = (trimmed.indexOf(currentPath) === 0 ? trimmed : currentPath + ' ' + trimmed).slice(0, 220), key = ev.toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      evidence.push(ev);
      paths[currentPath] = true;
    });

    // Get-Acl Format-List blocks (FileSystemRights / RegistryRights / AccessControlType / IdentityReference)
    if (/(?:FileSystemRights|RegistryRights)\s*:/i.test(text) && /IdentityReference\s*:/i.test(text)) {
      var flBlocks = text.split(/\r?\n\s*\r?\n/);
      flBlocks.forEach(function (blk) {
        var bp = _program_path_from_line(blk) || currentPath;
        if (!bp) return;
        if (!/AccessControlType\s*:\s*Allow/i.test(blk)) return;
        var fsrM = /(?:FileSystemRights|RegistryRights)\s*:\s*([^\r\n]*(?:FullControl|Modify|WriteData|CreateFiles|WriteKey|SetValue|CreateSubKey|GenericAll|GenericWrite|\bWrite\b)[^\r\n]*)/i.exec(blk);
        var idrM = /IdentityReference\s*:\s*([^\r\n]+)/i.exec(blk);
        if (!fsrM || !idrM) return;
        var flPrin = idrM[1].trim();
        if (_WIN_HIGHPRIV_ACL_PRINCIPAL_RE.test(flPrin)) return;
        _emit_writable_win_custom_binary(facts, ws, source, bp, flPrin, fsrM[1].trim(), leadKinds);
        var flEv = (bp + ' ' + flPrin + ' Allow ' + fsrM[1].trim()).slice(0, 220);
        if (!seen[flEv.toLowerCase()]) {
          seen[flEv.toLowerCase()] = true;
          evidence.push(flEv);
          paths[bp] = true;
        }
      });
    }

    if (!evidence.length) return;
    var lcCmd = (command || '').toLowerCase();
    var aclTool = lcCmd.indexOf('accesschk') >= 0 ? 'accesschk' : (lcCmd.indexOf('get-acl') >= 0 || _GETACL_HDR_RE.test(text) ? 'get-acl' : 'icacls');
    _add_host_privesc_fact(facts, ws, source, 'privesc.weak_service_permission',
      { evidence: evidence.slice(0, 30), paths: Object.keys(paths).sort().slice(0, 20), tool: aclTool }, leadKinds);
    _add_privesc_leads(facts, ws, source, leadKinds);
  }
  C._parse_icacls_accesschk = _parse_icacls_accesschk;

  var _SHADOW_LINE_RE = /(?:^|["'`\s:])(?<u>[a-z_][a-z0-9_.-]{0,31}):(?<h>\$(?:1|2[abxy]|5|6|y)\$[^\s:"'`]+)(?::[^\r\n:"'`]*){4,}/im;
  function _shadow_hash_format(h) {
    if (/^\$6\$/.test(h)) return 'sha512crypt';
    if (/^\$5\$/.test(h)) return 'sha256crypt';
    if (/^\$2[abxy]\$/i.test(h)) return 'bcrypt';
    if (/^\$y\$/.test(h)) return 'yescrypt';
    if (/^\$1\$/.test(h)) return 'md5crypt';
    return 'crypt';
  }
  function _parse_shadow_file(text, command, ws, source, facts) {
    if (!text || text.indexOf(':$') < 0) return;
    var matches = reAll(_SHADOW_LINE_RE, text);
    if (!matches.length) return;
    var hScope = 'host:' + ws.target;
    var users = [], entries = [], seen = {};
    matches.forEach(function (m) {
      var u = m.groups.u, hash = m.groups.h;
      users.push(u);
      var key = u.toLowerCase() + '|' + hash;
      if (seen[key]) return;
      seen[key] = true;
      var fmt = _shadow_hash_format(hash);
      entries.push({ user: u, hash: hash, format: fmt });
      _add(facts, mkFact('hash.crackable', hScope, { user: u, hash: hash, format: fmt, via: 'shadow' }, S, source));
      _add(facts, mkFact('hash.candidate', hScope, { user: u, hash: hash, format: fmt, via: 'shadow' }, S, source));
    });
    var uniqUsers = C.uniqueSortedCI(users);
    _add(facts, mkFact('loot.shadow', hScope, { users: uniqUsers.slice(0, 30), hashes: entries.slice(0, 30), count: uniqUsers.length }, S, source));
    _add(facts, mkFact('credential.candidate', hScope, { kind: 'shadow_hash', users: uniqUsers.slice(0, 30), count: entries.length, via: 'shadow' }, S, source));
  }
  C._parse_shadow_file = _parse_shadow_file;

  // ── endpoint defensive posture (read-only detection) ───────────────────────────────
  // Records which controls are ACTIVE from read-only enumeration output - PowerShell language mode,
  // Microsoft Defender real-time state + configured exclusion paths, and whether an AppLocker policy is
  // applied. Mints defense.control purely as situational awareness so the coach can prefer remote-first
  // and warn before on-host tooling; it detects posture only and asserts nothing about evading any control.
  function _looks_like_defense_enum(text) {
    if (!text) return false;
    return /\b(ConstrainedLanguage|FullLanguage)\b/.test(text) || /AMServiceEnabled|RealTimeProtectionEnabled/i.test(text)
      || /<AppLockerPolicy\b/i.test(text) || /\bExclusionPath\b/i.test(text);
  }
  C._looks_like_defense_enum = _looks_like_defense_enum;

  function _parse_defense_enum(text, ws, command, source, facts) {
    if (!_looks_like_defense_enum(text)) return;
    text = text.replace(C._ANSI_RE, '');
    var val = {}, any = false;
    var lm = text.match(/\b(ConstrainedLanguage|FullLanguage)\b/);
    if (lm) { val.language_mode = lm[1]; if (lm[1] === 'ConstrainedLanguage') val.clm = true; any = true; }
    var rtp = text.match(/RealTimeProtectionEnabled\s*[:=]\s*(True|False)/i);
    var amsvc = text.match(/AMServiceEnabled\s*[:=]\s*(True|False)/i);
    if (rtp || amsvc) { val.defender = !!((rtp && /true/i.test(rtp[1])) || (amsvc && /true/i.test(amsvc[1]))); any = true; }
    if (/<AppLockerPolicy\b/i.test(text)) { val.applocker = true; any = true; }
    if (/\bExclusionPath\b/i.test(text)) {
      var excl = [];
      text.split(/\r?\n/).forEach(function (line) { var t = line.trim(); if (/^[A-Za-z]:\\[^\r\n]+$/.test(t)) excl.push(t); });
      if (excl.length) { val.exclusions = excl.slice(0, 20); val.exclusion_count = excl.length; }
      any = true;
    }
    if (!any) return;
    _add(facts, mkFact('defense.control', 'host:' + ws.target, val, S, source));
  }
  C._parse_defense_enum = _parse_defense_enum;

  // NSClient++ nsclient.ini with a readable admin password (the web-API privesc
  // on 8443). The config stores it in cleartext under a settings section:
  //   [/settings/default]
  //   password = <secret>
  // Shape-based: a `password = <value>` line in an NSClient context (the config
  // path, the product name, or a settings section), so a generic password= line
  // elsewhere does not trip it. An empty `password =` (no value) mints nothing.
  var _NSCLIENT_CTX_RE = /nsclient(?:\+\+)?|\[\/settings\//i;
  var _NSCLIENT_PW_RE = /^\s*password\s*=\s*(?<pw>\S[^\r\n]*)/im;
  function _parse_nsclient_ini(text, ws, command, source, facts) {
    if (!text) return;
    if (!reSearch(_NSCLIENT_CTX_RE, text) && !/nsclient/i.test(command || '')) return;
    var m = reSearch(_NSCLIENT_PW_RE, text);
    if (!m || !m.groups.pw) return;
    var pw = m.groups.pw.trim();
    if (!pw || /^['"]?\s*['"]?$/.test(pw)) return;
    var h = 'host:' + ws.target;
    _add(facts, mkFact('file.nsclient_ini', h, { setting: 'password', value: pw, via: 'nsclient.ini' }, S, source));
    _add(facts, mkFact('credential.candidate', h, { kind: 'nsclient_web_password', user: 'admin', password: pw, via: 'nsclient.ini' }, S, source));
  }
  C._parse_nsclient_ini = _parse_nsclient_ini;

  var _LISTENER_OPEN_RE = /\bListening on\s+(?:\[?(?<host>[0-9a-fA-F.:*]+|any)\]?\s+(?:\([^)\r\n]*\)\s+)?)?(?:port\s+|:)?(?<port>\d{2,5})\b/i;
  var _LISTENER_CONN_RE = /\b(?:connect to \[[^\]]+\] from|Connection received on\s+\S+|Ncat:\s*Connection from\s+\S+)/i;
  var _OUTBOUND_NC_OPEN_RE = /^\(UNKNOWN\)\s+\[\d{1,3}(?:\.\d{1,3}){3}\]\s+\d{1,5}\s+\([^)]*\)\s+open\s*$/im;
  var _POSIX_JOB_CONTROL_STDERR_RE = /\b(?:ba|da|z|k|a)?sh:\s*(?:cannot set terminal process group|no job control in this shell|can't access tty;\s*job control turned off)\b/i;
  var _UBUNTU_POSTLOGIN_HINT_RE = /To run a command as administrator \(user "root"\),\s*use "sudo <command>"\./i;

  function _parse_listener_output(text, ws, command, source, facts) {
    var rawText = String(text || '');
    var followPrompt = (ws && ws.context && ws.context.followPrompt) || '';
    var callerPrompt = (ws && ws.context && ws.context.promptLine) || '';
    if (!rawText && !followPrompt) return;
    var hScope = 'host:' + ws.target;
    var m = rawText ? reSearch(_LISTENER_OPEN_RE, rawText) : null;
    if (m && m.groups && m.groups.port) {
      var p = parseInt(m.groups.port, 10);
      if (p && p >= 1 && p <= 65535) {
        var rawLh = (m.groups.host || '0.0.0.0').replace(/^\[|\]$/g, '');
        var lh = /^any$/i.test(rawLh) ? '0.0.0.0' : rawLh;
        _add(facts, mkFact('listener.open', hScope, { host: lh, port: p }, S, source));
      }
    }
    var connM = rawText ? (_LISTENER_CONN_RE.exec(rawText) || _OUTBOUND_NC_OPEN_RE.exec(rawText)) : null;
    var isListenerCmd = /\b(?:nc|ncat|netcat|socat|pwncat|penelope)\b/i.test(command || '')
      && (/\s-[A-Za-z0-9]*l|\bLISTEN\b/i.test(' ' + (command || '')) || !!m);
    var isPtySpawnTurn = /\bpty\.spawn\s*\(/i.test((command || '') + '\n' + rawText);
    if (!connM && !isListenerCmd && !isPtySpawnTurn) return;

    var isBindConn = !!(connM && /^\(UNKNOWN\)/i.test(connM[0].trim()));
    var shellMethod = isBindConn ? 'bind-shell' : (isPtySpawnTurn && !isListenerCmd ? 'pty-upgrade' : 'reverse-shell');
    var afterConn = connM ? rawText.slice(connM.index + connM[0].length) : rawText;
    var afterWithFollow = followPrompt ? (afterConn + '\n' + followPrompt) : afterConn;
    var notDos = !_is_dos_emulator(command, afterWithFollow, callerPrompt);
    var isWinShell = notDos && (
      /Microsoft Windows \[Version\s+[0-9.]+\]/i.test(afterWithFollow)
      || /(?:^|\n)\s*(?:PS\s+)?[A-Za-z]:\\[^>\r\n]*>/i.test(afterWithFollow)
      || !!(C._WHOAMI_ID_RE && C._WHOAMI_ID_RE.test(afterConn))
    );
    if (isWinShell) {
      _add(facts, mkFact('access.shell', hScope, { handler: isBindConn ? 'netcat' : 'listener', os: 'windows' }, S, source));
      _add(facts, mkFact('foothold.windows', hScope, { method: shellMethod }, S, source));
      var winVerM = /Microsoft Windows \[Version\s+([0-9.]+)\]/i.exec(afterWithFollow);
      if (winVerM && winVerM[1]) {
        _add(facts, mkFact('host.kernel', hScope, { kernel: winVerM[1].trim(), tool: 'ver' }, S, source));
        C._add_os_observation(facts, ws, source, 'windows', winVerM[0], 'high', 'listener', true, 'Windows ' + winVerM[1].trim());
      } else {
        C._add_os_observation(facts, ws, source, 'windows', shellMethod + ' callback established', 'high', 'listener', true);
      }
      _parse_command_execution(afterConn, ws, command, source, facts);
    } else {
      var linIdM = (afterConn && C._LINUX_ID_RE) ? reSearch(C._LINUX_ID_RE, afterConn) : null;
      var promptlessWhoamiM = /(?:^|\r?\n)[ \t]*(?:[$#%][ \t]*)?whoami[ \t]*\r?\n[ \t]*(?<shellUser>[a-z_][a-z0-9_.-]{0,31})[ \t]*(?:\r?\n|$)/m.exec(afterConn);
      var hasPtySpawn = /\bpty\.spawn\s*\(\s*['"]\/(?:usr\/)?s?bin\/(?:ba|z|da|k|a)?sh['"]\s*\)/i.test(afterWithFollow)
        || (isPtySpawnTurn && !!followPrompt);
      var hasPosixJobStderr = _POSIX_JOB_CONTROL_STDERR_RE.test(afterConn);
      var hasUbuntuHint = _UBUNTU_POSTLOGIN_HINT_RE.test(afterConn);
      var remotePromptM = _match_verified_remote_unix_prompt(afterWithFollow, callerPrompt, { allowSameHost: isPtySpawnTurn && !isListenerCmd });
      var isUnixShell = !!linIdM
        || !!(promptlessWhoamiM && promptlessWhoamiM.groups.shellUser !== 'whoami')
        || hasPtySpawn
        || hasPosixJobStderr
        || hasUbuntuHint
        || remotePromptM.matched
        || (!!connM && /(?:^|\n)\s*(?:\$\s+\S|#\s+(?:id|whoami|uname|pwd|ls|cat)\b)/i.test(afterConn))
        || !!reSearch(C._UNAME_RE, afterConn);
      if (isUnixShell) {
        var fhVal = { service: shellMethod };
        var shellUser = (linIdM && linIdM.groups && linIdM.groups.user) ? linIdM.groups.user.trim()
          : ((promptlessWhoamiM && promptlessWhoamiM.groups && promptlessWhoamiM.groups.shellUser !== 'whoami') ? promptlessWhoamiM.groups.shellUser
            : (remotePromptM.matched ? remotePromptM.user : ''));
        if (shellUser) fhVal.identity = shellUser;
        _add(facts, mkFact('access.shell', hScope, { handler: isBindConn ? 'netcat' : 'listener', os: 'linux' }, S, source));
        _add(facts, mkFact('foothold.linux', hScope, fhVal, S, source));
        C._add_os_observation(facts, ws, source, 'linux', shellMethod + ' callback established', 'high', 'listener', true);
        if ((linIdM && (linIdM.groups.uid === '0' || /\beuid=0\(root\)/i.test(afterConn)))
            || shellUser === 'root'
            || (remotePromptM.matched && remotePromptM.isRoot)
            || /(?:^|\n)\s*(?:root@[A-Za-z0-9_.-]+:[^#\r\n]*#|(?:ba|da|z|k|a)?sh-[0-9.]+\s*#)/i.test(afterWithFollow)) {
          _add(facts, mkFact('access.admin', hScope, { service: shellMethod, identity: 'root', uid: 0 }, S, source));
          _add(facts, mkFact('access.root', hScope, { method: shellMethod }, S, source));
        }
      }
    }
  }
  C._parse_listener_output = _parse_listener_output;

  // ---- Step 2: Universal Bug & Sink Grammars on Binary / Decompiler Inspection Output ----
  var _BIN_INSPECT_CMD_RE = /\b(?:strings|ltrace|strace|ldd|readelf|objdump|nm|ilspycmd|monodis|javap|rabin2|radare2)\b/i;
  var _SHELL_BUILTINS_RE = /^(?:cd|pwd|exit|return|export|unset|set|umask|ulimit|alias|unalias|eval|exec|echo|printf|true|false|test|\[|wait|shift|local|readonly|source|\.|break|continue|trap|read|type|hash|times|cls|rem|call|setlocal|endlocal|pushd|popd|dir|md|mkdir|rd|rmdir|del|erase|ren|rename|ver|vol)$/i;
  var _PROSE_FIRST_WORD_RE = /^(?:error|errors|warning|warnings|usage|failed|failure|cannot|unable|could|please|invalid|unknown|missing|note|info|debug|trace|fatal|panic|version|copyright|license|author|welcome|starting|stopping|running|checking|loading|reading|writing|opening|closing|connecting|connected|disconnected|usage:|http|https|glibc|gcc|clang|linux|windows|ubuntu|debian|system|popen|execl|execlp|execvp|execve|dlopen|setuid|setgid|geteuid|printf|puts|fopen|fread|fwrite|fclose|malloc|free|exit|main)$/i;
  var _STOCK_WIN32_DLL_RE = /^(?:kernel32|kernelbase|advapi32|user32|ntdll|ws2_32|wsock32|msvcrt|ucrtbase|vcruntime\d*|msvcp\d*|secur32|shell32|ole32|oleaut32|crypt32|rpcrt4|iphlpapi|netapi32|wtsapi32|psapi|shlwapi|gdi32|comctl32|comdlg32|wininet|winhttp|bcrypt|ncrypt|dbghelp|version|mscoree|msi|cabinet|setupapi|cfgmgr32|powrprof|userenv|samlib|logoncli|dnsapi|wldap32|sspicli|api-ms-win-[a-z0-9-]+|ext-ms-win-[a-z0-9-]+)(?:\.dll)?$/i;

  var _REMOTE_OR_WEB_FETCH_CMD_RE = /\b(?:curl|wget|httpie|whatweb|nikto|ffuf|gobuster|feroxbuster|dirb|dirsearch|wfuzz|httpx|nuclei|wpscan|sqlmap|nmap|masscan|rustscan|searchsploit)\b/i;
  var _HTML_OR_WEB_SOURCE_RE = /^(?:\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b)|<!doctype\s+html|<\/?(?:html|head|body|pre|div|span|script|style|p|h[1-6]|table|form|ul|ol|li)\b|<\?(?:php|=)|\?>|<%@?\s|(?:^|\n)\s*(?:from\s+(?:flask|django|fastapi|bottle|tornado)\s+import|import\s+(?:flask|django|fastapi)|const\s+\w+\s*=\s*require\s*\(\s*['"](?:express|koa|fastify|http|https)['"]\)|\bexpress\s*\(\s*\)|\bapp\.(?:get|post|put|delete|use|route|listen)\s*\(|\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION)\b|document\.(?:getElementById|querySelector|cookie)|window\.location)|^\s*(?:body|html|\.[A-Za-z_-]+|#[A-Za-z_-]+)\s*\{[^}]*\b(?:color|margin|padding|font|background|display)\s*:/im;

  var _GTFOBIN_IDENTITY_SIGS = [
    { id: 'find', re: /\bGNU findutils\b|bug-findutils@gnu\.org|gnu\.org\/software\/findutils\b|^Usage:\s+\S+\s+\[-H\]\s+\[-L\]\s+\[-P\]\s+\[-Olevel\]/im },
    { id: 'bash', re: /^GNU bash,\s+version\s+\d+\.\d+|bug-bash@gnu\.org/im },
    { id: 'awk', re: /^GNU Awk\s+\d+\.\d+|bug-gawk@gnu\.org|^Usage:\s+\S+\s+\[POSIX or GNU style options\]\s+-f\s+progfile\b/im },
    { id: 'vim', re: /^VIM\s+-\s+Vi IMproved\b/im },
    { id: 'tar', re: /\bGNU tar\b|bug-tar@gnu\.org|^Usage:\s+\S+[\s\S]{0,400}?--checkpoint(?:-action)?\b/im },
    { id: 'python', re: /^Python\s+[23]\.\d+\.\d+\s*$|^usage:\s+\S+\s+\[option\]\s*\.\.\.\s*\[-c\s+cmd\s*\|\s*-m\s+mod\b/im },
    { id: 'perl', re: /This is perl\s+\d+,\s+version\s+\d+/i },
    { id: 'openssl', re: /^(?:OpenSSL|LibreSSL)\s+\d+\.\d+\.\d+[a-z]*\s+\d+\s+[A-Z][a-z]{2}\s+\d{4}\b|^Standard commands\s*\r?\n[\s\S]{0,200}?\bciphers\b[\s\S]{0,200}?\bdgst\b/im },
    { id: 'nmap', re: /^Nmap\s+(?:version\s+)?\d+\.\d+\s*\(\s*https?:\/\/nmap\.org\s*\)/im },
    { id: 'less', re: /bug-less@gnu\.org|^less\s+\d{3,4}\s+\(/im }
  ];

  function _detect_gtfobin_identity(text) {
    var t = String(text || '');
    if (!t) return '';
    for (var i = 0; i < _GTFOBIN_IDENTITY_SIGS.length; i++) {
      if (_GTFOBIN_IDENTITY_SIGS[i].re.test(t)) return _GTFOBIN_IDENTITY_SIGS[i].id;
    }
    return '';
  }

  function _extract_direct_invoked_binary(command, text) {
    var cmd = String(command || '').trim();
    var mCmd = /^(?:(?:sudo|doas|env)\s+)?(\/[A-Za-z0-9_./-]+|\.\.?\/[A-Za-z0-9_./-]+|[A-Za-z0-9_.-]+)(?=\s|$)/.exec(cmd);
    if (mCmd && mCmd[1] && !_BIN_INSPECT_CMD_RE.test(mCmd[1])) return mCmd[1];
    var mUsage = /^\s*(?:Usage|usage):\s+(\/[A-Za-z0-9_./-]+|\.\.?\/[A-Za-z0-9_./-]+)(?=\s|$)/m.exec(String(text || ''));
    if (mUsage && mUsage[1]) return mUsage[1];
    return '';
  }

  function _is_nonstock_gtfobin_alias_probe(text, command) {
    var gtfoId = _detect_gtfobin_identity(text);
    if (!gtfoId) return '';
    if (_BIN_INSPECT_CMD_RE.test(command || '')) return gtfoId;
    var invoked = _extract_direct_invoked_binary(command, text);
    if (!invoked) return '';
    var base = invoked.split('/').pop().toLowerCase();
    var isCustomOrRelPath = _LINUX_CUSTOM_DIR_RE.test(invoked) || /^\.\.?\//.test(invoked);
    var normBase = _normalize_gtfobin(base);
    if (isCustomOrRelPath || normBase !== gtfoId) return gtfoId;
    return '';
  }

  function _looks_like_binary_inspection(text, command) {
    var raw = String(text || '');
    var t = raw.length > 65536 ? (raw.slice(0, 32768) + '\n' + raw.slice(-32768)) : raw;
    var cmd = String(command || '');
    if (!/\S/.test(t)) return false;
    var cmdIsBinInspect = _BIN_INSPECT_CMD_RE.test(cmd);
    if (!cmdIsBinInspect && _REMOTE_OR_WEB_FETCH_CMD_RE.test(cmd)) return false;
    var matchedPositive = cmdIsBinInspect
      || !!_is_nonstock_gtfobin_alias_probe(t, cmd)
      || (t.indexOf('(') >= 0 && /^(?:\[pid \d+\]\s+)?(?:__libc_start_main|system|popen|execlp?|execvp|dlopen)\s*\(/m.test(t))
      || (t.indexOf('"') >= 0 && /^(?:\[pid \d+\]\s+)?(?:execve|openat|open|access)\s*\(\s*"[^"]+"/m.test(t) && /\b(?:ENOENT|O_RDONLY)\b/.test(t))
      || (t.indexOf('.so') >= 0 && /^\s*[A-Za-z0-9_.+-]+\.so(?:\.\d+)*\s*=>\s*(?:not found|\/\S+)/m.test(t))
      || (t.indexOf('[') >= 0 && /\b(?:RPATH|RUNPATH|Library rpath|Library runpath)\b[^\r\n]*\[[^\]]+\]/i.test(t))
      || (t.indexOf('(') >= 0 && /\b(?:Process\.Start\s*\(|ProcessStartInfo\b|\[DllImport\s*\(|LoadLibrary(?:Ex)?[AW]?\s*\(|\bsystem\s*\(\s*"[^"\r\n]+"|\bpopen\s*\(\s*"[^"\r\n]+"|\bexec[lv]p\s*\(\s*"[^"\r\n]+")/.test(t))
      || (t.indexOf('*') >= 0 && /(?:__libc_start_main|GLIBC_2\.\d+|libc\.so\.6)/.test(t) && /\b(?:7z|7za|7zr|tar|rsync|zip|chown|chmod)\b[^\r\n;|&]*?(?:\s(?:[\w./-]*\/)?\*(?:\.[A-Za-z0-9]{1,8})?(?=\s|$|[;|&><)]))/i.test(t))
      || /\.(?:dll|so|ps1|py|sh)\b[^\r\n]*(?:NAME NOT FOUND|PATH NOT FOUND|FileNotFoundException)/i.test(t);
    if (!matchedPositive) return false;
    if (C._looks_like_edb_script && C._looks_like_edb_script(t, cmd)) return false;
    if (_HTML_OR_WEB_SOURCE_RE.test(t)) return false;
    return true;
  }
  C._looks_like_binary_inspection = _looks_like_binary_inspection;

  function _extractUnqualifiedBinsFromShellCmd(cmdStr) {
    var bins = [];
    var s = String(cmdStr || '').trim();
    if (!s) return bins;
    // Unwrap sh -c / bash -c / cmd /c wrappers
    var wrapM = /^(?:\/(?:usr\/)?s?bin\/)?(?:ba|da|z|k)?sh\s+-c\s+(['"]?)(.+)\1$/i.exec(s)
      || /^(?:[A-Za-z]:\\Windows\\System32\\)?cmd(?:\.exe)?\s+\/[cCkK]\s+(['"]?)(.+)\1$/i.exec(s);
    if (wrapM && wrapM[2]) s = wrapM[2].trim();

    var segments = s.split(/\s*(?:;|&&|\|\||\|)\s*/);
    for (var i = 0; i < segments.length; i++) {
      var seg = segments[i].trim().replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)+/, '').replace(/^[\s(]+/, '');
      if (!seg) continue;
      var firstTok = seg.split(/\s+/)[0].replace(/^['"]+|['"]+$/g, '');
      if (!firstTok) continue;
      if (firstTok.indexOf('/') >= 0 || firstTok.indexOf('\\') >= 0 || firstTok.indexOf(':') >= 0) continue;
      if (firstTok.charAt(0) === '.' || firstTok.charAt(0) === '$' || firstTok.charAt(0) === '-' || firstTok.charAt(0) === '%') continue;
      if (!/^[A-Za-z][A-Za-z0-9_.-]{0,31}$/.test(firstTok)) continue;
      var strippedExt = firstTok.replace(/\.(?:exe|bat|cmd)$/i, '');
      if (_SHELL_BUILTINS_RE.test(strippedExt)) continue;
      bins.push(firstTok);
    }
    return bins;
  }

  function _inferInspectedBinary(command, ws, facts, text) {
    var cmd = String(command || '');
    var mLin = /\b(?:strings|ltrace|strace|ldd|readelf|objdump|nm|rabin2|radare2|file)\b[^\r\n]*?\s(\/[A-Za-z0-9_./-]+|\.\.?\/[A-Za-z0-9_./-]+)/i.exec(cmd);
    var candPath = mLin ? mLin[1] : '';
    if (!candPath) {
      var mWin = /\b(?:strings|ilspycmd|monodis|objdump)\b[^\r\n]*?\s["']?([A-Za-z]:\\[^"'\s\r\n]+|\S+\.(?:exe|dll))["']?/i.exec(cmd);
      if (mWin) return mWin[1];
    }
    if (!candPath) {
      var directInv = _extract_direct_invoked_binary(cmd, text);
      if (directInv && (directInv.charAt(0) === '/' || /^\.\.?\//.test(directInv))) candPath = directInv;
    }
    var pools = [facts || [], (ws && ws.facts) || [], (ws && ws.seedFacts) || []];
    if (candPath && /^\.\.?\//.test(candPath)) {
      var relBase = candPath.split('/').pop().toLowerCase();
      for (var rpi = 0; rpi < pools.length; rpi++) {
        var rlist = pools[rpi];
        if (!Array.isArray(rlist)) continue;
        for (var ri = 0; ri < rlist.length; ri++) {
          var rf = rlist[ri];
          if (rf && rf.kind === 'privesc.custom_binary' && rf.value && rf.value.path) {
            if (String(rf.value.path).split('/').pop().toLowerCase() === relBase) return rf.value.path;
          }
          if (rf && (rf.kind === 'privesc.suid_candidate' || rf.kind === 'privesc.suid') && rf.value && Array.isArray(rf.value.paths)) {
            for (var sp = 0; sp < rf.value.paths.length; sp++) {
              if (String(rf.value.paths[sp]).split('/').pop().toLowerCase() === relBase) return rf.value.paths[sp];
            }
          }
        }
      }
      var promptLine = (ws && ws.context && ws.context.promptLine) || '';
      var parsedPrompt = promptLine ? _parse_unix_prompt_line(String(promptLine).split(/\r?\n/)[0]) : null;
      if (parsedPrompt && parsedPrompt.cwd && parsedPrompt.cwd.charAt(0) === '/' && candPath.indexOf('./') === 0) {
        return parsedPrompt.cwd.replace(/\/+$/, '') + '/' + candPath.slice(2);
      }
      return candPath;
    }
    if (candPath) return candPath;
    for (var pi = 0; pi < pools.length; pi++) {
      var list = pools[pi];
      if (!Array.isArray(list)) continue;
      for (var i = 0; i < list.length; i++) {
        var f = list[i];
        if (f && f.kind === 'privesc.custom_binary' && f.value && f.value.path) return f.value.path;
      }
    }
    return '';
  }

  function _parse_binary_inspection(text, ws, command, source, facts) {
    var t = String(text || '');
    var cmd = String(command || '');
    if (!_looks_like_binary_inspection(t, cmd)) return;
    var viaBin = _inferInspectedBinary(cmd, ws, facts, t);
    var leadKinds = {};

    // 0. Upstream GTFOBins binary identity recognition on renamed / custom SUID binaries
    var gtfoAliasId = _is_nonstock_gtfobin_alias_probe(t, cmd);
    if (gtfoAliasId && viaBin) {
      var viaBase = viaBin.split('/').pop().toLowerCase();
      var isNonStockOrRenamed = _LINUX_CUSTOM_DIR_RE.test(viaBin) || /^\.\.?\//.test(viaBin) || _normalize_gtfobin(viaBase) !== gtfoAliasId;
      if (isNonStockOrRenamed) {
        var trackedCtx = '';
        var pools = [facts || [], (ws && ws.facts) || [], (ws && ws.seedFacts) || []];
        for (var cpi = 0; cpi < pools.length && !trackedCtx; cpi++) {
          var clist = pools[cpi];
          if (!Array.isArray(clist)) continue;
          for (var ci = 0; ci < clist.length; ci++) {
            var cf = clist[ci];
            if (cf && cf.kind === 'privesc.custom_binary' && cf.value && cf.value.path === viaBin && cf.value.context) {
              trackedCtx = cf.value.context;
              break;
            }
          }
        }
        if (trackedCtx === 'sudo') {
          _add_host_privesc_fact(facts, ws, source, 'privesc.sudo_binary', {
            bin: viaBase,
            path: viaBin,
            gtfobins_id: gtfoAliasId,
            gtfobins_alias: gtfoAliasId,
            nopasswd: true,
            ref: 'https://gtfobins.github.io/gtfobins/' + gtfoAliasId + '/#sudo'
          }, leadKinds);
        } else {
          _add_host_privesc_fact(facts, ws, source, 'privesc.suid_candidate', {
            binary: viaBin,
            paths: [viaBin],
            gtfobins_alias: gtfoAliasId,
            custom: false,
            count: 1
          }, leadKinds);
          _add_host_privesc_fact(facts, ws, source, 'privesc.suid', {
            binaries: [viaBin],
            paths: [viaBin],
            gtfobins_alias: gtfoAliasId,
            count: 1
          }, leadKinds);
        }
      }
    }

    var pathHijacks = [], seenHijack = {};
    function addPathHijack(binName, callExpr) {
      var b = String(binName || '').trim();
      if (!b || seenHijack[b.toLowerCase()]) return;
      seenHijack[b.toLowerCase()] = 1;
      pathHijacks.push({ hijack_bin: b, call: String(callExpr || b).slice(0, 140) });
    }

    // 1A. Explicit C / ltrace / decompiled C calls: system("..."), popen("..."), execlp("..."), execvp("...")
    reAll(/\b(?:system|popen)\s*\(\s*"([^"\r\n]{1,220})"/g, t).forEach(function (m) {
      _extractUnqualifiedBinsFromShellCmd(m[1]).forEach(function (b) { addPathHijack(b, m[0]); });
    });
    reAll(/\bexec[lv]p(?:e)?\s*\(\s*"([^"\r\n\/\\:]{1,64})"/g, t).forEach(function (m) {
      var b = m[1].trim();
      if (/^[A-Za-z][A-Za-z0-9_.-]{0,31}$/.test(b) && !_SHELL_BUILTINS_RE.test(b)) addPathHijack(b, m[0]);
    });

    // 1B. .NET / C# decompiled Process.Start / ProcessStartInfo
    reAll(/\bProcess\.Start\s*\(\s*@?"([^"\r\n]{1,220})"(?:\s*,\s*@?"([^"\r\n]{0,220})")?/g, t).forEach(function (m) {
      var fn = m[1].trim(), args = (m[2] || '').trim();
      if (/^(?:cmd(?:\.exe)?|powershell(?:\.exe)?)$/i.test(fn) && args) {
        _extractUnqualifiedBinsFromShellCmd(fn + ' ' + args).forEach(function (b) { addPathHijack(b, m[0]); });
      } else {
        _extractUnqualifiedBinsFromShellCmd(fn).forEach(function (b) { addPathHijack(b, m[0]); });
      }
    });
    var psiBlocks = reAll(/\bFileName\s*=\s*@?"([^"\r\n]{1,160})"([\s\S]{0,220})/g, t);
    psiBlocks.forEach(function (m) {
      var fn = m[1].trim();
      var argM = /\bArguments\s*=\s*@?"([^"\r\n]{1,220})"/.exec(m[2] || '');
      if (/^(?:cmd(?:\.exe)?|powershell(?:\.exe)?)$/i.test(fn) && argM) {
        _extractUnqualifiedBinsFromShellCmd(fn + ' ' + argM[1]).forEach(function (b) { addPathHijack(b, fn + ' ' + argM[1]); });
      } else {
        _extractUnqualifiedBinsFromShellCmd(fn).forEach(function (b) { addPathHijack(b, m[0].split(/\r?\n/)[0]); });
      }
    });

    // 1C. Raw `strings` ELF .rodata command lines when `strings` command or ELF exec symbol context is present
    var isStringsPaste = /\bstrings\b/i.test(cmd) || (/(?:__libc_start_main|GLIBC_2\.\d+|libc\.so\.6)/.test(t) && /^\s*(?:system|popen|execlp|execvp)\s*$/m.test(t));
    if (isStringsPaste && !pathHijacks.length) {
      var sLines = t.split(/\r?\n/);
      for (var si = 0; si < sLines.length; si++) {
        var sl = sLines[si].trim();
        if (!sl || sl.length > 180 || /^[._@\[]/.test(sl)) continue;
        // Require unmistakable CLI structure: flag (-x / --long), pipe (|), redirect (>), or absolute/relative path argument (/...)
        if (!/(?:\s-[A-Za-z0-9-]|\s\|\s|[12]?>[>&]?|\s\/[A-Za-z0-9_./-]{2,})/.test(sl)) continue;
        var firstW = sl.split(/\s+/)[0];
        if (!/^[a-z][a-z0-9_.-]{1,23}$/.test(firstW)) continue;
        if (_PROSE_FIRST_WORD_RE.test(firstW) || _SHELL_BUILTINS_RE.test(firstW)) continue;
        _extractUnqualifiedBinsFromShellCmd(sl).forEach(function (b) {
          if (!_PROSE_FIRST_WORD_RE.test(b)) addPathHijack(b, sl);
        });
      }
    }

    if (pathHijacks.length) {
      var topPh = pathHijacks[0];
      _add_host_privesc_fact(facts, ws, source, 'privesc.path_hijack_candidate', {
        hijack_bin: topPh.hijack_bin,
        via_binary: viaBin || null,
        call: topPh.call,
        candidates: pathHijacks.slice(0, 10)
      }, leadKinds);
    }

    // 1D. Wildcard archiver / permission command embedded in inspected binary strings/source -> privesc.cron_wildcard
    var binWildcardHits = [];
    t.split(/\r?\n/).forEach(function (rawLine) {
      var wl = rawLine.trim();
      if (!wl || wl.length > 260) return;
      var wm = /\b(7z|7za|7zr|tar|rsync|zip|chown|chmod)\b[^\r\n;|&]*?(?:\s(?:[\w./-]*\/)?\*(?:\.[A-Za-z0-9]{1,8})?(?=\s|$|[;|&><")]))/i.exec(wl);
      if (wm) binWildcardHits.push({ tool: wm[1].toLowerCase(), evidence: wl.slice(0, 220) });
    });
    if (binWildcardHits.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.cron_wildcard', {
        tool: binWildcardHits[0].tool,
        evidence: binWildcardHits[0].evidence,
        via_binary: viaBin || null,
        count: binWildcardHits.length
      }, leadKinds);
    }

    // 2. Missing or user-writable shared libraries, DLLs, and helper scripts -> privesc.library_or_script_hijack
    var libHijacks = [], seenLib = {};
    function addLibHijack(target, tType, reason) {
      var tg = String(target || '').trim();
      if (!tg) return;
      var k = tg.toLowerCase();
      if (seenLib[k]) return;
      seenLib[k] = 1;
      libHijacks.push({ target: tg, target_type: tType, reason: reason });
    }

    // 2A. ldd missing or custom-directory shared object
    reAll(/^\s*([A-Za-z0-9_.+-]+\.so(?:\.\d+)*)\s*=>\s*not found\b/gm, t).forEach(function (m) {
      addLibHijack(m[1], 'so', 'ldd_not_found');
    });
    reAll(/^\s*([A-Za-z0-9_.+-]+\.so(?:\.\d+)*)\s*=>\s*(\/(?:opt|home|tmp|var\/tmp|dev\/shm|srv|var\/backups|usr\/local)\/\S+)/gim, t).forEach(function (m) {
      addLibHijack(m[2], 'so', 'custom_shared_library_path');
    });

    // 2B. readelf / objdump custom or relative RPATH / RUNPATH
    reAll(/\b(?:RPATH|RUNPATH|Library rpath|Library runpath)\b[^\r\n]*\[\s*([^\]]+)\]/gi, t).forEach(function (m) {
      m[1].split(':').forEach(function (rp) {
        var cleanRp = rp.trim();
        if (!cleanRp) return;
        if (/^(?:\/(?:opt|home|tmp|var\/tmp|dev\/shm|srv|var\/backups|usr\/local)\b|\$ORIGIN\b|\.(?:\/|$))/i.test(cleanRp)) {
          addLibHijack(cleanRp, 'so', 'custom_rpath');
        }
      });
    });

    // 2C. strace / ltrace ENOENT or dlopen on non-stock .so / .py / .sh / .pl / .rb
    reAll(/\bdlopen\s*\(\s*"([^"\r\n]+\.so(?:\.\d+)*)"/gi, t).forEach(function (m) {
      if (!/^\/(?:usr\/)?lib(?:32|64|x32)?\//i.test(m[1])) addLibHijack(m[1], 'so', 'dlopen_non_system');
    });
    reAll(/\b(?:open(?:at)?|access|stat|lstat|execve)\s*\([^"\r\n]*"([^"\r\n]+\.(so(?:\.\d+)*|py|sh|pl|rb|ps1|dll))"[^\r\n]*\bENOENT\b/gi, t).forEach(function (m) {
      var p = m[1], ext = m[2].toLowerCase().split('.')[0];
      if (/^\/(?:etc\/ld\.so|(?:usr\/)?lib(?:32|64)?\/|usr\/share\/locale)/i.test(p)) return;
      addLibHijack(p, ext, 'missing_referenced_target');
    });

    // 2D. C# / C non-stock [DllImport] or LoadLibrary, or Procmon / exception missing DLL/script
    reAll(/\[\s*DllImport\s*\(\s*@?"([^"\r\n]+)"/gi, t).forEach(function (m) {
      var dll = m[1].trim();
      var base = dll.split(/[\\/]/).pop();
      if (!_STOCK_WIN32_DLL_RE.test(base)) addLibHijack(dll.indexOf('.') >= 0 ? dll : (dll + '.dll'), 'dll', 'custom_dllimport');
    });
    reAll(/\bLoadLibrary(?:Ex)?[AW]?\s*\(\s*@?"([^"\r\n]+)"/gi, t).forEach(function (m) {
      var dll = m[1].trim();
      var base = dll.split(/[\\/]/).pop();
      if (!_STOCK_WIN32_DLL_RE.test(base)) addLibHijack(dll, 'dll', 'loadlibrary_custom');
    });
    reAll(/([A-Za-z]:\\[^"\r\n|<>?*]+?\.(dll|ps1|py|bat|cmd|vbs)|\/[A-Za-z0-9_./-]+?\.(so(?:\.\d+)*|py|sh|pl|rb))[^\r\n]*(?:NAME NOT FOUND|PATH NOT FOUND|FileNotFoundException|No such file or directory)/gi, t).forEach(function (m) {
      var p = m[1], ext = (m[2] || m[3] || '').toLowerCase().split('.')[0];
      if (/^[A-Za-z]:\\Windows\\/i.test(p) || /^\/(?:usr\/)?lib/i.test(p)) return;
      addLibHijack(p, ext, 'missing_target_path');
    });

    // 2E. Custom-location helper script/DLL/SO invoked or loaded by inspected binary
    reAll(/(?:["'\s]|^)(\/(?:opt|var\/backups|var\/tmp|tmp|dev\/shm|home|srv|usr\/local)\/[A-Za-z0-9_./-]+\.(sh|py|pl|rb|so(?:\.\d+)*)|[A-Za-z]:\\(?:tools|scripts|backups|dev|temp|tmp|Users|ProgramData|inetpub)\\[^"'\r\n|<>?*\s]+\.(ps1|bat|cmd|py|dll|vbs))(?=["'\s);]|$)/gim, t).forEach(function (m) {
      var p = m[1].trim();
      if (viaBin && p.toLowerCase() === viaBin.toLowerCase()) return;
      var ext = (m[2] || m[3] || '').toLowerCase().split('.')[0];
      addLibHijack(p, ext, 'referenced_custom_script_or_lib');
    });

    if (libHijacks.length) {
      var topLh = libHijacks[0];
      _add_host_privesc_fact(facts, ws, source, 'privesc.library_or_script_hijack', {
        target: topLh.target,
        target_type: topLh.target_type,
        reason: topLh.reason,
        via_binary: viaBin || null,
        targets: libHijacks.slice(0, 15)
      }, leadKinds);
      if (topLh.target_type === 'dll') {
        _add_host_privesc_fact(facts, ws, source, 'privesc.dll_hijack_candidate', {
          evidence: [topLh.target],
          count: 1
        }, leadKinds);
      }
    }

    _add_privesc_leads(facts, ws, source, leadKinds);
  }
  C._parse_binary_inspection = _parse_binary_inspection;

  // ---- POSIX/BSD whoami & doas/sudo/su/SUID/local-exploit subshell escalation ----
  var _POSIX_WHOAMI_NOISE_RE = /^(?:whoami|hostname|id|uname|pwd|ls|dir|groups|env|set|ver|date|ipconfig|ifconfig|netstat|ss|systeminfo|tasklist|ps|w|last|cat|type|echo|clear|exit|error|denied|failed|failure|unknown|none|null|invalid|unauthorized|not|command|usage|help)$/i;
  var _POSIX_SUID_SUBSHELL_RE = /(?:\/(?:usr\/)?s?bin\/(?:ba|da|z|k|a)?sh|(?:^|\s|['"(])(?:\.\.?|\/tmp|\/var\/tmp|\/dev\/shm)\/[A-Za-z0-9_.-]+)\b[^\r\n]*?\s-[A-Za-z']*p\b|\b(?:pcntl_exec|posix_sete?uid|os\.sete?uid|setresuid|setreuid|setuid|execve)\s*\(/i;
  function _parse_posix_whoami_escalation(text, ws, command, source, facts) {
    if (_is_attacker_local_turn(ws, command, text)) return;
    var followPrompt = (ws && ws.context && ws.context.followPrompt) || '';
    var callerPrompt = (ws && ws.context && ws.context.promptLine) || '';
    if (!text && !followPrompt) return;
    var clean = String(text || '').replace(C._ANSI_RE, '');
    var cmd = String(command || '');
    var h = 'host:' + ws.target;

    // 1. Bare POSIX `whoami` command returning a single lowercase POSIX username
    if (/^\s*whoami\s*$/i.test(cmd) && clean) {
      var stripped = clean.replace(/^\s*(?:[$#%]\s*)?whoami\s*\r?\n/i, '').trim();
      if (/^[a-z_][a-z0-9_.-]{0,31}$/.test(stripped) && !_POSIX_WHOAMI_NOISE_RE.test(stripped)) {
        _add(facts, mkFact('foothold.linux', h, { identity: stripped, method: 'whoami' }, S, source));
        _add(facts, mkFact('access.shell', h, { user: stripped, os: 'linux', via: 'whoami' }, S, source));
        C._add_os_observation(facts, ws, source, 'linux', 'POSIX whoami: ' + stripped, 'medium', 'whoami', true);
        if (stripped === 'root') {
          _add(facts, mkFact('access.admin', h, { identity: 'root', method: 'whoami' }, S, source));
          _add(facts, mkFact('access.root', h, { method: 'whoami' }, S, source));
        }
      }
    }

    // 2. doas / sudo / su / pkexec / SUID -p / local CVE exploit subshell escalation yielding echoed `whoami -> root`, `uid=0(root)`, or root prompt
    var combined = cmd + '\n' + clean;
    var hasSuidSubshell = _POSIX_SUID_SUBSHELL_RE.test(combined);
    var hasEscalationVerb = hasSuidSubshell
      || /\b(?:doas|sudo|su|pkexec)\b/i.test(cmd)
      || /(?:^|\r?\n)\s*(?:[$#%]\s*)?(?:doas|sudo|su|pkexec)\b/i.test(clean);
    var isSudoListOrFail = /may run the following commands|\bNOPASSWD\s*:|(?:Authentication|perm)\s+fail|Sorry,\s*try again|not in the sudoers|Operation not permitted|su:\s*Authentication failure|incorrect password/i.test(clean);
    var hasEchoedRoot = /(?:^|\r?\n)[ \t]*(?:[$#%>][ \t]*)?whoami[ \t]*\r?\n[ \t]*root[ \t]*(?:\r?\n|$)/i.test(clean);
    var hasDirectRoot = /\bwhoami\b/i.test(cmd) && /^\s*root\s*$/im.test(clean);
    var hasUidZero = /\b(?:e?uid)=0\(root\)/i.test(clean);
    var inBodyPromptM = _match_verified_remote_unix_prompt(clean, callerPrompt, { allowSameHost: true });
    var followPromptM = _match_verified_remote_unix_prompt(followPrompt, callerPrompt, { allowSameHost: true, isPromptCtx: true });
    var hasVerifiedRootPrompt = (inBodyPromptM.matched && inBodyPromptM.isRoot) || (followPromptM.matched && followPromptM.isRoot);
    var callerPObj = callerPrompt ? _parse_unix_prompt_line(String(callerPrompt).split(/\r?\n/)[0], { isPromptCtx: true }) : null;
    var hasVerifiedNonRootCaller = !!(callerPObj && callerPObj.sigil === '$'
      && (callerPObj.isBareSh || (callerPObj.user && callerPObj.user.toLowerCase() !== 'root'
        && !_ATTACKER_PROMPT_ENTITY_RE.test(callerPObj.user)
        && (!callerPObj.host || !_ATTACKER_PROMPT_ENTITY_RE.test(callerPObj.host)))));
    var isHttpContextEsc = /^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(clean) || /\bhttps?:\/\//i.test(cmd);
    var hasLocalExploitEscalation = hasVerifiedNonRootCaller && !isSudoListOrFail && !isHttpContextEsc
      && (hasEchoedRoot || hasDirectRoot || hasUidZero || hasVerifiedRootPrompt)
      && (hasVerifiedRootPrompt || /\b(?:cve-\d{4}-\d+|exploit|pwnkit|pkexec)\b/i.test(combined));
    if (!isSudoListOrFail && ((hasEscalationVerb && (hasEchoedRoot || hasDirectRoot || hasUidZero || hasVerifiedRootPrompt)) || hasLocalExploitEscalation)) {
      var escTool = /\bdoas\b/i.test(combined) ? 'doas'
        : (/\bpkexec\b/i.test(combined) ? 'pkexec'
          : (/\bsudo\b/i.test(combined) ? 'sudo'
            : (hasSuidSubshell && !/\bsu\b/i.test(cmd) ? 'suid-shell'
              : (hasLocalExploitEscalation && !/\bsu\b/i.test(cmd) ? 'local-exploit' : 'su'))));
      _add(facts, mkFact('foothold.linux', h, { identity: 'root', method: escTool }, S, source));
      _add(facts, mkFact('access.shell', h, { user: 'root', os: 'linux', via: escTool }, S, source));
      _add(facts, mkFact('access.admin', h, { identity: 'root', method: escTool }, S, source));
      _add(facts, mkFact('access.root', h, { method: escTool }, S, source));
      C._add_os_observation(facts, ws, source, 'linux', escTool + ' root escalation', 'high', escTool, true);
      return;
    }

    // 3. Horizontal `su` transition to a non-root user prompt
    if (!isSudoListOrFail && !isHttpContextEsc && /\bsu\b/i.test(cmd)) {
      var horizPrompt = (followPromptM.matched && !followPromptM.isRoot && followPromptM.user) ? followPromptM
        : ((inBodyPromptM.matched && !inBodyPromptM.isRoot && inBodyPromptM.user) ? inBodyPromptM : null);
      var cmdSuTargetM = /\bsu\s+(?:-\s+|-l\s+)?([a-z_][a-z0-9_.-]{0,31})(?:\s|$)/i.exec(cmd);
      var suTargetUser = horizPrompt ? horizPrompt.user : '';
      if (!suTargetUser && cmdSuTargetM && cmdSuTargetM[1].toLowerCase() !== 'root'
          && ((followPromptM.matched && !followPromptM.isRoot) || (inBodyPromptM.matched && !inBodyPromptM.isRoot))) {
        suTargetUser = cmdSuTargetM[1];
      }
      if (suTargetUser && suTargetUser.toLowerCase() !== 'root'
          && (!callerPObj || !callerPObj.user || suTargetUser.toLowerCase() !== callerPObj.user.toLowerCase())) {
        _add(facts, mkFact('foothold.linux', h, { identity: suTargetUser, method: 'su' }, S, source));
        _add(facts, mkFact('access.shell', h, { user: suTargetUser, os: 'linux', via: 'su' }, S, source));
        _add(facts, mkFact('credential.validated', h, { user: suTargetUser, service: 'su', outcome: 'accepted' }, S, source));
        C._add_os_observation(facts, ws, source, 'linux', 'su horizontal switch: ' + suTargetUser, 'high', 'su', true);
      }
    }
  }
  C._parse_posix_whoami_escalation = _parse_posix_whoami_escalation;

  function _parse_gcore_output(text, ws, command, source, facts) {
    if (!text) return;
    var clean = String(text).replace(C._ANSI_RE, '');
    var h = 'host:' + ws.target;
    var cores = C.uniqueSortedCI(reAll(/^\s*Saved corefile\s+(\S+)\s*$/gim, clean).map(function (m) { return m[1].trim(); }).filter(Boolean));
    if (cores.length) {
      _add(facts, mkFact('loot.files', h, { path: cores[0], files: cores, count: cores.length, kind: 'process_core_dump', tool: 'gcore', via: 'gcore' }, S, source));
    }
  }
  C._parse_gcore_output = _parse_gcore_output;

  function _parse_archive_listing(text, ws, command, source, facts) {
    if (!text) return;
    var clean = String(text).replace(C._ANSI_RE, '');
    var cmd = String(command || '');
    var h = 'host:' + ws.target;
    var entries = [], seenEnt = Object.create(null);
    function pushEntry(rawEnt) {
      var e = String(rawEnt || '').trim().replace(/^['"]|['"]$/g, '');
      if (!e || e.slice(-1) === '/' || e.slice(-1) === '\\' || seenEnt[e]) return;
      seenEnt[e] = 1;
      entries.push(e);
    }
    var lines = clean.split(/\r?\n/);
    var isTarVerboseCmd = /\btar\b[^\r\n]*-[A-Za-z]*[xt][A-Za-z]*v|\btar\b[^\r\n]*-[A-Za-z]*v[A-Za-z]*[xt]|\btar\b[^\r\n]*--list\b/i.test(cmd);
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      var uzM = /^\s*(?:inflating|extracting):\s+(\S.*?)(?:\s+->\s+\S.*)?\s*$/i.exec(ln);
      if (uzM) { pushEntry(uzM[1]); continue; }
      var uzPwM = /^\s*\[[^\]\r\n]+\]\s+(\S.+?)\s+password:\s*$/i.exec(ln);
      if (uzPwM) { pushEntry(uzPwM[1]); continue; }
      var uzListM = /^\s*\d+\s+\d{2,4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(\S.+?)\s*$/.exec(ln);
      if (uzListM && !/^-{3,}/.test(uzListM[1]) && !/\bfiles?\b$/i.test(uzListM[1])) { pushEntry(uzListM[1]); continue; }
      var szExtM = /^\s*Extracting\s+(\S.+?)\s*$/.exec(ln);
      if (szExtM && /\b(?:7z|7za|7zr)\b|7-Zip\b/i.test(cmd + '\n' + clean)) { pushEntry(szExtM[1]); continue; }
      var szListM = /^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[.DRHSA]{5}\s+\d+\s+\d*\s+(\S.+?)\s*$/.exec(ln);
      if (szListM) { pushEntry(szListM[1]); continue; }
      var tarLongM = /^-[rwxstST-]{9}\s+\S+\s+\d+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?\s+(\S.+?)(?:\s+->\s+\S.*)?\s*$/.exec(ln);
      if (tarLongM) { pushEntry(tarLongM[1]); continue; }
      if (isTarVerboseCmd && /^[A-Za-z0-9_./-]+$/.test(ln.trim())) {
        pushEntry(ln.trim());
      }
    }
    var archNameM = /^\s*Archive:\s+(\S+)/im.exec(clean)
      || /([^\s'"]+\.(?:zip|7z|rar|tar(?:\.(?:gz|bz2|xz|zst))?|tgz|bak))\b/i.exec(cmd + '\n' + clean);
    var archName = archNameM ? archNameM[1].trim() : '';
    var isEncryptedArchive = /\b(?:encrypted|incorrect password|wrong password|need PK compat|skipping:[^\r\n]*need password|Enter password(?:\s+\(will not be echoed\))?:|Encrypted\s*=\s*\+)|^\s*\[[^\]\r\n]+\]\s+\S.+?\s+password:\s*$/im.test(clean);
    var hasSensitiveArchiveMember = entries.some(function (ent) {
      var b = (ent.split(/[\/\\]/).pop() || ent).toLowerCase();
      return b === 'ntds.dit' || b === 'system' || b === 'sam' || /\.(?:kdbx|pfx|p12|psafe3)$/i.test(b);
    }) || /(?:^|[\s\/\\:])(?:ntds\.dit|[^\s\/\\:]+\.(?:kdbx|pfx|p12|psafe3))(?:\s|$)/im.test(clean);
    if (isEncryptedArchive || hasSensitiveArchiveMember) {
      var matVal = { kind: isEncryptedArchive ? 'encrypted_archive' : 'sensitive_archive', encrypted: !!isEncryptedArchive, via: 'archive' };
      if (archName) matVal.archive = archName;
      _add(facts, mkFact('loot.material', h, matVal, S, source));
    }
    if (!entries.length) return;
    var lootFiles = [];
    for (var ei = 0; ei < entries.length; ei++) {
      var ent = entries[ei];
      var base = ent.split(/[\/\\]/).pop() || ent;
      if (!/\.pub$/i.test(base) && (/^(?:id_(?:rsa|dsa|ecdsa|ed25519|xmss)|identity|[A-Za-z0-9_.-]+_rsa)$/i.test(base) || /\.(?:pem|ppk)$/i.test(base))) {
        _add(facts, mkFact('loot.ssh_key', h, { path: ent, file: base, via: 'archive' }, S, source));
        _add(facts, mkFact('credential.ssh_key', h, { path: ent, file: base, via: 'archive' }, S, source));
        _add(facts, mkFact('credential.candidate', h, { kind: 'ssh_private_key', file: ent, via: 'archive' }, S, source));
        lootFiles.push(ent);
      } else if (/\.(?:bak|old|kdbx|psafe3|ovpn|sql|sqlite3?|db|mdb|accdb|pst|pfx|p12|dit)$/i.test(base)
          || /^(?:ntds\.dit|sam|system|security|tomcat-users\.xml|wp-config\.php|web\.config|\.htpasswd|\.env|authorized_keys|shadow|passwd|(?:config|settings|database|db|secret|cred)[A-Za-z0-9_.-]*\.(?:php|ini|yml|yaml|json|xml|conf|cfg))$/i.test(base)) {
        lootFiles.push(ent);
      }
    }
    if (lootFiles.length) {
      _add(facts, mkFact('loot.files', h, { files: lootFiles, path: lootFiles[0], count: lootFiles.length, via: 'archive' }, S, source));
    }
  }
  C._parse_archive_listing = _parse_archive_listing;

  // ---- Meterpreter & Metasploit session / getuid / getsystem / local_exploit_suggester ----
  function _looks_like_meterpreter(text, command) {
    var t = String(text || '');
    var c = String(command || '');
    return /\bServer username:\s*\S+/i.test(t)
      || /\bgot system via technique\s+\d+/i.test(t)
      || /\[\*\]\s*(?:Meterpreter|Command shell) session \d+ opened\b/i.test(t)
      || /\[\*\]\s*Migration completed successfully/i.test(t)
      || /\[\+\]\s*\S+\s*-\s*exploit\/(?:windows|linux|multi|osx|freebsd)\/local\/[A-Za-z0-9_/-]+:\s*The target appears to be vulnerable/i.test(t)
      || /^\s*meterpreter\s*>/im.test(t)
      || /\b(?:getuid|getsystem|local_exploit_suggester)\b/i.test(c);
  }
  C._looks_like_meterpreter = _looks_like_meterpreter;

  function _parse_meterpreter(text, ws, command, source, facts) {
    if (!text) return;
    var clean = String(text).replace(C._ANSI_RE, '');
    var h = 'host:' + ws.target;
    var ctx = String(command || '') + '\n' + clean;

    var uidM = /\bServer username:\s*([^\r\n]+)/i.exec(clean);
    if (uidM && uidM[1]) {
      var srvUser = uidM[1].trim();
      if (/^nt authority\\system$/i.test(srvUser)) {
        _add(facts, mkFact('foothold.windows', h, { identity: 'nt authority\\system', method: 'meterpreter' }, S, source));
        _add(facts, mkFact('access.shell', h, { handler: 'meterpreter', os: 'windows', user: srvUser }, S, source));
        _add(facts, mkFact('access.admin', h, { identity: 'nt authority\\system', method: 'meterpreter' }, S, source));
        _add(facts, mkFact('access.system', h, { identity: 'nt authority\\system', method: 'meterpreter' }, S, source));
        C._add_os_observation(facts, ws, source, 'windows', 'Meterpreter getuid: ' + srvUser, 'high', 'meterpreter', true);
      } else if (/^(?:(?:nt authority|nt service|iis apppool|window manager|font driver host)\\[A-Za-z0-9_.$ -]+|[A-Za-z0-9_.-]+\\[A-Za-z0-9_.$-]+)$/i.test(srvUser)) {
        _add(facts, mkFact('foothold.windows', h, { identity: srvUser, method: 'meterpreter' }, S, source));
        _add(facts, mkFact('access.shell', h, { handler: 'meterpreter', os: 'windows', user: srvUser }, S, source));
        C._add_os_observation(facts, ws, source, 'windows', 'Meterpreter getuid: ' + srvUser, 'high', 'meterpreter', true);
        if (/(?:^|\\)administrator$/i.test(srvUser)) {
          _add(facts, mkFact('access.admin', h, { identity: srvUser, method: 'meterpreter' }, S, source));
        }
      } else if (/^(?:root\b|.*\buid=0\b)/i.test(srvUser)) {
        _add(facts, mkFact('foothold.linux', h, { identity: 'root', method: 'meterpreter' }, S, source));
        _add(facts, mkFact('access.shell', h, { handler: 'meterpreter', os: 'linux', user: 'root' }, S, source));
        _add(facts, mkFact('access.admin', h, { identity: 'root', method: 'meterpreter' }, S, source));
        _add(facts, mkFact('access.root', h, { method: 'meterpreter' }, S, source));
        C._add_os_observation(facts, ws, source, 'linux', 'Meterpreter getuid: ' + srvUser, 'high', 'meterpreter', true);
      } else if (/^[a-z_][a-z0-9_.-]{0,31}(?:\s*\(uid=\d+\))?$/i.test(srvUser)) {
        var pUser = srvUser.split(/\s+/)[0];
        _add(facts, mkFact('foothold.linux', h, { identity: pUser, method: 'meterpreter' }, S, source));
        _add(facts, mkFact('access.shell', h, { handler: 'meterpreter', os: 'linux', user: pUser }, S, source));
        C._add_os_observation(facts, ws, source, 'linux', 'Meterpreter getuid: ' + pUser, 'high', 'meterpreter', true);
      }
    }

    var sysM = /\bgot system via technique\s+(\d+)/i.exec(clean);
    if (sysM) {
      _add(facts, mkFact('foothold.windows', h, { identity: 'nt authority\\system', method: 'meterpreter-getsystem' }, S, source));
      _add(facts, mkFact('access.admin', h, { identity: 'nt authority\\system', method: 'meterpreter-getsystem' }, S, source));
      _add(facts, mkFact('access.system', h, { identity: 'nt authority\\system', method: 'meterpreter-getsystem', technique: parseInt(sysM[1], 10) }, S, source));
      C._add_os_observation(facts, ws, source, 'windows', sysM[0].trim(), 'high', 'meterpreter', true);
    }

    var sessM = /\[\*\]\s*(Meterpreter|Command shell) session (\d+) opened\b/i.exec(clean);
    if (sessM) {
      _add(facts, mkFact('access.shell', h, { handler: 'metasploit', session_type: sessM[1].toLowerCase(), session: parseInt(sessM[2], 10) }, S, source));
      if (/\b(?:windows\/|win(?:32|64)|x64\/windows|powershell|smb\/psexec)/i.test(ctx) && !/\b(?:linux|unix|freebsd|osx)\//i.test(ctx)) {
        _add(facts, mkFact('foothold.windows', h, { method: 'metasploit' }, S, source));
        C._add_os_observation(facts, ws, source, 'windows', sessM[0].trim(), 'medium', 'metasploit', true);
      } else if (/\b(?:linux\/|unix\/|cmd\/unix|freebsd\/|osx\/|php\/meterpreter)/i.test(ctx)) {
        _add(facts, mkFact('foothold.linux', h, { method: 'metasploit' }, S, source));
        C._add_os_observation(facts, ws, source, 'linux', sessM[0].trim(), 'medium', 'metasploit', true);
      }
    }

    if (/\[\*\]\s*Migration completed successfully/i.test(clean)) {
      _add(facts, mkFact('access.shell', h, { handler: 'meterpreter', via: 'migration' }, S, source));
      if (!/\b(?:linux\/|unix\/|freebsd\/|osx\/)/i.test(ctx)) {
        _add(facts, mkFact('foothold.windows', h, { method: 'meterpreter-migrate' }, S, source));
      }
    }

    var lesMods = C.uniqueSortedCI(reAll(/\[\+\]\s*\S+\s*-\s*(?<mod>exploit\/(?:windows|linux|multi|osx|freebsd)\/local\/[A-Za-z0-9_/-]+):\s*The target appears to be vulnerable/gim, clean).map(function (m) {
      return m.groups.mod;
    }));
    if (lesMods.length) {
      _add(facts, mkFact('exploit.candidate', h, { tool: 'local_exploit_suggester', modules: lesMods, module: lesMods[0], count: lesMods.length }, S, source));
      _add(facts, mkFact('privesc.leads', h, { kinds: ['exploit.candidate'], modules: lesMods, count: lesMods.length }, S, source));
    }
  }
  C._parse_meterpreter = _parse_meterpreter;

  // ---- Windows localgroup Administrators grant & SAM/SYSTEM/NTDS backup staging receipts ----
  function _parse_windows_admin_staging(text, ws, command, source, facts) {
    if (!text) return;
    var clean = String(text).replace(C._ANSI_RE, '');
    var combined = String(command || '') + '\n' + clean;
    var h = 'host:' + ws.target;

    // 1. net localgroup Administrators <principal> /add + The command completed successfully.
    var lgAddM = /\bnet(?:\.exe)?\s+localgroup\s+['"]?Administrators['"]?\s+['"]?([^\s'"]+)['"]?\s+\/add\b/i.exec(combined);
    if (lgAddM && !/\/domain\b/i.test(lgAddM[0]) && /The command completed successfully\./i.test(clean) && !/\b(?:System error\s+\d+|Access is denied)\b/i.test(clean)) {
      var rawPrin = lgAddM[1].trim();
      var cleanPrin = C._clean_username ? C._clean_username(rawPrin) : rawPrin;
      var hasPotatoSeImp = /Found privilege:\s*SeImpersonatePrivilege\b/i.test(clean)
        || (/\b(?:PrintSpoofer|GodPotato|SweetPotato|JuicyPotato|RoguePotato|EfsPotato)\b/i.test(combined) && /SeImpersonatePrivilege/i.test(combined));
      var adminVal = {
        user: cleanPrin,
        principal: rawPrin,
        method: hasPotatoSeImp ? 'seimpersonate' : 'net-localgroup',
        authorizationProof: 'net-localgroup-administrators'
      };
      _add(facts, mkFact('access.admin', h, adminVal, S, source));
      if (hasPotatoSeImp) {
        _add(facts, mkFact('privesc.seimpersonate', h, { privilege: 'SeImpersonatePrivilege', state: 'Enabled', exploited: true }, S, source));
        _add(facts, mkFact('privesc.windows_privilege', h, { privileges: ['SeImpersonatePrivilege'], state: 'Enabled' }, S, source));
      }
    }

    // 2. reg save hklm\(sam|system|security) <path> + The operation completed successfully.
    var regMatches = reAll(/\breg(?:\.exe)?\s+save\s+hklm\\(sam|system|security)\s+(?:"([^"]+)"|'([^']+)'|([^\s'"]+))/gim, combined);
    if (regMatches.length && /The operation completed successfully\./i.test(clean)) {
      var savedHives = C.uniqueSortedCI(regMatches.map(function (m) {
        return (m[2] || m[3] || m[4] || (m[1] + '.save')).trim();
      }).filter(Boolean));
      if (savedHives.length) {
        _add(facts, mkFact('loot.files', h, { files: savedHives, count: savedHives.length, tool: 'reg-save', via: 'reg-save-hive', sensitive: savedHives }, S, source));
      }
    }

    // 2B. Impacket reg.py backup -> Saved HKLM\(SAM|SYSTEM|SECURITY) to <path>
    var regPySaved = reAll(/Saved\s+HKLM\\(SAM|SYSTEM|SECURITY)\s+to\s+([^\r\n]+)/gi, clean);
    if (regPySaved.length) {
      var pyHivePaths = C.uniqueSortedCI(regPySaved.map(function (m) { return m[2].trim().replace(/^['"]|['"]$/g, ''); }).filter(Boolean));
      var hasSamHive = regPySaved.some(function (m) { return m[1].toUpperCase() === 'SAM'; });
      if (pyHivePaths.length) {
        _add(facts, mkFact('loot.files', h, { files: pyHivePaths, count: pyHivePaths.length, tool: 'reg-backup', via: 'reg-backup-hive', sensitive: pyHivePaths }, S, source));
      }
      if (hasSamHive) {
        _add(facts, mkFact('loot.sam', h, { files: pyHivePaths, via: 'reg-backup', unparsed_hive: true }, S, source));
      }
    }

    // 3. robocopy /b ... ntds.dit backup-mode staging completion
    if (/\brobocopy(?:\.exe)?\b/i.test(combined) && /(?:^|\s)\/b\b/i.test(combined) && /\bntds\.dit\b/i.test(combined)) {
      var roboOk = (/\b100%\b|\bNew File\b[^\r\n]*\bntds\.dit\b|^\s*Files\s*:\s*\d+\s+[1-9]\d*\b/im.test(clean))
        && !/\bERROR\s+\d+\s+\(0x[0-9a-fA-F]+\)/i.test(clean);
      if (roboOk) {
        _add(facts, mkFact('loot.files', h, { files: ['ntds.dit'], count: 1, tool: 'robocopy', via: 'backup-mode-copy', sensitive: ['ntds.dit'] }, S, source));
      }
    }
  }
  C._parse_windows_admin_staging = _parse_windows_admin_staging;

  // ---- Host auxiliary grammars: authorized_keys plant, ls /home, ls .ssh, ImageMagick version, stage delivery, relative find -type f ----
  function _parse_host_auxiliary(text, ws, command, source, facts) {
    var clean = String(text || '').replace(C._ANSI_RE || /\x1b\[[0-9;?]*[ -/]*[@-~]/g, '');
    var cmd = String(command || '');
    if (!clean && !cmd) return;
    var h = 'host:' + ws.target;
    var isAttackerLocal = _is_attacker_local_turn(ws, cmd, clean);
    var callerPrompt = (ws && ws.context && ws.context.promptLine) || '';
    var callerPObj = callerPrompt ? _parse_unix_prompt_line(String(callerPrompt).split(/\r?\n/)[0], { isPromptCtx: true }) : null;

    // 1. Stage-delivery logs (Metasploit / custom HTTP/TCP stager serving payload stage to target)
    if (/\bClient requested stage \d+\b|\bSending stage \(\d+ bytes\)\s+to\b/i.test(clean)) {
      _add(facts, mkFact('host.tool_staged', h, { via: 'stage-delivery' }, S, source));
    }

    // 2. Error-free authorized_keys plant (remote curl PUT/upload or on-host tee/cp/mv/redirect)
    var isCurlPutAuthKeys = /\bcurl\b[^\r\n]*(?:-X\s*PUT\b|-T\s+\S|--upload-file\b)[^\r\n]*\/\.?ssh\/authorized_keys\b/i.test(cmd);
    var isLocalWriteAuthKeys = !isAttackerLocal && /(?:\b(?:tee|cp|mv)\b[^\r\n]*|>>?\s*['"]?)[^\r\n]*?(?:\/|^|['"\s~])\.?ssh\/authorized_keys\b/i.test(cmd);
    if ((isCurlPutAuthKeys || isLocalWriteAuthKeys)
        && /\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)\b|\.pub\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b/i.test(cmd + '\n' + clean)
        && !/\b(?:Permission denied|No such file or directory|Read-only file system|Operation not permitted|cannot open|cannot create|curl:\s*\(\d+\)|Access denied)\b/i.test(clean)
        && !/HTTP\/[12](?:\.\d)?\s+[45]\d\d\b/i.test(clean)) {
      _add(facts, mkFact('credential.ssh_key', h, { via: 'authorized-keys-plant' }, S, source));
    }

    if (isAttackerLocal) return;

    // 3. ls /home (or ls inside /home CWD) -> host.users
    var isLsHome = /^\s*(?:sudo\s+)?ls(?:\s+-[A-Za-z0-9-]+)*\s+\/home\/?\s*$/i.test(cmd)
      || (/^\s*(?:sudo\s+)?ls(?:\s+-[A-Za-z0-9-]+)*\s*$/i.test(cmd) && callerPObj && /^\/home\/?$/.test(callerPObj.cwd || ''));
    if (isLsHome && clean.trim() && !/\b(?:No such file or directory|Permission denied|cannot access)\b/i.test(clean)) {
      var homeUsers = [];
      var isLongLs = /^total\s+\d+\b|^[d-][rwxstST-]{9}/m.test(clean);
      if (isLongLs) {
        clean.split(/\r?\n/).forEach(function (ln) {
          var dm = /^d[rwxstST-]{9}[.+@]?\s+\d+\s+\S+\s+\S+\s+\d+\s+(?:[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+|\d{4}-\d{2}-\d{2}\s+[\d:]+\s+)([a-z_][a-z0-9_.-]{0,31})\/?\s*$/i.exec(ln.trim());
          if (dm && !/^(?:lost\+found)$/i.test(dm[1])) homeUsers.push(dm[1]);
        });
      } else {
        clean.split(/\s+/).forEach(function (tok) {
          var tClean = tok.replace(/\/$/, '').trim();
          if (!tClean || /^(?:ls|total|lost\+found|\.+)$/i.test(tClean)) return;
          if (/^[a-z_][a-z0-9_.-]{0,31}$/i.test(tClean)) homeUsers.push(tClean);
        });
      }
      var uniqHome = C.uniqueSortedCI(homeUsers);
      if (uniqHome.length) {
        _add(facts, mkFact('host.users', h, { users: uniqHome, count: uniqHome.length, via: 'ls-home' }, S, source));
      }
    }

    // 4. ls inside .ssh listing private key filename -> loot.ssh_key (unverified_read: true)
    var isLsSsh = /\bls\b[^\r\n]*(?:^|[\s'"])(?:~|\S*)?\/?\.ssh\/?(?:\s|$|['"])/i.test(cmd)
      || (/^\s*(?:sudo\s+)?ls(?:\s+-[A-Za-z0-9-]+)*\s*$/i.test(cmd) && callerPObj && /(?:^|\/)\.ssh\/?$/.test(callerPObj.cwd || ''));
    if (isLsSsh && clean.trim() && !/\b(?:No such file or directory|Permission denied|cannot access)\b/i.test(clean)) {
      var keyM = /(?:^|\s)(id_(?:rsa|ed25519|ecdsa|dsa|xmss)|identity)(?=\s|$)/im.exec(clean);
      if (keyM) {
        _add(facts, mkFact('loot.ssh_key', h, { file: keyM[1], unverified_read: true, via: 'ls-ssh' }, S, source));
      }
    }

    // 5. ImageMagick CVE-2024-41817 version banner (when not routed through _parse_privesc)
    var imAuxM = /Version:\s+ImageMagick\s+(6\.\d+\.\d+-\d+|7\.0\.\d+-\d+|7\.1\.(?:0-\d+|1-(?:[0-2]?\d|3[0-5])))\b/i.exec(clean);
    if (imAuxM && !facts.some(function (f) { return f && f.kind === 'privesc.library_or_script_hijack'; })) {
      var auxLeads = {};
      _add_host_privesc_fact(facts, ws, source, 'privesc.library_or_script_hijack', {
        target: 'ImageMagick ' + imAuxM[1],
        target_type: 'so',
        reason: 'imagemagick_delegate_la_search_path',
        cve: 'CVE-2024-41817'
      }, auxLeads);
      _add_privesc_leads(facts, ws, source, auxLeads);
    }

    // 6. Non-empty relative `find <dir>/ -type f` enumerating local files -> loot.files
    var relFindM = /^\s*(?:sudo\s+)?find\s+(?!\/(?:\s|$))([A-Za-z0-9_.-][A-Za-z0-9_./-]*)\s+[^\r\n]*-type\s+f\b/i.exec(cmd);
    if (relFindM && !/\s-perm\b/i.test(cmd) && clean.trim()) {
      var prefixNorm = relFindM[1].replace(/\/+$/, '');
      var foundFiles = [];
      clean.split(/\r?\n/).forEach(function (ln) {
        var fl = ln.trim();
        if (!fl || /^find:\s/i.test(fl) || fl.indexOf(' ') >= 0) return;
        if (fl.indexOf(prefixNorm + '/') === 0 || fl.indexOf('./') === 0) foundFiles.push(fl);
      });
      if (foundFiles.length) {
        var uniqFound = C.uniqueSortedCI(foundFiles);
        _add(facts, mkFact('loot.files', h, { files: uniqFound.slice(0, 50), path: uniqFound[0], count: uniqFound.length, tool: 'find', via: 'find-type-f' }, S, source));
      }
    }
  }
  C._parse_host_auxiliary = _parse_host_auxiliary;

})(typeof globalThis !== 'undefined' ? globalThis : this);
