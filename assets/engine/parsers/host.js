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

  function _parse_command_execution(text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var identities = reAll(C._WHOAMI_ID_RE, text).map(function (m) { return _normalize_identity(m.groups.id); }).filter(Boolean);
    var isSystem = identities.some(function (identity) { return identity.toLowerCase() === 'nt authority\\system'; });
    var isAdminWhoami = identities.some(function (identity) { return /(?:^|[\\/])administrator$/i.test(identity); });
    var interactive = !!reSearch(C._INTERACTIVE_RE, text) || (command || '').toLowerCase().indexOf('enter-pssession') >= 0 || /^\s*(?:PS\s+)?[A-Za-z]:\\[^>\r\n]*>/im.test(text || '');
    var executed = identities.length > 0 || !!reSearch(C._EXEC_SUCCESS_RE, text) || interactive;
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
        var pm = /^\s*(?:\*?Evil-WinRM\*?\s+)?(?:PS\s+)?[A-Za-z]:\\Users\\([A-Za-z0-9._-]+)(?:\\[^>"'\r\n]*)?>/im.exec(text || '');
        if (pm && pm[1] && !/^(Public|Default|All Users)$/i.test(pm[1])) nonSystem.push(pm[1]);
      }
      if (!nonSystem.length && !isSystem && command) {
        var cmdUser = C._command_arg ? C._command_arg(command, ['-u', '--user', '--username']) : '';
        if (!cmdUser) {
          var impM = /\b(?:impacket-[\w.-]+|(?:wmi|ps|smb|at|dcom)exec(?:\.py)?)\b[^\r\n]*?(?:['"](?:[^/'":@\s]+[\\/])?([A-Za-z0-9._$-]+)(?::[^@'"]*)?@|(?:^|\s)(?:[^/'":@\s]+[\\/])?([A-Za-z0-9._$-]+)(?::[^\s@'"]*)?@\d{1,3}(?:\.\d{1,3}){3})/i.exec(command);
          if (impM) cmdUser = impM[1] || impM[2] || '';
        }
        if (cmdUser) {
          var cleanedCmdUser = C._clean_username ? C._clean_username(cmdUser) : cmdUser;
          if (cleanedCmdUser) nonSystem.push(cleanedCmdUser);
        }
      }
      if (nonSystem.length) {
        footholdValue.identity = nonSystem[0];
        for (var i = facts.length - 1; i >= 0; i--) {
          var f = facts[i];
          if (f.kind === 'foothold.windows' && f.scope === h && !('identity' in f.value)) facts.splice(i, 1);
        }
      }
      _add(facts, mkFact('foothold.windows', h, footholdValue, S, source));
      C._add_os_observation(facts, ws, source, 'windows', 'Windows command execution output', 'high', tool, true);
      if (isSystem) _add(facts, mkFact('access.system', h, { identity: 'nt authority\\system', method: tool }, S, source));
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

  function _parse_ssh_exec(text, ws, command, source, facts) {
    var m = reSearch(C._LINUX_ID_RE, text);
    if (!m) return;
    // A copied enumeration report can contain uid lines without establishing a new
    // remote session. Its identity and privilege leads are read by local-enum parsers.
    if (_is_local_enum_report(text, command)) return;
    var h = 'host:' + ws.target, user = m.groups.user.trim();
    var cs = ((command || '') + ' ' + (source || '')).toLowerCase();
    var svc = /\bssh\b/.test(cs) ? 'ssh' : 'shell';
    if (cs.indexOf('psql') >= 0 || cs.indexOf('postgres') >= 0) svc = 'postgresql';
    else if (cs.indexOf('elastic') >= 0) svc = 'elasticsearch';
    else if (cs.indexOf('rsync') >= 0) svc = 'rsync';
    else if (cs.indexOf('nfs') >= 0) svc = 'nfs';
    else if (cs.indexOf('tftp') >= 0) svc = 'tftp';
    else if (cs.indexOf('vnc') >= 0) svc = 'vnc';
    _add(facts, mkFact('access.shell', h, { service: svc }, S, source));
    _add(facts, mkFact('foothold.linux', h, { service: svc, identity: user }, S, source));
    C._add_os_observation(facts, ws, source, 'linux', m[0], 'high', svc, true);
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
    var h = 'host:' + ws.target;
    var user = C._command_arg(command, ['-u', '--user', '--username']);
    var value = { service: 'rdp' };
    if (user) value.user = C._clean_username(user);
    _add(facts, mkFact('rdp.authenticated', h, value, S, source));
    var foothold = { method: 'rdp' };
    if (user) foothold.identity = C._clean_username(user);
    _add(facts, mkFact('foothold.windows', h, foothold, S, source));
    C._add_os_observation(facts, ws, source, 'windows', 'nxc rdp authentication succeeded', 'high', 'nxc', true);
    if (user && C._clean_username(user).toLowerCase() === 'administrator') _add(facts, mkFact('access.admin', h, { service: 'rdp' }, S, source));
  }
  C._parse_nxc_rdp = _parse_nxc_rdp;

  function _parse_xfreerdp(text, ws, command, source, facts) {
    var t = String(text || '');
    var logonM = /Logon Info V\d+\s*\[([^\]]+)\]/i.exec(t);
    var authOnlyOk = /Authentication only,\s*exit status 0\b/i.test(t);
    if (!logonM && !authOnlyOk) return;
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

  function _add_host_privesc_fact(facts, ws, source, kind, value, leadKinds) {
    _add(facts, mkFact(kind, 'host:' + ws.target, value, S, source));
    if (kind.indexOf('privesc.') === 0 && kind !== 'privesc.leads') leadKinds[kind] = true;
  }
  function _add_privesc_leads(facts, ws, source, leadKinds) {
    var kinds = Object.keys(leadKinds);
    if (!kinds.length) return;
    kinds.sort();
    _add(facts, mkFact('privesc.leads', 'host:' + ws.target, { kinds: kinds, count: kinds.length }, S, source));
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
    apache2: 'apache2', openvpn: 'openvpn', capsh: 'capsh', setarch: 'setarch', time: 'time', timeout: 'timeout',
    watch: 'watch', expect: 'expect', ionice: 'ionice', nice: 'nice', nohup: 'nohup', stdbuf: 'stdbuf',
    taskset: 'taskset', chroot: 'chroot', nsenter: 'nsenter', unshare: 'unshare', doas: 'doas',
    'ansible-playbook': 'ansible-playbook', logrotate: 'logrotate'
  };

  function _normalize_gtfobin(base) {
    base = String(base || '').toLowerCase();
    if (_GTFOBINS_SUDO[base]) return _GTFOBINS_SUDO[base];
    var stripped = base.replace(/\.(?:basic|tiny|nox|gtk3?|athena|orig|distrib)$/i, '').replace(/[0-9.]+$/, '');
    if (_GTFOBINS_SUDO[stripped]) return _GTFOBINS_SUDO[stripped];
    return '';
  }

  var _STOCK_SUID_BINS = new Set([
    'passwd', 'su', 'sudo', 'mount', 'umount', 'chsh', 'chfn', 'newgrp', 'gpasswd',
    'fusermount', 'fusermount3', 'pkexec', 'polkit-agent-helper-1', 'ssh-keysign',
    'dbus-daemon-launch-helper', 'unix_chkpwd', 'chage', 'expiry', 'ping', 'ping6',
    'traceroute6.iputils', 'pppd', 'ntfs-3g', 'xorg.wrap', 'snap-confine', 'bwrap',
    'mount.cifs', 'mount.nfs', 'umount.nfs', 'at', 'crontab', 'pam_timestamp_check', 'pt_chown'
  ]);

  function _is_stock_suid(p) {
    var base = String(p || '').split('/').pop().toLowerCase();
    return _STOCK_SUID_BINS.has(base) && /^\/(?:usr\/)?(?:bin|sbin|lib|lib64|libexec)\//i.test(p);
  }

  function _parse_kernel_exploits(text, ws, command, source, facts, leadKinds) {
    var hits = [], cves = [], names = {};
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
      hits.push(line.slice(0, 200));
      cves.push(cve[0].toUpperCase());
      if (named) names[named] = true;
      if (hits.length >= 20) break;
    }
    if (!hits.length) return;
    var value = { cves: C.uniqueSortedCI(cves), evidence: hits, count: hits.length };
    var nk = Object.keys(names);
    if (nk.length) value.names = nk.sort();
    _add_host_privesc_fact(facts, ws, source, 'privesc.kernel_exploit', value, leadKinds);
    _add(facts, mkFact('exploit.candidate', 'host:' + ws.target, { tool: 'linux-exploit-suggester', cves: C.uniqueSortedCI(cves), findings: hits }, S, source));
    var h = 'host:' + ws.target;
    if (names['dirtycow'] || names['dirty cow']) {
      _add(facts, mkFact('vuln.dirtycow', h, { cve: 'CVE-2016-5195', via: 'exploit-suggester', lead: true }, S, source));
    }
    if (names['dirtypipe'] || names['dirty pipe']) {
      _add(facts, mkFact('vuln.dirtypipe', h, { cve: 'CVE-2022-0847', via: 'exploit-suggester', lead: true }, S, source));
    }
    if (names['baron samedit'] || names['sudoedit']) {
      _add(facts, mkFact('vuln.baron_samedit', h, { cve: 'CVE-2021-3156', via: 'exploit-suggester', lead: true }, S, source));
    }
    if (names['pwnkit'] || names['polkit'] || names['pkexec']) {
      _add(facts, mkFact('vuln.polkit', h, { cve: 'CVE-2021-4034', via: 'exploit-suggester', lead: true }, S, source));
    }
  }

  function _parse_linux_privesc_output(text, ws, command, source, facts, leadKinds) {
    var lowered = text.toLowerCase(), lc = (command || '').toLowerCase(), h = 'host:' + ws.target;
    var idMatch = reSearch(C._LINUX_ID_RE, text);
    if (idMatch) {
      var user = idMatch.groups.user.trim();
      C._add_os_observation(facts, ws, source, 'linux', idMatch[0], 'high', 'local-enum', true);
      var idLine = C._line_for_match(text, idMatch) || idMatch[0];
      var groups = C.uniqueSortedCI(reAll(/\d+\(([^)]+)\)/, idLine).map(function (m) { return m[1].toLowerCase(); }));
      if (groups.indexOf('lxd') >= 0 || groups.indexOf('lxc') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.lxd_group', { groups: groups, user: user }, leadKinds);
      if (groups.indexOf('docker') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.docker_group', { groups: groups, user: user }, leadKinds);
      if (idMatch.groups.uid === '0' || (idMatch.groups.euid && idMatch.groups.euid === '0') || /\beuid=0\(root\)/i.test(idLine)) {
        _add(facts, mkFact('access.admin', h, { identity: user, uid: 0, method: 'local-enum' }, S, source));
        _add(facts, mkFact('access.root', h, { method: 'shell' }, S, source));
      }
    } else if (lc.indexOf('whoami') >= 0 && /(?:^|\n)\s*root\s*(?:\n|$)/i.test(text)) {
      _add(facts, mkFact('access.admin', h, { identity: 'root', method: 'whoami' }, S, source));
      _add(facts, mkFact('access.root', h, { method: 'shell' }, S, source));
    } else if (/\bgroups\b/i.test(lc)) {
      var bareGroups = C.uniqueSortedCI((text.match(/\b(?:docker|lxd|lxc)\b/gi) || []).map(function (g) { return g.toLowerCase(); }));
      if (bareGroups.indexOf('lxd') >= 0 || bareGroups.indexOf('lxc') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.lxd_group', { groups: bareGroups }, leadKinds);
      if (bareGroups.indexOf('docker') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.docker_group', { groups: bareGroups }, leadKinds);
    }

    var uname = reSearch(C._UNAME_RE, text);
    if (uname) {
      _add_host_privesc_fact(facts, ws, source, 'host.kernel', { kernel: uname.groups.kernel, tool: 'uname', evidence: uname[0].trim().slice(0, 220) }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'host.arch', { arch: uname.groups.arch, tool: 'uname' }, leadKinds);
      C._add_os_observation(facts, ws, source, 'linux', uname[0], 'high', 'uname', true, C._os_product_from_label(text, 'linux'));
      if (C._check_linux_kernel_vulns) C._check_linux_kernel_vulns(uname.groups.kernel, ws, source, facts, leadKinds);
    } else {
      var procVer = /Linux version\s+([0-9][^\s]+)/i.exec(text) || /\bKernel:\s*(?:Linux\s+)?([2-6]\.\d+\.\d+-[0-9A-Za-z.+_-]+)/i.exec(text);
      var bareKernel = /^\s*([2-6]\.\d+\.\d+-[0-9A-Za-z.+_-]+)\s*$/m.exec(text);
      var kMatch = procVer || ((lc.indexOf('uname') >= 0 || (bareKernel && /(?:generic|amd64|i[3-6]86|arm64|el\d|kali|debian|ubuntu|arch|alpine|-\d+-)/i.test(bareKernel[1]))) ? bareKernel : null);
      if (kMatch && kMatch[1]) {
        _add_host_privesc_fact(facts, ws, source, 'host.kernel', { kernel: kMatch[1].trim(), tool: 'uname', evidence: kMatch[0].trim().slice(0, 220) }, leadKinds);
        C._add_os_observation(facts, ws, source, 'linux', kMatch[0], 'high', 'uname', true, C._os_product_from_label(text, 'linux'));
        if (C._check_linux_kernel_vulns) C._check_linux_kernel_vulns(kMatch[1].trim(), ws, source, facts, leadKinds);
      }
    }

    var osRel = /PRETTY_NAME\s*=\s*["']?([^"'\r\n]+)["']?/i.exec(text) || /Distributor ID:\s*(\S+)/i.exec(text) || /\b(?:OS|Operating System):\s*((?:Debian|Ubuntu|CentOS|Red Hat|Fedora|Kali|Alpine|Arch|Rocky|AlmaLinux|SUSE|openSUSE|Gentoo|FreeBSD)[^\r\n]*)/i.exec(text);
    if (osRel && osRel[1]) {
      C._add_os_observation(facts, ws, source, 'linux', osRel[0], 'high', 'os-release', true, osRel[1].trim());
    }

    var sudoVer = /Sudo(?:\s+version|\s+policy\s+plugin\s+version)\s+(1\.(?:8\.(?:[2-9]|[12]\d|3[01])|9\.[0-5](?:p1)?))\b/i.exec(text);
    if (sudoVer && sudoVer[1]) {
      _add(facts, mkFact('vuln.baron_samedit', h, { cve: 'CVE-2021-3156', version: sudoVer[1], lead: true }, S, source));
    }

    var pkexecVer = /pkexec\s+version\s+(0\.(?:0\d\d|10[0-5]))\b/i.exec(text);
    if (pkexecVer && pkexecVer[1]) {
      _add(facts, mkFact('vuln.polkit', h, { cve: 'CVE-2021-4034', version: pkexecVer[1], lead: true }, S, source));
    }

    var sudoEntries = [];
    var hasDoas = /\bpermit\s+(?:nopass\s+)?\S+(?:\s+as\s+root)?/i.test(text);
    var hasEnvKeep = /env_keep\s*\+?=\s*["']?[^\r\n"']*\b(?:LD_PRELOAD|LD_LIBRARY_PATH)\b/i.test(text);
    if (lowered.indexOf('may run the following commands') >= 0 || lowered.indexOf('nopasswd:') >= 0 || hasDoas || hasEnvKeep) {
      text.split(/\r?\n/).forEach(function (raw) {
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
      _add_host_privesc_fact(facts, ws, source, 'privesc.sudo_rights',
        { entries: C.uniqueSortedCI(sudoEntries).slice(0, 20), nopasswd: sudoEntries.some(function (e) { return /nopasswd|nopass/i.test(e); }) }, leadKinds);
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

    var suidPaths = {};
    var suidFind = ['-perm -4000', '-perm -u=s', '-perm /4000', '-perm /u=s'].some(function (t) { return lc.indexOf(t) >= 0; }) || /\bfind\s+\/.*-perm\b/i.test(text);
    var bareSuidList = (text.match(/^\s*\/(?:usr\/|bin\/|sbin\/|opt\/)[A-Za-z0-9._\/-]+\s*$/gm) || []).length >= 2;
    if (suidFind || lowered.indexOf('suid') >= 0 || lowered.indexOf('rws') >= 0 || bareSuidList) {
      text.split(/\r?\n/).forEach(function (raw) {
        var line = raw.trim();
        if (!line || line.indexOf('/proc/') >= 0) return;
        if (line.toLowerCase().indexOf('rws') >= 0) {
          var mm = reSearch(C._SUID_PATH_RE, line);
          if (mm && !_is_stock_suid(mm.groups.path)) suidPaths[mm.groups.path] = true;
          return;
        }
        if ((suidFind || bareSuidList) && line[0] === '/' && line.indexOf(' ') < 0 && !_is_stock_suid(line)) suidPaths[line] = true;
      });
    }
    var suidKeys = Object.keys(suidPaths);
    if (suidKeys.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.suid_candidate', { paths: suidKeys.sort().slice(0, 500), count: suidKeys.length }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'privesc.suid', { binaries: suidKeys.sort().slice(0, 500), paths: suidKeys.sort().slice(0, 500), count: suidKeys.length }, leadKinds);
    }
    if (suidKeys.some(function (p) { return /screen-4\.5\.0/i.test(p); }) || /screen-4\.5\.0|GNU Screen 4\.5\.0|Screen version 4\.05\.00/i.test(text)) {
      _add_host_privesc_fact(facts, ws, source, 'vuln.screen_suid', { cve: 'CVE-2017-5618', via: 'suid-scan' }, leadKinds);
    }

    var caps = reAll(C._CAPABILITY_RE, text).map(function (m) { return { path: m.groups.path, capabilities: m.groups.caps.trim() }; }).filter(function (c) {
      if (/\/(?:ping6?|mtr-packet|traceroute6\.iputils)$/i.test(c.path) && /^cap_net_raw(?:=[eip]+|\+[eip]+)?$/i.test(c.capabilities)) return false;
      if (C._DANGEROUS_CAPS && !C._DANGEROUS_CAPS.test(c.capabilities)) return false;
      return true;
    });
    if (caps.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.capability', { entries: caps.slice(0, 500), count: caps.length }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'privesc.capabilities', { entries: caps.slice(0, 500), binaries: caps.slice(0, 500).map(function (c) { return c.path; }), count: caps.length }, leadKinds);
    }

    reAll(C._PASSWD_MODE_RE, text).forEach(function (passwd) {
      var mode = passwd.groups.mode;
      var etcPath = (passwd.groups && passwd.groups.path) || '/etc/passwd';
      var groupWritable = mode[5] === 'w', worldWritable = mode[8] === 'w';
      if (groupWritable || worldWritable) {
        _add_host_privesc_fact(facts, ws, source, 'privesc.passwd_writable', { path: etcPath, mode: mode, world_writable: worldWritable, group_writable: groupWritable }, leadKinds);
        _add_host_privesc_fact(facts, ws, source, 'privesc.writable_etc', { path: etcPath, mode: mode, world_writable: worldWritable, group_writable: groupWritable }, leadKinds);
      }
    });

    if (lowered.indexOf('no_root_squash') >= 0 && !/\b(?:showmount|nmap)\b/i.test(command || '') && !/^Export list for\s+/im.test(text || '')) {
      var exports = text.split(/\r?\n/).filter(function (l) { return l.toLowerCase().indexOf('no_root_squash') >= 0; }).map(function (l) { return l.trim(); });
      _add_host_privesc_fact(facts, ws, source, 'privesc.nfs_no_root_squash', { exports: exports.slice(0, 20), count: exports.length || 1 }, leadKinds);
    }

    var cronLines = text.split(/\r?\n/).filter(function (l) {
      if (/cron|timer|systemd|\.service\b/i.test(l) && (/\b(writable|world-writable|777|666)\b/i.test(l) || /^-[r-][w-][xsStT-][r-]w[xsStT-]|^-[r-][w-][xsStT-]{4}[r-]w[xsStT-]|\brwx/i.test(l.trim()))) return true;
      if (lc.indexOf('-writable') >= 0 && /^\s*\/(?:etc|lib|usr\/lib)\/(?:systemd|cron)[^\s]*$/i.test(l)) return true;
      if (/^\s*(?:(?:[0-9*,/-]+\s+){5}|@(?:reboot|hourly|daily|weekly|monthly)\s+)(?:root\s+)?(?<cmd>(?:\/|(?:sh|bash|python\d?|perl|php|ruby)\s+\/)[^\r\n#]+)/i.test(l)) {
        if (!/\brun-parts\b|\/etc\/cron\.(?:hourly|daily|weekly|monthly)\b|debian-sa1|anacron|e2scrub|fstrim/i.test(l)) return true;
      }
      return false;
    }).map(function (l) { return l.trim(); });
    if (cronLines.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.cron_writable', { evidence: cronLines.slice(0, 20) }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'privesc.cron', { jobs: cronLines.slice(0, 20), count: cronLines.length }, leadKinds);
    }

    var isInteractiveExploitCmd = /\b(?:python[23]?|perl|ruby)\s+-c\b|\bos\.set(?:e?[ug]id)\s*\(/i.test(command || '');
    var processLines = text.split(/\r?\n/).filter(function (l) {
      if (/\b(?:python[23]?|perl|ruby)\s+-c\b|\bos\.set(?:e?[ug]id)\s*\(/i.test(l) && !/\bUID=0\b.*\bPID=/i.test(l) && !/\bCMD:/i.test(l)) return false;
      return /\bUID=0(?!\()\b|\broot\b.*\bCMD\b|\bCMD:/i.test(l);
    }).map(function (l) { return l.trim(); });
    if (!isInteractiveExploitCmd && processLines.length && (lc.indexOf('pspy') >= 0 || lowered.indexOf('uid=0') >= 0 || lowered.indexOf('cmd:') >= 0)) _add_host_privesc_fact(facts, ws, source, 'privesc.process_lead', { commands: processLines.slice(0, 30) }, leadKinds);

    if (reSearch(C._LOCAL_FILE_SECRET_RE, text)) _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'local_file_secret', evidence: 'local loot output' }, S, source));

    _parse_kernel_exploits(text, ws, command, source, facts, leadKinds);
  }
  C._parse_linux_privesc_output = _parse_linux_privesc_output;

  function _parse_windows_privesc_output(text, ws, command, source, facts, leadKinds) {
    var lowered = text.toLowerCase(), h = 'host:' + ws.target;
    var observedSystem = reAll(C._WHOAMI_ID_RE, text).some(function (m) { return m.groups.id.toLowerCase() === 'nt authority\\system'; });
    if (observedSystem) {
      C._add_os_observation(facts, ws, source, 'windows', 'Windows local command output', 'high', 'local-enum', true);
      _add(facts, mkFact('access.system', h, { identity: 'nt authority\\system', method: 'local-enum' }, S, source));
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
    if (privileges.length) {
      var uniqPrivs = C.uniqueSortedCI(privileges);
      _add_host_privesc_fact(facts, ws, source, 'privesc.windows_privilege', { privileges: uniqPrivs, state: 'Enabled' }, leadKinds);
      var lowPrivs = uniqPrivs.map(function (p) { return p.toLowerCase(); });
      if (lowPrivs.indexOf('sebackupprivilege') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.sebackup', { privilege: 'SeBackupPrivilege', state: 'Enabled' }, leadKinds);
      if (lowPrivs.indexOf('serestoreprivilege') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.serestore', { privilege: 'SeRestorePrivilege', state: 'Enabled' }, leadKinds);
      if (lowPrivs.indexOf('semanagevolumeprivilege') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.semanagevolume', { privilege: 'SeManageVolumePrivilege', state: 'Enabled' }, leadKinds);
    }

    var privGroups = [];
    var winGroupRe = /(?:BUILTIN\\|(?<![A-Za-z0-9._-])[A-Za-z0-9._-]{1,64}\\|\b)(Backup Operators|DnsAdmins|Server Operators|Print Operators|Account Operators|Hyper-V Administrators|Exchange Windows Permissions|Organization Management)\b/gi;
    var gm;
    while ((gm = winGroupRe.exec(text)) !== null) {
      if (privGroups.indexOf(gm[1]) < 0) privGroups.push(gm[1]);
    }
    if (privGroups.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.privileged_group', { groups: C.uniqueSortedCI(privGroups), count: privGroups.length }, leadKinds);
    }

    if (lowered.indexOf('alwaysinstallelevated') >= 0) {
      var aieHklm = false, aieHkcu = false, currentHive = '';
      text.split(/\r?\n/).forEach(function (raw) {
        if (reSearch(C._HKLM_HEADER_RE, raw)) currentHive = 'hklm';
        else if (reSearch(C._HKCU_HEADER_RE, raw)) currentHive = 'hkcu';
        var vm = reSearch(C._AIE_VALUE_RE, raw);
        if (!vm) return;
        var enabled = parseInt(vm.groups.val, 16) !== 0;
        if (currentHive === 'hklm') aieHklm = enabled;
        else if (currentHive === 'hkcu') aieHkcu = enabled;
      });
      if (aieHklm && aieHkcu) _add_host_privesc_fact(facts, ws, source, 'privesc.always_install_elevated', { hklm: true, hkcu: true }, leadKinds);
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

    var weakService = [];
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (reSearch(C._WEAK_SVC_ACCESS_RE, line) || reSearch(C._LOWPRIV_WRITE_ACE_RE, line) || (C._WEAK_SERVICE_PERM_RE && reSearch(C._WEAK_SERVICE_PERM_RE, line))) weakService.push(line.slice(0, 220));
    });
    if (weakService.length) _add_host_privesc_fact(facts, ws, source, 'privesc.weak_service_permission', { evidence: C.uniqueSortedCI(weakService).slice(0, 30) }, leadKinds);

    var stored = [];
    var cmdkeyNone = /Currently stored credentials:[\s\S]{0,160}?\*\s*NONE\s*\*/i.test(text);
    [['Target:', 'cmdkey'], ['Currently stored credentials', 'cmdkey'], ['Saved ', 'cmdkey'], ['DefaultPassword', 'autologon'], ['unattend.xml', 'unattend'], ['sysprep', 'sysprep'], ['confCons.xml', 'mRemoteNG'], ['.rdp', 'rdp_file'], ['simontatham', 'putty'], ['winscp', 'winscp'], ['vncpassword', 'vnc']].forEach(function (pair) {
      if (pair[1] === 'cmdkey' && cmdkeyNone) return;
      if (pair[0] === 'DefaultPassword' && !/DefaultPassword\s+REG_SZ\s+\S+/i.test(text)) return;
      if (lowered.indexOf(pair[0].toLowerCase()) >= 0) stored.push(pair[1]);
    });
    if (stored.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.stored_credentials', { kinds: C.uniqueSortedCI(stored), count: C.uniqueSortedCI(stored).length }, leadKinds);
      _add(facts, mkFact('credential.candidate', h, { kind: 'stored_windows_credentials' }, S, source));
    }

    var dllHits = text.split(/\r?\n/).filter(function (raw) { var l = raw.toLowerCase(); return l.indexOf('.dll') >= 0 && (l.indexOf('name not found') >= 0 || l.indexOf('path not found') >= 0); }).map(function (raw) { return raw.trim().slice(0, 220); });
    if (dllHits.length) _add_host_privesc_fact(facts, ws, source, 'privesc.dll_hijack_candidate', { evidence: C.uniqueSortedCI(dllHits).slice(0, 20), count: C.uniqueSortedCI(dllHits).length }, leadKinds);

    var patchLines = text.split(/\r?\n/).filter(function (l) { return /\bMS\d{2}-\d{3}\b|CVE-\d{4}-\d+|missing patches?|exploit/i.test(l); }).map(function (l) { return l.trim(); });
    if (patchLines.length && (/wes(?:\.py|ng)?|windows[- ]exploit[- ]suggester|missing patches?|found vulnerabilities/i.test((command || '') + '\n' + text))) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.patch_gap', { evidence: patchLines.slice(0, 30) }, leadKinds);
      _add(facts, mkFact('exploit.candidate', h, { tool: 'windows-exploit-suggester', findings: patchLines.slice(0, 30) }, S, source));
    }
  }
  C._parse_windows_privesc_output = _parse_windows_privesc_output;

  function _looks_like_linux_enum(text) {
    var t = String(text || '');
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
      /══╣/.test(t) ||
      reSearch(C._CAPABILITY_RE, t) ||
      reSearch(C._PASSWD_MODE_RE, t) ||
      /no_root_squash/i.test(t) ||
      /\bUID=0\b.*\bCMD\b|\bCMD:\s*UID=0\b/i.test(t) ||
      /^\s*(?:[0-9*,/-]+\s+){5}(?:root\s+)?\/(?:opt|home|tmp|var|srv|etc|usr\/local)\//m.test(t) ||
      /\bpermit\s+nopass\b/i.test(t) ||
      /\bfind\s+\/.*-perm\b/i.test(t) ||
      /\bgetcap\b/i.test(t) ||
      /(?:^|\r?\n)\s*\/(?:usr\/|bin\/|sbin\/|opt\/)[A-Za-z0-9._\/-]+\s*\r?\n\s*\/(?:usr\/|bin\/|sbin\/|opt\/)[A-Za-z0-9._\/-]+/.test(t) ||
      /^\s*-[rwxstST-]{9}\s+\d+\s+root\s+/m.test(t) ||
      /CVE-\d{4}-\d{4,7}.*?\b(?:dirty|pwnkit|polkit|samedit|overlayfs)/i.test(t) ||
      /Sudo(?:\s+version|\s+policy\s+plugin\s+version)\s+\d/i.test(t) ||
      /pkexec\s+version\s+\d/i.test(t) ||
      /\bgroups=[^\r\n]*\((?:docker|lxd|lxc|adm|disk|shadow)\)/i.test(t)
    );
  }
  C._looks_like_linux_enum = _looks_like_linux_enum;

  function _looks_like_windows_enum(text) {
    var t = String(text || '');
    if (!t.trim()) return false;
    return !!(
      /^\s*OS Name:\s*Microsoft Windows/im.test(t) ||
      /Microsoft Windows \[Version\s+[0-9.]+\]/i.test(t) ||
      /Saved [A-Z0-9_-]+ credentials|Currently stored credentials:/i.test(t) ||
      /ServiceName\s*:\s*\S+[\s\S]{1,200}?PathName\s*:/i.test(t) ||
      /\b(?:BINARY_PATH_NAME|Binary Path Name|PathName)\s*[:=]\s*["']?[A-Za-z]:\\/i.test(t) ||
      /\b(?:Backup Operators|DnsAdmins|Server Operators|Print Operators)\b[\s\S]{0,80}?\bS-1-5-/i.test(t) ||
      /Found vulnerabilities|\bMS\d{2}-\d{3}\b.*CVE-\d{4}-\d+/i.test(t) ||
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
    var t = text || '';
    return !!(reSearch(C._WIN_PRIV_RE, t) || /\b(?:Backup Operators|DnsAdmins|Server Operators|Print Operators)\b[\s\S]{0,80}?\bS-1-5-/i.test(t));
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
    // 2) net user <name> /domain showing domain-group membership → ad.user_list (the named account)
    var domainMembership = reSearch(_NET_DOMAIN_MEMBERSHIP_RE, text);
    var nm = reSearch(_NET_USER_NAME_RE, text);
    if (nm && domainMembership) {
      var user = C._clean_username(nm.groups.user);
      if (C._valid_username(user, false)) {
        var domain = C._domain_from_facts(ws);
        _add(facts, mkFact('ad.user_list', C._scope_for_domain(ws, domain), { users: [user], count: 1, method: 'net' }, S, source));
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
    var t = text || '';
    if (/winpeas|privesccheck|peass-ng|\bPEASS\b/i.test(t)) return true;
    if (/Checking (?:Token privileges|Credentials in files|AlwaysInstallElevated|Unquoted|Service)/i.test(t)) return true;
    return /^\s*Se[A-Za-z0-9]+Privilege\s*:\s*(?:Enabled|Disabled)\s*$/im.test(t);
  }
  C._looks_like_winpeas = _looks_like_winpeas;

  function _parse_winpeas(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var norm = text.replace(/^(\s*)(Se[A-Za-z0-9]+Privilege)\s*:\s*(Enabled|Disabled)\b/gim, '$1$2  state  $3');
    var leadKinds = {};
    _parse_windows_privesc_output(norm, ws, command, source, facts, leadKinds);
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

  function _parse_script_sinks(text, command, ws, source, facts) {
    var t = text || '', cmd = (command || '').toLowerCase();
    var isRead = _FILE_READ_CMDS.some(function (w) { return cmd.indexOf(w) >= 0; });
    var looksLikeCode = t.indexOf('def ') >= 0 || t.indexOf('import ') >= 0 || t.slice(0, 64).replace(/^\s+/, '').indexOf('#!') === 0;
    if (!(isRead || looksLikeCode)) return;
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

  function _has_windows_creds(text) {
    text = text || '';
    if (reSearch(_PS_SECURESTRING_RE, text) || reSearch(_PUTTY_PROXYPW_RE, text)) return true;
    return _WIN_CRED_RES.some(function (pair) { return reSearch(pair[1], text); });
  }
  C._has_windows_creds = _has_windows_creds;

  function _parse_windows_creds(text, ws, command, source, facts) {
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
        var key = user + '|' + pw;
        if (seen[key]) return;
        seen[key] = true;
        _add(facts, mkFact('credential.candidate', h, { user: user, password: C.stripChars(pw, "'\""), via: idiom }, S, source));
      });
    });
    reAll(_PS_SECURESTRING_RE, text).forEach(function (m) {
      var pw = m.groups.pw, key = '|' + pw;
      if (seen[key]) return;
      seen[key] = true;
      _add(facts, mkFact('credential.candidate', h, { password: pw, via: 'convertto-securestring' }, S, source));
    });
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
  var _NOTABLE_USER_LOC_RE = /[A-Za-z]:\\Users\\[^\\\r\n]+\\(?:Desktop|Documents|Downloads|Public|Scripts)|\/home\/[^/\r\n]+\/|\/root\/|\/opt\/|\/tmp\/|\/srv\/|\/usr\/local\//i;
  var _NOTABLE_WIN_EXT_RE = /\.(?:exe|bat|cmd|ps1|vbs)$/i;

  function _re_escape(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function _has_notable_programs(text) { return !!(text && reSearch(_NOTABLE_EXE_RE, text)); }
  C._has_notable_programs = _has_notable_programs;

  function _parse_notable_programs(text, ws, source, facts) {
    var seen = {}, currentDir = '', h = 'host:' + ws.target;
    var lines = String(text || '').split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/\bin\s+[\w.]+\s*\(|^\s*File\s+"[^"]+",\s+line\s+\d+|^\s*Traceback\b|\b[\w]+\.run\s*\(/i.test(line)) continue;
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

  function _looks_like_icacls_accesschk(text) {
    var t = text || '';
    return !!(reSearch(C._LOWPRIV_WRITE_ACE_RE, t) || reSearch(_ACCESSCHK_WRITE_RE, t) || (reSearch(C._WEAK_SVC_ACCESS_RE, t) && /^\s*RW\s+[A-Za-z0-9_.-]+\s*$/m.test(t)));
  }
  C._looks_like_icacls_accesschk = _looks_like_icacls_accesschk;

  function _program_path_from_line(line) {
    var m = reSearch(_ICACLS_PATH_RE, line);
    if (m) return m[0].trim();
    m = reSearch(_ICACLS_DIR_PATH_RE, line);
    if (m) return m[0].trim();
    var sm = _ACCESSCHK_SVC_HDR_RE.exec(line);
    if (sm && !/^(?:BUILTIN|Everyone|Authenticated|Users|NT)$/i.test(sm[1])) return sm[1].trim();
    return '';
  }

  function _parse_icacls_accesschk(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var currentPath = '', evidence = [], seen = {}, paths = {};
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.replace(/[ \t]+$/, '');
      if (!line.trim()) return;
      var p = _program_path_from_line(line);
      if (p) currentPath = p;
      if (!currentPath) return;
      if (!(reSearch(C._LOWPRIV_WRITE_ACE_RE, line) || reSearch(_ACCESSCHK_WRITE_RE, line) || reSearch(C._WEAK_SVC_ACCESS_RE, line))) return;
      var trimmed = line.trim();
      var ev = (trimmed.indexOf(currentPath) === 0 ? trimmed : currentPath + ' ' + trimmed).slice(0, 220), key = ev.toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      evidence.push(ev);
      paths[currentPath] = true;
    });
    if (!evidence.length) return;
    var leadKinds = {};
    _add_host_privesc_fact(facts, ws, source, 'privesc.weak_service_permission',
      { evidence: evidence.slice(0, 30), paths: Object.keys(paths).sort().slice(0, 20),
        tool: (command || '').toLowerCase().indexOf('accesschk') >= 0 ? 'accesschk' : 'icacls' }, leadKinds);
    _add_privesc_leads(facts, ws, source, leadKinds);
  }
  C._parse_icacls_accesschk = _parse_icacls_accesschk;

  var _SHADOW_LINE_RE = /^(?<u>[a-z_][\w.-]{0,31}):\$(?:1|2[aby]|5|6|y)\$[^\s:]+/im;
  function _parse_shadow_file(text, command, ws, source, facts) {
    var users = reAll(_SHADOW_LINE_RE, text || '').map(function (m) { return m.groups.u; });
    if (!users.length) return;
    _add(facts, mkFact('loot.shadow', 'host:' + ws.target, { users: C.uniqueSortedCI(users).slice(0, 30), count: users.length }, S, source));
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

  var _LISTENER_OPEN_RE = /\bListening on\s+(?:\[?(?<host>[0-9a-fA-F.:*]+)\]?\s+(?:\([^)\r\n]*\)\s+)?)?(?:port\s+|:)?(?<port>\d{2,5})\b/i;
  function _parse_listener_output(text, ws, command, source, facts) {
    if (!text) return;
    var m = reSearch(_LISTENER_OPEN_RE, text);
    if (!m || !m.groups || !m.groups.port) return;
    var p = parseInt(m.groups.port, 10);
    if (!p || p < 1 || p > 65535) return;
    var h = (m.groups.host || '0.0.0.0').replace(/^\[|\]$/g, '');
    _add(facts, mkFact('listener.open', 'host:' + ws.target, { host: h, port: p }, S, source));
  }
  C._parse_listener_output = _parse_listener_output;

})(typeof globalThis !== 'undefined' ? globalThis : this);
