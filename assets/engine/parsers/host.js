/*!
 * obol engine — parsers/host.js
 * Faithful JS port of obol-local/obol/parsers/host.py (command-exec / shell footholds
 * and Linux/Windows local-privesc leads). Leads never prove admin/root/SYSTEM by themselves.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  function _exec_tool(command) {
    var l = command.toLowerCase();
    var tools = ['evil-winrm', 'wmiexec', 'psexec', 'atexec', 'smbexec'];
    for (var i = 0; i < tools.length; i++) if (l.indexOf(tools[i]) >= 0) return tools[i];
    if (l.indexOf('enter-pssession') >= 0) return 'winrs';
    if (l.indexOf('nxc ') >= 0 || l.indexOf('nxc ') === 0) return 'nxc';
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
    var isSystem = !!reSearch(C._SYSTEM_ID_RE, text);
    var interactive = !!reSearch(C._INTERACTIVE_RE, text) || command.toLowerCase().indexOf('enter-pssession') >= 0;
    var executed = identities.length > 0 || !!reSearch(C._EXEC_SUCCESS_RE, text) || interactive;
    if (!executed) return;
    var tool = _exec_tool(command);
    var footholdValue = { method: tool };
    var nonSystem = identities.filter(function (i) { return i.toLowerCase() !== 'nt authority\\system'; });
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
    var lowCmd = command.toLowerCase();
    if (!isSystem && ['wmiexec', 'atexec'].some(function (t) { return lowCmd.indexOf(t) >= 0; })) {
      _add(facts, mkFact('access.admin', h, { identity: nonSystem.length ? nonSystem[0] : '', method: tool, note: 'local admin — wmiexec/atexec require it' }, S, source));
    }
    if (interactive && C._INTERACTIVE_WIN_TOOLS.has(tool)) _add(facts, mkFact('access.desktop', h, { session: tool }, S, source));
  }
  C._parse_command_execution = _parse_command_execution;

  function _parse_ssh_exec(text, ws, command, source, facts) {
    var m = reSearch(C._LINUX_ID_RE, text);
    if (!m) return;
    var h = 'host:' + ws.target, user = m.groups.user.trim();
    _add(facts, mkFact('access.shell', h, { service: 'ssh' }, S, source));
    _add(facts, mkFact('foothold.linux', h, { service: 'ssh', identity: user }, S, source));
    C._add_os_observation(facts, ws, source, 'linux', m[0], 'high', 'ssh', true);
    if (m.groups.uid === '0' || user.toLowerCase() === 'root') _add(facts, mkFact('access.admin', h, { service: 'ssh', identity: user }, S, source));
  }
  C._parse_ssh_exec = _parse_ssh_exec;

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
    if (text.toLowerCase().indexOf('pwn3d') >= 0) _add(facts, mkFact('access.admin', h, { service: 'rdp' }, S, source));
  }
  C._parse_nxc_rdp = _parse_nxc_rdp;

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
    vi: 'vi', vim: 'vim', nano: 'nano', less: 'less', more: 'more', man: 'man', awk: 'awk', gawk: 'gawk',
    sed: 'sed', ed: 'ed', find: 'find', nmap: 'nmap', python: 'python', python2: 'python', python3: 'python',
    perl: 'perl', ruby: 'ruby', php: 'php', lua: 'lua', node: 'node', bash: 'bash', sh: 'sh', zsh: 'zsh',
    env: 'env', docker: 'docker', tar: 'tar', zip: 'zip', git: 'git', ftp: 'ftp', gdb: 'gdb', make: 'make',
    cp: 'cp', mv: 'mv', dd: 'dd', tee: 'tee', wget: 'wget', curl: 'curl', ssh: 'ssh', scp: 'scp', rsync: 'rsync',
    socat: 'socat', nc: 'nc', tcpdump: 'tcpdump', openssl: 'openssl', mysql: 'mysql', psql: 'psql',
    systemctl: 'systemctl', journalctl: 'journalctl', apt: 'apt', 'apt-get': 'apt-get', pip: 'pip',
    screen: 'screen', tmux: 'tmux', xargs: 'xargs', cat: 'cat', base64: 'base64', cut: 'cut', flock: 'flock',
  };

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
  }

  function _parse_linux_privesc_output(text, ws, command, source, facts, leadKinds) {
    var lowered = text.toLowerCase(), lc = command.toLowerCase();
    var idMatch = reSearch(C._LINUX_ID_RE, text);
    if (idMatch) {
      var user = idMatch.groups.user.trim();
      C._add_os_observation(facts, ws, source, 'linux', idMatch[0], 'high', 'local-enum', true);
      var idLine = C._line_for_match(text, idMatch) || idMatch[0];
      var groups = C.uniqueSortedCI(reAll(/\d+\(([^)]+)\)/, idLine).map(function (m) { return m[1].toLowerCase(); }));
      if (groups.indexOf('lxd') >= 0 || groups.indexOf('lxc') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.lxd_group', { groups: groups, user: user }, leadKinds);
      if (groups.indexOf('docker') >= 0) _add_host_privesc_fact(facts, ws, source, 'privesc.docker_group', { groups: groups, user: user }, leadKinds);
      if (idMatch.groups.uid === '0' || user.toLowerCase() === 'root') _add(facts, mkFact('access.admin', 'host:' + ws.target, { identity: user, method: 'local-enum' }, S, source));
    } else if (lc.indexOf('whoami') >= 0 && /(?:^|\n)\s*root\s*(?:\n|$)/i.test(text)) {
      _add(facts, mkFact('access.admin', 'host:' + ws.target, { identity: 'root', method: 'whoami' }, S, source));
    }

    var uname = reSearch(C._UNAME_RE, text);
    if (uname) {
      _add_host_privesc_fact(facts, ws, source, 'host.kernel', { kernel: uname.groups.kernel, tool: 'uname', evidence: uname[0].trim().slice(0, 220) }, leadKinds);
      _add_host_privesc_fact(facts, ws, source, 'host.arch', { arch: uname.groups.arch, tool: 'uname' }, leadKinds);
    }

    var sudoEntries = [];
    if (lowered.indexOf('may run the following commands') >= 0 || lowered.indexOf('nopasswd:') >= 0) {
      text.split(/\r?\n/).forEach(function (raw) {
        var line = raw.trim();
        if (!line) return;
        var ll = line.toLowerCase();
        if (ll.indexOf('matching defaults') === 0 || ll.indexOf('user ') === 0 || ll.indexOf('sudoers') === 0) return;
        if (reSearch(C._ID_LINE_RE, line)) return;
        if (ll.indexOf('nopasswd:') >= 0 || /\([^)]+\)\s+\S+/.test(line)) sudoEntries.push(line.slice(0, 220));
      });
    }
    if (sudoEntries.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.sudo_rights',
        { entries: C.uniqueSortedCI(sudoEntries).slice(0, 20), nopasswd: sudoEntries.some(function (e) { return e.toLowerCase().indexOf('nopasswd') >= 0; }) }, leadKinds);
      var seenBins = {};
      sudoEntries.forEach(function (entry) {
        var nopasswd = entry.toLowerCase().indexOf('nopasswd') >= 0;
        var wildcard = entry.indexOf('*') >= 0;
        var toks = reAll(/(\/[^\s,]+)/, entry).map(function (m) { return m[1]; });
        toks.forEach(function (tok) {
          var base = tok.split('/').pop().toLowerCase();
          var gid = _GTFOBINS_SUDO[base];
          if (!gid || seenBins[base]) return;
          seenBins[base] = true;
          var fixedScript = '';
          for (var k = 0; k < toks.length; k++) {
            var t = toks[k];
            if (t !== tok && !_GTFOBINS_SUDO[t.split('/').pop().toLowerCase()]) { fixedScript = t; break; }
          }
          var val = { bin: base, path: tok, gtfobins_id: gid, wildcard: wildcard, nopasswd: nopasswd, ref: 'https://gtfobins.github.io/gtfobins/' + gid + '/#sudo' };
          if (fixedScript) val.fixed_script = fixedScript;
          _add_host_privesc_fact(facts, ws, source, 'privesc.sudo_binary', val, leadKinds);
        });
      });
    }

    var suidPaths = {};
    var suidFind = ['-perm -4000', '-perm -u=s', '-perm /4000', '-perm /u=s'].some(function (t) { return lc.indexOf(t) >= 0; });
    if (suidFind || lowered.indexOf('suid') >= 0 || lowered.indexOf('rws') >= 0) {
      text.split(/\r?\n/).forEach(function (raw) {
        var line = raw.trim();
        if (!line || line.indexOf('/proc/') >= 0) return;
        if (line.toLowerCase().indexOf('rws') >= 0) {
          var mm = reSearch(C._SUID_PATH_RE, line);
          if (mm) suidPaths[mm.groups.path] = true;
          return;
        }
        if (suidFind && line[0] === '/' && line.indexOf(' ') < 0) suidPaths[line] = true;
      });
    }
    var suidKeys = Object.keys(suidPaths);
    if (suidKeys.length) _add_host_privesc_fact(facts, ws, source, 'privesc.suid_candidate', { paths: suidKeys.sort().slice(0, 40), count: suidKeys.length }, leadKinds);

    var caps = reAll(C._CAPABILITY_RE, text).map(function (m) { return { path: m.groups.path, capabilities: m.groups.caps.trim() }; });
    if (caps.length) _add_host_privesc_fact(facts, ws, source, 'privesc.capability', { entries: caps.slice(0, 40), count: caps.length }, leadKinds);

    var passwd = reSearch(C._PASSWD_MODE_RE, text);
    if (passwd) {
      var mode = passwd.groups.mode;
      var groupWritable = mode[5] === 'w', worldWritable = mode[8] === 'w';
      if (groupWritable || worldWritable) _add_host_privesc_fact(facts, ws, source, 'privesc.passwd_writable', { path: '/etc/passwd', mode: mode, world_writable: worldWritable, group_writable: groupWritable }, leadKinds);
    }

    if (lowered.indexOf('no_root_squash') >= 0) {
      var exports = text.split(/\r?\n/).filter(function (l) { return l.toLowerCase().indexOf('no_root_squash') >= 0; }).map(function (l) { return l.trim(); });
      _add_host_privesc_fact(facts, ws, source, 'privesc.nfs_no_root_squash', { exports: exports.slice(0, 20), count: exports.length || 1 }, leadKinds);
    }

    var cronLines = text.split(/\r?\n/).filter(function (l) { return /cron|timer|systemd/i.test(l) && /\b(writable|world-writable|rwx|777)\b/i.test(l); }).map(function (l) { return l.trim(); });
    if (cronLines.length) _add_host_privesc_fact(facts, ws, source, 'privesc.cron_writable', { evidence: cronLines.slice(0, 20) }, leadKinds);

    var processLines = text.split(/\r?\n/).filter(function (l) { return /\bUID=0\b|\broot\b.*\bCMD\b|\bCMD:/i.test(l); }).map(function (l) { return l.trim(); });
    if (processLines.length && (lc.indexOf('pspy') >= 0 || lowered.indexOf('uid=0') >= 0 || lowered.indexOf('cmd:') >= 0)) _add_host_privesc_fact(facts, ws, source, 'privesc.process_lead', { commands: processLines.slice(0, 30) }, leadKinds);

    if (reSearch(C._LOCAL_FILE_SECRET_RE, text)) _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'local_file_secret', evidence: 'local loot output' }, S, source));

    _parse_kernel_exploits(text, ws, command, source, facts, leadKinds);
  }
  C._parse_linux_privesc_output = _parse_linux_privesc_output;

  function _parse_windows_privesc_output(text, ws, command, source, facts, leadKinds) {
    var lowered = text.toLowerCase(), h = 'host:' + ws.target;
    if (reSearch(C._SYSTEM_ID_RE, text)) {
      C._add_os_observation(facts, ws, source, 'windows', 'Windows local command output', 'high', 'local-enum', true);
      _add(facts, mkFact('access.system', h, { identity: 'nt authority\\system', method: 'local-enum' }, S, source));
    }
    var sysinfo = {};
    reAll(C._SYSTEMINFO_FIELD_RE, text).forEach(function (m) { sysinfo[m.groups.key.toLowerCase()] = m.groups.value.trim(); });
    if (Object.keys(sysinfo).length) {
      var osName = sysinfo['os name'] || '', osVersion = sysinfo['os version'] || '';
      if (osName || osVersion) {
        _add_host_privesc_fact(facts, ws, source, 'host.kernel', { kernel: [osName, osVersion].filter(Boolean).join(' '), tool: 'systeminfo' }, leadKinds);
        C._add_os_observation(facts, ws, source, 'windows', (osName || osVersion), 'high', 'systeminfo', true);
      }
      if (sysinfo['system type']) _add_host_privesc_fact(facts, ws, source, 'host.arch', { arch: sysinfo['system type'], tool: 'systeminfo' }, leadKinds);
    }

    var privileges = [];
    reAll(C._WIN_PRIV_RE, text).forEach(function (m) {
      var name = m.groups.name, state = m.groups.state.toLowerCase();
      if (state === 'enabled' && C._DANGEROUS_WIN_PRIVS.has(name.toLowerCase())) privileges.push(name);
    });
    if (privileges.length) _add_host_privesc_fact(facts, ws, source, 'privesc.windows_privilege', { privileges: C.uniqueSortedCI(privileges), state: 'Enabled' }, leadKinds);

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
        if (!line || line.toLowerCase().indexOf('.exe') < 0 || line.indexOf('"') >= 0) return;
        if (/[A-Za-z]:\\Program Files[^,\r\n]+\.exe/i.test(line)) unquoted.push(line.slice(0, 220));
      });
    }
    if (unquoted.length) _add_host_privesc_fact(facts, ws, source, 'privesc.unquoted_service_path', { services: C.uniqueSortedCI(unquoted).slice(0, 20), count: C.uniqueSortedCI(unquoted).length }, leadKinds);

    var weakService = [];
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (reSearch(C._WEAK_SVC_ACCESS_RE, line) || reSearch(C._LOWPRIV_WRITE_ACE_RE, line)) weakService.push(line.slice(0, 220));
    });
    if (weakService.length) _add_host_privesc_fact(facts, ws, source, 'privesc.weak_service_permission', { evidence: C.uniqueSortedCI(weakService).slice(0, 30) }, leadKinds);

    var stored = [];
    [['Target:', 'cmdkey'], ['DefaultPassword', 'autologon'], ['unattend.xml', 'unattend'], ['sysprep', 'sysprep'], ['confCons.xml', 'mRemoteNG'], ['.rdp', 'rdp_file'], ['simontatham', 'putty'], ['winscp', 'winscp'], ['vncpassword', 'vnc']].forEach(function (pair) {
      if (lowered.indexOf(pair[0].toLowerCase()) >= 0) stored.push(pair[1]);
    });
    if (stored.length) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.stored_credentials', { kinds: C.uniqueSortedCI(stored), count: C.uniqueSortedCI(stored).length }, leadKinds);
      _add(facts, mkFact('credential.candidate', h, { kind: 'stored_windows_credentials' }, S, source));
    }

    var dllHits = text.split(/\r?\n/).filter(function (raw) { var l = raw.toLowerCase(); return l.indexOf('.dll') >= 0 && (l.indexOf('name not found') >= 0 || l.indexOf('path not found') >= 0); }).map(function (raw) { return raw.trim().slice(0, 220); });
    if (dllHits.length) _add_host_privesc_fact(facts, ws, source, 'privesc.dll_hijack_candidate', { evidence: C.uniqueSortedCI(dllHits).slice(0, 20), count: C.uniqueSortedCI(dllHits).length }, leadKinds);

    var patchLines = text.split(/\r?\n/).filter(function (l) { return /\bMS\d{2}-\d{3}\b|CVE-\d{4}-\d+|missing patches?|exploit/i.test(l); }).map(function (l) { return l.trim(); });
    if (patchLines.length && (command.toLowerCase().indexOf('wesng') >= 0 || command.toLowerCase().indexOf('windows-exploit-suggester') >= 0 || lowered.indexOf('missing') >= 0)) {
      _add_host_privesc_fact(facts, ws, source, 'privesc.patch_gap', { evidence: patchLines.slice(0, 30) }, leadKinds);
      _add(facts, mkFact('exploit.candidate', h, { tool: 'windows-exploit-suggester', findings: patchLines.slice(0, 30) }, S, source));
    }
  }
  C._parse_windows_privesc_output = _parse_windows_privesc_output;

  function _parse_privesc_output(actionId, text, ws, command, source, facts) {
    if (!text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var leadKinds = {};
    if (C._LINUX_PRIVESC_ACTION_IDS.has(actionId)) _parse_linux_privesc_output(text, ws, command, source, facts, leadKinds);
    if (C._WINDOWS_PRIVESC_ACTION_IDS.has(actionId)) _parse_windows_privesc_output(text, ws, command, source, facts, leadKinds);
    _add_privesc_leads(facts, ws, source, leadKinds);
  }
  C._parse_privesc_output = _parse_privesc_output;

  // ── Bare on-host enum pastes (no privesc action-id) → privesc leads ────────────────
  // A pasted `whoami /priv` / `whoami /all` token-privilege dump, or a `sudo -l` rights
  // listing, arrives as operator-ingest with none of the _PRIVESC_ACTION_IDS, so the
  // action-id-gated _parse_privesc_output never fires. These thin entrypoints let the
  // dispatcher route such a paste to the matching privesc parser. The parser's inner blocks
  // are all content-gated (only an Enabled dangerous privilege → privesc.windows_privilege,
  // only a real sudo rights line → privesc.sudo_rights), so nothing is invented, and they
  // emit the same privesc.leads roll-up _parse_privesc_output would.
  function _looks_like_whoami_priv(text) { return !!reSearch(C._WIN_PRIV_RE, text || ''); }
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
    var lowered = (text || '').toLowerCase();
    return lowered.indexOf('may run the following commands') >= 0 || lowered.indexOf('nopasswd:') >= 0;
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
      var fm = /(\/[^\s'"]+\.(?:py|sh|pl|rb|php))/.exec(command || '');
      if (fm) value.script = fm[1];
      _add(facts, mkFact('privesc.script_sink', 'host:' + ws.target, value, S, source));
      break;
    }
  }
  C._parse_script_sinks = _parse_script_sinks;

  // ── Windows cleartext-cred idioms + PuTTY/plink/WinSCP stored creds (§33) ──────────
  // Cleartext credentials typed into a script/history/config, plus PuTTY's plaintext registry proxy
  // credential and a saved plink `-pw` command line → credential.candidate MATERIAL to try (never
  // access.* — §34 validates it into credential.available). A login the same transcript shows was
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
    // PuTTY stored proxy credential — pair the ProxyPassword value with the nearest ProxyUsername.
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
  var _NOTABLE_EXE_RE = /(?<name>[\w.\-]{1,60}\.(?:exe|bat|cmd|ps1|vbs|sh|py|pl|rb|jar|bin|run|elf))\b/gi;
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
  // lead (replace/overwrite that binary — or its directory — and you inherit the run-as identity).
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
  var _REG_DEFAULT_PW_RE = /^\s*DefaultPassword\s+REG_SZ\s+(?<pw>\S.*?)\s*$/im;
  var _REG_DEFAULT_USER_RE = /^\s*DefaultUserName\s+REG_SZ\s+(?<user>\S.*?)\s*$/im;
  var _REG_DEFAULT_DOMAIN_RE = /^\s*DefaultDomainName\s+REG_SZ\s+(?<dom>\S.*?)\s*$/im;
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
    // 1) Winlogon autologon → cleartext credential
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

  // ── icacls / accesschk → writable service/path privesc lead ────────────────────────
  // icacls prints `<path> <PRINCIPAL>:(perms)` (continuation ACEs indented); accesschk prints a path
  // then `RW <principal>` / `FILE_ALL_ACCESS` lines. When a LOW-PRIV principal (BUILTIN\Users,
  // Everyone, Authenticated Users) holds a WRITABLE ACE (F/M/W) on a SERVICE BINARY or program path,
  // that path is replaceable → you inherit whatever identity runs it. Mint privesc.leads (via
  // privesc.weak_service_permission). Path-gated: a writable ACE on an ordinary/user path, or a
  // read-only ACE, mints nothing.
  var _ICACLS_PATH_RE = /(?:[A-Za-z]:\\|\\\\)(?:[^\r\n:()]|:(?=\\))*?\.(?:exe|dll|bat|cmd|ps1|sys|msi|vbs|jar|scr)\b/i;
  var _ICACLS_DIR_PATH_RE = /[A-Za-z]:\\(?:[^\r\n:()]|:(?=\\))*(?:Program Files(?: \(x86\))?|ProgramData|inetpub|xampp|wamp)(?:\\[^\r\n:()]*)?/i;
  var _ACCESSCHK_WRITE_RE = /^\s*(?:RW|W)\s+(?:BUILTIN\\Users|Everyone|NT AUTHORITY\\(?:Authenticated Users|INTERACTIVE)|Authenticated Users|\bUsers\b)/im;

  function _looks_like_icacls_accesschk(text) {
    var t = text || '';
    return !!(reSearch(C._LOWPRIV_WRITE_ACE_RE, t) || reSearch(_ACCESSCHK_WRITE_RE, t));
  }
  C._looks_like_icacls_accesschk = _looks_like_icacls_accesschk;

  function _program_path_from_line(line) {
    var m = reSearch(_ICACLS_PATH_RE, line);
    if (m) return m[0].trim();
    m = reSearch(_ICACLS_DIR_PATH_RE, line);
    if (m) return m[0].trim();
    return '';
  }

  function _parse_icacls_accesschk(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var currentPath = '', evidence = [], seen = {}, paths = {};
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.replace(/\s+$/, '');
      if (!line.trim()) return;
      var p = _program_path_from_line(line);
      if (p) currentPath = p;
      if (!currentPath) return;
      if (!(reSearch(C._LOWPRIV_WRITE_ACE_RE, line) || reSearch(_ACCESSCHK_WRITE_RE, line))) return;
      var trimmed = line.trim();
      var ev = (trimmed.indexOf(currentPath) === 0 ? trimmed : currentPath + ' — ' + trimmed).slice(0, 220), key = ev.toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      evidence.push(ev);
      paths[currentPath] = true;
    });
    if (!evidence.length) return;
    var leadKinds = {};
    _add_host_privesc_fact(facts, ws, source, 'privesc.weak_service_permission',
      { evidence: evidence.slice(0, 30), paths: Object.keys(paths).sort().slice(0, 20),
        tool: command.toLowerCase().indexOf('accesschk') >= 0 ? 'accesschk' : 'icacls' }, leadKinds);
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

})(typeof globalThis !== 'undefined' ? globalThis : this);
