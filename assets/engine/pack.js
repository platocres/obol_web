/*!
 * obol engine — pack.js
 * Methodology packs: fact-gated actions loaded from data, plus the planner. An Action is
 * a methodology branch expressed as data: what facts must already be proven (`requires_*`),
 * what a successful run can prove (`produces`, as fact kinds), and — conservatively — what
 * it does *not* prove. The planner asks which actions the current facts unlock, which are
 * blocked and why, and ranks the unlocked ones by the phase/frontier model.
 *
 * Faithful JS port of obol-local/obol/pack.py.
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

  // ------------------------------------------------------- locus & scope (derived) --
  // Two teaching/ranking dimensions every move carries. Both honor an explicit pack field when present
  // (d.locus / d.scope) and otherwise DERIVE from the move's tool + gates, so new moves get a sensible
  // default with zero data churn and the handful of judgment calls can be pinned in the override maps.
  //
  // locus — where you operate relative to the target host, lowest-friction first:
  //   'R' remote/offline from Kali · 'F' one-shot code-exec on the box · 'I' interactive on-host session.
  // The coach prefers R, then F, then I: staying off-host is faster and safer in a timed lab, and the
  // on-host parsers are a safety net for when you are legitimately on the box, never a nudge to go there.
  var LOCUS_REMOTE = { // run from Kali against the target, or offline on Kali — off-host either way
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
  };
  function deriveLocus(d) {
    if (d.locus) return d.locus;
    if (LOCUS_OVERRIDE[d.id]) return LOCUS_OVERRIDE[d.id];
    var tl = (d.tools && d.tools.length ? d.tools : [d.tool || '']).map(function (t) { return String(t || '').toLowerCase(); });
    var anyRemote = tl.some(function (t) { return LOCUS_REMOTE[t] || t.indexOf('impacket-') === 0 || /\.py$/.test(t); });
    if (anyRemote) return 'R';
    if (tl.some(function (t) { return LOCUS_ONHOST_INTERACTIVE[t]; })) return 'I';
    if (tl.some(function (t) { return LOCUS_ONHOST_ONESHOT[t]; })) return 'F';
    // Tool unknown: fall back to the gates. A move that can only run once you hold the box is on-host.
    var gates = (d.requires_all || []).concat(d.requires_any || []);
    for (var i = 0; i < gates.length; i++) if (LOCUS_ONHOST_FACTS[gates[i]]) return 'F';
    return 'R'; // default: the remote-first assumption
  }

  // ---- per-COMMAND locus, for the Next Steps Remote/On-Host toggle ---------------------------------
  // This is a DIFFERENT axis from the move-level ranking locus above. The ranking locus asks "where is it
  // launched from" (prefer off-host). This asks the question a learner actually cares about: "does this
  // command put me ON the host?" — because OSCP only counts a flag read from a session on the target. By
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
  };
  // on-host if the command (or its tool) pins it, or its tool grants / runs within a session; else remote.
  function commandLocus(cmd) {
    if (!cmd) return 'remote';
    if (cmd.locus === 'onhost' || cmd.locus === 'remote') return cmd.locus;
    var t = String((cmd.tool || cmd.tools && cmd.tools[0] || '')).toLowerCase();
    if (CMD_ONHOST_SESSION[t] || CMD_ONHOST_RUN[t]) return 'onhost';
    return 'remote';
  }
  function commandIsOnHost(cmd) { return commandLocus(cmd) === 'onhost'; }
  // A move's command loci at a glance: does it offer remote commands, on-host commands, or both? The
  // Remote/On-Host toggle only appears when a move genuinely spans both.
  function moveCommandLoci(move) {
    var r = false, h = false, cs = (move && move.commands) || [];
    for (var i = 0; i < cs.length; i++) { if (commandIsOnHost(cs[i])) h = true; else r = true; if (r && h) break; }
    return { remote: r, onhost: h, both: r && h };
  }
  // The toggle's default side: Remote everywhere (off-host is faster and safer) EXCEPT a flag-capture move,
  // which must default On-Host because a remote flag read scores zero on the exam.
  var OBJECTIVE_FLAG_RE = /^objective\.(flag|local_flag|root_flag)$/;
  function defaultCommandLocus(move) {
    var prod = (move && move.produces) || [];
    for (var i = 0; i < prod.length; i++) if (OBJECTIVE_FLAG_RE.test(prod[i])) return 'onhost';
    return 'remote';
  }

  // ---- house toolkit preference ----------------------------------------------------------------
  // NetExec (nxc) is the house tool for the SMB/LDAP/WinRM/RDP/MSSQL/FTP surface. When a move offers the
  // same job through nxc AND an overlapping legacy tool (smbmap, enum4linux(-ng), rpcclient, smbclient),
  // the nxc command is the default shown, and among nxc commands a SWITCHLESS probe (connect + auth, no
  // action switch) leads so "do I even have anonymous/credentialed access?" is answered before the heavy
  // enumeration runs. This is ONE global rule expressed as tool-class DATA (the same shape as LOCUS_REMOTE),
  // applied as a tie-break and a default-pick, never a per-move hand-tuned rank.
  var PREFERRED_TOOLKIT = { nxc: 1, netexec: 1, crackmapexec: 1, cme: 1 };
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
    for (var i = 0; i < sb.length; i++) if (facts.has(sb[i])) return true;
    return false;
  }
  // The default command index for a move at a given locus: among commands matching the locus, not yet
  // settled, and not skipped (skipFn lets the UI exclude commands gated on facts the operator has not
  // earned yet), prefer the house toolkit (nxc), then a switchless probe, then earliest pack order. Falls
  // back to the first locus-matching command (even if settled/gated) so the toggle always has a target.
  function preferredCommandIndex(move, locus, facts, skipFn) {
    var cs = (move && move.commands) || [], best = -1, bestRank = 99, bestProbe = false, i;
    for (i = 0; i < cs.length; i++) {
      if (commandLocus(cs[i]) !== locus) continue;
      if (commandSettled(cs[i], facts)) continue;
      if (skipFn && skipFn(cs[i], i)) continue;
      var rank = commandToolkitRank(cs[i]), probe = rank === 0 && isSwitchlessProbe(cs[i]);
      if (best === -1 || rank < bestRank || (rank === bestRank && probe && !bestProbe)) {
        best = i; bestRank = rank; bestProbe = probe;
      }
    }
    if (best === -1) for (i = 0; i < cs.length; i++) if (commandLocus(cs[i]) === locus) return i;
    return best === -1 ? 0 : best;
  }
  // A move's toolkit rank for the across-move tie-break: 0 if any of its commands is a house-toolkit (nxc)
  // command, else 1. Prefers the nxc route only among moves the ranker has already tied on progress+priority.
  function moveToolkitRank(move) {
    var cs = (move && move.commands) || [];
    for (var i = 0; i < cs.length; i++) if (commandToolkitRank(cs[i]) === 0) return 0;
    return 1;
  }

  // scope — where a technique sits in the OSCP syllabus, for a newcomer-safe lens:
  //   'oscp' core exam material · 'oscp+' modern AD past the core · 'beyond' exotic / legacy / edge CVEs.
  // Default is 'oscp'; a move escalates only when its id, tool, or an earned gate fact matches a curated
  // signal. Curated (not auto-derived) because syllabus placement is a judgment call, overridable via d.scope.
  var SCOPE_BEYOND_IDS = { 'nopac': 1, 'printnightmare': 1, 'ms14-068': 1, 'zerologon': 1, 'zerologon-exploit': 1 };
  var SCOPE_BEYOND_TOOLS = { 'zerologon-scan': 1, sharpwsus: 1, sharpsccm: 1, sccmhunter: 1 };
  var SCOPE_BEYOND_FACTS = { 'ad.zerologon': 1, 'ad.sid_history': 1 };
  var SCOPE_PLUS_TOOLS = { certipy: 1, pywhisker: 1, ntlmrelayx: 1, responder: 1, coercer: 1, mitm6: 1,
    'impacket-ticketer': 1, 'impacket-rbcd': 1, 'impacket-dacledit': 1, 'impacket-getst': 1, bloodyad: 1,
    'petitpotam.py': 1, 'printerbug.py': 1, 'dfscoerce.py': 1, pygpoabuse: 1, targetedkerberoast: 1 };
  // Note: credential.certificate is deliberately NOT a plus-fact — it is overloaded (an ADCS cert in AD,
  // but also a bare SSH key for ssh-key-login, which is core). ADCS is caught by the certipy tool + the
  // adcs.vulnerable gate instead. Likewise the id regex uses `shadow-cred`, not a bare `shadow`, so that
  // crack-shadow (cracking /etc/shadow — core OSCP) is not mistaken for the shadow-credentials attack.
  var SCOPE_PLUS_FACTS = { 'adcs.vulnerable': 1, 'ad.coerced_auth': 1, 'ad.unconstrained': 1,
    'ad.gpo_control': 1, 'ad.gpo_writable': 1, 'ad.gmsa': 1, 'hash.krbtgt': 1, 'ad.control_paths': 1, 'relay.success': 1 };
  var SCOPE_PLUS_ID_RE = /deleg|shadow-cred|rbcd|dacl|golden|silver|gpo|relay|coerce|unconstrained|constrained/;
  function deriveScope(d) {
    if (d.scope) return d.scope;
    var id = String(d.id || '').toLowerCase();
    // Key the tool signal on the PRIMARY tool only — a secondary tool in the array (e.g. targetedKerberoast
    // listed alongside the standard GetUserSPNs Kerberoast) must not escalate an otherwise-core move.
    var primary = String((d.tool || (d.tools && d.tools[0]) || '')).toLowerCase();
    var gates = (d.requires_all || []).concat(d.requires_any || []);
    if (SCOPE_BEYOND_IDS[id] || SCOPE_BEYOND_TOOLS[primary] ||
        gates.some(function (g) { return SCOPE_BEYOND_FACTS[g]; })) return 'beyond';
    if (SCOPE_PLUS_ID_RE.test(id) || SCOPE_PLUS_TOOLS[primary] ||
        gates.some(function (g) { return SCOPE_PLUS_FACTS[g]; })) return 'oscp+';
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
    this.timeout = parseInt(d.timeout || 0, 10) || 0;
    this.locus = deriveLocus(d);   // 'R' remote/offline · 'F' one-shot on-host · 'I' interactive on-host
    this.scope = deriveScope(d);   // 'oscp' · 'oscp+' · 'beyond' (newcomer-safe lens)
  }

  Action.prototype.producedKinds = function () { return new Set(this.produces); };

  Action.prototype.settled = function (facts) {
    // True once every produced kind is already proven — re-running gains no new facts.
    var pk = this.produces;
    if (!pk.length) return false;
    var have = facts.kinds();
    for (var i = 0; i < pk.length; i++) { if (!have[pk[i]]) return false; }
    return true;
  };

  Action.prototype.obsolete = function (facts) {
    // True once a later achievement makes this move pointless — e.g. the coercion→relay lane is moot
    // after a completed DCSync (loot.ntds). Retired like a settled move: dropped from the ready list and
    // the blocked list alike, so the coach stops steering you toward a means to an end you already hold.
    for (var i = 0; i < this.obsoleted_by.length; i++) { if (facts.has(this.obsoleted_by[i])) return true; }
    return false;
  };

  var DEPRIORITIZE_PENALTY = 40;
  Action.prototype.effectivePriority = function (facts) {
    // Base priority, minus a penalty once a fact makes this move a side-quest rather than the point — e.g.
    // post-domain-admin persistence / path-mapping / pivots sink below the objective (flag capture) and the
    // cross-box loot once you already hold loot.ntds. The move stays AVAILABLE, just no longer up top.
    var p = this.priority;
    for (var i = 0; i < this.deprioritize_when.length; i++) { if (facts.has(this.deprioritize_when[i])) { p -= DEPRIORITIZE_PENALTY; break; } }
    return p;
  };

  Action.prototype.eligible = function (facts) {
    // True when the target's OS and proven facts satisfy this action's prerequisites.
    if (!osCompatible(facts, this.os)) return false;
    for (var i = 0; i < this.requires_all.length; i++) {
      if (!facts.has(this.requires_all[i])) return false;
    }
    if (this.requires_any.length) {
      var any = false;
      for (var j = 0; j < this.requires_any.length; j++) {
        if (facts.has(this.requires_any[j])) { any = true; break; }
      }
      if (!any) return false;
    }
    return true;
  };

  Action.prototype.unmet = function (facts) {
    // A friendly one-line reason this action is blocked (first unmet prerequisite).
    if (!osCompatible(facts, this.os)) {
      var family = hostOsFamily(facts) || 'another OS';
      return 'blocked because target looks like ' + family;
    }
    for (var i = 0; i < this.requires_all.length; i++) {
      if (!facts.has(this.requires_all[i])) {
        return 'blocked until ' + friendly(this.requires_all[i]) + ' exists';
      }
    }
    if (this.requires_any.length) {
      var anyMet = false;
      for (var j = 0; j < this.requires_any.length; j++) {
        if (facts.has(this.requires_any[j])) { anyMet = true; break; }
      }
      if (!anyMet) {
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
    'ad.anonymous_bind': 'anonymous LDAP bind', 'ad.graph.collected': 'the AD graph',
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
    'credential.admin': 'an admin credential', 'credential.certificate': 'certificate material',
    'credential.ntlm_hash': 'an NT hash', 'credential.plaintext': 'a plaintext password',
    'credential.weak_hash': 'a weak/unsalted password-hashing scheme',
    'kerberos.tickets': 'Kerberos tickets', 'kerberos.reachable': 'Kerberos is reachable',
    'ldap.reachable': 'LDAP is reachable', 'ldap.authenticated': 'authenticated LDAP access',
    'smb.reachable': 'SMB is reachable', 'smb.authenticated': 'authenticated SMB access',
    'smb.null_session': 'SMB null session', 'smb.guest_session': 'SMB guest session',
    'smb.shares': 'SMB shares', 'smb.ms17_010': 'an MS17-010/EternalBlue-vulnerable SMB host (CVE-2017-0144)',
    'winrm.authenticated': 'authenticated WinRM access',
    'winrm.reachable': 'WinRM is reachable', 'rdp.reachable': 'RDP is reachable',
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
    'host.program_inspected': 'a notable local program obol has already inspected',
    'lead.stalled': 'a promising move that didn\'t land for a technical reason (worth another look)',
    'ad.domain_control': 'a DACL control right over the domain root',
    'web.exposed_artifact': 'an exposed credential-bearing artifact (db/git/archive/config) to fetch and read',
    'web.artifact_looted': 'an exposed artifact obol has already fetched and read',
    'web.param_candidate': 'a discovered request parameter', 'web.params_discovered': 'parameter fuzzing completed for an endpoint',
    'web.param_probed': 'an injection probe tried against a parameter', 'web.injectable_param': 'a confirmed injectable parameter',
    'web.param_exploited': 'an injectable parameter handed off for exploitation',
    // service reachability leads (consumed by the service-to-foothold conversions)
    'nfs.reachable': 'a reachable NFS export', 'rsync.reachable': 'a reachable rsync module',
    'telnet.reachable': 'a reachable Telnet login', 'rservices.reachable': 'reachable Berkeley r-services',
    'tftp.reachable': 'a reachable TFTP service', 'x11.reachable': 'an open X11 display',
    'cloud.credential': 'a cloud credential', 'privesc.cron': 'a writable or hijackable cron job',
    'ssh.key_rejected': 'an SSH key the server refuses',
    // operational blockers (diagnostic walls a pasted error reveals — each surfaces its fix doctor)
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
  };

  function friendly(kind) {
    if (FRIENDLY[kind]) return FRIENDLY[kind];
    if (kind.indexOf('port:') === 0) return 'port ' + kind.split(':')[1] + ' open';
    if (kind.indexOf('service.') === 0) return kind.split('.')[1] + ' service evidence';
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
  // Only CAPABILITY-unlocks belong here — moves you work TOWARD (a credential, a shell, admin, a user
  // list, a reachable service). Contingency moves (the blocker.* trap doctors, the vuln.* fingerprint
  // exploits) are not a roadmap — you don't pursue "my clock is skewed" — so they are excluded; they
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
      if (facts.has('foothold.windows') || facts.has('winrm.authenticated') || facts.has('rdp.authenticated')) families.windows = true;
      if (facts.has('foothold.linux')) families.linux = true;
      keys = Object.keys(families);
    }
    return keys.length === 1 ? keys[0] : '';
  }

  function osCompatible(facts, actionOs) {
    var allowed = {};
    (actionOs || []).forEach(function (item) { var n = normalizeOsName(item); if (n) allowed[n] = true; });
    var keys = Object.keys(allowed);
    if (!keys.length) return true;
    var family = hostOsFamily(facts);
    if (!family) return true;
    return !!allowed[family];
  }

  // ------------------------------------------------------------ pack loading --
  // In the browser, packs are provided as already-parsed JSON (fetched by the loader),
  // so loadPacks concatenates + dedupes by action id (first definition wins).
  function actionsFromPackData(packData) {
    return (packData.actions || []).map(function (a) { return new Action(a); });
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

  // ------------------------------------------------------------------ planner --
  // The live actions, ranked by the engagement phase/flow model. Bucketed by how far
  // ahead of the target's frontier they reach (0 = on-flow), then by pack priority.
  function nextActions(facts, pack, opts) {
    opts = opts || {};
    var doneIds = opts.doneIds || {};
    var focus = opts.focusPrefixes || [];
    var live = pack.filter(function (a) {
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
    // ahead of a comparable one, but it must never bury a much higher-priority move — e.g. the priority-99
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
  function lockedActions(facts, pack) {
    var frontier = P.frontierIndex(facts);
    var out = [];
    pack.forEach(function (a) {
      if (a.eligible(facts) || a.settled(facts) || a.obsolete(facts)) return;
      if (!osCompatible(facts, a.os)) return;
      out.push({ action: a, reason: a.unmet(facts) });
    });
    out.sort(function (x, y) {
      var px = Math.max(0, P.phaseIndex(P.phaseOfAction(x.action)) - frontier);
      var py = Math.max(0, P.phaseIndex(P.phaseOfAction(y.action)) - frontier);
      if (px !== py) return px - py;
      return y.action.priority - x.action.priority;
    });
    return out;
  }

  function blockedActions(facts, pack) {
    var blocked = pack.filter(function (a) { return !a.eligible(facts) && !a.settled(facts) && !a.obsolete(facts); });
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
  // Keystone weighting (gate-wiring aware): `enable` already rewards the single BEST door a move opens
  // (Math.max over newly-unlocked moves). Keystone adds the BREADTH — how many currently-blocked moves a
  // move's produced facts unblock, goal-tempered — so a pivotal fact (credential.available unblocks the whole
  // authenticated surface; loot.ntds unblocks the endgame) is favoured over a narrow lead of equal
  // goal-distance, WITHOUT a hand-tuned priority bump. Kept small + capped: a refinement that breaks ties
  // toward the keystone, never a term that overrides a clearly-better-progress move. Tune against the corpus.
  var V2_KEYSTONE_W = 0.15;    // weight of the breadth term in the score
  var V2_KEYSTONE_CAP = 4;     // max accumulated breadth before the weight applies (bounds its influence)
  // Endgame objective pull. Goal-distance is MIN-over-goals, so the moment ONE objective is met (you grab the
  // user flag — objective.local_flag is a goal) the distance collapses to 0 and every move, including the
  // still-open ROOT/proof-flag capture, reads zero progress — the two-flag split would otherwise let
  // enumeration/pivot keystone bury the flag you came to capture. This pull gives any move that DIRECTLY
  // produces an as-yet-uncaptured objective.*flag a strong, bounded bonus so the reachable flag leads. It is a
  // within-tier score term (never changes the tier), so a genuinely fresher/higher-tier lead still wins — it
  // decides "what now that I CAN grab a flag", not "ignore a fresh keystone to grab one".
  var V2_OBJECTIVE_RE = /^objective\.(flag|local_flag|root_flag)$/;
  var V2_OBJECTIVE_W = 3;      // bonus for a move that captures an unmet objective flag (beats typical keystone)
  // Specific EARNED control/loot/credential facts: a move gated on one of these is a deterministic
  // cash-in (DCSync given control paths, a crack given a hash), not a gamble — full reliability.
  var V2_SPECIFIC = {
    'ad.control_paths': 1, 'ad.gpo_control': 1, 'ad.gpo_writable': 1, 'hash.krbtgt': 1,
    'hash.asrep': 1, 'hash.tgs': 1, 'hash.ntlm': 1, 'loot.ntds': 1, 'ad.zerologon': 1,
    'adcs.vulnerable': 1, 'credential.certificate': 1, 'ad.sid_history': 1, 'ad.coerced_auth': 1,
    'ad.unconstrained': 1, 'privesc.sudo_rights': 1, 'privesc.windows_privilege': 1,
    'db.session': 1, 'ad.gmsa': 1, 'kerberos.tickets': 1, 'smb.ms17_010': 1, 'hash.mscache': 1,
  };
  var V2_PRIV = { 'access.admin': 1, 'access.system': 1, 'access.root': 1, 'loot.ntds': 1, 'objective.flag': 1, 'objective.local_flag': 1, 'objective.root_flag': 1 };
  var V2_SPEC_RE = /check$|coerce|relay|responder|mitm|zerologon|printnight|nopac|ms14-068/;
  // An exploit/foothold move is EVIDENCED (not a bare-port gamble) when the box actually shows a
  // reason to run it: a proven vulnerability fingerprint, a credential/hash in hand, an existing
  // foothold/access to escalate from, looted material, or an earned privesc/kerberos/ADCS primitive.
  // A move that lands a foothold but is eligible only because a port/service is open — with none of
  // these held — is a "try if vulnerable" gamble and must not outrank the evidenced next step
  // (same discipline already applied to coerce/relay/check moves). EternalBlue is the model: it
  // requires its smb.ms17_010 NSE verdict, so it is evidenced, never a bare-445 guess.
  var V2_EVIDENCE_RE = /^(vuln\.|credential\.|hash\.|access\.|foothold\.|loot\.|privesc\.|kerberos\.|adcs\.)/;
  // Concrete AD primitives a collection/enumeration PROVED (a BloodHound attack path, an ACL lead, a
  // delegation right, a trust) — abusing one is an evidenced move, not a bare-port guess. (The earned
  // control/loot facts like ad.control_paths/ad.gpo_control are already in V2_SPECIFIC.)
  var V2_AD_LEAD = { 'ad.attack_paths': 1, 'ad.acl_lead': 1, 'ad.delegation': 1, 'ad.trusts': 1 };
  var V2_FOOTHOLD = { 'foothold.linux': 1, 'foothold.windows': 1, 'foothold.webshell': 1, 'access.shell': 1, 'access.admin': 1, 'access.system': 1, 'access.root': 1 };
  // Evidence = something you PROVED (a vuln verdict, a credential, a hash, a foothold, a control lead) —
  // never a mere "service reachable" recon fact. kerberos.reachable matched /^kerberos\./ and so was wrongly
  // treated as evidence, which let blind password-spray look "indicated" (reliable) and headline over the
  // deterministic AS-REP roast. A reachable port proves nothing about a credential or a vuln.
  // A `*_confirmed` fact is a PROVEN vulnerability verdict (web.sqli_confirmed, web.cmdi_confirmed, …) — the
  // same class of evidence as a vuln.* fingerprint, so a move gated on one is evidenced, not a bare-port
  // gamble. Without this a confirmed SQLi left sqlmap-automation capped as speculative, below weaker leads.
  function v2EvidenceFact(g) { if (/\.reachable$/.test(g)) return false; return !!V2_SPECIFIC[g] || !!V2_AD_LEAD[g] || V2_EVIDENCE_RE.test(g) || /_confirmed$/.test(g); }
  function v2ProducesFoothold(a) { for (var i = 0; i < a.produces.length; i++) { var k = a.produces[i]; if (V2_FOOTHOLD[k] || /_confirmed$/.test(k)) return true; } return false; }
  function v2Indicated(a, haveObj) { var g = a.requires_all.concat(a.requires_any), i; for (i = 0; i < g.length; i++) if (haveObj[g[i]] && v2EvidenceFact(g[i])) return true; return false; }

  function v2Speculative(a, haveObj) {
    // A guidance/troubleshooter move produces only advice.* — it mints no attack fact, so it can never
    // be a "try-if-vulnerable" gamble. Exempt it before the id-regex/payoff checks (otherwise a doctor
    // whose id merely contains "relay"/"responder"/"check" would be wrongly capped below everything).
    if (a.produces.length && a.produces.every(function (k) { return /^advice\./.test(k); })) return false;
    if (V2_SPEC_RE.test(a.id)) return true;
    for (var i = 0; i < a.produces.length; i++) {
      var k = a.produces[i];
      if (k === 'exploit.candidate' || k === 'ad.coerced_auth' || k === 'credential.netntlm') return true;
    }
    // A move that claims a real PAYOFF — a foothold/privilege, or a VALIDATED credential — while eligible
    // without any proven indicator (a fingerprint, a held credential/hash, a foothold) is a gamble: blind
    // password spraying or default-cred guessing against a bare user list, or firing an exploit at an open
    // port. Cap it below evidenced moves so the deterministic path (AS-REP roast, crack a captured hash)
    // leads. Once you actually hold material to work with, the move is indicated and promotes normally.
    if (haveObj && !v2Indicated(a, haveObj)) {
      if (v2ProducesFoothold(a)) return true;
      for (var j = 0; j < a.produces.length; j++) if (a.produces[j] === 'credential.available' || a.produces[j] === 'credential.plaintext') return true;
    }
    return false;
  }
  // Minimal steps from a set of held fact-kinds to any goal, through the produce/require graph:
  // AND over a move's requirements, OR over a fact's producers. Memoized, cycle-guarded.
  function v2GoalDistance(haveObj, producers) {
    var memoF = {}, memoM = {};
    function fc(f, stack) {
      if (haveObj[f]) return 0;
      if (memoF[f] !== undefined) return memoF[f];
      if (stack[f]) return V2_INF;
      stack[f] = 1; var best = V2_INF, ms = producers[f] || [];
      for (var i = 0; i < ms.length; i++) best = Math.min(best, mc(ms[i], stack));
      delete stack[f]; memoF[f] = best; return best;
    }
    function mc(m, stack) {
      if (memoM[m.id] !== undefined) return memoM[m.id];
      var c = 1, j;
      for (j = 0; j < m.requires_all.length; j++) c += fc(m.requires_all[j], stack);
      if (m.requires_any.length) {
        var mn = V2_INF;
        for (j = 0; j < m.requires_any.length; j++) mn = Math.min(mn, fc(m.requires_any[j], stack));
        c += mn;
      }
      c = Math.min(c, V2_INF); memoM[m.id] = c; return c;
    }
    var d = V2_INF;
    for (var g = 0; g < V2_GOALS.length; g++) d = Math.min(d, fc(V2_GOALS[g], {}));
    return d;
  }
  function v2ProgressFrom(d0, haveObj, produces, producers) {
    var h2 = {}, k;
    for (k in haveObj) h2[k] = 1;
    for (var i = 0; i < produces.length; i++) h2[produces[i]] = 1;
    var d1 = v2GoalDistance(h2, producers);
    if (d0 >= V2_INF) return d1 >= V2_INF ? 0 : 5;
    return Math.max(0, d0 - d1);
  }
  function v2EligAgainst(a, kindsObj) {
    var i;
    for (i = 0; i < a.requires_all.length; i++) if (!kindsObj[a.requires_all[i]]) return false;
    if (a.requires_any.length) {
      var any = false;
      for (i = 0; i < a.requires_any.length; i++) if (kindsObj[a.requires_any[i]]) { any = true; break; }
      if (!any) return false;
    }
    return true;
  }
  function v2Reliability(a, haveObj) {
    var gates = a.requires_all.concat(a.requires_any), i;
    for (i = 0; i < gates.length; i++) if (haveObj[gates[i]] && (V2_SPECIFIC[gates[i]] || /^vuln\./.test(gates[i]))) return 1.0;
    if (v2Speculative(a, haveObj)) return 0.25;
    for (i = 0; i < a.produces.length; i++) if (V2_PRIV[a.produces[i]]) return 0.3;
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
    // the unit — otherwise a 2000-in-seconds window spans ~33 min and the whole session reads as
    // "recent", which collapses the recency tier and lets raw priority surface noise.
    var win = maxT > 1e12 ? 2000 : 2;
    var cut = maxT - win, recent = {}, before = {};
    for (i = 0; i < facts.facts.length; i++) {
      f = facts.facts[i];
      if (f.state !== SUPP) continue;
      if (f.created_at >= cut) recent[f.kind] = 1; else before[f.kind] = 1;
    }
    return { recent: recent, before: before };
  }

  function nextActionsV2(facts, pack, opts) {
    opts = opts || {};
    var doneIds = opts.doneIds || {}, focus = opts.focusPrefixes || [];
    var live = pack.filter(function (a) { return a.eligible(facts) && !a.settled(facts) && !a.obsolete(facts) && !doneIds[a.id]; });
    var haveObj = facts.kinds();
    var producers = {};
    pack.forEach(function (a) { a.produces.forEach(function (k) { (producers[k] = producers[k] || []).push(a); }); });
    var rec = v2Recency(facts, opts);
    var d0 = v2GoalDistance(haveObj, producers);
    // "Orient before exploit" applies only at the OPENING: you have run a port scan but not yet the thorough
    // service scan, and you hold no foothold or usable credential. In that window a freshly-unlocked recon
    // move (the service scan that deepens the ports you just found) leads the enumeration it feeds. The
    // moment the service scan is done (scan.nmap.version), or you are on the box / hold a working credential,
    // the rule switches off: enumeration and the objective lead, and the optional extras (vuln/UDP/DNS scans)
    // never bury them. This is the "finish your service scan before you dump" discipline and nothing more.
    var earlyRecon = !haveObj['credential.available'] && !haveObj['scan.nmap.version'];
    if (earlyRecon) for (var _fk in haveObj) { if (/^foothold\./.test(_fk) || /^access\.(shell|admin|system|root|desktop)$/.test(_fk)) { earlyRecon = false; break; } }
    // "Validate before use" is live while you hold a usable credential you have not yet proven works.
    var validateFirst = !!haveObj['credential.available'] && !haveObj['credential.validated'];
    // "Map and get on the box before you reach for a named misconfiguration." While you hold a credential but
    // have NOT mapped the domain (no attack/control paths, no graph) and have NO foothold yet, a move that
    // EXPLOITS A SPECIFIC named AD misconfiguration (ADCS ESC, a trust hop, SCCM) is premature: you have not
    // confirmed it applies, and it reads as a near-win to the score (it produces a cert / a trust / an SCCM
    // path) so it buries the moves that get you there. Demote those below the moves that map the domain
    // (BloodHound or the manual path-finder), get you a foothold, or do the cheap always-worth-it roast.
    // Self-disables the moment you map (a path/graph fact mints) or land a foothold, so the post-map killchain,
    // where the named abuse IS the next step, is untouched. (ranker-sim.js measures this.)
    var v2Mapped = !!(haveObj['ad.attack_paths'] || haveObj['ad.control_paths'] || haveObj['ad.graph.collected']);
    var v2Foothold = false; for (var _hk in haveObj) { if (/^foothold\./.test(_hk) || /^access\.(shell|admin|system|root|desktop)$/.test(_hk)) { v2Foothold = true; break; } }
    var specializeHold = !!haveObj['credential.available'] && !v2Mapped && !v2Foothold;
    var SPECIALIZE_RE = /^(adcs\.vulnerable|credential\.certificate|ad\.trusts|sccm\.)/;
    function isSpecialize(a) { return (a.produces || []).some(function (k) { return SPECIALIZE_RE.test(k); }); }

    function onType(a) {
      if (!focus.length) return 0;
      for (var i = 0; i < a.produces.length; i++) for (var j = 0; j < focus.length; j++) if (String(a.produces[i]).indexOf(focus[j]) === 0) return -1;
      return 0;
    }

    var scored = live.map(function (a) {
      var gates = a.requires_all.concat(a.requires_any), indicated = false, i;
      for (i = 0; i < gates.length; i++) if (haveObj[gates[i]] && V2_SPECIFIC[gates[i]]) { indicated = true; break; }
      var spec = v2Speculative(a, haveObj);
      var fresh = v2EligAgainst(a, haveObj) && !v2EligAgainst(a, rec.before);
      var tier = (spec && !indicated) ? -1 : (fresh ? 2 : (indicated ? 1 : 0));
      var h2 = {}, k;
      for (k in haveObj) h2[k] = 1;
      a.produces.forEach(function (p) { h2[p] = 1; });
      var dH2 = v2GoalDistance(h2, producers);
      var progA = d0 >= V2_INF ? (dH2 >= V2_INF ? 0 : 5) : Math.max(0, d0 - dH2);
      // enablement + keystone in one forward pass over the moves this one unblocks (1-step lookahead):
      //   enable   = the single BEST door a opens (goal-tempered) — the deepest unlock.
      //   keystone = the BREADTH of doors it opens — how many blocked moves become eligible, each tempered
      //              by its reliability and whether it advances toward a goal (0.5 floor for being unblocked
      //              at all). Capped so a fact that unblocks the whole authenticated surface is favoured as
      //              the pivot, without letting raw fan-out dominate a better-progress move.
      var enable = 0, keystone = 0;
      pack.forEach(function (b) {
        if (b.id === a.id || v2EligAgainst(b, haveObj) || !v2EligAgainst(b, h2)) return;
        var relB = v2Reliability(b, h2), progB = v2ProgressFrom(dH2, h2, b.produces, producers);
        enable = Math.max(enable, relB * progB);
        keystone += relB * (0.5 + progB);
      });
      if (keystone > V2_KEYSTONE_CAP) keystone = V2_KEYSTONE_CAP;
      // Keystone is a MIDDLE-GAME term: it helps you reach a winning position, it does not adjudicate the
      // win itself. Once a move directly produces a privilege/goal fact it is a cash-in — rank it by
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
      var score = v2Reliability(a, haveObj) * (progA + 0.6 * enable + V2_KEYSTONE_W * keystone) + (onType(a) === -1 ? 0.5 : 0);
      // Endgame objective pull: a reachable, still-uncaptured flag is the box's actual objective — surface it
      // over keystone-rich enumeration even after another goal (e.g. the user flag) already zeroed the
      // goal-distance. See V2_OBJECTIVE_W.
      for (i = 0; i < a.produces.length; i++) { if (V2_OBJECTIVE_RE.test(a.produces[i]) && !haveObj[a.produces[i]]) { score += V2_OBJECTIVE_W; break; } }
      return { a: a, tier: tier, score: score };
    });
    scored.sort(function (x, y) {
      if (y.tier !== x.tier) return y.tier - x.tier;
      // Orient before exploit: within a freshly-unlocked batch (tier 2), finish RECON (scan deeper into what
      // you just found) before spending it on enumeration/exploitation. Scoped to the fresh tier so it only
      // reorders moves the SAME ingest unlocked, e.g. after a port scan the thorough service scan leads the
      // user dump. It never reaches back to bury a later evidenced step: the AS-REP roast you unlock from a
      // fresh user list is its own batch with no recon move in it, so this is a no-op there. Above score so
      // it actually leads (a pure scan has ~0 goal-progress and would otherwise always lose to a deeper move).
      // Only the THOROUGH SERVICE SCAN (the move that produces scan.nmap.version) gets the opening
      // boost, not every recon-phase move. Promoting all recon moves buried higher-priority orient
      // moves (e.g. confirm the DC) under per-service recon noise (FTP/SSH/DNS/UDP) on multi-service
      // boxes. With only the service scan lifted, the rest fall to normal score/priority, so the
      // evidenced orient line leads once the scan itself is in hand. (ranker-sim.js measures this.)
      if (earlyRecon && x.tier === 2 && y.tier === 2) {
        var xs = x.a.produces.indexOf('scan.nmap.version') >= 0, ys = y.a.produces.indexOf('scan.nmap.version') >= 0;
        if (xs !== ys) return xs ? -1 : 1;
      }
      // Validate before use: while you hold a credential you have not validated yet (a FOUND credential,
      // not a cracked one), the step that CONFIRMS it authenticates leads over the moves that spend it.
      // Mirrors the anonymous probe, a cheap check before you commit. The validating move produces
      // credential.validated and settles the instant it is proven; a cracked / bruteforced / already-logged-in
      // credential is validated from the start, so this never fires for those (the move is already gone).
      if (validateFirst) {
        var xcv = x.a.produces.indexOf('credential.validated') >= 0, ycv = y.a.produces.indexOf('credential.validated') >= 0;
        if (xcv !== ycv) return xcv ? -1 : 1;
      }
      // Map / foothold before a named-misconfiguration abuse (see specializeHold above): in this opening a
      // specialize move sorts after everything that is not one, so the domain map, the foothold and the
      // roasts lead and the ADCS/trust/SCCM lanes wait until you have confirmed the ground.
      if (specializeHold) {
        var xsp = isSpecialize(x.a), ysp = isSpecialize(y.a);
        if (xsp !== ysp) return xsp ? 1 : -1;
      }
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
      // objective. Placed below priority so it only decides genuine twins — it never overrides a move the
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
    var committed = !!(haveObj['access.shell'] || haveObj['access.admin'] || haveObj['access.system'] || haveObj['credential.available']);
    if (!committed) for (var _ck in haveObj) { if (/^foothold\./.test(_ck)) { committed = true; break; } }
    if (!adOriented && !committed) {
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
  // requires them) — an SPF/DMARC review, a security-header or TLS read, a CORS/HTTP-methods probe.
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
  // 1.5, a generic privilege shortcut 8, a speculative "try-if-vulnerable" move 12 — so the plan
  // prefers dependable routes and only resorts to speculation when nothing else reaches the goal.
  // A* with the step-distance heuristic (admissible: every step costs >= 1). Exact + instant for a
  // lab-sized graph. Returns { path:[actionId,...], cost, reachable }; reachable:false is an honest
  // "no route from here with the current move library", not a guess. OS is fixed per engagement, so
  // os-compatibility is judged once against the live facts.
  function v2ActionCost(a, haveObj) {
    var gates = a.requires_all.concat(a.requires_any), i, earned = false;
    for (i = 0; i < gates.length; i++) if (haveObj[gates[i]] && V2_SPECIFIC[gates[i]]) { earned = true; break; }
    var base;
    if (v2Speculative(a) && !earned) base = 12;
    else if (earned) base = 1;
    else { base = 1.5; for (i = 0; i < a.produces.length; i++) if (V2_PRIV[a.produces[i]]) { base = 8; break; } }
    // Remote-first: a small surcharge for stepping onto the host (R +0, F +0.3, I +0.6) so the planner
    // prefers the Kali-side route when steps otherwise tie — never enough to reorder a genuinely cheaper
    // path. Running a command from Kali beats getting on the box: faster, and it leaves nothing behind.
    return base + locusRank(a.locus) * 0.3;
  }
  function planPath(facts, pack, opts) {
    opts = opts || {};
    var goals = opts.goals || V2_GOALS;
    var producers = {}, relevant = {}, i;
    pack.forEach(function (a) {
      a.produces.forEach(function (k) { (producers[k] = producers[k] || []).push(a); });
      a.requires_all.concat(a.requires_any).forEach(function (k) { relevant[k] = 1; });
    });
    for (i = 0; i < goals.length; i++) relevant[goals[i]] = 1;

    // OS is fixed per box but may only be learned partway in: honor a known family from the live facts,
    // else infer it from footholds as the plan accrues them, so a Linux foothold rules out Windows moves.
    var startFam = hostOsFamily(facts);
    function famOf(st) {
      if (startFam) return startFam;
      if (st['foothold.windows'] || st['winrm.authenticated'] || st['rdp.authenticated']) return 'windows';
      if (st['foothold.linux']) return 'linux';
      return '';
    }
    function osOkIn(a, st) {
      var al = a.os || [];
      if (!al.length) return true;
      var f = famOf(st);
      if (!f) return true;
      for (var j = 0; j < al.length; j++) if (normalizeOsName(al[j]) === f) return true;
      return false;
    }

    function sig(st) { var ks = [], k; for (k in st) if (relevant[k]) ks.push(k); return ks.sort().join('|'); }
    function isGoal(st) { for (var g = 0; g < goals.length; g++) if (st[goals[g]]) return true; return false; }
    function applic(a, st) {
      if (!osOkIn(a, st)) return false;
      for (var j = 0; j < a.requires_all.length; j++) if (!st[a.requires_all[j]]) return false;
      if (a.requires_any.length) { var any = false; for (j = 0; j < a.requires_any.length; j++) if (st[a.requires_any[j]]) { any = true; break; } if (!any) return false; }
      return true;
    }
    var start = {}, have = facts.kinds(), k;
    for (k in have) start[k] = 1;
    var gScore = {}, came = {}, open = [{ st: start, gc: 0, f: v2GoalDistance(start, producers) }];
    gScore[sig(start)] = 0;
    var exp = 0, MAXEXP = 60000;
    while (open.length) {
      var bi = 0;
      for (i = 1; i < open.length; i++) if (open[i].f < open[bi].f) bi = i;
      var cur = open.splice(bi, 1)[0], cs = sig(cur.st);
      if (++exp > MAXEXP) break;
      if (isGoal(cur.st)) { var pathIds = [], s = cs; while (came[s]) { pathIds.unshift(came[s].move); s = came[s].prev; } return { path: pathIds, cost: cur.gc, reachable: true }; }
      if (cur.gc > gScore[cs]) continue;
      for (var ai = 0; ai < pack.length; ai++) {
        var a = pack[ai];
        if (!applic(a, cur.st)) continue;
        var addsRelevant = false, pk;
        for (var pi = 0; pi < a.produces.length; pi++) { pk = a.produces[pi]; if (relevant[pk] && !cur.st[pk]) { addsRelevant = true; break; } }
        if (!addsRelevant) continue;
        var ns = {}, kk;
        for (kk in cur.st) ns[kk] = 1;
        a.produces.forEach(function (p) { ns[p] = 1; });
        var nsig = sig(ns), ng = cur.gc + v2ActionCost(a, cur.st);
        if (gScore[nsig] === undefined || ng < gScore[nsig]) { gScore[nsig] = ng; came[nsig] = { prev: cs, move: a.id }; open.push({ st: ns, gc: ng, f: ng + v2GoalDistance(ns, producers) }); }
      }
    }
    return { path: null, cost: Infinity, reachable: false };
  }

  OBOL.pack = {
    DEFAULT_PACK: DEFAULT_PACK,
    PACK_NAMES: PACK_NAMES,
    Action: Action,
    deriveLocus: deriveLocus,
    deriveScope: deriveScope,
    locusRank: locusRank,
    commandLocus: commandLocus,
    commandIsOnHost: commandIsOnHost,
    moveCommandLoci: moveCommandLoci,
    defaultCommandLocus: defaultCommandLocus,
    commandTool: commandTool,
    commandToolkitRank: commandToolkitRank,
    isSwitchlessProbe: isSwitchlessProbe,
    commandSettled: commandSettled,
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
    // Shared fact-classification — the move linter (tools/move-lint.js) uses the SAME predicates the
    // ranker does, so a move that passes the lint is, by construction, one the ranker places sanely.
    GOALS: V2_GOALS,
    isEvidenceFact: v2EvidenceFact,
    producesFoothold: v2ProducesFoothold,
    producesPrivilege: function (a) { for (var i = 0; i < a.produces.length; i++) if (V2_PRIV[a.produces[i]]) return true; return false; },
    isIndicated: v2Indicated,
    planPath: planPath,
    ranker: 'v2',
    lockedActions: lockedActions,
    blockedActions: blockedActions,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
