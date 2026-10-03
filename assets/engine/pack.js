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
  };

  function friendly(kind) {
    if (FRIENDLY[kind]) return FRIENDLY[kind];
    if (kind.indexOf('port:') === 0) return 'port ' + kind.split(':')[1] + ' open';
    if (kind.indexOf('service.') === 0) return kind.split('.')[1] + ' service evidence';
    return kind;
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
  var V2_GOALS = ['objective.flag', 'access.admin', 'access.system', 'access.root', 'loot.ntds'];
  // Specific EARNED control/loot/credential facts: a move gated on one of these is a deterministic
  // cash-in (DCSync given control paths, a crack given a hash), not a gamble — full reliability.
  var V2_SPECIFIC = {
    'ad.control_paths': 1, 'ad.gpo_control': 1, 'ad.gpo_writable': 1, 'hash.krbtgt': 1,
    'hash.asrep': 1, 'hash.tgs': 1, 'hash.ntlm': 1, 'loot.ntds': 1, 'ad.zerologon': 1,
    'adcs.vulnerable': 1, 'credential.certificate': 1, 'ad.sid_history': 1, 'ad.coerced_auth': 1,
    'ad.unconstrained': 1, 'privesc.sudo_rights': 1, 'privesc.windows_privilege': 1,
    'db.session': 1, 'ad.gmsa': 1, 'kerberos.tickets': 1, 'smb.ms17_010': 1, 'hash.mscache': 1,
  };
  var V2_PRIV = { 'access.admin': 1, 'access.system': 1, 'access.root': 1, 'loot.ntds': 1, 'objective.flag': 1 };
  var V2_SPEC_RE = /check$|coerce|relay|responder|mitm|zerologon|printnight|nopac|ms14-068/;

  function v2Speculative(a) {
    if (V2_SPEC_RE.test(a.id)) return true;
    for (var i = 0; i < a.produces.length; i++) {
      var k = a.produces[i];
      if (k === 'exploit.candidate' || k === 'ad.coerced_auth' || k === 'credential.netntlm') return true;
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
    for (i = 0; i < gates.length; i++) if (haveObj[gates[i]] && V2_SPECIFIC[gates[i]]) return 1.0;
    if (v2Speculative(a)) return 0.25;
    for (i = 0; i < a.produces.length; i++) if (V2_PRIV[a.produces[i]]) return 0.3;
    return 0.8;
  }
  // Recency: the fact-kinds from the operator's latest ingest batch (within 2s of the newest fact),
  // and the set proven before it. opts.recentKinds / opts.beforeKinds override (tests / known deltas).
  function v2Recency(facts, opts) {
    if (opts && opts.recentKinds) return { recent: opts.recentKinds, before: opts.beforeKinds || {} };
    var SUPP = OBOL.facts.ProofState.SUPPORTED, maxT = 0, i, f;
    for (i = 0; i < facts.facts.length; i++) { f = facts.facts[i]; if (f.state === SUPP && f.created_at > maxT) maxT = f.created_at; }
    var cut = maxT - 2000, recent = {}, before = {};
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

    function onType(a) {
      if (!focus.length) return 0;
      for (var i = 0; i < a.produces.length; i++) for (var j = 0; j < focus.length; j++) if (String(a.produces[i]).indexOf(focus[j]) === 0) return -1;
      return 0;
    }

    var scored = live.map(function (a) {
      var gates = a.requires_all.concat(a.requires_any), indicated = false, i;
      for (i = 0; i < gates.length; i++) if (haveObj[gates[i]] && V2_SPECIFIC[gates[i]]) { indicated = true; break; }
      var spec = v2Speculative(a);
      var fresh = v2EligAgainst(a, haveObj) && !v2EligAgainst(a, rec.before);
      var tier = (spec && !indicated) ? -1 : (fresh ? 2 : (indicated ? 1 : 0));
      var h2 = {}, k;
      for (k in haveObj) h2[k] = 1;
      a.produces.forEach(function (p) { h2[p] = 1; });
      var dH2 = v2GoalDistance(h2, producers);
      var progA = d0 >= V2_INF ? (dH2 >= V2_INF ? 0 : 5) : Math.max(0, d0 - dH2);
      // enablement: best tempered value among moves newly-eligible after doing a (1-step lookahead).
      var enable = 0;
      pack.forEach(function (b) {
        if (b.id === a.id || v2EligAgainst(b, haveObj) || !v2EligAgainst(b, h2)) return;
        enable = Math.max(enable, v2Reliability(b, h2) * v2ProgressFrom(dH2, h2, b.produces, producers));
      });
      var score = v2Reliability(a, haveObj) * (progA + 0.6 * enable) + (onType(a) === -1 ? 0.5 : 0);
      return { a: a, tier: tier, score: score };
    });
    scored.sort(function (x, y) {
      if (y.tier !== x.tier) return y.tier - x.tier;
      if (y.score !== x.score) return y.score - x.score;
      if (y.a.priority !== x.a.priority) return y.a.priority - x.a.priority;
      return x.a.id < y.a.id ? -1 : (x.a.id > y.a.id ? 1 : 0);
    });
    return scored.map(function (s) { return s.a; });
  }

  // The coach's ranker. Goal-directed v2 by default; set OBOL.pack.ranker = 'v1' for the legacy
  // phase/priority planner (kept for comparison + fallback).
  function rankActions(facts, pack, opts) {
    return (OBOL.pack && OBOL.pack.ranker === 'v1') ? nextActions(facts, pack, opts) : nextActionsV2(facts, pack, opts);
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
    if (v2Speculative(a) && !earned) return 12;
    if (earned) return 1;
    for (i = 0; i < a.produces.length; i++) if (V2_PRIV[a.produces[i]]) return 8;
    return 1.5;
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
    friendly: friendly,
    FRIENDLY: FRIENDLY,
    hostOsFamily: hostOsFamily,
    osCompatible: osCompatible,
    normalizeOsName: normalizeOsName,
    actionsFromPackData: actionsFromPackData,
    loadPacks: loadPacks,
    nextActions: nextActions,
    nextActionsV2: nextActionsV2,
    rankActions: rankActions,
    planPath: planPath,
    ranker: 'v2',
    lockedActions: lockedActions,
    blockedActions: blockedActions,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
