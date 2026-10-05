/*!
 * obol engine — study.js
 * Study mode's engine half. Pure functions over the loaded packs (OBOL.packs.actions()) + ARSENAL +
 * the embedded sample-output map (OBOL.STUDY_FIXTURES).
 *
 * The conditional "study cell" is DERIVED, not hand-authored: every field maps to data the move
 * already carries — hypothesis / requires_* / produces / does_not_prove / commands[].note / refs —
 * plus two graph walks (what mints my prereqs, what my output opens). The one non-pack piece is the
 * sample output; a move with no fixture still produces a full cell (the Watch replay just shows no
 * streamed output yet). Each fixture pins the exact command its output came from (cmd/tool), so the
 * Watch replay always types the command that produced the result shown — command and output are one
 * coherent run, never a sample paired against a different command.
 *
 * Lanes are the methodology taxonomy: every move is auto-assigned to a lane from its source pack and
 * topologically ordered within it, so all 167 moves are navigable. Scenarios are curated cross-lane
 * paths. Command variants are ordered REMOTE-FIRST from each tool's ARSENAL os/class.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // --- the lane taxonomy: every move lands in exactly one lane, grouped by source pack ----------
  var LANE_DEFS = [
    { key: 'recon', name: 'Recon & Enumeration', short: 'Recon', packs: ['recon'], desc: 'Map the attack surface, ports, services, shares, and the web.' },
    { key: 'web', name: 'Web Exploitation', short: 'Web', packs: ['web', 'web_exploit_checks'], desc: 'Turn a web app into a shell, map it, find the injectable edge, land code execution.' },
    { key: 'checks', name: 'Service & Web Checks', short: 'Checks', packs: ['findings_checks'], desc: 'Fast, safe checks that surface misconfigurations and version leads.' },
    { key: 'ad', name: 'Active Directory', short: 'AD', packs: ['ad'], desc: 'From an anonymous foothold to owning the domain.' },
    { key: 'creds', name: 'Credentials & Cracking', short: 'Creds', packs: ['cracking', 'credential_access'], desc: 'Capture, relay, and crack credentials into usable access.' },
    { key: 'linux', name: 'Linux Privilege Escalation', short: 'Linux', packs: ['linux_privesc'], desc: 'From a low-priv shell to root.' },
    { key: 'windows', name: 'Windows Privilege Escalation', short: 'Windows', packs: ['windows_privesc'], desc: 'From a foothold to SYSTEM.' },
    { key: 'database', name: 'Databases', short: 'DB', packs: ['database'], desc: 'Enumerate and abuse database services.' },
    { key: 'shells', name: 'Shells & Transfer', short: 'Shells', packs: ['shells'], desc: 'Get a stable interactive shell and move files on and off the box.' },
    { key: 'pivot', name: 'Pivoting & Tunneling', short: 'Pivot', packs: ['pivoting', 'obol_local_pivot'], desc: 'Reach deeper networks through a compromised host.' },
    { key: 'proof', name: 'Flags & Proof', short: 'Proof', packs: ['obol_flag_hunt'], desc: 'Hunt the flags and capture the proof the report needs.' },
  ];
  var LANE_KEYS = LANE_DEFS.map(function (d) { return d.key; });

  function allMoves() { try { return (OBOL.packs && OBOL.packs.actions()) || []; } catch (e) { return []; } }
  function arsenal() { return OBOL.ARSENAL || {}; }
  function fixtures() { return OBOL._studyFx || (OBOL._studyFx = Object.assign({}, OBOL.STUDY_FIXTURES || {})); }
  function byId(id) { var a = allMoves(); for (var i = 0; i < a.length; i++) if (a[i].id === id) return a[i]; return null; }
  function reqSet(m) { return [].concat(m.requires_all || [], m.requires_any || []); }

  // id → pack basename (e.g. 'ad'), from the loaded pack bundle
  var _packOf = null;
  function packOf(id) {
    if (!_packOf) {
      _packOf = {};
      try {
        var pd = OBOL.packs.packData();
        Object.keys(pd).forEach(function (name) {
          var p = pd[name]; if (!p || !Array.isArray(p.actions)) return;
          var base = name.replace(/_\d{4}_\d{2}$/, '');
          p.actions.forEach(function (a) { _packOf[a.id] = base; });
        });
      } catch (e) {}
    }
    return _packOf[id] || '';
  }
  var _packToLane = null;
  function laneKeyForPack(base) {
    if (!_packToLane) { _packToLane = {}; LANE_DEFS.forEach(function (d) { d.packs.forEach(function (p) { _packToLane[p] = d.key; }); }); }
    return _packToLane[base] || 'recon';
  }
  // a few moves live in a pack that doesn't match their nature (nmap scans ship in the AD pack) —
  // reassign by id so the taxonomy reads right.
  function laneForMove(m) {
    if (/^nmap-/.test(m.id)) return 'recon';
    return laneKeyForPack(packOf(m.id));
  }

  // coarse stage label for a move, from the fact it mints (used as the phase chip at scale)
  // canonical stage labels, so synonyms (creds/credentials, priv/privesc/escalate, pivot/lateral) never
  // show up as two different headers in the rail or the atlas.
  var STAGE_ALIAS = {
    recon: 'Recon', web: 'Web', foothold: 'Foothold', access: 'Foothold', shell: 'Foothold',
    cred: 'Credentials', creds: 'Credentials', credential: 'Credentials', credentials: 'Credentials',
    priv: 'Escalate', privesc: 'Escalate', escalate: 'Escalate', escalation: 'Escalate',
    lateral: 'Lateral', pivot: 'Lateral', loot: 'Loot', proof: 'Proof', flag: 'Proof',
    enum: 'Enumeration', enumeration: 'Enumeration', recon: 'Recon', persistence: 'Persistence',
    ad: 'Active Directory', 'active directory': 'Active Directory', domain: 'Active Directory',
  };
  function canonStage(s) { var k = String(s || '').toLowerCase().trim(); return STAGE_ALIAS[k] || (s ? cap1(s) : ''); }
  function stageOfFact(p) {
    if (/^(persistence\.)/.test(p)) return 'Persistence';
    if (/^access\.(admin|system|root)/.test(p) || p === 'access.admin' || p === 'access.system' || /^privesc\./.test(p)) return 'Escalate';
    if (/^(foothold\.|access\.shell|db\.session|listener\.)/.test(p)) return 'Foothold';
    if (/^(hash\.|credential\.|db\.cred|kerberos\.)/.test(p)) return 'Credentials';
    if (/^(objective|flag|proof)/.test(p)) return 'Proof';
    if (/^loot\./.test(p)) return 'Loot';
    if (/^tunnel\./.test(p)) return 'Lateral';
    if (/^ad\./.test(p)) return 'Active Directory';
    if (/^web\./.test(p)) return 'Web';
    if (/^defense\./.test(p)) return 'Enumeration';
    if (/^(scan\.|host\.|ports|service\.)/.test(p) || /\.reachable$/.test(p)) return 'Recon';
    return '';
  }
  // when a move declares no output (or none that classifies), fall back to its lane's natural stage.
  var LANE_STAGE = { recon: 'Recon', web: 'Web', checks: 'Enumeration', ad: 'Active Directory', creds: 'Credentials', linux: 'Escalate', windows: 'Escalate', database: 'Foothold', shells: 'Foothold', pivot: 'Lateral', proof: 'Proof' };
  function deriveStage(m) {
    if (m.phase) return canonStage(m.phase);
    var prod = m.produces || [];
    for (var i = 0; i < prod.length; i++) { var st = stageOfFact(prod[i]); if (st) return st; }
    return LANE_STAGE[laneForMove(m)] || '';
  }
  function cap1(s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); }

  // --- topical categories: group reasonably-related moves together in the rail ("all the SQL in one
  //     place"), rather than by coarse attack stage. A move with no category falls back to its stage,
  //     so lanes not yet categorized still render. CATEGORY_ORDER sets the section order in the rail. ---
  var MOVE_CATEGORY = {
    // web lane
    'vhost-discovery': 'Recon & Discovery', 'content-discovery': 'Recon & Discovery', 'param-discovery': 'Recon & Discovery', 'nikto-scan': 'Recon & Discovery',
    'sqli-basics': 'SQL Injection', 'manual-sqli-exploitation': 'SQL Injection', 'sqlmap-automation': 'SQL Injection',
    'file-upload': 'Upload, Inclusion & Shells', 'lfi-probe': 'Upload, Inclusion & Shells', 'lfi-secret-harvest': 'Upload, Inclusion & Shells', 'web-shells': 'Upload, Inclusion & Shells',
    'command-injection': 'Command & Template Injection', 'ssti': 'Command & Template Injection',
    'ssrf': 'SSRF, XXE & Deserialization', 'xxe': 'SSRF, XXE & Deserialization', 'deserialization': 'SSRF, XXE & Deserialization',
    'idor': 'Auth & Access Control', 'jwt-attacks': 'Auth & Access Control', 'nosql-injection': 'Auth & Access Control', 'verb-tampering': 'Auth & Access Control',
    'xss-basics': 'Cross-Site Scripting',
    'git-exposed': 'Source Exposure', 'svn-exposed': 'Source Exposure',
    'tomcat-deploy': 'App Servers & Known CVEs', 'jenkins-access': 'App Servers & Known CVEs', 'wordpress': 'App Servers & Known CVEs', 'check-log4shell': 'App Servers & Known CVEs', 'check-struts2': 'App Servers & Known CVEs', 'ajp-ghostcat': 'App Servers & Known CVEs', 'java-rmi': 'App Servers & Known CVEs',
    // recon lane
    'nmap-fast-open-ports': 'Port Scanning', 'nmap-version-scripts': 'Port Scanning', 'nmap-vuln-scripts': 'Port Scanning', 'nmap-udp-top': 'Port Scanning',
    'recon-smb-anon': 'SMB, RDP & Web', 'rdp-enum': 'SMB, RDP & Web', 'recon-web-triage': 'SMB, RDP & Web',
    'recon-dns': 'DNS, SNMP & VPN', 'recon-snmp': 'DNS, SNMP & VPN', 'recon-ike-vpn': 'DNS, SNMP & VPN',
    'recon-smtp': 'Mail Services', 'smtp-open-relay': 'Mail Services', 'recon-mail': 'Mail Services',
    'recon-ftp': 'File Shares', 'nfs-enum': 'File Shares', 'recon-rsync': 'File Shares', 'recon-tftp': 'File Shares', 'ftp-upload-webshell': 'File Shares', 'ftp-bounce': 'File Shares',
    'recon-finger': 'Legacy & Remote Access', 'recon-vnc': 'Legacy & Remote Access', 'recon-telnet': 'Legacy & Remote Access', 'recon-rservices': 'Legacy & Remote Access', 'recon-x11': 'Legacy & Remote Access',
    // creds lane
    'crack-identify': 'Hash Cracking', 'crack-ntlm': 'Hash Cracking', 'crack-netntlmv2': 'Hash Cracking', 'crack-kerberoast': 'Hash Cracking',
    'crack-asrep-offline': 'Hash Cracking', 'crack-shadow': 'Hash Cracking', 'crack-mscache2': 'Hash Cracking', 'crack-archive': 'Hash Cracking',
    'online-brute-ssh': 'Online Brute-Force', 'online-brute-ftp': 'Online Brute-Force', 'online-brute-rdp': 'Online Brute-Force', 'ssh-user-enum': 'Online Brute-Force',
    'responder-poison': 'Poisoning & Relay', 'ntlm-relay-attack': 'Poisoning & Relay', 'mitm6-ipv6-takeover': 'Poisoning & Relay',
    // linux lane
    'linux-enum': 'Enumeration', 'pspy-monitor': 'Enumeration', 'linux-loot-hunt': 'Enumeration',
    'sudo-abuse': 'Sudo, SUID & Capabilities', 'suid-gtfobins': 'Sudo, SUID & Capabilities', 'capabilities': 'Sudo, SUID & Capabilities',
    'cron-abuse': 'Cron & Writable Files', 'writable-passwd': 'Cron & Writable Files', 'nfs-squash': 'Cron & Writable Files',
    'lxc-lxd-escape': 'Container Escape', 'docker-socket': 'Container Escape',
    'linux-persistence': 'Persistence',
    // windows lane
    'windows-enum': 'Enumeration', 'wesng-patch-gaps': 'Enumeration', 'defense-enum': 'Enumeration',
    'seimpersonate': 'Token & Service Abuse', 'unquoted-service-path': 'Token & Service Abuse', 'weak-service-permissions': 'Token & Service Abuse', 'alwaysinstallelevated': 'Token & Service Abuse',
    'dpapi-secrets': 'Credential Dumping', 'stored-credentials': 'Credential Dumping', 'windows-old-hives': 'Credential Dumping', 'lsass-dump-onbox': 'Credential Dumping',
    'windows-persistence': 'Windows Persistence',
    // database lane
    'mysql-login': 'Relational databases', 'mysql-loot': 'Relational databases', 'mysql-outfile-rce': 'Relational databases', 'mssql-login': 'Relational databases', 'mssql-xp-cmdshell': 'Relational databases', 'mssql-linked-server': 'Relational databases', 'postgres-login': 'Relational databases', 'oracle-tns': 'Relational databases',
    'redis-enum': 'NoSQL, Cache & Search', 'mongo-enum': 'NoSQL, Cache & Search', 'elasticsearch-enum': 'NoSQL, Cache & Search', 'memcached-enum': 'NoSQL, Cache & Search',
    // shells lane
    'shell-listener': 'Reverse Shells', 'shell-revshell-linux': 'Reverse Shells', 'shell-revshell-windows': 'Reverse Shells', 'shell-pty-upgrade': 'Reverse Shells',
    'ssh-key-login': 'Key & Credential Login', 'linux-remote-exec': 'Key & Credential Login',
    // pivot lane
    'local-linux-interfaces': 'Map the Foothold (Linux)', 'local-linux-routes': 'Map the Foothold (Linux)', 'local-linux-neighbors': 'Map the Foothold (Linux)', 'local-linux-dns': 'Map the Foothold (Linux)',
    'local-windows-interfaces': 'Map the Foothold (Windows)', 'local-windows-routes': 'Map the Foothold (Windows)', 'local-windows-neighbors': 'Map the Foothold (Windows)', 'local-windows-listeners': 'Map the Foothold (Windows)',
    'pivot-chisel-socks': 'Build the Tunnel', 'pivot-ligolo': 'Build the Tunnel', 'pivot-sshuttle': 'Build the Tunnel', 'pivot-ssh-dynamic': 'Build the Tunnel',
    'pivot-scan-through': 'Work Through the Pivot',
    // checks lane
    'check-tls-config': 'TLS & Cleartext', 'check-http-redirect': 'TLS & Cleartext',
    'check-http-methods': 'HTTP Verbs & CORS', 'check-cors': 'HTTP Verbs & CORS',
    'check-web-headers': 'Headers & Fingerprint', 'check-web-components': 'Headers & Fingerprint', 'check-cms-version': 'Headers & Fingerprint',
    'check-web-body': 'Page Body & Exposed Files', 'check-exposed-files': 'Page Body & Exposed Files',
    'check-subdomain-takeover': 'DNS & Email', 'check-dns-email': 'DNS & Email',
    // ad lane
    'ad-dc-identify': 'AD Recon & Enumeration', 'ad-anon-ldap-enum': 'AD Recon & Enumeration', 'ad-user-enum': 'AD Recon & Enumeration', 'bloodhound-collect': 'AD Recon & Enumeration', 'ad-path-manual': 'AD Recon & Enumeration', 'nxc-arsenal': 'AD Recon & Enumeration', 'powerview-enum': 'AD Recon & Enumeration', 'ad-legacy-enum': 'AD Recon & Enumeration', 'ad-psdotnet-enum': 'AD Recon & Enumeration', 'trust-enum': 'AD Recon & Enumeration',
    'asrep-roast': 'Credential Harvesting', 'crack-asrep': 'Credential Harvesting', 'kerberoast': 'Credential Harvesting', 'crack-tgs': 'Credential Harvesting', 'password-spray': 'Credential Harvesting', 'gpp-passwords': 'Credential Harvesting', 'smb-share-inventory': 'Credential Harvesting',
    'kerberos-tickets': 'Kerberos Tickets', 'silver-ticket': 'Kerberos Tickets', 'golden-ticket': 'Kerberos Tickets', 'diamond-ticket': 'Kerberos Tickets',
    'ad-acl-abuse': 'ACL & Object Abuse', 'bloodyad-acl': 'ACL & Object Abuse', 'shadow-credentials': 'ACL & Object Abuse', 'gmsa-read': 'ACL & Object Abuse', 'laps-read': 'ACL & Object Abuse',
    'delegation-abuse': 'Delegation & Coercion', 'unconstrained-delegation': 'Delegation & Coercion', 'getst-impersonation': 'Delegation & Coercion', 'coerce-auth': 'Delegation & Coercion',
    'adcs-esc': 'ADCS Abuse', 'cert-authenticate': 'ADCS Abuse',
    'lateral-exec': 'Lateral Movement', 'ticket-reuse': 'Lateral Movement',
    'dump-secrets': 'Dumping & Domain Dominance', 'dcsync': 'Dumping & Domain Dominance', 'own-domain-pth': 'Dumping & Domain Dominance', 'sid-history-abuse': 'Dumping & Domain Dominance',
    'zerologon-check': 'AD CVEs', 'zerologon-exploit': 'AD CVEs', 'eternalblue': 'AD CVEs', 'nopac': 'AD CVEs', 'printnightmare': 'AD CVEs', 'ms14-068': 'AD CVEs',
    'gpo-abuse': 'Service & Policy Abuse', 'dnsadmins-abuse': 'Service & Policy Abuse', 'wsus-abuse': 'Service & Policy Abuse', 'sccm-enum': 'Service & Policy Abuse',
    // proof lane
    'flag-hunt-linux': 'Proof & Capture', 'flag-hunt-windows': 'Proof & Capture',
  };
  var CATEGORY_ORDER = [
    // web
    'Recon & Discovery', 'SQL Injection', 'Upload, Inclusion & Shells', 'Command & Template Injection',
    'SSRF, XXE & Deserialization', 'Auth & Access Control', 'Cross-Site Scripting', 'Source Exposure', 'App Servers & Known CVEs',
    // recon
    'Port Scanning', 'SMB, RDP & Web', 'DNS, SNMP & VPN', 'Mail Services', 'File Shares', 'Legacy & Remote Access',
    // creds
    'Hash Cracking', 'Online Brute-Force', 'Poisoning & Relay',
    // linux
    'Enumeration', 'Sudo, SUID & Capabilities', 'Cron & Writable Files', 'Container Escape', 'Persistence',
    // windows
    'Token & Service Abuse', 'Credential Dumping', 'Windows Persistence',
    // database
    'Relational databases', 'NoSQL, Cache & Search',
    // shells
    'Reverse Shells', 'Key & Credential Login',
    // pivot
    'Map the Foothold (Linux)', 'Map the Foothold (Windows)', 'Build the Tunnel', 'Work Through the Pivot',
    // checks
    'TLS & Cleartext', 'HTTP Verbs & CORS', 'Headers & Fingerprint', 'Page Body & Exposed Files', 'DNS & Email',
    // ad
    'AD Recon & Enumeration', 'Credential Harvesting', 'Kerberos Tickets', 'ACL & Object Abuse', 'Delegation & Coercion',
    'ADCS Abuse', 'Lateral Movement', 'Dumping & Domain Dominance', 'AD CVEs', 'Service & Policy Abuse',
    // proof
    'Proof & Capture',
  ];
  function categoryOf(moveId) { var m = byId(moveId); return MOVE_CATEGORY[moveId] || deriveStage(m || {}); }

  // --- build the atlas lanes (all moves, topologically ordered within each lane) ----------------
  var _lanes = null;
  function buildLanes() {
    if (_lanes) return _lanes;
    var moves = allMoves();
    var buckets = {}; LANE_KEYS.forEach(function (k) { buckets[k] = []; });
    moves.forEach(function (m) { var k = laneForMove(m); (buckets[k] || buckets.recon).push(m); });
    _lanes = LANE_DEFS.map(function (d) {
      var ordered = topoOrder(buckets[d.key] || []);
      return {
        key: d.key, name: d.name, short: d.short, desc: d.desc,
        nodes: ordered.map(function (m) { return { id: m.id, title: m.title, phase: deriveStage(m), proves: m.produces || [], reqs: reqSet(m) }; }),
      };
    }).filter(function (L) { return L.nodes.length; });
    return _lanes;
  }
  // order so a move follows the in-lane moves that mint its prerequisites; stable on pack order otherwise
  function topoOrder(moves) {
    var produced = {}, out = [], remaining = moves.slice();
    var inLaneProducts = {};
    moves.forEach(function (m) { (m.produces || []).forEach(function (p) { inLaneProducts[p] = true; }); });
    function depsMet(m) {
      var reqs = reqSet(m);
      return reqs.every(function (r) { return !inLaneProducts[r] || produced[r]; });
    }
    var guard = 0;
    while (remaining.length && guard++ < 10000) {
      var picked = -1;
      for (var i = 0; i < remaining.length; i++) { if (depsMet(remaining[i])) { picked = i; break; } }
      if (picked < 0) picked = 0; // cycle / external-only deps: take next in pack order
      var m = remaining.splice(picked, 1)[0];
      out.push(m); (m.produces || []).forEach(function (p) { produced[p] = true; });
    }
    return out;
  }

  function lanes() { return buildLanes().map(function (L) { return { key: L.key, name: L.name, short: L.short, desc: L.desc, count: L.nodes.length, firstId: L.nodes[0].id }; }); }
  function lane(key) { var Ls = buildLanes(); for (var i = 0; i < Ls.length; i++) if (Ls[i].key === key) return Ls[i].nodes.map(function (n) { return { id: n.id, phase: n.phase, category: categoryOf(n.id), laneKey: key, title: n.title, proves: n.proves, reqs: n.reqs }; }); return []; }
  function laneOfId(id) { var Ls = buildLanes(); for (var i = 0; i < Ls.length; i++) for (var j = 0; j < Ls[i].nodes.length; j++) if (Ls[i].nodes[j].id === id) return { lane: Ls[i], idx: j }; return null; }
  function laneEntry(moveId) { var r = laneOfId(moveId); if (!r) return null; return { id: moveId, phase: r.lane.nodes[r.idx].phase, laneKey: r.lane.key }; }
  function laneEdges(key) {
    var N = lane(key), edges = [];
    N.forEach(function (a, ai) { N.forEach(function (b, bi) { if (bi <= ai) return; if (a.proves.some(function (p) { return b.reqs.indexOf(p) >= 0; })) edges.push({ from: a.id, to: b.id }); }); });
    return edges;
  }
  function laneNext(moveId) { var r = laneOfId(moveId); if (!r) return null; return r.idx < r.lane.nodes.length - 1 ? r.lane.nodes[r.idx + 1].id : null; }

  // --- per-command locus: remote(0) < offline(1) < on-target(2) --------------------------------
  function cmdLocus(c) {
    var run = (c && c.run) || '', tool = (c && c.tool) || '';
    var A = arsenal(), e = A[tool] || A[tool.toLowerCase()] || {};
    if (/(^|[\s|&;])(hashcat|john)\b/.test(run) || /\s-m\s+\d+/.test(run)) return { rank: 1, tag: 'Offline · Your Box', label: 'OFFLINE' };
    if (e.os === 'windows' || /^(stage-win|stage-lin|material)$/.test(e.class || '') || /(^|\s)\.[\\/]/.test(run) || /Rubeus|winPEAS|Sharp[A-Z]|mimikatz|GodPotato|PrintSpoofer/.test(run))
      return { rank: 2, tag: 'On-Target · Needs a Foothold', label: 'ON-TARGET' };
    return { rank: 0, tag: 'Remote · From Your Box', label: 'REMOTE' };
  }

  // --- derived graph edges ---------------------------------------------------------------------
  function producersOf(facts) { if (!facts || !facts.length) return []; return allMoves().filter(function (m) { return (m.produces || []).some(function (p) { return facts.indexOf(p) >= 0; }); }); }
  function opensNext(m) { var prod = m.produces || []; if (!prod.length) return []; return allMoves().filter(function (x) { return x.id !== m.id && reqSet(x).some(function (r) { return prod.indexOf(r) >= 0; }); }); }

  // --- "how you got here": the plausible lead-up chain to a move ---------------------------------
  // Walk the fact graph backward: the moves that mint this move's prerequisites, transitively, then
  // topologically ordered and ending at the target. Environmental prerequisites (a port, a reachable
  // form) have no producing move, so the chain bottoms out there; that is the gap an authored leadup
  // (leadupFor) fills well, rooting the story back at the scan. Returns move ids, oldest first.
  function pathTo(moveId) {
    var target = byId(moveId); if (!target) return [];
    var inset = {}; inset[moveId] = true;
    var stack = [target], guard = 0;
    while (stack.length && guard++ < 1000) {
      var m = stack.pop();
      producersOf(reqSet(m)).forEach(function (p) { if (p.id === m.id || inset[p.id]) return; inset[p.id] = true; stack.push(p); });
    }
    var moves = Object.keys(inset).map(byId).filter(Boolean);
    var ordered = topoOrder(moves).map(function (m) { return m.id; });
    return ordered.filter(function (id) { return id !== moveId; }).concat([moveId]);
  }
  // an authored recon lead-up for moves whose prerequisites come from the environment, not a prior move.
  function leadupFor(moveId) { var fx = fixtures()[moveId] || {}; return (fx.leadup && fx.leadup.length) ? fx.leadup.slice() : null; }

  function applyProfile(run, tool, profile) {
    if (!profile || !tool || !profile.tools) return run;
    var p = profile.tools[tool] || profile.tools[tool.toLowerCase()];
    if (!p || !p.invocation || p.present === false) return run;
    return run.replace(new RegExp('^\\s*' + tool.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), p.invocation);
  }

  // --- the derived conditional cell ------------------------------------------------------------
  function cellFor(moveId, opts) {
    opts = opts || {};
    var m = byId(moveId); if (!m) return null;
    var reqs = reqSet(m), profile = opts.profile || null, entry = laneEntry(moveId) || {};
    var ranked = (m.commands || []).map(function (c, i) { return { cmd: c, L: cmdLocus(c), i: i }; }).sort(function (a, b) { return a.L.rank - b.L.rank || a.i - b.i; });
    var seen = {}, commands = [];
    ranked.forEach(function (o) {
      var key = (o.cmd.tool || '?') + '|' + o.L.rank; if (seen[key]) return; seen[key] = 1;
      var run = (o.cmd.run || '').replace(/\{\{(\w+)\}\}/g, '<$1>');
      commands.push({ tool: o.cmd.tool || '', run: applyProfile(run, o.cmd.tool, profile), note: o.cmd.note || '', locus: o.L.label, tag: o.L.tag, rank: o.L.rank });
    });
    var fx = fixtures()[moveId] || null, prod = m.produces || [];
    return {
      id: m.id, title: m.title, phase: entry.phase || '', laneKey: entry.laneKey || '',
      scope: m.scope || '', locus: m.locus || '',
      whatItIs: m.hypothesis || '',
      prereqFacts: reqs,
      producedBy: producersOf(reqs).filter(function (x) { return x.id !== m.id; }).map(function (x) { return { id: x.id, title: x.title }; }),
      commands: commands,
      // A fixture pins the exact command its sample output came from (fx.cmd / fx.tool), so the Watch
      // replay types that command above its real result — command and output are one coherent run, never
      // a guess paired against the ranker. A multi-step fixture (fx.steps) models a tool that is set up
      // on BOTH your box and the target: each step carries its own `where` (local / host), command and
      // output, played in the real order. Single fixtures fall back to the move's remote-first command.
      output: buildFixtureOutput(fx),
      proves: prod,
      opens: opensNext(m).map(function (x) { return { id: x.id, title: x.title }; }),
      rulesOut: Array.isArray(m.does_not_prove) ? m.does_not_prove.join(' ; ') : (m.does_not_prove || ''),
      refs: m.refs || [],
    };
  }

  // Normalise a fixture's sample into a cell.output shape. A `steps` fixture keeps its ordered,
  // per-locus steps; a single fixture becomes a one-step sample. `text` is the concatenation used by
  // the static reference block; the Watch replay walks `steps`.
  function buildFixtureOutput(fx) {
    if (!fx) return null;
    if (fx.steps && fx.steps.length) {
      var text = fx.steps.map(function (s) { return s.output || ''; }).join('\n');
      return { text: text, signal: fx.signal || '', teach: fx.teach || '', cmd: fx.steps[0].cmd || '', tool: fx.steps[0].tool || '', steps: fx.steps };
    }
    if (fx.output) return { text: fx.output, signal: fx.signal || '', teach: fx.teach || '', cmd: fx.cmd || '', tool: fx.tool || '', steps: null };
    return null;
  }

  function stripPrompt(s) { return String(s || '').replace(/^\s*(kali\$|root@[^\s#]*[#$]|C:\\[^>]*>|[#$])\s*/, '').trim(); }
  function replayFor(moveId) {
    var cell = cellFor(moveId); if (!cell) return null;
    var primary = cell.commands[0] || null, out = cell.output;
    var steps = [];
    if (out && out.steps) {
      steps = out.steps.map(function (s) {
        var lines = String(s.output || '').split('\n');
        var cmd = s.cmd || '';
        if (lines.length && cmd && stripPrompt(lines[0]) === stripPrompt(cmd)) lines = lines.slice(1);
        return { where: s.where === 'host' ? 'host' : 'local', tool: s.tool || '', command: cmd, outputLines: lines, note: s.note || '' };
      });
    } else if (out) {
      var pcmd = out.cmd || (primary ? primary.run : '');
      var lines2 = out.text.split('\n');
      if (lines2.length && pcmd && stripPrompt(lines2[0]) === stripPrompt(pcmd)) lines2 = lines2.slice(1);
      var where = (primary && primary.locus === 'ON-TARGET') ? 'host' : 'local';
      steps = [{ where: where, tool: out.tool || (primary ? primary.tool : ''), command: pcmd, outputLines: lines2, note: primary ? primary.note : '' }];
    }
    var first = steps[0] || {};
    return {
      id: cell.id, title: cell.title, phase: cell.phase, laneKey: cell.laneKey,
      tool: first.tool || '', locus: primary ? primary.locus : '', tag: primary ? primary.tag : '',
      command: first.command || '', note: first.note || '',
      steps: steps, multi: steps.length > 1,
      outputLines: first.outputLines || [], hasOutput: !!(out && out.text),
      signal: out ? out.signal : '', teach: out ? out.teach : '',
      proves: cell.proves, opens: (cell.opens[0] || {}).title || '', next: laneNext(moveId),
    };
  }

  // --- the atlas: every lane as one layered graph, with cross-lane bridges ----------------------
  var BRIDGES = [
    { from: 'nmap-version-scripts', to: 'ad-dc-identify', note: 'a Windows/AD host → the AD lane' },
    { from: 'nmap-version-scripts', to: 'check-web-components', note: 'a web port → run the safe checks' },
    { from: 'recon-smb-anon', to: 'asrep-roast', note: 'anonymous SMB can leak the user list' },
    { from: 'recon-smb-anon', to: 'password-spray', note: 'a user list to spray' },
    { from: 'recon-web-triage', to: 'content-discovery', note: 'a live web app → map it' },
    { from: 'content-discovery', to: 'check-exposed-files', note: 'discovered paths → probe for leaks' },
    { from: 'web-shells', to: 'linux-enum', note: 'a web shell is a Linux foothold' },
    { from: 'web-shells', to: 'windows-enum', note: '…or a Windows foothold' },
    { from: 'web-shells', to: 'shell-pty-upgrade', note: 'a raw web shell → upgrade it to a real TTY' },
    { from: 'shell-revshell-linux', to: 'linux-enum', note: 'a caught shell → start Linux enumeration' },
    { from: 'shell-revshell-windows', to: 'windows-enum', note: 'a caught shell → start Windows enumeration' },
    { from: 'asrep-roast', to: 'crack-asrep-offline', note: 'an AS-REP hash to crack' },
    { from: 'kerberoast', to: 'crack-kerberoast', note: 'a service ticket to crack' },
    { from: 'dcsync', to: 'crack-ntlm', note: 'dumped NTLM hashes to crack' },
    { from: 'responder-poison', to: 'crack-netntlmv2', note: 'a captured NetNTLMv2 hash to crack' },
    { from: 'coerce-auth', to: 'ntlm-relay-attack', note: 'coerced auth → relay it to a second host' },
    { from: 'crack-netntlmv2', to: 'lateral-exec', note: 'a cracked password → move laterally' },
    { from: 'mssql-xp-cmdshell', to: 'windows-enum', note: 'a DB shell → escalate on the host' },
    { from: 'sudo-abuse', to: 'local-linux-interfaces', note: 'now root → pivot deeper' },
    { from: 'seimpersonate', to: 'local-windows-interfaces', note: 'now SYSTEM → pivot deeper' },
    { from: 'sudo-abuse', to: 'flag-hunt-linux', note: 'root → grab the proof' },
    { from: 'seimpersonate', to: 'flag-hunt-windows', note: 'SYSTEM → grab the proof' },
  ];
  function atlas() {
    var Ls = buildLanes(), nodes = [], index = {};
    Ls.forEach(function (L, row) { L.nodes.forEach(function (n, col) { var node = { id: n.id, title: n.title, lane: L.key, phase: n.phase, proves: n.proves, reqs: n.reqs, col: col, row: row }; nodes.push(node); index[n.id] = node; }); });
    var laneE = [], crossE = [];
    Ls.forEach(function (L) { for (var i = 1; i < L.nodes.length; i++) laneE.push({ from: L.nodes[i - 1].id, to: L.nodes[i].id }); });
    BRIDGES.forEach(function (b) { if (index[b.from] && index[b.to]) crossE.push({ from: b.from, to: b.to, note: b.note }); });
    return { nodes: nodes, laneEdges: laneE, crossEdges: crossE, laneOrder: Ls.map(function (L) { return L.key; }), lanes: Ls.map(function (L) { return { key: L.key, name: L.name, short: L.short, count: L.nodes.length }; }), cols: Math.max.apply(null, Ls.map(function (L) { return L.nodes.length; })) };
  }

  // --- scenarios: curated cross-lane paths ------------------------------------------------------
  // Curated end-to-end paths, grouped by category so the picker reads like a menu. `cat` drives the
  // grouping + colour in the UI; SCEN_CATS sets the display order. Every step is a real move id.
  var SCEN_CATS = ['Recon', 'Web to Shell', 'Privilege Escalation', 'Active Directory', 'Databases', 'Lateral & Pivot'];
  var SCENARIOS = [
    { key: 'recon-sweep', cat: 'Recon', name: 'Full recon sweep', desc: 'The opening every engagement shares: ports, versions, SMB, and the web surface.',
      steps: ['nmap-fast-open-ports', 'nmap-version-scripts', 'recon-smb-anon', 'recon-web-triage'] },

    { key: 'web-linux', cat: 'Web to Shell', name: 'Web app → Linux root', desc: 'Map a web app, get a shell through it, then escalate to root.',
      steps: ['recon-web-triage', 'content-discovery', 'lfi-probe', 'file-upload', 'web-shells', 'linux-enum', 'sudo-abuse'] },
    { key: 'web-windows', cat: 'Web to Shell', name: 'Web app → Windows SYSTEM', desc: 'Web foothold on a Windows host, then abuse a privilege to SYSTEM.',
      steps: ['recon-web-triage', 'content-discovery', 'file-upload', 'web-shells', 'windows-enum', 'seimpersonate'] },
    { key: 'ssti-root', cat: 'Web to Shell', name: 'SSTI → RCE → root', desc: 'Spot template injection, turn it into a shell, then escalate on Linux.',
      steps: ['recon-web-triage', 'content-discovery', 'ssti', 'web-shells', 'linux-enum', 'sudo-abuse'] },
    { key: 'cmdi-root', cat: 'Web to Shell', name: 'Command injection → shell → root', desc: 'Inject an OS command, catch a reverse shell, then escalate.',
      steps: ['recon-web-triage', 'content-discovery', 'command-injection', 'shell-revshell-linux', 'linux-enum', 'sudo-abuse'] },
    { key: 'tomcat-system', cat: 'Web to Shell', name: 'Tomcat manager → WAR → SYSTEM', desc: 'Fingerprint Tomcat, deploy a WAR shell, then take SYSTEM.',
      steps: ['recon-web-triage', 'check-web-components', 'tomcat-deploy', 'windows-enum', 'seimpersonate'] },
    { key: 'web-root-proof', cat: 'Web to Shell', name: 'Web → root → proof', desc: 'The full exam arc: recon a web app, shell it, escalate to root, capture the flag.',
      steps: ['nmap-fast-open-ports', 'recon-web-triage', 'content-discovery', 'file-upload', 'web-shells', 'linux-enum', 'sudo-abuse', 'flag-hunt-linux'] },

    { key: 'linux-sudo', cat: 'Privilege Escalation', name: 'Linux foothold → sudo → root', desc: 'From a low-priv shell, read your sudo rights and escape a binary to root.',
      steps: ['linux-enum', 'sudo-abuse', 'flag-hunt-linux'] },
    { key: 'win-potato', cat: 'Privilege Escalation', name: 'Windows foothold → SeImpersonate → SYSTEM', desc: 'Enumerate, find SeImpersonatePrivilege, and ride a potato to SYSTEM.',
      steps: ['windows-enum', 'seimpersonate', 'flag-hunt-windows'] },
    { key: 'cron-root', cat: 'Privilege Escalation', name: 'Find the cron job → root', desc: 'Watch processes with pspy, spot a root job you can influence, and take root.',
      steps: ['linux-enum', 'pspy-monitor', 'cron-abuse'] },

    { key: 'ad-classic', cat: 'Active Directory', name: 'Classic AD: no creds → Domain Admin', desc: 'Anonymous foothold, roast a hash, crack it, walk an ACL path to DCSync.',
      steps: ['nmap-fast-open-ports', 'ad-dc-identify', 'ad-anon-ldap-enum', 'asrep-roast', 'crack-asrep', 'ad-acl-abuse', 'dcsync'] },
    { key: 'kerberoast-da', cat: 'Active Directory', name: 'Kerberoast → crack → Domain Admin', desc: 'With one domain credential, roast a service account, crack it, and escalate.',
      steps: ['ad-dc-identify', 'ad-anon-ldap-enum', 'kerberoast', 'crack-tgs', 'ad-acl-abuse', 'dcsync'] },
    { key: 'adcs-da', cat: 'Active Directory', name: 'AD CS (ESC1) → Domain Admin', desc: 'Abuse a vulnerable certificate template to mint a DA credential, then DCSync.',
      steps: ['ad-dc-identify', 'ad-anon-ldap-enum', 'adcs-esc', 'cert-authenticate', 'dcsync'] },
    { key: 'smb-spray', cat: 'Active Directory', name: 'SMB foothold → spray → DA', desc: 'Pull a user list from anonymous SMB, spray for a login, escalate in the domain.',
      steps: ['recon-smb-anon', 'password-spray', 'ad-acl-abuse', 'dcsync'] },
    { key: 'nopac-da', cat: 'Active Directory', name: 'Domain cred → noPac → Domain Admin', desc: 'A single low-priv credential against an unpatched DC becomes Domain Admin.',
      steps: ['ad-dc-identify', 'ad-anon-ldap-enum', 'asrep-roast', 'crack-asrep', 'nopac'] },
    { key: 'coerce-relay', cat: 'Active Directory', name: 'Coerce → relay → DCSync', desc: 'Force the DC to authenticate, relay it to grant replication rights, then DCSync.',
      steps: ['coerce-auth', 'ntlm-relay-attack', 'dcsync'] },
    { key: 'golden-persist', cat: 'Active Directory', name: 'Domain Admin → Golden Ticket', desc: 'Once you own the domain, forge a TGT that survives password resets.',
      steps: ['dcsync', 'golden-ticket'] },
    { key: 'eternalblue-sys', cat: 'Active Directory', name: 'SMBv1 → EternalBlue → SYSTEM', desc: 'An unpatched SMBv1 host falls to MS17-010 for SYSTEM without credentials.',
      steps: ['nmap-version-scripts', 'nmap-vuln-scripts', 'eternalblue', 'flag-hunt-windows'] },

    { key: 'mssql-system', cat: 'Databases', name: 'MSSQL sysadmin → SYSTEM', desc: 'A database login with sysadmin becomes a shell, then SYSTEM on the host.',
      steps: ['nmap-version-scripts', 'mssql-login', 'mssql-xp-cmdshell', 'windows-enum', 'seimpersonate'] },
    { key: 'mysql-reuse', cat: 'Databases', name: 'MySQL → dump hashes → reuse', desc: 'Log in, dump the app password table, crack a hash, and reuse it to move.',
      steps: ['mysql-login', 'mysql-loot', 'crack-ntlm', 'lateral-exec'] },

    { key: 'responder-lateral', cat: 'Lateral & Pivot', name: 'Poison → crack → move laterally', desc: 'Capture a hash off the wire, crack it, and reuse it to own a second host.',
      steps: ['responder-poison', 'crack-netntlmv2', 'lateral-exec', 'windows-enum'] },
    { key: 'web-pivot-deep', cat: 'Lateral & Pivot', name: 'Web shell → loot → pivot', desc: 'Land through the web, loot creds, then tunnel into the network behind the box.',
      steps: ['recon-web-triage', 'content-discovery', 'web-shells', 'linux-enum', 'linux-loot-hunt', 'local-linux-interfaces', 'pivot-chisel-socks', 'pivot-scan-through'] },
    { key: 'pivot-internal', cat: 'Lateral & Pivot', name: 'Foothold → tunnel → reach internal', desc: 'From a foothold, map the hidden subnet, build a tunnel, and scan what is behind it.',
      steps: ['linux-enum', 'local-linux-interfaces', 'pivot-ligolo', 'pivot-scan-through'] },
  ];
  function scenCat(s) { return s.cat || 'Other'; }
  function scenMap(s) { return { key: s.key, cat: scenCat(s), name: s.name, desc: s.desc, steps: s.steps.slice(), count: s.steps.length }; }
  function scenarios() { return SCENARIOS.filter(function (s) { return s.steps.every(byId); }).map(scenMap); }
  function scenarioCats() { return SCEN_CATS.slice(); }
  function scenario(key) { for (var i = 0; i < SCENARIOS.length; i++) if (SCENARIOS[i].key === key) return scenMap(SCENARIOS[i]); return null; }

  // --- cold-box simulation: run a scenario as a guided, scaffolded playthrough -------------------
  // A real box starts cold: an IP and nothing else. simFor walks a scenario one move at a time. Each
  // step reveals that move's real captured output (the replay), then asks which move comes next. The
  // right answer is the scenario's own next step; the distractors are tempting-but-wrong moves, each
  // labelled with why it is wrong here (a prereq you have not earned yet, or simply a different path).
  // The simulation reuses the fixtures and the replay, so what the learner reads is the same evidence
  // the Watch panel shows, never a throwaway mock.
  function simLockState(id, produced) {
    var m = byId(id); if (!m) return { locked: true, missing: [] };
    var all = m.requires_all || [], any = m.requires_any || [];
    var missAll = all.filter(function (r) { return !produced[r] && !isExternal(r); });
    var anyOk = any.length === 0 || any.some(function (r) { return produced[r] || isExternal(r); });
    return { locked: missAll.length > 0 || !anyOk, missing: missAll.concat(anyOk ? [] : ['one of: ' + any.join(' / ')]) };
  }
  function simHumanFact(k) { return /^one of:/.test(k) ? ('one of: ' + k.replace(/^one of:\s*/, '').split(' / ').map(friendly).join(' or ')) : friendly(k); }
  function simChoices(ids, i, produced) {
    var correctId = ids[i + 1], cm = byId(correctId); if (!cm) return null;
    var onpath = {}; ids.forEach(function (x) { onpath[x] = 1; });
    var correctLane = (laneEntry(correctId) || {}).laneKey;
    var cand = allMoves().filter(function (m) { return !onpath[m.id]; });
    cand.sort(function (a, b) {
      var la = (laneEntry(a.id) || {}).laneKey === correctLane ? 0 : 1;
      var lb = (laneEntry(b.id) || {}).laneKey === correctLane ? 0 : 1;
      return la - lb;
    });
    var locked = [], open = [];
    cand.forEach(function (m) { var s = simLockState(m.id, produced); (s.locked ? locked : open).push({ m: m, s: s }); });
    var picks = [];
    if (locked.length) picks.push(locked[0]);
    if (open.length) picks.push(open[0]);
    [locked[1], open[1], locked[2], open[2]].forEach(function (p) { if (p && picks.length < 2 && picks.indexOf(p) < 0) picks.push(p); });
    var choices = [{ id: correctId, title: cm.title, correct: true, why: '' }];
    picks.slice(0, 2).forEach(function (p) {
      var why = p.s.locked
        ? 'Not yet. This needs ' + p.s.missing.map(simHumanFact).join(', ') + ', and you have not earned that.'
        : 'A legal move, but it is not the next step on this path.';
      choices.push({ id: p.m.id, title: p.m.title, correct: false, why: why });
    });
    for (var j = choices.length - 1; j > 0; j--) { var r = Math.floor(Math.random() * (j + 1)); var t = choices[j]; choices[j] = choices[r]; choices[r] = t; }
    return choices;
  }
  function simFor(key) {
    var sc = scenario(key); if (!sc) return null;
    var ids = sc.steps.filter(byId);
    var produced = {};
    var steps = ids.map(function (id, i) {
      var m = byId(id), rp = replayFor(id);
      (m.produces || []).forEach(function (p) { produced[p] = 1; });
      var nextId = ids[i + 1] || null;
      return {
        idx: i, id: id, title: m.title, phase: (laneEntry(id) || {}).phase || '',
        intro: i === 0 ? 'A fresh box: an IP and nothing else. You run your opening move.' : 'You run it. This comes back.',
        replay: rp,
        prompt: nextId ? 'You have your result. What is your next move?' : '',
        choices: nextId ? simChoices(ids, i, produced) : null,
        nextId: nextId, last: !nextId,
      };
    });
    return { key: sc.key, name: sc.name, desc: sc.desc, count: steps.length, steps: steps };
  }

  // --- the EVIDENCE index: "what do I have in front of me, and what does it unlock?" -------------
  // This is the by-port view, generalised. Ports are the first evidence you get; after a foothold the
  // evidence is a shell, a hash, a credential, a pivot host. Each entry carries one curated plain
  // sentence ("what it means") and a DERIVED, topo-ordered mini-lane of the moves that evidence opens,
  // so every entry is as navigable as a methodology lane. Membership is seeded + pulled from whole
  // taxonomy lanes, and a coverage check keeps it honest. tier 'ports' shows first, then tier 'access'.
  var EVIDENCE = [
    { key: 'scan', tier: 'ports', port: 'first', proto: '', fam: 'recon', label: 'Before anything, scan', signal: 'Every engagement opens the same way. Sweep the target so you know which doors exist before you touch any one of them.', seed: ['nmap-fast-open-ports', 'nmap-version-scripts', 'nmap-udp-top', 'nmap-vuln-scripts'] },
    { key: 'p21', tier: 'ports', port: '21', proto: 'tcp', fam: 'file', label: 'FTP', signal: 'File transfer. Test the anonymous login first because it costs nothing, then brute a known user. Files on FTP routinely hold configs, source, or credentials, and a writable directory that is also the web root is a shell.', seed: ['recon-ftp', 'online-brute-ftp', 'ftp-upload-webshell', 'ftp-bounce'] },
    { key: 'p22', tier: 'ports', port: '22', proto: 'tcp', fam: 'remote', label: 'SSH', signal: 'Remote shell. There is no code execution here, but a looted private key or a weak password is a stable foothold, and SSH is your cleanest pivot.', seed: ['ssh-key-login', 'online-brute-ssh', 'ssh-user-enum', 'pivot-ssh-dynamic', 'pivot-sshuttle'] },
    { key: 'p23', tier: 'ports', port: '23', proto: 'tcp', fam: 'remote', label: 'Telnet', signal: 'Cleartext remote login. The banner often names the OS or device, default and reused passwords log straight in, and nothing on the wire is encrypted.', seed: ['recon-telnet'] },
    { key: 'p25', tier: 'ports', port: '25/110/143', proto: 'tcp', fam: 'mail', label: 'SMTP, POP3, IMAP', signal: 'Mail. SMTP VRFY confirms real usernames, and a mailbox credential lets you read mail for secrets and reset links. NTLM auth leaks the domain name.', seed: ['recon-smtp', 'smtp-open-relay', 'recon-mail', 'password-spray'] },
    { key: 'p53', tier: 'ports', port: '53', proto: 'tcp/udp', fam: 'recon', label: 'DNS', signal: 'Name service. A zone transfer (AXFR) can hand you the whole internal host map in one request.', seed: ['recon-dns'] },
    { key: 'p69', tier: 'ports', port: '69', proto: 'udp', fam: 'file', label: 'TFTP', signal: 'A tiny unauthenticated file service with no listing. Common on routers and phones, it hands out config files full of hashes and management passwords if you can name them.', seed: ['recon-tftp'] },
    { key: 'p79', tier: 'ports', port: '79', proto: 'tcp', fam: 'recon', label: 'Finger', signal: 'Ancient, but when it is open it leaks real usernames and who is logged in, which is raw material for a spray or a brute.', seed: ['recon-finger'] },
    { key: 'p80', tier: 'ports', port: '80/443', proto: 'tcp', fam: 'web', label: 'HTTP, HTTPS', signal: 'A web app, the single richest attack surface on the exam. Fingerprint the stack, map the content, then hunt the injectable edge.', seed: ['recon-web-triage', 'vhost-discovery', 'content-discovery', 'param-discovery', 'nikto-scan', 'wordpress', 'check-web-headers', 'check-web-components', 'check-cms-version', 'check-exposed-files', 'check-http-methods', 'check-cors', 'check-http-redirect', 'check-web-body', 'check-tls-config', 'check-dns-email', 'check-subdomain-takeover', 'sqli-basics', 'manual-sqli-exploitation', 'sqlmap-automation', 'command-injection', 'lfi-probe', 'lfi-secret-harvest', 'file-upload', 'ssti', 'xxe', 'ssrf', 'nosql-injection', 'jwt-attacks', 'verb-tampering', 'xss-basics', 'git-exposed', 'svn-exposed', 'idor', 'deserialization', 'check-log4shell', 'check-struts2', 'jenkins-access', 'web-shells'] },
    { key: 'p88', tier: 'ports', port: '88', proto: 'tcp', fam: 'ad', label: 'Kerberos', signal: 'A Domain Controller. Kerberos (88) with LDAP (389) and SMB (445) is the AD fingerprint. Name the domain, list the users, then roast.', seed: ['ad-dc-identify', 'ad-user-enum', 'asrep-roast', 'crack-asrep', 'kerberoast', 'crack-tgs', 'kerberos-tickets', 'ticket-reuse'] },
    { key: 'p111', tier: 'ports', port: '111/2049', proto: 'tcp', fam: 'file', label: 'NFS', signal: 'Network file shares. An export open to everyone is readable by anyone, and no_root_squash turns it into a privilege escalation.', seed: ['nfs-enum', 'nfs-squash'] },
    { key: 'p135', tier: 'ports', port: '135/139/445', proto: 'tcp', fam: 'ad', label: 'SMB, RPC', signal: 'Windows file sharing and RPC, the busiest port in AD. Try anonymous access, hunt readable shares, check for old SMBv1 (EternalBlue), and poison or relay NTLM.', seed: ['recon-smb-anon', 'smb-share-inventory', 'gpp-passwords', 'eternalblue', 'responder-poison', 'ntlm-relay-attack', 'mitm6-ipv6-takeover', 'coerce-auth', 'ad-legacy-enum', 'lateral-exec', 'dump-secrets', 'own-domain-pth', 'dcsync'] },
    { key: 'p161', tier: 'ports', port: '161', proto: 'udp', fam: 'recon', label: 'SNMP', signal: 'A default "public" community string reads running processes, users, and sometimes credentials straight out of the host.', seed: ['recon-snmp'] },
    { key: 'p389', tier: 'ports', port: '389/636/3268', proto: 'tcp', fam: 'ad', label: 'LDAP, Global Catalog', signal: 'The directory itself. An anonymous bind lists every user, and with a credential you collect BloodHound, read LAPS, and find AD CS templates.', seed: ['ad-dc-identify', 'ad-anon-ldap-enum', 'bloodhound-collect', 'ad-path-manual', 'laps-read', 'gmsa-read', 'adcs-esc', 'cert-authenticate', 'password-spray', 'nxc-arsenal'] },
    { key: 'p500', tier: 'ports', port: '500', proto: 'udp', fam: 'remote', label: 'IKE, IPsec VPN', signal: 'A VPN endpoint. Aggressive Mode hands back a PSK hash you can crack offline, and is a finding on its own.', seed: ['recon-ike-vpn'] },
    { key: 'p512', tier: 'ports', port: '512/513/514', proto: 'tcp', fam: 'remote', label: 'r-services (rexec, rlogin, rsh)', signal: 'Berkeley trust logins. A permissive .rhosts or hosts.equiv lets you rlogin or rsh in as any user, root included, with no password at all.', seed: ['recon-rservices'] },
    { key: 'p873', tier: 'ports', port: '873', proto: 'tcp', fam: 'file', label: 'rsync', signal: 'A file-sync daemon serving named modules. Many list and read without auth (source, backups, keys), and a writable module maps straight onto a sensitive path.', seed: ['recon-rsync'] },
    { key: 'p1433', tier: 'ports', port: '1433', proto: 'tcp', fam: 'db', label: 'MSSQL', signal: 'Microsoft SQL. A login with sysadmin re-enables xp_cmdshell and runs OS commands, so the database becomes a shell.', seed: ['mssql-login', 'mssql-xp-cmdshell', 'mssql-linked-server', 'crack-identify'] },
    { key: 'p1521', tier: 'ports', port: '1521', proto: 'tcp', fam: 'db', label: 'Oracle TNS', signal: 'The Oracle listener. Brute the SID, try default accounts (system, scott, dbsnmp), and a privileged login reads and writes host files and reaches command execution.', seed: ['oracle-tns', 'crack-identify'] },
    { key: 'p3306', tier: 'ports', port: '3306', proto: 'tcp', fam: 'db', label: 'MySQL, MariaDB', signal: 'A login reads app secrets and the mysql.user hash table, and can write files into the web root.', seed: ['mysql-login', 'mysql-loot', 'mysql-outfile-rce', 'crack-identify'] },
    { key: 'p3389', tier: 'ports', port: '3389', proto: 'tcp', fam: 'remote', label: 'RDP', signal: 'Remote desktop. Confirm which credentials log in, because a weak password is a full graphical session as that user.', seed: ['rdp-enum', 'online-brute-rdp'] },
    { key: 'p5432', tier: 'ports', port: '5432', proto: 'tcp', fam: 'db', label: 'PostgreSQL', signal: 'A session with the right role reads files and, through COPY FROM PROGRAM, runs commands.', seed: ['postgres-login', 'crack-identify'] },
    { key: 'p5900', tier: 'ports', port: '5900', proto: 'tcp', fam: 'remote', label: 'VNC', signal: 'Remote desktop. A security type of "None" is an unauthenticated screen, and even with a password, VNC passwords are short and crackable.', seed: ['recon-vnc'] },
    { key: 'p5985', tier: 'ports', port: '5985/5986', proto: 'tcp', fam: 'remote', label: 'WinRM', signal: 'Windows remote management. With a credential it is an interactive shell (evil-winrm), your way onto and through Windows hosts.', seed: ['lateral-exec', 'local-windows-interfaces', 'local-windows-routes', 'local-windows-neighbors', 'local-windows-listeners'] },
    { key: 'p6000', tier: 'ports', port: '6000', proto: 'tcp', fam: 'remote', label: 'X11', signal: 'A desktop display with access control off. Any network client can screenshot the session, log keystrokes as they are typed, and inject input, all as the logged-in user.', seed: ['recon-x11'] },
    { key: 'p6379', tier: 'ports', port: '6379', proto: 'tcp', fam: 'db', label: 'Redis', signal: 'Often unauthenticated. INFO reads the host, and a writable Redis can drop an SSH key or a web shell, which is a direct foothold.', seed: ['redis-enum', 'ssh-key-login', 'shell-listener'] },
    { key: 'p1099', tier: 'ports', port: '1099', proto: 'tcp', fam: 'web', label: 'Java RMI', signal: 'A Java RMI registry. List the bound objects, then a deserialization gadget (ysoserial via remote-method-guesser) turns a remote method call into code execution.', seed: ['java-rmi'] },
    { key: 'p8009', tier: 'ports', port: '8009', proto: 'tcp', fam: 'web', label: 'AJP (Tomcat)', signal: 'Tomcat\'s AJP connector. Ghostcat (CVE-2020-1938) reads any file under the web root, and includes an uploaded file as JSP for code execution.', seed: ['ajp-ghostcat'] },
    { key: 'p8080', tier: 'ports', port: '8080', proto: 'tcp', fam: 'web', label: 'HTTP-alt (Tomcat, Jenkins)', signal: 'App servers. Tomcat Manager deploys a WAR, and the Jenkins script console runs Groovy. Both are code execution once you have credentials.', seed: ['tomcat-deploy', 'jenkins-access'] },
    { key: 'p9200', tier: 'ports', port: '9200', proto: 'tcp', fam: 'db', label: 'Elasticsearch', signal: 'A JSON REST API, often unauthenticated. List the indices and dump the interesting one for stored records; old versions carry a scripting-engine RCE.', seed: ['elasticsearch-enum'] },
    { key: 'p11211', tier: 'ports', port: '11211', proto: 'tcp', fam: 'db', label: 'Memcached', signal: 'An in-memory cache with no auth by design. Dump the cached keys for session tokens and secrets the application left in memory.', seed: ['memcached-enum'] },
    { key: 'p27017', tier: 'ports', port: '27017', proto: 'tcp', fam: 'db', label: 'MongoDB', signal: 'Historically no auth. If you can list the databases you can read them, and hashes and API keys sit in plain collections.', seed: ['mongo-enum'] },
    // once you are in: the evidence is no longer a port but what you are holding
    { key: 'shell-linux', tier: 'access', port: '', proto: '', fam: 'access', label: 'You have a shell on Linux', signal: 'You landed a foothold, so the box itself is now the signal. Before escalating, enumerate: sudo rights, SUID bits, capabilities, cron jobs, and loot all point the way to root.', seed: ['shell-listener', 'shell-revshell-linux', 'shell-pty-upgrade', 'linux-remote-exec'], lanes: ['linux'] },
    { key: 'shell-windows', tier: 'access', port: '', proto: '', fam: 'access', label: 'You have a shell on Windows', signal: 'You landed on a Windows host. Check your privileges first: a single enabled token privilege, a weak service, or a saved credential is usually the whole way to SYSTEM.', seed: ['shell-listener', 'shell-revshell-windows'], lanes: ['windows'] },
    { key: 'offline-hash', tier: 'access', port: '', proto: '', fam: 'access', label: 'You have a hash (crack it offline)', signal: 'A hash in hand is a credential you have not spent yet. Identify the type, pick the matching mode, and crack it offline where there is no lockout.', seed: ['crack-identify', 'crack-ntlm', 'crack-netntlmv2', 'crack-kerberoast', 'crack-asrep-offline', 'crack-shadow', 'crack-archive', 'crack-mscache2', 'crack-asrep', 'crack-tgs'] },
    { key: 'domain-cred', tier: 'access', port: '', proto: '', fam: 'ad', label: 'You have a valid domain credential', signal: 'One domain account changes everything. Map the attack paths, roast service accounts, abuse ACLs and delegation, and walk the graph toward Domain Admin.', seed: ['bloodhound-collect', 'ad-path-manual', 'powerview-enum', 'ad-psdotnet-enum', 'kerberoast', 'ad-acl-abuse', 'bloodyad-acl', 'gpo-abuse', 'dnsadmins-abuse', 'shadow-credentials', 'delegation-abuse', 'getst-impersonation', 'unconstrained-delegation', 'adcs-esc', 'cert-authenticate', 'dcsync', 'golden-ticket', 'silver-ticket', 'diamond-ticket', 'ticket-reuse', 'sid-history-abuse', 'trust-enum', 'laps-read', 'gmsa-read', 'own-domain-pth', 'zerologon-check', 'zerologon-exploit', 'nopac', 'printnightmare', 'ms14-068', 'wsus-abuse', 'sccm-enum'] },
    { key: 'pivot', tier: 'access', port: '', proto: '', fam: 'access', label: 'You have a foothold on a dual-homed host', signal: 'The box you own can reach a network you cannot. Enumerate its interfaces and routes, stand up a tunnel, and scan the subnet behind it.', seed: [], lanes: ['pivot'] },
    { key: 'proof', tier: 'access', port: '', proto: '', fam: 'access', label: 'You have root or SYSTEM (capture the proof)', signal: 'The objective. Grab the user and root flags, and capture the proof the report needs.', seed: [], lanes: ['proof'] },
  ];
  function evidenceMoves(seedIds) {
    var ms = [], seen = {};
    seedIds.forEach(function (id) { var m = byId(id); if (m && !seen[id]) { seen[id] = 1; ms.push(m); } });
    return topoOrder(ms).map(function (m) { return { id: m.id, title: m.title, laneKey: (laneEntry(m.id) || {}).laneKey || '', cat: categoryOf(m.id), phase: deriveStage(m) }; });
  }
  function evidence() {
    return EVIDENCE.map(function (e) {
      var seed = (e.seed || []).slice();
      (e.lanes || []).forEach(function (lk) { lane(lk).forEach(function (n) { if (seed.indexOf(n.id) < 0) seed.push(n.id); }); });
      return { key: e.key, tier: e.tier, port: e.port || '', proto: e.proto || '', fam: e.fam || '', label: e.label, signal: e.signal, moves: evidenceMoves(seed) };
    }).filter(function (e) { return e.moves.length; });
  }
  // moves that never appear under any evidence entry (coverage guard for the by-evidence view)
  function evidenceGaps() {
    var seen = {}; evidence().forEach(function (e) { e.moves.forEach(function (m) { seen[m.id] = 1; }); });
    return allMoves().map(function (m) { return m.id; }).filter(function (id) { return !seen[id]; });
  }

  // --- "Your turn" practice --------------------------------------------------------------------
  function factsInHandAt(moveId, seq) {
    var have = {}, m = byId(moveId);
    if (m) reqSet(m).forEach(function (k) { have[k] = 1; });
    var order = seq && seq.length ? seq : lane((laneEntry(moveId) || {}).laneKey).map(function (n) { return n.id; });
    for (var i = 0; i < order.length; i++) { if (order[i] === moveId) break; var pm = byId(order[i]); if (pm) (pm.produces || []).forEach(function (k) { have[k] = 1; }); }
    return Object.keys(have);
  }
  function practiceFor(moveId, seq) {
    var m = byId(moveId); if (!m) return null;
    var fx = fixtures()[moveId] || {};
    var have = factsInHandAt(moveId, seq);
    var ids = (fx.choices && fx.choices.length) ? fx.choices.slice() : autoChoices(moveId);
    if (ids.indexOf(moveId) < 0) ids.unshift(moveId);
    var coach = fx.coach || {};
    var choices = ids.map(function (id) {
      var d = byId(id); if (!d) return null;
      var verdict, missing = [];
      if (id === moveId) verdict = 'correct';
      else {
        var all = d.requires_all || [], any = d.requires_any || [];
        var allMet = all.every(function (r) { return have.indexOf(r) >= 0; });
        var anyMet = any.length === 0 || any.some(function (r) { return have.indexOf(r) >= 0; });
        missing = all.filter(function (r) { return have.indexOf(r) < 0; });
        if (!anyMet) missing.push('one of: ' + any.join(' / '));
        verdict = (allMet && anyMet) ? 'alt' : 'locked';
      }
      return { id: id, title: d.title, verdict: verdict, missing: missing, coach: coach[id] || '' };
    }).filter(Boolean);
    for (var j = choices.length - 1; j > 0; j--) { var r = Math.floor(Math.random() * (j + 1)); var t = choices[j]; choices[j] = choices[r]; choices[r] = t; }
    return { moveId: moveId, situation: fx.situation || '', have: have, choices: choices };
  }
  // when a move has no authored choices, draw distractors from its lane neighbours
  function autoChoices(moveId) {
    var N = lane((laneEntry(moveId) || {}).laneKey).map(function (n) { return n.id; });
    var i = N.indexOf(moveId), out = [moveId];
    [i + 1, i - 1, i + 2].forEach(function (k) { if (k >= 0 && k < N.length && N[k] !== moveId && out.indexOf(N[k]) < 0) out.push(N[k]); });
    return out.slice(0, 4);
  }

  // --- mastery (per-browser) -------------------------------------------------------------------
  var MKEY = 'obol.study-mastery';
  function mastery() { try { return JSON.parse(localStorage.getItem(MKEY) || '{}') || {}; } catch (e) { return {}; } }
  function markStudied(id, kind) { try { var m = mastery(); m[id] = Object.assign({ studied: false, correct: false }, m[id]); if (kind === 'studied') m[id].studied = true; if (kind === 'correct') { m[id].studied = true; m[id].correct = true; } localStorage.setItem(MKEY, JSON.stringify(m)); } catch (e) {} }
  function laneProgress(key) { var ids = lane(key).map(function (n) { return n.id; }), m = mastery(); var s = 0, c = 0; ids.forEach(function (id) { if (m[id] && m[id].studied) s++; if (m[id] && m[id].correct) c++; }); return { total: ids.length, studied: s, correct: c }; }

  // --- path validation: does each step's prereqs hold given the steps before it? ----------------
  function validatePath(ids) {
    var have = {}, issues = [];
    ids.forEach(function (id, i) {
      var m = byId(id); if (!m) { issues.push({ idx: i, id: id, kind: 'unknown' }); return; }
      var all = m.requires_all || [], any = m.requires_any || [];
      var missAll = all.filter(function (r) { return !have[r] && !isExternal(r); });
      var anyOk = any.length === 0 || any.some(function (r) { return have[r] || isExternal(r); });
      if (missAll.length || !anyOk) issues.push({ idx: i, id: id, kind: 'prereq', missing: missAll.concat(anyOk ? [] : ['one of: ' + any.join(' / ')]) });
      (m.produces || []).forEach(function (p) { have[p] = 1; });
    });
    return { ok: !issues.length, issues: issues };
  }
  // facts an opening move needs that come "from the environment" (a target, reachability) — not from
  // another move — so a path that starts mid-stream isn't flagged for them.
  function isExternal(fact) { return /^(target\.|host\.up|ports\.open|port:|.*\.reachable$|http\.reachable|foothold\.)/.test(fact); }

  // --- signal recognition helpers: the "so what" behind evidence -------------------------------
  function friendly(k) { try { return (OBOL.pack && OBOL.pack.friendly) ? OBOL.pack.friendly(k) : k; } catch (e) { return k; } }
  // the hand-written "why this, why now" teaching note for a move (fixtures carry it as `why`); empty
  // when none is authored yet, so the route can fall back to the derived dependency explanation.
  function whyNow(moveId) { var fx = fixtures()[moveId] || {}; return fx.why || ''; }
  // the hand-written "how to actually do it" field notes for a move (fixtures carry it as `how`):
  // { lead: '…', items: [{ t: 'technique', d: 'how' }, …] }. Empty when none is authored yet.
  function howTo(moveId) { var fx = fixtures()[moveId] || {}; var h = fx.how; return (h && h.items && h.items.length) ? h : null; }
  // the "why this line matters" read-out for a move's highlighted signal
  function signalTell(moveId) {
    var m = byId(moveId); if (!m) return null;
    var fx = fixtures()[moveId] || {};
    var proves = (m.produces || []).map(function (f) { return { fact: f, label: friendly(f) }; });
    var opens = opensNext(m).slice(0, 5).map(function (x) { return { id: x.id, title: x.title }; });
    var gist = proves.length
      ? ('This line is your proof that you now have ' + proves[0].label + (opens.length ? ', which is exactly what ' + opens[0].title + ' needs next.' : '.'))
      : 'This line is the result that confirms the step worked.';
    return { signal: fx.signal || '', proves: proves, opens: opens, gist: gist, teach: fx.teach || '' };
  }
  // one fact, made first-class: what produces it, and what it then unlocks
  function factInfo(fact) {
    return {
      fact: fact, label: friendly(fact),
      producedBy: allMoves().filter(function (m) { return (m.produces || []).indexOf(fact) >= 0; }).map(function (m) { return { id: m.id, title: m.title }; }),
      unlocks: allMoves().filter(function (m) { return reqSet(m).indexOf(fact) >= 0; }).map(function (m) { return { id: m.id, title: m.title }; }),
    };
  }
  // other moves that reach the same outcome (share a produced fact) — the candidates for "which, when?"
  function alternativesFor(moveId) {
    var m = byId(moveId); if (!m) return [];
    var prod = m.produces || []; if (!prod.length) return [];
    var out = [];
    allMoves().forEach(function (x) {
      if (x.id === moveId) return;
      var shared = (x.produces || []).filter(function (p) { return prod.indexOf(p) >= 0; });
      if (shared.length) out.push({ id: x.id, title: x.title, shared: shared });
    });
    return out;
  }

  // --- scope-safety: which moves are loud or can break things (teach when NOT to fire) ----------
  var SCOPE = {
    'eternalblue': { level: 'destructive', note: 'The SMBv1 exploit can blue-screen the target. Confirm it is a lab box, not a honeypot, before you fire it.' },
    'zerologon-check': { level: 'loud', note: 'The check itself is safe; the exploit it leads to is destructive.' },
    'zerologon-exploit': { level: 'destructive', note: 'Resets the DC machine password and breaks its secure channel. You MUST restore the original password afterward or you take the domain down.' },
    'dnsadmins-abuse': { level: 'loud', note: 'Requires restarting the DNS service on a DC, which is noisy and disruptive.' },
    'printnightmare': { level: 'loud', note: 'Loads a driver through the print spooler and can be unstable on some builds.' },
    'nopac': { level: 'loud', note: 'Creates a machine account and forges a ticket. Unpatched DCs only.' },
    'coerce-auth': { level: 'loud', note: 'Forces a target to authenticate to you. Obvious in logs.' },
    'responder-poison': { level: 'loud', note: 'Poisons name resolution for the whole segment and can affect machines you did not intend. Scope it carefully.' },
    'ntlm-relay-attack': { level: 'loud', note: 'Active on the wire; logs an authentication on the relayed host.' },
    'mitm6-ipv6-takeover': { level: 'loud', note: 'Rogue DHCPv6 and DNS affect every Windows host on the segment. Scope it carefully.' },
    'online-brute-ssh': { level: 'loud', note: 'Failed logins are logged and can lock accounts. Keep the list small.' },
    'online-brute-ftp': { level: 'loud', note: 'Failed logins are logged and can lock accounts.' },
    'online-brute-rdp': { level: 'loud', note: 'RDP lockout is unforgiving. Use one password at a time.' },
    'password-spray': { level: 'loud', note: 'One password across many users avoids lockout, but the failed logons are still logged. Read the policy first.' },
    'dcsync': { level: 'loud', note: 'Replication from a non-DC account stands out in the logs.' },
    'golden-ticket': { level: 'loud', note: 'Post-compromise persistence that forges tickets bypassing normal auth.' },
    'linux-persistence': { level: 'loud', note: 'Adds a durable way back in. On a real engagement this is scoped, logged, and cleaned up.' },
    'windows-persistence': { level: 'loud', note: 'Adds a local admin account. Scope it, log it, and remove it afterward.' },
  };
  function scopeSafety(moveId) { return SCOPE[moveId] || { level: 'safe', note: '' }; }

  // --- "which tool, when?": curated tradeoff decisions over moves that reach the same outcome ----
  var DECISIONS = [
    { key: 'ad-paths', moves: ['bloodhound-collect', 'ad-path-manual', 'powerview-enum'],
      question: 'BloodHound, bloodyAD, or PowerView to work AD attack paths?',
      pick: 'BloodHound to discover', rule: 'Use BloodHound to DISCOVER the path, then bloodyAD to EXECUTE a known edge.',
      unless: 'you cannot exfil a large collection or need to stay quiet (go straight to bloodyAD), or you are already on a Windows box with no way to upload (use PowerView in memory).',
      detail: [
        { id: 'bloodhound-collect', when: 'You want to see the whole domain and have it compute the shortest path for you. Heavier: it collects a large dataset, wants the GUI to analyse, and the collection is noisy.' },
        { id: 'ad-path-manual', when: 'You already know or suspect the edge and want to act on it surgically from the command line. Light and quiet, no big collection, but you have to know what you are looking for.' },
        { id: 'powerview-enum', when: 'You are on a Windows foothold and cannot upload tools. Loads in memory and queries live, at the cost of running on the target.' },
      ] },
    { key: 'dump-creds', moves: ['dcsync', 'dump-secrets', 'lsass-dump-onbox'],
      question: 'Dump credentials remotely, or on the host with mimikatz?',
      pick: 'Remotely', rule: 'Default to the remote dump. It is fast, uploads nothing, and never touches AV on the host.',
      unless: 'remote is blocked, or you specifically need the live secrets that only exist in memory (cleartext passwords, the Kerberos tickets of logged-in users), which are not in the SAM or NTDS. Then dump LSASS on the host.',
      detail: [
        { id: 'dcsync', when: 'You hold replication rights. Pulls every hash in the domain from the DC over the network, in seconds, with nothing uploaded.' },
        { id: 'dump-secrets', when: 'You have admin on a host and want its local SAM and LSA, remotely, with no shell needed.' },
        { id: 'lsass-dump-onbox', when: 'You need what is only in memory right now: cleartext passwords and the tickets of other logged-in users, none of which live in the SAM or NTDS. Slower and more tedious, runs on the host, and is exactly what AV watches most closely. Reach for it only when the fast remote dump cannot give you the live secret you are after.' },
      ] },
    { key: 'relay-or-crack', moves: ['ntlm-relay-attack', 'crack-netntlmv2'],
      question: 'A captured NetNTLMv2 hash: relay it, or crack it?',
      pick: 'Relay it', rule: 'If SMB signing is off on a host where the victim is a local admin, relay the authentication straight to it. No cracking, no password needed.',
      unless: 'signing is on everywhere (nothing to relay to) or you want the actual cleartext password to reuse elsewhere. Then crack it offline.',
      detail: [
        { id: 'ntlm-relay-attack', when: 'Signing is off and a reachable target has the victim as admin. Instant access, nothing to crack, but it needs a valid relay target.' },
        { id: 'crack-netntlmv2', when: 'You cannot relay, or you want the plaintext to reuse on services that will not accept a hash. Offline and no lockout, but only if the password is in your wordlist.' },
      ] },
    { key: 'capture-auth', moves: ['responder-poison', 'coerce-auth'],
      question: 'Wait for authentication with Responder, or coerce it?',
      pick: 'Coerce it', rule: 'If you can, force a chosen host to authenticate to you with a coercion tool. You get the hash on demand instead of hoping for traffic.',
      unless: 'you expect organic traffic (a busy segment, a user about to log on) or want to stay passive and quiet. Then just listen with Responder.',
      detail: [
        { id: 'responder-poison', when: 'Passive. Catches the authentication that happens to come your way. Quiet, but on a dead network you wait forever.' },
        { id: 'coerce-auth', when: 'Active. Forces a specific target to authenticate to you right now. Reliable, but obvious in the logs.' },
      ] },
    { key: 'crack-engine', moves: ['crack-ntlm', 'crack-netntlmv2', 'crack-kerberoast', 'crack-asrep-offline', 'crack-shadow', 'crack-mscache2', 'crack-tgs', 'crack-asrep', 'crack-archive'],
      question: 'hashcat or john to crack a hash?',
      pick: 'hashcat', rule: 'Default to hashcat. On a GPU it is far faster, and its mode numbers are well documented.',
      unless: 'you are CPU-only, or the hash is an odd format hashcat has no clean mode for. Then john, which has the widest format support and the bundled zip2john and ssh2john extractors.',
      detail: [
        { id: 'crack-ntlm', when: 'Applies to every crack step: hashcat for raw speed on a GPU, john for format breadth and its *2john helpers when you are extracting a hash from a file.' },
      ] },
  ];
  function decisionFor(moveId) { return DECISIONS.filter(function (d) { return d.moves.indexOf(moveId) >= 0; }); }

  // --- diagnosis practice: read raw output, name what you now have (facts, not moves) -----------
  var FACTPOOL = null;
  function factPool() {
    if (FACTPOOL) return FACTPOOL;
    var set = {}; allMoves().forEach(function (m) { (m.produces || []).forEach(function (f) { set[f] = 1; }); });
    FACTPOOL = Object.keys(set);
    return FACTPOOL;
  }
  function shuffle(a) { for (var i = a.length - 1; i > 0; i--) { var r = Math.floor(Math.random() * (i + 1)); var t = a[i]; a[i] = a[r]; a[r] = t; } return a; }
  function practiceDiagnose(moveId) {
    var cell = cellFor(moveId); if (!cell || !cell.output || !cell.output.text) return null;
    var m = byId(moveId); var correct = (m.produces || [])[0]; if (!correct) return null;
    var mine = {}; (m.produces || []).forEach(function (f) { mine[f] = 1; });
    var pool = {};
    lane((laneEntry(moveId) || {}).laneKey).forEach(function (n) { var nm = byId(n.id); if (nm) (nm.produces || []).forEach(function (f) { if (!mine[f]) pool[f] = 1; }); });
    var distract = shuffle(Object.keys(pool));
    if (distract.length < 3) { shuffle(factPool()).forEach(function (f) { if (!mine[f] && distract.indexOf(f) < 0 && distract.length < 3) distract.push(f); }); }
    distract = distract.slice(0, 3);
    var choices = distract.map(function (f) { return { fact: f, label: friendly(f), correct: false }; });
    choices.push({ fact: correct, label: friendly(correct), correct: true });
    return { moveId: moveId, title: cell.title, output: cell.output.text, signal: cell.output.signal,
      question: 'You ran this step and got the output above. What does it tell you that you now have?',
      choices: shuffle(choices),
      why: 'That output line is the evidence you now hold ' + friendly(correct) + ', which is what the next move needs.' };
  }

  // --- scaffolding level: how much "why" to show. Fades as a move is mastered, or set manually ---
  var CKEY = 'obol.study-coach';
  function coachPref() { try { return localStorage.getItem(CKEY) || 'always'; } catch (e) { return 'always'; } }
  function setCoachPref(v) { try { localStorage.setItem(CKEY, v); } catch (e) {} }
  function showWhy(moveId) { var p = coachPref(); if (p === 'always') return true; if (p === 'off') return false; var mk = mastery()[moveId] || {}; return !mk.correct; }

  OBOL.study = {
    LANE_DEFS: LANE_DEFS, LANE_KEYS: LANE_KEYS,
    lanes: lanes, lane: lane, laneEdges: laneEdges, laneEntry: laneEntry, laneNext: laneNext,
    atlas: atlas, scenarios: scenarios, scenarioCats: scenarioCats, scenario: scenario, simFor: simFor,
    evidence: evidence, evidenceGaps: evidenceGaps,
    cmdLocus: cmdLocus, cellFor: cellFor, replayFor: replayFor, practiceFor: practiceFor, practiceDiagnose: practiceDiagnose,
    producersOf: producersOf, opensNext: opensNext, pathTo: pathTo, leadupFor: leadupFor,
    categoryOf: categoryOf, CATEGORY_ORDER: CATEGORY_ORDER,
    signalTell: signalTell, whyNow: whyNow, howTo: howTo, factInfo: factInfo, alternativesFor: alternativesFor, decisionFor: decisionFor, scopeSafety: scopeSafety,
    coachPref: coachPref, setCoachPref: setCoachPref, showWhy: showWhy,
    mastery: mastery, markStudied: markStudied, laneProgress: laneProgress, validatePath: validatePath,
    // back-compat for tests
    get AD_LANE() { return lane('ad'); },
    get LANE_ORDER() { return LANE_KEYS; },
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
