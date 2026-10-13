/*!
 * obol data, stuck-catalog.js, the curated fact catalog for the Stuck? tab.
 *
 * Maps a fact kind to a human-phrased BINARY the user can click to assert ("A Website Is Up"), instead
 * of the raw kind ("http.reachable"). Only kinds that appear here are user-assertable in Stuck?; the
 * reveal engine (OBOL.stuck.suggestFacts) still decides WHICH of them to show based on the move graph,
 * so this file supplies the words, not the logic.
 *
 * Entry shape, per kind:
 *   label : the button text, Title Case, phrased as something the user can confirm about their target.
 *   help  : one plain sentence of clarification (sentence case; it is prose, not a UI label).
 *   group : the lane it belongs to, for sectioning the picker (Recon, Web, ...).
 *   value : OPTIONAL payload to attach to the asserted fact (most are presence-only, so omitted).
 *
 * House style: no em or en dashes; Title Case labels. These are what the USER tells obol, so the UI
 * frames every resulting suggestion as "based on what you told me."
 *
 * COVERAGE: all lanes authored in the sanctioned voice: Recon, Web, Windows And AD, Credentials,
 * Access, Linux Privesc, Windows Privesc, Loot, Pivoting. Database presence lives under Recon (the
 * service-open buttons). New user-assertable kinds are added here as the pack grows.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var CATALOG = {
    // ── Recon: the scan state and what is exposed ───────────────────────────────────────────────
    'host.up': { group: 'Recon', label: 'The Host Is Up', help: 'The target answers a ping or a scan, so it is alive and reachable.' },
    'ports.open': { group: 'Recon', label: 'I Have Open Ports', help: 'A port sweep came back with at least one open port.' },
    'scan.nmap.quick': { group: 'Recon', label: 'I Did A Quick Port Sweep', help: 'You ran a fast all-ports scan to find what is listening.' },
    'scan.nmap.version': { group: 'Recon', label: 'I Did A Service Version Scan', help: 'You ran the thorough scan (nmap -sC -sV) and know the service versions.' },
    // Note: 'scan.nmap.udp' is intentionally NOT catalogued. It is an activity marker ("I ran a UDP
    // scan"), not a target attribute, and offering it as an assertable fact let a user unlock SNMP
    // Enumeration without SNMP actually being open (recon-snmp gates on it in requires_any). In Stuck?
    // you indicate SNMP by lighting the 161 port in the palette; the UDP services a scan reveals are
    // themselves the findings. The move graph keeps the scan.nmap.udp -> recon-snmp reachability edge.
    'scan.nmap.vuln': { group: 'Recon', label: 'I Ran The Vuln Scripts', help: 'You ran nmap with the vuln scripts against the open services.' },

    // Service presence. A stuck student usually knows which ports answered, even without the versions.
    'smb.reachable': { group: 'Recon', label: 'SMB Is Open (445)', help: 'Port 445 answers, so file shares and Windows enumeration are on the table.' },
    'ldap.reachable': { group: 'Recon', label: 'LDAP Is Open (389)', help: 'Port 389 answers, a strong sign of Active Directory.' },
    'kerberos.reachable': { group: 'Recon', label: 'Kerberos Is Open (88)', help: 'Port 88 answers, so this is almost certainly a domain controller.' },
    'winrm.reachable': { group: 'Recon', label: 'WinRM Is Open (5985)', help: 'Remote PowerShell is listening, your route in once you hold a credential.' },
    'rdp.reachable': { group: 'Recon', label: 'RDP Is Open (3389)', help: 'Remote Desktop is listening.' },
    'ssh.reachable': { group: 'Recon', label: 'SSH Is Open (22)', help: 'An SSH server is listening, the usual Linux login.' },
    'ftp.reachable': { group: 'Recon', label: 'FTP Is Open (21)', help: 'An FTP server is listening, check for anonymous access first.' },
    'port:1433': { group: 'Recon', label: 'MSSQL Is Open (1433)', help: 'A Microsoft SQL Server is listening.' },
    'snmp.reachable': { group: 'Recon', label: 'SNMP Is Open (161/UDP)', help: 'SNMP answers, try the public community string for a quick info leak.' },
    'dns.reachable': { group: 'Recon', label: 'DNS Is Open (53)', help: 'A DNS server answers, worth a zone transfer attempt.' },
    'nfs.reachable': { group: 'Recon', label: 'NFS Is Open (2049)', help: 'Network File System exports may be mountable.' },
    'service.mysql': { group: 'Recon', label: 'MySQL Is Exposed (3306)', help: 'A MySQL/MariaDB server is listening.' },
    'service.postgresql': { group: 'Recon', label: 'PostgreSQL Is Exposed (5432)', help: 'A PostgreSQL server is listening.' },
    'service.redis': { group: 'Recon', label: 'Redis Is Exposed (6379)', help: 'A Redis instance is listening, often with no auth.' },
    'service.mongodb': { group: 'Recon', label: 'MongoDB Is Exposed (27017)', help: 'A MongoDB instance is listening.' },
    'service.elasticsearch': { group: 'Recon', label: 'Elasticsearch Is Exposed (9200)', help: 'An Elasticsearch node is listening.' },

    // ── Web: what you have found on the website ─────────────────────────────────────────────────
    'http.reachable': { group: 'Web', label: 'A Website Is Up', help: 'A web server answers on 80, 443, 8080, 8443, or similar.' },
    'web.server': { group: 'Web', label: 'I Know The Web Server', help: 'You can see the Server header (Apache, nginx, IIS).' },
    'web.tech': { group: 'Web', label: 'I Know The Framework Or CMS', help: 'You identified the stack (WordPress, Tomcat, Laravel, and so on).' },
    'web.content_map': { group: 'Web', label: 'I Did Content Discovery', help: 'You ran gobuster or ffuf and have a list of paths and files.' },
    'web.vhost': { group: 'Web', label: 'I Found A Virtual Host', help: 'A Host header or subdomain reveals another site on the same server.' },
    'web.parameterized': { group: 'Web', label: 'The App Takes User Input', help: 'There are forms or query parameters you can feed values into.' },
    'web.param_candidate': { group: 'Web', label: 'I Found A Parameter To Test', help: 'A specific URL or form parameter that looks worth attacking.' },
    'web.source': { group: 'Web', label: 'I Can See The Source Code', help: 'You have the app source (git, a backup file, an LFI leak).' },
    'web.users': { group: 'Web', label: 'I Found Usernames On The Site', help: 'The site leaks account names you can build a userlist from.' },
    'web.upload_form': { group: 'Web', label: 'There Is A File Upload', help: 'The app lets you upload a file somewhere.' },
    'web.jwt_secret': { group: 'Web', label: 'I Know The JWT Signing Secret', help: 'You recovered or cracked the token secret, so you can forge tokens.' },

    // Confirmed web findings. Phrased as what you have already proven, so obol hands the follow-through.
    'web.sqli_confirmed': { group: 'Web', label: 'I Confirmed SQL Injection', help: 'A parameter is injectable. obol can open the Manual SQLi builder for the follow-through.' },
    'web.cmdi_confirmed': { group: 'Web', label: 'I Confirmed Command Injection', help: 'You can run OS commands through the app.' },
    'web.lfi_confirmed': { group: 'Web', label: 'I Confirmed Local File Inclusion', help: 'The app reads server files you choose.' },
    'web.ssrf_confirmed': { group: 'Web', label: 'I Confirmed SSRF', help: 'You can make the server send requests on your behalf.' },
    'web.ssti_confirmed': { group: 'Web', label: 'I Confirmed Template Injection', help: 'Your input is evaluated by the templating engine.' },
    'web.xss_confirmed': { group: 'Web', label: 'I Confirmed XSS', help: 'Your script runs in another user context.' },
    'web.upload_confirmed': { group: 'Web', label: 'I Confirmed An Unrestricted Upload', help: 'You can upload and reach an executable file.' },
    'web.xxe_confirmed': { group: 'Web', label: 'I Confirmed XXE', help: 'The XML parser processes your external entities.' },
    'web.nosqli_confirmed': { group: 'Web', label: 'I Confirmed NoSQL Injection', help: 'A NoSQL query takes your unsanitized input.' },
    'web.deserial_confirmed': { group: 'Web', label: 'I Confirmed Insecure Deserialization', help: 'The app deserializes data you control.' },
    'web.authz_bypass': { group: 'Web', label: 'I Bypassed Authorization', help: 'You reached something you should not (IDOR, forced browsing, broken access control).' },
    'web.idor_candidate': { group: 'Web', label: 'I Found An IDOR Candidate', help: 'An object id in a request looks like you can swap it for another user.' },

    // ── Windows And Active Directory ─────────────────────────────────────────────────────────────
    'ad.domain_known': { group: 'Windows And AD', label: 'I Know The Domain Name', help: 'You have the AD domain (for example htb.local), so the LDAP base DN follows.' },
    'ad.dc_candidate': { group: 'Windows And AD', label: 'I Found The Domain Controller', help: 'You identified a DC to aim enumeration, roasting, and attacks at.' },
    'ad.user_list': { group: 'Windows And AD', label: 'I Have A List Of Domain Users', help: 'You enumerated usernames, the handoff for password spraying and roasting.' },
    'smb.null_session': { group: 'Windows And AD', label: 'Anonymous SMB Works (Null Session)', help: 'You can list shares or users with no login at all.' },
    'smb.guest_session': { group: 'Windows And AD', label: 'Guest SMB Access Works', help: 'The guest account gets you in without a password.' },
    'smb.shares': { group: 'Windows And AD', label: 'I Can See SMB Shares', help: 'You listed shares and can hunt them for files and credentials.' },
    'smb.authenticated': { group: 'Windows And AD', label: 'I Can Log In Over SMB', help: 'A credential authenticates to SMB on this host.' },
    'smb.ms17_010': { group: 'Windows And AD', label: 'SMB Is Vulnerable To MS17-010', help: 'EternalBlue is in play, the vuln scan flagged it.' },
    'ad.anonymous_bind': { group: 'Windows And AD', label: 'Anonymous LDAP Bind Works', help: 'You can query LDAP without credentials.' },
    'ad.graph.collected': { group: 'Windows And AD', label: 'I Ran BloodHound', help: 'You collected the graph and can read the attack paths.' },
    'ad.attack_paths': { group: 'Windows And AD', label: 'I Have Attack Paths To Follow', help: 'BloodHound found a route toward Domain Admin.' },
    'ad.acl_lead': { group: 'Windows And AD', label: 'I Found A Writable AD Object', help: 'An ACL lets you reset a password, add to a group, or similar.' },
    'ad.coerced_auth': { group: 'Windows And AD', label: 'I Coerced Authentication', help: 'You forced a machine to authenticate to you, relay or crack it.' },
    'ad.unconstrained': { group: 'Windows And AD', label: 'I Found Unconstrained Delegation', help: 'A host can be made to cough up other tickets.' },
    'ad.trusts': { group: 'Windows And AD', label: 'I Found A Domain Trust', help: 'Another domain trusts this one, a path to cross over.' },
    'ad.zerologon': { group: 'Windows And AD', label: 'The DC Is Vulnerable To Zerologon', help: 'CVE-2020-1472. If you exploit it, remember the mandatory password restore.' },
    'kerberos.tickets': { group: 'Windows And AD', label: 'I Have Kerberos Tickets', help: 'You hold TGT or TGS tickets you can use or abuse.' },
    'winrm.authenticated': { group: 'Windows And AD', label: 'I Can Log In Over WinRM', help: 'A credential gets you a PowerShell shell via evil-winrm.' },
    'rdp.authenticated': { group: 'Windows And AD', label: 'I Can Log In Over RDP', help: 'A credential gets you a Remote Desktop session.' },
    'snmp.community': { group: 'Windows And AD', label: 'I Found An SNMP Community String', help: 'A community string (often public) opens up an SNMP info dump.' },
    'dns.zone': { group: 'Windows And AD', label: 'I Pulled A DNS Zone Transfer', help: 'A full zone leaks internal hostnames.' },

    // ── Credentials And Hashes ───────────────────────────────────────────────────────────────────
    'credential.candidate': { group: 'Credentials', label: 'I Found A Possible Credential', help: 'A username, password, or hash you have not confirmed works yet.' },
    'credential.available': { group: 'Credentials', label: 'I Have A Credential', help: 'A username with a password or hash in hand.' },
    'credential.validated': { group: 'Credentials', label: 'My Credential Actually Logs In', help: 'You confirmed it works, by cracking it or by a successful login somewhere.' },
    'credential.plaintext': { group: 'Credentials', label: 'I Have A Plaintext Password', help: 'A cleartext password, not just a hash.' },
    'hash.ntlm': { group: 'Credentials', label: 'I Have An NTLM Hash', help: 'You can pass-the-hash or crack it. obol can open Hash ID.' },
    'credential.ntlm_hash': { group: 'Credentials', label: 'I Have A User NTLM Hash', help: 'An account hash you can relay, pass, or crack.' },
    'credential.netntlm': { group: 'Credentials', label: 'I Captured A NetNTLM Hash', help: 'From Responder or a relay. Crack it or relay it onward.' },
    'hash.asrep': { group: 'Credentials', label: 'I Have An AS-REP Hash', help: 'From AS-REP roasting. Crack it with hashcat mode 18200.' },
    'hash.tgs': { group: 'Credentials', label: 'I Have A Kerberoast (TGS) Hash', help: 'From Kerberoasting a service account. Crack it with hashcat mode 13100.' },
    'hash.krbtgt': { group: 'Credentials', label: 'I Have The krbtgt Hash', help: 'Golden ticket territory, you can forge any ticket.' },
    'hash.mscache': { group: 'Credentials', label: 'I Have Cached Domain Creds', help: 'mscache/DCC2 hashes from a logged-on box. Slow to crack, but offline.' },
    'credential.certificate': { group: 'Credentials', label: 'I Have A Certificate (PFX)', help: 'A client cert you can authenticate with (PKINIT) or turn into a hash.' },

    // ── Access And Shells ────────────────────────────────────────────────────────────────────────
    'access.shell': { group: 'Access', label: 'I Have A Shell', help: 'Any command execution on the box, however limited.' },
    'foothold.linux': { group: 'Access', label: 'My Shell Is On Linux', help: 'You landed on a Linux host.' },
    'foothold.windows': { group: 'Access', label: 'My Shell Is On Windows', help: 'You landed on a Windows host.' },
    'foothold.webshell': { group: 'Access', label: 'I Have A Web Shell', help: 'Command execution through the web app, time to upgrade it to a real shell.' },
    'access.admin': { group: 'Access', label: 'I Have Admin Or Root', help: 'Local admin on Windows, or root on Linux. Time to loot and move on.' },
    'access.system': { group: 'Access', label: 'I Have SYSTEM', help: 'The highest Windows local account.' },

    // ── Linux Privilege Escalation (what your enum found) ────────────────────────────────────────
    'privesc.sudo_rights': { group: 'Linux Privesc', label: 'I Can Run Something With Sudo', help: 'sudo -l shows allowed commands. Check GTFOBins for an escape.' },
    'privesc.suid_candidate': { group: 'Linux Privesc', label: 'I Found An Interesting SUID Binary', help: 'A SUID binary that might escape to root. Check GTFOBins.' },
    'privesc.capability': { group: 'Linux Privesc', label: 'I Found A Dangerous Capability', help: 'A file capability like cap_setuid that grants root.' },
    'privesc.cron_writable': { group: 'Linux Privesc', label: 'I Found A Writable Cron Job', help: 'A scheduled task you can edit runs as root.' },
    'privesc.docker_group': { group: 'Linux Privesc', label: 'My User Is In The Docker Group', help: 'Docker group membership is effectively root.' },
    'privesc.lxd_group': { group: 'Linux Privesc', label: 'My User Is In The LXD Group', help: 'LXD membership mounts the host disk as root.' },
    'privesc.nfs_no_root_squash': { group: 'Linux Privesc', label: 'There Is An NFS no_root_squash Export', help: 'Mount it and drop a SUID root binary.' },
    'privesc.passwd_writable': { group: 'Linux Privesc', label: '/etc/passwd Is Writable', help: 'Add a root user with a known password.' },
    'privesc.stored_credentials': { group: 'Linux Privesc', label: 'I Found Stored Credentials On The Box', help: 'Config files, history, or keys with a reusable secret.' },
    'privesc.patch_gap': { group: 'Linux Privesc', label: 'The Box Is Missing Patches', help: 'An out of date kernel or package points at a known exploit.' },

    // ── Windows Privilege Escalation (what your enum found) ──────────────────────────────────────
    'privesc.windows_privilege': { group: 'Windows Privesc', label: 'I Have A Dangerous Token Privilege', help: 'SeImpersonate, SeBackup, and friends. Potato or token abuse territory.' },
    'privesc.weak_service_permission': { group: 'Windows Privesc', label: 'I Found A Weak Service Permission', help: 'You can reconfigure a service that runs as SYSTEM.' },
    'privesc.unquoted_service_path': { group: 'Windows Privesc', label: 'I Found An Unquoted Service Path', help: 'A classic path-hijack to SYSTEM.' },
    'privesc.always_install_elevated': { group: 'Windows Privesc', label: 'AlwaysInstallElevated Is Set', help: 'Any MSI you craft installs as SYSTEM.' },
    'privesc.scheduled_task': { group: 'Windows Privesc', label: 'I Found A Writable Scheduled Task', help: 'A task you can edit runs with higher privileges.' },

    // ── Loot ─────────────────────────────────────────────────────────────────────────────────────
    'loot.ntds': { group: 'Loot', label: 'I Dumped NTDS', help: 'Every domain hash. The domain is effectively yours.' },
    'loot.shadow': { group: 'Loot', label: 'I Have /etc/shadow', help: 'The Linux password hashes, crack them offline.' },
    'loot.files': { group: 'Loot', label: 'I Found Interesting Files', help: 'Notes, backups, or configs worth reading for secrets.' },
    'loot.material': { group: 'Loot', label: 'I Found Loot (Keys, Configs)', help: 'SSH keys, config secrets, or tokens you can reuse.' },

    // ── Pivoting (once you are on a box with a second network) ───────────────────────────────────
    'host.multihomed': { group: 'Pivoting', label: 'The Box Has A Second Network', help: 'Another interface or subnet, your pivot into internal hosts.' },
    'scan.local.neighbors': { group: 'Pivoting', label: 'I See Internal Hosts From Here', help: 'Other machines are reachable from this foothold.' },
    'tunnel.socks': { group: 'Pivoting', label: 'I Have A SOCKS Tunnel Up', help: 'Proxy your tools through this box into the internal net.' },
    'tunnel.route': { group: 'Pivoting', label: 'I Have A Route To The Internal Net', help: 'Traffic to the internal subnet goes through your pivot.' },
  };

  OBOL.STUCK_CATALOG = CATALOG;

  // ── Port palette ────────────────────────────────────────────────────────────────────────────
  // Ports are foundational, so they get their own curated step (not reveal candidates). Picking a port
  // asserts the service/reachable fact(s) the pack gates on, which both opens that service's lane and
  // makes its moves eligible. The common OSCP/HTB set, plus a free-type box in the UI for anything
  // exotic. `facts` are what the click asserts; `lane` groups the palette visually.
  OBOL.STUCK_PORTS = [
    { port: 21, label: 'FTP', lane: 'Common', facts: ['ftp.reachable', 'port:21'] },
    { port: 22, label: 'SSH', lane: 'Common', facts: ['ssh.reachable', 'port:22'] },
    { port: 23, label: 'Telnet', lane: 'Common', facts: ['telnet.reachable', 'port:23'] },
    { port: 25, label: 'SMTP', lane: 'Common', facts: ['port:25'] },
    { port: 53, label: 'DNS', lane: 'Common', facts: ['dns.reachable', 'port:53'] },
    { port: 80, label: 'HTTP', lane: 'Web', facts: ['http.reachable', 'port:80'] },
    { port: 110, label: 'POP3', lane: 'Mail', facts: ['port:110'] },
    { port: 111, label: 'RPC / NFS', lane: 'Common', facts: ['port:111'] },
    { port: 135, label: 'MSRPC', lane: 'Windows', facts: ['port:135'] },
    { port: 139, label: 'NetBIOS', lane: 'Windows', facts: ['smb.reachable', 'port:139'] },
    { port: 143, label: 'IMAP', lane: 'Mail', facts: ['port:143'] },
    { port: 161, label: 'SNMP', lane: 'Common', facts: ['snmp.reachable', 'port:161'] },
    { port: 389, label: 'LDAP', lane: 'Windows', facts: ['ldap.reachable', 'port:389'] },
    { port: 443, label: 'HTTPS', lane: 'Web', facts: ['http.reachable', 'port:443'] },
    { port: 445, label: 'SMB', lane: 'Windows', facts: ['smb.reachable', 'port:445'] },
    { port: 88, label: 'Kerberos', lane: 'Windows', facts: ['kerberos.reachable', 'port:88'] },
    { port: 464, label: 'Kerberos PW', lane: 'Windows', facts: ['port:464'] },
    { port: 500, label: 'IKE / VPN', lane: 'Common', facts: ['port:500'] },
    { port: 587, label: 'SMTP (sub)', lane: 'Mail', facts: ['port:587'] },
    { port: 593, label: 'RPC / HTTP', lane: 'Windows', facts: ['port:593'] },
    { port: 636, label: 'LDAPS', lane: 'Windows', facts: ['ldap.reachable', 'port:636'] },
    { port: 873, label: 'rsync', lane: 'Common', facts: ['rsync.reachable', 'port:873'] },
    { port: 993, label: 'IMAPS', lane: 'Mail', facts: ['port:993'] },
    { port: 995, label: 'POP3S', lane: 'Mail', facts: ['port:995'] },
    { port: 1433, label: 'MSSQL', lane: 'Database', facts: ['port:1433'] },
    { port: 2049, label: 'NFS', lane: 'Common', facts: ['nfs.reachable', 'port:2049'] },
    { port: 3268, label: 'Global Catalog', lane: 'Windows', facts: ['ldap.reachable', 'port:3268'] },
    { port: 3306, label: 'MySQL', lane: 'Database', facts: ['service.mysql', 'port:3306'] },
    { port: 3389, label: 'RDP', lane: 'Windows', facts: ['rdp.reachable', 'port:3389'] },
    { port: 5432, label: 'PostgreSQL', lane: 'Database', facts: ['service.postgresql', 'port:5432'] },
    { port: 5985, label: 'WinRM', lane: 'Windows', facts: ['winrm.reachable', 'port:5985'] },
    { port: 5986, label: 'WinRM (TLS)', lane: 'Windows', facts: ['winrm.reachable', 'port:5986'] },
    { port: 6379, label: 'Redis', lane: 'Database', facts: ['service.redis', 'port:6379'] },
    { port: 8080, label: 'HTTP (alt)', lane: 'Web', facts: ['http.reachable', 'port:8080'] },
    { port: 8443, label: 'HTTPS (alt)', lane: 'Web', facts: ['http.reachable', 'port:8443'] },
    { port: 9200, label: 'Elasticsearch', lane: 'Database', facts: ['service.elasticsearch', 'port:9200'] },
    { port: 27017, label: 'MongoDB', lane: 'Database', facts: ['service.mongodb', 'port:27017'] },
  ];
})(typeof globalThis !== 'undefined' ? globalThis : this);
