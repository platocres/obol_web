/*!
 * obol data — parser-signatures.js — OBOL.PARSER_SIGNATURES
 *
 * Plain-language "what each parser looks for", plus the fact kinds it can emit. This is TWO things at
 * once (see docs/DECISION-MAP.md):
 *   1. the parser-lens content on the decision map — the readable sentence pinned at each move, so you
 *      can see, in English, what obol scans the pasted output for at that step;
 *   2. the authoritative PARSER CAPABILITY SET — the union of every `emits` list is "every fact obol
 *      can ever recognize from output". The decision map's parse-gap lens flags any move that produces
 *      a fact NOT in this set (nothing can read its result), and the gap report cross-checks this set
 *      against the real parsers so it can't drift (tools/gap-report.js --verify).
 *
 * An `emits` entry ending in "." is a PREFIX wildcard (e.g. "service." covers service.mysql, service.
 * ms-sql-s, …) — used for the families where the parser builds the fact kind dynamically. Keep the
 * sentences plain: this is read by learners, not just maintainers. `regex` is a short gloss of the
 * actual anchor, not the literal pattern (the parser source stays the source of truth for behavior).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.PARSER_SIGNATURES = {
    'ports': {
      looksFor: 'open-port rows from a scan — a line like "445/tcp open microsoft-ds" (or a bare port table pasted with no nmap command).',
      regex: 'N/tcp|udp open <service>',
      emits: ['ports.open', 'scan.nmap.quick', 'scan.nmap.version', 'scan.nmap.udp', 'scan.nmap.vuln', 'host.up',
        'service.', 'ftp.reachable', 'ssh.reachable', 'smb.reachable', 'ldap.reachable', 'kerberos.reachable',
        'rdp.reachable', 'winrm.reachable', 'snmp.reachable', 'dns.reachable', 'http.reachable', 'ad.dc_candidate'],
    },
    'vulnmatch': {
      looksFor: 'a product and version in a scan or banner (nmap -sV, whatweb, a CHANGELOG) or a CVE / nmap vuln verdict that matches a known-exploit module, for example "vsftpd 2.3.4", "ProFTPD 1.3.5", "Drupal 7.57", or "VULNERABLE: CVE-2019-0708".',
      regex: '<product> <vulnerable-version> | CVE-id | vuln-script VULNERABLE',
      emits: ['vuln.'],
    },
    'nmap-nse': {
      looksFor: 'nmap script output — the hostname/OS it fingerprints, SMB signing and SMBv1/EternalBlue verdicts, anonymous-FTP and SSH host-key lines, and the LDAP-named domain.',
      regex: '| <script>: … , Host is up, VULNERABLE',
      emits: ['host.hostname', 'host.fqdn', 'host.domain', 'host.os_family', 'host.os_hint', 'smb.signing', 'smb.smbv1',
        'smb.ms17_010', 'ssh.hostkey', 'ssh.banner', 'ftp.anonymous_login', 'ftp.banner', 'web.title', 'web.server',
        'web.tech', 'http.redirect', 'ad.domain_known', 'ad.base_dn'],
    },
    'http-metadata': {
      looksFor: 'an HTTP response or a whatweb/curl banner — the status line, the Server header, and the tech it reveals.',
      regex: 'HTTP/1.1 200, Server: …',
      emits: ['http.reachable', 'http.response', 'web.server', 'web.tech', 'web.title', 'http.redirect'],
    },
    'web-content': {
      looksFor: "a content-discovery tool's status/path lines (feroxbuster/gobuster/ffuf) — the 200s and 301s, and whether a page carries a form, a parameter, or an exposed file.",
      regex: '200 GET /path, 301 GET /dir',
      emits: ['web.content_map', 'web.exposed_artifact', 'web.upload_form', 'web.users', 'web.source'],
    },
    'web-params': {
      looksFor: "arjun's '[+] Parameter detected: id (GET)' lines, and reflected/dynamic parameters.",
      regex: '[+] Parameter detected: <name>',
      emits: ['web.param_candidate', 'web.parameterized'],
    },
    'web-exploit': {
      looksFor: 'a web-bug confirmation — a SQL error or boolean/timing divergence, an LFI file read, a command-injection echo, an SSTI math result, an SSRF/XXE/deserialization callback, a reflected XSS, or an accepted upload.',
      regex: 'SQL syntax; root:x:0:0; uid=…; {{7*7}}=49',
      emits: ['web.sqli_confirmed', 'web.lfi_confirmed', 'web.cmdi_confirmed', 'web.ssti_confirmed', 'web.ssrf_confirmed',
        'web.xxe_confirmed', 'web.xss_confirmed', 'web.nosqli_confirmed', 'web.deserial_confirmed', 'web.authz_bypass',
        'web.idor_candidate', 'web.jwt_secret', 'web.upload_confirmed', 'foothold.webshell', 'cloud.credential'],
    },
    'smb-shares': {
      looksFor: 'smbclient / smbmap / nxc share listings and the null-/guest-session banner that lets you read them.',
      regex: 'Disk  READ/WRITE, [+] Guest / null session',
      emits: ['smb.shares', 'smb.null_session', 'smb.guest_session', 'smb.reachable'],
    },
    'ad-ldap': {
      looksFor: 'ldapsearch / nxc --users / rid-brute output — the user and computer accounts, the named domain, and whether the bind was anonymous.',
      regex: 'sAMAccountName: …, DC=corp,DC=local',
      emits: ['ad.user_list', 'ad.domain_known', 'ad.base_dn', 'ad.anonymous_bind', 'ad.computer_list', 'ad.group_list'],
    },
    'kerberos-roast': {
      looksFor: 'GetNPUsers / GetUserSPNs output — the $krb5asrep$ and $krb5tgs$ hashes (also recognized by shape when pasted alone).',
      regex: '$krb5asrep$ / $krb5tgs$',
      emits: ['hash.asrep', 'hash.tgs'],
    },
    'secretsdump': {
      looksFor: 'secretsdump / mimikatz / pypykatz dumps — NTLM hashes, the full NTDS, the krbtgt key, cached (DCC2) hashes, Linux /etc/shadow, and any cleartext.',
      regex: 'user:rid:lm:nt:::, $DCC2$, krbtgt:502',
      emits: ['hash.ntlm', 'loot.ntds', 'hash.krbtgt', 'hash.mscache', 'credential.plaintext', 'loot.shadow'],
    },
    'cracked': {
      looksFor: "john/hashcat cracked lines — a recovered 'hash:password' pair.",
      regex: '<hash>:<password> (Cracked)',
      emits: ['credential.available', 'credential.candidate', 'credential.validated'],
    },
    'auth-validation': {
      looksFor: "nxc / evil-winrm auth results — the '[+] domain\\\\user:secret (Pwn3d!)' success and the failure lines, over SMB, WinRM, and RDP.",
      regex: '[+] …:… (Pwn3d!)',
      emits: ['credential.validation', 'credential.validated', 'credential.available', 'winrm.authenticated', 'rdp.authenticated',
        'smb.authenticated', 'ftp.authenticated', 'ssh.authenticated', 'access.admin'],
    },
    'responder': {
      looksFor: 'Responder / ntlmrelay output — a captured NetNTLMv2 hash on the wire.',
      regex: '[SMB] NTLMv2-SSP Hash : …',
      emits: ['credential.netntlm', 'hash.ntlm'],
    },
    'ad-abuse': {
      looksFor: 'BloodHound / bloodyAD / PowerView output — collected graph, attack and control paths, ACL edges (GenericAll/WriteDacl), delegation, GPO and gMSA control, and the objects you can now add or own.',
      regex: 'GenericAll, Unconstrained, has control over',
      emits: ['ad.graph.collected', 'ad.attack_paths', 'ad.control_paths', 'ad.acl_lead', 'ad.domain_control',
        'ad.gmsa', 'ad.gpo_writable', 'ad.unconstrained', 'ad.group_joined', 'ad.computer_added',
        'lateral.movement', 'ad.coerced_auth', 'ad.gpo_control', 'ad.sid_history'],
    },
    'adcs': {
      looksFor: 'certipy / pywhisker output — a `find -vulnerable` run naming ESC1-16 templates (adcs.vulnerable), a saved .pfx certificate from `req` or a shadow-credentials add (credential.certificate), and a `certipy auth` that exchanges a cert for the account’s NT hash (hash.ntlm → a usable credential).',
      regex: "ESC1, Saved certificate … to 'x.pfx', Got hash for …",
      emits: ['adcs.vulnerable', 'credential.certificate', 'hash.ntlm', 'credential.available', 'credential.ntlm_hash'],
    },
    'ad-trusts': {
      looksFor: 'domain/forest trust enumeration — nltest /domain_trusts, PowerView Get-DomainTrust, Get-ADTrust, or nxc --domain_trusts naming a trusted domain or a trust direction.',
      regex: 'Forest Tree Root, TrustDirection: …, acme.local -> child.acme.local',
      emits: ['ad.trusts'],
    },
    'zerologon': {
      looksFor: 'a Zerologon (CVE-2020-1472) scan verdict — a "Success!/vulnerable" line (and not a patched/failed one) that marks the DC exploitable.',
      regex: 'Success! … Zerologon, is vulnerable',
      emits: ['ad.zerologon'],
    },
    'http-findings': {
      looksFor: 'a web posture check — curl -I security headers (which are present vs missing), the OPTIONS Allow verbs, a reflected CORS Access-Control-Allow-Origin, a secret in a page comment or body, and a readable sensitive file (.git, .env, web.config, a private key).',
      regex: 'Strict-Transport-Security, Allow:, Access-Control-Allow-Origin:, ref: refs/heads/',
      emits: ['http.headers', 'http.methods', 'http.cors', 'http.body', 'http.exposed'],
    },
    'dns-findings': {
      looksFor: 'a DNS check — a successful AXFR zone transfer (the records and hostnames it leaks), SPF/DMARC email posture, and a dangling-CNAME subdomain-takeover fingerprint.',
      regex: 'IN SOA, v=spf1, v=DMARC1, NoSuchBucket',
      emits: ['dns.zone', 'dns.email', 'dns.takeover'],
    },
    'vhost': {
      looksFor: 'virtual-host discovery output — an ffuf/gobuster vhost result where a Host header returns a real, differently-sized page.',
      regex: 'Found: admin.acme.internal, [Status: 200]',
      emits: ['web.vhost'],
    },
    'tls-config': {
      looksFor: 'a TLS scan (sslscan / testssl / nmap ssl-enum-ciphers) — weak protocols (SSLv3, TLS 1.0/1.1), weak ciphers (RC4, 3DES, EXPORT), Heartbleed, and certificate problems.',
      regex: 'SSLv3 enabled, RC4 accepted, Heartbleed, self-signed',
      emits: ['tls.info'],
    },
    'host-privesc': {
      looksFor: "a privilege-escalation sweep on the host — winPEAS/linPEAS leads, sudo -l rights, SUID binaries, capabilities, writable cron/paths, docker/lxd groups, unquoted service paths, dangerous tokens, missing patches, stored app credentials (PuTTY/WinSCP/VNC), AV/AppLocker posture, notable programs, and a reachable desktop.",
      regex: 'NOPASSWD, SeImpersonatePrivilege, -rwsr-xr-x',
      emits: ['privesc.', 'config.review', 'defense.control', 'host.notable_program', 'host.arch', 'access.desktop',
        'host.os_family', 'credential.candidate'],
    },
    'flags': {
      looksFor: 'an on-host flag read — a clean flag token on its own line from a `type`/`cat …proof.txt`, or a ===FLAG marker, tied to its slot.',
      regex: '===FLAG:path::value / lone flag token',
      emits: ['objective.'],
    },
    'database': {
      looksFor: "a database session's output — a version/current-user banner or engine prompt that proves the login (db.session), listed databases and tables, and dumped credential rows.",
      regex: 'mysql>, SQL>, List of databases, Server version:',
      emits: ['db.session', 'db.creds', 'db.databases', 'db.tables', 'loot.material', 'credential.candidate', 'foothold.windows'],
    },
    'snmp': {
      looksFor: 'snmpwalk / snmp-check output — the community string that worked, running processes and users, and any credentials in the MIB.',
      regex: 'SNMPv2-MIB::…, community "public"',
      emits: ['snmp.info', 'snmp.community', 'snmp.reachable', 'ad.user_list', 'credential.candidate', 'host.hostname'],
    },
    'banners': {
      looksFor: 'a bare service banner — an SSH version string or an FTP 220/230 line — pasted without the scan around it.',
      regex: 'SSH-2.0-…, 220 (vsFTPd …)',
      emits: ['ssh.banner', 'ssh.reachable', 'ftp.banner', 'ftp.reachable', 'ftp.anonymous_login'],
    },
    'websource': {
      looksFor: 'secrets inside a response or source — a config/.env value, a PEM private key, a JWT secret, a VCS token or connection URI, an exposed artifact.',
      regex: 'BEGIN PRIVATE KEY, DB_PASSWORD=…, ghp_…',
      emits: ['web.source', 'web.jwt_secret', 'credential.plaintext', 'web.exposed_artifact'],
    },
    'shell-exec': {
      looksFor: "a caught shell or a command's result — an `id`/`whoami`/`uname` that proves you are executing on the box, as a user or as root/SYSTEM.",
      regex: 'uid=0(root), nt authority\\system',
      emits: ['access.shell', 'foothold.linux', 'foothold.windows', 'access.system', 'host.os_family', 'host.kernel'],
    },
    'auth-blocker': {
      looksFor: "a credential that is valid but refused for a fixable reason — a forced password change (STATUS_PASSWORD_MUST_CHANGE / expired), Kerberos clock skew (KRB_AP_ERR_SKEW), NTLM disabled (STATUS_NOT_SUPPORTED → use -k), account lockout (STATUS_ACCOUNT_LOCKED_OUT) or a disabled/restricted account.",
      regex: 'STATUS_PASSWORD_MUST_CHANGE | password has expired | KRB_AP_ERR_SKEW | clock skew too great | STATUS_NOT_SUPPORTED | STATUS_ACCOUNT_LOCKED_OUT | STATUS_ACCOUNT_DISABLED | STATUS_LOGON_TYPE_NOT_GRANTED',
      emits: ['blocker.password_change', 'blocker.clock_skew', 'blocker.ntlm_disabled', 'blocker.lockout', 'blocker.account_restricted'],
    },
    'op-blocker': {
      looksFor: "a classic operational wall from a pasted error — nmap 'host seems down' (needs -Pn), 'could not resolve host' (needs /etc/hosts), a CRLF 'bad interpreter', 'sudo: no tty present', Defender/AMSI blocking a payload, a SeImpersonate potato that failed, HTTP fuzzing rate-limited (429), or an http/https scheme mismatch (WRONG_VERSION_NUMBER).",
      regex: 'Host seems down | Could not resolve host | bad interpreter | no tty present | contains malicious content | the handle is invalid | 429 Too Many Requests | WRONG_VERSION_NUMBER',
      emits: ['blocker.host_down', 'blocker.name_resolution', 'blocker.crlf', 'blocker.no_tty', 'blocker.amsi', 'blocker.potato', 'blocker.rate_limited', 'blocker.tls_scheme', 'blocker.hash_format', 'blocker.egress_blocked', 'blocker.smb_signing', 'blocker.kerberos_spn', 'blocker.responder_quiet', 'blocker.web_wildcard', 'blocker.hashcat_env'],
    },
    'ssh-key-rejected': {
      looksFor: "an SSH key login that failed, and why — unprotected key perms, a passphrase prompt, the OpenSSH 8.8+ ssh-rsa block (no mutual signature algorithm), an invalid key format, or a bare \"Permission denied (publickey)\" (often target-side StrictModes).",
      regex: 'UNPROTECTED PRIVATE KEY FILE | permissions are too open | no mutual signature algorithm | enter passphrase for key | Load key …: invalid format | Permission denied (publickey)',
      emits: ['ssh.key_rejected'],
    },
    'files': {
      looksFor: 'a file or directory listing — an FTP/rsync/SMB-spider listing or a loot hunt, naming files worth taking (configs, backups, keys).',
      regex: '-rw-r--r-- … file, drwxr-xr-x … dir',
      emits: ['loot.files', 'loot.material'],
    },
    'klist': {
      looksFor: 'klist ticket-cache output — the Kerberos tickets currently held, for pass-the-ticket / reuse.',
      regex: 'Ticket cache: … , krbtgt/REALM',
      emits: ['kerberos.tickets'],
    },
    'vuln-scan': {
      looksFor: 'a wpscan/nikto/wesng finding that names a specific vulnerable component, plugin, or CVE to chase.',
      regex: '[+] CVE-…, vulnerable version …',
      emits: ['exploit.candidate'],
    },
    'sccm': {
      looksFor: 'SharpSCCM / sccmhunter output — a management point, a network-access-account credential, or a site code.',
      regex: 'Management Point: …, NAA credential',
      emits: ['sccm.enumerated'],
    },
    'internal-dns': {
      looksFor: "a dig / nslookup / host query or an AXFR zone transfer aimed at the foothold's internal resolver — the domain it serves (SOA/NS), the DCs it advertises (_ldap._tcp / _kerberos._tcp SRV, or the NS/SOA host resolved to an address), and the A records a successful transfer dumped.",
      regex: 'IN SOA|IN NS|_ldap._tcp…SRV … <dc>|service = 0 100 389 <dc>|<name> IN A <ip>|<name> has address <ip>',
      emits: ['ad.domain_known', 'ad.dc_candidate', 'dns.zone'],
    },
    'connectivity': {
      looksFor: "a foothold's own interface / route dump (ip a, ifconfig, ipconfig, ip route, route print) — the subnets it sits on, and whether it is a dual-homed pivot; its ARP/neighbour cache (ip neigh, arp -a) for adjacent hosts, its listening services (netstat -ano, ss -tlnp) and its internal resolvers (resolv.conf, DNS Servers); and a pivot tool's setup or status output that confirms a live tunnel (chisel R:socks, ssh -D, ligolo agent-joined, sshuttle connected, dnscat2 session).",
      regex: 'inet <ip>/<pfx> | Subnet Mask | <net>/<pfx> dev|via | <ip> ... lladdr|dynamic | LISTENING | nameserver <ip> | Agent joined | R:socks | Connected to server',
      emits: ['scan.local.interfaces', 'scan.local.routes', 'scan.local.neighbors', 'scan.local.listeners', 'scan.local.dns', 'host.multihomed', 'tunnel.socks', 'tunnel.route', 'tunnel.dns'],
    },
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
