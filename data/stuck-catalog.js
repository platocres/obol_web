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
 * COVERAGE NOTE: this is the first authored sample (Recon + Web lanes) for voice sanction. The
 * remaining lanes (SMB/AD, creds, Linux privesc, Windows privesc, database, pivot, ...) are authored
 * in follow-up commits to match the approved voice.
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
    'scan.nmap.udp': { group: 'Recon', label: 'I Scanned UDP Ports', help: 'You checked UDP too, not just TCP (SNMP, DNS, TFTP live there).' },
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
  };

  OBOL.STUCK_CATALOG = CATALOG;
})(typeof globalThis !== 'undefined' ? globalThis : this);
