/*!
 * obol data — coverage-expected.js — OBOL.COVERAGE_EXPECTED
 *
 * The per-port EXPECTED-COVERAGE oracle: for each by-port Evidence card, the techniques an OSCP operator
 * would expect to find, each mapped to the move id(s) that represent it. This is the ONLY place a human
 * "ideal" is written down, and it is deliberately NOT a drawn tree — just a checklist (see
 * docs/DECISION-MAP.md). The decision map / gap report diffs the derived per-port moves against this
 * list: a technique whose `moves` are all absent is a COVERAGE GAP (a technique we should teach but no
 * move represents). `moves: []` is how you record a known-missing technique on purpose, so it shows up
 * red until someone adds the move — then it clears itself. Keep entries honest: only list a move id here
 * if that move genuinely covers the technique.
 *
 * Keyed by Evidence card key: the open-port cards (p21, p80, …) AND the post-foothold access cards
 * (shell-linux, shell-windows, domain-cred, pivot, proof), so the oracle is a full OSCP exam-readiness
 * checklist, not just a per-service one. Each access-card entry lists the privilege-escalation, AD, or
 * pivoting techniques the exam expects, mapped to the move that teaches it; a `moves: []` entry is a
 * technique deliberately on the radar that no module teaches yet (it shows red until a move is added).
 *
 * DELIBERATELY OUT OF SCOPE (not listed as gaps, so they never show red): stack buffer overflow was
 * retired from the OSCP exam in 2020; client-side / phishing attacks are not part of the standalone or
 * AD-set objectives. The current exam is 3 standalone hosts (foothold + root, 20 pts each) plus a
 * 40-pt AD set (2 clients + 1 DC) reached by pivoting, which is the shape this oracle models.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.COVERAGE_EXPECTED = {
    p21: { label: 'FTP', expect: [
      { name: 'Anonymous login + read', moves: ['recon-ftp'] },
      { name: 'Credential brute-force', moves: ['online-brute-ftp'] },
      { name: 'Write-to-webroot → RCE', moves: ['ftp-upload-webshell'] },
      { name: 'FTP bounce scan (FXP)', moves: ['ftp-bounce'], note: 'nmap -b / bounce-scan an internal host via an open FTP relay' },
    ] },
    p22: { label: 'SSH', expect: [
      { name: 'Key-based login from a looted key', moves: ['ssh-key-login'] },
      { name: 'Password brute-force', moves: ['online-brute-ssh'] },
      { name: 'Pivot (dynamic / sshuttle)', moves: ['pivot-ssh-dynamic', 'pivot-sshuttle'] },
      { name: 'User enum (CVE-2018-15473, old OpenSSH)', moves: ['ssh-user-enum'], note: 'timing-based username enumeration on pre-7.7 OpenSSH' },
    ] },
    p23: { label: 'Telnet', expect: [
      { name: 'Banner + default/weak login', moves: ['recon-telnet'] },
      { name: 'Credential reuse', moves: ['recon-telnet'] },
    ] },
    p25: { label: 'SMTP / mail', expect: [
      { name: 'User enumeration (VRFY/EXPN/RCPT)', moves: ['recon-smtp'] },
      { name: 'Read the mailbox with a credential', moves: ['recon-mail'] },
      { name: 'Open-relay test', moves: ['smtp-open-relay'], note: 'confirm the server relays mail for arbitrary senders' },
    ] },
    p53: { label: 'DNS', expect: [
      { name: 'Zone transfer (AXFR)', moves: ['recon-dns'] },
      { name: 'Subdomain / record enumeration', moves: ['recon-dns'] },
    ] },
    p69: { label: 'TFTP', expect: [
      { name: 'Fetch device config files by name', moves: ['recon-tftp'] },
    ] },
    p80: { label: 'HTTP / HTTPS', expect: [
      { name: 'Stack fingerprint / triage', moves: ['recon-web-triage', 'check-web-components', 'check-cms-version'] },
      { name: 'Virtual-host discovery', moves: ['vhost-discovery'] },
      { name: 'Content / directory discovery', moves: ['content-discovery'] },
      { name: 'Parameter discovery', moves: ['param-discovery'] },
      { name: 'SQL injection (manual + sqlmap)', moves: ['sqli-basics', 'manual-sqli-exploitation', 'sqlmap-automation'] },
      { name: 'File upload → shell', moves: ['file-upload', 'web-shells'] },
      { name: 'LFI / RFI', moves: ['lfi-probe'] },
      { name: 'Command injection', moves: ['command-injection'] },
      { name: 'SSTI', moves: ['ssti'] },
      { name: 'SSRF / XXE / deserialization', moves: ['ssrf', 'xxe', 'deserialization'] },
      { name: 'Auth bypass / IDOR / JWT', moves: ['idor', 'jwt-attacks', 'verb-tampering'] },
      { name: 'Source exposure (.git/.svn)', moves: ['git-exposed', 'svn-exposed'] },
      { name: 'Known app CVEs (Log4Shell/Struts)', moves: ['check-log4shell', 'check-struts2'] },
      { name: 'Cloud metadata SSRF to IAM abuse', moves: ['aws-credential-abuse'], note: 'turn stolen IMDS keys into S3/Secrets/SSM access (beyond OSCP, common in practice)' },
      { name: 'Azure IMDS SSRF to managed-identity token', moves: ['azure-imds'], note: 'the Azure twin of the AWS metadata path: resource-scoped token, Metadata header, Key Vault loot (beyond OSCP)' },
      { name: 'GraphQL introspection + broken authorization', moves: ['graphql-abuse'], note: 'one URL fronting the data model: per-resolver authz and batching abuse (beyond OSCP, common in modern apps)' },
      { name: 'GCP metadata SSRF to service-account token', moves: ['gcp-metadata'], note: 'the GCP twin: Metadata-Flavor header, OAuth token at computeMetadata/v1 (beyond OSCP)' },
      { name: 'HTTP request smuggling (CL.TE / TE.CL)', moves: ['http-request-smuggling'], note: 'desync a front-end/back-end pair to poison or hijack requests (beyond OSCP)' },
      { name: 'Prototype pollution to RCE/authz bypass', moves: ['prototype-pollution'], note: 'Node/JS __proto__ pollution chaining to a gadget (beyond OSCP)' },
      { name: 'Mass assignment / autobinding', moves: ['mass-assignment'], note: 'set a privileged field (role, isAdmin) the binder exposes (beyond OSCP)' },
      { name: 'Local file read → secrets', moves: ['lfi-secret-harvest'], note: 'turn a confirmed LFI into credentials, keys, and source via the filter wrapper' },
    ] },
    p88: { label: 'Kerberos / DC', expect: [
      { name: 'Identify the DC + domain', moves: ['ad-dc-identify'] },
      { name: 'User enumeration', moves: ['ad-user-enum'] },
      { name: 'AS-REP roasting', moves: ['asrep-roast', 'crack-asrep'] },
      { name: 'Kerberoasting', moves: ['kerberoast', 'crack-tgs'] },
      { name: 'Ticket reuse / pass-the-ticket', moves: ['kerberos-tickets', 'ticket-reuse'] },
    ] },
    p135: { label: 'SMB / RPC', expect: [
      { name: 'Anonymous / null-session enum', moves: ['recon-smb-anon'] },
      { name: 'Share inventory + spider', moves: ['smb-share-inventory'] },
      { name: 'GPP cpassword in SYSVOL', moves: ['gpp-passwords'] },
      { name: 'EternalBlue (MS17-010)', moves: ['eternalblue'] },
      { name: 'NTLM poisoning / relay', moves: ['responder-poison', 'ntlm-relay-attack', 'mitm6-ipv6-takeover'] },
      { name: 'Coerce auth (PetitPotam/PrinterBug)', moves: ['coerce-auth'] },
      { name: 'Lateral exec (psexec/wmiexec)', moves: ['lateral-exec'] },
    ] },
    p389: { label: 'LDAP', expect: [
      { name: 'Anonymous bind enumeration', moves: ['ad-anon-ldap-enum'] },
      { name: 'BloodHound collection', moves: ['bloodhound-collect'] },
      { name: 'LAPS / gMSA read', moves: ['laps-read', 'gmsa-read'] },
      { name: 'AD CS template abuse (ESC1-8)', moves: ['adcs-esc', 'cert-authenticate'] },
    ] },
    p1433: { label: 'MSSQL', expect: [
      { name: 'Login (sa / domain / reused)', moves: ['mssql-login'] },
      { name: 'xp_cmdshell OS execution', moves: ['mssql-xp-cmdshell'] },
      { name: 'Linked-server / impersonation hop', moves: ['mssql-linked-server'], note: 'EXECUTE AS / linked-server chaining to another instance' },
    ] },
    p1521: { label: 'Oracle TNS', expect: [
      { name: 'SID brute + default accounts', moves: ['oracle-tns'] },
      { name: 'File read/write + RCE via odat', moves: ['oracle-tns'] },
    ] },
    p3306: { label: 'MySQL', expect: [
      { name: 'Login + schema/user enum', moves: ['mysql-login'] },
      { name: 'Credential-table sweep', moves: ['mysql-loot'] },
      { name: 'UDF / INTO OUTFILE to webroot', moves: ['mysql-outfile-rce'], note: 'write a shell via INTO OUTFILE, or RCE via a UDF when FILE priv is held' },
    ] },
    p9200: { label: 'Elasticsearch', expect: [
      { name: 'Unauthenticated index dump', moves: ['elasticsearch-enum'] },
      { name: 'Scripting-engine RCE (old versions)', moves: ['elasticsearch-enum'] },
    ] },
    p11211: { label: 'Memcached', expect: [
      { name: 'Dump cached keys/values', moves: ['memcached-enum'] },
    ] },
    p8009: { label: 'AJP (Tomcat)', expect: [
      { name: 'Ghostcat file read / inclusion', moves: ['ajp-ghostcat'] },
    ] },
    p1099: { label: 'Java RMI', expect: [
      { name: 'Registry enumeration', moves: ['java-rmi'] },
      { name: 'Deserialization RCE', moves: ['java-rmi'] },
    ] },

    // ---- post-foothold exam axes (keyed by the access cards) ----
    'shell-linux': { label: 'Linux privilege escalation', expect: [
      { name: 'Baseline enumeration (linpeas / manual)', moves: ['linux-enum'] },
      { name: 'Sudo rights abuse (GTFOBins)', moves: ['sudo-abuse'] },
      { name: 'SUID binaries (GTFOBins)', moves: ['suid-gtfobins'] },
      { name: 'Linux capabilities', moves: ['capabilities'] },
      { name: 'Cron jobs / writable scripts', moves: ['cron-abuse'] },
      { name: 'Writable /etc/passwd or /etc/shadow', moves: ['writable-passwd'] },
      { name: 'NFS no_root_squash', moves: ['nfs-squash'] },
      { name: 'Docker / LXD group escape', moves: ['docker-socket', 'lxc-lxd-escape'] },
      { name: 'Hidden processes (pspy)', moves: ['pspy-monitor'] },
      { name: 'Kernel / exploit-suggester (DirtyPipe, pwnkit)', moves: ['linux-kernel-exploit'], note: 'match a public LPE to the exact kernel as a last resort' },
      { name: 'PATH hijack in a SUID/cron script', moves: ['linux-path-hijack'], note: 'hijack a relative-binary call in a privileged SUID/cron' },
      { name: 'LD_PRELOAD / LD_LIBRARY_PATH via sudo env_keep', moves: ['linux-ld-preload'], note: 'library-injection through a preserved sudo environment' },
      { name: 'Wildcard injection in a privileged command', moves: ['wildcard-injection'], note: 'flag-named files a root tar/chown/rsync expands in a writable directory (beyond OSCP, classic lab root)' },
      { name: 'Writable systemd unit / timer', moves: ['systemd-timer-abuse'], note: 'the systemd-era cron abuse: a root unit file or ExecStart target you can write (beyond OSCP)' },
      { name: 'Polkit / D-Bus privileged-action abuse', moves: ['polkit-abuse'], note: 'PwnKit (CVE-2021-4034) or a loosely-policed D-Bus action (beyond OSCP)' },
      { name: 'Python / library path hijack (writable module)', moves: ['python-library-hijack'], note: 'a root script importing from a writable sys.path entry (beyond OSCP)' },
      { name: 'Container / Kubernetes breakout', moves: ['container-escape'], note: 'a privileged pod, mounted docker socket, or service-account token escaping to the node (beyond OSCP)' },
    ] },
    'shell-windows': { label: 'Windows privilege escalation', expect: [
      { name: 'Baseline enumeration (winPEAS / manual)', moves: ['windows-enum'] },
      { name: 'SeImpersonate token abuse (Potato family)', moves: ['seimpersonate'] },
      { name: 'Unquoted service path', moves: ['unquoted-service-path'] },
      { name: 'Weak service permissions', moves: ['weak-service-permissions'] },
      { name: 'AlwaysInstallElevated', moves: ['alwaysinstallelevated'] },
      { name: 'Stored credentials (Credential Manager / registry)', moves: ['stored-credentials'] },
      { name: 'windows.old / registry hive secrets', moves: ['windows-old-hives'] },
      { name: 'DPAPI-protected secrets', moves: ['dpapi-secrets'] },
      { name: 'LSASS memory dump', moves: ['lsass-dump-onbox'] },
      { name: 'Missing patches (wesng)', moves: ['wesng-patch-gaps'] },
      { name: 'Patch-gap / kernel CVE exploitation', moves: ['windows-patch-exploit'], note: 'run the public LPE a missing KB flags, Windows parallel of the Linux kernel path' },
      { name: 'Defensive posture (AV / AppLocker / CLM)', moves: ['defense-enum'] },
      { name: 'DLL search-order hijack', moves: ['windows-dll-hijack'], note: 'writable-path or phantom DLL hijack of a privileged process' },
      { name: 'Writable scheduled-task binary', moves: ['windows-schtask-abuse'], note: 'a SYSTEM scheduled task that runs a path you can overwrite' },
      { name: 'UAC bypass (filtered admin to high integrity)', moves: ['uac-bypass'], note: 'un-filter an existing admin token via an auto-elevating binary (beyond OSCP)' },
      { name: 'COM hijack (writable CLSID)', moves: ['com-hijack'], note: 'redirect a CLSID a privileged process loads to your DLL; also persistence (beyond OSCP)' },
      { name: 'Named-pipe impersonation', moves: ['windows-namedpipe-impersonation'], note: 'coerce a privileged client onto a pipe you own, impersonate its token to SYSTEM (the primitive behind the Potato family, beyond OSCP)' },
      { name: 'Service DACL abuse (SERVICE_CHANGE_CONFIG)', moves: ['windows-service-dacl-abuse'], note: 'reconfigure a service binpath/account via SERVICE_CHANGE_CONFIG, a weak DACL short of full write (beyond OSCP)' },
    ] },
    'domain-cred': { label: 'Active Directory to Domain Admin', expect: [
      { name: 'Graph recon (BloodHound)', moves: ['bloodhound-collect', 'ad-path-manual'] },
      { name: 'Kerberoasting (with a credential)', moves: ['kerberoast'] },
      { name: 'ACL abuse (GenericAll / WriteDACL)', moves: ['ad-acl-abuse', 'bloodyad-acl'] },
      { name: 'Delegation abuse (unconstrained / constrained / RBCD)', moves: ['unconstrained-delegation', 'delegation-abuse', 'getst-impersonation'] },
      { name: 'AD CS template abuse (ESC1-8)', moves: ['adcs-esc', 'cert-authenticate'] },
      { name: 'Shadow credentials (msDS-KeyCredentialLink)', moves: ['shadow-credentials'] },
      { name: 'LAPS / gMSA password read', moves: ['laps-read', 'gmsa-read'] },
      { name: 'DCSync', moves: ['dcsync'] },
      { name: 'Ticket forging (golden / silver / diamond)', moves: ['golden-ticket', 'silver-ticket', 'diamond-ticket'] },
      { name: 'Cross-domain (trusts / SID history)', moves: ['trust-enum', 'sid-history-abuse'] },
      { name: 'Critical CVEs (Zerologon / NoPac / PrintNightmare / MS14-068)', moves: ['zerologon-exploit', 'nopac', 'printnightmare', 'ms14-068'] },
      { name: 'Policy / service abuse (GPO / DNSAdmins / WSUS / SCCM)', moves: ['gpo-abuse', 'dnsadmins-abuse', 'wsus-abuse', 'sccm-enum', 'sccm-exploit'] },
      { name: 'Domain takeover with the owned hash (PtH as DA)', moves: ['own-domain-pth'] },
      { name: 'Certifried (CVE-2022-26923) machine-account to DA', moves: ['certifried'], note: 'AD CS plus MachineAccountQuota turns any user into a DC certificate (beyond OSCP)' },
      { name: 'Kerberos relay (AuthIP / DNS)', moves: ['kerberos-relay'], note: 'relay coerced Kerberos to LDAP/AD CS for RBCD or a certificate; survives SMB signing (beyond OSCP)' },
      { name: 'Timeroasting', moves: ['timeroasting'], note: 'NTP-signed computer-account hashes cracked offline, no credential needed (beyond OSCP)' },
      { name: 'ADIDNS record abuse', moves: ['adidns-abuse'], note: 'write an AD-integrated DNS record (wildcard / WPAD) to capture auth or anchor a relay (beyond OSCP)' },
    ] },
    'pivot': { label: 'Pivoting into the internal network', expect: [
      { name: 'Map the foothold interfaces / routes / neighbors', moves: ['local-linux-interfaces', 'local-windows-interfaces'] },
      { name: 'Stand up a tunnel (chisel / ligolo / sshuttle / ssh)', moves: ['pivot-chisel-socks', 'pivot-ligolo', 'pivot-sshuttle', 'pivot-ssh-dynamic'] },
      { name: 'Scan and attack through the tunnel', moves: ['pivot-scan-through'] },
      { name: 'DNS tunnel for egress-restricted hosts', moves: ['dns-tunnel'], note: 'dnscat2 / iodine when only DNS resolves outbound (beyond OSCP, the egress escape hatch)' },
      { name: 'SSH local / remote port forwarding (-L / -R)', moves: ['pivot-ssh-portforward'], note: 'single-port forwards distinct from a dynamic SOCKS pivot, when you need one internal service not the whole subnet' },
    ] },
    'proof': { label: 'Proof capture & documentation', expect: [
      { name: 'Capture user + root/proof flags', moves: ['flag-hunt-linux', 'flag-hunt-windows'] },
      { name: 'Screenshot with identity + IP visible', moves: ['flag-hunt-linux', 'flag-hunt-windows'] },
    ] },
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
