/*!
 * obol data — decision-forks.js — OBOL.DECISION_FORKS
 *
 * The one-line fork CONDITION per move, for the decision map (see docs/DECISION-MAP.md). The map derives
 * the tree STRUCTURE and the ranked spine from the engine; this file adds only the short, authored
 * sentence that labels the branch point — the observable question whose answer decides where you go:
 *   { '<moveId>': { cond: 'the yes/no the result turns on', onFail: 'what to do if it does not pan out' } }
 * `cond` renders on the node as "does X? → branch"; `onFail` is the authored hint for the "it didn't work"
 * edge (the map already derives the alternatives from alternativesFor, so onFail is just the human nudge).
 * Keep both to one plain sentence. A move with no entry still renders (structure + alternatives are
 * derived) — the lint simply reports it as a fork-condition gap, so coverage is visible and fillable.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.DECISION_FORKS = {
    // ---- recon / services ----
    'recon-ftp': { cond: 'Does anonymous login succeed, and is anything readable?', onFail: 'No anonymous access → brute a known user, or move on.' },
    'ftp-upload-webshell': { cond: 'Is the writable FTP directory also the web root (marker round-trips over HTTP)?', onFail: 'No overlap → the write is just loot, not a shell.' },
    'ftp-bounce': { cond: 'Does the FTP server accept the PORT command (200) to an internal host?', onFail: 'PORT blocked (500) → no bounce; find another route to the segment.' },
    'online-brute-ftp': { cond: 'Does any credential pair log in?', onFail: 'No hit → the account/wordlist is wrong; find usernames first.' },
    'recon-telnet': { cond: 'Does the banner name a device, and does a default/reused password log in?', onFail: 'No default works → brute a small list, or treat it as recon only.' },
    'recon-rservices': { cond: 'Does the host trust you for a password-free rlogin/rsh?', onFail: 'No trust → there is nothing to brute; move on.' },
    'recon-rsync': { cond: 'Are any modules listable, and is one writable?', onFail: 'Auth required → try a known credential, else move on.' },
    'recon-tftp': { cond: 'Does a guessed device-config filename come back?', onFail: 'Wrong names → try device-specific paths, or move on.' },
    'recon-x11': { cond: 'Is access control off (any client accepted)?', onFail: 'Cookie required → you cannot drive the display.' },
    'recon-smtp': { cond: 'Does the server confirm usernames (VRFY/EXPN/RCPT)?', onFail: 'Verbs disabled → enumerate users another way.' },
    'smtp-open-relay': { cond: 'Does it accept a MAIL FROM and RCPT TO that are both external (250)?', onFail: 'Refused with 550 → the relay is locked; record it and try user enumeration.' },
    'recon-mail': { cond: 'Do you hold a mailbox credential to read the inbox?', onFail: 'No credential yet → recover one first.' },
    'recon-dns': { cond: 'Does a zone transfer (AXFR) succeed?', onFail: 'Refused → fall back to record/subdomain enumeration.' },
    'recon-snmp': { cond: 'Does a default community string ("public") read the MIB?', onFail: 'No default → brute community strings, or move on.' },
    'recon-finger': { cond: 'Does the service disclose usernames?', onFail: 'Empty → no spray material here.' },
    'recon-vnc': { cond: 'Is the security type "None" (unauthenticated)?', onFail: 'Password required → crack the short VNC password.' },
    'rdp-enum': { cond: 'Does a held credential actually log in (Pwn3d!)?', onFail: 'No credential logs in → recover or crack one first.' },
    'nfs-enum': { cond: 'Is an export readable, and is no_root_squash set?', onFail: 'Nothing exported to you → move on.' },
    'recon-web-triage': { cond: 'What stack/app is this (so your attacks and wordlists match)?', onFail: 'Boring default page → fuzz for virtual hosts and hidden content.' },
    'oracle-tns': { cond: 'Do you have a SID and a working account?', onFail: 'No SID or no default account → brute harder, or move on.' },
    'elasticsearch-enum': { cond: 'Is the API unauthenticated (indices list)?', onFail: 'Auth required → find a credential; note the version for RCE.' },
    'memcached-enum': { cond: 'Are there cached items worth reading?', onFail: 'Empty cache → nothing to take here.' },
    'ajp-ghostcat': { cond: 'Is the Tomcat version pre-patch, and can you reach a file to include?', onFail: 'Patched → file read only, or nothing.' },
    'java-rmi': { cond: 'Does the registry deserialize attacker objects (rmg: Vulnerable)?', onFail: 'Not vulnerable → enumerate bound methods for another way.' },

    // ---- web ----
    'vhost-discovery': { cond: 'Does a Host value return a differently-sized, real site?', onFail: 'Only the default size → no hidden vhosts; work the main site.' },
    'content-discovery': { cond: 'Did discovery turn up an admin panel, upload, backup, or source?', onFail: 'Nothing interesting → add extensions and a bigger wordlist.' },
    'graphql-abuse': { cond: 'Does introspection return the schema, and does a privileged query/mutation run unauthenticated?', onFail: 'Introspection off and authorization enforced → test resolver arguments for injection instead.' },
    'param-discovery': { cond: 'Is there a hidden parameter that feeds the page?', onFail: 'No parameters → look for a different injectable surface.' },
    'sqli-basics': { cond: 'Does a single quote change the response (error/boolean/timing)?', onFail: 'No reaction → the parameter is not injectable here.' },
    'manual-sqli-exploitation': { cond: 'Can you read data (UNION reflects, or blind oracle responds)?', onFail: 'Locked down → try a different injection type or parameter.' },
    'file-upload': { cond: 'Does a filter bypass land a file that executes?', onFail: 'Every trick rejected → the upload may still feed LFI/XXE instead.' },
    'lfi-probe': { cond: 'Does a traversal payload read a known file?', onFail: 'No traversal → test wrappers, or a different parameter.' },
    'lfi-secret-harvest': { cond: 'Do the readable files hold a credential, key, or hash you can use?', onFail: 'Nothing reusable yet → try the filter wrapper for source, or log poisoning for RCE.' },
    'command-injection': { cond: 'Does an injected command run (echo / sleep / callback)?', onFail: 'No execution → the input is sanitised; try another sink.' },
    'ssti': { cond: 'Does a template expression evaluate (e.g. {{7*7}}=49)?', onFail: 'Rendered literally → not template injection.' },
    'web-shells': { cond: 'Does the planted shell return command output?', onFail: 'No execution → the drop point is not served as code.' },
    'tomcat-deploy': { cond: 'Do the manager credentials deploy a WAR?', onFail: 'No manager access → try Ghostcat on 8009, or default creds.' },
    'jenkins-access': { cond: 'Can you reach the script console or a build step?', onFail: 'Locked down → check for the unauth CLI file-read.' },

    // ---- AD / domain ----
    'ad-dc-identify': { cond: 'Is this a DC, and what is the domain name?', onFail: 'Not a DC → treat it as a normal host.' },
    'ad-anon-ldap-enum': { cond: 'Does an anonymous bind list the directory?', onFail: 'Bind refused → you need a credential first.' },
    'ad-user-enum': { cond: 'Can you build a real user list (RID-brute / --users)?', onFail: 'No list → try anonymous SMB/LDAP, or kerbrute.' },
    'asrep-roast': { cond: 'Does any account have pre-auth disabled (roastable)?', onFail: 'None roastable → spray a seasonal password instead.' },
    'kerberoast': { cond: 'Are there service accounts with SPNs to roast?', onFail: 'No SPNs / no creds → get a credential first.' },
    'password-spray': { cond: 'Does one password hit any account (watch lockout)?', onFail: 'No hit → refine the policy-aware password set.' },
    'bloodhound-collect': { cond: 'Did collection return a graph with attack paths?', onFail: 'Collection failed → check creds/DNS and retry a method.' },
    'ad-acl-abuse': { cond: 'Do you hold an ACL edge (GenericAll/WriteDacl) to abuse?', onFail: 'No edge → map more of the graph first.' },
    'adcs-esc': { cond: 'Is a certificate template vulnerable (ESC1-8)?', onFail: 'No vulnerable template → another path to privilege.' },
    'certifried': { cond: 'Is AD CS present and MachineAccountQuota non-zero?', onFail: 'Quota 0 or no CA → Certifried is closed; try a vulnerable template or roasting.' },
    'dcsync': { cond: 'Do you hold replication rights (DS-Replication-Get-Changes)?', onFail: 'Not yet → walk an ACL/delegation path to earn them.' },
    'eternalblue': { cond: 'Is the host confirmed MS17-010 vulnerable?', onFail: 'Patched / not vulnerable → do not fire; find another way.' },

    // ---- databases ----
    'mysql-login': { cond: 'Does a credential (or blank root) open a session?', onFail: 'No login → brute, or recover a credential elsewhere.' },
    'mysql-loot': { cond: 'Do the tables hold crackable hashes or reused secrets?', onFail: 'Nothing useful → the DB was a dead end.' },
    'mysql-outfile-rce': { cond: 'Do you hold FILE privilege with a writable web root (secure_file_priv empty)?', onFail: 'No FILE write → try the UDF route, or just loot the tables.' },
    'mssql-login': { cond: 'Does sa / a domain account log in?', onFail: 'No login → recover a credential first.' },
    'mssql-xp-cmdshell': { cond: 'Does the account have sysadmin to enable xp_cmdshell?', onFail: 'Not sysadmin → impersonate or chain a linked server.' },
    'mssql-linked-server': { cond: 'Is there a linked server, and is your link login sysadmin on it?', onFail: 'No usable link → impersonate a higher login locally, or loot instead.' },
    'postgres-login': { cond: 'Does a default/reused role log in?', onFail: 'No login → brute, or move on.' },
    'redis-enum': { cond: 'Is Redis unauthenticated, and is it writable?', onFail: 'AUTH set → find the password, else read-only at best.' },
    'mongo-enum': { cond: 'Can you list and read databases without auth?', onFail: 'Auth required → recover a credential first.' },

    // ---- creds / cracking ----
    'crack-identify': { cond: 'What hash type is this (so you pick the right mode)?', onFail: 'Unknown format → inspect length/prefix by hand.' },
    'crack-ntlm': { cond: 'Does the NT hash crack to a password in time?', onFail: 'Uncracked → pass the hash instead of cracking it.' },
    'crack-asrep': { cond: 'Does the AS-REP hash crack offline?', onFail: 'Uncracked → spray or roast another account.' },
    'online-brute-ssh': { cond: 'Does any credential pair log in over SSH?', onFail: 'No hit → wrong account; find usernames first.' },
    'ssh-user-enum': { cond: 'Is the OpenSSH banner before 7.7 (usernames enumerable)?', onFail: '7.7 or newer → the leak is closed; spray a small list blind or move on.' },
    'online-brute-rdp': { cond: 'Does any credential pair open an RDP session?', onFail: 'No hit → watch for lockout; narrow the list.' },

    // ---- shells / foothold ----
    'shell-listener': { cond: 'Is your listener up and reachable from the target?', onFail: 'No callback → check firewall/port and the reverse-shell one-liner.' },
    'shell-revshell-linux': { cond: 'Did the reverse shell connect back?', onFail: 'No connection → try another shell payload or transport.' },
    'shell-pty-upgrade': { cond: 'Is the shell now a full interactive TTY?', onFail: 'Still raw → try the python/script upgrade, then stty.' },
    'ssh-key-login': { cond: 'Does the recovered private key log in?', onFail: 'Rejected → wrong user, or the key needs a passphrase.' },

    // ---- privesc ----
    'linux-enum': { cond: 'What is the strongest escalation lead (sudo / SUID / cron / caps)?', onFail: 'Nothing obvious → run pspy and hunt writable files.' },
    'windows-enum': { cond: 'What is the strongest lead (token / service / stored cred)?', onFail: 'Nothing obvious → check patch level and AlwaysInstallElevated.' },
    'sudo-abuse': { cond: 'Is there a NOPASSWD / GTFOBins-abusable sudo entry?', onFail: 'No usable sudo → pivot to SUID or cron.' },
    'suid-gtfobins': { cond: 'Is a SUID binary abusable per GTFOBins?', onFail: 'None abusable → watch for a root cron job.' },
    'seimpersonate': { cond: 'Is SeImpersonate/SeAssignPrimaryToken enabled?', onFail: 'Not held → try a service or stored-credential path.' },

    // ---- phase-6 privesc radar modules + cloud post-exploitation ----
    'linux-kernel-exploit': { cond: 'Does an exploit-suggester match a public LPE to this exact kernel?', onFail: 'No clean match → re-check misconfig leads before risking a crash.' },
    'linux-path-hijack': { cond: 'Does a root SUID/cron binary call a program by its bare name?', onFail: 'All calls are absolute → no PATH hijack; try another lead.' },
    'linux-ld-preload': { cond: 'Does sudo -l show env_keep carrying LD_PRELOAD (or LD_LIBRARY_PATH)?', onFail: 'Variable stripped → this path is closed; abuse the sudo command itself instead.' },
    'windows-dll-hijack': { cond: 'Does a privileged process load a DLL from a writable or missing path?', onFail: 'No hijackable load → try service permissions or a token.' },
    'windows-schtask-abuse': { cond: 'Is there a SYSTEM task whose target file (or the task itself) you can write?', onFail: 'Nothing writable → pivot to a service or token path.' },
    'aws-credential-abuse': { cond: 'Do the stolen keys authenticate, and what can the role do?', onFail: 'Keys expired or denied → re-pull from the metadata service, mind the session token.' },
    'windows-patch-exploit': { cond: 'Does wesng/Watson name a missing KB with a reliable public exploit?', onFail: 'Fully patched → focus on tokens, services, and stored credentials.' },
    'sccm-exploit': { cond: 'Can you read the Network Access Account from the management point?', onFail: 'No NAA returned → try relaying the MP, or move to another AD path.' },
    'uac-bypass': { cond: 'Are you a local admin running at Medium integrity (a filtered token)?', onFail: 'Standard user or already High → a UAC bypass gives you nothing; find a real escalation.' },
    'com-hijack': { cond: 'Does a privileged process resolve a CLSID from a registry key you can write?', onFail: 'No writable CLSID load → try a DLL path hijack or a service.' },

    // ---- linux privesc ----
    'capabilities': { cond: 'Does a binary carry an abusable capability (cap_setuid, cap_dac_read_search)?', onFail: 'No usable cap, pivot to SUID or sudo.' },
    'cron-abuse': { cond: 'Is a root cron job running a script or path you can write?', onFail: 'No writable cron target, run pspy to catch hidden jobs.' },
    'wildcard-injection': { cond: 'Does a root job run a wildcard tool (tar, chown, rsync) in a directory you can write?', onFail: 'No writable wildcard directory → the expansion trick is closed; try cron or systemd.' },
    'systemd-timer-abuse': { cond: 'Is a root systemd unit file (or the script it ExecStarts) writable by you?', onFail: 'Nothing writable → fall back to cron, sudo, or SUID.' },
    'writable-passwd': { cond: 'Can you write /etc/passwd, or read /etc/shadow to crack it?', onFail: 'Not writable, look at sudo, SUID, or cron instead.' },
    'nfs-squash': { cond: 'Is an export mounted with no_root_squash?', onFail: 'root_squash set, your uploaded SUID runs as nobody; move on.' },
    'docker-socket': { cond: 'Can you reach a writable docker socket or the docker group?', onFail: 'No docker access, check the lxd group instead.' },
    'lxc-lxd-escape': { cond: 'Are you a member of the lxd or lxc group?', onFail: 'Not in the group, pivot to another escalation lead.' },
    'pspy-monitor': { cond: 'Does pspy reveal a hidden root process or cron you can abuse?', onFail: 'Nothing scheduled, focus on sudo, SUID, and capabilities.' },
    // ---- windows privesc ----
    'unquoted-service-path': { cond: 'Is there an unquoted service path with a writable directory in it?', onFail: 'All paths quoted or unwritable, try service permissions.' },
    'weak-service-permissions': { cond: 'Can you reconfigure or restart a service to run your binary?', onFail: 'No weak ACL, check unquoted paths or token abuse.' },
    'alwaysinstallelevated': { cond: 'Are both AlwaysInstallElevated registry keys set to 1?', onFail: 'Only one or neither key set, this path is closed.' },
    'stored-credentials': { cond: 'Did the hunt surface a reusable password or hash?', onFail: 'Nothing stored, dump LSASS or check DPAPI.' },
    'dpapi-secrets': { cond: "Can you decrypt a DPAPI blob with the user's secret or SYSTEM?", onFail: 'No masterkey access, try another credential source.' },
    'windows-old-hives': { cond: 'Are the SAM and SYSTEM hives (windows.old or a backup) readable?', onFail: 'No readable hives, pivot to another lead.' },
    'lsass-dump-onbox': { cond: 'Can you dump LSASS without AV blocking it?', onFail: 'AV blocks the dump, use remote secretsdump or the comsvcs trick.' },
    'wesng-patch-gaps': { cond: 'Does wesng flag a missing patch with a public exploit?', onFail: 'Fully patched, focus on misconfiguration and tokens.' },
    'defense-enum': { cond: 'What is blocking you (AV, AppLocker, Constrained Language Mode)?', onFail: 'No controls, run your tooling on-box freely.' },
    // ---- active directory ----
    'delegation-abuse': { cond: 'Does an account hold constrained or resource-based delegation you can abuse?', onFail: 'No delegation edge, walk another graph path.' },
    'unconstrained-delegation': { cond: 'Is there an unconstrained-delegation host to coerce a DC into?', onFail: 'None found, try constrained or RBCD instead.' },
    'getst-impersonation': { cond: 'Can you request a service ticket impersonating a privileged user?', onFail: 'No delegation rights, earn them via an ACL first.' },
    'bloodyad-acl': { cond: 'Do you hold a writable ACL (GenericAll/WriteDacl) over the target?', onFail: 'No edge, map more of the graph.' },
    'golden-ticket': { cond: 'Do you hold the krbtgt hash?', onFail: 'No krbtgt yet, DCSync or dump NTDS first.' },
    'silver-ticket': { cond: "Do you hold a service account's hash and its SPN?", onFail: 'Missing the service hash, kerberoast or dump it.' },
    'diamond-ticket': { cond: 'Do you have the krbtgt key to modify a real TGT?', onFail: 'No krbtgt key, fall back to a golden ticket.' },
    'cert-authenticate': { cond: 'Does the certificate authenticate for an NT hash or a TGT?', onFail: 'Auth rejected, the template or UPN mapping is wrong.' },
    'laps-read': { cond: 'Can you read the ms-Mcs-AdmPwd attribute on a host?', onFail: 'No read right, find an ACL that grants it.' },
    'gmsa-read': { cond: 'Can you read the gMSA managed-password blob?', onFail: 'No retrieve right, get it via an ACL first.' },
    'nopac': { cond: 'Is the DC unpatched for NoPac (CVE-2021-42278/42287)?', onFail: 'Patched, try another DC CVE or path.' },
    'printnightmare': { cond: 'Is the Print Spooler reachable and unpatched (CVE-2021-34527)?', onFail: 'Spooler off or patched, move on.' },
    'ms14-068': { cond: 'Is the DC unpatched for MS14-068 (legacy only)?', onFail: 'Patched, this only hits very old DCs.' },
    'own-domain-pth': { cond: 'Do you hold the Administrator or krbtgt hash to pass?', onFail: 'Not yet, DCSync the domain first.' },
    'dnsadmins-abuse': { cond: 'Are you a member of DNSAdmins?', onFail: 'Not a member, this path is closed.' },
    'wsus-abuse': { cond: 'Is WSUS served over HTTP and can you inject an update?', onFail: 'HTTPS or no position, move on.' },
    'sccm-enum': { cond: 'Did SCCM reveal a management point or a network-access-account credential?', onFail: 'Nothing exposed, pivot to another service.' },
    'lateral-exec': { cond: 'Does the credential execute on the target (psexec/wmiexec/winrm)?', onFail: 'No exec, the account lacks local admin there.' },
    'kerberos-tickets': { cond: 'Do you hold a usable ticket in the cache to reuse?', onFail: 'No ticket, request or forge one first.' },
    // ---- pivot ----
    'pivot-chisel-socks': { cond: 'Does the chisel SOCKS tunnel come up and proxy traffic?', onFail: 'No tunnel, check the server port and firewall.' },
    'dns-tunnel': { cond: 'Is DNS the only egress (faster transports all blocked) and can the host resolve your domain?', onFail: 'A faster channel works, or DNS does not resolve out → use that instead.' },
    'pivot-ligolo': { cond: 'Is the ligolo tunnel up with a route to the internal subnet?', onFail: 'No route, add the interface route and retry.' },
    'pivot-scan-through': { cond: 'Do internal hosts answer through the tunnel (proxychains nmap)?', onFail: 'Nothing responds, confirm the route and tunnel first.' },
    // ---- proof ----
    'flag-hunt-linux': { cond: 'Can you read user.txt and root.txt with proof context visible?', onFail: 'Not readable yet, you lack the required access.' },
    'flag-hunt-windows': { cond: 'Can you read user.txt and proof.txt with proof context visible?', onFail: 'Not readable yet, escalate further first.' },
    // ---- web ----
    'ssrf': { cond: 'Does the server fetch a URL you control (internal target or callback)?', onFail: 'No fetch, the parameter is not SSRFable.' },
    'azure-imds': { cond: 'Can the SSRF reach 169.254.169.254 with the Metadata header and return a token?', onFail: 'No token (not Azure, or header stripped) → try the AWS metadata path, or treat the SSRF as internal recon.' },
    'xxe': { cond: 'Does the XML parser resolve an external entity you define?', onFail: 'Entities disabled, try another injection point.' }

  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
