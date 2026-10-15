/*!
 * obol data — tool-recipes.js — named field PRESETS for the Tool Builders (the funnel's hero tiles).
 *
 * OBOL.TOOL_RECIPES maps a builder id to a small set of recipes. A recipe is a human-named bundle of
 * field values that pre-fills the builder form for a common job (the "directory brute", the "AS-REP
 * crack"), so a student gets the right command in one tap, then can tune or edit it. Recipes set the
 * METHOD knobs only (wordlist, mode, codes); the shared engagement-binding component supplies the
 * target, URL, and identity, so a recipe stays reusable across engagements.
 *
 * Bidirectional (Option B): picking a recipe writes its values into the form; editing a field after
 * just makes the command "custom". Every `values` key must be a real field id of the builder, and
 * every recipe must compile, both asserted by tests/engine/tool-recipes-smoke.js. Recipes mirror the
 * canonical pack commands (the source of truth); `phase` tags them for the right funnel lane. House
 * style: no em or en dashes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var WC = '/usr/share/seclists/Discovery/Web-Content/';
  var DNS = '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt';

  OBOL.TOOL_RECIPES = {
    'tb-nmap': [
      { id: 'discover', label: 'Host Discovery', phase: 'recon', hint: 'Ping sweep a range to find live hosts before you touch any ports.',
        values: { profile: 'discover' } },
      { id: 'quick', label: 'Quick Top 1000', phase: 'recon', hint: 'The fast first look: the 1000 most common TCP ports, open ones only.',
        values: { profile: 'quick', portScope: 'top1000', timing: 'T4' } },
      { id: 'allports', label: 'All TCP Ports', phase: 'recon', hint: 'Every one of the 65535 TCP ports at a high rate. Nothing hides.',
        values: { profile: 'full', portScope: 'all', timing: 'T4', minRate: '5000' } },
      { id: 'service', label: 'Service + Scripts', phase: 'recon', hint: 'Version banners and the default NSE scripts on the ports you already found.',
        values: { profile: 'service', version: true, scripts: true } },
      { id: 'udp', label: 'Top UDP', phase: 'recon', hint: 'The common UDP services (DNS, SNMP, TFTP) that a TCP scan never sees.',
        values: { profile: 'udp', portScope: 'top100udp' } },
    ],
    'tb-ffuf': [
      { id: 'dir-common', label: 'Directory Brute', phase: 'enum', hint: 'The default first sweep: common web paths, keep the interesting status codes, auto-calibrated.',
        values: { action: 'content', wordlist: WC + 'common.txt', matchCodes: '200,204,301,302,307,401,403', autoCalibration: true } },
      { id: 'dir-ext', label: 'Files + Extensions', phase: 'enum', hint: 'A deeper directory list that also tries php, txt, html, and bak on every word.',
        values: { action: 'content', wordlist: WC + 'raft-medium-directories.txt', extensions: '.php,.txt,.html,.bak', autoCalibration: true } },
      { id: 'vhost', label: 'Virtual Host Sweep', phase: 'enum', hint: 'Same IP, different site: fuzz the Host header to find hidden vhosts. Set the domain first.',
        values: { action: 'vhost', wordlist: DNS, filterSize: '0' } },
      { id: 'api', label: 'API Endpoints', phase: 'enum', hint: 'Hunt REST and API routes specifically.',
        values: { action: 'content', wordlist: WC + 'api/api-endpoints.txt', matchCodes: '200,201,401,403,405', autoCalibration: true } },
    ],
    'tb-gobuster-ferox': [
      { id: 'gobuster-dir', label: 'Gobuster Directories', phase: 'enum', hint: 'Classic directory and file discovery with common extensions.',
        values: { engine: 'gobuster', gobusterMode: 'dir', wordlist: WC + 'raft-medium-directories.txt', extensions: 'php,txt,html,bak' } },
      { id: 'ferox-recurse', label: 'Feroxbuster (recursive)', phase: 'enum', hint: 'Feroxbuster dives into each folder it finds automatically. Great for deep trees.',
        values: { engine: 'feroxbuster', wordlist: WC + 'raft-medium-directories.txt', extensions: 'php,txt,html', recursion: true, depth: '2' } },
      { id: 'gobuster-vhost', label: 'Gobuster VHosts', phase: 'enum', hint: 'Virtual-host discovery: same IP, different Host header.',
        values: { engine: 'gobuster', gobusterMode: 'vhost', wordlist: DNS } },
    ],
    'tb-wfuzz': [
      { id: 'path', label: 'Path Discovery', phase: 'enum', hint: 'Fuzz the URL path, hide the 404 background.',
        values: { action: 'path', mode: 'path', wordlist: '/usr/share/wordlists/dirb/common.txt', hideCodes: '404' } },
      { id: 'vhost', label: 'Virtual Host Sweep', phase: 'enum', hint: 'Fuzz the Host header; hide the baseline response size so only real vhosts show.',
        values: { action: 'custom', mode: 'custom', header: 'Host: FUZZ.target.local', hideChars: '0' } },
    ],
    'tb-hashcat': [
      { id: 'ntlm', label: 'NTLM', phase: 'cracking', hint: 'Plain Windows NT hashes (mode 1000) against rockyou.',
        values: { mode: '1000', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'ntlm-rules', label: 'NTLM + Rules', phase: 'cracking', hint: 'NTLM with best64 mangling rules when a plain wordlist stalls.',
        values: { mode: '1000', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt', rule: '/usr/share/hashcat/rules/best64.rule' } },
      { id: 'asrep', label: 'AS-REP Roast', phase: 'cracking', hint: 'Kerberos AS-REP hashes from pre-auth-disabled accounts (mode 18200).',
        values: { mode: '18200', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'kerberoast', label: 'Kerberoast', phase: 'cracking', hint: 'Kerberos TGS service-ticket hashes (mode 13100).',
        values: { mode: '13100', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'netntlmv2', label: 'NetNTLMv2', phase: 'cracking', hint: 'Captured responder / relay hashes (mode 5600).',
        values: { mode: '5600', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'netntlmv1', label: 'NetNTLMv1', phase: 'cracking', hint: 'Downgraded responder capture (mode 5500); crack or crack.sh it.',
        values: { mode: '5500', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'dcc2', label: 'DCC2 (mscash2)', phase: 'cracking', hint: 'Domain cached creds from a workstation (mode 2100). Slow, so a short wordlist.',
        values: { mode: '2100', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'shadow', label: 'Linux Shadow', phase: 'cracking', hint: 'sha512crypt $6$ from /etc/shadow (mode 1800). Unshadow first.',
        values: { mode: '1800', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'bcrypt', label: 'bcrypt', phase: 'cracking', hint: 'bcrypt $2* from a web app DB (mode 3200). Slow by design.',
        values: { mode: '3200', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'mssql2012', label: 'MSSQL 2012+', phase: 'cracking', hint: 'MSSQL 2012/2014 login hashes (mode 1731).',
        values: { mode: '1731', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'rawmd5', label: 'Raw MD5', phase: 'cracking', hint: 'Plain md5() from a web app (mode 0).',
        values: { mode: '0', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'keepass', label: 'KeePass', phase: 'cracking', hint: 'A .kdbx database (mode 13400); keepass2john makes the hash.',
        values: { mode: '13400', attack: 'straight', wordlist: '/usr/share/wordlists/rockyou.txt' } },
    ],
    'tb-rustscan': [
      { id: 'fast-service', label: 'Fast Scan + Service', phase: 'recon', hint: 'Every port in seconds, then nmap -sV -sC on whatever is open.',
        values: { ulimit: '5000', nmapArgs: '-sV -sC -oN scans/rustscan.txt' } },
      { id: 'gentle', label: 'Gentle (small batch)', phase: 'recon', hint: 'A smaller batch for a fragile or rate-limited target.',
        values: { ulimit: '2000', batch: '1500', nmapArgs: '-sV' } },
    ],
    'tb-masscan': [
      { id: 'all-tcp', label: 'All TCP (fast)', phase: 'recon', hint: 'Sweep every TCP port at a modest rate, then follow up with nmap -sV.',
        values: { ports: '1-65535', rate: '1000' } },
      { id: 'web', label: 'Web Ports', phase: 'recon', hint: 'Just the common web ports across a range.',
        values: { ports: '80,443,8080,8443', rate: '500' } },
    ],
    'tb-mssqlclient': [
      { id: 'win-auth', label: 'Windows Login', phase: 'access', hint: 'Domain or Windows account (pairs with your bound identity).',
        values: { authMode: 'password', windowsAuth: true } },
      { id: 'sql-auth', label: 'SQL Login (sa)', phase: 'access', hint: 'Local SQL account such as sa, no domain.',
        values: { authMode: 'password', windowsAuth: false } },
      { id: 'pth', label: 'Pass-the-Hash', phase: 'access', hint: 'Authenticate with the NT hash instead of a password.',
        values: { authMode: 'ntlm', windowsAuth: true } },
    ],
    'tb-mysql': [
      { id: 'show-dbs', label: 'List Databases', phase: 'loot', hint: 'One query: show every database the account can see.',
        values: { execute: 'show databases;' } },
      { id: 'version', label: 'Version + User', phase: 'loot', hint: 'Confirm the connection and see who you are.',
        values: { execute: 'select version(), current_user();' } },
    ],
    'tb-psql': [
      { id: 'list-dbs', label: 'List Databases', phase: 'loot', hint: 'One query: list every database.',
        values: { execute: 'SELECT datname FROM pg_database;' } },
      { id: 'version', label: 'Version + User', phase: 'loot', hint: 'Confirm the connection and the current role.',
        values: { execute: 'SELECT version(), current_user;' } },
    ],
    'tb-john': [
      { id: 'asrep', label: 'AS-REP Roast', phase: 'cracking', hint: 'Crack AS-REP hashes with john when you have no GPU.',
        values: { format: 'krb5asrep', mode: 'wordlist', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'kerberoast', label: 'Kerberoast', phase: 'cracking', hint: 'Crack TGS service tickets with john.',
        values: { format: 'krb5tgs', mode: 'wordlist', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'shadow', label: 'Linux Shadow', phase: 'cracking', hint: 'sha512crypt hashes from a Linux /etc/shadow (unshadow first).',
        values: { format: 'sha512crypt', mode: 'wordlist', wordlist: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'ntlm', label: 'NTLM', phase: 'cracking', hint: 'Windows NT hashes with john instead of hashcat.',
        values: { format: 'NT', mode: 'wordlist', wordlist: '/usr/share/wordlists/rockyou.txt' } },
    ],
    'tb-nxc': [
      { id: 'validate', label: 'Validate A Credential', phase: 'creds', hint: 'The switchless confirm: does this user/pass (or hash) actually log in over SMB? Do this before you trust a found credential.',
        values: { protocol: 'smb', action: 'validate' } },
      { id: 'shares', label: 'List SMB Shares', phase: 'enum', hint: 'What shares this identity can see, and READ/WRITE on each.',
        values: { protocol: 'smb', action: 'shares' } },
      { id: 'users', label: 'Domain Users', phase: 'enum', hint: 'Pull the domain user list over SMB to seed roasting and sprays.',
        values: { protocol: 'smb', action: 'users' } },
      { id: 'pass-pol', label: 'Password Policy', phase: 'enum', hint: 'Lockout threshold and min length before you spray, so you do not lock accounts.',
        values: { protocol: 'smb', action: 'pass-pol' } },
      { id: 'rid-brute', label: 'RID Brute (anonymous)', phase: 'enum', hint: 'Enumerate users by RID cycling when a null session is allowed, no credential needed.',
        values: { protocol: 'smb', authMode: 'anonymous', action: 'rid-brute' } },
      { id: 'asrep', label: 'AS-REP Roast', phase: 'creds', hint: 'Grab AS-REP hashes for accounts without pre-auth, straight to the Hash Identifier.',
        values: { protocol: 'ldap', action: 'asrep', output: 'loot/asrep.hashes' } },
      { id: 'kerberoast', label: 'Kerberoast', phase: 'creds', hint: 'Request TGS tickets for every SPN account and dump the crackable hashes.',
        values: { protocol: 'ldap', action: 'kerberoast', output: 'loot/kerberoast.hashes' } },
      { id: 'bloodhound', label: 'BloodHound Collect', phase: 'enum', hint: 'Collect the graph over LDAP with nxc, then open the Domain tab.',
        values: { protocol: 'ldap', action: 'bloodhound' } },
      { id: 'ntds', label: 'Dump NTDS', phase: 'loot', hint: 'With DA (or equivalent), dump every domain hash from NTDS.dit.',
        values: { protocol: 'smb', action: 'ntds' } },
    ],
    'tb-kerbrute': [
      { id: 'userenum', label: 'Username Enumeration', phase: 'recon', hint: 'Spray a username list at the KDC to find which accounts exist, no password needed and no lockout.',
        values: { mode: 'userenum', usersFile: '/usr/share/seclists/Usernames/top-usernames-shortlist.txt', safe: true } },
      { id: 'spray', label: 'Password Spray', phase: 'creds', hint: 'Try ONE password against your enumerated user list. Mind the lockout policy first.',
        values: { mode: 'passwordspray', usersFile: 'users.txt', safe: true } },
    ],
    'tb-smbmap': [
      { id: 'anon', label: 'Anonymous Shares', phase: 'enum', hint: 'List shares and permissions with a null session, no credential.',
        values: { authMode: 'anonymous' } },
      { id: 'creds', label: 'Authenticated Shares', phase: 'enum', hint: 'Shares and READ/WRITE this credential can reach.',
        values: { authMode: 'password' } },
      { id: 'recurse', label: 'Recurse A Share', phase: 'loot', hint: 'Walk a share recursively to spot configs, scripts, and creds left lying around.',
        values: { authMode: 'anonymous', recursive: true } },
    ],
    'tb-smbclient': [
      { id: 'list', label: 'List Shares', phase: 'enum', hint: 'The quick null-session share list.',
        values: { mode: 'list', authMode: 'anonymous' } },
      { id: 'connect-ipc', label: 'Connect To A Share', phase: 'enum', hint: 'Open an interactive session on a named share (change it from C$).',
        values: { mode: 'connect', authMode: 'anonymous', share: 'C$' } },
    ],
    'tb-getnpusers': [
      { id: 'userlist', label: 'AS-REP Roast A List', phase: 'creds', hint: 'Test a whole user list for accounts that need no pre-auth, no credential required. Hashcat format.',
        values: { source: 'users-file', usersFile: 'users.txt', format: 'hashcat', request: true } },
      { id: 'single', label: 'Check One User', phase: 'creds', hint: 'AS-REP test a single username you already have.',
        values: { source: 'single-user', authMode: 'no-pass', format: 'hashcat', request: true } },
    ],
    'tb-getuserspns': [
      { id: 'request-all', label: 'Kerberoast All', phase: 'creds', hint: 'Request a TGS for every SPN account and dump the hashes to crack.',
        values: { requestMode: 'request-all' } },
      { id: 'list', label: 'List SPN Accounts', phase: 'enum', hint: 'Just enumerate the kerberoastable accounts first, request nothing.',
        values: { requestMode: 'list' } },
    ],
    'tb-secretsdump': [
      { id: 'remote', label: 'Remote (password)', phase: 'loot', hint: 'Dump SAM + LSA + cached creds over the network with a username and password.',
        values: { authMode: 'password' } },
      { id: 'pth', label: 'Remote (pass-the-hash)', phase: 'loot', hint: 'Same dump using an NT hash instead of a password.',
        values: { authMode: 'ntlm' } },
      { id: 'just-dc', label: 'DCSync (just-dc)', phase: 'loot', hint: 'Pull every domain hash straight from the DC without touching NTDS on disk.',
        values: { authMode: 'password', justDc: true } },
    ],
    'tb-evilwinrm': [
      { id: 'password', label: 'Shell (password)', phase: 'access', hint: 'An interactive WinRM shell with a username and password.',
        values: { authMode: 'password' } },
      { id: 'pth', label: 'Shell (pass-the-hash)', phase: 'access', hint: 'A WinRM shell using an NT hash, no password needed.',
        values: { authMode: 'ntlm' } },
    ],
    'tb-hydra': [
      { id: 'ssh', label: 'SSH Password Spray', phase: 'creds', hint: 'Spray rockyou at one SSH user. Gate on a userlist and the lockout risk first.',
        values: { service: 'ssh', loginMode: 'single', passwordMode: 'list', passwordList: '/usr/share/wordlists/rockyou.txt' } },
      { id: 'http-post', label: 'HTTP Login Form', phase: 'creds', hint: 'Brute a web login form. Set the path and the failure string from the real response.',
        values: { service: 'http-post-form', loginMode: 'single', passwordMode: 'list', passwordList: '/usr/share/wordlists/rockyou.txt', postForm: '/login:username=^USER^&password=^PASS^:F=incorrect' } },
    ],
    'tb-bloodhound-python': [
      { id: 'all', label: 'Collect All', phase: 'enum', hint: 'The full remote collection (ACLs, sessions, trusts), zipped for the Domain tab.',
        values: { authMode: 'password', collection: 'All' } },
      { id: 'dconly', label: 'DC Only (quiet)', phase: 'enum', hint: 'The quiet collection: no session enumeration, just what the DC holds.',
        values: { authMode: 'password', collection: 'DCOnly' } },
    ],
    'tb-ldapsearch': [
      { id: 'anon-dump', label: 'Anonymous Dump', phase: 'enum', hint: 'Try a full anonymous subtree dump; many DCs leak plenty before you authenticate.',
        values: { authMode: 'anonymous', scope: 'sub' } },
      { id: 'users', label: 'User Objects', phase: 'enum', hint: 'Just the user accounts and their sAMAccountName.',
        values: { authMode: 'anonymous', filter: '(objectClass=user)', attributes: 'sAMAccountName' } },
    ],
    'tb-enum4linux-ng': [
      { id: 'all', label: 'Everything', phase: 'enum', hint: 'The full sweep: users, groups, shares, policy, OS, over a null session.',
        values: { all: true } },
      { id: 'users', label: 'Users Only', phase: 'enum', hint: 'Just enumerate the domain/local users.',
        values: { users: true } },
    ],
    'tb-rpcclient': [
      { id: 'enumusers', label: 'Enumerate Users', phase: 'enum', hint: 'The classic null-session user dump (enumdomusers).',
        values: { command: 'enumdomusers' } },
      { id: 'dominfo', label: 'Domain Info', phase: 'enum', hint: 'Domain and password policy summary (querydominfo).',
        values: { command: 'querydominfo' } },
    ],
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
