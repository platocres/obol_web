/*!
 * obol engine — tests/engine/parser-ports-smoke.js
 * Smoke tests for the conservative output parsers ported from obol-local into obol_web:
 *   1. SNMP loot (LanMan users table → ad.user_list; process-arg password → credential.candidate snmp-process)
 *   2. SQLite .dump → credential.candidate {via:'exposed-sqlite'}
 *   3. notable-program → host.notable_program
 *   4. PuTTY/plink/WinSCP stored creds → credential.candidate {via:'putty_registry'|'plink'} + stored marker
 *   5. VCS-token / connection-URI / framework-config secrets → credential.candidate {kind:'vcs_token'|'connection_uri'|'config_secret'}
 *   6. john LIVE cracked line → credential.candidate {kind:'cracked_secret'}
 *   7. arjun → web.param_candidate
 *   8. exposed-artifact classifier → web.exposed_artifact
 *   9. sccmhunter null-match → sccm.enumerated {present:true|false}
 *  10. bloodyAD domain-control → ad.domain_control {principal,right}
 *
 * Each parser gets a positive sample (asserting the exact minted kind + value) AND a negative case
 * (benign / discriminating output mints nothing). Sample outputs mirror obol-local's own tests.
 *
 * Run: node tests/engine/parser-ports-smoke.js
 */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ENGINE = path.join(__dirname, '..', '..', 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENGINE, 'parsers', m + '.js')); });
load(path.join(ENGINE, 'parsers', 'index.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function run(opts) {
  return OBOL.parsers.parseActionOutput({
    actionId: opts.actionId || '', command: opts.command || '', stdout: opts.stdout || '', stderr: '',
    source: opts.command || '', scope: opts.scope || 'host:10.10.10.10', domain: opts.domain || '',
  }).facts;
}
function of(facts, kind) { return facts.filter(function (f) { return f.kind === kind && f.state === 'supported'; }); }
function cands(facts, pred) { return of(facts, 'credential.candidate').filter(function (f) { return pred(f.value || {}); }); }

// ── 1. SNMP loot: LanMan users table + process-arg password ────────────────────────
console.log('# SNMP loot');
var snmp = run({ command: "snmpwalk -v2c -c public 10.10.10.10", scope: 'host:10.10.10.10', stdout: [
  'iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: x86 Software: Windows Version 6.1"',
  'iso.3.6.1.4.1.77.1.2.25.1.1.1 = STRING: "Administrator"',
  'iso.3.6.1.4.1.77.1.2.25.1.1.2 = STRING: "Guest"',
  'iso.3.6.1.4.1.77.1.2.25.1.1.3 = STRING: "backupsvc"',
  'HOST-RESOURCES-MIB::hrSWRunParameters.1234 = STRING: "-u dbadmin -p S3cretSauce! //db.local/app"',
].join('\n') });
var ul = of(snmp, 'ad.user_list');
ok(ul.length === 1 && ul[0].value.method === 'snmp', 'LanMan users table → ad.user_list {method:snmp}');
ok(ul.length && ul[0].value.users.indexOf('backupsvc') >= 0 && ul[0].value.count === 3, 'the spray list carries every LanMan account (3)');
var snmpPw = cands(snmp, function (v) { return v.via === 'snmp-process'; });
ok(snmpPw.length === 1 && snmpPw[0].value.password === 'S3cretSauce!' && snmpPw[0].value.user === 'dbadmin',
  'a password on a running-process command line → credential.candidate {via:snmp-process}');
var snmpNeg = run({ command: "snmpwalk -v2c -c public 10.10.10.10", stdout: 'Timeout: No Response from 10.10.10.10' });
ok(of(snmpNeg, 'ad.user_list').length === 0 && of(snmpNeg, 'snmp.reachable').length === 0, 'a timed-out SNMP read mints nothing');

// ── 2. SQLite .dump → credential.candidate {via:exposed-sqlite} ─────────────────────
console.log('# SQLite dump');
var sq = run({ command: "sqlite3 /tmp/obol_loot.db .dump", stdout: [
  'CREATE TABLE "users" (id INTEGER, login TEXT, passwd TEXT);',
  "INSERT INTO \"users\" VALUES(1,'admin','d41d8cd98f00b204e9800998ecf8427e');",
  "INSERT INTO \"users\" VALUES(2,'bob','Summer2024!');",
].join('\n') });
var sqc = cands(sq, function (v) { return v.via === 'exposed-sqlite'; });
ok(sqc.some(function (f) { return f.value.user === 'admin' && f.value.hash === 'd41d8cd98f00b204e9800998ecf8427e'; }),
  'a hashed secret row → credential.candidate {via:exposed-sqlite, hash}');
ok(sqc.some(function (f) { return f.value.user === 'bob' && f.value.password === 'Summer2024!'; }),
  'a plaintext secret row → credential.candidate {via:exposed-sqlite, password}');
var sqNeg = run({ command: "sqlite3 /tmp/logs.db .dump", stdout: [
  'CREATE TABLE logs (id INTEGER, msg TEXT);', "INSERT INTO logs VALUES(1,'started ok');",
].join('\n') });
ok(cands(sqNeg, function (v) { return v.via === 'exposed-sqlite'; }).length === 0, 'a dump with no user/secret columns mints nothing');

// ── 3. notable-program → host.notable_program ───────────────────────────────────────
console.log('# notable programs');
var notableDir = [
  ' Directory of C:\\Users\\eric\\Desktop',
  '02/16/2025  06:36 PM            12,345 admintool.exe',
  '02/16/2025  06:36 PM             2,222 pmcon.exe',
  '02/16/2025  06:36 PM               100 notes.txt',
  ' Directory of C:\\Windows\\System32',
  '02/16/2025  06:36 PM            99,999 svchost.exe',
  '/home/support/backup_manager.sh',
  '/usr/bin/python3',
].join('\n');
var np = run({ command: "dir /s C:\\Users", stdout: notableDir });
var progs = {}; of(np, 'host.notable_program').forEach(function (f) { progs[f.value.name] = f.value; });
ok(progs['admintool.exe'] && progs['admintool.exe'].path === 'C:\\Users\\eric\\Desktop\\admintool.exe', 'suggestive name in a user location → host.notable_program with resolved path');
ok(!!progs['pmcon.exe'], 'an unremarkable name is still flagged by its user LOCATION');
ok(!!progs['backup_manager.sh'] && progs['backup_manager.sh'].os === 'linux', 'a Linux bespoke script is flagged (os:linux)');
ok(!progs['svchost.exe'] && !progs['python3'] && !progs['notes.txt'], 'System32 binaries / interpreters / non-exe files are ignored');
var npNeg = run({ command: "dir C:\\Windows\\System32", stdout: ' Directory of C:\\Windows\\System32\nsvchost.exe\nconhost.exe\n' });
ok(of(npNeg, 'host.notable_program').length === 0, 'a pure system-binary listing mints nothing');

// ── 4. PuTTY/plink/WinSCP stored creds → credential.candidate {via:putty_registry|plink} ──
console.log('# PuTTY / plink / WinSCP');
var plink = run({ command: "reg query HKCU\\Software\\SimonTatham /s", stdout:
  'HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\n' +
  "    devbox    REG_SZ    \"&('C:\\Program Files\\PuTTY\\plink.exe') -pw 'Wr0ng@Place!' operator@10.20.30.40 'df -h'\"" });
var pl = cands(plink, function (v) { return v.via === 'plink'; });
ok(pl.length === 1 && pl[0].value.user === 'operator' && pl[0].value.password === 'Wr0ng@Place!', 'a saved plink -pw command line → credential.candidate {via:plink}');
var proxy = run({ command: "reg query HKCU\\Software\\SimonTatham /s", stdout: [
  'HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\prod',
  '    ProxyUsername    REG_SZ    backupsvc',
  '    ProxyPassword    REG_SZ    Spr1ng2025!',
  '    ProxyMethod    REG_DWORD    0x5',
].join('\n') });
ok(cands(proxy, function (v) { return v.via === 'putty_registry' && v.user === 'backupsvc' && v.password === 'Spr1ng2025!'; }).length === 1,
  'a PuTTY registry ProxyPassword → credential.candidate {via:putty_registry} paired with its ProxyUsername');
// WinSCP passwords are obfuscated: obol flags the store (stored_credentials label) but fabricates no cred.
var winscp = run({ actionId: 'stored-credentials', command: "reg query winscp", stdout: [
  'HKEY_CURRENT_USER\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\\admin@10.0.0.9',
  '    Password    REG_SZ    A35C8FE0AB1122...obfuscated...',
  '    UserName    REG_SZ    admin',
].join('\n') });
var storedLabels = of(winscp, 'privesc.stored_credentials').reduce(function (a, f) { return a.concat(f.value.kinds || []); }, []);
ok(storedLabels.indexOf('winscp') >= 0, 'a WinSCP store is flagged as a stored_credentials marker');
ok(cands(winscp, function (v) { return v.via === 'putty_registry'; }).length === 0, 'no cleartext credential is fabricated from the obfuscated WinSCP blob');

// ── 5. VCS token / connection URI / framework-config secrets → credential.candidate ─
console.log('# source secrets (vcs token / connection uri / config)');
var httpGit = ['| http-git:', '|   10.10.10.10:80/.git/', '|     Remotes:',
  '|_      https://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@github.com/org/dev.git'].join('\n');
var vcs = run({ command: "nmap -sV 10.10.10.10", stdout: httpGit });
ok(cands(vcs, function (v) { return v.kind === 'vcs_token' && v.token === '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'; }).length === 1,
  'a GitHub PAT leaked in a .git remote → credential.candidate {kind:vcs_token}');
var php = run({ command: "cat configuration.php", stdout: "class JConfig {\n  public $user = 'chloe';\n  public $password = 'BreakingBad92';\n}" });
ok(cands(php, function (v) { return v.kind === 'config_secret' && v.password === 'BreakingBad92'; }).length >= 1, 'a PHP framework $password literal → credential.candidate {kind:config_secret}');
var uri = run({ command: "cat app.props", stdout: "spring.datasource.url=mysql://svc:C0nnUri!pw@db.internal/app" });
ok(cands(uri, function (v) { return v.kind === 'connection_uri' && v.user === 'svc' && v.password === 'C0nnUri!pw'; }).length === 1,
  'a credentialed connection URI → credential.candidate {kind:connection_uri}');
var srcNeg = run({ command: "cat configuration.php", stdout: "$password = 'password';\n$db_password = \"$dbpass\";\npublic $password = '{{DB_PASS}}';\n" });
ok(of(srcNeg, 'credential.candidate').length === 0, 'deny-listed values, bare var refs, and placeholders are NOT minted as secrets');

// ── 6. john LIVE cracked line → credential.candidate {kind:cracked_secret} ──────────
console.log('# john LIVE cracked line');
var johnLive = run({ command: "john --format=zip hash.txt", stdout: [
  'Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])',
  'codeblue         (backup.zip)',
  '1g 0:00:00:01 DONE (2025-01-01 00:00) 1.000g/s',
].join('\n') });
var jl = cands(johnLive, function (v) { return v.kind === 'cracked_secret'; });
ok(jl.length === 1 && jl[0].value.password === 'codeblue' && jl[0].value.label === 'backup.zip' && jl[0].value.via === 'john',
  "john's live `<plaintext>  (<label>)` line → credential.candidate {kind:cracked_secret}");
var johnNeg = run({ command: "john --wordlist=rockyou.txt hash.txt", stdout: 'password123        (secret.zip)\n' });
ok(cands(johnNeg, function (v) { return v.kind === 'cracked_secret'; }).length === 0, "a `(...)` line with no `Loaded N password hash` preamble mints nothing");

// ── 7. arjun → web.param_candidate ──────────────────────────────────────────────────
console.log('# arjun');
var arj = run({ command: "arjun -u 'http://10.10.10.10:8080/search' -m GET,POST", stdout: '[+] Heuristic scanner found 2 params\n[+] Parameters found: query, page\n' });
var pc = of(arj, 'web.param_candidate');
var pcSet = {}; pc.forEach(function (f) { pcSet[f.value.param] = f.value.url; });
ok(pcSet['query'] === 'http://10.10.10.10:8080/search' && pcSet['page'] === 'http://10.10.10.10:8080/search',
  'arjun discovered params → one web.param_candidate each, tagged with the fuzzed endpoint');
var arjNeg = run({ command: "arjun -u 'http://10.10.10.10:8080/search' -m GET", stdout: '[*] Scanning 0/1000\n[!] No parameters were discovered.\n' });
ok(of(arjNeg, 'web.param_candidate').length === 0, 'an arjun run that finds nothing mints no param candidate');

// ── 8. exposed-artifact classifier → web.exposed_artifact ───────────────────────────
console.log('# exposed artifacts');
var ferox = run({ command: "feroxbuster -u http://10.10.10.10 -w list.txt", stdout: [
  '200      GET       10l       25w      600c http://10.10.10.10/index.html',
  '200      GET        5l       10w      200c http://10.10.10.10/backup.zip',
  '200      GET        2l        4w       80c http://10.10.10.10/.git/HEAD',
  '200      GET        1l        3w       40c http://10.10.10.10/config.php',
].join('\n') });
var art = {}; of(ferox, 'web.exposed_artifact').forEach(function (f) { art[f.value.kind] = f.value; });
ok(!!art['archive'] && art['archive'].url === 'http://10.10.10.10/backup.zip', 'a discovered .zip → web.exposed_artifact {kind:archive}');
ok(!!art['git'], 'a discovered /.git/ path → web.exposed_artifact {kind:git}');
ok(!!art['config'], 'a discovered config file → web.exposed_artifact {kind:config}');
var feroxNeg = run({ command: "feroxbuster -u http://10.10.10.10 -w list.txt", stdout: '200      GET       10l       25w      600c http://10.10.10.10/index.html\n' });
ok(of(feroxNeg, 'web.exposed_artifact').length === 0, 'ordinary content (index.html) leaks no credential store → no exposed_artifact');

// ── 9. sccmhunter null-match → sccm.enumerated {present:true|false} ─────────────────
console.log('# sccm enumerated (null-match)');
var find = "sccmhunter.py find -u svc -p x -d corp.local -dc-ip 10.0.0.5";
var sccmPresent = run({ command: find, scope: 'host:10.0.0.5', domain: 'corp.local', stdout: [
  'SCCMHunter v1.0.4', '[+] Found management point: MP01.corp.local', '[+] Found site server: SITE01.corp.local (site code: P01)',
].join('\n') });
var sp = of(sccmPresent, 'sccm.enumerated');
ok(sp.length === 1 && sp[0].value.present === true, 'a banner run that finds SCCM → sccm.enumerated {present:true}');
var sccmAbsent = run({ command: find, scope: 'host:10.0.0.5', domain: 'corp.local', stdout: [
  'SCCMHunter v1.0.4', '[*] Querying LDAP for potential PXE enabled distribution points',
  '[-] System Management Container not found.', '[-] No results found.',
].join('\n') });
var sa = of(sccmAbsent, 'sccm.enumerated');
ok(sa.length === 1 && sa[0].value.present === false, 'a banner run that finds no SCCM → sccm.enumerated {present:false} (a query DESCRIPTION line is not a hit)');
var sccmNeg = run({ command: find, scope: 'host:10.0.0.5', domain: 'corp.local', stdout: '[-] No results found.' });
ok(of(sccmNeg, 'sccm.enumerated').length === 0, 'a bannerless run records no enumeration outcome');

// ── 10. bloodyAD domain-control → ad.domain_control {principal,right} ───────────────
console.log('# bloodyAD domain control');
var dcOut = [
  'distinguishedName: DC=htb,DC=local',
  'Trustee: HTB\\Exchange Windows Permissions', '  Mask: WriteDacl',
  'Trustee: HTB\\Enterprise Admins', '  Mask: GenericAll',
  'Trustee: HTB\\Authenticated Users', '  Mask: ReadProperty',
].join('\n');
var bd = run({ command: "bloodyAD --host 10.129.91.55 -d htb.local -u svc -p s3rvice get object 'DC=htb,DC=local' --resolve-sd",
  scope: 'host:10.129.91.55', domain: 'htb.local', stdout: dcOut });
var dc = of(bd, 'ad.domain_control');
var principals = {}; dc.forEach(function (f) { principals[(f.value.principal || '').toLowerCase()] = f.value.right; });
ok(principals['exchange windows permissions'] === 'WriteDacl', 'a domain-DACL WriteDacl → ad.domain_control {principal, right}');
ok(!!principals['enterprise admins'], 'a GenericAll control right on the domain root is recorded');
ok(!principals['authenticated users'], 'a non-control right (ReadProperty) is NOT recorded');
var bdNeg = run({ command: "bloodyAD --host 10.129.91.55 -d htb.local -u svc -p s3rvice get object 'DC=htb,DC=local'",
  scope: 'host:10.129.91.55', domain: 'htb.local', stdout: dcOut });
ok(of(bdNeg, 'ad.domain_control').length === 0, 'a read without --resolve-sd records no domain-control (self-gated)');

console.log(fail ? ('\nPARSER PORTS: ' + fail + ' FAILURES') : '\nPARSER PORTS: all passed');
process.exit(fail ? 1 : 0);
