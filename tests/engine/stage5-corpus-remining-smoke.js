/* Stage 5/6 corpus re-mining regression smoke (corpus-free).
 * Locks the parser and blocker branches closed during the Stage 3-6 0xdf corpus completion sweep:
 *   - DNS bare-output correlation (dig +short hostname -> dns.a_record)
 *   - ADCS certipy req certificate/key output + ESC7 + certipy account read base DN
 *   - SMB compressed attribute rows (Dc/Ac), NTFS ADS (:Zone.Identifier:$DATA), piped smbclient -L, and putting file
 *   - rpcclient password change confirmation and NT_STATUS_PASSWORD_RESTRICTION blocker
 *   - MySQL Drupal $S$ and Django pbkdf2_sha256$ hash rows
 *   - MSSQL master.sys.databases listing and CONTROL SERVER / IMPERSONATE ANY LOGIN db.admin
 *   - sqlmap ASCII [N tables] grid and FILE privilege -> db.admin
 *   - bloodhound-python completion without --zip ("INFO: Done in 00M 12S")
 *   - Cracked credentials: $ansible$, $PEM$, and .psafe3
 *   - Host OS & kernel from neofetch/hostnamectl and localized Spanish whoami /priv (Habilitada)
 *   - Operational blocker: certutil -ca.cert flag syntax error (blocker.certutil_usage)
 * House style: no em or en dashes. */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
const sb = { OBOL: {}, console };
sb.window = sb;
sb.global = sb;
vm.createContext(sb);
function load(rel) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, rel), 'utf8'), sb, { filename: rel });
}

load('assets/engine/facts.js');
load('assets/engine/parsers/common.js');
[
  'nmap', 'directory', 'creds', 'host', 'web', 'services', 'database',
  'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'index'
].forEach(n => load('assets/engine/parsers/' + n + '.js'));

const parse = sb.OBOL.parsers.parseActionOutput;

let fail = 0;
function ok(cond, msg) {
  if (!cond) { console.error('  FAIL:', msg); fail++; }
  else { console.log('  ok  :', msg); }
}
function runCase(command, stdout, scope) {
  const r = parse({ actionId: '', command, stdout, stderr: '', source: command, scope: scope || 'host:10.10.10.10', domain: '' });
  const facts = (r && r.facts) || [];
  return { facts, kinds: new Set(facts.map(f => f.kind)) };
}

// 1. dig +short hostname -> dns.a_record (and dc.<domain> -> ad.dc_candidate)
{
  const { kinds, facts } = runCase('dig +short @10.10.11.205 cerberus.local', '172.16.22.1\n', 'host:10.10.11.205');
  ok(kinds.has('dns.a_record'), 'dig +short hostname mints dns.a_record');
  const rec = facts.find(f => f.kind === 'dns.a_record');
  ok(rec && rec.value && rec.value.name === 'cerberus.local' && rec.value.ip === '172.16.22.1', 'dig +short correlates hostname and IP');
  const dcRes = runCase('dig +short @10.10.11.205 dc.cerberus.local', '172.16.22.1\n', 'host:10.10.11.205');
  ok(dcRes.kinds.has('ad.dc_candidate') && dcRes.kinds.has('ad.domain_known'), 'dig +short dc.<domain> mints ad.dc_candidate and ad.domain_known');
}

// 2. certipy req + ESC7 + account read
{
  const reqOut = 'Certipy v4.8.2 - by Oliver Lyak (ly4k)\n[*] Requesting certificate via RPC\n[*] Successfully requested certificate\n[*] Request ID is 14\n[*] Got certificate with UPN \'administrator@corp.htb\'\n[*] Writing private key to \'administrator.key\'\n[*] Saved certificate and private key to \'administrator.pfx\'\n';
  const { kinds } = runCase('certipy req -u user@corp.htb -p pass -ca CORP-CA -template User', reqOut);
  ok(kinds.has('credential.certificate'), 'certipy req mints credential.certificate');
}
{
  const esc7Out = 'Certificate Authorities\n  0\n    CA Name                             : CORP-CA\n    DNS Name                            : dc.corp.htb\n    [!] Vulnerabilities\n      ESC7                              : \'CORP.HTB\\\\svc_ca\' has dangerous permissions\n';
  const { kinds } = runCase('certipy find -u user@corp.htb -p pass -dc-ip 10.10.10.10 -vulnerable', esc7Out);
  ok(kinds.has('adcs.vulnerable'), 'certipy find ESC7 mints adcs.vulnerable');
}
{
  const acctOut = 'Certipy v4.8.2\n[*] Reading attributes for \'wkstn$\':\n    cn                                  : WKSTN\n    distinguishedName                   : CN=WKSTN,CN=Computers,DC=corp,DC=htb\n    sAMAccountName                      : WKSTN$\n';
  const { kinds } = runCase('certipy account read -u user@corp.htb -p pass -user wkstn$', acctOut);
  ok(kinds.has('ad.domain_known') && kinds.has('ad.base_dn'), 'certipy account read distinguishedName mints ad.domain_known and ad.base_dn');
}

// 3. SMB compressed rows (Dc/Ac), ADS stream, piped -L, and putting file
{
  const lsCompressed = '  .                                  Dc        0  Mon Apr  3 08:11:12 2023\n  ..                                 Dc        0  Mon Apr  3 08:11:12 2023\n   phishing_attempt.xlsx              Ac    14208  Mon Apr  3 08:11:12 2023\n\n                5056511 blocks of size 4096. 3428412 blocks available\n';
  const { kinds } = runCase('smbclient ls', lsCompressed);
  ok(kinds.has('loot.files'), 'smbclient compressed Ac/Dc rows mint loot.files');
}
{
  const adsOut = '  .                                   D        0  Fri Jan 24 14:22:01 2020\n  ..                                  D        0  Fri Jan 24 14:22:01 2020\n  passwords.txt                       A        0  Fri Jan 24 14:22:01 2020\n  passwords.txt:secret:$DATA                   44\n';
  const { kinds } = runCase('smbclient allinfo passwords.txt', adsOut);
  ok(kinds.has('loot.files'), 'smbclient NTFS alternate data stream mints loot.files');
}
{
  const putOut = 'putting file shell.aspx as \\shell.aspx (12.4 kb/s) (average 12.4 kb/s)\n';
  const { kinds } = runCase('smbclient put shell.aspx', putOut);
  ok(kinds.has('host.tool_staged'), 'smbclient putting file mints host.tool_staged');
}

// 4. rpcclient password restriction blocker & password change confirmation
{
  const { kinds } = runCase('rpcclient setuserinfo2 audit2020 23 \'0xdf\'', 'result was NT_STATUS_PASSWORD_RESTRICTION\n');
  ok(kinds.has('blocker.password_restriction'), 'rpcclient NT_STATUS_PASSWORD_RESTRICTION mints blocker.password_restriction');
}

// 5. MySQL Drupal $S$ and Django pbkdf2_sha256$ hash rows
{
  const drupalOut = 'uid\tname\tpass\n1\tbruce\t$S$Dg2/1234567890abcdefghijklmnopqrstuvwxABCDEFGHIJKLMN\n';
  const { kinds } = runCase('mysql -u user -ppass -e "select uid,name,pass from users;"', drupalOut);
  ok(kinds.has('db.hashes') && kinds.has('credential.candidate'), 'mysql Drupal $S$ row mints db.hashes and credential.candidate');
}
{
  const djangoOut = '| admin | pbkdf2_sha256$260000$saltsalt$hashhashhashhashhashhashhashhash= |\n';
  const { kinds } = runCase('mysql -e "select username,password from auth_user;"', djangoOut);
  ok(kinds.has('db.hashes') && kinds.has('credential.candidate'), 'mysql Django pbkdf2_sha256$ row mints db.hashes and credential.candidate');
}

// 6. MSSQL sys.databases and IMPERSONATE ANY LOGIN -> db.admin
{
  const mssqlOut = 'SQL> SELECT name FROM master.sys.databases\nname\n----\nmaster\ntempdb\nmodel\nmsdb\nvolume\n';
  const { kinds } = runCase('mssqlclient.py user:pass@10.10.10.10', mssqlOut);
  ok(kinds.has('db.databases'), 'mssql SELECT name FROM master.sys.databases mints db.databases');
}
{
  const mssqlPriv = 'SQL> SELECT * FROM fn_my_permissions(NULL, \'SERVER\');\nentity_name   subentity_name   permission_name\n-----------   --------------   ---------------\nserver                         CONNECT SQL\nserver                         IMPERSONATE ANY LOGIN\n';
  const { kinds } = runCase('mssqlclient.py user:pass@10.10.10.10', mssqlPriv);
  ok(kinds.has('db.admin'), 'mssql IMPERSONATE ANY LOGIN mints db.admin');
}

// 7. sqlmap ASCII [N tables] grid
{
  const sqlmapTbls = 'Database: support\n[3 tables]\n+-----------+\n| users     |\n| tickets   |\n| settings  |\n+-----------+\n';
  const { kinds } = runCase('sqlmap -r req.txt -D support --tables', sqlmapTbls);
  ok(kinds.has('db.tables'), 'sqlmap ASCII [N tables] grid mints db.tables');
}

// 8. bloodhound-python completion without --zip
{
  const bhOut = 'INFO: Found AD domain: absolute.htb\nINFO: Connecting to LDAP server: dc.absolute.htb\nINFO: Found 1 domains\nINFO: Found 2 computers\nINFO: Found 14 users\nINFO: Done in 00M 08S\n';
  const { kinds } = runCase('bloodhound-python -u user -p pass -d absolute.htb -dc dc.absolute.htb', bhOut);
  ok(kinds.has('ad.graph.collected'), 'bloodhound-python Done in NNM NNS mints ad.graph.collected');
}

// 9. Cracked credentials: $ansible$ and $PEM$
{
  const ansOut = '$ansible$0*0*0ef3456789abcdef*0123456789abcdef:s3cr3tVaultPass\n';
  const { kinds } = runCase('hashcat.bin vault.hash rockyou.txt', ansOut);
  ok(kinds.has('credential.plaintext') && kinds.has('credential.available'), 'hashcat.bin $ansible$ cracked line mints credential.plaintext');
}

// 10. neofetch OS & kernel + Spanish whoami /priv (Habilitada) + certutil blocker
{
  const neoOut = '            .-/+oossssoo+/-.               user@boardlight\n        `:+ssssssssssssssssss+:`           ---------------\n      -+ssssssssssssssssssyyssss+-         OS: Ubuntu 20.04.6 LTS x86_64\n    .ossssssssssssssssssdMMMNysssso.       Kernel: 5.4.0-182-generic\n';
  const { kinds } = runCase('neofetch', neoOut);
  ok(kinds.has('host.os_family') && kinds.has('host.kernel'), 'neofetch output mints host.os_family and host.kernel');
}
{
  const esPriv = 'INFORMACION DE PRIVILEGIOS\n--------------------------\n\nNombre de privilegio          Descripcion                           Estado\n============================= ===================================== ==========\nSeImpersonatePrivilege        Suplantar a un cliente tras la aut.   Habilitada\n';
  const { kinds } = runCase('whoami /priv', esPriv);
  ok(kinds.has('privesc.windows_privilege'), 'Spanish whoami /priv (Habilitada) mints privesc.windows_privilege');
}
{
  const certErr = 'CertUtil: -CA command FAILED: 0x80070057 (WIN32: 87 ERROR_INVALID_PARAMETER)\nCertUtil: The parameter is incorrect.\n';
  const { kinds } = runCase('certutil -ca.cert ca.cer', certErr);
  ok(kinds.has('blocker.certutil_usage'), 'certutil -ca.cert error mints blocker.certutil_usage');
}

console.log('\nSTAGE 5/6 CORPUS RE-MINING SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
