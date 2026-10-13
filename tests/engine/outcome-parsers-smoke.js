/* Outcome parsers + reuse-loop wiring (decision-map gap fills, phases 1-2):
 *  - a looted/cracked plaintext credential becomes a usable credential (credential.available),
 *    so the 31 downstream moves that need one can fire;
 *  - a DB login mints db.session (unlocks loot / xp_cmdshell);
 *  - domain trusts, a Zerologon verdict, ADCS vulnerable templates and an issued certificate all
 *    read back now, so their chains advance instead of dead-ending. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack;
var fs = require('fs'), pdir = path.join(R, 'data/packs'), bundle = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); });
var A = PK.loadPacks(Object.keys(bundle).map(function (k) { return bundle[k]; }));
var by = {}; A.forEach(function (m) { by[m.id] = m; });
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');
req('data/field-notes.js');   // OBOL.FIELD_DOCTORS — the reactive fix-cards surfaced on a failed-command paste

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function run(cmd, out, aid) { var r = OBOL.parsers.parseActionOutput({ actionId: aid || '', command: cmd, stdout: out, scope: 'host:10.10.10.10', domain: 'acme.local' }); return (r.facts || []).map(function (f) { return f.kind; }); }
function prod(id) { return (by[id] && by[id].produces) || []; }

// --- Phase 1: the loot -> reuse loop is closed ---
ok(prod('lsass-dump-onbox').indexOf('credential.available') >= 0, 'an LSASS dump yields a usable credential (credential.available)');
['dpapi-secrets', 'stored-credentials', 'crack-netntlmv2', 'crack-ntlm'].forEach(function (id) {
  ok(prod(id).indexOf('credential.available') >= 0, id + ' produces a usable credential');
});
// nosql-injection is a WEB auth bypass, not an OS win: it must NOT claim access.admin or a validated
// credential — only the app-level bypass and candidate material it can extract (gate-audit, web batch).
ok(prod('nosql-injection').indexOf('access.admin') < 0, 'nosql-injection does NOT claim access.admin (app bypass, not OS win)');
ok(prod('nosql-injection').indexOf('web.authz_bypass') >= 0 && prod('nosql-injection').indexOf('credential.candidate') >= 0, 'nosql-injection produces web.authz_bypass + credential.candidate (honest)');
ok(prod('manual-sqli-exploitation').indexOf('credential.candidate') >= 0, 'SQLi-dumped creds enter the crack/reuse loop (credential.candidate)');
// Loot value-chain: pulling a file a share-spider flagged and pasting it must mint the fact that lights the
// NEXT move — a found-then-pasted thing generates the follow-up, not a dead end.
var pem = run('cat id_rsa', '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----');
ok(pem.indexOf('credential.certificate') >= 0, 'a pasted private key mints credential.certificate (→ ssh-key-login)');
ok([].concat(by['ssh-key-login'].requires_all || [], by['ssh-key-login'].requires_any || []).indexOf('credential.certificate') >= 0, 'ssh-key-login consumes credential.certificate (the key chains to a foothold)');
var cfg = run('cat web.config', '<add name="db" connectionString="Server=sql;Initial Catalog=app;User Id=sa;Password=P@ssw0rd123;"/>');
ok(cfg.indexOf('credential.candidate') >= 0, 'a pasted connection-string password mints credential.candidate');
ok(run('cat notes.txt', 'notes about the meeting tomorrow, nothing secret here').length === 0, 'a plain-text paste with no secret mints nothing (no false positive)');
// the usable-credential fact really has downstream consumers (so the loop advances the coach)
var consumers = A.filter(function (m) { return [].concat(m.requires_all || [], m.requires_any || []).indexOf('credential.available') >= 0; });
ok(consumers.length >= 20, 'credential.available drives many downstream moves (' + consumers.length + ')');

// --- Phase 2: db.session ---
ok(run("mysql -h 10.10.10.10 -u root --password= -e 'SHOW DATABASES;'", 'Database\ninformation_schema\nmysql\nwebapp').indexOf('db.session') >= 0, 'a successful MySQL login mints db.session');
ok(run('mssqlclient.py acme/sa:p@10.10.10.10', '[*] ENVCHANGE(DATABASE): master\nSQL (ACME\\sa  dbo@master)> ').indexOf('db.session') >= 0, 'a successful MSSQL login mints db.session');
ok(run("mysql -h 10.10.10.10 -u root -pwrong -e 'SHOW DATABASES;'", 'ERROR 1045 (28000): Access denied for user').indexOf('db.session') < 0, 'a denied DB login mints no session');
ok(prod('mysql-loot').length && [].concat(by['mysql-loot'].requires_all || [], by['mysql-loot'].requires_any || []).indexOf('db.session') >= 0, 'mysql-loot requires db.session (now reachable)');

// --- Phase 2: AD trusts / zerologon / ADCS ---
ok(run('nltest /domain_trusts', 'List of domain trusts:\n    0: ACME acme.local (NT 5) (Forest Tree Root)\n    1: CHILD child.acme.local (NT 5) (Direct Outbound)', 'trust-enum').indexOf('ad.trusts') >= 0, 'domain-trust enumeration mints ad.trusts');
ok(run('zerologon-scan DC01 10.10.10.10', 'Success! DC can be fully compromised by a Zerologon attack.', 'zerologon-check').indexOf('ad.zerologon') >= 0, 'a Zerologon success verdict mints ad.zerologon');
ok(run('zerologon-scan DC01 10.10.10.10', 'The target DC is not vulnerable to Zerologon (patched).', 'zerologon-check').indexOf('ad.zerologon') < 0, 'a patched Zerologon scan mints nothing');
ok(run('certipy find -vulnerable -dc-ip 10.10.10.10', 'Template Name  : UserAuth\n    [!] Vulnerabilities\n      ESC1 : Enrollee supplies subject', 'adcs-esc').indexOf('adcs.vulnerable') >= 0, 'certipy find -vulnerable mints adcs.vulnerable');
ok(run('certipy req -ca ACME-CA -template UserAuth', "Saved certificate and private key to 'administrator.pfx'", 'adcs-esc').indexOf('credential.certificate') >= 0, 'an issued certificate mints credential.certificate');
ok([].concat(by['zerologon-exploit'].requires_all || [], by['zerologon-exploit'].requires_any || []).indexOf('ad.zerologon') >= 0, 'zerologon-exploit requires ad.zerologon (now reachable)');
ok([].concat(by['cert-authenticate'].requires_all || [], by['cert-authenticate'].requires_any || []).indexOf('credential.certificate') >= 0, 'cert-authenticate requires credential.certificate (now reachable)');

// --- Auth/access failure awareness (reorder moves + surface a doctor when a failed command is pasted) ---
// (1) Anonymous LDAP bind accepted but search denied: the DC prints `[+] domain\:` yet errors the SEARCH
// (`searchRequest -> operationsError ... a successful bind must be completed`). This must NOT mint
// ad.anonymous_bind (that would advance to a --users dump that fails); blockers.js mints
// blocker.ldap_anonymous_disabled, which obsoletes the anonymous-enum move so its dead commands disappear.
var ldapDenied = run("nxc ldap 10.10.10.10 -u '' -p ''",
  'LDAP        10.10.10.10   389    DC   [*] Windows Server 2008 R2 (name:DC) (domain:acme.local) (signing:None)\n' +
  'LDAP        10.10.10.10   389    DC   [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C09075A, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v1db1\n' +
  'LDAP        10.10.10.10   389    DC   [+] acme.local\\: ');
ok(ldapDenied.indexOf('blocker.ldap_anonymous_disabled') >= 0, 'anon LDAP search-denied mints blocker.ldap_anonymous_disabled');
ok(ldapDenied.indexOf('ad.anonymous_bind') < 0, 'anon LDAP search-denied does NOT mint ad.anonymous_bind (no dead --users dump)');
var ldapOk = run("nxc ldap 10.10.10.10 -u '' -p ''", 'LDAP        10.10.10.10   389    DC   [+] acme.local\\: ');
ok(ldapOk.indexOf('ad.anonymous_bind') >= 0, 'a genuinely open anonymous bind still mints ad.anonymous_bind');
ok((by['ad-anon-ldap-enum'].obsoleted_by || []).indexOf('blocker.ldap_anonymous_disabled') >= 0, 'ad-anon-ldap-enum is obsoleted_by blocker.ldap_anonymous_disabled (anonymous commands disappear)');

// (2) Null/anonymous SMB session rejected: an anon attempt that returns STATUS_ACCESS_DENIED with no
// session mints blocker.smb_null_denied, which obsoletes recon-smb-anon. A working null session must NOT mint it.
var smbDenied = run("nxc smb 10.10.10.10 -u '' -p '' --shares",
  'SMB         10.10.10.10   445    DC   [*] Windows Server 2019 (name:DC) (domain:acme.local) (signing:True) (SMBv1:False)\n' +
  'SMB         10.10.10.10   445    DC   [-] acme.local\\: STATUS_ACCESS_DENIED ');
ok(smbDenied.indexOf('blocker.smb_null_denied') >= 0, 'rejected null SMB session mints blocker.smb_null_denied');
var smbOk = run("nxc smb 10.10.10.10 -u '' -p '' --shares",
  'SMB         10.10.10.10   445    DC   [*] Windows 7 (name:DC) (domain:acme.local) (signing:False) (SMBv1:True) (Null Auth:True)\n' +
  'SMB         10.10.10.10   445    DC   [+] acme.local\\: ');
ok(smbOk.indexOf('blocker.smb_null_denied') < 0 && smbOk.indexOf('smb.null_session') >= 0, 'a working null session mints smb.null_session, NOT blocker.smb_null_denied');
ok((by['recon-smb-anon'].obsoleted_by || []).indexOf('blocker.smb_null_denied') >= 0, 'recon-smb-anon is obsoleted_by blocker.smb_null_denied');

// (3) Bad credential (failed login) mints blocker.logon_failure (its doctor advises on it); (4) an account
// lockout mints blocker.lockout, and the spray/brute moves deprioritize on it so the coach stops leading
// with a spray that is now dangerous.
ok(run('nxc smb 10.10.10.10 -u bob -p wrongpass', 'SMB  10.10.10.10  445  DC  [-] acme.local\\bob:wrongpass STATUS_LOGON_FAILURE').indexOf('blocker.logon_failure') >= 0, 'a failed login mints blocker.logon_failure');
ok(run('nxc smb 10.10.10.10 -u bob -p Spring2026', 'SMB  10.10.10.10  445  DC  [-] acme.local\\bob:Spring2026 STATUS_ACCOUNT_LOCKED_OUT').indexOf('blocker.lockout') >= 0, 'a lockout response mints blocker.lockout');
['password-spray', 'online-brute-ssh', 'online-brute-ftp', 'online-brute-rdp', 'web-login-brute', 'blind-brute-ssh'].forEach(function (id) {
  ok((by[id].deprioritize_when || []).indexOf('blocker.lockout') >= 0, id + ' deprioritizes on blocker.lockout (back off spraying once an account locks)');
});
['blocker.logon_failure', 'blocker.ldap_anonymous_disabled', 'blocker.smb_null_denied'].forEach(function (k) {
  ok(!!(OBOL.FIELD_DOCTORS && OBOL.FIELD_DOCTORS[k]), 'a fix-card doctor exists for ' + k + ' (advice surfaces on the failed paste)');
});

console.log('\nOUTCOME PARSERS SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
