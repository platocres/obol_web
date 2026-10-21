/* Evidence contracts for recovered material and scoped authentication observations. */
'use strict';
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = path.resolve(__dirname, '../..');
const sandbox = { console: { log() {}, warn() {} } };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
function load(file) { vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), sandbox, { filename: file }); }
load('assets/engine/facts.js');
load('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'index'].forEach(n => load('assets/engine/parsers/' + n + '.js'));
const O = sandbox.OBOL, C = O._parserCommon, A = '10.0.0.10', B = '10.0.0.20';
const HASH = '11223344556677889900aabbccddeeff';
let assertions = 0;
function check(test, message) { assert.ok(test, message); assertions++; }
function parse(stdout, opts = {}) {
  const result = O.parsers.parseActionOutput(Object.assign({ stdout, command: 'nxc smb ' + A, scope: 'host:' + A, domain: 'corp.local' }, opts));
  check(!(result.diagnostics || []).length, 'Supported parser sample produces no parser exception');
  return result.facts;
}
function has(facts, kind, scope) { return facts.some(f => f.kind === kind && f.state === 'supported' && (!scope || f.scope === scope)); }
function forbidden(facts, kinds, label) { kinds.forEach(k => check(!has(facts, k), label + ' cannot establish ' + k)); }
function attempt(overrides = {}) {
  return Object.assign({ target: A, targetDomain: 'corp.local', authRealm: 'corp.local', principal: 'corp.local\\alice', credentialId: 'credential-alice-v1', service: 'smb', attemptKey: 'alice-v1-on-a-smb', credential: { user: 'alice', domain: 'corp.local', password: 'FirstSecret!' } }, overrides);
}
function invoke(name, stdout, ws, command = '') {
  const facts = [];
  if (name === '_parse_gpp_decrypted') C[name](stdout, ws, command, facts);
  else C[name](stdout, ws, command, 'sample', facts);
  return facts;
}

for (const text of ['😀', '𝌆𠜎', '日本語\u0000é', '\uD83D', 'x'.repeat(65), 'x'.repeat(1000)]) {
  check(O.facts.fingerprint(text) === crypto.createHash('sha256').update(text).digest('hex'), 'Credential identity digest preserves Unicode and block boundaries');
}

const material = parse(fs.readFileSync(path.join(ROOT, 'tests/engine/fixtures/parser/outputs/laps_gmsa_material_not_access.txt'), 'utf8'), { command: 'nxc ldap ' + A + ' -M laps && gMSADumper.py -d corp.local' });
for (const [name, user] of [['WEB01', 'Administrator'], ['FILE01', 'Adm-LAPS']]) {
  const recovered = material.find(f => f.kind === 'credential.available' && f.scope === 'host:' + name);
  check(recovered && recovered.value.user === user, 'Each recovered LAPS secret remains usable only for its named computer');
  check(recovered.value.computer === name + '$' && recovered.value.targetBinding === name && recovered.value.accountType === 'local', 'LAPS material retains local computer binding');
  check(!recovered.value.domain && recovered.value.realm === name, 'LAPS local identity is not converted into a domain account');
}
check(!material.some(f => f.kind === 'credential.available' && f.scope === 'domain:corp.local'), 'LAPS local credentials do not become domain-wide candidates');
check(material.some(f => f.kind === 'credential.ntlm_hash' && f.value.user === 'svc_web$' && f.value.accountType === 'domain'), 'gMSA recovery retains its domain account identity');
forbidden(material, ['credential.validated', 'credential.admin', 'access.admin', 'access.system', 'foothold.windows'], 'Recovered LAPS/gMSA material');

const ntds = parse('other.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:' + HASH + ':::\nother.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:' + HASH + ':::', { command: 'secretsdump.py -just-dc' });
check(has(ntds, 'loot.ntds', 'domain:other.local') && has(ntds, 'credential.available', 'domain:other.local'), 'NTDS recovery follows the domain named by the dump');
forbidden(ntds, ['credential.admin', 'credential.validated', 'access.admin', 'access.system'], 'Recovered NTDS hashes');
const sam = parse('Administrator:500:aad3b435b51404eeaad3b435b51404ee:' + HASH + ':::', { command: 'secretsdump.py -sam SAM -system SYSTEM LOCAL' });
check(has(sam, 'hash.ntlm', 'host:' + A) && has(sam, 'credential.available', 'host:' + A), 'Local SAM hashes stay on the host even when a domain is known');
forbidden(sam, ['credential.admin', 'credential.validated', 'access.admin'], 'Recovered SAM hash');

for (const user of ['david', 'administrator', 'krbtgt']) {
  const cert = parse("[+] Got hash for '" + user + "@other.local': " + HASH, { command: 'certipy auth' });
  check(has(cert, 'credential.available', 'domain:other.local'), 'Certipy recovery preserves the observed identity realm');
  forbidden(cert, ['credential.admin', 'access.admin', 'access.system'], 'Certipy account name ' + user);
}

const gppWs = { target: A, domainSeed: 'corp.local', facts: [], seedFacts: [] };
const gppUnknown = invoke('_parse_gpp_decrypted', 'DecryptedSecret!', gppWs, 'gpp-decrypt sample');
check(gppUnknown.some(f => f.kind === 'credential.candidate' && f.value.association === 'unresolved' && !f.value.user), 'A decrypted bare secret keeps an unresolved identity');
forbidden(gppUnknown, ['credential.available', 'credential.validated', 'credential.admin'], 'Unassociated offline GPP secret');
const gppSeed = O.facts.makeFact({ kind: 'credential.candidate', scope: 'host:' + A, value: { kind: 'gpp_cpassword', user: 'alice', count: 1, domain: 'corp.local' } });
const gppKnown = invoke('_parse_gpp_decrypted', 'DecryptedSecret!', Object.assign({}, gppWs, { facts: [gppSeed] }), 'gpp-decrypt sample');
check(gppKnown.some(f => f.kind === 'credential.available' && f.value.user === 'alice'), 'Unambiguous GPP material association remains available for deliberate use');
forbidden(gppKnown, ['credential.validated', 'credential.admin', 'access.admin'], 'Offline GPP decryption');
const gppAmbiguous = invoke('_parse_gpp_decrypted', 'DecryptedSecret!', Object.assign({}, gppWs, { facts: [gppSeed, O.facts.makeFact({ kind: 'credential.candidate', scope: 'host:' + A, value: { kind: 'gpp_cpassword', user: 'bob', count: 1 } })] }), 'gpp-decrypt sample');
check(!gppAmbiguous.some(f => f.kind === 'credential.available'), 'Multiple GPP candidates do not assign the first username arbitrarily');

const accepted = parse('SMB ' + A + ' 445 DC01 [+] corp.local\\alice:FirstSecret!', { context: attempt() });
const auth = accepted.find(f => f.kind === 'credential.validated');
check(auth && auth.scope === 'host:' + A && auth.value.service === 'smb' && auth.value.principal === 'corp.local\\alice', 'Login success has exact host, principal and service');
check(auth.value.credentialId === 'credential-alice-v1' && auth.value.attemptKey === 'alice-v1-on-a-smb', 'Matching output binds to the selected credential version and attempt');
check(auth.value.credentialFingerprint && !auth.value.password, 'Validation retains secret identity without duplicating its plaintext');
forbidden(accepted, ['access.admin', 'foothold.windows', 'access.shell'], 'A switchless authentication success');
for (const [name, line] of [
  ['different principal', 'SMB ' + A + ' 445 DC01 [+] corp.local\\bob:FirstSecret!'],
  ['different host', 'SMB ' + B + ' 445 FILE01 [+] corp.local\\alice:FirstSecret!'],
  ['different service', 'LDAP ' + A + ' 389 DC01 [+] corp.local\\alice:FirstSecret!'],
  ['different realm', 'SMB ' + A + ' 445 DC01 [+] other.local\\alice:FirstSecret!'],
  ['different secret', 'SMB ' + A + ' 445 DC01 [+] corp.local\\alice:RotatedSecret!']
]) {
  const facts = parse(line, { context: attempt() });
  const observation = facts.find(f => f.kind === 'credential.validated');
  check(observation && !observation.value.credentialId, name + ' cannot inherit the selected credential ID');
}
const masked = parse('SMB ' + A + ' 445 DC01 [+] corp.local\\alice:********', { context: attempt() });
check(has(masked, 'smb.authenticated') && !has(masked, 'credential.available'), 'Masked success can prove authentication without manufacturing a saved password');
check(masked.find(f => f.kind === 'credential.validated').value.credentialId === 'credential-alice-v1', 'Masked output can retain its explicit matching command association');
const noRealm = parse('SMB ' + A + ' 445 DC01 [+] alice:FirstSecret!');
check(noRealm.some(f => f.kind === 'credential.available' && f.scope === 'host:' + A && !f.value.domain && !f.value.realm), 'A target domain does not invent the authentication realm of an unqualified username');
const localLogin = parse('SMB ' + A + ' 445 DC01 [+] DC01\\Administrator:FirstSecret!');
check(localLogin.some(f => f.kind === 'credential.available' && f.scope === 'host:' + A && f.value.accountType === 'local' && !f.value.domain && f.value.realm === 'dc01'), 'An observed local account stays host-bound rather than becoming a domain account');

for (const [service, user] of [['SMB', 'Administrator'], ['WINRM', 'Administrator'], ['SSH', 'root']]) {
  const facts = parse(service + ' ' + A + ' 445 DC01 [+] corp.local\\' + user + ':FirstSecret!');
  check(has(facts, service.toLowerCase() + '.authenticated'), 'Service authentication remains recognized for ' + service);
  forbidden(facts, ['access.admin', 'foothold.windows', 'foothold.linux', 'access.shell'], service + ' login without execution/privilege evidence');
}
const pwned = parse('SMB ' + A + ' 445 DC01 [+] corp.local\\alice:FirstSecret! (Pwn3d!)');
check(has(pwned, 'access.admin', 'host:' + A), 'Explicit SMB administrative authorization remains recognized');
const sqlAdmin = parse('MSSQL ' + A + ' 1433 DC01 [+] corp.local\\alice:FirstSecret! (Pwn3d!)', { command: 'nxc mssql ' + A });
check(has(sqlAdmin, 'db.admin', 'host:' + A) && !has(sqlAdmin, 'access.admin'), 'MSSQL sysadmin authorization is not Windows administrator access');

const rejected = parse('SMB ' + B + ' 445 FILE01 [-] other.local\\alice:FirstSecret! STATUS_LOGON_FAILURE', { context: attempt() });
const rejection = rejected.find(f => f.kind === 'credential.validation');
check(rejection && rejection.scope === 'host:' + B && rejection.state === 'refuted' && rejection.value.user === 'alice' && rejection.value.domain === 'other.local' && rejection.value.service === 'smb', 'A rejected login is scoped to its observed host, identity and service');
check(!rejection.value.credentialId && !rejected.some(f => f.kind === 'credential.available' && f.state === 'refuted'), 'An unrelated failure neither selects nor invalidates a saved credential globally');
const denied = parse('SMB ' + A + ' 445 DC01 [+] corp.local\\alice:FirstSecret!\nSMB ' + A + ' 445 DC01 [-] Error enumerating shares: STATUS_ACCESS_DENIED', { context: attempt() });
check(has(denied, 'smb.authenticated') && has(denied, 'credential.authorization'), 'An operation denial preserves independent authentication success');
check(!denied.some(f => f.kind === 'credential.validation' && f.state === 'refuted'), 'Authorization denial is not a rejected password');
const denial = denied.find(f => f.kind === 'credential.authorization');
check(denial.value.credentialId === 'credential-alice-v1' && denial.value.stage === 'authorization', 'A denial with no username can use its explicit matching attempt context');
const mixed = parse('SMB ' + A + ' 445 DC01 [+] corp.local\\alice:FirstSecret!\nSMB ' + B + ' 445 FILE01 [-] corp.local\\alice:FirstSecret! STATUS_LOGON_FAILURE', { context: attempt() });
check(has(mixed, 'smb.authenticated', 'host:' + A) && !has(mixed, 'smb.authenticated', 'host:' + B), 'Mixed host output keeps each positive result on its own host');
check(mixed.filter(f => f.kind === 'credential.validation').every(f => f.scope === 'host:' + B && !f.value.credentialId), 'Mixed host failures cannot acquire another host attempt ID');

const skew = parse('SMB ' + B + ' 445 FILE01 [-] other.local\\bob:FirstSecret! KRB_AP_ERR_SKEW', { context: attempt() });
check(skew.filter(f => f.kind === 'blocker.clock_skew').every(f => f.scope === 'host:' + B && !f.value.credentialId), 'Authentication barriers are host-specific and retain mismatched attempt boundaries');
const passwordChange = parse('SMB ' + A + ' 445 DC01 [-] corp.local\\alice:FirstSecret! STATUS_PASSWORD_MUST_CHANGE', { context: attempt() });
check(passwordChange.some(f => f.kind === 'blocker.password_change' && f.scope === 'host:' + A && f.value.credentialId === 'credential-alice-v1'), 'Password-change barriers carry the selected matching credential context');

const banner = parse('Evil-WinRM shell v3.5\nEstablishing connection...', { command: 'evil-winrm -i ' + A + ' -u alice -p FirstSecret!' });
forbidden(banner, ['winrm.authenticated', 'foothold.windows'], 'A tool banner before connection');
const shell = parse('*Evil-WinRM* PS C:\\Users\\alice> whoami\ncorp\\alice', { command: 'evil-winrm -i ' + A + ' -u alice -p FirstSecret!', context: attempt({ service: 'winrm' }) });
check(has(shell, 'winrm.authenticated') && has(shell, 'foothold.windows'), 'An actual authenticated shell prompt still establishes foothold');
const hydra = parse('[22][ssh] host: ' + B + ' login: alice password: FirstSecret!', { command: 'hydra -L users.txt ssh://' + A, context: attempt({ service: 'ssh' }) });
check(has(hydra, 'credential.validated', 'host:' + B) && !has(hydra, 'credential.validated', 'host:' + A), 'Online validator output follows the observed host');
check(hydra.filter(f => f.kind === 'credential.validated').every(f => !f.value.credentialId), 'A different online-validation host cannot inherit selected credentials');

const unknown = parse('Connection opened. Operation started... [output truncated]', { context: attempt() });
forbidden(unknown, ['credential.available', 'credential.validated', 'credential.authorization', 'access.admin', 'access.shell'], 'Unknown or truncated output');
for (const name of ['linux_privesc_fixture_leads_only', 'linpeas_ansi_kernel_caps']) {
  const scan = parse(fs.readFileSync(path.join(ROOT, 'tests/engine/fixtures/parser/outputs/' + name + '.txt'), 'utf8'), { command: name.indexOf('linpeas') === 0 ? 'sh /dev/shm/linpeas.sh' : 'id; uname -a; sudo -l; find / -perm -4000; getcap -r /', actionId: 'linux-enum' });
  check(has(scan, 'privesc.leads') && has(scan, 'host.kernel'), 'Local scan identity and privilege leads remain recognized');
  forbidden(scan, ['access.shell', 'foothold.linux', 'access.admin', 'access.system'], 'Enumeration report ' + name);
}
const bareIdentity = parse('uid=1000(alice) gid=1000(alice) groups=1000(alice)', { command: 'id' });
check(has(bareIdentity, 'access.shell') && has(bareIdentity, 'foothold.linux'), 'A direct id result still establishes execution');
check(!bareIdentity.some(f => f.kind === 'access.shell' && f.value.service === 'ssh'), 'A bare identity result does not invent an SSH transport');
const namedRoot = parse('uid=1000(root) gid=1000(root) groups=1000(root)', { command: 'id' });
check(!has(namedRoot, 'access.admin'), 'A root account name with a nonzero UID does not establish root privilege');
const actualRoot = parse('uid=0(operator) gid=0(root) groups=0(root)', { command: 'id' });
check(has(actualRoot, 'access.admin'), 'Observed UID zero establishes privilege regardless of username');
const systemMention = parse('Service account: NT AUTHORITY\\SYSTEM\nSeImpersonatePrivilege Impersonate a client after authentication Enabled', { command: 'winPEASx64.exe', actionId: 'windows-enum' });
check(!has(systemMention, 'access.system'), 'A service-account description in enumeration does not establish the operator is SYSTEM');
const systemIdentity = parse('nt authority\\system', { command: 'whoami', actionId: 'windows-enum' });
check(has(systemIdentity, 'access.system'), 'An observed SYSTEM identity line remains supported');
const forced = parse('SMB ' + B + ' 445 FILE01 [+] corp.local\\alice:FirstSecret!', { context: attempt({ forceTarget: A }) });
check(has(forced, 'smb.authenticated', 'host:' + A) && !has(forced, 'smb.authenticated', 'host:' + B), 'Explicit force-route preserves the user-selected destination');
check(forced.find(f => f.kind === 'credential.validated').value.observedTarget === B, 'Forced routing retains the observed source host for review');
const previous = new O.facts.FactSet(accepted.concat(rejected));
check(previous.has('smb.authenticated') && previous.facts.some(f => f.kind === 'credential.validation' && f.scope === 'host:' + B), 'Success and later unrelated denial coexist without erasing the original observation');
console.log('Parser proof regressions: ' + assertions + ' assertions passed.');
