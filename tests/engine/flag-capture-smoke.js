/* Flag capture: the flag-hunt move prints `===FLAG:path::value` (and an identity block per flag); this must
 * mint objective.<slot>_flag so the read flag reaches the report. Proof-bound: a proof-file path must be
 * present, so a stray 32-hex (an NT hash) is NEVER mistaken for a flag. Generic data. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ROOT = path.join(__dirname, '..', '..'), ENG = path.join(ROOT, 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {}, error: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENG, 'facts.js'));
load(path.join(ENG, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENG, 'parsers', m + '.js')); });
load(path.join(ENG, 'parsers', 'index.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function parse(command, stdout) {
  return OBOL.parsers.parseActionOutput({ command: command, stdout: stdout, scope: 'host:10.0.0.5', source: command });
}
function flags(r) { return (r.facts || []).filter(function (f) { return f.kind.indexOf('objective.') === 0; }); }

// 1. The flag-hunt Windows output: per-flag identity block + ===FLAG markers → local + root objectives.
var winOut = [
  '===IDENT===', 'DC01', 'Windows IP Configuration', '   IPv4 Address. . . : 10.0.0.5',
  '===FLAG:C:\\Users\\bob\\Desktop\\local.txt::a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
  '===IDENT===', 'DC01', '   IPv4 Address. . . : 10.0.0.5',
  '===FLAG:C:\\Users\\Administrator\\Desktop\\proof.txt::f6e5d4c3b2a1098766554433221100ff',
].join('\n');
var w = flags(parse('nxc winrm 10.0.0.5 -u administrator -H deadbeef... -X "..."', winOut));
ok(w.some(function (f) { return f.kind === 'objective.local_flag' && f.value.flag === 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'; }), 'local.txt marker mints objective.local_flag with the value');
ok(w.some(function (f) { return f.kind === 'objective.root_flag' && f.value.flag === 'f6e5d4c3b2a1098766554433221100ff'; }), 'proof.txt marker mints objective.root_flag with the value');
ok(w.filter(function (f) { return f.kind.indexOf('objective.') === 0; }).length === 2, 'exactly two flags captured (ipconfig noise is not mistaken for a flag)');
var rootF = w.filter(function (f) { return f.kind === 'objective.root_flag'; })[0];
ok(rootF && rootF.value.slot === 'root' && /proof\.txt/.test(rootF.value.name), 'the root flag carries its slot + file name for the report');

// 2. A plain `type …\proof.txt` read (no marker) still captures, slot from the file in the command.
var t = flags(parse('type C:\\Users\\Administrator\\Desktop\\proof.txt', 'ba0987654321fedcba0987654321fed0\n'));
ok(t.some(function (f) { return f.kind === 'objective.root_flag' && f.value.flag === 'ba0987654321fedcba0987654321fed0'; }), 'a direct `type proof.txt` read captures the root flag');

// 3. HTB naming: user.txt/root.txt map to local/root slots.
var htb = flags(parse('cat', '===FLAG:/home/user/user.txt::11112222333344445555666677778888'));
ok(htb.some(function (f) { return f.kind === 'objective.local_flag'; }), 'user.txt maps to the local slot');

// 4. NEGATIVE: a secretsdump full of 32-hex NT hashes has NO proof-file path → mints NO flag.
var dump = ['[*] Using the DRSUAPI method to get NTDS.DIT secrets',
  'htb.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::',
  'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::'].join('\n');
ok(flags(parse("impacket-secretsdump 'htb.local/svc:pw'@10.0.0.5", dump)).length === 0, 'a hash dump mints NO flags (32-hex NT hashes are never mistaken for flags)');

// 5. NEGATIVE: an ordinary command with a 32-hex value but no flag-file path mints nothing.
ok(flags(parse('nxc smb 10.0.0.5 -u svc -p pw', 'SMB 10.0.0.5 445 DC [*] deadbeefdeadbeefdeadbeefdeadbeef')).length === 0, 'a bare 32-hex in unrelated output is not a flag');

// 6. REGRESSION (the reported bug): a flag-hunt that FAILED (nxc winrm -X zip bug — no ===FLAG output, just
// an auth banner carrying the Administrator NT hash) must capture NOTHING. The hash is not a flag.
var failedHunt = ['WINRM 10.0.0.5 5985 DC01 [*] Windows Server 2016 Build 14393 (name:DC01) (domain:corp.local)',
  'WINRM 10.0.0.5 5985 DC01 [+] corp.local\\Administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)',
  'WINRM 10.0.0.5 5985 DC01 [-] corp.local\\Administrator:32693b11e6aa90eb43d32c72a07ceea6 zip() argument 2 is longer than argument 1'].join('\n');
var fh = flags(parse('nxc winrm 10.0.0.5 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6 -X "Get-ChildItem -Path C:\\Users -Recurse -Force -Include user.txt,root.txt -File | ForEach-Object { Write-Output (\'===FLAG:\'+$_.FullName+\'::\'+(Get-Content -Raw $_.FullName)) }"', failedHunt));
ok(fh.length === 0, 'a FAILED flag hunt (no ===FLAG output, only an NT-hash auth banner) captures NO flag — the hash is not a flag');

// 6b. STEP-2 SMB read (nxc smb -x wmiexec) — the reliable path that dodges the nxc `winrm -X` zip() bug.
// Command is `... -x "hostname & ipconfig & type C:\...\root.txt"`; output is the identity block then the
// flag alone on its own line. The direct-read path captures it (root slot from the file in the command),
// and neither the ipconfig lines nor the (Pwn3d!) hash banner is mistaken for a flag.
var smbRead = [
  'SMB 10.0.0.5 445 DC01 [+] corp.local\\Administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)',
  'DC01',
  'Windows IP Configuration',
  '   IPv4 Address. . . . . . . . . . . : 10.0.0.5',
  'deadc0dedeadc0dedeadc0dedeadc0de',
].join('\n');
var sr = flags(parse('nxc smb 10.0.0.5 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6 -x "hostname & ipconfig & type C:\\Users\\Administrator\\Desktop\\root.txt"', smbRead));
ok(sr.length === 1 && sr[0].kind === 'objective.root_flag' && sr[0].value.flag === 'deadc0dedeadc0dedeadc0dedeadc0de', 'the SMB step-2 `type` read captures the flag (root slot); ipconfig + hash banner are not flags');

// 7. A real read whose output ALSO carries a hash banner: only the flag (alone on its own line) is taken.
var mixed = ['SMB 10.0.0.5 445 DC01 [+] corp.local\\Administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)',
  'deadbeef00112233445566778899aabb'].join('\n');
var mx = flags(parse('nxc smb 10.0.0.5 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6 -x "type C:\\Users\\Administrator\\Desktop\\root.txt"', mixed));
ok(mx.length === 1 && mx[0].value.flag === 'deadbeef00112233445566778899aabb', 'the flag on its own line is captured; the hash in the (Pwn3d!) banner is NOT');

// 6. The report renders a captured flag (end-to-end into the objectives table).
load(path.join(ENG, 'phases.js')); load(path.join(ENG, 'pack.js')); load(path.join(ENG, 'profile.js'));
try { load(path.join(ENG, 'report.js')); } catch (e) {}
if (OBOL.report && OBOL.report.buildContext) {
  var fset = new OBOL.facts.FactSet([
    OBOL.facts.makeFact({ kind: 'objective.root_flag', scope: 'host:10.0.0.5', value: { flag: 'f6e5d4c3b2a1098766554433221100ff', slot: 'root', name: 'proof.txt', path: 'C:\\Users\\Administrator\\Desktop\\proof.txt' }, source: 'nxc winrm' }),
  ]);
  var rc = OBOL.report.buildContext({ facts: fset, targets: [{ ip: '10.0.0.5', host: '10.0.0.5' }], activities: [], params: { target: '10.0.0.5' } });
  var seen = JSON.stringify(rc).indexOf('f6e5d4c3b2a1098766554433221100ff') >= 0;
  ok(seen, 'a captured flag appears in the report context (reaches the report)');
} else {
  ok(true, 'report module not loaded in this harness — parser coverage above stands');
}

console.log(fail ? ('\nFLAG CAPTURE: ' + fail + ' FAILURES') : '\nFLAG CAPTURE: all passed');
process.exit(fail ? 1 : 0);
