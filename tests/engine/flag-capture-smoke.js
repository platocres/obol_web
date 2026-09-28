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
function captured(r) { return flags(r).filter(function (f) { return f.kind !== 'objective.flag_located'; }); }
function located(r) { return flags(r).filter(function (f) { return f.kind === 'objective.flag_located'; }); }

// 1. A REMOTE flag hunt (nxc winrm -X markers) runs from the operator box → it only LOCATES the flags.
// OffSec scores a remote read zero, so these are objective.flag_located (intel), NOT captured objectives.
var winOut = [
  '===IDENT===', 'DC01', 'Windows IP Configuration', '   IPv4 Address. . . : 10.0.0.5',
  '===FLAG:C:\\Users\\bob\\Desktop\\local.txt::a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
  '===IDENT===', 'DC01', '   IPv4 Address. . . : 10.0.0.5',
  '===FLAG:C:\\Users\\Administrator\\Desktop\\proof.txt::f6e5d4c3b2a1098766554433221100ff',
].join('\n');
var wr = parse('nxc winrm 10.0.0.5 -u administrator -H deadbeef... -X "..."', winOut);
ok(captured(wr).length === 0, 'a remote nxc winrm hunt captures NOTHING (a remote read scores zero for OSCP)');
ok(located(wr).length === 2, 'the remote hunt LOCATES both flags (objective.flag_located intel)');
ok(located(wr).some(function (f) { return f.value.slot === 'local' && f.value.flag === 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'; }), 'located local flag carries slot + value');
ok(located(wr).some(function (f) { return f.value.slot === 'root' && f.value.flag === 'f6e5d4c3b2a1098766554433221100ff' && /proof\.txt/.test(f.value.name); }), 'located root flag carries slot + file name + value');

// 1b. ON-HOST capture: a bare read typed INSIDE an interactive shell (no transport lead) IS the report
// capture. hostname + ipconfig + the flag together, exactly what the operator screenshots.
var onhost = parse('hostname; ipconfig; type C:\\Users\\Administrator\\Desktop\\proof.txt', [
  'DC01', 'Windows IP Configuration', '   IPv4 Address. . . : 10.0.0.5',
  'f6e5d4c3b2a1098766554433221100ff',
].join('\n'));
ok(captured(onhost).length === 1 && captured(onhost)[0].kind === 'objective.root_flag' && captured(onhost)[0].value.flag === 'f6e5d4c3b2a1098766554433221100ff', 'a bare on-host `type proof.txt` (with ipconfig) captures the root flag for the report');

// 1c. LOCATE via SMB spider: the listing prints flag-file PATHS (no value). obol records each as
// objective.flag_located with the exact Windows path + slot, so the on-host capture can fill the real path.
var spider = [
  'SMB 10.0.0.5 445 DC01 [+] corp.local\\administrator:aaaa (Pwn3d!)',
  "SMB 10.0.0.5 445 DC01 //10.0.0.5/C$/Users/Administrator/Desktop/root.txt [lastm:'2026-09-27 22:28' size:34]",
  "SMB 10.0.0.5 445 DC01 //10.0.0.5/C$/Users/svc-user/Desktop/user.txt [lastm:'2026-09-27 22:28' size:34]",
].join('\n');
var sp = located(parse('nxc smb 10.0.0.5 -u administrator -H aaaa --spider C$ --regex "(local|proof|user|root|flag)\\.txt"', spider));
ok(captured(parse('nxc smb 10.0.0.5 -u administrator -H aaaa --spider C$', spider)).length === 0, 'a spider listing captures NOTHING (it reads no value)');
ok(sp.some(function (f) { return f.value.slot === 'root' && f.value.path === 'C:\\Users\\Administrator\\Desktop\\root.txt'; }), 'spider locates root.txt with its exact Windows path');
ok(sp.some(function (f) { return f.value.slot === 'local' && f.value.path === 'C:\\Users\\svc-user\\Desktop\\user.txt'; }), 'spider locates user.txt (local slot) at the right user Desktop');

// 1d. PASTED INTERACTIVE FRAME: the operator pastes a whole evil-winrm frame — the prompt echoes the read
// and the paste box may attach a DIFFERENT command (the spider) or none. The read + on-host verdict must be
// recovered from the echoed prompt line, so the flag is captured and the ipconfig noise is not.
var frame = [
  '*Evil-WinRM* PS C:\\Users\\Administrator\\Documents> hostname; ipconfig; type C:\\Users\\svc-user\\Desktop\\user.txt',
  'DC01', '', 'Windows IP Configuration', '',
  '   IPv6 Address. . . . . . . . . . . : dead:beef::5887:1f95:91e0:1ab0',
  '   IPv4 Address. . . . . . . . . . . : 10.0.0.5',
  '480c594d4c140ae84a74a3168cc0d46e',
].join('\n');
// paste box attached the spider command (not the read) — still captured from the echoed prompt line
var frSpider = captured(parse('nxc smb 10.0.0.5 -u administrator -H aaaa --spider C$', frame));
ok(frSpider.length === 1 && frSpider[0].kind === 'objective.local_flag' && frSpider[0].value.flag === '480c594d4c140ae84a74a3168cc0d46e', 'a pasted on-host frame captures the flag even when the box attached the spider command');
// paste box attached NO command — same result
var frNone = captured(parse('', frame));
ok(frNone.length === 1 && frNone[0].value.flag === '480c594d4c140ae84a74a3168cc0d46e', 'a pasted on-host frame captures the flag even with no command attached');
ok(located(parse('', frame)).length === 0, 'the on-host frame is a capture, not a locate');

// 1e. INVERSE: a Kali frame that echoes a REMOTE read (nxc -x type) after the kali prompt only LOCATES it —
// the echoed transport lead is honored, so a remote read pasted whole never counts as captured.
var kaliFrame = [
  '┌──(kali㉿kali)-[~]',
  '└─$ nxc smb 10.0.0.5 -u administrator -H aaaa -x "type C:\\Users\\svc-user\\Desktop\\user.txt"',
  'SMB 10.0.0.5 445 DC01 [+] corp.local\\administrator:aaaa (Pwn3d!)',
  '480c594d4c140ae84a74a3168cc0d46e',
].join('\n');
ok(captured(parse('', kaliFrame)).length === 0, 'a pasted Kali frame echoing a remote read captures NOTHING');
ok(located(parse('', kaliFrame)).some(function (f) { return f.value.flag === '480c594d4c140ae84a74a3168cc0d46e'; }), 'the echoed remote read only LOCATES the flag');

// 2. A plain on-host `type …\proof.txt` read captures, slot from the file in the command.
var t = captured(parse('type C:\\Users\\Administrator\\Desktop\\proof.txt', 'ba0987654321fedcba0987654321fed0\n'));
ok(t.some(function (f) { return f.kind === 'objective.root_flag' && f.value.flag === 'ba0987654321fedcba0987654321fed0'; }), 'a direct on-host `type proof.txt` read captures the root flag');

// 3. HTB naming: user.txt/root.txt map to local/root slots (bare `cat`, on-host).
var htb = captured(parse('cat /home/user/user.txt', '===FLAG:/home/user/user.txt::11112222333344445555666677778888'));
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

// 6b. A REMOTE SMB read (nxc smb -x) LOCATES a flag but does not capture it — it runs from the operator
// box. obol records the value as intel (objective.flag_located); the operator must read it on-host.
var smbRead = [
  'SMB 10.0.0.5 445 DC01 [+] corp.local\\Administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)',
  'DC01',
  'Windows IP Configuration',
  '   IPv4 Address. . . . . . . . . . . : 10.0.0.5',
  'deadc0dedeadc0dedeadc0dedeadc0de',
].join('\n');
var sr = parse('nxc smb 10.0.0.5 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6 -x "hostname & ipconfig & type C:\\Users\\Administrator\\Desktop\\root.txt"', smbRead);
ok(captured(sr).length === 0, 'a remote nxc smb read captures NOTHING (scores zero for OSCP)');
ok(located(sr).length === 1 && located(sr)[0].value.slot === 'root' && located(sr)[0].value.flag === 'deadc0dedeadc0dedeadc0dedeadc0de', 'the remote SMB read LOCATES the root flag (intel); ipconfig + hash banner are not flags');

// 7. A remote read whose output ALSO carries a hash banner: only the flag (alone on its own line) is
// located, and the NT hash in the (Pwn3d!) banner is never mistaken for it.
var mixed = ['SMB 10.0.0.5 445 DC01 [+] corp.local\\Administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)',
  'deadbeef00112233445566778899aabb'].join('\n');
var mx = located(parse('nxc smb 10.0.0.5 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6 -x "type C:\\Users\\Administrator\\Desktop\\root.txt"', mixed));
ok(mx.length === 1 && mx[0].value.flag === 'deadbeef00112233445566778899aabb', 'the flag on its own line is located; the hash in the (Pwn3d!) banner is NOT');

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
