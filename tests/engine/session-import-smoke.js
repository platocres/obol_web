/* Whole-session import: an operator pastes (or attaches) a full terminal capture — many commands and
 * their output at once — and obol catches up on the entire box in one pass. This proves the SPLITTER
 * carves the capture into correct per-command segments (handling the Kali two-line prompt, the obol
 * precmd time-stamp line, heredocs, and PowerShell), that multi-file captures stitch chronologically by
 * timestamp, that duplicates are dropped, and that the reconstructed segments drive the real parse→coach
 * pipeline to the same facts as if each had been pasted by hand. Generic data (corp.local) — validates
 * the PIPELINE, not any one lab. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ROOT = path.join(__dirname, '..', '..'), ENG = path.join(ROOT, 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {}, error: function () {} }, Promise: Promise };
ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
['facts.js', 'phases.js', 'pack.js', 'packs.js', 'command.js', 'workspace.js'].forEach(function (f) { try { load(path.join(ENG, f)); } catch (e) {} });
load(path.join(ENG, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENG, 'parsers', m + '.js')); });
load(path.join(ENG, 'parsers', 'index.js'));
load(path.join(ROOT, 'assets', 'ui', 'ingest.js'));
load(path.join(ROOT, 'data', 'packs-bundle.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// ── 1. splitSession carves a realistic multi-command capture into correct segments ──────────────────
// A Kali capture with obol's precmd stamp line above the two-line prompt, a couple of commands, a
// heredoc (whose body must NOT be read as more commands), and trailing output.
var cap = [
  '[2026-09-27 17:10:01 UTC] [tun0:10.10.14.5]',
  '┌──(kali㉿kali)-[~/engagements/dc01]',
  '└─$ nmap -Pn -p- 10.0.0.5',
  'Nmap scan report for 10.0.0.5',
  'Host is up.',
  'PORT   STATE SERVICE',
  '445/tcp open microsoft-ds',
  'Nmap done',
  '[2026-09-27 17:12:44 UTC] [tun0:10.10.14.5]',
  '┌──(kali㉿kali)-[~/engagements/dc01]',
  "└─$ cat > users.txt <<'EOF'",
  'jdoe',
  'svc-web',
  'EOF',
  '[2026-09-27 17:13:20 UTC] [tun0:10.10.14.5]',
  '┌──(kali㉿kali)-[~/engagements/dc01]',
  '└─$ nxc smb 10.0.0.5',
  'SMB 10.0.0.5 445 DC01 [*] Windows Server 2016 Build 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)',
].join('\n');

var segs = OBOL.ingest.splitSession(cap);
ok(segs.length === 3, 'splitSession finds exactly 3 commands (heredoc body is not mistaken for commands) — got ' + segs.length);
ok(segs[0].command === 'nmap -Pn -p- 10.0.0.5', 'segment 1 command is the nmap line');
ok(/Nmap scan report/.test(segs[0].stdout) && !/nxc smb/.test(segs[0].stdout), 'segment 1 stdout stops before the next command');
ok(segs[1].command === "cat > users.txt <<'EOF'", 'segment 2 command is the heredoc line');
ok(/jdoe\nsvc-web\nEOF/.test(segs[1].stdout), 'segment 2 swallows the heredoc body');
ok(segs[2].command === 'nxc smb 10.0.0.5', 'segment 3 command is the nxc line');
// the stamp line sits 2 rows above the └─$ command line → its timestamp is picked up
ok(segs[0].ts === Date.parse('2026-09-27T17:10:01Z'), 'segment 1 timestamp read from the precmd stamp line above the prompt');
ok(segs[2].ts === Date.parse('2026-09-27T17:13:20Z'), 'segment 3 timestamp read from its own stamp line');

// A bare "$ cmd" capture (no fancy prompt) still splits.
var bare = ['$ id', 'uid=0(root) gid=0(root)', '$ whoami', 'root'].join('\n');
var bs = OBOL.ingest.splitSession(bare);
ok(bs.length === 2 && bs[0].command === 'id' && bs[1].command === 'whoami', 'a plain "$ cmd" capture splits on the bare prompt');

// PowerShell prompt.
var ps = OBOL.ingest.splitSession(['PS C:\\Users\\svc> whoami', 'corp\\svc', 'PS C:\\Users\\svc> hostname', 'DC01'].join('\n'));
ok(ps.length === 2 && ps[0].command === 'whoami' && ps[1].command === 'hostname', 'a PowerShell capture splits on the PS ...> prompt');

// ── 2. importSession runs the segments through the real pipeline and mints the same facts ────────────
var store = (function () {
  var eng = { params: { target: '10.0.0.5', domain: 'corp.local' }, activities: [], facts: [] };
  var factSet = new OBOL.facts.FactSet([]);
  return {
    active: function () { return eng; },
    update: function (fn) { fn(eng); },
    addFacts: function (facts) { var n = 0; (facts || []).forEach(function (f) { if (factSet.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) n++; }); return n; },
    factSet: function () { return factSet; },
    _facts: factSet,
  };
})();
OBOL.store = store;

var res = OBOL.ingest.importSession(cap);
ok(res.ok, 'importSession completes');
ok(res.commands === 3, 'importSession reports 3 commands');
ok(res.added > 0, 'importSession mints facts from the reconstructed segments (added=' + res.added + ')');
ok(store._facts.has('ports.open'), 'facts: the nmap segment minted ports.open');
ok(store._facts.has('ad.domain_known'), 'facts: the nxc smb segment minted the domain');
// the operator's LHOST was learned from the [tun0:…] stamp during import
ok(store.active().params.lhost === '10.10.14.5', 'importSession learns {{lhost}} from the [tun0:IP] stamp');
// one activity recorded per real command
ok(store.active().activities.length === 3, 'one activity recorded per imported command (heredoc included) — got ' + store.active().activities.length);

// ── 3. Multi-file stitch + de-dupe ──────────────────────────────────────────────────────────────────
// Two capture files whose commands interleave in time; importing both must order by timestamp and drop a
// command that appears (identically) in both.
var fileA = ['[2026-09-27 09:00:00 UTC] [tun0:10.10.14.5]', '└─$ nmap -Pn 10.0.0.5', 'Nmap scan report for 10.0.0.5', 'Host is up.'].join('\n');
var fileB = ['[2026-09-27 09:05:00 UTC] [tun0:10.10.14.5]', '└─$ nxc smb 10.0.0.5', 'SMB 10.0.0.5 445 DC01 [*] (domain:corp.local)',
  '[2026-09-27 09:00:00 UTC] [tun0:10.10.14.5]', '└─$ nmap -Pn 10.0.0.5', 'Nmap scan report for 10.0.0.5', 'Host is up.'].join('\n');
// fresh store
OBOL.store = (function () {
  var eng = { params: { target: '10.0.0.5', domain: 'corp.local' }, activities: [], facts: [] };
  var factSet = new OBOL.facts.FactSet([]);
  return { active: function () { return eng; }, update: function (fn) { fn(eng); },
    addFacts: function (facts) { var n = 0; (facts || []).forEach(function (f) { if (factSet.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) n++; }); return n; },
    factSet: function () { return factSet; }, _e: eng };
})();
var multi = OBOL.ingest.importSession([fileA, fileB]);
ok(multi.commands === 3, 'multi-file: 3 raw command segments seen across both files');
ok(multi.dupes === 1, 'multi-file: the duplicate nmap run is detected and dropped (dupes=1)');
ok(multi.imported === 2, 'multi-file: exactly 2 unique commands imported');
ok(OBOL.store._e.activities.length === 2, 'multi-file: 2 activities recorded (no duplicate)');

console.log(fail ? ('\nSESSION IMPORT: ' + fail + ' FAILURES') : '\nSESSION IMPORT: all passed');
process.exit(fail ? 1 : 0);
