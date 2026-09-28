/* Node sanity test for the virtual-workspace model (engine/vfs.js): output-path + flag-file detection,
   suggested/anticipated files, the confirmation pass, hand add/remove overrides, and disk-sync reconcile. */
'use strict';
require('../../assets/engine/workspace.js');
require('../../assets/engine/vfs.js');
const OBOL = globalThis.OBOL;
const V = OBOL.vfs;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// ── path extraction ──
ok(V.outputPaths('nmap -oN scans/full.txt 10.0.0.5').indexOf('scans/full.txt') === 0, 'nmap -oN output path parsed');
ok(V.outputPaths('nxc ldap x --asreproast loot/asrep.txt').indexOf('loot/asrep.txt') === 0, '--asreproast output path parsed');
ok(V.outputPaths('rustscan -a x 2>/dev/null > scans/ports.txt').indexOf('scans/ports.txt') === 0, 'redirect output path parsed');
ok(V.outputPaths('cat file 2>/dev/null').length === 0, 'a bare cat writes no output file');
ok(V.flagPaths('type C:\\Users\\bob\\Desktop\\local.txt').indexOf('local.txt') === 0, 'flag file read is detected');
ok(V.flagPaths('cat {{flag_path_local}}').indexOf('local.txt') === 0, 'unresolved flag token → canonical local.txt');
ok(V.flagPaths('nxc smb x --regex "(local|proof|user|root|flag)\\.txt"').length === 0, 'a --regex pattern is NOT read as a path');

// ── suggested (anticipated) files come from a passed-in suggestion; a run always wins over a suggestion ──
let eng = { id: 'e1', workspace: { root: '~/box' },
  activities: [{ command: 'nmap -oN scans/tcp.txt 10.0.0.5', stdout: '22/tcp open ssh', produced: ['ports.open'], at: 10 }],
  screenshots: [] };
let m = V.build(eng, { suggested: [
  { command: 'nmap -oN scans/tcp.txt x', title: 'Full TCP', id: 'nmap-full' },     // dup of a real run → suppressed
  { command: 'gobuster dir -u x -o www/dirs.txt', title: 'Content Discovery', id: 'gobuster' },
  { command: 'type {{flag_path_local}}', title: 'Grab the flag', id: 'flag-hunt' },
] });
let scan = m.files.find(f => f.name === 'tcp.txt');
ok(scan && scan.status === 'captured' && scan.origin === 'ran', 'a captured run owns its file (suggestion does not override)');
let dirs = m.files.find(f => f.name === 'dirs.txt');
ok(dirs && dirs.status === 'expected' && dirs.origin === 'suggested' && dirs.actionId === 'gobuster', 'a suggested move pencils in an expected/anticipated file');
let flag = m.files.find(f => f.name === 'local.txt');
ok(flag && flag.origin === 'suggested' && flag.flag === true && flag.folder === 'proof', 'an anticipated flag file lands under proof/');
ok(m.anticipated === 2, 'anticipated count reflects the pencilled-in files');

// ── confirmation: a later paste proving a flag confirms the anticipated flag file ──
eng.activities.push({ command: 'type C:\\Users\\bob\\Desktop\\local.txt', stdout: 'a1b2c3', produced: ['objective.local_flag'], at: 20 });
m = V.build(eng);
flag = m.files.find(f => f.name === 'local.txt');
ok(flag && flag.status === 'captured', 'reading the flag file with a flag-producing paste captures it');

// ── hand add + remove overrides ──
eng.workspace.overrides = { added: [{ path: 'loot/notes.txt', source: 'manual', at: 1 }], removed: { 'scans/tcp.txt': true } };
m = V.build(eng);
ok(m.files.some(f => f.name === 'notes.txt' && f.manual === true), 'a hand-added file appears as manual');
ok(!m.files.some(f => f.name === 'tcp.txt'), 'a removed path is hidden from the tree');

// ── disk-sync reconcile: confirm known, adopt unknown, honor a removal ──
delete eng.workspace.overrides;
let entries = V.parseSnapshot(['### OBOL-WS-SNAPSHOT',
  'scans/tcp.txt\t5120\t2026-09-28T14:02',
  'loot/creds.txt\t88\t2026-09-28T15:00',
  '### END'].join('\n'));
ok(entries.length === 2, 'parseSnapshot ignores markers and reads two files');
let r = V.reconcile(eng, entries);
ok(r.confirmed === 1 && r.adopted === 1, 'reconcile confirms the predicted file and adopts the unknown one');
eng.workspace.overrides = r.overrides;
m = V.build(eng);
ok(m.files.some(f => f.name === 'creds.txt' && f.unknown === true && f.synced === true), 'the adopted file is flagged synced+unknown');
ok(m.files.find(f => f.name === 'tcp.txt').confirmed === true, 'the predicted file is now confirmed on disk');

// ── describe(): purpose + honest metric, no fabricated facts ──
ok(V.describe({ name: 'tcp.txt', tool: 'nmap', facts: ['ports.open', 'x'], output: 'a\nb' }) === 'Port & Service Scan · 2 Facts', 'describe: nmap purpose + fact count');
ok(V.describe({ name: 'x.py', tool: '', size: 400 }) === 'Python Script · 400 B', 'describe: unknown file by extension + size');
ok(V.describe({ name: 'local.txt', flag: true, facts: [] }) === 'Flag / Proof File', 'describe: flag file, no metric when nothing measured');
ok(/Credential/.test(V.describe({ name: 'ntds', tool: 'impacket-secretsdump', facts: ['loot.ntds'] })), 'describe: secretsdump reads as a credential dump');
// value-derived metrics (parsed values, never the filename) with exact casing + explicit plurals
ok(V.describe({ name: 's', tool: 'nmap', valMap: { 'ports.open': { ports: [22, 80, 445, 3389, 5985, 8080, 9090] } } }) === 'Port & Service Scan · 7 Open Ports (22, 80, 445, 3389, 5985, 8080, …)', 'describe: rich open-ports metric with overflow');
ok(V.describe({ name: 's', tool: 'nmap', valMap: { 'ports.open': { ports: [22] } } }) === 'Port & Service Scan · 1 Open Port (22)', 'describe: singular "1 open port"');
ok(V.describe({ name: 'd', tool: 'impacket-secretsdump', valMap: { 'loot.ntds': { count: 15 } } }) === 'Credential / NTDS Dump · NTDS: 15 Accounts', 'describe: NTDS account count');
ok(V.describe({ name: 'h', tool: 'impacket-secretsdump', valMap: { 'hash.ntlm': { count: 1 } } }) === 'Credential / NTDS Dump · 1 NTLM Hash', 'describe: singular "1 NTLM hash" (not hashs)');
ok(V.describe({ name: 'a', tool: 'GetNPUsers', valMap: { 'credential.candidate': { kind: 'asrep_hash', count: 3 } } }) === 'AS-REP Roast · 3 AS-REP Hashes', 'describe: AS-REP hash count with acronym casing');
// the flag detector must not swallow a userlist or a rootkit note
ok(V.flagPaths('nxc smb x --users | tee loot/users.txt').length === 0, 'flagPaths: users.txt is NOT a flag file');
ok(V.flagPaths('cat rootkit.txt').length === 0, 'flagPaths: rootkit.txt is NOT a flag file');
ok(V.flagPaths('type C:\\local1.txt').indexOf('local1.txt') === 0, 'flagPaths: local1.txt IS a flag file');

if (fail) { console.error('\nVFS SMOKE: ' + fail + ' FAILED'); process.exit(1); }
console.log('\nVFS SMOKE: all passed');
