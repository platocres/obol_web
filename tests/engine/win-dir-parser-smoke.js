/* Native on-host directory-listing parser (corpus-mined, loot axis):
 *  cmd.exe "dir" ("Directory of C:\path" + "MM/DD/YYYY HH:MM AM  <size|<DIR>>  name") and PowerShell
 *  Get-ChildItem / ls / Invoke-Command { ls } ("Directory: C:\path" + a "Mode LastWriteTime Length
 *  Name [PSComputerName]" table) carry no tool token on the unit command (just "dir"/"ls"/"gci"), so
 *  the dispatcher sniffs the header anchors and _parse_fs_listing mints loot.files, anchoring each
 *  file to its "Directory of/Directory:" header. Prose, a bare date line, or a bare mode row with no
 *  header must mint nothing (no false positives). Samples are lifted from the 0xdf corpus. */
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
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function facts(cmd, out) { var r = OBOL.parsers.parseActionOutput({ actionId: '', command: cmd, stdout: out, scope: 'host:10.10.10.10', domain: 'acme.local' }); return (r.facts || []); }
function loot(cmd, out) { return facts(cmd, out).filter(function (f) { return f.kind === 'loot.files'; })[0] || null; }

// --- cmd.exe "dir" (HTB Access: the stored-creds .lnk on the Public desktop) ---
var cmdDir =
  ' Volume in drive C has no label.\n' +
  ' Volume Serial Number is 9C45-DBF0\n' +
  '\n' +
  ' Directory of C:\\Users\\Public\\Desktop\n' +
  '\n' +
  '08/22/2018  10:18 PM             1,870 ZKAccess3.5 Security System.lnk\n' +
  '               1 File(s)          1,870 bytes\n' +
  '               0 Dir(s)  16,682,262,528 bytes free';
var c1 = loot('dir', cmdDir);
ok(!!c1, 'a cmd "dir" listing mints loot.files (command carries no dir token of its own)');
ok(c1 && c1.value.count === 1, 'the File(s)/Dir(s) footer lines are not mistaken for entries (count=' + (c1 && c1.value.count) + ')');
ok(c1 && c1.value.files.indexOf('C:/Users/Public/Desktop/ZKAccess3.5 Security System.lnk') >= 0, 'the file is anchored to its "Directory of" header, and a name with spaces is kept whole');
ok(c1 && c1.value.tool === 'dir' && c1.value.via === 'shell-listing', 'the listing is attributed to dir via a shell-listing');

// --- PowerShell Get-ChildItem (HTB Access: root.txt on the administrator desktop) ---
var psLs =
  '    Directory: C:\\users\\administrator\\desktop\n' +
  '\n' +
  '\n' +
  'Mode                LastWriteTime     Length Name\n' +
  '----                -------------     ------ ----\n' +
  '-a---         8/21/2018  11:07 PM         32 root.txt';
var p1 = loot('dir', psLs);
ok(!!p1 && p1.value.count === 1, 'a PowerShell Get-ChildItem table mints loot.files (count=' + (p1 && p1.value.count) + ')');
ok(p1 && p1.value.files.indexOf('C:/users/administrator/desktop/root.txt') >= 0, 'the PS row is anchored to its "Directory:" header');
ok(p1 && p1.value.tool === 'powershell', 'a plain Get-ChildItem table (no PSComputerName column) is attributed to powershell');

// --- Invoke-Command { ls } (HTB Acute: user.txt pulled over a remote PS session) ---
var psRemote =
  '    Directory: C:\\Users\\imonks\\desktop\n' +
  '\n' +
  'Mode                 LastWriteTime         Length Name                               PSComputerName\n' +
  '----                 -------------         ------ ----                               --------------\n' +
  '-ar---        05/06/2022     22:16             34 user.txt                           ATSSERVER          ';
var p2 = loot('ls', psRemote);
ok(!!p2 && p2.value.count === 1, 'an Invoke-Command { ls } table (24h time, trailing PSComputerName column) mints loot.files');
ok(p2 && p2.value.files.indexOf('C:/Users/imonks/desktop/user.txt') >= 0 && p2.value.files.indexOf('ATSSERVER') < 0, 'the trailing PSComputerName column is stripped from the file name');
ok(p2 && p2.value.tool === 'invoke-command', 'a table with a PSComputerName column is attributed to invoke-command');

// --- dir /a: "." / ".." and <DIR> entries (HTB Access: the DPAPI Protect folder) ---
var dirA =
  ' Directory of C:\\Users\\security\\AppData\\Roaming\\Microsoft\\Protect\n' +
  '\n' +
  '12/11/2018  04:47 PM    <DIR>          .\n' +
  '12/11/2018  04:47 PM    <DIR>          ..\n' +
  '12/11/2018  04:47 PM    <DIR>          S-1-5-21-953262931-566350628-63446256-1001';
var d1 = loot('dir /a', dirA);
ok(!!d1 && d1.value.count === 1, 'the "." and ".." self entries are skipped; the one real <DIR> is kept (count=' + (d1 && d1.value.count) + ')');
ok(d1 && d1.value.entries[0].size === '', 'a <DIR> entry records an empty size, not the literal "<DIR>"');

// --- sensitive-file flagging survives the native-listing path ---
var webcfg =
  ' Directory of C:\\inetpub\\wwwroot\n' +
  '\n' +
  '03/01/2020  10:00 AM             1,234 web.config\n' +
  '03/01/2020  10:00 AM             2,048 index.html';
var s1 = loot('dir', webcfg);
ok(s1 && (s1.value.sensitive || []).indexOf('C:/inetpub/wwwroot/web.config') >= 0, 'web.config is flagged sensitive through _emit_file_loot');
ok(s1 && (s1.value.sensitive || []).indexOf('C:/inetpub/wwwroot/index.html') < 0, 'an ordinary file is not flagged sensitive');

// --- the thousands-separator in cmd sizes is normalized ---
var bigfile =
  ' Directory of C:\\loot\n' +
  '\n' +
  '03/01/2020  10:00 AM         1,048,576 backup.bak';
var b1 = loot('dir', bigfile);
ok(b1 && b1.value.entries[0].size === '1048576', 'a cmd size with thousands separators is normalized to digits');

// --- No false positives ---
// A bare mode row with no "Mode/LastWriteTime" header and no "Directory:" must not route or mint.
ok(!loot('ls', '-a---         8/21/2018  11:07 PM         32 root.txt'), 'a bare PS mode row with no listing header mints no loot.files');
// A bare date line with no "Directory of" header must not route or mint.
ok(!loot('echo hi', '08/22/2018  10:18 PM             1,870 something.txt'), 'a bare date line with no "Directory of" header mints no loot.files');
// A "Directory of" header with no rows under it (an empty or prose mention) mints nothing.
ok(!loot('dir', ' Directory of C:\\temp\n\nFile Not Found'), 'a "Directory of" header with no listing rows mints no loot.files');
// Prose that mentions a Windows path but is not a listing mints nothing.
ok(!loot('type notes.txt', 'The Directory of interest is on the D drive, but I could not read it.'), 'prose mentioning "Directory of" inline (not at line start) mints no loot.files');

// --- The minted fact has a live downstream consumer (the loop advances) ---
var consumers = A.filter(function (m) { return [].concat(m.requires_all || [], m.requires_any || []).indexOf('loot.files') >= 0; });
ok(consumers.length >= 1, 'loot.files drives at least one downstream move (' + consumers.length + ')');

console.log('\nWIN DIR PARSER SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
