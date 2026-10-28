/* Interactive smbclient listing parser (corpus-mined, output axis):
 *  an interactive "smb: \>" ls/dir listing carries no tool token on the unit command (the command
 *  is just "ls"/"dir"), so the dispatcher sniffs the output (the blocks-of-size footer, the "." / ".."
 *  self entries, or >=2 listing rows) and _parse_share_inventory mints loot.files from the rows.
 *  Uploads (put/mput), empty directories, and prose must mint nothing (no false positives). */
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

// A plain interactive directory listing, dispatched by the ">=2 rows" sniff (command is just "ls").
var dirList =
  '  .                                   D        0  Sat Jul 21 06:37:44 2018\n' +
  '  ..                                  D        0  Sat Jul 21 06:37:44 2018\n' +
  '  Documents                           D        0  Mon Aug 13 09:02:11 2018\n' +
  '  jamovi-1.6.16.0-win64.exe           A  1234567  Tue Jan 05 11:15:00 2021\n' +
  '  VNC-Viewer-6.20.529-Windows.exe     A  9876543  Wed Feb 10 08:30:44 2021\n' +
  '\n\t\t5100031 blocks of size 4096. 2402263 blocks available';
var l1 = loot('ls', dirList);
ok(!!l1, 'an interactive "ls" listing mints loot.files (command carries no smbclient token)');
ok(l1 && l1.value.count === 3, 'the "." and ".." self entries are skipped; three real entries parsed (' + (l1 && l1.value.count) + ')');
ok(l1 && l1.value.files.indexOf('Documents') >= 0 && l1.value.files.indexOf('VNC-Viewer-6.20.529-Windows.exe') >= 0, 'both directory and file rows are captured, names with no spaces intact');
ok(l1 && l1.value.tool === 'smbclient', 'the listing is attributed to smbclient');

// Single sensitive file with the "." / ".." self entries but NO footer (HTB Active GPP Groups.xml):
// the self entries alone are the confidence signal, so the one real row is still trusted.
var gpp =
  '  .                                   D        0  Sat Jul 21 06:37:44 2018\n' +
  '  ..                                  D        0  Sat Jul 21 06:37:44 2018\n' +
  '  Groups.xml                          A      533  Wed Jul 18 16:46:06 2018';
var l2 = loot('ls', gpp);
ok(!!l2 && l2.value.count === 1, 'a single-file listing with "." / ".." self entries still mints loot.files');
ok(l2 && (l2.value.sensitive || []).indexOf('Groups.xml') >= 0, 'Groups.xml is flagged sensitive (GPP cpassword lead)');

// A name containing spaces is kept whole (attr column is the delimiter, not the first space).
var spaced =
  '  .                                   D        0  Sat Jul 21 06:37:44 2018\n' +
  '  ..                                  D        0  Sat Jul 21 06:37:44 2018\n' +
  '  Default User                        D        0  Mon Aug 13 09:02:11 2018\n' +
  '  All Users                           D        0  Mon Aug 13 09:02:11 2018';
var l3 = loot('dir', spaced);
ok(!!l3 && l3.value.files.indexOf('Default User') >= 0 && l3.value.files.indexOf('All Users') >= 0, 'entry names with spaces are preserved whole');

// --- No false positives ---
// An empty share (only "." / ".." plus a footer) has no real entries, so nothing is minted.
var empty =
  '  .                                   D        0  Fri Jul 14 09:48:44 2017\n' +
  '  ..                                  D        0  Fri Jul 14 09:48:44 2017\n' +
  '\t\t8362495 blocks of size 4096. 2819340 blocks available';
ok(!loot('ls', empty), 'an empty directory (only "." / "..") mints no loot.files');
// An upload (put / mput) is not a listing.
ok(!loot('put rev.exe', 'putting file rev.exe as \\client1\\rev.exe (17.2 kb/s) (average 8.8 kb/s)'), 'a "put" upload mints no loot.files');
ok(!loot('mput *', 'NT_STATUS_ACCESS_DENIED opening remote file \\doc.docx\nputting file a.jnlp as \\a.jnlp (0.7 kb/s) (average 0.7 kb/s)'), 'an "mput" upload mints no loot.files');
// Prose that happens to mention a date must not be mistaken for a listing row.
ok(!loot('help', 'Try "help <command>" to get help on a specific command.\nSession setup on Mon Jan 01 00:00:00 2024 completed.'), 'help/prose with a date but no listing rows mints no loot.files');

// --- The minted fact has a live downstream consumer (the loop advances) ---
var consumers = A.filter(function (m) { return [].concat(m.requires_all || [], m.requires_any || []).indexOf('loot.files') >= 0; });
ok(consumers.length >= 1, 'loot.files drives at least one downstream move (' + consumers.length + ')');

console.log('\nSMB LS PARSER SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
