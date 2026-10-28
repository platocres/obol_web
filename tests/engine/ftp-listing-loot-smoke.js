/* FTP directory listing loot (loot.files axis). An interactive `ftp> ls` / `dir` returns a directory
 * listing over the data channel; services.js _parse_ftp_output now mints loot.files for it the way
 * smbclient and native dir/Get-ChildItem listings already do. Two row shapes are handled: the Windows
 * IIS line ("MM-DD-YY  HH:MMAM/PM  <size|<DIR>>  name") and the Unix `ls -l` long listing. The parser is
 * reached when the command names ftp OR the output carries FTP control codes (200 PORT / 227 Passive /
 * 125|150 data channel), and rows mint only inside that FTP context so a stray date or permission line
 * never mints on its own. Corpus-independent (hand-built shapes, no verbatim corpus output). House style:
 * no em or en dashes. qa-only; nothing here ships. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL;
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function loot(cmd, out) {
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: cmd, stdout: out, scope: 'host:10.10.10.98', domain: '' });
  return (r.facts || []).filter(function (f) { return f.kind === 'loot.files'; });
}
function names(cmd, out) { var l = loot(cmd, out); return l.length ? (l[0].value.files || []) : []; }

// ---- true positive: Windows IIS listing (the canonical 0xdf shape, ftp> ls exposing backup.mdb) ----
var iis = '200 PORT command successful.\n' +
  '125 Data connection already open; Transfer starting.\n' +
  '08-23-18  09:16PM              5652480 backup.mdb\n' +
  '08-23-18  08:51PM       <DIR>          Reports\n' +
  '226 Transfer complete.';
ok(names('ls', iis).indexOf('backup.mdb') >= 0,
  'an IIS ftp listing (command "ls", FTP control codes) mints loot.files including backup.mdb');
ok(names('ls', iis).indexOf('Reports') >= 0, 'the <DIR> entry is captured too');

// ---- true positive: Unix long listing over ftp ----
var unix = 'ftp> ls\n' +
  '200 PORT command successful.\n' +
  '150 Opening ASCII mode data connection for file list.\n' +
  '-rw-r--r--   1 ftp ftp      5652480 Aug 23  2018 backup.mdb\n' +
  'drwxr-xr-x   2 ftp ftp         4096 Aug 23  2018 uploads\n' +
  '226 Transfer complete.';
ok(names('ftp 10.10.10.98', unix).indexOf('backup.mdb') >= 0,
  'a Unix ls -l listing over ftp mints loot.files including backup.mdb');

// ---- false positives: no listing content must mint nothing ----
ok(loot('ftp 10.10.10.98', '220 Microsoft FTP Service\n331 Password required\n230 User logged in.').length === 0,
  'an ftp login banner with no listing mints no loot.files');
ok(loot('cat changelog.txt', '08-23-18  09:16PM              5652480 backup.mdb').length === 0,
  'a lone IIS-shaped date line with no FTP control context does not mint (dispatch guard)');
ok(loot('ftp 10.10.10.98', '200 PORT command successful.\n150 Ok to send data.\n226 Transfer complete.\nftp> put shell.aspx').length === 0,
  'an ftp upload session with no listing rows mints no loot.files');

console.log('\nFTP-LISTING-LOOT SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
