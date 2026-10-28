/* Freeform labeled credential block (outcome/loot axis): a plaintext credential leak (an exposed
 * credentials.txt, a readme, a notes file) lists accounts as a bracketed section header followed by a
 * bare username line and a bare password line, with NO key=value delimiter for the field/ini extractors
 * to catch. websource `_parse_labeled_creds` now mints a labeled_leak credential.candidate for that
 * shape (source 'labeled-leak'), with tight guards: the header must name a credential, the username must
 * be a single token, and the password must be a usable printable-ASCII secret. The canonical case is the
 * real 0xdf admirer `/admin-dir/credentials.txt`. This test is corpus-independent (hand-built shapes, no
 * verbatim corpus output) so it holds the parser logic even where the 0xdf snapshot is absent. */
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
function leaks(cmd, out) {
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: cmd, stdout: out, scope: 'host:10.10.10.187', domain: '' });
  return (r.facts || []).filter(function (f) { return f.kind === 'credential.candidate' && f.value && f.value.kind === 'labeled_leak'; });
}
function pws(cmd, out) { return leaks(cmd, out).map(function (f) { return f.value.password; }); }

// ---- true positives: the bracket-header + bare-user + bare-pass leak the field extractors miss ----
var admirer = '[Internal mail account]\nw.cooper@admirer.htb\nfgJr6q#S\\W:$P\n\n[FTP account]\nftpuser\n%n?4Wz}R$tTF7\n\n[Wordpress account]\nadmin\nw0rdpr3ss01!';
var got = pws('curl http://10.10.10.187/admin-dir/credentials.txt', admirer);
ok(got.length === 3, 'admirer credentials.txt leaks all 3 account blocks (got ' + got.length + ')');
ok(got.indexOf('w0rdpr3ss01!') >= 0, 'the WordPress password is captured');
ok(leaks('curl http://t/creds.txt', admirer).some(function (f) { return f.value.user === 'ftpuser'; }), 'the FTP username rides with its password');
ok(leaks('cat /home/user/notes.txt', '[SSH login]\nsvc_backup\nR3dacted!Pass9').length === 1,
  'a single labeled block read on-host (cat) mints one labeled_leak (universal dispatch, not just curl)');
ok(leaks('curl http://t/creds', '[credentials]\nmanager\nSup3rManaged$2026').length === 1,
  'a bare [credentials] header is recognized, not just "... account"');

// ---- false positives: must mint NO labeled_leak ----
ok(leaks('curl http://t/app.log', '[INFO] starting service\nconnected to db\nlistening on 8080').length === 0,
  'a log section header ([INFO]) with two output lines does not mint');
ok(leaks('cat app.conf', '[options]\nverbose = true\ntimeout = 30').length === 0,
  'a non-credential config section ([options]) does not mint');
ok(leaks('curl http://t/readme', '[Account setup]\nTo create an account please visit the portal\nand follow the onboarding steps').length === 0,
  'prose sentences under a credential-y header do not mint (username shape guard)');
ok(leaks('cat notes.txt', '[admin account]\njustoneword').length === 0,
  'a header followed by a single line does not mint (needs user AND pass)');
ok(leaks('curl http://t/data', '[user accounts]\nalice\n<password-here>').length === 0,
  'a placeholder password value does not mint');
ok(leaks('curl http://t/data', '[login]\nbob\nfalse').length === 0,
  'a boolean-looking value does not mint (value guard)');
ok(leaks('curl http://t/users.txt', '[user accounts]\nalice\nbob\ncharlie\ndave\nerin').length === 0,
  'a multi-line username list (4+ lines) under [user accounts] does not mint the first two usernames as user/pass');

console.log('\nLABELED-LEAK CRED SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
