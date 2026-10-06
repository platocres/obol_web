/* SSH-key troubleshooter (parsers/host.js _parse_ssh_key_diagnostics + ssh-key-troubleshoot move): the
 * cryptic key-rejection errors OffSec labs lean on each mint ssh.key_rejected with the right cause, a
 * successful login mints none, and the niche shell-landing moves (tftp/vnc) mint foothold.linux from a
 * pasted id. This is the accessibility guarantee: a user who pastes a confusing SSH error gets the fix. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');
var OBOL = globalThis.OBOL, fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function run(cmd, out, aid) { return (OBOL.parsers.parseActionOutput({ command: cmd, stdout: out, scope: 'host:10.10.10.10', actionId: aid || '' }).facts || []); }
function kinds(cmd, out, aid) { return run(cmd, out, aid).map(function (f) { return f.kind; }); }
function cause(cmd, out) { var f = run(cmd, out).filter(function (x) { return x.kind === 'ssh.key_rejected'; })[0]; return f ? f.value.cause : ''; }
function has(a, v) { return a.indexOf(v) >= 0; }

// each failure signature → ssh.key_rejected with the right cause
ok(cause('ssh -i id_rsa bob@t', "Permissions 0644 for 'id_rsa' are too open.\nWARNING: UNPROTECTED PRIVATE KEY FILE!") === 'unprotected', 'unprotected-perms error → cause=unprotected');
ok(cause('ssh -i id_rsa bob@t', 'bob@t: Permission denied (publickey).\nno mutual signature algorithm') === 'legacy_algo', 'OpenSSH 8.8+ ssh-rsa block → cause=legacy_algo');
ok(cause('ssh -i id_rsa bob@t', 'Enter passphrase for key id_rsa:') === 'passphrase', 'encrypted key → cause=passphrase');
ok(cause('ssh -i id_rsa bob@t', 'Load key "id_rsa": invalid format') === 'bad_format', 'mangled key → cause=bad_format');
ok(cause('ssh -i id_rsa bob@t', 'bob@t: Permission denied (publickey).') === 'publickey_denied', 'bare publickey denial (target StrictModes) → cause=publickey_denied');
// a successful login mints a foothold, never a rejection
ok(!has(kinds('ssh -i id_rsa bob@t id', 'uid=1000(bob) gid=1000(bob) groups=1000(bob)'), 'ssh.key_rejected'), 'a successful key login mints no rejection');
ok(has(kinds('ssh -i id_rsa bob@t id', 'uid=1000(bob) gid=1000(bob) groups=1000(bob)'), 'foothold.linux'), 'a successful key login mints the foothold');
// a benign/unrelated paste mints nothing
ok(kinds('ssh bob@t', 'Welcome to Ubuntu 22.04').indexOf('ssh.key_rejected') < 0, 'a normal SSH banner mints no rejection');
// niche shell-landing moves mint foothold.linux from a pasted id (actionId-routed)
ok(has(kinds('curl http://t/shell.php?c=id', 'uid=33(www-data) gid=33(www-data) groups=33(www-data)', 'tftp-write-shell'), 'foothold.linux'), 'tftp webshell id → foothold.linux');
ok(has(kinds('id', 'uid=1000(bob) gid=1000(bob) groups=1000(bob)', 'vnc-desktop-shell'), 'foothold.linux'), 'vnc desktop terminal id → foothold.linux');

console.log('\nSSH KEY DOCTOR SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
