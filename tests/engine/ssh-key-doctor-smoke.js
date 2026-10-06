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
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
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

// ---- auth + operational blockers: each cryptic wall mints its blocker fact (and a benign paste none) ----
function hasKind(cmd, out, kind) { return kinds(cmd, out).indexOf(kind) >= 0; }
ok(hasKind('nxc smb dc -u bob -p x', 'SMB  dc  [-] corp\\bob:x STATUS_NOT_SUPPORTED', 'blocker.ntlm_disabled'), 'STATUS_NOT_SUPPORTED → blocker.ntlm_disabled');
ok(hasKind('nxc smb dc -u bob -p x', '[-] corp\\bob:x STATUS_ACCOUNT_LOCKED_OUT', 'blocker.lockout'), 'STATUS_ACCOUNT_LOCKED_OUT → blocker.lockout');
ok(hasKind('nxc smb dc -u bob -p x', '[-] corp\\bob:x STATUS_ACCOUNT_DISABLED', 'blocker.account_restricted'), 'STATUS_ACCOUNT_DISABLED → blocker.account_restricted');
ok(hasKind('nmap 10.10.10.10', 'Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn', 'blocker.host_down'), 'nmap host-seems-down → blocker.host_down');
ok(hasKind('curl http://box.htb/', 'curl: (6) Could not resolve host: box.htb', 'blocker.name_resolution'), 'could-not-resolve-host → blocker.name_resolution');
ok(hasKind('./enum.sh', '/bin/bash^M: bad interpreter: No such file or directory', 'blocker.crlf'), 'CRLF bad interpreter → blocker.crlf');
ok(hasKind('sudo -l', 'sudo: no tty present and no askpass program specified', 'blocker.no_tty'), 'sudo no-tty → blocker.no_tty');
ok(hasKind('powershell iex ...', 'At line:1 : This script contains malicious content and has been blocked by your antivirus software', 'blocker.amsi'), 'AMSI block → blocker.amsi');
ok(hasKind('JuicyPotato.exe', '[-] CreateProcessWithTokenW failed: the handle is invalid', 'blocker.potato'), 'potato failure → blocker.potato');
ok(hasKind('ffuf -u http://t/FUZZ', ':: Progress ... 429 Too Many Requests', 'blocker.rate_limited'), '429 → blocker.rate_limited');
ok(hasKind('curl https://t:80/', 'curl: (35) error:0A00010B:SSL routines::wrong version number', 'blocker.tls_scheme'), 'wrong-version-number → blocker.tls_scheme');
ok(kinds('nmap 10.10.10.10', 'Nmap scan report for 10.10.10.10\nHost is up (0.012s latency).').filter(function (x) { return /^blocker\./.test(x); }).length === 0, 'a healthy scan mints no blocker');

console.log('\nSSH KEY DOCTOR SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
