/* shellkit-smoke.js — OBOL.shellkit (the Shell Station listener kit). Asserts the PowerShell
 * -EncodedCommand is byte-exact (UTF-16LE then base64, matching powershell -e), the manual encoder
 * agrees with the Node Buffer path, payloads fill LHOST/LPORT with no token leak, and the generated
 * .sh is valid bash (checked with `bash -n`). */
'use strict';
var cp = require('child_process'), fs = require('fs'), os = require('os'), path = require('path');
require('../../assets/engine/shellkit.js');
var SK = globalThis.OBOL.shellkit;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// 1) -EncodedCommand is UTF-16LE then base64 (the known value for `whoami`).
ok(SK.psEncode('whoami') === 'dwBoAG8AYQBtAGkA', 'psEncode(whoami) is the known UTF-16LE base64 (' + SK.psEncode('whoami') + ')');
ok(SK.psEncode('IEX') === Buffer.from('IEX', 'utf16le').toString('base64'), 'psEncode matches Node Buffer utf16le');
// manual (no-Buffer) path agrees
var savedBuffer = global.Buffer; global.btoa = function (s) { return savedBuffer.from(s, 'binary').toString('base64'); };
global.Buffer = undefined;
try { ok(SK.psEncode('whoami') === 'dwBoAG8AYQBtAGkA', 'manual (browser) psEncode path agrees'); } finally { global.Buffer = savedBuffer; }

// 2) payloads fill, no token leak.
var ps = SK.payloads('10.10.14.5', '4444');
ok(ps.length >= 8, 'payload catalogue is populated (' + ps.length + ')');
ok(ps.every(function (p) { return !/\{\{/.test(p.cmd); }), 'no payload leaks a {{token}}');
ok(ps.some(function (p) { return p.id === 'bash-i' && p.cmd.indexOf('/dev/tcp/10.10.14.5/4444') >= 0; }), 'bash -i fills LHOST/LPORT');
ok(ps.some(function (p) { return p.os === 'windows'; }), 'includes a Windows PowerShell payload');

// 3) the encoded command invocation is present and decodes back.
var enc = SK.psEncodedCommand('10.10.14.5', '4444');
ok(/^powershell -nop -w hidden -EncodedCommand [A-Za-z0-9+/=]+$/.test(enc), 'psEncodedCommand is a clean powershell -e line');
ok(Buffer.from(enc.split(' ').pop(), 'base64').toString('utf16le').indexOf('10.10.14.5') >= 0, 'the encoded command decodes back to the filled script');

// 4) catchers.
ok(SK.catchers().length >= 4, 'several catchers offered');
ok(SK.catcherById('pwncat').label === 'pwncat-cs', 'catcherById resolves');

// 5) the generated .sh is valid bash.
['nc', 'pwncat', 'socat', 'msf'].forEach(function (c) {
  var kit = SK.listenerKit({ lhost: '10.10.14.5', lport: '4444', catcher: c });
  ok(kit.indexOf('#!/usr/bin/env bash') === 0, c + ': kit starts with a shebang');
  ok(!/\{\{/.test(kit), c + ': kit has no token leak');
  ok(kit.indexOf('/dev/tcp/10.10.14.5/4444') >= 0, c + ': kit contains a filled payload');
  ok(kit.indexOf('-EncodedCommand') >= 0, c + ': kit includes the PowerShell -EncodedCommand');
  var tmp = path.join(os.tmpdir(), 'obol-kit-' + c + '.sh');
  fs.writeFileSync(tmp, kit);
  var r = cp.spawnSync('bash', ['-n', tmp], { encoding: 'utf8' });
  ok(r.status === 0, c + ': kit passes bash -n' + (r.status === 0 ? '' : ' (' + (r.stderr || '').trim() + ')'));
  try { fs.unlinkSync(tmp); } catch (e) {}
});

// 6) web shells (drop-and-browse files).
var ws = SK.webshells();
ok(ws.length >= 4, 'web shell catalogue is populated (' + ws.length + ')');
ok(ws.some(function (w) { return w.ext === 'php' && w.code.indexOf('_GET') >= 0; }), 'a PHP cmd web shell is present');
ok(ws.some(function (w) { return w.ext === 'jsp'; }) && ws.some(function (w) { return w.ext === 'aspx'; }), 'JSP and ASPX web shells are present');

// 7) msfvenom one-liners fill LHOST/LPORT and name a format + output.
var mv = SK.msfvenom('10.10.14.5', '443');
ok(mv.length >= 5, 'msfvenom catalogue is populated (' + mv.length + ')');
ok(mv.every(function (m) { return m.cmd.indexOf('msfvenom -p ') === 0 && m.cmd.indexOf('LHOST=10.10.14.5') > 0 && m.cmd.indexOf('LPORT=443') > 0 && /-f \S+ -o \S+$/.test(m.cmd); }), 'every msfvenom row is filled and well-formed');

// 8) payload encoders round-trip (base64 runner + url-encode), raw passes through.
var one = SK.payloads('10.10.14.5', '4444').filter(function (p) { return p.os === 'linux'; })[0].cmd;
var b64 = SK.encodePayload(one, 'b64');
var m = b64.match(/^echo (\S+) \| base64 -d \| bash$/);
ok(!!m, 'b64 encode has the echo B64 | base64 -d | bash shape');
ok(m && Buffer.from(m[1], 'base64').toString('utf8') === one, 'b64 runner decodes back to the original payload');
ok(decodeURIComponent(SK.encodePayload(one, 'url')) === one, 'url encode round-trips');
ok(SK.encodePayload(one, 'raw') === one, 'raw encode passes the payload through unchanged');

// 9) the generated kit now carries the msfvenom + web-shell sections.
var fullKit = SK.listenerKit({ lhost: '10.10.14.5', lport: '4444', catcher: 'nc' });
ok(/msfvenom -p /.test(fullKit), 'kit includes an msfvenom section');
ok(/_GET/.test(fullKit), 'kit includes a web shell');

if (fail) { console.error('shellkit-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('shellkit-smoke: OK');
