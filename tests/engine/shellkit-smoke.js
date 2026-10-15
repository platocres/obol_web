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

if (fail) { console.error('shellkit-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('shellkit-smoke: OK');
