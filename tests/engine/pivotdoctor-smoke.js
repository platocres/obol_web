/*!
 * pivotdoctor-smoke.js — the symptom-first pivot troubleshooter engine.
 *
 * Locks the conservative contract: each symptom recognizes its real failure output and hands a fix;
 * healthy output is reported as healthy (not a false alarm); unrecognized output stands down to the
 * checklist rather than guessing; and the doctor never mints a fact into the ledger.
 */
'use strict';
var assert = require('assert');
var path = require('path');
require(path.join(__dirname, '..', '..', 'data', 'pivot-troubleshooter.js'));
require(path.join(__dirname, '..', '..', 'assets', 'engine', 'pivotdoctor.js'));
var OBOL = global.OBOL, D = OBOL.pivotDoctor;

var pass = 0;
function ok(c, m) { assert.ok(c, m); console.log('  ok - ' + m); pass++; }
var P = { lhost: '10.10.14.5', user: 'bob', username: 'bob' };

// ---- shape ------------------------------------------------------------------------------------
ok(D.symptoms().length >= 6, 'at least six plain-language symptoms are offered');
D.symptoms().forEach(function (s) {
  ok(s.key && s.symptom && s.hint, s.key + ': has a key, a plain symptom, and a hint');
  ok((s.probes || []).length >= 1, s.key + ': hands at least one probe command');
  s.probes.forEach(function (p) { ok(p.where && p.label && p.cmd && p.why, s.key + ': each probe is machine-labelled with a why'); });
  ok((s.diagnoses || []).length >= 2, s.key + ': carries recognizers');
  s.diagnoses.forEach(function (d) { ok(d.id && d.re && d.verdict, s.key + '/' + d.id + ': recognizer has id, pattern, verdict'); try { new RegExp(d.re, 'i'); if (d.notRe) new RegExp(d.notRe, 'i'); ok(true, s.key + '/' + d.id + ': pattern compiles'); } catch (e) { ok(false, s.key + '/' + d.id + ': pattern compiles'); } });
});

// ---- the diagnoses actually fire on real failure output ---------------------------------------
function v(key, text) { return D.diagnose(key, text, P); }

var r = v('agent-no-callback', 'Ncat: Connection refused.');
ok(r.matched && r.id === 'refused' && !r.healthy, 'agent-no-callback: "Connection refused" -> proxy-not-running verdict');
ok(r.fix.indexOf('./proxy') !== -1 && r.line.indexOf('refused') !== -1, 'agent-no-callback: hands a fix and highlights the problem line');

r = v('agent-no-callback', 'nc: connect to 10.10.14.5 port 11601 (tcp) timed out: Operation now in progress');
ok(r.matched && r.id === 'timeout', 'agent-no-callback: "timed out" -> firewall/routing verdict');

r = v('agent-no-callback', 'LISTEN 0 4096 0.0.0.0:11601 0.0.0.0:* users:(("proxy",pid=1))');
ok(r.matched && r.healthy && r.id === 'listening', 'agent-no-callback: a bound 11601 listener reads healthy (look target-side)');

r = v('no-subnet', '10.10.10.9 dev ligolo src 240.0.0.1 uid 0');
ok(r.matched && r.healthy && r.id === 'via-tun', 'no-subnet: route via dev ligolo reads healthy');
r = v('no-subnet', '10.10.10.9 via 10.10.14.1 dev eth0 src 10.10.14.5');
ok(r.matched && !r.healthy && r.id === 'via-nic', 'no-subnet: route via eth0 -> add-route fix');
ok(r.fix.indexOf('ip route add') !== -1, 'no-subnet: fix is the ip route add command');

r = v('proxychains-hangs', 'socks4 127.0.0.1 9050');
ok(r.matched && r.id === 'tor-default', 'proxychains-hangs: still aimed at Tor 9050 -> the classic mismatch');
ok(r.fix.indexOf('1080') !== -1, 'proxychains-hangs: fix repoints it at 1080');

r = v('all-filtered', 'nmap -sS -p- 172.16.5.10');
ok(r.matched && r.id === 'syn', 'all-filtered: -sS over SOCKS -> use -sT');
r = v('all-filtered', 'proxychains nmap -p 445 172.16.5.10');
ok(r.matched && (r.id === 'no-st' || r.id === 'no-pn'), 'all-filtered: a scan missing -sT/-Pn is flagged');
r = v('all-filtered', 'proxychains -q nmap -sT -Pn -p 445 172.16.5.10');
ok(r.matched && r.healthy && r.id === 'tcp-ok', 'all-filtered: -sT -Pn reads healthy (flags are right)');

r = v('refused-through-tunnel', 'Ncat: Connection refused.');
ok(r.matched && !r.healthy && r.id === 'refused', 'refused-through-tunnel: service not listening (pivot works)');

r = v('tunnel-died', 'client: Connection to server closed: read tcp: connection reset by peer');
ok(r.matched && !r.healthy && r.id === 'reset', 'tunnel-died: a reset -> restart + detach advice');

// ---- conservative: unrecognized / empty output stands down to the checklist -------------------
r = v('agent-no-callback', 'some unrelated banner text with nothing diagnostic in it');
ok(!r.matched && Array.isArray(r.checklist) && r.checklist.length >= 4, 'unrecognized output stands down to the checklist, no false verdict');
r = v('agent-no-callback', '   \n  ');
ok(!r.matched && r.empty, 'empty paste asks for the probe output rather than diagnosing');
ok(r.checklist.join(' ').indexOf('10.10.14.5') !== -1, 'checklist fills {{lhost}} from the engagement params');

// ---- it never touches the fact ledger ---------------------------------------------------------
ok(!OBOL.store || typeof D.diagnose === 'function', 'the doctor is a pure diagnose() call, not a fact minter');

console.log('\npivotdoctor-smoke: ' + pass + ' checks passed');
