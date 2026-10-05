/* Output-shape fallback (parsers/shape.js): a paste with no command line still yields the facts its
 * shape proves, and unrelated text mints nothing. Proves the Approach-A "capture the general shape"
 * parity for the Learn/ingest path, including the new-port services. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ENGINE = path.join(__dirname, '..', '..', 'assets', 'engine');
var ctx = vm.createContext({ console: console });
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'shape'].forEach(function (m) { load(path.join(ENGINE, 'parsers', m + '.js')); });
load(path.join(ENGINE, 'parsers', 'index.js'));
var OBOL = ctx.OBOL;

var pass = 0, fail = 0;
function ok(c, m) { if (c) { pass++; console.log('  ok  : ' + m); } else { fail++; console.error('  FAIL: ' + m); } }
// analyzeTerminal takes raw pasted text (no action/command); it uses the first line as a pseudo-command.
function kinds(text, opts) {
  var r = OBOL.parsers.analyzeTerminal(text, opts || {});
  return { set: r.facts.map(function (f) { return f.kind; }), facts: r.facts, unmatched: r.unmatched };
}
function has(k, t, opts) { return kinds(t, opts).set.indexOf(k) >= 0; }

// (1) a bare port table pasted with no nmap command -> port + reachability facts
var portTable = [
  'PORT     STATE SERVICE',
  '23/tcp   open  telnet',
  '873/tcp  open  rsync',
  '1521/tcp open  oracle',
  '8009/tcp open  ajp13',
].join('\n');
var pt = kinds(portTable, { scope: 'host:10.10.10.10' });
ok(pt.set.indexOf('port:23') >= 0 && pt.set.indexOf('port:873') >= 0 && pt.set.indexOf('port:1521') >= 0 && pt.set.indexOf('port:8009') >= 0, 'a bare port table mints every open port (23, 873, 1521, 8009)');
ok(pt.set.indexOf('ports.open') >= 0, 'a bare port table mints ports.open');
ok(pt.facts.some(function (f) { return f.kind === 'port:1521' && f.value && f.value.via === 'shape'; }), 'shape-minted ports are tagged via=shape for lineage');

// (2) a raw HTTP response pasted with no curl/whatweb command -> http.reachable (+ web.server)
var httpResp = [
  'HTTP/1.1 200 OK',
  'Date: Mon, 08 Jan 2024 09:14:02 GMT',
  'Server: Apache/2.4.49 (Unix)',
  'Content-Type: text/html',
].join('\n');
var hr = kinds(httpResp, { scope: 'host:10.10.10.10' });
ok(hr.set.indexOf('http.reachable') >= 0, 'a raw HTTP response mints http.reachable');
ok(hr.set.indexOf('web.server') >= 0, 'a raw HTTP response mints web.server from the Server header');

// (3) a pasted AS-REP hash with no command -> the correct hash fact TYPE (delegated to the real parser)
var asrep = '$krb5asrep$23$tgibson@ACME.INTERNAL:9f2c1a' + 'b'.repeat(32) + '$' + 'c'.repeat(200);
ok(has('hash.asrep', asrep, { scope: 'host:10.10.10.10', domain: 'acme.internal' }), 'a pasted $krb5asrep$ hash mints hash.asrep (right type, via the real parser)');

// (4) unrelated prose mints nothing (never invent)
var prose = 'The meeting is at 3pm. Remember to bring the 80/20 report and review section 445 of the manual.';
var pr = kinds(prose, { scope: 'host:10.10.10.10' });
ok(pr.unmatched === true && pr.facts.length === 0, 'unrelated prose (with incidental numbers) mints no facts');

// (5) a real nmap paste is unchanged: shape does not double-mint when the command parser already ran
var nmapPaste = 'Nmap scan report for 10.10.10.10\nPORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1\n80/tcp open  http    Apache httpd 2.4.49';
var nm = kinds(nmapPaste, { command: 'nmap -sV 10.10.10.10', scope: 'host:10.10.10.10' });
var p80 = nm.facts.filter(function (f) { return f.kind === 'port:80'; });
ok(p80.length === 1, 'an nmap paste mints each port exactly once (shape does not duplicate the command parser)');
ok(nm.facts.filter(function (f) { return f.kind === 'port:22'; }).length === 1 && p80.length === 1, 'consecutive simple port rows both parse (newline-safe nmap row regex)');

console.log('\nPARSER SHAPE SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
