/* nmap scan-profile markers: one paste of a -sC -sV scan must advance the coach past BOTH the
 * port-discovery and the version-scan move, even when tagged with the fast move's command. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ENGINE = path.join(__dirname, '..', '..', 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENGINE, 'parsers', m + '.js')); });
load(path.join(ENGINE, 'parsers', 'index.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function kindsOf(r) { return (r.facts || []).map(function (f) { return f.kind; }); }

var versionScan = [
  '# Nmap 7.95 scan initiated Sat as: nmap -Pn -sC -sV -p 53,389,445 -oN scans/v.txt 10.129.95.210',
  'Nmap scan report for 10.129.95.210',
  'Host is up (0.02s latency).',
  'PORT    STATE SERVICE VERSION',
  '53/tcp  open  domain  Simple DNS Plus',
  '389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: htb.local)',
  '445/tcp open  microsoft-ds',
  '| smb2-security-mode:',
  '|_  Message signing enabled',
  'Nmap done',
].join('\n');

// The reported case: operator ran a -sC -sV scan but pasted it onto the FAST move's inline box, so
// the paste is TAGGED with the fast command (no -sV). Both markers must still be proven.
var tagged = OBOL.parsers.parseActionOutput({
  actionId: 'nmap-fast-open-ports',
  command: 'nmap -Pn -p- --min-rate 5000 --open -oN scans/allports.txt 10.129.95.210',
  stdout: versionScan, source: 'nmap', scope: 'host:10.129.95.210', domain: '',
});
var tk = kindsOf(tagged);
ok(tk.indexOf('ports.open') >= 0, 'the scan proves the open-port surface');
ok(tk.indexOf('scan.nmap.quick') >= 0, 'scan.nmap.quick is proven (the port-discovery move completes)');
ok(tk.indexOf('scan.nmap.version') >= 0, 'scan.nmap.version is proven from CONTENT despite the fast-command tag (no re-suggest / double paste)');

// A genuinely bare port sweep must NOT falsely claim a version scan.
var bareScan = ['Nmap scan report for 10.129.95.210', 'Host is up.', 'PORT     STATE SERVICE', '53/tcp   open  domain', '445/tcp  open  microsoft-ds', 'Nmap done'].join('\n');
var bare = OBOL.parsers.parseActionOutput({
  actionId: 'nmap-fast-open-ports',
  command: 'nmap -Pn -p- --min-rate 5000 --open -oN scans/allports.txt 10.129.95.210',
  stdout: bareScan, source: 'nmap', scope: 'host:10.129.95.210', domain: '',
});
var bk = kindsOf(bare);
ok(bk.indexOf('scan.nmap.quick') >= 0, 'a bare -p- sweep still proves the quick marker');
ok(bk.indexOf('scan.nmap.version') === -1, 'a bare sweep with no versions does NOT over-claim scan.nmap.version');

// A TARGETED version scan (-sV -p <list>, no -p-) with NO action tag must still prove the quick
// marker — any scan that returned open ports IS port discovery, so the basic-port-scan move retires.
var targeted = OBOL.parsers.parseActionOutput({
  actionId: '', command: 'nmap -Pn -sC -sV -p 53,389,445 -oX - 10.129.95.210',
  stdout: versionScan, source: 'nmap', scope: 'host:10.129.95.210', domain: '',
});
var gk = kindsOf(targeted);
ok(gk.indexOf('scan.nmap.quick') >= 0 && gk.indexOf('scan.nmap.version') >= 0,
  'a targeted -sV -p<list> scan (no -p-, no action tag) proves BOTH markers — the fast-scan move retires');
// but a scan that found NO open ports does not claim port discovery
var empty = OBOL.parsers.parseActionOutput({ actionId: '', command: 'nmap -Pn -p 9999 10.129.95.210', stdout: 'Nmap scan report for 10.129.95.210\nHost is up.\nAll 1 scanned ports are closed\nNmap done', source: 'nmap', scope: 'host:10.129.95.210', domain: '' });
ok(kindsOf(empty).indexOf('scan.nmap.quick') === -1, 'a scan with no open ports does NOT claim port discovery');

console.log(fail ? ('\nNMAP MARKERS: ' + fail + ' FAILURES') : '\nNMAP MARKERS: all passed');
process.exit(fail ? 1 : 0);
