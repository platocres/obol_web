/* Parser dispatch resilience: one fragile sub-parser must never lose the whole paste. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ENGINE = path.join(__dirname, '..', '..', 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'parsers', '_common.js'));
['nmap', 'ad', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENGINE, 'parsers', m + '.js')); });
load(path.join(ENGINE, 'parsers', 'index.js'));
var OBOL = ctx.OBOL, C = OBOL._parserCommon;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

var cmd = 'nmap -Pn -p- --open -oN ~/x/scans/a.txt 10.129.95.210';
var stdout = ['PORT STATE SERVICE', '53/tcp open domain', '389/tcp open ldap', '445/tcp open microsoft-ds', 'Nmap done: 1 IP address (1 host up) scanned in 1s'].join('\n');

// baseline: clean parse works
var base = OBOL.parsers.parseActionOutput({ command: cmd, stdout: stdout, source: cmd, scope: 'host:10.129.95.210', domain: '' });
ok(base.facts.length > 0 && !base.error, 'a clean nmap paste parses with no error');

// a downstream sub-parser throws (simulates a fragile parser on unusual real output)
var orig = C._parse_shadow_file;
C._parse_shadow_file = function () { throw new Error('boom'); };
var res = OBOL.parsers.parseActionOutput({ command: cmd, stdout: stdout, source: cmd, scope: 'host:10.129.95.210', domain: '' });
C._parse_shadow_file = orig;

ok(res.facts && res.facts.length > 0, 'a throwing downstream parser does NOT lose the facts collected before it (' + (res.facts || []).length + ')');
ok(res.facts.some(function (f) { return f.kind === 'ports.open' || f.kind === 'ldap.reachable' || /^port:/.test(f.kind); }), 'the nmap ports still come through');
ok(!!res.error, 'the failure is reported (error field) instead of thrown');
ok(res.facts.length === base.facts.length, 'exactly the pre-throw facts are kept — nothing invented, nothing new lost here');

console.log(fail ? ('\nPARSER RESILIENCE: ' + fail + ' FAILURES') : '\nPARSER RESILIENCE: all passed');
process.exit(fail ? 1 : 0);
