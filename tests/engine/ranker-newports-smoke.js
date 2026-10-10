/* Next-Steps parity for the new tier-1/2/3 port modules: when a target shows one of the newly-added
 * ports open, the coach (OBOL.pack.nextActionsV2) must surface that port's module as a suggested next
 * action (with its command), not leave the operator staring at an open port with no lead. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
var fs = require('fs'), path = require('path');
var OBOL = globalThis.OBOL, PK = OBOL.pack, F = OBOL.facts;

var pdir = path.join(__dirname, '..', '..', 'data', 'packs');
var PACK = PK.loadPacks(fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); })
  .map(function (f) { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } }));

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// target.configured/host.up/ports.open + the one port fact under test, like a fresh scan of that box.
function suggestionsForPort(port) {
  var base = ['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick'];
  var flist = base.concat(['port:' + port]).map(function (kind, i) {
    return F.makeFact({ kind: kind, scope: { target: '10.10.10.10' }, source: 'scan', created_at: 1700000000000 + i * 1000 });
  });
  return PK.nextActionsV2(new F.FactSet(flist), PACK, {}).map(function (a) { return a.id; });
}

// each new module keyed by the port a scan would reveal
var CASES = [
  ['23', 'recon-telnet'],
  ['512', 'recon-rservices'],
  ['873', 'recon-rsync'],
  ['69', 'recon-tftp'],
  ['6000', 'recon-x11'],
  ['21', 'ftp-upload-webshell'],
  ['1521', 'oracle-tns'],
  ['9200', 'elasticsearch-enum'],
  ['11211', 'memcached-enum'],
  ['8009', 'ajp-ghostcat'],
  ['1099', 'java-rmi'],
];
CASES.forEach(function (c) {
  var ids = suggestionsForPort(c[0]);
  ok(ids.indexOf(c[1]) >= 0, 'port ' + c[0] + ' open → Next Steps suggests "' + c[1] + '"');
});

// and the suggested action carries a runnable command (so the coach shows what to run, not just a name)
var oracle = PK.nextActionsV2(new F.FactSet(['target.configured', 'host.up', 'ports.open', 'port:1521'].map(function (k, i) {
  return F.makeFact({ kind: k, scope: { target: '10.10.10.10' }, source: 'scan', created_at: 1700000000000 + i * 1000 });
})), PACK, {}).filter(function (a) { return a.id === 'oracle-tns'; })[0];
ok(oracle && (oracle.commands || []).length > 0, 'the suggested oracle-tns action carries a command for the operator to run');

console.log('\nRANKER NEW-PORTS: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
