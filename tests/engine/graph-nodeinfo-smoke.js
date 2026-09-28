/* Graph node metadata + title case: proven milestone facts are labeled with their catalog technique name
 * (a node reads "DCSync Replication Abuse", not "loot.ntds"), OBOL.graph.buildNodeInfo returns a hover
 * card payload (title, explanation, command) per node, and titleCase keeps AD/security acronyms canonical
 * (SMB/LDAP/WinRM/DCSync) while lowercasing connector words. Generic data. */
'use strict';
var fs = require('fs'), path = require('path');
var ROOT = path.join(__dirname, '..', '..'), ENG = path.join(ROOT, 'assets', 'engine');
require(path.join(ENG, 'facts.js'));
require(path.join(ENG, 'phases.js'));
require(path.join(ENG, 'pack.js'));
require(path.join(ENG, 'command.js'));
require(path.join(ENG, 'profile.js'));
require(path.join(ROOT, 'assets', 'ui', 'util.js'));
require(path.join(ROOT, 'data', 'findings-catalog.js'));
require(path.join(ROOT, 'data', 'narratives.js'));
require(path.join(ROOT, 'data', 'packs-bundle.js'));
require(path.join(ENG, 'packs.js'));
require(path.join(ENG, 'graph.js'));
var OBOL = globalThis.OBOL, F = OBOL.facts;

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// 1) titleCase keeps acronyms canonical and lowercases connectors (the "path graph items" gripe).
var tc = OBOL.util.titleCase;
ok(tc('smb authenticated') === 'SMB Authenticated', 'titleCase: "smb authenticated" → "SMB Authenticated"');
ok(tc('ad dc candidate') === 'AD DC Candidate', 'titleCase: acronyms AD/DC preserved');
ok(tc('own the domain') === 'Own the Domain', 'titleCase: connector "the" lowercased (not first)');
ok(tc('a live host') === 'A Live Host', 'titleCase: leading article stays capitalized');
ok(tc('authenticated winrm access') === 'Authenticated WinRM Access', 'titleCase: WinRM canonical');

// 2) A proven milestone fact node is labeled with its catalog technique name.
var pack = OBOL.packs.actions();
var facts = new F.FactSet(['target.configured', 'host.up', 'ports.open', 'ad.domain_known', 'hash.asrep', 'ad.control_paths', 'loot.ntds', 'access.admin']
  .map(function (k) { return F.makeFact({ kind: k, scope: 'host:10.0.0.5', state: F.ProofState.SUPPORTED }); }));
ok(OBOL.graph.techniqueForKind('loot.ntds') === 'DCSync Replication Abuse', 'loot.ntds maps to the DCSync technique name');
ok(OBOL.graph.techniqueForKind('hash.asrep') === 'AS-REP Roasting', 'hash.asrep maps to AS-REP Roasting');
ok(OBOL.graph.techniqueForKind('port:445') == null, 'a non-technique fact maps to no technique (stays friendly)');

// 3) buildNodeInfo yields hover payloads: fact nodes carry an explanation; action nodes carry a command.
var info = OBOL.graph.buildNodeInfo(facts, pack, { params: { target: '10.0.0.5', domain: 'corp.local' } });
var vals = Object.keys(info).map(function (k) { return info[k]; });
ok(vals.length > 0, 'buildNodeInfo returns node payloads (' + vals.length + ')');
var dcNode = vals.filter(function (v) { return /DCSync Replication Abuse/.test(v.title) && v.kind === 'fact'; })[0];
ok(dcNode && dcNode.explain && dcNode.explain.length > 20, 'the DCSync fact node carries a narrative explanation');
ok(vals.some(function (v) { return v.kind === 'action' && v.command && v.command.length > 0; }), 'action nodes carry a runnable command for the copy button');
ok(vals.every(function (v) { return v.explain.indexOf('{{') === -1; }), 'no unfilled {{tokens}} leak into hover text');

console.log(fail ? ('\nGRAPH NODEINFO: ' + fail + ' FAILURES') : '\nGRAPH NODEINFO: all passed');
process.exit(fail ? 1 : 0);
