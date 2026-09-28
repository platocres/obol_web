/* findings-catalog-smoke.js — the ported findings catalog + fact-driven match engine
 * (data/findings-catalog.js + assets/engine/findings.js). Builds a synthetic AD kill-chain FactSet and
 * asserts the catalog surfaces the expected AD findings; a bare recon FactSet surfaces ~none. */
'use strict';
require('../../assets/engine/facts.js');
require('../../data/findings-catalog.js');
require('../../assets/engine/findings.js');
var OBOL = globalThis.OBOL;
var F = OBOL.facts;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

console.log('catalog entries loaded:', OBOL.findingsCatalog.length);
ok(OBOL.findingsCatalog.length >= 550, 'catalog carries the ported entries plus web supplements (' + OBOL.findingsCatalog.length + ')');

function mk(kind) { return F.makeFact({ kind: kind, scope: 'host:10.0.0.5', value: {}, state: F.ProofState.SUPPORTED }); }

// AD kill-chain fixture: AD kill-chain proof kinds all proven on one host.
var adKinds = ['hash.asrep', 'ad.control_paths', 'loot.ntds', 'hash.krbtgt',
  'ad.anonymous_bind', 'smb.smbv1', 'access.admin', 'smb.null_session'];
var fs = new F.FactSet(adKinds.map(mk));

var matched = OBOL.findings.assess(fs);
var titles = matched.map(function (v) { return v.title; });
console.log('\nAD fixture matched (' + matched.length + '):');
titles.forEach(function (t) { console.log('  - ' + t); });

ok(matched.length >= 5, 'AD fixture yields AT LEAST 5 findings (' + matched.length + ')');
['AS-REP Roasting', 'DCSync Replication Abuse', 'Dangerous Active Directory ACLs'].forEach(function (t) {
  ok(titles.indexOf(t) >= 0, 'AD findings include "' + t + '"');
});

// each matched finding-view carries the report metadata + KEV stub.
var asrep = matched.find(function (v) { return v.title === 'AS-REP Roasting'; });
ok(asrep && asrep.severity === 'high' && asrep.kev === false, 'AS-REP Roasting view: severity high, kev stubbed false');
ok(asrep && asrep.trigger_kinds.indexOf('hash.asrep') >= 0, 'AS-REP view exposes its trigger_kinds (hash.asrep)');

// severity sort: critical (DCSync) sorts before high (AS-REP).
var dcsyncIdx = titles.indexOf('DCSync Replication Abuse');
var asrepIdx = titles.indexOf('AS-REP Roasting');
ok(dcsyncIdx >= 0 && asrepIdx >= 0 && dcsyncIdx < asrepIdx, 'critical findings sort ahead of high (DCSync before AS-REP)');

// a bare recon FactSet proves nothing report-worthy → 0 or very few findings.
var bare = new F.FactSet(['target.configured', 'host.up', 'ports.open'].map(mk));
var bareMatched = OBOL.findings.assess(bare);
console.log('\nbare recon fixture matched (' + bareMatched.length + '):', bareMatched.map(function (v) { return v.title; }).join(', ') || '(none)');
ok(bareMatched.length <= 2, 'bare recon FactSet yields 0 or very few findings (' + bareMatched.length + ')');

console.log(fail ? ('\nFINDINGS CATALOG SMOKE: ' + fail + ' FAILURES') : '\nFINDINGS CATALOG SMOKE: all passed');
process.exit(fail ? 1 : 0);
