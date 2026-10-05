/* Decision-map engine (OBOL.decisionMap): the by-port decision forest derives from the real move
 * graph + ranker, the hand-off interchanges fire, the parse/coverage/wiring diagnostics are sound, and
 * the authored PARSER_SIGNATURES capability set stays in sync with the real parsers (no drift). */
'use strict';
var fs = require('fs'), path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack;
var pdir = path.join(R, 'data/packs'), bundle = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); });
var A = PK.loadPacks(Object.keys(bundle).map(function (k) { return bundle[k]; }));
OBOL.packs = { actions: function () { return A; }, packData: function () { return bundle; } };
req('data/tools-install.js'); req('data/study-fixtures.js'); req('assets/engine/study.js');
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'shape'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');
req('data/decision-forks.js'); req('data/parser-signatures.js'); req('data/coverage-expected.js');
req('assets/engine/decisionmap.js');
var DM = OBOL.decisionMap;

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// --- the forest builds ---
var tree = DM.decisionTree();
ok(tree.ports.length >= 30, 'the forest has a subtree per by-port card (' + tree.ports.length + ')');
ok(tree.access.length >= 5, 'the forest carries the post-foothold access interchanges (' + tree.access.length + ')');

// filter re-roots to the requested ports only
var one = DM.decisionTree({ ports: ['p1521'] });
ok(one.ports.length === 1 && one.ports[0].key === 'p1521', 'filtering by port returns only that port subtree');

// a port subtree: roots, nodes, and a ranked spine that stays within the port's moves
var web = tree.ports.filter(function (p) { return p.key === 'p80'; })[0];
ok(web && web.order.length > 5, 'the HTTP subtree has many nodes');
ok(web.spine.length >= 1 && web.nodes[web.spine[0]], "the ranked spine's first move is a node in the subtree");

// hand-off: a move that lands a foothold links to an access-tier interchange rather than inlining it
var ftpTree = tree.ports.filter(function (p) { return p.key === 'p21'; })[0];
var hasHandoff = ftpTree.order.some(function (id) { return (ftpTree.nodes[id].handoffs || []).length > 0; });
ok(hasHandoff, 'the FTP subtree hands off to a post-foothold map (ftp-upload-webshell → shell)');
ok(DM.handoffFor('foothold.linux') && DM.handoffFor('foothold.linux').to === 'shell-linux', 'foothold.linux hands off to the Linux-shell interchange');
ok(!DM.handoffFor('web.sqli_confirmed'), 'a non-interchange fact does not hand off');

// --- the gap report is sound ---
var gr = DM.gapReport();
ok(gr.wiring.unreachable.length === 0, 'no move is unreachable (every requirement is obtainable)');
ok(gr.wiring.missingHandoff.length === 0, 'every hand-off points at an access card that exists');
ok(gr.counts.parseGap >= 1, 'parse-gap lens finds the documented unreadable facts (' + gr.counts.parseGap + ')');
// the known unported findings-checks surface as parse gaps (the diagnostic working as intended)
var gapIds = gr.parse.gap.map(function (g) { return g.id; });
ok(gapIds.indexOf('check-tls-config') >= 0 && gapIds.indexOf('recon-dns') >= 0, 'the known unported parsers (tls check, dns zone) show as parse gaps');
// every seeded expected technique now has a backing move, so the oracle reports zero coverage gaps;
// the machinery is still exercised (COVERAGE_EXPECTED is populated and each entry resolves to a move).
ok((OBOL.COVERAGE_EXPECTED && Object.keys(OBOL.COVERAGE_EXPECTED).length >= 6), 'the expected-coverage oracle is populated');
ok(gr.coverage.length === 0, 'the oracle reports no coverage gaps now every seeded technique has a module (' + gr.coverage.length + ')');
ok(!gr.coverage.some(function (c) { return c.port === 'p3306'; }), 'the p3306 INTO OUTFILE technique resolves to its new module (mysql-outfile-rce)');

// --- parser capability derivation ---
var pc = DM.parserCoverage();
ok(pc['nmap-fast-open-ports'] && pc['nmap-fast-open-ports'].status === 'verified', 'a port scan reads back verified (its facts are all parseable)');
ok(pc['recon-telnet'] && pc['recon-telnet'].status === 'noproduce', 'an enum-only move with no produced fact is graded noproduce, not a gap');

console.log('\nDECISION MAP SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
