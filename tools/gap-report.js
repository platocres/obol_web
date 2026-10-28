#!/usr/bin/env node
/*!
 * tools/gap-report.js — the coverage X-ray for the decision map (see docs/DECISION-MAP.md).
 *
 * Loads the real engine + packs + parsers + the decision-map data, then prints the three gap lenses:
 *   COVERAGE  — a technique the expected-coverage oracle lists for a port, with no backing move.
 *   PARSE: declared parser support, reported separately from actual per-move sample observations.
 *   WIRING    — a move that can never become ready (a requirement nothing produces/parses/hands over),
 *               plus a dead-end review list and truly-orphan parser facts.
 * Plus fork-condition coverage, and (--verify) real corpus assertions and a comparison of authored
 * PARSER_SIGNATURES with source-declared and actually observed emits.
 *
 * Run:  node tools/gap-report.js            (full report)
 *       node tools/gap-report.js --verify   (also cross-check signatures vs real parsers)
 *       node tools/gap-report.js --check    (exit 1 on unreachable moves, missing hand-offs, missing signature emits, or corpus failure)
 */
'use strict';
var fs = require('fs'), path = require('path');
var ROOT = path.join(__dirname, '..');
function req(p) { return require(path.join(ROOT, p)); }

req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack;
var pdir = path.join(ROOT, 'data/packs'), bundle = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); });
var A = PK.loadPacks(Object.keys(bundle).map(function (k) { return bundle[k]; }));
OBOL.packs = { actions: function () { return A; }, packData: function () { return bundle; } };
req('data/tools-install.js'); req('data/study-fixtures.js'); req('assets/engine/study.js');
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'inference'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');
req('data/decision-forks.js'); req('data/parser-signatures.js'); req('data/coverage-expected.js');
req('assets/engine/decisionmap.js');

var DM = OBOL.decisionMap, gr = DM.gapReport();
var argv = process.argv.slice(2), VERIFY = argv.indexOf('--verify') >= 0, CHECK = argv.indexOf('--check') >= 0;
function hd(s) { console.log('\n== ' + s + ' =='); }
function list(arr, fmt) { if (!arr.length) { console.log('  (none)'); return; } arr.forEach(function (x) { console.log('  ' + fmt(x)); }); }

console.log('OBOL decision-map gap report — ' + gr.counts.moves + ' moves');
console.log(JSON.stringify(gr.counts));
console.log('Fixture status totals: ' + gr.parse.verified.length + ' fully demonstrated, ' + gr.parse.unverified.length
  + ' not fully demonstrated, ' + ((gr.parse.statusCounts || {}).noproduce || 0) + ' without observable output proof.');
console.log('Missing samples (' + gr.parse.missingFixture.length + ') and parser errors (' + gr.parse.errors.length
  + ') are subsets of not fully demonstrated, not additional moves. Signature declarations are reported separately.');

hd('COVERAGE gaps — expected technique with no backing move (' + gr.coverage.length + ')');
list(gr.coverage, function (c) { return '[' + c.port + '] ' + c.technique + (c.note ? '  — ' + c.note : ''); });

hd('DECLARED PARSER CAPABILITY gaps (' + gr.parse.gap.length + ')');
list(gr.parse.gap, function (g) { return g.id + '  → unreadable: ' + g.unreadable.join(', '); });

hd('DECLARED PARSER CAPABILITY partial coverage (' + gr.parse.partial.length + ')');
list(gr.parse.partial, function (g) { return g.id + '  → unreadable: ' + g.unreadable.join(', '); });

hd('WIRING — unreachable moves (' + gr.wiring.unreachable.length + ')');
list(gr.wiring.unreachable, function (u) { return u.id + '  needs ' + (u.kind === 'any' ? 'one of: ' : '') + u.fact; });

hd('WIRING — dead-end review (produces a fact nothing uses) (' + gr.wiring.deadEnd.length + ')');
list(gr.wiring.deadEnd, function (d) { return d.id + '  → ' + d.fact; });

hd('WIRING — missing hand-off target (' + gr.wiring.missingHandoff.length + ')');
list(gr.wiring.missingHandoff, function (d) { return d.id + '  → ' + d.fact + ' (no access card "' + d.to + '")'; });

hd('Orphan parser facts — minted but used by nothing (' + gr.orphanParserFacts.length + ')');
console.log('  ' + (gr.orphanParserFacts.join(', ') || '(none)'));

// fork-condition coverage
var forks = OBOL.DECISION_FORKS || {}, withFork = A.filter(function (m) { return forks[m.id]; }).length;
hd('Fork-condition coverage');
console.log('  ' + withFork + '/' + A.length + ' moves have an authored fork condition');

var drift = { missingEmit: [], staleEmit: [] }, corpus = {passed:0,total:0,failures:[]};
if (VERIFY || CHECK) {
  // static mkFact('literal') kinds across parser sources + prefix families already allowed
  var srcKinds = {};
  fs.readdirSync(path.join(ROOT, 'assets/engine/parsers')).filter(function (f) { return f.endsWith('.js'); }).forEach(function (f) {
    var s = fs.readFileSync(path.join(ROOT, 'assets/engine/parsers', f), 'utf8');
    (s.match(/mkFact\('[a-z][a-z0-9._]+'/g) || []).forEach(function (m) { srcKinds[m.slice(8, -1)] = 1; });
    // data-driven parsers (e.g. blockers.js) declare the kind they emit in a `kind: 'blocker.*'` table
    // and mint it with mkFact(entry.kind, …); harvest just those so the drift check sees them without
    // sweeping up the kind: fields of ordinary extract-return objects.
    (s.match(/\bkind:\s*'(?:blocker|advice)\.[a-z0-9._]+'/g) || []).forEach(function (m) { srcKinds[m.replace(/.*'([^']+)'.*/, '$1')] = 1; });
    (s.match(/\badd\('blocker\.[a-z0-9._]+'/g) || []).forEach(function (m) { srcKinds[m.replace(/.*'([^']+)'.*/, '$1')] = 1; });
    (OBOL._nxcCatalog || []).forEach(function (c) { (c.produces || []).forEach(function (k) { srcKinds[k] = 1; }); });
  });
  // live corpus-minted kinds (parser fixtures exercise diverse real outputs)
  var minted = {};
  try {
    var man = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/engine/fixtures/parser/manifest.json'), 'utf8'));
    corpus = require('./verify-parser-corpus.js').verifyCorpus(man, function(tc){return fs.readFileSync(path.join(ROOT,'tests/engine/fixtures/parser',tc.stdout),'utf8');}, OBOL.parsers.parseActionOutput);
    minted = corpus.minted;
  } catch (e) { corpus.failures.push({id:'manifest',errors:[(e && e.message) || String(e)]}); }
  hd('EMPIRICAL PARSER CORPUS: ' + corpus.passed + '/' + corpus.total + ' cases passed');
  list(corpus.failures,function(c){return c.id + ': ' + c.errors.join('; ');});
  var cap = DM.capability();
  function isEnv(k) { return /^(target\.|host\.up$|ports\.open$|port:|scan\.|service\.)/.test(k) || /\.reachable$/.test(k); }
  function covered(k) { if (isEnv(k)) return true; if (cap.exact[k]) return true; for (var i = 0; i < cap.pref.length; i++) if (k.indexOf(cap.pref[i]) === 0) return true; return false; }
  // a real emit (static literal or corpus-minted) that no signature covers = drift (signatures too narrow)
  Object.keys(srcKinds).concat(Object.keys(minted)).forEach(function (k) { if (!covered(k) && drift.missingEmit.indexOf(k) < 0) drift.missingEmit.push(k); });
  // a signature exact emit that is neither a static literal nor corpus-minted = possibly stale
  Object.keys(cap.exact).forEach(function (k) { if (!srcKinds[k] && !minted[k]) drift.staleEmit.push(k); });
  hd('SIGNATURE DRIFT: source-declared or observed emits missing from PARSER_SIGNATURES (' + drift.missingEmit.length + ')');
  console.log('  ' + (drift.missingEmit.sort().join(', ') || '(none)'));
  hd('SIGNATURE REVIEW: emits not observed in source declarations or the corpus (' + drift.staleEmit.length + ')');
  console.log('  ' + (drift.staleEmit.sort().join(', ') || '(none)'));
}
if (VERIFY && corpus.failures.length) process.exitCode = 1;

if (CHECK) {
  var hard = gr.wiring.unreachable.length + gr.wiring.missingHandoff.length + drift.missingEmit.length + corpus.failures.length;
  if (hard) { console.error('\nGAP CHECK FAIL: ' + gr.wiring.unreachable.length + ' unreachable, ' + gr.wiring.missingHandoff.length + ' missing hand-off, ' + drift.missingEmit.length + ' signature-drift, ' + corpus.failures.length + ' corpus failures.'); process.exit(1); }
  console.log('\nGAP CHECK OK: no unreachable moves, missing hand-offs, signature drift, or parser corpus failures.');
}
