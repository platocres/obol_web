/* Corpus extraction-schema smoke (Stage 1 lock). Asserts the Stage 1 record contract in
 * tools/corpus/extraction-schema.js: the asset-record shape (type/fidelity enums, the dedup key, the
 * provenance floor, the Whole-Asset Rule), the facts-axis label sub-contract, and the fact-kind vocabulary
 * built from the LIVE engine PARSER_SIGNATURES (exact, prefix-wildcard, and environmental facts, mirroring
 * assets/engine/decisionmap.js). The corpus-optional tail then validates the real
 * tools/corpus/labels/0xdf-facts.json against the sub-contract so a mistyped expected_kind cannot silently
 * register as a facts-axis miss (the gap Stage 1 closes). Hand-built shapes, no verbatim corpus output
 * (docs/CORPUS-MINING.md Principle 7). qa-only; nothing ships. House style: no em or en dashes. */
'use strict';
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.join(__dirname, '..', '..');
var S = require(path.join(ROOT, 'tools', 'corpus', 'extraction-schema.js'));

// Load PARSER_SIGNATURES the way the engine does (an IIFE that hangs OBOL off the global).
var ctx = { globalThis: {} }; ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(ROOT, 'data', 'parser-signatures.js'), 'utf8'), ctx, { filename: 'parser-signatures.js' });
var SIGS = ctx.OBOL.PARSER_SIGNATURES;

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// ---- contract self-consistency ----
ok(S.ASSET_TYPES.length === 6 && S.ASSET_TYPES.indexOf('screenshot') >= 0, 'asset-type enum is the Section 4 set');
ok(S.FIDELITIES.join(',') === 'text,ocr', 'fidelity enum is text,ocr');

// ---- dedup key ----
var h1 = S.contentHash('nmap -sCV 10.10.10.1\nPORT STATE\n80/tcp open\n');
var h2 = S.contentHash('nmap -sCV 10.10.10.1\r\nPORT STATE\r\n80/tcp open\r\n');
ok(/^[0-9a-f]{64}$/.test(h1), 'contentHash returns a sha256 hex digest');
ok(h1 === h2, 'contentHash normalizes CRLF so the same block hashes identically across platforms');
ok(S.contentHash('a') !== S.contentHash('b'), 'contentHash distinguishes different content');

// ---- fact-kind vocabulary (mirrors decisionmap capability + env) ----
var V = S.buildKindVocabulary(SIGS);
ok(V.exactCount > 50 && V.prefixCount > 0, 'vocabulary built from PARSER_SIGNATURES (' + V.exactCount + ' exact, ' + V.prefixCount + ' prefix)');
ok(V.isKnownKind('credential.available'), 'exact kind known: credential.available');
ok(V.isKnownKind('web.sqli_confirmed'), 'exact kind known: web.sqli_confirmed');
ok(V.isKnownKind('service.mysql'), 'prefix-family kind known: service.mysql');
ok(V.isKnownKind('vuln.cve-2021-41773'), 'prefix-family kind known: vuln.*');
ok(V.isKnownKind('smb.reachable') && V.isKnownKind('port:445'), 'environmental kinds known: *.reachable, port:N');
ok(!V.isKnownKind('credential.availabe'), 'typo kind rejected: credential.availabe');
ok(!V.isKnownKind('totally.madeup'), 'unknown kind rejected: totally.madeup');

// ---- asset record: a valid one of each axis passes ----
function baseAsset(type) { return { hash: S.contentHash('x' + type), type: type, fidelity: 'text' }; }
var src = { url: 'https://example.test/writeup', author: 'anon', retrieved: '2026-10-23' };
var recOut = { source: src, asset: baseAsset('code_block'),
  output_blocks: [{ command_shown: 'id', tool: 'ssh', raw_output: 'uid=0(root)', truncated: false, fidelity: 'text' }] };
ok(S.validateRecord(recOut).ok, 'valid code_block record with one output block passes');
ok(S.validateRecord({ source: src, asset: baseAsset('screenshot'), flow: ['recon', 'foothold'] }).ok, 'valid screenshot record carrying only flow passes');

// ---- asset record: malformed ones fail with a pointed error ----
function firstErr(r) { return (r.errors[0] || ''); }
var rBadType = S.validateRecord({ source: src, asset: { hash: S.contentHash('z'), type: 'blog_post', fidelity: 'text' }, notes: 'n', failures: ['x'] });
ok(!rBadType.ok && /asset\.type/.test(firstErr(rBadType)), 'unknown asset.type rejected');
var rBadFid = S.validateRecord({ source: src, asset: { hash: S.contentHash('z'), type: 'code_block', fidelity: 'pixels' }, failures: ['x'] });
ok(!rBadFid.ok && rBadFid.errors.some(function (m) { return /fidelity/.test(m); }), 'unknown fidelity rejected');
var rNoHash = S.validateRecord({ source: src, asset: { type: 'code_block', fidelity: 'text' }, failures: ['x'] });
ok(!rNoHash.ok && rNoHash.errors.some(function (m) { return /asset\.hash/.test(m); }), 'missing dedup hash rejected');
var rNoSrc = S.validateRecord({ asset: baseAsset('code_block'), failures: ['x'] });
ok(!rNoSrc.ok && rNoSrc.errors.some(function (m) { return /source/.test(m); }), 'missing provenance rejected');
var rEmpty = S.validateRecord({ source: src, asset: baseAsset('code_block') });
ok(!rEmpty.ok && rEmpty.errors.some(function (m) { return /axis of value/.test(m); }), 'record carrying no axis rejected (Whole-Asset Rule)');
var rBadBlock = S.validateRecord({ source: src, asset: baseAsset('code_block'),
  output_blocks: [{ command_shown: 'id', tool: 'ssh', raw_output: 'x', truncated: 'no', fidelity: 'text' }] });
ok(!rBadBlock.ok && rBadBlock.errors.some(function (m) { return /truncated/.test(m); }), 'output block with non-boolean truncated rejected');
var rBadFact = S.validateRecord({ source: src, asset: baseAsset('code_block'), facts_implied: [{ kind: 'nope.bad' }] }, { isKnownKind: V.isKnownKind });
ok(!rBadFact.ok && rBadFact.errors.some(function (m) { return /known engine fact kind/.test(m); }), 'facts_implied naming an unknown kind rejected');

// ---- label sub-contract ----
var goodCase = { id: 'abc123', file: 'box.md', command: 'nmap -sCV 10.0.0.1', note: 'n',
  expected_kinds: ['host.up', 'ports.open', 'smb.reachable'], forbidden_kinds: ['credential.available'],
  expected_values: [{ kind: 'ports.open', value_contains: { ports: [445] } }] };
ok(S.validateLabelCase(goodCase, V.isKnownKind).ok, 'valid label case passes');
ok(!S.validateLabelCase({ id: 'x', file: 'f', command: 'c', expected_kinds: ['host.up', 'bogus.kind'] }, V.isKnownKind).ok, 'label case with an unknown expected kind rejected');
var overlap = S.validateLabelCase({ id: 'x', file: 'f', command: 'c', expected_kinds: ['host.up'], forbidden_kinds: ['host.up'] }, V.isKnownKind);
ok(!overlap.ok && overlap.errors.some(function (m) { return /both expected_kinds and forbidden_kinds/.test(m); }), 'kind in both expected and forbidden rejected');
ok(!S.validateLabelCase({ file: 'f', command: 'c', expected_kinds: [] }, V.isKnownKind).ok, 'label case missing id rejected');

// ---- corpus-optional: the real labels file must conform (skips when the private snapshot is absent) ----
var labelsPath = path.join(ROOT, 'tools', 'corpus', 'labels', '0xdf-facts.json');
if (fs.existsSync(labelsPath)) {
  var obj = JSON.parse(fs.readFileSync(labelsPath, 'utf8'));
  var r = S.validateLabelsFile(obj, V.isKnownKind);
  if (!r.ok) r.errors.slice(0, 20).forEach(function (m) { console.error('    labels:', m); });
  ok(r.ok, 'real labels file conforms to the sub-contract (' + r.cases + ' cases, all kinds known, ids unique)');
} else {
  console.log('  skip: tools/corpus/labels/0xdf-facts.json absent (corpus-optional)');
}

console.log('\nCORPUS EXTRACTION-SCHEMA SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
