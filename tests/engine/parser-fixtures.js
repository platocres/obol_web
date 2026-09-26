/*!
 * obol engine — tests/engine/parser-fixtures.js
 * Runs the golden parser fixture corpus through the ported vanilla-JS parsers and asserts:
 *   - every expected_supported_kind is present as a SUPPORTED fact;
 *   - every expected_refuted_kind is present as a REFUTED fact;
 *   - each expected_facts value_contains deep-matches some fact of that kind/state/scope;
 *   - the anti-overclaim gate: supported ∩ effective-forbidden == ∅
 *     (effective-forbidden = defaults.forbidden − case.allow_default ∪ case.forbidden);
 *   - expected_fact_count when a case pins it;
 *   - every retained fact's source === command (lineage discipline).
 *
 * Run: node tests/engine/parser-fixtures.js
 * Self-contained: loads the engine + parsers into a plain global and reads the copied corpus.
 */
'use strict';
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.resolve(__dirname, '..', '..');
var ENGINE = path.join(ROOT, 'assets', 'engine');
var FIXTURES = path.join(__dirname, 'fixtures', 'parser');

// ---- load the engine into a shared context (module pattern attaches to globalThis) ---- //
var ctx = { console: console };
ctx.globalThis = ctx;
vm.createContext(ctx);
function load(file) {
  var code = fs.readFileSync(file, 'utf8');
  vm.runInContext(code, ctx, { filename: file });
}
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) {
  load(path.join(ENGINE, 'parsers', m + '.js'));
});
load(path.join(ENGINE, 'parsers', 'index.js'));
var OBOL = ctx.OBOL;

// ---- deep "value_contains" matcher ---- //
function deepContains(actual, expected) {
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return false;
    return expected.every(function (ee) {
      return actual.some(function (ae) { return deepContains(ae, ee); });
    });
  }
  if (expected && typeof expected === 'object') {
    if (!actual || typeof actual !== 'object') return false;
    return Object.keys(expected).every(function (k) {
      return Object.prototype.hasOwnProperty.call(actual, k) && deepContains(actual[k], expected[k]);
    });
  }
  return actual === expected;
}

// ---- run ---- //
var manifest = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'manifest.json'), 'utf8'));
var defaults = manifest.defaults || {};
var defaultTarget = defaults.target || '10.10.10.10';
var defaultForbidden = defaults.forbidden_supported_kinds || [];

var failures = [];
var passed = 0;

manifest.cases.forEach(function (tc) {
  var errs = [];
  var stdout = '';
  try {
    stdout = fs.readFileSync(path.join(FIXTURES, tc.stdout), 'utf8');
  } catch (e) {
    failures.push({ id: tc.id, errs: ['missing fixture ' + tc.stdout] });
    return;
  }
  var scope = 'host:' + (tc.target || defaultTarget);
  var res = OBOL.parsers.parseActionOutput({
    actionId: tc.action_id || '',
    command: tc.command || '',
    stdout: stdout,
    stderr: '',
    source: tc.command || '',
    scope: scope,
    domain: tc.domain || '',
  });
  var facts = res.facts;

  var supportedKinds = {};
  facts.forEach(function (f) { if (f.state === 'supported') supportedKinds[f.kind] = true; });
  var refutedKinds = {};
  facts.forEach(function (f) { if (f.state === 'refuted') refutedKinds[f.kind] = true; });

  // 1. expected supported kinds present
  (tc.expected_supported_kinds || []).forEach(function (k) {
    if (!supportedKinds[k]) errs.push('missing expected supported kind: ' + k);
  });
  // 2. expected refuted kinds present
  (tc.expected_refuted_kinds || []).forEach(function (k) {
    if (!refutedKinds[k]) errs.push('missing expected refuted kind: ' + k);
  });

  // 3. expected_facts value_contains / state / scope
  (tc.expected_facts || []).forEach(function (ef) {
    var wantState = ef.state || 'supported';
    var candidates = facts.filter(function (f) {
      return f.kind === ef.kind && f.state === wantState &&
        (ef.scope === undefined || f.scope === ef.scope);
    });
    var ok = candidates.some(function (f) {
      return ef.value_contains === undefined || deepContains(f.value, ef.value_contains);
    });
    if (!ok) {
      errs.push('expected_fact not satisfied: ' + ef.kind +
        (ef.scope ? ' scope=' + ef.scope : '') +
        ' contains ' + JSON.stringify(ef.value_contains || {}));
    }
  });

  // 4. anti-overclaim gate
  var allow = tc.allow_default_forbidden_supported_kinds || [];
  var forbidden = {};
  defaultForbidden.forEach(function (k) { if (allow.indexOf(k) < 0) forbidden[k] = true; });
  (tc.forbidden_supported_kinds || []).forEach(function (k) { forbidden[k] = true; });
  Object.keys(forbidden).forEach(function (k) {
    if (supportedKinds[k]) errs.push('anti-overclaim: forbidden supported kind present: ' + k);
  });

  // 5. expected_fact_count
  if (typeof tc.expected_fact_count === 'number' && facts.length !== tc.expected_fact_count) {
    errs.push('expected_fact_count ' + tc.expected_fact_count + ' but got ' + facts.length);
  }

  // 6. lineage: every fact's source === command
  facts.forEach(function (f) {
    if (f.source !== (tc.command || '')) errs.push('fact source != command for kind ' + f.kind + ' (source="' + f.source + '")');
  });

  if (errs.length) failures.push({ id: tc.id, errs: errs });
  else passed++;
});

console.log('parser fixtures: ' + passed + '/' + manifest.cases.length + ' cases passed');
if (failures.length) {
  failures.forEach(function (fl) {
    console.error('\nFAIL ' + fl.id);
    fl.errs.forEach(function (e) { console.error('  - ' + e); });
  });
  process.exit(1);
}
console.log('OK — all parser fixtures pass.');
