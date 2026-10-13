#!/usr/bin/env node
/**
 * verify-multi-target.js
 * Verifies multi-target infrastructure:
 *  - Store activeTarget get/set
 *  - Per-target FactSet isolation
 *  - Per-target command templating ({{target}} filled with selected target, not global param)
 *  - Per-target coach ranking
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const sandbox = {
  console: console,
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  Date: Date,
  Math: Math,
  Array: Array,
  Object: Object,
  String: String,
  Number: Number,
  RegExp: RegExp,
  Set: Set,
  Map: Map,
  JSON: JSON,
  Promise: Promise,
  window: {},
  document: {
    addEventListener: () => {},
    getElementById: (id) => {
      if (!sandbox._elements) sandbox._elements = {};
      if (!sandbox._elements[id]) {
        sandbox._elements[id] = { id: id, innerHTML: '', setAttribute: () => {}, addEventListener: () => {} };
      }
      return sandbox._elements[id];
    }
  },
  localStorage: { getItem: () => null, setItem: () => {} },
  navigator: {},
  location: { hash: '' }
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;
sandbox.root = sandbox;

function load(relPath) {
  const code = fs.readFileSync(path.join(root, relPath), 'utf8');
  vm.runInNewContext(code, sandbox, { filename: relPath });
}

load('assets/engine/facts.js');
load('assets/engine/phases.js');
load('assets/engine/pack.js');
load('assets/engine/packs.js');
load('data/packs-bundle.js');
load('assets/engine/command.js');
load('assets/engine/workspace.js');
load('assets/ui/util.js');
load('assets/ui/icons.js');
load('assets/ui/store.js');
load('assets/ui/ctxbar.js');
load('assets/ui/routes/path.js');
load('assets/ui/routes/target.js');

const OBOL = sandbox.OBOL;

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
  console.log('PASS:', msg);
}

// 1. Setup mock engagement with 2 targets
const eng = {
  id: 'eng-multi-target-test',
  name: 'MultiTargetLab',
  params: {
    target: '10.10.11.41',
    domain: 'lab.local'
  },
  targets: [
    { id: 't-1', ip: '10.10.11.41', hostname: 'DC01', os: 'Windows' },
    { id: 't-2', ip: '10.10.11.42', hostname: 'WEB01', os: 'Linux' }
  ],
  facts: [
    // Target A facts
    { kind: 'target.configured', scope: 'host:10.10.11.41', state: 'supported', value: {} },
    { kind: 'port:88', scope: 'host:10.10.11.41', state: 'supported', value: {} },
    { kind: 'port:445', scope: 'host:10.10.11.41', state: 'supported', value: {} },
    { kind: 'smb.null_session', scope: 'host:10.10.11.41', state: 'supported', value: {} },
    // Target B facts
    { kind: 'target.configured', scope: 'host:10.10.11.42', state: 'supported', value: {} },
    { kind: 'port:80', scope: 'host:10.10.11.42', state: 'supported', value: {} },
    { kind: 'port:8080', scope: 'host:10.10.11.42', state: 'supported', value: {} },
    { kind: 'http.reachable', scope: 'host:10.10.11.42', state: 'supported', value: { port: 80 } },
    // Shared Domain facts
    { kind: 'ad.domain_known', scope: 'domain:lab.local', state: 'supported', value: { name: 'lab.local' } },
    { kind: 'credential.available', scope: 'domain:lab.local', state: 'supported', value: { user: 'guest', secret: '', domain: 'lab.local' } }
  ]
};

// Mock store.active()
OBOL.store.active = function () { return eng; };
OBOL.store.update = function (fn) { fn(eng); };

// Test 1: Store activeTarget
assert(OBOL.store.activeTarget() === null, 'Initial activeTarget is null');
OBOL.store.setActiveTarget('10.10.11.42');
assert(OBOL.store.activeTarget() === '10.10.11.42', 'activeTarget updated to 10.10.11.42');

// Test 2: FactSet isolation
const fsA = OBOL.store.factSetForTarget('10.10.11.41');
const fsB = OBOL.store.factSetForTarget('10.10.11.42');

assert(fsA.has('port:445') === true, 'Target A has port:445');
assert(fsA.has('port:80') === false, 'Target A does NOT have port:80 (isolated from B)');
assert(fsA.has('ad.domain_known') === true, 'Target A inherits domain:lab.local fact');

assert(fsB.has('port:80') === true, 'Target B has port:80');
assert(fsB.has('port:445') === false, 'Target B does NOT have port:445 (isolated from A)');
assert(fsB.has('http.reachable') === true, 'Target B has http.reachable');
assert(fsB.has('ad.domain_known') === true, 'Target B inherits domain:lab.local fact');

// Test 3: Command Context & Templating
const testCmd = { run: 'nmap -sC -sV -p {{nmap_ports}} {{target}}' };
const testAction = { id: 'test-nmap', commands: [testCmd] };

const filledA = OBOL.command.fillCommand(testAction, fsA, { params: Object.assign({}, eng.params, { target: '10.10.11.41' }), target: '10.10.11.41' }, 0);
assert(filledA.filled.includes('10.10.11.41'), 'Command for A filled with 10.10.11.41: ' + filledA.filled);
assert(filledA.filled.includes('88,445'), 'Command for A filled with ports 88,445');

const filledB = OBOL.command.fillCommand(testAction, fsB, { params: Object.assign({}, eng.params, { target: '10.10.11.42' }), target: '10.10.11.42' }, 0);
assert(filledB.filled.includes('10.10.11.42'), 'Command for B filled with 10.10.11.42: ' + filledB.filled);
assert(filledB.filled.includes('80,8080'), 'Command for B filled with ports 80,8080');

// Test 4: Coach Ranking per target
OBOL.store.setActiveTarget('10.10.11.41');
const coachA = OBOL.coach.compute();
assert(coachA.target === '10.10.11.41', 'Coach computed for target A');
assert(coachA.onFlow.length > 0, 'Coach has moves for target A');

OBOL.store.setActiveTarget('10.10.11.42');
const coachB = OBOL.coach.compute();
assert(coachB.target === '10.10.11.42', 'Coach computed for target B');
assert(coachB.onFlow.length > 0, 'Coach has moves for target B');

OBOL.store.setActiveTarget(null);
const coachAll = OBOL.coach.compute();
assert(coachAll.target === null, 'Coach computed for all targets');

// Test 5: Next Steps sub-nav remains clean and single-row
sandbox.location.hash = '#/path';
OBOL.ctxbar.render();
const barHtml = (sandbox._elements['ctxbar'] && sandbox._elements['ctxbar'].innerHTML) || '';
assert(!barHtml.includes('id="ctx-path-target"'), 'ctxbar keeps subnav clean and single-row without extra wasted line');

// Test 6: Next Steps Hero Banner contains Target Selector, Scope Lens, and Loadout Badge
const pathHtml = vm.runInNewContext('OBOL.routes.path.render({})', sandbox);
assert(pathHtml.includes('coach-hero-target'), 'Next Steps Hero banner has coach-hero-target container');
assert(pathHtml.includes('id="coach-target-select"'), 'Hero banner renders target selector dropdown');
assert(pathHtml.includes('All Targets (2)'), 'Hero target selector has All Targets (2)');
assert(pathHtml.includes('10.10.11.41 (DC01)'), 'Hero target selector has option for Target A: 10.10.11.41 (DC01)');
assert(pathHtml.includes('10.10.11.42 (WEB01)'), 'Hero target selector has option for Target B: 10.10.11.42 (WEB01)');
assert(pathHtml.includes('coach-hero-lens'), 'Hero banner consolidates Scope filter lens');
assert(pathHtml.includes('coach-hero-aside'), 'Hero banner has aside container');
assert(pathHtml.includes('hero-loadout-badge'), 'Hero banner has consolidated Loadout badge in top-right');
assert(pathHtml.includes('hero-ready-tag'), 'Hero banner integrates Ready Now move count badge');
assert(pathHtml.includes('campaign-bar-inner'), 'Campaign Playbook uses single-row campaign-bar-inner layout');
assert(pathHtml.includes('Field Notes'), 'Field Notes header rendered on canvas');
assert(!pathHtml.includes('Anatomy of a Move'), 'Anatomy of a Move replaced by Field Notes');
assert(!pathHtml.includes('<div class="ns-railhead"><h2>Ready Now'), 'Standalone Ready Now railhead divider removed');

// Test 7: Setting active target synchronizes eng.params.target
OBOL.store.setActiveTarget('10.10.11.41');
assert(OBOL.store.activeTarget() === '10.10.11.41', 'Active target is 10.10.11.41');
assert(eng.params.target === '10.10.11.41', 'eng.params.target synchronized to 10.10.11.41');

// Test 8: Move cards are stamped strictly with target IP badges (no hostnames)
const pathHtmlTargetA = vm.runInNewContext('OBOL.routes.path.render({})', sandbox);
assert(pathHtmlTargetA.includes('ns-chip-target'), 'Move cards are stamped with ns-chip-target');
assert(pathHtmlTargetA.includes('10.10.11.41'), 'Move cards for Target A stamped with 10.10.11.41');
assert(!pathHtmlTargetA.includes('10.10.11.41 · DC01'), 'Move cards do not contain hostname DC01');

// In Engagement-Wide mode:
OBOL.store.setActiveTarget(null);
const pathHtmlAll = vm.runInNewContext('OBOL.routes.path.render({})', sandbox);
assert(pathHtmlAll.includes('ns-chip-target'), 'Engagement-Wide move cards stamped with ns-chip-target');

// Test 9: Single-target engagement (Active) cards stamped strictly with IP (no hostname)
const engActive = {
  id: 'eng-active',
  params: { target: '10.129.105.90' },
  targets: [{ ip: '10.129.105.90', hostname: 'DC' }],
  facts: [
    { kind: 'port:445', scope: 'host:10.129.105.90', state: 'supported', value: {} }
  ]
};
OBOL.store.active = function () { return engActive; };
OBOL.store.setActiveTarget('10.129.105.90');
const pathHtmlSingle = vm.runInNewContext('OBOL.routes.path.render({})', sandbox);
assert(pathHtmlSingle.includes('10.129.105.90'), 'Single-target engagement cards stamped with 10.129.105.90');
assert(!pathHtmlSingle.includes('10.129.105.90 · DC'), 'Single-target move cards do not contain hostname DC');

console.log('\nAll multi-target infrastructure tests passed successfully!');



