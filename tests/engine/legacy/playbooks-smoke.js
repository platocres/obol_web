/* Node smoke for the ported playbooks layer (list/get/resolveSteps/applicable) against the
 * real packs + shipped playbook bundle. Mirrors planner-smoke.js loading. */
'use strict';

// Load the engine + generated bundles into Node's global (they attach to globalThis).
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../data/packs-bundle.js');
require('../../assets/engine/packs.js');
require('../../assets/engine/command.js');
require('../../data/playbooks-bundle.js');
require('../../assets/engine/playbooks.js');
const OBOL = globalThis.OBOL;
const F = OBOL.facts;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// --- list() returns the shipped playbooks --------------------------------------------------
const pbs = OBOL.playbooks.list();
console.log('Loaded ' + pbs.length + ' playbooks.');
ok(pbs.length === 5, 'list() returns the 5 shipped playbooks (got ' + pbs.length + ')');
const gotNames = pbs.map((p) => p.name).sort();
const want = ['ad-recon', 'domain-persistence', 'prepare-reverse-shell', 'tunnel-and-sweep', 'web-recon'];
ok(JSON.stringify(gotNames) === JSON.stringify(want), 'list() names = ' + want.join(', '));

// get() round-trips
ok(OBOL.playbooks.get('ad-recon') && OBOL.playbooks.get('ad-recon').title === 'AD Initial Recon', 'get(ad-recon) has its title');
ok(OBOL.playbooks.get('nope') === null, 'get(unknown) is null');

// --- resolveSteps(ad-recon) maps every step to a real pack action --------------------------
const ad = OBOL.playbooks.get('ad-recon');
const resolved = OBOL.playbooks.resolveSteps(ad);
ok(resolved.length === ad.steps.length && resolved.length === 5, 'resolveSteps(ad-recon) preserves all ' + ad.steps.length + ' steps');
ok(resolved.every((s) => s.action && s.action.id === s.action_id), 'every ad-recon step resolves to a real pack action');
console.log('  ad-recon steps:', resolved.map((s) => s.action_id).join(' -> '));
// step fields preserved (require_approval on the RID-enum step)
const ridStep = resolved.find((s) => s.action_id === 'ad-user-enum');
ok(ridStep && ridStep.require_approval === true, 'ad-user-enum step keeps require_approval=true');
ok(resolved.every((s) => typeof s.cmd === 'number' && typeof s.note === 'string'), 'steps keep cmd/note fields');

// every step of every shipped playbook resolves (drift guard)
let drift = [];
pbs.forEach((pb) => OBOL.playbooks.resolveSteps(pb).forEach((s) => { if (!s.action) drift.push(pb.name + ':' + s.action_id); }));
ok(drift.length === 0, 'no action-id drift across all playbooks' + (drift.length ? ' (missing: ' + drift.join(', ') + ')' : ''));

// --- applicable() surfaces ad-recon once its first step's prereqs are proven ---------------
function fs1(kinds) {
  const set = new OBOL.facts.FactSet([]);
  kinds.forEach((k) => set.add(F.makeFact({ kind: k, scope: 'host:10.10.10.10', state: F.ProofState.SUPPORTED })));
  return set;
}

// The first resolvable step of ad-recon is nmap-fast-open-ports — find its prereqs and seed them.
const firstAction = resolved[0].action;
console.log('  ad-recon first action:', firstAction.id, 'requires_all=', JSON.stringify(firstAction.requires_all), 'requires_any=', JSON.stringify(firstAction.requires_any));
const seed = ['target.configured'].concat(firstAction.requires_all, firstAction.requires_any);
const eligibleFacts = fs1(seed);
ok(firstAction.eligible(eligibleFacts), 'first ad-recon action is eligible on the seeded factset');
const app = OBOL.playbooks.applicable(eligibleFacts);
console.log('  applicable now:', app.map((p) => p.name).join(', ') || '(none)');
ok(app.some((p) => p.name === 'ad-recon'), 'applicable() surfaces ad-recon when its first step is eligible');

// An empty factset should NOT surface a playbook whose first step needs prereqs beyond nothing.
const emptyApp = OBOL.playbooks.applicable(new OBOL.facts.FactSet([]));
ok(!emptyApp.some((p) => p.name === 'web-recon'), 'web-recon not applicable on an empty factset (needs an HTTP port)');

console.log(fail ? ('\nPLAYBOOKS SMOKE: ' + fail + ' FAILURES') : '\nPLAYBOOKS SMOKE: all passed');
process.exit(fail ? 1 : 0);
