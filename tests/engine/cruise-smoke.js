/* Cruise engine (OBOL.cruise): the exam-legal batch planner behind the Cruise tab. Verifies the tier
 * classifier (safe enumeration vs active foothold/spray vs manual), that an exam batch is enumeration
 * only and a foothold-producer is the CHECKPOINT not a batched step, that lab batches further, that a
 * move requiring an earlier batched move's output DEFERS (the frontier cut), and that buildScript
 * emits the shebang + per-step markers + no {{token}} leaks. Pure, no store, no network. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
require('../../assets/engine/loot.js');
require('../../data/parser-signatures.js');
require('../../assets/engine/playbook.js');
require('../../assets/engine/cruise.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, PK = OBOL.pack, C = OBOL.cruise, F = OBOL.facts;

const pdir = path.join(__dirname, '..', '..', 'data', 'packs');
const packData = fs.readdirSync(pdir).filter((f) => f.endsWith('.json'))
  .map((f) => { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } });
const PACK = PK.loadPacks(packData);

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

function fsWith(facts) {
  const set = new F.FactSet();
  facts.forEach((f) => set.add(F.makeFact(f)));
  return set;
}
function byId(pack, id) { for (const a of pack) { if (a.id === id) return a; } return null; }

// ── tier classifier ──────────────────────────────────────────────────────────────────────────────
ok(C.tierOf({ autonomy: 'auto', phase: 'recon', produces: [] }) === 'safe', 'explicit autonomy:auto -> safe');
ok(C.tierOf({ autonomy: 'approve', produces: [] }) === 'active', 'explicit autonomy:approve -> active');
ok(C.tierOf({ autonomy: 'manual', produces: [] }) === 'manual', 'explicit autonomy:manual -> manual');
ok(C.tierOf({ id: 'x', phase: 'enum', produces: ['ad.user_list'] }) === 'safe', 'enum move, no foothold -> safe (derived)');
ok(C.tierOf({ id: 'smb-share-inventory', phase: 'loot', produces: ['loot.share'] }) === 'safe', 'a loot-phase enumeration read defaults safe (auto-batches)');
ok(C.tierOf({ id: 'x', phase: 'enum', produces: ['access.shell'] }) === 'active', 'a foothold producer is never safe');
ok(C.tierOf({ id: 'x', phase: 'creds', produces: ['foothold.linux'] }) === 'active', 'any access/foothold/session produce -> active, whatever the phase');
ok(C.tierOf({ id: 'online-brute-ssh', phase: 'creds', produces: [] }) === 'active', 'a brute/spray id -> active');
ok(C.tierOf({ id: 'eternalblue-exploit', phase: 'access', produces: ['vuln.ms17010'] }) === 'active', 'an exploit/RCE id -> active');
ok(C.allowsTier('exam', 'safe') && !C.allowsTier('exam', 'active'), 'exam allows only safe');
ok(C.allowsTier('lab', 'safe') && C.allowsTier('lab', 'active') && !C.allowsTier('lab', 'manual'), 'lab allows safe+active, not manual');

// ── exam batch is enumeration only; a foothold-producer becomes the checkpoint ─────────────────────
// A mid-recon AD box: ports open, a domain known. Lots of enum is eligible; a login/foothold is the stop.
const facts = fsWith([
  { kind: 'target.configured', scope: 'host:10.10.10.5', value: {} },
  { kind: 'scan.ports.open', scope: 'host:10.10.10.5', value: { ports: [53, 88, 139, 389, 445, 636, 5985] } },
  { kind: 'ad.domain_known', scope: 'host:10.10.10.5', value: { domain: 'htb.local' } },
  { kind: 'smb.reachable', scope: 'host:10.10.10.5', value: {} },
  { kind: 'ldap.reachable', scope: 'host:10.10.10.5', value: {} },
]);

const exam = C.plan(facts, PACK, { mode: 'exam' });
ok(exam.mode === 'exam', 'plan echoes exam mode');
ok(exam.batch.length > 0, 'exam batch is non-empty on a mid-recon AD box (' + exam.batch.length + ' steps)');
ok(exam.batch.every((b) => b.tier === 'safe'), 'every exam-batch step is tier safe');
const examProducesFoothold = exam.batch.some((b) => (b.action.produces || []).some((k) => /^access\.|^foothold\./.test(k)));
ok(!examProducesFoothold, 'no exam-batch step produces a foothold/shell');

// ── lab batches at least as much as exam (it also admits active-tier moves) ─────────────────────────
const lab = C.plan(facts, PACK, { mode: 'lab' });
ok(lab.batch.length >= exam.batch.length, 'lab batch >= exam batch (' + lab.batch.length + ' >= ' + exam.batch.length + ')');

// ── forward-looking unlocks: this batch surfaces the blocked move its output would unlock ───────────
// A tiny two-move pack: B is blocked (needs mini.y, not yet a fact); A is eligible and PRODUCES mini.y.
// A is in the batch now; B is not (it is still blocked), but it shows up as "this batch unlocks" via mini.y.
const miniRaw = [{
  name: 'mini', version: '1', actions: [
    { id: 'mini-a', title: 'Mini A', phase: 'enum', autonomy: 'auto', requires_all: ['seed.x'], produces: ['mini.y', 'mini.extra'], commands: [{ tool: 'echo', run: 'echo a {{target}}' }] },
    { id: 'mini-b', title: 'Mini B', phase: 'enum', autonomy: 'auto', requires_all: ['seed.x', 'mini.y'], produces: ['mini.z'], commands: [{ tool: 'echo', run: 'echo b {{target}}' }] },
  ],
}];
const MINI = PK.loadPacks(miniRaw);
// Seed only seed.x: A is eligible (and not settled, since mini.extra is unproven); B is blocked on mini.y.
const miniFacts = fsWith([
  { kind: 'target.configured', scope: 'host:10.0.0.1', value: {} },
  { kind: 'seed.x', scope: 'host:10.0.0.1', value: {} },
]);
const miniPlan = C.plan(miniFacts, MINI, { mode: 'exam' });
const inBatch = (id) => miniPlan.batch.some((b) => b.action.id === id);
const inUnlocks = (id) => miniPlan.unlocks.some((u) => u.action.id === id);
ok(inBatch('mini-a'), 'the eligible, safe move (mini-a) is batched');
ok(!inBatch('mini-b'), 'the still-blocked move (mini-b) is not in the batch');
ok(inUnlocks('mini-b'), 'the batch previews mini-b as a move it unlocks');
const u = miniPlan.unlocks.find((x) => x.action.id === 'mini-b');
ok(u && u.via === 'mini.y', 'the unlock preview records which produced fact (mini.y) unlocks it');

// ── buildScript: shebang, markers, var header, no token leaks ───────────────────────────────────────
const ctx = { pack: PACK, facts: facts, params: { target: '10.10.10.5', domain: 'htb.local' }, phase: exam.phase, mode: 'exam' };
const script = C.buildScript(exam.batch, ctx);
ok(/^#!\/usr\/bin\/env bash/.test(script), 'script starts with a bash shebang');
ok(/EXAM MODE: safe enumeration only/.test(script), 'exam script carries the exam-mode caveat');
ok(/===== OBOL STEP 1: /.test(script), 'script fences step 1 with a self-segmenting marker');
ok(/exec > >\(tee -a "\$LOG"\)/.test(script), 'script tees output to a log');
ok(/TARGET="10\.10\.10\.5"/.test(script), 'the TARGET variable is set from params');
ok(!/\{\{[a-z]/i.test(script), 'no {{token}} leaks survive into the exam script');

const labScript = C.buildScript(lab.batch, { pack: PACK, facts: facts, params: { target: '10.10.10.5' }, mode: 'lab', phase: lab.phase });
ok(/LAB MODE: .*NOT exam-legal/.test(labScript), 'lab script carries the NOT-exam-legal caveat');

if (fail) { console.error('\nCRUISE SMOKE: ' + fail + ' failed'); process.exit(1); }
console.log('\nCRUISE SMOKE: all passed');
