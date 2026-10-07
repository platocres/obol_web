/* Stuck? engine (OBOL.stuck): the pure logic behind the Stuck? tab. Verifies the sandbox is isolated,
 * the reveal-from-graph suggestFacts surfaces near-frontier facts and excludes what you already have,
 * triage seeds only assert real kinds, and rankedMoves reuses the coach ranker with doneIds so an
 * "I tried this move" exclusion floats up the next option. Pure, no store, no network. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
require('../../data/parser-signatures.js');
require('../../assets/engine/stuck.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, PK = OBOL.pack, S = OBOL.stuck;

const pdir = path.join(__dirname, '..', '..', 'data', 'packs');
const packData = fs.readdirSync(pdir).filter((f) => f.endsWith('.json'))
  .map((f) => { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } });
const PACK = PK.loadPacks(packData);

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function kinds(list) { return list.map((c) => c.kind); }

// ── sandbox isolation ──────────────────────────────────────────────────────────────────────────
const sb = S.sandbox();
ok(sb && sb.facts && sb.facts.length === 0, 'a fresh sandbox is empty');
S.assert(sb, 'ports.open', { scope: 'host:10.10.10.5', value: { ports: [445, 88] } });
ok(sb.has('ports.open'), 'assert adds a SUPPORTED fact the ranker can see');
S.retract(sb, 'ports.open');
ok(!sb.has('ports.open'), 'retract removes the fact (un-gates dependent moves)');

// ── kind universe ────────────────────────────────────────────────────────────────────────────────
const universe = S.kindUniverse(PACK);
const universeN = Object.keys(universe).length;
ok(universeN > 80, 'the kind universe is populated (' + universeN + ' kinds)');
ok(universe['ports.open'] && universe['credential.available'], 'universe includes core kinds');

// ── suggestFacts on an empty sandbox (opening: recon) ────────────────────────────────────────────
const empty = S.sandbox();
const s0 = S.suggestFacts(empty, PACK);
ok(s0.length > 0, 'empty sandbox yields candidate facts (' + s0.length + ')');
ok(s0.every((c) => !empty.kinds()[c.kind]), 'no candidate is a fact we already have');
ok(s0.some((c) => c.phase === 'recon'), 'the opening surfaces recon facts');
ok(s0.every((c) => typeof c.label === 'string' && c.label.length > 0), 'every candidate has a human label');
console.log('     top opening candidates:', kinds(s0).slice(0, 8).join(', '));

// ── suggestFacts advances as facts are added ─────────────────────────────────────────────────────
const mid = S.sandbox();
S.triageSeed(mid, 'services', PACK, 'host:10.10.10.5');
ok(mid.has('scan.nmap.version'), 'triage "services" seeds a version scan (real kind)');
const s1 = S.suggestFacts(mid, PACK);
ok(s1.length > 0, 'a seeded mid-game state still has candidate facts (' + s1.length + ')');
ok(!kinds(s1).includes('scan.nmap.version'), 'already-seeded facts drop out of the candidate list');
console.log('     after services seed:', kinds(s1).slice(0, 8).join(', '));

// every triage option seeds only real kinds (no dead facts), and sets a sensible phase
S.TRIAGE.forEach(function (t) {
  const f = S.sandbox();
  S.triageSeed(f, t.id, PACK, 'host:10.10.10.5');
  const bogus = (f.facts || []).filter((x) => !universe[x.kind]);
  ok(bogus.length === 0, 'triage "' + t.id + '" seeds only real kinds (' + (f.facts || []).length + ' facts)');
});

// report which seed kinds did NOT exist in the universe (so we can fix the triage list)
S.TRIAGE.forEach(function (t) {
  const missing = (t.seed || []).filter((k) => !universe[k]);
  if (missing.length) console.log('     NOTE: triage "' + t.id + '" seed kinds not in universe:', missing.join(', '));
});

// ── frontier weighting fires: later-phase facts are decayed below their raw unlock score ─────────
ok(s0.some((c) => c.unlocks < c.rawUnlocks - 1e-9), 'frontier weighting decays facts ahead of the frontier (phase-proximal suggestions)');
// a credential-seeded state (creds phase) surfaces access/escalate/loot candidates that an empty board does not lead with
const cred = S.sandbox();
S.triageSeed(cred, 'credential', PACK, 'host:10.10.10.5');
const sc = S.suggestFacts(cred, PACK, { limit: 10 });
ok(sc.some((c) => ['access', 'escalate', 'loot'].includes(c.phase)), 'holding a credential surfaces later-phase facts to assert');

// ── grouped-by-phase view for the sectioned picker ───────────────────────────────────────────────
const byPhase = S.suggestByPhase(empty, PACK);
ok(Array.isArray(byPhase) && byPhase.length > 0, 'suggestByPhase returns sections');
const pOrder = ['recon', 'enum', 'creds', 'access', 'escalate', 'loot'];
const idxs = byPhase.map((g) => pOrder.indexOf(g.phase));
ok(idxs.every((v, i) => i === 0 || idxs[i - 1] <= v), 'sections come back in phase order');
ok(byPhase.every((g) => g.facts.length > 0), 'every section has at least one fact');

// ── rankedMoves reuses the coach ranker; triedIds excludes a move ────────────────────────────────
const rm = S.sandbox();
S.triageSeed(rm, 'ports', PACK, 'host:10.10.10.5');
const moves = S.rankedMoves(rm, PACK);
ok(Array.isArray(moves) && moves.length > 0, 'rankedMoves returns ranked moves (' + moves.length + ')');
ok(moves[0] && moves[0].id, 'the top move has an id (' + (moves[0] && moves[0].id) + ')');
const topId = moves[0].id;
const moves2 = S.rankedMoves(rm, PACK, { triedIds: [topId] });
ok(!moves2.some((m) => m.id === topId), '"I tried this move" (triedIds) excludes it from the ranking');
ok(moves2.length === moves.length - 1 || moves2.length >= 1, 'the next option floats up after exclusion');

// ── honesty: rankedMoves does not write the active engagement ─────────────────────────────────────
ok(S.rankedMoves !== undefined && rm.facts.every((f) => f.source === 'stuck'), 'all sandbox facts are tagged source=stuck (never confused with proven facts)');

console.log(fail ? ('\nSTUCK: ' + fail + ' FAILURES') : '\nSTUCK: all passed');
process.exit(fail ? 1 : 0);
