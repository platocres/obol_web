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
require('../../data/stuck-catalog.js');
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

// ── catalog wiring ───────────────────────────────────────────────────────────────────────────────
ok(OBOL.STUCK_CATALOG && Object.keys(OBOL.STUCK_CATALOG).length > 0, 'the stuck catalog is loaded (' + Object.keys(OBOL.STUCK_CATALOG || {}).length + ' kinds)');
ok(S.isAskable('web.sqli_confirmed') && !S.isAskable('blocker.foo'), 'isAskable gates on catalog membership');
ok(S.labelFor('http.reachable') === 'A Website Is Up', 'labelFor prefers the catalog label over friendly()');
ok(S.groupFor('smb.reachable') === 'Recon' && S.groupFor('web.server') === 'Web', 'groupFor returns the lane');
// every cataloged kind is a real kind the engine knows about (no typos that would never surface)
Object.keys(OBOL.STUCK_CATALOG).forEach(function (k) {
  ok(universe[k], 'catalog kind "' + k + '" exists in the pack/parser universe');
});
// the reveal, gated by the catalog, only ever surfaces cataloged kinds
const gated = S.suggestFacts(S.sandbox(), PACK, { askable: S.isAskable });
ok(gated.every((c) => S.isAskable(c.kind)), 'catalog-gated reveal surfaces only user-assertable kinds');

// ── port palette + lane gating ───────────────────────────────────────────────────────────────────
ok(OBOL.STUCK_PORTS && OBOL.STUCK_PORTS.length >= 30, 'port palette is populated (' + (OBOL.STUCK_PORTS || []).length + ')');
// every NON-port palette fact (the reachable/service kinds) must be real so a pick gates moves;
// a bare port:N is always a valid record even if no move keys on that exact port.
var paletteBad = [];
OBOL.STUCK_PORTS.forEach(function (p) { (p.facts || []).forEach(function (k) { if (k.indexOf('port:') !== 0 && !universe[k]) paletteBad.push(p.port + ':' + k); }); });
ok(paletteBad.length === 0, 'every service/reachable palette fact is a real pack/parser kind' + (paletteBad.length ? ' (bad: ' + paletteBad.join(', ') + ')' : ''));
ok(OBOL.STUCK_PORTS.every(function (p) { return (p.facts || []).length > 0; }), 'every port asserts at least one fact');

var pf = S.sandbox();
ok(!S.portOn(pf, 445), 'port 445 starts off');
S.togglePort(pf, 445, 'host:1.2.3.4');
ok(S.portOn(pf, 445) && pf.has('smb.reachable') && pf.has('port:445'), 'toggling 445 asserts smb.reachable + port:445');
S.togglePort(pf, 445, 'host:1.2.3.4');
ok(!S.portOn(pf, 445) && !pf.has('smb.reachable'), 'toggling 445 again clears it');
S.addPortNumber(pf, 50000, 'host:1.2.3.4');
ok(pf.has('port:50000'), 'a free-typed exotic port asserts port:N');

// palette kinds are excluded from the findings refiner
ok(S.isPaletteKind('smb.reachable') && !S.isFinding('smb.reachable'), 'service-presence kinds are palette-owned, not refiner findings');
ok(S.isFinding('web.sqli_confirmed'), 'a real finding is still a refiner finding');

// lane gating: Web hidden until a web port; always-on lanes always on
var lg = S.sandbox();
ok(S.laneActive('Credentials', lg) && S.laneActive('Recon', lg), 'depth/recon lanes are always active');
ok(!S.laneActive('Web', lg), 'Web lane is hidden with no web port');
S.togglePort(lg, 80, 'host:1');
ok(S.laneActive('Web', lg), 'picking 80 activates the Web lane');
ok(!S.laneActive('Windows And AD', lg), 'AD lane still hidden without an AD port');
S.togglePort(lg, 445, 'host:1');
ok(S.laneActive('Windows And AD', lg), 'picking 445 activates the Windows And AD lane');
ok(!S.laneActive('Linux Privesc', lg), 'privesc lane hidden without a foothold');
S.assert(lg, 'foothold.linux', { scope: 'host:1' });
ok(S.laneActive('Linux Privesc', lg), 'a Linux foothold activates Linux Privesc');

console.log(fail ? ('\nSTUCK: ' + fail + ' FAILURES') : '\nSTUCK: all passed');
process.exit(fail ? 1 : 0);
