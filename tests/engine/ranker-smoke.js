/* Node test for the goal-directed coach ranker (OBOL.pack.nextActionsV2).
 * Walks the canonical AD lab fact progression and asserts the #1 next-move at each step is the
 * evidenced next step — not a stale recon follow-up and not a speculative "try-if-vulnerable" move.
 * Locks in the v2 behaviour so a pack/weight change can't silently regress the coach. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, PK = OBOL.pack, F = OBOL.facts;

const pdir = path.join(__dirname, '..', '..', 'data', 'packs');
const packData = fs.readdirSync(pdir).filter((f) => f.endsWith('.json'))
  .map((f) => { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } });
const PACK = PK.loadPacks(packData);

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// Each step adds its facts with a strictly later timestamp, so the ranker's recency signal sees
// exactly the latest ingest batch (mirrors real per-paste timestamps).
const T0 = 1700000000000;
const steps = [
  ['recon → DC found', ['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick', 'ad.dc_candidate', 'ad.domain_known', 'ad.base_dn', 'ldap.reachable', 'smb.reachable', 'kerberos.reachable']],
  ['→ user list',      ['ad.user_list']],
  ['→ AS-REP hash',    ['hash.asrep', 'credential.candidate']],
  ['→ cracked creds',  ['credential.available']],
  ['→ BH graph/paths', ['ad.graph.collected', 'ad.attack_paths']],
  ['→ control paths',  ['ad.control_paths']],
  ['→ NTDS + krbtgt',  ['loot.ntds', 'hash.krbtgt']],
];

const cumulative = [];
function factSetAt(stepIdx) {
  const flist = [];
  for (let s = 0; s <= stepIdx; s++) {
    steps[s][1].forEach((kind) => flist.push(F.makeFact({ kind: kind, scope: { target: '10.10.10.5' }, source: 't', created_at: T0 + s * 10000 })));
  }
  return new F.FactSet(flist);
}
function top(stepIdx) { return PK.nextActionsV2(factSetAt(stepIdx), PACK, {}).map((a) => a.id); }

// The evidenced next move at each step — exact where there's one right answer, a small accept-set
// where two moves are genuinely co-equal (box-specific knowledge the planner can't have).
const SPECULATIVE = ['coerce-auth', 'zerologon-check', 'zerologon-exploit', 'lateral-exec', 'responder-poison', 'ntlm-relay-attack'];
const expect = [
  { any: ['ad-anon-ldap-enum', 'ad-user-enum'] },
  { any: ['password-spray', 'asrep-roast'] },
  { is: 'crack-asrep' },
  { any: ['ad-path-manual', 'bloodhound-collect', 'bloodyad-acl', 'kerberos-tickets'] }, // "work your new creds / analyze paths"
  { is: 'ad-acl-abuse' },
  { is: 'dcsync' },
  { is: 'own-domain-pth' },
];

steps.forEach((step, i) => {
  const order = top(i);
  const first = order[0];
  const e = expect[i];
  if (e.is) ok(first === e.is, step[0] + ' → #1 is ' + e.is + ' (got ' + first + ')');
  else ok(e.any.indexOf(first) >= 0, step[0] + ' → #1 ∈ {' + e.any.join(', ') + '} (got ' + first + ')');
  // Guardrails that held across the whole progression:
  ok(first !== 'nmap-version-scripts', step[0] + ' → stale recon is not #1');
  ok(SPECULATIVE.indexOf(first) < 0 || (e.any && e.any.indexOf(first) >= 0), step[0] + ' → a speculative move is not #1');
});

// Determinism: identical fact set ranks identically.
const a = PK.nextActionsV2(factSetAt(3), PACK, {}).map((x) => x.id);
const b = PK.nextActionsV2(factSetAt(3), PACK, {}).map((x) => x.id);
ok(JSON.stringify(a) === JSON.stringify(b), 'ranking is deterministic for a fixed fact set');

// The dispatcher honours the flag.
ok(typeof PK.rankActions === 'function' && PK.ranker === 'v2', 'rankActions dispatcher present, v2 is the default');

console.log(fail ? ('\nRANKER SMOKE: ' + fail + ' FAILURES') : '\nRANKER SMOKE: all passed');
process.exit(fail ? 1 : 0);
