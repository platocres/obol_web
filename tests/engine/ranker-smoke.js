/* Node test for the goal-directed coach ranker (OBOL.pack.nextActionsV2).
 * Walks the canonical AD lab fact progression and asserts the #1 next-move at each step is the right one:
 * in the early game, finish recon (the thorough service scan) before enumerating ("orient before exploit");
 * once recon is done, the evidenced next step leads, never a speculative "try-if-vulnerable" move.
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
  ['port scan only',   ['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick']],
  ['recon done, DC found', ['scan.nmap.version', 'ad.dc_candidate', 'ad.domain_known', 'ad.base_dn', 'ldap.reachable', 'smb.reachable', 'kerberos.reachable']],
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
  { is: 'nmap-version-scripts' },   // orient before exploit: finish the thorough service scan first
  { any: ['ad-anon-ldap-enum', 'ad-user-enum'] },
  { is: 'asrep-roast' },   // deterministic no-cred path leads; blind password-spray is capped (speculative)
  { is: 'crack-asrep' },
  { any: ['ad-path-manual', 'bloodhound-collect', 'bloodyad-acl', 'kerberos-tickets'] }, // "work your new creds / analyze paths"
  { is: 'bloodyad-acl' },  // ACL abuse unlocks on the lead; the REMOTE twin wins over on-host ad-acl-abuse
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
  // Once recon is done (step 1 onward), the thorough service scan is settled and never buries the
  // evidenced next step. (At step 0 it is correctly #1 — orient before exploit — so it is exempt.)
  if (i >= 1) ok(first !== 'nmap-version-scripts', step[0] + ' → finished recon does not resurface as #1');
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
