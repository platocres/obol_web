/* Endgame relevance: once the domain is owned (loot.ntds) and we hold admin, the coach must lead with the
 * objective (capture the flags), NOT with side-quests whose avenue is now closed — SCCM enumeration and
 * local privilege-escalation sweeps. Those stay AVAILABLE (cross-box loot in a larger lab) but must be
 * demoted below the flag hunt. Generic data; regression for the "sccm surfaced as the next command" bug. */
'use strict';
const fs = require('fs');
const path = require('path');
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/command.js');
const OBOL = globalThis.OBOL;

const PACKS_DIR = path.join(__dirname, '..', '..', 'data', 'packs');
const pack = OBOL.pack.loadPacks(OBOL.pack.PACK_NAMES.map((n) =>
  JSON.parse(fs.readFileSync(path.join(PACKS_DIR, n + '.json'), 'utf8'))));

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
const F = OBOL.facts;

// A fully domain-owned Windows DC as a realistic IMPORT leaves it: recon already ran (scan.nmap.quick, so
// the opening nmap has SETTLED and dropped), creds in hand, NTDS dumped, admin + WinRM proven. This mirrors
// what the operator sees after pasting a run.txt that reached Domain Admin.
const set = new OBOL.facts.FactSet([]);
['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick', 'port:445', 'port:389', 'port:88',
 'os.windows', 'foothold.windows', 'credential.available', 'winrm.authenticated',
 'access.admin', 'loot.ntds'].forEach((k) =>
  set.add(F.makeFact({ kind: k, scope: 'host:10.0.0.5', state: F.ProofState.SUPPORTED })));

const ranked = OBOL.pack.nextActions(set, pack);
const ids = ranked.map((a) => a.id);
function rank(id) { const i = ids.indexOf(id); return i < 0 ? Infinity : i; }
console.log('  top 6:', ids.slice(0, 6).join(', '));

// The flag hunt must LEAD after import — it is the objective, and it surfaces at the very top of Ready now,
// not buried under recon or side-quests. (This is the "make the flag commands surface at the top" contract.)
ok(rank('flag-hunt-windows') === 0, 'the Windows flag hunt is the #1 Ready-now move after a domain-compromise import (id[0]=' + ids[0] + ')');
ok(rank('flag-hunt-windows') < rank('sccm-enum'), 'flag hunt outranks SCCM enumeration after loot.ntds');
ok(rank('flag-hunt-windows') < rank('windows-enum'), 'flag hunt outranks the local privesc sweep once admin');
ok(rank('flag-hunt-windows') < rank('seimpersonate'), 'flag hunt outranks SeImpersonate once admin');

// SCCM and local privesc stay AVAILABLE (cross-box loot / larger labs) — just not the next move.
ok(rank('sccm-enum') < Infinity, 'SCCM stays available (not retired) for cross-box loot in larger labs');

console.log(fail ? ('\nENDGAME RELEVANCE: ' + fail + ' FAILURES') : '\nENDGAME RELEVANCE: all passed');
process.exit(fail ? 1 : 0);
