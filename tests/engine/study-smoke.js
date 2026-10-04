/* Node test for Study mode's engine half (OBOL.study — the AD vertical slice, milestone 1).
 * Locks the derived conditional cell, the remote-first command ordering, the lane graph edges, and
 * the retrieval-practice verdicts, so a pack/ARSENAL/fixture change can't silently regress study. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, PK = OBOL.pack;

const pdir = path.join(__dirname, '..', '..', 'data', 'packs');
const packData = fs.readdirSync(pdir).filter((f) => f.endsWith('.json'))
  .map((f) => { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } });
const A = PK.loadPacks(packData);
OBOL.packs = { actions: () => A };
globalThis.globalThis = globalThis;
require('../../data/tools-install.js');     // OBOL.ARSENAL
require('../../data/study-fixtures.js');     // OBOL.STUDY_FIXTURES
require('../../assets/engine/study.js');     // OBOL.study
const S = OBOL.study;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// --- lane + edges ----------------------------------------------------------------------------
const lane = S.lane();
ok(lane.length === 7, 'AD lane has 7 nodes');
ok(lane[0].id === 'ad-dc-identify' && lane[lane.length - 1].id === 'dcsync', 'lane runs DC-identify → DCSync');
const edges = S.laneEdges();
ok(edges.some((e) => e.from === 'ad-anon-ldap-enum' && e.to === 'asrep-roast'), 'edge derived: anon-LDAP → AS-REP (ad.user_list)');
ok(edges.some((e) => e.from === 'asrep-roast' && e.to === 'crack-asrep'), 'edge derived: AS-REP → crack (hash.asrep)');

// --- cell generation (asrep-roast, the hero) -------------------------------------------------
const c = S.cellFor('asrep-roast');
ok(c && c.whatItIs && c.whatItIs.length > 20, 'cell.whatItIs comes from move.hypothesis');
ok(c.prereqFacts.indexOf('ad.user_list') >= 0, 'cell prereqs include ad.user_list');
ok(c.producedBy.some((p) => /LDAP/i.test(p.title)), 'cell.producedBy names the upstream LDAP enum move');
ok(c.commands.length >= 3, 'cell has multiple command variants');
ok(c.output && c.output.signal === '$krb5asrep$23$', 'cell.output + signal come from STUDY_FIXTURES');
ok(c.proves.indexOf('hash.asrep') >= 0, 'cell.proves includes hash.asrep (from produces)');
ok(c.opens.some((o) => o.id === 'crack-asrep'), 'cell.opens includes Crack AS-REP (graph edge)');
ok(c.rulesOut && /candidate/i.test(c.rulesOut), 'cell.rulesOut comes from does_not_prove');

// --- remote-first command ordering -----------------------------------------------------------
const ranks = c.commands.map((x) => x.rank);
ok(ranks.every((v, i) => i === 0 || v >= ranks[i - 1]), 'commands are ordered remote-first (non-decreasing rank)');
ok(c.commands[0].locus === 'REMOTE', 'first command is REMOTE');
const rubeus = c.commands.filter((x) => x.tool === 'Rubeus')[0];
ok(rubeus && rubeus.locus === 'ON-TARGET', 'Rubeus (Windows stage-bin) classed ON-TARGET');
ok(S.cmdLocus({ tool: 'hashcat', run: 'hashcat -m 18200 x y' }).label === 'OFFLINE', 'hashcat classed OFFLINE');
ok(S.cmdLocus({ tool: 'nxc', run: "nxc ldap x -u y -p ''" }).label === 'REMOTE', 'nxc classed REMOTE');

// --- practice verdicts (derived from real requires) ------------------------------------------
const p = S.practiceFor('asrep-roast');
const v = {}; p.choices.forEach((ch) => { v[ch.id] = ch.verdict; });
ok(v['asrep-roast'] === 'correct', 'practice: AS-REP is the correct answer');
ok(v['password-spray'] === 'alt', 'practice: Password Spray reads as also-valid (shares the user list)');
ok(v['kerberoast'] === 'locked', 'practice: Kerberoasting is locked (needs credentials)');
ok(v['dcsync'] === 'locked', 'practice: DCSync is locked (needs Domain Admin)');

// --- every lane node generates a usable cell + practice --------------------------------------
let allCells = true;
S.AD_LANE.forEach((e) => {
  const cc = S.cellFor(e.id), pp = S.practiceFor(e.id);
  if (!cc || !cc.commands.length || !cc.output || !pp || !pp.choices.length) { allCells = false; console.error('    weak node:', e.id); }
});
ok(allCells, 'all 7 AD lane nodes produce a complete cell + practice');

if (fail) { console.error('\nSTUDY SMOKE: ' + fail + ' failure(s)'); process.exit(1); }
console.log('\nSTUDY SMOKE: all passed');
