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

// --- lanes + edges ---------------------------------------------------------------------------
ok(S.lanes().length === 5, 'five lanes exposed (recon, ad, web, linux, windows)');
const lane = S.lane('ad');
ok(lane.length === 7, 'AD lane has 7 nodes');
ok(lane[0].id === 'ad-dc-identify' && lane[lane.length - 1].id === 'dcsync', 'AD lane runs DC-identify → DCSync');
const edges = S.laneEdges('ad');
ok(edges.some((e) => e.from === 'ad-anon-ldap-enum' && e.to === 'asrep-roast'), 'edge derived: anon-LDAP → AS-REP (ad.user_list)');
ok(edges.some((e) => e.from === 'asrep-roast' && e.to === 'crack-asrep'), 'edge derived: AS-REP → crack (hash.asrep)');
ok(S.laneOf('sudo-abuse').key === 'linux' && S.laneOf('seimpersonate').key === 'windows', 'moves resolve to the right lane');

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

// --- every node in every lane generates a complete cell + practice + replay ------------------
let allCells = true, total = 0;
S.LANE_ORDER.forEach((k) => {
  S.lane(k).forEach((n) => {
    total++;
    const cc = S.cellFor(n.id), pp = S.practiceFor(n.id), rr = S.replayFor(n.id);
    if (!cc || !cc.commands.length || !cc.output || !cc.output.text || !pp || !pp.choices.length || !rr || !rr.command) { allCells = false; console.error('    weak node:', k, n.id); }
    if (cc && cc.commands.length) { const rk = cc.commands.map((c) => c.rank); if (!rk.every((v, i) => i === 0 || v >= rk[i - 1])) { allCells = false; console.error('    not remote-first:', n.id); } }
  });
});
ok(allCells, 'all ' + total + ' nodes across 5 lanes: complete cell + output + practice + replay, commands remote-first');

// --- the atlas (all lanes as one graph) ------------------------------------------------------
const at = S.atlas();
ok(at.nodes.length === 26, 'atlas has all 26 nodes');
ok(at.laneEdges.length === 21, 'atlas has 21 intra-lane edges (5 lanes)');
ok(at.crossEdges.length >= 5 && at.crossEdges.some((e) => e.from === 'recon-smb-anon' && e.to === 'asrep-roast'), 'atlas draws cross-lane bridges (SMB enum → AS-REP)');
ok(at.nodes.every((n) => typeof n.col === 'number' && typeof n.row === 'number'), 'every atlas node has a grid position');

// --- replay drops a command-echo first line --------------------------------------------------
const rs = S.replayFor('sudo-abuse');
ok(rs.command === 'sudo -l', 'replay primary command is sudo -l');
ok(!/^\s*\$?\s*sudo -l\s*$/.test(rs.outputLines[0] || ''), 'replay output does not re-echo the played command');

if (fail) { console.error('\nSTUDY SMOKE: ' + fail + ' failure(s)'); process.exit(1); }
console.log('\nSTUDY SMOKE: all passed');
