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
// Build the pack bundle keyed by file basename (e.g. 'cracking_2026_09'), exactly how data/packs-bundle.js
// keys OBOL.packData in the browser — study.js strips the _YYYY_MM suffix off each key to find the lane.
const bundle = {};
fs.readdirSync(pdir).filter((f) => f.endsWith('.json')).forEach((f) => {
  try { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) {}
});
const A = PK.loadPacks(Object.keys(bundle).map((k) => bundle[k]));
OBOL.packs = { actions: () => A, packData: () => bundle };
globalThis.globalThis = globalThis;
require('../../data/tools-install.js');          // OBOL.ARSENAL
require('../../data/study-fixtures.js');         // OBOL.STUDY_FIXTURES (hand-written, coherence-vetted)
require('../../assets/engine/study.js');         // OBOL.study
const S = OBOL.study;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// --- lanes + edges ---------------------------------------------------------------------------
ok(S.lanes().length === 11, 'eleven taxonomy lanes exposed (every pack lands in one)');
ok(S.LANE_KEYS.length === 11 && S.LANE_KEYS[0] === 'recon' && S.LANE_KEYS.indexOf('proof') === 10, 'lane order runs recon → … → proof');
const lane = S.lane('ad');
ok(lane.length === 48, 'AD lane carries all 48 AD-pack moves');
ok(lane[0].id === 'ad-dc-identify', 'AD lane opens on DC-identify');
const edges = S.laneEdges('ad');
ok(edges.some((e) => e.from === 'ad-anon-ldap-enum' && e.to === 'asrep-roast'), 'edge derived: anon-LDAP → AS-REP (ad.user_list)');
ok(edges.some((e) => e.from === 'asrep-roast' && e.to === 'crack-asrep'), 'edge derived: AS-REP → crack (hash.asrep)');
ok(S.laneEntry('sudo-abuse').laneKey === 'linux' && S.laneEntry('seimpersonate').laneKey === 'windows', 'moves resolve to the right lane');
ok(S.laneEntry('nmap-fast-open-ports').laneKey === 'recon', 'nmap scans re-homed to the Recon lane (they ship in the AD pack)');

// --- cell generation (asrep-roast, the hero) -------------------------------------------------
const c = S.cellFor('asrep-roast');
ok(c && c.whatItIs && c.whatItIs.length > 20, 'cell.whatItIs comes from move.hypothesis');
ok(c.prereqFacts.indexOf('ad.user_list') >= 0, 'cell prereqs include ad.user_list');
ok(c.producedBy.some((p) => /LDAP/i.test(p.title)), 'cell.producedBy names the upstream LDAP enum move');
ok(c.commands.length >= 3, 'cell has multiple command variants');
ok(c.output && c.output.signal.indexOf('$krb5asrep$23$') === 0, 'cell.output + signal come from STUDY_FIXTURES');
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
// (the sample OUTPUT is the one non-derivable field — a move with no fixture still makes a full
//  cell, so output is counted, not required.)
let allCells = true, total = 0, withOutput = 0;
S.LANE_KEYS.forEach((k) => {
  S.lane(k).forEach((n) => {
    total++;
    const cc = S.cellFor(n.id), pp = S.practiceFor(n.id), rr = S.replayFor(n.id);
    if (!cc || !cc.commands.length || !pp || !pp.choices.length || !rr || !rr.command) { allCells = false; console.error('    weak node:', k, n.id); }
    if (cc && cc.output && cc.output.text) withOutput++;
    if (cc && cc.commands.length) { const rk = cc.commands.map((c) => c.rank); if (!rk.every((v, i) => i === 0 || v >= rk[i - 1])) { allCells = false; console.error('    not remote-first:', n.id); } }
  });
});
ok(total === 167, 'all 167 pack moves are navigable as lane nodes');
ok(allCells, 'every one of ' + total + ' nodes: complete cell + commands + practice + replay, commands remote-first');
ok(withOutput >= 40, withOutput + ' nodes carry a sample output (hand + auto-bootstrapped fixtures)');

// --- the atlas (all lanes as one graph) ------------------------------------------------------
const at = S.atlas();
ok(at.nodes.length === 167, 'atlas has all 167 nodes');
ok(at.laneEdges.length === 167 - at.lanes.length, 'atlas intra-lane edges = nodes − lanes (one chain per lane)');
ok(at.crossEdges.length >= 5 && at.crossEdges.some((e) => e.from === 'recon-smb-anon' && e.to === 'asrep-roast'), 'atlas draws cross-lane bridges (SMB enum → AS-REP)');
ok(at.nodes.every((n) => typeof n.col === 'number' && typeof n.row === 'number'), 'every atlas node has a grid position');
ok(at.lanes.length === 11 && at.laneOrder.length === 11, 'atlas carries all eleven lanes');

// --- fixed scenarios -------------------------------------------------------------------------
const scn = S.scenarios();
ok(scn.length >= 4, 'at least four fixed scenarios are defined');
ok(scn.every((s) => s.steps.every((id) => !!S.cellFor(id))), 'every scenario step maps to a real study node');
ok(scn.some((s) => s.key === 'web-linux' && s.steps[0] === 'recon-web-triage'), 'the Web → Linux scenario starts at web triage');

// --- replay drops a command-echo first line --------------------------------------------------
const rs = S.replayFor('sudo-abuse');
ok(rs.command === 'sudo -l', 'replay primary command is sudo -l');
ok(!/^\s*\$?\s*sudo -l\s*$/.test(rs.outputLines[0] || ''), 'replay output does not re-echo the played command');
ok(typeof rs.hasOutput === 'boolean', 'replay reports hasOutput for graceful no-sample rendering');

// --- command ↔ output COHERENCE (the contract: the replay types the command that made the sample) ---
// Every fixture must pin the command its output came from, the signal must really be in the output,
// and the output must be pure tool result — never a re-typed `$ command` echo that fights the command
// the replay types above it. This is what stops a move from showing one tool's command over another
// tool's output (e.g. an `nxc ldap` command over an nmap port-scan).
const FX = OBOL.STUDY_FIXTURES || {};
const echoLine = (ln) => /^\s*\$\s+\S/.test(ln) || /^\s*kali\$\s/.test(ln) || /^\s*target\$\s/.test(ln);
let incoherent = 0;
Object.keys(FX).forEach((id) => {
  const f = FX[id];
  const move = S.cellFor(id);
  if (!move) { console.error('    fixture for unknown move:', id); incoherent++; return; }
  if (f.steps) {
    // multi-step fixture: each step pins a command + output, carries a valid locus, and no echo lines
    if (!Array.isArray(f.steps) || f.steps.length < 2) { console.error('    steps fixture needs >=2 steps:', id); incoherent++; }
    let all = '';
    (f.steps || []).forEach((s, i) => {
      if (!s.cmd || !s.cmd.trim()) { console.error('    step ' + i + ' missing cmd:', id); incoherent++; }
      if (s.where !== 'local' && s.where !== 'host') { console.error('    step ' + i + ' bad where:', id); incoherent++; }
      const so = String(s.output || '');
      if (so.split('\n').some(echoLine)) { console.error('    step ' + i + ' re-types a command:', id); incoherent++; }
      all += so + '\n';
    });
    if (!f.signal || all.indexOf(f.signal) < 0) { console.error('    signal not in any step output:', id); incoherent++; }
    const rp = S.replayFor(id);
    if (rp && (!rp.multi || rp.steps.length !== f.steps.length)) { console.error('    replay did not expand steps:', id); incoherent++; }
    return;
  }
  if (!f.cmd || typeof f.cmd !== 'string' || !f.cmd.trim()) { console.error('    fixture missing pinned cmd:', id); incoherent++; }
  if (!f.output || !f.signal) { console.error('    fixture missing output/signal:', id); incoherent++; return; }
  if (f.output.indexOf(f.signal) < 0) { console.error('    signal not in output:', id); incoherent++; }
  // no embedded bash-command echo lines (they duplicate / contradict the one typed command)
  const bad = f.output.split('\n').filter(echoLine);
  if (bad.length) { console.error('    output re-types a command (' + id + '):', JSON.stringify(bad[0])); incoherent++; }
  // the replay must surface the pinned command, not the pack default
  const rp = S.replayFor(id);
  if (rp && rp.command !== f.cmd) { console.error('    replay command != pinned cmd:', id); incoherent++; }
});
ok(incoherent === 0, 'all ' + Object.keys(FX).length + ' fixtures: coherent command↔output (pinned cmd, signal present, no re-typed echoes, multi-step locus-labelled)');

// --- path validation (locked-door detection across a drawn path) -----------------------------
const good = S.validatePath(['ad-anon-ldap-enum', 'asrep-roast', 'crack-asrep']);
ok(good.ok, 'a path that mints each step\'s prereqs validates clean');
const bad = S.validatePath(['asrep-roast', 'crack-asrep']);
ok(!bad.ok && bad.issues[0].idx === 0 && bad.issues[0].missing.indexOf('ad.user_list') >= 0, 'a path that opens on AS-REP flags the missing user list (locked door)');
ok(S.validatePath(['nmap-fast-open-ports']).ok, 'an opening recon move needs only environment facts (not flagged)');

// --- mastery (per-browser progress) ----------------------------------------------------------
const mem = {}; globalThis.localStorage = { getItem: (k) => (k in mem ? mem[k] : null), setItem: (k, v) => { mem[k] = String(v); }, removeItem: (k) => { delete mem[k]; } };
S.markStudied('asrep-roast', 'studied');
S.markStudied('crack-asrep', 'correct');
const M = S.mastery();
ok(M['asrep-roast'] && M['asrep-roast'].studied && !M['asrep-roast'].correct, 'markStudied records a watched step');
ok(M['crack-asrep'] && M['crack-asrep'].correct && M['crack-asrep'].studied, 'a correct answer records both studied + correct');
const lp = S.laneProgress('ad');
ok(lp.total === 48 && lp.studied >= 2 && lp.correct >= 1, 'laneProgress counts studied/correct within a lane');

if (fail) { console.error('\nSTUDY SMOKE: ' + fail + ' failure(s)'); process.exit(1); }
console.log('\nSTUDY SMOKE: all passed');
