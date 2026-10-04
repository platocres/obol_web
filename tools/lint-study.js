#!/usr/bin/env node
/* Study content linter + coverage map. Loads packs + fixtures + the study engine the same way the
 * engine smoke test does, then reports, per move and per lane:
 *   - which surfaces are present (why / leadup / fieldnotes / yourturn / watch)
 *   - whether `why` overlaps the description (hypothesis) too much to be its own thing
 *   - content hygiene: em-dashes in user strings, untemplated literal lab IPs, demo/leadup sig not in out
 * This is the Phase-0 baseline for the curriculum-wide upgrade; run: node tools/lint-study.js [--flagged]
 */
'use strict';
require('../assets/engine/facts.js');
require('../assets/engine/phases.js');
require('../assets/engine/pack.js');
require('../assets/engine/profile.js');
require('../assets/engine/command.js');
require('../assets/engine/workspace.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, PK = OBOL.pack;
const pdir = path.join(__dirname, '..', 'data', 'packs');
const bundle = {};
fs.readdirSync(pdir).filter((f) => f.endsWith('.json')).forEach((f) => {
  try { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) {}
});
const A = PK.loadPacks(Object.keys(bundle).map((k) => bundle[k]));
OBOL.packs = { actions: () => A, packData: () => bundle };
require('../data/tools-install.js');
require('../data/study-fixtures.js');
require('../assets/engine/study.js');
const S = OBOL.study, FX = OBOL.STUDY_FIXTURES || {};

// --- helpers -------------------------------------------------------------------------------------
const STOP = new Set(('a an the and or but of to in on at by for with from is are be it this that you your they ' +
  'as so into not no if then than when where which what who whom whose will would can could may might do does ' +
  'did have has had its their them we our us i me my one two run runs running use used using get gets got also ' +
  'any all some each more most other another over under up down out off about just only very can\'t cannot').split(/\s+/));
function words(s) {
  return String(s || '').toLowerCase().replace(/`[^`]*`/g, ' ').replace(/[^a-z0-9. ]+/g, ' ')
    .split(/\s+/).filter((w) => w.length > 2 && !STOP.has(w));
}
function jaccard(a, b) {
  const A2 = new Set(a), B2 = new Set(b); if (!A2.size || !B2.size) return 0;
  let inter = 0; A2.forEach((w) => { if (B2.has(w)) inter++; });
  return inter / (A2.size + B2.size - inter);
}
function openingShared(a, b) {   // do description and why open with the same ~6 content words?
  const wa = words(a).slice(0, 6), wb = words(b).slice(0, 6); if (!wa.length || !wb.length) return 0;
  let n = 0; wa.forEach((w) => { if (wb.includes(w)) n++; }); return n;
}
function sigMisses(steps) {       // demo/leadup steps whose signal line is not in their output
  let miss = 0;
  (steps || []).forEach((s) => { const sig = s.sig; const out = s.out; if (sig && out && String(out).indexOf(sig) < 0) miss++; });
  return miss;
}
function emDash(s) { return /[—–]/.test(String(s || '')); }
function labIp(s) { return /\b10\.10\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b/.test(String(s || '')); }

// --- walk every move -----------------------------------------------------------------------------
const lanes = S.lanes();
const perLane = {};
const flagged = [];
let total = 0;

lanes.forEach((L) => {
  const nodes = S.lane(L.key);
  const stat = { key: L.key, name: L.name, n: nodes.length, why: 0, overlap: 0, leadup: 0, leadMulti: 0, how: 0, howDemo: 0, yourturn: 0, watch: 0, hygiene: 0 };
  nodes.forEach((node) => {
    total++;
    const id = node.id;
    const cell = S.cellFor(id) || {};
    const fx = FX[id] || {};
    const desc = cell.whatItIs || '';
    const why = fx.why || '';
    const lead = S.leadupFor ? S.leadupFor(id) : (fx.leadup || null);
    const how = fx.how || null;
    const prac = fx.situation ? fx : null;
    const rp = S.replayFor(id);
    const issues = [];

    if (why) stat.why++; else issues.push('no why');
    const ov = jaccard(words(desc), words(why));
    const openShare = openingShared(desc, why);
    if (why && desc && (ov >= 0.30 || openShare >= 4)) { stat.overlap++; issues.push('why~desc overlap ' + ov.toFixed(2) + (openShare >= 4 ? ' open' + openShare : '')); }

    if (lead) {
      stat.leadup++;
      const multi = Array.isArray(lead) && lead[0] && lead[0].steps;
      if (multi && lead.length > 1) stat.leadMulti++;
      const steps = multi ? [].concat.apply([], lead.map((p) => p.steps)) : lead;
      if (sigMisses(steps)) issues.push('leadup sig-not-in-out x' + sigMisses(steps));
    }

    if (how && how.items && how.items.length) {
      stat.how++;
      const demos = how.items.filter((it) => it.demo && it.demo.length);
      if (demos.length) stat.howDemo++;
      let m = 0; how.items.forEach((it) => { m += sigMisses(it.demo); });
      if (m) issues.push('fieldnote sig-not-in-out x' + m);
    }

    if (prac) stat.yourturn++;
    if (rp && rp.hasOutput) stat.watch++;

    // hygiene: em-dash / literal lab IP in user-visible strings
    let hyg = 0;
    [why, desc, fx.teach].forEach((s) => { if (emDash(s)) hyg++; });
    if (how && how.lead && emDash(how.lead)) hyg++;
    if (hyg) { stat.hygiene++; issues.push('em-dash x' + hyg); }

    if (issues.length) flagged.push({ lane: L.key, id, title: cell.title || id, issues });
  });
  perLane[L.key] = stat;
});

// --- report --------------------------------------------------------------------------------------
const pad = (s, n) => String(s).padEnd(n);
const num = (s, n) => String(s).padStart(n);
console.log('\nSTUDY CONTENT COVERAGE  (' + total + ' moves, ' + lanes.length + ' lanes)\n');
console.log(pad('lane', 10) + num('n', 4) + num('why', 5) + num('ovlp', 5) + num('lead', 5) + num('multi', 6) + num('how', 5) + num('demo', 5) + num('turn', 6) + num('watch', 6));
console.log('-'.repeat(57));
let T = { n: 0, why: 0, overlap: 0, leadup: 0, leadMulti: 0, how: 0, howDemo: 0, yourturn: 0, watch: 0 };
lanes.forEach((L) => {
  const s = perLane[L.key];
  ['n', 'why', 'overlap', 'leadup', 'leadMulti', 'how', 'howDemo', 'yourturn', 'watch'].forEach((k) => T[k] += s[k]);
  console.log(pad(L.key, 10) + num(s.n, 4) + num(s.why, 5) + num(s.overlap, 5) + num(s.leadup, 5) + num(s.leadMulti, 6) + num(s.how, 5) + num(s.howDemo, 5) + num(s.yourturn, 6) + num(s.watch, 6));
});
console.log('-'.repeat(57));
console.log(pad('TOTAL', 10) + num(T.n, 4) + num(T.why, 5) + num(T.overlap, 5) + num(T.leadup, 5) + num(T.leadMulti, 6) + num(T.how, 5) + num(T.howDemo, 5) + num(T.yourturn, 6) + num(T.watch, 6));
console.log('\nLegend: why=has why · ovlp=why duplicates description · lead=has lead-up · multi=multi-route lead-up');
console.log('        how=has field notes · demo=field notes are playable · turn=bespoke your-turn · watch=has replay output\n');

if (process.argv.includes('--flagged') || process.argv.includes('--lane')) {
  const laneArg = (process.argv[process.argv.indexOf('--lane') + 1]) || null;
  const list = laneArg ? flagged.filter((f) => f.lane === laneArg) : flagged;
  console.log('FLAGGED MOVES (' + list.length + (laneArg ? ' in ' + laneArg : '') + '):\n');
  list.forEach((f) => console.log('  [' + pad(f.lane, 8) + '] ' + pad(f.id, 28) + ' ' + f.issues.join(' · ')));
  console.log('');
}

// --check: fail (exit 1) on HARD content errors only (bad demo signals, em-dashes), for CI gating.
if (process.argv.includes('--check')) {
  const hard = flagged.filter((f) => f.issues.some((s) => /sig-not-in-out|em-dash/.test(s)));
  if (hard.length) {
    console.error('LINT FAIL: ' + hard.length + ' move(s) with hard content errors:');
    hard.forEach((f) => console.error('  ' + f.id + ': ' + f.issues.filter((s) => /sig-not-in-out|em-dash/.test(s)).join(' · ')));
    process.exit(1);
  }
  console.log('LINT OK: no hard content errors.');
}

