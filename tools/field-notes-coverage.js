#!/usr/bin/env node
/* field-notes-coverage.js — an honest meter for the Next Steps field notes.
 *
 * The canvas shows per-(move, command) execution help: authored notes when they exist (OBOL.FIELD_NOTES),
 * otherwise a fallback built from the pack's own command note / move hypothesis. This tool reports, per lane
 * (pack) and overall, how many commands are AUTHORED vs merely falling back — so we never again mistake "the
 * canvas is never empty" for "the field notes are written". It also shows how many fallbacks even have a pack
 * command note to fall back on (a bare fallback is the weakest cell), and the reactive-doctor coverage.
 *
 *   node tools/field-notes-coverage.js            # the table
 *   node tools/field-notes-coverage.js --json      # machine-readable
 *   node tools/field-notes-coverage.js --missing <lane>   # list un-authored moves in a lane
 *
 * No --check gate: coverage is a long content effort, tracked, not enforced in CI.
 */
'use strict';
const fs = require('fs');
const path = require('path');
require('../assets/engine/facts.js');
require('../assets/engine/phases.js');
require('../assets/engine/pack.js');
require('../data/field-notes.js');
const OBOL = globalThis.OBOL;
const P = OBOL.pack;

const PACKS_DIR = path.join(__dirname, '..', 'data', 'packs');
const laneName = (n) => n.replace(/_20\d\d_\d\d$/, '').replace(/_/g, ' ');

// Load each pack file on its own so every move keeps its lane (pack) of origin.
const lanes = {};
let allMoves = [];
P.PACK_NAMES.forEach((n) => {
  const data = JSON.parse(fs.readFileSync(path.join(PACKS_DIR, n + '.json'), 'utf8'));
  const moves = P.actionsFromPackData(data);
  const lane = laneName(n);
  moves.forEach((m) => { m._lane = lane; });
  lanes[lane] = (lanes[lane] || []).concat(moves);
  allMoves = allMoves.concat(moves);
});

function authoredAt(id, i) { return !!((OBOL.FIELD_NOTES[id] || [])[i]); }

function tally(moves) {
  let cmds = 0, authoredCmds = 0, fallbackWithNote = 0, authoredMoves = 0, bareFallback = 0;
  moves.forEach((m) => {
    const cs = m.commands || [];
    let anyAuthored = false;
    cs.forEach((c, i) => {
      cmds++;
      if (authoredAt(m.id, i)) { authoredCmds++; anyAuthored = true; }
      else if (c.note) fallbackWithNote++;
      else if (!m.hypothesis) bareFallback++;
    });
    if (anyAuthored) authoredMoves++;
  });
  return { moves: moves.length, authoredMoves, cmds, authoredCmds, fallbackWithNote, bareFallback };
}

const args = process.argv.slice(2);
if (args[0] === '--missing') {
  const want = (args[1] || '').toLowerCase();
  const moves = (lanes[want] || []).filter((m) => (m.commands || []).length && !OBOL.FIELD_NOTES[m.id]);
  console.log('Un-authored moves in lane "' + want + '" (' + moves.length + '):');
  moves.forEach((m) => console.log('  ' + m.id + '  —  ' + m.title + '  (' + (m.commands || []).length + ' cmds)'));
  process.exit(0);
}

const rows = Object.keys(lanes).sort().map((l) => Object.assign({ lane: l }, tally(lanes[l])));
const tot = tally(allMoves);
const doctorKinds = Object.keys(OBOL.FIELD_DOCTORS || {}).length;

if (args[0] === '--json') {
  console.log(JSON.stringify({ lanes: rows, total: tot, reactiveDoctors: doctorKinds }, null, 2));
  process.exit(0);
}

const pct = (a, b) => b ? (Math.round((a / b) * 1000) / 10).toFixed(1) + '%' : '—';
const pad = (s, n) => String(s).padEnd(n);
const num = (s, n) => String(s).padStart(n);
console.log('\nFIELD NOTES COVERAGE  (authored per-command vs fallback)\n');
console.log(pad('lane', 18) + num('moves', 6) + num('auth', 5) + num('cmds', 6) + num('auth', 5) + num('cmd%', 7) + num('fb+note', 8) + num('bare', 6));
console.log('-'.repeat(61));
rows.forEach((r) => {
  console.log(pad(r.lane, 18) + num(r.moves, 6) + num(r.authoredMoves, 5) + num(r.cmds, 6) + num(r.authoredCmds, 5)
    + num(pct(r.authoredCmds, r.cmds), 7) + num(r.fallbackWithNote, 8) + num(r.bareFallback, 6));
});
console.log('-'.repeat(61));
console.log(pad('TOTAL', 18) + num(tot.moves, 6) + num(tot.authoredMoves, 5) + num(tot.cmds, 6) + num(tot.authoredCmds, 5)
  + num(pct(tot.authoredCmds, tot.cmds), 7) + num(tot.fallbackWithNote, 8) + num(tot.bareFallback, 6));
console.log('\nLegend: auth=authored · cmd%=authored commands / all commands · fb+note=un-authored but has a pack');
console.log('        command note to fall back on · bare=no authored note AND no pack note AND no hypothesis.');
console.log('Reactive blocker doctors: ' + doctorKinds + ' diagnostic facts carry a canvas fix.');
console.log('\nUse --missing <lane> to list a lane\'s un-authored moves. Authored coverage is a content');
console.log('effort tracked here, not a CI gate — the fallback keeps every cell non-empty meanwhile.\n');
