/* Golden-path corpus — replays real box kill-chains as fact-timelines and asserts the coach surfaces
 * the right next move at each checkpoint. This is the ground truth that turns "run 50 labs to find a
 * ranking bug" into "run CI". Adding a box is adding a JSON file under tests/engine/corpus/ — no code.
 *
 * It ranks with the SAME path every obol surface uses: rankActions (v2), report-only writeup checks
 * excluded, frontier-ready (prematurity 0) first — i.e. exactly what the coach/hub/target panel show.
 *
 * Box file schema (tests/engine/corpus/<box>.json):
 *   { "name": "...", "target": "10.10.10.161", "machine_type": "ad",
 *     "steps": [ { "after": "what you just did",
 *                  "add": ["fact.kind", ...],         // facts proven by this step (cumulative)
 *                  "topIn": ["move-id", ...],          // the #1 ready move must be one of these
 *                  "top": "move-id",                   // (strict) the #1 ready move must be exactly this
 *                  "present": ["move-id", ...],         // each must appear somewhere in the ready list
 *                  "absentTop": ["move-id", ...],       // none of these may be the #1 ready move
 *                  "prep": ["move-id", ...] } ] }       // each must offer a "Set Up First" command (loot)
 * Every assertion key is optional; use the loosest one that still pins the behaviour you care about
 * (topIn tolerates defensible co-leads; top is strict).
 */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
require('../../assets/engine/loot.js');
var fs = require('fs'), path = require('path');
var OBOL = globalThis.OBOL, PK = OBOL.pack, F = OBOL.facts, PH = OBOL.phases, L = OBOL.loot;
var pdir = path.join(__dirname, '..', '..', 'data', 'packs');
var PACK = PK.loadPacks(fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); })
  .map(function (f) { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } }));

var fail = 0, boxes = 0, checks = 0;
function ok(c, m) { checks++; if (!c) { console.error('    FAIL: ' + m); fail++; } }

// The ready list the coach/hub/target actually show: v2 ranking, report-only excluded, frontier-ready first.
function readyMoves(fset, focus) {
  var ranked = PK.rankActions(fset, PACK, { focusPrefixes: focus || [] });
  return ranked.filter(function (a) { return !PK.isReportOnly(a, PACK); })
    .filter(function (a) { return PH.prematurity(a, fset) === 0; });
}
// Does a move offer a "Set Up First" prep command for the facts in hand (writes loot/users.txt etc.)?
function hasPrep(move, fset) {
  var dirs = { lootdir: 'loot', scandir: 'scans' };
  if (L.actionUsesToken(move, 'userlist') && L.usernames(fset).length && L.userlistCommand(fset, dirs)) return true;
  var reqs = [].concat(move.requires_all || []);
  if (reqs.some(function (r) { return /^hash\./.test(r); }) && L.actionUsesToken(move, 'hashfile') && L.hashfileCommand(fset, move, dirs)) return true;
  return false;
}

var dir = path.join(__dirname, 'corpus');
var files = fs.existsSync(dir) ? fs.readdirSync(dir).filter(function (f) { return f.endsWith('.json'); }).sort() : [];
if (!files.length) { console.error('CORPUS: no box files under tests/engine/corpus/'); process.exit(1); }

files.forEach(function (file) {
  var box; try { box = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8')); } catch (e) { console.error('  bad box file ' + file + ': ' + e.message); fail++; return; }
  boxes++;
  console.log('\n# ' + (box.name || file));
  var focus = box.machine_type && OBOL.profile ? OBOL.profile.machineFocus(box.machine_type) : [];
  var target = box.target || '10.10.10.10';
  // Steps happen over time on a real box, so stamp each step's facts in its own batch an hour apart. This
  // keeps the recency tier meaningful (a move that JUST unlocked at this step is surfaced, exactly as the
  // live coach does) instead of collapsing every fact into one instant.
  var have = [], BASE = 1700000000000, HOUR = 3600000;
  (box.steps || []).forEach(function (step, si) {
    var t = BASE + (si + 1) * HOUR, n = 0;
    // An "add" entry is a fact kind (string) or { kind, value } when a checkpoint needs the payload
    // (e.g. ad.user_list with its users, so the AS-REP prep command has names to write).
    (step.add || []).forEach(function (k) {
      if (typeof k === 'string') have.push({ kind: k, value: {}, t: t + (++n) });
      else have.push({ kind: k.kind, value: k.value || {}, t: t + (++n) });
    });
    var flist = have.map(function (p) { return F.makeFact({ kind: p.kind, scope: { target: target }, value: p.value, source: 'corpus', created_at: p.t }); });
    var fset = new F.FactSet(flist);
    var ready = readyMoves(fset, focus);
    var ids = ready.map(function (a) { return a.id; });
    var label = '  [' + (si + 1) + '] ' + (step.after || '(step)');
    var top = ids[0] || '(none)';
    var note = ' → ' + top;
    if (step.top) ok(ids[0] === step.top, label + ' — #1 is ' + step.top + ' (got ' + top + ')');
    if (step.topIn) ok(step.topIn.indexOf(ids[0]) >= 0, label + ' — #1 ∈ {' + step.topIn.join(', ') + '} (got ' + top + ')');
    (step.present || []).forEach(function (id) { ok(ids.indexOf(id) >= 0, label + ' — ' + id + ' is offered'); });
    (step.absentTop || []).forEach(function (id) { ok(ids[0] !== id, label + ' — ' + id + ' is NOT #1'); });
    (step.prep || []).forEach(function (id) {
      var mv = PACK.filter(function (a) { return a.id === id; })[0];
      ok(mv && hasPrep(mv, fset), label + ' — ' + id + ' offers its Set-Up-First prep command');
    });
    console.log(label + note + (step.top || step.topIn || step.present || step.absentTop || step.prep ? '  ✓' : ''));
  });
});

console.log('\nCORPUS: ' + boxes + ' box(es), ' + checks + ' checks — ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
