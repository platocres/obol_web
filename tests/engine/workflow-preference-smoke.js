/* Learner workflow preference: neurodivergent and disabled learners attack a box in the order that suits
 * them, and the coach must bend to that order PREDICTABLY without ever burying the obvious objective. This
 * locks three things: (1) the workflow preset is a NUDGE, fed to the ranker as focus prefixes alongside the
 * machine-type focus via the single profileFocus() helper; (2) it reorders the non-objective tail (a
 * 'pivot-aware' learner sees the pivot sooner than a 'flags-first' learner) but (3) never displaces a
 * reachable, still-uncaptured flag from #1 — the endgame objective pull, which also fixes the two-flag
 * blind spot where capturing the user flag used to zero the goal-distance and hide the open root flag.
 * Generic data. */
'use strict';
const fs = require('fs');
const path = require('path');
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/command.js');
const OBOL = globalThis.OBOL;

const pack = OBOL.pack.loadPacks(OBOL.pack.PACK_NAMES.map((n) =>
  JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'data', 'packs', n + '.json'), 'utf8'))));
const F = OBOL.facts;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function mk(kinds) {
  const s = new F.FactSet([]);
  kinds.forEach((k) => s.add(F.makeFact({ kind: k, scope: 'host:10.0.0.5', state: F.ProofState.SUPPORTED })));
  return s;
}
function ranked(kinds, wf) {
  return OBOL.pack.rankActions(mk(kinds), pack, { focusPrefixes: OBOL.profile.profileFocus({ workflow: wf }) })
    .map((a) => a.id);
}
function rankOf(ids, id) { const i = ids.indexOf(id); return i < 0 ? Infinity : i; }

// 1. The preset plumbing: normalize, default, and the combined focus helper.
ok(OBOL.profile.normalizeWorkflow('admin-first') === 'flags-first', 'a learner-friendly alias (admin-first) maps to the flags-first workflow');
ok(OBOL.profile.normalizeWorkflow('') === '' && OBOL.profile.workflowFocus('') .length === 0, 'an unset workflow yields no nudge (pure evidence order)');
ok(OBOL.profile.normalizeWorkflow('nonsense') === '', 'an unknown workflow falls back to no nudge, never throws');
const combined = OBOL.profile.profileFocus({ machine_type: 'dc', workflow: 'flags-first' });
ok(combined.indexOf('ad.') >= 0 && combined.indexOf('objective.') >= 0,
  'profileFocus() layers the machine-type focus (ad.) and the workflow focus (objective.) into one nudge');
ok(OBOL.profile.listWorkflows().some((w) => w.id === 'pivot-aware'),
  'the workflow list the UI renders includes the pivot-aware preset');

// 2. Fresh foothold, no flags captured yet: the USER flag leads under the default (balanced) order —
// "when I first get on a box I look for the user flag" — not an enumeration sweep.
const foot = ['target.configured', 'host.up', 'ports.open', 'os.linux', 'foothold.linux'];
ok(ranked(foot, 'balanced')[0] === 'flag-hunt-linux',
  'on a fresh Linux foothold the user-flag capture is the #1 balanced move (id=' + ranked(foot, 'balanced')[0] + ')');

// 3. The two-flag blind spot is fixed: user flag already captured + admin in hand + a second network in
// view. The still-open ROOT flag must lead under balanced — capturing the user flag no longer zeroes the
// goal-distance and hides the open root flag behind pivot/enumeration keystone.
const postAdmin = ['target.configured', 'host.up', 'ports.open', 'os.linux', 'foothold.linux',
  'access.admin', 'objective.local_flag', 'scan.local.neighbors'];
const bal = ranked(postAdmin, 'balanced');
ok(bal[0] === 'flag-hunt-root-linux',
  'with admin + the user flag already taken, the ROOT flag leads under balanced (id=' + bal[0] + ') — the open objective is not buried');

// 4. The INVARIANT: a reachable, uncaptured flag stays #1 under EVERY workflow — the nudge reorders the
// tail, it never displaces the obvious objective. Even a "map the network early" learner grabs the
// one-command-away root flag first.
['balanced', 'flags-first', 'pivot-aware'].forEach((wf) => {
  ok(ranked(postAdmin, wf)[0] === 'flag-hunt-root-linux',
    'the reachable root flag is #1 under the ' + wf + ' workflow — a preference never overrides the objective');
});

// 5. The nudge DOES reorder the non-objective tail: a pivot-aware learner sees the pivot sooner than a
// flags-first learner (both below the objective, but the relative order flips as asked).
const pivotId = 'pivot-chisel-socks';
const flagsFirst = ranked(postAdmin, 'flags-first');
const pivotAware = ranked(postAdmin, 'pivot-aware');
ok(rankOf(pivotAware, pivotId) < rankOf(flagsFirst, pivotId),
  'pivot-aware surfaces the pivot earlier than flags-first (pivot-aware=' + rankOf(pivotAware, pivotId) + ', flags-first=' + rankOf(flagsFirst, pivotId) + ')');
// …and flags-first keeps the escalation/enumeration ahead of the pivot (grab everything on THIS box first).
ok(rankOf(flagsFirst, 'linux-enum') < rankOf(flagsFirst, pivotId) || rankOf(flagsFirst, 'linux-loot-hunt') < rankOf(flagsFirst, pivotId),
  'flags-first keeps on-box escalation/loot ahead of the pivot');

console.log(fail ? ('\nWORKFLOW PREFERENCE: ' + fail + ' FAILURES') : '\nWORKFLOW PREFERENCE: all passed');
process.exit(fail ? 1 : 0);
