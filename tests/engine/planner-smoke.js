/* Node sanity test for the ported engine (facts/phases/pack) against the real packs. */
'use strict';
const fs = require('fs');
const path = require('path');

// Load the browser engine modules into Node's global (they attach to globalThis).
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/command.js');
const OBOL = globalThis.OBOL;

const PACKS_DIR = path.join(__dirname, '..', '..', 'data', 'packs');
const packData = OBOL.pack.PACK_NAMES.map((n) =>
  JSON.parse(fs.readFileSync(path.join(PACKS_DIR, n + '.json'), 'utf8'))
);
const pack = OBOL.pack.loadPacks(packData);

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

console.log('Loaded ' + pack.length + ' actions from ' + packData.length + ' packs.');
ok(pack.length >= 140, 'pack action count >= 140 (got ' + pack.length + ')');

// Fresh target: only target.configured proven.
const F = OBOL.facts;
function fs1(kinds) {
  const set = new OBOL.facts.FactSet([]);
  kinds.forEach((k) => set.add(F.makeFact({ kind: k, scope: 'host:10.10.10.10', state: F.ProofState.SUPPORTED })));
  return set;
}

// 1) A bare configured target should surface an nmap-first recon move at/near the top.
let facts = fs1(['target.configured']);
let ranked = OBOL.pack.nextActions(facts, pack);
ok(ranked.length > 0, 'bare target yields live actions (' + ranked.length + ')');
console.log('  top move:', ranked[0] && ranked[0].id, '—', ranked[0] && ranked[0].tool);
ok(ranked[0] && /nmap/i.test(ranked[0].tool + ranked[0].id), 'top move is nmap recon');

// 2) Frontier: after ports open, targeted service scan should be on-flow; loot must not lead.
facts = fs1(['target.configured', 'host.up', 'ports.open', 'port:389', 'port:445', 'port:88']);
ranked = OBOL.pack.nextActions(facts, pack);
ok(ranked.length > 0, 'post-portscan yields live actions (' + ranked.length + ')');
const topPhase = OBOL.phases.phaseOfAction(ranked[0]);
console.log('  frontier=', OBOL.phases.frontierIndex(facts), 'top move=', ranked[0].id, 'phase=', topPhase);
ok(['recon', 'enum'].indexOf(topPhase) >= 0, 'top move is on-flow (recon/enum), not premature');

// 3) Blocked reasons exist and read friendly.
const locked = OBOL.pack.lockedActions(facts, pack);
ok(locked.length > 0, 'locked actions surfaced with reasons (' + locked.length + ')');
console.log('  sample blocked:', locked[0].action.id, '=>', locked[0].reason);
ok(/blocked/.test(locked[0].reason), 'blocked reason phrased');

// 4) settled: an action whose produces are all proven drops off the frontier.
const anyAction = pack.find((a) => a.produces.length);
const settledFacts = fs1(['target.configured'].concat(anyAction.produces));
ok(anyAction.settled(settledFacts), 'settled() true when all produces proven (' + anyAction.id + ')');
ok(OBOL.pack.nextActions(settledFacts, pack).indexOf(anyAction) === -1, 'settled action not in nextActions');

// 5) OS gating: a Windows-only action hidden once linux proven.
facts = fs1(['target.configured', 'foothold.linux']);
const winOnly = pack.find((a) => a.os && a.os.length === 1 && OBOL.pack.normalizeOsName(a.os[0]) === 'windows');
if (winOnly) {
  ok(!winOnly.eligible(facts), 'windows-only action hidden on proven-linux target (' + winOnly.id + ')');
} else {
  console.log('  (no single-OS windows action found to test OS gating)');
}

// 6) web-suited commands: obol web prefers a `web` variant + surfaces its `web_note`, and the
// AD firehose actions carry one that redirects to a file (for the Evidence file-attach path).
const emptyFacts = fs1([]);
const synthetic = { id: 'w', commands: [{ tool: 'x', run: 'cmd --big', web: 'cmd --big | tee out.txt', web_note: 'attach the file' }] };
const wf = OBOL.command.fillCommand(synthetic, emptyFacts, {}, 0);
ok(/\| tee out\.txt/.test(wf.run) && wf.webNote === 'attach the file', 'fillCommand prefers the web command variant and exposes its web_note');
const plain = OBOL.command.fillCommand({ id: 'p', command: 'nmap -sC t' }, emptyFacts, {}, 0);
ok(plain.run === 'nmap -sC t' && plain.webNote === '', 'fillCommand falls back to the base command when no web variant exists');
const firehose = pack.filter((a) => (a.commands || []).some((c) => c.web && /\| tee /.test(c.web)));
ok(firehose.length >= 2, 'AD firehose actions carry a tee-to-file web variant (' + firehose.length + ' found)');
const anyWebNote = firehose.some((a) => (a.commands || []).some((c) => c.web_note && /attach/i.test(c.web_note)));
ok(anyWebNote, 'the web variant carries hands-on guidance to attach the file in Evidence');

console.log(fail ? ('\nENGINE SMOKE: ' + fail + ' FAILURES') : '\nENGINE SMOKE: all passed');
process.exit(fail ? 1 : 0);
