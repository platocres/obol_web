/* Next Steps field notes (Phase 2). The canvas help is scoped to a (move, command) and must never be
 * empty: an authored entry is used when present, otherwise it falls back to the pack's own command note or
 * the move hypothesis. Also locks that the authored flag spine carries land/win, that the resolver reports
 * the command's locus, and that the reactive blocker doctors are present and well-formed. Generic data. */
'use strict';
const fs = require('fs');
const path = require('path');
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../data/field-notes.js');
const OBOL = globalThis.OBOL;
const P = OBOL.pack;

const pack = P.loadPacks(P.PACK_NAMES.map((n) =>
  JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'data', 'packs', n + '.json'), 'utf8'))));
function byId(id) { return pack.filter((a) => a.id === id)[0]; }

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// 1. Authored spine: each flag move's commands resolve to a note with land + win + a locus.
['flag-hunt-linux', 'flag-hunt-root-linux', 'flag-hunt-windows', 'flag-hunt-root-windows'].forEach((id) => {
  const m = byId(id);
  ok(m, 'move exists: ' + id);
  (m.commands || []).forEach((c, i) => {
    const n = OBOL.fieldNote(m, i);
    ok(n && n.land.length > 0, id + ' cmd[' + i + '] has How-To-Land-It content');
    ok(n && typeof n.win === 'string', id + ' cmd[' + i + '] has a win string');
    ok(n && (n.locus === 'remote' || n.locus === 'onhost'), id + ' cmd[' + i + '] reports a locus');
  });
});

// the windows flag move's remote spider note explains it only locates (the on-host distinction).
const fhw = OBOL.fieldNote(byId('flag-hunt-windows'), 1);
ok(/locate/i.test(fhw.land.join(' ')) || /scores zero/i.test(fhw.mistakes.join(' ')), 'the windows remote spider note explains it only locates');

// 2. Graceful fallback: an un-authored move still yields non-empty help from its command note/hypothesis.
// Coverage is now 100%, so there is no real un-authored move to probe; synthesize one from a real move
// (a fake id the FIELD_NOTES map does not carry) to exercise the fallback deterministically.
const real = pack.filter((a) => (a.commands || []).length > 0 && ((a.commands[0] || {}).note || a.hypothesis))[0];
ok(real, 'found a pack move with a command note or hypothesis to clone');
const unauthored = Object.assign({}, real, { id: '__unauthored_probe__' });
ok(!OBOL.FIELD_NOTES[unauthored.id], 'the probe id is not authored');
const fb = OBOL.fieldNote(unauthored, 0);
ok(fb && fb.land.length > 0 && !fb.authored, 'un-authored command falls back to a non-empty note (from the pack command note / hypothesis)');

// 3. Reactive doctors: present, keyed by blocker.* (or ssh.key_rejected), each with a title + body.
const docKeys = Object.keys(OBOL.FIELD_DOCTORS);
ok(docKeys.length >= 8, 'a set of reactive blocker doctors is seeded (' + docKeys.length + ')');
ok(docKeys.every((k) => /^(blocker\.|ssh\.key_rejected)/.test(k)), 'every reactive doctor is keyed by a diagnostic fact');
ok(docKeys.every((k) => OBOL.FIELD_DOCTORS[k].title && OBOL.FIELD_DOCTORS[k].body), 'every reactive doctor has a title and body');
ok(OBOL.FIELD_DOCTORS['ssh.key_rejected'] && /chmod 600/.test(OBOL.FIELD_DOCTORS['ssh.key_rejected'].code || ''), 'the SSH-key doctor hands the chmod 600 fix');

console.log(fail ? ('\nFIELD NOTES: ' + fail + ' FAILURES') : '\nFIELD NOTES: all passed');
process.exit(fail ? 1 : 0);
