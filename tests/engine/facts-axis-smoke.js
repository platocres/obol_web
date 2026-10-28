/* FACTS-axis regression smoke (corpus-optional). Drives tools/corpus/facts-axis.js over the
 * human-labeled 0xdf ground-truth set (tools/corpus/labels/0xdf-facts.json) and asserts the labeled
 * set stays green:
 *   - zero forbidden-kind hits: a guarded kind minted is a real false positive, the ONLY hard failure,
 *   - recall does not regress below the recorded floor (misses are the facts-axis backlog, tracked not fatal),
 *   - every label still resolves to a live corpus block (no dangling ids after a corpus refresh).
 * The 0xdf snapshot is a large, local-only private oracle (see docs/CORPUS-MINING.md Principle 7) that is
 * NOT present on CI or a fresh checkout, so when facts-axis.js reports the corpus is absent (exit 2) this
 * test SKIPS cleanly (exit 0) and never breaks the verification gauntlet. qa-only; nothing here ships to
 * prod or runs at runtime. House style: no em or en dashes. */
'use strict';
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const QA = path.resolve(__dirname, '..', '..');
const TOOL = path.join(QA, 'tools', 'corpus', 'facts-axis.js');
const MATRIX = path.join(QA, 'tools', 'corpus', 'reports', '0xdf-facts-matrix.json');

// Ratchet thresholds. History: the admirer credentials.txt miss was closed by the websource labeled_leak
// extractor (2026-10-23), then the set expanded to 38 blocks across 15 parsers at the floor the parsers
// already meet (recall 1.0). A follow-up batch the same day deliberately asserted a STRICTER floor on
// three ambiguous blocks, opening the facts-axis backlog on purpose (recall 101/104 = 0.971):
//   - 100754e619b9  ftp `ls` exposing backup.mdb should mint loot.files (smbclient listings already do)
//   - 23708bbeb1b8  curl HTTP 404 error body should mint http.reachable (minted for a clean 200, not here)
//   - e0c783a21aa5  proxychains curl 200 HTML should mint http.reachable (prefix defeats the parser)
// Two Stage 5 parser fixes (2026-10-23) then closed all three backlog misses:
//   - the http.reachable pair: services.js _parse_http_metadata now mints http.reachable from a returned
//     response body (an HTML document or an "HTTP Error <code>" wrapper line), guarded so a name
//     resolution or connection failure (no body) stays unreachable (tests/engine/http-reachable-body-smoke.js
//     and the f87b247fe3a8 true-negative anchor), and
//   - the loot.files miss: services.js _parse_ftp_output now mints loot.files from an FTP directory
//     listing (Windows IIS and Unix ls -l row shapes), reached when the command names ftp or the output
//     carries FTP control codes, and minting only inside that FTP context (tests/engine/ftp-listing-loot-smoke.js).
// Recall is back to 104/104 = 1.0, so the floor is RAISED to 1.0: the facts-axis backlog is empty.
// Misses are tracked, not fatal (facts-axis.js still exits 0 on misses; only a forbidden-kind hit fails
// the axis). The floor is a one-way ratchet: lowering it to open a new backlog needs a comment naming the
// ids, and it must never drop silently. forbidden_hits must stay 0 regardless.
const RECALL_FLOOR = 1.0;
const MIN_LABELS = 100;    // ratchet: guards against an emptied or corrupt labels file passing vacuously (102 labeled 2026-10-23)

let fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

let code = 0, stderr = '';
try {
  execFileSync('node', [TOOL], { cwd: QA, stdio: ['ignore', 'ignore', 'pipe'] });
} catch (e) {
  code = typeof e.status === 'number' ? e.status : 1;
  stderr = (e.stderr && e.stderr.toString()) || '';
}

// Corpus-optional: facts-axis.js exits 2 when the private 0xdf snapshot is not present. Skip cleanly.
if (code === 2) {
  console.log('FACTS-AXIS SMOKE: SKIP (0xdf corpus snapshot not present; qa-only oracle)');
  process.exit(0);
}

ok(code === 0, 'facts-axis matrix ran with no forbidden-kind hits (exit 0); got exit ' + code + (stderr ? ' / ' + stderr.trim().split('\n')[0] : ''));
ok(fs.existsSync(MATRIX), 'matrix report was written');
if (fs.existsSync(MATRIX)) {
  const r = JSON.parse(fs.readFileSync(MATRIX, 'utf8'));
  const t = r.totals || {};
  ok((r.labeled_blocks || 0) >= MIN_LABELS, 'labeled set has at least ' + MIN_LABELS + ' blocks (got ' + r.labeled_blocks + ')');
  ok(!(r.missing_blocks || []).length, 'every label resolves to a live corpus block: ' + ((r.missing_blocks || []).join(', ') || 'none dangling'));
  ok(r.resolved_blocks === r.labeled_blocks, 'all labeled blocks resolved (' + r.resolved_blocks + '/' + r.labeled_blocks + ')');
  ok(t.forbidden_hits === 0, 'zero forbidden-kind hits on the labeled set (got ' + t.forbidden_hits + ')');
  ok(typeof t.recall === 'number' && t.recall >= RECALL_FLOOR, 'recall ' + t.recall + ' >= floor ' + RECALL_FLOOR);
}

console.log('\nFACTS-AXIS SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
