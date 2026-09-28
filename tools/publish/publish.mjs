#!/usr/bin/env node
/*
 * publish.mjs — produce a clean, de-provenanced snapshot of this repo for the public `obol` repo.
 *
 * WHAT IT DOES
 *   1. Takes the exact set of git-tracked files (so no stray/untracked junk ships).
 *   2. Drops the private/provenance files entirely (DENY).
 *   3. Scrubs every text file: removes lineage/derivation references and renames the product
 *      (obol_web -> obol), so the public code reads as original, standalone work.
 *   4. Adds a LICENSE.
 *   5. Regenerates the pack bundle + asset cache-bust stamps from the scrubbed sources.
 *   6. GATE: scans the finished tree for any forbidden token. If even one survives, it prints
 *      every hit (file:line) and refuses — nothing is published until the tree is clean.
 *
 * MODES
 *   node tools/publish/publish.mjs               → practice run: stage to a scratch dir, report, stop.
 *   node tools/publish/publish.mjs --publish DIR  → also sync into the `obol` checkout at DIR
 *                                                   (commit + push are done separately, by hand).
 *
 * This file lives under tools/publish/, which DENY excludes — the robot never ships itself.
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const STAGE = process.env.OBOL_STAGE || '/tmp/claude-0/obol-staging';
const PUBLISH_TO = (() => { const i = process.argv.indexOf('--publish'); return i >= 0 ? process.argv[i + 1] : null; })();

// ── files never published (private context + the robot itself) ──────────────
const DENY = ['CLAUDE.md', 'AGENTS.md', 'CHANGELOG.md', 'docs/', '.github/', 'tools/publish/'];

// ── which files are text (get scrubbed + gate-scanned); everything else copies verbatim ──
const TEXT_EXT = new Set(['.js', '.mjs', '.cjs', '.json', '.css', '.html', '.md', '.txt', '.svg', '.yml', '.yaml', '.map']);

// ── exact-match fixes for a few prose spots, applied BEFORE the regex rules ──
const MANUAL = [
  ["normalized to obol-local's namespace\n(AGENTS.md). Every snippet", "normalized to obol's namespace. Every snippet"],
];

// ── scrub rules, applied in order to every text file ────────────────────────
// IMPORTANT: strip rules match with [^.\n]/[^)\n] and trim only [ \t] (never \s, which eats
// newlines) so a comment can never swallow the line of CODE beneath it.
const RULES = [
  // 1) exact file-path tokens (obol-local/obol/graph.py, obol-local/webapp/static/js/coin.js …)
  [/\bobol-local\/[^\s`)'"]*/gi, ''],
  // 2) parentheticals that are derivation notes or name the donor (single-line only — never cross
  //    into code: [^)\n] keeps the match inside one comment line, [ \t]* never eats a newline)
  [/[ \t]*\([^)\n]*\bobol-local\b[^)\n]*\)/gi, ''],
  [/[ \t]*\((?:ported|adapted|derived|faithful[^)\n]*port|parity|mirror\w*|emulat\w*|harvest\w*)[^)\n]*\)/gi, ''],
  // 3) sentence/clause derivation phrasing (single-line: [^.\n] stops at a period OR the line end,
  //    so a period-less comment can never gobble the code below it; trailing trim is [ \t]* only)
  [/\bA faithful JS port of[^.\n]*\.[ \t]*/gi, ''],
  [/\bFaithful JS port of[^.\n]*\.[ \t]*/gi, ''],
  [/\bPorted from[^.\n]*\.[ \t]*/gi, ''],
  [/,?[ \t]*ported and cleaned from the donor\b[^.\n]*/gi, ''],
  [/,?[ \t]*(?:mirror(?:s|ing)|emulat\w+|parity with|harvest\w+ from)\s+obol-local(?:'s)?[^.\n,;:)]*/gi, ''],
  // 4) leftover donor name → self-reference (reads naturally, reveals no separate repo)
  [/\bobol-local's\b/gi, "obol's"],
  [/\bobol-local\b/gi, 'obol'],
  [/\bthe donor\b/gi, 'the original'],
  [/\bdonor\b/gi, 'origin'],
  // 5) python-origin file references (NOTICE.md etc.)
  [/\(`?obol\/provision\.py`?\)/gi, '(the tool cache)'],
  [/`?obol\/provision\.py`?/gi, 'the tool cache'],
  [/\(`?obol\/tools\.py`?[^)]*\)/gi, '(shell handlers)'],
  [/`?obol\/tools\.py`?/gi, 'the shell-handler catalogue'],
  [/\bobol\/[a-z_]+\.py\b/gi, 'the engine'],
  [/§\s*8\s*/g, ''],
  // 6) internal planning/agent doc references (never shipped)
  [/\[`?AGENTS\.md`?\]\([^)]*\)/gi, ''],
  [/\s*\(AGENTS\.md\)/gi, ''],
  [/\s*\((?:ROADMAP|SOURCES)[^)]*\)/gi, ''],
  [/\s*ROADMAP\s*§\s*\d+/gi, ''],
  [/\bAGENTS\.md\b/gi, ''],
  // 7) drop the README "Under the hood (for developers)" section — it maps the port lineage
  [/\n## Under the hood \(for developers\)[\s\S]*?(?=\n## )/g, '\n'],
  // 8) rename the product everywhere (comments, headers, the live-site URL)
  [/\bobol_web\b/g, 'obol'],
];

// ── the gate: none of these may survive anywhere in the published tree ───────
const FORBIDDEN = [
  ['claude', /claude/i],
  ['anthropic', /anthropic/i],
  ['co-authored', /co-authored/i],
  ['claude.ai', /claude\.ai/i],
  ['session id', /session_[0-9a-f]{6,}/i],
  ['obol-local', /obol-local/i],
  ['obol_web', /obol_web/i],
  ['donor', /\bdonor\b/i],
  ['AGENTS.md ref', /AGENTS\.md/i],
  ['CLAUDE.md ref', /CLAUDE\.md/i],
  // other AI assistants that helped build obol_web — never credit them in the public repo either
  ['openai', /openai/i],
  ['chatgpt', /chatgpt/i],
  ['codex', /\bcodex\b/i],
  ['gpt', /\bgpt\b/i],
  ['copilot', /copilot/i],
];

const MIT = (year, holder) => `MIT License

Copyright (c) ${year} ${holder}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

function isDenied(rel) { return DENY.some((d) => (d.endsWith('/') ? rel.startsWith(d) : rel === d)); }
function isText(rel) { return TEXT_EXT.has(path.extname(rel).toLowerCase()); }
function scrub(text) {
  let s = text;
  for (const [find, rep] of MANUAL) s = s.split(find).join(rep);
  return RULES.reduce((acc, [re, rep]) => acc.replace(re, rep), s);
}

function rmrf(p) { fs.rmSync(p, { recursive: true, force: true }); }
function ensureDir(p) { fs.mkdirSync(p, { recursive: true }); }

// 1) file set
const tracked = execFileSync('git', ['-C', REPO, 'ls-files'], { encoding: 'utf8' })
  .split('\n').map((s) => s.trim()).filter(Boolean);

// 2) stage
rmrf(STAGE); ensureDir(STAGE);
let copied = 0, scrubbed = 0, denied = 0;
for (const rel of tracked) {
  if (isDenied(rel)) { denied++; continue; }
  const src = path.join(REPO, rel), dst = path.join(STAGE, rel);
  ensureDir(path.dirname(dst));
  if (isText(rel)) {
    const out = scrub(fs.readFileSync(src, 'utf8'));
    fs.writeFileSync(dst, out); scrubbed++;
  } else {
    fs.copyFileSync(src, dst); copied++;
  }
}

// 3) add LICENSE
fs.writeFileSync(path.join(STAGE, 'LICENSE'), MIT(new Date().getFullYear(), 'platocres'));

// 4) regenerate bundle + stamps from the scrubbed sources so everything is internally consistent
function run(cmd, args) { execFileSync(cmd, args, { cwd: STAGE, stdio: 'pipe' }); }
try { run('node', ['tools/build-packs.js']); } catch (e) { console.error('build-packs failed in staging:', e.message); }
try { run('node', ['tools/stamp-assets.js']); } catch (e) { console.error('stamp-assets failed in staging:', e.message); }

// 5) gate — scan the finished tree
const hits = [];
(function walk(dir) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name), rel = path.relative(STAGE, p);
    if (fs.statSync(p).isDirectory()) { if (name !== '.git') walk(p); continue; }
    if (!isText(rel)) continue;
    const lines = fs.readFileSync(p, 'utf8').split('\n');
    lines.forEach((ln, i) => {
      for (const [label, re] of FORBIDDEN) {
        if (re.test(ln)) hits.push({ rel, line: i + 1, label, text: ln.trim().slice(0, 140) });
      }
    });
  }
})(STAGE);

// 6) report
console.log('\n=== PUBLISH PRACTICE RUN ===');
console.log(`staged to : ${STAGE}`);
console.log(`files     : ${scrubbed} scrubbed (text) + ${copied} copied (binary) = ${scrubbed + copied}`);
console.log(`dropped   : ${denied} private/provenance files (${DENY.join(', ')})`);
console.log(`gate      : ${hits.length ? hits.length + ' FORBIDDEN TOKEN(S) STILL PRESENT' : 'CLEAN — no forbidden tokens'}`);
if (hits.length) {
  console.log('\n--- remaining hits (must be fixed before publishing) ---');
  for (const h of hits.slice(0, 200)) console.log(`  ${h.rel}:${h.line}  [${h.label}]  ${h.text}`);
  if (hits.length > 200) console.log(`  … and ${hits.length - 200} more`);
}

if (PUBLISH_TO && hits.length) {
  console.error('\nRefusing to publish: gate is not clean.');
  process.exit(1);
}
if (PUBLISH_TO && !hits.length) {
  // mirror staged tree into the target checkout, preserving its .git
  for (const name of fs.readdirSync(PUBLISH_TO)) { if (name !== '.git') rmrf(path.join(PUBLISH_TO, name)); }
  (function copyTree(from, to) {
    for (const name of fs.readdirSync(from)) {
      const s = path.join(from, name), d = path.join(to, name);
      if (fs.statSync(s).isDirectory()) { ensureDir(d); copyTree(s, d); }
      else fs.copyFileSync(s, d);
    }
  })(STAGE, PUBLISH_TO);
  console.log(`\nSynced clean tree into ${PUBLISH_TO} (commit + push done separately).`);
}
process.exit(hits.length && PUBLISH_TO ? 1 : 0);
