#!/usr/bin/env node
/* build-study-fixtures.js — bootstrap Study-mode sample outputs from the parser test fixtures.
 *
 * The 80 files in tests/engine/fixtures/parser/outputs/ are real, representative tool outputs the
 * parsers were built against. This maps each one to the study move it best fits, extracts a heuristic
 * "signal" line, and writes data/study-fixtures-auto.js (OBOL.STUDY_FIXTURES_AUTO). Hand-written
 * entries in study-fixtures.js always win over these (the engine merges auto first, hand second).
 *
 * Auto entries carry output + signal only — no teach note (those are hand-written where they matter).
 * Run: node tools/build-study-fixtures.js
 */
'use strict';
const fs = require('fs'), path = require('path');
const ROOT = path.join(__dirname, '..');

// load the move set
require(path.join(ROOT, 'assets/engine/facts.js'));
require(path.join(ROOT, 'assets/engine/phases.js'));
require(path.join(ROOT, 'assets/engine/pack.js'));
require(path.join(ROOT, 'assets/engine/profile.js'));
require(path.join(ROOT, 'assets/engine/command.js'));
require(path.join(ROOT, 'assets/engine/workspace.js'));
const PK = globalThis.OBOL.pack;
const pdir = path.join(ROOT, 'data/packs');
const packData = fs.readdirSync(pdir).filter((f) => f.endsWith('.json')).map((f) => { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } });
const MOVES = PK.loadPacks(packData);

const FXDIR = path.join(ROOT, 'tests/engine/fixtures/parser/outputs');
const files = fs.existsSync(FXDIR) ? fs.readdirSync(FXDIR).filter((f) => f.endsWith('.txt')) : [];

// tokens that identify a move: its id, its tools, and the tails of the facts it produces
function tokens(s) { return String(s || '').toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 2); }
function moveTokens(m) {
  let t = tokens(m.id);
  (m.tools || []).concat([m.tool]).forEach((x) => { if (x) t = t.concat(tokens(x)); });
  (m.commands || []).forEach((c) => { if (c.tool) t = t.concat(tokens(c.tool)); const w = (c.run || '').match(/^[^\s]+/); if (w) t = t.concat(tokens(w[0])); });
  (m.produces || []).forEach((p) => { t = t.concat(tokens(p)); });
  return new Set(t);
}
// a fixture only counts as a confident match when it shares a *distinctive* tool/id token with a move
const STOP = new Set(['hit', 'none', 'only', 'ansi', 'test', 'out', 'output', 'context', 'auth', 'login', 'denied', 'metadata', 'negative', 'leads', 'the', 'and', 'raw', 'web', 'ad', 'windows', 'linux']);
function fixtureTokens(fn) { return tokens(fn.replace(/\.txt$/, '')).filter((t) => !STOP.has(t)); }

function signalOf(text) {
  const lines = text.split('\n');
  const prio = [
    /\$krb5asrep|\$krb5tgs|\$DCC2|\$MACHINE/, /aad3b435b51404ee|:::$/, /VALID LOGIN|\[\+\] /i,
    /root:x:0:0/, /uid=\d+.*(root|euid=0)/, /euid=0\(root\)/, /nt authority\\system/i,
    /SERVICE_ALL_ACCESS|GenericAll|SeImpersonate|AlwaysInstallElevated/, /NOPASSWD/,
    /HTTP\/1\.[01] (200|301|302|500)/, /\bopen\b.*(ssh|http|smb|ldap|kerberos|microsoft-ds)/i,
    /password|secret|key|token|flag\{/i,
  ];
  for (const re of prio) { const hit = lines.find((l) => re.test(l)); if (hit) return hit.trim().slice(0, 80); }
  // else the longest substantive line
  let best = ''; lines.forEach((l) => { const t = l.trim(); if (t.length > best.length && !/^[-=\s]*$/.test(t)) best = t; });
  return best.slice(0, 80);
}

// the tool basenames a move actually invokes — a shared one of these is a strong, confident match
function toolSet(m) {
  let t = [];
  (m.commands || []).forEach((c) => { if (c.tool) t = t.concat(tokens(c.tool)); });
  (m.tools || []).concat([m.tool]).forEach((x) => { if (x) t = t.concat(tokens(x)); });
  return new Set(t);
}
// negative / empty fixtures make poor teaching samples ("nothing found")
const NEG = /(_none|_denied|_no_|_not_|_negative|_timeout|_refutes|_exhausted|_fail)/;
// moves whose only token overlap is a coincidence — never auto-map these
const DENY = new Set(['shell-pty-upgrade']);

const auto = {};
const matched = [];
files.forEach((fn) => {
  if (NEG.test(fn)) return;
  const ftoks = fixtureTokens(fn); if (!ftoks.length) return;
  let best = null, bestScore = 0, bestStrong = false;
  MOVES.forEach((m) => {
    const mt = moveTokens(m), ts = toolSet(m);
    let score = 0, strong = false; ftoks.forEach((t) => { if (mt.has(t)) { score += 1; if (ts.has(t)) strong = true; } });
    if (score > bestScore || (score === bestScore && strong && !bestStrong)) { bestScore = score; best = m; bestStrong = strong; }
  });
  // accept only a confident match: a shared tool name, or heavy keyword overlap
  if (best && !DENY.has(best.id) && (bestStrong || bestScore >= 3)) {
    const text = fs.readFileSync(path.join(FXDIR, fn), 'utf8').replace(/\s+$/,'').split('\n').slice(0, 14).join('\n');
    // keep the strongest fixture per move (prefer a tool-name match)
    var rank = bestScore + (bestStrong ? 10 : 0);
    if (!auto[best.id] || rank > auto[best.id]._rank) {
      auto[best.id] = { output: text, signal: signalOf(text), _score: bestScore, _rank: rank, _file: fn };
    }
  }
});

// emit
const clean = {};
Object.keys(auto).sort().forEach((id) => { clean[id] = { output: auto[id].output, signal: auto[id].signal }; matched.push(id + ' ← ' + auto[id]._file + ' (' + auto[id]._score + ')'); });
const header = '/*! obol data — study-fixtures-auto.js — OBOL.STUDY_FIXTURES_AUTO\n'
  + ' * GENERATED by tools/build-study-fixtures.js from the parser test fixtures. Do not edit by hand.\n'
  + ' * Hand-written entries in study-fixtures.js override these. Auto entries carry output + signal only.\n'
  + ' */\n';
const body = '(function (root) {\n  \'use strict\';\n  var OBOL = root.OBOL = root.OBOL || {};\n  OBOL.STUDY_FIXTURES_AUTO = ' + JSON.stringify(clean, null, 2) + ';\n})(typeof globalThis !== \'undefined\' ? globalThis : this);\n';
fs.writeFileSync(path.join(ROOT, 'data/study-fixtures-auto.js'), header + body);
console.log('build-study-fixtures: ' + Object.keys(clean).length + ' auto fixtures from ' + files.length + ' parser outputs');
matched.forEach((l) => console.log('  ' + l));
