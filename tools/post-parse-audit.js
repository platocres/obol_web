#!/usr/bin/env node
/*!
 * tools/post-parse-audit.js — the post-parse-advance auditor (the "command -> real output -> fact ->
 * advance/retire" round-trip, task #30).
 *
 * gap-report.js audits the MOVE level (a move whose produced fact no parser reads; a move that produces
 * a fact nothing uses; an unreachable move). This auditor adds the COMMAND level and the FAILURE level,
 * the things that make a run feel broken even when the move graph is fine:
 *
 *   MISSED GAIN  — a move produces a PROGRESS fact (a foothold, access, credential, loot.ntds, or
 *                  objective) that NO parser can read. You get a shell / a cred / root, paste it, and
 *                  obol cannot tell. This is the worst class and the only one --check hard-fails on by
 *                  default (plus the probe-retire class below).
 *   PROBE RETIRE — a switchless confirm/probe command (an anonymous/auth check, a count) with no
 *                  `settled_by`, so after you run it and paste the proof the command just sits there
 *                  asking to be re-run (the recurring one-off bug the owner asked us to stop fixing
 *                  individually).
 *   RE-OFFER     — a move whose proven terminal state (access.admin/root/system, loot.ntds, a flag) has
 *                  neither `obsoleted_by` nor `deprioritize_when`, so it can re-offer after it is done.
 *   FAILURE GAP  — a move whose command authenticates / sprays / probes anonymous access but whose
 *                  likely failure (denied, locked out, wrong creds, bind-restricted) maps to no
 *                  `blocker.*` fact that a FIELD_DOCTOR handles. obol cannot doctor or redirect on
 *                  failure. Advisory (heuristic), not a hard gate.
 *
 * Read-only: never touches the pack or the ranker. Clustered output; human-triaged like ranker-sweep.
 *
 * Run:  node tools/post-parse-audit.js              (full report)
 *       node tools/post-parse-audit.js --check      (exit 1 on MISSED GAIN or PROBE RETIRE)
 */
'use strict';
var fs = require('fs'), path = require('path');
var ROOT = path.join(__dirname, '..');
function req(p) { return require(path.join(ROOT, p)); }

req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack;
var pdir = path.join(ROOT, 'data/packs'), bundle = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); });
var A = PK.loadPacks(Object.keys(bundle).map(function (k) { return bundle[k]; }));
OBOL.packs = { actions: function () { return A; }, packData: function () { return bundle; } };
req('data/tools-install.js'); req('data/study-fixtures.js'); req('assets/engine/study.js');
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');
req('data/decision-forks.js'); req('data/parser-signatures.js'); req('data/coverage-expected.js');
req('assets/engine/decisionmap.js'); req('data/field-notes.js');

var CHECK = process.argv.indexOf('--check') >= 0;

// Known-deferred hard findings that --check tolerates (so it catches NEW regressions, not these). Each
// is a captured-hash routing case closed by the "generic captured hash -> cracking path" work (TC), or a
// genuinely borderline probe. Remove an entry when its real fix lands.
var ALLOW_MISSED = { 'crack-identify|hash.type': 1, 'sqlite-table-extract|hash.candidate': 1, 'recon-ike-vpn|hash.ike_psk': 1, 'ipmi-bmc-cipher0|credential.hash': 1 };
var ALLOW_PROBE = { 'rdp-enum|0': 1, 'ftp-bounce|2': 1 };

// ── the parser capability set: every fact any parser can mint (prefix "." = wildcard family) ───────
var SIG = OBOL.PARSER_SIGNATURES || {};
var EMITS = {};
Object.keys(SIG).forEach(function (k) { (SIG[k].emits || []).forEach(function (e) { EMITS[e] = true; }); });
function parserReads(fact) {
  if (EMITS[fact]) return true;
  // prefix families: "service." reads "service.mysql"; and a parser emitting "foothold." reads "foothold.shell"
  return Object.keys(EMITS).some(function (e) { return e.slice(-1) === '.' && fact.indexOf(e) === 0; });
}

// a "progress" fact is one whose whole point is forward motion: not reading it loses real gain.
function isProgressFact(f) {
  return /^(foothold\.|access\.(shell|admin|root|system)|credential\.(available|validated|plain|admin|hash|candidate)|loot\.(ntds|sam)|hash\.|objective\.|ad\.(dcsync|attack_paths|acl_lead)|tunnel\.)/.test(f);
}
// a "terminal/proven" fact: a move that mints one is "done" and should retire rather than re-offer.
function isTerminalFact(f) {
  return /^(access\.(admin|root|system)|loot\.ntds|objective\.|foothold\.(linux|windows|webshell))/.test(f);
}
// a confirm/probe command: a switchless anonymous/auth check or a count, no exploit/dump payload.
var PAYLOAD_RE = /(^|\s)(-x|-X|-M|-T|-O|--exec|--sam|--lsa|--ntds|--shares|--spider|--rid-brute|--users|--put|--get|--upload|--download|--dump|--pass-pol|--asreproast|--kerberoasting|-c\s|--command)/i;
var PROBE_RE = /-u\s*('')|-u\s*''|-u\s+guest|-p\s*('')|-p\s*''|--null|anonymous/i;
function isProbe(run) { run = String(run || ''); return PROBE_RE.test(run) && !PAYLOAD_RE.test(run); }
// a command that authenticates or sprays (its failure is a login/lockout the operator should be doctored on)
function isAuthish(run) { run = String(run || ''); return /-u\s+\S|-p\s+\S|-H\s+\S|--password|--hashes|hydra|kerbrute|--spray/i.test(run) || isProbe(run); }

var DOCTORS = OBOL.FIELD_DOCTORS || {};

var missedGain = [], probeRetire = [], reOffer = [], failureGap = [];

A.forEach(function (m) {
  var produces = m.produces || [], cmds = (m.commands && m.commands.length) ? m.commands : (m.command ? [{ run: m.command }] : []);

  // MISSED GAIN — a produced progress fact no parser reads
  produces.forEach(function (f) {
    if (isProgressFact(f) && !parserReads(f)) missedGain.push({ id: m.id, fact: f });
  });

  // RE-OFFER — mints a terminal fact but has no retire edge
  var terminal = produces.filter(isTerminalFact);
  if (terminal.length && !(m.obsoleted_by && m.obsoleted_by.length) && !(m.deprioritize_when && m.deprioritize_when.length)) {
    reOffer.push({ id: m.id, facts: terminal });
  }

  // PROBE RETIRE — a probe command with no settled_by
  cmds.forEach(function (c, i) {
    if (isProbe(c.run) && !(c.settled_by && c.settled_by.length)) probeRetire.push({ id: m.id, idx: i, run: String(c.run || '').slice(0, 72) });
  });

  // FAILURE GAP — authenticating/spraying move with no reachable blocker doctor. Heuristic: the move
  // neither obsoletes on a blocker.* nor deprioritizes on one, and none of its commands settle on one.
  var authish = cmds.some(function (c) { return isAuthish(c.run); });
  if (authish) {
    var touchesBlocker = (m.obsoleted_by || []).concat(m.deprioritize_when || []).some(function (x) { return /^blocker\./.test(x) && DOCTORS[x]; })
      || cmds.some(function (c) { return (c.settled_by || []).some(function (x) { return /^blocker\./.test(x); }); });
    if (!touchesBlocker) failureGap.push({ id: m.id });
  }
});

// ── report ─────────────────────────────────────────────────────────────────────────────────────
function hd(s, n) { console.log('\n== ' + s + ' (' + n + ') =='); }
function list(arr, fmt, cap) { if (!arr.length) { console.log('  (none)'); return; } arr.slice(0, cap || 60).forEach(function (x) { console.log('  ' + fmt(x)); }); if (arr.length > (cap || 60)) console.log('  ... and ' + (arr.length - (cap || 60)) + ' more'); }

console.log('OBOL post-parse-advance audit — ' + A.length + ' moves');
console.log(JSON.stringify({ missedGain: missedGain.length, probeRetire: probeRetire.length, reOffer: reOffer.length, failureGap: failureGap.length }));

hd('MISSED GAIN — a progress fact no parser can read (you gain, obol cannot tell)', missedGain.length);
list(missedGain, function (x) { return x.id + '  -> ' + x.fact; });

hd('PROBE RETIRE — a confirm/probe command with no settled_by (cannot retire after it is proven)', probeRetire.length);
list(probeRetire, function (x) { return x.id + ' [cmd ' + x.idx + ']  ' + x.run; });

hd('RE-OFFER — mints a terminal fact but has no obsoleted_by/deprioritize_when', reOffer.length);
list(reOffer, function (x) { return x.id + '  -> ' + x.facts.join(', '); });

hd('FAILURE GAP (advisory) — authenticates/sprays but no blocker doctor reachable on failure', failureGap.length);
list(failureGap, function (x) { return x.id; }, 40);

var newMissed = missedGain.filter(function (x) { return !ALLOW_MISSED[x.id + '|' + x.fact]; });
var newProbe = probeRetire.filter(function (x) { return !ALLOW_PROBE[x.id + '|' + x.idx]; });
var hard = newMissed.length + newProbe.length;
console.log('\n' + (hard ? ('AUDIT: ' + hard + ' NEW hard finding(s) (MISSED GAIN + PROBE RETIRE)') : 'AUDIT: no new hard findings') +
  '  [' + (missedGain.length - newMissed.length + (probeRetire.length - newProbe.length)) + ' allowlisted, ' +
  reOffer.length + ' re-offer, ' + failureGap.length + ' failure-gap advisory]');
if (hard) { console.log('  NEW:'); newMissed.forEach(function (x) { console.log('   MISSED ' + x.id + ' -> ' + x.fact); }); newProbe.forEach(function (x) { console.log('   PROBE ' + x.id + ' [' + x.idx + ']'); }); }
if (CHECK && hard) process.exit(1);
process.exit(0);
