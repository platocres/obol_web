#!/usr/bin/env node
/*!
 * tools/gate-audit.js — the per-move GATE AUDIT (bidirectional).
 *
 * move-lint checks the move CONTRACT; gap-report checks graph WIRING; this prints, for EVERY move, the
 * actual gate/produce wiring in both directions so a human can verify each one surfaces exactly when it
 * should — and flags the mechanical gate faults outright. It exists so "I audited every move" is a command
 * you re-run, not a promise.
 *
 * For each move it shows:
 *   req_all / req_any  — each gate fact tagged with WHERE it can come from: <env> (a seed recon fact),
 *                        <move:N> (N moves produce it), <parser> (a parser mints it from pasted output),
 *                        or <NONE> (nothing mints it — a dead gate).
 *   produces           — each produced fact tagged with its SINK: a goal, N consumers (the hand-off),
 *                        evidence the ranker reads, or TERMINAL/none (a dead-end effect).
 *
 * Lenses (printed as sections; FAIL ones exit 1 under --check):
 *   FAIL · DEAD-GATE   a gate fact nothing mints (move/parser/env) — the move can never fire through it.
 *                      If it is the ONLY option the move is unreachable (gap-report catches that too); if
 *                      one of several, it is a dead OR-branch to delete or wire up.
 *   FAIL · NO-GATE     a move with no requires at all — always eligible, so it can surface on an empty box.
 *   FAIL · PHASE-EFFECT  a recon/enum move that produces a foothold/privilege (mis-phased; it would be
 *                      ranked as mere recon while handing you access).
 *   INFO · BARE-RECON-PAYOFF  a move that can fire from bare recon (all req_all are env, a req_any is env)
 *                      AND produces a payoff. With a vuln. or service. option this is the INTENDED
 *                      offer-at-port/promote-on-evidence pattern (capped by the ranker). With ONLY a bare
 *                      port/http option it is pure speculation — review whether it wants a tech/vuln lead.
 *
 * Run:  node tools/gate-audit.js            (full per-move wiring + lenses)
 *       node tools/gate-audit.js --flags    (lenses only, skip the per-move dump)
 *       node tools/gate-audit.js --check     (exit 1 on any FAIL lens)
 */
'use strict';
var fs = require('fs'), path = require('path');
var ROOT = path.join(__dirname, '..');
function req(p) { return require(path.join(ROOT, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
req('assets/engine/decisionmap.js');
try { req('data/parser-signatures.js'); } catch (e) {}
var OBOL = globalThis.OBOL, PK = OBOL.pack, PH = OBOL.phases, DM = OBOL.decisionMap;

var argv = process.argv.slice(2), CHECK = argv.indexOf('--check') >= 0, FLAGS_ONLY = argv.indexOf('--flags') >= 0 || CHECK;
var pdir = path.join(ROOT, 'data/packs');
var raw = [], packOf = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) {
  try { var p = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); (p.actions || p.moves || []).forEach(function (a) { raw.push(a); packOf[a.id] = f.replace('_2026_09.json', ''); }); } catch (e) {}
});
raw.sort(function (a, b) { return (packOf[a.id] + a.id).localeCompare(packOf[b.id] + b.id); });

var producers = {}, consumers = {};
raw.forEach(function (a) {
  (a.produces || []).forEach(function (k) { (producers[k] = producers[k] || []).push(a.id); });
  (a.requires_all || []).concat(a.requires_any || []).forEach(function (k) { (consumers[k] = consumers[k] || []).push(a.id); });
});
var GOAL = {}; (PK.GOALS || []).forEach(function (g) { GOAL[g] = 1; });
var cap = DM.capability();
function isEnv(k) { return /^(target\.|host\.up$|ports\.open$|port:|scan\.|service\.|os\.)/.test(k) || /\.reachable$/.test(k) || /^(ad\.dc_candidate|ad\.domain_known|host\.os_hint|host\.fqdn|host\.domain|host\.hostname)$/.test(k); }
function parserCovers(k) { if (cap.exact[k]) return true; for (var i = 0; i < cap.pref.length; i++) if (k.indexOf(cap.pref[i]) === 0) return true; return false; }
function gateSource(k) { var s = []; if (isEnv(k)) s.push('env'); if (producers[k]) s.push('move:' + producers[k].length); if (parserCovers(k)) s.push('parser'); return s.join('+') || 'NONE'; }
function prodSink(k) { if (GOAL[k]) return 'GOAL'; if (consumers[k]) return consumers[k].length + ' consumers'; if (PK.isEvidenceFact && PK.isEvidenceFact(k)) return 'evidence'; return 'TERMINAL/none'; }
function firesFromBareRecon(a) { var all = a.requires_all || [], any = a.requires_any || []; if (!all.every(isEnv)) return false; return any.length === 0 || any.some(isEnv); }
var PAYOFF = /^(foothold\.|access\.|loot\.ntds|credential\.(available|plaintext))/;

var deadGate = [], noGate = [], phaseEffect = [], bareReconIntended = [], bareReconSpeculative = [];

raw.forEach(function (a) {
  var all = a.requires_all || [], any = a.requires_any || [], prod = a.produces || [];
  var phase = PH.phaseOfAction ? PH.phaseOfAction(a) : a.phase;
  if (!FLAGS_ONLY) {
    var locus = a.locus ? a.locus + '(expl)' : (PK.deriveLocus ? PK.deriveLocus(a) : '?') + '(der)';
    console.log('### [' + packOf[a.id] + '] ' + a.id + '  locus=' + locus + ' phase=' + phase + (a.sequence ? ' SEQ' : ''));
    console.log('   req_all: ' + (all.map(function (k) { return k + ' <' + gateSource(k) + '>'; }).join(', ') || '(none)'));
    console.log('   req_any: ' + (any.map(function (k) { return k + ' <' + gateSource(k) + '>'; }).join(', ') || '(none)'));
    console.log('   produces: ' + (prod.map(function (k) { return k + ' [' + prodSink(k) + ']'; }).join(', ') || '(none)'));
  }
  all.concat(any).forEach(function (k) { if (gateSource(k) === 'NONE') deadGate.push(a.id + '  dead gate: ' + k + (any.indexOf(k) >= 0 && any.length > 1 ? ' (one of ' + any.length + ' OR-options)' : ' (sole/required)')); });
  if (!all.length && !any.length) noGate.push(a.id + ' [' + packOf[a.id] + ']');
  if ((phase === 'recon' || phase === 'enum') && prod.some(function (k) { return /^(foothold\.|access\.|loot\.ntds)/.test(k); })) phaseEffect.push(a.id + ' phase=' + phase + ' produces ' + prod.join(','));
  if (firesFromBareRecon(a) && prod.some(function (k) { return PAYOFF.test(k); })) {
    var lead = any.some(function (k) { return /^(vuln\.|service\.)/.test(k); });
    var line = a.id + ' [' + packOf[a.id] + '] any=[' + any.join(',') + ']';
    if (lead) bareReconIntended.push(line); else bareReconSpeculative.push(line);
  }
});

function section(title, arr) { console.log('\n== ' + title + ' (' + arr.length + ') =='); if (!arr.length) { console.log('  (none)'); return; } arr.forEach(function (x) { console.log('  ' + x); }); }

if (!FLAGS_ONLY) console.log('\n──────── GATE-AUDIT LENSES ────────');
console.log('OBOL gate audit — ' + raw.length + ' moves');
section('FAIL · DEAD-GATE — a gate fact nothing mints (env/move/parser)', deadGate);
section('FAIL · NO-GATE — move with no requires (always eligible)', noGate);
section('FAIL · PHASE-EFFECT — recon/enum move producing a foothold/privilege', phaseEffect);
section('INFO · BARE-RECON-PAYOFF (intended: has a vuln./service. promote option, capped till then)', bareReconIntended);
section('INFO · BARE-RECON-PAYOFF (pure speculation: only a bare port/http option — review for a tech/vuln lead)', bareReconSpeculative);

var failCount = deadGate.length + noGate.length + phaseEffect.length;
console.log('\n' + raw.length + ' moves · ' + failCount + ' FAIL · ' + (bareReconIntended.length + bareReconSpeculative.length) + ' bare-recon-payoff (advisory)');
if (CHECK && failCount) { console.error('GATE AUDIT FAIL: ' + failCount + ' gate fault(s).'); process.exit(1); }
if (CHECK) console.log('GATE AUDIT OK: no dead gates, no ungated moves, no mis-phased payoffs.');
