/*!
 * tools/attack-coverage.js, the ATT&CK lineup-coverage auditor.
 *
 * The Frameworks view maps obol's moves onto MITRE ATT&CK (data/attack-move-map.js: BY_KIND fact-kind
 * -> technique, BY_MOVE move-id -> technique). This tool audits that mapping two ways, both read-only:
 *
 *   (1) INTEGRITY (a hard gate, exits non-zero on failure): every BY_MOVE id names a real pack move;
 *       every BY_MOVE / BY_KIND technique and every findings-catalog `attack` code is a real ATT&CK
 *       technique in the bundled catalog. A dangling id is a silent bug (a blank cell, a lost example).
 *
 *   (2) COVERAGE (informational, the gap signal the owner asked for): over the techniques obol already
 *       references, which have a runnable example command (OBOL.frameworks.exampleCommands) and which do
 *       not, plus the inverse, pack moves that clearly PERFORM a technique (they produce a foothold /
 *       access / shell win) yet map to NO technique, so they never light a cell or offer an example.
 *       That inverse list is where real move/label gaps surface (it is how Pass-the-Hash, Golden Ticket
 *       and Password Spraying were found unmapped). Not a gate: a "no example" technique is often
 *       by-design (a parser-minted privesc lead resolved through GTFOBins, not a discrete command).
 *
 * Run: node tools/attack-coverage.js            (summary + the gap lists)
 *      node tools/attack-coverage.js --verbose  (also every referenced technique with its status)
 */
'use strict';
var fs = require('fs'), path = require('path');
require('../assets/engine/facts.js');
require('../assets/engine/phases.js');
require('../assets/engine/pack.js');
require('../assets/engine/profile.js');
require('../assets/engine/command.js');
require('../assets/engine/workspace.js');
require('../assets/engine/loot.js');
require('../data/attack-catalog.js');
require('../data/attack-move-map.js');
require('../data/findings-catalog.js');
require('../assets/engine/frameworks.js');

var OBOL = globalThis.OBOL, PK = OBOL.pack, FW = OBOL.frameworks;
var VERBOSE = process.argv.indexOf('--verbose') >= 0;
var cat = OBOL.ATTACK.techniques, byKind = OBOL.ATTACK_MOVE.byKind, byMove = OBOL.ATTACK_MOVE.byMove;

// load the live pack the same way the app and the other sims do
var pdir = path.join(__dirname, '..', 'data', 'packs');
var PACK = PK.loadPacks(fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); })
  .map(function (f) { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } }));
var moveById = {}; PACK.forEach(function (a) { moveById[a.id] = a; });
function nm(t) { return (cat[t] || {}).n || '?'; }
function parentOf(id) { return String(id).indexOf('.') >= 0 ? String(id).split('.')[0] : String(id); }

var errors = [];   // integrity failures (gate)

// ── (1) integrity ───────────────────────────────────────────────────────────────────────────
Object.keys(byMove).forEach(function (id) {
  if (!moveById[id]) errors.push('BY_MOVE "' + id + '" -> ' + byMove[id] + ': no such move in the pack');
  if (!cat[byMove[id]]) errors.push('BY_MOVE "' + id + '" -> ' + byMove[id] + ': not an ATT&CK technique');
});
Object.keys(byKind).forEach(function (k) { if (!cat[byKind[k]]) errors.push('BY_KIND "' + k + '" -> ' + byKind[k] + ': not an ATT&CK technique'); });
var badFindAttack = {};
(OBOL.findingsCatalog || []).forEach(function (f) {
  if (!f.attack) return;
  String(f.attack).split(/[,\s]+/).filter(Boolean).forEach(function (t) { if (!cat[t]) badFindAttack[t] = (badFindAttack[t] || 0) + 1; });
});
Object.keys(badFindAttack).forEach(function (t) { errors.push('findings-catalog attack "' + t + '": not an ATT&CK technique (' + badFindAttack[t] + ' finding(s))'); });

// ── (2) coverage over obol's referenced techniques ───────────────────────────────────────────
var referenced = {};
function ref(t) { if (t && cat[t]) { referenced[t] = 1; referenced[parentOf(t)] = 1; } }
Object.keys(byKind).forEach(function (k) { ref(byKind[k]); });
Object.keys(byMove).forEach(function (id) { ref(byMove[id]); });
(OBOL.findingsCatalog || []).forEach(function (f) { if (f.attack) String(f.attack).split(/[,\s]+/).filter(Boolean).forEach(ref); });

var refList = Object.keys(referenced).sort();
var withEx = [], noEx = [];
refList.forEach(function (t) { (FW.exampleCommands(t, PACK, {}).length ? withEx : noEx).push(t); });

// ── (2b) inverse: moves that clearly PERFORM a technique (produce a win) but map to nothing ───
var WIN = /^(foothold|access|lateral|persistence)\.|^access\.(shell|admin|system|root)$/;
function mapsSomething(a) {
  if (byMove[a.id]) return true;
  return [].concat(a.produces || []).some(function (k) { return byKind[k]; });
}
function isAdvice(a) { return [].concat(a.produces || []).every(function (k) { return /^advice\./.test(k); }) && (a.produces || []).length > 0; }
var unmappedActs = PACK.filter(function (a) {
  if (mapsSomething(a) || isAdvice(a)) return false;
  var prod = [].concat(a.produces || []);
  return prod.some(function (k) { return WIN.test(k); });
}).map(function (a) { return a.id; }).sort();

// ── report ────────────────────────────────────────────────────────────────────────────────────
console.log('ATT&CK lineup coverage (ATT&CK v' + OBOL.ATTACK.version + ', ' + PACK.length + ' moves)\n');
console.log('INTEGRITY: ' + (errors.length ? (errors.length + ' FAILURE(S)') : 'clean'));
errors.forEach(function (e) { console.log('  x ' + e); });

console.log('\nCOVERAGE over ' + refList.length + ' referenced techniques:');
console.log('  ' + withEx.length + ' have a runnable example command');
console.log('  ' + noEx.length + ' have no example (parser-minted lead or a gap):');
noEx.forEach(function (t) { console.log('    - ' + t + '  ' + nm(t)); });

console.log('\nUNMAPPED ACTS (' + unmappedActs.length + '): pack moves that produce a win but map to no technique');
console.log('  (triage: add a BY_MOVE entry if the move performs a real ATT&CK technique)');
unmappedActs.forEach(function (id) {
  var a = moveById[id];
  console.log('    - ' + id + '  "' + (a.title || '') + '"  produces ' + JSON.stringify(a.produces || []));
});

if (VERBOSE) {
  console.log('\nREFERENCED TECHNIQUES (example status):');
  refList.forEach(function (t) {
    var ex = FW.exampleCommands(t, PACK, {});
    console.log('  ' + (ex.length ? '[cmd] ' : '[   ] ') + t + '  ' + nm(t) + (ex.length ? '  <- ' + ex.map(function (e) { return e.moveId; }).join(', ') : ''));
  });
}

console.log('\n' + (errors.length ? ('ATTACK-COVERAGE: ' + errors.length + ' integrity failure(s)') : 'ATTACK-COVERAGE: integrity clean'
  + ' (' + withEx.length + '/' + refList.length + ' referenced techniques have an example; ' + unmappedActs.length + ' unmapped acts to triage)'));
process.exit(errors.length ? 1 : 0);
