/* toolkit-smoke.js — OBOL.toolkit (recipes + glossary + stations) and the recipe<->builder contract.
 *
 * Guards the TB foundations: every recipe targets REAL field ids and compiles to a clean command (no
 * token leak, no "undefined", starts with the right binary); applying a recipe makes it the matching
 * recipe (Option B round-trip); the glossary resolves the flags in a command; and the stations resolve
 * to built engines, carry shared params across an engine swap, and pick a fact-aware default.
 */
'use strict';
var fs = require('fs'), path = require('path');
var ROOT = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(ROOT, p)); }

req('assets/engine/toolbuilder.js');
req('data/toolset.js');
req('data/tool-recipes.js');
req('data/tool-glossary.js');
req('data/tool-stations.js');
req('assets/engine/toolkit.js');
var OBOL = globalThis.OBOL, TB = OBOL.toolbuilder, TK = OBOL.toolkit;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

var byId = {}; OBOL.TOOLSET.forEach(function (b) { byId[b.id] = b; });
// a context that supplies the engagement-bound inputs the binding component would fill.
var CTX = { target: { value: '10.10.10.10', ip: '10.10.10.10' }, context: { domain: 'corp.local' }, workspace: { outputDir: 'loot', wordlist: '/usr/share/wordlists/rockyou.txt', hashfile: 'hashes.txt' } };
// placeholders for required inputs a recipe never sets (the operator / binding supplies them).
var FILL = { url: 'http://10.10.10.10', target: '10.10.10.10', hashOrFile: 'hashes.txt', hashFile: 'hashes.txt', mask: '?a?a?a' };

// ---- recipes ----
Object.keys(OBOL.TOOL_RECIPES).forEach(function (bid) {
  var b = byId[bid];
  ok(b, 'recipe builder exists: ' + bid);
  if (!b) return;
  var fieldIds = {}; (b.fields || []).forEach(function (f) { fieldIds[f.id] = f; });
  var recipes = TK.recipesFor(bid);
  ok(recipes.length > 0, bid + ' has recipes (' + recipes.length + ')');
  recipes.forEach(function (r) {
    // every value key is a real field id
    var bad = Object.keys(r.values || {}).filter(function (k) { return !fieldIds[k]; });
    ok(bad.length === 0, bid + '/' + r.id + ' targets only real fields' + (bad.length ? ' (BAD: ' + bad.join(',') + ')' : ''));
    // phase + hint present (funnel needs them)
    ok(r.label && r.hint && r.phase, bid + '/' + r.id + ' has label+hint+phase');
    // applyRecipe -> compiles cleanly once required inputs are present
    var vals = TK.applyRecipe(b, r, CTX);
    Object.keys(FILL).forEach(function (k) { if (fieldIds[k] && (vals[k] === undefined || vals[k] === '')) vals[k] = FILL[k]; });
    var missing = TB.validateRequired(b, TB.normalizeValues(b, vals, CTX));
    ok(missing.length === 0, bid + '/' + r.id + ' has no missing required fields' + (missing.length ? ' (' + missing.join(',') + ')' : ''));
    var cmd = '';
    try { cmd = TB.compile(b, vals, CTX); } catch (e) { cmd = 'ERR:' + e.message; }
    ok(cmd.indexOf('ERR:') !== 0, bid + '/' + r.id + ' compiles');
    ok(!/\{\{|\bundefined\b|\[object/.test(cmd), bid + '/' + r.id + ' command is clean (no token leak / undefined)');
    // applying the recipe makes it the matching recipe (Option B bidirectional round-trip)
    ok(TK.matchingRecipe(b, TK.applyRecipe(b, r, CTX)) === r.id, bid + '/' + r.id + ' round-trips to matchingRecipe');
  });
});

// ---- glossary ----
(function () {
  var ffuf = TK.glossCommand('ffuf -u http://x/FUZZ -w list.txt -mc 200,301 -ac -t 40', byId['tb-ffuf']);
  var flags = ffuf.map(function (g) { return g.flag; });
  ok(['-u', '-w', '-mc', '-ac', '-t'].every(function (f) { return flags.indexOf(f) >= 0; }), 'ffuf gloss covers -u -w -mc -ac -t (' + flags.join(' ') + ')');
  var nmap = TK.glossCommand('nmap -Pn -sC -sV -p 80,443 10.10.10.10', byId['tb-nmap']).map(function (g) { return g.flag; });
  ok(['-Pn', '-sC', '-sV', '-p'].every(function (f) { return nmap.indexOf(f) >= 0; }), 'nmap gloss covers -Pn -sC -sV -p (' + nmap.join(' ') + ')');
  var john = TK.glossCommand('john --format=krb5asrep --wordlist=rockyou.txt hash.txt', byId['tb-john']).map(function (g) { return g.flag; });
  ok(john.indexOf('--format') >= 0 && john.indexOf('--wordlist') >= 0, 'john gloss handles --flag=value (' + john.join(' ') + ')');
  var gob = TK.glossCommand('gobuster dir -u http://x -w w.txt -x php', byId['tb-gobuster-ferox']).map(function (g) { return g.flag; });
  ok(gob.indexOf('dir') >= 0 && gob.indexOf('-u') >= 0, 'gobuster gloss recognizes the subcommand word (' + gob.join(' ') + ')');
  // a quoted header stays one token (its inner spaces are not read as flags)
  var hdr = TK.glossCommand('ffuf -u http://x -H "User-Agent: Mozilla/5.0" -w w', byId['tb-ffuf']);
  ok(hdr.filter(function (g) { return g.flag === '-H'; }).length === 1, 'quoted -H value is one token');
})();

// ---- stations ----
(function () {
  var web = TK.stationById('web-content');
  ok(web && TK.stationBuilders(web).length === 3, 'web-content resolves 3 built engines');
  var ps = TK.stationById('port-scan');
  ok(ps && TK.stationBuilders(ps).length === 1, 'port-scan resolves only nmap now (rustscan/masscan skipped until TC)');
  var carried = TK.carryShared(web, web.engines[0], web.engines[1], { wordlist: 'x.txt', extensions: 'php', url: 'http://x' });
  ok(carried.wordlist === 'x.txt' && carried.extensions === 'php', 'carryShared moves wordlist+extensions across an engine swap');
  ok(TK.defaultEngine(web, []) === 'tb-ffuf', 'web-content default engine is ffuf');
  // every station default engine must be a built engine
  TK.stations().forEach(function (s) {
    var built = {}; TK.stationBuilders(s).forEach(function (e) { built[e.builder.id] = 1; });
    ok(built[s.defaultEngine], s.id + ' default engine ' + s.defaultEngine + ' is built');
  });
})();

if (fail) { console.error('toolkit-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('toolkit-smoke: OK');
