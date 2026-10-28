/* Stage 6 fact-handling smoke (corpus-free). The Stage 5 parser fixes made two facts reliable from
 * NEW output shapes: http.reachable from a returned HTTP response body (services.js _parse_http_metadata)
 * and loot.files from an interactive FTP directory listing (services.js _parse_ftp_output). Stage 6 is the
 * fact-handling pass: a success must drive a downstream follow-up. This asserts that minting each fact from
 * its new shape and running the real coach ranker (OBOL.pack.rankActions) surfaces a sensible next move:
 *   - http.reachable  -> a web-enumeration lead (recon-web-triage / content-discovery) ranks near the top,
 *   - loot.files      -> a loot-triage consumer ranks near the top, and for a listed .mdb the Access DB
 *                        export move leads (the correct 0xdf Access follow-up).
 * This locks the downstream half of the Stage 5 work (the mint half is covered by http-reachable-body-smoke
 * and ftp-listing-loot-smoke); post-parse-audit.js --check holds the graph-level guarantee across all moves.
 * Hand-built shapes, no verbatim corpus output (docs/CORPUS-MINING.md Principle 7). qa-only; nothing ships.
 * House style: no em or en dashes. */
'use strict';
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.join(__dirname, '..', '..');
var ENG = path.join(ROOT, 'assets', 'engine');
var ctx = { console: console, Date: Date, Math: Math, Array: Array, Object: Object, String: String,
  Number: Number, RegExp: RegExp, Set: Set, Map: Map, JSON: JSON };
ctx.globalThis = ctx; ctx.window = ctx;
vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
['facts.js', 'phases.js', 'pack.js', 'packs.js', 'command.js', 'workspace.js', 'profile.js', 'loot.js'].forEach(function (f) { load(path.join(ENG, f)); });
load(path.join(ENG, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { load(path.join(ENG, 'parsers', m + '.js')); });
load(path.join(ENG, 'parsers', 'index.js'));
load(path.join(ROOT, 'data', 'packs-bundle.js'));

var OBOL = ctx.OBOL;
var pack = OBOL.packs.actions();
var TGT = '10.10.10.98', SCOPE = 'host:' + TGT;

function freshFacts() { return new OBOL.facts.FactSet([ OBOL.facts.makeFact({ kind: 'target.configured', scope: SCOPE, source: 'eng' }) ]); }
function ingest(facts, command, stdout) {
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: command, stdout: stdout, source: 'sim', scope: SCOPE, target: TGT, domain: '' });
  var minted = {};
  (r.facts || []).forEach(function (f) { if (facts.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) minted[f.kind] = 1; });
  return minted;
}
function rankedIds(facts) { return OBOL.pack.rankActions(facts, pack, {}).map(function (a) { return a.id; }); }
function consumers(kind) {
  return pack.filter(function (a) {
    return (a.requires_any || []).indexOf(kind) >= 0 || (a.requires_all || []).indexOf(kind) >= 0;
  }).map(function (a) { return a.id; });
}

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// ---- http.reachable from a returned response body (Stage 5 fix b) drives web enumeration ----
var fHttp = freshFacts();
var mintedHttp = ingest(fHttp, 'proxychains curl -s http://10.10.10.98/',
  '[proxychains] Strict chain  ...  10.10.10.98:80  ...  OK\n<!DOCTYPE html>\n<html><head><title>Welcome</title></head><body>It works</body></html>\n');
ok(mintedHttp['http.reachable'], 'http.reachable minted from a proxychains response body');
var topH = rankedIds(fHttp).slice(0, 8);
ok(topH.indexOf('recon-web-triage') >= 0 || topH.indexOf('content-discovery') >= 0,
  'a web-enumeration lead ranks in the top 8 (recon-web-triage / content-discovery)');
ok(consumers('http.reachable').length > 0, 'http.reachable has pack consumers (' + consumers('http.reachable').length + ')');

// ---- loot.files from an ftp IIS listing (Stage 5 fix c) drives loot triage, Access DB export for .mdb ----
var fFtp = freshFacts();
var mintedFtp = ingest(fFtp, 'ls',
  '200 PORT command successful.\n125 Data connection already open; Transfer starting.\n08-23-18  09:16PM              5652480 backup.mdb\n08-23-18  08:51PM       <DIR>          Reports\n226 Transfer complete.');
ok(mintedFtp['loot.files'], 'loot.files minted from the ftp IIS listing');
var topF = rankedIds(fFtp).slice(0, 10);
var lootCons = consumers('loot.files');
ok(topF.some(function (id) { return lootCons.indexOf(id) >= 0; }),
  'a loot.files consumer ranks in the top 10');
ok(topF.indexOf('access-db-export') >= 0,
  'the Access DB export move leads for a listed .mdb (access-db-export in top 10)');
ok(lootCons.length > 0, 'loot.files has pack consumers (' + lootCons.length + ')');

console.log('\nSTAGE 6 FACT-FOLLOWUP SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
