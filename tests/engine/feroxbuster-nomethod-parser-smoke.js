/* feroxbuster plain-text content-discovery parser (corpus-mined, output axis):
 *  feroxbuster prints one result row per discovered path. Newer builds carry a method column
 *  ("200  GET  6l  77w  3351c  http://host/x"); older/default output omits it
 *  ("301  9l  28w  313c  http://host/x"). The product's ingest keeps the "feroxbuster -u ..."
 *  command, which is what the dispatcher routes on, so both shapes must feed the existing
 *  web.content_map fact (the content catalogue, already consumed by downstream web moves).
 *  404 rows carry no live surface and must be dropped; the scan progress bars
 *  ("[####] - 1m 299990/299990 ... found:11 errors:0") and a banner-only paste with no result
 *  rows must mint nothing. Shapes are hand-built, not copied from any walkthrough. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack;
var fs = require('fs'), pdir = path.join(R, 'data/packs'), bundle = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); });
var A = PK.loadPacks(Object.keys(bundle).map(function (k) { return bundle[k]; }));
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function facts(cmd, out) { var r = OBOL.parsers.parseActionOutput({ actionId: '', command: cmd, stdout: out, scope: 'host:10.10.10.244', domain: '' }); return (r.facts || []); }
function contentMap(cmd, out) { return facts(cmd, out).filter(function (f) { return f.kind === 'web.content_map'; })[0] || null; }
function has(arr, v) { return (arr || []).map(function (x) { return x.toLowerCase(); }).indexOf(v.toLowerCase()) >= 0; }

var FEROX_CMD = 'feroxbuster -u http://10.10.10.244';

// --- No-method shape (older / default feroxbuster output): status, counts, URL, no method column. ---
var noMethod =
  '301        9l       28w      313c http://10.10.10.244/assets\n' +
  '403        9l       28w      277c http://10.10.10.244/server-status\n' +
  '200        1l        1w        8c http://10.10.10.244/nic/update\n' +
  '404        9l       28w      169c http://10.10.10.244/nothing-here\n' +
  '[####################] - 1m    299990/299990  0s      found:11      errors:0\n' +
  '[####################] - 18s    29999/29999   1626/s  http://10.10.10.244/assets';
var nm = contentMap(FEROX_CMD, noMethod);
ok(nm && has(nm.value.paths, '/assets'), 'no-method feroxbuster row (301) feeds web.content_map');
ok(nm && has(nm.value.paths, '/server-status') && has(nm.value.paths, '/nic/update'), 'no-method rows for 403 and 200 are both captured');
ok(nm && !has(nm.value.paths, '/nothing-here'), 'a 404 row is dropped from the content map');
ok(nm && !nm.value.paths.some(function (p) { return /^\d/.test(p) || /^\[|errors:|found:/.test(p); }), 'scan progress bars do not leak junk tokens into the path set');

// --- Method-column shape (newer feroxbuster) still parses: no regression, and the redirect arrow
//     records the source path, not the "=> target" it points at. ---
var withMethod =
  '200      GET        6l       77w     3351c http://10.10.10.244/css/owl.css\n' +
  '301      GET        2l       10w      150c http://10.10.10.244/images => http://10.10.10.244/images/\n' +
  '404      GET        9l       28w      169c http://10.10.10.244/missing.php';
var wm = contentMap(FEROX_CMD, withMethod);
ok(wm && has(wm.value.paths, '/css/owl.css'), 'GET-method feroxbuster row still feeds web.content_map (no regression)');
ok(wm && has(wm.value.paths, '/images'), 'a 301 redirect row records the source path');
ok(wm && !has(wm.value.paths, '/missing.php'), 'a 404 GET-method row is dropped');

// --- No false positives: a banner / config-only paste (0xdf often snips the result rows) mints nothing. ---
var bannerOnly =
  '     ___  ___  __   __     __      __         __   ___\n' +
  '    |__  |__  |__) |__) | /  `    /  \\ \\_/ | |  \\ |__\n' +
  '    by Ben "epi" Risher                 ver: 2.2.1\n' +
  ' Target Url            | http://10.10.10.244\n' +
  ' Threads               | 50\n' +
  ' Status Codes          | [200, 204, 301, 302, 307, 308, 401, 403, 405]\n' +
  ' Press [ENTER] to use the Scan Cancel Menu';
ok(!contentMap(FEROX_CMD, bannerOnly), 'a banner / config-only feroxbuster paste with no result rows mints no web.content_map');

// --- The minted fact has a live downstream consumer (the loop advances). ---
var consumers = A.filter(function (m) { return [].concat(m.requires_all || [], m.requires_any || []).indexOf('web.content_map') >= 0; });
ok(consumers.length >= 1, 'web.content_map drives at least one downstream move (' + consumers.length + ')');

console.log('\nFEROXBUSTER NO-METHOD PARSER SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
