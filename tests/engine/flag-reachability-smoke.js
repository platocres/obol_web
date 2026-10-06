/* Flag reachability (tools/flag-paths.js): every by-port entry point must have a charted path to a
 * foothold, the user flag, and root — a disabled/neurodivergent user who lands on any port is never
 * stranded. This runs the real reachability tool (so it can never drift from the move graph) and also
 * checks the committed badge data (data/flag-reach.js) the decision tree renders is gap-free. */
'use strict';
var path = require('path'), cp = require('child_process');
var R = path.join(__dirname, '..', '..');
var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// 1) the live reachability check — exits non-zero if any entry cannot reach foothold/user-flag/root
var code = 0;
try { cp.execFileSync('node', [path.join(R, 'tools/flag-paths.js'), '--check'], { stdio: 'pipe' }); }
catch (e) { code = e.status || 1; console.error(String((e.stdout || '') + (e.stderr || '')).split('\n').filter(function (l) { return /GAP|cannot reach|FAIL/.test(l); }).join('\n')); }
ok(code === 0, 'tools/flag-paths.js --check: every by-port entry reaches foothold, user flag, and root');

// 2) the committed badge data the decision tree renders must exist and be gap-free on the floor metrics
var OBOL = globalThis.OBOL = globalThis.OBOL || {};
require(path.join(R, 'data/flag-reach.js'));
var reach = OBOL.FLAG_REACH || {};
var keys = Object.keys(reach);
ok(keys.length >= 30, 'flag-reach.js carries every by-port entry (' + keys.length + ')');
var bad = keys.filter(function (k) { return !(reach[k].foothold && reach[k].userFlag && reach[k].rootFlag); });
ok(bad.length === 0, 'flag-reach.js: no entry is stranded short of foothold/user-flag/root' + (bad.length ? ' — ' + bad.join(', ') : ''));
// domain control is tri-state: a boolean for AD entries, null for non-AD — never undefined
var illDomain = keys.filter(function (k) { return reach[k].domain === undefined; });
ok(illDomain.length === 0, 'flag-reach.js: domain-control attribute is present (bool for AD, null otherwise)');

console.log('\nFLAG REACHABILITY SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
