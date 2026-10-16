/* fact-canon-smoke.js — the TA canonical-fact migration, locked in as a regression guard.
 *
 * The post-parse-advance auditor (tools/post-parse-audit.js) surfaced that several RCE/privesc moves
 * produced NON-CANONICAL progress facts (foothold.shell, access.root, credential.plain) that no parser
 * reads and nothing consumes, so a real shell/root/cred paste minted nothing and the move could not
 * advance. The fix normalized them to the canonical foothold.linux / access.admin / credential.plaintext.
 * This test pins that: the old names can never return, the canonical names stay parser-readable, the
 * four switchless probes keep their settled_by, and admin-producing privesc moves still RETIRE once
 * access.admin is held (the round-trip the migration protects).
 */
'use strict';
var fs = require('fs'), path = require('path');
var ROOT = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(ROOT, p)); }

req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
req('assets/engine/loot.js'); req('data/parser-signatures.js');
var OBOL = globalThis.OBOL;

var pdir = path.join(ROOT, 'data/packs'), bundle = [];
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); })
  .forEach(function (f) { bundle.push(JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8'))); });
var A = OBOL.pack.loadPacks(bundle);
OBOL.packs = { actions: function () { return A; }, packData: function () { return {}; } };

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// 1) the three migrated names are gone from every edge of every move (produces/requires/obsoleted/depri).
var OLD = ['foothold.shell', 'access.root', 'credential.plain'];
var stray = [];
A.forEach(function (m) {
  (m.produces || []).concat(m.requires_all || [], m.requires_any || [], m.obsoleted_by || [], m.deprioritize_when || [])
    .forEach(function (f) { if (OLD.indexOf(f) >= 0) stray.push(m.id + ':' + f); });
});
ok(stray.length === 0, 'no move uses a non-canonical fact name (' + (stray.join(', ') || 'clean') + ')');

// 2) the canonical progress facts are all parser-readable (a parser can actually mint them from a paste).
var SIG = OBOL.PARSER_SIGNATURES || {}, EMITS = {};
Object.keys(SIG).forEach(function (k) { (SIG[k].emits || []).forEach(function (e) { EMITS[e] = true; }); });
function reads(f) { return !!EMITS[f] || Object.keys(EMITS).some(function (e) { return e.slice(-1) === '.' && f.indexOf(e) === 0; }); }
['foothold.linux', 'foothold.windows', 'access.admin', 'access.shell', 'credential.plaintext'].forEach(function (f) {
  ok(reads(f), 'canonical fact is parser-readable: ' + f);
});

// 3) the four switchless probes retire on their proof (settled_by present and non-empty).
var PROBES = { 'ad-dc-identify': 0, 'recon-ftp': [0, 1], 'recon-smb-anon': 2 };
Object.keys(PROBES).forEach(function (id) {
  var m = A.filter(function (x) { return x.id === id; })[0];
  ok(m, 'probe move exists: ' + id);
  if (!m) return;
  [].concat(PROBES[id]).forEach(function (i) {
    var c = (m.commands || [])[i];
    ok(c && c.settled_by && c.settled_by.length, id + '[' + i + '] has settled_by (' + (c && (c.settled_by || []).join(',')) + ')');
  });
});

// 4) round-trip: admin-producing Linux privesc moves RETIRE once access.admin is held (global phase
//    logic, not per-move obsoleted_by). A migrated fact that nothing retired on would be the real bug.
function mkfs(kinds) { var s = new OBOL.facts.FactSet(); kinds.forEach(function (k) { s.add(OBOL.facts.makeFact({ kind: k, scope: 'target', value: 'x' })); }); return s; }
var PRIVESC = ['suid-gtfobins', 'sudo-abuse', 'cron-abuse', 'capabilities', 'docker-socket', 'dirtycow', 'linux-kernel-exploit'];
var pre = mkfs(['foothold.linux', 'service.ssh', 'scan.nmap.version']);
var preIds = OBOL.pack.rankActions(pre, A, {}).map(function (a) { return a.id; });
ok(PRIVESC.some(function (id) { return preIds.indexOf(id) >= 0; }), 'pre-admin: at least one privesc move is eligible');
var post = mkfs(['foothold.linux', 'service.ssh', 'scan.nmap.version', 'access.admin']);
var postIds = OBOL.pack.rankActions(post, A, {}).map(function (a) { return a.id; });
var lingering = PRIVESC.filter(function (id) { return postIds.indexOf(id) >= 0; });
ok(lingering.length === 0, 'post-admin: every admin-producing privesc move retired (' + (lingering.join(', ') || 'all retired') + ')');

if (fail) { console.error('fact-canon-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('fact-canon-smoke: OK');
