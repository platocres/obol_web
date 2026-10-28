/* Stage 7 flow-ordering smoke (corpus-free). The banked flow data (194 ranked walkthroughs) gives an
 * empirical precedence over coarse technique tags: every co-occurring pair is 100% consistent in direction,
 * and the strong chains are recon/web -> foothold -> privesc/pivot, and (for AD) domain creds -> roasting ->
 * DCSync. Stage 7 audits whether OBOL's move graph is faithful to that order. The finding: faithfulness is
 * enforced by eligibility GATES (requires_all / requires_any), not by phase labels, so a few moves whose
 * derived phase tag reads recon/enum (pivoting, the cred-producing SQLi variant, potato/token) are NOT a real
 * ordering fault; their gates hold them until the prerequisite fact exists. This locks that dynamically through
 * the real coach ranker (OBOL.pack.rankActions): a prerequisite-free state must NOT offer the gated families,
 * and the state that mints the gate fact MUST. No verbatim corpus output; the fact states are hand-built
 * (docs/CORPUS-MINING.md Principle 7). qa-only; nothing ships. House style: no em or en dashes. */
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
load(path.join(ROOT, 'data', 'packs-bundle.js'));

var OBOL = ctx.OBOL;
var pack = OBOL.packs.actions();
var SCOPE = 'host:10.10.10.98';

function state(kinds) {
  return new OBOL.facts.FactSet(kinds.map(function (k) {
    return OBOL.facts.makeFact({ kind: k, scope: SCOPE, source: 'eng' });
  }));
}
function eligibleIds(facts) { return OBOL.pack.rankActions(facts, pack, {}).map(function (a) { return a.id; }); }
function present(list, set) { return list.filter(function (id) { return set.indexOf(id) >= 0; }); }

// Families whose derived phase tag reads early (recon/enum) but whose empirical place is post-prerequisite.
var PIVOT = ['ligolo-tunnel-pivot', 'pivot-chisel-socks', 'pivot-ligolo', 'pivot-sshuttle', 'pivot-ssh-dynamic',
  'pivot-scan-through', 'pivot-ssh-portforward', 'pivot-enumerate-neighbors', 'pivot-reach-listener', 'pivot-internal-dns'];
var LINPE = ['linux-enum', 'sudo-abuse', 'suid-gtfobins', 'cron-abuse', 'capabilities', 'linux-kernel-exploit', 'screen-suid-privesc'];
var POTATO = ['seimpersonate', 'potato-select'];

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// ---- INV1: a pre-foothold web-recon state offers NONE of the gated families ----
// Empirically recon/web precedes foothold, and foothold precedes privesc/pivot. The coarse phase tags on
// pivot/linpe/potato would (wrongly) place them at recon/enum; gates must keep them out with no foothold.
var A = eligibleIds(state(['target.configured', 'host.up', 'port:80', 'http.reachable', 'web.content_map', 'web.parameterized']));
ok(present(PIVOT, A).length === 0, 'pre-foothold web state offers no pivoting move (' + (present(PIVOT, A).join(',') || 'none') + ')');
ok(present(LINPE, A).length === 0, 'pre-foothold web state offers no linux-privesc move (' + (present(LINPE, A).join(',') || 'none') + ')');
ok(present(POTATO, A).length === 0, 'pre-foothold web state offers no potato/token move (' + (present(POTATO, A).join(',') || 'none') + ')');

// ---- INV2: a linux foothold unlocks linux-privesc and pivoting (the empirical successors) ----
var B = eligibleIds(state(['target.configured', 'host.up', 'foothold.linux', 'access.shell']));
ok(present(LINPE, B).length > 0, 'linux foothold unlocks a linux-privesc move (' + (present(LINPE, B).join(',') || 'NONE') + ')');
ok(present(PIVOT, B).length > 0, 'linux foothold unlocks a pivoting move (' + (present(PIVOT, B).join(',') || 'NONE') + ')');

// ---- INV3: a windows privilege token unlocks the potato/token path (and not before, per INV1) ----
var C = eligibleIds(state(['target.configured', 'host.up', 'foothold.windows', 'access.shell', 'privesc.windows_privilege']));
ok(present(POTATO, C).length > 0, 'windows privilege token unlocks a potato/token move (' + (present(POTATO, C).join(',') || 'NONE') + ')');

// ---- INV4: domain creds offer roasting and BloodHound but NOT DCSync (empirical roast -> DCSync) ----
var D = eligibleIds(state(['target.configured', 'host.up', 'credential.available', 'ad.domain_known', 'ad.user_list', 'kerberos.reachable', 'port:88']));
ok(present(['kerberoast', 'asrep-roast'], D).length > 0, 'domain creds offer a roasting move (' + (present(['kerberoast', 'asrep-roast'], D).join(',') || 'NONE') + ')');
ok(D.indexOf('bloodhound-collect') >= 0, 'domain creds offer bloodhound-collect');
ok(D.indexOf('dcsync') < 0, 'domain creds do NOT offer dcsync (it waits on admin / control paths)');

// ---- INV5: admin or AD control paths unlock DCSync (the empirical successor to roasting) ----
var E = eligibleIds(state(['target.configured', 'host.up', 'credential.available', 'ad.domain_known', 'access.admin', 'ad.control_paths']));
ok(E.indexOf('dcsync') >= 0, 'admin / control paths unlock dcsync');

console.log('\nSTAGE 7 FLOW-ORDERING SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
