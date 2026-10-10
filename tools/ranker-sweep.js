/*!
 * tools/ranker-sweep.js, the BROAD ranking sweep (fuzzer).
 *
 * Where ranker-sim.js is the curated 42-state scoreboard, this casts a wide net: many realistic
 * archetypes x stages, thousands of randomly-sampled port-sets x stages x injected findings, and
 * pairwise port co-occurrence coverage. It runs the REAL ranker over every state, judges the top
 * moves with ranker-sim's SAME rubric (no drift), and CLUSTERS the violations by (principle + top
 * move) so the output is "N distinct issue patterns," not a wall of flagged states. Read-only.
 *
 * Run: node tools/ranker-sweep.js [--n 4000] [--seed 1] [--show 3]
 *   --n     random samples (default 4000)     --seed  PRNG seed (default 1, reproducible)
 *   --show  exemplars per cluster (default 2)
 */
'use strict';
var sim = require('./ranker-sim.js');
var OBOL = sim.OBOL, PK = sim.PK, S = sim.S, PACK = sim.PACK, judge = sim.judge, stageFacts = sim.stageFacts;

function argv(flag, dflt) { var i = process.argv.indexOf(flag); return i >= 0 ? process.argv[i + 1] : dflt; }
var N = parseInt(argv('--n', '4000'), 10), SHOW = parseInt(argv('--show', '2'), 10);
var SEED = parseInt(argv('--seed', '1'), 10);
function mulberry32(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; var t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
var rnd = mulberry32(SEED);
function pick(arr) { return arr[Math.floor(rnd() * arr.length)]; }
function sample(arr, k) { var c = arr.slice(), out = []; while (out.length < k && c.length) out.push(c.splice(Math.floor(rnd() * c.length), 1)[0]); return out; }

// ── port themes (realistic co-occurrence) ───────────────────────────────────────────────────────
var THEMES = {
  web: [80, 443, 8080, 8443],
  ad: [53, 88, 135, 139, 389, 445, 464, 636, 3268, 5985, 9389],
  windows_svc: [135, 139, 445, 3389, 5985],
  linux_svc: [21, 22, 53, 111, 2049],
  db: [1433, 3306, 5432, 6379, 9200, 27017],
  mail: [25, 110, 143, 587, 993, 995],
};
var ALL_PORTS = (OBOL.STUCK_PORTS || []).map(function (p) { return p.port; });
var STAGES = sim.STAGES;

function synthArch(ports) {
  var set = {}; ports.forEach(function (p) { set[p] = 1; });
  var ad = [88, 389, 636, 3268, 464, 9389].some(function (p) { return set[p]; });
  var winish = ad || [445, 139, 135, 3389, 5985].some(function (p) { return set[p]; });
  var linuxish = [22, 21, 2049, 111].some(function (p) { return set[p]; }) || set[80] || set[3306];
  var os = winish && !(!ad && linuxish && !set[445]) ? 'windows' : (linuxish ? 'linux' : 'linux');
  if (ad) os = 'windows';
  return { os: os, ad: ad };
}

// optional finding injections (safe facts a box might have), to probe deeper states
var FINDINGS = ['web.content_map', 'web.param_candidate', 'web.sqli_confirmed', 'smb.null_session', 'ad.user_list',
  'ad.domain_known', 'ad.base_dn', 'privesc.sudo_rights', 'privesc.suid_candidate', 'hash.ntlm', 'hash.asrep',
  'credential.candidate', 'loot.files', 'host.multihomed', 'web.users', 'smb.shares'];

// Injections must be REALISTIC: a fact can only appear if the state could actually produce it. Dropping
// privesc.* onto a box with no foothold, or smb.* onto a box with no SMB port, invents impossible states
// and flags the ranker for doing the right thing with facts that could never co-exist. Only inject a
// finding whose preconditions the state already meets.
function canInject(sb, kind) {
  if (/^web\./.test(kind)) return sb.has('http.reachable');
  if (/^smb\./.test(kind)) return sb.has('smb.reachable');
  if (/^(ad|kerberos|ldap)\./.test(kind) || /^hash\.(krbtgt|ntlm|asrep|tgs|mscache)/.test(kind)) return sb.has('ldap.reachable') || sb.has('kerberos.reachable') || sb.has('smb.reachable');
  if (/^privesc\./.test(kind)) return sb.has('access.shell') || sb.has('foothold.linux') || sb.has('foothold.windows');
  if (/^loot\./.test(kind)) return sb.has('access.shell') || sb.has('access.admin') || sb.has('smb.authenticated') || sb.has('smb.null_session');
  if (kind === 'host.multihomed') return sb.has('access.shell') || sb.has('foothold.linux') || sb.has('foothold.windows');
  return true; // credential.candidate, web.users, etc. can plausibly turn up broadly
}
function stateFrom(ports, stage, inject, tag) {
  var arch = synthArch(ports);
  var sb = S.sandbox();
  S.assert(sb, 'host.up', { scope: 'host:t' });
  ports.forEach(function (p) { if (ALL_PORTS.indexOf(p) >= 0) S.togglePort(sb, p, 'host:t'); else S.assert(sb, 'port:' + p, { scope: 'host:t' }); });
  stageFacts(arch, stage).forEach(function (k) { S.assert(sb, k, { scope: 'host:t' }); });
  (inject || []).forEach(function (k) { if (canInject(sb, k)) S.assert(sb, k, { scope: 'host:t' }); });
  return { sb: sb, arch: arch, archKey: tag || (arch.ad ? 'ad' : arch.os), stage: stage, ports: ports };
}

// ── build the state space ────────────────────────────────────────────────────────────────────
var states = [];

// (1) structured: every theme as a whole box, and theme-pairs, across every stage
var themeKeys = Object.keys(THEMES);
themeKeys.forEach(function (t) { STAGES.forEach(function (st) { states.push(stateFrom(THEMES[t], st, [], t)); }); });
for (var i = 0; i < themeKeys.length; i++) for (var j = i + 1; j < themeKeys.length; j++) {
  var combo = THEMES[themeKeys[i]].concat(THEMES[themeKeys[j]]);
  STAGES.forEach(function (st) { states.push(stateFrom(combo, st, [], themeKeys[i] + '+' + themeKeys[j])); });
}

// (2) pairwise port coverage: every pair of "interesting" ports as a 2-port box at recon + versioned
var INTERESTING = [21, 22, 25, 53, 80, 88, 110, 135, 139, 389, 443, 445, 464, 636, 1433, 2049, 3268, 3306, 3389, 5432, 5985, 6379, 8080, 9200];
for (var a = 0; a < INTERESTING.length; a++) for (var b = a + 1; b < INTERESTING.length; b++) {
  states.push(stateFrom([INTERESTING[a], INTERESTING[b]], 'recon_ports', [], 'pair'));
  states.push(stateFrom([INTERESTING[a], INTERESTING[b]], 'recon_versioned', [], 'pair'));
}

// (3) random fuzz: themed port-sets (1-2 themes) + a random extra port, random stage, 0-2 injected findings
var structuredN = states.length;
for (var r = 0; r < N; r++) {
  var nThemes = 1 + (rnd() < 0.4 ? 1 : 0);
  var ports = [];
  sample(themeKeys, nThemes).forEach(function (t) { sample(THEMES[t], 1 + Math.floor(rnd() * THEMES[t].length)).forEach(function (p) { if (ports.indexOf(p) < 0) ports.push(p); }); });
  if (rnd() < 0.3) { var ex = pick(ALL_PORTS); if (ports.indexOf(ex) < 0) ports.push(ex); }
  if (!ports.length) ports = sample(INTERESTING, 2);
  var stage = pick(STAGES);
  var inject = rnd() < 0.5 ? sample(FINDINGS, 1 + Math.floor(rnd() * 2)) : [];
  states.push(stateFrom(ports, stage, inject, 'fuzz'));
}

// ── run + cluster ────────────────────────────────────────────────────────────────────────────
var clusters = {}, byPrinciple = {}, dirty = 0;
states.forEach(function (state) {
  var ranked = PK.rankActions(state.sb, PACK);
  var vios = judge(state, ranked);
  if (vios.length) dirty++;
  vios.forEach(function (x) {
    byPrinciple[x.p] = (byPrinciple[x.p] || 0) + 1;
    var top1 = ranked[0] ? ranked[0].id : '(none)';
    var key = x.p + '  ::  #1=' + top1;
    var cl = clusters[key] = clusters[key] || { key: key, principle: x.p, count: 0, exemplars: [] };
    cl.count++;
    if (cl.exemplars.length < SHOW) cl.exemplars.push({ arch: state.archKey + '/' + state.stage, ports: state.ports.slice().sort(function (a, b) { return a - b; }).join(','), top: ranked.slice(0, 5).map(function (m) { return m.id; }).join(' > '), detail: x.detail });
  });
});

console.log('RANKING SWEEP');
console.log('  states: ' + states.length + ' (' + structuredN + ' structured + ' + N + ' random, seed ' + SEED + ')');
console.log('  states with >=1 violation: ' + dirty + ' (' + (100 * dirty / states.length).toFixed(1) + '%)\n');
console.log('VIOLATIONS BY PRINCIPLE');
Object.keys(byPrinciple).sort(function (x, y) { return byPrinciple[y] - byPrinciple[x]; }).forEach(function (p) { console.log('  ' + String(byPrinciple[p]).padStart(5) + '  ' + p); });
if (!Object.keys(byPrinciple).length) console.log('  (none, clean sweep)');

console.log('\nDISTINCT CLUSTERS (' + Object.keys(clusters).length + ')  [principle :: the move that led]');
Object.keys(clusters).map(function (k) { return clusters[k]; }).sort(function (x, y) { return y.count - x.count; }).forEach(function (cl) {
  console.log('\n  [' + cl.count + ']  ' + cl.key);
  cl.exemplars.forEach(function (e) { console.log('        ' + e.arch + '  ports:' + e.ports + '\n           ' + e.detail + '\n           top: ' + e.top); });
});
