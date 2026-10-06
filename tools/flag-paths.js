#!/usr/bin/env node
/*!
 * tools/flag-paths.js — the FLAG-REACHABILITY map (see docs/MOVE-ENGINE.md).
 *
 * The decision map is only as good as its worst path: a disabled/neurodivergent user who reaches a port
 * we cannot carry to the flag is stranded. This tool proves, for EVERY by-port entry point, that the
 * engine's own A* planner (OBOL.pack.planPath) can get from "recon found this port" to each milestone:
 *
 *   FOOTHOLD  — any shell / foothold on the box               (foothold.* / access.shell / webshell)
 *   USER-FLAG — the user flag is capturable                    (objective.flag)
 *   ROOT      — root / SYSTEM / local admin                    (access.root / access.system / access.admin)
 *   DOMAIN    — (AD entry points) domain controlled            (loot.ntds / own-domain-pth path)
 *
 * It seeds each entry with the facts recon yields for that port (port:N plus the service's reachable
 * fact), then plans to each milestone and prints the path or a *** GAP *** that names the milestone that
 * cannot be reached. Run with --paths to print the full move path for every entry.
 *
 * Run:  node tools/flag-paths.js              (table + gaps)
 *       node tools/flag-paths.js --paths      (also print each planned path)
 *       node tools/flag-paths.js --check      (exit 1 if any entry cannot reach FOOTHOLD, USER-FLAG or ROOT)
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

var argv = process.argv.slice(2), PATHS = argv.indexOf('--paths') >= 0, CHECK = argv.indexOf('--check') >= 0;

// The reachable fact(s) recon mints for a given TCP/UDP port — the same handoff the nmap parser does.
var PORT_REACH = {
  '21': ['ftp.reachable'], '22': ['ssh.reachable'], '23': ['telnet.reachable'], '25': ['smtp.reachable'],
  '53': ['dns.reachable'], '80': ['http.reachable'], '110': ['pop3.reachable'], '111': ['rpcbind.reachable'],
  '139': ['smb.reachable'], '143': ['imap.reachable'], '161': ['snmp.reachable'], '389': ['ldap.reachable'],
  '443': ['http.reachable'], '445': ['smb.reachable'], '636': ['ldap.reachable'], '873': ['rsync.reachable'],
  '1433': ['service.ms-sql-s'], '1521': ['oracle.reachable'], '2049': ['nfs.reachable'], '3268': ['ldap.reachable'],
  '3306': ['mysql.reachable'], '3389': ['rdp.reachable'], '5432': ['postgres.reachable'], '5900': ['vnc.reachable'],
  '5985': ['winrm.reachable'], '5986': ['winrm.reachable'], '88': ['kerberos.reachable'], '8080': ['http.reachable'],
  '8443': ['http.reachable'], '6379': ['redis.reachable'], '9200': ['http.reachable'], '11211': ['memcached.reachable'],
  '27017': ['mongo.reachable'], '8009': ['ajp.reachable'], '1099': ['service.java-rmi'], '10000': ['http.reachable'],
  '20000': ['http.reachable'], '6000': ['x11.reachable'], '500': ['ike.reachable'], '512': ['rservices.reachable'],
  '69': ['tftp.reachable'], '79': ['finger.reachable'], '1978': ['http.reachable'], '3000': ['aerospike.reachable'],
  '8000': ['http.reachable'], '8787': ['http.reachable'], '5005': ['http.reachable'], '8021': ['freeswitch.reachable'],
};
function seedFor(entry) {
  var seed = { 'target.configured': 1, 'host.up': 1, 'ports.open': 1, 'scan.nmap.quick': 1 };
  String(entry.port).split('/').forEach(function (p) {
    p = p.trim(); if (!/^\d+$/.test(p)) return;
    seed['port:' + p] = 1;
    (PORT_REACH[p] || []).forEach(function (r) { seed[r] = 1; });
  });
  // An AD DC advertises the trio; seed all three reachable facts for the AD-family entries so the plan
  // can open the directory lane exactly as recon would.
  if (entry.fam === 'ad') { seed['smb.reachable'] = 1; seed['ldap.reachable'] = 1; seed['kerberos.reachable'] = 1; seed['port:445'] = 1; seed['port:389'] = 1; seed['port:88'] = 1; }
  return seed;
}
// Forward reachability fixpoint over the move graph (fast, and terminates on unreachable goals, unlike
// A* with its expansion cap). Mirrors planPath's gating: requires_all all held, at least one
// requires_any held, OS-compatible with the family the plan has committed to. Records the move that
// first produced each fact so a representative path can be reconstructed.
function osFamOf(have) {
  if (have['foothold.windows'] || have['winrm.authenticated'] || have['rdp.authenticated']) return 'windows';
  if (have['foothold.linux']) return 'linux';
  return '';
}
function osOk(a, fam) {
  var al = a.os || []; if (!al.length || !fam) return true;
  for (var j = 0; j < al.length; j++) if (PK.normalizeOsName(al[j]) === fam) return true;
  return false;
}
function reachClosure(seed) {
  var have = {}, firstMove = {}, k; for (k in seed) have[k] = 1;
  var changed = true;
  while (changed) {
    changed = false; var fam = osFamOf(have);
    for (var i = 0; i < A.length; i++) {
      var a = A[i];
      if (!osOk(a, fam)) continue;
      var all = a.requires_all || [], any = a.requires_any || [], ok = true, j;
      for (j = 0; j < all.length; j++) if (!have[all[j]]) { ok = false; break; }
      if (ok && any.length) { ok = false; for (j = 0; j < any.length; j++) if (have[any[j]]) { ok = true; break; } }
      if (!ok) continue;
      var prod = a.produces || [], added = false;
      for (j = 0; j < prod.length; j++) if (!have[prod[j]]) { have[prod[j]] = 1; if (!firstMove[prod[j]]) firstMove[prod[j]] = a.id; added = true; changed = true; }
      if (added) fam = osFamOf(have);
    }
  }
  return { have: have, firstMove: firstMove };
}
var byId = {}; A.forEach(function (a) { byId[a.id] = a; });
function pathToFact(fact, clo, seed, seen) {
  seen = seen || {}; if (seed[fact] || seen[fact]) return []; seen[fact] = 1;
  var mid = clo.firstMove[fact]; if (!mid) return [];
  var a = byId[mid], out = [];
  (a.requires_all || []).forEach(function (r) { pathToFact(r, clo, seed, seen).forEach(function (x) { if (out.indexOf(x) < 0) out.push(x); }); });
  var any = a.requires_any || [];
  for (var j = 0; j < any.length; j++) { if (clo.have[any[j]]) { pathToFact(any[j], clo, seed, seen).forEach(function (x) { if (out.indexOf(x) < 0) out.push(x); }); break; } }
  if (out.indexOf(mid) < 0) out.push(mid);
  return out;
}
function plan(seed, goals) {
  var clo = reachClosure(seed);
  for (var i = 0; i < goals.length; i++) if (clo.have[goals[i]]) { return { reachable: true, path: pathToFact(goals[i], clo, seed), goal: goals[i] }; }
  return { reachable: false, path: null };
}

var MILES = [
  { key: 'FOOTHOLD', goals: ['foothold.linux', 'foothold.windows', 'access.shell', 'foothold.webshell', 'access.desktop'] },
  { key: 'USER-FLAG', goals: ['objective.flag', 'objective.local_flag'] },
  { key: 'ROOT', goals: ['access.root', 'access.system', 'access.admin'] },
];
var DOMAIN = { key: 'DOMAIN', goals: ['loot.ntds', 'access.admin', 'persistence.domain'] };

var S = OBOL.study, ev = S.evidence().filter(function (e) { return e.tier === 'ports'; });
var gaps = [], rows = [];
ev.forEach(function (e) {
  var seed = seedFor(e), row = { key: e.key, port: e.port, label: e.label, fam: e.fam, res: {} };
  MILES.forEach(function (mil) {
    var r = plan(seed, mil.goals);
    row.res[mil.key] = r;
    if (!r.reachable) gaps.push({ port: e.port, label: e.label, milestone: mil.key });
  });
  if (e.fam === 'ad') { row.res.DOMAIN = plan(seed, DOMAIN.goals); }
  rows.push(row);
});

function mark(r) { return r && r.reachable ? ('ok(' + r.path.length + ')') : 'GAP'; }
console.log('FLAG-REACHABILITY MAP — ' + ev.length + ' by-port entry points, ' + A.length + ' moves\n');
console.log(['PORT'.padEnd(16), 'FOOTHOLD'.padEnd(10), 'USER-FLAG'.padEnd(11), 'ROOT'.padEnd(10), 'DOMAIN'].join(' '));
rows.forEach(function (row) {
  console.log([String(row.port).padEnd(16), mark(row.res.FOOTHOLD).padEnd(10), mark(row.res['USER-FLAG']).padEnd(11), mark(row.res.ROOT).padEnd(10), (row.res.DOMAIN ? mark(row.res.DOMAIN) : '-')].join(' '));
  if (PATHS) {
    ['FOOTHOLD', 'USER-FLAG', 'ROOT', 'DOMAIN'].forEach(function (key) {
      var r = row.res[key]; if (!r) return;
      console.log('    ' + key + ': ' + (r.reachable ? r.path.join(' → ') : '*** NO PATH ***'));
    });
  }
});

console.log('\n' + gaps.length + ' reachability gap(s)');
gaps.forEach(function (g) { console.log('  ' + String(g.port).padEnd(16) + ' cannot reach ' + g.milestone + '  (' + g.label + ')'); });
if (CHECK && gaps.length) { console.error('\nFLAG-PATHS CHECK FAIL: ' + gaps.length + ' entry/milestone pair(s) cannot reach the flag.'); process.exit(1); }
console.log(gaps.length ? '' : '\nFLAG PATHS OK: every by-port entry reaches a foothold, the user flag, and root.');

// --robust: fragility lens. For each port, how many DISTINCT moves can produce a foothold reachably?
// A port with only one is a single point of failure — if that one technique does not work on the box,
// the user is stranded with no alternative. Also names chokepoints: a move whose removal makes the
// foothold unreachable from that port (every path depends on it). This is the "prepare for exceptions"
// view: the thin paths are where a disabled user most needs a second option.
if (argv.indexOf('--robust') >= 0) {
  var FOOT = { 'foothold.linux': 1, 'foothold.windows': 1, 'access.shell': 1, 'foothold.webshell': 1, 'access.desktop': 1 };
  function reachWithout(seed, dropId) {
    var have = {}, k; for (k in seed) have[k] = 1; var changed = true;
    while (changed) { changed = false; var fam = osFamOf(have);
      for (var i = 0; i < A.length; i++) { var a = A[i]; if (a.id === dropId || !osOk(a, fam)) continue;
        var all = a.requires_all || [], any = a.requires_any || [], ok = true, j;
        for (j = 0; j < all.length; j++) if (!have[all[j]]) { ok = false; break; }
        if (ok && any.length) { ok = false; for (j = 0; j < any.length; j++) if (have[any[j]]) { ok = true; break; } }
        if (!ok) continue; (a.produces || []).forEach(function (p) { if (!have[p]) { have[p] = 1; changed = true; } }); } }
    return have;
  }
  function footReachable(have) { for (var f in FOOT) if (have[f]) return true; return false; }
  console.log('\nROBUSTNESS (foothold path diversity)\n');
  var thin = [];
  ev.forEach(function (e) {
    var seed = seedFor(e), clo = reachClosure(seed);
    // distinct foothold-producing moves that are reachable (their gates hold within the closure)
    var footMoves = A.filter(function (a) {
      if (!(a.produces || []).some(function (p) { return FOOT[p]; })) return false;
      var all = a.requires_all || [], any = a.requires_any || [];
      if (!all.every(function (r) { return clo.have[r]; })) return false;
      if (any.length && !any.some(function (r) { return clo.have[r]; })) return false;
      return true;
    }).map(function (a) { return a.id; });
    var choke = footReachable(clo.have) ? footMoves.filter(function (id) { return !footReachable(reachWithout(seed, id)); }) : [];
    var flag = footMoves.length <= 1 || choke.length;
    if (flag) thin.push({ port: e.port, label: e.label, n: footMoves.length, moves: footMoves, choke: choke });
  });
  if (!thin.length) console.log('  every entry has at least two independent ways to a foothold, no chokepoints.');
  thin.forEach(function (t) {
    console.log('  ' + String(t.port).padEnd(14) + ' ' + t.n + ' foothold option(s): ' + (t.moves.join(', ') || '(none direct)') + (t.choke.length ? '   CHOKEPOINT: ' + t.choke.join(', ') : ''));
  });
}

// --emit: write the shared map (docs/FLAG-PATHS.md) and the app badge data (data/flag-reach.js), both
// generated from the live graph so they never drift from the moves.
if (argv.indexOf('--emit') >= 0) {
  var nameOf = {}; A.forEach(function (a) { nameOf[a.id] = a.title || a.id; });
  function chain(r) { return r && r.reachable ? r.path.map(function (id) { return nameOf[id] || id; }).join(' → ') : '**UNREACHABLE**'; }
  var md = [];
  md.push('# Flag-reachability map', '');
  md.push('_Generated by `node tools/flag-paths.js --emit` from the live move graph — do not edit by hand._', '');
  md.push('Every by-port entry point, proven by the engine\'s own reachability to each milestone: a **foothold**, the **user flag** (`objective.flag`), **root/admin** (`access.admin`/`access.system`), and — for AD entry points — **domain control** (`loot.ntds` / own-the-domain). A disabled or neurodivergent user who lands on any of these ports has a charted path to the flag; a GAP here is someone stranded.', '');
  md.push('| Port | Foothold | User flag | Root/Admin | Domain control |');
  md.push('| --- | :-: | :-: | :-: | :-: |');
  rows.forEach(function (row) {
    function c(k) { var r = row.res[k]; return r ? (r.reachable ? '✅' : '❌') : '—'; }
    md.push('| `' + row.port + '` ' + row.label + ' | ' + c('FOOTHOLD') + ' | ' + c('USER-FLAG') + ' | ' + c('ROOT') + ' | ' + (row.res.DOMAIN ? c('DOMAIN') : '—') + ' |');
  });
  md.push('', '## Canonical path per entry point', '');
  rows.forEach(function (row) {
    md.push('### `' + row.port + '` — ' + row.label + (row.fam === 'ad' ? '  _(domain control is a milestone on the way to the flag)_' : ''));
    md.push('- **Foothold:** ' + chain(row.res.FOOTHOLD));
    md.push('- **User flag:** ' + chain(row.res['USER-FLAG']));
    md.push('- **Root/Admin:** ' + chain(row.res.ROOT));
    if (row.res.DOMAIN) md.push('- **Domain control:** ' + chain(row.res.DOMAIN));
    md.push('');
  });
  md.push('---', '', gaps.length ? ('**' + gaps.length + ' GAP(S) REMAIN** — see above.') : '**No gaps: every entry point reaches a foothold, the user flag, and root.**', '');
  fs.writeFileSync(path.join(ROOT, 'docs/FLAG-PATHS.md'), md.join('\n') + '\n');

  var reach = {};
  rows.forEach(function (row) {
    reach[row.key] = {
      foothold: !!(row.res.FOOTHOLD && row.res.FOOTHOLD.reachable),
      userFlag: !!(row.res['USER-FLAG'] && row.res['USER-FLAG'].reachable),
      rootFlag: !!(row.res.ROOT && row.res.ROOT.reachable),
      domain: row.res.DOMAIN ? !!row.res.DOMAIN.reachable : null,
    };
  });
  var banner = '/*! obol data :: flag-reach.js :: GENERATED by tools/flag-paths.js --emit. Do not edit by hand.\n'
    + ' * Per-port flag reachability (foothold / user flag / root / domain control), proven from the move\n'
    + ' * graph, so the decision tree can badge every entry with the milestones it provably reaches. */\n';
  fs.writeFileSync(path.join(ROOT, 'data/flag-reach.js'),
    banner + '(function (root) {\n  "use strict";\n  var OBOL = root.OBOL = root.OBOL || {};\n  OBOL.FLAG_REACH = ' + JSON.stringify(reach, null, 2) + ';\n})(typeof globalThis !== "undefined" ? globalThis : this);\n');
  console.log('\nemitted docs/FLAG-PATHS.md and data/flag-reach.js');
}
