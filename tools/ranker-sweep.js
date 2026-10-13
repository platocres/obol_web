/*
 * tools/ranker-sweep.js — the broad ranker fuzzer.
 *
 * ranker-sim.js judges ~25 curated archetype states; this fuzzes thousands of
 * sampled states to catch what the curated matrix misses. It reuses the SIM's
 * judge() and RUBRIC verbatim (one source of truth: edit a rule in ranker-sim.js
 * and it changes here too), and reports CLUSTERED issue patterns, not a wall.
 *
 * The hard part of a fuzzer is not inventing impossible states. The obol lineage
 * learned this the expensive way: unconstrained fact injection (privesc.* with no
 * foothold, smb.* with no SMB port, a hash on a pure-DB box) manufactures states
 * the live app can never reach and then cries wolf about them. So every injected
 * fact passes canInject(): a precondition check that keeps the sampled state in
 * the space the parsers could actually mint.
 *
 * Usage:
 *   node tools/ranker-sweep.js                 # default N, seeded, clustered report
 *   node tools/ranker-sweep.js --n 4000        # sample size
 *   node tools/ranker-sweep.js --seed 7        # reproducible run
 *   node tools/ranker-sweep.js --show 3        # example states per pattern
 *   node tools/ranker-sweep.js --check         # exit 1 if violation RATE exceeds threshold
 *   node tools/ranker-sweep.js --rate 0.0      # set the --check threshold (fraction)
 */
'use strict';
const sim = require('./ranker-sim.js'); // loads the engine + exposes judge/F/seed/RUBRIC
const F = sim.F;

// ---- deterministic RNG (mulberry32) so runs are reproducible ----------------
function rng(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---- port pool (service -> port), sampled to build the attack surface -------
const SERVICE_PORTS = {
  ftp: 21, ssh: 22, smtp: 25, dns: 53, http: 80, kerberos: 88, rpc: 135, netbios: 139,
  ldap: 389, smb: 445, ldaps: 636, mssql: 1433, mysql: 3306, rdp: 3389, winrm: 5985,
  https: 443, gc: 3268, snmp: 161, pop3: 110, imap: 143, nfs: 2049, vnc: 5900, redis: 6379,
};
// A real DC always exposes Kerberos(88) + LDAP(389). Treat THOSE as the AD
// signal, not the secondary GC(3268)/LDAPS(636) ports, so a GC-only surface
// (which never occurs on a real box) is not mislabeled as an AD target.
const CORE_AD_PORTS = [88, 389];
// When the version scan reveals services, these reachability facts are minted
// (mirrors a real nmap -sV paste), so a box's only lead is actually reachable.
const PORT_SERVICE_FACT = {
  21: 'ftp.reachable', 22: 'ssh.reachable', 80: 'http.reachable', 443: 'http.reachable',
  135: 'smb.reachable', 139: 'smb.reachable', 445: 'smb.reachable', 389: 'ldap.reachable',
  636: 'ldap.reachable', 3268: 'ldap.reachable', 88: 'kerberos.reachable', 5985: 'winrm.reachable',
  3389: 'rdp.reachable', 161: 'snmp.reachable', 6379: 'redis.reachable', 2049: 'nfs.exports',
  1433: 'service.mssql', 3306: 'service.mysql', 5900: 'vnc.reachable',
};

// A stage is how far the engagement has progressed; each adds cumulative facts.
const STAGES = ['recon', 'enum', 'credentialed', 'foothold', 'admin'];

// Candidate injectable findings, each with a precondition over the current facts.
// canInject keeps the sampled state reachable: a fact only lands if something in
// the state could plausibly have minted it.
function openPorts(facts) {
  const p = facts.find(f => f.kind === 'ports.open');
  return (p && p.value && p.value.ports) || [];
}
function hasPort(facts, n) { return openPorts(facts).indexOf(n) >= 0; }
function has(facts, k) { return facts.some(f => f.kind === k); }
function isAD(facts) { return has(facts, 'ad.dc_candidate') || CORE_AD_PORTS.some(p => hasPort(facts, p)); }
function hasFoothold(facts) { return ['foothold.linux', 'foothold.windows', 'access.shell', 'access.admin'].some(k => has(facts, k)); }
function hasCred(facts) { return has(facts, 'credential.available') || has(facts, 'credential.validated'); }

const INJECTABLE = [
  { kind: 'scan.nmap.version', can: () => true },
  { kind: 'scan.nmap.vuln', can: (f) => has(f, 'scan.nmap.version') },
  { kind: 'smb.null_session', can: (f) => hasPort(f, 445) },
  { kind: 'smb.reachable', can: (f) => hasPort(f, 445) },
  { kind: 'ldap.reachable', can: (f) => hasPort(f, 389) },
  { kind: 'ad.dc_candidate', can: (f) => isAD(f) },
  { kind: 'ad.domain_known', can: (f) => isAD(f), value: { domain: 'test.local' } },
  { kind: 'ad.base_dn', can: (f) => isAD(f) && has(f, 'ad.domain_known') },
  { kind: 'ad.anonymous_bind', can: (f) => has(f, 'ldap.reachable') },
  { kind: 'ad.user_list', can: (f) => isAD(f) && (has(f, 'ad.anonymous_bind') || has(f, 'smb.null_session')), value: { users: ['svc', 'bob'] } },
  { kind: 'hash.asrep', can: (f) => has(f, 'ad.user_list') },
  { kind: 'hash.tgs', can: (f) => has(f, 'ad.user_list') && hasCred(f) },
  { kind: 'http.reachable', can: (f) => hasPort(f, 80) || hasPort(f, 443) },
  { kind: 'web.server', can: (f) => has(f, 'http.reachable'), value: { headers: ['Apache/2.4'] } },
  { kind: 'web.content_map', can: (f) => has(f, 'http.reachable'), value: { paths: ['/admin'] } },
  { kind: 'web.users', can: (f) => has(f, 'http.reachable'), value: { users: ['admin'] } },
  { kind: 'db.session', can: (f) => (hasPort(f, 1433) || hasPort(f, 3306)) && hasCred(f) },
  // service-reachable facts the version scan reveals, so a box whose only lead is
  // an exotic service can actually reach its move (otherwise the generator makes
  // it look dead and the leads_somewhere rule cries wolf about a non-real state).
  { kind: 'redis.reachable', can: (f) => hasPort(f, 6379) },
  { kind: 'snmp.community', can: (f) => hasPort(f, 161) },
  { kind: 'ftp.anonymous_login', can: (f) => hasPort(f, 21) },
  { kind: 'rdp.reachable', can: (f) => hasPort(f, 3389) },
  { kind: 'nfs.exports', can: (f) => hasPort(f, 2049) },
  { kind: 'credential.available', can: (f) => has(f, 'hash.asrep') || has(f, 'smb.null_session') || has(f, 'web.content_map'), value: { user: 'svc', password: 'p' } },
  { kind: 'credential.validated', can: (f) => has(f, 'credential.available') },
  { kind: 'foothold.linux', can: (f) => hasCred(f) && hasPort(f, 22) },
  { kind: 'foothold.windows', can: (f) => hasCred(f) && (hasPort(f, 5985) || hasPort(f, 445)) },
  { kind: 'access.shell', can: (f) => hasFoothold(f) },
  { kind: 'privesc.suid_candidate', can: (f) => has(f, 'foothold.linux'), value: { paths: ['/usr/bin/x'] } },
  { kind: 'privesc.sudo_rights', can: (f) => has(f, 'foothold.linux') },
  { kind: 'privesc.windows_privilege', can: (f) => has(f, 'foothold.windows'), value: { priv: 'SeImpersonatePrivilege' } },
  { kind: 'access.admin', can: (f) => hasFoothold(f) && (has(f, 'privesc.suid_candidate') || has(f, 'privesc.windows_privilege') || has(f, 'privesc.sudo_rights')) },
  { kind: 'loot.ntds', can: (f) => has(f, 'access.admin') && isAD(f) },
];

function buildState(rand) {
  // 1. sample an attack surface (2-7 services, biased toward realistic clusters)
  const svcNames = Object.keys(SERVICE_PORTS);
  const n = 2 + Math.floor(rand() * 6);
  const chosen = new Set();
  // seed a coherent cluster half the time (AD, or web box) so surfaces aren't pure noise
  const roll = rand();
  if (roll < 0.4) ['dns', 'kerberos', 'rpc', 'ldap', 'smb', 'winrm'].forEach(s => chosen.add(s));
  else if (roll < 0.7) { chosen.add('http'); chosen.add(rand() < 0.5 ? 'ssh' : 'smb'); }
  while (chosen.size < n) chosen.add(svcNames[Math.floor(rand() * svcNames.length)]);
  const ports = [...chosen].map(s => SERVICE_PORTS[s]).sort((a, b) => a - b);

  let facts = [F('scan.nmap.quick'), { kind: 'ports.open', scope: 'host:10.10.10.10', value: { ports }, state: 'supported' }];
  ports.forEach(p => facts.push(F('port:' + p)));

  // 2. advance to a random stage by injecting as many plausible findings as the
  //    stage depth allows (recon=0 ... admin=deep), each gated by canInject.
  const depth = Math.floor(rand() * STAGES.length); // 0..4
  const rounds = depth * 3;
  for (let i = 0; i < rounds; i++) {
    const cand = INJECTABLE[Math.floor(rand() * INJECTABLE.length)];
    if (has(facts, cand.kind)) continue;
    if (!cand.can(facts)) continue;
    facts.push(F(cand.kind, cand.value || {}));
  }
  // Once the version scan has run, it reveals the service on each open port, so
  // mint the reachability facts a real nmap -sV paste would (keeps post-scan
  // states reachable instead of artificially dead).
  if (has(facts, 'scan.nmap.version')) {
    ports.forEach(p => { const k = PORT_SERVICE_FACT[p]; if (k && !has(facts, k)) facts.push(F(k)); });
  }
  return facts;
}

// ---- run the sweep -----------------------------------------------------------
function arg(name, def) { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : def; }
const N = parseInt(arg('--n', '4000'), 10);
const SEED = parseInt(arg('--seed', '1'), 10);
const SHOW = parseInt(arg('--show', '2'), 10);
const CHECK = process.argv.indexOf('--check') >= 0;
const RATE = parseFloat(arg('--rate', '0.0'));

const rand = rng(SEED);
const clusters = {};
let flagged = 0;
for (let i = 0; i < N; i++) {
  const facts = buildState(rand);
  const meta = { isAD: isAD(facts) };
  const r = sim.judge(facts, meta);
  if (!r.violations.length) continue;
  flagged++;
  r.violations.forEach(v => {
    const key = v.principle + ' | lead=' + (v.lead || '(none)');
    const c = clusters[key] || (clusters[key] = { count: 0, examples: [] });
    c.count++;
    if (c.examples.length < SHOW) {
      const surface = openPorts(facts).join(',');
      c.examples.push(`ports[${surface}] top3=${r.top3.join('>')}`);
    }
  });
}

const rate = flagged / N;
console.log('=== RANKER SWEEP ===');
console.log(`samples: ${N}   seed: ${SEED}   flagged states: ${flagged}   rate: ${(rate * 100).toFixed(2)}%`);
const keys = Object.keys(clusters).sort((a, b) => clusters[b].count - clusters[a].count);
if (keys.length) {
  console.log(`\n${keys.length} issue pattern(s):`);
  keys.forEach(k => {
    console.log(`  (${clusters[k].count}) ${k}`);
    clusters[k].examples.forEach(e => console.log(`        e.g. ${e}`));
  });
} else {
  console.log('\nno violations across the sampled space.');
}
if (CHECK) {
  if (rate > RATE) { console.log(`\nFAIL: violation rate ${(rate * 100).toFixed(2)}% exceeds threshold ${(RATE * 100).toFixed(2)}%`); process.exit(1); }
  console.log(`\nPASS: violation rate ${(rate * 100).toFixed(2)}% within threshold ${(RATE * 100).toFixed(2)}%`);
}
