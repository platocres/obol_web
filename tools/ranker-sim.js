/*
 * tools/ranker-sim.js — the broad ranker scoreboard.
 *
 * The golden replays (verify-replay-goldens / verify-oscp-practice-exams) pin a
 * handful of REAL boxes step by step. They are concrete and honest, but they are
 * also overfit-prone: tune a weight until those ~20 boxes pass and you have fit
 * the ranker to those boxes. This sim is the complement: a curated matrix of
 * ARCHETYPE x STAGE fact-states, each run through the SAME gated coach the user
 * sees (OBOL.coach.compute), and judged against a methodology rubric. It never
 * touches the ranker; it only measures it, so you can tell whether a ranking or
 * move-data change helped or quietly regressed the general case.
 *
 * Usage:
 *   node tools/ranker-sim.js            # summary + violation count
 *   node tools/ranker-sim.js --verbose  # every state's top-3 and every violation
 *   node tools/ranker-sim.js --check    # exit 1 if violations exceed the baseline
 *
 * Triage discipline (from the project's own history): most violations are
 * MOVE-DATA (a move's requires/produces is wrong) or PARSER/FACT correctness,
 * not ranking-math. Sort each one before touching pack.js. A genuine ranking
 * rule goes in as a soft tiebreak BELOW the hand-tuned priority, measured here,
 * reverted on any golden OR sim regression. The rubric is exported so a future
 * fuzzer (ranker-sweep) can reuse it as the single source of truth.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
global.OBOL = global.OBOL || {};
function load(rel) { vm.runInThisContext(fs.readFileSync(path.join(root, rel), 'utf8'), { filename: rel }); }
[
  'assets/engine/facts.js', 'assets/engine/loot.js', 'assets/engine/profile.js', 'assets/engine/vfs.js',
  'assets/engine/phases.js', 'assets/engine/pack.js', 'assets/engine/packs.js', 'data/packs-bundle.js',
  'assets/engine/command.js', 'assets/engine/workspace.js', 'assets/ui/util.js', 'assets/ui/icons.js',
  'assets/ui/store.js',
  'assets/engine/parsers/common.js', 'assets/engine/parsers/shape.js', 'assets/engine/parsers/blockers.js',
  'assets/engine/parsers/creds.js', 'assets/engine/parsers/directory.js', 'assets/engine/parsers/index.js',
  'assets/ui/ctxbar.js', 'assets/ui/routes/path.js',
].forEach(load);

const P = OBOL.phases;
const F = (kind, value) => ({ kind, scope: 'host:10.10.10.10', value: value || {}, state: 'supported' });

// Seed a synthetic engagement the gated coach will read (mirrors the golden harness).
function seed(facts) {
  const eng = {
    id: 'sim-' + Date.now(), checklist: {}, activities: [],
    params: { platform: 'htb', target: '10.10.10.10', scope_defined: true, lhost: '10.10.14.1',
      lhost_iface: 'tun0', username: '', password: '', nthash: '', domain: 'test.local' },
    facts: facts.map(f => OBOL.facts.factFromJson(f)),
  };
  OBOL.store.active = () => eng;
  OBOL.store.factSet = () => { const s = new OBOL.facts.FactSet(); eng.facts.forEach(f => s.add(f)); return s; };
  OBOL.store.factSetForTarget = () => OBOL.store.factSet();
  return eng;
}

// ---- Fact-state building blocks (realistic, shape-based, no box quirks) -------
const PORTS = {
  dc: ['port:53', 'port:88', 'port:135', 'port:139', 'port:389', 'port:445', 'port:464', 'port:593', 'port:636', 'port:3268', 'port:5985'],
  winStandalone: ['port:135', 'port:139', 'port:445', 'port:3389', 'port:5985'],
  linuxWeb: ['port:22', 'port:80'],
  db: ['port:1433'],
};
const openPortsFact = (ports) => F('ports.open', { ports: ports.map(p => parseInt(p.split(':')[1], 10)) });

// Each archetype returns the facts for a given stage (cumulative).
const ARCHETYPES = {
  'ad-dc': {
    isAD: true,
    base: () => [F('scan.nmap.quick'), openPortsFact(PORTS.dc), ...PORTS.dc.map(p => F(p)),
      F('smb.reachable'), F('ldap.reachable'), F('kerberos.reachable'), F('ad.dc_candidate')],
    stages: {
      recon: () => [],
      oriented: () => [F('scan.nmap.version'), F('ad.domain_known', { domain: 'test.local' }), F('ad.base_dn'), F('ad.anonymous_bind'), F('ad.user_list', { users: ['svc', 'bob'] })],
      credentialed: () => [F('hash.asrep'), F('credential.available', { user: 'svc', password: 'p' }), F('credential.validated', { user: 'svc' })],
      foothold: () => [F('foothold.windows'), F('access.shell')],
      admin: () => [F('access.admin'), F('loot.ntds')],
    },
  },
  'ad-dc-noisy': { // a DC that also runs web + a DB, to test cross-service ordering
    isAD: true,
    base: () => [F('scan.nmap.quick'), openPortsFact(PORTS.dc.concat(['port:80', 'port:1433'])),
      ...PORTS.dc.map(p => F(p)), F('port:80'), F('port:1433'),
      F('smb.reachable'), F('ldap.reachable'), F('kerberos.reachable'), F('ad.dc_candidate'),
      F('http.reachable'), F('web.server', { headers: ['Microsoft-IIS/10.0'] }), F('service.mssql')],
    stages: {
      recon: () => [],
      oriented: () => [F('scan.nmap.version'), F('ad.domain_known'), F('ad.base_dn'), F('ad.user_list', { users: ['svc'] })],
      credentialed: () => [F('credential.available', { user: 'svc' }), F('credential.validated')],
      foothold: () => [F('foothold.windows'), F('access.shell')],
      admin: () => [F('access.admin'), F('loot.ntds')],
    },
  },
  'win-standalone': {
    isAD: false,
    base: () => [F('scan.nmap.quick'), openPortsFact(PORTS.winStandalone), ...PORTS.winStandalone.map(p => F(p)), F('smb.reachable')],
    stages: {
      recon: () => [],
      enum: () => [F('scan.nmap.version'), F('smb.null_session')],
      credentialed: () => [F('credential.available', { user: 'admin' }), F('credential.validated')],
      foothold: () => [F('foothold.windows'), F('access.shell')],
      admin: () => [F('access.admin'), F('privesc.windows_privilege', { priv: 'SeImpersonatePrivilege' })],
    },
  },
  'linux-web': {
    isAD: false,
    base: () => [F('scan.nmap.quick'), openPortsFact(PORTS.linuxWeb), ...PORTS.linuxWeb.map(p => F(p)),
      F('ssh.reachable'), F('http.reachable'), F('web.server', { headers: ['Apache/2.4.41'] })],
    stages: {
      recon: () => [],
      enum: () => [F('scan.nmap.version'), F('web.content_map', { paths: ['/admin'] })],
      foothold: () => [F('foothold.linux'), F('access.shell')],
      privready: () => [F('privesc.suid_candidate', { paths: ['/usr/bin/screen'] }), F('privesc.sudo_rights')],
      rooted: () => [F('access.admin')],
    },
  },
  'db-box': {
    isAD: false,
    base: () => [F('scan.nmap.quick'), openPortsFact(PORTS.db), F('port:1433'), F('service.mssql')],
    stages: {
      recon: () => [],
      enum: () => [F('scan.nmap.version')],
      credentialed: () => [F('credential.available', { user: 'sa' }), F('db.session')],
      foothold: () => [F('foothold.windows'), F('access.shell')],
      admin: () => [F('access.admin')],
    },
  },
};

// Build the cumulative fact-state for an archetype up to and including `stage`.
function stateFor(arch, stageName) {
  const a = ARCHETYPES[arch];
  let facts = a.base();
  const order = Object.keys(a.stages);
  for (const s of order) { facts = facts.concat(a.stages[s]()); if (s === stageName) break; }
  return facts;
}

// ---- Rubric (methodology judge). Exported so a sweep can reuse it. -----------
const AD_ORIENT_KINDS = ['ad.dc_candidate', 'ad.domain_known', 'ad.base_dn', 'ad.anonymous_bind'];
const ACCESS_KINDS = ['foothold.windows', 'foothold.linux', 'access.shell', 'access.admin', 'access.system'];
const CRED_KINDS = ['credential.available', 'credential.validated'];

function has(facts, kind) { return facts.some(f => f.kind === kind && f.state === 'supported'); }
function hasAny(facts, kinds) { return kinds.some(k => has(facts, k)); }
function phaseOf(a) { try { return P.phaseOfAction(a); } catch (e) { return 'recon'; } }
function produces(a, kinds) { return (a.produces || []).some(k => kinds.indexOf(k) >= 0); }

// Each rule: { name, test(ctx) -> violation-string | null }. ctx carries the
// state facts, the archetype meta, and the gated top moves (full action objects).
const RUBRIC = [
  {
    name: 'leads_somewhere',
    test: (ctx) => ctx.top.length === 0 ? 'no ready move at all (dead state)' : null,
  },
  {
    name: 'no_privesc_before_access',
    test: (ctx) => {
      if (hasAny(ctx.facts, ACCESS_KINDS)) return null;
      const bad = ctx.top3.find(a => phaseOf(a) === 'escalate');
      return bad ? `escalate move '${bad.id}' leads with no foothold/access` : null;
    },
  },
  {
    name: 'no_loot_before_access',
    test: (ctx) => {
      if (has(ctx.facts, 'access.admin') || has(ctx.facts, 'access.system')) return null;
      // A loot move leading before any access at all is premature.
      if (hasAny(ctx.facts, ACCESS_KINDS)) return null;
      const bad = ctx.top3.find(a => phaseOf(a) === 'loot');
      return bad ? `loot move '${bad.id}' leads with no access` : null;
    },
  },
  {
    name: 'ad_orient_in_top3',
    test: (ctx) => {
      if (!ctx.meta.isAD) return null;
      // Match the ranker's own orientADFirst contract: it pins an AD-orient move
      // to the top-3 only while the DC/domain is NOT yet confirmed and you hold
      // no foothold/credential. Once ad.dc_candidate + ad.domain_known are known
      // the ranker considers you oriented and stops pinning, so the rubric must
      // stop demanding it there too (else it flags states the ranker never
      // promised to pin).
      if (has(ctx.facts, 'ad.dc_candidate') && has(ctx.facts, 'ad.domain_known')) return null;
      if (hasAny(ctx.facts, ACCESS_KINDS) || hasAny(ctx.facts, CRED_KINDS)) return null;
      // Is an orient move even eligible in the full ranked set? If not, nothing to pin.
      const eligibleOrient = ctx.all.some(a => produces(a, AD_ORIENT_KINDS) && !AD_ORIENT_KINDS.every(k => has(ctx.facts, k)));
      if (!eligibleOrient) return null;
      const inTop3 = ctx.top3.some(a => produces(a, AD_ORIENT_KINDS));
      return inTop3 ? null : `AD orient move not in top-3 (leads: ${ctx.top3.map(a => a.id).join(', ')})`;
    },
  },
  {
    name: 'no_blind_spray_lead',
    test: (ctx) => {
      const lead = ctx.top[0];
      if (!lead) return null;
      const isSpray = /spray|online-brute/i.test(lead.id) && !/blind/i.test(lead.id);
      if (!isSpray) return null;
      if (hasAny(ctx.facts, ['ad.user_list', 'web.users'])) return null;
      return `userlist-spray '${lead.id}' leads with no enumerated user list`;
    },
  },
  {
    // The RFC's explore-first principle, as a measurable rule: in the opening
    // (scanned, no version yet, no foothold, no credential), the #1 move should
    // be the thorough service/version scan, or on an AD box an orient move.
    name: 'recon_scan_leads_opening',
    test: (ctx) => {
      if (!has(ctx.facts, 'scan.nmap.quick')) return null;
      if (has(ctx.facts, 'scan.nmap.version')) return null; // past the opening
      if (hasAny(ctx.facts, ACCESS_KINDS) || hasAny(ctx.facts, CRED_KINDS)) return null;
      const lead = ctx.top[0];
      if (!lead) return null;
      const isScan = produces(lead, ['scan.nmap.version']) || /version-script|service-scan|nmap-version/i.test(lead.id);
      const isOrient = ctx.meta.isAD && produces(lead, AD_ORIENT_KINDS);
      return (isScan || isOrient) ? null : `opening lead '${lead.id}' is neither the service scan nor an AD orient`;
    },
  },
];

// ---- Teeth-check: prove every rule CAN fire (node tools/ranker-sim.js --selftest)
// A scoreboard that always reads 0 is worthless if its rules are vacuous. This
// feeds each rule a crafted violating context and asserts it returns a finding.
if (process.argv.indexOf('--selftest') >= 0) {
  const pack = OBOL.packs.actions();
  const esc = pack.find(a => P.phaseOfAction(a) === 'escalate');
  const loot = pack.find(a => P.phaseOfAction(a) === 'loot');
  const spray = pack.find(a => /spray/i.test(a.id) && !/blind/i.test(a.id));
  const orient = pack.find(a => (a.produces || []).some(k => AD_ORIENT_KINDS.indexOf(k) >= 0));
  const nmapScan = pack.find(a => (a.produces || []).indexOf('scan.nmap.version') >= 0);
  const openFact = [F('scan.nmap.quick')];
  const cases = {
    leads_somewhere: { facts: [], meta: {}, top: [], top3: [], all: [] },
    no_privesc_before_access: { facts: [], meta: {}, top: [esc], top3: [esc], all: [esc] },
    no_loot_before_access: { facts: [], meta: {}, top: [loot], top3: [loot], all: [loot] },
    ad_orient_in_top3: { facts: openFact, meta: { isAD: true }, top: [esc], top3: [esc], all: [esc, orient] },
    no_blind_spray_lead: { facts: [], meta: {}, top: [spray], top3: [spray], all: [spray] },
    recon_scan_leads_opening: { facts: openFact, meta: { isAD: false }, top: [esc], top3: [esc], all: [esc] },
  };
  let ok = 0, bad = 0;
  RUBRIC.forEach(rule => {
    const ctx = cases[rule.name];
    const fired = ctx && rule.test(ctx);
    if (fired) { console.log(`PASS teeth: ${rule.name} fires -> ${fired}`); ok++; }
    else { console.log(`FAIL teeth: ${rule.name} did NOT fire on a crafted violating state`); bad++; }
  });
  console.log(`\n${ok} rules have teeth, ${bad} vacuous`);
  process.exit(bad ? 1 : 0);
}

// ---- The single judging path: seed a state, run the gated coach, apply the
// rubric. Both the curated matrix (below) and the broad sweep (ranker-sweep.js)
// go through here, so the rubric has exactly one implementation.
function judge(facts, meta) {
  seed(facts);
  const c = OBOL.coach.compute();
  const top = c.onFlow || [];
  const all = top.concat(c.comingUp || []);
  const ctx = { facts, meta: meta || {}, top, top3: top.slice(0, 3), all };
  const out = [];
  for (const rule of RUBRIC) {
    const v = rule.test(ctx);
    if (v) out.push({ principle: rule.name, detail: v, lead: top[0] && top[0].id });
  }
  return { violations: out, top3: top.slice(0, 3).map(a => a.id) };
}

module.exports = { RUBRIC, ARCHETYPES, stateFor, judge, F, seed, AD_ORIENT_KINDS };

// ---- Run the curated matrix (only when invoked directly) ---------------------
if (require.main === module) {
  const VERBOSE = process.argv.indexOf('--verbose') >= 0;
  const CHECK = process.argv.indexOf('--check') >= 0;
  const BASELINE = 0; // keep the board clean; raise only with a recorded, owner-approved reason.

  let states = 0; const violations = [];
  for (const arch of Object.keys(ARCHETYPES)) {
    for (const stage of Object.keys(ARCHETYPES[arch].stages)) {
      states++;
      const r = judge(stateFor(arch, stage), ARCHETYPES[arch]);
      r.violations.forEach(v => violations.push(Object.assign({ arch, stage }, v)));
      if (VERBOSE || r.violations.length) {
        console.log(`[${arch} / ${stage}]  top3: ${r.top3.join(' > ') || '(none)'}`);
        r.violations.forEach(v => console.log(`    VIOLATION ${v.principle}: ${v.detail}`));
      }
    }
  }

  const clusters = {};
  violations.forEach(v => { const k = v.principle + ' | lead=' + (v.lead || '?'); (clusters[k] = clusters[k] || []).push(`${v.arch}/${v.stage}`); });
  console.log('\n=== RANKER SIM SCOREBOARD ===');
  console.log(`States judged: ${states}   Violations: ${violations.length}`);
  if (violations.length) {
    console.log('\nViolation patterns:');
    Object.keys(clusters).forEach(k => console.log(`  (${clusters[k].length}) ${k}  [${clusters[k].join(', ')}]`));
  }
  if (CHECK) {
    if (violations.length > BASELINE) { console.log(`\nFAIL: ${violations.length} violations exceed baseline ${BASELINE}`); process.exit(1); }
    console.log(`\nPASS: ${violations.length} violations (baseline ${BASELINE})`);
  }
}
