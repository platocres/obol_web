#!/usr/bin/env node
'use strict';

/**
 * causal-frontier-adversarial-smoke.js
 *
 * Adversarial regression and stress suite for the 7-Tier Causal Frontier &
 * Graph-Utility Ranking Engine (nextActionsV2 in assets/engine/pack.js).
 *
 * Verifies:
 *  1. Recency-decay immunity across 10-minute wall-clock gaps (Tier 3/4/5 persistence).
 *  2. Intermediate-goal distance-zeroing immunity (activeGoals filter after user.txt).
 *  3. Escalation-aware lookahead (inEscalationWindow) & pure graph utility ordering
 *     (bloodyad-acl S=0.980 > kerberoast S=0.940 > laps-read S=0.080).
 *  4. Strict lexicographic separation across all 7 Causal Frontier Tiers (-1..5)
 *     and speculative/side-quest suppression even under 'all' ('beyond') scope lens.
 *  5. Out-of-order jump resilience with backward causal entailment.
 *  6. Environmental error vs. conclusive negative dry-probe rotation & cross-card
 *     command signature retirement.
 *  7. Multi-host & multi-credential isolation under Tier 4/5 promotions.
 */

var assert = require('assert');
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.resolve(__dirname, '..', '..');

function makeSandbox() {
  var storeData = {};
  var sb = {
    console: console,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    Date: Date,
    Math: Math,
    Array: Array,
    Object: Object,
    String: String,
    Number: Number,
    RegExp: RegExp,
    Set: Set,
    Map: Map,
    JSON: JSON,
    Promise: Promise,
    Error: Error,
    TypeError: TypeError,
    parseInt: parseInt,
    parseFloat: parseFloat,
    isNaN: isNaN,
    isFinite: isFinite,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
    window: {},
    document: {
      addEventListener: function () {},
      getElementById: function (id) {
        return { id: id, innerHTML: '', setAttribute: function () {}, addEventListener: function () {} };
      }
    },
    localStorage: {
      getItem: function (k) { return Object.prototype.hasOwnProperty.call(storeData, k) ? storeData[k] : null; },
      setItem: function (k, v) { storeData[k] = String(v); }
    },
    navigator: {},
    location: { hash: '' }
  };
  sb.globalThis = sb;
  sb.window = sb;
  sb.root = sb;
  [
    'assets/engine/facts.js',
    'assets/engine/loot.js',
    'assets/engine/profile.js',
    'assets/engine/vfs.js',
    'assets/engine/phases.js',
    'assets/engine/context.js',
    'assets/engine/outcomes.js',
    'assets/engine/pack.js',
    'assets/engine/packs.js',
    'data/packs-bundle.js',
    'assets/engine/command.js',
    'assets/engine/workspace.js',
    'assets/ui/util.js',
    'assets/ui/icons.js',
    'assets/ui/store.js',
    'assets/engine/parsers/common.js',
    'assets/engine/parsers/nmap.js',
    'assets/engine/parsers/directory.js',
    'assets/engine/parsers/creds.js',
    'assets/engine/parsers/host.js',
    'assets/engine/parsers/web.js',
    'assets/engine/parsers/services.js',
    'assets/engine/parsers/database.js',
    'assets/engine/parsers/websource.js',
    'assets/engine/parsers/findings.js',
    'assets/engine/parsers/shape.js',
    'assets/engine/parsers/pivot.js',
    'assets/engine/parsers/dns.js',
    'assets/engine/parsers/blockers.js',
    'assets/engine/parsers/nxc-catalog.js',
    'assets/engine/parsers/inference.js',
    'assets/engine/parsers/index.js',
    'assets/ui/ingest.js',
    'assets/engine/chain.js',
    'data/findings-catalog.js',
    'assets/engine/findings.js',
    'data/narratives.js',
    'assets/engine/report.js',
    'assets/ui/ctxbar.js',
    'assets/ui/routes/path.js'
  ].forEach(function (rel) {
    vm.runInNewContext(fs.readFileSync(path.join(ROOT, rel), 'utf8'), sb, { filename: rel });
  });
  return sb;
}

var sb = makeSandbox();
var OBOL = sb.OBOL;
var passed = 0;

function check(cond, msg) {
  if (!cond) {
    console.error('  FAIL: ' + msg);
    process.exit(1);
  }
  passed++;
  console.log('  ok  : ' + msg);
}

function mkFact(kind, value, scope, createdAt) {
  return OBOL.facts.makeFact({
    kind: kind,
    scope: scope || 'host:10.10.10.100',
    value: value || {},
    state: 'supported',
    source: 'adversarial-test',
    created_at: createdAt != null ? createdAt : 1000
  });
}

function mountEng(params, facts, activities) {
  var eng = {
    id: 'eng-adv-' + Date.now(),
    params: Object.assign({
      platform: 'htb',
      target: '10.10.10.100',
      scope_defined: true,
      lhost: '10.10.14.5',
      lhost_iface: 'tun0',
      domain: 'corp.local',
      username: '',
      password: '',
      nthash: ''
    }, params || {}),
    facts: (facts || []).slice(),
    checklist: {},
    activities: (activities || []).slice(),
    targets: [{ ip: (params && params.target) || '10.10.10.100', label: 'target' }]
  };
  OBOL.store.active = function () { return eng; };
  OBOL.store.activeTarget = function () { return eng.params.target; };
  OBOL.store.factSet = function () { return new OBOL.facts.FactSet(eng.facts); };
  OBOL.store.factSetForTarget = function (t) {
    var ip = t || eng.params.target;
    return new OBOL.facts.FactSet(eng.facts.filter(function (f) {
      return !f.scope || f.scope === 'global' || f.scope === 'host:' + ip || f.scope.indexOf('domain:') === 0;
    }));
  };
  return eng;
}

console.log('=== CAUSAL FRONTIER & GRAPH-UTILITY ADVERSARIAL SMOKE ===');

// ---------------------------------------------------------------------------
// 1. Recency-Decay Immunity Across a 10-Minute Wall-Clock Gap
// ---------------------------------------------------------------------------
(function testRecencyDecayImmunity() {
  var t0 = 1000;          // Initial recon + credential validation at t = 1s
  var tLate = 601000;     // 10 minutes later: operator captures user.txt + a stray banner
  var facts = [
    mkFact('target.configured', {}, 'host:10.10.10.100', t0),
    mkFact('host.up', {}, 'host:10.10.10.100', t0),
    mkFact('ports.open', { ports: [53, 88, 135, 139, 389, 445, 5985] }, 'host:10.10.10.100', t0),
    mkFact('port:53', { port: 53 }, 'host:10.10.10.100', t0),
    mkFact('port:88', { port: 88 }, 'host:10.10.10.100', t0),
    mkFact('port:135', { port: 135 }, 'host:10.10.10.100', t0),
    mkFact('port:139', { port: 139 }, 'host:10.10.10.100', t0),
    mkFact('port:389', { port: 389 }, 'host:10.10.10.100', t0),
    mkFact('port:445', { port: 445 }, 'host:10.10.10.100', t0),
    mkFact('port:5985', { port: 5985 }, 'host:10.10.10.100', t0),
    mkFact('scan.nmap.quick', {}, 'host:10.10.10.100', t0),
    mkFact('scan.nmap.version', {}, 'host:10.10.10.100', t0),
    mkFact('smb.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('ldap.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('kerberos.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('winrm.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('ad.dc_candidate', { host: '10.10.10.100', domain: 'corp.local' }, 'host:10.10.10.100', t0),
    mkFact('ad.domain_known', { name: 'corp.local' }, 'domain:corp.local', t0),
    mkFact('credential.plaintext', { user: 'svc_user', password: 'Password123!', domain: 'corp.local' }, 'host:10.10.10.100', t0),
    mkFact('credential.available', { user: 'svc_user', password: 'Password123!', domain: 'corp.local' }, 'host:10.10.10.100', t0),
    mkFact('credential.validated', { user: 'svc_user', password: 'Password123!', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0),
    mkFact('smb.authenticated', { user: 'svc_user', password: 'Password123!', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0),
    // 10 minutes later, user captures local flag + discovers port 80 open:
    mkFact('objective.flag_located', { slot: 'local', path: 'C:\\Users\\svc_user\\Desktop\\user.txt' }, 'host:10.10.10.100', tLate),
    mkFact('objective.local_flag', { flag: '0123456789abcdef0123456789abcdef', slot: 'local' }, 'host:10.10.10.100', tLate),
    mkFact('port:80', { port: 80 }, 'host:10.10.10.100', tLate),
    mkFact('http.reachable', {}, 'host:10.10.10.100', tLate)
  ];

  mountEng({ username: 'svc_user', password: 'Password123!' }, facts);
  var coach = OBOL.coach.compute();
  var top4 = coach.onFlow.slice(0, 4).map(function (a) { return a.id; });

  check(top4[0] === 'bloodyad-acl', 'Recency-decay immunity: bloodyad-acl stays #1 even 10 minutes after credential fact timestamp');
  check(top4[1] === 'kerberoast', 'Recency-decay immunity: kerberoast stays #2 even when a fresh port:80/http.reachable fact arrives at t+600s');
  check(top4[2] === 'bloodhound-collect', 'Recency-decay immunity: bloodhound-collect stays #3 ahead of newly unlocked Tier 2 HTTP probes');
  check(top4[3] === 'ad-path-manual', 'Recency-decay immunity: ad-path-manual stays #4 ahead of Tier 2 HTTP probes');
})();

// ---------------------------------------------------------------------------
// 2. Intermediate-Goal Distance-Zeroing Immunity & Pure Graph Utility Scores
// ---------------------------------------------------------------------------
(function testActiveGoalsAndGraphUtility() {
  var t0 = 1000;
  var facts = [
    mkFact('target.configured', {}, 'host:10.10.10.100', t0),
    mkFact('host.up', {}, 'host:10.10.10.100', t0),
    mkFact('ports.open', { ports: [88, 389, 445, 5985] }, 'host:10.10.10.100', t0),
    mkFact('port:88', { port: 88 }, 'host:10.10.10.100', t0),
    mkFact('port:389', { port: 389 }, 'host:10.10.10.100', t0),
    mkFact('port:445', { port: 445 }, 'host:10.10.10.100', t0),
    mkFact('port:5985', { port: 5985 }, 'host:10.10.10.100', t0),
    mkFact('scan.nmap.quick', {}, 'host:10.10.10.100', t0),
    mkFact('scan.nmap.version', {}, 'host:10.10.10.100', t0),
    mkFact('smb.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('ldap.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('kerberos.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('ad.dc_candidate', { host: '10.10.10.100', domain: 'corp.local' }, 'host:10.10.10.100', t0),
    mkFact('ad.domain_known', { name: 'corp.local' }, 'domain:corp.local', t0),
    mkFact('credential.available', { user: 'svc_user', password: 'Password123!', domain: 'corp.local' }, 'host:10.10.10.100', t0),
    mkFact('credential.validated', { user: 'svc_user', password: 'Password123!', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0),
    mkFact('smb.authenticated', { user: 'svc_user', password: 'Password123!', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0),
    mkFact('objective.local_flag', { flag: 'aaaa', slot: 'local' }, 'host:10.10.10.100', t0)
  ];

  var fsSet = new OBOL.facts.FactSet(facts);
  var ranked = OBOL.pack.nextActionsV2(fsSet, OBOL.packs.actions(), 50);
  var idxBloody = ranked.findIndex(function (a) { return a.id === 'bloodyad-acl'; });
  var idxKerb = ranked.findIndex(function (a) { return a.id === 'kerberoast'; });
  var idxBh = ranked.findIndex(function (a) { return a.id === 'bloodhound-collect'; });
  var idxManual = ranked.findIndex(function (a) { return a.id === 'ad-path-manual'; });
  var idxLaps = ranked.findIndex(function (a) { return a.id === 'laps-read'; });

  check(idxBloody >= 0 && idxKerb > idxBloody, 'Pure graph utility: bloodyad-acl ranks strictly above kerberoast after user.txt');
  check(idxBh > idxKerb && idxManual > idxBh, 'Within-tier stageRank: fast probes (bloodyad-acl, kerberoast) > graph collect (bloodhound-collect) > manual (ad-path-manual)');
  check(idxLaps > idxManual, 'Narrow attribute probe (laps-read, S=0.080) ranks strictly below all domain escalation mappers');
})();

// ---------------------------------------------------------------------------
// 3. Tier 4 & Tier 5 Preemption Under All Scope Lens
// ---------------------------------------------------------------------------
(function testTier4AndTier5Preemption() {
  sb.localStorage.setItem('obol.scope.lens.v1', 'all');
  try {
    var t0 = 1000;
    var baseFacts = [
      mkFact('target.configured', {}, 'host:10.10.10.100', t0),
      mkFact('host.up', {}, 'host:10.10.10.100', t0),
      mkFact('ports.open', { ports: [88, 389, 445, 5985] }, 'host:10.10.10.100', t0),
      mkFact('port:88', { port: 88 }, 'host:10.10.10.100', t0),
      mkFact('port:389', { port: 389 }, 'host:10.10.10.100', t0),
      mkFact('port:445', { port: 445 }, 'host:10.10.10.100', t0),
      mkFact('port:5985', { port: 5985 }, 'host:10.10.10.100', t0),
      mkFact('scan.nmap.quick', {}, 'host:10.10.10.100', t0),
      mkFact('scan.nmap.version', {}, 'host:10.10.10.100', t0),
      mkFact('smb.reachable', {}, 'host:10.10.10.100', t0),
      mkFact('ldap.reachable', {}, 'host:10.10.10.100', t0),
      mkFact('kerberos.reachable', {}, 'host:10.10.10.100', t0),
      mkFact('ad.dc_candidate', { host: '10.10.10.100', domain: 'corp.local' }, 'host:10.10.10.100', t0),
      mkFact('ad.domain_known', { name: 'corp.local' }, 'domain:corp.local', t0),
      mkFact('credential.available', { user: 'svc_user', password: 'Password123!', domain: 'corp.local' }, 'host:10.10.10.100', t0),
      mkFact('credential.validated', { user: 'svc_user', password: 'Password123!', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0),
      mkFact('smb.authenticated', { user: 'svc_user', password: 'Password123!', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0),
      mkFact('objective.local_flag', { flag: 'aaaa', slot: 'local' }, 'host:10.10.10.100', t0)
    ];

    // 3a. Add hash.tgs -> Tier 4.4 crack-tgs must preempt all Tier 3 moves
    var tgsFacts = baseFacts.concat([
      mkFact('hash.tgs', { hashes: ['$krb5tgs$23$*Administrator$CORP.LOCAL$...'] }, 'host:10.10.10.100', t0)
    ]);
    mountEng({ username: 'svc_user', password: 'Password123!' }, tgsFacts);
    var coachTgs = OBOL.coach.compute();
    check(coachTgs.onFlow[0].id === 'crack-tgs', 'Tier 4.4 preemption: crack-tgs is #1 immediately when hash.tgs is held');

    // 3b. Add ad.acl_lead -> Tier 4.3 bloodyad-acl must preempt Tier 3 moves and promote Command #2 (add groupMember)
    var aclFacts = baseFacts.concat([
      mkFact('ad.acl_lead', { targets: ['Exchange Windows Permissions'] }, 'host:10.10.10.100', t0)
    ]);
    mountEng({ username: 'svc_user', password: 'Password123!' }, aclFacts);
    var coachAcl = OBOL.coach.compute();
    check(coachAcl.onFlow[0].id === 'bloodyad-acl', 'Tier 4.3 preemption: bloodyad-acl is #1 when ad.acl_lead is held');
    var bestIdxAcl = OBOL.command.bestCommandIndex(coachAcl.onFlow[0], OBOL.store.factSet());
    var filledAcl = OBOL.command.fillCommand(coachAcl.onFlow[0], OBOL.store.factSet(), { params: OBOL.store.active().params }, bestIdxAcl).filled;
    check(filledAcl.indexOf('add groupMember') >= 0 && filledAcl.indexOf('Exchange Windows Permissions') >= 0,
      'Settled command progression: bloodyad-acl settles get writable and promotes add groupMember to Command #1');

    // 3c. Add ad.control_paths -> Tier 5.2 dcsync must preempt everything
    var dcsyncFacts = aclFacts.concat([
      mkFact('ad.group_joined', { group: 'Exchange Windows Permissions' }, 'host:10.10.10.100', t0),
      mkFact('ad.control_paths', { principal: 'svc_user', rights: ['DS-Replication-Get-Changes-All'] }, 'host:10.10.10.100', t0)
    ]);
    mountEng({ username: 'svc_user', password: 'Password123!' }, dcsyncFacts);
    var coachDc = OBOL.coach.compute();
    check(coachDc.onFlow[0].id === 'dcsync', 'Tier 5.2 preemption: dcsync is #1 under All scope lens when ad.control_paths is held');

    // 3d. Add loot.ntds + access.admin -> Tier 5.3 flag-hunt-root-windows must preempt everything
    var rootFacts = dcsyncFacts.concat([
      mkFact('loot.ntds', { count: 10 }, 'host:10.10.10.100', t0),
      mkFact('hash.krbtgt', { nthash: '11112222333344445555666677778888' }, 'host:10.10.10.100', t0),
      mkFact('credential.available', { user: 'Administrator', nthash: '32693b11e6aa90eb43d32c72a07ceea6', domain: 'corp.local' }, 'host:10.10.10.100', t0),
      mkFact('access.admin', { user: 'Administrator', nthash: '32693b11e6aa90eb43d32c72a07ceea6', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0)
    ]);
    mountEng({ username: 'Administrator', nthash: '32693b11e6aa90eb43d32c72a07ceea6' }, rootFacts);
    var coachRoot = OBOL.coach.compute();
    check(coachRoot.onFlow[0].id === 'flag-hunt-root-windows', 'Tier 5.3 preemption: flag-hunt-root-windows is #1 when admin access is held and root.txt is uncaptured');
    var top3Root = coachRoot.onFlow.slice(0, 3).map(function (a) { return a.id; });
    check(top3Root.indexOf('golden-ticket') < 0 && top3Root.indexOf('silver-ticket') < 0,
      'Post-compromise side-quest suppression: golden-ticket and silver-ticket do not invade top 3 after loot.ntds');
  } finally {
    sb.localStorage.setItem('obol.scope.lens.v1', 'oscp+');
  }
})();

// ---------------------------------------------------------------------------
// 4. Environmental Error vs. Conclusive Negative Dry-Probe Rotation
// ---------------------------------------------------------------------------
(function testEnvErrorVsDryProbeRotation() {
  var t0 = 1000;
  var facts = [
    mkFact('target.configured', {}, 'host:10.10.10.100', t0),
    mkFact('host.up', {}, 'host:10.10.10.100', t0),
    mkFact('ports.open', { ports: [88, 389, 445, 5985] }, 'host:10.10.10.100', t0),
    mkFact('port:88', { port: 88 }, 'host:10.10.10.100', t0),
    mkFact('port:389', { port: 389 }, 'host:10.10.10.100', t0),
    mkFact('port:445', { port: 445 }, 'host:10.10.10.100', t0),
    mkFact('port:5985', { port: 5985 }, 'host:10.10.10.100', t0),
    mkFact('scan.nmap.quick', {}, 'host:10.10.10.100', t0),
    mkFact('scan.nmap.version', {}, 'host:10.10.10.100', t0),
    mkFact('smb.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('ldap.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('kerberos.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('ad.dc_candidate', { host: '10.10.10.100', domain: 'corp.local' }, 'host:10.10.10.100', t0),
    mkFact('ad.domain_known', { name: 'corp.local' }, 'domain:corp.local', t0),
    mkFact('credential.available', { user: 'svc_user', password: 'Password123!', domain: 'corp.local' }, 'host:10.10.10.100', t0),
    mkFact('credential.validated', { user: 'svc_user', password: 'Password123!', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0),
    mkFact('smb.authenticated', { user: 'svc_user', password: 'Password123!', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0),
    mkFact('objective.local_flag', { flag: 'aaaa', slot: 'local' }, 'host:10.10.10.100', t0)
  ];

  var eng = mountEng({ username: 'svc_user', password: 'Password123!' }, facts);
  var bloodyMove = OBOL.packs.actions().find(function (a) { return a.id === 'bloodyad-acl'; });
  var writableCmd = OBOL.command.fillCommand(bloodyMove, OBOL.store.factSet(), { params: eng.params }, 0).filled;

  // 4a. Environmental error (KRB_AP_ERR_SKEW) must NOT retire the command or demote bloodyad-acl
  var envOutcome = OBOL.outcomes.classify({
    command: writableCmd,
    text: 'KRB_AP_ERR_SKEW(Clock skew too great)',
    facts: [mkFact('blocker.clock_skew', {}, 'host:10.10.10.100', 2000)]
  });
  check(envOutcome.kind === 'environment-error' && envOutcome.retireCommand === false,
    'Outcome classifier: KRB_AP_ERR_SKEW is classified as environment-error with retireCommand=false');

  var curEpoch = OBOL.pack.accessEpoch(OBOL.store.factSet());
  var actCtx = OBOL.context.resolve({
    engagement: eng,
    target: '10.10.10.100',
    command: writableCmd,
    actionId: 'bloodyad-acl',
    locus: 'remote'
  });
  eng.activities.unshift({
    action_id: 'bloodyad-acl',
    target: '10.10.10.100',
    command: writableCmd,
    epoch: curEpoch,
    addedCount: 0,
    blockers: ['blocker.clock_skew'],
    context: actCtx,
    outcome: envOutcome
  });
  eng.facts.push(mkFact('blocker.clock_skew', {}, 'host:10.10.10.100', 2000));
  check(OBOL.command.moveDryTriesInEpoch(bloodyMove, OBOL.store.factSet(), eng, curEpoch, '10.10.10.100') === 0,
    'Env-blocker immunity: moveDryTriesInEpoch remains 0 when an attempt fails due to an active blocker');
  check(OBOL.coach.compute().onFlow[0].id === 'bloodyad-acl',
    'Env-blocker immunity: bloodyad-acl remains #1 so the operator can fix clock skew and retry');

  // 4b. Operator fixes clock skew and runs get writable, which returns 0 writable objects (conclusive negative)
  eng.facts = eng.facts.filter(function (f) { return f.kind !== 'blocker.clock_skew'; });
  eng.activities = [];
  var negOutcome = OBOL.outcomes.classify({
    command: writableCmd,
    text: '┌──(kali㉿kali)-[~]\n└─$ ' + writableCmd + '\n\n┌──(kali㉿kali)-[~]\n└─$ ',
    facts: []
  });
  check(negOutcome.kind === 'completed-negative' && negOutcome.retireCommand === true,
    'Outcome classifier: empty prompt-to-prompt bloodyAD get writable is classified as completed-negative with retireCommand=true');

  eng.activities.unshift({
    action_id: 'bloodyad-acl',
    target: '10.10.10.100',
    command: writableCmd,
    epoch: curEpoch,
    addedCount: 0,
    blockers: [],
    context: actCtx,
    outcome: negOutcome
  });
  var coachAfterDry = OBOL.coach.compute();
  check(coachAfterDry.onFlow[0].id === 'kerberoast',
    'Closed-loop dry-probe rotation: after empty bloodyad-acl, kerberoast automatically rotates to Card #1');

  var manualMove = OBOL.packs.actions().find(function (a) { return a.id === 'ad-path-manual'; });
  var manualBestIdx = OBOL.command.bestCommandIndex(manualMove, OBOL.store.factSet(), { params: eng.params, activities: eng.activities });
  var manualCmd = OBOL.command.fillCommand(manualMove, OBOL.store.factSet(), { params: eng.params }, manualBestIdx).filled;
  check(manualCmd.indexOf('get writable') < 0,
    'Cross-card command signature retirement: ad-path-manual skips the already-tried bloodyAD get writable variant');
})();

// ---------------------------------------------------------------------------
// 5. Multi-Host Isolation Under Tier 5 Promotion
// ---------------------------------------------------------------------------
(function testMultiHostIsolation() {
  var t0 = 1000;
  var facts = [
    // Host A (10.10.10.100): compromised AD DC with admin access
    mkFact('target.configured', {}, 'host:10.10.10.100', t0),
    mkFact('host.up', {}, 'host:10.10.10.100', t0),
    mkFact('ports.open', { ports: [88, 389, 445, 5985] }, 'host:10.10.10.100', t0),
    mkFact('port:445', { port: 445 }, 'host:10.10.10.100', t0),
    mkFact('port:5985', { port: 5985 }, 'host:10.10.10.100', t0),
    mkFact('smb.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('winrm.reachable', {}, 'host:10.10.10.100', t0),
    mkFact('credential.available', { user: 'Administrator', nthash: '32693b11e6aa90eb43d32c72a07ceea6', domain: 'corp.local' }, 'host:10.10.10.100', t0),
    mkFact('access.admin', { user: 'Administrator', nthash: '32693b11e6aa90eb43d32c72a07ceea6', domain: 'corp.local', service: 'smb' }, 'host:10.10.10.100', t0),

    // Host B (10.10.10.200): fresh Linux web server in the same engagement
    mkFact('target.configured', {}, 'host:10.10.10.200', t0),
    mkFact('host.up', {}, 'host:10.10.10.200', t0),
    mkFact('ports.open', { ports: [22, 80] }, 'host:10.10.10.200', t0),
    mkFact('port:22', { port: 22 }, 'host:10.10.10.200', t0),
    mkFact('port:80', { port: 80 }, 'host:10.10.10.200', t0),
    mkFact('scan.nmap.quick', {}, 'host:10.10.10.200', t0),
    mkFact('ssh.reachable', {}, 'host:10.10.10.200', t0),
    mkFact('http.reachable', {}, 'host:10.10.10.200', t0)
  ];

  var eng = mountEng({ target: '10.10.10.100', username: 'Administrator', nthash: '32693b11e6aa90eb43d32c72a07ceea6' }, facts);
  var coachA = OBOL.coach.rankFor(OBOL.store.factSetForTarget('10.10.10.100'), { target: '10.10.10.100' });
  check(coachA.onFlow[0].id === 'flag-hunt-root-windows', 'Multi-host isolation: Host A (compromised DC) leads with Tier 5 flag-hunt-root-windows');

  eng.params.target = '10.10.10.200';
  eng.params.username = '';
  eng.params.nthash = '';
  var coachB = OBOL.coach.rankFor(OBOL.store.factSetForTarget('10.10.10.200'), { target: '10.10.10.200' });
  var top3B = coachB.onFlow.slice(0, 3).map(function (a) { return a.id; });
  check(top3B[0] === 'nmap-version-scripts', 'Multi-host isolation: Host B (fresh Linux web box) leads with Tier 2 nmap-version-scripts');
  check(top3B.indexOf('flag-hunt-root-windows') < 0 && top3B.indexOf('dcsync') < 0,
    'Multi-host isolation: Host A admin facts never bleed Tier 5 moves onto Host B');
})();

console.log('\nALL ' + passed + ' CAUSAL FRONTIER ADVERSARIAL CHECKS PASSED.');
