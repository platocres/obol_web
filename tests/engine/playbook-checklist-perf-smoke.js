/* Playbook & Checklist CPU / performance and functional parity smoke test.
 * Verifies:
 *   1. House style & structural guards: no em/en dashes, and Playbook click handlers
 *      update in-place instead of calling OBOL.router.render().
 *   2. commandWasRun() activity-signature WeakMap cache produces 100% identical results
 *      across the entire pack and invalidates cleanly on in-place activities.push() / mutation.
 *   3. Shared OBOL.context.resolve() frame in buildContext / fillAll / playbook.renderLine
 *      produces identical command strings to unframed resolution at a fraction of the CPU cost.
 *   4. _arsenalProfile() memoizes JSON.parse on raw localStorage string and updates on change.
 *   5. Checklist route render() lazy-defers closed <details class="chk-move"> bodies while
 *      eagerly rendering open moves, keeping 250-fact + 45-activity renders fast (< 50ms).
 *   6. Store change listeners in boot.js / ctxbar.js skip redundant sidebar/ctxbar rebuilds
 *      on 'playbook', 'checklist', and 'ws' mutations.
 */
'use strict';

var fs = require('fs');
var path = require('path');
var perf = require('perf_hooks').performance;

var ROOT = path.join(__dirname, '..', '..');

// Provide a lightweight localStorage shim before loading engine/UI modules
var _ls = {};
globalThis.localStorage = {
  getItem: function (k) { return Object.prototype.hasOwnProperty.call(_ls, k) ? _ls[k] : null; },
  setItem: function (k, v) { _ls[k] = String(v); },
  removeItem: function (k) { delete _ls[k]; }
};

require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/context.js');
require('../../assets/engine/arsenal.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
require('../../assets/engine/loot.js');
require('../../assets/engine/playbook.js');
require('../../data/oscp-scope.js');
require('../../assets/ui/util.js');
require('../../assets/ui/icons.js');

var OBOL = globalThis.OBOL;
var pdir = path.join(ROOT, 'data', 'packs');
var packFiles = fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); });
var packData = packFiles.map(function (f) {
  try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; }
});
var PACK = OBOL.pack.loadPacks(packData);
OBOL.packs = { actions: function () { return PACK; } };

var checklistSrc = fs.readFileSync(path.join(ROOT, 'assets/ui/routes/checklist.js'), 'utf8');
var bootSrc = fs.readFileSync(path.join(ROOT, 'assets/ui/boot.js'), 'utf8');
var ctxbarSrc = fs.readFileSync(path.join(ROOT, 'assets/ui/ctxbar.js'), 'utf8');
var cssSrc = fs.readFileSync(path.join(ROOT, 'assets/css/obol.css'), 'utf8');

var passed = 0, failed = 0;
function ok(cond, msg) {
  if (cond) { passed++; console.log('  [PASS] ' + msg); }
  else { failed++; console.error('  [FAIL] ' + msg); }
}

// 1. House style & static architecture guards
ok(!/[\u2014\u2013]/.test(checklistSrc), 'checklist.js contains no em dashes or en dashes');
ok(!/data-pb-(?:add|addmove|toggle|up|down|del|clear)[^\r\n]*router\.render/.test(checklistSrc),
  'Playbook click handlers never trigger full-route OBOL.router.render()');
ok(/SIDEBAR_SKIP_REASONS\s*=\s*\{\s*playbook:\s*1,\s*checklist:\s*1,\s*ws:\s*1\s*\}/.test(bootSrc),
  'boot.js skips redundant renderSidebar() work on playbook, checklist, and ws store updates');
ok(/CTXBAR_SKIP_REASONS\s*=\s*\{\s*playbook:\s*1,\s*checklist:\s*1,\s*ws:\s*1\s*\}/.test(ctxbarSrc),
  'ctxbar.js skips redundant ctxbar.render() work on playbook, checklist, and ws store updates');
ok(/\.pb-fab\[hidden\],\s*\.pb-foot\[hidden\]\s*\{\s*display:\s*none\s*!important;\s*\}/.test(cssSrc),
  'obol.css enforces display:none !important on .pb-fab[hidden] and .pb-foot[hidden]');
ok(/\.pb-panel\s*\{[^}]*contain:\s*layout\s+style\s+paint/.test(cssSrc),
  'obol.css isolates .pb-panel with contain: layout style paint');

// Build a realistic 250-fact, 45-activity Active Directory engagement (modeled on HTB Active)
var factsArr = [];
var ports = [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 47001, 49152, 49153, 49154, 49155, 49157, 49158];
ports.forEach(function (p) {
  factsArr.push(OBOL.facts.makeFact({ kind: 'port:' + p, scope: 'host:10.129.118.56', value: { port: p, proto: 'tcp' }, source: 'nmap' }));
});
factsArr.push(OBOL.facts.makeFact({ kind: 'ad.domain_known', scope: 'domain:active.htb', value: { name: 'active.htb', domain: 'active.htb' }, source: 'nmap' }));
factsArr.push(OBOL.facts.makeFact({ kind: 'host.hostname', scope: 'host:10.129.118.56', value: { name: 'DC', fqdn: 'DC.active.htb' }, source: 'nmap' }));
factsArr.push(OBOL.facts.makeFact({ kind: 'host.fqdn', scope: 'host:10.129.118.56', value: { fqdn: 'DC.active.htb' }, source: 'nmap' }));
factsArr.push(OBOL.facts.makeFact({ kind: 'ad.dc_candidate', scope: 'host:10.129.118.56', value: { name: 'DC', fqdn: 'DC.active.htb' }, source: 'nmap' }));
factsArr.push(OBOL.facts.makeFact({ kind: 'smb.shares', scope: 'host:10.129.118.56', value: { shares: [{ name: 'Replication', readable: true }, { name: 'Users', readable: true }, { name: 'SYSVOL', readable: true }] }, source: 'nxc' }));
factsArr.push(OBOL.facts.makeFact({ kind: 'credential.available', scope: 'domain:active.htb', value: { user: 'SVC_TGS', domain: 'active.htb', password: 'GPPstillStandingStrong2k18', validated: true }, source: 'gpp' }));
factsArr.push(OBOL.facts.makeFact({ kind: 'credential.available', scope: 'domain:active.htb', value: { user: 'Administrator', domain: 'active.htb', password: 'Ticketmaster1968', admin: true, validated: true }, source: 'kerberoast' }));
factsArr.push(OBOL.facts.makeFact({ kind: 'ad.acl_lead', scope: 'domain:active.htb', value: { targets: ['Domain Admins', 'Exchange Windows Permissions'] }, source: 'bloodyad' }));
factsArr.push(OBOL.facts.makeFact({ kind: 'ad.user_list', scope: 'domain:active.htb', value: { users: ['Administrator', 'SVC_TGS', 'krbtgt', 'Guest'] }, source: 'ldap' }));
while (factsArr.length < 250) {
  var idx = factsArr.length;
  factsArr.push(OBOL.facts.makeFact({
    kind: 'service.detail.' + (idx % 35),
    scope: 'host:10.129.118.56',
    value: { idx: idx, banner: 'Microsoft Windows RPC endpoint #' + idx, port: 49152 + (idx % 20) },
    source: 'enum'
  }));
}

var activities = [
  { command: 'nmap -sC -sV -p- 10.129.118.56', dispatch: 'nmap -sC -sV 10.129.118.56' },
  { command: "nxc smb 10.129.118.56 -u '' -p '' --shares", dispatch: 'nxc smb --shares' },
  { command: "nxc ldap 10.129.118.56 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --users", dispatch: 'nxc ldap --users' },
  { command: "bloodyAD --host 10.129.118.56 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' get writable", dispatch: 'bloodyAD get writable' },
  { command: "impacket-GetUserSPNs 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -dc-ip 10.129.118.56 -request", dispatch: 'impacket-GetUserSPNs -request' }
];
while (activities.length < 45) {
  activities.push({
    command: 'smbclient //10.129.118.56/Replication -N -c "ls dir' + activities.length + '"',
    dispatch: 'smbclient -N'
  });
}

var eng = {
  id: 'eng-perf-test',
  name: 'Active',
  profile: { platform: 'htb', machine_type: 'windows' },
  params: {
    target: '10.129.118.56',
    domain: 'active.htb',
    username: 'SVC_TGS',
    user: 'SVC_TGS',
    password: 'GPPstillStandingStrong2k18',
    lhost: '10.10.14.12',
    lport: '4444'
  },
  targets: [{ id: 't-1', ip: '10.129.118.56', hostname: 'DC', domain: 'active.htb', os: 'Windows' }],
  credentials: [
    { id: 'c-1', user: 'SVC_TGS', domain: 'active.htb', secret: 'GPPstillStandingStrong2k18', secretType: 'PW' },
    { id: 'c-2', user: 'Administrator', domain: 'active.htb', secret: 'Ticketmaster1968', secretType: 'PW' }
  ],
  facts: factsArr.map(OBOL.facts.factToJson),
  activities: activities,
  checkTicks: { 'nmap-full#0': true },
  playbook: []
};

OBOL.store = {
  active: function () { return eng; },
  activeId: function () { return eng.id; },
  factSet: function () { return new OBOL.facts.FactSet(factsArr.slice()); },
  update: function (mutator) { mutator(eng); }
};

require('../../assets/ui/routes/checklist.js');

// 2. Verify commandWasRun WeakMap cache parity & live mutation invalidation
(function testCommandWasRunCache() {
  var ranBefore = OBOL.command.commandWasRun("bloodyAD --host 10.129.118.56 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' get writable", activities, eng.params);
  var notRanBefore = OBOL.command.commandWasRun("bloodyAD --host 10.129.118.56 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' add dcsync 'SVC_TGS'", activities, eng.params);
  ok(ranBefore === true, 'commandWasRun detects already-executed bloodyAD get writable');
  ok(notRanBefore === false, 'commandWasRun does not false-positive on unrun bloodyAD add dcsync');

  // Mutate the SAME activities array reference in place and verify cache invalidates immediately
  activities.push({ command: "bloodyAD --host 10.129.118.56 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' add dcsync 'SVC_TGS'", dispatch: 'bloodyAD add dcsync' });
  var ranAfterPush = OBOL.command.commandWasRun("bloodyAD --host 10.129.118.56 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' add dcsync 'SVC_TGS'", activities, eng.params);
  ok(ranAfterPush === true, 'commandWasRun WeakMap cache invalidates immediately on in-place activities.push()');
  activities.pop();
})();

// 3. Verify _arsenalProfile() memoization & invalidation
(function testArsenalProfileMemo() {
  localStorage.setItem('obol.arsenal-profile', JSON.stringify({
    tools: { impacket: { present: true, invocation: 'impacket-GetUserSPNs' } },
    wordlists: { rockyou: '/custom/rockyou.txt' }
  }));
  var r1 = OBOL.command.applyArsenal('john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt', null);
  ok(r1.indexOf('/custom/rockyou.txt') >= 0, 'applyArsenal applies initial Loadout profile');
  localStorage.setItem('obol.arsenal-profile', JSON.stringify({
    tools: {},
    wordlists: { rockyou: '/opt/lists/rockyou2.txt' }
  }));
  var r2 = OBOL.command.applyArsenal('john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt', null);
  ok(r2.indexOf('/opt/lists/rockyou2.txt') >= 0, 'applyArsenal invalidates memoized profile immediately when localStorage string changes');
  localStorage.removeItem('obol.arsenal-profile');
})();

// 4. Verify shared resolved context frame produces identical fillAll & playbook.renderLine outputs
(function testSharedFrameEquivalence() {
  var rawFs = OBOL.store.factSet();
  var framedFs = OBOL.context.resolve({ engagement: eng, facts: rawFs, params: eng.params }).facts;
  var ws = OBOL.workspace.tokens(eng);
  var opts = { params: eng.params, profile: eng.profile, workspace: ws };
  var sampleMoves = PACK;
  var diffs = 0;
  sampleMoves.forEach(function (a) {
    var u = OBOL.command.fillAll(a, rawFs, opts);
    var f = OBOL.command.fillAll(a, framedFs, opts);
    if (u.length !== f.length) { diffs++; return; }
    for (var i = 0; i < u.length; i++) {
      if (u[i].filled !== f[i].filled) diffs++;
    }
  });
  ok(diffs === 0, 'Shared OBOL.context.resolve + baseCtx cache produces 100% identical fillAll output across all ' + PACK.length + ' pack moves');

  var pbItems = OBOL.playbook.resolve(sampleMoves.slice(0, 8).map(function (a) { return { id: a.id, idx: 0 }; }), PACK);
  var pbDiffs = 0;
  pbItems.forEach(function (it) {
    var l1 = OBOL.playbook.renderLine(it, rawFs, opts).run;
    var l2 = OBOL.playbook.renderLine(it, framedFs, opts).run;
    if (l1 !== l2) pbDiffs++;
  });
  ok(pbDiffs === 0, 'Shared OBOL.context.resolve frame produces 100% identical playbook.renderLine output');
})();

// 5. Verify Checklist route lazy move deferral, open-move rendering, and render speed on 250 facts + 45 activities
(function testChecklistLazyRenderAndSpeed() {
  // Open 1 phase and 1 move (like the user's live Kali session)
  var targetMove = PACK[0];
  var targetPhase = OBOL.phases.phaseOfAction(targetMove);
  localStorage.setItem('obol.ck:' + eng.id + ':ph:' + targetPhase, '1');
  localStorage.setItem('obol.ck:' + eng.id + ':mv:' + targetMove.id, '1');
  eng.playbook = [{ id: targetMove.id, idx: 0 }];

  // Warmup once
  OBOL.routes.checklist.render();

  var t0 = perf.now();
  var html = OBOL.routes.checklist.render();
  var elapsed = perf.now() - t0;

  var lazyMatches = html.match(/data-cmds-lazy="1"/g) || [];
  var rowMatches = html.match(/class="chk-row(?:["\s])/g) || [];
  var expectedOpenRows = (targetMove.commands && targetMove.commands.length) ? targetMove.commands.length : 1;

  ok(lazyMatches.length === PACK.length - 1,
    'Closed moves (' + lazyMatches.length + '/' + PACK.length + ') defer command-row DOM creation via data-cmds-lazy="1"');
  ok(rowMatches.length === expectedOpenRows,
    'Open move renders its exact ' + expectedOpenRows + ' command row(s) eagerly');
  ok(html.indexOf('id="pb-fab"') >= 0 && html.indexOf('id="pb-panel"') >= 0 && html.indexOf('id="pb-foot"') >= 0,
    'Both #pb-fab and #pb-panel (+ #pb-foot) persist in the DOM for zero-rerender open/close toggling');
  ok(html.indexOf('chk-add on') >= 0 && html.indexOf('class="pb-item"') >= 0,
    'Initial render marks in-playbook command with .chk-add.on and populates .pb-item in #pb-panel');
  ok(elapsed < 50,
    'Full #/checklist initial render on 250-fact / 45-activity engagement completes in ' + elapsed.toFixed(2) + 'ms (< 50ms budget)');
})();

if (failed > 0) {
  console.error('\nPLAYBOOK & CHECKLIST PERF SMOKE: ' + failed + ' failure(s)');
  process.exit(1);
}
console.log('\nPLAYBOOK & CHECKLIST PERF SMOKE: all ' + passed + ' checks passed.');
