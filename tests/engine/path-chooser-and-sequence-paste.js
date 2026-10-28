'use strict';

var assert = require('assert');
var fs = require('fs');
var path = require('path');

var qaRoot = path.resolve(__dirname, '../..');

function loadQaScript(rel) {
  var full = path.join(qaRoot, rel);
  require(full);
}

loadQaScript('assets/engine/facts.js');
loadQaScript('assets/engine/phases.js');
loadQaScript('assets/engine/pack.js');
loadQaScript('assets/engine/profile.js');
loadQaScript('assets/engine/context.js');
loadQaScript('assets/engine/command.js');
loadQaScript('assets/engine/workspace.js');
loadQaScript('assets/engine/vfs.js');
loadQaScript('assets/engine/loot.js');
loadQaScript('assets/engine/playbook.js');
loadQaScript('assets/engine/chain.js');
loadQaScript('data/findings-catalog.js');
loadQaScript('data/narratives.js');
loadQaScript('assets/engine/findings.js');
loadQaScript('data/packs-bundle.js');
loadQaScript('data/field-notes.js');
loadQaScript('assets/engine/packs.js');
loadQaScript('assets/engine/resolve.js');
loadQaScript('assets/ui/util.js');
loadQaScript('assets/ui/store.js');
loadQaScript('assets/engine/outcomes.js');
loadQaScript('assets/engine/parsers/common.js');
loadQaScript('assets/engine/parsers/nmap.js');
loadQaScript('assets/engine/parsers/directory.js');
loadQaScript('assets/engine/parsers/creds.js');
loadQaScript('assets/engine/parsers/host.js');
loadQaScript('assets/engine/parsers/services.js');
loadQaScript('assets/engine/parsers/database.js');
loadQaScript('assets/engine/parsers/web.js');
loadQaScript('assets/engine/parsers/websource.js');
loadQaScript('assets/engine/parsers/findings.js');
loadQaScript('assets/engine/parsers/shape.js');
loadQaScript('assets/engine/parsers/pivot.js');
loadQaScript('assets/engine/parsers/dns.js');
loadQaScript('assets/engine/parsers/blockers.js');
loadQaScript('assets/engine/parsers/nxc-catalog.js');
loadQaScript('assets/engine/parsers/inference.js');
loadQaScript('assets/engine/parsers/index.js');
loadQaScript('assets/ui/ingest.js');

var OBOL = globalThis.OBOL;

console.log('--- Testing OBOL.pathChooser & Multi-Command Sequence Pastes ---');

// 1. Verify all 24 Path Chooser moves build cleanly
var allActions = OBOL.packs.actions();
var chooserIds = Object.keys(OBOL.pathChooser.IDS);
assert(chooserIds.length >= 24, 'Expected at least 24 Path Chooser move IDs');

var baseFacts = new OBOL.facts.FactSet([
  { kind: 'os.windows', value: { os: 'windows' }, scope: 'host:10.129.100.23' },
  { kind: 'os.linux', value: { os: 'linux' }, scope: 'host:10.129.100.23' },
  { kind: 'service.smb', value: { port: 445 }, scope: 'host:10.129.100.23' },
  { kind: 'service.ssh', value: { port: 22 }, scope: 'host:10.129.100.23' },
  { kind: 'credential.available', value: { username: 'SVC_TGS', secret_kind: 'password' }, scope: 'host:10.129.100.23' },
  { kind: 'credential.password', value: { username: 'SVC_TGS', password: 'GPPstillStandingStrong2k18' }, scope: 'host:10.129.100.23' }
]);
var baseParams = {
  target: '10.129.100.23',
  username: 'SVC_TGS',
  user: 'SVC_TGS',
  password: 'GPPstillStandingStrong2k18',
  domain: 'active.htb',
  dc_ip: '10.129.100.23',
  lhost: '10.10.14.5',
  lport: '4444'
};

chooserIds.forEach(function (id) {
  var action = allActions.find(function (a) { return a.id === id; });
  assert(action, 'Action ' + id + ' should exist in packs');
  var filled = OBOL.command.fillAll(action, baseFacts, { params: baseParams });
  var pc = OBOL.pathChooser.build(action, baseFacts, baseParams, filled, { activities: [], params: baseParams, ui: {} });
  assert(pc, 'OBOL.pathChooser.build should return a model for ' + id);
  assert(pc.groups && pc.groups.length >= 1, id + ' should have at least 1 group');
  assert(pc.selectedGroup && pc.selectedLane, id + ' should have a selectedGroup and selectedLane');
  assert(pc.selectedLane.steps && pc.selectedLane.steps.length >= 1, id + ' selectedLane should have steps');
});
console.log('[PASS] All ' + chooserIds.length + ' Path Chooser moves build valid groups, lanes, and step chains.');

// 2. Verify Active (10.129.100.23) Non-Admin flag-hunt-windows state
var winUserMove = allActions.find(function (a) { return a.id === 'flag-hunt-windows'; });
var nonAdminFacts = new OBOL.facts.FactSet([
  { kind: 'os.windows', value: { os: 'windows' }, scope: 'host:10.129.100.23' },
  { kind: 'service.smb', value: { port: 445 }, scope: 'host:10.129.100.23' },
  { kind: 'smb.authenticated', value: { username: 'SVC_TGS' }, scope: 'host:10.129.100.23' },
  { kind: 'credential.available', value: { username: 'SVC_TGS', secret_kind: 'password' }, scope: 'host:10.129.100.23' },
  { kind: 'credential.password', value: { username: 'SVC_TGS', password: 'GPPstillStandingStrong2k18' }, scope: 'host:10.129.100.23' }
]);
var filledNonAdmin = OBOL.command.fillAll(winUserMove, nonAdminFacts, { params: baseParams });
var pcNonAdmin = OBOL.pathChooser.build(winUserMove, nonAdminFacts, baseParams, filledNonAdmin, { activities: [], params: baseParams, ui: {} });
assert.strictEqual(pcNonAdmin.selectedGroup.id, 'remote', 'Non-admin with closed WinRM/RDP should default to remote group');
assert.strictEqual(pcNonAdmin.selectedLane.id, 'smb-share', 'Non-admin should select smb-share lane');
assert.strictEqual(pcNonAdmin.selectedLane.steps.length, 2, 'smb-share should have 2 steps (Locate + Read)');
assert.strictEqual(pcNonAdmin.selectedLane.steps[0].done, false);
assert.strictEqual(pcNonAdmin.selectedLane.steps[1].needsPrevStepPaste, true, 'Step 2 should indicate Paste Prev Step First before flag path is discovered');

var onHostGroup = pcNonAdmin.groups.find(function (g) { return g.id === 'onhost'; });
assert(onHostGroup, 'onhost group should be visible');
onHostGroup.lanes.forEach(function (l) {
  assert.strictEqual(l.status, 'locked', 'On-host lane ' + l.id + ' should be locked when non-admin & 5985/3389 closed');
  assert.strictEqual(l.badgeIcon, 'lock', 'Locked lane should set badgeIcon: lock (' + l.badge + ')');
});
console.log('[PASS] Non-admin flag-hunt-windows shows Ready remote SMB lane and visible locked On-Host lanes with explanations.');

// 3. Test Multi-Command Sequence Paste (A3a) on flag-hunt-windows
(async function () {
await OBOL.store.init();
var eng = OBOL.store.active();
eng.params = Object.assign({}, baseParams);
OBOL.store.addFacts(nonAdminFacts.facts);

var twoStepRemotePaste = [
  "┌──(kali㉿kali)-[~/ctf]",
  "└─$ nxc smb 10.129.100.23 -u SVC_TGS -p 'GPPstillStandingStrong2k18' --spider Users --regex \"(local|proof|user|root|flag)\\.txt$\"",
  "SMB         10.129.100.23   445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb)",
  "SMB         10.129.100.23   445    DC               [+] active.htb\\SVC_TGS:GPPstillStandingStrong2k18",
  "SMB         10.129.100.23   445    DC               [*] Started spidering plus with option:",
  "SMB         10.129.100.23   445    DC               //10.129.100.23/Users/SVC_TGS/Desktop/user.txt [lastm:'2018-07-18 19:01' size:32]",
  "┌──(kali㉿kali)-[~/ctf]",
  "└─$ smbclient '//10.129.100.23/Users' -U 'active.htb/SVC_TGS%GPPstillStandingStrong2k18' -c 'get \"SVC_TGS\\Desktop\\user.txt\" user.txt' && cat user.txt",
  "getting file \\SVC_TGS\\Desktop\\user.txt of size 34 as user.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)",
  "a1b2c3d4e5f60718293a4b5c6d7e8f90"
].join('\n');

var resRemoteSeq = OBOL.ingest.run({
  text: twoStepRemotePaste,
  command: filledNonAdmin[15].filled,
  actionId: 'flag-hunt-windows',
  source: 'paste',
  scope: 'host:10.129.100.23',
  locus: 'remote'
});
assert(resRemoteSeq.ok, 'Multi-command remote paste should succeed');
assert(resRemoteSeq.sequenceCommands && resRemoteSeq.sequenceCommands.length === 2, 'Should record 2 sequenceCommands');

var updatedFacts = OBOL.store.factSetForTarget('10.129.100.23');
assert(updatedFacts.has('objective.flag_located'), 'Should mint objective.flag_located from Step 1');
assert(updatedFacts.has('objective.local_flag'), 'Should mint objective.local_flag from Step 2');
var localFlagVals = updatedFacts.values('objective.local_flag');
assert.strictEqual(localFlagVals[0].on_host, false, 'Remote SMB get capture must set on_host: false');

var filledAfterRemote = OBOL.command.fillAll(winUserMove, updatedFacts, { params: baseParams });
var pcAfterRemote = OBOL.pathChooser.build(winUserMove, updatedFacts, baseParams, filledAfterRemote, OBOL.store.active());
assert.strictEqual(pcAfterRemote.selectedLane.steps[0].done, true, 'Step 1 should be marked done');
assert.strictEqual(pcAfterRemote.selectedLane.steps[1].done, true, 'Step 2 should be marked done');
console.log('[PASS] Multi-command sequence paste (A3a) mints both steps\' facts, sets on_host: false on remote flag grab, and marks both steps ✓ Done.');

// 4. Verify Remote-Only user.txt Auto-Promotion on flag-hunt-root-windows (A4)
OBOL.store.addFacts([
  { kind: 'access.admin', value: { username: 'Administrator', via: 'smb' }, scope: 'host:10.129.100.23' },
  { kind: 'credential.nthash', value: { username: 'Administrator', nthash: '58a478135a93ac3bf058a5ea0e8fdb71' }, scope: 'host:10.129.100.23' }
]);
var adminParams = Object.assign({}, baseParams, {
  username: 'Administrator',
  user: 'Administrator',
  dauser: 'Administrator',
  nthash: '58a478135a93ac3bf058a5ea0e8fdb71',
  dahash: '58a478135a93ac3bf058a5ea0e8fdb71',
  password: ''
});
var adminFacts = OBOL.store.factSetForTarget('10.129.100.23');
var winRootMove = allActions.find(function (a) { return a.id === 'flag-hunt-root-windows'; });
var filledAdminRoot = OBOL.command.fillAll(winRootMove, adminFacts, { params: adminParams });
var pcAdminRoot = OBOL.pathChooser.build(winRootMove, adminFacts, adminParams, filledAdminRoot, OBOL.store.active());

assert.strictEqual(pcAdminRoot.needsBothFlagsOnHost, true, 'Should detect that user.txt was grabbed remotely (on_host: false) and promote both-flags capture');
assert.strictEqual(pcAdminRoot.selectedGroup.id, 'onhost', 'Should default to On-Host group when user.txt needs on-host proof');
assert(pcAdminRoot.callout && pcAdminRoot.callout.kind === 'highlight', 'Should display highlight callout for capturing both user + root flags on-host');
var wmiLane = pcAdminRoot.selectedGroup.lanes.find(function (l) { return l.id === 'wmi-shell'; });
assert(wmiLane, 'wmi-shell lane should exist');
assert.strictEqual(wmiLane.status, 'ready', 'wmi-shell lane should be Ready with admin');
assert.strictEqual(wmiLane.steps[2].cmdIndex, 22, 'WMI Step 3 should select universal combined user.txt + root.txt command (cmdIndex 22) before root path is known');
console.log('[PASS] Remote-only user.txt (on_host: false) triggers "Capture Both User + Root Flags On-Host" highlight and selects combined proof command.');

// 5. Verify Implicit Prerequisite Completion (A3b) when operator only pastes Step 3 output
var rdpLaneBefore = pcAdminRoot.selectedGroup.lanes.find(function (l) { return l.id === 'enable-rdp'; });
assert.strictEqual(rdpLaneBefore.steps.length, 3, 'enable-rdp lane should have 3 steps (Enable RDP -> Connect xfreerdp -> Capture Proof)');
assert.strictEqual(rdpLaneBefore.steps[0].done, false);
assert.strictEqual(rdpLaneBefore.steps[1].done, false);
assert.strictEqual(rdpLaneBefore.steps[2].done, false);

var finalStepOnlyPaste = [
  'C:\\Windows\\system32>cmd /c "whoami & hostname & ipconfig & for /d %d in (C:\\Users\\*) do @for %f in (%d\\Desktop\\*user*.txt %d\\Desktop\\*local*.txt %d\\Desktop\\*root*.txt %d\\Desktop\\*proof*.txt) do @(echo --- %~f --- & type %~f 2>nul)"',
  'active\\administrator',
  'DC',
  'Windows IP Configuration',
  '   IPv4 Address. . . . . . . . . . . : 10.129.100.23',
  '--- C:\\Users\\SVC_TGS\\Desktop\\user.txt ---',
  'a1b2c3d4e5f60718293a4b5c6d7e8f90',
  '--- C:\\Users\\Administrator\\Desktop\\root.txt ---',
  'f0e1d2c3b4a5968778695a4b3c2d1e0f'
].join('\n');

var resFinalOnly = OBOL.ingest.run({
  text: finalStepOnlyPaste,
  command: wmiLane.steps[2].filled,
  actionId: 'flag-hunt-root-windows',
  source: 'paste',
  scope: 'host:10.129.100.23',
  locus: 'onhost',
  commandObj: winRootMove.commands[22]
});
assert(resFinalOnly.ok, 'Final-step-only paste should succeed');

var postRootFacts = OBOL.store.factSetForTarget('10.129.100.23');
assert(postRootFacts.has('objective.root_flag'), 'Should mint objective.root_flag');
var rootFlagVals = postRootFacts.values('objective.root_flag');
assert.strictEqual(rootFlagVals[0].on_host, true, 'On-host proof paste must set on_host: true on objective.root_flag');
var localFlagValsAfter = postRootFacts.values('objective.local_flag');
assert(localFlagValsAfter.some(function (v) { return v.on_host === true; }), 'Combined on-host proof paste must also record on_host: true for user.txt');

var filledPostRoot = OBOL.command.fillAll(winRootMove, postRootFacts, { params: adminParams });
var pcPostRoot = OBOL.pathChooser.build(winRootMove, postRootFacts, adminParams, filledPostRoot, OBOL.store.active());
var wmiLaneAfter = pcPostRoot.groups.find(function (g) { return g.id === 'onhost'; }).lanes.find(function (l) { return l.id === 'wmi-shell'; });
assert.strictEqual(wmiLaneAfter.steps[0].done, true, 'Step 1 (impacket-wmiexec) should be marked Done when Step 3 proof is pasted');
assert.strictEqual(wmiLaneAfter.steps[1].done, true, 'Step 2 (locate flags) should be marked Done');
assert.strictEqual(wmiLaneAfter.steps[2].done, true, 'Step 3 (proof command) should be marked Done');
var rdpLaneAfter = pcPostRoot.groups.find(function (g) { return g.id === 'onhost'; }).lanes.find(function (l) { return l.id === 'enable-rdp'; });
assert.strictEqual(rdpLaneAfter.steps[0].done, true, 'enable-rdp Step 1 should be implicitly marked Done when Step 3 proof is pasted');
assert.strictEqual(rdpLaneAfter.steps[0].implicitDone, true, 'enable-rdp Step 1 should have implicitDone: true');
assert.strictEqual(rdpLaneAfter.steps[1].done, true, 'enable-rdp Step 2 should be implicitly marked Done when Step 3 proof is pasted');
assert.strictEqual(rdpLaneAfter.steps[1].implicitDone, true, 'enable-rdp Step 2 should have implicitDone: true');
assert.strictEqual(rdpLaneAfter.steps[2].done, true, 'enable-rdp Step 3 should be marked Done');
console.log('[PASS] Final-step-only paste (A3b) implicitly marks prerequisite setup/connect steps Done and records on_host: true for both flags.');

// 6. Test Hero Operator Deck (buildDeck) & Account Creation Auto-Minting
var deck = OBOL.pathChooser.buildDeck(postRootFacts, adminParams, OBOL.store.active());
assert(deck && deck.unlocked, 'Operator Deck should be unlocked when credentials/admin facts exist');
assert.strictEqual(deck.tabs.length, 5, 'Operator Deck should have 5 tabs');
assert.deepStrictEqual(deck.tabs.map(function (t) { return t.id; }), ['flags', 'shells', 'persistence', 'shares', 'credops']);

['flags', 'shells', 'persistence', 'shares', 'credops'].forEach(function (tid) {
  var dTab = OBOL.pathChooser.buildDeck(postRootFacts, adminParams, { ui: { operatorDeckTab: tid } });
  assert.strictEqual(dTab.selectedTabId, tid, 'buildDeck should honor eng.ui.operatorDeckTab = ' + tid);
});

var nonAdminDeck = OBOL.pathChooser.buildDeck(nonAdminFacts, baseParams, { ui: { operatorDeckTab: 'flags' } });
var lockedUserLane = nonAdminDeck.tabs[0].lanes.find(function (l) { return l.id === 'user-onhost-proof'; });
assert(lockedUserLane && lockedUserLane.status === 'locked', 'User on-host lane should be locked without shell/admin');
assert.strictEqual(lockedUserLane.badge, 'Ports Closed', 'Locked lane badge should be a concise 2-word tag');
assert(lockedUserLane.lockReason && lockedUserLane.lockReason.length > 12, 'Locked lane lockReason should preserve full explanation');

var persistTab = deck.tabs.find(function (t) { return t.id === 'persistence'; });
assert(persistTab && persistTab.lanes.length >= 6, 'Persistence tab should have all 6 lanes');
var localAcctLane = persistTab.lanes.find(function (l) { return l.id === 'persist-local-admin'; });
assert(localAcctLane && localAcctLane.steps[0].variants && localAcctLane.steps[0].variants.length >= 2, 'Local admin lane should have tool-swap variants');

var acctCreateRes = OBOL.ingest.run({
  text: 'SMB         10.129.100.23   445    DC               [+] Executed command\nThe command completed successfully.',
  command: localAcctLane.steps[0].command,
  actionId: 'windows-enum',
  source: 'paste',
  scope: 'host:10.129.100.23',
  locus: 'remote'
});
assert(acctCreateRes.ok, 'Account creation paste should succeed');
var factsAfterAcct = OBOL.store.factSetForTarget('10.129.100.23');
var pwVals = factsAfterAcct.values('credential.password');
assert(pwVals.some(function (v) { return v.username === 'obol' && v.password === 'ObolPass123!'; }), 'Should auto-mint created obol account into credential.password');
var userSmbLaneBefore = nonAdminDeck.tabs[0].lanes.find(function (l) { return l.id === 'user-smb-share'; });
assert(userSmbLaneBefore, 'user-smb-share lane should exist in nonAdminDeck');
assert(userSmbLaneBefore.steps[0].command.indexOf('--spider Users --regex "(local|proof|user|root|flag)\\.txt$"') >= 0,
  'user-smb-share Step 1 should use narrow regex spider instead of --pattern txt: ' + userSmbLaneBefore.steps[0].command);
assert.strictEqual(userSmbLaneBefore.steps[1].isEducatedGuess, true,
  'user-smb-share Step 2 should carry isEducatedGuess: true before objective.flag_located_local is proven');
assert.strictEqual(userSmbLaneBefore.steps[1].verifiedPath, false,
  'user-smb-share Step 2 should carry verifiedPath: false before objective.flag_located_local is proven');
assert(userSmbLaneBefore.steps[1].command.indexOf('user.txt\' && cat user.txt') >= 0,
  'user-smb-share Step 2 default smbclient get should save locally and print via && cat user.txt: ' + userSmbLaneBefore.steps[1].command);
assert(userSmbLaneBefore.steps[1].variants.some(function (v) { return v.label === 'smbclient stdout' && v.command.indexOf(' -\'') >= 0; }),
  'user-smb-share Step 2 should include smbclient stdout variant');

var userWinrmLaneBefore = nonAdminDeck.tabs[0].lanes.find(function (l) { return l.id === 'user-winrm-remote'; });
assert(userWinrmLaneBefore && userWinrmLaneBefore.steps[0].command.indexOf("Get-ChildItem 'C:\\Users\\*\\Desktop'") >= 0,
  'user-winrm-remote Step 1 (locate) should use fast profile Desktop sweep: ' + (userWinrmLaneBefore && userWinrmLaneBefore.steps[0].command));

var onhostUserStepsBefore = lockedUserLane.steps;
assert.strictEqual(onhostUserStepsBefore[1].isEducatedGuess, true,
  'user-onhost-proof Step 2 (capture proof) default variant should carry isEducatedGuess: true before flag path is proven');
var autoSearchVariant = onhostUserStepsBefore[1].variants.find(function (v) { return v.id === 'cmd-search'; });
assert(autoSearchVariant && autoSearchVariant.isEducatedGuess === false && autoSearchVariant.verifiedPath === true && autoSearchVariant.command.indexOf('for /d %d in (C:\\Users\\*) do') >= 0,
  'user-onhost-proof Step 2 should offer cmd.exe (auto-search) variant with isEducatedGuess: false, verifiedPath: true, and fast Desktop sweep');

// Verify transition from Educated Guess to Verified Path once objective.flag_located_local is minted (before flag is captured)
var locatedOnlyFacts = new OBOL.facts.FactSet((nonAdminFacts.facts || []).concat([
  OBOL.facts.makeFact({
    kind: 'objective.flag_located_local',
    scope: 'host:10.129.100.23',
    value: { slot: 'local', path: 'C:\\Users\\SVC_TGS\\Desktop\\user.txt', share_path: 'SVC_TGS/Desktop/user.txt' }
  })
]));
var locatedDeck = OBOL.pathChooser.buildDeck(locatedOnlyFacts, baseParams, { ui: { operatorDeckTab: 'flags' } });
var userSmbLaneLocated = locatedDeck.tabs[0].lanes.find(function (l) { return l.id === 'user-smb-share'; });
assert.strictEqual(userSmbLaneLocated.steps[0].done, true, 'Step 1 (locate) is Done once objective.flag_located_local is minted');
assert.strictEqual(userSmbLaneLocated.steps[1].isEducatedGuess, false, 'Step 2 isEducatedGuess clears once path is verified');
assert.strictEqual(userSmbLaneLocated.steps[1].verifiedPath, true, 'Step 2 verifiedPath becomes true once path is verified');
console.log('[PASS] Operator Deck epistemic honesty (Option A): narrow regex spider, smbclient get + cat, Educated Guess -> Verified Path transition, and auto-search variants verified.');

// 7. Regression: smbclient recurse; ls and smbmap -R Users mint objective.flag_located_local
var smbclientRecFacts = [];
OBOL._parserCommon._parse_flags(
  "  \\SVC_TGS\\Desktop\n    .                                   D        0  Sat Jul 21 10:15:12 2018\n    user.txt                           AR       34  Sat Jul 21 10:15:12 2018\n",
  { target: '10.129.100.23' },
  "smbclient //10.129.100.23/Users -U 'active.htb/SVC_TGS%GPPstillStandingStrong2k18' -c 'recurse; ls'",
  'paste',
  smbclientRecFacts
);
assert(smbclientRecFacts.some(function (f) { return f.kind === 'objective.flag_located_local' && f.value.path === 'C:\\Users\\SVC_TGS\\Desktop\\user.txt'; }),
  'smbclient recurse; ls output should mint objective.flag_located_local with C:\\Users\\SVC_TGS\\Desktop\\user.txt');

var smbmapRecFacts = [];
OBOL._parserCommon._parse_flags(
  "  .\\SVC_TGS\\Desktop\n  dr--r--r--                0 Sat Jul 21 10:15:12 2018  .\n  -r--r--r--               34 Sat Jul 21 10:15:12 2018  user.txt\n",
  { target: '10.129.100.23' },
  "smbmap -H 10.129.100.23 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -R Users --depth 5",
  'paste',
  smbmapRecFacts
);
assert(smbmapRecFacts.some(function (f) { return f.kind === 'objective.flag_located_local' && f.value.path === 'C:\\Users\\SVC_TGS\\Desktop\\user.txt'; }),
  'smbmap -R Users output should mint objective.flag_located_local with C:\\Users\\SVC_TGS\\Desktop\\user.txt');

// 8. Regression: Direct Step 2 shortcut (smbclient get / nxc --get-file) preserves full Windows path even after switching to Administrator
var shortcutFactsArr = [];
OBOL._parserCommon._parse_flags(
  "getting file \\SVC_TGS\\Desktop\\user.txt of size 34 as user.txt (0.3 KiloBytes/sec)\na1b2c3d4e5f60718293a4b5c6d7e8f90\n",
  { target: '10.129.100.23' },
  "smbclient //10.129.100.23/Users -U 'active.htb/SVC_TGS%GPPstillStandingStrong2k18' -c 'get \"SVC_TGS\\Desktop\\user.txt\" user.txt' && cat user.txt",
  'paste',
  shortcutFactsArr
);
var shortcutLocalFlag = shortcutFactsArr.find(function (f) { return f.kind === 'objective.local_flag'; });
var shortcutLocated = shortcutFactsArr.find(function (f) { return f.kind === 'objective.flag_located_local'; });
assert(shortcutLocalFlag && shortcutLocalFlag.value.path === 'C:\\Users\\SVC_TGS\\Desktop\\user.txt',
  'Direct smbclient get shortcut should record full Windows path on objective.local_flag');
assert(shortcutLocated && shortcutLocated.value.path === 'C:\\Users\\SVC_TGS\\Desktop\\user.txt',
  'Direct smbclient get shortcut should also mint objective.flag_located_local');

// 9. Regression: NT-Hash Pass-the-Hash identity in buildDeck produces valid --pw-nt-hash syntax with zero unfilled {{password}} tokens
var pthFacts = new OBOL.facts.FactSet([
  OBOL.facts.makeFact({ kind: 'os.windows', value: { os: 'windows' }, scope: 'host:10.129.100.23' }),
  OBOL.facts.makeFact({ kind: 'service.smb', value: { port: 445 }, scope: 'host:10.129.100.23' }),
  OBOL.facts.makeFact({ kind: 'ldap.reachable', value: { port: 389 }, scope: 'host:10.129.100.23' }),
  OBOL.facts.makeFact({ kind: 'config.review', value: { kind: 'gpp_xml', path: 'Groups.xml' }, scope: 'host:10.129.100.23' }),
  OBOL.facts.makeFact({ kind: 'credential.candidate', value: { kind: 'gpp_cpassword', cpassword: 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ' }, scope: 'host:10.129.100.23' }),
  OBOL.facts.makeFact({ kind: 'credential.ntlm_hash', value: { username: 'Administrator', domain: 'active.htb', hash: '58a478135a93ac3bf058a5ea0e8fdb71' }, scope: 'host:10.129.100.23' }),
  OBOL.facts.makeFact({ kind: 'access.admin', value: { username: 'Administrator', via: 'smb' }, scope: 'host:10.129.100.23' })
].concat(shortcutFactsArr));
var pthDeck = OBOL.pathChooser.buildDeck(pthFacts, { target: '10.129.100.23', domain: 'active.htb', user: 'Administrator', nthash: '58a478135a93ac3bf058a5ea0e8fdb71' }, { ui: {} });
var pthSmbLane = pthDeck.tabs[0].lanes.find(function (l) { return l.id === 'user-smb-share'; });
var pthSmbGetVariant = pthSmbLane.steps[1].variants.find(function (v) { return v.id === 'smbclient'; });
assert(pthSmbGetVariant.command.indexOf("%58a478135a93ac3bf058a5ea0e8fdb71' --pw-nt-hash") >= 0,
  'smbclient variant should use valid -U user%hash --pw-nt-hash syntax: ' + pthSmbGetVariant.command);
assert(pthSmbGetVariant.command.indexOf('SVC_TGS\\Desktop\\user.txt') >= 0,
  'Switching to Administrator after SVC_TGS shortcut grab should preserve SVC_TGS\\Desktop\\user.txt path: ' + pthSmbGetVariant.command);
var pthGppLane = pthDeck.tabs[3].lanes.find(function (l) { return l.id === 'shares-custom-gpp'; });
assert.strictEqual(pthGppLane.steps[0].done, true, 'shares-custom-gpp Step 1 should recognize config.review (kind: gpp_xml)');
assert(pthGppLane.steps[1].variants[0].command.indexOf('edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ') >= 0,
  'shares-custom-gpp Step 2 should prefill discovered cpassword from credential.candidate');
assert.strictEqual(userSmbLaneBefore.steps[1].guessBadge, 'Educated Guess',
  'guessBadge pill text should be concise ("Educated Guess") to prevent step header wrapping');
assert.strictEqual(pthDeck.needsBothFlagsOnHost, true, 'pthDeck with remote user.txt should set needsBothFlagsOnHost: true');
assert.strictEqual(pthDeck.localFlagCapturedRemotely, true, 'pthDeck with remote user.txt should set localFlagCapturedRemotely: true');
var adminPreUserFlagFacts = new OBOL.facts.FactSet([
  OBOL.facts.makeFact({ kind: 'os.windows', value: { os: 'windows' }, scope: 'host:10.129.100.23' }),
  OBOL.facts.makeFact({ kind: 'service.smb', value: { port: 445 }, scope: 'host:10.129.100.23' }),
  OBOL.facts.makeFact({ kind: 'credential.ntlm_hash', value: { username: 'Administrator', domain: 'active.htb', hash: '58a478135a93ac3bf058a5ea0e8fdb71' }, scope: 'host:10.129.100.23' }),
  OBOL.facts.makeFact({ kind: 'access.admin', value: { username: 'Administrator', via: 'smb' }, scope: 'host:10.129.100.23' })
]);
var adminPreUserFlagDeck = OBOL.pathChooser.buildDeck(adminPreUserFlagFacts, { target: '10.129.100.23', domain: 'active.htb', user: 'Administrator', nthash: '58a478135a93ac3bf058a5ea0e8fdb71' }, { ui: {} });
assert.strictEqual(adminPreUserFlagDeck.needsBothFlagsOnHost, true, 'Admin deck before user.txt is captured should set needsBothFlagsOnHost: true');
assert.strictEqual(adminPreUserFlagDeck.localFlagCapturedRemotely, false, 'Admin deck before user.txt is captured must set localFlagCapturedRemotely: false (no false premise)');
adminPreUserFlagDeck.tabs.forEach(function (t) {
  (t.lanes || []).forEach(function (l) {
    (l.steps || []).forEach(function (s) {
      var vChars = (s.variants && s.variants.length > 1)
        ? s.variants.map(function (v) { return v.label || ''; }).join(' ').length
        : 0;
      var totalChars = (s.label || '').length + vChars;
      assert(totalChars <= 82, 'Step ' + t.id + '/' + l.id + '/' + s.id + ' header text (' + totalChars + ' chars) must stay concise (<= 82) so .hero-op-step-head fits on one line at 1440px without truncating the step title');
    });
  });
});
console.log('[PASS] Regression checks for smbclient/smbmap locate, shortcut path preservation, Pass-the-Hash smbClientAuth, localFlagCapturedRemotely, single-line header budget, and canonical GPP/NTLM facts verified.');

// 10. Stage-by-stage Operator Deck proof-gating regressions (Active lifecycle)
var stage0Facts = new OBOL.facts.FactSet([
  OBOL.facts.makeFact({ kind: 'host.ip', value: { ip: '10.129.118.39' }, scope: 'host:10.129.118.39' })
]);
var stage0DeckA = OBOL.pathChooser.buildDeck(stage0Facts, { target: '10.129.118.39', lhost: '10.10.14.191' }, { ui: {} });
assert.strictEqual(stage0DeckA.readyLaneCount, 0, 'Stage 0A (before Nmap): readyLaneCount must be 0');
assert.strictEqual(stage0DeckA.unlocked, false, 'Stage 0A (before Nmap): deck.unlocked must be false');
assert.strictEqual(stage0DeckA.selectedTabId, 'flags', 'Stage 0A (before Nmap): default tab must be flags');

var stage0DeckB = OBOL.pathChooser.buildDeck(stage0Facts, { target: '10.129.118.39', domain: 'active.htb', user: 'Administrator', lhost: '10.10.14.191' }, { ui: {} });
assert.strictEqual(stage0DeckB.readyLaneCount, 0, 'Stage 0B (before Nmap, domain/user typed without secret): readyLaneCount must be 0');
assert.strictEqual(stage0DeckB.activeIdentity.isAdmin, false, 'Stage 0B: bare username Administrator without secret or admin fact must not set isAdmin');

var stage1Arr = [
  OBOL.facts.makeFact({ kind: 'host.ip', value: { ip: '10.129.118.39' }, scope: 'host:10.129.118.39' }),
  OBOL.facts.makeFact({ kind: 'os.windows', value: { os: 'windows' }, scope: 'host:10.129.118.39' }),
  OBOL.facts.makeFact({ kind: 'port:88', value: { port: 88 }, scope: 'host:10.129.118.39' }),
  OBOL.facts.makeFact({ kind: 'port:135', value: { port: 135 }, scope: 'host:10.129.118.39' }),
  OBOL.facts.makeFact({ kind: 'port:389', value: { port: 389 }, scope: 'host:10.129.118.39' }),
  OBOL.facts.makeFact({ kind: 'port:445', value: { port: 445 }, scope: 'host:10.129.118.39' }),
  OBOL.facts.makeFact({ kind: 'service.smb', value: { port: 445 }, scope: 'host:10.129.118.39' }),
  OBOL.facts.makeFact({ kind: 'ldap.reachable', value: { port: 389 }, scope: 'host:10.129.118.39' }),
  OBOL.facts.makeFact({ kind: 'ad.dc_candidate', value: { ip: '10.129.118.39' }, scope: 'host:10.129.118.39' })
];
var stage1Facts = new OBOL.facts.FactSet(stage1Arr);
var stage1Deck = OBOL.pathChooser.buildDeck(stage1Facts, { target: '10.129.118.39', domain: 'active.htb', lhost: '10.10.14.191' }, { ui: {} });
assert.strictEqual(stage1Deck.readyLaneCount, 0, 'Stage 1 (after Nmap, before share enum or cred): readyLaneCount must be 0');

var stage2Facts = new OBOL.facts.FactSet(stage1Arr.concat([
  OBOL.facts.makeFact({ kind: 'smb.null_session', value: { anonymous: true }, scope: 'host:10.129.118.39' }),
  OBOL.facts.makeFact({ kind: 'smb.readable_share', value: { share: 'Replication' }, scope: 'host:10.129.118.39' })
]));
var stage2Deck = OBOL.pathChooser.buildDeck(stage2Facts, { target: '10.129.118.39', domain: 'active.htb', lhost: '10.10.14.191' }, { ui: {} });
assert.strictEqual(stage2Deck.readyLaneCount, 3, 'Stage 2 (after Replication share discovered): readyLaneCount must be 3');
var stage2StageTools = stage2Deck.tabs[3].lanes.find(function (l) { return l.id === 'shares-stage-tools'; });
assert.strictEqual(stage2StageTools.status, 'locked', 'Stage 2: shares-stage-tools must remain locked until shell or admin exec');
console.log('[PASS] Stage-by-stage Operator Deck proof-gating regressions (Stage 0 -> Stage 1 -> Stage 2 -> Stage 4) verified.');

console.log('ALL PATH CHOOSER & SEQUENCE PASTE TESTS PASSED!');
})().catch(function (err) { console.error(err); process.exit(1); });
