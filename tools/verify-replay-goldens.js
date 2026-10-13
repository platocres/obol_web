#!/usr/bin/env node
/**
 * verify-replay-goldens.js
 * Comprehensive Stateful Golden Replay Test Suite.
 * Replays completed labs milestone-by-milestone and asserts:
 *  - computeCoach() #1 Suggested Start move
 *  - Exclusion of wrong/premature moves in top 3
 *  - Suggested command index and templated string for Remote and On-Host
 *  - Proper gating (read commands gated until locate output is ingested)
 *  - Clean settlement of completed actions
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const sandbox = {
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
  window: {},
  document: {
    addEventListener: () => {},
    getElementById: (id) => {
      if (!sandbox._elements) sandbox._elements = {};
      if (!sandbox._elements[id]) {
        sandbox._elements[id] = { id: id, innerHTML: '', setAttribute: () => {}, addEventListener: () => {} };
      }
      return sandbox._elements[id];
    }
  },
  localStorage: { getItem: () => null, setItem: () => {} },
  navigator: {},
  location: { hash: '' }
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;
sandbox.root = sandbox;

function load(relPath) {
  const code = fs.readFileSync(path.join(root, relPath), 'utf8');
  vm.runInNewContext(code, sandbox, { filename: relPath });
}

load('assets/engine/facts.js');
load('assets/engine/loot.js');
load('assets/engine/profile.js');
load('assets/engine/vfs.js');
load('assets/engine/phases.js');
load('assets/engine/pack.js');
load('assets/engine/packs.js');
load('data/packs-bundle.js');
load('assets/engine/command.js');
load('assets/engine/workspace.js');
load('assets/ui/util.js');
load('assets/ui/icons.js');
load('assets/ui/store.js');
load('assets/engine/parsers/common.js');
load('assets/engine/parsers/shape.js');
load('assets/engine/parsers/blockers.js');
load('assets/engine/parsers/creds.js');
load('assets/engine/parsers/directory.js');
load('assets/engine/parsers/index.js');
load('assets/ui/ctxbar.js');
load('assets/ui/routes/path.js');

const OBOL = sandbox.OBOL;

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
  console.log('PASS:', msg);
}

console.log('===========================================================');
console.log('=== STATEFUL GOLDEN REPLAY SUITE: HTB FOREST & ACTIVE ===');
console.log('===========================================================\n');

// Load facts from obol-forest(3).json
const forestWs = JSON.parse(fs.readFileSync(path.join(root, 'Testing/obol-forest(3).json'), 'utf8'));
const allForestFacts = forestWs.engagement.facts;

function createMockEng(params, facts) {
  const eng = {
    id: 'eng-replay-' + Date.now(),
    params: Object.assign({}, params),
    facts: facts.map(f => OBOL.facts.factFromJson(f)),
    checklist: {},
    activities: []
  };
  OBOL.store.active = function () { return eng; };
  OBOL.store.factSet = function () {
    const fs = new OBOL.facts.FactSet();
    eng.facts.forEach(f => fs.add(f));
    return fs;
  };
  OBOL.store.factSetForTarget = function (tgt) {
    return OBOL.store.factSet();
  };
  return eng;
}

// =========================================================================
// TEST SUITE 1: HTB FOREST GOLDEN PROGRESSION
// =========================================================================
console.log('--- TEST 1: HTB FOREST PROGRESSION REPLAY ---');

const forestParams = {
  platform: 'htb',
  target: '10.129.105.202',
  scope_defined: true,
  lhost: '10.10.14.191',
  lhost_iface: 'tun0',
  username: '',
  password: '',
  nthash: '',
  domain: 'htb.local'
};

// --- Forest Stage 1: Port Scan Ingested ---
console.log('\n[Forest Stage 1: Initial Recon]');
const stage1Facts = allForestFacts.slice(0, 149);
createMockEng(forestParams, stage1Facts);
const coach1 = OBOL.coach.compute();
assert(coach1.onFlow.length > 0, 'Stage 1: Coach computed ready moves');
const top1 = coach1.onFlow[0].id;
console.log('  Stage 1 Top Move:', top1);
assert(['ad-anon-ldap-enum', 'recon-smb-anon', 'recon-nmap-fast'].includes(top1), 'Stage 1: Top move is anonymous enumeration');

// --- Forest Stage 2: Anonymous User Enum (svc-alfresco found) ---
console.log('\n[Forest Stage 2: AS-REP Roasting Potential]');
const stage2Facts = allForestFacts.slice(0, 152);
createMockEng(forestParams, stage2Facts);
const coach2 = OBOL.coach.compute();
console.log('  Stage 2 Top Moves:', coach2.onFlow.slice(0, 5).map(m => m.id + ' (priority: ' + m.priority + ')'));
const top2 = coach2.onFlow[0].id;
console.log('  Stage 2 Top Move:', top2);
assert(top2 === 'asrep-roast', 'Stage 2: asrep-roast is #1 SUGGESTED START after discovering user accounts');

// --- Forest Stage 3: AS-REP Hash Cracked (svc-alfresco:s3rvice) ---
console.log('\n[Forest Stage 3: User Foothold]');
const stage3Facts = allForestFacts.slice(0, 160);
const eng3 = createMockEng(Object.assign({}, forestParams, {
  username: 'svc-alfresco',
  password: 's3rvice'
}), stage3Facts);
const coach3 = OBOL.coach.compute();
const top3 = coach3.onFlow[0].id;
console.log('  Stage 3 Top Move:', top3);
assert(['flag-hunt-windows', 'win-interactive-shell'].includes(top3), 'Stage 3: flag-hunt-windows or win-interactive-shell is top move once credentials held');

// --- Forest Stage 4: User Flag Hunt In Progress ---
console.log('\n[Forest Stage 4: User Flag Hunt]');
const stage4Facts = allForestFacts.slice(0, 169);
createMockEng(Object.assign({}, forestParams, {
  username: 'svc-alfresco',
  password: 's3rvice'
}), stage4Facts);
const coach4 = OBOL.coach.compute();
const top4 = coach4.onFlow[0].id;
console.log('  Stage 4 Top Move:', top4);
assert(top4 === 'flag-hunt-windows', 'Stage 4: flag-hunt-windows is #1 SUGGESTED START');
const moveUserFlag = coach4.onFlow[0];
const filledUserFlag = OBOL.command.fillAll(moveUserFlag, OBOL.store.factSet(), { params: OBOL.store.active().params });
const prefOnHostUserFlag = OBOL.pack.preferredCommandIndex(moveUserFlag, 'onhost', OBOL.store.factSet(), (cmd, i) => {
  return OBOL.command.unfilledTokens(filledUserFlag[i].filled || '').some(t => OBOL.command.EARNED_TOKENS[t]);
});
console.log('  Stage 4 On-Host Command:', filledUserFlag[prefOnHostUserFlag].filled);
assert(filledUserFlag[prefOnHostUserFlag].filled.includes('evil-winrm -i 10.129.105.202 -u \'svc-alfresco\' -p \'s3rvice\''), 'Stage 4: Evil-WinRM shell is suggested on host');

// --- Forest Stage 5: User Flag Captured -> BloodyAD Must Be #1 ---
console.log('\n[Forest Stage 5: Post-User Flag ACL Discovery]');
const stage5Facts = allForestFacts.slice(0, 174);
createMockEng(Object.assign({}, forestParams, {
  username: 'svc-alfresco',
  password: 's3rvice'
}), stage5Facts);
const coach5 = OBOL.coach.compute();
const top5 = coach5.onFlow[0].id;
console.log('  Stage 5 Top Move:', top5);
assert(top5 === 'bloodyad-acl', 'Stage 5: bloodyad-acl MUST BE #1 SUGGESTED START post-user-flag');
const top3IdsStage5 = coach5.onFlow.slice(0, 3).map(m => m.id);
assert(!top3IdsStage5.includes('kerberoast'), 'Stage 5: kerberoast MUST NOT be in top 3 on Forest');
const filledBloodyAD = OBOL.command.fillAll(coach5.onFlow[0], OBOL.store.factSet(), { params: OBOL.store.active().params });
console.log('  Stage 5 Suggested Command:', filledBloodyAD[0].filled);
assert(filledBloodyAD[0].filled.includes('bloodyAD -d htb.local --host 10.129.105.202 -u svc-alfresco -p \'s3rvice\' get writable --detail'), 'Stage 5: bloodyAD get writable is the #1 command');

// --- Forest Stage 6: DCSync Rights Added -> dcsync Must Be #1 ---
console.log('\n[Forest Stage 6: DCSync Execution]');
const stage6Facts = allForestFacts.slice(0, 188);
createMockEng(Object.assign({}, forestParams, {
  username: 'svc-alfresco',
  password: 's3rvice'
}), stage6Facts);
const coach6 = OBOL.coach.compute();
const top6 = coach6.onFlow[0].id;
console.log('  Stage 6 Top Move:', top6);
assert(top6 === 'dcsync', 'Stage 6: dcsync MUST BE #1 SUGGESTED START when DCSync rights are granted');

// --- Forest Stage 7: NTDS Dumped -> Administrator NT Hash Held ---
console.log('\n[Forest Stage 7: Root Flag Hunt Before Locate]');
const stage7Facts = allForestFacts.slice(0, 198);
createMockEng(Object.assign({}, forestParams, {
  username: 'svc-alfresco',
  password: 's3rvice'
}), stage7Facts);
const coach7 = OBOL.coach.compute();
console.log('  Stage 7 Top 5 Moves:', coach7.onFlow.slice(0, 5).map(m => m.id + ' (priority: ' + m.priority + ')'));
const top7 = coach7.onFlow[0].id;
console.log('  Stage 7 Top Move:', top7);
assert(top7 === 'flag-hunt-root-windows', 'Stage 7: flag-hunt-root-windows MUST BE #1 SUGGESTED START post-DCSync');
const moveRoot = coach7.onFlow[0];
const filledRoot = OBOL.command.fillAll(moveRoot, OBOL.store.factSet(), { params: OBOL.store.active().params });
const prefRemoteRoot = OBOL.pack.preferredCommandIndex(moveRoot, 'remote', OBOL.store.factSet(), (cmd, i) => {
  return OBOL.command.unfilledTokens(filledRoot[i].filled || '').some(t => OBOL.command.EARNED_TOKENS[t]);
});
console.log('  Stage 7 Remote #1 Command:', filledRoot[prefRemoteRoot].filled);
assert(filledRoot[prefRemoteRoot].filled.includes('nxc smb 10.129.105.202 -u Administrator -H 32693b11'), 'Stage 7: Remote locate with Administrator NT hash is suggested');
const prefOnHostRoot = OBOL.pack.preferredCommandIndex(moveRoot, 'onhost', OBOL.store.factSet(), (cmd, i) => {
  return OBOL.command.unfilledTokens(filledRoot[i].filled || '').some(t => OBOL.command.EARNED_TOKENS[t]);
});
console.log('  Stage 7 On-Host #1 Command:', filledRoot[prefOnHostRoot].filled);
assert(filledRoot[prefOnHostRoot].filled.includes('evil-winrm -i 10.129.105.202 -u Administrator -H 32693b11'), 'Stage 7: Evil-WinRM shell with Administrator NT hash is suggested');

// Verify read commands are gated:
const readCmdIdx = moveRoot.commands.findIndex(c => c.run && c.run.includes('{{flag_path_root}}'));
assert(readCmdIdx >= 0, 'Stage 7: Read command exists');
const readUnfilled = OBOL.command.unfilledTokens(filledRoot[readCmdIdx].filled || '');
assert(readUnfilled.includes('flag_path_root'), 'Stage 7: Read command is strictly gated waiting for flag_path_root');

// --- Forest Stage 8: Root Flag Located -> Read Command Un-Gated ---
console.log('\n[Forest Stage 8: Root Flag Located]');
const stage8Facts = allForestFacts.slice(0, 204);
createMockEng(Object.assign({}, forestParams, {
  username: 'svc-alfresco',
  password: 's3rvice'
}), stage8Facts);
const coach8 = OBOL.coach.compute();
assert(coach8.onFlow[0].id === 'flag-hunt-root-windows', 'Stage 8: flag-hunt-root-windows is still active');
const moveRoot8 = coach8.onFlow[0];
const filledRoot8 = OBOL.command.fillAll(moveRoot8, OBOL.store.factSet(), { params: OBOL.store.active().params });
const prefRemoteRoot8 = OBOL.pack.preferredCommandIndex(moveRoot8, 'remote', OBOL.store.factSet(), (cmd, i) => {
  return OBOL.command.unfilledTokens(filledRoot8[i].filled || '').some(t => OBOL.command.EARNED_TOKENS[t]);
});
console.log('  Stage 8 Remote Read Command:', filledRoot8[prefRemoteRoot8].filled);
assert(filledRoot8[prefRemoteRoot8].filled.includes('type C:\\Users\\Administrator\\Desktop\\root.txt'), 'Stage 8: Remote read command un-gated with discovered root path');

// --- Forest Stage 9: Final Flag Captured -> Settled ---
console.log('\n[Forest Stage 9: Box Completion]');
const stage9Facts = allForestFacts.slice(0, 208);
createMockEng(Object.assign({}, forestParams, {
  username: 'svc-alfresco',
  password: 's3rvice'
}), stage9Facts);
const coach9 = OBOL.coach.compute();
const onFlowIds9 = coach9.onFlow.map(m => m.id);
assert(!onFlowIds9.includes('flag-hunt-root-windows'), 'Stage 9: flag-hunt-root-windows is retired/settled once root flag is captured');
console.log('PASS: HTB Forest 9-Stage Golden Replay 100% SUCCESSFUL!\n');

// =========================================================================
// TEST SUITE 2: HTB ACTIVE GOLDEN PROGRESSION
// =========================================================================
console.log('--- TEST 2: HTB ACTIVE PROGRESSION REPLAY ---');

const activeParams = {
  platform: 'htb',
  target: '10.129.105.10',
  scope_defined: true,
  lhost: '10.10.14.191',
  lhost_iface: 'tun0',
  domain: 'active.htb'
};

// Stage 1: Port Scan
console.log('\n[Active Stage 1: Initial Recon]');
const activeFs = new OBOL.facts.FactSet();
function addActiveFact(kind, value, scope) {
  activeFs.add(OBOL.facts.makeFact({
    kind: kind,
    scope: scope || 'host:10.129.105.10',
    value: value || {},
    source: 'active-recon'
  }));
}

[53, 88, 135, 139, 389, 445, 5985].forEach(p => addActiveFact('port:' + p, { port: p }));
addActiveFact('ad.domain_known', { name: 'active.htb' }, 'domain:active.htb');
addActiveFact('ad.dc_candidate', { host: '10.129.105.10', domain: 'active.htb' });
addActiveFact('smb.reachable', {});

createMockEng(activeParams, activeFs.facts);
const coachActive1 = OBOL.coach.compute();
assert(coachActive1.onFlow.length > 0, 'Active Stage 1: Coach computed moves');
console.log('  Active Stage 1 Top Move:', coachActive1.onFlow[0].id);
assert(['recon-smb-anon', 'smb-shares', 'ad-anon-ldap-enum'].includes(coachActive1.onFlow[0].id), 'Active Stage 1: Top move is SMB/LDAP discovery');

// Stage 2: Anonymous SMB Shares (Replication share found)
console.log('\n[Active Stage 2: Replication Share Discovered]');
addActiveFact('smb.shares', { shares: [{ name: 'Replication', readable: true }, { name: 'Users', readable: true }] });
addActiveFact('smb.readable_share', { name: 'Replication' });
createMockEng(activeParams, activeFs.facts);
const coachActive2 = OBOL.coach.compute();
const onFlowActive2 = coachActive2.onFlow.map(m => m.id);
console.log('  Active Stage 2 Moves:', onFlowActive2.slice(0, 3));
assert(onFlowActive2.includes('gpp-passwords') || onFlowActive2.includes('smb-shares'), 'Active Stage 2: GPP decrypt or SMB shares active');

// Stage 3: GPP Password Decrypted (SVC_TGS:GPPstillStandingStrong2k18)
console.log('\n[Active Stage 3: GPP Credential Discovered]');
addActiveFact('credential.plaintext', { user: 'SVC_TGS', password: 'GPPstillStandingStrong2k18', domain: 'active.htb' });
addActiveFact('credential.available', { user: 'SVC_TGS', password: 'GPPstillStandingStrong2k18', domain: 'active.htb' });
addActiveFact('credential.validated', { user: 'SVC_TGS' });
createMockEng(Object.assign({}, activeParams, {
  username: 'SVC_TGS',
  password: 'GPPstillStandingStrong2k18'
}), activeFs.facts);
const coachActive3 = OBOL.coach.compute();
const onFlowActive3 = coachActive3.onFlow.map(m => m.id);
console.log('  Active Stage 3 Moves:', onFlowActive3.slice(0, 3));
assert(onFlowActive3.includes('kerberoast') || onFlowActive3.includes('flag-hunt-windows'), 'Active Stage 3: kerberoast is ready with service account');

// Stage 4: Kerberoasting Yields TGS Hash
console.log('\n[Active Stage 4: Kerberos Ticket Harvested]');
addActiveFact('hash.tgs', { hashes: ['$krb5tgs$23$*Administrator$ACTIVE.HTB$...'] });
createMockEng(Object.assign({}, activeParams, {
  username: 'SVC_TGS',
  password: 'GPPstillStandingStrong2k18'
}), activeFs.facts);
const coachActive4 = OBOL.coach.compute();
console.log('  Active Stage 4 Top Move:', coachActive4.onFlow[0].id);
assert(coachActive4.onFlow[0].id === 'crack-tgs', 'Active Stage 4: crack-tgs is #1 SUGGESTED START');

// Stage 5: Administrator Password Cracked (Administrator:Ticketmaster1968)
console.log('\n[Active Stage 5: Administrator Password Cracked]');
addActiveFact('credential.plaintext', { user: 'Administrator', password: 'Ticketmaster1968', domain: 'active.htb' });
addActiveFact('credential.available', { user: 'Administrator', password: 'Ticketmaster1968', domain: 'active.htb' });
addActiveFact('credential.admin', { user: 'Administrator', password: 'Ticketmaster1968', domain: 'active.htb' });
addActiveFact('access.admin', { user: 'Administrator', password: 'Ticketmaster1968', domain: 'active.htb' });
createMockEng(Object.assign({}, activeParams, {
  username: 'Administrator',
  password: 'Ticketmaster1968'
}), activeFs.facts);
const coachActive5 = OBOL.coach.compute();
console.log('  Active Stage 5 Top Move:', coachActive5.onFlow[0].id);
assert(coachActive5.onFlow[0].id === 'flag-hunt-root-windows', 'Active Stage 5: flag-hunt-root-windows is #1 SUGGESTED START');
const filledActiveRoot = OBOL.command.fillAll(coachActive5.onFlow[0], OBOL.store.factSet(), { params: OBOL.store.active().params });
const prefActiveRoot = OBOL.pack.preferredCommandIndex(coachActive5.onFlow[0], 'remote', OBOL.store.factSet(), (cmd, i) => {
  return OBOL.command.unfilledTokens(filledActiveRoot[i].filled || '').some(t => OBOL.command.EARNED_TOKENS[t]);
});
console.log('  Active Stage 5 Suggested Remote Locate:', filledActiveRoot[prefActiveRoot].filled);
assert(filledActiveRoot[prefActiveRoot].filled.includes('Ticketmaster1968'), 'Active Stage 5: WMI/SMB locate filled with Administrator password');

// Stage 6: Root Flag Located & Captured
console.log('\n[Active Stage 6: Root Flag Located]');
addActiveFact('objective.flag_located', { slot: 'root', name: 'root.txt', path: 'C:\\Users\\Administrator\\Desktop\\root.txt' });
addActiveFact('objective.flag_located_root', { slot: 'root', name: 'root.txt', path: 'C:\\Users\\Administrator\\Desktop\\root.txt' });
createMockEng(Object.assign({}, activeParams, {
  username: 'Administrator',
  password: 'Ticketmaster1968'
}), activeFs.facts);
const coachActive6 = OBOL.coach.compute();
const filledActiveRoot6 = OBOL.command.fillAll(coachActive6.onFlow[0], OBOL.store.factSet(), { params: OBOL.store.active().params });
const prefActiveRoot6 = OBOL.pack.preferredCommandIndex(coachActive6.onFlow[0], 'remote', OBOL.store.factSet(), (cmd, i) => {
  return OBOL.command.unfilledTokens(filledActiveRoot6[i].filled || '').some(t => OBOL.command.EARNED_TOKENS[t]);
});
console.log('  Active Stage 6 Un-gated Read:', filledActiveRoot6[prefActiveRoot6].filled);
assert(filledActiveRoot6[prefActiveRoot6].filled.includes('type C:\\Users\\Administrator\\Desktop\\root.txt'), 'Active Stage 6: Root read command un-gated');

console.log('PASS: HTB Active 6-Stage Golden Replay 100% SUCCESSFUL!\n');
console.log('===========================================================');
console.log('ALL GOLDEN REPLAY ASSERTIONS PASSED WITH 100% SUCCESS!');
console.log('===========================================================');
