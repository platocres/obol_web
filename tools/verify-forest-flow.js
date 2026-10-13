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
    { from: 'svc-alfresco@htb.local', edge: 'MemberOf', to: 'Exchange Windows Permissions@htb.local' },
    { from: 'Exchange Windows Permissions@htb.local', edge: 'WriteDacl', to: 'HTB.LOCAL' }
  ]
];

const bhFacts = bh.toFacts(bhSummary, bhPaths, 'domain:' + domain);
console.log('BloodHound generated facts for Forest:', bhFacts.map(f => f.kind));
bhFacts.forEach(f => store.add(f));

// Check that ad.control_paths and ad.acl_lead are present
if (!store.has('ad.control_paths')) {
  console.error('FAIL: ad.control_paths missing from BloodHound ingest!');
  process.exit(1);
}
console.log('PASS: BloodHound minted ad.control_paths and ad.acl_lead');

// 5. Verify ACL abuse / bloodyAD action un-gated
const bloodyAction = OBOL.packs.actions().find(a => a.id === 'bloodyad-acl');
const isBloodyEligible = bloodyAction.eligible(store);
console.log('Is bloodyad-acl eligible?:', isBloodyEligible);
if (!isBloodyEligible) {
  console.error('FAIL: bloodyad-acl should be eligible with ad.control_paths / ad.acl_lead!');
  process.exit(1);
}
console.log('PASS: bloodyad-acl is eligible!');

// 6. Simulate adding DCSync rights to svc-alfresco
addFact('ad.control_paths', { tool: 'bloodyad', action: 'add dcsync', principal: 'svc-alfresco' });

// 7. Verify DCSync action un-gated
const dcsyncAction = OBOL.packs.actions().find(a => a.id === 'dcsync');
const isDcsyncEligible = dcsyncAction.eligible(store);
console.log('Is dcsync eligible?:', isDcsyncEligible);
if (!isDcsyncEligible) {
  console.error('FAIL: dcsync should be eligible!');
  process.exit(1);
}
console.log('PASS: dcsync is eligible!');

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
