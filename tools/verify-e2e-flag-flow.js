const fs = require('fs');
const path = require('path');

// Simulate the browser environment for OBOL
global.window = global;
global.OBOL = global.OBOL || {};

// Load engine modules
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

const allActions = OBOL.packs.actions();
const rootPack = allActions.find(p => p.id === 'flag-hunt-root-windows');

if (!rootPack) {
  console.error('ERROR: flag-hunt-root-windows pack not found in packs bundle!');
  process.exit(1);
}

console.log('--- FOUND flag-hunt-root-windows ---');
console.log('Action Title:', rootPack.title);
console.log('Total commands:', rootPack.commands.length);

// Load obol-active.json if available
const activeData = fs.existsSync('obol-active.json') ? JSON.parse(fs.readFileSync('obol-active.json', 'utf8')) : {};

// Initialize FactStore with existing facts from obol-active.json
const target = activeData.active_target || '10.129.105.90';
const rawFacts = (activeData.facts && (activeData.facts[target] || activeData.facts)) || [];

const factList = rawFacts.map(d => OBOL.facts.factFromJson(d));
const store = new OBOL.facts.FactSet(factList);

function addFact(kind, value, source) {
  store.add(OBOL.facts.makeFact({
    kind: kind,
    scope: 'host:' + target,
    value: value || {},
    source: source || 'test'
  }));
}

// Ensure Administrator credentials and domain exist in facts for this test
addFact('ad.domain_known', { name: 'active.htb' });
addFact('credential.available', {
  user: 'Administrator',
  password: 'Ticketmaster1968',
  domain: 'active.htb',
  admin: true
});
addFact('credential.admin', {
  user: 'Administrator',
  password: 'Ticketmaster1968',
  domain: 'active.htb'
});
addFact('port.open', { port: 135, service: 'msrpc' });
addFact('port.open', { port: 445, service: 'microsoft-ds' });
addFact('host.os', { os: 'windows' });

const opts = { locus: 'remote', params: { target: target } };

console.log('\n=== STAGE 1: BEFORE FLAG LOCATE ===');
console.log('Has flag_located?:', store.has('objective.flag_located'));
const idx1 = OBOL.command.bestCommandIndex(rootPack, store, opts);
const cmdObj1 = OBOL.command.fillCommand(rootPack, store, opts, idx1);
const filled1 = cmdObj1.filled;
console.log('Suggested Command Index:', idx1);
console.log('Suggested Command Note:', rootPack.commands[idx1].note);
console.log('Command String:', filled1);

if (!filled1.includes('dir') && !filled1.includes('--spider')) {
  console.error('FAIL: Expected a locate command before locating the flag, but got:', filled1);
  process.exit(1);
}
console.log('PASS: Correctly suggested locate command as #1.');

// STAGE 2: INGEST LOCATE OUTPUT
console.log('\n=== STAGE 2: INGEST LOCATE OUTPUT ===');
const locateOutput = `
SMB         10.129.105.90   445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 (name:DC) (domain:active.htb) (signing:None) (channel binding:No TLS cert)
SMB         10.129.105.90   445    DC               [+] active.htb\\Administrator:Ticketmaster1968 (Pwn3d!)
C:\\Users\\Administrator\\Desktop\\root.txt
`;

const parseResult1 = OBOL.parsers.parseActionOutput({
  actionId: rootPack.id,
  command: filled1,
  stdout: locateOutput,
  scope: 'host:' + target
});
console.log('Facts parsed from locate output:', parseResult1.facts.map(f => `${f.kind}: ${JSON.stringify(f.value)}`));

const hasLocated = parseResult1.facts.some(f => f.kind === 'objective.flag_located');
if (!hasLocated) {
  console.error('FAIL: Parser failed to mint objective.flag_located from locate output!');
  process.exit(1);
}
console.log('PASS: objective.flag_located successfully minted!');

// Add parsed facts into store
parseResult1.facts.forEach(f => store.add(f));

console.log('\n=== STAGE 3: AFTER FLAG LOCATE (UN-GATED READ) ===');
console.log('Has flag_located?:', store.has('objective.flag_located'));
const idx2 = OBOL.command.bestCommandIndex(rootPack, store, opts);
const cmdObj2 = OBOL.command.fillCommand(rootPack, store, opts, idx2);
const filled2 = cmdObj2.filled;
console.log('Suggested Command Index:', idx2);
console.log('Suggested Command Note:', rootPack.commands[idx2].note);
console.log('Command String:', filled2);

if (filled2.includes('dir') || filled2.includes('--spider')) {
  console.error('FAIL: Locate command was not settled after flag was located!');
  process.exit(1);
}
if (!filled2.includes('type C:\\Users\\Administrator\\Desktop\\root.txt')) {
  console.error('FAIL: Expected read command with populated discovered flag path, but got:', filled2);
  process.exit(1);
}
console.log('PASS: Read command correctly un-gated with discovered flag path!');

// STAGE 4: INGEST FLAG READ OUTPUT
console.log('\n=== STAGE 4: INGEST FLAG READ OUTPUT ===');
const flagOutput = `
WMI         10.129.105.90   135    DC               [*] Windows 7 / Server 2008 R2 Build 7601 (name:DC) (domain:active.htb) (signing:None) (channel binding:No TLS cert)
WMI         10.129.105.90   135    DC               [+] active.htb\\Administrator:Ticketmaster1968 (Pwn3d!)
WMI         10.129.105.90   135    DC               [+] Executed command: "type C:\\Users\\Administrator\\Desktop\\root.txt" via wmiexec
edb0f900a0b73c4d7e98d92cb6239121
`;

const parseResult2 = OBOL.parsers.parseActionOutput({
  actionId: rootPack.id,
  command: filled2,
  stdout: flagOutput,
  scope: 'host:' + target
});
console.log('Facts parsed from read output:', parseResult2.facts.map(f => `${f.kind}: ${JSON.stringify(f.value)}`));

const hasRootFlag = parseResult2.facts.some(f => f.kind === 'objective.root_flag');
if (!hasRootFlag) {
  console.error('FAIL: Parser failed to mint objective.root_flag from flag output!');
  process.exit(1);
}
console.log('PASS: objective.root_flag successfully minted!');

parseResult2.facts.forEach(f => store.add(f));

console.log('\n=== STAGE 5: FINAL PACK SETTLED STATUS ===');
const isSettled = rootPack.settled(store);
console.log('Is flag-hunt-root-windows settled?:', isSettled);
if (!isSettled) {
  console.error('FAIL: Action was expected to be settled once root_flag is captured!');
  process.exit(1);
}
console.log('PASS: Action flag-hunt-root-windows fully settled!');
console.log('\nALL END-TO-END CRITERIA VERIFIED SUCCESSFULLY!');
