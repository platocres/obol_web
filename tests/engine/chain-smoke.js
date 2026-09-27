/* Node sanity test for the compromise-chain reconstruction (engine/chain.js). */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/chain.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL;
const F = OBOL.facts;

const PACKS = path.join(__dirname, '..', '..', 'data', 'packs');
const NAMES = ['recon_2026_09', 'ad_2026_09', 'credential_access_2026_09', 'cracking_2026_09', 'shells_2026_09', 'obol_flag_hunt_2026_09'];
const actions = OBOL.pack.loadPacks(NAMES.map((n) => JSON.parse(fs.readFileSync(path.join(PACKS, n + '.json'), 'utf8'))));

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

const host = '10.10.10.5';
function mk(k, v, s, at) { return F.makeFact({ kind: k, scope: 'host:' + host, value: v || {}, state: F.ProofState.SUPPORTED, source: s || '', created_at: at || 0 }); }
const facts = new F.FactSet([
  mk('target.configured', {}, 'engagement', 1), mk('host.up', {}, 'nmap', 2), mk('ldap.reachable', {}, 'nmap', 3),
  mk('host.hostname', { hostname: 'DC' }, 'nmap', 3), mk('port:389', {}, 'nmap', 3),
  mk('service.ldap', { port: 389 }, 'nmap', 3), mk('scan.nmap.version', {}, 'nmap', 3),
  mk('hash.asrep', {}, 'GetNPUsers', 5), mk('credential.available', { user: 'svc' }, 'john', 6),
  mk('foothold.windows', {}, 'evil-winrm', 7), mk('access.admin', {}, 'secretsdump', 9),
  mk('objective.root_flag', { slot: 'root', flag: 'x', path: 'C:/x/root.txt' }, 'type', 10),
]);
const activities = [
  { tool: 'nmap', command: 'nmap -sC -sV 10.10.10.5', target: host, scope: 'host:' + host, at: 3, produced: ['host.up', 'ldap.reachable', 'host.hostname', 'port:389', 'service.ldap', 'scan.nmap.version'] },
  { tool: 'GetNPUsers', command: 'impacket-GetNPUsers corp/ -no-pass', target: host, scope: 'host:' + host, at: 5, produced: ['hash.asrep'] },
  { tool: 'john', command: 'john hash -w rockyou.txt', target: host, scope: 'host:' + host, at: 6, produced: ['credential.available'] },
  { tool: 'evil-winrm', command: 'evil-winrm -i 10.10.10.5 -u svc -p x', target: host, scope: 'host:' + host, at: 7, produced: ['foothold.windows'] },
  { tool: 'secretsdump', command: 'impacket-secretsdump corp/svc@10.10.10.5', target: host, scope: 'host:' + host, at: 9, produced: ['access.admin'] },
  { tool: 'type', command: 'type root.txt', target: host, scope: 'host:' + host, at: 10, produced: ['objective.root_flag'] },
];

const chain = OBOL.chain.build({ facts: facts, activities: activities, actions: actions, host: host });
const kinds = chain.map((s) => s.kind);

ok(chain.length >= 6, 'chain has the walked milestones (' + chain.length + ' steps)');
ok(kinds[0] === 'target.configured', 'chain is rooted at recon (a configured target)');
ok(kinds[kinds.length - 1] === 'objective.root_flag' && chain[chain.length - 1].isFlag, 'chain ends at the captured flag');
ok(kinds.indexOf('host.hostname') === -1 && kinds.indexOf('port:389') === -1, 'enumeration noise (hostname / individual port) is filtered out');
ok(kinds.indexOf('service.ldap') === -1 && kinds.indexOf('scan.nmap.version') === -1 && kinds.indexOf('ldap.reachable') === -1,
  'per-service evidence, scan markers, and reachability are filtered — only milestones tell the story');
// ledger order is preserved: hash → credential → foothold → admin → flag
function before(a, b) { return kinds.indexOf(a) !== -1 && kinds.indexOf(b) !== -1 && kinds.indexOf(a) < kinds.indexOf(b); }
ok(before('hash.asrep', 'credential.available') && before('credential.available', 'foothold.windows') && before('foothold.windows', 'access.admin') && before('access.admin', 'objective.root_flag'),
  'steps are in the order they were walked (hash → cred → foothold → admin → flag)');
// causal arrow: the credential was enabled by the AS-REP hash it was cracked from
const cred = chain.find((s) => s.kind === 'credential.available');
ok(cred && cred.enabledBy.indexOf('hash.asrep') !== -1, 'the credential step names the AS-REP hash that enabled it (← from)');
// each ledger step carries the command that produced it
ok(chain.find((s) => s.kind === 'foothold.windows').command.indexOf('evil-winrm') === 0, 'each step carries the command that produced it');
// synthesized detail: the credential resolves to its concrete principal, not a generic label
ok(cred && cred.detail === 'svc', 'the credential step names its concrete subject (svc), not just "A Usable Credential"');
// technique framing is derived from the produced kind
ok(chain.find((s) => s.kind === 'hash.asrep').technique === 'AS-REP Roasting', 'the AS-REP step is framed as AS-REP Roasting');
ok(chain.find((s) => s.kind === 'foothold.windows').technique === 'Initial Access / Foothold', 'the foothold step is framed as Initial Access / Foothold');
ok(chain[chain.length - 1].technique === 'Root Flag Captured', 'the flag step is framed as Root Flag Captured');

// no ledger + no flag → falls back to phase/time-ordered proven milestones, still rooted at recon
const bare = new F.FactSet([mk('target.configured', {}, 'engagement', 1), mk('credential.available', { user: 'x' }, 'manual', 2)]);
const bareChain = OBOL.chain.build({ facts: bare, activities: [], actions: actions, host: host });
ok(bareChain.length >= 1 && bareChain[0].kind === 'target.configured', 'degrades gracefully with no run ledger');

console.log(fail ? ('\nCHAIN SMOKE: ' + fail + ' FAILURES') : '\nCHAIN SMOKE: all passed');
process.exit(fail ? 1 : 0);
