/* Context regressions across real command locations and credential selections.
 * All commands are inert fixture strings or existing pack data; nothing is run.
 */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = path.resolve(__dirname, '../..');
function storage() {
  const values = new Map();
  return { get length() { return values.size; }, key: i => Array.from(values.keys())[i],
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)), removeItem: key => values.delete(key) };
}
const sandbox = { console, localStorage: storage(), sessionStorage: storage(),
  setTimeout() { return 1; }, clearTimeout() {}, Promise };
sandbox.window = sandbox; sandbox.globalThis = sandbox; vm.createContext(sandbox);
function load(file) { vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), sandbox, { filename: file }); }
['facts', 'context', 'phases', 'pack', 'command', 'profile', 'workspace', 'chain', 'outcomes'].forEach(name => load('assets/engine/' + name + '.js'));
load('assets/ui/store.js');
load('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'index']
  .forEach(name => load('assets/engine/parsers/' + name + '.js'));
load('assets/ui/ingest.js');
const O = sandbox.OBOL, S = O.store, F = O.facts, A = '10.0.0.10', B = '10.0.0.20';
const packData = O.pack.PACK_NAMES.map(name => JSON.parse(fs.readFileSync(path.join(ROOT, 'data/packs', name + '.json'), 'utf8')));
const actions = O.pack.loadPacks(packData);
O.packs = { actions: () => actions }; O.util = {}; O.routes = {};
load('assets/ui/routes/path.js');
let checks = 0;
function check(value, message) { assert.ok(value, message); checks++; }
function fact(kind, target, value = {}) { return F.makeFact({ kind, scope: 'host:' + target, value, source: 'location-regression' }); }
function credential(user) { return O.context.credentials(S.active()).find(c => c.user === user); }
async function fresh(name) {
  await S.createEngagement(name);
  S.update(eng => {
    eng.params = { target: A }; eng.activeTarget = A;
    eng.targets = [{ ip: A, hostname: 'ALPHA', domain: 'alpha.local' }, { ip: B, hostname: 'BETA', domain: 'beta.local' }];
  });
  S.addFacts([fact('target.configured', A), fact('target.configured', B), fact('os.windows', A),
    fact('host.os_family', A, { family: 'windows' }),
    fact('credential.available', A, { user: 'alice', password: 'AlphaFixture!', domain: 'alpha.local' }),
    fact('credential.available', B, { user: 'bob', password: 'BetaFixture!', domain: 'beta.local' })]);
  S.selectCredential(credential('alice').id, A);
}
function ownSystemSession() {
  S.addFacts([fact('foothold.windows', A, { identity: 'nt authority\\system', via: 'observed-session' }),
    fact('access.shell', A, { identity: 'nt authority\\system', via: 'observed-session' }),
    fact('access.system', A, { identity: 'nt authority\\system', via: 'whoami' })]);
}
function fixture(id, commands) {
  return new O.pack.Action({ id, os: ['windows'], phase: 'escalate', requires_all: ['access.system'],
    produces: ['loot.files'], commands });
}
(async () => {
  await fresh('Actual command execution'); ownSystemSession();
  let facts = S.resolvedContext({ locus: 'overview' }).facts;
  const remote = { tool: 'nxc', run: 'echo fixture-remote' };
  const local = { tool: 'powershell', run: 'echo fixture-on-host' };
  const launcher = { tool: 'evil-winrm', run: 'echo fixture-session-launcher' };
  const mixed = fixture('test-location-mixed', [remote, local]);
  check(O.pack.commandLocus(launcher) === 'onhost' && O.pack.commandExecutionLocus(launcher) === 'remote',
    'A remote session launcher retains its UI posture while its execution context remains remote');
  check(O.pack.commandExecutionLocus(local) === 'onhost', 'Commands typed inside the host use on-host execution');
  check(facts.has('access.system'), 'Host overview retains established SYSTEM access');
  check(!mixed.eligible(facts.forAction(mixed, remote)), 'Remote variant cannot borrow another session privilege');
  check(mixed.eligible(facts.forAction(mixed, local)), 'An existing on-host session can use its demonstrated privilege');
  check(mixed.eligible(facts), 'A mixed move remains eligible through a usable on-host variant after its remote variant is gated');
  check(mixed.unmet(facts) === 'blocked', 'An eligible alternate location does not produce a false missing-privilege explanation');
  check(!fixture('test-location-launcher', [launcher]).eligible(facts),
    'Launching another session remotely still requires proof for the selected credential');
  check(O.command.bestCommandIndex(mixed, facts) === 1, 'The preferred command skips a variant without its own scoped prerequisites');
  for (const id of ['lsass-dump-onbox', 'windows-old-hives']) {
    const action = actions.find(a => a.id === id);
    check(action && action.locus === 'R' && action.eligible(facts),
      'Existing ' + id + ' retains its usable on-host commands despite coarse remote action metadata');
  }

  const selected = credential('alice');
  S.addFacts([fact('access.admin', A, { user: selected.user, domain: selected.domain, credentialId: selected.id, service: 'smb' })]);
  facts = S.resolvedContext({ locus: 'overview' }).facts;
  const smb = new O.pack.Action({ id: 'test-smb-privilege', requires_all: ['access.admin'],
    commands: [{ tool: 'nxc', run: 'nxc smb fixture-only' }] });
  const ldap = new O.pack.Action({ id: 'test-ldap-privilege', requires_all: ['access.admin'],
    commands: [{ tool: 'nxc', run: 'nxc ldap fixture-only' }] });
  check(smb.eligible(facts) && !ldap.eligible(facts), 'Remote privilege proof remains scoped to the demonstrated service');
  const remoteSession = fixture('test-location-retry', [launcher]);
  const launcherContext = O.context.snapshot(S.resolvedContext({ command: launcher.run, actionId: remoteSession.id, locus: 'remote' }));
  const launcherAttempt = { target: A, action_id: remoteSession.id, command: launcher.run,
    context: launcherContext, outcome: { retireCommand: true } };
  check(O.command.commandTriedInEpoch(remoteSession, launcher, launcher.run, [launcherAttempt], '', A),
    'Remote session launcher snapshots match the actual execution context used for retry suppression');

  await fresh('No runnable privileged variant'); ownSystemSession();
  facts = S.resolvedContext({ locus: 'overview' }).facts;
  const onlyLocalRemaining = fixture('test-location-exhausted', [remote, local]);
  const localContext = O.context.snapshot(S.resolvedContext({ command: local.run, actionId: onlyLocalRemaining.id, locus: 'onhost' }));
  S.update(eng => { eng.activities.unshift({ target: A, action_id: onlyLocalRemaining.id, command: local.run,
    epoch: O.pack.accessEpoch(facts), context: localContext, outcome: { retireCommand: true } }); });
  const originalActions = O.packs.actions; O.packs.actions = () => [onlyLocalRemaining];
  let coach;
  try { coach = O.coach.rankFor(S.factSetForTarget(A), { target: A }); } finally { O.packs.actions = originalActions; }
  check(!coach.onFlow.some(a => a.id === onlyLocalRemaining.id) && coach.comingUp.some(a => a.id === onlyLocalRemaining.id),
    'Coach does not promote an unproven remote variant after the actual on-host variant is exhausted');

  await fresh('Stable local material and inactive selection');
  S.update(eng => { eng.credentials = [{ user: 'localuser', secret: 'SharedFixture!', accountType: 'local', targetBinding: A },
    { user: 'localuser', secret: 'SharedFixture!', accountType: 'local', targetBinding: B }]; });
  const locals = O.context.credentials(S.active()).filter(c => c.user === 'localuser');
  const localA = locals.find(c => c.targetBinding === A), localB = locals.find(c => c.targetBinding === B);
  S.setActiveTarget(B); S.selectCredential(localB.id, B);
  let resolved = S.resolvedContext();
  check(resolved.credentialId === localB.id && resolved.credential.accountType === 'local' && resolved.credential.targetBinding === B,
    'Selecting a local account preserves its stable material, type, and host binding');
  check(resolved.authRealm !== 'beta.local' && resolved.targetDomain === 'beta.local',
    'A target domain never replaces the selected local authentication identity');
  S.setActiveTarget(A); const before = S.resolvedContext().credentialId;
  S.selectCredential(localB.id, B);
  check(S.resolvedContext().credentialId === before && S.resolvedContext({ target: B }).credentialId === localB.id,
    'Remembering an inactive target selection leaves the active target selection unchanged');
  S.selectCredential(localA.id, A); S.setCredentialPin(true); S.setActiveTarget(B);
  check(S.resolvedContext().credentialId === localA.id, 'A temporary pin carries the same local material without reclassifying it');
  S.setCredentialPin(false);
  check(S.resolvedContext().credentialId === localB.id, 'Releasing a pin restores the destination local account memory');
  S.selectCredential(null, B); S.setActiveTarget(A); S.setActiveTarget(B); resolved = S.resolvedContext();
  check(!resolved.credentialId && !resolved.params.password && !resolved.params.nthash,
    'Explicit no-credential state stays empty when returning to a target');

  await fresh('Partial observation is not whole-operation completion');
  const scan = new O.pack.Action({ id: 'test-location-scan', phase: 'recon', requires_all: ['target.configured'],
    produces: ['host.up', 'ports.open', 'scan.nmap.quick'], commands: [{ tool: 'nmap', run: 'nmap -p- {{target}}' }] });
  const scanCommand = O.command.fillCommand(scan, S.resolvedContext().facts, { params: S.active().params }, 0).filled;
  const observations = 'Starting Nmap 7.95\nNmap scan report for ' + A + '\nHost is up (0.001s latency).\nPORT STATE SERVICE\n445/tcp open microsoft-ds\n';
  let result = O.ingest.run({ text: observations + '[output truncated]', command: scanCommand,
    scope: 'host:' + A, actionId: scan.id, quiet: true });
  facts = S.resolvedContext({ locus: 'overview' }).facts;
  check(result.outcome.kind === 'partial' && scan.produces.every(kind => facts.has(kind)),
    'A real partial scan can establish every advertised observation without completing its operation');
  check(!scan.settled(facts), 'Supported partial observations do not settle the current scan');
  check(scan.settled(new F.FactSet(facts.facts)), 'Unresolved-context compatibility keeps legacy fact-only settlement unchanged');
  O.packs.actions = () => [scan];
  try { coach = O.coach.rankFor(S.factSetForTarget(A), { target: A }); } finally { O.packs.actions = originalActions; }
  check(coach.onFlow.some(action => action.id === scan.id), 'The planner keeps an incomplete scan available after its partial observations unlock later work');
  result = O.ingest.run({ text: observations + 'Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds',
    command: scanCommand, scope: 'host:' + A, actionId: scan.id, quiet: true });
  facts = S.resolvedContext({ locus: 'overview' }).facts;
  check(result.outcome.conclusive && scan.settled(facts), 'A conclusive receipt settles the exact completed operation');
  check(!scan.settled(S.resolvedContext({ target: B, locus: 'overview' }).facts), 'Completion on one host does not settle the same question on another host');
  scan.commands[0] = { tool: 'nmap', run: 'nmap -p 80 {{target}}' };
  check(!scan.settled(facts), 'Changing the query reopens the action even when its produced fact kinds are already held');
  const flag = new O.pack.Action({ id: 'test-terminal-goal', produces: ['objective.root_flag'], commands: [local] });
  S.addFacts([fact('objective.root_flag', A, { flag: 'synthetic-proof' })]);
  check(flag.settled(S.resolvedContext({ locus: 'overview' }).facts), 'Supported terminal objective proof settles its goal without requiring a particular command receipt');

  await fresh('One service does not settle credential validation');
  const validation = actions.find(action => action.id === 'validate-credential');
  const validationCommand = O.command.fillCommand(validation, S.resolvedContext().facts, { params: S.active().params }, 0).filled;
  result = O.ingest.run({ text: 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaFixture!',
    command: validationCommand, scope: 'host:' + A, actionId: validation.id, quiet: true });
  check(result.outcome.conclusive && !validation.settled(S.resolvedContext({ locus: 'overview' }).facts),
    'A conclusive SMB validation does not exhaust the other service-specific validation commands');
  console.log('CONTEXT LOCATION REGRESSIONS: ' + checks + ' checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
