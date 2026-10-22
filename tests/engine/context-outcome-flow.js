/* Stateful contracts for host/identity/service resolution and real paste ingestion.
 * Synthetic transcripts are parsed locally; no external command or target is run.
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
    getItem: k => values.has(k) ? values.get(k) : null,
    setItem: (k, v) => values.set(k, String(v)), removeItem: k => values.delete(k) };
}
const sandbox = { console: { log() {}, warn() {}, error() {} }, localStorage: storage(), sessionStorage: storage(),
  setTimeout() { return 1; }, clearTimeout() {}, Promise };
sandbox.window = sandbox; sandbox.globalThis = sandbox; vm.createContext(sandbox);
function load(file) { vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), sandbox, { filename: file }); }
['facts', 'context', 'phases', 'pack', 'command', 'profile', 'workspace', 'chain', 'outcomes'].forEach(n => load('assets/engine/' + n + '.js'));
load('assets/ui/store.js');
load('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'index']
  .forEach(n => load('assets/engine/parsers/' + n + '.js'));
load('assets/ui/ingest.js');
const O = sandbox.OBOL, S = O.store, F = O.facts, A = '10.0.0.10', B = '10.0.0.20';
const packData = O.pack.PACK_NAMES.map(name => JSON.parse(fs.readFileSync(path.join(ROOT, 'data/packs', name + '.json'), 'utf8')));
const actions = O.pack.loadPacks(packData);
O.packs = { actions: () => actions };
O.util = {}; O.routes = {};
load('assets/ui/routes/path.js');
load('assets/engine/report.js');
let checks = 0;
function check(condition, description) { assert.ok(condition, description); checks++; }
function fact(kind, target, value = {}) { return F.makeFact({ kind, scope: 'host:' + target, value, source: 'test' }); }
function records() { return O.context.credentials(S.active()); }
function user(c) { return c.user || c.username || c.principal || ''; }
function secret(c) { return c.password || c.secret || (c.value && c.value.password) || ''; }
function record(username, password) {
  const found = records().find(c => user(c).toLowerCase().replace(/^.*\\/, '') === username && (!password || secret(c) === password));
  assert.ok(found, 'Fixture credential is registered: ' + username); return found;
}
function supported(target, kind) { return S.factSetForTarget(target).facts.filter(f => f.kind === kind && f.state === 'supported'); }
function ingest(target, command, text, actionId = 'validate-credential') {
  return O.ingest.run({ command, text, scope: 'host:' + target, actionId, source: 'paste', quiet: true });
}
async function fresh(name) {
  await S.createEngagement(name);
  S.update(e => { e.params = { target: A }; e.activeTarget = A; e.targets = [
    { ip: A, hostname: 'ALPHA', domain: 'alpha.local' }, { ip: B, hostname: 'BETA', domain: 'beta.local' }]; });
  S.addFacts([fact('target.configured', A), fact('target.configured', B), fact('smb.reachable', A), fact('smb.reachable', B),
    fact('ldap.reachable', A), fact('ldap.reachable', B), fact('port:445', A), fact('port:445', B),
    fact('credential.available', A, { user: 'alice', password: 'AlphaPassword!', domain: 'alpha.local' }),
    fact('credential.available', B, { user: 'bob', password: 'BetaPassword!', domain: 'beta.local' })]);
  S.setActiveTarget(A); S.selectCredential(record('alice').id, A);
}
function expectOutcome(result, kind) {
  check(result && result.ok && result.outcome && result.outcome.kind === kind, 'Ingestion has explicit ' + kind + ' outcome (received ' + (result && result.outcome && result.outcome.kind || 'missing') + ')');
  const activity = S.active().activities[0];
  check(activity && activity.outcome && activity.outcome.kind === kind, 'Activity persists its ' + kind + ' interpretation');
  return activity;
}
(async () => {
  await fresh('Context restoration');
  const alice = record('alice'), bob = record('bob');
  S.setActiveTarget(B); S.selectCredential(bob.id, B);
  S.setActiveTarget(A);
  let ctx = S.resolvedContext({ service: 'smb' });
  check(ctx.credentialId === alice.id && ctx.target === A, 'Returning to A restores its selected credential');
  S.setActiveTarget(B); ctx = S.resolvedContext({ service: 'smb' });
  check(ctx.credentialId === bob.id && ctx.targetDomain === 'beta.local', 'Returning to B restores its credential and target domain');
  check(ctx.authRealm === 'beta.local', 'Authentication realm comes from the selected credential');
  const offscreen = S.resolvedContext({ target: A, service: 'smb' });
  check(offscreen.credentialId === alice.id && offscreen.target === A && offscreen.authRealm === 'alpha.local', 'Resolving an inactive target uses its own memory before aggregation');
  check(JSON.stringify(O.context.snapshot(ctx)).indexOf('BetaPassword!') < 0, 'Persistable attempt context contains no raw secret');
  check(!alice.id.includes('AlphaPassword!') && !bob.id.includes('BetaPassword!'), 'Credential identifiers do not expose secrets');

  S.setActiveTarget(A); S.setCredentialPin(true); S.setActiveTarget(B); ctx = S.resolvedContext({ service: 'smb' });
  check(ctx.credentialId === alice.id, 'Explicit pin carries one selected credential across targets');
  check(ctx.targetDomain === 'beta.local' && ctx.authRealm === 'alpha.local', 'Credential reuse preserves independent target domain and auth realm');
  S.setCredentialPin(false); ctx = S.resolvedContext({ service: 'smb' });
  check(ctx.credentialId === bob.id, 'Unpin restores B memory instead of overwriting it');
  S.setActiveTarget(A); S.selectCredential(null, A); S.setActiveTarget(B); S.setActiveTarget(A);
  ctx = S.resolvedContext({ service: 'smb' });
  check(!ctx.credentialId && !ctx.params.password && !ctx.params.nthash, 'Explicit no-credential choice is restored without loose secret fallback');

  await fresh('Authentication and authorization');
  const validation = ingest(A, "nxc smb " + A + " -u alice -p 'AlphaPassword!'", 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!');
  expectOutcome(validation, 'success');
  check(supported(A, 'smb.authenticated').length > 0, 'Successful SMB output establishes service authentication');
  check(!supported(B, 'smb.authenticated').length, 'SMB success on A does not authenticate B');
  check(!supported(A, 'access.admin').length, 'Ordinary authentication does not establish admin access');
  const denied = ingest(A, "nxc smb " + A + " -u alice -p 'AlphaPassword!' --shares", 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!\nSMB ' + A + ' 445 ALPHA [-] Error enumerating shares: STATUS_ACCESS_DENIED', 'smb-share-inventory');
  expectOutcome(denied, 'authorization-denied');
  check(supported(A, 'smb.authenticated').length > 0, 'Action denial preserves demonstrated authentication');
  check(!supported(A, 'access.admin').length, 'Action denial never grants administrator rights');
  check(!S.doneIdsForTarget(A)['smb-share-inventory'], 'Denied one operation does not retire the entire move');
  const duplicate = ingest(A, "nxc smb " + A + " -u alice -p 'AlphaPassword!'", 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!');
  expectOutcome(duplicate, 'duplicate');
  check(duplicate.outcome.originalKind === 'success', 'Duplicate retains the original successful result');
  check(!supported(A, 'ldap.authenticated').length, 'SMB authentication does not establish LDAP authentication');
  const ldapRejected = ingest(A, "nxc ldap " + A + " -u alice -p 'AlphaPassword!'", 'LDAP ' + A + ' 389 ALPHA [-] alpha.local\\alice:AlphaPassword! STATUS_LOGON_FAILURE');
  expectOutcome(ldapRejected, 'rejected');
  check(supported(A, 'smb.authenticated').length > 0, 'LDAP rejection does not undo SMB authentication');
  S.setActiveTarget(B); S.selectCredential(record('bob').id, B);
  const hostRejected = ingest(B, "nxc smb " + B + " -u bob -p 'BetaPassword!'", 'SMB ' + B + ' 445 BETA [-] beta.local\\bob:BetaPassword! STATUS_LOGON_FAILURE');
  expectOutcome(hostRejected, 'rejected');
  check(supported(A, 'smb.authenticated').length > 0 && !supported(B, 'smb.authenticated').length, 'Rejected login on B preserves the supported login on A');
  check(S.resolvedContext({ service: 'smb' }).credentialId === record('bob').id, 'Rejection does not discard the credential selection');
  S.setActiveTarget(A);
  const oldAlice = record('alice', 'AlphaPassword!');
  S.addFacts([fact('credential.available', A, { user: 'charlie', password: 'OtherPassword!', domain: 'alpha.local' })]);
  S.selectCredential(record('charlie').id, A);
  check(!S.resolvedContext({ service: 'smb' }).facts.has('smb.authenticated'), 'Another principal does not inherit the previous identity authentication');
  S.addFacts([fact('credential.available', A, { user: 'alice', password: 'RotatedPassword!', domain: 'alpha.local' })]);
  const rotated = record('alice', 'RotatedPassword!');
  check(rotated.id !== oldAlice.id, 'A changed secret creates a distinct credential version');
  S.selectCredential(rotated.id, A);
  ctx = S.resolvedContext({ service: 'smb' });
  check(!ctx.facts.has('smb.authenticated'), 'A changed secret does not inherit authentication proven by the old secret');
  check(supported(A, 'smb.authenticated').length > 0, 'Historical supported evidence remains available in the host record');

  await fresh('Unresolved attempts');
  const command = "nxc smb " + A + " -u alice -p 'AlphaPassword!'";
  for (const [text, kind] of [['zsh: command not found: nxc', 'environment-error'],
    ['Connection opened.\nOperation started...\n[output truncated]', 'unknown'],
    ['An unfamiliar output line\nA second unfamiliar line', 'unknown']]) {
    const result = ingest(A, command, text); const activity = expectOutcome(result, kind);
    check(activity.stdout === text, 'Raw evidence is preserved for ' + kind);
    check(result.outcome.retryable && !result.outcome.retireMove && !result.outcome.retireCommand, kind + ' remains retryable without completion');
    check(!S.doneIdsForTarget(A)['validate-credential'], kind + ' does not mark the move done');
    check(!supported(A, 'smb.authenticated').length && !supported(A, 'access.admin').length, kind + ' fabricates no access proof');
  }
  const oldParser = O._parserCommon._parse_nxc_common;
  O._parserCommon._parse_nxc_common = () => { throw new Error('intentional behavior-contract parser failure'); };
  let parserFailure;
  try { parserFailure = ingest(A, command, 'SMB ' + A + ' 445 ALPHA output that needs directory parsing'); }
  finally { O._parserCommon._parse_nxc_common = oldParser; }
  const failedActivity = expectOutcome(parserFailure, 'parser-error');
  check((failedActivity.parseDiagnostics || []).length > 0 && parserFailure.outcome.retryable, 'Parser exceptions preserve diagnostics and a retry path');
  const proseNegative = ingest(A, '', 'No results found\nAn unrecognized note without a command', '');
  expectOutcome(proseNegative, 'unknown');
  check(!proseNegative.outcome.conclusive, 'Negative-looking prose cannot become a completed tool result');

  await fresh('Partial operation and mixed session');
  const partial = ingest(A, command + ' --shares', 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!\n[output truncated]', 'smb-share-inventory');
  expectOutcome(partial, 'partial');
  check(supported(A, 'smb.authenticated').length > 0, 'Partial operation retains a supported authentication observation');
  check(partial.outcome.retryable && !partial.outcome.conclusive && !partial.outcome.retireCommand && !partial.outcome.retireMove,
    'A partial result does not exhaust its operation or move');
  check(!S.doneIdsForTarget(A)['smb-share-inventory'], 'Partial observation does not become whole-move completion');
  await fresh('Mixed per-command contexts');
  S.setActiveTarget(B); S.selectCredential(record('bob').id, B); S.setActiveTarget(A);
  const mixed = O.ingest.importSession('$ ' + command + '\nSMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!\n'
    + '$ nxc ldap ' + B + " -u bob -p 'BetaPassword!'\nzsh: command not found: nxc", { target: 'auto' });
  check(mixed.ok && mixed.outcome.kind === 'mixed' && mixed.outcomes.length === 2, 'A mixed terminal session retains distinct command outcomes');
  check(mixed.outcomes[0].kind === 'success' && mixed.outcomes[1].kind === 'environment-error', 'Session summary preserves successful and failed commands independently');
  check(mixed.outcomes[0].context.target === A && mixed.outcomes[1].context.target === B, 'Session outcomes retain their own target contexts');
  check(/alice/.test(mixed.outcomes[0].context.principal) && /bob/.test(mixed.outcomes[1].context.principal), 'Mixed session does not collapse identities into the active credential');
  check(supported(A, 'smb.authenticated').length > 0 && !supported(B, 'ldap.authenticated').length, 'A mixed session only establishes the operation that actually succeeded');

  await fresh('Negative result and material possession');
  const negative = ingest(A, 'nmap -sn ' + A, 'Starting Nmap 7.95\nNmap done: 1 IP address (0 hosts up) scanned in 0.12 seconds', 'nmap-fast-open-ports');
  expectOutcome(negative, 'completed-negative');
  check(!supported(A, 'host.up').length, 'Completed negative scan does not invent a live host');
  const recovered = ingest(A, 'john --show recovered.hashes', 'administrator:RecoveredOnly!\n1 password hash cracked, 0 left', 'crack-ntlm');
  check(recovered.ok && supported(A, 'credential.available').length > 0, 'Recovered material remains available for a later test');
  check(!supported(A, 'access.admin').length && !supported(A, 'credential.admin').length && !supported(A, 'smb.authenticated').length,
    'Recovered administrator-looking material establishes neither authentication nor privilege');
  const privileged = new O.pack.Action({ id: 'test-auth-gate', requires_all: ['smb.authenticated'], produces: ['test.next'], commands: [] });
  check(!privileged.eligible(S.resolvedContext({ service: 'smb' }).facts), 'Recommendation gate stays locked until authentication is supported');

  await fresh('Independent Coach host computations');
  const selectionA = record('alice'), selectionB = record('bob');
  S.setActiveTarget(B); S.selectCredential(selectionB.id, B); S.setActiveTarget(A);
  S.addFacts([fact('smb.authenticated', A, { user: 'alice', domain: 'alpha.local', credentialId: selectionA.id, service: 'smb' }), fact('http.reachable', B), fact('port:80', B)]);
  const splitGate = new O.pack.Action({ id: 'test-split-host-gates', requires_all: ['smb.authenticated', 'http.reachable'], produces: ['loot.files'], commands: [{ tool: 'echo', run: 'echo test-fixture' }] });
  const originalActions = O.packs.actions;
  O.packs.actions = () => actions.concat([splitGate]);
  let aggregate;
  try { aggregate = O.coach.compute(null); } finally { O.packs.actions = originalActions; }
  check(aggregate.targetContexts.length === 2, 'All-target Coach computes one resolved context for every target');
  const candidates = aggregate.onFlow.concat(aggregate.comingUp, aggregate.reportChecks);
  check(!candidates.some(a => a.id === splitGate.id), 'All-target Coach never combines prerequisite proof from different hosts');
  const bCoach = aggregate.targetContexts.find(c => c.context.target === B);
  const bValidation = bCoach.onFlow.concat(bCoach.comingUp).find(a => a.id === 'validate-credential');
  check(bValidation && bValidation.contextTarget === B && bValidation.resolvedContext.credentialId === selectionB.id, 'Inactive-target recommendation is bound to that host credential');
  const boundCommand = O.command.fillCommand(bValidation, S.factSet(), { params: S.active().params }, 0);
  check(boundCommand.filled.includes(B) && boundCommand.filled.includes('bob') && boundCommand.filled.includes('BetaPassword!') && !boundCommand.filled.includes('AlphaPassword!'),
    'A bound card fills its target and secret despite another active host and engagement-wide facts');

  S.setCredentialPin(true); S.setActiveTarget(B);
  const crossRealm = S.resolvedContext({ service: 'smb' });
  const authTemplate = new O.pack.Action({ id: 'test-auth-realm', commands: [{ tool: 'nxc', run: "nxc smb {{target}} -d {{domain}} -u {{user}} -p '{{password}}'" }] });
  const authFilled = O.command.fillCommand(authTemplate, crossRealm.facts, { context: crossRealm }, 0).filled;
  check(authFilled.includes('-d alpha.local') && authFilled.includes(B), 'NXC authentication realm uses the credential realm on a different-domain target');
  const dnsTemplate = new O.pack.Action({ id: 'test-target-domain', commands: [{ tool: 'dig', run: 'dig @{{target}} {{domain}}' }] });
  const dnsFilled = O.command.fillCommand(dnsTemplate, crossRealm.facts, { context: crossRealm }, 0).filled;
  check(dnsFilled.includes('beta.local') && !dnsFilled.includes('alpha.local'), 'DNS target domain remains the destination domain');
  const principalTemplate = new O.pack.Action({ id: 'test-principal-realm', commands: [{ tool: 'echo', run: "echo '{{domain}}/{{user}}' '{{user}}@{{domain}}' '{{basedn}}'" }] });
  const principalFilled = O.command.fillCommand(principalTemplate, crossRealm.facts, { context: crossRealm }, 0).filled;
  check(principalFilled.includes('alpha.local/alice') && principalFilled.includes('alice@alpha.local'), 'Principal templates preserve the selected account realm');
  check(principalFilled.includes('DC=beta,DC=local'), 'Directory base DN continues to describe the destination domain');
  S.setCredentialPin(false);

  await fresh('Conclusive attempt suppression');
  const validator = actions.find(a => a.id === 'validate-credential'), validatorCommand = validator.commands[0];
  let attempted = ingest(A, command, 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!');
  const supportedAttempt = S.active().activities[0];
  check(O.command.commandTriedInEpoch(validator, validatorCommand, command, [supportedAttempt], '', A), 'A conclusive matching command can be suppressed in the same resolved context');
  S.addFacts([fact('credential.available', A, { user: 'charlie', password: 'OtherPassword!', domain: 'alpha.local' })]);
  S.selectCredential(record('charlie').id, A);
  check(!O.command.commandTriedInEpoch(validator, validatorCommand, command, [supportedAttempt], '', A), 'Changing identity reopens a previously conclusive command');
  S.addFacts([fact('credential.available', A, { user: 'alice', password: 'RotatedPassword!', domain: 'alpha.local' })]);
  S.selectCredential(record('alice', 'RotatedPassword!').id, A);
  check(!O.command.commandTriedInEpoch(validator, validatorCommand, command, [supportedAttempt], '', A), 'Changing the secret version reopens a previously conclusive command');
  for (const [output, kind] of [['Unrecognized first line\nUnrecognized second line', 'unknown'], ['zsh: command not found: nxc', 'environment-error'],
    ['SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!\n[output truncated]', 'partial']]) {
    await fresh('Nonconclusive suppression ' + kind);
    attempted = ingest(A, command, output); expectOutcome(attempted, kind);
    check(!O.command.commandTriedInEpoch(validator, validatorCommand, command, [S.active().activities[0]], '', A), kind + ' never suppresses an otherwise identical command');
  }

  const materialFacts = new F.FactSet([fact('credential.available', A, { user: 'alice', password: 'AlphaPassword!', domain: 'alpha.local' })]);
  const materialReport = O.report.buildContext({ facts: materialFacts, params: { target: A }, targets: [{ ip: A }] });
  check(/unverified|untested|recovered/i.test(materialReport.tiles.credential_state), 'Report describes recovered credentials as unverified material');
  check(!materialReport.access_ladder.some(s => s.reached && /authenticat|valid credential|foothold/i.test(s.stage)), 'Report material does not reach authentication or foothold milestones');
  const winrmFacts = new F.FactSet([fact('winrm.authenticated', A, { user: 'alice', domain: 'alpha.local', service: 'winrm' }),
    fact('credential.validated', A, { user: 'alice', domain: 'alpha.local', service: 'winrm' })]);
  const winrmReport = O.report.buildContext({ facts: winrmFacts, params: { target: A }, targets: [{ ip: A }], activities: [] });
  check(!winrmReport.access_ladder.some(s => s.reached && /foothold/i.test(s.stage)), 'Report WinRM authentication does not establish a foothold milestone');
  check(/no access proven/i.test(winrmReport.tiles.access_state), 'Report access tile leaves shell access unproven after WinRM authentication alone');
  const markdown = O.report.toMarkdown(O.report.document('oscp', winrmReport));
  check(/shell access unproven|no initial access demonstrated/i.test(markdown), 'Exported report prose does not invent an interactive shell from authentication');

  await fresh('Copied execution context');
  const copiedAlice = record('alice');
  const copiedContext = S.resolvedContext({ command: 'whoami', actionId: 'windows-enum', locus: 'onhost' });
  O.ingest.setLastCopied({ command: 'whoami', target: A, actionId: 'windows-enum', locus: 'onhost', context: O.context.snapshot(copiedContext) });
  S.addFacts([fact('credential.available', A, { user: 'charlie', password: 'OtherPassword!', domain: 'alpha.local' })]);
  S.selectCredential(record('charlie').id, A);
  const copiedPreview = O.ingest.preview({ text: 'alpha.local\\alice', scope: 'host:' + A });
  check(copiedPreview.credentialId === copiedAlice.id && copiedPreview.locus === 'onhost' && copiedPreview.source === 'copied-command', 'Preview retains the copied on-host identity after the visible credential changes');
  const copiedOutput = O.ingest.run({ text: 'alpha.local\\alice', scope: 'host:' + A, quiet: true });
  check(copiedOutput.context.credentialId === copiedAlice.id && copiedOutput.context.locus === 'onhost', 'Raw output remains associated with the copied execution context');
  const conflictOutput = O.ingest.run({ text: 'LDAP ' + A + ' 389 ALPHA [+] alpha.local\\alice:AlphaPassword!', scope: 'host:' + A, quiet: true });
  check(conflictOutput.context.service === 'ldap' && conflictOutput.context.locus === 'remote', 'Observed LDAP output overrides a stale on-host copied command');
  check(JSON.stringify(copiedPreview).indexOf('AlphaPassword!') < 0, 'Precommit context preview exposes no credential secret');
  await fresh('Imports preserve explicit credential selection');
  const importAlice = record('alice'), importBob = record('bob');
  S.setActiveTarget(B); S.selectCredential(importBob.id, B);
  S.setActiveTarget(A); S.selectCredential(null, A);
  const beforeImportMemories = JSON.stringify(S.active().contextSelections.byTarget);
  const importedAuth = O.ingest.importSession('$ nxc smb ' + A + " -u alice -p 'AlphaPassword!' -d alpha.local\n"
    + 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword! (Pwn3d!)', { target: 'auto' });
  check(importedAuth.ok && importedAuth.imported === 1, 'Import records an authentication result while no credential is selected');
  check(!S.resolvedContext({ target: A, service: 'smb' }).credentialId && !(S.active().params || {}).username,
    'Successful imported output never overwrites explicit no-credential selection or loose identity parameters');
  check(JSON.stringify(S.active().contextSelections.byTarget) === beforeImportMemories,
    'Import preserves every target credential memory');
  check(records().some(c => c.id === importAlice.id), 'Imported material remains available as a candidate without being selected');
  S.setActiveTarget(B);
  check(S.resolvedContext({ service: 'smb' }).credentialId === importBob.id, 'Another target retains its selected credential after import');
  S.setActiveTarget(A); S.selectCredential(importAlice.id, A);
  const importedOther = O.ingest.importSession('$ nxc smb ' + A + " -u charlie -p 'CharliePassword!' -d alpha.local\n"
    + 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\charlie:CharliePassword! (Pwn3d!)', { target: 'auto' });
  check(importedOther.ok && records().some(c => user(c).toLowerCase() === 'charlie'), 'A newly imported identity is offered as recovered material');
  check(S.resolvedContext({ service: 'smb' }).credentialId === importAlice.id,
    'Proof for a different imported identity never changes the selected credential');
  O.ingest.setLastCopied({ target: A, actionId: 'ssh-login', command: 'ssh alice@' + A,
    locus: 'onhost', commandObj: { tool: 'ssh', run: 'ssh alice@' + A } });
  check(O.ingest.getLastCopied().context.locus === 'remote', 'A session-launcher copy records where it is entered, independently of the UI on-host posture');
  check(O.ingest.preview({ text: 'A response without a producer banner' }).locus === 'remote', 'Raw paste preview preserves the actual launcher execution location');
  const localIdentity = O.ingest.run({ command: 'whoami', text: 'alpha.local\\alice', scope: 'host:' + A, locus: 'remote', commandObj: { tool: 'whoami', run: 'whoami' }, quiet: true });
  check(localIdentity.context.locus === 'onhost', 'Native identity-command ingestion records on-host execution independently of the UI posture');
  console.log('CONTEXT OUTCOME FLOW: ' + checks + ' behavioral checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
