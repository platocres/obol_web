/* Regression cases for the 17 source-audit findings in the workspace's chatgpt.txt. */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');
const cp = require('child_process');
const bash = process.env.OBOL_BASH || (process.platform === 'win32' && fs.existsSync('C:/Program Files/Git/bin/bash.exe') ? 'C:/Program Files/Git/bin/bash.exe' : 'bash');
const ROOT = path.resolve(__dirname, '../..');
function memoryStorage() {
  const values = new Map();
  return { get length() { return values.size; }, key: i => Array.from(values.keys())[i],
    getItem: k => values.has(k) ? values.get(k) : null,
    setItem: (k, v) => values.set(k, String(v)), removeItem: k => values.delete(k) };
}
const context = { console: { log() {}, warn() {} }, localStorage: memoryStorage(), sessionStorage: memoryStorage(),
  setTimeout() { return 1; }, clearTimeout() {} };
context.globalThis = context; context.window = context;
vm.createContext(context);
function load(file) { vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), context, { filename: file }); }
['facts', 'phases', 'pack', 'command', 'profile', 'workspace', 'chain', 'cruise'].forEach(n => load('assets/engine/' + n + '.js'));
load('assets/ui/store.js');
load('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'index']
  .forEach(n => load('assets/engine/parsers/' + n + '.js'));
load('assets/ui/ingest.js');
load('assets/engine/report.js');
const O = context.OBOL, F = O.facts, S = O.store, A = '10.0.0.10', B = '10.0.0.20';
O.util = {}; O.routes = {}; O.packs = { actions: () => [] };
load('assets/ui/routes/path.js');
const fact = (kind, scope, value = {}, at = 10, state = 'supported') => F.makeFact({ kind, scope, value, created_at: at, state });
const hostFact = (kind, target, value = {}) => fact(kind, 'host:' + target, value);
const set = facts => new F.FactSet(facts);
let count = 0;
function check(condition, message) { assert.ok(condition, message); count++; }

(async () => {
  for (const input of ['', 'abc', 'password with $ and quotes', '\u2603'.repeat(100)]) {
    check(F.fingerprint(input) === crypto.createHash('sha256').update(input).digest('hex'), 'Identity digest matches SHA-256');
  }
  const eng = await S.createEngagement('Audit Regression');
  S.update(e => { e.params = { target: A }; e.targets = [{ ip: A, domain: 'Alpha.Local.' }, { ip: B, domain: 'beta.local' }]; });
  S.addFacts([hostFact('port:445', A), hostFact('port:445', B), hostFact('port:88', A), hostFact('port:88', B),
    fact('credential.available', 'domain:alpha.local', { user: 'alice', password: 'AlphaPassword!' }),
    fact('access.admin', 'domain:beta.local', { user: 'bob' }), fact('hash.krbtgt', 'domain:beta.local', { hash: 'abc' })]);
  const alpha = S.factSetForTarget(A), beta = S.factSetForTarget(B);
  check(alpha.has('credential.available'), 'Normalized matching domain credentials apply to their host');
  check(!alpha.has('access.admin') && !alpha.has('hash.krbtgt'), 'Unrelated domain compromise cannot contaminate a host');
  check(!beta.has('credential.available') && beta.has('access.admin'), 'Domain filtering works in both directions');
  S.update(e => { e.targets.push({ ip: '10.0.0.30' }); });
  S.addFacts([hostFact('port:445', '10.0.0.30')]);
  check(!S.factSetForTarget('10.0.0.30').has('credential.available'), 'Unknown-domain hosts do not inherit engagement credentials');

  S.setChecklist('recon-smb-anon', 'done', A);
  check(S.doneIdsForTarget(A, alpha)['recon-smb-anon'], 'Manual completion applies on its host');
  check(!S.doneIdsForTarget(B, beta)['recon-smb-anon'], 'Manual completion never hides another host move');
  S.update(e => { e.checklist['legacy-move'] = 'done'; e.activities.push({ action_id: 'legacy-move', target: A }); });
  check(S.doneIdsForTarget(A, alpha)['legacy-move'] && !S.doneIdsForTarget(B, beta)['legacy-move'], 'Legacy completion migrates to its evidence host');
  check(!Object.prototype.hasOwnProperty.call(eng.checklist, 'legacy-move'), 'Legacy global key is removed');
  const attempt = { id: 'probe', commands: [{ tool: 'nxc', run: 'nxc smb {{target}} --users' }] };
  const activities = [{ action_id: 'probe', target: A, tool: 'nxc', command: 'nxc smb ' + A + ' --users', epoch: 'anon' }];
  check(!O.command.commandTriedInEpoch(attempt, attempt.commands[0], 'nxc smb ' + B + ' --users', activities, 'anon', B), 'Command retry memory is host-scoped');

  const oldCred = hostFact('credential.available', B, { user: 'bob', password: 'OldPassword!' });
  const newCred = hostFact('credential.available', B, { user: 'bob', password: 'NewPassword!' });
  const oldEpoch = O.pack.accessEpoch(set([oldCred])), newEpoch = O.pack.accessEpoch(set([newCred]));
  check(oldEpoch !== newEpoch && !newEpoch.includes('NewPassword!'), 'New secret changes retry epoch without exposing the secret');
  check(O.pack.accessEpoch(set([hostFact('credential.available', A, newCred.value)])) !== newEpoch, 'Credential identity includes authentication scope');
  S.setChecklist('retry-move', 'empty:' + oldEpoch, B);
  check(!S.doneIdsForTarget(B, set([newCred]))['retry-move'], 'Changed credentials wake an exhausted move');

  S.addFacts([hostFact('blocker.clock_skew', A), hostFact('blocker.clock_skew', B)]);
  O.ingest.run({ command: 'nmap -sV ' + B, text: 'Nmap scan report for ' + B + '\n22/tcp open ssh OpenSSH 9.0\nNmap done.', scope: 'host:' + B, quiet: true });
  check(S.factSetForTarget(A).has('blocker.clock_skew') && S.factSetForTarget(B).has('blocker.clock_skew'), 'Unrelated successful enumeration cannot clear clock-skew blockers');
  O.ingest.run({ command: 'ntpdate ' + B, text: 'ntpdate: step time server ' + B + ' offset 2.20 sec', scope: 'host:' + B, quiet: true });
  check(S.factSetForTarget(A).has('blocker.clock_skew') && !S.factSetForTarget(B).has('blocker.clock_skew'), 'Relevant repair clears only the affected host blocker');
  assert.throws(() => S.retractFactKind('blocker.clock_skew'), /scope/); count++;

  const recovered = O.parsers.parseActionOutput({ command: 'john --show hashes', stdout: 'administrator:CrackedPassword!\n1 password hash cracked, 0 left', scope: 'host:' + A });
  check(recovered.facts.some(f => f.kind === 'credential.available'), 'Cracked credential remains available');
  check(!recovered.facts.some(f => /credential\.(validated|admin)$/.test(f.kind)), 'Cracking a privileged-looking username proves neither authentication nor admin capability');

  const xml = '<nmaprun args="nmap -sC -sV">'
    + '<host><status state="up"/><address addr="' + A + '" addrtype="ipv4"/><ports><port portid="22" protocol="tcp"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port></ports><hostscript><script output="Computer name: ALPHA&#10;Domain name: alpha.local"/></hostscript></host>'
    + '<host><status state="up"/><address addrtype="ipv4" addr="' + B + '"/><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows Server" version="2019"/></port></ports></host>'
    + '<host><status state="down"/><address addrtype="ipv4" addr="10.0.0.99"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>';
  const scanned = O.parsers.parseActionOutput({ command: 'nmap -sV', stdout: xml, scope: 'host:' + A }).facts;
  check(scanned.some(f => f.kind === 'port:22' && f.scope === 'host:' + A), 'XML records SSH on host A');
  check(scanned.some(f => f.kind === 'port:445' && f.scope === 'host:' + B), 'XML records SMB on host B');
  check(!scanned.some(f => f.kind === 'port:445' && f.scope === 'host:' + A || f.kind === 'port:22' && f.scope === 'host:' + B), 'XML never merges host port sets');
  check(!scanned.some(f => f.scope === 'host:10.0.0.99'), 'Down XML hosts do not mint live service facts');
  check(!scanned.some(f => f.kind === 'host.domain' && f.scope === 'host:' + B), 'Host-script identity does not leak to another XML host');

  const originalNmap = O._parserCommon._parse_nmap, originalShape = O._parserCommon._parse_shape;
  O._parserCommon._parse_nmap = () => { throw new Error('intentional parser fault'); };
  O._parserCommon._parse_shape = (text, ws, source, facts) => facts.push(hostFact('host.up', B));
  const isolated = O.parsers.parseActionOutput({ command: 'nmap', stdout: 'Nmap scan report for ' + B, scope: 'host:' + B });
  O._parserCommon._parse_nmap = originalNmap; O._parserCommon._parse_shape = originalShape;
  check(isolated.facts.some(f => f.kind === 'host.up'), 'Later independent parsers run after an earlier parser throws');
  check(isolated.diagnostics.some(d => d.parser === '_parse_nmap' && /intentional/.test(d.message)), 'Parser failure includes its name and diagnostic');

  const chronology = set([fact('smb.authenticated', 'host:' + A, { user: 'bob' }, 100)]);
  chronology.add(fact('smb.authenticated', 'host:' + A, { user: 'bob' }, 50, 'refuted'));
  check(chronology.has('smb.authenticated'), 'Older contradiction cannot reverse current proof');
  chronology.add(fact('smb.authenticated', 'host:' + A, { user: 'bob' }, 200));
  chronology.add(fact('smb.authenticated', 'host:' + A, { user: 'bob' }, 150, 'refuted'));
  check(chronology.has('smb.authenticated'), 'Recent confirming evidence also advances the proof timestamp');
  chronology.add(fact('smb.authenticated', 'host:' + A, { user: 'bob' }, 300, 'refuted'));
  check(!chronology.has('smb.authenticated'), 'Newer refutation still supersedes old proof');

  const before = eng.activities.length;
  const header = 'Starting Nmap 7.95';
  const capture1 = '$ nmap ' + B + '\n' + header + '\nNmap scan report for ' + B + '\n22/tcp open ssh\nNmap done.';
  const capture2 = capture1.replace('22/tcp open ssh', '445/tcp open microsoft-ds');
  const imported = O.ingest.importSession([capture1, capture2, capture1], { target: B, quiet: true });
  check(imported.imported === 2 && imported.dupes === 1 && eng.activities.length === before + 2, 'Session dedup uses the whole observation rather than its shared opening banner');

  const originalFill = O.command.fillAll;
  O.packs.actions = () => [new O.pack.Action({ id: 'target-probe', requires_all: [], produces: ['test.probe'], commands: [{ run: 'echo {{target}}' }] })];
  let filledTarget;
  O.command.fillAll = (action, facts, opts) => { filledTarget = opts.params.target; return originalFill(action, facts, opts); };
  S.update(e => { e.params.target = B; });
  O.coach.rankFor(set([hostFact('host.up', A)]), { target: A });
  O.command.fillAll = originalFill; O.packs.actions = () => [];
  check(filledTarget === A, 'Per-target eligibility fills commands with that target even when another host is active');
  const savedTargets = eng.targets;
  S.update(e => { e.targets = [{ ip: A }]; });
  S.setActiveTarget(A);
  check(!O.coach.compute().facts.facts.some(f => f.scope === 'host:' + B), 'Explicit host focus stays scoped even with one listed target and old evidence from another host');
  S.update(e => { e.targets = savedTargets; });

  const values = ['with spaces', "O'Brien", 'a; printf INJECTED', '$(printf INJECTED)', 'a"$HOME`printf INJECTED`', 'literal{{password}}'];
  for (const value of values) {
    for (const template of ['printf %s {{user}}', "printf %s '{{user}}'", 'printf %s "{{user}}"']) {
      const command = O.command.fillTemplate(template, set([]), { params: { user: value }, shell: 'bash' });
      const actual = cp.execFileSync(bash, ['-c', command], { encoding: 'utf8' });
      check(actual === value, 'Bash interpolation preserves literal metacharacters and quote context');
    }
  }
  const ps = O.command.fillTemplate("Write-Output '{{user}}'", set([]), { params: { user: "O'Brien;$env:PATH" }, shell: 'powershell' });
  check(ps === "Write-Output 'O''Brien;$env:PATH'", 'PowerShell uses doubled apostrophes for single-quoted literals');
  if (process.platform === 'win32') {
    for (const value of ["O'Brien", '$(Write-Output INJECTED)', 'a"$env:PATH`']) {
      for (const template of ["Write-Output '{{user}}'", 'Write-Output "{{user}}"']) {
        const command = O.command.fillTemplate(template, set([]), { params: { user: value }, shell: 'powershell' }) + ' | ConvertTo-Json -Compress';
        const actual = JSON.parse(cp.execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { encoding: 'utf8' }).trim());
        check(actual === value, 'PowerShell interpolation preserves literal metacharacters in an actual shell');
      }
    }
  }
  const unsafeCmd = O.command.fillCommand({ commands: [{ shell: 'cmd', run: 'echo {{user}}' }] }, set([]), { params: { user: '%PATH%!' } });
  check(unsafeCmd.blocked && !unsafeCmd.filled && unsafeCmd.errors.length, 'CMD values with expansion syntax are blocked with an explanation');
  check(O.command.fillTemplate('{{command}}', set([]), { extra: { command: 'id; whoami' } }) === 'id; whoami', 'Explicit command-expression tokens retain their syntax');
  check(O.command.fillTemplate('{{missing|{{domain}}}}', set([]), { params: { domain: 'alpha.local' } }) === 'alpha.local', 'Authored nested defaults resolve without recursively expanding discovered values');

  await S.importData({ name: 'Legacy Crack Proof', params: { target: A }, facts: [
    hostFact('credential.available', A, { user: 'administrator', password: 'LegacyPassword!', method: 'john' }),
    hostFact('credential.validated', A, { user: 'administrator', via: 'john' }),
    hostFact('credential.admin', A, { user: 'administrator', method: 'john' })
  ] });
  check(S.factSet().has('credential.available') && !S.factSet().has('credential.validated') && !S.factSet().has('credential.admin'), 'Legacy offline-crack privilege claims are removed during import migration');
  await S.setActive(eng.id);

  const FLAG = '0123456789abcdef0123456789abcdef', PASSWORD = 'AuditPassword!';
  const PIXEL = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==';
  const reportFacts = set([hostFact('host.up', A), hostFact('credential.available', A, { user: 'alice', password: PASSWORD }),
    hostFact('objective.local_flag', A, { slot: 'local', flag: FLAG, path: '/home/alice/local.txt' })]);
  const reportOpts = { facts: reportFacts, params: { target: A }, targets: [{ ip: A }],
    screenshots: [{ id: 'proof-shot', target: A, kind: 'proof', slot: 'local', data_uri: PIXEL }],
    activities: [{ target: A, at: 10, command: 'cat local.txt', stdout: FLAG, produced: ['objective.local_flag'] }] };
  const ctx = O.report.buildContext(reportOpts);
  check(!JSON.stringify(O.report.document('oscp', ctx)).includes(PIXEL), 'Redacted reports omit raw screenshot pixels that may contain flags');
  check(ctx.tiles.credential_state === 'Recovered credential, authentication unverified', 'Report distinguishes recovered from validated credentials');
  for (const profile of Object.keys(O.report.PROFILES)) {
    const blocks = O.report.document(profile, ctx);
    const outputs = [O.report.toMarkdown(blocks), O.report.toHtml(blocks), O.report.htmlDocument(O.report.toHtml(blocks), 'Audit'), JSON.stringify(O.report.docxFiles(blocks))];
    check(outputs.every(output => !output.includes(FLAG) && !output.includes(PASSWORD)), 'Every text export redacts flags and credentials for profile ' + profile);
  }
  const raw = O.report.buildContext(Object.assign({}, reportOpts, { includeSecrets: true }));
  check(O.report.toMarkdown(O.report.document('oscp', raw)).includes(FLAG), 'Explicit secret-inclusive report still contains its flag');
  check(O.report.toHtml(O.report.document('oscp', raw)).includes(PIXEL), 'Secret-inclusive reports still embed proof screenshots');

  for (const target of ['', '  ', '999.1.2.3', 'host; echo x', '$(whoami)']) {
    check(!O.cruise.buildStageScript('recon', { params: { target } }), 'Cruise refuses a missing or invalid target');
    check(!O.cruise.buildStageOneLiner('foothold', { params: { target } }) && !O.cruise.buildHostShellAccess('foothold', { params: { target } }), 'Auxiliary Cruise commands also require an explicit valid target');
  }
  check(O.cruise.buildStageScript('recon', { params: { target: A } }).includes(A), 'Cruise generates only for the configured target');

  context.sessionStorage.setItem('other-app-session', 'keep'); context.sessionStorage.setItem('obol:test', 'remove');
  await S.resetAll();
  check(context.sessionStorage.getItem('other-app-session') === 'keep' && !context.sessionStorage.getItem('obol:test'), 'Reset preserves other apps session-storage keys');
  console.log('AUDIT REGRESSIONS: ' + count + ' checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
