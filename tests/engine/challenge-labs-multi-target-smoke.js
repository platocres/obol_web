/* Multi-target pivot discovery, cross-host unvalidated reuse hypothesis propagation,
 * and extended earned-token extraction smoke tests.
 * Uses strictly synthetic 3-tier topologies and synthesized protocol fixtures.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '../..');

function makeStorage() {
  const values = new Map();
  return {
    get length() { return values.size; },
    key: i => Array.from(values.keys())[i] || null,
    getItem: k => (values.has(k) ? values.get(k) : null),
    setItem: (k, v) => values.set(k, String(v)),
    removeItem: k => values.delete(k)
  };
}

const sandbox = {
  console,
  localStorage: makeStorage(),
  sessionStorage: makeStorage(),
  setTimeout() { return 1; },
  clearTimeout() {},
  Promise
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

function load(relFile) {
  const full = path.join(ROOT, relFile);
  if (!fs.existsSync(full)) return false;
  vm.runInContext(fs.readFileSync(full, 'utf8'), sandbox, { filename: relFile });
  return true;
}

['facts', 'context', 'phases', 'pack', 'command', 'profile', 'workspace', 'chain', 'outcomes']
  .forEach(name => load('assets/engine/' + name + '.js'));
load('assets/ui/store.js');
load('assets/engine/parsers/common.js');
[
  'nmap', 'directory', 'creds', 'host', 'web', 'services', 'database',
  'websource', 'findings', 'shape', 'inference', 'edb', 'pivot', 'dns',
  'blockers', 'nxc-catalog', 'index'
].forEach(name => load('assets/engine/parsers/' + name + '.js'));
load('assets/ui/ingest.js');

const O = sandbox.OBOL;
const S = O.store;
const F = O.facts;
const packData = O.pack.PACK_NAMES.map(name =>
  JSON.parse(fs.readFileSync(path.join(ROOT, 'data/packs', name + '.json'), 'utf8'))
);
const actions = O.pack.loadPacks(packData);
O.packs = { actions: () => actions };
O.util = {};
O.routes = {};
load('assets/ui/routes/path.js');

const HOST_A = '10.200.1.10';
const HOST_DMZ_SIBLING = '10.200.1.99';
const HOST_B = '172.30.5.20';
const HOST_C = '172.30.5.5';
const HOST_D_ARP = '172.30.9.40';

let checks = 0;
function ok(cond, msg) {
  assert.ok(cond, msg);
  checks++;
}

function mkFact(kind, target, value = {}, source = 'multi-target-smoke') {
  return F.makeFact({ kind, scope: 'host:' + target, state: 'supported', value, source });
}

function ingest(target, command, text, actionId = '') {
  return O.ingest.run({
    command,
    text,
    scope: 'host:' + target,
    actionId,
    source: 'paste',
    quiet: true
  });
}

(async () => {
  // ---------------------------------------------------------------------------
  // 1. Unscanned targets inherit ZERO cross-host loot or pivot facts
  // ---------------------------------------------------------------------------
  await S.createEngagement('Synthetic three-tier pivot verification');
  S.update(eng => {
    eng.params = { target: HOST_A, lhost: '198.51.100.7' };
    eng.activeTarget = HOST_A;
    eng.targets = [
      { ip: HOST_A, hostname: 'EDGE-GW' },
      { ip: HOST_B },
      { ip: HOST_C, domain: 'synth.example' },
      { ip: HOST_DMZ_SIBLING }
    ];
  });
  S.addFacts([
    mkFact('target.configured', HOST_A),
    mkFact('target.configured', HOST_B),
    mkFact('target.configured', HOST_C),
    mkFact('target.configured', HOST_DMZ_SIBLING)
  ]);

  // Configure label metadata on unscanned HOST_B via editTarget; must still count as unscanned.
  S.editTarget(HOST_B, { hostname: 'APP-NODE', os: 'Windows' });

  // Scan and compromise HOST_A (DMZ pivot host)
  ingest(
    HOST_A,
    'nmap -sV -p 22,80 ' + HOST_A,
    [
      'Starting Nmap 7.95',
      'Nmap scan report for ' + HOST_A,
      'Host is up (0.0020s latency).',
      'PORT   STATE SERVICE VERSION',
      '22/tcp open  ssh     OpenSSH 9.2p1 Debian',
      '80/tcp open  http    nginx 1.24.0',
      'Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds'
    ].join('\n'),
    'nmap-fast-open-ports'
  );

  // Establish foothold + root + recovered config credentials + SSH key + LAPS bound to HOST_A
  S.addFacts([
    mkFact('foothold.linux', HOST_A, { user: 'www-data', via: 'web-rce' }),
    mkFact('access.shell', HOST_A, { user: 'www-data', via: 'web-rce' }),
    mkFact('access.root', HOST_A, { identity: 'root', via: 'id' }),
    mkFact('credential.available', HOST_A, {
      user: 'cfg_svc',
      password: 'SynthCfg#2026!',
      method: 'config-extract'
    }),
    mkFact('credential.validated', HOST_A, {
      user: 'cfg_svc',
      password: 'SynthCfg#2026!',
      service: 'ssh',
      method: 'ssh'
    }),
    mkFact('credential.available', HOST_A, {
      user: 'ops_deploy',
      password: 'SynthOps#2026!',
      method: 'env-extract'
    }),
    mkFact('credential.available', HOST_A, {
      user: 'Administrator',
      password: 'LapsBoundOnly#1!',
      accountType: 'local',
      targetBinding: HOST_A,
      computer: 'EDGE-GW$',
      method: 'laps'
    }),
    mkFact('credential.plaintext', HOST_A, {
      user: '',
      password: 'KeyPassphraseOnly!',
      file: 'id_rsa',
      via: 'john-ssh'
    }),
    mkFact('loot.ssh_key', HOST_A, {
      path: '/home/ops_deploy/.ssh/id_ed25519',
      user: 'ops_deploy'
    })
  ]);

  // Dual-homed interface dump + ARP neighbor + live ligolo tunnel on HOST_A
  ingest(
    HOST_A,
    'ip -4 a',
    [
      '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536',
      '    inet 127.0.0.1/8 scope host lo',
      '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500',
      '    inet ' + HOST_A + '/24 brd 10.200.1.255 scope global eth0',
      '3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500',
      '    inet 172.30.5.10/24 brd 172.30.5.255 scope global eth1'
    ].join('\n'),
    'local-net-enum'
  );
  O.ingest.run({
    command: 'ip neigh',
    text: 'www-data@edge-gw:~$ ip neigh\n' + HOST_D_ARP + ' dev eth1 lladdr 02:42:ac:1e:09:28 REACHABLE\n',
    scope: 'host:' + HOST_A,
    forceTarget: true,
    actionId: 'local-neighbors',
    source: 'paste',
    quiet: true
  });
  S.update(eng => { eng.targets.push({ ip: HOST_D_ARP }); });
  S.addFacts([mkFact('target.configured', HOST_D_ARP)]);
  ingest(
    HOST_A,
    'ligolo-proxy -selfcert',
    '[Tunnel] Interface ligolo is UP\nAgent joined session\n',
    'pivot-ligolo'
  );

  const pivB = S.pivotRouteForTarget(HOST_B);
  const pivC = S.pivotRouteForTarget(HOST_C);
  const pivDmz = S.pivotRouteForTarget(HOST_DMZ_SIBLING);
  const pivArp = S.pivotRouteForTarget(HOST_D_ARP);

  ok(pivB && pivB.pivotHost === HOST_A && pivB.subnet === '172.30.5.0/24' && pivB.active === true,
    'pivotRouteForTarget matches internal Host B CIDR to dual-homed pivot Host A');
  ok(pivC && pivC.pivotHost === HOST_A && pivC.subnet === '172.30.5.0/24',
    'pivotRouteForTarget matches internal Host C CIDR to dual-homed pivot Host A');
  ok(pivDmz === null,
    'pivotRouteForTarget does not mark a sibling on Host A external /24 as behind a pivot');
  ok(pivArp && pivArp.pivotHost === HOST_A && pivArp.peerMatch === true,
    'pivotRouteForTarget matches cross-segment ARP neighbor discovered on Host A');

  // Verify unscanned HOST_B and HOST_C inherit zero cross-host loot or pivot projection
  const unscannedB = S.factSetForTarget(HOST_B);
  const unscannedC = S.factSetForTarget(HOST_C);
  ok(!unscannedB.has('credential.reuse_candidate'), 'Unscanned Host B inherits zero credential.reuse_candidate');
  ok(!unscannedB.has('credential.available'), 'Unscanned Host B inherits zero credential.available');
  ok(!unscannedB.has('loot.ssh_key'), 'Unscanned Host B inherits zero loot.ssh_key');
  ok(!unscannedB.has('tunnel.reachable_via_pivot'), 'Unscanned Host B inherits zero tunnel.reachable_via_pivot');
  ok(!unscannedC.has('credential.reuse_candidate'), 'Unscanned Host C inherits zero credential.reuse_candidate');
  ok(!S.resolvedContext({ target: HOST_B }).credentialId, 'Unscanned Host B resolvedContext has no auto-selected credential');
  ok(!S.resolvedContext({ target: HOST_C }).credentialId, 'Unscanned Host C resolvedContext has no auto-selected credential');

  // ---------------------------------------------------------------------------
  // 2. Scanning HOST_B surfaces unvalidated reuse hypotheses without false proof
  // ---------------------------------------------------------------------------
  S.setActiveTarget(HOST_B);
  ingest(
    HOST_B,
    'nmap -sV -p 22,445,5985 ' + HOST_B,
    [
      'Starting Nmap 7.95',
      'Nmap scan report for ' + HOST_B,
      'Host is up (0.0040s latency).',
      'PORT     STATE SERVICE       VERSION',
      '22/tcp   open  ssh           OpenSSH for_Windows_8.9',
      '445/tcp  open  microsoft-ds?',
      '5985/tcp open  http          Microsoft HTTPAPI httpd 2.0',
      'Nmap done: 1 IP address (1 host up) scanned in 0.65 seconds'
    ].join('\n'),
    'nmap-fast-open-ports'
  );

  const scannedB = S.factSetForTarget(HOST_B);
  ok(scannedB.has('tunnel.reachable_via_pivot'), 'Scanned Host B receives tunnel.reachable_via_pivot');
  const pivFactsB = scannedB.values('tunnel.reachable_via_pivot');
  ok(pivFactsB[0] && pivFactsB[0].pivotHost === HOST_A && pivFactsB[0].subnet === '172.30.5.0/24',
    'tunnel.reachable_via_pivot records pivotHost and internal subnet');

  const reuseCandsB = scannedB.values('credential.reuse_candidate');
  ok(reuseCandsB.some(c => c.user === 'cfg_svc' && c.password === 'SynthCfg#2026!' && c.originHost === HOST_A),
    'Config credential from Host A projects as credential.reuse_candidate on scanned Host B');
  ok(reuseCandsB.some(c => c.user === 'ops_deploy' && c.password === 'SynthOps#2026!' && c.originHost === HOST_A),
    'Second credential from Host A projects as credential.reuse_candidate on scanned Host B');
  ok(reuseCandsB.some(c => c.keyPath === '/home/ops_deploy/.ssh/id_ed25519' && c.originHost === HOST_A),
    'SSH private key from Host A projects as credential.reuse_candidate on scanned Host B');
  ok(!reuseCandsB.some(c => c.password === 'LapsBoundOnly#1!'),
    'Machine-bound LAPS secret on Host A never projects onto Host B');
  ok(!reuseCandsB.some(c => c.password === 'KeyPassphraseOnly!'),
    'Userless SSH key passphrase never projects as a login credential onto Host B');

  const availB = scannedB.values('credential.available');
  ok(availB.some(c => c.user === 'cfg_svc' && c.reuseFrom === HOST_A && c.unvalidatedOnTarget === true),
    'Projected credential.available on Host B is explicitly tagged unvalidatedOnTarget');
  ok(!availB.some(c => c.password === 'LapsBoundOnly#1!'),
    'Machine-bound LAPS secret never projects as credential.available on Host B');
  ok(scannedB.has('loot.ssh_key') && scannedB.values('loot.ssh_key')[0].unvalidatedOnTarget === true,
    'SSH private key projects as unvalidated loot.ssh_key on scanned Host B');

  // Strict zero-false-claim invariants on Host B
  for (const forbidden of [
    'credential.validated', 'foothold.linux', 'foothold.windows',
    'access.shell', 'access.root', 'access.admin', 'access.system',
    'smb.authenticated', 'ssh.authenticated', 'winrm.authenticated'
  ]) {
    ok(!scannedB.has(forbidden), 'Scanned Host B never fabricates ' + forbidden + ' from Host A');
  }

  const ctxB = S.resolvedContext({ target: HOST_B, service: 'smb' });
  ok(ctxB.credential && ctxB.credential.user === 'cfg_svc' && ctxB.selectionSource === 'cross-host-reuse',
    'Resolved context on scanned Host B selects projected reuse candidate without mutating target memory');
  ok(!ctxB.facts.has('credential.validated') && !ctxB.facts.has('access.root') && !ctxB.facts.has('access.admin'),
    'Resolved context on Host B holds material only, never validation or privilege');

  const rankedB = O.coach.rankFor(S.factSetForTarget(HOST_B), { target: HOST_B });
  const valMoveB = rankedB.onFlow.concat(rankedB.comingUp).find(a => a.id === 'validate-credential');
  ok(valMoveB, 'Coach surfaces validate-credential on Host B from cross-host reuse projection');
  const filledValB = O.command.fillCommand(valMoveB, rankedB.facts, { params: rankedB.params }, 0);
  ok(filledValB.filled.includes(HOST_B) && filledValB.filled.includes('cfg_svc') && filledValB.filled.includes('SynthCfg#2026!'),
    'validate-credential on Host B fills target IP and reused credential material');

  const sshKeyMoveB = rankedB.onFlow.concat(rankedB.comingUp).find(a => a.id === 'ssh-key-login');
  ok(sshKeyMoveB, 'Coach surfaces ssh-key-login on Host B when SSH and cross-host key are present');
  const filledKeyB = O.command.fillCommand(sshKeyMoveB, rankedB.facts, { params: rankedB.params }, 0);
  ok(filledKeyB.filled.includes('/home/ops_deploy/.ssh/id_ed25519') && filledKeyB.filled.includes(HOST_B),
    'ssh-key-login on Host B fills projected SSH key path and Host B IP');

  // Explicit anonymous selection on Host B suppresses cross-host auto-selection
  S.selectCredential(null, HOST_B);
  const anonCtxB = S.resolvedContext({ target: HOST_B, service: 'smb' });
  ok(!anonCtxB.credentialId && !anonCtxB.facts.has('credential.available'),
    'Explicit no-credential choice on Host B suppresses cross-host credential.available projection');
  S.update(eng => {
    delete eng.contextSelections.anonymousByTarget[HOST_B];
    delete eng.contextSelections.byTarget[HOST_B];
  });

  // ---------------------------------------------------------------------------
  // 3. Reuse failure on HOST_B retires cleanly without corrupting HOST_A,
  //    advances to next candidate on HOST_B, and HOST_C succeeds independently
  // ---------------------------------------------------------------------------
  const rejectB = ingest(
    HOST_B,
    "nxc smb " + HOST_B + " -u cfg_svc -p 'SynthCfg#2026!'",
    'SMB ' + HOST_B + ' 445 APP-NODE [-] APP-NODE\\cfg_svc:SynthCfg#2026! STATUS_LOGON_FAILURE',
    'validate-credential'
  );
  ok(rejectB.ok && rejectB.outcome && rejectB.outcome.kind === 'rejected',
    'Failed reuse attempt on Host B records rejected outcome');
  ok(S.factSetForTarget(HOST_B).has('blocker.logon_failure'),
    'Host B records blocker.logon_failure for rejected reuse attempt');

  // Dry negative probe on Host B
  const dryProbeB = ingest(
    HOST_B,
    'nmap -p 8443 ' + HOST_B,
    [
      'Starting Nmap 7.95',
      'Nmap scan report for ' + HOST_B,
      'Host is up (0.0030s latency).',
      'PORT     STATE  SERVICE',
      '8443/tcp closed https-alt',
      'Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds'
    ].join('\n'),
    'nmap-targeted-service'
  );
  ok(dryProbeB.ok, 'Dry probe on Host B ingests cleanly');

  // Verify HOST_A proven state is 100% intact after failure on HOST_B
  const afterFailA = S.factSetForTarget(HOST_A);
  ok(afterFailA.has('credential.validated') && afterFailA.has('foothold.linux') && afterFailA.has('access.root'),
    'Reuse failure on Host B never erases or corrupts proven state on Host A');
  ok(!afterFailA.has('blocker.logon_failure'),
    'Host B logon failure blocker never leaks back onto Host A');

  // Verify Host B advances to the second untried reuse candidate (ops_deploy)
  const nextCtxB = S.resolvedContext({ target: HOST_B, service: 'smb' });
  ok(nextCtxB.credential && nextCtxB.credential.user === 'ops_deploy',
    'After cfg_svc fails on Host B, cross-host reuse advances to untried candidate ops_deploy');
  const nextCmdCtxB = O.command.buildContext(S.factSetForTarget(HOST_B), { target: HOST_B });
  ok(nextCmdCtxB.reuse_user === 'ops_deploy' && nextCmdCtxB.reuse_secret === 'SynthOps#2026!',
    '{{reuse_user}} and {{reuse_secret}} on Host B also advance past rejected cfg_svc to ops_deploy');

  // Now scan HOST_C and verify cfg_svc is still untried on HOST_C and validates cleanly
  S.setActiveTarget(HOST_C);
  ingest(
    HOST_C,
    'nmap -sV -p 88,389,445,5985 ' + HOST_C,
    [
      'Starting Nmap 7.95',
      'Nmap scan report for ' + HOST_C,
      'Host is up (0.0035s latency).',
      'PORT     STATE SERVICE       VERSION',
      '88/tcp   open  kerberos-sec  Microsoft Windows Kerberos',
      '389/tcp  open  ldap          Microsoft Windows Active Directory LDAP',
      '445/tcp  open  microsoft-ds?',
      '5985/tcp open  http          Microsoft HTTPAPI httpd 2.0',
      'Nmap done: 1 IP address (1 host up) scanned in 0.55 seconds'
    ].join('\n'),
    'nmap-fast-open-ports'
  );

  const ctxCBefore = S.resolvedContext({ target: HOST_C, service: 'smb' });
  ok(ctxCBefore.credential && ctxCBefore.credential.user === 'cfg_svc',
    'Rejection on Host B does not penalize cfg_svc reuse hypothesis on freshly scanned Host C');
  ok(S.factSetForTarget(HOST_C).has('tunnel.reachable_via_pivot'),
    'Scanned Host C also receives tunnel.reachable_via_pivot via Host A');

  const winC = ingest(
    HOST_C,
    "nxc smb " + HOST_C + " -u cfg_svc -p 'SynthCfg#2026!' -d synth.example",
    'SMB ' + HOST_C + ' 445 DIR-CORE [+] synth.example\\cfg_svc:SynthCfg#2026! (Pwn3d!)',
    'validate-credential'
  );
  ok(winC.ok && winC.outcome && winC.outcome.kind === 'success',
    'Successful reuse validation on Host C records success outcome');
  ok(S.factSetForTarget(HOST_C).has('smb.authenticated') && S.factSetForTarget(HOST_C).has('access.admin'),
    'Successful reuse validation establishes smb.authenticated and access.admin on Host C');
  ok(!S.factSetForTarget(HOST_B).has('smb.authenticated') && !S.factSetForTarget(HOST_B).has('access.admin'),
    'Admin reuse win on Host C does not bleed onto Host B');

  // ---------------------------------------------------------------------------
  // 4. Extended EARNED_TOKENS gating and multi-shape extraction
  // ---------------------------------------------------------------------------
  const requiredTokens = [
    'edb_id', 'edb_file', 'edb_path', 'custom_bin',
    'source_path', 'app_base_path', 'ssh_key_path', 'reuse_user', 'reuse_secret'
  ];
  for (const tk of requiredTokens) {
    ok(O.command.EARNED_TOKENS[tk] === 1, 'EARNED_TOKENS registers ' + tk);
  }

  // Unearned gating check (including ordinary http.path not falsely unlocking source_path)
  const bareFacts = new F.FactSet([
    mkFact('port:80', '10.250.0.10'),
    mkFact('http.path', '10.250.0.10', { path: '/images' })
  ]);
  const probeTpl = [
    '{{edb_id}}', '{{edb_file}}', '{{edb_path}}', '{{custom_bin}}',
    '{{source_path}}', '{{app_base_path}}', '{{ssh_key_path}}', '{{reuse_user}}', '{{reuse_secret}}'
  ].join(' ');
  const unfilled = O.command.unfilledTokens(O.command.fillTemplate(probeTpl, bareFacts, { target: '10.250.0.10' }));
  ok(requiredTokens.every(tk => unfilled.includes(tk)),
    'All 9 extended earned tokens remain unfilled and gated when supporting facts are absent');

  // Earned EDB candidate + inspected script
  const edbFacts = new F.FactSet([
    mkFact('exploit.edb_candidate', '10.250.0.10', {
      edb_id: 'EDB-51420',
      edb_path: '/usr/share/exploitdb/exploits/linux/remote/51420.py'
    }),
    mkFact('exploit.script_inspected', '10.250.0.10', {
      edb_id: '51420',
      edb_file: '51420.py'
    })
  ]);
  const filledEdb = O.command.fillTemplate(
    'searchsploit -m {{edb_id}} && cp {{edb_path}} . && python3 {{edb_file}}',
    edbFacts,
    { target: '10.250.0.10' }
  );
  ok(filledEdb === 'searchsploit -m 51420 && cp /usr/share/exploitdb/exploits/linux/remote/51420.py . && python3 51420.py',
    'EDB tokens resolve cleanly across exploit.edb_candidate and exploit.script_inspected: ' + filledEdb);

  // Earned custom binary (both privesc.custom_binary and host.custom_artifact shapes)
  const binFacts1 = new F.FactSet([
    mkFact('privesc.custom_binary', '10.250.0.10', { binary: '/opt/svc-helper/bin/runner' })
  ]);
  const binFacts2 = new F.FactSet([
    mkFact('host.custom_artifact', '10.250.0.10', { artifacts: ['~/tools/custom_agent'] })
  ]);
  ok(O.command.fillTemplate('strings {{custom_bin}}', binFacts1, { target: '10.250.0.10' }) === 'strings /opt/svc-helper/bin/runner',
    'custom_bin resolves from privesc.custom_binary');
  ok(O.command.fillTemplate('ls -la {{custom_bin}}', binFacts2, { target: '10.250.0.10' }) === 'ls -la ~/tools/custom_agent',
    'custom_bin resolves from host.custom_artifact array and honors PATH_TOKENS tilde handling');

  // Earned source_path and derived/explicit app_base_path
  const srcFacts1 = new F.FactSet([
    mkFact('web.manifest_disclosed', '10.250.0.10', { url: 'http://10.250.0.10:3000/portal/app/package.json' })
  ]);
  const filledSrc1 = O.command.fillTemplate(
    'curl -s http://10.250.0.10:3000{{source_path}} && curl -s http://10.250.0.10:3000{{app_base_path}}/index.js',
    srcFacts1,
    { target: '10.250.0.10' }
  );
  ok(filledSrc1 === 'curl -s http://10.250.0.10:3000/portal/app/package.json && curl -s http://10.250.0.10:3000/portal/app/index.js',
    'source_path and derived app_base_path resolve from web.manifest_disclosed URL: ' + filledSrc1);

  const srcFacts2 = new F.FactSet([
    mkFact('web.source_disclosed', '10.250.0.10', {
      source_path: '/var/www/service/src/routes.py',
      app_base_path: '/var/www/service'
    })
  ]);
  ok(O.command.fillTemplate('ls {{app_base_path}} && cat {{source_path}}', srcFacts2, { target: '10.250.0.10' })
    === 'ls /var/www/service && cat /var/www/service/src/routes.py',
    'Explicit source_path and app_base_path resolve from web.source_disclosed');

  // Earned ssh_key_path and NT-hash reuse_secret Pass-the-Hash adaptation
  const ntHash = '8846f7eaee8fb117ad06bdd830b7586c';
  const reuseNtFacts = new F.FactSet([
    mkFact('credential.certificate', '10.250.0.10', { kind: 'private_key', encrypted: false }),
    mkFact('credential.reuse_candidate', '10.250.0.10', {
      user: 'svc_sync',
      nthash: ntHash,
      originHost: HOST_A
    })
  ]);
  const filledNtReuse = O.command.fillTemplate(
    "ssh -i {{ssh_key_path}} {{reuse_user}}@{{target}} && nxc smb {{target}} -u {{reuse_user}} -p '{{reuse_secret}}'",
    reuseNtFacts,
    { target: '10.250.0.10' }
  );
  ok(filledNtReuse === "ssh -i id_rsa svc_sync@10.250.0.10 && nxc smb 10.250.0.10 -u svc_sync -H '" + ntHash + "'",
    'ssh_key_path defaults to id_rsa on inline private_key and NT-hash reuse_secret adapts -p to -H: ' + filledNtReuse);

  console.log('challenge-labs-multi-target-smoke: ' + checks + ' checks passed');
})().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
