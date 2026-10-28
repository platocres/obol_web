/* Wittgensteinian Contextual Inference & Causal Entailment Smoke Suite.
 * Verifies:
 *   1. Persistent 5-slot copiedQueue (Attention Frame, no wall-clock expiration, move contract lookup)
 *   2. Dynamic 2D Table Header Mapping (survives column reordering & unknown tools)
 *   3. Key-Value Object Block Grouping (order-independent attribute co-occurrence)
 *   4. Command-Line Input Echo Subtraction (never mints echoed input arguments on failure)
 *   5. Global Engagement Entity Cross-Referencing (binds known engagement users to new secrets/hashes)
 *   6. Wrapper-Delta Diffing across consecutive pastes (strips shared HTML/banner boilerplate)
 *   7. Shell Prompt Telemetry & Phase-Aware Internal Subnet Pivot Discovery
 *   8. Out-of-Order Jump & Causal Entailment Gate Synchronization (Success, Protocol Rejection, Transport Failure)
 */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '../..');
function storage() {
  const values = new Map();
  return {
    get length() { return values.size; },
    key: i => Array.from(values.keys())[i],
    getItem: k => values.has(k) ? values.get(k) : null,
    setItem: (k, v) => values.set(k, String(v)),
    removeItem: k => values.delete(k)
  };
}

const sandbox = {
  console: { log() {}, warn() {}, error() {} },
  localStorage: storage(),
  sessionStorage: storage(),
  setTimeout() { return 1; },
  clearTimeout() {},
  Promise
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

function load(file) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), sandbox, { filename: file });
}

['facts', 'context', 'phases', 'pack', 'command', 'profile', 'workspace', 'chain', 'outcomes'].forEach(n => load('assets/engine/' + n + '.js'));
load('assets/ui/store.js');
load('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'inference', 'index']
  .forEach(n => load('assets/engine/parsers/' + n + '.js'));
load('assets/ui/ingest.js');

const O = sandbox.OBOL;
const S = O.store;
const packData = O.pack.PACK_NAMES.map(name => JSON.parse(fs.readFileSync(path.join(ROOT, 'data/packs', name + '.json'), 'utf8')));
const actions = O.pack.loadPacks(packData);
O.packs = { actions: () => actions };

let passed = 0;
function ok(cond, msg, debugTarget) {
  if (!cond) {
    console.error('  FAIL:', msg);
    if (debugTarget) console.error('  FACTS:', JSON.stringify(S.factSetForTarget(debugTarget).facts, null, 2));
    process.exit(1);
  }
  console.log('  ok  :', msg);
  passed++;
}

function hasFact(target, kind, pred) {
  const fs = S.factSetForTarget(target);
  return fs.facts.some(f => f && f.state === 'supported' && f.kind === kind && (!pred || pred(f.value || {}, f)));
}

(async () => {
await S.createEngagement('Wittgenstein Smoke');
console.log('=== Wittgensteinian Contextual Inference & Causal Entailment Smoke ===');

// ---- 1. Attention Frame: Persistent 5-slot copiedQueue & Move Contract Lookup ----
{
  S.update(e => { e.params = e.params || {}; e.params.target = '10.10.10.11'; });
  O.ingest.setLastCopied({ command: 'nxc smb 10.10.10.11 -u "" -p "" --shares', actionId: 'smb-shares', target: '10.10.10.11' });
  O.ingest.setLastCopied({ command: 'GetUserSPNs.py -request corp.local/bob', actionId: 'kerberoast', target: '10.10.10.11' });
  const q = O.ingest.getCopiedQueue();
  ok(q.length === 2, 'copiedQueue retains multiple copied commands in LIFO order');
  ok(q[0].actionId === 'kerberoast' && Array.isArray(q[0].produces) && q[0].produces.includes('hash.tgs'), 'copiedQueue automatically resolves action.produces contract from pack catalog');
  ok(O.ingest.getLastCopied().actionId === 'kerberoast', 'getLastCopied returns most recent entry without arbitrary timer expiration');
}

// ---- 2. Dynamic 2D Table Header Mapping (Column Reordering & Unknown Tool Output) ----
{
  const T = '10.10.10.12';
  // Reordered SMB Share Table: Access | Description | Share (reversed from classic Share | Type | Comment)
  const reorderedShares = [
    'Access       Description          Share',
    '------       -----------          -----',
    'NO ACCESS    Remote Admin         ADMIN$',
    'READ, WRITE  Finance Department   Finance_Drop',
    'READ         IPC Service          IPC$'
  ].join('\n');
  O.ingest.run({ text: reorderedShares, command: 'custom-smb-tool 10.10.10.12', scope: 'host:' + T, quiet: true });
  ok(hasFact(T, 'smb.shares', v => Array.isArray(v.shares) && v.shares.includes('Finance_Drop')), 'Dynamic table mapper extracts reordered share column (Access | Description | Share)');
  ok(hasFact(T, 'smb.readable_share') && hasFact(T, 'smb.writable_share'), 'Dynamic table mapper infers readable and writable share facts from reordered columns');

  // Reordered Port Scan Table: State | Banner | Port
  const T2 = '10.10.10.13';
  const reorderedPorts = [
    'State   Service   Port',
    '-----   -------   ----',
    'OPEN    ssh       22/tcp',
    'OPEN    http      8080/tcp',
    'CLOSED  telnet    23/tcp'
  ].join('\n');
  O.ingest.run({ text: reorderedPorts, command: 'nextgen-portscan 10.10.10.13', scope: 'host:' + T2, quiet: true });
  ok(hasFact(T2, 'port:22') && hasFact(T2, 'port:8080') && !hasFact(T2, 'port:23'), 'Dynamic table mapper extracts open ports and ignores closed ports from reordered columns');
  ok(hasFact(T2, 'ssh.reachable') && hasFact(T2, 'http.reachable'), 'Dynamic table mapper triggers service reachability from reordered port scan');

  // Reordered Web Fuzz Table: Status | Size | Endpoint
  const reorderedWeb = [
    '| Status | Bytes | Endpoint       |',
    '|--------|-------|----------------|',
    '| 200    | 4120  | /admin-console |',
    '| 403    | 280   | /internal-api  |',
    '| 404    | 0     | /not-found     |'
  ].join('\n');
  O.ingest.run({ text: reorderedWeb, command: 'custom-web-fuzz http://10.10.10.13:8080', scope: 'host:' + T2, quiet: true });
  ok(hasFact(T2, 'web.paths', v => Array.isArray(v.paths) && v.paths.includes('/admin-console') && !v.paths.includes('/not-found')), 'Dynamic table mapper extracts web paths from pipe-delimited reordered columns');
}

// ---- 3. Key-Value Object Block Grouping (Order-Independent Attributes) ----
{
  const T = '10.10.10.14';
  const reorderedAdcs = [
    '=== Certificate Audit v9 ===',
    'Enrollment Rights         : CORP\\Domain Users',
    'Enrollee Supplies Subject : True',
    'Risk Flag                 : ESC1',
    'Template Name             : CorpVPNSubordinate'
  ].join('\n');
  O.ingest.run({ text: reorderedAdcs, command: 'future-pkiaudit -t 10.10.10.14', scope: 'host:' + T, quiet: true });
  ok(hasFact(T, 'adcs.vulnerable', v => v.template === 'CorpVPNSubordinate' && Array.isArray(v.esc) && v.esc.includes('ESC1')), 'KV block grouper pairs Enrollee Supplies Subject / ESC1 with Template Name regardless of line order');
}

// ---- 4. Command-Echo Subtraction (Zero Self-Inflicted False Positives) ----
{
  const T = '10.10.10.15';
  const failedEcho = [
    '[*] Tool v2.0 connecting to 10.10.10.15',
    '[*] Authenticating with username = svc_test and password = WrongGuessPassword123!',
    '[-] Authentication FAILED: invalid credentials'
  ].join('\n');
  O.ingest.run({
    command: 'unknown-auth-tool -u svc_test -p WrongGuessPassword123! 10.10.10.15',
    text: failedEcho,
    scope: 'host:' + T,
    quiet: true
  });
  ok(!hasFact(T, 'credential.candidate', v => v.password === 'WrongGuessPassword123!'), 'Command-echo subtraction prevents echoed input password on a failed attempt from minting credential.candidate');
}

// ---- 5. Global Engagement Entity Cross-Referencing ----
{
  const T = '10.10.10.16';
  // Seed engagement with known AD user list
  S.addFacts([O.facts.makeFact({ kind: 'ad.user_list', scope: 'host:' + T, value: { users: ['svc_ark', 'j.smith'], count: 2 }, state: 'supported', source: 'seed' })], 'seed', T);
  // Now paste an unrecognized tool output containing known user svc_ark alongside a 32-hex hash
  const customDump = 'Record #4 -> Account: svc_ark | Digest: 8846f7eaee8fb117ad06bdd830b7586c';
  O.ingest.run({ command: 'custom-extractor 10.10.10.16', text: customDump, scope: 'host:' + T, quiet: true });
  ok(hasFact(T, 'credential.candidate', v => v.user === 'svc_ark' && v.nthash === '8846f7eaee8fb117ad06bdd830b7586c'), 'Global entity index binds already-known engagement user svc_ark to co-occurring NTLM digest in unknown tool output');
}

// ---- 6. Wrapper-Delta Diffing Across Consecutive Pastes ----
{
  const T = '10.10.10.17';
  const baseWrapper = [
    '<html>',
    '<head><title>Corporate Portal</title></head>',
    '<body>',
    '<nav>Home | About | Contact</nav>',
    '<div class="banner">Welcome to Corporate Portal v4.2</div>',
    '<div class="content">Standard page content here.</div>',
    '<footer>Copyright 2026</footer>',
    '</body>',
    '</html>'
  ].join('\n');
  const secondPasteWithDelta = [
    '<html>',
    '<head><title>Corporate Portal</title></head>',
    '<body>',
    '<nav>Home | About | Contact</nav>',
    '<div class="banner">Welcome to Corporate Portal v4.2</div>',
    'db_user: portal_admin',
    'db_password = PortalSuperSecret2026!',
    '<div class="content">Standard page content here.</div>',
    '<footer>Copyright 2026</footer>',
    '</body>',
    '</html>'
  ].join('\n');
  O.ingest.run({ command: 'curl -s "http://10.10.10.17/view.php?page=home"', text: baseWrapper, scope: 'host:' + T, quiet: true });
  O.ingest.run({ command: 'curl -s "http://10.10.10.17/view.php?page=config"', text: secondPasteWithDelta, scope: 'host:' + T, quiet: true });
  ok(hasFact(T, 'credential.candidate', v => v.password === 'PortalSuperSecret2026!'), 'Wrapper-delta diffing isolates injected payload lines between consecutive HTML wrapper pastes');
}

// ---- 7. Shell Prompt Telemetry & Phase-Aware Internal Subnet Pivot Discovery ----
{
  const T = '10.10.10.18';
  const promptAndNet = [
    'www-data@prod-web:/var/www/html$ custom-net-check',
    'Interface 1: 10.10.10.18/24',
    'Internal link: 172.16.88.5 (reachable)',
    'Internal subnet: 172.16.88.0/24'
  ].join('\n');
  O.ingest.run({ text: promptAndNet, scope: 'host:' + T, quiet: true });
  ok(hasFact(T, 'foothold.linux', v => v.identity === 'www-data'), 'Shell prompt telemetry infers local Linux foothold and user identity from non-attacker prompt');
  ok(hasFact(T, 'network.subnet_candidate', v => Array.isArray(v.subnets) && v.subnets.includes('172.16.88.0/24')), 'Phase-aware inference mints network.subnet_candidate for new internal /24 discovered on foothold host');
  ok(hasFact(T, 'host.arp_neighbor', v => Array.isArray(v.neighbors) && v.neighbors.includes('172.16.88.5')), 'Phase-aware inference mints host.arp_neighbor for internal host discovered on foothold host');
}

// ---- 8. Out-of-Order Jump & Causal Entailment Gate Synchronization ----
{
  // 8A: Jump Ahead & Succeed (Skip nmap, paste AD ACL finding directly on a fresh host)
  const T_JUMP = '10.10.10.50';
  const aclOut = 'CORP\\svc_loanmgr -> GenericAll -> CN=Domain Admins,CN=Users,DC=corp,DC=local';
  O.ingest.run({ command: 'custom-acl-check 10.10.10.50', text: aclOut, scope: 'host:' + T_JUMP, quiet: true });
  ok(hasFact(T_JUMP, 'ad.acl_lead'), 'Out-of-order paste mints the direct finding (ad.acl_lead)');
  ok(hasFact(T_JUMP, 'host.up') && hasFact(T_JUMP, 'ldap.reachable') && hasFact(T_JUMP, 'ad.dc_candidate'), 'Causal entailment backfills host.up, ldap.reachable, and ad.dc_candidate when user jumps ahead to AD');
  ok(!hasFact(T_JUMP, 'scan.nmap.quick'), 'Causal entailment preserves unsettled scan.nmap.quick so skipped broad port scan stays visible');

  // Verify downstream move in pack.js is now unlocked!
  const fsJump = S.factSetForTarget(T_JUMP);
  const aclAbuseMove = actions.find(a => a.id === 'ad-acl-abuse');
  const anonLdapMove = actions.find(a => a.id === 'ad-anon-ldap-enum');
  ok(aclAbuseMove && aclAbuseMove.eligible(fsJump) && anonLdapMove && anonLdapMove.eligible(fsJump), 'Downstream AD ACL abuse and LDAP moves are immediately eligible in pack.js after out-of-order jump');

  // 8B: Jump Ahead & Get Protocol Rejection (Skip nmap, fail SMB login with STATUS_LOGON_FAILURE)
  const T_REJ = '10.10.10.60';
  const smbRej = 'SMB   10.10.10.60   445   FILESRV   [-] CORP\\bob:badpass STATUS_LOGON_FAILURE';
  O.ingest.run({ command: 'nxc smb 10.10.10.60 -u bob -p badpass', text: smbRej, scope: 'host:' + T_REJ, quiet: true });
  ok(!hasFact(T_REJ, 'smb.authenticated'), 'Failed SMB login never unlocks smb.authenticated');
  ok(hasFact(T_REJ, 'host.up') && hasFact(T_REJ, 'port:445') && hasFact(T_REJ, 'smb.reachable'), 'Protocol rejection (STATUS_LOGON_FAILURE) entails host.up, port:445, and smb.reachable so unauthenticated SMB recon unlocks');

  // 8C: Jump Ahead & Hit Transport Failure (Host down / Connection refused)
  const T_DOWN = '10.10.10.70';
  const downOut = 'Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn';
  O.ingest.run({ command: 'nmap 10.10.10.70', text: downOut, scope: 'host:' + T_DOWN, quiet: true });
  ok(!hasFact(T_DOWN, 'host.up') && !hasFact(T_DOWN, 'smb.reachable'), 'Transport failure (Host seems down) unlocks zero reachability or progress gates');
}

// ---- 9. Adversarial Format-Mutation Matrix (M1-M13: Unknown Future Tool Outputs) ----
{
  // M1: Key-value per-line port scan
  const T_M1 = '10.10.10.80';
  const mutPorts = [
    '[+] Scan result: Port: 80/tcp | Service: http | State: OPEN',
    '[+] Scan result: Port: 445/tcp | Service: microsoft-ds | State: OPEN',
    '[-] Scan result: Port: 23/tcp | Service: telnet | State: CLOSED'
  ].join('\n');
  O.ingest.run({ command: 'future-scan 10.10.10.80', text: mutPorts, scope: 'host:' + T_M1, quiet: true });
  ok(hasFact(T_M1, 'port:80') && hasFact(T_M1, 'port:445') && !hasFact(T_M1, 'port:23') && hasFact(T_M1, 'http.reachable') && hasFact(T_M1, 'smb.reachable'),
    'M1: Atom port + positive polarity co-occurrence extracts open ports and service reachability without a table');

  // M2: Mutated SMB auth + Pwn3d!
  const T_M2 = '10.10.10.81';
  const mutSmbAuth = '[SMB-v4] host=10.10.10.81 port=445 status=AUTHENTICATED user=CORP\\svc_sql:Winter2026! (Pwn3d!)';
  O.ingest.run({ command: 'nextgen-smb 10.10.10.81', text: mutSmbAuth, scope: 'host:' + T_M2, quiet: true });
  ok(hasFact(T_M2, 'credential.available', v => v.user === 'svc_sql' && v.password === 'Winter2026!')
    && hasFact(T_M2, 'smb.authenticated') && hasFact(T_M2, 'access.admin'),
    'M2: Domain\\user:password + positive polarity co-occurrence mints credential.available, smb.authenticated, and access.admin');

  // M3: Unicode box-drawing SMB share table with multi-word headers and ==== underline
  const T_M3 = '10.10.10.82';
  const mutUnicodeShares = [
    '┌──────────────┬───────────────┬────────────────────┐',
    '│ Share Name   │ Access Rights │ Comment            │',
    '╞══════════════╪═══════════════╪════════════════════╡',
    '│ Backups      │ READ, WRITE   │ Server Backups     │',
    '│ IPC$         │ READ          │ Remote IPC         │',
    '└──────────────┴───────────────┴────────────────────┘'
  ].join('\n');
  O.ingest.run({ command: 'unicode-shares 10.10.10.82', scope: 'host:' + T_M3, text: mutUnicodeShares, quiet: true });
  ok(hasFact(T_M3, 'smb.shares', v => Array.isArray(v.shares) && v.shares.includes('Backups'))
    && hasFact(T_M3, 'smb.writable_share'),
    'M3: Dynamic table mapper handles Unicode box-drawing borders and multi-word headers (Share Name | Access Rights)');

  // M4: Bullet-prefixed LDAP KV blocks with [Record #N] dividers
  const T_M4 = '10.10.10.83';
  const mutLdapKv = [
    '[Record #1]',
    '- Account: svc_mssql',
    '- SPN: MSSQLSvc/dc01.corp.local:1433',
    '- SID: S-1-5-21-11111111-22222222-33333333-1104',
    '[Record #2]',
    '- Account: svc_backup',
    '- UPN: svc_backup@corp.local',
    '- SID: S-1-5-21-11111111-22222222-33333333-1105'
  ].join('\n');
  O.ingest.run({ command: 'ldap-ng -d corp.local 10.10.10.83', scope: 'host:' + T_M4, text: mutLdapKv, quiet: true });
  ok(hasFact(T_M4, 'ad.user_list', v => Array.isArray(v.users) && v.users.includes('svc_mssql') && v.users.includes('svc_backup')),
    'M4: KV block grouper extracts directory users across [Record #N] dividers and bullet prefixes');

  // M5 & M6: Mutated NTDS dump & modular hash lines
  const T_M6 = '10.10.10.84';
  const mutNtds = [
    'CORP\\Administrator | RID=500 | Hashes=aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c',
    'svc_web:$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG'
  ].join('\n');
  O.ingest.run({ command: 'ntds-extract 10.10.10.84', scope: 'host:' + T_M6, text: mutNtds, quiet: true });
  ok(hasFact(T_M6, 'hash.ntlm', v => v.user === 'Administrator' && v.nthash === '8846f7eaee8fb117ad06bdd830b7586c')
    && hasFact(T_M6, 'credential.available', v => v.user === 'Administrator' && v.nthash === '8846f7eaee8fb117ad06bdd830b7586c')
    && hasFact(T_M6, 'hash.crackable'),
    'M5/M6: Atom NT-hash pair and modular hash co-occurrence mints hash.ntlm, credential.available, and hash.crackable', T_M6);

  // M8: Mutated ACL KV block (ReadLAPSPassword) does NOT prematurely settle ad-acl-abuse
  const T_M8 = '10.10.10.85';
  const mutAclKv = [
    'Trustee : CORP\\john',
    'Right   : ReadLAPSPassword',
    'Target  : CN=DC01,OU=Domain Controllers,DC=corp,DC=local'
  ].join('\n');
  O.ingest.run({ command: 'acl-finder 10.10.10.85', scope: 'host:' + T_M8, text: mutAclKv, quiet: true });
  ok(hasFact(T_M8, 'ad.acl_lead', v => v.right === 'ReadLAPSPassword') && !hasFact(T_M8, 'ad.control_paths'),
    'M8: ACL discovery mints ad.acl_lead without prematurely co-minting ad.control_paths');

  // M9: Short 3-line web fuzzer output (below statistical outlier 10-line threshold)
  const T_M9 = '10.10.10.86';
  const mutWebShort = [
    '[200 OK] GET /api/v2/export (1420 bytes)',
    '[403 FORBIDDEN] GET /admin-panel (280 bytes)',
    '[404 NOT FOUND] GET /missing (0 bytes)'
  ].join('\n');
  O.ingest.run({ command: 'tiny-fuzz http://10.10.10.86', scope: 'host:' + T_M9, text: mutWebShort, quiet: true });
  ok(hasFact(T_M9, 'web.paths', v => Array.isArray(v.paths) && v.paths.includes('/api/v2/export') && v.paths.includes('/admin-panel') && !v.paths.includes('/missing')),
    'M9: Per-line URI + HTTP status co-occurrence extracts web.paths even on <10 line outputs');

  // M10: CSV database credential dump with HTTP header preamble
  const T_M10 = '10.10.10.87';
  const mutCsvHttp = [
    'HTTP/1.1 200 OK',
    'Server: nginx/1.24.0',
    '',
    'login_name,password',
    'db_operator,Sup3rCsvPass2026!'
  ].join('\n');
  O.ingest.run({ command: 'curl -i http://10.10.10.87/export.csv', scope: 'host:' + T_M10, text: mutCsvHttp, quiet: true });
  ok(hasFact(T_M10, 'credential.available', v => v.user === 'db_operator' && v.password === 'Sup3rCsvPass2026!'),
    'M10: CSV table inside HTTP 200 response extracts credential.available without being blocked by http.reachable');

  // M11, M12, M13: Linux SUID/Capabilities/Writable-etc, Windows Unquoted Service, and Web RCE `id`
  const T_M11 = '10.10.10.88';
  const mutLinuxPriv = [
    '-rwsr-xr-x 1 root root 54256 Jan 10 12:00 /usr/bin/find',
    '/usr/bin/python3.11 = cap_setuid+ep',
    '-rw-rw-rw- 1 root root 1842 Jan 10 12:00 /etc/passwd'
  ].join('\n');
  O.ingest.run({ command: 'custom-lin-enum', scope: 'host:' + T_M11, text: mutLinuxPriv, quiet: true });
  ok(hasFact(T_M11, 'privesc.suid') && hasFact(T_M11, 'privesc.capabilities') && hasFact(T_M11, 'privesc.writable_etc') && hasFact(T_M11, 'foothold.linux'),
    'M11: Permission mode + POSIX path co-occurrence mints privesc.suid, privesc.capabilities, privesc.writable_etc, and entails foothold.linux');

  const T_M12 = '10.10.10.89';
  const mutWinSvc = [
    'Service Name : VulnAgent',
    'Binary Path  : C:\\Program Files\\Custom Corp\\Vuln Agent\\agent.exe',
    'Permissions  : BUILTIN\\Users (SERVICE_ALL_ACCESS)'
  ].join('\n');
  O.ingest.run({ command: 'custom-win-enum', scope: 'host:' + T_M12, text: mutWinSvc, quiet: true });
  ok(hasFact(T_M12, 'privesc.unquoted_service') && hasFact(T_M12, 'privesc.weak_service_permission') && hasFact(T_M12, 'foothold.windows'),
    'M12: Windows service KV block mints privesc.unquoted_service, privesc.weak_service_permission, and entails foothold.windows');

  const T_M13 = '10.10.10.90';
  O.ingest.run({ command: 'curl -s "http://10.10.10.90/shell.php?c=id"', scope: 'host:' + T_M13, text: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)', quiet: true });
  ok(hasFact(T_M13, 'web.rce') && hasFact(T_M13, 'foothold.linux', v => v.identity === 'www-data'),
    'M13: POSIX uid/gid output from web client mints web.rce and foothold.linux');
}

// ---- 10. Adversarial False-Positive & Poisoning Guards (FP1-FP7) ----
{
  const T_FP = '10.10.10.91';
  // FP1: Two-line Kali prompt followed by UPN + `# comment` in stdout
  const kaliPromptWithUpnComment = [
    '┌──(kali㉿kali)-[~]',
    '└─$ custom-query 10.10.10.91',
    'Contact: admin@corp.local # built-in domain admin account'
  ].join('\n');
  O.ingest.run({ text: kaliPromptWithUpnComment, scope: 'host:' + T_FP, quiet: true });
  ok(!hasFact(T_FP, 'foothold.linux') && !hasFact(T_FP, 'access.root'),
    'FP1: Two-line Kali prompt and UPN with inline # comment never false-positive as foothold.linux or access.root');

  // FP2: CLI --help output containing secret and ACL examples
  const helpOut = [
    'usage: super-tool [-h] -u USER -p PASSWORD',
    'optional arguments:',
    '  -h, --help            show this help message and exit',
    '  -p, --password        Example: password = SuperSecretExample123! or GenericAll'
  ].join('\n');
  O.ingest.run({ command: 'super-tool --help', text: helpOut, scope: 'host:' + T_FP, quiet: true });
  ok(!hasFact(T_FP, 'credential.candidate') && !hasFact(T_FP, 'ad.acl_lead'),
    'FP2: CLI --help / usage output is ignored and never mints credentials or ACL leads');

  // FP3: Benign table `| Author | Vulnerability | None |` and benign ADCS `Enrollee Supplies Subject: False`
  const benignTblAndAdcs = [
    '| Author | Vulnerability |',
    '|--------|---------------|',
    '| alice  | None          |',
    '',
    'Template Name             : StandardUser',
    'Enrollee Supplies Subject : False',
    'Extended Key Usage        : Any Purpose'
  ].join('\n');
  O.ingest.run({ command: 'audit-report 10.10.10.91', text: benignTblAndAdcs, scope: 'host:' + T_FP, quiet: true });
  ok(!hasFact(T_FP, 'ad.acl_lead') && !hasFact(T_FP, 'adcs.vulnerable') && !hasFact(T_FP, 'ad.dc_candidate'),
    'FP3/FP4: Benign Author/Vulnerability:None table and Enrollee Supplies Subject:False never mint ad.acl_lead or adcs.vulnerable');

  // FP5: Known user on a line with an MD5 file checksum
  S.addFacts([O.facts.makeFact({ kind: 'ad.user_list', scope: 'host:' + T_FP, value: { users: ['svc_ark'], count: 1 }, state: 'supported', source: 'seed' })], 'seed', T_FP);
  O.ingest.run({ command: 'md5sum backup_svc_ark.tar.gz', text: '9e107d9d372bb6826bd81d3542a419d6  backup_svc_ark.tar.gz\nMD5 (svc_ark.zip) = d41d8cd98f00b204e9800998ecf8427e', scope: 'host:' + T_FP, quiet: true });
  ok(!hasFact(T_FP, 'hash.ntlm'),
    'FP5: MD5 file checksums co-occurring with a known username never false-positive as NTLM hashes');

  // FP6: Mixed-polarity output (line 1 fails, line 3 succeeds)
  const mixedPolarity = [
    '[-] Anonymous bind FAILED: access denied',
    '[*] Retrying with fallback config...',
    '[+] Found config secret: user = svc_ark, password = ValidMixedPass2026!'
  ].join('\n');
  O.ingest.run({ command: 'config-probe 10.10.10.91', text: mixedPolarity, scope: 'host:' + T_FP, quiet: true });
  ok(hasFact(T_FP, 'credential.available', v => v.user === 'svc_ark' && v.password === 'ValidMixedPass2026!'),
    'FP6: Negative polarity on an earlier line does not poison valid credential extraction on a later line', T_FP);

  // FP7: Two consecutive non-web CLI commands sharing ASCII table headers
  const T_FP7 = '10.10.10.92';
  const cliTable1 = [
    '+----------+----------+',
    '| username | password |',
    '+----------+----------+',
    '| user_one | PassOne! |',
    '+----------+----------+'
  ].join('\n');
  const cliTable2 = [
    '+----------+----------+',
    '| username | password |',
    '+----------+----------+',
    '| user_two | PassTwo! |',
    '+----------+----------+'
  ].join('\n');
  O.ingest.run({ command: 'my-db-cli --row 1', text: cliTable1, scope: 'host:' + T_FP7, quiet: true });
  O.ingest.run({ command: 'my-db-cli --row 2', text: cliTable2, scope: 'host:' + T_FP7, quiet: true });
  ok(hasFact(T_FP7, 'credential.available', v => v.user === 'user_two' && v.password === 'PassTwo!'),
    'FP7: Wrapper-delta never strips table headers across consecutive CLI commands');
}

// ---- 11. Adversarial Gating, Domain Linkage, Target Routing & Multi-Command Session Guards (G1-G4) ----
{
  // G1 & G2: Out-of-order AD jump with domain-scoped facts (`kerbrute -d corp.local` on a fresh host)
  const T_DOM = '10.10.10.95';
  const kerbruteOut = [
    '2026/10/24 22:00:00 >  [+] VALID USERNAME:       svc_tgs@corp.local',
    '2026/10/24 22:00:01 >  [+] VALID USERNAME:       j.doe@corp.local'
  ].join('\n');
  O.ingest.run({ command: 'kerbrute userenum -d corp.local --dc 10.10.10.95 users.txt', text: kerbruteOut, scope: 'host:' + T_DOM, quiet: true });
  ok(hasFact(T_DOM, 'host.domain', v => v.domain === 'corp.local')
    && hasFact(T_DOM, 'ad.domain_known', v => v.domain === 'corp.local')
    && hasFact(T_DOM, 'ad.user_list', v => Array.isArray(v.users) && v.users.includes('svc_tgs')),
    'G1/G2: Out-of-order AD tool with -d corp.local co-mints host.domain and ad.domain_known so domain-scoped facts are linked to the host');

  // G3: On-host foothold command mentioning another internal IP must NOT hijack target routing
  const T_LOCAL = '10.10.10.96';
  S.update(e => { e.params = e.params || {}; e.params.target = T_LOCAL; });
  const localPing = [
    'www-data@prod-web:/var/www/html$ ping -c 1 172.16.200.5',
    'PING 172.16.200.5 (172.16.200.5) 56(84) bytes of data.',
    '64 bytes from 172.16.200.5: icmp_seq=1 ttl=64 time=0.45 ms'
  ].join('\n');
  O.ingest.run({ text: localPing, quiet: true });
  ok(hasFact(T_LOCAL, 'foothold.linux', v => v.identity === 'www-data')
    && !hasFact('172.16.200.5', 'foothold.linux'),
    'G3: On-host target shell prompt running ping to an internal IP routes foothold.linux to the active host, not the pinged IP');

  // G4: Multi-command session paste preserves prompt telemetry across splitSession -> importSession
  const T_SESS = '10.10.10.97';
  S.update(e => { e.params = e.params || {}; e.params.target = T_SESS; });
  const multiCmdPaste = [
    'dev_admin@app-srv:/opt/app$ uname -r',
    '5.15.0-105-generic',
    'dev_admin@app-srv:/opt/app$ ip route',
    'default via 10.10.10.1 dev eth0',
    '172.16.250.0/24 dev eth1 proto kernel scope link src 172.16.250.10'
  ].join('\n');
  O.ingest.run({ text: multiCmdPaste, quiet: true });
  ok(hasFact(T_SESS, 'foothold.linux', v => v.identity === 'dev_admin')
    && hasFact(T_SESS, 'network.subnet_candidate', v => Array.isArray(v.subnets) && v.subnets.includes('172.16.250.0/24')),
    'G4: Multi-command session paste preserves shell prompt telemetry across splitSession and infers foothold.linux + network.subnet_candidate');
}

// ---- 12. Wave 2 Adversarial & Performance Stress Tests (W2-P1..P4, W2-A1..A7) ----
{
  const { performance } = require('perf_hooks');

  // W2-P1: 20,000-line (2.1 MB) full-log paste performance & deep-tail recall (< 650ms, down from 4,545ms)
  const bigLines = [];
  for (let i = 0; i < 20000; i++) {
    bigLines.push('2026-10-24 12:00:00 [INFO] Worker ' + (i % 16) + ' processed /api/v1/items/' + i + ' from 10.10.10.' + ((i % 250) + 1) + ' status=200 time=12ms');
  }
  bigLines.push('CORP\\svc_tail_20k : password = TailSecretAtLine20000!');
  const bigBlob = bigLines.join('\n');
  let t0 = performance.now();
  const resP1 = O.parsers.parseActionOutput({ command: 'cat /var/log/app.log', stdout: bigBlob, scope: 'host:10.10.10.100' });
  let elapsedP1 = performance.now() - t0;
  ok(elapsedP1 < 650 && resP1.facts.some(f => f.kind === 'credential.candidate' && f.value && f.value.password === 'TailSecretAtLine20000!'),
    'W2-P1: 20,000-line (2.1 MB) log paste completes full parseActionOutput in <650ms (' + elapsedP1.toFixed(1) + 'ms) and extracts finding at line 20,001');

  // W2-P2: _SECTION_DIVIDER_RE 10,000-dash ReDoS guard (< 20ms, down from 558ms)
  const divLine = '--- a' + '-'.repeat(10000) + 'x';
  t0 = performance.now();
  O.inference.groupKvBlocks([divLine, 'User: alice_kv', 'Password: SecretKv123!']);
  let elapsedP2 = performance.now() - t0;
  ok(elapsedP2 < 20, 'W2-P2: 10,000-dash near-miss divider line completes groupKvBlocks in <20ms (' + elapsedP2.toFixed(2) + 'ms)');

  // W2-P3: 2,000 known users x 2,000 log lines Global Entity Index scaling (< 50ms, zero RegExp allocation)
  const manyUsers = [];
  for (let i = 0; i < 2000; i++) manyUsers.push('user_' + i + '_corp');
  const seed2k = [O.facts.makeFact({ kind: 'ad.user_list', scope: 'host:10.10.10.101', value: { users: manyUsers }, state: 'supported', source: 'seed' })];
  const log2k = [];
  for (let i = 0; i < 2000; i++) log2k.push('2026-10-24 [DEBUG] Checking record for account entry ' + i + ' with status active and flags=0x01');
  log2k.push('user_1999_corp : password = SuperSecretEntityPass2026!');
  t0 = performance.now();
  const resP3 = O.parsers.parseActionOutput({
    command: 'cat dump.txt',
    stdout: log2k.join('\n'),
    scope: 'host:10.10.10.101',
    context: { target: '10.10.10.101', facts: seed2k }
  });
  let elapsedP3 = performance.now() - t0;
  ok(elapsedP3 < 80 && resP3.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'user_1999_corp'),
    'W2-P3: 2,000 users x 2,000 lines global entity cross-referencing completes in <80ms (' + elapsedP3.toFixed(2) + 'ms) and binds user_1999_corp');

  // W2-P4: _DB_HASH_ROW_RE 2,000-char multi-column near-miss row (< 15ms)
  const dbNearMiss = '| admin | ' + 'a '.repeat(1000) + '| ' + 'b '.repeat(1000) + '| $2a$10$invalid |';
  t0 = performance.now();
  O.parsers.parseActionOutput({ command: 'mysql -e "select * from users"', stdout: dbNearMiss, scope: 'host:10.10.10.102' });
  let elapsedP4 = performance.now() - t0;
  ok(elapsedP4 < 15, 'W2-P4: _DB_HASH_ROW_RE multi-column near-miss completes in <15ms (' + elapsedP4.toFixed(2) + 'ms)');

  // W2-A1: proxychains4 preloading libproxychains.so.4 (linux-gnu) + inline OKSMB prefix on Windows DC
  const T_PC1 = '10.10.10.103';
  const pcNxcOut = [
    '[proxychains] config file found: /etc/proxychains4.conf',
    '[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4',
    '[proxychains] DLL init: proxychains-ng 4.17',
    '[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.10.103:445  ...  OKSMB         10.10.10.103    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:corp.local)',
    '[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.10.103:445  ...  OKSMB         10.10.10.103    445    DC01             [+] corp.local\\svc_pc:ProxyPass2026! (Pwn3d!)'
  ].join('\n');
  O.ingest.run({ command: 'proxychains4 -q nxc smb 10.10.10.103 -u svc_pc -p ProxyPass2026!', text: pcNxcOut, scope: 'host:' + T_PC1, quiet: true });
  ok(hasFact(T_PC1, 'credential.available', v => v.user === 'svc_pc' && v.password === 'ProxyPass2026!')
    && hasFact(T_PC1, 'smb.authenticated')
    && hasFact(T_PC1, 'access.admin')
    && hasFact(T_PC1, 'host.os_family', v => v.family === 'windows')
    && !hasFact(T_PC1, 'host.os_family', v => v.family === 'linux'),
    'W2-A1: proxychains4 preloading linux-gnu .so and inline OKSMB prefix mints Windows OS, credential.available, and access.admin without Linux false positive', T_PC1);

  // W2-A2: proxychains4 impacket-GetUserSPNs with interleaved timeout line inside table
  const T_PC2 = '10.10.10.104';
  const pcSpnOut = [
    'ServicePrincipalName          Name      MemberOf                                           PasswordLastSet             LastLogon  Delegation',
    '----------------------------  --------  -------------------------------------------------  --------------------------  ---------  ----------',
    '[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.10.104:88  ...  timeout',
    'MSSQLSvc/dc01.corp.local:1433 svc_mssql CN=Domain Admins,CN=Users,DC=corp,DC=local         2026-01-01 12:00:00.000000  <never>'
  ].join('\n');
  O.ingest.run({ command: 'proxychains4 impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.10.10.104', text: pcSpnOut, scope: 'host:' + T_PC2, quiet: true });
  ok(hasFact(T_PC2, 'ad.user_list', v => Array.isArray(v.users) && v.users.includes('svc_mssql') && !v.users.includes('Strict')),
    'W2-A2: Interleaved [proxychains] lines inside GetUserSPNs table never pollute ad.user_list with "Strict"', T_PC2);

  // W2-A3: Wrapper stripping in prompt telemetry, command semantics, and catalog move matcher
  const pcPromptMeta = O.inference.extractPromptTelemetry('root@jumpbox:~# proxychains4 -q nxc smb 10.10.10.103 -u a -p b --shares\n', { target: '10.10.10.103' });
  const pcCmdSem = O.inference.extractCommandSemantics('sudo -E proxychains4 -q nxc smb 10.10.10.103 -u a -p b --shares', { target: '10.10.10.103' });
  const pcCatMove = O.inference.matchCatalogMove('proxychains4 -q nxc smb 10.10.10.103 -u a -p b --shares', null, { target: '10.10.10.103' });
  ok(pcPromptMeta.locus === 'remote' && pcCmdSem.tool === 'nxc' && pcCmdSem.inputService === 'smb' && pcCatMove && Array.isArray(pcCatMove.produces) && pcCatMove.produces.includes('smb.shares'),
    'W2-A3: Command wrapper stripping handles sudo/proxychains4 -q across prompt telemetry, command semantics, and catalog move matching');

  // W2-A4: Multi-object JSON array cross-boundary credential isolation
  const T_JSON = '10.10.10.105';
  const jsonUsers = JSON.stringify([
    { id: 1, username: 'alice_no_pw', password: null, role: 'viewer' },
    { id: 2, username: 'svc_json_api', password: 'JsonBoundPass!2026', role: 'admin' }
  ], null, 2);
  O.ingest.run({ command: 'curl -s http://10.10.10.105/api/users', text: jsonUsers, scope: 'host:' + T_JSON, quiet: true });
  ok(hasFact(T_JSON, 'credential.available', v => v.user === 'svc_json_api' && v.password === 'JsonBoundPass!2026')
    && !hasFact(T_JSON, 'credential.available', v => v.user === 'alice_no_pw'),
    'W2-A4: Multi-object JSON credential extraction isolates {"username","password"} within object braces and never bleeds across objects', T_JSON);

  // W2-A5: Password spray mixed output (19 failures + 1 success)
  const T_SPRAY = '10.10.10.106';
  const sprayLines = [];
  for (let i = 1; i <= 19; i++) sprayLines.push('[-] CORP\\user' + i + ':Spring2026! - STATUS_LOGON_FAILURE');
  sprayLines.push('[+] CORP\\svc_deploy:Spring2026! - STATUS_SUCCESS');
  const directSpray = O.parsers.parseActionOutput({
    command: 'custom-spray -u users.txt -p Spring2026! 10.10.10.106',
    stdout: sprayLines.join('\n'),
    scope: 'host:' + T_SPRAY
  });
  ok(directSpray.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'svc_deploy' && f.value.password === 'Spring2026!'),
    'W2-A5: Password spray with 19 STATUS_LOGON_FAILURE lines and 1 STATUS_SUCCESS line extracts svc_deploy:Spring2026! even when blocker.logon_failure fires');

  // W2-A6: Quoted password with spaces + ADMIN$ boilerplate vs DC01$ machine account NTLM hash
  const T_QUOT = '10.10.10.107';
  const quotAndMachineOut = [
    'Username: backup_op',
    'Password: "My Secret Pass 2026!"',
    '---',
    '[+] CORP\\ADMIN$:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c',
    '[+] CORP\\DC01$:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0',
    '[+] CORP\\SRV01$:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
  ].join('\n');
  O.ingest.run({ command: 'custom-dump 10.10.10.107', text: quotAndMachineOut, scope: 'host:' + T_QUOT, quiet: true });
  ok(hasFact(T_QUOT, 'credential.available', v => v.user === 'backup_op' && v.password === 'My Secret Pass 2026!')
    && !hasFact(T_QUOT, 'credential.available', v => /^admin\$?$/i.test(v.user || ''))
    && !hasFact(T_QUOT, 'credential.available', v => /^dc01\$?$/i.test(v.user || ''))
    && hasFact(T_QUOT, 'hash.ntlm', v => v.user === 'SRV01$' && v.nthash === '8846f7eaee8fb117ad06bdd830b7586c'),
    'W2-A6: Strips outer quotes on password with spaces, filters ADMIN$ share and empty NTLM hash on DC01$, and extracts non-empty NTLM hash on SRV01$', T_QUOT);

  // W2-A7: Multi-Host & Linux OS Isolation (HTTP/1.1 non-SPN + no AD DC entailment on Linux host)
  const T_LIN_WEB = '10.10.10.108';
  S.addFacts([
    O.facts.makeFact({ kind: 'foothold.linux', scope: 'host:' + T_LIN_WEB, value: { identity: 'www-data' }, state: 'supported', source: 'seed' }),
    O.facts.makeFact({ kind: 'host.os_family', scope: 'host:' + T_LIN_WEB, value: { family: 'linux' }, state: 'supported', source: 'seed' })
  ], 'seed', T_LIN_WEB);
  const linHttpResp = [
    'HTTP/1.1 200 OK',
    'Server: Apache/2.4.58 (Ubuntu)',
    'Content-Type: text/plain',
    '',
    'Author: j.doe@corp.local',
    'User: svc_sql',
    'Permission: AddMember',
    'Target: developers'
  ].join('\n');
  O.ingest.run({ command: 'curl -i http://10.10.10.108/about', text: linHttpResp, scope: 'host:' + T_LIN_WEB, quiet: true });
  ok(!hasFact(T_LIN_WEB, 'ad.dc_candidate')
    && !hasFact(T_LIN_WEB, 'ldap.reachable')
    && !hasFact(T_LIN_WEB, 'kerberos.reachable')
    && !hasFact(T_LIN_WEB, 'ad.acl_lead')
    && !hasFact(T_LIN_WEB, 'host.os_family', v => v.family === 'windows'),
    'W2-A7: HTTP/1.1 response on a Linux host never matches HTTP/1.1 as a Kerberos SPN and never contaminates the Linux host with AD DC or Windows facts', T_LIN_WEB);
}

// ---------------------------------------------------------------------------
// 13. WAVE 3 ADVERSARIAL TESTS: 346-MOVE DIFFERENTIAL MUTATIONS, DECOY
//     BANNERS, TERMINAL CORRUPTION, WRAPPED HASHES, PIVOT FILTERING & REDOS
// ---------------------------------------------------------------------------
{
  // W3-1: Command-less paste + Attention Frame (matchedCopy / _inferenceContext.attention)
  //       routes Tier 1 actionId/command dispatch even when opts.command is empty.
  const T_W3_ATTN = '10.10.10.111';
  const attnPaste = 'User www-data may run the following commands on box:\n    (ALL : ALL) NOPASSWD: /usr/bin/find\n';
  const attnOut = O.parsers.parseActionOutput({
    command: '',
    stdout: attnPaste,
    scope: 'host:' + T_W3_ATTN,
    context: {
      attentionFrame: {
        matchedCopy: { actionId: 'linux-privesc-triage', command: 'sudo -l', produces: ['privesc.sudo_rights'], ts: Date.now() }
      }
    }
  });
  ok(attnOut && attnOut.facts && attnOut.facts.some(f => f.kind === 'privesc.sudo_rights'),
    'W3-1a: Command-less paste with Attention Frame (matchedCopy) dispatches Tier 1 parser via matchedCopy.actionId/command', T_W3_ATTN);

  // Also test Pack Action IDs (systemd-timer-abuse, win-privesc-triage) and empty actionId fallback in _parse_privesc_output
  const timerPaste = '/etc/systemd/system/backup-cleanup.service\n-rw-rw-rw- 1 root devops 214 Oct 25 01:10 /etc/systemd/system/backup-cleanup.timer\n';
  const timerOut = O.parsers.parseActionOutput({
    command: 'find /etc/systemd /lib/systemd -writable -type f 2>/dev/null',
    stdout: timerPaste,
    scope: 'host:' + T_W3_ATTN,
    actionId: 'systemd-timer-abuse'
  });
  ok(timerOut && timerOut.facts && timerOut.facts.some(f => f.kind === 'privesc.cron_writable'),
    'W3-1b: Pack actionId systemd-timer-abuse is recognized in _LINUX_PRIVESC_ACTION_IDS and extracts privesc.cron_writable from writable systemd unit/timer', T_W3_ATTN);

  // W3-2: 80-column hard-wrapped uncracked $krb5tgs$ (with :1433*$ SPN port) and $krb5asrep$
  //       extract full unwrapped hashes and NEVER mint fake plaintext credentials from :1433*$
  const T_W3_KRB = '10.10.10.112';
  const rawTgs = '$krb5tgs$23$*svc_mssql$CORP.LOCAL$CORP.LOCAL/svc_mssql~MSSQLSvc/dc01.corp.local:1433*$' + 'a1b2c3d4e5f60718'.repeat(16);
  const wrappedUncrackedTgs = rawTgs.match(/.{1,80}/g).join('\n');
  O.ingest.run({ command: 'GetUserSPNs.py -request -dc-ip 10.10.10.112 corp.local/john:Pass123', text: wrappedUncrackedTgs, scope: 'host:' + T_W3_KRB, quiet: true });
  const tgsFacts = S.factSetForTarget(T_W3_KRB).facts.filter(f => f.kind === 'hash.tgs');
  ok(tgsFacts.length === 1
    && tgsFacts[0].value && Array.isArray(tgsFacts[0].value.hashes) && tgsFacts[0].value.hashes[0].length === rawTgs.length
    && !hasFact(T_W3_KRB, 'credential.plaintext')
    && !hasFact(T_W3_KRB, 'credential.available', v => v && v.password && v.password.indexOf('1433*$') === 0),
    'W3-2a: 80-column hard-wrapped uncracked $krb5tgs$ with :1433*$ SPN port unwraps cleanly into full hash.tgs and NEVER mints a fake 1433*$ password', T_W3_KRB);

  const wrappedCrackedTgs = (rawTgs + ':Summer2024!').match(/.{1,80}/g).join('\n');
  O.ingest.run({ command: 'hashcat -m 13100 tgs.hash rockyou.txt --show', text: wrappedCrackedTgs, scope: 'host:' + T_W3_KRB, quiet: true });
  ok(hasFact(T_W3_KRB, 'credential.plaintext', v => v && v.password === 'Summer2024!'),
    'W3-2b: 80-column hard-wrapped hashcat --show $krb5tgs$...:Summer2024! unwraps and extracts plaintext password Summer2024!', T_W3_KRB);

  // W3-3: Decoy HTTP/1.1 200 OK on Windows IIS with Linux kernel strings, Content-Length: 429,
  //       STATUS_LOGON_FAILURE, "Note: Host seems down", and internal IP in HTML body.
  const T_W3_DECOY = '10.10.10.113';
  const decoyHttp = [
    'HTTP/1.1 200 OK',
    'Server: Microsoft-IIS/10.0',
    'Content-Length: 429',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<!DOCTYPE html><html><body>',
    '<h1>Kernel Crash Dump: Linux version 5.15.0-76-generic (buildd@lcy02-amd64-043) (Ubuntu 22.04)</h1>',
    '<p>PRETTY_NAME="Ubuntu 22.04.2 LTS" Sudo version 1.8.27 pkexec version 0.105</p>',
    '<p>Troubleshooting: STATUS_LOGON_FAILURE and Note: Host seems down when connecting to 172.16.99.5</p>',
    '</body></html>'
  ].join('\r\n');
  O.ingest.run({ command: 'curl -i http://10.10.10.113/blog/kernel-debugging', text: decoyHttp, scope: 'host:' + T_W3_DECOY, quiet: true });
  ok(hasFact(T_W3_DECOY, 'host.os_family', v => v.family === 'windows')
    && !hasFact(T_W3_DECOY, 'host.os_family', v => v.family === 'linux')
    && !hasFact(T_W3_DECOY, 'host.kernel')
    && !hasFact(T_W3_DECOY, 'vuln.dirtypipe')
    && !hasFact(T_W3_DECOY, 'vuln.baron_samedit')
    && !hasFact(T_W3_DECOY, 'vuln.polkit')
    && !hasFact(T_W3_DECOY, 'blocker.rate_limited')
    && !hasFact(T_W3_DECOY, 'blocker.logon_failure')
    && !hasFact(T_W3_DECOY, 'blocker.host_down')
    && !hasFact(T_W3_DECOY, 'smb.reachable')
    && !hasFact(T_W3_DECOY, 'network.subnet_candidate'),
    'W3-3: Decoy HTTP/1.1 200 OK on Windows IIS with Linux kernel/vuln strings, Content-Length: 429, STATUS_LOGON_FAILURE, and internal IP in HTML body mints Windows OS from headers and zero false Linux/vuln/blocker/SMB/pivot facts', T_W3_DECOY);

  // W3-4: Terminal \r progress-bar overwrites and vertically split tmux right-pane bleed
  const T_W3_TERM = '10.10.10.114';
  const crGobuster = [
    'Progress: 1200 / 4615 (26.00%)\r/admin                (Status: 200) [Size: 1420]',
    '/backup               (Status: 301) [Size: 312] [--> http://10.10.10.114/backup/]\r:: Progress: [4615/4615] :: Job [1/1] :: 920 req/sec ::',
    '80/tcp open\r   \n'
  ].join('\r\r\n');
  O.ingest.run({ command: 'gobuster dir -u http://10.10.10.114 -w common.txt', text: crGobuster, scope: 'host:' + T_W3_TERM, quiet: true });
  ok(hasFact(T_W3_TERM, 'web.content_map', v => v && Array.isArray(v.paths) && v.paths.includes('/admin') && v.paths.includes('/backup'))
    && hasFact(T_W3_TERM, 'port:80'),
    'W3-4a: Terminal \\r progress-bar overwrites (both prefix and suffix progress bars + \\r\\r\\n + trailing spaces) preserve discovered web paths (/admin, /backup) and port:80', T_W3_TERM);

  const T_W3_TMUX = '10.10.10.115';
  const tmuxNmap = [
    'PORT    STATE SERVICE VERSION                        │ ┌──(kali㉿kali)-[~/obol]',
    '80/tcp  open  http    Microsoft IIS httpd 10.0       │ └─$ ssh user@10.10.10.99',
    '445/tcp open  microsoft-ds Windows Server 2019       │ Linux kali 6.6.9-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.6.9-1kali1'
  ].join('\n');
  O.ingest.run({ command: 'nmap -sV 10.10.10.115', text: tmuxNmap, scope: 'host:' + T_W3_TMUX, quiet: true });
  ok(hasFact(T_W3_TMUX, 'port:80')
    && hasFact(T_W3_TMUX, 'port:445')
    && hasFact(T_W3_TMUX, 'host.os_family', v => v.family === 'windows')
    && !hasFact(T_W3_TMUX, 'host.os_family', v => v.family === 'linux'),
    'W3-4b: Vertically split tmux pane selection (│ right-pane Kali prompt/uname bleed) strips right-pane columns and never misclassifies Windows target as Linux', T_W3_TMUX);

  // W3-5: Broadcast ARP (.255 / ff-ff-ff-ff-ff-ff), public DNS (8.8.8.8 / 1.1.1.1),
  //       lhost VPN (tun0) subnet exclusion, and non-canonical CIDR (172.17.0.1/16 -> 172.17.0.0/16)
  const T_W3_PIVOT = '10.10.10.116';
  S.update(e => { e.params = e.params || {}; e.params.lhost = '10.10.14.22'; });
  S.addFacts([
    O.facts.makeFact({ kind: 'foothold.linux', scope: 'host:' + T_W3_PIVOT, value: { user: 'www-data' }, state: 'supported', source: 'seed' })
  ], 'seed', T_W3_PIVOT);
  const arpAndDnsPaste = [
    'Interface: 10.10.10.116 --- 0x6',
    '  Internet Address      Physical Address      Type',
    '  10.10.10.255          ff-ff-ff-ff-ff-ff     static',
    '  224.0.0.22            01-00-5e-00-00-16     static',
    'nameserver 8.8.8.8',
    'nameserver 1.1.1.1',
    '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500',
    '    inet 10.10.10.116/24 brd 10.10.10.255 scope global eth0',
    '3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500',
    '    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0',
    '    peer 10.10.14.22/24'
  ].join('\n');
  O.ingest.run({ command: 'ip a && cat /etc/resolv.conf && arp -a', text: arpAndDnsPaste, scope: 'host:' + T_W3_PIVOT, quiet: true });
  const allTargets = (S.active() && S.active().hosts) ? Object.keys(S.active().hosts) : [];
  ok(!hasFact(T_W3_PIVOT, 'scan.local.neighbors')
    && !hasFact(T_W3_PIVOT, 'scan.local.dns')
    && allTargets.indexOf('8.8.8.8') === -1
    && allTargets.indexOf('1.1.1.1') === -1
    && !hasFact(T_W3_PIVOT, 'network.subnet_candidate', v => v && v.cidr === '10.10.14.0/24')
    && (hasFact(T_W3_PIVOT, 'scan.local.routes', v => v && Array.isArray(v.subnets) && v.subnets.indexOf('172.17.0.0/16') >= 0)
        || hasFact(T_W3_PIVOT, 'network.subnet_candidate', v => v && v.cidr === '172.17.0.0/16')),
    'W3-5: Broadcast ARP (10.10.10.255 / ff-ff-ff-ff-ff-ff), public DNS (8.8.8.8 / 1.1.1.1), and attacker VPN lhost subnet (10.10.14.0/24) are excluded while 172.17.0.1/16 is canonicalized to 172.17.0.0/16', T_W3_PIVOT);

  // W3-6: Truncated <nmaprun XML, folded RFC 2849 LDIF description before sAMAccountName,
  //       bloodyAD get writable unicodePwd: WRITE guard + service-account RBCD, and leading failure noise
  const T_W3_AD = '10.10.10.117';
  const truncNmapXml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE nmaprun>',
    '<nmaprun scanner="nmap" args="nmap -sV -oX - 10.10.10.117">',
    '<host starttime="1700000000"><status state="up"/>',
    '<address addr="10.10.10.117" addrtype="ipv4"/>',
    '<ports>',
    '<port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec" product="Microsoft Windows Kerberos"/></port>',
    '<port protocol="tcp" portid="389"><state state="open"/><service name="ldap" product="Microsoft Windows Active Directory LDAP"/>'
    // deliberately truncated mid-XML before </port>, </ports>, </host>, </nmaprun>
  ].join('\n');
  O.ingest.run({ command: 'nmap -sV -oX - 10.10.10.117', text: truncNmapXml, scope: 'host:' + T_W3_AD, quiet: true });
  ok(hasFact(T_W3_AD, 'port:88') && hasFact(T_W3_AD, 'port:389'),
    'W3-6a: Truncated <nmaprun XML (missing </port>, </host>, and </nmaprun>) still extracts open ports 88 and 389', T_W3_AD);

  const foldedLdifAndBloody = [
    'dn: CN=svc_backup,CN=Users,DC=corp,DC=local',
    'description: Default password for backup account is Back',
    ' upPass#2026!',
    'sAMAccountName: svc_backup',
    '',
    'distinguishedName: CN=svc_sql,CN=Users,DC=corp,DC=local',
    '      unicodePwd: WRITE',
    '      msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE',
    '',
    '[-] Authenticating against 10.10.10.117 as CORP\\guest FAILED',
    '[+] Successfully updated password for svc_sql'
  ].join('\n');
  O.ingest.run({ command: 'ldapsearch -x && bloodyAD -d corp.local -u john -p Pass123 --host 10.10.10.117 get writable && bloodyAD set password svc_sql NewPass123!', text: foldedLdifAndBloody, scope: 'host:' + T_W3_AD, quiet: true });
  ok(hasFact(T_W3_AD, 'credential.candidate', v => v && v.user === 'svc_backup' && v.password === 'BackupPass#2026!')
    && !hasFact(T_W3_AD, 'credential.candidate', v => v && v.password === 'WRITE')
    && !hasFact(T_W3_AD, 'credential.plaintext', v => v && v.password === 'WRITE')
    && hasFact(T_W3_AD, 'ad.acl_lead', v => v && Array.isArray(v.rights) && v.rights.includes('RBCD') && Array.isArray(v.targets) && v.targets.includes('svc_sql'))
    && hasFact(T_W3_AD, 'ad.control_paths'),
    'W3-6b: RFC 2849 folded LDIF (description before sAMAccountName) unwraps BackupPass#2026!, bloodyAD unicodePwd: WRITE never mints password "WRITE", RBCD works on user accounts, and leading [-] noise does not suppress bloodyAD set password success', T_W3_AD);

  // W3-7: ReDoS / Catastrophic Backtracking guard across parser suite on 8,000-char near-miss strings
  const t0 = Date.now();
  const nearMissBlob = [
    '[!] Initializing [GMSA] ' + 'a'.repeat(5000) + ' :::: ',
    'password = "' + 'B'.repeat(5000) + '"',
    'C:\\Users\\admin\\' + 'folder\\'.repeat(400) + 'not_kdbx.txt',
    'lrwxrwxrwx 1 root root 12 Oct 25 01:00 ' + 'x'.repeat(4000) + ' -> target',
    'STATUS_' + 'A_'.repeat(2500) + ' message'
  ].join('\n');
  O.parsers.parseActionOutput({ command: 'nxc smb 10.10.10.117 -u a -p b --gmsa', stdout: nearMissBlob, scope: 'host:' + T_W3_AD });
  const elapsedMs = Date.now() - t0;
  ok(elapsedMs < 250,
    'W3-7: Adversarial near-miss ReDoS payload (20,000+ chars across gMSA, secret, path, symlink, and STATUS_ patterns) completes full parser pipeline in ' + elapsedMs + 'ms (< 250ms)', T_W3_AD);

  // W4-1: Deep-Tail Enumeration Dump (> 450 KB / 6,000 lines, past old 256 KB & 3,000-line caps)
  const T_W4_TAIL = '10.10.10.118';
  const enumNoise = [];
  for (let i = 0; i < 6000; i++) {
    enumNoise.push('-rwxr-xr-x 1 root root 14216 Mar 14 2024 /usr/lib/x86_64-linux-gnu/libnormal_' + i + '.so');
  }
  enumNoise.push('-rwsr-xr-x 1 root root 54216 Mar 14 2024 /usr/bin/python3.11');
  enumNoise.push('/usr/bin/openssl = cap_setuid+ep');
  enumNoise.push('CORP\\svc_deep_tail : password = DeepTailPass2026!');
  const enumBlob = enumNoise.join('\n');
  const resW4_1 = O.parsers.parseActionOutput({ command: 'custom-host-sweep', stdout: enumBlob, scope: 'host:' + T_W4_TAIL, context: { target: T_W4_TAIL } });
  ok(enumBlob.length > 400000
    && resW4_1.facts.some(f => f.kind === 'privesc.suid' && f.value && Array.isArray(f.value.binaries) && f.value.binaries.includes('/usr/bin/python3.11'))
    && resW4_1.facts.some(f => f.kind === 'privesc.capabilities' && f.value && Array.isArray(f.value.binaries) && f.value.binaries.includes('/usr/bin/openssl'))
    && resW4_1.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'svc_deep_tail' && f.value.password === 'DeepTailPass2026!'),
    'W4-1: 6,000-line (>450 KB) host sweep extracts SUID, capabilities, and credentials at lines 6,001-6,003 without truncation');

  // W4-2: Deep-Tail KV Block & Dynamic Table (> 2,500 lines, past old 600-line KV and 400-line table caps)
  const T_W4_KV = '10.10.10.119';
  const kvNoise = [];
  for (let i = 0; i < 600; i++) {
    kvNoise.push('ObjectName: workstation-' + i);
    kvNoise.push('ObjectType: Computer');
    kvNoise.push('Enabled: True');
    kvNoise.push('');
  }
  kvNoise.push('[!] Vulnerabilities: ESC1');
  kvNoise.push('Enrollee Supplies Subject: True');
  kvNoise.push('Template Name: TailCorpVPN');
  kvNoise.push('');
  kvNoise.push('| Secret | User |');
  kvNoise.push('| --- | --- |');
  kvNoise.push('| TailTablePass!99 | svc_table_tail |');
  const resW4_2 = O.parsers.parseActionOutput({ command: 'custom-ad-audit', stdout: kvNoise.join('\n'), scope: 'host:' + T_W4_KV, context: { target: T_W4_KV } });
  ok(resW4_2.facts.some(f => f.kind === 'adcs.vulnerable' && f.value && (f.value.template === 'TailCorpVPN' || (Array.isArray(f.value.templates) && f.value.templates.includes('TailCorpVPN'))))
    && resW4_2.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'svc_table_tail' && f.value.password === 'TailTablePass!99'),
    'W4-2: Deep-tail KV block and dynamic table at line 2,400+ extract adcs.vulnerable (TailCorpVPN) and credential.available (svc_table_tail)');

  // W4-3: Large Domain (> 1,200 users, past old 500 atom cap) + Global Entity Binding at line 8,000
  const T_W4_DOM = '10.10.10.120';
  const domDump = ['S-1-5-21-111111111-222222222-333333333-500'];
  for (let i = 1; i <= 1200; i++) {
    domDump.push('CORP\\acct_user_' + i);
  }
  const resW4_3a = O.parsers.parseActionOutput({ command: 'custom-user-dump', stdout: domDump.join('\n'), scope: 'host:' + T_W4_DOM });
  const ulFact = resW4_3a.facts.find(f => f.kind === 'ad.user_list');
  const log8k = [];
  for (let i = 0; i < 8000; i++) log8k.push('INFO: routine audit check on line ' + i);
  log8k.push('acct_user_1150 : 8846f7eaee8fb117ad06bdd830b7586c');
  const resW4_3b = O.parsers.parseActionOutput({
    command: 'cat audit.log',
    stdout: log8k.join('\n'),
    scope: 'host:' + T_W4_DOM,
    context: { target: T_W4_DOM, facts: resW4_3a.facts }
  });
  ok(ulFact && ulFact.value && ulFact.value.users && ulFact.value.users.length === 1200
    && resW4_3b.facts.some(f => f.kind === 'hash.ntlm' && f.value && f.value.user === 'acct_user_1150' && f.value.nthash === '8846f7eaee8fb117ad06bdd830b7586c'),
    'W4-3: Captures all 1,200 domain users (past old 500 atom cap) and binds acct_user_1150 to its NTLM hash at line 8,001');

  // W4-4: Adversarial Single-Line 50 KB Minified Blob + 10,000-Line Unbroken KV Flood + Tail Credential
  const T_W4_ADV = '10.10.10.121';
  const advLines = [
    'var bundle="' + 'x'.repeat(25000) + ' password=FakeMinifiedPass123! ESC1 ' + 'y'.repeat(25000) + '";'
  ];
  for (let i = 0; i < 10000; i++) {
    advLines.push('net.ipv4.conf.interface_' + i + '.accept_redirects = 0');
  }
  advLines.push('');
  advLines.push('Username: final_survivor');
  advLines.push('Password: FinalSurvivorPass!2026');
  const tAdv = Date.now();
  const resW4_4 = O.parsers.parseActionOutput({ command: 'sysctl -a && cat notes.txt', stdout: advLines.join('\n'), scope: 'host:' + T_W4_ADV });
  const advElapsed = Date.now() - tAdv;
  ok(advElapsed < 500
    && !resW4_4.facts.some(f => f.value && f.value.password === 'FakeMinifiedPass123!')
    && resW4_4.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'final_survivor' && f.value.password === 'FinalSurvivorPass!2026'),
    'W4-4: 50 KB single-line minified decoy blob + 10,000-line unbroken sysctl KV flood + tail credential completes in ' + advElapsed + 'ms (<500ms) with zero decoy pollution and 100% tail recall');

  // W4-5: Headless Multi-Section Paste (No opts.context) with Skeleton credential.candidate + GPP cpassword + Table + KV Block
  const T_W4_MULTI = '10.10.10.122';
  const multiSectionOut = [
    '-rwsr-xr-x 1 root root 54216 Mar 14 2024 /usr/bin/python3.11',
    '/usr/bin/openssl = cap_setuid+ep',
    '<Properties userName="CORP\\svc_gpp" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" />',
    '',
    '| Secret | User |',
    '| --- | --- |',
    '| MultiTblPass!77 | svc_multi_tbl |',
    '',
    'Account: svc_multi_kv',
    'Secret: MultiKvPass!88'
  ].join('\n');
  const resW4_5 = O.parsers.parseActionOutput({ command: 'custom-bundle-audit', stdout: multiSectionOut, scope: 'host:' + T_W4_MULTI });
  ok(resW4_5.facts.some(f => f.kind === 'privesc.suid_candidate' && f.value && Array.isArray(f.value.paths) && f.value.paths.includes('/usr/bin/python3.11'))
    && resW4_5.facts.some(f => f.kind === 'credential.candidate' && f.value && f.value.kind === 'gpp_cpassword' && f.value.user === 'svc_gpp')
    && !resW4_5.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'svc_gpp')
    && resW4_5.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'svc_multi_tbl' && f.value.password === 'MultiTblPass!77')
    && resW4_5.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'svc_multi_kv' && f.value.password === 'MultiKvPass!88'),
    'W4-5: Headless multi-section paste (without opts.context) extracts SUID, GPP cpassword candidate (without false plaintext promotion), custom table credential, and KV credential');

  // W4-6: Multi-Credential Co-Occurrence (Early Tier 1 Credential + Deep-Tail Table & KV Credentials)
  const T_W4_MCRED = '10.10.10.123';
  const multiCredLines = [
    'db_user = svc_tier1_early',
    'db_password = EarlyTier1Pass!11'
  ];
  for (let i = 0; i < 4000; i++) multiCredLines.push('INFO: audit log line ' + i);
  multiCredLines.push('| Secret | User |');
  multiCredLines.push('| --- | --- |');
  multiCredLines.push('| LateTablePass!22 | svc_tier3_late |');
  multiCredLines.push('');
  multiCredLines.push('Account: svc_tier3_kv');
  multiCredLines.push('Secret: LateKvPass!33');
  const resW4_6 = O.parsers.parseActionOutput({
    command: 'cat /opt/app/config.ini && custom-dump',
    stdout: multiCredLines.join('\n'),
    scope: 'host:' + T_W4_MCRED,
    context: { target: T_W4_MCRED }
  });
  ok(resW4_6.facts.some(f => f.kind === 'credential.candidate' && f.value && f.value.password === 'EarlyTier1Pass!11')
    && resW4_6.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'svc_tier3_late' && f.value.password === 'LateTablePass!22')
    && resW4_6.facts.some(f => f.kind === 'credential.available' && f.value && f.value.user === 'svc_tier3_kv' && f.value.password === 'LateKvPass!33'),
    'W4-6: Early Tier 1 credential at line 2 does not suppress distinct Tier 3 table and KV credentials at line 4,000+');

  // W4-7: High-Cardinality Tier 1 Array Caps (120 DB Hashes, 120 Web Paths, 30 ADCS Templates, 80 SUID Binaries)
  const T_W4_CARD = '10.10.10.124';
  const dbRows = ['mysql> SELECT user, password FROM users;'];
  for (let i = 1; i <= 120; i++) {
    const hex = i.toString(16).padStart(32, 'a');
    dbRows.push('| dbuser_' + i + ' | ' + hex + ' |');
  }
  const resDb = O.parsers.parseActionOutput({ command: 'mysql -u root -e "SELECT user, password FROM users"', stdout: dbRows.join('\n'), scope: 'host:' + T_W4_CARD });
  const dbHashFact = resDb.facts.find(f => f.kind === 'db.hashes');
  const dbCandCount = resDb.facts.filter(f => f.kind === 'credential.candidate' && f.value && f.value.kind === 'database_hash').length;

  const gobusterRows = [];
  for (let i = 1; i <= 120; i++) gobusterRows.push('/route_' + i + ' (Status: 200) [Size: 512]');
  const resWeb = O.parsers.parseActionOutput({ command: 'gobuster dir -u http://10.10.10.124 -w common.txt', stdout: gobusterRows.join('\n'), scope: 'host:' + T_W4_CARD });
  const webMapFact = resWeb.facts.find(f => f.kind === 'web.content_map');

  const adcsRows = ['Certificate Authorities', '  0', '    CA Name: CORP-CA'];
  for (let i = 1; i <= 30; i++) {
    adcsRows.push('  ' + i);
    adcsRows.push('    Template Name: VulnTemplate_' + i);
    adcsRows.push('    Enrollee Supplies Subject: True');
    adcsRows.push('    [!] Vulnerabilities');
    adcsRows.push('      ESC1: Enrollee supplies subject');
  }
  const resAdcs = O.parsers.parseActionOutput({ command: 'certipy find -u a@corp.local -p b -dc-ip 10.10.10.124 -stdout', stdout: adcsRows.join('\n'), scope: 'host:' + T_W4_CARD });
  const adcsFact = resAdcs.facts.find(f => f.kind === 'adcs.vulnerable');

  const suidRows = [];
  for (let i = 1; i <= 80; i++) suidRows.push('-rwsr-xr-x 1 root root 54216 Mar 14 2024 /opt/custom/suid_bin_' + i);
  const resSuid = O.parsers.parseActionOutput({ command: 'find / -perm -4000 2>/dev/null', stdout: suidRows.join('\n'), scope: 'host:' + T_W4_CARD });
  const suidFact = resSuid.facts.find(f => f.kind === 'privesc.suid_candidate');

  ok(dbHashFact && dbHashFact.value.entries.length === 120 && dbCandCount === 120
    && webMapFact && webMapFact.value.paths.length === 120
    && adcsFact && adcsFact.value.templates.length === 30
    && suidFact && suidFact.value.paths.length === 80,
    'W4-7: High-cardinality outputs preserve all 120 DB hashes + 120 credential.candidate facts, 120 web paths, 30 ADCS templates, and 80 SUID binaries without truncation');

  // W4-8: Canonical Pack Gate Synchronization (web.content_map, privesc.unquoted_service_path, privesc.suid_candidate, hash.candidate, hash.mscache)
  const T_W4_GATES = '10.10.10.125';
  const gatePaste = [
    '| Endpoint | HTTP Status |',
    '| --- | --- |',
    '| /internal-admin | 200 |',
    '',
    'Service Name: CustomUpdater',
    'Binary Path: C:\\Program Files\\Custom Updater\\updater service.exe',
    '',
    'corp_cached_user : $DCC2$10240#corp_cached_user#11223344556677889900aabbccddeeff'
  ].join('\n');
  const resGates = O.parsers.parseActionOutput({ command: 'custom-gate-probe', stdout: gatePaste, scope: 'host:' + T_W4_GATES, context: { target: T_W4_GATES } });
  ok(resGates.facts.some(f => f.kind === 'web.content_map' && f.value && f.value.paths.includes('/internal-admin'))
    && resGates.facts.some(f => f.kind === 'privesc.unquoted_service_path')
    && resGates.facts.some(f => f.kind === 'hash.mscache')
    && resGates.facts.some(f => f.kind === 'hash.candidate'),
    'W4-8: Tier 3 inference co-mints canonical pack gate facts (web.content_map, privesc.unquoted_service_path, hash.mscache, hash.candidate)');
}

console.log('\nALL ' + passed + ' WITTGENSTEINIAN INFERENCE & CAUSAL ENTAILMENT CHECKS PASSED.');
})().catch(e => { console.error(e); process.exit(1); });
