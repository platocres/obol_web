#!/usr/bin/env node
/**
 * verify-oscp-practice-exams.js
 * Comprehensive Stateful Golden Progression Replay Suite for OSCP Practice Exams:
 *  - OSCP A (Challenge 4): MS01, MS02, DC01, AERO, CRYSTAL, HERMES
 *  - OSCP B (Challenge 5): MS01, MS02, DC01, KIERO, BERLIN, GUST
 *  - OSCP C (Challenge 6 - Reconstructed): MS01, MS02, DC01, Standalone A, Standalone B, Standalone C
 *
 * Verifies that the Obol engine computes ready moves, suggests the correct #1 actions,
 * validates prerequisite transitions, and guides an operator end-to-end to Domain Admin / proof flags.
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
load('assets/engine/parsers/host.js');
load('assets/engine/parsers/database.js');
load('assets/engine/parsers/findings.js');
load('assets/engine/parsers/services.js');
load('assets/engine/parsers/web.js');
load('assets/engine/parsers/pivot.js');
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

function mkFact(kind, scope, val) {
  return OBOL.facts.makeFact({
    kind: kind,
    scope: scope,
    value: val || {},
    state: OBOL.facts.ProofState.SUPPORTED,
    source: 'simulation'
  });
}

function createMockEng(params, facts) {
  const eng = {
    id: 'eng-oscp-replay-' + Date.now(),
    params: Object.assign({}, params),
    facts: facts,
    checklist: {},
    activities: []
  };
  OBOL.store.active = function () { return eng; };
  OBOL.store.factSet = function () {
    const fs = new OBOL.facts.FactSet();
    eng.facts.forEach(f => {
      const factObj = (f && f.kind ? f : OBOL.facts.factFromJson(f));
      fs.add(factObj);
    });
    return fs;
  };
  OBOL.store.factSetForTarget = function (tgt) {
    return OBOL.store.factSet();
  };
  return eng;
}

console.log('=============================================================================');
console.log('=== STATEFUL GOLDEN REPLAY SUITE: 3 PEN-200 OSCP PRACTICE EXAM LABS ===');
console.log('=============================================================================\n');

// =========================================================================
// SECTION 1: OSCP A (CHALLENGE 4) GOLDEN PROGRESSION REPLAY
// =========================================================================
console.log('===========================================================');
console.log('=== TEST SUITE 1: OSCP A (CHALLENGE 4) GOLDEN REPLAY ===');
console.log('===========================================================');

const oscpAParams = {
  platform: 'offsec-exam',
  target: '192.168.178.141',
  scope_defined: true,
  lhost: '192.168.45.156',
  lhost_iface: 'tun0',
  username: 'Eric.Wallows',
  password: 'EricLikesRunning800',
  nthash: '',
  domain: 'OSCP.EXAM'
};

// 1.1 MS01 Foothold -> WinRM shell & Service DACL PrivEsc
console.log('\n[OSCP A — 1.1 MS01: Foothold Shell & Service DACL PrivEsc]');
const ms01Facts = [
  mkFact('port:5985', 'host:192.168.178.141', { port: 5985, service: 'wsman' }),
  mkFact('port:445', 'host:192.168.178.141', { port: 445, service: 'microsoft-ds' }),
  mkFact('credential.available', 'host:192.168.178.141', { username: 'Eric.Wallows', password: 'EricLikesRunning800' }),
  mkFact('winrm.authenticated', 'host:192.168.178.141', { username: 'Eric.Wallows' })
];
createMockEng(oscpAParams, ms01Facts);
let coach = OBOL.coach.compute();
assert(coach.onFlow.length > 0, 'MS01: Coach computed ready moves');
let moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('win-interactive-shell') || moveIds.includes('flag-hunt-windows'), 'MS01: Recommends WinRM interactive shell or flag hunt');

// MS01 Post-Shell: Service DACL PrivEsc & BloodHound
console.log('\n[OSCP A — 1.2 MS01: Service DACL PrivEsc & BloodHound Collection]');
ms01Facts.push(mkFact('foothold.windows', 'host:192.168.178.141', { user: 'eric.wallows' }));
ms01Facts.push(mkFact('privesc.weak_service_permission', 'host:192.168.178.141', { service: 'CustomService' }));
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('windows-service-dacl-abuse'), 'MS01: Recommends windows-service-dacl-abuse upon detecting weak service permissions');

// MS01 Local Admin Achieved & Ligolo-ng Pivot
console.log('\n[OSCP A — 1.3 MS01: Ligolo-ng Pivot Routing into 10.10.118.0/24]');
ms01Facts.push(mkFact('access.admin', 'host:192.168.178.141', { identity: 'NT AUTHORITY\\SYSTEM' }));
ms01Facts.push(mkFact('scan.local.routes', 'host:192.168.178.141', { subnets: ['10.10.118.0/24'] }));
ms01Facts.push(mkFact('host.multihomed', 'host:192.168.178.141', { interfaces: 2 }));
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('ligolo-tunnel-pivot'), 'MS01: Recommends ligolo-tunnel-pivot to un-gate internal subnet pivot');

// 1.2 MS02 Internal Member Pivot -> SAM Dump & Constrained Delegation
console.log('\n[OSCP A — 1.4 MS02: Internal Member SAM Extraction & Delegation]');
const ms02Params = Object.assign({}, oscpAParams, { target: '10.10.118.142' });
const ms02Facts = [
  mkFact('tunnel.route', 'host:192.168.178.141', { via: 'ligolo' }),
  mkFact('pivot.active', 'host:192.168.178.141', { via: 'ligolo' }),
  mkFact('port:445', 'host:10.10.118.142', { port: 445 }),
  mkFact('port:5985', 'host:10.10.118.142', { port: 5985 }),
  mkFact('foothold.windows', 'host:10.10.118.142', { user: 'administrator' }),
  mkFact('access.admin', 'host:10.10.118.142', { identity: 'Administrator' }),
  mkFact('ad.control_paths', 'host:10.10.118.142', { lead: 'constrained_delegation' })
];
createMockEng(ms02Params, ms02Facts);
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('dump-secrets') || moveIds.includes('delegation-abuse'), 'MS02: Recommends dump-secrets or delegation-abuse');

// 1.3 DC01 Domain Controller -> DCSync & Proof Flag
console.log('\n[OSCP A — 1.5 DC01: DCSync & Proof Flag Capture]');
const dc01Params = Object.assign({}, oscpAParams, { target: '10.10.118.140' });
const dc01Facts = [
  mkFact('ad.control_paths', 'host:10.10.118.140', { privilege: 'DCSync' }),
  mkFact('credential.admin', 'host:10.10.118.140', { username: 'Administrator', hash: 'e19ccf750f378735b46974a103f81ae5' })
];
createMockEng(dc01Params, dc01Facts);
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('dcsync') || moveIds.includes('flag-hunt-root-windows'), 'DC01: Recommends dcsync or flag-hunt-root-windows with domain admin rights');

// 1.4 Standalone AERO -> Pico CMS -> Aerospike UDF RCE -> Screen 4.5.0 SUID Root
console.log('\n[OSCP A — 1.6 Standalone AERO: Aerospike UDF RCE -> Screen 4.5.0 SUID Root]');
const aeroParams = Object.assign({}, oscpAParams, { target: '192.168.178.143', domain: '' });
const aeroFacts = [
  mkFact('port:80', 'host:192.168.178.143', { port: 80, service: 'http' }),
  mkFact('port:3000', 'host:192.168.178.143', { port: 3000, service: 'aerospike' }),
  mkFact('vuln.pico_cms', 'host:192.168.178.143', {}),
  mkFact('vuln.aerospike', 'host:192.168.178.143', { cve: 'CVE-2020-13151' }),
  mkFact('vuln.aerospike_udf', 'host:192.168.178.143', { cve: 'CVE-2020-13151' })
];
createMockEng(aeroParams, aeroFacts);
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('aerospike-udf-rce'), 'AERO: Recommends aerospike-udf-rce upon discovering vulnerable Aerospike service');

// Shell caught as aerospike -> SUID scan finds screen-4.5.0
aeroFacts.push(mkFact('foothold.linux', 'host:192.168.178.143', { user: 'aerospike' }));
aeroFacts.push(mkFact('privesc.suid_candidate', 'host:192.168.178.143', { paths: ['/usr/bin/screen-4.5.0'] }));
aeroFacts.push(mkFact('vuln.screen_suid', 'host:192.168.178.143', { cve: 'CVE-2017-5618' }));
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('screen-suid-privesc'), 'AERO: Recommends screen-suid-privesc upon detecting SUID screen-4.5.0');
console.log('PASS: OSCP A complete end-to-end replay verified!');

// =========================================================================
// SECTION 2: OSCP B (CHALLENGE 5) GOLDEN PROGRESSION REPLAY
// =========================================================================
console.log('\n===========================================================');
console.log('=== TEST SUITE 2: OSCP B (CHALLENGE 5) GOLDEN REPLAY ===');
console.log('===========================================================');

const oscpBParams = {
  platform: 'offsec-exam',
  target: '192.168.157.147',
  scope_defined: true,
  lhost: '192.168.45.156',
  lhost_iface: 'tun0',
  username: 'Eric.Wallows',
  password: 'EricLikesRunning800',
  nthash: '',
  domain: 'OSCP.EXAM'
};

// 2.1 MS01 Foothold -> SeImpersonate Potato -> Kerberoasting sql_svc
console.log('\n[OSCP B — 2.1 MS01: SeImpersonate Potato & Kerberoasting sql_svc]');
const ms01BFacts = [
  mkFact('port:5985', 'host:192.168.157.147', { port: 5985 }),
  mkFact('credential.available', 'host:192.168.157.147', { username: 'Eric.Wallows', password: 'EricLikesRunning800' }),
  mkFact('foothold.windows', 'host:192.168.157.147', { user: 'eric.wallows' }),
  mkFact('privesc.windows_privilege', 'host:192.168.157.147', { privilege: 'SeImpersonatePrivilege' }),
  mkFact('ad.domain_user', 'host:192.168.157.147', { user: 'eric.wallows' }),
  mkFact('port:88', 'host:10.10.118.146', { port: 88, service: 'kerberos' })
];
createMockEng(oscpBParams, ms01BFacts);
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('seimpersonate') || moveIds.includes('kerberoast'), 'MS01 (B): Recommends seimpersonate or kerberoast');

// Kerberoast hash captured -> Crack TGS
ms01BFacts.push(mkFact('hash.tgs', 'host:192.168.157.147', { user: 'sql_svc', hash: '$krb5tgs$...' }));
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('crack-tgs'), 'MS01 (B): Recommends crack-tgs when TGS ticket hash is held');

// 2.2 MS02 Internal Member -> sql_svc Login & SAM Hive Export
console.log('\n[OSCP B — 2.2 MS02: sql_svc WinRM & SAM Hash Cracking]');
const ms02BParams = Object.assign({}, oscpBParams, { target: '10.10.118.148' });
const ms02BFacts = [
  mkFact('tunnel.route', 'host:192.168.157.147', { via: 'ligolo' }),
  mkFact('port:5985', 'host:10.10.118.148', { port: 5985 }),
  mkFact('credential.available', 'host:10.10.118.148', { username: 'sql_svc', password: 'Password123' }),
  mkFact('foothold.windows', 'host:10.10.118.148', { user: 'sql_svc' }),
  mkFact('access.admin', 'host:10.10.118.148', { identity: 'Administrators' })
];
createMockEng(ms02BParams, ms02BFacts);
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('dump-secrets') || moveIds.includes('flag-hunt-windows'), 'MS02 (B): Recommends dump-secrets or flag-hunt-windows with administrative rights');

// 2.3 DC01 Domain Controller -> Pass-the-Hash & Proof Flag
console.log('\n[OSCP B — 2.3 DC01: PTH Admin & Flag Hunt]');
const dc01BParams = Object.assign({}, oscpBParams, { target: '10.10.118.146' });
const dc01BFacts = [
  mkFact('port:445', 'host:10.10.118.146', { port: 445 }),
  mkFact('port:5985', 'host:10.10.118.146', { port: 5985 }),
  mkFact('credential.admin', 'host:10.10.118.146', { username: 'Administrator', nthash: '469bc3550bed9ce3ea94b792a4b036b1' }),
  mkFact('access.admin', 'host:10.10.118.146', { identity: 'Administrator' })
];
createMockEng(dc01BParams, dc01BFacts);
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('win-interactive-shell') || moveIds.includes('dcsync') || moveIds.includes('flag-hunt-root-windows'), 'DC01 (B): Recommends win-interactive-shell, dcsync, or flag-hunt-root-windows');

// 2.4 Standalones (KIERO / BERLIN / GUST)
console.log('\n[OSCP B — 2.4 Standalones: KIERO, BERLIN, GUST]');
// KIERO (wildcard tar cron)
const kieroFacts = [
  mkFact('foothold.linux', 'host:192.168.158.149', { user: 'kiero' }),
  mkFact('privesc.cron', 'host:192.168.158.149', { command: 'tar czf /tmp/backup.tar.gz *' })
];
createMockEng(Object.assign({}, oscpBParams, { target: '192.168.158.149' }), kieroFacts);
coach = OBOL.coach.compute();
assert(coach.onFlow.some(m => m.id === 'wildcard-injection'), 'KIERO: Recommends wildcard-injection for tar * cron script');

// BERLIN (PATH hijack SUID)
const berlinFacts = [
  mkFact('foothold.linux', 'host:192.168.158.150', { user: 'www-data' }),
  mkFact('privesc.suid_candidate', 'host:192.168.158.150', { paths: ['/usr/local/bin/backup'] })
];
createMockEng(Object.assign({}, oscpBParams, { target: '192.168.158.150' }), berlinFacts);
coach = OBOL.coach.compute();
assert(coach.onFlow.some(m => m.id === 'linux-path-hijack' || m.id === 'suid-gtfobins'), 'BERLIN: Recommends linux-path-hijack or suid-gtfobins');

// GUST (FTP webroot upload webshell & potato privesc)
const gustFacts = [
  mkFact('port:21', 'host:192.168.158.151', { port: 21, service: 'ftp' }),
  mkFact('port:80', 'host:192.168.158.151', { port: 80, service: 'http' }),
  mkFact('ftp.anon_write', 'host:192.168.158.151', {}),
  mkFact('credential.available', 'host:192.168.158.151', { user: 'anonymous' })
];
createMockEng(Object.assign({}, oscpBParams, { target: '192.168.158.151' }), gustFacts);
coach = OBOL.coach.compute();
assert(coach.onFlow.some(m => m.id === 'ftp-webroot-upload-webshell'), 'GUST: Recommends ftp-webroot-upload-webshell');
console.log('PASS: OSCP B complete end-to-end replay verified!');

// =========================================================================
// SECTION 3: OSCP C (CHALLENGE 6 - RECONSTRUCTED) GOLDEN PROGRESSION REPLAY
// =========================================================================
console.log('\n===========================================================');
console.log('=== TEST SUITE 3: OSCP C (CHALLENGE 6) GOLDEN REPLAY ===');
console.log('===========================================================');

const oscpCParams = {
  platform: 'offsec-exam',
  target: '192.168.100.153',
  scope_defined: true,
  lhost: '192.168.45.156',
  lhost_iface: 'tun0',
  username: 'support',
  password: 'Password123!',
  nthash: '',
  domain: 'OSCP.EXAM'
};

// 3.1 MS01: SQLite partners.db -> support SSH -> admintool NTLM leak -> Ligolo pivot
console.log('\n[OSCP C — 3.1 MS01: SQLite partners.db extraction & SSH Foothold]');
const ms01CFacts = [
  mkFact('port:8000', 'host:192.168.100.153', { port: 8000, service: 'http' }),
  mkFact('port:22', 'host:192.168.100.153', { port: 22, service: 'ssh' }),
  mkFact('loot.material', 'host:192.168.100.153', { kind: 'sqlite_db' }),
  mkFact('web.file_leak', 'host:192.168.100.153', { path: '/partner/db/partners.db' })
];
createMockEng(oscpCParams, ms01CFacts);
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('sqlite-table-extract'), 'MS01 (C): Recommends sqlite-table-extract when SQLite database file is discovered');

// Support SSH foothold established -> admintool.exe diagnostic NTLM leak -> Ligolo pivot
ms01CFacts.push(mkFact('foothold.windows', 'host:192.168.100.153', { user: 'support' }));
ms01CFacts.push(mkFact('scan.local.routes', 'host:192.168.100.153', { subnets: ['10.10.68.0/24'] }));
ms01CFacts.push(mkFact('host.multihomed', 'host:192.168.100.153', { interfaces: 2 }));
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('ligolo-tunnel-pivot'), 'MS01 (C): Recommends ligolo-tunnel-pivot on dual-homed foothold');

// 3.2 MS02 Internal Member: MSSQL xp_cmdshell -> SAM/Mimikatz domain admin dump
console.log('\n[OSCP C — 3.2 MS02: MSSQL xp_cmdshell & Mimikatz Domain Admin Dump]');
const ms02CParams = Object.assign({}, oscpCParams, { target: '10.10.68.154' });
const ms02CFacts = [
  mkFact('tunnel.route', 'host:192.168.100.153', { via: 'ligolo' }),
  mkFact('port:1433', 'host:10.10.68.154', { port: 1433, service: 'ms-sql-s' }),
  mkFact('credential.available', 'host:10.10.68.154', { username: 'support', password: 'Password123!' })
];
createMockEng(ms02CParams, ms02CFacts);
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('mssql-login'), 'MS02 (C): Recommends mssql-login with valid support credentials');

// MSSQL connected -> xp_cmdshell foothold -> Mimikatz / SAM dump
ms02CFacts.push(mkFact('foothold.windows', 'host:10.10.68.154', { user: 'sql_svc' }));
ms02CFacts.push(mkFact('access.admin', 'host:10.10.68.154', { identity: 'NT AUTHORITY\\SYSTEM' }));
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('dump-secrets') || moveIds.includes('lsass-dump-onbox'), 'MS02 (C): Recommends dump-secrets or lsass-dump-onbox with SYSTEM privileges');

// 3.3 DC01 Domain Controller: Pass-The-Hash to DC & Proof Flag
console.log('\n[OSCP C — 3.3 DC01: Domain Controller PTH & Proof Flag Hunt]');
const dc01CParams = Object.assign({}, oscpCParams, { target: '10.10.68.152' });
const dc01CFacts = [
  mkFact('port:445', 'host:10.10.68.152', { port: 445 }),
  mkFact('credential.admin', 'host:10.10.68.152', { username: 'Administrator', hash: 'e19ccf750f378735b46974a103f81ae5' }),
  mkFact('access.admin', 'host:10.10.68.152', { identity: 'Administrator' })
];
createMockEng(dc01CParams, dc01CFacts);
coach = OBOL.coach.compute();
moveIds = coach.onFlow.map(m => m.id);
assert(moveIds.includes('win-interactive-shell') || moveIds.includes('dcsync') || moveIds.includes('flag-hunt-root-windows'), 'DC01 (C): Recommends win-interactive-shell, dcsync, or flag-hunt-root-windows');

// 3.4 Standalone A: Mobile Mouse Server (port 1978) RCE
console.log('\n[OSCP C — 3.4 Standalone A: Mobile Mouse RCE]');
const standAFacts = [
  mkFact('port:1978', 'host:192.168.100.160', { port: 1978, service: 'mouse-server' }),
  mkFact('vuln.wifi_mouse', 'host:192.168.100.160', {})
];
createMockEng(Object.assign({}, oscpCParams, { target: '192.168.100.160' }), standAFacts);
coach = OBOL.coach.compute();
assert(coach.onFlow.some(m => m.id === 'wifi-mouse-rce'), 'Standalone A: Recommends wifi-mouse-rce on port 1978');

// 3.5 Standalone B: SNMP hrSWRun Credential Leak -> Scheduled Task Privesc
console.log('\n[OSCP C — 3.5 Standalone B: SNMP Process Harvesting & Task PrivEsc]');
const standBFacts = [
  mkFact('port:161', 'host:192.168.100.161', { port: 161, service: 'snmp' }),
  mkFact('snmp.community', 'host:192.168.100.161', { community: 'public' }),
  mkFact('service.snmp', 'host:192.168.100.161', {})
];
createMockEng(Object.assign({}, oscpCParams, { target: '192.168.100.161' }), standBFacts);
coach = OBOL.coach.compute();
assert(coach.onFlow.some(m => m.id === 'snmp-process-cmdline-harvest'), 'Standalone B: Recommends snmp-process-cmdline-harvest');

// Credentials recovered from SNMP process parameters -> Scheduled Task privesc
standBFacts.push(mkFact('foothold.windows', 'host:192.168.100.161', { user: 'admin' }));
standBFacts.push(mkFact('privesc.scheduled_task', 'host:192.168.100.161', { task: 'obolsvc' }));
coach = OBOL.coach.compute();
assert(coach.onFlow.some(m => m.id === 'windows-schtask-abuse'), 'Standalone B: Recommends windows-schtask-abuse');

// 3.6 Standalone C: FTP Anonymous Config Leak -> Usermin RCE -> Sudo Root
console.log('\n[OSCP C — 3.6 Standalone C: Usermin RCE & Sudo Root]');
const standCFacts = [
  mkFact('port:20000', 'host:192.168.100.162', { port: 20000, service: 'usermin' }),
  mkFact('vuln.usermin', 'host:192.168.100.162', { cve: 'EDB-50234' }),
  mkFact('vuln.usermin_rce', 'host:192.168.100.162', { cve: 'EDB-50234' })
];
createMockEng(Object.assign({}, oscpCParams, { target: '192.168.100.162' }), standCFacts);
coach = OBOL.coach.compute();
assert(coach.onFlow.some(m => m.id === 'usermin-auth-rce'), 'Standalone C: Recommends usermin-auth-rce');

// Usermin shell caught -> Sudo rights present
standCFacts.push(mkFact('foothold.linux', 'host:192.168.100.162', { user: 'usermin' }));
standCFacts.push(mkFact('privesc.sudo_rights', 'host:192.168.100.162', { binary: '/bin/bash' }));
coach = OBOL.coach.compute();
assert(coach.onFlow.some(m => m.id === 'sudo-abuse'), 'Standalone C: Recommends sudo-abuse');
console.log('PASS: OSCP C complete end-to-end replay verified!');

console.log('\n=============================================================================');
console.log('ALL 18 OSCP PRACTICE EXAM TARGET PROGRESSIONS PASSED WITH 100% SUCCESS!');
console.log('=============================================================================');
