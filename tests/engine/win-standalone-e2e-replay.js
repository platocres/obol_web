/* Windows Standalone Service-to-SYSTEM Stateful E2E Replay:
 * Replays realistic tool output through the parser and asserts at each stage:
 *   - Stage 1 (Nmap Recon): host.os_family is windows, service.ms-sql-s / port:1433 minted
 *   - Stage 2 (Foothold via MSSQL): foothold.windows minted, windows-enum / flag-hunt-windows lead
 *   - Stage 3 (Windows Enum -> SeImpersonate / Service Perms): privesc.seimpersonate minted, seimpersonate promotes to tier = 0
 *   - Stage 4 (SYSTEM & Proofs): both flags captured, privesc settles, report has initial access and privesc, preflightCheck ok
 */
'use strict';

var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.join(__dirname, '..', '..');
var ENG = path.join(ROOT, 'assets', 'engine');
var ctx = {
  console: console,
  Date: Date,
  Math: Math,
  Array: Array,
  Object: Object,
  String: String,
  Number: Number,
  RegExp: RegExp,
  Set: Set,
  Map: Map,
  JSON: JSON
};
ctx.globalThis = ctx;
ctx.window = ctx;
vm.createContext(ctx);

function load(f) {
  vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f });
}

['facts.js', 'phases.js', 'pack.js', 'packs.js', 'command.js', 'workspace.js', 'profile.js', 'loot.js'].forEach(function (f) {
  load(path.join(ENG, f));
});
load(path.join(ENG, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape'].forEach(function (m) {
  load(path.join(ENG, 'parsers', m + '.js'));
});
load(path.join(ENG, 'parsers', 'index.js'));
load(path.join(ROOT, 'data', 'packs-bundle.js'));
load(path.join(ROOT, 'data', 'reportmeta.js'));
load(path.join(ENG, 'report.js'));

var OBOL = ctx.OBOL;
var fail = 0;
function ok(cond, msg) {
  if (!cond) {
    console.error('  FAIL:', msg);
    fail++;
  } else {
    console.log('  ok  :', msg);
  }
}

var TGT = '10.10.10.25';
var SCOPE = 'host:' + TGT;
var pack = OBOL.packs.actions();
var facts = new OBOL.facts.FactSet([
  OBOL.facts.makeFact({ kind: 'target.configured', scope: SCOPE, source: 'eng' })
]);
var activities = [];

function ingest(command, stdout, actionId) {
  var r = OBOL.parsers.parseActionOutput({
    actionId: actionId || '',
    command: command,
    stdout: stdout,
    source: 'sim',
    scope: SCOPE,
    target: TGT
  });
  var minted = {};
  (r.facts || []).forEach(function (f) {
    if (facts.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) {
      minted[f.kind] = 1;
    }
  });
  activities.push({
    action_id: actionId || '',
    command: command,
    stdout: stdout,
    target: TGT,
    at: Date.now(),
    produced: (r.facts || []).map(function (f) { return f.kind; })
  });
  return minted;
}

function ready() {
  return OBOL.pack.rankActions(facts, pack, {});
}
function readyIds() {
  return ready().map(function (a) { return a.id; });
}
function moveById(id) {
  return pack.filter(function (a) { return a.id === id; })[0];
}

console.log('=== WINDOWS STANDALONE SERVICE-TO-SYSTEM STATEFUL E2E REPLAY ===\n');

// -- Stage 1: Nmap Recon -----------------------------------------------------
console.log('[Stage 1: Nmap Recon]');
ingest('nmap -sV -sC -Pn ' + TGT, [
  'Starting Nmap 7.94 ( https://nmap.org )',
  'Nmap scan report for ' + TGT,
  'Host is up (0.032s latency).',
  'PORT     STATE SERVICE       VERSION',
  '135/tcp  open  msrpc         Microsoft Windows RPC',
  '445/tcp  open  microsoft-ds  Microsoft Windows Server 2019 Standard 17763 microsoft-ds',
  '1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00',
  '5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)',
  'Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows'
].join('\n'));

var osFacts = facts.values('host.os_family') || [];
ok(facts.has('host.os_family') && osFacts[0] && osFacts[0].family === 'windows', 'Stage 1: host.os_family is windows');
ok(facts.has('port:1433'), 'Stage 1: port:1433 is minted');
ok(facts.has('winrm.reachable'), 'Stage 1: winrm.reachable is minted (port 5985)');
ok(!facts.has('http.reachable'), 'Stage 1: WinRM HTTPAPI on 5985 does NOT falsely mint http.reachable');

// -- Stage 2: Foothold via MSSQL xp_cmdshell ---------------------------------
console.log('\n[Stage 2: Foothold via MSSQL xp_cmdshell]');
ingest('impacket-mssqlclient sa:Password123@' + TGT + ' -q "EXEC xp_cmdshell \'whoami\'"', [
  '[*] Encryption required, switching to TLS',
  '[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master',
  'output',
  '--------------------------------------------------------------------------------',
  'sql01\\mssqlsvc'
].join('\n'), 'mssql-xp-cmdshell');

ok(facts.has('foothold.windows'), 'Stage 2: foothold.windows is minted from xp_cmdshell whoami');

var topMoves2 = readyIds().slice(0, 5);
var hasWinEnumOrFlag = topMoves2.indexOf('windows-enum') >= 0 || topMoves2.indexOf('flag-hunt-windows') >= 0;
ok(hasWinEnumOrFlag, 'Stage 2: windows-enum / flag-hunt-windows rank at the top');

// -- Stage 3: Windows Enum -> SeImpersonate Escalation -----------------------
console.log('\n[Stage 3: Windows Enum -> SeImpersonate Escalation]');
ingest('whoami /priv', [
  'PRIVILEGES INFORMATION',
  '----------------------',
  '',
  'Privilege Name                Description                               State',
  '============================= ========================================= ========',
  'SeImpersonatePrivilege        Impersonate a client after authentication Enabled',
  'SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled'
].join('\n'), 'windows-enum');

ok(facts.has('privesc.windows_privilege'), 'Stage 3: privesc.windows_privilege is minted from whoami /priv');

var seimpMove = moveById('seimpersonate');
ok(seimpMove && OBOL.phases.prematurity(seimpMove, facts) === 0, 'Stage 3: seimpersonate promotes to tier = 0 Ready Now');
ok(readyIds().slice(0, 3).indexOf('seimpersonate') >= 0, 'Stage 3: seimpersonate ranks in top 3 moves');

// -- Stage 4: SYSTEM & Proof Capture -> Report Verification ------------------
console.log('\n[Stage 4: SYSTEM & Proof Capture -> Report Verification]');
ingest('GodPotato-NET4.exe -cmd "cmd /c whoami"', 'nt authority\\system\n', 'seimpersonate');

ingest('', [
  'PS C:\\Users\\mssqlsvc\\Desktop> whoami; ipconfig; type C:\\Users\\mssqlsvc\\Desktop\\local.txt',
  'sql01\\mssqlsvc',
  '   IPv4 Address. . . . . . . . . . . : ' + TGT,
  '11223344556677889900aabbccddeeff',
  'PS C:\\Users\\Administrator\\Desktop> whoami; ipconfig; type C:\\Users\\Administrator\\Desktop\\proof.txt',
  'nt authority\\system',
  '   IPv4 Address. . . . . . . . . . . : ' + TGT,
  'ffeeddccbbaa00998877665544332211'
].join('\n'));

ok(facts.has('access.system'), 'Stage 4: access.system is minted');
ok(facts.has('objective.local_flag'), 'Stage 4: objective.local_flag is minted');
ok(facts.has('objective.root_flag'), 'Stage 4: objective.root_flag is minted');
ok(facts.has('proof.captured'), 'Stage 4: proof.captured is minted');
ok(seimpMove.settled(facts), 'Stage 4: seimpersonate settles once access.system is held');

var repCtx = OBOL.report.buildContext({
  facts: facts,
  actions: pack,
  targets: [{ host: TGT, ip: TGT }],
  activities: activities
});

ok(repCtx && repCtx.proofs && repCtx.proofs.length === 2, 'Stage 4: buildContext collects both captured proofs');

var targetObj = repCtx.targets[0] || {};
var initialFindings = OBOL.report.initialAccessFindings(targetObj.findings, targetObj);
var privescFindings = OBOL.report.privescFindings(targetObj.findings, targetObj);

ok(initialFindings && initialFindings.length > 0, 'Stage 4: report contains non-empty Initial Access section');
ok(privescFindings && privescFindings.length > 0, 'Stage 4: report contains non-empty Privilege Escalation section');

var preflight = OBOL.report.preflightCheck(repCtx);
ok(preflight && preflight.ok === true, 'Stage 4: preflightCheck reports ok: true');
ok(preflight && preflight.warnings && preflight.warnings.length === 0, 'Stage 4: preflightCheck emits 0 warnings for compliant capture');

console.log(fail ? ('\nWINDOWS STANDALONE E2E REPLAY: ' + fail + ' FAILURES') : '\nWINDOWS STANDALONE E2E REPLAY: all passed, recon -> foothold -> privesc -> proof & report');
process.exit(fail ? 1 : 0);
