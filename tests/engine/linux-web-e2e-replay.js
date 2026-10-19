/* Linux Web-to-Root Stateful E2E Replay:
 * Replays realistic tool output through the parser and asserts at each stage:
 *   - Stage 1 (Nmap Recon): host.os_family is linux, http.reachable minted, web enumeration leads
 *   - Stage 2 (Foothold): id output mints foothold.linux, web moves deprioritize, enum/flags lead
 *   - Stage 3 (Privesc Enum): sudo -l + uname -a mint privesc.sudo_rights, host.kernel, vuln.dirtypipe (tier 0)
 *   - Stage 4 (Root & Proofs): both flags captured, privesc retires, report has initial access and privesc
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
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) {
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

var TGT = '10.10.10.5';
var SCOPE = 'host:' + TGT;
var pack = OBOL.packs.actions();
var facts = new OBOL.facts.FactSet([
  OBOL.facts.makeFact({ kind: 'target.configured', scope: SCOPE, source: 'eng' })
]);
var activities = [];
var params = { target: TGT, username: '', password: '' };

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

console.log('=== LINUX WEB-TO-ROOT STATEFUL E2E REPLAY ===\n');

// ── Stage 1: Nmap Recon ─────────────────────────────────────────────────────
console.log('[Stage 1: Nmap Recon]');
ingest('nmap -sV -sC -Pn ' + TGT, [
  'Starting Nmap 7.94 ( https://nmap.org )',
  'Nmap scan report for ' + TGT,
  'Host is up (0.045s latency).',
  'PORT   STATE SERVICE VERSION',
  '22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu-4ubuntu0.5',
  '80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))',
  'Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel'
].join('\n'));

var osFacts = facts.values('host.os_family') || [];
ok(facts.has('host.os_family') && osFacts[0] && osFacts[0].family === 'linux', 'Stage 1: host.os_family is linux');
ok(facts.has('http.reachable'), 'Stage 1: http.reachable is minted');

var topMoves1 = readyIds().slice(0, 5);
var hasWebEnum = topMoves1.indexOf('recon-web-triage') >= 0 || topMoves1.indexOf('content-discovery') >= 0;
ok(hasWebEnum, 'Stage 1: web enumeration (recon-web-triage / content-discovery) ranks in top moves');

// ── Stage 2: Foothold ───────────────────────────────────────────────────────
console.log('\n[Stage 2: Foothold]');
ingest('ssh www-data@' + TGT + ' id', 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n');

ok(facts.has('foothold.linux'), 'Stage 2: foothold.linux is minted from id output');

var topMoves2 = readyIds().slice(0, 5);
ok(topMoves2.indexOf('recon-web-triage') === -1, 'Stage 2: recon-web-triage deprioritized/retired after foothold');
var hasEnumOrFlag = topMoves2.indexOf('linux-enum') >= 0 || topMoves2.indexOf('flag-hunt-linux') >= 0;
ok(hasEnumOrFlag, 'Stage 2: linux-enum / flag-hunt-linux rank at the top');

// ── Stage 3: Linux Enum -> Sudo/Kernel/SUID Escalation ──────────────────────
console.log('\n[Stage 3: Linux Enum -> Sudo/Kernel Escalation]');
ingest('sudo -l', [
  'Matching Defaults entries for www-data on web01:',
  '    env_reset, mail_badpass',
  '',
  'User www-data may run the following commands on web01:',
  '    (ALL : ALL) NOPASSWD: /usr/bin/find'
].join('\n'));

ingest('uname -a', 'Linux web01 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64 GNU/Linux\n', 'linux-enum');

ok(facts.has('privesc.sudo_rights'), 'Stage 3: privesc.sudo_rights is minted from sudo -l');
ok(facts.has('host.kernel'), 'Stage 3: host.kernel is minted from uname -a');
ok(facts.has('vuln.dirtypipe'), 'Stage 3: vuln.dirtypipe is minted from vulnerable kernel version');

var sudoMove = moveById('sudo-abuse');
var dirtypipeMove = moveById('dirtypipe');
ok(sudoMove && OBOL.phases.prematurity(sudoMove, facts) === 0, 'Stage 3: sudo-abuse promotes to tier = 0 Ready Now');
ok(dirtypipeMove && OBOL.phases.prematurity(dirtypipeMove, facts) === 0, 'Stage 3: dirtypipe promotes to tier = 0 Ready Now');
ok(readyIds()[0] === 'sudo-abuse', 'Stage 3: sudo-abuse ranks #1');

// ── Stage 4: Root & Proof Capture -> Report Verification ────────────────────
console.log('\n[Stage 4: Root & Proof Capture -> Report Verification]');
ingest('sudo /usr/bin/find . -exec /bin/sh -p \\; -quit', 'root@web01:/# whoami\nroot\n', 'sudo-abuse');

ingest('', [
  'www-data@web01:~$ whoami; ip a; cat /home/www-data/local.txt',
  'www-data',
  '2: eth0: inet 10.10.10.5/24',
  'a1b2c3d4e5f60718293a4b5c6d7e8f90',
  'root@web01:/root# whoami; ip a; cat /root/proof.txt',
  'root',
  '2: eth0: inet 10.10.10.5/24',
  'f0e1d2c3b4a5968778695a4b3c2d1e0f'
].join('\n'));

// Confirm root access
facts.add(OBOL.facts.makeFact({ kind: 'access.admin', scope: SCOPE, value: { identity: 'root' } }));

ok(facts.has('objective.local_flag'), 'Stage 4: objective.local_flag is minted');
ok(facts.has('objective.root_flag'), 'Stage 4: objective.root_flag is minted');
ok(facts.has('proof.captured'), 'Stage 4: proof.captured is minted');
ok(sudoMove.settled(facts), 'Stage 4: privesc moves settle once access.admin is held');

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
ok(preflight && preflight.warnings.length === 0, 'Stage 4: preflightCheck emits 0 warnings for compliant capture');

console.log(fail ? ('\nLINUX WEB E2E REPLAY: ' + fail + ' FAILURES') : '\nLINUX WEB E2E REPLAY: all passed, recon -> foothold -> privesc -> proof & report');
process.exit(fail ? 1 : 0);
