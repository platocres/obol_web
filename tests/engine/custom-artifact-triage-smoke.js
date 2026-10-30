/* Smoke test: 2-Step Zero-Hardcoding Custom Binary & Disclosed Web-Source Triage Pipeline.
 *
 * Uses runtime-randomized synthetic names, paths, and secrets to verify zero filename or literal
 * hardcoding across:
 *   1. Linux Custom Binary Triage (Step 1 OS-baseline/GTFOBins subtraction -> privesc.custom_binary
 *      -> {{custom_bin}} in linux-custom-binary-triage; Step 2 strings/ldd/readelf/ltrace ->
 *      privesc.path_hijack_candidate & privesc.library_or_script_hijack -> hijack moves).
 *   2. Windows Custom Binary Triage (Step 1 C:\Windows + vendor baseline subtraction across sc qc,
 *      wmic, schtasks -> privesc.custom_binary -> {{custom_bin}} in windows-custom-binary-triage;
 *      Step 2 ilspycmd / strings -> Process.Start & DllImport hijack facts).
 *   3. Disclosed Web Source & Manifest Triage (Step 1 HTTP 500 trace, phpinfo, LFI source, and
 *      package.json/composer.json/requirements.txt/pom.xml -> web.source_disclosed &
 *      web.manifest_disclosed + {{source_path}}/{{app_base_path}}; Step 2 DB connectors ->
 *      credential.available, JWT secrets, and server-side CmdI/Deserial/TypeJuggling/NoSQLi sinks).
 */
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
function req(rel) { return require(path.join(ROOT, rel)); }

req('assets/engine/facts.js');
req('assets/engine/phases.js');
req('assets/engine/pack.js');
req('assets/engine/profile.js');
req('assets/engine/command.js');
req('assets/engine/workspace.js');
req('data/field-notes.js');
req('data/decision-forks.js');
req('data/parser-signatures.js');
req('assets/engine/parsers/common.js');
[
  'nmap', 'directory', 'creds', 'host', 'web', 'services', 'database',
  'websource', 'findings', 'edb', 'shape', 'pivot', 'dns', 'blockers',
  'nxc-catalog', 'inference', 'index'
].forEach((m) => req('assets/engine/parsers/' + m + '.js'));

const OBOL = globalThis.OBOL;
const PK = OBOL.pack;
const F = OBOL.facts;

const pdir = path.join(ROOT, 'data', 'packs');
const bundle = {};
fs.readdirSync(pdir).filter((f) => f.endsWith('.json')).forEach((f) => {
  bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8'));
});
const ACTIONS = PK.loadPacks(Object.keys(bundle).map((k) => bundle[k]));
OBOL.packs = { actions: () => ACTIONS, dataPack: (n) => bundle[n], packData: () => bundle };

const byId = {};
ACTIONS.forEach((a) => { byId[a.id] = a; });

let passed = 0;
function check(cond, msg) {
  if (!cond) {
    console.error('  FAIL:', msg);
    assert.ok(cond, msg);
  }
  passed++;
}

function randId(prefix) {
  return (prefix || 'syn') + '_' + crypto.randomBytes(3).toString('hex');
}

function parseOut(command, stdout, extraFacts) {
  return OBOL.parsers.parseActionOutput({
    command: command || '',
    stdout: stdout || '',
    stderr: '',
    scope: 'host:198.51.100.77',
    target: '198.51.100.77',
    context: { target: '198.51.100.77' },
    existingFacts: extraFacts || []
  });
}

function makeFactSet(factsArr) {
  const fs2 = new F.FactSet();
  fs2.add(F.makeFact({ kind: 'target.configured', value: { target: '198.51.100.77' }, scope: 'host:198.51.100.77', state: 'supported' }));
  fs2.add(F.makeFact({ kind: 'host.up', value: {}, scope: 'host:198.51.100.77', state: 'supported' }));
  (factsArr || []).forEach((f) => fs2.add(f));
  return fs2;
}

function isReady(moveId, fset) {
  const act = byId[moveId];
  return !!(act && act.eligible(fset) && !act.settled(fset) && !act.obsolete(fset));
}

function isRetired(moveId, fset) {
  const act = byId[moveId];
  return !!(act && (act.settled(fset) || act.obsolete(fset)) && !isReady(moveId, fset));
}

function fillCmd(moveId, cmdIdx, fset) {
  const act = byId[moveId];
  return OBOL.command.fillTemplate(act.commands[cmdIdx].run, fset, {
    action: act,
    params: { target: '198.51.100.77', lhost: '203.0.113.9', lport: '4444' }
  });
}

console.log('=== Custom Artifact & Disclosed Web-Source Triage Smoke ===');

// --- 1. Linux Custom Binary Triage (Step 1 + Step 2) ---
{
  const appDir = randId(' suite').trim();
  const suidBin = '/opt/' + appDir + '/' + randId('collector');
  const suidOut = [
    '/usr/bin/passwd',
    '/usr/bin/chsh',
    '/usr/bin/gpasswd',
    '/usr/bin/newgrp',
    '/usr/bin/sudo',
    '/usr/bin/mount',
    '/usr/bin/umount',
    '/usr/bin/su',
    '/usr/lib/openssh/ssh-keysign',
    '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
    suidBin
  ].join('\n');

  const res1 = parseOut('find / -perm -4000 -type f 2>/dev/null', suidOut);
  const cb = res1.facts.find((f) => f.kind === 'privesc.custom_binary');
  check(!!cb, 'Linux Step 1 (SUID): non-stock SUID binary mints privesc.custom_binary');
  check(cb.value.custom_bin === suidBin && cb.value.path === suidBin,
    'Linux Step 1 (SUID): subtracts all stock SUID binaries and selects ' + suidBin);
  check(res1.facts.some((f) => f.kind === 'foothold.linux'),
    'Linux Step 1: out-of-order privesc.custom_binary entails foothold.linux');

  const fset = makeFactSet(res1.facts);
  check(isReady('linux-custom-binary-triage', fset), 'Linux Step 1: unlocks linux-custom-binary-triage');
  const triageCmd = fillCmd('linux-custom-binary-triage', 0, fset);
  check(triageCmd.includes(suidBin), 'Linux Step 1: fills {{custom_bin}} with randomized path (' + triageCmd + ')');

  // Stock-only SUID list + GTFOBins sudo must NOT mint privesc.custom_binary
  const stockOnlyRes = parseOut('find / -perm -4000 -type f 2>/dev/null', '/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/mount');
  check(!stockOnlyRes.facts.some((f) => f.kind === 'privesc.custom_binary'),
    'Linux Step 1: stock-only SUID list mints 0 privesc.custom_binary facts');

  const gtfoSudoRes = parseOut('sudo -l', 'User operator may run the following commands on host:\n    (ALL) NOPASSWD: /usr/bin/vim');
  check(!gtfoSudoRes.facts.some((f) => f.kind === 'privesc.custom_binary'),
    'Linux Step 1: GTFOBins sudo (/usr/bin/vim) yields to sudo-abuse without minting privesc.custom_binary');

  const customSudoBin = '/usr/local/bin/' + randId(' guardian');
  const customSudoRes = parseOut('sudo -l', 'User operator may run the following commands on host:\n    (root) NOPASSWD: ' + customSudoBin.replace(/\s+/g, ''));
  check(customSudoRes.facts.some((f) => f.kind === 'privesc.custom_binary'),
    'Linux Step 1: non-GTFOBins sudo binary in /usr/local/bin mints privesc.custom_binary');

  // Step 2a: Relative command invocation -> privesc.path_hijack_candidate
  const ltraceRel = [
    '__libc_start_main(0x401150, 1, 0x7ffc88, 0x401210 <unfinished ...>',
    'setuid(0)                                        = 0',
    'system("tar -czf /tmp/snap.tgz /var/log/syslog" <no return ...>',
    '+++ exited (status 0) +++'
  ].join('\n');
  const res2a = parseOut('ltrace ' + suidBin, ltraceRel);
  const pathHijack = res2a.facts.find((f) => f.kind === 'privesc.path_hijack_candidate');
  check(!!pathHijack && pathHijack.value.hijack_bin === 'tar',
    'Linux Step 2a: ltrace system("tar ...") mints privesc.path_hijack_candidate (hijack_bin=tar)');

  // Absolute path must NOT false-positive as relative PATH hijack
  const ltraceAbs = 'system("/usr/bin/tar -czf /tmp/snap.tgz /var/log/syslog") = 0';
  const resAbs = parseOut('ltrace ' + suidBin, ltraceAbs);
  check(!resAbs.facts.some((f) => f.kind === 'privesc.path_hijack_candidate'),
    'Linux Step 2a: absolute system("/usr/bin/tar ...") does NOT false-positive as PATH hijack');

  const fset2a = makeFactSet(res1.facts.concat(res2a.facts));
  check(isRetired('linux-custom-binary-triage', fset2a),
    'Linux Step 2a: privesc.path_hijack_candidate retires linux-custom-binary-triage');
  check(isReady('linux-path-hijack', fset2a),
    'Linux Step 2a: privesc.path_hijack_candidate unlocks linux-path-hijack');

  // Step 2b: Missing .so / custom RPATH -> privesc.library_or_script_hijack
  const missingSo = 'lib' + randId('ext') + '.so';
  const lddOut = [
    '\tlinux-vdso.so.1 (0x00007ffd55df1000)',
    '\t' + missingSo + ' => not found',
    '\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9a12000000)',
    '\tRPATH                /opt/' + appDir + '/plugins'
  ].join('\n');
  const res2b = parseOut('ldd ' + suidBin, lddOut);
  const libHijack = res2b.facts.find((f) => f.kind === 'privesc.library_or_script_hijack');
  check(!!libHijack, 'Linux Step 2b: ldd missing .so / custom RPATH mints privesc.library_or_script_hijack');
  const fset2b = makeFactSet(res1.facts.concat(res2b.facts));
  check(isRetired('linux-custom-binary-triage', fset2b),
    'Linux Step 2b: privesc.library_or_script_hijack retires linux-custom-binary-triage');
  check(isReady('linux-shared-library-hijack', fset2b),
    'Linux Step 2b: unlocks linux-shared-library-hijack');
}

// --- 2. Windows Custom Binary Triage (Step 1 + Step 2) ---
{
  const winFolder = randId('VendorSuite');
  const winExe = 'C:\\Apps\\' + winFolder + '\\' + randId('SyncWorker') + '.exe';
  const schtasksOut = [
    'Folder: \\',
    'HostName:                             WIN-NODE01',
    'TaskName:                             \\Microsoft\\Windows\\Defrag\\ScheduledDefrag',
    'Task To Run:                          C:\\Windows\\system32\\defrag.exe -c -h -o',
    'Run As User:                          SYSTEM',
    '',
    'HostName:                             WIN-NODE01',
    'TaskName:                             \\' + winFolder + 'Job',
    'Task To Run:                          "' + winExe + '" --daemon',
    'Run As User:                          SYSTEM'
  ].join('\n');

  const resWin1 = parseOut('schtasks /query /v /fo LIST', schtasksOut);
  const cbWin = resWin1.facts.find((f) => f.kind === 'privesc.custom_binary');
  check(!!cbWin && cbWin.value.custom_bin === winExe,
    'Windows Step 1 (schtasks): subtracts C:\\Windows\\system32\\defrag.exe and mints privesc.custom_binary for ' + winExe);
  check(resWin1.facts.some((f) => f.kind === 'foothold.windows'),
    'Windows Step 1: out-of-order Windows custom binary entails foothold.windows');

  // sc qc variant
  const scWinExe = 'C:\\ProgramData\\' + winFolder + '\\' + randId('AgentSvc') + '.exe';
  const scOut = [
    '[SC] QueryServiceConfig SUCCESS',
    '',
    'SERVICE_NAME: ' + winFolder + 'Svc',
    '        TYPE               : 10  WIN32_OWN_PROCESS',
    '        START_TYPE         : 2   AUTO_START',
    '        BINARY_PATH_NAME   : "' + scWinExe + '" --service',
    '        SERVICE_START_NAME : LocalSystem'
  ].join('\n');
  const resSc = parseOut('sc qc ' + winFolder + 'Svc', scOut);
  check(resSc.facts.some((f) => f.kind === 'privesc.custom_binary' && f.value.custom_bin === scWinExe),
    'Windows Step 1 (sc qc): non-baseline service binary mints privesc.custom_binary');

  const fsetWin = makeFactSet(resWin1.facts);
  check(isReady('windows-custom-binary-triage', fsetWin),
    'Windows Step 1: unlocks windows-custom-binary-triage');
  const winCmd = fillCmd('windows-custom-binary-triage', 0, fsetWin);
  check(winCmd.includes(winExe), 'Windows Step 1: fills {{custom_bin}} in icacls command (' + winCmd + ')');

  // Step 2: ilspycmd decompiled .NET C# showing Process.Start + DllImport
  const customDll = randId(' native_hook').trim() + '.dll';
  const ilspyOut = [
    'using System;',
    'using System.Diagnostics;',
    'using System.Runtime.InteropServices;',
    'namespace WorkerCore {',
    '    public class Runner {',
    '        [DllImport("' + customDll + '")]',
    '        public static extern int RunCheck();',
    '        public void Tick() {',
    '            Process.Start("rotate_logs.bat", "--silent");',
    '        }',
    '    }',
    '}'
  ].join('\n');
  const resWin2 = parseOut('ilspycmd ./Worker.exe', ilspyOut);
  check(resWin2.facts.some((f) => f.kind === 'privesc.path_hijack_candidate'),
    'Windows Step 2: ilspycmd relative Process.Start mints privesc.path_hijack_candidate');
  check(resWin2.facts.some((f) => f.kind === 'privesc.library_or_script_hijack'),
    'Windows Step 2: ilspycmd non-system [DllImport] mints privesc.library_or_script_hijack');
  check(resWin2.facts.some((f) => f.kind === 'privesc.dll_hijack_candidate'),
    'Windows Step 2: custom .dll dependency also mints privesc.dll_hijack_candidate');

  const fsetWin2 = makeFactSet(resWin1.facts.concat(resWin2.facts));
  check(isRetired('windows-custom-binary-triage', fsetWin2),
    'Windows Step 2: retires windows-custom-binary-triage');
  check(isReady('windows-dll-hijack', fsetWin2),
    'Windows Step 2: unlocks windows-dll-hijack');
}

// --- 3. Disclosed Web Source & Dependency Manifest Triage (Step 1 + Step 2) ---
{
  const appSlug = randId('webapp');
  const traceOut = [
    'HTTP/1.1 500 Internal Server Error',
    'Content-Type: text/plain',
    '',
    'Traceback (most recent call last):',
    '  File "/srv/' + appSlug + '/app/views/report.py", line 58, in render_export',
    '    raise RuntimeError("Invalid export template")',
    'RuntimeError: Invalid export template'
  ].join('\n');
  const traceRes = parseOut('curl -si http://198.51.100.77/export', traceOut);
  const disc = traceRes.facts.find((f) => f.kind === 'web.source_disclosed');
  check(!!disc, 'Web Step 1 (500 trace): stack trace leaking server path mints web.source_disclosed');

  const fsetTrace = makeFactSet(traceRes.facts);
  check(isReady('web-source-sink-audit', fsetTrace), 'Web Step 1: unlocks web-source-sink-audit');
  const auditCmd = fillCmd('web-source-sink-audit', 0, fsetTrace);
  check(auditCmd.includes('/srv/' + appSlug), 'Web Step 1: populates {{source_path}} from stack trace (' + auditCmd + ')');

  // Manifests: package.json, composer.json, requirements.txt, pom.xml
  const pkgJson = JSON.stringify({
    name: appSlug,
    version: '1.0.0',
    dependencies: {
      express: '4.17.1',
      'node-serialize': '0.0.4',
      mongoose: '6.8.0'
    }
  }, null, 2);
  const pkgRes = parseOut('curl -s http://198.51.100.77/package.json', pkgJson);
  const mf = pkgRes.facts.find((f) => f.kind === 'web.manifest_disclosed');
  check(!!mf && mf.value.manifest_type === 'package.json' && mf.value.count >= 3,
    'Web Step 1 (package.json): mints web.manifest_disclosed with parsed dependency versions');

  const reqTxt = 'Flask==2.2.2\nPyYAML==5.3.1\nJinja2>=3.1.0\n';
  const reqRes = parseOut('curl -s http://198.51.100.77/requirements.txt', reqTxt);
  check(reqRes.facts.some((f) => f.kind === 'web.manifest_disclosed' && f.value.manifest_type === 'requirements.txt'),
    'Web Step 1 (requirements.txt): mints web.manifest_disclosed');

  // Step 2a: Concrete DB credentials + JWT secrets from disclosed source
  const dbUser1 = randId('dbusr');
  const dbPass1 = 'P@ss_' + randId('Alpha') + '!';
  const dbUser2 = randId('pgusr');
  const dbPass2 = 'Pg_' + randId('Bravo') + '#9';
  const jwtKey = 'JwtSecret_' + randId('Key') + '_2026';

  const phpAndNodeSource = [
    '<?php',
    '$db_user = "' + dbUser1 + '";',
    '$db_pass = "' + dbPass1 + '";',
    '$pdo = new PDO("mysql:host=127.0.0.1;dbname=portal", $db_user, $db_pass);',
    'if (strcmp($_POST["password"], $admin_token) == 0) { $_SESSION["admin"] = true; }',
    '$out = shell_exec("ping -c 1 " . $_GET["host"]);',
    '?>',
    '// Node config snippet:',
    'const DATABASE_URL = "postgres://' + dbUser2 + ':' + dbPass2 + '@127.0.0.1:5432/analytics";',
    'const token = jwt.sign({ role: "user" }, "' + jwtKey + '");',
    'app.post("/api/login", async (req, res) => { const u = await db.collection("users").findOne(req.body); });'
  ].join('\n');

  const srcRes = parseOut('curl -s http://198.51.100.77/src_dump', phpAndNodeSource);
  const creds = srcRes.facts.filter((f) => f.kind === 'credential.available');
  check(creds.some((f) => f.value.user === dbUser1 && f.value.password === dbPass1),
    'Web Step 2a: resolves PHP $var assignments in new PDO(...) to mint credential.available (' + dbUser1 + ')');
  check(creds.some((f) => f.value.user === dbUser2 && f.value.password === dbPass2),
    'Web Step 2a: extracts postgres:// URI credentials to mint credential.available (' + dbUser2 + ')');
  check(srcRes.facts.some((f) => f.kind === 'web.jwt_secret' && f.value.secret === jwtKey),
    'Web Step 2a: extracts jwt.sign() secret to mint web.jwt_secret');

  // Standalone mysqli_connect & SqlConnection (without separate $db_pass variable)
  const dbUser3 = randId('myusr');
  const dbPass3 = 'My_' + randId('Charlie') + '$7';
  const standaloneMysqli = parseOut('cat db.php', '<?php $c = mysqli_connect("127.0.0.1", "' + dbUser3 + '", "' + dbPass3 + '", "app"); ?>');
  check(standaloneMysqli.facts.some((f) => f.kind === 'credential.available' && f.value.user === dbUser3 && f.value.password === dbPass3),
    'Web Step 2a: standalone mysqli_connect(...) mints credential.available');

  const dbUser4 = randId('sqlusr');
  const dbPass4 = 'Sq_' + randId('Delta') + '%5';
  const standaloneAdo = parseOut('cat Startup.cs', 'using var conn = new SqlConnection("Server=127.0.0.1;Database=Billing;User Id=' + dbUser4 + ';Password=' + dbPass4 + ';");');
  check(standaloneAdo.facts.some((f) => f.kind === 'credential.available' && f.value.user === dbUser4 && f.value.password === dbPass4),
    'Web Step 2a: standalone SqlConnection(...) mints credential.available');

  // Step 2b: Server-side vulnerability sinks
  const sinks = srcRes.facts.filter((f) => f.kind === 'web.vuln_sink');
  check(sinks.length >= 1 && srcRes.facts.some((f) => f.kind === 'vuln.web_sink'),
    'Web Step 2b: mints web.vuln_sink + vuln.web_sink from disclosed code');
  const allCats = [];
  sinks.forEach((f) => {
    if (f.value.category) allCats.push(f.value.category);
    (f.value.sinks || []).forEach((s) => { if (s.category) allCats.push(s.category); });
  });
  check(allCats.includes('cmdi'), 'Web Step 2b: detects server-side command execution sink (shell_exec)');
  check(allCats.includes('type_juggling'), 'Web Step 2b: detects PHP loose/strcmp authentication sink');
  check(allCats.includes('nosql_injection'), 'Web Step 2b: detects raw NoSQL findOne(req.body) sink');

  // Python deserialization sink
  const pyDeserSrc = [
    'from flask import Flask, request',
    'import pickle, base64, yaml',
    '@app.route("/import", methods=["POST"])',
    'def do_import():',
    '    obj = pickle.loads(base64.b64decode(request.form["blob"]))',
    '    cfg = yaml.load(request.form["cfg"])',
    '    return "ok"'
  ].join('\n');
  const pyRes = parseOut('curl -s http://198.51.100.77/app.py', pyDeserSrc);
  check(pyRes.facts.some((f) => f.kind === 'web.vuln_sink' && (f.value.category === 'deserialization' || (f.value.sinks || []).some((s) => s.category === 'deserialization'))),
    'Web Step 2b: detects Python pickle.loads / unsafe yaml.load deserialization sinks');

  const fsetWeb2 = makeFactSet(traceRes.facts.concat(srcRes.facts));
  check(isRetired('web-source-sink-audit', fsetWeb2),
    'Web Step 2b: web.vuln_sink retires web-source-sink-audit');
  check(isReady('web-vuln-sink-exploit', fsetWeb2),
    'Web Step 2b: unlocks web-vuln-sink-exploit');
}

console.log('PASSED: ' + passed + ' checks in custom-artifact-triage-smoke.js');
