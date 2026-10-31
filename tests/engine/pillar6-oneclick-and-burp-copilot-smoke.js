/* Pillar 6 smoke & regression tests:
 *  6.1 Pivot priority (pivot-ligolo #1 default, pivot-sshuttle #1 with Linux SSH creds) + automatic SOCKS proxychains4 / nmap -sT -Pn -n wrapping + unwrap toggle.
 *  6.2 Guided two-terminal sequence micro-stepper (STEP 1 OF 2 ON KALI TERMINAL 1 -> STEP 2 OF 2 ON TARGET SHELL) + auto-advance after Step 1 paste.
 *  6.3 OPTIONAL (alt: true) tool isolation + immediate Command #1 fallback rotation after paste/Ran - Nothing Found.
 *  6.4 Flagless Exploit-DB safe working-copy (<id>_obol.py) sed auto-patcher + Burp proxy strip.
 *  6.5 Calm 1-line "What to paste back" hint on listener / server commands.
 *  6.6 Tier A HTML <form> + CSRF extraction & curl auto-wiring + History HTML collapse, and Tier B Burp Suite Repeater Co-Pilot (3-state SVG instrument, Smart Auto-Open, mutation + equivalent curl, and #/workbench/burp).
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
load('assets/ui/util.js');
load('assets/ui/icons.js');
load('assets/ui/store.js');
load('assets/engine/parsers/common.js');
[
  'nmap', 'directory', 'creds', 'host', 'web', 'services', 'database',
  'websource', 'findings', 'shape', 'inference', 'edb', 'pivot', 'dns',
  'blockers', 'nxc-catalog', 'index'
].forEach(name => load('assets/engine/parsers/' + name + '.js'));
load('assets/ui/ingest.js');
load('assets/ui/burp-copilot.js');

const O = sandbox.OBOL;
const S = O.store;
const F = O.facts;
const packData = O.pack.PACK_NAMES.map(name =>
  JSON.parse(fs.readFileSync(path.join(ROOT, 'data/packs', name + '.json'), 'utf8'))
);
const actions = O.pack.loadPacks(packData);
O.packs = { actions: () => actions };
O.routes = {};
O.router = { render() {} };
load('assets/ui/routes/path.js');
load('assets/ui/routes/workbench.js');
load('assets/ui/routes/history.js');

const HOST_EDGE = '198.51.100.10';
const HOST_INTERNAL = '172.31.88.25';
const HOST_WEB = '203.0.113.5';

let checks = 0;
function ok(cond, msg) {
  assert.ok(cond, msg);
  checks++;
}

function mkFact(kind, target, value = {}, source = 'pillar6-smoke') {
  return F.makeFact({ kind, scope: 'host:' + target, state: 'supported', value, source });
}

function ingest(target, command, text, actionId = '', extra = {}) {
  return O.ingest.run(Object.assign({
    command,
    text,
    scope: 'host:' + target,
    actionId,
    source: 'paste',
    quiet: true
  }, extra));
}

function findAction(id) {
  return actions.find(a => a.id === id);
}

function setParams(p) {
  S.update(eng => {
    eng.params = Object.assign(eng.params || {}, p);
  }, 'params');
}

function addTarget(t) {
  S.update(eng => {
    eng.targets = eng.targets || [];
    if (!eng.targets.some(x => x.ip === t.ip)) eng.targets.push(t);
  }, 'targets');
}

function setActiveTarget(ip) {
  if (typeof S.setActiveTarget === 'function') S.setActiveTarget(ip);
  else S.update(eng => { eng.activeTarget = ip; }, 'targets');
}

(async () => {
  // =========================================================================
  // 1. Pillar 6.1: Pivot Priority (Ligolo #1 default, Sshuttle #1 Linux+SSH)
  // =========================================================================
  await S.createEngagement('Pillar 6 smoke section');
  setParams({ target: HOST_EDGE, lhost: '198.51.100.99', lport: '4444' });
  S.update(eng => { eng.ui = Object.assign(eng.ui || {}, { wsScaffoldDone: true }); }, 'ui');
  addTarget({ ip: HOST_EDGE, label: 'Edge Pivot' });
  setActiveTarget(HOST_EDGE);
  S.addFacts([
    mkFact('host.up', HOST_EDGE),
    mkFact('foothold.windows', HOST_EDGE),
    mkFact('access.shell', HOST_EDGE),
    mkFact('host.multihomed', HOST_EDGE, { subnets: ['172.31.88.0/24'] })
  ]);
  S.setChecklist('flag-hunt-windows', 'done');
  S.setChecklist('flag-hunt-root-windows', 'done');

  let edgeFacts = S.factSetForTarget(HOST_EDGE);
  let rankedDefault = O.pack.rankActions(edgeFacts, actions, S.active());
  let pivotRankedDefault = rankedDefault.filter(a => /^pivot-(?:ligolo|chisel-socks|sshuttle)$/.test(a.id));
  ok(pivotRankedDefault.length >= 2, 'Expected pivot moves to be ready on dual-homed Windows foothold');
  ok(pivotRankedDefault[0].id === 'pivot-ligolo',
    'Expected pivot-ligolo #1 by default on multihomed host, got: ' + pivotRankedDefault.map(a => a.id).join(', '));

  // Now test Linux foothold + SSH surface + SSH credential -> pivot-sshuttle promoted to #1
  await S.createEngagement('Pillar 6 smoke section');
  setParams({ target: HOST_EDGE, lhost: '198.51.100.99' });
  S.update(eng => { eng.ui = Object.assign(eng.ui || {}, { wsScaffoldDone: true }); }, 'ui');
  addTarget({ ip: HOST_EDGE, label: 'Linux SSH Pivot' });
  setActiveTarget(HOST_EDGE);
  S.addFacts([
    mkFact('host.up', HOST_EDGE),
    mkFact('foothold.linux', HOST_EDGE),
    mkFact('access.shell', HOST_EDGE),
    mkFact('port:22', HOST_EDGE),
    mkFact('service.ssh', HOST_EDGE),
    mkFact('credential.available', HOST_EDGE, { user: 'ops', secret: 'SynthPass2026!', kind: 'password' }),
    mkFact('ssh.authenticated', HOST_EDGE, { user: 'ops' }),
    mkFact('host.multihomed', HOST_EDGE, { subnets: ['172.31.88.0/24'] })
  ]);
  S.setChecklist('flag-hunt-windows', 'done');
  S.setChecklist('flag-hunt-root-windows', 'done');
  ingest(
    HOST_EDGE,
    'ip -4 a',
    [
      '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500',
      '    inet ' + HOST_EDGE + '/24 scope global eth0',
      '3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500',
      '    inet 172.31.88.10/24 scope global eth1'
    ].join('\n'),
    'local-net-enum'
  );
  let linuxSshFacts = S.factSetForTarget(HOST_EDGE);
  let rankedSsh = O.pack.rankActions(linuxSshFacts, actions, S.active());
  let pivotRankedSsh = rankedSsh.filter(a => /^pivot-(?:ligolo|chisel-socks|sshuttle)$/.test(a.id));
  ok(pivotRankedSsh[0].id === 'pivot-sshuttle',
    'Expected pivot-sshuttle #1 when Linux foothold + SSH + creds exist, got: ' + pivotRankedSsh.map(a => a.id).join(', '));

  // =========================================================================
  // 2. Pillar 6.1: Automatic SOCKS proxychains4 & nmap -sT -Pn -n wrapping
  // =========================================================================
  addTarget({ ip: HOST_INTERNAL, label: 'Internal Host B' });
  // Active SOCKS tunnel on HOST_EDGE (no route tunnel yet) -> HOST_INTERNAL gets tunnelKind === 'socks'
  S.addFacts([
    mkFact('tunnel.socks', HOST_EDGE, { port: 1080, tool: 'chisel' }),
    mkFact('pivot.active', HOST_EDGE, { via: 'chisel-socks' }),
    mkFact('host.up', HOST_INTERNAL),
    mkFact('ports.open', HOST_INTERNAL),
    mkFact('port:445', HOST_INTERNAL),
    mkFact('service.smb', HOST_INTERNAL)
  ]);

  let internalFacts = S.factSetForTarget(HOST_INTERNAL);
  let pivVals = internalFacts.values('tunnel.reachable_via_pivot') || [];
  ok(pivVals.length > 0 && pivVals[0].tunnelKind === 'socks',
    'Expected tunnel.reachable_via_pivot with tunnelKind=socks on internal Host B');

  const nmapQuick = findAction('nmap-fast-open-ports');
  let filledNmapSocks = O.command.fillCommand(nmapQuick, internalFacts, { params: { target: HOST_INTERNAL } }, 0);
  ok(filledNmapSocks.socksAvailable && filledNmapSocks.socksWrapped,
    'Expected nmap on SOCKS-only Host B to have socksAvailable=true and socksWrapped=true');
  ok(/^proxychains4 -q nmap\b/.test(filledNmapSocks.filled)
    && /\s-sT\b/.test(filledNmapSocks.filled)
    && /\s-Pn\b/.test(filledNmapSocks.filled)
    && /\s-n\b/.test(filledNmapSocks.filled)
    && !/\bsudo\b/.test(filledNmapSocks.filled),
    'Expected SOCKS nmap to rewrite to proxychains4 -q nmap -n -Pn -sT without sudo, got: ' + filledNmapSocks.filled);

  // Test unwrapSocks toggle
  let filledNmapUnwrapped = O.command.fillCommand(nmapQuick, internalFacts, { params: { target: HOST_INTERNAL }, unwrapSocks: true }, 0);
  ok(filledNmapUnwrapped.socksAvailable && !filledNmapUnwrapped.socksWrapped,
    'Expected unwrapSocks:true to expose unwrapped command while keeping socksAvailable:true');
  ok(!/^proxychains4\b/.test(filledNmapUnwrapped.filled),
    'Expected unwrapped command not to start with proxychains4, got: ' + filledNmapUnwrapped.filled);

  // Once a direct TUN/route tunnel (ligolo/sshuttle) is active on HOST_EDGE, tunnelKind becomes 'route' -> NO proxychains4 wrap!
  S.addFacts([mkFact('tunnel.route', HOST_EDGE, { subnet: '172.31.88.0/24', tool: 'ligolo' })]);
  let internalRouteFacts = S.factSetForTarget(HOST_INTERNAL);
  let filledNmapRoute = O.command.fillCommand(nmapQuick, internalRouteFacts, { params: { target: HOST_INTERNAL } }, 0);
  ok(!filledNmapRoute.socksWrapped && !/^proxychains4\b/.test(filledNmapRoute.filled),
    'Expected direct route tunnel (ligolo/sshuttle) NOT to wrap commands in proxychains4');

  // =========================================================================
  // 3. Pillar 6.2 & 6.5: Guided Sequence Micro-Stepper + Calm Listener Hint
  // =========================================================================
  await S.createEngagement('Pillar 6 smoke section');
  setParams({ target: HOST_EDGE, lhost: '198.51.100.99' });
  S.update(eng => { eng.ui = Object.assign(eng.ui || {}, { wsScaffoldDone: true }); }, 'ui');
  addTarget({ ip: HOST_EDGE, label: 'Pivot Stepper Host' });
  addTarget({ ip: HOST_INTERNAL, label: 'Internal Target' });
  setActiveTarget(HOST_EDGE);
  S.addFacts([
    mkFact('host.up', HOST_EDGE),
    mkFact('foothold.windows', HOST_EDGE),
    mkFact('access.shell', HOST_EDGE),
    mkFact('access.system', HOST_EDGE),
    mkFact('objective.flag.local', HOST_EDGE, { value: 'a'.repeat(32) }),
    mkFact('objective.flag.root', HOST_EDGE, { value: 'b'.repeat(32) }),
    mkFact('host.multihomed', HOST_EDGE, { subnets: ['172.31.88.0/24'] })
  ]);
  S.setChecklist('flag-hunt-windows', 'done');
  S.setChecklist('flag-hunt-root-windows', 'done');

  sandbox.sessionStorage.setItem('obol.campaign', 'lateral-pivot');
  let pathHtmlStep1 = O.routes.path.render({ target: HOST_EDGE });
  ok(pathHtmlStep1.includes('STEP 1 OF 2') && pathHtmlStep1.includes('ON KALI TERMINAL 1'),
    'Expected Guided Micro-Stepper to render STEP 1 OF 2 · ON KALI TERMINAL 1 on pivot-ligolo; cards: ' + JSON.stringify(pathHtmlStep1.match(/selected[^>]*data-action="[^"]+"/g)));
  ok(pathHtmlStep1.includes('Step 1 Running -&gt; Show Step 2'),
    'Expected [Step 1 Running -> Show Step 2] advance button in stepper');
  ok(pathHtmlStep1.includes('Show all 2 steps'),
    'Expected searchable <details> "Show all 2 steps" peek link under stepper');
  ok(pathHtmlStep1.includes('What to paste back:'),
    'Expected calm 1-line "What to paste back:" listener hint on Step 1 ligolo-proxy command');

  // 3a. Clicking [Step 1 Running -> Show Step 2] switches stepper to STEP 2 OF 2 · ON TARGET SHELL
  S.update(eng => {
    eng.ui = eng.ui || {};
    eng.ui.seqStepByAction = { 'pivot-ligolo': 1 };
  }, 'ui');
  let pathHtmlBtnStep2 = O.routes.path.render({ target: HOST_EDGE });
  ok(pathHtmlBtnStep2.includes('STEP 2 OF 2') && pathHtmlBtnStep2.includes('ON TARGET SHELL'),
    'Expected [Step 1 Running -> Show Step 2] state to render STEP 2 OF 2 · ON TARGET SHELL');

  // 3b. Auto-advance when Step 1 output is pasted on a sequence:true move before final settlement (pivot-chisel-socks Step 1 server banner -> Step 2 target client)
  S.update(eng => { delete eng.ui.seqStepByAction; }, 'ui');
  S.setChecklist('pivot-ligolo', 'done');
  let pathChiselStep1 = O.routes.path.render({ target: HOST_EDGE });
  ok(pathChiselStep1.includes('chisel server -p 8080 --reverse') && pathChiselStep1.includes('STEP 1 OF 2'),
    'Expected pivot-chisel-socks to start on STEP 1 OF 2 · ON KALI TERMINAL 1');
  const chiselMove = findAction('pivot-chisel-socks');
  const chiselStep1Filled = O.command.fillCommand(chiselMove, S.factSetForTarget(HOST_EDGE), { params: S.active().params }, 0).filled;
  ingest(HOST_EDGE, chiselStep1Filled, '2026/10/31 12:00:00 server: Reverse tunnelling enabled\n2026/10/31 12:00:00 server: Listening on http://0.0.0.0:8080', 'pivot-chisel-socks', {
    locus: 'remote',
    commandObj: chiselMove.commands[0]
  });
  let pathHtmlStep2 = O.routes.path.render({ target: HOST_EDGE });
  ok(pathHtmlStep2.includes('STEP 2 OF 2') && pathHtmlStep2.includes('ON TARGET SHELL') && pathHtmlStep2.includes('R:socks'),
    'Expected Guided Micro-Stepper to auto-advance to STEP 2 OF 2 · ON TARGET SHELL after Step 1 server output paste');

  // 3c. Scope guard: ordered-alternative catalogs with sequence:true (flag-hunt-windows, bloodhound-collect) keep locus toggle and normal command list
  ok(O.pack.isGuidedSequenceMove(findAction('pivot-ligolo')) && O.pack.isGuidedSequenceMove(findAction('pivot-chisel-socks')),
    'Expected isGuidedSequenceMove=true for two-terminal pivot moves');
  ok(!O.pack.isGuidedSequenceMove(findAction('flag-hunt-windows')) && !O.pack.isGuidedSequenceMove(findAction('bloodhound-collect')),
    'Expected isGuidedSequenceMove=false for ordered-alternative catalog moves');
  sandbox.sessionStorage.setItem('obol.campaign', 'all');

  // =========================================================================
  // 4. Pillar 6.3: OPTIONAL alt:true Isolation & Immediate Command #1 Fallback
  // =========================================================================
  const contentDisc = findAction('content-discovery');
  ok(contentDisc.commands[3].alt === true && contentDisc.commands[4].alt === true,
    'Expected content-discovery cewl/eyewitness commands to be tagged alt:true');
  ok(nmapQuick.commands[1].alt === true && nmapQuick.commands[2].alt === true,
    'Expected nmap-fast-open-ports rustscan/masscan commands to be tagged alt:true');

  // Verify immediate Command #1 fallback rotation on a multi-command move when Command #1 returns nothing found
  await S.createEngagement('Pillar 6 smoke section');
  setParams({ target: HOST_WEB, lhost: '198.51.100.99' });
  S.update(eng => { eng.ui = Object.assign(eng.ui || {}, { wsScaffoldDone: true }); }, 'ui');
  addTarget({ ip: HOST_WEB, label: 'Web Fallback Host' });
  setActiveTarget(HOST_WEB);
  S.addFacts([
    mkFact('host.up', HOST_WEB),
    mkFact('ports.open', HOST_WEB),
    mkFact('port:80', HOST_WEB),
    mkFact('service.http', HOST_WEB),
    mkFact('web.surface', HOST_WEB),
    mkFact('web.params', HOST_WEB, { params: ['page'] })
  ]);
  const lfiMove = findAction('lfi-probe');
  let webFacts0 = S.factSetForTarget(HOST_WEB);
  let cmd0Before = O.command.fillCommand(lfiMove, webFacts0, { params: S.active().params }, 0).filled;
  // Select lfi-probe in Cockpit and verify Command 0 is active
  let idxBefore = O.pack.preferredCommandIndex(lfiMove, 'remote', webFacts0, () => false, () => false);
  ok(idxBefore === 0, 'Expected lfi-probe to start at Command index 0');
  // Record Ran - Nothing Found on Command 0
  ingest(HOST_WEB, cmd0Before, '[OBOL: completed with no output / nothing found]', 'lfi-probe', {
    locus: 'remote',
    commandObj: lfiMove.commands[0]
  });
  let curEpoch = O.pack.accessEpoch(S.factSetForTarget(HOST_WEB));
  let idxAfter = O.pack.preferredCommandIndex(
    lfiMove,
    'remote',
    S.factSetForTarget(HOST_WEB),
    () => false,
    (cmd, i) => {
      const f = O.command.fillCommand(lfiMove, S.factSetForTarget(HOST_WEB), { params: S.active().params }, i);
      return O.command.commandTriedInEpoch(lfiMove, cmd, f.filled, S.active().activities, curEpoch, HOST_WEB);
    }
  );
  ok(idxAfter === 1, 'Expected immediate fallback rotation from Command 0 to Command 1 after Ran - Nothing Found, got: ' + idxAfter);

  // Verify OPTIONAL (alt: true) commands are NOT promoted ahead of untried primary commands
  let altTestIdx = O.pack.preferredCommandIndex(
    contentDisc,
    'remote',
    S.factSetForTarget(HOST_WEB),
    () => false,
    (_cmd, i) => i < 3 // primary 0,1,2 tried; 3,4 are alt:true
  );
  ok(altTestIdx === 3, 'Expected alt:true commands to serve only as last-resort fallback once all non-alt commands are tried');
  let primaryPreferredIdx = O.pack.preferredCommandIndex(
    contentDisc,
    'remote',
    S.factSetForTarget(HOST_WEB),
    () => false,
    (_cmd, i) => i === 0 // only cmd 0 tried; non-alt cmd 1 should be chosen before alt cmd 3
  );
  ok(primaryPreferredIdx === 1, 'Expected non-alt primary fallback (index 1) to beat alt:true commands');

  // =========================================================================
  // 5. Pillar 6.4: Flagless Exploit-DB Safe Working Copy (<id>_obol.py) Patcher
  // =========================================================================
  await S.createEngagement('Pillar 6 smoke section');
  setParams({ target: HOST_WEB, lhost: '198.51.100.99', lport: '4444' });
  addTarget({ ip: HOST_WEB, label: 'EDB Target' });
  setActiveTarget(HOST_WEB);
  S.addFacts([
    mkFact('host.up', HOST_WEB),
    mkFact('port:8080', HOST_WEB),
    mkFact('service.http', HOST_WEB),
    mkFact('exploit.candidate', HOST_WEB, { edb_id: '50383', path: '/usr/share/exploitdb/exploits/php/webapps/50383.py', lang: 'python' })
  ]);

  const flaglessScript = [
    '#!/usr/bin/env python3',
    'import requests',
    'RHOST = "192.168.1.50"',
    'RPORT = 8080',
    'LHOST = "192.168.1.99"',
    'LPORT = 9001',
    'proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}',
    'requests.get(f"http://{RHOST}:{RPORT}/shell", proxies=proxies)'
  ].join('\n');

  let edbIngest = ingest(HOST_WEB, 'head -n 60 50383.py', flaglessScript, 'edb-inspect-exploit');
  let inspectedFact = (edbIngest.facts || []).find(f => f.kind === 'exploit.script_inspected');
  ok(inspectedFact && inspectedFact.value && inspectedFact.value.patch_plan && inspectedFact.value.patch_plan.needs_patch,
    'Expected edb.js to emit exploit.script_inspected with patch_plan.needs_patch=true on flagless script');

  const edbAdaptMove = findAction('edb-run-adapted-exploit');
  let edbCmd0 = O.command.fillCommand(edbAdaptMove, S.factSetForTarget(HOST_WEB), { params: S.active().params }, 0);
  ok(edbCmd0.filled.includes('cp ') && edbCmd0.filled.includes('50383_obol.py') && edbCmd0.filled.includes('sed -i -E'),
    'Expected edb-run-adapted-exploit Command #1 to copy to 50383_obol.py and sed-patch in one shot, got: ' + edbCmd0.filled);
  ok(edbCmd0.filled.includes('proxies = {}') && edbCmd0.filled.includes('python3 ') && edbCmd0.filled.endsWith('50383_obol.py'),
    'Expected sed auto-patcher to neutralize hardcoded Burp proxies={} and execute 50383_obol.py');
  ok(edbCmd0.edbPatchSummary && edbCmd0.edbPatchSummary.includes('50383_obol.py'),
    'Expected 1-line edbPatchSummary badge metadata on patched Exploit-DB command');

  // =========================================================================
  // 6. Pillar 6.6 Tier A: HTML <form> + Hidden CSRF Extraction & curl Wiring
  // =========================================================================
  await S.createEngagement('Pillar 6 smoke section');
  setParams({ target: HOST_WEB, lhost: '198.51.100.99' });
  S.update(eng => { eng.ui = Object.assign(eng.ui || {}, { wsScaffoldDone: true }); }, 'ui');
  addTarget({ ip: HOST_WEB, label: 'Web App Host' });
  setActiveTarget(HOST_WEB);
  S.addFacts([
    mkFact('host.up', HOST_WEB),
    mkFact('ports.open', HOST_WEB),
    mkFact('port:80', HOST_WEB),
    mkFact('service.http', HOST_WEB),
    mkFact('web.surface', HOST_WEB)
  ]);

  const htmlResponse = [
    'HTTP/1.1 200 OK',
    'Content-Type: text/html; charset=UTF-8',
    'Set-Cookie: PHPSESSID=synthcookie9988; Path=/',
    '',
    '<!DOCTYPE html>',
    '<html><body>',
    '<form action="/portal/search.php" method="POST">',
    '  <input type="hidden" name="csrf_token" value="tok_99aabbccdd">',
    '  <input type="text" name="query" value="">',
    '  <input type="submit" value="Search">',
    '</form>',
    '<form action="/portal/upload.php" method="POST" enctype="multipart/form-data">',
    '  <input type="hidden" name="_token" value="up_csrf_7711">',
    '  <input type="file" name="avatar">',
    '</form>',
    '</body></html>'
  ].join('\n');

  let formIngest = ingest(HOST_WEB, 'curl -skL -i -c loot/cookies.txt -b loot/cookies.txt http://' + HOST_WEB + '/', htmlResponse, 'recon-web-triage');
  let formsFact = (formIngest.facts || []).find(f => f.kind === 'web.forms_discovered');
  ok(formsFact && Array.isArray(formsFact.value.forms) && formsFact.value.forms.length === 2,
    'Expected websource.js to extract both HTML <form> definitions into web.forms_discovered');
  ok(formsFact.value.forms[0].hasCsrf && formsFact.value.forms[0].csrfFields[0].value === 'tok_99aabbccdd',
    'Expected hidden csrf_token value to be captured from form 0');
  ok(formsFact.value.forms[1].isMultipart && formsFact.value.forms[1].hasFile,
    'Expected multipart file-upload form 1 to be flagged isMultipart & hasFile');

  // Verify downstream sqli-basics Command #1 auto-wires action, POST method, query field, csrf_token, and cookie jar!
  const sqliMove = findAction('sqli-basics');
  let sqliCmd0 = O.command.fillCommand(sqliMove, S.factSetForTarget(HOST_WEB), { params: S.active().params }, 0);
  ok(sqliCmd0.filled.includes('/portal/search.php')
    && sqliCmd0.filled.includes('-X POST')
    && sqliCmd0.filled.includes('query=')
    && sqliCmd0.filled.includes('csrf_token=tok_99aabbccdd')
    && sqliCmd0.filled.includes('cookies.txt'),
    'Expected sqli-basics Command #1 to auto-wire form action, POST, query field, hidden CSRF token, and cookie jar, got: ' + sqliCmd0.filled);

  // Verify downstream file-upload Command #1 auto-wires multipart form action, file field avatar, and _token CSRF!
  const uploadMove = findAction('file-upload');
  let uploadCmd0 = O.command.fillCommand(uploadMove, S.factSetForTarget(HOST_WEB), { params: S.active().params }, 0);
  ok(uploadCmd0.filled.includes('/portal/upload.php')
    && uploadCmd0.filled.includes('avatar=@')
    && uploadCmd0.filled.includes('_token=up_csrf_7711'),
    'Expected file-upload Command #1 to auto-wire /portal/upload.php, avatar=@, and _token CSRF, got: ' + uploadCmd0.filled);

  // Verify History route collapses raw pasted HTML inside <details class="hl-out html-collapse">
  let histHtml = O.routes.history.render();
  ok(histHtml.includes('html-collapse') && histHtml.includes('HTML response body - collapsed'),
    'Expected #/history to collapse raw pasted HTML bodies inside <details class="hl-out html-collapse">');

  // Verify Smart Auto-Open stays on Pillar 1 (CLI lead) when runnable HTML forms exist and no raw Burp request was pasted yet
  ok(O.burpCopilot.shouldAutoOpen(sqliMove, S.factSetForTarget(HOST_WEB), S.active(), HOST_WEB) === false,
    'Expected Smart Auto-Open to stay FALSE (lead with 1-click CLI curl) when runnable HTML forms exist and no raw Burp request was pasted');

  // =========================================================================
  // 7. Pillar 6.6 Tier B: Raw Burp Request Capture + 3-State SVG Co-Pilot
  // =========================================================================
  const rawBurpReq = [
    'POST /portal/upload.php HTTP/1.1',
    'Host: ' + HOST_WEB,
    'Cookie: PHPSESSID=synthcookie9988',
    'Content-Type: multipart/form-data; boundary=obol_synth_5511',
    '',
    '--obol_synth_5511',
    'Content-Disposition: form-data; name="avatar"; filename="photo.png"',
    'Content-Type: image/png',
    '',
    'PNGDATA',
    '--obol_synth_5511--'
  ].join('\r\n');

  let burpIngest = ingest(HOST_WEB, '', rawBurpReq, 'file-upload');
  let capFact = (burpIngest.facts || []).find(f => f.kind === 'web.http_request_captured');
  ok(capFact && capFact.value.method === 'POST' && capFact.value.pathname === '/portal/upload.php',
    'Expected web.js to parse raw Burp HTTP request into web.http_request_captured');
  ok(Array.isArray(S.active().webRequests[HOST_WEB]) && S.active().webRequests[HOST_WEB].length === 1,
    'Expected store.js to persist captured raw HTTP request in eng.webRequests[targetIp]');

  // Now Smart Auto-Open MUST return true because a raw Burp request was pasted for HOST_WEB!
  ok(O.burpCopilot.shouldAutoOpen(uploadMove, S.factSetForTarget(HOST_WEB), S.active(), HOST_WEB) === true,
    'Expected Smart Auto-Open to activate [ Burp Co-Pilot ] once a raw Burp HTTP request is captured for target');

  let copilotPanelHtml = O.burpCopilot.renderPanel({
    targetIp: HOST_WEB,
    move: uploadMove,
    facts: S.factSetForTarget(HOST_WEB)
  });
  ok(copilotPanelHtml.includes('<svg class="burp-svg" role="img"')
    && copilotPanelHtml.includes('<title>')
    && copilotPanelHtml.includes('burp-glow-tok')
    && copilotPanelHtml.includes('Copy Mutated Repeater Request')
    && copilotPanelHtml.includes('Copy Equivalent 1-Click curl'),
    'Expected Burp Co-Pilot State 2 to render accessible inline <svg role="img"><title>, <mark class="burp-glow-tok"> highlights, and both Copy buttons');

  // Verify #/workbench/burp persistent route renders cleanly and reads saved requests from eng.webRequests[HOST_WEB]
  let wbBurpHtml = O.routes.workbench.render({ args: ['burp'] });
  ok(wbBurpHtml.includes('Burp Co-Pilot') && wbBurpHtml.includes('/portal/upload.php'),
    'Expected #/workbench/burp to render persistent Burp Co-Pilot backed by eng.webRequests[targetIp]');

  console.log('PASS: pillar6-oneclick-and-burp-copilot-smoke (' + checks + ' assertions)');
})().catch(err => {
  console.error('FAIL:', err);
  process.exit(1);
});
