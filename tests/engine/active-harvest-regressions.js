'use strict';

var assert = require('assert');
var fs = require('fs');
var path = require('path');

var qaRoot = path.resolve(__dirname, '../..');

function loadQaScript(rel) {
  require(path.join(qaRoot, rel));
}

[
  'assets/engine/facts.js',
  'assets/engine/phases.js',
  'assets/engine/pack.js',
  'assets/engine/profile.js',
  'assets/engine/context.js',
  'assets/engine/command.js',
  'assets/engine/workspace.js',
  'assets/engine/vfs.js',
  'assets/engine/loot.js',
  'assets/engine/playbook.js',
  'assets/engine/chain.js',
  'data/findings-catalog.js',
  'data/narratives.js',
  'assets/engine/findings.js',
  'data/packs-bundle.js',
  'data/field-notes.js',
  'assets/engine/packs.js',
  'assets/engine/resolve.js',
  'assets/ui/util.js',
  'assets/ui/store.js',
  'assets/engine/outcomes.js',
  'assets/engine/parsers/common.js',
  'assets/engine/parsers/nmap.js',
  'assets/engine/parsers/directory.js',
  'assets/engine/parsers/creds.js',
  'assets/engine/parsers/host.js',
  'assets/engine/parsers/services.js',
  'assets/engine/parsers/database.js',
  'assets/engine/parsers/web.js',
  'assets/engine/parsers/websource.js',
  'assets/engine/parsers/findings.js',
  'assets/engine/parsers/shape.js',
  'assets/engine/parsers/pivot.js',
  'assets/engine/parsers/dns.js',
  'assets/engine/parsers/blockers.js',
  'assets/engine/parsers/nxc-catalog.js',
  'assets/engine/parsers/inference.js',
  'assets/engine/parsers/index.js',
  'assets/ui/ingest.js'
].forEach(loadQaScript);

var OBOL = globalThis.OBOL;
var harvestPath = path.resolve(qaRoot, '../test-runs/active-10-26/harvest-10.129.117.156-20261026-214827.md');
var raw = fs.readFileSync(harvestPath, 'utf8');

(async function () {
  console.log('--- Testing Active (10.129.117.156) Harvest Regressions ---');
  await OBOL.store.init();

  // 1. Verify splitSession coalesces OBOL STEP markers + $ cmd lines into exactly 19 clean segments
  //    and stops at closing markdown code fences (preventing trailing Markdown table bleed).
  var segs = OBOL.ingest.splitSession(raw);
  assert.strictEqual(segs.length, 19, 'Expected exactly 19 segments (no empty ghost segments)');
  assert.strictEqual(segs[0].actionId, 'nmap-full-tcp', 'Segment 1 should preserve actionId nmap-full-tcp');
  assert.strictEqual(segs[18].actionId, 'rpc-endpoints', 'Segment 19 should preserve actionId rpc-endpoints');
  assert(!/Harvest Execution Index|WrongPass123!/i.test(segs[18].stdout), 'Segment 19 must not include trailing Markdown index table');
  console.log('[PASS] splitSession coalesces OBOL STEP markers into 19 segments and excludes Markdown prose/tables.');

  var results = segs.map(function (s) {
    return OBOL.ingest.run({
      text: s.stdout,
      command: s.command,
      actionId: s.actionId,
      source: 'session-split',
      scope: 'host:10.129.117.156'
    });
  });

  // 2. Verify port 47001/tcp (NetTcpPortSharing HTTPAPI) does NOT mint winrm.reachable or http.reachable
  var fsTarget = OBOL.store.factSetForTarget('10.129.117.156');
  assert.strictEqual(fsTarget.has('winrm.reachable'), false, 'Port 47001 must never mint winrm.reachable');
  assert.strictEqual(fsTarget.has('service.winrm'), false, 'Port 47001 must never mint service.winrm');
  assert.strictEqual(fsTarget.has('http.reachable'), false, 'Port 47001 Not Found title must never mint http.reachable');
  assert.strictEqual(fsTarget.has('service.httpapi'), true, 'Port 47001 should mint service.httpapi');
  console.log('[PASS] Port 47001/tcp mints service.httpapi and never false-positives winrm.reachable or http.reachable.');

  // 3. Verify zero false-positive credentials or usernames from rpcdump named pipes or Markdown tables
  assert.strictEqual(fsTarget.values('credential.username').length, 0, 'Must not mint bogus usernames from \\pipe\\srvsvc or Markdown table');
  assert.strictEqual(fsTarget.values('credential.password').length, 0, 'Must not mint bogus passwords from Markdown table');
  assert.strictEqual(fsTarget.has('ad.user_list'), false, 'Must not mint ad.user_list from rpcdump named pipes');
  console.log('[PASS] Zero false-positive usernames or credentials from rpcdump pipes or Markdown tables.');

  // 4. Verify Step 4 (nxc smb -u guest) does not mint smb.null_session and classifies as rejected
  var step4Kinds = results[3].facts.map(function (f) { return f.kind; });
  assert(step4Kinds.indexOf('smb.null_session') === -1, 'Guest login failure must not mint smb.null_session from banner');
  assert.strictEqual(results[3].outcome.kind, 'rejected', 'Guest STATUS_ACCOUNT_DISABLED should classify as rejected');
  console.log('[PASS] Guest login failure (STATUS_ACCOUNT_DISABLED) does not mint smb.null_session and classifies as rejected.');

  // 5. Verify Step 6 (ad-user-enum), Step 10 (rpcclient), Step 11 (enum4linux-ng) mint blocker.samr_null_denied
  assert.strictEqual(fsTarget.has('blocker.samr_null_denied'), true, 'Unauthenticated SAMR/RID denial must mint blocker.samr_null_denied');
  assert.strictEqual(results[5].outcome.kind, 'authorization-denied', 'Step 6 (ad-user-enum) should classify as authorization-denied');
  assert.strictEqual(results[6].outcome.kind, 'completed-negative', 'Step 7 (ad-pass-pol) should classify as completed-negative');
  console.log('[PASS] Unauthenticated SAMR/RID denial mints blocker.samr_null_denied and ad-pass-pol classifies as completed-negative.');

  // 6. Verify Step 9 (smbmap-anon) and Step 11 (enum4linux-ng) classify as success and discover Replication share
  assert.strictEqual(results[8].outcome.kind, 'success', 'Step 9 (smbmap-anon) should classify as success');
  assert(results[8].blockers.indexOf('blocker.access_denied') === -1, 'Step 9 (smbmap-anon) must not mint blocker.access_denied when readable share found');
  assert.strictEqual(results[10].outcome.kind, 'success', 'Step 11 (enum4linux-ng) should classify as success');
  var enum4Shares = results[10].facts.filter(function (f) { return f.kind === 'smb.readable_share'; });
  assert(enum4Shares.some(function (f) { return f.value && f.value.name === 'Replication'; }), 'enum4linux-ng must extract readable share Replication');
  console.log('[PASS] smbmap-anon and enum4linux-ng classify as success and extract readable share Replication.');

  // 7. Verify Step 13 (ldap-rootdse), Step 15 (ldap-fail-probe), Step 17 (recon-dns), Step 18 (dns-zone-transfer), Step 19 (rpc-endpoints)
  assert.strictEqual(results[12].outcome.kind, 'success', 'Step 13 (ldap-rootdse) must not trigger environment-error on InitRecvTimeout');
  assert.strictEqual(results[14].outcome.kind, 'rejected', 'Step 15 (ldap-fail-probe) should classify as rejected');
  assert(results[14].blockers.indexOf('blocker.logon_failure') >= 0, 'Step 15 (ldap-fail-probe) should mint blocker.logon_failure');
  assert(results[16].facts.some(function (f) { return f.kind === 'dns.reachable'; }), 'Step 17 (recon-dns) should mint dns.reachable from Microsoft DNS version');
  assert.strictEqual(results[17].outcome.kind, 'completed-negative', 'Step 18 (dns-zone-transfer) should classify as completed-negative');
  assert.strictEqual(results[18].outcome.kind, 'success', 'Step 19 (rpc-endpoints) should classify as success');
  assert.strictEqual(fsTarget.has('rpc.endpoints'), true, 'Step 19 (rpc-endpoints) should mint rpc.endpoints');
  console.log('[PASS] LDAP RootDSE, LDAP invalid bind, DNS version, DNS AXFR negative, and rpcdump endpoints all parse and classify cleanly.');

  // 8. Verify ad-user-enum suppresses unauthenticated SAMR/RID commands when blocker.samr_null_denied is active
  var adUserEnum = OBOL.packs.actions().find(function (a) { return a.id === 'ad-user-enum'; });
  assert.strictEqual(OBOL.pack.commandIsEligible(adUserEnum.commands[0], fsTarget, adUserEnum), false, 'nxc --rid-brute null session should be suppressed when blocker.samr_null_denied');
  assert.strictEqual(OBOL.pack.commandIsEligible(adUserEnum.commands[1], fsTarget, adUserEnum), true, 'kerbrute userenum should remain eligible when blocker.samr_null_denied');
  assert.strictEqual(OBOL.pack.commandIsEligible(adUserEnum.commands[2], fsTarget, adUserEnum), false, 'enum4linux -U should be suppressed when blocker.samr_null_denied');
  assert.strictEqual(OBOL.pack.commandIsEligible(adUserEnum.commands[3], fsTarget, adUserEnum), false, 'rpcclient enumdomusers should be suppressed when blocker.samr_null_denied');
  assert.strictEqual(OBOL.pack.preferredCommandIndex(adUserEnum, 'remote', fsTarget), 1, 'preferredCommandIndex should promote kerbrute userenum (index 1) when SAMR null is denied');
  console.log('[PASS] blocker.samr_null_denied suppresses unauthenticated SAMR/RID commands and promotes kerbrute userenum.');

  // 9. Verify gpp-passwords promotes share-aware smbclient command (index 0) and suppresses -M gpp_password when SYSVOL is not readable
  var gppAction = OBOL.packs.actions().find(function (a) { return a.id === 'gpp-passwords'; });
  assert(gppAction, 'gpp-passwords action must exist');
  assert.strictEqual(OBOL.pack.preferredCommandIndex(gppAction, 'remote', fsTarget), 0, 'gpp-passwords should lead with smbclient //{{target}}/{{share}} (index 0) when Replication is the only readable share');
  assert.strictEqual(OBOL.pack.commandIsEligible(gppAction.commands[0], fsTarget, gppAction), true, 'smbclient //{{target}}/{{share}} -N must be eligible when Replication is readable');
  assert.strictEqual(OBOL.pack.commandIsEligible(gppAction.commands[4], fsTarget, gppAction), false, 'nxc -M gpp_password must be suppressed when SYSVOL is not readable');
  console.log('[PASS] gpp-passwords leads with share-aware smbclient command for Replication and suppresses -M gpp_password when SYSVOL is not readable.');

  // 10. Verify bloodyad get writable --detail with --host and benign self-write output retires command and settles bloodyad-acl
  var eng = OBOL.store.active();
  eng.params.target = '10.129.117.156';
  eng.params.domain = 'active.htb';
  eng.params.username = 'SVC_TGS';
  eng.params.password = 'GPPstillStandingStrong2k18';
  OBOL.store.addFacts([
    { kind: 'credential.available', value: { user: 'SVC_TGS', password: 'GPPstillStandingStrong2k18', domain: 'active.htb' }, scope: 'host:10.129.117.156' },
    { kind: 'credential.plaintext', value: { user: 'SVC_TGS', password: 'GPPstillStandingStrong2k18', domain: 'active.htb' }, scope: 'host:10.129.117.156' },
    { kind: 'smb.authenticated', value: { user: 'SVC_TGS', password: 'GPPstillStandingStrong2k18', domain: 'active.htb', service: 'smb' }, scope: 'host:10.129.117.156' },
    { kind: 'credential.validated', value: { user: 'SVC_TGS', password: 'GPPstillStandingStrong2k18', domain: 'active.htb', service: 'smb' }, scope: 'host:10.129.117.156' },
    { kind: 'flag.local', value: { flag: '34d03b0f5662ac3fb83b2ef2015ae18a' }, scope: 'host:10.129.117.156' },
    { kind: 'objective.local_proof', value: { flag: '34d03b0f5662ac3fb83b2ef2015ae18a' }, scope: 'host:10.129.117.156' }
  ]);
  var bloodyCmd = "bloodyad -d active.htb --host 10.129.117.156 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' get writable --detail | tee scans/bloodyad-writable.txt";
  var bloodyOut = [
    'distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=active,DC=htb',
    'msDS-PrincipalName: NT AUTHORITY\\Authenticated Users: WRITE_PROP',
    '                        ; 00299570-246d-11d0-a768-00aa006e0529 (User-Force-Change-Password): CREATE_CHILD',
    '---',
    'distinguishedName: CN=SVC_TGS,CN=Users,DC=active,DC=htb',
    'Public-Information: WRITE_PROP',
    '                    streetAddress: WRITE_PROP'
  ].join('\n');
  var bloodyRes = OBOL.ingest.run({ actionId: 'bloodyad-acl', command: bloodyCmd, text: bloodyOut, scope: 'host:10.129.117.156' });
  assert.strictEqual(bloodyRes.outcome.kind, 'completed-negative', 'bloodyad get writable with only self-write rights must classify as completed-negative');
  assert.strictEqual(bloodyRes.outcome.retireCommand, true, 'bloodyad get writable must set retireCommand: true');
  var pack = { actions: OBOL.packs.actions() };
  var resCtx = OBOL.context.resolve({ engagement: eng, target: '10.129.117.156' });
  var bloodyAction = pack.actions.find(function (a) { return a.id === 'bloodyad-acl'; });
  assert.strictEqual(bloodyAction.settled(resCtx.facts), true, 'bloodyad-acl must settle when get writable completes with no ACL leads');
  var adPathManual = pack.actions.find(function (a) { return a.id === 'ad-path-manual'; });
  assert.strictEqual(resCtx.facts.commandCompleted(adPathManual, adPathManual.commands[1], 1), true, 'ad-path-manual bloodyAD get writable variant must also mark completed across cards');

  // Verify legacy activity healing when a pre-fix activity had outcome.kind='success' and retireCommand=false
  eng.activities[0].outcome = { kind: 'success', conclusive: false, retireCommand: false };
  var healedCtx = OBOL.context.resolve({ engagement: eng, target: '10.129.117.156' });
  assert.strictEqual(bloodyAction.settled(healedCtx.facts), true, 'Legacy --host activity with retireCommand: false must auto-heal and settle bloodyad-acl');
  var ranked = OBOL.pack.rankActions(healedCtx.facts, pack.actions, { engagement: eng, target: '10.129.117.156' });
  assert.strictEqual(ranked.some(function (a) { return a.id === 'bloodyad-acl'; }), false, 'bloodyad-acl must be settled and absent from ready actions');
  var nonFlagReady = ranked.filter(function (a) { return a.id !== 'flag-hunt-windows'; });
  assert.strictEqual(nonFlagReady[0].id, 'kerberoast', 'kerberoast must advance to #1 escalation move once bloodyad-acl settles');
  console.log('[PASS] bloodyad get writable --detail with --host retires command, settles bloodyad-acl, and promotes kerberoast to #1.');

  // 11. Verify Operator Deck RDP, WinRM, and On-Host Proof commands (psexec default, parenthesized cmd chains, /tls:seclevel:0, WMI-safe WinRM enablement)
  eng.params.username = 'Administrator';
  eng.params.password = 'Ticketmaster1968';
  OBOL.store.addFacts([
    { kind: 'port:445', value: { port: 445, protocol: 'tcp', state: 'open' }, scope: 'host:10.129.117.156' },
    { kind: 'smb.reachable', value: { port: 445 }, scope: 'host:10.129.117.156' },
    { kind: 'credential.available', value: { user: 'Administrator', password: 'Ticketmaster1968', domain: 'active.htb' }, scope: 'host:10.129.117.156' },
    { kind: 'access.admin', value: { user: 'Administrator', domain: 'active.htb' }, scope: 'host:10.129.117.156' }
  ]);
  var adminCtx = OBOL.context.resolve({ engagement: eng, target: '10.129.117.156' });
  var deck = OBOL.pack.buildDeck(eng, { target: '10.129.117.156', facts: adminCtx.facts });
  var flagsTab = deck.tabs.find(function (t) { return t.id === 'flags'; });
  var bothLane = flagsTab.lanes.find(function (l) { return l.id === 'both-flags-onhost'; });
  assert.strictEqual(bothLane.steps[0].variants[0].id, 'psexec', 'both-flags-onhost Step 1 must default to impacket-psexec');
  assert.ok(/^\(whoami & hostname & ipconfig & type /.test(bothLane.steps[1].variants[0].command), 'cmd.exe proof variant must be parenthesized so wmiexec/smbexec redirects all commands');

  var rdpLane = flagsTab.lanes.find(function (l) { return l.id === 'root-enable-rdp'; });
  assert.ok(rdpLane.steps[0].variants.every(function (v) { return v.command.indexOf('UserAuthentication') >= 0 && v.command.indexOf('TermService') >= 0; }), 'All RDP Step 1 variants must disable NLA and start TermService');
  assert.ok(rdpLane.steps[1].variants[0].command.indexOf('/tls:seclevel:0') >= 0, 'Default xfreerdp command must include /tls:seclevel:0 for legacy TLS 1.0 targets');
  assert.ok(rdpLane.steps[1].variants.some(function (v) { return v.command.indexOf('/sec:rdp') >= 0; }), 'RDP Step 2 must offer /sec:rdp fallback variant');

  var winrmLane = flagsTab.lanes.find(function (l) { return l.id === 'root-enable-winrm'; });
  assert.ok(winrmLane.steps[0].variants.every(function (v) { return v.command.indexOf('AllowAutoConfig') >= 0 && v.command.indexOf('IPv4Filter') >= 0 && v.command.indexOf('WinRMInit') >= 0; }), 'All WinRM Step 1 variants must configure AllowAutoConfig + IPv4Filter and run Enable-PSRemoting via SYSTEM scheduled task');

  // 12. Verify failed WMI Set-WSManQuickConfig does NOT mint host.winrm_enabled or port:5985 and surfaces diagnostic fix
  var winrmFailRes = OBOL.parsers.parseActionOutput({
    actionId: 'flag-hunt-root-windows',
    command: "nxc smb 10.129.118.39 -u 'Administrator' -p 'Ticketmaster1968' -x 'powershell -c \"Enable-PSRemoting -Force\"'",
    stdout: [
      'SMB         10.129.118.39   445    DC               [+] active.htb\\Administrator:Ticketmaster1968 (Pwn3d!)',
      'SMB         10.129.118.39   445    DC               [+] Executed command via wmiexec',
      'SMB         10.129.118.39   445    DC               WinRM already is set up to receive requests on this machine.',
      'SMB         10.129.118.39   445    DC               Set-WSManQuickConfig : Access is denied.',
      'SMB         10.129.118.39   445    DC               + FullyQualifiedErrorId : WsManError,Microsoft.WSMan.Management.SetWSManQuickConfigCommand'
    ].join('\n'),
    scope: '10.129.118.39',
    domain: 'active.htb'
  });
  assert.strictEqual(winrmFailRes.facts.some(function (f) { return f.kind === 'host.winrm_enabled' || f.kind === 'port:5985'; }), false, 'Failed Set-WSManQuickConfig must never mint host.winrm_enabled or port:5985');
  assert.strictEqual(winrmFailRes.facts.some(function (f) { return f.kind === 'blocker.winrm_closed'; }), true, 'Failed Set-WSManQuickConfig must mint blocker.winrm_closed');

  // 13. Verify FreeRDP BIO_do_handshake error fix and Logon Info V2 success parsing
  var rdpFailOut = OBOL.outcomes.classify({
    command: "xfreerdp /v:10.129.118.39 /u:'Administrator' /p:'Ticketmaster1968' /cert:ignore",
    text: '[ERROR][com.freerdp.crypto] - [freerdp_tls_handshake]: BIO_do_handshake failed\nERRCONNECT_TLS_CONNECT_FAILED [0x00020008]',
    facts: [],
    context: { target: '10.129.118.39', targetDomain: 'active.htb', principal: 'Administrator' }
  });
  assert.strictEqual(rdpFailOut.kind, 'environment-error', 'BIO_do_handshake failure must classify as environment-error');
  assert.ok((rdpFailOut.errorFixes || []).some(function (e) { return e.id === 'xfreerdp-tls'; }), 'BIO_do_handshake failure must surface xfreerdp-tls errorFix');

  var rdpOkRes = OBOL.parsers.parseActionOutput({
    actionId: 'flag-hunt-root-windows',
    command: "xfreerdp /v:10.129.118.39 /d:'active.htb' /u:'Administrator' /p:'Ticketmaster1968' /cert:ignore /tls:seclevel:0 +clipboard",
    stdout: '[INFO][com.freerdp.client.common] - [client_common_save_session_info]: Logon Info V2 [ACTIVE\\Administrator (2)]',
    scope: '10.129.118.39',
    domain: 'active.htb'
  });
  assert.ok(rdpOkRes.facts.some(function (f) { return f.kind === 'rdp.authenticated'; }), 'Logon Info V2 must mint rdp.authenticated');
  assert.ok(rdpOkRes.facts.some(function (f) { return f.kind === 'access.desktop' && f.value.admin === true; }), 'Logon Info V2 as Administrator must mint admin access.desktop');

  // 14. Verify soft-wrapped terminal prompt flag capture and no SVC_TGS identity theft
  var psexecWrappedRes = OBOL.parsers.parseActionOutput({
    actionId: 'flag-hunt-root-windows',
    command: "impacket-psexec 'active.htb/Administrator:Ticketmaster1968@10.129.118.39'",
    stdout: [
      '[*] Starting service jsRh.....',
      'Microsoft Windows [Version 6.1.7601]',
      'C:\\Windows\\system32> whoami && hostname && ipconfig && type "C:\\Users\\SVC_TGS\\Desktop\\user.txt" && type "C:\\Users',
      '\\Administrator\\Desktop\\root.txt"',
      'nt authority\\system',
      'DC',
      '   IPv4 Address. . . . . . . . . . . : 10.129.118.39',
      'f17de2820d7832fa541dc2e96c4f57cb',
      '67bac6fdc84023cad65b1199f1d1c36a',
      'C:\\Windows\\system32>'
    ].join('\n'),
    scope: '10.129.118.39',
    domain: 'active.htb'
  });
  assert.strictEqual(psexecWrappedRes.facts.some(function (f) { return f.value && (f.value.identity === 'SVC_TGS' || f.value.user === 'SVC_TGS'); }), false, 'Must not scrape SVC_TGS as session identity from type C:\\Users\\SVC_TGS\\Desktop\\user.txt');
  assert.ok(psexecWrappedRes.facts.some(function (f) { return f.kind === 'objective.local_flag' && f.value.on_host === true && f.value.flag === 'f17de2820d7832fa541dc2e96c4f57cb'; }), 'Soft-wrapped psexec session must capture on-host local flag');
  assert.ok(psexecWrappedRes.facts.some(function (f) { return f.kind === 'objective.root_flag' && f.value.on_host === true && f.value.flag === '67bac6fdc84023cad65b1199f1d1c36a'; }), 'Soft-wrapped psexec session must capture on-host root flag');
  console.log('[PASS] RDP, WinRM, and PsExec/WMIExec on-host proof regressions verified.');

  console.log('\nALL ACTIVE HARVEST REGRESSION TESTS PASSED!');
})().catch(function (err) {
  console.error(err);
  process.exit(1);
});
