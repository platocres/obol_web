#!/usr/bin/env node
/*
 * tests/engine/dual-pass-harvester-smoke.js
 *
 * 100% synthetic, corpus-free smoke suite verifying OBOL's v13.0 Dual-Pass + Multi-Target
 * Corpus Harness and Anti-Overfitting Red-Team Scanner:
 *   1. tools/corpus/sandbox-loader.js (v13.0 load order, 3-tier attribution, stateless
 *      probing, single/multi-target stateful sessions, snapshot/restore, BloodHound JSON)
 *   2. tools/corpus/markdown-extractor.js (0xdf HTML + CommonMark fences, static-code
 *      exclusion + Exploit-DB exception, multi-shell prompt splitting, exact-line OCR
 *      sidecar splicing, and cross-author alternate discovery)
 *   3. tools/corpus/extraction-schema.js (v1 compatibility + Schema v2 outcome_expected,
 *      tier_attribution, and trajectory_checkpoints contracts)
 *   4. tools/corpus/harvest-markdown.js & tools/corpus/facts-axis.js (Pass 1 CommonMark
 *      harvest, tier attribution summary, and negative-outcome matrix grading)
 *   5. tools/corpus/harvest-trajectories.js (Pass 2 single/multi-target stateful replay,
 *      Closed-Loop #1 promotion via dry-probe retirement, and 5-bucket stall diagnostics)
 *   6. tools/corpus/verify-no-overfit.js (dynamic manifest identity blocking, English
 *      allowlist, lookup-table guard, >= 48-char prose leak guard, and house-style scan)
 *
 * House style: no em dashes, no en dashes, no emoji.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const sandboxLoader = require('../../tools/corpus/sandbox-loader');
const mdExtractor = require('../../tools/corpus/markdown-extractor');
const schema = require('../../tools/corpus/extraction-schema');
const harvestMd = require('../../tools/corpus/harvest-markdown');
const factsAxis = require('../../tools/corpus/facts-axis');
const harvestTraj = require('../../tools/corpus/harvest-trajectories');
const overfitScanner = require('../../tools/corpus/verify-no-overfit');

let passed = 0;
function check(label, cond) {
  if (!cond) {
    console.error('FAIL: ' + label);
    process.exit(1);
  }
  passed++;
}

// ---- 1. sandbox-loader.js ----------------------------------------------------
{
  const loadOrder = sandboxLoader.resolveLoadOrder();
  const idxIndex = loadOrder.indexOf('assets/engine/parsers/index.js');
  const shapeIndex = loadOrder.indexOf('assets/engine/parsers/shape.js');
  const inferIndex = loadOrder.indexOf('assets/engine/parsers/inference.js');
  const pathRouteIndex = loadOrder.indexOf('assets/ui/routes/path.js');
  check('sandbox-loader: shape.js and inference.js load before parsers/index.js', shapeIndex > 0 && inferIndex > shapeIndex && idxIndex > inferIndex);
  check('sandbox-loader: UI coach route path.js loads after parsers/index.js', pathRouteIndex > idxIndex);

  const OBOL = sandboxLoader.createSandbox();
  check('sandbox-loader: exposes parsers, outcomes, packs, command, bloodhound, store, ingest, coach',
    Boolean(OBOL.parsers && OBOL.outcomes && OBOL.packs && OBOL.command && OBOL.bloodhound && OBOL.store && OBOL.ingest && OBOL.coach));

  // Tier classification unit checks
  check('classifyFactTier: default -> tier1', sandboxLoader.classifyFactTier({ kind: 'port:80', value: { port: 80 } }) === 'tier1');
  check('classifyFactTier: via=shape -> tier2_shape', sandboxLoader.classifyFactTier({ kind: 'http.reachable', value: { via: 'shape' } }) === 'tier2_shape');
  check('classifyFactTier: via=vulnmatch -> tier2_shape', sandboxLoader.classifyFactTier({ kind: 'vuln.candidate', value: { via: 'vulnmatch' } }) === 'tier2_shape');
  check('classifyFactTier: via=context-cooccurrence -> tier3_inference', sandboxLoader.classifyFactTier({ kind: 'foothold.linux', value: { via: 'context-cooccurrence' } }) === 'tier3_inference');
  check('classifyFactTier: via=prompt-telemetry -> tier3_inference', sandboxLoader.classifyFactTier({ kind: 'foothold.windows', value: { via: 'prompt-telemetry' } }) === 'tier3_inference');

  // Stateless positive probe
  const posProbe = sandboxLoader.probeBlockStateless(OBOL, {
    command: 'nmap -sV 10.250.10.20',
    stdout: [
      'Nmap scan report for 10.250.10.20',
      'PORT    STATE SERVICE VERSION',
      '22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6',
      '80/tcp  open  http    Apache httpd 2.4.52 ((Ubuntu))'
    ].join('\n')
  });
  check('probeBlockStateless: mints port:22 and http.reachable on synthetic nmap',
    posProbe.supported_kinds.includes('port:22') && posProbe.supported_kinds.includes('http.reachable'));
  check('probeBlockStateless: tier1 dominant on standard nmap',
    posProbe.tier_attribution.dominant_tier === 'tier1' && posProbe.tier_attribution.counts.tier1 >= 3);

  // Stateless negative / empty probe
  const negProbe = sandboxLoader.probeBlockStateless(OBOL, {
    command: 'whatweb -a3 http://10.250.10.20',
    stdout: '[OBOL: completed with no output / nothing found]'
  });
  check('probeBlockStateless: grades dry probe sentinel as completed-negative',
    negProbe.outcome && negProbe.outcome.kind === 'completed-negative');

  // Stateful multi-target engagement + snapshot/restore + BloodHound JSON
  const session = sandboxLoader.createEngagementSession(OBOL, {
    name: 'SyntheticMultiHost',
    targets: ['10.250.10.20', '10.250.20.30'],
    lhost: '10.10.14.99',
    multiTarget: true
  });
  check('createEngagementSession: registers both initial targets', session.getTargets().length === 2);

  session.ingestTurn({
    command: 'nmap -sV 10.250.10.20',
    stdout: 'Nmap scan report for 10.250.10.20\nPORT STATE SERVICE\n80/tcp open http\n'
  });
  const snap = session.snapshot();

  session.ingestTurn({
    command: 'nmap -sV 10.250.20.30',
    stdout: 'Nmap scan report for 10.250.20.30\nPORT STATE SERVICE\n445/tcp open microsoft-ds\n'
  });
  check('multi-target session: switches active target to 10.250.20.30 and isolates facts per host',
    session.getActiveTarget() === '10.250.20.30'
    && session.factSetForTarget('10.250.20.30').has('port:445')
    && !session.factSetForTarget('10.250.10.20').has('port:445'));

  session.restore(snap);
  check('snapshot/restore: rolls back 10.250.20.30 facts cleanly',
    !session.factSetForTarget('10.250.20.30').has('port:445')
    && session.factSetForTarget('10.250.10.20').has('port:80'));

  const domSid = 'S-1-5-21-1111111111-2222222222-3333333333';
  const bhRes = session.ingestBloodHound({
    domains: {
      meta: { type: 'domains', count: 1, version: 5 },
      data: [{
        ObjectIdentifier: domSid,
        Properties: { name: 'SYNTHLAB.LOCAL', domain: 'SYNTHLAB.LOCAL' },
        Aces: []
      }]
    },
    users: {
      meta: { type: 'users', count: 1, version: 5 },
      data: [{
        ObjectIdentifier: domSid + '-1105',
        Properties: { name: 'SVC_SYNTH@SYNTHLAB.LOCAL', domain: 'SYNTHLAB.LOCAL', enabled: true },
        Aces: []
      }]
    },
    groups: {
      meta: { type: 'groups', count: 1, version: 5 },
      data: [{
        ObjectIdentifier: domSid + '-512',
        Properties: { name: 'DOMAIN ADMINS@SYNTHLAB.LOCAL', domain: 'SYNTHLAB.LOCAL' },
        Members: [],
        Aces: [{
          PrincipalSID: domSid + '-1105',
          PrincipalType: 'User',
          RightName: 'GenericAll',
          IsInherited: false
        }]
      }]
    }
  }, { owned: ['SVC_SYNTH@SYNTHLAB.LOCAL'] });

  const bhKinds = (bhRes.facts || []).map(f => f.kind);
  check('ingestBloodHound: mints ad.graph.collected and ad.attack_paths from SharpHound JSON',
    bhKinds.includes('ad.graph.collected') && bhKinds.includes('ad.attack_paths'));
}

// ---- 2. markdown-extractor.js ------------------------------------------------
{
  const zshPromptTop = '\u250c\u2500\u2500(kali\u327fkali)-[~/work]';
  const zshPromptBot = '\u2514\u2500$ ';
  const sampleMd = [
    '# Enumeration',
    '',
    'Initial network sweep on synthetic lab host:',
    '',
    '<div class="language-console"><div class="highlight">',
    '```console',
    zshPromptTop,
    zshPromptBot + 'nmap -sV 10.250.10.20',
    'Nmap scan report for 10.250.10.20',
    'PORT   STATE SERVICE',
    '80/tcp open  http',
    zshPromptTop,
    zshPromptBot + 'whatweb http://10.250.10.20',
    'http://10.250.10.20 [200 OK] Apache[2.4.52]',
    '```',
    '</div></div>',
    '',
    'Static helper script (must be excluded):',
    '',
    '```python',
    'import sys',
    'def helper(x):',
    '    return x + 1',
    '```',
    '',
    'Exploit-DB snippet (must be included despite python tag):',
    '',
    '```python',
    '# Exploit Title: Synthetic Widget 1.4 Unauthenticated RCE',
    '# CVE: CVE-2024-99999',
    'import requests',
    '```',
    '',
    'Interactive multi-shell CommonMark session:',
    '',
    '~~~powershell',
    '*Evil-WinRM* PS C:\\Users\\svc_synth\\Documents> whoami /priv',
    'SeImpersonatePrivilege Enabled',
    '~~~',
    '',
    '```',
    'smb: \\> ls',
    '  notes.txt      A    128  Mon Oct 20 10:00:00 2026',
    'mysql> show databases;',
    'information_schema',
    'postgres=# \\dt',
    'public | accounts',
    'sqlite> .tables',
    'sessions',
    '127.0.0.1:6379> INFO server',
    'redis_version:7.0.11',
    'sh-5.1$ id',
    'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
    '[operator@synthhost ~]$ sudo -l',
    '(ALL) NOPASSWD: /usr/bin/find',
    '```'
  ].join('\n');

  const blocks = mdExtractor.extractBlocks(sampleMd);
  check('markdown-extractor: includes html-div, Exploit-DB python, powershell, and bare REPL block while excluding static python',
    blocks.length === 4
    && blocks[0].sourceFormat === 'html-div'
    && blocks[1].classificationReason === 'exploit-db-header'
    && blocks[2].lang === 'powershell'
    && blocks[3].classificationReason === 'bare-prompt');

  const extracted = mdExtractor.extractWalkthroughTurns(sampleMd, {
    slug: 'synth-sample',
    ocrEntries: [{
      line: 18,
      fidelity: 'ocr',
      command: 'curl -sSI http://10.250.10.20/admin',
      stdout: 'HTTP/1.1 200 OK\nServer: Apache/2.4.52'
    }]
  });

  const cmds = extracted.turns.map(t => t.command);
  check('markdown-extractor: splits 2-line Kali zsh prompts into separate turns',
    cmds[0] === 'nmap -sV 10.250.10.20' && cmds[1] === 'whatweb http://10.250.10.20');
  check('markdown-extractor: splices OCR sidecar turn at exact chronological line position',
    extracted.turns[2].fidelity === 'ocr' && extracted.turns[2].lineStart === 18);
  check('markdown-extractor: splits Evil-WinRM, smbclient, mysql, psql, sqlite3, redis-cli, sh-5.1, and bracket unix prompts',
    cmds.includes('whoami /priv')
    && cmds.includes('smbclient ls')
    && cmds.includes('mysql show databases;')
    && cmds.includes('psql \\dt')
    && cmds.includes('sqlite3 .tables')
    && cmds.includes('redis-cli INFO server')
    && cmds.includes('id')
    && cmds.includes('sudo -l'));
}

// ---- 3. extraction-schema.js v2 ----------------------------------------------
{
  const OBOL = sandboxLoader.createSandbox();
  const vocab = schema.buildKindVocabulary(OBOL.PARSER_SIGNATURES);

  const baseText = 'PORT STATE SERVICE\n80/tcp open http\n';
  const validV2Record = {
    source: { url: 'https://example.invalid/synth/1', author: 'synthetic', retrieved: '2026-10-29' },
    asset: { hash: schema.contentHash(baseText), type: 'code_block', fidelity: 'text' },
    context: { box: 'synth-unit', os: 'linux', phase: 'recon' },
    output_blocks: [{
      command_shown: 'nmap 10.250.10.20',
      tool: 'nmap',
      raw_output: baseText,
      truncated: false,
      fidelity: 'text',
      outcome_expected: 'success',
      tier_attribution: { 'port:80': 'tier1', 'http.reachable': 'tier1' }
    }],
    facts_implied: [{ kind: 'port:80' }, { kind: 'http.reachable' }],
    outcome_expected: 'success',
    tier_attribution: 'tier1',
    trajectory_checkpoints: [{
      step_index: 1,
      target_ip: '10.250.10.20',
      expected_move_ids: ['content-discovery'],
      required_gates: ['http.reachable'],
      earned_tokens: ['target'],
      require_closed_loop_top1: true,
      retired_dry_moves: ['recon-web-triage']
    }]
  };

  const vr = schema.validateRecord(validV2Record, { isKnownKind: vocab.isKnownKind });
  check('extraction-schema v2: valid v2 record passes with 0 errors', vr.ok && vr.errors.length === 0);

  const badOutcomeRec = Object.assign({}, validV2Record, { outcome_expected: 'totally-bogus-outcome' });
  check('extraction-schema v2: rejects invalid outcome_expected', !schema.validateRecord(badOutcomeRec, { isKnownKind: vocab.isKnownKind }).ok);

  const badTierRec = Object.assign({}, validV2Record, { tier_attribution: { 'nonexistent.fact_kind': 'tier1' } });
  check('extraction-schema v2: rejects unknown fact kind inside tier_attribution map', !schema.validateRecord(badTierRec, { isKnownKind: vocab.isKnownKind }).ok);

  const badCpRec = Object.assign({}, validV2Record, { trajectory_checkpoints: [{ step_index: -1 }] });
  check('extraction-schema v2: rejects negative checkpoint step_index', !schema.validateRecord(badCpRec, { isKnownKind: vocab.isKnownKind }).ok);

  const validV2Labels = {
    version: 2,
    description: 'Synthetic v2 ground-truth labels',
    cases: [{
      id: '0123456789ab',
      file: 'synth.md',
      command: 'whatweb http://10.250.10.20',
      expected_kinds: [],
      forbidden_kinds: ['foothold.linux'],
      outcome_expected: 'completed-negative'
    }]
  };
  check('extraction-schema v2: validates v2 labels file with outcome_expected',
    schema.validateLabelsFile(validV2Labels, vocab.isKnownKind).ok);
}

// ---- 4. harvest-markdown.js & facts-axis.js on Temp Synthetic Corpus ---------
{
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'obol-dual-pass-'));
  try {
    const wtDir = path.join(tmpRoot, 'walkthroughs');
    const ocrDir = path.join(tmpRoot, 'ocr-sidecars');
    const altDir = path.join(tmpRoot, 'alternates');
    fs.mkdirSync(wtDir, { recursive: true });
    fs.mkdirSync(ocrDir, { recursive: true });
    fs.mkdirSync(altDir, { recursive: true });

    const wtMd = [
      '# Synthetic Host Walkthrough',
      '',
      '```bash',
      '$ nmap -sV 10.250.10.20',
      'Nmap scan report for 10.250.10.20',
      'PORT   STATE SERVICE VERSION',
      '22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu',
      '80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))',
      '```',
      '',
      '```bash',
      '$ whatweb -a3 http://10.250.10.20',
      '[OBOL: completed with no output / nothing found]',
      '```'
    ].join('\n');

    fs.writeFileSync(path.join(wtDir, 'synth01.md'), wtMd, 'utf8');
    fs.writeFileSync(path.join(ocrDir, 'synth01.json'), JSON.stringify([{
      line: 10,
      fidelity: 'ocr',
      command: 'gobuster dir -u http://10.250.10.20 -w common.txt',
      stdout: '/portal (Status: 200) [Size: 1420]\n/uploads (Status: 301) [Size: 312]'
    }], null, 2), 'utf8');
    fs.writeFileSync(path.join(altDir, 'synth01--altauthor.md'), [
      '# Alternate Writeup',
      '```bash',
      '$ feroxbuster -u http://10.250.10.20',
      '200      GET       12l       40w      420c http://10.250.10.20/login.php',
      '```'
    ].join('\n'), 'utf8');

    const OBOL = sandboxLoader.createSandbox();
    const { report: blindReport } = harvestMd.runHarvest({
      OBOL: OBOL,
      corpusDir: tmpRoot,
      includeAlternates: true,
      writeReports: false
    });

    check('harvest-markdown: processes CommonMark walkthrough + alternate + spliced OCR sidecar',
      blindReport.walkthroughs_scanned_with_alternates === 2
      && blindReport.ocr_spliced_turns === 1
      && blindReport.tier_attribution.facts_by_tier.tier1 >= 4
      && blindReport.outcome_distribution['completed-negative'] >= 1);

    // Build exact block IDs for facts-axis v2 grading
    const extractedTurns = mdExtractor.extractWalkthroughTurns(wtMd).turns;
    const nmapBlockId = mdExtractor.blockId('synth01.md', extractedTurns[0].command, extractedTurns[0].output);
    const negBlockId = mdExtractor.blockId('synth01.md', extractedTurns[1].command, extractedTurns[1].output);
    const labelsPath = path.join(tmpRoot, 'labels-v2.json');
    fs.writeFileSync(labelsPath, JSON.stringify({
      version: 2,
      description: 'Synthetic CommonMark v2 labels',
      cases: [
        {
          id: nmapBlockId,
          file: 'synth01.md',
          command: 'nmap -sV 10.250.10.20',
          expected_kinds: ['port:22', 'port:80', 'http.reachable'],
          forbidden_kinds: ['foothold.linux'],
          outcome_expected: 'success',
          tier_attribution: { 'port:80': 'tier1' }
        },
        {
          id: negBlockId,
          file: 'synth01.md',
          command: 'whatweb -a3 http://10.250.10.20',
          expected_kinds: [],
          forbidden_kinds: ['http.reachable'],
          outcome_expected: 'completed-negative'
        }
      ]
    }, null, 2), 'utf8');

    const faRes = factsAxis.runFactsAxis({
      OBOL: OBOL,
      corpusDir: tmpRoot,
      labels: labelsPath,
      writeReports: false
    });
    check('facts-axis v2: resolves CommonMark blocks and grades outcome_expected + tier_attribution with 0 mismatches',
      faRes.report.resolved_blocks === 2
      && faRes.report.totals.recall === 1
      && faRes.report.totals.forbidden_hits === 0
      && faRes.report.totals.outcome_mismatches === 0
      && faRes.report.totals.tier_mismatches === 0);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ---- 5. harvest-trajectories.js Pass 2 Closed-Loop Replay --------------------
{
  const OBOL = sandboxLoader.createSandbox();

  // 5A. Single-target kill-chain with $IP variable expansion, multi-port fork, and checkpoint
  const singleMd = [
    '# Synthetic Kill Chain',
    '',
    '```bash',
    '$ export IP=10.250.10.20',
    '$ nmap -sC -sV $IP',
    'Nmap scan report for 10.250.10.20',
    'PORT    STATE SERVICE      VERSION',
    '21/tcp  open  ftp          vsftpd 3.0.5',
    '80/tcp  open  http         Apache httpd 2.4.52 ((Ubuntu))',
    '445/tcp open  microsoft-ds Samba smbd 4.15.13-Ubuntu',
    '$ gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt',
    '/admin (Status: 301) [Size: 310]',
    '/uploads (Status: 200) [Size: 1024]',
    '```'
  ].join('\n');

  const repSingle = harvestTraj.replayWalkthrough(OBOL, {
    slug: 'synth-single',
    markdown: singleMd,
    trajectory_checkpoints: [{
      step_index: 2,
      target_ip: '10.250.10.20',
      expected_move_ids: ['content-discovery'],
      required_gates: ['ports.open', 'http.reachable'],
      earned_tokens: ['target'],
      require_closed_loop_top1: true
    }]
  });

  check('harvest-trajectories: classifies export IP=... as housekeeping and expands $IP on subsequent turns',
    repSingle.steps[0].housekeeping === true
    && repSingle.steps[1].command.includes('10.250.10.20')
    && repSingle.steps[2].command.includes('http://10.250.10.20'));
  check('harvest-trajectories: reaches 100% closed-loop reachability on synthetic recon + content-discovery flow',
    repSingle.totals.graded_steps === 2 && repSingle.totals.reachable_steps === 2);
  check('harvest-trajectories: passes v2 trajectory checkpoint at step 2',
    repSingle.checkpoints.length === 1 && repSingle.checkpoints[0].ok === true);

  // 5B. Explicit Closed-Loop #k -> #1 promotion & non-mutating snapshot verification
  const promoSession = sandboxLoader.createEngagementSession(OBOL, {
    target: '10.250.10.55',
    lhost: '10.10.14.99'
  });
  promoSession.ingestTurn({
    actionId: 'nmap-fast-open-ports',
    command: 'nmap -Pn -p- --min-rate 5000 10.250.10.55',
    stdout: 'Nmap scan report for 10.250.10.55\nPORT STATE SERVICE\n21/tcp open ftp\n80/tcp open http\n445/tcp open microsoft-ds\n'
  });
  promoSession.ingestTurn({
    actionId: 'nmap-version-scripts',
    command: 'nmap -Pn -sC -sV -p 21,80,445 10.250.10.55',
    stdout: 'Nmap scan report for 10.250.10.55\nPORT STATE SERVICE VERSION\n21/tcp open ftp vsftpd 3.0.5\n80/tcp open http Apache httpd 2.4.52\n445/tcp open microsoft-ds Samba 4.15.13\n'
  });
  // Add one non-nmap activity so initial-recon-fork Top-4 exemption is off and strict #k -> #1 dry-probe promotion runs
  promoSession.ingestTurn({
    actionId: 'recon-web-triage',
    command: 'whatweb -a3 http://10.250.10.55',
    stdout: 'http://10.250.10.55 [200 OK] Apache[2.4.52]'
  });

  const coachBeforePromo = promoSession.computeCoach('10.250.10.55');
  check('closed-loop setup: Ready Now has >= 2 moves', coachBeforePromo.onFlow.length >= 2);
  const actsCountBefore = promoSession.eng.activities.length;
  const secondMove = coachBeforePromo.onFlow[1];
  const promoEval = harvestTraj.evaluateClosedLoopReachability(
    promoSession,
    [{ move: secondMove, id: secondMove.id, title: secondMove.title, match_score: 25 }],
    { command: secondMove.id },
    { targetIp: '10.250.10.55' }
  );
  check('closed-loop promotion: promotes #2 Ready Now move to #1 via simulated dry-probe retirement',
    promoEval.reachable === true
    && promoEval.mode === 'closed_loop_promoted_top1'
    && promoEval.initial_rank === 2
    && promoEval.retired_preceding.length === 1);
  check('closed-loop promotion: restores engagement snapshot without mutating live activities',
    promoSession.eng.activities.length === actsCountBefore);

  // 5C. Stall diagnostic buckets (GATE_DEADLOCK_OR_UNDERGATED_GAMBLE vs PARSE_OR_SHAPE_MISS)
  const freshSession = sandboxLoader.createEngagementSession(OBOL, { target: '10.250.10.88' });
  const dcsyncMove = OBOL.packs.actions().find(a => a.id === 'dcsync');
  const gateStall = harvestTraj.evaluateClosedLoopReachability(
    freshSession,
    [{ move: dcsyncMove, id: dcsyncMove.id, title: dcsyncMove.title, match_score: 25 }],
    { command: 'secretsdump.py -just-dc corp.internal/admin@10.250.10.88' },
    { targetIp: '10.250.10.88', historyTurns: [] }
  );
  check('stall bucket: out-of-order dcsync without prior evidence -> GATE_DEADLOCK_OR_UNDERGATED_GAMBLE',
    !gateStall.reachable && gateStall.stall_bucket === 'GATE_DEADLOCK_OR_UNDERGATED_GAMBLE');

  const sudoMove = OBOL.packs.actions().find(a => a.id === 'sudo-abuse');
  const parseMissStall = harvestTraj.evaluateClosedLoopReachability(
    freshSession,
    [{ move: sudoMove, id: sudoMove.id, title: sudoMove.title, match_score: 25 }],
    { command: 'sudo /usr/bin/find . -exec /bin/sh \\;' },
    {
      targetIp: '10.250.10.88',
      historyTurns: [{
        step_index: 0,
        command: 'sudo -l',
        stdout: 'User operator may run the following commands on host:\n    (ALL) NOPASSWD: /usr/bin/find',
        housekeeping: false,
        minted_count: 0
      }]
    }
  );
  check('stall bucket: unmet sudo gate when prior stdout had unminted sudo -l text -> PARSE_OR_SHAPE_MISS',
    !parseMissStall.reachable && parseMissStall.stall_bucket === 'PARSE_OR_SHAPE_MISS');

  // 5D. Multi-target trajectory replay
  const multiMd = [
    '```bash',
    '$ nmap -sV 10.250.10.20',
    'Nmap scan report for 10.250.10.20',
    'PORT   STATE SERVICE',
    '80/tcp open  http',
    '$ nmap -sV 10.250.20.30',
    'Nmap scan report for 10.250.20.30',
    'PORT    STATE SERVICE',
    '445/tcp open  microsoft-ds',
    '```'
  ].join('\n');
  const repMulti = harvestTraj.replayWalkthrough(OBOL, { slug: 'synth-multi', markdown: multiMd }, { multiTarget: true });
  check('harvest-trajectories --multi-target: registers and routes across both hosts',
    repMulti.targets_observed.includes('10.250.10.20') && repMulti.targets_observed.includes('10.250.20.30'));
}

// ---- 6. verify-no-overfit.js Red-Team Scanner --------------------------------
{
  const synthProse = 'During the secondary enumeration phase we noticed an unusual custom daemon listening on loopback port nine thousand forty two and accepting serialized frames.';
  const identities = overfitScanner.loadCorpusIdentities({
    manifestPaths: [],
    manifests: [{
      walkthroughs: [
        {
          slug: 'zz_fictional_box_q7',
          title: ['PG', 'Practice:', 'Access'].join(' '),
          name: 'Access',
          ip: '198.51.100.88',
          winner_source: { repo_id: 'zz_fictional_author42' }
        },
        { slug: 'internal', name: 'Internal' },
        { slug: 'vault', name: 'Vault' },
        { slug: 'squid', name: 'Squid' }
      ]
    }],
    proseTexts: [synthProse]
  });

  // Clean allowlisted English/pentest words in assets/
  const cleanCode = 'function checkAccess(vault, internal, squid, administrator, booleanFlag, vector) { return vault && internal; }';
  const cleanRes = overfitScanner.scanTextForOverfit(cleanCode, {
    relPath: 'assets/engine/parsers/sample.js',
    identities: identities
  });
  check('verify-no-overfit: allowlisted English/protocol words produce 0 violations', cleanRes.length === 0);

  // Distinctive box slug in assets/
  const slugLeak = overfitScanner.scanTextForOverfit('if (host === "zz_fictional_box_q7") return true;', {
    relPath: 'assets/engine/parsers/sample.js',
    identities: identities
  });
  check('verify-no-overfit: flags distinctive corpus box slug in assets/',
    slugLeak.some(v => v.rule === 'HARDCODED_BOX_IDENTITY' && v.subtype === 'box_slug'));

  // Author handle in data/
  const authorLeak = overfitScanner.scanTextForOverfit('{"notes": "adapted from zz_fictional_author42"}', {
    relPath: 'data/packs/sample.json',
    identities: identities
  });
  check('verify-no-overfit: flags corpus author handle in data/',
    authorLeak.some(v => v.rule === 'HARDCODED_BOX_IDENTITY' && v.subtype === 'author_handle'));

  // Manifest IP in tests/
  const ipLeak = overfitScanner.scanTextForOverfit('const target = "198.51.100.88";', {
    relPath: 'tests/engine/sample-smoke.js',
    identities: identities
  });
  check('verify-no-overfit: flags manifest walkthrough IP in tests/',
    ipLeak.some(v => v.rule === 'HARDCODED_BOX_IDENTITY' && v.subtype === 'walkthrough_ip'));

  // Multi-slug lookup array of allowlisted words + explicit PG Practice qualifier (assembled dynamically)
  const dynListLiteral = 'access internal vault squid'.split(' ').map(w => '"' + w + '"').join(', ');
  const dynQualifier = ['PG', 'Practice:', 'Access'].join(' ');
  const tableLeak = overfitScanner.scanTextForOverfit(
    'const boxes = [' + dynListLiteral + ']; // ' + dynQualifier,
    { relPath: 'assets/engine/parsers/sample.js', identities: identities }
  );
  check('verify-no-overfit: flags multi-slug lookup table and explicit box qualifier even for English words',
    tableLeak.filter(v => v.rule === 'SUSPICIOUS_BOX_LOOKUP_TABLE').length === 2);

  // >= 48-char verbatim walkthrough prose substring in tests/
  const proseSub = synthProse.slice(18, 86); // 68 chars >= 48
  const proseLeak = overfitScanner.scanTextForOverfit(
    'const comment = ' + JSON.stringify(proseSub) + ';',
    { relPath: 'tests/engine/sample-smoke.js', identities: identities }
  );
  check('verify-no-overfit: flags >= 48-char verbatim walkthrough prose substring in tests/',
    proseLeak.some(v => v.rule === 'VERBATIM_WALKTHROUGH_PROSE'));

  // House style checks (constructed dynamically so this source file stays 100% house-style clean)
  const emDashChar = String.fromCharCode(0x2014);
  const enDashChar = String.fromCharCode(0x2013);
  const rocketEmoji = String.fromCodePoint(0x1F680);

  check('verify-no-overfit: flags em dash',
    overfitScanner.scanTextForOverfit('bad ' + emDashChar + ' dash', { relPath: 'docs/sample.md', identities: identities })
      .some(v => v.subtype === 'em_dash'));
  check('verify-no-overfit: flags en dash',
    overfitScanner.scanTextForOverfit('pages 1' + enDashChar + '5', { relPath: 'docs/sample.md', identities: identities })
      .some(v => v.subtype === 'en_dash'));
  check('verify-no-overfit: flags decorative emoji',
    overfitScanner.scanTextForOverfit('launch ' + rocketEmoji, { relPath: 'docs/sample.md', identities: identities })
      .some(v => v.subtype === 'decorative_emoji'));
  check('verify-no-overfit: allows Kali zsh box-drawing prompt characters',
    overfitScanner.scanTextForOverfit('\u250c\u2500\u2500(kali\u327fkali)-[~]\n\u2514\u2500$ id', { relPath: 'tools/sample.js', identities: identities }).length === 0);
}

console.log('dual-pass-harvester-smoke: ' + passed + ' assertions passed.');
