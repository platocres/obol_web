/* Node sanity test for OBOL.report.preflightCheck(ctx).
 * Tests the three core preflight checks:
 *   1. Flag capture lacking whoami / IP context emits MISSING_PROOF_CONTEXT warning.
 *   2. Complete capture (whoami + ip a + proof.txt) with initial access and privesc is clean (ok: true, 0 warnings).
 *   3. Activity containing prohibited sqlmap command emits EXAM_RESTRICTED_TOOL error (ok: false).
 */
'use strict';

globalThis.window = globalThis;
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/chain.js');
require('../../data/reportmeta.js');
require('../../assets/engine/report.js');

const OBOL = globalThis.OBOL;
let fail = 0;
function ok(cond, msg) {
  if (!cond) {
    console.error('  FAIL:', msg);
    fail++;
  } else {
    console.log('  ok  :', msg);
  }
}

// ── Test 1: Flag paste lacking whoami / IP context ──────────────────────────
{
  const ctx1 = {
    targets: [{ host: '10.10.10.5', ip: '10.10.10.5', findings: [] }],
    proofs: [{
      host: '10.10.10.5',
      kind: 'proof.txt',
      slot: 'root',
      rawFlag: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
      stdout: 'cat proof.txt\na1b2c3d4e5f60718293a4b5c6d7e8f90\n'
    }],
    activities: [{
      target: '10.10.10.5',
      command: 'cat proof.txt',
      stdout: 'a1b2c3d4e5f60718293a4b5c6d7e8f90\n',
      phase: 'loot'
    }]
  };

  const res1 = OBOL.report.preflightCheck(ctx1);
  ok(res1 && Array.isArray(res1.warnings), 'Test 1: preflightCheck returns warnings array');
  const hasMissingCtx = res1.warnings.some(function (w) {
    return w.code === 'MISSING_PROOF_CONTEXT' && w.level === 'warn';
  });
  ok(hasMissingCtx, 'Test 1: emits MISSING_PROOF_CONTEXT warning for flag paste lacking whoami / IP');
}

// ── Test 2: Clean host with full context + initial access + privesc ─────────
{
  const cleanStdout = [
    'root@web01:/# whoami; ip a; cat proof.txt',
    'root',
    '2: eth0: inet 10.10.10.5/24',
    'a1b2c3d4e5f60718293a4b5c6d7e8f90'
  ].join('\n');

  const ctx2 = {
    targets: [{
      host: '10.10.10.5',
      ip: '10.10.10.5',
      findings: [
        {
          category: 'access',
          title: 'Web RCE Foothold',
          _movePhase: 'initial'
        },
        {
          category: 'privesc',
          title: 'Sudo Abuse Escalation',
          _movePhase: 'privesc'
        }
      ]
    }],
    proofs: [{
      host: '10.10.10.5',
      kind: 'proof.txt',
      slot: 'root',
      rawFlag: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
      stdout: cleanStdout
    }],
    activities: [
      {
        target: '10.10.10.5',
        command: 'curl http://10.10.10.5/shell.php',
        stdout: 'uid=33(www-data)',
        phase: 'initial'
      },
      {
        target: '10.10.10.5',
        command: 'sudo find . -exec /bin/sh \\; -quit',
        stdout: 'root',
        phase: 'privesc'
      },
      {
        target: '10.10.10.5',
        command: 'whoami; ip a; cat proof.txt',
        stdout: cleanStdout,
        phase: 'loot'
      }
    ]
  };

  const res2 = OBOL.report.preflightCheck(ctx2);
  ok(res2 && res2.ok === true, 'Test 2: ok is true for complete proof and chains');
  ok(res2 && res2.warnings.length === 0, 'Test 2: warnings.length is 0 for clean engagement');
}

// ── Test 3: Activity log containing prohibited sqlmap command ───────────────
{
  const ctx3 = {
    targets: [{ host: '10.10.10.5', ip: '10.10.10.5', findings: [] }],
    proofs: [],
    activities: [{
      target: '10.10.10.5',
      command: 'sqlmap -u http://10.10.10.5/item?id=1',
      stdout: 'Testing connection to http://10.10.10.5/item?id=1',
      phase: 'exploit'
    }]
  };

  const res3 = OBOL.report.preflightCheck(ctx3);
  ok(res3 && res3.ok === false, 'Test 3: ok is false when exam-restricted tool used');
  const hasSqlmapErr = res3.warnings.some(function (w) {
    return w.code === 'EXAM_RESTRICTED_TOOL' && w.level === 'error';
  });
  ok(hasSqlmapErr, 'Test 3: emits EXAM_RESTRICTED_TOOL error for sqlmap activity');
}

console.log(fail ? ('\nREPORT PREFLIGHT SMOKE: ' + fail + ' FAILURES') : '\nREPORT PREFLIGHT SMOKE: all passed');
process.exit(fail ? 1 : 0);
