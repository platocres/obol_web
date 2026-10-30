#!/usr/bin/env node
/*
 * tests/engine/phase0-redteam-adversarial-smoke.js
 *
 * Wave-C Independent Adversarial Red-Team Suite for Phase 0 changes:
 *   Probe 1: Identifier, Subnet & Topology Perturbation
 *   Probe 2: Command-Stripped Mid-Scroll & Surface-Format Warp
 *   Probe 3: Negative-Polarity & False-Positive Traps (forbidden_hits === 0)
 *   Probe 4: Hostile Exploit-DB Broken-Script & Traceback Traps
 *   Probe 5: Noisy Dead-End & Closed-Loop Retirement Stress
 *   Probe 6: Zero-Overfit, Asset Cache-Bust & House-Style Scan
 *   Probe 7: Cross-Corpus Structural & Seam Invariants
 *
 * Runs all 7 probes to completion without early exit so every resilient pass
 * and every uncovered defect is reported with exact reproduction evidence.
 * Exits 0 only when all adversarial assertions pass; exits 1 if any fail.
 *
 * House style: no em dashes, no en dashes, no decorative emoji, zero corpus literals.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const QA_ROOT = path.resolve(__dirname, '..', '..');
const sandboxLoader = require(path.join(QA_ROOT, 'tools', 'corpus', 'sandbox-loader'));
const harvestTraj = require(path.join(QA_ROOT, 'tools', 'corpus', 'harvest-trajectories'));
const overfitScanner = require(path.join(QA_ROOT, 'tools', 'corpus', 'verify-no-overfit'));

const results = {
  passed: 0,
  failed: 0,
  byProbe: {},
  failures: []
};

function record(probeId, ok, label, detail) {
  if (!results.byProbe[probeId]) {
    results.byProbe[probeId] = { passed: 0, failed: 0 };
  }
  if (ok) {
    results.passed++;
    results.byProbe[probeId].passed++;
    console.log('  [PASS] ' + label);
  } else {
    results.failed++;
    results.byProbe[probeId].failed++;
    const entry = {
      probe: probeId,
      label: label,
      detail: detail || 'assertion failed'
    };
    results.failures.push(entry);
    console.log('  [FAIL] ' + label + ' -> ' + entry.detail);
  }
}

// Deterministic xorshift32 PRNG for reproducible identifier/subnet perturbation
function makePrng(seed) {
  let state = (seed >>> 0) || 0x6d2b79f5;
  return {
    nextInt(min, max) {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      const u = (state >>> 0) / 0x100000000;
      return min + Math.floor(u * (max - min + 1));
    },
    token(prefix, len) {
      const alphabet = 'bcdfghjkmnpqrstvwxz2346789';
      let out = prefix || '';
      const n = len || 6;
      for (let i = 0; i < n; i++) {
        out += alphabet[this.nextInt(0, alphabet.length - 1)];
      }
      return out;
    }
  };
}

function buildPerturbedTopology(seed) {
  const rng = makePrng(seed);
  const octA = rng.nextInt(211, 249);
  const octB = rng.nextInt(31, 199);
  const hostWeb = '10.' + octA + '.' + octB + '.' + rng.nextInt(21, 89);
  const hostSmb = '172.' + rng.nextInt(24, 30) + '.' + rng.nextInt(110, 210) + '.' + rng.nextInt(31, 149);
  const lhost = '192.168.' + rng.nextInt(201, 239) + '.' + rng.nextInt(11, 99);
  const lport = String(rng.nextInt(4411, 5899));
  const webPort = rng.nextInt(8110, 8899);
  const domPrefix = rng.token('kstrl', 5);
  const domain = domPrefix + '.internal';
  const dcFqdn = 'dc-' + rng.token('', 4) + '.' + domain;
  const shareName = rng.token('shr_', 5);
  const reuseUser = rng.token('svc_', 5);
  const reusePass = 'Kp9#' + rng.token('Zx', 6) + '!';
  const edbId = String(rng.nextInt(91001, 98999));
  const customDir = '/opt/' + rng.token('agt_', 5);
  const customBinName = rng.token('diag_', 5);
  const customBinPath = customDir + '/' + customBinName;
  const hijackBin = rng.token('hlpr_', 5);
  const winDir = 'C:\\' + rng.token('Vendor', 5);
  const winExe = winDir + '\\' + rng.token('SyncSvc', 4) + '.exe';
  return {
    hostWeb,
    hostSmb,
    lhost,
    lport,
    webPort,
    domain,
    dcFqdn,
    shareName,
    reuseUser,
    reusePass,
    edbId,
    customDir,
    customBinName,
    customBinPath,
    hijackBin,
    winDir,
    winExe
  };
}

function sortedSupportedKinds(factSet) {
  const kinds = ((factSet && factSet.facts) || [])
    .filter(f => !f.state || f.state === 'supported')
    .map(f => f.kind);
  return Array.from(new Set(kinds)).sort();
}

function sha1_8(relPath) {
  const cleanRel = relPath.split('?')[0];
  const abs = path.join(QA_ROOT, cleanRel);
  const content = fs.readFileSync(abs, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha1').update(content, 'utf8').digest('hex').slice(0, 8);
}

// ============================================================================
// PROBE 1: Identifier, Subnet & Topology Perturbation
// ============================================================================
function runProbe1() {
  const P = 'P1';
  console.log('\n=== PROBE 1: Identifier, Subnet & Topology Perturbation ===');

  function runTopologyTrial(topo) {
    const OBOL = sandboxLoader.createSandbox();
    const sess = sandboxLoader.createEngagementSession(OBOL, {
      targets: [topo.hostWeb, topo.hostSmb],
      lhost: topo.lhost,
      lport: topo.lport,
      multiTarget: true
    });

    // Host A: non-standard web port + versioned 3rd-party app + disclosed PHP config secret
    sess.ingestTurn({
      target: topo.hostWeb,
      command: 'nmap -sV -p 22,' + topo.webPort + ' ' + topo.hostWeb,
      stdout: [
        'Nmap scan report for ' + topo.hostWeb,
        'PORT     STATE SERVICE VERSION',
        '22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2',
        topo.webPort + '/tcp open  http    OrbitalWiki 3.4.1',
        'Nmap done: 1 IP address (1 host up) scanned in 1.72 seconds'
      ].join('\n')
    });

    sess.ingestTurn({
      target: topo.hostWeb,
      command: 'curl -s http://' + topo.hostWeb + ':' + topo.webPort + '/config.php.bak',
      stdout: '<?php\n$pdo = new PDO("mysql:host=127.0.0.1;dbname=app", "' + topo.reuseUser + '", "' + topo.reusePass + '");\nif (strcmp($_POST["pin"], $secret_pin) == 0) { echo "ok"; }\n?>'
    });

    // Searchsploit + mirror inspect with randomized EDB ID
    sess.ingestTurn({
      target: topo.hostWeb,
      command: 'searchsploit OrbitalWiki 3.4',
      stdout: [
        '-------------------------------------------------------- ---------------------------------',
        ' Exploit Title                                          |  Path',
        '-------------------------------------------------------- ---------------------------------',
        'OrbitalWiki <= 3.5.0 - Unauthenticated Remote Code Exec | php/webapps/' + topo.edbId + '.py',
        '-------------------------------------------------------- ---------------------------------'
      ].join('\n')
    });

    sess.ingestTurn({
      target: topo.hostWeb,
      command: 'head -n 45 ' + topo.edbId + '.py',
      stdout: [
        '#!/usr/bin/env python3',
        '# Exploit Title: OrbitalWiki <= 3.5.0 - Unauthenticated RCE',
        '# EDB-ID: ' + topo.edbId,
        'import argparse, requests',
        'parser = argparse.ArgumentParser()',
        'parser.add_argument("--url", required=True)',
        'parser.add_argument("--lhost", required=True)',
        'parser.add_argument("--lport", required=True)'
      ].join('\n')
    });

    // Foothold + custom SUID binary + strings disclosing bare helper binary
    sess.ingestTurn({
      target: topo.hostWeb,
      command: 'id',
      stdout: 'uid=1004(webusr) gid=1004(webusr) groups=1004(webusr)'
    });
    sess.ingestTurn({
      target: topo.hostWeb,
      command: 'find / -perm -4000 -type f 2>/dev/null',
      stdout: '/usr/bin/passwd\n/usr/bin/sudo\n' + topo.customBinPath
    });
    sess.ingestTurn({
      target: topo.hostWeb,
      command: 'ltrace ' + topo.customBinPath,
      stdout: '__libc_start_main(0x401150, 1, 0x7ffc1122)\nsystem("' + topo.hijackBin + ' --sync")\n+++ exited (status 0) +++'
    });

    // Host B: AD / SMB host with custom share + custom Windows service binary
    sess.ingestTurn({
      target: topo.hostSmb,
      command: 'nmap -sV -p 88,389,445 ' + topo.hostSmb,
      stdout: [
        'Nmap scan report for ' + topo.dcFqdn + ' (' + topo.hostSmb + ')',
        'PORT    STATE SERVICE       VERSION',
        '88/tcp  open  kerberos-sec  Microsoft Windows Kerberos',
        '389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ' + topo.domain + '0., Site: Default-First-Site-Name)',
        '445/tcp open  microsoft-ds?',
        'Nmap done: 1 IP address (1 host up) scanned in 2.41 seconds'
      ].join('\n')
    });

    const factsA = sess.factSetForTarget(topo.hostWeb);
    const factsB = sess.factSetForTarget(topo.hostSmb);
    const ctxA = OBOL.command.buildContext(factsA, {
      target: topo.hostWeb,
      lhost: topo.lhost,
      lport: topo.lport
    });
    const ctxB = OBOL.command.buildContext(factsB, {
      target: topo.hostSmb,
      lhost: topo.lhost,
      lport: topo.lport
    });

    return {
      OBOL,
      sess,
      kindsA: sortedSupportedKinds(factsA),
      kindsB: sortedSupportedKinds(factsB),
      ctxA,
      ctxB
    };
  }

  const topo1 = buildPerturbedTopology(0x13572468);
  const topo2 = buildPerturbedTopology(0x9abcdef1);
  const t1 = runTopologyTrial(topo1);
  const t2 = runTopologyTrial(topo2);

  const normKinds = arr => arr.map(k => (/^port:\d+$/.test(k) && k !== 'port:22' && k !== 'port:88' && k !== 'port:389' && k !== 'port:445') ? 'port:<perturbed>' : k);
  record(
    P,
    JSON.stringify(normKinds(t1.kindsA)) === JSON.stringify(normKinds(t2.kindsA)) &&
      JSON.stringify(normKinds(t1.kindsB)) === JSON.stringify(normKinds(t2.kindsB)),
    'Structural fact-kind invariance across two independent randomized subnets/FQDNs/paths',
    'kindsA1=' + JSON.stringify(t1.kindsA) + ' vs kindsA2=' + JSON.stringify(t2.kindsA)
  );

  record(
    P,
    t1.ctxA.edb_id === topo1.edbId &&
      t1.ctxA.edb_file === topo1.edbId + '.py' &&
      String(t1.ctxA.url || '').includes(topo1.hostWeb + ':' + topo1.webPort) &&
      t1.ctxA.lhost === topo1.lhost &&
      t1.ctxA.lport === topo1.lport,
    'EARNED_TOKENS {{edb_id}}, {{edb_file}}, {{url}}, {{lhost}}, {{lport}} bind perturbed IP/port/callback',
    'ctxA edb tokens=' + JSON.stringify({ id: t1.ctxA.edb_id, file: t1.ctxA.edb_file, url: t1.ctxA.url, lhost: t1.ctxA.lhost, lport: t1.ctxA.lport })
  );

  const hijackVals = t1.sess.factSetForTarget(topo1.hostWeb).values('privesc.path_hijack_candidate');
  record(
    P,
    t1.ctxA.custom_bin === topo1.customBinPath &&
      hijackVals.some(v => v && (v.hijack_bin === topo1.hijackBin || v.binary === topo1.hijackBin)),
    'EARNED_TOKENS {{custom_bin}} and privesc.path_hijack_candidate bind perturbed binary paths',
    'custom_bin=' + t1.ctxA.custom_bin + ', hijackVals=' + JSON.stringify(hijackVals)
  );

  record(
    P,
    t1.ctxB.reuse_user === topo1.reuseUser && t1.ctxB.reuse_secret === topo1.reusePass,
    'Cross-host credential reuse binds {{reuse_user}} and {{reuse_secret}} onto perturbed Host B',
    'reuse_user=' + t1.ctxB.reuse_user + ', reuse_secret=' + t1.ctxB.reuse_secret
  );

  // Seam probe on command.js:983: when a privesc.custom_binary fact carries { path, binary }
  // without the redundant custom_bin key, {{custom_bin}} MUST still resolve to the full path
  // rather than the bare basename.
  {
    const OBOL = t1.OBOL;
    const F = OBOL.facts;
    const fset = new F.FactSet([
      F.makeFact({
        kind: 'privesc.custom_binary',
        scope: 'host:' + topo1.hostWeb,
        state: 'supported',
        value: { path: topo1.customBinPath, binary: topo1.customBinName }
      })
    ]);
    const filled = OBOL.command.fillTemplate('strings -a "{{custom_bin}}"', fset, { target: topo1.hostWeb });
    const expected = 'strings -a "' + topo1.customBinPath + '"';
    record(
      P,
      filled === expected,
      'Seam: {{custom_bin}} prefers full value.path over bare value.binary basename (assets/engine/command.js:983)',
      'assets/engine/command.js:983 resolved "' + filled + '" instead of "' + expected + '" because cbv.binary precedes cbv.path'
    );
  }
}

// ============================================================================
// PROBE 2: Command-Stripped Mid-Scroll & Surface-Format Warp
// ============================================================================
function runProbe2() {
  const P = 'P2';
  console.log('\n=== PROBE 2: Command-Stripped Mid-Scroll & Surface-Format Warp ===');
  const OBOL = sandboxLoader.createSandbox();
  const target = '10.243.91.44';

  // 2A. ANSI + spinner + [proxychains] wrapped searchsploit with command=''
  {
    const warpedSearchsploit = [
      '[proxychains] config file found: /etc/proxychains4.conf',
      '[proxychains] Strict chain  ...  127.0.0.1:9050  ...  ok',
      'Searching...\r\x1b[32m------------------------------------------------------------ ---------------------------------\x1b[0m',
      '\x1b[1m Exploit Title                                              \x1b[0m | \x1b[1m Path\x1b[0m',
      '------------------------------------------------------------ ---------------------------------',
      'KestrelPortal 2.1.4 - Remote Code Execution                  | \x1b[33mpython/webapps/96214.py\x1b[0m',
      '------------------------------------------------------------ ---------------------------------'
    ].join('\n');
    const r = OBOL.parsers.parseActionOutput({
      command: '',
      stdout: warpedSearchsploit,
      stderr: '',
      scope: 'host:' + target,
      target: target
    });
    const hasMatch = r.facts.some(f => f.kind === 'exploit.edb_candidate' && f.value && f.value.edb_id === '96214');
    record(
      P,
      hasMatch,
      'Command-stripped ANSI + \\r spinner + [proxychains] searchsploit table mints exploit.edb_candidate',
      'minted=' + JSON.stringify(r.facts.map(f => f.kind))
    );
  }

  // 2B. Command-stripped mid-scroll PHP source disclosure with ANSI escapes
  {
    const rawPhp = '\x1b[36m<?php\x1b[0m\n$cfg_pass = "Vanguard#2026!xy";\n$data = unserialize($_COOKIE["sess_blob"]);\n?>';
    const r = OBOL.parsers.parseActionOutput({
      command: '',
      stdout: rawPhp,
      stderr: '',
      scope: 'host:' + target,
      target: target
    });
    const kinds = r.facts.map(f => f.kind);
    record(
      P,
      kinds.includes('web.source_disclosed') && kinds.includes('web.vuln_sink'),
      'Command-stripped ANSI-wrapped PHP source paste mints web.source_disclosed + web.vuln_sink',
      'minted=' + JSON.stringify(kinds)
    );
  }

  // 2C. Command-stripped mid-scroll SUID paste with custom binary under /srv/ or /var/backups/
  // host.js:483 (bareSuidList) explicitly supports /srv/ and /var/backups/, so mid-scroll paste
  // (command='') MUST reach _parse_linux_enum via _looks_like_linux_enum (host.js:771).
  {
    const midScrollSrvSuid = '/usr/bin/sudo\n/srv/kestrel_portal/sync_helper\n';
    const r = OBOL.parsers.parseActionOutput({
      command: '',
      stdout: midScrollSrvSuid,
      stderr: '',
      scope: 'host:' + target,
      target: target
    });
    const hasCustom = r.facts.some(f => f.kind === 'privesc.custom_binary');
    record(
      P,
      hasCustom,
      'Command-stripped mid-scroll SUID list with /srv/... custom binary mints privesc.custom_binary (assets/engine/parsers/host.js:771)',
      'assets/engine/parsers/host.js:771 _looks_like_linux_enum omits /srv/, /var/backups/, /home/, minting ' + JSON.stringify(r.facts.map(f => f.kind))
    );
  }

  // 2D. Command-stripped mid-scroll legacy Exploit-DB Python 2 PoC lacking modern "# Exploit Title:" header
  {
    const legacyMidScrollPoc = [
      '#!/usr/bin/python',
      '# Author: Research Lab',
      '# CVE: CVE-2024-88991',
      '# Software: KestrelPortal 2.1.4',
      'import urllib2, cookielib, sys',
      'proxies = {"http": "http://127.0.0.1:8080"}',
      'print "[+] Sending exploit stage to " + sys.argv[1]'
    ].join('\n');
    const r = OBOL.parsers.parseActionOutput({
      command: '',
      stdout: legacyMidScrollPoc,
      stderr: '',
      scope: 'host:' + target,
      target: target
    });
    const kinds = r.facts.map(f => f.kind);
    record(
      P,
      kinds.includes('exploit.script_inspected') && kinds.includes('exploit.hazard_py2'),
      'Command-stripped legacy Python 2 CVE PoC paste mints exploit.script_inspected + exploit.hazard_py2 (assets/engine/parsers/edb.js:316-340)',
      'assets/engine/parsers/edb.js:316-340 _looks_like_edb_script requires modern EDB header when command=="", minting ' + JSON.stringify(kinds)
    );
  }

  // 2E. Reordered / whitespace-warped Windows wmic service output with custom service path
  {
    const warpedWmic = [
      'StartMode   State     StartName           Name          PathName',
      'Auto        Running   LocalSystem         KestrelAgent  "C:\\KestrelApps\\Agent\\kestrel_svc.exe" --daemon'
    ].join('\r\n');
    const r = OBOL.parsers.parseActionOutput({
      command: 'wmic service get Name,State,StartMode,StartName,PathName',
      stdout: warpedWmic,
      stderr: '',
      scope: 'host:' + target,
      target: target
    });
    const hasWinCustom = r.facts.some(
      f => f.kind === 'privesc.custom_binary' && f.value && f.value.os === 'windows' && String(f.value.custom_bin || '').includes('kestrel_svc.exe')
    );
    record(
      P,
      hasWinCustom,
      'Column-reordered CRLF Windows wmic service table mints Windows privesc.custom_binary',
      'minted=' + JSON.stringify(r.facts.map(f => ({ kind: f.kind, value: f.value })))
    );
  }
}

// ============================================================================
// PROBE 3: Negative-Polarity & False-Positive Traps (forbidden_hits === 0)
// ============================================================================
function runProbe3() {
  const P = 'P3';
  console.log('\n=== PROBE 3: Negative-Polarity & False-Positive Traps ===');
  const OBOL = sandboxLoader.createSandbox();
  const target = '10.244.62.18';

  // 3A. searchsploit --help + "Exploits: No Results" + stock Apache/OpenSSH banners + closed ports
  {
    const negInputs = [
      {
        command: 'searchsploit --help',
        stdout: '  Usage: searchsploit [options] term1 [term2] ... [termN]\n  Example: searchsploit afd windows local\n  -m, --mirror [EDB-ID]   Mirror (aka copies) an exploit to the current working directory'
      },
      {
        command: 'searchsploit apache 2.4.58',
        stdout: 'Exploits: No Results\nShellcodes: No Results\nPapers: No Results\n'
      },
      {
        command: 'nmap -sV -p 22,80,445 ' + target,
        stdout: [
          'Nmap scan report for ' + target,
          'PORT    STATE  SERVICE      VERSION',
          '22/tcp  open   ssh          OpenSSH 9.2p1 Ubuntu 3ubuntu0.6',
          '80/tcp  open   http         Apache httpd 2.4.58 ((Ubuntu))',
          '445/tcp closed microsoft-ds',
          'Nmap done: 1 IP address (1 host up) scanned in 1.19 seconds'
        ].join('\n')
      },
      {
        command: "nxc smb " + target + " -u 'svc_kstrl' -p 'BadSecret!1'",
        stdout: 'SMB         ' + target + '    445    NODE01           [-] NODE01\\svc_kstrl:BadSecret!1 STATUS_LOGON_FAILURE'
      },
      {
        command: 'curl -si http://' + target + '/assets/app.css',
        stdout: 'HTTP/1.1 200 OK\nETag: "4f8a2b1c9d0e7f6a5b4c3d2e1f0a9b8c"\n\n/* cache digest 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d */\nbody { color: #222; } <!-- benign marketing comment -->'
      }
    ];

    const forbidden = new Set([
      'exploit.versioned_banner',
      'exploit.edb_candidate',
      'exploit.script_inspected',
      'credential.validated',
      'credential.available',
      'credential.candidate',
      'smb.authenticated',
      'smb.reachable',
      'objective.local_flag',
      'objective.root_flag',
      'objective.flag',
      'web.source_disclosed',
      'web.vuln_sink'
    ]);

    const hits = [];
    for (const item of negInputs) {
      const r = OBOL.parsers.parseActionOutput({
        command: item.command,
        stdout: item.stdout,
        stderr: '',
        scope: 'host:' + target,
        target: target
      });
      for (const f of r.facts) {
        if (!f.state || f.state === 'supported') {
          if (f.kind === 'smb.reachable' && /\bnxc\s+smb\b/i.test(item.command)) continue;
          if (forbidden.has(f.kind)) {
            hits.push(item.command + ' -> ' + f.kind);
          }
        }
      }
    }
    record(
      P,
      hits.length === 0,
      'Zero false-positive supported facts across --help, No Results, stock Apache/OpenSSH, STATUS_LOGON_FAILURE, 32-hex CSS ETag, and closed port 445',
      'forbidden_hits=' + JSON.stringify(hits)
    );
  }

  // 3B. Remote HTTP HTML tutorial mentioning C system("tar ...") MUST NOT mint Linux privesc or foothold!
  {
    const sess = sandboxLoader.createEngagementSession(OBOL, { target: target, lhost: '192.168.210.15' });
    sess.ingestTurn({
      target: target,
      command: 'curl -si http://' + target + '/tutorial.html',
      stdout: [
        'HTTP/1.1 200 OK',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><h1>C Archive Example</h1>',
        '<pre>int main(void) { return system("tar -czf archive.tgz /var/log"); }</pre>',
        '</body></html>'
      ].join('\n')
    });
    const sessMidScroll = sandboxLoader.createEngagementSession(OBOL, { target: target, lhost: '192.168.210.15' });
    sessMidScroll.ingestTurn({
      target: target,
      command: '',
      stdout: '<html><body><pre>int main(void) { return system("tar -czf archive.tgz /var/log"); }</pre></body></html>'
    });
    const kindsCurl = sortedSupportedKinds(sess.factSetForTarget(target));
    const kindsRaw = sortedSupportedKinds(sessMidScroll.factSetForTarget(target));
    const leaked = kindsCurl.filter(k => /^privesc\.|^foothold\./.test(k))
      .concat(kindsRaw.filter(k => /^privesc\.|^foothold\./.test(k)).map(k => 'midscroll:' + k));
    record(
      P,
      leaked.length === 0,
      'Benign remote HTML C tutorial with system("tar ...") must NOT mint privesc.path_hijack_candidate or fabricate foothold.linux (assets/engine/parsers/index.js:309, host.js:1401-1414, inference.js:1905-1921)',
      'fabricated facts on uncompromised remote web target: ' + JSON.stringify(leaked)
    );
  }

  // 3C. Disclosed remote PHP web source with system("ping ...") must mint web.vuln_sink ONLY, NOT local privesc.path_hijack_candidate or foothold.linux
  {
    const sess = sandboxLoader.createEngagementSession(OBOL, { target: target, lhost: '192.168.210.15' });
    sess.ingestTurn({
      target: target,
      command: 'curl -s http://' + target + '/ping.php.bak',
      stdout: '<?php\n$out = system("ping -c 1 " . $_GET["host"]);\necho $out;\n?>'
    });
    const kinds = sortedSupportedKinds(sess.factSetForTarget(target));
    const badPrivesc = kinds.filter(k => /^privesc\./.test(k));
    record(
      P,
      kinds.includes('web.vuln_sink') && badPrivesc.length === 0,
      'Remote PHP source disclosure with system("ping ...") must NOT cross-fire host.js _parse_binary_inspection into privesc.path_hijack_candidate (assets/engine/parsers/index.js:309, host.js:1405)',
      'cross-fired privesc facts=' + JSON.stringify(badPrivesc)
    );
  }

  // 3D. Stock Ubuntu /snap/core20 & /snap/core22 SUID mounts MUST NOT mint privesc.suid or privesc.custom_binary
  {
    const r = OBOL.parsers.parseActionOutput({
      command: 'find / -perm -4000 -type f 2>/dev/null',
      stdout: [
        '/usr/bin/passwd',
        '/usr/bin/sudo',
        '/snap/core20/1974/usr/bin/passwd',
        '/snap/core20/1974/usr/bin/sudo',
        '/snap/core22/858/usr/lib/snapd/snap-device-helper'
      ].join('\n'),
      stderr: '',
      scope: 'host:' + target,
      target: target
    });
    const suidLeaks = r.facts
      .filter(f => (!f.state || f.state === 'supported') && (f.kind === 'privesc.suid' || f.kind === 'privesc.custom_binary'))
      .map(f => f.kind + ':' + JSON.stringify(f.value));
    record(
      P,
      suidLeaks.length === 0,
      'Stock Ubuntu /snap/core20 and /snap/core22 SUID binaries must NOT mint privesc.suid or privesc.custom_binary (assets/engine/parsers/host.js:294-319)',
      'false-positive SUID facts=' + JSON.stringify(suidLeaks)
    );
  }

  // 3E. Client-side JS DOM password input lookup must NOT mint credential.candidate
  {
    const r = OBOL.parsers.parseActionOutput({
      command: 'curl -s http://' + target + '/static/app.js',
      stdout: [
        'const password = "";',
        'user_password = document.getElementById("pwd").value;',
        'login_password = form.elements.password;',
        'console.log("eval is prohibited in CSP");'
      ].join('\n'),
      stderr: '',
      scope: 'host:' + target,
      target: target
    });
    const bogusCreds = r.facts.filter(f => f.kind === 'credential.candidate');
    record(
      P,
      bogusCreds.length === 0,
      'Benign client-side JS document.getElementById("pwd").value must NOT mint credential.candidate (assets/engine/parsers/websource.js:166,184)',
      'bogus credential.candidate=' + JSON.stringify(bogusCreds.map(f => f.value))
    );
  }
}

// ============================================================================
// PROBE 4: Hostile Exploit-DB Broken-Script & Traceback Traps
// ============================================================================
function runProbe4() {
  const P = 'P4';
  console.log('\n=== PROBE 4: Hostile Exploit-DB Broken-Script & Traceback Traps ===');
  const OBOL = sandboxLoader.createSandbox();
  const target = '10.245.38.71';
  const sess = sandboxLoader.createEngagementSession(OBOL, {
    target: target,
    lhost: '192.168.215.22',
    lport: '4477'
  });

  // Stage 0 + Stage 1: Decoy-laden searchsploit output ((Metasploit) .rb + /dos/ + real RCE .py)
  sess.ingestTurn({
    target: target,
    command: 'nmap -sV -p 8282 ' + target,
    stdout: 'PORT     STATE SERVICE VERSION\n8282/tcp open  http    ZephyrCMS 4.2.0\nNmap done: 1 IP address (1 host up) scanned in 1.3s'
  });
  sess.ingestTurn({
    target: target,
    command: 'searchsploit ZephyrCMS 4.2',
    stdout: [
      '-------------------------------------------------------------------- ---------------------------------',
      ' Exploit Title                                                      |  Path',
      '-------------------------------------------------------------------- ---------------------------------',
      'ZephyrCMS 4.2.0 - Remote Crash Denial of Service                    | php/dos/97401.py',
      'ZephyrCMS 4.2.0 - Authenticated Code Execution (Metasploit)         | linux/remote/97402.rb',
      'ZephyrCMS <= 4.2.1 - Unauthenticated Remote Code Execution          | php/webapps/97403.py',
      '-------------------------------------------------------------------- ---------------------------------'
    ].join('\n')
  });

  const edbFacts = sess.factSetForTarget(target).facts.filter(f => f.kind === 'exploit.edb_candidate');
  const chosenIds = edbFacts.map(f => f.value && f.value.edb_id);
  record(
    P,
    chosenIds.includes('97403') && !chosenIds.includes('97401') && !chosenIds.includes('97402'),
    'searchsploit filters out /dos/ and (Metasploit) .rb decoys, retaining standalone RCE 97403.py',
    'chosen edb_ids=' + JSON.stringify(chosenIds)
  );

  // Stage 2: Broken Python 2 script with CRLF endings, Latin-1 byte comment, and leftover 127.0.0.1:8080 Burp proxy
  sess.ingestTurn({
    target: target,
    command: 'head -n 80 97403.py',
    stdout: [
      '#!/usr/bin/python',
      '# Exploit Title: ZephyrCMS <= 4.2.1 - Unauthenticated RCE',
      '# Author: R\xe9mi Security',
      '# EDB-ID: 97403',
      'import urllib2, cookielib, argparse',
      'proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}',
      'parser = argparse.ArgumentParser()',
      'parser.add_argument("--url", required=True)',
      'parser.add_argument("--lhost", required=True)',
      'parser.add_argument("--lport", required=True)',
      'print "[+] Firing exploit..."'
    ].join('\r\n')
  });

  const stage2Kinds = sortedSupportedKinds(sess.factSetForTarget(target));
  record(
    P,
    stage2Kinds.includes('exploit.hazard_py2') && stage2Kinds.includes('exploit.hazard_burp_proxy'),
    'Broken CRLF Python 2 + 127.0.0.1:8080 Burp script mints exploit.hazard_py2 + exploit.hazard_burp_proxy',
    'stage2Kinds=' + JSON.stringify(stage2Kinds)
  );

  // Stage 2 Cockpit UI check: pre-execution hazards MUST surface a repair card or diagnostic banner BEFORE crashing!
  const stage2Coach = sess.computeCoach(target);
  const stage2Html = OBOL.routes.path.render();
  const stage2HasRepair =
    stage2Coach.onFlow.some(a => /^fix-edb-/.test(a.id)) ||
    stage2Html.includes('fix-card');
  record(
    P,
    stage2HasRepair,
    'Stage 2 pre-execution exploit.hazard_* surfaces a repair card or diagnostic banner in Cockpit before crashing (assets/ui/routes/path.js:1528-1533,722-771)',
    'assets/ui/routes/path.js:1528 isCanvasDoctor drops all fix-edb-* cards from onFlow while OBOL.FIELD_DOCTORS lacks exploit.hazard_* keys; Stage 2 Cockpit shows 0 repair guidance'
  );

  // Stage 3: Runtime Python 2 SyntaxError + PEP 668 + TLS cert verify + GLIBC mismatch
  sess.ingestTurn({
    target: target,
    command: 'python3 97403.py --url http://' + target + ':8282 --lhost 192.168.215.22 --lport 4477',
    stdout: '  File "97403.py", line 11\n    print "[+] Firing exploit..."\nSyntaxError: Missing parentheses in call to \'print\'. Did you mean print(...)?'
  });

  const latestAct = (sess.eng.activities || [])[0] || {};
  const py2Outcome = latestAct.outcome || {};
  record(
    P,
    py2Outcome.kind === 'environment-error' && py2Outcome.next === 'repair',
    'Runtime Python 2 SyntaxError classifies outcome as kind="environment-error", next="repair" (assets/engine/outcomes.js:136-137)',
    'assets/engine/outcomes.js:136-137 omits Phase 0 runtime blockers and SyntaxError:, returning ' + JSON.stringify({ kind: py2Outcome.kind, status: py2Outcome.status, next: py2Outcome.next })
  );

  const stage3Html = OBOL.routes.path.render();
  const fixCodeMatch = stage3Html.match(/<pre class="fix-card-code"><code>([\s\S]*?)<\/code><\/pre>/);
  const fixCode = fixCodeMatch ? fixCodeMatch[1] : '';
  record(
    P,
    fixCode.includes('97403.py') && !fixCode.includes('&lt;exploit.py&gt;') && !fixCode.includes('<exploit.py>'),
    'Stage 3 Cockpit Diagnostic Fix Card binds proven 97403.py instead of literal <exploit.py> shell-redirection text (data/field-notes.js:15889-15893, assets/ui/routes/path.js:751-760)',
    'rendered fix-card code="' + fixCode + '"'
  );

  // Verify PEP 668 and GLIBC runtime blocker detection in blockers.js + outcomes.js
  for (const rt of [
    {
      label: 'PEP 668 externally-managed-environment',
      cmd: 'pip3 install pycryptodome',
      out: 'error: externally-managed-environment\n\nThis environment is externally managed.',
      expectedBlocker: 'blocker.python_dep_or_pep668'
    },
    {
      label: 'Target GLIBC_2.38 mismatch',
      cmd: './exploit_elf',
      out: './exploit_elf: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38\' not found (required by ./exploit_elf)',
      expectedBlocker: 'blocker.glibc_or_arch_mismatch'
    }
  ]) {
    sess.ingestTurn({ target: target, command: rt.cmd, stdout: rt.out });
    const hasBlocker = sess.factSetForTarget(target).has(rt.expectedBlocker);
    const actOut = ((sess.eng.activities || [])[0] || {}).outcome || {};
    record(
      P,
      hasBlocker,
      rt.label + ' mints ' + rt.expectedBlocker,
      'missing ' + rt.expectedBlocker
    );
    record(
      P,
      actOut.kind === 'environment-error',
      rt.label + ' classifies outcome as environment-error (assets/engine/outcomes.js:136-137)',
      'assets/engine/outcomes.js:136-137 returned kind="' + actOut.kind + '" instead of "environment-error"'
    );
  }
}

// ============================================================================
// PROBE 5: Noisy Dead-End & Closed-Loop Retirement Stress
// ============================================================================
function runProbe5() {
  const P = 'P5';
  console.log('\n=== PROBE 5: Noisy Dead-End & Closed-Loop Retirement Stress ===');

  // 5A. Web/SMB host with 4 dead-end probes + failed cross-host password reuse -> winning EDB chain promotes to #1
  {
    const OBOL = sandboxLoader.createSandbox();
    const target = '10.246.51.29';
    const sess = sandboxLoader.createEngagementSession(OBOL, {
      target: target,
      lhost: '192.168.219.12',
      lport: '4488'
    });

    sess.ingestTurn({
      target: target,
      command: 'nmap -sV -p 445,8088 ' + target,
      stdout: 'PORT     STATE SERVICE VERSION\n445/tcp  open  microsoft-ds?\n8088/tcp open  http    OrbitalWiki 3.4.1\nNmap done: 1 IP address (1 host up) scanned in 2.0s'
    });

    // 4 noisy dead ends (failed cross-host cred reuse, null SMB denied, empty vhost scan, dry nikto)
    sess.ingestTurn({
      target: target,
      command: "nxc smb " + target + " -u 'svc_oldhost' -p 'StalePass#99'",
      stdout: 'SMB         ' + target + '    445    WEB02            [-] WEB02\\svc_oldhost:StalePass#99 STATUS_LOGON_FAILURE'
    });
    sess.ingestTurn({
      target: target,
      command: "nxc smb " + target + " -u '' -p '' --shares",
      stdout: 'SMB         ' + target + '    445    WEB02            [-] WEB02\\: STATUS_ACCESS_DENIED'
    });
    sess.ingestTurn({
      target: target,
      actionId: 'vhost-discovery',
      command: 'ffuf -u http://' + target + ':8088 -H "Host: FUZZ.orbital.internal" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1420',
      stdout: '[OBOL: completed with no output / nothing found]'
    });
    sess.ingestTurn({
      target: target,
      actionId: 'nikto-scan',
      command: 'nikto -h http://' + target + ':8088',
      stdout: '[OBOL: completed with no output / nothing found]'
    });

    const fset = sess.factSetForTarget(target);
    record(
      P,
      !fset.has('credential.validated') && !fset.has('smb.authenticated'),
      'Failed cross-host password reuse + null SMB denial do not leak authenticated facts',
      'kinds=' + JSON.stringify(sortedSupportedKinds(fset))
    );

    const reachLookup = harvestTraj.evaluateClosedLoopReachability(
      sess,
      [{ id: 'edb-searchsploit-lookup' }],
      { command: 'searchsploit OrbitalWiki 3.4' },
      { targetIp: target }
    );
    record(
      P,
      reachLookup.reachable === true,
      'After 4 dead-end probes, edb-searchsploit-lookup promotes to #1 via closed-loop retirement',
      JSON.stringify(reachLookup)
    );

    sess.ingestTurn({
      target: target,
      command: 'searchsploit OrbitalWiki 3.4',
      stdout: 'Exploit Title                                        |  Path\n----------------------------------------------------- ---------------------------------\nOrbitalWiki <= 3.5.0 - Remote Code Execution         | php/webapps/98311.py\n'
    });
    const reachMirror = harvestTraj.evaluateClosedLoopReachability(
      sess,
      [{ id: 'edb-mirror-and-inspect' }],
      { command: 'searchsploit -m 98311' },
      { targetIp: target }
    );
    record(
      P,
      reachMirror.reachable === true,
      'edb-mirror-and-inspect promotes to #1 via closed-loop retirement',
      JSON.stringify(reachMirror)
    );

    sess.ingestTurn({
      target: target,
      command: 'head -n 40 98311.py',
      stdout: '#!/usr/bin/env python3\n# Exploit Title: OrbitalWiki RCE\n# EDB-ID: 98311\nimport requests\nparser.add_argument("--url", required=True)\n'
    });
    const reachRun = harvestTraj.evaluateClosedLoopReachability(
      sess,
      [{ id: 'edb-run-adapted-exploit' }],
      { command: 'python3 98311.py --url http://' + target + ':8088' },
      { targetIp: target }
    );
    record(
      P,
      reachRun.reachable === true,
      'edb-run-adapted-exploit promotes to #1 via closed-loop retirement',
      JSON.stringify(reachRun)
    );
  }

  // 5B. Out-of-order Linux foothold jump + 3 dead-end privesc probes -> custom binary triage -> PATH hijack #1
  {
    const OBOL = sandboxLoader.createSandbox();
    const target = '172.28.177.63';
    const sess = sandboxLoader.createEngagementSession(OBOL, {
      target: target,
      lhost: '192.168.219.12',
      lport: '4488'
    });

    // Out-of-order shell paste without prior nmap
    sess.ingestTurn({ target: target, command: 'id', stdout: 'uid=1009(op_vanguard) gid=1009(op_vanguard) groups=1009(op_vanguard)' });
    sess.ingestTurn({ target: target, actionId: 'linux-orient', command: 'sudo -l', stdout: 'Sorry, user op_vanguard may not run sudo on node-77.' });
    sess.ingestTurn({ target: target, actionId: 'capabilities', command: 'getcap -r / 2>/dev/null', stdout: '[OBOL: completed with no output / nothing found]' });
    sess.ingestTurn({ target: target, command: 'find /usr/bin -perm -4000 2>/dev/null', stdout: '/usr/bin/passwd\n/usr/bin/su\n/usr/bin/sudo' });

    // Winning custom SUID discovery
    sess.ingestTurn({
      target: target,
      command: 'find / -perm -4000 -type f 2>/dev/null',
      stdout: '/usr/bin/passwd\n/usr/bin/sudo\n/opt/kestrel_agent/pulse_ctl'
    });
    const reachTriage = harvestTraj.evaluateClosedLoopReachability(
      sess,
      [{ id: 'linux-custom-binary-triage' }],
      { command: 'strings -a /opt/kestrel_agent/pulse_ctl' },
      { targetIp: target }
    );
    record(
      P,
      reachTriage.reachable === true,
      'Out-of-order foothold + 3 dead-end privesc probes promotes linux-custom-binary-triage to #1',
      JSON.stringify(reachTriage)
    );

    sess.ingestTurn({
      target: target,
      command: 'strings -a -n 5 /opt/kestrel_agent/pulse_ctl',
      stdout: 'GLIBC_2.34\nsystem("log_rotator --compress")\nDone.'
    });
    const reachHijack = harvestTraj.evaluateClosedLoopReachability(
      sess,
      [{ id: 'linux-path-hijack' }],
      { command: 'export PATH=/tmp:$PATH' },
      { targetIp: target }
    );
    record(
      P,
      reachHijack.reachable === true,
      'After strings reveals bare system() call, linux-path-hijack promotes to #1',
      JSON.stringify(reachHijack)
    );
  }

  // 5C. Sandbox snapshot()/restore() isolation across module-scoped ingest copiedQueue
  {
    const OBOL = sandboxLoader.createSandbox();
    const sess = sandboxLoader.createEngagementSession(OBOL, { target: '10.246.51.99' });
    const snap = sess.snapshot();
    if (OBOL.ingest && OBOL.ingest.recordCopy) {
      OBOL.ingest.recordCopy({ command: 'nmap -p- 10.246.51.99', actionId: 'nmap-full-tcp', target: '10.246.51.99' });
    }
    sess.restore(snap);
    const leaked = (OBOL.ingest && OBOL.ingest.consumeCopy) ? OBOL.ingest.consumeCopy('') : null;
    record(
      P,
      leaked === null,
      'sandbox-loader snapshot()/restore() isolates module-scoped ingest copiedQueue with zero leakage',
      'leaked=' + JSON.stringify(leaked)
    );
  }
}

// ============================================================================
// PROBE 6: Zero-Overfit, Asset Cache-Bust & House-Style Scan
// ============================================================================
function runProbe6() {
  const P = 'P6';
  console.log('\n=== PROBE 6: Zero-Overfit, Asset Cache-Bust & House-Style Scan ===');

  // 6A. Self-audit of this adversarial test file first (must be 100% clean)
  {
    const selfScan = overfitScanner.runVerifyNoOverfit({
      qaRoot: QA_ROOT,
      files: ['tests/engine/phase0-redteam-adversarial-smoke.js']
    });
    record(
      P,
      selfScan.ok === true && selfScan.violations.length === 0,
      'phase0-redteam-adversarial-smoke.js passes verify-no-overfit with 0 overfit/style violations',
      JSON.stringify(selfScan.violations)
    );
  }

  // 6B. Default branch git-diff verify-no-overfit gate
  {
    const branchScan = overfitScanner.runVerifyNoOverfit({ qaRoot: QA_ROOT });
    record(
      P,
      branchScan.ok === true && branchScan.violations.length === 0,
      'Branch git-diff passes verify-no-overfit.js with 0 violations (tools/corpus/verify-no-overfit.js:516-543, data/packs-bundle.js:6)',
      'verify-no-overfit found ' + branchScan.violations.length + ' violation(s): ' +
        JSON.stringify(branchScan.violations.map(v => v.file + ':' + v.line + ':' + v.rule + ':' + v.token))
    );
  }

  // 6C. Browser cache-busting ?v=<sha1_8> parity in assets/ui/lazy.js and index.html
  {
    const drifts = [];
    for (const hostFile of ['assets/ui/lazy.js', 'index.html']) {
      const src = fs.readFileSync(path.join(QA_ROOT, hostFile), 'utf8');
      const re = /(['"])((?:assets|data)\/[^'"?]+?\.(?:js|css))(?:\?v=([0-9a-f]+))?(\1)/g;
      let m;
      while ((m = re.exec(src)) !== null) {
        const assetRel = m[2];
        const curHash = m[3] || '(none)';
        const expHash = sha1_8(assetRel);
        if (curHash !== expHash) {
          drifts.push(hostFile + ' -> ' + assetRel + ' [cur=' + curHash + ', exp=' + expHash + ']');
        }
      }
    }
    record(
      P,
      drifts.length === 0,
      'All shipped asset URLs in assets/ui/lazy.js and index.html carry fresh ?v=<sha1_8> stamps (assets/ui/lazy.js:19)',
      drifts.length + ' unstamped/stale asset URL(s): ' + drifts.slice(0, 6).join('; ')
    );
  }
}

// ============================================================================
// PROBE 7: Cross-Corpus Structural & Multi-Target Isolation Invariants
// ============================================================================
function runProbe7() {
  const P = 'P7';
  console.log('\n=== PROBE 7: Cross-Corpus Structural & Multi-Target Isolation Invariants ===');

  const OBOL = sandboxLoader.createSandbox();
  const actions = OBOL.packs.actions();
  const byId = {};
  for (const a of actions) byId[a.id] = a;

  const requiredPhase0Moves = [
    'edb-searchsploit-lookup',
    'edb-mirror-and-inspect',
    'edb-run-adapted-exploit',
    'fix-edb-py2',
    'fix-edb-python-deps',
    'fix-edb-proxy-tls',
    'fix-edb-c-compile',
    'linux-custom-binary-triage',
    'linux-shared-library-hijack',
    'windows-custom-binary-triage',
    'web-source-sink-audit',
    'web-vuln-sink-exploit'
  ];

  const missingMoves = requiredPhase0Moves.filter(id => !byId[id]);
  record(
    P,
    missingMoves.length === 0,
    'All 12 Phase 0 moves are registered in packs-bundle and compiled in OBOL.packs.actions()',
    'missing=' + JSON.stringify(missingMoves)
  );

  // Verify every Phase 0 move has authored OBOL.FIELD_MOVE and OBOL.FIELD_NOTES coverage
  const missingNotes = requiredPhase0Moves.filter(id => {
    const m = byId[id];
    if (!m) return true;
    const fm = (OBOL.FIELD_MOVE || {})[id];
    const fn = (OBOL.FIELD_NOTES || {})[id];
    return !fm || !fm.what || !Array.isArray(fn) || fn.length < (m.commands || []).length;
  });
  record(
    P,
    missingNotes.length === 0,
    'All 12 Phase 0 moves have 100% OBOL.FIELD_MOVE and per-command OBOL.FIELD_NOTES coverage',
    'missingNotes=' + JSON.stringify(missingNotes)
  );

  // Verify multi-target scope isolation: Host A web/EDB/privesc facts never bleed onto Host B
  {
    const hostA = '10.247.12.11';
    const hostB = '10.247.12.22';
    const sess = sandboxLoader.createEngagementSession(OBOL, {
      targets: [hostA, hostB],
      lhost: '192.168.221.5',
      multiTarget: true
    });
    sess.ingestTurn({
      target: hostA,
      command: 'searchsploit ZephyrCMS 4.2',
      stdout: 'Exploit Title                                    |  Path\n------------------------------------------------- ---------------------------------\nZephyrCMS 4.2.0 - Remote Code Execution          | php/webapps/97555.py\n'
    });
    sess.ingestTurn({
      target: hostA,
      command: 'find / -perm -4000 -type f 2>/dev/null',
      stdout: '/usr/bin/sudo\n/opt/zephyr/helper_suid'
    });
    const kindsB = sortedSupportedKinds(sess.factSetForTarget(hostB));
    const bleed = kindsB.filter(k => /^exploit\.|^privesc\.|^foothold\./.test(k));
    record(
      P,
      bleed.length === 0,
      'Multi-target scope isolation: Host A exploit.* and privesc.* facts never bleed into Host B FactSet',
      'bleed on Host B=' + JSON.stringify(bleed)
    );
  }
}

function main() {
  console.log('OBOL Phase 0 Independent Red-Team Adversarial Smoke Suite');
  runProbe1();
  runProbe2();
  runProbe3();
  runProbe4();
  runProbe5();
  runProbe6();
  runProbe7();

  console.log('\n============================================================');
  console.log('PHASE 0 RED-TEAM SUMMARY: ' + results.passed + ' passed, ' + results.failed + ' failed');
  for (const pid of Object.keys(results.byProbe)) {
    const s = results.byProbe[pid];
    const verdict = s.failed === 0 ? 'PASS' : 'FAIL';
    console.log('  ' + pid + ': ' + verdict + ' (' + s.passed + ' passed, ' + s.failed + ' failed)');
  }
  if (results.failures.length > 0) {
    console.log('\nUNCOVERED DEFECT REPRODUCTION LEDGER (' + results.failures.length + '):');
    results.failures.forEach((f, idx) => {
      console.log('  ' + (idx + 1) + '. [' + f.probe + '] ' + f.label);
      console.log('     Evidence: ' + f.detail);
    });
    process.exitCode = 1;
  } else {
    console.log('\nALL 7 ADVERSARIAL PROBES PASSED.');
    process.exitCode = 0;
  }
}

main();
