#!/usr/bin/env node
/*
 * tools/corpus/harvest-trajectories.js - Pass 2: Stateful Kill-Chain & Closed-Loop
 * Retirement Harvester (qa-only; never ships to prod, never runs at runtime).
 *
 * Chronologically replays extracted walkthrough turns (plus spliced OCR sidecar turns
 * and optional SharpHound/BloodHound JSON bundles) into a stateful OBOL engagement
 * session (single-target or --multi-target).
 *
 * Before executing each actionable operator turn b_t, evaluates OBOL's Closed-Loop #1
 * Reachability Contract:
 *   1. Candidate catalog move a is eligible (a.eligible(facts)) and has at least one
 *      runnable command with zero unfilled EARNED_TOKENS.
 *   2. Candidate move a either:
 *      (a) sits directly at #1 in Ready Now (coach.onFlow[0]), or within Top-4 (#1..#4)
 *          at an unprobed initial multi-port recon fork (>= 2 open ports in anon epoch
 *          before service-specific probes run), OR
 *      (b) sits at #k (k > 1) in Ready Now, and simulating immediate flag settlement
 *          (for objective flag-collection cards) or Cockpit .mi-empty completed-negative
 *          dry-probe retirement on preceding cards 1..k-1 (inside a snapshot/restore
 *          sandbox transaction) promotes a to #1.
 *
 * Any unreachable turn is classified into one of five diagnostic stall buckets:
 *   - PARSE_OR_SHAPE_MISS
 *   - GATE_DEADLOCK_OR_UNDERGATED_GAMBLE
 *   - UNFILLED_EARNED_TOKEN
 *   - OUTCOME_OR_RETIREMENT_STALL
 *   - CLOSED_LOOP_RANK_STALL
 *
 * Usage:
 *   node tools/corpus/harvest-trajectories.js [--corpus-dir <dir>] [--slugs a,b,c]
 *     [--multi-target] [--include-alternates] [--limit <n>] [--lens <oscp+|all>]
 *     [--out <report.json>]
 *
 * House style: no em dashes, no en dashes, no emoji.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const {
  createSandbox,
  createEngagementSession
} = require('./sandbox-loader');

const {
  ATTACKER_HOST,
  extractWalkthroughTurns,
  discoverAlternates
} = require('./markdown-extractor');

const QA_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_CORPUS_DIR = path.join(QA_ROOT, 'tests', 'corpus', '0xdf-oscp', 'walkthroughs');

const STALL_BUCKETS = [
  'PARSE_OR_SHAPE_MISS',
  'GATE_DEADLOCK_OR_UNDERGATED_GAMBLE',
  'UNFILLED_EARNED_TOKEN',
  'OUTCOME_OR_RETIREMENT_STALL',
  'CLOSED_LOOP_RANK_STALL'
];

const IPV4_GLOBAL_RE = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;
const ATTACKER_SUBNET_RE = /^(?:10\.10\.1[4-7]\.\d{1,3}|192\.168\.4[589]\.\d{1,3})$/;
const LHOST_PROMPT_RE = /\[(?:tun|tap|vpn|wg|eth)\d*[:/ ]\s*(\d{1,3}(?:\.\d{1,3}){3})\]/i;
const LHOST_ARG_RE = /(?:LHOST\s*=\s*|--lhost(?:=|\s+)|-l\s+)(\d{1,3}(?:\.\d{1,3}){3})\b/i;
const SHELL_VAR_ASSIGN_RE = /^(?:export\s+)?(ip|IP|target|TARGET|rhost|RHOST|host|HOST|dc|DC|dc_ip|DC_IP)=(['"]?)(\d{1,3}(?:\.\d{1,3}){3})\2\s*$/;

const DRY_PROBE_SENTINEL = '[OBOL: completed with no output / nothing found]';

function isRoutableIpv4(ip) {
  if (!ip) return false;
  const parts = String(ip).split('.');
  if (parts.length !== 4) return false;
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
  }
  const o0 = Number(parts[0]);
  const o1 = Number(parts[1]);
  const o3 = Number(parts[3]);
  if (o0 === 0 || o0 === 127 || o0 >= 224) return false;
  if (o0 === 169 && o1 === 254) return false;
  if (o3 === 0 || o3 === 255) return false;
  if (ip === '8.8.8.8' || ip === '8.8.4.4' || ip === '1.1.1.1' || ip === '1.0.0.1') return false;
  return true;
}

function isPrivateLabIpv4(ip) {
  if (!isRoutableIpv4(ip)) return false;
  const p = ip.split('.').map(Number);
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  return false;
}

function resolveWalkthroughDir(dirInput) {
  const raw = dirInput ? path.resolve(dirInput) : DEFAULT_CORPUS_DIR;
  if (fs.existsSync(path.join(raw, 'walkthroughs')) && fs.statSync(path.join(raw, 'walkthroughs')).isDirectory()) {
    return {
      corpusRoot: raw,
      walkthroughDir: path.join(raw, 'walkthroughs')
    };
  }
  return {
    corpusRoot: path.dirname(raw),
    walkthroughDir: raw
  };
}

function stripCommandWrappers(cmd) {
  let s = String(cmd || '').trim();
  if (!s) return '';
  let changed = true;
  while (changed) {
    changed = false;
    const next = s
      .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S+)\s+)+/, '')
      .replace(/^(?:proxychains4?(?:\s+-q|\s+-f\s+\S+)*|time|rlwrap(?:\s+-[A-Za-z0-9]+)*|stdbuf(?:\s+-\S+)*|timeout\s+\S+)\s+/i, '');
    if (next !== s) {
      s = next.trim();
      changed = true;
    }
  }
  if (/^sudo\b/i.test(s) && !/^sudo\s+(?:-l\b|--list\b|-V\b|--version\b)/i.test(s)) {
    const afterSudo = s.replace(/^sudo(?:\s+(?:-[uUggh]\s+\S+|-[A-Za-z]+))*\s+/i, '').trim();
    const head = (afterSudo.split(/\s+/)[0] || '').split(/[\\/]/).pop().toLowerCase();
    if (/^(?:nmap|masscan|rustscan|responder|ntlmrelayx|mitm6|chisel|ligolo|socat|tcpdump|openvpn|ip| mount|python3?)$/i.test(head)) {
      s = afterSudo;
    }
  }
  return s;
}

function canonicalTool(rawToken) {
  const base = String(rawToken || '')
    .trim()
    .replace(/^["']|["']$/g, '')
    .split(/[\\/]/)
    .pop()
    .toLowerCase()
    .replace(/;+$/, '')
    .replace(/\.(?:py|exe|sh|ps1|pl|rb|bin)$/i, '');

  if (!base) return '';
  if (/^(?:nxc|netexec|crackmapexec|cme)$/.test(base)) return 'nxc';
  if (base.startsWith('impacket-')) return base.slice(9);
  if (base === 'certipy-ad') return 'certipy';
  if (base === 'enum4linux-ng') return 'enum4linux';
  if (base === 'bloodhound-python' || base === 'bloodhound-ce-python') return 'bloodhound';
  if (base === 'python3' || base === 'python2') return 'python';
  if (base === 'pwsh') return 'powershell';
  if (base === 'ncat' || base === 'netcat') return 'nc';
  if (base === 'xfreerdp3' || base === 'rdesktop') return 'xfreerdp';
  return base;
}

function extractPrimaryTool(cmd) {
  const clean = stripCommandWrappers(cmd);
  if (!clean) return '';
  const toks = clean.split(/\s+/);
  const first = canonicalTool(toks[0]);
  if (first === 'python' && toks.length > 1) {
    if (toks[1] === '-m' && toks[2]) return 'python -m ' + toks[2].toLowerCase();
    const scriptTool = canonicalTool(toks[1]);
    if (scriptTool && !scriptTool.startsWith('-')) return scriptTool;
  }
  return first;
}

function inferEngagementNetworking(turns, opts) {
  opts = opts || {};
  let lhost = opts.lhost || '';
  const selfIps = new Set();
  if (lhost) selfIps.add(lhost);

  const varMap = Object.create(null);
  const candidateCounts = Object.create(null);
  const candidateOrder = [];

  function noteTargetIp(ip, weight) {
    if (!isPrivateLabIpv4(ip)) return;
    if (selfIps.has(ip) || ATTACKER_SUBNET_RE.test(ip)) return;
    if (!candidateCounts[ip]) {
      candidateCounts[ip] = 0;
      candidateOrder.push(ip);
    }
    candidateCounts[ip] += (weight || 1);
  }

  for (const t of turns || []) {
    const pLine = String(t.promptLine || '');
    const cmd = String(t.command || '');
    const out = String(t.stdout || t.output || '');

    const pm = LHOST_PROMPT_RE.exec(pLine);
    if (pm && isPrivateLabIpv4(pm[1])) {
      if (!lhost) lhost = pm[1];
      selfIps.add(pm[1]);
    }
    const lm = LHOST_ARG_RE.exec(cmd);
    if (lm && isPrivateLabIpv4(lm[1])) {
      if (!lhost) lhost = lm[1];
      selfIps.add(lm[1]);
    }

    const isAttackerHost = !t.host || ATTACKER_HOST.test(t.host);
    if (isAttackerHost && /^(?:sudo\s+)?(?:ip\s+(?:-\d\s+)?a(?:ddr)?|ifconfig|hostname\s+-I)\b/i.test(cmd.trim())) {
      let m;
      IPV4_GLOBAL_RE.lastIndex = 0;
      while ((m = IPV4_GLOBAL_RE.exec(out)) !== null) {
        if (isPrivateLabIpv4(m[1])) {
          selfIps.add(m[1]);
          if (!lhost && ATTACKER_SUBNET_RE.test(m[1])) lhost = m[1];
        }
      }
    }

    let am;
    IPV4_GLOBAL_RE.lastIndex = 0;
    while ((am = IPV4_GLOBAL_RE.exec(cmd + '\n' + out)) !== null) {
      if (ATTACKER_SUBNET_RE.test(am[1])) {
        selfIps.add(am[1]);
        if (!lhost) lhost = am[1];
      }
    }
  }

  for (const t of turns || []) {
    const cmd = String(t.command || '').trim();
    const out = String(t.stdout || t.output || '');

    const vm = SHELL_VAR_ASSIGN_RE.exec(cmd);
    if (vm && isPrivateLabIpv4(vm[3]) && !selfIps.has(vm[3])) {
      varMap[vm[1]] = vm[3];
      noteTargetIp(vm[3], 5);
    }

    const nmapM = /Nmap scan report for (?:[^\r\n(]+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?/i.exec(out);
    if (nmapM) noteTargetIp(nmapM[1], 6);

    const nxcM = /^(?:SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+/im.exec(out);
    if (nxcM) noteTargetIp(nxcM[1], 5);

    let cm;
    IPV4_GLOBAL_RE.lastIndex = 0;
    while ((cm = IPV4_GLOBAL_RE.exec(cmd)) !== null) {
      const ip = cm[1];
      if (!selfIps.has(ip)) noteTargetIp(ip, 3);
    }
  }

  if (!lhost) lhost = '10.10.14.5';
  selfIps.add(lhost);

  const sortedTargets = candidateOrder
    .filter(ip => !selfIps.has(ip))
    .sort((a, b) => (candidateCounts[b] - candidateCounts[a]) || (candidateOrder.indexOf(a) - candidateOrder.indexOf(b)));

  const primaryTarget = opts.target || sortedTargets[0] || '10.10.10.50';
  if (sortedTargets.indexOf(primaryTarget) < 0) sortedTargets.unshift(primaryTarget);

  return {
    lhost: lhost,
    primaryTarget: primaryTarget,
    targets: sortedTargets,
    selfIps: Array.from(selfIps),
    varMap: varMap
  };
}

function expandShellTargetVars(command, activeTarget, varMap) {
  let s = String(command || '');
  if (!s || s.indexOf('$') < 0) return s;
  const map = Object.assign({
    ip: activeTarget,
    IP: activeTarget,
    target: activeTarget,
    TARGET: activeTarget,
    rhost: activeTarget,
    RHOST: activeTarget,
    host: activeTarget,
    HOST: activeTarget
  }, varMap || {});

  s = s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)\b/g, (full, braced, bare) => {
    const key = braced || bare;
    return Object.prototype.hasOwnProperty.call(map, key) && map[key] ? map[key] : full;
  });
  return s;
}

function isAttackerTurn(turn) {
  if (!turn) return true;
  if (turn.kind === 'powershell' || turn.kind === 'cmd') return false;
  if (turn.hostHint === 'windows') return false;
  if (turn.host && !ATTACKER_HOST.test(turn.host)) return false;
  if (turn.user && /^(?:www-data|apache|nginx| daemon|nobody|postgres|mysql|mssql|tomcat|jenkins|svc[_-])/i.test(turn.user)) {
    return false;
  }
  return !turn.host || ATTACKER_HOST.test(turn.host);
}

function isHousekeepingTurn(turn) {
  const rawCmd = String((turn && turn.command) || '').trim();
  const out = String((turn && (turn.stdout || turn.output)) || '').trim();
  if (!rawCmd) {
    return { housekeeping: !out, reason: out ? 'unprompted_output' : 'empty_turn' };
  }

  if (SHELL_VAR_ASSIGN_RE.test(rawCmd) || /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S+)$/.test(rawCmd)) {
    return { housekeeping: true, reason: 'shell_var_assignment' };
  }

  const clean = stripCommandWrappers(rawCmd);
  const first = (clean.split(/[\s;|&]+/)[0] || '').toLowerCase();

  if (/^(?:cd|pwd|clear|cls|exit|logout|quit|history|alias|unalias|reset|fg|bg|jobs)$/.test(first)) {
    return { housekeeping: true, reason: 'shell_navigation' };
  }
  if (/^(?:vim?|nano|emacs|mousepad|gedit|kate|code|subl|less|more)$/.test(first)) {
    return { housekeeping: true, reason: 'editor_or_pager' };
  }
  if (/^(?:stty\b|export\s+TERM=|script\s+\/dev\/null|python3?\s+-c\s+['"]import\s+pty)/.test(clean)) {
    return { housekeeping: true, reason: 'tty_stabilization' };
  }
  if (/^(?:python3?\s+-m\s+(?:http\.server|pyftpdlib)|python\s+-m\s+SimpleHTTPServer|php\s+-S\b|updog\b|impacket-smbserver\b|smbserver(?:\.py)?\b)/i.test(clean)) {
    return { housekeeping: true, reason: 'local_staging_server' };
  }
  if (/^(?:nc|ncat|netcat|penelope)\b/i.test(clean) && /\s-[A-Za-z]*l[A-Za-z]*\b/.test(clean)) {
    return { housekeeping: true, reason: 'local_listener_wait' };
  }

  if (isAttackerTurn(turn)) {
    if (/^(?:mkdir|rmdir|touch|cp|mv|rm|chmod|chown|tar|unzip|zip|gunzip|wget\s+https?:\/\/(?:github\.com|raw\.githubusercontent\.com)|git\s+clone)\b/i.test(clean)) {
      return { housekeeping: true, reason: 'attacker_workspace_prep' };
    }
    if (/^(?:ls|ll|la|dir|cat|head|tail|echo|printf|tee|sed|awk|cut|sort|uniq|wc|tr|file|md5sum|sha256sum)\b/i.test(clean)) {
      if (!/(?:id_rsa|\.kdbx|\.pfx|\.psafe3|shadow|passwd|ntds|sam\b|system\b|credentials|config|\.env|web\.config|wp-config)/i.test(clean)) {
        return { housekeeping: true, reason: 'attacker_local_file_op' };
      }
    }
    if (/^(?:ip\s+a(?:ddr)?|ifconfig|hostname\s+-I|ping)\b/i.test(clean)) {
      return { housekeeping: true, reason: 'attacker_network_check' };
    }
  }

  return { housekeeping: false, reason: '' };
}

function isCanvasDoctorMove(a, facts) {
  const gates = (a.requires_all || []).concat(a.requires_any || []);
  const blockerGates = gates.filter(k => /^blocker\./.test(k));
  if (blockerGates.length > 0) {
    if (facts && typeof facts.has === 'function' && blockerGates.some(k => facts.has(k))) {
      return false;
    }
    return true;
  }
  const prod = a.produces || [];
  return prod.length > 0 && prod.every(k => /^advice\./.test(k));
}

function isReportOnlyMove(OBOL, a, pack) {
  return !!(OBOL.pack && OBOL.pack.isReportOnly && OBOL.pack.isReportOnly(a, pack));
}

function isFlagCollectionMove(a) {
  if (!a) return false;
  if (/^flag-hunt-/.test(String(a.id || ''))) return true;
  const prod = a.produces || [];
  return prod.length > 0 && prod.some(k => /^objective\.(?:local_flag|root_flag|flag)$/.test(k));
}

function extractCommandFlags(cmdStr) {
  const noTemplates = String(cmdStr || '').replace(/\{\{[^}]+\}\}/g, ' ');
  const matches = noTemplates.match(/(?:--[a-zA-Z0-9][a-zA-Z0-9_-]*|-[a-zA-Z0-9]{1,8}|\b(?:smb|ldap|winrm|mssql|ssh|ftp|rdp|wmi|dir|vhost|dns|fuzz|find|req|auth|shadow|account|get|set|add|dump|shares|users|groups|pass-pol|rid-brute|kerberoasting|asreproast|bloodhound|spider_plus|just-dc|just-dc-ntlm|request|perm|getcap|linpeas|winpeas|systeminfo|cmdkey|socks|server|client)\b)/gi) || [];
  const out = [];
  const seen = Object.create(null);
  for (const raw of matches) {
    const tok = raw.toLowerCase();
    if (/^-(?:u|p|d|h|i|t|o|v|n|w|x|c|e|f|q|a|r|s)$/.test(tok)) continue;
    if (!seen[tok]) {
      seen[tok] = 1;
      out.push(tok);
    }
  }
  return out;
}

function matchTurnToCatalogMoves(OBOL, turn, ctx) {
  ctx = ctx || {};
  const facts = ctx.facts || null;
  const pack = (OBOL.packs && typeof OBOL.packs.actions === 'function') ? OBOL.packs.actions() : [];
  if (!pack.length) return [];

  const rawCmd = String((turn && turn.command) || '').trim();
  const stdout = String((turn && (turn.stdout || turn.output)) || '');
  if (!rawCmd) return [];

  const cleanCmd = stripCommandWrappers(rawCmd);
  const lowCmd = cleanCmd.toLowerCase();
  const cmdTool = extractPrimaryTool(cleanCmd);
  const cmdFlags = extractCommandFlags(cleanCmd);
  const onTarget = !isAttackerTurn(turn) || !!(facts && (facts.has('foothold.linux') || facts.has('foothold.windows')) && /^(?:sudo|find|getcap|whoami|systeminfo|cmdkey|cat|type|uname|crontab)\b/i.test(cleanCmd));

  const byId = Object.create(null);
  const actionableMoves = [];
  for (const a of pack) {
    if (!a || !a.id) continue;
    if (isReportOnlyMove(OBOL, a, pack)) continue;
    if (isCanvasDoctorMove(a, facts)) continue;
    byId[a.id] = a;
    actionableMoves.push(a);
  }

  const scored = Object.create(null);
  function bump(id, pts) {
    if (!byId[id]) return;
    scored[id] = Math.max(scored[id] || 0, pts);
  }

  // High-precision domain-independent tool/intent equivalences against live catalog IDs
  if (/(?:^|\s)(?:cat|type|Get-Content|more|head|tail)\s+[^\r\n;|&]*\b(local|user|root|proof)\.txt\b/i.test(cleanCmd)) {
    const isRootFlag = /\b(?:root|proof)\.txt\b/i.test(cleanCmd);
    const isWin = turn.kind === 'powershell' || turn.kind === 'cmd' || /\btype\b|Get-Content|[A-Za-z]:\\/i.test(cleanCmd) || !!(facts && facts.has('foothold.windows'));
    if (isWin) {
      bump(isRootFlag ? 'flag-hunt-root-windows' : 'flag-hunt-windows', 25);
    } else {
      bump(isRootFlag ? 'flag-hunt-root-linux' : 'flag-hunt-linux', 25);
    }
  }

  if (cmdTool === 'nmap' || cmdTool === 'rustscan' || cmdTool === 'masscan') {
    if (/\s-sU\b/.test(cleanCmd)) {
      bump('nmap-udp-top', 24);
    } else if (/--script[=\s]+["']?[^"'\s]*vuln/i.test(cleanCmd)) {
      bump('nmap-vuln-scripts', 24);
    } else {
      const hasOpenPorts = !!(facts && (facts.has('ports.open') || facts.has('scan.nmap.quick')));
      if (!hasOpenPorts) {
        bump('nmap-fast-open-ports', 24);
        if (/\s-(?:sV|sC|A)\b/.test(cleanCmd)) bump('nmap-version-scripts', 18);
      } else if (/\s-(?:sV|sC|A)\b/.test(cleanCmd)) {
        bump('nmap-version-scripts', 24);
        bump('nmap-fast-open-ports', 14);
      } else {
        bump('nmap-fast-open-ports', 22);
      }
    }
  }

  if (/^(?:gobuster|feroxbuster|ffuf|dirsearch|dirb|wfuzz)$/.test(cmdTool)) {
    if (/\bvhost\b|\bdns\b|-H\s+['"]?Host:\s*FUZZ/i.test(cleanCmd)) {
      bump('vhost-fuzz', 24);
      bump('subdomain-vhost-fuzz', 24);
    } else {
      bump('content-discovery', 24);
    }
  }

  if (cmdTool === 'whatweb' || (cmdTool === 'curl' && /\s-(?:I|sSI|sI|-head)\b/.test(cleanCmd))) {
    bump('recon-web-triage', 22);
  }

  if ((cmdTool === 'smbclient' && /\s-L\b/.test(cleanCmd) && /\s-N\b|-U\s*['"]?['"]?(?:\s|$)|anonymous/i.test(cleanCmd))
      || (cmdTool === 'enum4linux')
      || (cmdTool === 'smbmap' && /(?:-u\s*(?:''|""|anonymous|guest)|\s-H\s+\S+\s*$)/i.test(cleanCmd))
      || (cmdTool === 'nxc' && /\bsmb\b/i.test(cleanCmd) && /-u\s*(?:''|""|guest|anonymous)\b/i.test(cleanCmd))) {
    bump('recon-smb-anon', 23);
  }

  if (onTarget && /^sudo\s+(?:-l|--list)\b/i.test(cleanCmd)) {
    if (facts && facts.has('privesc.sudo_rights')) {
      bump('sudo-abuse', 23);
      bump('linux-enum', 20);
    } else {
      bump('linux-enum', 23);
      bump('sudo-abuse', 18);
    }
  } else if (!isAttackerTurn(turn) && /^sudo\s+/i.test(rawCmd) && !/^sudo\s+(?:-l|--list|-V|--version)\b/i.test(rawCmd)) {
    bump('sudo-abuse', 22);
  }

  if (onTarget && (/\blinpeas\b/i.test(cleanCmd) || /\bfind\s+\/\s+[^\r\n]*-perm\s+[-/]?(?:4000|u=s)/i.test(cleanCmd) || /\bgetcap\s+-r\b/i.test(cleanCmd))) {
    bump('linux-enum', 23);
  }

  if (onTarget && (/\bwinpeas/i.test(cleanCmd) || /^whoami\s+\/(?:priv|all)\b/i.test(cleanCmd) || /^systeminfo\b/i.test(cleanCmd) || /^cmdkey\s+\/list\b/i.test(cleanCmd))) {
    bump('windows-enum', 23);
    if (/^whoami\s+\/priv\b/i.test(cleanCmd) && facts && facts.has('privesc.se_impersonate')) {
      bump('seimpersonate', 21);
    }
  }

  // Consult OBOL.inference.matchCatalogMove as an engine-native signal
  if (OBOL.inference && typeof OBOL.inference.matchCatalogMove === 'function') {
    const nativeHit = OBOL.inference.matchCatalogMove(cleanCmd, null, { target: ctx.target || '' });
    if (nativeHit && nativeHit.id && byId[nativeHit.id]) {
      bump(nativeHit.id, Math.max(10, (nativeHit.score || 5) + 5));
    }
  }

  // General structural scoring across every sub-clause of every action's commands[]
  for (const a of actionableMoves) {
    const cmds = a.commands || [];
    let bestActionScore = scored[a.id] || 0;

    for (let i = 0; i < cmds.length; i++) {
      const cObj = cmds[i];
      if (!cObj || !cObj.run) continue;
      const clauses = String(cObj.run).split(/\s*(?:&&|\|\||;|\|)\s*/);
      for (const clause of clauses) {
        const cleanClause = stripCommandWrappers(clause.replace(/\{\{[^}]+\}\}/g, 'TOKEN'));
        if (!cleanClause) continue;
        const clauseTool = extractPrimaryTool(cleanClause);
        const declaredTool = canonicalTool(cObj.tool || a.tool || '');
        if (!cmdTool || (cmdTool !== clauseTool && cmdTool !== declaredTool)) continue;

        let s = 6;
        const clauseFlags = extractCommandFlags(cleanClause);
        let hits = 0;
        let misses = 0;
        for (const fl of clauseFlags) {
          if (cmdFlags.indexOf(fl) >= 0 || lowCmd.indexOf(fl) >= 0) {
            hits += fl.length > 4 ? 4 : 2;
          } else if (fl.startsWith('--') && fl.length > 5) {
            misses += 2;
          }
        }
        s += hits - misses;
        if (s > bestActionScore) bestActionScore = s;
      }
    }

    if (bestActionScore >= 9) {
      scored[a.id] = bestActionScore;
    }
  }

  const rankedIds = Object.keys(scored).sort((idA, idB) => {
    const diff = scored[idB] - scored[idA];
    if (Math.abs(diff) > 2) return diff;
    const elA = (facts && byId[idA] && typeof byId[idA].eligible === 'function' && byId[idA].eligible(facts)) ? 1 : 0;
    const elB = (facts && byId[idB] && typeof byId[idB].eligible === 'function' && byId[idB].eligible(facts)) ? 1 : 0;
    if (elA !== elB) return elB - elA;
    if (diff !== 0) return diff;
    return (byId[idB].priority || 0) - (byId[idA].priority || 0);
  });

  if (!rankedIds.length) return [];
  const topScore = scored[rankedIds[0]];
  return rankedIds
    .filter(id => scored[id] >= Math.max(9, topScore - 5))
    .slice(0, 3)
    .map(id => ({
      move: byId[id],
      id: id,
      title: byId[id].title || id,
      match_score: scored[id]
    }));
}

function inspectMoveCommandReadiness(OBOL, session, move, facts, targetIp) {
  const eng = session.eng;
  const params = Object.assign({}, eng.params || {}, { target: targetIp });
  const wsTokens = (OBOL.workspace && OBOL.workspace.tokens) ? OBOL.workspace.tokens(eng) : {};
  const cmds = move.commands || [];
  if (!cmds.length) {
    return {
      hasRunnableTokens: true,
      allSettled: false,
      unfilledEarnedTokens: [],
      filledCommands: []
    };
  }

  const filledAll = OBOL.command.fillAll(move, facts, {
    params: params,
    profile: eng.profile,
    workspace: wsTokens
  });
  const earnedSet = (OBOL.command && OBOL.command.EARNED_TOKENS) || {};

  let hasRunnableTokens = false;
  let eligibleVariantCount = 0;
  let settledCount = 0;
  const missingEarned = [];

  for (let i = 0; i < cmds.length; i++) {
    const cObj = cmds[i];
    const cFacts = (facts && typeof facts.forAction === 'function') ? facts.forAction(move, cObj) : facts;
    if (OBOL.pack && OBOL.pack.commandIsEligible && !OBOL.pack.commandIsEligible(cObj, cFacts, move)) {
      continue;
    }
    eligibleVariantCount++;
    if (OBOL.pack && OBOL.pack.commandSettled && OBOL.pack.commandSettled(cObj, cFacts)) {
      settledCount++;
      continue;
    }
    const f = filledAll[i] || { filled: cObj.run || '', blocked: false };
    const unfilled = (OBOL.command && OBOL.command.unfilledTokens)
      ? OBOL.command.unfilledTokens(f.filled || '')
      : [];
    const earnedMissing = unfilled.filter(tok => !!earnedSet[tok]);
    if (!f.blocked && earnedMissing.length === 0) {
      hasRunnableTokens = true;
    } else {
      for (const tok of earnedMissing) {
        if (missingEarned.indexOf(tok) < 0) missingEarned.push(tok);
      }
    }
  }

  return {
    hasRunnableTokens: hasRunnableTokens,
    allSettled: eligibleVariantCount > 0 && settledCount === eligibleVariantCount,
    unfilledEarnedTokens: missingEarned,
    filledCommands: filledAll
  };
}

function gateEvidencePresentInHistory(gateOrTokens, historyTurns) {
  if (!historyTurns || !historyTurns.length) return { found: false, reason: '' };
  const combinedOut = historyTurns.map(h => String(h.stdout || '')).join('\n');
  if (!combinedOut.trim()) return { found: false, reason: '' };

  for (const item of gateOrTokens || []) {
    const g = String(item || '');
    const portM = /^port:(\d+)$/.exec(g);
    if (portM) {
      const re = new RegExp('\\b' + portM[1] + '\\/(?:tcp|udp)\\s+open\\b', 'i');
      if (re.test(combinedOut)) return { found: true, reason: 'raw_stdout_had_' + g };
    }
    if (g === 'ports.open' && /\b\d+\/(?:tcp|udp)\s+open\b/i.test(combinedOut)) {
      return { found: true, reason: 'raw_stdout_had_open_port_row' };
    }
    if (g === 'http.reachable' && (/\b(?:80|443|8080|8000|8443)\/tcp\s+open\b/i.test(combinedOut) || /^HTTP\/\d(?:\.\d)?\s+\d{3}\b/im.test(combinedOut))) {
      return { found: true, reason: 'raw_stdout_had_http_signal' };
    }
    if (g === 'smb.reachable' && (/\b(?:445|139)\/tcp\s+open\b/i.test(combinedOut) || /^SMB\s+\d{1,3}(?:\.\d{1,3}){3}/im.test(combinedOut))) {
      return { found: true, reason: 'raw_stdout_had_smb_signal' };
    }
    if ((g === 'foothold.linux' || g === 'access.shell') && /\buid=\d+\([^)]+\)\s+gid=\d+\(/i.test(combinedOut)) {
      return { found: true, reason: 'raw_stdout_had_posix_uid' };
    }
    if (g === 'foothold.windows' && (/\bMicrosoft Windows \[Version\b/i.test(combinedOut) || /\bSeImpersonatePrivilege\b/i.test(combinedOut))) {
      return { found: true, reason: 'raw_stdout_had_windows_shell_signal' };
    }
    if (/^(?:credential\.|hash\.|user$|password$|nthash$)/.test(g) && (/\$krb5(?:tgs|asrep)\$/i.test(combinedOut) || /^\S+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::/m.test(combinedOut))) {
      return { found: true, reason: 'raw_stdout_had_hash_or_cred_material' };
    }
    if ((g === 'smb.shares' || g === 'share') && /\bDisk\b|\bIPC\$\b|\bADMIN\$\b/i.test(combinedOut)) {
      return { found: true, reason: 'raw_stdout_had_share_listing' };
    }
    if (g === 'privesc.sudo_rights' && /\bUser\s+\S+\s+may\s+run\s+the\s+following\s+commands\b/i.test(combinedOut)) {
      return { found: true, reason: 'raw_stdout_had_sudo_l_listing' };
    }
    if (g === 'privesc.se_impersonate' && /\bSe(?:Impersonate|AssignPrimaryToken)Privilege\b/i.test(combinedOut)) {
      return { found: true, reason: 'raw_stdout_had_impersonate_priv' };
    }
  }

  const prev = historyTurns[historyTurns.length - 1];
  if (prev && !prev.housekeeping && String(prev.stdout || '').trim().length >= 24 && (prev.minted_count || 0) === 0) {
    return { found: true, reason: 'immediately_preceding_turn_had_unminted_stdout' };
  }

  return { found: false, reason: '' };
}

function isInitialMultiPortReconFork(OBOL, session, facts, targetIp) {
  const curEpoch = (OBOL.pack && OBOL.pack.accessEpoch) ? OBOL.pack.accessEpoch(facts) : 'anon';
  if (curEpoch !== 'anon') return false;
  const ports = (OBOL.command && OBOL.command.openPorts) ? OBOL.command.openPorts(facts, targetIp) : [];
  if (!ports || ports.length < 2) return false;

  const acts = (session.eng && session.eng.activities) || [];
  let nonNmapTargetActs = 0;
  for (const act of acts) {
    if (!act) continue;
    const actTarget = act.target || (/^host:/.test(act.scope || '') ? act.scope.slice(5) : '');
    if (actTarget && actTarget !== targetIp) continue;
    const aid = String(act.action_id || '');
    const tool = String(act.tool || '').toLowerCase();
    if (/^nmap-/.test(aid) || tool === 'nmap' || tool === 'rustscan' || tool === 'masscan') continue;
    nonNmapTargetActs++;
  }
  return nonNmapTargetActs === 0;
}

function simulateRetireMoveInSandbox(OBOL, session, card, targetIp) {
  if (isFlagCollectionMove(card)) {
    OBOL.store.setChecklist(card.id, 'done');
    return { method: 'flag_checklist_done', outcomes: ['done'] };
  }

  const cmds = card.commands || [];
  if (!cmds.length) {
    OBOL.store.setChecklist(card.id, 'done');
    return { method: 'no_cmd_checklist_done', outcomes: ['done'] };
  }

  const outcomes = [];
  const maxAttempts = Math.min(cmds.length, 6);
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const coachNow = session.computeCoach(targetIp);
    const stillAtHead = coachNow.onFlow.findIndex(x => x.id === card.id);
    if (stillAtHead < 0) break;
    if (attempt > 0 && stillAtHead > 0) break;

    const factsNow = coachNow.facts || session.factSetForTarget(targetIp);
    const params = Object.assign({}, session.eng.params || {}, { target: targetIp });
    const wsTokens = (OBOL.workspace && OBOL.workspace.tokens) ? OBOL.workspace.tokens(session.eng) : {};
    const bestIdx = (OBOL.command && typeof OBOL.command.bestCommandIndex === 'function')
      ? OBOL.command.bestCommandIndex(card, factsNow, {
          params: params,
          profile: session.eng.profile,
          workspace: wsTokens,
          activities: session.eng.activities
        })
      : 0;
    const cmdObj = cmds[bestIdx] || cmds[0];
    const filled = (OBOL.command && typeof OBOL.command.fillCommand === 'function')
      ? OBOL.command.fillCommand(card, factsNow, {
          params: params,
          profile: session.eng.profile,
          workspace: wsTokens
        }, bestIdx)
      : { filled: (cmdObj && cmdObj.run) || card.id };

    const res = OBOL.ingest.run({
      text: DRY_PROBE_SENTINEL,
      command: (filled && filled.filled) || (cmdObj && cmdObj.run) || card.id,
      actionId: card.id,
      source: 'paste',
      scope: 'host:' + targetIp,
      forceTarget: targetIp,
      commandObj: cmdObj
    });
    outcomes.push((res && res.outcome && res.outcome.kind) || 'unknown');
  }

  return { method: 'completed_negative_dry_probe', outcomes: outcomes };
}

function evaluateClosedLoopReachability(session, candidates, turn, opts) {
  opts = opts || {};
  const OBOL = session.OBOL;
  const targetIp = opts.targetIp || session.getActiveTarget();
  const historyTurns = opts.historyTurns || [];
  const executedMoveIds = opts.executedMoveIds || new Set();

  const coach = session.computeCoach(targetIp);
  const facts = coach.facts || session.factSetForTarget(targetIp);
  const onFlow = coach.onFlow || [];
  const comingUp = coach.comingUp || [];
  const doneIds = (OBOL.store && OBOL.store.doneIdsForTarget)
    ? OBOL.store.doneIdsForTarget(targetIp, facts, session.eng)
    : {};

  const atReconFork = isInitialMultiPortReconFork(OBOL, session, facts, targetIp);

  // 1. Check if any candidate is ALREADY at #1 (or Top-4 at an initial multi-port recon fork)
  for (const cand of candidates) {
    const idx = onFlow.findIndex(m => m.id === cand.id);
    if (idx === 0) {
      return {
        reachable: true,
        mode: 'direct_top1',
        matched_move_id: cand.id,
        initial_rank: 1,
        retired_preceding: [],
        stall_bucket: null,
        detail: 'Move sits at #1 in Ready Now'
      };
    }
    if (idx > 0 && idx < 4 && atReconFork) {
      return {
        reachable: true,
        mode: 'initial_recon_fork_top4',
        matched_move_id: cand.id,
        initial_rank: idx + 1,
        retired_preceding: [],
        stall_bucket: null,
        detail: 'Move sits within Top-4 at unprobed initial multi-port recon fork'
      };
    }
  }

  // 2. Check if any candidate sits in Ready Now at #k > 1 and promotes to #1 via closed-loop retirement
  const rankedInFlow = candidates
    .map(c => ({ cand: c, idx: onFlow.findIndex(m => m.id === c.id) }))
    .filter(x => x.idx > 0)
    .sort((a, b) => a.idx - b.idx);

  if (rankedInFlow.length > 0) {
    const best = rankedInFlow[0];
    const targetMoveId = best.cand.id;
    const initialRank = best.idx + 1;
    const originalPreceding = onFlow.slice(0, best.idx).map(m => m.id);
    const precedingSet = new Set(originalPreceding);

    const snap = session.snapshot();
    const retiredPreceding = [];
    let stallBucket = null;
    let stallDetail = '';
    let stalledPrecedingId = null;

    try {
      const maxSteps = originalPreceding.length + 2;
      for (let step = 0; step < maxSteps; step++) {
        const simCoach = session.computeCoach(targetIp);
        const simFlow = simCoach.onFlow || [];
        if (simFlow[0] && simFlow[0].id === targetMoveId) {
          return {
            reachable: true,
            mode: 'closed_loop_promoted_top1',
            matched_move_id: targetMoveId,
            initial_rank: initialRank,
            retired_preceding: retiredPreceding,
            stall_bucket: null,
            detail: 'Promoted from #' + initialRank + ' to #1 after retiring ' + retiredPreceding.length + ' preceding card(s)'
          };
        }

        const curTargetIdx = simFlow.findIndex(m => m.id === targetMoveId);
        if (curTargetIdx < 0) {
          stallBucket = 'CLOSED_LOOP_RANK_STALL';
          stallDetail = 'Candidate move dropped out of Ready Now during preceding-card retirement';
          break;
        }

        const head = simFlow[0];
        if (!head || !precedingSet.has(head.id)) {
          stallBucket = 'CLOSED_LOOP_RANK_STALL';
          stallDetail = 'Unrelated move (' + (head ? head.id : 'none') + ') remained ahead of candidate after retiring preceding cards';
          break;
        }

        simulateRetireMoveInSandbox(OBOL, session, head, targetIp);
        const afterCoach = session.computeCoach(targetIp);
        const afterFlow = afterCoach.onFlow || [];
        const newHeadIdx = afterFlow.findIndex(m => m.id === head.id);
        const newTargetIdx = afterFlow.findIndex(m => m.id === targetMoveId);

        if (newHeadIdx === 0 || (newHeadIdx >= 0 && newTargetIdx >= 0 && newHeadIdx < newTargetIdx)) {
          stallBucket = 'OUTCOME_OR_RETIREMENT_STALL';
          stalledPrecedingId = head.id;
          stallDetail = 'Preceding card ' + head.id + ' failed to retire or demote on completed-negative dry probe';
          break;
        }

        if (retiredPreceding.indexOf(head.id) < 0) retiredPreceding.push(head.id);
      }

      if (!stallBucket) {
        const finalCoach = session.computeCoach(targetIp);
        if (finalCoach.onFlow && finalCoach.onFlow[0] && finalCoach.onFlow[0].id === targetMoveId) {
          return {
            reachable: true,
            mode: 'closed_loop_promoted_top1',
            matched_move_id: targetMoveId,
            initial_rank: initialRank,
            retired_preceding: retiredPreceding,
            stall_bucket: null,
            detail: 'Promoted from #' + initialRank + ' to #1'
          };
        }
        stallBucket = 'CLOSED_LOOP_RANK_STALL';
        stallDetail = 'Candidate move remained below #1 after retiring all original preceding cards';
      }
    } finally {
      session.restore(snap);
    }

    return {
      reachable: false,
      mode: 'stalled_in_ready_now',
      matched_move_id: targetMoveId,
      initial_rank: initialRank,
      retired_preceding: retiredPreceding,
      stalled_preceding_move_id: stalledPrecedingId,
      stall_bucket: stallBucket,
      detail: stallDetail
    };
  }

  // 3. No candidate is in Ready Now: check if already executed & settled earlier in this replay
  for (const cand of candidates) {
    const cmdInfo = inspectMoveCommandReadiness(OBOL, session, cand.move, facts, targetIp);
    if (executedMoveIds.has(cand.id) && (doneIds[cand.id] || cmdInfo.allSettled)) {
      return {
        reachable: true,
        mode: 'already_settled_repeat',
        matched_move_id: cand.id,
        initial_rank: null,
        retired_preceding: [],
        stall_bucket: null,
        detail: 'Operator repeated a sub-command of an already settled move'
      };
    }
  }

  // 4. Diagnose exact upstream stall bucket on the best-matching catalog candidate
  const primary = candidates[0];
  const move = primary.move;
  const isEligible = typeof move.eligible === 'function' ? move.eligible(facts) : true;

  if (!isEligible) {
    const missingAll = (move.requires_all || []).filter(g => !facts.has(g));
    const hasAny = !move.requires_any || !move.requires_any.length || move.requires_any.some(g => facts.has(g));
    const missingAny = hasAny ? [] : (move.requires_any || []).slice();
    const missingGates = missingAll.concat(missingAny);

    const histProbe = gateEvidencePresentInHistory(missingGates, historyTurns);
    if (histProbe.found) {
      return {
        reachable: false,
        mode: 'ineligible_parse_miss',
        matched_move_id: primary.id,
        initial_rank: null,
        missing_gates: missingGates,
        stall_bucket: 'PARSE_OR_SHAPE_MISS',
        detail: 'Unmet gate(s) [' + missingGates.join(', ') + '] had prior raw output signal (' + histProbe.reason + ')'
      };
    }

    return {
      reachable: false,
      mode: 'ineligible_gate_deadlock',
      matched_move_id: primary.id,
      initial_rank: null,
      missing_gates: missingGates,
      stall_bucket: 'GATE_DEADLOCK_OR_UNDERGATED_GAMBLE',
      detail: 'Move ineligible; unmet gate(s): [' + (missingGates.join(', ') || 'os_or_scope_gate') + ']'
    };
  }

  const cmdReadiness = inspectMoveCommandReadiness(OBOL, session, move, facts, targetIp);
  if (!cmdReadiness.hasRunnableTokens && cmdReadiness.unfilledEarnedTokens.length > 0) {
    const histProbe = gateEvidencePresentInHistory(cmdReadiness.unfilledEarnedTokens, historyTurns);
    if (histProbe.found) {
      return {
        reachable: false,
        mode: 'unfilled_token_parse_miss',
        matched_move_id: primary.id,
        initial_rank: null,
        unfilled_earned_tokens: cmdReadiness.unfilledEarnedTokens,
        stall_bucket: 'PARSE_OR_SHAPE_MISS',
        detail: 'Unfilled EARNED_TOKENS [' + cmdReadiness.unfilledEarnedTokens.join(', ') + '] had prior raw output signal (' + histProbe.reason + ')'
      };
    }

    return {
      reachable: false,
      mode: 'unfilled_earned_token',
      matched_move_id: primary.id,
      initial_rank: null,
      unfilled_earned_tokens: cmdReadiness.unfilledEarnedTokens,
      stall_bucket: 'UNFILLED_EARNED_TOKEN',
      detail: 'Move eligible, but blocked from Ready Now by unfilled EARNED_TOKENS: [' + cmdReadiness.unfilledEarnedTokens.join(', ') + ']'
    };
  }

  const inComingUp = comingUp.some(m => m.id === primary.id);
  const prematurity = (OBOL.phases && typeof OBOL.phases.prematurity === 'function')
    ? OBOL.phases.prematurity(move, facts)
    : 0;

  return {
    reachable: false,
    mode: inComingUp ? 'stuck_in_coming_up' : 'excluded_from_ready_now',
    matched_move_id: primary.id,
    initial_rank: null,
    prematurity: prematurity,
    stall_bucket: 'CLOSED_LOOP_RANK_STALL',
    detail: inComingUp
      ? ('Move eligible with runnable tokens, but held in Coming Up (prematurity=' + prematurity + ')')
      : ('Move eligible with runnable tokens, but excluded from Ready Now (lens=' + (coach.lens || 'default') + ')')
  };
}

function evaluateCheckpoint(session, cp) {
  const OBOL = session.OBOL;
  const targetIp = cp.target_ip || session.getActiveTarget();
  const coach = session.computeCoach(targetIp);
  const facts = coach.facts || session.factSetForTarget(targetIp);
  const errors = [];

  if (Array.isArray(cp.required_gates)) {
    for (const g of cp.required_gates) {
      if (!facts.has(g)) errors.push('missing required_gate ' + g);
    }
  }

  if (Array.isArray(cp.earned_tokens) && cp.earned_tokens.length > 0 && OBOL.command) {
    const ctx = OBOL.command.buildContext(facts, {
      engagement: session.eng,
      params: Object.assign({}, session.eng.params || {}, { target: targetIp }),
      target: targetIp
    });
    for (const tok of cp.earned_tokens) {
      if (ctx[tok] === undefined || ctx[tok] === null || ctx[tok] === '') {
        errors.push('unfilled earned_token ' + tok);
      }
    }
  }

  if (Array.isArray(cp.retired_dry_moves)) {
    for (const rid of cp.retired_dry_moves) {
      if ((coach.onFlow || []).some(m => m.id === rid)) {
        errors.push('expected retired_dry_move ' + rid + ' is still in Ready Now');
      }
    }
  }

  if (Array.isArray(cp.expected_move_ids) && cp.expected_move_ids.length > 0) {
    const pack = OBOL.packs.actions();
    const candidates = cp.expected_move_ids
      .map(id => pack.find(a => a && a.id === id))
      .filter(Boolean)
      .map(a => ({ move: a, id: a.id, title: a.title || a.id, match_score: 25 }));

    if (!candidates.length) {
      errors.push('none of expected_move_ids exist in catalog: ' + cp.expected_move_ids.join(', '));
    } else if (cp.require_closed_loop_top1) {
      const reach = evaluateClosedLoopReachability(session, candidates, null, { targetIp: targetIp });
      if (!reach.reachable) {
        errors.push('closed_loop_top1 failed (' + reach.stall_bucket + '): ' + reach.detail);
      }
    } else {
      const anyInFlow = candidates.some(c => (coach.onFlow || []).some(m => m.id === c.id));
      if (!anyInFlow) {
        errors.push('none of expected_move_ids present in Ready Now: ' + cp.expected_move_ids.join(', '));
      }
    }
  }

  return {
    step_index: cp.step_index,
    target_ip: targetIp,
    ok: errors.length === 0,
    errors: errors
  };
}

function replayWalkthrough(OBOL, walkthroughInput, opts) {
  opts = opts || {};
  const slug = walkthroughInput.slug
    || (walkthroughInput.mdPath ? path.basename(walkthroughInput.mdPath, '.md') : 'synthetic');

  let extracted;
  if (Array.isArray(walkthroughInput.turns)) {
    extracted = { turns: walkthroughInput.turns.slice(), ocrCount: 0 };
  } else if (typeof walkthroughInput.markdown === 'string') {
    extracted = extractWalkthroughTurns(walkthroughInput.markdown, {
      slug: slug,
      ocrEntries: walkthroughInput.ocrEntries || []
    });
  } else if (walkthroughInput.mdPath) {
    const md = fs.readFileSync(walkthroughInput.mdPath, 'utf8');
    extracted = extractWalkthroughTurns(md, {
      slug: slug,
      corpusDir: walkthroughInput.corpusRoot
    });
  } else {
    throw new Error('replayWalkthrough requires turns, markdown, or mdPath');
  }

  const turns = extracted.turns || [];
  const net = inferEngagementNetworking(turns, {
    target: opts.target,
    lhost: opts.lhost
  });
  const multiTarget = !!opts.multiTarget || net.targets.length > 1 && !!opts.autoMultiTarget;

  const session = createEngagementSession(OBOL, {
    name: 'Replay:' + slug,
    target: net.primaryTarget,
    targets: multiTarget ? net.targets : [net.primaryTarget],
    lhost: net.lhost,
    multiTarget: multiTarget,
    lens: opts.lens
  });

  // Optional SharpHound / BloodHound JSON bundle ingestion (either pre-supplied or discovered on disk)
  let bloodhoundResult = null;
  const bhPayload = walkthroughInput.bloodhound
    || (opts.bloodhoundDir && fs.existsSync(path.join(opts.bloodhoundDir, slug))
        ? path.join(opts.bloodhoundDir, slug)
        : (walkthroughInput.corpusRoot && fs.existsSync(path.join(walkthroughInput.corpusRoot, 'bloodhound', slug))
            ? path.join(walkthroughInput.corpusRoot, 'bloodhound', slug)
            : null));

  const checkpointsByStep = Object.create(null);
  for (const cp of (walkthroughInput.trajectory_checkpoints || opts.checkpoints || [])) {
    if (cp && Number.isInteger(cp.step_index)) {
      if (!checkpointsByStep[cp.step_index]) checkpointsByStep[cp.step_index] = [];
      checkpointsByStep[cp.step_index].push(cp);
    }
  }

  const stepReports = [];
  const checkpointResults = [];
  const historyTurns = [];
  const executedMoveIds = new Set();
  const stallCounts = Object.create(null);
  for (const b of STALL_BUCKETS) stallCounts[b] = 0;

  let gradedSteps = 0;
  let reachableSteps = 0;
  let directTop1Steps = 0;
  let reconForkTop4Steps = 0;
  let closedLoopPromotedSteps = 0;
  let unmappedSteps = 0;
  let housekeepingSteps = 0;
  let bhIngested = false;

  for (let idx = 0; idx < turns.length; idx++) {
    const rawTurn = turns[idx];
    const activeBefore = session.getActiveTarget();
    const expandedCmd = expandShellTargetVars(rawTurn.command || '', activeBefore, net.varMap);
    const turn = Object.assign({}, rawTurn, { command: expandedCmd });

    // Determine target IP for this turn in multi-target mode BEFORE grading reachability
    let turnTarget = activeBefore;
    if (multiTarget) {
      let m;
      IPV4_GLOBAL_RE.lastIndex = 0;
      const foundIps = [];
      while ((m = IPV4_GLOBAL_RE.exec(expandedCmd + '\n' + (turn.stdout || ''))) !== null) {
        if (isPrivateLabIpv4(m[1]) && net.selfIps.indexOf(m[1]) < 0) {
          foundIps.push(m[1]);
        }
      }
      if (foundIps.length > 0) {
        turnTarget = foundIps[0];
        session.setActiveTarget(turnTarget);
      }
    }

    // Trigger BloodHound JSON bundle right when a bloodhound/sharphound collection command appears
    if (!bhIngested && bhPayload && /\b(?:bloodhound|sharphound)\b/i.test(expandedCmd)) {
      bloodhoundResult = session.ingestBloodHound(bhPayload);
      bhIngested = true;
    }

    // Evaluate any trajectory checkpoints pinned BEFORE step idx
    if (checkpointsByStep[idx]) {
      for (const cp of checkpointsByStep[idx]) {
        checkpointResults.push(evaluateCheckpoint(session, cp));
      }
    }

    const hk = isHousekeepingTurn(turn);
    let reachability = null;
    let candidates = [];

    if (hk.housekeeping) {
      housekeepingSteps++;
    } else {
      const preFacts = session.factSetForTarget(turnTarget);
      candidates = matchTurnToCatalogMoves(OBOL, turn, {
        facts: preFacts,
        target: turnTarget
      });

      if (!candidates.length) {
        unmappedSteps++;
      } else {
        gradedSteps++;
        reachability = evaluateClosedLoopReachability(session, candidates, turn, {
          targetIp: turnTarget,
          historyTurns: historyTurns,
          executedMoveIds: executedMoveIds
        });

        if (reachability.reachable) {
          reachableSteps++;
          if (reachability.mode === 'direct_top1') directTop1Steps++;
          else if (reachability.mode === 'initial_recon_fork_top4') reconForkTop4Steps++;
          else if (reachability.mode === 'closed_loop_promoted_top1') closedLoopPromotedSteps++;
        } else if (reachability.stall_bucket) {
          stallCounts[reachability.stall_bucket] = (stallCounts[reachability.stall_bucket] || 0) + 1;
        }
      }
    }

    // Execute / ingest turn into stateful engagement session
    let ingestReport = null;
    const hasPayload = Boolean((expandedCmd && !hk.housekeeping) || String(turn.stdout || '').trim());
    if (hasPayload) {
      const matchedActionId = (reachability && reachability.matched_move_id)
        || (candidates[0] && candidates[0].id)
        || '';
      ingestReport = session.ingestTurn({
        actionId: matchedActionId,
        command: expandedCmd,
        stdout: turn.stdout || '',
        promptLine: turn.promptLine || '',
        target: turnTarget,
        forceTarget: turnTarget
      });
      if (matchedActionId) executedMoveIds.add(matchedActionId);
    }

    const mintedKinds = ingestReport
      ? (ingestReport.minted_facts || []).map(f => f.kind)
      : [];

    historyTurns.push({
      step_index: idx,
      command: expandedCmd,
      stdout: turn.stdout || '',
      housekeeping: hk.housekeeping,
      minted_count: mintedKinds.length
    });

    stepReports.push({
      step_index: idx,
      line: turn.lineStart || 1,
      fidelity: turn.fidelity || 'text',
      target_ip: turnTarget,
      command: expandedCmd,
      housekeeping: hk.housekeeping,
      housekeeping_reason: hk.reason || undefined,
      matched_moves: candidates.map(c => c.id),
      reachability: reachability,
      minted_kinds: mintedKinds,
      outcome_kind: (ingestReport && ingestReport.outcome && ingestReport.outcome.kind) || null
    });
  }

  // If a BloodHound bundle was provided without an explicit CLI collection turn, ingest it before final checkpoints
  if (!bhIngested && bhPayload) {
    bloodhoundResult = session.ingestBloodHound(bhPayload);
    bhIngested = true;
  }

  if (checkpointsByStep[turns.length]) {
    for (const cp of checkpointsByStep[turns.length]) {
      checkpointResults.push(evaluateCheckpoint(session, cp));
    }
  }

  return {
    slug: slug,
    multi_target: multiTarget,
    lhost: net.lhost,
    targets_observed: session.getTargets().map(t => t.ip),
    ocr_turns_spliced: extracted.ocrCount || 0,
    bloodhound_ingested: bhIngested,
    bloodhound_facts: bloodhoundResult ? (bloodhoundResult.facts || []).map(f => f.kind) : [],
    totals: {
      turns: turns.length,
      housekeeping_steps: housekeepingSteps,
      unmapped_steps: unmappedSteps,
      graded_steps: gradedSteps,
      reachable_steps: reachableSteps,
      reachability_rate: gradedSteps ? +(reachableSteps / gradedSteps).toFixed(4) : 1,
      direct_top1_steps: directTop1Steps,
      recon_fork_top4_steps: reconForkTop4Steps,
      closed_loop_promoted_steps: closedLoopPromotedSteps,
      stalled_steps: gradedSteps - reachableSteps
    },
    stalls_by_bucket: stallCounts,
    checkpoints: checkpointResults,
    steps: stepReports
  };
}

function runTrajectoryHarvest(opts) {
  opts = opts || {};
  const resolved = resolveWalkthroughDir(opts.corpusDir);
  if (!fs.existsSync(resolved.walkthroughDir)) {
    throw new Error('Walkthrough directory not found: ' + resolved.walkthroughDir);
  }

  const slugFilter = opts.slugs
    ? new Set(String(opts.slugs).split(',').map(s => s.trim().replace(/\.md$/i, '')).filter(Boolean))
    : null;

  let entries = fs.readdirSync(resolved.walkthroughDir)
    .filter(f => f.endsWith('.md'))
    .sort()
    .map(f => ({
      slug: path.basename(f, '.md'),
      mdPath: path.join(resolved.walkthroughDir, f),
      corpusRoot: resolved.corpusRoot,
      isAlternate: false
    }));

  if (slugFilter) {
    entries = entries.filter(e => slugFilter.has(e.slug));
  }

  if (opts.includeAlternates) {
    const baseEntries = entries.slice();
    for (const base of baseEntries) {
      const alts = discoverAlternates(resolved.corpusRoot, base.slug);
      for (const alt of alts) {
        entries.push({
          slug: path.basename(alt.file, '.md'),
          mdPath: alt.path,
          corpusRoot: resolved.corpusRoot,
          isAlternate: true
        });
      }
    }
  }

  if (opts.limit && Number(opts.limit) > 0) {
    entries = entries.slice(0, Number(opts.limit));
  }

  const OBOL = opts.OBOL || createSandbox();
  const walkthroughReports = [];

  const aggregateStalls = Object.create(null);
  for (const b of STALL_BUCKETS) aggregateStalls[b] = 0;

  let totalTurns = 0;
  let totalGraded = 0;
  let totalReachable = 0;
  let totalDirectTop1 = 0;
  let totalReconForkTop4 = 0;
  let totalPromoted = 0;
  let totalUnmapped = 0;
  let totalHousekeeping = 0;
  const topStalledMoves = Object.create(null);

  for (const entry of entries) {
    const rep = replayWalkthrough(OBOL, entry, {
      multiTarget: !!opts.multiTarget,
      bloodhoundDir: opts.bloodhoundDir,
      lens: opts.lens
    });
    walkthroughReports.push(rep);

    totalTurns += rep.totals.turns;
    totalGraded += rep.totals.graded_steps;
    totalReachable += rep.totals.reachable_steps;
    totalDirectTop1 += rep.totals.direct_top1_steps;
    totalReconForkTop4 += rep.totals.recon_fork_top4_steps;
    totalPromoted += rep.totals.closed_loop_promoted_steps;
    totalUnmapped += rep.totals.unmapped_steps;
    totalHousekeeping += rep.totals.housekeeping_steps;

    for (const b of STALL_BUCKETS) {
      aggregateStalls[b] += (rep.stalls_by_bucket[b] || 0);
    }

    for (const st of rep.steps) {
      if (st.reachability && !st.reachability.reachable && st.reachability.matched_move_id) {
        const key = st.reachability.matched_move_id + '::' + st.reachability.stall_bucket;
        if (!topStalledMoves[key]) {
          topStalledMoves[key] = {
            move_id: st.reachability.matched_move_id,
            stall_bucket: st.reachability.stall_bucket,
            count: 0,
            samples: []
          };
        }
        topStalledMoves[key].count++;
        if (topStalledMoves[key].samples.length < 4) {
          topStalledMoves[key].samples.push({
            slug: rep.slug,
            step_index: st.step_index,
            line: st.line,
            command: st.command.slice(0, 140),
            detail: st.reachability.detail
          });
        }
      }
    }
  }

  const rankedStalls = Object.values(topStalledMoves)
    .sort((a, b) => b.count - a.count);

  const report = {
    generated_at: new Date().toISOString(),
    corpus_dir: resolved.walkthroughDir,
    multi_target: !!opts.multiTarget,
    walkthrough_count: walkthroughReports.length,
    totals: {
      turns: totalTurns,
      housekeeping_steps: totalHousekeeping,
      unmapped_steps: totalUnmapped,
      graded_steps: totalGraded,
      reachable_steps: totalReachable,
      reachability_rate: totalGraded ? +(totalReachable / totalGraded).toFixed(4) : 1,
      direct_top1_steps: totalDirectTop1,
      recon_fork_top4_steps: totalReconForkTop4,
      closed_loop_promoted_steps: totalPromoted,
      stalled_steps: totalGraded - totalReachable
    },
    stalls_by_bucket: aggregateStalls,
    top_stalled_moves: rankedStalls.slice(0, 50),
    walkthroughs: walkthroughReports
  };

  if (opts.outFile) {
    fs.mkdirSync(path.dirname(path.resolve(opts.outFile)), { recursive: true });
    fs.writeFileSync(path.resolve(opts.outFile), JSON.stringify(report, null, 2) + '\n', 'utf8');
  }

  return report;
}

function parseCliArgs(argv) {
  const opts = {
    corpusDir: '',
    slugs: '',
    multiTarget: false,
    includeAlternates: false,
    bloodhoundDir: '',
    limit: 0,
    lens: '',
    outFile: ''
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--corpus-dir' && argv[i + 1]) opts.corpusDir = argv[++i];
    else if (a === '--slugs' && argv[i + 1]) opts.slugs = argv[++i];
    else if (a === '--multi-target') opts.multiTarget = true;
    else if (a === '--include-alternates') opts.includeAlternates = true;
    else if (a === '--bloodhound-dir' && argv[i + 1]) opts.bloodhoundDir = argv[++i];
    else if (a === '--limit' && argv[i + 1]) opts.limit = parseInt(argv[++i], 10) || 0;
    else if (a === '--lens' && argv[i + 1]) opts.lens = argv[++i];
    else if (a === '--out' && argv[i + 1]) opts.outFile = argv[++i];
  }
  return opts;
}

function main() {
  const opts = parseCliArgs(process.argv.slice(2));
  let report;
  try {
    report = runTrajectoryHarvest(opts);
  } catch (err) {
    console.error('harvest-trajectories: ' + (err && err.message ? err.message : err));
    process.exit(1);
  }

  const t = report.totals;
  console.log(
    'Trajectory harvest: ' + report.walkthrough_count + ' walkthrough(s), ' +
    t.turns + ' turn(s), ' + t.graded_steps + ' graded step(s)'
  );
  console.log(
    'Closed-loop #1 reachability: ' + t.reachable_steps + '/' + t.graded_steps +
    ' (' + (t.reachability_rate * 100).toFixed(1) + '%) ' +
    '[direct #1=' + t.direct_top1_steps +
    ', recon-fork top4=' + t.recon_fork_top4_steps +
    ', closed-loop promoted=' + t.closed_loop_promoted_steps + ']'
  );
  console.log('Stalls by bucket: ' + JSON.stringify(report.stalls_by_bucket));
  if (opts.outFile) {
    console.log('Report written: ' + path.resolve(opts.outFile));
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  STALL_BUCKETS: STALL_BUCKETS,
  isHousekeepingTurn: isHousekeepingTurn,
  inferEngagementNetworking: inferEngagementNetworking,
  expandShellTargetVars: expandShellTargetVars,
  matchTurnToCatalogMoves: matchTurnToCatalogMoves,
  evaluateClosedLoopReachability: evaluateClosedLoopReachability,
  replayWalkthrough: replayWalkthrough,
  runTrajectoryHarvest: runTrajectoryHarvest
};
