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
  PURE_REPL_SUBCOMMAND_LINE_RE,
  isExternalReferenceUrlOrCommand,
  extractWalkthroughTurns,
  discoverAlternates,
  discoverCorpusEntries
} = require('./markdown-extractor');

const QA_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_CORPUS_DIR = fs.existsSync(path.join(QA_ROOT, 'tests', 'corpus', '0xdf-oscp', 'walkthroughs'))
  ? path.join(QA_ROOT, 'tests', 'corpus', '0xdf-oscp', 'walkthroughs')
  : path.resolve(QA_ROOT, '..', '0xdf-offsec-complete-2026-08-20');

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

const SUDO_TRANSPARENT_TOOLS_RE = /^(?:hashcat|john|[a-z0-9_]+2john|nmap|masscan|rustscan|feroxbuster|gobuster|ffuf|dirsearch|dirb|wfuzz|nikto|nuclei|wpscan|sqlmap|hydra|whatweb|httpx|impacket-[\w-]+|(?:secretsdump|getuserspns|getnpusers|getst|gettgt|wmiexec|psexec|smbexec|atexec|dcomexec|mssqlclient|smbclient|lookupsid|rpcdump|samrdump|finddelegation|ntlmrelayx|dacledit|owneredit|aclpwn|addcomputer|ticketer|changepasswd|targetedkerberoast|timeroast|pywhisker)(?:\.py)?|nxc|netexec|crackmapexec|cme|smbmap|rpcclient|enum4linux(?:-ng)?|ldapsearch|certipy(?:-ad)?|bloodyad|bloodhound(?:-ce)?-python|rusthound(?:-ce)?|kerbrute|evil-winrm(?:-py)?|xfreerdp3?|rdesktop|responder|mitm6|chisel|ligolo[-\w]*|socat|tcpdump|tshark|openvpn|ip|mount|python[23]?|curl|wget|ike-scan|snmpwalk|snmpbulkwalk|onesixtyone|showmount|git[-_]dumper(?:\.py)?|msfconsole|msfvenom|searchsploit)$/i;

function stripCommandWrappers(cmd) {
  let s = String(cmd || '').trim();
  if (!s) return '';
  let changed = true;
  while (changed) {
    changed = false;
    let next = s
      .replace(/^cd\s+(?:-[LP]\s+)?(?:"[^"]+"|'[^']+'|[^;&|<>\s]+)\s*&&\s*/i, '')
      .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S+)\s+)+/, '')
      .replace(/^(?:proxychains4?(?:\s+-q|\s+-f\s+\S+)*|time|rlwrap(?:\s+-[A-Za-z0-9]+)*|stdbuf(?:\s+-\S+)*|timeout\s+\S+)\s+/i, '');
    if (/^sudo\b/i.test(next) && !/^sudo\s+(?:-[A-Za-z]*[lisV]\b|--list\b|--version\b|su\b)/i.test(next)) {
      const afterSudo = next.replace(/^sudo(?:\s+-E|\s+(?:-[uUggh]\s+\S+|-[A-Za-z]+))*\s+/i, '').trim();
      const headRaw = (afterSudo.split(/\s+/)[0] || '').replace(/^["']|["']$/g, '').split(/[\\/]/).pop();
      const headClean = headRaw.replace(/\.(?:bin|exe)$/i, '').toLowerCase();
      if (afterSudo && afterSudo !== next && (SUDO_TRANSPARENT_TOOLS_RE.test(headRaw) || SUDO_TRANSPARENT_TOOLS_RE.test(headClean) || /^(?:proxychains4?|time|rlwrap|stdbuf|timeout|[A-Za-z_][A-Za-z0-9_]*=)/i.test(afterSudo))) {
        next = afterSudo;
      }
    }
    if (next !== s) {
      s = next.trim();
      changed = true;
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
  if (base === 'evil-winrm-py') return 'evil-winrm';
  if (base === 'certipy-ad') return 'certipy';
  if (base === 'enum4linux-ng') return 'enum4linux';
  if (base === 'bloodhound-python' || base === 'bloodhound-ce-python' || base === 'rusthound-ce' || base === 'rusthound') return 'bloodhound';
  if (base === 'git_dumper') return 'git-dumper';
  if (base === 'python3' || base === 'python2') return 'python';
  if (base === 'pwsh') return 'powershell';
  if (base === 'ncat' || base === 'netcat') return 'nc';
  if (base === 'xfreerdp3' || base === 'rdesktop') return 'xfreerdp';
  return base;
}

function extractPrimaryTool(cmd) {
  const clean = stripCommandWrappers(cmd);
  if (!clean) return '';
  if (/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s+=\s*(?!=)\S/.test(clean)) return '';
  const toks = clean.split(/\s+/);
  const first = canonicalTool(toks[0]);
  if (first === 'python' && toks.length > 1) {
    if (toks[1] === '-m' && toks[2]) return 'python -m ' + toks[2].toLowerCase();
    const scriptTool = canonicalTool(toks[1]);
    if (scriptTool && !scriptTool.startsWith('-')) return scriptTool;
  }
  return first;
}

function splitShellClausesQuoteAware(cmdStr) {
  const s = String(cmdStr || '');
  const out = [];
  let cur = '';
  let quote = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      cur += ch;
      if (ch === '\\' && quote === '"' && i + 1 < s.length) {
        cur += s[++i];
      } else if (ch === quote) {
        quote = '';
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === '\\' && i + 1 < s.length) {
      cur += ch + s[++i];
      continue;
    }
    if (ch === ';') {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      continue;
    }
    if ((ch === '&' && s[i + 1] === '&') || (ch === '|' && s[i + 1] === '|')) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      i++;
      continue;
    }
    if (ch === '|') {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function applyIpAliases(text, ipAliasMap) {
  let s = String(text || '');
  if (!s || !ipAliasMap) return s;
  const fromIps = Object.keys(ipAliasMap);
  if (!fromIps.length) return s;
  for (const fromIp of fromIps) {
    const toIp = ipAliasMap[fromIp];
    if (!fromIp || !toIp || fromIp === toIp) continue;
    const re = new RegExp('(?<![\\d.])' + fromIp.replace(/\./g, '\\.') + '(?![\\d.])', 'g');
    s = s.replace(re, toIp);
  }
  return s;
}

function isRfc1918Prefix2(prefix2) {
  return prefix2 === '192.168'
    || /^10\.\d+$/.test(prefix2)
    || /^172\.(?:1[6-9]|2\d|3[01])$/.test(prefix2);
}

function spansAreNonOverlapping(spA, spB) {
  if (spA.lastTurn < spB.firstTurn || spB.lastTurn < spA.firstTurn) return true;
  const arrA = spA.soloTurns.length > 0 ? spA.soloTurns : spA.turns;
  const arrB = spB.soloTurns.length > 0 ? spB.soloTurns : spB.turns;
  if (!arrA.length || !arrB.length) return false;
  if (arrA[arrA.length - 1] < arrB[0] || arrB[arrB.length - 1] < arrA[0]) return true;

  function trimSingleBoundaryOutlier(arr) {
    if (arr.length < 3) return [arr];
    const variants = [arr];
    if (arr[1] - arr[0] > 3) variants.push(arr.slice(1));
    if (arr[arr.length - 1] - arr[arr.length - 2] > 3) variants.push(arr.slice(0, -1));
    return variants;
  }

  const varsA = trimSingleBoundaryOutlier(arrA);
  const varsB = trimSingleBoundaryOutlier(arrB);
  for (let i = 0; i < varsA.length; i++) {
    for (let j = 0; j < varsB.length; j++) {
      const a = varsA[i];
      const b = varsB[j];
      if (a[a.length - 1] < b[0] || b[b.length - 1] < a[0]) return true;
    }
  }
  return false;
}

function detectSequentialRevertAliases(turns, selfIps, preferredTarget) {
  const spansByIp = Object.create(null);
  const cooccurringPairs = new Set();
  const cooccurringSubnetPairs = new Set();
  const oct3FirstSeen = Object.create(null);

  for (let idx = 0; idx < (turns || []).length; idx++) {
    const t = turns[idx] || {};
    const cmd = String(t.command || '');
    const out = String(t.stdout || t.output || '');
    const turnIps = new Set();

    let m;
    IPV4_GLOBAL_RE.lastIndex = 0;
    while ((m = IPV4_GLOBAL_RE.exec(cmd)) !== null) {
      const ip = m[1];
      if (isPrivateLabIpv4(ip) && !selfIps.has(ip) && !ATTACKER_SUBNET_RE.test(ip)) {
        turnIps.add(ip);
      }
    }
    const nmapM = /Nmap scan report for (?:[^\r\n(]+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?/i.exec(out);
    if (nmapM && isPrivateLabIpv4(nmapM[1]) && !selfIps.has(nmapM[1]) && !ATTACKER_SUBNET_RE.test(nmapM[1])) {
      turnIps.add(nmapM[1]);
    }
    const nxcM = /^(?:SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|VNC|WMI)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+/im.exec(out);
    if (nxcM && isPrivateLabIpv4(nxcM[1]) && !selfIps.has(nxcM[1]) && !ATTACKER_SUBNET_RE.test(nxcM[1])) {
      turnIps.add(nxcM[1]);
    }

    const allInTurn = [];
    IPV4_GLOBAL_RE.lastIndex = 0;
    while ((m = IPV4_GLOBAL_RE.exec(cmd + '\n' + out)) !== null) {
      const ip = m[1];
      if (isPrivateLabIpv4(ip) && !selfIps.has(ip) && !ATTACKER_SUBNET_RE.test(ip)) {
        if (allInTurn.indexOf(ip) < 0) allInTurn.push(ip);
      }
    }
    for (let i = 0; i < allInTurn.length; i++) {
      const pa = allInTurn[i].split('.');
      const prefA = pa[0] + '.' + pa[1];
      for (let j = i + 1; j < allInTurn.length; j++) {
        const a = allInTurn[i];
        const b = allInTurn[j];
        cooccurringPairs.add(a < b ? (a + '|' + b) : (b + '|' + a));
        const pb = b.split('.');
        const prefB = pb[0] + '.' + pb[1];
        if (prefA === prefB && pa[2] !== pb[2]) {
          const oLo = Number(pa[2]) < Number(pb[2]) ? pa[2] : pb[2];
          const oHi = Number(pa[2]) < Number(pb[2]) ? pb[2] : pa[2];
          cooccurringSubnetPairs.add(prefA + ':' + oLo + '|' + oHi);
        }
      }
    }

    const isFocusedTurn = turnIps.size <= 2 && allInTurn.length <= 2;
    for (const ip of turnIps) {
      const p = ip.split('.');
      const prefix2 = p[0] + '.' + p[1];
      if (!isRfc1918Prefix2(prefix2)) continue;
      const octKey = prefix2 + ':' + p[2];
      if (oct3FirstSeen[octKey] === undefined) oct3FirstSeen[octKey] = idx;
      if (!spansByIp[ip]) {
        spansByIp[ip] = {
          ip: ip,
          prefix2: prefix2,
          oct3: p[2],
          host4: p[3],
          firstTurn: idx,
          lastTurn: idx,
          turns: [idx],
          soloTurns: isFocusedTurn ? [idx] : []
        };
      } else {
        spansByIp[ip].lastTurn = idx;
        spansByIp[ip].turns.push(idx);
        if (isFocusedTurn) spansByIp[ip].soloTurns.push(idx);
      }
    }
  }

  const groups = Object.create(null);
  for (const ip of Object.keys(spansByIp)) {
    const sp = spansByIp[ip];
    const key = sp.prefix2 + '.*.' + sp.host4;
    if (!groups[key]) groups[key] = [];
    groups[key].push(sp);
  }

  // Count how many distinct host4 endpoints in the same prefix2 share an identical
  // non-co-occurring third-octet substitution pair (octLo, octHi).
  const octPairHostCounts = Object.create(null);
  for (const key of Object.keys(groups)) {
    const grp = groups[key];
    if (grp.length < 2) continue;
    const seenPairsForHost = new Set();
    for (let i = 0; i < grp.length; i++) {
      for (let j = i + 1; j < grp.length; j++) {
        const a = grp[i];
        const b = grp[j];
        const ipPair = a.ip < b.ip ? (a.ip + '|' + b.ip) : (b.ip + '|' + a.ip);
        if (cooccurringPairs.has(ipPair)) continue;
        const oLo = Number(a.oct3) < Number(b.oct3) ? a.oct3 : b.oct3;
        const oHi = Number(a.oct3) < Number(b.oct3) ? b.oct3 : a.oct3;
        const subKey = a.prefix2 + ':' + oLo + '|' + oHi;
        if (cooccurringSubnetPairs.has(subKey)) continue;
        seenPairsForHost.add(subKey);
      }
    }
    for (const sk of seenPairsForHost) {
      octPairHostCounts[sk] = (octPairHostCounts[sk] || 0) + 1;
    }
  }

  const prefParts = preferredTarget && isPrivateLabIpv4(preferredTarget) ? preferredTarget.split('.') : null;
  const prefPrefix2 = prefParts ? (prefParts[0] + '.' + prefParts[1]) : '';
  const prefOct3 = prefParts ? prefParts[2] : '';

  const aliasMap = Object.create(null);
  for (const key of Object.keys(groups)) {
    const grp = groups[key];
    if (grp.length < 2) continue;
    grp.sort((a, b) => a.firstTurn - b.firstTurn);

    // Build connected components of valid revert-alias pairs within this (prefix2, host4) group
    const parent = grp.map((_, idx) => idx);
    function find(x) {
      while (parent[x] !== x) {
        parent[x] = parent[parent[x]];
        x = parent[x];
      }
      return x;
    }
    function unite(x, y) {
      const rx = find(x);
      const ry = find(y);
      if (rx !== ry) parent[ry] = rx;
    }

    for (let i = 0; i < grp.length; i++) {
      for (let j = i + 1; j < grp.length; j++) {
        const a = grp[i];
        const b = grp[j];
        const ipPair = a.ip < b.ip ? (a.ip + '|' + b.ip) : (b.ip + '|' + a.ip);
        if (cooccurringPairs.has(ipPair)) continue;
        const oLo = Number(a.oct3) < Number(b.oct3) ? a.oct3 : b.oct3;
        const oHi = Number(a.oct3) < Number(b.oct3) ? b.oct3 : a.oct3;
        const subKey = a.prefix2 + ':' + oLo + '|' + oHi;
        if (cooccurringSubnetPairs.has(subKey)) continue;
        const siblingCorroborated = (octPairHostCounts[subKey] || 0) >= 2;
        if (spansAreNonOverlapping(a, b) || siblingCorroborated) {
          unite(i, j);
        }
      }
    }

    const comps = Object.create(null);
    for (let i = 0; i < grp.length; i++) {
      const r = find(i);
      if (!comps[r]) comps[r] = [];
      comps[r].push(grp[i]);
    }

    for (const r of Object.keys(comps)) {
      const comp = comps[r];
      if (comp.length < 2) continue;
      // Ensure no pair inside the transitive component co-occurred in the same turn
      let compCooccurred = false;
      for (let i = 0; i < comp.length && !compCooccurred; i++) {
        for (let j = i + 1; j < comp.length; j++) {
          const a = comp[i].ip;
          const b = comp[j].ip;
          const oLo = Number(comp[i].oct3) < Number(comp[j].oct3) ? comp[i].oct3 : comp[j].oct3;
          const oHi = Number(comp[i].oct3) < Number(comp[j].oct3) ? comp[j].oct3 : comp[i].oct3;
          const subKey = comp[i].prefix2 + ':' + oLo + '|' + oHi;
          if (cooccurringPairs.has(a < b ? (a + '|' + b) : (b + '|' + a)) || cooccurringSubnetPairs.has(subKey)) {
            compCooccurred = true;
            break;
          }
        }
      }
      if (compCooccurred) continue;

      let canonical = '';
      if (preferredTarget && comp.some(g => g.ip === preferredTarget)) {
        canonical = preferredTarget;
      } else if (prefPrefix2 && comp[0].prefix2 === prefPrefix2 && comp.some(g => g.oct3 === prefOct3)) {
        canonical = comp.find(g => g.oct3 === prefOct3).ip;
      } else {
        comp.sort((a, b) => {
          const seenA = oct3FirstSeen[a.prefix2 + ':' + a.oct3];
          const seenB = oct3FirstSeen[b.prefix2 + ':' + b.oct3];
          if (seenA !== seenB) return seenA - seenB;
          return a.firstTurn - b.firstTurn;
        });
        canonical = comp[0].ip;
      }
      for (const g of comp) {
        if (g.ip !== canonical) aliasMap[g.ip] = canonical;
      }
    }
  }
  return aliasMap;
}

function inferEngagementNetworking(turns, opts) {
  opts = opts || {};
  let lhost = opts.lhost || '';
  const selfIps = new Set();
  if (lhost) selfIps.add(lhost);

  const scannedTargetIps = new Set();
  for (const t of turns || []) {
    const rawCmd = String((t && t.command) || '').trim();
    const cleanScanCmd = stripCommandWrappers(rawCmd);
    const out = String((t && (t.stdout || t.output)) || '');
    if (/^(?:nmap|rustscan|masscan)\b/i.test(cleanScanCmd)) {
      const cmdNoSrc = cleanScanCmd.replace(/(?:^|\s)-S\s+\d{1,3}(?:\.\d{1,3}){3}\b/g, ' ');
      let sm;
      IPV4_GLOBAL_RE.lastIndex = 0;
      while ((sm = IPV4_GLOBAL_RE.exec(cmdNoSrc)) !== null) {
        if (isPrivateLabIpv4(sm[1]) && !ATTACKER_SUBNET_RE.test(sm[1])) {
          scannedTargetIps.add(sm[1]);
        }
      }
    }
    const nmapRepRe = /Nmap scan report for (?:[^\r\n(]+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?/gi;
    let nm;
    while ((nm = nmapRepRe.exec(out)) !== null) {
      if (isPrivateLabIpv4(nm[1]) && !ATTACKER_SUBNET_RE.test(nm[1])) {
        scannedTargetIps.add(nm[1]);
      }
    }
  }

  const varMap = Object.create(null);
  const candidateCounts = Object.create(null);
  const candidateOrder = [];

  for (const t of turns || []) {
    const pLine = String(t.promptLine || '');
    const cmd = String(t.command || '');
    const out = String(t.stdout || t.output || '');

    const pm = LHOST_PROMPT_RE.exec(pLine);
    if (pm && isPrivateLabIpv4(pm[1]) && !scannedTargetIps.has(pm[1])) {
      if (!lhost) lhost = pm[1];
      selfIps.add(pm[1]);
    }
    const isMsfvenomBindPayload = /\bmsfvenom\b/i.test(cmd) && /\bbind_(?:tcp|udp|ipv6|named_pipe)\b/i.test(cmd);
    const lm = isMsfvenomBindPayload ? null : LHOST_ARG_RE.exec(cmd);
    if (lm && isPrivateLabIpv4(lm[1]) && !scannedTargetIps.has(lm[1])) {
      if (!lhost) lhost = lm[1];
      selfIps.add(lm[1]);
    }

    const isAttackerHost = !t.host || ATTACKER_HOST.test(t.host);
    if (isAttackerHost && /^(?:sudo\s+)?(?:ip\s+(?:-\d\s+)?a(?:ddr)?|ifconfig|hostname\s+-I)\b/i.test(cmd.trim())) {
      let m;
      IPV4_GLOBAL_RE.lastIndex = 0;
      while ((m = IPV4_GLOBAL_RE.exec(out)) !== null) {
        if (isPrivateLabIpv4(m[1]) && !scannedTargetIps.has(m[1])) {
          selfIps.add(m[1]);
          if (!lhost && ATTACKER_SUBNET_RE.test(m[1])) lhost = m[1];
        }
      }
    }

    let am;
    IPV4_GLOBAL_RE.lastIndex = 0;
    while ((am = IPV4_GLOBAL_RE.exec(cmd + '\n' + out)) !== null) {
      if (ATTACKER_SUBNET_RE.test(am[1]) && !scannedTargetIps.has(am[1])) {
        selfIps.add(am[1]);
        if (!lhost) lhost = am[1];
      }
    }
  }

  const ipAliasMap = detectSequentialRevertAliases(turns, selfIps, opts.target || '');

  function resolveIp(rawIp) {
    return (rawIp && ipAliasMap[rawIp]) ? ipAliasMap[rawIp] : rawIp;
  }

  function noteTargetIp(rawIp, weight) {
    const ip = resolveIp(rawIp);
    if (!isPrivateLabIpv4(ip)) return;
    if (selfIps.has(ip) || ATTACKER_SUBNET_RE.test(ip)) return;
    if (!candidateCounts[ip]) {
      candidateCounts[ip] = 0;
      candidateOrder.push(ip);
    }
    candidateCounts[ip] += (weight || 1);
  }

  for (const t of turns || []) {
    const cmd = applyIpAliases(String(t.command || '').trim(), ipAliasMap);
    const out = applyIpAliases(String(t.stdout || t.output || ''), ipAliasMap);

    const vm = SHELL_VAR_ASSIGN_RE.exec(cmd);
    if (vm && isPrivateLabIpv4(vm[3]) && !selfIps.has(vm[3])) {
      varMap[vm[1]] = resolveIp(vm[3]);
      noteTargetIp(vm[3], 5);
    }

    const nmapM = /Nmap scan report for (?:[^\r\n(]+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?/i.exec(out);
    if (nmapM) noteTargetIp(nmapM[1], 6);

    const nxcM = /^(?:SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|VNC|WMI)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+/im.exec(out);
    if (nxcM) noteTargetIp(nxcM[1], 5);

    if (isAttackerTurn(t) || /\b(?:ssh|scp|evil-winrm|impacket-[\w-]+|(?:psexec|wmiexec|smbexec|atexec|dcomexec|mssqlclient)(?:\.py)?|nxc|netexec|crackmapexec|cme|nmap|rustscan|masscan|chisel|ligolo[-\w]*|socat|portfwd|Enter-PSSession|Invoke-Command)\b/i.test(cmd)) {
      let cm;
      IPV4_GLOBAL_RE.lastIndex = 0;
      while ((cm = IPV4_GLOBAL_RE.exec(cmd)) !== null) {
        const ip = cm[1];
        if (!selfIps.has(ip)) noteTargetIp(ip, 3);
      }
    }
  }

  if (!lhost) lhost = '10.10.14.5';
  selfIps.add(lhost);

  const sortedTargets = candidateOrder
    .filter(ip => !selfIps.has(ip))
    .sort((a, b) => (candidateCounts[b] - candidateCounts[a]) || (candidateOrder.indexOf(a) - candidateOrder.indexOf(b)));

  const primaryTarget = resolveIp(opts.target || sortedTargets[0] || '10.10.10.50');
  if (sortedTargets.indexOf(primaryTarget) < 0) sortedTargets.unshift(primaryTarget);

  return {
    lhost: lhost,
    primaryTarget: primaryTarget,
    targets: sortedTargets,
    selfIps: Array.from(selfIps),
    varMap: varMap,
    ipAliasMap: ipAliasMap
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

const ATTACKER_ONLY_BARE_PROMPT_TOOLS_RE = /^(?:nmap|rustscan|masscan|gobuster|feroxbuster|ffuf|wfuzz|dirb|dirsearch|nikto|whatweb|wpscan|nuclei|httpx|sqlmap|hydra|medusa|ncrack|hashcat|john|[a-z0-9_]+2john|searchsploit|msfvenom|msfconsole|nxc|netexec|crackmapexec|cme|evil-winrm(?:-py)?|xfreerdp3?|rdesktop|impacket-[\w-]+|(?:secretsdump|getuserspns|getnpusers|getst|gettgt|dacledit|owneredit|aclpwn|pywhisker|wmiexec|psexec|smbexec|atexec|mssqlclient)(?:\.py)?|bloodhound(?:-ce)?-python|rusthound(?:-ce)?|certipy(?:-ad)?|bloodyad|kerbrute|enum4linux(?:-ng)?|smbmap|responder|git[-_]dumper(?:\.py)?)\b/i;

function getPreCommandPromptLine(turn) {
  if (!turn) return '';
  let pl = String(turn.promptLine || '');
  const fp = String(turn.followPrompt || '').trim();
  if (fp && pl.indexOf('\n') >= 0) {
    const parts = pl.split(/\r?\n/);
    if (parts[parts.length - 1].trim() === fp) {
      pl = parts.slice(0, -1).join('\n');
    }
  }
  return pl;
}

function stripPromptPrefixFromPreLine(prePl, rawCmd) {
  const clean = String(prePl || '').trim();
  if (!clean) return '';
  const lastLine = clean.split(/\r?\n/).pop().trim();
  const cmd = String(rawCmd || '').trim();
  if (!cmd) return lastLine;
  const idx = lastLine.lastIndexOf(cmd);
  return (idx > 0 ? lastLine.slice(0, idx) : lastLine).trim();
}

function isDosBoxPromptOrTurn(turn, prePromptLine) {
  const pl = String(prePromptLine != null ? prePromptLine : getPreCommandPromptLine(turn)).trim();
  const cmd = String((turn && turn.command) || '').trim();
  const out = String((turn && (turn.stdout || turn.output)) || '');
  if (/^Z:\\>/i.test(pl) || /\bDOSBox\b/i.test(pl + '\n' + out)) return true;
  if (/^[A-Z]:\\>/i.test(pl) && (/^\s*mount\s+[a-z]\s+\//i.test(cmd) || /(?:^|\s)\/(?:etc|root|home|var|usr|opt|tmp|bin)\//i.test(cmd))) {
    return true;
  }
  return false;
}

function inspectPreCommandTargetPrompt(turn, prePl, currentFacts, extraCtx) {
  const pl = String(prePl || '').trim();
  if (!pl || !turn) return null;
  if (turn.localContainer || (extraCtx && extraCtx.inLocalContainerShell)) return null;
  if (turn.host && (ATTACKER_HOST.test(turn.host) || (extraCtx && extraCtx.launchedLocalContainer && /^[0-9a-f]{12}$/i.test(turn.host)))) return null;
  if (/^\s*[┌╭]──\(/.test(pl) || /\[(?:tun|tap|vpn|wg)\d*:/i.test(pl)) return null;
  if (isDosBoxPromptOrTurn(turn, pl)) return null;

  const hasFact = k => Boolean(currentFacts && typeof currentFacts.has === 'function' && currentFacts.has(k));

  if ((hasFact('foothold.linux') || hasFact('access.root')) && (turn.kind === 'cmd' || /^\s*[A-Za-z]:\\>/i.test(pl))) {
    return null;
  }

  const shM = /^\s*(?:(?:ba|da|z|k|a)?sh-[0-9.]+|[A-Za-z0-9_.-]{2,32}-[3-6]\.\d+)\s*([#$])/i.exec(pl);
  if (shM) {
    const priv = shM[1] === '#';
    if (!hasFact('foothold.linux') || (priv && !hasFact('access.root'))) {
      return { os: 'linux', privileged: priv, promptPrefix: priv ? 'sh-5.1#' : 'sh-5.1$' };
    }
    return null;
  }

  const absCwdM = /^\s*\/(?:[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*)?\/?\s+([#$])(?:\s|$)/.exec(pl);
  if (absCwdM && !/^\s*\/\//.test(pl)) {
    const priv = absCwdM[1] === '#';
    if (!hasFact('foothold.linux') || (priv && !hasFact('access.root'))) {
      return { os: 'linux', privileged: priv, promptPrefix: priv ? 'sh-5.1#' : 'sh-5.1$' };
    }
    return null;
  }

  if (hasFact('foothold.linux') && !hasFact('access.root') && extraCtx && extraCtx.inTargetRootCwd && /^\s*#\s+\S/.test(pl)) {
    return { os: 'linux', privileged: true, promptPrefix: 'sh-5.1#' };
  }

  if (turn.kind === 'unix' && ((turn.host && !ATTACKER_HOST.test(turn.host)) || turn.isRelCwdUnix || turn.isCustomSuidBash || turn.isAbsCwdUnix) && !ATTACKER_HOST.test(turn.user || '')) {
    const pfx = stripPromptPrefixFromPreLine(pl, turn.rawCommand);
    if (!pfx) return null;
    const priv = turn.user === 'root' || /#\s*$/.test(pfx);
    if (!hasFact('foothold.linux') || (priv && !hasFact('access.root'))) {
      return { os: 'linux', privileged: priv, promptPrefix: pfx };
    }
    return null;
  }

  if (turn.kind === 'powershell' || turn.kind === 'cmd') {
    const pfx = stripPromptPrefixFromPreLine(pl, turn.rawCommand);
    if (!pfx || !/(?:PS\s*(?:>|\s+(?:[A-Za-z]:\\|[A-Za-z0-9_.\\-]+\s*::\\\\|[A-Za-z]{2,12}:\\))|Evil-WinRM|evil-winrm(?:-py)?|[A-Za-z]:\\(?:Users|Windows|Program|inetpub|Temp|tmp)|@[A-Za-z0-9_.-]+\s+[A-Za-z]:\\)/i.test(pfx)) {
      return null;
    }
    const priv = /^administrator$/i.test(turn.user || '')
      || /C:\\Users\\Administrator(?:\\|>|\s|$)|C:\\Windows\\system32(?:\\|>|\s|$)/i.test(pfx);
    if (!hasFact('foothold.windows') || (priv && !hasFact('access.admin') && !hasFact('access.system'))) {
      return { os: 'windows', privileged: priv, promptPrefix: pfx };
    }
    return null;
  }

  return null;
}

const VPN_TUNNEL_SNIFFER_RE = /\b(?:tcpdump|tshark|wireshark)\b[^\r\n]*\s-i\s+(?:tun|tap|wg)\d+\b/i;
const METASYNTACTIC_TEMPLATE_CMD_RE = /(?:^|[\s/:=@])\[(?:key|value|query|username|hostname|password|passwd|port|url|uri|ip|target|target_ip|domain|cmd|command|file|filename|filepath|path|token|hash|secret|wordlist|interface|options?)\](?:$|[\s/:=@])/i;

function isAttackerTurn(turn, ctx) {
  if (!turn) return true;
  ctx = ctx || {};
  if (turn.localContainer || ctx.inLocalContainerShell) return true;
  if (ctx.launchedLocalContainer && /^[0-9a-f]{12}$/i.test(turn.host || '')) return true;
  const facts = ctx.facts || null;
  const prePl = getPreCommandPromptLine(turn);
  if (turn.kind === 'powershell' || turn.kind === 'cmd') return false;
  if (VPN_TUNNEL_SNIFFER_RE.test(String(turn.command || '')) && !(turn.host && !ATTACKER_HOST.test(turn.host))) {
    return true;
  }
  if (turn.hostHint === 'windows' || turn.hostHint === 'remote-windows' || /^remote-/i.test(turn.hostHint || '')) return false;
  if (turn.hostHint && !ATTACKER_HOST.test(turn.hostHint)) return false;
  if (turn.host && !ATTACKER_HOST.test(turn.host)) return false;
  if (turn.user && /^(?:www-data|apache|nginx|daemon|nobody|postgres|mysql|mssql|tomcat|jenkins|svc[_-])/i.test(turn.user)) {
    return false;
  }
  if (/^\s*(?:(?:ba|da|z|k|a)?sh-[0-9.]+|[A-Za-z0-9_.-]{2,32}-[3-6]\.\d+)\s*[#$]/i.test(prePl)) {
    return false;
  }
  if (!/^\s*\/\//.test(prePl) && /^\s*\/(?:[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*)?\/?\s+[#$](?:\s|$)/.test(prePl)) {
    return false;
  }
  if (!turn.host && (turn.kind === 'bare' || turn.isHash || turn.isDollar || /^\s*[$#]\s+\S/.test(prePl))) {
    const hasLinuxShellState = Boolean(
      ctx.inTargetShell ||
      (facts && typeof facts.has === 'function' && (
        facts.has('foothold.linux') ||
        facts.has('access.root') ||
        facts.has('access.shell')
      ))
    );
    if (hasLinuxShellState) {
      const cleanCmd = stripCommandWrappers(String(turn.command || '').trim());
      if (!ATTACKER_ONLY_BARE_PROMPT_TOOLS_RE.test(cleanCmd)) {
        return false;
      }
    }
  }
  return !turn.host || ATTACKER_HOST.test(turn.host);
}

function isHousekeepingTurn(turn, ctx) {
  ctx = ctx || {};
  const facts = ctx.facts || null;
  const rawCmd = String((turn && turn.command) || '').trim();
  const out = String((turn && (turn.stdout || turn.output)) || '').trim();
  if (turn && (turn.externalReference || ((turn.kind === 'browser' || turn.ocrKind === 'browser') && isExternalReferenceUrlOrCommand(rawCmd || turn.url || '')))) {
    return { housekeeping: true, reason: 'attacker_reference_lookup' };
  }
  if (!rawCmd) {
    return { housekeeping: !out, reason: out ? 'unprompted_output' : 'empty_turn' };
  }
  if (ctx.inLocalContainerShell || (turn && turn.localContainer)) {
    return { housekeeping: true, reason: 'attacker_local_container_op' };
  }
  if (!out && METASYNTACTIC_TEMPLATE_CMD_RE.test(rawCmd)) {
    return { housekeeping: true, reason: 'metasyntactic_template' };
  }
  if (/^(?:sudo\s+)?[A-Za-z0-9_./\\-]+\s+(?:-h|--help|\/\?)\s*$/i.test(rawCmd)) {
    return { housekeeping: true, reason: 'cli_help_or_version' };
  }
  if (isAttackerTurn(turn, ctx) && /^(?:sudo\s+)?[A-Za-z0-9_./\\-]+\s+(?:-V|--version)\s*$/i.test(rawCmd)) {
    return { housekeeping: true, reason: 'cli_help_or_version' };
  }

  if (SHELL_VAR_ASSIGN_RE.test(rawCmd) || /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S+)$/.test(rawCmd)) {
    return { housekeeping: true, reason: 'shell_var_assignment' };
  }

  if (/^(?:sudo\s+-(?:i|s)(?:\s+-u\s+\S+)?|sudo\s+su(?:\s+-|\s+root)?|su(?:\s+-|\s+root)?|powershell(?:\.exe)?(?:\s+(?:-(?:ep|exec(?:utionpolicy)?)\s+\S+|-nop(?:rofile)?|-sta|-w(?:indowstyle)?\s+\S+|-i(?:nteractive)?))*|pwsh(?:\.exe)?(?:\s+-(?:nop(?:rofile)?|ep\s+\S+))*|cmd(?:\.exe)?|\/bin\/(?:ba|z|da|k|a)?sh(?:\s+-[ip]+)?|(?:ba|z|da|k)?sh(?:\s+-[ip]+)?)\s*$/i.test(rawCmd)) {
    return { housekeeping: true, reason: 'subshell_entry' };
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
  if ((/^(?:nc|ncat|netcat|penelope)\b/i.test(clean) && /\s-[A-Za-z]*l[A-Za-z]*\d*\b/.test(clean))
      || (/^socat\b/i.test(clean) && /\b(?:TCP\d*-LISTEN|UDP\d*-LISTEN|OPENSSL-LISTEN)\b/i.test(clean))) {
    return { housekeeping: true, reason: 'local_listener_wait' };
  }
  if (/^(?:sudo\s+)?(?:tcpdump|tshark|wireshark)\b[^\r\n]*\s-i\s+(?:tun|tap|wg)\d+\b/i.test(rawCmd) && isAttackerTurn(turn, ctx)) {
    return { housekeeping: true, reason: 'attacker_callback_listener' };
  }

  if (isAttackerTurn(turn, ctx)) {
    if (/^(?:sudo\s+)?(?:docker|podman)\s+(?:run|build|pull|exec|ps|images|rm|rmi|stop|kill|inspect|logs|cp|tag)\b/i.test(rawCmd)
        && !/\s(?:-H|--host)\s*(?:=|tcp:|ssh:|\d)/i.test(rawCmd)) {
      return { housekeeping: true, reason: 'attacker_workspace_prep' };
    }
    if (/(?:^|\s|>>?)\/etc\/hosts(?:\s|$|['"])/.test(rawCmd)) {
      return { housekeeping: true, reason: 'attacker_hosts_update' };
    }
    if (!/^find\s+\//i.test(clean) && /^(?:find|tree)\b/i.test(clean) && !/\s-(?:exec|execdir|ok|okdir)\b/i.test(clean)) {
      return { housekeeping: true, reason: 'attacker_local_file_op' };
    }
    if (/^git\s+clone\b/i.test(clean)) {
      const urlM = /(?:https?|git|ssh):\/\/([^/\s:'"]+)|([A-Za-z0-9_.-]+)@([^:\s/'"]+):/i.exec(clean);
      const cloneHost = urlM ? String(urlM[1] || urlM[3] || '').toLowerCase() : '';
      const targetsExternalHost = !cloneHost
        || isExternalReferenceUrlOrCommand('https://' + cloneHost)
        || /(?:^|\.)(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sourceforge\.net)$/i.test(cloneHost);
      if (targetsExternalHost) {
        return { housekeeping: true, reason: 'attacker_workspace_prep' };
      }
    } else if (/^(?:mkdir|rmdir|touch|cp|mv|rm|chmod|chown|tar|unzip|zip|gunzip|wget\s+https?:\/\/(?:github\.com|raw\.githubusercontent\.com))\b/i.test(clean)) {
      return { housekeeping: true, reason: 'attacker_workspace_prep' };
    } else if (/^(?:(?:[a-z0-9_]+-[a-z0-9_.-]+-)?(?:gcc|g\+\+|cc|clang|clang\+\+|mcs|csc|javac|nasm|ld)(?:-\d+(?:\.\d+)*)?|go\s+build|cargo\s+build|dotnet\s+(?:build|publish)|msbuild)\b/i.test(clean)) {
      return { housekeeping: true, reason: 'attacker_workspace_prep' };
    }
    if (turn && turn.tool === 'python' && !out && !/\bpty\.spawn\b/i.test(rawCmd) && /^(?:import\s+\S+|from\s+\S+\s+import\s+\S+|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*=\s*(?!=)\S)/.test(rawCmd)) {
      return { housekeeping: true, reason: 'repl_setup' };
    }
    if (/^(?:ls|ll|la|dir|cat|head|tail|echo|printf|tee|sed|awk|cut|sort|uniq|wc|tr|file|md5sum|sha256sum)\b/i.test(clean)) {
      const hasTargetFoothold = Boolean(
        ctx.inTargetShell ||
        (facts && typeof facts.has === 'function' && (
          facts.has('foothold.linux') ||
          facts.has('foothold.windows') ||
          facts.has('access.root') ||
          facts.has('access.admin') ||
          facts.has('access.system') ||
          facts.has('access.shell')
        ))
      );
      const isFlagFileOp = hasTargetFoothold
        && /^(?:cat|type|head|tail|more|less)\b/i.test(clean)
        && /(?:^|[\s/\\'"`])(?:proof|local|user|root)\.txt\b/i.test(clean);
      if (!isFlagFileOp && !/(?:id_rsa|\.kdbx|\.pfx|\.psafe3|shadow|passwd|ntds|sam\b|system\b|credentials|config|\.env|web\.config|wp-config)/i.test(clean)) {
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

const STANDALONE_SUBCMD_KEYWORDS = new Set([
  'smb', 'ldap', 'winrm', 'mssql', 'ssh', 'ftp', 'rdp', 'vnc', 'wmi', 'dir', 'vhost', 'dns', 'fuzz',
  'http', 'https', 'http-get', 'http-post', 'http-head', 'http-get-form', 'http-post-form',
  'https-get', 'https-post', 'https-head', 'https-get-form', 'https-post-form',
  'telnet', 'mysql', 'postgres', 'redis', 'rsync', 'smtp', 'pop3', 'imap',
  'req', 'auth', 'shadow', 'account', 'dump', 'shares', 'users', 'groups', 'pass-pol',
  'rid-brute', 'kerberoasting', 'asreproast', 'bloodhound', 'spider_plus', 'just-dc',
  'just-dc-ntlm', 'request', 'getcap', 'linpeas', 'winpeas', 'systeminfo', 'cmdkey',
  'socks', 'server', 'client', 'genericall', 'dcsync', 'groupmember', 'rbcd', 'shadowcredentials'
]);

const HASHCAT_GENERIC_RUNTIME_FLAGS = new Set([
  '--force', '--potfile-disable', '--quiet', '--status', '--show', '--username', '--user',
  '-o', '-w', '-r', '-a'
]);

const GENERIC_INTERPRETERS = new Set([
  'python', 'python2', 'python3', 'powershell', 'pwsh', 'cmd', 'sh', 'bash', 'zsh',
  'perl', 'ruby', 'php', 'certutil', 'iwr', 'invoke-webrequest', 'curl', 'wget'
]);

const ANON_EPOCH_MOVE_IDS = [
  'recon-smb-anon',
  'smb-anon-shares',
  'ad-anon-ldap-enum',
  'ldap-anon-bind',
  'rpc-null-enum',
  'fix-samr-null-denied'
];

function extractCommandFlags(cmdStr) {
  const noTemplates = String(cmdStr || '').replace(/\{\{[^}]+\}\}/g, ' ');
  const rawTokens = noTemplates.split(/[\s;|&'"]+/).filter(Boolean);
  const isWinStyle = /[A-Za-z]:\\|\b(?:whoami|xfreerdp|cmd|dir|reg|schtasks|icacls|runas)\b/i.test(noTemplates);
  const isHashcat = extractPrimaryTool(noTemplates) === 'hashcat';
  const out = [];
  const seen = Object.create(null);

  function pushTok(t) {
    if (!t || seen[t]) return;
    seen[t] = 1;
    out.push(t);
  }

  for (let tIdx = 0; tIdx < rawTokens.length; tIdx++) {
    const raw = rawTokens[tIdx];
    const lowRaw = raw.toLowerCase();
    if (isHashcat) {
      if ((lowRaw === '-m' || lowRaw === '--hash-type') && tIdx + 1 < rawTokens.length && /^\d+$/.test(rawTokens[tIdx + 1])) {
        pushTok('-m:' + rawTokens[tIdx + 1]);
        tIdx++;
        continue;
      }
      if (/^-m\d+$/.test(lowRaw)) {
        pushTok('-m:' + lowRaw.slice(2));
        continue;
      }
      if (/^--hash-type=\d+$/.test(lowRaw)) {
        pushTok('-m:' + lowRaw.split('=')[1]);
        continue;
      }
    }
    if (raw === '-H') {
      pushTok('-H');
      continue;
    }
    if (/^--[a-zA-Z0-9][a-zA-Z0-9_-]*(?:=.*)?$/.test(raw)) {
      const eqIdx = raw.indexOf('=');
      const baseFlag = (eqIdx > 0 ? raw.slice(0, eqIdx) : raw).toLowerCase();
      if (baseFlag === '--format' && eqIdx > 0) {
        const fmtVal = raw.slice(eqIdx + 1).trim().toLowerCase();
        if (fmtVal && fmtVal !== 'token') pushTok('--format=' + fmtVal);
        else pushTok('--format');
      } else {
        pushTok(baseFlag);
      }
      continue;
    }
    if (/^-[a-zA-Z][a-zA-Z0-9_-]{0,24}$/.test(raw) || /^-[0-9]{1,4}$/.test(raw)) {
      const low = raw.toLowerCase();
      if (/^-(?:u|p|d|h|i|t|o|v|n|w|x|c|e|f|q|a|r|s)$/.test(low)) continue;
      pushTok(low);
      continue;
    }
    if (isWinStyle && /^\/[a-zA-Z]{2,10}(?::|$)/.test(raw)) {
      pushTok(raw.split(':')[0].toLowerCase());
      continue;
    }
    const protoUriM = /^([a-zA-Z][a-zA-Z0-9+.-]{1,15}):\/\//.exec(raw);
    if (protoUriM) {
      let scheme = protoUriM[1].toLowerCase();
      if (scheme === 'ftps') scheme = 'ftp';
      else if (scheme === 'ldaps') scheme = 'ldap';
      else if (scheme === 'postgresql') scheme = 'postgres';
      else if (scheme === 'smtps') scheme = 'smtp';
      else if (scheme === 'imaps') scheme = 'imap';
      else if (scheme === 'pop3s') scheme = 'pop3';
      if (STANDALONE_SUBCMD_KEYWORDS.has(scheme)) pushTok(scheme);
      continue;
    }
    // Only treat standalone bare words (never filenames/paths containing '.', '/', '\\', ':') as subcommand tokens
    if (/^[a-zA-Z0-9_-]+$/.test(raw)) {
      const low = raw.toLowerCase();
      if (STANDALONE_SUBCMD_KEYWORDS.has(low)) pushTok(low);
    }
  }
  return out;
}

function hasExplicitAuthenticatedCreds(cleanCmd, facts, rawTurnOut) {
  const s = String(cleanCmd || '');
  const out = String(rawTurnOut || '');
  if (/\[\+\]\s*Guest\s+session\b|\bAnonymous\s+login\b|\[\+\]\s*[^\r\n]+\(Guest\)\s*$/im.test(out)) {
    return false;
  }
  const hasKnownCred = Boolean(facts && typeof facts.has === 'function' && facts.has('credential.available'));
  const isHostDashHTool = /^\s*(?:smbmap|ldapsearch)\b/i.test(s);
  const uMatch = /(?:^|\s)-u\s+(?:'([^']*)'|"([^"]*)"|(\S+))/i.exec(s);
  if (uMatch) {
    const uVal = (uMatch[1] !== undefined ? uMatch[1] : (uMatch[2] !== undefined ? uMatch[2] : uMatch[3])).trim();
    const isAnonUser = !uVal || /^(?:''|""|guest|anonymous|null|-)$/i.test(uVal);
    if (!isAnonUser) {
      const pValM = /(?:^|\s)(?:-p|--password)(?:=|\s+)(?:'([^']*)'|"([^"]*)"|(\S+))/i.exec(s);
      if (pValM) {
        const pVal = (pValM[1] !== undefined ? pValM[1] : (pValM[2] !== undefined ? pValM[2] : pValM[3])).trim();
        if (pVal && !/^(?:''|""|null)$/i.test(pVal)) {
          const bareU = uVal.indexOf('\\') >= 0 ? uVal.split('\\').pop() : (uVal.indexOf('/') >= 0 ? uVal.split('/').pop() : uVal);
          if (!hasKnownCred && pVal.toLowerCase() === bareU.toLowerCase()) {
            return false;
          }
          return true;
        }
      }
      if (!isHostDashHTool) {
        const hFlagM = /(?:^|\s)-H\s+(\S+)/.exec(s);
        if (hFlagM && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hFlagM[1]) && !/^[a-z]+:\/\//i.test(hFlagM[1])) {
          return true;
        }
      }
      if (/(?:^|\s)(?:--hashes(?:=|\s+)\S+|-hashes\s+\S+)/i.test(s)) {
        return true;
      }
    }
  }
  const smbU = /(?:^|\s)-U\s+(?:'([^']*)'|"([^"]*)"|(\S+))/.exec(s);
  if (smbU) {
    const up = (smbU[1] !== undefined ? smbU[1] : (smbU[2] !== undefined ? smbU[2] : smbU[3])).trim();
    const pctIdx = up.indexOf('%');
    if (up && pctIdx > 0) {
      const uPart = up.slice(0, pctIdx).trim();
      const pPart = up.slice(pctIdx + 1).trim();
      if (uPart && pPart && !/^(?:guest|anonymous|null)$/i.test(uPart)) {
        const bareU = uPart.indexOf('\\') >= 0 ? uPart.split('\\').pop() : (uPart.indexOf('/') >= 0 ? uPart.split('/').pop() : uPart);
        if (!hasKnownCred && pPart.toLowerCase() === bareU.toLowerCase()) {
          return false;
        }
        return true;
      }
    }
  }
  return false;
}

const SSTI_TEMPLATE_EXPR_RE = /(?:\{\{[\s\S]+?\}\}|\$\{[^}]+\}|<%[\s\S]+?%>|\{%[\s\S]+?%\}|#\{[^}]+\})/;
const SSTI_TEMPLATE_EXPR_GLOBAL_RE = /(?:\{\{[\s\S]+?\}\}|\$\{[^}]+\}|<%[\s\S]+?%>|\{%[\s\S]+?%\}|#\{[^}]+\})/g;
const SSTI_RCE_PRIMITIVE_RE = /(?:\b(?:exec|system|popen|passthru|shell_exec|proc_open|eval|spawn|fork|Runtime|getRuntime|ProcessBuilder|Execute|ObjectInputStream|child_process|mainModule|require|__import__|__class__|__mro__|__subclasses__|__globals__|__builtins__|__init__|cycler|joiner|namespace|lipsum|from_object|registerUndefinedFilterCallback|getFilter|subprocess|whoami|uname|mkfifo|ncat)\b|\bos\.[A-Za-z_]+|\/bin\/(?:ba)?sh\b|\b(?:sh|bash)\s+-c\b|\bcat\s+\/|\b(?:id|nc|curl|wget)\b(?=[\s'"`()]))/i;

function hasSstiRceTemplatePayload(probeStr) {
  const spans = String(probeStr || '').match(SSTI_TEMPLATE_EXPR_GLOBAL_RE);
  if (!spans || !spans.length) return false;
  return spans.some(sp => SSTI_RCE_PRIMITIVE_RE.test(sp));
}

function decodeUrlProbeText(rawStr) {
  const raw = String(rawStr || '');
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw.replace(/\+/g, ' '));
  } catch (_e) {
    decoded = raw
      .replace(/%20/gi, ' ')
      .replace(/%27/gi, "'")
      .replace(/%22/gi, '"')
      .replace(/%28/gi, '(')
      .replace(/%29/gi, ')')
      .replace(/%3d/gi, '=')
      .replace(/%7b/gi, '{')
      .replace(/%7d/gi, '}')
      .replace(/%2a/gi, '*');
  }
  return raw + '\n' + decoded;
}

function hasRequiredMoveSemantics(moveId, cleanCmd, facts, turn) {
  const raw = String(cleanCmd || '');
  const probe = decodeUrlProbeText(raw);
  if (moveId === 'laps-read') {
    return /(?:ms-mcs-admpwd|mslaps-(?:encrypted)?password|\blaps\b|pylaps|get-laps|lapstoolkit|laps\.py)/i.test(probe);
  }
  if (moveId === 'manual-sqli-exploitation') {
    return /(?:\bunion\s+(?:all\s+)?select\b|\bselect\b[\s\S]*?\bfrom\b|\bsleep\s*\(|\bwaitfor\s+delay\b|\bbenchmark\s*\(|\bpg_sleep\s*\(|\binformation_schema\b|\bxp_cmdshell\b|\bload_file\s*\(|\binto\s+(?:outfile|dumpfile)\b|\bextractvalue\s*\(|\bupdatexml\s*\(|'\s*(?:or|and)\b\s*['0-9a-z_]+\s*=|\b(?:or|and)\s+\d+\s*=\s*\d+|\bsqlmap\b)/i.test(probe);
  }
  if (moveId === 'authz-abuse') {
    return /(?:authorization\s*:|bearer\s+[A-Za-z0-9._~+\/-]+|cookie\s*:|(?:^|\s)(?:-b|--cookie)\s+\S+|x-(?:api-key|auth|access-token|forwarded|original-url|rewrite-url|custom-ip-authorization|real-ip)\s*:|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|(?:[?&]|^|\s|"|'|\{)(?:role|is_admin|isadmin|admin|privilege|priv|group|userid|user_id|uid|account_id|accountid|org_id|tenant_id|owner_id)\s*[:=])/i.test(probe);
  }
  if (moveId === 'xxe') {
    if (/^(?:curl|wget|http|httpie|iwr|invoke-webrequest|invoke-restmethod|irm)\b/i.test(raw)) {
      return /(?:<!doctype\b|<!entity\b|<\?xml\b|content-type\s*:\s*(?:application|text)\/[^\r\n"']*xml\b|\.xml\b|<[A-Za-z_][A-Za-z0-9_.:-]*>[\s\S]*<\/[A-Za-z_][A-Za-z0-9_.:-]*>)/i.test(probe);
    }
    return true;
  }
  if (moveId === 'powerview-enum') {
    if (turn && turn.tool === 'powerview') return true;
    return /\b(?:powerview|Get-(?:Net|Domain|ObjectAcl)\w*|Find-(?:LocalAdminAccess|DomainShare|DomainUserLocation|InterestingDomainAcl|ForeignUser|ForeignGroup)\w*|Invoke-(?:ShareFinder|UserHunter|ACLScanner|EnumerateLocalAdmin|CheckLocalAdminAccess|FileFinder|EventHunter)\w*|Resolve-IPAddress|Convert-NameToSid|ConvertFrom-SID)\b/i.test(probe);
  }
  if (moveId === 'baron-samedit') {
    return /\b(?:sudoedit|cve-2021-3156|samedit)\b|sudo\s+-s\s+['"]?\\/i.test(probe);
  }
  if (moveId === 'lsass-dump-onbox') {
    return /\b(?:lsass|comsvcs|minidump|procdump|nanodump|pypykatz|sekurlsa|out-minidump|dumpert|handlekatz|ppldump)\b/i.test(probe);
  }
  if (moveId === 'recon-mail') {
    return /(?:\b(?:swaks|smtp-user-enum|sendmail|postfix)\b|(?:smtps?|imaps?|pop3s?):\/\/|-starttls\s+(?:smtp|imap|pop3)\b|(?:^|[\s:])(?:25|110|143|465|587|993|995)(?:\b|\/|$))/i.test(probe);
  }
  if (moveId === 'ssti-to-rce') {
    if (facts && typeof facts.has === 'function' && facts.has('web.ssti_confirmed')) return true;
    return SSTI_TEMPLATE_EXPR_RE.test(probe);
  }
  return true;
}

function scoreCommandAgainstVariant(action, cObj, cleanCmd, scoreCtx) {
  if (!action || !cObj || !cObj.run) return 0;
  const ctx = scoreCtx || {};
  if (!hasRequiredMoveSemantics(action.id, cleanCmd, ctx.facts, ctx.turn)) return 0;
  const rawHeadBin = ctx.rawHeadBin !== undefined
    ? ctx.rawHeadBin
    : canonicalTool((String(cleanCmd || '').split(/\s+/)[0] || ''));
  const cmdTool = ctx.cmdTool !== undefined ? ctx.cmdTool : extractPrimaryTool(cleanCmd);
  const cmdFlags = ctx.cmdFlags || extractCommandFlags(cleanCmd);
  const cmdHashcatModes = ctx.cmdHashcatModes || (cmdTool === 'hashcat' ? cmdFlags.filter(f => f.indexOf('-m:') === 0) : []);
  const hasPassAuth = Boolean(ctx.hasPassAuth);
  const hasHashAuth = Boolean(ctx.hasHashAuth);

  if (hasPassAuth && !hasHashAuth && /(?:\{\{dahash\}\}|\{\{nthash\}\}|\s-H\s|--hashes|-hashes)/i.test(cObj.run) && !/(?:\{\{password\}\}|\s-p\s)/i.test(cObj.run)) {
    return 0;
  }

  let bestVariantScore = 0;
  const clauses = splitShellClausesQuoteAware(cObj.run);
  for (const clause of clauses) {
    const cleanClause = stripCommandWrappers(clause.replace(/\{\{[^}]+\}\}/g, 'TOKEN'));
    if (!cleanClause) continue;
    const clauseTool = extractPrimaryTool(cleanClause);
    const declaredTool = canonicalTool(cObj.tool || action.tool || '');
    const matchedViaClause = Boolean(cmdTool && cmdTool === clauseTool);
    const matchedViaDeclared = Boolean(
      cmdTool
      && !matchedViaClause
      && cmdTool === declaredTool
      && !GENERIC_INTERPRETERS.has(declaredTool)
      && (!clauseTool || GENERIC_INTERPRETERS.has(clauseTool))
    );
    if (!matchedViaClause && !matchedViaDeclared) continue;

    const isGenericTool = GENERIC_INTERPRETERS.has(cmdTool) || GENERIC_INTERPRETERS.has(rawHeadBin);
    let s = isGenericTool ? 2 : 6;
    const clauseFlags = extractCommandFlags(cleanClause);
    let hits = 0;
    let distinctiveHits = 0;
    let misses = 0;
    for (const fl of clauseFlags) {
      if (fl.indexOf('-m:') === 0) {
        if (cmdFlags.indexOf(fl) >= 0) {
          hits += 12;
          distinctiveHits++;
        } else if (cmdHashcatModes.length > 0) {
          misses += 10;
        }
      } else if (cmdTool === 'hashcat' && HASHCAT_GENERIC_RUNTIME_FLAGS.has(fl)) {
        if (cmdFlags.indexOf(fl) >= 0) {
          hits += 1;
        }
      } else if (cmdFlags.indexOf(fl) >= 0) {
        const weight = fl.length > 4 ? 4 : 2;
        hits += weight;
        if (fl.length > 4 && fl !== '--cmd') distinctiveHits++;
      } else if (fl.startsWith('--') && fl.length > 5) {
        misses += 2;
      }
    }
    if (isGenericTool && distinctiveHits === 0) continue;
    s += hits - misses;
    if (s > bestVariantScore) bestVariantScore = s;
  }
  return bestVariantScore;
}

function matchTurnToCatalogMoves(OBOL, turn, ctx) {
  ctx = ctx || {};
  const facts = ctx.facts || null;
  const pack = (OBOL.packs && typeof OBOL.packs.actions === 'function') ? OBOL.packs.actions() : [];
  if (!pack.length) return [];

  let rawCmd = String((turn && turn.command) || '').trim();
  const rawTurnOut = String((turn && (turn.stdout || turn.output)) || '');
  if (!rawCmd) {
    const openPortRows = rawTurnOut.match(/^\s*\d+\/(?:tcp|udp)\s+open\b/gim) || [];
    if (openPortRows.length >= 2) {
      const hasVersionOrScripts = /^\s*\d+\/(?:tcp|udp)\s+open\s+\S+\s+\S+|^\s*\|[_ ]/m.test(rawTurnOut);
      rawCmd = hasVersionOrScripts ? 'nmap -sC -sV' : 'nmap';
    } else {
      return [];
    }
  }

  const cleanCmd = stripCommandWrappers(rawCmd);
  const rawHeadBin = canonicalTool((cleanCmd.split(/\s+/)[0] || ''));
  const cmdTool = extractPrimaryTool(cleanCmd);
  const cmdFlags = extractCommandFlags(cleanCmd);
  const isUnambiguousWinLocalEnum = /^(?:whoami(?:\.exe)?\s+\/(?:priv|groups|all)\b|cmdkey(?:\.exe)?\s+\/list\b|systeminfo(?:\.exe)?\b)/i.test(cleanCmd);
  const isUnambiguousLinuxLocalEnum = /^(?:sudo\s+(?:-[A-Za-z]*l\b|--list\b)|getcap\s+-r\s+\/|find\s+\/\s+[^\r\n]*-perm\b|(?:sh|bash|\.)\s+\S*linpeas|\.?\/?linpeas\.sh\b)/i.test(cleanCmd);
  const prePlForLocus = getPreCommandPromptLine(turn);
  const hasExplicitAttackerLocus = Boolean(
    (turn && turn.host && ATTACKER_HOST.test(turn.host)) ||
    /^\s*[┌╭]──\(/.test(prePlForLocus) ||
    /\[(?:tun|tap|vpn|wg)\d*:/i.test(prePlForLocus) ||
    ctx.inLocalContainerShell ||
    (ctx.launchedLocalContainer && turn && /^[0-9a-f]{12}$/i.test(turn.host || ''))
  );
  const onTarget = !hasExplicitAttackerLocus && (
    !isAttackerTurn(turn, ctx) ||
    isUnambiguousWinLocalEnum ||
    isUnambiguousLinuxLocalEnum ||
    !!(facts && (facts.has('foothold.linux') || facts.has('foothold.windows')) && /^(?:sudo|find|getcap|whoami|systeminfo|cmdkey|cat|type|Get-ChildItem|gci|Get-Content|gc|dir|tree|uname|crontab)\b/i.test(cleanCmd))
  );
  const hasAdminOrSystem = !!(facts && (facts.has('access.admin') || facts.has('access.system')));
  const hasNtdsLoot = !!(facts && facts.has('loot.ntds'));

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
  const excludedIds = new Set();
  function bump(id, pts) {
    if (!byId[id] || excludedIds.has(id)) return;
    scored[id] = Math.max(scored[id] || 0, pts);
  }

  const hasHashAuth = (!/^(?:smbmap|ldapsearch)$/.test(cmdTool) && /(?:^|\s)-H(?:\s|$)/.test(cleanCmd))
    || /(?:^|\s)(?:--hashes|-hashes|\/pth:)(?:\s|=|$)/i.test(cleanCmd);
  const isRemoteSessionTool = /^(?:evil-winrm|xfreerdp|psexec|wmiexec|smbexec|atexec|dcomexec)$/.test(cmdTool);
  const isAttackerSideFootholdBridgeTool = Boolean(
    isRemoteSessionTool ||
    (turn && turn.tool === 'powerview') ||
    /^(?:ssh|sshpass|scp|sftp|rsync|nxc|curl|wget|evil-winrm|chisel|ligolo[-\w]*|sshuttle|vncviewer|xtightvncviewer|tigervnc|dpapi|wesng|git|msfvenom)\b/i.test(cmdTool)
  );
  if ((hasExplicitAttackerLocus || !onTarget) && !isAttackerSideFootholdBridgeTool) {
    for (const a of actionableMoves) {
      if (a.locus === 'F') excludedIds.add(a.id);
    }
    for (const tid of ['linux-enum', 'windows-enum']) {
      excludedIds.add(tid);
    }
  }
  const hasPassAuth = isRemoteSessionTool
    ? (/(?:^|\s)(?:-p|--password|\/p:)(?:\s|=|$)/i.test(cleanCmd) || (!hasHashAuth && /\/[^/\s:]+:[^@\s]+@/.test(cleanCmd)))
    : /(?:^|\s)(?:-p\s+(?!''(?:\s|$)|""(?:\s|$))\S+|--password(?:=|\s+)\S+)/i.test(cleanCmd);
  const hasKrbEnv = /\bKRB5CCNAME=\S+/i.test(rawCmd);
  const hasKrbAuth = hasKrbEnv || (cmdTool === 'evil-winrm'
    ? /(?:^|\s)(?:-r|--realm|--spn)\s+\S+/i.test(cleanCmd)
    : /(?:^|\s)(?:-k\b|--kerberos\b|--use-kcache\b)/i.test(cleanCmd));
  const hasCertAuth = cmdTool === 'evil-winrm'
    && /(?:^|\s)(?:-c|--cert)\s+\S+/i.test(cleanCmd)
    && (/(?:^|\s)(?:-k|--key)\s+\S+/i.test(cleanCmd) || /(?:^|\s)-S\b/.test(cleanCmd));
  const explicitAuth = hasExplicitAuthenticatedCreds(cleanCmd, facts, rawTurnOut) || hasKrbAuth || hasCertAuth;

  if (cmdTool === 'evil-winrm') {
    excludedIds.add('getst-impersonation');
  }

  // Exclude anonymous-epoch moves whenever explicit non-anonymous credentials (-u + -p/-H or Kerberos/cert) are supplied
  if (explicitAuth) {
    for (const anonId of ANON_EPOCH_MOVE_IDS) excludedIds.add(anonId);
  }

  // Exclude post-NTDS domain-admin PTH move whenever authenticating with a plaintext password or pre-NTDS hash
  if ((hasPassAuth && !hasHashAuth) || (hasHashAuth && !hasNtdsLoot)) {
    excludedIds.add('own-domain-pth');
  }

  // B2.1: Password vs Hash vs Kerberos/Cert remote interactive / lateral session disambiguation
  if (isRemoteSessionTool) {
    const hasInlineFlagRead = /\b(?:local|user|root|proof)\.txt\b/i.test(cleanCmd);
    if (!hasInlineFlagRead) {
      excludedIds.add('flag-hunt-windows');
      excludedIds.add('flag-hunt-root-windows');
    }
    if (hasPassAuth && !hasHashAuth) {
      bump('win-interactive-shell', 25);
      bump('rdp-interactive', 25);
      bump('lateral-exec', 23);
      bump('validate-credential', 21);
    } else if (hasHashAuth) {
      if (hasNtdsLoot) {
        bump('own-domain-pth', 24);
        bump('win-interactive-shell', 23);
        bump('lateral-exec', 22);
      } else {
        bump('win-interactive-shell', 25);
        bump('lateral-exec', 23);
        bump('validate-credential', 21);
      }
    } else if (hasKrbAuth || hasCertAuth) {
      bump('win-interactive-shell', 25);
      bump('lateral-exec', 23);
      bump('validate-credential', 21);
    }
  }

  // PG-2 B4 / PG-3 B4: Disambiguate GTFOBins find -exec execution vs find -name flag search
  const isFindTool = cmdTool === 'find' || /^sudo\s+(?:-[A-Za-z]+\s+)*\S*find\b/i.test(cleanCmd);
  const findExecM = isFindTool ? /(?:^|\s)-(?:exec|execdir|ok|okdir)\s+([^\r\n;|&]+)/i.exec(cleanCmd) : null;
  let isFindExecShell = false;
  if (findExecM) {
    const execFirstTok = (String(findExecM[1] || '').trim().split(/\s+/)[0] || '').replace(/^['"]|['"]$/g, '');
    const execBase = execFirstTok.split(/[\\/]/).pop().toLowerCase();
    isFindExecShell = Boolean(
      execBase &&
      execBase !== '{}' &&
      !/^(?:cat|head|tail|grep|egrep|fgrep|ls|file|stat|md5sum|sha\d+sum|strings|wc|echo|printf|rm|chmod|chown|cp|mv)$/.test(execBase)
    );
  }
  const findFlagNameM = (isFindTool && !isFindExecShell)
    ? /\s-i?name\s+['"]?\*?(local|user|root|proof)\.txt\*?['"]?(?:\s|;|2>|\||$)/i.exec(cleanCmd)
    : null;
  if (isFindExecShell) {
    excludedIds.add('flag-hunt-linux');
    excludedIds.add('flag-hunt-root-linux');
    excludedIds.add('linux-loot-hunt');
    excludedIds.add('linux-enum');
    if (/^sudo\s+/i.test(rawCmd)) {
      bump('sudo-abuse', 26);
      bump('suid-gtfobins', 22);
    } else {
      bump('suid-gtfobins', 26);
    }
  } else if (findFlagNameM) {
    excludedIds.add('linux-loot-hunt');
    excludedIds.add('linux-enum');
    excludedIds.add('suid-gtfobins');
    const isRootFindFlag = /^(?:root|proof)$/i.test(findFlagNameM[1]);
    bump(isRootFindFlag ? 'flag-hunt-root-linux' : 'flag-hunt-linux', 25);
  }

  // B2.2: Explicit flag file reads vs recursive user/loot/config sweeps on Windows
  const isExplicitFlagRead = !isFindTool && /(?:^|\s)(?:cat|type|Get-Content|gc|more|head|tail)\s+[^\r\n;|&]*\b(local|user|root|proof)\.txt\b/i.test(cleanCmd);
  if (isExplicitFlagRead) {
    const isRootFlag = /\b(?:root|proof)\.txt\b/i.test(cleanCmd);
    const isWin = turn.kind === 'powershell' || turn.kind === 'cmd' || /\btype\b|Get-Content|\bgc\b|[A-Za-z]:\\/i.test(cleanCmd) || !!(facts && facts.has('foothold.windows'));
    if (isWin) {
      bump(isRootFlag ? 'flag-hunt-root-windows' : 'flag-hunt-windows', 25);
    } else {
      bump(isRootFlag ? 'flag-hunt-root-linux' : 'flag-hunt-linux', 25);
    }
  } else if (/^(?:Get-ChildItem|gci|dir|tree|where(?:\.exe)?)$/i.test(cleanCmd.split(/\s+/)[0] || '')) {
    const mentionsRootFlag = /\b(?:proof|root)\.txt\b|C:\\Users\\Administrator\\Desktop/i.test(cleanCmd);
    const mentionsUserFlag = /\b(?:local|user)\.txt\b/i.test(cleanCmd);
    const extMatches = cleanCmd.match(/\*\.[A-Za-z0-9]{2,8}\b/g) || [];
    const hasLootExtensions = /\.(?:pdf|xlsx?|docx?|ini|cfg|xml|kdbx|kbdx|bak|ps1|config|ppk|rdg|pfx|key|env|sql|mdb|accdb|pst)\b/i.test(cleanCmd)
      || extMatches.length >= 2;
    const isLootPath = /\b(?:PSReadLine|ConsoleHost_history|AppData|Program\s*Files|inetpub|xampp|wamp|unattend|sysprep|web\.config)\b/i.test(cleanCmd);

    if (hasLootExtensions || isLootPath) {
      excludedIds.add('flag-hunt-root-windows');
      excludedIds.add('flag-hunt-windows');
      bump('windows-loot-hunt', 25);
      bump('stored-credentials', 24);
      bump('windows-enum', 23);
    } else if (mentionsRootFlag && hasAdminOrSystem) {
      bump('flag-hunt-root-windows', 25);
    } else if (mentionsUserFlag || (/\bDesktop\b/i.test(cleanCmd) && !hasAdminOrSystem)) {
      if (!hasAdminOrSystem) excludedIds.add('flag-hunt-root-windows');
      bump('flag-hunt-windows', 24);
      bump('windows-enum', 20);
    } else if (!hasAdminOrSystem && /\bUsers\b|[A-Za-z]:\\/i.test(cleanCmd)) {
      excludedIds.add('flag-hunt-root-windows');
      bump('windows-loot-hunt', 24);
      bump('windows-enum', 23);
      bump('stored-credentials', 22);
      bump('flag-hunt-windows', 20);
    }
  } else if (onTarget && /^(?:type|Get-Content|gc|cat|more|less|head|tail)\b/i.test(cleanCmd) && (/\b(?:ConsoleHost_history|PSReadLine|unattend\.xml|sysprep|web\.config|confCons\.xml)\b/i.test(cleanCmd) || /\.(?:ini|conf|cfg|config)\b/i.test(cleanCmd) || /(?:^|[\s/\\'"`])\.?(?:monitrc|netrc|pgpass|my\.cnf|env|htpasswd|git-credentials)\b/i.test(cleanCmd))) {
    const isWinSpecificArtifact = /\b(?:ConsoleHost_history|PSReadLine|unattend\.xml|sysprep|confCons\.xml)\b/i.test(cleanCmd)
      || /^(?:type|Get-Content|gc)\b/i.test(cleanCmd)
      || /[A-Za-z]:\\/i.test(cleanCmd);
    const hasLinuxOsFamily = Boolean(
      facts && (
        facts.has('foothold.linux') ||
        facts.has('access.root') ||
        (typeof facts.values === 'function' && (facts.values('host.os_family') || []).some(v => String((v && (v.os || v.family || v.value)) || v || '').toLowerCase() === 'linux')) ||
        (Array.isArray(facts.facts) && facts.facts.some(f => f && f.kind === 'host.os_family' && String((f.value && (f.value.os || f.value.family || f.value.value)) || f.value || '').toLowerCase() === 'linux'))
      )
    );
    const isLinuxTarget = !isWinSpecificArtifact && (turn.kind === 'unix' || hasLinuxOsFamily) && !(facts && facts.has('foothold.windows'));
    if (isLinuxTarget) {
      excludedIds.add('flag-hunt-root-linux');
      excludedIds.add('flag-hunt-linux');
      excludedIds.add('flag-hunt-root-windows');
      excludedIds.add('flag-hunt-windows');
      excludedIds.add('stored-credentials');
      excludedIds.add('windows-loot-hunt');
      excludedIds.add('windows-enum');
      bump('linux-loot-hunt', 25);
      bump('linux-enum', 23);
    } else {
      excludedIds.add('flag-hunt-root-windows');
      excludedIds.add('flag-hunt-windows');
      bump('windows-loot-hunt', 25);
      bump('stored-credentials', 24);
      bump('windows-enum', 23);
    }
  }

  // B2.4: Archive & KeePass cracking (zip2john/rar2john/7z2john, keepass2john, hashcat -m <mode>)
  const johnPositionalArgs = (cmdTool === 'john' || /^(?:sudo\s+)?john\b/i.test(cleanCmd))
    ? cleanCmd
        .replace(/^(?:sudo\s+)?\S*john(?:\.exe)?\b/i, ' ')
        .replace(/(?:^|\s)--(?:wordlist|rules|pot|session|config|encoding|fork|max-run-time|min-length|max-length)(?:=\S+|\s+\S+)?/gi, ' ')
        .replace(/(?:^|\s)-[A-Za-z0-9-]+(?:\s|$)/g, ' ')
    : '';
  const HASHCAT_ARCHIVE_MODES = new Set([
    '-m:11600', '-m:12500', '-m:13000', '-m:17200', '-m:17210',
    '-m:17220', '-m:17225', '-m:17230', '-m:23700', '-m:23800'
  ]);
  const isArchiveCrack = /\b(?:zip|rar|7z)2john\b/i.test(cleanCmd)
    || ((cmdTool === 'john' || /^(?:sudo\s+)?john\b/i.test(cleanCmd)) && (
      /--format=(?:zip|pkzip|rar|rar5|7z)\b/i.test(cleanCmd) ||
      /(?:^|\s)[^\s/\\]*(?:^|[._-])(?:rar5?|pkzip|zip|7z)(?:$|[._-]|\.|hash)[^\s/\\]*/i.test(johnPositionalArgs) ||
      /Loaded\s+\d+\s+password\s+hash(?:es)?\s+\([^)\r\n]*\b(?:RAR5?|PKZIP|WinZip|ZIP|7z|7-Zip)\b/i.test(rawTurnOut) ||
      /\$(?:rar[35]|pkzip2?|zip2?|7z)\$/i.test(rawTurnOut)
    ))
    || ((cmdTool === 'hashcat' || /^(?:sudo\s+)?hashcat\b/i.test(cleanCmd)) && (
      cmdFlags.some(f => HASHCAT_ARCHIVE_MODES.has(f)) ||
      /\$(?:rar[35]|pkzip2?|zip2?|7z)\$/i.test(cleanCmd + '\n' + rawTurnOut)
    ));
  if (isArchiveCrack) {
    excludedIds.add('cisco-decrypt');
    excludedIds.add('crack-modular-hash');
    bump('crack-archive', 26);
  }

  const cmdHashcatModes = cmdTool === 'hashcat'
    ? cmdFlags.filter(f => f.indexOf('-m:') === 0)
    : [];
  if (
    ((cmdTool === 'hashcat' || /^(?:sudo\s+)?hashcat\b/i.test(cleanCmd))
      && (/(?:^|\s)(?:-m\s*|--hash-type(?:=|\s+))(?:13100|19600|19700)\b/.test(cleanCmd)
          || cmdHashcatModes.some(m => m === '-m:13100' || m === '-m:19600' || m === '-m:19700')))
    || ((cmdTool === 'john' || /^(?:sudo\s+)?john\b/i.test(cleanCmd)) && /--format=krb5tgs\b/i.test(cleanCmd))
  ) {
    bump('crack-kerberoast', 26);
    bump('crack-tgs', 25);
  }
  if (!isArchiveCrack && (cmdTool === 'john' || /^(?:sudo\s+)?john\b/i.test(cleanCmd)) && !/keepass|\.kdbx\b|krb5|netntlm/i.test(cleanCmd)) {
    bump('crack-modular-hash', 22);
  }
  if (cmdTool === 'keepass2john' || (cmdTool === 'hashcat' && cmdHashcatModes.indexOf('-m:13400') >= 0)) {
    bump('keepass-dump-recover', 24);
  }
  if (cmdHashcatModes.length > 0) {
    for (const a of actionableMoves) {
      const actionModes = [];
      for (const cObj of (a.commands || [])) {
        if (!cObj || !cObj.run) continue;
        const clauses = splitShellClausesQuoteAware(cObj.run);
        for (const clause of clauses) {
          const cleanClause = stripCommandWrappers(clause.replace(/\{\{[^}]+\}\}/g, 'TOKEN'));
          if (extractPrimaryTool(cleanClause) !== 'hashcat') continue;
          for (const fl of extractCommandFlags(cleanClause)) {
            if (fl.indexOf('-m:') === 0 && actionModes.indexOf(fl) < 0) actionModes.push(fl);
          }
        }
      }
      if (actionModes.length > 0 && !actionModes.some(m => cmdHashcatModes.indexOf(m) >= 0)) {
        excludedIds.add(a.id);
      }
    }
  }

  if (cmdTool === 'nmap' || cmdTool === 'rustscan' || cmdTool === 'masscan') {
    if (/\s-sU\b/.test(cleanCmd)) {
      bump('nmap-udp-top', 24);
    } else if (/--script[=\s]+["']?[^"'\s]*vuln/i.test(cleanCmd)) {
      bump('nmap-vuln-scripts', 24);
    } else {
      const hasOpenPorts = !!(facts && (facts.has('ports.open') || facts.has('scan.nmap.quick')));
      const hasNmapVersionOrScriptsFlag = /(?:^|\s)-(?:s[A-Za-z]*[VC][A-Za-z]*|A)\b/.test(cleanCmd);
      if (!hasOpenPorts) {
        bump('nmap-fast-open-ports', 24);
        if (hasNmapVersionOrScriptsFlag) bump('nmap-version-scripts', 18);
      } else if (hasNmapVersionOrScriptsFlag) {
        bump('nmap-version-scripts', 24);
        bump('nmap-fast-open-ports', 14);
      } else {
        bump('nmap-fast-open-ports', 22);
      }
    }
  }

  if (/^(?:gobuster|feroxbuster|ffuf|dirsearch|dirb|wfuzz)$/.test(cmdTool)) {
    if (/\bvhost\b|\bdns\b|-H\s+['"]?Host:\s*[^\r\n'"]*FUZZ/i.test(cleanCmd)) {
      excludedIds.add('content-discovery');
      bump('vhost-discovery', 25);
    } else {
      bump('content-discovery', 24);
    }
  }

  if (/^(?:curl|wget|http|httpie)$/.test(cmdTool)) {
    const sstiProbe = decodeUrlProbeText(cleanCmd);
    if (SSTI_TEMPLATE_EXPR_RE.test(sstiProbe)) {
      if (hasSstiRceTemplatePayload(sstiProbe)) {
        bump('ssti-to-rce', 26);
        bump('ssti', 21);
      } else {
        excludedIds.add('ssti-to-rce');
        bump('ssti', 25);
      }
    } else {
      excludedIds.add('ssti-to-rce');
    }
  }

  if (cmdTool === 'curl' && (/(?:^|\s)(?:-F|--form(?:-string)?)\s+['"]?[^'"\s]*=@/i.test(cleanCmd) || /(?:^|\s)(?:-T|--upload-file)\s+\S+/i.test(cleanCmd))) {
    if (/\bftps?:\/\//i.test(cleanCmd)) {
      bump('ftp-webroot-upload-webshell', 25);
      bump('ftp-upload-webshell', 24);
      bump('file-upload', 22);
    } else {
      bump('file-upload', 25);
    }
  } else if (cmdTool === 'whatweb' || (cmdTool === 'curl' && /\s-(?:I|sSI|sI|-head)\b/.test(cleanCmd))) {
    bump('recon-web-triage', 22);
  }

  // B2.3: Multi-protocol NetExec (nxc/cme) & Authenticated vs Anonymous SMB disambiguation
  if (cmdTool === 'nxc') {
    if (!/-M\s+smbghost\b/i.test(cleanCmd)) {
      excludedIds.add('smbghost');
    }
    if (!/\b(?:local|user|root|proof)\.txt\b/i.test(cleanCmd)) {
      excludedIds.add('flag-hunt-windows');
      excludedIds.add('flag-hunt-root-windows');
      excludedIds.add('flag-hunt-linux');
      excludedIds.add('flag-hunt-root-linux');
    }
    excludedIds.add('windows-enum');
    excludedIds.add('linux-enum');
    excludedIds.add('windows-loot-hunt');
    excludedIds.add('stored-credentials');
  }

  const nxcProtoM = cmdTool === 'nxc'
    ? /^(?:nxc|netexec|crackmapexec|cme)\s+(smb|winrm|rdp|ssh|ldap|mssql|ftp|vnc|wmi)\b/i.exec(cleanCmd)
    : null;
  const nxcProto = nxcProtoM ? nxcProtoM[1].toLowerCase() : '';
  const hasNxcSprayList = cmdTool === 'nxc'
    && (/(?:^|\s)-(?:u|p|H)\s+(?:'[^']*\.(?:txt|lst)'|"[^"]*\.(?:txt|lst)"|\S+\.(?:txt|lst))(?:\s|$)/i.test(cleanCmd)
        || /--continue-on-success\b/i.test(cleanCmd));
  const hasNxcSpecialAction = cmdTool === 'nxc'
    && /\s-[xX]\b|--(?:shares|sam|lsa|ntds|dpapi|mkfile|get-file|put-file|kerberoasting|asreproast|users|groups|pass-pol|rid-brute|loggedon-users|sessions|disks|bloodhound)\b|\s-M\s+\S+/i.test(cleanCmd);

  if (cmdTool === 'nxc' && nxcProto === 'smb' && /-M\s+(?:gpp_password|gpp_autologin)\b/i.test(cleanCmd)) {
    bump('smb-share-inventory', 25);
    bump('gpp-passwords', 24);
  }
  if (!explicitAuth && (
      (cmdTool === 'smbclient' && /\s-L\b/.test(cleanCmd) && (/\s-N\b|anonymous|guest/i.test(cleanCmd) || /-U\s*(?:''|""|%|null)(?=\s|$)/i.test(cleanCmd)))
      || (cmdTool === 'enum4linux')
      || (cmdTool === 'smbmap')
      || (cmdTool === 'nxc' && nxcProto === 'smb' && !hasNxcSprayList))) {
    if (!/-M\s+(?:gpp_password|gpp_autologin|spider_plus)\b/i.test(cleanCmd)) {
      bump('recon-smb-anon', 24);
    } else {
      bump('smb-share-inventory', 24);
      bump('recon-smb-anon', 20);
    }
  } else if (!explicitAuth && cmdTool === 'nxc' && nxcProto === 'rdp') {
    bump('rdp-enum', 24);
  } else if (explicitAuth) {
    if (cmdTool === 'nxc' && nxcProto === 'smb') {
      if (/--shares\b|-M\s+spider_plus\b/i.test(cleanCmd)) {
        bump('smb-share-inventory', 24);
        bump('validate-credential', 22);
      } else if (hasNxcSprayList) {
        bump('password-spray', 25);
        bump('cred-reuse-sweep', 23);
        bump('validate-credential', 21);
      } else if (!/\s-[xX]\b|--sam\b|--lsa\b|--ntds\b|-M\s+(?:lsassy|ntds|dcsync)/i.test(cleanCmd)) {
        if (/\/\d{1,2}\b/.test(cleanCmd)) {
          bump('cred-reuse-sweep', 24);
          bump('pivot-enumerate-neighbors', 23);
          bump('validate-credential', 21);
        } else {
          bump('validate-credential', 24);
          bump('cred-reuse-sweep', 22);
          bump('lateral-exec', 21);
        }
      }
    } else if (cmdTool === 'nxc' && nxcProto && nxcProto !== 'smb') {
      if (nxcProto === 'rdp') {
        if (hasNxcSprayList) {
          bump('online-brute-rdp', 25);
          bump('password-spray', 24);
          bump('cred-reuse-sweep', 23);
          bump('rdp-enum', 22);
          bump('validate-credential', 21);
        } else if (!hasNxcSpecialAction) {
          bump('validate-credential', 25);
          bump('cred-reuse-sweep', 24);
          bump('rdp-enum', 23);
          bump('rdp-interactive', 22);
        }
      } else if (nxcProto === 'winrm') {
        if (hasNxcSprayList) {
          bump('password-spray', 25);
          bump('cred-reuse-sweep', 24);
          bump('validate-credential', 22);
        } else if (/\s-[xX]\b/.test(cleanCmd)) {
          bump('win-interactive-shell', 24);
          bump('lateral-exec', 24);
          bump('validate-credential', 21);
        } else if (!hasNxcSpecialAction) {
          bump('validate-credential', 25);
          bump('win-interactive-shell', 23);
          bump('cred-reuse-sweep', 23);
        }
      } else if (nxcProto === 'mssql') {
        if (hasNxcSprayList) {
          bump('password-spray', 25);
          bump('mssql-login', 23);
          bump('validate-credential', 22);
        } else if (!hasNxcSpecialAction) {
          bump('mssql-login', 25);
          bump('validate-credential', 24);
          bump('cred-reuse-sweep', 22);
        }
      } else if (nxcProto === 'ldap' && /--bloodhound\b/i.test(cleanCmd)) {
        bump('bloodhound-collect', 25);
      } else if (hasNxcSprayList) {
        if (nxcProto === 'ssh') {
          bump('online-brute-ssh', 26);
          bump('blind-brute-ssh', 21);
        }
        if (nxcProto === 'ftp') bump('online-brute-ftp', 26);
        bump('password-spray', 25);
        bump('cred-reuse-sweep', 23);
        bump('validate-credential', 21);
      } else if (!hasNxcSpecialAction) {
        bump('validate-credential', 25);
        bump('cred-reuse-sweep', 24);
        if (nxcProto === 'ssh') bump('ssh-login', 22);
        if (nxcProto === 'wmi') bump('lateral-exec', 22);
      }
    } else if ((cmdTool === 'smbclient' || cmdTool === 'smbmap') && !/\s-N\b/.test(cleanCmd)) {
      bump('smb-share-inventory', 24);
      if (cmdTool === 'smbclient' && !/\s-L\b/.test(cleanCmd)) {
        bump('smb-share-browse-download', 23);
      } else {
        bump('validate-credential', 21);
      }
    }
  }

  // AD, Kerberos, ACL, Web & Target-Enum disambiguations
  if (cmdTool === 'bloodhound' || (onTarget && /\b(?:sharphound(?:\.exe|\.ps1)?|Invoke-BloodHound)\b/i.test(cleanCmd))) {
    bump('bloodhound-collect', 25);
  }
  if (cmdTool === 'secretsdump' && (hasKrbEnv || /(?:^|\s)(?:-k\b|--use-kcache\b|-just-dc(?:-ntlm|-user)?\b)/i.test(cleanCmd) || hasPassAuth || hasHashAuth || explicitAuth)) {
    excludedIds.add('zerologon-exploit');
    excludedIds.add('certifried');
    bump('dcsync', 26);
    bump('dump-secrets', 23);
  }
  if (cmdTool === 'getst' && /(?:^|\s)-impersonate\b/i.test(cleanCmd) && !(/(?:^|\s)-additional-ticket\b|\bkrbrelayx\b/i.test(cleanCmd) || (facts && facts.has('ad.coerced_auth')))) {
    excludedIds.add('kerberos-relay');
    bump('getst-impersonation', 26);
    bump('delegation-abuse', 25);
  }
  if ((cmdTool === 'certipy' && /\bshadow\b/i.test(cleanCmd)) || cmdTool === 'pywhisker') {
    excludedIds.add('certifried');
    excludedIds.add('adcs-esc');
    bump('shadow-credentials', 26);
  }
  if (
    /\b(?:Add-DomainObjectAcl|Add-DomainGroupMember|Add-ADGroupMember|Add-LocalGroupMember|Set-ADObject|Set-DomainObject|Add-ObjectAcl)\b/i.test(cleanCmd) ||
    /^(?:dacledit|owneredit|aclpwn)$/.test(cmdTool) ||
    (cmdTool === 'bloodyad' && /\b(?:add|set)\s+(?:genericAll|dcsync|groupMember|rbcd|uac|shadowCredentials|owner|object|password)\b/i.test(cleanCmd))
  ) {
    excludedIds.add('dcsync');
    bump('bloodyad-acl', 26);
    bump('ad-acl-abuse', 26);
  }
  if (
    /\/graphql(?:\b|\/|\?|$)/i.test(cleanCmd) ||
    (/\b(?:curl|http|httpie|wget|Invoke-RestMethod|irm|Invoke-WebRequest|iwr)\b/i.test(cleanCmd)
      && /(?:__schema|__type|["']query["']\s*:\s*["']\s*(?:query|mutation|\{))/i.test(cleanCmd))
  ) {
    if (!hasRequiredMoveSemantics('xxe', cleanCmd, facts, turn)) {
      excludedIds.add('xxe');
    }
    bump('graphql-abuse', 26);
  }
  if (turn && turn.tool === 'powerview') {
    bump('powerview-enum', 26);
  }
  if (
    /\bjenkins-cli\.jar\b/i.test(cleanCmd) &&
    (/@\/\S+/.test(cleanCmd) || (!/(?:^|\s)(?:-auth|-i|--username)\b/i.test(cleanCmd) && /\b(?:help|who-am-i|connect-node|reload-job|get-job|list-jobs|version)\b/i.test(cleanCmd)))
  ) {
    excludedIds.add('jenkins-access');
    bump('jenkins-cli-fileread', 26);
  }
  if (/^(?:hydra|medusa|ncrack|crowbar|patator)$/.test(cmdTool)) {
    const uriProtoM = /\b(ssh|ftps?|rdp|smb|https?|telnet|mysql|mssql|postgres(?:ql)?|vnc|redis|ldaps?|smtps?|pop3s?|imaps?):\/\//i.exec(cleanCmd);
    const medusaModM = cmdTool === 'medusa' ? /(?:^|\s)-M\s+(ssh|ftp|rdp|smbnt|http|web-form|telnet|mysql|mssql|postgres|vnc)\b/i.exec(cleanCmd) : null;
    const modProtoM = (!uriProtoM && !medusaModM)
      ? /(?:^|\s)(ssh|ftps?|rdp|smb2?|https?-(?:get|post|head)(?:-form)?|telnet|mysql|mssql|postgres|vnc|redis|smtp|pop3|imap)(?=\s|$|:)/i.exec(cleanCmd)
      : null;
    const rawProto = (uriProtoM && uriProtoM[1]) || (medusaModM && medusaModM[1]) || (modProtoM && modProtoM[1]) || '';
    const bruteProto = rawProto.toLowerCase();
    if (bruteProto === 'ssh') {
      excludedIds.add('web-login-brute');
      excludedIds.add('online-brute-ftp');
      excludedIds.add('online-brute-rdp');
      bump('online-brute-ssh', 26);
      bump('blind-brute-ssh', 22);
    } else if (bruteProto === 'ftp' || bruteProto === 'ftps') {
      excludedIds.add('web-login-brute');
      excludedIds.add('online-brute-ssh');
      excludedIds.add('blind-brute-ssh');
      excludedIds.add('online-brute-rdp');
      bump('online-brute-ftp', 26);
    } else if (bruteProto === 'rdp') {
      excludedIds.add('web-login-brute');
      excludedIds.add('online-brute-ssh');
      excludedIds.add('blind-brute-ssh');
      excludedIds.add('online-brute-ftp');
      bump('online-brute-rdp', 26);
    } else if (/^(?:https?|web-form|https?-(?:get|post|head)(?:-form)?)$/.test(bruteProto)) {
      excludedIds.add('online-brute-ssh');
      excludedIds.add('blind-brute-ssh');
      excludedIds.add('online-brute-ftp');
      excludedIds.add('online-brute-rdp');
      bump('web-login-brute', 26);
    } else if (/^smb(?:2|nt)?$/.test(bruteProto)) {
      excludedIds.add('web-login-brute');
      excludedIds.add('online-brute-ssh');
      excludedIds.add('blind-brute-ssh');
      excludedIds.add('online-brute-ftp');
      excludedIds.add('online-brute-rdp');
      bump('password-spray', 25);
      bump('cred-reuse-sweep', 23);
    }
  }

  if (cmdTool === 'ldapsearch') {
    const hasInteractiveOrSaslBind = /\s-(?:W|Y)\b/.test(cleanCmd);
    const dM = /\s-D\s*(?:'([^']*)'|"([^"]*)"|(\S+))/.exec(cleanCmd);
    const wM = /\s-w\s*(?:'([^']*)'|"([^"]*)"|(\S+))/.exec(cleanCmd);
    const dVal = dM ? (dM[1] !== undefined ? dM[1] : (dM[2] !== undefined ? dM[2] : dM[3])).trim() : '';
    const wVal = wM ? (wM[1] !== undefined ? wM[1] : (wM[2] !== undefined ? wM[2] : wM[3])).trim() : '';
    if (!hasInteractiveOrSaslBind && !dVal && !wVal) {
      excludedIds.add('ad-path-manual');
      excludedIds.add('ldap-deep-enum');
      bump('ad-anon-ldap-enum', 25);
    } else if (!/ms-mcs-admpwd|mslaps/i.test(cleanCmd)) {
      excludedIds.add('ad-anon-ldap-enum');
      excludedIds.add('ldap-anon-bind');
      bump('ldap-deep-enum', 25);
    }
  }
  if (turn && turn.tool === 'python' && (/\bldap3\b/i.test(cleanCmd) || /DSA info \(from DSE\):|Naming contexts:/i.test(rawTurnOut))) {
    if (!/\buser\s*=\s*['"][^'"]+['"]/i.test(cleanCmd)) {
      excludedIds.add('ldap-deep-enum');
      excludedIds.add('ad-path-manual');
      bump('ad-anon-ldap-enum', 25);
    } else {
      bump('ldap-deep-enum', 25);
    }
  }
  if (cmdTool === 'rsync') {
    const rsyncArgs = cleanCmd.replace(/^rsync\b/i, '').trim().split(/\s+/).filter(t => t && !t.startsWith('-'));
    const lastArg = rsyncArgs.length > 0 ? rsyncArgs[rsyncArgs.length - 1] : '';
    const destIsRemote = /^rsync:\/\//i.test(lastArg) || /^[A-Za-z0-9_.@-]+::?\S*/.test(lastArg);
    const isShellWritePayload = /(?:authorized_keys|\.ssh\b|\.(?:php[0-9]?|phtml|jsp|jspx|asp|aspx|war|sh)\b)/i.test(cleanCmd);
    if (rsyncArgs.length >= 2 && destIsRemote && isShellWritePayload) {
      bump('rsync-write-shell', 26);
      bump('recon-rsync', 21);
    } else {
      bump('recon-rsync', 25);
      if (destIsRemote && rsyncArgs.length >= 2) bump('rsync-write-shell', 22);
    }
  }
  if (cmdTool === 'davtest' || cmdTool === 'cadaver') {
    bump('http-put-webshell', 25);
    bump('file-upload', 23);
    bump('recon-web-triage', 21);
  }
  if (cmdTool === 'git-dumper') {
    bump('git-exposed', 25);
    bump('git-repo-forensics', 23);
  }
  if (cmdTool === 'snmpwalk' || cmdTool === 'snmpbulkwalk' || cmdTool === 'onesixtyone') {
    if (/hrSWRun|1\.3\.6\.1\.2\.1\.25\.4\.2\.1/i.test(cleanCmd)) {
      bump('snmp-process-cmdline-harvest', 26);
    }
    bump('recon-snmp', 25);
  }
  if (cmdTool === 'sqlmap') {
    bump('sqlmap-automation', 25);
  }

  // PG-2 B4: Direct SSH, PostgreSQL psql, and target-hosted git clone attribution
  if (cmdTool === 'ssh' || (cmdTool === 'sshpass' && /\bssh\b/i.test(cleanCmd))) {
    const isSshTunnel = /(?:^|\s)-[A-Za-z]*[DLR](?:\s|\d|$)/.test(cleanCmd);
    if (!isSshTunnel) {
      excludedIds.add('pivot-ssh-dynamic');
      excludedIds.add('pivot-ssh-portforward');
      excludedIds.add('pivot-reach-listener');
      excludedIds.add('jdwp-local-privesc');
      const hasSshKeyFlag = /(?:^|\s)-i(?:\s+\S+|\S+)/.test(cleanCmd);
      if (hasSshKeyFlag) {
        bump('ssh-key-login', 26);
        bump('ssh-login', 24);
        bump('linux-remote-exec', 24);
        bump('validate-credential', 22);
      } else {
        bump('ssh-login', 25);
        bump('linux-remote-exec', 25);
        bump('validate-credential', 24);
        if (facts && (facts.has('loot.ssh_key') || facts.has('credential.ssh_key') || facts.has('credential.certificate'))) {
          bump('ssh-key-login', 23);
        }
      }
    }
  }

  if (cmdTool === 'psql') {
    if (/\bCOPY\b[\s\S]*?\b(?:FROM|TO)\s+PROGRAM\b/i.test(cleanCmd)) {
      excludedIds.add('postgres-login');
      bump('postgres-rce', 26);
    } else {
      bump('postgres-login', 25);
      bump('validate-credential', 21);
    }
  }

  if (cmdTool === 'redis-cli' || /^redis-cli\b/i.test(cleanCmd)) {
    if (/\b(?:slaveof|replicaof|module\s+load|system\.exec|shell\.exec)\b/i.test(cleanCmd)) {
      bump('redis-rogue-server-rce', 26);
      bump('redis-rce', 26);
      bump('redis-enum', 22);
    } else if (/\b(?:config\s+set\s+(?:dir|dbfilename)|flushall|save)\b/i.test(cleanCmd)) {
      bump('redis-rce', 25);
      bump('redis-enum', 25);
      bump('redis-rogue-server-rce', 23);
    } else {
      bump('redis-enum', 25);
      bump('redis-unauth-check', 24);
    }
  } else if (/\bredis[-_](?:master|rogue|rce)\b/i.test(cleanCmd) || (/\bexp\.so\b|\bmodule\.so\b/i.test(cleanCmd) && /-p\s*6379\b|\b6379\b/.test(cleanCmd))) {
    bump('redis-rogue-server-rce', 26);
    bump('redis-rce', 26);
  }

  if (cmdTool === 'mysql' || cmdTool === 'mariadb' || /^(?:mysql|mariadb)\b/i.test(cleanCmd)) {
    if (/\bINTO\s+(?:OUTFILE|DUMPFILE)\b/i.test(cleanCmd)) {
      bump('mysql-outfile-rce', 26);
      bump('mysql-loot', 22);
    } else if (/\b(?:select\b[\s\S]*?\bfrom\b|show\s+(?:databases|tables)\b|describe\s+\S+|use\s+[A-Za-z0-9_]+)\b/i.test(cleanCmd)) {
      bump('mysql-loot', 25);
      bump('mysql-enum', 24);
      bump('mysql-login', 22);
    } else {
      bump('mysql-login', 25);
      bump('mysql-loot', 23);
      bump('mysql-enum', 23);
      bump('validate-credential', 21);
    }
  }

  if (cmdTool === 'git' && /^git\s+clone\b/i.test(cleanCmd)) {
    const cloneUrlM = /(?:https?|git|ssh):\/\/([^/\s:'"]+)|([A-Za-z0-9_.-]+)@([^:\s/'"]+):/i.exec(cleanCmd);
    const cloneHost = cloneUrlM ? String(cloneUrlM[1] || cloneUrlM[3] || '').toLowerCase() : '';
    const isExternalClone = !cloneHost
      || isExternalReferenceUrlOrCommand('https://' + cloneHost)
      || /(?:^|\.)(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sourceforge\.net)$/i.test(cloneHost);
    if (!isExternalClone) {
      bump('git-exposed', 24);
      bump('git-repo-forensics', 22);
    }
  }

  if (onTarget && /^sudo\s+(?:-V|--version)\b/i.test(cleanCmd)) {
    excludedIds.add('baron-samedit');
    excludedIds.add('sudo-abuse');
    bump('linux-enum', 24);
  } else if (onTarget && /^sudo\s+(?:-l|--list)\b/i.test(cleanCmd)) {
    if (facts && facts.has('privesc.sudo_rights')) {
      bump('sudo-abuse', 23);
      bump('linux-enum', 20);
    } else {
      bump('linux-enum', 23);
      bump('sudo-abuse', 18);
    }
  } else if (!isAttackerTurn(turn, ctx) && /^sudo\s+/i.test(rawCmd) && !/^sudo\s+(?:-l|--list|-V|--version)\b/i.test(rawCmd)) {
    bump('sudo-abuse', 22);
  }

  if (onTarget && /^(?:Get-Process|gps|tasklist(?:\.exe)?)\b/i.test(cleanCmd) && !/\blsass\b/i.test(cleanCmd)) {
    excludedIds.add('lsass-dump-onbox');
    bump('windows-enum', 24);
  }
  if (/^schtasks(?:\.exe)?\b/i.test(cleanCmd) && /\s\/query\b/i.test(cleanCmd) && !/\s\/(?:create|change|run|delete)\b/i.test(cleanCmd)) {
    if (!(facts && facts.has('privesc.scheduled_task'))) {
      excludedIds.add('windows-schtask-abuse');
    }
    bump('windows-enum', 24);
  }

  if (cmdTool === 'find' && /\s-writable\b/.test(cleanCmd) && !/\.(?:timer|service)\b|\/(?:etc|lib|usr\/lib)\/systemd\b/i.test(cleanCmd)) {
    excludedIds.add('systemd-timer-abuse');
    bump('linux-enum', 24);
  }

  if (onTarget && (/\blinpeas\b/i.test(cleanCmd) || /\bfind\s+\/\s+[^\r\n]*-perm\s+[-/]?(?:4000|u=s)/i.test(cleanCmd) || /\bgetcap\s+-r\b/i.test(cleanCmd))) {
    bump('linux-enum', 23);
  }

  if (isUnambiguousWinLocalEnum || (onTarget && /\bwinpeas/i.test(cleanCmd))) {
    bump('windows-enum', 24);
    if (/^whoami(?:\.exe)?\s+\/priv\b/i.test(cleanCmd) && facts && (facts.has('privesc.se_impersonate') || facts.has('privesc.seimpersonate'))) {
      bump('seimpersonate', 21);
    }
    if (/^whoami(?:\.exe)?\s+\/groups\b/i.test(cleanCmd) && !(facts && facts.has('privesc.uac_bypass')) && !/\b(?:fodhelper|eventvwr|computerdefaults|sdclt|ms-settings)\b/i.test(cleanCmd)) {
      excludedIds.add('uac-bypass');
    }
  }

  for (const semMoveId of [
    'laps-read', 'manual-sqli-exploitation', 'authz-abuse', 'xxe',
    'powerview-enum', 'baron-samedit', 'lsass-dump-onbox', 'recon-mail', 'ssti-to-rce'
  ]) {
    if (!hasRequiredMoveSemantics(semMoveId, cleanCmd, facts, turn)) {
      excludedIds.add(semMoveId);
    }
  }

  // Consult OBOL.inference.matchCatalogMove as an engine-native signal (guarded against exclusions and generic interpreters)
  if (OBOL.inference && typeof OBOL.inference.matchCatalogMove === 'function') {
    const nativeHit = OBOL.inference.matchCatalogMove(cleanCmd, null, { target: ctx.target || '' });
    if (nativeHit && nativeHit.id && byId[nativeHit.id] && !excludedIds.has(nativeHit.id) && hasRequiredMoveSemantics(nativeHit.id, cleanCmd, facts, turn)) {
      let allowNative = true;
      if (GENERIC_INTERPRETERS.has(rawHeadBin) || GENERIC_INTERPRETERS.has(cmdTool)) {
        const hitCmds = byId[nativeHit.id].commands || [];
        const specificTools = hitCmds
          .map(c => extractPrimaryTool(stripCommandWrappers(String((c && c.run) || '').replace(/\{\{[^}]+\}\}/g, 'TOKEN'))))
          .filter(t => t && !GENERIC_INTERPRETERS.has(t));
        if (specificTools.length > 0 && specificTools.indexOf(cmdTool) < 0) {
          allowNative = false;
        }
      }
      if (allowNative) {
        bump(nativeHit.id, Math.max(10, (nativeHit.score || 5) + 5));
      }
    }
  }

  // General structural scoring across every sub-clause of every action's commands[]
  const scoreCtx = {
    rawHeadBin: rawHeadBin,
    cmdTool: cmdTool,
    cmdFlags: cmdFlags,
    cmdHashcatModes: cmdHashcatModes,
    hasPassAuth: hasPassAuth,
    hasHashAuth: hasHashAuth,
    facts: facts,
    turn: turn
  };
  for (const a of actionableMoves) {
    if (excludedIds.has(a.id)) continue;
    const cmds = a.commands || [];
    let bestActionScore = scored[a.id] || 0;

    for (let i = 0; i < cmds.length; i++) {
      const s = scoreCommandAgainstVariant(a, cmds[i], cleanCmd, scoreCtx);
      if (s > bestActionScore) bestActionScore = s;
    }

    if (bestActionScore >= 9 && !excludedIds.has(a.id)) {
      scored[a.id] = bestActionScore;
    }
  }

  for (const exId of excludedIds) {
    delete scored[exId];
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
  const moveCtxParams = (move && move.resolvedContext && move.resolvedContext.params) || {};
  const params = Object.assign({}, eng.params || {}, moveCtxParams, { target: targetIp });
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
    workspace: wsTokens,
    resolvedContext: move.resolvedContext,
    context: move.resolvedContext
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

function stripCommentsAndReplEchoes(rawOut) {
  const s = String(rawOut || '');
  if (!s.trim()) return '';
  const nonComment = [];
  const lines = s.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('#')) continue;
    nonComment.push(lines[i]);
  }
  if (!nonComment.length) return '';
  if (nonComment.every(l => PURE_REPL_SUBCOMMAND_LINE_RE.test(l.trim()))) {
    return '';
  }
  return nonComment
    .filter(l => !PURE_REPL_SUBCOMMAND_LINE_RE.test(l.trim()))
    .join('\n');
}

function gateEvidencePresentInHistory(gateOrTokens, historyTurns) {
  if (!historyTurns || !historyTurns.length) return { found: false, reason: '' };
  const filteredHistory = historyTurns.filter(h => !/(?:^|\s|>>?)\/etc\/hosts(?:\s|$|['"])/.test(String((h && h.command) || '')));
  if (!filteredHistory.length) return { found: false, reason: '' };
  const combinedOut = filteredHistory.map(h => stripCommentsAndReplEchoes(h.stdout || '')).join('\n');
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

  const NEGATIVE_OUTCOME_KINDS = new Set([
    'completed-negative',
    'authorization-denied',
    'rejected',
    'environment-error'
  ]);
  const prev = filteredHistory[filteredHistory.length - 1];
  const prevCleanOut = prev ? stripCommentsAndReplEchoes(prev.stdout || '') : '';
  if (
    prev
    && !prev.housekeeping
    && !NEGATIVE_OUTCOME_KINDS.has(String(prev.outcome_kind || ''))
    && prevCleanOut.trim().length >= 24
    && (prev.minted_count || 0) === 0
  ) {
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

function simulateRetireMoveInSandbox(OBOL, session, card, targetIp, targetMoveId, initialCoach) {
  if (isFlagCollectionMove(card)) {
    OBOL.store.setChecklist(card.id, 'done');
    return { method: 'flag_checklist_done', outcomes: ['done'], lastCoach: null };
  }

  const cmds = card.commands || [];
  if (!cmds.length) {
    OBOL.store.setChecklist(card.id, 'done');
    return { method: 'no_cmd_checklist_done', outcomes: ['done'], lastCoach: null };
  }

  const outcomes = [];
  const seenAttemptSigs = new Set();
  const activeCreds = (OBOL.context && typeof OBOL.context.credentials === 'function')
    ? OBOL.context.credentials(session.eng)
    : [];
  const activeCredentialCount = Array.isArray(activeCreds) ? activeCreds.length : 0;
  const maxAttempts = Math.min(256, Math.max(16, (cmds.length || 4) * Math.max(2, activeCredentialCount + 1)));
  let freshCoach = initialCoach || null;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const coachNow = freshCoach || session.computeCoach(targetIp);
    freshCoach = coachNow;
    const stillAtHead = coachNow.onFlow.findIndex(x => x.id === card.id);
    if (stillAtHead < 0) break;
    if (attempt > 0) {
      if (targetMoveId) {
        const targetIdxNow = coachNow.onFlow.findIndex(x => x.id === targetMoveId);
        if (targetIdxNow >= 0 && stillAtHead > targetIdxNow) break;
      } else if (stillAtHead > 0) {
        break;
      }
    }

    const liveCard = coachNow.onFlow[stillAtHead] || card;
    const liveCmds = liveCard.commands || cmds;
    const cardCtx = liveCard.resolvedContext || card.resolvedContext || undefined;
    const cardCtxParams = (cardCtx && cardCtx.params) || {};
    const factsNow = coachNow.facts || session.factSetForTarget(targetIp);
    const params = Object.assign({}, session.eng.params || {}, cardCtxParams, { target: targetIp });
    const wsTokens = (OBOL.workspace && OBOL.workspace.tokens) ? OBOL.workspace.tokens(session.eng) : {};
    const bestIdx = (OBOL.command && typeof OBOL.command.bestCommandIndex === 'function')
      ? OBOL.command.bestCommandIndex(liveCard, factsNow, {
          params: params,
          profile: session.eng.profile,
          workspace: wsTokens,
          activities: session.eng.activities
        })
      : 0;
    const cmdObj = liveCmds[bestIdx] || liveCmds[0];
    const cmdFacts = (factsNow && typeof factsNow.forAction === 'function')
      ? factsNow.forAction(liveCard, cmdObj)
      : factsNow;
    const cmdCtx = (cmdFacts && cmdFacts._resolvedContext) || cardCtx;
    const filled = (OBOL.command && typeof OBOL.command.fillCommand === 'function')
      ? OBOL.command.fillCommand(liveCard, cmdFacts || factsNow, {
          params: (cmdCtx && cmdCtx.params) || params,
          profile: session.eng.profile,
          workspace: wsTokens
        }, bestIdx)
      : { filled: (cmdObj && cmdObj.run) || liveCard.id };
    const filledCmd = (filled && filled.filled) || (cmdObj && cmdObj.run) || liveCard.id;
    const attemptSig = filledCmd + '::' + ((cmdCtx && cmdCtx.credentialId) || '');
    if (seenAttemptSigs.has(attemptSig)) break;
    seenAttemptSigs.add(attemptSig);

    const turnRes = session.ingestTurn({
      command: filledCmd,
      stdout: DRY_PROBE_SENTINEL,
      actionId: liveCard.id,
      target: targetIp,
      forceTarget: targetIp,
      commandObj: cmdObj,
      resolvedContext: cmdCtx
    });
    freshCoach = null;
    outcomes.push((turnRes && turnRes.outcome && turnRes.outcome.kind) || 'unknown');
  }

  return { method: 'completed_negative_dry_probe', outcomes: outcomes, lastCoach: freshCoach };
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
      let simCoach = coach;
      for (let step = 0; step < maxSteps; step++) {
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

        const retRes = simulateRetireMoveInSandbox(OBOL, session, head, targetIp, targetMoveId, simCoach);
        const afterCoach = (retRes && retRes.lastCoach) || session.computeCoach(targetIp);
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
        simCoach = afterCoach;
      }

      if (!stallBucket) {
        if (simCoach.onFlow && simCoach.onFlow[0] && simCoach.onFlow[0].id === targetMoveId) {
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

    const targetHistoryForFlow = historyTurns.filter(h => !h.target_ip || h.target_ip === targetIp);
    for (const cand of candidates) {
      const cmdInfo = inspectMoveCommandReadiness(OBOL, session, cand.move, facts, targetIp);
      const seenReachableInHistory = targetHistoryForFlow.some(h =>
        h.was_reachable &&
        ((Array.isArray(h.matched_moves) && h.matched_moves.indexOf(cand.id) >= 0) || h.executed_move_id === cand.id)
      );
      const producesList = Array.isArray(cand.move.produces) ? cand.move.produces : [];
      const allProducesSatisfied = producesList.length > 0 && producesList.every(p => facts.has(p));
      const adGraphAlreadyCollected = producesList.indexOf('ad.graph.collected') >= 0 && facts.has('ad.graph.collected');
      const isCandEligible = typeof cand.move.eligible === 'function' ? cand.move.eligible(facts) : true;
      const isCandObsolete = Boolean(cand.move && typeof cand.move.obsolete === 'function' && cand.move.obsolete(facts));
      const alreadySatisfiedOnTarget = isCandEligible && Boolean(
        doneIds[cand.id] || allProducesSatisfied || cmdInfo.allSettled || adGraphAlreadyCollected || isCandObsolete
      );
      const priorSubcmdContinuation =
        seenReachableInHistory &&
        isCandEligible &&
        !comingUp.some(m => m.id === cand.id);
      if (priorSubcmdContinuation || alreadySatisfiedOnTarget) {
        return {
          reachable: true,
          mode: 'already_settled_repeat',
          matched_move_id: cand.id,
          initial_rank: initialRank,
          retired_preceding: retiredPreceding,
          stall_bucket: null,
          detail: 'Operator continued a sub-command of an already reached move in Ready Now'
        };
      }
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

  const targetHistory = historyTurns.filter(h => !h.target_ip || h.target_ip === targetIp);

  // 3. No candidate is in Ready Now: check if already executed & settled earlier in this replay
  //    or if the operator is running a subsequent sub-command of a multi-command move already reached on this host
  for (const cand of candidates) {
    const cmdInfo = inspectMoveCommandReadiness(OBOL, session, cand.move, facts, targetIp);
    const seenReachableInHistory = targetHistory.some(h =>
      h.was_reachable &&
      ((Array.isArray(h.matched_moves) && h.matched_moves.indexOf(cand.id) >= 0) || h.executed_move_id === cand.id)
    );
    const seenAnyInHistory = targetHistory.some(h =>
      (Array.isArray(h.matched_moves) && h.matched_moves.indexOf(cand.id) >= 0) || h.executed_move_id === cand.id
    );
    const producesList = Array.isArray(cand.move.produces) ? cand.move.produces : [];
    const allProducesSatisfied =
      producesList.length > 0 &&
      producesList.every(p => facts.has(p));
    const adGraphAlreadyCollected =
      producesList.indexOf('ad.graph.collected') >= 0 &&
      facts.has('ad.graph.collected');
    const settledByEngine = Boolean(cand.move && typeof cand.move.settled === 'function' && cand.move.settled(facts));
    const actionSettled =
      allProducesSatisfied ||
      adGraphAlreadyCollected ||
      settledByEngine ||
      (typeof cand.move.obsolete === 'function' && cand.move.obsolete(facts));
    const isCandEligible = typeof cand.move.eligible === 'function' ? cand.move.eligible(facts) : true;
    const isCandObsolete = Boolean(cand.move && typeof cand.move.obsolete === 'function' && cand.move.obsolete(facts));
    const alreadySatisfiedOnTarget = isCandEligible && Boolean(
      doneIds[cand.id] || allProducesSatisfied || cmdInfo.allSettled || adGraphAlreadyCollected || isCandObsolete
    );
    const priorSubcmdContinuation =
      seenReachableInHistory &&
      isCandEligible &&
      !comingUp.some(m => m.id === cand.id);

    if (alreadySatisfiedOnTarget || ((executedMoveIds.has(cand.id) || seenAnyInHistory) && (doneIds[cand.id] || cmdInfo.allSettled || actionSettled)) || priorSubcmdContinuation) {
      return {
        reachable: true,
        mode: 'already_settled_repeat',
        matched_move_id: cand.id,
        initial_rank: null,
        retired_preceding: [],
        settled_by_engine: settledByEngine,
        stall_bucket: null,
        detail: 'Operator repeated or continued a sub-command of an already settled or reached move'
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

    const histProbe = gateEvidencePresentInHistory(missingGates, targetHistory);
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
    const histProbe = gateEvidencePresentInHistory(cmdReadiness.unfilledEarnedTokens, targetHistory);
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
  const settledByEngine = Boolean(move && typeof move.settled === 'function' && move.settled(facts));

  return {
    reachable: false,
    mode: settledByEngine ? 'settled_predicate_drift' : (inComingUp ? 'stuck_in_coming_up' : 'excluded_from_ready_now'),
    matched_move_id: primary.id,
    initial_rank: null,
    prematurity: prematurity,
    settled_by_engine: settledByEngine,
    stall_bucket: 'CLOSED_LOOP_RANK_STALL',
    detail: settledByEngine
      ? ('SETTLED_PREDICATE_DRIFT: move.settled(facts) returned true while produces remained incomplete (lens=' + (coach.lens || 'default') + ')')
      : (inComingUp
          ? ('Move eligible with runnable tokens, but held in Coming Up (prematurity=' + prematurity + ')')
          : ('Move eligible with runnable tokens, but excluded from Ready Now (lens=' + (coach.lens || 'default') + ')'))
  };
}

function evaluateCheckpoint(session, cp, ipAliasMap) {
  const OBOL = session.OBOL;
  const aliasedCpTarget = cp.target_ip ? applyIpAliases(cp.target_ip, ipAliasMap) : '';
  const targetIp = aliasedCpTarget || session.getActiveTarget();
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

const OUTBOUND_REMOTE_CMD_RE = /\b(?:ssh|scp|sftp|evil-winrm|impacket-[\w-]+|(?:psexec|wmiexec|smbexec|atexec|dcomexec|mssqlclient|secretsdump|GetUserSPNs|GetNPUsers)(?:\.py)?|nxc|netexec|crackmapexec|cme|nmap|rustscan|masscan|Enter-PSSession|Invoke-Command|New-PSSession|PsExec(?:64)?\.exe|mstsc|xfreerdp3?|rdesktop)\b/i;

function stripAttackerCallbackArgsForTargetRouting(cmd) {
  return String(cmd || '')
    .replace(/\bLHOST\s*=\s*\S+/gi, ' ')
    .replace(/--lhost(?:=|\s+)\S+/gi, ' ')
    .replace(/(?:^|\s)-l\s+\d{1,3}(?:\.\d{1,3}){3}\b/g, ' ')
    .replace(/--socks\d*(?:=|\s+)\S+/gi, ' ')
    .replace(/(?:^|\s)-[A-Za-z]*[LR]\s*(?:(?:\d{1,3}\.){3}\d{1,3}:)?\d{2,5}:(?:\d{1,3}(?:\.\d{1,3}){3}|localhost):\d{2,5}\b/g, ' ')
    .replace(/\bR:(?:(?:\d{1,3}\.){3}\d{1,3}:)?\d{2,5}:(?:\d{1,3}(?:\.\d{1,3}){3}|localhost):\d{2,5}\b/gi, ' ');
}

function extractLoopbackForwardPort(cmd) {
  const s = String(cmd || '');
  if (!/\b(?:127\.0\.0\.1|localhost)\b/i.test(s)) return '';
  // Do not treat tunnel-establishment flags themselves (-L/-R/R:/chisel server) as tunnel consumers
  if (/\bchisel(?:\.exe)?\s+(?:server|client)\b/i.test(s)) return '';
  if (/(?:^|\s)-[A-Za-z]*[LR]\s*(?:(?:\d{1,3}\.){3}\d{1,3}:)?\d{2,5}:(?:\d{1,3}(?:\.\d{1,3}){3}|localhost):\d{2,5}\b/.test(s)) {
    return '';
  }
  const hostPortM = /\b(?:127\.0\.0\.1|localhost):(\d{2,5})\b/i.exec(s);
  if (hostPortM) return hostPortM[1];
  const flagPortM = /(?:^|\s)(?:-p|-P|--port)(?:=|\s+)(\d{2,5})\b/.exec(s);
  if (flagPortM) return flagPortM[1];
  const ncPortM = /\b(?:nc|ncat|netcat|telnet)\b[^\r\n]*?\b(?:127\.0\.0\.1|localhost)\s+(\d{2,5})\b/i.exec(s);
  if (ncPortM) return ncPortM[1];
  return '';
}

function recordPortForwardBindings(cmd, stdout, hostTarget, fallbackTunnelTarget, net, portForwardTargets) {
  const s = String(cmd || '');
  const out = String(stdout || '');
  function isNonSelfLabIp(ip) {
    return Boolean(ip && isPrivateLabIpv4(ip) && net.selfIps.indexOf(ip) < 0 && !ATTACKER_SUBNET_RE.test(ip));
  }
  function bindPort(lport, rhost) {
    if (!lport) return;
    const endpoint = isNonSelfLabIp(rhost) ? rhost : (hostTarget || fallbackTunnelTarget || '');
    if (endpoint) portForwardTargets[String(lport)] = endpoint;
  }

  let m;
  const chiselRevRe = /\bR:(?:(?:\d{1,3}\.){3}\d{1,3}:)?(\d{2,5}):(\d{1,3}(?:\.\d{1,3}){3}|localhost):(\d{2,5})\b/gi;
  while ((m = chiselRevRe.exec(s)) !== null) {
    bindPort(m[1], m[2]);
  }
  if (/\bchisel(?:\.exe)?\s+client\b/i.test(s)) {
    const chiselFwdRe = /(?:^|\s)(?:(?:\d{1,3}\.){3}\d{1,3}:)?(\d{2,5}):(\d{1,3}(?:\.\d{1,3}){3}|localhost):(\d{2,5})(?=\s|$)/g;
    while ((m = chiselFwdRe.exec(s)) !== null) {
      bindPort(m[1], m[2]);
    }
  }
  const sshTunnelRe = /(?:^|\s)-[A-Za-z]*[LR]\s*(?:(?:\d{1,3}\.){3}\d{1,3}:)?(\d{2,5}):(\d{1,3}(?:\.\d{1,3}){3}|localhost):(\d{2,5})\b/g;
  while ((m = sshTunnelRe.exec(s)) !== null) {
    bindPort(m[1], m[2]);
  }
  if (/\bportfwd\s+add\b/i.test(s)) {
    const lpM = /(?:^|\s)-l\s+(\d{2,5})\b/i.exec(s);
    const rhM = /(?:^|\s)-r\s+(\d{1,3}(?:\.\d{1,3}){3}|localhost)\b/i.exec(s);
    if (lpM) bindPort(lpM[1], rhM ? rhM[1] : '');
  }
  const chiselOutRe = /proxy#R:(?:(?:\d{1,3}\.){3}\d{1,3}:)?(\d{2,5})=>/gi;
  while ((m = chiselOutRe.exec(out)) !== null) {
    const lp = String(m[1]);
    if (!portForwardTargets[lp] && (fallbackTunnelTarget || hostTarget)) {
      portForwardTargets[lp] = fallbackTunnelTarget || hostTarget;
    }
  }
}

const SCENARIO_STOPWORDS = new Set([
  'the', 'for', 'with', 'and', 'from', 'into', 'this', 'that', 'your', 'you', 'will',
  'start', 'box', 'machine', 'lab', 'target', 'host', 'account', 'accounts', 'user',
  'username', 'password', 'credentials', 'credential', 'creds', 'following', 'given',
  'provided', 'windows', 'linux', 'active', 'directory', 'pentest', 'pentests',
  'common', 'real', 'life', 'http', 'https', 'ldap', 'ldaps', 'smb'
]);

function extractScenarioBriefCredentials(markdownText) {
  const full = String(markdownText || '');
  if (!full || full.indexOf('htb-scenario-') < 0) return [];
  let cutIdx = Math.min(full.length, 16384);
  const fenceIdx = full.indexOf('\n```');
  if (fenceIdx > 0 && fenceIdx < cutIdx) cutIdx = fenceIdx;
  const divHlIdx = full.indexOf('<div class="highlight"');
  if (divHlIdx > 0 && divHlIdx < cutIdx) cutIdx = divHlIdx;
  const head = full.slice(0, cutIdx);

  const out = [];
  const seen = new Set();
  function addCred(rawUser, rawPass) {
    let u = String(rawUser || '').trim();
    const p = String(rawPass || '').trim();
    if (!u || !p || u.length > 64 || p.length > 96) return;
    let domain = '';
    if (u.indexOf('\\') > 0) {
      const parts = u.split('\\');
      domain = parts[0].trim();
      u = parts.slice(1).join('\\').trim();
    }
    if (!u || !/^[A-Za-z0-9_.$@-]{2,64}$/.test(u)) return;
    if (SCENARIO_STOPWORDS.has(u.toLowerCase())) return;
    if (SCENARIO_STOPWORDS.has(p.toLowerCase()) && !/[^A-Za-z]/.test(p)) return;
    const key = domain.toLowerCase() + '\\' + u.toLowerCase() + ':' + p;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ user: u, password: p, domain: domain });
  }

  function decodeEntities(s) {
    return String(s || '')
      .replace(/&quot;/g, '"')
      .replace(/&#39;|&apos;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&');
  }

  const boxRe = /<(?:div|span)\b[^>]*class=["'][^"']*htb-scenario-(?:box|text)[^"']*["'][^>]*>([\s\S]{1,4096}?)<\/(?:div|span)>/gi;
  let bm;
  while ((bm = boxRe.exec(head)) !== null) {
    const htmlChunk = bm[1];
    const codeTokens = [];
    const codeRe = /<code>([^<]{1,160})<\/code>|`([^`\r\n]{1,160})`/gi;
    let cm;
    while ((cm = codeRe.exec(htmlChunk)) !== null) {
      const val = decodeEntities(cm[1] !== undefined ? cm[1] : cm[2]).trim();
      if (val) {
        codeTokens.push({
          val: val,
          start: cm.index,
          end: cm.index + cm[0].length
        });
      }
    }

    let matchedFromCode = false;
    for (let i = 0; i < codeTokens.length; i++) {
      const tok = codeTokens[i].val;
      const colonIdx = tok.indexOf(':');
      if (colonIdx > 0 && colonIdx < tok.length - 1 && !/^(?:https?|ldaps?|smb|ftp|ssh)$/i.test(tok.slice(0, colonIdx))) {
        const lhs = tok.slice(0, colonIdx).trim();
        const rhs = tok.slice(colonIdx + 1).trim();
        if (lhs && rhs && !/\s/.test(lhs) && !/\s/.test(rhs)) {
          addCred(lhs, rhs);
          matchedFromCode = true;
          continue;
        }
      }
      const slashParts = tok.split(/\s+\/\s+/);
      if (slashParts.length === 2 && !/\s/.test(slashParts[0]) && !/\s/.test(slashParts[1])) {
        addCred(slashParts[0], slashParts[1]);
        matchedFromCode = true;
        continue;
      }
      if (i + 1 < codeTokens.length) {
        const between = decodeEntities(htmlChunk.slice(codeTokens[i].end, codeTokens[i + 1].start).replace(/<[^>]+>/g, ' '));
        if (between.length <= 48 && /^(?:\s*(?:\/|:|,|;|and|-)\s*|\s*(?:and\s+)?(?:with\s+)?password\s*[:=]?\s*)$/i.test(between)) {
          addCred(tok, codeTokens[i + 1].val);
          matchedFromCode = true;
          i++;
        }
      }
    }
    if (matchedFromCode) continue;

    const plain = decodeEntities(htmlChunk.replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
    const pairRe = /\b(?:account|credentials?|creds?|login|user(?:name)?)\b[^:\r\n]{0,48}?[:\s]+['"]?([A-Za-z0-9_.\\@-]{2,64})['"]?\s*(?:\/|\s+(?:and\s+|with\s+)?password\s*[:=]?\s*|\s*[,;]\s*password\s*[:=]?\s*)['"]?([^\s'"]{2,96})['"]?/gi;
    let pm;
    while ((pm = pairRe.exec(plain)) !== null) {
      let pwd = pm[2];
      if (pwd.endsWith('.') && (pm.index + pm[0].length >= plain.length || /\s/.test(plain[pm.index + pm[0].length] || ''))) {
        pwd = pwd.slice(0, -1);
      }
      addCred(pm[1], pwd);
    }
  }

  return out;
}

function replayWalkthrough(OBOL, walkthroughInput, opts) {
  opts = opts || {};
  const slug = walkthroughInput.slug
    || (walkthroughInput.mdPath ? path.basename(walkthroughInput.mdPath, '.md') : 'synthetic');

  let extracted;
  let rawMarkdown = typeof walkthroughInput.markdown === 'string' ? walkthroughInput.markdown : '';
  if (Array.isArray(walkthroughInput.turns)) {
    extracted = { turns: walkthroughInput.turns.slice(), ocrCount: 0 };
  } else if (typeof walkthroughInput.markdown === 'string') {
    extracted = extractWalkthroughTurns(walkthroughInput.markdown, {
      slug: slug,
      ocrEntries: walkthroughInput.ocrEntries || []
    });
  } else if (walkthroughInput.mdPath) {
    rawMarkdown = fs.readFileSync(walkthroughInput.mdPath, 'utf8');
    extracted = extractWalkthroughTurns(rawMarkdown, {
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
  const hasIpAliases = Boolean(net.ipAliasMap && Object.keys(net.ipAliasMap).length > 0);
  const multiTarget = !!opts.multiTarget || (net.targets.length > 1 && !!opts.autoMultiTarget);

  const session = createEngagementSession(OBOL, {
    name: 'Replay:' + slug,
    target: net.primaryTarget,
    targets: multiTarget ? net.targets : [net.primaryTarget],
    lhost: net.lhost,
    multiTarget: multiTarget,
    lens: opts.lens
  });

  if (rawMarkdown && OBOL.facts && typeof OBOL.facts.makeFact === 'function' && OBOL.store && typeof OBOL.store.addFacts === 'function') {
    const scenarioCreds = extractScenarioBriefCredentials(rawMarkdown);
    if (scenarioCreds.length > 0 && net.primaryTarget) {
      const seedFacts = [];
      const hostScope = 'host:' + net.primaryTarget;
      for (const sc of scenarioCreds) {
        const val = {
          user: sc.user,
          password: sc.password,
          secret: sc.password,
          domain: sc.domain || '',
          secretType: 'password',
          method: 'scenario_brief'
        };
        seedFacts.push(OBOL.facts.makeFact({
          kind: 'credential.plaintext',
          scope: hostScope,
          value: val,
          source: 'scenario_brief'
        }));
        seedFacts.push(OBOL.facts.makeFact({
          kind: 'credential.available',
          scope: hostScope,
          value: val,
          source: 'scenario_brief'
        }));
      }
      OBOL.store.addFacts(seedFacts, 'scenario_brief', net.primaryTarget);
    }
  }

  // Optional SharpHound / BloodHound JSON bundle ingestion (either pre-supplied or discovered on disk)
  let bloodhoundResult = null;
  const bhSlug = walkthroughInput.labSlug || slug;
  const bhPayload = walkthroughInput.bloodhound
    || (opts.bloodhoundDir && fs.existsSync(path.join(opts.bloodhoundDir, bhSlug))
        ? path.join(opts.bloodhoundDir, bhSlug)
        : (walkthroughInput.corpusRoot && fs.existsSync(path.join(walkthroughInput.corpusRoot, 'bloodhound', bhSlug))
            ? path.join(walkthroughInput.corpusRoot, 'bloodhound', bhSlug)
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
  let inTargetShell = false;
  let launchedLocalContainer = false;
  let inLocalContainerShell = false;
  let inTargetRootCwd = false;
  let ligoloAgentHost = '';
  let activeTunnelTarget = '';
  const portForwardTargets = Object.create(null);

  for (let idx = 0; idx < turns.length; idx++) {
    const rawTurn = turns[idx];
    const aliasedTurn = hasIpAliases
      ? Object.assign({}, rawTurn, {
          command: applyIpAliases(rawTurn.command || '', net.ipAliasMap),
          rawCommand: rawTurn.rawCommand ? applyIpAliases(rawTurn.rawCommand, net.ipAliasMap) : rawTurn.rawCommand,
          stdout: applyIpAliases(rawTurn.stdout || '', net.ipAliasMap),
          output: rawTurn.output ? applyIpAliases(rawTurn.output, net.ipAliasMap) : rawTurn.output,
          promptLine: rawTurn.promptLine ? applyIpAliases(rawTurn.promptLine, net.ipAliasMap) : rawTurn.promptLine,
          followPrompt: rawTurn.followPrompt ? applyIpAliases(rawTurn.followPrompt, net.ipAliasMap) : rawTurn.followPrompt
        })
      : rawTurn;
    const activeBefore = session.getActiveTarget();
    const expandedCmd = applyIpAliases(
      expandShellTargetVars(aliasedTurn.command || '', activeBefore, net.varMap),
      net.ipAliasMap
    );
    const turn = Object.assign({}, aliasedTurn, { command: expandedCmd });
    const prePl = getPreCommandPromptLine(turn);
    const hasExplicitAttackerPrompt = Boolean(
      (turn.host && ATTACKER_HOST.test(turn.host)) ||
      /^\s*[┌╭]──\(/.test(prePl) ||
      /\[(?:tun|tap|vpn|wg)\d*:/i.test(prePl)
    );
    if (hasExplicitAttackerPrompt) {
      inTargetShell = false;
      inLocalContainerShell = false;
      inTargetRootCwd = false;
    } else if (launchedLocalContainer && turn.host && /^[0-9a-f]{12}$/i.test(turn.host)) {
      inLocalContainerShell = true;
      inTargetShell = false;
    } else if (
      !inLocalContainerShell && (
        (turn.host && !ATTACKER_HOST.test(turn.host)) ||
        (/^(?:powershell|cmd)$/.test(turn.kind || '') && !isDosBoxPromptOrTurn(turn, prePl)) ||
        /^\s*(?:(?:ba|da|z|k|a)?sh-[0-9.]+|[A-Za-z0-9_.-]{2,32}-[3-6]\.\d+)\s*[#$]/i.test(prePl) ||
        (!/^\s*\/\//.test(prePl) && /^\s*\/(?:[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*)?\/?\s+[#$](?:\s|$)/.test(prePl)) ||
        (turn.user && /^(?:www-data|apache|nginx|daemon|nobody|postgres|mysql|mssql|tomcat|jenkins|svc[_-])/i.test(turn.user))
      )
    ) {
      inTargetShell = true;
    }
    if (inTargetShell && /:\s*\/root(?:\s|\/)*[#$]/.test(prePl)) {
      inTargetRootCwd = true;
    }

    const locusHints = {
      inTargetShell: inTargetShell,
      inLocalContainerShell: inLocalContainerShell,
      launchedLocalContainer: launchedLocalContainer,
      inTargetRootCwd: inTargetRootCwd
    };

    // Determine target IP for this turn in multi-target mode BEFORE grading reachability.
    // Never scan general stdout for target routing (prevents ipconfig/arp/hosts/download-peer hijack).
    let turnTarget = activeBefore;
    if (multiTarget) {
      const isLocalIpRouteCmd = isAttackerTurn(turn, locusHints) && /^(?:sudo\s+)?ip\s+(?:route|tuntap|link|addr)\b/i.test(expandedCmd.trim());
      if (!isLocalIpRouteCmd && /\b240\.0\.0\.1\b/.test(expandedCmd)) {
        turnTarget = ligoloAgentHost || activeTunnelTarget || activeBefore;
        if (turnTarget && turnTarget !== activeBefore) {
          session.setActiveTarget(turnTarget);
        }
      } else if (!isAttackerTurn(turn, locusHints) && !OUTBOUND_REMOTE_CMD_RE.test(expandedCmd)) {
        turnTarget = activeBefore;
      } else if (!isLocalIpRouteCmd) {
        const cmdForIp = stripAttackerCallbackArgsForTargetRouting(expandedCmd);
        let m;
        IPV4_GLOBAL_RE.lastIndex = 0;
        const foundIps = [];
        while ((m = IPV4_GLOBAL_RE.exec(cmdForIp)) !== null) {
          const ip = m[1];
          if (isPrivateLabIpv4(ip) && net.selfIps.indexOf(ip) < 0 && !ATTACKER_SUBNET_RE.test(ip)) {
            foundIps.push(ip);
          }
        }
        if (!foundIps.length && !turn.rawCommand && /^\s*(?:sudo\s+)?nmap\b/i.test(expandedCmd)) {
          const nmapHeaderM = /^Nmap scan report for (?:[^\r\n(]+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?/im.exec(turn.stdout || '');
          if (nmapHeaderM && isPrivateLabIpv4(nmapHeaderM[1]) && net.selfIps.indexOf(nmapHeaderM[1]) < 0 && !ATTACKER_SUBNET_RE.test(nmapHeaderM[1])) {
            foundIps.push(nmapHeaderM[1]);
          }
        }
        if (foundIps.length > 0) {
          turnTarget = foundIps[0];
          session.setActiveTarget(turnTarget);
          if (turnTarget !== net.primaryTarget) {
            activeTunnelTarget = turnTarget;
          }
        } else if (isAttackerTurn(turn, locusHints)) {
          const fwdPort = extractLoopbackForwardPort(expandedCmd);
          if (fwdPort && portForwardTargets[fwdPort]) {
            turnTarget = portForwardTargets[fwdPort];
            if (turnTarget !== activeBefore) {
              session.setActiveTarget(turnTarget);
            }
          }
        }
      }

      if (/\b(?:ligolo-)?agent(?:\.exe)?\b[\s\S]*?-connect\b/i.test(expandedCmd) || /\bchisel(?:\.exe)?\s+client\b/i.test(expandedCmd)) {
        if (turnTarget) {
          ligoloAgentHost = turnTarget;
          activeTunnelTarget = turnTarget;
        }
      }

      recordPortForwardBindings(
        expandedCmd,
        turn.stdout || '',
        turnTarget,
        activeTunnelTarget,
        net,
        portForwardTargets
      );
    }

    // Trigger BloodHound JSON bundle right when a bloodhound/sharphound collection command appears
    if (!bhIngested && bhPayload && /\b(?:bloodhound|sharphound)\b/i.test(expandedCmd)) {
      bloodhoundResult = session.ingestBloodHound(bhPayload);
      bhIngested = true;
    }

    // Evaluate any trajectory checkpoints pinned BEFORE step idx
    if (checkpointsByStep[idx]) {
      for (const cp of checkpointsByStep[idx]) {
        checkpointResults.push(evaluateCheckpoint(session, cp, net.ipAliasMap));
      }
    }

    // Seed pre-command target shell prompt telemetry (e.g. uncaptured privesc landing root@target:~#)
    // after checkpoints for step idx and before grading step idx reachability.
    const preSeedFacts = session.factSetForTarget(turnTarget);
    const prePromptSeed = inspectPreCommandTargetPrompt(turn, prePl, preSeedFacts, locusHints);
    if (prePromptSeed) {
      session.ingestTurn({
        command: '',
        stdout: '',
        promptLine: prePromptSeed.promptPrefix,
        followPrompt: prePromptSeed.promptPrefix,
        target: turnTarget,
        forceTarget: turnTarget,
        direct: true
      });
      if (OBOL.facts && typeof OBOL.facts.makeFact === 'function' && OBOL.store && typeof OBOL.store.addFacts === 'function' && turnTarget) {
        const afterPromptFacts = session.factSetForTarget(turnTarget);
        const fallbackSeedFacts = [];
        const tScope = 'host:' + turnTarget;
        if (prePromptSeed.os === 'linux') {
          if (!afterPromptFacts.has('foothold.linux')) {
            fallbackSeedFacts.push(OBOL.facts.makeFact({ kind: 'foothold.linux', scope: tScope, value: { method: 'prompt_telemetry' }, source: 'prompt_telemetry' }));
          }
          if (prePromptSeed.privileged && !afterPromptFacts.has('access.root')) {
            fallbackSeedFacts.push(OBOL.facts.makeFact({ kind: 'access.root', scope: tScope, value: { user: 'root', method: 'prompt_telemetry' }, source: 'prompt_telemetry' }));
            fallbackSeedFacts.push(OBOL.facts.makeFact({ kind: 'access.admin', scope: tScope, value: { user: 'root', method: 'prompt_telemetry' }, source: 'prompt_telemetry' }));
          }
        } else if (prePromptSeed.os === 'windows') {
          if (!afterPromptFacts.has('foothold.windows')) {
            fallbackSeedFacts.push(OBOL.facts.makeFact({ kind: 'foothold.windows', scope: tScope, value: { method: 'prompt_telemetry' }, source: 'prompt_telemetry' }));
          }
          if (prePromptSeed.privileged && !afterPromptFacts.has('access.admin') && !afterPromptFacts.has('access.system')) {
            fallbackSeedFacts.push(OBOL.facts.makeFact({ kind: 'access.admin', scope: tScope, value: { user: 'Administrator', method: 'prompt_telemetry' }, source: 'prompt_telemetry' }));
          }
        }
        if (fallbackSeedFacts.length > 0) {
          OBOL.store.addFacts(fallbackSeedFacts, 'prompt_telemetry', turnTarget);
        }
      }
      inTargetShell = true;
    }

    const preFacts = session.factSetForTarget(turnTarget);
    const turnCtx = {
      inTargetShell: inTargetShell,
      inLocalContainerShell: inLocalContainerShell,
      launchedLocalContainer: launchedLocalContainer,
      inTargetRootCwd: inTargetRootCwd,
      facts: preFacts,
      target: turnTarget
    };

    const isLocalContainerLaunch = isAttackerTurn(turn, turnCtx)
      && /^(?:sudo\s+)?(?:docker|podman)\s+(?:run|exec)\b/i.test(expandedCmd.trim())
      && !/\s(?:-H|--host)\s*(?:=|tcp:|ssh:|\d)/i.test(expandedCmd);
    if (isLocalContainerLaunch) {
      launchedLocalContainer = true;
    }

    const hk = isHousekeepingTurn(turn, turnCtx);
    let reachability = null;
    let candidates = [];

    if (hk.housekeeping) {
      housekeepingSteps++;
    } else {
      candidates = matchTurnToCatalogMoves(OBOL, turn, turnCtx);

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
    let matchedActionId = '';
    const isExternalRefLookup = hk.housekeeping && hk.reason === 'attacker_reference_lookup';
    const isLocalContainerTurn = Boolean(inLocalContainerShell || turn.localContainer);
    const suppressPromptTelemetry = Boolean(
      isLocalContainerTurn ||
      isLocalContainerLaunch ||
      (launchedLocalContainer && /@[0-9a-f]{12}:/i.test(String(turn.followPrompt || '')))
    );
    const hasTargetPromptTelemetry = !suppressPromptTelemetry && Boolean(
      String(turn.followPrompt || '').trim() ||
      (!isAttackerTurn(turn, turnCtx) && String(turn.promptLine || '').trim())
    );
    const hasPayload = !isExternalRefLookup && !isLocalContainerLaunch && Boolean(
      (expandedCmd && !hk.housekeeping) ||
      String(turn.stdout || '').trim() ||
      hasTargetPromptTelemetry
    );
    if (hasPayload) {
      matchedActionId = (reachability && reachability.matched_move_id)
        || (candidates[0] && candidates[0].id)
        || '';
      ingestReport = session.ingestTurn({
        actionId: matchedActionId,
        command: expandedCmd,
        stdout: turn.stdout || '',
        promptLine: isLocalContainerTurn
          ? ('kali@kali:~$ ' + expandedCmd)
          : (suppressPromptTelemetry ? '' : (turn.promptLine || '')),
        followPrompt: suppressPromptTelemetry ? '' : (turn.followPrompt || ''),
        target: turnTarget,
        forceTarget: turnTarget
      });
      if (matchedActionId) executedMoveIds.add(matchedActionId);
    }

    const postFollowPrompt = String(turn.followPrompt || '').trim();
    if (isLocalContainerLaunch && /@[0-9a-f]{12}:/i.test(postFollowPrompt)) {
      inLocalContainerShell = true;
      inTargetShell = false;
    } else if (inLocalContainerShell && /^(?:exit|logout)\s*$/i.test(expandedCmd.trim())) {
      inLocalContainerShell = false;
    } else if (!suppressPromptTelemetry && postFollowPrompt && !isDosBoxPromptOrTurn(turn, postFollowPrompt)) {
      if (!/^\s*[┌╭]──\(/.test(postFollowPrompt) && !/\[(?:tun|tap|vpn|wg)\d*:/i.test(postFollowPrompt)) {
        inTargetShell = true;
      }
    } else if (/^(?:exit|logout)\s*$/i.test(expandedCmd.trim())) {
      inTargetShell = false;
      inTargetRootCwd = false;
    }

    if (inTargetShell && /^cd\s+\/root(?:\s|\/|$)/i.test(expandedCmd.trim())) {
      inTargetRootCwd = true;
    } else if (inTargetShell && /^cd(?:\s+|$)/i.test(expandedCmd.trim()) && !/^cd\s+\.(?:\/|$|\s)/i.test(expandedCmd.trim())) {
      inTargetRootCwd = false;
    }

    const mintedKinds = ingestReport
      ? (ingestReport.minted_facts || []).map(f => f.kind)
      : [];
    const outcomeKind = (ingestReport && ingestReport.outcome && ingestReport.outcome.kind) || null;

    historyTurns.push({
      step_index: idx,
      target_ip: turnTarget,
      command: expandedCmd,
      stdout: turn.stdout || '',
      housekeeping: hk.housekeeping,
      minted_count: mintedKinds.length,
      outcome_kind: outcomeKind,
      matched_moves: candidates.map(c => c.id),
      executed_move_id: matchedActionId,
      was_reachable: Boolean(reachability && reachability.reachable)
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
      outcome_kind: outcomeKind
    });
  }

  // If a BloodHound bundle was provided without an explicit CLI collection turn, ingest it before final checkpoints
  if (!bhIngested && bhPayload) {
    bloodhoundResult = session.ingestBloodHound(bhPayload);
    bhIngested = true;
  }

  if (checkpointsByStep[turns.length]) {
    for (const cp of checkpointsByStep[turns.length]) {
      checkpointResults.push(evaluateCheckpoint(session, cp, net.ipAliasMap));
    }
  }

  return {
    slug: slug,
    multi_target: multiTarget,
    lhost: net.lhost,
    ip_aliases: net.ipAliasMap || {},
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
  const rawDir = opts.corpusDir ? path.resolve(opts.corpusDir) : DEFAULT_CORPUS_DIR;
  let discovered;
  try {
    discovered = discoverCorpusEntries(rawDir, {
      slugs: opts.slugs,
      limit: opts.limit && Number(opts.limit) > 0 ? Number(opts.limit) : undefined,
      includeAlternates: !!opts.includeAlternates,
      includeHosts: !!opts.includeHosts
    });
  } catch (e) {
    if (e && e.code === 'CORPUS_NOT_FOUND') {
      throw new Error('Walkthrough directory not found: ' + rawDir);
    }
    throw e;
  }

  const resolved = {
    corpusRoot: discovered.corpusRoot,
    walkthroughDir: discovered.walkthroughsDir
  };
  const entries = discovered.entries;

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
    includeHosts: false,
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
    else if (a === '--include-hosts') opts.includeHosts = true;
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
  stripCommandWrappers: stripCommandWrappers,
  extractPrimaryTool: extractPrimaryTool,
  splitShellClausesQuoteAware: splitShellClausesQuoteAware,
  extractCommandFlags: extractCommandFlags,
  detectSequentialRevertAliases: detectSequentialRevertAliases,
  applyIpAliases: applyIpAliases,
  inspectPreCommandTargetPrompt: inspectPreCommandTargetPrompt,
  isAttackerTurn: isAttackerTurn,
  isHousekeepingTurn: isHousekeepingTurn,
  hasExplicitAuthenticatedCreds: hasExplicitAuthenticatedCreds,
  hasRequiredMoveSemantics: hasRequiredMoveSemantics,
  extractScenarioBriefCredentials: extractScenarioBriefCredentials,
  inferEngagementNetworking: inferEngagementNetworking,
  expandShellTargetVars: expandShellTargetVars,
  scoreCommandAgainstVariant: scoreCommandAgainstVariant,
  matchTurnToCatalogMoves: matchTurnToCatalogMoves,
  gateEvidencePresentInHistory: gateEvidencePresentInHistory,
  simulateRetireMoveInSandbox: simulateRetireMoveInSandbox,
  evaluateClosedLoopReachability: evaluateClosedLoopReachability,
  replayWalkthrough: replayWalkthrough,
  runTrajectoryHarvest: runTrajectoryHarvest
};
