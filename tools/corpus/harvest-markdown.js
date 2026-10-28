/*
 * tools/corpus/harvest-markdown.js - Stage 2 of the Corpus Mining program (see
 * docs/CORPUS-MINING.md). Harvests terminal output from the local 0xdf walkthroughs, segments
 * each console block into command units (split on real shell prompts), runs each through OBOL's
 * REAL parser, and measures gaps along the five signal axes, using the surrounding walkthrough
 * PROSE as the ground-truth oracle for whether an output mattered.
 *
 * Axes (see CORPUS-MINING.md Signal Axes):
 *   1 enumeration  - nmap/netexec/gobuster style recon output (should mint enumeration facts)
 *   2 state-change - a shell/foothold/pivot, or on-host identity (should flip suggestions)
 *   3 loot         - a cat/ls that reveals a key, flag, or secret (low base rate, prose decides)
 *   4 outcome      - a transfer/auth succeeded or failed (success-advance / failure-doctoring)
 *   5 none         - cd, pwd, clear
 *
 * The headline deliverable is OPPORTUNITIES: units where the prose shows the output mattered
 * (a materiality cue fired) but OBOL minted nothing. Those are candidates, not confirmed; a
 * human reviews the samples before any scope or parser decision. House style: no em/en dashes.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_CORPUS_DIR = fs.existsSync(path.resolve(ROOT, '..', 'corpus', '0xdf-htb'))
  ? path.resolve(ROOT, '..', 'corpus', '0xdf-htb')
  : path.resolve(ROOT, '..', '0xdf-offsec-complete-2026-08-20');
const CORPUS_DIR = process.env.OBOL_CORPUS_DIR ? path.resolve(process.env.OBOL_CORPUS_DIR) : DEFAULT_CORPUS_DIR;
const WALK = path.join(CORPUS_DIR, 'walkthroughs');
const REPORT = path.resolve(__dirname, 'reports', '0xdf-blindspots.json');
const AXIS_REPORT = path.resolve(__dirname, 'reports', '0xdf-axes.json');

// ---- Load the real engine into an isolated sandbox.
const sandbox = { console: { log() {}, warn() {}, error() {} } };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
function load(f) { vm.runInContext(fs.readFileSync(path.join(ROOT, f), 'utf8'), sandbox, { filename: f }); }
load('assets/engine/facts.js');
load('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource',
 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'inference', 'index'].forEach(n => load('assets/engine/parsers/' + n + '.js'));
const parse = sandbox.OBOL.parsers.parseActionOutput;

// ---- Extract terminal blocks WITH their surrounding prose.
// All code blocks (any language) delimit prose; we score only terminal ones but keep the prose
// that sits before and after each.
const TERMINAL_LANGS = new Set(['console', 'shell', 'bash', 'sh', 'terminal']);
const ANY_BLOCK_RE = /<div class="language-([a-z0-9]+)[^"]*">\s*(?:<div class="highlight">\s*)?```[^\n]*\n([\s\S]*?)\n```/g;

function cleanProse(s) {
  return s
    .replace(/!\[[^\]]*\]\((?:data:[^)]*|[^)]*)\)/g, ' ')   // images incl. base64 data URIs
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')                // links -> link text
    .replace(/<[^>]+>/g, ' ')                               // html tags
    .replace(/[`*#>]+/g, ' ')                               // md punctuation
    .replace(/\s+/g, ' ')
    .trim();
}
function extractBlocks(md) {
  const all = []; let m;
  while ((m = ANY_BLOCK_RE.exec(md)) !== null) all.push({ lang: m[1], text: m[2], start: m.index, end: ANY_BLOCK_RE.lastIndex });
  const out = [];
  for (let i = 0; i < all.length; i++) {
    if (!TERMINAL_LANGS.has(all[i].lang)) continue;
    const leadStart = i > 0 ? all[i - 1].end : Math.max(0, all[i].start - 1200);
    const followEnd = i < all.length - 1 ? all[i + 1].start : Math.min(md.length, all[i].end + 1200);
    out.push({
      text: all[i].text,
      lead: cleanProse(md.slice(leadStart, all[i].start)).slice(-500),
      follow: cleanProse(md.slice(all[i].end, followEnd)).slice(0, 500),
    });
  }
  return out;
}

// ---- Prompt set (precise, anchored). Returns { tool, command, kind, host }.
const ATTACKER_HOST = /^(kali|hacky|parrot|attacker|localhost|bt|siunam)$/i;
const PROMPTS = [
  { kind: 'powershell', re: /^\s*(?:\*Evil-WinRM\*\s*)?PS\s+[A-Za-z]:\\[^\n]*?>\s?(.*)$/ },
  { kind: 'powershell', re: /^\s*(?:\*Evil-WinRM\*\s*)?PS\s*>\s?(.*)$/ },
  { kind: 'cmd', re: /^\s*[A-Za-z]:\\[^\n>]*>\s?(.*)$/ },
  { kind: 'unix', re: /^\s*([\w.-]+)@([\w.-]+)(?::[^\s#$]*)?\s*[#$]\s+(.*)$/ },
  { kind: 'unix', re: /^\s*bash-[\d.]+\s*[#$]\s+(.*)$/ },
  { kind: 'ftp', tool: 'ftp', prefix: 'ftp', re: /^\s*ftp>\s+(.*)$/ },
  { kind: 'repl', tool: 'smbclient', prefix: 'smbclient', re: /^\s*smb:\s*\\?[^>]*>\s+(.*)$/ },
  { kind: 'repl', tool: 'mysql', prefix: 'mysql', re: /^\s*(?:mysql|MariaDB \[[^\]]*\])>\s+(.*)$/ },
  { kind: 'repl', tool: 'mssql', prefix: 'mssqlclient', re: /^\s*SQL>\s+(.*)$/ },
  { kind: 'repl', tool: 'sqlite', re: /^\s*sqlite>\s+(.*)$/ },
  { kind: 'repl', tool: 'rpcclient', prefix: 'rpcclient', re: /^\s*rpcclient\s+\$>\s+(.*)$/ },
  { kind: 'meterpreter', tool: 'meterpreter', prefix: 'meterpreter', re: /^\s*meterpreter\s*>\s+(.*)$/ },
  { kind: 'repl', tool: 'metasploit', re: /^\s*msf\d?[^>]*>\s+(.*)$/ },
  { kind: 'repl', tool: 'mimikatz', re: /^\s*mimikatz\s*#\s+(.*)$/ },
  { kind: 'repl', tool: 'python', re: /^\s*>>>\s+(.*)$/ },
  { kind: 'repl', tool: 'gdb', re: /^\s*(?:gdb-peda\$|\(gdb\))\s+(.*)$/ },
  { kind: 'bare', re: /^\s*[#$]\s+([A-Za-z\/.].*)$/ },
];
// Prepend the REPL tool to the inner command exactly as the product's ingest does (assets/ui/ingest.js
// _promptCmd via _PROMPT_PREFIX): a sub-shell prompt strips the tool name off the command line, so
// `mysql> select ...` becomes bare `select ...` and `rpcclient $> enumdomgroups` becomes bare
// `enumdomgroups`. The engine's parseActionOutput dispatches on the command string (index.js keys on
// `mysql`/`rpcclient`/`mssqlclient`/...), so without the tool token every REPL unit misses its sub-parser
// and reads as a false blind. Mirroring the product keeps the sweep honest: we measure what the product
// actually mints, not what a prompt-stripped command happens to route to.
function _applyPrefix(command, prefix) {
  if (!prefix) return command;
  if (new RegExp('^' + prefix + '\\b', 'i').test(command)) return command;
  return prefix + ' ' + command;
}
function matchPrompt(line) {
  for (const p of PROMPTS) {
    const m = line.match(p.re);
    if (!m) continue;
    if (p.kind === 'unix' && m.length >= 4) return { tool: p.tool || '', command: (m[3] || '').trim(), kind: 'unix', host: m[2] };
    return { tool: p.tool || '', command: _applyPrefix((m[m.length - 1] || '').trim(), p.prefix), kind: p.kind, host: '' };
  }
  return null;
}
function segment(block) {
  const lines = block.split('\n'); const units = []; let cur = null; let saw = false;
  for (const ln of lines) {
    const p = matchPrompt(ln);
    if (p) { saw = true; if (cur) units.push(cur); cur = { tool: p.tool, command: p.command, kind: p.kind, host: p.host, outLines: [] }; }
    else if (cur) cur.outLines.push(ln);
  }
  if (cur) units.push(cur);
  return { units: units.map(u => ({ tool: u.tool, command: u.command, kind: u.kind, host: u.host, output: u.outLines.join('\n') })), hadPrompt: saw };
}
function targetScope(t) {
  const ip = t.match(/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.1[6-9]\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/);
  return 'host:' + (ip ? ip[1] : '10.10.10.10');
}

// ---- Tool label (for the enumeration ranking we keep).
const TOOLS = [
  [/\bnmap\b/i, 'nmap'], [/\bgobuster\b/i, 'gobuster'], [/\bferoxbuster\b/i, 'feroxbuster'],
  [/\bffuf\b/i, 'ffuf'], [/\bdirb\b|\bdirbuster\b/i, 'dirb'], [/\bwfuzz\b/i, 'wfuzz'],
  [/\b(nxc|netexec|crackmapexec|cme)\b/i, 'netexec/cme'], [/\bsmbclient\b/i, 'smbclient'],
  [/\bsmbmap\b/i, 'smbmap'], [/\brpcclient\b/i, 'rpcclient'], [/\benum4linux\b/i, 'enum4linux'],
  [/\bsecretsdump\b/i, 'secretsdump'], [/getuserspns|GetUserSPNs/i, 'GetUserSPNs'],
  [/getnpusers|GetNPUsers/i, 'GetNPUsers'], [/\bevil-winrm\b/i, 'evil-winrm'],
  [/\bbloodhound\b|\bsharphound\b|bloodhound-python/i, 'bloodhound'], [/\bkerbrute\b/i, 'kerbrute'],
  [/\bhashcat(?:\.bin|\.exe)?\b/i, 'hashcat'], [/\bjohn\b/i, 'john'], [/\bhydra\b/i, 'hydra'],
  [/\bsqlmap\b/i, 'sqlmap'], [/\bnikto\b/i, 'nikto'], [/\bwpscan\b/i, 'wpscan'],
  [/\bcurl\b/i, 'curl'], [/\bwget\b/i, 'wget'], [/\b(nc|netcat|ncat)\b/i, 'netcat'],
  [/\bssh\b/i, 'ssh'], [/\bftp\b/i, 'ftp'], [/\b(mysql|mariadb)\b/i, 'mysql'],
  [/\b(psql|postgres)\b/i, 'postgres'], [/\b(mssqlclient|impacket-mssqlclient)\b/i, 'mssql'],
  [/\blinpeas\b/i, 'linpeas'], [/\bwinpeas\b/i, 'winpeas'], [/\bpspy\b/i, 'pspy'],
  [/\bsudo\s+(?:-[A-Za-z]*l\b|--list\b)/i, 'sudo-l'], [/\bcertipy(?:-ad)?\b/i, 'certipy'], [/\bldapsearch\b/i, 'ldapsearch'],
  [/\b(dig|nslookup|dnsrecon|dnsenum)\b/i, 'dns'],
];
const WRAPPER_PREFIX_RE = /^(?:\s*(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s]+)|sudo(?:\s+-(?:u\s+\S+|E|i|s|H|n))?(?!\s+(?:-[A-Za-z]*l\b|--list\b))|proxychains4?(?:\s+-q|\s+-f\s+\S+)?|time|timeout\s+\S+|stdbuf(?:\s+-[ioe]\S+)+|nice(?:\s+-n\s+\S+)?|rlwrap(?:\s+-\S+)*|python[23]?(?:\.\d+)?(?:\s+-m)?|uv\s+run|pipx\s+run|mono|wine|ruby|perl|php|(?:ba)?sh\s+-c|cmd(?:\.exe)?\s+\/[cC]|powershell(?:\.exe)?(?:\s+-(?:c|command|enc|ep\s+\S+|nop|w\s+\S+))*|&)\s+)+/i;
const SHELL_WRAPPER_BINS = new Set(['for', 'while', 'if', 'xargs', 'watch', 'parallel', 'eval', 'exec']);
function detectTool(u) {
  if (u.tool) return u.tool;
  const hay = (u.command || '').trim();
  if (!hay) return 'other';
  if (/\bsudo\s+(?:-[A-Za-z]*l\b|--list\b)/i.test(hay)) return 'sudo-l';
  let stripped = hay.replace(WRAPPER_PREFIX_RE, '').trim();
  if (/^(?:echo|printf|cat)\b/i.test(stripped) && stripped.indexOf('|') >= 0) {
    const afterPipe = stripped.split('|').slice(1).join('|').replace(WRAPPER_PREFIX_RE, '').trim();
    if (afterPipe) stripped = afterPipe;
  }
  const firstToken = (stripped.split(/[\s|;&><]+/)[0] || '').replace(/^["']|["']$/g, '');
  const baseBin = firstToken.split(/[\\/]/).pop().replace(/^impacket-/i, '');
  if (baseBin && !/2john/i.test(baseBin)) {
    for (const [re, name] of TOOLS) {
      if (re.test(baseBin)) return name;
    }
  }
  if (SHELL_WRAPPER_BINS.has(baseBin.toLowerCase())) {
    for (const [re, name] of TOOLS) if (re.test(hay)) return name;
  }
  return 'other';
}
const FACT_BEARING = new Set(['nmap', 'gobuster', 'feroxbuster', 'ffuf', 'dirb', 'wfuzz',
  'netexec/cme', 'smbclient', 'smbmap', 'rpcclient', 'enum4linux', 'secretsdump', 'GetUserSPNs',
  'GetNPUsers', 'bloodhound', 'kerbrute', 'hashcat', 'john', 'hydra', 'sqlmap', 'nikto', 'wpscan',
  'certipy', 'ldapsearch', 'dns', 'mysql', 'postgres', 'mssql', 'linpeas', 'winpeas', 'pspy', 'curl', 'sudo-l']);

// ---- De-inflation of the two multi-purpose primitives (Stage 2 cleanup; see CORPUS-LEDGER output
// axis). smbclient and curl are NOT pure enumeration tools: smbclient is connect-then-browse and
// curl is a raw fetch, so each mixes genuine enumeration output with launch/login banners,
// transfers, and app-content reads. Their real enumeration output already mints through the shipped
// parsers (smbclient interactive ls/dir -> loot.files via _parse_share_inventory; curl web pages ->
// web.*/http.* via the web parser). A unit that MINTED is therefore real coverage and is never
// reclassified. A BLIND unit, however, is only an enumeration gap when the shape is one we could
// have parsed; the launch/transfer/content-read residue is loot/outcome signal (measured on those
// axes), not a missed enumeration fact, so counting it here falsely crowns these two as the top
// gaps. rankingLabel moves that residue to explicit non-fact-bearing buckets, gated on independent
// content signatures (never on mint status), so a genuinely missed page or share-list still counts.
const SMB_LAUNCH = /Try "help" to get a list of possible commands|Anonymous login successful|session setup failed|tree connect failed|Impacket v[\d.]|Type help for list of commands|CCache file is not found|Reconnecting with SMB1|Server requested encryption|protocol negotiation failed|NT_STATUS_LOGON_FAILURE|NT_STATUS_ACCESS_DENIED|Enter\s+\S+\s+password:/i;
const SMB_LISTING = /^\s*\.{1,2}\s+D|\b[DAHNRS]+\s+\d+\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun)|\bblocks of size\b|\bSharename\b|\bDisk\b|\bIPC\b/im;
const SMB_REPL_XFER = /^(?:smbclient\s+)?(put|mput|get|mget|cd|lcd|mkdir|rmdir|rm|del|rename|!|q|quit|exit|recurse|prompt|mask)\b/i;
const CURL_XFER_CMD = /(^|\s)-[oO]\b|--output\b|--remote-name\b|>\s*[^\s|>&]+\s*$/;
const CURL_XFER_OUT = /%\s*Total\s+%\s*Received|\bDload\s+Upload\b|Saving to:/i;
const CURL_PS_FAIL = /\bcurl\s*:\s|CategoryInfo|FullyQualifiedErrorId|Invoke-WebRequest\s*:|is not recognized as|could not be resolved|positional parameter|ParameterBindingException/i;
const WEB_ENUM_SHAPE = /HTTP\/\d|<!DOCTYPE|<html|<head\b|<title|<body|<form|<a\s+href|Server:\s|Content-Type:\s|Set-Cookie:|X-Powered-By:/i;
const WEB_FUZZ_TOOLS = new Set(['ffuf', 'gobuster', 'feroxbuster', 'dirb', 'wfuzz']);
const WEB_FUZZ_HIT = /\[Status:\s*\d{3}|\(Status:\s*\d{3}\)|\bFound:\s|\b\d{3}\s+(?:(?:GET|POST|HEAD)\s+)?\d+l\s+\d+w|\b==>\s+DIRECTORY:|^\s*\+\s+https?:\/\/|^\s*000\d+\s*:\s*\d{3}\b/im;
const DB_TOOLS = new Set(['mysql', 'mssql', 'postgres']);
const DB_MUTATION_OR_META_CMD = /\b(insert\s+into|update\s+\S+\s+set|delete\s+from|create\s+(?:table|database|user|function)|drop\s+|alter\s+|use\s+\S+|describe\s+|desc\s+|show\s+(?:columns|tables|variables|grants|status)|sp_configure|reconfigure|xp_dirtree|exec\s+master)\b|^\s*\\[dclq]\b/i;
const DB_EMPTY_OR_ACK_OUT = /^(?:\s*(?:Query OK,\s*\d+\s*rows?\s*affected|Database changed|Empty set|0 rows in set|\(\d+\s*rows?\s*affected\)|Records:\s*\d+\s+Duplicates:\s*\d+\s+Warnings:\s*\d+|Table\s+Op\s+Msg_type\s+Msg_text)[^\r\n]*\r?\n?)+\s*$/i;
function rankingLabel(tool, u, didMint) {
  if (didMint) return tool;                               // a mint is real coverage: never reclassify out
  const out = u.output || '';
  const cmd = u.command || '';
  if (tool === 'smbclient') {
    if (u.kind === 'repl') {
      if (SMB_REPL_XFER.test(cmd)) return 'smbclient-xfer'; // put/get/cd navigation, not a listing
      const nonDotRows = (out.match(/^\s+(?!\.{1,2}\s+D\b)\S.*?\s+[DAHSRNCETI]+\s+\d+\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)/gim) || []);
      if (/\bblocks of size\b/i.test(out) && nonDotRows.length === 0) return 'smbclient-empty';
      return tool;
    }
    if (/-L\b/.test(cmd) || /\s-c\b|--command/.test(cmd)) return tool;          // -L share-list / -c one-shot ARE enumeration (real gap if blind)
    if (SMB_LAUNCH.test(out) && !SMB_LISTING.test(out)) return 'smbclient-launch'; // factless connect/login banner
    return tool;
  }
  if (tool === 'curl') {
    if (CURL_XFER_CMD.test(cmd) || CURL_XFER_OUT.test(out)) return 'curl-xfer';   // file download / redirect to disk
    if (CURL_PS_FAIL.test(out)) return 'curl-fail';                                     // PowerShell curl-alias error
    if (!WEB_ENUM_SHAPE.test(out)) return 'curl-read';                                  // raw app payload / file / API body
    return tool;                                                                             // blind but web-shaped: a genuine missed page, kept as a real gap
  }
  if (WEB_FUZZ_TOOLS.has(tool)) {
    if (!WEB_FUZZ_HIT.test(out)) return tool + '-empty';
  }
  if (DB_TOOLS.has(tool)) {
    if (DB_MUTATION_OR_META_CMD.test(cmd) || DB_EMPTY_OR_ACK_OUT.test(out)) return tool + '-ack';
    if (!/\b(?:admin|root|hash|pass|pwd|secret|token|key|flag|version|xp_cmdshell|\$[1256yabPASH]+\$|0x[0-9a-f]{32}|[0-9a-f]{32})\b/i.test(out)) return tool + '-app-rows';
  }
  if (tool === 'GetNPUsers' && /No entries found!|doesn't have UF_DONT_REQUIRE_PREAUTH set/i.test(out) && !/\$krb5asrep\$/i.test(out)) return 'GetNPUsers-none';
  if (tool === 'GetUserSPNs' && /No entries found!/i.test(out) && !/\$krb5tgs\$/i.test(out)) return 'GetUserSPNs-none';
  if (tool === 'certipy' && (/Found no vulnerable certificate templates/i.test(out) || (!/Template Name|Got hash for|Saved credential cache|Successfully|ESC\d/i.test(out)))) return 'certipy-none';
  if (tool === 'ldapsearch' && /# numResponses:\s*1\b/i.test(out) && !/^dn:/im.test(out)) return 'ldapsearch-empty';
  if (tool === 'sudo-l' && /may not run sudo|a password is required|\[sudo\] password for|1 incorrect password attempt/i.test(out) && !/may run the following/i.test(out)) return 'sudo-l-denied';
  if ((tool === 'john' || tool === 'hashcat') && (/0 password hashes cracked|No password hashes loaded|No hashes loaded|Usage:|--help|\bExhausted\b/i.test(out) || /--stdout\b/i.test(cmd))) return tool + '-util';
  if (tool === 'nmap' && /0 hosts up|All \d+ scanned ports on .* are (?:closed|filtered|in ignored states)/i.test(out) && !/^\d+\/(?:tcp|udp)\s+open\b/im.test(out)) return 'nmap-empty';
  return tool;
}

// ---- Axis classification (priority order chosen so each axis's characteristic signal wins).
const FILE_READ = /\b(cat|type|more|less|head|tail|strings)\b|\bget-content\b|\bgc\b/i;
const LISTING = /\b(ls|dir|tree|find)\b|\bget-childitem\b|\bgci\b/i;
const TRANSFER = /\b(wget|curl|scp|certutil|tftp|smbget)\b|\biwr\b|\binvoke-webrequest\b/i;
const SHELL_LAUNCH = /\bevil-winrm\b|\bpsexec(\.py)?\b|\bwmiexec(\.py)?\b|\bsmbexec(\.py)?\b|\batexec(\.py)?\b|\bssh\b|\bxfreerdp\b|pty\.spawn|\/bin\/(ba)?sh\b|\bsu\b|\bsudo\s+-i\b|nc .*-e|runas/i;
const IDENTITY = /\b(whoami|id|hostname|systeminfo)\b|\bnet user\b|\bnet localgroup\b|\bgetuid\b/i;
const ENUM_CMD = /\b(nmap|gobuster|feroxbuster|ffuf|dirb|wfuzz|nxc|netexec|crackmapexec|cme|smbmap|enum4linux|secretsdump|kerbrute|hashcat|john|hydra|sqlmap|nikto|wpscan|ldapsearch|certipy|bloodhound|dig|nslookup)\b/i;
const NONE_CMD = /^\s*(cd|pwd|clear|export|set|echo|which|cls|exit)\b/i;

function classifyAxis(u, toolLabel) {
  const c = u.command || '';
  const onHostPrompt = u.kind === 'powershell' || u.kind === 'cmd' || u.kind === 'meterpreter' || (u.kind === 'unix' && u.host && !ATTACKER_HOST.test(u.host));
  if (FILE_READ.test(c)) return 'loot';
  if (TRANSFER.test(c)) return 'outcome';
  if (SHELL_LAUNCH.test(c)) return 'state-change';
  if (IDENTITY.test(c) && (onHostPrompt || !u.host)) return 'state-change';
  if (ENUM_CMD.test(c) || FACT_BEARING.has(toolLabel)) return 'enumeration';
  if (LISTING.test(c)) return 'loot';
  if (onHostPrompt) return 'state-change';   // a command run in a victim shell with no other tag
  if (NONE_CMD.test(c)) return 'none';
  return 'other';
}

// ---- Prose materiality cues (the ground-truth oracle). Did the walkthrough say it mattered?
const CUES = {
  loot: /\b(password|passwd|cred(ential)?s?|hash(es)?|id_rsa|private key|ssh key|flag|user\.txt|root\.txt|proof\.txt|secret|api[_ ]?key|token|passphrase)\b|\b(log ?in|logs in|gives us|reveals?|leak)\b/i,
  'state-change': /\b(shell|foothold|reverse shell|meterpreter|logged in|log in as|access as|we are now|we're now|got a shell|as root|as system|as administrator|on the box|on the host|on the target|user on|runs as|execution as)\b/i,
  outcome: /\b(works?|worked|successful|success|fail(s|ed)?|doesn'?t work|does not work|denied|refused|download(ed)?|upload(ed)?|transfer(red)?|timed out|didn'?t work)\b/i,
};
function cueFires(axis, prose) { const re = CUES[axis]; return re ? re.test(prose) : false; }

// ---- Sweep
const files = fs.readdirSync(WALK).filter(f => f.endsWith('.md'));
const perTool = Object.create(null);
const axes = {}; ['enumeration', 'state-change', 'loot', 'outcome', 'none', 'other'].forEach(a => axes[a] = { units: 0, withOutput: 0, minted: 0, proseMaterial: 0, opportunities: 0, samples: [] });
let totalBlocks = 0, noPrompt = 0, totalUnits = 0, noOutput = 0, withOutput = 0, minted = 0, blind = 0, parserErrors = 0;
function bump(t) { if (!perTool[t]) perTool[t] = { units: 0, withOutput: 0, minted: 0, blind: 0, kinds: Object.create(null) }; return perTool[t]; }

for (const file of files) {
  const md = fs.readFileSync(path.join(WALK, file), 'utf8');
  for (const block of extractBlocks(md)) {
    totalBlocks++;
    const { units, hadPrompt } = segment(block.text);
    if (!hadPrompt) { noPrompt++; continue; }
    const prose = (block.lead + ' ' + block.follow);
    for (const u of units) {
      totalUnits++;
      const toolLabel = detectTool(u);
      const axis = classifyAxis(u, toolLabel);
      const A = axes[axis]; A.units++;
      const hasOut = u.output.replace(/\s/g, '').length >= 20 || /^\s*(?:\d{1,3}\.){3}\d{1,3}\s*$/.test(u.output);
      if (!hasOut) { noOutput++; bump(toolLabel).units++; continue; }
      A.withOutput++;
      let facts = [];
      try { const r = parse({ actionId: '', command: u.command, stdout: u.output, stderr: '', source: u.command || file, scope: targetScope(u.output + ' ' + u.command), domain: '' }); facts = (r && r.facts) || []; }
      catch (e) { parserErrors++; }
      const didMint = facts.length > 0;
      // The axis tally above stays keyed on the real tool; the enumeration RANKING below uses the
      // de-inflated label so a primitive's launch/transfer/content residue leaves the fact-bearing gap.
      const rec = bump(rankingLabel(toolLabel, u, didMint)); rec.units++; rec.withOutput++; withOutput++;
      if (didMint) { rec.minted++; minted++; A.minted++; for (const f of facts) rec.kinds[f.kind] = (rec.kinds[f.kind] || 0) + 1; }
      else { rec.blind++; blind++; }
      // Prose-grounded opportunity for the non-enumeration axes.
      if (axis === 'state-change' || axis === 'loot' || axis === 'outcome') {
        const material = cueFires(axis, prose);
        if (material) A.proseMaterial++;
        if (material && !didMint) {
          A.opportunities++;
          if (A.samples.length < 12) A.samples.push({ file, command: u.command.slice(0, 90), outputHead: u.output.split('\n').filter(l => l.trim()).slice(0, 4).join(' | ').slice(0, 220), prose: prose.slice(0, 240) });
        }
      }
    }
  }
}

// ---- Enumeration ranking (unchanged, kept for the parser-gap view).
const toolRows = Object.keys(perTool).map(t => { const r = perTool[t]; return { tool: t, factBearing: FACT_BEARING.has(t), withOutput: r.withOutput, minted: r.minted, blind: r.blind, blindRate: r.withOutput ? +(r.blind / r.withOutput).toFixed(2) : 0 }; }).sort((a, b) => b.blind - a.blind);
const actionable = toolRows.filter(r => r.factBearing);
const act = actionable.reduce((a, r) => { a.withOutput += r.withOutput; a.minted += r.minted; a.blind += r.blind; return a; }, { withOutput: 0, minted: 0, blind: 0 });

fs.mkdirSync(path.dirname(REPORT), { recursive: true });
fs.writeFileSync(REPORT, JSON.stringify({ generated_at: new Date().toISOString(), walkthroughs: files.length, units_with_output: withOutput, minted, blind, actionable: { units: act.withOutput, minted: act.minted, blind: act.blind }, per_tool: toolRows }, null, 2));
fs.writeFileSync(AXIS_REPORT, JSON.stringify({ generated_at: new Date().toISOString(), note: 'opportunities = prose cue fired AND OBOL minted nothing; candidates for human review', axes }, null, 2));

// ---- Console
console.log('Walkthroughs ' + files.length + ' | terminal blocks ' + totalBlocks + ' (no-prompt ' + noPrompt + ') | command units ' + totalUnits + ' (command-only ' + noOutput + ') | with output ' + withOutput);
console.log('Overall: minted ' + minted + ', blind ' + blind + ' | Enumeration actionable: ' + act.minted + ' minted / ' + act.blind + ' blind of ' + act.withOutput + '\n');
console.log('Per-axis (units / withOutput / OBOL-minted / prose-material / OPPORTUNITIES):');
for (const a of Object.keys(axes)) {
  const x = axes[a];
  console.log('  ' + a.padEnd(14) + String(x.units).padStart(6) + String(x.withOutput).padStart(8) + String(x.minted).padStart(8) + String(x.proseMaterial).padStart(9) + String(x.opportunities).padStart(8));
}
for (const a of ['state-change', 'loot', 'outcome']) {
  console.log('\n=== ' + a + ' opportunity samples (prose said it mattered, OBOL minted nothing) ===');
  for (const s of axes[a].samples.slice(0, 5)) {
    console.log('  cmd : ' + s.command);
    console.log('  out : ' + s.outputHead);
    console.log('  why : ' + s.prose + '\n');
  }
}
console.log('Reports: ' + REPORT + '  and  ' + AXIS_REPORT);
