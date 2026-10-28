/*
 * tools/corpus/facts-axis.js - FACTS axis of the Corpus Mining program (see docs/CORPUS-MINING.md
 * Section 4 `facts_implied[]`, Section 6 Stage 4, and the Four Axes block in CORPUS-LEDGER.md).
 *
 * The output-axis harvester (harvest-markdown.js) measures a BINARY signal per block: did OBOL
 * mint any fact (not-blind) or nothing (blind). That overcounts success, because a block can mint
 * a junk or incidental fact and look "not blind" while completely missing the fact that mattered.
 * The facts axis grades at the FACT-KIND level against human-authored ground truth: for each
 * labeled block we assert the kinds the block SHOULD mint (the floor) and, optionally, kinds it
 * must NOT mint (false-positive guards). Running OBOL's real parser over the block then yields a
 * true confusion matrix: correct (expected kind minted), miss (expected kind not minted), and
 * forbidden-hit (a guarded kind minted). Minted-but-unlabeled kinds are reported as `extra` for
 * information only; they are not failures, because a labeler lists the floor, not every structural
 * fact (host.up, scan.*) a mature parser legitimately adds.
 *
 * Ground truth lives in labels/0xdf-facts.json, authored by a human reading the real block. To
 * respect the copyright boundary (Principle 7: we derive output shapes and commands, never prose),
 * a label stores only { id, file, command, expected_kinds, forbidden_kinds?, expected_values?,
 * note? }. It never stores the raw output verbatim; this tool re-reads the live output from the
 * local corpus by re-extracting the block whose id matches. The engine is the deterministic oracle
 * (Principle 2); the human only supplies the ground truth the engine is graded against.
 *
 * Usage:
 *   node tools/corpus/facts-axis.js                 # matrix: grade every labeled block, write report
 *   node tools/corpus/facts-axis.js --worksheet     # list UNLABELED blocks (observed kinds prefilled)
 *   node tools/corpus/facts-axis.js --worksheet --axis loot --tool smbclient --limit 40
 *
 * The matrix report is tools/corpus/reports/0xdf-facts-matrix.json. The worksheet report is
 * tools/corpus/reports/0xdf-facts-worksheet.json. Both are qa-only dev artifacts; nothing here
 * ships to prod or runs at runtime. House style: no em or en dashes.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_CORPUS_DIR = fs.existsSync(path.resolve(ROOT, '..', 'corpus', '0xdf-htb'))
  ? path.resolve(ROOT, '..', 'corpus', '0xdf-htb')
  : path.resolve(ROOT, '..', '0xdf-offsec-complete-2026-08-20');
const CORPUS_DIR = process.env.OBOL_CORPUS_DIR ? path.resolve(process.env.OBOL_CORPUS_DIR) : DEFAULT_CORPUS_DIR;
const WALK = path.join(CORPUS_DIR, 'walkthroughs');
const LABELS = path.resolve(__dirname, 'labels', '0xdf-facts.json');
const MATRIX = path.resolve(__dirname, 'reports', '0xdf-facts-matrix.json');
const WORKSHEET = path.resolve(__dirname, 'reports', '0xdf-facts-worksheet.json');

// ---- CLI
const argv = process.argv.slice(2);
function flag(name) { return argv.includes('--' + name); }
function opt(name, def) { const i = argv.indexOf('--' + name); return i >= 0 && argv[i + 1] ? argv[i + 1] : def; }
const MODE_WORKSHEET = flag('worksheet');
const SHOW_ID = opt('show', '');
const WS_AXIS = opt('axis', '');
const WS_TOOL = opt('tool', '');
const WS_LIMIT = parseInt(opt('limit', '60'), 10);

if (!fs.existsSync(WALK)) {
  console.error('facts-axis: local corpus not found at ' + WALK);
  console.error('This is a qa-only dev tool; it needs the 0xdf snapshot. Nothing shipped depends on it.');
  process.exit(2);
}

// ---- Load the real engine into an isolated sandbox (same set the harvester loads).
const sandbox = { console: { log() {}, warn() {}, error() {} } };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
function load(f) { vm.runInContext(fs.readFileSync(path.join(ROOT, f), 'utf8'), sandbox, { filename: f }); }
load('assets/engine/facts.js');
load('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource',
 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog', 'inference', 'index'].forEach(n => load('assets/engine/parsers/' + n + '.js'));
const parse = sandbox.OBOL.parsers.parseActionOutput;
const { verifyCorpus } = require('../verify-parser-corpus.js');

// ---- Block extraction and segmentation (compact, self-contained copy so block ids are stable
// regardless of harvest-markdown.js; see the note in CORPUS-LEDGER.md about consolidating these).
const TERMINAL_LANGS = new Set(['console', 'shell', 'bash', 'sh', 'terminal']);
const ANY_BLOCK_RE = /<div class="language-([a-z0-9]+)[^"]*">\s*(?:<div class="highlight">\s*)?```[^\n]*\n([\s\S]*?)\n```/g;
function cleanProse(s) {
  return s.replace(/!\[[^\]]*\]\((?:data:[^)]*|[^)]*)\)/g, ' ').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/<[^>]+>/g, ' ').replace(/[`*#>]+/g, ' ').replace(/\s+/g, ' ').trim();
}
function extractBlocks(md) {
  const all = []; let m;
  while ((m = ANY_BLOCK_RE.exec(md)) !== null) all.push({ lang: m[1], text: m[2], start: m.index, end: ANY_BLOCK_RE.lastIndex });
  const out = [];
  for (let i = 0; i < all.length; i++) {
    if (!TERMINAL_LANGS.has(all[i].lang)) continue;
    const leadStart = i > 0 ? all[i - 1].end : Math.max(0, all[i].start - 1200);
    const followEnd = i < all.length - 1 ? all[i + 1].start : Math.min(md.length, all[i].end + 1200);
    out.push({ text: all[i].text, lead: cleanProse(md.slice(leadStart, all[i].start)).slice(-500), follow: cleanProse(md.slice(all[i].end, followEnd)).slice(0, 500) });
  }
  return out;
}
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
function _applyPrefix(command, prefix) {
  if (!prefix) return command;
  if (new RegExp('^' + prefix + '\\b', 'i').test(command)) return command;
  return prefix + ' ' + command;
}
function matchPrompt(line) {
  for (const p of PROMPTS) {
    const m = line.match(p.re);
    if (!m) continue;
    if (p.kind === 'unix' && m.length >= 4) {
      const raw = (m[3] || '').trim();
      return { tool: p.tool || '', rawCommand: raw, command: raw, kind: 'unix', host: m[2] };
    }
    const raw = (m[m.length - 1] || '').trim();
    return { tool: p.tool || '', rawCommand: raw, command: _applyPrefix(raw, p.prefix), kind: p.kind, host: '' };
  }
  return null;
}
function segment(block) {
  const lines = block.split('\n'); const units = []; let cur = null; let saw = false;
  for (const ln of lines) {
    const p = matchPrompt(ln);
    if (p) { saw = true; if (cur) units.push(cur); cur = { tool: p.tool, rawCommand: p.rawCommand, command: p.command, kind: p.kind, host: p.host, outLines: [] }; }
    else if (cur) cur.outLines.push(ln);
  }
  if (cur) units.push(cur);
  return units.map(u => ({ tool: u.tool, rawCommand: u.rawCommand, command: u.command, kind: u.kind, host: u.host, output: u.outLines.join('\n') }));
}
function targetScope(t) {
  const ip = t.match(/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.1[6-9]\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/);
  return 'host:' + (ip ? ip[1] : '10.10.10.10');
}

// ---- Tool + axis labels (reused from the harvester so the worksheet filters line up).
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
const FACT_BEARING = new Set(['nmap', 'gobuster', 'feroxbuster', 'ffuf', 'dirb', 'wfuzz', 'netexec/cme',
  'smbclient', 'smbmap', 'rpcclient', 'enum4linux', 'secretsdump', 'GetUserSPNs', 'GetNPUsers',
  'bloodhound', 'kerbrute', 'hashcat', 'john', 'hydra', 'sqlmap', 'nikto', 'wpscan', 'certipy',
  'ldapsearch', 'dns', 'mysql', 'postgres', 'mssql', 'linpeas', 'winpeas', 'pspy', 'curl', 'sudo-l']);
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
  if (onHostPrompt) return 'state-change';
  if (NONE_CMD.test(c)) return 'none';
  return 'other';
}

// ---- Stable block id: sha1(file + command + first non-empty output lines). Reproducible so a
// label authored against a worksheet entry keeps matching the same corpus block across runs.
function outputHead(out) { return out.split('\n').filter(l => l.trim()).slice(0, 6).join('\n'); }
function blockId(file, command, out) {
  return crypto.createHash('sha1').update(file + '\u0000' + command + '\u0000' + outputHead(out)).digest('hex').slice(0, 12);
}

// ---- Build the live index of all command units with output.
function buildIndex() {
  const index = new Map();
  for (const file of fs.readdirSync(WALK).filter(f => f.endsWith('.md'))) {
    const md = fs.readFileSync(path.join(WALK, file), 'utf8');
    for (const block of extractBlocks(md)) {
      for (const u of segment(block.text)) {
        if (u.output.replace(/\s/g, '').length < 20) continue;
        const id = blockId(file, u.rawCommand != null ? u.rawCommand : u.command, u.output);
        if (!index.has(id)) index.set(id, { id, file, unit: u, lead: block.lead, follow: block.follow });
      }
    }
  }
  return index;
}

function observedKinds(u) {
  try {
    const r = parse({ actionId: '', command: u.command, stdout: u.output, stderr: '', source: u.command || '', scope: targetScope(u.output + ' ' + u.command), domain: '' });
    const facts = (r && r.facts) || [];
    const supported = [], refuted = [];
    for (const f of facts) { if (f.state === 'refuted') refuted.push(f.kind); else supported.push(f.kind); }
    return { supported: Array.from(new Set(supported)), refuted: Array.from(new Set(refuted)) };
  } catch (e) { return { supported: [], refuted: [], error: e.message }; }
}

// ===================================================================== show mode (inspect one block)
if (SHOW_ID) {
  const index = buildIndex();
  const entry = index.get(SHOW_ID);
  if (!entry) { console.error('facts-axis --show: no block with id ' + SHOW_ID); process.exit(2); }
  const obs = observedKinds(entry.unit);
  console.log('id      : ' + entry.id);
  console.log('file    : ' + entry.file);
  console.log('command : ' + entry.unit.command);
  console.log('observed supported: ' + obs.supported.join(', '));
  console.log('observed refuted  : ' + obs.refuted.join(', '));
  console.log('----- full output -----');
  console.log(entry.unit.output);
  console.log('----- end output -----');
  process.exit(0);
}

// ===================================================================== worksheet mode
if (MODE_WORKSHEET) {
  const index = buildIndex();
  const labeled = new Set((readLabels().cases || []).map(c => c.id));
  const rows = [];
  for (const entry of index.values()) {
    if (labeled.has(entry.id)) continue;
    const tool = detectTool(entry.unit);
    const axis = classifyAxis(entry.unit, tool);
    if (WS_AXIS && axis !== WS_AXIS) continue;
    if (WS_TOOL && tool !== WS_TOOL) continue;
    const obs = observedKinds(entry.unit);
    rows.push({
      id: entry.id, file: entry.file, tool, axis,
      command: entry.unit.command.slice(0, 120),
      observed_supported_kinds: obs.supported,
      observed_refuted_kinds: obs.refuted,
      output_head: outputHead(entry.unit.output).slice(0, 600),
      // A human copies the id, command and file into labels/0xdf-facts.json and fills these:
      expected_kinds: [],
      forbidden_kinds: [],
    });
  }
  rows.sort((a, b) => (a.tool + a.file).localeCompare(b.tool + b.file));
  const out = rows.slice(0, WS_LIMIT);
  fs.mkdirSync(path.dirname(WORKSHEET), { recursive: true });
  fs.writeFileSync(WORKSHEET, JSON.stringify({ generated_at: new Date().toISOString(), filter: { axis: WS_AXIS || null, tool: WS_TOOL || null }, total_unlabeled_matching: rows.length, shown: out.length, rows: out }, null, 2));
  console.log('facts-axis worksheet: ' + rows.length + ' unlabeled block(s) match' + (WS_AXIS ? ' axis=' + WS_AXIS : '') + (WS_TOOL ? ' tool=' + WS_TOOL : '') + '; wrote ' + out.length + ' to ' + WORKSHEET);
  process.exit(0);
}

// ===================================================================== matrix mode
function readLabels() {
  if (!fs.existsSync(LABELS)) return { version: 1, cases: [] };
  return JSON.parse(fs.readFileSync(LABELS, 'utf8'));
}
const labelDoc = readLabels();
const index = buildIndex();

// Shape labels into verify-parser-corpus cases, reading live output by id.
const missingBlocks = [];
const cases = [];
const outputs = Object.create(null);
for (const lab of labelDoc.cases || []) {
  const entry = index.get(lab.id);
  if (!entry) { missingBlocks.push(lab.id); continue; }
  outputs[lab.id] = entry.unit.output;
  cases.push({
    id: lab.id,
    command: entry.unit.command,
    target: targetScope(entry.unit.output + ' ' + entry.unit.command).replace('host:', ''),
    expected_supported_kinds: lab.expected_kinds || [],
    forbidden_supported_kinds: lab.forbidden_kinds || [],
    expected_facts: lab.expected_values || [],
    // verifyCorpus asserts fact lineage source === command; the harvester parses with source===command.
  });
}
const manifest = { defaults: { target: '10.10.10.10' }, cases };
const result = verifyCorpus(manifest, tc => outputs[tc.id] || '', parse);

// Classify each case into the confusion matrix.
const perKind = Object.create(null);
function krow(k) { if (!perKind[k]) perKind[k] = { expected: 0, correct: 0, miss: 0 }; return perKind[k]; }
const caseRows = [];
let totalExpected = 0, totalCorrect = 0, totalMiss = 0, forbiddenHits = 0, lineageIssues = 0;
const extraKinds = Object.create(null);
for (const c of result.cases) {
  const lab = (labelDoc.cases || []).find(l => l.id === c.id);
  const entry = index.get(c.id);
  const obs = observedKinds(entry.unit);
  const supported = new Set(obs.supported);
  const expected = lab.expected_kinds || [];
  const misses = [], corrects = [];
  for (const k of expected) { totalExpected++; krow(k).expected++; if (supported.has(k)) { totalCorrect++; krow(k).correct++; corrects.push(k); } else { totalMiss++; krow(k).miss++; misses.push(k); } }
  const forbHit = (lab.forbidden_kinds || []).filter(k => supported.has(k));
  forbiddenHits += forbHit.length;
  const expSet = new Set(expected);
  const extra = obs.supported.filter(k => !expSet.has(k));
  for (const k of extra) extraKinds[k] = (extraKinds[k] || 0) + 1;
  // Lineage: verifyCorpus flags source mismatches as errors; surface them without failing the axis.
  const lineage = c.errors.filter(e => /lineage/i.test(e));
  lineageIssues += lineage.length;
  caseRows.push({ id: c.id, file: entry.file, command: entry.unit.command.slice(0, 100), expected, correct: corrects, miss: misses, forbidden_hit: forbHit, extra_observed: extra });
}

fs.mkdirSync(path.dirname(MATRIX), { recursive: true });
const report = {
  generated_at: new Date().toISOString(),
  note: 'FACTS axis: fact-kind confusion matrix over human-labeled real corpus blocks. correct = expected kind minted; miss = expected kind not minted; forbidden_hit = a guarded kind minted (false positive). extra = minted-but-unlabeled, informational only.',
  labeled_blocks: (labelDoc.cases || []).length,
  resolved_blocks: cases.length,
  missing_blocks: missingBlocks,
  totals: { expected_facts: totalExpected, correct: totalCorrect, miss: totalMiss, forbidden_hits: forbiddenHits, recall: totalExpected ? +(totalCorrect / totalExpected).toFixed(3) : null },
  per_kind: perKind,
  extra_observed_kinds: extraKinds,
  cases: caseRows,
};
if (fs.existsSync(MATRIX)) {
  try {
    const prev = JSON.parse(fs.readFileSync(MATRIX, 'utf8'));
    const prevCmp = Object.assign({}, prev, { generated_at: null });
    const nextCmp = Object.assign({}, report, { generated_at: null });
    if (JSON.stringify(prevCmp) === JSON.stringify(nextCmp) && prev.generated_at) {
      report.generated_at = prev.generated_at;
    }
  } catch (e) {}
}
fs.writeFileSync(MATRIX, JSON.stringify(report, null, 2));

console.log('FACTS axis matrix: ' + cases.length + ' / ' + ((labelDoc.cases || []).length) + ' labeled blocks resolved against the live corpus.');
if (missingBlocks.length) console.log('  ' + missingBlocks.length + ' label(s) did not match any current corpus block (ids: ' + missingBlocks.join(', ') + ').');
console.log('  expected facts ' + totalExpected + ' | correct ' + totalCorrect + ' | miss ' + totalMiss + ' | recall ' + (totalExpected ? (100 * totalCorrect / totalExpected).toFixed(1) + '%' : 'n/a'));
console.log('  forbidden-kind hits (false positives on labeled set): ' + forbiddenHits);
const missKinds = Object.keys(perKind).filter(k => perKind[k].miss > 0).sort((a, b) => perKind[b].miss - perKind[a].miss);
if (missKinds.length) { console.log('\n  misses by kind (the facts-axis backlog):'); for (const k of missKinds) console.log('    ' + k.padEnd(28) + ' miss ' + perKind[k].miss + ' / expected ' + perKind[k].expected); }
console.log('\nReport: ' + MATRIX);
// Non-zero exit only on a false positive (a guarded kind minted); misses are backlog, not failures.
process.exit(forbiddenHits > 0 ? 1 : 0);
