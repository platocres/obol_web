/*
 * tools/corpus/markdown-extractor.js - Unified Markdown + CommonMark + 0xdf HTML Terminal
 * Block Extractor, Multi-Turn Prompt Splitter, OCR Sidecar Splicer, and Alternate Discoverer
 * (qa-only; never ships to prod, never runs at runtime).
 *
 * Replaces duplicated block/prompt regexes in harvest-markdown.js and facts-axis.js while
 * preserving 100% SHA-1 blockId compatibility for existing 0xdf-facts.json ground-truth labels.
 *
 * Supports:
 *   1. 0xdf <div class="language-..."> HTML-wrapped fenced blocks.
 *   2. Standard CommonMark ``` and ~~~ fenced blocks (case-insensitive terminal/output tags,
 *      plus bare fences classified with ingest.js-aligned prompt/tool/content signatures,
 *      excluding static source blocks like python/c/php/html/json/xml unless they contain a
 *      real shell prompt or Exploit-DB header).
 *   3. Multi-command chronological turn splitting across 2-line Kali zsh prompts
 *      (┌──(kali㉿kali)-[...] / └─$), [user@host cwd]$, user@host:cwd$, sh-5.1$, PS C:\...>,
 *      C:\...>, *Evil-WinRM* PS ...>, smb: \>, ftp>, mysql>, postgres=#, sqlite>,
 *      127.0.0.1:6379>, rpcclient $>, meterpreter >, msf6 >, mimikatz #, and bare $ / #.
 *   4. Chronological OCR sidecar splicing (<corpusDir>/ocr-sidecars/<slug>.json) at exact
 *      1-based Markdown line positions.
 *   5. Cross-author alternate discovery (<corpusDir>/alternates/<slug>--*.md).
 *
 * House style: no em dashes, no en dashes, no emoji.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ATTACKER_HOST = /^(kali|hacky|parrot|attacker|localhost|bt|siunam|pwnbox|offsec)$/i;

const EXPLICIT_TERMINAL_LANGS = new Set([
  'console', 'shell', 'bash', 'sh', 'zsh', 'terminal', 'shell-session', 'sh-session',
  'powershell', 'ps1', 'pwsh', 'posh', 'cmd', 'dos', 'bat', 'batch',
  'text', 'plaintext', 'txt', 'raw', 'output', 'log',
  'sql', 'mysql', 'psql', 'postgresql', 'postgres', 'mssql', 'tsql', 'sqlite', 'sqlite3',
  'ftp', 'smb', 'smbclient', 'redis'
]);

const STATIC_CODE_LANGS = new Set([
  'python', 'py', 'python2', 'python3', 'c', 'cpp', 'c++', 'cc', 'cxx', 'h', 'hpp',
  'csharp', 'cs', 'c#', 'java', 'javascript', 'js', 'jsx', 'typescript', 'ts', 'tsx',
  'php', 'html', 'htm', 'css', 'scss', 'less', 'json', 'jsonc', 'xml', 'svg',
  'yaml', 'yml', 'toml', 'ini', 'conf', 'dockerfile', 'makefile', 'cmake',
  'ruby', 'rb', 'go', 'golang', 'rust', 'rs', 'perl', 'pl', 'lua', 'swift', 'kotlin',
  'scala', 'r', 'dart', 'elixir', 'erlang', 'haskell', 'diff', 'patch', 'mermaid', 'graphql'
]);

const TOOL_HEAD_TOKENS = new Set((
  'nmap rustscan masscan nxc netexec crackmapexec cme ldapsearch smbclient smbmap rpcclient ' +
  'enum4linux enum4linux-ng gpp-decrypt wpscan kerbrute getnpusers getnpusers.py getuserspns ' +
  'getuserspns.py secretsdump secretsdump.py certipy certipy-ad bloodyad bloodhound ' +
  'bloodhound-python sharphound evil-winrm hashcat john responder ntlmrelayx ntlmrelayx.py ' +
  'getst getst.py gettgt gettgt.py wmiexec wmiexec.py psexec psexec.py smbexec atexec dcomexec ' +
  'lookupsid lookupsid.py rubeus pywhisker sccmhunter sharpsccm impacket-secretsdump ' +
  'impacket-getuserspns impacket-getnpusers impacket-rpcdump rpcdump rpcdump.py ' +
  'impacket-samrdump samrdump samrdump.py impacket-lookupsid impacket-wmiexec impacket-psexec ' +
  'impacket-smbexec impacket-atexec impacket-dcomexec impacket-mssqlclient impacket-getst ' +
  'impacket-gettgt impacket-addcomputer impacket-ntlmrelayx impacket-dacledit ' +
  'impacket-owneredit impacket-finddelegation finddelegation finddelegation.py ' +
  'nikto nuclei feroxbuster ffuf gobuster dirb dirsearch whatweb httpx curl wget sqlmap ' +
  'hydra dig host nslookup fierce dnsrecon dnsenum volatility vol.py git-dumper ike-scan ' +
  'penelope ftp lftp snmpwalk onesixtyone showmount rpcinfo id whoami sudo uname hostname ' +
  'ipconfig ifconfig systeminfo net netstat ss ps find findstr grep awk sed cat type head ' +
  'tail more less ls dir tree chmod chown cp mv rm scp ssh ssh-keygen tar unzip zip base64 ' +
  'certutil powershell pwsh cmd msfvenom msfconsole searchsploit linpeas winpeas pspy ' +
  'chisel ligolo-ng ligolo-proxy ligolo-agent agent socat nc ncat netcat rlwrap ' +
  'mssqlclient mysql psql sqlite3 redis-cli xfreerdp xfreerdp3 rdesktop'
).split(/\s+/));

const EXPLOIT_DB_HEADER_RE = /(?:^\s*(?:#|\/\/|\/\*+|\*|--|;)\s*Exploit\s+Title\s*:|Exploit\s+Database|\bExploit-DB\b|^\s*(?:#|\/\/|\*)\s*CVE\s*:\s*CVE-\d{4}-\d+)/im;

const TERMINAL_CONTENT_SIG_RE = new RegExp([
  'Nmap scan report for',
  'Starting Nmap',
  '^PORT\\s+STATE\\s+SERVICE',
  '^\\d+\\/(?:tcp|udp)\\s+(?:open|filtered|closed)\\s+\\S+',
  '^(?:SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI)\\s+\\d{1,3}(?:\\.\\d{1,3}){3}\\s+\\d+\\s+\\S+\\s+\\[[-*+]\\]',
  '^\\S+:\\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::',
  '\\$krb5(?:tgs|asrep)\\$\\d*\\$',
  '\\buid=\\d+\\([^)]*\\)\\s+gid=\\d+\\(',
  '^HTTP\\/\\d(?:\\.\\d)?\\s+\\d{3}\\b',
  '^\\s*Directory of [A-Za-z]:\\\\',
  '^(?:d|-|l)[rwxstST-]{9}\\s+\\d+\\s+\\S+',
  '\\bNT AUTHORITY\\\\(?:SYSTEM|NETWORK SERVICE|LOCAL SERVICE)\\b',
  '\\bSe(?:Impersonate|AssignPrimaryToken|Backup|Restore|Debug|ManageVolume|TakeOwnership|LoadDriver)Privilege\\b',
  '\\bSPN\\(\\d+\\)\\s*=',
  '\\bServicePrincipalName\\b',
  '\\blistening on \\[any\\] \\d+',
  '\\bconnect to \\[[^\\]]+\\] from\\b',
  '^\\s*\\[\\+\\]\\s+\\S+',
  '^\\s*\\[\\*\\]\\s+\\S+',
  '^\\/[A-Za-z0-9._\\/-]+\\s+\\(Status:\\s*\\d{3}\\)',
  '^[0-9a-fA-F]{32}\\s*$'
].join('|'), 'im');

const STATIC_SOURCE_LOOK_RE = /^(?:\s*(?:import\s+[A-Za-z0-9_.]+|from\s+[A-Za-z0-9_.]+\s+import|def\s+[A-Za-z_]\w*\s*\(|class\s+[A-Za-z_]\w*[\s(:]|function\s+[A-Za-z_]\w*\s*\(|<\?php\b|<!DOCTYPE\s+html|<html\b|#include\s*[<"]|using\s+System;|package\s+[a-z0-9_.]+;))/m;

// 2-line Kali / Parrot prompt top line: ┌──(kali㉿kali)-[~/dir] or ╭──(root@kali)-[/tmp]
const ZSH_TOP_PROMPT_RE = /^\s*[┌╭]──\(([^)㉿@\r\n]+)[㉿@]([^)\r\n]+)\)-(?:\[[^\]]*\])?\s*$/;
const ZSH_BOT_PROMPT_RE = /^\s*[└╰]─\s*([#$%>])\s?(.*)$/;
const ZSH_ONE_LINE_RE = /^\s*[┌╭]──\(([^)㉿@\r\n]+)[㉿@]([^)\r\n]+)\)-(?:\[[^\]]*\])?\s*[└╰]─\s*([#$%>])\s?(.*)$/;

// Non-command comment patterns that must NOT be misread as root `# cmd` prompts
const HASH_PROSE_COMMENT_RE = /^(?:extended LDIF|LDAPv3|base\s*<|filter\s*:|requesting\s*:|search result|search:|result:|numResponses\s*:|numEntries\s*:|Nmap\s+\d|Nmap done at|Password\s*:|Username\s*:|Exploit\s+Title\s*:|Date\s*:|Exploit\s+Author\s*:|Vendor\s+Homepage\s*:|Software\s+Link\s*:|Version\s*:|Tested\s+on\s*:|CVE\s*:|\d+\s+[A-Za-z]+|(?:doctors|users|from|using|shows|file|transfer|create|upload|download|check|note|todo|step|example|output)\b)/i;

const PROMPTS = [
  { kind: 'unix', isZshOneLine: true, re: ZSH_ONE_LINE_RE },
  { kind: 'unix', isZshBotOnly: true, re: ZSH_BOT_PROMPT_RE },
  { kind: 'powershell', hostHint: 'windows', re: /^\s*(?:\*?Evil-WinRM\*?\s*)?PS\s+[A-Za-z]:\\[^\r\n>]*>\s?(.*)$/ },
  { kind: 'powershell', hostHint: 'windows', re: /^\s*(?:\*?Evil-WinRM\*?\s*)?PS\s*>\s?(.*)$/ },
  { kind: 'cmd', hostHint: 'windows', re: /^\s*[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]*\\)*[^\\/:*?"<>|\r\n]*>\s?(.*)$/ },
  { kind: 'unix', isBracketUnix: true, re: /^\s*(?:\([^)\r\n]+\)\s*)?\[([\w.-]+)@([\w.-]+)(?:[:\s][^\]]*)?\]\s*[#$%]\s?(.*)$/ },
  { kind: 'unix', isAtUnix: true, re: /^\s*(?:\([^)\r\n]+\)\s*)?([\w.-]+)@([\w.-]+)(?::[^\s#$%]*)?\s*[#$%](?:\s+(.*)|\s*)$/ },
  { kind: 'unix', re: /^\s*(?:sh|bash|zsh|dash|ksh)-[\d.]+\s*[#$]\s?(.*)$/ },
  { kind: 'ftp', tool: 'ftp', prefix: 'ftp', re: /^\s*ftp>\s*(.*)$/i },
  { kind: 'repl', tool: 'smbclient', prefix: 'smbclient', re: /^\s*smb:\s*\\[^>]*>\s*(.*)$/i },
  { kind: 'repl', tool: 'mysql', prefix: 'mysql', re: /^\s*(?:mysql|MariaDB\s*\[[^\]]*\])\s*>\s*(.*)$/i },
  { kind: 'repl', tool: 'mssql', prefix: 'mssqlclient', re: /^\s*SQL(?:\s*\([^)]*\))?\s*>\s*(.*)$/i },
  { kind: 'repl', tool: 'postgres', prefix: 'psql', re: /^\s*[a-zA-Z_][a-zA-Z0-9_]*=[#>-]\s+(?![{"'\[])(.*)$/ },
  { kind: 'repl', tool: 'sqlite', prefix: 'sqlite3', re: /^\s*sqlite3?>\s*(.*)$/i },
  { kind: 'repl', tool: 'redis', prefix: 'redis-cli', re: /^\s*(?:(?:\d{1,3}\.){3}\d{1,3}|localhost|127\.0\.0\.1|redis)(?::6379)?(?:\[\d+\])?>\s*(.*)$/i },
  { kind: 'repl', tool: 'rpcclient', prefix: 'rpcclient', re: /^\s*rpcclient\s*\$>\s*(.*)$/i },
  { kind: 'meterpreter', tool: 'meterpreter', prefix: 'meterpreter', re: /^\s*meterpreter\s*>\s*(.*)$/i },
  { kind: 'repl', tool: 'metasploit', re: /^\s*msf\d?(?:\s+[a-z]+\([^)]+\))?\s*>\s*(.*)$/i },
  { kind: 'repl', tool: 'mimikatz', prefix: 'mimikatz', re: /^\s*mimikatz\s*#\s*(.*)$/i },
  { kind: 'repl', tool: 'python', re: /^\s*>>>\s+(.*)$/ },
  { kind: 'repl', tool: 'gdb', re: /^\s*(?:gdb-peda\$|\(gdb\)|pwndbg>)\s+(.*)$/ },
  { kind: 'bare', isDollar: true, re: /^\s*\$\s+([A-Za-z0-9_.\/~\\-].*)$/ },
  { kind: 'bare', isHash: true, re: /^\s*#\s+([A-Za-z\/.].*)$/ }
];

function applyPrefix(command, prefix) {
  if (!prefix || !command) return command;
  if (new RegExp('^' + prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i').test(command)) {
    return command;
  }
  return prefix + ' ' + command;
}

function stripAnsi(s) {
  return String(s || '').replace(/\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]/g, '');
}

function matchPromptLine(rawLine, opts) {
  const line = stripAnsi(rawLine);
  for (const p of PROMPTS) {
    const m = line.match(p.re);
    if (!m) continue;
    if (p.isHash) {
      const cand = (m[1] || '').trim();
      if (!opts || !opts.legacyBareHash) {
        if (HASH_PROSE_COMMENT_RE.test(cand)) continue;
      }
    }
    if (p.isZshOneLine) {
      const raw = (m[4] || '').trim();
      return {
        tool: '',
        rawCommand: raw,
        command: raw,
        kind: 'unix',
        user: m[1] || '',
        host: m[2] || '',
        hostHint: m[2] || '',
        promptLine: rawLine
      };
    }
    if (p.isZshBotOnly) {
      const raw = (m[2] || '').trim();
      return {
        tool: '',
        rawCommand: raw,
        command: raw,
        kind: 'unix',
        user: '',
        host: '',
        hostHint: '',
        promptLine: rawLine
      };
    }
    if (p.isBracketUnix || p.isAtUnix) {
      const raw = (m[3] || '').trim();
      return {
        tool: '',
        rawCommand: raw,
        command: raw,
        kind: 'unix',
        user: m[1] || '',
        host: m[2] || '',
        hostHint: m[2] || '',
        promptLine: rawLine
      };
    }
    const raw = (m[m.length - 1] || '').trim();
    return {
      tool: p.tool || '',
      rawCommand: raw,
      command: applyPrefix(raw, p.prefix),
      kind: p.kind,
      user: '',
      host: '',
      hostHint: p.hostHint || '',
      promptLine: rawLine
    };
  }
  return null;
}

function hasShellPrompt(text) {
  const lines = String(text || '').split(/\r?\n/);
  for (let i = 0; i < lines.length && i < 200; i++) {
    if (ZSH_TOP_PROMPT_RE.test(lines[i]) && i + 1 < lines.length && ZSH_BOT_PROMPT_RE.test(lines[i + 1])) {
      return true;
    }
    const mp = matchPromptLine(lines[i]);
    if (mp && mp.rawCommand) return true;
  }
  return false;
}

function isCommandLikeLine(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('/*')) return false;
  let s = trimmed.replace(/^(?:sudo(?:\s+-\S+)*|proxychains4?(?:\s+-\S+)*|time|rlwrap(?:\s+-\S+)*|&)\s+/i, '').trim();
  if (!s) return false;
  const first = s.split(/[\s|;&><]+/)[0].replace(/^["']|["']$/g, '');
  if (!first) return false;
  if (/^(?:\.\/|\.\\|\/usr\/|\/bin\/|\/sbin\/|\/opt\/|[A-Za-z]:\\)/.test(first)) return true;
  if (/^(?:Invoke|Get|Set|New|Import|Start|Stop|Enter|Add|Enable|Disable|Test|Select|Out|ConvertTo|ConvertFrom)-[A-Za-z0-9]+$/i.test(first)) {
    return true;
  }
  const base = first.split(/[\\/]/).pop().toLowerCase();
  const stem = base.replace(/\.(?:py|exe|sh|ps1|pl|rb|bin)$/i, '');
  return TOOL_HEAD_TOKENS.has(base) || TOOL_HEAD_TOKENS.has(stem);
}

function classifyFenceBlock(lang, text) {
  const normLang = String(lang || '').trim().split(/\s+/)[0].toLowerCase();
  const body = String(text || '');
  if (!body.trim()) return { include: false, reason: 'empty' };

  if (normLang && EXPLICIT_TERMINAL_LANGS.has(normLang)) {
    return { include: true, reason: 'terminal-lang', lang: normLang };
  }

  if (normLang && STATIC_CODE_LANGS.has(normLang)) {
    if (EXPLOIT_DB_HEADER_RE.test(body)) {
      return { include: true, reason: 'exploit-db-header', lang: normLang };
    }
    if (hasShellPrompt(body)) {
      return { include: true, reason: 'prompt-inside-code-fence', lang: normLang };
    }
    return { include: false, reason: 'static-code-lang', lang: normLang };
  }

  // Bare fence or unknown tag: classify via ingest.js-aligned prompt/tool/content signatures
  if (hasShellPrompt(body)) return { include: true, reason: 'bare-prompt', lang: normLang };
  if (EXPLOIT_DB_HEADER_RE.test(body)) return { include: true, reason: 'bare-exploit-db', lang: normLang };
  if (TERMINAL_CONTENT_SIG_RE.test(body)) return { include: true, reason: 'bare-content-sig', lang: normLang };

  const nonEmptyLines = body.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const firstActive = nonEmptyLines.find(l => !l.startsWith('#') && !l.startsWith('//'));
  if (firstActive && isCommandLikeLine(firstActive)) {
    return { include: true, reason: 'bare-tool-command', lang: normLang };
  }
  if (STATIC_SOURCE_LOOK_RE.test(body)) {
    return { include: false, reason: 'bare-static-source', lang: normLang };
  }
  return { include: false, reason: 'bare-unrecognized', lang: normLang };
}

function cleanProse(s) {
  return String(s || '')
    .replace(/!\[[^\]]*\]\((?:data:[^)]*|[^)]*)\)/g, ' ')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/[`*#>]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function buildLineIndex(md) {
  const starts = [0];
  for (let i = 0; i < md.length; i++) {
    if (md.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

function lineNumberAt(lineStarts, offset) {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (lineStarts[mid] <= offset) lo = mid + 1;
    else hi = mid - 1;
  }
  return Math.max(1, lo);
}

function extractHeadings(md, lineStarts) {
  const headings = [];
  const lines = md.split(/\r?\n/);
  let inFence = null;
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    const fm = ln.match(/^[ \t]{0,3}(`{3,}|~{3,})/);
    if (fm) {
      const ch = fm[1][0];
      if (!inFence) inFence = { ch: ch, len: fm[1].length };
      else if (inFence.ch === ch && fm[1].length >= inFence.len && /^[ \t]{0,3}(?:`{3,}|~{3,})[ \t]*$/.test(ln)) inFence = null;
      continue;
    }
    if (inFence) continue;
    const hm = ln.match(/^[ \t]{0,3}(#{1,6})[ \t]+(.+?)[ \t]*#*$/);
    if (hm) {
      headings.push({
        line: i + 1,
        level: hm[1].length,
        text: hm[2].trim(),
        offset: lineStarts[i] || 0
      });
    }
  }
  return headings;
}

function headingAtLine(headings, lineNum) {
  let cur = '';
  for (let i = 0; i < headings.length; i++) {
    if (headings[i].line <= lineNum) cur = headings[i].text;
    else break;
  }
  return cur;
}

const HTML_DIV_BLOCK_RE = /<div class="language-([a-zA-Z0-9_+-]+)[^"]*">\s*(?:<div class="highlight">\s*)?```[^\r\n]*\r?\n([\s\S]*?)\r?\n```(?:\s*<\/div>)*/g;

function findCommonMarkBlocksOutsideSpans(md, excludedSpans) {
  const blocks = [];
  const lineStarts = buildLineIndex(md);
  const lines = md.split(/\r?\n/);

  function isExcludedOffset(off) {
    for (let i = 0; i < excludedSpans.length; i++) {
      if (off >= excludedSpans[i].start && off < excludedSpans[i].end) return true;
    }
    return false;
  }

  let open = null;
  for (let i = 0; i < lines.length; i++) {
    const off = lineStarts[i];
    if (!open && isExcludedOffset(off)) continue;
    const ln = lines[i];
    if (!open) {
      const m = ln.match(/^[ \t]{0,3}(`{3,}|~{3,})([^\r\n]*)$/);
      if (m) {
        const fence = m[1];
        const info = (m[2] || '').trim();
        if (fence[0] === '`' && info.indexOf('`') >= 0) continue;
        open = {
          fenceChar: fence[0],
          fenceLen: fence.length,
          lang: info.split(/\s+/)[0] || '',
          startOffset: off,
          startLineIdx: i,
          contentStartOffset: i + 1 < lineStarts.length ? lineStarts[i + 1] : md.length
        };
      }
    } else {
      const closeRe = new RegExp('^[ \\t]{0,3}' + open.fenceChar + '{' + open.fenceLen + ',}[ \\t]*$');
      if (closeRe.test(ln)) {
        const bodyLines = lines.slice(open.startLineIdx + 1, i);
        const endOffset = off + ln.length;
        blocks.push({
          lang: open.lang.toLowerCase(),
          text: bodyLines.join('\n'),
          start: open.startOffset,
          end: endOffset,
          contentLineStart: open.startLineIdx + 2,
          sourceFormat: 'commonmark'
        });
        open = null;
      }
    }
  }
  return blocks;
}

function extractBlocks(md, opts) {
  opts = opts || {};
  const src = String(md || '');
  const lineStarts = buildLineIndex(src);
  const headings = extractHeadings(src, lineStarts);

  const htmlBlocks = [];
  HTML_DIV_BLOCK_RE.lastIndex = 0;
  let m;
  while ((m = HTML_DIV_BLOCK_RE.exec(src)) !== null) {
    const innerOffset = src.indexOf('```', m.index);
    const firstNewline = innerOffset >= 0 ? src.indexOf('\n', innerOffset) : -1;
    const contentLineStart = firstNewline >= 0
      ? lineNumberAt(lineStarts, firstNewline + 1)
      : lineNumberAt(lineStarts, m.index);
    htmlBlocks.push({
      lang: String(m[1] || '').toLowerCase(),
      text: m[2].replace(/\r\n/g, '\n'),
      start: m.index,
      end: HTML_DIV_BLOCK_RE.lastIndex,
      contentLineStart: contentLineStart,
      sourceFormat: 'html-div'
    });
  }

  const cmBlocks = opts.htmlOnly ? [] : findCommonMarkBlocksOutsideSpans(src, htmlBlocks);
  const allBlocks = htmlBlocks.concat(cmBlocks).sort((a, b) => a.start - b.start);

  const legacy0xdfLangsOnly = !!opts.legacyTerminalLangsOnly;
  const legacySet = new Set(['console', 'shell', 'bash', 'sh', 'terminal']);

  const out = [];
  for (let i = 0; i < allBlocks.length; i++) {
    const b = allBlocks[i];
    let keep = false;
    let classification = null;
    if (legacy0xdfLangsOnly) {
      keep = legacySet.has(b.lang);
      classification = { include: keep, reason: keep ? 'legacy-terminal-lang' : 'excluded', lang: b.lang };
    } else if (b.sourceFormat === 'html-div' && legacySet.has(b.lang)) {
      keep = true;
      classification = { include: true, reason: 'html-terminal-lang', lang: b.lang };
    } else {
      classification = classifyFenceBlock(b.lang, b.text);
      keep = classification.include;
    }
    if (!keep) continue;

    const lineStart = lineNumberAt(lineStarts, b.start);
    const lineEnd = lineNumberAt(lineStarts, Math.max(b.start, b.end - 1));
    const leadStart = i > 0 ? allBlocks[i - 1].end : Math.max(0, b.start - 1200);
    const followEnd = i < allBlocks.length - 1 ? allBlocks[i + 1].start : Math.min(src.length, b.end + 1200);

    out.push({
      lang: b.lang,
      sourceFormat: b.sourceFormat,
      classificationReason: classification.reason,
      text: b.text,
      start: b.start,
      end: b.end,
      lineStart: lineStart,
      contentLineStart: b.contentLineStart || lineStart,
      lineEnd: lineEnd,
      heading: headingAtLine(headings, lineStart),
      lead: cleanProse(src.slice(leadStart, b.start)).slice(-500),
      follow: cleanProse(src.slice(b.end, followEnd)).slice(0, 500)
    });
  }
  return out;
}

function inferContentCommandHint(text) {
  const s = String(text || '');
  if (/Nmap scan report for|Starting Nmap|^PORT\s+STATE\s+SERVICE/im.test(s)) return 'nmap';
  const nxcM = /^(SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+\s+\[[-*+]\]/m.exec(s);
  if (nxcM) return 'nxc ' + nxcM[1].toLowerCase();
  if (/^\S+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::/m.test(s)) return 'secretsdump';
  if (/\$krb5tgs\$/i.test(s)) return 'GetUserSPNs.py';
  if (/\$krb5asrep\$/i.test(s)) return 'GetNPUsers.py';
  if (EXPLOIT_DB_HEADER_RE.test(s)) return 'searchsploit';
  return '';
}

function segmentBlock(blockOrText, opts) {
  opts = opts || {};
  const isObj = blockOrText && typeof blockOrText === 'object';
  const text = String(isObj ? blockOrText.text : (blockOrText || '')).replace(/\r\n/g, '\n');
  const baseLine = isObj ? (blockOrText.contentLineStart || blockOrText.lineStart || 1) : (opts.lineStart || 1);
  const heading = isObj ? (blockOrText.heading || '') : (opts.heading || '');
  const lang = isObj ? String(blockOrText.lang || '').toLowerCase() : String(opts.lang || '').toLowerCase();
  const includeUnprompted = opts.includeUnprompted !== false;

  const lines = text.split('\n');
  const rawUnits = [];
  let cur = null;
  let sawPrompt = false;

  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];

    // Check 2-line Kali / Parrot zsh prompt (┌──(user㉿host)-[cwd] followed by └─$ cmd)
    const topM = ln.match(ZSH_TOP_PROMPT_RE);
    if (topM && i + 1 < lines.length) {
      const botM = lines[i + 1].match(ZSH_BOT_PROMPT_RE);
      if (botM) {
        sawPrompt = true;
        if (cur) rawUnits.push(cur);
        const rawCmd = (botM[2] || '').trim();
        cur = {
          promptLine: ln + '\n' + lines[i + 1],
          tool: '',
          rawCommand: rawCmd,
          command: rawCmd,
          kind: 'unix',
          user: topM[1] || '',
          host: topM[2] || '',
          hostHint: topM[2] || '',
          lineStart: baseLine + i,
          heading: heading,
          outLines: []
        };
        i++; // consume bottom prompt line
        continue;
      }
    }

    const p = matchPromptLine(ln, opts);
    if (p) {
      sawPrompt = true;
      if (cur) rawUnits.push(cur);
      // Skip trailing empty prompt at the very end of a block if rawCommand === ''
      if (!p.rawCommand && i === lines.length - 1) {
        cur = null;
        continue;
      }
      cur = {
        promptLine: p.promptLine,
        tool: p.tool,
        rawCommand: p.rawCommand,
        command: p.command,
        kind: p.kind,
        user: p.user || '',
        host: p.host || '',
        hostHint: p.hostHint || p.host || '',
        lineStart: baseLine + i,
        heading: heading,
        outLines: []
      };
    } else if (cur) {
      cur.outLines.push(ln);
    }
  }
  if (cur) rawUnits.push(cur);

  if (!sawPrompt && includeUnprompted) {
    // Handle unprompted CommonMark blocks (command-first or raw stdout paste)
    let firstIdx = -1;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (!t || (t.startsWith('#') && !EXPLOIT_DB_HEADER_RE.test(t))) continue;
      firstIdx = i;
      break;
    }

    if (firstIdx >= 0) {
      const firstLine = lines[firstIdx].trim();
      const shellTagged = /^(?:bash|sh|shell|zsh|console|terminal|powershell|ps1|pwsh|cmd|dos|bat|batch)$/.test(lang);
      if (isCommandLikeLine(firstLine) || (shellTagged && !TERMINAL_CONTENT_SIG_RE.test(firstLine) && !EXPLOIT_DB_HEADER_RE.test(text))) {
        // Check if block is multiple standalone command lines (e.g. a 2-line command snippet with no stdout)
        const restLines = lines.slice(firstIdx + 1);
        const nonCommentRest = restLines.filter(l => l.trim() && !l.trim().startsWith('#'));
        const allCommands = shellTagged && nonCommentRest.length > 0 && nonCommentRest.length <= 6
          && nonCommentRest.every(l => isCommandLikeLine(l));

        if (allCommands) {
          for (let i = firstIdx; i < lines.length; i++) {
            const t = lines[i].trim();
            if (!t || t.startsWith('#')) continue;
            rawUnits.push({
              promptLine: '',
              tool: '',
              rawCommand: t,
              command: t,
              kind: /^(?:powershell|ps1|pwsh)$/.test(lang) ? 'powershell' : (/^(?:cmd|dos|bat|batch)$/.test(lang) ? 'cmd' : 'unprompted'),
              user: '',
              host: '',
              hostHint: /^(?:powershell|ps1|pwsh|cmd|dos|bat|batch)$/.test(lang) ? 'windows' : '',
              lineStart: baseLine + i,
              heading: heading,
              outLines: []
            });
          }
        } else {
          rawUnits.push({
            promptLine: '',
            tool: '',
            rawCommand: firstLine,
            command: firstLine,
            kind: /^(?:powershell|ps1|pwsh)$/.test(lang) ? 'powershell' : (/^(?:cmd|dos|bat|batch)$/.test(lang) ? 'cmd' : 'unprompted'),
            user: '',
            host: '',
            hostHint: /^(?:powershell|ps1|pwsh|cmd|dos|bat|batch)$/.test(lang) ? 'windows' : '',
            lineStart: baseLine + firstIdx,
            heading: heading,
            outLines: restLines
          });
        }
      } else {
        const inferredCmd = inferContentCommandHint(text);
        rawUnits.push({
          promptLine: '',
          tool: inferredCmd.split(/\s+/)[0] || '',
          rawCommand: '',
          command: inferredCmd,
          kind: 'unprompted',
          user: '',
          host: '',
          hostHint: '',
          lineStart: baseLine,
          heading: heading,
          outLines: lines
        });
      }
    }
  }

  const units = rawUnits
    .filter(u => u.rawCommand || u.command || u.outLines.some(l => l.trim()))
    .map(u => {
      const stdout = u.outLines.join('\n');
      return {
        source: 'markdown',
        fidelity: 'text',
        promptLine: u.promptLine || '',
        tool: u.tool || '',
        rawCommand: u.rawCommand != null ? u.rawCommand : u.command,
        command: u.command || '',
        stdout: stdout,
        output: stdout,
        kind: u.kind || 'unix',
        user: u.user || '',
        host: u.host || '',
        hostHint: u.hostHint || u.host || '',
        lineStart: u.lineStart || baseLine,
        heading: u.heading || heading
      };
    });

  return {
    units: units,
    hadPrompt: sawPrompt
  };
}

function loadOcrSidecar(corpusDir, slug) {
  if (!corpusDir || !slug) return [];
  const cleanSlug = String(slug).replace(/\.md$/i, '');
  const candidates = [
    path.join(corpusDir, 'ocr-sidecars', cleanSlug + '.json'),
    path.join(corpusDir, '..', 'ocr-sidecars', cleanSlug + '.json')
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
      return Array.isArray(parsed) ? parsed : (Array.isArray(parsed && parsed.entries) ? parsed.entries : []);
    }
  }
  return [];
}

function normalizeOcrSidecarEntries(entries, headings) {
  if (!Array.isArray(entries)) return [];
  return entries.map((entry, idx) => {
    const line = typeof entry.line === 'number' && entry.line > 0 ? Math.floor(entry.line) : 1;
    const cmd = String(entry.reconstructed_command != null ? entry.reconstructed_command : (entry.command || '')).trim();
    const out = String(
      entry.transcribed_output != null
        ? entry.transcribed_output
        : (entry.stdout != null ? entry.stdout : (entry.output || ''))
    );
    const h = entry.heading || (headings ? headingAtLine(headings, line) : '') || '';
    return {
      source: 'ocr-sidecar',
      fidelity: entry.fidelity || 'ocr',
      ocrIndex: idx,
      ocrKind: entry.kind || 'screenshot',
      visualObservation: entry.visual_observation || '',
      promptLine: entry.prompt_line || '',
      tool: '',
      rawCommand: cmd,
      command: cmd,
      stdout: out,
      output: out,
      kind: entry.kind || 'ocr',
      user: '',
      host: '',
      hostHint: entry.host_hint || '',
      lineStart: line,
      heading: h
    };
  });
}

function extractWalkthroughTurns(md, opts) {
  opts = opts || {};
  const src = String(md || '');
  const lineStarts = buildLineIndex(src);
  const headings = extractHeadings(src, lineStarts);
  const blocks = extractBlocks(src, opts);

  const mdTurns = [];
  for (let bIdx = 0; bIdx < blocks.length; bIdx++) {
    const block = blocks[bIdx];
    const seg = segmentBlock(block, opts);
    for (let uIdx = 0; uIdx < seg.units.length; uIdx++) {
      const u = seg.units[uIdx];
      mdTurns.push(Object.assign({}, u, {
        blockIndex: bIdx,
        turnInBlock: uIdx,
        hadPrompt: seg.hadPrompt,
        blockLang: block.lang,
        sourceFormat: block.sourceFormat,
        lead: block.lead,
        follow: block.follow,
        _orderTie: mdTurns.length
      }));
    }
  }

  let sidecarRaw = [];
  if (Array.isArray(opts.ocrSidecar)) {
    sidecarRaw = opts.ocrSidecar;
  } else if (Array.isArray(opts.ocrEntries)) {
    sidecarRaw = opts.ocrEntries;
  } else if (opts.ocrSidecarPath && fs.existsSync(opts.ocrSidecarPath)) {
    const parsed = JSON.parse(fs.readFileSync(opts.ocrSidecarPath, 'utf8'));
    sidecarRaw = Array.isArray(parsed) ? parsed : (Array.isArray(parsed && parsed.entries) ? parsed.entries : []);
  } else if (opts.corpusDir && opts.slug) {
    sidecarRaw = loadOcrSidecar(opts.corpusDir, opts.slug);
  }

  const ocrTurns = normalizeOcrSidecarEntries(sidecarRaw, headings).map((t, idx) => Object.assign({}, t, {
    blockIndex: -1,
    turnInBlock: idx,
    hadPrompt: Boolean(t.promptLine),
    blockLang: 'ocr',
    sourceFormat: 'ocr-sidecar',
    lead: t.visualObservation || '',
    follow: '',
    _orderTie: 1000000 + idx
  }));

  const combined = mdTurns.concat(ocrTurns).sort((a, b) => {
    if (a.lineStart !== b.lineStart) return a.lineStart - b.lineStart;
    // If an OCR image is on the exact same line, keep deterministic order
    return a._orderTie - b._orderTie;
  });

  combined.forEach((t, idx) => {
    delete t._orderTie;
    t.turnIndex = idx;
  });

  return {
    blocks: blocks,
    turns: combined,
    ocrSplicedCount: ocrTurns.length,
    ocrCount: ocrTurns.length
  };
}

function discoverAlternates(corpusDir, slug) {
  if (!corpusDir || !slug) return [];
  const cleanSlug = String(slug).replace(/\.md$/i, '').toLowerCase();
  const altDirs = [
    path.join(corpusDir, 'alternates'),
    path.join(corpusDir, '..', 'alternates')
  ];
  const seen = new Set();
  const out = [];
  for (const dir of altDirs) {
    if (!fs.existsSync(dir)) continue;
    let entries = [];
    try { entries = fs.readdirSync(dir); } catch (_e) { continue; }
    for (const file of entries) {
      if (!file.toLowerCase().endsWith('.md')) continue;
      const stem = file.slice(0, -3);
      const sepIdx = stem.indexOf('--');
      if (sepIdx <= 0) continue;
      const fileSlug = stem.slice(0, sepIdx).toLowerCase();
      if (fileSlug !== cleanSlug) continue;
      const fullPath = path.resolve(dir, file);
      if (seen.has(fullPath)) continue;
      seen.add(fullPath);
      out.push({
        slug: stem.slice(0, sepIdx),
        author: stem.slice(sepIdx + 2),
        file: file,
        path: fullPath
      });
    }
  }
  out.sort((a, b) => a.file.localeCompare(b.file));
  return out;
}

// ---- Shared Tool & Signal-Axis Classifiers (single source of truth for harvesters) ----
const TOOLS = [
  [/\bnmap\b/i, 'nmap'], [/\bgobuster\b/i, 'gobuster'], [/\bferoxbuster\b/i, 'feroxbuster'],
  [/\bffuf\b/i, 'ffuf'], [/\bdirb\b|\bdirbuster\b|\bdirsearch\b/i, 'dirb'], [/\bwfuzz\b/i, 'wfuzz'],
  [/\b(nxc|netexec|crackmapexec|cme)\b/i, 'netexec/cme'], [/\bsmbclient\b/i, 'smbclient'],
  [/\bsmbmap\b/i, 'smbmap'], [/\brpcclient\b/i, 'rpcclient'], [/\benum4linux(?:-ng)?\b/i, 'enum4linux'],
  [/\bsecretsdump\b/i, 'secretsdump'], [/getuserspns|GetUserSPNs/i, 'GetUserSPNs'],
  [/getnpusers|GetNPUsers/i, 'GetNPUsers'], [/\bevil-winrm\b/i, 'evil-winrm'],
  [/\bbloodhound\b|\bsharphound\b|bloodhound-python/i, 'bloodhound'], [/\bbloodyad\b/i, 'bloodyad'],
  [/\brubeus\b/i, 'rubeus'], [/\bkerbrute\b/i, 'kerbrute'],
  [/\bhashcat(?:\.bin|\.exe)?\b/i, 'hashcat'], [/\bjohn\b/i, 'john'], [/\bhydra\b/i, 'hydra'],
  [/\bsqlmap\b/i, 'sqlmap'], [/\bnikto\b/i, 'nikto'], [/\bwpscan\b/i, 'wpscan'],
  [/\bsearchsploit\b/i, 'searchsploit'],
  [/\bcurl\b/i, 'curl'], [/\bwget\b/i, 'wget'], [/\b(nc|netcat|ncat)\b/i, 'netcat'],
  [/\bssh\b/i, 'ssh'], [/\bftp\b/i, 'ftp'], [/\b(mysql|mariadb)\b/i, 'mysql'],
  [/\b(psql|postgres)\b/i, 'postgres'], [/\b(mssqlclient|impacket-mssqlclient)\b/i, 'mssql'],
  [/\bsqlite3?\b/i, 'sqlite'], [/\bredis-cli\b/i, 'redis'],
  [/\blinpeas\b/i, 'linpeas'], [/\bwinpeas\b/i, 'winpeas'], [/\bpspy\b/i, 'pspy'],
  [/\bsudo\s+(?:-[A-Za-z]*l\b|--list\b)/i, 'sudo-l'], [/\bcertipy(?:-ad)?\b/i, 'certipy'], [/\bldapsearch\b/i, 'ldapsearch'],
  [/\b(dig|nslookup|dnsrecon|dnsenum|host)\b/i, 'dns']
];

const WRAPPER_PREFIX_RE = /^(?:\s*(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s]+)|sudo(?:\s+-(?:u\s+\S+|E|i|s|H|n))?(?!\s+(?:-[A-Za-z]*l\b|--list\b))|proxychains4?(?:\s+-q|\s+-f\s+\S+)?|time|timeout\s+\S+|stdbuf(?:\s+-[ioe]\S+)+|nice(?:\s+-n\s+\S+)?|rlwrap(?:\s+-\S+)*|python[23]?(?:\.\d+)?(?:\s+-m)?|uv\s+run|pipx\s+run|mono|wine|ruby|perl|php|(?:ba)?sh\s+-c|cmd(?:\.exe)?\s+\/[cC]|powershell(?:\.exe)?(?:\s+-(?:c|command|enc|ep\s+\S+|nop|w\s+\S+))*|&)\s+)+/i;
const SHELL_WRAPPER_BINS = new Set(['for', 'while', 'if', 'xargs', 'watch', 'parallel', 'eval', 'exec']);

function detectTool(u) {
  if (u && u.tool) return u.tool;
  const hay = ((u && u.command) || '').trim();
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
    for (const [re, name] of TOOLS) {
      if (re.test(hay)) return name;
    }
  }
  return 'other';
}

const FACT_BEARING = new Set([
  'nmap', 'gobuster', 'feroxbuster', 'ffuf', 'dirb', 'wfuzz',
  'netexec/cme', 'smbclient', 'smbmap', 'rpcclient', 'enum4linux', 'secretsdump',
  'GetUserSPNs', 'GetNPUsers', 'bloodhound', 'bloodyad', 'rubeus', 'kerbrute',
  'hashcat', 'john', 'hydra', 'sqlmap', 'nikto', 'wpscan', 'searchsploit',
  'certipy', 'ldapsearch', 'dns', 'mysql', 'postgres', 'mssql', 'sqlite', 'redis',
  'linpeas', 'winpeas', 'pspy', 'curl', 'sudo-l'
]);

const FILE_READ = /\b(cat|type|more|less|head|tail|strings)\b|\bget-content\b|\bgc\b/i;
const LISTING = /\b(ls|dir|tree|find)\b|\bget-childitem\b|\bgci\b/i;
const TRANSFER = /\b(wget|curl|scp|certutil|tftp|smbget)\b|\biwr\b|\binvoke-webrequest\b/i;
const SHELL_LAUNCH = /\bevil-winrm\b|\bpsexec(\.py)?\b|\bwmiexec(\.py)?\b|\bsmbexec(\.py)?\b|\batexec(\.py)?\b|\bssh\b|\bxfreerdp\b|pty\.spawn|\/bin\/(ba)?sh\b|\bsu\b|\bsudo\s+-i\b|nc .*-e|runas/i;
const IDENTITY = /\b(whoami|id|hostname|systeminfo)\b|\bnet user\b|\bnet localgroup\b|\bgetuid\b/i;
const ENUM_CMD = /\b(nmap|gobuster|feroxbuster|ffuf|dirb|dirsearch|wfuzz|nxc|netexec|crackmapexec|cme|smbmap|enum4linux|secretsdump|kerbrute|hashcat|john|hydra|sqlmap|nikto|wpscan|searchsploit|ldapsearch|certipy|bloodhound|bloodyad|rubeus|dig|nslookup)\b/i;
const NONE_CMD = /^\s*(cd|pwd|clear|export|set|echo|which|cls|exit)\b/i;

function classifyAxis(u, toolLabel) {
  const c = (u && u.command) || '';
  const host = (u && (u.host || u.hostHint)) || '';
  const onHostPrompt = u.kind === 'powershell' || u.kind === 'cmd' || u.kind === 'meterpreter'
    || (u.kind === 'unix' && host && host !== 'windows' && !ATTACKER_HOST.test(host));
  if (FILE_READ.test(c)) return 'loot';
  if (TRANSFER.test(c)) return 'outcome';
  if (SHELL_LAUNCH.test(c)) return 'state-change';
  if (IDENTITY.test(c) && (onHostPrompt || !host)) return 'state-change';
  if (ENUM_CMD.test(c) || FACT_BEARING.has(toolLabel)) return 'enumeration';
  if (LISTING.test(c)) return 'loot';
  if (onHostPrompt) return 'state-change';
  if (NONE_CMD.test(c)) return 'none';
  return 'other';
}

function outputHead(out) {
  return String(out || '').split('\n').filter(l => l.trim()).slice(0, 6).join('\n');
}

function blockId(file, command, out) {
  return crypto.createHash('sha1').update(file + '\u0000' + command + '\u0000' + outputHead(out)).digest('hex').slice(0, 12);
}

function resolveCorpusWalkthroughsDir(corpusDir) {
  const resolved = path.resolve(corpusDir);
  if (fs.existsSync(path.join(resolved, 'walkthroughs')) && fs.statSync(path.join(resolved, 'walkthroughs')).isDirectory()) {
    return { corpusRoot: resolved, walkthroughsDir: path.join(resolved, 'walkthroughs') };
  }
  if (path.basename(resolved).toLowerCase() === 'walkthroughs') {
    return { corpusRoot: path.dirname(resolved), walkthroughsDir: resolved };
  }
  return { corpusRoot: resolved, walkthroughsDir: resolved };
}

module.exports = {
  ATTACKER_HOST: ATTACKER_HOST,
  EXPLICIT_TERMINAL_LANGS: EXPLICIT_TERMINAL_LANGS,
  STATIC_CODE_LANGS: STATIC_CODE_LANGS,
  FACT_BEARING: FACT_BEARING,
  cleanProse: cleanProse,
  classifyFenceBlock: classifyFenceBlock,
  hasShellPrompt: hasShellPrompt,
  isCommandLikeLine: isCommandLikeLine,
  matchPromptLine: matchPromptLine,
  extractBlocks: extractBlocks,
  segmentBlock: segmentBlock,
  loadOcrSidecar: loadOcrSidecar,
  extractWalkthroughTurns: extractWalkthroughTurns,
  discoverAlternates: discoverAlternates,
  detectTool: detectTool,
  classifyAxis: classifyAxis,
  outputHead: outputHead,
  blockId: blockId,
  resolveCorpusWalkthroughsDir: resolveCorpusWalkthroughsDir
};
