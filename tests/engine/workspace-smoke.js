/* Node sanity test for the workspace directory model (engine/workspace.js) and its command tokens. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
const OBOL = globalThis.OBOL;
const W = OBOL.workspace, C = OBOL.command;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// default root: box-centric on labs (uses the target), engagement-centric on exams (uses the name)
ok(W.defaultRoot('~/htb', { name: 'Lab night', targets: [{ hostname: 'boxy', ip: '10.0.0.5' }] }, false) === '~/htb/boxy',
  'lab default root is box-centric (target hostname)');
ok(W.defaultRoot('~/exams', { name: 'OSCP Prep', targets: [{ ip: '10.0.0.9' }] }, true) === '~/exams/oscp-prep',
  'exam default root is engagement-centric (slugified name)');
ok(W.defaultRoot('~/htb', { name: 'n', targets: [{ ip: '10.0.0.5' }] }, false) === '~/htb/10.0.0.5',
  'lab default root falls back to the target IP when no hostname');

const eng = { name: 'x', workspace: { root: '/home/kali/ctf/boxy' } };
const t = W.tokens(eng);
ok(t.scandir === '/home/kali/ctf/boxy/scans' && t.lootdir === '/home/kali/ctf/boxy/loot' && t.proofdir === '/home/kali/ctf/boxy/proof',
  'tokens resolve to absolute output dirs under the root');
ok(W.scaffold(eng) === 'mkdir -p /home/kali/ctf/boxy/{scans,loot,exploit,www,proof} && cd /home/kali/ctf/boxy',
  'scaffold builds a one-line mkdir + cd');
ok(W.isConfigured(eng) === true && W.isConfigured({ name: 'y' }) === false, 'isConfigured tracks whether a root is set');

// sanitizeRoot: shell metacharacters in a typed/pasted working directory never reach a command
ok(W.sanitizeRoot('~/CTF/HTB/boxes/Windows/forest]') === '~/CTF/HTB/boxes/Windows/forest', 'a stray ] in the workdir is stripped');
ok(W.sanitizeRoot('~/lab; rm -rf ~').indexOf(';') === -1 && W.sanitizeRoot('~/lab; rm -rf ~').indexOf(' ') === -1, 'shell-injection chars + spaces are stripped from the workdir');
ok(W.sanitizeRoot('~/box $(whoami)/`id`').indexOf('$') === -1 && W.sanitizeRoot('~/box $(whoami)/`id`').indexOf('`') === -1, 'command-substitution characters are stripped');
ok(W.sanitizeRoot('~/ok_dir-1.2/proof') === '~/ok_dir-1.2/proof', 'ordinary POSIX path characters are preserved');
// a root saved with junk auto-heals when read (an existing broken engagement fixes itself)
ok(W.rootFor({ workspace: { root: '~/a]/b' } }) === '~/a/b' && W.tokens({ workspace: { root: '~/a]/b' } }).scandir === '~/a/b/scans',
  'a previously-saved unsafe root is sanitized on read (auto-heal)');

// command fill: {{scandir}} resolves from opts.workspace; falls back to a relative dir with none
const nmap = { commands: [{ tool: 'nmap', run: 'nmap -oN {{scandir}}/nmap.txt {{target}}' }] };
const withWs = C.fillCommand(nmap, new OBOL.facts.FactSet([]), { params: { target: '10.0.0.5' }, workspace: t }, 0);
ok(withWs.filled === 'nmap -oN /home/kali/ctf/boxy/scans/nmap.txt 10.0.0.5', 'command writes into the absolute scans/ dir with a workspace');
const noWs = C.fillCommand(nmap, new OBOL.facts.FactSet([]), { params: { target: '10.0.0.5' } }, 0);
ok(noWs.filled === 'nmap -oN scans/nmap.txt 10.0.0.5', 'command still forms with a relative scans/ dir when no workspace is set');

// the non-destructive zsh prompt-stamp tweak: it must be a real precmd hook, and CRUCIALLY the line it
// prints must be one obol's own ingest can read back (the [UTC time] and [dev:IP] the splitter/LHOST
// detector key on). We simulate the line the snippet would emit and round-trip it through ingest.
const stamp = W.PROMPT_STAMP_ZSH;
ok(/precmd_functions\+=\(/.test(stamp), 'prompt-stamp appends a precmd hook (non-destructive — keeps the operator prompt)');
ok(/date -u/.test(stamp) && /tun\|tap\|wg/.test(stamp), 'prompt-stamp prints a UTC time and auto-detects the VPN device');
require('../../assets/ui/ingest.js'); // IIFE — attaches OBOL.ingest to globalThis.OBOL
const ing = OBOL.ingest;
const emitted = '[2026-09-27 17:17:38 UTC] [tun0:10.10.14.191]';
ok(ing.detectLhost(emitted) === '10.10.14.191', 'the stamp line the snippet emits yields the operator LHOST');
const seg = ing.splitSession(emitted + '\n┌──(kali㉿kali)-[~]\n└─$ id\nuid=0(root)');
ok(seg.length === 1 && seg[0].command === 'id' && seg[0].ts === Date.parse('2026-09-27T17:17:38Z'),
  'the stamp line the snippet emits is picked up as the timestamp for the command below it');
ok(typeof W.captureCmd({ workspace: { root: '/h/k/box' } }) === 'string' && /^script /.test(W.captureCmd({ workspace: { root: '/h/k/box' } })),
  'captureCmd offers a `script` session-recording command');

// the prompt stamp pins to a configured interface (reading that adapter directly, labelling with its name)
const pinned = W.promptStamp('eth0');
ok(/ip -4 -o addr show eth0\b/.test(pinned) && /\[eth0:\$ip\]/.test(pinned), 'promptStamp(iface) pins to the operator\'s configured interface');
ok(W.promptStamp('') === W.PROMPT_STAMP_ZSH, 'promptStamp() with no interface falls back to auto-detect');
ok(W.promptStamp('tun0; rm -rf ~') === W.PROMPT_STAMP_ZSH, 'a junk interface value is rejected (no shell injection into the snippet)');
// the pinned stamp's emitted line must round-trip through ingest.detectLhost (obol reads back its own snippet)
ok(ing.detectLhost('[2026-09-27 17:17:38 UTC] [eth0:10.0.2.15]') === '10.0.2.15', 'a pinned-interface stamp line is still read back as the operator LHOST');

// {{iface}} command token: pinned from the engagement interface, else defaults to tun0
const resp = { commands: [{ tool: 'responder', run: 'sudo responder -I {{iface}} -wv' }] };
ok(C.fillCommand(resp, new OBOL.facts.FactSet([]), { params: { lhost_iface: 'eth0' } }, 0).filled === 'sudo responder -I eth0 -wv',
  '{{iface}} fills from the engagement\'s configured interface');
ok(C.fillCommand(resp, new OBOL.facts.FactSet([]), { params: {} }, 0).filled === 'sudo responder -I tun0 -wv',
  '{{iface}} defaults to tun0 when no interface is configured (matches the old hardcoded value)');

// the real AD pack's nmap discovery action now writes native output into {{scandir}}
const PACKS_DIR = require('path').join(__dirname, '..', '..', 'data', 'packs');
const ad = JSON.parse(require('fs').readFileSync(require('path').join(PACKS_DIR, 'ad_2026_09.json'), 'utf8'));
const nmapAct = ad.actions.find((a) => a.id === 'nmap-fast-open-ports');
ok(nmapAct && (nmapAct.commands || []).every((c) => /-oN \{\{scandir\}\}\//.test(c.run)), 'nmap discovery commands write -oN into {{scandir}}');

console.log(fail ? ('\nWORKSPACE SMOKE: ' + fail + ' FAILURES') : '\nWORKSPACE SMOKE: all passed');
process.exit(fail ? 1 : 0);
