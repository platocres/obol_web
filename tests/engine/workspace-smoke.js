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

// the real AD pack's nmap discovery action now writes native output into {{scandir}}
const PACKS_DIR = require('path').join(__dirname, '..', '..', 'data', 'packs');
const ad = JSON.parse(require('fs').readFileSync(require('path').join(PACKS_DIR, 'ad_2026_09.json'), 'utf8'));
const nmapAct = ad.actions.find((a) => a.id === 'nmap-fast-open-ports');
ok(nmapAct && (nmapAct.commands || []).every((c) => /-oN \{\{scandir\}\}\//.test(c.run)), 'nmap discovery commands write -oN into {{scandir}}');

console.log(fail ? ('\nWORKSPACE SMOKE: ' + fail + ' FAILURES') : '\nWORKSPACE SMOKE: all passed');
process.exit(fail ? 1 : 0);
