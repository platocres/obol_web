/* Loadout command-rewrite (OBOL.command.applyArsenal): once a box is synced, filled commands adopt the
 * operator's real tool invocations + wordlist paths. Conservative + reversible - only a recognized ARSENAL
 * variant as a standalone token is swapped; un-synced or unknown is left exactly as authored. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
require('../../data/tools-install.js');
require('../../assets/engine/arsenal.js');
require('../../assets/ui/ingest.js');
const OBOL = globalThis.OBOL, C = OBOL.command, F = OBOL.facts;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

const prof = {
  tools: {
    'impacket-psexec': { present: true, invocation: 'psexec.py' },
    'impacket-getst': { present: true, invocation: 'getST.py' },
    nxc: { present: true, invocation: 'netexec' },
    certipy: { present: true, invocation: 'certipy' },
    krbrelayx: { present: true, invocation: 'python3 /opt/krbrelayx/krbrelayx.py', path: '/opt/krbrelayx/krbrelayx.py', via: 'located' },
    targetedkerberoast: { present: true, invocation: 'targetedkerberoast', path: '/opt/targetedKerberoast', via: 'cloned' },
    'set_empty_pw.py': {
      present: true,
      invocation: 'python3 /home/kali/tools/CVE-2020-1472/set_empty_pw.py',
      path: '/home/kali/tools/CVE-2020-1472/set_empty_pw.py',
      dir: '/home/kali/tools/CVE-2020-1472',
      via: 'cloned'
    },
    'autoblue-ms17-010': {
      present: true,
      invocation: 'python3 /home/kali/tools/MS17-010/eternalblue_exploit7.py',
      path: '/home/kali/tools/MS17-010/eternalblue_exploit7.py',
      dir: '/home/kali/tools/MS17-010',
      via: 'cloned'
    },
    'reinstall_original_pw.py': {
      present: true,
      invocation: 'python3 /home/kali/tools/CVE-2020-1472/reinstall_original_pw.py',
      path: '/home/kali/tools/CVE-2020-1472/reinstall_original_pw.py',
      dir: '/home/kali/tools/CVE-2020-1472',
      via: 'cloned'
    },
    _unused_autoblue: {
      present: true,
      invocation: 'python3 /home/kali/tools/MS17-010/eternalblue_exploit7.py',
      path: '/home/kali/tools/MS17-010/eternalblue_exploit7.py',
      dir: '/home/kali/tools/MS17-010',
      via: 'cloned'
    },
    'keepass-dump-masterkey': {
      present: true,
      invocation: 'python3 /home/kali/tools/keepass-dump-masterkey/poc.py',
      path: '/home/kali/tools/keepass-dump-masterkey/poc.py',
      dir: '/home/kali/tools/keepass-dump-masterkey',
      scripts: { 'poc.py': '/home/kali/tools/keepass-dump-masterkey/poc.py', 'keepass_dump_masterkey.py': '/home/kali/tools/keepass-dump-masterkey/poc.py' },
      via: 'cloned'
    },
    'smbghost-rce': {
      present: true,
      invocation: 'python3 /home/kali/tools/SMBGhost_RCE_PoC/exploit.py',
      path: '/home/kali/tools/SMBGhost_RCE_PoC/exploit.py',
      dir: '/home/kali/tools/SMBGhost_RCE_PoC',
      scripts: { 'exploit.py': '/home/kali/tools/SMBGhost_RCE_PoC/exploit.py', 'smbghost_rce.py': '/home/kali/tools/SMBGhost_RCE_PoC/exploit.py' },
      via: 'cloned'
    },
  },
  wordlists: { rockyou: '/opt/lists/rockyou.txt', seclists: '/opt/SecLists' },
  lhost: '10.10.14.55',
  lhost_iface: 'tun0',
  tooldir: '/home/kali/tools',
  wwwdir: '/home/kali/.obol/arsenal/www',
  savedAt: Date.now(),
};

console.log('# invocation rewrite');
ok(C.applyArsenal('impacket-psexec -hashes :abc corp/admin@10.0.0.5', { tool: 'impacket-psexec' }, prof).indexOf('psexec.py -hashes') === 0,
  'impacket-psexec -> psexec.py (the box\'s actual invocation)');
ok(C.applyArsenal('nxc smb 10.0.0.5 -u a -p b', { tool: 'nxc' }, prof).indexOf('netexec smb') === 0,
  'nxc -> netexec');
ok(C.applyArsenal('certipy find -vulnerable', { tool: 'certipy' }, prof) === 'certipy find -vulnerable',
  'certipy stays certipy (invocation matches canonical - no spurious change)');

console.log('# standalone-token safety');
ok(C.applyArsenal('nxc smb 10.0.0.5 --comment mynxc', { tool: 'nxc' }, prof) === 'netexec smb 10.0.0.5 --comment mynxc',
  'only the standalone nxc token is swapped, not the substring inside "mynxc"');

console.log('# existing-Kali located/cloned Python scripts & pipelines');
ok(C.applyArsenal('python3 krbrelayx.py -hashes :abc', { tool: 'krbrelayx' }, prof) === 'python3 /opt/krbrelayx/krbrelayx.py -hashes :abc',
  'python3 krbrelayx.py rewrites to located /opt path without doubling python3');
ok(C.applyArsenal('krbrelayx.py -hashes :abc', { tool: 'krbrelayx' }, prof) === 'python3 /opt/krbrelayx/krbrelayx.py -hashes :abc',
  'bare krbrelayx.py rewrites to python3 /opt/krbrelayx/krbrelayx.py');
ok(C.applyArsenal('python3 ~/tools/krbrelayx/krbrelayx.py -hashes :abc', { tool: 'krbrelayx' }, prof) === 'python3 /opt/krbrelayx/krbrelayx.py -hashes :abc',
  'hardcoded ~/tools/krbrelayx/krbrelayx.py rewrites to located /opt path');
ok(C.applyArsenal('targetedKerberoast.py -d corp.local -u user -p pass', { tool: 'targetedKerberoast.py' }, prof) === 'python3 /opt/targetedKerberoast/targetedKerberoast.py -d corp.local -u user -p pass',
  'legacy cloned profile with lowercase key upgrades to python3 <dir>/<canonical>');
ok(C.applyArsenal('certipy find -vulnerable && impacket-getST -spn cifs/dc.corp.local corp.local/user', { tool: 'certipy' }, prof).indexOf('getST.py -spn') > 0,
  'secondary tool in a multi-tool pipeline is rewritten even when action.tool only names the primary tool');
ok(C.applyArsenal('python3 set_empty_pw.py DC01 10.10.10.10', { tool: 'set_empty_pw.py' }, prof) === 'python3 /home/kali/tools/CVE-2020-1472/set_empty_pw.py DC01 10.10.10.10',
  'multi-script repo (zerologon-exploit) rewrites set_empty_pw.py to its exact repo script');
ok(C.applyArsenal('python3 reinstall_original_pw.py DC01 10.10.10.10 aad3b4', { tool: 'reinstall_original_pw.py' }, prof) === 'python3 /home/kali/tools/CVE-2020-1472/reinstall_original_pw.py DC01 10.10.10.10 aad3b4',
  'multi-script repo (zerologon-exploit) rewrites reinstall_original_pw.py to reinstall_original_pw.py (never clobbered by set_empty_pw.py)');
ok(C.applyArsenal('python3 eternalblue_exploit8.py 10.10.10.40 shellcode/sc_all.bin', { tool: 'autoblue' }, prof) === 'python3 /home/kali/tools/MS17-010/eternalblue_exploit8.py 10.10.10.40 shellcode/sc_all.bin',
  'multi-script repo (autoblue) rewrites eternalblue_exploit8.py to eternalblue_exploit8.py (never clobbered by eternalblue_exploit7.py)');
ok(C.applyArsenal('python3 keepass_dump_masterkey.py -d KeePass.DMP', { tool: 'keepass_dump_masterkey.py' }, prof) === 'python3 /home/kali/tools/keepass-dump-masterkey/poc.py -d KeePass.DMP',
  'renamed upstream repo script (keepass-dump-masterkey poc.py) rewrites keepass_dump_masterkey.py cleanly');
ok(C.applyArsenal('python3 SMBGhost_RCE.py -ip 10.10.10.10', { tool: 'smbghost-rce' }, prof) === 'python3 /home/kali/tools/SMBGhost_RCE_PoC/exploit.py -ip 10.10.10.10',
  'renamed upstream repo script (SMBGhost_RCE_PoC exploit.py) rewrites SMBGhost_RCE.py cleanly');

console.log('# wordlist paths');
ok(C.applyArsenal('hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt', { tool: 'hashcat' }, prof).indexOf('/opt/lists/rockyou.txt') >= 0,
  'rockyou path rewritten to the box\'s real location');
ok(C.applyArsenal('ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u URL', { tool: 'ffuf' }, prof).indexOf('/opt/SecLists/Discovery') >= 0,
  'SecLists base path (/usr/share/seclists) rewritten');
ok(C.applyArsenal('ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u URL', { tool: 'ffuf' }, prof).indexOf('/opt/SecLists/Discovery') >= 0,
  'SecLists alternative path (/usr/share/wordlists/seclists) rewritten');

console.log('# reversible / no-op without a profile');
ok(C.applyArsenal('impacket-psexec corp/admin@10.0.0.5', { tool: 'impacket-psexec' }, null) === 'impacket-psexec corp/admin@10.0.0.5',
  'no synced profile -> command left exactly as authored (canonical)');
ok(C.applyArsenal('mimikatz sekurlsa::logonpasswords', { tool: 'mimikatz' }, prof) === 'mimikatz sekurlsa::logonpasswords',
  'a tool the box did not report present is left unchanged');

console.log('# fillCommand threads opts.arsenal and per-command c.tool end-to-end');
const act = new OBOL.pack.Action({ id: 'x', tool: 'impacket-psexec', tools: ['impacket-psexec'],
  commands: [
    { tool: 'impacket-psexec', run: 'impacket-psexec -hashes :{{nthash}} {{domain}}/{{username}}@{{target}}' },
    { tool: 'nxc', run: 'nxc smb {{target}} -u {{username}} -H {{nthash}}' }
  ],
  requires_all: [], requires_any: [], produces: [] });
const facts = new F.FactSet([]);
const out0 = C.fillCommand(act, facts, { arsenal: prof, params: { username: 'admin', domain: 'corp', target: '10.0.0.5', nthash: 'abc' } }, 0);
ok(out0.filled.indexOf('psexec.py') === 0, 'fillCommand applies rewrite on variant 0 (' + out0.filled + ')');
const out1 = C.fillCommand(act, facts, { arsenal: prof, params: { username: 'admin', domain: 'corp', target: '10.0.0.5', nthash: 'abc' } }, 1);
ok(out1.filled.indexOf('netexec smb') === 0, 'fillCommand applies rewrite on variant 1 with per-command c.tool (' + out1.filled + ')');

console.log('# OBOL.ingest routes OBOL-ARSENAL v1 paste-back from QuickPaste / Evidence');
const pasteBlock = '✂────── COPY FROM HERE ──────\nOBOL-ARSENAL v1\n' + JSON.stringify({
  v: 1,
  tools: { nxc: { present: true, invocation: 'netexec', path: '/usr/bin/netexec' } },
  staged: ['linpeas.sh', 'winPEASx64.exe'],
  wwwdir: '/home/kali/.obol/arsenal/www',
  tooldir: '/home/kali/tools',
  lhost: '10.10.14.77',
  lhost_iface: 'tun0',
  wordlists: { rockyou: '/opt/lists/rockyou.txt', seclists: '/opt/SecLists' }
}) + '\n✂────── TO HERE ──────';
const ingRun = OBOL.ingest.run({ text: pasteBlock });
ok(ingRun && ingRun.ok && ingRun.arsenal && ingRun.arsenal.present === 1 && ingRun.arsenal.staged === 2 && ingRun.arsenal.lhost === '10.10.14.77',
  'OBOL.ingest.run intercepts OBOL-ARSENAL v1 and stocks Loadout profile + lhost');
const ingSess = OBOL.ingest.importSession(pasteBlock);
ok(ingSess && ingSess.ok && ingSess.arsenal && ingSess.arsenal.wordlists === 2,
  'OBOL.ingest.importSession intercepts OBOL-ARSENAL v1 and stocks Loadout profile');
const ingDirect = OBOL.arsenal.ingestInventory(pasteBlock);
ok(ingDirect && ingDirect.ok && ingDirect.lhost === '10.10.14.77' && ingDirect.lhost_iface === 'tun0',
  'OBOL.arsenal.ingestInventory parses lhost and lhost_iface from OBOL-ARSENAL v1');

console.log(fail ? ('\nFAILED (' + fail + ')') : '\nALL PASS');
process.exit(fail ? 1 : 0);
