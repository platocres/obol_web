/* Loadout command-rewrite (OBOL.command.applyArsenal): once a box is synced, filled commands adopt the
 * operator's real tool invocations + wordlist paths. Conservative + reversible — only a recognized ARSENAL
 * variant as a standalone token is swapped; un-synced or unknown is left exactly as authored. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
require('../../data/tools-install.js');
const OBOL = globalThis.OBOL, C = OBOL.command, F = OBOL.facts;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

const prof = {
  tools: {
    'impacket-psexec': { present: true, invocation: 'psexec.py' },
    nxc: { present: true, invocation: 'netexec' },
    certipy: { present: true, invocation: 'certipy' },
  },
  wordlists: { rockyou: '/opt/lists/rockyou.txt', seclists: '/opt/SecLists' },
  savedAt: Date.now(),
};

console.log('# invocation rewrite');
ok(C.applyArsenal('impacket-psexec -hashes :abc corp/admin@10.0.0.5', { tool: 'impacket-psexec' }, prof).indexOf('psexec.py -hashes') === 0,
  'impacket-psexec → psexec.py (the box\'s actual invocation)');
ok(C.applyArsenal('nxc smb 10.0.0.5 -u a -p b', { tool: 'nxc' }, prof).indexOf('netexec smb') === 0,
  'nxc → netexec');
ok(C.applyArsenal('certipy find -vulnerable', { tool: 'certipy' }, prof) === 'certipy find -vulnerable',
  'certipy stays certipy (invocation matches canonical — no spurious change)');

console.log('# standalone-token safety');
ok(C.applyArsenal('nxc smb 10.0.0.5 --comment mynxc', { tool: 'nxc' }, prof) === 'netexec smb 10.0.0.5 --comment mynxc',
  'only the standalone nxc token is swapped, not the substring inside "mynxc"');

console.log('# wordlist paths');
ok(C.applyArsenal('hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt', { tool: 'hashcat' }, prof).indexOf('/opt/lists/rockyou.txt') >= 0,
  'rockyou path rewritten to the box\'s real location');
ok(C.applyArsenal('ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u URL', { tool: 'ffuf' }, prof).indexOf('/opt/SecLists/Discovery') >= 0,
  'SecLists base path rewritten');

console.log('# reversible / no-op without a profile');
ok(C.applyArsenal('impacket-psexec corp/admin@10.0.0.5', { tool: 'impacket-psexec' }, null) === 'impacket-psexec corp/admin@10.0.0.5',
  'no synced profile → command left exactly as authored (canonical)');
ok(C.applyArsenal('mimikatz sekurlsa::logonpasswords', { tool: 'mimikatz' }, prof) === 'mimikatz sekurlsa::logonpasswords',
  'a tool the box did not report present is left unchanged');

console.log('# fillCommand threads opts.arsenal end-to-end');
const act = new OBOL.pack.Action({ id: 'x', tool: 'impacket-psexec', tools: ['impacket-psexec'],
  commands: [{ tool: 'impacket-psexec', run: 'impacket-psexec -hashes :{{nthash}} {{domain}}/{{username}}@{{target}}' }],
  requires_all: [], requires_any: [], produces: [] });
const facts = new F.FactSet([]);
const out = C.fillCommand(act, facts, { arsenal: prof, params: { username: 'admin', domain: 'corp', target: '10.0.0.5', nthash: 'abc' } }, 0);
ok(out.filled.indexOf('psexec.py') === 0, 'fillCommand applies the rewrite on the filled command (' + out.filled + ')');

console.log(fail ? ('\nFAILED (' + fail + ')') : '\nALL PASS');
process.exit(fail ? 1 : 0);
