/* Locus (R/F/I) + scope (oscp/oscp+/beyond) derivation and the remote-first ranker tiebreak.
 * Locus and scope are DERIVED in the engine (explicit pack field wins, else classified from tool + gates),
 * so every loaded move carries both. These assertions lock the classifier against the regressions found
 * when it was built (a secondary tool escalating a core move; an overloaded fact; a greedy id regex) and
 * prove the coach prefers the lowest-friction locus among otherwise-equal moves. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, PK = OBOL.pack, F = OBOL.facts;

const pdir = path.join(__dirname, '..', '..', 'data', 'packs');
const PACK = PK.loadPacks(fs.readdirSync(pdir).filter((f) => f.endsWith('.json'))
  .map((f) => JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8'))));
const byId = {}; PACK.forEach((a) => { byId[a.id] = a; });

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function locusOf(id) { return byId[id] ? byId[id].locus : '(missing ' + id + ')'; }
function scopeOf(id) { return byId[id] ? byId[id].scope : '(missing ' + id + ')'; }

console.log('# every loaded move carries a valid locus + scope');
ok(PACK.every((a) => a.locus === 'R' || a.locus === 'F' || a.locus === 'I'), 'all ' + PACK.length + ' moves have a valid locus');
ok(PACK.every((a) => a.scope === 'oscp' || a.scope === 'oscp+' || a.scope === 'beyond'), 'all moves have a valid scope');

console.log('# locus classification');
ok(locusOf('nmap-fast-open-ports') === 'R', 'nmap scan is remote (R)');
ok(locusOf('kerberoast') === 'R', 'kerberoast (impacket from Kali) is remote (R)');
ok(locusOf('dcsync') === 'R', 'dcsync (impacket secretsdump) is remote (R)');
ok(locusOf('windows-enum') === 'I', 'winPEAS is interactive on-host (I)');
ok(locusOf('linux-enum') === 'I', 'linPEAS is interactive on-host (I)');
ok(locusOf('powerview-enum') === 'F', 'PowerView via powershell is on-host one-shot (F)');
ok(locusOf('suid-gtfobins') === 'F', 'SUID/GTFOBins shell step is on-host (F)');

console.log('# scope classification (and the three regressions it was built against)');
ok(scopeOf('kerberoast') === 'oscp', 'kerberoast is core OSCP — a secondary targetedKerberoast tool must NOT escalate it');
ok(scopeOf('ssh-key-login') === 'oscp', 'ssh-key-login is core — the overloaded credential.certificate fact must NOT escalate it');
ok(scopeOf('crack-shadow') === 'oscp', 'crack-shadow (/etc/shadow) is core — the shadow-cred regex must NOT catch it');
ok(scopeOf('eternalblue') === 'oscp', 'EternalBlue is core OSCP');
ok(scopeOf('delegation-abuse') === 'oscp+', 'delegation abuse is OSCP+');
ok(scopeOf('adcs-esc') === 'oscp+', 'ADCS ESC is OSCP+');
ok(scopeOf('ntlm-relay-attack') === 'oscp+', 'NTLM relay is OSCP+');
ok(scopeOf('nopac') === 'beyond', 'noPac is beyond-OSCP');
ok(scopeOf('printnightmare') === 'beyond', 'PrintNightmare is beyond-OSCP');
ok(scopeOf('ms14-068') === 'beyond', 'MS14-068 is beyond-OSCP');
ok(scopeOf('sccm-enum') === 'beyond', 'SCCM takeover is beyond-OSCP');

console.log('# explicit pack field wins over derivation');
const expl = new PK.Action({ id: 'x', tool: 'nmap', locus: 'I', scope: 'beyond', produces: [], requires_all: [], requires_any: [] });
ok(expl.locus === 'I' && expl.scope === 'beyond', 'an explicit d.locus/d.scope overrides the classifier');

console.log('# remote-first tiebreak: equal moves, R ranks before I');
// Two synthetic moves, identical gate + produce (so identical tier + score), differing only in locus.
const mkSyn = (id, tool) => new PK.Action({ id: id, tool: tool, requires_all: ['smb.reachable'], requires_any: [], produces: ['loot.files'] });
const remoteMove = mkSyn('zz-remote-grab', 'smbclient');   // R
const onhostMove = mkSyn('zz-onhost-grab', 'winpeas');     // I
ok(remoteMove.locus === 'R' && onhostMove.locus === 'I', 'synthetic pair classifies R vs I');
const facts = new F.FactSet([F.makeFact({ kind: 'smb.reachable', scope: { target: '10' }, source: 't' })]);
const ranked = PK.nextActionsV2(facts, [onhostMove, remoteMove], {});
const ri = ranked.findIndex((a) => a.id === 'zz-remote-grab');
const ii = ranked.findIndex((a) => a.id === 'zz-onhost-grab');
ok(ri >= 0 && ii >= 0 && ri < ii, 'the remote (R) move is ranked above the on-host (I) move at equal score (R@' + ri + ' < I@' + ii + ')');

console.log(fail ? ('\nFAILED (' + fail + ')') : '\nALL PASS (' + PACK.length + ' moves)');
process.exit(fail ? 1 : 0);
