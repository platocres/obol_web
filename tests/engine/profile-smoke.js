/* Node smoke for the ported engagement profile model. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
const P = globalThis.OBOL.profile;

let fail = 0;
function ok(c, m) { console.log((c ? '  ok  : ' : '  FAIL: ') + m); if (!c) fail++; }

// presets present
['htb', 'oscp', 'pwk', 'thm', 'cpts', 'pnpt', 'ctf', 'client', 'oswp', 'custom'].forEach((p) => ok(!!P.PRESETS[p], 'preset present: ' + p));

// alias normalization
ok(P.normalizePlatform('offsec') === 'oscp', 'alias offsec -> oscp');
ok(P.normalizePlatform('tryhackme') === 'thm', 'alias tryhackme -> thm');
ok(P.normalizePlatform('PEN-200') === 'oscp', 'alias PEN-200 -> oscp');
ok(P.normalizePlatform('Hack The Box') === 'htb', 'alias "Hack The Box" -> htb');
ok(P.normalizePlatform('TCM Security') === 'pnpt', 'alias "TCM Security" -> pnpt');
ok(P.normalizePlatform('organization') === 'client', 'alias "organization" -> client');
ok(P.normalizePlatform('nonsense') === '', 'unknown platform -> empty');

// exam flags
ok(P.isExamPlatform('oscp') && P.isExamPlatform('oswp') && P.isExamPlatform('cpts') && P.isExamPlatform('pnpt'), 'oscp/oswp/cpts/pnpt are exam platforms');
ok(!P.isExamPlatform('htb') && !P.isExamPlatform('thm') && !P.isExamPlatform('pwk') && !P.isExamPlatform('client'), 'htb/thm/pwk/client are labs/client');
ok(P.counterpartPlatform('oscp') === 'pwk' && P.counterpartPlatform('htb') === 'cpts', 'exam<->lab counterparts');

// flagless vs flag-based profiles
ok(P.hasFlags({ platform: 'oscp' }) === true && P.hasFlags({ platform: 'cpts' }) === true, 'oscp and cpts have flags');
ok(P.hasFlags({ platform: 'pnpt' }) === false && P.hasFlags({ platform: 'client' }) === false && P.hasFlags({ platform: 'oswp' }) === false, 'pnpt, client, and oswp are flagless');
ok(P.defaultLens({ platform: 'oscp' }) === 'oscp+' && P.defaultLens({ platform: 'pnpt' }) === 'all' && P.defaultLens({ platform: 'cpts' }) === 'all', 'defaultLens maps oscp->oscp+ and pnpt/cpts->all');
ok(P.reportProfileFor({ platform: 'pnpt' }) === 'pnpt' && P.reportProfileFor({ platform: 'cpts' }) === 'cpts' && P.reportProfileFor({ platform: 'client' }) === 'client', 'reportProfileFor maps pnpt/cpts/client');

// flag config
const oscpFlags = P.resolveFlagConfig({ platform: 'oscp' });
ok(JSON.stringify(oscpFlags.names) === JSON.stringify(['local.txt', 'proof.txt']), 'oscp flag names = local.txt, proof.txt');
const htbFlags = P.resolveFlagConfig({ platform: 'htb' });
ok(htbFlags.slots['root.txt'] === 'root', 'htb root.txt maps to root slot');
const pnptFlags = P.resolveFlagConfig({ platform: 'pnpt' });
ok(pnptFlags.flags_enabled === false && pnptFlags.names.length === 0, 'pnpt flag config has flags_enabled=false and empty names');

// proof config
ok(P.resolveProofConfig({ platform: 'oscp' }).required === true, 'oscp requires proof screenshots');
ok(P.resolveProofConfig({ platform: 'htb' }).required === false, 'htb does not require proof screenshots');
ok(P.resolveProofConfig({ platform: 'oscp' }).pass_threshold === 70, 'oscp pass threshold 70');
ok(P.resolveProofConfig({ platform: 'pnpt' }).no_flags === true, 'pnpt proof config sets no_flags=true');

// machine focus feeds the planner nudge
ok(P.machineFocus('dc').indexOf('ad.') >= 0, 'dc machine focus includes ad.');
ok(P.machineFocus('standalone').indexOf('web.') >= 0, 'standalone focus includes web.');
ok(P.profileFocus({ platform: 'pnpt' }, 'standalone').indexOf('ad.') >= 0, 'pnpt profile focus includes ad.');

// token helpers are injection-safe
const expr = P.linuxInameExpr(['user.txt', 'root.txt', 'evil; rm -rf /']);
ok(expr === '-iname user.txt -o -iname root.txt', 'linuxInameExpr drops unsafe names');
ok(P.windowsNameList(['local.txt', 'proof.txt']) === 'local.txt,proof.txt', 'windowsNameList joins safe names');

// pack.js noFlags suppresses flag-hunt moves
const F = globalThis.OBOL.facts;
const PK = globalThis.OBOL.pack;
const flagPack = PK.loadPacks([require('../../data/packs/obol_flag_hunt_2026_09.json'), require('../../data/packs/linux_privesc_2026_09.json')]);
const fs = new F.FactSet();
fs.add(F.makeFact({ kind: 'foothold.linux', scope: '10.10.10.5', value: { user: 'www-data' } }));
const rankedWithFlags = PK.nextActionsV2(fs, flagPack, { noFlags: false });
const rankedNoFlags = PK.nextActionsV2(fs, flagPack, { noFlags: true });
ok(rankedWithFlags.some((a) => a.id === 'flag-hunt-linux'), 'with flags: flag-hunt-linux is offered on Linux foothold');
ok(!rankedNoFlags.some((a) => a.id.indexOf('flag-hunt') === 0), 'noFlags: flag-hunt-* moves are completely suppressed');

console.log(fail ? ('\nPROFILE SMOKE: ' + fail + ' FAILURES') : '\nPROFILE SMOKE: all passed');
process.exit(fail ? 1 : 0);

