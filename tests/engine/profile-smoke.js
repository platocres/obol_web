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
['htb', 'oscp', 'pwk', 'thm', 'cpts', 'ctf', 'oswp', 'custom'].forEach((p) => ok(!!P.PRESETS[p], 'preset present: ' + p));

// alias normalization
ok(P.normalizePlatform('offsec') === 'oscp', 'alias offsec -> oscp');
ok(P.normalizePlatform('tryhackme') === 'thm', 'alias tryhackme -> thm');
ok(P.normalizePlatform('PEN-200') === 'oscp', 'alias PEN-200 -> oscp');
ok(P.normalizePlatform('Hack The Box') === 'htb', 'alias "Hack The Box" -> htb');
ok(P.normalizePlatform('nonsense') === '', 'unknown platform -> empty');

// exam flags
ok(P.isExamPlatform('oscp') && P.isExamPlatform('oswp') && P.isExamPlatform('cpts'), 'oscp/oswp/cpts are exam platforms');
ok(!P.isExamPlatform('htb') && !P.isExamPlatform('thm') && !P.isExamPlatform('pwk'), 'htb/thm/pwk are labs');
ok(P.counterpartPlatform('oscp') === 'pwk' && P.counterpartPlatform('htb') === 'cpts', 'exam<->lab counterparts');

// flag config
const oscpFlags = P.resolveFlagConfig({ platform: 'oscp' });
ok(JSON.stringify(oscpFlags.names) === JSON.stringify(['local.txt', 'proof.txt']), 'oscp flag names = local.txt, proof.txt');
const htbFlags = P.resolveFlagConfig({ platform: 'htb' });
ok(htbFlags.slots['root.txt'] === 'root', 'htb root.txt maps to root slot');

// proof config
ok(P.resolveProofConfig({ platform: 'oscp' }).required === true, 'oscp requires proof screenshots');
ok(P.resolveProofConfig({ platform: 'htb' }).required === false, 'htb does not require proof screenshots');
ok(P.resolveProofConfig({ platform: 'oscp' }).pass_threshold === 70, 'oscp pass threshold 70');

// machine focus feeds the planner nudge
ok(P.machineFocus('dc').indexOf('ad.') >= 0, 'dc machine focus includes ad.');
ok(P.machineFocus('standalone').indexOf('web.') >= 0, 'standalone focus includes web.');

// token helpers are injection-safe
const expr = P.linuxInameExpr(['user.txt', 'root.txt', 'evil; rm -rf /']);
ok(expr === '-iname user.txt -o -iname root.txt', 'linuxInameExpr drops unsafe names');
ok(P.windowsNameList(['local.txt', 'proof.txt']) === 'local.txt,proof.txt', 'windowsNameList joins safe names');

console.log(fail ? ('\nPROFILE SMOKE: ' + fail + ' FAILURES') : '\nPROFILE SMOKE: all passed');
process.exit(fail ? 1 : 0);
