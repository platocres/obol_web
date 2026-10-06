/* Keystone weighting — the gate-wiring-aware score term. At a mid-game state with several parallel,
 * equally-eligible moves, a move whose produced facts unblock MORE of the attack surface (a keystone) should
 * rank above a narrow-outcome move of comparable goal-distance — computed from the wiring, not a priority
 * bump. This pins that behaviour so it cannot silently regress (with V2_KEYSTONE_W=0 the first assertion
 * flips). See docs/MOVE-ENGINE.md and the keystone block in assets/engine/pack.js.
 */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
var fs = require('fs'), path = require('path');
var OBOL = globalThis.OBOL, PK = OBOL.pack, F = OBOL.facts, PH = OBOL.phases;
var pdir = path.join(__dirname, '..', '..', 'data', 'packs');
var PACK = PK.loadPacks(fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); })
  .map(function (f) { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } }));

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

function ready(kinds) {
  var fl = kinds.map(function (k, i) { return F.makeFact({ kind: k, scope: { target: '10.0.0.5' }, value: {}, source: 's', created_at: 1700000000000 + i * 3600000 }); });
  var fset = new F.FactSet(fl);
  return PK.rankActions(fset, PACK, { focusPrefixes: OBOL.profile.machineFocus('ad') })
    .filter(function (a) { return !PK.isReportOnly(a, PACK); })
    .filter(function (a) { return PH.prematurity(a, fset) === 0; })
    .map(function (a) { return a.id; });
}
function rankOf(ids, id) { var i = ids.indexOf(id); return i < 0 ? 1e9 : i; }

// Mid-game AD: DC known, user list, a cracked domain credential — kerberoast (→ hash.tgs → crack → another
// credential, unblocking the whole re-use surface) vs laps-read (→ one machine's local-admin candidate).
// Both eligible, comparable goal-distance; keystone favours the broader unlock.
var mid = ['target.configured', 'host.up', 'ports.open', 'port:445', 'port:389', 'port:88',
  'smb.reachable', 'ldap.reachable', 'kerberos.reachable', 'ad.dc_candidate', 'ad.domain_known',
  'ad.user_list', 'credential.available'];
var ids = ready(mid);
ok(rankOf(ids, 'kerberoast') < rankOf(ids, 'laps-read'),
  'keystone: kerberoast (broad unlock) ranks above laps-read (narrow) at the cracked-cred stage (kerberoast #' + (rankOf(ids, 'kerberoast') + 1) + ', laps-read #' + (rankOf(ids, 'laps-read') + 1) + ')');

// The endgame guard — keystone must not displace own-domain-pth at NTDS+krbtgt (cash-ins and loot.ntds
// side-quests are keystone-suppressed) — is covered by ranker-smoke's final checkpoint, which passes with
// keystone on; not duplicated here.

console.log('\nRANKER KEYSTONE SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
