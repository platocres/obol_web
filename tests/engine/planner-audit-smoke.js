/* Node test for the full-route planner (OBOL.pack.planPath) — doubles as a GATE AUDITOR.
 * The planner finds the lowest-cost path from current facts to a goal. If a move's gate is too loose,
 * the planner routes through it and produces a nonsensical cross-domain plan (e.g. a Linux web box that
 * "reaches" AD DCSync). These assertions lock the gates: a non-AD box must never plan domain moves, and
 * an OS-known plan must not mix OS. Run realistic, OS-known starts (the normal case). */
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
  .map((f) => { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } }));
const byId = {}; PACK.forEach((a) => { byId[a.id] = a; });

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

function fset(kinds) {
  return new F.FactSet(kinds.map((k) => {
    if (k === 'os:linux') return F.makeFact({ kind: 'host.os_family', value: { family: 'linux' }, scope: { target: '10' }, source: 't' });
    if (k === 'os:windows') return F.makeFact({ kind: 'host.os_family', value: { family: 'windows' }, scope: { target: '10' }, source: 't' });
    return F.makeFact({ kind: k, scope: { target: '10' }, source: 't' });
  }));
}
function plan(kinds) { return PK.planPath(fset(kinds), PACK, {}); }

const AD_MOVES = ['dcsync', 'own-domain-pth', 'ad-path-manual', 'kerberoast', 'asrep-roast', 'crack-asrep', 'password-spray', 'bloodhound-collect', 'golden-ticket', 'silver-ticket', 'coerce-auth', 'delegation-abuse'];
function hasAD(p) { return (p || []).filter((id) => AD_MOVES.indexOf(id) >= 0 || /^ad-/.test(id)); }
function winOnly(id) { var a = byId[id]; var os = (a && a.os) || []; return os.length && os.every((o) => OBOL.pack.normalizeOsName(o) === 'windows'); }
function winMoves(p) { return (p || []).filter(winOnly); }

// 1) AD box: a domain-compromise route is reachable (sanity — AD moves SHOULD appear here).
const ad = plan(['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick', 'ad.dc_candidate', 'ad.domain_known', 'ad.base_dn', 'ldap.reachable', 'smb.reachable', 'kerberos.reachable', 'os:windows']);
ok(ad.reachable, 'AD box: a route to domain compromise is reachable');
ok(hasAD(ad.path).length > 0, 'AD box: the plan uses AD moves (expected here)');

// 2) Linux box (OS known) with a web service: reachable, and NO AD move, NO windows-only move.
const lin = plan(['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick', 'web.server', 'http.headers', 'web.tech', 'foothold.linux', 'os:linux']);
ok(lin.reachable, 'Linux web box: a route to root is reachable');
ok(hasAD(lin.path).length === 0, 'Linux web box: plan contains NO AD domain move (got: ' + (hasAD(lin.path).join(',') || 'none') + ')');
ok(winMoves(lin.path).length === 0, 'Linux web box: plan contains NO windows-only move (got: ' + (winMoves(lin.path).join(',') || 'none') + ')');

// 3) Linux foothold shell: a privesc route, no AD, no windows.
const foot = plan(['target.configured', 'host.up', 'ports.open', 'foothold.linux', 'os:linux']);
ok(foot.reachable && hasAD(foot.path).length === 0 && winMoves(foot.path).length === 0,
  'Linux foothold: clean privesc route (' + (foot.path || []).join(' → ') + ')');

// 4) REGRESSION — the SNMP leak: a Linux box with a user list but no domain context must NOT plan
//    domain spraying / DCSync. (recon-snmp mints ad.user_list; password-spray now needs an AD context.)
const leak = plan(['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick', 'ad.user_list', 'foothold.linux', 'os:linux']);
ok((leak.path || []).indexOf('password-spray') < 0, 'SNMP leak fixed: a user list without a domain does NOT unlock password-spray');
ok((leak.path || []).indexOf('dcsync') < 0, 'SNMP leak fixed: a non-AD box does NOT plan DCSync');

// 5) shape: planPath returns reachable + path, exported.
ok(typeof PK.planPath === 'function', 'planPath is exported');
ok(ad.path && typeof ad.cost === 'number', 'planPath returns a path and a numeric cost');

console.log(fail ? ('\nPLANNER AUDIT: ' + fail + ' FAILURES') : '\nPLANNER AUDIT: all passed');
process.exit(fail ? 1 : 0);
