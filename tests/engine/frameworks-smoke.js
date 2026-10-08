/* Node smoke test for the Frameworks engine (assets/engine/frameworks.js).
 *
 * Loads the bundled reference data (ATT&CK catalog, D3FEND map, framework tables, KEV lookup) + the
 * findings engine, seeds a FactSet with a few facts that trigger known findings carrying ATT&CK codes,
 * and asserts the ATT&CK matrix lights the right cells, the kill chain buckets, the defensive lens
 * carries D3FEND countermeasures, the compliance rollup groups by framework, and the CVE/KEV overlay
 * flags an actively-exploited CVE. Run: node tests/engine/frameworks-smoke.js
 */
'use strict';
require('../../assets/engine/facts.js');
require('../../data/findings-catalog.js');
require('../../data/attack-catalog.js');
require('../../data/attack-move-map.js');
require('../../data/d3fend-map.js');
require('../../data/frameworks-tables.js');
require('../../data/kev-catalog.js');
require('../../assets/engine/findings.js');
require('../../assets/engine/frameworks.js');
const OBOL = globalThis.OBOL;
const F = OBOL.facts;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// seed facts that trigger findings carrying ATT&CK codes
const fs = new F.FactSet();
['web.authz_bypass', 'smb.null_session', 'hash.asrep'].forEach(function (k) {
  fs.add(F.makeFact({ kind: k, scope: 'target', value: true }));
});

// reference data loaded
ok(OBOL.ATTACK && Object.keys(OBOL.ATTACK.techniques).length > 100, 'ATT&CK catalog loaded (' + Object.keys(OBOL.ATTACK.techniques).length + ' techniques)');
ok(OBOL.ATTACK.tactics.length >= 12, 'ATT&CK tactics loaded (' + OBOL.ATTACK.tactics.length + ')');
ok(OBOL.D3FEND && Object.keys(OBOL.D3FEND.map).length > 20, 'D3FEND map loaded');
ok(OBOL.KEV && Object.keys(OBOL.KEV.map).length > 1000, 'KEV lookup loaded (' + Object.keys(OBOL.KEV.map).length + ')');

const m = OBOL.frameworks.compute(fs);
ok(m.ready === true, 'compute reports ready (reference data present)');

// technique use from findings
const used = Object.keys(m.use);
ok(used.indexOf('T1190') >= 0, 'IDOR finding contributes T1190 (used)');
ok(used.indexOf('T1135') >= 0, 'SMB null session contributes T1135 (used)');
ok(used.indexOf('T1558.004') >= 0, 'AS-REP roasting contributes T1558.004 (used)');

// ATT&CK matrix: a used cell in the credential-access column, and the sub-technique rolls to its parent
const credCol = m.attack.tactics.find(function (c) { return c.id === 'credential-access'; });
ok(credCol && credCol.usedCount >= 1, 'credential-access column has a used cell');
const t1558cell = credCol && credCol.cells.find(function (c) { return c.id === 'T1558'; });
ok(t1558cell && t1558cell.used && t1558cell.subs.indexOf('T1558.004') >= 0, 'T1558 cell is lit and lists the used sub-technique T1558.004');
const discCol = m.attack.tactics.find(function (c) { return c.id === 'discovery'; });
ok(discCol && discCol.cells.some(function (c) { return c.id === 'T1135' && c.used; }), 'discovery column lights T1135');
ok(m.attack.usedTotal >= 3, 'matrix usedTotal counts the distinct top-level techniques used');

// kill chain buckets
const kcActions = m.killchain.find(function (s) { return s.id === 'actions'; });
ok(kcActions && kcActions.techniques.length >= 1, 'kill chain Actions-on-Objectives bucket is populated');

// defensive lens: D3FEND countermeasures for a used technique
const def1558 = m.defensive.find(function (d) { return d.id === 'T1558.004'; });
ok(def1558 && def1558.d3fend.length >= 1, 'defensive lens carries D3FEND countermeasures for T1558.004');
ok(def1558 && def1558.d3fend.some(function (c) { return /Strong Password Policy/i.test(c.name); }), 'Kerberoast-family countermeasure resolves a D3FEND name');
const def1135 = m.defensive.find(function (d) { return d.id === 'T1135'; });
ok(def1135 && (def1135.mitigations.length >= 0) && typeof def1135.detection === 'string', 'defensive lens carries ATT&CK mitigations + detection fields');

// compliance rollup (nist/cwe from the seeded findings, if any carry them)
ok(m.compliance && Array.isArray(m.compliance.nist) && Array.isArray(m.compliance.cwe), 'compliance rollup has nist + cwe lists');

// compliance direct: a finding carrying cis/pci/nist groups correctly
const comp = OBOL.frameworks.compliance([
  { key: 'x', nist: 'AC-3', cwe: 'CWE-639', cis: 'CIS-6', pci: '7.1', refs: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'] },
]);
ok(comp.nist.some(function (e) { return /AC-3/.test(e.title) && /Access Control/.test(e.title); }), 'NIST control labelled with its family name');
ok(comp.cis.some(function (e) { return /CIS 6/.test(e.title) && /Access Control Management/.test(e.title); }), 'CIS control labelled with its v8 title');
ok(comp.pci.some(function (e) { return /PCI Req 7/.test(e.title) && /Need to Know/.test(e.title); }), 'PCI requirement labelled with its v4 title');
ok(comp.owasp.some(function (e) { return e.key === 'A01'; }), 'OWASP category derived from a reference link');

// ── D3FEND defensive-tactic matrix (grouped by tactic, MITRE-recognizable) ─────────────────
ok(m.d3fend && Array.isArray(m.d3fend.tactics), 'compute returns a d3fend matrix');
ok(m.d3fend.tactics.length >= 1, 'd3fend matrix has at least one tactic column');
ok(m.d3fend.tactics.every(function (c) { return ['Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore'].indexOf(c.tactic) >= 0; }), 'd3fend tactic columns are the 7 D3FEND tactics');
ok(m.d3fend.tactics.some(function (c) { return c.tactic === 'Harden'; }), 'd3fend matrix includes a Harden column (Strong Password Policy etc. for Kerberoast)');
ok(m.d3fend.tactics.every(function (c) { return c.items.every(function (it) { return it.name && it.counters.length; }); }), 'each d3fend countermeasure names what it counters');

// ── MF5 derivations: recorded-moves trail + finding gap-fill + NIST->CIS/PCI crosswalk ─────
// recorded-moves trail: an activity that produced hash.kerberoast lights T1558.003 even with no finding
const withMoves = OBOL.frameworks.compute(new F.FactSet(), {
  findings: [],
  activities: [{ command: 'nxc ldap dc -u u -p p --kerberoasting kerb.hashes', produced: ['hash.kerberoast'] },
               { command: 'nmap -p- 10.10.10.10', produced: ['ports.open', 'host.up'] }],
});
ok(Object.keys(withMoves.use).indexOf('T1558.003') >= 0, 'recorded move (produced hash.kerberoast) lights T1558.003');
ok(Object.keys(withMoves.use).indexOf('T1046') >= 0, 'recorded move (produced ports.open) lights T1046 (Network Service Discovery)');
ok(withMoves.use['T1046'][0] && withMoves.use['T1046'][0].k === 'm' && withMoves.use['T1046'][0].t === 'nmap -p- 10.10.10.10', 'recorded-move contribution carries the ran command (k:m, t:<command>)');

// finding gap-fill: a finding with NO authored attack derives one from its trigger_kind
const gap = OBOL.frameworks.techniqueUse([{ title: 'Writable cron', trigger_kinds: ['privesc.cron_writable'] }], []);
ok(Object.keys(gap).indexOf('T1053.003') >= 0, 'finding with no attack derives T1053.003 from its trigger_kind (cron)');

// NIST -> CIS / PCI crosswalk: a finding with only a NIST control yields CIS + PCI
const cw = OBOL.frameworks.compliance([{ key: 'z', nist: 'IA-5' }]);
ok(cw.cis.some(function (e) { return /CIS 5/.test(e.title); }), 'IA-5 crosswalks to CIS 5 (Account Management)');
ok(cw.pci.some(function (e) { return /PCI Req 8/.test(e.title); }), 'IA-5 crosswalks to PCI Req 8 (Authenticate Access)');

// CVE/KEV overlay
const kevd = OBOL.frameworks.cves([
  { key: 'k', cve: 'CVE-2021-41773', title: 'Apache path traversal', severity: 'high', remediation: 'patch' },
  { key: 'q', cve: 'CVE-1900-0001', title: 'fake', severity: 'low', remediation: '' },
]);
const hit = kevd.find(function (c) { return c.cve === 'CVE-2021-41773'; });
ok(hit && hit.kev === true, 'a real KEV CVE is flagged actively exploited');
const miss = kevd.find(function (c) { return c.cve === 'CVE-1900-0001'; });
ok(miss && miss.kev === false, 'a non-KEV CVE is not flagged');
ok(kevd[0].cve === 'CVE-2021-41773', 'CVEs sort KEV-first');

// ── BY_MOVE map accuracy: a run that USES a move lights the move's authored technique, not its fact's ──
const sprayTrail = OBOL.frameworks.compute(new F.FactSet(), {
  findings: [],
  activities: [{ action_id: 'password-spray', command: 'nxc smb dc -u users.txt -p Spring2026', produced: ['credential.available'] }],
});
ok(Object.keys(sprayTrail.use).indexOf('T1110.003') >= 0, 'password-spray lights T1110.003 (Password Spraying) via BY_MOVE');
ok(Object.keys(sprayTrail.use).indexOf('T1078') < 0, 'password-spray does NOT also light T1078 (BY_MOVE wins over the produced-fact map)');
const pthTrail = OBOL.frameworks.compute(new F.FactSet(), {
  findings: [], activities: [{ action_id: 'own-domain-pth', command: 'nxc smb dc -u Administrator -H <hash>', produced: ['access.admin'] }],
});
ok(Object.keys(pthTrail.use).indexOf('T1550.002') >= 0, 'own-domain-pth lights T1550.002 (Pass the Hash) via BY_MOVE');

// ── exampleCommands: a technique resolves to a real obol move command, filled for teaching ──
const pdir2 = require('path').join(__dirname, '..', '..', 'data', 'packs');
let PACK2 = [];
try {
  require('../../assets/engine/phases.js'); require('../../assets/engine/pack.js');
  require('../../assets/engine/profile.js'); require('../../assets/engine/command.js');
  require('../../assets/engine/workspace.js'); require('../../assets/engine/loot.js');
  const fsx = require('fs');
  PACK2 = OBOL.pack.loadPacks(fsx.readdirSync(pdir2).filter(f => f.endsWith('.json'))
    .map(f => { try { return JSON.parse(fsx.readFileSync(require('path').join(pdir2, f), 'utf8')); } catch (e) { return {}; } }));
} catch (e) { console.error('  (pack load for exampleCommands failed: ' + e.message + ')'); }
ok(PACK2.length > 100, 'pack loaded for exampleCommands (' + PACK2.length + ' moves)');
const exKerb = OBOL.frameworks.exampleCommands('T1558', PACK2, { params: { target: '10.10.10.10' } });
ok(exKerb.length >= 1 && exKerb.some(function (e) { return /kerberoast/i.test(e.run); }), 'T1558 resolves to a kerberoast example command');
ok(exKerb.every(function (e) { return e.run.indexOf('{{') < 0 || /\{\{\w+\}\}/.test(e.run); }), 'example command is filled (known tokens substituted)');
const exSpray = OBOL.frameworks.exampleCommands('T1110.003', PACK2, {});
ok(exSpray.length >= 1 && exSpray[0].moveId === 'password-spray', 'T1110.003 resolves to the password-spray move');
const exSuid = OBOL.frameworks.exampleCommands('T1548.001', PACK2, {});
ok(exSuid.some(function (e) { return e.moveId === 'suid-gtfobins'; }), 'T1548.001 (Setuid) resolves to the SUID abuse move (consume-side act)');
const exNone = OBOL.frameworks.exampleCommands('T1203', PACK2, {});
ok(exNone.length === 0, 'a technique obol does not perform (T1203) resolves to no example command (honest blank)');
// filler leaves an unknown token visible rather than inventing one
ok(OBOL.frameworks.exampleFill('run {{target}} {{zzznotatoken}}', { target: 'x' }) === 'run x {{zzznotatoken}}', 'exampleFill substitutes known tokens and leaves unknown ones visible');

console.log(fail ? ('\nFRAMEWORKS SMOKE: ' + fail + ' FAILURES') : '\nFRAMEWORKS SMOKE: all passed');
process.exit(fail ? 1 : 0);
