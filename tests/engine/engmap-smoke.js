/* Node sanity test for the engagement map projection (OBOL.engmap).
 * Builds a synthetic engagement and asserts the tiered node/edge model matches the
 * conservative rules ported from obol-local build_engagement_graph. */
'use strict';

// Load the browser engine modules into Node's global (they attach to globalThis).
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/engmap.js');
const OBOL = globalThis.OBOL;
const F = OBOL.facts;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

function fact(kind, scope, value) {
  return F.factToJson(F.makeFact({ kind: kind, scope: scope, value: value || {}, state: F.ProofState.SUPPORTED }));
}

// ── synthetic engagement ──
// t1 (10.10.10.5): open SMB(445) + LDAP(389) + a linux foothold  → access "foothold", 2 services.
// t2 (10.10.10.6): only host.up                                  → access "discovered", no services.
// one credential (svc_sql @ corp.local); one domain fact; scope is a /24 containing both hosts.
const eng = {
  profile: { scope: ['10.10.10.0/24'] },
  targets: [
    { id: 't1', ip: '10.10.10.5', hostname: 'DC01', os: 'windows' },
    { id: 't2', ip: '10.10.10.6', hostname: '', os: '' },
  ],
  credentials: [{ user: 'svc_sql', secretType: 'password', domain: 'corp.local' }],
  bloodhound: null,
  facts: [
    fact('host.up', 'host:10.10.10.5'),
    fact('port:445', 'host:10.10.10.5', { port: 445, protocol: 'tcp', service: 'microsoft-ds' }),
    fact('port:389', 'host:10.10.10.5', { port: 389, protocol: 'tcp', service: 'ldap' }),
    fact('foothold.linux', 'host:10.10.10.5'),
    fact('host.up', 'host:10.10.10.6'),
    fact('ad.domain_known', 'domain:corp.local', { name: 'corp.local' }),
  ],
};

const g = OBOL.engmap.buildEngagementGraph(eng);
const nodes = g.nodes, edges = g.edges;
const byType = (t) => nodes.filter((n) => n.type === t);
const nodeById = (id) => nodes.find((n) => n.id === id);

console.log('nodes=' + nodes.length + ' edges=' + edges.length);

// 1) target nodes with the right access levels
const targets = byType('target');
ok(targets.length === 2, 'two target nodes (' + targets.length + ')');
const t1 = targets.find((n) => n.meta.host === '10.10.10.5');
const t2 = targets.find((n) => n.meta.host === '10.10.10.6');
ok(t1 && t1.meta.access === 'foothold', 't1 access = foothold (' + (t1 && t1.meta.access) + ')');
ok(t2 && t2.meta.access === 'discovered', 't2 access = discovered (' + (t2 && t2.meta.access) + ')');
ok(t1 && t1.tier === 1 && t2 && t2.tier === 1, 'targets are tier 1');

// 2) service nodes for the open ports on t1 (SMB 445, LDAP 389); none on t2
const services = byType('service');
ok(services.length === 2, 't1 yields 2 service nodes (' + services.length + ')');
const labels = services.map((s) => s.label).sort();
ok(labels.indexOf('SMB 445') >= 0, 'SMB 445 service node present');
ok(labels.indexOf('LDAP 389') >= 0, 'LDAP 389 service node present');
ok(services.every((s) => s.meta.host === '10.10.10.5'), 'all services belong to t1');
// exposes edges: target -> its services
const exposes = edges.filter((e) => e.kind === 'exposes');
ok(exposes.length === 2 && exposes.every((e) => e.from === t1.id), 'two exposes edges from t1');

// 3) a credential node (svc_sql), linked to its domain, NOT glued to a host
const creds = byType('credential');
ok(creds.length === 1 && /svc_sql/.test(creds[0].label), 'one credential node (' + (creds[0] && creds[0].label) + ')');
ok(edges.some((e) => e.kind === 'credential' && e.to === creds[0].id), 'credential -> domain edge');
ok(!edges.some((e) => e.kind === 'authenticates'), 'no authenticates edge (no host-scoped cred fact ties it)');

// 4) an in-scope edge when scope is set (scope /24 -> each target)
const scopeNodes = byType('scope');
ok(scopeNodes.length === 1, 'one scope node (the /24)');
const inScope = edges.filter((e) => e.kind === 'in-scope');
ok(inScope.length === 2, 'two in-scope edges (both hosts in the /24) — got ' + inScope.length);
ok(inScope.every((e) => e.from === scopeNodes[0].id), 'in-scope edges originate at the scope node');

// 5) NO invented host-to-host edge
const targetIds = {}; targets.forEach((t) => { targetIds[t.id] = true; });
ok(!edges.some((e) => targetIds[e.from] && targetIds[e.to]), 'no target-to-target edge invented');

// 6) domain node present from the ad.domain_known fact
const domains = byType('domain');
ok(domains.some((d) => d.label === 'corp.local'), 'domain node corp.local present');

// 7) SVG renders and is well-formed-ish (single root, target group carries data-ip)
const svg = OBOL.engmap.buildEngagementSvg(eng);
ok(/^<svg[\s\S]*<\/svg>$/.test(svg.trim()), 'SVG has a single svg root');
ok(svg.indexOf('class="obol-engmap"') >= 0, 'SVG root carries obol-engmap class');
ok(svg.indexOf('data-ip="10.10.10.5"') >= 0, 'target group carries data-ip for navigation');
ok(svg.indexOf('em-acc-foothold') >= 0, 'foothold access class applied to a target node');

// 8) empty engagement -> empty-state SVG, no throw
const empty = OBOL.engmap.buildEngagementSvg({ targets: [], facts: [] });
ok(/em-empty/.test(empty), 'empty engagement yields empty-state SVG');

console.log(fail ? ('\nENGMAP SMOKE: ' + fail + ' FAILURES') : '\nENGMAP SMOKE: all passed');
process.exit(fail ? 1 : 0);
