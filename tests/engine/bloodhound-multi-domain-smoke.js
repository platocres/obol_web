/* Smoke test for multi-domain BloodHound engine, AD graph layout, and Domain route helpers. */
'use strict';

require('../../assets/engine/facts.js');
require('../../assets/engine/bloodhound.js');
require('../../assets/ui/bhgraph.js');

const OBOL = globalThis.OBOL;
const BH = OBOL.bloodhound;
const BHG = OBOL.bhgraph;

// Minimal stub for OBOL.util so routes/domain.js can load in Node
OBOL.util = {
  esc: function (s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); },
  attr: function (s) { return String(s == null ? '' : s).replace(/"/g, '&quot;'); },
  on: function () {},
  copy: function () { return Promise.resolve(true); },
  toast: function () {}
};
require('../../assets/ui/routes/domain.js');
const DomRoute = OBOL.routes.domain;

let fail = 0;
function ok(cond, msg) {
  if (!cond) { console.error('  FAIL:', msg); fail++; }
  else { console.log('  ok  :', msg); }
}

// 1. Multi-domain forest + trusts + GPO -> OU -> Child propagation + SID History + cross-domain collisions
const forestPreset = DomRoute.getSamplePreset('forest');
const forestSummary = BH.ingestObjects(forestPreset.data);

ok(Array.isArray(forestSummary.domains) && forestSummary.domains.length === 2, 'multi-domain: summary.domains captures both CORP.LOCAL and DEV.CORP.LOCAL');
ok(forestSummary.domains.indexOf('CORP.LOCAL') >= 0 && forestSummary.domains.indexOf('DEV.CORP.LOCAL') >= 0, 'multi-domain: both domain names present');
ok(Array.isArray(forestSummary.trusts) && forestSummary.trusts.length === 2, 'multi-domain: domain trusts parsed from domains.json');
ok(forestSummary.trusts[0].target_domain === 'DEV.CORP.LOCAL' && forestSummary.trusts[0].sid_filtering === false, 'multi-domain: trust direction and sid_filtering parsed');

// Domain Admins concatenated across both domains (ADMIN, BACKUP_ADM, DEV_LEAD)
ok(forestSummary.domain_admins.indexOf('BACKUP_ADM') >= 0 && forestSummary.domain_admins.indexOf('DEV_LEAD') >= 0,
   'multi-domain: domain_admins concatenates members across all domains instead of overwriting');
ok(forestSummary._graph.da_sids.length === 2 && forestSummary._graph.domain_sids.length === 2,
   'multi-domain: graph tracks all da_sids and domain_sids');

// foreign_principals: DEV_LEAD@DEV.CORP.LOCAL in DOMAIN ADMINS@DEV.CORP.LOCAL is NOT foreign,
// whereas DEV_LEAD@DEV.CORP.LOCAL in EXCHANGE WINDOWS PERMISSIONS@CORP.LOCAL IS foreign.
ok(forestSummary.foreign_principals.length === 1 && /DEV_LEAD/.test(forestSummary.foreign_principals[0]) && /EXCHANGE WINDOWS PERMISSIONS/.test(forestSummary.foreign_principals[0]),
   'multi-domain: foreign_principals flags cross-domain membership without false positives on secondary domain groups');

// GPO -> OU -> Child propagation
ok(forestSummary.gpo_abuse.length >= 1 && /SERVER_POLICY_GPO/.test(forestSummary.gpo_abuse[0]) && /BACKUP_ADM/.test(forestSummary.gpo_abuse[0]),
   'GPO abuse: GPO linked to OU propagates control to child user BACKUP_ADM');
const gpoPaths = BH.ownedPaths(forestSummary, ['SVC_DEPLOY@CORP.LOCAL']);
ok(gpoPaths.paths.length >= 1 && gpoPaths.paths[0].some(function (h) { return h.edge === 'GPOAbuse'; }),
   'GPO abuse: ownedPaths derives path through SERVER_POLICY_GPO -> GPOAbuse -> BACKUP_ADM -> DOMAIN ADMINS');

// SID History
ok(forestSummary.sid_history.length >= 1, 'SID history: summary.sid_history records HasSIDHistory edge');
const sidHistPaths = BH.ownedPaths(forestSummary, ['ADMIN@DEV.CORP.LOCAL']);
ok(sidHistPaths.paths.some(function (p) { return p.some(function (h) { return h.edge === 'HasSIDHistory'; }); }),
   'SID history: ADMIN@DEV.CORP.LOCAL reaches ENTERPRISE ADMINS@CORP.LOCAL via HasSIDHistory');

// Cross-domain name collision resolution: ADMIN@CORP.LOCAL vs ADMIN@DEV.CORP.LOCAL
const sidCorpAdmin = BH.resolvePrincipalSid(forestSummary._graph, 'ADMIN@CORP.LOCAL');
const sidDevAdmin = BH.resolvePrincipalSid(forestSummary._graph, 'ADMIN@DEV.CORP.LOCAL');
ok(sidCorpAdmin && sidDevAdmin && sidCorpAdmin !== sidDevAdmin, 'collision resolution: ADMIN@CORP.LOCAL and ADMIN@DEV.CORP.LOCAL resolve to distinct SIDs');
const plistForest = BH.principalList(forestSummary, { types: ['users'] });
ok(plistForest.some(function (p) { return p.short === 'ADMIN@CORP.LOCAL'; }) && plistForest.some(function (p) { return p.short === 'ADMIN@DEV.CORP.LOCAL'; }),
   'collision resolution: principalList preserves @DOMAIN on colliding short names');

// 2. Delegation, RBCD, gMSA, LAPS & AdminTo -> Computer -> HasSession -> User traversal
const delPreset = DomRoute.getSamplePreset('delegation');
const delSummary = BH.ingestObjects(delPreset.data);

ok(delSummary.constrained_delegation.length >= 1 && /SQL_PROXY/.test(delSummary.constrained_delegation[0]),
   'delegation: constrained_delegation parsed and resolved to target computer');
ok(delSummary.rbcd_targets.length >= 1 && /WEB_SVC/.test(delSummary.rbcd_targets[0]) && /WS01/.test(delSummary.rbcd_targets[0]),
   'delegation: RBCD AllowedToAct parsed');
ok(delSummary.gmsa_accounts.length >= 1 && delSummary.laps_computers.length >= 1,
   'delegation: gMSA and LAPS accounts recorded in census');

const sessionPaths = BH.ownedPaths(delSummary, ['WEB_SVC@LAB.LOCAL']);
ok(sessionPaths.paths.length >= 1, 'traversal: WEB_SVC derives paths to Domain Admins in delegation topology');
ok(sessionPaths.paths.some(function (p) {
  return p.some(function (h) { return h.edge === 'HasSession'; }) && p.some(function (h) { return h.edge === 'AdminTo' || h.edge === 'AllowedToAct'; });
}), 'traversal: pathfinder walks Computer -> HasSession -> DA_OPER -> MemberOf -> DOMAIN ADMINS');

// 3. Missing domains.json fallback (infer domain name and domain SID from users + groups)
const SPARSE_DOM = 'S-1-5-21-999999999-888888888-777777777';
const sparseSummary = BH.parseJson([
  {
    name: 'users.json',
    text: JSON.stringify({
      meta: { type: 'users', count: 2 },
      data: [
        { ObjectIdentifier: SPARSE_DOM + '-500', Properties: { name: 'ADMINISTRATOR@SPARSE.LOCAL', enabled: true } },
        { ObjectIdentifier: SPARSE_DOM + '-1101', Properties: { name: 'LOWPRIV@SPARSE.LOCAL', enabled: true } }
      ]
    })
  },
  {
    name: 'groups.json',
    text: JSON.stringify({
      meta: { type: 'groups', count: 1 },
      data: [
        {
          ObjectIdentifier: SPARSE_DOM + '-512',
          Properties: { name: 'DOMAIN ADMINS@SPARSE.LOCAL' },
          Members: [{ ObjectIdentifier: SPARSE_DOM + '-500', ObjectType: 'User' }],
          Aces: [{ PrincipalSID: SPARSE_DOM + '-1101', PrincipalType: 'User', RightName: 'AddSelf' }]
        }
      ]
    })
  }
]);
ok(sparseSummary.domain === 'SPARSE.LOCAL' && sparseSummary.domains.indexOf('SPARSE.LOCAL') >= 0,
   'missing domains.json: infers domain name SPARSE.LOCAL from principal names');
ok(sparseSummary._graph.domain_sid === SPARSE_DOM && sparseSummary._graph.domain_sids.indexOf(SPARSE_DOM) >= 0,
   'missing domains.json: infers domain SID prefix from principal SIDs');
const sparsePaths = BH.ownedPaths(sparseSummary, ['LOWPRIV']);
ok(sparsePaths.paths.length === 1 && sparsePaths.paths[0][0].edge === 'AddSelf',
   'missing domains.json: derives owned->DA path without domains.json');

// 4. Graph projection & bhgraph layout/geometry (goal right-alignment, viewBox min size, t=0.35 edge label)
const multiLenGraph = BH.pathsToGraph([
  [{ from: 'USER1', edge: 'AddSelf', to: 'DOMAIN ADMINS', to_kind: 'groups' }],
  [
    { from: 'USER2', edge: 'MemberOf', to: 'OPS_GROUP', to_kind: 'groups' },
    { from: 'OPS_GROUP', edge: 'GenericAll', to: 'SVC_ACCT', to_kind: 'users' },
    { from: 'SVC_ACCT', edge: 'WriteDacl', to: 'CORP.LOCAL', to_kind: 'domains' }
  ]
], ['USER1', 'USER2'], forestSummary);

const daNode = multiLenGraph.nodes.find(function (n) { return n.id === 'DOMAIN ADMINS'; });
const domNode = multiLenGraph.nodes.find(function (n) { return n.id === 'CORP.LOCAL'; });
const svcNode = multiLenGraph.nodes.find(function (n) { return n.id === 'SVC_ACCT'; });
ok(daNode && domNode && daNode.goal === true && domNode.goal === true, 'pathsToGraph: marks terminal nodes as goals');
ok(daNode.depth === domNode.depth && daNode.depth > svcNode.depth, 'pathsToGraph: right-aligns all goal nodes to the rightmost depth column');

const pos = BHG.layout(multiLenGraph);
ok(pos.width >= 720 && pos.height >= 240, 'bhgraph.layout: enforces minimum viewBox dimensions (720x240)');
ok(pos['DOMAIN ADMINS'].x === pos['CORP.LOCAL'].x && pos['DOMAIN ADMINS'].x > pos['SVC_ACCT'].x,
   'bhgraph.layout: places all goal nodes in the rightmost X column');

const longEdgeD = BHG.edgePath(pos, { from: 'USER1', to: 'DOMAIN ADMINS' });
ok(longEdgeD.indexOf(' Q') > 0, 'bhgraph.edgePath: curves multi-column edges with quadratic Bezier arc');
const lblPt = BHG.edgeLabelPoint(pos, 'USER1', 'DOMAIN ADMINS', 0);
const col1X = pos['OPS_GROUP'].x + 75;
ok(Math.abs(lblPt.x - col1X) > 20, 'bhgraph.edgeLabelPoint: places multi-column label at t=0.35 clear of intermediate column nodes');
ok(BHG.ICONS.ou && BHG.ICONS.container && BHG.ICONS.certtemplate && BHG.ICONS.ca && BHG.ICONS.gpo,
   'bhgraph.ICONS: includes icons for ou, container, certtemplate, ca, and gpo');

// 5. Fact minting (toFacts / summaryToFacts)
const forestFacts = BH.toFacts(forestSummary, gpoPaths, 'domain:CORP.LOCAL');
const delFacts = BH.toFacts(delSummary, sessionPaths, 'domain:LAB.LOCAL');
const allKinds = forestFacts.concat(delFacts).map(function (f) { return f.kind; });
['ad.graph.collected', 'ad.domain_known', 'ad.domain_sid', 'ad.trusts', 'ad.foreign_principals',
 'ad.gpo_abuse', 'ad.sid_history', 'ad.delegation', 'ad.rbcd', 'ad.gmsa', 'ad.laps', 'ad.attack_paths', 'ad.acl_lead'].forEach(function (k) {
  ok(allKinds.indexOf(k) >= 0, 'toFacts: mints ' + k);
});

// 6. Multi-hop identity handoff in domain.js pathCommandChain
const handoffChain = DomRoute.pathCommandChain([
  { from: 'WEB_SVC', edge: 'ReadGMSAPassword', to: 'GMSA_APP$', to_kind: 'users' },
  { from: 'GMSA_APP$', edge: 'ForceChangePassword', to: 'SQL_PROXY', to_kind: 'users' },
  { from: 'SQL_PROXY', edge: 'AllowedToDelegate', to: 'DC01.LAB.LOCAL', to_kind: 'computers' }
], { dc: '10.10.10.5', pw: 'StartPass1' }, 'LAB.LOCAL', 'WEB_SVC');

ok(handoffChain.steps.length === 3, 'pathCommandChain: generates steps for all 3 non-MemberOf hops');
ok(handoffChain.steps[0].actor === 'WEB_SVC' && handoffChain.steps[1].actor === 'GMSA_APP$' && handoffChain.steps[2].actor === 'SQL_PROXY',
   'pathCommandChain: hands off active principal identity across ReadGMSAPassword -> ForceChangePassword -> AllowedToDelegate');
ok(handoffChain.finalYou === 'SQL_PROXY', 'pathCommandChain: tracks final identity after multi-hop takeover');

console.log(fail ? ('\nBLOODHOUND MULTI-DOMAIN SMOKE: ' + fail + ' FAILURES') : '\nBLOODHOUND MULTI-DOMAIN SMOKE: all passed');
process.exit(fail ? 1 : 0);
