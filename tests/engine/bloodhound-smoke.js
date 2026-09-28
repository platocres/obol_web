/* Node smoke test for the ported BloodHound engine (assets/engine/bloodhound.js).
 *
 * Synthesizes a small BloodHound-CE-shaped collection (a domain, a few users incl. one
 * Kerberoastable + one AS-REP-roastable, a Domain Admins group, and an ACL edge giving a
 * low-priv user GenericAll over the domain object), runs parse (the JSON path — no zip) →
 * deriveCensus → ownedPaths with an owned user, and asserts the census finds the roastable
 * users and that an owned→Domain-Admins path is derived. Also exercises pathsToGraph,
 * domainView, domainReportHtml and toFacts. Fixtures are inline. Run:
 *
 *     node tests/engine/bloodhound-smoke.js
 */
'use strict';

// The engine modules attach to globalThis; facts.js must load before bloodhound.js.
require('../../assets/engine/facts.js');
require('../../assets/engine/bloodhound.js');
const OBOL = globalThis.OBOL;
const BH = OBOL.bloodhound;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// ── inline fixtures — BloodHound-CE shape (lowercase Properties, ObjectIdentifier SIDs) ──────
// A synthetic domain SID prefix (S-1-5-21-<a>-<b>-<c>) so RIDs resolve to well-known labels.
const DOM = 'S-1-5-21-1111111111-2222222222-3333333333';

const domainsJson = {
  meta: { type: 'domains', count: 1, version: 5 },
  data: [{
    ObjectIdentifier: DOM,
    Properties: { name: 'CORP.LOCAL', domain: 'CORP.LOCAL', highvalue: true },
    Aces: [
      // low-priv user JEFF holds GenericAll over the domain object → can grant self DCSync,
      // and (for the pathfinder) a direct control edge owned→domain (a goal).
      { PrincipalSID: DOM + '-1105', PrincipalType: 'User', RightName: 'GenericAll', IsInherited: false },
      // a service account with real replication rights → a DCSync principal by the census rule.
      { PrincipalSID: DOM + '-1106', PrincipalType: 'User', RightName: 'GetChanges', IsInherited: false },
      { PrincipalSID: DOM + '-1106', PrincipalType: 'User', RightName: 'GetChangesAll', IsInherited: false },
    ],
  }],
};

const usersJson = {
  meta: { type: 'users', count: 5 },
  data: [
    { ObjectIdentifier: DOM + '-500', Properties: { name: 'ADMINISTRATOR@CORP.LOCAL', enabled: true, highvalue: true } },
    // Kerberoastable: hasspn true
    { ObjectIdentifier: DOM + '-1103', Properties: { name: 'SQLSVC@CORP.LOCAL', enabled: true, hasspn: true } },
    // AS-REP roastable: dontreqpreauth true
    { ObjectIdentifier: DOM + '-1104', Properties: { name: 'HELPDESK@CORP.LOCAL', enabled: true, dontreqpreauth: true } },
    // the account we OWN — a low-priv user with GenericAll on the domain (see domainsJson Aces)
    { ObjectIdentifier: DOM + '-1105', Properties: { name: 'JEFF@CORP.LOCAL', enabled: true, passwordnotreqd: true } },
    // a replication-rights service account (DCSync census)
    { ObjectIdentifier: DOM + '-1106', Properties: { name: 'REPLSVC@CORP.LOCAL', enabled: true, pwdneverexpires: true } },
    // a disabled account that is also AS-REP flagged — must NOT count as a live weakness for pwd flags,
    // but AS-REP/kerberoast are reported regardless of enabled in the Python, so keep it simple/enabled above.
  ],
};

const groupsJson = {
  meta: { type: 'groups', count: 2 },
  data: [
    {
      ObjectIdentifier: DOM + '-512',
      Properties: { name: 'DOMAIN ADMINS@CORP.LOCAL', highvalue: true },
      Members: [{ ObjectIdentifier: DOM + '-500', ObjectType: 'User' }],
    },
    {
      ObjectIdentifier: DOM + '-519',
      Properties: { name: 'ENTERPRISE ADMINS@CORP.LOCAL', highvalue: true },
      Members: [{ ObjectIdentifier: DOM + '-500', ObjectType: 'User' }],
    },
  ],
};

const computersJson = {
  meta: { type: 'computers', count: 1 },
  data: [
    {
      ObjectIdentifier: DOM + '-1000',
      Properties: { name: 'DC01.CORP.LOCAL', enabled: true, unconstraineddelegation: true },
      // Domain Users (broad, RID 513) is local admin here → an AdminTo finding
      LocalAdmins: { Collected: true, Results: [{ ObjectIdentifier: DOM + '-513', ObjectType: 'Group' }] },
    },
  ],
};

const files = [
  { name: '20260101_users.json', text: JSON.stringify(usersJson) },
  { name: '20260101_groups.json', text: JSON.stringify(groupsJson) },
  { name: '20260101_computers.json', text: JSON.stringify(computersJson) },
  { name: '20260101_domains.json', text: JSON.stringify(domainsJson) },
];

// ── run: parse (async, JSON path) → asserts ──────────────────────────────────────────────────
BH.parse(files).then(function (summary) {
  console.log('Parsed', summary.files.length, 'files; domain =', summary.domain, '; users =', summary.users);

  ok(summary.domain === 'CORP.LOCAL', 'domain parsed (CORP.LOCAL)');
  ok(summary.users === 5, 'user count = 5 (got ' + summary.users + ')');
  ok(summary.computers.indexOf('DC01.CORP.LOCAL') >= 0, 'computer DC01 collected');

  // census: roastable users found
  ok(summary.kerberoastable.indexOf('SQLSVC@CORP.LOCAL') >= 0, 'Kerberoastable finds SQLSVC (hasSPN)');
  ok(summary.asrep_roastable.indexOf('HELPDESK@CORP.LOCAL') >= 0, 'AS-REP finds HELPDESK (dontReqPreAuth)');
  ok(summary.password_not_required.indexOf('JEFF@CORP.LOCAL') >= 0, 'password-not-required finds JEFF');
  ok(summary.pwd_never_expires.indexOf('REPLSVC@CORP.LOCAL') >= 0, 'pwd-never-expires finds REPLSVC');

  // Domain Admins members resolved to a readable label (RID 500 → Administrator)
  ok(summary.domain_admins.length >= 1, 'Domain Admins has a member');
  // the collection's own name wins over the well-known RID (Python _resolve_sid), so the RID-500
  // member resolves to the user's own (uppercased) name, not the well-known "Administrator".
  ok(summary.domain_admins.indexOf('ADMINISTRATOR') >= 0, 'DA member SID resolved via the collection name map');

  // DCSync principals: REPLSVC (GetChanges+GetChangesAll) and JEFF (GenericAll → can grant) on the domain
  ok(summary.dcsync_principals.indexOf('REPLSVC') >= 0, 'DCSync census finds REPLSVC (replication rights)');
  ok(summary.dcsync_principals.indexOf('JEFF') >= 0, 'DCSync census finds JEFF (GenericAll → can grant DCSync)');

  // unconstrained delegation + broad AdminTo
  ok(summary.unconstrained_delegation.indexOf('DC01.CORP.LOCAL') >= 0, 'unconstrained delegation finds DC01');
  ok(summary.admin_to.some(function (s) { return /Domain Users/.test(s) && /DC01/.test(s); }),
     'AdminTo finds Domain Users -> DC01 (broad local admin)');

  // deriveCensus is idempotent (parse already called it) — a second call must not corrupt the census.
  const before = JSON.stringify(summary.domain_admins);
  BH.deriveCensus(summary);
  ok(JSON.stringify(summary.domain_admins) === before, 'deriveCensus is idempotent on already-resolved census');

  // ── ownedPaths: JEFF (owned) → GenericAll → domain object (a goal) ─────────────────────────
  const owned = BH.ownedPaths(summary, ['JEFF']);
  console.log('  ownedPaths: ' + owned.paths.length + ' path(s); shortest length ='
    + (owned.paths[0] ? owned.paths[0].length : 0));
  ok(owned.paths.length > 0, 'an owned->goal path is derived for JEFF');
  const shortest = owned.paths[0];
  const goalHop = shortest[shortest.length - 1];
  ok(/CORP.LOCAL/i.test(goalHop.to) || goalHop.to === 'CORP.LOCAL', 'shortest path ends at the domain/DA goal (got ' + goalHop.to + ')');
  ok(owned.first && owned.first.edge === 'GenericAll', 'first abusable edge on the path is GenericAll (got ' + (owned.first && owned.first.edge) + ')');

  // census-only graceful path: no owned principals → no path derivation, no throw
  const none = BH.ownedPaths(summary, []);
  ok(none.paths.length === 0 && none.first === null, 'no owned principals => census-only (no path), graceful');

  // unknown owned principal => also graceful empty
  const bogus = BH.ownedPaths(summary, ['NOBODY']);
  ok(bogus.paths.length === 0, 'unknown owned principal => no path, graceful');

  // ── pathsToGraph over the derived paths (via domainView's structured hops) ─────────────────
  const view = BH.domainView(summary, ['JEFF']);
  ok(view.collected === true, 'domainView reports collected=true');
  ok(/path\(s\) from a principal you own/.test(view.analysis.headline), 'analysis headline names the owned->DA route');
  ok(view.analysis.graph.nodes.length >= 2, 'pathsToGraph produced nodes (' + view.analysis.graph.nodes.length + ')');
  ok(view.analysis.graph.edges.length >= 1, 'pathsToGraph produced edges (' + view.analysis.graph.edges.length + ')');
  const kerbSec = view.sections.find(function (s) { return s.id === 'kerberoast'; });
  ok(kerbSec && kerbSec.count >= 1, 'domainView kerberoast section is populated');
  ok(kerbSec && kerbSec.commands.length >= 1, 'domainView section carries copy-paste commands');

  // ── ctx fill: DC/host/lhost/secret from the engagement replace the operator placeholders ─────
  const filled = BH.domainView(summary, ['ADMINISTRATOR'],
    { dc: '10.0.0.5', host: '10.0.0.5', lhost: '10.0.0.9', secret: '-H ' + 'f'.repeat(32) });
  const winrm = filled.sections.find(function (s) { return s.id === 'winrm'; });
  ok(winrm && winrm.commands[0].indexOf('nxc winrm 10.0.0.5 ') === 0, 'ctx fills the DC/host into a query command');
  ok(winrm && winrm.commands[0].indexOf('-H ' + 'f'.repeat(32)) !== -1, 'ctx fills the owned secret (-H hash)');
  ok(winrm && winrm.commands.every(function (c) { return c.indexOf('<HOST>') === -1; }), 'no <HOST> placeholder survives when a host is known');
  const uncon = filled.sections.find(function (s) { return s.id === 'unconstrained'; });
  ok(!uncon || uncon.commands.every(function (c) { return c.indexOf('<YOUR_IP>') === -1; }), 'ctx fills <YOUR_IP> from lhost');
  // without ctx, placeholders remain for the operator to fill
  const bare = BH.domainView(summary, ['ADMINISTRATOR']);
  const bareWinrm = bare.sections.find(function (s) { return s.id === 'winrm'; });
  ok(bareWinrm && bareWinrm.commands[0].indexOf('<HOST>') !== -1, 'without ctx, <HOST> placeholder is preserved');

  // ── toFacts: conservative fact minting ─────────────────────────────────────────────────────
  const facts = BH.toFacts(summary, owned, 'domain:CORP.LOCAL');
  const kinds = facts.map(function (f) { return f.kind; });
  console.log('  facts minted:', kinds.join(', '));
  ok(kinds.indexOf('ad.graph.collected') >= 0, 'mints ad.graph.collected');
  ok(kinds.indexOf('ad.domain_known') >= 0, 'mints ad.domain_known');
  ok(kinds.indexOf('ad.attack_paths') >= 0, 'mints ad.attack_paths (a LEAD)');
  ok(kinds.indexOf('ad.control_paths') < 0, 'does NOT mint ad.control_paths (collection != access)');
  const apFact = facts.find(function (f) { return f.kind === 'ad.attack_paths'; });
  ok(apFact && apFact.value.evidence === 'reachability', 'ad.attack_paths evidence=reachability');
  ok(apFact && apFact.value.path && apFact.value.paths && apFact.value.goal, 'ad.attack_paths shape has path/paths/goal');
  ok(apFact && apFact.value.first_action && apFact.value.first_action.edge === 'GenericAll', 'ad.attack_paths carries first_action');
  const gc = facts.find(function (f) { return f.kind === 'ad.graph.collected'; });
  ok(gc && gc.value.users === 5 && gc.value.domain_admins >= 1, 'ad.graph.collected carries census counts');
  // facts are real OBOL.facts
  ok(gc && gc.state === OBOL.facts.ProofState.SUPPORTED && gc.source === 'bloodhound ingest', 'facts are proper OBOL.facts');

  // ── domainReportHtml: self-contained, printable ─────────────────────────────────────────────
  const html = BH.domainReportHtml(summary, view);
  ok(/^<!doctype html>/i.test(html), 'report is a full HTML document');
  ok(html.indexOf('CORP.LOCAL') >= 0, 'report names the domain');
  ok(html.indexOf('Attack analysis') >= 0, 'report includes the attack-analysis section');
  ok(html.indexOf('SQLSVC') >= 0, 'report lists the Kerberoastable account');
  ok(html.indexOf('<style>') >= 0 && html.indexOf('--accent') >= 0, 'report has embedded CSS (self-contained)');
  ok(html.indexOf('not a claim it was walked') >= 0, 'report keeps the conservative footer');

  // dropGraph removes the transient graph
  BH.dropGraph(summary);
  ok(summary._graph === undefined, 'dropGraph removes the transient _graph');

  console.log(fail ? ('\nBLOODHOUND SMOKE: ' + fail + ' FAILURES') : '\nBLOODHOUND SMOKE: all passed');
  process.exit(fail ? 1 : 0);
}).catch(function (err) {
  console.error('SMOKE ERROR:', err && err.stack || err);
  process.exit(1);
});
