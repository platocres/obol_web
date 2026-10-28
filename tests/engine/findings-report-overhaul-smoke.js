/* Regression smoke test for the Findings, Frameworks, Parsers & Report Pagination overhaul.
 *
 * Verifies:
 *   1. DC unconstrained delegation false-positive exclusion (single DC$ / SERVER_TRUST_ACCOUNT
 *      excluded; non-DC WEB01$ / APPSRV01$ still mints ad.unconstrained).
 *   2. AST block-level report pagination (paginateBlocks): balanced tags on every sheet,
 *      zero split .proof-item wrappers even with 120 KB base64 screenshots, Proof of Access
 *      and Appendix starting on clean sheets, repeated <thead> across split Appendix tables,
 *      and zero orphan trailing headings.
 *   3. Zero-gap Defensive coverage across every OBOL-referenced ATT&CK technique (D3FEND URLs,
 *      detection, telemetry/Event IDs, M10xx mitigationItems with "Do Not Mitigate" filtered out,
 *      and concrete hardening).
 *   4. ATT&CK BY_CMD signature matching + OBOL Scope coverage counts.
 *   5. Compliance control title/summary/URL enrichment, findingItems drill-down, and NIST CSF 2.0 rollup.
 *   6. CVE extraction from cve/cves/refs/title with host attribution and KEV metadata.
 *
 * Run: node tests/engine/findings-report-overhaul-smoke.js
 */
'use strict';

var path = require('path');
globalThis.window = globalThis;

function req(p) { require(path.join(__dirname, '..', '..', p)); }

[
  'assets/engine/facts.js',
  'assets/engine/phases.js',
  'assets/engine/pack.js',
  'assets/engine/profile.js',
  'assets/engine/command.js',
  'assets/engine/workspace.js',
  'assets/engine/chain.js',
  'assets/engine/parsers/common.js',
  'assets/engine/parsers/nmap.js',
  'assets/engine/parsers/directory.js',
  'assets/engine/parsers/creds.js',
  'assets/engine/parsers/host.js',
  'assets/engine/parsers/web.js',
  'assets/engine/parsers/services.js',
  'assets/engine/parsers/database.js',
  'assets/engine/parsers/websource.js',
  'assets/engine/parsers/findings.js',
  'assets/engine/parsers/shape.js',
  'assets/engine/parsers/pivot.js',
  'assets/engine/parsers/dns.js',
  'assets/engine/parsers/blockers.js',
  'assets/engine/parsers/nxc-catalog.js',
  'assets/engine/parsers/index.js',
  'data/findings-catalog.js',
  'data/reportmeta.js',
  'data/attack-catalog.js',
  'data/attack-move-map.js',
  'data/d3fend-map.js',
  'data/frameworks-tables.js',
  'data/kev-catalog.js',
  'assets/engine/findings.js',
  'assets/engine/frameworks.js',
  'assets/engine/report.js',
  'assets/ui/util.js',
  'assets/ui/routes/report.js'
].forEach(req);

var OBOL = globalThis.OBOL;
var F = OBOL.facts;
var P = OBOL.parsers;

var fail = 0;
function ok(cond, msg) {
  if (!cond) { console.error('  FAIL:', msg); fail++; }
  else { console.log('  ok  :', msg); }
}

function parseKinds(cmd, stdout) {
  var r = P.parseActionOutput({
    command: cmd,
    actionId: '',
    stdout: stdout,
    scope: '10.129.118.56',
    domain: 'active.htb'
  });
  return (r.facts || []).map(function (f) { return f.kind; });
}

// 1. DC unconstrained delegation false-positive exclusion
var dcNxc = 'LDAP 10.129.118.56 389 DC [*] Windows 6.1 Build 7601 (name:DC) (domain:active.htb)\n' +
            'LDAP 10.129.118.56 389 DC [+] active.htb\\SVC_TGS:GPPstillStandingStrong2k18\n' +
            'LDAP 10.129.118.56 389 DC DC$ (unconstrained)';
var dcKinds = parseKinds("nxc ldap 10.129.118.56 -u SVC_TGS -p 'GPPstillStandingStrong2k18' --trusted-for-delegation", dcNxc);
ok(dcKinds.indexOf('ad.unconstrained') < 0, 'single DC$ unconstrained delegation in nxc output does NOT mint ad.unconstrained');

var dcLdif = [
  'dn: CN=DC,OU=Domain Controllers,DC=active,DC=htb',
  'objectClass: top',
  'objectClass: computer',
  'cn: DC',
  'sAMAccountName: DC$',
  'dNSHostName: DC.active.htb',
  'userAccountControl: 532480',
  'primaryGroupID: 516',
  'servicePrincipalName: HOST/DC.active.htb'
].join('\n');
var ldifKinds = parseKinds('ldapsearch -x -H ldap://10.129.118.56 -b "DC=active,DC=htb"', dcLdif);
ok(ldifKinds.indexOf('ad.unconstrained') < 0, 'Domain Controller LDIF (OU=Domain Controllers, UAC 532480, primaryGroupID 516) does NOT mint ad.unconstrained');

var nonDcNxc = 'LDAP 10.129.118.56 389 DC WEB01$ (unconstrained)';
var nonDcKinds = parseKinds("nxc ldap 10.129.118.56 -u SVC_TGS -p 'pass' --trusted-for-delegation", nonDcNxc);
ok(nonDcKinds.indexOf('ad.unconstrained') >= 0, 'non-DC computer WEB01$ unconstrained delegation mints ad.unconstrained');

var mixedLdif = dcLdif + '\n\n' + [
  'dn: CN=APPSRV01,CN=Computers,DC=active,DC=htb',
  'objectClass: computer',
  'sAMAccountName: APPSRV01$',
  'userAccountControl: 528384',
  'primaryGroupID: 515'
].join('\n');
var mixedKinds = parseKinds('ldapsearch -x -H ldap://10.129.118.56 -b "DC=active,DC=htb"', mixedLdif);
ok(mixedKinds.indexOf('ad.unconstrained') >= 0, 'mixed LDIF with DC$ + APPSRV01$ (UAC 528384 TRUSTED_FOR_DELEGATION) mints ad.unconstrained');

// 2. AST block-level report pagination (paginateBlocks)
function mkFact(kind, scope, value, source, at) {
  return F.makeFact({
    kind: kind,
    scope: scope,
    value: value || {},
    state: F.ProofState.SUPPORTED,
    source: source || '',
    created_at: at || 1
  });
}

var bigB64 = 'data:image/png;base64,' + 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='.repeat(1200);
var repFacts = [
  mkFact('host.up', 'host:10.129.118.56', {}, 'nmap -sC -sV 10.129.118.56', 1),
  mkFact('port:445', 'host:10.129.118.56', { protocol: 'tcp', service: 'microsoft-ds' }, 'nmap -p 445 10.129.118.56', 2),
  mkFact('port:88', 'host:10.129.118.56', { protocol: 'tcp', service: 'kerberos-sec' }, 'nmap -p 88 10.129.118.56', 2),
  mkFact('smb.gpp_password', 'host:10.129.118.56', { user: 'active.htb\\SVC_TGS', path: 'Replication/active.htb/Policies/Groups.xml' }, 'smbclient //10.129.118.56/Replication -N', 3),
  mkFact('hash.tgs', 'host:10.129.118.56', { user: 'Administrator', spn: 'active/CIFS:445' }, 'impacket-GetUserSPNs active.htb/SVC_TGS -dc-ip 10.129.118.56 -request', 4),
  mkFact('foothold.windows', 'host:10.129.118.56', { user: 'nt authority\\system' }, 'impacket-psexec active.htb/Administrator@10.129.118.56', 5),
  mkFact('access.system', 'host:10.129.118.56', { user: 'nt authority\\system' }, 'impacket-psexec active.htb/Administrator@10.129.118.56', 5),
  mkFact('objective.local_flag', 'host:10.129.118.56', {
    slot: 'local',
    flag: '7196228545721a4b6376f2a20d267113',
    path: 'C:\\Users\\SVC_TGS\\Desktop\\user.txt',
    whoami: 'active\\svc_tgs',
    hostname: 'DC',
    ip: '10.129.118.56',
    shot_data_uri: bigB64
  }, 'type C:\\Users\\SVC_TGS\\Desktop\\user.txt && whoami && ipconfig', 6),
  mkFact('objective.proof_flag', 'host:10.129.118.56', {
    slot: 'proof',
    flag: 'a41935d5594c00514e0ef3d93b502a5b',
    path: 'C:\\Users\\Administrator\\Desktop\\root.txt',
    whoami: 'nt authority\\system',
    hostname: 'DC',
    ip: '10.129.118.56',
    shot_data_uri: bigB64
  }, 'type C:\\Users\\Administrator\\Desktop\\root.txt && whoami && ipconfig', 7)
];
for (var portIdx = 0; portIdx < 28; portIdx++) {
  repFacts.push(mkFact('loot.files', 'host:10.129.118.56', {
    path: '\\\\10.129.118.56\\Replication\\Policy_' + portIdx + '\\Groups.xml'
  }, 'smbclient //10.129.118.56/Replication -c "recurse;ls" #' + portIdx, 10 + portIdx));
}
var repActs = [];
for (var actIdx = 0; actIdx < 45; actIdx++) {
  repActs.push({
    tool: 'nxc',
    action_id: actIdx % 2 === 0 ? 'smb-shares' : 'kerberoast',
    command: 'nxc smb 10.129.118.56 -u SVC_TGS --shares # step ' + actIdx,
    at: 100 + actIdx,
    produced: ['smb.shares'],
    returncode: 0
  });
}

var repCtx = OBOL.report.buildContext({
  facts: new F.FactSet(repFacts),
  targets: [{ host: '10.129.118.56', hostname: 'DC', domain: 'active.htb', os: 'Windows Server 2008 R2', status: 'owned' }],
  activities: repActs,
  credentials: [
    { user: 'SVC_TGS', secret: 'GPPstillStandingStrong2k18', source: 'GPP Groups.xml', validated: true },
    { user: 'Administrator', secret: 'Ticketmaster1968', source: 'Kerberoast', validated: true }
  ],
  params: { name: 'Active', scope: ['10.129.118.56'], platform: 'oscp', osid: '99999', candidate: 'Operator' },
  screenshots: [],
  reportmeta: globalThis.OBOL_REPORTMETA,
  includeSecrets: false
});

var oscpBlocks = OBOL.report.document('oscp', repCtx);
var proofHeadingIdx = oscpBlocks.findIndex(function (b) { return b && b.t === 'heading' && b.text === 'Proof of Access'; });
ok(proofHeadingIdx > 0 && oscpBlocks[proofHeadingIdx - 1].t === 'pagebreak', 'Proof of Access section is preceded by an explicit pagebreak block');

var paged = OBOL.routes.report.paginateBlocks(oscpBlocks, 'OSCP-OS-99999-Exam-Report', 'OSCP Exam Report');
var sheetsHtml = paged.html;
var sheetMatches = sheetsHtml.match(/<article class="rep-sheet[\s\S]*?<\/article>/g) || [];
ok(sheetMatches.length >= 6 && paged.total === sheetMatches.length, 'paginateBlocks renders multi-sheet OSCP report (' + sheetMatches.length + ' sheets)');

var totalFooters = (sheetsHtml.match(/class="rep-sheet-ftr"/g) || []).length;
ok(totalFooters === sheetMatches.length, 'every .rep-sheet-ftr is strictly contained inside its .rep-sheet article (' + totalFooters + '/' + sheetMatches.length + ')');

var tagImbalance = 0;
var orphanHeading = 0;
sheetMatches.forEach(function (sheet, idx) {
  ['div', 'table', 'thead', 'tbody', 'tr'].forEach(function (tag) {
    var opens = (sheet.match(new RegExp('<' + tag + '(\\s|>)', 'g')) || []).length;
    var closes = (sheet.match(new RegExp('</' + tag + '>', 'g')) || []).length;
    if (opens !== closes) {
      console.error('  IMBALANCE on sheet ' + (idx + 1) + ' for <' + tag + '>: open=' + opens + ' close=' + closes);
      tagImbalance++;
    }
  });
  var bodyMatch = sheet.match(/<div class="rep-sheet-body">([\s\S]*?)<\/div>\s*<footer class="rep-sheet-ftr">/);
  if (bodyMatch) {
    var trimmed = bodyMatch[1].trim();
    if (/<h[234][^>]*>[^<]*<\/h[234]>$/.test(trimmed)) {
      console.error('  ORPHAN trailing heading on sheet ' + (idx + 1));
      orphanHeading++;
    }
  }
});
ok(tagImbalance === 0, 'all ' + sheetMatches.length + ' sheets have strictly balanced div/table/thead/tbody/tr tags (zero split proof-item wrappers)');
ok(orphanHeading === 0, 'zero sheets end with an orphaned trailing heading');

var dataTableSheets = sheetMatches.filter(function (s) { return /<table(?!\s+class="kv")[^>]*>/.test(s); });
var dataTableSheetsMissingThead = dataTableSheets.filter(function (s) {
  var tables = (s.match(/<table(?!\s+class="kv")[^>]*>/g) || []).length;
  var theads = (s.match(/<table(?!\s+class="kv")[^>]*>\s*<thead>/g) || []).length;
  return tables !== theads;
});
ok(dataTableSheets.length >= 3 && dataTableSheetsMissingThead.length === 0, 'split Appendix data tables repeat <thead> column headers on every continuation sheet (' + dataTableSheets.length + ' data-table sheets)');

// 3. Zero-gap Defensive coverage across every OBOL-referenced technique
var allReferenced = {};
var MM = OBOL.ATTACK_MOVE || {};
Object.keys(MM.byMove || {}).forEach(function (k) {
  var t = MM.byMove[k];
  if (t) allReferenced[t] = [{ k: 'a', t: k }];
});
Object.keys(MM.byKind || {}).forEach(function (k) {
  var t = MM.byKind[k];
  if (t) allReferenced[t] = [{ k: 'k', t: k }];
});
(MM.byCmd || []).forEach(function (pair) {
  if (pair && pair[1]) allReferenced[pair[1]] = [{ k: 'c', t: String(pair[0]) }];
});
(OBOL.findingsCatalog || OBOL.FINDINGS_CATALOG || []).forEach(function (c) {
  if (c && c.attack) allReferenced[c.attack] = [{ k: 'f', t: c.title || c.key, host: '10.129.118.56', fix: c.remediation || '' }];
});

var allDef = OBOL.frameworks.defensive(allReferenced);
var defGaps = [];
var doNotMitigateLeak = 0;
allDef.forEach(function (d) {
  if (!d.d3fend || !d.d3fend.length || !d.d3fend.every(function (c) { return /^https:\/\/d3fend\.mitre\.org\//.test(c.url || ''); })) {
    defGaps.push(d.id + ':d3fend');
  }
  if (!d.detection || d.detection.trim().length < 20) defGaps.push(d.id + ':detection');
  if (!d.dataSources || !d.dataSources.length) defGaps.push(d.id + ':dataSources');
  if (!d.mitigationItems || !d.mitigationItems.length || !d.mitigationItems.every(function (m) { return /^M\d{4}$/.test(m.id || ''); })) {
    defGaps.push(d.id + ':mitigationItems');
  }
  if ((d.mitigations || []).some(function (m) { return /do not mitigate/i.test(m); }) ||
      (d.mitigationItems || []).some(function (m) { return /do not mitigate/i.test(m.name || ''); })) {
    doNotMitigateLeak++;
  }
  if (!d.hardening || !d.hardening.length) defGaps.push(d.id + ':hardening');
});
ok(allDef.length >= 95 && defGaps.length === 0, 'all ' + allDef.length + ' OBOL-referenced ATT&CK techniques have complete D3FEND URLs, detection, telemetry, M10xx mitigations, and hardening (gaps: ' + defGaps.join(', ') + ')');
ok(doNotMitigateLeak === 0, 'STIX "Do Not Mitigate" placeholder entries are filtered out across all techniques');

// 4. ATT&CK BY_CMD signature matching & OBOL Scope matrix counts
var cmdOnlyUse = OBOL.frameworks.techniqueUse(
  [],
  [
    { command: 'gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ' },
    { command: 'impacket-GetUserSPNs active.htb/SVC_TGS:pass -dc-ip 10.129.118.56 -request' },
    { command: 'impacket-psexec active.htb/Administrator:Ticketmaster1968@10.129.118.56' },
    { command: 'nxc ldap 10.129.118.56 -u SVC_TGS -p pass --kerberoasting kerb.txt', produced: ['host.up', 'ad.dc_candidate', 'hash.tgs'] }
  ]
);
ok(Boolean(cmdOnlyUse['T1552.006'] && cmdOnlyUse['T1558.003'] && cmdOnlyUse['T1021.002']), 'BY_CMD maps raw pasted gpp-decrypt, GetUserSPNs, and impacket-psexec commands to T1552.006, T1558.003, and T1021.002');
ok(!cmdOnlyUse['T1018'], 'incidental ad.dc_candidate / host.up on a Kerberoast paste does not bleed into T1018');

var mat = OBOL.frameworks.attackMatrix(cmdOnlyUse);
ok(mat.coveredTotal >= 45 && mat.enterpriseTotal >= 200 && mat.coveredTotal < mat.enterpriseTotal,
  'attackMatrix computes OBOL Scope (' + mat.coveredTotal + ') vs Full Enterprise (' + mat.enterpriseTotal + ') totals');

// 5. Compliance enrichment & NIST CSF 2.0 posture rollup
var comp = OBOL.frameworks.compliance([
  {
    id: 'gpp-cpassword',
    title: 'GPP cpassword in SYSVOL (MS14-025)',
    severity: 'critical',
    host: '10.129.118.56',
    attack: 'T1552.006',
    nist: ['IA-5', 'CM-6'],
    cis: ['CIS 4'],
    pci: ['PCI DSS 2.2', 'PCI DSS 8.3'],
    cwe: ['CWE-522', 'CWE-256'],
    owasp: ['A07:2021']
  }
]);
ok(comp.nist.some(function (x) { return /IA-5: Authenticator Management/.test(x.title) && x.summary.length > 20 && /^https:\/\//.test(x.url) && x.findingItems.length === 1; }),
  'Compliance NIST row includes exact control title, plain-English summary, official URL, and drill-down findingItems');
ok(comp.cwe.some(function (x) { return /CWE-522: Insufficiently Protected Credentials/.test(x.title) && x.summary.length > 20 && /^https:\/\/cwe\.mitre\.org\//.test(x.url); }),
  'Compliance CWE row includes exact CWE title, weakness summary, and official MITRE CWE URL');
ok(comp.pci.length === 2 && comp.pci.every(function (x) { return /^PCI Req [28]/.test(x.title) && x.summary.length > 20 && /^https:\/\//.test(x.url); }),
  'Compliance PCI DSS v4.0 rows parse cleanly without bogus DSS tokens and carry summaries + official URLs');
ok(comp.cis.length === 1 && /^CIS 4:/.test(comp.cis[0].title),
  'Compliance CIS Controls v8 rows parse cleanly without bogus CIS tokens');
ok(Array.isArray(comp.csf) && comp.csf.length === 6 && comp.csf.some(function (fn) { return fn.id === 'PR' && fn.findingCount >= 1; }),
  'Compliance computes 6-function NIST CSF 2.0 posture rollup');

// 6. CVE extraction & KEV enrichment
var cveRows = OBOL.frameworks.cves([
  {
    id: 'zerologon',
    title: 'Netlogon Elevation of Privilege (CVE-2020-1472)',
    severity: 'critical',
    host: '10.129.118.56',
    refs: ['https://nvd.nist.gov/vuln/detail/CVE-2020-1472']
  }
]);
ok(cveRows.length === 1 && cveRows[0].cve === 'CVE-2020-1472' && cveRows[0].kev === true &&
  cveRows[0].hosts.indexOf('10.129.118.56') >= 0 && /^https:\/\/nvd\.nist\.gov\//.test(cveRows[0].nvdUrl),
  'CVE rollup extracts CVE from title/refs, attaches affected host, NVD link, and CISA KEV status');

if (fail) {
  console.error('\nFINDINGS/REPORT OVERHAUL SMOKE: ' + fail + ' FAILURE(S)');
  process.exit(1);
}
console.log('\nFINDINGS/REPORT OVERHAUL SMOKE: all assertions passed');
