/* Report-only gating: an info-severity "writeup check" whose produced fact enables nothing (SPF/DMARC,
 * security headers, TLS, CORS, HTTP methods) must NEVER headline a box you're actively working. It is
 * still offered — just pulled into its own group — so the coach's top "Ready now" move is always a real
 * step. This locks the fix for the Hub/Coach showing "Email DNS Review (SPF/DMARC)" as the #1 move on a
 * freshly-enumerated AD box. OBOL.pack.isReportOnly is the single classifier every screen shares. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
var fs = require('fs'), path = require('path');
var OBOL = globalThis.OBOL, PK = OBOL.pack, F = OBOL.facts;
var pdir = path.join(__dirname, '..', '..', 'data', 'packs');
var PACK = PK.loadPacks(fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); })
  .map(function (f) { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } }));

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function byId(id) { return PACK.filter(function (a) { return a.id === id; })[0]; }

// ---- the classifier itself ----
ok(PK.isReportOnly(byId('check-dns-email'), PACK), 'check-dns-email (SPF/DMARC, info, produces dead-end dns.email) is report-only');
ok(PK.isReportOnly(byId('check-web-headers'), PACK), 'check-web-headers (info, produces dead-end http.headers) is report-only');
ok(byId('ad-user-enum') && !PK.isReportOnly(byId('ad-user-enum'), PACK), 'a real enum move (ad-user-enum) is NOT report-only');
ok(byId('nmap-version-scripts') && !PK.isReportOnly(byId('nmap-version-scripts'), PACK), 'the nmap version scan is NOT report-only');

// ---- Forest after a null SMB session: domain is known, so the SPF/DMARC check is eligible. It must not lead. ----
var kinds = ['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick',
  'port:88', 'port:139', 'port:389', 'port:445', 'port:464', 'port:636', 'port:3268', 'port:5985',
  'smb.reachable', 'ldap.reachable', 'kerberos.reachable', 'winrm.reachable',
  'ad.dc_candidate', 'ad.domain_known', 'smb.null_session'];
var flist = kinds.map(function (k, i) { return F.makeFact({ kind: k, scope: { target: '10.129.95.210' }, source: 'scan', created_at: 1700000000000 + i }); });
var fset = new F.FactSet(flist);
var ranked = PK.rankActions(fset, PACK, {});
// the "ready now" headline set the coach/hub actually show: report-only excluded, frontier-ready first
var onFlow = ranked.filter(function (a) { return !PK.isReportOnly(a, PACK); })
  .filter(function (a) { return OBOL.phases.prematurity(a, fset) === 0; });

ok(onFlow.length > 0, 'the box has ready moves');
ok(onFlow[0].id !== 'check-dns-email', 'the #1 ready move is NOT the SPF/DMARC review (got ' + onFlow[0].id + ')');
ok(!/^check-/.test(onFlow[0].id), 'the #1 ready move is a real step, not any info-check (got ' + onFlow[0].id + ')');
ok(onFlow.slice(0, 8).every(function (a) { return a.id !== 'check-dns-email'; }), 'the SPF/DMARC review does not appear anywhere in the top-8 headline set');
ok(ranked.some(function (a) { return a.id === 'check-dns-email'; }), 'the SPF/DMARC review is still offered (present in the full ranking), just not headlining');

console.log('\nRANKER REPORT-ONLY: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
