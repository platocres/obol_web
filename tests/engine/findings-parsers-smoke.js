/* Findings-lens parsers (decision-map parse-gap fills, phase 4): the "checks" lane and a few recon
 * observations now read their tool output into a report-grade fact, and a clean run mints nothing. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL;
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function run(cmd, out, aid) { var r = OBOL.parsers.parseActionOutput({ actionId: aid || '', command: cmd, stdout: out, scope: 'host:10.10.10.10', domain: 'acme.local' }); return (r.facts || []).map(function (f) { return f.kind; }); }
function has(cmd, out, aid, kind) { return run(cmd, out, aid).indexOf(kind) >= 0; }

ok(has('curl -I', 'HTTP/1.1 200 OK\nServer: nginx\nX-Frame-Options: DENY', 'check-web-headers', 'http.headers'), 'security-header scan mints http.headers');
ok(has('curl -X OPTIONS', 'HTTP/1.1 200 OK\nAllow: GET, POST, PUT, DELETE', 'check-http-methods', 'http.methods'), 'OPTIONS Allow line mints http.methods');
ok(has('curl -H Origin', 'HTTP/1.1 200\nAccess-Control-Allow-Origin: https://evil.example\nAccess-Control-Allow-Credentials: true', 'check-cors', 'http.cors'), 'reflected CORS mints http.cors');
ok(has('curl', '<!-- TODO: admin password=Sup3r! -->', 'check-web-body', 'http.body'), 'a secret in the page body mints http.body');
ok(has('curl .git/HEAD', 'ref: refs/heads/master', 'check-exposed-files', 'http.exposed'), 'an exposed .git mints http.exposed');
ok(has('sslscan 10.10.10.10', '  SSLv3     enabled\n  Accepted  RC4-SHA', 'check-tls-config', 'tls.info'), 'weak TLS mints tls.info');
ok(!has('sslscan 10.10.10.10', '  TLSv1.2 enabled\n  TLSv1.3 enabled', 'check-tls-config', 'tls.info'), 'a modern TLS config mints nothing');
ok(has('dig axfr acme.local @10.10.10.10', 'acme.local. 3600 IN SOA ns1.acme.local.\nwww.acme.local. 3600 IN A 10.10.10.20\ndev.acme.local. 3600 IN A 10.10.10.21', 'recon-dns', 'dns.zone'), 'a successful AXFR mints dns.zone');
ok(!has('dig axfr acme.local @10.10.10.10', '; Transfer failed.', 'recon-dns', 'dns.zone'), 'a refused AXFR mints nothing');
ok(has('dig TXT', 'acme.local. IN TXT "v=spf1 ~all"\n_dmarc IN TXT "v=DMARC1; p=none"', 'check-dns-email', 'dns.email'), 'SPF/DMARC records mint dns.email');
ok(has('dig CNAME', 'shop.acme.local. CNAME shop.myshopify.com.\nStatus: NoSuchBucket', 'check-subdomain-takeover', 'dns.takeover'), 'a takeover fingerprint mints dns.takeover');
ok(has('ffuf -H Host: FUZZ.acme.local', 'admin  [Status: 200, Size: 3312]', 'vhost-discovery', 'web.vhost'), 'a discovered vhost mints web.vhost');
ok(has('Rubeus.exe ptt', '[*] Ticket applied\nnt authority\\system', 'ticket-reuse', 'lateral.movement'), 'ticket reuse lands lateral.movement');
ok(has('coercer coerce', '[+] Received connection from 10.10.10.10', 'coerce-auth', 'ad.coerced_auth'), 'coercion mints ad.coerced_auth');
ok(has('pygpoabuse', '[+] versionNumber updated\n[+] Scheduled task created', 'gpo-abuse', 'ad.gpo_control'), 'GPO abuse mints ad.gpo_control');
ok(has('impacket-ticketer -extra-sid', 'ExtraSids added', 'sid-history-abuse', 'ad.sid_history'), 'SID-history abuse mints ad.sid_history');

console.log('\nFINDINGS PARSERS SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
