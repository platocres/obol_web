/* DNS forward-resolution output (Corpus Mining Stage 5, parser hardening). The Stage 2 blind-spot sweep
 * named `dig` A-records as a real output gap: a plain forward lookup (dig/host/nslookup resolving one name
 * to an address) is not a zone transfer, so it never met the dns.zone receipt's >=2-record floor and minted
 * nothing at all. parsers/dns.js now mints dns.a_record {name, ip} for a single forward resolution, scoped to
 * the resolved host, WITHOUT raising the dns.zone "Zone Transfer Permitted" finding. This locks: the three
 * A-record shapes mint the mapping; a real multi-record AXFR still mints dns.zone and does NOT also emit
 * per-record a_records (no double receipt); a DC resolution stays ad.dc_candidate (not a bare a_record); and
 * a bare error answer mints nothing. Hand-built shapes, no verbatim corpus output (Principle 7). House style:
 * no em or en dashes. qa-only; the engine under test ships, this test does not. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ENGINE = path.join(__dirname, '..', '..', 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
['facts.js', 'phases.js', 'command.js'].forEach(function (f) { try { load(path.join(ENGINE, f)); } catch (e) {} });
load(path.join(ENGINE, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'dns', 'findings'].forEach(function (m) { try { load(path.join(ENGINE, 'parsers', m + '.js')); } catch (e) {} });
load(path.join(ENGINE, 'parsers', 'index.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function kinds(command, stdout) {
  return OBOL.parsers.parseActionOutput({ command: command, stdout: stdout, scope: 'host:10.10.10.5' }).facts;
}
function of(facts, kind) { return facts.filter(function (f) { return f.kind === kind; }); }

// ---- 1. dig default ANSWER SECTION, single A record -> dns.a_record, no dns.zone ----
var f1 = kinds('dig webserver.htb @10.10.10.5', [
  ';; ANSWER SECTION:',
  'webserver.htb.\t\t604800\tIN\tA\t10.10.10.50',
].join('\n'));
var a1 = of(f1, 'dns.a_record');
ok(a1.length === 1, 'single dig A record mints one dns.a_record (got ' + a1.length + ')');
ok(a1.length && a1[0].value.name === 'webserver.htb' && a1[0].value.ip === '10.10.10.50', 'the a_record carries name and ip');
ok(a1.length && a1[0].scope === 'host:10.10.10.50', 'the a_record is scoped to the resolved IP');
ok(of(f1, 'dns.zone').length === 0, 'a single forward lookup does NOT raise a dns.zone (no false Zone Transfer finding)');

// ---- 2. host "has address" and nslookup "internet address =" shapes ----
ok(of(kinds('host mail.corp.local 10.10.10.5', 'mail.corp.local has address 10.10.10.70\n'), 'dns.a_record').length === 1, 'host "has address" mints a dns.a_record');
ok(of(kinds('nslookup app.corp.local', 'app.corp.local\tinternet address = 10.10.10.80\n'), 'dns.a_record').length === 1, 'nslookup "internet address =" mints a dns.a_record');

// ---- 3. a real AXFR with >=2 records mints dns.zone and NOT per-record a_records (no double receipt) ----
var fz = kinds('dig axfr corp.local @10.10.10.5', [
  'corp.local.\t\t604800\tIN\tA\t10.10.10.10',
  'mail.corp.local.\t604800\tIN\tA\t10.10.10.11',
  'www.corp.local.\t604800\tIN\tA\t10.10.10.12',
].join('\n'));
ok(of(fz, 'dns.zone').length === 1, 'a multi-record AXFR mints dns.zone');
ok(of(fz, 'dns.a_record').length === 0, 'a zone dump does NOT also emit per-record dns.a_records (the zone receipt covers them)');

// ---- 4. a DC resolution stays ad.dc_candidate, not a bare a_record ----
var fdc = kinds('dig dc01.corp.local @10.10.10.5', [
  'corp.local.\t\t3600\tIN\tSOA\tdc01.corp.local. admin.corp.local. 1 900 600 86400 3600',
  'dc01.corp.local.\t3600\tIN\tA\t10.10.10.10',
].join('\n'));
ok(of(fdc, 'ad.dc_candidate').length >= 1, 'a DC resolution mints ad.dc_candidate');
ok(of(fdc, 'dns.a_record').length === 0, 'the DC name is not duplicated as a bare dns.a_record');

// ---- 5. a bare error answer mints nothing ----
ok(kinds('dig nope.corp.local @10.10.10.5', ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n').length === 0, 'an NXDOMAIN answer alone mints nothing');

console.log('\nDNS A-RECORD SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
