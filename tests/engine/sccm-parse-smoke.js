/* sccmhunter / SharpSCCM → credential.candidate (sccm_naa). The dispatch existed but the parser did
 * not, so every SCCM paste minted nothing. Conservative: only a recovered Network Access Account
 * credential is a fact; site/MP discovery and a no-SCCM run correctly earn nothing (not a parse error). */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ENGINE = path.join(__dirname, '..', '..', 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENGINE, 'parsers', m + '.js')); });
load(path.join(ENGINE, 'parsers', 'index.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function leads(r, kind) { return (r.facts || []).filter(function (f) { return f.kind === kind && (f.value || {}).kind === 'sccm_naa'; }); }

var find = "sccmhunter.py find -u svc -p 'x' -d corp.local -dc-ip 10.0.0.5";

// The reported run: SCCM is not deployed → `No results found`. This is the HONEST outcome, not a
// parse failure. It must mint NOTHING (never invent a foothold that isn't there).
var absent = OBOL.parsers.parseActionOutput({ actionId: '', command: find, source: 'paste', scope: 'host:10.0.0.5', domain: 'corp.local',
  stdout: ['[02:01:11] INFO [*] Checking for System Management Container.',
           '[02:01:11] INFO [-] System Management Container not found.',
           '[02:01:12] INFO [-] No results found.'].join('\n') });
ok(leads(absent, 'credential.candidate').length === 0, 'a no-SCCM run (No results found) mints nothing — honest, not a failure');

// A real NAA secret recovered → candidate credential material (a secret to try, not validated access).
var naa = OBOL.parsers.parseActionOutput({ actionId: '', command: find, source: 'paste', scope: 'host:10.0.0.5', domain: 'corp.local',
  stdout: ['[+] Recovered SCCM policy secrets', 'NetworkAccessUsername: CORP\\sccm_svc', 'NetworkAccessPassword: R3dactedButPresent'].join('\n') });
var l = leads(naa, 'credential.candidate');
ok(l.length === 1, 'a recovered Network Access Account credential mints a credential.candidate (dispatch was dead before)');
ok((l[0].value || {}).count >= 1, 'the candidate records how many NAA accounts were seen');

// Site-server / management-point discovery alone proves nothing — no credential, no fact.
var disco = OBOL.parsers.parseActionOutput({ actionId: '', command: find, source: 'paste', scope: 'host:10.0.0.5', domain: 'corp.local',
  stdout: ['[+] Found management point: MP01.corp.local', '[+] Found site server: SITE01.corp.local (site code: P01)'].join('\n') });
ok(leads(disco, 'credential.candidate').length === 0, 'site/MP discovery alone earns no credential fact');

console.log(fail ? ('\nSCCM PARSE: ' + fail + ' FAILURES') : '\nSCCM PARSE: all passed');
process.exit(fail ? 1 : 0);
