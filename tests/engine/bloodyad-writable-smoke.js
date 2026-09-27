/* bloodyAD `get writable --detail` → ad.acl_lead: the AD-escalation input obol used to drop on the
 * floor (a large dump parsed to zero facts). Surface the abusable writes, filter the noise. */
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

// The real shape: blank-line-separated blocks of `distinguishedName:` + `<attr>: <RIGHT>` lines.
var out = [
  'distinguishedName: CN=Users,DC=corp,DC=local',
  'group: CREATE_CHILD',
  'user: CREATE_CHILD',
  '',
  'distinguishedName: CN=Domain Guests,CN=Users,DC=corp,DC=local',   // abusable member? no — not a priv group
  'member: WRITE',
  '',
  'distinguishedName: CN=Exchange Windows Permissions,CN=Users,DC=corp,DC=local',  // the DCSync path
  'member: WRITE',
  'msExchAddressBookFlags: WRITE',
  '',
  'distinguishedName: CN=DnsAdmins,CN=Users,DC=corp,DC=local',
  'member: WRITE',
].join('\n');

var r = OBOL.parsers.parseActionOutput({
  actionId: 'bloodyad-acl',
  command: "bloodyAD -d corp.local --host 10.0.0.5 -u svc -p 'x' get writable --detail",
  stdout: out, source: 'bloodyad', scope: 'host:10.0.0.5', domain: 'corp.local',
});
var leads = (r.facts || []).filter(function (f) { return f.kind === 'ad.acl_lead'; });
ok(leads.length === 1, 'a bloodyAD writable dump yields an ad.acl_lead fact (was zero before)');
var v = (leads[0] || {}).value || {};
ok((v.targets || []).indexOf('Exchange Windows Permissions') !== -1, 'the DCSync-path group (Exchange Windows Permissions) is surfaced');
ok((v.targets || []).indexOf('DnsAdmins') !== -1, 'a second privilege group (DnsAdmins) is surfaced');
ok((v.targets || []).indexOf('Domain Guests') === -1, 'a non-privileged group (Domain Guests) is NOT surfaced as a lead');
ok((v.rights || []).indexOf('WriteMembers') !== -1, 'the right is recorded (WriteMembers = add-self-to-group)');
ok(/Exchange Windows Permissions/.test(v.note || ''), 'the note names the concrete DCSync cash-in');

// The reported failure: the operator ATTACHES the (multi-thousand-line) dump as a file, so ingest has
// NO command and NO action tag. Content-sniffing must still recognize it — this is the case that was
// dropping every fact on the floor.
var attached = OBOL.parsers.parseActionOutput({
  actionId: '', command: '', stdout: out, source: 'bloodyad-writable.txt', scope: 'host:10.0.0.5', domain: 'corp.local',
});
var al = (attached.facts || []).filter(function (f) { return f.kind === 'ad.acl_lead'; });
ok(al.length === 1, 'a bloodyAD dump ATTACHED with no command/action tag is still recognized (the reported bug)');
ok(((al[0] || {}).value || {}).targets.indexOf('Exchange Windows Permissions') !== -1, 'the file-attach path surfaces the same DCSync lead');

// A plain LDAP/LDIF dump has `distinguishedName:` too, but its attribute values are DATA, not the bare
// WRITE / CREATE_CHILD permission tokens — it must NOT be mistaken for bloodyAD writable output.
var ldif = ['distinguishedName: CN=Bob,CN=Users,DC=corp,DC=local', 'memberOf: CN=Domain Users,CN=Users,DC=corp,DC=local', 'description: helpdesk operator', 'userAccountControl: 512'].join('\n');
var mis = OBOL.parsers.parseActionOutput({ actionId: '', command: '', stdout: ldif, source: 'ldap.txt', scope: 'host:10.0.0.5', domain: 'corp.local' });
ok(!(mis.facts || []).some(function (f) { return f.kind === 'ad.acl_lead'; }), 'a plain LDAP/LDIF dump is NOT mis-sniffed as bloodyAD writable output');

// no bloodyAD writable output → no invented lead
var none = OBOL.parsers.parseActionOutput({ actionId: 'bloodyad-acl', command: "bloodyAD ... get writable", stdout: 'No writable object found.', source: 'bloodyad', scope: 'host:10.0.0.5', domain: 'corp.local' });
ok(!(none.facts || []).some(function (f) { return f.kind === 'ad.acl_lead'; }), 'no writable objects → no ad.acl_lead invented');

console.log(fail ? ('\nBLOODYAD WRITABLE: ' + fail + ' FAILURES') : '\nBLOODYAD WRITABLE: all passed');
process.exit(fail ? 1 : 0);
