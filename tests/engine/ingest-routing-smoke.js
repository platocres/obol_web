/* Paste-anywhere routing: output pasted with NO command (redirected file, screenshot text, a tool run
 * out of obol's order, or dropped on the wrong move) must still reach the right parser. ingest.js widens
 * the DISPATCH label from the paste itself — command-ish lines + content signatures — and every parser
 * stays content-bound, so a recovered token enables a parser but never invents a fact. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ROOT = path.join(__dirname, '..', '..'), ENGINE = path.join(ROOT, 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} }, Promise: Promise }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENGINE, 'parsers', m + '.js')); });
load(path.join(ENGINE, 'parsers', 'index.js'));
load(path.join(ROOT, 'assets', 'ui', 'ingest.js'));   // defines OBOL.ingest.{dispatchLabel,sniffCommand,contentSignatures}
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
// Simulate an OUTPUT-ONLY paste with NO command threaded (the reported gap): widen the label the way
// ingest.run() does, then dispatch, and collect the fact kinds.
function kindsFromOutputOnly(text) {
  var dispatchCmd = OBOL.ingest.dispatchLabel('', text);
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: dispatchCmd, stdout: text, source: 'paste', scope: 'host:10.0.0.5', domain: 'corp.local' });
  return { kinds: (r.facts || []).map(function (f) { return f.kind; }), label: dispatchCmd };
}

// nmap TEXT scan, output only (no `nmap …` invocation, no move tag)
var nmap = kindsFromOutputOnly(['Nmap scan report for 10.0.0.5', 'Host is up (0.01s latency).', 'PORT     STATE SERVICE', '445/tcp  open  microsoft-ds', '5985/tcp open  wsman', 'Nmap done'].join('\n'));
ok(nmap.kinds.indexOf('ports.open') >= 0, 'output-only nmap scan routes to the nmap parser (ports.open)');

// secretsdump dump line, output only
var sd = kindsFromOutputOnly('Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::');
ok(sd.kinds.indexOf('hash.ntlm') >= 0, 'output-only NTDS/SAM dump line routes to the dump parser (hash.ntlm)');

// kerberoast / asrep blobs, output only
ok(kindsFromOutputOnly('$krb5tgs$23$*svc$CORP$...*$abcdef').kinds.indexOf('credential.candidate') >= 0, 'a bare $krb5tgs$ blob routes to the roast parser');
ok(kindsFromOutputOnly('$krb5asrep$23$user@CORP:aabbcc$ddeeff').kinds.indexOf('credential.candidate') >= 0, 'a bare $krb5asrep$ blob routes to the AS-REP parser');

// nxc SMB login banner, output only (no `nxc …` line)
var nxc = kindsFromOutputOnly('SMB   10.0.0.5   445   DC01   [+] corp.local\\svc:Password1 (Pwn3d!)');
ok(nxc.label.indexOf('nxc ') >= 0, 'an nxc SMB banner is recognized from content (routes to the nxc parsers)');
// REGRESSION: the nxc content signature must recover the ACTUAL protocol, not a fixed `nxc smb`. Submitting
// `nxc ldap` output used to recover `nxc smb`, which then falsely marked an UNRUN `nxc smb` check as ✓ ran.
ok(OBOL.ingest.contentSignatures('LDAP   10.0.0.5   389   DC01   [+] corp.local\\:') === 'nxc ldap', 'nxc ldap output recovers `nxc ldap`, never `nxc smb`');
ok(OBOL.ingest.contentSignatures('WINRM  10.0.0.5   5985  DC01   [+] corp.local\\svc:pw (Pwn3d!)') === 'nxc winrm', 'nxc winrm output recovers `nxc winrm`');
ok(OBOL.ingest.contentSignatures('SMB    10.0.0.5   445   DC01   [+] corp.local\\svc:pw') === 'nxc smb', 'nxc smb output still recovers `nxc smb`');

// sccmhunter NAA, output only
var sccm = kindsFromOutputOnly(['[+] Recovered SCCM secrets', 'NetworkAccessUsername: CORP\\sccm_svc', 'NetworkAccessPassword: S3cret'].join('\n'));
ok(sccm.kinds.indexOf('credential.candidate') >= 0, 'output-only sccmhunter NAA output routes to the sccm parser');

// bloodyAD get writable, output only (parser self-sniffs; dispatch label may stay empty)
var bad = kindsFromOutputOnly(['distinguishedName: CN=Exchange Windows Permissions,CN=Users,DC=corp,DC=local', 'member: WRITE', 'nTSecurityDescriptor: WRITE'].join('\n'));
ok(bad.kinds.indexOf('ad.acl_lead') >= 0, 'output-only bloodyAD get-writable is recognized (ad.acl_lead)');

// A tool-hint line that leads the paste (no shell prompt) is recovered too
ok(OBOL.ingest.sniffCommand('nxc smb 10.0.0.5 -u svc -p x\n[*] some output').indexOf('nxc smb') >= 0, 'a leading tool-hint line (no prompt) is recovered by sniffCommand');

// NEGATIVE: prose / a report paragraph names no tool and must recover NOTHING (no misrouting, no facts)
var prose = 'The target was compromised through a series of steps. We enumerated users and cracked a password.';
ok(OBOL.ingest.dispatchLabel('', prose) === '', 'plain prose recovers no dispatch label (no misrouting)');
ok(kindsFromOutputOnly(prose).kinds.length === 0, 'plain prose mints no facts');

// ---- "ran but proved nothing" classification (drives retiring a move from the coach) ----
var sccmFind = "sccmhunter.py find -u svc -p 'x' -d corp.local -dc-ip 10.0.0.5";
var sccmEmpty = ['[02:01:11] INFO [*] Checking for System Management Container.', '[02:01:11] INFO [-] System Management Container not found.', '[02:01:12] INFO [-] No results found.'].join('\n');
ok(OBOL.ingest.recognizesTool(sccmFind, sccmEmpty) === true, 'a real sccmhunter run is recognized as a tool that actually ran');
ok(OBOL.ingest.looksLikeError(sccmEmpty) === false, 'a clean "No results found" is NOT read as an error (so the move can retire)');
ok(OBOL.ingest.looksLikeError('bloodyAD: error: unrecognized arguments: svc-alfresco') === true, 'a usage/arg error IS an error (the move must NOT be retired — the operator will retry)');
ok(OBOL.ingest.looksLikeError('LDAPModifyException: insufficientAccessRights ... Access is denied.') === true, 'an access-denied failure IS an error (not a clean negative)');
ok(OBOL.ingest.recognizesTool('', 'the quick brown fox jumped over the lazy dog') === false, 'unrelated prose is not recognized as a tool run (never retires a move)');

// an ATTACHED bloodyAD get-writable dump (no command line) → the dispatch label recovers "get writable"
var bloodyDump = ['distinguishedName: CN=Exchange Windows Permissions,CN=Users,DC=corp,DC=local', 'member: WRITE', 'nTSecurityDescriptor: WRITE', '', 'distinguishedName: CN=DnsAdmins,CN=Users,DC=corp,DC=local', 'member: WRITE'].join('\n');
ok(/get writable/.test(OBOL.ingest.dispatchLabel('', bloodyDump)), 'an attached bloodyAD get-writable dump is recovered into the dispatch label (so the coach can mark it ran)');

// obol learns the operator's LHOST from the terminal prompt in a paste (`[tun0:10.10.14.191]`)
ok(OBOL.ingest.detectLhost('┌──(kali㉿kali)-[~/CTF] [2026-09-27 00:14:34 UTC] [tun0:10.10.14.191]\n└─$ nmap -Pn 10.129.94.251') === '10.10.14.191', 'the operator LHOST is read from the [tun0:IP] prompt');
ok(OBOL.ingest.detectLhost('[tap0:10.8.0.5]') === '10.8.0.5', 'a tap adapter address is recognized too');
ok(OBOL.ingest.detectLhost('Nmap scan report for 10.129.94.251\nHost is up.') === '', 'a target IP in tool output is NOT mistaken for the operator LHOST');

console.log(fail ? ('\nINGEST ROUTING: ' + fail + ' FAILURES') : '\nINGEST ROUTING: all passed');
process.exit(fail ? 1 : 0);
