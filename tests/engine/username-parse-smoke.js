/* nxc --users column parsing: the '-Username-' header row must never leak in as an account. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ENGINE = path.join(__dirname, '..', '..', 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'parsers', 'common.js'));
var C = ctx.OBOL._parserCommon;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// The real shape of `nxc ldap … --users` output: banner + status lines, the column header row, then
// user rows (username in column 5), including a $-led trust account and machine mailbox accounts.
var out = [
  'LDAP  10.129.95.210  389  FOREST  [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)',
  'LDAP  10.129.95.210  389  FOREST  [+] htb.local\\: ',
  'LDAP  10.129.95.210  389  FOREST  [*] Enumerated 31 domain users: htb.local',
  'LDAP  10.129.95.210  389  FOREST  -Username-                    -Last PW Set-       -BadPW-  -Description-',
  'LDAP  10.129.95.210  389  FOREST  Administrator                 2021-08-31 00:51:58 0        Built-in account',
  'LDAP  10.129.95.210  389  FOREST  krbtgt                        2019-09-18 10:53:23 0        Key Distribution',
  'LDAP  10.129.95.210  389  FOREST  $331000-VK4ADACQNUCA          <never>             0',
  'LDAP  10.129.95.210  389  FOREST  svc-alfresco                  2026-09-26 23:48:42 0',
  'LDAP  10.129.95.210  389  FOREST  sebastien                     2019-09-20 00:29:59 0',
].join('\n');

var users = C._usernames(out);
ok(users.indexOf('-Username') === -1, 'the -Username- column header does NOT leak in as a user');
ok(users.indexOf('-Username-') === -1, 'nor its bracketed form');
ok(!users.some(function (u) { return u.charAt(0) === '-'; }), 'no dash-led artifact survives at all');
ok(users.indexOf('Administrator') !== -1 && users.indexOf('svc-alfresco') !== -1 && users.indexOf('sebastien') !== -1,
  'real accounts (incl. the roastable svc-alfresco) are still captured');
ok(users.indexOf('$331000-VK4ADACQNUCA') !== -1, 'a $-led trust/machine account is still captured (leading $ is legitimate)');
// no banner/status token bleeds through
['Windows', 'Enumerated', 'htb.local'].forEach(function (junk) {
  ok(users.indexOf(junk) === -1, 'banner/status token "' + junk + '" is not a user');
});

// direct validator checks
ok(C._valid_username('-Username') === false, '_valid_username rejects a leading dash');
ok(C._valid_username('.hidden') === false, '_valid_username rejects a leading dot');
ok(C._valid_username('svc-alfresco') === true, '_valid_username accepts a normal hyphenated account');
ok(C._valid_username('$331000-VK4ADACQNUCA') === true, '_valid_username accepts a $-led account');

console.log(fail ? ('\nUSERNAME PARSE: ' + fail + ' FAILURES') : '\nUSERNAME PARSE: all passed');
process.exit(fail ? 1 : 0);
