/* loot.js — fact → {{userlist}}/{{hashfile}}/{{wordlist}} glue + heredoc materialization. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ENGINE = path.join(__dirname, '..', '..', 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} } }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'command.js'));
load(path.join(ENGINE, 'loot.js'));
var OBOL = ctx.OBOL, F = OBOL.facts, L = OBOL.loot;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

function fs_(list) { return new F.FactSet((list || []).map(F.makeFact)); }
var dirs = { root: '~/e/forest', scandir: '~/e/forest/scans', lootdir: '~/e/forest/loot', exploitdir: '~/e/forest/exploit', wwwdir: '~/e/forest/www', proofdir: '~/e/forest/proof' };

// --- usernames: dedupe (case-insensitive), sort, trim ---
var facts = fs_([
  { kind: 'ad.user_list', scope: 'domain:corp.local', value: { users: ['Guest', 'Administrator', ' krbtgt ', 'guest'], count: 4 } },
  { kind: 'ad.user_list', scope: 'domain:corp.local', value: { users: ['svc-web', 'Administrator'], count: 2 } },
]);
var names = L.usernames(facts);
ok(JSON.stringify(names) === JSON.stringify(['Administrator', 'Guest', 'krbtgt', 'svc-web']),
  'usernames dedupes case-insensitively, trims, and sorts (' + names.join(',') + ')');
ok(L.usernames(fs_([])).length === 0, 'no user list → no usernames');

// --- token paths ---
ok(L.userlistPath(dirs) === '~/e/forest/loot/users.txt', 'userlistPath → loot/users.txt');
ok(L.hashName({ id: 'asrep-roast', produces: ['hash.asrep'] }) === 'asrep', 'hashName asrep from id/produces');
ok(L.hashName({ id: 'crack-tgs', requires_all: ['hash.tgs'] }) === 'tgs', 'hashName tgs from requires_all');
ok(L.hashName({ id: 'kerberoast' }) === 'tgs', 'hashName tgs from kerber* id');
ok(L.hashName({ id: 'dump-secrets' }) === 'hashes', 'hashName falls back to generic');
ok(L.hashfilePath(dirs, { id: 'asrep-roast', produces: ['hash.asrep'] }) === '~/e/forest/loot/asrep.hashes', 'hashfilePath → loot/asrep.hashes');
ok(L.wordlistPath({}) === '/usr/share/wordlists/rockyou.txt', 'wordlist defaults to rockyou');
ok(L.wordlistPath({ wordlist: '/tmp/w.txt' }) === '/tmp/w.txt', 'operator wordlist wins');

// --- tokensFor: userlist only when proven; hashfile/wordlist always; operator inputs win ---
var roast = { id: 'asrep-roast', produces: ['hash.asrep', 'credential.candidate'], requires_all: ['ad.user_list'] };
var t = L.tokensFor(roast, facts, dirs, {});
ok(t.userlist === '~/e/forest/loot/users.txt', 'tokensFor fills userlist once a list is proven');
ok(t.hashfile === '~/e/forest/loot/asrep.hashes', 'tokensFor fills the roast hashfile');
ok(t.wordlist === '/usr/share/wordlists/rockyou.txt', 'tokensFor fills wordlist');
ok(L.tokensFor(roast, fs_([]), dirs, {}).userlist === undefined, 'no proven list → userlist stays literal (a real dependency signal)');
ok(L.tokensFor(roast, facts, dirs, { userlist: '/my/list' }).userlist === undefined, 'operator-pinned userlist is not overridden');

// --- heredoc materialization: obol writes the exact proven names/hashes to the known path ---
var ulCmd = L.userlistCommand(facts, dirs);
ok(ulCmd.indexOf("cat > ~/e/forest/loot/users.txt <<'EOF'") === 0, 'userlistCommand writes to the canonical path via a quoted heredoc');
ok(ulCmd.indexOf('\nAdministrator\nGuest\nkrbtgt\nsvc-web\nEOF') >= 0, 'the heredoc body is exactly the proven, sorted names');
ok(L.userlistCommand(fs_([]), dirs) === '', 'no users → no materialize command');

var withHashes = fs_([{ kind: 'hash.asrep', scope: 'domain:corp.local', value: { hashes: ['$krb5asrep$23$a', '$krb5asrep$23$a', '$krb5asrep$23$b'], count: 3 } }]);
var hfCmd = L.hashfileCommand(withHashes, roast, dirs);
ok(hfCmd.indexOf("cat > ~/e/forest/loot/asrep.hashes <<'EOF'") === 0, 'hashfileCommand writes the roast hashes to loot/asrep.hashes');
ok(hfCmd.indexOf('$krb5asrep$23$a\n$krb5asrep$23$b\nEOF') >= 0, 'roast hashes are order-stable deduped');
ok(L.hashfileCommand(fs_([]), roast, dirs) === '', 'no roast hashes → no hashfile command');

// --- actionUsesToken ---
ok(L.actionUsesToken({ commands: [{ run: "nxc ldap {{target}} -u {{userlist}} -p '' --asreproast {{hashfile}}" }] }, 'userlist'), 'actionUsesToken sees {{userlist}} in a command');
ok(!L.actionUsesToken({ commands: [{ run: 'nxc smb {{target}}' }] }, 'userlist'), 'actionUsesToken false when absent');

// --- integration: command.fillCommand actually resolves the tokens for the move ---
var action = { id: 'asrep-roast', produces: ['hash.asrep'], requires_all: ['ad.user_list'],
  commands: [{ tool: 'nxc', run: "nxc ldap {{target}} -u {{userlist}} -p '' --asreproast {{hashfile}}" }] };
var filled = OBOL.command.fillCommand(action, facts, { params: { target: '10.129.95.210' }, workspace: dirs }, 0);
ok(filled.filled.indexOf('-u ~/e/forest/loot/users.txt') >= 0, 'fillCommand resolves {{userlist}} to the loot path');
ok(filled.filled.indexOf('--asreproast ~/e/forest/loot/asrep.hashes') >= 0, 'fillCommand resolves {{hashfile}} to loot/asrep.hashes');
ok(OBOL.command.unfilledTokens(filled.filled).indexOf('userlist') === -1, 'no {{userlist}} left unfilled once proven');
// and a bare enum move (no proven list) keeps {{userlist}} visible as a dependency
var enumAct = { id: 'ad-user-enum', produces: ['ad.user_list'], commands: [{ tool: 'kerbrute', run: 'kerbrute userenum --dc {{target}} -d {{domain}} {{userlist}}' }] };
var enumFilled = OBOL.command.fillCommand(enumAct, fs_([]), { params: { target: '10.129.95.210', domain: 'corp.local' }, workspace: dirs }, 0);
ok(enumFilled.filled.indexOf('{{userlist}}') >= 0, 'before a list is proven, {{userlist}} stays literal (dependency still visible)');

console.log(fail ? ('\nLOOT SMOKE: ' + fail + ' FAILURES') : '\nLOOT SMOKE: all passed');
process.exit(fail ? 1 : 0);
