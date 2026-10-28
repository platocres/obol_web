/* Interactive database schema-enumeration parser (corpus-mined, output axis):
 *  a "show databases;" / "show tables;" run inside a mysql/mariadb/mssql/psql sub-shell prints a
 *  single-column inventory (either the boxed ASCII grid an interactive client draws, or the bare
 *  newline list a one-shot "mysql -e" prints). parser-signatures already declares the database parser
 *  emits db.databases/db.tables; this fills that declared-but-missing emission for the interactive
 *  session, so the schema map (what to loot next) mints instead of reading as a blind unit.
 *  describe/select grids (multi-column, different intent), header labels, empty sets, and DDL
 *  acknowledgements must mint nothing (no false positives). Shapes are hand-built, not copied. */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack;
var fs = require('fs'), pdir = path.join(R, 'data/packs'), bundle = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); });
var A = PK.loadPacks(Object.keys(bundle).map(function (k) { return bundle[k]; }));
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function facts(cmd, out) { var r = OBOL.parsers.parseActionOutput({ actionId: '', command: cmd, stdout: out, scope: 'host:10.10.10.10', domain: 'acme.local' }); return (r.facts || []); }
function one(cmd, out, kind) { return facts(cmd, out).filter(function (f) { return f.kind === kind; })[0] || null; }

// The product's ingest prepends the sub-shell tool to the REPL command (mysql> show tables; -> the
// command string "mysql show tables;"), which is what the dispatcher routes on.

// --- SHOW TABLES: the boxed ASCII grid an interactive client draws. ---
var tblBoxed =
  '+------------------------+\n' +
  '| Tables_in_mattermost   |\n' +
  '+------------------------+\n' +
  '| Audits                 |\n' +
  '| Bots                   |\n' +
  '| Sessions               |\n' +
  '+------------------------+\n' +
  '3 rows in set (0.00 sec)';
var t1 = one('mysql show tables;', tblBoxed, 'db.tables');
ok(!!t1, 'a boxed "show tables" grid mints db.tables');
ok(t1 && t1.value.count === 3, 'all three table rows are captured, header excluded (' + (t1 && t1.value.count) + ')');
ok(t1 && t1.value.tables.indexOf('Audits') >= 0 && t1.value.tables.indexOf('Sessions') >= 0, 'table names are captured intact');
ok(t1 && !t1.value.tables.some(function (n) { return /^tables_in_/i.test(n); }), 'the "Tables_in_<db>" header label is not captured as a table name');
ok(t1 && t1.value.tool === 'mysql', 'the listing is attributed to the mysql client');

// --- SHOW DATABASES: boxed grid, header is the bare word "Database". ---
var dbBoxed =
  '+--------------------+\n' +
  '| Database           |\n' +
  '+--------------------+\n' +
  '| information_schema |\n' +
  '| mattermost         |\n' +
  '| mysql              |\n' +
  '+--------------------+';
var d1 = one('mysql show databases;', dbBoxed, 'db.databases');
ok(!!d1, 'a boxed "show databases" grid mints db.databases');
ok(d1 && d1.value.databases.indexOf('information_schema') >= 0 && d1.value.databases.indexOf('mattermost') >= 0, 'database names are captured (information_schema kept, it is a real schema)');
ok(d1 && d1.value.databases.map(function (n) { return n.toLowerCase(); }).indexOf('database') < 0, 'the bare "Database" header label is not captured as a database name');

// --- Bare one-shot form: "mysql -e 'show tables'" prints a header line then one name per line. ---
var tblBare = 'Tables_in_drupal\nactions\nauthmap\nbatch\nblock\ncache';
var t2 = one("mysql -e 'show tables;' -u drupaluser -p'x' drupal", tblBare, 'db.tables');
ok(!!t2, 'the bare (unboxed) "mysql -e show tables" form also mints db.tables');
ok(t2 && t2.value.tables.indexOf('actions') >= 0 && t2.value.tables.indexOf('cache') >= 0 && !t2.value.tables.some(function (n) { return /^tables_in_/i.test(n); }), 'bare rows captured, the header line dropped');

// --- No false positives ---
// A DESCRIBE grid is multi-column (interior pipes) and a different intent: no inventory fact.
var describe =
  '+-------------+--------------+------+-----+---------+----------------+\n' +
  '| Field       | Type         | Null | Key | Default | Extra          |\n' +
  '+-------------+--------------+------+-----+---------+----------------+\n' +
  '| id          | int(11)      | NO   | PRI | NULL    | auto_increment |\n' +
  '| name        | varchar(255) | NO   |     | NULL    |                |\n' +
  '+-------------+--------------+------+-----+---------+----------------+';
ok(!one('mysql describe files;', describe, 'db.tables') && !one('mysql describe files;', describe, 'db.databases'), 'a multi-column DESCRIBE grid mints no db.tables/db.databases');
// A SELECT result is multi-column and not an inventory verb.
var sel =
  '+----------------+------+--------+-----------+\n' +
  '| name           | size | user   | protected |\n' +
  '+----------------+------+--------+-----------+\n' +
  '| siteBackup.zip | 9948 | newguy |         1 |\n' +
  '+----------------+------+--------+-----------+';
ok(!one('mysql select name,size,user,protected from files;', sel, 'db.tables'), 'a multi-column SELECT grid mints no db.tables');
// An empty result set has no rows to list.
ok(!one('mysql show tables;', 'Empty set (0.00 sec)', 'db.tables'), 'an empty "show tables" (Empty set) mints no db.tables');
// A DDL acknowledgement is not a listing.
ok(!one('mysql show tables;', 'Query OK, 0 rows affected (0.01 sec)', 'db.tables'), 'a "Query OK" DDL acknowledgement mints no db.tables');

// --- The minted fact has a live downstream consumer (the loop advances) ---
var consumers = A.filter(function (m) { return [].concat(m.requires_all || [], m.requires_any || []).indexOf('db.tables') >= 0; });
ok(consumers.length >= 1, 'db.tables drives at least one downstream move (' + consumers.length + ')');

console.log('\nDB LISTING PARSER SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
