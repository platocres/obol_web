/* Web content-discovery dispatch (Corpus Mining Stage 5, parser hardening). The confusion matrix (Stage 4)
 * flagged gobuster as the highest-leverage blind spot: when a found-path block is pasted WITHOUT the command
 * line, dispatch has to recognize it by shape alone. The gobuster path line is /path (Status: NNN) with zero
 * or more trailing bracket groups: v2.0.1 had none, 3.x adds [Size: N], a redirect adds [--> url]. The old
 * (Status)-only form was the real miss (the shape sniff required [Size: N]). This locks all three forms, the
 * Found:-prefixed line, and the command-present path, and asserts prose that merely mentions a path mints
 * nothing. Hand-built shapes, no verbatim corpus output (docs/CORPUS-MINING.md Principle 7). House style: no
 * em or en dashes. qa-only; the engine under test ships, this test does not. */
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

function contentPaths(command, stdout) {
  var r = OBOL.parsers.parseActionOutput({ command: command || '', stdout: stdout, scope: 'host:10.10.10.5' });
  var cm = r.facts.filter(function (f) { return f.kind === 'web.content_map'; });
  return cm.length ? cm[0].value.paths : [];
}

// ---- old gobuster v2.0.1: (Status: NNN) with NO [Size], pasted with only the result block ----
var oldFmt = [
  '=====================================================',
  'Gobuster v2.0.1              OJ Reeves (@TheColonial)',
  '=====================================================',
  '[+] Mode         : dir',
  '[+] Url/Domain   : http://10.10.10.5/',
  '=====================================================',
  '/index.html (Status: 200)',
  '/images (Status: 301)',
  '/admin (Status: 301)',
  '/server-status (Status: 403)',
  '=====================================================',
].join('\n');
var oldPaths = contentPaths('', oldFmt);
ok(oldPaths.length === 4, 'old gobuster v2.0.1 block (no command, no [Size]) mints all 4 paths (got ' + oldPaths.length + ')');
ok(oldPaths.indexOf('/admin') >= 0 && oldPaths.indexOf('/server-status') >= 0, 'old-format paths include /admin and /server-status');

// ---- modern gobuster 3.x: [Size: N], still dispatches on shape with no command ----
var modern = [
  '/login.php           (Status: 200) [Size: 1543]',
  '/uploads             (Status: 301) [Size: 311] [--> http://10.10.10.5/uploads/]',
  '/secret.txt          (Status: 200) [Size: 42]',
].join('\n');
var modernPaths = contentPaths('', modern);
ok(modernPaths.length === 3, 'modern gobuster 3.x block (no command) still mints all 3 paths including the redirect line (got ' + modernPaths.length + ')');
ok(modernPaths.indexOf('/uploads') >= 0, 'the [--> url] redirect line is parsed');

// ---- Found: prefix (older gobuster/other tools) ----
var found = ['Found: /backup (Status: 200)', 'Found: /config (Status: 403)'].join('\n');
ok(contentPaths('', found).length === 2, 'Found:-prefixed path lines mint both paths');

// ---- command present: unchanged behaviour ----
ok(contentPaths('gobuster dir -u http://10.10.10.5/ -w common.txt', oldFmt).length === 4, 'with the command present the same block still mints 4 paths');

// ---- negative: prose that mentions a path must NOT mint a content map ----
var prose = [
  'I browsed to /admin (Status: 200) was shown in the corner of the screen but it was a login form.',
  'The box at 10.10.10.5 served a default page.',
].join('\n');
ok(contentPaths('', prose).length === 0, 'prose mentioning /admin (Status: 200) mid-sentence mints no content map (end-of-line anchor holds)');

console.log('\nWEB CONTENT PATHS SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
