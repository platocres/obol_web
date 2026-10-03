/* Endpoint defensive-posture DETECTION (read-only). defense-enum mints defense.control from Get-*
 * enumeration output — language mode, Defender state + exclusions, AppLocker — so the coach can warn and
 * stay remote-first. Detection only: no bypass moves, no claim any control can be evaded. */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');
var ROOT = path.join(__dirname, '..', '..'), ENGINE = path.join(ROOT, 'assets', 'engine');
var ctx = { console: { log: function () {}, warn: function () {} }, Promise: Promise }; ctx.globalThis = ctx; vm.createContext(ctx);
function load(f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f }); }
load(path.join(ENGINE, 'facts.js'));
load(path.join(ENGINE, 'phases.js'));
load(path.join(ENGINE, 'pack.js'));
load(path.join(ENGINE, 'parsers', 'common.js'));
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource'].forEach(function (m) { load(path.join(ENGINE, 'parsers', m + '.js')); });
load(path.join(ENGINE, 'parsers', 'index.js'));
load(path.join(ROOT, 'assets', 'ui', 'ingest.js'));
var OBOL = ctx.OBOL, PK = OBOL.pack, F = OBOL.facts;
var pdir = path.join(ROOT, 'data', 'packs');
var PACK = PK.loadPacks(fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); })
  .map(function (f) { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } }));
var byId = {}; PACK.forEach(function (a) { byId[a.id] = a; });

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function kinds(text, cmd) {
  var dispatchCmd = OBOL.ingest.dispatchLabel(cmd || '', text);
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: dispatchCmd, stdout: text, source: 'paste', scope: 'host:10.0.0.5', domain: 'corp.local' });
  return r.facts || [];
}
function defVal(text, cmd) { return (kinds(text, cmd).filter(function (f) { return f.kind === 'defense.control'; })[0] || {}).value; }

console.log('# the move exists, detection-only (produces defense.control, no bypass)');
ok(byId['defense-enum'] && byId['defense-enum'].produces.indexOf('defense.control') >= 0, 'defense-enum move produces defense.control');
ok(byId['defense-enum'] && byId['defense-enum'].scope === 'oscp+', 'defense-enum is scoped oscp+');
ok(!byId['amsi-bypass'] && !byId['applocker-bypass'] && !byId['clm-breakout'], 'no bypass moves shipped (detection-only lane)');

console.log('# detection mints defense.control with the right flags');
var clm = defVal('LanguageMode\n------------\nConstrainedLanguage', 'powershell $ExecutionContext.SessionState.LanguageMode');
ok(clm && clm.clm === true && clm.language_mode === 'ConstrainedLanguage', 'ConstrainedLanguage → clm flag set');
var def = defVal('AMServiceEnabled      : True\nRealTimeProtectionEnabled : True\nAntivirusEnabled      : True', 'Get-MpComputerStatus');
ok(def && def.defender === true, 'Defender real-time on → defender flag true');
var excl = defVal('ExclusionPath\n-------------\nC:\\Temp\\dev\nC:\\Tools', 'Get-MpPreference | select ExclusionPath');
ok(excl && excl.exclusion_count === 2 && (excl.exclusions || []).indexOf('C:\\Temp\\dev') >= 0, 'exclusion paths recorded (' + JSON.stringify(excl && excl.exclusions) + ')');
var al = defVal('<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"></RuleCollection></AppLockerPolicy>', 'Get-AppLockerPolicy -Effective -Xml');
ok(al && al.applocker === true, 'AppLocker policy present → applocker flag true');

console.log('# false-positive guard');
ok(!defVal('total 12\ndrwxr-xr-x 2 root root 4096 Jan 1 00:00 .', 'ls -la'), 'a harmless ls mints no defense.control');

console.log('# defense.control has a producer AND a consumer (not a dead-end fact)');
ok(!!PK.FRIENDLY['defense.control'], 'defense.control carries a FRIENDLY label');

console.log(fail ? ('\nFAILED (' + fail + ')') : '\nALL PASS');
process.exit(fail ? 1 : 0);
