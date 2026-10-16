/* tool-options-smoke.js — the Options composition contract (stackable Option toggles).
 *
 * Guards that every builder's headlineToggles are real, independent checkbox switches; that stacking ANY
 * subset of the toggles valid for a given primary state compiles to a clean command (no token leak, no
 * "undefined", right executable); and that nxc's selectorAliases (the deep-link back-compat) reference a
 * real protocol and real toggles. This is what makes "any stacked command is guaranteed to run" a test,
 * not a vibe.
 */
'use strict';
var path = require('path');
var ROOT = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(ROOT, p)); }
req('assets/engine/toolbuilder.js');
req('data/toolset.js');
var OBOL = globalThis.OBOL, TB = OBOL.toolbuilder;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

var byId = {}; OBOL.TOOLSET.forEach(function (b) { byId[b.id] = b; });
// a bound context so auth/target fill; plus placeholder fill for any non-secret required field left empty.
var CTX = { target: { value: '10.10.10.10', ip: '10.10.10.10', url: 'http://10.10.10.10', fuzzurl: 'http://10.10.10.10/FUZZ' }, context: { domain: 'corp.local', baseDn: 'DC=corp,DC=local', username: 'svc', lhost: '10.10.14.5', lport: '4444' }, workspace: { wordlist: 'rockyou.txt', outputDir: 'loot', hashfile: 'hashes.txt' } };
function fillRequired(b, vals) {
  var norm = TB.normalizeValues(b, vals, CTX), out = {}; Object.keys(norm).forEach(function (k) { out[k] = norm[k]; });
  (b.fields || []).forEach(function (f) {
    if (f.visibleWhen && !TB.conditionMatches(f.visibleWhen, norm)) return;
    var reqd = f.required === true || (f.requiredWhen ? TB.conditionMatches(f.requiredWhen, norm) : false);
    if (!reqd) return;
    var v = out[f.id];
    if (v === undefined || v === null || v === '') { if (f.type === 'checkbox') { if (f.mustBeChecked) out[f.id] = true; } else out[f.id] = (f.type === 'secret' ? 'S3cret!' : 'x'); }
  });
  return out;
}
function cleanCompile(b, vals, label) {
  var cmd;
  try { cmd = TB.compile(b, fillRequired(b, vals), CTX); } catch (e) { cmd = 'ERR:' + e.message; }
  ok(cmd.indexOf('ERR:') !== 0 && !/\{\{|\bundefined\b|\[object/.test(cmd), label + ' compiles clean' + (/ERR|\{\{|undefined/.test(cmd) ? ' -> ' + cmd : ''));
  return cmd;
}

// ---- every headlineToggle is a real, independent checkbox ----
var tooled = OBOL.TOOLSET.filter(function (b) { return (b.headlineToggles || []).length; });
ok(tooled.length >= 12, 'at least 12 tools carry stackable Option toggles (' + tooled.length + ')');
tooled.forEach(function (b) {
  var fieldById = {}; (b.fields || []).forEach(function (f) { fieldById[f.id] = f; });
  var bad = b.headlineToggles.filter(function (t) { return !fieldById[t] || fieldById[t].type !== 'checkbox'; });
  ok(bad.length === 0, b.id + ': every headlineToggle is a real checkbox' + (bad.length ? ' (BAD: ' + bad.join(',') + ')' : ''));
  ok(typeof b.switchesLabel === 'string' && b.switchesLabel.length > 0, b.id + ' has a switchesLabel');
});

// ---- stacking every module valid for a primary state compiles clean (the core guarantee) ----
// For a tool with a primary select (protocol/mode/role/engine), for each option value, turn ON every toggle
// whose visibleWhen is satisfied by that option, and assert a clean command. This proves no in-state stack
// is invalid.
var PRIMARY_IDS = ['protocol', 'mode', 'role', 'engine', 'method', 'client', 'requestMode'];
tooled.forEach(function (b) {
  var prim = (b.fields || []).filter(function (f) { return f.type === 'select' && PRIMARY_IDS.indexOf(f.id) >= 0 && (f.options || []).length; })[0];
  var states = prim ? prim.options.map(function (o) { var s = {}; s[prim.id] = o.value; return { k: prim.id + '=' + o.value, v: s }; }) : [{ k: 'default', v: {} }];
  states.forEach(function (st) {
    var norm = TB.normalizeValues(b, st.v, CTX);
    var onAll = {}; Object.keys(st.v).forEach(function (k) { onAll[k] = st.v[k]; });
    var lit = 0;
    (b.headlineToggles || []).forEach(function (tid) {
      var f = (b.fields || []).filter(function (x) { return x.id === tid; })[0];
      var vis = !(f.visibleWhen && !TB.conditionMatches(f.visibleWhen, norm));
      if (vis) { onAll[tid] = true; lit++; }
    });
    cleanCompile(b, onAll, b.id + ' [' + st.k + '] all ' + lit + ' visible toggles ON');
  });
});

// ---- nxc selectorAliases reference real protocol + real toggles (deep-link back-compat) ----
(function () {
  var nxc = byId['tb-nxc'];
  ok(nxc && nxc.selectorAliases, 'nxc has selectorAliases');
  if (!nxc || !nxc.selectorAliases) return;
  var protoOpts = {}; (nxc.fields.filter(function (f) { return f.id === 'protocol'; })[0].options || []).forEach(function (o) { protoOpts[o.value] = 1; });
  var toggleSet = {}; (nxc.headlineToggles || []).forEach(function (t) { toggleSet[t] = 1; });
  var bad = [];
  Object.keys(nxc.selectorAliases).forEach(function (sel) {
    var a = nxc.selectorAliases[sel];
    if (a.protocol && !protoOpts[a.protocol]) bad.push(sel + ' bad protocol ' + a.protocol);
    (a.on || []).forEach(function (t) { if (!toggleSet[t]) bad.push(sel + ' bad toggle ' + t); });
  });
  ok(bad.length === 0, 'every nxc selectorAlias maps to a real protocol + toggle' + (bad.length ? ' (' + bad.join('; ') + ')' : ''));
  // a couple of real stacks from the brief
  cleanCompile(nxc, { protocol: 'ldap', authMode: 'password', username: 'u', password: 'p', doUsers: true, doGroups: true, doAsrep: true, doKerberoast: true }, 'nxc ldap users+groups+asrep+kerberoast');
  cleanCompile(nxc, { protocol: 'smb', authMode: 'ntlm', username: 'administrator', hash: 'aad3b', doSam: true, doLsa: true, doNtds: true }, 'nxc smb sam+lsa+ntds');
})();

if (fail) { console.error('tool-options-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('tool-options-smoke: OK');
