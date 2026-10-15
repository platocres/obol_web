/* field-audit-smoke.js — adversarial field auditor across EVERY Tool Builder. The guardrail against three
 * bug classes the operator must never hit:
 *   (A) VISIBLE-BUT-INERT: a field is shown (its visibleWhen is satisfied) but changing or toggling it does
 *       NOT change the compiled command in that state (you fill/tick it and nothing happens). Cause: a
 *       field's visibleWhen is broader than its command token's `when`.
 *   (B) BURIED: a field has a command token but there is NO state where it is visible, so its switch can
 *       never be toggled from the UI.
 *   (C) DEAD: a field has no token, is not an executable selector, and is referenced by no condition, so it
 *       does nothing at all.
 * It enumerates the control fields (selects + checkboxes) referenced by each field's visibleWhen and its
 * token's `when`, holds everything else at a realistic filled default, and checks contribution by compiling
 * with two distinct values. If this stays green, no tool can ship a field you can see but cannot use.
 */
'use strict';
var path = require('path');
var ROOT = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(ROOT, p)); }
req('assets/engine/toolbuilder.js'); req('data/toolset.js');
var OBOL = globalThis.OBOL, TB = OBOL.toolbuilder;

var CTX = { target: { value: '10.10.10.10', ip: '10.10.10.10', hostname: 'dc01.corp.local', url: 'http://10.10.10.10', fuzzurl: 'http://10.10.10.10/FUZZ' }, context: { domain: 'corp.local', baseDn: 'DC=corp,DC=local', username: 'svc', port: '445', lhost: '10.10.14.5', lport: '4444' }, workspace: { wordlist: 'rockyou.txt', outputDir: 'loot', hashfile: 'hashes.txt' } };

function refsIn(cond, out) {
  out = out || {};
  if (!cond) return out;
  if (Array.isArray(cond)) { cond.forEach(function (c) { refsIn(c, out); }); return out; }
  if (cond.any) { refsIn(cond.any, out); return out; }
  if (cond.field) out[cond.field] = 1;
  return out;
}
function tokensForField(b, fid) {
  return (b.command.tokens || []).filter(function (t) {
    if (t.field === fid) return true;
    if (t.kind === 'concat') return (t.parts || []).some(function (p) { return p.field === fid; });
    return false;
  });
}
function isExecField(b, fid) { var e = b.command && b.command.executable; return e && typeof e === 'object' && e.field === fid; }
function domainOf(b, fid) {
  var f = (b.fields || []).filter(function (x) { return x.id === fid; })[0];
  if (!f) return ['', 'X'];
  if (f.type === 'checkbox') return [false, true];
  if (f.type === 'select') return (f.options || []).map(function (o) { return o.value; });
  return ['', 'present-value'];
}
function cartesian(keys, domains) {
  var out = [{}];
  keys.forEach(function (k) {
    var next = [];
    (domains[k] || ['']).forEach(function (v) { out.forEach(function (base) { var c = Object.assign({}, base); c[k] = v; next.push(c); }); });
    out = next; if (out.length > 600) out = out.slice(0, 600);
  });
  return out;
}
function filledBase(b) {
  var vals = TB.defaultsFor(b, CTX);
  (b.fields || []).forEach(function (f) {
    if (vals[f.id] !== undefined && vals[f.id] !== '') return;
    if (f.type === 'checkbox') return;
    if (f.type === 'select') { if ((f.options || []).length) vals[f.id] = f.options[0].value; return; }
    vals[f.id] = f.type === 'secret' ? 'S3cret' : 'fillval';
  });
  return vals;
}
function compileSafe(b, vals) { try { return TB.compile(b, TB.normalizeValues(b, vals, CTX), CTX); } catch (e) { return 'ERR:' + e.message; } }
function visible(b, f, state) { return !(f.visibleWhen && !TB.conditionMatches(f.visibleWhen, TB.normalizeValues(b, state, CTX))); }

var dead = [], buried = [], inert = [];
(OBOL.TOOLSET || []).forEach(function (b) {
  var base = filledBase(b);
  (b.fields || []).forEach(function (f) {
    var toks = tokensForField(b, f.id), isExec = isExecField(b, f.id);
    var isControl = (b.command.tokens || []).some(function (t) { return t.when && refsIn(t.when)[f.id]; })
      || (b.fields || []).some(function (x) { return (x.visibleWhen && refsIn(x.visibleWhen)[f.id]) || (x.requiredWhen && refsIn(x.requiredWhen)[f.id]); });
    if (!toks.length && !isExec && !isControl) { dead.push(b.id + ' / ' + f.id); return; }
    if (!toks.length && !isExec) return; // a pure control field works via what it gates
    var ctrl = {}; refsIn(f.visibleWhen, ctrl); toks.forEach(function (t) { refsIn(t.when, ctrl); }); delete ctrl[f.id];
    var keys = Object.keys(ctrl), domains = {}; keys.forEach(function (k) { domains[k] = domainOf(b, k); });
    var anyVisible = false, inertEx = null;
    cartesian(keys, domains).forEach(function (combo) {
      var state = Object.assign({}, base, combo);
      if (!visible(b, f, state)) return;
      anyVisible = true;
      if (inertEx) return;
      var v1, v2;
      if (f.type === 'checkbox') { v1 = false; v2 = true; }
      else if (f.type === 'select') { var o = (f.options || []).map(function (x) { return x.value; }); if (o.length < 2) return; v1 = o[0]; v2 = o[1]; }
      else { v1 = 'ZZAAA'; v2 = 'ZZBBB'; }
      var s1 = Object.assign({}, state); s1[f.id] = v1; var s2 = Object.assign({}, state); s2[f.id] = v2;
      // a field VISIBLE here must change the command here; if it does not, it is inert in a state the user
      // can reach (fill/tick it, nothing happens). Flag the field on the first such state.
      if (compileSafe(b, s1) === compileSafe(b, s2)) inertEx = JSON.stringify(combo);
    });
    if (!anyVisible) buried.push(b.id + ' / ' + f.id);
    else if (inertEx) inert.push(b.id + ' / ' + f.id + ' visible-but-inert at ' + inertEx);
  });
});

var fail = dead.length + buried.length + inert.length;
function show(t, a) { if (a.length) { console.error('  ' + t + ' (' + a.length + '):'); a.forEach(function (x) { console.error('    FAIL: ' + x); }); } else console.log('  ok  : no ' + t); }
show('DEAD fields', dead); show('BURIED fields', buried); show('INERT-in-every-visible-state fields', inert);
if (fail) { console.error('field-audit-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('field-audit-smoke: OK');
