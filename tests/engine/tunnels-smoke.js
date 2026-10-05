/*!
 * tunnels-smoke.js — the connection wizard (OBOL.TUNNELS + OBOL.renderTunnelSteps).
 *
 * Guards the hand-holding contract the wizard exists for: every tunnel tool teaches a thorough,
 * machine-labelled, phased setup; the complex agent-based tools stage their binary onto BOTH
 * machines; and the one shared renderer both surfaces use produces in-sync, tickable steps keyed on
 * the move id. Pure data + a DOM-free render, so it runs in plain Node.
 */
'use strict';
var assert = require('assert');
var path = require('path');

global.localStorage = { _d: {}, getItem: function (k) { return this._d[k] == null ? null : this._d[k]; }, setItem: function (k, v) { this._d[k] = String(v); } };
require(path.join(__dirname, '..', '..', 'assets', 'ui', 'util.js'));
require(path.join(__dirname, '..', '..', 'data', 'tunnels.js'));
var OBOL = global.OBOL;

var pass = 0;
function ok(cond, msg) { assert.ok(cond, msg); console.log('  ok - ' + msg); pass++; }

// ---- catalog shape ----------------------------------------------------------------------------
var T = OBOL.TUNNELS;
ok(Array.isArray(T) && T.length >= 5, 'the catalog lists at least five tunnel tools');
ok(T.filter(function (t) { return t.rec; }).length === 1 && T.filter(function (t) { return t.rec; })[0].key === 'ligolo', 'Ligolo-ng is the single recommended default');

var moveIds = {};
T.forEach(function (t) {
  ok(t.key && t.name && t.moveId && t.kind, t.name + ': has key / name / moveId / kind');
  ok(!moveIds[t.moveId], t.name + ': moveId is unique (' + t.moveId + ')');
  moveIds[t.moveId] = 1;
  ok(t.prereq && t.prereq.length > 20, t.name + ': states a plain-language before-you-start prereq');
  ok(Array.isArray(t.steps) && t.steps.length >= 3, t.name + ': walks at least three setup steps');
  t.steps.forEach(function (st, i) {
    ok(st.phase && st.title && st.where, t.name + ' step ' + (i + 1) + ': has a phase, title and machine (where)');
    ok(st.where === 'local' || st.where === 'host', t.name + ' step ' + (i + 1) + ': where is local or host');
    ok(st.cmd || (st.alts && st.alts.length), t.name + ' step ' + (i + 1) + ': carries a command or OS variants');
    (st.alts || []).forEach(function (a) { ok(a.label && a.cmd, t.name + ' step ' + (i + 1) + ': each OS variant is labelled and has a command'); });
  });
  // no decorative emoji / em-dash in authored strings (the project content discipline)
  var blob = JSON.stringify(t);
  ok(!/[—\u{1F000}-\u{1FAFF}☀-➿]/u.test(blob), t.name + ': no em-dash or decorative emoji in content');
});

// ---- the agent-based tools stage onto BOTH machines (the core of the ask) ----------------------
['pivot-ligolo', 'pivot-chisel-socks', 'dns-tunnel'].forEach(function (id) {
  var t = T.filter(function (x) { return x.moveId === id; })[0];
  var wheres = {}; t.steps.forEach(function (s) { wheres[s.where] = 1; });
  ok(wheres.local && wheres.host, id + ': prepares on Kali AND stages onto the compromised host');
  var hasStaging = t.steps.some(function (s) { return /stage/i.test(s.phase || ''); });
  ok(hasStaging, id + ': has an explicit staging phase (gets the binary onto the host)');
  var hasTeardown = t.steps.some(function (s) { return /clean up|tear/i.test((s.phase || '') + ' ' + (s.title || '')); });
  ok(hasTeardown, id + ': ends with a clean-up / teardown step');
});

// ligolo, the recommended path, must spell out the agent transfer (not bury it in a note)
var lig = T.filter(function (t) { return t.moveId === 'pivot-ligolo'; })[0];
var transfer = lig.steps.filter(function (s) { return s.where === 'host' && /download|pull|agent/i.test(s.title); })[0];
ok(transfer && transfer.alts && transfer.alts.length >= 2, 'Ligolo spells out the agent download with Linux and Windows variants');

// ---- the shared renderer (one source for both surfaces) ----------------------------------------
ok(typeof OBOL.renderTunnelSteps === 'function', 'a single shared renderer drives both the coach and the hub');
var html = OBOL.renderTunnelSteps(lig, { lhost: '10.10.14.5', target: '10.10.10.10' });
ok(/stage-steps/.test(html) && /stage-phase/.test(html), 'the render groups steps under phase headers');
ok(/On your Kali box/.test(html) && /On the target host/.test(html), 'both machine labels are rendered in text');
ok(/data-stage="pivot-ligolo"/.test(html) && /data-stage-i="0"/.test(html), 'each step carries the shared tick key (moveId + flat index)');
ok((html.match(/role="checkbox"/g) || []).length === lig.steps.length, 'one tickable checkbox per real step (phase headers are not steps)');
ok(/10\.10\.14\.5/.test(html), 'engagement params fill the command tokens ({{lhost}})');
ok(/&lt;internal-cidr&gt;/.test(html), 'operator-supplied placeholders survive as visible <angle> text');
ok(/You'll know it worked/.test(html), 'steps carry a verify checkpoint for confidence');

// tick state round-trips through the shared localStorage key both routes toggle
global.localStorage.setItem('obol.stage:pivot-ligolo:0', '1');
var html2 = OBOL.renderTunnelSteps(lig, {});
ok(/aria-checked="true"/.test(html2), 'a ticked step renders checked on the next paint');

console.log('\ntunnels-smoke: ' + pass + ' checks passed');
