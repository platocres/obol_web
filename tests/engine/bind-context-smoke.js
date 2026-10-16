/* bind-context-smoke.js — OBOL.bind.context(), the nested autofill context the binding bar feeds the
 * Tool Builder. Stubs the minimal store/creds/command so the pure context logic is testable in Node:
 * params flow through; a locally-selected identity overrides username/domain; a picked port and
 * wordlist land in context.port / workspace.wordlist; manual mode returns an empty context. The DOM
 * render()/mount() paths are verified headless in the browser-smoke, not here. */
'use strict';
var OBOL = globalThis.OBOL = globalThis.OBOL || {};

// --- minimal stubs (only what context() reads) ---
var ENG = { params: {}, ui: {} };
OBOL.store = {
  active: function () { return ENG; },
  factSet: function () { return { facts: [] }; },
  update: function (fn) { fn(ENG); },
  targetIdentity: function () { return {}; },
};
var CREDS = [
  { user: 'svc-alfresco', domain: 'htb.local', secret: 's3rvice', nthash: '', type: 'PW' },
  { user: 'Administrator', domain: 'htb.local', secret: '', nthash: 'aad3b...31d6', type: 'NT' },
];
OBOL.creds = {
  gather: function () { return CREDS; },
  keyOf: function (c) { return (c.user || '').toLowerCase() + '|' + (c.domain || '').toLowerCase() + '|' + (c.secret || c.nthash || ''); },
  activeKey: function () { return ''; },
};
OBOL.command = { openPorts: function () { return [88, 389, 445]; } };

require('../../assets/ui/bind.js');
var B = OBOL.bind;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// 1) params flow through
ENG.params = { target: '10.10.10.10', domain: 'corp.local', username: 'bob' };
ENG.ui = {};
var c1 = B.context();
ok(c1.target.value === '10.10.10.10', 'target.value from params');
ok(c1.context.username === 'bob', 'username from params');
ok(c1.workspace.wordlist === B.DEFAULT_WORDLIST, 'wordlist defaults when unset');
ok(c1.target.url === 'http://10.10.10.10', 'target.url is scheme + host (' + c1.target.url + ')');
ok(c1.target.fuzzurl === 'http://10.10.10.10/FUZZ', 'target.fuzzurl appends /FUZZ (' + c1.target.fuzzurl + ')');

// 2) a locally-selected identity overrides username/domain (not the active params)
ENG.ui = { bind: { identityKey: OBOL.creds.keyOf(CREDS[0]) } };
var c2 = B.context();
ok(c2.context.username === 'svc-alfresco', 'local identity overrides username (' + c2.context.username + ')');
ok(c2.context.domain === 'htb.local', 'local identity overrides domain (' + c2.context.domain + ')');
ok(B.selectedIdentity() && B.selectedIdentity().user === 'svc-alfresco', 'selectedIdentity resolves the stored key');

// 3) picked port + wordlist land in the right nested slots
ENG.ui = { bind: { port: '445', wordlist: '/tmp/w.txt' } };
var c3 = B.context();
ok(c3.context.port === '445', 'picked port -> context.port');
ok(c3.workspace.wordlist === '/tmp/w.txt', 'picked wordlist -> workspace.wordlist');

// 4) manual mode returns an empty context (autofill paused)
ENG.ui = { bind: { manual: true } };
var c4 = B.context();
ok(!c4.target.value && !c4.context.username && !c4.workspace.wordlist, 'manual mode yields an empty context');

if (fail) { console.error('bind-context-smoke: ' + fail + ' FAIL'); process.exit(1); }
console.log('bind-context-smoke: OK');
