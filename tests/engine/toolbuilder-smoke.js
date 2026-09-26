/* Node smoke test for the Tool Builder engine (assets/engine/toolbuilder.js) and the equipped
 * toolset (data/toolset.js). Asserts, for every builder in OBOL.TOOLSET:
 *   - it passes OBOL.toolbuilder.validate() (structural + safety),
 *   - it declares no execution hook (execute/exec/spawn/runCommand/autoRun),
 *   - it compiles to a non-empty, single-line command with sample values,
 *   - the compiled command is shell-safe (a hostile secret is single-quoted, not raw),
 *   - its equips[] intersect the real equipped-tool set, and it carries a known category.
 * Then asserts OBOL.TOOLSET covers a healthy subset of OBOL.packs.equippedTools()
 * (computed from the real packs bundle). Run:
 *
 *     node tests/engine/toolbuilder-smoke.js
 */
'use strict';

// Engine modules attach to globalThis. facts -> phases -> pack -> packs-bundle -> packs gives us
// the real equipped-tool universe; toolbuilder + toolset give us the builders under test.
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../data/packs-bundle.js');
require('../../assets/engine/packs.js');
require('../../assets/engine/toolbuilder.js');
require('../../data/toolset.js');
const OBOL = globalThis.OBOL;
const TB = OBOL.toolbuilder;
const TS = OBOL.TOOLSET || [];

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

const FORBIDDEN = ['execute', 'exec', 'spawn', 'runCommand', 'autoRun'];
const CATS = ['web', 'credentials', 'ad', 'remote-exec', 'pivot', 'enum', 'privesc', 'shells'];

const equipped = new Set(OBOL.packs.equippedTools());
console.log('Equipped-tool universe: ' + equipped.size + ' tools.');
console.log('TOOLSET builders: ' + TS.length + '.');

ok(Array.isArray(TS) && TS.length >= 25, 'OBOL.TOOLSET is a non-trivial array (got ' + TS.length + ')');

// A nested autofill context + hostile secret to prove quoting.
const HOSTILE = "p@ss w0rd!$`;rm -rf /";
const context = {
  target: { value: '10.10.10.10', ip: '10.10.10.10', hostname: 'dc01.corp.local' },
  context: { domain: 'corp.local', username: 'alice', port: '445' },
  workspace: { wordlist: '/usr/share/wordlists/rockyou.txt', outputDir: 'loot', hashfile: 'hashes.txt' },
};
const SAMPLE = {
  baseDn: 'DC=corp,DC=local', interface: 'tun0', lhost: '10.10.14.9', lport: '4444',
  wrapped: 'nmap -sT -Pn 172.16.5.5', command: 'whoami /all', communityFile: '/usr/share/wl/snmp.txt',
};

const ids = {};
const covered = new Set();
let secretFieldsSeen = 0;

TS.forEach(function (b) {
  const tag = b.id || '(no id)';

  // unique id
  ok(b.id && !ids[b.id], tag + ': unique builder id');
  ids[b.id] = true;

  // validate()
  const errs = TB.validate(b);
  ok(errs.length === 0, tag + ': passes validate()' + (errs.length ? ' -> ' + errs.join('; ') : ''));

  // no execution hook
  const hooks = FORBIDDEN.filter(function (h) { return Object.prototype.hasOwnProperty.call(b, h); });
  ok(hooks.length === 0, tag + ': declares no execution hook');

  // category + equips scoping
  ok(CATS.indexOf(b.category) !== -1, tag + ': has a known category (' + b.category + ')');
  const inSet = (b.equips || []).some(function (t) { return equipped.has(t); });
  ok(inSet, tag + ': equips[] intersect the equipped set (' + (b.equips || []).join(',') + ')');
  (b.equips || []).forEach(function (t) { if (equipped.has(t)) covered.add(t); });

  // build a sample value set: defaults + fill any required-but-empty visible field.
  const vals = Object.assign({}, TB.defaultsFor(b, context));
  (b.fields || []).forEach(function (f) {
    const req = f.required === true || (f.requiredWhen && TB.conditionMatches(f.requiredWhen, vals));
    if (req && (vals[f.id] === undefined || vals[f.id] === '')) {
      if (f.type === 'checkbox') vals[f.id] = true;
      else if (SAMPLE[f.id] !== undefined) vals[f.id] = SAMPLE[f.id];
      else if (f.type === 'select' && f.options && f.options.length) vals[f.id] = f.options[0].value;
      else if (f.type === 'secret') vals[f.id] = HOSTILE;
      else if (f.type === 'number') vals[f.id] = '1';
      else vals[f.id] = 'sampleval';
    }
  });
  // Force the hostile secret onto every secret field so quoting is exercised where present.
  let hasSecretHere = false;
  (b.fields || []).forEach(function (f) { if (f.type === 'secret') { vals[f.id] = HOSTILE; hasSecretHere = true; } });

  let cmd = '';
  let threw = null;
  try { cmd = TB.compile(b, vals, context); } catch (e) { threw = e; }
  ok(!threw, tag + ': compiles with sample values' + (threw ? ' -> ' + threw.message : ''));
  if (threw) return;

  ok(typeof cmd === 'string' && cmd.trim().length > 0, tag + ': command is non-empty');
  ok(cmd.indexOf('\n') === -1, tag + ': command is a single line');
  // starts with a bare executable (or shell-quoted one) — never an empty token
  ok(/^\S/.test(cmd), tag + ': command starts with an executable token');

  // shell-safety: wherever the hostile secret lands (a bare -p arg, or fused into a
  // user:pass@host connection string via a concat token), it must sit INSIDE a single-quoted
  // span so its backtick/;/$/space are inert. POSIX single-quoting wraps the value verbatim, so
  // the raw bytes appearing inside quotes is correct — the property to prove is enclosure.
  if (hasSecretHere && cmd.indexOf(HOSTILE) !== -1) {
    secretFieldsSeen++;
    const before = cmd.slice(0, cmd.indexOf(HOSTILE));
    const quotesBefore = (before.match(/'/g) || []).length;
    ok(quotesBefore % 2 === 1, tag + ': hostile secret is enclosed in a single-quoted span');
    // and it is never a bare, space-delimited token on its own
    ok(cmd.indexOf(' ' + HOSTILE + ' ') === -1 && !new RegExp(' ' + HOSTILE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$').test(cmd), tag + ': hostile secret is not a bare unquoted argument');
  }
});

ok(secretFieldsSeen >= 8, 'exercised shell-quoting on many builders with secrets (' + secretFieldsSeen + ')');

// coverage of the equipped set
console.log('Equipped tools covered by TOOLSET: ' + covered.size + ' / ' + equipped.size + '.');
ok(covered.size >= 40, 'TOOLSET covers a healthy subset of the equipped set (>=40, got ' + covered.size + ')');

// the golden reference must be present and equipped
ok(TS.some(function (b) { return b.id === 'tb-ffuf'; }), 'golden reference tb-ffuf is present');
ok(equipped.has('ffuf'), 'ffuf is in the equipped set');

if (fail) { console.error('\n' + fail + ' assertion(s) FAILED.'); process.exit(1); }
console.log('\nAll toolbuilder smoke assertions passed (' + TS.length + ' builders).');
