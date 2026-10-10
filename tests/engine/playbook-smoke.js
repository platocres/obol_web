/* Node smoke test for the Playbook engine (assets/engine/playbook.js).
 *
 * Loads the pack + command filler, resolves a couple of real moves into playbook items, builds the
 * bash script, and asserts: it carries a shebang + a TARGET variable block, a command references
 * "$TARGET" (param tokens variabilized), loot tokens fill to concrete paths (no {{...}} leaks), and
 * an unresolved token degrades to a <placeholder>. Run: node tests/engine/playbook-smoke.js
 */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
require('../../assets/engine/loot.js');
require('../../assets/engine/playbook.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, PK = OBOL.pack, F = OBOL.facts, PB = OBOL.playbook;

const pdir = path.join(__dirname, '..', '..', 'data', 'packs');
const packData = fs.readdirSync(pdir).filter((f) => f.endsWith('.json'))
  .map((f) => { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } });
const PACK = PK.loadPacks(packData);

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// pick a couple of moves that use {{target}} in a command
function moveUsingTarget() {
  for (var i = 0; i < PACK.length; i++) {
    var cs = PACK[i].commands || (PACK[i].command ? [{ run: PACK[i].command }] : []);
    for (var j = 0; j < cs.length; j++) { if (/\{\{target\}\}/.test(cs[j].run || '')) return { id: PACK[i].id, idx: j }; }
  }
  return null;
}
const pick = moveUsingTarget();
ok(!!pick, 'found a pack command that uses {{target}}');

const resolved = PB.resolve([pick], PACK);
ok(resolved.length === 1 && resolved[0].template.indexOf('{{target}}') >= 0, 'resolve() returns the item with its raw template');

const fsFacts = new F.FactSet();
const params = { target: '10.129.95.66', lhost: '10.10.14.2', lport: '4444', domain: 'htb.local', username: 'svc-alfresco', password: 's3rvice' };
const script = PB.buildScript(resolved, { params: params, facts: fsFacts, workspace: { root: '.', scandir: 'scans', lootdir: 'loot' }, name: 'Smoke' });

ok(/^#!\/usr\/bin\/env bash/.test(script), 'script starts with a bash shebang');
ok(/\nTARGET="10\.129\.95\.66"/.test(script), 'TARGET variable is set from params');
ok(script.indexOf('"$TARGET"') >= 0, 'the command references "$TARGET" (param token variabilized)');
ok(/exec > >\(tee -a "\$LOG"\)/.test(script), 'logging line present (tee to $LOG)');
ok(script.indexOf('{{') < 0, 'no raw {{tokens}} leak into the script');

// a command with a loot token resolves to a concrete path, not a leftover placeholder
function moveUsingLootUserlist() {
  for (var i = 0; i < PACK.length; i++) {
    var cs = PACK[i].commands || [];
    for (var j = 0; j < cs.length; j++) { if (/\{\{userlist\}\}/.test(cs[j].run || '')) return { id: PACK[i].id, idx: j }; }
  }
  return null;
}
const lp = moveUsingLootUserlist();
if (lp) {
  const r2 = PB.resolve([lp], PACK);
  const s2 = PB.buildScript(r2, { params: params, facts: fsFacts, workspace: { root: '.', lootdir: 'loot' } });
  ok(s2.indexOf('{{userlist}}') < 0, 'a {{userlist}} command resolves (no raw token left)');
}

// an unknown token degrades to <placeholder>
const fake = [{ id: '__fake__', idx: 0, action: { id: '__fake__' }, title: 'Fake', tool: '', note: '', template: 'tool {{target}} --thing {{nonexistent_token}}' }];
const s3 = PB.buildScript(fake, { params: params, facts: fsFacts });
ok(s3.indexOf('<nonexistent_token>') >= 0, 'an unresolved token becomes a <placeholder>');
ok(s3.indexOf('"$TARGET"') >= 0, 'param token still variabilized in the fake command');

if (fail) { console.error('\nPLAYBOOK SMOKE: ' + fail + ' failure(s)'); process.exit(1); }
console.log('\nPLAYBOOK SMOKE: all passed');
