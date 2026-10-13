const fs = require('fs');

global.window = global;
global.OBOL = global.OBOL || {};

require('../assets/engine/facts.js');
require('../assets/engine/profile.js');
require('../assets/engine/vfs.js');
require('../assets/engine/command.js');
require('../assets/engine/pack.js');
require('../assets/engine/phases.js');
require('../assets/engine/parsers/common.js');
require('../assets/engine/parsers/shape.js');
require('../assets/engine/parsers/blockers.js');
require('../assets/engine/parsers/creds.js');
require('../assets/engine/parsers/directory.js');
require('../assets/engine/parsers/index.js');
require('../data/packs-bundle.js');
require('../assets/engine/packs.js');

if (!fs.existsSync('obol-active(2).json')) {
  console.log('SKIP: obol-active(2).json not present in root directory');
  process.exit(0);
}
const raw = JSON.parse(fs.readFileSync('obol-active(2).json', 'utf8'));
const eng = raw.engagement;
const target = eng.active_target || (eng.targets && eng.targets[0] && eng.targets[0].ip) || '10.129.105.90';

const factList = (eng.facts || []).map(d => OBOL.facts.factFromJson(d));
const store = new OBOL.facts.FactSet(factList);

const allActions = OBOL.packs.actions();
const rootAction = allActions.find(a => a.id === 'flag-hunt-root-windows');

console.log('Target:', target);
console.log('Total facts:', store.facts.length);
console.log('Has flag_located:', store.has('objective.flag_located'));
console.log('Flag located values:', store.values('objective.flag_located'));

const opts = { locus: 'remote', params: Object.assign({}, eng.params || {}, { target }) };
const idx = OBOL.command.bestCommandIndex(rootAction, store, opts);
const cmd = OBOL.command.fillCommand(rootAction, store, opts, idx);

console.log('Selected Command Index:', idx);
console.log('Selected Command:', cmd.filled);
console.log('Command Note:', cmd.note);

if (!cmd.filled.includes('type C:\\Users\\Administrator\\Desktop\\root.txt')) {
  console.error('FAIL: Expected type C:\\Users\\Administrator\\Desktop\\root.txt, but got:', cmd.filled);
  process.exit(1);
}
console.log('\nPASS: obol-active(2).json now cleanly selects the Desktop root flag read command!');
