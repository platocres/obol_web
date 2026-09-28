/* The locate → capture loop: once obol has LOCATED a flag (a spider recorded objective.flag_located with the
 * file's exact path), the on-host capture step must FILL that real path — the right user's Desktop, the
 * platform's own flag name — instead of a guessed placeholder. Without a located path it falls back to a
 * profile-aware default. Generic data. */
'use strict';
const fs = require('fs');
const path = require('path');
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
const OBOL = globalThis.OBOL;

const pack = OBOL.pack.loadPacks(OBOL.pack.PACK_NAMES.map((n) =>
  JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'data', 'packs', n + '.json'), 'utf8'))));
const fh = pack.filter((a) => a.id === 'flag-hunt-windows')[0];
const F = OBOL.facts;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function fillAll(facts, profile) {
  return (fh.commands || []).map((c, i) => OBOL.command.fillCommand(fh, facts, {
    params: { target: '10.0.0.5', username: 'administrator', nthash: 'aaaa' }, profile: profile,
  }, i).filled);
}
function set(kinds, extra) {
  const s = new F.FactSet([]);
  (kinds || []).forEach((k) => s.add(F.makeFact({ kind: k, scope: 'host:10.0.0.5', state: F.ProofState.SUPPORTED })));
  (extra || []).forEach((f) => s.add(f));
  return s;
}

// 1. With LOCATED paths, steps 3-4 fill the exact files the spider found.
const located = set(['credential.available', 'access.admin', 'os.windows', 'foothold.windows'], [
  F.makeFact({ kind: 'objective.flag_located', scope: 'host:10.0.0.5', value: { slot: 'root', name: 'root.txt', path: 'C:\\Users\\Administrator\\Desktop\\root.txt' }, source: 'nxc smb --spider' }),
  F.makeFact({ kind: 'objective.flag_located', scope: 'host:10.0.0.5', value: { slot: 'local', name: 'user.txt', path: 'C:\\Users\\svc-user\\Desktop\\user.txt' }, source: 'nxc smb --spider' }),
]);
const lf = fillAll(located, { platform: 'htb' });
ok(lf.some((r) => r === 'hostname; ipconfig; type C:\\Users\\svc-user\\Desktop\\user.txt'), 'STEP 3 fills the LOCATED local flag path (svc-user Desktop, user.txt)');
ok(lf.some((r) => r === 'hostname; ipconfig; type C:\\Users\\Administrator\\Desktop\\root.txt'), 'STEP 4 fills the LOCATED root flag path (Administrator Desktop, root.txt)');
ok(!lf.some((r) => /<user>/.test(r)), 'no <user> placeholder remains once the flags are located');

// 2. Without a located path, HTB profile defaults use the platform names (user.txt / root.txt).
const htb = fillAll(set(['credential.available', 'access.admin', 'os.windows']), { platform: 'htb' });
ok(htb.some((r) => /type C:\\Users\\.*\\Desktop\\root\.txt$/.test(r)), 'HTB default root path uses root.txt');
ok(htb.some((r) => /type C:\\Users\\.*\\Desktop\\user\.txt$/.test(r)), 'HTB default local path uses user.txt');

// 3. Without a located path, OSCP profile defaults use OffSec names (local.txt / proof.txt).
const oscp = fillAll(set(['credential.available', 'access.admin', 'os.windows']), { platform: 'oscp' });
ok(oscp.some((r) => /proof\.txt$/.test(r)), 'OSCP default root path uses proof.txt');
ok(oscp.some((r) => /local\.txt$/.test(r)), 'OSCP default local path uses local.txt');

console.log(fail ? ('\nFLAG PATH FILL: ' + fail + ' FAILURES') : '\nFLAG PATH FILL: all passed');
process.exit(fail ? 1 : 0);
