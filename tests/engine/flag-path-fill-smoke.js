/* The locate → capture loop: once obol has LOCATED a flag (a spider or a recursive search recorded
 * objective.flag_located with the file's exact path), the on-host capture step must FILL that real path, the
 * right user's Desktop, the platform's own flag name, instead of a guessed placeholder. Without a located
 * path: the ROOT/proof flag falls back to a profile-aware default (reliably Administrator's Desktop once you
 * are admin); the USER/local flag only defaults to an UNPRIVILEGED active user's own Desktop, and otherwise
 * stays UNFILLED so the capture gates behind "locate it first" (a privileged user is not the flag owner, so
 * a C:\Users\Administrator\Desktop\user.txt guess is wrong, the Forest failure). Generic data. */
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
// local flag lives in flag-hunt-windows; the root/proof flag capture is now its own move
// (flag-hunt-root-windows), so fill both and check each fills the path its slot located.
const fhMoves = ['flag-hunt-windows', 'flag-hunt-root-windows'].map((id) => pack.filter((a) => a.id === id)[0]);
const F = OBOL.facts;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function fillAll(facts, profile, username) {
  const out = [];
  fhMoves.forEach((fh) => (fh.commands || []).forEach((c, i) => out.push(OBOL.command.fillCommand(fh, facts, {
    params: { target: '10.0.0.5', username: username || 'administrator', nthash: 'aaaa' }, profile: profile,
  }, i).filled)));
  return out;
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
ok(lf.some((r) => /type C:\\Users\\Administrator\\Desktop\\root\.txt\b/.test(r)), 'the root move fills the LOCATED root flag path (Administrator Desktop, root.txt)');
ok(!lf.some((r) => /<user>/.test(r)), 'no <user> placeholder remains once the flags are located');

// 2. Without a located path and PRIVILEGED (administrator): the ROOT default fills (reliably Administrator's
// Desktop), but the USER/local capture is LEFT UNFILLED so it gates behind "locate it first" rather than
// handing a C:\Users\Administrator\Desktop\user.txt that does not exist (the Forest failure).
const htb = fillAll(set(['credential.available', 'access.admin', 'os.windows']), { platform: 'htb' });
ok(htb.some((r) => /type C:\\Users\\Administrator\\Desktop\\root\.txt$/.test(r)), 'HTB default root path uses Administrator\\Desktop\\root.txt');
ok(!htb.some((r) => /type C:\\Users\\administrator\\Desktop\\user\.txt$/i.test(r)), 'as admin, the user-flag capture does NOT guess Administrator\\Desktop\\user.txt');
ok(htb.some((r) => /type \{\{flag_path_local\}\}$/.test(r)), 'as admin with no locate, the user-flag capture stays unfilled (gates: locate first)');

// 3. Without a located path, OSCP profile ROOT default uses OffSec proof.txt; the local capture still gates.
const oscp = fillAll(set(['credential.available', 'access.admin', 'os.windows']), { platform: 'oscp' });
ok(oscp.some((r) => /proof\.txt$/.test(r)), 'OSCP default root path uses proof.txt');
ok(oscp.some((r) => /type \{\{flag_path_local\}\}$/.test(r)), 'OSCP admin user-flag capture also gates until located');

// 4. An UNPRIVILEGED active user (you ARE that user) DOES default the local flag to their own Desktop, with
// the profile name, because that is exactly where their user flag sits.
const asBob = fillAll(set(['credential.available', 'foothold.windows', 'os.windows']), { platform: 'htb' }, 'bob');
ok(asBob.some((r) => /type C:\\Users\\bob\\Desktop\\user\.txt$/.test(r)), 'an unprivileged user (bob) defaults the local flag to C:\\Users\\bob\\Desktop\\user.txt');
const asBobOscp = fillAll(set(['credential.available', 'foothold.windows', 'os.windows']), { platform: 'oscp' }, 'bob');
ok(asBobOscp.some((r) => /type C:\\Users\\bob\\Desktop\\local\.txt$/.test(r)), 'unprivileged OSCP local flag defaults to the user Desktop with local.txt');

console.log(fail ? ('\nFLAG PATH FILL: ' + fail + ' FAILURES') : '\nFLAG PATH FILL: all passed');
process.exit(fail ? 1 : 0);
