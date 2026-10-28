/* The locate → capture loop: once obol has LOCATED a flag (a spider or a recursive search recorded
 * objective.flag_located with the file's exact path), the on-host and remote capture steps must FILL that real
 * path, the right user's Desktop, and the platform's own flag name, instead of a guessed placeholder. Without
 * a located path, both ROOT/proof and USER/local flag paths (and flag_smb_path_local) stay UNFILLED so capture
 * steps strictly gate behind "locate it first" for all users (privileged and unprivileged alike). Generic data. */
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

// 1. With LOCATED paths, steps fill the exact files the spider found (including SMB relative path).
const located = set(['credential.available', 'access.admin', 'os.windows', 'foothold.windows'], [
  F.makeFact({ kind: 'objective.flag_located', scope: 'host:10.0.0.5', value: { slot: 'root', name: 'root.txt', path: 'C:\\Users\\Administrator\\Desktop\\root.txt' }, source: 'nxc smb --spider' }),
  F.makeFact({ kind: 'objective.flag_located', scope: 'host:10.0.0.5', value: { slot: 'local', name: 'user.txt', path: 'C:\\Users\\svc-user\\Desktop\\user.txt' }, source: 'nxc smb --spider' }),
]);
const lf = fillAll(located, { platform: 'htb' });
ok(lf.some((r) => r === 'cmd /c "whoami & hostname & ipconfig & type C:\\Users\\svc-user\\Desktop\\user.txt"'), 'Universal on-host read fills the LOCATED local flag path with cmd /c whoami & hostname & ipconfig');
ok(lf.some((r) => /get "svc-user\/Desktop\/user\.txt" user\.txt/.test(r)), 'SMB read fills the LOCATED share-relative flag_smb_path_local (svc-user/Desktop/user.txt)');
ok(lf.some((r) => r === 'cmd /c "whoami & hostname & ipconfig & type C:\\Users\\Administrator\\Desktop\\root.txt"'), 'Universal root move fills the LOCATED root flag path with cmd /c whoami & hostname & ipconfig');
ok(lf.some((r) => r === 'cmd /c "whoami & hostname & ipconfig & type C:\\Users\\svc-user\\Desktop\\user.txt & type C:\\Users\\Administrator\\Desktop\\root.txt"'), 'combined proof read fills both LOCATED local and root flag paths');
ok(!lf.some((r) => /<user>/.test(r)), 'no <user> placeholder remains once the flags are located');

// 2. Without a located path and PRIVILEGED (administrator): both ROOT and USER/local read steps stay
// UNFILLED (gated behind locating the flag first via Get-ChildItem -Include with profile-aware flag_names_windows).
const htb = fillAll(set(['credential.available', 'access.admin', 'os.windows']), { platform: 'htb' });
ok(htb.some((r) => /-Include user\.txt,root\.txt\b/.test(r)), 'HTB locate command searches for user.txt,root.txt');
ok(htb.some((r) => /type \{\{flag_path_root\}\}$/.test(r)), 'as admin with no locate, the root-flag capture stays unfilled (gates: locate first)');
ok(!htb.some((r) => /type C:\\Users\\administrator\\Desktop\\user\.txt$/i.test(r)), 'as admin, the user-flag capture does NOT guess Administrator\\Desktop\\user.txt');
ok(htb.some((r) => /type \{\{flag_path_local\}\}$/.test(r)), 'as admin with no locate, the user-flag capture stays unfilled (gates: locate first)');

// 3. Without a located path, OSCP profile locate step searches for OffSec local.txt,proof.txt; read captures gate until located.
const oscp = fillAll(set(['credential.available', 'access.admin', 'os.windows']), { platform: 'oscp' });
ok(oscp.some((r) => /-Include local\.txt,proof\.txt\b/.test(r)), 'OSCP locate command searches for local.txt,proof.txt');
ok(oscp.some((r) => /type \{\{flag_path_root\}\}$/.test(r)), 'OSCP admin root-flag capture gates until located');
ok(oscp.some((r) => /type \{\{flag_path_local\}\}$/.test(r)), 'OSCP admin user-flag capture also gates until located');

// 4. An UNPRIVILEGED active user (bob) ALSO gates both local flag path and SMB flag path until located,
// and fills them once objective.flag_located is recorded.
const asBob = fillAll(set(['credential.available', 'foothold.windows', 'os.windows']), { platform: 'htb' }, 'bob');
ok(asBob.some((r) => /type \{\{flag_path_local\}\}$/.test(r)), 'an unprivileged user (bob) without locate gates flag_path_local');
ok(asBob.some((r) => /get "\{\{flag_smb_path_local\}\}"/.test(r)), 'an unprivileged user (bob) without locate gates flag_smb_path_local');
const asBobLocated = fillAll(set(['credential.available', 'foothold.windows', 'os.windows'], [
  F.makeFact({ kind: 'objective.flag_located', scope: 'host:10.0.0.5', value: { slot: 'local', name: 'local.txt', path: 'C:\\Users\\bob\\Desktop\\local.txt' }, source: 'nxc smb --spider' }),
]), { platform: 'oscp' }, 'bob');
ok(asBobLocated.some((r) => /type C:\\Users\\bob\\Desktop\\local\.txt$/.test(r)), 'unprivileged user (bob) with locate fills C:\\Users\\bob\\Desktop\\local.txt');
ok(asBobLocated.some((r) => /get "bob\/Desktop\/local\.txt" local\.txt/.test(r)), 'unprivileged user (bob) with locate fills bob/Desktop/local.txt for smbclient');

console.log(fail ? ('\nFLAG PATH FILL: ' + fail + ' FAILURES') : '\nFLAG PATH FILL: all passed');
process.exit(fail ? 1 : 0);
