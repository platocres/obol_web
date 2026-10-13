/* Ranker behaviour for the trap-doctor / blocker moves (OBOL.pack.nextActionsV2).
 * When a blocker fact is the freshly-pasted evidence, the move that fixes it MUST be the #1 next step —
 * that is the whole accessibility promise: paste the cryptic error, the fix is right there. Guidance
 * doctors (advice.*) must never be capped as speculative, and the service→foothold moves must NOT
 * headline a bare port (recon leads; they promote once a lead indicates them). Locks it so a weight or
 * v2Speculative change can't silently bury a fix. */
'use strict';
require('../../assets/engine/facts.js'); require('../../assets/engine/phases.js'); require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js'); require('../../assets/engine/command.js'); require('../../assets/engine/workspace.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, PK = OBOL.pack, F = OBOL.facts, T0 = 1700000000000;
const PACK = PK.loadPacks(fs.readdirSync(path.join(__dirname, '..', '..', 'data', 'packs')).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'data', 'packs', f), 'utf8'))));
let fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function rank(base, trigger) {
  const fl = [];
  base.forEach((k) => fl.push(F.makeFact({ kind: k, scope: { target: '10.10.10.5' }, source: 't', created_at: T0 })));
  trigger.forEach((k) => fl.push(F.makeFact({ kind: k, scope: { target: '10.10.10.5' }, source: 't', created_at: T0 + 10000 })));
  return PK.nextActionsV2(new F.FactSet(fl), PACK, {}).map((a) => a.id);
}
function top1(base, trigger, expect, label) { const o = rank(base, trigger); ok(o[0] === expect, label + ' → #1 is ' + expect + ' (got ' + (o[0] || 'none') + ')'); }
function notTop1(base, trigger, banned, label) { const o = rank(base, trigger); ok(o[0] !== banned, label + ' → ' + banned + ' is NOT #1 (got ' + (o[0] || 'none') + ')'); }
function present(base, trigger, id, label) { ok(rank(base, trigger).indexOf(id) >= 0, label + ' → ' + id + ' is offered'); }

// --- a freshly-pasted blocker makes its fix the #1 next move ---
top1(['target.configured', 'ad.dc_candidate', 'ad.domain_known', 'kerberos.reachable', 'credential.available'], ['blocker.clock_skew'], 'fix-clock-skew', 'clock skew');
top1(['target.configured', 'smb.reachable', 'ad.dc_candidate'], ['blocker.password_change'], 'account-password-change', 'password must change');
top1(['target.configured', 'smb.reachable', 'ad.dc_candidate', 'credential.available'], ['blocker.ntlm_disabled'], 'ntlm-disabled-kerberos', 'NTLM disabled');
top1(['target.configured', 'smb.reachable', 'ad.dc_candidate'], ['blocker.lockout'], 'auth-account-blocked', 'account lockout');
top1(['target.configured', 'ssh.reachable', 'credential.certificate', 'port:22'], ['ssh.key_rejected'], 'ssh-key-troubleshoot', 'ssh key rejected');
top1(['target.configured'], ['blocker.host_down'], 'nmap-host-unresponsive', 'host seems down');
top1(['target.configured', 'port:80', 'http.reachable'], ['blocker.name_resolution'], 'fix-name-resolution', 'could not resolve host');
top1(['target.configured', 'foothold.linux', 'access.shell'], ['blocker.crlf'], 'fix-tool-wont-run', 'CRLF bad interpreter');
top1(['target.configured', 'foothold.linux', 'access.shell'], ['blocker.no_tty'], 'fix-no-tty', 'no tty');
top1(['target.configured', 'foothold.windows'], ['blocker.amsi'], 'bypass-amsi', 'AMSI block');
top1(['target.configured', 'foothold.windows', 'privesc.windows_privilege'], ['blocker.potato'], 'potato-select', 'potato failed');
top1(['target.configured', 'port:80', 'http.reachable', 'web.server'], ['blocker.rate_limited'], 'web-access-blocked', 'web rate-limited');
top1(['target.configured', 'port:443', 'http.reachable'], ['blocker.tls_scheme'], 'web-access-blocked', 'tls scheme');
top1(['target.configured', 'hash.ntlm'], ['blocker.hash_format'], 'crack-hash-troubleshoot', 'hash format');
top1(['target.configured', 'hash.ntlm'], ['blocker.hashcat_env'], 'crack-hash-troubleshoot', 'hashcat no-devices');
top1(['target.configured', 'foothold.linux', 'access.shell'], ['blocker.egress_blocked'], 'egress-blocked-shell', 'egress blocked');
top1(['target.configured', 'smb.reachable', 'ad.dc_candidate', 'ad.coerced_auth'], ['blocker.smb_signing'], 'relay-target-signing', 'smb signing');
top1(['target.configured', 'ad.dc_candidate', 'credential.available'], ['blocker.kerberos_spn'], 'kerberos-spn-fix', 'kerberos SPN');
top1(['target.configured', 'smb.reachable'], ['blocker.responder_quiet'], 'responder-tune', 'responder quiet');
top1(['target.configured', 'port:80', 'http.reachable', 'web.server'], ['blocker.web_wildcard'], 'web-access-blocked', 'gobuster wildcard');

// --- service→foothold: recon leads on a bare port; the exploit promotes once a lead indicates it ---
notTop1(['target.configured'], ['port:23', 'telnet.reachable'], 'telnet-login', 'bare telnet');
notTop1(['target.configured'], ['port:5432', 'postgres.reachable'], 'postgres-rce', 'bare postgres');
top1(['target.configured', 'port:5432', 'postgres.reachable'], ['db.session'], 'postgres-rce', 'postgres with db.session lead');
present(['target.configured'], ['port:23', 'telnet.reachable'], 'telnet-login', 'bare telnet still offers the login');

// --- the new pivot moves float on their own fresh discovery fact ---
top1(['target.configured', 'foothold.linux', 'access.shell'], ['scan.local.dns'], 'pivot-internal-dns', 'internal resolver found');
top1(['target.configured', 'foothold.linux', 'access.shell'], ['scan.local.neighbors'], 'pivot-enumerate-neighbors', 'neighbours found');

console.log('\nRANKER BLOCKERS SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
