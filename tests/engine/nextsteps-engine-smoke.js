/* Next Steps redesign — engine foundations. Locks the three new pure helpers the rebuilt #/path route is
 * built on: (1) per-command locus is the "does it put me ON the host" axis (a session tool like evil-winrm
 * is on-host even though it launches from Kali; nxc/nmap are remote), with Remote the default everywhere
 * except a flag-capture move; (2) every gate kind now renders a human Title-Case chip label — no raw
 * machine strings leak into the UI; (3) opensUpNext is an aspirational roadmap of capability-unlocks only,
 * excluding the blocker-dot and vuln-dot contingency moves and report-only checks, nearest unlock first.
 * Generic data. */
'use strict';
const fs = require('fs');
const path = require('path');
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
const OBOL = globalThis.OBOL;
const P = OBOL.pack;

const pack = P.loadPacks(P.PACK_NAMES.map((n) =>
  JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'data', 'packs', n + '.json'), 'utf8'))));
const F = OBOL.facts;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function byId(id) { return pack.filter((a) => a.id === id)[0]; }

// 1. Per-command locus — the session axis, not the launch-location axis.
ok(P.commandLocus({ tool: 'evil-winrm' }) === 'onhost', 'evil-winrm is on-host (it hands you a session on the box)');
ok(P.commandLocus({ tool: 'ssh' }) === 'onhost', 'ssh is on-host');
ok(P.commandLocus({ tool: 'cmd' }) === 'onhost', 'cmd (run inside a session) is on-host');
ok(P.commandLocus({ tool: 'linpeas' }) === 'onhost', 'linpeas is on-host');
ok(P.commandLocus({ tool: 'nxc' }) === 'remote', 'nxc is remote (interrogates from Kali)');
ok(P.commandLocus({ tool: 'nmap' }) === 'remote', 'nmap is remote');
ok(P.commandLocus({ tool: 'impacket-secretsdump' }) === 'remote', 'secretsdump is remote (dumps over the wire, no session)');
ok(P.commandLocus({ tool: 'nmap', locus: 'onhost' }) === 'onhost', 'a per-command locus override wins over the tool default');

// 2. Default toggle side: Remote everywhere, On-Host only for a flag-capture move.
const flagMove = byId('flag-hunt-windows');
const enumMove = byId('ad-user-enum') || byId('ad-anon-ldap-enum');
ok(P.defaultCommandLocus(flagMove) === 'onhost', 'a flag-capture move defaults to On-Host (a remote read scores zero)');
ok(enumMove && P.defaultCommandLocus(enumMove) === 'remote', 'a non-flag move defaults to Remote');

// the flag move genuinely spans both loci, so the toggle should appear; a single-locus move should not.
const fhLoci = P.moveCommandLoci(flagMove);
ok(fhLoci.both, 'flag-hunt-windows spans both loci (nxc spider remote + evil-winrm/type on-host) → toggle shown');

// 3. Every gate kind renders a human label — no raw machine string leaks (regression for the 51 unlabelled).
const gates = {};
pack.forEach((a) => (a.requires_all || []).concat(a.requires_any || []).forEach((k) => { gates[k] = 1; }));
const raw = Object.keys(gates).filter((k) => P.friendly(k) === k && k.indexOf('port:') !== 0 && k.indexOf('service.') !== 0);
ok(raw.length === 0, 'every gate kind has a friendly label (unlabelled: ' + (raw.join(', ') || 'none') + ')');
ok(P.chipLabel('credential.available') === 'Usable Credential', 'chipLabel drops the article and Title-Cases ("Usable Credential")');
ok(/SYSTEM/.test(P.chipLabel('access.system')), 'chipLabel preserves acronyms/caps (SYSTEM)');

// 4. opensUpNext — aspirational capability unlocks only, nearest first, contingency/report excluded.
const set = new F.FactSet([]);
['target.configured', 'host.up', 'ports.open', 'port:445', 'port:80', 'os.linux', 'scan.nmap.quick', 'http.service'].forEach((k) =>
  set.add(F.makeFact({ kind: k, scope: 'host:10.0.0.5', state: F.ProofState.SUPPORTED })));
const opens = P.opensUpNext(set, pack);
ok(opens.length > 0, 'opensUpNext returns a roadmap (' + opens.length + ' moves)');
const openIds = opens.map((o) => o.action.id);
ok(!openIds.some((id) => /^(fix-|bypass-|potato-|crack-hash-troubleshoot|ssh-key-troubleshoot|responder-tune|relay-target-signing|account-password|ntlm-disabled|auth-account|web-access-blocked|egress-blocked|kerberos-spn|nmap-host-unresponsive|fix-no-tty|fix-name|fix-tool)/.test(id)),
  'no trap-doctor (blocker.*) move appears in the aspirational roadmap');
ok(opens.every((o) => !o.needs.some((k) => /^(blocker|vuln)\./.test(k))), 'no roadmap card needs a blocker.*/vuln.* contingency fact');
ok(opens.every((o) => o.needs.length > 0), 'every roadmap card carries at least one fact-chip (what it needs)');
// nearness ordering: steps are non-decreasing down the list
let sorted = true; for (let i = 1; i < opens.length; i++) if (opens[i].steps < opens[i - 1].steps) sorted = false;
ok(sorted, 'the roadmap is sorted by nearness-to-unlock (fewest unmet prerequisites first)');

console.log(fail ? ('\nNEXT STEPS ENGINE: ' + fail + ' FAILURES') : '\nNEXT STEPS ENGINE: all passed');
process.exit(fail ? 1 : 0);
