/* Node sanity test for the ported report pipeline (engine/report.js).
 * Builds a small context from browser-shaped state and asserts:
 *   - the OSCP profile renders its sections in the expected order (markdown),
 *   - redaction blanks a harvested secret by default and shows it when includeSecrets=true,
 *   - the `-p` allowlist keeps `nmap -p 445` intact while redacting `smbclient ... -p secret`,
 *   - validate() flags an OSCP report with no OSID set,
 *   - proofLabels() classifies non-interactive / identity-missing proof.
 * Fixtures are inline. */
'use strict';

// Load the browser engine modules into Node's global (they attach to globalThis).
// reportmeta.js targets `window`; shim it so the real finding backing loads unchanged.
globalThis.window = globalThis;
require('../../assets/engine/facts.js');
require('../../data/reportmeta.js');   // sets window.OBOL_REPORTMETA (the finding backing we keep)
require('../../assets/engine/report.js');
const OBOL = globalThis.OBOL;
const F = OBOL.facts;
const R = OBOL.report;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// ── inline fixture ────────────────────────────────────────────────────────
const SECRET = 'Sup3rSecretPass!';   // a harvested credential value (>= 6 chars)
const HOST_A = '10.10.10.10';
const HOST_B = '10.10.10.20';

function mk(kind, scope, value, source, at) {
  return F.makeFact({ kind, scope, value: value || {}, state: F.ProofState.SUPPORTED, source: source || '', created_at: at || 0 });
}

const factset = new F.FactSet([
  // host A: recon → foothold → credential (with a secret) → a captured local flag
  mk('host.up', 'host:' + HOST_A, {}, 'nmap -sn ' + HOST_A, 1),
  mk('port:445', 'host:' + HOST_A, { protocol: 'tcp', service: 'microsoft-ds' }, 'nmap -p 445 ' + HOST_A, 2),
  mk('foothold.linux', 'host:' + HOST_A, { user: 'svc' }, 'ssh svc@' + HOST_A, 4),
  mk('credential.available', 'host:' + HOST_A, { user: 'admin', password: SECRET },
    'nxc smb ' + HOST_A + ' -u admin -p ' + SECRET, 5),
  mk('objective.local_flag', 'host:' + HOST_A, { slot: 'local', flag: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', path: '/home/svc/local.txt' },
    'ssh svc@' + HOST_A + ' cat local.txt', 6),
  // a catalogued finding on host A (backing = reportmeta enrichment by card id)
  mk('finding.smb-anon-enum', 'host:' + HOST_A, {
    title: 'Anonymous SMB share access', severity: 'high', category: 'access', key: 'smb-anon',
    card: 'smb-anon-enum', description: 'Null-session enumeration exposed shares.',
  }, 'nxc smb ' + HOST_A + ' -u "" -p ""', 3),
  // host B: only recon
  mk('host.up', 'host:' + HOST_B, {}, 'nmap -sn ' + HOST_B, 1),
]);

const targets = [
  { host: HOST_A, label: 'ALPHA', hostname: 'alpha', domain: '', os: 'Linux', status: 'owned', notes: '' },
  { host: HOST_B, label: 'BRAVO', hostname: '', domain: '', os: '', status: '', notes: '' },
];

const activities = [
  { tool: 'nxc', command: 'nxc smb ' + HOST_A + ' -u admin -p ' + SECRET, at: 5, produced: ['credential.available'], returncode: 0 },
];

const credentials = [{ user: 'admin', secret: SECRET, source: 'nxc', validated: true }];

ok(globalThis.OBOL_REPORTMETA && globalThis.OBOL_REPORTMETA.cards['smb-anon-enum'], 'reportmeta finding backing loaded (kept from obol_web)');

function ctxWith(includeSecrets, params) {
  return R.buildContext({
    facts: factset, targets, activities, credentials,
    params: Object.assign({ name: 'exam', scope: [HOST_A, HOST_B], platform: 'oscp' }, params || {}),
    screenshots: [], reportmeta: globalThis.OBOL_REPORTMETA, includeSecrets,
  });
}

// ── 1) OSCP section order in markdown ───────────────────────────────────────
const ctx = ctxWith(false);
const md = R.toMarkdown(R.document('oscp', ctx));
const headings = md.split('\n').filter((l) => /^#{1,2} /.test(l)).map((l) => l.replace(/^#{1,2} /, ''));
const expected = [
  'OSCP Exam Report',
  'High-Level Summary',
  'Recommendations',
  'Exam Objective Summary',
  'Methodology',
  'Attack Narrative',
  'Per-Machine Walkthrough',
  'Proof of Access',
  'Appendix: Key Commands & Evidence',
];
console.log('  headings:', JSON.stringify(headings));
ok(JSON.stringify(headings) === JSON.stringify(expected), 'OSCP renders sections in the expected order');
ok(R.defaultFor(ctx) === 'oscp', 'defaultFor() picks oscp for an oscp platform');

// ── 2) redaction: secret blanked by default, shown with includeSecrets ──────
ok(md.indexOf(SECRET) === -1, 'default report does NOT leak the harvested secret');
ok(md.indexOf('<redacted>') !== -1, 'default report shows <redacted> where the secret was');

const mdOpen = R.toMarkdown(R.document('oscp', ctxWith(true)));
ok(mdOpen.indexOf(SECRET) !== -1, 'includeSecrets=true surfaces the real secret');

// value-level redaction of the credential fact
const cvOff = R.buildContext({ facts: factset, targets, activities, credentials, params: { name: 'x' }, includeSecrets: false });
const credFact = cvOff.facts.find((f) => f.kind === 'credential.available');
ok(credFact && credFact.value.password === '<redacted>', 'redactValue blanks the credential password by default');
const cvOn = R.buildContext({ facts: factset, targets, activities, credentials, params: { name: 'x' }, includeSecrets: true });
const credFactOn = cvOn.facts.find((f) => f.kind === 'credential.available');
ok(credFactOn && credFactOn.value.password === SECRET, 'redactValue reveals the password with includeSecrets');

// ── 3) the -p allowlist ─────────────────────────────────────────────────────
const nmapCmd = 'nmap -p 445 ' + HOST_A;
ok(R.redact(nmapCmd, { includeSecrets: false, secrets: [] }) === nmapCmd, 'nmap -p 445 is left intact (port flag, spared tool)');

const smbCmd = 'smbclient //10.10.10.10/share -p hunter2xyz';
const smbRed = R.redact(smbCmd, { includeSecrets: false, secrets: [] });
ok(smbRed.indexOf('hunter2xyz') === -1 && smbRed.indexOf('<redacted>') !== -1, 'smbclient -p secret is redacted (password flag, non-spared tool)');

// value-based redaction catches a glued/unknown-flag secret too
const glued = R.redact('nxc smb h -u admin -pp=' + SECRET, { includeSecrets: false, secrets: [SECRET] });
ok(glued.indexOf(SECRET) === -1, 'value-based redaction blanks a harvested secret in any command shape');

// ── 4) validate() flags a missing OSID ──────────────────────────────────────
const gapsNoOsid = R.validate('oscp', ctxWith(false));
ok(gapsNoOsid.some((g) => /OSID/.test(g.message)), 'validate() flags an OSCP report with no OSID');
const gapsWithOsid = R.validate('oscp', ctxWith(false, { osid: 'OS-12345', candidate: 'Test Operator' }));
ok(!gapsWithOsid.some((g) => /OSID/.test(g.message)), 'validate() stops flagging OSID once it is set');
// the captured local flag has no compliant proof → screenshots_required fail
ok(gapsWithOsid.some((g) => g.level === 'fail' && /ZERO points/.test(g.message)), 'validate() flags a flag with no compliant proof screenshot');

// ── 5) proofLabels() proof discipline ───────────────────────────────────────
const nonInteractive = R.proofLabels({ command: 'nxc smb 10.10.10.10 -u admin -p x -x "type proof.txt"', block: 'proof: abc 10.10.10.10 hostname WIN', os: 'windows' });
ok(nonInteractive.interactive === false && nonInteractive.flags.some((f) => /Non-interactive/.test(f.message)), 'proofLabels flags a non-interactive nxc transport as scoring zero');
const interactive = R.proofLabels({ command: 'evil-winrm -i 10.10.10.10 -u admin -p x', block: 'C:\\Users> ipconfig\n  IPv4 Address. . . : 10.10.10.10\nhostname\nWIN-DC01', os: 'windows' });
ok(interactive.interactive === true && interactive.identityPresent === true && interactive.compliant === true, 'proofLabels credits an interactive evil-winrm shell with identity present');
const noIdentity = R.proofLabels({ command: 'ssh svc@10.10.10.10', block: 'THM{just_the_flag}' });
ok(noIdentity.identityPresent === false && noIdentity.flags.some((f) => /identity/.test(f.message)), 'proofLabels flags a capture missing host identity');

// ── 6) HTML renderer sanity ─────────────────────────────────────────────────
const html = R.toHtml(R.document('oscp', ctx));
ok(/<h1[^>]*>OSCP Exam Report<\/h1>/.test(html), 'HTML renderer emits the report title heading');
ok(html.indexOf(SECRET) === -1, 'HTML report also honors redaction by default');

console.log(fail ? ('\nREPORT SMOKE: ' + fail + ' FAILURES') : '\nREPORT SMOKE: all passed');
process.exit(fail ? 1 : 0);
