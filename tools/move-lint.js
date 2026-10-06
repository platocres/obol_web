#!/usr/bin/env node
/*!
 * tools/move-lint.js — the MOVE CONTRACT linter (see docs/MOVE-ENGINE.md).
 *
 * The ranking engine is only as sustainable as the honesty of each move's own declaration. This lint
 * enforces that contract at authoring time, using the SAME fact-classification the ranker uses
 * (OBOL.pack.*), so a move that passes here is one the ranker places sanely — no per-box tuning, no
 * hunting through labs to discover a mis-ranked move.
 *
 * FAIL (exit 1 under --check) — unambiguous contract breaches:
 *   FIELDS       a move missing/invalid locus or phase.
 *   INFO-DEADEND a move that produces ONLY informational facts (not a goal, not consumed by any move,
 *                not an evidence/loot fact) yet is NOT tagged report-only (severity: info). This is the
 *                class that let "Email DNS Review (SPF/DMARC)" headline a live box. Tag it info (so the
 *                coach files it under Report Checks) or give it a real, consumed effect.
 *   NXC-FIRST    a move that offers an nxc (NetExec) command variant but does NOT lead with it (the nxc
 *                command sits at a later index than 0). NetExec is the preferred tool (docs/MOVE-ENGINE.md
 *                "Operator preferences") — when a move can be done with nxc, its nxc command leads. Exempt:
 *                moves tagged sequence:true, where commands are ordered pipeline steps (build-then-load,
 *                confirm-then-act), not interchangeable alternatives.
 *
 * WARN (review, never blocks) — judgment calls worth a human glance:
 *   UNINDICATED-PAYOFF a move that produces a real payoff (foothold/privilege, or a VALIDATED credential)
 *                 without any evidence gate — it can only ever fire as a gamble (blind spray, exploit at a
 *                 bare port). The ranker caps it; gate it on the fact that actually yields the payoff
 *                 (a found credential.candidate to spray, a hash to crack) or confirm it's meant to be
 *                 speculative.
 *   SHORTCUT      a move that produces a privilege fact (access.admin/system/root/loot.ntds) straight
 *                 from a soft AD lead (ad.attack_paths/acl_lead/control_paths/delegation) with no
 *                 credential/hash/ticket in hand — an over-claimed one-step jump to DA. Prefer modeling
 *                 the honest intermediate (→ ad.control_paths → dcsync) so the remote twin wins by cost.
 *
 * Run:  node tools/move-lint.js           (full report)
 *       node tools/move-lint.js --check   (exit 1 on any FAIL)
 */
'use strict';
var fs = require('fs'), path = require('path');
var ROOT = path.join(__dirname, '..');
function req(p) { return require(path.join(ROOT, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack, PH = OBOL.phases;
var pdir = path.join(ROOT, 'data/packs');
var A = PK.loadPacks(fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); })
  .map(function (f) { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } }));

var argv = process.argv.slice(2), CHECK = argv.indexOf('--check') >= 0;

// Legitimately-terminal facts: produced as a real end-state or consumed by the UI rather than by another
// move's requires, so they are NOT "informational dead-ends" even though no move consumes them. This is a
// deliberate, documented allow-list — the contract for adding one is: wire your new fact to a consumer, OR
// register it here with a reason, OR tag the move severity:info (a Report Check). An unregistered,
// unconsumed, non-evidence, non-goal fact is what let "Email DNS Review" headline a live box, so it FAILs.
var TERMINAL_FACTS = {
  // local recon from a foothold — consumed by the hub's Connectivity map / pivot planner (UI), not a move.
  'scan.local.interfaces': 1, 'scan.local.routes': 1, 'scan.local.neighbors': 1, 'scan.local.dns': 1, 'scan.local.listeners': 1,
  // tunnels/pivots — infrastructure the Connectivity panel reads, an end-state of the pivot wizard.
  'tunnel.route': 1, 'tunnel.dns': 1, 'tunnel.socks': 1,
  // end-state outcomes (goals in their own right, surfaced in the report / scoreboard).
  'persistence.domain': 1, 'persistence.linux': 1, 'persistence.windows': 1,
  // posture the coach reads directly (defenseAdvisory) + scan leads surfaced for the operator.
  'defense.control': 1, 'scan.nmap.vuln': 1, 'dns.zone': 1,
  // standalone findings that ARE the deliverable (medium/high severity report items, not info noise).
  'http.exposed': 1, 'http.redirect': 1, 'dns.takeover': 1, 'config.review': 1,
  // web exploitation leads the operator pursues by hand (candidate = the finding).
  'web.idor_candidate': 1, 'web.authz_bypass': 1,
};

// Every fact some move consumes (a requirement). A produced fact that is consumed, is a goal, is an
// evidence/loot fact, or is a registered terminal, represents real progress/outcome; anything else a move
// produces is purely informational and the move must be tagged report-only.
var consumed = {};
A.forEach(function (a) { (a.requires_all || []).concat(a.requires_any || []).forEach(function (k) { consumed[k] = 1; }); });
var GOAL = {}; (PK.GOALS || []).forEach(function (g) { GOAL[g] = 1; });
var VALID_LOCUS = { R: 1, F: 1, I: 1 };
var PHASES = {}; (PH.PHASES || []).forEach(function (p) { PHASES[p] = 1; });
var AD_LEAD = { 'ad.attack_paths': 1, 'ad.acl_lead': 1, 'ad.control_paths': 1, 'ad.delegation': 1, 'ad.trusts': 1, 'foothold.windows': 1, 'foothold.linux': 1 };

var fail = { fields: [], infoDead: [], nxcFirst: [] };
var warn = { bareFoothold: [], shortcut: [] };
function cmdTool(c) { return String((c && c.tool) || '').toLowerCase(); }
function isNxcTool(t) { return t === 'nxc' || t === 'netexec'; }

A.forEach(function (a) {
  var gates = (a.requires_all || []).concat(a.requires_any || []);
  var produces = a.produces || [];

  // FIELDS — locus + phase present and valid.
  var locus = a.locus || (PK.deriveLocus ? PK.deriveLocus(a) : '');
  var phase = PH.phaseOfAction ? PH.phaseOfAction(a) : a.phase;
  var fieldProblems = [];
  if (!VALID_LOCUS[locus]) fieldProblems.push('locus=' + JSON.stringify(a.locus));
  if (!phase || !PHASES[phase]) fieldProblems.push('phase=' + JSON.stringify(phase));
  if (fieldProblems.length) fail.fields.push(a.id + '  ' + fieldProblems.join(' '));

  // INFO-DEADEND — produces only informational facts yet not report-only.
  if (produces.length) {
    var allInformational = produces.every(function (k) {
      return !GOAL[k] && !consumed[k] && !PK.isEvidenceFact(k) && !TERMINAL_FACTS[k];
    });
    if (allInformational && !PK.isReportOnly(a, A)) {
      fail.infoDead.push(a.id + '  → produces ' + produces.join(', ') + ' (nothing consumes; not a goal; not evidence) — tag severity:info or give it a real effect');
    }
  }

  // UNINDICATED-PAYOFF — produces a real payoff (a foothold/priv fact, or a VALIDATED credential) with no
  // evidence gate, so it can only ever fire as a gamble (blind spray, default-cred guess, exploit at a bare
  // port). The ranker caps it; the author should make sure that's intended, or gate it on the fact that
  // actually produces the payoff (e.g. a found credential.candidate for spraying, a hash for cracking).
  var producesValidatedCred = produces.some(function (k) { return k === 'credential.available' || k === 'credential.plaintext'; });
  if (PK.producesFoothold(a) || producesValidatedCred) {
    var hasEvidenceGate = gates.some(function (g) { return PK.isEvidenceFact(g); });
    if (!hasEvidenceGate) warn.bareFoothold.push(a.id + '  (produces ' + produces.filter(function (k) { return /^(foothold\.|access\.)/.test(k) || k === 'credential.available' || k === 'credential.plaintext'; }).join(', ') + '; gates: ' + (gates.join(', ') || 'none') + ')');
  }

  // NXC-FIRST — nxc is the preferred tool; when a move offers an nxc command variant it must lead (index 0).
  // Commands are interchangeable alternatives here; sequence:true moves (ordered pipeline steps) are exempt.
  if (!a.sequence) {
    var cmds = a.commands || [];
    var nxcIdx = -1;
    for (var ci = 0; ci < cmds.length; ci++) { if (isNxcTool(cmdTool(cmds[ci]))) { nxcIdx = ci; break; } }
    if (nxcIdx > 0) {
      fail.nxcFirst.push(a.id + '  nxc command at index ' + nxcIdx + ' of ' + cmds.length + ' (pos0=' + (cmdTool(cmds[0]) || '?') + ') — lead with the nxc variant, or tag sequence:true if these are ordered steps');
    }
  }

  // SHORTCUT — produces a privilege fact straight from a soft AD lead, no credential/hash/ticket held.
  if (PK.producesPrivilege(a)) {
    var hardGate = gates.some(function (g) { return /^(credential\.|hash\.|kerberos\.tickets|access\.)/.test(g); });
    var softLead = gates.some(function (g) { return AD_LEAD[g]; });
    if (!hardGate && softLead) {
      warn.shortcut.push(a.id + '  → ' + produces.filter(function (k) { return PK.producesPrivilege({ produces: [k] }); }).join(', ') + ' from soft lead (gates: ' + gates.join(', ') + ')');
    }
  }
});

function section(title, arr) {
  console.log('\n== ' + title + ' (' + arr.length + ') ==');
  if (!arr.length) { console.log('  (none)'); return; }
  arr.forEach(function (x) { console.log('  ' + x); });
}

console.log('OBOL move-contract lint — ' + A.length + ' moves');
section('FAIL · FIELDS — missing/invalid locus or phase', fail.fields);
section('FAIL · INFO-DEADEND — informational move not tagged report-only', fail.infoDead);
section('FAIL · NXC-FIRST — nxc command variant present but not leading (not at index 0)', fail.nxcFirst);
section('WARN · UNINDICATED-PAYOFF — foothold/priv/validated-credential with no evidence gate (speculative-only)', warn.bareFoothold);
section('WARN · SHORTCUT — privilege claimed straight from a soft AD lead', warn.shortcut);

var failCount = fail.fields.length + fail.infoDead.length + fail.nxcFirst.length;
console.log('\n' + A.length + ' moves · ' + failCount + ' FAIL · ' + (warn.bareFoothold.length + warn.shortcut.length) + ' WARN');
if (CHECK && failCount) { console.error('MOVE LINT FAIL: ' + failCount + ' contract breach(es).'); process.exit(1); }
if (CHECK) console.log('MOVE LINT OK: every move satisfies the contract (warnings are advisory).');
