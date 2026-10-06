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
 *   NXC-COVERAGE a NetExec capability or protocol the tb-nxc toolbuilder teaches (data/toolset.js — the
 *                "teach" surface) that no ranked MOVE backs, so it shows in teach but never in Next Steps.
 *                Derived from the builder itself; add a move using that nxc capability to clear it.
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
 *   SELF-SATISFIED a non-report move whose produced facts are all already among its own gates, so it
 *                 `settled()`s the instant that gate fact exists and can only fire through some other gate.
 *                 Usually the produces or the gate is mis-modeled (give it a distinct effect, or drop the
 *                 redundant gate). Report-only checks are exempt.
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
req('data/toolset.js');
req('assets/engine/parsers/common.js'); req('assets/engine/parsers/nxc-catalog.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack, PH = OBOL.phases;
var NXC_CAT = OBOL._nxcCatalog || [];
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

var fail = { fields: [], infoDead: [], nxcFirst: [], nxcCoverage: [], nxcUncat: [] };
var warn = { bareFoothold: [], shortcut: [], selfSat: [] };
function cmdTool(c) { return String((c && c.tool) || '').toLowerCase(); }
function isNxcTool(t) { return t === 'nxc' || t === 'netexec'; }
// Option/connection flags that configure a run but are NOT capabilities (don't change what's produced), so
// they need no catalog entry. Everything else (a -M module, or a capability --flag) must be catalogued.
var NXC_OPTION_FLAGS = { '--local-auth': 1, '--continue-on-success': 1, '--dns-server': 1, '--kdcHost': 1,
  '--kdchost': 1, '--use-kcache': 1, '--port': 1, '--threads': 1, '--timeout': 1, '--jitter': 1, '--verbose': 1,
  '--debug': 1, '--log': 1, '--no-bruteforce': 1, '--key-file': 1, '--kerberos': 1, '--aesKey': 1,
  '--regex': 1, '--content': 1, '--pattern': 1, '--exclude-dirs': 1, '--depth': 1 };
function nxcCatHas(proto, token) {
  return NXC_CAT.some(function (e) { return e.proto === proto && (('-M ' + e.module) === token || e.flag === token || (e.validate && token === '@validate')); });
}
// Extract (proto, capability-tokens) a single nxc command invokes.
function nxcTokens(run) {
  var m = String(run).match(/\bn(?:xc|etexec)\s+(smb|ldap|winrm|mssql|rdp|ftp|ssh|wmi|vnc|nfs)\b/i);
  if (!m) return null;
  var proto = m[1].toLowerCase(), toks = [];
  (run.match(/-M\s+([a-z0-9_]+)/gi) || []).forEach(function (x) { toks.push('-M ' + x.replace(/-M\s+/i, '')); });
  (run.match(/(^|\s)(--[a-z][a-z0-9-]+)/gi) || []).forEach(function (x) { var f = x.trim(); if (!NXC_OPTION_FLAGS[f]) toks.push(f); });
  if (/(^|\s)-x(\s|$)/.test(run)) toks.push('-x');
  if (/(^|\s)-X(\s|$)/.test(run)) toks.push('-X');
  if (/(^|\s)-q(\s|$)/.test(run)) toks.push('-q');
  if (!toks.length) toks.push('@validate'); // bare auth
  return { proto: proto, toks: toks };
}

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

  // NXC-UNCATALOGUED — an nxc command a move OFFERS whose protocol+capability has no catalog entry (hence
  // no parser): pasting its output would mint nothing. Every offered nxc switch/module must be in
  // nxc-catalog.js so the switch→parser test covers it. Keeps "exhaustive + parsed" from silently drifting.
  (a.commands || []).forEach(function (c) {
    if (!isNxcTool(cmdTool(c))) return;
    var t = nxcTokens(c.run || ''); if (!t) return;
    t.toks.forEach(function (tok) {
      if (tok === '@validate') return; // bare auth handled by _parse_nxc_common for every protocol
      if (!nxcCatHas(t.proto, tok)) fail.nxcUncat.push(a.id + '  offers `nxc ' + t.proto + ' … ' + tok + '` with no catalog entry (add it to nxc-catalog.js + a switch→parser sample)');
    });
  });

  // SELF-SATISFIED — a (non-report) move whose produced facts are ALL already in its own gates. Once that
  // gate fact exists the move is `settled()` and vanishes, so it can only ever run in the narrow window
  // where some OTHER gate admits it — usually a sign the produces or the gate is mis-modeled. Report-only
  // checks are exempt (they live in the collapsed group and re-running them to refine a fact is fine).
  if (produces.length && !PK.isReportOnly(a, A) && produces.every(function (k) { return gates.indexOf(k) >= 0; })) {
    warn.selfSat.push(a.id + '  produces ' + produces.join(', ') + ' ⊆ gates (' + gates.join(', ') + ') — settles as soon as that gate holds');
  }

  // SHORTCUT — produces a privilege fact straight from a soft AD lead with nothing proven in hand. "In hand"
  // = a held credential/hash/ticket, an existing access, OR a PROVEN primitive the ranker counts as evidence
  // (ad.control_paths/adcs.vulnerable, a privesc.* primitive, a vuln.* fingerprint, a *_confirmed verdict).
  // A move gated on one of those is evidenced, not a one-step jump — only a bare soft lead with none of them
  // is the over-claim this flags.
  if (PK.producesPrivilege(a)) {
    var hardGate = gates.some(function (g) { return /^(credential\.|hash\.|kerberos\.tickets|access\.|privesc\.|adcs\.|vuln\.)/.test(g) || g === 'ad.control_paths' || /_confirmed$/.test(g); });
    var softLead = gates.some(function (g) { return AD_LEAD[g]; });
    if (!hardGate && softLead) {
      warn.shortcut.push(a.id + '  → ' + produces.filter(function (k) { return PK.producesPrivilege({ produces: [k] }); }).join(', ') + ' from soft lead (gates: ' + gates.join(', ') + ')');
    }
  }
});

// NXC-COVERAGE — teach↔moves parity. The tb-nxc toolbuilder (data/toolset.js) is the "teach" surface: it
// offers a protocol + an action for every NetExec capability we teach. nxc being the preferred tool, every
// capability the builder teaches must have at least one ranked MOVE backing it — otherwise it shows up in
// teach but never in Next Steps (the exact gap the operator flagged). Derived from the builder itself (not a
// hand-list) so it stays honest as the builder grows: each action's distinctive arg token (--flag or
// `-M module`) and each protocol must appear in some move's nxc command.
(function () {
  var TS = (OBOL.TOOLSET || []).filter(Boolean);
  var nxc = TS.filter(function (t) { return t.id === 'tb-nxc'; })[0];
  if (!nxc || !nxc.command) return;
  var tokFor = function (field) { return (nxc.command.tokens || []).filter(function (t) { return t.field === field; })[0] || { choices: [] }; };
  // every nxc command string across all moves, lowercased
  var nxcCmds = [];
  A.forEach(function (a) { (a.commands || []).forEach(function (c) { if (isNxcTool(cmdTool(c))) nxcCmds.push(String(c.run || '').toLowerCase()); }); });
  var haystack = nxcCmds.join('\n');
  // capability signatures: the first `--flag` or `-M module` in each action's arg (validate/exec handled below)
  (tokFor('action').choices || []).forEach(function (ch) {
    var arg = String(ch.arg || '').toLowerCase();
    var sig = null;
    var mod = arg.match(/-m\s+([a-z0-9_]+)/); var flag = arg.match(/--[a-z0-9-]+/);
    if (mod) sig = '-m ' + mod[1]; else if (flag) sig = flag[0];
    else if (ch.value === 'exec-cmd' || ch.value === 'exec-ps') sig = null; // exec checked separately
    else return; // validate = bare auth, trivially covered if any nxc move exists
    if (sig && haystack.indexOf(sig) < 0) fail.nxcCoverage.push('capability "' + ch.value + '" (' + sig + ') is taught by tb-nxc but no move uses it');
  });
  // exec: at least one move must run nxc with -x or -X
  if (!/\s-x\s|\s-x'|\s-x"|\s-x$|\s-X\s/.test(haystack)) fail.nxcCoverage.push('capability "exec" (-x/-X) is taught by tb-nxc but no move uses it');
  // protocols
  (tokFor('protocol').choices || []).forEach(function (ch) {
    var proto = String(ch.arg || ch.value || '').toLowerCase();
    if (!proto) return;
    if (haystack.indexOf('nxc ' + proto) < 0 && haystack.indexOf('netexec ' + proto) < 0) {
      fail.nxcCoverage.push('protocol "' + proto + '" is offered by tb-nxc but no move runs `nxc ' + proto + '`');
    }
  });
})();

function section(title, arr) {
  console.log('\n== ' + title + ' (' + arr.length + ') ==');
  if (!arr.length) { console.log('  (none)'); return; }
  arr.forEach(function (x) { console.log('  ' + x); });
}

console.log('OBOL move-contract lint — ' + A.length + ' moves');
section('FAIL · FIELDS — missing/invalid locus or phase', fail.fields);
section('FAIL · INFO-DEADEND — informational move not tagged report-only', fail.infoDead);
section('FAIL · NXC-FIRST — nxc command variant present but not leading (not at index 0)', fail.nxcFirst);
section('FAIL · NXC-COVERAGE — a NetExec capability/protocol taught by tb-nxc with no backing move', fail.nxcCoverage);
section('FAIL · NXC-UNCATALOGUED — a move offers an nxc switch/module with no catalog entry (no parser)', fail.nxcUncat);
section('WARN · UNINDICATED-PAYOFF — foothold/priv/validated-credential with no evidence gate (speculative-only)', warn.bareFoothold);
section('WARN · SHORTCUT — privilege claimed straight from a soft AD lead', warn.shortcut);
section('WARN · SELF-SATISFIED — move produces only facts it already requires (settles immediately)', warn.selfSat);

var failCount = fail.fields.length + fail.infoDead.length + fail.nxcFirst.length + fail.nxcCoverage.length + fail.nxcUncat.length;
var warnCount = warn.bareFoothold.length + warn.shortcut.length + warn.selfSat.length;
console.log('\n' + A.length + ' moves · ' + failCount + ' FAIL · ' + warnCount + ' WARN');
if (CHECK && failCount) { console.error('MOVE LINT FAIL: ' + failCount + ' contract breach(es).'); process.exit(1); }
if (CHECK) console.log('MOVE LINT OK: every move satisfies the contract (warnings are advisory).');
