/*!
 * obol engine — cruise.js — Cruise control for the browser, the exam-legal, no-execution port of
 * obol-local/obol/cruise.py. obol-local runs ONE safe move per loop (execution is free there). Here
 * the human is the execution channel and the expensive step is the PASTE round-trip, so Cruise hands
 * out a phase-scoped BATCH of the moves that are independent of each other's output, then checkpoints
 * where output genuinely changes what comes next. The batch is a FRONTIER CUT over the move graph
 * (requires_* / produces), derived from data we already have.
 *
 * Exam-legal by construction: Cruise only ever batches SAFE enumeration and always checkpoints before
 * anything that lands a shell, sprays/brutes creds, or fires an exploit. Two modes: exam (safe only,
 * default) and lab (also batches foothold/setup; NOT exam-legal). The human reviews and runs every
 * command; obol never executes.
 *
 * Pure and Node-safe: reads nothing from OBOL.store. plan() takes the FactSet + pack; the route owns
 * the store, the paste-back ingest, and the regenerate loop. Boundary: one store, one filler, the
 * ranker is NOT forked (Cruise calls OBOL.pack.rankActions and only re-presents its output).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var P = OBOL.phases;

  var MODES = ['exam', 'lab'];

  // Fact kinds that mean "a shell / a foothold / elevated access was gained" — producing one of these
  // is always a Cruise checkpoint (you decide before you run the move that lands it), never auto-batched.
  var FOOTHOLD_KINDS = {
    'foothold.linux': 1, 'foothold.windows': 1, 'foothold.webshell': 1,
    'access.shell': 1, 'access.admin': 1, 'access.system': 1, 'access.root': 1,
  };
  // A move whose id/tool reads as a credential spray or brute: noisy, lockout risk, run it deliberately.
  var SPRAY_RE = /spray|brute|bruteforce|hydra|medusa|ncrack|kerbrute|guess|cred-?stuff|password-?spray/i;
  // A move whose id reads as running an exploit / gaining code execution: never auto-batched.
  var EXPLOIT_RE = /exploit|rce|overflow|deserial|payload|revshell|reverse-?shell|eternalblue|bluekeep|zerologon|nopac|petitpotam|printnightmare|smbghost|log4shell|shellshock|struts|dirtycow|pwnkit|ms\d\d-\d\d\d|cve-\d/i;

  function phaseOf(action) { try { return (P && P.phaseOfAction) ? P.phaseOfAction(action) : (action.phase || ''); } catch (e) { return action.phase || ''; } }

  // A move that would gain or escalate access (a shell/session/foothold/credentialed login that lands you
  // ON the box). Keyed on produced fact kinds, so it catches footholds however the move is named.
  function producesFoothold(action) {
    var pr = (action && action.produces) || [];
    for (var i = 0; i < pr.length; i++) {
      var k = pr[i];
      if (FOOTHOLD_KINDS[k] || /^(access|foothold|session)\./.test(k) || /_confirmed$/.test(k)) return true;
    }
    return false;
  }

  // The Cruise tier of a move. Explicit pack autonomy wins (auto/approve/manual, the pack author's call).
  // Otherwise DEFAULT TO SAFE (enumeration and discovery, including reading shares/LDAP/loot), and only
  // lift to 'active' on a positive "lands a shell / sprays / exploits" signal. So safe enumeration across
  // every phase auto-batches in exam mode; the dangerous classes (foothold, spray/brute, exploit/RCE)
  // still hard-stop at a checkpoint. 'manual' is only ever an explicit pack flag.
  function tierOf(action) {
    if (!action) return 'manual';
    var au = String(action.autonomy || '').toLowerCase();
    if (au === 'auto') return 'safe';
    if (au === 'approve') return 'active';
    if (au === 'manual') return 'manual';
    var id = action.id || '';
    if (producesFoothold(action)) return 'active';   // gains/escalates access
    if (SPRAY_RE.test(id)) return 'active';           // sprays or brute-forces credentials
    if (EXPLOIT_RE.test(id)) return 'active';         // runs an exploit / gains code execution
    return 'safe';                                    // everything else is enumeration: auto-batch it
  }

  function allowsTier(mode, tier) {
    if (mode === 'lab') return tier === 'safe' || tier === 'active';
    return tier === 'safe';   // exam (default): safe enumeration only
  }

  // Forward-looking preview: the BLOCKED moves this batch would likely unlock, i.e. a move that is not
  // eligible yet but whose missing prerequisite is a fact-kind one of the batched moves produces. This
  // is the honest "what comes next" (the dependent steps that appear in the NEXT round after you paste).
  // Returns [{action, via}] where via is the produced kind that would unlock it.
  function unlocksFrom(facts, pack, producedSet, cap) {
    var out = [], locked = [];
    try { locked = OBOL.pack.lockedActions(facts, pack) || []; } catch (e) { locked = []; }
    for (var i = 0; i < locked.length && out.length < (cap || 6); i++) {
      var a = locked[i].action;
      var gates = (a.requires_all || []).concat(a.requires_any || []);
      for (var j = 0; j < gates.length; j++) {
        if (producedSet[gates[j]] && !facts.has(gates[j])) { out.push({ action: a, via: gates[j] }); break; }
      }
    }
    return out;
  }

  function cmdIndexFor(action, facts) {
    try {
      if (OBOL.pack && OBOL.pack.preferredCommandIndex) {
        var idx = OBOL.pack.preferredCommandIndex(action, action.locus, facts);
        return (typeof idx === 'number' && idx >= 0) ? idx : 0;
      }
    } catch (e) {}
    return 0;
  }

  function reasonFor(action, tier, mode) {
    var base;
    if (producesFoothold(action)) base = 'This move lands or escalates access. You decide before you run it.';
    else if (SPRAY_RE.test(action.id || '')) base = 'This move sprays or brute-forces credentials. Noisy, so run it deliberately.';
    else if (tier === 'manual') base = 'This move is interactive or flagged manual. Run it by hand.';
    else { var ph = phaseOf(action) || 'next-step'; base = 'This is a ' + ph + ' phase move. Review it before you run it.'; }
    if (mode === 'exam' && tier === 'active') base += ' Exam mode stops here; switch to Lab to batch past the foothold.';
    return base;
  }

  // The live frontier phase for display.
  function frontierPhase(facts) {
    try {
      var fi = P.frontierIndex(facts);
      var phases = P.PHASES || ['recon', 'enum', 'creds', 'access', 'escalate', 'loot'];
      return { index: fi, name: phases[Math.min(fi, phases.length - 1)] };
    } catch (e) { return { index: 0, name: 'recon' }; }
  }

  // Plan the next Cruise batch. opts = { mode:'exam'|'lab', doneIds:{id:true}, cap:number }.
  // Returns { mode, phase, frontier, batch:[{action,cmdIndex,tier}], deferred:[{action,waitsOn}],
  //           checkpoint:{action,reason,tier}|null, counts:{batch,deferred,ready} }.
  function plan(facts, pack, opts) {
    opts = opts || {};
    var mode = (opts.mode === 'lab') ? 'lab' : 'exam';
    var cap = opts.cap || 12;
    var doneIds = opts.doneIds || {};
    pack = pack || (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];

    var ranked = [];
    try { ranked = OBOL.pack.rankActions(facts, pack, { doneIds: doneIds }) || []; } catch (e) { ranked = []; }

    var fp = frontierPhase(facts);
    var batch = [], checkpoint = null, produced = {};

    for (var i = 0; i < ranked.length; i++) {
      var a = ranked[i];
      var tier = tierOf(a);
      if (!allowsTier(mode, tier)) {
        // The highest-ranked move the mode will not auto-batch: what you stop before.
        if (!checkpoint) checkpoint = { action: a, tier: tier, reason: reasonFor(a, tier, mode) };
        continue;   // keep scanning: a lower-ranked safe move can still batch
      }
      if (batch.length < cap) {
        batch.push({ action: a, cmdIndex: cmdIndexFor(a, facts), tier: tier });
        (a.produces || []).forEach(function (k) { produced[k] = 1; });
      }
    }

    var unlocks = unlocksFrom(facts, pack, produced, 6);

    return {
      mode: mode,
      phase: fp.name,
      frontier: fp.index,
      batch: batch,
      unlocks: unlocks,
      checkpoint: checkpoint,
      counts: { batch: batch.length, unlocks: unlocks.length, ready: ranked.length },
    };
  }

  // ── script builder ──────────────────────────────────────────────────────────────────────────────
  var VAR_ORDER = ['TARGET', 'DOMAIN', 'USER', 'PASS', 'NTHASH', 'LHOST', 'LPORT'];
  function shellEsc(s) { return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/`/g, '\\`').replace(/\$/g, '\\$'); }
  function oneLine(s) { return String(s == null ? '' : s).replace(/[\r\n]+/g, ' '); }
  function markerSafe(s) { return String(s == null ? '' : s).replace(/[^A-Za-z0-9 _.:\/-]/g, ''); }

  // Build the self-delimiting cruise batch script. ctx = { params, facts, profile, workspace, pack,
  // mode, phase, name }. Each command is fenced with an "===== OBOL STEP n: <id> =====" echo marker so
  // the pasted-back terminal blob self-segments per move. Reuses OBOL.playbook for $VAR variabilization.
  function buildScript(batch, ctx) {
    ctx = ctx || {};
    var pack = ctx.pack || (OBOL.packs && OBOL.packs.actions && OBOL.packs.actions()) || [];
    var items = OBOL.playbook.resolve((batch || []).map(function (b) {
      return { id: b.action.id, idx: b.cmdIndex || 0 };
    }), pack);
    var params = ctx.params || {};
    var opts = { params: params, profile: ctx.profile, workspace: ctx.workspace };
    var mode = (ctx.mode === 'lab') ? 'lab' : 'exam';

    var usedAll = {}, body = [], n = 0;
    items.forEach(function (it) {
      var r = OBOL.playbook.renderLine(it, ctx.facts, opts);
      if (!r.run) return;
      n++;
      Object.keys(r.used).forEach(function (V) { usedAll[V] = 1; });
      body.push('echo "===== OBOL STEP ' + n + ': ' + markerSafe(it.id) + ' ====="');
      var note = it.note ? ('   # ' + oneLine(it.note)) : '';
      body.push('# [' + n + '] ' + oneLine(it.title) + note);
      body.push(r.run);
      body.push('');
    });

    var valOf = {
      TARGET: params.target, DOMAIN: params.domain, USER: params.username || params.user,
      PASS: params.password, NTHASH: params.nthash, LHOST: params.lhost, LPORT: params.lport,
    };
    var varLines = VAR_ORDER.filter(function (V) { return usedAll[V]; }).map(function (V) {
      var val = valOf[V];
      return V + '="' + (val ? shellEsc(val) : ('<' + V.toLowerCase() + '>')) + '"';
    });
    var stamp = (function () { try { return new Date().toISOString().slice(0, 16).replace('T', ' '); } catch (e) { return ''; } })();
    var head = [
      '#!/usr/bin/env bash',
      '# obol cruise' + (ctx.phase ? (': ' + markerSafe(ctx.phase) + ' batch') : '') + ' [' + mode + ' mode]',
      '# Generated ' + stamp + ' UTC. obol generates command text only, it never runs anything.',
      '# Review every command, confirm the target is in scope, and run each step yourself. Then paste',
      '# the whole output back into obol (Cruise) and the next batch generates. Steps are fenced with',
      '# "===== OBOL STEP n =====" markers so the paste self-segments.',
      (mode === 'lab'
        ? '# LAB MODE: this batch may push past a foothold. It is NOT exam-legal, do not use it in the OSCP exam.'
        : '# EXAM MODE: safe enumeration only. You decide before anything that lands a shell or sprays creds.'),
      'set -o pipefail',
      '',
    ];
    if (varLines.length) head = head.concat(varLines, ['']);
    head = head.concat([
      'LOG="obol-cruise-$(date +%Y%m%d-%H%M%S).log"',
      'exec > >(tee -a "$LOG") 2>&1',
      '',
    ]);
    return head.join('\n') + body.join('\n') + '\n';
  }

  OBOL.cruise = {
    MODES: MODES,
    tierOf: tierOf,
    allowsTier: allowsTier,
    plan: plan,
    buildScript: buildScript,
    frontierPhase: frontierPhase,
  };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.cruise; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
