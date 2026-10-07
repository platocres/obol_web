/*!
 * obol engine, stuck.js, the pure logic behind the Stuck? tab.
 *
 * Stuck? lets a user ASSERT facts about their target by clicking human-phrased binary buttons (rather
 * than pasting tool output), then shows the same ranked move cards the coach shows in Next Steps. This
 * module is the engine half: it is pure (a function of the facts and the pack you hand it) and writes
 * nothing to OBOL.store, so the Stuck? tab can run in a throwaway sandbox FactSet with zero side effects.
 *
 * Boundaries honoured:
 *   - One store, one filler: ranking goes through OBOL.pack.rankActions, the SAME ranker as Next Steps.
 *     We never fork the move graph or re-weight anything here.
 *   - Advisory: these facts are what the USER told us, not parser-proven. The UI frames every suggestion
 *     as "based on what you told me." Deterministic and explainable, same as the coach.
 *   - REFUTED is inert in the ranker (it reads SUPPORTED only), so "I tried it, didn't work" is modelled
 *     as a per-move exclusion (opts.triedIds -> ranker doneIds), never as a negative fact.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var S = OBOL.stuck = OBOL.stuck || {};

  var PHASE_ORDER = ['recon', 'enum', 'creds', 'access', 'escalate', 'loot'];
  function phaseIndex(p) { var i = PHASE_ORDER.indexOf(p); return i < 0 ? 99 : i; }
  function phaseOfKind(k) { return (OBOL.phases && OBOL.phases.phaseOfKind) ? OBOL.phases.phaseOfKind(k) : 'enum'; }

  // ── sandbox state ────────────────────────────────────────────────────────────────────────────
  // A standalone FactSet that is never connected to the active engagement. The UI may optionally seed
  // it from OBOL.store.factSet(), but by default it starts empty and stays local.
  S.sandbox = function () { return new OBOL.facts.FactSet([]); };

  // Assert a presence fact. Returns true if it was new/changed (FactSet.add dedups on kind+scope+value).
  S.assert = function (fs, kind, opts) {
    opts = opts || {};
    return fs.add(OBOL.facts.makeFact({
      kind: kind,
      scope: opts.scope || '',
      value: opts.value || {},
      state: opts.state || OBOL.facts.ProofState.SUPPORTED,
      source: 'stuck',
      created_at: opts.created_at || Math.floor(Date.now() / 1000),
    }));
  };

  // Un-assert: drop every SUPPORTED fact of this kind (optionally scoped) from the sandbox. Used when a
  // user toggles a binary attribute back off. (We remove rather than mark REFUTED: the ranker ignores
  // REFUTED, so removal is the only thing that actually un-gates the dependent moves.)
  S.retract = function (fs, kind, scope) {
    var hadScope = (scope !== undefined && scope !== null);
    fs.facts = (fs.facts || []).filter(function (f) {
      if (f.kind !== kind) return true;
      if (hadScope && f.scope !== scope) return true;
      return false;
    });
    return fs;
  };

  // ── catalog (human-phrased binary attributes; the words, not the logic) ─────────────────────────
  S.entry = function (kind) { return (OBOL.STUCK_CATALOG || {})[kind] || null; };
  // A kind is user-assertable only if it is in the curated catalog. The UI passes S.isAskable as the
  // reveal's askable predicate, so the picker never surfaces a raw internal kind with no human phrasing.
  S.isAskable = function (kind) { return !!S.entry(kind); };

  // ── labels (catalog first, then the existing human-readable sources) ────────────────────────────
  S.labelFor = function (kind) {
    var e = S.entry(kind);
    if (e && e.label) return e.label;
    var pk = OBOL.pack;
    if (pk && pk.friendly) { var fl = pk.friendly(kind); if (fl) return fl; }
    return kind;
  };
  S.detailFor = function (kind) {
    var e = S.entry(kind);
    if (e && e.help) return e.help;
    var wb = OBOL.workbench;
    if (wb && wb.explainKind) { var ex = wb.explainKind(kind); if (ex && ex.proves) return ex.proves; }
    return '';
  };
  S.groupFor = function (kind) { var e = S.entry(kind); return (e && e.group) || ''; };

  // ── the kind universe (what facts even exist) ──────────────────────────────────────────────────
  // Every fact kind the pack references (requires/produces) plus every kind the parsers can emit. Used
  // to guard triage seeds and, later, to bound the authored catalog.
  S.kindUniverse = function (pack) {
    var u = {};
    (pack || []).forEach(function (a) {
      (a.requires_all || []).forEach(function (k) { u[k] = true; });
      (a.requires_any || []).forEach(function (k) { u[k] = true; });
      (a.produces || []).forEach(function (k) { u[k] = true; });
    });
    var sigs = OBOL.PARSER_SIGNATURES;
    if (sigs) Object.keys(sigs).forEach(function (name) { (sigs[name].emits || []).forEach(function (k) { u[k] = true; }); });
    return u;
  };

  // ── reveal from the graph ──────────────────────────────────────────────────────────────────────
  // "What should I tell obol next?" = the facts the near-frontier moves REQUIRE or PRODUCE. For each
  // non-settled, non-obsolete move: an eligible move's produces are mild candidates (asserting them
  // advances you); an ineligible move's unmet requires are candidates weighted higher the closer the
  // move is to eligible. Kinds already asserted are excluded. This keeps the question set in lockstep
  // with the move graph and self-prunes to only the facts that would change your suggestions.
  S.suggestFacts = function (facts, pack, opts) {
    opts = opts || {};
    var askable = opts.askable;
    var have = facts.kinds();
    // Bias toward the frontier: a fact many phases ahead of where you are is not what an un-sticking
    // student needs first, even if lots of far-off moves require it. frontierIndex is "furthest reached
    // + 1", so a candidate at or behind the frontier is fully relevant and later phases decay.
    var frontier = (OBOL.phases && OBOL.phases.frontierIndex) ? OBOL.phases.frontierIndex(facts) : 1;
    function phaseFactor(p) { var d = phaseIndex(p) - frontier; if (d <= 0) return 1; if (d === 1) return 0.55; if (d === 2) return 0.3; return 0.12; }
    var score = {};
    function bump(kind, w, near) {
      if (!kind || have[kind]) return;
      if (askable && !askable(kind)) return;
      var s = score[kind] = (score[kind] || { kind: kind, unlocks: 0, near: 0 });
      s.unlocks += w;
      if (near) s.near += 1;
    }
    (pack || []).forEach(function (a) {
      if (a.settled(facts) || a.obsolete(facts)) return;
      if (a.eligible(facts)) {
        (a.produces || []).forEach(function (k) { bump(k, 0.5, false); });
        return;
      }
      var unmetAll = (a.requires_all || []).filter(function (k) { return !have[k]; });
      var anyList = a.requires_any || [];
      var anyMet = !anyList.length || anyList.some(function (k) { return have[k]; });
      var gap = unmetAll.length + (anyMet ? 0 : 1);
      var w = gap <= 1 ? 3 : (gap === 2 ? 1 : 0.3);
      unmetAll.forEach(function (k) { bump(k, w, gap <= 1); });
      if (!anyMet) anyList.forEach(function (k) { bump(k, w * 0.7, false); });
    });
    var out = Object.keys(score).map(function (k) {
      var s = score[k], p = phaseOfKind(k);
      return { kind: k, unlocks: s.unlocks * phaseFactor(p), rawUnlocks: s.unlocks, near: s.near, label: S.labelFor(k), detail: S.detailFor(k), phase: p };
    });
    out.sort(function (a, b) { return (b.unlocks - a.unlocks) || (phaseIndex(a.phase) - phaseIndex(b.phase)) || String(a.label).localeCompare(String(b.label)); });
    if (opts.limit) out = out.slice(0, opts.limit);
    return out;
  };

  // The same candidates, grouped by phase in phase order, for a sectioned picker.
  S.suggestByPhase = function (facts, pack, opts) {
    var list = S.suggestFacts(facts, pack, opts);
    var groups = {};
    list.forEach(function (c) { (groups[c.phase] = groups[c.phase] || []).push(c); });
    return PHASE_ORDER.filter(function (p) { return groups[p]; }).map(function (p) { return { phase: p, facts: groups[p] }; });
  };

  // ── ranked moves (sandbox + "I tried this move" exclusion) ─────────────────────────────────────
  // Same ranker as Next Steps. triedIds removes the moves the user already tried that failed, so the
  // next option floats up (REFUTED facts cannot do this; doneIds is the supported mechanism).
  S.rankedMoves = function (facts, pack, opts) {
    opts = opts || {};
    var doneIds = {};
    (opts.triedIds || []).forEach(function (id) { doneIds[id] = true; });
    return OBOL.pack.rankActions(facts, pack, { doneIds: doneIds, focusPrefixes: opts.focusPrefixes });
  };

  // Moves that are OS-ok but not yet eligible, with the plain-language reason they are blocked. Useful
  // for a "what would unlock more" hint under the picker.
  S.lockedMoves = function (facts, pack) {
    return (OBOL.pack && OBOL.pack.lockedActions) ? OBOL.pack.lockedActions(facts, pack) : [];
  };

  // ── triage: the single opening question ────────────────────────────────────────────────────────
  // Each option seeds a minimal fact set that sets the phase/frontier, so the first batch of questions
  // and moves is relevant. Seeds are applied only for kinds that actually exist in the pack universe,
  // so a seed kind that is not modelled is a safe no-op rather than a dead fact.
  S.TRIAGE = [
    { id: 'nothing',    label: 'Nothing Yet',                 note: 'You just got the target. We will start you at recon.',           seed: [] },
    { id: 'ports',      label: 'I Have Open Ports',           note: 'A port sweep came back. We will help you scan services and orient.', seed: ['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick'] },
    { id: 'services',   label: 'I Know The Services',         note: 'You ran a version scan. We will help you enumerate what is exposed.', seed: ['target.configured', 'host.up', 'ports.open', 'scan.nmap.quick', 'scan.nmap.version'] },
    { id: 'foothold',   label: 'I Have A Shell On The Box',   note: 'You are on the box as a normal user. We will help you escalate.',   seed: ['target.configured', 'host.up', 'ports.open', 'scan.nmap.version', 'access.shell'] },
    { id: 'credential', label: 'I Have A Working Credential', note: 'You hold a credential that logs in. We will help you use it.',      seed: ['target.configured', 'host.up', 'credential.available', 'credential.validated'] },
    { id: 'localadmin', label: 'I Have Local Admin Or Root',  note: 'You are admin or root on a box. We will help you loot and move on.', seed: ['target.configured', 'host.up', 'access.shell', 'access.admin'] },
  ];

  S.triageSeed = function (fs, id, pack, scope) {
    var opt = S.TRIAGE.filter(function (t) { return t.id === id; })[0];
    if (!opt) return fs;
    var universe = S.kindUniverse(pack);
    opt.seed.forEach(function (k) { if (universe[k]) S.assert(fs, k, { scope: scope || '' }); });
    return fs;
  };

  OBOL.stuck = S;
})(typeof globalThis !== 'undefined' ? globalThis : this);
