/*!
 * obol engine — study.js
 * Study mode's engine half (milestone 1: the AD vertical slice). Pure functions over the loaded
 * packs (OBOL.packs.actions()) + ARSENAL + the embedded sample-output map (OBOL.STUDY_FIXTURES).
 *
 * The conditional "study cell" is DERIVED, not hand-authored: every field maps to data the move
 * already carries — hypothesis / requires_* / produces / does_not_prove / commands[].note / refs —
 * plus two graph walks (what mints my prereqs, what my output opens). The one non-pack piece is the
 * sample output, which lives in OBOL.STUDY_FIXTURES because a static site can't read test fixtures.
 *
 * Command variants are ordered REMOTE-FIRST (remote → offline → on-target), derived from each tool's
 * ARSENAL os/class — never hand-ranked. Rationale: prefer the option that needs the least access to
 * the box; needing a foothold first is almost always the worse path.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // --- Milestone 1 scope: the AD vertical slice, as an ordered teaching path. -----------------
  var AD_LANE = [
    { id: 'ad-dc-identify',    phase: 'Recon' },
    { id: 'ad-anon-ldap-enum', phase: 'Recon' },
    { id: 'asrep-roast',       phase: 'Credentials' },
    { id: 'crack-asrep',       phase: 'Credentials' },
    { id: 'password-spray',    phase: 'Credentials' },
    { id: 'ad-acl-abuse',      phase: 'Escalate' },
    { id: 'dcsync',            phase: 'Domain' },
  ];

  function allMoves() { try { return (OBOL.packs && OBOL.packs.actions()) || []; } catch (e) { return []; } }
  function arsenal() { return OBOL.ARSENAL || {}; }
  function fixtures() { return OBOL.STUDY_FIXTURES || {}; }
  function byId(id) { var a = allMoves(); for (var i = 0; i < a.length; i++) if (a[i].id === id) return a[i]; return null; }
  function reqSet(m) { return [].concat(m.requires_all || [], m.requires_any || []); }
  function laneEntry(id) { for (var i = 0; i < AD_LANE.length; i++) if (AD_LANE[i].id === id) return AD_LANE[i]; return null; }

  // --- per-command locus: remote(0) < offline(1) < on-target(2) --------------------------------
  // Read the ARSENAL class/os of the command's tool, but also peek INSIDE the run string so an
  // `sh`/`bash` wrapper around an offline cracker or an on-host binary is classed by what it does.
  function cmdLocus(c) {
    var run = (c && c.run) || '', tool = (c && c.tool) || '';
    var A = arsenal(), e = A[tool] || A[tool.toLowerCase()] || {};
    if (/(^|[\s|&;])(hashcat|john)\b/.test(run) || /\s-m\s+\d+/.test(run)) return { rank: 1, tag: 'offline · your box', label: 'OFFLINE' };
    if (e.os === 'windows' || /^(stage-win|stage-lin|material)$/.test(e.class || '') || /(^|\s)\.[\\/]/.test(run) || /Rubeus|winPEAS|Sharp[A-Z]|mimikatz|GodPotato|PrintSpoofer/.test(run))
      return { rank: 2, tag: 'on-target · needs a foothold', label: 'ON-TARGET' };
    return { rank: 0, tag: 'remote · from your box', label: 'REMOTE' };
  }

  // --- derived graph edges ---------------------------------------------------------------------
  function producersOf(facts) {
    if (!facts || !facts.length) return [];
    return allMoves().filter(function (m) { return (m.produces || []).some(function (p) { return facts.indexOf(p) >= 0; }); });
  }
  function opensNext(m) {
    var prod = m.produces || []; if (!prod.length) return [];
    return allMoves().filter(function (x) { return x.id !== m.id && reqSet(x).some(function (r) { return prod.indexOf(r) >= 0; }); });
  }

  // Swap the canonical tool invocation for the learner's own, if a synced Loadout profile knows it
  // (same bounded rule as the coach's command-rewrite: only tools we have a profile entry for).
  function applyProfile(run, tool, profile) {
    if (!profile || !tool || !profile.tools) return run;
    var p = profile.tools[tool] || profile.tools[tool.toLowerCase()];
    if (!p || !p.invocation || p.present === false) return run;
    // replace the leading canonical token (tool name) with the box's actual invocation
    return run.replace(new RegExp('^\\s*' + tool.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), p.invocation);
  }

  // --- the derived conditional cell ------------------------------------------------------------
  function cellFor(moveId, opts) {
    opts = opts || {};
    var m = byId(moveId); if (!m) return null;
    var reqs = reqSet(m), profile = opts.profile || null;

    var ranked = (m.commands || []).map(function (c, i) { return { cmd: c, L: cmdLocus(c), i: i }; })
      .sort(function (a, b) { return a.L.rank - b.L.rank || a.i - b.i; });
    var seen = {}, commands = [];
    ranked.forEach(function (o) {
      var key = (o.cmd.tool || '?') + '|' + o.L.rank; if (seen[key]) return; seen[key] = 1;
      var run = (o.cmd.run || '').replace(/\{\{(\w+)\}\}/g, '<$1>');
      commands.push({ tool: o.cmd.tool || '', run: applyProfile(run, o.cmd.tool, profile), note: o.cmd.note || '', locus: o.L.label, tag: o.L.tag, rank: o.L.rank });
    });

    var fx = fixtures()[moveId] || null;
    var prod = m.produces || [];
    return {
      id: m.id, title: m.title, phase: (laneEntry(moveId) || {}).phase || '',
      scope: m.scope || '', locus: m.locus || '',
      whatItIs: m.hypothesis || '',
      prereqFacts: reqs,
      producedBy: producersOf(reqs).filter(function (x) { return x.id !== m.id; }).map(function (x) { return { id: x.id, title: x.title }; }),
      commands: commands,
      output: fx ? { text: fx.output || '', signal: fx.signal || '', teach: fx.teach || '' } : null,
      proves: prod,
      opens: opensNext(m).map(function (x) { return { id: x.id, title: x.title }; }),
      rulesOut: Array.isArray(m.does_not_prove) ? m.does_not_prove.join(' ; ') : (m.does_not_prove || ''),
      refs: m.refs || [],
    };
  }

  // --- the AD lane as graph nodes + derived edges ----------------------------------------------
  function lane() {
    return AD_LANE.map(function (e) {
      var m = byId(e.id);
      return { id: e.id, phase: e.phase, title: m ? m.title : e.id, proves: m ? (m.produces || []) : [], reqs: m ? reqSet(m) : [] };
    });
  }
  // an edge a→b when a's output satisfies one of b's prereqs (and b is later in the lane)
  function laneEdges() {
    var L = lane(), edges = [];
    L.forEach(function (a, ai) {
      L.forEach(function (b, bi) {
        if (bi <= ai) return;
        if (a.proves.some(function (p) { return b.reqs.indexOf(p) >= 0; })) edges.push({ from: a.id, to: b.id });
      });
    });
    return edges;
  }

  // --- "Your turn" practice: a retrieval-practice question for a lane node ----------------------
  // The learner is standing AT the node, having satisfied its prereqs. Those are the facts "in hand".
  // Each candidate move is scored for real: correct (this move), alt (prereqs already satisfiable),
  // or locked (needs a fact you don't hold yet) — with the missing fact named. Choice set + nuance
  // coaching come from STUDY_FIXTURES so the hard distinctions read well; verdicts stay derived.
  // What you actually hold when standing at a lane node: its own prerequisites PLUS everything the
  // earlier lane nodes produced (you had to run them to get here). Models the real state, so a
  // sibling like Password Spray reads as "also-valid" rather than falsely "locked".
  function factsInHandAt(moveId) {
    var have = {}, m = byId(moveId);
    if (m) reqSet(m).forEach(function (k) { have[k] = 1; });
    for (var i = 0; i < AD_LANE.length; i++) {
      if (AD_LANE[i].id === moveId) break;
      var pm = byId(AD_LANE[i].id);
      if (pm) (pm.produces || []).forEach(function (k) { have[k] = 1; });
    }
    return Object.keys(have);
  }

  function practiceFor(moveId) {
    var m = byId(moveId); if (!m) return null;
    var fx = fixtures()[moveId] || {};
    var have = factsInHandAt(moveId);
    var ids = (fx.choices && fx.choices.length) ? fx.choices.slice() : [moveId];
    if (ids.indexOf(moveId) < 0) ids.unshift(moveId);
    var coach = fx.coach || {};
    var choices = ids.map(function (id) {
      var d = byId(id); if (!d) return null;
      var verdict, missing = [];
      if (id === moveId) { verdict = 'correct'; }
      else {
        // honour requires_all vs requires_any: ALL of requires_all must be held, and (if present) at
        // least ONE of requires_any. "missing" names only what genuinely blocks the move.
        var all = d.requires_all || [], any = d.requires_any || [];
        var allMet = all.every(function (r) { return have.indexOf(r) >= 0; });
        var anyMet = any.length === 0 || any.some(function (r) { return have.indexOf(r) >= 0; });
        missing = all.filter(function (r) { return have.indexOf(r) < 0; });
        if (!anyMet) missing.push('one of: ' + any.join(' / '));
        verdict = (allMet && anyMet) ? 'alt' : 'locked';
      }
      return { id: id, title: d.title, verdict: verdict, missing: missing, coach: coach[id] || '' };
    }).filter(Boolean);
    return { moveId: moveId, situation: fx.situation || '', have: have, choices: choices };
  }

  OBOL.study = {
    AD_LANE: AD_LANE,
    cmdLocus: cmdLocus,
    cellFor: cellFor,
    lane: lane,
    laneEdges: laneEdges,
    practiceFor: practiceFor,
    producersOf: producersOf,
    opensNext: opensNext,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
