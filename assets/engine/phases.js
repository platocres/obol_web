/*!
 * obol engine — phases.js
 * The engagement phase/flow model — one projection, shared by the planner and the graph.
 * Phases order an engagement recon -> enum -> creds -> access -> escalate -> loot.
 * The frontier (furthest reached + 1) separates "how valuable is this fact" (priority)
 * from "is it time for it yet" (phase distance), so recon/low-risk enum sort ahead of a
 * premature high-value branch without a low-priority recon step leapfrogging the real move.
 *
 * Faithful JS port of obol-local/obol/phases.py.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var ProofState = OBOL.facts.ProofState;

  var PHASES = ['recon', 'enum', 'creds', 'access', 'escalate', 'loot'];
  var PHASE_INDEX = {};
  PHASES.forEach(function (name, i) { PHASE_INDEX[name] = i; });

  // An UNMAPPED fact kind defaults to 'enum', deliberately early, so an un-ruled recon
  // signal cannot silently shove the frontier to loot and flatten the move ranking.
  var DEFAULT_PHASE = 'enum';

  // Prefix/exact rules mapping a fact kind to a phase. Ordered longest-first at use.
  var PHASE_RULES = [
    ['target.', 'recon'], ['host.', 'recon'], ['ports.open', 'recon'],
    ['port:', 'recon'], ['scan.', 'recon'],
    ['ldap.reachable', 'recon'], ['smb.reachable', 'recon'],
    ['kerberos.reachable', 'recon'], ['winrm.reachable', 'recon'],
    ['http.reachable', 'recon'], ['service.', 'recon'],
    ['dns.reachable', 'recon'], ['dns.zone', 'enum'], ['dns.email', 'enum'],
    ['dns.takeover', 'access'],
    ['ad.dc_candidate', 'enum'], ['ad.domain_known', 'enum'], ['ad.base_dn', 'enum'],
    ['ad.anonymous_bind', 'enum'], ['ad.user_list', 'enum'], ['ad.protected_user', 'enum'],
    ['smb.null_session', 'enum'], ['smb.guest_session', 'enum'], ['smb.shares', 'enum'],
    ['enum.deep', 'enum'],
    ['web.content_map', 'enum'], ['web.vhost', 'enum'], ['web.source', 'enum'],
    ['web.users', 'enum'], ['web.parameterized', 'enum'],
    ['hash.', 'creds'], ['kerberos.tickets', 'creds'], ['credential.', 'creds'],
    ['ldap.authenticated', 'access'], ['smb.authenticated', 'access'],
    ['winrm.authenticated', 'access'], ['web.authenticated', 'access'],
    ['access.', 'access'], ['foothold.', 'access'], ['phish.', 'access'],
    ['ad.graph.collected', 'escalate'], ['ad.attack_paths', 'escalate'],
    ['ad.control_paths', 'escalate'], ['ad.trusts', 'escalate'],
    ['ad.computer_added', 'escalate'], ['adcs.', 'escalate'],
    ['ad.zerologon', 'escalate'], ['ad.coerced_auth', 'escalate'],
    ['ad.gpo_control', 'escalate'], ['ad.sid_history', 'escalate'],
    ['privesc.', 'escalate'],
    ['defense.control', 'escalate'],
    ['relay.success', 'escalate'], ['lateral.movement', 'escalate'],
    ['vuln.', 'escalate'], ['exploit.candidate', 'escalate'],
    // scanner detection is ENUMERATION output, not post-foothold escalation — a longer,
    // more-specific prefix wins over the generic vuln./finding. above.
    ['vuln.candidates', 'enum'], ['finding.scanner', 'enum'],
    ['web.lfi_confirmed', 'escalate'], ['web.sqli_confirmed', 'escalate'],
    ['web.cmdi_confirmed', 'escalate'], ['web.ssrf_confirmed', 'escalate'],
    ['web.upload_confirmed', 'escalate'], ['web.nosqli_confirmed', 'escalate'],
    ['web.jwt_secret', 'creds'], ['web.authz_bypass', 'escalate'],
    ['loot.', 'loot'], ['persistence.', 'loot'], ['db.creds', 'loot'],
    ['cloud.', 'loot'], ['config.', 'loot'],
  ];
  var SORTED_RULES = PHASE_RULES.slice().sort(function (a, b) { return b[0].length - a[0].length; });

  function phaseIndex(phase) {
    return (phase in PHASE_INDEX) ? PHASE_INDEX[phase] : PHASE_INDEX[DEFAULT_PHASE];
  }

  function phaseOfKind(kind) {
    for (var i = 0; i < SORTED_RULES.length; i++) {
      var prefix = SORTED_RULES[i][0];
      if (kind === prefix || kind.indexOf(prefix) === 0) return SORTED_RULES[i][1];
    }
    return DEFAULT_PHASE;
  }

  function maxByPhase(kinds) {
    var best = null, bestIdx = -1;
    for (var i = 0; i < kinds.length; i++) {
      var idx = phaseIndex(phaseOfKind(kinds[i]));
      if (idx > bestIdx) { bestIdx = idx; best = phaseOfKind(kinds[i]); }
    }
    return best;
  }

  // An action's phase: an explicit `phase` the pack set on it, else the latest phase of
  // anything it produces (fallback: the latest phase of its prerequisites).
  function phaseOfAction(action) {
    var explicit = action.phase || '';
    if (explicit in PHASE_INDEX) return explicit;
    var kinds = (action.produces || []).slice();
    if (!kinds.length) {
      kinds = (action.requires_all || []).slice().concat(action.requires_any || []);
    }
    if (!kinds.length) return 'recon';
    return maxByPhase(kinds);
  }

  function targetPhase(factset) {
    var kinds = [];
    for (var i = 0; i < factset.facts.length; i++) {
      if (factset.facts[i].state === ProofState.SUPPORTED) kinds.push(factset.facts[i].kind);
    }
    if (!kinds.length) return 'recon';
    return maxByPhase(kinds);
  }

  // The phase index the target is actively pushing into: furthest reached + 1 (capped).
  function frontierIndex(factset) {
    var reached = phaseIndex(targetPhase(factset));
    return Math.min(reached + 1, PHASES.length - 1);
  }

  // How many phases past the target's frontier an action reaches (0 == on-flow).
  function prematurity(action, factset) {
    return Math.max(0, phaseIndex(phaseOfAction(action)) - frontierIndex(factset));
  }

  OBOL.phases = {
    PHASES: PHASES,
    PHASE_INDEX: PHASE_INDEX,
    DEFAULT_PHASE: DEFAULT_PHASE,
    phaseIndex: phaseIndex,
    phaseOfKind: phaseOfKind,
    phaseOfAction: phaseOfAction,
    targetPhase: targetPhase,
    frontierIndex: frontierIndex,
    prematurity: prematurity,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
