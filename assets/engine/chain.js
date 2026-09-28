/*!
 * obol engine — chain.js
 * Reconstructs the *compromise chain* for a host: the specific, ordered "this led to that, all the
 * way to the flags" path the operator actually walked — not the eligibility graph (what's possible)
 * or a flat list (what's proven). It walks backward from the flags (or the furthest access reached
 * mid-run) using the pack's prereq→produces structure, tying each step to the command/evidence that
 * produced it. Prereq-linked where provenance is clean; degrades to phase-ordered otherwise.
 *
 * The same chain feeds the target screen and the report's attack narrative. Pure + self-contained.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var FLAG_KINDS = { 'objective.local_flag': 'local', 'objective.root_flag': 'root', 'objective.flag': 'flag' };
  // When no flag is captured yet, end the chain at the furthest access reached, so it's useful live.
  var ACCESS_PRIORITY = ['access.system', 'access.admin', 'loot.ntds', 'foothold.windows', 'foothold.linux',
    'winrm.authenticated', 'access.shell', 'credential.available', 'credential.candidate'];
  // Recon anchors — seeded/observed roots that no action "produces" but the chain should start from.
  var ANCHORS = ['target.configured', 'host.up', 'ports.open'];

  function label(kind) { try { return OBOL.pack.friendly(kind); } catch (e) { return kind; } }
  function phaseOf(kind) { try { return OBOL.phases.phaseOfKind(kind); } catch (e) { return 'recon'; } }
  function phaseIdx(kind) { try { return OBOL.phases.phaseIndex(phaseOf(kind)); } catch (e) { return 0; } }

  // ── concrete "so what" per milestone (ported from obol-local storyline._milestone_detail) ──
  // Turns a generic kind ("A Usable Credential") into its real subject ("svc@corp.local"), so a
  // block says WHAT specifically, not just its category. Never returns a bare secret value unless
  // no subject exists (callers redact that fallback when secrets are hidden).
  function principal(v) {
    var user = v.user || v.username || v.account || '';
    var dom = v.domain || '';
    return (user && dom) ? (user + '@' + dom) : (user || v.host || '');
  }
  function detailOf(kind, v) {
    v = v || {};
    if (/^(credential\.|hash\.)/.test(kind)) return principal(v) || String(v.hash || '').slice(0, 24);
    if (kind === 'ad.acl_lead') {
      var tg = (v.targets || []).slice(0, 3).join(', ');
      return String(v.note || (tg ? ('writable: ' + tg) : '')).split(' · ')[0];
    }
    if (kind === 'ad.control_paths') return ((v.rights || []).join('/') + ' on ' + (v.target || 'the domain')).trim();
    if (kind === 'adcs.vulnerable') return v.template || '';
    if (kind === 'objective.flag_located') return v.path || v.name || 'located remotely — read on-host';
    if (/^objective\./.test(kind)) return v.flag || v.value || 'captured';
    if (kind === 'access.admin' || kind === 'access.system' || kind === 'foothold.windows' || kind === 'foothold.linux') {
      return v.user || v.via || v.method || '';
    }
    var keys = ['template', 'service', 'method', 'name', 'target'];
    for (var i = 0; i < keys.length; i++) { if (v[keys[i]]) return String(v[keys[i]]); }
    return '';
  }
  // Is a detail string a bare secret (a hash/password value, no subject)? Then redaction hides it.
  function isSecretDetail(kind, v, detail) {
    if (!/^(credential\.|hash\.)/.test(kind)) return false;
    return !principal(v || {}) && !!detail; // the [:24] hash fallback fired
  }

  // ── light technique framing (ported from storyline._technique; substring over produced kinds) ──
  var TECH_RULES = [
    [['objective.root_flag'], 'Root Flag Captured'],
    [['objective.local_flag', 'objective.flag'], 'Local Flag Captured'],
    [['ntds', 'dcsync', 'krbtgt'], 'DCSync / NTDS Dump'],
    [['kerberoast', 'tgs'], 'Kerberoasting'],
    [['asrep', 'asreproast'], 'AS-REP Roasting'],
    [['ad.control_paths', 'ad.acl_lead', 'rbcd', 'shadow'], 'AD Attack Path'],
    [['access.system', 'access.admin'], 'Privilege Escalation'],
    [['foothold', 'access.shell', 'winrm.authenticated', 'webshell'], 'Initial Access / Foothold'],
    [['credential', 'hash.ntlm'], 'Credential Access'],
    [['loot'], 'Looting'],
    [['service.', 'port:', 'scan.', 'http.', 'smb.'], 'Service Enumeration'],
  ];
  function techniqueOf(kind) {
    var j = String(kind).toLowerCase();
    for (var i = 0; i < TECH_RULES.length; i++) {
      var needles = TECH_RULES[i][0];
      for (var n = 0; n < needles.length; n++) { if (j.indexOf(needles[n]) !== -1) return TECH_RULES[i][1]; }
    }
    return '';
  }

  // Build the ordered compromise chain for one host.
  //   opts = { facts: FactSet, activities: [row], actions: [Action], host: '10.0.0.5' }
  // Returns [{ kind, label, phase, phaseIdx, command, tool, at, enabledBy:[kind], isFlag, flag }].
  function build(opts) {
    opts = opts || {};
    var host = opts.host;
    var facts = opts.facts;
    var actions = opts.actions || [];
    var acts = (opts.activities || []).filter(function (r) { return r && (r.target === host || r.scope === 'host:' + host); });
    if (!facts || !host) return [];

    var SUP = OBOL.facts.ProofState.SUPPORTED;
    var hostFacts = (facts.facts || []).filter(function (f) { return f.scope === 'host:' + host && f.state === SUP; });
    if (!hostFacts.length) return [];
    var proven = {}; hostFacts.forEach(function (f) { if (!proven[f.kind]) proven[f.kind] = f; });

    // Noise: enumeration / identity / posture detail that isn't a milestone in the walked path. The
    // attack-path ribbon and the report narrative both derive from these steps, so this is the single
    // definition of "what tells the compromise story" — kept in lockstep with the report's own noise
    // prefixes (port:/service./scan.) plus reachability, whose UNLOCKED OUTCOME (a bind, a user list,
    // a foothold) is the real milestone. Generic across labs: it filters by shape, not box specifics.
    function isNoise(kind) {
      if (/^port:\d+$/.test(kind)) return true;   // individual open ports (ports.open is the anchor)
      if (/^service\./.test(kind)) return true;    // per-service enumeration evidence (dns/ldap/msrpc/…)
      if (/^scan\./.test(kind)) return true;       // nmap scan-profile markers (quick/version/vuln/udp)
      if (/\.reachable$/.test(kind)) return true;  // reachability — the outcome it unlocks is the milestone
      return {
        'host.hostname': 1, 'host.domain': 1, 'host.fqdn': 1, 'host.os_family': 1, 'host.os_hint': 1,
        'smb.signing': 1, 'smb.smbv1': 1, 'smb.guest_session': 1, 'smb.null_session': 1,
        'ad.base_dn': 1, nav: 1, cmd: 1,
      }[kind] === 1;
    }

    // the action most likely responsible for a proven kind — its prereqs give the causal backlink.
    var producers = {}; // kind -> [Action]
    actions.forEach(function (a) { (a.produces || []).forEach(function (k) { (producers[k] = producers[k] || []).push(a); }); });
    function enablers(kind, priorSet) {
      var cands = producers[kind] || [];
      if (!cands.length) return [];
      var best = null, bestScore = -1;
      cands.forEach(function (a) {
        var all = a.requires_all || [], any = a.requires_any || [];
        var score = all.filter(function (k) { return proven[k]; }).length + (any.some(function (k) { return proven[k]; }) ? 1 : 0);
        if (all.every(function (k) { return proven[k]; })) score += 100;
        if (score > bestScore) { bestScore = score; best = a; }
      });
      if (!best) return [];
      var out = (best.requires_all || []).filter(function (k) { return proven[k] && priorSet[k]; });
      var anyOk = (best.requires_any || []).filter(function (k) { return proven[k] && priorSet[k]; });
      if (anyOk.length) out.push(anyOk[0]);
      return out.filter(function (k) { return k !== kind; });
    }

    // Primary signal = the run ledger: the ordered commands the operator ran and what each proved.
    // That IS the walked path. Emit a step the first time a milestone kind is produced, in time order.
    var steps = [], seen = {};
    function emit(kind, command, tool, at) {
      if (seen[kind] || !proven[kind] || isNoise(kind)) return;
      seen[kind] = true;
      var v = proven[kind].value || {};
      var detail = detailOf(kind, v);
      steps.push({ kind: kind, label: label(kind), detail: detail, technique: techniqueOf(kind),
        secret: isSecretDetail(kind, v, detail), phase: phaseOf(kind), phaseIdx: phaseIdx(kind),
        command: command || '', tool: tool || '', at: at || 0, enabledBy: [], isFlag: !!FLAG_KINDS[kind],
        flag: (FLAG_KINDS[kind] && v) ? { slot: FLAG_KINDS[kind], value: v.flag || '', path: v.path || '' } : null });
    }
    // recon anchors first (seeded/observed, usually no command)
    ANCHORS.forEach(function (k) { if (proven[k]) emit(k, '', '', (proven[k].created_at) || 0); });
    // then everything the ledger produced, in run order
    acts.slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); }).forEach(function (r) {
      (r.produced || []).forEach(function (k) { emit(k, r.command, r.tool, r.at || 0); });
    });
    // finally any proven milestone with no ledger row (seeded creds, a screenshot-only flag), by time
    hostFacts.slice().sort(function (a, b) { return (a.created_at || 0) - (b.created_at || 0); }).forEach(function (f) {
      if (FLAG_KINDS[f.kind] || ACCESS_PRIORITY.indexOf(f.kind) !== -1) {
        var src = f.source && !/^(manual|engagement|seeded|operator-|asserted)/i.test(f.source) ? f.source : '';
        emit(f.kind, src, (src.split(/\s+/)[0] || ''), f.created_at || 0);
      }
    });

    // order by time, then phase, then kind; then annotate each step's causal "enabled by" from
    // the prereqs of its producer that are already earlier in the chain.
    // Order by run time; on a tie, a captured flag is terminal (sorts last), then by phase — so the
    // winning-path trim below never cuts escalation steps that share a timestamp with the flag.
    function anchorRank(k) { var i = ANCHORS.indexOf(k); return i === -1 ? 99 : i; }
    steps.sort(function (a, b) {
      return ((a.at || 0) - (b.at || 0)) || (anchorRank(a.kind) - anchorRank(b.kind))
        || ((a.isFlag ? 1 : 0) - (b.isFlag ? 1 : 0)) || (a.phaseIdx - b.phaseIdx) || a.kind.localeCompare(b.kind);
    });
    var priorSet = {};
    steps.forEach(function (s) { s.enabledBy = enablers(s.kind, priorSet); priorSet[s.kind] = true; });

    // winning path only: if a flag was captured, trim anything after the last flag.
    var lastFlag = -1; steps.forEach(function (s, i) { if (s.isFlag) lastFlag = i; });
    if (lastFlag >= 0) steps = steps.slice(0, lastFlag + 1);
    return steps;
  }

  OBOL.chain = { build: build, FLAG_KINDS: FLAG_KINDS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
