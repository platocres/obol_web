/*!
 * obol engine - chain.js
 * Reconstructs the *compromise chain* for a host: the specific, ordered "this led to that, all the
 * way to the flags" path the operator actually walked - not the eligibility graph (what's possible)
 * or a flat list (what's proven). It walks backward from the flags (or the furthest access reached
 * mid-run) using the pack's prereq->produces structure, tying each step to the command/evidence that
 * produced it. Prereq-linked where provenance is clean; degrades to phase-ordered otherwise.
 *
 * The same chain feeds the target screen and the report's attack narrative. Pure + self-contained.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var FLAG_KINDS = { 'objective.local_flag': 'local', 'objective.root_flag': 'root', 'objective.flag': 'flag' };
  // When no flag is captured yet, end the chain at the furthest access reached, so it's useful live.
  var ACCESS_PRIORITY = ['access.system', 'access.admin', 'access.root', 'loot.ntds', 'foothold.windows', 'foothold.linux',
    'winrm.authenticated', 'access.shell', 'credential.available', 'credential.candidate'];
  // Recon anchors - seeded/observed roots that no action "produces" but the chain should start from.
  var ANCHORS = ['target.configured', 'host.up', 'ports.open'];

  var FALLBACK_LABELS = {
    'credential.validated': 'a validated credential',
    'credential.plaintext': 'a cracked plaintext credential',
    'credential.available': 'a usable credential',
    'credential.admin': 'an administrative credential',
    'ad.user_list': 'a domain user list',
    'ad.acl_lead': 'writable Active Directory objects',
    'ad.group_joined': 'privileged AD group membership',
    'ad.control_paths': 'an AD object control path',
    'ad.dcsync_granted': 'DCSync replication rights',
    'loot.ntds': 'dumped NTDS.dit domain secrets',
    'hash.krbtgt': 'the krbtgt Kerberos hash',
    'hash.ntlm': 'dumped NTLM password hashes',
    'hash.asrep': 'an AS-REP roastable hash',
    'hash.tgs': 'a Kerberoastable TGS hash',
  };

  function label(kind) {
    if (FALLBACK_LABELS[kind]) return FALLBACK_LABELS[kind];
    try {
      var l = OBOL.pack.friendly(kind);
      if (l && l !== kind) return l;
    } catch (e) {}
    return FALLBACK_LABELS[kind] || kind;
  }
  function phaseOf(kind) { try { return OBOL.phases.phaseOfKind(kind); } catch (e) { return 'recon'; } }
  function phaseIdx(kind) { try { return OBOL.phases.phaseIndex(phaseOf(kind)); } catch (e) { return 0; } }

  // ── concrete "so what" per milestone ──
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
    if (kind === 'ad.group_joined') {
      var grp = v.group || '';
      var mem = v.member || v.user || '';
      return (mem && grp) ? (mem + ' -> ' + grp) : (grp || mem);
    }
    if (kind === 'ad.control_paths') {
      var rightStr = v.right || (v.rights || []).join('/');
      var tgtStr = v.group || v.target || 'the domain';
      return (rightStr ? (rightStr + ' on ' + tgtStr) : tgtStr).trim();
    }
    if (kind === 'adcs.vulnerable') return v.template || '';
    if (kind === 'objective.flag_located') return v.path || v.name || 'located remotely, read on-host';
    if (/^objective\./.test(kind)) return v.flag || v.value || 'captured';
    if (kind === 'access.admin' || kind === 'access.system' || kind === 'access.root' || kind === 'foothold.windows' || kind === 'foothold.linux') {
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

  // ── light technique framing ──
  var TECH_RULES = [
    [['objective.root_flag'], 'Root Flag Captured'],
    [['objective.local_flag', 'objective.flag'], 'Local Flag Captured'],
    [['ntds', 'dcsync', 'krbtgt'], 'DCSync / NTDS Dump'],
    [['kerberoast', 'tgs'], 'Kerberoasting'],
    [['asrep', 'asreproast'], 'AS-REP Roasting'],
    [['ad.control_paths', 'ad.acl_lead', 'ad.group_joined', 'rbcd', 'shadow'], 'AD Attack Path'],
    [['access.system', 'access.admin', 'access.root'], 'Privilege Escalation'],
    [['foothold', 'access.shell', 'winrm.authenticated', 'webshell'], 'Initial Access / Foothold'],
    [['credential', 'hash.ntlm'], 'Credential Access'],
    [['loot'], 'Looting'],
    [['ad.user_list', 'service.', 'port:', 'scan.', 'http.', 'smb.'], 'Service Enumeration'],
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
    if (!facts || !host) return [];

    var SUP = OBOL.facts.ProofState.SUPPORTED;
    var allSupported = (facts.facts || []).filter(function (f) { return f.state === SUP; });
    var hostScopes = {};
    allSupported.forEach(function (f) {
      if (f.scope && f.scope.indexOf('host:') === 0 && f.scope !== 'host:target') hostScopes[f.scope] = 1;
    });
    var singleHost = Object.keys(hostScopes).length <= 1;
    var directFacts = allSupported.filter(function (f) { return f.scope === 'host:' + host; });
    if (!directFacts.length) return [];
    var isDc = singleHost || directFacts.some(function (f) {
      return f.kind === 'ad.dc_candidate' || f.kind === 'port:88' || f.kind === 'port:389';
    });

    var hostFacts = allSupported.filter(function (f) {
      if (f.scope === 'host:' + host) return true;
      if (isDc && f.scope && f.scope.indexOf('domain:') === 0) return true;
      if (singleHost && (f.scope === 'host:target' || f.scope === 'engagement' || !f.scope)) return true;
      return false;
    });

    var acts = (opts.activities || []).filter(function (r) {
      if (!r) return false;
      if (r.target === host || r.scope === 'host:' + host) return true;
      if (isDc && r.scope && r.scope.indexOf('domain:') === 0) return true;
      if (singleHost && (!r.target || r.scope === 'host:target')) return true;
      return false;
    });

    var proven = {}; hostFacts.forEach(function (f) { if (!proven[f.kind]) proven[f.kind] = f; });

    // Noise: enumeration / identity / posture detail that isn't a milestone in the walked path. The
    // attack-path ribbon and the report narrative both derive from these steps, so this is the single
    // definition of "what tells the compromise story" - kept in lockstep with the report's own noise
    // prefixes (port:/service./scan.) plus reachability, whose UNLOCKED OUTCOME (a bind, a user list,
    // a foothold) is the real milestone. Generic across labs: it filters by shape, not box specifics.
    var hasCapturedFlag = !!(proven['objective.local_flag'] || proven['objective.root_flag'] || proven['objective.flag']);
    var hasDomainCompromise = !!(proven['loot.ntds'] || proven['objective.root_flag']);

    function isNoise(kind) {
      if (/^port:\d+$/.test(kind)) return true;   // individual open ports (ports.open is the anchor)
      if (/^service\./.test(kind)) return true;    // per-service enumeration evidence (dns/ldap/msrpc/...)
      if (/^scan\./.test(kind)) return true;       // nmap scan-profile markers (quick/version/vuln/udp)
      if (/\.reachable$/.test(kind)) return true;  // reachability - the outcome it unlocks is the milestone
      if (/^blocker\./.test(kind)) return true;    // transient error/blocker markers are not attack milestones
      if (/^objective\.flag_located_/.test(kind)) return true; // internal slot-specific duplicate of objective.flag_located
      if (kind === 'objective.flag_located' && hasCapturedFlag) return true; // superseded once the flag value is captured
      if (kind === 'credential.available' && proven['credential.plaintext']) return true; // redundant with cracked/recovered plaintext cred
      if (kind === 'ad.acl_lead' && (proven['ad.control_paths'] || proven['ad.group_joined'])) return true;
      if (kind === 'ad.control_paths' && proven['ad.group_joined']) return true;
      if (hasDomainCompromise && {
        'hash.sntp': 1, 'ad.coerced_auth': 1, 'smb.readable_share': 1, 'smb.writable_share': 1,
        'host.notable_program': 1, 'loot.keepass_dump': 1, 'ad.delegation': 1, 'ad.rbcd': 1,
        'ad.laps_lead': 1, 'privesc.stored_credentials': 1, 'privesc.windows_privilege': 1,
      }[kind] === 1) return true;
      return {
        'host.hostname': 1, 'host.domain': 1, 'host.fqdn': 1, 'host.os_family': 1, 'host.os_hint': 1,
        'host.kernel': 1, 'smb.signing': 1, 'smb.smbv1': 1, 'smb.guest_session': 1, 'smb.null_session': 1,
        'ad.base_dn': 1, 'ad.domain_known': 1, 'ad.domain_sid': 1, 'ad.dc_candidate': 1,
        'ad.anonymous_bind': 1, 'ad.group_list': 1, 'ad.attack_paths': 1, 'ad.graph.collected': 1,
        'web.title': 1, 'config.review': 1, 'credential.validation': 1, 'credential.validated': 1,
        'credential.candidate': 1, 'ldap.authenticated': 1, 'smb.authenticated': 1, 'smb.shares': 1,
        'smb.content_accessible': 1, 'winrm.authenticated': 1, 'loot.files': 1,
        'privesc.leads': 1, 'privesc.privileged_group': 1,
        'proof.captured': 1, 'access.desktop': 1,
        nav: 1, cmd: 1,
      }[kind] === 1;
    }

    var MILESTONE_PRIORITY = [
      'loot.ntds', 'access.system', 'access.root', 'access.admin', 'credential.admin',
      'hash.krbtgt', 'ad.dcsync_granted', 'ad.domain_control', 'ad.group_joined', 'ad.control_paths', 'ad.acl_lead',
      'foothold.windows', 'foothold.linux', 'foothold.webshell', 'access.shell',
      'credential.plaintext', 'credential.available',
      'hash.asrep', 'hash.tgs', 'hash.ntlm', 'ad.user_list', 'ports.open',
    ];
    function milestoneRank(k) {
      var idx = MILESTONE_PRIORITY.indexOf(k);
      return idx >= 0 ? idx : (100 + phaseIdx(k));
    }

    // the action most likely responsible for a proven kind - its prereqs give the causal backlink.
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

    function cleanStepCommand(r) {
      if (!r) return { cmd: '', tool: '' };
      var cmd = String(r.command || '').trim();
      var tool = String(r.tool || '').replace(/;+$/, '');
      if (r.action_id && cmd.indexOf(r.action_id + ' ') === 0) {
        cmd = cmd.slice(r.action_id.length).trim();
      } else if (/^[a-z0-9]+(?:-[a-z0-9]+)+\s+(?:nmap|nxc|netexec|smbclient|rpcclient|enum4linux|ldapsearch|impacket|GetNPUsers|GetUserSPNs|secretsdump|bloodyAD|bloodhound-python|certipy|john|hashcat|evil-winrm|ffuf|gobuster|curl|ssh|for|if|whoami)\b/i.test(cmd)) {
        cmd = cmd.replace(/^[a-z0-9]+(?:-[a-z0-9]+)+\s+/i, '').trim();
      }
      var trailIp = cmd.match(/\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$/);
      if (trailIp && /\bTARGET\b/.test(cmd)) {
        cmd = cmd.slice(0, cmd.length - trailIp[0].length).replace(/\bTARGET\b/g, trailIp[1]).trim();
      }
      if (!cmd && r.stdout) {
        var lines = String(r.stdout).split(/\r?\n/);
        for (var i = 0; i < lines.length; i++) {
          var pm = lines[i].match(/^(?:└─[$#]|(?:\*Evil-WinRM\*\s+)?PS\s+[A-Za-z]:[^\r\n>]*>|[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[^$#\r\n]*[$#])\s+(.+?)\s*$/);
          if (pm && pm[1] && !/^cd\s+.*&&\s*bash\s+.*obol-stage/i.test(pm[1])) {
            cmd = pm[1].trim();
            break;
          }
        }
        if (!cmd && /===FLAG:/i.test(r.stdout)) {
          cmd = 'evil-winrm (on-host proof capture)';
          tool = 'evil-winrm';
        }
      }
      if ((!tool || /^[a-z0-9]+(?:-[a-z0-9]+)+$/i.test(tool)) && cmd) {
        tool = (cmd.split(/\s+/)[0] || tool).replace(/;+$/, '');
      }
      return { cmd: cmd, tool: tool };
    }

    // Primary signal = the run ledger: the ordered commands the operator ran and what each proved.
    // That IS the walked path. Emit at most one primary milestone per activity (plus any flag facts).
    var steps = [], seen = {}, stepByKind = {};
    function emit(kind, command, tool, at, rOut) {
      if (seen[kind] || !proven[kind] || isNoise(kind)) return false;
      seen[kind] = true;
      var v = proven[kind].value || {};
      var detail = detailOf(kind, v);
      var stObj = { kind: kind, label: label(kind), detail: detail, technique: techniqueOf(kind),
        secret: isSecretDetail(kind, v, detail), phase: phaseOf(kind), phaseIdx: phaseIdx(kind),
        command: command || '', tool: tool || '', at: at || 0, enabledBy: [], isFlag: !!FLAG_KINDS[kind],
        flag: (FLAG_KINDS[kind] && v) ? { slot: FLAG_KINDS[kind], value: v.flag || '', path: v.path || '' } : null,
        _hadError: /Unable to connect to the remote server|Exception calling "DownloadString"/i.test(rOut || '') };
      steps.push(stObj);
      stepByKind[kind] = stObj;
      return true;
    }
    // recon anchors first (seeded/observed, usually no command)
    ANCHORS.forEach(function (k) { if (proven[k]) emit(k, '', '', (proven[k].created_at) || 0, ''); });
    // then everything the ledger produced, in run order (at most 1 non-flag milestone per command row + any flags)
    acts.slice().sort(function (a, b) { return (a.at || 0) - (b.at || 0); }).forEach(function (r) {
      var ct = cleanStepCommand(r);
      var rOut = String(r.stdout || '');
      var rHadError = /Unable to connect to the remote server|Exception calling "DownloadString"/i.test(rOut);
      (r.produced || []).forEach(function (k) {
        if (stepByKind[k] && stepByKind[k]._hadError && !rHadError && ct.cmd) {
          stepByKind[k].command = ct.cmd;
          stepByKind[k].tool = ct.tool;
          stepByKind[k]._hadError = false;
        }
      });
      var prod = (r.produced || []).filter(function (k) { return !seen[k] && proven[k] && !isNoise(k); });
      var flags = prod.filter(function (k) { return !!FLAG_KINDS[k]; });
      var nonFlags = prod.filter(function (k) { return !FLAG_KINDS[k]; }).sort(function (a, b) { return milestoneRank(a) - milestoneRank(b); });
      if (nonFlags.length) {
        var primary = nonFlags[0];
        emit(primary, ct.cmd, ct.tool, r.at || 0, rOut);
        // Mark co-produced secondary facts from the same single command (e.g. dcsync co-minting hash.ntlm/hash.krbtgt/credential.admin)
        // as seen so a later re-run does not re-emit them out of order.
        if (primary === 'loot.ntds') {
          nonFlags.slice(1).forEach(function (k) { seen[k] = true; });
        }
      }
      flags.sort(function (a, b) { return (a === 'objective.root_flag' ? 1 : 0) - (b === 'objective.root_flag' ? 1 : 0); });
      flags.forEach(function (k) { emit(k, ct.cmd, ct.tool, r.at || 0, rOut); });
    });
    // finally any proven milestone with no ledger row (seeded creds, a screenshot-only flag), by time
    hostFacts.slice().sort(function (a, b) { return (a.created_at || 0) - (b.created_at || 0); }).forEach(function (f) {
      if (FLAG_KINDS[f.kind] || ACCESS_PRIORITY.indexOf(f.kind) !== -1) {
        var src = f.source && !/^(manual|engagement|seeded|operator-|asserted)/i.test(f.source) && !/\.log$/i.test(f.source) ? f.source : '';
        emit(f.kind, src, (src.split(/\s+/)[0] || ''), f.created_at || 0);
      }
    });

    // order by time, then phase, then kind; then annotate each step's causal "enabled by" from
    // the prereqs of its producer that are already earlier in the chain.
    // Order by run time; root/proof flag is always terminal (sorts last), and on a timestamp tie any flag sorts after non-flags.
    function anchorRank(k) { var i = ANCHORS.indexOf(k); return i === -1 ? 99 : i; }
    function flagOrder(k) { return k === 'objective.root_flag' ? 2 : (FLAG_KINDS[k] ? 1 : 0); }
    steps.sort(function (a, b) {
      var aRoot = a.kind === 'objective.root_flag' ? 1 : 0;
      var bRoot = b.kind === 'objective.root_flag' ? 1 : 0;
      if (aRoot !== bRoot) return aRoot - bRoot;
      if (a.isFlag && b.isFlag) return flagOrder(a.kind) - flagOrder(b.kind);
      return ((a.at || 0) - (b.at || 0)) || (anchorRank(a.kind) - anchorRank(b.kind))
        || (flagOrder(a.kind) - flagOrder(b.kind)) || (a.phaseIdx - b.phaseIdx) || a.kind.localeCompare(b.kind);
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
