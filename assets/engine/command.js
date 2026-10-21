/*!
 * obol engine - command.js
 * Command templating: build the {{token}} context from proven facts + engagement params,
 * fill a command template, and render an action's command variants. Faithful JS port of the
 * relevant parts of  (command_context / fill_template / fill_command).
 *
 * Browser adaptation: there is no Workspace. Callers pass a FactSet (OBOL.facts.FactSet) and
 * an engagement `params` object (target/domain/username/password/lhost/…). Facts-derived
 * tokens fill from proven facts; `extra` pins specific values and wins over both.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // These tokens deliberately contain authored shell syntax, rather than one argument.
  var EXPRESSION_TOKENS = { command: true, kerberos_command: true, sudo_command: true,
    abuse_groups_quoted: true, shares_readable_quoted: true, flag_inames_linux: true, flag_names_windows: true };
  var PATH_TOKENS = /(?:dir|file|path|list|script|binary|archive|keyfile|export)$/i;
  var LIT_OPEN = '\x00OBOL_LBRACE\x00';
  var LIT_CLOSE = '\x00OBOL_RBRACE\x00';

  // POSIX shell single-quote quoting (equivalent of Python shlex.quote for our needs).
  function shellQuote(s) {
    s = String(s);
    if (s === '') return "''";
    if (/^[A-Za-z0-9_@%+=:,.\/-]+$/.test(s)) return s;
    return "'" + s.replace(/'/g, "'\\''") + "'";
  }

  function firstVal(facts, kind) {
    if (!facts) return null;
    if (typeof facts.values === 'function') {
      var v = facts.values(kind);
      return v && v.length ? v[0] : null;
    }
    var list = facts.facts || (Array.isArray(facts) ? facts : []);
    for (var i = 0; i < list.length; i++) {
      if (list[i] && (list[i].kind === kind || list[i].k === kind)) {
        return (list[i].value !== undefined) ? list[i].value : list[i].v;
      }
    }
    return null;
  }

  function isMultiOrKnownHost(list, targetScope) {
    if (!targetScope || !list || !list.length) return false;
    var hostScopes = {};
    var count = 0;
    for (var i = 0; i < list.length; i++) {
      var f = list[i];
      if (!f || !f.scope) continue;
      if (f.scope === targetScope) return true;
      if (f.scope.indexOf('host:') === 0 && f.scope !== 'host:target') {
        if (!hostScopes[f.scope]) {
          hostScopes[f.scope] = true;
          count++;
          if (count > 1) return true;
        }
      }
    }
    return false;
  }

  function scopedValues(facts, kind, targetIp) {
    if (!facts) return [];
    var list = (facts && facts.facts) || (Array.isArray(facts) ? facts : []);
    if (targetIp && list.length) {
      var targetScope = 'host:' + targetIp;
      var hostMatches = [];
      var genericMatches = [];
      for (var i = 0; i < list.length; i++) {
        var f = list[i];
        if (!f) continue;
        var k = f.kind || f.k || '';
        if (k !== kind) continue;
        if (f.state && OBOL.facts && f.state !== OBOL.facts.ProofState.SUPPORTED && f.state !== 'supported') continue;
        var val = f.value !== undefined ? f.value : f.v;
        if (f.scope === targetScope) {
          hostMatches.push(val);
        } else if (!f.scope || f.scope === 'global' || f.scope === 'host:target' || f.scope.indexOf('host:') !== 0) {
          genericMatches.push(val);
        }
      }
      if (hostMatches.length) return hostMatches;
      if (isMultiOrKnownHost(list, targetScope)) return genericMatches;
    }
    if (typeof facts.values === 'function') {
      return facts.values(kind);
    }
    var out = [];
    for (var j = 0; j < list.length; j++) {
      var fj = list[j];
      if (!fj) continue;
      var kj = fj.kind || fj.k || '';
      if (kj !== kind) continue;
      if (fj.state && OBOL.facts && fj.state !== OBOL.facts.ProofState.SUPPORTED && fj.state !== 'supported') continue;
      out.push(fj.value !== undefined ? fj.value : fj.v);
    }
    return out;
  }

  // Open ports as sorted numbers, from port:NNN facts (recon output).
  function openPorts(facts, targetIp) {
    var ports = [];
    if (!facts) return ports;
    var list = (facts && facts.facts) || (Array.isArray(facts) ? facts : []);
    var targetScope = targetIp ? ('host:' + targetIp) : '';
    var strictScope = isMultiOrKnownHost(list, targetScope);
    if (!strictScope && targetScope) {
      for (var s = 0; s < list.length; s++) {
        var fs = list[s];
        if (!fs) continue;
        var ks = fs.kind || fs.k || '';
        if (fs.scope === targetScope && ks.indexOf('port:') === 0) {
          strictScope = true;
          break;
        }
      }
    }
    for (var i = 0; i < list.length; i++) {
      var f = list[i];
      if (!f) continue;
      if (f.state && OBOL.facts && f.state !== OBOL.facts.ProofState.SUPPORTED && f.state !== 'supported') continue;
      if (strictScope && f.scope && f.scope.indexOf('host:') === 0 && f.scope !== 'host:target' && f.scope !== targetScope) continue;
      var k = f.kind || f.k || '';
      if (k.indexOf('port:') === 0) {
        var n = parseInt(k.split(':')[1], 10);
        if (!isNaN(n)) ports.push(n);
      }
    }
    // also honor a ports.open summary fact carrying a list
    var summaries = scopedValues(facts, 'ports.open', targetIp);
    var summary = summaries && summaries[0] ? summaries[0] : (strictScope ? null : firstVal(facts, 'ports.open'));
    if (summary && Array.isArray(summary.ports)) {
      summary.ports.forEach(function (p) { var n = parseInt(p, 10); if (!isNaN(n)) ports.push(n); });
    }
    ports = ports.filter(function (v, i, a) { return a.indexOf(v) === i; });
    ports.sort(function (a, b) { return a - b; });
    return ports;
  }

  // Map obol engagement params to the base token context (ws.inputs analog).
  function paramsToInputs(params) {
    params = params || {};
    var ctx = {};
    Object.keys(params).forEach(function (k) {
      var v = params[k];
      if (v === null || v === undefined || v === '') return;
      ctx[k] = v;
    });
    // common aliases obol uses
    if (params.username && !ctx.user) ctx.user = params.username;
    if (params.target && !ctx.target) ctx.target = params.target;
    if (params.rhost && !ctx.target) ctx.target = params.rhost;
    return ctx;
  }

  // Build the {{token}} context from facts + params (+ extra which wins).
  function buildContext(facts, opts) {
    opts = opts || {};
    var resolved = opts.context && opts.context.params ? opts.context : null;
    if (!resolved && OBOL.context) {
      var activeEng = opts.engagement || (OBOL.store && OBOL.store.active && OBOL.store.active()) || null;
      resolved = OBOL.context.resolve({ engagement: activeEng, facts: facts, params: opts.params || (activeEng && activeEng.params) || {},
        target: opts.target, command: opts.command || '', service: opts.service, locus: opts.locus, actionId: opts.action && opts.action.id });
    }
    if (resolved) { facts = resolved.facts; opts = Object.assign({}, opts, { params: resolved.params, target: resolved.target }); }
    if (Array.isArray(facts) && OBOL.facts && OBOL.facts.FactSet) {
      facts = new OBOL.facts.FactSet(facts.map(function (x) {
        return (OBOL.facts && OBOL.facts.factFromJson) ? OBOL.facts.factFromJson(x) : x;
      }));
    }
    function fvals(kind) {
      if (!facts) return [];
      if (typeof facts.values === 'function') return facts.values(kind);
      return scopedValues(facts, kind, '');
    }
    var params = opts.params || {};
    var extra = opts.extra || {};
    var tgt = opts.target || params.target || params.rhost || '';

    var ctx = Object.assign({ target: tgt || '<target>' }, paramsToInputs(params));
    if (tgt) ctx.target = tgt;

    var ports = openPorts(facts, tgt);
    if (ports.length) ctx.nmap_ports = ports.join(',');

    var dom = firstVal(facts, 'ad.domain_known');
    if (!ctx.domain && dom && dom.name) {
      ctx.domain = dom.name;
      ctx.basedn = dom.name.split('.').map(function (p) { return 'DC=' + p; }).join(',');
      ctx.dc = dom.name;
    }
    if (!ctx.domain) {
      var hdoms = fvals('host.domain');
      for (var hd = 0; hd < hdoms.length; hd++) {
        var dname = hdoms[hd].domain || hdoms[hd].name || '';
        if (dname) { ctx.domain = dname; break; }
      }
    }
    if (!ctx.domain) {
      var fqdns = fvals('host.fqdn');
      for (var fq = 0; fq < fqdns.length; fq++) {
        var fqStr = String(fqdns[fq].fqdn || fqdns[fq].name || '');
        var fqParts = fqStr.split('.');
        if (fqParts.length >= 3) {
          ctx.domain = fqParts.slice(1).join('.');
          break;
        }
      }
    }
    if (ctx.domain && !ctx.dc) ctx.dc = ctx.domain;
    if (!ctx.basedn) {
      var bases = fvals('ad.base_dn');
      for (var i = 0; i < bases.length; i++) {
        var bd = bases[i].base_dn || bases[i].basedn || '';
        if (bd) { ctx.basedn = bd; break; }
      }
    }
    // domain from params if facts didn't provide it, derive basedn
    if (!ctx.domain && params.domain) ctx.domain = params.domain;
    if (ctx.domain && !ctx.basedn) {
      ctx.basedn = ctx.domain.split('.').map(function (p) { return 'DC=' + p; }).join(',');
    }

    var arProf = _arsenalProfile();
    // lhost: params-pinned, else a listener fact, else synced Loadout VPN IP, else leave for operator
    if (!ctx.lhost) {
      var lo = firstVal(facts, 'listener.open');
      if (lo && lo.lhost) ctx.lhost = lo.lhost;
      else if (arProf && arProf.lhost) ctx.lhost = arProf.lhost;
    }
    // lport: params-pinned (set in the sidebar), else a listener fact, else the 4444 convention so a
    // reverse-shell / listener command is complete out of the box. The operator can change it anywhere.
    if (!ctx.lport) {
      var lop = firstVal(facts, 'listener.open');
      ctx.lport = (lop && lop.lport) || params.lport || '4444';
    }
    // iface: the operator's attacker interface (responder -I, mitm6 -i, ...). Pinned from the engagement's
    // configured VM interface or synced Loadout VPN interface, defaulting to tun0.
    if (!ctx.iface) ctx.iface = params.lhost_iface || (arProf && arProf.lhost_iface) || 'tun0';
    if (!ctx.arsenal_www) ctx.arsenal_www = (arProf && arProf.wwwdir) || '~/.obol/arsenal/www';
    if (!ctx.tooldir) ctx.tooldir = params.toolsDir || (arProf && arProf.tooldir) || '~/tools';

    // credentials: prefer credential.available then credential.plaintext. IDENTITY-COHERENT fill - never
    // pair one credential's username with another's secret. `-u svc-alfresco -H <administrator-hash>` just
    // fails auth; the user and the secret must come from the SAME credential. When params already pin a
    // user, fill that same user's secret; otherwise adopt the first credential wholesale.
    if (!resolved) {
    var creds = fvals('credential.available');
    if (!creds.length) creds = fvals('credential.plaintext');
    function _lc(x) { return String(x == null ? '' : x).toLowerCase(); }
    function _credRank(c) {
      if (!c) return -1;
      var s = 0;
      if (c.admin) s += 4;
      if (/^administrator$/i.test(c.user || '')) s += 2;
      if (c.validated) s += 2;
      if (c.password || c.secret || c.nthash || c.hash) s += 1;
      return s;
    }
    var rankedCreds = creds.map(function (c, i) { return { c: c, i: i, r: _credRank(c) }; })
      .sort(function (a, b) { return (b.r - a.r) || (b.i - a.i); })
      .map(function (x) { return x.c; });
    if (ctx.user) {
      for (var c = 0; c < rankedCreds.length; c++) {
        if (_lc(rankedCreds[c].user) !== _lc(ctx.user)) continue;
        if (!ctx.password && !ctx.nthash) {
          if (rankedCreds[c].password) ctx.password = rankedCreds[c].password;
          var nhm = rankedCreds[c].nthash || rankedCreds[c].hash;
          if (nhm) ctx.nthash = nhm;
        }
        if (!ctx.domain && rankedCreds[c].domain) ctx.domain = rankedCreds[c].domain;
        break;
      }
    } else if (rankedCreds.length) {
      var c0 = rankedCreds[0];
      if (c0.user) ctx.user = c0.user;
      if (c0.password && !ctx.password) ctx.password = c0.password;
      var nh0 = c0.nthash || c0.hash;
      if (nh0 && !ctx.nthash) ctx.nthash = nh0;
      if (c0.domain && !ctx.domain) ctx.domain = c0.domain;
    }
    }
    if (!ctx.user && !resolved) {
      var fhList = fvals('foothold.linux').concat(fvals('foothold.windows'));
      for (var fi = 0; fi < fhList.length; fi++) {
        var fu = fhList[fi] && (fhList[fi].identity || fhList[fi].user);
        if (fu) {
          ctx.user = String(fu).replace(/^.*\\/, '').trim();
          if (ctx.user) break;
        }
      }
    }
    if (!ctx.user && opts && opts.action && opts.action.id === 'asrep-roast') {
      var cands = fvals('credential.candidate');
      for (var ci = 0; ci < cands.length; ci++) {
        if (cands[ci] && cands[ci].kind === 'asrep_roastable' && cands[ci].user) {
          ctx.user = String(cands[ci].user).trim();
          break;
        }
      }
      if (!ctx.user) {
        var uls = fvals('ad.user_list');
        for (var ui = 0; ui < uls.length; ui++) {
          if (uls[ui] && Array.isArray(uls[ui].asrep_users) && uls[ui].asrep_users.length) {
            ctx.user = String(uls[ui].asrep_users[0]).trim();
            break;
          }
        }
      }
    }

    // krbtgt key for golden-ticket forging - the DEDICATED krbtgt NT hash from a DCSync/NTDS dump, NEVER
    // the first credential's hash (forging with the wrong key silently produces an unusable ticket).
    if (!ctx.krbtgt_hash) {
      var kt = firstVal(facts, 'hash.krbtgt');
      if (kt && kt.nthash) ctx.krbtgt_hash = kt.nthash;
    }

    // Domain-admin hash from a DCSync/NTDS dump, resolved INDEPENDENTLY of the active credential (like
    // krbtgt_hash). So the moment you dump NTDS, the "read the flag / own the box with the DA hash"
    // commands fill with the built-in Administrator (RID 500) hash, with NO manual credential swap.
    if (!ctx.dahash) {
      var avs = fvals('credential.available');
      for (var ai = 0; ai < avs.length; ai++) {
        var v = avs[ai];
        if (v && v.method === 'dcsync' && (v.nthash || v.hash)) {
          ctx.dahash = v.nthash || v.hash;
          ctx.dauser = v.user || 'Administrator';
          if (!ctx.domain && v.domain) ctx.domain = v.domain;
          break;
        }
      }
      if (!ctx.dahash) {
        for (var ai2 = 0; ai2 < avs.length; ai2++) {
          var v2 = avs[ai2];
          if (v2 && (v2.nthash || v2.hash) && String(v2.user || '').toLowerCase() === 'administrator') {
            ctx.dahash = v2.nthash || v2.hash;
            ctx.dauser = v2.user || 'Administrator';
            if (!ctx.domain && v2.domain) ctx.domain = v2.domain;
            break;
          }
        }
      }
    }

    // ADCS ca/template/pfx
    var adcs = firstVal(facts, 'adcs.vulnerable');
    if (adcs) {
      var caVal = adcs.ca || (adcs.cas && adcs.cas[0]) || '';
      if (caVal && !ctx.ca_name) ctx.ca_name = caVal;
      if (adcs.templates && adcs.templates.length && !ctx.template) ctx.template = adcs.templates[0];
    }
    var certs = fvals('credential.certificate');
    for (var ci = 0; ci < certs.length; ci++) {
      var pfxFile = certs[ci].pfx || (certs[ci].files && certs[ci].files[0]);
      if (pfxFile) { ctx.pfx = pfxFile; break; }
    }

    // DC identity
    if (!ctx.dc_netbios || !ctx.dc_account) {
      var dcName = '';
      var dcCands = fvals('ad.dc_candidate');
      for (var d = 0; d < dcCands.length; d++) {
        dcName = dcCands[d].name || dcCands[d].hostname || dcCands[d].netbios || '';
        if (dcName) break;
      }
      if (!dcName) {
        var hns = scopedValues(facts, 'host.hostname', tgt);
        for (var h = 0; h < hns.length; h++) { dcName = hns[h].name || hns[h].hostname || ''; if (dcName) break; }
      }
      if (dcName) {
        var short = dcName.split('.')[0];
        if (!ctx.dc_netbios) ctx.dc_netbios = short;
        if (!ctx.dc_account) ctx.dc_account = short + '$';
      }
    }
    if (!ctx.hostname) {
      var hnList = fvals('host.hostname');
      for (var hi = 0; hi < hnList.length; hi++) {
        var hnVal = hnList[hi] && (hnList[hi].name || hnList[hi].hostname);
        if (hnVal) { ctx.hostname = hnVal; break; }
      }
      if (!ctx.hostname) {
        var dcList = fvals('ad.dc_candidate');
        for (var di = 0; di < dcList.length; di++) {
          var dcVal = dcList[di] && (dcList[di].name || dcList[di].hostname || dcList[di].netbios);
          if (dcVal) { ctx.hostname = dcVal; break; }
        }
      }
    }
    if (!ctx.dc_fqdn) {
      var fqList = fvals('host.fqdn');
      for (var fqi = 0; fqi < fqList.length; fqi++) {
        if (fqList[fqi] && fqList[fqi].fqdn) { ctx.dc_fqdn = fqList[fqi].fqdn; break; }
      }
      if (!ctx.dc_fqdn && ctx.hostname && ctx.domain) {
        ctx.dc_fqdn = (ctx.hostname.indexOf('.') >= 0) ? ctx.hostname : (ctx.hostname + '.' + ctx.domain);
      }
    }

    // domain SID
    var sids = fvals('ad.domain_sid');
    for (var s = 0; s < sids.length; s++) { if (sids[s].sid) { ctx.domain_sid = sids[s].sid; break; } }

    // BloodHound cash-in tokens from attack path hops (advancing past already-joined groups)
    var paths = fvals('ad.attack_paths');
    var joinedSet = {};
    fvals('ad.group_joined').forEach(function (jv) {
      if (jv && jv.group) joinedSet[String(jv.group).split('@')[0].trim().toLowerCase()] = 1;
    });
    for (var p = 0; p < paths.length; p++) {
      var pHops = Array.isArray(paths[p].path) ? paths[p].path : [];
      var fa = paths[p].first_action || {};
      var faTgt = String(fa.target || '').split('@')[0].trim();
      var chosenGroup = '';
      var chosenSam = '';
      for (var hi = 0; hi < pHops.length; hi++) {
        var hop = pHops[hi];
        if (!hop || /^memberof$/i.test(String(hop.edge || ''))) continue;
        var hShort = String(hop.to || '').split('@')[0].trim();
        if (!hShort) continue;
        var isGrpHop = /group/i.test(String(hop.to_kind || '')) || /^add(?:member|self)$/i.test(String(hop.edge || ''));
        if (!isGrpHop && !hop.to_kind && !/^getchanges/i.test(String(hop.edge || ''))) {
          var domPart = String(hop.to || '').indexOf('@') >= 0 ? String(hop.to).split('@')[1].trim() : '';
          if ((!domPart || hShort.toLowerCase() !== domPart.toLowerCase()) && hShort.indexOf('.') < 0) isGrpHop = true;
        }
        if (isGrpHop) {
          if (!chosenGroup && !joinedSet[hShort.toLowerCase()]) chosenGroup = hShort;
          if (!chosenSam && !joinedSet[hShort.toLowerCase()]) chosenSam = hShort;
        } else if (!chosenSam) {
          chosenSam = hShort;
        }
      }
      if (!chosenGroup && faTgt && fa.kind !== 'domain' && (!ctx.domain || faTgt.toLowerCase() !== String(ctx.domain).toLowerCase())) {
        chosenGroup = faTgt;
      }
      if (!chosenSam && faTgt) chosenSam = faTgt;
      if (chosenGroup || chosenSam) {
        if (chosenGroup && !ctx.group) ctx.group = chosenGroup;
        if (chosenSam && !ctx.target_sam) ctx.target_sam = chosenSam;
        break;
      }
    }
    // ...and, when BloodHound wasn't run, from a bloodyAD `get writable` lead (ad.acl_lead). obol does NOT
    // guess which single group is the winner (that would hard-code one lab's path): it ranks the abusable
    // groups the lead actually shows and lets the operator try them until one unlocks with evidence.
    //   {{group}}                - the top-ranked candidate to try first (a starting point, not the answer)
    //   {{abuse_groups_quoted}}  - every reasonable candidate, quoted & space-joined, for a ONE-SHOT sweep
    //                              (`for g in {{abuse_groups_quoted}}; do add groupMember "$g" ...`)
    // Ranking is try-order only; whichever add actually sticks (and then unlocks DCSync) is the real path.
    if (ctx.group === undefined || ctx.target_sam === undefined || ctx.abuse_groups_quoted === undefined) {
      // The standard high-value AD groups, in the order worth trying: direct-DA first, then the groups
      // whose membership yields domain control (WriteDACL->DCSync, SeBackup, service install, DLL-on-DC).
      var ABUSE_PRIORITY = ['domain admins', 'enterprise admins', 'administrators',
        'exchange windows permissions', 'account operators', 'organization management',
        'backup operators', 'server operators', 'dnsadmins', 'print operators',
        'group policy creator owners', 'key admins', 'enterprise key admins'];
      var leadTargets = [];
      fvals('ad.acl_lead').forEach(function (v) {
        (v.targets || []).forEach(function (tgt) { if (tgt && leadTargets.indexOf(tgt) < 0) leadTargets.push(tgt); });
      });
      // Candidates = the reasonable, known-abusable groups the lead shows, in priority order. When the
      // lead names none of them (or there is no lead yet), fall back to the usual suspects so the sweep
      // still tries every group worth trying rather than forming an empty loop.
      var lowerSet = {};
      leadTargets.forEach(function (t) { lowerSet[String(t).toLowerCase()] = t; });
      var candidates = [];
      ABUSE_PRIORITY.forEach(function (g) { if (lowerSet[g]) candidates.push(lowerSet[g]); });
      if (!candidates.length) candidates = ABUSE_PRIORITY.map(function (g) { return g.replace(/\b\w/g, function (c) { return c.toUpperCase(); }); });
      if (ctx.group === undefined && leadTargets.length) ctx.group = candidates[0] || leadTargets[0] || '';
      if (ctx.target_sam === undefined && leadTargets.length) ctx.target_sam = candidates[0] || leadTargets[0] || '';
      if (ctx.abuse_groups_quoted === undefined) ctx.abuse_groups_quoted = candidates.map(function (g) { return '"' + String(g).replace(/(["\\$`])/g, '\\$1') + '"'; }).join(' ');
    }

    // flag-hunt tokens from the engagement profile (which flag names the hunt searches)
    var fc = (OBOL.profile && OBOL.profile.resolveFlagConfig)
      ? OBOL.profile.resolveFlagConfig(opts.profile || {})
      : { names: ['local.txt', 'user.txt', 'proof.txt', 'root.txt'], slots: { 'local.txt': 'local', 'user.txt': 'local', 'proof.txt': 'root', 'root.txt': 'root' } };
    if (!ctx.flag_inames_linux && OBOL.profile && OBOL.profile.linuxInameExpr) ctx.flag_inames_linux = OBOL.profile.linuxInameExpr(fc.names);
    if (!ctx.flag_names_windows && OBOL.profile && OBOL.profile.windowsNameList) ctx.flag_names_windows = OBOL.profile.windowsNameList(fc.names);

      // Per-slot flag file PATHS for the on-host capture step. Prefer a path obol actually LOCATED (a
      // nxc/smb spider, or a prior read) so step 3/4 fill with the real file, the user's Desktop, the
      // platform's own name, instead of a guessed placeholder; else a profile-aware default.
      var _flagName = function (slot) {
        var ns = fc.names || [];
        for (var i = 0; i < ns.length; i++) if ((fc.slots || {})[ns[i]] === slot) return ns[i];
        return slot === 'root' ? 'root.txt' : 'user.txt';
      };
      var _locatedPath = function (slot) {
        var kinds = [
          'objective.flag_located',
          slot === 'root' ? 'objective.root_flag' : 'objective.local_flag',
          slot === 'root' ? 'objective.flag_located_root' : 'objective.flag_located_local'
        ];
        for (var k = 0; k < kinds.length; k++) {
          var vs = scopedValues(facts, kinds[k], tgt);
          var candidates = [];
          for (var i = 0; i < vs.length; i++) {
            var v = vs[i];
            if (!v) continue;
            var p = '';
            if (typeof v === 'string') {
              p = v;
            } else if (typeof v === 'object') {
              if (v.slot && v.slot !== slot && v.slot !== (slot === 'local' ? 'user' : 'root')) continue;
              p = String(v.path || v.file || v.value || '');
            }
            if (!p) continue;
            if (/\.lnk$/i.test(p) || /[\\/](?:Recent|AppData|Temp)[\\/]/i.test(p)) continue;
            candidates.push(p);
          }
          if (candidates.length) {
            for (var c = 0; c < candidates.length; c++) {
              if (/[\\/]Desktop[\\/]/i.test(candidates[c])) return candidates[c];
            }
            return candidates[0];
          }
        }
        return '';
      };
      var _isLinux = facts && facts.has && (facts.has('foothold.linux') || facts.has('access.shell') || facts.has('os.linux'))
        && !facts.has('foothold.windows') && !facts.has('os.windows');
      var _priv = function (u) {
        var s = String(u || '').toLowerCase();
        return !s || /^(?:administrator|admin|root|system|nt authority\\system|guest|defaultaccount|krbtgt|www-data|apache|nginx|nobody|daemon|http|postgres|mysql|redis|tomcat|iis apppool|network service|local service)$/.test(s) || /^svc[-_]/i.test(s) || /\$$/.test(s);
      };
      // The ROOT/proof flag path is an earned gate token (only filled once located).
      // The USER/local flag path prefers a located path; otherwise, when the active user is an unprivileged
      // user (not admin/root/SYSTEM), it defaults to that user's own Desktop/home directory.
      if (ctx.flag_path_local === undefined) {
        var _locL = _locatedPath('local');
        if (_locL) {
          ctx.flag_path_local = _locL;
        } else if (ctx.user && !_priv(ctx.user) && !(facts && facts.has && (facts.has('access.admin') || facts.has('access.system') || facts.has('access.root')))) {
          ctx.flag_path_local = _isLinux
            ? ('/home/' + ctx.user + '/' + _flagName('local'))
            : ('C:\\Users\\' + ctx.user + '\\Desktop\\' + _flagName('local'));
        }
      }
      if (ctx.flag_path_root === undefined) {
        var _locR = _locatedPath('root');
        if (_locR) {
          ctx.flag_path_root = _locR;
        }
      }

    // SMB share tokens: resolve the top-ranked readable share from discovered shares (smb.shares / smb.readable_share)
    // Priority order:
    //   1. Custom non-default shares (e.g. Replication, Backups, Shared, Public, Data)
    //   2. Domain policy shares (SYSVOL, NETLOGON)
    //   3. Administrative shares (C$)
    // Exclude transport noise: IPC$, PRINT$
    if (!ctx.share) {
      var allShares = [];
      fvals('smb.shares').forEach(function (v) {
        (v.shares || []).forEach(function (s) { if (s && s.name) allShares.push(s); });
      });
      fvals('smb.readable_share').forEach(function (s) {
        if (s && s.name && !allShares.some(function (x) { return x.name.toUpperCase() === s.name.toUpperCase(); })) {
          allShares.push(Object.assign({ readable: true }, s));
        }
      });
      var BOILERPLATE = { 'IPC$': 1, 'PRINT$': 1 };
      var readableList = allShares.filter(function (s) {
        var n = (s.name || '').toUpperCase();
        var isAdminShare = (n === 'ADMIN$' || n === 'C$');
        return (s.readable === true || (!s.permission && !isAdminShare) || (s.permission && s.permission.indexOf('READ') >= 0)) && !BOILERPLATE[n];
      });
      var customList = readableList.filter(function (s) {
        var n = (s.name || '').toUpperCase();
        return ['SYSVOL', 'NETLOGON', 'ADMIN$', 'C$'].indexOf(n) < 0;
      });
      var policyList = readableList.filter(function (s) {
        var n = (s.name || '').toUpperCase();
        return n === 'SYSVOL' || n === 'NETLOGON';
      });
      var adminList = readableList.filter(function (s) {
        var n = (s.name || '').toUpperCase();
        return n === 'C$';
      });

      var chosen = (customList[0] || policyList[0] || adminList[0] || readableList[0] || {});
      if (chosen.name) ctx.share = chosen.name;
      else if (params && params.share) ctx.share = params.share;

      var candidateNames = customList.concat(policyList).map(function (s) { return s.name; });
      if (candidateNames.length) {
        ctx.shares_readable_quoted = candidateNames.map(function (n) { return '"' + String(n).replace(/(["\\$`])/g, '\\$1') + '"'; }).join(' ');
      }
    }

    // cpassword from GPP hunting facts (credential.candidate with kind: 'gpp_cpassword')
    if (!ctx.cpassword) {
      var gppCandidates = fvals('credential.candidate');
      for (var gc = 0; gc < gppCandidates.length; gc++) {
        var gVal = gppCandidates[gc] || {};
        if (gVal.kind === 'gpp_cpassword' && gVal.values && gVal.values.length) {
          ctx.cpassword = gVal.values[0];
          break;
        }
      }
    }

    // workspace output-directory tokens ({{scandir}} etc.) - from opts.workspace when the caller
    // supplies it (OBOL.workspace.tokens(eng)), else relative fallbacks so commands still form.
    var wsd = opts.workspace || { root: '.', scandir: 'scans', lootdir: 'loot', exploitdir: 'exploit', wwwdir: 'www', proofdir: 'proof' };
    ['root', 'scandir', 'lootdir', 'exploitdir', 'wwwdir', 'proofdir'].forEach(function (k) {
      if (ctx[k] === undefined && wsd[k] !== undefined) ctx[k] = wsd[k];
    });

    // loot-materialized file tokens ({{userlist}}/{{hashfile}}/{{wordlist}}) - resolve to stable
    // paths under the workspace loot/ dir so the roast that writes {{hashfile}} and the crack that
    // reads it agree, and {{userlist}} points at the file obol can materialize from ad.user_list.
    // Only fills for an action the caller identified (opts.action); params still win over these.
    if (OBOL.loot && opts.action) {
      var lt = OBOL.loot.tokensFor(opts.action, facts, wsd, params);
      Object.keys(lt).forEach(function (k) {
        if (ctx[k] === undefined && lt[k] !== undefined && lt[k] !== '') ctx[k] = lt[k];
      });
    }

    // extra wins
    Object.keys(extra).forEach(function (k) {
      var v = extra[k];
      if (v !== null && v !== undefined && v !== '') ctx[k] = v;
    });
    if (ctx.basedn && !ctx.base_dn) ctx.base_dn = ctx.basedn;
    if (ctx.template && !ctx.cert_template) ctx.cert_template = ctx.template;
    if (ctx.group && !ctx.target_group) ctx.target_group = ctx.group;
    if (ctx.target_sam && !ctx.victim) ctx.victim = ctx.target_sam;
    if (ctx.lhost && !ctx.attacker_ip) ctx.attacker_ip = ctx.lhost;
    if (ctx.hashfile && !ctx.hashes_file) ctx.hashes_file = ctx.hashfile;
    if (ctx.sid && !ctx.oracle_sid) ctx.oracle_sid = ctx.sid;
    return ctx;
  }

  function quoteStateAt(str, idx, shell) {
    var q = '';
    for (var i = 0; i < idx; i++) {
      var ch = str.charAt(i);
      if ((shell === 'powershell' && ch === '`' && q !== "'") || (shell === 'bash' && ch === '\\' && q !== "'")) { i++; continue; }
      if (shell === 'powershell' && q === "'" && ch === "'" && str.charAt(i + 1) === "'") { i++; continue; }
      if (!q && (ch === '"' || (shell !== 'cmd' && ch === "'"))) q = ch;
      else if (q === ch) q = '';
    }
    return q;
  }

  function inferShell(run) {
    if (/^\s*(?:\$env:|(?:Get|Set|Add|Remove|New|Invoke|Import|Start|Stop|Enable|Disable)-[A-Za-z]|IEX\b)/i.test(run)) return 'powershell';
    if (/^\s*(?:cmd\s+\/c\b|schtasks\b|reg\s+(?:query|add)|icacls\b|net\s+(?:user|localgroup)|type\s+)/i.test(run)) return 'cmd';
    if (/^\s*(?:hostname|whoami|ipconfig)\b[^\r\n]*;\s*(?:ipconfig|type|Get-)/i.test(run)) return 'powershell';
    return 'bash';
  }

  function renderValue(value, key, shell, quote, opts) {
    var s = String(value);
    if (EXPRESSION_TOKENS[key] || (opts.expressionTokens && opts.expressionTokens.indexOf(key) >= 0)) return s;
    if (shell === 'powershell') {
      if (quote === "'") return s.replace(/'/g, "''");
      if (quote === '"') return s.replace(/`/g, '``').replace(/(["$])/g, '`$1');
      return /^[A-Za-z0-9_@%+=:,.\\\/-]+$/.test(s) ? s : "'" + s.replace(/'/g, "''") + "'";
    }
    if (shell === 'cmd') {
      // CMD expands %variables% and delayed !variables! even inside quotes. Refuse
      // unrepresentable literals rather than handing the operator an altered argument.
      if (/["%!\r\n\x00]/.test(s)) {
        if (opts.errors) opts.errors.push('Cannot safely render ' + key + ' for CMD. Use PowerShell or Bash.');
        return '{{' + key + '}}';
      }
      if (quote === '"') return s;
      return /^[A-Za-z0-9_@+=:,.\\\/-]+$/.test(s) ? s : '"' + s + '"';
    }
    if (quote === "'") return s.replace(/'/g, "'\\''");
    if (quote === '"') return s.replace(/(["\\$`])/g, '\\$1');
    if (PATH_TOKENS.test(key) && /^~\//.test(s)) {
      return /^[A-Za-z0-9_@%+=:,.\/-]+$/.test(s.slice(1)) ? s : '"$HOME"' + shellQuote(s.slice(1));
    }
    return shellQuote(s);
  }

  // A single pass ensures discovered values cannot introduce new template tokens.
  function fillTemplate(text, facts, opts) {
    if (!text) return '';
    opts = opts || {};
    var cmd = String(text).split('\\{\\{').join(LIT_OPEN).split('\\}\\}').join(LIT_CLOSE);
    var ctx = buildContext(facts, opts), shell = opts.shell || inferShell(cmd);
    cmd = cmd.replace(/\{\{([a-zA-Z0-9_]+)(?:\|((?:\{\{[a-zA-Z0-9_]+\}\}|[^{}])*))?\}\}/g, function (placeholder, key, defVal, offset) {
      var value = ctx[key];
      if (key === 'domain' && ctx.auth_realm && ctx.user) {
        var before = cmd.slice(0, offset), after = cmd.slice(offset + placeholder.length);
        var principalRealm = /\{\{(?:user|username)\}\}@['"]?$/.test(before) || /^(?:\/|\\+)\{\{(?:user|username)\}\}/.test(after);
        var authFlag = /(?:^|\s)(?:-d|--domain|-domain)\s+['"]?$/.test(before)
          && /\b(?:nxc|netexec|crackmapexec|smbmap|smbclient|rpcclient)\b/.test(cmd);
        if (principalRealm || authFlag) value = ctx.auth_realm;
      }
      if (value === undefined || value === null || value === '') {
        if (defVal === undefined) return placeholder;
        value = defVal.replace(/\{\{([a-zA-Z0-9_]+)\}\}/g, function (nested, name) {
          return ctx[name] !== undefined && ctx[name] !== null && ctx[name] !== '' ? String(ctx[name]) : nested;
        });
      }
      return renderValue(value, key, shell, quoteStateAt(cmd, offset, shell), opts);
    });
    return cmd.split(LIT_OPEN).join('{{').split(LIT_CLOSE).join('}}');
  }

  // -- Loadout command-rewrite ------------------------------------------------------
  // Once the operator has synced their box (Loadout), rewrite a filled command to THEIR box's reality:
  //   - tool invocation: impacket-psexec <-> psexec.py <-> python3 .../psexec.py; nxc <-> netexec <-> crackmapexec
  //   - wordlist paths: the real rockyou / SecLists location on this box
  // Conservative + reversible: only a recognized ARSENAL variant appearing as a STANDALONE token is
  // swapped, and only for the actual invocation the box reported; anything un-synced or unknown is left
  // exactly as authored (today's behavior). Reads the per-browser profile from localStorage (so it needs
  // none of the lazy arsenal.js); a profile may be passed explicitly (tests / callers that already have it).
  function _arsenalProfile() { try { return JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null'); } catch (e) { return null; } }
  function _reEsc(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function applyArsenal(filled, action, prof) {
    if (!filled) return filled;
    prof = prof || _arsenalProfile();
    if (!prof) return filled;
    var A = (root.OBOL && root.OBOL.ARSENAL) || {};
    var ptools = prof.tools || {};
    var rawTools = [];
    if (action) {
      if (action.tools && action.tools.length) rawTools = rawTools.concat(action.tools);
      if (action.tool) rawTools.push(action.tool);
      if (action.cmdTool) rawTools.push(action.cmdTool);
    }
    // Also inspect standalone command tokens in `filled` so multi-tool pipelines and per-variant tools rewrite cleanly.
    String(filled).split(/[\s|;&()`"']+/).forEach(function (tok) {
      if (!tok || tok.charAt(0) === '-') return;
      var base = tok.split('/').pop().toLowerCase();
      if (A[base]) rawTools.push(base);
      else if (base.slice(-3) === '.py' && A[base.slice(0, -3)]) rawTools.push(base.slice(0, -3));
    });
    var seenKey = {};
    rawTools.forEach(function (t) {
      if (!t) return;
      var tl = String(t).toLowerCase();
      var e = A[tl] || (tl.slice(-3) === '.py' ? A[tl.slice(0, -3)] : null);
      if (!e || seenKey[e.key]) return;
      seenKey[e.key] = 1;
      var rec = ptools[e.key];
      var inv = rec && rec.present && rec.invocation;
      if (!inv) return;
      // Guard older profiles where a cloned git repo recorded its bare lowercase key instead of a script invocation
      if (rec.via === 'cloned' && inv === e.key && e.canonical && e.canonical !== e.key) {
        inv = rec.path ? ('python3 ' + rec.path.replace(/\/+$/, '') + '/' + e.canonical) : e.canonical;
      }
      var variants = (e.variants && e.variants.length) ? e.variants.slice() : [e.canonical || e.key];
      if (e.canonical && variants.indexOf(e.canonical) < 0) variants.push(e.canonical);
      var pyVariants = variants.filter(function (x) { return x && x.slice(-3).toLowerCase() === '.py'; });
      var multiPyRepo = pyVariants.length > 1;
      variants.forEach(function (v) {
        if (!v) return;
        var vl = v.toLowerCase();
        var vInv = inv;
        if (rec.scripts && rec.scripts[vl]) {
          var sp = rec.scripts[vl];
          vInv = (sp.slice(-3).toLowerCase() === '.py' && sp.indexOf('python') !== 0) ? ('python3 ' + sp) : sp;
        } else if (multiPyRepo && vl.slice(-3) === '.py') {
          var invBase = inv.split('/').pop().toLowerCase();
          if (invBase !== vl && inv.indexOf('/') >= 0) {
            var dirPart = inv.slice(0, inv.lastIndexOf('/'));
            if (dirPart.indexOf('python') !== 0 && vl.slice(-3) === '.py') dirPart = 'python3 ' + dirPart;
            vInv = dirPart + '/' + v;
          } else if (rec.dir) {
            vInv = 'python3 ' + String(rec.dir).replace(/\/+$/, '') + '/' + v;
          }
        }
        var isPy = vl.slice(-3) === '.py' || vInv.indexOf('python') === 0;
        if (isPy) {
          var pyRe = new RegExp('(^|\\s)(?:python3?\\s+)?(?:(?:\\$HOME|~|\\/opt|\\/usr\\/local|\\/usr\\/share|\\/home\\/[^\\s"\';|&\\/]+)\\/[^\\s"\';|&]*\\/)?' + _reEsc(v) + '(?=\\s|$)', 'gi');
          filled = filled.replace(pyRe, '$1' + vInv);
        } else if (v !== vInv) {
          filled = filled.replace(new RegExp('(^|\\s)' + _reEsc(v) + '(?=\\s|$)', 'g'), '$1' + vInv);
        }
      });
    });
    var wl = prof.wordlists || {};
    if (wl.rockyou) {
      filled = filled.replace(/\/usr\/share\/wordlists\/rockyou\.txt(?:\.gz)?/g, wl.rockyou)
                     .replace(/(^|\s)rockyou\.txt(?=\s|$)/g, '$1' + wl.rockyou);
    }
    if (wl.seclists) {
      filled = filled.replace(/\/usr\/share\/(?:wordlists\/)?(?:seclists|SecLists)\b/g, wl.seclists);
    }
    return filled;
  }

  // Fill a command variant of an action (0-based). Returns {tool, run, note, filled, webNote}.
  // obol is the hands-on edition: where an action carries a web-suited command (`web` on a
  // variant, or `web_command` on the action) - one tuned for a human who must copy/paste or attach
  // the output by hand, not a terminal reading it off disk - that form is preferred here. A
  // `web_note` carries the matching hands-on guidance (e.g. "large output -> tee to a file and
  // attach it in Evidence"). Neither field exists in obol's mined data; both are additive.
  function fillCommand(action, facts, opts, index) {
    opts = opts || {};
    if (action && action.resolvedContext) {
      facts = action.resolvedContext.facts;
      opts = Object.assign({}, opts, {params:action.resolvedContext.params,target:action.resolvedContext.target});
    }
    index = index || 0;
    var commands = (action.commands && action.commands.length) ? action.commands : [{ run: action.command, tool: action.tool }];
    if (index < 0 || index >= commands.length) index = 0;
    var c = commands[index] || {};
    var run = c.web || c.run || action.web_command || action.command || '';
    var errors = [];
    var fillOpts = Object.assign({}, opts, { action: action, command: run, locus: opts.locus || (OBOL.pack && OBOL.pack.commandExecutionLocus ? OBOL.pack.commandExecutionLocus(c) : 'remote'), shell: c.shell || opts.shell || inferShell(run), errors: errors });
    var filled = fillTemplate(run, facts, fillOpts);
    var actForArsenal = (c.tool && action && c.tool !== action.tool) ? Object.assign({}, action, { cmdTool: c.tool }) : action;
    return {
      tool: c.tool || action.tool || '',
      note: c.note || '',
      webNote: c.web_note || action.web_note || '',
      win: !!c.win,   // a box-ending move - the coach flags it "PWN THIS TARGET"
      run: run,
      // thread the action so the loot glue can resolve {{userlist}}/{{hashfile}} for THIS move, then
      // rewrite to the operator's synced box (invocation + wordlist paths) - a no-op until they sync.
      filled: errors.length ? '' : applyArsenal(filled, actForArsenal, opts.arsenal),
      blocked: errors.length > 0, errors: errors,
    };
  }

  // All variants of an action, filled - for the coach to show "many commands".
  function fillAll(action, facts, opts) {
    var commands = (action.commands && action.commands.length) ? action.commands : [{ run: action.command, tool: action.tool }];
    return commands.map(function (c, i) { return fillCommand(action, facts, opts, i); });
  }

  // The distinctive ACTION tokens of a command - the verbs/subcommands that say WHAT it does, with the
  // tool name, flags, param values (target/domain/user/secret/…), paths, numbers and shell scaffolding
  // stripped out. Two commands with the same action tokens are "the same move" regardless of which host or
  // credential filled them, so this is how obol tells that a suggested command is one you already ran.
  // Long flags that only say WHERE/HOW to connect, not what the move does - dropped so `--host`/`--dc-ip`
  // don't drown out the real action, and so a run with `--detail` matches one without it.
  var _PLUMBING_FLAGS = { host: 1, 'dc-ip': 1, 'dc-host': 1, dns: 1, domain: 1, port: 1, timeout: 1, detail: 1,
    json: 1, threads: 1, jitter: 1, nameserver: 1, 'no-pass': 1, gc: 1, 'min-rate': 1 };
  // Bare words that are shell scaffolding or output plumbing, never an action.
  var _NOISE_WORDS = { 'for': 1, 'in': 1, 'do': 1, 'done': 1, 'then': 1, 'fi': 1, 'else': 1, 'echo': 1,
    'sudo': 1, 'while': 1, 'tee': 1, 'cat': 1 };
  // Short flags that DEFINE the action and must be kept - `-x`/`-X` (execute a command) is the whole
  // difference between `nxc smb …` (validate the credential) and `nxc smb … -x '<cmd>'` (run a command),
  // so dropping it made running the validator wrongly mark the exec command as already run.
  var _ACTION_SHORT_FLAGS = { x: 1 };
  function _actionSig(cmd, params) {
    // Process the WHOLE pipeline (do NOT stop at the first pipe): the transform after a `|` - awk / grep /
    // sort in a HANDOFF - is exactly what distinguishes `nxc … --users | tee` from `… | awk | grep | sort`,
    // so two commands that share a prefix but differ downstream must NOT collapse to the same signature.
    var toks = String(cmd || '').trim().split(/\s+/);
    var vals = {};
    ['target', 'domain', 'username', 'user', 'password', 'nthash', 'lhost', 'lport', 'rhost'].forEach(function (k) {
      var v = params && params[k]; if (v) vals[String(v).toLowerCase()] = 1;
    });
    var out = {};
    // Include the leading tool token too (i=0): the tool IS distinctive - `certipy find` and
    // `sccmhunter find` share the `find` subcommand but are NOT the same move, so dropping the tool made
    // one wrongly match the other. Shell keywords (`for`/`while`/`sudo`) fall out via the noise filter.
    for (var i = 0; i < toks.length; i++) {
      var raw = toks[i];
      if (/^(?:\||\|\||&&|;|>|>>|<)$/.test(raw)) continue;        // shell operators
      var t = raw.replace(/^["']+|["']+$/g, '');                  // strip surrounding quotes
      if (!t || t.indexOf('{{') >= 0) continue;                   // empty, or an unfilled template value slot

      if (t.charAt(0) === '-') {
        if (t.charAt(1) === '-' && t.length > 3) {                // long flag: keep action ones (--users), drop plumbing
          var lf = t.replace(/^--/, '').toLowerCase();
          if (!vals[lf] && !_PLUMBING_FLAGS[lf]) out[lf] = 1;
        } else {                                                  // short flag: drop plumbing (-u/-p/-d), keep action (-x)
          var sf = t.replace(/^-+/, '').toLowerCase();
          if (_ACTION_SHORT_FLAGS[sf]) out[sf] = 1;
        }
        continue;
      }
      var lt = t.toLowerCase();
      if (vals[lt] || _NOISE_WORDS[lt]) continue;                 // param value or shell/plumbing word
      if (/^\d+$/.test(t) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(t)) continue; // number or IP
      if (/[\/@\\=]/.test(t) || t.indexOf('$') >= 0) continue;    // path/email/kv or shell var ($g)
      if (lt.length < 2) continue;
      out[lt] = 1;
    }
    return out;
  }
  // Has a command with these same action tokens already been run (is it in the activity ledger)? Used by
  // the coach to demote a suggested variant you have already executed, so it stops re-offering it.
  function commandWasRun(filledCmd, activities, params) {
    var sig = _actionSig(filledCmd, params), keys = Object.keys(sig);
    // Only DISTINCTIVE commands are confidently "already run": a verb+object enumeration or grant has 3+
    // action tokens (`bloodyad get writable`, `nxc ldap --users`, `bloodyad add dcsync`). A generic
    // tool+mode invocation, `nxc smb` (validate), `evil-winrm`, `impacket-psexec`, `certipy find`, is a
    // re-runnable check/shell that recurs across many moves; marking it run is high-confusion, low-value,
    // and is exactly what wrongly flagged an UNRUN `nxc smb` as ✓ ran. Bias to under-marking: re-suggesting
    // a command is a mild annoyance, wrongly hiding one you still need is the failure that keeps biting.
    if (keys.length < 3) return false;
    function covers(cmd) {
      if (!cmd) return false;
      var asig = _actionSig(cmd, params);
      for (var k = 0; k < keys.length; k++) { if (!asig[keys[k]]) return false; }
      return true;
    }
    for (var a = 0; a < (activities || []).length; a++) {
      var act = activities[a] || {};
      // Match the honest command OR the recovered dispatch label, an ATTACHED dump has no typed command,
      // so obol's recovered routing signature is the only record of what actually ran.
      if (covers(act.command) || covers(act.dispatch)) return true;
    }
    return false;
  }

  // Which {{tokens}} in a template are still unfilled (dependencies the operator must supply).
  function unfilledTokens(filledText) {
    var out = [], re = /\{\{([a-zA-Z0-9_]+)\}\}/g, m;
    while ((m = re.exec(filledText)) !== null) { if (out.indexOf(m[1]) === -1) out.push(m[1]); }
    return out;
  }

  var EARNED_TOKENS = {
    domain: 1, basedn: 1, dc: 1, dc_netbios: 1, dc_account: 1, user: 1, password: 1,
    nthash: 1, userlist: 1, hashfile: 1, domain_sid: 1, target_sam: 1, group: 1, ca_name: 1, template: 1,
    pfx: 1, nmap_ports: 1, krbtgt_hash: 1, dahash: 1, dauser: 1, flag_path_local: 1, flag_path_root: 1, share: 1, cpassword: 1
  };

  function _normCmd(s) {
    return String(s || '').trim().replace(/\s+/g, ' ');
  }

  function primaryBinary(cmdStr) {
    var m = String(cmdStr || '').trim().match(/^(?:sudo\s+)?(\S+)/);
    return m ? m[1].replace(/^.*[\\/]/, '') : '';
  }

  function commandTriedInEpoch(action, cmdObj, filledStr, activities, epoch, target) {
    if (!action || !cmdObj || !Array.isArray(activities) || !activities.length) return false;
    var rawRun = _normCmd(cmdObj.run);
    var filledCmd = _normCmd(filledStr);
    var cmdTool = String(cmdObj.tool || primaryBinary(rawRun) || '').toLowerCase().replace(/\.(py|exe)$/, '');
    var sameToolCount = 0;
    var cmds = action.commands || [];
    if (cmdTool) {
      for (var c = 0; c < cmds.length; c++) {
        var ct = String(cmds[c].tool || primaryBinary(cmds[c].run) || '').toLowerCase().replace(/\.(py|exe)$/, '');
        if (ct === cmdTool) sameToolCount++;
      }
    }
    var isFlagHuntSession = (action.id === 'flag-hunt-windows' || action.id === 'flag-hunt-root-windows') && cmdTool === 'evil-winrm';
    var currentContext = OBOL.context && OBOL.store && OBOL.store.active ? OBOL.context.resolve({engagement:OBOL.store.active(),target:target,command:filledStr || rawRun,actionId:action.id,locus:OBOL.pack && OBOL.pack.commandExecutionLocus ? OBOL.pack.commandExecutionLocus(cmdObj) : 'remote'}) : null;
    for (var a = 0; a < activities.length; a++) {
      var act = activities[a];
      if (!act || (act.action_id || act.actionId) !== action.id) continue;
      var actTarget = act.target || (/^host:/.test(act.scope || '') ? act.scope.slice(5) : '');
      if (target && actTarget !== target) continue;
      if (epoch && act.epoch && act.epoch !== epoch) continue;
      if (act.outcome && !act.outcome.retireCommand) continue;
      if (currentContext) {
        var previousContext = act.context || (act.outcome && act.outcome.context);
        if (!previousContext) continue;
        if ((previousContext.credentialId || null) !== currentContext.credentialId || (previousContext.service || '') !== currentContext.service || (previousContext.locus || 'remote') !== currentContext.locus) continue;
      }
      var ac = _normCmd(act.command);
      if (ac && (ac === rawRun || (filledCmd && ac === filledCmd))) return true;
      var ad = _normCmd(act.dispatch);
      if (filledCmd && ad && ad.indexOf(filledCmd) >= 0) return true;
      var actTool = String(act.tool || primaryBinary(ac) || '').toLowerCase().replace(/\.(py|exe)$/, '');
      if (!currentContext && cmdTool && actTool === cmdTool && (!ac || sameToolCount === 1 || isFlagHuntSession)) return true;
    }
    return false;
  }

  function bestCommandIndex(action, facts, opts) {
    if (!action) return 0;
    var commands = action.commands || [];
    if (!commands.length) return 0;
    opts = opts || {};
    var locus = opts.locus || (action.locus === 'F' || action.locus === 'I' ? 'onhost' : 'remote');
    var filled = fillAll(action, facts, opts);
    function isGated(cmd, i) {
      var commandFacts = facts && facts.forAction ? facts.forAction(action, cmd) : facts;
      if (action.eligible && commandFacts && !action.eligible(commandFacts)) return true;
      if (OBOL.pack && OBOL.pack.commandIsEligible && !OBOL.pack.commandIsEligible(cmd, commandFacts)) return true;
      if (!filled[i]) return false;
      if (filled[i].blocked) return true;
      var un = unfilledTokens(filled[i].filled || '');
      return un.some(function (t) { return EARNED_TOKENS[t]; });
    }
    var acts = Array.isArray(opts.activities) ? opts.activities : null;
    var curEpoch = opts.epoch || ((root.OBOL && root.OBOL.pack && root.OBOL.pack.accessEpoch && facts) ? root.OBOL.pack.accessEpoch(facts) : '');
    var triedFn = acts ? function (cmd, i) {
      return commandTriedInEpoch(action, cmd, filled[i] && filled[i].filled, acts, curEpoch, opts.params && opts.params.target);
    } : null;
    if (root.OBOL && root.OBOL.pack && root.OBOL.pack.preferredCommandIndex) {
      return root.OBOL.pack.preferredCommandIndex(action, locus, facts || null, isGated, triedFn);
    }
    for (var i = 0; i < commands.length; i++) {
      var cmd = commands[i];
      if (root.OBOL && root.OBOL.pack && root.OBOL.pack.commandSettled) {
        if (root.OBOL.pack.commandSettled(cmd, facts)) continue;
      } else if (cmd && (cmd.settled_by || cmd.settledBy) && facts) {
        var sb = cmd.settled_by || cmd.settledBy;
        var settled = false;
        for (var s = 0; s < sb.length; s++) { if (facts.has(sb[s])) { settled = true; break; } }
        if (settled) continue;
      }
      if (!isGated(cmd, i)) return i;
    }
    return 0;
  }

  // Check if a command's transport port is confirmed open when port evidence exists
  var CMD_PORT_MAP = {
    'evil-winrm': [5985, 5986],
    'winrs': [5985, 5986],
    'ssh': [22], 'sshpass': [22],
    'smbclient': [445, 139], 'smbmap': [445, 139],
    'impacket-psexec': [445], 'impacket-wmiexec': [445, 135], 'impacket-smbexec': [445],
    'psexec': [445], 'wmiexec': [445, 135], 'smbexec': [445],
    'xfreerdp': [3389], 'rdesktop': [3389],
    'mysql': [3306], 'mssqlclient': [1433],
    'ldapsearch': [389, 636], 'windapsearch': [389, 636],
    'ftp': [21], 'snmpwalk': [161]
  };

  function commandPortFeasible(cmd, facts) {
    if (!cmd || !facts) return { feasible: true };
    var tool = String(cmd.tool || '').toLowerCase();
    var portsNeeded = CMD_PORT_MAP[tool];
    if (!portsNeeded || !portsNeeded.length) return { feasible: true };

    var portsKnown = openPorts(facts);
    if (!portsKnown || !portsKnown.length) return { feasible: true }; // No scan data yet, don't rule out

    for (var i = 0; i < portsNeeded.length; i++) {
      if (portsKnown.indexOf(portsNeeded[i]) >= 0 || facts.has('port:' + portsNeeded[i])) {
        return { feasible: true, port: portsNeeded[i] };
      }
    }
    return { feasible: false, required: portsNeeded };
  }

  // Deconstruct common CLI flags into structured, plain-language explanations for student learning
  var FLAG_EXPLANATIONS = {
    '-m': 'Hash type mode (e.g. 18200 = Kerberos AS-REP, 13100 = Kerberos TGS, 1000 = NTLM, 0 = MD5)',
    '-u': 'Target username, username list, or URL',
    '-p': 'Password, hash, or password list',
    '-d': 'Target Active Directory domain name',
    '-H': 'NTLM hash for Pass-the-Hash authentication (no plaintext needed)',
    '-k': 'Use Kerberos ticket authentication (requires existing ccache / TGT)',
    '-dc-ip': 'IP address of Domain Controller for Kerberos/LDAP queries',
    '-request': 'Request Kerberos TGS service tickets for Kerberoasting',
    '-no-pass': 'Authenticate without a password (for AS-REP roasting or anonymous bind)',
    '-O': 'Optimized OpenCL hashcat kernel (faster speed; limits password length to 32)',
    '-Pn': 'Skip ICMP ping discovery (treat host as online, bypassing firewall blocks)',
    '-sC': 'Run default Nmap script set against discovered ports',
    '-sV': 'Probe open ports to fingerprint service and software version',
    '-oN': 'Save output in human-readable normal format to file',
    '-oX': 'Save output in structured XML format for parsers',
    '--min-rate': 'Send packets at minimum rate (packets/sec) for faster scanning',
    '--shares': 'List accessible SMB shares and current access rights',
    '--users': 'Query and enumerate domain user accounts',
    '--rid-brute': 'Enumerate domain users via anonymous/guest RPC RID cycling',
    '--asreproast': 'Extract AS-REP hashes for accounts with DONT_REQ_PREAUTH',
    '--kerberoasting': 'Request and extract TGS hashes for service accounts (SPNs)',
    '--bloodhound': 'Collect full Active Directory domain graph data for BloodHound',
    '-M': 'Execute a NetExec enumeration or post-exploitation module',
    '-x': 'Execute a remote shell command',
    '-X': 'Execute a remote PowerShell command',
    '--local-auth': 'Authenticate against local target SAM database instead of domain',
    '-r': 'Recursively list directories or shares',
    '-R': 'Recursively list directories or shares (smbmap)',
    '-w': 'Wordlist path for dictionary attack or directory fuzzing',
    '-t': 'Number of concurrent execution threads',
    '-N': 'No password / anonymous bind (suppress password prompt)',
    '-c': 'Execute a single command string and exit',
    '-L': 'List available SMB shares on the target',
    '-U': 'Username or credentials (format: DOMAIN\\USER%PASSWORD)',
    '--download': 'Download specified remote file from SMB share'
  };

  function explainFlags(cmdStr) {
    if (!cmdStr) return [];
    var toks = String(cmdStr).trim().split(/\s+/);
    var results = [];
    var seen = {};

    for (var i = 0; i < toks.length; i++) {
      var tok = toks[i];
      if (tok.charAt(0) !== '-') continue;
      var flagName = tok;
      var val = '';
      if (i + 1 < toks.length && toks[i + 1].charAt(0) !== '-') {
        val = toks[i + 1].replace(/^["']|["']$/g, '');
      }

      var exp = FLAG_EXPLANATIONS[flagName];
      if (!exp && flagName.indexOf('=') > 0) {
        var base = flagName.split('=')[0];
        exp = FLAG_EXPLANATIONS[base];
        val = flagName.slice(base.length + 1);
        flagName = base;
      }

      // Context-aware flag definitions
      if (flagName === '-p') {
        var firstTool = toks[0].toLowerCase();
        if (firstTool.indexOf('nmap') >= 0 || firstTool.indexOf('rustscan') >= 0 || /^[\d,-]+$/.test(val)) {
          exp = 'Target port(s) to probe (e.g. -p 80,445 or -p-)';
        }
      }

      var displayVal = val;
      if (val && val.length > 20) {
        if (val.indexOf(',') >= 0) {
          var pList = val.split(',');
          displayVal = pList.slice(0, 3).join(',') + '… (' + pList.length + ' ports)';
        } else {
          displayVal = val.slice(0, 18) + '…';
        }
      }

      if (exp && !seen[flagName]) {
        seen[flagName] = 1;
        results.push({
          flag: flagName,
          value: displayVal,
          fullValue: val,
          meaning: exp
        });
      }
    }
    return results;
  }

  OBOL.command = {
    shellQuote: shellQuote,
    openPorts: openPorts,
    scopedValues: scopedValues,
    buildContext: buildContext,
    commandContext: buildContext,
    fillTemplate: fillTemplate,
    fillCommand: fillCommand,
    fillAll: fillAll,
    applyArsenal: applyArsenal,
    commandWasRun: commandWasRun,
    unfilledTokens: unfilledTokens,
    commandPortFeasible: commandPortFeasible,
    explainFlags: explainFlags,
    bestCommandIndex: bestCommandIndex,
    commandTriedInEpoch: commandTriedInEpoch,
    EARNED_TOKENS: EARNED_TOKENS,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);

