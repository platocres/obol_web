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
  var PATH_TOKENS = /(?:dir|file|path|list|script|binary|bin|archive|keyfile|export)$/i;
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

  var _baseCtxCache = typeof WeakMap !== 'undefined' ? new WeakMap() : null;

  // Build the {{token}} context from facts + params (+ extra which wins).
  function buildContext(facts, opts) {
    opts = opts || {};
    var resolved = opts.context && opts.context.params ? opts.context : null;
    if (!resolved && facts && typeof facts.forAction === 'function' && opts.action && !opts.service && !opts.locus
        && (!opts.target || (facts._resolvedContext && opts.target === facts._resolvedContext.target))) {
      var af = facts.forAction(opts.action, { run: opts.command || '' });
      if (af && af._resolvedContext) resolved = af._resolvedContext;
    }
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
    var wsd = opts.workspace || { root: '.', scandir: 'scans', lootdir: 'loot', exploitdir: 'exploit', wwwdir: 'www', proofdir: 'proof' };
    var arProf = _arsenalProfile();

    var projObj = (_baseCtxCache && resolved && facts && !(opts.action && opts.action.id === 'asrep-roast'))
      ? Object.getPrototypeOf(facts) : null;
    if (projObj === Object.prototype) projObj = null;
    var projMap = projObj ? _baseCtxCache.get(projObj) : null;
    var baseKey = projObj
      ? [tgt, resolved.credentialId || '', (facts.facts && facts.facts.length) || 0, JSON.stringify(params), JSON.stringify(opts.profile || null), JSON.stringify(wsd), _arsenalRaw || ''].join('\x01')
      : '';
    var ctx;
    if (projMap && projMap[baseKey]) {
      ctx = Object.assign({}, projMap[baseKey]);
    } else {
    ctx = Object.assign({ target: tgt || '<target>' }, paramsToInputs(params));
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
          if (rankedCreds[c].password || rankedCreds[c].secret) ctx.password = rankedCreds[c].password || rankedCreds[c].secret;
          var nhm = rankedCreds[c].nthash || rankedCreds[c].hash;
          if (nhm) ctx.nthash = nhm;
        }
        if (!ctx.domain && rankedCreds[c].domain) ctx.domain = rankedCreds[c].domain;
        break;
      }
    } else if (rankedCreds.length) {
      var c0 = rankedCreds[0];
      if (c0.user) ctx.user = c0.user;
      if ((c0.password || c0.secret) && !ctx.password) ctx.password = c0.password || c0.secret;
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

    // Resolve admin hash aliases from the command's scoped material. A resolved
    // context contains only the selected credential, so these aliases never
    // silently switch away from the account the operator chose.
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
      if (!ctx.dahash && !(facts && facts._resolvedContext && facts._resolvedContext.credentialId)) {
        var ntFacts = fvals('hash.ntlm'), ntEntries = [];
        for (var ntf = 0; ntf < ntFacts.length; ntf++) {
          var fv = ntFacts[ntf] || {};
          if (Array.isArray(fv.entries)) {
            for (var nte = 0; nte < fv.entries.length; nte++) ntEntries.push(fv.entries[nte]);
          } else {
            ntEntries.push(fv);
          }
        }
        for (var nt = 0; nt < ntEntries.length; nt++) {
          var ntVal = ntEntries[nt] || {};
          var ntUser = String(ntVal.user || '');
          var isAdminNt = ntVal.rid === 500 || ntUser.toLowerCase() === 'administrator';
          if (!isAdminNt) continue;
          if ((ntVal.nt || ntVal.nthash || ntVal.hash)) {
            ctx.dahash = ntVal.nt || ntVal.nthash || ntVal.hash;
            ctx.dauser = ntUser || 'Administrator';
            if (!ctx.domain && ntVal.domain) ctx.domain = ntVal.domain;
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
    var joinedByLower = {};
    var lastJoinedGroup = '';
    fvals('ad.group_joined').forEach(function (jv) {
      if (jv && jv.group) {
        var gClean = String(jv.group).split('@')[0].trim();
        if (gClean) {
          var gl = gClean.toLowerCase();
          joinedSet[gl] = 1;
          joinedByLower[gl] = gClean;
          lastJoinedGroup = gClean;
        }
      }
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
      var aclLeads = fvals('ad.acl_lead');
      var leadTargets = [];
      aclLeads.forEach(function (v) {
        (v.targets || []).forEach(function (tgt) { if (tgt && leadTargets.indexOf(tgt) < 0) leadTargets.push(tgt); });
      });
      var knownComputers = { 'the domain object': 1 };
      fvals('ad.computer_list').forEach(function (cv) {
        ((cv && cv.computers) || []).forEach(function (c) {
          var base = String(c || '').replace(/\$$/, '').split('.')[0].toLowerCase();
          if (base) knownComputers[base] = 1;
        });
      });
      if (ctx.dc_netbios) knownComputers[String(ctx.dc_netbios).toLowerCase()] = 1;
      if (ctx.hostname) knownComputers[String(ctx.hostname).split('.')[0].toLowerCase()] = 1;
      function _looksLikeComputerTarget(t) {
        var s = String(t || '').trim();
        if (!s) return true;
        var sl = s.toLowerCase();
        if (knownComputers[sl] || s.charAt(s.length - 1) === '$') return true;
        if (/^[A-Z0-9_-]+\d+$/.test(s) && s.indexOf(' ') < 0) return true;
        return false;
      }
      // Candidates = the reasonable, known-abusable groups the lead shows, in priority order, followed by
      // any custom domain groups discovered by `get writable` or BloodHound.
      var lowerSet = {};
      leadTargets.forEach(function (t) { lowerSet[String(t).toLowerCase()] = t; });
      var candidates = [], seenCand = {};
      function _pushCand(g) {
        var gl = String(g || '').toLowerCase();
        if (gl && !seenCand[gl]) { seenCand[gl] = 1; candidates.push(g); }
      }
      if (ctx.group && !joinedSet[String(ctx.group).toLowerCase()]) _pushCand(ctx.group);
      ABUSE_PRIORITY.forEach(function (g) { if (lowerSet[g] && !joinedSet[g]) _pushCand(lowerSet[g]); });
      leadTargets.forEach(function (t) {
        var tl = String(t || '').toLowerCase();
        if (!seenCand[tl] && !joinedSet[tl] && !_looksLikeComputerTarget(t)) _pushCand(t);
      });
      if (!candidates.length && aclLeads.length) {
        candidates = ABUSE_PRIORITY.map(function (g) { return g.replace(/\b\w/g, function (c) { return c.toUpperCase(); }); });
      }
      if (ctx.group === undefined && leadTargets.length) ctx.group = candidates[0] || leadTargets[0] || '';
      if (ctx.target_sam === undefined && leadTargets.length) ctx.target_sam = candidates[0] || leadTargets[0] || '';
      if (ctx.abuse_groups_quoted === undefined && candidates.length) {
        ctx.abuse_groups_quoted = candidates.map(function (g) { return '"' + String(g).replace(/(["\\$`])/g, '\\$1') + '"'; }).join(' ');
      }
    }
    if (ctx.joined_group === undefined) {
      var bestJoined = '';
      var JOINED_PRIORITY = ['domain admins', 'enterprise admins', 'administrators',
        'exchange windows permissions', 'account operators', 'organization management',
        'backup operators', 'server operators', 'dnsadmins', 'print operators',
        'group policy creator owners', 'key admins', 'enterprise key admins'];
      for (var jpi = 0; jpi < JOINED_PRIORITY.length; jpi++) {
        if (joinedByLower[JOINED_PRIORITY[jpi]]) {
          bestJoined = joinedByLower[JOINED_PRIORITY[jpi]];
          break;
        }
      }
      ctx.joined_group = bestJoined || lastJoinedGroup || ctx.group || 'Exchange Windows Permissions';
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
      // Both flag_path_local (plus flag_smb_path_local) and flag_path_root are earned gate tokens:
      // only populated once objective.flag_located has confirmed the exact file path on the target.
      if (ctx.flag_path_local === undefined) {
        var _locL = _locatedPath('local');
        if (_locL) {
          ctx.flag_path_local = _locL;
        }
      }
      if (ctx.flag_path_local) {
        var _baseL = String(ctx.flag_path_local).split(/[\\/]/).pop();
        if (_baseL && !ctx.flag_name_local) ctx.flag_name_local = _baseL;
        if (ctx.flag_smb_path_local === undefined) {
          var _smbRel = String(ctx.flag_path_local)
            .replace(/^(?:[A-Za-z]:[\\/]+Users[\\/]+|(?:\/\/|\\\\)[^/\\]+[/\\]+Users[/\\]+)/i, '')
            .replace(/\\+/g, '/');
          if (_smbRel) ctx.flag_smb_path_local = _smbRel;
        }
      }
      if (!ctx.flag_name_local) {
        ctx.flag_name_local = _flagName('local');
      }
      if (ctx.flag_path_root === undefined) {
        var _locR = _locatedPath('root');
        if (_locR) {
          ctx.flag_path_root = _locR;
        }
      }
      if (ctx.flag_path_root) {
        var _baseR = String(ctx.flag_path_root).split(/[\\/]/).pop();
        if (_baseR && !ctx.flag_name_root) ctx.flag_name_root = _baseR;
      }
      if (!ctx.flag_name_root) {
        ctx.flag_name_root = _flagName('root');
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

    // Pivot, subnet, neighbor, resolver, and listener tokens from local-pivot / listener facts
    var subCandidates = fvals('network.subnet_candidate');
    var routeVals = fvals('host.route');
    var bestCidr = (subCandidates[0] && subCandidates[0].cidr) || (routeVals[0] && routeVals[0].dst) || '';
    if (!bestCidr && ctx.target && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(ctx.target))) {
      bestCidr = String(ctx.target).replace(/\.\d+$/, '.0/24');
    }
    if (bestCidr) {
      if (!ctx.subnet) ctx.subnet = bestCidr;
      if (!ctx.internal_subnet) ctx.internal_subnet = bestCidr;
      if (!ctx.internal_cidr) ctx.internal_cidr = bestCidr;
    }
    var arpNeighbors = fvals('host.arp_neighbor');
    if (arpNeighbors.length) {
      var nIps = arpNeighbors.map(function (n) { return n && n.ip; }).filter(Boolean);
      if (nIps.length) {
        if (!ctx.internal_host) ctx.internal_host = nIps[0];
        if (!ctx.neighbor_hosts) ctx.neighbor_hosts = nIps.join(' ');
      }
    }
    var dnsServers = fvals('host.dns_server');
    if (!ctx.dns_server) {
      ctx.dns_server = (dnsServers[0] && dnsServers[0].ip) || ctx.dc_ip || ctx.target || '';
    }
    var listenSockets = fvals('host.listen_socket');
    var openListeners = fvals('listener.open');
    var lSockPort = (listenSockets[0] && listenSockets[0].port) || (openListeners[0] && openListeners[0].port) || '';
    if (lSockPort) {
      if (!ctx.listener_port) ctx.listener_port = String(lSockPort);
      if (!ctx.local_port) ctx.local_port = String(lSockPort);
    }

    // workspace output-directory tokens ({{scandir}} etc.) - from opts.workspace when the caller
    // supplies it (OBOL.workspace.tokens(eng)), else relative fallbacks so commands still form.
    ['root', 'scandir', 'lootdir', 'exploitdir', 'wwwdir', 'proofdir'].forEach(function (k) {
      if (ctx[k] === undefined && wsd[k] !== undefined) ctx[k] = wsd[k];
    });

    // Populate high-frequency service, web, keyfile, SPN, NFS, SNMP, module, and KeePass tokens
    if (!ctx.web_port || !ctx.url) {
      var httpResps = fvals('http.response').concat(fvals('web.server')).concat(fvals('http.reachable'));
      var foundUrl = '', foundWebPort = '';
      for (var hri = 0; hri < httpResps.length; hri++) {
        var hv = httpResps[hri] || {};
        if (!foundUrl && (hv.url || hv.base_url)) foundUrl = String(hv.url || hv.base_url);
        if (!foundWebPort && hv.port) foundWebPort = String(hv.port);
      }
      if (!foundWebPort) {
        var openP = openPorts(facts);
        var webPortOrder = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000];
        for (var wpi = 0; wpi < webPortOrder.length; wpi++) {
          if (openP.indexOf(webPortOrder[wpi]) >= 0 || (facts && facts.has && facts.has('port:' + webPortOrder[wpi]))) {
            foundWebPort = String(webPortOrder[wpi]);
            break;
          }
        }
      }
      if (!ctx.web_port) ctx.web_port = foundWebPort || '80';
      if (!ctx.http_port) ctx.http_port = ctx.web_port;
      if (!ctx.url) {
        if (foundUrl) {
          ctx.url = foundUrl;
        } else {
          var webHost = ctx.hostname || ctx.target || '127.0.0.1';
          var wp = ctx.web_port || '80';
          var scheme = (wp === '443' || wp === '8443') ? 'https://' : 'http://';
          var portSuffix = (wp === '80' || wp === '443') ? '' : (':' + wp);
          ctx.url = scheme + webHost + portSuffix;
        }
      }
    }
    if (!ctx.service) {
      var svcFacts = fvals('privesc.weak_service_permission').concat(fvals('privesc.unquoted_service_path')).concat(fvals('privesc.sudo_rights'));
      for (var svi = 0; svi < svcFacts.length; svi++) {
        var sv = svcFacts[svi] || {};
        if (sv.service || sv.name || sv.unit) { ctx.service = String(sv.service || sv.name || sv.unit); break; }
      }
      if (!ctx.service) ctx.service = 'Spooler';
    }
    if (!ctx.command) ctx.command = 'whoami';
    if (!ctx.sid) {
      var oraSids = fvals('oracle.sid');
      if (oraSids[0] && (oraSids[0].sid || oraSids[0].name)) ctx.sid = String(oraSids[0].sid || oraSids[0].name);
      else if (ctx.domain_sid) ctx.sid = ctx.domain_sid;
      else ctx.sid = 'XE';
    }
    if (!ctx.keyfile && !ctx.key_file) {
      var sshKeys = fvals('loot.ssh_key').concat(fvals('credential.ssh_key')).concat(fvals('ssh.private_key')).concat(fvals('credential.certificate'));
      var kf = '';
      for (var ski = 0; ski < sshKeys.length; ski++) {
        var skv = sshKeys[ski] || {};
        var skCandidate = skv.ssh_key_path || skv.sshKeyPath || skv.keyPath || skv.key_path || skv.path || skv.file || skv.keyfile;
        if (skCandidate) { kf = String(skCandidate); break; }
      }
      ctx.keyfile = kf || 'id_rsa';
      ctx.key_file = ctx.keyfile;
    } else if (ctx.keyfile && !ctx.key_file) {
      ctx.key_file = ctx.keyfile;
    } else if (ctx.key_file && !ctx.keyfile) {
      ctx.keyfile = ctx.key_file;
    }
    if (!ctx.cert_file) {
      ctx.cert_file = ctx.pfx || 'cert.pfx';
    }
    if (!ctx.spn_host) {
      var delFacts = fvals('ad.delegation').concat(fvals('ad.rbcd')).concat(fvals('ad.unconstrained'));
      for (var dli = 0; dli < delFacts.length; dli++) {
        var dlv = delFacts[dli] || {};
        var spnTgt = dlv.target || dlv.spn_host || (dlv.spn ? String(dlv.spn).split('/')[1] : '');
        if (spnTgt) { ctx.spn_host = String(spnTgt); break; }
      }
      if (!ctx.spn_host) ctx.spn_host = ctx.dc_fqdn || ctx.hostname || ctx.target || '';
    }
    if (!ctx.export) {
      var nfsEx = fvals('nfs.exports').concat(fvals('privesc.nfs_no_root_squash'));
      for (var nfi = 0; nfi < nfsEx.length; nfi++) {
        var nfv = nfsEx[nfi] || {};
        if (nfv.path || nfv.export || (Array.isArray(nfv.exports) && nfv.exports[0])) {
          ctx.export = String(nfv.path || nfv.export || nfv.exports[0]);
          break;
        }
      }
      if (!ctx.export) ctx.export = '/var/nfs';
    }
    if (!ctx.community) {
      var snmpCom = fvals('snmp.community');
      if (snmpCom[0] && (snmpCom[0].community || snmpCom[0].value)) ctx.community = String(snmpCom[0].community || snmpCom[0].value);
      else ctx.community = 'public';
    }
    if (!ctx.module) {
      var modFacts = fvals('rsync.modules').concat(fvals('privesc.script_sink'));
      for (var mdi = 0; mdi < modFacts.length; mdi++) {
        var mdv = modFacts[mdi] || {};
        if (mdv.module || mdv.name || (Array.isArray(mdv.modules) && mdv.modules[0])) {
          ctx.module = String(mdv.module || mdv.name || mdv.modules[0]);
          break;
        }
      }
      if (!ctx.module) ctx.module = 'files';
    }
    if (!ctx.kdbx_file) {
      var kdbxFacts = fvals('loot.keepass_dump').concat(fvals('loot.files'));
      for (var kbi = 0; kbi < kdbxFacts.length; kbi++) {
        var kbv = kdbxFacts[kbi] || {};
        var kbPath = kbv.path || kbv.file || (Array.isArray(kbv.files) ? kbv.files.find(function (f) { return /\.kdbx$/i.test(String(f)); }) : '');
        if (kbPath && /\.kdbx$/i.test(String(kbPath))) { ctx.kdbx_file = String(kbPath); break; }
      }
      if (!ctx.kdbx_file) ctx.kdbx_file = 'Database.kdbx';
    }
    if ((ctx.group === undefined || ctx.group === '') && facts && facts.has && (facts.has('ad.acl_lead') || facts.has('ad.attack_paths') || facts.has('ad.control_paths'))) {
      ctx.group = 'Domain Admins';
    }
    if ((ctx.target_sam === undefined || ctx.target_sam === '') && facts && facts.has && (facts.has('ad.acl_lead') || facts.has('ad.attack_paths') || facts.has('ad.control_paths'))) {
      ctx.target_sam = ctx.group || ctx.user || 'Administrator';
    }
    if (!ctx.new_password) {
      ctx.new_password = (params && params.new_password) || 'Newp@ss123!';
    }
    if (!ctx.target_user) {
      var KNOWN_GROUPS = {
        'domain admins': 1, 'enterprise admins': 1, 'administrators': 1,
        'exchange windows permissions': 1, 'account operators': 1, 'organization management': 1,
        'backup operators': 1, 'server operators': 1, 'dnsadmins': 1, 'print operators': 1,
        'group policy creator owners': 1, 'key admins': 1, 'enterprise key admins': 1,
        'domain users': 1, 'remote management users': 1, 'remote desktop users': 1
      };
      var curUserLower = String(ctx.user || ctx.username || '').toLowerCase();
      var _isUserTarget = function (cand) {
        var s = String(cand || '').trim().replace(/@.*$/, '');
        if (!s || s.indexOf(' ') >= 0 || s.charAt(s.length - 1) === '$') return false;
        var sl = s.toLowerCase();
        if (KNOWN_GROUPS[sl] || sl === curUserLower || sl === 'krbtgt' || sl === 'guest' || sl === 'defaultaccount') return false;
        if (ctx.dc_netbios && sl === String(ctx.dc_netbios).toLowerCase()) return false;
        if (ctx.hostname && sl === String(ctx.hostname).split('.')[0].toLowerCase()) return false;
        return true;
      };
      var pickedUser = '';
      var aclVals = fvals('ad.acl_lead');
      for (var aui = 0; aui < aclVals.length && !pickedUser; aui++) {
        var atgts = (aclVals[aui] && aclVals[aui].targets) || [];
        for (var auj = 0; auj < atgts.length; auj++) {
          if (_isUserTarget(atgts[auj])) { pickedUser = String(atgts[auj]).trim().replace(/@.*$/, ''); break; }
        }
      }
      if (!pickedUser) {
        var apVals = fvals('ad.attack_paths');
        for (var api = 0; api < apVals.length && !pickedUser; api++) {
          var faObj = (apVals[api] && apVals[api].first_abuse) || {};
          if (faObj.kind === 'user' && _isUserTarget(faObj.target)) {
            pickedUser = String(faObj.target).trim().replace(/@.*$/, '');
            break;
          }
        }
      }
      if (!pickedUser) {
        var ulVals = fvals('ad.user_list');
        for (var uli = 0; uli < ulVals.length && !pickedUser; uli++) {
          var ulist = (ulVals[uli] && ulVals[uli].users) || [];
          for (var ulj = 0; ulj < ulist.length; ulj++) {
            if (_isUserTarget(ulist[ulj])) { pickedUser = String(ulist[ulj]).trim().replace(/@.*$/, ''); break; }
          }
        }
      }
      ctx.target_user = pickedUser || 'Administrator';
    }
    if (!ctx.edb_id || !ctx.edb_file || !ctx.edb_path) {
      var edbItems = [];
      fvals('exploit.script_inspected').concat(fvals('exploit.edb_candidate')).forEach(function (ev) {
        if (!ev || typeof ev !== 'object') return;
        edbItems.push(ev);
        ['candidates', 'exploits', 'matches'].forEach(function (arrKey) {
          if (Array.isArray(ev[arrKey])) {
            ev[arrKey].forEach(function (sub) { if (sub && typeof sub === 'object') edbItems.push(sub); });
          }
        });
      });
      var foundEdbId = ctx.edb_id ? String(ctx.edb_id).trim() : '';
      var foundEdbFile = ctx.edb_file ? String(ctx.edb_file).trim() : '';
      var foundEdbPath = ctx.edb_path ? String(ctx.edb_path).trim() : '';
      var foundEdbExt = '';
      for (var edi = 0; edi < edbItems.length; edi++) {
        var edv = edbItems[edi];
        var rawEdbId = edv.edb_id || edv.edbId || edv.exploit_id || edv.id || '';
        var normEdbId = rawEdbId ? String(rawEdbId).trim().replace(/^edb(?:-id)?[:\s-]*/i, '') : '';
        var rawEdbPath = edv.edb_path || edv.edbPath || edv.full_path || edv.fullPath || edv.script_path || edv.path || '';
        var rawEdbFile = edv.edb_file || edv.edbFile || edv.filename || edv.file || edv.script || '';
        if (!rawEdbPath && rawEdbFile && /[\\\/]/.test(String(rawEdbFile))) rawEdbPath = String(rawEdbFile);
        var cleanEdbFile = rawEdbFile ? String(rawEdbFile).trim().replace(/^.*[\\\/]/, '') : '';
        if (!cleanEdbFile && rawEdbPath) cleanEdbFile = String(rawEdbPath).trim().replace(/^.*[\\\/]/, '');
        if (!normEdbId && cleanEdbFile) {
          var idMatch = /^(?:edb[_-]?)?(\d{3,7})(?:\.[A-Za-z0-9]+)?$/i.exec(cleanEdbFile);
          if (idMatch) normEdbId = idMatch[1];
        }
        if (!foundEdbId && normEdbId) foundEdbId = normEdbId;
        var isGenericEdbFallback = /^exploit\.[A-Za-z0-9]+$/i.test(cleanEdbFile);
        if ((!foundEdbFile || (/^exploit\.[A-Za-z0-9]+$/i.test(foundEdbFile) && !isGenericEdbFallback)) && cleanEdbFile && (!foundEdbId || !normEdbId || normEdbId === foundEdbId)) foundEdbFile = cleanEdbFile;
        if (!foundEdbPath && rawEdbPath && !/^exploit\.[A-Za-z0-9]+$/i.test(String(rawEdbPath).trim()) && (!foundEdbId || !normEdbId || normEdbId === foundEdbId)) foundEdbPath = String(rawEdbPath).trim();
        if (!foundEdbExt && (edv.ext || edv.extension)) foundEdbExt = String(edv.ext || edv.extension).trim().replace(/^\./, '');
      }
      if (!foundEdbPath) {
        for (var edp = 0; edp < edbItems.length; edp++) {
          var epVal = edbItems[edp].edb_path || edbItems[edp].edbPath || edbItems[edp].full_path || edbItems[edp].fullPath || edbItems[edp].script_path || edbItems[edp].path || '';
          if (epVal) { foundEdbPath = String(epVal).trim(); break; }
        }
      }
      if (!foundEdbFile && foundEdbPath) foundEdbFile = foundEdbPath.replace(/^.*[\\\/]/, '');
      if (!foundEdbFile && foundEdbId && foundEdbExt) foundEdbFile = foundEdbId + '.' + foundEdbExt;
      if (!foundEdbPath && foundEdbFile) foundEdbPath = foundEdbFile;
      if (!ctx.edb_id && foundEdbId) ctx.edb_id = foundEdbId;
      if (!ctx.edb_file && foundEdbFile) ctx.edb_file = foundEdbFile;
      if (!ctx.edb_path && foundEdbPath) ctx.edb_path = foundEdbPath;
    }
    if (!ctx.custom_bin) {
      var cbItems = [];
      fvals('privesc.custom_binary').concat(fvals('host.custom_artifact')).forEach(function (cv) {
        if (!cv) return;
        if (typeof cv === 'string') { cbItems.push(cv); return; }
        cbItems.push(cv);
        ['binaries', 'artifacts', 'paths', 'files', 'items'].forEach(function (ak) {
          if (Array.isArray(cv[ak])) cv[ak].forEach(function (sub) { if (sub) cbItems.push(sub); });
        });
      });
      for (var cbi = 0; cbi < cbItems.length; cbi++) {
        var cbv = cbItems[cbi];
        var cbPick = typeof cbv === 'string'
          ? cbv
          : (cbv.custom_bin || cbv.customBin || cbv.path || cbv.full_path || cbv.fullPath || cbv.file || cbv.artifact || cbv.exe || cbv.binary || cbv.bin || cbv.command || cbv.target || cbv.name || '');
        if (cbPick && String(cbPick).trim()) { ctx.custom_bin = String(cbPick).trim(); break; }
      }
    }
    if (!ctx.source_path || !ctx.app_base_path) {
      var srcItems = [];
      fvals('web.source_disclosed').concat(fvals('web.manifest_disclosed')).forEach(function (sv) {
        if (!sv) return;
        if (typeof sv === 'string') { srcItems.push({ path: sv }); return; }
        srcItems.push(sv);
        ['paths', 'files', 'manifests', 'items'].forEach(function (ak) {
          if (Array.isArray(sv[ak])) {
            sv[ak].forEach(function (sub) {
              if (!sub) return;
              srcItems.push(typeof sub === 'string' ? { path: sub } : sub);
            });
          }
        });
      });
      fvals('exploit.script_inspected').concat(fvals('http.path')).forEach(function (hv) {
        if (!hv || typeof hv !== 'object') return;
        if (hv.source_path || hv.sourcePath || hv.manifest_path || hv.manifestPath || hv.app_base_path || hv.appBasePath) {
          srcItems.push(hv);
        }
      });
      var foundSrcPath = ctx.source_path ? String(ctx.source_path).trim() : '';
      var foundBasePath = ctx.app_base_path ? String(ctx.app_base_path).trim() : '';
      for (var sri = 0; sri < srcItems.length; sri++) {
        var srv = srcItems[sri];
        if (!foundSrcPath) {
          var rawSp = srv.source_path || srv.sourcePath || srv.manifest_path || srv.manifestPath || srv.target_path || srv.remote_path || srv.file_path || srv.path || srv.file || srv.uri || srv.endpoint || srv.url || '';
          if (rawSp && String(rawSp).trim()) {
            var spClean = String(rawSp).trim();
            var urlPathMatch = /^https?:\/\/[^\/]+(\/.*)$/i.exec(spClean);
            if (urlPathMatch) spClean = urlPathMatch[1];
            else if (/^https?:\/\/[^\/]+$/i.test(spClean)) spClean = '/';
            foundSrcPath = spClean;
          }
        }
        if (!foundBasePath) {
          var rawBp = srv.app_base_path || srv.appBasePath || srv.base_path || srv.basePath || srv.app_root || srv.appRoot || srv.docroot || srv.webroot || srv.root_dir || srv.dir || srv.directory || '';
          if (rawBp && String(rawBp).trim()) foundBasePath = String(rawBp).trim();
        }
        if (foundSrcPath && foundBasePath) break;
      }
      if (!foundBasePath && foundSrcPath) {
        if (foundSrcPath.indexOf('/') >= 0) {
          var trimmedSp = foundSrcPath.replace(/\/+$/, '');
          var lastSlash = trimmedSp.lastIndexOf('/');
          foundBasePath = lastSlash > 0 ? trimmedSp.slice(0, lastSlash) : '/';
        } else if (foundSrcPath.indexOf('\\') >= 0) {
          var trimmedWin = foundSrcPath.replace(/\\+$/, '');
          var lastBs = trimmedWin.lastIndexOf('\\');
          if (lastBs > 0) foundBasePath = trimmedWin.slice(0, lastBs);
        } else {
          foundBasePath = '/';
        }
      }
      if (!ctx.source_path && foundSrcPath) ctx.source_path = foundSrcPath;
      if (!ctx.app_base_path && foundBasePath) ctx.app_base_path = foundBasePath;
    }
    if (!ctx.ssh_key_path) {
      var keyItems = [];
      fvals('loot.ssh_key').concat(fvals('credential.ssh_key')).concat(fvals('ssh.private_key')).forEach(function (kv) {
        if (kv) keyItems.push(typeof kv === 'string' ? { path: kv } : kv);
      });
      fvals('credential.reuse_candidate').forEach(function (rv) {
        if (rv && (rv.ssh_key_path || rv.sshKeyPath || rv.keyPath || rv.key_path || rv.keyfile)) keyItems.push(rv);
      });
      fvals('credential.certificate').forEach(function (cv) {
        if (cv && (cv.kind === 'private_key' || cv.ssh_key_path || cv.sshKeyPath || cv.keyPath || cv.key_path || cv.keyfile)) keyItems.push(cv);
      });
      if (keyItems.length) {
        var pickedKeyPath = '';
        for (var kpi = 0; kpi < keyItems.length; kpi++) {
          var kpv = keyItems[kpi] || {};
          var rawKp = kpv.ssh_key_path || kpv.sshKeyPath || kpv.keyPath || kpv.key_path || kpv.keyfile || kpv.path || kpv.file || '';
          if (rawKp && String(rawKp).trim()) { pickedKeyPath = String(rawKp).trim(); break; }
        }
        ctx.ssh_key_path = pickedKeyPath || 'id_rsa';
      }
    }
    if (!ctx.reuse_user || !ctx.reuse_secret) {
      var reuseVals = fvals('credential.reuse_candidate');
      fvals('credential.available').forEach(function (av) {
        if (av && av.unvalidatedOnTarget && av.reuseFrom) reuseVals = reuseVals.concat([av]);
      });
      if (reuseVals.length) {
        var failedUsers = Object.create(null);
        fvals('blocker.logon_failure').forEach(function (bv) {
          var bu = String((bv && (bv.user || bv.username || bv.principal)) || '').trim().toLowerCase().replace(/^.*\\/, '');
          if (bu) failedUsers[bu] = (failedUsers[bu] || 0) + 1;
        });
        var activeUserLower = String(ctx.user || ctx.username || '').trim().toLowerCase();
        var scoredCands = [];
        var keyOnlyUser = '';
        for (var rci = 0; rci < reuseVals.length; rci++) {
          var rcv = reuseVals[rci] || {};
          var rUser = String(rcv.reuse_user || rcv.user || rcv.username || '').trim();
          var rPw = rcv.reuse_secret != null && rcv.reuse_secret !== ''
            ? String(rcv.reuse_secret)
            : (rcv.password != null && rcv.password !== '' ? String(rcv.password) : (rcv.secret != null && rcv.secret !== '' ? String(rcv.secret) : ''));
          var rNt = String(rcv.nthash || rcv.hash || '').trim();
          var rSec = rPw || rNt;
          if (rUser && rSec) {
            scoredCands.push({
              user: rUser,
              secret: rSec,
              isNtOnly: !rPw && /^[0-9a-f]{32}$/i.test(rNt),
              fails: failedUsers[rUser.toLowerCase()] || 0,
              matchesActive: activeUserLower && rUser.toLowerCase() === activeUserLower ? 1 : 0,
              idx: rci
            });
          } else if (rUser && !keyOnlyUser) {
            keyOnlyUser = rUser;
          }
        }
        if (scoredCands.length) {
          scoredCands.sort(function (a, b) {
            if (a.fails !== b.fails) return a.fails - b.fails;
            if (b.matchesActive !== a.matchesActive) return b.matchesActive - a.matchesActive;
            return a.idx - b.idx;
          });
          if (!ctx.reuse_user) ctx.reuse_user = scoredCands[0].user;
          if (!ctx.reuse_secret) {
            ctx.reuse_secret = scoredCands[0].secret;
            if (scoredCands[0].isNtOnly) ctx._reuseSecretIsNtHash = true;
          }
        } else if (!ctx.reuse_user && keyOnlyUser) {
          ctx.reuse_user = keyOnlyUser;
        }
      }
    }
    if (projObj) {
      if (!projMap) { projMap = Object.create(null); _baseCtxCache.set(projObj, projMap); }
      projMap[baseKey] = Object.assign({}, ctx);
    }
    }

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
    if (ctx.user && !ctx.username) ctx.username = ctx.user;
    if (ctx.username && !ctx.user) ctx.user = ctx.username;
    if (ctx.nthash && String(ctx.nthash).indexOf(':') !== -1) ctx.nthash = String(ctx.nthash).split(':').pop();
    if (ctx.dahash && String(ctx.dahash).indexOf(':') !== -1) ctx.dahash = String(ctx.dahash).split(':').pop();
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
    if (/^\s*(?:cmd\s+\/c\b|schtasks\b|reg\s+(?:query|add|save)|icacls\b|net\s+(?:user|localgroup|share|use)|type\s+|(?:hostname|whoami|ipconfig)\b[^\r\n]*&\s*(?:hostname|ipconfig|type)\b|(?:\.\\)?(?:Rubeus|SharpHound|certutil|mimikatz|procdump|GodPotato|PrintSpoofer|JuicyPotato|SweetPotato|accesschk|winPEAS\w*)\.exe\b)/i.test(run)) return 'cmd';
    if (/^\s*(?:hostname|whoami|ipconfig)\b[^\r\n]*;\s*(?:hostname|ipconfig|type|Get-)/i.test(run)) return 'powershell';
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
      if (/["%\r\n\x00]|![^!\r\n]+!/.test(s)) {
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
    // When an NT-hash-only credential is active (no cleartext password, nthash present),
    // automatically adapt AD tool templates from -p '{{password}}' / domain/user:{{password}} to Pass-the-Hash.
    if (!ctx.password && ctx.nthash && cmd.indexOf('{{password}}') >= 0) {
      if (/\b(?:nxc|netexec|crackmapexec|cme|smbmap|evil-winrm|pywhisker(?:\.py)?|targetedKerberoast(?:\.py)?)\b/i.test(cmd)) {
        cmd = cmd.replace(/(\s)-p\s+(?:'\{\{password\}\}'|"\{\{password\}\}"|\{\{password\}\})/g, "$1-H '{{nthash}}'");
      } else if (/\b(?:bloodyAD|dnstool(?:\.py)?|sccmhunter(?:\.py)?)\b/i.test(cmd)) {
        cmd = cmd.replace(/(\s)-p\s+(?:'\{\{password\}\}'|"\{\{password\}\}"|\{\{password\}\})/g, "$1-p ':{{nthash}}'");
      } else if (/\bcertipy(?:-ad)?\b/i.test(cmd)) {
        cmd = cmd.replace(/(\s)-p\s+(?:'\{\{password\}\}'|"\{\{password\}\}"|\{\{password\}\})/g, "$1-hashes ':{{nthash}}'");
      } else if (/\bbloodhound-python\b/i.test(cmd)) {
        cmd = cmd.replace(/(\s)-p\s+(?:'\{\{password\}\}'|"\{\{password\}\}"|\{\{password\}\})/g, "$1--hashes 'aad3b435b51404eeaad3b435b51404ee:{{nthash}}'");
      } else if (/\bxfreerdp3?\b/i.test(cmd)) {
        cmd = cmd.replace(/\/p:(?:'\{\{password\}\}'|"\{\{password\}\}"|\{\{password\}\})/g, "/pth:{{nthash}}");
      } else if (/\b(?:smbclient|rpcclient|net\s+rpc)\b/i.test(cmd)) {
        cmd = cmd.replace(/(-U\s+)(['"])([^'"]*?)%\{\{password\}\}\2/g, "$1$2$3%{{nthash}}$2 --pw-nt-hash");
        cmd = cmd.replace(/(-U\s+\S+?)%(?:'\{\{password\}\}'|"\{\{password\}\}"|\{\{password\}\})/g, "$1%{{nthash}} --pw-nt-hash");
      } else if (/\b(?:impacket-[\w-]+|(?:GetUserSPNs|GetNPUsers|Get-GPPPassword|raiseChild|secretsdump|ticketer|findDelegation|addcomputer|rbcd|dacledit|owneredit|getST|getTGT|psexec|wmiexec|smbexec|atexec|dcomexec|mssqlclient|noPac|goldenPac|lookupsid|rpcdump|samrdump|services|reg)(?:\.py)?)\b/i.test(cmd)) {
        cmd = cmd.replace(/(['"])(\{\{domain\}\}\/\{\{(?:user|username)\}\}):\{\{password\}\}(@[^'"]+)?\1(@\S+)?/g, function (_, q, ident, inAt, outAt) {
          return q + ident + (inAt || '') + q + (outAt || '') + " -hashes ':{{nthash}}'";
        });
        cmd = cmd.replace(/(['"]?\{\{domain\}\}['"]?\/['"]?\{\{(?:user|username)\}\}['"]?):(?:'\{\{password\}\}'|"\{\{password\}\}"|\{\{password\}\})(@\S+)?/g, function (_, ident, outAt) {
          return ident + (outAt || '') + " -hashes ':{{nthash}}'";
        });
        cmd = cmd.replace(/(\s)-p\s+(?:'\{\{password\}\}'|"\{\{password\}\}"|\{\{password\}\})/g, "$1-hashes ':{{nthash}}'");
      }
    }
    if (ctx._reuseSecretIsNtHash && cmd.indexOf('{{reuse_secret}}') >= 0) {
      if (/\b(?:nxc|netexec|crackmapexec|cme|smbmap|evil-winrm|pywhisker(?:\.py)?|targetedKerberoast(?:\.py)?)\b/i.test(cmd)) {
        cmd = cmd.replace(/(\s)-p\s+(?:'\{\{reuse_secret\}\}'|"\{\{reuse_secret\}\}"|\{\{reuse_secret\}\})/g, "$1-H '{{reuse_secret}}'");
      }
    }
    cmd = cmd.replace(/\{\{([a-zA-Z0-9_]+)(?:\|((?:\{\{[a-zA-Z0-9_]+\}\}|[^{}])*))?\}\}/g, function (placeholder, key, defVal, offset) {
      var value = ctx[key];
      if ((key === 'target_sam' || key === 'victim') && value && /\b(?:setuserinfo2|net\s+rpc\s+password|Set-ADAccountPassword|bloodyAD\b[^\r\n]*\bset\s+password)\b/i.test(cmd)) {
        var vl = String(value).trim().toLowerCase();
        var isGrp = vl.indexOf(' ') >= 0 || /^(?:domain admins|enterprise admins|administrators|exchange windows permissions|account operators|organization management|backup operators|server operators|dnsadmins|print operators|group policy creator owners|key admins|enterprise key admins)$/.test(vl);
        if (isGrp) value = ctx.target_user || 'Administrator';
      }
      if (key === 'domain' && ctx.auth_realm && ctx.user) {
        var before = cmd.slice(0, offset), after = cmd.slice(offset + placeholder.length);
        var principalRealm = /\{\{(?:user|username)\}\}@['"]?$/.test(before) || /^(?:\/|\\+)\{\{(?:user|username)\}\}/.test(after);
        var authFlag = /(?:^|\s)(?:-d|--domain|-domain)\s+['"]?$/.test(before)
          && /\b(?:nxc|netexec|crackmapexec|smbmap|smbclient|rpcclient)\b/.test(cmd);
        if (principalRealm || authFlag) value = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(ctx.auth_realm)) ? '.' : ctx.auth_realm;
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
  var _arsenalRaw = null;
  var _arsenalParsed = null;
  function _arsenalProfile() {
    try {
      var raw = typeof localStorage !== 'undefined' ? localStorage.getItem('obol.arsenal-profile') : null;
      if (!raw) { _arsenalRaw = null; _arsenalParsed = null; return null; }
      if (raw === _arsenalRaw) return _arsenalParsed;
      _arsenalRaw = raw;
      _arsenalParsed = JSON.parse(raw);
      return _arsenalParsed;
    } catch (e) { return null; }
  }
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
      var uniqPy = {};
      pyVariants.forEach(function (x) {
        var xl = x.toLowerCase();
        if (xl !== 'poc.py' && xl !== 'exploit.py') uniqPy[xl] = 1;
      });
      var multiPyRepo = Object.keys(uniqPy).length > 1;
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
    if (!fillOpts.context && facts && facts.forAction) fillOpts.context = facts.forAction(action, c)._resolvedContext;
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
  var _actSigCache = typeof WeakMap !== 'undefined' ? new WeakMap() : null;
  function _paramsSigKey(params) {
    if (!params) return '';
    return [
      params.target || '', params.domain || '', params.username || '', params.user || '',
      params.password || '', params.nthash || '', params.lhost || '', params.lport || '', params.rhost || ''
    ].join('\x00').toLowerCase();
  }
  function _activitySigs(activities, params) {
    if (!Array.isArray(activities) || !activities.length) return [];
    var pKey = _paramsSigKey(params);
    var hit = _actSigCache ? _actSigCache.get(activities) : null;
    if (hit && hit.pKey === pKey && hit.refs.length === activities.length) {
      var same = true;
      for (var c = 0; c < activities.length; c++) {
        var cur = activities[c] || {};
        if (hit.refs[c] !== activities[c] || hit.cmds[c] !== (cur.command || '') || hit.disps[c] !== (cur.dispatch || '')) {
          same = false;
          break;
        }
      }
      if (same) return hit.sigs;
    }
    var sigs = [], refs = new Array(activities.length), cmds = new Array(activities.length), disps = new Array(activities.length);
    for (var a = 0; a < activities.length; a++) {
      var act = activities[a] || {};
      refs[a] = activities[a];
      cmds[a] = act.command || '';
      disps[a] = act.dispatch || '';
      // Match the honest command OR the recovered dispatch label, an ATTACHED dump has no typed command,
      // so obol's recovered routing signature is the only record of what actually ran.
      if (act.command) sigs.push(_actionSig(act.command, params));
      if (act.dispatch && act.dispatch !== act.command) sigs.push(_actionSig(act.dispatch, params));
      if (Array.isArray(act.sequenceCommands)) {
        for (var s = 0; s < act.sequenceCommands.length; s++) {
          if (act.sequenceCommands[s]) sigs.push(_actionSig(act.sequenceCommands[s], params));
        }
      }
    }
    if (_actSigCache) {
      _actSigCache.set(activities, { pKey: pKey, refs: refs, cmds: cmds, disps: disps, sigs: sigs });
    }
    return sigs;
  }

  // Has a command with these same action tokens already been run (is it in the activity ledger)? Used by
  // the coach to demote a suggested variant you have already executed, so it stops re-offering it.
  function commandWasRun(filledCmd, activities, params) {
    if (!filledCmd || !Array.isArray(activities) || !activities.length) return false;
    var sig = _actionSig(filledCmd, params), keys = Object.keys(sig);
    // Only DISTINCTIVE commands are confidently "already run": a verb+object enumeration or grant has 3+
    // action tokens (`bloodyad get writable`, `nxc ldap --users`, `bloodyad add dcsync`). A generic
    // tool+mode invocation, `nxc smb` (validate), `evil-winrm`, `impacket-psexec`, `certipy find`, is a
    // re-runnable check/shell that recurs across many moves; marking it run is high-confusion, low-value,
    // and is exactly what wrongly flagged an UNRUN `nxc smb` as ran. Bias to under-marking: re-suggesting
    // a command is a mild annoyance, wrongly hiding one you still need is the failure that keeps biting.
    if (keys.length < 3) return false;
    var sigs = _activitySigs(activities, params);
    for (var i = 0; i < sigs.length; i++) {
      var asig = sigs[i], match = true;
      for (var k = 0; k < keys.length; k++) {
        if (!asig[keys[k]]) { match = false; break; }
      }
      if (match) return true;
    }
    return false;
  }

  function commandRanExactOrSig(filledCmd, activities, params, target) {
    if (!filledCmd || !Array.isArray(activities) || !activities.length) return false;
    var cf = _canonCmd(filledCmd);
    if (cf) {
      for (var i = 0; i < activities.length; i++) {
        var act = activities[i] || {};
        if (target) {
          var actTgt = act.target || (/^host:/.test(act.scope || '') ? act.scope.slice(5) : '');
          if (actTgt && actTgt !== target) continue;
        }
        if (act.command && _canonCmd(act.command) === cf) return true;
        if (Array.isArray(act.sequenceCommands)) {
          for (var j = 0; j < act.sequenceCommands.length; j++) {
            if (_canonCmd(act.sequenceCommands[j]) === cf) return true;
          }
        }
      }
    }
    return commandWasRun(filledCmd, activities, params);
  }

  // Which {{tokens}} in a template are still unfilled (dependencies the operator must supply).
  function unfilledTokens(filledText) {
    var out = [], re = /\{\{([a-zA-Z0-9_]+)\}\}/g, m;
    while ((m = re.exec(filledText)) !== null) { if (out.indexOf(m[1]) === -1) out.push(m[1]); }
    return out;
  }

  var EARNED_TOKENS = {
    domain: 1, basedn: 1, dc: 1, dc_netbios: 1, dc_account: 1, user: 1, password: 1,
    nthash: 1, userlist: 1, hashfile: 1, domain_sid: 1, target_sam: 1, group: 1, abuse_groups_quoted: 1, ca_name: 1, template: 1,
    pfx: 1, nmap_ports: 1, krbtgt_hash: 1, dahash: 1, dauser: 1, flag_path_local: 1, flag_smb_path_local: 1, flag_path_root: 1, share: 1, cpassword: 1,
    edb_id: 1, edb_file: 1, edb_path: 1, custom_bin: 1, source_path: 1, app_base_path: 1, ssh_key_path: 1, reuse_user: 1, reuse_secret: 1
  };

  function _normCmd(s) {
    return String(s || '').trim().replace(/\s+/g, ' ');
  }

  function primaryBinary(cmdStr) {
    var m = String(cmdStr || '').trim().match(/^(?:sudo\s+)?(\S+)/);
    return m ? m[1].replace(/^.*[\\/]/, '') : '';
  }

  function _canonCmd(s) {
    return _normCmd(s)
      .replace(/^\S+/, function (t) { return t.toLowerCase(); })
      .replace(/\s*\|\s*tee\s+\S+\s*$/i, '')
      .replace(/'([A-Za-z0-9_@%+=:,./-]+)'/g, '$1')
      .replace(/"([A-Za-z0-9_@%+=:,./-]+)"/g, '$1')
      .replace(/\s+--detail\b/g, '');
  }

  function _privEpoch(e) {
    if (!e) return '';
    return String(e).replace(/(?:^|\|)h:[^|]*/g, '') || 'anon';
  }

  function commandTriedInEpoch(action, cmdObj, filledStr, activities, epoch, target, resolvedContext) {
    if (!action || !cmdObj || !Array.isArray(activities) || !activities.length) return false;
    var rawRun = _normCmd(cmdObj.run);
    var filledCmd = _normCmd(filledStr);
    var canonFilled = _canonCmd(filledCmd || rawRun);
    var privEp = _privEpoch(epoch);
    var isDistinctive = Object.keys(_actionSig(rawRun, {})).length >= 3;
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
    var currentContext = resolvedContext;
    if (!currentContext && action.resolvedContext && action.resolvedContext.target === target) currentContext = action.resolvedContext.facts.forAction(action, cmdObj)._resolvedContext;
    if (!currentContext && OBOL.context && OBOL.store && OBOL.store.active) currentContext = OBOL.context.resolve({engagement:OBOL.store.active(),target:target,command:filledStr || rawRun,actionId:action.id,locus:OBOL.pack && OBOL.pack.commandExecutionLocus ? OBOL.pack.commandExecutionLocus(cmdObj) : 'remote'});
    for (var a = 0; a < activities.length; a++) {
      var act = activities[a];
      if (!act) continue;
      var sameAction = (act.action_id || act.actionId) === action.id;
      if (!sameAction && !isDistinctive) continue;
      var actTarget = act.target || (/^host:/.test(act.scope || '') ? act.scope.slice(5) : '');
      if (target && actTarget !== target) continue;
      if (privEp && act.epoch && _privEpoch(act.epoch) !== privEp) continue;
      if (act.outcome && !act.outcome.retireCommand) {
        if (act.outcome.kind === 'success' && /(?:^|\s)--host\b/i.test(act.command || '') && OBOL && OBOL.outcomes && OBOL.outcomes.completion) {
          var comp = OBOL.outcomes.completion(act.stdout || '', act.command);
          if (comp && comp.complete) { act.outcome.conclusive = true; act.outcome.retireCommand = true; }
        }
        if (!act.outcome.retireCommand) continue;
      }
      if (currentContext) {
        var previousContext = act.context || (act.outcome && act.outcome.context);
        if (!previousContext) continue;
        if ((previousContext.credentialId || null) !== currentContext.credentialId || (previousContext.service || '') !== currentContext.service || (previousContext.locus || 'remote') !== currentContext.locus) continue;
      }
      var ac = _normCmd(act.command);
      if (ac && (ac === rawRun || (filledCmd && ac === filledCmd) || (canonFilled && _canonCmd(ac) === canonFilled))) return true;
      if (Array.isArray(act.sequenceCommands)) {
        for (var scIdx = 0; scIdx < act.sequenceCommands.length; scIdx++) {
          var scNorm = _normCmd(act.sequenceCommands[scIdx]);
          if (scNorm && (scNorm === rawRun || (filledCmd && scNorm === filledCmd) || (canonFilled && _canonCmd(scNorm) === canonFilled))) return true;
        }
      }
      var ad = _normCmd(act.dispatch);
      if (filledCmd && ad && ad.indexOf(filledCmd) >= 0) return true;
      if (sameAction) {
        var actTool = String(act.tool || primaryBinary(ac) || '').toLowerCase().replace(/\.(py|exe)$/, '');
        if (!currentContext && cmdTool && actTool === cmdTool && (!ac || sameToolCount === 1 || isFlagHuntSession)) return true;
      }
    }
    return false;
  }

  function moveDryTriesInEpoch(action, facts, eng, epoch, target) {
    if (!action || !eng || !Array.isArray(eng.activities) || !eng.activities.length) return 0;
    var acts = eng.activities;
    var curEpoch = epoch || ((root.OBOL && root.OBOL.pack && root.OBOL.pack.accessEpoch && facts) ? root.OBOL.pack.accessEpoch(facts) : '');
    var privEp = _privEpoch(curEpoch);
    var tgt = target || action.contextTarget || (eng.params && eng.params.target) || '';
    // `eng.activities` is stored newest-first (`unshift`), so index 0 is the most recent paste.
    // Find the most recent productive (addedCount > 0) or active-blocker paste on this action;
    // only dry attempts MORE RECENT than that (`0 <= m < firstProductiveIdx`) count as current dry tries.
    function _actAddedFacts(a) {
      if (typeof a.addedCount === 'number') return a.addedCount > 0;
      return Array.isArray(a.produced) && a.produced.some(function (p) { return p && !/^blocker\./.test(p); });
    }
    var firstProductiveIdx = acts.length;
    for (var k = 0; k < acts.length; k++) {
      var ak = acts[k];
      if (!ak || (ak.action_id || ak.actionId) !== action.id) continue;
      var akTgt = ak.target || (/^host:/.test(ak.scope || '') ? ak.scope.slice(5) : '');
      if (tgt && akTgt && akTgt !== tgt) continue;
      if (privEp && ak.epoch && _privEpoch(ak.epoch) !== privEp) continue;
      var hasActiveBlocker = Array.isArray(ak.blockers) && ak.blockers.length && facts && typeof facts.has === 'function' &&
        ak.blockers.some(function (b) { return facts.has(b); });
      if (hasActiveBlocker || _actAddedFacts(ak)) {
        firstProductiveIdx = k;
        break;
      }
    }
    var dryActs = [];
    for (var m = 0; m < firstProductiveIdx; m++) {
      var am = acts[m];
      if (!am) continue;
      var amBlocker = Array.isArray(am.blockers) && am.blockers.length && facts && typeof facts.has === 'function' &&
        am.blockers.some(function (b) { return facts.has(b); });
      if (amBlocker || _actAddedFacts(am)) continue;
      dryActs.push(am);
    }
    if (!dryActs.length) return 0;
    var cmds = action.commands || [];
    if (!cmds.length) return 0;
    var commandParams = action.resolvedContext ? action.resolvedContext.params : Object.assign({}, eng.params || {}, tgt ? { target: tgt } : {});
    var wsTokens = (root.OBOL && root.OBOL.workspace && root.OBOL.workspace.tokens) ? root.OBOL.workspace.tokens(eng) : {};
    var filled = fillAll(action, facts, { params: commandParams, profile: eng.profile, workspace: wsTokens });
    var dryCount = 0;
    for (var i = 0; i < cmds.length; i++) {
      var cmd = cmds[i];
      var commandFacts = facts && facts.forAction ? facts.forAction(action, cmd) : facts;
      if (root.OBOL && root.OBOL.pack && root.OBOL.pack.commandSettled && root.OBOL.pack.commandSettled(cmd, commandFacts)) {
        continue;
      }
      var ctx = (commandFacts && commandFacts._resolvedContext) || action.resolvedContext || (facts && facts._resolvedContext);
      if (commandTriedInEpoch(action, cmd, filled[i] && filled[i].filled, dryActs, curEpoch, tgt, ctx)) {
        dryCount++;
      }
    }
    return dryCount;
  }

  function bestCommandIndex(action, facts, opts) {
    if (!action) return 0;
    var commands = action.commands || [];
    if (!commands.length) return 0;
    opts = opts || {};
    var locus = opts.locus || ((root.OBOL && root.OBOL.pack && root.OBOL.pack.defaultCommandLocus) ? root.OBOL.pack.defaultCommandLocus(action, facts) : (action.locus === 'F' || action.locus === 'I' ? 'onhost' : 'remote'));
    var filled = fillAll(action, facts, opts);
    function isGated(cmd, i) {
      var commandFacts = facts && facts.forAction ? facts.forAction(action, cmd) : facts;
      if (action.eligible && commandFacts && !action.eligible(commandFacts)) return true;
      if (OBOL.pack && OBOL.pack.commandIsEligible && !OBOL.pack.commandIsEligible(cmd, commandFacts, action)) return true;
      if (!filled[i]) return false;
      if (filled[i].blocked) return true;
      var un = unfilledTokens(filled[i].filled || '');
      return un.some(function (t) { return EARNED_TOKENS[t]; });
    }
    var activeEng = (!Array.isArray(opts.activities) && root.OBOL && root.OBOL.store && typeof root.OBOL.store.active === 'function') ? root.OBOL.store.active() : null;
    var acts = (Array.isArray(opts.activities) && opts.activities.length) ? opts.activities : (activeEng && Array.isArray(activeEng.activities) && activeEng.activities.length ? activeEng.activities : null);
    var curEpoch = opts.epoch || ((root.OBOL && root.OBOL.pack && root.OBOL.pack.accessEpoch && facts) ? root.OBOL.pack.accessEpoch(facts) : '');
    var triedFn = acts ? function (cmd, i) {
      var commandFacts = (facts && facts.forAction) ? facts.forAction(action, cmd) : facts;
      var ctx = (commandFacts && commandFacts._resolvedContext) || action.resolvedContext || (facts && facts._resolvedContext) || null;
      var tgt = (opts.params && opts.params.target) || action.contextTarget || (ctx && ctx.target) || ((root.OBOL && root.OBOL.store && typeof root.OBOL.store.activeTarget === 'function') ? root.OBOL.store.activeTarget() : '');
      return commandTriedInEpoch(action, cmd, filled[i] && filled[i].filled, acts, curEpoch, tgt, ctx);
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
    commandRanExactOrSig: commandRanExactOrSig,
    unfilledTokens: unfilledTokens,
    commandPortFeasible: commandPortFeasible,
    explainFlags: explainFlags,
    bestCommandIndex: bestCommandIndex,
    commandTriedInEpoch: commandTriedInEpoch,
    moveDryTriesInEpoch: moveDryTriesInEpoch,
    EARNED_TOKENS: EARNED_TOKENS,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);

