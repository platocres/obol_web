/*!
 * obol engine — engmap.js
 * The ENGAGEMENT MAP: a client-side projection of the whole engagement's browser state
 * (targets, facts, scope, credentials, bloodhound) as a tiered node/edge model, rendered
 * to a self-contained inline SVG (tier rows top→down, bezier edges, node classes by
 * type/access so the active skin themes it).
 *
 * Faithful JS port of obol-local/obol/graph.py build_engagement_graph (+ target_access_level).
 * Conservative: NEVER invents a host-to-host edge from a shared subnet — a target hangs from a
 * scope range only where CIDR/IP membership proves it, from a domain only where an identity/DC
 * fact ties it, and a credential links to a host only where a host-scoped fact ties them.
 *
 * Pure / Node-safe: attaches to `self` (window or Web Worker) and runs unchanged under Node
 * (`node tests/engine/engmap-smoke.js`). Depends only on OBOL.facts and OBOL.phases.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function nid(s) { return String(s).replace(/[^a-zA-Z0-9_]/g, '_'); }
  function slug(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''); }

  // ── port / service labelling (mirrors graph.py's tables) ─────────────────────────────────
  var PORT_LABELS = {
    21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    88: 'Kerberos', 135: 'RPC', 139: 'NetBIOS', 389: 'LDAP',
    443: 'HTTPS', 445: 'SMB', 464: 'Kerberos', 636: 'LDAPS',
    3268: 'GC LDAP', 3269: 'GC LDAPS', 3389: 'RDP',
    5985: 'WinRM', 5986: 'WinRM SSL', 8000: 'HTTP', 8080: 'HTTP', 8443: 'HTTPS',
  };
  var SERVICE_ALIASES = {
    'microsoft-ds': 'SMB', 'netbios-ssn': 'SMB', 'ldap': 'LDAP',
    'kerberos-sec': 'Kerberos', 'domain': 'DNS', 'http': 'HTTP',
    'https': 'HTTPS', 'ssl-http': 'HTTPS', 'ms-wbt-server': 'RDP',
    'wsman': 'WinRM', 'winrm': 'WinRM',
  };
  var REACHABLE_LABELS = {
    'ldap.reachable': 'LDAP', 'smb.reachable': 'SMB', 'kerberos.reachable': 'Kerberos',
    'winrm.reachable': 'WinRM', 'http.reachable': 'HTTP',
  };

  function titleCase(s) {
    return String(s).replace(/-/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  // The port a fact concerns: value.port, else parsed from a "port:<n>" kind.
  function portOf(kind, value) {
    var p = value && value.port;
    var n = parseInt(p, 10);
    if (!isNaN(n) && n > 0) return n;
    var m = /^port:(\d+)$/.exec(kind || '');
    return m ? parseInt(m[1], 10) : 0;
  }

  function serviceLabel(kind, value) {
    if (REACHABLE_LABELS[kind]) return REACHABLE_LABELS[kind];
    var service = String((value && value.service) || '').toLowerCase();
    if (service) return SERVICE_ALIASES[service] || titleCase(service);
    var port = portOf(kind, value);
    if (port) return PORT_LABELS[port] || ('Port ' + port);
    if (kind && kind.indexOf('service.') === 0) {
      var raw = kind.split('.').slice(1).join('.');
      return SERVICE_ALIASES[raw] || titleCase(raw);
    }
    return '';
  }

  // One service row per distinct (label, port, proto) among a host's port:* / service.* / *.reachable facts.
  function hostServices(factset) {
    var seen = {}, out = [];
    factset.facts.forEach(function (f) {
      if (!(f.kind.indexOf('port:') === 0 || f.kind.indexOf('service.') === 0 || REACHABLE_LABELS[f.kind])) return;
      if (f.state !== 'supported') return;
      var value = f.value || {};
      var port = portOf(f.kind, value);
      var proto = value.protocol || (port ? 'tcp' : '');
      var label = serviceLabel(f.kind, value);
      if (!label) return;
      var key = label.toLowerCase() + '|' + port + '|' + proto;
      if (seen[key]) return;
      seen[key] = true;
      var row = { label: label, port: port, protocol: proto, kind: f.kind };
      if (value.version) row.version = value.version;
      out.push(row);
    });
    out.sort(function (a, b) {
      return (a.port || 99999) - (b.port || 99999) || a.label.toLowerCase().localeCompare(b.label.toLowerCase());
    });
    return out;
  }

  function hasPort(factset) {
    var wanted = Array.prototype.slice.call(arguments, 1);
    for (var i = 0; i < factset.facts.length; i++) {
      var f = factset.facts[i];
      if (f.state !== 'supported') continue;
      var v = f.value || {};
      if (Array.isArray(v.ports)) {
        for (var j = 0; j < v.ports.length; j++) {
          if (wanted.indexOf(parseInt(v.ports[j], 10)) >= 0) return true;
        }
      }
      var p = portOf(f.kind, v);
      if (p && wanted.indexOf(p) >= 0) return true;
    }
    return false;
  }

  // DC signal (per the map spec): a domain-controller candidate fact, OR the classic DC port
  // triple (Kerberos 88 + LDAP 389 + SMB 445) all present on the host.
  function isDomainController(factset) {
    if (factset.has('ad.dc_candidate')) return true;
    return hasPort(factset, 88) && hasPort(factset, 389) && hasPort(factset, 445);
  }

  // Coarse access level, ported verbatim from graph.py target_access_level.
  function accessLevel(factset) {
    if (factset.has('access.system') || factset.has('access.admin')) return 'privileged';
    if (factset.has('foothold.windows') || factset.has('foothold.linux')
        || factset.has('access.shell') || factset.has('winrm.authenticated')
        || factset.has('foothold.webshell')) return 'foothold';
    if (factset.has('credential.available') || factset.has('credential.candidate')) return 'credentialed';
    for (var i = 0; i < factset.facts.length; i++) {
      var f = factset.facts[i];
      if (f.state === 'supported' && f.kind.indexOf('target.') !== 0 && f.kind.indexOf('host.') !== 0) return 'enumerated';
    }
    return 'discovered';
  }

  function firstValue(factset, kind) {
    var keys = Array.prototype.slice.call(arguments, 2);
    var vals = factset.values(kind);
    for (var i = 0; i < vals.length; i++) {
      for (var k = 0; k < keys.length; k++) {
        if (vals[i][keys[k]]) return String(vals[i][keys[k]]);
      }
    }
    return '';
  }

  function targetIdentity(target, factset) {
    var hostname = target.hostname
      || firstValue(factset, 'host.hostname', 'name', 'hostname')
      || firstValue(factset, 'host.fqdn', 'hostname')
      || firstValue(factset, 'ad.dc_candidate', 'name') || '';
    var fqdn = target.fqdn || firstValue(factset, 'host.fqdn', 'fqdn', 'name') || '';
    var domain = target.domain
      || firstValue(factset, 'host.domain', 'domain', 'name')
      || firstValue(factset, 'host.fqdn', 'domain')
      || firstValue(factset, 'ad.dc_candidate', 'domain') || '';
    return { hostname: hostname, fqdn: fqdn, domain: domain ? String(domain).toLowerCase() : '' };
  }

  // ── IPv4 scope membership (the map's only host↔range test; no subnet reachability inferred) ──
  function ipToInt(ip) {
    var parts = String(ip).trim().split('.');
    if (parts.length !== 4) return null;
    var n = 0;
    for (var i = 0; i < 4; i++) {
      var o = parseInt(parts[i], 10);
      if (isNaN(o) || o < 0 || o > 255 || !/^\d+$/.test(parts[i])) return null;
      n = (n * 256) + o;
    }
    return n >>> 0;
  }
  function targetInScope(host, entry) {
    entry = String(entry || '').trim();
    if (!entry) return false;
    var slash = entry.indexOf('/');
    if (slash >= 0) {
      var base = ipToInt(entry.slice(0, slash));
      var bits = parseInt(entry.slice(slash + 1), 10);
      var addr = ipToInt(host);
      if (base === null || addr === null || isNaN(bits) || bits < 0 || bits > 32) return false;
      if (bits === 0) return true;
      var mask = (0xffffffff << (32 - bits)) >>> 0;
      return (base & mask) === (addr & mask);
    }
    return entry === String(host).trim();
  }

  // ── the model ────────────────────────────────────────────────────────────────────────────
  function buildEngagementGraph(engagement) {
    engagement = engagement || {};
    var F = OBOL.facts;
    var allFacts = new F.FactSet((engagement.facts || []).map(F.factFromJson));
    var targets = engagement.targets || [];
    var scope = (engagement.profile && engagement.profile.scope) || engagement.scope || [];
    var credentials = engagement.credentials || [];
    var bh = engagement.bloodhound || {};

    var nodes = [], edges = [], seenEdges = {};
    function addEdge(from, to, kind) {
      var key = from + '|' + to + '|' + kind;
      if (seenEdges[key]) return;
      seenEdges[key] = true;
      edges.push({ from: from, to: to, kind: kind });
    }

    function hostFactSet(host) {
      var scoped = allFacts.facts.filter(function (f) {
        return f.state === 'supported' && f.scope === ('host:' + host);
      });
      return new F.FactSet(scoped);
    }

    // ── tier 0: domains ──
    var domainIds = {};
    function addDomain(domain) {
      domain = String(domain || '').trim().toLowerCase();
      if (!domain) return '';
      if (!domainIds[domain]) {
        var did = nid('dom_' + domain);
        domainIds[domain] = did;
        nodes.push({ id: did, type: 'domain', tier: 0, label: domain, meta: { domain: domain } });
      }
      return domainIds[domain];
    }
    allFacts.values('ad.domain_known').forEach(function (v) { addDomain(v.name || v.domain || ''); });
    if (bh.domain) addDomain(bh.domain);
    targets.forEach(function (t) { if (t.domain) addDomain(t.domain); });

    // ── tier 0: scope ranges (only entries that aren't themselves a target host) ──
    var scopeIds = {};
    var targetHosts = {};
    targets.forEach(function (t) { if (t.ip) targetHosts[t.ip] = true; });
    scope.forEach(function (entry) {
      entry = String(entry || '').trim();
      if (!entry || targetHosts[entry]) return;
      if (scopeIds[entry]) return;
      var sid = nid('scope_' + entry);
      scopeIds[entry] = sid;
      nodes.push({ id: sid, type: 'scope', tier: 0, label: entry, meta: { scope: entry } });
    });

    // ── tier 2: credentials — one node per distinct (user, domain) ──
    // From credential facts (host-scoped ones tie the cred to that host) and from the engagement's
    // credential list. NEVER glued to a foothold; a host link needs actual evidence.
    var creds = {}; // key -> {user, domain, hosts:{}}
    function credRec(user, domain) {
      user = String(user || '').trim();
      domain = String(domain || '').trim().toLowerCase();
      var key = user.toLowerCase() + '|' + domain;
      if (!creds[key]) creds[key] = { user: user || 'credential', domain: domain, hosts: {} };
      return creds[key];
    }
    allFacts.facts.forEach(function (f) {
      if ((f.kind !== 'credential.available' && f.kind !== 'credential.plaintext') || f.state !== 'supported') return;
      var v = f.value || {};
      var rec = credRec(v.user, v.domain);
      if (f.scope && f.scope.indexOf('host:') === 0) rec.hosts[f.scope.slice(5)] = true;
    });
    credentials.forEach(function (c) {
      if (!c || (!c.user && !c.username)) return;
      credRec(c.user || c.username, c.domain);
    });

    var credIds = {};
    Object.keys(creds).forEach(function (key) {
      var rec = creds[key];
      var cid = nid('cred_' + rec.user + '_' + rec.domain);
      credIds[key] = cid;
      nodes.push({ id: cid, type: 'credential', tier: 2,
        label: 'cred: ' + rec.user, meta: { user: rec.user, domain: rec.domain } });
      if (rec.domain) addEdge(addDomain(rec.domain), cid, 'credential');
    });

    // ── tier 1: targets, and their tier-2 services ──
    targets.forEach(function (t) {
      var host = t.ip;
      if (!host) return;
      var tf = hostFactSet(host);
      var identity = targetIdentity(t, tf);
      var services = hostServices(tf).slice(0, 8);
      var level = accessLevel(tf);
      var dc = isDomainController(tf);
      var tid = nid('tgt_' + host);
      var phase = (OBOL.phases && OBOL.phases.targetPhase) ? OBOL.phases.targetPhase(tf) : '';
      nodes.push({
        id: tid, type: 'target', tier: 1,
        label: t.hostname || t.label || host,
        meta: {
          host: host, ip: host, access: level, phase: phase, os: t.os || '', dc: dc,
          hostname: identity.hostname, fqdn: identity.fqdn, domain: identity.domain,
          services: services, service_count: services.length,
        },
      });

      var did = addDomain(identity.domain);
      if (did) addEdge(did, tid, dc ? 'domain-controller' : 'domain-service');

      Object.keys(scopeIds).forEach(function (entry) {
        if (targetInScope(host, entry)) addEdge(scopeIds[entry], tid, 'in-scope');
      });

      services.forEach(function (svc) {
        var port = svc.port || 0;
        var proto = svc.protocol || '';
        var sid = nid('svc_' + host + '_' + svc.label + '_' + port + '_' + proto);
        var label = port ? (svc.label + ' ' + port) : svc.label;
        nodes.push({ id: sid, type: 'service', tier: 2, label: label,
          meta: Object.assign({ host: host }, svc) });
        addEdge(tid, sid, 'exposes');
      });

      // credential → this host only where a host-scoped fact tied them
      Object.keys(credIds).forEach(function (key) {
        if (creds[key].hosts[host]) addEdge(credIds[key], tid, 'authenticates');
      });
    });

    // ── BloodHound overlay: high-value groups + roastable principals + attack paths ──
    if (bh.domain || (bh.computers && bh.computers.length) || (bh.domain_admins && bh.domain_admins.length)) {
      var domId = addDomain(bh.domain || '') || (Object.keys(domainIds).length ? domainIds[Object.keys(domainIds)[0]] : '');
      [['domain_admins', 'Domain Admins'], ['enterprise_admins', 'Enterprise Admins']].forEach(function (pair) {
        var members = bh[pair[0]] || [];
        if (!members.length) return;
        var gid = nid('bh_' + pair[0]);
        nodes.push({ id: gid, type: 'highvalue', tier: 2,
          label: pair[1] + ' (' + members.length + ')', meta: { members: members.slice(0, 40) } });
        if (domId) addEdge(domId, gid, 'controls');
      });
      [['kerberoastable', 'Kerberoastable'], ['asrep_roastable', 'AS-REP-roastable']].forEach(function (pair) {
        var items = bh[pair[0]] || [];
        if (!items.length) return;
        var kid = nid('bh_' + pair[0]);
        nodes.push({ id: kid, type: 'roastable', tier: 3,
          label: pair[1] + ' (' + items.length + ')', meta: { items: items.slice(0, 40) } });
        if (domId) addEdge(domId, kid, pair[0]);
      });
    }

    // ── §38 attack path chains to Domain Admins (drawn hop-by-hop) ──
    var apIds = {};
    function apNode(label) {
      var key = String(label).toLowerCase();
      if (!apIds[key]) {
        var id = nid('ap_' + label);
        apIds[key] = id;
        nodes.push({ id: id, type: 'attackpath', tier: 2, label: label, meta: { attack_path: true } });
      }
      return apIds[key];
    }
    allFacts.values('ad.attack_paths').forEach(function (v) {
      var chains = v.paths || (v.path ? [v.path] : []);
      chains.forEach(function (hops) {
        (hops || []).forEach(function (h) {
          var frm = String(h.from || ''), to = String(h.to || '');
          if (frm && to) addEdge(apNode(frm), apNode(to), h.edge || '');
        });
      });
    });

    return { nodes: nodes, edges: edges };
  }

  // ── SVG renderer ─────────────────────────────────────────────────────────────────────────
  var NW = 156, NH = 44, COLW = 182, ROWH = 116, PADX = 26, PADY = 34, LEFT = 96;
  var TIER_LABELS = { 0: 'SCOPE / DOMAINS', 1: 'TARGETS', 2: 'SERVICES / CREDS', 3: 'FINDINGS' };

  function trunc(label, limit) {
    limit = limit || 22;
    return label.length <= limit ? label : label.slice(0, limit - 1).replace(/\s+$/, '') + '…';
  }

  function buildEngagementSvg(engagement) {
    var model = buildEngagementGraph(engagement);
    if (!model.nodes.length) {
      return '<svg viewBox="0 0 360 60" width="360" height="60" xmlns="http://www.w3.org/2000/svg" class="obol-engmap">'
        + '<text x="12" y="34" class="em-empty" font-size="13">No engagement map yet — add a target or paste a scan.</text></svg>';
    }
    // group nodes by tier, preserving insertion order within a tier
    var byTier = {};
    model.nodes.forEach(function (n) { (byTier[n.tier] = byTier[n.tier] || []).push(n); });
    var tiers = Object.keys(byTier).map(Number).sort(function (a, b) { return a - b; });
    var maxCount = Math.max.apply(null, tiers.map(function (t) { return byTier[t].length; }));
    var contentW = maxCount * COLW;
    var width = LEFT + contentW + PADX;
    var height = PADY + tiers.length * ROWH + PADY;

    var pos = {};
    tiers.forEach(function (t, ti) {
      var rowNodes = byTier[t];
      var y = PADY + ti * ROWH;
      var offset = (contentW - rowNodes.length * COLW) / 2;
      rowNodes.forEach(function (n, ci) {
        var x = LEFT + offset + ci * COLW + (COLW - NW) / 2;
        pos[n.id] = { x: x, y: y, cx: x + NW / 2, cy: y + NH / 2, node: n };
      });
    });

    // tier row labels
    var rowLabels = tiers.map(function (t, ti) {
      var y = PADY + ti * ROWH + NH / 2 + 4;
      return '<text x="8" y="' + y + '" class="em-tier-label" font-size="10" font-weight="700" letter-spacing="1">'
        + esc(TIER_LABELS[t] || ('TIER ' + t)) + '</text>';
    }).join('');

    // edges (bezier); vertical between tiers, horizontal within a tier
    var edgeSvg = model.edges.map(function (e) {
      var a = pos[e.from], b = pos[e.to];
      if (!a || !b) return '';
      var x1, y1, x2, y2, d;
      if (a.cy === b.cy) {
        var rightward = b.cx > a.cx;
        x1 = rightward ? a.x + NW : a.x; y1 = a.cy;
        x2 = rightward ? b.x : b.x + NW; y2 = b.cy;
        var mx = (x1 + x2) / 2;
        d = 'M' + x1 + ',' + y1 + ' C' + mx + ',' + y1 + ' ' + mx + ',' + y2 + ' ' + x2 + ',' + y2;
      } else {
        var down = b.cy > a.cy;
        x1 = a.cx; y1 = down ? a.y + NH : a.y;
        x2 = b.cx; y2 = down ? b.y : b.y + NH;
        var my = (y1 + y2) / 2;
        d = 'M' + x1 + ',' + y1 + ' C' + x1 + ',' + my + ' ' + x2 + ',' + my + ' ' + x2 + ',' + y2;
      }
      var cls = 'em-edge' + (e.kind ? ' em-edge-' + slug(e.kind) : '');
      return '<path d="' + d + '" fill="none" class="' + cls + '" data-from="' + esc(e.from) + '" data-to="' + esc(e.to) + '"/>';
    }).join('');

    // nodes
    var nodeSvg = model.nodes.map(function (n) {
      var m = pos[n.id];
      if (!m) return '';
      var meta = n.meta || {};
      var cls = 'em-node em-' + n.type;
      var extra = '';
      if (n.type === 'target') {
        cls += ' em-acc-' + (meta.access || 'discovered');
        if (meta.dc) cls += ' em-dc';
        extra = ' data-ip="' + esc(meta.ip || meta.host || '') + '"';
      }
      var rx = (n.type === 'target' || n.type === 'domain') ? 8 : 6;
      var cx = m.cx;
      var main = '<text x="' + cx + '" y="' + (m.y + (n.type === 'target' ? NH / 2 - 2 : NH / 2 + 4))
        + '" text-anchor="middle" class="em-label" font-size="12">'
        + '<title>' + esc(n.label) + (meta.fqdn ? ' — ' + esc(meta.fqdn) : '') + '</title>'
        + esc(trunc(n.label)) + '</text>';
      var sub = '';
      if (n.type === 'target') {
        var tag = (meta.dc ? 'DC · ' : '') + (meta.access || '');
        sub = '<text x="' + cx + '" y="' + (m.y + NH / 2 + 12) + '" text-anchor="middle" class="em-sub" font-size="9">'
          + esc(tag) + '</text>';
      }
      return '<g class="' + cls + '" data-node-id="' + esc(n.id) + '"' + extra + '>'
        + '<rect x="' + m.x + '" y="' + m.y + '" width="' + NW + '" height="' + NH + '" rx="' + rx + '"/>'
        + main + sub + '</g>';
    }).join('');

    return '<svg viewBox="0 0 ' + width + ' ' + height + '" width="' + width + '" height="' + height + '" '
      + 'preserveAspectRatio="xMinYMin meet" xmlns="http://www.w3.org/2000/svg" class="obol-engmap" '
      + 'font-family="system-ui,sans-serif">' + rowLabels + edgeSvg + nodeSvg + '</svg>';
  }

  OBOL.engmap = {
    buildEngagementGraph: buildEngagementGraph,
    buildEngagementSvg: buildEngagementSvg,
    // exposed for tests / reuse
    accessLevel: accessLevel,
    isDomainController: isDomainController,
    targetInScope: targetInScope,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
