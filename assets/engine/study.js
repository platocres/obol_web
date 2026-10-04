/*!
 * obol engine — study.js
 * Study mode's engine half. Pure functions over the loaded packs (OBOL.packs.actions()) + ARSENAL +
 * the embedded sample-output map (OBOL.STUDY_FIXTURES).
 *
 * The conditional "study cell" is DERIVED, not hand-authored: every field maps to data the move
 * already carries — hypothesis / requires_* / produces / does_not_prove / commands[].note / refs —
 * plus two graph walks (what mints my prereqs, what my output opens). The one non-pack piece is the
 * sample output (OBOL.STUDY_FIXTURES), since a static site can't read test fixtures at runtime.
 *
 * Command variants are ordered REMOTE-FIRST (remote → offline → on-target), derived from each tool's
 * ARSENAL os/class — never hand-ranked. Prefer the option that needs the least access to the box.
 *
 * Lanes are guided teaching paths (ordered move lists). A move can appear in one lane.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // --- the lanes: ordered teaching paths through the methodology ------------------------------
  var LANES = {
    recon: {
      key: 'recon', name: 'Recon & Foothold', short: 'Recon',
      desc: 'Map the attack surface — find the open ports, the services behind them, and the first way in.',
      nodes: [
        { id: 'nmap-fast-open-ports', phase: 'Scan' },
        { id: 'nmap-version-scripts', phase: 'Scan' },
        { id: 'recon-smb-anon', phase: 'Enumerate' },
        { id: 'recon-web-triage', phase: 'Enumerate' },
      ],
    },
    ad: {
      key: 'ad', name: 'Active Directory', short: 'AD',
      desc: 'From an anonymous foothold to owning the domain — enumerate, roast, crack, abuse ACLs, DCSync.',
      nodes: [
        { id: 'ad-dc-identify', phase: 'Recon' },
        { id: 'ad-anon-ldap-enum', phase: 'Recon' },
        { id: 'asrep-roast', phase: 'Credentials' },
        { id: 'crack-asrep', phase: 'Credentials' },
        { id: 'password-spray', phase: 'Credentials' },
        { id: 'ad-acl-abuse', phase: 'Escalate' },
        { id: 'dcsync', phase: 'Domain' },
      ],
    },
    web: {
      key: 'web', name: 'Web Exploitation', short: 'Web',
      desc: 'Turn a web app into a shell — map it, find the injectable edge, and land code execution.',
      nodes: [
        { id: 'content-discovery', phase: 'Discover' },
        { id: 'param-discovery', phase: 'Discover' },
        { id: 'lfi-probe', phase: 'Exploit' },
        { id: 'file-upload', phase: 'Exploit' },
        { id: 'web-shells', phase: 'Foothold' },
      ],
    },
    linux: {
      key: 'linux', name: 'Linux Privesc', short: 'Linux',
      desc: 'From a low-priv shell to root — enumerate, then abuse sudo, SUID, cron, and capabilities.',
      nodes: [
        { id: 'linux-enum', phase: 'Enumerate' },
        { id: 'sudo-abuse', phase: 'Escalate' },
        { id: 'suid-gtfobins', phase: 'Escalate' },
        { id: 'pspy-monitor', phase: 'Enumerate' },
        { id: 'cron-abuse', phase: 'Escalate' },
      ],
    },
    windows: {
      key: 'windows', name: 'Windows Privesc', short: 'Windows',
      desc: 'From a foothold to SYSTEM — enumerate, then abuse privileges, services, and installers.',
      nodes: [
        { id: 'windows-enum', phase: 'Enumerate' },
        { id: 'seimpersonate', phase: 'Escalate' },
        { id: 'unquoted-service-path', phase: 'Escalate' },
        { id: 'weak-service-permissions', phase: 'Escalate' },
        { id: 'alwaysinstallelevated', phase: 'Escalate' },
      ],
    },
  };
  var LANE_ORDER = ['recon', 'ad', 'web', 'linux', 'windows'];

  function allMoves() { try { return (OBOL.packs && OBOL.packs.actions()) || []; } catch (e) { return []; } }
  function arsenal() { return OBOL.ARSENAL || {}; }
  function fixtures() { return OBOL.STUDY_FIXTURES || {}; }
  function byId(id) { var a = allMoves(); for (var i = 0; i < a.length; i++) if (a[i].id === id) return a[i]; return null; }
  function reqSet(m) { return [].concat(m.requires_all || [], m.requires_any || []); }

  function laneOf(moveId) {
    for (var k = 0; k < LANE_ORDER.length; k++) {
      var L = LANES[LANE_ORDER[k]];
      for (var i = 0; i < L.nodes.length; i++) if (L.nodes[i].id === moveId) return L;
    }
    return null;
  }
  function laneEntry(moveId) {
    var L = laneOf(moveId); if (!L) return null;
    for (var i = 0; i < L.nodes.length; i++) if (L.nodes[i].id === moveId) return { id: moveId, phase: L.nodes[i].phase, laneKey: L.key };
    return null;
  }

  // --- per-command locus: remote(0) < offline(1) < on-target(2) --------------------------------
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

  function applyProfile(run, tool, profile) {
    if (!profile || !tool || !profile.tools) return run;
    var p = profile.tools[tool] || profile.tools[tool.toLowerCase()];
    if (!p || !p.invocation || p.present === false) return run;
    return run.replace(new RegExp('^\\s*' + tool.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), p.invocation);
  }

  // --- the derived conditional cell ------------------------------------------------------------
  function cellFor(moveId, opts) {
    opts = opts || {};
    var m = byId(moveId); if (!m) return null;
    var reqs = reqSet(m), profile = opts.profile || null, entry = laneEntry(moveId) || {};

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
      id: m.id, title: m.title, phase: entry.phase || '', laneKey: entry.laneKey || '',
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

  // --- lanes as graph nodes + derived edges ----------------------------------------------------
  function lane(laneKey) {
    var L = LANES[laneKey]; if (!L) return [];
    return L.nodes.map(function (e) {
      var m = byId(e.id);
      return { id: e.id, phase: e.phase, laneKey: laneKey, title: m ? m.title : e.id, proves: m ? (m.produces || []) : [], reqs: m ? reqSet(m) : [] };
    });
  }
  function laneEdges(laneKey) {
    var N = lane(laneKey), edges = [];
    N.forEach(function (a, ai) {
      N.forEach(function (b, bi) {
        if (bi <= ai) return;
        if (a.proves.some(function (p) { return b.reqs.indexOf(p) >= 0; })) edges.push({ from: a.id, to: b.id });
      });
    });
    return edges;
  }
  function lanes() {
    return LANE_ORDER.map(function (k) { var L = LANES[k]; return { key: k, name: L.name, short: L.short, desc: L.desc, count: L.nodes.length, firstId: L.nodes[0].id }; });
  }
  function laneNext(moveId) {
    var L = laneOf(moveId); if (!L) return null;
    for (var i = 0; i < L.nodes.length - 1; i++) if (L.nodes[i].id === moveId) return L.nodes[i + 1].id;
    return null;
  }

  // strip a leading shell prompt so an echoed command line can be compared to the played command
  function stripPrompt(s) { return String(s || '').replace(/^\s*(kali\$|root@[^\s#]*[#$]|C:\\[^>]*>|[#$])\s*/, '').trim(); }

  // --- replay script (Watch) -------------------------------------------------------------------
  function replayFor(moveId) {
    var cell = cellFor(moveId); if (!cell) return null;
    var primary = cell.commands[0] || null;
    var cmd = primary ? primary.run : '';
    var lines = cell.output ? cell.output.text.split('\n') : [];
    // the replay already types the command as its prompt line — drop a first output line that just
    // echoes that same command, so it isn't shown twice.
    if (lines.length && cmd && stripPrompt(lines[0]) === stripPrompt(cmd)) lines = lines.slice(1);
    return {
      id: cell.id, title: cell.title, phase: cell.phase, laneKey: cell.laneKey,
      tool: primary ? primary.tool : '', locus: primary ? primary.locus : '', tag: primary ? primary.tag : '',
      command: cmd, note: primary ? primary.note : '',
      outputLines: lines,
      signal: cell.output ? cell.output.signal : '',
      teach: cell.output ? cell.output.teach : '',
      proves: cell.proves,
      opens: (cell.opens[0] || {}).title || '',
      next: laneNext(moveId),
    };
  }

  // --- the atlas: all lanes as one layered graph, with cross-lane bridges ----------------------
  // Hand-curated bridges tell the real story the raw fact-vocabulary doesn't always spell out: how
  // a result in one lane becomes the foothold/seed for another.
  var BRIDGES = [
    { from: 'nmap-version-scripts', to: 'ad-dc-identify', note: 'a Windows/AD host → the AD lane' },
    { from: 'recon-smb-anon', to: 'asrep-roast', note: 'anonymous SMB can leak the user list' },
    { from: 'recon-smb-anon', to: 'password-spray', note: 'a user list to spray' },
    { from: 'recon-web-triage', to: 'content-discovery', note: 'a live web app → map it' },
    { from: 'web-shells', to: 'linux-enum', note: 'a web shell is a Linux foothold' },
    { from: 'web-shells', to: 'windows-enum', note: '…or a Windows foothold' },
  ];
  function atlas() {
    var nodes = [], index = {};
    LANE_ORDER.forEach(function (lk, row) {
      lane(lk).forEach(function (n, col) {
        var node = { id: n.id, title: n.title, lane: lk, phase: n.phase, proves: n.proves, reqs: n.reqs, col: col, row: row };
        nodes.push(node); index[n.id] = node;
      });
    });
    var laneE = [], crossE = [];
    LANE_ORDER.forEach(function (lk) {
      var N = lane(lk);
      for (var i = 1; i < N.length; i++) laneE.push({ from: N[i - 1].id, to: N[i].id });
    });
    BRIDGES.forEach(function (b) { if (index[b.from] && index[b.to]) crossE.push({ from: b.from, to: b.to, note: b.note }); });
    return { nodes: nodes, laneEdges: laneE, crossEdges: crossE, laneOrder: LANE_ORDER, cols: Math.max.apply(null, LANE_ORDER.map(function (k) { return LANES[k].nodes.length; })) };
  }

  // --- "Your turn" practice --------------------------------------------------------------------
  // Facts in hand at a lane node: its own prereqs + everything earlier lane nodes produced.
  function factsInHandAt(moveId) {
    var have = {}, m = byId(moveId), L = laneOf(moveId);
    if (m) reqSet(m).forEach(function (k) { have[k] = 1; });
    if (L) for (var i = 0; i < L.nodes.length; i++) {
      if (L.nodes[i].id === moveId) break;
      var pm = byId(L.nodes[i].id);
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
        var all = d.requires_all || [], any = d.requires_any || [];
        var allMet = all.every(function (r) { return have.indexOf(r) >= 0; });
        var anyMet = any.length === 0 || any.some(function (r) { return have.indexOf(r) >= 0; });
        missing = all.filter(function (r) { return have.indexOf(r) < 0; });
        if (!anyMet) missing.push('one of: ' + any.join(' / '));
        verdict = (allMet && anyMet) ? 'alt' : 'locked';
      }
      return { id: id, title: d.title, verdict: verdict, missing: missing, coach: coach[id] || '' };
    }).filter(Boolean);
    for (var j = choices.length - 1; j > 0; j--) { var r = Math.floor(Math.random() * (j + 1)); var t = choices[j]; choices[j] = choices[r]; choices[r] = t; }
    return { moveId: moveId, situation: fx.situation || '', have: have, choices: choices };
  }

  OBOL.study = {
    LANES: LANES, LANE_ORDER: LANE_ORDER, AD_LANE: LANES.ad.nodes,
    lanes: lanes, lane: lane, laneEdges: laneEdges, laneOf: laneOf, laneEntry: laneEntry, laneNext: laneNext,
    atlas: atlas,
    cmdLocus: cmdLocus, cellFor: cellFor, replayFor: replayFor, practiceFor: practiceFor,
    producersOf: producersOf, opensNext: opensNext,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
